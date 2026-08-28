/**************************************************/
/*  WkDefender — Tier3 深度取证引擎实现 (2026-07 重置) */
/*                                                  */
/*  纯同步架构 — T2直接调用T3DeepForensics。         */
/*  无异步队列, 无后台线程。触发频率极低（每天个位数）。  */
/**************************************************/

#include "Tier3Engine.h"
#include "T3AttackChain.h"
#include "CausalAnalyzer.h"
#include "../IoaEngine.h"
#include "../IoaEdgeAggregate.h"
#include "../IoaProcessPair.h"
#include "../IoaCarsalGraph.h"
#include "../IoaPersistQueue.h"
#include "../../Common/Utils.h"

/* StPersistAlert 前置声明 (Storage/StorageEngine.h, 避免循环 include) */
NTSTATUS StPersistAlert(_In_ PVOID AlertData);

/**************************************************/
/*           引擎生命周期                           */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
T3Initialize(
    _Out_ PIOA_TIER3_ENGINE*    Out
    )
{
    PIOA_TIER3_ENGINE e;

    if (!Out) return STATUS_INVALID_PARAMETER;

    e = UtHeapAlloc(sizeof(IOA_TIER3_ENGINE));
    if (!e) return STATUS_NO_MEMORY;
    RtlZeroMemory(e, sizeof(IOA_TIER3_ENGINE));

    InitializeCriticalSection(&e->Lock);

    /* 初始化攻击链池 */
    T3ChainPool_Init(&e->ChainPool);

    /* 初始化分析器回调注册表 */
    T3Registry_Initialize();

    e->Initialized = TRUE;

    printf("[Tier3] Initialized: synchronous forensics engine + ChainPool ready\n");

    *Out = e;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
T3Cleanup(
    _In_ PIOA_TIER3_ENGINE Engine
    )
{
    if (!Engine || !Engine->Initialized) return;

    Engine->Initialized = FALSE;

    /* 清理攻击链池 */
    T3ChainPool_Cleanup(&Engine->ChainPool);

    DeleteCriticalSection(&Engine->Lock);

    printf("[Tier3] Cleanup: forensics=%lld chains=%lld merges=%lld "
           "blockingQueries=%lld denies=%lld\n",
           Engine->TotalForensicsCalls, Engine->TotalChainsCreated,
           Engine->TotalChainMerges,
           Engine->TotalBlockingQueries, Engine->TotalBlockingDenies);

    UtHeapFree(Engine);
}

/**************************************************/
/*       可疑集群检测 (对齐 SS 进程关系图)            */
/*                                                  */
/*  迁移自 ShadowStrike ProcessRelationship.c       */
/*  PrFindSuspiciousClusters + PrpAnalyzeCluster-   */
/*  Recursive: 因果图连通子图 + 评分聚合, 判协同攻击。*/
/*  数据源: WkdIoaEngine.Graph (因果图唯一数据源)。   */
/*                                                  */
/*  [死代码] 门控 g_IoaClusterDetectionEnabled=      */
/*  FALSE 默认关（对齐 g_IoaCmdLineAnalyzerEnabled   */
/*  模式）。阈值按 SS 0-1000 → wkd 0-100 尺度换算。  */
/*  消费: IOA_ALERT → IoaPersistQueueEnqueue。       */
/**************************************************/

static BOOLEAN g_IoaClusterDetectionEnabled = FALSE;

/* 对齐 SS PR_CLUSTER_* (ProcessRelationship.h) */
#define T3_CLUSTER_MIN_SCORE         30      /* SS 300 / 10 → 0-100 尺度 */
#define T3_CLUSTER_MIN_RELATIONSHIPS 3       /* SS PR_CLUSTER_MIN_RELATIONSHIPS */
#define T3_CLUSTER_TIMEWINDOW_MS     30000   /* SS PR_CLUSTER_TIMEWINDOW_MS */
#define T3_CLUSTER_MAX_DEPTH         8       /* SS PR_CLUSTER_MAX_DEPTH */
#define T3_CLUSTER_MAX_PROCESSES     64      /* SS PR_CLUSTER_MAX_PROCESSES */

typedef struct _T3_CLUSTER_CONTEXT {
    GUID    NodeIds[T3_CLUSTER_MAX_PROCESSES];
    ULONG   ProcessCount;
    ULONG   RelationshipCount;      /* 窗口内边数 */
    ULONG   TotalScore;             /* 簇分 0-100 */
    LARGE_INTEGER FirstSeen;
    LARGE_INTEGER LastSeen;
    ULONG   CurrentDepth;
} T3_CLUSTER_CONTEXT, *PT3_CLUSTER_CONTEXT;

static
BOOLEAN
T3pClusterIsInCluster(
    _In_ PT3_CLUSTER_CONTEXT Ctx,
    _In_ GUID*               NodeId
    )
/*++
Routine Description:
    检查节点是否已加入簇（去重, 对齐 SS PrpIsNodeInCluster）。

Arguments:
    Ctx    — 簇上下文。
    NodeId — 节点 GUID。

Return Value:
    TRUE=已存在。
--*/
{
    ULONG i;

    for (i = 0; i < Ctx->ProcessCount; i++) {
        if (DefGuidEqual(&Ctx->NodeIds[i], NodeId)) {
            return TRUE;
        }
    }
    return FALSE;
}

static
VOID
T3pClusterVisit(
    _In_ PIOA_CARSAL_GRAPH   Graph,
    _In_ PIOA_CARSAL_GRAPH_NODE Node,
    _In_ LARGE_INTEGER       Now,
    _Inout_ PT3_CLUSTER_CONTEXT Ctx
    )
/*++
Routine Description:
    递归扩散簇: 沿出边遍历, 只计 30s 窗口内边, 加权置信度累计簇分。
    对齐 SS PrpAnalyzeClusterRecursive (深度/进程上限剪枝 + 出边扩散)。

Arguments:
    Graph — 因果图。
    Node  — 当前节点。
    Now   — 当前时间 (FILETIME)。
    Ctx   — 簇上下文 (累计)。

Return Value:
    VOID。
--*/
{
    PLIST_ENTRY entry;
    ULONG scanned = 0;

    if (Ctx->CurrentDepth >= T3_CLUSTER_MAX_DEPTH ||
        Ctx->ProcessCount >= T3_CLUSTER_MAX_PROCESSES) {
        return;
    }

    /* 加入簇（去重） */
    if (!T3pClusterIsInCluster(Ctx, &Node->NodeId)) {
        if (Ctx->ProcessCount >= T3_CLUSTER_MAX_PROCESSES) {
            return;
        }
        Ctx->NodeIds[Ctx->ProcessCount++] = Node->NodeId;
        if (Ctx->FirstSeen.QuadPart == 0 ||
            Node->LastSeen.QuadPart < Ctx->FirstSeen.QuadPart) {
            Ctx->FirstSeen = Node->LastSeen;
        }
    }

    /* 沿出边扩散（对齐 SS 源节点关系列表遍历）:
     * 只计 LastSeen 在 30s 窗口内的边, 簇分 = Σ(Weight×Confidence/100)/10 */
    for (entry = Node->OutEdgesHead.Flink;
         entry != &Node->OutEdgesHead;
         entry = entry->Flink) {
        PIOA_GRAPH_EDGE edge = CONTAINING_RECORD(entry, IOA_GRAPH_EDGE, SrcOutLink);
        LONGLONG ageMs;

        if (++scanned > 512) break;   /* 防单节点超大出度拖垮扫描 */

        ageMs = (Now.QuadPart - edge->LastSeen.QuadPart) / 10000;
        if (ageMs < 0 || ageMs > T3_CLUSTER_TIMEWINDOW_MS) {
            continue;
        }

        Ctx->RelationshipCount++;
        /* 簇分 = Σ(边Weight × Confidence/100) / 10 (SS 300/10 → 0-100) */
        Ctx->TotalScore += (edge->Weight * edge->Confidence) / 100 / 10;
        if (edge->LastSeen.QuadPart > Ctx->LastSeen.QuadPart) {
            Ctx->LastSeen = edge->LastSeen;
        }

        /* 递归扩散到目标进程节点 */
        if (edge->TgtNode != NULL &&
            edge->TgtNode->NodeType == DefNode_Process &&
            !T3pClusterIsInCluster(Ctx, &edge->TgtNode->NodeId)) {
            Ctx->CurrentDepth++;
            T3pClusterVisit(Graph, edge->TgtNode, Now, Ctx);
            Ctx->CurrentDepth--;
        }
    }
}

static
PIOA_ALERT
T3pAllocClusterAlert(
    _In_ PT3_CLUSTER_CONTEXT Ctx
    )
/*++
Routine Description:
    可疑集群告警构造 (单块堆分配, 含字符串缓冲)。
    对齐 RaAllocStatAlert / VerdictEngine_AllocPersistAlert 分配语义,
    满足持久化队列 UtHeapFree(Data) 整体释放; 调用方转移所有权。

Arguments:
    Ctx — 簇上下文。

Return Value:
    告警指针 (调用方转移所有权); 分配失败返回 NULL。
--*/
{
    static const WCHAR* sRuleName = L"Cluster/Coordinated";
    DEF_THREAT_SEVERITY severity;
    size_t ruleLen, descLen, total;
    PIOA_ALERT alert;
    PWCHAR buf;
    WCHAR descBuf[256];

    if (Ctx->TotalScore >= 60) {
        severity = DefThreatSeverity_High;
    } else {
        severity = DefThreatSeverity_Medium;
    }

    swprintf_s(descBuf, 256,
               L"Cluster: processes=%lu edges=%lu score=%lu windowMs=%u",
               Ctx->ProcessCount, Ctx->RelationshipCount,
               Ctx->TotalScore, T3_CLUSTER_TIMEWINDOW_MS);

    ruleLen = wcslen(sRuleName);
    descLen = wcslen(descBuf);
    total = sizeof(IOA_ALERT) +
            (ruleLen + 1 + descLen + 1) * sizeof(WCHAR);

    alert = (PIOA_ALERT)UtHeapAlloc(total);
    if (!alert) {
        return NULL;
    }
    RtlZeroMemory(alert, total);

    CoCreateGuid(&alert->AlertId);
    GetSystemTimeAsFileTime((PFILETIME)&alert->Timestamp);
    alert->SuspectNodeId = Ctx->NodeIds[0];
    alert->VictimNodeId = Ctx->ProcessCount > 1 ?
        Ctx->NodeIds[Ctx->ProcessCount - 1] : Ctx->NodeIds[0];
    alert->Severity = severity;
    alert->Score = Ctx->TotalScore;
    alert->Confidence = (Ctx->TotalScore >= 60) ? 100 : 60;
    alert->Category = DefThreatCat_SuspiciousBehavior;
    alert->ConfidenceLevel = (Ctx->TotalScore >= 60) ?
        DefConfidence_High : DefConfidence_Medium;
    alert->RecommendedAction = DefRespAction_Alert;
    alert->DetectionSource = DefDetSrc_Cluster;
    alert->MitreId = NULL;   /* 协同攻击无单一 MITRE 技术, 对齐 SS 提交 SuspiciousParentChild 语义 */

    buf = (PWCHAR)((PUCHAR)alert + sizeof(IOA_ALERT));
    alert->RuleName = buf;
    wcscpy_s(buf, ruleLen + 1, sRuleName);
    buf += ruleLen + 1;

    alert->Description = buf;
    wcscpy_s(buf, descLen + 1, descBuf);

    return alert;
}

static
VOID
T3pDetectSuspiciousClusters(
    VOID
    )
/*++
Routine Description:
    因果图可疑集群周期扫描。遍历 process 节点, 出边扩散 BFS,
    簇分≥30 且边数≥3 判定为可疑集群, 构造 IOA_ALERT 入队。
    对齐 SS PrFindSuspiciousClusters (60s 周期定时器触发)。

    [死代码] 门控 g_IoaClusterDetectionEnabled=FALSE 默认关。
    阈值按 SS 0-1000 → wkd 0-100 尺度换算 (/10), 需按 wkd 数据校准。

Return Value:
    VOID。
--*/
{
    PIOA_CARSAL_GRAPH graph = WkdIoaEngine.Graph;
    PLIST_ENTRY entry;
    LARGE_INTEGER now;
    GUID alerted[T3_CLUSTER_MAX_PROCESSES];
    ULONG alertedCount = 0;
    ULONG clusterCount = 0;

    if (!graph || !graph->Initialized) {
        return;
    }

    GetSystemTimeAsFileTime((PFILETIME)&now);
    RtlZeroMemory(alerted, sizeof(alerted));

    EnterCriticalSection(&graph->Lock);

    for (entry = graph->NodeGlobalList.Flink;
         entry != &graph->NodeGlobalList;
         entry = entry->Flink) {
        PIOA_CARSAL_GRAPH_NODE node =
            CONTAINING_RECORD(entry, IOA_CARSAL_GRAPH_NODE, GlobalLink);
        T3_CLUSTER_CONTEXT ctx;
        ULONG i;
        BOOLEAN seen = FALSE;

        /* 仅 process 节点 + 有出边 */
        if (node->NodeType != DefNode_Process || node->OutDegree == 0) {
            continue;
        }

        /* 跳过已判定簇成员（防重复发现同一簇） */
        for (i = 0; i < alertedCount; i++) {
            if (DefGuidEqual(&alerted[i], &node->NodeId)) {
                seen = TRUE;
                break;
            }
        }
        if (seen) {
            continue;
        }

        RtlZeroMemory(&ctx, sizeof(ctx));
        T3pClusterVisit(graph, node, now, &ctx);

        if (ctx.TotalScore >= T3_CLUSTER_MIN_SCORE &&
            ctx.RelationshipCount >= T3_CLUSTER_MIN_RELATIONSHIPS) {
            PIOA_ALERT alert = T3pAllocClusterAlert(&ctx);
            if (alert && WkdIoaEngine.PersistQueue) {
                IoaPersistQueueEnqueue(WkdIoaEngine.PersistQueue,
                                       PersistType_Alert, alert,
                                       (PERSIST_SERDE_WRITE_FN)StPersistAlert,
                                       TRUE);
                clusterCount++;
            }
            /* 标记簇内节点, 防重复发现 */
            for (i = 0; i < ctx.ProcessCount &&
                        alertedCount < T3_CLUSTER_MAX_PROCESSES; i++) {
                alerted[alertedCount++] = ctx.NodeIds[i];
            }
        }
    }

    LeaveCriticalSection(&graph->Lock);

    if (clusterCount > 0) {
        printf("[Tier3] Suspicious clusters detected: %lu\n", clusterCount);
    }
}

/**************************************************/
/*           周期性维护                             */
/**************************************************/

VOID
T3PeriodicMaintenance(
    _In_ PIOA_TIER3_ENGINE Engine
    )
{
    if (!Engine || !Engine->Initialized) return;

    /* 淘汰过期链 */
    T3ChainPool_EvictExpired(&Engine->ChainPool);

    /* 可疑集群检测（死代码门控, 对齐 SS PrFindSuspiciousClusters 60s 周期） */
    if (g_IoaClusterDetectionEnabled) {
        T3pDetectSuspiciousClusters();
    }

    /* 多点攻击关联扫描 */
    {
        ULONG correlated = 0;
        EnterCriticalSection(&Engine->ChainPool.Lock);

        PLIST_ENTRY outer = Engine->ChainPool.ChainHead.Flink;
        while (outer != &Engine->ChainPool.ChainHead) {
            PTIRE3_ATTACK_CHAIN chainA = CONTAINING_RECORD(
                outer, TIRE3_ATTACK_CHAIN, Link);
            PLIST_ENTRY inner = outer->Flink;
            while (inner != &Engine->ChainPool.ChainHead) {
                PTIRE3_ATTACK_CHAIN chainB = CONTAINING_RECORD(
                    inner, TIRE3_ATTACK_CHAIN, Link);

                /* 简化的多链关联检查: 共享节点 >= 2 → 潜在合并 */
                ULONG shared = 0;
                for (ULONG a = 0; a < chainA->ProcessCount; a++) {
                    for (ULONG b = 0; b < chainB->ProcessCount; b++) {
                        if (DefGuidEqual(&chainA->ProcessSet[a],
                                         &chainB->ProcessSet[b])) {
                            shared++;
                            break;
                        }
                    }
                }
                if (shared >= 2) {
                    correlated++;
                }
                inner = inner->Flink;
            }
            outer = outer->Flink;
        }

        LeaveCriticalSection(&Engine->ChainPool.Lock);

        if (correlated > 0) {
            printf("[Tier3] Multi-chain correlation: %lu overlaps found\n",
                   correlated);
        }
    }
}

/**************************************************/
/*           同步阻塞快速路径                       */
/**************************************************/

NTSTATUS
T3HandleBlockingQuery(
    _In_    PIOA_TIER3_ENGINE   Engine,
    _In_    GUID                SrcNodeId,
    _In_    GUID                TgtNodeId,
    _In_    IOA_GRAPH_EDGE_TYPE OperationType,
    _Out_   BOOLEAN*            OutAllow,
    _Out_   PT3_STATE_UPDATE    OutState
    )
/*++
Routine Description:
    Driver 同步阻塞敏感操作时调用。

    核心原则: 进入 Tier3 本身就是"威胁已确认"的强信号。
    默认 DENY — 只有明确确认威胁很低时才 ALLOW。
--*/
{
    T3_DANGER_LEVEL danger;
    ULONG threatScore = 0;
    BOOLEAN foundChain = FALSE;

    if (!Engine || !OutAllow || !OutState) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(OutState, sizeof(T3_STATE_UPDATE));
    *OutAllow = FALSE;                    /* ★ 默认 DENY ★ */

    danger = T3AssessDangerLevel(OperationType);

    /* 查攻击链缓存 */
    EnterCriticalSection(&Engine->ChainPool.Lock);
    {
        PLIST_ENTRY entry = Engine->ChainPool.ChainHead.Flink;
        while (entry != &Engine->ChainPool.ChainHead) {
            PTIRE3_ATTACK_CHAIN chain = CONTAINING_RECORD(
                entry, TIRE3_ATTACK_CHAIN, Link);
            if (T3QueryAttackChainIncludedProcess(chain, SrcNodeId) &&
                T3QueryAttackChainIncludedProcess(chain, TgtNodeId)) {
                threatScore = chain->ThreatScore;
                foundChain = TRUE;
                break;
            }
            entry = entry->Flink;
        }
    }
    LeaveCriticalSection(&Engine->ChainPool.Lock);

    /*
     * 决策矩阵 (默认 DENY):
     *   ThreatScore < 15:  ALLOW (明确低威胁 — 可能是 FSM 误触发)
     *   ThreatScore 15~30: 仅 LOW 危险操作 ALLOW
     *   ThreatScore ≥ 30: 全部 DENY (威胁已确认)
     *   未命中缓存 + 执行权转移: 强制 DENY
     */
    if (threatScore < 15) {
        *OutAllow = TRUE;
    } else if (threatScore < 30) {
        *OutAllow = (danger <= T3Danger_Low);
    } else {
        *OutAllow = FALSE;
    }

    /* 未命中 + 执行权转移 → 强制 DENY */
    if (!foundChain && danger >= T3Danger_Critical) {
        *OutAllow = FALSE;
    }
    /* 未命中 + 低威胁且无历史 → 保守放行 */
    if (!foundChain && danger <= T3Danger_Low && threatScore == 0) {
        *OutAllow = TRUE;
    }

    if (!*OutAllow) {
        OutState->SrcRiskScoreDelta = 30;
        OutState->SrcBlacklist = TRUE;
        Engine->TotalBlockingDenies++;
    }

    Engine->TotalBlockingQueries++;

    printf("[Tier3] BlockingQuery: op=%d danger=%d threatScore=%lu "
           "foundChain=%d → %s\n",
           OperationType, danger, threatScore, foundChain,
           *OutAllow ? L"ALLOW" : L"DENY");

    return STATUS_SUCCESS;
}

/**************************************************/
/*           统计                                   */
/**************************************************/

VOID
T3GetStats(
    _In_  PIOA_TIER3_ENGINE Engine,
    _Out_ ULONG64*            ForensicsCalls,
    _Out_ ULONG64*            BlockingQueries,
    _Out_ ULONG64*            BlockingDenies
    )
{
    if (Engine && Engine->Initialized) {
        if (ForensicsCalls)  *ForensicsCalls  = Engine->TotalForensicsCalls;
        if (BlockingQueries) *BlockingQueries = Engine->TotalBlockingQueries;
        if (BlockingDenies)  *BlockingDenies  = Engine->TotalBlockingDenies;
    }
}
