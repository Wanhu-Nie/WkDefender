/**************************************************/
/*  WkDefender IOA 引擎 — 编排层实现                */
/*  拥有并管理: Genealogy / Graph / GraphMatcher    */
/*             RateAnalyzer / GraphWalker / Scorer  */
/*                                                  */
/*  外部入口: IoaObserve(event)                     */
/*  内部自行决定: 何时更新谱系 / 何时插入图边       */
/*               何时做图模式匹配 / 何时做速率分析  */
/*               何时更新评分                        */
/**************************************************/

#include "IoaEngine.h"
#include "../Process/ProcessTree.h"
#include "../Process/ProcessThread.h"   /* 线程表挂载 (2026-08-15 进程域) */
#include "../Orchestrator/VerdictEngine.h"   /* VerdictEngine_OnProcessTerminate: 进程退出活跃威胁清理 */
#include "IoaCarsalGraph.h"
#include "IoaPersistQueue.h"
#include "Tier1/Tier1Engine.h"
#include "Tier2/IoaTier2Backtrack.h"
#include "Tier2/IoaFsmEngine.h"
#include "Tier3/IoaGraphMatcher.h"
#include "Tier3/IoaGraphWalker.h"
#include "Tier1/IoaRateAnalyzer.h"
#include "Tier1/T1ShellcodeDetect.h"
#include "IoaThreatScorer.h"
#include "IoaMitreMapper.h"
#include "IoaGraphRingBuffer.h"
#include "IoaEdgeAggregate.h"
#include "IoaRansomwareDetect.h"   /* 勒索行为评分（FBE 迁移 2026-08） */
#include "IoaProcessPair.h"
#include "IoaInjectionClassifier.h"
#include "Tier3/Tier3Engine.h"
#include "../Notification/EventTypes.h"
#include "../PolicyEngine/PolicyEngine.h"   /* 序列规则引擎 (PatternMatcher 迁移) */
#include "../IOC/IocProcessEnrich.h"
#include "../Common/Exempts/Exempts.h"   /* 统一豁免门面 (Exempts 重构 #67, 注入豁免原 IocInjectionWhitelist) */
#include "../Memory/MemoryScan.h"
#include "../CmdLineAnalyzer.h"             /* 命令行深度分析 (SS CommandLineParser 迁移) */
#include "../TokenAnalyzer.h"               /* 令牌分析 (SS TokenAnalyzer+PrivilegeMonitor 迁移) */
#include "../FileLockManager.h"             /* 文件锁模式关联 (FileLockManager 迁移 2026-08) */
#include "IoaHeapSprayDetect.h"             /* 堆喷检测 (HeapSpray 迁移 2026-08) */
// #include "../Notification/EventParser.h"

/* StPersistAlert 前置声明 (Storage/StorageEngine.h, 避免循环 include) */
NTSTATUS StPersistAlert(_In_ PVOID AlertData);

/**************************************************/
/*               全局实例                           */
/**************************************************/

IOA_ENGINE WkdIoaEngine = { 0 };

/* 命令行深度分析接线开关（死代码开关，默认关闭，对齐 EnableRuntimeRules/
 * EnableSequenceRules）。置 TRUE 后 IoaObserve 阶段4.7 对 ProcessCreate
 * 事件调用 WpaAnalyzeCommandLine。 */
static BOOLEAN g_IoaCmdLineAnalyzerEnabled = FALSE;

/* 进程环境分析接线开关（死代码开关，默认关闭，对齐 g_IoaCmdLineAnalyzerEnabled，
 * ShadowStrike EnvironmentMonitor 迁移 2026-08）。置 TRUE 后 IoaObserve 阶段4.8
 * 对 ProcessCreate 事件调用 IpeAnalyzeEnvironment（见 IOC/IocProcessEnrich.h）。 */
static BOOLEAN g_IoaEnvironmentAnalyzerEnabled = FALSE;

/* 令牌分析接线开关（ShadowStrike TokenAnalyzer + PrivilegeMonitor 迁移
 * 2026-08-05/2026-08-06）。置 TRUE 后 IoaObserve 阶段4.9 对 ProcessCreate
 * 事件调用 WpaAnalyzeToken（7 类令牌操控攻击检测）+ WpaRecordBaseline（建立
 * 基线）；阶段4.9b 对 token 操作 syscall 事件（驱动 0x100C-0x100F 上送）调用
 * WpaCheckForEscalation（9 类提权 + UAC 10 模式运行期基线对比）。引擎初始化
 * 处已调用 WpaTokenAnalyzerInitialize()。 */
static BOOLEAN g_IoaTokenAnalyzerEnabled = TRUE;

/* 文件行为分析接线开关（FBE 迁移 2026-08，死代码开关，默认关闭，对齐
 * g_IoaCmdLineAnalyzerEnabled）。置 TRUE 后 IoaObserve 阶段4.9c 对文件事件
 * （驱动 FBE 上送 0x1302-0x1304，WkdEvent_FileWrite/FileRename/FileDelete）
 * 调用 IoaRansomware_UpdateScore：高熵写/勒索扩展名变更/大量删除/勒索信/Canary
 * 评分，命中置 DEF_BEHAVIOR_FLAG_RANSOMWARE_* 并产分复用阶段6c2 injConfirmed
 * 提升路径。勒索检测闭环（文件熵需驱动 minifilter 补 + 告警持久化）打通后置 TRUE。 */
static BOOLEAN g_IoaFileBehaviorAnalyzerEnabled = FALSE;

/* 命名管道分析接线开关（NamedPipeMonitor 迁移 2026-08，死代码开关，默认关闭，
 * 对齐 g_IoaCmdLineAnalyzerEnabled）。置 TRUE 后 IoaObserve 阶段4.10 对命名管道
 * 创建事件（驱动 0x1307 上送，WkdEvent_NamedPipeCreate）消费驱动分类结果：已知
 * C2 管道名 → C2_COMMUNICATION、系统管道冒充 → LATERAL_MOVEMENT、高熵随机名 →
 * C2_COMMUNICATION，产分复用阶段6c2 injConfirmed 提升路径。驱动已注册
 * IRP_MJ_CREATE_NAMED_PIPE 回调 + 上送 0x1307，解析器已注册（NtfpParseNamedPipe）。 */
static BOOLEAN g_IoaNamedPipeAnalyzerEnabled = FALSE;

/* 文件锁模式关联接线开关（FileLockManager 迁移 2026-08，死代码开关，默认关闭，
 * 对齐 g_IoaCmdLineAnalyzerEnabled）。置 TRUE 后 IoaObserve 阶段4.9d 对文件事件
 * 做锁快照 (FileLockManager_GetLockInfo)：未签名进程持独占锁+文档扩展名 →
 * Ransomware 锁模式、注入进程持锁 → ProcessInjection/DefenseEvasion，命中置
 * DEF_BEHAVIOR_FLAG_RANSOMWARE_ENC 并产分复用阶段6c2 injConfirmed 提升路径。
 * 注: 锁快照 (RM+句柄枚举) 成本高, 接入需按需触发 (如扫描命中后复核)。 */
static BOOLEAN g_IoaLockPatternEnabled = FALSE;

/* 堆喷分析接线开关（HeapSpray 迁移 2026-08，死代码开关，默认关闭，对齐
 * g_IoaCmdLineAnalyzerEnabled）。置 TRUE 后 IoaObserve 阶段4.11 对内存分配
 * 事件（驱动 0x1002，WkdEvent_MemoryAllocate）调用 IoaHeapSpray_OnAllocate：
 * 窗口聚合（计数/字节/对齐/分配率）+ 门控内容采样（复用 MsReadMemory）+
 * 评分（0-1000）→ 判定 SprayInProgress → 阶段6 产分复用 6c2 injConfirmed
 * 提升路径 + IOA_ALERT（T1203/T1499）。驱动 SmInitialize 注释态（WkdEntry.c:261）
 * 内存事件不可达，启用后自动贯通。 */
static BOOLEAN g_IoaHeapSprayEnabled = FALSE;

/**************************************************/
/*           统一环形缓冲区写入 (重构)               */
/**************************************************/

static NTSTATUS
IoapHandleDynamicEdge(
    _In_ PWKD_EVENT_HEADER Event,
    _In_ PWKD_PROCESS SrcNode,
    _In_ PWKD_PROCESS TgtNode,
    _In_opt_ PAE_PROCESS_PAIR PairCtx,
    _In_opt_ GUID* PreGeneratedEdgeId
    )
/*++
Routine Description:
    处理动态行为事件的图边写入。
    职责:
       1. 推导边类型 (EdgeType)
       2. 分层决策 (GrbDecideLayer)
       3. 合并进程级+进程对级行为标志 → 构造边描述符 → 无锁写入环形缓冲区

    边 GUID 复用:
      PreGeneratedEdgeId → 复用 IoaObserve 阶段2 预生成的 GUID
        (已写入聚合边 RecentEdgeIds，FSM 可按此 GUID 在因果图中精确关联)
      NULL → 自动生成 (如进程退出事件, 不关联 FSM)

Arguments:
    Event       — 动态行为事件 (Severity/BehaviorFlags 已被 T1Evaluate 富化)。
    SrcNode     — 源进程谱系节点 (可 NULL)。
    TgtNode     — 目标进程谱系节点 (可 NULL)。
    PairCtx     — 进程对上下文 (可 NULL, 提供对级交互标志)。
    PreGeneratedEdgeId — 预生成的边 GUID (可 NULL)。

Return Value:
    NTSTATUS。
--*/
{
    IOA_GRAPH_EDGE_TYPE edgeType;
    GRAPH_EDGE_DESCRIPTOR edgeDesc;
    GRAPH_LAYER_DECISION layer;
    GUID sourceWkdProcessId, targetWkdProcessId;

    /* 默认 Null GUID */
    RtlZeroMemory(&sourceWkdProcessId, sizeof(GUID));
    RtlZeroMemory(&targetWkdProcessId, sizeof(GUID));
    if (SrcNode) WkdCopyGuid(&sourceWkdProcessId, &SrcNode->NodeId);
    if (TgtNode) WkdCopyGuid(&targetWkdProcessId, &TgtNode->NodeId);

    /* 1. 推导边类型 */
    edgeType = IoaMapEventToEdgeType(Event->Type);
    if (edgeType == DefEdge_Unknown) {
        return STATUS_SUCCESS;
    }

    /* 2. 分层决策 */
    layer = GrbDecideLayer(Event, SrcNode, TgtNode, FALSE);

    /* 3. 构造边描述符 → 无锁写入环形缓冲区 */
    if (layer != GraphLayer_Skip) {
        if (PreGeneratedEdgeId) {
            WkdCopyGuid(&edgeDesc.EdgeId, PreGeneratedEdgeId);
        } else {
            WkdCreateGuid(&edgeDesc.EdgeId);
        }
        WkdCopyGuid(&edgeDesc.SourceNodeId, &sourceWkdProcessId);
        WkdCopyGuid(&edgeDesc.TargetNodeId, &targetWkdProcessId);
        edgeDesc.EdgeType      = edgeType;
        edgeDesc.EventClass    = Event->Class;
        edgeDesc.Confidence    = Event->Confidence;
        edgeDesc.Timestamp     = Event->Timestamp;

        /*
         * 合并进程级 + 进程对级行为标志。
         * Event->BehaviorFlags: 驱动侧采集的进程固有标志
         * PairCtx->InteractionBitmap 高64位: T1 语义进化后的交互语义标志
         */
        edgeDesc.BehaviorFlags = Event->BehaviorFlags;
        if (PairCtx) {
            /* 语义层 → 行为标志 (DEF_BEHAVIOR_FLAG_* 格式)
             * 映射规则: L2 高级语义位 → 对应的 DEF_BEHAVIOR_FLAG_* */
            ULONG64 semDword = BM_SEM_U64(&PairCtx->InteractionBitmap);
            if (semDword & (1ULL << BM_SEM_DLL_INJECTION))
                edgeDesc.BehaviorFlags |= DEF_BEHAVIOR_FLAG_INJECTION | DEF_BEHAVIOR_FLAG_REMOTE_THREAD;
            if (semDword & (1ULL << BM_SEM_PROCESS_HOLLOWING))
                edgeDesc.BehaviorFlags |= DEF_BEHAVIOR_FLAG_HOLLOWING;
            if (semDword & (1ULL << BM_SEM_CREDENTIAL_DUMPING))
                edgeDesc.BehaviorFlags |= DEF_BEHAVIOR_FLAG_MEMORY_READ_REMOTE | DEF_BEHAVIOR_FLAG_PROCESS_OPEN;
            if (semDword & (1ULL << BM_SEM_TOKEN_MANIPULATE))
                edgeDesc.BehaviorFlags |= DEF_BEHAVIOR_FLAG_TOKEN_MANIPULATE;
            if (semDword & (1ULL << BM_SEM_REFLECTIVE_LOAD))
                edgeDesc.BehaviorFlags |= DEF_BEHAVIOR_FLAG_REFLECTIVE_LOAD;
            if (semDword & (1ULL << BM_SEM_APC_INJECTION))
                edgeDesc.BehaviorFlags |= DEF_BEHAVIOR_FLAG_APC_INJECTION;
            if (semDword & (1ULL << BM_SEM_DLL_SIDE_LOADING))
                edgeDesc.BehaviorFlags |= DEF_BEHAVIOR_FLAG_DLL_SIDE_LOAD;
            if (semDword & (1ULL << BM_SEM_SUSPICIOUS_CHAIN))
                edgeDesc.BehaviorFlags |= DEF_BEHAVIOR_FLAG_SUSPICIOUS_CHAIN;
        }

        NTSTATUS rbStatus = GrbWriteEdge(WkdIoaEngine.RingBuffer, &edgeDesc, layer);
        if (NT_SUCCESS(rbStatus)) {
            WkdIoaEngine.Statistics.RingBufferWrites++;
        } else {
            WkdIoaEngine.Statistics.RingBufferDrops++;
        }
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*                   公开 API                       */
/**************************************************/

NTSTATUS
IoaEngine_Initialize(
    _In_ PIOA_ENGINE_CONFIG Config
    )
/*++
Routine Description:
    初始化 IOA 引擎及其所有内部组件。
    初始化顺序: 谱系 → 因果图 → 图模式匹配 → 速率分析 → 图游走 → 评分。

Arguments:
    Config — 引擎配置。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;

    if (!Config) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&WkdIoaEngine, sizeof(WkdIoaEngine));
    memcpy(&WkdIoaEngine.Config, Config, sizeof(IOA_ENGINE_CONFIG));
    InitializeCriticalSection(&WkdIoaEngine.Lock);
    CoInitializeRundownProtection(&WkdIoaEngine.RundownRef);

    printf("========================================\n");
    printf("  WkDefender IOA Engine (3-Tier Detection)\n");
    printf("  Tier 1.0: Single-Event Rules\n");
    printf("  Tier 2:   DFA+FSM + Semantic Verification\n");
    printf("  Tier 2:   Async Bounded Backtrack\n");
    printf("  Tier 3:   Async Full-Graph Matching\n");
    printf("========================================\n\n");

    /* 1. 初始化因果图（进程域树 WkdProcessTree 由 main.c 在 IoaEngine 之前初始化） */
    printf("[IoaEngine] [2/12] Initializing Causality Graph...\n");
    status = IoaCarsalGraphInitialize(&WkdIoaEngine.Graph);
    if (!NT_SUCCESS(status)) { goto fail_graph; }

    /* 3. 初始化异步持久化队列 */
    printf("[IoaEngine] [3/12] Initializing Persist Queue...\n");
    status = PersistQueue_Initialize(&WkdIoaEngine.PersistQueue, 4096);
    if (!NT_SUCCESS(status)) { goto fail_persist; }

    /* 4. 初始化 DFA+FSM 时序引擎 (Tier 2 核心组件) */
    printf("[IoaEngine] [4/12] Initializing DFA+FSM Engine (Tier 2)...\n");
    status = FsmInitialize(&WkdIoaEngine.FsmEngine);
    if (!NT_SUCCESS(status)) { goto fail_fsm; }

    /* 5. 初始化无锁环形缓冲区 (异步图写入) */
    printf("[IoaEngine] [5/12] Initializing Graph Ring Buffer...\n");
    status = GrbInitialize(&WkdIoaEngine.RingBuffer);
    if (!NT_SUCCESS(status)) { goto fail_ring; }

    /* 6. Tier 2: 有界回溯 (通过 WkdIoaEngine 直接访问 FsmEngine/Genealogy 等) */
    printf("[IoaEngine] [6/12] Initializing Tier-2 Backtrack...\n");
    status = T2Initialize(&WkdIoaEngine.Tier2, WkdIoaEngine.PersistQueue);
    if (!NT_SUCCESS(status)) { goto fail_tier2; }

    /* 7. Tier 1: 单事件规则引擎 (依赖 PersistQueue) */
    printf("[IoaEngine] [7/12] Initializing Tier-1 Rule Engine...\n");
    status = T1Initialize(&WkdIoaEngine.Tier1, WkdIoaEngine.PersistQueue);
    if (!NT_SUCCESS(status)) { goto fail_tier1; }

    /* 8. 图模式匹配器 (Tier 3) */
    printf("[IoaEngine] [8/12] Initializing Graph Matcher (Tier 3)...\n");
    status = GmInitialize(&WkdIoaEngine.GraphMatcher);
    if (!NT_SUCCESS(status)) { goto fail_matcher; }

    /* 9. 图游走器 (Tier 3) */
    printf("[IoaEngine] [9/12] Initializing Graph Walker (Tier 3)...\n");
    status = GwInitialize(&WkdIoaEngine.GraphWalker);
    if (!NT_SUCCESS(status)) { goto fail_walker; }

    /* 10. Tier3 深度取证引擎 */
    printf("[IoaEngine] [10/12] Initializing Tier3 Deep Forensics Engine...\n");
    status = T3Initialize(&WkdIoaEngine.Tier3);
    if (!NT_SUCCESS(status)) { goto fail_tier3; }

    /* T2→T3 通路通过 WkdIoaEngine 全局变量自动建立 */

    /* 11. 速率分析器 */
    printf("[IoaEngine] [11/12] Initializing Rate Analyzer...\n");
    status = RaInitialize(&WkdIoaEngine.RateAnalyzer);
    if (!NT_SUCCESS(status)) { goto fail_rate; }

    /* 11b. 全局边聚合表 <spn, tpn, type> */
    printf("[IoaEngine] [11b/12] Initializing Edge Aggregate Table...\n");
    status = IoaInitializeAggregateEdgeTable(&WkdIoaEngine.EdgeAggTable);
    if (!NT_SUCCESS(status)) { goto fail_edgeagg; }

    /* 11c. 进程对管理器 <spn, tpn> */
    printf("[IoaEngine] [11c/12] Initializing Process Pair Manager...\n");
    status = PairManager_Initialize(&WkdIoaEngine.PairManager);
    if (!NT_SUCCESS(status)) { goto fail_pairmgr; }

    /* 12. 威胁评分器 */
    printf("[IoaEngine] [12/12] Initializing Threat Scorer...\n");
    status = IoaScorer_Initialize(&WkdIoaEngine.Scorer, Config->ScoreDecayIntervalMs);
    if (!NT_SUCCESS(status)) { goto fail_scorer; }

    WkdIoaEngine.Initialized = TRUE;
    printf("\n[IoaEngine] All 12 subsystems initialized\n\n");

    /* 令牌分析引擎（ShadowStrike TokenAnalyzer+PrivilegeMonitor 迁移 2026-08-06）：
     * 阶段4.9 ProcessCreate 建基线 (WpaRecordBaseline) + 阶段4.9b token 操作
     * syscall 事件 (驱动 0x100C-0x100F) 触发运行期提权对比 (WpaCheckForEscalation)。 */
    WpaTokenAnalyzerInitialize();

    return STATUS_SUCCESS;

    /* 逆序清理（与初始化顺序严格相反，每个标签清理自己的组件后 fall through） */
fail_scorer:
    IoaScorer_Cleanup(WkdIoaEngine.Scorer);
fail_pairmgr:
    PairManager_Cleanup(WkdIoaEngine.PairManager);
fail_edgeagg:
    IoaCleanupAggregateEdgeTable(WkdIoaEngine.EdgeAggTable);
fail_rate:
    RaCleanup(WkdIoaEngine.RateAnalyzer);
fail_tier3:
    T3Cleanup(WkdIoaEngine.Tier3);
fail_walker:
    GwCleanup(WkdIoaEngine.GraphWalker);
fail_matcher:
    GmCleanup(WkdIoaEngine.GraphMatcher);
fail_tier1:
    T1Cleanup(WkdIoaEngine.Tier1);
fail_tier2:
    T2Cleanup(WkdIoaEngine.Tier2);
fail_ring:
    GrbCleanup(WkdIoaEngine.RingBuffer);
fail_fsm:
    FsmCleanup(WkdIoaEngine.FsmEngine);
fail_persist:
    PersistQueue_Cleanup(WkdIoaEngine.PersistQueue);
fail_graph:
    IoaCarsalGraphCleanup(WkdIoaEngine.Graph);
    DeleteCriticalSection(&WkdIoaEngine.Lock);
    printf("[IoaEngine] Init failed at step: 0x%X\n", status);
    return status;
}

VOID
IoaEngine_Cleanup(
    VOID
    )
/*++
Routine Description:
    按初始化逆序清理 IOA 引擎所有内部组件。
--*/
{
    if (!WkdIoaEngine.Initialized) return;

    printf("[IoaEngine] Cleaning up...\n");
    IoaEngine_PrintStats();

    IoaScorer_Cleanup(WkdIoaEngine.Scorer);
    PairManager_Cleanup(WkdIoaEngine.PairManager);
    IoaCleanupAggregateEdgeTable(WkdIoaEngine.EdgeAggTable);
    RaCleanup(WkdIoaEngine.RateAnalyzer);
    T3Cleanup(WkdIoaEngine.Tier3);
    GwCleanup(WkdIoaEngine.GraphWalker);
    GmCleanup(WkdIoaEngine.GraphMatcher);
    T1Cleanup(WkdIoaEngine.Tier1);
    T2Cleanup(WkdIoaEngine.Tier2);
    GrbCleanup(WkdIoaEngine.RingBuffer);
    FsmCleanup(WkdIoaEngine.FsmEngine);
    PersistQueue_Cleanup(WkdIoaEngine.PersistQueue);
    IoaCarsalGraphCleanup(WkdIoaEngine.Graph);

    /* 令牌分析引擎（与 IoaEngine_Initialize 中初始化顺序逆序清理） */
    WpaTokenAnalyzerShutdown();

    WkdIoaEngine.Initialized = FALSE;
    DeleteCriticalSection(&WkdIoaEngine.Lock);
    printf("[IoaEngine] Cleanup complete\n");
}

/**************************************************/
/*           T1→T2/T3 分级调度枢纽                   */
/*                                                  */
/*  注意:                                          */
/*    - IoapBuildDynamicBacktrackEdges 已移除       */
/*      (猜边回溯已被全量子图提取 T2ExtractSubgraph  */
/*       替代，消费端不限边类型)                      */
/*    - IOA_TIER2_TRIGGER 已移除 (空壳结构体)        */
/*    - IoaTire2Trackback 已简化参数                 */
/*      (不再需要 BacktrackEdges/MaxDepth 等)        */
/**************************************************/

static
VOID
IoapDispatchTier2(
    _In_ T1_DISPATCH_LEVEL       Level,
    _In_ PAE_PROCESS_PAIR PairCtx
    )
/*++
Routine Description:
    分级调度枢纽 — 同步/异步路由到 T2 分析流水线。

Arguments:
    Level   — PolicyDecideDispatch 的分级决策。
    PairCtx — 进程对上下文 (可 NULL)。

Return Value:
    VOID。
--*/
{
    PIOA_TIER2_BACKTRACK t2;

    t2 = WkdIoaEngine.Tier2;
    if (!t2 || !t2->Initialized) return;
    if (!PairCtx) return;

    if (Level >= T1_DISPATCH_T2_SYNC) {
        T2_ANALYSIS_RESULT result;

        NTSTATUS status = T2EvaluateSync(t2, PairCtx, &result);

        if (!NT_SUCCESS(status)) {
            printf("[IoapDispatchTier2] T2EvaluateSync failed: 0x%X\n", status);
            return;
        }

        printf("[IoapDispatchTier2] %ls (sync%ls): verdict=%ls threatScore=%lu\n",
               Level == T1_DISPATCH_T3_DIRECT ? L"T3_DIRECT" : L"T2_SYNC",
               result.FsmAccepted ? L" FSM-guided" : L"",
               result.Verdict == T2_VERDICT_ATTACK     ? L"ATTACK" :
               result.Verdict == T2_VERDICT_SUSPICIOUS ? L"SUSPICIOUS" :
                                                          L"BENIGN",
               result.ThreatScore);

        if (result.Verdict >= T2_VERDICT_SUSPICIOUS) {
            t2->VerificationHits++;

            if (Level == T1_DISPATCH_T3_DIRECT ||
                result.Verdict == T2_VERDICT_ATTACK) {
                if (PairCtx) {
                    PairCtx->DirtyFlags |= IOA_PAIR_DIRTY_TIER3;
                }
            }
        }
        t2->TotalCalls++;

    } else {
        /* 并发安全重构 2026-08-23：持 EwmaLock 共享读，与写者互斥 */
        LONG ewmaScore;
        AcquireSRWLockShared(&PairCtx->T1Feature.EwmaLock);
        ewmaScore = PairCtx->T1Feature.CumulativeRiskScore;
        ReleaseSRWLockShared(&PairCtx->T1Feature.EwmaLock);
        T2EnqueueAsync(t2, PairCtx, ewmaScore > 50 ?
                       DefThreatSeverity_High : DefThreatSeverity_Medium);
    }
}



/**************************************************/
/*           持久化 + 速率分析辅助                   */
/**************************************************/

/**************************************************/
/*           Policy: 策略选择 + 分级调度              */
/**************************************************/

/*
 * PolicyAnalyze — 基于位图丰富度选择评分策略。
 *
 * 决策树:
 *   1. T2 强抑制 → SCORE_BY_T2_FEEDBACK (已证实良性)
 *   2. 语义层 L2 命中 → SCORE_BY_TEMPLATE    (高级语义确认)
 *   3. 语义层 L1 丰富 (≥2) 且 数据层丰富 (≥2) → SCORE_BY_ACCUMULATE
 *   4. 仅速率/统计异常 → SCORE_BY_ANOMALY   (未知威胁兜底)
 *   5. 目标为系统进程 + 数据层非空 → SCORE_BY_CONTEXT
 *   6. 其余 → SCORE_BY_BASELINE            (轻量基线)
 *
 * 上下文参数:
 *   bm — PINTERACTION_BITMAP (PairCtx->InteractionBitmap), 不可 NULL。
 */
static
SCORE_STRATEGY
PolicyAnalyze(
    _In_ PT1_PAIR_FEATURE      f,
    _In_ PINTERACTION_BITMAP   bm
    )
{
    ULONG64 semDword;
    ULONG semanticHits;

    if (!f || !bm) return SCORE_BY_BASELINE;

    semDword     = BM_SEM_U64(bm);
    semanticHits = (ULONG)__popcnt64(semDword);

    /* 1. T2 强抑制 → 反馈修正 (预留) */

    /* 2. 语义层 L2 命中 → 模板匹配 */
    if (semDword & BM_MASK_L2_SEMANTIC) {
        return SCORE_BY_TEMPLATE;
    }

    /* 3. 低级语义 ≥ 2 且 数据层丰富 → 累积评估 */
    if (semanticHits >= 2) {
        return SCORE_BY_ACCUMULATE;
    }
    if (f->RuleHitCount >= 2 && semanticHits >= 1) {
        return SCORE_BY_ACCUMULATE;
    }

    /* 4. 仅速率/统计异常 → 稀有度兜底 */
    if (f->ActiveOutTargets >= 5 || f->ActiveInSources >= 3) {
        return SCORE_BY_ANOMALY;
    }

    /* 5. 目标为系统进程 + 有数据层交互 → 上下文敏感 */
    if (f->TgtIsSystemProcess) {
        ULONG64 dataDword = BM_DATA_U64(bm);
        if (dataDword) return SCORE_BY_CONTEXT;
    }

    /* 6. 其他 → 基线 */
    return SCORE_BY_BASELINE;
}

/*
 * PolicyDecideDispatch — 基于策略 + 评分决定是否触发 Tier2/T3。
 *
 * 决策表:
 *   TEMPLATE 策略 && 评分 ≥ 80 → T3_DIRECT  (已知攻击, 直接全图匹配)
 *   评分 ≥ 70                → T2_SYNC     (高威胁, 同步回溯)
 *   评分 ≥ 40                → T2_ASYNC    (中威胁, 异步分析)
 *   评分 ≥ 20                → MARK        (低威胁, 仅标记)
 *   其余                      → FILTER      (过滤)
 */
static
T1_DISPATCH_LEVEL
PolicyDecideDispatch(
    _In_ SCORE_STRATEGY   Strategy,
    _In_ ULONG            Score,
    _In_ PT1_PAIR_FEATURE f
    )
{
    UNREFERENCED_PARAMETER(f);

    /* 已知攻击模板命中 + 高分 → 直接全图匹配 */
    if (Strategy == SCORE_BY_TEMPLATE && Score >= 80) {
        return T1_DISPATCH_T3_DIRECT;
    }

    if (Score >= 70) return T1_DISPATCH_T2_SYNC;
    if (Score >= 40) return T1_DISPATCH_T2_ASYNC;
    if (Score >= 20) return T1_DISPATCH_MARK;
    return T1_DISPATCH_FILTER;
}

/**************************************************/
/*               IOA 事件入口                        */
/**************************************************/

/*
 * IoaHandleRealTimeMemoryEvent — 实时内存监控事件处理。
 * 对齐 SS ReflectiveDLLDetector OnMemoryAllocation (cpp L1835-1878)
 *   / OnProtectionChange (cpp L1880-1901)。
 *
 * RWX 分配 / RW→RX 保护变更 → PE 预判 → 定向扫描 (MsScanRegionAt)。
 *
 * ※ 死代码: 依赖驱动 Sm 启用 (NtAllocateVirtualMemory/NtProtectVirtualMemory
 *   case 已实现于 SyscallHijack.c:730/748, 但 SmInitialize 未启用), 且
 *   EVENT_PAYLOAD_SYSCALL 参数语义对齐驱动上送 (SyscallHijack.c L453-469):
 *     MemoryAllocate: ParameterBase[1]=实际地址 [3]=实际大小 [5]=PageProtection
 *     MemoryProtect : ParameterBase[1]=地址 [2]=大小 [3]=NewProtection [4]=OldProtection
 *   当前驱动不发送内存事件, 函数实际不可达。
 */
VOID
IoaHandleRealTimeMemoryEvent(
    _In_ PWKD_EVENT_HEADER Event
    )
{
    PEVENT_PAYLOAD_SYSCALL payload;
    ULONG_PTR address = 0;
    SIZE_T size = 0;
    ULONG protect = 0;
    ULONG oldProtect = 0;
    BOOLEAN rwx;
    BOOLEAN writableOld, execOld, execNew, writableNew;
    ULONG sourceProcessId;
    PWKD_MEM_SCAN_RESULT scan;

    if (Event == NULL) return;
    payload = (PEVENT_PAYLOAD_SYSCALL)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
    sourceProcessId = (ULONG)(ULONG_PTR)payload->SourceProcessId;

    if (Event->Type == WkdEvent_MemoryAllocate) {
        /* 对齐 SS OnMemoryAllocation: RWX 分配 + 大块可执行无背衬 */
        address = (ULONG_PTR)payload->ParameterBase[1];
        size    = (SIZE_T)payload->ParameterBase[3];
        protect = (ULONG)(ULONG_PTR)payload->ParameterBase[5];   /* PageProtection */

        rwx = (protect & PAGE_EXECUTE_READWRITE) != 0;
        if (rwx) {
            /* RWX 分配几乎从不合法 (对齐 SS): 若含 PE 结构 → 定向扫描 */
            printf("[IoaMem] RWX alloc pid=%lu addr=0x%p size=%zu\n",
                   sourceProcessId, (void*)address, size);
            if (size >= 4096) {   /* 对齐 SS MIN_PE_SIZE */
                scan = (PWKD_MEM_SCAN_RESULT)malloc(sizeof(WKD_MEM_SCAN_RESULT));
                if (scan != NULL) {
                    MsScanRegionAt(sourceProcessId, address, size, scan);
                    free(scan);
                }
            }
        } else if ((protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0 &&
                   size >= 64 * 1024) {
            /* 大块可执行分配 (手动映射常分配大 RX) — 记录 */
            printf("[IoaMem] Large exec alloc pid=%lu addr=0x%p size=%zu\n",
                   sourceProcessId, (void*)address, size);
        }
    } else if (Event->Type == WkdEvent_MemoryProtect) {
        /* 对齐 SS OnProtectionChange: RW->RX 过渡 (反射加载/手动映射标志) */
        address     = (ULONG_PTR)payload->ParameterBase[1];
        size        = (SIZE_T)payload->ParameterBase[2];
        protect     = (ULONG)(ULONG_PTR)payload->ParameterBase[3];  /* NewProtection */
        oldProtect  = (ULONG)(ULONG_PTR)payload->ParameterBase[4];  /* OldProtection */

        writableOld = (oldProtect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE |
                                     PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
        execOld     = (oldProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                     PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        execNew     = (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                  PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        writableNew = (protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE |
                                  PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;

        if (writableOld && !execOld && execNew && !writableNew) {
            printf("[IoaMem] RW->RX protect pid=%lu addr=0x%p size=%zu\n",
                   sourceProcessId, (void*)address, size);
            if (size >= 4096) {
                scan = (PWKD_MEM_SCAN_RESULT)malloc(sizeof(WKD_MEM_SCAN_RESULT));
                if (scan != NULL) {
                    MsScanRegionAt(sourceProcessId, address, size, scan);
                    free(scan);
                }
            }
        }
    }
}

/**************************************************/
/*      线程劫持时序追踪 (T1055.003)               */
/*                                                  */
/*  Suspend→SetContext→Resume 同线程序列闭合确认。   */
/*  状态挂 AE_PROCESS_PAIR::ThreadHijack,  */
/*  由 Suspend/SetContext/Resume 事件驱动更新。      */
/*  数据源依赖: 驱动补 NtSuspendThread/              */
/*  NtSetContextThread/NtResumeThread case。         */
/**************************************************/

static
VOID
IoapUpdateThreadHijackTracker(
    _In_ PAE_PROCESS_PAIR PairCtx,
    _In_ PWKD_EVENT_HEADER Event
    )
/*++
Routine Description:
    更新线程劫持时序追踪器。按线程 (ThreadId) 关联 Suspend→SetContext→Resume:
      Suspend    → 开启新序列
      SetContext → 距 SuspendTime ≤ THREAD_HIJACK_WINDOW_MS 则标记
      Resume     → 距 SetContextTime ≤ 窗口则序列闭合 → Confirmed
    闭合时回填 BM_SEM_THREAD_HIJACK 语义位 + DEF_BEHAVIOR_FLAG_SET_CONTEXT
    标志，并提升事件 Confidence/Severity，使阶段6 评分链路生效。

Arguments:
    PairCtx - 进程对上下文 (ThreadHijack 追踪器宿主)。
    Event   - 当前事件 (ThreadSuspend/ThreadResume/SetThreadContext)。
--*/
{
    PEVENT_PAYLOAD_THREAD_OP payload;
    PTHREAD_HIJACK_TRACKER tracker;
    HANDLE tid;
    LARGE_INTEGER now;
    ULONG64 elapsedMs;

    if (!PairCtx || !Event) {
        return;
    }

    payload = (PEVENT_PAYLOAD_THREAD_OP)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
    tracker = &PairCtx->ThreadHijack;
    tid = payload->ThreadId;
    now = Event->Timestamp;
    GetSystemTimeAsFileTime((PFILETIME)&now);

    switch (Event->Type) {
    case WkdEvent_ThreadSuspend:
        /* 开启新序列: 重置并记录挂起线程 */
        tracker->TrackedThreadId = tid;
        tracker->SuspendTime = now;
        tracker->SetContextTime.QuadPart = 0;
        tracker->ResumeTime.QuadPart = 0;
        tracker->SuspendSeen = TRUE;
        tracker->SetContextSeen = FALSE;
        tracker->Confirmed = FALSE;
        break;

    case WkdEvent_SetThreadContext:
        /* 跨进程 SetContext 本身即可疑 (对齐 SS OnContextChangeInternal
           L1825-1861): 即使无挂起前置, 跨进程修改另一进程线程上下文
           是强注入信号。提升事件供分类器/评分链路消费。 */
        if ((ULONG)(ULONG_PTR)payload->SourceProcessId !=
            (ULONG)(ULONG_PTR)payload->TargetProcessId) {
            Event->BehaviorFlags |= DEF_BEHAVIOR_FLAG_SET_CONTEXT;
            if (Event->Confidence < 60) {
                Event->Confidence = 60;
            }
            if (Event->Severity < DefThreatSeverity_Medium) {
                Event->Severity = DefThreatSeverity_Medium;
            }
        }
        /* 时序路径: 需同线程 + 窗口内前置挂起, 否则不构成劫持序列 */
        if (!tracker->SuspendSeen || tracker->TrackedThreadId != tid) {
            break;
        }
        elapsedMs = (now.QuadPart - tracker->SuspendTime.QuadPart) / 10000;
        if (elapsedMs <= THREAD_HIJACK_WINDOW_MS) {
            tracker->SetContextTime = now;
            tracker->SetContextSeen = TRUE;
        }
        break;

    case WkdEvent_ThreadResume:
        /* 需同线程 + 窗口内 SetContext 前置, 序列闭合 → 确认劫持 */
        if (!tracker->SetContextSeen || tracker->TrackedThreadId != tid) {
            break;
        }
        elapsedMs = (now.QuadPart - tracker->SetContextTime.QuadPart) / 10000;
        if (elapsedMs <= THREAD_HIJACK_WINDOW_MS) {
            tracker->ResumeTime = now;
            tracker->Confirmed = TRUE;
            tracker->Confidence = 85;   /* 对齐 IoaComputeInjectionConfidence ThreadHijacking 基准 */
            /* 挂起时长维度 (对齐 SS CalculateRiskScore: >500ms +5) */
            elapsedMs = (now.QuadPart - tracker->SuspendTime.QuadPart) / 10000;
            if (elapsedMs > 500) {
                tracker->Confidence = min(90, tracker->Confidence + 5);
            }
            tracker->ConfirmedTime = now;

            /* 回填语义位 + 事件标志, 使阶段6 评分链路生效 */
            BM_SEM_SET(&PairCtx->InteractionBitmap, BM_SEM_THREAD_HIJACK);
            Event->BehaviorFlags |= DEF_BEHAVIOR_FLAG_SET_CONTEXT;
            if (Event->Confidence < tracker->Confidence) {
                Event->Confidence = tracker->Confidence;
            }
            if (Event->Severity < DefThreatSeverity_High) {
                Event->Severity = DefThreatSeverity_High;
            }
        }
        break;

    default:
        return;
    }

    PairCtx->DirtyFlags |= IOA_PAIR_DIRTY_THREAD_HIJACK;
}

_Use_decl_annotations_
NTSTATUS
IoaObserve(
    _Inout_ PAE_PROCESS_PAIR Pair,
    _In_ const PWKD_EVENT_HEADER Event
    )
/*++
Routine Description:
    IOA 引擎 — 事件驱动入口。Pipeline 架构:

       1. 进程节点获取 (ProcessCreate → 谱系插入; 其他 → 按 PID 查)
       2. 边聚合 + PairContext + EdgeId 预生成 (不变)
       3. IoaCollectFeatures — Tier1 纯数据采集 (填充 T1Feature)
       4. T1Evaluate — 单事件规则匹配 + 行为标志分流
       5. IoapHandleDynamicEdge — 环形缓冲区写入
       6. Policy + Scorer + Dispatch
          ├─ PolicyAnalyze       → 选择评分策略
          ├─ IoaScorer_Evaluate  → 按策略计算原始评分
          ├─ Scorer_ApplyEwmaDecay → EWMA 平滑 + 时间衰减
          └─ PolicyDecideDispatch → 分级调度 (T2/T3)
       7. 持久化

Arguments:
    Event — 已解析的 WKD_EVENT_HEADER。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PWKD_PROCESS sourceWkdProcess = NULL, targetWkdProcess = NULL;
    PIOA_AGGREGATE_EDGE aggEdge = NULL;
    IOA_GRAPH_EDGE_TYPE edgeType;
    ULONG rawScore;
    ULONG finalScore;
    T1_DISPATCH_LEVEL level;
    BOOLEAN injConfirmed = FALSE;   /* 阶段4.5 注入分类确认 */
    ULONG injFinalRisk = 0;         /* 阶段4.5 注入风险分 */

    if (!Pair || !Event) return STATUS_INVALID_PARAMETER;
    if (!CoAcquireRundownProtection(&WkdIoaEngine.RundownRef)) {
        return STATUS_REQUEST_ABORTED;
    }

    InterlockedIncrement(&WkdIoaEngine.Statistics.EventsIngested);

    /* ── 阶段1: 进程节点获取 ──
     * 实体创建唯一出口已上移至 OrcpWkdMessageDispatcher 分发层
     * (IoapHandleProcessCreate / PsThreadAttachProcess)，此处仅按 PID 反查
     * 已建立的节点。ProcessCreate 经 PsLookupWkdProcessByStrictProcessId 取得刚创建的
     * 节点（IoapHandleProcessCreate 已回填 Event->Source/TargetProcessId）。 */
    {
        HANDLE sourceProcessId, targetProcessId;

        //status = NtfExtractEventPids(Event, &sourceProcessId, &targetProcessId);
        //if (NT_SUCCESS(status)) goto Cleanup;

        switch (Event->Type) {
        case WkdEvent_ThreadCreate:
        case WkdEvent_RemoteThreadCreate: {
            PEVENT_PAYLOAD_THREAD_CREATE payload =
                (PEVENT_PAYLOAD_THREAD_CREATE)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
            sourceProcessId = (ULONG)(ULONG_PTR)payload->CreatorProcessId;
            targetProcessId = (ULONG)(ULONG_PTR)payload->ProcessId;

            /*
             * Shellcode 模式检测（对齐 PS TnpCheckShellcodePatterns，9 种模式）
             * 使用内核采集的 StartBytes 做纯用户态模式匹配。
             * 命中时设置 SHELLCODE_PATTERN 标志，后续评分自动 +300。
             */
            //if (payload->StartBytesSize >= 64 &&
            //    !(payload->InjectIndicators & 0x00000080)) {
            //    if (T1DetectShellcodePatterns(payload->StartBytes,
            //                                  payload->StartBytesSize)) {
            //        payload->InjectIndicators |= 0x00000080; /* WKD_MSG_INJECT_SHELLCODE_PATTERN */
            //    }
            //}

            /*
             * 注入评分计算（对齐 PS TnpCalculateInjectionScore / TnpCalculateRiskLevel）
             * 将内核采集的 InjectIndicators 转换为 0-1000 评分 + 风险等级。
             * 权重完全对齐 PS:
             *   WKD_INJECT_REMOTE_THREAD    = 100 (PS: TN_SCORE_REMOTE_THREAD)
             *   WKD_INJECT_SUSPENDED_START  = 50  (PS: TN_SCORE_SUSPENDED_START)
             *   WKD_INJECT_UNBACKED_START   = 200 (PS: TN_SCORE_UNBACKED_START)
             *   WKD_INJECT_RWX_START        = 250 (PS: TN_SCORE_RWX_START)
             *   WKD_INJECT_CROSS_SESSION    = 100 (PS: TN_SCORE_CROSS_SESSION)
             *   WKD_INJECT_SYSTEM_TARGET    = 150 (PS: TN_SCORE_SYSTEM_TARGET)
             *   WKD_INJECT_ELEVATED_SOURCE  = 50  (PS: TN_SCORE_ELEVATED_SOURCE)
             *   WKD_INJECT_SHELLCODE_PATTERN= 300 (PS: TN_SCORE_SHELLCODE_PATTERN)
             *   WKD_INJECT_PROTECTED_TARGET = 200 (PS: TN_SCORE_PROTECTED_TARGET)
             *   WKD_INJECT_UNUSUAL_ENTRY    = 75  (PS: TN_SCORE_UNUSUAL_ENTRY)
             *   WKD_INJECT_RAPID_CREATION   = 100 (PS: TN_SCORE_RAPID_CREATION)
             */
            if (payload->InjectionScore == 0 && payload->InjectIndicators != 0) {
                ULONG score = 0;
                ULONG ind = payload->InjectIndicators;

                if (ind & 0x00000001) score += 100;  /* WKD_MSG_INJECT_REMOTE_THREAD */
                if (ind & 0x00000002) score += 50;   /* WKD_MSG_INJECT_SUSPENDED_START */
                if (ind & 0x00000004) score += 200;  /* WKD_MSG_INJECT_UNBACKED_START */
                if (ind & 0x00000008) score += 250;  /* WKD_MSG_INJECT_RWX_START */
                if (ind & 0x00000010) score += 100;  /* WKD_MSG_INJECT_CROSS_SESSION */
                if (ind & 0x00000020) score += 150;  /* WKD_MSG_INJECT_SYSTEM_TARGET */
                if (ind & 0x00000040) score += 50;   /* WKD_MSG_INJECT_ELEVATED_SOURCE */
                if (ind & 0x00000080) score += 300;  /* WKD_MSG_INJECT_SHELLCODE_PATTERN */
                if (ind & 0x00000100) score += 200;  /* WKD_MSG_INJECT_PROTECTED_TARGET */
                if (ind & 0x00000200) score += 75;   /* WKD_MSG_INJECT_UNUSUAL_ENTRY */
                if (ind & 0x00000400) score += 100;  /* WKD_MSG_INJECT_RAPID_CREATION */

                if (score > 1000) score = 1000;
                payload->InjectionScore = score;

                /* 风险等级（对齐 PS: None<100, Low<300, Medium<500, High<700, Critical>=700） */
                if (score >= 700)      payload->RiskLevel = 4;  /* Critical */
                else if (score >= 500) payload->RiskLevel = 3;  /* High */
                else if (score >= 300) payload->RiskLevel = 2;  /* Medium */
                else if (score >= 100) payload->RiskLevel = 1;  /* Low */
                else                   payload->RiskLevel = 0;  /* None */
            }

            /*
             * 同步回 Event 的 Severity 和 Confidence（基于评分覆盖）
             */
            if (payload->InjectionScore >= 300) {
                Event->Severity = DefThreatSeverity_High;
                Event->Confidence = (USHORT)min(900, payload->InjectionScore + 200);
            } else if (payload->InjectionScore >= 100) {
                Event->Severity = DefThreatSeverity_Medium;
                Event->Confidence = (USHORT)min(600, payload->InjectionScore + 100);
            }

            break;
        }
        case WkdEvent_FileWrite:
        case WkdEvent_FileRename:
        case WkdEvent_FileDelete: {
            /* 文件事件（FBE 迁移 2026-08）：前两字段 SourceProcessId/TargetProcessId
             * 与 EVENT_PAYLOAD_SYSCALL 布局一致，按单进程事件解析节点 */
            PEVENT_PAYLOAD_FILE_EVENT payload =
                (PEVENT_PAYLOAD_FILE_EVENT)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
            sourceProcessId = (ULONG)(ULONG_PTR)payload->SourceProcessId;
            targetProcessId = (ULONG)(ULONG_PTR)payload->TargetProcessId;
            break;
        }
        case WkdEvent_NamedPipeCreate: {
            /* 命名管道创建（NamedPipeMonitor 迁移 2026-08）：单进程事件，
             * Source=Target=创建者，供因果图 ListensOn 边（服务端监听语义） */
            PEVENT_PAYLOAD_NAMED_PIPE payload =
                (PEVENT_PAYLOAD_NAMED_PIPE)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
            sourceProcessId = (ULONG)(ULONG_PTR)payload->SourceProcessId;
            targetProcessId = (ULONG)(ULONG_PTR)payload->TargetProcessId;
            break;
        }
        case WkdEvent_ImageLoad: {
            /* 镜像加载（2026-08-09 镜像职责收敛）：单进程事件，
             * Source=Target=加载进程，供因果图 Executes 边（模块加载语义，
             * DefEdge_Executes 自环映射已就绪 IoaFsmEngine）。全量分析
             * 由 OrcpWkdMessageDispatcher 桥接 ScanManager.ScanFileDirect。 */
            PEVENT_PAYLOAD_IMAGE_LOAD payload =
                (PEVENT_PAYLOAD_IMAGE_LOAD)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
            sourceProcessId = (ULONG)(ULONG_PTR)payload->SourceProcessId;
            targetProcessId = (ULONG)(ULONG_PTR)payload->TargetProcessId;
            break;
        }
        default: {
            sourceProcessId = Pair->SourceProcessId;
            targetProcessId = Pair->TargetProcessId;

            /* 实时内存监控 (对齐 SS OnMemoryAllocation/OnProtectionChange, cpp L1835-1901)
               ※ 死代码: 依赖驱动 Sm 启用 (NtAllocateVirtualMemory/NtProtectVirtualMemory
               上送), 当前无内存事件到达 */
   /*         if (Event->Type == WkdEvent_MemoryAllocate ||
             Event->Type == WkdEvent_MemoryProtect) {
                 IoaHandleRealTimeMemoryEvent(Event);
             }*/
            break;
        }
        }

        status = PsLookupWkdProcessByProcessId(NULL, sourceProcessId, &sourceWkdProcess);
        if (!NT_SUCCESS(status)) goto Cleanup;
        status = PsLookupWkdProcessByProcessId(NULL, targetProcessId, &targetWkdProcess);
        if (!NT_SUCCESS(status)) goto Cleanup;
    }

    /* ── 阶段1b: 统计基线喂入 (SS AnomalyDetector 迁移 2026-08-05) ──
     * 事件窗口计数 → 阶段6 RaCheckForAnomaly 检测统计异常。
     * 0x80 IOC 段事件在 RaFeedEvent 内部跳过 (防攻击流量驯化基线)。 */
    //if (WkdIoaEngine.RateAnalyzer) {
    //    RaFeedEvent(WkdIoaEngine.RateAnalyzer, Event);
    //}

    /* ── 阶段2: 边聚合 + PairContext ── */
    edgeType = IoaMapEventToEdgeType(Event->Type);

    if (!DefIsNullNodeId(sourceWkdProcess->NodeId) &&
        !DefIsNullNodeId(targetWkdProcess->NodeId) &&
        edgeType != DefEdge_Unknown) {

        aggEdge = IoaFindOrCreateAggregateEdge(NULL,
            sourceWkdProcess->NodeId, targetWkdProcess->NodeId,
            edgeType, Event->Timestamp);
        if (!aggEdge) goto Cleanup;
        /* 将事件所携带的边插入聚合边 */
        IoaUpdateAggregateEdge(aggEdge, Event);

        IoaAggregateEdgeAttachProcessPair(Pair, aggEdge);
        // PairContext_RefreshScore(pair, sourceWkdProcess);

        /* FindOrCreate 返回已 pin 的边, 本作用域用毕归还引用 (→ 仅剩表引用)。
         * pair->EdgeAgg 保留裸指针 (既有语义, 由过期清理摘链保护), 此处不额外 pin。 */
        IoaDereferenceAggregateEdge(aggEdge);

        Pair->LastSeen = Event->Timestamp;
        InterlockedIncrement64(&Pair->SequenceNumber);
        Pair->DirtyFlags |= IOA_PAIR_DIRTY_TIER1;

        /* 时序位图更新 (写入 T1Feature, 供 60s 窗口衰减) */
        //if (edgeType < 64) {
        //    InterlockedOr64(
        //        (LONG64 volatile*)&pair->T1Feature.RecentEdgeMask,
        //        1ULL << (ULONGLONG)edgeType);
        //    pair->T1Feature.EdgeLastSeen[edgeType] = Event->Timestamp;
        //}
        
    }

    /* ── 阶段3: Tier1 纯特征采集 (语义层清零 + 速率/谱系/衰减) ── */
    //IoaCollectFeatures(WkdIoaEngine.Tier1, pair, sourceWkdProcess, targetWkdProcess,
    //                   Event->Timestamp);

    /* ── 阶段4: Tier1 语义进化 (数据层写入 + 多轮推导) ── */
    //T1Evaluate(WkdIoaEngine.Tier1, edgeType, Event, sourceWkdProcess, targetWkdProcess, pair);
    //WkdIoaEngine.Statistics.T1Evaluations++;

    /* ── 阶段4.5: 注入类型分类 ──
     * 移植 ShadowStrike ClassifyFromEvents。
     * 在 T1 语义规则之后补充参数级精确判定 (起始地址合法性区分子类),
     * 并回填注入语义位/事件标志。仅对注入相关边类型调用以减少开销。
     * 死代码模式 (镂空/APC/劫持/区段映射) 依赖驱动补 syscall case, 见
     * IoaInjectionClassifier.h 数据源依赖说明。 */
    //if (pair &&
    //    (edgeType == DefEdge_InjectsInto ||
    //     edgeType == DefEdge_Hollows ||
    //     edgeType == DefEdge_Allocates ||
    //     edgeType == DefEdge_WritesTo ||
    //     edgeType == DefEdge_Protects ||
    //     edgeType == DefEdge_Opens)) {
    //    WKD_INJECTION_TYPE injType;
    //    ULONG injConf;
    //    ULONG injRisk;

    //    if (NT_SUCCESS(IoaClassifyInjection(pair, Event, sourceWkdProcess, targetWkdProcess,
    //                                        &injType, &injConf, &injRisk))) {
    //        if (injType != WkdInjection_Unknown) {
    //            /* 注入专用白名单豁免 (三步: 进程对+受保护目录+签名+LOLBin)。
    //             * 命中则不提升风险/严重度, 抑制告警。 */
    //            if (!ExemptsShouldWhitelistInjection(sourceWkdProcess, targetWkdProcess)) {
    //                injConfirmed = TRUE;
    //                injFinalRisk = injRisk;
    //                /* 注入置信度融合进事件置信度 (取较大者) */
    //                if (injConf > Event->Confidence) {
    //                    Event->Confidence = min(injConf, 100);
    //                }
    //                if (injRisk >= 50) {
    //                    Event->Severity = max(Event->Severity,
    //                                          DefThreatSeverity_High);
    //                }
    //            }
    //        }
    //    }
    //}

    /* ── 阶段4.5b: 线程劫持时序确认 (T1055.003) ──
     * Suspend→SetContext→Resume 同线程序列闭合 → 确认线程劫持。
     * ※ 独立于阶段4.5 门控: DefEdge_AssociatedWith 由 ThreadCreate 也产生,
     *   不能把 Suspend/Resume 事件塞入门控 (会误判正常线程创建)。
     *   数据源依赖: 驱动补 NtSuspendThread/NtSetContextThread/NtResumeThread case。 */
    //if (pair &&
    //    (Event->Type == WkdEvent_ThreadSuspend ||
    //     Event->Type == WkdEvent_ThreadResume ||
    //     Event->Type == WkdEvent_SetThreadContext)) {
    //    IoapUpdateThreadHijackTracker(pair, Event);
    //}

    /* ── 阶段4.6: 序列规则匹配 (ShadowStrike PatternMatcher 迁移, 2026-08) ──
     * 与阶段4.5 注入分类器并列。状态宿主 = PairCtx (进程对粒度)。
     * 默认 EnableSequenceRules=FALSE 不执行 (死代码开关, 对齐
     * PolicyEngine.EnableRuntimeRules)。命中产分与注入风险合并,
     * 在阶段6c2 进 finalScore (触发 T2/T3 分级 + VerdictEngine 融合),
     * 告警由引擎内部构造 IOA_ALERT → IoaPersistQueueEnqueue。 */
    //if (pair && edgeType != DefEdge_Unknown) {
    //    ULONG seqScore = 0;
    //    PolicyEngine_EvaluateSequenceRules(pair, Event, sourceWkdProcess, targetWkdProcess,
    //                                       edgeType, &seqScore);
    //    if (seqScore > 0 && seqScore > injFinalRisk) {
    //        injConfirmed = TRUE;       /* 复用现有"确认"提升路径 */
    //        injFinalRisk = seqScore;
    //    }
    //}

    /* ── 阶段4.7: 命令行深度分析 (ShadowStrike CommandLineParser 迁移, 2026-08) ──
     * 仅 ProcessCreate 事件；默认 g_IoaCmdLineAnalyzerEnabled=FALSE 死代码开关
     * (对齐 EnableRuntimeRules/EnableSequenceRules)。调用 CmdLineAnalyzer 的
     * WpaAnalyzeCommandLine 10 类检测 + Base64 解码。命中产分复用阶段6c2
     * injConfirmed 提升 finalScore 路径 (触发 T2/T3 分级 + VerdictEngine 融合)。
     * 接入时在此构造 IOA_ALERT → IoaPersistQueueEnqueue。 */
    //if (g_IoaCmdLineAnalyzerEnabled && sourceWkdProcess &&
    //    Event->Type == WkdEvent_ProcessCreate) {
    //    PWKD_PROCESS clpNode = targetWkdProcess ? targetWkdProcess : sourceWkdProcess;
    //    PCWSTR clpCmdLine = (clpNode->CommandLine && clpNode->CommandLine->Buffer)
    //                        ? clpNode->CommandLine->Buffer : NULL;
    //    PCWSTR clpImage = (clpNode->ImageFileName && clpNode->ImageFileName->Buffer)
    //                      ? clpNode->ImageFileName->Buffer
    //                      : (clpNode->ImagePath && clpNode->ImagePath->Buffer)
    //                        ? clpNode->ImagePath->Buffer : NULL;

    //    if (clpCmdLine) {
    //        WPA_CMDLINE_RESULT clpResult;

    //        WpaAnalyzeCommandLine(clpCmdLine, clpImage, &clpResult);
    //        if (clpResult.SuspicionScore > 0) {
    //            if (clpResult.SuspicionScore > injFinalRisk) {
    //                injConfirmed = TRUE;
    //                injFinalRisk = clpResult.SuspicionScore;
    //            }
    //            /* TODO(接入): 构造 IOA_ALERT → IoaPersistQueueEnqueue */
    //        }
    //    }
    //}

    /* ── 阶段4.8: 进程环境分析 (ShadowStrike EnvironmentMonitor 迁移, 2026-08) ──
     * 仅 ProcessCreate 事件；默认 g_IoaEnvironmentAnalyzerEnabled=FALSE 死代码开关
     * (对齐 g_IoaCmdLineAnalyzerEnabled)。调用 IocProcessEnrich 的 IpeAnalyzeEnvironment
     * 读取目标进程 PEB 环境块, 6 维度检测 (PATH 可写/用户/可疑条目、代理劫持 T1090.001、
     * TEMP 覆盖、Base64·Hex 编码 T1027、高熵 Shannon>4.5、变量数>500)。
     * 命中产分复用阶段6c2 injConfirmed 提升 finalScore 路径 (触发 T2/T3 分级 +
     * VerdictEngine 融合)。接入时在此构造 IOA_ALERT → IoaPersistQueueEnqueue,
     * 并可将结果写回 WKD_PROCESS.ExtraData (进程表进程画像)。 */
    //if (g_IoaEnvironmentAnalyzerEnabled && sourceWkdProcess &&
    //    Event->Type == WkdEvent_ProcessCreate) {
    //    PWKD_PROCESS envNode = targetWkdProcess ? targetWkdProcess : sourceWkdProcess;
    //    WKD_ENV_ANALYSIS envResult;
    //    ULONG envPid = (ULONG)(ULONG_PTR)envNode->ProcessId;

    //    if (IpeAnalyzeEnvironment(envPid, &envResult) && envResult.SuspicionScore > 0) {
    //        if (envResult.SuspicionScore > injFinalRisk) {
    //            injConfirmed = TRUE;
    //            injFinalRisk = envResult.SuspicionScore;
    //        }
    //        /* TODO(接入): 构造 IOA_ALERT → IoaPersistQueueEnqueue */
    //    }
    //}

    /* ── 阶段4.9: 令牌分析 (ShadowStrike TokenAnalyzer + PrivilegeMonitor 迁移, 2026-08-05) ──
     * 仅 ProcessCreate 事件；默认 g_IoaTokenAnalyzerEnabled=FALSE 死代码开关
     * (对齐 g_IoaCmdLineAnalyzerEnabled)。调用 WpaAnalyzeToken 全量令牌采集 +
     * 无条件攻击检测 (7 类令牌操控 + 高完整性模拟令牌 + 危险特权组合) +
     * WpaRecordBaseline 建立基线。
     * 命中置 sourceWkdProcess->BehaviorFlags 的 DEF_BEHAVIOR_FLAG_PRIVILEGE_ABUSE/ELEVATED
     * (PROCESS_INTRINSIC 掩码位); DEF_BEHAVIOR_FLAG_TOKEN_MANIPULATE 属
     * PAIR_INTERACTION 掩码, 留给 syscall 边 (阶段4.5 上游)。
     * 运行期基线对比 (WpaCheckForEscalation 9 类提权 + WpaDetectUACBypass 10 模式)
     * 逻辑已全量迁移, 触发源待驱动补 NtSetInformationToken/NtAdjustPrivilegesToken
     * syscall 后激活。启用前需在引擎初始化处调用 WpaTokenAnalyzerInitialize()。
     * 产分复用阶段6c2 injConfirmed 提升 finalScore 路径 (触发 T2/T3 分级 +
     * VerdictEngine 融合)。接入时在此构造 IOA_ALERT → IoaPersistQueueEnqueue。 */
    //if (g_IoaTokenAnalyzerEnabled && sourceWkdProcess &&
    //    Event->Type == WkdEvent_ProcessCreate) {
    //    PWKD_PROCESS taNode = targetWkdProcess ? targetWkdProcess : sourceWkdProcess;
    //    ULONG taPid = (ULONG)(ULONG_PTR)taNode->ProcessId;
    //    WPA_TOKEN_INFO taInfo;

    //    if (WpaAnalyzeToken((HANDLE)(ULONG_PTR)taPid, &taInfo) == S_OK) {
    //        if (taInfo.DetectedAttack != WpaAttack_None) {
    //            sourceWkdProcess->BehaviorFlags |= DEF_BEHAVIOR_FLAG_PRIVILEGE_ABUSE;
    //            if (taInfo.IsElevated) {
    //                sourceWkdProcess->BehaviorFlags |= DEF_BEHAVIOR_FLAG_ELEVATED;
    //            }
    //        }

    //        if (taInfo.SuspicionScore > injFinalRisk) {
    //            injConfirmed = TRUE;
    //            injFinalRisk = taInfo.SuspicionScore;
    //        }

    //        /* 建立基线 (供运行期提权对比, 死代码) */
    //        {
    //            PCWSTR taName = (taNode->ImageFileName &&
    //                             taNode->ImageFileName->Buffer)
    //                            ? taNode->ImageFileName->Buffer : NULL;
    //            ULONG taParentProcessId = 0;
    //            PCWSTR taParentName = NULL;
    //            PWKD_PROCESS taParent = taNode->Parent;

    //            if (taParent) {
    //                taParentProcessId = (ULONG)(ULONG_PTR)taParent->ProcessId;
    //                taParentName = (taParent->ImageFileName &&
    //                                taParent->ImageFileName->Buffer)
    //                               ? taParent->ImageFileName->Buffer : NULL;
    //            }
    //            WpaRecordBaseline((HANDLE)(ULONG_PTR)taPid, taName,
    //                              (HANDLE)(ULONG_PTR)taParentProcessId, taParentName);
    //        }

    //        /* TODO(接入): 构造 IOA_ALERT → IoaPersistQueueEnqueue */
    //    }
    //}

    /* ── 阶段4.9b: token 操作 syscall 事件 → 运行期基线对比 (PrivilegeMonitor 迁移 2026-08-06) ──
     * 驱动上送 NtAdjustPrivilegesToken/NtDuplicateToken/NtSetInformationToken/
     * NtImpersonateThread 事件 (消息 0x100C-0x100F)，对源进程调用
     * WpaCheckForEscalation: 重采当前令牌对比创建时基线 (阶段4.9 WpaRecordBaseline
     * 建立)，判定 9 类提权 (完整性升高/敏感特权新增/非提权→提权/AuthId 变化/跨会话
     * 进 Session0) + UAC 绕过 10 模式 (WpaDetectUACBypass)。
     * 驱动侧令牌句柄无进程反查 → 非模拟类 TargetProcessId 回退源进程；本分支对
     * sourceWkdProcess (源进程) 触发即可覆盖；Impersonate 事件的 targetWkdProcess 为被模拟线程所属
     * 进程，源进程 (模拟发起者) 的令牌状态同样需要复查。
     * 提权命中置 sourceWkdProcess 行为标志 (PROCESS_INTRINSIC) + 产分复用阶段6c2
     * injConfirmed 提升 finalScore 路径 (触发 T2/T3 分级 + VerdictEngine 融合)。
     * tkEvent 归引擎事件队列所有 (WpaCheckForEscalation 已入队), 调用方不释放。 */
    //if (g_IoaTokenAnalyzerEnabled && sourceWkdProcess &&
    //    (Event->Type == WkdEvent_TokenAdjustPrivileges ||
    //     Event->Type == WkdEvent_TokenDuplicate ||
    //     Event->Type == WkdEvent_TokenSetInformation ||
    //     Event->Type == WkdEvent_TokenImpersonate)) {
    //    PWPA_ESCALATION_EVENT tkEvent = NULL;
    //    ULONG tkPid = (ULONG)(ULONG_PTR)sourceWkdProcess->ProcessId;

    //    if (WpaCheckForEscalation((HANDLE)(ULONG_PTR)tkPid, &tkEvent) == S_OK && tkEvent) {
    //        sourceWkdProcess->BehaviorFlags |= DEF_BEHAVIOR_FLAG_PRIVILEGE_ABUSE;
    //        if (tkEvent->NewIsElevated) {
    //            sourceWkdProcess->BehaviorFlags |= DEF_BEHAVIOR_FLAG_ELEVATED;
    //        }
    //        if (tkEvent->SuspicionScore > injFinalRisk) {
    //            injConfirmed = TRUE;
    //            injFinalRisk = tkEvent->SuspicionScore;
    //        }
    //        /* TODO(接入): 构造 IOA_ALERT → IoaPersistQueueEnqueue */
    //    }
    //}

    /* ── 阶段4.9c: 文件事件 → 勒索行为评分 (FBE 迁移 2026-08) ──
     * 驱动上送文件写/重命名/删除/创建/卷影删除事件（0x1301-0x1306），对源进程调用
     * IoaRansomware_UpdateScore：高熵写/勒索扩展名变更/大量删除/勒索信/Canary/卷影
     * 触碰累计评分，命中置 DEF_BEHAVIOR_FLAG_RANSOMWARE_* 并产分复用阶段6c2
     * injConfirmed 提升路径 (触发 T2/T3 + VerdictEngine 融合)。
     * 死代码开关: g_IoaFileBehaviorAnalyzerEnabled=FALSE（对齐 g_IoaCmdLine
     * AnalyzerEnabled 模式）。驱动已补 FileEntropy（Q16）/IsCanary(Flags bit0)/
     * shadow 事件源（0x1306），高熵/Canary/卷影分支现已可达。 */
    //if (g_IoaFileBehaviorAnalyzerEnabled && sourceWkdProcess &&
    //    (Event->Type == WkdEvent_FileWrite ||
    //     Event->Type == WkdEvent_FileRename ||
    //     Event->Type == WkdEvent_FileDelete ||
    //     Event->Type == WkdEvent_FileCreate ||
    //     Event->Type == WkdEvent_FileShadowCopyDelete)) {
    //    PEVENT_PAYLOAD_FILE_EVENT fPayload =
    //        (PEVENT_PAYLOAD_FILE_EVENT)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
    //    WKD_BEHAVIOR_EVENT bev;
    //    PCWSTR path = NULL;
    //    size_t pathLen = 0;

    //    RtlZeroMemory(&bev, sizeof(bev));
    //    switch (Event->Type) {
    //    case WkdEvent_FileWrite:  bev.Type = WKD_EVT_FILE_WRITE;  break;
    //    case WkdEvent_FileRename: bev.Type = WKD_EVT_FILE_RENAME; break;
    //    case WkdEvent_FileDelete: bev.Type = WKD_EVT_FILE_DELETE; break;
    //    case WkdEvent_FileCreate: bev.Type = WKD_EVT_FILE_CREATE; break;
    //    case WkdEvent_FileShadowCopyDelete: bev.Type = WKD_EVT_SHADOW_COPY_DELETE; break;
    //    default: break;
    //    }
    //    bev.TargetProcessId = (ULONG)(ULONG_PTR)fPayload->TargetProcessId;

    //    /* 驱动补源（迁移 2026-08）：FileEntropy（Q16 高熵分支）与 IsCanary（Flags bit0） */
    //    bev.FileEntropy = fPayload->FileEntropy;
    //    bev.IsCanary = (fPayload->Flags & DEF_FILE_FLAG_CANARY) ? TRUE : FALSE;

    //    /* 路径借用指针（指向 EVENT_PAYLOAD_FILE_EVENT 内嵌路径，IoaObserve 内有效） */
    //    if (fPayload->FilePath && fPayload->FilePath->Buffer &&
    //        fPayload->FilePath->Length > 0) {
    //        path = fPayload->FilePath->Buffer;
    //        pathLen = fPayload->FilePath->Length / sizeof(WCHAR);
    //        bev.TargetPath = path;

    //        /* 提取扩展名（含前导点，FileExtension[16] 上限） */
    //        const WCHAR* lastDot = NULL;
    //        for (USHORT i = (USHORT)pathLen; i > 0; i--) {
    //            if (path[i - 1] == L'.') { lastDot = &path[i - 1]; break; }
    //            if (path[i - 1] == L'\\') break;
    //        }
    //        if (lastDot) {
    //            size_t extChars = (size_t)((path + pathLen) - lastDot);
    //            if (extChars < 16) {
    //                RtlCopyMemory(bev.FileExtension, lastDot, extChars * sizeof(WCHAR));
    //                bev.FileExtension[extChars] = L'\0';
    //            }
    //        }
    //    }

    //    IoaRansomware_UpdateScore(&sourceWkdProcess->BehaviorState, &bev);

    //    if (sourceWkdProcess->BehaviorState.DetectionFlags &
    //        (DEF_BEHAVIOR_FLAG_RANSOMWARE_ENC |
    //         DEF_BEHAVIOR_FLAG_RANSOMWARE_DELETE |
    //         DEF_BEHAVIOR_FLAG_RANSOMWARE_SHADOW)) {
    //        sourceWkdProcess->BehaviorFlags |= DEF_BEHAVIOR_FLAG_RANSOMWARE_ENC;
    //        if (sourceWkdProcess->BehaviorState.MaliceScore > injFinalRisk) {
    //            injConfirmed = TRUE;
    //            injFinalRisk = sourceWkdProcess->BehaviorState.MaliceScore;
    //        }
    //    }
    //    /* TODO(接入): 构造 IOA_ALERT → IoaPersistQueueEnqueue */
    //}

    /* ── 阶段4.9d: 文件锁模式关联 (FileLockManager 迁移 2026-08) ──
     * 文件事件触发时对目标文件做锁快照 (FileLockManager_GetLockInfo):
     *   未签名进程持独占锁 + 文档扩展名 → Ransomware 锁模式;
     *   注入进程持锁 → ProcessInjection / DefenseEvasion。
     * 命中置 DEF_BEHAVIOR_FLAG_RANSOMWARE_ENC 并产分复用阶段6c2 injConfirmed
     * 提升路径 (触发 T2/T3 + VerdictEngine 融合, 与 E6 槽位防双计)。
     * 死代码开关: g_IoaLockPatternEnabled=FALSE (对齐 4.9c 惯例)。
     * 注: 锁快照 (RM + 句柄枚举) 成本高, 接入需按需触发。 */
    //if (g_IoaLockPatternEnabled && sourceWkdProcess &&
    //    (Event->Type == WkdEvent_FileWrite ||
    //     Event->Type == WkdEvent_FileRename ||
    //     Event->Type == WkdEvent_FileDelete)) {
    //    PEVENT_PAYLOAD_FILE_EVENT fPayload =
    //        (PEVENT_PAYLOAD_FILE_EVENT)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
    //    if (fPayload->FilePath && fPayload->FilePath->Buffer &&
    //        fPayload->FilePath->Length > 0) {
    //        WKD_FILE_LOCK_INFO lockInfo;
    //        RtlZeroMemory(&lockInfo, sizeof(lockInfo));
    //        if (FileLockManager_GetLockInfo(fPayload->FilePath->Buffer, &lockInfo) == STATUS_SUCCESS &&
    //            lockInfo.IsLocked) {
    //            WKD_THREAT_ASSESSMENT* ta = &lockInfo.ThreatAssessment;
    //            if (ta->DominantPattern == WkdLockPattern_Ransomware ||
    //                ta->DominantPattern == WkdLockPattern_ProcessInjection ||
    //                ta->DominantPattern == WkdLockPattern_DefenseEvasion) {
    //                if (ta->DominantPattern == WkdLockPattern_Ransomware) {
    //                    sourceWkdProcess->BehaviorFlags |= DEF_BEHAVIOR_FLAG_RANSOMWARE_ENC;
    //                }
    //                if (ta->OverallThreatScore > (DOUBLE)injFinalRisk) {
    //                    injConfirmed = TRUE;
    //                    injFinalRisk = (ULONG)ta->OverallThreatScore;
    //                }
    //            }
    //        }
    //        FileLockManager_FreeLockInfo(&lockInfo);
    //    }
    //    /* TODO(接入): 构造 IOA_ALERT → IoaPersistQueueEnqueue */
    //}

    /* ── 阶段4.10: 命名管道事件 → C2/横向移动评分 (NamedPipeMonitor 迁移 2026-08) ──
     * 驱动 minifilter IRP_MJ_CREATE_NAMED_PIPE 上送管道创建事件（0x1307，
     * WkdEvent_NamedPipeCreate）：命中已知 C2 管道名（MSSE-/msagent_/postex_/
     * meterpreter 等）、系统管道冒充（T1036，lsass 等由非预期进程创建）或高熵
     * 随机名。置 C2_COMMUNICATION / LATERAL_MOVEMENT 行为标志，产分复用阶段6c2
     * injConfirmed 提升路径（触发 T2/T3 + VerdictEngine 融合）。
     * 死代码开关: g_IoaNamedPipeAnalyzerEnabled=FALSE（对齐 g_IoaCmdLineAnalyzer
     * Enabled 模式）。驱动与解析器已接线（NamedPipeMonitor.c + NtfpParseNamedPipe）。 */
    //if (g_IoaNamedPipeAnalyzerEnabled && sourceWkdProcess && Event->Type == WkdEvent_NamedPipeCreate) {
    //    PEVENT_PAYLOAD_NAMED_PIPE nPayload =
    //        (PEVENT_PAYLOAD_NAMED_PIPE)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
    //    ULONG nClass = nPayload->Classification;

    //    /* 已知 C2 管道 → C2_COMMUNICATION；系统管道冒充 → LATERAL_MOVEMENT；
    //     * 高熵随机名 → C2_COMMUNICATION（C2 框架随机化管道名） */
    //    if (nClass >= DEF_NPM_CLASS_C2_COBALT && nClass <= DEF_NPM_CLASS_C2_GENERIC) {
    //        sourceWkdProcess->BehaviorFlags |= DEF_BEHAVIOR_FLAG_C2_COMMUNICATION;
    //    } else if (nClass == DEF_NPM_CLASS_SPOOFED_SYSTEM) {
    //        sourceWkdProcess->BehaviorFlags |= DEF_BEHAVIOR_FLAG_LATERAL_MOVEMENT;
    //    } else if (nClass == DEF_NPM_CLASS_HIGH_ENTROPY) {
    //        sourceWkdProcess->BehaviorFlags |= DEF_BEHAVIOR_FLAG_C2_COMMUNICATION;
    //    }

    //    /* 产分：威胁分经 injConfirmed 提升路径进 finalScore（触发 T2/T3 + VerdictEngine） */
    //    if (nPayload->ThreatScore > injFinalRisk) {
    //        injConfirmed = TRUE;
    //        injFinalRisk = nPayload->ThreatScore;
    //    }
    //    /* TODO(接入): 构造 IOA_ALERT → IoaPersistQueueEnqueue */
    //}

    /* ── 阶段4.11: 堆喷聚合 (HeapSpray 迁移 2026-08) ──
     * 分配事件 → IoaHeapSpray_OnAllocate 窗口聚合 + 门控内容采样 + 评分 →
     * 判定 SprayInProgress (评分≥500 且 ≥1MB 且 ≥100 次, 半阈值迟滞)。
     * 地址/大小/保护语义对齐 IoaHandleRealTimeMemoryEvent (L717-719):
     *   ParameterBase[1]=实际地址 [3]=实际大小 [5]=PageProtection。
     * 死代码开关: g_IoaHeapSprayEnabled=FALSE。驱动 SmInitialize 注释态
     * (WkdEntry.c:261) 内存事件不可达; 启用后阶段1 default 分支已消费。 */
    //if (g_IoaHeapSprayEnabled && sourceWkdProcess && Event->Type == WkdEvent_MemoryAllocate) {
    //    PEVENT_PAYLOAD_SYSCALL hsPayload =
    //        (PEVENT_PAYLOAD_SYSCALL)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));

    //    IoaHeapSpray_OnAllocate(
    //        &sourceWkdProcess->BehaviorState.HeapSpray,
    //        (ULONG)(ULONG_PTR)hsPayload->SourceProcessId,
    //        (ULONG_PTR)hsPayload->ParameterBase[1],      /* 实际地址 */
    //        (SIZE_T)hsPayload->ParameterBase[3],         /* 实际大小 */
    //        (ULONG)(ULONG_PTR)hsPayload->ParameterBase[5]);  /* PageProtection */
    //}

    /* ── 阶段5: 环形缓冲区写入 ── */
    // IoapHandleDynamicEdge(Event, sourceWkdProcess, targetWkdProcess, Pair, &Event->EventId);

    /* ── 阶段6: Policy + Scorer + Dispatch ── */
    //if (pair) {
    //    PT1_PAIR_FEATURE f = &pair->T1Feature;
    //    PINTERACTION_BITMAP bm = &pair->InteractionBitmap;

    //    /* 6a. Policy: 分析位图丰富度 → 选择评分策略 */
    //    SCORE_STRATEGY strategy = PolicyAnalyze(f, bm);

    //    /* 6b. Scorer: 按策略计算原始评分 (Context=InteractionBitmap) */
    //    rawScore = IoaScorer_Evaluate(strategy, f, bm);

    //    /* 6c. EWMA 平滑 + 时间衰减 */
    //    // finalScore = Scorer_ApplyEwmaDecay(f, rawScore);
    //    finalScore = rawScore;

    //    /* 6c2. 注入确认提升: 阶段4.5 分类器确认注入且风险达标时,
    //     * 使注入风险分进入累积评分链路 (触发 T2/T3 分级调度)。 */
    //    if (injConfirmed && injFinalRisk >= 50) {
    //        finalScore = max(finalScore, injFinalRisk);
    //    }

    //    /* 6c2b. 堆喷确认提升 (HeapSpray 迁移 2026-08)
    //     * 阶段4.11 聚合判定 SprayInProgress → 评分 (0-1000 → /10 归一)
    //     * max 提升 finalScore → 触发 T2/T3 + VerdictEngine 融合。
    //     * 告警仅一次 (SprayAlerted 置位防重复)。
    //     * 不走 6c3: RA_METRIC_MEM 统计异常与确定性堆喷签名重复计分。 */
    //    if (g_IoaHeapSprayEnabled && sourceWkdProcess &&
    //        sourceWkdProcess->BehaviorState.HeapSpray.SprayInProgress) {
    //        ULONG hsScore = sourceWkdProcess->BehaviorState.HeapSpray.SprayScore;

    //        if (hsScore / 10 > injFinalRisk) {
    //            injConfirmed = TRUE;
    //            injFinalRisk = hsScore / 10;
    //        }

    //        if (!sourceWkdProcess->BehaviorState.HeapSpray.SprayAlerted) {
    //            sourceWkdProcess->BehaviorState.HeapSpray.SprayAlerted = TRUE;
    //            if (WkdIoaEngine.PersistQueue) {
    //                PIOA_ALERT hsAlert = IoaHeapSpray_AllocAlert(
    //                    sourceWkdProcess->NodeId, &sourceWkdProcess->BehaviorState.HeapSpray);
    //                if (hsAlert) {
    //                    IoaPersistQueueEnqueue(WkdIoaEngine.PersistQueue,
    //                                           PersistType_Alert, hsAlert,
    //                                           (PERSIST_SERDE_WRITE_FN)StPersistAlert,
    //                                           TRUE);
    //                }
    //            }
    //        }
    //    }

        /* 6c3. 统计异常提升 (SS AnomalyDetector 迁移 2026-08-05)
         * 进程级 Z-Score/MAD 统计基线检测:
         *  - RaCheckForAnomaly 检测当前事件指标 (观测值 = 10s 窗口计数)
         *  - 异常 → 严重度分 max 提升 finalScore → 触发 T2/T3 + E2 融合
         *  - 严重度 ≥ Medium(60) → 构造 IOA_ALERT 持久化告警 */
        /*if (sourceWkdProcess && WkdIoaEngine.RateAnalyzer) {
            RA_METRIC_TYPE raMetric = RaMapEventTypeToMetric(Event->Type);
            BOOLEAN raIsAnomaly = FALSE;
            RA_ANOMALY_INFO raInfo;

            RtlZeroMemory(&raInfo, sizeof(raInfo));
            RaCheckForAnomaly(WkdIoaEngine.RateAnalyzer, sourceWkdProcess->NodeId,
                              raMetric, &raIsAnomaly, &raInfo);

            if (raIsAnomaly) {
                finalScore = max(finalScore, raInfo.SeverityScore);

                if (raInfo.SeverityScore >= 60 && WkdIoaEngine.PersistQueue) {
                    PIOA_ALERT alert = RaAllocStatAlert(sourceWkdProcess->NodeId, &raInfo);
                    if (alert) {
                        IoaPersistQueueEnqueue(WkdIoaEngine.PersistQueue,
                                               PersistType_Alert, alert,
                                               (PERSIST_SERDE_WRITE_FN)StPersistAlert,
                                               TRUE);
                    }
                }
            }
        }*/

        /* 6d. Policy: 分级调度决策 */
        // level = PolicyDecideDispatch(strategy, finalScore, f);

        /* 记录决策统计 */
        /*if (level <= T1_DISPATCH_T3_DIRECT) {
            InterlockedIncrement64(
                &WkdIoaEngine.Tier1->Decisions[level]);
        }

        if (finalScore >= 20) {
            ULONG64 semWord = BM_SEM_U64(bm);
            printf("[IoaObserve] Strategy=%d Raw=%lu Final=%lu "
                   "Level=%d SemWord=0x%llx SemPop=%lu SrcGen=0x%lx\n",
                   strategy, rawScore, finalScore, level,
                   semWord, f->SemanticPopcount, f->SrcGenealogyFlags);
        }*/

        /* 6e. 触发 Tier2 */
        //if (level >= T1_DISPATCH_T2_ASYNC) {
        //    IoapDispatchTier2(level, pair);
        //}

        /* 6f. 写回进程对累积评分 — VerdictEngine 融合信号 E2 读取
         *     (ThreatDetector 迁移, 2026-08-04)。
         *     Scorer_ApplyEwmaDecay (EWMA 平滑) 被注释未启用, 此处直接
         *     写 rawScore 结果, 不改动既有 level 决策逻辑。
         *     并发安全重构 2026-08-23：持 EwmaLock 与 IoaThreatScorer 锁内
         *     读者互斥（后续启用 EWMA 时该写点即为唯一并发写者）。 */
    //    AcquireSRWLockExclusive(&f->EwmaLock);
    //    f->CumulativeRiskScore = finalScore;
    //    ReleaseSRWLockExclusive(&f->EwmaLock);
    //}

    /* 持久化已由 Orchestrator 统一异步处理 (OrcpWkdMessageDispatcher) */
Cleanup:
    if (targetWkdProcess) PsDereferenceWkdProcess(targetWkdProcess);
    if (sourceWkdProcess) PsDereferenceWkdProcess(sourceWkdProcess);

    CoReleaseRundownProtection(&WkdIoaEngine.RundownRef);
    return status;
}

PWKD_PROCESS
IoaEngine_LookupProcess(
    _In_ GUID NodeId
    )
{
    return PtTreeLookupByNodeId(&WkdProcessTree, NodeId);
}

PWKD_PROCESS
IoaEngine_LookupProcessByPid(
    _In_ ULONG              Pid,
    _In_opt_ PLARGE_INTEGER CreateTime
    )
/*++
Routine Description:
    按 PID 查找进程节点 (当前无调用方)。
    注意: 借出查找 pin (PsLookupWkdProcessByStrictProcessId 契约),
    未来调用方用完须 PsDereferenceWkdProcess 归还。

Arguments:
    Pid        — 进程 ID。
    CreateTime — 可选创建时间精确匹配。

Return Value:
    进程节点指针 (pin 未释放) 或 NULL。
--*/
{
    PWKD_PROCESS result = NULL;
    NTSTATUS _status = PsLookupWkdProcessByStrictProcessId(&WkdProcessTree, (HANDLE)(ULONG_PTR)Pid, CreateTime, &result);
    UNREFERENCED_PARAMETER(_status);
    return result;
}

VOID
IoaEngine_PrintStats(
    VOID
    )
{
    printf("\n");
    printf("========================================\n");
    printf("  IOA Engine Statistics\n");
    printf("========================================\n");
    printf("  Events Ingested:        %lld\n", WkdIoaEngine.Statistics.EventsIngested);
    printf("  Process Nodes:          %lld created / %lld terminated\n",
           WkdIoaEngine.Statistics.ProcessNodesCreated,
           WkdIoaEngine.Statistics.ProcessNodesTerminated);
    printf("  Current Alive:          %lld\n", WkdIoaEngine.Statistics.CurrentProcessCount);
    printf("  Graph Nodes:            %lld\n", WkdIoaEngine.Statistics.GraphNodesCreated);
    printf("  Graph Edges:            %lld created / %lld compacted\n",
           WkdIoaEngine.Statistics.EdgesCreated, WkdIoaEngine.Statistics.EdgesCompacted);
    printf("  Tier 1 Evaluations:     %lld\n", WkdIoaEngine.Statistics.T1Evaluations);
    printf("  Tier 1 Rule Hits:       %lld\n", WkdIoaEngine.Tier1->RuleHits);
    printf("  Tier 1 Features:        %lld\n", WkdIoaEngine.Tier1->FeatureCollects);
    printf("  Tier 2 Backtrack Calls: %lld / Verified: %lld\n",
           WkdIoaEngine.Tier2->TotalCalls, WkdIoaEngine.Tier2->VerificationHits);
    /* FSM stats 从 FsmGetStats 实时读取 */
    {
        ULONG fsmActive = 0, fsmPeak = 0;
        LONG64 fsmProcessed = 0, fsmMatches = 0, fsmTimeouts = 0;
        if (WkdIoaEngine.FsmEngine) {
            FsmGetStats(WkdIoaEngine.FsmEngine, &fsmActive, &fsmPeak,
                        &fsmProcessed, &fsmMatches, &fsmTimeouts);
        }
        printf("  ── FSM Engine ──\n");
        printf("  FSM Events Processed:   %lld\n", fsmProcessed);
        printf("  FSM Accept Hits:        %lld\n", fsmMatches);
        printf("  FSM Active Trackers:    %lld\n", (LONG64)fsmActive);
        printf("  FSM Timeouts:            %lld\n", fsmTimeouts);
    }

    /* Ring Buffer stats 从 GrbGetStats 实时读取 */
    {
        LONG64 rbWritten = 0, rbConsumed = 0, rbDropped = 0;
        LONG64 rbLayers[4] = { 0 };
        if (WkdIoaEngine.RingBuffer) {
            GrbGetStats(WkdIoaEngine.RingBuffer, &rbWritten, &rbConsumed,
                        &rbDropped, rbLayers);
        }
        printf("  ── Ring Buffer ──\n");
        printf("  Ring Buffer Writes:     %lld\n", rbWritten);
        printf("  Ring Buffer Consumed:   %lld\n", rbConsumed);
        printf("  Ring Buffer Drops:      %lld\n", rbDropped);
    }
    printf("  ── Persist ──\n");
    printf("  Persist Enqueued:       %lld / Written: %lld\n",
           WkdIoaEngine.PersistQueue->TotalEnqueued, WkdIoaEngine.PersistQueue->TotalWritten);
    printf("  Scorer Calls:           %lld\n",
           WkdIoaEngine.Scorer->TotalScoresProduced);
    printf("  PairManager Pairs:       %lu (peak=%lu)\n",
           PairManager_GetCount(WkdIoaEngine.PairManager), PairManager_GetPeakCount(WkdIoaEngine.PairManager));
    printf("  EdgeAgg Entries:         %lu\n",
           EdgeAggTable_GetCount(WkdIoaEngine.EdgeAggTable));
    printf("  MITRE Mappings:         %lld\n", WkdIoaEngine.Statistics.MitreMappings);
    printf("========================================\n\n");
}
