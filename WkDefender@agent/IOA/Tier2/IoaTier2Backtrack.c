/**************************************************/
/*  WkDefender — Tier 2 异步有界回溯实现             */
/**************************************************/

#include "IoaTier2Backtrack.h"
#include "../../Process/ProcessTree.h"
#include "IoaFsmEngine.h"
#include "../Tier3/IoaGraphMatcher.h"
#include "../Tier3/IoaGraphWalker.h"
#include "../Tier3/Tier3Engine.h"
#include "../IoaEngine.h"
#include "../IoaProcessPair.h"
#include "../IoaEdgeAggregate.h"

/**************************************************/
/*           BFS 回溯已移除                          */
/*                                                  */
/*  历史: IoapBfsBackward 曾用于 T1 分支的限边类型   */
/*  回溯，但 T2ExtractSubgraph 已实现全量入边遍历    */
/*  （不限边类型），且 consume 端硬编码覆盖了 trigger */
/*  中的 BacktrackEdges，使限边回溯完全无效。         */
/*                                                  */
/*  移除后 T1 分支直接使用 T2ExtractSubgraph，       */
/*  信息更完整（所有入边都收录），无漏报风险。        */
/**************************************************/

/**************************************************/
/*               告警 Serde                         */
/**************************************************/

static
NTSTATUS
T2SerdeAlert(
    _In_ PVOID Data
    )
/*++
Routine Description:
    告警写入的 serde 函数。输出到控制台。
--*/
{
    PIOA_ALERT alert = (PIOA_ALERT)Data;
    if (!alert) return STATUS_INVALID_PARAMETER;

    printf("[Tier2-Alert] ID=%08X Rule=%S Mitre=%S Sev=%d Score=%lu Conf=%lu Desc=%S\n",
           alert->AlertId.Data1, alert->RuleName, alert->MitreId,
           alert->Severity, alert->Score, alert->Confidence,
           alert->Description ? alert->Description : L"");

    return STATUS_SUCCESS;
}

/**************************************************/
/*                   公开 API                       */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
T2Initialize(
    PIOA_TIER2_BACKTRACK* Out,
    PIOA_PERSIST_QUEUE    PersistQueue
    )
{
    PIOA_TIER2_BACKTRACK t2;

    t2 = UtHeapAlloc(sizeof(IOA_TIER2_BACKTRACK));
    if (!t2) return STATUS_NO_MEMORY;

    t2->PersistQueue  = PersistQueue;
    InitializeCriticalSection(&t2->Lock);
    InitializeListHead(&t2->AlertDescHead);
    t2->AlertDescCount = 0;

    t2->AlertWakeEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!t2->AlertWakeEvent) {
        UtHeapFree(t2);
        return STATUS_UNSUCCESSFUL;
    }

    t2->Initialized   = TRUE;
    printf("[Tier2Backtrack] Initialized (async mode)\n");
    *Out = t2;
    return STATUS_SUCCESS;
}

VOID
T2Cleanup(
    PIOA_TIER2_BACKTRACK Engine
    )
{
    PIOA_TIER2_ALERT_DESCRIPTOR desc;

    if (!Engine || !Engine->Initialized) return;

    printf("[Tier2Backtrack] Cleanup: calls=%lld hits=%lld processed=%lld crossvals=%lld\n",
           Engine->TotalCalls, Engine->VerificationHits,
           Engine->TotalProcessed, Engine->CrossValidations);

    /* 清空告警队列 */
    EnterCriticalSection(&Engine->Lock);
    while (!IsListEmpty(&Engine->AlertDescHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&Engine->AlertDescHead);
        desc = CONTAINING_RECORD(entry, IOA_TIER2_ALERT_DESCRIPTOR, Link);
        if (desc->FromFsm && desc->Source.Fsm.Evidence) {
            UtHeapFree(desc->Source.Fsm.Evidence);
        }
        UtHeapFree(desc);
    }
    LeaveCriticalSection(&Engine->Lock);

    if (Engine->AlertWakeEvent) CloseHandle(Engine->AlertWakeEvent);
    DeleteCriticalSection(&Engine->Lock);
    UtHeapFree(Engine);
}

/**************************************************/
/*           FSM → T2 告警入队 (通路修复)           */
/**************************************************/

VOID
T2EnqueueFsmAlert(
    _In_ PIOA_TIER2_BACKTRACK  Engine,
    _In_ PIOA_FSM_EVIDENCE   Evidence,
    _In_ DEF_THREAT_SEVERITY    Severity
    )
/*++
Routine Description:
    FSM 证据包入队到 Tier 2 告警处理队列。
    由 IoaEngine 的 FSM 接受态回调调用。
    深拷贝证据包，插入 AlertDescHead，唤醒 T2 异步线程。

Arguments:
    Engine   — Tier 2 实例。
    Evidence — FSM 输出的证据包 (所有权转移，本函数负责释放)。
    Severity — 触发时的严重等级。

Return Value:
    VOID。
--*/
{
    PIOA_TIER2_ALERT_DESCRIPTOR descT2;
    PIOA_FSM_EVIDENCE copy;

    if (!Engine || !Evidence) {
        if (Evidence) UtHeapFree(Evidence);
        return;
    }

    descT2 = UtHeapAlloc(sizeof(IOA_TIER2_ALERT_DESCRIPTOR));
    if (!descT2) {
        UtHeapFree(Evidence);
        return;
    }

    /* 深拷贝证据包 */
    copy = UtHeapAlloc(sizeof(IOA_FSM_EVIDENCE));
    if (!copy) {
        UtHeapFree(descT2);
        UtHeapFree(Evidence);
        return;
    }
    RtlCopyMemory(copy, Evidence, sizeof(IOA_FSM_EVIDENCE));

    descT2->FromFsm = TRUE;
    descT2->Source.Fsm.Evidence = copy;
    descT2->TriggerSeverity = Severity;
    GetSystemTimeAsFileTime((LPFILETIME)&descT2->Timestamp);

    EnterCriticalSection(&Engine->Lock);
    InsertTailList(&Engine->AlertDescHead, &descT2->Link);
    InterlockedIncrement(&Engine->AlertDescCount);
    Engine->TotalCalls++;
    LeaveCriticalSection(&Engine->Lock);

    /* 唤醒 T2 异步消费线程 */
    SetEvent(Engine->AlertWakeEvent);
}

NTSTATUS
IoaTire2Trackback(
    _In_ PIOA_TIER2_BACKTRACK   Engine,
    _In_ GUID                   SuspectNodeId,
    _In_ GUID                   VictimNodeId,
    _In_opt_ PCWSTR             RuleName,
    _In_ DEF_THREAT_SEVERITY    Severity,
    _In_ LONG64                 SeqNum
    )
/*++
Routine Description:
    简化入队：T1 触发 → 告警描述符入队。
    不再使用 IOA_TIER2_TRIGGER（已弃用）。
    消费端 T2ProcessAlertQueue 直接读取 SuspectNodeId 做子图提取，
    不限边类型（T2ExtractSubgraph 全量回溯）。

Arguments:
    Engine         — Tier 2 实例。
    SuspectNodeId  — 嫌疑节点 GUID。
    VictimNodeId   — 受害节点 GUID。
    RuleName       — 规则名（可 NULL，用于日志）。
    Severity       — 触发严重级。
    SeqNum         — 进程对序列号（用于脏标记跳过）。

Return Value:
    NTSTATUS。
--*/
{
    PIOA_TIER2_ALERT_DESCRIPTOR desc;

    if (!Engine) return STATUS_INVALID_PARAMETER;

    desc = UtHeapAlloc(sizeof(IOA_TIER2_ALERT_DESCRIPTOR));
    if (!desc) return STATUS_NO_MEMORY;

    desc->FromFsm = FALSE;
    WkdCopyGuid(&desc->SrcNodeId, &SuspectNodeId);
    WkdCopyGuid(&desc->TgtNodeId, &VictimNodeId);
    desc->EdgeType      = DefEdge_Unknown;
    desc->BehaviorFlags = 0;
    if (RuleName) {
        wcsncpy_s(desc->Source.T1.RuleName, 64, RuleName, _TRUNCATE);
    } else {
        desc->Source.T1.RuleName[0] = L'\0';
    }
    desc->Source.T1.MitreId[0] = L'\0';
    desc->TriggerSeverity = Severity;
    desc->TriggerSeqNum = SeqNum;
    GetSystemTimeAsFileTime((LPFILETIME)&desc->Timestamp);

    EnterCriticalSection(&Engine->Lock);
    InsertTailList(&Engine->AlertDescHead, &desc->Link);
    InterlockedIncrement(&Engine->AlertDescCount);
    LeaveCriticalSection(&Engine->Lock);

    Engine->TotalCalls++;
    SetEvent(Engine->AlertWakeEvent);

    return STATUS_SUCCESS;
}

/**************************************************/
/*   Tier2 异步入队                                */
/**************************************************/

NTSTATUS
T2EnqueueAsync(
    _In_ PIOA_TIER2_BACKTRACK   Engine,
    _In_ PAE_PROCESS_PAIR PairCtx,
    _In_ DEF_THREAT_SEVERITY    Severity
    )
/*++
Routine Description:
    Tier2 异步入队。携带 SrcNodeId/TgtNodeId 入队。
    消费端 T2ProcessAlertQueue 取出后重建 PairCtx 调用 T2AnalyzeInternal。
--*/
{
    PIOA_TIER2_ALERT_DESCRIPTOR desc;

    if (!Engine) return STATUS_INVALID_PARAMETER;

    desc = UtHeapAlloc(sizeof(IOA_TIER2_ALERT_DESCRIPTOR));
    if (!desc) return STATUS_NO_MEMORY;

    desc->FromFsm = FALSE;
    /* 2026-08-23 pair 键 PID 化: NodeId 经谱系树反查 */
    IoaPairResolveNodeIds(PairCtx, &desc->SrcNodeId, &desc->TgtNodeId);
    desc->EdgeType = DefEdge_Unknown;
    desc->BehaviorFlags = 0;

    desc->Source.T1.RuleName[0] = L'\0';
    desc->Source.T1.MitreId[0] = L'\0';
    desc->TriggerSeverity = Severity;
    desc->TriggerSeqNum = PairCtx->SequenceNumber;
    GetSystemTimeAsFileTime((LPFILETIME)&desc->Timestamp);

    EnterCriticalSection(&Engine->Lock);
    InsertTailList(&Engine->AlertDescHead, &desc->Link);
    InterlockedIncrement(&Engine->AlertDescCount);
    LeaveCriticalSection(&Engine->Lock);

    SetEvent(Engine->AlertWakeEvent);

    return STATUS_SUCCESS;
}

/* 前向声明: 交叉验证函数定义在 T2ProcessAlertQueue 之后 */
static BOOLEAN IoapEvidenceCrossValidate(
    _In_  PIOA_TIER2_BACKTRACK  Engine,
    _In_  PIOA_FSM_EVIDENCE     Evidence,
    _Out_ PULONG                MatchedCount,
    _Out_ PULONG                MissCount
    );

VOID
T2ProcessAlertQueue(
    _In_ PIOA_TIER2_BACKTRACK Engine
    )
/*++
Routine Description:
    异步消费告警描述符队列。
    对每个条目:
      - FromFsm: 调用 IoaEvidenceCrossValidate 做证据包交叉验证
      - From T1:  T2ExtractSubgraph 子图提取 + 特征测量 + 判定

Arguments:
    Engine — Tier 2 实例。

Return Value:
    VOID。
--*/
{
    PIOA_TIER2_ALERT_DESCRIPTOR desc;
    LONG processed = 0;

    if (!Engine || !Engine->Initialized) return;

    EnterCriticalSection(&Engine->Lock);

    while (!IsListEmpty(&Engine->AlertDescHead) && processed < 32) {
        PLIST_ENTRY entry = RemoveHeadList(&Engine->AlertDescHead);
        desc = CONTAINING_RECORD(entry, IOA_TIER2_ALERT_DESCRIPTOR, Link);
        InterlockedDecrement(&Engine->AlertDescCount);
        processed++;

        if (desc->FromFsm) {
            /* ── FSM 证据包交叉验证 + 子图分析 ── */
            ULONG matched = 0, missed = 0;
            PIOA_FSM_EVIDENCE evidence = desc->Source.Fsm.Evidence;

            if (evidence) {
                IoapEvidenceCrossValidate(Engine, evidence, &matched, &missed);
                /* P2: 脏标记跳过 — 若 SequenceNumber 未变化则跳过 BFS/subgraph 分析 */
                {
                    PAE_PROCESS_PAIR pc = NULL;
                    if (WkdIoaEngine.PairManager) {
                        /* 2026-08-23 pair 键 PID 化: GUID → 节点 → PID */
                        PWKD_PROCESS srcN = PtTreeLookupByNodeId(
                            &WkdProcessTree, evidence->SrcProcessNodeId);
                        PWKD_PROCESS tgtN = PtTreeLookupByNodeId(
                            &WkdProcessTree, evidence->TgtProcessNodeId);
                        if (srcN && tgtN &&
                            !srcN->SecCtx.Placeholder && !tgtN->SecCtx.Placeholder) {
                            if (!NT_SUCCESS(AeLookupProcessPair(
                                    srcN->ProcessId, tgtN->ProcessId, &pc))) {
                                pc = NULL;
                            }
                        }
                    }
                    if (pc && desc->TriggerSeqNum > 0 &&
                        pc->SequenceNumber == desc->TriggerSeqNum) {
                        printf("[Tier2Backtrack] FSM skip: pair SeqNum unchanged (%lld)\n",
                               desc->TriggerSeqNum);
                        Engine->TotalProcessed++;
                        UtHeapFree(desc->Source.Fsm.Evidence);
                        AeDereferenceProcessPair(pc);   /* 归还 pair 查找 pin */
                        goto skip_alert;
                    }
                    /* 归还 pair 查找 pin (2026-08-25 HashMap ref/deref 契约;
                     * pc 仅护住上方 SeqNum 复查, 不跨后续子图分析持有) */
                    if (pc) AeDereferenceProcessPair(pc);
                }
                Engine->CrossValidations++;
                /*
                 * 新的 FSM 指导分析:
                 * 利用 FSM 给出的精确 <Src, Tgt> 和边序列，
                 * 以 SrcProcessNodeId 为种子做子图结构分析，
                 * 验证 FSM 推断与图事实的一致性。
                 */
                {
                    T2_ANALYSIS_RESULT analysis;
                    GUID seedId;
                    WkdCopyGuid(&seedId, &evidence->SrcProcessNodeId);

                    RtlZeroMemory(&analysis, sizeof(analysis));

                    /* 提取子图 + 测量特征 */
                    if (NT_SUCCESS(T2ExtractSubgraph(WkdIoaEngine.Graph, seedId,
                                                       T2_BACKTRACK_MAX_DEPTH,
                                                       &analysis.Subgraph))) {
                        T2MeasureFeatures(&analysis.Subgraph, WkdIoaEngine.Graph,
                                         &analysis.Features);

                        /* 使用 FSM 指导做规则树判定 */
                        T2ClassifySubgraph(&analysis.Features, TRUE, &analysis);

                        printf("[Tier2Backtrack] FSM-guided analysis: verdict=%d threatScore=%lu "
                               "reason=%S\n",
                               analysis.Verdict, analysis.ThreatScore, analysis.Reason);

                        if (analysis.Verdict == T2_VERDICT_ATTACK) {
                            Engine->VerificationHits++;
                        }
                    }
                }

                if (missed == 0) {
                    printf("[Tier2Backtrack] FSM evidence FULLY VERIFIED: "
                           "FsmClass=%d matched=%lu missed=%lu threatScore=%lu\n",
                           (int)evidence->FsmClass, matched, missed, evidence->ThreatScore);
                } else {
                    printf("[Tier2Backtrack] FSM evidence PARTIAL: "
                           "FsmClass=%d matched=%lu missed=%lu\n",
                           (int)evidence->FsmClass, matched, missed);
                }

                /* 构造结构化告警（精简版 2026-07） */
                {
                    PIOA_ALERT alert = UtHeapAlloc(sizeof(IOA_ALERT));
                    if (alert) {
                        CoCreateGuid(&alert->AlertId);
                        alert->Timestamp = desc->Timestamp;
                        WkdCopyGuid(&alert->SuspectNodeId,
                                    &evidence->SrcProcessNodeId);
                        WkdCopyGuid(&alert->VictimNodeId,
                                    &evidence->TgtProcessNodeId);
                        alert->RuleName   = L"Tier2FSM";
                        alert->MitreId    = L"";  /* 不再预填，由 Tier3 确认后回填 */
                        alert->Severity   = desc->TriggerSeverity;
                        alert->Score      = evidence->ThreatScore;
                        alert->Confidence = (missed == 0)
                                            ? evidence->ThreatScore
                                            : evidence->ThreatScore * 60 / 100;

                        WCHAR descBuf[256];
                        swprintf_s(descBuf, 256,
                                   L"FSM: FsmClass=%d steps=%lu threatScore=%lu",
                                   (int)evidence->FsmClass,
                                   evidence->CurrentStep,
                                   evidence->ThreatScore);
                        alert->Description = _wcsdup(descBuf);

                        if (Engine->PersistQueue) {
                            IoaPersistQueueEnqueue(Engine->PersistQueue,
                                                 PersistType_Alert, alert,
                                                 T2SerdeAlert, TRUE);
                        }
                    }
                }
            }

            /* ── Tier 3 触发: FSM证据包 → T3DeepForensics (同步) ── */
            if (WkdIoaEngine.Tier3 && desc->Source.Fsm.Evidence) {
                PTIRE3_ATTACK_CHAIN chain = NULL;
                NTSTATUS ts = T3DeepForensics(
                    WkdIoaEngine.Tier3,
                    desc->Source.Fsm.Evidence,
                    &chain);
                if (NT_SUCCESS(ts) && chain) {
                    printf("[Tier2Backtrack] T3 forensics complete: "
                           "chain %08X threatScore=%lu\n",
                           chain->ChainId.Data1, chain->ThreatScore);
                }
                /* T3DeepForensics 接管证据所有权 → 释放 */
                UtHeapFree(desc->Source.Fsm.Evidence);
                desc->Source.Fsm.Evidence = NULL;
            }
skip_alert:
            /* 脏标记跳过路径：evidence 已在 goto 前释放，Tier 3 也跳过 */
            ;

        } else {
            /* ── T1 触发: 重建 PairCtx → T2AnalyzeInternal ── */
            {
                T2_ANALYSIS_RESULT analysis;
                PAE_PROCESS_PAIR asyncPairCtx = NULL;

                if (WkdIoaEngine.PairManager &&
                    !DefIsNullNodeId(desc->SrcNodeId) &&
                    !DefIsNullNodeId(desc->TgtNodeId)) {
                    /* 2026-08-23 pair 键 PID 化: GUID → 节点 → PID */
                    PWKD_PROCESS srcN = PtTreeLookupByNodeId(
                        &WkdProcessTree, desc->SrcNodeId);
                    PWKD_PROCESS tgtN = PtTreeLookupByNodeId(
                        &WkdProcessTree, desc->TgtNodeId);
                    if (srcN && tgtN &&
                        !srcN->SecCtx.Placeholder && !tgtN->SecCtx.Placeholder) {
                        if (!NT_SUCCESS(AeLookupProcessPair(
                                srcN->ProcessId, tgtN->ProcessId, &asyncPairCtx))) {
                            asyncPairCtx = NULL;
                        }
                    }
                }

                if (NT_SUCCESS(T2AnalyzeInternal(
                        Engine, asyncPairCtx, &analysis))) {

                    printf("[Tier2Backtrack] Async analysis: "
                           "verdict=%d threatScore=%lu fsm=%d fsmScore=%lu "
                           "nodes=%lu edges=%lu\n",
                           analysis.Verdict, analysis.ThreatScore,
                           analysis.FsmAccepted,
                           analysis.FsmMaxScore,
                           analysis.Subgraph.NodeCount,
                           analysis.Subgraph.EdgeCount);

                    if (analysis.Verdict >= T2_VERDICT_SUSPICIOUS) {
                        Engine->VerificationHits++;
                    }
                } else {
                    printf("[Tier2Backtrack] Async analysis: "
                           "no PairContext available\n");
                }

                /* 归还 pair 查找 pin (2026-08-25 HashMap ref/deref 契约;
                 * T2AnalyzeInternal 为同步消费, 返回后不再持有) */
                if (asyncPairCtx) AeDereferenceProcessPair(asyncPairCtx);
            }
        }

        Engine->TotalProcessed++;
        // UtHeapFree(desc);
    }

    LeaveCriticalSection(&Engine->Lock);
}

static
BOOLEAN
IoapEvidenceCrossValidate(
    _In_  PIOA_TIER2_BACKTRACK  Engine,
    _In_  PIOA_FSM_EVIDENCE     Evidence,
    _Out_ PULONG                MatchedCount,
    _Out_ PULONG                MissCount
    )
/*++
Routine Description:
    FSM 证据包交叉验证。
    逐条扫描证据包中的边，在 Warm 因果图中查找对应边。

Arguments:
    Engine       — Tier 2 实例。
    Evidence     — FSM 输出的证据包。
    MatchedCount — 输出: 图中找到的边数。
    MissCount    — 输出: 图中未找到的边数。

Return Value:
    TRUE = 验证过程正常完成。
--*/
{
    ULONG matched = 0, missed = 0;
    
    if (!Engine || !Evidence || !MatchedCount || !MissCount)
        return FALSE;

    *MatchedCount = 0;
    *MissCount = 0;

    /* SrcNodeId/TgtNodeId 有效性检查 */
    if (DefIsNullNodeId(Evidence->SrcProcessNodeId) ||
        DefIsNullNodeId(Evidence->TgtProcessNodeId)) {
        *MissCount = Evidence->CurrentStep;
        return TRUE;
    }

    /* 精简交叉验证 (2026-07): States[] 已移除。
       改为通过 PatternIndex 查 Steps[] 定义，在聚合边表中验证边类型存在性。
       详细的参数验证由 Tier3 因果倒推负责。 */
    {
        ULONG patternIdx = Evidence->PatternIndex;
        if (patternIdx < FSM_PATTERN_COUNT) {
            const FSM_PATTERN_TEMPLATE* tmpl = &WkdIoaEngine.FsmEngine->Patterns[patternIdx];
            ULONG maxStep = (Evidence->CurrentStep < tmpl->StateCount)
                          ? Evidence->CurrentStep : tmpl->StateCount - 1;
            for (ULONG i = 0; i < maxStep; i++) {
                PIOA_AGGREGATE_EDGE agg = IoaLookupAggregateEdge(
                    WkdIoaEngine.EdgeAggTable,
                    Evidence->SrcProcessNodeId,
                    Evidence->TgtProcessNodeId,
                    tmpl->Steps[i].TriggerEdge);
                if (agg && agg->ActiveEdgeCount > 0) {
                    matched++;
                } else {
                    missed++;
                }
            }
        }
    }

    *MatchedCount = matched;
    *MissCount    = missed;
    return TRUE;
}

/**************************************************/
/*         P2: 同步 Tier2 评估入口                  */
/**************************************************/

NTSTATUS
T2EvaluateSync(
    _In_  PIOA_TIER2_BACKTRACK  Engine,
    _In_  PAE_PROCESS_PAIR PairCtx,
    _Out_ PT2_ANALYSIS_RESULT   Result
    )
/*++
Routine Description:
    Tier2 同步评估入口 — 直接调用 T2AnalyzeInternal 统一流水线。
--*/
{
    return T2AnalyzeInternal(Engine, PairCtx, Result);
}

/**************************************************/
/*         P2: 局部因果子图提取                      */
/**************************************************/

NTSTATUS
T2ExtractSubgraph(
    _In_  PIOA_CARSAL_GRAPH  Graph,
    _In_  GUID               SeedNodeId,
    _In_  ULONG              MaxDepth,
    _Out_ PT2_SUBGRAPH       Subgraph
    )
/*++
Routine Description:
    双向 BFS 提取局部因果子图。
    沿入边回溯 MaxDepth 层，沿出边前向追踪 1 层。
    节点数上限 64，边数上限 128，超出截断。

Arguments:
    Graph      — 因果图
    SeedNodeId — 种子节点 GUID
    MaxDepth   — 回溯深度上限
    Subgraph   — 输出: 提取的子图

Return Value:
    NTSTATUS
--*/
{
    PIOA_CARSAL_GRAPH_NODE node;
    GUID queue[T2_SUBGRAPH_MAX_NODES];
    ULONG qHead = 0, qTail = 0;
    GUID visited[T2_SUBGRAPH_MAX_NODES];
    ULONG visitedCount = 0;

    if (!Graph || !Subgraph || DefIsNullNodeId(SeedNodeId))
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Subgraph, sizeof(T2_SUBGRAPH));
    WkdCopyGuid(&Subgraph->SeedNodeId, &SeedNodeId);

    /* 查找种子节点 */
    node = IoaCarsalGraphLookupNode(Graph, SeedNodeId);
    if (!node) return STATUS_NOT_FOUND;

    /* BFS 初始化 */
    WkdCopyGuid(&queue[qTail], &SeedNodeId); qTail++;
    WkdCopyGuid(&visited[visitedCount], &SeedNodeId); visitedCount++;
    Subgraph->NodeIds[Subgraph->NodeCount] = SeedNodeId;
    Subgraph->NodeCount = 1;

    /* 分层 BFS — 双向提取 */
    ULONG layerStart = 0;

    for (ULONG depth = 0; depth <= MaxDepth && Subgraph->NodeCount < T2_SUBGRAPH_MAX_NODES; depth++) {
        ULONG layerEnd = qTail;
        BOOLEAN layerFound = FALSE;

        for (ULONG qi = layerStart; qi < layerEnd; qi++) {
            PIOA_CARSAL_GRAPH_NODE curNode = IoaCarsalGraphLookupNode(Graph, queue[qi]);
            if (!curNode) continue;

            /* ── 入边遍历（回溯方向）── */
            if (depth < MaxDepth) {
                PLIST_ENTRY e = curNode->InEdgesHead.Flink;
                while (e != &curNode->InEdgesHead &&
                       Subgraph->EdgeCount < T2_SUBGRAPH_MAX_EDGES &&
                       Subgraph->NodeCount < T2_SUBGRAPH_MAX_NODES) {
                    PIOA_GRAPH_EDGE edge = CONTAINING_RECORD(e, IOA_GRAPH_EDGE, TgtInLink);

                    /* 记录边 */
                    PT2_SUBGRAPH_EDGE se = &Subgraph->Edges[Subgraph->EdgeCount];
                    WkdCopyGuid(&se->SrcNodeId, &edge->SrcNodeId);
                    WkdCopyGuid(&se->TgtNodeId, &edge->TgtNodeId);
                    se->EdgeType        = edge->Type;
                    se->OccurrenceCount = edge->OccurrenceCount;
                    se->Confidence      = edge->Confidence;
                    se->BehaviorFlags   = edge->BehaviorFlags;
                    Subgraph->EdgeCount++;
                    Subgraph->InEdgeCount++;

                    /* 边类型统计 */
                    switch (edge->Type) {
                    case DefEdge_InjectsInto:
                    case DefEdge_Hollows:
                        Subgraph->InjectionEdgeCount++; break;
                    case DefEdge_Allocates:
                    case DefEdge_WritesTo:
                    case DefEdge_Protects:
                    case DefEdge_ReadsFrom:
                        Subgraph->MemoryOpEdgeCount++; break;
                    case DefEdge_Creates:
                        Subgraph->CreatesEdgeCount++; break;
                    default: break;
                    }

                    /* 添加源节点（去重） */
                    if (edge->SrcNode) {
                        BOOLEAN dup = FALSE;
                        for (ULONG v = 0; v < visitedCount; v++) {
                            if (DefGuidEqual(&visited[v], &edge->SrcNodeId)) { dup = TRUE; break; }
                        }
                        if (!dup && visitedCount < T2_SUBGRAPH_MAX_NODES) {
                            WkdCopyGuid(&visited[visitedCount], &edge->SrcNodeId);
                            visitedCount++;
                            WkdCopyGuid(&queue[qTail], &edge->SrcNodeId); qTail++;
                            Subgraph->NodeIds[Subgraph->NodeCount] = edge->SrcNodeId;
                            Subgraph->NodeCount++;
                            layerFound = TRUE;
                        }
                    }
                    e = e->Flink;
                }
            }

            /* ── 出边遍历（前向 1 层，仅看敏感类型）── */
            if (depth == 0 && Subgraph->EdgeCount < T2_SUBGRAPH_MAX_EDGES) {
                PLIST_ENTRY oe = curNode->OutEdgesHead.Flink;
                while (oe != &curNode->OutEdgesHead &&
                       Subgraph->EdgeCount < T2_SUBGRAPH_MAX_EDGES &&
                       Subgraph->NodeCount < T2_SUBGRAPH_MAX_NODES) {
                    PIOA_GRAPH_EDGE edge = CONTAINING_RECORD(oe, IOA_GRAPH_EDGE, SrcOutLink);

                    /* 仅记录非创建边（出方向只关注操作类边） */
                    if (edge->Type != DefEdge_Creates) {
                        PT2_SUBGRAPH_EDGE se = &Subgraph->Edges[Subgraph->EdgeCount];
                        WkdCopyGuid(&se->SrcNodeId, &edge->SrcNodeId);
                        WkdCopyGuid(&se->TgtNodeId, &edge->TgtNodeId);
                        se->EdgeType        = edge->Type;
                        se->OccurrenceCount = edge->OccurrenceCount;
                        se->Confidence      = edge->Confidence;
                        se->BehaviorFlags   = edge->BehaviorFlags;
                        Subgraph->EdgeCount++;
                        Subgraph->OutEdgeCount++;

                        /* 添加目标节点 */
                        if (edge->TgtNode) {
                            BOOLEAN dup = FALSE;
                            for (ULONG v = 0; v < visitedCount; v++) {
                                if (DefGuidEqual(&visited[v], &edge->TgtNodeId)) { dup = TRUE; break; }
                            }
                            if (!dup && visitedCount < T2_SUBGRAPH_MAX_NODES) {
                                WkdCopyGuid(&visited[visitedCount], &edge->TgtNodeId);
                                visitedCount++;
                                Subgraph->NodeIds[Subgraph->NodeCount] = edge->TgtNodeId;
                                Subgraph->NodeCount++;
                            }
                        }
                    }
                    oe = oe->Flink;
                }
            }
        }

        layerStart = layerEnd;
        if (!layerFound) break;
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*         P2: 子图特征测量                          */
/**************************************************/

VOID
T2MeasureFeatures(
    _In_  PT2_SUBGRAPH        Subgraph,
    _In_  PIOA_CARSAL_GRAPH   Graph,
    _Out_ PT2_FEATURE_VECTOR  Features
    )
/*++
Routine Description:
    测量子图的结构特征向量。
    包括拓扑特征、节点属性特征、时序特征三大类。

Arguments:
    Subgraph — 提取的局部子图
    Graph    — 因果图 (用于查询节点属性)
    Features — 输出: 特征向量
--*/
{
    ULONG i;
    LARGE_INTEGER earliest, latest;

    if (!Subgraph || !Features) return;

    RtlZeroMemory(Features, sizeof(T2_FEATURE_VECTOR));

    /* ── 拓扑特征 ── */
    if (Subgraph->EdgeCount > 0) {
        Features->NonCreateEdgeRatio =
            (FLOAT)(Subgraph->EdgeCount - Subgraph->CreatesEdgeCount) /
            (FLOAT)max(Subgraph->EdgeCount, 1);
    }
    Features->HasInjectionEdge = (Subgraph->InjectionEdgeCount > 0);
    Features->HasWriteEdge     = FALSE;  /* 下面遍历边时设置 */
    Features->HasAllocateEdge  = FALSE;

    /* 边类型去重计数 */
    {
        ULONG seenTypes = 0;
        for (i = 0; i < Subgraph->EdgeCount; i++) {
            ULONG bit = 1 << (Subgraph->Edges[i].EdgeType & 0x1F);
            if (!(seenTypes & bit)) {
                seenTypes |= bit;
                Features->DistinctEdgeTypes++;
            }
            if (Subgraph->Edges[i].EdgeType == DefEdge_WritesTo)
                Features->HasWriteEdge = TRUE;
            if (Subgraph->Edges[i].EdgeType == DefEdge_Allocates)
                Features->HasAllocateEdge = TRUE;
            if (Subgraph->Edges[i].EdgeType == DefEdge_WritesTo ||
                Subgraph->Edges[i].EdgeType == DefEdge_Allocates ||
                Subgraph->Edges[i].EdgeType == DefEdge_Protects ||
                Subgraph->Edges[i].EdgeType == DefEdge_ReadsFrom)
                Features->MemoryOpEdgeCount++;
        }
    }

    /* 最大入度 + 多跳注入深度（简化: 用 InjectionEdgeCount 推断） */
    {
        ULONG maxInDeg = 0;
        for (i = 0; i < Subgraph->NodeCount; i++) {
            ULONG inDeg = 0;
            for (ULONG j = 0; j < Subgraph->EdgeCount; j++) {
                if (DefGuidEqual(&Subgraph->Edges[j].TgtNodeId, &Subgraph->NodeIds[i]))
                    inDeg++;
            }
            if (inDeg > maxInDeg) maxInDeg = inDeg;
        }
        Features->MaxInDegree = maxInDeg;
    }
    Features->MultiHopInjectionDepth = (Subgraph->InjectionEdgeCount >= 2) ? 2 :
                                       (Subgraph->InjectionEdgeCount >= 1) ? 1 : 0;

    /* ── 节点属性特征 ── */
    earliest.QuadPart = LLONG_MAX;
    latest.QuadPart   = 0;

    for (i = 0; i < Subgraph->NodeCount; i++) {
        PIOA_CARSAL_GRAPH_NODE gn = IoaCarsalGraphLookupNode(Graph, Subgraph->NodeIds[i]);
        if (!gn) continue;

        /* 时间窗口 */
        if (gn->FirstSeen.QuadPart < earliest.QuadPart) earliest = gn->FirstSeen;
        if (gn->LastSeen.QuadPart  > latest.QuadPart)   latest   = gn->LastSeen;

        if (!gn->ProcessNode) continue;

        /* 提权进程 */
        if (gn->ProcessNode->IsElevated ||
            gn->ProcessNode->IntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
            Features->ElevatedProcessCount++;

        /* 系统进程被非常规操作 */
        if (gn->ProcessNode->IsSystemProcess ||
            gn->ProcessNode->IsProtectedProcess) {
            Subgraph->ContainsSystemProcess = TRUE;
            /* 入度>1 意味着不仅被父进程创建，还被其他进程操作 */
            ULONG inDeg = 0;
            for (ULONG j = 0; j < Subgraph->EdgeCount; j++) {
                if (DefGuidEqual(&Subgraph->Edges[j].TgtNodeId, &Subgraph->NodeIds[i]) &&
                    Subgraph->Edges[j].EdgeType != DefEdge_Creates)
                    inDeg++;
            }
            if (inDeg > 0) Features->SystemProcessAbused++;
        }

        /* lsass 检测 */
        if (gn->ProcessNode->ImageFileName &&
            gn->ProcessNode->ImageFileName->Buffer &&
            wcsstr(gn->ProcessNode->ImageFileName->Buffer, L"lsass.exe")) {
            Subgraph->ContainsLsass = TRUE;
        }
    }

    Features->HasSensitiveTarget = (Subgraph->ContainsLsass ||
                                     Features->SystemProcessAbused > 0);

    /* ── 时序特征 ── */
    if (earliest.QuadPart < LLONG_MAX && latest.QuadPart > 0) {
        Features->TotalDurationMs = (latest.QuadPart - earliest.QuadPart) / 10000;
    }
    if (Features->TotalDurationMs > 0) {
        Features->EventDensity = (FLOAT)Subgraph->EdgeCount /
                                 (FLOAT)Features->TotalDurationMs * 1000.0f;
        /* 密集操作检测: ≥3 条边在 100ms 内 */
        Features->HasBurstPattern = (Subgraph->EdgeCount >= 3 &&
                                      Features->TotalDurationMs <= 100);
    }
}

/**************************************************/
/*         P2: 规则树判定                            */
/**************************************************/

VOID
T2ClassifySubgraph(
    _In_  PT2_FEATURE_VECTOR   Features,
    _In_  BOOLEAN              HasFsmGuidance,
    _Out_ PT2_ANALYSIS_RESULT  Result
    )
/*++
Routine Description:
    基于子图特征向量做二分类判定。
    规则树优先级: 注入边 > 内存操作 + 系统进程 > 密集突发 > 边多样性异常

Arguments:
    Features       — 子图特征向量
    HasFsmGuidance — FSM 是否提供了攻击假设（接受态指导）
    Result         — 输出: 分析结果（Verdict + Confidence + Reason）

Return Value:
    VOID
--*/
{
    if (!Features || !Result) return;

    /*
     * 规则树:
     *
     * R1: 存在注入边 + 触及敏感目标
     *     → ATTACK (Confidence=90)
     *
     * R2: 存在注入边 + 多跳注入深度≥2
     *     → ATTACK (Confidence=85)
     *
     * R3: 存在注入边（单一跳）
     *     → ATTACK (Confidence=70)  [有FSM指导时+10]
     *
     * R4: 内存操作边≥3 + 系统进程被非常规操作 + 非创建边≥50%
     *     → ATTACK (Confidence=75)
     *
     * R5: 密集突发模式 + 非创建边≥50%
     *     → SUSPICIOUS (Confidence=60)
     *
     * R6: 边类型多样性≥3 + 提权进程数≥1
     *     → SUSPICIOUS (Confidence=50)
     *
     * R7: 其他
     *     → BENIGN (Confidence=90)
     */

    /* R1: 注入边 + 敏感目标 */
    if (Features->HasInjectionEdge && Features->HasSensitiveTarget) {
        Result->Verdict    = T2_VERDICT_ATTACK;
        Result->ThreatScore = 90;
        swprintf_s(Result->Reason, 128,
                   L"Injection to sensitive target (lsass=%d sysAbused=%lu)",
                   Features->HasSensitiveTarget, Features->SystemProcessAbused);
        return;
    }

    /* R2: 注入边 + 多跳 */
    if (Features->HasInjectionEdge && Features->MultiHopInjectionDepth >= 2) {
        Result->Verdict    = T2_VERDICT_ATTACK;
        Result->ThreatScore = 85;
        swprintf_s(Result->Reason, 128,
                   L"Multi-hop injection chain (depth=%lu)", Features->MultiHopInjectionDepth);
        return;
    }

    /* R3: 注入边 */
    if (Features->HasInjectionEdge) {
        Result->Verdict    = T2_VERDICT_ATTACK;
        Result->ThreatScore = HasFsmGuidance ? 80 : 70;
        swprintf_s(Result->Reason, 128,
                   L"Injection edge detected%s", HasFsmGuidance ? L" (FSM verified)" : L"");
        return;
    }

    /* R4: 内存操作链 + 系统进程被操作 */
    if (Features->MemoryOpEdgeCount >= 3 &&
        Features->SystemProcessAbused > 0 &&
        Features->NonCreateEdgeRatio >= 0.5f) {
        Result->Verdict    = T2_VERDICT_ATTACK;
        Result->ThreatScore = 75;
        swprintf_s(Result->Reason, 128,
                   L"Memory op chain to system process (memEdges=%lu sysAbused=%lu)",
                   Features->MemoryOpEdgeCount, Features->SystemProcessAbused);
        return;
    }

    /* R5: 密集突发 */
    if (Features->HasBurstPattern && Features->NonCreateEdgeRatio >= 0.5f) {
        Result->Verdict    = T2_VERDICT_SUSPICIOUS;
        Result->ThreatScore = 60;
        swprintf_s(Result->Reason, 128,
                   L"Burst pattern (density=%.1f edges/s)", Features->EventDensity);
        return;
    }

    /* R6: 边类型多样 + 提权 */
    if (Features->DistinctEdgeTypes >= 3 && Features->ElevatedProcessCount >= 1) {
        Result->Verdict    = T2_VERDICT_SUSPICIOUS;
        Result->ThreatScore = 50;
        swprintf_s(Result->Reason, 128,
                   L"Diverse edge types (%lu) + elevated processes (%lu)",
                   Features->DistinctEdgeTypes, Features->ElevatedProcessCount);
        return;
    }

    /* R7: 默认 — 良性 */
    Result->Verdict    = T2_VERDICT_BENIGN;
    Result->ThreatScore = 90;
    wcsncpy_s(Result->Reason, 128, L"No attack pattern detected", _TRUNCATE);
}

/**************************************************/
/*   谱系上下文权重评估                              */
/**************************************************/

#define T2_SUPPRESS_WINDOW_MS  60000
#define T2_SUPPRESS_MIN_FACTOR 5

static
FLOAT
T2EvaluateGenealogyContext(
    _In_opt_ PWKD_PROCESS   SrcNode,
    _In_opt_ PWKD_PROCESS   TgtNode
    )
/*++
Routine Description:
    评估源/目标进程的谱系上下文权重因子。

    跨会话、向上提权、系统进程受害 → 上调权重。
    父→子自然关系 → 下调权重。

Return Value:
    上下文权重因子 [0.5, 2.0]。
--*/
{
    FLOAT factor = 1.0f;

    if (!SrcNode || !TgtNode) return factor;

    if (SrcNode->SessionId != TgtNode->SessionId)
        factor += 0.3f;
    if (SrcNode->IntegrityLevel < TgtNode->IntegrityLevel)
        factor += 0.5f;
    if (TgtNode->IsSystemProcess || TgtNode->IsProtectedProcess)
        factor += 0.4f;
    if (SrcNode->IsElevated)
        factor += 0.2f;
    if (SrcNode->TreeDepth == 0 &&
        DefIsNullNodeId(SrcNode->ParentNodeId))
        factor += 0.1f;
    if (TgtNode->Parent == SrcNode)
        factor -= 0.2f;

    if (factor < 0.5f) factor = 0.5f;
    if (factor > 2.0f) factor = 2.0f;
    return factor;
}

/**************************************************/
/*   良性抑制反写 (反馈闭环)                        */
/**************************************************/

static
VOID
T2ApplyBenignSuppress(
    _Inout_ PAE_PROCESS_PAIR PairCtx
    )
/*++
Routine Description:
    Tier2 判定良性后, 向 PairCtx 反写抑制因子。
    Tier1 下次采集信号时读取并降权, 避免频繁误触发。

    抑制强度随连续良性判定次数递增:
      第1次 → factor=80 (×0.8)
      第2次 → factor=60 (×0.6)
      第3次 → factor=40 (×0.4)
      第4次 → factor=20 (×0.2)
      第5+次 → factor=5 (×0.05, 地板)
--*/
{
    LARGE_INTEGER now;

    if (!PairCtx) return;

    GetSystemTimeAsFileTime((LPFILETIME)&now);

    PairCtx->T1Feature.LastT2Verdict = T2_VERDICT_BENIGN;
    PairCtx->LastT2VerdictTime       = now;
    PairCtx->T2VerdictEdgeMask       = (ULONG)BM_DATA_U64(&PairCtx->InteractionBitmap);

    PairCtx->T2SuppressCount++;
    PairCtx->T1Feature.T2SuppressFactor =
        max(T2_SUPPRESS_MIN_FACTOR,
            100 - (PairCtx->T2SuppressCount * 20));
    PairCtx->T2SuppressResetTime.QuadPart =
        now.QuadPart + (T2_SUPPRESS_WINDOW_MS * 10000LL);
}

/**************************************************/
/*   Tier2 统一分析流水线                           */
/**************************************************/

NTSTATUS
T2AnalyzeInternal(
    _In_  PIOA_TIER2_BACKTRACK  Engine,
    _In_  PAE_PROCESS_PAIR PairCtx,
    _Out_ PT2_ANALYSIS_RESULT   Result
    )
/*++
Routine Description:
    Tier2 统一分析流水线 — FSM 多路归并 + 谱系上下文 + 时序验证 +
    子图分析 + 置信度融合 + 判决。

    同步和异步路径均调用此函数。

    流水线:
      1. FSM 多路归并推进 (从 PairCtx->EdgeListHead)
      2. 谱系上下文权重 (从 Genealogy 反查 SrcNode/TgtNode)
      3. 良性/部分接受 → 早期返回
      4. 时序验证 (FSM 边 GUID → CarsalGraph)
      5. 子图提取 + 特征测量 + 规则树判定
      6. 置信度融合 (FSM×0.4 + 子图×0.3 + 时序×0.3)
      7. 判决 + 后处理

Arguments:
    Engine   — Tier2 实例 (持有 FsmEngine/Graph/Genealogy)。
    PairCtx  — 进程对上下文。
    Result   — [输出] 分析结果。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    GUID seedNodeId;
    PWKD_PROCESS SrcNode = NULL, TgtNode = NULL;
    BOOLEAN hasFsmGuidance = FALSE;
    ULONG fsmScore = 0, subgraphScore = 0;
    UINT8 bestPatternIdx = 0;
    PFSM_TRANSITION_RESULT fsmResult = NULL;
    PIOA_FSM_EVIDENCE fsmEvidence = NULL;

    if (!Engine || !Result) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Result, sizeof(T2_ANALYSIS_RESULT));
    Result->Verdict = T2_VERDICT_BENIGN;

    /*
     * ── 阶段0: 从 Genealogy 反查 SrcNode/TgtNode ──
     * 2026-08-23 pair 键 PID 化: 经 PsLookupWkdProcessByStrictProcessId 反查
     */
    if (PairCtx) {
        SrcNode = NULL;
        if (NT_SUCCESS(PsLookupWkdProcessByStrictProcessId(&WkdProcessTree,
                            ULongToHandle(PairCtx->SourceProcessId), NULL, &SrcNode))) {
            if (SrcNode && SrcNode->SecCtx.Placeholder) SrcNode = NULL;
        }
        TgtNode = NULL;
        if (NT_SUCCESS(PsLookupWkdProcessByStrictProcessId(&WkdProcessTree,
                            ULongToHandle(PairCtx->TargetProcessId), NULL, &TgtNode))) {
            if (TgtNode && TgtNode->SecCtx.Placeholder) TgtNode = NULL;
        }
    }

    /*
     * ── 阶段1: FSM 多路归并推进 ──
     */
    if (WkdIoaEngine.FsmEngine && PairCtx) {

        BOOLEAN fsmAccepted;
        ULONG bestThreatScore = 0;

        /* 动态分配 FSM_TRANSITION_RESULT (柔性数组) */
        fsmResult = FSM_ALLOC_TRANSITION_RESULT(FSM_PATTERN_COUNT);
        if (!fsmResult) return STATUS_NO_MEMORY;
        fsmResult->Capacity = FSM_PATTERN_COUNT;

        /* FSM 从 EdgeListHead 收集具体边序列, 多路归并推进 */
        fsmAccepted = FsmRefreshStateTransition(
            WkdIoaEngine.FsmEngine, PairCtx, fsmResult);

        /* 遍历结果数组, 选取最佳模式: 接受态 > 部分接受 > 活跃最高分 */
        {
            BOOLEAN foundAccept = FALSE;

            for (ULONG i = 0; i < fsmResult->PatternCount; i++) {
                PFSM_PATTERN_RESULT pr = &fsmResult->Patterns[i];

                if (!pr->IsValid) continue;

                /* 优先选接受态模式中威胁得分最高的 */
                if (pr->IsAccept && !foundAccept) {
                    foundAccept = TRUE;
                    bestPatternIdx = pr->PatternIndex;
                    bestThreatScore = pr->ThreatScore;
                    fsmEvidence = pr->Evidence;
                } else if (pr->IsAccept && foundAccept) {
                    if (pr->ThreatScore > bestThreatScore) {
                        bestPatternIdx = pr->PatternIndex;
                        bestThreatScore = pr->ThreatScore;
                        fsmEvidence = pr->Evidence;
                    }
                }
                /* 无接受态时选部分接受态中威胁得分最高的 */
                else if (!foundAccept && pr->IsPartialAccept) {
                    if (pr->ThreatScore > bestThreatScore) {
                        bestPatternIdx = pr->PatternIndex;
                        bestThreatScore = pr->ThreatScore;
                        fsmEvidence = pr->Evidence;
                    }
                }
                /* 无接受无部分时选活跃模式中威胁得分最高的 */
                else if (!foundAccept && bestThreatScore == 0) {
                    if (pr->ThreatScore > bestThreatScore) {
                        bestPatternIdx = pr->PatternIndex;
                        bestThreatScore = pr->ThreatScore;
                    }
                }
            }
        }

        fsmScore = bestThreatScore;

        Result->FsmAccepted      = fsmAccepted;
        Result->FsmPartialAccept = fsmResult->HasAccept ? FALSE : (bestThreatScore >= 50);
        Result->FsmMaxScore      = fsmScore;

        if (fsmEvidence) {
            /* PatternName 不在 IOA_FSM_EVIDENCE 中，通过 PatternIndex 从引擎获取 */
            if (WkdIoaEngine.FsmEngine &&
                fsmEvidence->PatternIndex < FSM_PATTERN_COUNT) {
                wcsncpy_s(Result->FsmPatternName, 64,
                          WkdIoaEngine.FsmEngine->Patterns[fsmEvidence->PatternIndex].Name,
                          _TRUNCATE);
            } else {
                swprintf_s(Result->FsmPatternName, 64, L"Pattern[%u]", fsmEvidence->PatternIndex);
            }
            hasFsmGuidance = TRUE;

            printf("[T2AnalyzeInternal] FSM accept: FsmClass=%d (threatScore=%lu, steps=%lu)\n",
                   (int)fsmEvidence->FsmClass, fsmScore,
                   fsmEvidence->CurrentStep);
        } else if (bestThreatScore >= 50) {
            printf("[T2AnalyzeInternal] FSM partial: pattern[%u] threatScore=%lu\n",
                   bestPatternIdx, fsmScore);
        }
    }

    /*
     * ── 阶段2: 良性抑制 ──
     */
    if (fsmScore < 30) {
        T2ApplyBenignSuppress(PairCtx);
        Result->Verdict     = T2_VERDICT_BENIGN;
        Result->ThreatScore = fsmScore + 10;
        wcsncpy_s(Result->Reason, 128,
                  L"Benign — FSM threat score below threshold, suppress applied",
                  _TRUNCATE);
        Engine->TotalProcessed++;
        goto Cleanup;
    }

    /*
     * ── 阶段3: 部分接受态 ──
     */
    if (fsmScore < 50) {
        Result->Verdict     = T2_VERDICT_SUSPICIOUS;
        Result->ThreatScore = fsmScore;
        swprintf_s(Result->Reason, 128,
                   L"Partial accept: %S threatScore=%lu — early warning",
                   Result->FsmPatternName[0] ? Result->FsmPatternName : L"?",
                   fsmScore);
        if (PairCtx) {
            PairCtx->DirtyFlags |= IOA_PAIR_DIRTY_T2_SUSPICIOUS;
        }
        Engine->TotalProcessed++;
        goto Cleanup;
    }

    /*
     * ── 种子选择: FSM 锚定 > SrcNode > PairCtx ──
     */
    if (hasFsmGuidance && fsmEvidence &&
        !DefIsNullNodeId(fsmEvidence->SrcProcessNodeId)) {
        WkdCopyGuid(&seedNodeId, &fsmEvidence->SrcProcessNodeId);
    } else if (SrcNode) {
        WkdCopyGuid(&seedNodeId, &SrcNode->NodeId);
    } else if (TgtNode) {
        WkdCopyGuid(&seedNodeId, &TgtNode->NodeId);
    } else if (PairCtx) {
        /* 2026-08-23 pair 键 PID 化: NodeId 经谱系树反查 */
        GUID pairSrcId;
        IoaPairResolveNodeIds(PairCtx, &pairSrcId, NULL);
        WkdCopyGuid(&seedNodeId, &pairSrcId);
    } else {
        Engine->TotalProcessed++;
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    /*
     * ── 阶段4: 子图分析 ──
     */
    status = T2ExtractSubgraph(WkdIoaEngine.Graph, seedNodeId,
                                T2_BACKTRACK_MAX_DEPTH, &Result->Subgraph);
    if (NT_SUCCESS(status)) {
        T2MeasureFeatures(&Result->Subgraph, WkdIoaEngine.Graph, &Result->Features);
        T2ClassifySubgraph(&Result->Features, hasFsmGuidance, Result);
        subgraphScore = Result->ThreatScore;
    }

    /*
     * ── 阶段5: 威胁得分融合 (FSM 70% + 子图 30%) ──
     */
    Result->ThreatScore = (fsmScore * 70 + subgraphScore * 30) / 100;
    if (Result->ThreatScore > 100) Result->ThreatScore = 100;

    /*
     * ── 阶段6: 判决 + 后处理 ──
     */
    if (Result->ThreatScore >= 70) {
        Result->Verdict = T2_VERDICT_ATTACK;
    } else if (Result->ThreatScore >= 50) {
        Result->Verdict = T2_VERDICT_SUSPICIOUS;
    } else {
        Result->Verdict = T2_VERDICT_BENIGN;
    }

    if (Result->Verdict == T2_VERDICT_BENIGN) {
        T2ApplyBenignSuppress(PairCtx);
        wcsncpy_s(Result->Reason, 128,
                  L"Benign — FSM+subgraph fusion below threshold",
                  _TRUNCATE);
    } else if (Result->Verdict >= T2_VERDICT_SUSPICIOUS) {
        if (PairCtx) {
            PairCtx->DirtyFlags |= IOA_PAIR_DIRTY_T2_SUSPICIOUS;
        }
        if (Result->Verdict == T2_VERDICT_ATTACK) {
            if (PairCtx) {
                PairCtx->DirtyFlags |= IOA_PAIR_DIRTY_TIER3;
            }
            /* T3 同步取证 (直接调用, 极低频) */
            if (WkdIoaEngine.Tier3 && fsmEvidence) {
                PTIRE3_ATTACK_CHAIN chain = NULL;
                NTSTATUS ts = T3DeepForensics(
                    WkdIoaEngine.Tier3, fsmEvidence, &chain);
                if (NT_SUCCESS(ts) && chain) {
                    printf("[T2AnalyzeInternal] T3 forensics complete: "
                           "chain %08X threatScore=%lu\n",
                           chain->ChainId.Data1, chain->ThreatScore);
                }
            }
        }
    }

    Engine->TotalProcessed++;
    status = STATUS_SUCCESS;

Cleanup:
    /* 释放 FSM 结果 (含各槽位按需分配的 Evidence) */
    if (fsmResult) {
        for (ULONG i = 0; i < fsmResult->PatternCount; i++) {
            if (fsmResult->Patterns[i].Evidence) {
                UtHeapFree(fsmResult->Patterns[i].Evidence);
            }
        }
        UtHeapFree(fsmResult);
    }

    /* 归还阶段0 反查的节点查找 pin (2026-08-25 HashMap ref/deref 契约;
     * Placeholder 节点已置 NULL 不归还) */
    if (TgtNode) PsDereferenceWkdProcess(TgtNode);
    if (SrcNode) PsDereferenceWkdProcess(SrcNode);

    return status;
}
