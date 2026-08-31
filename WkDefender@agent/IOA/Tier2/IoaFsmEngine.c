/**************************************************/
/*  WkDefender — DFA+FSM 时序攻击链追踪引擎实现       */
/*                                                  */
/*  重构: 多路归并从 EdgeListHead 收集具体边序列       */
/*  FSM 不再依赖聚合边统计量 / 事件标志 / 目标镜像     */
/*  状态转移仅检查 TriggerEdge + 按序推进               */
/**************************************************/

#include "IoaFsmEngine.h"
#include "../IoaEngine.h"
#include "../IoaCarsalGraph.h"
#include "../IoaEdgeAggregate.h"
#include "../../DefendTypes.h"
#include <string.h>
#include <process.h>

/**************************************************/
/*               预定义攻击模式                     */
/*               Steps 精简为 (EdgeType, Score, Timeout) */
/**************************************************/

static const FSM_PATTERN_TEMPLATE g_FsmBuiltinPatterns[FSM_PATTERN_COUNT] = {

    /* ── Classic DLL Injection (FsmClass_ProcessInjection) ────── */
    [0] = {
        .Name = L"ClassicDllInjection",
        .FsmClass = FsmClass_ProcessInjection,
        .StateCount = 5,
        .Steps = {
            { DefEdge_Opens,       10,   5000  },
            { DefEdge_Allocates,   20,   5000  },
            { DefEdge_WritesTo,    30,   5000  },
            { DefEdge_InjectsInto, 40,  10000  },
        },
        .AcceptStates   = { FALSE, FALSE, FALSE, FALSE, TRUE },
        .AcceptThreshold = 70,
        .TotalTimeoutMs  = 30000,
    },

    /* ── Process Hollowing (FsmClass_ProcessHollowing) ────────── */
    [1] = {
        .Name = L"ProcessHollowing",
        .FsmClass = FsmClass_ProcessHollowing,
        .StateCount = 5,
        .Steps = {
            { DefEdge_Allocates,   10,   5000  },
            { DefEdge_WritesTo,    20,   5000  },
            { DefEdge_Protects,    20,   3000  },
            { DefEdge_InjectsInto, 40,   5000  },
        },
        .AcceptStates   = { FALSE, FALSE, FALSE, FALSE, TRUE },
        .AcceptThreshold = 75,
        .TotalTimeoutMs  = 30000,
    },

    /* ── Credential Dumping (FsmClass_CredentialAccess) ───────── */
    [2] = {
        .Name = L"LsassCredentialDumping",
        .FsmClass = FsmClass_CredentialAccess,
        .StateCount = 3,
        .Steps = {
            { DefEdge_Opens,      20,   3000  },
            { DefEdge_ReadsFrom,  50,   5000  },
        },
        .AcceptStates   = { FALSE, FALSE, TRUE },
        .AcceptThreshold = 55,
        .TotalTimeoutMs  = 10000,
    },

    /* ── APC Injection (FsmClass_ProcessInjection) ────────────── */
    /* 与模式0共享 FsmClass — 边序列相同，Tier3 通过参数区分 */
    [3] = {
        .Name = L"APCInjection",
        .FsmClass = FsmClass_ProcessInjection,
        .StateCount = 5,
        .Steps = {
            { DefEdge_Opens,       10,   5000  },
            { DefEdge_Allocates,   20,   5000  },
            { DefEdge_WritesTo,    30,   5000  },
            { DefEdge_InjectsInto, 40,  10000  },
        },
        .AcceptStates   = { FALSE, FALSE, FALSE, FALSE, TRUE },
        .AcceptThreshold = 70,
        .TotalTimeoutMs  = 30000,
    },

    /* ── DLL Side-Loading (FsmClass_Persistence) ──────────────── */
    [4] = {
        .Name = L"DllSideLoading",
        .FsmClass = FsmClass_Persistence,
        .StateCount = 3,
        .Steps = {
            { DefEdge_Modifies,   25,   60000  },
            { DefEdge_Sideloads,  55,  240000  },
        },
        .AcceptStates   = { FALSE, FALSE, TRUE },
        .AcceptThreshold = 60,
        .TotalTimeoutMs  = 300000,
    },

    /* ── Thread Hijacking (FsmClass_ProcessInjection, T1055.003) ─
     * Suspend→SetContext→Resume 时序序列 (T1055.003, 2026-08 新增)。
     * WkD 边映射: SetContext→InjectsInto, Suspend/Resume→AssociatedWith。
     * 状态机按 CurrentStep 索引推进, 同边类型 (AssociatedWith) 多步
     * 由步索引区分。Tier3 通过因果倒推验证时序严格性。
     * 数据源依赖: 驱动补 NtSuspendThread/NtSetContextThread/NtResumeThread case。 */
    [5] = {
        .Name = L"ThreadHijacking",
        .FsmClass = FsmClass_ProcessInjection,
        .StateCount = 4,
        .Steps = {
            { DefEdge_AssociatedWith, 10,   3000  },   /* Suspend */
            { DefEdge_InjectsInto,    40,   3000  },   /* SetContext */
            { DefEdge_AssociatedWith, 20,   3000  },   /* Resume */
        },
        .AcceptStates   = { FALSE, FALSE, FALSE, TRUE },
        .AcceptThreshold = 70,
        .TotalTimeoutMs  = 10000,
    },
};

/**************************************************/
/*               内部辅助: 稀疏哈希函数              */
/**************************************************/

static
ULONG
FsmpPatternHash(
    _In_ GUID   SourceNodeId,
    _In_ GUID   TargetNodeId,
    _In_ UINT8  PatternIndex
    )
{
    ULONG hash = 5381;
    UCHAR* p;
    ULONG i;

    p = (UCHAR*)&SourceNodeId;
    for (i = 0; i < sizeof(GUID); i++) {
        hash = ((hash << 5) + hash) ^ p[i];
    }
    p = (UCHAR*)&TargetNodeId;
    for (i = 0; i < sizeof(GUID); i++) {
        hash = ((hash << 5) + hash) ^ p[i];
    }
    hash = ((hash << 5) + hash) ^ PatternIndex;
    return hash % FSM_STATE_HASH_BUCKETS;
}

/**************************************************/
/*           内部辅助: 稀疏状态查找/创建/释放        */
/**************************************************/

static
PFSM_PATTERN
FsmpLookupPattern(
    _In_ PIOA_FSM_ENGINE Engine,
    _In_ GUID             SourceNodeId,
    _In_ GUID             TargetNodeId,
    _In_ ULONG            PatternIndex
    )
{
    ULONG bucket = FsmpPatternHash(SourceNodeId, TargetNodeId, PatternIndex);
    PLIST_ENTRY head = &Engine->PatternHashBuckets[bucket];
    PLIST_ENTRY entry;

    for (entry = head->Flink; entry != head; entry = entry->Flink) {
        PFSM_PATTERN pe = CONTAINING_RECORD(entry, FSM_PATTERN, HashLink);
        if (DefGuidEqual(&pe->SourceNodeId, &SourceNodeId) &&
            DefGuidEqual(&pe->TargetNodeId, &TargetNodeId) &&
            pe->PatternIndex == PatternIndex) {
            return pe;
        }
    }
    return NULL;
}

static
PFSM_PATTERN
FsmpGetOrCreatePattern(
    _In_ PIOA_FSM_ENGINE Engine,
    _In_ GUID            SourceNodeId,
    _In_ GUID            TargetNodeId,
    _In_ ULONG           PatternIndex
    )
{
    PFSM_PATTERN pe;
    ULONG bucket;

    pe = FsmpLookupPattern(Engine, SourceNodeId, TargetNodeId, PatternIndex);
    if (pe) return pe;

    pe = UtHeapAlloc(sizeof(FSM_PATTERN));
    if (!pe) return NULL;

    WkdCopyGuid(&pe->SourceNodeId, &SourceNodeId);
    WkdCopyGuid(&pe->TargetNodeId, &TargetNodeId);
    pe->PatternIndex    = PatternIndex;
    pe->ThreatScore     = 0;
    pe->LastStepTime.QuadPart = 0;
    pe->CurrentStep    = 0;
    pe->RefCount        = 1;

    bucket = FsmpPatternHash(SourceNodeId, TargetNodeId, PatternIndex);
    InsertTailList(&Engine->PatternHashBuckets[bucket], &pe->HashLink);
    InterlockedIncrement(&Engine->PatternCount);
    Engine->TotalStateEntriesCreated++;

    return pe;
}

static
VOID
FsmFreeStateEntry(
    _In_ PIOA_FSM_ENGINE Engine,
    _In_ PFSM_PATTERN StateEntry
    )
{
    if (!StateEntry) return;

    RemoveEntryList(&StateEntry->HashLink);
    InterlockedDecrement(&Engine->PatternCount);
    Engine->TotalStateEntriesFreed++;
    UtHeapFree(StateEntry);
}

/**************************************************/
/*           内部辅助: 证据记录 (具体边)             */
/**************************************************/

static
VOID
FsmRecordStateTransition(
    _Inout_ PFSM_PATTERN      Pattern,
    _In_    PIOA_AGGREGATE_EDGE   Aggregate,
    _In_    PIOA_CONCRETE_EDGE  ConcreteEdge
    )
/*++
Routine Description:
    记录 FSM 状态转移的具体边证据。
    填充 TriggerEdgeId (→因果图) 和 TriggerEventId (→SQLite cg_events) 供Tier3反查。
--*/
{
    PFSM_PATTERN_STATE state;

    state = &Pattern->States[Pattern->CurrentStep - 1];

    /* 记录聚合边类型，供 Tier2/3 回查聚合边表使用 */
    state->EdgeType = Aggregate->EdgeType;

    /* 记录具体边的精确时间戳和GUID（供Tier3证据反查） */
    state->TriggerTime    = ConcreteEdge->Timestamp;
    state->TriggerEdgeId  = ConcreteEdge->EdgeId;
}

/**************************************************/
/*           内部辅助: 内嵌证据填充                 */
/**************************************************/

static
VOID
FsmFillEvidencePacket(
    _In_  const FSM_PATTERN_TEMPLATE* Template,
    _In_  PFSM_PATTERN                Pattern,
    _In_  LARGE_INTEGER               Now,
    _In_  ULONG                       PatternIndex,
    _Out_ PIOA_FSM_EVIDENCE           Packet
    )
/*++
Routine Description:
    构造精简版 FSM 证据包 (2026-07 重构)。
    States[] 数组不再传递 — Tier3 从聚合边表自行做因果倒推。
    MitreId/MitreTactic 替换为 FsmClass — Tier2 只做粗判。

    流程:
      1. 填充元信息 (FsmClass/节点GUID/PatternIndex/StepCount)
      2. 计算原始威胁得分
      3. 应用总耗时衰减系数
--*/
{
    RtlZeroMemory(Packet, sizeof(IOA_FSM_EVIDENCE));

    Packet->FsmClass     = Template->FsmClass;
    WkdCopyGuid(&Packet->SrcProcessNodeId, &Pattern->SourceNodeId);
    WkdCopyGuid(&Packet->TgtProcessNodeId, &Pattern->TargetNodeId);
    Packet->PatternIndex = PatternIndex;
    Packet->CurrentStep  = Pattern->CurrentStep;
    Packet->StartTime    = Pattern->CreationTime;
    Packet->LastStepTime = Pattern->LastStepTime;

    /*
     * 计算威胁得分 (含总耗时衰减)。
     * 总耗时越长，衰减越大 — 攻击通常具有时间局部性。
     */
    {
        ULONG rawScore = Pattern->ThreatScore;
        ULONG totalDecay = 100;  /* Q8定点: 100 = 1.0 */

        if (Template->TotalTimeoutMs > 0 &&
            Pattern->CreationTime.QuadPart > 0) {
            LONGLONG totalSpanMs =
                (Now.QuadPart - Pattern->CreationTime.QuadPart) / 10000LL;

            if (totalSpanMs > 0) {
                ULONG ratio = (ULONG)((totalSpanMs * 100) / (LONGLONG)Template->TotalTimeoutMs);

                if (ratio <= 50) {
                    totalDecay = 100;
                } else if (ratio <= 100) {
                    totalDecay = 100 - (ratio - 50);
                } else if (ratio <= 200) {
                    totalDecay = 50 - (ratio - 100) / 4;
                } else {
                    totalDecay = 10;
                }
            }
        }

        Packet->ThreatScore = (rawScore * totalDecay) / 100;
    }
}

/**************************************************/
/*           内部辅助: 部分匹配告警输出              */
/**************************************************/

static
VOID
FsmReportPartial(
    _In_ PIOA_FSM_ENGINE     Engine,
    _In_ PFSM_PATTERN    StateEntry,
    _In_ LARGE_INTEGER       Now
    )
{
    const FSM_PATTERN_TEMPLATE* pat = &Engine->Patterns[StateEntry->PatternIndex];

    if (StateEntry->CurrentStep > 0 &&
        !pat->AcceptStates[StateEntry->CurrentStep] &&
        StateEntry->ThreatScore >= pat->AcceptThreshold / 2) {

        printf("[FsmEngine] Partial pattern: %S (FsmClass=%d) "
               "state=%u/%u threatScore=%lu/%lu\n",
               pat->Name, (int)pat->FsmClass,
               StateEntry->CurrentStep, pat->StateCount - 1,
               StateEntry->ThreatScore, pat->AcceptThreshold);

        Engine->TotalPartialsReported++;
    }
    UNREFERENCED_PARAMETER(Now);
}

/**************************************************/
/*               共享工具函数                       */
/**************************************************/

IOA_GRAPH_EDGE_TYPE
IoaMapEventToEdgeType(
    _In_ WKD_EVENT_TYPE EventType
    )
{
    switch (EventType) {
    case WkdEvent_ProcessCreate:        return DefEdge_Creates;
    case WkdEvent_ProcessExit:          return DefEdge_Creates;
    case WkdEvent_ProcessOpen:          return DefEdge_Opens;
    case WkdEvent_ThreadCreate:         return DefEdge_AssociatedWith;
    case WkdEvent_ThreadExit:           return DefEdge_AssociatedWith;
    case WkdEvent_RemoteThreadCreate:   return DefEdge_InjectsInto;
    case WkdEvent_MemoryAllocate:       return DefEdge_Allocates;
    case WkdEvent_MemoryProtect:        return DefEdge_Protects;
    case WkdEvent_MemoryWrite:          return DefEdge_WritesTo;
    case WkdEvent_MemoryRead:           return DefEdge_ReadsFrom;
    case WkdEvent_ImageLoad:            return DefEdge_Executes;
    case WkdEvent_FileWrite:
    case WkdEvent_FileCreate:           return DefEdge_WritesTo;
    case WkdEvent_NamedPipeCreate:      return DefEdge_ListensOn;  /* 命名管道服务端监听（NamedPipeMonitor 迁移 2026-08） */
    case WkdEvent_NetworkConnect:       return DefEdge_ConnectsTo;
    case WkdEvent_RegSetValue:
    case WkdEvent_RegCreateKey:         return DefEdge_Modifies;

    /* ── 注入相关新事件映射 (PreAcquireSection 迁移 2026-08: 区段映射文件轨
     * AcquireSection 已激活; 线程/区段 syscall 轨 case 已落位, 依赖 SmInitialize 启用) ── */
    case WkdEvent_QueueApc:             return DefEdge_InjectsInto;  /* APC 注入 */
    case WkdEvent_SetThreadContext:     return DefEdge_InjectsInto;  /* 执行流劫持 */
    case WkdEvent_ThreadSuspend:
    case WkdEvent_ThreadResume:         return DefEdge_AssociatedWith; /* 线程操作 */
    case WkdEvent_MapViewOfSection:     return DefEdge_Allocates;   /* 远程映射 */
    case WkdEvent_UnmapViewOfSection:   return DefEdge_Hollows;     /* 镂空标志动作 */

    case WkdEvent_AmsiBypass:           return DefEdge_Modifies;  /* 进程修改自身 amsi.dll (T1562.001) */

    /* ── Token 操作事件 (PrivilegeMonitor 迁移 2026-08-06) ──
     * 令牌操纵家族统一映射 DefEdge_Impersonates (=43)，激活 IoaThreatScorer.c
     * TokenManipulation 模板 (Impersonates → BM_SEM_TOKEN_MANIPULATE)。
     * Adjust/Duplicate/SetInfo 目标进程=源进程 (self-pair)，Impersonate 为被模拟
     * 线程所属进程 (跨进程)。配合阶段4.9b WpaCheckForEscalation 产分。 */
    case WkdEvent_TokenAdjustPrivileges:
    case WkdEvent_TokenDuplicate:
    case WkdEvent_TokenSetInformation:
    case WkdEvent_TokenImpersonate:     return DefEdge_Impersonates;

    default:                            return DefEdge_Unknown;
    }
}

/**************************************************/
/*           多路归并: 最小堆节点                    */
/**************************************************/

/* 用于归并的"路"描述符 */
typedef struct _FSM_MERGE_ROAD {
    IOA_GRAPH_EDGE_TYPE     EdgeType;
    PIOA_AGGREGATE_EDGE     Aggregate;  /* 所属聚合边指针（用于 FsmRecordStateTransition） */
    PLIST_ENTRY             Head;       /* 聚合边的 EdgesHead */
    PLIST_ENTRY             Cursor;     /* 当前遍历位置 */
    PLIST_ENTRY             End;        /* &EdgesHead (哨兵) */
    LONG                    Remaining;  /* 剩余活跃节点数 */
} FSM_MERGE_ROAD, *PFSM_MERGE_ROAD;

#define FSM_MAX_ROADS (DefEdge_Max)  /* 最多每条边类型一路 */

/**************************************************/
/*           多路归并核心: FSM 追赶                  */
/**************************************************/

BOOLEAN
FsmRefreshStateTransition(
    _In_    PIOA_FSM_ENGINE           Engine,
    _In_    PAE_PROCESS_PAIR PairCtx,
    _Out_   PFSM_TRANSITION_RESULT    Result
    )
/*++
Routine Description:
    FSM 多路归并推进 — 从 PairCtx->EdgeListHead 收集活跃具体边序列,
    按 Timestamp 归并为全局有序序列, 驱动所有攻击模式的状态转移。

    每个模式独立消费全局边序列。不读聚合边统计量、不读事件标志。
    空窗期: 未激活 → CreationTime; 已激活 → LastStepTime。

    设计原则:
      阶段4: 达到接受态仅标记, 不销毁、不构造证据。
      阶段5: 统一评分收集 + 证据构造 (接受态和部分接受态均构造)。
      阶段6: 统一清理接受态模式 (重置 + 释放), 预留部分接受模式。

Arguments:
    Engine  — FSM 引擎。
    PairCtx — 进程对上下文 (提供 FsmTracker + EdgeListHead)。
    Result  — [输出] 状态转移结果 (数组式, 遍历 Patterns[])。

Return Value:
    TRUE  = 有任意模式到达接受态 (Result->HasAccept==TRUE)。
--*/
{
    PIOA_FSM_TRACKER tracker;
    GUID srcNodeId, tgtNodeId;
    LARGE_INTEGER now;
    ULONG localAcceptMask = 0;          /* 达到接受态的模式位图 */
    ULONG roadCount = 0;
    FSM_MERGE_ROAD roads[FSM_MAX_ROADS];

    if (!Engine || !Engine->Initialized || !PairCtx || !Result) return FALSE;
    if (Result->Capacity == 0) return FALSE;

    /* 2026-08-23 pair 键 PID 化: NodeId 经谱系树反查 */
    IoaPairResolveNodeIds(PairCtx, &srcNodeId, &tgtNodeId);

    /* 清零结果头 + Patterns[] 数组 */
    Result->PatternCount = 0;
    Result->HasAccept    = FALSE;
    RtlZeroMemory(Result->Patterns, Result->Capacity * sizeof(FSM_PATTERN_RESULT));
    RtlZeroMemory(roads, sizeof(roads));
    GetSystemTimeAsFileTime((LPFILETIME)&now);

    EnterCriticalSection(&Engine->Lock);

    /* ================================================================
       阶段1: 收集路源 — 遍历 EdgeListHead, 为每种有活跃节点的聚合边建路
       链头锁原则 (2026-08-25): EdgeListHead 读持 PairCtx->EdgeListLock
       共享; 路内 Cursor 消费的 agg->EdgesHead 由各聚合边自身 EdgeLock
       承担 — 该链节点只在 InsertConcrete 尾插/标记 Active, 淘汰分支
       已停用 (无摘除者), 归并期间 Cursor 链上遍历安全。
       ================================================================ */
    {
        AcquireSRWLockShared(&PairCtx->EdgeListLock);
        PLIST_ENTRY entry = PairCtx->EdgeListHead.Flink;
        while (entry != &PairCtx->EdgeListHead && roadCount < FSM_MAX_ROADS) {
            PIOA_AGGREGATE_EDGE agg = CONTAINING_RECORD(entry, IOA_AGGREGATE_EDGE, PairLink);

            if (agg->ActiveEdges > 0 && !IsListEmpty(&agg->EdgesHead)) {
                roads[roadCount].EdgeType   = agg->EdgeType;
                roads[roadCount].Aggregate  = agg;               /* 保存聚合边指针 */
                roads[roadCount].Head       = &agg->EdgesHead;
                roads[roadCount].Cursor     = agg->EdgesHead.Flink;
                roads[roadCount].End        = &agg->EdgesHead;
                roads[roadCount].Remaining  = agg->ActiveEdges;
                roadCount++;
            }
            entry = entry->Flink;
        }
        ReleaseSRWLockShared(&PairCtx->EdgeListLock);
    }

    /* ================================================================
       阶段2: 按需创建/获取 Tracker
       ================================================================ */
    tracker = PairCtx->FsmTracker;
    if (!tracker) {
        tracker = (PIOA_FSM_TRACKER)UtHeapAlloc(sizeof(IOA_FSM_TRACKER));
        if (!tracker) {
            LeaveCriticalSection(&Engine->Lock);
            return FALSE;
        }
        WkdCopyGuid(&tracker->SourceProcessNodeId, &srcNodeId);
        WkdCopyGuid(&tracker->TargetProcessNodeId, &tgtNodeId);
        InitializeListHead(&tracker->ActivePatternHead);
        tracker->ActivePatternMask      = 0;
        tracker->CreationTime           = now;
        tracker->RefCount               = 1;
        PairCtx->FsmTracker             = tracker;
    }

    /* ================================================================
       阶段3: 全局边消费 — 用简单"探路"法代替最小堆 (路数 ≤18, 每条路
              内部按时间有序)
       每轮找出所有路中 Cursor 指向的最早边, 消费之, 推进该路 Cursor。
       ================================================================ */
    {
        ULONG totalConsumed = 0;
        while (TRUE) {
            LONGLONG earliestTime = LLONG_MAX;
            ULONG earliestRoad = 0;
            BOOLEAN found = FALSE;
            PIOA_CONCRETE_EDGE edge;
            PIOA_AGGREGATE_EDGE aggEdge;

            /* 遍历所有路, 找最早且在空窗期内的边（tracker->LastActivity 之后的新边） */
            for (ULONG r = 0; r < roadCount; r++) {
                while (roads[r].Cursor != roads[r].End) {
                    edge = CONTAINING_RECORD(roads[r].Cursor, IOA_CONCRETE_EDGE, Link);

                    /* 跳过空窗期外的边 — 必须是 tracker->LastActivity 之后的新边 */
                    /* 跳过 inactive 节点 */
                    /* 跳过未知节点 */
                    if (edge->Timestamp.QuadPart <= tracker->LastActivity.QuadPart || 
                        !edge->Active) {
                        roads[r].Cursor = roads[r].Cursor->Flink;
                        continue;
                    }

                    if (edge->Timestamp.QuadPart < earliestTime) {
                        earliestTime = edge->Timestamp.QuadPart;
                        earliestRoad = r;
                        found = TRUE;
                    }

                    break;
                }
            }

            if (!found) break;  /* 所有路已穷尽 */

            /* 消费最早边 */
            edge = CONTAINING_RECORD(roads[earliestRoad].Cursor, IOA_CONCRETE_EDGE, Link);
            aggEdge = roads[earliestRoad].Aggregate;  /* 所属聚合边 */
            roads[earliestRoad].Cursor = roads[earliestRoad].Cursor->Flink;
            totalConsumed++;

            /* ============================================================
               阶段4: 驱动所有模式的 FSM 状态转移

               接受态处理原则: 仅标记 localAcceptMask, 不销毁、不构造证据。
               已接受的模式跳过后续边推进。

               ThreatIncrement + 步骤间隔衰减:
                 - 每步威胁增量 = step->ThreatIncrement * gapDecayFactor
                 - 间隔在 TimeoutMs 50% 内: 无衰减
                 - 间隔 50%~100% TimeoutMs: 90%
                 - 间隔 100%~200% TimeoutMs: 75%
                 - 间隔 >200% TimeoutMs: 地板 50%
               ============================================================ */
            PFSM_PATTERN pattern;

            for (ULONG p = 0; p < FSM_PATTERN_COUNT; p++) {
                const PFSM_PATTERN_TEMPLATE pt = &Engine->Patterns[p];

                /* ── 模式已活跃 → 推进现有状态 ── */
                if (tracker->ActivePatternMask & (1 << p)) {
                    /* 已接受态的模式跳过, 不再推进 */
                    if ((localAcceptMask >> p) & 1) continue;

                    pattern = FsmpLookupPattern(Engine, srcNodeId, tgtNodeId, p);

                    if (pattern && pattern->CurrentStep > 0 &&
                        pattern->CurrentStep < pt->StateCount) {

                        const PFSM_STATE_TRANSITION step = &pt->Steps[pattern->CurrentStep];

                        /* 仅检查边类型匹配 */
       /*                 if (step->TriggerEdge != edge->EdgeType) continue;*/

                        /*
                         * 计算步骤间隔衰减系数。
                         * 步骤 0→1 (首次激活) 无间隔，不衰减。
                         */
                        ULONG gapDecay = 100;  /* Q8: 100 = 1.0 */
                        if (step->TimeoutMs > 0 &&
                            pattern->LastStepTime.QuadPart > 0) {
                            LONGLONG gapMs =
                                (edge->Timestamp.QuadPart - pattern->LastStepTime.QuadPart) / 10000LL;

                            if (gapMs > 0) {
                                ULONG ratio = (ULONG)((gapMs * 100) / (LONGLONG)step->TimeoutMs);

                                if (ratio <= 50) {
                                    gapDecay = 100;
                                } else if (ratio <= 100) {
                                    gapDecay = 90;
                                } else if (ratio <= 200) {
                                    gapDecay = 75;
                                } else {
                                    gapDecay = 50;
                                }
                            }
                        }

                        /* 应用衰减后的威胁增量 */
                        ULONG effectiveIncrement =
                            (step->ThreatIncrement * gapDecay) / 100;

                        pattern->CurrentStep++;
                        pattern->ThreatScore += effectiveIncrement;
                        pattern->LastStepTime = edge->Timestamp;
                        Engine->TotalPatternAdvances++;

                        FsmRecordStateTransition(pattern, aggEdge, edge);

                        /* 接受态检查 — 仅标记，不销毁 */
                        if (pt->AcceptStates[pattern->CurrentStep] &&
                            pattern->ThreatScore >= pt->AcceptThreshold) {
                            localAcceptMask |= (1 << p);
                            Engine->TotalAcceptHits++;
                        }
                    }
                }
                /* ── 模式未激活 → 尝试 S0→S1 启动 ── */
                else {
                    const PFSM_STATE_TRANSITION firstStep = &pt->Steps[0];

                    /*if (firstStep->TriggerEdge != edge->EdgeType) continue;*/

                    /* 启动新模式 (首步无间隔，不衰减) */
                    pattern = FsmpGetOrCreatePattern(
                        Engine, srcNodeId, tgtNodeId, p);
                    if (pattern) {
                        pattern->OwnerTracker = tracker;
                        pattern->CurrentStep = 1;
                        pattern->ThreatScore = firstStep->ThreatIncrement;
                        pattern->CreationTime = edge->Timestamp;
                        pattern->LastStepTime = edge->Timestamp;
                        Engine->TotalPatternAdvances++;

                        FsmRecordStateTransition(pattern, aggEdge, edge);

                        InsertTailList(&tracker->ActivePatternHead, &pattern->TrackerLink);
                        tracker->ActivePatternMask |= (1 << p);
                    }
                }
            }
        }

        /* ==============================================================
           阶段5: 统一威胁得分收集 + Evidence 按需分配

           遍历所有模式 (活跃+已接受):
             - 收集 ThreatScore (直接取自模式状态)
             - 接受态 / 部分接受态 → 按需分配 Evidence
             - 填充到 Result->Patterns[]
           ============================================================== */
        {
            ULONG count = 0;

            for (ULONG p = 0; p < FSM_PATTERN_COUNT; p++) {
                BOOLEAN patAccept = ((localAcceptMask >> p) & 1) ? TRUE : FALSE;
                BOOLEAN patActive = (tracker->ActivePatternMask & (1 << p)) ? TRUE : FALSE;

                /* 既未激活也未接受 → 跳过 */
                if (!patAccept && !patActive) continue;

                /* 容量保护 */
                if (count >= Result->Capacity) break;

                PFSM_PATTERN pe = FsmpLookupPattern(
                    Engine, srcNodeId, tgtNodeId, (UINT8)p);
                if (!pe) continue;

                const PFSM_PATTERN_TEMPLATE pt = &Engine->Patterns[p];
                PFSM_PATTERN_RESULT pr = &Result->Patterns[count];

                pr->IsValid         = TRUE;
                pr->IsAccept        = patAccept;
                pr->PatternIndex    = (UINT8)p;
                pr->ThreatScore     = pe->ThreatScore;
                pr->AcceptThreshold = pt->AcceptThreshold;
                pr->Evidence        = NULL;

                /* 部分接受态：未接受但 ThreatScore >= AcceptThreshold */
                if (!patAccept && pe->ThreatScore >= pt->AcceptThreshold) {
                    pr->IsPartialAccept = TRUE;
                }

                /* 按需分配 Evidence (接受态 + 部分接受态) */
                if (patAccept || pr->IsPartialAccept) {
                    pr->Evidence = (PIOA_FSM_EVIDENCE)
                        UtHeapAlloc(sizeof(IOA_FSM_EVIDENCE));
                    if (pr->Evidence) {
                        FsmFillEvidencePacket(pt, pe, now, (UINT8)p, pr->Evidence);
                    }
                }

                count++;
            }

            Result->PatternCount = count;
            Result->HasAccept    = (localAcceptMask != 0);
        }

        /* ==============================================================
           阶段6: 统一清理

           接受态模式: 重置 + 释放 (调用方已通过 Result 读取证据)。
           部分接受/活跃模式: 保留不变, 等待下一轮继续推进。
           ============================================================== */
        {
            for (ULONG p = 0; p < FSM_PATTERN_COUNT; p++) {
                if ((localAcceptMask >> p) & 1) {
                    PFSM_PATTERN pe = FsmpLookupPattern(
                        Engine, srcNodeId, tgtNodeId, (UINT8)p);
                    if (pe) {
                        pe->ThreatScore = 0;
                        pe->CurrentStep = 0;
                        pe->LastStepTime.QuadPart = 0;
                        RtlZeroMemory(pe->States, sizeof(pe->States));
                        RemoveEntryList(&pe->TrackerLink);
                        tracker->ActivePatternMask &= ~(1 << p);
                        FsmFreeStateEntry(Engine, pe);
                    }
                }
            }
        }
    }

    tracker->LastActivity = now;
    Engine->TotalEventsProcessed++;
    LeaveCriticalSection(&Engine->Lock);
    return Result->HasAccept;
}

/**************************************************/
/*           FsmCleanupExpired                     */
/**************************************************/

VOID
FsmCleanupExpired(
    _In_ PIOA_FSM_ENGINE Engine
    )
/*++
Routine Description:
    后台清理过期状态条目。
    超时判定: LastStepTime 超过步骤 TimeoutMs 即清理。
    超时条目: 部分报告 + 重置 + 释放。

    应由后台线程周期性调用 (每 FSM_CLEANUP_INTERVAL_MS)。
--*/
{
    LARGE_INTEGER now;
    LONGLONG nowMs;
    ULONG b;
    LONG cleaned = 0;

    if (!Engine || !Engine->Initialized) return;

    GetSystemTimeAsFileTime((LPFILETIME)&now);
    nowMs = now.QuadPart / 10000;

    EnterCriticalSection(&Engine->Lock);

    for (b = 0; b < FSM_STATE_HASH_BUCKETS; b++) {
        PLIST_ENTRY head = &Engine->PatternHashBuckets[b];
        PLIST_ENTRY entry = head->Flink;

        while (entry != head) {
            PFSM_PATTERN pe = CONTAINING_RECORD(
                entry, FSM_PATTERN, HashLink);
            PLIST_ENTRY next = entry->Flink;

            if (pe->CurrentStep > 0 &&
                pe->CurrentStep < Engine->Patterns[pe->PatternIndex].StateCount) {

                const PFSM_STATE_TRANSITION step =
                    &Engine->Patterns[pe->PatternIndex].Steps[pe->CurrentStep];
                LONGLONG age = nowMs - (pe->LastStepTime.QuadPart / 10000);

                if (step->TimeoutMs > 0 && age > (LONGLONG)step->TimeoutMs) {
                    FsmReportPartial(Engine, pe, now);

                    if (pe->OwnerTracker) {
                        pe->OwnerTracker->ActivePatternMask &= ~(1 << pe->PatternIndex);
                    }

                    RemoveEntryList(&pe->TrackerLink);
                    FsmFreeStateEntry(Engine, pe);
                    Engine->TotalTimeouts++;
                    cleaned++;
                }
            }
            entry = next;
        }
    }

    LeaveCriticalSection(&Engine->Lock);

    if (cleaned > 0) {
        printf("[FsmEngine] Cleanup: %ld timed-out state entries removed\n", cleaned);
    }
}

/**************************************************/
/*           FsmGetStats / Initialize / Cleanup    */
/**************************************************/

VOID
FsmGetStats(
    _In_  PIOA_FSM_ENGINE Engine,
    _Out_ ULONG*          ActiveTrackers,
    _Out_ ULONG*          PeakTrackers,
    _Out_ LONG64*         TotalProcessed,
    _Out_ LONG64*         TotalMatches,
    _Out_ LONG64*         TotalTimeouts
    )
{
    if (Engine && Engine->Initialized) {
        if (ActiveTrackers) *ActiveTrackers = (ULONG)Engine->PatternCount;
        if (PeakTrackers)  *PeakTrackers  = 0;
        if (TotalProcessed)*TotalProcessed = Engine->TotalEventsProcessed;
        if (TotalMatches)  *TotalMatches   = Engine->TotalAcceptHits;
        if (TotalTimeouts) *TotalTimeouts  = Engine->TotalTimeouts;
    }
}

NTSTATUS
FsmInitialize(
    _Out_ PIOA_FSM_ENGINE* Out
    )
{
    PIOA_FSM_ENGINE e;
    ULONG i;

    e = UtHeapAlloc(sizeof(IOA_FSM_ENGINE));
    if (!e) return STATUS_NO_MEMORY;

    for (i = 0; i < FSM_STATE_HASH_BUCKETS; i++) {
        InitializeListHead(&e->PatternHashBuckets[i]);
    }

    memcpy(e->Patterns, g_FsmBuiltinPatterns, sizeof(g_FsmBuiltinPatterns));

    InitializeCriticalSection(&e->Lock);
    e->Initialized = TRUE;

    printf("[FsmEngine] Initialized: %u patterns, %u sparse hash buckets "
           "(multi-way merge model)\n",
           FSM_PATTERN_COUNT, FSM_STATE_HASH_BUCKETS);
    for (i = 0; i < FSM_PATTERN_COUNT; i++) {
        printf("[FsmEngine]   Pattern[%u]: %S (FsmClass=%d) %u states, threshold=%u\n",
               i, e->Patterns[i].Name, (int)e->Patterns[i].FsmClass,
               e->Patterns[i].StateCount, e->Patterns[i].AcceptThreshold);
    }

    *Out = e;
    return STATUS_SUCCESS;
}

VOID
FsmCleanup(
    _In_ PIOA_FSM_ENGINE Engine
    )
{
    if (!Engine || !Engine->Initialized) return;

    Engine->Initialized = FALSE;
    EnterCriticalSection(&Engine->Lock);

    for (ULONG b = 0; b < FSM_STATE_HASH_BUCKETS; b++) {
        while (!IsListEmpty(&Engine->PatternHashBuckets[b])) {
            PLIST_ENTRY entry = RemoveHeadList(&Engine->PatternHashBuckets[b]);
            PFSM_PATTERN se = CONTAINING_RECORD(entry, FSM_PATTERN, HashLink);
            UtHeapFree(se);
        }
    }

    LeaveCriticalSection(&Engine->Lock);
    DeleteCriticalSection(&Engine->Lock);

    printf("[FsmEngine] Cleanup: entries=%ld created=%lld freed=%lld "
           "processed=%lld matches=%lld timeouts=%lld partials=%lld\n",
           Engine->PatternCount, Engine->TotalStateEntriesCreated,
           Engine->TotalStateEntriesFreed, Engine->TotalEventsProcessed,
           Engine->TotalAcceptHits, Engine->TotalTimeouts,
           Engine->TotalPartialsReported);

    UtHeapFree(Engine);
}
