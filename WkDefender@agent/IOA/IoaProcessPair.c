/**************************************************/
/*  WkDefender IOA — 进程对管理器实现                */
/**************************************************/

#include "IoaProcessPair.h"
#include "IoaEdgeAggregate.h"
#include "PairAnalysisContext.h"      /* 三分析上下文分配/释放 (改造点四, 2026-08-23) */
#include "../DefendTypes.h"
#include "../PolicyEngine/PolicyEngine.h"
#include "../Process/ProcessTree.h"
#include <string.h>

/**************************************************/
/*             对数饱和评分常量                      */
/*             与 Driver 侧 IoapGetPairScore 一致    */
/**************************************************/

#define LOG2_SAT_CEILING   7
#define LOG2_SAT_STEP_PCT  14

/**************************************************/
/*       受监视进程对 key 表 (调试/存在性巡检)       */
/*  用途: 验证 IocCleanupExpiredProcessPair 快照     */
/*  枚举是否漏掉特定目标进程对 (如 <system,loadpe>/  */
/*  <explorer,loadpe>/<loadpe,loadpe>)。            */
/*  注册经 IocRegisterMonitoredProcessPair (Engine.c */
/*  命中 loadpe 时调用), 巡检在快照后逐 key 用       */
/*  AeLookupProcessPair 精确直查 PairMap。          */
/**************************************************/

#define IOA_MONITORED_PAIR_MAX  16

static SRWLOCK                     g_MonitorLock   = SRWLOCK_INIT;
static AE_PROCESS_PAIR_KEY         g_MonitorKeys[IOA_MONITORED_PAIR_MAX];
static ULONG                       g_MonitorKeyCount = 0;

/**************************************************/
/*             边类型语义权重表                      */
/*             与 Driver 侧 G_IoapBitWeights 对应    */
/**************************************************/

/*
 * 每种 IOA_GRAPH_EDGE_TYPE 的语义权重。
 * 索引 = EdgeType 枚举值。未定义的边类型权重=0。
 */
static const ULONG G_EdgeTypeWeights[] = {
    [DefEdge_Creates]        = 10,
    [DefEdge_Terminates]     = 10,
    [DefEdge_WritesTo]       = 25,
    [DefEdge_ReadsFrom]      = 20,
    [DefEdge_Executes]       = 20,
    [DefEdge_Opens]          = 20,
    [DefEdge_InjectsInto]    = 35,
    [DefEdge_Hollows]        = 35,
    [DefEdge_ReflectiveLoad] = 30,
    [DefEdge_Sideloads]      = 25,
    [DefEdge_ConnectsTo]     = 20,
    [DefEdge_ListensOn]      = 15,
    [DefEdge_DnsQueries]     = 10,
    [DefEdge_Modifies]       = 15,
    [DefEdge_Allocates]      = 25,
    [DefEdge_Protects]       = 25,
    [DefEdge_Impersonates]   = 30,
    [DefEdge_AssociatedWith] = 15,
};

#define EDGE_TYPE_WEIGHT_COUNT \
    (sizeof(G_EdgeTypeWeights) / sizeof(G_EdgeTypeWeights[0]))

/**************************************************/
/*             组合检测模式表                       */
/*             移植自 Driver 侧 G_IoaComboPatterns  */
/**************************************************/

typedef struct _PAIR_COMBO_PATTERN {
    UCHAR       SlotCount;
    IOA_GRAPH_EDGE_TYPE SlotTypes[4];
    ULONG       BonusScore;
    PCSTR       Description;
} PAIR_COMBO_PATTERN;

#define PAIR_MAX_COMBO_PATTERNS 16

static const PAIR_COMBO_PATTERN G_PairComboPatterns[PAIR_MAX_COMBO_PATTERNS] = {

    /* ── 四槽组合 ── */
    { 4, { DefEdge_Opens, DefEdge_Allocates, DefEdge_WritesTo, DefEdge_InjectsInto }, 75,
      "APC注入链: Opens+Allocates+WritesTo+InjectsInto" },
    { 4, { DefEdge_Opens, DefEdge_Allocates, DefEdge_WritesTo, DefEdge_AssociatedWith }, 65,
      "远程线程注入链: Opens+Allocates+WritesTo+AssociatedWith" },

    /* ── 三槽组合 ── */
    { 3, { DefEdge_Opens, DefEdge_WritesTo, DefEdge_InjectsInto }, 50,
      "简化注入: Opens+WritesTo+InjectsInto" },
    { 3, { DefEdge_Allocates, DefEdge_WritesTo, DefEdge_Protects }, 45,
      "Shellcode加载: Allocates+WritesTo+Protects" },
    { 3, { DefEdge_Opens, DefEdge_Allocates, DefEdge_AssociatedWith }, 55,
      "线程劫持: Opens+Allocates+AssociatedWith" },
    { 3, { DefEdge_Hollows, DefEdge_Creates, DefEdge_InjectsInto }, 50,
      "进程镂空确认: Hollows+Creates+InjectsInto" },

    /* ── 双槽组合 ── */
    { 2, { DefEdge_Opens, DefEdge_InjectsInto }, 35,
      "远程线程: Opens+InjectsInto" },
    { 2, { DefEdge_Opens, DefEdge_AssociatedWith }, 30,
      "线程操纵: Opens+AssociatedWith" },
    { 2, { DefEdge_Opens, DefEdge_WritesTo }, 20,
      "内存写入: Opens+WritesTo" },
    { 2, { DefEdge_Allocates, DefEdge_Protects }, 25,
      "可执行内存: Allocates+Protects" },

    /* 哨兵 */
    { 0, { 0, 0, 0, 0 }, 0, NULL },
};

/**************************************************/
/*               内部辅助: 对数饱和                  */
/**************************************************/

static
ULONG
IntegerLog2(
    _In_ ULONG Value
    )
{
    ULONG index;
    if (Value == 0) return 0;
    _BitScanReverse(&index, Value);
    return index;
}

/**************************************************/
/*               内部辅助: 获取边类型权重             */
/**************************************************/

static
ULONG
PairGetEdgeTypeWeight(
    _In_ IOA_GRAPH_EDGE_TYPE EdgeType
    )
{
    if ((ULONG)EdgeType >= EDGE_TYPE_WEIGHT_COUNT) return 0;
    return G_EdgeTypeWeights[EdgeType];
}

/**************************************************/
/*               内部辅助: 组合检测                  */
/**************************************************/

static
ULONG
PairCalcComboBonus(
    _In_ PAE_PROCESS_PAIR Pair
    )
/*++
Routine Description:
    遍历 G_PairComboPatterns，检查进程对的 InteractionBitmap 数据层
    是否满足组合条件。使用贪心策略：多槽组合优先匹配，
    已匹配的组合中的边类型不参与后续组合。

    与 Driver 侧 IoapCalcComboBonus 逻辑一致。

Return Value:
    组合加分 [0, 100]。
--*/
{
    ULONG bonus = 0;
    ULONG usedMask = 0;     /* 已被组合使用的边类型位图 */
    ULONG i;

    for (i = 0; G_PairComboPatterns[i].SlotCount > 0; i++) {
        const PAIR_COMBO_PATTERN* pat = &G_PairComboPatterns[i];
        BOOLEAN match = TRUE;
        ULONG patTypeMask = 0;

        /* 构建该组合的边类型位图 */
        for (UCHAR j = 0; j < pat->SlotCount; j++) {
            patTypeMask |= (1UL << pat->SlotTypes[j]);
        }

        /* 检查是否与已使用的边类型重叠 */
        if (usedMask & patTypeMask) {
            continue;   /* 贪心: 跳过重叠组合 */
        }

        /* 检查所有指定边类型是否都活跃 (数据层位图) */
        {
            ULONG64 dataMask = BM_DATA_U64(&Pair->InteractionBitmap);
            for (UCHAR j = 0; j < pat->SlotCount; j++) {
                ULONG64 bit = 1ULL << pat->SlotTypes[j];
                if (!(dataMask & bit)) {
                    match = FALSE;
                    break;
                }
            }
        }

        if (match) {
            bonus += pat->BonusScore;
            usedMask |= patTypeMask;
            if (bonus >= 100) break;
        }
    }

    return min(bonus, 100);
}

/**************************************************/
/*          HashMap ref/deref 回调                  */
/**************************************************/

/* 查找/插入命中 pin：RefCount++（与调用方归还配对）。锁内仅原子。 */
_Use_decl_annotations_
LONG
AeReferenceProcessPair(
    _In_ PAE_PROCESS_PAIR Pair
    )
{
    if (Pair) {
        return InterlockedIncrement(&Pair->RefCount);
    }
}

/*++
 * AepDestroyProcessPair — 进程对统一销毁入口 (2026-08-25)。
 *
 * 唯一物理释放路径: AeDereferenceProcessPair 在 RefCount 归零
 * (表引用与全部外部 pin 归还) 时调用; 创建失败回滚副本亦经
 * Dereference 归零抵达本函数, 天然覆盖"未完全初始化"形态:
 *   - 三分析上下文可能部分/全部缺失 (AeDestroyProcessPairContexts
 *     逐域判 NULL, 幂等);
 *   - SrcNode/TgtNode 可能为 NULL (上下文分配早退, 引用尚未挂出);
 *   - 双向链头构造即自环 (FindOrCreate 于任何可失败步骤前
 *     InitializeListHead), IsListEmpty 判定完备;
 *   - FsmTracker / 序列匹配状态可能不存在。
 *
 * 锁序契约:
 *   - 调用方可能处于 map 桶独占锁内 (CoRemoveHashMapEntry 的
 *     Deref 回调), 本函数仅获取下游单向锁 (PairLinksLock /
 *     FSM Engine->Lock / SeqEngine.Lock), 各锁域无反向获取路径;
 *   - PsDereferenceWkdProcess 一律在 PairLinksLock 外执行 —
 *     节点引用归零将触发 PspDestroyWkdProcess 重入同一把锁;
 *   - 摘链后链节重置自环, 本函数幂等, 抵御重复销毁。
 * --*/
static
VOID
AepDestroyProcessPair(
    _In_ PAE_PROCESS_PAIR Pair
    )
{
    NTSTATUS status;
    PWKD_PROCESS sourceWkdProcess = NULL;
    PWKD_PROCESS targetWkdProcess = NULL;

    if (!Pair) return;

    status = PsLookupWkdProcessByProcessId(NULL, Pair->SourceProcessId, &sourceWkdProcess);
    if (!NT_SUCCESS(status)) goto Cleanup;
    status = PsLookupWkdProcessByProcessId(NULL, Pair->TargetProcessId, &targetWkdProcess);
    if (!NT_SUCCESS(status)) goto Cleanup;

    /* ---- 摘除 Source 端双向关联 (挂/摘同锁域: PairLinksLock) ---- */
    //AcquireSRWLockExclusive(&sourceWkdProcess->PairLinksLock);
    //if (!IsListEmpty(&Pair->SourceProcessLinks)) {
    //    RemoveAggEdgeList(&Pair->SourceProcessLinks);
    //    InitializeListHead(&Pair->SourceProcessLinks);   /* 幂等标记 */
    //    InterlockedDecrement(&sourceWkdProcess->OutPairCount);
    //}
    //ReleaseSRWLockExclusive(&sourceWkdProcess->PairLinksLock);
    //PsDereferenceWkdProcess(sourceWkdProcess);

    /* ---- 摘除 Target 端双向关联 ---- */
    //AcquireSRWLockExclusive(&targetWkdProcess->PairLinksLock);
    //if (!IsListEmpty(&Pair->TargetProcessLinks)) {
    //    RemoveAggEdgeList(&Pair->TargetProcessLinks);
    //    InitializeListHead(&Pair->TargetProcessLinks);   /* 幂等标记 */
    //    InterlockedDecrement(&targetWkdProcess->InPairCount);
    //}
    //ReleaseSRWLockExclusive(&targetWkdProcess->PairLinksLock);
    //PsDereferenceWkdProcess(targetWkdProcess);

    /* ---- 释放关联的 FsmTracker — ActivePatternHead 归 FSM
     * Engine->Lock 管辖; 先本地接管指针 (此刻无人可达) 再持锁清链,
     * 不形成两锁嵌套; 引擎未初始化 (teardown 时序) 则无锁兜底 ---- */
    //if (Pair->FsmTracker) {
    //    PIOA_FSM_TRACKER tracker = Pair->FsmTracker;
    //    PIOA_FSM_ENGINE fsmEngine = WkdIoaEngine.FsmEngine;
    //    Pair->FsmTracker = NULL;
    //    if (fsmEngine && fsmEngine->Initialized) {
    //        EnterCriticalSection(&fsmEngine->Lock);
    //        while (!IsListEmpty(&tracker->ActivePatternHead)) {
    //            PLIST_ENTRY se = RemoveHeadList(&tracker->ActivePatternHead);
    //            PFSM_PATTERN stateAggEdge = CONTAINING_RECORD(
    //                se, FSM_PATTERN, TrackerLink);
    //            RemoveAggEdgeList(&stateAggEdge->HashLink);
    //            UtHeapFree(stateAggEdge);
    //        }
    //        LeaveCriticalSection(&fsmEngine->Lock);
    //    } else {
    //        while (!IsListEmpty(&tracker->ActivePatternHead)) {
    //            PLIST_ENTRY se = RemoveHeadList(&tracker->ActivePatternHead);
    //            PFSM_PATTERN stateAggEdge = CONTAINING_RECORD(
    //                se, FSM_PATTERN, TrackerLink);
    //            RemoveAggEdgeList(&stateAggEdge->HashLink);
    //            UtHeapFree(stateAggEdge);
    //        }
    //    }
    //    UtHeapFree(tracker);
    //}

    /* ---- 回收序列规则引擎状态 (SeqEngine 锁域, 引擎未初始化则跳过) ---- */
    // PolicyEngine_RemovePairSequenceStates(Pair);

    /* ---- 摘除本 pair 挂载的全部子边 (聚合边是子对象): 清空 OwnerPair + 摘 PairLink ----
     * 进程对是主对象, 其子边回收由 IocCleanupExpiredProcessPair 经 AepRefreshProcessPair
     * 在删除 pair 之前统一完成 (销毁时 EdgeListHead 必已空); 此处仍兜底摘链以防重复
     * 销毁/异常路径。摘链在 EdgeListLock 独占下完成, 与 AttachEdge 同锁域; PairLink
     * 重置自环, 幂等抵御重复销毁。 */
    {
        PLIST_ENTRY entry;
        AcquireSRWLockExclusive(&Pair->EdgeListLock);
        while (!IsListEmpty(&Pair->EdgeListHead)) {
            entry = RemoveHeadList(&Pair->EdgeListHead);
            InitializeListHead(entry);
            {
                PIOA_AGGREGATE_EDGE edge = CONTAINING_RECORD(entry, IOA_AGGREGATE_EDGE, PairLink);
                edge->OwnerPair = NULL;   /* 裸回指置空, 边清扫见 NULL 即跳过 owner 锁 */
            }
        }
        ReleaseSRWLockExclusive(&Pair->EdgeListLock);
    }

    /* 释放进程对所持有的进程对象引用计数 */
    PsDereferenceWkdProcess(sourceWkdProcess);
    PsDereferenceWkdProcess(targetWkdProcess);

    /* ---- 三分析上下文 (逐域判 NULL + 置 NULL, 幂等) ---- */
    AeDestroyProcessPairContexts(Pair);
    free(Pair);

Cleanup:
    if (sourceWkdProcess) PsDereferenceWkdProcess(sourceWkdProcess);
    if (targetWkdProcess) PsDereferenceWkdProcess(targetWkdProcess);
}

_Use_decl_annotations_
LONG
AeDereferenceProcessPair(
    _In_ PAE_PROCESS_PAIR Pair
    )
/*++
Routine Description:
    归还 pair 存活引用（RefCount--）。计数归零即最后一个引用
    （表引用或外部 pin）已归还，无人再可达 → 就地调用
    AepDestroyProcessPair 完成全套销毁（摘双向关联/归还节点引用/
    FsmTracker/序列状态/三分析上下文/本体）。

    经 CoRemoveHashMapEntry 触发时本调用处于 map 桶独占锁内，
    销毁仅获取下游单向锁，锁序安全（详见 AepDestroyProcessPair）。

Arguments:
    Pair — PAE_PROCESS_PAIR（可 NULL，静默忽略）。

Return Value:
    VOID。
--*/
{
    LONG ref;

    if (!Pair) return MAXLONG;
    ref = InterlockedDecrement(&Pair->RefCount);
    if (ref == 0) {
        /* 计数归零 = 无并发可达者, 统一销毁入口完成物理释放 */
        AepDestroyProcessPair(Pair);
    }
    return ref;
}

/* 移除裁决（Remove 独占锁内调用）：仅剩表引用（RefCount<=1，
 * 即无外部 pin 借出）方可摘除。闭合"枚举→复查→Remove 窗口内
 * 并发 Lookup pin"的 UAF：复查通过后若被并发 pin，此处裁决
 * 取消移除，延至下轮清扫兜底（对齐计划预留设计）。 */
static BOOLEAN
AepShouldRemoveProcessPair(
    _In_ const PAE_PROCESS_PAIR Pair,
    _In_ BOOLEAN HoldLock
    )
{
    return (Pair->RefCount == (HoldLock ? 2 : 1));
}

/*
 * 全量释放收集回调: 仅拷贝 pair 指针到数组, 不做任何释放/修改
 * (对齐 IocpExpiredProcessPairEnumerationCallback 只读契约)。释放动作由调用方在枚举
 * 结束后循环完成 (两阶段: 收集 → 释放, 与 CleanupExpired 一致)。
 */
typedef struct _PAIR_COLLECT_CTX {
    PAE_PROCESS_PAIR* All;       /* pair 指针数组 (容量 = Count) */
    ULONG                       Capacity;
    ULONG                       Count;
} PAIR_COLLECT_CTX, *PPAIR_COLLECT_CTX;

static BOOLEAN
PairCollectAllCallback(
    _In_     PVOID Key,
    _In_     ULONG KeySize,
    _In_     PVOID Value,
    _Inout_  PVOID Context
    )
{
    PPAIR_COLLECT_CTX ctx = (PPAIR_COLLECT_CTX)Context;
    PAE_PROCESS_PAIR pairCtx = (PAE_PROCESS_PAIR)Value;

    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(KeySize);

    if (ctx->Count < ctx->Capacity) {
        ctx->All[ctx->Count++] = pairCtx;
    }
    return TRUE;
}

/**************************************************/
/*                   公开 API                       */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
PairManager_Initialize(
    PIOA_PROCESS_PAIR_MANAGER* Out
    )
{
    PIOA_PROCESS_PAIR_MANAGER mgr;

    mgr = UtHeapAlloc(sizeof(IOA_PROCESS_PAIR_MANAGER));
    if (!mgr) return STATUS_NO_MEMORY;

    RtlZeroMemory(mgr, sizeof(IOA_PROCESS_PAIR_MANAGER));

    /* HashMap 化 (2026-08-25 强制对称契约): 注册 ref/deref 成对回调。
     * 引用模型: 创建方预置 RefCount=1 (调用者 pin) + Insert 回调 +1
     * (表引用) = 2; Lookup 命中 pin +1; Remove 触发 Deref -1 (表引用)。
     * ShouldRemove 裁决"仅剩表引用方可摘除", 防摘除与并发 pin 竞态。 */
    {
        NTSTATUS status = CoInitializeHashMap(
            &mgr->PairMap, PAIR_MAP_BUCKETS, PAIR_MAX_COUNT,
            TRUE, TRUE,
            AeReferenceProcessPair, AepShouldRemoveProcessPair, AeDereferenceProcessPair);
        if (!NT_SUCCESS(status)) {
            UtHeapFree(mgr);
            return status;
        }
    }

    mgr->MaxPairs      = PAIR_MAX_COUNT;
    mgr->PairTtlMs     = PAIR_TTL_MS;

    InitializeCriticalSection(&mgr->Lock);
    mgr->Initialized = TRUE;

    printf("[PairManager] Initialized: %u map buckets, max %u pairs, TTL=%ums\n",
           PAIR_MAP_BUCKETS, PAIR_MAX_COUNT, PAIR_TTL_MS);

    *Out = mgr;
    return STATUS_SUCCESS;
}

VOID
PairManager_Cleanup(
    PIOA_PROCESS_PAIR_MANAGER Manager
    )
/*++
Routine Description:
    清理进程对管理器，释放所有进程对。
    注意：不释放关联的 EdgeAggregate 条目（由 IoaCleanupAggregateEdgeTable 负责）。
--*/
{
    ULONG totalFreed = 0;
    ULONG removed = 0;

    if (!Manager || !Manager->Initialized) return;

    EnterCriticalSection(&Manager->Lock);

    totalFreed = InterlockedCompareExchange(&Manager->ActivePairs, 0, 0);

    /* 两阶段全量销毁 (2026-08-25 统一路径):
     * 阶段1 — CoEnumerateHashMap 共享锁内收集全部 pair 指针
     *          (回调只读, 不解引用/释放);
     * 阶段2 — 逐个 CoRemoveHashMapEntry: Deref 回调扣减表引用,
     *          归零即经 AepDestroyProcessPair 完成全套销毁
     *          (节点双向关联摘除 + 节点引用归还 + FsmTracker/
     *          序列状态/三上下文/本体)。teardown 时序下 FSM/
     *          Seq 引擎未初始化已由销毁入口容错。
     * CoHashMapClear 随后仅回收桶/entry 包装 (引用已在阶段2清零)。 */
    if (totalFreed > 0) {
        PAE_PROCESS_PAIR* all =
            UtHeapAlloc(totalFreed * sizeof(PAE_PROCESS_PAIR));
        if (all) {
            PAIR_COLLECT_CTX ctx;
            ULONG i;

            ctx.All      = all;
            ctx.Capacity = totalFreed;
            ctx.Count    = 0;
            CoEnumerateHashMap(&Manager->PairMap, PairCollectAllCallback, &ctx);

            for (i = 0; i < ctx.Count; i++) {
                PAE_PROCESS_PAIR pairCtx = ctx.All[i];
                AE_PROCESS_PAIR_KEY key;

                key.SourceProcessId = pairCtx->SourceProcessId;
                key.TargetProcessId = pairCtx->TargetProcessId;
                if (CoRemoveHashMapEntry(&Manager->PairMap, &key, sizeof(key), FALSE)) {
                    removed++;
                }
            }
            UtHeapFree(all);
        }
    }

    CoHashMapClear(&Manager->PairMap);
    InterlockedExchange(&Manager->ActivePairs, 0);

    Manager->Initialized = FALSE;
    LeaveCriticalSection(&Manager->Lock);
    DeleteCriticalSection(&Manager->Lock);

    printf("[PairManager] Cleanup: %lu/%lu pairs destroyed\n", removed, totalFreed);
    UtHeapFree(Manager);
}

NTSTATUS
AeLookupProcessPair(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _Out_ PAE_PROCESS_PAIR* Pair
    )
/*++
Routine Description:
    精确查找（只查不建）。HashMap 命中经回调 pin (+1) 借出，
    调用方用完须 AeDereferenceProcessPair 归还（2026-08-25
    强制对称契约）；pin 仅护同步消费，不可跨清扫摘除窗口持有。
--*/
{
    AE_PROCESS_PAIR_KEY key;
    PAE_PROCESS_PAIR pair;

    if (!SourceProcessId || !TargetProcessId || !Pair)
        return STATUS_INVALID_PARAMETER;
    *Pair = NULL;

    key.SourceProcessId = SourceProcessId;
    key.TargetProcessId = TargetProcessId;
    pair = (PAE_PROCESS_PAIR)CoLookupHashMapEntry(
        &WkdIoaEngine.PairManager->PairMap, &key, sizeof(AE_PROCESS_PAIR_KEY));
    if (pair) { *Pair = pair; return STATUS_SUCCESS; }
    else return STATUS_UNSUCCESSFUL;
}

NTSTATUS
AeFindOrCreateProcessPair(
    _Inout_ PWKD_PROCESS SourceWkdProcess,
    _Inout_ PWKD_PROCESS TargetWkdProcess,
    _Out_ PAE_PROCESS_PAIR* Pair
    )
/*++
Routine Description:
    查找或创建进程对上下文 (2026-08-24 重构: 收 PWKD_PROCESS 节点指针,
    对齐 driver AeFindOrCreateProcessPair 双路径范式)。

    快路径: HashMap 查找命中直接返回。
    慢路径: 预分配 pair + 初始化 → CoInsertHashMapEntry 内置 double-check，
            碰撞则取赢家释放本地副本。
    创建时建立与进程节点的双向关联 (SourceProcessLinks → SourceWkdProcess->OutPairListHead,
    TargetProcessLinks → TargetWkdProcess->InPairListHead) 并对两端 PsReferenceWkdProcess (+1)。

    key 保持 PID 二元组 (AE_PROCESS_PAIR_KEY 不变)：与 driver syscall
    同步阻断查询按 PID 二元组上送的通信契约一致。

    配额由 PairMap.MaxEntries 承接 (STATUS_QUOTA_EXCEEDED)；
    LRU 淘汰已废弃，淘汰由 IocCleanupExpiredProcessPair 按 LastSeen 摘除。

    引用契约 (2026-08-25 强制对称): *Pair 借出 pin (创建路径 =
    调用者 pin; 复用路径 = Lookup 回调 pin)，调用方用完须
    AeDereferenceProcessPair 归还。

Arguments:
    Src   — 源进程节点指针 (调用方保证存在)。
    Tgt   — 目标进程节点指针 (调用方保证存在)。

Return Value:
    STATUS_SUCCESS + *Pair 指向找到/新创建的对; 失败返回错误码。
--*/
{
    PIOA_PROCESS_PAIR_MANAGER mgr = WkdIoaEngine.PairManager;
    PAE_PROCESS_PAIR pair = NULL;
    NTSTATUS status;

    if (!mgr || !mgr->Initialized ||
        !SourceWkdProcess || !TargetWkdProcess || !Pair) {
        return STATUS_INVALID_PARAMETER;
    }
    *Pair = NULL;

    /* ---- 快路径 (Lookup 成功时 *Pair 已填写, 借出回调 pin) ---- */
    status = AeLookupProcessPair(SourceWkdProcess->ProcessId,
                                 TargetWkdProcess->ProcessId, &pair);
    if (NT_SUCCESS(status)) { *Pair = pair; return STATUS_SUCCESS; }

    /* ---- 慢速路径: 创建进程对 ---- */
    /* 2026-08-25 堆口径对齐 malloc/free (与 AepDestroyProcessPair 配对);
     * 零初始化必须显式 — FsmTracker/三上下文指针等域的"NULL=缺失"
     * 语义与销毁入口的逐域判空都依赖全零起点。 */
    pair = (PAE_PROCESS_PAIR)malloc(sizeof(AE_PROCESS_PAIR));
    if (!pair) return STATUS_NO_MEMORY;
    RtlZeroMemory(pair, sizeof(AE_PROCESS_PAIR));

    /* 基础骨架先行 (2026-08-25 "构造即自环"不变量): 双向链节/内部
     * 链头/锁/创建临时引用在任何可失败步骤之前就绪 — 后续任一
     * 失败路径统一经 AeDereferenceProcessPair 归零抵达
     * AepDestroyProcessPair, 其"未完全初始化"防护 (节点判 NULL /
     * 链头自环判定完备 / 上下文逐域 NULL) 因此成立。 */
    pair->RefCount = 1;   /* 创建临时引用 (成功时 Insert 回调再 +1 = 表引用, 合计 2) */
    pair->SourceProcessId = SourceWkdProcess->ProcessId;
    pair->TargetProcessId = TargetWkdProcess->ProcessId;
    pair->SourceNodeId = SourceWkdProcess->NodeId;
    pair->TargetNodeID = TargetWkdProcess->NodeId;
    InitializeListHead(&pair->SourceProcessLinks);
    InitializeListHead(&pair->TargetProcessLinks);
    InitializeListHead(&pair->EdgeListHead);
    InitializeListHead(&pair->SeqMatchHead);
    InitializeSRWLock(&pair->EdgeListLock);
    InitializeSRWLock(&pair->T1Feature.EwmaLock);

    /* 分配三分析上下文 (IOC/IOA/TS, 改造点四 2026-08-23 对齐 driver
     * AeFindOrCreateProcessPair 创建时全部分配); 失败归零临时引用
     * 经统一销毁入口回收半成品。 */
    status = AeCreateProcessPairContexts(pair);
    if (!NT_SUCCESS(status)) {
        AeDereferenceProcessPair(pair);
        return status;
    }

    /* 链头锁原则: pair 双向关联挂/摘一律持节点 PairLinksLock
     * (不借用 GenealogyLock — ChildrenHead 归它管, 职责分离) */
    //AcquireSRWLockExclusive(&SourceWkdProcess->PairLinksLock);
    //InsertTailList(&SourceWkdProcess->OutPairListHead, &pair->SourceProcessLinks);
    //InterlockedIncrement(&SourceWkdProcess->OutPairCount);
    //PsReferenceWkdProcess(SourceWkdProcess);
    //ReleaseSRWLockExclusive(&SourceWkdProcess->PairLinksLock);

    //AcquireSRWLockExclusive(&TargetWkdProcess->PairLinksLock);
    //InsertTailList(&TargetWkdProcess->InPairListHead, &pair->TargetProcessLinks);
    //InterlockedIncrement(&TargetWkdProcess->InPairCount);
    //PsReferenceWkdProcess(TargetWkdProcess);
    //ReleaseSRWLockExclusive(&TargetWkdProcess->PairLinksLock);

    {
        LARGE_INTEGER now;
        GetSystemTimeAsFileTime((LPFILETIME)&now);
        pair->FirstSeen    = now;
        pair->LastSeen     = now;
        pair->CreationTime = now;
    }

    {
        ULONG attempts = 3; // 重试次数
        PAE_PROCESS_PAIR existing = NULL;
        AE_PROCESS_PAIR_KEY key = { SourceWkdProcess->ProcessId, TargetWkdProcess->ProcessId };

Retry:
        if (0 == attempts--) {
            status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }

        status = CoInsertHashMapEntry(&mgr->PairMap, &key, sizeof(key), pair);
        if (NT_SUCCESS(status)) {
            LONG active = 0, peak = 0;

            InterlockedIncrement(&mgr->ActivePairs);
            InterlockedIncrement(&mgr->TotalPairs);
            do {
                active = InterlockedCompareExchange(&mgr->ActivePairs, 0, 0);
                peak = InterlockedCompareExchange(&mgr->PeakPairs, 0, 0);
            } while (active > peak &&
                InterlockedCompareExchange(&mgr->PeakPairs, active, peak) != peak);

            /* 将Src/Tgt进程对象与进程对绑定 */
            PsReferenceWkdProcess(SourceWkdProcess);
            PsReferenceWkdProcess(TargetWkdProcess);
            *Pair = pair;
            return STATUS_SUCCESS;
        } else if (status == STATUS_OBJECT_NAME_COLLISION) {
            /* 并发赢家已插入 → 本地副本未入表: 归还创建临时引用,
             * 归零即经统一销毁入口 (AepDestroyProcessPair) 完成摘链 +
             * 节点引用归还 + 半成品回收; 随后重查复用赢家副本 pin */
            status = AeLookupProcessPair(SourceWkdProcess->ProcessId,
                TargetWkdProcess->ProcessId, &existing);
            if (NT_SUCCESS(status)) {
                *Pair = existing;
                status = STATUS_SUCCESS;
                goto Cleanup;
            }
        }
        /* 插入失败重试 - 内存不足或极端情况下的新插入的项又被删除 */
        goto Retry;
    }

Cleanup:
    /* 释放 pair 及其上下文 */
    AepDestroyProcessPair(pair);
    return status;
}

BOOLEAN
IoaPairResolveNodeIds(
    _In_      PAE_PROCESS_PAIR Pair,
    _Out_opt_ GUID*                     SourceNodeId,
    _Out_opt_ GUID*                     TargetNodeId
    )
/*++
Routine Description:
    进程对键 → 节点 NodeId 反查。pair 键 PID 化后（2026-08-23），
    下游需要 GUID 的消费方经本 helper 从谱系树取 NodeId。
    任一端反查失败（占位/已回收/未找到）对应输出置零 GUID。

Return Value:
    两端均成功解析返回 TRUE；任一端失败返回 FALSE。
--*/
{
    PWKD_PROCESS sourceWkdProcess;
    PWKD_PROCESS targetWkdProcess;
    BOOLEAN ok = TRUE;

    if (!Pair) {
        if (SourceNodeId) RtlZeroMemory(SourceNodeId, sizeof(GUID));
        if (TargetNodeId) RtlZeroMemory(TargetNodeId, sizeof(GUID));
        return FALSE;
    }

    sourceWkdProcess = NULL;
    NTSTATUS _status = PsLookupWkdProcessByStrictProcessId(&WkdProcessTree,
                                    ULongToHandle(Pair->SourceProcessId), NULL, &sourceWkdProcess);
    if (!NT_SUCCESS(_status)) { sourceWkdProcess = NULL; }

    targetWkdProcess = NULL;
    _status = PsLookupWkdProcessByStrictProcessId(&WkdProcessTree,
                                    ULongToHandle(Pair->TargetProcessId), NULL, &targetWkdProcess);
    if (!NT_SUCCESS(_status)) { targetWkdProcess = NULL; }

    if (SourceNodeId) {
        if (sourceWkdProcess && !sourceWkdProcess->SecCtx.Placeholder) {
            *SourceNodeId = sourceWkdProcess->NodeId;
        } else {
            RtlZeroMemory(SourceNodeId, sizeof(GUID));
            ok = FALSE;
        }
    }
    if (TargetNodeId) {
        if (targetWkdProcess && !targetWkdProcess->SecCtx.Placeholder) {
            *TargetNodeId = targetWkdProcess->NodeId;
        } else {
            RtlZeroMemory(TargetNodeId, sizeof(GUID));
            ok = FALSE;
        }
    }

    /* 归还两端查找 pin (仅读 NodeId, 不跨函数持有) */
    if (targetWkdProcess) PsDereferenceWkdProcess(targetWkdProcess);
    if (sourceWkdProcess) PsDereferenceWkdProcess(sourceWkdProcess);
    return ok;
}

_Use_decl_annotations_
NTSTATUS
IoaAggregateEdgeAttachProcessPair(
    _Inout_ PAE_PROCESS_PAIR Pair,
    _Inout_ PIOA_AGGREGATE_EDGE AggEdge
    )
/*++
Routine Description:
    将边聚合条目挂载到进程对上下文的 EdgeListHead。
    数据层位图由 T1Evaluate 阶段1 无条件写入,
    此处不再重复操作。
    链头锁原则 (2026-08-25): 查重遍历 + 插入统一持
    Pair->EdgeListLock 独占。
--*/
{
    if (!Pair || !AggEdge) return STATUS_INVALID_PARAMETER;

    /* 将聚合边挂入进程对上下文 (聚合边是子对象, 进程对是主对象)。
     * 不再以"边是否存在于哈希表"做快速路径跳过 —— FindOrCreate 已把边入表,
     * 此前据此跳过导致边几乎从不挂入 EdgeListHead, 既破坏"进程对含有效聚合边"
     * 的清理判定, 也使 FSM 从 EdgeListHead 收集不到边。此处按 PairLink 是否已挂
     * 本 pair 判定幂等, 确保子边正确挂到主对象。 */
    if (InterlockedCompareExchangePointer(
        &AggEdge->OwnerPair, NULL, NULL) == Pair) {
        return STATUS_SUCCESS;   /* 已挂本 pair, 幂等 */
    }

    AcquireSRWLockExclusive(&Pair->EdgeListLock);
    //if (AggEdge->OwnerPair && AggEdge->OwnerPair != Pair) {
    //    /* 共享边 (全局 源/目标/类型 唯一) 极少跨 pair; 先放本锁再摘旧 pair,
    //     * 避免双锁嵌套 (链头锁原则: 永远先持"新 pair"锁, 再持"旧 pair"锁)。 */
    //    PAE_PROCESS_PAIR old = (PAE_PROCESS_PAIR)AggEdge->OwnerPair;
    //    ReleaseSRWLockExclusive(&Pair->EdgeListLock);
    //    AcquireSRWLockExclusive(&old->EdgeListLock);
    //    if (!IsListEmpty(&AggEdge->PairLink)) RemoveEntryList(&AggEdge->PairLink);
    //    ReleaseSRWLockExclusive(&old->EdgeListLock);
    //    AcquireSRWLockExclusive(&Pair->EdgeListLock);
    //    /* 重入校验: 期间可能被其他路径改挂, 简单跳过 (极端竞争, 下轮补挂) */
    //    if (AggEdge->OwnerPair) {
    //        ReleaseSRWLockExclusive(&Pair->EdgeListLock);
    //        return;
    //    }
    //}

    InsertTailList(&Pair->EdgeListHead, &AggEdge->PairLink);
    /* 注意: 对象引用应该遵循引用顺序，严禁互相引用!!! */
    AeReferenceProcessPair(Pair);
    AggEdge->OwnerPair = Pair;
    ReleaseSRWLockExclusive(&Pair->EdgeListLock);
    InterlockedIncrement(&Pair->ActiveEdges);
    InterlockedIncrement(&Pair->TotalEdges);
    InterlockedIncrement(&Pair->ActiveAggEdges);
    InterlockedIncrement(&Pair->TotalAggEdges);
}

VOID
PairContext_RefreshScore(
    _Inout_ PAE_PROCESS_PAIR Pair,
    _In_opt_ PWKD_PROCESS        SrcNode
    )
/*++
Routine Description:
    遍历 EdgeListHead，对所有 ActiveCount>0 的边类型:
      score += PairGetEdgeTypeWeight(type) × (100 + min(log2(ActiveCount),7) × 14) / 100

    汇总 <spn, tpn> 级别的 TotalEvents 和 ActiveEdges:
      - TotalEvents  = Σ OccurrenceCount (历史累计)
      - ActiveEdges = Σ ActiveCount      (活跃窗口内)

    评分已迁移至 IoaScorer, 特征由 IoaCollectFeatures 采集。
    此函数仅负责统计计数更新, 不再涉及评分计算。
    链头锁原则 (2026-08-25): 遍历统一持 Pair->EdgeListLock 共享。
--*/
{
    ULONG score = 0;
    LONG64 totalEvents = 0;
    LONG64 activeEvents = 0;
    PLIST_ENTRY entry;

    if (!Pair) return;

    AcquireSRWLockShared(&Pair->EdgeListLock);

    entry = Pair->EdgeListHead.Flink;
    while (entry != &Pair->EdgeListHead) {
        PIOA_AGGREGATE_EDGE ea = CONTAINING_RECORD(entry,
            IOA_AGGREGATE_EDGE, PairLink);

        totalEvents += ea->TotalEdges;
        activeEvents += ea->ActiveEdges;

        if (ea->ActiveEdges > 0) {
            ULONG weight = PairGetEdgeTypeWeight(ea->EdgeType);
            ULONG log2 = min(IntegerLog2(ea->ActiveEdges), LOG2_SAT_CEILING);
            ULONG sat100 = 100 + log2 * LOG2_SAT_STEP_PCT;

            score += weight * sat100 / 100;
        }

        entry = entry->Flink;
    }

    ReleaseSRWLockShared(&Pair->EdgeListLock);

    /* 写回 <spn, tpn> 级总计数 */
    Pair->TotalEdges = totalEvents;
    Pair->ActiveEdges = activeEvents;

    /* 评分不再由 PairContext_RefreshScore 负责, 已迁移至 IoaScorer */
}

/*
 * 刷新进程对的聚合边 (两阶段, 对齐 driver IoaRefreshProcessPair 对行为节点的回收):
 *   Phase 1 在 Pair->EdgeListLock 读锁下枚举 EdgeListHead, 对每个聚合边
 *           IoaReferenceAggregateEdge(pin) 防 UAF, 并按 ExistEdges 预判定拆入
 *           toRelease(无具体边, 直接回收) / toRefresh(需刷新);
 *   Phase 2 在 Pair->EdgeListLock 写锁下: 先对 toRefresh 调 IoaRefreshAggregateEdgeLocked
 *           回收过期具体边, "刷新后仍无有效具体边"则升级为 toRelease; 再对 toRelease
 *           统一从 EdgeAggTable 摘除 + 从 pair 链摘 + 释放。
 *   无过期项时 Phase 1 后即零写锁返回 (对齐 driver 短路返回)。
 *   锁序: EdgeListLock(外) → (IoaRefreshAggregateEdgeLocked 内 EdgeLock) →
 *         (CoRemoveHashMapEntry 桶锁), 单向无环。
 */
static
NTSTATUS
AepRefreshProcessPair(
    _Inout_ PAE_PROCESS_PAIR Pair,
    _In_ LARGE_INTEGER Now
    )
{
    PIOA_AGGREGATE_EDGE toRelease[64];
    PIOA_AGGREGATE_EDGE toRefresh[64];
    ULONG releaseCount = 0;
    ULONG refreshCount = 0;
    PIOA_AGGREGATE_EDGE aggEdge;

    if (!Pair || Now.QuadPart == 0) return STATUS_INVALID_PARAMETER;

    /* Phase 1: 读锁枚举 + 收集 (pin 防 UAF) */
    {
        PLIST_ENTRY entry;

        AcquireSRWLockShared(&Pair->EdgeListLock);
        entry = Pair->EdgeListHead.Flink;
        while (entry != &Pair->EdgeListHead) {
            aggEdge = CONTAINING_RECORD(entry, IOA_AGGREGATE_EDGE, PairLink);
            entry = entry->Flink;
            IoaReferenceAggregateEdge(aggEdge);   /* pin, 防 Phase2 处理前 UAF */
            if (InterlockedCompareExchange(&aggEdge->ActiveEdges, 0, 0) == 0) {
                if (releaseCount < 64) toRelease[releaseCount++] = aggEdge;
                else IoaDereferenceAggregateEdge(aggEdge);
            } else if ((LONGLONG)InterlockedCompareExchange64(
                &aggEdge->EarliestExpireTime.QuadPart, 0, 0) < Now.QuadPart) {
                if (refreshCount < 64) toRefresh[refreshCount++] = aggEdge;
                else IoaDereferenceAggregateEdge(aggEdge);
            } else IoaDereferenceAggregateEdge(aggEdge);
        }
        ReleaseSRWLockShared(&Pair->EdgeListLock);

        if (releaseCount == 0 && refreshCount == 0) {
            return STATUS_SUCCESS;  /* 无过期: 零写锁返回 */
        }
    }

    /* Phase 2: 写锁处理 */
    AcquireSRWLockExclusive(&Pair->EdgeListLock);

    /* 刷新待刷新边: 回收过期具体边; 无有效具体边则"升级"为待释放 */
    for (ULONG i = 0; i < refreshCount; i++) {
        aggEdge = toRefresh[i];
        AcquireSRWLockExclusive(&aggEdge->EdgeLock);
        
        IoaRefreshAggregateEdgeLocked(aggEdge, Now);
        if (InterlockedCompareExchange(&aggEdge->ActiveEdges, 0, 0) == 0) {
            if (releaseCount < 64) toRelease[releaseCount++] = aggEdge;
            else IoaDereferenceAggregateEdge(aggEdge);
        } else IoaDereferenceAggregateEdge(aggEdge);

        ReleaseSRWLockExclusive(&aggEdge->EdgeLock);
    }

    /* 释放待释放边: 二次确认无有效具体边 → 摘链 + 归还 Phase1 pin + 摘除表项 */
    for (ULONG i = 0; i < releaseCount; i++) {
        aggEdge = toRelease[i];
        AcquireSRWLockExclusive(&aggEdge->EdgeLock);

        if (InterlockedCompareExchange(&aggEdge->ActiveEdges, 0, 0) == 0) {
            IOA_AGGREGATE_EDGE_KEY removeKey = { aggEdge->SourceNodeId,
                aggEdge->TargetNodeId, aggEdge->EdgeType };

            if (CoRemoveHashMapEntry(&WkdIoaEngine.EdgeAggTable->HashMap,
                &removeKey, sizeof(removeKey), TRUE)) {
                RemoveEntryList(&aggEdge->PairLink);
                InterlockedDecrement(&Pair->ActiveAggEdges);
                /* 聚合边清理时需要回收进程对的引用计数 */
                AeDereferenceProcessPair(Pair);
            }
        }

        ReleaseSRWLockExclusive(&aggEdge->EdgeLock);
        /* 释放阶段1所持有的引用计数 */
        IoaDereferenceAggregateEdge(aggEdge);
    }

    ReleaseSRWLockExclusive(&Pair->EdgeListLock);

    return STATUS_SUCCESS;
}

/*++
 * 注册为受监视进程对 (按 PID 二元组去重)。
 * 供 Engine.c 命中目标 loadpe.exe 时调用, 记录真实事件源/目标 PID。
 * 并发安全: 写侧独占 SRWLOCK, 读侧共享 SRWLOCK。
 *
 * 参数:
 *   SourcePid — 源进程 PID。
 *   TargetPid — 目标进程 PID。
 *
 * 返回值: 无。
 *--*/
_Use_decl_annotations_
VOID
IocRegisterMonitoredProcessPair(
    _In_ HANDLE SourcePid,
    _In_ HANDLE TargetPid
    )
{
    ULONG i;

    /* 公共函数验证参数: PID 均不可为 0 (经 (ULONG)cast 后判 0) */
    if ((ULONG)(ULONG_PTR)SourcePid == 0 || (ULONG)(ULONG_PTR)TargetPid == 0) return;

    AcquireSRWLockExclusive(&g_MonitorLock);

    for (i = 0; i < g_MonitorKeyCount; i++) {
        if (g_MonitorKeys[i].SourceProcessId == SourcePid &&
            g_MonitorKeys[i].TargetProcessId == TargetPid) {
            /* 已注册, 去重返回 */
            ReleaseSRWLockExclusive(&g_MonitorLock);
            return;
        }
    }

    if (g_MonitorKeyCount < IOA_MONITORED_PAIR_MAX) {
        g_MonitorKeys[g_MonitorKeyCount].SourceProcessId = SourcePid;
        g_MonitorKeys[g_MonitorKeyCount].TargetProcessId = TargetPid;
        g_MonitorKeyCount++;
        printf("[PairMon] register monitor pair <%lu,%lu>\n",
            (ULONG)(ULONG_PTR)SourcePid, (ULONG)(ULONG_PTR)TargetPid);
    }

    ReleaseSRWLockExclusive(&g_MonitorLock);
}

/*++
 * 快照后对受监视进程对 key 逐个精确直查 PairMap, 打印存在性。
 * 用于对照快照枚举是否漏掉目标进程对 (验证"快照有时没有目标进程对")。
 * 直查经 AeLookupProcessPair (命中借出 pin, 用完必须 AeDereferenceProcessPair 归还)。
 * 注: 目前调用点已改为内联裸代码 (遍历快照 key 直接比对), 本函数暂时保留
 *     备用 (不声明 static 以避免 C4505 未使用告警)。
 *
 * 参数:
 *   Manager — 进程对管理器 (NULL 则直接返回)。
 *
 * 返回值: 无。
 *--*/
VOID
IocReportMonitoredPairsPresent(
    _In_opt_ PIOA_PROCESS_PAIR_MANAGER Manager
    )
{
    AE_PROCESS_PAIR_KEY keys[IOA_MONITORED_PAIR_MAX];
    ULONG               count = 0;
    ULONG               i;

    if (!Manager) return;

    /* 在共享锁下拷贝受监视 key 到局部数组, 避免持锁跨 AeLookupProcessPair */
    AcquireSRWLockShared(&g_MonitorLock);
    for (i = 0; i < g_MonitorKeyCount && i < IOA_MONITORED_PAIR_MAX; i++) {
        keys[i] = g_MonitorKeys[i];
    }
    count = i;
    ReleaseSRWLockShared(&g_MonitorLock);

    printf("[PairMon] ---- monitored pair presence check (%lu keys) ----\n", count);
    for (i = 0; i < count; i++) {
        PAE_PROCESS_PAIR p = NULL;
        NTSTATUS         st;

        st = AeLookupProcessPair(keys[i].SourceProcessId, keys[i].TargetProcessId, &p);
        if (NT_SUCCESS(st)) {
            printf("[PairMon] <%lu,%lu> PRESENT pair=%p Ref=%d Agg=%d ActiveEdges=%d\n",
                (ULONG)(ULONG_PTR)keys[i].SourceProcessId,
                (ULONG)(ULONG_PTR)keys[i].TargetProcessId,
                p, p->RefCount, p->ActiveAggEdges, p->ActiveEdges);
            AeDereferenceProcessPair(p);
        } else {
            printf("[PairMon] <%lu,%lu> ABSENT (st=0x%lx)\n",
                (ULONG)(ULONG_PTR)keys[i].SourceProcessId,
                (ULONG)(ULONG_PTR)keys[i].TargetProcessId,
                (ULONG)st);
        }
    }
    printf("[PairMon] ---- monitored pair presence check done ----\n");
}

_Use_decl_annotations_
VOID
IocCleanupExpiredProcessPair(
    _In_opt_ PIOA_PROCESS_PAIR_MANAGER Manager
    )
/*++
Routine Description:
    后台清理进程对 (对齐 driver AepPerformMaintenance 两阶段快照 + 刷新回收):
      Phase 1 — CoCaptureHashMapSnapshot 取 key-only 快照 (逐桶共享锁), 无 ref 负担;
      Phase 2 — 对快照每 key 执行 AeLookupProcessPair(pin) + IocpExpiredProcessPair-
                EnumerationCallback (刷新聚合边/具体边 + 判定是否仍含有效聚合边);
                归还查找 pin 后若无人持 pin (ShouldRemove(RefCount<=1)) 且无可有效
                聚合边 → CoRemoveHashMapEntry 回收空 pair (销毁统一走 AepDestroy-
                ProcessPair)。
    进程对是主对象, 聚合边是子对象: 仅当无任何有效聚合边时主对象方可清理。
关联的聚合边由本函数经 AepRefreshProcessPair 同步回收 (聚合边必挂靠进程对,
进程对删除受 pin/ShouldRemove 保护, 不存在无主孤儿聚合边, 故无需独立边表清扫)。
--*/
{
    NTSTATUS status;
    LARGE_INTEGER now;
    PWKD_HASH_MAP_SNAPSHOT snapshot = NULL;
    SIZE_T snapshotSize = 0;
    ULONG  capacity = 0;    // hashmap快照中的项数
    ULONG  cleaned = 0;

    if (!Manager) Manager = WkdIoaEngine.PairManager;
    if (!Manager || !Manager->Initialized) return;

    GetSystemTimeAsFileTime((LPFILETIME)&now);

    /* Phase 1: 查询容量 */
    status = CoCaptureHashMapSnapshot(&Manager->PairMap, NULL, &snapshotSize, NULL);
    if (snapshotSize == 0) return;
    else snapshotSize = ALIGN_UP_BY(snapshotSize, PAGE_SIZE);

    snapshot = (PWKD_HASH_MAP_SNAPSHOT)malloc(snapshotSize);
    if (!snapshot) return;

    /* Phase 2: 获取快照 (截断则仅处理已写入条目, 其余延迟下一轮) */
    status = CoCaptureHashMapSnapshot(&Manager->PairMap, snapshot, &snapshotSize, &capacity);
    if (!(NT_SUCCESS(status) ||
        /* 所提供缓冲区容量不足，存在 hashmap 项被遗漏，非致命 */
        status == STATUS_INFO_LENGTH_MISMATCH)) {
        goto Cleanup;
    }

    ///* [调试] 快照已返回的是进程对 key: 直接遍历快照内每个 key 与受监视 key
    // * (如 <system,loadpe>/<explorer,loadpe>/<loadpe,loadpe>) 比对, 判断目标
    // * 进程对是否被快照枚举到 (IN-SNAPSHOT) 或漏掉 (NOT-IN-SNAPSHOT)。
    // * 纯调试裸代码, 不再经 AeLookupProcessPair 反查。 */
    //{
    //    AE_PROCESS_PAIR_KEY mkeys[IOA_MONITORED_PAIR_MAX];
    //    ULONG               mcount = 0;
    //    BOOLEAN             mhit[IOA_MONITORED_PAIR_MAX];
    //    ULONG               mi;
    //    ULONG               sj;

    //    /* 拷贝受监视 key 表到局部 (共享锁) */
    //    AcquireSRWLockShared(&g_MonitorLock);
    //    for (mi = 0; mi < g_MonitorKeyCount && mi < IOA_MONITORED_PAIR_MAX; mi++) {
    //        mkeys[mi] = g_MonitorKeys[mi];
    //        mhit[mi] = FALSE;
    //    }
    //    mcount = mi;
    //    ReleaseSRWLockShared(&g_MonitorLock);

    //    /* 遍历快照返回的每个 key, 与受监视 key 比对 */
    //    /* 注意: WKD_HASH_MAP_SNAPSHOT 是变长结构 (KeySize + KeyData[]), 必须用
    //     * 指针按每项实际长度变长步进, 绝不能用下标 snapshot[i] (按 sizeof 固
    //     * 定步进会错位, 导致读不到正确 key)。 */
    //    {
    //        PWKD_HASH_MAP_SNAPSHOT se = (PWKD_HASH_MAP_SNAPSHOT)snapshot;
    //        for (sj = 0; sj < capacity; sj++) {
    //            AE_PROCESS_PAIR_KEY skey;
    //            SIZE_T              sks = se->KeySize;
    //            PUCHAR              Next = (PUCHAR)se + sizeof(SIZE_T) + sks;
    //            ULONG               mi2;

    //            if (sks != sizeof(AE_PROCESS_PAIR_KEY)) {
    //                /* 非法/非常规 key: 仍须按真实长度推进指针 */
    //                se = (PWKD_HASH_MAP_SNAPSHOT)Next;
    //                continue;
    //            }
    //            RtlCopyMemory(&skey, se->KeyData, sks);

    //            for (mi2 = 0; mi2 < mcount; mi2++) {
    //                if (mkeys[mi2].SourceProcessId == skey.SourceProcessId &&
    //                    mkeys[mi2].TargetProcessId == skey.TargetProcessId) {
    //                    mhit[mi2] = TRUE;
    //                }
    //            }

    //            se = (PWKD_HASH_MAP_SNAPSHOT)Next;
    //        }
    //    }

    //    printf("[PairMon] ---- in-snapshot check (%lu keys) ----\n", mcount);
    //    for (mi = 0; mi < mcount; mi++) {
    //        printf("[PairMon] <%lu,%lu> %s\n",
    //            (ULONG)(ULONG_PTR)mkeys[mi].SourceProcessId,
    //            (ULONG)(ULONG_PTR)mkeys[mi].TargetProcessId,
    //            mhit[mi] ? "IN-SNAPSHOT" : "NOT-IN-SNAPSHOT");
    //    }
    //    printf("[PairMon] ---- in-snapshot check done ----\n");
    //}

    /* 快照为变长结构 (KWKD: KeySize + KeyData[]): 用指针按每项实际长度变长
     * 步进遍历, 绝不能用下标 snapshot[i] (会按 sizeof 固定步进导致错位)。 */
    PWKD_HASH_MAP_SNAPSHOT se = snapshot;
    for (ULONG i = 0; i < capacity; i++) {
        AE_PROCESS_PAIR_KEY key;
        PAE_PROCESS_PAIR pair;
        PUCHAR Next = (PUCHAR)se + sizeof(SIZE_T) + se->KeySize;

        RtlCopyMemory(&key, se->KeyData, se->KeySize);
        se = (PWKD_HASH_MAP_SNAPSHOT)Next;

        status = AeLookupProcessPair(key.SourceProcessId, key.TargetProcessId, &pair);
        if (!NT_SUCCESS(status)) continue;   /* TOCTOU: 已被并发清理 */

        PWKD_PROCESS tmp1 = NULL, tmp2 = NULL;
        status = PsLookupWkdProcessByProcessId(NULL, key.SourceProcessId, &tmp1);
        if (!NT_SUCCESS(status)) continue;
        status = PsLookupWkdProcessByProcessId(NULL, key.TargetProcessId, &tmp2);
        if (!NT_SUCCESS(status)) continue;
        if ((CoCheckUnicodeStringValidity(&tmp1->ImagePath) &&
            _wcsicmp(tmp1->ImagePath->Buffer, L"c:\\users\\walker\\desktop\\loadpe.exe") == 0) ||
            (CoCheckUnicodeStringValidity(&tmp2->ImagePath) &&
                _wcsicmp(tmp2->ImagePath->Buffer, L"c:\\users\\walker\\desktop\\loadpe.exe") == 0)) {
            printf("############ found laodpe.exe! %ws %ws Pair=%p Pair.Ref=%d Pair.ActiveAggEdges=%d, Pair.ActiveEdges=%d\n", tmp1->ImagePath->Buffer, tmp2->ImagePath->Buffer, pair, pair->RefCount, pair->ActiveAggEdges, pair->ActiveEdges);
        }
        PWCHAR copy1 = _wcsdup(tmp1->ImagePath->Buffer);
        PWCHAR copy2 = _wcsdup(tmp2->ImagePath->Buffer);
        PsDereferenceWkdProcess(tmp1);
        PsDereferenceWkdProcess(tmp2);

        AepRefreshProcessPair(pair, now);
        AeDereferenceProcessPair(pair);

        InterlockedDecrement(&Manager->ActivePairs);
        if (InterlockedCompareExchange(&pair->ActiveAggEdges, 0, 0) == 0) {
            AE_PROCESS_PAIR_KEY removeKey = { key.SourceProcessId, key.TargetProcessId };
            if (CoRemoveHashMapEntry(&Manager->PairMap, &removeKey, sizeof(removeKey), FALSE)) {
                cleaned++;
                printf("############ %ws %ws released!\n", copy1, copy2);
            }
        }

        free(copy1);
        free(copy2);
    }

    if (cleaned > 0) {
        printf("[PairManager] Cleanup: %lu expired pairs removed\n", cleaned);
    }

Cleanup:
    free(snapshot);
}

ULONG
PairManager_GetCount(
    _In_ PIOA_PROCESS_PAIR_MANAGER Manager
    )
{
    if (!Manager) return 0;
    return InterlockedCompareExchange(&Manager->ActivePairs, 0, 0);
}

ULONG
PairManager_GetPeakCount(
    _In_ PIOA_PROCESS_PAIR_MANAGER Manager
    )
{
    if (!Manager) return 0;
    return InterlockedCompareExchange(&Manager->PeakPairs, 0, 0);
}
