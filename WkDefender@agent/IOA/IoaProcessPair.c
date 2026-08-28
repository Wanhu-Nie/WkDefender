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
    _In_ PAE_PROCESS_PAIR PairCtx
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
            ULONG64 dataMask = BM_DATA_U64(&PairCtx->InteractionBitmap);
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
static VOID
AepDestroyProcessPair(
    _In_ PAE_PROCESS_PAIR Pair
    )
{
    PWKD_PROCESS sourceWkdProcess;
    PWKD_PROCESS targetWkdProcess;

    if (!Pair) return;

    sourceWkdProcess = Pair->SrcNode;
    targetWkdProcess = Pair->TgtNode;

    /* ---- 摘除 Source 端双向关联 (挂/摘同锁域: PairLinksLock) ---- */
    AcquireSRWLockExclusive(&sourceWkdProcess->PairLinksLock);
    if (!IsListEmpty(&Pair->SourceProcessLinks)) {
        RemoveEntryList(&Pair->SourceProcessLinks);
        InitializeListHead(&Pair->SourceProcessLinks);   /* 幂等标记 */
        InterlockedDecrement(&sourceWkdProcess->OutPairCount);
    }
    ReleaseSRWLockExclusive(&sourceWkdProcess->PairLinksLock);
    PsDereferenceWkdProcess(sourceWkdProcess);

    /* ---- 摘除 Target 端双向关联 ---- */
    AcquireSRWLockExclusive(&targetWkdProcess->PairLinksLock);
    if (!IsListEmpty(&Pair->TargetProcessLinks)) {
        RemoveEntryList(&Pair->TargetProcessLinks);
        InitializeListHead(&Pair->TargetProcessLinks);   /* 幂等标记 */
        InterlockedDecrement(&targetWkdProcess->InPairCount);
    }
    ReleaseSRWLockExclusive(&targetWkdProcess->PairLinksLock);
    PsDereferenceWkdProcess(targetWkdProcess);

    /* ---- 释放关联的 FsmTracker — ActivePatternHead 归 FSM
     * Engine->Lock 管辖; 先本地接管指针 (此刻无人可达) 再持锁清链,
     * 不形成两锁嵌套; 引擎未初始化 (teardown 时序) 则无锁兜底 ---- */
    if (Pair->FsmTracker) {
        PIOA_FSM_TRACKER tracker = Pair->FsmTracker;
        PIOA_FSM_ENGINE fsmEngine = WkdIoaEngine.FsmEngine;
        Pair->FsmTracker = NULL;
        if (fsmEngine && fsmEngine->Initialized) {
            EnterCriticalSection(&fsmEngine->Lock);
            while (!IsListEmpty(&tracker->ActivePatternHead)) {
                PLIST_ENTRY se = RemoveHeadList(&tracker->ActivePatternHead);
                PFSM_PATTERN stateEntry = CONTAINING_RECORD(
                    se, FSM_PATTERN, TrackerLink);
                RemoveEntryList(&stateEntry->HashLink);
                UtHeapFree(stateEntry);
            }
            LeaveCriticalSection(&fsmEngine->Lock);
        } else {
            while (!IsListEmpty(&tracker->ActivePatternHead)) {
                PLIST_ENTRY se = RemoveHeadList(&tracker->ActivePatternHead);
                PFSM_PATTERN stateEntry = CONTAINING_RECORD(
                    se, FSM_PATTERN, TrackerLink);
                RemoveEntryList(&stateEntry->HashLink);
                UtHeapFree(stateEntry);
            }
        }
        UtHeapFree(tracker);
    }

    /* ---- 回收序列规则引擎状态 (SeqEngine 锁域, 引擎未初始化则跳过) ---- */
    PolicyEngine_RemovePairSequenceStates(Pair);

    /* ---- 三分析上下文 (逐域判 NULL + 置 NULL, 幂等) ---- */
    AeDestroyProcessPairContexts(Pair);

    /* ---- 本体 (与创建侧 UtHeapAlloc 配对) ---- */
    free(Pair);
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
    } else return ref;
}

/* 移除裁决（Remove 独占锁内调用）：仅剩表引用（RefCount<=1，
 * 即无外部 pin 借出）方可摘除。闭合"枚举→复查→Remove 窗口内
 * 并发 Lookup pin"的 UAF：复查通过后若被并发 pin，此处裁决
 * 取消移除，延至下轮清扫兜底（对齐计划预留设计）。 */
static BOOLEAN
AePairShouldRemove(
    _In_ PVOID Value
    )
{
    return ((PAE_PROCESS_PAIR)Value)->RefCount <= 1;
}

/*
 * 全量释放收集回调: 仅拷贝 pair 指针到数组, 不做任何释放/修改
 * (对齐 PairExpireCallback 只读契约)。释放动作由调用方在枚举
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
            FALSE, TRUE,
            AeReferenceProcessPair, AePairShouldRemove, AeDereferenceProcessPair);
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
    注意：不释放关联的 EdgeAggregate 条目（由 EdgeAggTable_Cleanup 负责）。
--*/
{
    ULONG totalFreed = 0;
    ULONG removed = 0;

    if (!Manager || !Manager->Initialized) return;

    EnterCriticalSection(&Manager->Lock);

    totalFreed = InterlockedCompareExchange(&Manager->ActivePairs, 0, 0);

    /* 两阶段全量销毁 (2026-08-25 统一路径):
     * 阶段1 — CoHashMapEnumerate 共享锁内收集全部 pair 指针
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
            CoHashMapEnumerate(&Manager->PairMap, PairCollectAllCallback, &ctx);

            for (i = 0; i < ctx.Count; i++) {
                PAE_PROCESS_PAIR pairCtx = ctx.All[i];
                AE_PROCESS_PAIR_KEY key;

                key.SourceProcessId = pairCtx->SourceProcessId;
                key.TargetProcessId = pairCtx->TargetProcessId;
                if (CoRemoveHashMapEntry(&Manager->PairMap, &key, sizeof(key))) {
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
    LRU 淘汰已废弃，淘汰由 PairManager_CleanupExpired 按 LastSeen 摘除。

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
    ULONG attempts = 3;
    AE_PROCESS_PAIR_KEY key;
    PIOA_PROCESS_PAIR_MANAGER mgr = WkdIoaEngine.PairManager;
    PAE_PROCESS_PAIR pair = NULL;
    NTSTATUS status;

    if (!mgr || !mgr->Initialized ||
        !SourceWkdProcess || !TargetWkdProcess || !Pair) {
        return STATUS_INVALID_PARAMETER;
    }
    *Pair = NULL;

Retry:
    if (0 == attempts--) return STATUS_UNSUCCESSFUL;

    /* ---- 快路径 (Lookup 成功时 *Pair 已填写, 借出回调 pin) ---- */
    status = AeLookupProcessPair(SourceWkdProcess->ProcessId,
                                 TargetWkdProcess->ProcessId, &pair);
    if (NT_SUCCESS(status)) return STATUS_SUCCESS;

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
    pair->SrcNode = SourceWkdProcess;
    pair->TgtNode = TargetWkdProcess;
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
    AcquireSRWLockExclusive(&SourceWkdProcess->PairLinksLock);
    InsertTailList(&SourceWkdProcess->OutPairListHead, &pair->SourceProcessLinks);
    InterlockedIncrement(&SourceWkdProcess->OutPairCount);
    PsReferenceWkdProcess(SourceWkdProcess);
    ReleaseSRWLockExclusive(&SourceWkdProcess->PairLinksLock);

    AcquireSRWLockExclusive(&TargetWkdProcess->PairLinksLock);
    InsertTailList(&TargetWkdProcess->InPairListHead, &pair->TargetProcessLinks);
    InterlockedIncrement(&TargetWkdProcess->InPairCount);
    PsReferenceWkdProcess(TargetWkdProcess);
    ReleaseSRWLockExclusive(&TargetWkdProcess->PairLinksLock);

    {
        LARGE_INTEGER now;
        GetSystemTimeAsFileTime((LPFILETIME)&now);
        pair->FirstSeen    = now;
        pair->LastSeen     = now;
        pair->CreationTime = now;
    }

    /* 插入 HashMap; COLLISION 不可能 (上方 double-check 已排除),
     * QUOTA 表示配额耗尽 → 释放本地副本返回 NULL */
    key.SourceProcessId = SourceWkdProcess->ProcessId;
    key.TargetProcessId = TargetWkdProcess->ProcessId;
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
    } else {
        /* 并发赢家已插入 → 本地副本未入表: 归还创建临时引用,
         * 归零即经统一销毁入口 (AepDestroyProcessPair) 完成摘链 +
         * 节点引用归还 + 半成品回收; 随后重查复用赢家副本 pin */
        AeDereferenceProcessPair(pair);

        if (status == STATUS_OBJECT_NAME_COLLISION) {
            goto Retry;
        } else return status;
    }

    *Pair = pair;
    return STATUS_SUCCESS;
}

BOOLEAN
IoaPairResolveNodeIds(
    _In_      PAE_PROCESS_PAIR PairCtx,
    _Out_opt_ GUID*                     SrcNodeId,
    _Out_opt_ GUID*                     TgtNodeId
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

    if (!PairCtx) {
        if (SrcNodeId) RtlZeroMemory(SrcNodeId, sizeof(GUID));
        if (TgtNodeId) RtlZeroMemory(TgtNodeId, sizeof(GUID));
        return FALSE;
    }

    sourceWkdProcess = NULL;
    NTSTATUS _status = PsLookupWkdProcessByStrictProcessId(&WkdProcessTree,
                                    ULongToHandle(PairCtx->SourceProcessId), NULL, &sourceWkdProcess);
    if (!NT_SUCCESS(_status)) { sourceWkdProcess = NULL; }

    targetWkdProcess = NULL;
    _status = PsLookupWkdProcessByStrictProcessId(&WkdProcessTree,
                                    ULongToHandle(PairCtx->TargetProcessId), NULL, &targetWkdProcess);
    if (!NT_SUCCESS(_status)) { targetWkdProcess = NULL; }

    if (SrcNodeId) {
        if (sourceWkdProcess && !sourceWkdProcess->SecCtx.Placeholder) {
            *SrcNodeId = sourceWkdProcess->NodeId;
        } else {
            RtlZeroMemory(SrcNodeId, sizeof(GUID));
            ok = FALSE;
        }
    }
    if (TgtNodeId) {
        if (targetWkdProcess && !targetWkdProcess->SecCtx.Placeholder) {
            *TgtNodeId = targetWkdProcess->NodeId;
        } else {
            RtlZeroMemory(TgtNodeId, sizeof(GUID));
            ok = FALSE;
        }
    }

    /* 归还两端查找 pin (仅读 NodeId, 不跨函数持有) */
    if (targetWkdProcess) PsDereferenceWkdProcess(targetWkdProcess);
    if (sourceWkdProcess) PsDereferenceWkdProcess(sourceWkdProcess);
    return ok;
}

VOID
PairContext_AttachEdge(
    _Inout_ PAE_PROCESS_PAIR PairCtx,
    _Inout_ PIOA_AGGREGATE_EDGE       Entry
    )
/*++
Routine Description:
    将边聚合条目挂载到进程对上下文的 EdgeListHead。
    数据层位图由 T1Evaluate 阶段1 无条件写入,
    此处不再重复操作。
    链头锁原则 (2026-08-25): 查重遍历 + 插入统一持
    PairCtx->EdgeListLock 独占。
--*/
{
    if (!PairCtx || !Entry) return;

    /* 更新进程对上下文元数据 */
    InterlockedIncrement64(&PairCtx->TotalEventCount);
    InterlockedIncrement64(&PairCtx->ActiveEventCount);

    AcquireSRWLockExclusive(&PairCtx->EdgeListLock);

    /* 检查是否已挂载（遍历链表） */
    {
        PLIST_ENTRY e = PairCtx->EdgeListHead.Flink;
        while (e != &PairCtx->EdgeListHead) {
            PIOA_AGGREGATE_EDGE ea = CONTAINING_RECORD(e,
                IOA_AGGREGATE_EDGE, PairLink);
            if (ea == Entry) {
                ReleaseSRWLockExclusive(&PairCtx->EdgeListLock);
                return;  /* 已挂载 */
            }
            e = e->Flink;
        }
    }

    /* 挂载 (数据层位图由 T1Evaluate 负责);
     * 写入 OwnerPair 反向指针, 供聚合边 TTL 清扫时双向摘链 */
    InsertTailList(&PairCtx->EdgeListHead, &Entry->PairLink);
    Entry->OwnerPair = PairCtx;

    ReleaseSRWLockExclusive(&PairCtx->EdgeListLock);
}

VOID
PairContext_RefreshScore(
    _Inout_ PAE_PROCESS_PAIR PairCtx,
    _In_opt_ PWKD_PROCESS        SrcNode
    )
/*++
Routine Description:
    遍历 EdgeListHead，对所有 ActiveCount>0 的边类型:
      score += PairGetEdgeTypeWeight(type) × (100 + min(log2(ActiveCount),7) × 14) / 100

    汇总 <spn, tpn> 级别的 TotalEventCount 和 ActiveEventCount:
      - TotalEventCount  = Σ OccurrenceCount (历史累计)
      - ActiveEventCount = Σ ActiveCount      (活跃窗口内)

    评分已迁移至 IoaScorer, 特征由 IoaCollectFeatures 采集。
    此函数仅负责统计计数更新, 不再涉及评分计算。
    链头锁原则 (2026-08-25): 遍历统一持 PairCtx->EdgeListLock 共享。
--*/
{
    ULONG score = 0;
    LONG64 totalEvents = 0;
    LONG64 activeEvents = 0;
    PLIST_ENTRY entry;

    if (!PairCtx) return;

    AcquireSRWLockShared(&PairCtx->EdgeListLock);

    entry = PairCtx->EdgeListHead.Flink;
    while (entry != &PairCtx->EdgeListHead) {
        PIOA_AGGREGATE_EDGE ea = CONTAINING_RECORD(entry,
            IOA_AGGREGATE_EDGE, PairLink);

        totalEvents += ea->OccurrenceCount;
        activeEvents += ea->ActiveCount;

        if (ea->ActiveCount > 0) {
            ULONG weight = PairGetEdgeTypeWeight(ea->EdgeType);
            ULONG log2 = min(IntegerLog2(ea->ActiveCount), LOG2_SAT_CEILING);
            ULONG sat100 = 100 + log2 * LOG2_SAT_STEP_PCT;

            score += weight * sat100 / 100;
        }

        entry = entry->Flink;
    }

    ReleaseSRWLockShared(&PairCtx->EdgeListLock);

    /* 写回 <spn, tpn> 级总计数 */
    PairCtx->TotalEventCount = totalEvents;
    PairCtx->ActiveEventCount = activeEvents;

    /* 评分不再由 PairContext_RefreshScore 负责, 已迁移至 IoaScorer */
}

/* PairContext_RefreshProcessCache 已移除。
 * 进程级特征缓存已迁移至 T1_PAIR_FEATURE, 由 IoaCollectFeatures 填充。
 * 评分由 IoaScorer 统一计算, 不再需要 PairContext 级别的评分缓存。 */

/* TTL 清扫回调上下文（阶段1 收集候选） */
typedef struct _PAIR_EXPIRE_CTX {
    LONGLONG                    NowMs;
    ULONG                       TtlMs;
    PAE_PROCESS_PAIR*  Victims;    /* 候选指针数组 */
    ULONG                       Capacity;
    ULONG                       Count;
} PAIR_EXPIRE_CTX, *PPAIR_EXPIRE_CTX;

static BOOLEAN
PairExpireCallback(
    _In_     PVOID Key,
    _In_     ULONG KeySize,
    _In_     PVOID Value,
    _Inout_  PVOID Context
    )
/*++
Routine Description:
    CoHashMapEnumerate 回调（表共享锁内）：TTL 过期判定，
    过期候选指针收进数组。仅读操作，不做任何修改。

Return Value:
    恒 TRUE（继续枚举）。
--*/
{
    PPAIR_EXPIRE_CTX ctx = (PPAIR_EXPIRE_CTX)Context;
    PAE_PROCESS_PAIR pairCtx = (PAE_PROCESS_PAIR)Value;
    LONGLONG age = ctx->NowMs - (pairCtx->LastSeen.QuadPart / 10000);

    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(KeySize);

    if (age > (LONGLONG)ctx->TtlMs && pairCtx->RefCount <= 1 &&
        ctx->Count < ctx->Capacity) {
        ctx->Victims[ctx->Count++] = pairCtx;
    }
    return TRUE;
}

VOID
PairManager_CleanupExpired(
    _In_ PIOA_PROCESS_PAIR_MANAGER Manager
    )
/*++
Routine Description:
    后台清理：移除超过 PAIR_TTL_MS 无活动的进程对。
    销毁动作 (双向关联摘除/节点引用归还/FsmTracker/序列状态/
    三上下文/本体) 统一由引用归零回调 AepDestroyProcessPair 完成。
    注意：不删除关联的 EdgeAggregate 条目（由 EdgeAggTable_CleanupExpired 负责）。

    HashMap 化两阶段清扫（2026-08-23）:
      阶段1 — CoHashMapEnumerate 共享锁内收集过期候选；
      阶段2 — 逐候选 CoRemoveHashMapEntry 摘除（内部独占锁裁决），
              移除成功者已脱离索引，归清扫线程独占可安全释放。
    已知边界（与旧实现等价）: 事件线程持裸指针更新 LastSeen 与
    清扫摘除间存在理论窗口（RefCount 无法感知裸指针借用），
    实际由流水线串行性缓解，最坏情况延至下轮清扫兜底。
--*/
{
    PAIR_EXPIRE_CTX ctx;
    LARGE_INTEGER now;
    PAE_PROCESS_PAIR* victims;
    ULONG capacity;
    ULONG i;
    ULONG cleaned = 0;

    if (!Manager || !Manager->Initialized) return;

    capacity = InterlockedCompareExchange(&Manager->ActivePairs, 0, 0);
    if (capacity == 0) return;

    victims = UtHeapAlloc(capacity * sizeof(PAE_PROCESS_PAIR));
    if (!victims) return;

    /* ── 阶段1: 枚举收集过期候选 ── */
    GetSystemTimeAsFileTime((LPFILETIME)&now);
    ctx.NowMs   = now.QuadPart / 10000;
    ctx.TtlMs   = Manager->PairTtlMs;
    ctx.Victims = victims;
    ctx.Capacity = capacity;
    ctx.Count   = 0;
    CoHashMapEnumerate(&Manager->PairMap, PairExpireCallback, &ctx);

    if (ctx.Count == 0) {
        UtHeapFree(victims);
        return;
    }

    /* ── 阶段2: 逐候选摘除 (销毁由引用归零自动完成) ──
     * 引用契约 (2026-08-25 统一销毁): 枚举收集为共享锁内纯指针拷贝
     * (不 pin), 对象存活由表引用兜底。摘除经 CoRemoveHashMapEntry:
     *   ShouldRemove 独占锁内裁决 (RefCount<=1, 无外部 pin 借出)
     *   → Deref 回调扣减表引用 → RefCount 归零
     *   → AeDereferenceProcessPair 就地调用统一销毁入口
     *     AepDestroyProcessPair (节点摘链/引用归还/FsmTracker/
     *     序列状态/三上下文/本体, 全套完成)。
     * 清扫线程此后不得再触碰对象本体; 枚举借用从未 +1,
     * 此处严禁再 Dereference (下溢风险)。 */
    for (i = 0; i < ctx.Count; i++) {
        PAE_PROCESS_PAIR pairCtx = ctx.Victims[i];
        AE_PROCESS_PAIR_KEY key;

        /* 快速预检: 复活或被 pin 则跳过 (ShouldRemove 锁内再裁决) */
        {
            LONGLONG age = ctx.NowMs - (pairCtx->LastSeen.QuadPart / 10000);
            if (age <= (LONGLONG)Manager->PairTtlMs || pairCtx->RefCount > 1) {
                continue;
            }
        }

        key.SourceProcessId = pairCtx->SourceProcessId;
        key.TargetProcessId = pairCtx->TargetProcessId;
        if (!CoRemoveHashMapEntry(&Manager->PairMap, &key, sizeof(key))) {
            continue;   /* 已被并发移除/裁决取消 */
        }

        InterlockedDecrement(&Manager->ActivePairs);
        cleaned++;
    }
    UtHeapFree(victims);

    if (cleaned > 0) {
        printf("[PairManager] Cleanup: %lu expired pairs removed\n", cleaned);
    }
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
