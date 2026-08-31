/**************************************************/
/*  WkDefender Driver — 进程对生命周期 + 同步位图表   */
/*                                                  */
/*  全局哈希表 WkdProcessPairMap（WKD_HASH_MAP，HashMap.c）    */
/*  以 <sPid,tPid> 为键，存储 PAE_PROCESS_PAIR。    */
/*  职责:                                            */
/*    进程对查找（CoLookupHashMapEntry）、创建（AeFindOrCreateProcessPair）、 */
/*    同步位图查询（PsPairNeedsSync）和更新           */
/* （PsUpdatePairBitmap）。                          */
/*                                                  */
/*  PublicBitmap 分离为独立全局变量 g_PairPublicBitmap。*/
/**************************************************/

#include "ProcessPairContext.h"
#include "../Common/Utils.h"
#include "../AnalysisEngine/IoaEngine.h"    /* AE_IOA_CONTEXT 完整定义 */
#include "../AnalysisEngine/IocEngine.h"    /* IocAllocateProcessPairContext / IocDestroyProcessPairContext */
#include "../ThreatScoring/ThreatScoring.h" /* TsAllocateProcessPairContext / TsDestroyProcessPairContext */

/**************************************************/
/*               公共位图默认值                     */
/*  执行权转移类 (CreateRemoteThread/APC/          */
/*  MapView/ResumeThread) + 进程/线程创建          */
/*  硬编码置 1，其余为 0                            */
/**************************************************/

#define WKD_PAIR_PUBLIC_BITMAP_DEFAULT      \
    ((1ULL << WkdOp_OpenProcess)        |   \
     (1ULL << WkdOp_ReadVirtualMemory)  |   \
     (1ULL << WkdOp_CreateRemoteThread) |   \
     (1ULL << WkdOp_QueueApcThread)     |   \
     (1ULL << WkdOp_MapViewOfSection)   |   \
     (1ULL << WkdOp_ResumeThread)       |   \
     (1ULL << WkdOp_CreateProcess)      |   \
     (1ULL << WkdOp_CreateThread))

/* 全局 pair 数量上限（2026-07 迁移：替代已失效的按进程上限） */
#define AE_MAX_PROCESS_PAIRS         65536

volatile LONG WkdPairCount = 0;

WKD_HASH_MAP WkdProcessPairMap = { 0 };
ULONG64 g_PairPublicBitmap = WKD_PAIR_PUBLIC_BITMAP_DEFAULT;

//
// ShouldRemove 回调 — 仅在 ActiveBehaviors == 0 时允许摘除
//
static
BOOLEAN
IoapShouldRemoveProcessPair(
    _In_ const PAE_PROCESS_PAIR Pair
    )
{
    /* 当前只有hashmap和调用者持有ref时才能删除，否则拒绝 */
    return (InterlockedCompareExchange(&Pair->RefCount, 0, 0) == 1);
}

/**************************************************/
/*               初始化                             */
/**************************************************/

_Use_decl_annotations_
VOID
WkdPairTableInitialize(
    VOID
    )
/*++
Routine Description:
    初始化进程对 hash 表（WKD_HASH_MAP）。
    g_PairPublicBitmap 初始值: 执行权转移 + 进程/线程创建置 1。
--*/
{
    CoInitializeHashMap(&WkdProcessPairMap, 256, TRUE,
                        PsReferenceWkdProcessPair,
                        IoapShouldRemoveProcessPair,
                        PsDereferenceWkdProcessPair);
    g_PairPublicBitmap = WKD_PAIR_PUBLIC_BITMAP_DEFAULT;
}

//
// AeLookupProcessPair — CoLookupHashMapEntry 的简单封装，
// 返回 pair 指针（已 Reference，调用者需 PsDereferenceWkdProcessPair）。
//
_Use_decl_annotations_
PAE_PROCESS_PAIR
AeLookupProcessPair(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId
    )
{
    if (!SourceProcessId || !TargetProcessId) {
        return NULL;
    }

    AE_PROCESS_PAIR_KEY key = { SourceProcessId, TargetProcessId };
    return (PAE_PROCESS_PAIR)CoLookupHashMapEntry(
        &WkdProcessPairMap, &key, sizeof(key));
}

/**************************************************/
/*               查询是否需要同步                    */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
PsPairNeedsSync(
    _In_ HANDLE      SourceProcessId,
    _In_ HANDLE      TargetProcessId,
    _In_ WKD_OP_TYPE OpType
    )
/*++
Routine Description:
    查询 <SourceProcessId, TargetProcessId> 进程对上指定操作是否需要同步阻塞。
    WkdProcessPairMap 命中 → 查 pair->SyncBitmap[OpType]。
    未命中          → 查 g_PairPublicBitmap[OpType]。

    使用 CoLookupHashMapEntry 在桶共享锁下查找并 Reference，
    操作完成后再释放引用（PsDereferenceWkdProcessPair）。
    SyncBitmap 为 64 位原子读（InterlockedCompareExchange64），
    与 PsUpdatePairBitmap 的原子写（InterlockedExchange64）互不撕裂；
    pair 存活由引用计数保证（桶锁内 Reference pin）。

Arguments:
    SourceProcessId — 源进程 PID。
    TargetProcessId — 目标进程 PID。
    OpType          — 操作类型（WKD_OP_TYPE）。

Return Value:
    TRUE  — 需要同步阻塞。
    FALSE — 异步发送即可。
--*/
{
    PAE_PROCESS_PAIR pair;

    if (!SourceProcessId || !TargetProcessId || OpType >= WKD_OP_MAX) {
        return FALSE;
    }

    pair = AeLookupProcessPair(SourceProcessId, TargetProcessId);
    if (pair) {
        BOOLEAN result = ((ULONG64)InterlockedCompareExchange64(
            (volatile LONG64*)&pair->SyncBitmap, 0, 0) & (1ULL << OpType)) != 0;
        PsDereferenceWkdProcessPair(pair);
        return result;
    }

    /* 条目不存在 → 查公共位图 */
    return (g_PairPublicBitmap & (1ULL << OpType)) != 0;
}

/**************************************************/
/*               更新位图 (Agent 下发)               */
/**************************************************/

_Use_decl_annotations_
VOID
PsUpdatePairBitmap(
    _In_ HANDLE  SourceProcessId,
    _In_ HANDLE  TargetProcessId,
    _In_ ULONG64 NewBitmap
    )
/*++
Routine Description:
    Agent 通过 ALPC 下发位图更新。
    进程对必须已存在于 WkdProcessPairMap（由 IOA 引擎保证）。
    本函数只更新位图，不创建/删除条目。
    NewBitmap == 0 表示位图清零（所有操作异步）。

    使用 CoLookupHashMapEntry 在桶共享锁下查找并 Reference。
    SyncBitmap 写入用 InterlockedExchange64（原子，与热路径原子读
    InterlockedCompareExchange64 配对），配合引用计数与并发
    CoRemoveHashMapEntry 互斥。

Arguments:
    SourceProcessId — 源进程 PID。
    TargetProcessId — 目标进程 PID。
    NewBitmap       — 新的位图值（可以为 0）。
--*/
{
    PAE_PROCESS_PAIR pair;

    if (!SourceProcessId || !TargetProcessId) {
        return;
    }

    pair = AeLookupProcessPair(SourceProcessId, TargetProcessId);
    if (pair) {
        InterlockedExchange64(
            (volatile LONG64*)&pair->SyncBitmap, (LONG64)NewBitmap);
        PsDereferenceWkdProcessPair(pair);
    }
    /* 进程对不存在 → 忽略（IOA 引擎尚未创建或已销毁） */
}

/**************************************************/
/*           进程对查找 / 创建                       */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
AeFindOrCreateProcessPair(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _Out_ PAE_PROCESS_PAIR* Pair
    )
/*++

Routine Description:

    在 WkdProcessPairMap 中查找 <sid,tid> 进程对，未命中时创建新条目。
    采用双路径设计：
       快路径（热路径 ~95% 命中）：CoLookupHashMapEntry 桶共享锁查找。
       慢路径（首次 miss）: 无锁区预分配 → CoInsertHashMap（内置独占锁 double-check）。

    AE_PROCESS_PAIR_KEY 以 <sPid, tPid> 为键，HashMap 内部管理桶级锁。

    2026-07 迁移：创建时全部分配 IocContext/IoaContext/TsContext 三个
    上下文；不挂入任何进程侧链表（无挂链机制）；pair 只依赖 PID。

Arguments:

    SourceProcessId — 源进程 PID。
    TargetProcessId — 目标进程 PID。
    Pair            — 输出进程对指针（仅在 STATUS_SUCCESS 时有效）。

Return Value:

    STATUS_SUCCESS                — 找到或创建成功，Pair 输出有效指针。
    STATUS_QUOTA_EXCEEDED         — 超过全局 AE_MAX_PROCESS_PAIRS 上限。
    STATUS_INSUFFICIENT_RESOURCES — 内存分配失败。

--*/
{
    NTSTATUS status;
    LARGE_INTEGER time;
    PAE_PROCESS_PAIR pair;

    if (!SourceProcessId || !TargetProcessId || !Pair) {
        return STATUS_INVALID_PARAMETER;
    }
    *Pair = NULL;

    /* ===== 快路径：桶共享锁查找（热路径，大概率命中） ===== */
    pair = AeLookupProcessPair(SourceProcessId, TargetProcessId);
    if (pair) { *Pair = pair; return STATUS_SUCCESS; }

    /* ===== 慢路径：预分配 + CoInsertHashMap（内置 double-check） ===== */

    /* ---- 全局 pair 上限检查 ---- */
    if (InterlockedCompareExchange(&WkdPairCount, 0, 0) >= AE_MAX_PROCESS_PAIRS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    /* ---- (1) 无锁区：可失败操作（内存分配 + 三个上下文分配） ---- */
    {
        pair = ExAllocatePool2(POOL_FLAG_NON_PAGED,
            sizeof(AE_PROCESS_PAIR), 'prCt');
        if (!pair) return STATUS_NO_MEMORY;
        RtlZeroMemory(pair, sizeof(AE_PROCESS_PAIR));

        KeQuerySystemTime(&time);
        pair->RefCount = 1;     /* 返回给调用者 */
        pair->SourceProcessId = SourceProcessId;
        pair->TargetProcessId = TargetProcessId;
        pair->SyncBitmap = g_PairPublicBitmap;
        pair->CreateTime = time;
        pair->LastAccessTime = time;
        ExInitializePushLock(&pair->Lock);

        /* 需要支持惰性分配，因此上下文创建时需要原子更新 AE_PROCESS_PAIR */
        status = IocAllocateProcessPairContext(pair);
        if (!NT_SUCCESS(status)) goto Cleanup;
        status = IoaAllocateProcessPairContext(pair);
        if (!NT_SUCCESS(status)) goto Cleanup;
        status = TsAllocateProcessPairContext(NULL, pair);
        if (!NT_SUCCESS(status)) goto Cleanup;

        /* 行为上下文：RtlZeroMemory 已归零全部字段，乘数须显式置默认 100
         * （SS BepCalculateEventThreatScore：无调节时乘原分，0 会让结算归零） */
        pair->BehaviorContext.ScoreMultiplierPercent = 100;
    }

    /* ---- (2) 进程对安全属性继承 - (SourceProcess | TargetProcess) ---- */
    {
        PWKD_PROCESS sourceWkdProcess, targetWkdProcess;

        sourceWkdProcess = PsLookupWkdProcessByProcessId(SourceProcessId);
        // WkdProcess无效??? 发生严重错误!!!
        if (!sourceWkdProcess) { status = STATUS_UNSUCCESSFUL; goto Cleanup; }
        targetWkdProcess = PsLookupWkdProcessByProcessId(TargetProcessId);
        if (!targetWkdProcess) { status = STATUS_UNSUCCESSFUL; goto Cleanup; }

        if (sourceWkdProcess->SecurityContext) {
            pair->BehaviorContext.BehaviorFlags |=
                sourceWkdProcess->SecurityContext->BehaviorFlags;
        }
        if (targetWkdProcess->SecurityContext) {
            pair->BehaviorContext.BehaviorFlags |=
                targetWkdProcess->SecurityContext->BehaviorFlags;
        }

        PsDereferenceWkdProcess(sourceWkdProcess);
        PsDereferenceWkdProcess(targetWkdProcess);
    }

    /* ---- (3) CoInsertHashMap（内置桶独占锁 + double-check） ---- */
    {
        AE_PROCESS_PAIR_KEY insertKey = { SourceProcessId, TargetProcessId };
        ULONG attempts = 3;    /* 默认3次重试机会 */

Retry:
        if (0 == attempts--) {
            status = STATUS_UNSUCCESSFUL;
            goto Cleanup; /* 机会耗尽 */
        }

        status = CoInsertHashMap(&WkdProcessPairMap, &insertKey,
            sizeof(insertKey), (ULONG64)pair, NULL);

        if (NT_SUCCESS(status)) {
            /* 无冲突，插入成功 */
            InterlockedIncrement(&WkdPairCount);
            *Pair = pair;
            return STATUS_SUCCESS;
        } else if (status = STATUS_OBJECT_NAME_COLLISION) {
            /* double-check 命中：其他线程先插入了 → 回退 */
            PAE_PROCESS_PAIR existing =
                AeLookupProcessPair(SourceProcessId, TargetProcessId);
            if (existing) {
                *Pair = existing;
                status = STATUS_SUCCESS;
                goto Cleanup;
            }
        }

        /* 插入失败 */
        /* 极端情况：插入后又被删除，直接将当前局部Pair再进行提交（理论上不应发生）*/
        goto Retry;
    }

Cleanup:
    /* 无任何持有者，可无锁安全释放 */
    if (pair->IocContext) IocDestroyProcessPairContext(pair);
    if (pair->IoaContext) IoaDestroyProcessPairContext(pair);
    if (pair->TsContext) TsDestroyProcessPairContext(NULL, pair);
    if (pair) ExFreePoolWithTag(pair, 'prCt');
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
LONG
PsReferenceWkdProcessPair(
    _Inout_ PAE_PROCESS_PAIR Pair
    ) 
{
    if (!Pair) return MAXLONG;
    else return InterlockedIncrement(&Pair->RefCount);
}

//
// PsDereferenceWkdProcessPair — 进程对引用计数释放。
// refcount==0 时释放三个上下文（IocContext/IoaContext/TsContext）+ pair。
// 2026-07 迁移：pair 不做封存——driver 侧分析完毕，后续归 agent。
//
_Use_decl_annotations_
LONG
PsDereferenceWkdProcessPair(
    _Inout_ PAE_PROCESS_PAIR Pair
    )
{
    LONG ref;

    if (!Pair) return MAXLONG;
    ref = InterlockedDecrement(&Pair->RefCount);
    if (ref == 0) {
        /* ---- Pair无引用计数，可无锁安全释放 ---- */

        if (!IsListEmpty(&Pair->IoaContext->BehaviorHead) ||
            Pair->IoaContext->ActiveBehaviors != 0) {
            // 出现错误!!!
            DbgBreakPoint();
        }

        IocDestroyProcessPairContext(Pair);
        IoaDestroyProcessPairContext(Pair);
        TsDestroyProcessPairContext(NULL, Pair);

        ExFreePoolWithTag(Pair, 'prCt');
    }

    return ref;
}

_Use_decl_annotations_
LONG
PsReferenceWkdBehavior(
    _Inout_ PWKD_BEHAVIOR Behavior
    )
{
    if (!Behavior) return MAXLONG;
    else return InterlockedIncrement(&Behavior->RefCount);
}
//
// PsDereferenceWkdBehavior — 行为节点引用计数释放。
// 确保 Behavior 无锁访问。
//
_Use_decl_annotations_
LONG
PsDereferenceWkdBehavior(
    _Inout_ PWKD_BEHAVIOR Behavior
    )
{
    LONG ref;
    
    if (!Behavior) return MAXLONG;

    ref = InterlockedDecrement(&Behavior->RefCount);
    if (ref == 0) {
        DaDestroy(&Behavior->Records);
        ExFreePoolWithTag(Behavior, 'bhNd');
    }

    return ref;
}
