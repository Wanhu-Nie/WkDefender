/**************************************************/
/*  WkDefender — TrustedPID 引擎实现                */
/*                                                   */
/*  按 wkd 架构重写自 SS ProcessExclusion.c（对齐     */
/*  SS 行号: OnProcessCreate L766 / OnProcessTerminate*/
/*  L927 / IsProcessTrusted L1002 / AddTrustedProcess */
/*  L1193 / PepCheckParentExclusion L1903）           */
/*                                                   */
/*  双位图方案（wkd 裁剪）:                           */
/*    TrustedBitmap — 全部可信 PID（排除命中+手动）   */
/*    InheritBitmap — 可继承信任 PID（仅排除命中）    */
/*    InheritDepthMap— 低 PID 继承深度表（修复深度    */
/*                     限制失效缺陷）                 */
/*  低 PID(0-65535) 位图无锁原子读写；高 PID 走       */
/*  256 桶哈希集（push lock 保护）。                  */
/*  进程创建命中路径/进程名/父继承排除 → 置位。        */
/*                                                   */
/*  职责：只做 PID 信任逻辑（播种/继承/热查询/终止）， */
/*  不维护规则表（规则表在 ExemptsManager）。          */
/*  状态与 rundown 归 EXEMPT_ENGINE（门面集中持有）。*/
/**************************************************/

#include "ExemptsInternal.h"
#include "../Utils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CopInitializeExemptPid)
#endif

/**************************************************/
/*                  内部常量                        */
/**************************************************/

#define EXEMPT_PID_POOL_TAG             EXEMPT_POOL_TAG_PROCESS   /* 'rExW' 进程引擎（ExemptsInternal.h） */

/**************************************************/
/*                  内部辅助函数                    */
/**************************************************/

_IRQL_requires_max_(DISPATCH_LEVEL)
static FORCEINLINE ULONG
ExemptPidBitmapIndex(
    _In_ HANDLE ProcessId
    )
{
    return (ULONG)((ULONG_PTR)ProcessId / 32);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static FORCEINLINE ULONG
ExemptPidBitmapBit(
    _In_ HANDLE ProcessId
    )
{
    return (ULONG)((ULONG_PTR)ProcessId % 32);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static FORCEINLINE BOOLEAN
ExemptPidBitmapTest(
    _In_ PULONG Bitmap,
    _In_ HANDLE ProcessId
    )
{
    return (InterlockedOr((volatile LONG*)&Bitmap[ExemptPidBitmapIndex(ProcessId)], 0)
            & (1L << ExemptPidBitmapBit(ProcessId))) != 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static FORCEINLINE VOID
ExemptPidBitmapSet(
    _In_ PULONG Bitmap,
    _In_ HANDLE ProcessId
    )
{
    InterlockedOr((volatile LONG*)&Bitmap[ExemptPidBitmapIndex(ProcessId)],
                  1L << ExemptPidBitmapBit(ProcessId));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static FORCEINLINE VOID
ExemptPidBitmapClear(
    _In_ PULONG Bitmap,
    _In_ HANDLE ProcessId
    )
{
    InterlockedAnd((volatile LONG*)&Bitmap[ExemptPidBitmapIndex(ProcessId)],
                   ~(1L << ExemptPidBitmapBit(ProcessId)));
}

_IRQL_requires_max_(APC_LEVEL)
static FORCEINLINE ULONG
ExemptPidHashBucket(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;
    return (ULONG)((pid ^ (pid >> 16)) % EXEMPT_PID_HASH_BUCKETS);
}

/*
 * 高 PID 哈希集查找（数据按值返回，锁内拷贝防悬垂）。
 */
_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN
ExemptPidFindInHash(
    _In_ PEXEMPT_PID_CONTEXT Ctx,
    _In_ HANDLE ProcessId,
    _Out_opt_ PEXEMPT_REASON Reason,
    _Out_opt_ PBOOLEAN InheritToChildren,
    _Out_opt_ PBOOLEAN Permanent,
    _Out_opt_ PUINT8 Depth
    )
{
    ULONG bucket = ExemptPidHashBucket(ProcessId);
    PLIST_ENTRY entry;
    PEXEMPT_PID_ENTRY pidEntry;
    BOOLEAN found = FALSE;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Ctx->HashLock);

    for (entry = Ctx->HashBuckets[bucket].ListHead.Flink;
         entry != &Ctx->HashBuckets[bucket].ListHead;
         entry = entry->Flink) {

        pidEntry = CONTAINING_RECORD(entry, EXEMPT_PID_ENTRY, ListEntry);

        if (pidEntry->ProcessId == ProcessId) {
            found = TRUE;

            if (Reason != NULL) {
                *Reason = pidEntry->Reason;
            }
            if (InheritToChildren != NULL) {
                *InheritToChildren = pidEntry->InheritToChildren;
            }
            if (Permanent != NULL) {
                *Permanent = pidEntry->Permanent;
            }
            if (Depth != NULL) {
                *Depth = pidEntry->InheritanceDepth;
            }
            break;
        }
    }

    ExReleasePushLockShared(&Ctx->HashLock);
    KeLeaveCriticalRegion();

    return found;
}

/*
 * 高 PID 哈希集插入（排他锁下重复检测 + 插入）。
 */
_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS
ExemptPidAddToHash(
    _In_ PEXEMPT_PID_CONTEXT Ctx,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _In_ EXEMPT_REASON Reason,
    _In_ BOOLEAN InheritToChildren,
    _In_ UINT8 InheritanceDepth,
    _In_ BOOLEAN Permanent
    )
{
    PEXEMPT_PID_ENTRY entry;
    PLIST_ENTRY listEntry;
    PEXEMPT_PID_ENTRY existingEntry;
    ULONG bucket;

    bucket = ExemptPidHashBucket(ProcessId);

    entry = (PEXEMPT_PID_ENTRY)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(EXEMPT_PID_ENTRY),
        EXEMPT_PID_POOL_TAG);

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->ProcessId = ProcessId;
    entry->ParentProcessId = ParentProcessId;
    entry->Reason = Reason;
    entry->InheritToChildren = InheritToChildren;
    entry->InheritanceDepth = InheritanceDepth;
    entry->Permanent = Permanent;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Ctx->HashLock);

    for (listEntry = Ctx->HashBuckets[bucket].ListHead.Flink;
         listEntry != &Ctx->HashBuckets[bucket].ListHead;
         listEntry = listEntry->Flink) {

        existingEntry = CONTAINING_RECORD(listEntry, EXEMPT_PID_ENTRY, ListEntry);

        if (existingEntry->ProcessId == ProcessId) {
            ExReleasePushLockExclusive(&Ctx->HashLock);
            KeLeaveCriticalRegion();
            ExFreePoolWithTag(entry, EXEMPT_PID_POOL_TAG);
            return STATUS_OBJECT_NAME_COLLISION;
        }
    }

    InsertHeadList(&Ctx->HashBuckets[bucket].ListHead, &entry->ListEntry);
    InterlockedIncrement(&Ctx->HashBuckets[bucket].EntryCount);
    InterlockedIncrement(&Ctx->ActiveRecords);

    ExReleasePushLockExclusive(&Ctx->HashLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/*
 * 高 PID 哈希集移除。
 */
_IRQL_requires_max_(APC_LEVEL)
static VOID
ExemptPidRemoveFromHash(
    _In_ PEXEMPT_PID_CONTEXT Ctx,
    _In_ HANDLE ProcessId
    )
{
    ULONG bucket = ExemptPidHashBucket(ProcessId);
    PLIST_ENTRY entry;
    PEXEMPT_PID_ENTRY pidEntry;
    PEXEMPT_PID_ENTRY toRemove = NULL;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Ctx->HashLock);

    for (entry = Ctx->HashBuckets[bucket].ListHead.Flink;
         entry != &Ctx->HashBuckets[bucket].ListHead;
         entry = entry->Flink) {

        pidEntry = CONTAINING_RECORD(entry, EXEMPT_PID_ENTRY, ListEntry);

        if (pidEntry->ProcessId == ProcessId) {
            toRemove = pidEntry;
            RemoveEntryList(&pidEntry->ListEntry);
            InterlockedDecrement(&Ctx->HashBuckets[bucket].EntryCount);
            InterlockedDecrement(&Ctx->ActiveRecords);
            break;
        }
    }

    ExReleasePushLockExclusive(&Ctx->HashLock);
    KeLeaveCriticalRegion();

    if (toRemove != NULL) {
        ExFreePoolWithTag(toRemove, EXEMPT_PID_POOL_TAG);
    }
}

/*
 * 判断父进程是否可继承信任（父在可继承集且深度未超限）。
 * 命中时输出子进程继承深度 = 父深度 + 1。
 */
_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN
CopCheckParentInheritedPidExempt(
    _In_ PEXEMPT_PID_CONTEXT Ctx,
    _In_ HANDLE ParentProcessId,
    _Out_ PEXEMPT_REASON Reason,
    _Out_ PULONG ChildDepth
    )
{
    ULONG ppid;

    if (!Ctx || !ParentProcessId || !Reason || !ChildDepth) {
        return FALSE;
    }
    *Reason = ExemptReason_None;
    *ChildDepth = 1;

    ppid = HandleToULong(ParentProcessId);
    if (ppid < EXEMPT_PID_BITMAP_LIMIT) {
        if (ExemptPidBitmapTest(Ctx->InheritBitmap, ParentProcessId)) {
            UINT8 parentDepth = (Ctx->InheritDepthMap != NULL)
                ? Ctx->InheritDepthMap[ppid] : 0;

            if (parentDepth < EXEMPT_MAX_INHERIT_DEPTH) {
                *Reason = ExemptReason_TrustedParent;
                *ChildDepth = parentDepth + 1;
                return TRUE;
            }
        }
        return FALSE;
    }

    {
        EXEMPT_REASON hashReason = ExemptReason_None;
        BOOLEAN hashInherit = FALSE;
        UINT8 hashDepth = 0;

        if (ExemptPidFindInHash(Ctx, ParentProcessId, &hashReason, &hashInherit,
                                NULL, &hashDepth)) {
            if (hashInherit && hashDepth < EXEMPT_MAX_INHERIT_DEPTH) {
                *Reason = ExemptReason_TrustedParent;
                *ChildDepth = hashDepth + 1;
                return TRUE;
            }
        }
    }

    return FALSE;
}

/*
 * 将 PID 置为可信（低 PID 位图 / 高 PID 哈希集），记录继承深度。
 */
_IRQL_requires_max_(APC_LEVEL)
static VOID
CopTrustExemptedPid(
    _In_ PEXEMPT_PID_CONTEXT Ctx,
    _In_ HANDLE ProcessId,
    _In_opt_ HANDLE ParentProcessId,
    _In_ EXEMPT_REASON Reason,
    _In_ BOOLEAN InheritToChildren,
    _In_ ULONG Depth
    )
{
    ULONG ppid;

    if (!Ctx || !ProcessId || 
        Reason == ExemptReason_None || Depth == 0) {
        return;
    }

    ppid = HandleToULong(ParentProcessId);
    if (ppid != 0 && ppid < EXEMPT_PID_BITMAP_LIMIT) {
        if (!ExemptPidBitmapTest(Ctx->TrustedBitmap, ProcessId)) {
            InterlockedIncrement(&Ctx->ActiveRecords);
        }
        ExemptPidBitmapSet(Ctx->TrustedBitmap, ProcessId);

        if (InheritToChildren) {
            ExemptPidBitmapSet(Ctx->InheritBitmap, ProcessId);
            Ctx->InheritDepthMap[ppid] = Depth;
        }
    } else {
        /* 未提供ParentProcessId或超限 */
        ExemptPidAddToHash(Ctx, ProcessId, ParentProcessId, Reason,
                           InheritToChildren, Depth, FALSE);
    }
}

/**************************************************/
/*                  生命周期                        */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
CopInitializeExemptPid(
    _Inout_ PEXEMPT_ENGINE Engine
    )
/*++
Routine Description:
    初始化 TrustedPID 引擎：分配双位图 + 继承深度表，初始化哈希桶与锁。
    状态机归 EXEMPT_ENGINE（由门面管理，调用时处于 INITIALIZING）。

Arguments:
    Engine - 子系统全局结构体（PID 上下文位于 Engine->PidContext）。

Return Value:
    STATUS_SUCCESS / 分配失败状态。
--*/
{
    PEXEMPT_PID_CONTEXT ctx = &Engine->PidContext;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    ctx->TrustedBitmap = (PULONG)ExAllocatePoolZero(
        NonPagedPoolNx,
        EXEMPT_PID_BITMAP_ULONGS * sizeof(ULONG),
        EXEMPT_PID_POOL_TAG);

    if (ctx->TrustedBitmap == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    ctx->InheritBitmap = (PULONG)ExAllocatePoolZero(
        NonPagedPoolNx,
        EXEMPT_PID_BITMAP_ULONGS * sizeof(ULONG),
        EXEMPT_PID_POOL_TAG);

    if (ctx->InheritBitmap == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    ctx->InheritDepthMap = (PUCHAR)ExAllocatePoolZero(
        NonPagedPoolNx,
        EXEMPT_PID_BITMAP_LIMIT * sizeof(UCHAR),
        EXEMPT_PID_POOL_TAG);

    if (ctx->InheritDepthMap == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    ExInitializePushLock(&ctx->HashLock);

    for (ULONG i = 0; i < EXEMPT_PID_HASH_BUCKETS; i++) {
        InitializeListHead(&ctx->HashBuckets[i].ListHead);
        ctx->HashBuckets[i].EntryCount = 0;
    }

    ctx->EnableInheritance = TRUE;

    return STATUS_SUCCESS;

Cleanup:
    if (ctx->InheritDepthMap != NULL) {
        ExFreePoolWithTag(ctx->InheritDepthMap, EXEMPT_PID_POOL_TAG);
        ctx->InheritDepthMap = NULL;
    }
    if (ctx->InheritBitmap != NULL) {
        ExFreePoolWithTag(ctx->InheritBitmap, EXEMPT_PID_POOL_TAG);
        ctx->InheritBitmap = NULL;
    }
    if (ctx->TrustedBitmap != NULL) {
        ExFreePoolWithTag(ctx->TrustedBitmap, EXEMPT_PID_POOL_TAG);
        ctx->TrustedBitmap = NULL;
    }

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptPidShutdown(
    _Inout_ PEXEMPT_ENGINE Engine
    )
/*++
Routine Description:
    关闭 TrustedPID 引擎：释放哈希条目、继承深度表与双位图。
    调用前门面已停清理线程并排空 rundown（无在途查询）。

Arguments:
    Engine - 子系统全局结构体。

Return Value:
    无。
--*/
{
    PEXEMPT_PID_CONTEXT ctx = &Engine->PidContext;
    PLIST_ENTRY entry;
    PEXEMPT_PID_ENTRY pidEntry;
    ULONG i;

    PAGED_CODE();

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&ctx->HashLock);

    for (i = 0; i < EXEMPT_PID_HASH_BUCKETS; i++) {
        while (!IsListEmpty(&ctx->HashBuckets[i].ListHead)) {
            entry = RemoveHeadList(&ctx->HashBuckets[i].ListHead);
            pidEntry = CONTAINING_RECORD(entry, EXEMPT_PID_ENTRY, ListEntry);
            ExFreePoolWithTag(pidEntry, EXEMPT_PID_POOL_TAG);
        }
        ctx->HashBuckets[i].EntryCount = 0;
    }

    ExReleasePushLockExclusive(&ctx->HashLock);
    KeLeaveCriticalRegion();

    if (ctx->InheritDepthMap != NULL) {
        ExFreePoolWithTag(ctx->InheritDepthMap, EXEMPT_PID_POOL_TAG);
        ctx->InheritDepthMap = NULL;
    }
    if (ctx->InheritBitmap != NULL) {
        ExFreePoolWithTag(ctx->InheritBitmap, EXEMPT_PID_POOL_TAG);
        ctx->InheritBitmap = NULL;
    }
    if (ctx->TrustedBitmap != NULL) {
        ExFreePoolWithTag(ctx->TrustedBitmap, EXEMPT_PID_POOL_TAG);
        ctx->TrustedBitmap = NULL;
    }

    InterlockedExchange(&ctx->ActiveRecords, 0);
}

/**************************************************/
/*                  进程生命周期                    */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
CopExemptCreatedProcessInternal(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _In_opt_ HANDLE ParentProcessId,
    _In_opt_ PCUNICODE_STRING ImagePath
    )
/*++
Routine Description:
    进程创建排除判定（三步）：路径排除 → 进程名排除 → 父继承。
    命中则置可信位图（可继承，记录继承深度）。

Arguments:
    Engine         - 子系统全局结构体。
    ProcessId      - 新进程 ID。
    ParentProcessId- 父进程 ID（可选）。
    ImagePath      - 镜像路径（可选），必须经过标准化为Dos风格且小写。

Return Value:
    TRUE 进程被排除（可信）。
--*/
{
    PEXEMPT_PID_CONTEXT ctx;
    BOOLEAN excluded = FALSE;
    EXEMPT_REASON reason = ExemptReason_None;
    ULONG inheritDepth = 1;

    if (!Engine || !ProcessId) {
        return STATUS_INVALID_PARAMETER;
    }
    ctx = &Engine->PidContext;

    /*
     * 步骤 1/2: 路径排除 → 进程名排除（从路径提取 basename）。
     */
    if (ImagePath && ImagePath->Buffer && ImagePath->Length > 0) {
        NTSTATUS status;
        UNICODE_STRING basename = { 0 };

        if (CopCheckPathExempted(Engine, ImagePath, NULL)) {
            excluded = TRUE;
            reason = ExemptReason_PathExclusion;
        }

        if (!excluded &&
            /* 提取basename，零拷贝 */
            NT_SUCCESS(CoGetBasenameFromPath(ImagePath, &basename))) {
            if (CopCheckProcessExemptedByIdOrName(Engine, ProcessId, &basename)) {
                excluded = TRUE;
                reason = ExemptReason_ProcessNameMatch;
            }
        }
    }

Skip:
    /*
     * 步骤 3: 父进程继承（父在可继承集且深度未超限）。
     */
    //if (!excluded && ctx->EnableInheritance) {
    //    ULONG childDepth = 1;

    //    if (CopCheckParentInheritedPidExempt(ctx, ParentProcessId, &reason, &childDepth)) {
    //        excluded = TRUE;
    //        inheritDepth = childDepth;
    //    }
    //}

    if (excluded) {
        CopTrustExemptedPid(ctx, ProcessId, ParentProcessId, reason, TRUE, inheritDepth);
    }

    return excluded;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptPidOnProcessTerminate(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    进程终止：从可信集移除（位图/哈希集 + 继承深度表）。

Arguments:
    Engine    - 子系统全局结构体。
    ProcessId - 终止进程 ID。

Return Value:
    无。
--*/
{
    PEXEMPT_PID_CONTEXT ctx = &Engine->PidContext;
    ULONG_PTR pidValue = (ULONG_PTR)ProcessId;

    PAGED_CODE();

    if (pidValue < EXEMPT_PID_BITMAP_LIMIT) {
        if (ExemptPidBitmapTest(ctx->TrustedBitmap, ProcessId)) {
            ExemptPidBitmapClear(ctx->TrustedBitmap, ProcessId);
            ExemptPidBitmapClear(ctx->InheritBitmap, ProcessId);
            if (ctx->InheritDepthMap != NULL) {
                ctx->InheritDepthMap[pidValue] = 0;
            }
            InterlockedDecrement(&ctx->ActiveRecords);
        }
    } else {
        ExemptPidRemoveFromHash(ctx, ProcessId);
    }
}

/**************************************************/
/*                  查询/播种 API                  */
/**************************************************/

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ExemptPidIsTrusted(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    热路径 O(1) 可信查询。低 PID 位图无锁原子读；高 PID 哈希集锁读。
    调用方（门面 ExemptsIsProcessTrusted）须已获取全局 rundown 保护。

Arguments:
    Engine    - 子系统全局结构体。
    ProcessId - 进程 ID。

Return Value:
    TRUE 进程可信（排除）。
--*/
{
    PEXEMPT_PID_CONTEXT ctx = &Engine->PidContext;
    ULONG_PTR pidValue = (ULONG_PTR)ProcessId;

    if (ProcessId == NULL) {
        return FALSE;
    }

    if (ctx->TrustedBitmap == NULL) {
        return FALSE;
    }

    if (pidValue < EXEMPT_PID_BITMAP_LIMIT) {
        return ExemptPidBitmapTest(ctx->TrustedBitmap, ProcessId);
    }

    return ExemptPidFindInHash(ctx, ProcessId, NULL, NULL, NULL, NULL);
}

_IRQL_requires_max_(APC_LEVEL)
VOID
ExemptPidMarkTrusted(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    手动置可信（门面 ExemptsAddPidExclusion 成功后的同步播种）。
    不参与继承（不置 InheritBitmap），深度为 0。

Arguments:
    Engine    - 子系统全局结构体。
    ProcessId - 进程 ID。

Return Value:
    无。
--*/
{
    PEXEMPT_PID_CONTEXT ctx = &Engine->PidContext;
    ULONG_PTR pidValue = (ULONG_PTR)ProcessId;

    if (pidValue < EXEMPT_PID_BITMAP_LIMIT) {
        if (!ExemptPidBitmapTest(ctx->TrustedBitmap, ProcessId)) {
            InterlockedIncrement(&ctx->ActiveRecords);
        }
        ExemptPidBitmapSet(ctx->TrustedBitmap, ProcessId);
        if (ctx->InheritDepthMap != NULL) {
            ctx->InheritDepthMap[pidValue] = 0;
        }
        /* 手动信任不参与继承，不置 InheritBitmap */
    } else {
        ExemptPidAddToHash(ctx, ProcessId, NULL, ExemptReason_ManualExclusion,
                           FALSE, 0, FALSE);
    }
}
