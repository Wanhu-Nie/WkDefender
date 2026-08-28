#include "SyscallContextCache.h"
#include "../Notification/MessageSync.h"   /* PWKD_SYNC_REQUEST */

/**************************************************/
/*                   全局状态                       */
/**************************************************/

/*
 * 全局链表头 — ETW 回调（Entry/Exit）与线程回调共享。
 * 通过 KSPIN_LOCK 保护。
 *
 * ETW Entry 侧尾插（CtxCacheInsertEx），
 * 线程回调 / ETW Exit 侧头取遍历（CtxCacheConsumeByTid）。
 * 遍历时遇到超时项顺手清理，匹配成功则取出参数并移除节点。
 */
static LIST_ENTRY  g_CacheListHead;
static KSPIN_LOCK  g_CacheListLock;
static BOOLEAN     g_CacheInitialized = FALSE;

/**************************************************/
/*                   内部辅助                       */
/**************************************************/

/*
 * 根据系统调用类型获取超时阈值
 */
static
LONGLONG
CtxCacheGetTimeout(
    _In_ WKD_SYSCALL_TYPE SyscallType
    )
{
    switch (SyscallType) {
    case WkdSyscall_NtCreateThreadEx:
        return CTX_CACHE_TIMEOUT_100NS;         /* 15秒 */
    default:
        return CTX_CACHE_EXIT_TIMEOUT_100NS;    /*  5秒 */
    }
}

/**************************************************/
/*                   接口实现                       */
/**************************************************/

VOID
CtxCacheInitialize(
    VOID
    )
{
    if (g_CacheInitialized) return;

    InitializeListHead(&g_CacheListHead);
    KeInitializeSpinLock(&g_CacheListLock);
    g_CacheInitialized = TRUE;
}

_Use_decl_annotations_
NTSTATUS
CtxCacheInsertEx(
    _In_ PWKD_SYSCALL_CONTEXT SyscallContext
    )
{
    PCTX_CACHE_ENTRY entry;

    if (!g_CacheInitialized || !SyscallContext) {
        return STATUS_INVALID_PARAMETER;
    }

    entry = (PCTX_CACHE_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(CTX_CACHE_ENTRY),
        'CtEx');
    if (!entry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /*
     * 从 SyscallContext 提取所有字段存入缓存条目。
     * SourceProcessId/TargetProcessId 已在 ShpEtwCallback 中通过
     * ObReferenceObjectByHandle 解析完成，直接复用。
     * SourceTid 为当前线程 ID（ETW Entry 回调上下文）。
     */
    entry->SyscallType  = SyscallContext->SyscallNumber;
    entry->SourceTid    = SyscallContext->SourceThreadId;
    entry->SourceProcessId    = SyscallContext->SourceProcessId;
    entry->TargetProcessId    = SyscallContext->TargetProcessId;

    RtlCopyMemory(
        &entry->Params,
        &SyscallContext->ParameterBlock,
        SyscallContext->ParameterNumber * sizeof(PVOID));

    KeQuerySystemTime(&entry->CaptureTime);

    ExInterlockedInsertTailList(
        &g_CacheListHead,
        &entry->Links,
        &g_CacheListLock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
PCTX_CACHE_ENTRY
CtxCacheConsumeByTid(
    _In_ HANDLE           SourceTid,
    _In_ WKD_SYSCALL_TYPE SyscallType
    )
{
    KIRQL oldIrql;
    LIST_ENTRY *entry;
    LARGE_INTEGER now;
    PCTX_CACHE_ENTRY result = NULL;

    if (!g_CacheInitialized) {
        return NULL;
    }

    KeQuerySystemTime(&now);

    KeAcquireSpinLock(&g_CacheListLock, &oldIrql);

    entry = g_CacheListHead.Flink;
    while (entry != &g_CacheListHead) {
        PCTX_CACHE_ENTRY ctx = CONTAINING_RECORD(entry, CTX_CACHE_ENTRY, Links);
        LIST_ENTRY *next = entry->Flink;

        /* 超时清理 */
        if (now.QuadPart - ctx->CaptureTime.QuadPart >
            CtxCacheGetTimeout(ctx->SyscallType)) {
            RemoveEntryList(entry);
            ExFreePool(ctx);
            entry = next;
            continue;
        }

        /*
         * 匹配条件：SourceTid（同一线程串行执行）+ SyscallType
         */
        if (ctx->SourceTid == SourceTid &&
            ctx->SyscallType == SyscallType) {

            /* 从链表移除但不释放，返回给调用者 */
            RemoveEntryList(entry);
            result = ctx;
            break;
        }

        entry = next;
    }

    KeReleaseSpinLock(&g_CacheListLock, oldIrql);
    return result;
}

_Use_decl_annotations_
VOID
CtxCachePurgeExpired(
    VOID
    )
{
    KIRQL oldIrql;
    LIST_ENTRY *entry;
    LARGE_INTEGER now;

    if (!g_CacheInitialized) {
        return;
    }

    KeQuerySystemTime(&now);

    KeAcquireSpinLock(&g_CacheListLock, &oldIrql);

    entry = g_CacheListHead.Flink;
    while (entry != &g_CacheListHead) {
        PCTX_CACHE_ENTRY ctx = CONTAINING_RECORD(entry, CTX_CACHE_ENTRY, Links);
        LIST_ENTRY *next = entry->Flink;

        if (now.QuadPart - ctx->CaptureTime.QuadPart >
            CtxCacheGetTimeout(ctx->SyscallType)) {
            RemoveEntryList(entry);
            ExFreePool(ctx);
        }

        entry = next;
    }

    KeReleaseSpinLock(&g_CacheListLock, oldIrql);
}

/**************************************************/
/*         Entry→跳板缓存：插入                     */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
CtxCacheInsertDeferSync(
    _In_ PWKD_SYSCALL_CONTEXT SyscallContext,
    _In_ PWKD_SYNC_REQUEST    Request
    )
/*++
Routine Description:
    在 ETW Entry 回调的同步路径中调用。
    将原始服务例程地址 + SyncRequest 存入缓存，
    供 ScTrampoline 跳板消费。

Arguments:
    SyscallContext — 系统调用上下文（含 RoutineAddress）。
    Request        — 已分配的同步请求节点。

Return Value:
    STATUS_SUCCESS / STATUS_INSUFFICIENT_RESOURCES
--*/
{
    PCTX_CACHE_ENTRY entry;

    if (!SyscallContext || !Request) {
        return STATUS_INVALID_PARAMETER;
    }

    entry = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(CTX_CACHE_ENTRY), 'DfSh');
    if (!entry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->SyscallType  = SyscallContext->SyscallNumber;
    entry->SourceTid    = SyscallContext->SourceThreadId;
    entry->SourceProcessId    = SyscallContext->SourceProcessId;
    entry->TargetProcessId    = SyscallContext->TargetProcessId;
    entry->DeferSync.RoutineAddr = SyscallContext->RoutineAddress;
    entry->DeferSync.SyncRequest = Request;
    KeQuerySystemTime(&entry->CaptureTime);

    ExInterlockedInsertTailList(&g_CacheListHead, &entry->Links, &g_CacheListLock);
    return STATUS_SUCCESS;
}

/**************************************************/
/*         Entry→跳板缓存：消费                     */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
CtxCacheConsumeDeferSync(
    _In_     HANDLE             ThreadId,
    _Outptr_ PVOID*             RoutineAddress,
    _Outptr_ PWKD_SYNC_REQUEST* SyncRequest
    )
/*++
Routine Description:
    在 ScTrampolineCallback 中调用。
    按 SourceTid 匹配缓存的 defer 条目，
    输出原始服务例程地址和 SyncRequest，内部释放条目。
    不检查超时（超时由 NtfSyncWait 自身处理）。

Arguments:
    ThreadId        — 当前线程 TID（匹配键）。
    RoutineAddress  — 输出原始系统调用例程地址。
    SyncRequest     — 输出同步请求指针。

Return Value:
    STATUS_SUCCESS / STATUS_NOT_FOUND
--*/
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (!ThreadId || !RoutineAddress || !SyncRequest) {
        return STATUS_INVALID_PARAMETER;
    }

    *RoutineAddress = NULL;
    *SyncRequest = NULL;

    KeAcquireSpinLock(&g_CacheListLock, &oldIrql);

    PLIST_ENTRY entry = g_CacheListHead.Flink;
    while (entry != &g_CacheListHead) {
        PCTX_CACHE_ENTRY ctx = CONTAINING_RECORD(entry, CTX_CACHE_ENTRY, Links);
        PLIST_ENTRY next = entry->Flink;

        if (ctx->SourceTid == ThreadId) {
            RemoveEntryList(entry);
            *RoutineAddress = ctx->DeferSync.RoutineAddr;
            *SyncRequest    = ctx->DeferSync.SyncRequest;
            status          = STATUS_SUCCESS;

            ExFreePool(ctx);
            break;
        }

        entry = next;
    }

    KeReleaseSpinLock(&g_CacheListLock, oldIrql);
    return status;
}
