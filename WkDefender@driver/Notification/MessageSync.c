/**************************************************/
/*  WkDefender Driver — 统一同步请求管理器实现       */
/*  纯同步原语层，与 ALPC / 消息队列无关             */
/**************************************************/

#include "MessageSync.h"

WKD_SYNC_REQUEST_MANAGER g_SyncMgr = { 0 };

/**************************************************/
/*               初始化                             */
/**************************************************/

_Use_decl_annotations_
VOID
WkdSyncInitialize(
    _Out_ PWKD_SYNC_REQUEST_MANAGER Mgr
    )
/*++
Routine Description:
    初始化同步请求管理器。
    初始化所有 KEVENT，所有节点入 FreeList。

Arguments:
    Mgr — 未初始化的管理器指针。
--*/
{
    ULONG i;

    InitializeListHead(&Mgr->ActiveList);
    InitializeListHead(&Mgr->FreeList);
    ExInitializeFastMutex(&Mgr->Lock);
    Mgr->NextRequestId = 0;

    for (i = 0; i < WKD_SYNC_REQUEST_MAX; i++) {
        KeInitializeEvent(&Mgr->Requests[i].Event, SynchronizationEvent, FALSE);
        Mgr->Requests[i].State = 0;
        Mgr->Requests[i].RequestId = 0;
        Mgr->Requests[i].ReplyBuffer = NULL;
        Mgr->Requests[i].ReplyCapacity = 0;
        InsertTailList(&Mgr->FreeList, &Mgr->Requests[i].Link);
    }
}

/**************************************************/
/*               分配请求                           */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
NtfAcquireSyncRequest(
    _Inout_ PWKD_SYNC_REQUEST_MANAGER   Mgr,
    _In_opt_ PVOID                      ReplyBuffer,
    _In_ SIZE_T                         ReplyCapacity,
    _Out_ PWKD_SYNC_REQUEST*            OutReq
    )
/*++
Routine Description:
    从 FreeList 取一个空闲节点，分配全局唯一 RequestId，
    状态置为等待后插入 ActiveList。

Arguments:
    Mgr           — 管理器指针。
    ReplyBuffer   — 等待线程注册的回复数据接收缓冲区。
    ReplyCapacity — 缓冲区容量。
    OutReq        — 输出分配到的请求节点。

Return Value:
    NTSTATUS。
--*/
{
    PWKD_SYNC_REQUEST req;

    if (!Mgr || !OutReq) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&Mgr->Lock);

    if (IsListEmpty(&Mgr->FreeList)) {
        ExReleaseFastMutex(&Mgr->Lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    req = CONTAINING_RECORD(
        RemoveHeadList(&Mgr->FreeList),
        WKD_SYNC_REQUEST,
        Link
    );

    req->RequestId = (ULONG)InterlockedIncrement(&Mgr->NextRequestId);
    req->ReplyBuffer = ReplyBuffer;
    req->ReplyCapacity = ReplyCapacity;
    req->State = 1;
    KeClearEvent(&req->Event);

    InsertTailList(&Mgr->ActiveList, &req->Link);

    ExReleaseFastMutex(&Mgr->Lock);

    *OutReq = req;
    return STATUS_SUCCESS;
}

/**************************************************/
/*               等待请求                           */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
NtfSyncWait(
    _In_ PWKD_SYNC_REQUEST_MANAGER  Mgr,
    _In_ PWKD_SYNC_REQUEST          Req,
    _In_opt_ PLARGE_INTEGER         Timeout
    )
/*++
Routine Description:
    等待指定请求完成。委托 KeWaitForSingleObject。

Arguments:
    Mgr     — 管理器指针（不使用）。
    Req     — 要等待的请求节点。
    Timeout — 超时时间，NULL=无限等待。

Return Value:
    KeWaitForSingleObject 的返回值。
--*/
{
    UNREFERENCED_PARAMETER(Mgr);
    return KeWaitForSingleObject(
        &Req->Event,
        Executive,
        KernelMode,
        FALSE,
        Timeout
    );
}

/**************************************************/
/*               写入回复                           */
/**************************************************/

_Use_decl_annotations_
VOID
NtfSyncWriteReply(
    _In_ PWKD_SYNC_REQUEST_MANAGER  Mgr,
    _In_ ULONG                      RequestId,
    _In_ PVOID                      Data,
    _In_ SIZE_T                     DataSize
    )
/*++
Routine Description:
    根据 RequestId 遍历 ActiveList 查找匹配的等待节点。
    找到后拷贝数据到 ReplyBuffer 并触发事件。
    如果节点已被超时释放（不在 ActiveList 中），直接丢弃。
    可在 DISPATCH_LEVEL 调用。

Arguments:
    Mgr       — 管理器指针。
    RequestId — 要回复的请求 ID。
    Data      — 回复数据。
    DataSize  — 数据大小。
--*/
{
    PLIST_ENTRY entry;

    ExAcquireFastMutex(&Mgr->Lock);

    for (entry = Mgr->ActiveList.Flink;
         entry != &Mgr->ActiveList;
         entry = entry->Flink) {

        PWKD_SYNC_REQUEST req = CONTAINING_RECORD(entry, WKD_SYNC_REQUEST, Link);

        if (req->RequestId == RequestId && req->State == 1) {
            SIZE_T copySize = (DataSize < req->ReplyCapacity) ? DataSize : req->ReplyCapacity;
            if (req->ReplyBuffer && copySize > 0) {
                RtlCopyMemory(req->ReplyBuffer, Data, copySize);
            }
            req->State = 2;
            KeSetEvent(&req->Event, IO_NO_INCREMENT, FALSE);
            break;
        }
    }

    ExReleaseFastMutex(&Mgr->Lock);
}

/**************************************************/
/*               释放请求                           */
/**************************************************/

_Use_decl_annotations_
VOID
NtfReleaseSyncRequest(
    _Inout_ PWKD_SYNC_REQUEST_MANAGER   Mgr,
    _In_ PWKD_SYNC_REQUEST              Req
    )
/*++
Routine Description:
    将请求节点从 ActiveList 移除，清空状态后归还 FreeList。

Arguments:
    Mgr — 管理器指针。
    Req — 要释放的请求节点。
--*/
{
    ExAcquireFastMutex(&Mgr->Lock);

    RemoveEntryList(&Req->Link);
    Req->ReplyBuffer = NULL;
    Req->ReplyCapacity = 0;
    Req->State = 0;

    InsertTailList(&Mgr->FreeList, &Req->Link);

    ExReleaseFastMutex(&Mgr->Lock);
}

/**************************************************/
/*               全局唤醒                           */
/**************************************************/

_Use_decl_annotations_
VOID
WkdSyncCancelAll(
    _Inout_ PWKD_SYNC_REQUEST_MANAGER Mgr
    )
/*++
Routine Description:
    端口断开时调用。唤醒所有在 ActiveList 中等待的线程，
    并将节点归还 FreeList。确保没有线程因端口断开而永久挂起。

Arguments:
    Mgr — 管理器指针。
--*/
{
    ExAcquireFastMutex(&Mgr->Lock);

    while (!IsListEmpty(&Mgr->ActiveList)) {
        PLIST_ENTRY entry = RemoveHeadList(&Mgr->ActiveList);
        PWKD_SYNC_REQUEST req = CONTAINING_RECORD(entry, WKD_SYNC_REQUEST, Link);

        req->State = 0;
        req->ReplyBuffer = NULL;
        req->ReplyCapacity = 0;

        KeSetEvent(&req->Event, IO_NO_INCREMENT, FALSE);

        InsertTailList(&Mgr->FreeList, &req->Link);
    }

    ExReleaseFastMutex(&Mgr->Lock);
}
