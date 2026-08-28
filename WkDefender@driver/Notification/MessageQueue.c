#include "MessageQueue.h"

/**************************************************/
/*               初始化 / 清理                      */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
NtfInitializeMessageQueue(
    _Out_ PWKD_MESSAGE_QUEUE Queue,
    _In_ ULONG MaxCount
    )
{
    if (!Queue || !MaxCount) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Queue, sizeof(WKD_MESSAGE_QUEUE));

    for (ULONG i = 0; i < WKD_QUEUE_PRIORITY_LEVELS; i++) {
        InitializeListHead(&Queue->Heads[i]);
    }

    KeInitializeSpinLock(&Queue->Lock);
    Queue->MaxCount = MaxCount;

    return STATUS_SUCCESS;
}

/**************************************************/
/*                 入队操作                        */
/**************************************************/

_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
NtfMessageEnqueue(
    _Inout_ PWKD_MESSAGE_QUEUE Queue,
    _In_ ULONG Priority,
    _In_ PLIST_ENTRY Entry
    )
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;

    if (!Queue || !Entry) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 限定 Priority 范围 */
    if (Priority >= WKD_QUEUE_PRIORITY_LEVELS) {
        Priority = WKD_QUEUE_PRIORITY_LOW;
    }

    KeAcquireSpinLock(&Queue->Lock, &oldIrql);

    /* 检查队列是否已满 */
    if (Queue->MaxCount > 0 && Queue->CurrentCount >= Queue->MaxCount) {
        InterlockedIncrement64(&Queue->TotalDropped);
        status = STATUS_BUFFER_TOO_SMALL;
        KeReleaseSpinLock(&Queue->Lock, oldIrql);
        return status;
    }

    /* 插入对应优先级的链表尾部 */
    InsertTailList(&Queue->Heads[Priority], Entry);
    Queue->CurrentCount++;

    InterlockedIncrement64(&Queue->TotalEnqueued);
    InterlockedIncrement64(&Queue->CurrentCount);

    KeReleaseSpinLock(&Queue->Lock, oldIrql);

    return status;
}

/**************************************************/
/*                 出队操作                        */
/**************************************************/

_Use_decl_annotations_
PLIST_ENTRY
NtfMessageDequeue(
    _Inout_ PWKD_MESSAGE_QUEUE Queue
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry = NULL;

    if (!Queue) {
        return NULL;
    }

    KeAcquireSpinLock(&Queue->Lock, &oldIrql);

    if (Queue->CurrentCount == 0) {
        KeReleaseSpinLock(&Queue->Lock, oldIrql);
        return NULL;
    }

    /* 严格优先级：始终从最高优先级的非空链表取出 */
    for (ULONG i = 0; i < WKD_QUEUE_PRIORITY_LEVELS; i++) {
        if (!IsListEmpty(&Queue->Heads[i])) {
            entry = RemoveHeadList(&Queue->Heads[i]);
            InterlockedDecrement64(&Queue->CurrentCount);
            InterlockedIncrement64(&Queue->TotalDequeued);
            break;
        }
    }

    KeReleaseSpinLock(&Queue->Lock, oldIrql);
    return entry;
}

/**************************************************/
/*                 清空队列                        */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
VOID
MqFlush(
    _Inout_ PWKD_MESSAGE_QUEUE Queue
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    ULONG i;

    if (!Queue) {
        return;
    }

    KeAcquireSpinLock(&Queue->Lock, &oldIrql);

    for (i = 0; i < WKD_QUEUE_PRIORITY_LEVELS; i++) {
        while (!IsListEmpty(&Queue->Heads[i])) {
            entry = RemoveHeadList(&Queue->Heads[i]);
            /* 仅移除链表节点，不释放节点内存——
               由调用方负责其节点生命周期 */
            (VOID)entry;
        }
    }

    Queue->CurrentCount = 0;
    Queue->CurrentCount = 0;

    KeReleaseSpinLock(&Queue->Lock, oldIrql);
}

/**************************************************/
/*               获取统计信息                      */
/**************************************************/

_IRQL_requires_(DISPATCH_LEVEL)
VOID
MqGetStatistics(
    _In_ PWKD_MESSAGE_QUEUE Queue,
    _Out_opt_ PLONG64 Enqueued,
    _Out_opt_ PLONG64 Dequeued,
    _Out_opt_ PLONG64 Dropped,
    _Out_opt_ PULONG CurrentCount
    )
{
    if (!Queue) {
        return;
    }

    if (Enqueued) {
        *Enqueued = Queue->TotalEnqueued;
    }
    if (Dequeued) {
        *Dequeued = Queue->TotalDequeued;
    }
    if (Dropped) {
        *Dropped = Queue->TotalDropped;
    }
    if (CurrentCount) {
        *CurrentCount = Queue->CurrentCount;
    }
}
