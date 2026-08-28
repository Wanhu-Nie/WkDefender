/**************************************************/
/*  WkDefender — 异步持久化队列实现                  */
/**************************************************/

#include "IoaPersistQueue.h"
#include <process.h>

#define PERSIST_FLUSH_INTERVAL_MS   200     /* 批处理间隔 */

/**************************************************/
/*               后台工作线程                       */
/**************************************************/

static
unsigned int
__stdcall
IoapPersistQueueWorkerThread(
    _In_ PVOID Context
    )
/*++
Routine Description:
    持久化队列后台线程。
    循环等待 WakeEvent，取出队列中所有条目调用 serde 写入。
    Persist 是 IOA 管线必须调用环节，非可选项。
--*/
{
    PIOA_PERSIST_QUEUE queue = (PIOA_PERSIST_QUEUE)Context;
    PLIST_ENTRY entry;
    PIOA_RECORD_ENTRY persistEntry;
    ULONG batch;

    while (queue->Running) {
        /* 等待唤醒或超时 */
        WaitForSingleObject(queue->WakeEvent, INFINITE);

        if (!queue->Running) break;

        /* 批处理：取出所有待处理的条目 */
        batch = 0;
        EnterCriticalSection(&queue->Lock);

        while (!IsListEmpty(&queue->Head)) {
            entry = queue->Head.Flink;
            RemoveEntryList(entry);
            queue->Count--;

            LeaveCriticalSection(&queue->Lock);

            persistEntry = CONTAINING_RECORD(entry, IOA_RECORD_ENTRY, Link);

            /* 调用 serde 写入持久化层 */
            if (persistEntry->SerdeWrite) {
                NTSTATUS s = persistEntry->SerdeWrite(persistEntry->Data);
                if (NT_SUCCESS(s)) {
                    InterlockedIncrement64(&queue->TotalWritten);
                }
            }

            /* 释放条目内存 */
            if (persistEntry->Data) {
                UtHeapFree(persistEntry->Data);
            }
            UtHeapFree(persistEntry);

            batch++;
            EnterCriticalSection(&queue->Lock);
        }

        LeaveCriticalSection(&queue->Lock);
    }

    return 0;
}

/**************************************************/
/*                   公开 API                       */
/**************************************************/

NTSTATUS
PersistQueue_Initialize(
    PIOA_PERSIST_QUEUE* OutQueue,
    ULONG               MaxCapacity
    )
{
    PIOA_PERSIST_QUEUE q;

    q = UtHeapAlloc(sizeof(IOA_PERSIST_QUEUE));
    if (!q) return STATUS_NO_MEMORY;

    InitializeListHead(&q->Head);
    q->MaxCount = (MaxCapacity > 0) ? MaxCapacity : 4096;
    InitializeCriticalSection(&q->Lock);

    q->WakeEvent = CreateEventW(NULL, FALSE, FALSE, NULL);  /* 自动重置 */
    if (!q->WakeEvent) {
        DeleteCriticalSection(&q->Lock);
        UtHeapFree(q);
        return STATUS_UNSUCCESSFUL;
    }

    q->Running = TRUE;
    q->WorkerThread = (HANDLE)_beginthreadex(
        NULL, 0, IoapPersistQueueWorkerThread, q, 0, NULL);
    if (!q->WorkerThread) {
        q->Running = FALSE;
        CloseHandle(q->WakeEvent);
        DeleteCriticalSection(&q->Lock);
        UtHeapFree(q);
        return STATUS_UNSUCCESSFUL;
    }

    printf("[PersistQueue] Initialized: capacity=%lu\n", q->MaxCount);
    *OutQueue = q;
    return STATUS_SUCCESS;
}

VOID
PersistQueue_Cleanup(
    PIOA_PERSIST_QUEUE Queue
    )
{
    if (!Queue) return;

    printf("[PersistQueue] Cleanup: enq=%lld written=%lld dropped=%lld\n",
           Queue->TotalEnqueued, Queue->TotalWritten, Queue->TotalDropped);

    /* 通知线程退出 */
    Queue->Running = FALSE;
    SetEvent(Queue->WakeEvent);

    if (Queue->WorkerThread) {
        WaitForSingleObject(Queue->WorkerThread, 5000);
        CloseHandle(Queue->WorkerThread);
    }

    /* 释放剩余条目 */
    PersistQueue_Flush(Queue);

    if (Queue->WakeEvent) CloseHandle(Queue->WakeEvent);
    DeleteCriticalSection(&Queue->Lock);
    UtHeapFree(Queue);
}

VOID
IoaPersistQueueEnqueue(
    PIOA_PERSIST_QUEUE Queue,
    IOA_RECORD_ENTRY_TYPE Type,
    PVOID              Data,
    PERSIST_SERDE_WRITE_FN SerdeWrite,
    BOOLEAN            IsCritical
    )
/*++
Routine Description:
    非阻塞入队。数据以副本形式复制到堆。
    超限时：非关键条目丢弃，关键条目强制入队。

Arguments:
    Queue      — 队列实例。
    Type       — 条目类型。
    Data       — 数据指针。
    SerdeWrite — 写入 serde 函数。
    IsCritical — 是否不可丢弃。
--*/
{
    PIOA_RECORD_ENTRY entry;

    if (!Queue || !Data) return;

    /* 非关键 + 超限 → 丢弃 */
    if (!IsCritical && Queue->Count >= Queue->MaxCount) {
        InterlockedIncrement64(&Queue->TotalDropped);
        return;
    }

    entry = UtHeapAlloc(sizeof(IOA_RECORD_ENTRY));
    if (!entry) {
        InterlockedIncrement64(&Queue->TotalDropped);
        return;
    }

    entry->Type       = Type;
    entry->Data       = Data;       /* 调用者负责分配堆内存并转移所有权 */
    entry->SerdeWrite = SerdeWrite;
    entry->IsCritical = IsCritical;

    EnterCriticalSection(&Queue->Lock);
    InsertTailList(&Queue->Head, &entry->Link);
    Queue->Count++;
    LeaveCriticalSection(&Queue->Lock);

    InterlockedIncrement64(&Queue->TotalEnqueued);

    /* 唤醒后台线程 */
    SetEvent(Queue->WakeEvent);
}

VOID
PersistQueue_Flush(
    PIOA_PERSIST_QUEUE Queue
    )
/*++
Routine Description:
    同步刷新队列中剩余条目。
--*/
{
    PLIST_ENTRY entry;

    if (!Queue) return;

    EnterCriticalSection(&Queue->Lock);
    while (!IsListEmpty(&Queue->Head)) {
        entry = Queue->Head.Flink;
        RemoveEntryList(entry);
        Queue->Count--;

        LeaveCriticalSection(&Queue->Lock);

        PIOA_RECORD_ENTRY pe = CONTAINING_RECORD(entry, IOA_RECORD_ENTRY, Link);
        if (pe->SerdeWrite && pe->Data) {
            pe->SerdeWrite(pe->Data);
            InterlockedIncrement64(&Queue->TotalWritten);
        }
        if (pe->Data) UtHeapFree(pe->Data);
        UtHeapFree(pe);

        EnterCriticalSection(&Queue->Lock);
    }
    LeaveCriticalSection(&Queue->Lock);
}

