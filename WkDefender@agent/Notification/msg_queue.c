/**************************************************/
/*  WkDefender Agent — 公共消息队列模板库实现         */
/*  版本: 4.0.0                                     */
/**************************************************/

#include "msg_queue.h"

/**************************************************/
/*               内部辅助宏                         */
/**************************************************/

#ifndef STATUS_UNEXPECTED
#define STATUS_UNEXPECTED       ((NTSTATUS)0xC000000D)
#endif

#ifndef STATUS_ASSERTION_FAILURE
#define STATUS_ASSERTION_FAILURE ((NTSTATUS)0xC0000420L)
#endif

/**************************************************/
/*               用户模式链表操作                    */
/**************************************************/

#define WkdInitListHead(ListHead)       ((ListHead)->Flink = (ListHead)->Blink = (ListHead))
#define WkdIsListEmpty(ListHead)        ((ListHead)->Flink == (ListHead))

static void WkdInsertTailList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry)
{
    PLIST_ENTRY Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
}

static PLIST_ENTRY WkdRemoveHeadList(PLIST_ENTRY ListHead)
{
    PLIST_ENTRY Entry = ListHead->Flink;
    PLIST_ENTRY Next = Entry->Flink;
    ListHead->Flink = Next;
    Next->Blink = ListHead;
    Entry->Flink = Entry->Blink = NULL;
    return Entry;
}

static void WkdRemoveEntryList(PLIST_ENTRY Entry)
{
    PLIST_ENTRY Flink = Entry->Flink;
    PLIST_ENTRY Blink = Entry->Blink;
    if (Flink) Flink->Blink = Blink;
    if (Blink) Blink->Flink = Flink;
    Entry->Flink = Entry->Blink = NULL;
}

/**************************************************/
/*               内部函数声明                       */
/**************************************************/

static DWORD WINAPI WkdMsgQueueWorkerThread(LPVOID Param);

/**************************************************/
/*               获取系统时间                       */
/**************************************************/

static void WkdGetSystemTimeAsLargeInteger(PLARGE_INTEGER Time)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    Time->LowPart = ft.dwLowDateTime;
    Time->HighPart = ft.dwHighDateTime;
}

/* 从高到低查找第一个非空优先级的索引 */
static ULONG
WkdMsgQueueFindHighestPriority(
    _In_ PWKD_MSG_QUEUE Queue
    )
{
    for (ULONG i = 0; i < WKD_MSG_QUEUE_PRIORITY_LEVELS; i++) {
        if (!WkdIsListEmpty(&Queue->QueueHeads[i])) {
            return i;
        }
    }
    return WKD_MSG_QUEUE_PRIORITY_LEVELS; /* 全空 */
}

/**************************************************/
/*                   公开 API                       */
/**************************************************/

NTSTATUS
NtfInitializeMessageQueueMessageQueue(
    _Out_ PWKD_MSG_QUEUE    Queue,
    _In_ ULONG              MaxSize,
    _In_opt_ WKD_MSG_HANDLER Handler,
    _In_opt_ PVOID          UserContext
    )
/*++
Routine Description:
    初始化消息队列实例。

Arguments:
    Queue       — 未初始化的队列结构体。
    MaxSize     — 队列最大容量（0 = 使用默认值 1024）。
    Handler     — 消息处理回调（可为 NULL，稍后设置）。
    UserContext — 透传给 Handler 的上下文。

Return Value:
    NTSTATUS。
--*/
{
    if (!Queue) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Queue, sizeof(WKD_MSG_QUEUE));
    for (ULONG i = 0; i < WKD_MSG_QUEUE_PRIORITY_LEVELS; i++) {
        WkdInitListHead(&Queue->QueueHeads[i]);
    }

    if (!InitializeCriticalSectionAndSpinCount(&Queue->Lock, 0x00000400)) {
        return STATUS_UNSUCCESSFUL;
    }

    Queue->NotEmptyEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!Queue->NotEmptyEvent) {
        DeleteCriticalSection(&Queue->Lock);
        return STATUS_UNSUCCESSFUL;
    }

    Queue->StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!Queue->StopEvent) {
        CloseHandle(Queue->NotEmptyEvent);
        DeleteCriticalSection(&Queue->Lock);
        return STATUS_UNSUCCESSFUL;
    }

    Queue->MaxQueueSize = (MaxSize > 0) ? MaxSize : WKD_MSG_QUEUE_MAX_SIZE;
    Queue->MessageHandler = Handler;
    Queue->UserContext = UserContext;
    Queue->Running = FALSE;
    Queue->QueueSize = 0;
    Queue->DroppedCount = 0;

    return STATUS_SUCCESS;
}

VOID
WkdMsgQueueCleanup(
    _In_ PWKD_MSG_QUEUE Queue
    )
/*++
Routine Description:
    清理消息队列，释放所有待处理消息和同步对象。

Arguments:
    Queue — 消息队列实例。
--*/
{
    if (!Queue) {
        return;
    }

    if (Queue->Running) {
        WkdMsgQueueStopProcessing(Queue);
    }

    /* 释放队列中所有残留消息（遍历所有优先级） */
    for (ULONG i = 0; i < WKD_MSG_QUEUE_PRIORITY_LEVELS; i++) {
        while (!WkdIsListEmpty(&Queue->QueueHeads[i])) {
            PLIST_ENTRY entry = WkdRemoveHeadList(&Queue->QueueHeads[i]);
            PWKD_MSG_QUEUE_NODE node = CONTAINING_RECORD(entry, WKD_MSG_QUEUE_NODE, ListEntry);
            WkdMsgQueueFreeMessage(node);
        }
    }

    if (Queue->NotEmptyEvent) {
        CloseHandle(Queue->NotEmptyEvent);
        Queue->NotEmptyEvent = NULL;
    }

    if (Queue->StopEvent) {
        CloseHandle(Queue->StopEvent);
        Queue->StopEvent = NULL;
    }

    DeleteCriticalSection(&Queue->Lock);
}

NTSTATUS
WkdMsgQueueEnqueue(
    _In_ PWKD_MSG_QUEUE     Queue,
    _In_ ULONG              MessageType,
    _In_ WKD_MSG_PRIORITY   Priority,
    _In_opt_ PVOID          Data,
    _In_ ULONG              DataSize
    )
/*++
Routine Description:
    将消息入队。如果队列已满，从最低优先级丢弃最旧的消息。
    支持三级优先级：High > Medium > Normal，出队从高到低扫描。

Arguments:
    Queue       — 消息队列实例。
    MessageType — 业务消息类型标识。
    Priority    — 消息优先级（High/Medium/Normal）。
    Data        — 消息数据（深拷贝到堆内存）。
    DataSize    — 数据大小。

Return Value:
    NTSTATUS。
--*/
{
    PWKD_MSG_QUEUE_NODE node;

    if (!Queue || Priority >= WKD_MSG_QUEUE_PRIORITY_LEVELS) {
        return STATUS_INVALID_PARAMETER;
    }

    node = (PWKD_MSG_QUEUE_NODE)UtHeapAlloc(sizeof(WKD_MSG_QUEUE_NODE));
    if (!node) {
        return STATUS_NO_MEMORY;
    }

    node->MessageType = MessageType;
    node->Priority = Priority;
    node->DataSize = DataSize;

    if (Data && DataSize > 0) {
        node->Data = UtHeapAlloc(DataSize);
        if (!node->Data) {
            UtHeapFree(node);
            return STATUS_NO_MEMORY;
        }
        memcpy(node->Data, Data, DataSize);
    } else {
        node->Data = NULL;
    }

    WkdGetSystemTimeAsLargeInteger(&node->EnqueueTime);

    EnterCriticalSection(&Queue->Lock);

    /* 队列满：从最低优先级的队列头丢弃最旧的消息 */
    if (Queue->QueueSize >= Queue->MaxQueueSize) {
        for (LONG p = WKD_MSG_QUEUE_PRIORITY_LEVELS - 1; p >= 0; p--) {
            if (!WkdIsListEmpty(&Queue->QueueHeads[p])) {
                PLIST_ENTRY oldEntry = WkdRemoveHeadList(&Queue->QueueHeads[p]);
                PWKD_MSG_QUEUE_NODE oldNode = CONTAINING_RECORD(oldEntry, WKD_MSG_QUEUE_NODE, ListEntry);
                WkdMsgQueueFreeMessage(oldNode);
                Queue->QueueSize--;
                Queue->DroppedCount++;
                break;
            }
        }
    }

    /* 入队到对应优先级链表尾 */
    WkdInsertTailList(&Queue->QueueHeads[Priority], &node->ListEntry);
    Queue->QueueSize++;

    LeaveCriticalSection(&Queue->Lock);

    SetEvent(Queue->NotEmptyEvent);

    return STATUS_SUCCESS;
}

NTSTATUS
WkdMsgQueueDequeue(
    _In_ PWKD_MSG_QUEUE         Queue,
    _Out_ PWKD_MSG_QUEUE_NODE*  Message,
    _In_ ULONG                  TimeoutMs
    )
/*++
Routine Description:
    从队列中取出消息。如果队列为空则等待，直到超时或收到停止信号。

Arguments:
    Queue       — 消息队列实例。
    Message     — 出队的消息节点（由调用方负责释放）。
    TimeoutMs   — 最大等待时间（毫秒）。

Return Value:
    STATUS_SUCCESS / STATUS_TIMEOUT / STATUS_SHUTDOWN_IN_PROGRESS。
--*/
{
    HANDLE handles[2];
    DWORD waitResult;

    if (!Queue || !Message) {
        return STATUS_INVALID_PARAMETER;
    }

    handles[0] = Queue->NotEmptyEvent;
    handles[1] = Queue->StopEvent;

    EnterCriticalSection(&Queue->Lock);

    if (Queue->QueueSize == 0) {
        ResetEvent(Queue->NotEmptyEvent);
        LeaveCriticalSection(&Queue->Lock);

        waitResult = WaitForMultipleObjects(2, handles, FALSE, TimeoutMs);

        if (waitResult == WAIT_TIMEOUT) {
            return STATUS_TIMEOUT;
        }
        if (waitResult == WAIT_OBJECT_0 + 1) {
            return STATUS_SHUTDOWN_IN_PROGRESS;
        }
        if (waitResult != WAIT_OBJECT_0) {
            return STATUS_UNEXPECTED;
        }

        EnterCriticalSection(&Queue->Lock);
    }

    /* 从高优先级到低优先级扫描 */
    if (Queue->QueueSize > 0) {
        ULONG prioIdx = WkdMsgQueueFindHighestPriority(Queue);
        if (prioIdx < WKD_MSG_QUEUE_PRIORITY_LEVELS) {
            PLIST_ENTRY entry = WkdRemoveHeadList(&Queue->QueueHeads[prioIdx]);
            *Message = CONTAINING_RECORD(entry, WKD_MSG_QUEUE_NODE, ListEntry);
            Queue->QueueSize--;

            if (Queue->QueueSize == 0) {
                ResetEvent(Queue->NotEmptyEvent);
            }
            LeaveCriticalSection(&Queue->Lock);
            return STATUS_SUCCESS;
        }
    }

    LeaveCriticalSection(&Queue->Lock);
    return STATUS_TIMEOUT;
}

VOID
WkdMsgQueueFreeMessage(
    _In_ PWKD_MSG_QUEUE_NODE Message
    )
/*++
Routine Description:
    释放消息节点的堆内存（包括数据负载）。

Arguments:
    Message — 消息节点。
--*/
{
    if (!Message) {
        return;
    }

    if (Message->Data) {
        UtHeapFree(Message->Data);
        Message->Data = NULL;
    }

    UtHeapFree(Message);
}

NTSTATUS
WkdMsgQueueStartProcessing(
    _In_ PWKD_MSG_QUEUE Queue
    )
/*++
Routine Description:
    启动消息队列的消费线程。线程内部调用注册的 MessageHandler。

Arguments:
    Queue — 已初始化的消息队列。

Return Value:
    NTSTATUS。
--*/
{
    DWORD threadId;

    if (!Queue) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Queue->Running) {
        return STATUS_ALREADY_INITIALIZED;
    }

    Queue->Running = TRUE;

    Queue->WorkerThread = CreateThread(
        NULL,
        0,
        WkdMsgQueueWorkerThread,
        Queue,
        0,
        &threadId
    );

    if (!Queue->WorkerThread) {
        Queue->Running = FALSE;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
WkdMsgQueueStopProcessing(
    _In_ PWKD_MSG_QUEUE Queue
    )
/*++
Routine Description:
    停止消费线程。发送停止信号并等待线程退出。

Arguments:
    Queue — 运行中的消息队列。
--*/
{
    if (!Queue) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Queue->Running) {
        return STATUS_SUCCESS;
    }

    Queue->Running = FALSE;
    SetEvent(Queue->StopEvent);

    if (Queue->WorkerThread) {
        WaitForSingleObject(Queue->WorkerThread, 5000);
        CloseHandle(Queue->WorkerThread);
        Queue->WorkerThread = NULL;
    }

    ResetEvent(Queue->StopEvent);
    return STATUS_SUCCESS;
}

/**************************************************/
/*               消费线程                           */
/**************************************************/

static DWORD WINAPI
WkdMsgQueueWorkerThread(
    _In_ LPVOID Param
    )
/*++
Routine Description:
    消息队列消费线程。循环出队并调用注册的 Handler。

Arguments:
    Param — 指向 WKD_MSG_QUEUE 的指针。

Return Value:
    线程退出码。
--*/
{
    PWKD_MSG_QUEUE      queue;
    PWKD_MSG_QUEUE_NODE message;
    NTSTATUS            status;
    WKD_MSG_HANDLER     handler;
    PVOID               context;

    queue = (PWKD_MSG_QUEUE)Param;

    printf("[MsgQueue] Worker thread started (max=%lu)\n", queue->MaxQueueSize);

    while (queue->Running) {
        status = WkdMsgQueueDequeue(queue, &message, 100);

        if (status == STATUS_TIMEOUT) {
            continue;
        }

        if (status == STATUS_SHUTDOWN_IN_PROGRESS) {
            break;
        }

        if (!NT_SUCCESS(status)) {
            continue;
        }

        handler = queue->MessageHandler;
        context = queue->UserContext;

        if (handler) {
            handler(context, message->MessageType, message->Data);
        }

        WkdMsgQueueFreeMessage(message);
    }

    printf("[MsgQueue] Worker thread exited (dropped=%lu)\n", queue->DroppedCount);
    return 0;
}
