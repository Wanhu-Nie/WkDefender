#include "msg_queue.h"
#include "alpc_server.h"

// 定义缺失的状态码
#ifndef STATUS_UNEXPECTED
#define STATUS_UNEXPECTED ((NTSTATUS)0xC000000D)
#endif

// 用户模式下的链表操作替代实现
#define InitializeListHead(ListHead) ((ListHead)->Flink = (ListHead)->Blink = (ListHead))

#define IsListEmpty(ListHead) ((ListHead)->Flink == (ListHead))

void InsertTailList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry)
{
    PLIST_ENTRY Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
}

PLIST_ENTRY RemoveHeadList(PLIST_ENTRY ListHead)
{
    PLIST_ENTRY Entry = ListHead->Flink;
    PLIST_ENTRY Next = Entry->Flink;
    ListHead->Flink = Next;
    Next->Blink = ListHead;
    Entry->Flink = Entry->Blink = NULL;
    return Entry;
}

void RemoveEntryList(PLIST_ENTRY Entry)
{
    PLIST_ENTRY Flink = Entry->Flink;
    PLIST_ENTRY Blink = Entry->Blink;
    Flink->Blink = Blink;
    Blink->Flink = Flink;
    Entry->Flink = Entry->Blink = NULL;
}

// 替代KeQuerySystemTimeAsFileTime
void GetSystemTimeAsLargeInteger(PLARGE_INTEGER Time)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    Time->LowPart = ft.dwLowDateTime;
    Time->HighPart = ft.dwHighDateTime;
}

MESSAGE_QUEUE g_MessageQueue;

static DWORD WINAPI MsgQueue_WorkerThread(LPVOID lpParam);

NTSTATUS MsgQueue_Initialize(
    _Out_ PMESSAGE_QUEUE Queue,
    _In_ ULONG MaxSize,
    _In_opt_ MESSAGE_HANDLER MessageHandler,
    _In_opt_ PVOID UserContext
)
{
    if (Queue == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // 初始化所有队列头
    for (int i = 0; i < MSG_QUEUE_MAX_TARGETS; i++) {
        InitializeListHead(&Queue->QueueHeads[i]);
    }

    if (!InitializeCriticalSectionAndSpinCount(&Queue->Lock, 0x00000400)) {
        return STATUS_UNSUCCESSFUL;
    }

    Queue->NotEmptyEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (Queue->NotEmptyEvent == NULL) {
        DeleteCriticalSection(&Queue->Lock);
        return STATUS_UNSUCCESSFUL;
    }

    Queue->StopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (Queue->StopEvent == NULL) {
        CloseHandle(Queue->NotEmptyEvent);
        DeleteCriticalSection(&Queue->Lock);
        return STATUS_UNSUCCESSFUL;
    }

    Queue->WorkerThread = NULL;
    Queue->Running = FALSE;
    Queue->Processing = FALSE;
    Queue->QueueSize = 0;
    Queue->MaxQueueSize = (MaxSize > 0) ? MaxSize : MSG_QUEUE_MAX_SIZE;
    Queue->NextQueueIndex = 0;
    Queue->UserContext = UserContext;
    Queue->MessageHandler = MessageHandler;

    return STATUS_SUCCESS;
}

VOID MsgQueue_Cleanup(
    _In_ PMESSAGE_QUEUE Queue
)
{
    if (Queue == NULL) {
        return;
    }

    if (Queue->Running) {
        MsgQueue_StopProcessing(Queue);
    }

    // 清理所有队列
    for (int i = 0; i < MSG_QUEUE_MAX_TARGETS; i++) {
        while (!IsListEmpty(&Queue->QueueHeads[i])) {
            PLIST_ENTRY entry = RemoveHeadList(&Queue->QueueHeads[i]);
            PMESSAGE_QUEUE_NODE node = CONTAINING_RECORD(entry, MESSAGE_QUEUE_NODE, ListEntry);
            MsgQueue_FreeMessage(node);
        }
    }

    if (Queue->NotEmptyEvent != NULL) {
        CloseHandle(Queue->NotEmptyEvent);
        Queue->NotEmptyEvent = NULL;
    }

    if (Queue->StopEvent != NULL) {
        CloseHandle(Queue->StopEvent);
        Queue->StopEvent = NULL;
    }

    DeleteCriticalSection(&Queue->Lock);
}

NTSTATUS MsgQueue_Enqueue(
    _In_ PMESSAGE_QUEUE Queue,
    _In_ MESSAGE_TARGET Target,
    _In_ ULONG MessageType,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize
)
{
    PMESSAGE_QUEUE_NODE node;
    ULONG queueIndex;

    if (Queue == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Queue->QueueSize >= Queue->MaxQueueSize) {
        printf("[MsgQueue] Queue is full, dropping message\n");
        return STATUS_UNSUCCESSFUL;
    }

    // 确定队列索引
    switch (Target) {
    case MSG_TARGET_PROCESS_MANAGER:
        queueIndex = 0;
        break;
    case MSG_TARGET_NOTIFICATION_SERVICE:
        queueIndex = 1;
        break;
    case MSG_TARGET_LOG_MANAGER:
        queueIndex = 2;
        break;
    case MSG_TARGET_SCAN_MANAGER:
        queueIndex = 3;
        break;
    default:
        queueIndex = 4; // MSG_TARGET_UNKNOWN
        break;
    }

    node = (PMESSAGE_QUEUE_NODE)malloc(sizeof(MESSAGE_QUEUE_NODE));
    if (node == NULL) {
        return STATUS_NO_MEMORY;
    }

    node->Target = Target;
    node->MessageType = MessageType;
    node->DataSize = DataSize;

    if (Data != NULL && DataSize > 0) {
        node->Data = malloc(DataSize);
        if (node->Data == NULL) {
            free(node);
            return STATUS_NO_MEMORY;
        }
        memcpy(node->Data, Data, DataSize);
    } else {
        node->Data = NULL;
        DataSize = 0;
    }

    GetSystemTimeAsLargeInteger((PLARGE_INTEGER)&node->EnqueueTime);

    EnterCriticalSection(&Queue->Lock);
    InsertTailList(&Queue->QueueHeads[queueIndex], &node->ListEntry);
    Queue->QueueSize++;
    LeaveCriticalSection(&Queue->Lock);

    SetEvent(Queue->NotEmptyEvent);

    return STATUS_SUCCESS;
}

NTSTATUS MsgQueue_Dequeue(
    _In_ PMESSAGE_QUEUE Queue,
    _Out_ PMESSAGE_QUEUE_NODE* Message,
    _In_ ULONG TimeoutMs
)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE handles[2];
    DWORD waitResult;
    ULONG startIndex, currentIndex, i;
    PLIST_ENTRY entry;
    PMESSAGE_QUEUE_NODE node;

    if (Queue == NULL || Message == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    handles[0] = Queue->NotEmptyEvent;
    handles[1] = Queue->StopEvent;

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

    // 检查所有队列是否为空
    BOOL allEmpty = TRUE;
    for (i = 0; i < MSG_QUEUE_MAX_TARGETS; i++) {
        if (!IsListEmpty(&Queue->QueueHeads[i])) {
            allEmpty = FALSE;
            break;
        }
    }

    if (allEmpty) {
        ResetEvent(Queue->NotEmptyEvent);
        LeaveCriticalSection(&Queue->Lock);
        return STATUS_TIMEOUT;
    }

    // 轮询队列，从NextQueueIndex开始
    startIndex = Queue->NextQueueIndex;
    currentIndex = startIndex;
    
    do {
        if (!IsListEmpty(&Queue->QueueHeads[currentIndex])) {
            entry = RemoveHeadList(&Queue->QueueHeads[currentIndex]);
            node = CONTAINING_RECORD(entry, MESSAGE_QUEUE_NODE, ListEntry);
            Queue->QueueSize--;
            
            // 更新下一次轮询的起始索引
            Queue->NextQueueIndex = (currentIndex + 1) % MSG_QUEUE_MAX_TARGETS;
            
            if (Queue->QueueSize == 0) {
                ResetEvent(Queue->NotEmptyEvent);
            }
            
            LeaveCriticalSection(&Queue->Lock);
            *Message = node;
            return status;
        }
        
        currentIndex = (currentIndex + 1) % MSG_QUEUE_MAX_TARGETS;
    } while (currentIndex != startIndex);

    // 理论上不会到达这里，因为前面已经检查过至少有一个队列不为空
    ResetEvent(Queue->NotEmptyEvent);
    LeaveCriticalSection(&Queue->Lock);
    return STATUS_TIMEOUT;
}

VOID MsgQueue_FreeMessage(
    _In_ PMESSAGE_QUEUE_NODE Message
)
{
    if (Message == NULL) {
        return;
    }

    if (Message->Data != NULL) {
        free(Message->Data);
        Message->Data = NULL;
    }

    free(Message);
}

typedef struct _MSG_QUEUE_PROCESS_CONTEXT {
    PVOID UserContext;
    PVOID (*HandlerFunc)(PVOID Context, MESSAGE_TARGET Target, ULONG MessageType, PVOID Data);
} MSG_QUEUE_PROCESS_CONTEXT, *PMSG_QUEUE_PROCESS_CONTEXT;

static DWORD WINAPI MsgQueue_WorkerThread(LPVOID lpParam)
{
    PMESSAGE_QUEUE queue = (PMESSAGE_QUEUE)lpParam;
    PMESSAGE_QUEUE_NODE message;
    NTSTATUS status;
    MESSAGE_HANDLER handler;

    printf("[MsgQueue] Worker thread started\n");

    while (queue->Running) {
        status = MsgQueue_Dequeue(queue, &message, 100);

        if (status == STATUS_TIMEOUT) {
            continue;
        }

        if (status == STATUS_SHUTDOWN_IN_PROGRESS) {
            break;
        }

        if (!NT_SUCCESS(status)) {
            continue;
        }

        printf("[MsgQueue] Processing message: Target=%d, Type=0x%X\n",
               message->Target, message->MessageType);

        // 使用单个回调函数处理消息
        if (queue->Processing && queue->MessageHandler != NULL) {
            queue->MessageHandler(queue->UserContext, message->MessageType, message->Data);
        }

        MsgQueue_FreeMessage(message);
    }

    printf("[MsgQueue] Worker thread exiting\n");
    return 0;
}

// 启动消息队列处理线程
NTSTATUS MsgQueue_StartProcessing(
    _In_ PMESSAGE_QUEUE Queue
)
{
    if (Queue == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Queue->Running) {
        return STATUS_ALREADY_INITIALIZED;
    }

    Queue->Running = TRUE;
    Queue->Processing = TRUE;

    DWORD threadId;
    Queue->WorkerThread = CreateThread(NULL, 0, MsgQueue_WorkerThread, Queue, 0, &threadId);

    if (Queue->WorkerThread == NULL) {
        Queue->Running = FALSE;
        Queue->Processing = FALSE;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS MsgQueue_StopProcessing(
    _In_ PMESSAGE_QUEUE Queue
)
{
    if (Queue == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Queue->Running) {
        return STATUS_SUCCESS;
    }

    Queue->Running = FALSE;
    SetEvent(Queue->StopEvent);

    if (Queue->WorkerThread != NULL) {
        WaitForSingleObject(Queue->WorkerThread, 5000);
        CloseHandle(Queue->WorkerThread);
        Queue->WorkerThread = NULL;
    }

    ResetEvent(Queue->StopEvent);
    return STATUS_SUCCESS;
}

MESSAGE_TARGET MsgQueue_ResolveTarget(
    _In_ ULONG MessageType
)
{
    // 系统状态相关消息
    if (MessageType == 0x1001) {  // WKDEFENDER_MSG_GET_SYSTEM_STATUS_REQUEST
        return MSG_TARGET_SYSTEM_MANAGER;
    }

    // 进程相关消息
    if (MessageType >= 0x1000 && MessageType < 0x2000) {
        return MSG_TARGET_PROCESS_MANAGER;
    }

    // 通知相关消息
    if (MessageType >= 0x2000 && MessageType < 0x3000) {
        return MSG_TARGET_NOTIFICATION_SERVICE;
    }

    // 驱动进程创建消息
    if (MessageType & WKDEFENDER_MSG_FROM_DRIVER) {
        return MSG_TARGET_PROCESS_MANAGER;
    }

    //// 日志相关消息
    //if (MessageType >= 0x3000 && MessageType < 0x4000) {
    //    return MSG_TARGET_LOG_MANAGER;
    //}

    //// 扫描相关消息
    //if (MessageType >= 0x4000 && MessageType < 0x5000) {
    //    return MSG_TARGET_SCAN_MANAGER;
    //}

    return MSG_TARGET_UNKNOWN;
}