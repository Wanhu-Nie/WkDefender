#pragma once

#include "WkDefenderHeader.h"

#define MSG_QUEUE_MAX_SIZE 1024

typedef enum _MESSAGE_TARGET {
    MSG_TARGET_PROCESS_MANAGER = 1,
    MSG_TARGET_NOTIFICATION_SERVICE = 2,
    MSG_TARGET_LOG_MANAGER = 3,
    MSG_TARGET_SCAN_MANAGER = 4,
    MSG_TARGET_SYSTEM_MANAGER = 5,
    MSG_TARGET_UNKNOWN = 99
} MESSAGE_TARGET;

typedef struct _MESSAGE_QUEUE_NODE {
    LIST_ENTRY ListEntry;
    MESSAGE_TARGET Target;
    ULONG MessageType;
    PVOID Data;
    ULONG DataSize;
    LARGE_INTEGER EnqueueTime;
} MESSAGE_QUEUE_NODE, *PMESSAGE_QUEUE_NODE;

#define MSG_QUEUE_MAX_TARGETS 6

// 消息处理回调函数类型
typedef PVOID (*MESSAGE_HANDLER)(PVOID Context, ULONG MessageType, PVOID Data);

typedef struct _MESSAGE_QUEUE {
    LIST_ENTRY QueueHeads[MSG_QUEUE_MAX_TARGETS];
    CRITICAL_SECTION Lock;
    HANDLE NotEmptyEvent;
    HANDLE StopEvent;
    HANDLE WorkerThread;
    BOOL Running;
    BOOL Processing;
    ULONG QueueSize;
    ULONG MaxQueueSize;
    ULONG NextQueueIndex;
    PVOID UserContext;
    MESSAGE_HANDLER MessageHandler; // 单个回调函数
} MESSAGE_QUEUE, *PMESSAGE_QUEUE;

NTSTATUS MsgQueue_Initialize(
    _Out_ PMESSAGE_QUEUE Queue,
    _In_ ULONG MaxSize,
    _In_opt_ MESSAGE_HANDLER MessageHandler,
    _In_opt_ PVOID UserContext
);

VOID MsgQueue_Cleanup(
    _In_ PMESSAGE_QUEUE Queue
);

NTSTATUS MsgQueue_Enqueue(
    _In_ PMESSAGE_QUEUE Queue,
    _In_ MESSAGE_TARGET Target,
    _In_ ULONG MessageType,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize
);

NTSTATUS MsgQueue_Dequeue(
    _In_ PMESSAGE_QUEUE Queue,
    _Out_ PMESSAGE_QUEUE_NODE* Message,
    _In_ ULONG TimeoutMs
);

VOID MsgQueue_FreeMessage(
    _In_ PMESSAGE_QUEUE_NODE Message
);

NTSTATUS MsgQueue_StartProcessing(
    _In_ PMESSAGE_QUEUE Queue
);

NTSTATUS MsgQueue_StopProcessing(
    _In_ PMESSAGE_QUEUE Queue
);

MESSAGE_TARGET MsgQueue_ResolveTarget(
    _In_ ULONG MessageType
);


MESSAGE_QUEUE g_MessageQueue;