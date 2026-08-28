/**************************************************/
/*  WkDefender Agent — 公共消息队列模板库            */
/*  功能：提供可复用的异步消息队列，供各组件独立使用  */
/*        - 事件激活避免 CPU 空耗                    */
/*        - 单生产者 (ALPC Worker) 多消费者           */
/*        - 每个模块创建自己的队列+消费线程            */
/*  作者: WkDefender Team                           */
/*  版本: 4.0.0                                     */
/**************************************************/

#pragma once

#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <stdio.h>
#include <ntstatus.h>

#include "../Common/Utils.h"

/**************************************************/
/*                   常量定义                       */
/**************************************************/

#define WKD_MSG_QUEUE_MAX_SIZE          1024
#define WKD_MSG_QUEUE_PRIORITY_LEVELS   3           /* 高、中、普通三级 */

/**************************************************/
/*               消息优先级                        */
/**************************************************/

typedef enum _WKD_MSG_PRIORITY {
    WkdMsgPriority_High     = 0,        /* 紧急：共享节请求、控制指令 */
    WkdMsgPriority_Medium   = 1,        /* 中度：进程事件、系统状态 */
    WkdMsgPriority_Normal   = 2,        /* 普通：日志、统计信息 */
    WkdMsgPriority_Count    = 3
} WKD_MSG_PRIORITY;

/**************************************************/
/*                   消息节点                       */
/**************************************************/

typedef struct _WKD_MSG_QUEUE_NODE {
    LIST_ENTRY                  ListEntry;
    ULONG                       MessageType;        /* 业务消息类型 */
    WKD_MSG_PRIORITY            Priority;           /* 消息优先级 */
    PVOID                       Data;               /* 堆副本 (消息处理完后需释放) */
    ULONG                       DataSize;
    LARGE_INTEGER               EnqueueTime;
} WKD_MSG_QUEUE_NODE, *PWKD_MSG_QUEUE_NODE;

/**************************************************/
/*               消息处理回调                       */
/**************************************************/

typedef PVOID (*WKD_MSG_HANDLER)(
    _In_ PVOID                  Context,
    _In_ ULONG                  MessageType,
    _In_ PVOID                  Data
    );

/**************************************************/
/*               消息队列结构体                     */
/**************************************************/

typedef struct _WKD_MSG_QUEUE {
    LIST_ENTRY                  QueueHeads[WKD_MSG_QUEUE_PRIORITY_LEVELS];  /* 每优先级独立链表 */
    CRITICAL_SECTION            Lock;
    HANDLE                      NotEmptyEvent;      /* 队列非空事件 */
    HANDLE                      StopEvent;          /* 停止信号 */
    HANDLE                      WorkerThread;       /* 消费线程句柄 */
    volatile BOOLEAN            Running;            /* 消费线程运行标志 */
    ULONG                       QueueSize;          /* 当前队列总长度 */
    ULONG                       MaxQueueSize;       /* 最大容量 */
    PVOID                       UserContext;        /* 透传给 Handler */
    WKD_MSG_HANDLER             MessageHandler;     /* 消息处理回调 */
    ULONG                       DroppedCount;       /* 溢出丢弃计数 */
} WKD_MSG_QUEUE, *PWKD_MSG_QUEUE;

/**************************************************/
/*                   函数声明                       */
/**************************************************/

NTSTATUS
NtfInitializeMessageQueueMessageQueue(
    _Out_ PWKD_MSG_QUEUE        Queue,
    _In_ ULONG                  MaxSize,
    _In_opt_ WKD_MSG_HANDLER    Handler,
    _In_opt_ PVOID              UserContext
    );

VOID
WkdMsgQueueCleanup(
    _In_ PWKD_MSG_QUEUE         Queue
    );

NTSTATUS
WkdMsgQueueEnqueue(
    _In_ PWKD_MSG_QUEUE         Queue,
    _In_ ULONG                  MessageType,
    _In_ WKD_MSG_PRIORITY       Priority,
    _In_opt_ PVOID              Data,
    _In_ ULONG                  DataSize
    );

/* 向后兼容：默认普通优先级入队 */
#define WkdMsgQueueEnqueueDefault(Queue, MsgType, Data, Size) \
    WkdMsgQueueEnqueue(Queue, MsgType, WkdMsgPriority_Normal, Data, Size)

NTSTATUS
WkdMsgQueueDequeue(
    _In_ PWKD_MSG_QUEUE         Queue,
    _Out_ PWKD_MSG_QUEUE_NODE*  Message,
    _In_ ULONG                  TimeoutMs
    );

VOID
WkdMsgQueueFreeMessage(
    _In_ PWKD_MSG_QUEUE_NODE    Message
    );

NTSTATUS
WkdMsgQueueStartProcessing(
    _In_ PWKD_MSG_QUEUE         Queue
    );

NTSTATUS
WkdMsgQueueStopProcessing(
    _In_ PWKD_MSG_QUEUE         Queue
    );
