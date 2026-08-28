#pragma once

#include <ntifs.h>

/**************************************************/
/*            优先级消息队列公共模块                */
/*                                                 */
/*  提供轻量级、线程安全的优先级消息队列，用于     */
/*  内核态组件间的异步通信。                       */
/*                                                 */
/*  设计要点：                                     */
/*  - 3 级优先级链表 (High/Normal/Low)             */
/*  - 严格优先级出队（始终优先取 High）            */
/*  - KSPIN_LOCK 保护，可在 DISPATCH_LEVEL 使用   */
/*  - 节点类型由调用方定义（仅操作 LIST_ENTRY）    */
/*                                                 */
/*  使用示例：                                     */
/*    typedef struct _MY_NODE {                    */
/*        LIST_ENTRY Links;                        */
/*        PVOID Data;                              */
/*    } MY_NODE;                                   */
/*                                                 */
/*    NtfInitializeMessageQueue(&Queue, 1024);                  */
/*    NtfMessageEnqueue(&Queue, WKD_QUEUE_PRIORITY_HIGH,   */
/*               &node->Links);                    */
/*    entry = NtfMessageDequeue(&Queue);                   */
/*    node = CONTAINING_RECORD(entry, MY_NODE, Links); */
/**************************************************/

//
// 优先级等级定义
//
#define WKD_QUEUE_PRIORITY_HIGH     0   // 高优先级（Critical + High 事件）
#define WKD_QUEUE_PRIORITY_NORMAL   1   // 普通优先级（Normal 事件）
#define WKD_QUEUE_PRIORITY_LOW      2   // 低优先级（日志、统计）
#define WKD_QUEUE_PRIORITY_LEVELS   3   // 总优先级等级数

//
// 消息队列结构
//
typedef struct _WKD_MESSAGE_QUEUE {
    LIST_ENTRY Heads[WKD_QUEUE_PRIORITY_LEVELS];    // 3 级优先级链表头
    KSPIN_LOCK Lock;                                // 自旋锁（保护链表操作）
    ULONG MaxCount;                                 // 最大节点数（0 = 无限制）

    volatile LONG64 TotalEnqueued;                  // 总入队数
    volatile LONG64 TotalDequeued;                  // 总出队数
    volatile LONG64 TotalDropped;                   // 总丢弃数
    volatile LONG64 CurrentCount;                   // 当前队列中节点数
} WKD_MESSAGE_QUEUE, *PWKD_MESSAGE_QUEUE;

//
// 初始化队列
//
// 设置 3 个链表头、自旋锁和最大容量限制。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NtfInitializeMessageQueue(
    _Out_ PWKD_MESSAGE_QUEUE Queue,
    _In_ ULONG MaxCount
    );

//
// 入队
//
// 按优先级将节点插入对应链表的尾部。
// 队列已满时返回 STATUS_BUFFER_TOO_SMALL 并丢弃。
//
_IRQL_requires_(DISPATCH_LEVEL)
NTSTATUS
NtfMessageEnqueue(
    _Inout_ PWKD_MESSAGE_QUEUE Queue,
    _In_ ULONG Priority,
    _In_ PLIST_ENTRY Entry
    );

//
// 出队（严格优先级）
//
// 按 High → Normal → Low 顺序检查，返回第一个非空链表的头部节点。
// 所有链表均为空时返回 NULL。
//
_IRQL_requires_(DISPATCH_LEVEL)
PLIST_ENTRY
NtfMessageDequeue(
    _Inout_ PWKD_MESSAGE_QUEUE Queue
    );

//
// 清空队列
//
// 移除并释放所有节点（通过回调函数释放节点内存）。
// 不释放节点本身——由调用方负责。
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MqFlush(
    _Inout_ PWKD_MESSAGE_QUEUE Queue
    );

//
// 获取队列统计信息
//
_IRQL_requires_(DISPATCH_LEVEL)
VOID
MqGetStatistics(
    _In_ PWKD_MESSAGE_QUEUE Queue,
    _Out_opt_ PLONG64 Enqueued,
    _Out_opt_ PLONG64 Dequeued,
    _Out_opt_ PLONG64 Dropped,
    _Out_opt_ PULONG CurrentCount
    );
