#pragma once

#include <ntifs.h>

/**************************************************/
/*       统一同步请求管理器 (Layer 0)               */
/*                                                  */
/*  纯同步原语，与 ALPC / 消息队列无关。              */
/*  所有需要"等待-唤醒"的场景共享此基础设施。         */
/*  使用预分配节点数组 + 链表管理，消除 ABA 问题。    */
/*                                                  */
/*  使用方:                                          */
/*    - ALPC Section 申请（共享节协商）               */
/*    - 同步阻塞查询（事件源 → Agent 决策）           */
/*    - Driver IOA 内部直决（零延迟）                 */
/*    - 未来其他同步场景                             */
/**************************************************/

#define WKD_SYNC_REQUEST_MAX        64

/**************************************************/
/*                   同步判决                        */
/**************************************************/

typedef enum _WKD_SYNC_VERDICT {
    WkdSyncVerdict_Allow   = 0,      /* 放行: 激活执行线程继续 */
    WkdSyncVerdict_Deny    = 1,      /* 拒绝: 激活执行线程返回失败 */
    WkdSyncVerdict_Forward = 2,      /* 转发: 执行线程拒绝, Agent 继续分析 */
} WKD_SYNC_VERDICT;

typedef struct _WKD_SYNC_REPLY_DATA {
    WKD_SYNC_VERDICT Verdict;
    ULONG            Reserved;
} WKD_SYNC_REPLY_DATA;

/**************************************************/
/*                   同步请求节点                    */
/**************************************************/

typedef struct _WKD_SYNC_REQUEST {
    LIST_ENTRY      Link;               /* FreeList 或 ActiveList 链接 */
    ULONG           RequestId;          /* 全局唯一（InterlockedIncrement） */
    KEVENT          Event;              /* SynchronizationEvent, auto-reset */
    PVOID           ReplyBuffer;        /* 等待线程注册的回复接收缓冲区 */
    SIZE_T          ReplyCapacity;
    volatile LONG   State;              /* 0=空闲, 1=等待, 2=已完成 */
} WKD_SYNC_REQUEST, *PWKD_SYNC_REQUEST;

/**************************************************/
/*                   同步请求管理器                  */
/**************************************************/

typedef struct _WKD_SYNC_REQUEST_MANAGER {
    LIST_ENTRY          ActiveList;         /* 活跃请求链表头（尾插） */
    LIST_ENTRY          FreeList;           /* 空闲节点链表头（头取） */
    WKD_SYNC_REQUEST    Requests[WKD_SYNC_REQUEST_MAX]; /* 预分配节点 */
    FAST_MUTEX          Lock;
    volatile LONG       NextRequestId;      /* 全局唯一自增 */
} WKD_SYNC_REQUEST_MANAGER, *PWKD_SYNC_REQUEST_MANAGER;

/**************************************************/
/*                   函数声明                       */
/**************************************************/

/*
 * WkdSyncInitialize
 *   初始化同步请求管理器。
 *   初始化所有 KEVENT，所有节点入 FreeList。
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdSyncInitialize(
    _Out_ PWKD_SYNC_REQUEST_MANAGER Mgr
    );

/*
 * NtfAcquireSyncRequest
 *   从 FreeList 取一个空闲节点，分配全局唯一 RequestId，
 *   状态置为等待，尾插入 ActiveList。
 *   失败（池满）返回 STATUS_INSUFFICIENT_RESOURCES。
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NtfAcquireSyncRequest(
    _Inout_ PWKD_SYNC_REQUEST_MANAGER   Mgr,
    _In_opt_ PVOID                      ReplyBuffer,
    _In_ SIZE_T                         ReplyCapacity,
    _Out_ PWKD_SYNC_REQUEST*            OutReq
    );

/*
 * NtfSyncWait
 *   等待指定请求完成。委托 KeWaitForSingleObject。
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NtfSyncWait(
    _In_ PWKD_SYNC_REQUEST_MANAGER  Mgr,
    _In_ PWKD_SYNC_REQUEST          Req,
    _In_opt_ PLARGE_INTEGER         Timeout
    );

/*
 * NtfSyncWriteReply
 *   根据 RequestId 遍历 ActiveList 查找匹配的等待节点。
 *   找到后拷贝数据到 ReplyBuffer 并触发事件。
 *   节点已超时释放（不在 ActiveList 中）则直接丢弃。
 *   可在 DISPATCH_LEVEL 调用。
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NtfSyncWriteReply(
    _In_ PWKD_SYNC_REQUEST_MANAGER  Mgr,
    _In_ ULONG                      RequestId,
    _In_ PVOID                      Data,
    _In_ SIZE_T                     DataSize
    );

/*
 * NtfReleaseSyncRequest
 *   将请求节点从 ActiveList 移除，清空状态后归还 FreeList。
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
NtfReleaseSyncRequest(
    _Inout_ PWKD_SYNC_REQUEST_MANAGER   Mgr,
    _In_ PWKD_SYNC_REQUEST              Req
    );

/*
 * WkdSyncCancelAll
 *   端口断开时调用。唤醒所有在 ActiveList 中等待的线程，
 *   并将节点归还 FreeList。确保无线程因端口断开而永久挂起。
 */
_IRQL_requires_(DISPATCH_LEVEL)
VOID
WkdSyncCancelAll(
    _Inout_ PWKD_SYNC_REQUEST_MANAGER Mgr
    );

/**************************************************/
/*               全局实例                           */
/**************************************************/

extern WKD_SYNC_REQUEST_MANAGER g_SyncMgr;
