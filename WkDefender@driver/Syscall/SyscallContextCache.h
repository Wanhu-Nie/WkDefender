#pragma once

/*
 * 注意：不直接包含 <wdm.h> 或 <ntifs.h>。
 * 依赖于编译单元通过预编译头 framework.h → ntifs.h → wdm.h 
 * 加载 WDK 类型（LIST_ENTRY、LARGE_INTEGER 等）。
 * SyscallMonitor.h 提供 WKD_SYSCALL_CONTEXT 以及
 * SyscallService.h（WKD_SYSCALL_TYPE）。
 */
#include "SyscallMonitor.h"
#include "../Notification/MessageSync.h"   /* PWKD_SYNC_REQUEST */

/**************************************************/
/*  ETW 回调 参数传递缓存                           */
/*                                                  */
/*  用途：ETW 回调（Entry/Exit）之间的参数传递。     */
/*                                                  */
/*  所有缓存条目统一按 (SourceTid, SyscallType)     */
/*  匹配消费，无类型区分。                           */
/*                                                  */
/*  注意：使用 WKD_SYSCALL_TYPE 标识缓存的系统调用   */
/*  类型（而非 WKD_MESSAGE_TYPE），因为缓存匹配维度  */
/*  是纯系统调用类型，不需要消息层的事件分类。        */
/*  因为 ETW 回调后不再解析 Pid，SrcPid/TgtPid 直接  */
/*  从 WKD_SYSCALL_CONTEXT 提取后存入。              */
/*                                                  */
/*  操作：尾插（ETW 侧）、头取遍历（消费侧）         */
/*  超时：15秒（NtCreateThreadEx）/ 5秒（其他）      */
/**************************************************/

/*
 * 单条缓存项
 *
 * 匹配键为 (SourceTid, SyscallType)：
 *   SourceTid  — 调用者线程 TID
 *   SyscallType — 系统调用类型（超时阈值也据此判断）
 */
typedef struct _CTX_CACHE_ENTRY {
    LIST_ENTRY      Links;
    WKD_SYSCALL_TYPE SyscallType;           /* 系统调用类型（匹配键 + 超时阈值） */
    HANDLE          SourceTid;              /* 调用者线程 TID — 匹配键 */
    HANDLE          SourceProcessId;              /* 源进程 PID（从 SyscallContext 提取） */
    HANDLE          TargetProcessId;              /* 目标进程 PID（从 SyscallContext 提取） */
    union {
        WKD_SYSCALL_PARAMETER_BLOCK Params; /* Entry→Exit：syscall 参数块 */
        struct {
            PVOID               RoutineAddr;    /* Entry→跳板：原始服务例程地址 */
            PWKD_SYNC_REQUEST   SyncRequest;    /* Entry→跳板：同步请求指针 */
        } DeferSync;
    };
    LARGE_INTEGER   CaptureTime;            /* ETW 捕获时间戳 */
} CTX_CACHE_ENTRY, *PCTX_CACHE_ENTRY;

/* 超时阈值（100ns 单位） */
#define CTX_CACHE_TIMEOUT_100NS         (15 * 1000 * 10000LL)   /* 15秒 — NtCreateThreadEx */
#define CTX_CACHE_EXIT_TIMEOUT_100NS    (5 * 1000 * 10000LL)    /*  5秒 — Exit 消费类 */

/**************************************************/
/*                   接口声明                      */
/**************************************************/

//
// 初始化全局链表
//
VOID
CtxCacheInitialize(
    VOID
    );

//
// 通用缓存插入
// 在 ETW Entry 回调中调用。
// 从 SyscallContext 提取 SourceProcessId、TargetProcessId、参数块等
// 全部存入缓存，避免消费侧重复解析。
//
NTSTATUS
CtxCacheInsertEx(
    _In_ PWKD_SYSCALL_CONTEXT SyscallContext
    );

//
// 按 SourceTid + SyscallType 匹配消费缓存项
// 匹配成功返回缓存的条目指针（调用者负责 ExFreePool），
// 失败返回 NULL。
// 遍历时顺手清理超时条目。
//
PCTX_CACHE_ENTRY
CtxCacheConsumeByTid(
    _In_ HANDLE           SourceTid,
    _In_ WKD_SYSCALL_TYPE SyscallType
    );

//
// Entry→跳板缓存插入
//   在 ETW Entry 回调的同步路径中调用。
//   存入原始服务例程地址 + SyncRequest，供 ScTrampoline 跳板消费。
//
NTSTATUS
CtxCacheInsertDeferSync(
    _In_ PWKD_SYSCALL_CONTEXT SyscallContext,
    _In_ PWKD_SYNC_REQUEST    Req
    );

//
// Entry→跳板缓存消费
//   在 ScTrampolineCallback 中调用，按 SourceTid 匹配。
//   匹配成功输出原始地址和 SyncRequest，内部释放条目。
//
NTSTATUS
CtxCacheConsumeDeferSync(
    _In_ HANDLE     SourceTid,
    _Out_ PVOID*    RoutineAddr,
    _Out_ PWKD_SYNC_REQUEST* SyncRequest
    );

//
// 清理所有超时条目（定时器或惰性清理）
//
VOID
CtxCachePurgeExpired(
    VOID
    );
