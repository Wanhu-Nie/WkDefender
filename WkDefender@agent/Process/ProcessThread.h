/**************************************************/
/*  WkDefender Agent — 进程域线程挂载              */
/*                                                  */
/*  2026-08-15 新增：WKD_THREAD 生命周期管理。       */
/*  数据源 = 编排链线程事件（IoaObserve 线程分支），  */
/*  线程挂载 WKD_PROCESS::ThreadContext。             */
/*  不分配 GUID（自然键 = ThreadId + 所属进程）。      */
/*  锁：独立 WKD_PROCESS::ThreadContext.Lock          */
/*  （并发安全重构 2026-08-23，与 ModuleContext.Lock 解耦） */
/**************************************************/

#pragma once

#include "ProcessTypes.h"
#include "../Notification/EventTypes.h"

/**************************************************/
/*               函数声明                           */
/**************************************************/

NTSTATUS
PsThreadAttachProcess(
    _Inout_ PWKD_PROCESS WkdProcess,
    _In_ const PEVENT_PAYLOAD_THREAD_CREATE Payload,
    _Out_ PWKD_THREAD* WkdThread
    );

NTSTATUS
PsThreadDetachProcess(
    _Inout_ PWKD_PROCESS WkdProcess,
    _In_ HANDLE ThreadId
    );

VOID
PsDestroyThreadContext(
    _Inout_ PWKD_PROCESS Process
    );
