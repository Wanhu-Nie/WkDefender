/**************************************************/
/*  WkDefender Agent — 进程域快照兜底              */
/*                                                  */
/*  进程域统一重构 (2026-08-15)：                    */
/*    原 process_manager.c 的 Toolhelp 60s 快照线程  */
/*    迁入本文件。语义保持：只维护进程域树（Wkd-     */
/*    ProcessTree），不产生 IOA 事件（避免与因果图    */
/*    时间线混淆）。快照节点 GUID=零、不持久化。      */
/**************************************************/

#pragma once

/* NTSTATUS 等基础类型（本头被 ProcessSnapshot.c 首个包含） */
#include <Windows.h>

NTSTATUS
ProcessSnapshot_Start(
    VOID
    );

VOID
ProcessSnapshot_Stop(
    VOID
    );
