/**************************************************/
/*  WkDefender — 事件展平/反展平（持久化归档）        */
/*  连续内存布局: 结构体 + 紧跟字符串数据             */
/*  指针字段存储相对偏移量，供 SQLite BLOB 存储       */
/**************************************************/

#pragma once

#include "EventTypes.h"

/**************************************************/
/*           事件展平: 独立分配 → 连续内存布局       */
/**************************************************/

NTSTATUS
NtfEventArchive(
    _In_  PWKD_EVENT_HEADER  Event,
    _Out_ PWKD_EVENT_HEADER* FlatEvent,
    _Out_ ULONG*             FlatSize
    );
/*++
Routine Description:
    将事件展平为连续内存布局（结构体 + 紧跟字符串），供 SQLite BLOB 存储。

    对于不含指针字段的事件类型（ProcessExit/Syscall/Thread），
    直接返回原指针（*FlatEvent == Event），调用方无需释放。

    对于 ProcessCreate，将 3 个 UNICODE_STRING 字符串追加到结构体后面，
    指针字段替换为相对偏移量（< 0x10000），调用方需 UtHeapFree(*FlatEvent)。

Arguments:
    Event     — 源事件（含独立分配的 UNICODE_STRING）。
    FlatEvent — 输出: 展平后的事件指针。
    FlatSize  — 输出: 展平后事件总大小（header + payload）。
--*/

/**************************************************/
/*           事件反展平: 偏移量 → 实际指针          */
/**************************************************/

VOID
NtfEventRestore(
    _Inout_ PWKD_EVENT_HEADER Event
    );
/*++
Routine Description:
    将 SQLite 恢复的事件指针从旧绝对地址还原为当前内存地址。
    不依赖 BLOB 中存储的旧指针值，完全基于连续内存布局约定重建指针。

    当前支持:
      - WkdEvent_ProcessCreate: 重建 ImagePath/CommandLine/ImageFileName

Arguments:
    Event — 从 SQLite 读出后的事件（in/out，指针字段被原地修正）。
--*/
