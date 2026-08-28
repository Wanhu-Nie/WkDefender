/**************************************************/
/*  WkDefender 事件解析系统                         */
/*  WKD_MESSAGE → WKD_EVENT_HEADER 的 Schema 驱动解析 */
/**************************************************/

#pragma once

#include "EventTypes.h"
#include "../WkDefenderHeader.h"
#include "../Notification/AlpcService.h"

/**************************************************/
/*               Schema 条目                        */
/**************************************************/

typedef struct _WKD_EVENT_SCHEMA_ENTRY {
    WKD_EVENT_TYPE      Type;
    ULONG               Version;
    NTSTATUS (*ParseWkdMessage)(_In_ PWKD_MESSAGE Msg, _Out_ PWKD_EVENT_HEADER* Event);
    VOID     (*FreeEvent)(_In_ PWKD_EVENT_HEADER Event);
} WKD_EVENT_SCHEMA_ENTRY, *PWKD_EVENT_SCHEMA_ENTRY;

#define DEF_SCHEMA_MAX_ENTRIES 64

typedef struct _WKD_SCHEMA_TABLE {
    WKD_EVENT_SCHEMA_ENTRY Entries[DEF_SCHEMA_MAX_ENTRIES];
    ULONG Count;        // 实际使用量
    CRITICAL_SECTION Lock;
} WKD_SCHEMA_TABLE, *PWKD_SCHEMA_TABLE;

extern WKD_SCHEMA_TABLE g_DefSchemaTable;

NTSTATUS WkdEvent_InitializeSchema(VOID);
VOID     WkdEvent_CleanupSchema(VOID);

NTSTATUS 
NtfWkdMessageParse(
    _In_ const PWKD_SCHEMA_TABLE Table,
    _In_ const PWKD_MESSAGE Message,
    _Out_ const PWKD_EVENT_HEADER* Event
    );

VOID     DefEventFree(_In_ PWKD_EVENT_HEADER Event);

/* 事件 PID 提取 (供 OrcpWkdMessageDispatcher switch 前统一建 pair 与
 * IoaObserve 阶段1 节点反查共用, 避免两处维护各事件类型 payload 布局) */
NTSTATUS
NtfExtractEventPids(
    _In_ const PWKD_EVENT_HEADER Event,
    _Out_ PHANDLE SourceProcessId,
    _Out_ PHANDLE TargetProcessId
    );