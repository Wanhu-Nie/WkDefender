/**************************************************/
/*  WkDefender — 事件展平/反展平（持久化归档）        */
/*  载荷为嵌入式扁平布局 (2026-08-25):               */
/*    [header][payload (内嵌 UNICODE_STRING)][数据区] */
/*  归档 = 整块拷贝; Buffer 为进程内绝对地址,          */
/*  恢复时按布局约定重建 (排布序 = 字段声明序)。       */
/**************************************************/

#include "EventArchive.h"
#include "../Common/Utils.h"

/**************************************************/
/*        事件归档: 单块连续内存整块拷贝             */
/*  依赖 Parse 端 PayloadSize 含载荷+字符串数据区    */
/*  总长 (NtfpEventParseProcessCreate 等,           */
/*  2026-08-25 嵌入式扁平化约定)。                  */
/**************************************************/

NTSTATUS
NtfEventArchive(
    _In_  PWKD_EVENT_HEADER  Event,
    _Out_ PWKD_EVENT_HEADER* ArchivedEvent,
    _Out_ ULONG*             ArchivedSize
    )
{
    ULONG allocSize;
    PWKD_EVENT_HEADER archivedEvent;

    if (!Event || !ArchivedEvent || !ArchivedSize)
        return STATUS_INVALID_PARAMETER;

    allocSize = sizeof(WKD_EVENT_HEADER) + Event->PayloadSize;
    archivedEvent = UtHeapAlloc(allocSize);
    if (!archivedEvent) return STATUS_NO_MEMORY;

    RtlCopyMemory(archivedEvent, Event, allocSize);

    *ArchivedEvent = archivedEvent;
    *ArchivedSize = allocSize;
    return STATUS_SUCCESS;
}

/**************************************************/
/*           事件反展平: 重建字符串指针              */
/*                                                  */
/*  BLOB 中 Length/MaximumLength 正确持久化,         */
/*  Buffer 存的是归档时的旧绝对地址 — 忽略其值,      */
/*  仅以 Length!=0 判定字段存在, 按声明序推进游标     */
/*  重算地址 (与 Parse 端排布序严格一致)。            */
/**************************************************/

VOID
NtfEventRestore(
    _Inout_ PWKD_EVENT_HEADER Event
    )
{
    PUCHAR strData;

    if (!Event) return;

    switch (Event->Type)
    {
    case WkdEvent_ProcessCreate:
    {
        /* 排布序: ImagePath → CommandLine → ImageFileName */
        PEVENT_PAYLOAD_PROCESS_CREATE payload =
            (PEVENT_PAYLOAD_PROCESS_CREATE)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));

        strData = (PUCHAR)(payload + 1);

        if (payload->ImagePath.Length) {
            payload->ImagePath.Buffer = (PWCHAR)strData;
            strData += payload->ImagePath.MaximumLength;
        }
        if (payload->CommandLine.Length) {
            payload->CommandLine.Buffer = (PWCHAR)strData;
            strData += payload->CommandLine.MaximumLength;
        }
        if (payload->ImageFileName.Length) {
            payload->ImageFileName.Buffer = (PWCHAR)strData;
        }
        break;
    }

    case WkdEvent_FileCreate:
    case WkdEvent_FileWrite:
    case WkdEvent_FileRename:
    case WkdEvent_FileDelete:
    case WkdEvent_FileShadowCopyDelete:
    {
        PEVENT_PAYLOAD_FILE_EVENT payload =
            (PEVENT_PAYLOAD_FILE_EVENT)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));

        if (payload->FilePath.Length) {
            payload->FilePath.Buffer = (PWCHAR)(payload + 1);
        }
        break;
    }

    case WkdEvent_NamedPipeCreate:
    {
        PEVENT_PAYLOAD_NAMED_PIPE payload =
            (PEVENT_PAYLOAD_NAMED_PIPE)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));

        if (payload->PipeName.Length) {
            payload->PipeName.Buffer = (PWCHAR)(payload + 1);
        }
        break;
    }

    case WkdEvent_ImageLoad:
    {
        PEVENT_PAYLOAD_IMAGE_LOAD payload =
            (PEVENT_PAYLOAD_IMAGE_LOAD)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));

        if (payload->ImagePath.Length) {
            payload->ImagePath.Buffer = (PWCHAR)(payload + 1);
        }
        break;
    }

    default:
        /*
         * 其余事件类型 (ProcessExit/Syscall/Thread/Section 等)
         * 载荷无字符串域或恒空 (SectionMap.FilePath 全零), 无需重建。
         */
        break;
    }
}
