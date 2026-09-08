/*++
    SelfProtection/SelfProtectionCompat.c - 自保护子系统公共适配层实现

    仅实现篡改事件上报；SHA-256 通用设施已迁移至 Common/BCryptUtils.c。

    Copyright (c) WkDefender Team
--*/

#include "SelfProtectionCompat.h"
#include <ntstrsafe.h>

/* ============================================================================
 * 篡改事件上报
 * ============================================================================ */

_Use_decl_annotations_
_Must_inspect_result_
NTSTATUS
WkdReportSelfProtectionEvent(
    ULONG EventSubType,
    ULONG Severity,
    PCWSTR Description
    )
{
    PWKD_MESSAGE msg = NULL;
    PWKD_MESSAGE_BODY_SECURITY_EVENT body = NULL;
    NTSTATUS status;

    //
    // 分发消息到通知总线
    //
    msg = NtfCreateMessage(
        WkdMessage_SecurityEvent,
        WkdMessage_SourceBehaviorEngine,   // 复用已有的来源枚举
        (Severity >= 8) ? WkdMessage_PriorityHigh : WkdMessage_PriorityNormal,
        sizeof(WKD_MESSAGE_BODY_SECURITY_EVENT)
    );

    if (msg == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    body = (PWKD_MESSAGE_BODY_SECURITY_EVENT)msg->Body;
    RtlZeroMemory(body, sizeof(WKD_MESSAGE_BODY_SECURITY_EVENT));

    body->EventId = EventSubType;
    body->Severity = Severity;
    body->Category = 0;    // 自保护类别（预留）
    body->RelatedProcessId = PsGetCurrentProcessId();

    if (Description != NULL) {
        RtlStringCchCopyW(body->EventName, ARRAYSIZE(body->EventName), L"SelfProtectionEvent");
        RtlStringCchCopyW(body->Description, ARRAYSIZE(body->Description), Description);
    }

    status = NtfSendMessageAsync(msg);
    if (!NT_SUCCESS(status)) {
        NmFreeMessage(msg);
    }

    return status;
}

_Use_decl_annotations_
_Must_inspect_result_
NTSTATUS
WkdReportTamperAlert(
    ULONG CallbackType,
    PVOID CallbackAddress,
    BOOLEAN Restored,
    PCWSTR Description
    )
{
    PWKD_MESSAGE msg = NULL;
    PWKD_MESSAGE_BODY_SECURITY_EVENT body = NULL;
    NTSTATUS status;
    WCHAR descBuffer[512];

    //
    // 构造描述字符串
    //
    RtlStringCchPrintfW(
        descBuffer,
        ARRAYSIZE(descBuffer),
        L"CallbackTamper: Type=%lu Address=0x%p Restored=%s %s",
        CallbackType,
        CallbackAddress,
        Restored ? L"YES" : L"NO",
        (Description != NULL) ? Description : L""
    );

    msg = NtfCreateMessage(
        WkdMessage_SecurityEvent,
        WkdMessage_SourceBehaviorEngine,
        WkdMessage_PriorityHigh,
        sizeof(WKD_MESSAGE_BODY_SECURITY_EVENT)
    );

    if (msg == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    msg->Header.Flags.CriticalPath = 1;   // 安全事件不可丢弃

    body = (PWKD_MESSAGE_BODY_SECURITY_EVENT)msg->Body;
    RtlZeroMemory(body, sizeof(WKD_MESSAGE_BODY_SECURITY_EVENT));

    body->EventId = 0x5001;     // 回调篡改事件子类型
    body->Severity = 9;         // 高严重程度
    body->Category = 1;         // 回调完整性类别
    body->RelatedProcessId = PsGetCurrentProcessId();
    RtlStringCchCopyW(body->EventName, ARRAYSIZE(body->EventName), L"CallbackCodeTamper");
    RtlStringCchCopyW(body->Description, ARRAYSIZE(body->Description), descBuffer);

    status = NtfSendMessageAsync(msg);
    if (!NT_SUCCESS(status)) {
        NmFreeMessage(msg);
    }

    return status;
}
