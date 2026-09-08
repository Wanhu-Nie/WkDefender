/*++
    SelfProtection/SelfProtectionCompat.h - 自保护子系统公共适配层

    Purpose:
        提供篡改事件上报的统一接口，隔离 BehaviorEngine/TelemetryEvents
        等外部依赖，供 SelfProtection 目录下所有模块共用。

    SHA-256:
        通用加密设施已解耦迁移至 Common/BCryptUtils.h（CoInitializeSha256Algorithm/
        WkdSha256Shutdown/CoComputeSha256）。此处仅透传 include，
        便于 SelfProtection 各模块以单一头文件组合引用。

    上报:
        通过 ALPC 通知总线（NtfSendMessageAsync）上报事件到用户态 Agent。
        事件格式复用 WKD_MESSAGE_BODY_SECURITY_EVENT。

    Copyright (c) WkDefender Team
--*/

#pragma once

#include <ntifs.h>
#include "../Common/Constants.h"
#include "../Common/BCryptUtils.h"
#include "../Notification/NotificationManager.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 篡改事件上报
 * ============================================================================ */

//
// 上报自保护事件到用户态 Agent（通过 ALPC 通知总线）
//
// EventSubType:  事件子类型（由调用模块定义，如 0x5001 = 回调篡改）
// Severity:      严重程度 1-10
// Description:   事件描述（Unicode 字符串，最长 512 字符）
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
WkdReportSelfProtectionEvent(
    _In_ ULONG EventSubType,
    _In_ ULONG Severity,
    _In_ PCWSTR Description
    );

//
// 上报篡改告警（含回调地址、恢复结果等详细信息）
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
WkdReportTamperAlert(
    _In_ ULONG CallbackType,
    _In_ PVOID CallbackAddress,
    _In_ BOOLEAN Restored,
    _In_ PCWSTR Description
    );

#ifdef __cplusplus
}
#endif
