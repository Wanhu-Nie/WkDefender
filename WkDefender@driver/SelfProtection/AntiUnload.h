/*++
    SelfProtection/AntiUnload.h - 驱动防卸载保护模块

    Purpose:
        提供驱动卸载防护能力（2026-09-05 收敛：受保护进程句柄访问剥离
        已迁移 Pap/Tap 画像体系，本模块仅保留防卸载核心）。

        防卸载机制：
        - 置空 DriverObject->DriverUnload，阻断 NtUnloadDriver；
        - 受控卸载：ALPC 命令（SpEngineUnloadPrepare）触发 AuShutdown
          恢复 DriverUnload，Agent 再执行 sc stop。

        演进史（2026-09-05）：
        - 删除受保护进程体系：ProtectedProcesses 表 + AuProtectProcess /
          AuUnprotectProcess / AuIsProcessProtectedById / AuLookupProcessProtection
          / AupLookupProcessProtection（无任何注册通道，表恒空，判定恒 FALSE）；
        - 删除 OB 句柄访问剥离：SpCheckObjectAccessMaskInternal /
          SpCheckObjectAccessMask / SpIsProcessProtected（含热路径
          DbgBreakPoint 残留缺陷；AU 表默认空 + 源 wkd 对象未赋值前
          解引用 NULL）；
        - 受保护判定统一为 WKD_SECURITY_CONTEXT.PapProfile（Pap/Tap 审计
          主链承接句柄危险位剥离），本模块不再自注册/被调 OB 回调。

    Copyright (c) WkDefender Team
--*/

#pragma once

#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WKD_AU_POOL_TAG                 'LUAW'      /* 主结构池标签 */

/* ============================================================================
 * 防卸载保护器（不透明句柄，结构定义在 .c 中）
 * ============================================================================ */

typedef struct _WKD_ANTIUNLOAD_PROTECTION WKD_ANTIUNLOAD_PROTECTION, *PWKD_ANTIUNLOAD_PROTECTION;

/* ============================================================================
 * 公共 API
 * ============================================================================ */

//
// 初始化防卸载保护。
// 分配 WKD_ANTIUNLOAD_PROTECTION，置空 DriverObject->DriverUnload（保存 OriginalUnload），
// 对 DriverObject 取引用。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SpInitializeAntiUnloadProtection(
    _Out_ PWKD_ANTIUNLOAD_PROTECTION* Protector
    );

//
// 关闭防卸载保护。
// 恢复 DriverUnload -> 释放驱动引用 -> 释放保护器。NULL 安全。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
AuShutdown(
    _In_ PWKD_ANTIUNLOAD_PROTECTION Protector
    );

#ifdef __cplusplus
}
#endif