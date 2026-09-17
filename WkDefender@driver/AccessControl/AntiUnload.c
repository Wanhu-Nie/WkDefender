/*++
    SelfProtection/AntiUnload.c - 驱动防卸载保护模块实现

    Purpose:
        防卸载保护（2026-09-05 收敛：受保护进程句柄剥离已迁移
        Pap/Tap 画像体系，本模块仅保留防卸载核心）。

        - SpInitializeAntiUnloadProtection：置空 DriverUnload（保存
          OriginalUnload），阻断 NtUnloadDriver；
        - AuShutdown：恢复 DriverUnload 供受控卸载（ALPC 命令经
          SpEngineUnloadPrepare 编排）。

        演进史（2026-09-05）：删除受保护进程表（ProtectedProcesses）、
        进程注册/查询 API（AuProtectProcess/AuUnprotectProcess/
        AuIsProcessProtectedById/AuLookupProcessProtection）、OB 句柄
        访问剥离（SpCheckObjectAccessMaskInternal）及其配套设施
        （Level/事件环/统计/用户回调/ALPC 事件上报）。

    Copyright (c) WkDefender Team
--*/

#include "AntiUnload.h"
#include "../Common/Utils.h"     /* WkdDriverObject 全局（驱动对象句柄，供置空 DriverUnload） */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SpInitializeAntiUnloadProtection)
#endif

/* ============================================================================
 * 保护器结构（不透明句柄的定义）
 * ============================================================================ */

typedef struct _WKD_ANTIUNLOAD_PROTECTION {
    PDRIVER_OBJECT  ProtectedDriver;    /* 被保护驱动（引用） */
    PDRIVER_UNLOAD  OriginalUnload;     /* 原始卸载例程 */
} WKD_ANTIUNLOAD_PROTECTION;

/* ============================================================================
 * 公共 API
 * ============================================================================ */

/*++
    Routine Description:
        初始化防卸载保护。置空 DriverUnload，取驱动引用。

    Arguments:
        Protection — 输出分配的保护器句柄。

    Returns:
        STATUS_SUCCESS 或分配失败。
--*/
_Use_decl_annotations_
NTSTATUS
SpInitializeAntiUnloadProtection(
    _Out_ PWKD_ANTIUNLOAD_PROTECTION* Protection
    )
{
    PWKD_ANTIUNLOAD_PROTECTION protection = NULL;

    PAGED_CODE();

    if (!Protection) return STATUS_INVALID_PARAMETER;
    *Protection = NULL;

    protection = (PWKD_ANTIUNLOAD_PROTECTION)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(WKD_ANTIUNLOAD_PROTECTION),
        WKD_AU_POOL_TAG
        );
    if (!protection) return STATUS_NO_MEMORY;

    protection->ProtectedDriver = WkdDriverObject;

    /* 置空卸载例程 —— 核心防卸载机制。保存原始例程供 AuShutdown 恢复进行受控卸载。 */
    protection->OriginalUnload = WkdDriverObject->DriverUnload;
    WkdDriverObject->DriverUnload = NULL;

    *Protection = protection;
    return STATUS_SUCCESS;
}

/*++
    Routine Description:
        关闭防卸载保护。恢复 DriverUnload，释放保护器。

    Arguments:
        Protection — 待销毁的保护器。NULL 安全。
--*/
_Use_decl_annotations_
VOID
AuShutdown(
    PWKD_ANTIUNLOAD_PROTECTION Protection
    )
{
    if (Protection == NULL) {
        return;
    }

    /* 恢复 DriverUnload 进行受控卸载并解除引用 */
    if (Protection->ProtectedDriver != NULL) {
        Protection->ProtectedDriver->DriverUnload = Protection->OriginalUnload;
        ObDereferenceObject(Protection->ProtectedDriver);
        Protection->ProtectedDriver = NULL;
    }

    ExFreePoolWithTag(Protection, WKD_AU_POOL_TAG);
}