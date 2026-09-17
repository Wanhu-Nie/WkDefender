/*++
    Callbacks/RegistryNotification.h - 注册表回调节点（独立 CM 回调节点）

    Purpose:
        提供注册表配置变更的 CM（Config Manager）回调节点，与自防护子系统
        解耦。本节点仅负责：
        1. 注册/注销 CmRegisterCallbackEx / CmUnRegisterCallback
        2. 对 6 类 Pre 操作（DeleteKey/SetValueKey/DeleteValueKey/
           RenameKey/CreateKeyEx/SetKeySecurity）做 allow-list 过滤
        3. 解析受操作键的完整路径（ObQueryNameString；CreateKeyEx 拼接
           RootObject + CompleteName）
        4. 将 (路径, 操作, 请求者 PID) 交给自防护引擎判定是否允许
           （SpEngineShouldBlockRegistryAccess）
        5. 对 SetValue/DeleteValue 提取值名/数据/类型，转交分析入口
           AcAuditRegistryAccess（分类/持久化/勒索语义/进程行为
           关联/统计），其阻断点返回值并入判定

        【重要】本节点【不】内嵌判定/豁免/上报逻辑。判定由自防护子系统
        消费（引擎公共入口 SpEngineShouldBlockRegistryAccess /
        AcAuditRegistryAccess），本节点只做路径与值信息提取、
        BLOCK 决策的转发（BLOCK -> STATUS_ACCESS_DENIED）。

        注册表回调的注册/注销均在本模块（callbacks/ 层）完成，与自防护
        无关。注销须在驱动卸载的 callbacks 清整阶段执行（先于引擎 shutdown），
        确保不再有回调进入引擎判定（阻止新的 rundown 获取）。

    Synchronization:
        - FAST_MUTEX 串行化注册/注销；CbRegistryNotificationCallback 由 CM 在
          PASSIVE_LEVEL 调用，删除钩子后不再有并发进入。

    Copyright (c) WkDefender Team
--*/

#pragma once

#include <ntifs.h>
#include <wdm.h>    /* REG_NOTIFY_CLASS / REG_*_INFORMATION 结构 / ExAcquireFastMutex 等 */

#ifdef __cplusplus
extern "C" {
#endif

//
// 初始化注册表回调节点（注册 CmRegisterCallbackEx，altitude L"380050"）。
// 非致命：调用方（WkdEntry）在失败时继续加载，仅丧失注册表保护可见性。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CbInitializeRegistryNotify(
    _In_ PDRIVER_OBJECT DriverObject
    );

//
// 清理注册表回调节点（注销 CmUnRegisterCallback）。
// 须在驱动卸载的 callbacks 清整阶段、自防护引擎 Shutdown 之前调用，
// 阻止新的受保护判定回调进入。NULL 安全，重复调用安全。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
CbShutdownRegistryNotify(
    VOID
    );

#ifdef __cplusplus
}
#endif