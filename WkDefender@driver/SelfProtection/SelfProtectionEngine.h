/*++
    SelfProtection/SelfProtectionEngine.h - 自防护子系统编排器（唯一对外公共头）

    Purpose:
        自防护子系统（SelfProtection）的唯一对外接口。
        外部世界（WkdEntry / Callbacks / Notification）【只能】通过本头文件的
        函数与自防护引擎交互，严禁直接引用或调用内部组件
        （CallbackProtection / AntiUnload）的头文件与函数。

        编排器组合持有内部组件：
        - 回调代码完整性保护（CallbackProtection, CP）
        - 防卸载保护（AntiUnload, AU）
        - 防调试检测与告警（AntiDebug, AD）
        - 驱动自我完整性监控（IntegrityMonitor, IM）
            —— 对驱动自身内存映像（代码节/只读数据节/PE 头）建立
               SHA-256 基线并周期比对，检测内存篡改（IAT/导出钩子、
               代码补丁、数据损坏、头篡改）并上报。

        编排流水线：
            SpCreateSelfProtectionEngine    -> SpInitializeSelfProtectionEngine -> (SpRegisterSelfProtectionCallback*)
                             -> SppStartSelfProtectionEngine -> ... -> SpShutdownSelfProtectionEngine

    Rundown 语义（重要）:
        - 自防护引擎持有【唯一】EX_RUNDOWN_REF，作为整个子系统的生命周期
          保护与关闭同步点。
        - 只有【暴露给外部的异步入口】才需要获取/释放该 rundown：
            * SpEngineUnloadPrepare      — 由 ALPC 命令处理线程异步调用
        - 内部组件（CP/AU/AD）自身不持有也不获取 rundown；它们在引擎安排的
          确定性上下文中（Initialize/Start/Shutdown/定时器）运行，
          生命周期由引擎统一编排。

    关闭时序（WkdEntry DriverUnload）:
        1. 先注销 OB 回调（CbObjectNotifyCleanup，外部执行，阻止新的
           句柄访问进入 OB 回调）
        2. 再调用 SpShutdownSelfProtectionEngine（本引擎在内部停定时器、等待
           rundown 排空后逆序释放 CP/AU）

    Copyright (c) WkDefender Team
--*/

#pragma once

#include <ntifs.h>
#include <wdm.h>    /* REG_NOTIFY_CLASS（SpEngineShouldBlockRegistryAccess 参数） */
#include "../Common/Constants.h"
#include "SelfProtectionCompat.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 常量
 * ============================================================================ */

#define WKD_SP_ENGINE_POOL_TAG          'nEgW'      /* 引擎主结构池标签 */
#define WKD_SP_MAX_PROTECTED_CALLBACK   128         /* 可保护的回调数量上限 */

/* ============================================================================
 * 需保护的回调类型（编排器公共概念，供外部注册受保护回调）
 * ============================================================================ */

typedef enum _WKD_SP_CALLBACK_TYPE {
    WkdSpCallback_Process = 0,      /* 进程创建/终止回调 */
    WkdSpCallback_Thread,           /* 线程创建/终止回调 */
    WkdSpCallback_Image,            /* 镜像加载回调 */
    WkdSpCallback_MaxType
} WKD_SP_CALLBACK_TYPE, *PWKD_SP_CALLBACK_TYPE;

/* ============================================================================
 * 自防护引擎（不透明句柄，结构定义在 SelfProtectionEngine.c 中）
 * ============================================================================ */

typedef struct _WKD_SELF_PROTECTION_ENGINE WKD_SELF_PROTECTION_ENGINE,
    *PWKD_SELF_PROTECTION_ENGINE;

/* ============================================================================
 * 生命周期编排 API（PASSIVE_LEVEL，DriverEntry / DriverUnload 调用）
 * ============================================================================ */

//
// 创建自防护引擎（分配句柄）。
// 此时仅分配并初始化引擎级 rundown，尚未创建内部组件。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SpCreateSelfProtectionEngine(
    _Out_ PWKD_SELF_PROTECTION_ENGINE* Engine
    );

//
// 初始化自防护引擎的各个内部组件：
//   - SHA-256 公共设施
//   - 回调代码完整性保护（CP）
//   - 防卸载保护（AU，置空 DriverObject->DriverUnload 保存 OriginalUnload）
//   - 防调试保护（AD，周期检测内核/用户调试器/Hypervisor/Verifier/CrashDump）
//   - 驱动自我完整性监控（IM，复用 CoParsePe 建立驱动内存映像 SHA-256 基线）
// 非致命：任一组件初始化失败仅丧失对应能力，不阻断整体启动。
// 引擎必须已由 SpCreateSelfProtectionEngine 创建。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SpInitializeSelfProtectionEngine(
    _Out_ PWKD_SELF_PROTECTION_ENGINE* Engine
    );

//
// 关闭自防护引擎（统一逆序清理）。
//   - 停止 IM 周期校验定时器并等待排空
//   - 停止 CP 周期验证定时器并等待排空
//   - 等待引擎 rundown 排空（外部异步入口）
//   - 关闭 AU（恢复 DriverUnload、解除驱动引用）
//   - 关闭 CP（释放回调条目链表、Lookaside、定时器）
//   - 关闭 IM（释放节基线、事件、上下文）
//   - 关闭 RG（释放键列表、保护器）
//   - 关闭 SHA-256 公共设施，最后释放引擎
// 调用前提：外部必须已注销 OB 回调和 CM 回调（CbRegistryCleanup），
//           确保不再有新的 SpEngineShouldBlockRegistryAccess 进入。NULL 安全。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
SpShutdownSelfProtectionEngine(
    _Inout_ _Pre_valid_ _Post_invalid_ PWKD_SELF_PROTECTION_ENGINE Engine
    );

//
// 判定是否应 BLOCK 一次注册表操作（注册表自保护消费者入口）。
// 由 Callbacks/RegistryCallback.c 的 CM 回调调用。内部获取引擎 rundown 后
// 转调 RG（RgpShouldBlockRegistryAccess）完成豁免（受保护进程自改自键放行）、
// 键前缀匹配、危险操作拦截与 0x5030 段上报。
// 若引擎关闭中或 RG 未就绪，返回 FALSE 表示放行（尽力而为）。
// 运行环境: PASSIVE_LEVEL（CM 回调上下文）
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
SpEngineShouldBlockRegistryAccess(
    _In_ PCUNICODE_STRING KeyPath,
    _In_ REG_NOTIFY_CLASS Operation,
    _In_ HANDLE RequestorProcessId
    );

//
// 保护一个注册表键/键前缀（注册表自保护配置入口）。
// 转调 RG（RgpProtectKey）。当前无外部调用者（预留 API，供后续 Agent
// 策略推送受保护键）。运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SpEngineProtectRegistryKey(
    _In_ PWKD_SELF_PROTECTION_ENGINE Engine,
    _In_ PCWSTR KeyPath
    );

//
// 注销对一个注册表键/键前缀的保护（注册表自保护配置入口）。
// 转调 RG（RgpUnprotectKey）。运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
SpEngineUnprotectRegistryKey(
    _In_ PWKD_SELF_PROTECTION_ENGINE Engine,
    _In_ PCWSTR KeyPath
    );

/* ============================================================================
 * 外部异步入口（需要引擎 rundown 保护）
 * ============================================================================ */

//
// 受控卸载准备（由 Notification/AlpcService.c 的 ALPC 命令处理线程调用）。
// 触发 AU 恢复 DriverObject->DriverUnload，使 Agent 可执行 sc stop 完成正常卸载。
// 内部获取引擎 rundown 后转调 AU。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SpEngineUnloadPrepare(
    VOID
    );

#ifdef __cplusplus
}
#endif
