/*++
    SelfProtection/SelfProtectionEngine.c - 自防护子系统编排器实现

    Purpose:
        自防护子系统（SelfProtection）的唯一编排器。组合持有内部组件：
        - 回调代码完整性保护（CallbackProtection, CP）
        - 防卸载保护（AntiUnload, AU）
        - 防调试检测与告警（AntiDebug, AD）
        - 驱动自我完整性监控（IntegrityMonitor, IM）
        -- 对驱动自身内存映像（代码节/只读数据节/PE 头）建立 SHA-256
           基线并周期比对，检测内存篡改并上报。
        并以【唯一】EX_RUNDOWN_REF 作为整个子系统的生命周期保护与关闭同步点。

    句柄范式:
        - 引擎以堆指针句柄（PWKD_SELF_PROTECTION_ENGINE）对外暴露，
          由 WkdEntry 的 SpCreateSelfProtectionEngine(&g_SpEngine) 创建并持有。
        - 所有生命周期 API 均操作调用方传入的 Engine 指针（非 NULL）。
        - 模块内 static 会话指针 g_spEngineSession 仅在创建时记录、关闭时清空，
          专供无参外部异步入口 SpEngineUnloadPrepare 定位引擎实例。

    Rundown 语义:
        - 引擎持有唯一 EX_RUNDOWN_REF。
        - 只有【暴露给外部的异步入口】才获取/释放该 rundown：
            * SpEngineUnloadPrepare     — ALPC 命令处理线程（PASSIVE_LEVEL）
        - 内部组件（CP/AU/AD）自身不持有也不获取 rundown；它们在引擎安排的
          确定性上下文中（Initialize/Start/Shutdown/定时器）运行。

    关闭时序（WkdEntry DriverUnload）:
        1. 外部先注销 OB 回调（CbObjectNotifyCleanup），阻止新的
           句柄访问进入 OB 回调
        2. 再调用 SpShutdownSelfProtectionEngine(Engine)：
           停 CP 定时器 -> 停 AD 周期定时器 -> 停 IM 周期校验定时器
           -> 等待引擎 rundown 排空 -> 关闭 AU -> 关闭 CP -> 关闭 AD
           -> 关闭 IM -> 关闭 SHA-256 -> 释放引擎

    Copyright (c) WkDefender Team
--*/

#include "SelfProtectionEngine.h"
#include "CallbackProtection.h"  /* 2026-09-03 恢复：回调保护 */
#include "AntiUnload.h"          /* 2026-09-03 恢复：防卸载 */
#include "AntiDebug.h"           /* 2026-09-03 恢复：防调试 */
#include "IntegrityMonitor.h"    /* 2026-09-03 恢复：完整性监控 */
#include "RegistryProtection.h"  /* 2026-09-03 恢复：注册表自保护 */
#include "SelfProtectionCompat.h"
#include "../Callbacks/ProcessNotify.h"   /* CbGetProcessNotifyCallback */
#include "../Callbacks/ThreadNotify.h"    /* CbGetThreadNotifyCallback */
#include "../Callbacks/ImageNotify.h"     /* CbGetImageNotifyCallback */
#include "../Process/ProcessAccessProtection.h" /* PapIsProcessProtected（RG 豁免判定收敛） */



// SppStartSelfProtectionEngine 前向声明——需在使用（pragma 列表、下方调用）之前可见。
_Must_inspect_result_
static
NTSTATUS
SppStartSelfProtectionEngine(
    _In_ const PWKD_SELF_PROTECTION_ENGINE Engine
    );

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SpCreateSelfProtectionEngine)
#pragma alloc_text(PAGE, SpInitializeSelfProtectionEngine)
#pragma alloc_text(PAGE, SppStartSelfProtectionEngine)
#pragma alloc_text(PAGE, SpShutdownSelfProtectionEngine)
#endif

//
// 豁免判定回调前向声明（定义在文件末尾 RG 段）。
// 由 SpInitializeRegistryProtection 注入，内部查 AntiUnload：受保护进程自改自键放行。
//
static
BOOLEAN
SpEngineIsRegistryProcessExempt(
    _In_ HANDLE RequestorProcessId,
    _In_opt_ PVOID Context
    );

/* ============================================================================
 * 引擎上下文（不透明句柄结构定义）
 * ============================================================================ */

//
// 引擎主结构。组合内嵌持有 CP/AU/AD/IM 子对象指针 + 唯一 EX_RUNDOWN_REF。
//
struct _WKD_SELF_PROTECTION_ENGINE {
    EX_RUNDOWN_REF              RundownRef;             /* 唯一生命周期保护（外部异步入口使用） */

    /* 以下子模块已恢复（2026-09-03） */
    PWKD_CALLBACK_PROTECTION    CallbackProtection;     /* CP 子对象句柄 */
    PWKD_ANTIUNLOAD_PROTECTION  AntiUnloadProtection;   /* AU 子对象句柄 */
    PWKD_ANTIDEBUG_PROTECTION   AntiDebugProtection;    /* AD 子对象句柄 */
    PWKD_INTEGRITY_PROTECTION   IntegrityProtection;    /* IM 子对象句柄 */
    PWKD_REGISTRY_PROTECTION    RegistryProtection;     /* RG 子对象句柄（注册表自保护消费者） */
};

//
// 模块内会话指针。创建时由 SpCreateSelfProtectionEngine 记录、关闭时清空，
// 专供无参外部异步入口 SpEngineUnloadPrepare 使用。
// 生命周期 API 一律使用调用方传入的 Engine 参数，不使用此全局。
//
static PWKD_SELF_PROTECTION_ENGINE g_spEngineSession = NULL;

/* ============================================================================
 * 生命周期编排 API
 * ============================================================================ */

/*++
    SpCreateSelfProtectionEngine - 创建自防护引擎

    分配引擎主结构、初始化引擎级 rundown，并记录模块内会话指针
    （供无参外部异步入口定位）。此时尚未创建内部组件。
    运行环境: PASSIVE_LEVEL
--*/
_Use_decl_annotations_
NTSTATUS
SpCreateSelfProtectionEngine(
    _Out_ PWKD_SELF_PROTECTION_ENGINE* Engine
    )
{
    PWKD_SELF_PROTECTION_ENGINE engine = NULL;

    PAGED_CODE();

    if (!Engine) return STATUS_INVALID_PARAMETER;
    *Engine = NULL;

    engine = (PWKD_SELF_PROTECTION_ENGINE)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(WKD_SELF_PROTECTION_ENGINE),
        WKD_SP_ENGINE_POOL_TAG
    );
    if (!engine) return STATUS_NO_MEMORY;

    /* 初始化唯一生命周期保护 */
    ExInitializeRundownProtection(&engine->RundownRef);

    /* 记录会话指针，供无参外部异步入口 SpEngineUnloadPrepare 使用 */
    g_spEngineSession = engine;
    *Engine = engine;

    return STATUS_SUCCESS;
}

/*++
    SpInitializeSelfProtectionEngine - 初始化引擎的各个内部组件

    依次初始化：
        - SHA-256 公共设施（CoInitializeSha256Algorithm）
        - 回调代码完整性保护（CP，SpInitializeCallbackProtection）
        - 防卸载保护（AU，SpInitializeAntiUnloadProtection，置空 DriverUnload 保存 OriginalUnload）
        - 防调试保护（AD，SpInitializeAntiDebugProtection，周期检测内核/用户调试器/Hypervisor/Verifier/CrashDump）

    非致命：任一组件初始化失败仅丧失对应能力，不阻断整体启动。
    运行环境: PASSIVE_LEVEL
--*/
_Use_decl_annotations_
NTSTATUS
SpInitializeSelfProtectionEngine(
    _Out_ PWKD_SELF_PROTECTION_ENGINE* Engine
    )
{
    NTSTATUS status;
    PWKD_SELF_PROTECTION_ENGINE engine = NULL;

    PAGED_CODE();

    if (!Engine) return STATUS_INVALID_PARAMETER;
    *Engine = NULL;

    status = SpCreateSelfProtectionEngine(&engine);
    if (!NT_SUCCESS(status)) return status;

    //
    // 1. SHA-256 公共设施（CP 依赖）
    //
    status = CoInitializeSha256Algorithm();
    if (!NT_SUCCESS(status)) goto Cleanup;

    //
    // 2. 回调代码完整性保护（CP）— 2026-09-03 恢复
    //    注入引擎 rundown：校验线程据此判活
    //
    status = SpInitializeCallbackProtection(&engine->CallbackProtection);
    if (!NT_SUCCESS(status)) goto Cleanup;

    //
    // 3. 防卸载保护（AU）— 2026-09-03 恢复
    //
    status = SpInitializeAntiUnloadProtection(&engine->AntiUnloadProtection);
    if (!NT_SUCCESS(status)) goto Cleanup;

    //
    // 4. 防调试保护（AD）— 2026-09-03 恢复；注入引擎 rundown
    //
    status = SpInitializeAntiDebugProtection(&engine->AntiDebugProtection);
    if (!NT_SUCCESS(status)) goto Cleanup;

    //
    // 5. 驱动自我完整性监控（IM）— 2026-09-03 恢复；注入引擎 rundown
    //
    status = SpInitializeIntegrityProtection(&engine->IntegrityProtection);
    if (!NT_SUCCESS(status)) goto Cleanup;

    //
    // 6. 注册表自保护（RG）— 2026-09-03 恢复
    //
    status = SpInitializeRegistryProtection(
        &engine->RegistryProtection,
        SpEngineIsRegistryProcessExempt,
        Engine
        );
    if (!NT_SUCCESS(status)) goto Cleanup;

    /* ---- 注册回调防护 ---- */
    status = SpRegisterCallbackProtection(
        engine->CallbackProtection,
        WkdSpCallback_Process,
        CbProcessNotifyCallback
        );
    if (!NT_SUCCESS(status)) goto Cleanup;

    status = SpRegisterCallbackProtection(
        engine->CallbackProtection,
        WkdSpCallback_Thread,
        CbThreadNotifyCallback
        );
    if (!NT_SUCCESS(status)) goto Cleanup;

    status = SpRegisterCallbackProtection(
        engine->CallbackProtection,
        WkdSpCallback_Image,
        CbImageNotifyCallback
        );
    if (!NT_SUCCESS(status)) goto Cleanup;

    /* 启动周期性验证 + AU 升级 Full 级 + AD 周期检测 */
    status = SppStartSelfProtectionEngine(engine);
    if (!NT_SUCCESS(status)) goto Cleanup;

    *Engine = engine;
    return STATUS_SUCCESS;

Cleanup:
    SpShutdownSelfProtectionEngine(engine);
    return STATUS_UNSUCCESSFUL;
}

/*++
     SppStartSelfProtectionEngine - 启动引擎的周期性能力

        - CP: 启用周期性回调代码完整性验证（默认间隔）
        - AU: 升级到 Full 保护级别（受保护 PID 句柄访问剥离）
        - AD: 启动周期性防调试检测
        - IM: 启动周期性驱动映像完整性校验
    运行环境: PASSIVE_LEVEL
--*/
_Must_inspect_result_
static
NTSTATUS
SppStartSelfProtectionEngine(
    _In_ const PWKD_SELF_PROTECTION_ENGINE Engine
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    if (!Engine) return STATUS_INVALID_PARAMETER;

    //
    // CP 周期性验证 — 2026-09-03 恢复
    //
    if (Engine->CallbackProtection) {
        status = SpStartPeriodicCallbackProtection(
            Engine->CallbackProtection,
            &Engine->RundownRef,
            WKD_CP_DEFAULT_INTERVAL_MS
            );
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WkDefender] SppStartSelfProtectionEngine: SpStartPeriodicCallbackProtection failed: 0x%08X\n",
                status);
        }
    }

    //
    // AD 启动周期检测 — 2026-09-03 恢复
    //
    if (Engine->AntiDebugProtection) {
        status = SpStartPeriodicAntiDebugProtection(
            Engine->AntiDebugProtection,
            &Engine->RundownRef,
            WKD_CP_DEFAULT_INTERVAL_MS
            );
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WkDefender] SppStartSelfProtectionEngine: SpStartPeriodicAntiDebugProtection failed: 0x%08X\n",
                status);
        }
    }

    //
    // IM 启动周期完整性校验 — 2026-09-03 恢复
    //
    if (Engine->IntegrityProtection) {
        status = SpStartPeriodicIntegrityProtection(
            Engine->IntegrityProtection,
            &Engine->RundownRef,
            WKD_CP_DEFAULT_INTERVAL_MS
            );
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WkDefender] SppStartSelfProtectionEngine: SpStartPeriodicIntegrityProtection failed: 0x%08X\n",
                status);
        }
    }

    return status;
}

/*++
    SpShutdownSelfProtectionEngine - 关闭自防护引擎（统一逆序清理）

    时序：
        1. 停止 CP 周期验证定时器（CpShutdown 内部完成）
        2. 停止 AD 周期检测定时器（AdbShutdown 内部完成）
        2.1 停止 IM 周期校验定时器（ImShutdown 内部完成）
        3. 等待引擎 rundown 排空（外部异步入口全部退出）
        4. 关闭 AU（恢复 DriverUnload、解除驱动引用）
        4.1 关闭 RG（释放键列表、保护器）
        5. 关闭 CP（释放回调条目链表、Lookaside、定时器）
        6. 关闭 AD（释放事件队列、统计、定时器）
        6.1 关闭 IM（释放节基线、事件、上下文）
        7. 关闭 SHA-256 公共设施
        8. 释放引擎主结构，清空模块会话指针

    调用前提：外部必须已注销 OB 回调和 CM 回调（CbObjectNotifyCleanup /
    CbRegistryCleanup），确保不再有新的 SpEngineShouldBlockRegistryAccess
    进入。NULL 安全。
    运行环境: PASSIVE_LEVEL
--*/
_Use_decl_annotations_
VOID
SpShutdownSelfProtectionEngine(
    _Inout_ PWKD_SELF_PROTECTION_ENGINE Engine
    )
{
    PAGED_CODE();

    if (!Engine) return;

    //
    // 1. 等待引擎 rundown 排空
    //
    ExWaitForRundownProtectionRelease(&Engine->RundownRef);

    //
    // 2. 停止 IM 周期校验定时器并关闭 IM（2026-09-03 恢复）
    //
    if (Engine->IntegrityProtection) {
        ImShutdown(Engine->IntegrityProtection);
        Engine->IntegrityProtection = NULL;
    }

    //
    // 3. 停止 CP 周期验证定时器并关闭 CP — 2026-09-03 恢复
    //
    if (Engine->CallbackProtection) {
        CpShutdown(Engine->CallbackProtection);
        Engine->CallbackProtection = NULL;
    }

    //
    // 4. 停止 AD 周期检测定时器并释放 AD — 2026-09-03 恢复
    //
    if (Engine->AntiDebugProtection) {
        AdbShutdown(Engine->AntiDebugProtection);
        Engine->AntiDebugProtection = NULL;
    }

    //
    // 5. 关闭 AU（恢复 DriverUnload、解除驱动引用、释放保护器）— 2026-09-03 恢复
    //
    if (Engine->AntiUnloadProtection) {
        AuShutdown(Engine->AntiUnloadProtection);
        Engine->AntiUnloadProtection = NULL;
    }

    //
    // 5.1 关闭 RG — 2026-09-03 恢复
    //
    if (Engine->RegistryProtection) {
        RgpShutdown(Engine->RegistryProtection);
        Engine->RegistryProtection = NULL;
    }

    //
    // 6. 关闭 SHA-256 公共设施
    //
    WkdSha256Shutdown();

    //
    // 7. 清空模块会话指针并释放引擎主结构
    //
    if (g_spEngineSession == Engine) {
        g_spEngineSession = NULL;
    }
    ExFreePoolWithTag(Engine, WKD_SP_ENGINE_POOL_TAG);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] SelfProtectionEngine shut down\n");
}

/* ============================================================================
 * 外部异步入口（需要引擎 rundown 保护）
 * ============================================================================ */

/*++
    SpEngineUnloadPrepare - 受控卸载准备（ALPC 命令处理线程入口）

    内部获取引擎 rundown 后转调 AU 恢复 DriverObject->DriverUnload，
    使 Agent 可执行 sc stop 完成正常卸载。
    引擎实例取自模块会话指针 g_spEngineSession。
    运行环境: PASSIVE_LEVEL
--*/
_Use_decl_annotations_
NTSTATUS
SpEngineUnloadPrepare(
    VOID
    )
{
    PWKD_SELF_PROTECTION_ENGINE engine = g_spEngineSession;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    if (engine == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!ExAcquireRundownProtection(&engine->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    // 2026-09-03 AU 子模块恢复：受控卸载恢复 DriverUnload 转调。
    if (engine->AntiUnloadProtection != NULL) {
        AuShutdown(engine->AntiUnloadProtection);
        engine->AntiUnloadProtection = NULL;
        status = STATUS_SUCCESS;
    }

    ExReleaseRundownProtection(&engine->RundownRef);

    return status;
}

/* ============================================================================
 * 注册表自保护（RG）— 外部消费者与配置 API
 * ============================================================================ */

/*++
    SpEngineIsRegistryProcessExempt - 注册表自保护豁免判定回调（引擎注入 RG）

    由 SpInitializeRegistryProtection 注入，作为 WKD_RG_EXEMPT_CALLBACK。
    受保护进程（Pap 画像，PapProfile 非零，如主服务）对自身注册表键的修改
    不被 BLOCK——对齐 ShadowStrike 的 ShadowStrikeIsProcessProtected 豁免。
    2026-09-05：原经 AU 受保护进程表（AuIsProcessProtectedById）判定，该表
    已删除（恒空恒 FALSE），收敛为直接查 Pap 画像。
    运行环境: PASSIVE_LEVEL（CM 回调上下文）
--*/
static
BOOLEAN
SpEngineIsRegistryProcessExempt(
    _In_ HANDLE RequestorProcessId,
    _In_opt_ PVOID Context
    )
{
    PEPROCESS process = NULL;
    BOOLEAN toExempt = FALSE;

    UNREFERENCED_PARAMETER(Context);

    if (RequestorProcessId == NULL) {
        return FALSE;
    }

    /* 受保护判定 = Pap 画像（PapProfile 非零） */
    if (NT_SUCCESS(PsLookupProcessByProcessId(RequestorProcessId, &process))) {
        toExempt = PapIsProcessProtected(process);
        ObDereferenceObject(process);
    }

    return toExempt;
}

/*++
    SpEngineShouldBlockRegistryAccess - 注册表操作 BLOCK 判定（CM 回调消费者入口）

    由 Callbacks/RegistryCallback.c 的 CM 回调调用。内部获取引擎 rundown 后
    转调 RG（RgpShouldBlockRegistryAccess）完成豁免（受保护进程自改自键放行）、
    键前缀匹配、危险操作拦截与 0x5030 段上报。
    若引擎关闭中（rundown 获取失败）或 RG 未就绪，返回 FALSE 表示放行
    （尽力而为，不阻断系统注册表写）。
    运行环境: PASSIVE_LEVEL
--*/
_Use_decl_annotations_
BOOLEAN
SpEngineShouldBlockRegistryAccess(
    _In_ PCUNICODE_STRING KeyPath,
    _In_ REG_NOTIFY_CLASS Operation,
    _In_ HANDLE RequestorProcessId
    )
{
    PWKD_SELF_PROTECTION_ENGINE engine = g_spEngineSession;
    BOOLEAN shouldBlock = FALSE;

    if (KeyPath == NULL || engine == NULL) {
        return FALSE;
    }

    if (!ExAcquireRundownProtection(&engine->RundownRef)) {
        return FALSE;
    }

    // 2026-09-03 RG 子模块恢复：注册表 BLOCK 判定转调。
    if (engine->RegistryProtection != NULL) {
        shouldBlock = RgpShouldBlockRegistryAccess(
            engine->RegistryProtection,
            KeyPath,
            Operation,
            RequestorProcessId
            );
    }

    ExReleaseRundownProtection(&engine->RundownRef);

    return shouldBlock;
}

/*++
    SpEngineProtectRegistryKey - 保护一个注册表键/键前缀（配置入口）

    转调 RG（RgpProtectKey）。当前无外部调用者（预留 API，供后续 Agent
    策略推送受保护键）。运行环境: PASSIVE_LEVEL
--*/
_Use_decl_annotations_
NTSTATUS
SpEngineProtectRegistryKey(
    PWKD_SELF_PROTECTION_ENGINE Engine,
    PCWSTR KeyPath
    )
{
    PAGED_CODE();

    if (Engine == NULL || KeyPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    // 2026-09-03 RG 子模块恢复：按键保护转调。
    if (Engine->RegistryProtection == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }
    return RgpProtectKey(Engine->RegistryProtection, KeyPath);
}

/*++
    SpEngineUnprotectRegistryKey - 注销对一个注册表键/键前缀的保护（配置入口）

    转调 RG（RgpUnprotectKey）。运行环境: PASSIVE_LEVEL
--*/
_Use_decl_annotations_
VOID
SpEngineUnprotectRegistryKey(
    PWKD_SELF_PROTECTION_ENGINE Engine,
    PCWSTR KeyPath
    )
{
    PAGED_CODE();

    if (Engine == NULL || KeyPath == NULL) {
        return;
    }
    // 2026-09-03 RG 子模块恢复：取消按键保护转调。
    if (Engine->RegistryProtection == NULL) {
        return;
    }
    RgpUnprotectKey(Engine->RegistryProtection, KeyPath);
}
