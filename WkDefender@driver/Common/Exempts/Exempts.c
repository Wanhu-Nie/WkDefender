/**************************************************/
/*  WkDefender — 排除子系统门面/管理引擎             */
/*                                                   */
/*  本文件是 Exempts 子系统的唯一对外接口。持有全局   */
/*  子系统结构体 EXEMPT_ENGINE WkdExempts（集中记录   */
/*  各组件状态 + 全局 rundown 保护 + 清理线程），     */
/*  编排 CoEvaluateProcessExemption 统一判定，转发规则管理门面， */
/*  恢复关闭清理链。                                 */
/*                                                   */
/*  组件职责:                                        */
/*    ExemptsManager.c — 纯存储仓库（四表规则）      */
/*    ExemptPid.c      — PID 信任状态 + 判定逻辑     */
/*    ExemptPath.c     — 无状态路径算法              */
/**************************************************/

#include "ExemptsInternal.h"
#include "../../Process/ProcessMonitor.h"   /* WKD_PROCESS / WKD_SECURITY_CONTEXT */
#include "../Constants.h"                   /* WkdIntegrityEdr */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CoInitializeExempts)
#endif

/**************************************************/
/*                  全局子系统结构体                */
/**************************************************/

/*
 * 排除子系统唯一全局实例。各组件上下文内嵌于此，
 * 组件函数均以 PEXEMPT_ENGINE 为首参访问。
 */
static EXEMPT_ENGINE WkdExempts;

/**************************************************/
/*              清理线程（门面自建 60s 周期）        */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
ExemptpCleanupThread(
    _In_ PVOID Context
    )
/*++
Routine Description:
    门面自建独立过期清理线程：每 60s 调用一次 ExemptsMgrCleanupExpired。
    职责单一，与 AnalysisEngine 维护线程无逻辑关联。

Arguments:
    Context - PEXEMPT_ENGINE（门面全局结构体）。

Return Value:
    无。
--*/
{
    PEXEMPT_ENGINE system = (PEXEMPT_ENGINE)Context;
    LARGE_INTEGER interval;
    NTSTATUS waitStatus;

    interval.QuadPart = -((LONGLONG)EXEMPT_CLEANUP_INTERVAL_MS * 10000LL);

    for (;;) {
        waitStatus = KeWaitForSingleObject(
            &system->CleanupStopEvent,
            Executive,
            KernelMode,
            FALSE,
            &interval);

        if (waitStatus == STATUS_WAIT_0) {
            break;  /* 停止信号 → 退出线程 */
        }

        ExemptsMgrCleanupExpired(system);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
ExemptpStartCleanupThread(
    VOID
    )
{
    NTSTATUS status;

    status = PsCreateSystemThread(
        &WkdExempts.CleanupThread,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        ExemptpCleanupThread,
        &WkdExempts);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Exempts cleanup thread creation failed: 0x%X\n", status);
        WkdExempts.CleanupThread = NULL;
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
ExemptpStopCleanupThread(
    VOID
    )
{
    if (WkdExempts.CleanupThread != NULL) {
        KeSetEvent(&WkdExempts.CleanupStopEvent, IO_NO_INCREMENT, FALSE);
        KeWaitForSingleObject(
            WkdExempts.CleanupThread,
            Executive,
            KernelMode,
            FALSE,
            NULL);
        ZwClose(WkdExempts.CleanupThread);
        WkdExempts.CleanupThread = NULL;
    }
}

/**************************************************/
/*                  生命周期                        */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
CoInitializeExempts(
    VOID
    )
/*++
Routine Description:
    初始化排除子系统：三段清零组件上下文 → 全局 rundown → 事件 →
    Manager → Pid → Hash 依次初始化（失败逆序回滚）→ 加载内建默认
    → 启动清理线程。

Arguments:
    无。

Return Value:
    STATUS_SUCCESS / 任一步失败状态（已回滚前序初始化）。
--*/
{
    NTSTATUS status;
    LONG previousState;

    PAGED_CODE();

    previousState = InterlockedCompareExchange(
        &WkdExempts.State,
        EXEMPT_STATE_INITIALIZING,
        EXEMPT_STATE_UNINITIALIZED);

    if (previousState == EXEMPT_STATE_READY) {
        return STATUS_ALREADY_INITIALIZED;
    }

    if (previousState != EXEMPT_STATE_UNINITIALIZED) {
        return STATUS_UNSUCCESSFUL;
    }

    /*
     * 分段清零组件上下文（Manager/Pid），消除对结构体字段顺序的依赖。
     * State/Enabled/RundownRef 位于结构体头部，不在此清零范围。
     */
    RtlZeroMemory(&WkdExempts.Manager, sizeof(EXEMPT_MANAGER));
    RtlZeroMemory(&WkdExempts.PidContext, sizeof(EXEMPT_PID_CONTEXT));

    ExInitializeRundownProtection(&WkdExempts.RundownRef);
    KeInitializeEvent(&WkdExempts.CleanupStopEvent, NotificationEvent, FALSE);
    WkdExempts.CleanupThread = NULL;

    status = CopInitializeExemptMgr(&WkdExempts);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = CopInitializeExemptPid(&WkdExempts);
    if (!NT_SUCCESS(status)) {
        ExemptsMgrShutdown(&WkdExempts);
        goto Cleanup;
    }

    WkdExempts.Enabled = TRUE;

    MemoryBarrier();
    InterlockedExchange(&WkdExempts.State, EXEMPT_STATE_READY);

    CoLoadDefaultExempts(&WkdExempts);
    ExemptpStartCleanupThread();

    return STATUS_SUCCESS;

Cleanup:
    InterlockedExchange(&WkdExempts.State, EXEMPT_STATE_UNINITIALIZED);
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptsCleanup(
    VOID
    )
/*++
Routine Description:
     关闭排除子系统（逆序）：置 SHUTTING_DOWN → 停清理线程 →
     排空全局 rundown → Pid/Manager 逆序 Shutdown → 回 UNINITIALIZED。
     顺序保证：先停线程、再排空 rundown，才释放位图/规则条目，
     闭合 PID 引擎关停 UAF。

Arguments:
    无。

Return Value:
    无。
--*/
{
    LONG previousState;

    PAGED_CODE();

    previousState = InterlockedCompareExchange(
        &WkdExempts.State,
        EXEMPT_STATE_SHUTTING_DOWN,
        EXEMPT_STATE_READY);

    if (previousState != EXEMPT_STATE_READY) {
        return;
    }

    WkdExempts.Enabled = FALSE;

    ExemptpStopCleanupThread();

    /* 排空所有在途查询（IsPathExcluded/IsProcessExcluded/IsProcessTrusted） */
    ExWaitForRundownProtectionRelease(&WkdExempts.RundownRef);

    ExemptPidShutdown(&WkdExempts);
    ExemptsMgrShutdown(&WkdExempts);

    InterlockedExchange(&WkdExempts.State, EXEMPT_STATE_UNINITIALIZED);
}

/**************************************************/
/*                  排除评估                        */
/**************************************************/

_Use_decl_annotations_
EXEMPT_VERDICT
CoEvaluateProcessExemption(
    _In_ PWKD_PROCESS WkdProcess,
    _Out_opt_ PEXEMPT_REASON Reason
    )
/*++
Routine Description:
     统一排除入口判定（对齐 SS PnpIsTrustedProcess）。判定顺序：
       0. EDR 自身组件（IntegrityLevel==WkdIntegrityEdr）→ Trusted
       1. 路径排除（系统服务精确路径）+ 进程名排除 → Trusted
       2. TrustedPID 位图（CoExemptCreatedProcess 已播种）→ Trusted
       3. 皆空 → NotTrusted
     步骤 1-2 整体持全局 rundown（组件查询内部可重入获取）。

Arguments:
    WkdProcess - 进程对象（进程创建上下文已建立）。
    Reason     - 可选输出命中原因。

Return Value:
    ExemptVerdict_Trusted / ExemptVerdict_NotTrusted。
--*/
{
    EXEMPT_REASON retReason = ExemptReason_None;

    if (!WkdProcess) {
        return ExemptVerdict_NotTrusted;
    }
    if (Reason) {
        *Reason = ExemptReason_None;
    }

    /*
     * 步骤 0: EDR 自身组件完全可信（自保护前提）。
     */
    if (WkdProcess->SecurityContext != NULL &&
        WkdProcess->SecurityContext->IntegrityLevel == WkdIntegrityEdr) {
        if (Reason) {
            *Reason = ExemptReason_SystemExclusion;
        }
        return ExemptVerdict_Trusted;
    }

    /*
     * 步骤 1-2 需访问组件状态（位图/规则表），持全局 rundown 防关停竞态。
     * 子系统未就绪（初始化失败/已关闭）时直接判定为不可信，
     * 避免触碰未初始化的 rundown 保护。
     */
    if (!ExAcquireRundownProtection(&WkdExempts.RundownRef)) {
        return ExemptVerdict_NotTrusted;
    }

    /*
     * 步骤 1: 路径排除（系统服务精确路径）+ 进程名排除。
     */
    if (WkdProcess->Core.ImagePath != NULL &&
        WkdProcess->Core.ImagePath->Buffer != NULL &&
        WkdProcess->Core.ImagePath->Length > 0) {

        /*  ImagePath已经经过标准化为Dos风格且小写*/
        if (CopCheckPathExempted(&WkdExempts, WkdProcess->Core.ImagePath, NULL)) {
            retReason = ExemptReason_PathExclusion;
            goto Cleanup;
        }

        {
            UNICODE_STRING basename = { 0 };
            if (NT_SUCCESS(CoGetBasenameFromPath(WkdProcess->Core.ImagePath, &basename)) &&
                CopCheckProcessExemptedByIdOrName(&WkdExempts, WkdProcess->Core.ProcessId, &basename)) {
                retReason = ExemptReason_ProcessNameMatch;
                goto Cleanup;
            }
        }
    }

    /*
     * 步骤 2: TrustedPID 位图（进程创建回调 CoExemptCreatedProcess 已播种）。
     */
    if (ExemptPidIsTrusted(&WkdExempts, WkdProcess->Core.ProcessId)) {
        retReason = ExemptReason_PidExclusion;
        goto Cleanup;
    }

    /* 无任何匹配项 */
    ExReleaseRundownProtection(&WkdExempts.RundownRef);
    return ExemptVerdict_NotTrusted;

Cleanup:
    if (Reason) *Reason = retReason;
    ExReleaseRundownProtection(&WkdExempts.RundownRef);
    return ExemptVerdict_Trusted;
}

/**************************************************/
/*                  进程生命周期                    */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
CoExemptCreatedProcess(
    _In_ HANDLE ProcessId,
    _In_opt_ HANDLE ParentProcessId,
    _In_opt_ PCUNICODE_STRING ImagePath,
    _Out_ PBOOLEAN Exempt
    )
/*++
Routine Description:
    进程创建播种：判定路径/进程名/父继承排除，命中写可信位图。
    被 ProcessMonitor 进程创建回调调用。

Arguments:
    ProcessId       - 新进程 ID。
    ParentProcessId - 父进程 ID（可选）。
    ImagePath       - 镜像路径（可选），必须经过标准化为Dos风格且小写。
    Exempt          - TRUE 进程被排除（可信）

Return Value:
    NTSTATUS
--*/
{
    if (!ProcessId || !Exempt) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&WkdExempts.RundownRef)) {
        return STATUS_REQUEST_ABORTED;
    }

    *Exempt = CopExemptCreatedProcessInternal(&WkdExempts, ProcessId, ParentProcessId, ImagePath);

    ExReleaseRundownProtection(&WkdExempts.RundownRef);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptsOnProcessTerminate(
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    进程终止通知：清理 PID 可信集 + 回收 PID 规则表 TTL=0 条目。
    被 ProcessMonitor 进程销毁回调调用。

Arguments:
    ProcessId - 终止进程 ID。

Return Value:
    无。
--*/
{
    ExemptPidOnProcessTerminate(&WkdExempts, ProcessId);
    ExemptsMgrReapPidOnExit(&WkdExempts, ProcessId);
}

/**************************************************/
/*                  热路径查询                     */
/**************************************************/

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ExemptsIsProcessTrusted(
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    热路径 O(1) 可信查询（门面转发）。持全局 rundown 保护后
    调 ExemptPidIsTrusted（低 PID 位图无锁原子读 / 高 PID 哈希集锁读）。
    被 Filter/ObjectNotify/ThreadNotify/SyscallHijack 直调，签名不变。

Arguments:
    ProcessId - 进程 ID。

Return Value:
    TRUE 进程可信（排除）。
--*/
{
    BOOLEAN trusted = FALSE;

    /*
     * 子系统未就绪（初始化失败/已关闭）时返回 FALSE，
     * 避免触碰未初始化的 rundown 保护。
     */
    if (ReadAcquire(&WkdExempts.State) != EXEMPT_STATE_READY) {
        return FALSE;
    }

    if (!ExAcquireRundownProtection(&WkdExempts.RundownRef)) {
        return FALSE;
    }

    trusted = ExemptPidIsTrusted(&WkdExempts, ProcessId);

    ExReleaseRundownProtection(&WkdExempts.RundownRef);

    return trusted;
}

/**************************************************/
/*              规则管理门面（转发 Manager）         */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ExemptsAddPathExclusion(
    _In_ PCUNICODE_STRING Path,
    _In_ UINT8 Flags,
    _In_ ULONG TTLSeconds
    )
/*++
Routine Description:
    添加路径排除（门面转发 CopAddExemptedPath）。

Arguments:
    Path       - 排除路径。
    Flags      - EXEMPT_FLAG_*。
    TTLSeconds - 临时排除有效期（0=永不过期）。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER / STATUS_NAME_TOO_LONG /
    STATUS_INSUFFICIENT_RESOURCES / STATUS_OBJECT_NAME_COLLISION。
--*/
{
    return CopAddExemptedPath(&WkdExempts, Path, Flags, TTLSeconds);
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExemptsRemovePathExclusion(
    _In_ PCUNICODE_STRING Path
    )
/*++
Routine Description:
    移除路径排除（门面转发 ExemptsMgrRemovePathExclusion）。

Arguments:
    Path - 排除路径。

Return Value:
    TRUE 已移除。
--*/
{
    return ExemptsMgrRemovePathExclusion(&WkdExempts, Path);
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ExemptsAddExtensionExclusion(
    _In_ PCUNICODE_STRING Extension,
    _In_ UINT8 Flags
    )
/*++
Routine Description:
    添加扩展名排除（门面转发 ExemptsMgrAddExtensionExclusion）。

Arguments:
    Extension - 扩展名（不含点）。
    Flags     - EXEMPT_FLAG_*。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER / STATUS_NAME_TOO_LONG /
    STATUS_INSUFFICIENT_RESOURCES / STATUS_OBJECT_NAME_COLLISION。
--*/
{
    return ExemptsMgrAddExtensionExclusion(&WkdExempts, Extension, Flags);
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExemptsRemoveExtensionExclusion(
    _In_ PCUNICODE_STRING Extension
    )
/*++
Routine Description:
    移除扩展名排除（门面转发 ExemptsMgrRemoveExtensionExclusion）。

Arguments:
    Extension - 扩展名。

Return Value:
    TRUE 已移除。
--*/
{
    return ExemptsMgrRemoveExtensionExclusion(&WkdExempts, Extension);
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ExemptsAddProcessExclusion(
    _In_ PCUNICODE_STRING ProcessName,
    _In_ UINT8 Flags
    )
/*++
Routine Description:
    添加进程名排除（门面转发 ExemptsMgrAddProcessExclusion）。

Arguments:
    ProcessName - 进程名。
    Flags       - EXEMPT_FLAG_*。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER / STATUS_NAME_TOO_LONG /
    STATUS_INSUFFICIENT_RESOURCES / STATUS_OBJECT_NAME_COLLISION。
--*/
{
    return ExemptsMgrAddProcessExclusion(&WkdExempts, ProcessName, Flags);
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExemptsRemoveProcessExclusion(
    _In_ PCUNICODE_STRING ProcessName
    )
/*++
Routine Description:
    移除进程名排除（门面转发 ExemptsMgrRemoveProcessExclusion）。

Arguments:
    ProcessName - 进程名。

Return Value:
    TRUE 已移除。
--*/
{
    return ExemptsMgrRemoveProcessExclusion(&WkdExempts, ProcessName);
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ExemptsAddPidExclusion(
    _In_ HANDLE ProcessId,
    _In_opt_ ULONG TTLSeconds
    )
/*++
Routine Description:
    添加 PID 排除（门面转发 ExemptsMgrAddPidExclusion + 同步播种位图）。

Arguments:
    ProcessId   - 进程 ID。
    TTLSeconds  - 有效期（0=进程退出前有效）。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER / STATUS_INSUFFICIENT_RESOURCES。
--*/
{
    NTSTATUS status;

    status = ExemptsMgrAddPidExclusion(&WkdExempts, ProcessId, TTLSeconds);

    /*
     * 同步播种热路径位图：修复"仅 ALPC PID 规则时热路径
     * ExemptsIsProcessTrusted 不信任该 PID"的缺口。
     */
    if (NT_SUCCESS(status)) {
        ExemptPidMarkTrusted(&WkdExempts, ProcessId);
    }

    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExemptsRemovePidExclusion(
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    移除 PID 排除（门面转发 ExemptsMgrRemovePidExclusion）。

Arguments:
    ProcessId - 进程 ID。

Return Value:
    TRUE 已移除。
--*/
{
    return ExemptsMgrRemovePidExclusion(&WkdExempts, ProcessId);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptsClearExclusions(
    _In_ EXEMPT_RULE_TYPE Type
    )
/*++
Routine Description:
    按类型清空排除规则（门面转发 ExemptsMgrClearExclusions）。

Arguments:
    Type - EXEMPT_RULE_TYPE。

Return Value:
    无。
--*/
{
    ExemptsMgrClearExclusions(&WkdExempts, Type);
}
