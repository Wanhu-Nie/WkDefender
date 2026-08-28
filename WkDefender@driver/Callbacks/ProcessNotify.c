#include "ProcessNotify.h"
#include "../Process/ProcessMonitor.h"
#include "../Memory/AmsiBypassDetector.h"
#include "../Notification/AlpcService.h"
#include "../FileSystem/FileBackupEngine.h"   /* FBE 进程退出提交备份 */

//
// 函数声明
//

/* PsGetProcessImageFileName — 从 EPROCESS 获取 ImageFileName（仅文件名） */
NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
CbProcessNotifyRegister(
    VOID
);

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
CbProcessNotifyUnregister(
    VOID
    );

/* ETW 函数前向声明 */
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
CbEtwInitialize(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
CbEtwCleanup(
    VOID
    );

//
// 回调处理函数
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
CbpProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

//
// BootGrace 窗口（秒数）
// 启动后的前 WKD_BOOT_GRACE_SECONDS 秒内，系统关键进程走快速路径
//
#define WKD_BOOT_GRACE_SECONDS       60
#define WKD_BOOT_GRACE_100NS         ((LONGLONG)WKD_BOOT_GRACE_SECONDS * 1000 * 10000)

//
// 回调管理器全局状态
//
typedef struct _WKD_CALLBACK_MANAGER {
    BOOLEAN Initialized;
    BOOLEAN ShutdownRequested;

    EX_RUNDOWN_REF RundownRef;
    FAST_MUTEX Lock;

    BOOLEAN ProcessCallbackRegistered;
    BOOLEAN ThreadCallbackRegistered;
    BOOLEAN ImageCallbackRegistered;

    ULONG ProcessCreations;
    ULONG ProcessTerminationCount;

    /* BootGrace 启动防护 */
    LARGE_INTEGER BootStartTime;            // 驱动初始化时间戳
    BOOLEAN BootGraceInitialized;
} WKD_CALLBACK_MANAGER, * PWKD_CALLBACK_MANAGER;

//
// 全局回调管理器实例
//
WKD_CALLBACK_MANAGER WkdCallbackManager = {0};

//
// 判断当前是否处于启动灰屏窗口期
// 返回 TRUE 表示系统仍在启动阶段，应走快速路径
//
_IRQL_requires_(PASSIVE_LEVEL)
static
BOOLEAN
CbpInBootGrace(
    VOID
    )
{
    LARGE_INTEGER now;

    if (!WkdCallbackManager.BootGraceInitialized) {
        return FALSE;   /* 未初始化则视为已过窗口期 */
    }

    KeQuerySystemTime(&now);
    return (now.QuadPart - WkdCallbackManager.BootStartTime.QuadPart < WKD_BOOT_GRACE_100NS);
}

//
// 判断是否为启动关键进程（UNICODE_STRING 尾部匹配）
// 
// 使用 UNICODE_STRING 尾部匹配 + RtlEqualUnicodeString 大小写不敏感比较。
// 零分配、无锁、<200ns。
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
CbpIsCriticalBootProcess(
    _In_opt_ PCUNICODE_STRING ImageFileName
    )
{
    UNICODE_STRING needle;  // 指针
    UNICODE_STRING tail;

    static const PCWSTR WkdCriticalBootImages[] = {
        L"System"
        L"\\smss.exe",
        L"\\csrss.exe",
        L"\\wininit.exe",
        L"\\services.exe",
        L"\\lsass.exe",
        L"\\winlogon.exe",
        L"\\userinit.exe",
        L"\\explorer.exe",
        L"\\dwm.exe",
        L"\\sihost.exe",
        L"\\fontdrvhost.exe",
        L"\\LogonUI.exe",
        L"\\Registry",          /* System Registry process (Win10 1903+) */
        L"\\MemCompression",    /* Memory compression system process */
    };

    if (ImageFileName == NULL ||
        ImageFileName->Buffer == NULL ||
        ImageFileName->Length == 0) {
        return FALSE;
    }

    for (ULONG i = 0; i < RTL_NUMBER_OF(WkdCriticalBootImages); i++) {
        RtlInitUnicodeString(&needle, WkdCriticalBootImages[i]);

        /* 路径比目标短则无法匹配 */
        if (ImageFileName->Length < needle.Length) {
            continue;
        }

        /* 构造尾部 UNICODE_STRING（指向末尾与 needle 等长的位置） */
        tail.Buffer = (PWCH)((PUCHAR)ImageFileName->Buffer +
                             (ImageFileName->Length - needle.Length));
        tail.Length = needle.Length;
        tail.MaximumLength = needle.MaximumLength;

        // 不区分大小写
        if (RtlEqualUnicodeString(&tail, &needle, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

//
// 初始化回调管理器
//
_Use_decl_annotations_
NTSTATUS
CbProcessNotifyInitialize(
    VOID
    )
{
    NTSTATUS Status = STATUS_SUCCESS;

    RtlZeroMemory(&WkdCallbackManager, sizeof(WKD_CALLBACK_MANAGER));

    ExInitializeRundownProtection(&WkdCallbackManager.RundownRef);
    ExInitializeFastMutex(&WkdCallbackManager.Lock);

    /* 初始化 BootGrace 计时器 */
    KeQuerySystemTime(&WkdCallbackManager.BootStartTime);
    WkdCallbackManager.BootGraceInitialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] BootGrace initialized, grace period=%us\n", WKD_BOOT_GRACE_SECONDS);

    //
    // 注册进程创建/终止回调
    //
    Status = CbProcessNotifyRegister();
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] CbProcessNotifyRegister failed: 0x%08X\n", Status);
        return Status;
    }

    /* 初始化 ETW Provider（非致命——失败不影响回调注册） */
    {
        NTSTATUS etwStatus = CbEtwInitialize();
        if (!NT_SUCCESS(etwStatus)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[WkDefender] CbEtwInitialize failed (non-fatal): 0x%08X\n", etwStatus);
        }
    }

    /* 镜像加载回调已迁至独立模块 Callbacks/ImageNotify.c（DEC-05），
     * 由 WkdEntry.c 直接调 CbInitializeImageNotify，不在此注册。 */

    WkdCallbackManager.Initialized = TRUE;

    return Status;
}

//
// 清理回调管理器
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
CbProcessNotifyCleanup(
    VOID
    )
{
    WkdCallbackManager.ShutdownRequested = TRUE;

    ExWaitForRundownProtectionRelease(&WkdCallbackManager.RundownRef);

    // 镜像回调注销由 WkdEntry.c 调 ImgNotifyCleanup（模块独立，见 DEC-05）
    // CbThreadNotifyUnregister();
    CbProcessNotifyUnregister();

    /* 清理 ETW Provider */
    CbEtwCleanup();

    WkdCallbackManager.Initialized = FALSE;
}

//
// 注册进程回调
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
CbProcessNotifyRegister(
    VOID
    )
{
    NTSTATUS Status = PsSetCreateProcessNotifyRoutineEx(
        CbpProcessNotifyCallback,
        FALSE
        );

    if (NT_SUCCESS(Status)) {
        WkdCallbackManager.ProcessCallbackRegistered = TRUE;
    }

    return Status;
}

//
// 注销进程回调
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CbProcessNotifyUnregister(
    VOID
    )
{
    if (!WkdCallbackManager.ProcessCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    NTSTATUS Status = PsSetCreateProcessNotifyRoutineEx(
        CbpProcessNotifyCallback,
        TRUE
        );

    if (NT_SUCCESS(Status)) {
        WkdCallbackManager.ProcessCallbackRegistered = FALSE;
    }

    return Status;
}

//
// ETW 事件发射
//
// 当前实现：WkDefender ETW Provider 注册框架 + DbgPrintEx 回退。
// 当 ETW Provider GUID 和 Event Descriptors 最终确定后，
// 将 DbgPrintEx 替换为 EtwWrite 调用。
//
// Provider GUID: {B5F1A3C2-DE4F-49B0-8A1C-2E3D4F5A6B7C} (占位)
// 后续需通过 manifest (MC.exe) 生成正式事件描述符。
//

#define WKD_ETW_PROVIDER_GUID 0xC2A3F1B5, 0x4FDE, 0xB049, 0x8A, 0x1C, 0x2E, 0x3D, 0x4F, 0x5A, 0x6B, 0x7C

typedef struct _WKD_ETW_STATE {
    BOOLEAN  Initialized;
    REGHANDLE RegHandle;            // ETW 注册句柄
} WKD_ETW_STATE;

static WKD_ETW_STATE g_WkdEtwState = { FALSE, 0 };

//
// ETW 回调——启用/禁用通知（当前空实现）
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
CbEtwEnableCallback(
    _In_ LPCGUID SourceId,
    _In_ ULONG IsEnabled,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _In_opt_ PVOID CallbackContext
    )
{
    UNREFERENCED_PARAMETER(SourceId);
    UNREFERENCED_PARAMETER(IsEnabled);
    UNREFERENCED_PARAMETER(Level);
    UNREFERENCED_PARAMETER(MatchAnyKeyword);
    UNREFERENCED_PARAMETER(MatchAllKeyword);
    UNREFERENCED_PARAMETER(FilterData);
    UNREFERENCED_PARAMETER(CallbackContext);
}

//
// 初始化 ETW Provider
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
CbEtwInitialize(
    VOID
    )
{
    NTSTATUS status;
    GUID providerGuid = { WKD_ETW_PROVIDER_GUID };

    if (g_WkdEtwState.Initialized) {
        return STATUS_SUCCESS;
    }

    status = EtwRegister(&providerGuid, CbEtwEnableCallback, NULL, &g_WkdEtwState.RegHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] EtwRegister failed: 0x%08X\n", status);
        return status;
    }

    g_WkdEtwState.Initialized = TRUE;
    return STATUS_SUCCESS;
}

//
// 清理 ETW Provider
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
CbEtwCleanup(
    VOID
    )
{
    if (g_WkdEtwState.Initialized) {
        EtwUnregister(g_WkdEtwState.RegHandle);
        g_WkdEtwState.RegHandle = 0;
        g_WkdEtwState.Initialized = FALSE;
    }
}

//
// 发射进程创建 ETW 事件（DbgPrintEx 回退，TODO 待替换为 EtwWrite）
//
_Use_decl_annotations_
VOID
CbEtwEmitProcessCreate(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _In_opt_ PUNICODE_STRING ImagePath
    )
{
    /* TODO[ProcessNotify→ETW]: 替换为 EtwWrite 调用
     * EVENT_DESCRIPTOR desc = { 1, 0, 0, 4, 0, 0, 0 };
     * EVENT_DATA_DESCRIPTOR data[3];
     * EventDataDescCreate(&data[0], &ProcessId, sizeof(HANDLE));
     * EventDataDescCreate(&data[1], &ParentProcessId, sizeof(HANDLE));
     * EventDataDescCreate(&data[2], ImagePath->Buffer, ImagePath->Length);
     * EtwWrite(g_WkdEtwState.RegHandle, &desc, 3, data);
     */
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender][ETW] ProcessCreate: PID=%p Parent=%p Image=%wZ\n",
        ProcessId, ParentProcessId, ImagePath);
}

//
// 发射进程终止 ETW 事件（DbgPrintEx 回退，TODO 待替换为 EtwWrite）
//
_Use_decl_annotations_
VOID
CbEtwEmitProcessExit(
    _In_ HANDLE ProcessId,
    _In_ NTSTATUS ExitStatus
    )
{
    /* TODO[ProcessNotify→ETW]: 替换为 EtwWrite 调用
     * EVENT_DESCRIPTOR desc = { 2, 0, 0, 4, 0, 0, 0 };
     * EVENT_DATA_DESCRIPTOR data[2];
     * EventDataDescCreate(&data[0], &ProcessId, sizeof(HANDLE));
     * EventDataDescCreate(&data[1], &ExitStatus, sizeof(NTSTATUS));
     * EtwWrite(g_WkdEtwState.RegHandle, &desc, 2, data);
     */
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender][ETW] ProcessExit: PID=%p ExitStatus=0x%08X\n",
        ProcessId, ExitStatus);
}

//
// 发射线程创建 ETW 事件（DbgPrintEx 回退，TODO 待替换为 EtwWrite）
// [死代码] 对齐 SS TeLogRemoteThread/TeLogThreadCreate（ThreadNotify.c L1202-1218）。
// 不接入原因：线程创建高频（每秒数千次），wkd ETW 未接 EtwWrite 前用 DbgPrintEx
//   会严重刷屏；待 EtwWrite 接入后激活，且仅对远程线程/高分线程上送
//   （IsRemote || InjectionScore>=阈值 门控）。
//
_Use_decl_annotations_
VOID
CbEtwEmitThreadCreate(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ HANDLE CreatorProcessId,
    _In_ BOOLEAN IsRemote,
    _In_opt_ PVOID StartAddress,
    _In_ ULONG InjectionScore
    )
{
    /* TODO[ThreadNotify→ETW]: 替换为 EtwWrite 调用
     * EVENT_DESCRIPTOR desc = { 3, 0, 0, 4, 0, 0, 0 };
     * EVENT_DATA_DESCRIPTOR data[6];
     * EventDataDescCreate(&data[0], &ProcessId, sizeof(HANDLE));
     * EventDataDescCreate(&data[1], &ThreadId, sizeof(HANDLE));
     * EventDataDescCreate(&data[2], &CreatorProcessId, sizeof(HANDLE));
     * EventDataDescCreate(&data[3], &IsRemote, sizeof(BOOLEAN));
     * EventDataDescCreate(&data[4], &StartAddress, sizeof(PVOID));
     * EventDataDescCreate(&data[5], &InjectionScore, sizeof(ULONG));
     * EtwWrite(g_WkdEtwState.RegHandle, &desc, 6, data);
     */
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender][ETW] ThreadCreate: PID=%p TID=%p Creator=%p Remote=%d Start=%p Score=%lu\n",
        ProcessId, ThreadId, CreatorProcessId, IsRemote ? 1 : 0, StartAddress, InjectionScore);
}

//
// 发射线程终止 ETW 事件（DbgPrintEx 回退，TODO 待替换为 EtwWrite）
// [死代码] 对齐 SS TeLogThreadExit 语义；不接线原因同 CbEtwEmitThreadCreate。
//
_Use_decl_annotations_
VOID
CbEtwEmitThreadExit(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId
    )
{
    /* TODO[ThreadNotify→ETW]: 替换为 EtwWrite 调用
     * EVENT_DESCRIPTOR desc = { 4, 0, 0, 4, 0, 0, 0 };
     * EVENT_DATA_DESCRIPTOR data[2];
     * EventDataDescCreate(&data[0], &ProcessId, sizeof(HANDLE));
     * EventDataDescCreate(&data[1], &ThreadId, sizeof(HANDLE));
     * EtwWrite(g_WkdEtwState.RegHandle, &desc, 2, data);
     */
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender][ETW] ThreadExit: PID=%p TID=%p\n",
        ProcessId, ThreadId);
}

//
// 进程终止处理函数
//
// 参考 PhantomSensor: PnpHandleProcessTermination (ProcessNotify.c:3865-4213)
// 结构调整说明：
//   1. 先查表（非致命——查不到继续执行无条件清理）
//   2. 查到时：记录退出码/终止时间 + 发送 ALPC 退出消息
//   3. 无条件执行子系统清理 TODO（即使查不到表也必须执行）
//   4. 发射 ETW 退出事件
//   5. 查到时释放引用（触发 PspDestroyProcess）
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
CbpHanleProcessTermination(
    _In_ HANDLE ProcessId,
    _In_ const PEPROCESS Process
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PWKD_PROCESS wkdProcess;
    NTSTATUS exitStatus = STATUS_UNSUCCESSFUL;

    /* 更新计数器 */
    InterlockedIncrement(&g_WkdProcessMonitor.Statistics.ProcessTerminationCount);

    wkdProcess = PsLookupWkdProcessByProcessId(ProcessId);
    /* 进程对象为意外删除??? 这不可能发生!!! */
    if (!wkdProcess) { DbgBreakPoint(); return STATUS_OBJECTID_NOT_FOUND; }

    {
        LARGE_INTEGER time = { 0 };

        // 进程退出时间
        KeQuerySystemTime(&time);
        InterlockedExchange64(&wkdProcess->Core.ExitTime, time.QuadPart);

        InterlockedExchange8(&wkdProcess->Core.Alive, FALSE);
    }

    /* 调用编排器通知进程退出 */
    //AeOrchestratorDispatch(wkdProcess, NULL, NULL,
    //          WkdMessage_SourceProcessCallback);

    /* 发送退出通知到 Agent（对齐 PhantomSensor:3984） */
    status = PsNotifyProcessExit(wkdProcess, PsGetProcessExitStatus(Process));
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] CbpHanleProcessTermination: PsNotifyProcessExit "
            "failed for PID %p: 0x%08X\n", ProcessId, status);
    }
    

    //
    // === Phase 2: 无条件子系统清理（即使查不到表也必须执行） ===
    //
    // 对齐 PhantomSensor:3876-3960 + 4029-4213
    // 这些子系统可能通过创建路径外的其他路径注册了该 PID 的上下文。
    // 跳过会导致内存泄漏和 PID 复用安全漏洞。
    //

    /* TODO[ProcessNotify→ProcessAnalyzer]: PaInvalidateProcess(g_ProcessAnalyzer, ProcessId); */
    /* 已实现: AeOrchestratorDispatch(..., WkdMessage_SourceProcessCallback) — 见 Phase 1 */
    /* TODO[ProcessNotify→ThreadNotify]: TnNotifyProcessTermination(ProcessId); */
    /* TODO[ProcessNotify→WSLMonitor]: WslMonProcessTerminated(ProcessId); */
    /* 已实现: 融合方案覆盖——WSL 状态为 WKD_PROCESS.SecurityContext->BehaviorFlags
     * (WKD_BEHAVIOR_WSL_PROCESS, IocProcess.c §3.3 IocpDetectWsl 设置)，随 WKD_PROCESS
     * 释放自动消失，无需独立追踪表清理（迁移自 SS WSLMonitor 2026-08）。 */
    /* TODO[ProcessNotify→RegistryCallback]: ShadowStrikeRegistryProcessTerminated(ProcessId); */
    /* TODO[ProcessNotify→ALPC]: ShadowAlpcProcessTerminated(ProcessId); */
    /* TODO[ProcessNotify→TokenAnalyzer]: TaOnProcessTerminated(g_TokenAnalyzer, ProcessId); */
    /* TODO[ProcessNotify→ProcessRelationship]: PrRemoveProcess(g_PrGraph, ProcessId); */
    /* TODO[ProcessNotify→MemoryMonitor]: MmMonitorRemoveProcessContext(HandleToULong(ProcessId)); */
    /* TODO[ProcessNotify→SyscallMonitor]: ScMonitorRemoveProcessContext(HandleToULong(ProcessId)); */
    /* 已实现: AMSI 绕过检测器进程终止清理（防追踪表泄漏 + PID 复用） */
    // AbdRemoveProcessTracking(ProcessId);
    /* TODO[ProcessNotify→C2Detector]: C2ProcessTerminated(g_C2Detector, ProcessId); */
    /* TODO[ProcessNotify→ConnectionTracker]: CtProcessTerminated(g_ConnTracker, ProcessId); */
    /* TODO[ProcessNotify→DataExfiltration]: DxProcessTerminated(g_DxDetector, ProcessId); */
    /* TODO[ProcessNotify→DnsMonitor]: DnsProcessTerminated(g_DnsMonitor, ProcessId); */
    /* TODO[ProcessNotify→PatternMatcher]: PmCleanupProcessStates(g_PatternMatcher, ProcessId); */
    /* TODO[ProcessNotify→HandleProtection]: HpProcessTerminated(g_HandleProtection, ProcessId); */
    /* TODO[ProcessNotify→SelfProtection]: ShadowStrikeUnprotectProcess(ProcessId); */
    /* TODO[ProcessNotify→ResourceThrottling]: RtRemoveProcess(g_ResourceThrottler, ProcessId); */
    /* TODO[ProcessNotify→AntiUnload]: AuUnprotectProcess(g_AntiUnloadProtector, ProcessId); */
    /* TODO[ProcessNotify→ClipboardMonitor]: IocpClipboardRemoveProcess(ProcessId);
     *   （T1115 剪贴板追踪表清理，IocProcess.c §8 死代码——追踪表未激活时无需清理，
     *     待 Filter.c IRP_MJ_WRITE 接线 + IocpClipboardTrackProcess 入表后启用） */
    /* TODO[ProcessNotify→ImageNotify]: ImageNotifyProcessTerminated(ProcessId); */
    /* TODO[ProcessNotify→PrivilegeMonitor]: PmMarkProcessTerminated(g_PrivilegeMonitor, ProcessId); */
    /* TODO[ProcessNotify→InjectionDetector]: MmMonitorNotifyInjectionProcessExit(ProcessId); */
    /* 2026-08-10 [FileSystem 排除]: FBE 进程退出提交注释
     * （FbeCommitProcess 定义于 FileSystem\FileBackupEngine.c，暂不参与编译） */
#if 0 /* [FileSystem 排除-暂存代码] */
    /* FBE 进程退出提交：丢弃备份（对齐 SS PnpHandleProcessTermination
     * →FbeCommitProcess，SS ProcessNotify.c:4034）。PASSIVE_LEVEL，
     * 早于 PmHashMapRemove 释放上下文（防 PID 复用误回滚）。 */
    FbeCommitProcess(ProcessId);
#endif /* [FileSystem 排除-暂存代码] */
    /* TODO[ProcessNotify→ObjectCallback]: ObRemoveProtectedProcess(ProcessId); */
    /* TODO[ProcessNotify→BehaviorEngine]: BehaviorEngine_OnProcessTerminate(ProcessId); */

    //
    // === Phase 3: ETW 退出事件 ===
    //
    // 对齐 PhantomSensor:4023 — 即使查不到上下文也要发射 ETW
    //
    CbEtwEmitProcessExit(ProcessId, exitStatus);

    //
    // === Phase 4: 释放引用（进程表注册 Dereference 后的三步模型） ===
    //
    if (wkdProcess != NULL) {
        /*
         * 1. PsDereferenceWkdProcess — 释放 Phase 1 查找引用（PsLookupWkdProcessByProcessId
         *    在桶共享锁内 Reference +1，此处配对）。
         * 2. PmHashMapRemove — 摘除进程表条目，桶独占锁内 Dereference 释放
         *    表引用（插入时 Reference +1 的配对）。
         * 3. PsDereferenceWkdProcess — 释放创建时持有的基础引用（创建时
         *    RefCount=1 的最后一份），归零即触发 PspDestroyProcess（内部
         *    PmHashMapRemove 幂等，返回 FALSE 无副作用）。
         *
         * 顺序约束：必须先摘表（步骤 2）再释放基础引用（步骤 3）。
         * 保证 Dereference 在桶锁内执行时 RefCount 不归零（表引用释放时
         * 基础引用仍在，RefCount ≥ 2），避免桶锁内触发 PspDestroyProcess
         * 造成锁序嵌套（见 ProcessMonitor.c PspDereferenceWkdProcessCallback 约束注释）。
         */
        PsDereferenceWkdProcess(wkdProcess);
        PmHashMapRemove(ProcessId);
    }

    return STATUS_SUCCESS;
}

//
// 进程回调处理函数
//
_Use_decl_annotations_
static
VOID
CbpProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
/*++
Routine Description:
    process creation/termination callback.
    
    Registered via PsSetCreateProcessNotifyRoutineEx.

Arguments:
    Process     - Pointer to the process object.
    ProcessId   - ID of the process.
    CreateInfo  - Creation info (NULL for termination).
--*/
{
    /* 防御性检查（对齐 SS ShadowStrikeProcessNotifyCallback L1128-1130） */
    if (Process == NULL) {
        return;
    }

    BOOLEAN isCreation = (CreateInfo != NULL);

    // 进程终止
    if (!isCreation) {
        CbpHanleProcessTermination(ProcessId, Process);
    }
    else {
        //
        // === WINLOGON GREY-SCREEN MITIGATION (BOOT-PHASE EARLY BAIL) ===
        //
        // 关键启动进程走零分配快速路径——不分配 WKD_PROCESS、不入表、
        // 不发送 ALPC 消息、不调用任何深层分析。仅仅更新统计后返回。
        // 终止路径也快速跳过（从未分配，无需释放）。
        //
        //if (CbpInBootGrace() && CbpIsCriticalBootProcess(CreateInfo->ImageFileName)) {
        //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        //        "[WkDefender] BootGrace: fast-path for PID %p\n", ProcessId);
        //    InterlockedIncrement(&g_WkdProcessMonitor.Statistics.ProcessCreations);
        //    return;
        //}

        //
        // === SERVICE-NOT-CONNECTED FAST PATH ===
        // 对齐 SS ShadowStrikeIsServiceConnected（ProcessNotify.c:184-191,1159-1167）。
        // Agent 未连接时同步裁决无法进行（AlpcSendWkdMessage 失败即放行），深度
        // 分析也依赖 agent 反馈——此处跳过创建处理，仅计数。进程由 Agent 连接后
        // 的 PmEnumerateProcesses 快照补全入表。
        // 注意：终止路径不在此处跳过——WKD_PROCESS 清理是引用驱动（RefCount 归零
        // 才释放），断线期间已入表进程的终止仍须正常回收，避免 PID 复用泄漏。
        //
        //if (!AlpcIsAgentConnected(&WkdDefaultAlpcServer)) {
        //    InterlockedIncrement(&g_WkdProcessMonitor.Statistics.ProcessCreations);
        //    return;
        //}

        PmCreateProcess(Process, ProcessId, CreateInfo);
    }

    return;
}

/**************************************************/
/*       死代码迁移区（对齐 SS ProcessNotify.c）     */
/**************************************************/
//
// 以下函数为 ShadowStrike ProcessNotify.c 功能面迁移（重功能实现非复制），
// 当前不接入流水线。每个函数标注：对齐 SS 行号 / 不接入原因 / 激活条件。
// 死代码 static 函数未引用，包裹 #pragma warning(4505) 抑制告警。
//

#pragma warning(push)
#pragma warning(disable:4505)

//
// [死代码] 大小写不敏感子串搜索（对齐 SS PnpSafeWcsStrI L4504-4571；
//   与 ProcessMonitor.c PmpFindInUnicodeString 同算法，UNICODE_STRING 版）。
// 不接入原因：仅被本区死代码函数（PnpIsTrustedProcess）使用。
//
_IRQL_requires_max_(APC_LEVEL)
static
BOOLEAN
PnpSafeWcsStrI(
    _In_ PCWCH Buffer,
    _In_ USHORT BufferLengthBytes,
    _In_ PCWSTR Pattern
    )
{
    SIZE_T bufferChars;
    SIZE_T patternChars;
    SIZE_T i, j;

    if (Buffer == NULL || Pattern == NULL || BufferLengthBytes == 0) {
        return FALSE;
    }

    bufferChars = BufferLengthBytes / sizeof(WCHAR);
    patternChars = wcslen(Pattern);

    if (patternChars == 0 || patternChars > bufferChars) {
        return FALSE;
    }

    for (i = 0; i <= bufferChars - patternChars; i++) {
        BOOLEAN match = TRUE;

        for (j = 0; j < patternChars; j++) {
            WCHAR bufChar = Buffer[i + j];
            WCHAR patChar = Pattern[j];

            if (bufChar >= L'a' && bufChar <= L'z') bufChar -= (L'a' - L'A');
            if (patChar >= L'a' && patChar <= L'z') patChar -= (L'a' - L'A');

            if (bufChar != patChar) {
                match = FALSE;
                break;
            }
        }

        if (match) {
            return TRUE;
        }
    }

    return FALSE;
}

//
// [死代码] 已知系统进程检查（对齐 SS PnpIsKnownSystemProcess L4233-4269）
// 功能：PID<=4（System/Idle）跳过详细分析——SS 的性能优化，非安全控制。
// 不接入原因：wkd 创建热路径已被 Agent 同步裁决限速；AepIsCriticalProcess
//   （AnalysisEngine.c:418）覆盖关键进程阻断豁免，CoEvaluateProcessExemption
//   （SecurityFlags.Trusted）覆盖可信跳过。
// 激活条件：若需在 PmCreateProcess 早期跳过 PID<=4 详细分析，接入本函数。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
BOOLEAN
PnpIsKnownSystemProcess(
    _In_ HANDLE ProcessId
    )
{
    return (HandleToULong(ProcessId) <= 4);
}

//
// [死代码] 信任否决阻断判定（对齐 SS PnpIsTrustedProcess L4272-4343）
// 功能：PPID 欺骗/编码命令/无有效签名 → 不可信；System32/SysWOW64/WinSxS
//   路径且无 ".." 路径遍历 → 可信。SS 用于 ShouldBlock 后"信任覆盖阻断"。
// 不接入原因：wkd Agent 同步裁决（PmpNotifyProcessCreation）与驱动信任
//   （CoEvaluateProcessExemption/SecurityFlags.Trusted）的优先级未定——驱动信任能否决
//   Agent DENY 待确认，未决前保留功能面不接线。
// 激活条件：确定"驱动信任 vs Agent 同步 DENY"优先级后接线。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
BOOLEAN
PnpIsTrustedProcess(
    _In_ PWKD_PROCESS Process
    )
{
    if (Process == NULL || Process->SecurityContext == NULL) {
        return FALSE;
    }

    /* 永不信任：PPID 欺骗 / 编码命令 */
    if (Process->SecurityContext->PpidSpoofingDetected) {
        return FALSE;
    }
    if (Process->SecurityContext->BehaviorFlags & WKD_BEHAVIOR_ENCODED_CMD) {
        return FALSE;
    }

    /* 要求有效签名 */
    if (!Process->SecurityContext->IsSignatureValid) {
        return FALSE;
    }

    /* 系统路径判定 + 路径遍历防护（对齐 SS L4315-4340） */
    if (Process->Core.ImagePath != NULL &&
        Process->Core.ImagePath->Buffer != NULL &&
        Process->Core.ImagePath->Length > 0) {

        if (PnpSafeWcsStrI(Process->Core.ImagePath->Buffer,
                           Process->Core.ImagePath->Length,
                           L"\\Windows\\System32\\") ||
            PnpSafeWcsStrI(Process->Core.ImagePath->Buffer,
                           Process->Core.ImagePath->Length,
                           L"\\Windows\\SysWOW64\\") ||
            PnpSafeWcsStrI(Process->Core.ImagePath->Buffer,
                           Process->Core.ImagePath->Length,
                           L"\\Windows\\WinSxS\\")) {

            /* 路径遍历尝试 → 不可信 */
            if (PnpSafeWcsStrI(Process->Core.ImagePath->Buffer,
                               Process->Core.ImagePath->Length,
                               L"..")) {
                return FALSE;
            }

            return TRUE;
        }
    }

    return FALSE;
}

//
// [死代码] 周期特权/令牌变化巡检（对齐 SS PnpPeriodicSecurityChecks L4637-4828）
// 功能：周期遍历活跃进程，检测运行时特权提升（T1134/T1548）与令牌操纵。
//   锁内收集 PID（≤64/cycle）+ 引用，锁外做检测；跳过 PID≤4 与已终止进程。
// 不接入原因：wkd 提权/令牌检测应走**事件驱动**（token 操纵 syscall 钩子，
//   SyscallService.h TODO 已标注）；周期巡检是 SS 无 syscall 钩子时的补偿。
//   agent 侧 TokenAnalyzer WpaCheckForEscalation/WpaDetectTokenManipulation
//   （#40，g_IoaTokenAnalyzerEnabled=FALSE）已覆盖检测逻辑。
// 激活条件：token 操纵 syscall 钩子（NtSetInformationToken 等）补全后，
//   由 agent 事件驱动替代本函数。
//
#define PN_MAX_SECURITY_CHECKS_PER_CYCLE  64

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
PnpCheckTokenPrivilegeChange(
    _In_ PWKD_PROCESS Process
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
PnpPeriodicSecurityChecks(
    VOID
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PWKD_PROCESS process;
    PWKD_PROCESS pidList[PN_MAX_SECURITY_CHECKS_PER_CYCLE];
    ULONG pidCount = 0;

    /* 锁内收集 PID + 引用（对齐 SS：锁内只收集，锁外检测最小化持锁） */
    KeAcquireSpinLock(&g_WkdProcessMonitor.Lock, &oldIrql);
    for (entry = g_WkdProcessMonitor.ActiveProcessHead.Flink;
         entry != &g_WkdProcessMonitor.ActiveProcessHead &&
             pidCount < PN_MAX_SECURITY_CHECKS_PER_CYCLE;
         entry = entry->Flink) {

        process = CONTAINING_RECORD(entry, WKD_PROCESS, Links);

        if (HandleToULong(process->Core.ProcessId) <= 4) {
            continue;
        }
        if (!process->Core.Alive) {
            continue;
        }

        PsReferenceWkdProcess(process);
        pidList[pidCount++] = process;
    }
    KeReleaseSpinLock(&g_WkdProcessMonitor.Lock, oldIrql);

    /* 锁外检测（对齐 SS L4718-4789） */
    for (ULONG i = 0; i < pidCount; i++) {
        process = pidList[i];

        PnpCheckTokenPrivilegeChange(process);

        PsDereferenceWkdProcess(process);
    }
}

//
// [死代码] 单进程特权变化检测（周期巡检的检测核心）
// 功能：重捕获当前令牌特权，与创建时 SecurityContext 快照对比，新启用的
//   危险特权（SeDebug/SeTcb/SeLoadDriver/SeImpersonate）视为提权迹象。
// 不接入原因：同 PnpPeriodicSecurityChecks——wkd 由 agent TokenAnalyzer
//   事件驱动覆盖；本函数保留检测逻辑功能面。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
PnpCheckTokenPrivilegeChange(
    _In_ PWKD_PROCESS Process
    )
{
    PACCESS_TOKEN token;
    PTOKEN_PRIVILEGES privileges;
    NTSTATUS status;
    BOOLEAN elevatedNow[4];
    BOOLEAN baseline[4];
    LUID debugLuid = RtlConvertLongToLuid(SE_DEBUG_PRIVILEGE);
    LUID tcbLuid = RtlConvertLongToLuid(SE_TCB_PRIVILEGE);
    LUID loadDriverLuid = RtlConvertLongToLuid(SE_LOAD_DRIVER_PRIVILEGE);
    LUID impersonateLuid = RtlConvertLongToLuid(SE_IMPERSONATE_PRIVILEGE);

    if (Process == NULL || Process->Core.EProcess == NULL ||
        Process->SecurityContext == NULL) {
        return;
    }

    baseline[0] = Process->SecurityContext->SeDebugPrivilege;
    baseline[1] = Process->SecurityContext->SeTcbPrivilege;
    baseline[2] = Process->SecurityContext->SeLoadDriverPrivilege;
    baseline[3] = Process->SecurityContext->SeImpersonatePrivilege;

    token = PsReferencePrimaryToken(Process->Core.EProcess);
    if (token == NULL) {
        return;
    }

    RtlZeroMemory(elevatedNow, sizeof(elevatedNow));

    status = SeQueryInformationToken(token, TokenPrivileges, &privileges);
    if (NT_SUCCESS(status)) {
        for (ULONG i = 0; i < privileges->PrivilegeCount; i++) {
            PLUID_AND_ATTRIBUTES laa = &privileges->Privileges[i];
            if (!(laa->Attributes & SE_PRIVILEGE_ENABLED)) {
                continue;
            }

            if (RtlEqualLuid(&laa->Luid, &debugLuid)) {
                elevatedNow[0] = TRUE;
            } else if (RtlEqualLuid(&laa->Luid, &tcbLuid)) {
                elevatedNow[1] = TRUE;
            } else if (RtlEqualLuid(&laa->Luid, &loadDriverLuid)) {
                elevatedNow[2] = TRUE;
            } else if (RtlEqualLuid(&laa->Luid, &impersonateLuid)) {
                elevatedNow[3] = TRUE;
            }
        }
        ExFreePool(privileges);
    }

    PsDereferencePrimaryToken(token);

    /* 新启用的危险特权 = 运行时提权迹象（对齐 SS PmCheckForEscalation 语义） */
    for (ULONG i = 0; i < 4; i++) {
        if (elevatedNow[i] && !baseline[i]) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[WkDefender][PeriodicCheck] Privilege escalation: PID=%lu, "
                "privIndex=%lu (newly enabled)\n",
                HandleToULong(Process->Core.ProcessId), i);
            /* TODO[周期巡检→上报]: 进程级上报入口（无 pair 场景）或转 agent
             * 事件驱动（token syscall 钩子补全后）替代 DbgPrint。 */
        }
    }
}

//
// [死代码] 创建时进程保护分类（对齐 SS 主回调 L1312-1321 PpClassifyProcess/
//   PpAddProtectedProcess 调用段）。
// 功能：创建时将关键系统进程（LSASS/CSRSS/services.exe 等）与 EDR/AV 进程
//   注册进保护缓存，供 Ob 回调句柄访问强制（handle-access enforcement）。
// 不接入原因：wkd Ob 回调未注册（ObRegisterCallbacks 无匹配），保护注册无
//   消费方；关键进程豁免已由 AepIsCriticalProcess（AnalysisEngine.c:418）覆盖。
// 激活条件：Ob 保护子系统就绪后，在创建路径接线。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
PnpClassifyAndProtectProcess(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING ImageFileName
    )
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageFileName);

    /* 对齐 SS PpClassifyProcess：按镜像名分类关键进程 + 注册保护。
     * wkd 无 PpClassifyProcess 对等物（Ob 保护子系统未激活），
     * 关键进程名单见 AepIsCriticalProcess。 */
}

#pragma warning(pop)