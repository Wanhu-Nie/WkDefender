/*++
    SelfProtection/AntiDebug.c - 防调试检测与告警（AntiDebug, AD）子组件实现

    Detect-and-alert：检测调试/虚拟化/内存转储配置并上报，不阻止调试器附加。

    架构对齐（自防护引擎铁律）:
        - 不持有 rundown / 生命周期标志，生命周期由引擎编排。
        - 周期检测用 Common/PeriodicTimer.h Thread 模式（PASSIVE_LEVEL 回调）。
        - 事件内部节点挂 EventList（EX_PUSH_LOCK 保护），对外返回值类型快照。
        - 上报经 WkdReportSelfProtectionEvent（PASSIVE_LEVEL，内部做 IRQL 门控）。

    周期检测范围（系统线程上下文为 PID 4，用户调试器检测无效）:
        - 内核调试器 / Hypervisor / 驱动验证器 / 完整内存转储配置
    用户态调试器检测：由 AdbCheckForDebugger 在用户态服务进程上下文中主动查询。

    Copyright (c) WkDefender Team
--*/

#include "AntiDebug.h"
#include "SelfProtectionCompat.h"
#include "../Common/PeriodicTimer.h"
#include "../Common/ExportParser.h"
#include <ntstrsafe.h>
#include <intrin.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SpInitializeAntiDebugProtection)
#pragma alloc_text(PAGE, SpStartPeriodicAntiDebugProtection)
#endif



/* ============================================================================
 * WDK KERNEL-MODE MISSING DECLARATIONS
 * ============================================================================ */

NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
    );

#ifndef ProcessDebugPort
#define ProcessDebugPort 7
#endif

// ZwQueryInformationProcess 原型与函数指针统一由 Common/ExportParser.h 提供
// （pfnZwQueryInformationProcess）。

/* ============================================================================
 * INTERNAL TYPES
 * ============================================================================ */

//
// 保护器上下文（不透明句柄定义，tag 与 AntiDebug.h 前向声明一致）
//
typedef struct _WKD_ANTIDEBUG_PROTECTION {
    //
    // 周期检测（Thread 模式，PASSIVE_LEVEL 回调）
    //
    WKD_PERIODIC_TIMER  CheckTimer;

    //
    // 事件链表（EventLock 保护）
    //
    LIST_ENTRY          EventList;
    EX_PUSH_LOCK        EventLock;
    volatile LONG       EventCount;

    //
    // 检测状态（原子读写）
    //
    volatile LONG       KernelDebuggerPresent;
    volatile LONG       UserDebuggerPresent;
    volatile LONG       HypervisorPresent;
    volatile LONG       VerifierEnabled;
    volatile LONG       CrashDumpEnabled;

    //
    // 生命周期辅助（防重复 Start/Shutdown）
    //
    volatile LONG       State;

    //
    // 统计
    //
    ADB_STATISTICS      Stats;
} WKD_ANTIDEBUG_PROTECTION, *PWKD_ANTIDEBUG_PROTECTION;

//
// 内部事件节点——挂在 EventList 上，对外返回值类型快照
//
typedef struct _ADB_EVENT {
    LIST_ENTRY          ListEntry;
    ADB_DEBUG_ATTEMPT   Type;
    HANDLE              ProcessId;
    WCHAR               ProcessName[ADB_MAX_PROCESS_NAME];
    USHORT              ProcessNameLength;
    CHAR                Details[ADB_MAX_DETAIL_LENGTH];
    LARGE_INTEGER       Timestamp;
} ADB_EVENT, *PADB_EVENT;

/* ============================================================================
 * FORWARD DECLARATIONS
 * ============================================================================ */

static VOID SppPeriodicAntiDebugCheck(_Inout_opt_ PVOID Context);

static BOOLEAN SppDetectKernelDebugger(VOID);
static BOOLEAN SppDetectUserDebugger(VOID);
static BOOLEAN SppDetectHypervisor(VOID);
static BOOLEAN SppDetectDriverVerifier(VOID);
static BOOLEAN SppDetectCrashDumpConfiguration(VOID);

static VOID AdbpRecordEvent(
    _In_ PWKD_ANTIDEBUG_PROTECTION Protection,
    _In_ ADB_DEBUG_ATTEMPT Type,
    _In_opt_ PCCH Details
    );

static VOID AdbpReport(
    _In_ PWKD_ANTIDEBUG_PROTECTION Protection,
    _In_ ULONG SubType,
    _In_ ULONG Severity,
    _In_ PCWSTR Description
    );

static VOID AdbpSnapshotEvent(
    _In_ PADB_EVENT Source,
    _Out_ PADB_EVENT_INFO Dest
    );

static VOID AdbpFreeEventList(_Inout_ PLIST_ENTRY ListHead);

static VOID AdbpEvictOldestEventsLocked(
    _In_ PWKD_ANTIDEBUG_PROTECTION Protection,
    _In_ ULONG TargetCount,
    _Inout_ PLIST_ENTRY FreeList
    );

static VOID AdbpFillProcessName(_Inout_ PADB_EVENT Evt);

_Use_decl_annotations_
NTSTATUS
SpInitializeAntiDebugProtection(
    _Out_ PWKD_ANTIDEBUG_PROTECTION* Protection
    )
{
    PWKD_ANTIDEBUG_PROTECTION protection = NULL;

    PAGED_CODE();

    if (!Protection) return STATUS_INVALID_PARAMETER;
    *Protection = NULL;

    protection = (PWKD_ANTIDEBUG_PROTECTION)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(WKD_ANTIDEBUG_PROTECTION),
        ADB_POOL_TAG_CTX
        );
    if (!protection) return STATUS_NO_MEMORY;

    ExInitializePushLock(&protection->EventLock);
    InitializeListHead(&protection->EventList);
    KeQuerySystemTimePrecise(&protection->Stats.StartTime);

    /* 初始检测（同步，非致命） */
    protection->KernelDebuggerPresent = SppDetectKernelDebugger();
    protection->HypervisorPresent = SppDetectHypervisor();
    protection->VerifierEnabled = SppDetectDriverVerifier();
    protection->CrashDumpEnabled = SppDetectCrashDumpConfiguration();
    protection->Stats.KernelDebuggerPresent = (protection->KernelDebuggerPresent != 0);
    protection->Stats.HypervisorPresent = (protection->HypervisorPresent != 0);
    protection->Stats.VerifierEnabled = (protection->VerifierEnabled != 0);
    protection->Stats.CrashDumpEnabled = (protection->CrashDumpEnabled != 0);

    *Protection = protection;
    return STATUS_SUCCESS;
}

/* ============================================================================
 * SpStartPeriodicAntiDebugProtection
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
SpStartPeriodicAntiDebugProtection(
    _Inout_ PWKD_ANTIDEBUG_PROTECTION Protection,
    _In_ const PEX_RUNDOWN_REF RundownRef,
    _In_ ULONG IntervalMs
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (!Protection || !RundownRef ||
        IntervalMs < WKD_TIMER_MIN_INTERVAL_MS || IntervalMs > WKD_TIMER_MAX_INTERVAL_MS) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedExchange(&Protection->State, 1) != 0) {
        /* 已启动 */
        return STATUS_SUCCESS;
    }

    status = CoCreatePeriodicTimer(
        &Protection->CheckTimer,
        ADB_CHECK_INTERVAL_MS,
        SppPeriodicAntiDebugCheck,
        Protection,
        TRUE,                                     /* Thread 模式，回调运行于 PASSIVE_LEVEL */
        RundownRef
        );
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&Protection->State, 0);
        return status;
    }

    CoStartPeriodicTimer(&Protection->CheckTimer);
    return STATUS_SUCCESS;
}

/* ============================================================================
 * AdbShutdown
 * ============================================================================ */

_Use_decl_annotations_
VOID
AdbShutdown(
    PWKD_ANTIDEBUG_PROTECTION Protection
    )
{
    PWKD_ANTIDEBUG_PROTECTION protection = Protection;
    LIST_ENTRY freeList;

    PAGED_CODE();

    if (protection == NULL) {
        return;
    }

    if (InterlockedExchange(&protection->State, 0) != 0) {
        /* 停止并销毁周期定时器（等待当前回调排空） */
        WkdTimerDestroy(&protection->CheckTimer);
    }

    /* 释放事件链表（此后不再有回调写入；Start 已置 0 阻止重启） */
    InitializeListHead(&freeList);
    while (!IsListEmpty(&protection->EventList)) {
        PLIST_ENTRY entry = RemoveHeadList(&protection->EventList);
        InsertTailList(&freeList, entry);
    }
    AdbpFreeEventList(&freeList);

    ExFreePoolWithTag(protection, ADB_POOL_TAG_CTX);
}

/* ============================================================================
 * AdbCheckForDebugger
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
AdbCheckForDebugger(
    PWKD_ANTIDEBUG_PROTECTION Protection,
    PBOOLEAN DebuggerPresent
    )
{
    PWKD_ANTIDEBUG_PROTECTION protection = Protection;
    BOOLEAN previousState;
    BOOLEAN currentState;

    PAGED_CODE();

    if (protection == NULL || DebuggerPresent == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *DebuggerPresent = FALSE;

    previousState = (InterlockedCompareExchange(
        &protection->KernelDebuggerPresent, 0, 0) != 0);

    currentState = SppDetectKernelDebugger();
    InterlockedExchange(&protection->KernelDebuggerPresent, currentState ? 1 : 0);

    if (currentState && !previousState) {
        AdbpRecordEvent(protection, AdbAttemptKernelDebugger,
                        "Kernel debugger newly detected");
        AdbpReport(protection, ADB_EVENT_SUBTYPE_KERNEL_DEBUGGER, 7,
                   L"AntiDebug: kernel debugger detected");
    }

    /* 用户态调试器：检查当前调用进程（须在用户态服务进程上下文调用） */
    if (SppDetectUserDebugger()) {
        if (!currentState) {
            AdbpRecordEvent(protection, AdbAttemptUserDebugger,
                            "User-mode debugger detected on calling process");
            AdbpReport(protection, ADB_EVENT_SUBTYPE_USER_DEBUGGER, 6,
                       L"AntiDebug: user-mode debugger detected");
        }
        currentState = TRUE;
        InterlockedExchange(&protection->UserDebuggerPresent, 1);
    } else {
        InterlockedExchange(&protection->UserDebuggerPresent, 0);
    }

    *DebuggerPresent = currentState;
    return STATUS_SUCCESS;
}

/* ============================================================================
 * AdbCheckForHypervisor
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
AdbCheckForHypervisor(
    PWKD_ANTIDEBUG_PROTECTION Protection,
    PBOOLEAN HypervisorPresent
    )
{
    PWKD_ANTIDEBUG_PROTECTION protection = Protection;
    BOOLEAN previousState;
    BOOLEAN currentState;

    PAGED_CODE();

    if (protection == NULL || HypervisorPresent == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *HypervisorPresent = FALSE;

    previousState = (InterlockedCompareExchange(
        &protection->HypervisorPresent, 0, 0) != 0);

    currentState = SppDetectHypervisor();
    InterlockedExchange(&protection->HypervisorPresent, currentState ? 1 : 0);

    if (currentState && !previousState) {
        AdbpRecordEvent(protection, AdbAttemptHypervisor, "Hypervisor newly detected");
        AdbpReport(protection, ADB_EVENT_SUBTYPE_HYPERVISOR, 5,
                   L"AntiDebug: hypervisor/VM detected");
    }

    *HypervisorPresent = currentState;
    return STATUS_SUCCESS;
}

/* ============================================================================
 * AdbGetEvents
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
AdbGetEvents(
    PWKD_ANTIDEBUG_PROTECTION Protection,
    PADB_EVENT_INFO EventArray,
    ULONG MaxEvents,
    PULONG ReturnedCount
    )
{
    PWKD_ANTIDEBUG_PROTECTION protection = Protection;
    ULONG copied = 0;
    PLIST_ENTRY entry;

    if (protection == NULL || EventArray == NULL ||
        MaxEvents == 0 || ReturnedCount == NULL) {
        if (ReturnedCount != NULL) *ReturnedCount = 0;
        return STATUS_INVALID_PARAMETER;
    }
    *ReturnedCount = 0;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&protection->EventLock);

    for (entry = protection->EventList.Flink;
         entry != &protection->EventList && copied < MaxEvents;
         entry = entry->Flink) {
        PADB_EVENT evt = CONTAINING_RECORD(entry, ADB_EVENT, ListEntry);
        AdbpSnapshotEvent(evt, &EventArray[copied]);
        copied++;
    }

    ExReleasePushLockShared(&protection->EventLock);
    KeLeaveCriticalRegion();

    *ReturnedCount = copied;
    return STATUS_SUCCESS;
}

/* ============================================================================
 * AdbGetStatistics
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
AdbGetStatistics(
    PWKD_ANTIDEBUG_PROTECTION Protection,
    PADB_STATISTICS Stats
    )
{
    PWKD_ANTIDEBUG_PROTECTION protection = Protection;

    if (protection == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Stats->TotalDetections = InterlockedCompareExchange64(
        &protection->Stats.TotalDetections, 0, 0);
    Stats->ReportInvocations = InterlockedCompareExchange64(
        &protection->Stats.ReportInvocations, 0, 0);
    Stats->CurrentEventCount = InterlockedCompareExchange(
        &protection->EventCount, 0, 0);
    Stats->KernelDebuggerPresent = (InterlockedCompareExchange(
        &protection->KernelDebuggerPresent, 0, 0) != 0);
    Stats->UserDebuggerPresent = (InterlockedCompareExchange(
        &protection->UserDebuggerPresent, 0, 0) != 0);
    Stats->HypervisorPresent = (InterlockedCompareExchange(
        &protection->HypervisorPresent, 0, 0) != 0);
    Stats->VerifierEnabled = (InterlockedCompareExchange(
        &protection->VerifierEnabled, 0, 0) != 0);
    Stats->CrashDumpEnabled = (InterlockedCompareExchange(
        &protection->CrashDumpEnabled, 0, 0) != 0);
    Stats->LastCheckTime = protection->Stats.LastCheckTime;
    Stats->StartTime = protection->Stats.StartTime;

    return STATUS_SUCCESS;
}

/* ============================================================================
 * AdbClearEvents
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
AdbClearEvents(
    PWKD_ANTIDEBUG_PROTECTION Protection
    )
{
    PWKD_ANTIDEBUG_PROTECTION protection = Protection;
    LIST_ENTRY freeList;

    if (protection == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeListHead(&freeList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&protection->EventLock);

    while (!IsListEmpty(&protection->EventList)) {
        PLIST_ENTRY entry = RemoveHeadList(&protection->EventList);
        InsertTailList(&freeList, entry);
    }
    InterlockedExchange(&protection->EventCount, 0);

    ExReleasePushLockExclusive(&protection->EventLock);
    KeLeaveCriticalRegion();

    AdbpFreeEventList(&freeList);
    return STATUS_SUCCESS;
}

/* ============================================================================
 * INTERNAL: 周期检测（PeriodicTimer Thread 模式回调，PASSIVE_LEVEL）
 * ============================================================================ */

static VOID
SppPeriodicAntiDebugCheck(
    _Inout_opt_ PVOID Context
    )
{
    PWKD_ANTIDEBUG_PROTECTION protection = (PWKD_ANTIDEBUG_PROTECTION)Context;
    BOOLEAN prevKd, prevHv, prevVf, prevDump;
    BOOLEAN currKd, currHv, currVf, currDump;

    if (!protection) return;

    prevKd = (InterlockedCompareExchange(&protection->KernelDebuggerPresent, 0, 0) != 0);
    prevHv = (InterlockedCompareExchange(&protection->HypervisorPresent, 0, 0) != 0);
    prevVf = (InterlockedCompareExchange(&protection->VerifierEnabled, 0, 0) != 0);
    prevDump = (InterlockedCompareExchange(&protection->CrashDumpEnabled, 0, 0) != 0);

    currKd = SppDetectKernelDebugger();
    currHv = SppDetectHypervisor();
    currVf = SppDetectDriverVerifier();
    currDump = SppDetectCrashDumpConfiguration();

    InterlockedExchange(&protection->KernelDebuggerPresent, currKd ? 1 : 0);
    InterlockedExchange(&protection->HypervisorPresent, currHv ? 1 : 0);
    InterlockedExchange(&protection->VerifierEnabled, currVf ? 1 : 0);
    InterlockedExchange(&protection->CrashDumpEnabled, currDump ? 1 : 0);

    /* 仅记录 FALSE -> TRUE 跳变 */
    if (currKd && !prevKd) {
        AdbpRecordEvent(protection, AdbAttemptKernelDebugger,
                        "Kernel debugger attached (periodic check)");
        AdbpReport(protection, ADB_EVENT_SUBTYPE_KERNEL_DEBUGGER, 7,
                   L"AntiDebug: kernel debugger attached");
    }
    if (currHv && !prevHv) {
        AdbpRecordEvent(protection, AdbAttemptHypervisor,
                        "Hypervisor detected (periodic check)");
        AdbpReport(protection, ADB_EVENT_SUBTYPE_HYPERVISOR, 5,
                   L"AntiDebug: hypervisor/VM detected");
    }
    if (currVf && !prevVf) {
        AdbpRecordEvent(protection, AdbAttemptDriverVerifier,
                        "Driver Verifier enabled (periodic check)");
        AdbpReport(protection, ADB_EVENT_SUBTYPE_DRIVER_VERIFIER, 4,
                   L"AntiDebug: driver verifier enabled");
    }
    if (currDump && !prevDump) {
        AdbpRecordEvent(protection, AdbAttemptMemoryDump,
                        "Complete memory dump enabled (periodic check)");
        AdbpReport(protection, ADB_EVENT_SUBTYPE_MEMORY_DUMP, 6,
                   L"AntiDebug: complete memory dump enabled");
    }

    protection->Stats.KernelDebuggerPresent = currKd;
    protection->Stats.HypervisorPresent = currHv;
    protection->Stats.VerifierEnabled = currVf;
    protection->Stats.CrashDumpEnabled = currDump;
    KeQuerySystemTimePrecise(&protection->Stats.LastCheckTime);
}

/* ============================================================================
 * INTERNAL: 上报（IRQL 门控 + WkdReportSelfProtectionEvent）
 * ============================================================================ */

static VOID
AdbpReport(
    _In_ PWKD_ANTIDEBUG_PROTECTION Protection,
    _In_ ULONG SubType,
    _In_ ULONG Severity,
    _In_ PCWSTR Description
    )
{
    PWKD_ANTIDEBUG_PROTECTION protection = Protection;

    UNREFERENCED_PARAMETER(protection);

    /* WkdReportSelfProtectionEvent（经 ALPC）要求 PASSIVE_LEVEL */
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return;
    }

    (VOID)WkdReportSelfProtectionEvent(SubType, Severity, Description);
    InterlockedIncrement64(&protection->Stats.ReportInvocations);
}

/* ============================================================================
 * INTERNAL: 记录事件
 * ============================================================================ */

static VOID
AdbpRecordEvent(
    _In_ PWKD_ANTIDEBUG_PROTECTION Protection,
    _In_ ADB_DEBUG_ATTEMPT Type,
    _In_opt_ PCCH Details
    )
{
    PWKD_ANTIDEBUG_PROTECTION protection = Protection;
    PADB_EVENT evt;
    LIST_ENTRY freeList;

    evt = (PADB_EVENT)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(ADB_EVENT),
        ADB_POOL_TAG_EVENT
        );
    if (evt == NULL) {
        InterlockedIncrement64(&protection->Stats.TotalDetections);
        return;
    }

    evt->Type = Type;
    evt->ProcessId = PsGetCurrentProcessId();
    KeQuerySystemTimePrecise(&evt->Timestamp);

    if (Details != NULL) {
        RtlStringCchCopyA(evt->Details, ADB_MAX_DETAIL_LENGTH, Details);
    }

    AdbpFillProcessName(evt);

    InitializeListHead(&freeList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&protection->EventLock);

    InsertTailList(&protection->EventList, &evt->ListEntry);
    InterlockedIncrement(&protection->EventCount);

    if (protection->EventCount > ADB_MAX_EVENTS) {
        AdbpEvictOldestEventsLocked(protection, ADB_MAX_EVENTS, &freeList);
    }

    ExReleasePushLockExclusive(&protection->EventLock);
    KeLeaveCriticalRegion();

    AdbpFreeEventList(&freeList);

    InterlockedIncrement64(&protection->Stats.TotalDetections);
}

/* ============================================================================
 * INTERNAL: 填进程名（宽字符，防御性截断）
 * ============================================================================ */

static VOID
AdbpFillProcessName(
    _Inout_ PADB_EVENT Evt
    )
{
    PEPROCESS process = PsGetCurrentProcess();
    PCHAR imageName = NULL;

    if (process == NULL) {
        return;
    }
    imageName = PsGetProcessImageFileName(process);
    if (imageName != NULL) {
        ANSI_STRING ansi;
        UNICODE_STRING wide;

        RtlInitAnsiString(&ansi, (PCSZ)imageName);
        wide.Buffer = Evt->ProcessName;
        wide.Length = 0;
        wide.MaximumLength = sizeof(Evt->ProcessName) - sizeof(WCHAR);
        if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&wide, &ansi, FALSE))) {
            Evt->ProcessNameLength = wide.Length / sizeof(WCHAR);
            Evt->ProcessName[Evt->ProcessNameLength] = L'\0';
        }
    }
}

/* ============================================================================
 * INTERNAL: 快照事件到值类型
 * ============================================================================ */

static VOID
AdbpSnapshotEvent(
    _In_ PADB_EVENT Source,
    _Out_ PADB_EVENT_INFO Dest
    )
{
    USHORT nameLen;

    Dest->Type = Source->Type;
    Dest->ProcessId = Source->ProcessId;
    Dest->Timestamp = Source->Timestamp;

    nameLen = Source->ProcessNameLength;
    if (nameLen >= ADB_MAX_PROCESS_NAME) {
        nameLen = ADB_MAX_PROCESS_NAME - 1;
    }
    Dest->ProcessNameLength = nameLen;
    if (nameLen > 0) {
        RtlCopyMemory(Dest->ProcessName, Source->ProcessName,
                      (SIZE_T)nameLen * sizeof(WCHAR));
    }
    Dest->ProcessName[nameLen] = L'\0';
    Dest->ProcessName[ADB_MAX_PROCESS_NAME - 1] = L'\0';

    RtlCopyMemory(Dest->Details, Source->Details, ADB_MAX_DETAIL_LENGTH);
    Dest->Details[ADB_MAX_DETAIL_LENGTH - 1] = '\0';
}

/* ============================================================================
 * INTERNAL: 释放事件链表
 * ============================================================================ */

static VOID
AdbpFreeEventList(
    _Inout_ PLIST_ENTRY ListHead
    )
{
    while (!IsListEmpty(ListHead)) {
        PLIST_ENTRY entry = RemoveHeadList(ListHead);
        PADB_EVENT evt = CONTAINING_RECORD(entry, ADB_EVENT, ListEntry);
        ExFreePoolWithTag(evt, ADB_POOL_TAG_EVENT);
    }
}

/* ============================================================================
 * INTERNAL: 淘汰最旧事件至 TargetCount（调用方须持 EventLock exclusive）
 * ============================================================================ */

static VOID
AdbpEvictOldestEventsLocked(
    _In_ PWKD_ANTIDEBUG_PROTECTION Protection,
    _In_ ULONG TargetCount,
    _Inout_ PLIST_ENTRY FreeList
    )
{
    PWKD_ANTIDEBUG_PROTECTION protection = Protection;

    while (protection->EventCount > (LONG)TargetCount &&
           !IsListEmpty(&protection->EventList)) {
        PLIST_ENTRY entry = RemoveHeadList(&protection->EventList);
        InsertTailList(FreeList, entry);
        InterlockedDecrement(&protection->EventCount);
    }
}

/* ============================================================================
 * INTERNAL: 检测——内核调试器
 * ============================================================================ */

FORCEINLINE
static BOOLEAN
SppDetectKernelDebugger(
    VOID
    )
{
    if (KD_DEBUGGER_ENABLED && !KD_DEBUGGER_NOT_PRESENT) return TRUE;
    else return FALSE;
}

/* ============================================================================
 * INTERNAL: 检测——用户态调试器（检查当前调用进程的 DebugPort）
 * ============================================================================ */

static BOOLEAN
SppDetectUserDebugger(
    VOID
    )
{
    NTSTATUS status;
    HANDLE debugPort = NULL;

    /* System 进程（PID 4）不可能有用户态调试器 */
    if (PsGetProcessId(PsGetCurrentProcess()) == (HANDLE)4) {
        return FALSE;
    }

    status = pfnZwQueryInformationProcess(
        NtCurrentProcess(),
        (PROCESSINFOCLASS)ProcessDebugPort,
        &debugPort,
        sizeof(debugPort),
        NULL
        );

    if (NT_SUCCESS(status) && debugPort != NULL) {
        return TRUE;
    } else return FALSE;
}

/* ============================================================================
 * INTERNAL: 检测——Hypervisor
 * ============================================================================ */

static BOOLEAN
SppDetectHypervisor(
    VOID
    )
{
    int cpuInfo[4] = { 0 };

    __cpuid(cpuInfo, 1);

    /* CPUID leaf 1, ECX bit 31 = Hypervisor Present */
    if (((ULONG)cpuInfo[2] & (1u << 31)) != 0) {
        return TRUE;
    } else return FALSE;
}

/* ============================================================================
 * INTERNAL: 检测——驱动验证器
 * ============================================================================ */

static BOOLEAN
SppDetectDriverVerifier(
    VOID
    )
{
    NTSTATUS status;
    ULONG verifierFlags = 0;

    status = MmIsVerifierEnabled(&verifierFlags);
    if (NT_SUCCESS(status) && verifierFlags != 0) {
        return TRUE;
    } else return FALSE;
}

/* ============================================================================
 * INTERNAL: 检测——完整内存转储配置
 * ============================================================================ */

static BOOLEAN
SppDetectCrashDumpConfiguration(
    VOID
    )
{
    NTSTATUS status;
    UNICODE_STRING string;
    OBJECT_ATTRIBUTES objAttrs;
    HANDLE keyHandle = NULL;
    KEY_VALUE_PARTIAL_INFORMATION valueInfo = { 0 };
    ULONG resultLength = 0;
    ULONG dumpType = 0;

    RtlInitUnicodeString(&string,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CrashControl");
    InitializeObjectAttributes(&objAttrs, &string,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&keyHandle, KEY_READ, &objAttrs);
    if (!NT_SUCCESS(status)) return FALSE;

    RtlInitUnicodeString(&string, L"CrashDumpEnabled");
    status = ZwQueryValueKey(
        keyHandle,
        &string,
        KeyValuePartialInformation,
        &valueInfo,
        sizeof(KEY_VALUE_PARTIAL_INFORMATION),
        &resultLength
        );
    ZwClose(keyHandle);

    if (!NT_SUCCESS(status) ||
        valueInfo.Type != REG_DWORD ||
        valueInfo.DataLength < sizeof(ULONG)) {
        return FALSE;
    }

    dumpType = *(PULONG)valueInfo.Data;
    /* CrashDumpEnabled == 1（完整内存转储）视为可疑 */
    if (dumpType == 1) {
        return TRUE;
    } else return FALSE;
}
