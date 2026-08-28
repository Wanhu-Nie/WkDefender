/**************************************************/
/*  WkDefender — AMSI 绕过检测器实现                */
/*  参考 PhantomSensor AmsiBypassDetector.c         */
/*  MITRE ATT&CK: T1562.001 Disable or Modify Tools */
/*  (AMSI bypass)                                    */
/*                                                    */
/*  检测能力（全量对齐 SS）：                         */
/*    - amsi.dll 函数序言补丁签名匹配                */
/*    - 干净基线 prologue 对比（检出未知补丁/hook）  */
/*    - amsi.dll 区域保护变更检测（变可写）           */
/*  架构改进（vs SS）：                              */
/*    ★ 基线陈旧防护: 序言与基线不一致时先校验磁盘    */
/*      amsi.dll 文件时间戳/大小，过期自动刷新基线，  */
/*      根治 Windows Update 后全量误报               */
/*    ★ 自注册镜像回调追踪 amsi.dll 加载             */
/*    ★ 自建 30s worker 线程主动扫描                 */
/*    ★ 检测结果经 ALPC 上报 agent                   */
/**************************************************/

#include "AmsiBypassDetector.h"
#include "../Notification/NotificationManager.h"
#include "../Common/Utils.h"
#include "../Common/PeParser.h"
#include <ntstrsafe.h>
#include <ntimage.h>

/**************************************************/
/*              内部数据结构声明                    */
/**************************************************/

typedef struct _ABD_CRITICAL_FUNCTION {
    CHAR Name[ABD_FUNCTION_NAME_MAX];       /* 导出函数名 */
    ULONG RvaOffset;                        /* 内存内函数地址 RVA */
    ULONG FileOffset;                       /* 基线内序言文件偏移 */
    BOOLEAN Resolved;                       /* 是否成功解析 */
} ABD_CRITICAL_FUNCTION, *PABD_CRITICAL_FUNCTION;

typedef struct _ABD_PATCH_SIGNATURE {
    const UCHAR *Bytes;
    ULONG Length;
    ABD_BYPASS_TYPE BypassType;         /* 命中时判定类型（对齐 SS：NopSled → InlineHook） */
} ABD_PATCH_SIGNATURE;

typedef struct _ABD_PROCESS_ENTRY {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    PVOID AmsiBase;                         /* amsi.dll 映射基址 */
    SIZE_T AmsiSize;                        /* amsi.dll 映射大小 */
    LARGE_INTEGER LoadTime;
    LARGE_INTEGER LastScanTime;
    BOOLEAN IsPatched;                      /* 已检出缓存 */
    ABD_BYPASS_TYPE LastDetectedBypass;
    volatile LONG ReferenceCount;           /* 1=链表持有，扫描+1 */
} ABD_PROCESS_ENTRY, *PABD_PROCESS_ENTRY;

typedef struct _ABD_DETECTOR_STATE {
    volatile LONG State;                    /* CAS 生命周期状态机 */

    /* worker 周期扫描线程 */
    HANDLE WorkerThread;
    KEVENT ShutdownEvent;
    BOOLEAN WorkerCreated;

    /* 干净基线（\SystemRoot\System32\amsi.dll 磁盘副本） */
    PVOID CleanAmsiCopy;
    SIZE_T CleanAmsiSize;
    LARGE_INTEGER BaselineFileTime;         /* 基线对应磁盘文件修改时间（陈旧防护） */
    LARGE_INTEGER BaselineFileSize;         /* 基线对应磁盘文件大小（陈旧防护） */

    /* 关键函数导出偏移表 */
    ABD_CRITICAL_FUNCTION CriticalFunctions[ABD_MAX_CRITICAL_FUNCTIONS];
    ULONG CriticalFunctionCount;

    /* per-process amsi.dll 追踪表 */
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessLock;
    volatile LONG ProcessCount;

    /* 统计 */
    ABD_STATISTICS Stats;
} ABD_DETECTOR_STATE, *PABD_DETECTOR_STATE;

static ABD_DETECTOR_STATE g_AbdState;

/**************************************************/
/*            补丁签名表（对齐 SS）                 */
/**************************************************/

/* Pattern 1: "mov eax, 0x80070057; ret" — 最常用 AmsiScanBuffer 补丁（E_INVALIDARG） */
static const UCHAR g_PatchSig_MovEaxInvalidArg[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

/* Pattern 2: "xor eax, eax; ret" — 返回 S_OK */
static const UCHAR g_PatchSig_XorEaxRet[]  = { 0x31, 0xC0, 0xC3 };
static const UCHAR g_PatchSig_XorEaxRet2[] = { 0x33, 0xC0, 0xC3 };

/* Pattern 3: "ret" — 立即返回 */
static const UCHAR g_PatchSig_Ret[] = { 0xC3 };

/* Pattern 4: NOP sled（>=4 NOP）— 常见 hook 覆写 */
static const UCHAR g_PatchSig_NopSled[] = { 0x90, 0x90, 0x90, 0x90 };

/* Pattern 5: "mov eax, 0; ret" — 显式返回 S_OK */
static const UCHAR g_PatchSig_MovEaxZeroRet[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };

static const ABD_PATCH_SIGNATURE g_PatchSignatures[] = {
    { g_PatchSig_MovEaxInvalidArg, sizeof(g_PatchSig_MovEaxInvalidArg), AbdBypass_PatchAmsiScanBuffer },
    { g_PatchSig_XorEaxRet,        sizeof(g_PatchSig_XorEaxRet),        AbdBypass_PatchAmsiScanBuffer },
    { g_PatchSig_XorEaxRet2,       sizeof(g_PatchSig_XorEaxRet2),       AbdBypass_PatchAmsiScanBuffer },
    { g_PatchSig_Ret,              sizeof(g_PatchSig_Ret),              AbdBypass_PatchAmsiScanBuffer },
    { g_PatchSig_NopSled,          sizeof(g_PatchSig_NopSled),          AbdBypass_InlineHook },
    { g_PatchSig_MovEaxZeroRet,    sizeof(g_PatchSig_MovEaxZeroRet),    AbdBypass_PatchAmsiScanBuffer },
};

/**************************************************/
/*            关键导出函数名（对齐 SS）             */
/**************************************************/

static const WCHAR g_AmsiDllName[] = L"amsi.dll";

static const CHAR* g_CriticalExportNames[] = {
    "AmsiScanBuffer",
    "AmsiScanString",
    "AmsiOpenSession",
    "AmsiInitialize",
    "AmsiCloseSession",
    "AmsiUninitialize",
};

/**************************************************/
/*           内部函数前向声明                       */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
AbdpImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_opt_ PIMAGE_INFO ImageInfo
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
AbdpScanWorkerThread(
    _In_ PVOID Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
AbdpScanAllProcesses(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
AbdpLoadCleanBaseline(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
AbdpResolveExports(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
AbdpFreeBaseline(
    VOID
    );

static
BOOLEAN
AbdpIsAmsiDll(
    _In_ PCUNICODE_STRING ImageName
    );

static
PABD_PROCESS_ENTRY
AbdpFindProcess(
    _In_ HANDLE ProcessId
    );

static
PABD_PROCESS_ENTRY
AbdpTrackProcess(
    _In_ HANDLE ProcessId,
    _In_ PVOID AmsiBase,
    _In_ SIZE_T AmsiSize
    );

static
VOID
AbdpRemoveProcess(
    _In_ HANDLE ProcessId
    );

static
VOID
AbdpReleaseProcess(
    _In_ PABD_PROCESS_ENTRY Entry
    );

static
BOOLEAN
AbdpBaselineIsFresh(
    VOID
    );

static
NTSTATUS
AbdpRefreshBaseline(
    VOID
    );

static
BOOLEAN
AbdpCheckPrologueForPatch(
    _In_ PCUCHAR CurrentPrologue,
    _In_ ULONG PrologueSize,
    _Out_ PABD_BYPASS_TYPE BypassType
    );

static
NTSTATUS
AbdpReadProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    );

static
VOID
AbdpSendDetection(
    _In_ HANDLE ProcessId,
    _In_ PABD_CRITICAL_FUNCTION Func,
    _In_ PVOID FunctionAddress,
    _In_ ABD_BYPASS_TYPE BypassType,
    _In_ PCUCHAR CurrentBytes,
    _In_opt_ PCUCHAR OriginalBytes
    );

static
VOID
AbdpSendProtectionChange(
    _In_ HANDLE ProcessId,
    _In_ PVOID BaseAddress,
    _In_ ULONG OldProtection,
    _In_ ULONG NewProtection
    );

/**************************************************/
/*           公共 API 实现                          */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AbdInitialize(
    VOID
    )
/*++
Routine Description:
    初始化 AMSI 绕过检测器：加载干净基线、注册镜像回调、创建周期扫描线程。
Arguments:
    无。
Return Value:
    NTSTATUS。镜像回调注册失败为致命（模块依赖其追踪基址）。
--*/
{
    LONG prevState;
    NTSTATUS status;

    PAGED_CODE();

    prevState = InterlockedCompareExchange(
        &g_AbdState.State, ABD_STATE_INITIALIZING, ABD_STATE_UNINITIALIZED);
    if (prevState != ABD_STATE_UNINITIALIZED) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlZeroMemory(&g_AbdState.Stats, sizeof(ABD_STATISTICS));
    InitializeListHead(&g_AbdState.ProcessList);
    ExInitializePushLock(&g_AbdState.ProcessLock);
    g_AbdState.ProcessCount = 0;
    KeInitializeEvent(&g_AbdState.ShutdownEvent, NotificationEvent, FALSE);
    g_AbdState.WorkerThread = NULL;
    g_AbdState.WorkerCreated = FALSE;

    /* 加载干净基线（非致命：失败则降级签名-only 模式） */
    status = AbdpLoadCleanBaseline();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] AMSI Bypass Detector: Failed to load clean baseline: 0x%08X\n"
            "[WkDefender] AMSI bypass detection will use signature-only mode.\n", status);
    }

    if (g_AbdState.CleanAmsiCopy != NULL) {
        AbdpResolveExports();
    }

    /* 注册镜像回调（模块自包含，不依赖 CbInitializeImageNotify） */
    status = PsSetLoadImageNotifyRoutine(AbdpImageNotifyCallback);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] AMSI Bypass Detector: PsSetLoadImageNotifyRoutine failed: 0x%08X\n", status);
        AbdpFreeBaseline();
        InterlockedExchange(&g_AbdState.State, ABD_STATE_UNINITIALIZED);
        return status;
    }

    /* 创建周期扫描 worker 线程（非致命：失败降级为加载时扫描+保护变更） */
    status = PsCreateSystemThread(&g_AbdState.WorkerThread, THREAD_ALL_ACCESS, NULL, NULL,
                                  NULL, AbdpScanWorkerThread, NULL);
    if (NT_SUCCESS(status)) {
        g_AbdState.WorkerCreated = TRUE;
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] AMSI Bypass Detector: worker thread create failed: 0x%08X "
            "(fallback to load-time scan only)\n", status);
    }

    InterlockedExchange(&g_AbdState.State, ABD_STATE_READY);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] AMSI Bypass Detector initialized "
        "(baseline=%s, functions=%u, signatures=%u)\n",
        g_AbdState.CleanAmsiCopy ? "loaded" : "unavailable",
        g_AbdState.CriticalFunctionCount,
        (ULONG)ARRAYSIZE(g_PatchSignatures));

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
AbdCleanup(
    VOID
    )
/*++
Routine Description:
    清理 AMSI 绕过检测器：停止 worker、移除镜像回调、释放全部资源。
Arguments:
    无。
Return Value:
    无。
--*/
{
    LONG prevState;

    PAGED_CODE();

    prevState = InterlockedCompareExchange(
        &g_AbdState.State, ABD_STATE_SHUTTING_DOWN, ABD_STATE_READY);
    if (prevState != ABD_STATE_READY) {
        return;
    }

    /* 唤醒并等待 worker 退出（ShutdownEvent 设立即中断 30s 等待） */
    if (g_AbdState.WorkerCreated) {
        KeSetEvent(&g_AbdState.ShutdownEvent, IO_NO_INCREMENT, FALSE);
        if (g_AbdState.WorkerThread != NULL) {
            KeWaitForSingleObject(g_AbdState.WorkerThread, Executive, KernelMode, FALSE, NULL);
            ZwClose(g_AbdState.WorkerThread);
            g_AbdState.WorkerThread = NULL;
        }
        g_AbdState.WorkerCreated = FALSE;
    }

    /* 移除镜像回调 */
    PsRemoveLoadImageNotifyRoutine(AbdpImageNotifyCallback);

    /* 释放全部进程条目（SHUTTING_DOWN 后 AbdIsActive()=FALSE，扫描不再取新引用） */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_AbdState.ProcessLock);
    while (!IsListEmpty(&g_AbdState.ProcessList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_AbdState.ProcessList);
        PABD_PROCESS_ENTRY proc = CONTAINING_RECORD(entry, ABD_PROCESS_ENTRY, ListEntry);
        ExFreePoolWithTag(proc, ABD_POOL_TAG_PROC);
    }
    g_AbdState.ProcessCount = 0;
    ExReleasePushLockExclusive(&g_AbdState.ProcessLock);
    KeLeaveCriticalRegion();

    AbdpFreeBaseline();

    InterlockedExchange(&g_AbdState.State, ABD_STATE_UNINITIALIZED);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
AbdIsActive(
    VOID
    )
{
    return (ReadAcquire(&g_AbdState.State) == ABD_STATE_READY);
}

/**************************************************/
/*        镜像加载集成（自注册回调）                */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
AbdpImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_opt_ PIMAGE_INFO ImageInfo
    )
/*++
Routine Description:
    PsSetLoadImageNotifyRoutine 回调：检测 amsi.dll 加载并追踪基址，
    加载即扫描一次（覆盖"加载即被 patch"的恶意加载）。
Arguments:
    FullImageName - 镜像完整路径。
    ProcessId     - 加载进程 PID。
    ImageInfo     - 镜像信息（基址/大小）。
Return Value:
    无。
--*/
{
    ABD_DETECTION det;

    if (!AbdIsActive()) return;
    if (FullImageName == NULL || ImageInfo == NULL) return;
    if (FullImageName->Length == 0 || ImageInfo->ImageSize == 0) return;

    if (!AbdpIsAmsiDll(FullImageName)) return;

    AbdpTrackProcess(ProcessId, ImageInfo->ImageBase, ImageInfo->ImageSize);
    InterlockedIncrement64(&g_AbdState.Stats.AmsiLoadsObserved);

    /* 加载即扫描 */
    (VOID)AbdScanProcess(ProcessId, &det);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
AbdNotifyImageLoad(
    _In_ HANDLE ProcessId,
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_opt_ PCUNICODE_STRING ImageName
    )
/*++
Routine Description:
    外部镜像加载喂入接口（供现有 ImageNotify 接线，幂等——重复喂入仅更新基址）。
Arguments:
    ProcessId - 加载进程 PID。
    ImageBase - 镜像基址。
    ImageSize - 镜像大小。
    ImageName - 镜像路径。
Return Value:
    无。
--*/
{
    ABD_DETECTION det;

    if (!AbdIsActive()) return;
    if (ImageBase == NULL || ImageSize == 0 || ImageName == NULL) return;

    if (!AbdpIsAmsiDll(ImageName)) return;

    AbdpTrackProcess(ProcessId, ImageBase, ImageSize);
    InterlockedIncrement64(&g_AbdState.Stats.AmsiLoadsObserved);
    (VOID)AbdScanProcess(ProcessId, &det);
}

/**************************************************/
/*              完整性扫描（核心）                  */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AbdScanProcess(
    _In_ HANDLE ProcessId,
    _Out_ PABD_DETECTION Detection
    )
/*++
Routine Description:
    扫描指定进程的 amsi.dll 关键函数序言完整性。
    基线优先：序言匹配基线→跳过；不匹配→先做基线陈旧防护，再查补丁签名；
    未知修改→InlineHook。无基线时降级签名-only 模式。
Arguments:
    ProcessId - 目标进程 PID。
    Detection - 输出检测结果（BypassType=None 表示未检出）。
Return Value:
    STATUS_SUCCESS - 扫描完成（检查 Detection->BypassType）。
    STATUS_NOT_FOUND - 进程未追踪 amsi.dll。
--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PABD_PROCESS_ENTRY procEntry;
    UCHAR currentPrologue[ABD_PROLOGUE_SIZE];

    PAGED_CODE();

    if (Detection == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Detection, sizeof(ABD_DETECTION));
    Detection->BypassType = AbdBypass_None;

    if (!AbdIsActive()) {
        return STATUS_DEVICE_NOT_READY;
    }

    procEntry = AbdpFindProcess(ProcessId);
    if (procEntry == NULL) {
        return STATUS_NOT_FOUND;
    }

    InterlockedIncrement64(&g_AbdState.Stats.ScansPerformed);

    for (ULONG i = 0; i < g_AbdState.CriticalFunctionCount; i++) {
        PABD_CRITICAL_FUNCTION func = &g_AbdState.CriticalFunctions[i];
        PVOID functionAddress;
        ABD_BYPASS_TYPE bypassType;

        if (!func->Resolved || func->RvaOffset == 0) {
            continue;
        }

        /* 深度防御：确保 RvaOffset+prologue 在 amsi.dll 映射内，防指针回绕/越界读 */
        if (procEntry->AmsiBase == NULL || procEntry->AmsiSize == 0 ||
            (SIZE_T)func->RvaOffset >= procEntry->AmsiSize ||
            (SIZE_T)func->RvaOffset + ABD_PROLOGUE_SIZE > procEntry->AmsiSize) {
            continue;
        }

        functionAddress = (PVOID)((ULONG_PTR)procEntry->AmsiBase + func->RvaOffset);

        status = AbdpReadProcessMemory(ProcessId, functionAddress,
                                       currentPrologue, ABD_PROLOGUE_SIZE);
        if (!NT_SUCCESS(status)) {
            continue;
        }

        /* Step 1: 基线对比（基线有效时最强信号，可检出未知补丁） */
        if (g_AbdState.CleanAmsiCopy != NULL && func->FileOffset != 0 &&
            func->FileOffset + ABD_PROLOGUE_SIZE <= g_AbdState.CleanAmsiSize) {

            PCUCHAR cleanPrologue =
                (PCUCHAR)g_AbdState.CleanAmsiCopy + func->FileOffset;

            if (RtlCompareMemory(currentPrologue, cleanPrologue, ABD_PROLOGUE_SIZE)
                == ABD_PROLOGUE_SIZE) {
                continue;   /* 序言匹配基线，未修改 */
            }

            /* ★ 基线陈旧防护：序言与基线不一致时，先校验磁盘 amsi.dll 是否已更新。
             *   Windows Update 会替换 amsi.dll，导致序言变化——此时刷新基线而非误报。 */
            if (!AbdpBaselineIsFresh()) {
                AbdpRefreshBaseline();
                continue;   /* 基线已刷新，cleanPrologue 失效，下轮扫描用新基线重比 */
            }

            /* 基线有效且序言确实不同：查补丁签名 */
            if (AbdpCheckPrologueForPatch(currentPrologue, ABD_PROLOGUE_SIZE, &bypassType)) {
                /* 已知补丁签名命中 */
            } else {
                bypassType = AbdBypass_InlineHook;   /* 未知修改（基线有效时可判定） */
            }

            Detection->BypassType = bypassType;
            Detection->ProcessId = ProcessId;
            Detection->TargetAddress = functionAddress;
            RtlCopyMemory(Detection->CurrentBytes, currentPrologue, ABD_PROLOGUE_SIZE);
            RtlCopyMemory(Detection->OriginalBytes, cleanPrologue, ABD_PROLOGUE_SIZE);
            KeQuerySystemTimePrecise(&Detection->DetectionTime);
            RtlStringCbCopyA(Detection->FunctionName, sizeof(Detection->FunctionName), func->Name);

            procEntry->IsPatched = TRUE;
            procEntry->LastDetectedBypass = bypassType;
            InterlockedIncrement64(&g_AbdState.Stats.BypassesDetected);
            InterlockedIncrement64(&g_AbdState.Stats.PatchDetections);

            AbdpSendDetection(ProcessId, func, functionAddress, bypassType,
                              currentPrologue, cleanPrologue);
            break;      /* 一次扫描一条检测足够 */
        }

        /* Step 2: 无基线 → 签名-only 模式（低保真，只检已知补丁） */
        if (AbdpCheckPrologueForPatch(currentPrologue, ABD_PROLOGUE_SIZE, &bypassType)) {
            Detection->BypassType = bypassType;
            Detection->ProcessId = ProcessId;
            Detection->TargetAddress = functionAddress;
            RtlCopyMemory(Detection->CurrentBytes, currentPrologue, ABD_PROLOGUE_SIZE);
            KeQuerySystemTimePrecise(&Detection->DetectionTime);
            RtlStringCbCopyA(Detection->FunctionName, sizeof(Detection->FunctionName), func->Name);

            procEntry->IsPatched = TRUE;
            procEntry->LastDetectedBypass = bypassType;
            InterlockedIncrement64(&g_AbdState.Stats.BypassesDetected);
            InterlockedIncrement64(&g_AbdState.Stats.PatchDetections);

            AbdpSendDetection(ProcessId, func, functionAddress, bypassType,
                              currentPrologue, NULL);
            break;
        }
    }

    KeQuerySystemTimePrecise(&procEntry->LastScanTime);
    AbdpReleaseProcess(procEntry);
    return STATUS_SUCCESS;
}

/**************************************************/
/*        保护变更检测（VirtualProtect）            */
/**************************************************/

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
AbdCheckProtectionChange(
    _In_ HANDLE ProcessId,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG OldProtection,
    _In_ ULONG NewProtection
    )
/*++
Routine Description:
    检查一次 VirtualProtect 是否把 amsi.dll 区域改为可写（绕过前置步骤）。
Arguments:
    ProcessId     - 目标进程 PID。
    BaseAddress   - 区域基址。
    RegionSize    - 区域大小。
    OldProtection - 旧保护属性。
    NewProtection - 新保护属性。
Return Value:
    TRUE - 命中 amsi.dll 区域且被改为可写（已上报）。
--*/
{
    PABD_PROCESS_ENTRY procEntry;
    ULONG_PTR regionStart, regionEnd, amsiStart, amsiEnd;

    PAGED_CODE();

    if (!AbdIsActive()) return FALSE;

    procEntry = AbdpFindProcess(ProcessId);
    if (procEntry == NULL) return FALSE;

    regionStart = (ULONG_PTR)BaseAddress;
    amsiStart = (ULONG_PTR)procEntry->AmsiBase;

    /* 减法校验防 ULONG_PTR 溢出 */
    if (RegionSize > (ULONG_PTR)-1 - regionStart ||
        procEntry->AmsiSize > (ULONG_PTR)-1 - amsiStart) {
        AbdpReleaseProcess(procEntry);
        return FALSE;
    }

    regionEnd = regionStart + RegionSize;
    amsiEnd = amsiStart + procEntry->AmsiSize;

    if (regionStart < amsiEnd && regionEnd > amsiStart) {
        /* 保护变更命中 amsi.dll 区域：检查是否变可写 */
        BOOLEAN wasWritable = (OldProtection & (PAGE_READWRITE | PAGE_WRITECOPY |
                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        BOOLEAN isWritable = (NewProtection & (PAGE_READWRITE | PAGE_WRITECOPY |
                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

        if (!wasWritable && isWritable) {
            /* amsi.dll 区域被改可写 — 强绕过指示 */
            procEntry->IsPatched = TRUE;
            procEntry->LastDetectedBypass = AbdBypass_MemoryProtectionChange;
            InterlockedIncrement64(&g_AbdState.Stats.BypassesDetected);
            InterlockedIncrement64(&g_AbdState.Stats.ProtectionChangeDetections);

            AbdpSendProtectionChange(ProcessId, BaseAddress,
                                     OldProtection, NewProtection);

            AbdpReleaseProcess(procEntry);
            return TRUE;
        }
    }

    AbdpReleaseProcess(procEntry);
    return FALSE;
}

/**************************************************/
/*                 统计                             */
/**************************************************/

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
AbdGetStatistics(
    _Out_ PABD_STATISTICS Stats
    )
{
    if (Stats == NULL) return;

    RtlZeroMemory(Stats, sizeof(ABD_STATISTICS));

    if (ReadAcquire(&g_AbdState.State) != ABD_STATE_READY) return;

    Stats->ProcessesMonitored           = ReadNoFence64((PLONG64)&g_AbdState.Stats.ProcessesMonitored);
    Stats->AmsiLoadsObserved            = ReadNoFence64((PLONG64)&g_AbdState.Stats.AmsiLoadsObserved);
    Stats->BypassesDetected             = ReadNoFence64((PLONG64)&g_AbdState.Stats.BypassesDetected);
    Stats->PatchDetections              = ReadNoFence64((PLONG64)&g_AbdState.Stats.PatchDetections);
    Stats->ProtectionChangeDetections   = ReadNoFence64((PLONG64)&g_AbdState.Stats.ProtectionChangeDetections);
    Stats->EtwPatchDetections           = ReadNoFence64((PLONG64)&g_AbdState.Stats.EtwPatchDetections);
    Stats->ScansPerformed               = ReadNoFence64((PLONG64)&g_AbdState.Stats.ScansPerformed);
}

/**************************************************/
/*           进程终止清理（公共封装）               */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
VOID
AbdRemoveProcessTracking(
    _In_ HANDLE ProcessId
    )
{
    PAGED_CODE();
    AbdpRemoveProcess(ProcessId);
}

/**************************************************/
/*       周期扫描 worker 线程                       */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
AbdpScanWorkerThread(
    _In_ PVOID Context
    )
/*++
Routine Description:
    30s 周期扫描所有已追踪进程（对齐 SS ABD_SCAN_INTERVAL_100NS）。
    通过 ShutdownEvent 唤醒中断等待，支持快速退出。
Arguments:
    Context - 未使用。
Return Value:
    无。
--*/
{
    LARGE_INTEGER interval;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Context);

    interval.QuadPart = ABD_SCAN_INTERVAL_100NS;

    for (;;) {
        /* 等待 30s 或 shutdown 信号（清理时立即中断） */
        status = KeWaitForSingleObject(&g_AbdState.ShutdownEvent,
                                       Executive, KernelMode, FALSE, &interval);
        UNREFERENCED_PARAMETER(status);

        if (g_AbdState.State != ABD_STATE_READY) break;

        AbdpScanAllProcesses();
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
AbdpScanAllProcesses(
    VOID
    )
/*++
Routine Description:
    收集进程表全部未检测条目的引用，锁外逐个扫描。
    引用计数保证扫描期间条目不被终止清理释放（UAF 防护）。
Arguments:
    无。
Return Value:
    无。
--*/
{
    PABD_PROCESS_ENTRY scanList[ABD_MAX_TRACKED_PROCESSES];
    ULONG scanCount = 0;
    PLIST_ENTRY listEntry;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_AbdState.ProcessLock);

    for (listEntry = g_AbdState.ProcessList.Flink;
         listEntry != &g_AbdState.ProcessList && scanCount < ABD_MAX_TRACKED_PROCESSES;
         listEntry = listEntry->Flink) {

        PABD_PROCESS_ENTRY entry = CONTAINING_RECORD(listEntry, ABD_PROCESS_ENTRY, ListEntry);
        if (entry->IsPatched) continue;      /* 已检出跳过（除非 amsi.dll 重载复位） */
        InterlockedIncrement(&entry->ReferenceCount);
        scanList[scanCount++] = entry;
    }

    ExReleasePushLockShared(&g_AbdState.ProcessLock);
    KeLeaveCriticalRegion();

    for (ULONG i = 0; i < scanCount; i++) {
        ABD_DETECTION det;
        (VOID)AbdScanProcess(scanList[i]->ProcessId, &det);
        AbdpReleaseProcess(scanList[i]);
    }
}

/**************************************************/
/*            per-process 追踪表                   */
/**************************************************/

static
BOOLEAN
AbdpIsAmsiDll(
    _In_ PCUNICODE_STRING ImageName
    )
/*++
Routine Description:
    判断镜像路径是否以 \amsi.dll 结尾（大小写不敏感）。
Arguments:
    ImageName - 镜像完整路径。
Return Value:
    TRUE - 是 amsi.dll。
--*/
{
    USHORT nameChars, matchChars;

    if (ImageName == NULL || ImageName->Buffer == NULL || ImageName->Length == 0) {
        return FALSE;
    }

    nameChars = ImageName->Length / sizeof(WCHAR);
    matchChars = (USHORT)(sizeof(g_AmsiDllName) / sizeof(WCHAR) - 1);

    if (nameChars < matchChars + 1) {   /* +1 反斜杠 */
        return FALSE;
    }

    PCWSTR suffix = &ImageName->Buffer[nameChars - matchChars];
    if (_wcsnicmp(suffix, g_AmsiDllName, matchChars) != 0) {
        return FALSE;
    }

    /* 确认后缀前是路径分隔符，避免 \foo\baramsi.dll 误判 */
    if (ImageName->Buffer[nameChars - matchChars - 1] != L'\\') {
        return FALSE;
    }

    return TRUE;
}

static
PABD_PROCESS_ENTRY
AbdpFindProcess(
    _In_ HANDLE ProcessId
    )
{
    PABD_PROCESS_ENTRY entry = NULL;
    PLIST_ENTRY listEntry;
    ULONG walkCount = 0;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_AbdState.ProcessLock);

    for (listEntry = g_AbdState.ProcessList.Flink;
         listEntry != &g_AbdState.ProcessList && walkCount < ABD_MAX_TRACKED_PROCESSES;
         listEntry = listEntry->Flink, walkCount++) {

        PABD_PROCESS_ENTRY current = CONTAINING_RECORD(listEntry, ABD_PROCESS_ENTRY, ListEntry);
        if (current->ProcessId == ProcessId) {
            InterlockedIncrement(&current->ReferenceCount);
            entry = current;
            break;
        }
    }

    ExReleasePushLockShared(&g_AbdState.ProcessLock);
    KeLeaveCriticalRegion();

    return entry;
}

static
PABD_PROCESS_ENTRY
AbdpTrackProcess(
    _In_ HANDLE ProcessId,
    _In_ PVOID AmsiBase,
    _In_ SIZE_T AmsiSize
    )
{
    PABD_PROCESS_ENTRY entry = NULL;
    PABD_PROCESS_ENTRY newEntry = NULL;
    PLIST_ENTRY listEntry;
    ULONG walkCount = 0;

    /* 锁外预分配，缩短锁持有时间 */
    if (ReadAcquire(&g_AbdState.ProcessCount) < ABD_MAX_TRACKED_PROCESSES) {
        newEntry = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                   sizeof(ABD_PROCESS_ENTRY), ABD_POOL_TAG_PROC);
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_AbdState.ProcessLock);

    for (listEntry = g_AbdState.ProcessList.Flink;
         listEntry != &g_AbdState.ProcessList && walkCount < ABD_MAX_TRACKED_PROCESSES;
         listEntry = listEntry->Flink, walkCount++) {

        PABD_PROCESS_ENTRY current = CONTAINING_RECORD(listEntry, ABD_PROCESS_ENTRY, ListEntry);
        if (current->ProcessId == ProcessId) {
            /* 已存在（amsi.dll 重载）：更新基址并复位检测缓存 */
            current->AmsiBase = AmsiBase;
            current->AmsiSize = AmsiSize;
            current->IsPatched = FALSE;
            current->LastDetectedBypass = AbdBypass_None;
            entry = current;
            break;
        }
    }

    if (entry == NULL && newEntry != NULL &&
        g_AbdState.ProcessCount < ABD_MAX_TRACKED_PROCESSES) {

        RtlZeroMemory(newEntry, sizeof(ABD_PROCESS_ENTRY));
        newEntry->ProcessId = ProcessId;
        newEntry->AmsiBase = AmsiBase;
        newEntry->AmsiSize = AmsiSize;
        newEntry->ReferenceCount = 1;       /* 链表持有 */
        KeQuerySystemTimePrecise(&newEntry->LoadTime);

        InsertTailList(&g_AbdState.ProcessList, &newEntry->ListEntry);
        InterlockedIncrement(&g_AbdState.ProcessCount);
        entry = newEntry;
        newEntry = NULL;
    }

    ExReleasePushLockExclusive(&g_AbdState.ProcessLock);
    KeLeaveCriticalRegion();

    if (newEntry != NULL) {
        ExFreePoolWithTag(newEntry, ABD_POOL_TAG_PROC);
    }

    if (entry != NULL) {
        InterlockedIncrement64(&g_AbdState.Stats.ProcessesMonitored);
    }

    return entry;
}

static
VOID
AbdpRemoveProcess(
    _In_ HANDLE ProcessId
    )
{
    PLIST_ENTRY listEntry;
    PABD_PROCESS_ENTRY entry = NULL;
    ULONG walkCount = 0;

    if (!AbdIsActive()) return;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_AbdState.ProcessLock);

    for (listEntry = g_AbdState.ProcessList.Flink;
         listEntry != &g_AbdState.ProcessList && walkCount < ABD_MAX_TRACKED_PROCESSES;
         listEntry = listEntry->Flink, walkCount++) {

        PABD_PROCESS_ENTRY current = CONTAINING_RECORD(listEntry, ABD_PROCESS_ENTRY, ListEntry);
        if (current->ProcessId == ProcessId) {
            RemoveEntryList(&current->ListEntry);
            InterlockedDecrement(&g_AbdState.ProcessCount);
            entry = current;
            break;
        }
    }

    ExReleasePushLockExclusive(&g_AbdState.ProcessLock);
    KeLeaveCriticalRegion();

    if (entry != NULL) {
        /* 释放链表持有；若有扫描正持有引用，则等其 AbdpReleaseProcess 归零再释放 */
        AbdpReleaseProcess(entry);
    }
}

static
VOID
AbdpReleaseProcess(
    _In_ PABD_PROCESS_ENTRY Entry
    )
{
    if (InterlockedDecrement(&Entry->ReferenceCount) == 0) {
        ExFreePoolWithTag(Entry, ABD_POOL_TAG_PROC);
    }
}

/**************************************************/
/*           干净基线加载（对齐 SS）                */
/**************************************************/

static
NTSTATUS
AbdpLoadCleanBaseline(
    VOID
    )
/*++
Routine Description:
    从 \SystemRoot\System32\amsi.dll 读取干净副本到内核内存，
    记录文件大小/修改时间用于基线陈旧防护。
Arguments:
    无。
Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;
    UNICODE_STRING amsiPath;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    FILE_BASIC_INFORMATION basicInfo;
    FILE_STANDARD_INFORMATION stdInfo;
    PVOID buffer = NULL;
    LARGE_INTEGER readOffset;

    PAGED_CODE();

    RtlInitUnicodeString(&amsiPath, L"\\SystemRoot\\System32\\amsi.dll");

    InitializeObjectAttributes(&objAttr, &amsiPath,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenFile(&fileHandle,
                        FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                        &objAttr, &ioStatus,
                        FILE_SHARE_READ | FILE_SHARE_DELETE,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(status)) return status;

    /* 文件大小 + 修改时间（基线陈旧防护依据）
     * FileStandardInformation / FileBasicInformation 查询需 FILE_READ_ATTRIBUTES */
    status = ZwQueryInformationFile(fileHandle, &ioStatus,
                                    &stdInfo, sizeof(stdInfo), FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        ZwClose(fileHandle);
        return status;
    }
    status = ZwQueryInformationFile(fileHandle, &ioStatus,
                                    &basicInfo, sizeof(basicInfo), FileBasicInformation);
    if (!NT_SUCCESS(status)) {
        ZwClose(fileHandle);
        return status;
    }

    /* 合理性检查：amsi.dll 应 < 1MB */
    if (stdInfo.EndOfFile.QuadPart == 0 ||
        stdInfo.EndOfFile.QuadPart > (1024 * 1024)) {
        ZwClose(fileHandle);
        return STATUS_FILE_TOO_LARGE;
    }

    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                             (SIZE_T)stdInfo.EndOfFile.QuadPart, ABD_POOL_TAG_BASELINE);
    if (buffer == NULL) {
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    readOffset.QuadPart = 0;
    status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatus,
                        buffer, (ULONG)stdInfo.EndOfFile.QuadPart, &readOffset, NULL);
    ZwClose(fileHandle);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, ABD_POOL_TAG_BASELINE);
        return status;
    }

    /* PE 头校验（统一解析核心，File 模式，零回调） */
    {
        WKD_PE_PARSE_CONTEXT ctx;
        NTSTATUS parseStatus;

        RtlZeroMemory(&ctx, sizeof(ctx));
        ctx.Data = buffer;
        ctx.DataSize = (SIZE_T)stdInfo.EndOfFile.QuadPart;
        ctx.Mode = WkdPeMode_File;
        ctx.MaxSections = WKD_PE_MAX_SECTIONS_DEFAULT;
        parseStatus = CoParsePe(&ctx);
        if (!NT_SUCCESS(parseStatus)) {
            ExFreePoolWithTag(buffer, ABD_POOL_TAG_BASELINE);
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }

    g_AbdState.CleanAmsiCopy = buffer;
    g_AbdState.CleanAmsiSize = (SIZE_T)stdInfo.EndOfFile.QuadPart;
    g_AbdState.BaselineFileSize.QuadPart = stdInfo.EndOfFile.QuadPart;
    g_AbdState.BaselineFileTime.QuadPart = basicInfo.LastWriteTime.QuadPart;

    return STATUS_SUCCESS;
}

static
VOID
AbdpFreeBaseline(
    VOID
    )
{
    if (g_AbdState.CleanAmsiCopy != NULL) {
        ExFreePoolWithTag(g_AbdState.CleanAmsiCopy, ABD_POOL_TAG_BASELINE);
        g_AbdState.CleanAmsiCopy = NULL;
        g_AbdState.CleanAmsiSize = 0;
    }
    g_AbdState.CriticalFunctionCount = 0;
}

static
NTSTATUS
AbdpResolveExports(
    VOID
    )
/*++
Routine Description:
    解析 6 个关键导出函数的 RVA 与文件偏移（统一解析核心导出查询）。
Arguments:
    无。
Return Value:
    NTSTATUS。
--*/
{
    WKD_PE_PARSE_CONTEXT ctx;
    ULONG resolved = 0;

    PAGED_CODE();

    if (g_AbdState.CleanAmsiCopy == NULL) {
        return STATUS_NOT_FOUND;
    }

    RtlZeroMemory(&ctx, sizeof(ctx));
    ctx.Data = g_AbdState.CleanAmsiCopy;
    ctx.DataSize = g_AbdState.CleanAmsiSize;
    ctx.Mode = WkdPeMode_File;
    ctx.MaxSections = WKD_PE_MAX_SECTIONS_DEFAULT;

    /* 统一解析核心（File 模式，仅校验+节表，零回调） */
    if (!NT_SUCCESS(CoParsePe(&ctx))) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    for (ULONG i = 0; i < ARRAYSIZE(g_CriticalExportNames); i++) {
        WKD_PE_EXPORT_ENTRY entry;
        NTSTATUS exportStatus;

        if (resolved >= ABD_MAX_CRITICAL_FUNCTIONS) break;

        exportStatus = WkdPeResolveExport(&ctx, g_CriticalExportNames[i], &entry);

        PABD_CRITICAL_FUNCTION func = &g_AbdState.CriticalFunctions[resolved];
        RtlStringCbCopyA(func->Name, sizeof(func->Name), g_CriticalExportNames[i]);
        func->RvaOffset = NT_SUCCESS(exportStatus) ? entry.Rva : 0;
        func->FileOffset = NT_SUCCESS(exportStatus) ? entry.FileOffset : 0;
        func->Resolved = (func->RvaOffset != 0 && func->FileOffset != 0);

        if (func->Resolved) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                "[WkDefender] AMSI export resolved: %s -> RVA 0x%X (file 0x%X)\n",
                g_CriticalExportNames[i], func->RvaOffset, func->FileOffset);
        }
        resolved++;
    }

    g_AbdState.CriticalFunctionCount = resolved;
    return STATUS_SUCCESS;
}

/**************************************************/
/*         基线陈旧防护（★ 根治 SS 误报缺陷）       */
/**************************************************/

static
BOOLEAN
AbdpBaselineIsFresh(
    VOID
    )
/*++
Routine Description:
    校验磁盘 System32\amsi.dll 的文件大小/修改时间是否与基线一致。
    不一致说明 Windows Update 替换了 amsi.dll，基线已过期（需刷新而非误报）。
Arguments:
    无。
Return Value:
    TRUE - 基线仍有效。
--*/
{
    NTSTATUS status;
    UNICODE_STRING amsiPath;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    FILE_BASIC_INFORMATION basicInfo;
    FILE_STANDARD_INFORMATION stdInfo;

    RtlInitUnicodeString(&amsiPath, L"\\SystemRoot\\System32\\amsi.dll");
    InitializeObjectAttributes(&objAttr, &amsiPath,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenFile(&fileHandle,
                        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                        &objAttr, &ioStatus,
                        FILE_SHARE_READ | FILE_SHARE_DELETE,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(status)) return FALSE;

    status = ZwQueryInformationFile(fileHandle, &ioStatus,
                                    &basicInfo, sizeof(basicInfo), FileBasicInformation);
    if (NT_SUCCESS(status)) {
        status = ZwQueryInformationFile(fileHandle, &ioStatus,
                                        &stdInfo, sizeof(stdInfo), FileStandardInformation);
    }
    ZwClose(fileHandle);

    if (!NT_SUCCESS(status)) return FALSE;

    return (stdInfo.EndOfFile.QuadPart == g_AbdState.BaselineFileSize.QuadPart &&
            basicInfo.LastWriteTime.QuadPart == g_AbdState.BaselineFileTime.QuadPart);
}

static
NTSTATUS
AbdpRefreshBaseline(
    VOID
    )
/*++
Routine Description:
    释放旧基线并重新加载磁盘 amsi.dll + 重新解析导出（Windows Update 后调用）。
Arguments:
    无。
Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;

    AbdpFreeBaseline();

    status = AbdpLoadCleanBaseline();
    if (!NT_SUCCESS(status)) return status;

    AbdpResolveExports();
    return STATUS_SUCCESS;
}

/**************************************************/
/*             补丁签名检测（对齐 SS）              */
/**************************************************/

static
BOOLEAN
AbdpCheckPrologueForPatch(
    _In_ PCUCHAR CurrentPrologue,
    _In_ ULONG PrologueSize,
    _Out_ PABD_BYPASS_TYPE BypassType
    )
{
    *BypassType = AbdBypass_None;

    for (ULONG i = 0; i < ARRAYSIZE(g_PatchSignatures); i++) {
        if (g_PatchSignatures[i].Length <= PrologueSize) {
            if (RtlCompareMemory(CurrentPrologue, g_PatchSignatures[i].Bytes,
                                 g_PatchSignatures[i].Length)
                == g_PatchSignatures[i].Length) {
                *BypassType = g_PatchSignatures[i].BypassType;
                return TRUE;
            }
        }
    }

    return FALSE;
}

/**************************************************/
/*         跨进程内存读取（对齐 SS）                */
/**************************************************/

static
NTSTATUS
AbdpReadProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    )
/*++
Routine Description:
    附加到目标进程读取指定地址内存（SEH 保护）。
    委托给通用 WkdReadProcessMemory（Utils.c，对齐 SS MmpReadProcessMemory），
    保留单次读取上限约束（当前调用仅 ABD_PROLOGUE_SIZE=16）。
Arguments:
    ProcessId - 目标进程 PID。
    Address   - 源地址。
    Buffer    - 输出缓冲。
    Size      - 读取大小。
Return Value:
    NTSTATUS。
--*/
{
    /* 单次读取上限（当前调用仅 ABD_PROLOGUE_SIZE=16） */
    if (Buffer == NULL || Address == NULL || Size == 0 || Size > PAGE_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    return WkdReadProcessMemory(ProcessId, Address, Buffer, Size);
}

/**************************************************/
/*          ALPC 上报（驱动→Agent）                 */
/**************************************************/

static
VOID
AbdpSendDetection(
    _In_ HANDLE ProcessId,
    _In_ PABD_CRITICAL_FUNCTION Func,
    _In_ PVOID FunctionAddress,
    _In_ ABD_BYPASS_TYPE BypassType,
    _In_ PCUCHAR CurrentBytes,
    _In_opt_ PCUCHAR OriginalBytes
    )
/*++
Routine Description:
    构造 WkdMessage_AmsiBypassDetected 消息并经 ALPC 异步上报 agent。
Arguments:
    ProcessId      - 被检测进程 PID。
    Func           - 被补丁的关键函数。
    FunctionAddress- 函数内存地址。
    BypassType     - 绕过类型。
    CurrentBytes   - 当前序言字节。
    OriginalBytes  - 基线序言字节（可为 NULL）。
Return Value:
    无。
--*/
{
    PWKD_MESSAGE msg;
    PWKD_MESSAGE_BODY_AMSI_BYPASS body;

    msg = NtfCreateMessage(WkdMessage_AmsiBypassDetected,
                           WkdMessage_SourceAmsiBypass,
                           WkdMessage_PriorityHigh,
                           (ULONG)sizeof(WKD_MESSAGE_BODY_AMSI_BYPASS));
    if (msg == NULL) return;

    msg->Header.SourceProcessId = ProcessId;
    msg->Header.TargetProcessId = ProcessId;
    msg->Header.ThreadId = NULL;
    KeQuerySystemTime(&msg->Header.Timestamp);
    msg->Header.Flags.IsAsync = 1;

    body = WKD_MESSAGE_BODY(msg, WKD_MESSAGE_BODY_AMSI_BYPASS);
    body->ProcessId = ProcessId;
    body->BypassType = BypassType;
    body->TargetAddress = FunctionAddress;
    RtlStringCbCopyA(body->FunctionName, sizeof(body->FunctionName), Func->Name);
    if (OriginalBytes != NULL) {
        RtlCopyMemory(body->OriginalBytes, OriginalBytes, ABD_PROLOGUE_SIZE);
    }
    RtlCopyMemory(body->CurrentBytes, CurrentBytes, ABD_PROLOGUE_SIZE);
    body->OldProtection = 0;
    body->NewProtection = 0;

    (VOID)NtfSendMessageAsync(msg);
}

static
VOID
AbdpSendProtectionChange(
    _In_ HANDLE ProcessId,
    _In_ PVOID BaseAddress,
    _In_ ULONG OldProtection,
    _In_ ULONG NewProtection
    )
/*++
Routine Description:
    保护变更检测的 ALPC 上报（复用 AMSI bypass 消息，BypassType=MemoryProtectionChange）。
Arguments:
    ProcessId     - 目标进程 PID。
    BaseAddress   - 区域基址。
    OldProtection - 旧保护。
    NewProtection - 新保护。
Return Value:
    无。
--*/
{
    PWKD_MESSAGE msg;
    PWKD_MESSAGE_BODY_AMSI_BYPASS body;

    msg = NtfCreateMessage(WkdMessage_AmsiBypassDetected,
                           WkdMessage_SourceAmsiBypass,
                           WkdMessage_PriorityHigh,
                           (ULONG)sizeof(WKD_MESSAGE_BODY_AMSI_BYPASS));
    if (msg == NULL) return;

    msg->Header.SourceProcessId = ProcessId;
    msg->Header.TargetProcessId = ProcessId;
    msg->Header.ThreadId = NULL;
    KeQuerySystemTime(&msg->Header.Timestamp);
    msg->Header.Flags.IsAsync = 1;

    body = WKD_MESSAGE_BODY(msg, WKD_MESSAGE_BODY_AMSI_BYPASS);
    body->ProcessId = ProcessId;
    body->BypassType = AbdBypass_MemoryProtectionChange;
    body->TargetAddress = BaseAddress;
    body->OldProtection = OldProtection;
    body->NewProtection = NewProtection;
    RtlStringCbCopyA(body->FunctionName, sizeof(body->FunctionName), "(protection-change)");

    (VOID)NtfSendMessageAsync(msg);
}
