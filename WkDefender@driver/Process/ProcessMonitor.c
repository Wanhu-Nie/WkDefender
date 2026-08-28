#include "ProcessMonitor.h"
#include "../Common/HashMap.h"
#include "../Common/Utils.h"
#include "../Memory/MemoryRegion.h"
#include "../AnalysisEngine/AnalysisEngine.h"
#include "../AnalysisEngine/IocProcess.h"
#include "../AnalysisEngine/IocAppControl.h"
#include "../Callbacks/ThreadNotify.h"
#include "../Callbacks/ProcessNotify.h"
#include "../Notification/NotificationManager.h"
#include "../Notification/AlpcService.h"
#include "../Notification/MessageSync.h"
#include "../Common/Exempts/Exempts.h"

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5,
} SYSTEM_INFORMATION_CLASS;

typedef enum _KTHREAD_STATE
{
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWaitObsolete,
    WaitingForProcessInSwap,
    MaximumThreadState
} KTHREAD_STATE, * PKTHREAD_STATE;

typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;                   // Number of 100-nanosecond intervals spent executing kernel code.
    LARGE_INTEGER UserTime;                     // Number of 100-nanosecond intervals spent executing user code.
    LARGE_INTEGER CreateTime;                   // The date and time when the thread was created.
    ULONG WaitTime;                             // The current time spent in ready queue or waiting (depending on the thread state).
    PVOID StartAddress;                         // The initial start address of the thread.
    CLIENT_ID ClientId;                         // The identifier of the thread and the process owning the thread.
    KPRIORITY Priority;                         // The dynamic priority of the thread.
    KPRIORITY BasePriority;                     // The starting priority of the thread.
    ULONG ContextSwitches;                      // The total number of context switches performed.
    KTHREAD_STATE ThreadState;                  // The current state of the thread.
    KWAIT_REASON WaitReason;                    // The current reason the thread is waiting.
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;                      // The address of the previous item plus the value in the NextEntryOffset member. For the last item in the array, NextEntryOffset is 0.
    ULONG NumberOfThreads;                      // The NumberOfThreads member contains the number of threads in the process.
    ULONGLONG WorkingSetPrivateSize;            // The total private memory that a process currently has allocated and is physically resident in memory. // since VISTA
    ULONG HardFaultCount;                       // The total number of hard faults for data from disk rather than from in-memory pages. // since WIN7
    ULONG NumberOfThreadsHighWatermark;         // The peak number of threads that were running at any given point in time, indicative of potential performance bottlenecks related to thread management.
    ULONGLONG CycleTime;                        // The sum of the cycle time of all threads in the process.
    LARGE_INTEGER CreateTime;                   // Number of 100-nanosecond intervals since the creation time of the process. Not updated during system timezone changes.
    LARGE_INTEGER UserTime;                     // Number of 100-nanosecond intervals the process has executed in user mode.
    LARGE_INTEGER KernelTime;                   // Number of 100-nanosecond intervals the process has executed in kernel mode.
    UNICODE_STRING ImageName;                   // The file name of the executable image.
    KPRIORITY BasePriority;                     // The starting priority of the process.
    HANDLE UniqueProcessId;                     // The identifier of the process.
    HANDLE InheritedFromUniqueProcessId;        // The identifier of the process that created this process. Not updated and incorrectly refers to processes with recycled identifiers.
    ULONG HandleCount;                          // The current number of open handles used by the process.
    ULONG SessionId;                            // The identifier of the Remote Desktop Services session under which the specified process is running.
    ULONG_PTR UniqueProcessKey;                 // since VISTA (requires SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;                     // The peak size, in bytes, of the virtual memory used by the process.
    SIZE_T VirtualSize;                         // The current size, in bytes, of virtual memory used by the process.
    ULONG PageFaultCount;                       // The total number of page faults for data that is not currently in memory. The value wraps around to zero on average 24 hours.
    SIZE_T PeakWorkingSetSize;                  // The peak size, in kilobytes, of the working set of the process.
    SIZE_T WorkingSetSize;                      // The number of pages visible to the process in physical memory. These pages are resident and available for use without triggering a page fault.
    SIZE_T QuotaPeakPagedPoolUsage;             // The peak quota charged to the process for pool usage, in bytes.
    SIZE_T QuotaPagedPoolUsage;                 // The quota charged to the process for paged pool usage, in bytes.
    SIZE_T QuotaPeakPOOL_FLAG_NON_PAGEDUsage;          // The peak quota charged to the process for nonpaged pool usage, in bytes.
    SIZE_T QuotaPOOL_FLAG_NON_PAGEDUsage;              // The current quota charged to the process for nonpaged pool usage.
    SIZE_T PagefileUsage;                       // The total number of bytes of page file storage in use by the process.
    SIZE_T PeakPagefileUsage;                   // The maximum number of bytes of page-file storage used by the process.
    SIZE_T PrivatePageCount;                    // The number of memory pages allocated for the use by the process.
    LARGE_INTEGER ReadOperationCount;           // The total number of read operations performed.
    LARGE_INTEGER WriteOperationCount;          // The total number of write operations performed.
    LARGE_INTEGER OtherOperationCount;          // The total number of I/O operations performed other than read and write operations.
    LARGE_INTEGER ReadTransferCount;            // The total number of bytes read during a read operation.
    LARGE_INTEGER WriteTransferCount;           // The total number of bytes written during a write operation.
    LARGE_INTEGER OtherTransferCount;           // The total number of bytes transferred during operations other than read and write operations.
    SYSTEM_THREAD_INFORMATION Threads[1];       // This type is not defined in the structure but was added for convenience.
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


/*************************************************/
/*                  内部函数声明                  */
/*************************************************/

_IRQL_requires_max_(DISPATCH_LEVEL)
static
VOID
PspDestroyProcess(
    _In_ PWKD_PROCESS Process
    );

/* PsGetProcessSessionId 函数指针类型（未文档化API） */
typedef ULONG (*PFN_PsGetProcessSessionId)(
    _In_ PEPROCESS Process
    );
PFN_PsGetProcessSessionId pfnPsGetProcessSessionId;  // PsGetProcessSessionId 函数指针

/* ZwQuerySystemInformation 函数指针类型（未文档化API） */
typedef NTSTATUS (*PFN_ZwQuerySystemInformation)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );
PFN_ZwQuerySystemInformation pfnZwQuerySystemInformation;  // ZwQuerySystemInformation 函数指针

//
// ZwQueryInformationProcess 声明
//
typedef NTSTATUS (*PFN_ZwQueryInformationProcess)(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_opt_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );
PFN_ZwQueryInformationProcess pfnZwQueryInformationProcess;

/* PsGetProcessInheritedFromUniqueProcessId 函数指针类型（未文档化API） */
typedef HANDLE (*PFN_PsGetProcessInheritedFromUniqueProcessId)(
    _In_ PEPROCESS Process
    );
// PsGetProcessInheritedFromUniqueProcessId 函数指针
PFN_PsGetProcessInheritedFromUniqueProcessId pfnPsGetProcessInheritedFromUniqueProcessId;

/* PsGetProcessProtection 函数指针类型（未文档化API） */
typedef PS_PROTECTION (*PFN_PsGetProcessProtection)(
    _In_ PEPROCESS Process
    );
// PsGetProcessProtection 函数指针
PFN_PsGetProcessProtection pfnPsGetProcessProtection;

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
PmpQueryProcessCommandLine(
    _In_ const PEPROCESS EProcess,
    _Out_ PUNICODE_STRING* CommandLine
    );

//
// 全局进程管理器实例
//
WKD_PROCESS_MONITOR g_WkdProcessMonitor = { 0 };

//
// 初始化进程管理器
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PmInitialize(
    VOID
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING usFunctionName;

    RtlZeroMemory(&g_WkdProcessMonitor, sizeof(WKD_PROCESS_MONITOR));

    ExInitializeRundownProtection(&g_WkdProcessMonitor.RundownRef);
    KeInitializeSpinLock(&g_WkdProcessMonitor.Lock);  // 初始化自旋锁
    InitializeListHead(&g_WkdProcessMonitor.ActiveProcessHead);

    //
    // 获取未文档化API ZwQuerySystemInformation 的地址
    //
    RtlInitUnicodeString(&usFunctionName, L"ZwQuerySystemInformation");
    pfnZwQuerySystemInformation = 
        (PFN_ZwQuerySystemInformation)MmGetSystemRoutineAddress(&usFunctionName);
    if (!pfnZwQuerySystemInformation) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to get ZwQuerySystemInformation address\n");
        return STATUS_NOT_FOUND;
    }

    //
    // 获取未文档化API ZwQueryInformationProcess 的地址
    //
    RtlInitUnicodeString(&usFunctionName, L"ZwQueryInformationProcess");
    pfnZwQueryInformationProcess =
        (PFN_ZwQuerySystemInformation)MmGetSystemRoutineAddress(&usFunctionName);
    if (!pfnZwQueryInformationProcess) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to get ZwQueryInformationProcess address\n");
        return STATUS_NOT_FOUND;
    }

    //
    // 获取未文档化API PsGetProcessSessionId 的地址
    //
    RtlInitUnicodeString(&usFunctionName, L"PsGetProcessSessionId");
    pfnPsGetProcessSessionId = 
        (PFN_PsGetProcessSessionId)MmGetSystemRoutineAddress(&usFunctionName);
    if (!pfnPsGetProcessSessionId) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to get PsGetProcessSessionId address\n");
        return STATUS_UNSUCCESSFUL;
    }

    //
    // 获取未文档化API PsGetProcessInheritedFromUniqueProcessId 的地址
    //
    RtlInitUnicodeString(&usFunctionName, L"PsGetProcessInheritedFromUniqueProcessId");
    pfnPsGetProcessInheritedFromUniqueProcessId =
        (PFN_PsGetProcessInheritedFromUniqueProcessId)MmGetSystemRoutineAddress(&usFunctionName);
    if (!pfnPsGetProcessInheritedFromUniqueProcessId) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to get PsGetProcessInheritedFromUniqueProcessId address\n");
        return STATUS_UNSUCCESSFUL;
    }

    //
    // 获取未文档化API PsGetProcessProtection 的地址
    //
    RtlInitUnicodeString(&usFunctionName, L"PsGetProcessProtection");
    pfnPsGetProcessProtection =
        (PFN_PsGetProcessProtection)MmGetSystemRoutineAddress(&usFunctionName);
    if (!pfnPsGetProcessProtection) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to get PsPsGetProcessProtection address\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    //
    // 初始化哈希映射表（使用桶级锁优化读多写少场景）
    //
    status = CoInitializeHashMap(
        &g_WkdProcessMonitor.ProcessTable,
        WKD_PROCESS_HASH_MAP_SIZE,          // 桶数量
        TRUE,                               // 是否桶锁
        PsReferenceWkdProcess,              // 2026-08-25 强制对称契约: ref/deref 成对必选
        NULL,                               // ShouldRemove: 进程表摘除由退出路径显式执行
        PsDereferenceWkdProcess
        );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    /*
     * 引用/解引用回调已在 CoInitializeHashMap 传入（pair/behavior 等模块统一约定）：
     *   插入 CoInsertHashMap   → Reference（引用 +1，表引用）
     *   查找 CoLookupHashMapEntry → 桶锁内 Reference（pin）
     *   摘除 CoRemoveHashMapEntry → 桶独占锁 Dereference（释放表引用）
     * 注意 PsLookupWkdProcessByProcessId 的语义是"查找即 +1"，
     * 调用方必须"PsLookup + PsDereferenceWkdProcess"配对以自动平衡。
     * 未注册 ShouldRemove：进程被摘除仅能由退出路径显式执行，不应被其他路径禁止
     */

    g_WkdProcessMonitor.Initialized = TRUE;
    g_WkdProcessMonitor.MaxProcesses = WKD_PROCESS_HASH_MAP_SIZE;

    /* 初始化父-子规则 */
    IocInitializeParentChildRules();

    return status;
}

//
// 清理进程管理器
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PmCleanup(
    VOID
    )
{
    g_WkdProcessMonitor.ShutdownRequested = TRUE;

    //
    // 清理哈希映射表
    //
    CoFreeHashMap(&g_WkdProcessMonitor.ProcessTable);

    //
    // 等待所有正在运行的操作完成
    //
    ExWaitForRundownProtectionRelease(&g_WkdProcessMonitor.RundownRef);

    g_WkdProcessMonitor.Initialized = FALSE;
}

//
// 减少引用计数
//
_Use_decl_annotations_
LONG
PsDereferenceWkdProcess(
    _Inout_ PWKD_PROCESS WkdProcess
    )
{
    LONG refCount;
    
    if (!WkdProcess) return MAXLONG;

    refCount = InterlockedDecrement(&WkdProcess->RefCount);
    
    /* 全局活动进程链额外持有一个 Ref - g_WkdProcessMonitor.ActiveProcessHead */
    if (refCount == 1) {
        PspDestroyProcess(WkdProcess);
    }
    
    return refCount;
}

//
// 在 UNICODE_STRING 中查找子串（大小写敏感）
// 返回 TRUE 如果子串在目标串中出现
//
//
// 大小写不敏感的 Unicode 子串搜索
//
// 参考 PhantomSensor: PnpSafeWcsStrI (ProcessNotify.c:4504-4571)
// 手动 a-z→A-Z 转换比较，不依赖 null 终止符，不触发分页。
// 适用于 PASSIVE_LEVEL / APC_LEVEL，不保证 DISPATCH_LEVEL 安全。
//
_IRQL_requires_max_(APC_LEVEL)
static
BOOLEAN
PmpFindInUnicodeString(
    _In_ PUNICODE_STRING Haystack,
    _In_ PUNICODE_STRING Needle
    )
{
    SIZE_T i, j;
    SIZE_T needleChars, haystackChars;

    if (!Haystack || !Needle || !Haystack->Buffer || !Needle->Buffer ||
        Needle->Length == 0 || Haystack->Length < Needle->Length) {
        return FALSE;
    }

    needleChars = Needle->Length / sizeof(WCHAR);
    haystackChars = Haystack->Length / sizeof(WCHAR);

    for (i = 0; i <= haystackChars - needleChars; i++) {
        BOOLEAN match = TRUE;

        for (j = 0; j < needleChars; j++) {
            WCHAR bufChar = Haystack->Buffer[i + j];
            WCHAR patChar = Needle->Buffer[j];

            /* 转换为大写再比较（大小写不敏感） */
            if (bufChar >= L'a' && bufChar <= L'z') {
                bufChar -= (L'a' - L'A');
            }
            if (patChar >= L'a' && patChar <= L'z') {
                patChar -= (L'a' - L'A');
            }

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
// djb2 哈希函数（大小写不敏感）
//
// 参考 PhantomSensor: PapHashStringInsensitive (ProcessAnalyzer.c:1399-1429)
// 用于已知父进程和父-子规则匹配。
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
ULONG
PmpHashStringInsensitive(
    _In_ PCWSTR String,
    _In_ ULONG LengthInChars
    )
{
    ULONG Hash = 5381;
    ULONG i;

    if (String == NULL || LengthInChars == 0) {
        return Hash;
    }

    for (i = 0; i < LengthInChars && String[i] != L'\0'; i++) {
        WCHAR Ch = String[i];

        /* 大小写不敏感 */
        if (Ch >= L'A' && Ch <= L'Z') {
            Ch = Ch - L'A' + L'a';
        }

        /* djb2 哈希 */
        Hash = ((Hash << 5) + Hash) + (ULONG)Ch;
    }

    return Hash;
}

//
// 从完整路径中提取文件名（最后一个路径分隔符后的部分）
//
// 参考 PhantomSensor: PapExtractFileName (ProcessAnalyzer.c:3269-3297)
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
BOOLEAN
PmpExtractFileName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING FileName
    )
{
    USHORT i;
    USHORT lastSlash = 0;

    if (FullPath == NULL || FullPath->Buffer == NULL || FullPath->Length == 0) {
        RtlZeroMemory(FileName, sizeof(UNICODE_STRING));
        return FALSE;
    }

    for (i = 0; i < FullPath->Length / sizeof(WCHAR); i++) {
        if (FullPath->Buffer[i] == L'\\' || FullPath->Buffer[i] == L'/') {
            lastSlash = i + 1;
        }
    }

    FileName->Buffer = &FullPath->Buffer[lastSlash];
    FileName->Length = FullPath->Length - (lastSlash * sizeof(WCHAR));
    FileName->MaximumLength = FileName->Length + sizeof(WCHAR);

    return (FileName->Length > 0);
}

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
PspCreateProcessContextInternal(
    _Inout_ PWKD_PROCESS WkdProcess
    )
{
    NTSTATUS status;

    if (!WkdProcess) return STATUS_INVALID_PARAMETER;

    /* 初始化内存区域追踪状态（2026-08-27 下沉自两条创建路径公共初始化：
     * 必须在 Phase 1 之前完成，确保任何后续 goto Cleanup 路径中
     * PspDestroyProcess → WkdMemRegionCleanupProcess 访问到合法链表头，
     * 否则 RegionList 为 NULL 链表头会导致 RemoveHeadList 对 NULL 解引用蓝屏）。 */
    InitializeListHead(&WkdProcess->MemRegionState.RegionList);
    ExInitializePushLock(&WkdProcess->MemRegionState.RegionLock);
    WkdProcess->MemRegionState.ProcessId = WkdProcess->Core.ProcessId;

    /* Phase 1: 安全上下文分配 + 快速签名验证（排除判决需要 IsSignatureValid） */
    WkdProcess->SecurityContext = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(WKD_SECURITY_CONTEXT), 'secC');
    if (!WkdProcess->SecurityContext) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] SecurityContext allocation failed for PID %p\n",
            WkdProcess->Core.ProcessId);
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }
    RtlZeroMemory(WkdProcess->SecurityContext, sizeof(WKD_SECURITY_CONTEXT));
    ExInitializePushLock(&WkdProcess->SecurityContext->Lock);   /* 2026-08-25 锁下沉 */

    /* Phase 1.5: PPL 采集（对齐 SS ShadowStrikeValidateProcessSignature 的
     * ProcessProtectionInformation 段，2026-08-09 迁至进程回调）。
     * PsGetProcessProtection 读 EPROCESS->Protection：低 4 位 Type（PPL 判定）、
     * 高 4 位 Signer（Authenticode/Antimalware/Windows 等）。Type==None 非 PPL。
     * 消费点（Exempts 判定 / L1 参考）标注未来。 */
    WkdProcess->SecurityContext->PplProtection =
        pfnPsGetProcessProtection(WkdProcess->Core.EProcess); 

    /* Phase 2: 排除判决（统一单一排除入口 CoEvaluateProcessExemption） */
    {
        BOOLEAN isExempted = FALSE;
        EXEMPT_REASON reason;
        EXEMPT_VERDICT verdict;

        /*
         * TrustedPID 播种：进程创建时先判定路径/进程名/父继承排除，
         * 命中写位图（供热路径 ExemptsIsProcessTrusted 消费）。
         */
        CoExemptCreatedProcess(
            WkdProcess->Core.ProcessId,
            WkdProcess->Core.ParentProcessId,
            WkdProcess->Core.ImagePath,
            &isExempted);
        if (isExempted) WkdProcess->SecurityFlags.Trusted = TRUE;

        // verdict = CoEvaluateProcessExemption(WkdProcess, &reason);

        //if (verdict == ExemptVerdict_Trusted) {
        //    /* 完全可信 — 标记 Trusted 供自保护/镜像加载免检 */
        //    WkdProcess->SecurityFlags.Trusted = TRUE;

        //    /* 信任覆盖（对齐 SS PnpIsTrustedProcess）：PPID 欺骗进程即使
        //     * 路径/身份符合排除（可信外观）也不豁免——撤销信任走完整
        //     * 创建 IOC 分析以被 IocpDetectPpidSpoofing 标记上报。 */
        //    if (!WkdIsPpidSpoofed(WkdProcess->Core.ProcessId,
        //                          WkdProcess->Core.ParentProcessId,
        //                          WkdProcess->Core.CreatorProcessId)) {
        //        return STATUS_SUCCESS;
        //    }
        //    WkdProcess->SecurityFlags.Trusted = FALSE;
        //}
    }

    /* Phase 2.5: 模块追踪上下文（2026-08-11 前移自镜像回调惰性初始化，
     * 消除多镜像回调并发建 Context 的覆盖泄漏竞态）。
     * 失败非致命：镜像回调保留惰性兜底。 */
    PsAllocateModuleContext(WkdProcess);

    /* Phase 2.6: 线程追踪上下文（对齐 Phase 2.5 模块上下文急切创建模式，
     * 2026-08-27 前移自线程回调惰性初始化，消除并发建 Context 的竞态与
     * 单点失败）。失败非致命：线程回调保留惰性兜底；切勿改为致命失败，
     * 否则池紧张时会永久丢失进程全部线程追踪。 */
    CbAllocateThreadContext(WkdProcess);

    /*
     * 2026-07 迁移：IOC/IOA/评分上下文已迁至进程对（AE_PROCESS_PAIR），
     * 进程创建时不再注册任何分析上下文；进程对在事件到达时经
     * AeFindOrCreateProcessPair 创建（创建时全部分配三上下文）。
     */

    return STATUS_SUCCESS;

Cleanup:
    PspDestroyProcess(WkdProcess);
    return status;
}


/*
 * 创建进程上下文，按需执行不同粒度的进程信息采集
 *
 * 所有分配失败均通过 Cleanup 统一回退，避免部分分配泄漏。
 * 调用者约定：返回成功时 *WkdProcess 非空且已就绪；
 *              返回失败或排除时 *WkdProcess 置 NULL，调用者不应再访问。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
PspCreateProcessContext(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo,
    _Outptr_ PWKD_PROCESS* WkdProcess
)
{
    NTSTATUS status;
    PWKD_PROCESS temp_WkdProcess;

    if (!(WkdProcess && Process && ProcessId && CreateInfo)) {
        return STATUS_INVALID_PARAMETER;
    }
    *WkdProcess = NULL;

    temp_WkdProcess = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(WKD_PROCESS), 'proc');
    if (!temp_WkdProcess) {
        return STATUS_NO_MEMORY;
    }
    /* 分配成功即递增池计数（PspDestroyProcess 无条件递减，严格配对） */
    InterlockedIncrement(&g_WkdProcessMonitor.PoolLimiter.ActiveContexts);

    /* Phase 1: 初始化主结构体 */
    {
        RtlZeroMemory(temp_WkdProcess, sizeof(WKD_PROCESS));
        temp_WkdProcess->RefCount = 1;
        temp_WkdProcess->Core.Alive = TRUE;
        temp_WkdProcess->Core.ProcessId = ProcessId;
        temp_WkdProcess->Core.ParentProcessId = CreateInfo->ParentProcessId;
        temp_WkdProcess->Core.CreatorProcessId = CreateInfo->CreatingThreadId.UniqueProcess;
        temp_WkdProcess->Core.CreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);

        /* 初始化区段映射画像（PreAcquireSection 迁移 2026-08）：窗口起点继承
         * CreateTime（PID 复用防护由 WKD_PROCESS 表按 PID+CreateTime 保证），
         * 创建后 5s 内视为空心化检测窗口。其余字段 RtlZeroMemory 已清零。 */
        temp_WkdProcess->SectionMapProfile.WindowStartTime =
            temp_WkdProcess->Core.CreateTime;
        temp_WkdProcess->SectionMapProfile.IsEarlyProcess = TRUE;
    }

    /* Phase 2: 解析字符串字段（非致命——失败时保留 NULL）*/
    {
        if (CoCheckUnicodeStringValidity(CreateInfo->ImageFileName)) {
            CoNormalizeDosPath((PUNICODE_STRING)CreateInfo->ImageFileName,
                &temp_WkdProcess->Core.ImagePath);
        }
        
        if (CoCheckUnicodeStringValidity(CreateInfo->CommandLine)) {
            CoCopyUnicodeString(&temp_WkdProcess->CommandLine, CreateInfo->CommandLine);
        }
    }

    /* Phase 3: 绑定 EPROCESS，增加引用计数 */
    status = PsLookupProcessByProcessId(ProcessId, &temp_WkdProcess->Core.EProcess);
    if (!NT_SUCCESS(status) ||
        temp_WkdProcess->Core.EProcess != Process) {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    /* Phase 4: 初始化相关上下文 */
    status = PspCreateProcessContextInternal(temp_WkdProcess);
    if (!NT_SUCCESS(status)) goto Cleanup;

    *WkdProcess = temp_WkdProcess;
    return STATUS_SUCCESS;;

Cleanup:
    PspDestroyProcess(temp_WkdProcess);
    return status;
}

//
// 计算单条进程创建事件体的总字节数（按8字节对齐）
//
_IRQL_requires_(PASSIVE_LEVEL)
static
SIZE_T
PmpCalculateProcessBodySize(
    _In_ PWKD_PROCESS Process
    )
/*++
Routine Description:
    计算将 WKD_PROCESS 序列化为 WKD_MESSAGE_BODY_PROCESS_CREATE 时所需的总字节数。
    发送级大小说明（对齐 SS PnpSendProcessNotification L3703/3729）：SS 对命令行
    再 cap 4096 + 超 SHADOWSTRIKE_MAX_MESSAGE_SIZE 截断；wkd 的 AlpcSendMessage
    对超长消息（>WKD_ALPC_MAX_MESSAGE_SUPPORTED）走 SectionView 共享内存，且
    捕获阶段已 cap 命令行 8192 字节（WKD_MAX_COMMAND_LINE_CAPTURE），无需发送级截断。

Arguments:
    Process — 进程对象。

Return Value:
    所需字节数（含固定头 + ImagePath 字符串 + CommandLine 字符串）。
--*/
{
    SIZE_T size = sizeof(WKD_MESSAGE_BODY_PROCESS_CREATE);

    if (Process->Core.ImagePath && Process->Core.ImagePath->Length) {
        size += Process->Core.ImagePath->Length + sizeof(WCHAR);
    }
    if (Process->CommandLine && Process->CommandLine->Length) {
        size += Process->CommandLine->Length + sizeof(WCHAR);
    }

    return ALIGN_8(size);
}

//
// 从 WKD_PROCESS 构建单个进程创建事件体（固定头 + 字符串数据连续布局）按8字节对齐
//
_IRQL_requires_(PASSIVE_LEVEL)
static
ULONG
PmpBuildProcessCreateBody(
    _In_ PWKD_PROCESS Process,
    _Out_writes_bytes_(BufferSize) PUCHAR Buffer,
    _In_ ULONG BufferSize
    )
/*++
Routine Description:
    将 WKD_PROCESS 序列化为 WKD_MESSAGE_BODY_PROCESS_CREATE 格式写入 Buffer。

    内存布局:
      [WKD_MESSAGE_BODY_PROCESS_CREATE 固定头]
      [ImagePath WCHAR string]     ← ImagePath.Buffer 指向此处
      [CommandLine WCHAR string]   ← CommandLine->Buffer 指向此处

    UNICODE_STRING.Buffer 指向 Buffer 内的偏移位置，
    Agent 端解析时按同样的偏移量重建指针。

Arguments:
    Process    — 进程对象。
    Buffer     — 输出缓冲区。
    BufferSize — 缓冲区大小（字节）。

Return Value:
    实际写入的字节数。
--*/
{
    PWKD_MESSAGE_BODY_PROCESS_CREATE body;
    PUCHAR cursor;   // 游标

    body = (PWKD_MESSAGE_BODY_PROCESS_CREATE)Buffer;
    RtlZeroMemory(body, sizeof(WKD_MESSAGE_BODY_PROCESS_CREATE));

    /* 字符串游标起始于固定头之后 */
    cursor = Buffer + sizeof(WKD_MESSAGE_BODY_PROCESS_CREATE);

    /* ---- 固定字段 ---- */
    body->ProcessId = Process->Core.ProcessId;
    body->ParentProcessId = Process->Core.ParentProcessId;
    body->CreateTime = Process->Core.CreateTime;
    body->SessionId = Process->SecurityContext->SessionId;
    body->IntegrityLevel = (ULONG)Process->SecurityContext->IntegrityLevel;
    body->Elevated = Process->SecurityContext->Elevated;
    // body->SecurityFlags = *(PULONG)&Process->SecurityContext->SecurityFlags;
    // ※已注释 (2026-08-05): SecurityFlags 消息字段恒 0。agent 令牌深度分析
    //   (TokenAnalyzer) 用 OpenProcessToken 自采, 不依赖此字段。若未来需驱动
    //   上送 token 标志, 修复此序列化时注意与 agent TokenAnalyzer 双份计分
    //   (内核 SeDebug/SeImpersonate/SeTcb/Elevated/CrossSession 指示器 + agent)。

    /* ---- ImagePath 字符串 ---- */
    if (Process->Core.ImagePath && Process->Core.ImagePath->Length > 0) {
        ULONG bytes = Process->Core.ImagePath->Length + sizeof(WCHAR);

        body->ImagePath.Buffer = cursor;
        body->ImagePath.Length = Process->Core.ImagePath->Length;
        body->ImagePath.MaximumLength = (USHORT)bytes;
        RtlCopyMemory(cursor, Process->Core.ImagePath->Buffer, bytes);
        cursor = cursor + bytes;
    } else {
        body->ImagePath.Buffer = NULL;
        body->ImagePath.Length = 0;
        body->ImagePath.MaximumLength = 0;
    }

    /* ---- CommandLine 字符串 ---- */
    if (Process->CommandLine && Process->CommandLine->Length > 0) {
        ULONG bytes = Process->CommandLine->Length + sizeof(WCHAR);

        body->CommandLine.Buffer = cursor;
        body->CommandLine.Length = Process->CommandLine->Length;
        body->CommandLine.MaximumLength = (USHORT)bytes;
        RtlCopyMemory(cursor, Process->CommandLine->Buffer, bytes);
        cursor = cursor + bytes;
    } else {
        body->CommandLine.Buffer = NULL;
        body->CommandLine.Length = 0;
        body->CommandLine.MaximumLength = 0;
    }

    /* ---- 记录总大小 ---- */
    return ALIGN_8(cursor - Buffer);
}

//
// 发送单个进程创建事件到 Agent（同步，不走异步消息队列）
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
PmpNotifyProcessCreation(
    _In_ PWKD_PROCESS WkdProcess,
    _Out_ PBOOLEAN Denied
    )
/*++

Routine Description:

    将进程创建事件通过 ALPC 同步发送到 Agent，并阻塞等待 Agent 裁决。
    进程创建属于执行权转移操作，必须无条件进入 Agent 分析流水线。

    超时 (5s) 后默认放行，避免阻塞系统关键路径。

Arguments:

    WkdProcess - 新创建的进程对象。
    Denied     - 输出：TRUE = Agent 拒绝此进程创建。

Return Value:

    NTSTATUS。
--*/
{
    NTSTATUS status;
    SIZE_T bodySize;
    SIZE_T msgSize;
    PWKD_MESSAGE wkdMsg;
    PWKD_SYNC_REQUEST req;
    WKD_SYNC_REPLY_DATA verdict;
    LARGE_INTEGER timeout;

    *Denied = FALSE;

    bodySize = PmpCalculateProcessBodySize(WkdProcess);
    msgSize = sizeof(WKD_MESSAGE_HEADER) + bodySize;

    wkdMsg = ExAllocatePool2(POOL_FLAG_NON_PAGED, msgSize, 'PcEv');
    if (!wkdMsg) {
        return STATUS_NO_MEMORY;
    }

    ///* ---- 注册同步请求 ---- */
    //status = NtfAcquireSyncRequest(&g_SyncMgr, &verdict, sizeof(verdict), &req);
    //if (!NT_SUCCESS(status)) {
    //    /* 同步队列满 → 默认放行 */
    //    ExFreePoolWithTag(wkdMsg, 'PcEv');
    //    return STATUS_SUCCESS;
    //}

    /* ---- 填充 WKD_MESSAGE ---- */
    wkdMsg->Header.Magic = WKD_NOTIFICATION_MAGIC;
    wkdMsg->Header.Version = WKD_NOTIFICATION_VERSION;
    wkdMsg->Header.Type = WkdMessage_ProcessCreated;
    wkdMsg->Header.Source = WkdMessage_SourceProcessCallback;
    wkdMsg->Header.Priority = WkdMessage_PriorityHigh;
    KeQuerySystemTime(&wkdMsg->Header.Timestamp);
    wkdMsg->Header.SourceProcessId = WkdProcess->Core.ParentProcessId;
    wkdMsg->Header.TargetProcessId = WkdProcess->Core.ProcessId;
    // wkdMsg->Header.SyncRequestId = req->RequestId;
    wkdMsg->Header.BodySize = bodySize;

    PmpBuildProcessCreateBody(WkdProcess, wkdMsg->Body, bodySize);

    /* ---- 发送 ALPC ---- */
    status = AlpcSendWkdMessage(wkdMsg);
    ExFreePoolWithTag(wkdMsg, 'PcEv');

    if (!NT_SUCCESS(status)) {
        /*
         * Agent 未连接/发送失败：跳过同步等待，直接放行，避免创建路径
         * 阻塞 5s（对齐 SS ShadowStrikeIsServiceConnected 快速路径语义——
         * Agent 不在线时回调不阻塞，进程由 Agent 连接后的快照/基线补齐）。
         */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] PmpNotifyProcessCreation: AlpcSendWkdMessage failed "
            "for PID %p: 0x%08X, skipping sync verdict\n",
            WkdProcess->Core.ProcessId, status);
        // NtfReleaseSyncRequest(&g_SyncMgr, req);
        return STATUS_SUCCESS;
    }

    ///* ---- 同步阻塞等待 Agent 裁决（5s 超时） ---- */
    //timeout.QuadPart = -50000000LL;  /* 5 秒 */
    //status = NtfSyncWait(&g_SyncMgr, req, &timeout);

    //if (status == STATUS_SUCCESS) {
    //    *Denied = (verdict.Verdict == WkdSyncVerdict_Deny);
    //} else {
    //    /* 超时或错误 → 默认放行 */
    //    *Denied = FALSE;
    //}

    //NtfReleaseSyncRequest(&g_SyncMgr, req);
    return STATUS_SUCCESS;
}

//
// 发送进程退出事件到 Agent（通过 ALPC，使用 WKD_MESSAGE 线格式）
//
_Use_decl_annotations_
NTSTATUS
PsNotifyProcessExit(
    _In_ const PWKD_PROCESS WkdProcess,
    _In_ NTSTATUS ExitStatus
    )
/*++
Routine Description:
    将进程退出事件封装为 WKD_MESSAGE 并通过 ALPC 发送到 Agent。
    与 PmpNotifyProcessCreation 对称，但体结构为固定大小（无变长字符串）。

Arguments:
    Process    — 进程对象（调用前应已更新 Core.ExitTime / Core.Alive）。
    ExitStatus — 进程退出状态码。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;
    PWKD_MESSAGE wkdMsg;
    PWKD_MESSAGE_BODY_PROCESS_EXIT body;
    SIZE_T msgSize;

    if (!WkdProcess) return STATUS_INVALID_PARAMETER;

    msgSize = sizeof(WKD_MESSAGE_HEADER) + sizeof(WKD_MESSAGE_BODY_PROCESS_EXIT);
    wkdMsg = ExAllocatePool2(POOL_FLAG_NON_PAGED, msgSize, 'ExEv');
    if (!wkdMsg) return STATUS_NO_MEMORY;
    RtlZeroMemory(wkdMsg, msgSize);

    /* 填充 WKD_MESSAGE 头 */
    wkdMsg->Header.Magic = WKD_NOTIFICATION_MAGIC;
    wkdMsg->Header.Version = WKD_NOTIFICATION_VERSION;
    wkdMsg->Header.Type = WkdMessage_ProcessExited;
    wkdMsg->Header.Source = WkdMessage_SourceProcessCallback;
    wkdMsg->Header.Priority = WkdMessage_PriorityNormal;
    KeQuerySystemTime(&wkdMsg->Header.Timestamp);
    wkdMsg->Header.SourceProcessId = PsGetCurrentProcessId();
    wkdMsg->Header.TargetProcessId = WkdProcess->Core.ProcessId;
    wkdMsg->Header.BodySize = sizeof(WKD_MESSAGE_BODY_PROCESS_EXIT);

    /* 填充 Body */
    body = (PWKD_MESSAGE_BODY_PROCESS_EXIT)wkdMsg->Body;
    body->ProcessId = WkdProcess->Core.ProcessId;
    body->ExitCode = ExitStatus;
    body->TerminatorProcessId = PsGetCurrentProcessId();
    body->CreateTime = WkdProcess->Core.CreateTime;
    body->ExitTime = WkdProcess->Core.ExitTime;
    body->SessionId = WkdProcess->SecurityContext->SessionId;

    /* 通过 ALPC 发送 */
    status = AlpcSendWkdMessage(wkdMsg);
    ExFreePoolWithTag(wkdMsg, 'ExEv');
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] PsNotifyProcessExit failed for PID %p: 0x%X\n",
            WkdProcess->Core.ProcessId, status);
    }

    return status;
}

//
// 检查速率限流：超 1000/s 时丢弃
// 返回 TRUE = 限流命中，应跳过本次创建
//
_IRQL_requires_(PASSIVE_LEVEL)
static
BOOLEAN
PmpCheckRateLimit(
    VOID
    )
{
    LARGE_INTEGER now;
    LARGE_INTEGER windowStart;
    
    KeQuerySystemTime(&now);
    windowStart = g_WkdProcessMonitor.RateLimiter.WindowStart;

    /* 检查当前时间是否仍在窗口内 */
    if (now.QuadPart - windowStart.QuadPart < WKD_RATE_LIMIT_WINDOW_NS) {
        /* 仍在当前窗口——检查计数 */
        LONG count = InterlockedIncrement(&g_WkdProcessMonitor.RateLimiter.Counter);
        if (count > WKD_PROCESS_CREATE_RATE_LIMIT) {
            InterlockedIncrement(&g_WkdProcessMonitor.RateLimiter.DropCount);
            return TRUE;    /* 限流命中 */
        }
    }
    else {
        /* 窗口过期——重置窗口 */
        g_WkdProcessMonitor.RateLimiter.WindowStart = now;
        InterlockedExchange(&g_WkdProcessMonitor.RateLimiter.Counter, 1);
    }

    return FALSE;
}

//
// 检查池限流：上下文数是否已达上限（仅检查，不修改计数）
// 返回 TRUE = 池满，应跳过本次创建
//
_Use_decl_annotations_
BOOLEAN
PmpCheckPoolLimit(
    VOID
    )
{
    if (g_WkdProcessMonitor.PoolLimiter.ActiveContexts >= WKD_PROCESS_CONTEXT_POOL_MAX) {
        InterlockedIncrement(&g_WkdProcessMonitor.PoolLimiter.DropCount);
        return TRUE;
    }

    return FALSE;
}

//
// 在 PspDestroyProcess 中调用，更新池限流计数（递减上下文数）
//
_Use_decl_annotations_
VOID
PmpUpdatePoolLimitOnDestroy(
    VOID
    )
{
    InterlockedDecrement(&g_WkdProcessMonitor.PoolLimiter.ActiveContexts);
}

_Use_decl_annotations_
NTSTATUS
PmCreateProcess(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    NTSTATUS status;
    PWKD_PROCESS temp_WkdProcess = NULL;

    // 避免PM发生UAF
    if (!ExAcquireRundownProtection(&g_WkdProcessMonitor.RundownRef)) {
        return STATUS_REQUEST_ABORTED;
    }

    // 更新引用计数
    InterlockedIncrement(&g_WkdProcessMonitor.Statistics.ProcessCreations);

    /*
     * 速率限流（先限流再分配）
     * 超过 1000/s 时跳过创建，避免 DoS 打满内核池
     * TODO[ProcessNotify→RateLimit]: 超限时可通知 Agent 告警
     */
    if (PmpCheckRateLimit()) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Rate limit exceeded, dropping PID %p\n", ProcessId);
        status = STATUS_QUOTA_EXCEEDED;    /* 静默跳过，不影响系统 */
        goto Cleanup;
    }

    status = PspCreateProcessContext(Process, ProcessId, CreateInfo, &temp_WkdProcess);
    if (!temp_WkdProcess) {
        goto Cleanup;
    }

    /*
     * 池限流已上移至 PspCreateProcessContext 分配前检查 + 分配后递增
     * （对齐 SS PnpCheckPoolLimit 分配前检查语义），此处无需重复。
     */

    // 将Context插入全局链表
    ExInterlockedInsertTailList(&g_WkdProcessMonitor.ActiveProcessHead,
        &temp_WkdProcess->Links, &g_WkdProcessMonitor.Lock);
    InterlockedIncrement(&g_WkdProcessMonitor.Statistics.ActiveProcessCounter);
    PsReferenceWkdProcess(temp_WkdProcess);

    // 将WkdProcess插入全局哈希表
    // PID 复用防护（对齐 SS TsOnProcessCreate 创建时间校验语义）：同 PID 已有
    // 条目时比对 CreateTime——不一致说明旧进程已退出但清理遗漏（PID 复用），
    // 先摘除旧条目再插入，防止新旧上下文串号。
    {
        PWKD_PROCESS existing =
            PsLookupWkdProcessByProcessId(temp_WkdProcess->Core.ProcessId);
        if (existing) {
            if (existing->Core.CreateTime.QuadPart !=
                temp_WkdProcess->Core.CreateTime.QuadPart) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "[WkDefender] PID reuse detected for PID %p, "
                    "removing stale context\n",
                    temp_WkdProcess->Core.ProcessId);
                PmHashMapRemove(temp_WkdProcess->Core.ProcessId);
            }
            PsDereferenceWkdProcess(existing);
        }
    }

    status = CoInsertHashMap(
        &g_WkdProcessMonitor.ProcessTable,
        &temp_WkdProcess->Core.ProcessId,
        sizeof(HANDLE),
        (ULONG64)temp_WkdProcess,
        NULL
    );

    /*
     * AppControl 执行策略判定：命中哈希/路径黑名单在创建早期阻断。
     * WKD_PROCESS 已入全局链表与哈希表，goto Cleanup 由 PspDestroyProcess
     * 摘链摘表（幂等）+ 释放，安全。创建被拒的进程由 Windows 走终止回调，
     * 查表已摘，无副作用。门控 IocAcEnabled() 默认关闭（零行为变化）。
     */
    //if (IocAcEnabled() &&
    //    IocAppControlCheckProcessExecution(
    //        temp_WkdProcess->Core.ImagePath,
    //        NULL,   /* 进程创建路径无哈希（对齐 SS 异步哈希，哈希判定待 SHA256 能力） */
    //        temp_WkdProcess->Core.ProcessId,
    //        temp_WkdProcess->Core.ParentProcessId) == AcVerdict_Block) {
    //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
    //        "[WkDefender/AC] Blocked process execution: %wZ (PID=%lu)\n",
    //        temp_WkdProcess->Core.ImagePath,
    //        HandleToULong(temp_WkdProcess->Core.ProcessId));
    //    CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
    //    status = STATUS_ACCESS_DENIED;
    //    goto Cleanup;
    //}

    //
    // 记录"父进程创建子进程"行为到进程对
    // 如果父进程未被跟踪（系统初始化阶段），跳过行为记录
    // 信任覆盖（对齐 SS PnpIsTrustedProcess）：被排除的"可信外观"进程若 PPID
    // 欺骗 → 不再跳过创建 IOC 分析，使其被 IocpDetectPpidSpoofing 标记上报。
    //
    if (!temp_WkdProcess->SecurityFlags.Trusted) {
        PWKD_PROCESS parent =
            PsLookupWkdProcessByProcessId(CreateInfo->ParentProcessId);
        if (parent) {
            IOA_BEHAVIOR_RECORD_ENTRY_PROCESS_CREATE entry;

            KeQuerySystemTime(&entry.Header.TimeStamp);
            entry.ChildProcessId = temp_WkdProcess->Core.ProcessId;
            entry.CreateFlags = CreateInfo->Flags;

            AeOrchestratorDispatch(parent, temp_WkdProcess,
                WkdMessage_SourceProcessCallback, 
                WkdMessage_ProcessCreated, CreateInfo);

            PsDereferenceWkdProcess(parent);
        } else {
            /* 父进程没有被记录? 发生严重错误 */
            DbgBreakPoint();
        }
    }

    //
    // 同步发送进程创建事件到 Agent（构建进程谱系和因果图）
    // 进程创建属于执行权转移操作，无条件阻塞等待 Agent 裁决。
    //
    {
        BOOLEAN denied = FALSE;
        NTSTATUS sendStatus = PmpNotifyProcessCreation(temp_WkdProcess, &denied);
        if (!NT_SUCCESS(sendStatus)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[WkDefender] Failed to send process create event: 0x%08X\n", sendStatus);
        }
        if (denied) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WkDefender] Agent denied process creation: PID %p\n",
                temp_WkdProcess->Core.ProcessId);
            /* 补写 CreationStatus：让 Agent 同步裁决真正阻断进程创建
             * （既有缺口——此前仅销毁 WKD_PROCESS 上下文，创建未被拒） */
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            status = STATUS_ACCESS_DENIED;
            goto Cleanup;
        }
    }

    /*
     * 发射 ETW 进程创建事件
     * 对齐 SS 主回调 L1264-1291（EtwWriteProcessEvent 先行发射）：SS 在分析前
     * 对所有进程发射 ETW；wkd 的 CbEtwEmitProcessCreate 当前为 DbgPrintEx 回退
     * （EtwWrite 未接线），激活前保持注释——EtwWrite 接入后在此调用，
     * 且服务未连接/跳过的进程由入口快速路径提前 return（对齐 SS 语义）。
     * TODO[ProcessNotify→ETW]: 当前为 DbgPrintEx 回退，替换为 EtwWrite
     */
    //CbEtwEmitProcessCreate(
    //    temp_WkdProcess->Core.ProcessId,
    //    temp_WkdProcess->Core.ParentProcessId,
    //    temp_WkdProcess->Core.ImagePath);

Cleanup:
    PsDereferenceWkdProcess(temp_WkdProcess);
    ExReleaseRundownProtection(&g_WkdProcessMonitor.RundownRef);

    return status;
}

//
// 销毁进程对象
//
// 此时可以直接无锁访问，因为没有任何线程持有进程对象(RefCount=0)!!!
//
_Use_decl_annotations_
static
VOID
PspDestroyProcess(
    _In_ PWKD_PROCESS WkdProcess
    )
{
    if (!WkdProcess) return;

    /* 全局活动进程链额外持有一个 Ref - g_WkdProcessMonitor.ActiveProcessHead */
    ASSERT(WkdProcess->RefCount == 1);

    /* 释放镜像路径（先检查 UNICODE_STRING 指针本身） */
    if (CoCheckUnicodeStringValidity(WkdProcess->Core.ImagePath)) {
        ExFreePoolWithTag(WkdProcess->Core.ImagePath->Buffer, 'imgP');
        ExFreePoolWithTag(WkdProcess->Core.ImagePath, 'imgU');
    }

    /* 释放命令行（先检查指针） */
    if (CoCheckUnicodeStringValidity(WkdProcess->CommandLine)) {
        ExFreePool(WkdProcess->CommandLine->Buffer);
        ExFreePool(WkdProcess->CommandLine);
    }

    /* 清理线程上下文 */
    if (WkdProcess->ThreadContext) {
        CbDistroyThreadContext(WkdProcess);
    }

    /* 清理模块追踪上下文 */
    if (WkdProcess->ModuleContext) {
        PsDestroyWkdModuleContext(WkdProcess);
    }

    /*
     * 2026-07 迁移：IOC/IOA/评分上下文已迁至进程对，进程退出不再
     * 注销分析上下文；进程对由维护线程（60s 周期，IoaContext->ActiveBehaviors==0）
     * 回收，回收时经 PsDereferenceWkdProcessPair 释放三个上下文。
     */

    if (WkdProcess->SecurityContext) {
        ExFreePoolWithTag(WkdProcess->SecurityContext, 'secC');
    }

    /* 2026-08-10 恢复：Common\Exempts 重新引入，TrustedPID 位图清理复原 */
    /* 清理 TrustedPID（独立于分析上下文，进程退出必须清理位图） */
    ExemptsOnProcessTerminate(WkdProcess->Core.ProcessId);

    /* 区段映射画像 SectionMapProfile 为内嵌值类型，无独立分配；若未来挂
     * 逐映射记录（LRU）在此处回收（对齐 PreAcquireSection.c 死代码分区）。 */

    /* TODO[ProcessNotify→ProcessAnalyzer]: 从 ProcessAnalyzer 进程快照表中移除 */
    /* TODO[ProcessNotify→ParentChainTracker]: 通知父链追踪器断开关系 */
    /* TODO[ProcessNotify→AppControl]: 更新进程白名单 / 缓存状态 */
    /* TODO[ProcessNotify→BehaviorEngine]: 通知行为引擎停止对该进程的 IOA 追踪 */
    /* TODO[ProcessNotify→ScriptEngine]: 清理脚本引擎进程上下文 */
    /* TODO[ProcessNotify→NetworkResolver]: 通知网络模块释放与该进程关联的连接追踪 */
    /* TODO[ProcessNotify→RegistryAccessor]: 清理注册表访问追踪上下文 */

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_WkdProcessMonitor.Lock, &oldIrql);
    RemoveEntryList(&WkdProcess->Links);
    KeReleaseSpinLock(&g_WkdProcessMonitor.Lock, oldIrql);
    InterlockedDecrement(&g_WkdProcessMonitor.Statistics.ActiveProcessCounter);

    /* 递减池限流计数（分配时递增，销毁必递减，严格配对） */
    PmpUpdatePoolLimitOnDestroy();

    /* 清理内存区域追踪（MemoryMonitor 迁移 2026-08）：遍历释放区域节点。
     * 必须在释放 WKD_PROCESS 之前调用（MemRegionState 内嵌其中）。 */
    WkdMemRegionCleanupProcess(&WkdProcess->MemRegionState);

    ObfDereferenceObject(WkdProcess->Core.EProcess);
    ExFreePoolWithTag(WkdProcess, 'proc');
}

//
// 从 EPROCESS 创建进程上下文（用于枚举已有进程，无 CreateInfo）
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
PmpCreateExistingProcess(
    _In_ PSYSTEM_PROCESS_INFORMATION ProcessInfo,
    _Outptr_ PWKD_PROCESS* WkdProcess
    )
{
    NTSTATUS status;
    PEPROCESS eprocess;
    PWKD_PROCESS temp_WkdProcess;

    if (!ProcessInfo || !WkdProcess) {
        return STATUS_INVALID_PARAMETER;
    }
    *WkdProcess = NULL;

    /* 池限流检查（分配前，对齐 SS PnpCheckPoolLimit）。枚举已有进程同样受
     * 4096 上限约束——池满时跳过该进程，由下轮快照补全。 */
    if (PmpCheckPoolLimit()) {
        return STATUS_QUOTA_EXCEEDED;
    }

    temp_WkdProcess = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(WKD_PROCESS), 'proc');
    if (!temp_WkdProcess) {
        return STATUS_NO_MEMORY;
    }

    /* 分配成功即递增池计数（PspDestroyProcess 无条件递减，严格配对） */
    InterlockedIncrement(&g_WkdProcessMonitor.PoolLimiter.ActiveContexts);

    /* 绑定引用计数，直到进程退出时释放 */
    status = PsLookupProcessByProcessId(ProcessInfo->UniqueProcessId, &eprocess);
    if (!NT_SUCCESS(status)) goto Cleanup;

    /* Step 1: 设置Context的基本信息 */
    RtlZeroMemory(temp_WkdProcess, sizeof(WKD_PROCESS));
    temp_WkdProcess->RefCount = 1;  /* 返回给调用者 */
    temp_WkdProcess->Core.Alive = TRUE;
    temp_WkdProcess->Core.ProcessId = ProcessInfo->UniqueProcessId;
    temp_WkdProcess->Core.ParentProcessId = ProcessInfo->InheritedFromUniqueProcessId;
    temp_WkdProcess->Core.EProcess = eprocess;
    temp_WkdProcess->Core.CreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(eprocess);

    /* 初始化区段映射画像（PreAcquireSection 迁移 2026-08），同 PmCreateProcess */
    temp_WkdProcess->SectionMapProfile.WindowStartTime =
        temp_WkdProcess->Core.CreateTime;
    temp_WkdProcess->SectionMapProfile.IsEarlyProcess = TRUE;

    /* Step 2: 解析字符串 */
    {
        PUNICODE_STRING rawPath = NULL;

        status = SeLocateProcessImageName(eprocess, &rawPath);
        if (!NT_SUCCESS(status) ||
            !rawPath || !rawPath->Buffer || rawPath->Length == 0) {
            rawPath = &ProcessInfo->ImageName;
        }

        status = CoNormalizeDosPath(rawPath, &temp_WkdProcess->Core.ImagePath);
        if (!NT_SUCCESS(status)) goto Cleanup;

        /* 获取命令行（非致命——失败时保留 NULL，后续仍可分析） */
        // PmpQueryProcessCommandLine(eprocess, &temp_WkdProcess->CommandLine);
    }

    ///* 获取进程完整性等级和安全标志 */
    //{
    //    PACCESS_TOKEN token = PsReferencePrimaryToken(temp_WkdProcess->Core.EProcess);
    //    if (token) {
    //        SeQueryInformationToken(token, TokenIntegrityLevel,
    //            (PVOID)&temp_WkdProcess->IntegrityLevel);
    //        PsDereferencePrimaryToken(token);
    //    }
    //    temp_WkdProcess->SecurityFlags.System = HandleToULong(temp_WkdProcess->Core.ProcessId) <= 4;
    //}

    /* Step 3: 初始化相关上下文
     * （线程上下文已下沉至 PspCreateProcessContextInternal 急切创建，此处无需重复） */
    status = PspCreateProcessContextInternal(temp_WkdProcess);
    if (!NT_SUCCESS(status)) goto Cleanup;

    //
    // 插入活动进程链表（自旋锁保护）
    //
    ExInterlockedInsertTailList(
        &g_WkdProcessMonitor.ActiveProcessHead,
        &temp_WkdProcess->Links,
        &g_WkdProcessMonitor.Lock);
    InterlockedIncrement( &g_WkdProcessMonitor.Statistics.ActiveProcessCounter);
    PsReferenceWkdProcess(temp_WkdProcess);

    // 将WkdProcess插入全局哈希表
    status = CoInsertHashMap(
        &g_WkdProcessMonitor.ProcessTable,
        &temp_WkdProcess->Core.ProcessId,
        sizeof(HANDLE),
        (ULONG64)temp_WkdProcess,
        NULL    // 不存在重复的可能性? pid重用?
    );
    
    *WkdProcess = temp_WkdProcess;

    return STATUS_SUCCESS;

Cleanup:
    if (eprocess) ObDereferenceObject(eprocess);
    PspDestroyProcess(temp_WkdProcess);

    return status;
}

//
// 将活动进程链表中所有进程打包为快照发送到 Agent
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
PmpSendProcessSnapshot(
    VOID
    )
/*++
Routine Description:
    遍历活动进程链表，为每个进程构造独立的 WKD_MESSAGE，
    通过 AlpcSendWkdMessageBatch 统一打包到一个 ALPC 消息中发送到 Agent。

    每个 WKD_MESSAGE:
      Header.Type           = WkdMessage_ProcessCreated
      Header.SourceProcessId = 父进程 PID
      Header.TargetProcessId = 子进程 PID

Arguments:
    无。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG processCount = 0;
    PWKD_MESSAGE* msgArray = NULL;
    PWKD_MESSAGE wkdMsg;
    ULONG bodySize;
    ULONG msgSize;
    PLIST_ENTRY entry;
    KIRQL oldIrql;
    PWKD_PROCESS temp_WkdProcess;

    /*
     * 第一遍遍历：统计进程数
     */
    KeAcquireSpinLock(&g_WkdProcessMonitor.Lock, &oldIrql);

    for (entry = g_WkdProcessMonitor.ActiveProcessHead.Flink;
         entry != &g_WkdProcessMonitor.ActiveProcessHead;
         entry = entry->Flink) {
        processCount++;
    }

    if (processCount == 0) {
        KeReleaseSpinLock(&g_WkdProcessMonitor.Lock, oldIrql);
        return STATUS_SUCCESS;
    }

    /* 分配 WKD_MESSAGE 指针数组 */
    msgArray = ExAllocatePool2(POOL_FLAG_NON_PAGED,
        processCount * sizeof(PWKD_MESSAGE), 'PsSn');
    if (!msgArray) {
        KeReleaseSpinLock(&g_WkdProcessMonitor.Lock, oldIrql);
        return STATUS_NO_MEMORY;
    }

    /*
     * 第二遍遍历：为每个进程构造独立的 WKD_MESSAGE
     */
    ULONG i = 0;
    for (entry = g_WkdProcessMonitor.ActiveProcessHead.Flink;
         entry != &g_WkdProcessMonitor.ActiveProcessHead && i < processCount;
         entry = entry->Flink, i++) {

        temp_WkdProcess = CONTAINING_RECORD(entry, WKD_PROCESS, Links);
        bodySize = PmpCalculateProcessBodySize(temp_WkdProcess);
        msgSize = sizeof(WKD_MESSAGE_HEADER) + bodySize;

        wkdMsg = ExAllocatePool2(POOL_FLAG_NON_PAGED, msgSize, 'PsSn');
        if (!wkdMsg) {
            /* 释放已分配的消息后退出 */
            for (ULONG j = 0; j < i; j++) {
                ExFreePoolWithTag(msgArray[j], 'PsSn');
            }
            ExFreePoolWithTag(msgArray, 'PsSn');
            KeReleaseSpinLock(&g_WkdProcessMonitor.Lock, oldIrql);
            return STATUS_NO_MEMORY;
        }

        /* 填充 WKD_MESSAGE 头 */
        wkdMsg->Header.Magic = WKD_NOTIFICATION_MAGIC;
        wkdMsg->Header.Version = WKD_NOTIFICATION_VERSION;
        wkdMsg->Header.Type = WkdMessage_ProcessCreated;
        wkdMsg->Header.Source = WkdMessage_SourceProcessCallback;
        wkdMsg->Header.Priority = WkdMessage_PriorityNormal;
        KeQuerySystemTime(&wkdMsg->Header.Timestamp);
        wkdMsg->Header.SourceProcessId = temp_WkdProcess->Core.ParentProcessId;
        wkdMsg->Header.TargetProcessId = temp_WkdProcess->Core.ProcessId;
        wkdMsg->Header.BodySize = bodySize;

        /* 填充 Body */
        PmpBuildProcessCreateBody(temp_WkdProcess, wkdMsg->Body, bodySize);

        msgArray[i] = wkdMsg;
    }

    KeReleaseSpinLock(&g_WkdProcessMonitor.Lock, oldIrql);

    /*
     * 批量 ALPC 发送
     */
    status = AlpcSendWkdMessageBatch(
        WkdAlpcMessage_ProcessSnapshot,
        msgArray,
        processCount);

    /* 释放所有 WKD_MESSAGE */
    for (i = 0; i < processCount; i++) {
        ExFreePoolWithTag(msgArray[i], 'PsSn');
    }
    ExFreePoolWithTag(msgArray, 'PsSn');

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Process snapshot sent: %u processes, status=0x%X\n",
        processCount, status);

    return status;
}

//
// 枚举系统中已有进程并填充全局进程表
// 必须在 CbProcessNotifyInitialize() 之后调用，确保进程创建回调已注册
//
_Use_decl_annotations_
NTSTATUS
PmEnumerateProcesses(
    VOID
    )
{
    NTSTATUS status;
    ULONG bufferSize = 0;
    ULONG returnLength = 0;
    ULONG enumCount = 0;
    PSYSTEM_PROCESS_INFORMATION processInfo, current;

    //
    // 第一次调用获取所需缓冲区大小
    //
    status = pfnZwQuerySystemInformation(
        SystemProcessInformation,
        NULL,
        0,
        &returnLength
    );

    if (returnLength == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    //
    // 分配缓冲区（预留额外空间防止枚举期间进程数增长）
    //
    bufferSize = returnLength + PAGE_SIZE;
    processInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        bufferSize,
        'proE'
    );
    if (!processInfo) {
        return STATUS_NO_MEMORY;
    }

    //
    // 第二次调用获取实际数据
    //
    status = pfnZwQuerySystemInformation(
        SystemProcessInformation,
        processInfo,
        bufferSize,
        &returnLength
    );
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(processInfo, 'proE');
        return status;
    }

    //
    // 遍历进程列表，跳过 Idle (PID=0)
    //
    current = processInfo;
    for (;;) {
        if (current->UniqueProcessId) {
            //
            // 检查是否已在表中（回调可能已先于枚举插入）
            //
            PWKD_PROCESS temp_WkdProcess = PsLookupWkdProcessByProcessId(current->UniqueProcessId);
            if (!temp_WkdProcess) {
                status = PmpCreateExistingProcess(
                    current,
                    &temp_WkdProcess);
                if (NT_SUCCESS(status)) {
                    enumCount++;
                    PsDereferenceWkdProcess(temp_WkdProcess);
                }
            }
            else {
                //
                // 进程已通过回调插入到表中，释放查找引用
                //
                PsDereferenceWkdProcess(temp_WkdProcess);
            }

            // DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Process: %wZ\n", temp_WkdProcess->Core.ImagePath);
        }

        if (current->NextEntryOffset == 0) {
            break;
        }

        current = (PSYSTEM_PROCESS_INFORMATION)(
            (PUCHAR)current + current->NextEntryOffset
        );
    }

    ExFreePoolWithTag(processInfo, 'proE');

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Enumerated %u existing processes\n", enumCount);

    //
    // 枚举完成后，将全部进程打包为快照发送到 Agent
    //
    {
        status = PmpSendProcessSnapshot();
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[WkDefender] Failed to send process snapshot: 0x%X\n", status);
        }
    }

    return STATUS_SUCCESS;
}

//
// 从映射表删除
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PmHashMapRemove(
    _In_ HANDLE ProcessId
    )
{
    BOOLEAN removed = CoRemoveHashMapEntry(
        &g_WkdProcessMonitor.ProcessTable,
        &ProcessId,
        sizeof(HANDLE));
    return removed ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

//
// 采集命令行 — 使用 ZwQueryInformationProcess(ProcessCommandLineInformation)
//
// 从目标 EPROCESS 打开内核句柄，通过 ProcessCommandLineInformation 信息类
// 读取进程的完整命令行字符串。结果以分配的 UNICODE_STRING 返回，
// 调用者负责释放 CommandLine->Buffer（使用 'cmdL' tag）。
//
// 注意：ZwQueryInformationProcess 自 Windows 7 起支持 ProcessCommandLineInformation。
//
_Use_decl_annotations_
NTSTATUS
PmpQueryProcessCommandLine(
    _In_ const PEPROCESS EProcess,
    _Out_ PUNICODE_STRING* CommandLine
    )
{
    NTSTATUS status;
    HANDLE processHandle;
    ULONG returnLength;
    PUNICODE_STRING cmdLine;

    if (!EProcess || !CommandLine) {
        return STATUS_INVALID_PARAMETER;
    }
    *CommandLine = NULL;

    //
    // 从 EPROCESS 打开内核句柄（需要 PROCESS_QUERY_INFORMATION + PROCESS_VM_READ
    // 来读取 PEB 中的 ProcessParameters->CommandLine）
    //
    status = ObOpenObjectByPointer(
        EProcess,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        &processHandle
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] PmpQueryProcessCommandLine: ObOpenObjectByPointer failed: 0x%08X\n",
            status);
        return status;
    }

    //
    // Phase 1: 查询所需缓冲区大小
    //
    status = pfnZwQueryInformationProcess(
        processHandle,
        ProcessCommandLineInformation,
        NULL,
        0,
        &returnLength
    );

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] PmpQueryProcessCommandLine: size query failed: 0x%08X\n", status);
        goto Close;
    }

    if (returnLength == 0) {
        /* 空命令行，不是错误 */
        status = STATUS_SUCCESS;
        goto Close;
    }

    //
    // Phase 2: 分配缓冲区并查询实际命令行（返回值为PUNICODE_STRING）
    //
    cmdLine = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, returnLength, 'cmdL');
    if (!cmdLine) {
        status = STATUS_NO_MEMORY;
        goto Close;
    }

    status = pfnZwQueryInformationProcess(
        processHandle,
        ProcessCommandLineInformation,
        cmdLine,
        returnLength,
        &returnLength
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] PmpQueryProcessCommandLine: data query failed: 0x%08X\n", status);
        goto Cleanup;
    }

    *CommandLine = cmdLine;
    status = STATUS_SUCCESS;
    goto Close;

Cleanup:
    if (cmdLine) ExFreePoolWithTag(cmdLine, 'cmdL');
Close:
    ZwClose(processHandle);

    return status;
}

//
// 检查镜像异常
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
PmCheckImageAnomaly(
    _In_ PWKD_PROCESS Process
    )
{
    UNREFERENCED_PARAMETER(Process);
    return FALSE;
}

//
// 检查文件属性
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
PmCheckFileAttributes(
    _In_ PWKD_PROCESS Process
    )
{
    UNREFERENCED_PARAMETER(Process);
    return FALSE;
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
// [死代码] 进程上下文清理兜底（对齐 SS PnpCleanupStaleContexts L4888-5006）
// 功能：周期遍历活跃进程表，回收两类遗漏上下文：
//   1. 已标记终止（ExitTime≠0）且超时（5min）未回收的——终止回调后引用未归零；
//   2. 未标记终止但实际已退出（PsGetProcessExitStatus≠PENDING）——终止回调遗漏。
// 不接入原因：wkd 终止路径（CbpHanleProcessTermination Phase 4）已引用驱动
//   回收；AepPerformMaintenance（AnalysisEngine.c:137，60s）仅清理进程对，
//   WKD_PROCESS 层无周期兜底。激活前需核对引用配对（见下方注释）并确认
//   wkd 终止路径无泄漏窗口。
// 激活条件：确认终止路径存在泄漏场景后，在周期线程挂接本函数。
//
#define PN_CONTEXT_TIMEOUT_MS   300000          // 5 分钟（对齐 SS PN_CONTEXT_TIMEOUT_MS）
#define PN_CLEANUP_STALE_MAX    128             // 单轮回收上限（防单轮 CPU 独占）

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
PnpCleanupStaleContexts(
    VOID
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PLIST_ENTRY next;
    PWKD_PROCESS process;
    LARGE_INTEGER now;
    LARGE_INTEGER timeout;
    PWKD_PROCESS stalePids[PN_CLEANUP_STALE_MAX];
    ULONG staleCount = 0;

    KeQuerySystemTime(&now);
    timeout.QuadPart = (LONGLONG)PN_CONTEXT_TIMEOUT_MS * 10000;

    /* 锁内收集 stale 进程（对齐 SS：锁内只收集 + 引用，锁外移除最小化持锁） */
    KeAcquireSpinLock(&g_WkdProcessMonitor.Lock, &oldIrql);

    for (entry = g_WkdProcessMonitor.ActiveProcessHead.Flink;
         entry != &g_WkdProcessMonitor.ActiveProcessHead &&
             staleCount < PN_CLEANUP_STALE_MAX;
         entry = next) {

        next = entry->Flink;
        process = CONTAINING_RECORD(entry, WKD_PROCESS, Links);

        BOOLEAN shouldRemove = FALSE;

        if (process->Core.ExitTime.QuadPart != 0) {
            /* 已标记终止，超时兜底（对齐 SS L4930-4935） */
            if ((now.QuadPart - process->Core.ExitTime.QuadPart) > timeout.QuadPart) {
                shouldRemove = TRUE;
            }
        } else {
            /* 未标记终止但实际已退出（终止回调遗漏，对齐 SS L4942-4952） */
            if (process->Core.EProcess != NULL &&
                PsGetProcessExitStatus(process->Core.EProcess) != STATUS_PENDING) {
                shouldRemove = TRUE;
            }
        }

        if (shouldRemove) {
            PsReferenceWkdProcess(process);
            stalePids[staleCount++] = process;
        }
    }

    KeReleaseSpinLock(&g_WkdProcessMonitor.Lock, oldIrql);

    /* 锁外移除（对齐 SS L4978-5005）。
     * 引用配对（激活时需核对）：
     *   收集 +1                   → PsDereferenceWkdProcess（释放收集引用）
     *   表引用（插入时 +1）        → PmHashMapRemove 触发 Dereference 释放
     *   基础引用（创建时 1）       → PsDereferenceWkdProcess（归零 → PspDestroyProcess 摘链+释放） */
    for (ULONG i = 0; i < staleCount; i++) {
        process = stalePids[i];

        PmHashMapRemove(process->Core.ProcessId);
        PsDereferenceWkdProcess(process);
        PsDereferenceWkdProcess(process);
    }
}

#pragma warning(pop)







