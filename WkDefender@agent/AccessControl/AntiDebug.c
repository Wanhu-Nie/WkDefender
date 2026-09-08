/**************************************************/
/*  WkDefender Agent — 反调试检测引擎实现            */
/*                                                     */
/*  纯 C 实现 ShadowStrike AntiDebug 迁移（核心）。     */
/*                                                     */
/*  包含：                                            */
/*   - PEB/TEB 检测（BeingDebugged/NtGlobalFlag/堆标志）*/
/*   - DebugPort / DebugObjectHandle 检测              */
/*   - RDTSC 时序检测                                  */
/*   - 硬件断点检测（GetThreadContext Dr0-3/Dr7）       */
/*   - 调试器进程/窗口快照（基础）                      */
/*   - 线程防护（ThreadHideFromDebugger + 清调试寄存器）*/
/*   - 周期监测线程                                    */
/*   - 分级处置 + 回调上报                              */
/*                                                     */
/*  编码：UTF-8 with BOM（铁律）                       */
/**************************************************/

#include "AntiDebug.h"
#include "AccessControlEngine.h"  /* 公共契约：SP_SEVERITY_* / SP_STATUS_ALREADY_RUNNING */
#include "../Process/ProcessModule.h"  /* PsLookupModuleInstanceByName（模块实例链按名查基址） */
#include "../IOC/PEAnalyzer/PeAnalyzer.h"  /* PeVerifyFunctionAddressTable（统一双 reader 导入/延迟校验门面, 2026-09-07） */
#include "../Common/Utils.h"            /* CoOpenProcessForQueryRead（跨进程最小句柄, 2026-09-07 自本文件迁出） */

#include "../Process/ProcessTree.h"     /* WkdProcessTree.PidMap hashmap enum, 2026-09-08 */
#include <intrin.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

/* ------------------------------------------------------------------ */
/* 私有类型                                                           */
/* ------------------------------------------------------------------ */

/* 线程信息类（NtSetInformationThread） */
#define AD_THREAD_HIDE_FROM_DEBUGGER  17

/* 单进程线程枚举上限（AcpVerifyProtectedProcessAntiDebug 链扫描线程防护） */
#define AD_MAX_THREADS_PER_PROCESS    512

/* 进程信息类（NtQueryInformationProcess） */
#define AD_PROCESS_DEBUG_OBJECT_HANDLE 30 /* ProcessDebugObjectHandle */
#define AD_PROCESS_DEBUG_FLAGS        31  /* ProcessDebugFlags */

typedef NTSTATUS (NTAPI *PNT_QUERY_INFO_PROCESS)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *PNT_SET_INFO_THREAD)(
    HANDLE, ULONG, PVOID, ULONG);

/* 反调试引擎上下文 */
struct _AC_ANTIDEBUG_PROTECTION {
    CRITICAL_SECTION    Lock;               /* 保护上下文 */
    AD_CALLBACKS        Callbacks;          /* 回调集合 */
    BOOLEAN             Initialized;        /* 初始化完成 */

    /* 历史环形缓冲 */
    AD_EVENT            History[AD_MAX_HISTORY];
    ULONG               HistoryHead;        /* 写入位置 */
    ULONG               HistoryCount;

    /* 统计 */
    AD_STATISTICS       Stats;

    /* 受保护线程标记 */
    BOOLEAN             ThreadProtected;

    /* 检测项使能位图（policy 使能开关, 2026-09-06；2026-09-07：位图即最终使能，
     * AD_MASK_ALL=全激活 / AD_MASK_NONE=0=全关闭，无哨兵语义） */
    ULONG64             DetectionMask;

    /* 周期监测线程 */
    HANDLE              MonitorThread;
    HANDLE              MonitorStopEvent;
    volatile BOOLEAN    MonitorRunning;
    ULONG               MonitorIntervalMs;

    /* 动态导入的 NT 函数 */
    PNT_QUERY_INFO_PROCESS NtQueryInformationProcess;
    PNT_SET_INFO_THREAD    NtSetInfoThread;
};

/* ------------------------------------------------------------------ */
/* 私有函数声明                                                       */
/* ------------------------------------------------------------------ */

_Must_inspect_result_
static
NTSTATUS
AdQueryProcessDebugInfo(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ ULONG InfoClass,
    _Out_ PVOID Out,
    _In_ ULONG OutSize
    );

_Must_inspect_result_
static VOID AdRecordEvent(PAC_ANTIDEBUG_PROTECTION Protection, PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result);
static VOID AdDispatchDetection(PAC_ANTIDEBUG_PROTECTION Protection, PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result);
static DWORD WINAPI AcpAntiDebugRoutine(LPVOID Param);
static NTSTATUS AdClearHardwareBreakpoints(PAC_ANTIDEBUG_PROTECTION Protection);
static NTSTATUS AdHideThreadFromDebugger(PAC_ANTIDEBUG_PROTECTION Protection);
/* 统一目标扫描（2026-09-06）：AcpVerifySignalProtectedProcessAntiDebug 对自身/受保护进程
 * 统一以谱系树 WKD_PROCESS 为目标（持引用防 UAF）执行检测块表（单编排循环，无第二套调度）。 */

/* SEH 辅助原子操作（POD，规避 MSVC 在带 __try 函数内声名局部对象的问题） */
static BOOLEAN AdSehReadUlong(const VOID* Addr, PULONG Out);
static BOOLEAN AdSehReadPointer(const VOID* Addr, PVOID* Out);
static SIZE_T  AdSehReadBytes(const BYTE* Src, BYTE* Dst, SIZE_T Size);
static BOOLEAN AdSehInt3Swallowed(VOID);
static BOOLEAN AdSehGuardPageSwallowed(PVOID GuardPage);
static BOOLEAN AdSehRaiseAccessViolation(VOID);

/* ------------------------------------------------------------------ */
/* 已知调试器/插桩框架签名清单                                         */
/*  对齐 SS DebuggerProcesses/WindowClasses/Drivers/Instrumentation。  */
/* ------------------------------------------------------------------ */

const WCHAR* const AdDebuggerProcessNames[] = {
    L"ollydbg.exe", L"x64dbg.exe", L"x32dbg.exe", L"windbg.exe",
    L"ida.exe", L"ida64.exe", L"idag.exe", L"idag64.exe",
    L"idaw.exe", L"idaw64.exe", L"idaq.exe", L"idaq64.exe",
    L"radare2.exe", L"r2.exe", L"ghidra.exe", L"immunity debugger.exe",
    L"devenv.exe", L"dbgview.exe", L"procmon.exe", L"procexp.exe",
    L"wireshark.exe", L"fiddler.exe", L"apimonitor.exe", L"dnspy.exe",
    L"cheatengineine.exe"
};

const WCHAR* const AdDebuggerWindowClasses[] = {
    L"OLLYDBG", L"X64DBG", L"X32DBG", L"WinDbgFrameClass",
    L"IDASteelClass", L"Qt5QWindowIcon", L"TIdaWindow", L"Rock Debugger",
    L"GHIDRA", L"ImmunityDebugger", L"SoftICE", L"PROCMON_WINDOW_CLASS",
    L"ProcessExplorer", L"APIMonitor", L"dnSpy"
};

const WCHAR* const AdDebuggerDrivers[] = {
    L"SICE", L"SIWVID", L"NTICE", L"ICEEXT", L"SYSER",
    L"SYSERDEBUGGER", L"REGMON", L"FILEMON", L"DBGHELP", L"PROCMON"
};

const WCHAR* const AdInstrumentationSignatures[] = {
    L"frida", L"dynamorio", L"pin", L"valgrind",
    L"drmemory", L"apimonitor", L"winapis", L"detours"
};

/* ------------------------------------------------------------------ */
/* 安全内存读取                                                       */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
BOOLEAN
AdSafeReadMemory(
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    )
{
    if (!Address || !Buffer || Size == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if ((ULONG_PTR)Address + Size < (ULONG_PTR)Address) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    __try {
        RtlCopyMemory(Buffer, Address, Size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(GetExceptionCode());
        return FALSE;
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* SEH 原子助手（AWPOD 类型，规避 MSVC 对带 __try 函数内声明非 POD   */
/*  局部对象的限制）。                                                */
/* ------------------------------------------------------------------ */

BOOLEAN
AdSehReadUlong(
    _In_ const VOID* Addr,
    _Out_ PULONG Out
    )
{
    __try {
        *Out = *(const volatile ULONG*)Addr;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

BOOLEAN
AdSehReadPointer(
    _In_ const VOID* Addr,
    _Out_ PVOID* Out
    )
{
    __try {
        *Out = *(volatile PVOID*)Addr;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

SIZE_T
AdSehReadBytes(
    _In_ const BYTE* Src,
    _Out_ BYTE* Dst,
    _In_ SIZE_T Size
    )
{
    SIZE_T i;
    for (i = 0; i < Size; i++) {
        __try {
            Dst[i] = Src[i];
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return i;
        }
    }
    return i;
}

/* INT3 例外：返回 TRUE=正常捕获（无调试器），FALSE=被调试器吞掉。 */
BOOLEAN
AdSehInt3Swallowed(
    VOID
    )
{
    __try {
        __debugbreak();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return TRUE;
    }
    return FALSE;
}

/* GuardPage 例外：返回 TRUE=正常捕获（无调试器），FALSE=被调试器吞掉。 */
BOOLEAN
AdSehGuardPageSwallowed(
    _In_ PVOID GuardPage
    )
{
    __try {
        volatile BYTE* p = (volatile BYTE*)GuardPage;
        *p = 0x42;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return TRUE;
    }
    return FALSE;
}

/* 主动抛 ACCESS_VIOLATION 供 VEH 链验证：返回 TRUE=SEH 捕获。 */
BOOLEAN
AdSehRaiseAccessViolation(
    VOID
    )
{
    __try {
        RaiseException(0xC0000005UL, 0, 0, NULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return TRUE;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* NT 动态导入                                                        */
/* ------------------------------------------------------------------ */

static
PNT_QUERY_INFO_PROCESS
AdGetNtQueryInformationProcess(VOID)
{
    static PNT_QUERY_INFO_PROCESS sFn = NULL;
    static volatile LONG sResolved = 0;
    if (InterlockedCompareExchange(&sResolved, 1, 0) == 0) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            sFn = (PNT_QUERY_INFO_PROCESS)GetProcAddress(ntdll, "NtQueryInformationProcess");
        }
    }
    return sFn;
}

static
PNT_SET_INFO_THREAD
AdGetNtSetInfoThread(VOID)
{
    static PNT_SET_INFO_THREAD sFn = NULL;
    static volatile LONG sResolved = 0;
    if (InterlockedCompareExchange(&sResolved, 1, 0) == 0) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            sFn = (PNT_SET_INFO_THREAD)GetProcAddress(ntdll, "NtSetInformationThread");
        }
    }
    return sFn;
}

/* ------------------------------------------------------------------ */
/* 生命周期                                                           */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
NTSTATUS
SpInitializeAntiDebugProtection(
    _Out_ PAC_ANTIDEBUG_PROTECTION* Protection,
    _In_opt_ PAD_CALLBACKS Callbacks
    )
{
    PAC_ANTIDEBUG_PROTECTION engine;

    if (!Protection) return STATUS_INVALID_PARAMETER;
    *Protection = NULL;

    engine = (PAC_ANTIDEBUG_PROTECTION)malloc(sizeof(AC_ANTIDEBUG_PROTECTION));
    if (!engine) return STATUS_NO_MEMORY;
    RtlZeroMemory(engine, sizeof(AC_ANTIDEBUG_PROTECTION));

    InitializeCriticalSection(&engine->Lock);

    if (Callbacks) {
        engine->Callbacks = *Callbacks;
    }

    engine->Initialized = TRUE;
    engine->HistoryHead = 0;
    engine->HistoryCount = 0;
    engine->ThreadProtected = FALSE;
    engine->DetectionMask = AD_MASK_ALL;   /* 默认全激活（EDR 自身，显式全位） */
    engine->MonitorRunning = FALSE;
    engine->MonitorThread = NULL;
    engine->MonitorStopEvent = NULL;
    engine->MonitorIntervalMs = AD_DEFAULT_MONITOR_INTERVAL_MS;

    engine->NtQueryInformationProcess = AdGetNtQueryInformationProcess();
    engine->NtSetInfoThread = AdGetNtSetInfoThread();

    GetSystemTimeAsFileTime((LPFILETIME)&engine->Stats.StartTime);

    *Protection = engine;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
AdCleanup(
    _In_opt_ _Post_invalid_ PAC_ANTIDEBUG_PROTECTION Protection
    )
{
    if (!Protection) return;
    (VOID)AdStopMonitoring(Protection);

    DeleteCriticalSection(&Protection->Lock);
    free(Protection);
}

/* ------------------------------------------------------------------ */
/* 调试器附加检测                                                     */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
NTSTATUS
AdIsDebuggerAttached(
    _In_ PAC_ANTIDEBUG_PROTECTION Protection,
    _Out_ PBOOLEAN DebuggerPresent
    )
{
    ULONG_PTR debugPort = 0;

    if (!Protection || !DebuggerPresent) return STATUS_INVALID_PARAMETER;
    *DebuggerPresent = FALSE;

    if (!Protection->NtQueryInformationProcess) return STATUS_PROCEDURE_NOT_FOUND;

    (VOID)AdQueryProcessDebugInfo(Protection, ProcessDebugPort, &debugPort, sizeof(debugPort));
    *DebuggerPresent = (debugPort != 0);
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* 底层检测实现                                                       */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
static
NTSTATUS
AdQueryProcessDebugInfo(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ ULONG InfoClass,
    _Out_ PVOID Out,
    _In_ ULONG OutSize
    )
{
    if (!Protection || !Out || OutSize == 0) return STATUS_INVALID_PARAMETER;
    if (!Protection->NtQueryInformationProcess) return STATUS_PROCEDURE_NOT_FOUND;

    return Protection->NtQueryInformationProcess(
        GetCurrentProcess(),
        InfoClass,
        Out,
        OutSize,
        NULL);
}

/* ------------------------------------------------------------------ */
/* 检测记录与分发                                                     */
/* ------------------------------------------------------------------ */

static
VOID
AdRecordEvent(
    _In_ PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    PAD_EVENT ev;
    WCHAR pname[64];

    pname[0] = 0;
    {
        DWORD pid = GetCurrentProcessId();
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe;
        if (snap != INVALID_HANDLE_VALUE) {
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (pe.th32ProcessID == pid) {
                        wcscpy_s(pname, 64, pe.szExeFile);
                        break;
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
    }

    EnterCriticalSection(&Protection->Lock);
    ev = &Protection->History[Protection->HistoryHead];
    ev->Technique = Result->Technique;
    ev->Confidence = Result->Confidence;
    ev->Score = Result->Score;
    ev->Severity = Result->Severity;
    ev->ProcessId = (HANDLE)(ULONG_PTR)GetCurrentProcessId();
    wcscpy_s(ev->ProcessName, 64, pname[0] ? pname : L"<current>");
    GetSystemTimeAsFileTime((LPFILETIME)&ev->Timestamp);
    wcscpy_s(ev->Description, 256, Result->Description);

    Protection->HistoryHead = (Protection->HistoryHead + 1) % AD_MAX_HISTORY;
    if (Protection->HistoryCount < AD_MAX_HISTORY) {
        Protection->HistoryCount++;
    }
    Protection->Stats.TotalDetections++;

    /* 按分类累加统计（对齐 SS AntiDebugStatistics） */
    switch (Result->Technique) {
        case AdTechniquePebBeingDebugged:
        case AdTechniquePebHeapFlags:
        case AdTechniquePebNtGlobalFlag:
        case AdTechniquePebProcessHeap:
            Protection->Stats.PebDetections++;
            break;
        case AdTechniqueIsDebuggerPresent:
        case AdTechniqueNtQueryDebugPort:
        case AdTechniqueNtQueryDebugFlags:
        case AdTechniqueNtQueryDebugObject:
        case AdTechniqueNtQueryProcessBasic:
        case AdTechniqueOutputDebugString:
        case AdTechniqueCloseHandle:
            Protection->Stats.ApiDetections++;
            break;
        case AdTechniqueTimingRdtsc:
        case AdTechniqueTimingQueryPerf:
        case AdTechniqueTimingGetTickCount:
        case AdTechniqueTimingInstruction:
            Protection->Stats.TimingDetections++;
            break;
        case AdTechniqueHardwareBreakpoint:
        case AdTechniqueHardwareContext:
            Protection->Stats.HardwareDetections++;
            Protection->Stats.HardwareBreakpointsFound = TRUE;
            break;
        case AdTechniqueExceptionInt3:
        case AdTechniqueExceptionGuardPage:
        case AdTechniqueExceptionVeh:
        case AdTechniqueExceptionTrap:
            Protection->Stats.ExceptionDetections++;
            break;
        case AdTechniqueMemoryIatHook:
        case AdTechniqueMemoryDelayImport:
            Protection->Stats.MemoryDetections++;
            Protection->Stats.HooksDetected++;
            break;
        case AdTechniqueProcessDebugger:
        case AdTechniqueWindowDebugger:
        case AdTechniqueKernelDebugger:
        case AdTechniqueDebuggerDriver:
        case AdTechniqueParentProcess:
            Protection->Stats.ProcessDetections++;
            break;
        default:
            Protection->Stats.InstrumentationDetections++;
            break;
    }
    LeaveCriticalSection(&Protection->Lock);
}

static
VOID
AdDispatchDetection(
    _In_ PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    AD_RESPONSE_ACTION action = Result->RecommendedAction;

    /* 记录历史（含分类统计累加） */
    AdRecordEvent(Protection, Result);

    /* 更新状态标志 */
    switch (Result->Technique) {
        case AdTechniqueKernelDebugger:
            Protection->Stats.KernelDebuggerPresent = TRUE;
            break;
        case AdTechniqueHardwareBreakpoint:
        case AdTechniqueHardwareContext:
            Protection->Stats.HardwareBreakpointsFound = TRUE;
            break;
        default:
            Protection->Stats.DebuggerPresent = TRUE;
            break;
    }

    /* 调用检测回调 */
    if (Protection->Callbacks.OnDetection) {
        (VOID)Protection->Callbacks.OnDetection(Result, Protection->Callbacks.Context);
    }

    /* 根据建议动作执行处置 */
    if (action == AdResponseAggressive) {
        /* 清调试寄存器 + 隐藏线程 */
        (VOID)AdClearHardwareBreakpoints(Protection);
        (VOID)AdHideThreadFromDebugger(Protection);
        Protection->Stats.TotalResponses++;
        if (Protection->Callbacks.OnResponse) {
            (VOID)Protection->Callbacks.OnResponse(action, Result, Protection->Callbacks.Context);
        }
    }
}

static
NTSTATUS
AdClearHardwareBreakpoints(
    _In_ PAC_ANTIDEBUG_PROTECTION Protection
    )
{
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return STATUS_ACCESS_DENIED;
    ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
    ctx.Dr7 &= ~0xFFUL;   /* 清除 L0-L3/G0-G3 启用位 */
    if (!SetThreadContext(GetCurrentThread(), &ctx)) return STATUS_ACCESS_DENIED;
    (VOID)Protection;
    return STATUS_SUCCESS;
}

static
NTSTATUS
AdHideThreadFromDebugger(
    _In_ PAC_ANTIDEBUG_PROTECTION Protection
    )
{
    NTSTATUS status;
    if (!Protection->NtSetInfoThread) return STATUS_PROCEDURE_NOT_FOUND;
    status = Protection->NtSetInfoThread(
        GetCurrentThread(),
        AD_THREAD_HIDE_FROM_DEBUGGER,
        NULL,
        0);
    return status;
}

/* ------------------------------------------------------------------ */
/* 单次扫描                                                           */
/* ------------------------------------------------------------------ */

/* 按进程类型取默认检测位图（2026-09-07 废除 0=全激活哨兵：显式全位=全激活）。
 * 普通进程默认：全位去掉「仅自身可执行」项 —— AD_MASK_SELF_ONLY_BITS 宏集合
 * （Timing/ODS 语义为当前线程执行痕迹，仅 EDR 自身路径有效）。数值可在本函数按需调整。 */
_Use_decl_annotations_
ULONG64
AdGetDefaultMask(
    _In_ AD_POLICY_PROFILE Profile
    )
{
    switch (Profile) {
    case AdPolicyProfileEdr:
        return AD_MASK_ALL;    /* EDR 自身：显式全激活（含未来检测项） */

    case AdPolicyProfileSystemService:
        return AD_MASK_ALL;    /* 系统服务：同 EDR 级守护，全激活 */

    case AdPolicyProfileNormal:
        /* 普通进程：显式位图 = 全位去掉基线/自省项 */
        return AD_MASK_ALL & ~AD_MASK_SELF_ONLY_BITS;

    case AdPolicyProfileCustom:
    default:
        return AD_MASK_ALL;    /* Custom 无默认：调用方显式提供位图覆盖（防御全激活） */
    }
}

/* 检测项使能判定（policy 使能开关，2026-09-06）。AntidebugMask 为按进程
 * policy 位图：AD_MASK_ALL（显式全位）= 全激活（含未来检测项）；其余按
 * AC_ANTIDEBUG_TECHNIQUE 下标位过滤（0=全关闭，显式裁剪）。 */
static
BOOLEAN
AcpIsAntiDebugTechniqueEnabled(
    _In_ ULONG64 AntidebugMask,
    _In_ AC_ANTIDEBUG_TECHNIQUE Technique
    )
{
    if (AC_ANTIDEBUG_TECHNIQUE_MASK_ALL(AntidebugMask)) return TRUE;
    return (AntidebugMask & AC_ANTIDEBUG_TECHNIQUE_MASK_BIT(Technique)) != 0;
}

_Use_decl_annotations_
NTSTATUS
AdSetDetectionMask(
    _Inout_ PAC_ANTIDEBUG_PROTECTION Engine,
    _In_ ULONG64 Mask
    )
{
    if (!Engine) return STATUS_INVALID_PARAMETER;

    /* 位图即最终使能（2026-09-07）：AD_MASK_ALL=全激活、AD_MASK_NONE(0)=
     * 全关闭、部分位=显式裁剪；不再做任何哨兵归一化。 */
    Engine->DetectionMask = Mask;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* 统一目标扫描（2026-09-06）                                          */
/*  AcpVerifySignalProtectedProcessAntiDebug 对目标进程（EDR 自身或受保护进程）统一执行    */
/*  反调试检测：目标统一为谱系树 WKD_PROCESS（调用内 PsLookup        */
/*  PsLookupWkdProcessByProcessId 持引用防 UAF），检测块直接以          */
/*  PWKD_PROCESS 为参数，读取原语（OpenProcess|VM_READ 句柄 +          */
/*  Toolhelp 模块表）由块内按需派生，检测块集合与 AntidebugMask 门控   */
/*  完全一致，无第二套编排。                                           */
/*  能力矩阵：PEB/DebugPort/DebugFlags/DebugObject/RemoteDebugger/      */
/*  硬件断点/插桩模块/内存软断点/内联钩子/IAT 抽查/父进程/全系统调试器   */
/*  枚举——适用于任意目标（掩码显式启用即执行）；                       */
/*  Timing/OutputDebugString 仅自身路径语义成立，由 policy 位图生成时    */
/*  AD_MASK_SELF_ONLY_BITS 裁剪（非自身目标位图不含这些位，              */
/*  2026-09-07 废除表内 AppliesTo 列与运行时 isSelf 门控）。            */
/*  2026-09-08：MemoryCrc32 完整性校验已移交 MemoryProtection 模块     */
/*  （受保护进程链驱动），本表不再含代码节基线检测项。                  */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* 跨进程检测块公共原语：进程句柄统一经 Common/Utils CoOpenProcessForQueryRead
 * 派生（2026-09-07 自本文件 AcpOpenProcess 迁出——PEAnalyzer IOC 层门面
 * PeVerifyFunctionAddressTable 同源共用，消除 IOC→AccessControl 循环依赖）。 */
/* 跨进程 NtQueryInformationProcess（复用引擎已解析的 pfn）。 */
static
NTSTATUS
AcpQueryProcessInformation(
    _In_ PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    )
{
    if (!ProcessHandle || !ProcessInformation ||
        ProcessInformationLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!Protection->NtQueryInformationProcess) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    ProcessInformation = NULL;
    if (ReturnLength) *ReturnLength = 0;
    
    return Protection->NtQueryInformationProcess(ProcessHandle, ProcessInformationClass,
        ProcessInformation, ProcessInformationLength, ReturnLength);
}

/* ---- 跨进程检测块（命中返回 STATUS_SUCCESS，未命中 STATUS_NOT_FOUND） ---- */

/* PEB 探针：BeingDebugged(+0x02) 为主位、NtGlobalFlag(+0xBC/0x68) 为副位。 */
static
NTSTATUS
AcpDetectPeb(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ const PWKD_PROCESS WkdProcess,
    _Out_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    PPEB peb;
    HANDLE hProcess;
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = STATUS_NOT_FOUND;
    SIZE_T read = 0;
    BYTE beingDebugged = 0;
    ULONG ntGlobalFlag = 0;
#ifdef _WIN64
    const ULONG_PTR NtGlobalFlagOffset    = 0xBC;
#else
    const ULONG_PTR NtGlobalFlagOffset    = 0x68;
#endif

    if (!Protection || !WkdProcess || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT));

    if (!CoOpenProcessForQueryRead((ULONG)(ULONG_PTR)WkdProcess->ProcessId, &hProcess)) return STATUS_UNSUCCESSFUL;
    status = AcpQueryProcessInformation(Protection, hProcess, ProcessBasicInformation,
                                        &pbi, sizeof(pbi), NULL);
    if (!NT_SUCCESS(status)) goto Cleanup;

    peb = pbi.PebBaseAddress;
    if (!peb) goto Cleanup;

    /* PEB.BeingDebugged（x64/x86 同偏移 0x02） */
    if (ReadProcessMemory(hProcess, &peb->BeingDebugged,
                          &beingDebugged, sizeof(beingDebugged), &read) &&
        read == sizeof(beingDebugged) && beingDebugged != 0) {
        Result->Technique = AdTechniquePebBeingDebugged;
        Result->Confidence = AdConfidenceHigh;
        Result->Score = AD_WEIGHT_PEB_DETECTION;
        Result->Severity = SP_SEVERITY_HIGH;
        Result->RecommendedAction = AdResponseAggressive;
        wcscpy_s(Result->Description, 256,
                 L"Remote PEB.BeingDebugged is set in protected process");
        status = STATUS_SUCCESS;
        goto Cleanup;
    }

    /* PEB.NtGlobalFlag（x64 0xBC / x86 0x68）调试堆标志 */
    if (ReadProcessMemory(hProcess, (PUCHAR)peb + NtGlobalFlagOffset,
                          &ntGlobalFlag, sizeof(ntGlobalFlag), &read) &&
        read == sizeof(ntGlobalFlag) && (ntGlobalFlag & AD_NT_GLOBAL_FLAG_DEBUGGED)) {
        Result->Technique = AdTechniquePebNtGlobalFlag;
        Result->Confidence = AdConfidenceHigh;
        Result->Score = AD_WEIGHT_PEB_DETECTION;
        Result->Severity = SP_SEVERITY_HIGH;
        Result->RecommendedAction = AdResponseAggressive;
        swprintf_s(Result->Description, 256,
                   L"Remote NtGlobalFlag debug bits set: 0x%lX", ntGlobalFlag);
        status = STATUS_SUCCESS;
    }

Cleanup:
    CloseHandle(hProcess);
    return status;
}

/* DebugPort（InfoClass 7）：非 0 表示调试器附加。 */
static
NTSTATUS
AcpDetectDebugPort(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ const PWKD_PROCESS WkdProcess,
    _Out_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    DWORD_PTR debugPort = 0;
    NTSTATUS status;
    HANDLE hProcess;

    if (!Protection || !WkdProcess || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT));

    if (!CoOpenProcessForQueryRead((ULONG)(ULONG_PTR)WkdProcess->ProcessId, &hProcess)) return STATUS_UNSUCCESSFUL;
    status = AcpQueryProcessInformation(Protection, hProcess, ProcessDebugPort,
                                        &debugPort, sizeof(debugPort), NULL);
    if (!NT_SUCCESS(status)) return STATUS_NOT_FOUND;
    else CloseHandle(hProcess);

    if (debugPort != 0) {
        Result->Technique = AdTechniqueNtQueryDebugPort;
        Result->Confidence = AdConfidenceHigh;
        Result->Score = AD_WEIGHT_API_DETECTION;
        Result->Severity = SP_SEVERITY_HIGH;
        Result->RecommendedAction = AdResponseAggressive;
        wcscpy_s(Result->Description, 256,
                 L"Protected process DebugPort is set (debugger attached)");
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

/* DebugFlags（InfoClass 31）：0 表示进程处于被调试状态。 */
static
NTSTATUS
AcpDetectDebugFlags(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ const PWKD_PROCESS WkdProcess,
    _Out_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    ULONG debugFlags = 1;
    NTSTATUS status;
    HANDLE hProcess;

    if (!Protection || !WkdProcess || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT));

    if (!CoOpenProcessForQueryRead((ULONG)(ULONG_PTR)WkdProcess->ProcessId, &hProcess)) return STATUS_UNSUCCESSFUL;
    status = AcpQueryProcessInformation(Protection, hProcess, AD_PROCESS_DEBUG_FLAGS,
                                        &debugFlags, sizeof(debugFlags), NULL);
    if (!NT_SUCCESS(status)) return STATUS_NOT_FOUND;
    else CloseHandle(hProcess);

    /* EPROCESS->NoDebugInherit，进程在被调试时的“继承”属性，0为调试状态 */
    if (debugFlags == 0) {
        Result->Technique = AdTechniqueNtQueryDebugFlags;
        Result->Confidence = AdConfidenceHigh;
        Result->Score = AD_WEIGHT_API_DETECTION;
        Result->Severity = SP_SEVERITY_HIGH;
        Result->RecommendedAction = AdResponseAggressive;
        wcscpy_s(Result->Description, 256,
                 L"Protected process ProcessDebugFlags is zero (debugger attached)");
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

/* DebugObjectHandle（InfoClass 30）：非空句柄表示调试对象存在。 */
static
NTSTATUS
AcpDetectDebugObject(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ const PWKD_PROCESS WkdProcess,
    _Out_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    HANDLE hProcess;
    HANDLE debugObject = NULL;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (!Protection || !WkdProcess || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT));

    if (!CoOpenProcessForQueryRead((ULONG)(ULONG_PTR)WkdProcess->ProcessId, &hProcess)) return STATUS_UNSUCCESSFUL;
    status = AcpQueryProcessInformation(Protection, hProcess, AD_PROCESS_DEBUG_OBJECT_HANDLE,
                                        &debugObject, sizeof(debugObject), NULL);
    if (!NT_SUCCESS(status)) return STATUS_NOT_FOUND;
    else CloseHandle(hProcess);

    if (debugObject && debugObject != (HANDLE)-1) {
        Result->Technique = AdTechniqueNtQueryDebugObject;
        Result->Confidence = AdConfidenceHigh;
        Result->Score = AD_WEIGHT_API_DETECTION;
        Result->Severity = SP_SEVERITY_HIGH;
        Result->RecommendedAction = AdResponseAggressive;
        swprintf_s(Result->Description, 256,
                   L"Protected process holds a debug object handle");
        CloseHandle(debugObject);
        status = STATUS_SUCCESS;
    }

    return status;
}

/* 硬件断点（遍历 WKD_PROCESS 线程链，逐线程 GetThreadContext）。 */
static
NTSTATUS
AcpDetectHardwareBreakpoint(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ const PWKD_PROCESS WkdProcess,
    _Out_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    PWKD_THREAD_CONTEXT threadCtx;
    HANDLE tid = 0;
    ULONG_PTR dr0 = 0, dr7 = 0;

    if (!Protection || !WkdProcess || !Result) return STATUS_INVALID_PARAMETER;
    if (!WkdProcess->ThreadContext) return STATUS_OBJECT_NAME_NOT_FOUND;
    RtlZeroMemory(Result, sizeof(AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT));

    threadCtx = WkdProcess->ThreadContext;
    AcquireSRWLockShared(&threadCtx->Lock);
    for (PLIST_ENTRY entry = threadCtx->ThreadList.Flink;
         entry != &threadCtx->ThreadList;
         entry = entry->Flink)
    {
        PWKD_THREAD thread = CONTAINING_RECORD(entry, WKD_THREAD, ListEntry);
        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT,
                                    FALSE, (DWORD)thread->ThreadId);
        if (hThread) {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (GetThreadContext(hThread, &ctx)) {
                if ((ctx.Dr0 != 0 || ctx.Dr1 != 0 ||
                     ctx.Dr2 != 0 || ctx.Dr3 != 0) &&
                    (ctx.Dr7 & 0xFF) != 0) {
                    tid = thread->ThreadId;
                    dr0 = (ULONG_PTR)ctx.Dr0;
                    dr7 = (ULONG_PTR)ctx.Dr7;
                    CloseHandle(hThread);
                    break;
                }
            }
            CloseHandle(hThread);
        }
    }
    ReleaseSRWLockShared(&threadCtx->Lock);

    if (tid != 0) {
        Result->Technique = AdTechniqueHardwareBreakpoint;
        Result->Confidence = AdConfidenceHigh;
        Result->Score = AD_WEIGHT_HW_BP_DETECTION;
        Result->Severity = SP_SEVERITY_HIGH;
        Result->RecommendedAction = AdResponseAggressive;
        Result->Address = dr0;
        swprintf_s(Result->Description, 256,
                   L"Protected process HW breakpoint: tid=%lu Dr0=0x%p Dr7=0x%p",
                   tid, (PVOID)dr0, (PVOID)dr7);
        return STATUS_SUCCESS;
    } else return STATUS_NOT_FOUND;
}

/* 插桩框架（目标模块表签名匹配）。 */
static
NTSTATUS
AcpDetectInstrumentation(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ const PWKD_PROCESS WkdProcess,
    _Out_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    WCHAR module[64];
    PWKD_MODULE_INSTANCE instance = NULL;
    AC_ANTIDEBUG_TECHNIQUE technique;

    if (!Protection || !WkdProcess || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT));

    for (ULONG i = 0; i < RTL_NUMBER_OF(AdInstrumentationSignatures); i++) {
        swprintf_s(module, 64, L"%ls.dll", AdInstrumentationSignatures[i]);
        switch (i) {
            case 0:  technique = AdTechniqueInstrumentationFrida;      break;
            case 1:  technique = AdTechniqueInstrumentationDynamo;     break;
            case 2:  technique = AdTechniqueInstrumentationPin;        break;
            case 3:  technique = AdTechniqueInstrumentationGeneric;    break;
            case 4:  technique = AdTechniqueInstrumentationGeneric;    break;
            case 5:  technique = AdTechniqueInstrumentationApiMonitor; break;
            case 6:  technique = AdTechniqueInstrumentationGeneric;    break;
            default: technique = AdTechniqueInstrumentationDetours;    break;
        }

        if (!NT_SUCCESS(PsLookupModuleInstanceByName(WkdProcess, module, &instance))) {
            continue;
        }

        Result->Technique = technique;
        Result->Confidence = AdConfidenceHigh;
        Result->Score = AD_WEIGHT_INSTRUMENTATION_DETECTION;
        Result->Severity = SP_SEVERITY_HIGH;
        Result->RecommendedAction = AdResponseAggressive;
        swprintf_s(Result->Description, 256,
                   L"Protected process instrumentation module: %ls @0x%p",
                   module, instance->ImageBase);
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

/* IAT / 延迟导入统一校验（2026-09-07 重构）：
 * 核心校验逻辑整体内移 PEAnalyzer PeVerifyFunctionAddressTable 门面——进程句柄、
 * 主模块域、磁盘副本（CoOpenFileForSequentialRead）、双 reader 回调装配全部
 * 由门面内部完成（接受 wkd_process 自取上下文，输入不再经调用方构造）。
 * 常规导入表 + 延迟导入表一次覆盖（复用同一装配），命中分别回填
 * Result->Iat / Result->Delay。防误报关键区（延迟三态 / 目标 DLL 未加载 /
 * 导出未命中）由解析层统一覆盖。
 * QueryDelay=FALSE → 仅常规表命中（AdTechniqueMemoryIatHook）；
 * QueryDelay=TRUE  → 仅延迟表命中（AdTechniqueMemoryDelayImport）。
 * 检测表两个槽位分别引用（编排按掩码位独立使能，双槽共用本辅助避免重复代码）。 */
static
NTSTATUS
AcpDetectImportHookCommon(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ const PWKD_PROCESS WkdProcess,
    _In_ BOOLEAN QueryDelay,
    _Out_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    PE_IMPORT_VERIFY_RESULT verifyResult;
    const PE_IMPORT_VERIFY_HIT* hit;
    AC_ANTIDEBUG_TECHNIQUE technique;
    const WCHAR* verb;

    if (!Protection || !WkdProcess || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT));

    if (!NT_SUCCESS(PeVerifyFunctionAddressTable(WkdProcess, &verifyResult))) {
        return STATUS_UNSUCCESSFUL;
    }

    if (QueryDelay) {
        if (!verifyResult.Delay.Found) return STATUS_NOT_FOUND;
        hit = &verifyResult.Delay;
        technique = AdTechniqueMemoryDelayImport;
        verb = L"delay-load hook";
    } else {
        if (!verifyResult.Iat.Found) return STATUS_NOT_FOUND;
        hit = &verifyResult.Iat;
        technique = AdTechniqueMemoryIatHook;
        verb = L"IAT hook";
    }

    Result->Technique = technique;
    Result->Confidence = AdConfidenceHigh;
    Result->Score = AD_WEIGHT_HOOK_DETECTION;
    Result->Severity = SP_SEVERITY_HIGH;
    Result->RecommendedAction = AdResponseAggressive;
    Result->Address = hit->ActualAddress;
    swprintf_s(Result->Description, 256,
               L"Protected process %s: %s!%hs -> 0x%p (expect 0x%p)",
               verb, hit->DllName, hit->FuncName, (PVOID)hit->ActualAddress,
               (PVOID)hit->ExpectedAddress);
    return STATUS_SUCCESS;
}

static
NTSTATUS
AcpDetectIatHook(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ const PWKD_PROCESS WkdProcess,
    _Out_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    return AcpDetectImportHookCommon(Protection, WkdProcess, FALSE, Result);
}

static
NTSTATUS
AcpDetectDelayImportHook(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ const PWKD_PROCESS WkdProcess,
    _Out_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    return AcpDetectImportHookCommon(Protection, WkdProcess, TRUE, Result);
}

/* 父进程（PPID）名落入调试器清单。
 * 2026-09-08（档案 #85）：由 Toolhelp 全系统快照改为进程域树谱系直查
 * （WkdProcessTree.PidMap hashmap），消除 CreateToolhelp32Snapshot 开销；
 * 父进程信息取自树内谱系字段——优先父节点 ImageFileName（权威，防父
 * 进程更名/复用竞态），回退子节点记录的原始父映像名 ParentImageName
 * （快照/事件两路写入）。 */
static
NTSTATUS
AcpDetectParentProcess(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ const PWKD_PROCESS WkdProcess,
    _Out_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    HANDLE ppid;
    WCHAR parentProcessName[256] = { 0 };

    if (!Protection || !WkdProcess || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT));

    /* ---- Step 1: 通过进程树获取父进程对象 ---- */
    ppid = WkdProcess->ParentProcessId;
    if (WkdProcess->ParentProcessId != 0) {
        NTSTATUS status;
        PWKD_PROCESS parent = NULL;

        status = PsLookupWkdProcessByProcessId(NULL,
                                               WkdProcess->ParentProcessId,
                                               &parent);
        if (!NT_SUCCESS(status)) return status;
        wcsncpy_s(parentProcessName, RTL_NUMBER_OF(parentProcessName),
                  parent->ImageFileName->Buffer, _TRUNCATE);
        PsDereferenceWkdProcess(parent);
    }

    /* ---- Step 2: 枚举调试器进程名进行对比 ---- */
    for (ULONG i = 0; i < RTL_NUMBER_OF(AdDebuggerProcessNames); i++) {
        if (_wcsicmp(parentProcessName, AdDebuggerProcessNames[i]) == 0) {
            Result->Technique = AdTechniqueParentProcess;
            Result->Confidence = AdConfidenceMedium;
            Result->Score = AD_WEIGHT_PROCESS_DETECTION / 2;
            Result->Severity = SP_SEVERITY_MEDIUM;
            Result->RecommendedAction = AdResponseAlert;
            swprintf_s(Result->Description, 256,
                       L"Protected process parent is tool: %ls (PPID=%lu)",
                       (PCWSTR)parentProcessName, HandleToULong(ppid));
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

/* ---- 检测块适配层：全系统枚举与仅自省项统一为 (Protection, Target, Result) ---- */

/* 全系统枚举类（与目标无关，直接复用自省版实现） */

static
NTSTATUS
AcpDetectDebuggerProcess(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ const PWKD_PROCESS WkdProcess,
    _Out_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    /*
     * 枚举进程域树（WkdProcessTree.PidMap hashmap），检测已知调试器/
     * 逆向工具映像名（对齐 SS，使用外部 AD_DEBUGGER_PROCESS_COUNT 项清单）。
     *
     * 2026-09-08（档案 #85）：由 Toolhelp 全系统快照改为 CoCaptureHashMapSnapshot
     * 两阶段快照枚举（对齐 IocCleanupExpiredProcessPair 范式）：
     *   Phase 1 — 查询容量（key-only 快照，逐桶共享锁，无 ref 负担）；
     *   Phase 2 — 取快照后按变长结构（SIZE_T KeySize + KeyData[]）指针步进
     *             遍历，每 key=PID，经 PsLookupWkdProcessByProcessId 反查
     *             节点（pin 语义，比对后须 PsDereferenceWkdProcess 归还）。
     * 范围=进程域树内已追踪进程（事件驱动 + 快照兜底），语义较「全系统
     * 快照」更贴合监控域。
     * 命中返回 STATUS_SUCCESS。
     */
    NTSTATUS status;
    SIZE_T snapshotSize = 0;
    ULONG capacity = 0;         /* 快照项数 */
    PWKD_HASH_MAP_SNAPSHOT snapshot = NULL;

    if (!Protection || !WkdProcess || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT));

    /* ---- Phase 1: 查询容量 ---- */
    status = CoCaptureHashMapSnapshot(&WkdProcessTree.PidMap, NULL, &snapshotSize, NULL);
    if (!NT_SUCCESS(status) || snapshotSize == 0) return STATUS_NOT_FOUND;
    snapshotSize = ALIGN_UP_BY(snapshotSize, PAGE_SIZE);

    snapshot = (PWKD_HASH_MAP_SNAPSHOT)malloc(snapshotSize);
    if (!snapshot) return STATUS_NOT_FOUND;

    /* ---- Phase 2: 获取快照（截断则仅处理已写入条目，其余延迟下一轮）---- */
    status = CoCaptureHashMapSnapshot(&WkdProcessTree.PidMap, snapshot, &snapshotSize, &capacity);
    if (!NT_SUCCESS(status)) goto Cleanup;

    /* ---- Phase 3: 快照枚举 ----
     * 快照为变长结构（SIZE_T KeySize + KeyData[]）：按每项实际长度指针步进，
     * 绝不能用下标 snapshot[i]（按 sizeof 固定步进会错位）。 */
    PWKD_HASH_MAP_SNAPSHOT se = snapshot;
    for (ULONG i = 0; i < capacity; i++) {
        HANDLE pid = 0;
        PWKD_PROCESS wkdProcess = NULL;
        PUCHAR next = (PUCHAR)se + sizeof(SIZE_T) + se->KeySize;    

        if (se->KeySize != sizeof(HANDLE)) continue;
        RtlCopyMemory(&pid, se->KeyData, sizeof(HANDLE));
        se = (PWKD_HASH_MAP_SNAPSHOT)next;
        if (pid == 0) continue;

        status = PsLookupWkdProcessByProcessId(NULL, pid, &wkdProcess);
        if (!NT_SUCCESS(status)) continue;   /* TOCTOU: 已被并发清理 */

        /* 只查存活进程；快照兜底节点/未富化节点跳过 */
        if (wkdProcess->Alive) {
            for (ULONG j = 0; j < RTL_NUMBER_OF(AdDebuggerProcessNames); j++) {
                if (_wcsicmp(wkdProcess->ImageFileName->Buffer,
                        AdDebuggerProcessNames[j]) == 0) {
                    Result->Technique = AdTechniqueProcessDebugger;
                    Result->Confidence = AdConfidenceHigh;
                    Result->Score = AD_WEIGHT_PROCESS_DETECTION;
                    Result->Severity = SP_SEVERITY_HIGH;
                    Result->RecommendedAction = AdResponseAggressive;
                    swprintf_s(Result->Description, 256,
                               L"Debugger process: %ls (PID=%lu)",
                               wkdProcess->ImageFileName->Buffer,
                               HandleToULong(wkdProcess->ProcessId));
                    PsDereferenceWkdProcess(wkdProcess);   /* 归还查找 pin */
                    status = STATUS_SUCCESS;
                    goto Cleanup;
                }
            }
        }
        PsDereferenceWkdProcess(wkdProcess);               /* 归还查找 pin */
    }
    status = STATUS_NOT_FOUND;

Cleanup:
    free(snapshot);
    return status;
}

static
NTSTATUS
AcpDetectDebuggerWindow(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ const PWKD_PROCESS WkdProcess,
    _Out_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    if (!Protection || !WkdProcess || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT));

    for (ULONG i = 0; i < RTL_NUMBER_OF(AdDebuggerWindowClasses); i++) {
        HWND hwnd = FindWindowW(AdDebuggerWindowClasses[i], NULL);
        if (hwnd) {
            Result->Technique = AdTechniqueWindowDebugger;
            Result->Confidence = AdConfidenceMedium;
            Result->Score = AD_WEIGHT_PROCESS_DETECTION / 2;
            Result->Severity = SP_SEVERITY_MEDIUM;
            Result->RecommendedAction = AdResponseAlert;
            swprintf_s(Result->Description, 256, L"Debugger window: %ls", AdDebuggerWindowClasses[i]);
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

static
NTSTATUS
AcpDetectDebuggerDriver(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ const PWKD_PROCESS WkdProcess,
    _Out_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    if (!Protection || !WkdProcess || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT));

    for (ULONG i = 0; i < RTL_NUMBER_OF(AdDebuggerDrivers); i++) {
        WCHAR devPath[64];
        swprintf_s(devPath, RTL_NUMBER_OF(devPath), L"\\\\.\\%ls", AdDebuggerDrivers[i]);

        HANDLE hDev = CreateFileW(devPath,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        if (hDev != INVALID_HANDLE_VALUE) {
            CloseHandle(hDev);
            Result->Technique = AdTechniqueDebuggerDriver;
            Result->Confidence = AdConfidenceHigh;
            Result->Score = AD_WEIGHT_PROCESS_DETECTION;
            Result->Severity = SP_SEVERITY_HIGH;
            Result->RecommendedAction = AdResponseAggressive;
            swprintf_s(Result->Description, 256, L"Debugger driver: %ls", AdDebuggerDrivers[i]);
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

/* 仅自省项（时序/ODS/CRC32 基线）：非自身目标位图已在 policy 层裁剪 */
static
NTSTATUS
AcpDetectTiming(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ const PWKD_PROCESS WkdProcess,
    _Out_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    /*
     * RDTSC 时序检测（对齐 SS CheckTiming_RDTSC）：自省项，Target 占位。
     *  采样 AD_TIMING_SAMPLE_COUNT 次，计算均值与标准差。
     *  被调试（单步/软断点开销）会导致平均执行周期显著大于
     *  正常水平。判定：avg > AD_RDTSC_SINGLE_THRESHOLD(500)。
     */
    ULONG i;
    ULONG64 samples[AD_TIMING_SAMPLE_COUNT];
    ULONG64 total = 0;
    ULONG64 avg;
    ULONG64 sumSq;
    ULONG64 variance;

    if (!Protection || !WkdProcess || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT));
    if (!Result) return STATUS_INVALID_PARAMETER;

    for (i = 0; i < AD_TIMING_SAMPLE_COUNT; i++) {
        ULONG64 start = __rdtsc();
        /* 若干条指令作为基准块 */
        (VOID)GetCurrentProcessId();
        (VOID)GetCurrentThreadId();
        (VOID)GetLastError();
        samples[i] = __rdtsc() - start;
        total += samples[i];
    }

    avg = total / AD_TIMING_SAMPLE_COUNT;
    if (avg <= AD_RDTSC_SINGLE_THRESHOLD) {
        /* 未超过阈值，可能被虚拟化/时序稳定，不判定核心但计算波动 */
        sumSq = 0;
        for (i = 0; i < AD_TIMING_SAMPLE_COUNT; i++) {
            ULONG64 d = samples[i] - avg;
            sumSq += d * d;
        }
        variance = sumSq / AD_TIMING_SAMPLE_COUNT;
        if (variance == 0 && avg == 0) {
            /* 精确反调试陷阱：均值为 0（时间被冻结） */
            Result->Technique = AdTechniqueTimingRdtsc;
            Result->Confidence = AdConfidenceMedium;
            Result->Score = AD_WEIGHT_TIMING_DETECTION;
            Result->Severity = SP_SEVERITY_MEDIUM;
            Result->RecommendedAction = AdResponseAlert;
            wcscpy_s(Result->Description, 256, L"RDTSC timing frozen (avg=0)");
            return STATUS_SUCCESS;
        }
        return STATUS_NOT_FOUND;
    }

    Result->Technique = AdTechniqueTimingRdtsc;
    Result->Confidence = AdConfidenceMedium;
    Result->Score = AD_WEIGHT_TIMING_DETECTION;
    Result->Severity = SP_SEVERITY_MEDIUM;
    Result->RecommendedAction = AdResponseAlert;
    swprintf_s(Result->Description, 256, L"RDTSC timing anomaly: avg=%I64u cycles", avg);
    return STATUS_SUCCESS;
}

static
NTSTATUS
AcpDetectOutputDebugString(
    _In_ const PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ const PWKD_PROCESS WkdProcess,
    _Out_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    )
{
    /* OutputDebugString 在调试器中会恢复 LastError；若 0x12345678 被
     * 清空则判定。对齐 SS CheckAPI_OutputDebugString。自省项：Target 占位。 */
    DWORD lastError;

    if (!Protection || !WkdProcess || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT));

    SetLastError(0x12345678);
    OutputDebugStringA("WkDefender Anti-Debug Check");
    lastError = GetLastError();
    SetLastError(0);

    if (lastError == 0) {
        Result->Technique = AdTechniqueOutputDebugString;
        Result->Confidence = AdConfidenceMedium;
        Result->Score = AD_WEIGHT_API_DETECTION / 2;
        Result->Severity = SP_SEVERITY_MEDIUM;
        Result->RecommendedAction = AdResponseAlert;
        wcscpy_s(Result->Description, 256, L"OutputDebugString behavior indicates debugger");
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

/* ---- 检测块表：AntidebugMask 唯一门控（2026-09-07）----
 * 结构仅保留 { 门控位, 检测块 }：目标适用性（AppliesTo）与合表门控
 * （AlsoBits）已上移到掩码层 —— 自省项经 AD_MASK_SELF_ONLY_BITS 在
 * AdGetDefaultMask/policy 位图生成时裁剪；HardwareContext 位在扫描入口
 * 一次性归一化并入 HardwareBreakpoint 位。运行时无二次门控。 */

typedef NTSTATUS (*AC_ANTIDEBUG_DETECTION_FUNC)(
    _In_ PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ PWKD_PROCESS WkdProcess,
    _Out_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result
    );

typedef struct _AC_ANTIDEBUG_DETECTION {
    AC_ANTIDEBUG_TECHNIQUE          Technique;      /* 唯一门控位（AntidebugMask） */
    AC_ANTIDEBUG_DETECTION_FUNC     Detect;         /* 检测块（命中 STATUS_SUCCESS） */
} AC_ANTIDEBUG_DETECTION, *PAC_ANTIDEBUG_DETECTION;

/* 执行顺序对齐原有自身/整链语义；HardwareContext 与 HardwareBreakpoint 合表
 * （同一硬件断点检测块，HardwareContext 位在扫描入口归一化并入）。 */
static const AC_ANTIDEBUG_DETECTION AcpAntiDebugDetectionTable[] = {
    { AdTechniquePebBeingDebugged,       AcpDetectPeb },
    { AdTechniqueNtQueryDebugPort,       AcpDetectDebugPort },
    { AdTechniqueNtQueryDebugFlags,      AcpDetectDebugFlags },
    { AdTechniqueNtQueryDebugObject,     AcpDetectDebugObject },
    { AdTechniqueHardwareBreakpoint,     AcpDetectHardwareBreakpoint },
    { AdTechniqueTimingRdtsc,            AcpDetectTiming },
    { AdTechniqueProcessDebugger,        AcpDetectDebuggerProcess },
    { AdTechniqueWindowDebugger,         AcpDetectDebuggerWindow },
    { AdTechniqueDebuggerDriver,         AcpDetectDebuggerDriver },
    { AdTechniqueInstrumentationGeneric, AcpDetectInstrumentation },
    { AdTechniqueMemoryIatHook,          AcpDetectIatHook },
    { AdTechniqueMemoryDelayImport,      AcpDetectDelayImportHook },
    { AdTechniqueOutputDebugString,      AcpDetectOutputDebugString },
    { AdTechniqueParentProcess,          AcpDetectParentProcess },
};

/* 扫描入口掩码归一化（2026-09-07 上移自原表 AlsoBits）：HardwareContext
 * （逐线程 Dr 原语）与 HardwareBreakpoint（用户态 Dr0-3/Dr7 检测块）合表，
 * 任一启用即并入 HardwareBreakpoint 门控位，表内不再携带辅助位。 */
static
ULONG64
AcpNormalizeAntiDebugMask(
    _In_ ULONG64 AntidebugMask
    )
{
    if (AntidebugMask & AC_ANTIDEBUG_TECHNIQUE_MASK_BIT(AdTechniqueHardwareContext)) {
        AntidebugMask |= AC_ANTIDEBUG_TECHNIQUE_MASK_BIT(AdTechniqueHardwareBreakpoint);
    }
    return AntidebugMask;
}

/* 对指定受保护进程执行反调试检测（单一编排循环，无第二套调度）：
 *  ProcessId == 0 或当前进程 → 自身目标（IsSelf=TRUE，全检测项）；
 *  目标统一为谱系树 WKD_PROCESS：调用内先 PsLookupWkdProcessByProcessId
 *  持 WKD_PROCESS 引用（HashMap pin 防目标并发销毁 UAF），扫描结束
 *  PsDereferenceWkdProcess 归还；检测块直接以 PWKD_PROCESS 为参数，
 *  读取原语（OpenProcess|VM_READ 句柄 + Toolhelp 模块表）由块内自取。
 *  AntidebugMask 为唯一能力门控（AD_MASK_ALL=全激活、AD_MASK_NONE(0)=
 *  全关闭、部分位=显式裁剪）；目标适用性（自省项）在 policy 位图生成时
 *  已由 AD_MASK_SELF_ONLY_BITS 裁剪，运行时无第二次门控。
 *  命中即分发（AdDispatchDetection）并返回 STATUS_SUCCESS。 */
_Use_decl_annotations_
NTSTATUS
AcpVerifySignalProtectedProcessAntiDebug(
    _In_ PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ HANDLE ProcessId,
    _In_ ULONG64 AntidebugMask,
    _Out_opt_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT FirstHit
    )
{
    NTSTATUS status;
    PWKD_PROCESS wkdProcess = NULL;
    AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT result;
    PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT pResult = FirstHit;
    BOOLEAN found = FALSE;

    if (!Protection) return STATUS_INVALID_PARAMETER;
    if (FirstHit) RtlZeroMemory(FirstHit, sizeof(AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT));

    /* 掩码入口归一化（HardwareContext→HardwareBreakpoint 位并入，幂等） */
    AntidebugMask = AcpNormalizeAntiDebugMask(AntidebugMask);

    /* ---- 持 WKD_PROCESS 引用，防止 UAF（ProcessId 基于受保护进程快照） ---- */
    status = PsLookupWkdProcessByProcessId(NULL, ProcessId, &wkdProcess);
    if (!NT_SUCCESS(status)) return STATUS_OBJECT_NO_LONGER_EXISTS;

    Protection->Stats.TotalScans++;
    GetSystemTimeAsFileTime((LPFILETIME)&Protection->Stats.LastScanTime);
    RtlZeroMemory(&result, sizeof(result));

    for (ULONG i = 0; i < RTL_NUMBER_OF(AcpAntiDebugDetectionTable); i++) {
        const AC_ANTIDEBUG_DETECTION* detection = &AcpAntiDebugDetectionTable[i];

        /* AntidebugMask 唯一门控（表内无辅助位、无适用性列） */
        if (!AcpIsAntiDebugTechniqueEnabled(AntidebugMask, detection->Technique)) {
            continue;
        }
        if (NT_SUCCESS(detection->Detect(Protection, wkdProcess, &result))) {
            // AdDispatchDetection(Protection, &result);
            if (pResult) { *pResult = result; }
            found = TRUE;
            break;
        }
    }

    PsDereferenceWkdProcess(wkdProcess);   /* 归还查找 pin（与 PsLookup 对称） */
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}


/* 映射检测技术到可读名称（供日志/上报）。 */
_Use_decl_annotations_
PCWSTR
AdTechniqueName(
    _In_ AC_ANTIDEBUG_TECHNIQUE Technique
    )
{
    switch (Technique) {
        case AdTechniquePebBeingDebugged:      return L"PEB_BeingDebugged";
        case AdTechniquePebHeapFlags:          return L"PEB_HeapFlags";
        case AdTechniquePebNtGlobalFlag:       return L"PEB_NtGlobalFlag";
        case AdTechniquePebProcessHeap:        return L"PEB_ProcessHeap";
        case AdTechniqueTebThreadInfo:         return L"TEB_ThreadInfo";
        case AdTechniqueIsDebuggerPresent:     return L"IsDebuggerPresent";
        case AdTechniqueNtQueryDebugPort:      return L"NtQuery_DebugPort";
        case AdTechniqueNtQueryDebugFlags:     return L"NtQuery_DebugFlags";
        case AdTechniqueNtQueryDebugObject:    return L"NtQuery_DebugObject";
        case AdTechniqueNtQueryProcessBasic:   return L"NtQuery_ProcessBasic";
        case AdTechniqueOutputDebugString:     return L"OutputDebugString";
        case AdTechniqueCloseHandle:           return L"CloseHandle";
        case AdTechniqueTimingRdtsc:           return L"Timing_RDTSC";
        case AdTechniqueTimingQueryPerf:       return L"Timing_QPC";
        case AdTechniqueTimingGetTickCount:    return L"Timing_GetTickCount";
        case AdTechniqueTimingInstruction:     return L"Timing_Instruction";
        case AdTechniqueHardwareBreakpoint:    return L"Hardware_Breakpoint";
        case AdTechniqueHardwareContext:       return L"Hardware_Context";
        case AdTechniqueExceptionInt3:         return L"Exception_INT3";
        case AdTechniqueExceptionGuardPage:    return L"Exception_GuardPage";
        case AdTechniqueExceptionVeh:          return L"Exception_VEH";
        case AdTechniqueExceptionTrap:         return L"Exception_Trap";
        case AdTechniqueMemoryIatHook:         return L"Memory_IAT";
        case AdTechniqueMemoryDelayImport:     return L"Memory_DelayImport";
        case AdTechniqueProcessDebugger:       return L"Process_Debugger";
        case AdTechniqueWindowDebugger:        return L"Window_Debugger";
        case AdTechniqueKernelDebugger:        return L"Kernel_Debugger";
        case AdTechniqueDebuggerDriver:        return L"Driver_Probe";
        case AdTechniqueParentProcess:         return L"Parent_Process";
        case AdTechniqueInstrumentationFrida:  return L"Instrumentation_Frida";
        case AdTechniqueInstrumentationDynamo: return L"Instrumentation_Dynamo";
        case AdTechniqueInstrumentationPin:    return L"Instrumentation_PIN";
        case AdTechniqueInstrumentationDetours:return L"Instrumentation_Detours";
        case AdTechniqueInstrumentationApiMonitor: return L"Instrumentation_APIMonitor";
        case AdTechniqueInstrumentationGeneric:return L"Instrumentation_Generic";
        default:                               return L"Unknown";
    }
}

/* ------------------------------------------------------------------ */
/* 线程防护                                                           */
/* ------------------------------------------------------------------ */

/* 枚举指定进程的线程 ID（Toolhelp，线程反调试能力归位反调试模块）。 */
static
ULONG
AdEnumerateThreadIds(
    _In_ ULONG ProcessId,
    _Out_writes_(Capacity) PULONG ThreadIds,
    _In_ ULONG Capacity
    )
{
    HANDLE snap;
    THREADENTRY32 te;
    ULONG count = 0;

    if (!ThreadIds || Capacity == 0) return 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != ProcessId) continue;
            if (count >= Capacity) break;
            ThreadIds[count++] = te.th32ThreadID;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return count;
}

/* 周期扫描受保护进程链：对链上每个受保护进程按其 policy
 * （WKD_ACCESS_CONTROL_CONTEXT::AntidebugMask，AD_MASK_ALL=全激活显式全位）
 * 执行反调试检测（AcpVerifySignalProtectedProcessAntiDebug），并对全体线程
 * 实施 HideFromDebugger（幂等）。
 * EDR 自身跳过——自身由周期线程第一步 AcpVerifySignalProtectedProcessAntiDebug(0) 处理。
 * 2026-09-06：线程防调试能力统一归位反调试模块；V2 起为整链策略扫描
 * （经编排层受保护进程链枚举，引用出需逐个 Deref）。 */
_Use_decl_annotations_
NTSTATUS
AcpVerifyProtectedProcessAntiDebug(
    _In_ PAC_ANTIDEBUG_PROTECTION Engine
    )
{
    NTSTATUS status;
    PWKD_PROCESS* ptrs = NULL;  // PWKD_PROCESS 指针数组
    ULONG needed = 0;
    ULONG count = 0;

    if (!Engine) return STATUS_INVALID_PARAMETER;

    /* ---- Step 1: 枚举被保护进程链，获取进程对象 ---- */
    {
        if (AcGetAccessControlEngine() == NULL) return STATUS_DEVICE_NOT_READY;   /* 编排层未启动：无受保护进程集 */

        status = AcEnumerateProtectedProcessPtrs(NULL, 0, &needed);
        if (needed == 0) return STATUS_SUCCESS;

        ptrs = (PWKD_PROCESS*)malloc(needed * sizeof(PWKD_PROCESS));
        if (!ptrs) return STATUS_NO_MEMORY;
        RtlZeroMemory(ptrs, sizeof(ptrs));

        status = AcEnumerateProtectedProcessPtrs(ptrs, needed, &count);
    }

    /* ---- Step 2: 串行检查每个受保护线程的反调试状态 ---- */
    for (ULONG i = 0; i < min(count, needed); i++) {
        ULONG tids[AD_MAX_THREADS_PER_PROCESS];
        ULONG tc;
        HANDLE pid;
        ULONG64 mask;
        PWKD_ACCESS_CONTROL_CONTEXT acCtx;

        if (!ptrs[i]) continue; /* 几乎不可能!!! */
        pid = ptrs[i]->ProcessId;

        /* 按进程 policy 位图执行反调试检测（无 ctx 防御性取 EDR 默认全激活） */
        acCtx = ptrs[i]->AccessControlContext;
        mask = acCtx ? acCtx->AntidebugMask : AD_MASK_ALL;
        AcpVerifySignalProtectedProcessAntiDebug(Engine, pid, mask, NULL);

        /* 线程级反调试防护（HideFromDebugger，重复设置幂等） */
        tc = AdEnumerateThreadIds((ULONG)(ULONG_PTR)pid, tids, RTL_NUMBER_OF(tids));
        for (ULONG j = 0; j < tc; j++) {
            (VOID)AdHideThreadFromDebuggerById(Engine, tids[j]);
        }

        PsDereferenceWkdProcess(ptrs[i]);
    }

    free(ptrs);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
AdApplyThreadProtection(
    _In_ PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ BOOLEAN HideFromDebugger,
    _In_ BOOLEAN ClearDebugRegisters
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (!Protection) return STATUS_INVALID_PARAMETER;

    if (ClearDebugRegisters) {
        status = AdClearHardwareBreakpoints(Protection);
        if (!NT_SUCCESS(status) && status != STATUS_ACCESS_DENIED) {
            goto done;
        }
        status = STATUS_SUCCESS;
    }

    if (HideFromDebugger) {
        status = AdHideThreadFromDebugger(Protection);
        if (!NT_SUCCESS(status)) {
            goto done;
        }
        Protection->ThreadProtected = TRUE;
    }

done:
    return status;
}

/* 对指定线程隐藏调试器（threadId=0 表示当前线程）。
 * 线程防调试动作归位反调试模块（2026-09-06）；由编排层经
 * SdfApplyAntiDebugToCurrentThread / 受保护线程登记回调接入。 */
_Use_decl_annotations_
NTSTATUS
AdHideThreadFromDebuggerById(
    _In_ PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ ULONG ThreadId
    )
{
    PNT_SET_INFO_THREAD pNtSetInfoThread;
    HANDLE hThread = NULL;
    NTSTATUS status;

    if (!Protection) return STATUS_INVALID_PARAMETER;

    pNtSetInfoThread = AdGetNtSetInfoThread();
    if (!pNtSetInfoThread) return STATUS_PROCEDURE_NOT_FOUND;

    if (ThreadId == 0) {
        return pNtSetInfoThread(GetCurrentThread(), AD_THREAD_HIDE_FROM_DEBUGGER, NULL, 0);
    }

    hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, ThreadId);
    if (!hThread) return STATUS_ACCESS_DENIED;
    status = pNtSetInfoThread(hThread, AD_THREAD_HIDE_FROM_DEBUGGER, NULL, 0);
    CloseHandle(hThread);
    return status;
}

/* ------------------------------------------------------------------ */
/* 周期监测                                                           */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
static
DWORD WINAPI
AcpAntiDebugRoutine(
    _In_ LPVOID Param
    )
{
    PAC_ANTIDEBUG_PROTECTION protection = (PAC_ANTIDEBUG_PROTECTION)Param;

    if (!protection) return 0;

    while (protection->MonitorRunning) {
        /* 第一步：EDR 自身按自身 policy（DetectionMask，AD_MASK_ALL=全激活）扫描；
         * 第二步：受保护进程链整链扫描——链上每个受保护进程按其自身
         * policy（WKD_ACCESS_CONTROL_CONTEXT::AntidebugMask，位图即最终使能）
         * 执行反调试检测（统一目标扫描表驱动，见 AcpAntiDebugDetectionTable），
         * 并对全体线程实施 HideFromDebugger（幂等）。
         * 2026-09-06：V2 起为整链策略扫描（非仅 EDR 自身 / 非仅线程隐藏）。 */
        AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT result;

        AcpVerifySignalProtectedProcessAntiDebug(protection, NULL,
                                     protection->DetectionMask, &result);
        AcpVerifyProtectedProcessAntiDebug(protection);

        WaitForSingleObject(protection->MonitorStopEvent, protection->MonitorIntervalMs);
        if (!protection->MonitorRunning) {
            break;
        }
    }
    return 0;
}

_Use_decl_annotations_
NTSTATUS
AcStartAntiDebugProtection(
    _Inout_ PAC_ANTIDEBUG_PROTECTION Protection,
    _In_ ULONG IntervalMs
    )
{
    if (!Protection) return STATUS_INVALID_PARAMETER;
    if (Protection->MonitorRunning) return SP_STATUS_ALREADY_RUNNING;

    if (IntervalMs < 100) IntervalMs = AD_DEFAULT_MONITOR_INTERVAL_MS;
    Protection->MonitorIntervalMs = IntervalMs;

    Protection->MonitorStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!Protection->MonitorStopEvent) return STATUS_INSUFFICIENT_RESOURCES;

    Protection->MonitorRunning = TRUE;
    Protection->MonitorThread = CreateThread(
        NULL, 0, AcpAntiDebugRoutine, Protection, 0, NULL);
    if (!Protection->MonitorThread) {
        Protection->MonitorRunning = FALSE;
        CloseHandle(Protection->MonitorStopEvent);
        Protection->MonitorStopEvent = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
AdStopMonitoring(
    _In_ PAC_ANTIDEBUG_PROTECTION Protection
    )
{
    HANDLE thread = NULL;
    HANDLE evt = NULL;

    if (!Protection) return STATUS_INVALID_PARAMETER;
    if (!Protection->MonitorRunning) return STATUS_SUCCESS;

    Protection->MonitorRunning = FALSE;
    if (Protection->MonitorStopEvent) {
        SetEvent(Protection->MonitorStopEvent);
    }
    thread = Protection->MonitorThread;
    evt = Protection->MonitorStopEvent;
    Protection->MonitorThread = NULL;
    Protection->MonitorStopEvent = NULL;

    if (thread) {
        WaitForSingleObject(thread, 3000);
        CloseHandle(thread);
    }
    if (evt) {
        CloseHandle(evt);
    }

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* 查询 / 统计                                                        */
/* ------------------------------------------------------------------ */

_Use_decl_annotations_
NTSTATUS
AdGetEvents(
    _In_ PAC_ANTIDEBUG_PROTECTION Protection,
    _Out_writes_to_(MaxEvents, *ReturnedCount) PAD_EVENT EventArray,
    _In_ ULONG MaxEvents,
    _Out_ PULONG ReturnedCount
    )
{
    ULONG i, src, count;

    if (!Protection || !EventArray || !ReturnedCount || MaxEvents == 0) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&Protection->Lock);
    count = (Protection->HistoryCount < MaxEvents) ? Protection->HistoryCount : MaxEvents;
    /* 从最旧往最新读 */
    if (Protection->HistoryCount <= count) {
        src = 0;
    } else {
        src = (Protection->HistoryHead + AD_MAX_HISTORY - Protection->HistoryCount) % AD_MAX_HISTORY;
    }
    for (i = 0; i < count; i++) {
        EventArray[i] = Protection->History[(src + i) % AD_MAX_HISTORY];
    }
    *ReturnedCount = count;
    LeaveCriticalSection(&Protection->Lock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
AdGetStatistics(
    _In_ PAC_ANTIDEBUG_PROTECTION Protection,
    _Out_ PAD_STATISTICS Stats
    )
{
    BOOLEAN dbg = FALSE;

    if (!Protection || !Stats) return STATUS_INVALID_PARAMETER;

    (VOID)AdIsDebuggerAttached(Protection, &dbg);

    EnterCriticalSection(&Protection->Lock);
    *Stats = Protection->Stats;
    Stats->HistoryCount = Protection->HistoryCount;
    Stats->DebuggerPresent = dbg;
    Stats->HardwareBreakpointsFound = FALSE;  /* 周期扫描更新 */
    LeaveCriticalSection(&Protection->Lock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
AdClearEvents(
    _In_ PAC_ANTIDEBUG_PROTECTION Protection
    )
{
    if (!Protection) return STATUS_INVALID_PARAMETER;
    EnterCriticalSection(&Protection->Lock);
    Protection->HistoryHead = 0;
    Protection->HistoryCount = 0;
    LeaveCriticalSection(&Protection->Lock);
    return STATUS_SUCCESS;
}
