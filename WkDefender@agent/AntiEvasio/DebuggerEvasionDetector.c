/**************************************************/
/*  WkDefender Agent — 反调试检测引擎实现            */
/*  分析目标样本视角（AntiEvasio）                   */
/*                                                  */
/*  迁移自 ShadowStrike DebuggerEvasionDetector       */
/*  (.cpp 5581行 + .hpp 2408行)。                    */
/*                                                  */
/*  字节模式降级策略：                               */
/*   Phantom::Disasm 反汇编 → 原始字节模式匹配       */
/*   （INT3/INT xx/F1/UD2/RDTSC/RDTSCP/CPUID）；    */
/*   syscall stub 校验 → 纯字节 4C 8B D1 B8 + 0F 05; */
/*   内联钩子检测 → 首字节模式（E9/FF 25/68+C3 等）  */
/*                                                  */
/*  编码：UTF-8 with BOM（铁律）                     */
/**************************************************/

#include "DebuggerEvasionDetector.h"
#include "../WkDefenderHeader.h"
#include "../Common/Utils.h"            /* CoOpenProcessForQueryRead */
#include "../ProcessThreads.h"          /* WptGetThreadContext, WKD_THREAD_CONTEXT64 */

#include <intrin.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

/**************************************************/
/*          NT 函数类型与动态加载                   */
/**************************************************/

typedef NTSTATUS (NTAPI *PfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS (NTAPI *PfnNtQuerySystemInformation)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
    );

static PfnNtQueryInformationProcess  g_NtQueryInfoProcess  = NULL;
static PfnNtQuerySystemInformation   g_NtQuerySystemInfo   = NULL;
static BOOLEAN                       g_NtFuncsLoaded       = FALSE;

/**************************************************/
/*          SystemExtendedHandleInformation (0x40) */
/*  标准头文件不含此结构，内联定义。                 */
/**************************************************/

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID       Object;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR                       NumberOfHandles;
    ULONG_PTR                       Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

/* 进程信息类（NtQueryInformationProcess） */
#define EDE_PROCESS_DEBUG_OBJECT_HANDLE  0x1E    /* ProcessDebugObjectHandle */
#define EDE_PROCESS_DEBUG_FLAGS          0x1F    /* ProcessDebugFlags */
#define EDE_PROCESS_EXCEPTION_PORT       8       /* ProcessExceptionPort */
#define EDE_PROCESS_INSTRUMENTATION_CB   40      /* ProcessInstrumentationCallback */

/* SystemProcessInformation (0x05) 用于线程计数对比 */
#define EDE_SYSTEM_PROCESS_INFO          5

/* SystemExtendedHandleInformation (0x40) */
#define EDE_SYSTEM_EXTENDED_HANDLE_INFO  0x40

/**************************************************/
/*          回调与全局状态                         */
/**************************************************/

static PDEDE_DETECTION_CALLBACK g_Callback     = NULL;
static PVOID                   g_CallbackCtx  = NULL;
static PEDE_STATS              g_GlobalStats   = NULL;

/**************************************************/
/*          已知调试器进程/窗口/驱动名清单           */
/*  KnownDebuggerNames/KnownWindowClasses  */
/**************************************************/

static const WCHAR* const s_KnownDebuggerProcesses[] = {
    L"ollydbg.exe",       L"ida.exe",           L"ida64.exe",
    L"idag.exe",          L"idag32.exe",        L"idapro.exe",
    L"x64dbg.exe",        L"x32dbg.exe",        L"windbg.exe",
    L"windbgx.exe",       L"devenv.exe",        L"vsjitdebugger.exe",
    L"fiddler.exe",       L"wireshark.exe",     L"procmon.exe",
    L"procmon64.exe",     L"procexp.exe",       L"procexp64.exe",
    L"diskmon.exe",       L"tcpview.exe",       L"filemon.exe",
    L"autoruns.exe",      L"regshot.exe",       L"binaryninja.exe",
    L"radare2.exe",       L"r2.exe",            L"gdb.exe",
    L"lldb.exe",          L"cutter.exe",        L"jd-gui.exe",
    L"jds.exe",           L"processhacker.exe", L"processhacker64.exe",
    NULL
};

static const WCHAR* const s_KnownDebuggerWindows[] = {
    L"OLLYDBG",           L"OllyDbg",           L"x64dbg",
    L"Immunity Debugger", L"IDA",               L"WinDbgFrameClass",
    L"WinDbg",            L"Dbg议",             L"ProcessHacker",
    L"Fiddler",           L"Wireshark",         L"Procmon",
    NULL
};

static const WCHAR* const s_KnownDebuggerDrivers[] = {
    L"\\Device\\SoftICE", L"\\Device\\NTICE",
    L"\\Device\\SICE",    L"\\Device\\Syser",
    L"\\Device\\REGAPI",  L"\\Device\\WinIo",
    NULL
};

/* 已知插桩框架名（Frida/DynamoRIO/PIN/Detours 等） */
static const WCHAR* const s_InstrumentationNames[] = {
    L"frida",             L"frida-agent",       L"frida-gadget",
    L"dynamo",            L"dynamoRIO",         L"drrun",
    L"pin.exe",           L"pin",               L"intel_pin",
    L"detours",           L"apimonitor",        L"api_monitor",
    NULL
};

/* 时序 API 导入函数名（IAT 扫描时匹配） */
static const CHAR* const s_TimingApiNames[] = {
    "GetTickCount",       "GetTickCount64",
    "QueryPerformanceCounter", "QueryPerformanceFrequency",
    "GetSystemTimeAsFileTime", "GetLocalTime",
    "GetSystemTime",      "timeGetTime",
    "NtQueryPerformanceCounter",
    NULL
};

/* 反调试命令行关键词 */
static const WCHAR* const s_DebuggerCmdKeywords[] = {
    L"--no-sandbox",      L"-debug-on-start",
    L"debug.break",       L"int3",
    L"debugbreak",        L"isdebuggerpresent",
    L"ollydbg",           L"x64dbg",
    L"windbg",            L"ida64",
    NULL
};

/* 可疑启动目录 */
static const WCHAR* const s_SuspiciousDirs[] = {
    L"\\temp\\",          L"\\tmp\\",
    L"\\appdata\\local\\temp\\",
    L"\\downloads\\",     L"\\public\\",
    L"\\recycle",         NULL
};

/**************************************************/
/*          便利宏                                 */
/**************************************************/

#define EdepHasFlag(flags, f)  (((ULONG)(flags) & (ULONG)(f)) != 0)

#define EdepSafeClose(h) do { if ((h) != NULL && (h) != INVALID_HANDLE_VALUE) { \
    CloseHandle(h); (h) = NULL; } } while(0)

/* SEH 安全读远程内存 */
#define EdepReadRemote(hProcess, addr, buf, sz) \
    EdepReadRemoteMemory((hProcess), (PVOID)(addr), (buf), (sz))

/**************************************************/
/*          Nt 函数动态加载                        */
/**************************************************/

_Use_decl_annotations_
static
VOID
EdepLoadNtFunctions(
    VOID
    )
{
    HMODULE hNtdll;

    if (g_NtFuncsLoaded) return;

    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    g_NtQueryInfoProcess = (PfnNtQueryInformationProcess)
        GetProcAddress(hNtdll, "NtQueryInformationProcess");
    g_NtQuerySystemInfo = (PfnNtQuerySystemInformation)
        GetProcAddress(hNtdll, "NtQuerySystemInformation");

    g_NtFuncsLoaded = (g_NtQueryInfoProcess != NULL &&
                       g_NtQuerySystemInfo   != NULL);
}

/**************************************************/
/*          SEH 安全读远程内存                      */
/**************************************************/

static
BOOLEAN
EdepReadRemoteMemory(
    _In_  HANDLE hProcess,
    _In_  PVOID  RemoteAddress,
    _Out_writes_(Size) PVOID  LocalBuffer,
    _In_  SIZE_T Size
    )
{
    SIZE_T bytesRead = 0;
    __try {
        return ReadProcessMemory(hProcess, RemoteAddress, LocalBuffer, Size, &bytesRead)
               && bytesRead == Size;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

/**************************************************/
/*          辅助：将调试器名小写化并匹配             */
/**************************************************/

static
BOOLEAN
EdepIsDebuggerProcess(
    _In_ PCWSTR ProcessName
    )
{
    WCHAR lower[MAX_PATH];
    SIZE_T i;
    if (!ProcessName) return FALSE;

    wcscpy_s(lower, MAX_PATH, ProcessName);
    _wcslwr_s(lower, MAX_PATH);

    for (i = 0; s_KnownDebuggerProcesses[i]; i++) {
        if (wcsstr(lower, s_KnownDebuggerProcesses[i]))
            return TRUE;
    }
    return FALSE;
}

static
BOOLEAN
EdepIsInstrumentationDll(
    _In_ PCWSTR ModuleName
    )
{
    WCHAR lower[MAX_PATH];
    SIZE_T i;
    if (!ModuleName) return FALSE;

    wcscpy_s(lower, MAX_PATH, ModuleName);
    _wcslwr_s(lower, MAX_PATH);

    for (i = 0; s_InstrumentationNames[i]; i++) {
        if (wcsstr(lower, s_InstrumentationNames[i]))
            return TRUE;
    }
    return FALSE;
}

/**************************************************/
/*          检测条目添加                            */
/**************************************************/

static
VOID
EdepAddDetection(
    _Inout_ PEDE_RESULT   Result,
    _In_    EDE_TECHNIQUE Technique,
    _In_    EDE_CATEGORY  Category,
    _In_    EDE_SEVERITY  Severity,
    _In_    DOUBLE        Confidence,
    _In_opt_ ULONG_PTR    Address,
    _In_opt_ ULONG        ThreadId,
    _In_    PCWSTR        Description,
    _In_opt_ PCWSTR        Details
    )
{
    PEDE_DETECTION det;
    SIZE_T i;

    if (Result->TotalDetections >= EDE_MAX_DETECTIONS) return;
    if (Confidence < 0.0 || Confidence > 1.0) Confidence = 0.5;

    det = &Result->Detections[Result->TotalDetections];
    det->Technique   = Technique;
    det->Category    = Category;
    det->Severity    = Severity;
    det->Confidence  = Confidence;
    det->Address     = Address;
    det->ThreadId    = ThreadId;
    det->Description[0] = L'\0';
    det->Details[0]     = L'\0';

    if (Description) {
        for (i = 0; Description[i] && i < EDE_MAX_DESCRIPTION - 1; i++)
            det->Description[i] = (WCHAR)Description[i];
        det->Description[i] = L'\0';
    }
    if (Details) {
        for (i = 0; Details[i] && i < EDE_MAX_DETAILS - 1; i++)
            det->Details[i] = (WCHAR)Details[i];
        det->Details[i] = L'\0';
    }

    /* 更新类别位码 */
    if ((ULONG)Category < 32)
        Result->DetectedCategories |= (1u << (ULONG)Category);

    Result->TotalDetections++;
    if (Severity > Result->MaxSeverity)
        Result->MaxSeverity = Severity;

    /* 更新统计 */
    if (g_GlobalStats && (ULONG)Category < 16)
        InterlockedIncrement64(&g_GlobalStats->CategoryDetections[Category]);

    /* 触发回调 */
    if (g_Callback) {
        g_Callback(Result->TargetPid, det, g_CallbackCtx);
    }
}

/**************************************************/
/*          工具：地址是否落在已加载模块内            */
/**************************************************/

/* 通过 Toolhelp32 模块快照判定（本地进程为主模块对比） */
typedef struct _EDE_MODULE_ENTRY {
    ULONG_PTR Base;
    ULONG     Size;
    WCHAR     Name[MAX_PATH];
} EDE_MODULE_ENTRY;

#define EDE_MAX_MODULES 512

static
ULONG
EdepSnapshotModules(
    _In_  DWORD            TargetPid,
    _Out_writes_to_(MaxModules, *Count)
    PEDE_MODULE_ENTRY     Modules,
    _In_  ULONG            MaxModules,
    _Out_ PULONG           Count
    )
{
    HANDLE hSnap;
    MODULEENTRY32W me;
    ULONG n = 0;

    *Count = 0;
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                     TargetPid);
    if (hSnap == INVALID_HANDLE_VALUE) return STATUS_UNSUCCESSFUL;

    me.dwSize = sizeof(me);
    if (Module32FirstW(hSnap, &me)) {
        do {
            if (n < MaxModules) {
                Modules[n].Base = (ULONG_PTR)me.modBaseAddr;
                Modules[n].Size = me.modBaseSize;
                wcscpy_s(Modules[n].Name, MAX_PATH, me.szModule);
                n++;
            }
        } while (Module32NextW(hSnap, &me) && n < MaxModules);
    }
    CloseHandle(hSnap);
    *Count = n;
    return STATUS_SUCCESS;
}

static
BOOLEAN
EdepIsAddressInModules(
    _In_ ULONG_PTR          Address,
    _In_ const EDE_MODULE_ENTRY* Modules,
    _In_ ULONG              ModuleCount,
    _Out_opt_ PWSTR         OutModuleName,
    _In_ ULONG              NameLen
    )
{
    ULONG i;
    for (i = 0; i < ModuleCount; i++) {
        if (Address >= Modules[i].Base &&
            Address <  Modules[i].Base + Modules[i].Size) {
            if (OutModuleName && NameLen > 0)
                wcscpy_s(OutModuleName, NameLen, Modules[i].Name);
            return TRUE;
        }
    }
    if (OutModuleName && NameLen > 0) OutModuleName[0] = L'\0';
    return FALSE;
}

/**************************************************/
/*  工具：反调试字节模式扫描（替代 Phantom::Disasm） */
/*  扫描代码区域中的反调试指令字节编码。            */
/*  发现匹配项时返回 TRUE 并填充偏移。              */
/**************************************************/

/* 单条反调试字节模式 */
typedef struct _EDE_BYTE_PATTERN {
    const UCHAR* Pattern;
    ULONG        Length;
    ULONG        Technique;     /* EDE_TECHNIQUE 值 */
    PCWSTR       Name;
} EDE_BYTE_PATTERN;

/* 反调试字节模式表 */
static const EDE_BYTE_PATTERN s_AntiDebugPatterns[] = {
    /* INT3 */
    { (const UCHAR[]){0xCC}, 1,
      EdeTechniqueException_INT3, L"INT3 (0xCC)" },
    /* INT 2D (debug service) */
    { (const UCHAR[]){0xCD, 0x2D}, 2,
      EdeTechniqueException_INT2D, L"INT 2D" },
    /* INT 3 (CD 03 编码) */
    { (const UCHAR[]){0xCD, 0x03}, 2,
      EdeTechniqueException_INT3, L"INT 3 (CD 03)" },
    /* ICEBP / INT1 (F1) */
    { (const UCHAR[]){0xF1}, 1,
      EdeTechniqueException_ICEBP, L"ICEBP (0xF1)" },
    /* UD2 */
    { (const UCHAR[]){0x0F, 0x0B}, 2,
      EdeTechniqueException_UD2, L"UD2 (0F 0B)" },
    /* RDTSC */
    { (const UCHAR[]){0x0F, 0x31}, 2,
      EdeTechniqueTiming_RDTSC, L"RDTSC (0F 31)" },
    /* RDTSCP */
    { (const UCHAR[]){0x0F, 0x01, 0xF7}, 3,
      EdeTechniqueTiming_RDTSCP, L"RDTSCP (0F 01 F7)" },
    /* CPUID */
    { (const UCHAR[]){0x0F, 0xA2}, 2,
      EdeTechniqueTiming_RDTSC, /* CPUID 归入时序类 */
      L"CPUID (0F A2)" },
    /* RDPMC */
    { (const UCHAR[]){0x0F, 0x33}, 2,
      EdeTechniqueTiming_RDTSC, L"RDPMC (0F 33)" },
};

#define EDE_NUM_ANTI_DEBUG_PATTERNS \
    (sizeof(s_AntiDebugPatterns) / sizeof(s_AntiDebugPatterns[0]))

static
BOOLEAN
EdepScanBytePatterns(
    _In_reads_(Size) const UCHAR* Code,
    _In_  SIZE_T Size,
    _Out_ PULONG FoundCount,
    _Out_ PULONG UniqueTechniques
    )
{
    SIZE_T offset;
    ULONG found = 0;
    ULONG uniqueMask = 0;
    SIZE_t p;

    *FoundCount = 0;
    *UniqueTechniques = 0;

    for (offset = 0; offset + 1 < Size; offset++) {
        for (p = 0; p < EDE_NUM_ANTI_DEBUG_PATTERNS; p++) {
            const EDE_BYTE_PATTERN* pat = &s_AntiDebugPatterns[p];
            if (Size - offset >= pat->Length) {
                if (memcmp(Code + offset, pat->Pattern, pat->Length) == 0) {
                    found++;
                    if (pat->Technique < 32)
                        uniqueMask |= (1u << pat->Technique);
                    break; /* 一个偏移只匹配一次 */
                }
            }
        }
    }

    *FoundCount = found;
    *UniqueTechniques = uniqueMask;
    return (found > 0);
}

/**************************************************/
/*  工具：检测函数入口内联钩子（字节模式版）          */
/*  DetectInlineHook 5 种模式。             */
/*  无 Phantom::Disasm，用原始字节判定。            */
/**************************************************/

static
BOOLEAN
EdepDetectInlineHook(
    _In_reads_(Size) const UCHAR* FunctionBytes,
    _In_  SIZE_T Size,
    _Out_writes_(EDE_MAX_DETAILS) WCHAR* OutDetails
    )
{
    OutDetails[0] = L'\0';
    if (!FunctionBytes || Size < 5) return FALSE;

    /* Pattern 1: JMP rel32 (E9 xx xx xx xx) */
    if (FunctionBytes[0] == 0xE9) {
        wcscpy_s(OutDetails, EDE_MAX_DETAILS, L"JMP rel32 at function start");
        return TRUE;
    }

    /* Pattern 2: JMP [RIP+disp32] (FF 25 xx xx xx xx) */
    if (FunctionBytes[0] == 0xFF && Size >= 2 && FunctionBytes[1] == 0x25) {
        wcscpy_s(OutDetails, EDE_MAX_DETAILS, L"JMP [RIP+disp32] at function start");
        return TRUE;
    }

    /* Pattern 3: PUSH imm32 + RET (68 xx xx xx xx C3) */
    if (FunctionBytes[0] == 0x68 && Size >= 6 && FunctionBytes[5] == 0xC3) {
        wcscpy_s(OutDetails, EDE_MAX_DETAILS, L"PUSH+RET hook pattern");
        return TRUE;
    }

    /* Pattern 4: MOV RAX, imm64 + JMP RAX (48 B8 xx...xx FF E0) */
    if (Size >= 12 &&
        FunctionBytes[0] == 0x48 && FunctionBytes[1] == 0xB8 &&
        FunctionBytes[10] == 0xFF && FunctionBytes[11] == 0xE0) {
        wcscpy_s(OutDetails, EDE_MAX_DETAILS, L"MOV RAX,imm64+JMP RAX hook");
        return TRUE;
    }

    /* Pattern 5: INT3 at function start (CC) */
    if (FunctionBytes[0] == 0xCC) {
        wcscpy_s(OutDetails, EDE_MAX_DETAILS, L"INT3 at function start");
        return TRUE;
    }

    return FALSE;
}

/**************************************************/
/*  工具：x64 syscall stub 校验（字节模式版）        */
/*  ValidateSyscallStubBytePattern          */
/*  标准模式：4C 8B D1 B8 xx xx 00 00 [..] 0F 05  */
/**************************************************/

static
BOOLEAN
EdepValidateSyscallStub(
    _In_reads_(Size) const UCHAR* StubBytes,
    _In_  SIZE_T Size,
    _Out_writes_(EDE_MAX_DETAILS) WCHAR* OutDetails
    )
{
    SIZE_T i;
    OutDetails[0] = L'\0';

    if (!StubBytes || Size < 8) return TRUE;

    /* Phase 1：首字节快速判定已知钩子模式 */
    switch (StubBytes[0]) {
    case 0xE9: /* JMP rel32 */
        wcscpy_s(OutDetails, EDE_MAX_DETAILS, L"Inline hook: JMP rel32 at stub start");
        return FALSE;
    case 0xCC: /* INT3 */
        wcscpy_s(OutDetails, EDE_MAX_DETAILS, L"Software breakpoint at stub start");
        return FALSE;
    case 0xFF:
        if (Size >= 2 && StubBytes[1] == 0x25) {
            wcscpy_s(OutDetails, EDE_MAX_DETAILS, L"Inline hook: JMP [RIP+disp32] at stub start");
            return FALSE;
        }
        break;
    case 0x48: /* MOV RAX, imm64 */
        if (Size >= 12 && StubBytes[1] == 0xB8) {
            if (Size >= 14 && StubBytes[10] == 0xFF && StubBytes[11] == 0xE0) {
                wcscpy_s(OutDetails, EDE_MAX_DETAILS, L"Inline hook: MOV RAX,imm64+JMP RAX");
                return FALSE;
            }
        }
        break;
    case 0x68: /* PUSH imm32 */
        if (Size >= 6 && (StubBytes[5] == 0xC3 || StubBytes[5] == 0xC2)) {
            wcscpy_s(OutDetails, EDE_MAX_DETAILS, L"Inline hook: PUSH imm32+RET");
            return FALSE;
        }
        break;
    default:
        break;
    }

    /* Phase 2：标准 x64 syscall stub 验证 */
    /* 期望：4C 8B D1 B8 xx xx 00 00 ... 0F 05 */
    if (StubBytes[0] == 0x4C &&
        StubBytes[1] == 0x8B &&
        StubBytes[2] == 0xD1 &&
        StubBytes[3] == 0xB8) {
        /* 扫描 0F 05 (SYSCALL) 是否在合理范围内 */
        for (i = 8; i < Size - 1 && i < 32; i++) {
            if (StubBytes[i] == 0x0F && StubBytes[i + 1] == 0x05) {
                wcscpy_s(OutDetails, EDE_MAX_DETAILS, L"Valid syscall stub");
                return TRUE;
            }
        }
        wcscpy_s(OutDetails, EDE_MAX_DETAILS, L"Valid prologue but no SYSCALL found");
        return FALSE;
    }

    /* 非标准 prologue */
    wcscpy_s(OutDetails, EDE_MAX_DETAILS, L"Non-standard syscall stub prologue");
    return FALSE;
}

/**************************************************/
/*  工具：从 syscall stub 提取 syscall 号           */
/*  ExtractSyscallNumberFromStub            */
/*  Pattern 1: 4C 8B D1 B8 [num LE]               */
/*  Pattern 2: 跟随 E9 跳转（限 ntdll ±1MB）       */
/*  Pattern 3: 宽松扫 B8 + 附近 0F 05 验证          */
/**************************************************/

static
ULONG
EdepExtractSyscallNumber(
    _In_reads_(MaxSize) const UCHAR* StubBytes,
    _In_  SIZE_T MaxSize
    )
{
    SIZE_T offset;
    ULONG num;

    if (!StubBytes || MaxSize < 8) return 0;

    __try {
        /* Pattern 1: 标准 x64 4C 8B D1 B8 */
        if (MaxSize >= 8 &&
            StubBytes[0] == 0x4C && StubBytes[1] == 0x8B &&
            StubBytes[2] == 0xD1 && StubBytes[3] == 0xB8) {
            num = (ULONG)StubBytes[4]       | ((ULONG)StubBytes[5] << 8) |
                  ((ULONG)StubBytes[6] << 16) | ((ULONG)StubBytes[7] << 24);
            if (num < 0x2000) return num;
        }

        /* Pattern 3: 宽松扫 B8 + 附近 syscall/int 2e */
        for (offset = 0; offset < (MaxSize < 16 ? MaxSize : 16) - 4; offset++) {
            if (StubBytes[offset] == 0xB8) {
                num = (ULONG)StubBytes[offset + 1]       |
                      ((ULONG)StubBytes[offset + 2] << 8) |
                      ((ULONG)StubBytes[offset + 3] << 16) |
                      ((ULONG)StubBytes[offset + 4] << 24);
                if (num < 0x2000) {
                    SIZE_T i;
                    for (i = offset + 5; i < MaxSize - 1 && i < offset + 20; i++) {
                        if ((StubBytes[i] == 0x0F && StubBytes[i+1] == 0x05) ||
                            (StubBytes[i] == 0xCD && StubBytes[i+1] == 0x2E)) {
                            return num;
                        }
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* 内存访问违规 */
    }
    return 0;
}

/**************************************************/
/*          检测 1：PEB 分析                       */
/*  PEB.BeingDebugged / NtGlobalFlag / Heap Flags  */
/*  AnalyzePEB (L1988-2168)                */
/**************************************************/

static
VOID
EdepAnalyzePEB(
    _In_ HANDLE hProcess,
    _In_ BOOLEAN Is64Bit,
    _Inout_ PEDE_RESULT Result
    )
{
    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen = 0;
    UCHAR pebBuf[512];
    ULONG_PTR pebAddr;
    NTSTATUS status;

    if (!g_NtQueryInfoProcess) return;

    /* 取 PEB 基址 */
    status = g_NtQueryInfoProcess(hProcess, ProcessBasicInformation,
                                  &pbi, sizeof(pbi), &retLen);
    if (!NT_SUCCESS(status) || !pbi.PebBaseAddress) return;

    pebAddr = (ULONG_PTR)pbi.PebBaseAddress;

    /* 读取 PEB 前 512 字节 */
    if (!EdepReadRemote(hProcess, pebAddr, pebBuf, sizeof(pebBuf)))
        return;

    Result->TechniquesChecked++;

    /* PEB.BeingDebugged (offset 0x02, 同 x64/x86) */
    if (pebBuf[2] != 0) {
        EdepAddDetection(Result, EdeTechniquePEB_BeingDebugged,
                         EdeCategoryPEBBased, EdeSeverityHigh, 0.95,
                         pebAddr + 2, 0,
                         L"PEB.BeingDebugged is set",
                         L"Remote process has BeingDebugged=1 in PEB");
    }

    /* PEB.NtGlobalFlag (x64 offset 0xBC, x86 offset 0x68) */
    {
        ULONG ntGlobalFlag;
        ULONG offset = Is64Bit ? 0xBC : 0x68;

        if (offset + sizeof(ULONG) <= sizeof(pebBuf)) {
            ntGlobalFlag = *(ULONG*)(pebBuf + offset);
            /* 调试堆标志掩码：FLG_HEAP_ENABLE_TAIL_CHECK|FREE_CHECK|VALIDATE_PARAMETERS = 0x70 */
            if (ntGlobalFlag & 0x70) {
                WCHAR details[64];
                _snwprintf_s(details, 64, _TRUNCATE,
                             L"NtGlobalFlag=0x%08X (debug heap flags)",
                             ntGlobalFlag);
                EdepAddDetection(Result, EdeTechniquePEB_NtGlobalFlag,
                                 EdeCategoryPEBBased, EdeSeverityHigh, 0.90,
                                 pebAddr + offset, 0,
                                 L"PEB.NtGlobalFlag contains debug heap flags",
                                 details);
            }
        }
    }

    /* PEB.ProcessHeap → Heap.Flags / Heap.ForceFlags */
    /* ProcessHeap 指针在 offset 0x30 (x64) / 0x18 (x86) */
    {
        ULONG_PTR heapAddr = 0;
        ULONG heapOffset = Is64Bit ? 0x30 : 0x18;
        UCHAR heapBuf[64];

        if (heapOffset + sizeof(ULONG_PTR) <= sizeof(pebBuf)) {
            if (Is64Bit)
                heapAddr = *(ULONG_PTR*)(pebBuf + heapOffset);
            else
                heapAddr = (ULONG_PTR)(*(ULONG*)(pebBuf + heapOffset));

            if (heapAddr && EdepReadRemote(hProcess, (PVOID)heapAddr, heapBuf, sizeof(heapBuf))) {
                /* Flags offset: 0x40 (x64) / 0x40 (x86) */
                /* ForceFlags offset: 0x44 (x64) / 0x44 (x86) */
                ULONG heapFlags     = *(ULONG*)(heapBuf + 0x40);
                ULONG heapForceFlags = *(ULONG*)(heapBuf + 0x44);

                /* 正常 Flags = 0x2 (HEAP_GROWABLE) 或 0x40 (HEAP_CREATE_ENABLE_TRACING)
                 * 调试 Flags = 0x50000062 等（含 FLG_HEAP_*位）*/
                if (heapForceFlags != 0) {
                    WCHAR details[128];
                    _snwprintf_s(details, 128, _TRUNCATE,
                                 L"Heap.Flags=0x%08X ForceFlags=0x%08X",
                                 heapFlags, heapForceFlags);
                    EdepAddDetection(Result, EdeTechniquePEB_HeapFlags,
                                     EdeCategoryPEBBased, EdeSeverityHigh, 0.85,
                                     heapAddr, 0,
                                     L"Heap ForceFlags non-zero (debug heap)",
                                     details);
                }
            }
        }
    }
}

/**************************************************/
/*          检测 2：DebugObject / DebugPort         */
/*  AnalyzeAPIUsage (L2168-2240)            */
/**************************************************/

static
VOID
EdepAnalyzeDebugObject(
    _In_ HANDLE hProcess,
    _Inout_ PEDE_RESULT Result
    )
{
    HANDLE debugObject = NULL;
    NTSTATUS status;
    ULONG retLen = 0;

    if (!g_NtQueryInfoProcess) return;

    Result->TechniquesChecked++;

    /* ProcessDebugObjectHandle (0x1E) — 有调试对象 = 被调试 */
    status = g_NtQueryInfoProcess(hProcess, EDE_PROCESS_DEBUG_OBJECT_HANDLE,
                                  &debugObject, sizeof(debugObject), &retLen);
    if (NT_SUCCESS(status) && debugObject != NULL) {
        WCHAR details[128];
        _snwprintf_s(details, 128, _TRUNCATE,
                     L"DebugObject handle=0x%p", debugObject);
        EdepAddDetection(Result, EdeTechniqueAPI_NtQueryInfo_DebugObject,
                         EdeCategoryObjectHandleBased, EdeSeverityCritical, 0.95,
                         (ULONG_PTR)debugObject, 0,
                         L"ProcessDebugObjectHandle is set (debugger attached)",
                         details);
        CloseHandle(debugObject);
    }

    /* ProcessDebugFlags (0x1F) — 值为 0 = 被调试 */
    {
        ULONG debugFlags = 1;
        retLen = 0;
        status = g_NtQueryInfoProcess(hProcess, EDE_PROCESS_DEBUG_FLAGS,
                                      &debugFlags, sizeof(debugFlags), &retLen);
        if (NT_SUCCESS(status) && debugFlags == 0) {
            EdepAddDetection(Result, EdeTechniqueAPI_NtQueryInfo_DebugFlags,
                             EdeCategoryObjectHandleBased, EdeSeverityCritical, 0.95,
                             0, 0,
                             L"ProcessDebugFlags=0 (debugger present)",
                             L"NtQueryInformationProcess(DebugFlags) returned 0");
        }
    }
}

/**************************************************/
/*          检测 3：全系统句柄枚举                  */
/*  AnalyzeHandles (L2396-2467)            */
/*  检测调试对象句柄、进程注入句柄等可疑句柄。      */
/**************************************************/

static
VOID
EdepAnalyzeHandles(
    _In_ HANDLE hProcess,
    _In_ ULONG  TargetPid,
    _Inout_ PEDE_RESULT Result
    )
{
    SYSTEM_HANDLE_INFORMATION_EX* pHandleInfo = NULL;
    ULONG bufSize = 0x10000; /* 64KB 初始缓冲 */
    ULONG retLen = 0;
    NTSTATUS status;
    ULONG i;
    ULONG debugObjCount = 0;
    ULONG remoteHandleCount = 0;

    if (!g_NtQuerySystemInfo) return;

    Result->TechniquesChecked++;

    /* 循环扩容直到成功 */
    for (i = 0; i < 4; i++) {
        pHandleInfo = (SYSTEM_HANDLE_INFORMATION_EX*)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
        if (!pHandleInfo) return;

        status = g_NtQuerySystemInfo(EDE_SYSTEM_EXTENDED_HANDLE_INFO,
                                     pHandleInfo, bufSize, &retLen);
        if (NT_SUCCESS(status)) break;
        HeapFree(GetProcessHeap(), 0, pHandleInfo);
        pHandleInfo = NULL;
        bufSize *= 2;
        if (bufSize > 16 * 1024 * 1024) break; /* 上限 16MB */
    }

    if (!pHandleInfo) return;

    /* 遍历句柄，统计目标进程持有的跨进程句柄 */
    for (i = 0; i < pHandleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* entry = &pHandleInfo->Handles[i];

        if (entry->UniqueProcessId == (ULONG_PTR)TargetPid) {
            remoteHandleCount++;

            /* 调试对象类型句柄 (GrantedAccess 含 DEBUG_READ_EVENT 等) */
            /* 通过 GrantedAccess 位模式判断：0x1F0FFF 是全访问调试权限 */
            if ((entry->GrantedAccess & 0x1F0FFF) == 0x1F0FFF ||
                (entry->GrantedAccess & 0x0010) != 0) {
                debugObjCount++;
            }
        }
    }

    Result->HandlesEnumerated = (ULONG)pHandleInfo->NumberOfHandles;

    if (remoteHandleCount > 100) {
        WCHAR details[128];
        _snwprintf_s(details, 128, _TRUNCATE,
                     L"Target holds %lu cross-process handles (total system: %lu)",
                     remoteHandleCount, (ULONG)pHandleInfo->NumberOfHandles);
        EdepAddDetection(Result, EdeTechniqueObject_ProcessHandleEnum,
                         EdeCategoryObjectHandleBased, EdeSeverityMedium, 0.60,
                         0, 0,
                         L"High cross-process handle count",
                         details);
    }

    HeapFree(GetProcessHeap(), 0, pHandleInfo);
}

/**************************************************/
/*          检测 4：线程上下文（DR 寄存器）         */
/*  AnalyzeThreadContexts (L2240-2348)     */
/*  复用 WptGetThreadContext 获取 DR0-3/DR6/DR7   */
/**************************************************/

static
VOID
EdepAnalyzeThreadContexts(
    _In_ DWORD TargetPid,
    _Inout_ PEDE_RESULT Result
    )
{
    HANDLE hSnap;
    THREADENTRY32W te;
    ULONG hwBpCount = 0;

    Result->TechniquesChecked++;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    te.dwSize = sizeof(te);
    if (Thread32FirstW(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != TargetPid) continue;
            if (Result->ThreadsScanned >= EDE_MAX_THREADS) break;

            {
                WKD_THREAD_CONTEXT64 ctx;
                if (WptGetThreadContext(te.th32ThreadID, &ctx)) {
                    Result->ThreadsScanned++;

                    /* 检查 DR7 低 8 位是否非零（硬件断点启用） */
                    if (ctx.Dr7 & 0xFF) {
                        ULONG bpCount = 0;
                        if (ctx.Dr0) bpCount++;
                        if (ctx.Dr1) bpCount++;
                        if (ctx.Dr2) bpCount++;
                        if (ctx.Dr3) bpCount++;

                        if (bpCount >= EDE_BREAKPOINT_THRESHOLD) {
                            WCHAR details[192];
                            _snwprintf_s(details, 192, _TRUNCATE,
                                L"TID=%lu DR0=0x%p DR1=0x%p DR2=0x%p DR3=0x%p DR7=0x%p (%lu BP)",
                                te.th32ThreadID,
                                (PVOID)ctx.Dr0, (PVOID)ctx.Dr1,
                                (PVOID)ctx.Dr2, (PVOID)ctx.Dr3,
                                (PVOID)ctx.Dr7, bpCount);
                            EdepAddDetection(Result,
                                EdeTechniqueHW_BreakpointRegisters,
                                EdeCategoryHardwareDebugRegisters,
                                EdeSeverityHigh, 0.90,
                                ctx.Dr0 ? ctx.Dr0 : ctx.Dr1,
                                te.th32ThreadID,
                                L"Hardware breakpoints detected (DR0-3)",
                                details);
                        }
                        hwBpCount += bpCount;
                    }
                }
            }
        } while (Thread32NextW(hSnap, &te));
    }

    CloseHandle(hSnap);

    if (hwBpCount > 0) {
        WCHAR details[64];
        _snwprintf_s(details, 64, _TRUNCATE,
                     L"Total hardware breakpoints found: %lu", hwBpCount);
        EdepAddDetection(Result, EdeTechniqueHW_DebugControlRegister,
                         EdeCategoryHardwareDebugRegisters, EdeSeverityMedium, 0.80,
                         0, 0,
                         L"Hardware debug control registers active",
                         details);
    }
}

/**************************************************/
/*          检测 5：隐藏线程                        */
/*  CheckHiddenThreadsInternal (L2890-2990)*/
/*  Toolhelp32 线程快照 vs 内核线程计数差异检测。   */
/**************************************************/

static
VOID
EdepCheckHiddenThreads(
    _In_ HANDLE hProcess,
    _In_ DWORD  TargetPid,
    _Inout_ PEDE_RESULT Result
    )
{
    HANDLE hSnap;
    THREADENTRY32W te;
    ULONG toolhelpCount = 0;

    Result->TechniquesChecked++;

    /* Step 1: Toolhelp32 线程枚举计数 */
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    te.dwSize = sizeof(te);
    if (Thread32FirstW(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == TargetPid)
                toolhelpCount++;
        } while (Thread32NextW(hSnap, &te));
    }
    CloseHandle(hSnap);

    /* Step 2: 通过 NtQuerySystemInformation 获取内核线程计数 */
    if (g_NtQuerySystemInfo && toolhelpCount > 0) {
        UCHAR buf[64 * 1024];
        ULONG retLen = 0;
        NTSTATUS status;

        status = g_NtQuerySystemInfo(EDE_SYSTEM_PROCESS_INFO,
                                     buf, sizeof(buf), &retLen);
        if (NT_SUCCESS(status)) {
            /* 遍历 SYSTEM_PROCESS_INFORMATION 链表 */
            ULONG_PTR offset = 0;
            while (offset < retLen) {
                /* SYSTEM_PROCESS_INFORMATION 布局:
                 * NextEntryOffset (ULONG, +0x00)
                 * NumberOfThreads (ULONG, +0x04)
                 * ... 其余字段 ...
                 * Threads[0] (SYSTEM_THREAD_INFORMATION)
                 */
                PSYSTEM_PROCESS_INFORMATION procInfo =
                    (PSYSTEM_PROCESS_INFORMATION)(buf + offset);
                ULONG kernelThreadCount = procInfo->NumberOfThreads;

                if ((ULONG_PTR)procInfo->UniqueProcessId == (ULONG_PTR)TargetPid) {
                    if (kernelThreadCount > toolhelpCount) {
                        WCHAR details[128];
                        _snwprintf_s(details, 128, _TRUNCATE,
                            L"Kernel threads=%lu Toolhelp threads=%lu (delta=%lu)",
                            kernelThreadCount, toolhelpCount,
                            kernelThreadCount - toolhelpCount);
                        EdepAddDetection(Result,
                            EdeTechniqueThread_HiddenThread,
                            EdeCategoryThreadBased, EdeSeverityHigh, 0.85,
                            0, 0,
                            L"Hidden threads detected (kernel count > Toolhelp count)",
                            details);
                    }
                    break;
                }

                if (procInfo->NextEntryOffset == 0) break;
                offset += procInfo->NextEntryOffset;
            }
        }
    }
}

/**************************************************/
/*          检测 6：TLS 回调                        */
/*  CheckTLSCallbacksInternal (L2712-2890)*/
/*  读取目标 PE TLS 目录 → 回调地址 → 字节模式扫描 */
/**************************************************/

static
VOID
EdepCheckTLSCallbacks(
    _In_ HANDLE hProcess,
    _In_ DWORD  TargetPid,
    _Inout_ PEDE_RESULT Result
    )
{
    HMODULE hMods[256];
    DWORD   cbNeeded;
    ULONG   i;

    Result->TechniquesChecked++;

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        return;

    for (i = 0; i < cbNeeded / sizeof(HMODULE) && i < 256; i++) {
        UCHAR modHeader[4096];
        PIMAGE_DOS_HEADER dosHdr;
        PIMAGE_NT_HEADERS ntHdr;
        ULONG_PTR modBase = (ULONG_PTR)hMods[i];
        ULONG tlsRva = 0, tlsSize = 0;

        if (!EdepReadRemote(hProcess, (PVOID)modBase, modHeader, sizeof(modHeader)))
            continue;

        dosHdr = (PIMAGE_DOS_HEADER)modHeader;
        if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) continue;

        /* 仅处理 64 位 PE */
        ntHdr = (PIMAGE_NT_HEADERS)(modHeader + dosHdr->e_lfanew);
        if ((ULONG_PTR)ntHdr + sizeof(IMAGE_NT_HEADERS) >
            (ULONG_PTR)modHeader + sizeof(modHeader))
            continue;
        if (ntHdr->Signature != IMAGE_NT_SIGNATURE) continue;
        if (ntHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) continue;

        {
            PIMAGE_DATA_DIRECTORY tlsDir =
                &ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            tlsRva  = tlsDir->VirtualAddress;
            tlsSize = tlsDir->Size;
        }

        if (tlsRva == 0 || tlsSize == 0) continue;

        /* 读取 IMAGE_TLS_DIRECTORY64 */
        {
            UCHAR tlsBuf[64];
            IMAGE_TLS_DIRECTORY64* tlsDir;
            ULONG_PTR callbackRva;

            if (!EdepReadRemote(hProcess, (PVOID)(modBase + tlsRva), tlsBuf, sizeof(tlsBuf)))
                continue;

            tlsDir = (IMAGE_TLS_DIRECTORY64*)tlsBuf;
            callbackRva = (ULONG_PTR)(tlsDir->AddressOfCallBacks - modBase);

            /* 回调数组是 RVA 数组（8 字节指针 × N） */
            if (callbackRva > 0 && callbackRva < 0x100000) {
                ULONG cbIdx;
                for (cbIdx = 0; cbIdx < 16; cbIdx++) { /* 最多检查 16 个回调 */
                    UCHAR cbPtrBuf[8];
                    ULONG_PTR cbAddr;
                    UCHAR codeBuf[512];
                    ULONG foundCount = 0, uniqueMask = 0;

                    if (!EdepReadRemote(hProcess,
                        (PVOID)(modBase + callbackRva + cbIdx * 8),
                        cbPtrBuf, sizeof(cbPtrBuf)))
                        break;

                    cbAddr = *(ULONG_PTR*)cbPtrBuf;
                    if (cbAddr == 0) break;

                    if (!EdepReadRemote(hProcess, (PVOID)cbAddr, codeBuf, sizeof(codeBuf)))
                        continue;

                    /* 扫描回调代码中的反调试指令 */
                    if (EdepScanBytePatterns(codeBuf, sizeof(codeBuf),
                                             &foundCount, &uniqueMask) &&
                        foundCount > 0) {
                        WCHAR details[192];
                        _snwprintf_s(details, 192, _TRUNCATE,
                            L"TLS callback #%lu at 0x%p: %lu anti-debug instructions",
                            cbIdx, (PVOID)cbAddr, foundCount);
                        EdepAddDetection(Result,
                            EdeTechniqueThread_TLSCallback,
                            EdeCategoryThreadBased, EdeSeverityHigh, 0.80,
                            cbAddr, 0,
                            L"TLS callback contains anti-debug instructions",
                            details);
                        break; /* 一个模块一个告警 */
                    }
                }
            }
        }
    }
}

/**************************************************/
/*          检测 7：内存扫描                        */
/*  ScanMemory (L2467-2600)                */
/*  VirtualQueryEx 枚举 → 读代码区 → 字节模式扫描  */
/**************************************************/

static
VOID
EdepScanMemory(
    _In_ HANDLE hProcess,
    _In_ PEDE_RESULT Result
    )
{
    ULONG_PTR addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    ULONG regionCount = 0;
    ULONG totalBpCount = 0;

    Result->TechniquesChecked++;

    while (regionCount < Result->MemoryRegionsScanned &&
           regionCount < EDE_MAX_MEMORY_REGIONS) {

        SIZE_T ret = VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi));
        if (ret == 0) break;

        regionCount++;

        /* 仅扫描已提交的可执行区域（MEM_COMMIT + PAGE_EXECUTE_*） */
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE |
                            PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE |
                            PAGE_EXECUTE_WRITECOPY))) {

            SIZE_T regionSize = mbi.RegionSize;
            SIZE_T scanSize;
            UCHAR* codeBuf;

            /* 限制单区域扫描大小 */
            if (regionSize > EDE_MAX_SCAN_REGION_SIZE)
                regionSize = EDE_MAX_SCAN_REGION_SIZE;
            scanSize = regionSize;

            codeBuf = (UCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, scanSize);
            if (codeBuf) {
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress,
                                      codeBuf, scanSize, &bytesRead) &&
                    bytesRead > 0) {
                    ULONG foundCount = 0, uniqueMask = 0;

                    Result->BytesScanned += bytesRead;

                    if (EdepScanBytePatterns(codeBuf, bytesRead,
                                             &foundCount, &uniqueMask) &&
                        foundCount > 0) {
                        totalBpCount += foundCount;

                        /* 仅当 INT3 计数 >= 阈值 时告警（避免误报） */
                        if (foundCount >= EDE_BREAKPOINT_THRESHOLD) {
                            WCHAR details[192];
                            _snwprintf_s(details, 192, _TRUNCATE,
                                L"Region 0x%p size 0x%zX: %lu anti-debug bytes",
                                mbi.BaseAddress, mbi.RegionSize, foundCount);
                            EdepAddDetection(Result,
                                EdeTechniqueMemory_SoftwareBreakpoints,
                                EdeCategoryMemoryArtifacts, EdeSeverityMedium,
                                0.70,
                                (ULONG_PTR)mbi.BaseAddress, 0,
                                L"Multiple anti-debug byte patterns in executable memory",
                                details);
                        }
                    }
                }
                HeapFree(GetProcessHeap(), 0, codeBuf);
            }
        }

        addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (addr <= (ULONG_PTR)mbi.BaseAddress) break; /* 溢出保护 */
    }

    Result->MemoryRegionsScanned = regionCount;
}

/**************************************************/
/*          检测 8：进程关系分析                    */
/*  AnalyzeProcessRelationships (L2348-2467)*/
/*  父进程链：非 explorer/cmd/services 启动 = 可疑  */
/*  已知调试器父进程 = 高置信                      */
/**************************************************/

static
VOID
EdepAnalyzeProcessRelationships(
    _In_ DWORD  TargetPid,
    _In_ PEDE_RESULT Result
    )
{
    HANDLE hSnap;
    PROCESSENTRY32W pe;
    DWORD parentPid = 0;
    WCHAR parentName[MAX_PATH] = { 0 };
    DWORD grandParentPid = 0;

    Result->TechniquesChecked++;

    /* 获取父进程 PID */
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == (DWORD)TargetPid) {
                parentPid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    /* 查找父进程名与祖父进程 */
    if (parentPid != 0) {
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID == parentPid) {
                    wcscpy_s(parentName, MAX_PATH, pe.szExeFile);
                    grandParentPid = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
    }
    CloseHandle(hSnap);

    if (parentPid == 0) return;

    /* 已知调试器父进程 */
    if (EdepIsDebuggerProcess(parentName)) {
        WCHAR details[256];
        _snwprintf_s(details, 256, _TRUNCATE,
                     L"Parent PID=%lu '%s' is a known debugger",
                     parentPid, parentName);
        EdepAddDetection(Result, EdeTechniqueProcess_ParentIsDebugger,
                         EdeCategoryProcessRelationship, EdeSeverityCritical, 0.95,
                         0, 0,
                         L"Parent process is a known debugger",
                         details);
    }

    /* 非 explorer/services/cmd/powershell 启动 */
    if (parentPid > 4 && parentName[0] != L'\0') {
        WCHAR lower[MAX_PATH];
        SIZE_t j;
        BOOLEAN isNormalParent = FALSE;
        static const WCHAR* const normalParents[] = {
            L"explorer.exe", L"services.exe", L"svchost.exe",
            L"cmd.exe", L"powershell.exe", L"conhost.exe",
            L"msiexec.exe", L"setup.exe", L"install.exe",
            L"applicationhost.exe", L"wsmprovhost.exe",
            NULL
        };

        wcscpy_s(lower, MAX_PATH, parentName);
        _wcslwr_s(lower, MAX_PATH);

        for (j = 0; normalParents[j]; j++) {
            if (wcscmp(lower, normalParents[j]) == 0) {
                isNormalParent = TRUE;
                break;
            }
        }

        if (!isNormalParent) {
            WCHAR details[256];
            _snwprintf_s(details, 256, _TRUNCATE,
                         L"Parent PID=%lu '%s' (grandparent=%lu) is unusual",
                         parentPid, parentName, grandParentPid);
            EdepAddDetection(Result, EdeTechniqueProcess_ParentNotExplorer,
                             EdeCategoryProcessRelationship, EdeSeverityMedium, 0.50,
                             0, 0,
                             L"Parent process is not a standard launcher",
                             details);
        }
    }

    /* PPID 欺骗检测：通过 NtQueryInformationProcess 查真实创建者 PID */
    if (g_NtQueryInfoProcess) {
        HANDLE hProcess = NULL;
        PROCESS_BASIC_INFORMATION pbi;
        ULONG retLen = 0;

        if (CoOpenProcessForQueryRead(TargetPid, &hProcess)) {
            if (NT_SUCCESS(g_NtQueryInfoProcess(hProcess, ProcessBasicInformation,
                                                &pbi, sizeof(pbi), &retLen))) {
                /* PBI.InheritedFromUniqueProcessId 是真实的父 PID */
                DWORD realParentPid = (DWORD)pbi.InheritedFromUniqueProcessId;
                if (realParentPid != parentPid && realParentPid != 0) {
                    WCHAR details[128];
                    _snwprintf_s(details, 128, _TRUNCATE,
                                 L"Toolhelp parent=%lu Real parent=%lu (PPID spoof)",
                                 parentPid, realParentPid);
                    EdepAddDetection(Result,
                        EdeTechniqueKernelCtx_ParentPidSpoofed,
                        EdeCategoryCombined, EdeSeverityCritical, 0.90,
                        0, 0,
                        L"Parent PID spoofed (kernel vs user mismatch)",
                        details);
                }
            }
            CloseHandle(hProcess);
        }
    }
}

/**************************************************/
/*          检测 9：时序分析                        */
/*  IAT 时序 API 导入 + 入口点 RDTSC 字节扫描      */
/*  + KUSER_SHARED_DATA 读取                       */
/*  AnalyzeTimingPatterns (L3156-3900)     */
/**************************************************/

/* 辅助：检查目标进程某模块的 IAT 是否导入了时序 API */
static
VOID
EdepCheckIatTimingImports(
    _In_ HANDLE hProcess,
    _In_ ULONG_PTR ModBase,
    _In_ ULONG ModSize,
    _In_ PEDE_RESULT Result
    )
{
    UCHAR ntHeaders[4096];
    PIMAGE_DOS_HEADER dosHdr;
    PIMAGE_NT_HEADERS ntHdr;
    PIMAGE_DATA_DIRECTORY importDir;
    UCHAR* importBuf;
    ULONG importDirRva, importDirSize;
    IMAGE_IMPORT_DESCRIPTOR importDesc;
    SIZE_T bytesRead;

    if (!EdepReadRemote(hProcess, (PVOID)ModBase, ntHeaders, sizeof(ntHeaders)))
        return;

    dosHdr = (PIMAGE_DOS_HEADER)ntHeaders;
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return;

    ntHdr = (PIMAGE_NT_HEADERS)(ntHeaders + dosHdr->e_lfanew);
    if (ntHdr->Signature != IMAGE_NT_SIGNATURE) return;

    importDir = &ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDirRva  = importDir->VirtualAddress;
    importDirSize = importDir->Size;

    if (importDirRva == 0 || importDirSize == 0) return;
    if (importDirSize > 65536) return; /* 安全上限 */

    importBuf = (UCHAR*)HeapAlloc(GetProcessHeap(), 0, importDirSize);
    if (!importBuf) return;

    if (!EdepReadRemote(hProcess, (PVOID)(ModBase + importDirRva),
                        importBuf, importDirSize)) {
        HeapFree(GetProcessHeap(), 0, importBuf);
        return;
    }

    /* 遍历导入描述符 */
    {
        ULONG descIdx;
        for (descIdx = 0; descIdx < importDirSize / sizeof(IMAGE_IMPORT_DESCRIPTOR); descIdx++) {
            ULONG thunkRva;
            PVOID thunkPtr;

            memcpy(&importDesc, importBuf + descIdx * sizeof(IMAGE_IMPORT_DESCRIPTOR),
                   sizeof(IMAGE_IMPORT_DESCRIPTOR));
            if (importDesc.OriginalFirstThunk == 0 && importDesc.FirstThunk == 0)
                break;

            thunkRva = importDesc.OriginalFirstThunk;
            if (thunkRva == 0) thunkRva = importDesc.FirstThunk;
            if (thunkRva == 0) continue;

            /* 逐个检查 INT 条目（RVA 数组） */
            {
                ULONG thunkIdx;
                for (thunkIdx = 0; thunkIdx < 1024; thunkIdx++) {
                    UCHAR thunkBuf[16];
                    ULONG_PTR nameOrOrdinal;

                    if (!EdepReadRemote(hProcess,
                        (PVOID)(ModBase + thunkRva + thunkIdx * 8),
                        thunkBuf, sizeof(thunkBuf)))
                        break;

                    nameOrOrdinal = *(ULONG_PTR*)thunkBuf;
                    if (nameOrOrdinal == 0) break;

                    /* IMAGE_ORDINAL_FLAG64 = 0x8000000000000000 */
                    if (!(nameOrOrdinal & 0x8000000000000000ULL)) {
                        /* 按名称导入：读取 IMAGE_IMPORT_BY_NAME */
                        UCHAR nameBuf[256];
                        PIMAGE_IMPORT_BY_NAME importByName;
                        ULONG nameRva = (ULONG)(nameOrOrdinal & 0xFFFFFFFF);

                        if (EdepReadRemote(hProcess, (PVOID)(ModBase + nameRva),
                                           nameBuf, sizeof(nameBuf))) {
                            importByName = (PIMAGE_IMPORT_BY_NAME)nameBuf;
                            /* 检查函数名是否是已知时序 API */
                            ULONG apiIdx;
                            for (apiIdx = 0; s_TimingApiNames[apiIdx]; apiIdx++) {
                                if (_stricmp((const char*)importByName->Name,
                                             s_TimingApiNames[apiIdx]) == 0) {
                                    WCHAR details[128];
                                    _snwprintf_s(details, 128, _TRUNCATE,
                                        L"IAT imports %hs at RVA 0x%X",
                                        s_TimingApiNames[apiIdx], nameRva);
                                    EdepAddDetection(Result,
                                        EdeTechniqueTiming_QueryPerformanceCounter,
                                        EdeCategoryTimingBased, EdeSeverityMedium, 0.60,
                                        ModBase + nameRva, 0,
                                        L"Timing API found in IAT",
                                        details);
                                    goto done_iat;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

done_iat:
    HeapFree(GetProcessHeap(), 0, importBuf);
}

static
VOID
EdepCheckTimingTechniques(
    _In_ HANDLE hProcess,
    _In_ DWORD  TargetPid,
    _In_ PEDE_RESULT Result
    )
{
    HMODULE hMods[256];
    DWORD   cbNeeded;
    ULONG   i;

    Result->TechniquesChecked++;

    /* Part A: 扫描各模块 IAT 中的时序 API */
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (i = 0; i < cbNeeded / sizeof(HMODULE) && i < 256; i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                EdepCheckIatTimingImports(hProcess, (ULONG_PTR)modInfo.lpBaseOfDll,
                                          modInfo.SizeOfImage, Result);
            }
        }
    }

    /* Part B: 主模块入口点字节模式扫描（RDTSC/CPUID 指令） */
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded) &&
        cbNeeded >= sizeof(HMODULE)) {

        MODULEINFO modInfo;
        if (GetModuleInformation(hProcess, hMods[0], &modInfo, sizeof(modInfo))) {
            PIMAGE_DOS_HEADER dosHdr;
            PIMAGE_NT_HEADERS ntHdr;
            UCHAR headerBuf[4096];
            ULONG_PTR modBase = (ULONG_PTR)modInfo.lpBaseOfDll;
            ULONG epRva = 0;
            UCHAR epCode[256];

            if (EdepReadRemote(hProcess, (PVOID)modBase, headerBuf, sizeof(headerBuf))) {
                dosHdr = (PIMAGE_DOS_HEADER)headerBuf;
                if (dosHdr->e_magic == IMAGE_DOS_SIGNATURE) {
                    ntHdr = (PIMAGE_NT_HEADERS)(headerBuf + dosHdr->e_lfanew);
                    if (ntHdr->Signature == IMAGE_NT_SIGNATURE &&
                        ntHdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                        epRva = ntHdr->OptionalHeader.AddressOfEntryPoint;
                    }
                }
            }

            if (epRva > 0 && epRva < modInfo.SizeOfImage &&
                EdepReadRemote(hProcess, (PVOID)(modBase + epRva), epCode, sizeof(epCode))) {

                ULONG foundCount = 0, uniqueMask = 0;
                if (EdepScanBytePatterns(epCode, sizeof(epCode),
                                         &foundCount, &uniqueMask) &&
                    foundCount > 0) {
                    WCHAR details[128];
                    _snwprintf_s(details, 128, _TRUNCATE,
                        L"Entry point 0x%p: %lu anti-debug instructions found",
                        (PVOID)(modBase + epRva), foundCount);
                    EdepAddDetection(Result,
                        EdeTechniqueTiming_RDTSC,
                        EdeCategoryTimingBased, EdeSeverityHigh, 0.85,
                        modBase + epRva, 0,
                        L"Anti-debug timing instructions at entry point",
                        details);
                }
            }
        }
    }

    /* Part C: KUSER_SHARED_DATA 时序字段检测 */
    {
        UCHAR kusdBuf[512];
        __try {
            if (EdepReadRemote(hProcess, EDE_KUSER_SHARED_DATA,
                               kusdBuf, sizeof(kusdBuf))) {
                /* KUSER_SHARED_DATA.TimeLowAtLastUpdate (offset 0x0318) */
                /* KUSER_SHARED_DATA.SystemTime (offset 0x0014, 8 字节) */
                /* 如果进程直接读 KUSER_SHARED_DATA 做时序检测，会反映在代码中 */
                /* 这里我们仅验证 KUSER_SHARED_DATA 可读（通常总可读），
                 * 实际检测由入口点字节扫描覆盖。 */
                Result->BytesScanned += sizeof(kusdBuf);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            /* 不可达（KUSER_SHARED_DATA 通常映射在每个用户进程） */
        }
    }
}

/**************************************************/
/*          检测 10：异常处理                       */
/*  ProcessExceptionPort + 入口点 INT3/INT2D 扫描  */
/*  AnalyzeExceptionHandling (L3961-4183)  */
/**************************************************/

static
VOID
EdepCheckExceptionTechniques(
    _In_ HANDLE hProcess,
    _In_ DWORD  TargetPid,
    _In_ PEDE_RESULT Result
    )
{
    NTSTATUS status;
    ULONG retLen = 0;
    ULONG_PTR exceptionPort = 0;

    Result->TechniquesChecked++;

    /* ProcessExceptionPort (class 8) — 非零 = 有异常端口 */
    if (g_NtQueryInfoProcess) {
        status = g_NtQueryInfoProcess(hProcess, EDE_PROCESS_EXCEPTION_PORT,
                                      &exceptionPort, sizeof(exceptionPort), &retLen);
        if (NT_SUCCESS(status) && exceptionPort != 0) {
            WCHAR details[128];
            _snwprintf_s(details, 128, _TRUNCATE,
                         L"ExceptionPort handle=0x%p", (PVOID)exceptionPort);
            EdepAddDetection(Result, EdeTechniqueException_BreakpointHandler,
                             EdeCategoryExceptionBased, EdeSeverityHigh, 0.80,
                             exceptionPort, 0,
                             L"ProcessExceptionPort is set (possible debug/anti-attach)",
                             details);
        }
    }

    /* 入口点 INT3/INT2D 字节扫描 */
    {
        HMODULE hMod = NULL;
        DWORD cbNeeded = 0;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded) &&
            cbNeeded >= sizeof(HMODULE)) {

            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMod, &modInfo, sizeof(modInfo))) {
                PIMAGE_DOS_HEADER dosHdr;
                PIMAGE_NT_HEADERS ntHdr;
                UCHAR headerBuf[4096];
                ULONG_PTR modBase = (ULONG_PTR)modInfo.lpBaseOfDll;
                ULONG epRva = 0;
                UCHAR epCode[64];

                if (EdepReadRemote(hProcess, (PVOID)modBase, headerBuf, sizeof(headerBuf))) {
                    dosHdr = (PIMAGE_DOS_HEADER)headerBuf;
                    if (dosHdr->e_magic == IMAGE_DOS_SIGNATURE) {
                        ntHdr = (PIMAGE_NT_HEADERS)(headerBuf + dosHdr->e_lfanew);
                        if (ntHdr->Signature == IMAGE_NT_SIGNATURE &&
                            ntHdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                            epRva = ntHdr->OptionalHeader.AddressOfEntryPoint;
                        }
                    }
                }

                if (epRva > 0 && epRva < modInfo.SizeOfImage &&
                    EdepReadRemote(hProcess, (PVOID)(modBase + epRva),
                                   epCode, sizeof(epCode))) {

                    /* INT3 at entry point */
                    if (epCode[0] == 0xCC) {
                        EdepAddDetection(Result,
                            EdeTechniqueException_INT3,
                            EdeCategoryExceptionBased, EdeSeverityHigh, 0.90,
                            modBase + epRva, 0,
                            L"INT3 breakpoint at entry point",
                            L"Entry point starts with 0xCC");
                    }

                    /* INT 2D at entry point */
                    if (epCode[0] == 0xCD && epCode[1] == 0x2D) {
                        EdepAddDetection(Result,
                            EdeTechniqueException_INT2D,
                            EdeCategoryExceptionBased, EdeSeverityHigh, 0.90,
                            modBase + epRva, 0,
                            L"INT 2D at entry point",
                            L"Entry point starts with CD 2D");
                    }

                    /* ICEBP (F1) at entry point */
                    if (epCode[0] == 0xF1) {
                        EdepAddDetection(Result,
                            EdeTechniqueException_ICEBP,
                            EdeCategoryExceptionBased, EdeSeverityHigh, 0.85,
                            modBase + epRva, 0,
                            L"ICEBP at entry point",
                            L"Entry point starts with F1");
                    }
                }
            }
        }
    }
}

/**************************************************/
/*          检测 11：API 钩子检测                   */
/*  ntdll 远程 vs 本地比对 + syscall stub 校验      */
/*  CheckAPIHookDetection (L2565-2818)     */
/*  + CheckAPIHookDetectionInternal (L4394-4624)   */
/**************************************************/

static
VOID
EdepCheckAPIHookDetection(
    _In_ HANDLE hProcess,
    _In_ DWORD  TargetPid,
    _In_ PEDE_RESULT Result
    )
{
    HMODULE hMods[256];
    DWORD   cbNeeded;
    ULONG   i;
    HMODULE hLocalNtdll = NULL;
    PVOID   remoteNtdllBase = NULL;
    ULONG   remoteNtdllSize = 0;

    Result->TechniquesChecked++;

    /* 定位远程 ntdll */
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        return;

    for (i = 0; i < cbNeeded / sizeof(HMODULE) && i < 256; i++) {
        WCHAR modName[MAX_PATH];
        if (GetModuleFileNameExW(hProcess, hMods[i], modName, MAX_PATH)) {
            if (_wcsicmp(modName, L"ntdll.dll") == 0) {
                MODULEINFO modInfo;
                if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                    remoteNtdllBase = modInfo.lpBaseOfDll;
                    remoteNtdllSize = modInfo.SizeOfImage;
                }
                break;
            }
        }
    }

    if (!remoteNtdllBase || remoteNtdllSize == 0) return;

    /* 获取本地 ntdll */
    hLocalNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hLocalNtdll) return;

    /* Part A: 关键函数 syscall stub 验证 */
    {
        static const char* const criticalFuncs[] = {
            "NtQueryInformationProcess",
            "NtSetInformationThread",
            "NtClose",
            "NtReadVirtualMemory",
            "NtWriteVirtualMemory",
            "NtProtectVirtualMemory",
            "NtAllocateVirtualMemory",
            "NtFreeVirtualMemory",
            "LdrLoadDll",
            "NtCreateThreadEx",
            "NtResumeThread",
            "NtSuspendThread",
            "NtQuerySystemInformation",
            "NtQueryObject",
            "NtCreateFile",
            "NtOpenProcess",
            NULL
        };
        ULONG fi;

        for (fi = 0; criticalFuncs[fi]; fi++) {
            PVOID localFunc;
            PVOID remoteFunc;
            UCHAR localStub[32];
            UCHAR remoteStub[32];

            localFunc = (PVOID)GetProcAddress(hLocalNtdll, criticalFuncs[fi]);
            if (!localFunc) continue;

            /* 读取远程进程中的函数入口 */
            remoteFunc = (PVOID)((ULONG_PTR)remoteNtdllBase +
                ((ULONG_PTR)localFunc - (ULONG_PTR)hLocalNtdll));

            if (!EdepReadRemote(hProcess, remoteFunc, remoteStub, sizeof(remoteStub)))
                continue;

            /* 快速首字节钩子检测 */
            if (remoteStub[0] == 0xE9 || remoteStub[0] == 0xFF ||
                remoteStub[0] == 0xCC) {
                WCHAR details[256];
                _snwprintf_s(details, 256, _TRUNCATE,
                    L"%hs @ 0x%p: first byte=0x%02X (hooked)",
                    criticalFuncs[fi], remoteFunc, remoteStub[0]);
                EdepAddDetection(Result,
                    EdeTechniqueMemory_APIHookDetection,
                    EdeCategoryCodeIntegrity, EdeSeverityHigh, 0.90,
                    (ULONG_PTR)remoteFunc, 0,
                    L"Critical API has inline hook",
                    details);
                continue;
            }

            /* 标准 syscall stub 校验 */
            {
                WCHAR stubDetails[EDE_MAX_DETAILS];
                if (!EdepValidateSyscallStub(remoteStub, sizeof(remoteStub), stubDetails)) {
                    WCHAR details[256];
                    _snwprintf_s(details, 256, _TRUNCATE,
                        L"%hs @ 0x%p: %ls",
                        criticalFuncs[fi], remoteFunc, stubDetails);
                    EdepAddDetection(Result,
                        EdeTechniqueMemory_APIHookDetection,
                        EdeCategoryCodeIntegrity, EdeSeverityHigh, 0.85,
                        (ULONG_PTR)remoteFunc, 0,
                        L"Syscall stub validation failed",
                        details);
                }
            }
        }
    }

    /* Part B: ntdll 代码段整体比对 */
    {
        PIMAGE_DOS_HEADER localDos, remoteDos;
        PIMAGE_NT_HEADERS localNt, remoteNt;
        UCHAR localHdr[4096], remoteHdr[4096];
        ULONG_PTR localBase = (ULONG_PTR)hLocalNtdll;

        if (EdepReadRemote(hProcess, remoteNtdllBase, remoteHdr, sizeof(remoteHdr)) &&
            EdepReadRemote(hProcess, (PVOID)localBase, localHdr, sizeof(localHdr))) {

            localDos  = (PIMAGE_DOS_HEADER)localHdr;
            remoteDos = (PIMAGE_DOS_HEADER)remoteHdr;

            if (localDos->e_magic == IMAGE_DOS_SIGNATURE &&
                remoteDos->e_magic == IMAGE_DOS_SIGNATURE) {

                localNt  = (PIMAGE_NT_HEADERS)(localHdr + localDos->e_lfanew);
                remoteNt = (PIMAGE_NT_HEADERS)(remoteHdr + remoteDos->e_lfanew);

                if (localNt->Signature == IMAGE_NT_SIGNATURE &&
                    remoteNt->Signature == IMAGE_NT_SIGNATURE) {

                    /* 比对代码段（.text 节的前 4KB） */
                    PIMAGE_SECTION_HEADER localSec, remoteSec;
                    ULONG secIdx;

                    localSec = IMAGE_FIRST_SECTION(localNt);
                    remoteSec = IMAGE_FIRST_SECTION(remoteNt);

                    for (secIdx = 0; secIdx < localNt->FileHeader.NumberOfSections &&
                         secIdx < remoteNt->FileHeader.NumberOfSections; secIdx++) {
                        if (memcmp(localSec[secIdx].Name, ".text", 5) == 0) {
                            UCHAR localCode[4096], remoteCode[4096];
                            PVOID localCodeAddr = (PVOID)(localBase +
                                localSec[secIdx].VirtualAddress);
                            PVOID remoteCodeAddr = (PVOID)((ULONG_PTR)remoteNtdllBase +
                                remoteSec[secIdx].VirtualAddress);
                            SIZE_T cmpSize = localSec[secIdx].SizeOfRawData;
                            SIZE_T readSize = (cmpSize < 4096) ? cmpSize : 4096;

                            if (readSize > 0 &&
                                EdepReadRemote(hProcess, remoteCodeAddr,
                                               remoteCode, readSize) &&
                                ReadProcessMemory(GetCurrentProcess(), localCodeAddr,
                                                  localCode, readSize, NULL)) {

                                SIZE_T diffCount = 0;
                                SIZE_t j;
                                for (j = 0; j < readSize; j++) {
                                    if (localCode[j] != remoteCode[j]) diffCount++;
                                }

                                if (diffCount > 0) {
                                    WCHAR details[192];
                                    _snwprintf_s(details, 192, _TRUNCATE,
                                        L"ntdll .text: %zu bytes differ (possible hook)",
                                        diffCount);
                                    EdepAddDetection(Result,
                                        EdeTechniqueMemory_NtDllIntegrity,
                                        EdeCategoryCodeIntegrity,
                                        EdeSeverityHigh, 0.80,
                                        (ULONG_PTR)remoteCodeAddr, 0,
                                        L"ntdll code section integrity mismatch",
                                        details);
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
}

/**************************************************/
/*          检测 12：代码完整性                     */
/*  ProcessInstrumentationCallback + ntdll 完整性  */
/*  AnalyzeCodeIntegrity (L4394-4624)      */
/**************************************************/

static
VOID
EdepAnalyzeCodeIntegrity(
    _In_ HANDLE hProcess,
    _In_ PEDE_RESULT Result
    )
{
    NTSTATUS status;
    ULONG retLen = 0;
    UCHAR icbBuf[32];

    Result->TechniquesChecked++;

    /* ProcessInstrumentationCallback (class 40) */
    if (g_NtQueryInfoProcess) {
        status = g_NtQueryInfoProcess(hProcess, EDE_PROCESS_INSTRUMENTATION_CB,
                                      icbBuf, sizeof(icbBuf), &retLen);
        if (NT_SUCCESS(status)) {
            /* PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION:
             *   Version (ULONG, offset 0)
             *   Reserved (ULONG, offset 4)
             *   CallbackAddress (PVOID, offset 8)
             */
            PVOID callbackAddr = NULL;
            if (retLen >= sizeof(UCHAR) * 16) {
                callbackAddr = *(PVOID*)(icbBuf + 8);
            }

            if (callbackAddr != NULL) {
                WCHAR details[128];
                _snwprintf_s(details, 128, _TRUNCATE,
                             L"InstrumentationCallback=0x%p", callbackAddr);
                EdepAddDetection(Result,
                    EdeTechniqueCode_ImportTableHooks,
                    EdeCategoryCodeIntegrity, EdeSeverityHigh, 0.85,
                    (ULONG_PTR)callbackAddr, 0,
                    L"ProcessInstrumentationCallback is active (code instrumentation)",
                    details);
            }
        }
    }

    /* ntdll 磁盘 vs 内存 PE 头完整性 */
    {
        HMODULE hMods[256];
        DWORD cbNeeded;
        ULONG i;

        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (i = 0; i < cbNeeded / sizeof(HMODULE) && i < 256; i++) {
                WCHAR modPath[MAX_PATH];
                WCHAR modName[MAX_PATH];

                if (GetModuleFileNameExW(hProcess, hMods[i], modPath, MAX_PATH)) {
                    /* 提取模块名 */
                    PCWSTR slash = wcsrchr(modPath, L'\\');
                    if (slash) wcscpy_s(modName, MAX_PATH, slash + 1);
                    else wcscpy_s(modName, MAX_PATH, modPath);

                    if (_wcsicmp(modName, L"ntdll.dll") == 0 ||
                        _wcsicmp(modName, L"kernel32.dll") == 0) {

                        MODULEINFO modInfo;
                        HANDLE hFile;
                        ULONG_PTR diskHdrBuf[512 / sizeof(ULONG_PTR)];
                        ULONG_PTR memHdrBuf[512 / sizeof(ULONG_PTR)];

                        if (!GetModuleInformation(hProcess, hMods[i],
                                                  &modInfo, sizeof(modInfo)))
                            continue;

                        /* 读取远程内存 PE 头 */
                        if (!EdepReadRemote(hProcess, modInfo.lpBaseOfDll,
                                            memHdrBuf, sizeof(memHdrBuf)))
                            continue;

                        /* 读取磁盘 PE 头 */
                        hFile = CreateFileW(modPath, GENERIC_READ,
                                            FILE_SHARE_READ, NULL,
                                            OPEN_EXISTING, 0, NULL);
                        if (hFile == INVALID_HANDLE_VALUE) continue;

                        {
                            DWORD bytesRead = 0;
                            ReadFile(hFile, diskHdrBuf, sizeof(diskHdrBuf),
                                     &bytesRead, NULL);
                            CloseHandle(hFile);

                            if (bytesRead >= sizeof(diskHdrBuf)) {
                                /* 比对前 256 字节（PE 头核心区域） */
                                SIZE_T diffCount = 0;
                                SIZE_t j;
                                PUCHAR d = (PUCHAR)diskHdrBuf;
                                PUCHAR m = (PUCHAR)memHdrBuf;

                                for (j = 0; j < 256; j++) {
                                    if (d[j] != m[j]) diffCount++;
                                }

                                if (diffCount > 5) {
                                    WCHAR details[128];
                                    _snwprintf_s(details, 128, _TRUNCATE,
                                        L"%ls PE header: %zu bytes differ (256)",
                                        modName, diffCount);
                                    EdepAddDetection(Result,
                                        EdeTechniqueMemory_NtDllIntegrity,
                                        EdeCategoryCodeIntegrity, EdeSeverityHigh,
                                        0.75,
                                        (ULONG_PTR)modInfo.lpBaseOfDll, 0,
                                        L"Module PE header mismatch (disk vs memory)",
                                        details);
                                    break; /* 一个模块一个告警 */
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/**************************************************/
/*          检测 13：内核调试信息查询               */
/*  QueryKernelDebugInfo (L4624-4817)     */
/*  扫描目标 ntdll 代码中的 0x23 常量              */
/*  （NtQuerySystemInformation(SystemKernelDebuggerInformation)） */
/**************************************************/

static
VOID
EdepQueryKernelDebugInfo(
    _In_ HANDLE hProcess,
    _In_ DWORD  TargetPid,
    _In_ PEDE_RESULT Result
    )
{
    HMODULE hMods[256];
    DWORD   cbNeeded;
    ULONG   i;
    PVOID   remoteNtdllBase = NULL;
    ULONG   remoteNtdllSize = 0;

    Result->TechniquesChecked++;

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        return;

    for (i = 0; i < cbNeeded / sizeof(HMODULE) && i < 256; i++) {
        WCHAR modName[MAX_PATH];
        if (GetModuleFileNameExW(hProcess, hMods[i], modName, MAX_PATH)) {
            if (_wcsicmp(modName, L"ntdll.dll") == 0) {
                MODULEINFO modInfo;
                if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                    remoteNtdllBase = modInfo.lpBaseOfDll;
                    remoteNtdllSize = modInfo.SizeOfImage;
                }
                break;
            }
        }
    }

    if (!remoteNtdllBase || remoteNtdllSize == 0) return;

    /* 扫描 ntdll 代码段中 NtQuerySystemInformation 的 syscall 号 */
    {
        PIMAGE_DOS_HEADER dosHdr;
        PIMAGE_NT_HEADERS ntHdr;
        UCHAR headerBuf[4096];
        PIMAGE_SECTION_HEADER secHdr;
        ULONG secIdx;

        if (!EdepReadRemote(hProcess, remoteNtdllBase, headerBuf, sizeof(headerBuf)))
            return;

        dosHdr = (PIMAGE_DOS_HEADER)headerBuf;
        if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return;
        ntHdr = (PIMAGE_NT_HEADERS)(headerBuf + dosHdr->e_lfanew);
        if (ntHdr->Signature != IMAGE_NT_SIGNATURE) return;
        if (ntHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return;

        secHdr = IMAGE_FIRST_SECTION(ntHdr);
        for (secIdx = 0; secIdx < ntHdr->FileHeader.NumberOfSections; secIdx++) {
            if (memcmp(secHdr[secIdx].Name, ".text", 5) == 0) {
                PVOID codeAddr = (PVOID)((ULONG_PTR)remoteNtdllBase +
                                         secHdr[secIdx].VirtualAddress);
                ULONG codeSize = secHdr[secIdx].SizeOfRawData;
                UCHAR* codeBuf;

                if (codeSize > 256 * 1024) codeSize = 256 * 1024;

                codeBuf = (UCHAR*)HeapAlloc(GetProcessHeap(), 0, codeSize);
                if (!codeBuf) return;

                if (EdepReadRemote(hProcess, codeAddr, codeBuf, codeSize)) {
                    SIZE_t j;
                    ULONG kernelDebugCheckCount = 0;

                    /* 扫描 0x23 (35) — NtQuerySystemInformation 的 syscall 号 */
                    for (j = 0; j < codeSize - 7; j++) {
                        /* 标准模式：4C 8B D1 B8 23 00 00 00 (mov r10,rcx; mov eax,0x23) */
                        if (codeBuf[j] == 0x4C && codeBuf[j+1] == 0x8B &&
                            codeBuf[j+2] == 0xD1 && codeBuf[j+3] == 0xB8 &&
                            codeBuf[j+4] == 0x23 && codeBuf[j+5] == 0x00) {
                            kernelDebugCheckCount++;
                        }
                    }

                    if (kernelDebugCheckCount > 0) {
                        WCHAR details[128];
                        _snwprintf_s(details, 128, _TRUNCATE,
                            L"Found %lu NtQuerySystemInformation(0x23) stubs",
                            kernelDebugCheckCount);
                        EdepAddDetection(Result,
                            EdeTechniqueKernel_SystemKernelDebugger,
                            EdeCategoryKernelQueries, EdeSeverityMedium, 0.65,
                            0, 0,
                            L"Kernel debugger query detected in ntdll",
                            details);
                    }
                }

                HeapFree(GetProcessHeap(), 0, codeBuf);
                break;
            }
        }
    }
}

/**************************************************/
/*          检测 14：内核上下文/命令行分析           */
/*  AnalyzeKernelContext (L4817-4915)      */
/*  命令行关键词 + 可疑启动目录 + 异常命令行长度    */
/**************************************************/

static
VOID
EdepAnalyzeKernelContext(
    _In_ const EDE_KERNEL_CONTEXT* KernelContext,
    _Inout_ PEDE_RESULT Result
    )
{
    SIZE_t i;
    WCHAR lowerCmd[1024];

    Result->TechniquesChecked++;

    if (!KernelContext) return;

    /* 命令行反调试关键词 */
    if (KernelContext->CommandLine[0] != L'\0') {
        wcscpy_s(lowerCmd, 1024, KernelContext->CommandLine);
        _wcslwr_s(lowerCmd, 1024);

        for (i = 0; s_DebuggerCmdKeywords[i]; i++) {
            if (wcsstr(lowerCmd, s_DebuggerCmdKeywords[i])) {
                WCHAR details[256];
                _snwprintf_s(details, 256, _TRUNCATE,
                    L"Keyword '%s' in cmdline (first 128 chars): %.128s",
                    s_DebuggerCmdKeywords[i], KernelContext->CommandLine);
                EdepAddDetection(Result,
                    EdeTechniqueKernelCtx_CmdLineDebuggerKeyword,
                    EdeCategoryKernelContext, EdeSeverityMedium, 0.70,
                    0, 0,
                    L"Command line contains debugger/anti-debug keyword",
                    details);
                break;
            }
        }

        /* 异常命令行长度 (>8KB = 可疑混淆载荷) */
        {
            SIZE_T cmdLen = wcslen(KernelContext->CommandLine);
            if (cmdLen > 8192) {
                WCHAR details[128];
                _snwprintf_s(details, 128, _TRUNCATE,
                             L"CmdLine length=%zu chars (possible obfuscated payload)",
                             cmdLen);
                EdepAddDetection(Result,
                    EdeTechniqueKernelCtx_AbnormalCmdLineLength,
                    EdeCategoryKernelContext, EdeSeverityMedium, 0.60,
                    0, 0,
                    L"Abnormally long command line",
                    details);
            }
        }
    }

    /* PPID 欺骗（内核创建者 PID vs 用户态父 PID） */
    if (KernelContext->CreatingProcessId != 0 &&
        KernelContext->ParentProcessId != 0 &&
        KernelContext->CreatingProcessId != KernelContext->ParentProcessId) {
        WCHAR details[128];
        _snwprintf_s(details, 128, _TRUNCATE,
            L"parentPid=%lu creatingPid=%lu creatingTid=%lu",
            KernelContext->ParentProcessId,
            KernelContext->CreatingProcessId,
            KernelContext->CreatingThreadId);
        EdepAddDetection(Result,
            EdeTechniqueKernelCtx_ParentPidSpoofed,
            EdeCategoryCombined, EdeSeverityCritical, 0.90,
            0, 0,
            L"Parent PID spoofing: kernel creatingPid differs from parentPid",
            details);
    }

    /* 可疑启动目录 */
    if (KernelContext->ImagePath[0] != L'\0' && Result->TotalDetections > 0) {
        WCHAR lowerPath[260];
        wcscpy_s(lowerPath, 260, KernelContext->ImagePath);
        _wcslwr_s(lowerPath, 260);

        for (i = 0; s_SuspiciousDirs[i]; i++) {
            if (wcsstr(lowerPath, s_SuspiciousDirs[i])) {
                EdepAddDetection(Result,
                    EdeTechniqueKernelCtx_SuspiciousLaunchDir,
                    EdeCategoryKernelContext, EdeSeverityHigh, 0.80,
                    0, 0,
                    L"Evasive process launched from suspicious directory",
                    KernelContext->ImagePath);
                break;
            }
        }
    }
}

/**************************************************/
/*          评分计算                                */
/*  CalculateEvasionScore (L4921-4986)     */
/**************************************************/

static
VOID
EdepCalculateScore(
    _Inout_ PEDE_RESULT Result
    )
{
    DOUBLE score = 0.0;
    ULONG i;
    DOUBLE categoryWeights[] = {
        EDE_WEIGHT_PEB,                    /* 0: PEBBased */
        EDE_WEIGHT_HARDWARE_BP,            /* 1: HardwareDebugRegisters */
        EDE_WEIGHT_API,                    /* 2: APIBased */
        EDE_WEIGHT_TIMING,                 /* 3: TimingBased */
        EDE_WEIGHT_EXCEPTION,              /* 4: ExceptionBased */
        EDE_WEIGHT_OBJECT_HANDLE,          /* 5: ObjectHandleBased */
        EDE_WEIGHT_PROCESS_RELATIONSHIP,   /* 6: ProcessRelationship */
        EDE_WEIGHT_MEMORY_ARTIFACTS,       /* 7: MemoryArtifacts */
        EDE_WEIGHT_SELF_DEBUGGING,         /* 8: SelfDebugging */
        EDE_WEIGHT_THREAD_BASED,           /* 9: ThreadBased */
        EDE_WEIGHT_KERNEL_QUERIES,         /* 10: KernelQueries */
        EDE_WEIGHT_CODE_INTEGRITY,         /* 11: CodeIntegrity */
        EDE_WEIGHT_COMBINED,               /* 12: Combined */
        EDE_WEIGHT_KERNEL_QUERIES,         /* 13: KernelContext */
    };
    DOUBLE severityMultipliers[] = {
        1.0,    /* Low */
        2.5,    /* Medium */
        5.0,    /* High */
        10.0    /* Critical */
    };

    for (i = 0; i < Result->TotalDetections; i++) {
        const EDE_DETECTION* det = &Result->Detections[i];
        DOUBLE catWeight = 1.0;
        DOUBLE sevMult   = 1.0;

        if ((ULONG)det->Category < sizeof(categoryWeights) / sizeof(categoryWeights[0]))
            catWeight = categoryWeights[det->Category];

        if ((ULONG)det->Severity < sizeof(severityMultipliers) / sizeof(severityMultipliers[0]))
            sevMult = severityMultipliers[det->Severity];

        score += catWeight * sevMult * det->Confidence;
    }

    Result->EvasionScore = (score > 100.0) ? 100.0 : score;
    Result->IsEvasive = (Result->EvasionScore >= EDE_HIGH_EVASION_THRESHOLD) ||
                        (Result->MaxSeverity >= EdeSeverityHigh);
}

/**************************************************/
/*          编排入口（内部）                        */
/*  AnalyzeProcessInternal (L5040-5125)    */
/**************************************************/

static
VOID
EdepAnalyzeProcessInternal(
    _In_ HANDLE hProcess,
    _In_ DWORD  TargetPid,
    _In_ BOOLEAN Is64Bit,
    _In_ const EDE_CONFIG* Config,
    _In_opt_ const EDE_KERNEL_CONTEXT* KernelContext,
    _Inout_ PEDE_RESULT Result
    )
{
    ULONG flags = Config->Flags;

    __try {
        /* 1. PEB 分析 */
        if (EdepHasFlag(flags, EDE_FLAG_SCAN_PEB))
            EdepAnalyzePEB(hProcess, Is64Bit, Result);

        /* 2. API/DebugObject 分析 */
        if (EdepHasFlag(flags, EDE_FLAG_SCAN_API)) {
            EdepAnalyzeDebugObject(hProcess, Result);
            EdepAnalyzeHandles(hProcess, TargetPid, Result);
        }

        /* 3. 线程上下文 + 隐藏线程 + TLS 回调 */
        if (EdepHasFlag(flags, EDE_FLAG_SCAN_HARDWARE_BP) ||
            EdepHasFlag(flags, EDE_FLAG_SCAN_THREAD_TECHNIQUES)) {

            if (EdepHasFlag(flags, EDE_FLAG_SCAN_HARDWARE_BP))
                EdepAnalyzeThreadContexts(TargetPid, Result);

            if (EdepHasFlag(flags, EDE_FLAG_SCAN_THREAD_TECHNIQUES)) {
                EdepCheckHiddenThreads(hProcess, TargetPid, Result);
                EdepCheckTLSCallbacks(hProcess, TargetPid, Result);
            }
        }

        /* 4. 内存扫描 */
        if (EdepHasFlag(flags, EDE_FLAG_SCAN_MEMORY_ARTIFACTS))
            EdepScanMemory(hProcess, Result);

        /* 5. 进程关系 */
        if (EdepHasFlag(flags, EDE_FLAG_SCAN_PROCESS_RELATIONSHIPS))
            EdepAnalyzeProcessRelationships(TargetPid, Result);

        /* 6. 时序分析 */
        if (EdepHasFlag(flags, EDE_FLAG_SCAN_TIMING))
            EdepCheckTimingTechniques(hProcess, TargetPid, Result);

        /* 7. 异常处理 */
        if (EdepHasFlag(flags, EDE_FLAG_SCAN_EXCEPTION))
            EdepCheckExceptionTechniques(hProcess, TargetPid, Result);

        /* 8. API 钩子 / 代码完整性 */
        if (EdepHasFlag(flags, EDE_FLAG_SCAN_CODE_INTEGRITY))
            EdepCheckAPIHookDetection(hProcess, TargetPid, Result);

        /* 9. 代码完整性（InstrumentationCallback + PE 头完整性） */
        if (EdepHasFlag(flags, EDE_FLAG_SCAN_CODE_INTEGRITY))
            EdepAnalyzeCodeIntegrity(hProcess, Result);

        /* 10. 内核调试信息 */
        if (EdepHasFlag(flags, EDE_FLAG_SCAN_KERNEL_QUERIES))
            EdepQueryKernelDebugInfo(hProcess, TargetPid, Result);

        /* 11. 内核上下文/命令行分析 */
        if (KernelContext && KernelContext->ImagePath[0] != L'\0')
            EdepAnalyzeKernelContext(KernelContext, Result);

        /* 计算评分 */
        EdepCalculateScore(Result);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (g_GlobalStats)
            InterlockedIncrement64(&g_GlobalStats->AnalysisErrors);
    }
}

/**************************************************/
/*          公共 API 实现                           */
/**************************************************/

_Must_inspect_result_
NTSTATUS
EdeAnalyzeProcessWithContext(
    _In_  ULONG                     ProcessId,
    _In_opt_ const EDE_CONFIG*      Config,
    _In_opt_ const EDE_KERNEL_CONTEXT* KernelContext,
    _Out_ PEDE_RESULT               Result
    )
{
    HANDLE hProcess = NULL;
    EDE_CONFIG defaultConfig;
    ULONG cbNeeded = 0;
    HMODULE hMod = NULL;
    BOOLEAN is64Bit = FALSE;

    if (!Result) return STATUS_INVALID_PARAMETER;
    ZeroMemory(Result, sizeof(EDE_RESULT));

    /* 加载 NT 函数（懒加载） */
    EdepLoadNtFunctions();

    /* 使用默认配置（如果未提供） */
    if (!Config) {
        ZeroMemory(&defaultConfig, sizeof(defaultConfig));
        defaultConfig.Depth = EdeDepthComprehensive;
        defaultConfig.Flags = EDE_PRESET_COMPREHENSIVE;
        defaultConfig.TimeoutMs = EDE_DEFAULT_TIMEOUT_MS;
        defaultConfig.MaxThreads = EDE_MAX_THREADS;
        defaultConfig.MaxMemoryRegions = EDE_MAX_MEMORY_REGIONS;
        defaultConfig.MaxHandles = EDE_MAX_HANDLES;
        Config = &defaultConfig;
    }

    /* 打开目标进程 */
    if (!CoOpenProcessForQueryRead(ProcessId, &hProcess))
        return STATUS_ACCESS_DENIED;

    /* 检测位数 */
    IsWow64Process(hProcess, (PBOOL)&is64Bit);
    is64Bit = !is64Bit; /* IsWow64=FALSE 表示 64 位进程 */

    /* 填充结果基本信息 */
    Result->TargetPid = ProcessId;
    Result->Is64Bit = is64Bit;
    Result->MaxSeverity = EdeSeverityLow;
    QueryPerformanceCounter(&Result->AnalysisStartTime);

    /* 获取进程名 */
    {
        WCHAR exePath[MAX_PATH] = { 0 };
        SIZE_t j;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded) &&
            cbNeeded >= sizeof(HMODULE)) {
            GetModuleFileNameExW(hProcess, hMod, exePath, MAX_PATH);
        }

        if (exePath[0] != L'\0') {
            PCWSTR slash = wcsrchr(exePath, L'\\');
            if (slash) {
                for (j = 0; slash[j+1] && j < EDE_MAX_PROCESS_NAME - 1; j++)
                    Result->ProcessName[j] = slash[j+1];
                Result->ProcessName[j] = L'\0';
            }
            wcscpy_s(Result->ProcessPath, EDE_MAX_PROCESS_PATH, exePath);
        }
    }

    /* 执行分析 */
    EdepAnalyzeProcessInternal(hProcess, ProcessId, is64Bit,
                               Config, KernelContext, Result);

    QueryPerformanceCounter(&Result->AnalysisEndTime);

    /* 更新全局统计 */
    if (g_GlobalStats) {
        InterlockedIncrement64(&g_GlobalStats->TotalAnalyses);
        if (Result->IsEvasive)
            InterlockedIncrement64(&g_GlobalStats->EvasiveProcesses);
        InterlockedAdd64(&g_GlobalStats->TotalDetections, Result->TotalDetections);
    }

    EdepSafeClose(hProcess);
    return STATUS_SUCCESS;
}

_Must_inspect_result_
NTSTATUS
EdeAnalyzeProcess(
    _In_  ULONG                     ProcessId,
    _In_opt_ const EDE_CONFIG*      Config,
    _Out_ PEDE_RESULT               Result
    )
{
    return EdeAnalyzeProcessWithContext(ProcessId, Config, NULL, Result);
}

/**************************************************/
/*          初始化/清理                             */
/**************************************************/

_Must_inspect_result_
NTSTATUS
EdeInitialize(
    _Outptr_ PEDE_STATS* GlobalStats
    )
{
    if (!GlobalStats) return STATUS_INVALID_PARAMETER;

    *GlobalStats = (PEDE_STATS)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY, sizeof(EDE_STATS));
    if (!*GlobalStats) return STATUS_INSUFFICIENT_RESOURCES;

    g_GlobalStats = *GlobalStats;
    EdepLoadNtFunctions();

    return STATUS_SUCCESS;
}

VOID
EdeShutdown(
    _In_opt_ _Post_invalid_ PEDE_STATS GlobalStats
    )
{
    if (GlobalStats) {
        HeapFree(GetProcessHeap(), 0, GlobalStats);
        if (g_GlobalStats == GlobalStats)
            g_GlobalStats = NULL;
    }
}

/**************************************************/
/*          回调/工具 API                           */
/**************************************************/

VOID
EdeSetDetectionCallback(
    _In_opt_ PDEDE_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    g_Callback    = Callback;
    g_CallbackCtx = Context;
}

PCWSTR
EdeTechniqueName(
    _In_ EDE_TECHNIQUE Technique
    )
{
    switch (Technique) {
    case EdeTechniqueNone:                       return L"None";
    case EdeTechniquePEB_BeingDebugged:          return L"PEB_BeingDebugged";
    case EdeTechniquePEB_NtGlobalFlag:           return L"PEB_NtGlobalFlag";
    case EdeTechniquePEB_HeapFlags:              return L"PEB_HeapFlags";
    case EdeTechniquePEB_HeapFlagsForceFlags:    return L"PEB_HeapForceFlags";
    case EdeTechniquePEB_HeapTailChecking:       return L"PEB_HeapTailChecking";
    case EdeTechniquePEB_LdrModuleList:          return L"PEB_LdrModuleList";
    case EdeTechniquePEB_ProcessParameters:      return L"PEB_ProcessParameters";
    case EdeTechniquePEB_OSVersionCheck:         return L"PEB_OSVersionCheck";
    case EdeTechniqueHW_BreakpointRegisters:     return L"HW_BreakpointRegisters";
    case EdeTechniqueHW_DebugStatusRegister:     return L"HW_DebugStatusRegister";
    case EdeTechniqueHW_DebugControlRegister:    return L"HW_DebugControlRegister";
    case EdeTechniqueHW_GetThreadContext:        return L"HW_GetThreadContext";
    case EdeTechniqueHW_SetThreadContext:        return L"HW_SetThreadContext";
    case EdeTechniqueHW_ContextDebugEnum:        return L"HW_ContextDebugEnum";
    case EdeTechniqueAPI_IsDebuggerPresent:      return L"API_IsDebuggerPresent";
    case EdeTechniqueAPI_CheckRemoteDebuggerPresent: return L"API_CheckRemoteDebuggerPresent";
    case EdeTechniqueAPI_NtQueryInfo_DebugPort:  return L"API_NtQueryInfo_DebugPort";
    case EdeTechniqueAPI_NtQueryInfo_DebugFlags: return L"API_NtQueryInfo_DebugFlags";
    case EdeTechniqueAPI_NtQueryInfo_DebugObject: return L"API_NtQueryInfo_DebugObject";
    case EdeTechniqueAPI_OutputDebugString:      return L"API_OutputDebugString";
    case EdeTechniqueTiming_RDTSC:               return L"Timing_RDTSC";
    case EdeTechniqueTiming_RDTSCP:              return L"Timing_RDTSCP";
    case EdeTechniqueTiming_QueryPerformanceCounter: return L"Timing_QPC";
    case EdeTechniqueTiming_GetTickCount:        return L"Timing_GetTickCount";
    case EdeTechniqueTiming_KUSER_SHARED_DATA:   return L"Timing_KUSER_SHARED_DATA";
    case EdeTechniqueException_INT3:             return L"Exception_INT3";
    case EdeTechniqueException_INT2D:            return L"Exception_INT2D";
    case EdeTechniqueException_ICEBP:            return L"Exception_ICEBP";
    case EdeTechniqueException_UD2:              return L"Exception_UD2";
    case EdeTechniqueObject_DebugObjectHandle:   return L"Object_DebugObjectHandle";
    case EdeTechniqueObject_ProcessHandleEnum:   return L"Object_ProcessHandleEnum";
    case EdeTechniqueProcess_ParentIsDebugger:   return L"Process_ParentIsDebugger";
    case EdeTechniqueProcess_ParentNotExplorer:  return L"Process_ParentNotExplorer";
    case EdeTechniqueMemory_SoftwareBreakpoints: return L"Memory_SoftwareBreakpoints";
    case EdeTechniqueMemory_APIHookDetection:    return L"Memory_APIHookDetection";
    case EdeTechniqueMemory_NtDllIntegrity:      return L"Memory_NtDllIntegrity";
    case EdeTechniqueThread_TLSCallback:         return L"Thread_TLSCallback";
    case EdeTechniqueThread_HiddenThread:        return L"Thread_HiddenThread";
    case EdeTechniqueKernel_SystemKernelDebugger: return L"Kernel_SystemKernelDebugger";
    case EdeTechniqueCode_ImportTableHooks:      return L"Code_ImportTableHooks";
    case EdeTechniqueAdvanced_MultiTechniqueCheck: return L"Advanced_MultiTechniqueCheck";
    case EdeTechniqueKernelCtx_CmdLineDebuggerKeyword: return L"KernelCtx_CmdLineKeyword";
    case EdeTechniqueKernelCtx_ParentPidSpoofed: return L"KernelCtx_ParentPidSpoofed";
    case EdeTechniqueKernelCtx_SuspiciousLaunchDir: return L"KernelCtx_SuspiciousLaunchDir";
    default:                                     return L"UnknownTechnique";
    }
}

PCWSTR
EdeCategoryName(
    _In_ EDE_CATEGORY Category
    )
{
    switch (Category) {
    case EdeCategoryPEBBased:               return L"PEB-Based";
    case EdeCategoryHardwareDebugRegisters: return L"Hardware Debug Registers";
    case EdeCategoryAPIBased:               return L"API-Based";
    case EdeCategoryTimingBased:            return L"Timing-Based";
    case EdeCategoryExceptionBased:         return L"Exception-Based";
    case EdeCategoryObjectHandleBased:      return L"Object Handle";
    case EdeCategoryProcessRelationship:    return L"Process Relationship";
    case EdeCategoryMemoryArtifacts:        return L"Memory Artifacts";
    case EdeCategorySelfDebugging:          return L"Self-Debugging";
    case EdeCategoryThreadBased:            return L"Thread-Based";
    case EdeCategoryKernelQueries:          return L"Kernel Queries";
    case EdeCategoryCodeIntegrity:          return L"Code Integrity";
    case EdeCategoryCombined:               return L"Combined";
    case EdeCategoryKernelContext:           return L"Kernel Context";
    default:                                return L"Unknown";
    }
}

PCWSTR
EdeSeverityName(
    _In_ EDE_SEVERITY Severity
    )
{
    switch (Severity) {
    case EdeSeverityLow:      return L"Low";
    case EdeSeverityMedium:   return L"Medium";
    case EdeSeverityHigh:     return L"High";
    case EdeSeverityCritical: return L"Critical";
    default:                  return L"Unknown";
    }
}
