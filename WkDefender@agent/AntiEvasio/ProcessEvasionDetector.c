/**************************************************/
/*  WkDefender Agent — 进程逃逸检测引擎实现            */
/*  AntiEvasio                                      */
/*                                                  */
/*  迁移自 ShadowStrike ProcessEvasionDetector       */
/*  (.cpp 3364行 + .hpp 752行)。                     */
/*                                                  */
/*  检测类别：                                       */
/*    1. 注入检测 (DLL/Hollowing/APC/反射/线程劫持)   */
/*    2. 代码注入 (RWX/远程线程/Hook/IAT)             */
/*    3. 伪装检测 (路径/父进程/签名/命令行)           */
/*    4. 反调试   (调试端口/硬件断点/时序/TLS)        */
/*    5. 权限提升 (SeDebug/Token/UAC)                */
/*                                                  */
/*  asm/PhantomDisasm 不迁移：用字节模式等价替代。    */
/*  PEParser 不迁移：用内联 PE 解析。                */
/*  编码：UTF-8 with BOM（铁律）                     */
/**************************************************/

#include "ProcessEvasionDetector.h"
#include "../WkDefenderHeader.h"
#include "../Common/Utils.h"

#include <intrin.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <winreg.h>
#include <wctype.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress 9
#endif

#ifndef ProcessDebugPort
#define ProcessDebugPort 7
#endif

#ifndef ProcessDebugObjectHandle
#define ProcessDebugObjectHandle 30
#endif

#ifndef ProcessDebugFlags
#define ProcessDebugFlags 31
#endif

/* 用于进程空心化检测的常量 */
#define PES_DOS_MAGIC      0x5A4D   /* "MZ" */
#define PES_PE_MAGIC       0x00004550 /* "PE\0\0" */
#define PES_OPT_MAGIC_PE32 0x10B
#define PES_OPT_MAGIC_PE64 0x20B
#define PES_HEADER_BUFFER  4096
#define PES_MIN_PE_HEADER_SPACE (sizeof(ULONG) + 20 + 256)

/* 阈值常量 */
#define PES_RDTSC_WARNING_THRESHOLD     50
#define PES_RDTSC_SUSPICIOUS_THRESHOLD  200
#define PES_INT3_THRESHOLD              50
#define PES_MAX_THREADS_CHECK           1000
#define PES_MAX_ENUM_MODS               256
#define PES_MAX_INSTRUCTIONS_SCAN       100000
#define PES_MAX_IMPORT_DLLS             128
#define PES_MAX_IMPORT_FUNCS            512

/**************************************************/
/*          NT 函数动态加载                        */
/**************************************************/

static PfnNtQueryInformationProcess g_NtQueryInfoProcess  = NULL;
static PfnNtQueryInformationThread  g_NtQueryInfoThread   = NULL;
static BOOLEAN                      g_NtFuncsLoaded      = FALSE;

/**************************************************/
/*          回调与全局状态                         */
/**************************************************/

static PES_DETECTION_CALLBACK g_Callback    = NULL;
static PVOID                  g_CallbackCtx = NULL;
static PES_STATS              g_Stats;
static SRWLOCK                g_Lock;
static BOOLEAN                g_Initialized = FALSE;

/**************************************************/
/*          便利宏                                 */
/**************************************************/

#define PesHasFlag(flags, f)   (((ULONG)(flags) & (ULONG)(f)) != 0)

#define PesSafeClose(h) do { if ((h) != NULL && (h) != INVALID_HANDLE_VALUE) { \
    CloseHandle(h); (h) = NULL; } } while(0)

/**************************************************/
/*          已知合法进程路径映射表                  */
/*  m_legitimateProcessPaths               */
/**************************************************/

typedef struct _PES_KNOWN_PATH {
    PCWSTR Name;
    PCWSTR Path;
} PES_KNOWN_PATH;

static const PES_KNOWN_PATH s_KnownProcessPaths[] = {
    {L"svchost.exe",         L"C:\\Windows\\System32\\svchost.exe"},
    {L"explorer.exe",        L"C:\\Windows\\explorer.exe"},
    {L"lsass.exe",           L"C:\\Windows\\System32\\lsass.exe"},
    {L"csrss.exe",           L"C:\\Windows\\System32\\csrss.exe"},
    {L"winlogon.exe",        L"C:\\Windows\\System32\\winlogon.exe"},
    {L"services.exe",        L"C:\\Windows\\System32\\services.exe"},
    {L"smss.exe",            L"C:\\Windows\\System32\\smss.exe"},
    {L"wininit.exe",         L"C:\\Windows\\System32\\wininit.exe"},
    {L"spoolsv.exe",         L"C:\\Windows\\System32\\spoolsv.exe"},
    {L"lsm.exe",             L"C:\\Windows\\System32\\lsm.exe"},
    {L"conhost.exe",         L"C:\\Windows\\System32\\conhost.exe"},
    {L"taskhost.exe",        L"C:\\Windows\\System32\\taskhost.exe"},
    {L"taskhostw.exe",       L"C:\\Windows\\System32\\taskhostw.exe"},
    {L"dwm.exe",             L"C:\\Windows\\System32\\dwm.exe"},
    {L"RuntimeBroker.exe",   L"C:\\Windows\\System32\\RuntimeBroker.exe"},
};
#define PES_KNOWN_PROCESS_COUNT (sizeof(s_KnownProcessPaths) / sizeof(s_KnownProcessPaths[0]))

/**************************************************/
/*          期望父进程映射表                       */
/*  m_expectedParents — 含合法边界情况      */
/**************************************************/

typedef struct _PES_EXPECTED_PARENT {
    PCWSTR ProcessName;
    PCWSTR ExpectedParents[PES_MAX_PARENTS_PER_PROC];
    ULONG  ParentCount;
} PES_EXPECTED_PARENT;

static const PES_EXPECTED_PARENT s_ExpectedParents[] = {
    {L"services.exe", {L"wininit.exe"}, 1},
    {L"svchost.exe",  {L"services.exe"}, 1},
    {L"lsass.exe",    {L"wininit.exe"}, 1},
    {L"csrss.exe",    {L"smss.exe"}, 1},
    {L"winlogon.exe", {L"smss.exe"}, 1},
    {L"wininit.exe",  {L"smss.exe"}, 1},
    {L"smss.exe",     {L"System"}, 1},
    /* explorer.exe 可由多个合法父进程启动 */
    {L"explorer.exe", {L"userinit.exe", L"winlogon.exe", L"sihost.exe",
                       L"taskmgr.exe",  L"explorer.exe", L"dllhost.exe"}, 6},
    {L"taskhost.exe", {L"svchost.exe"}, 1},
    {L"taskhostw.exe",{L"svchost.exe"}, 1},
    {L"RuntimeBroker.exe", {L"svchost.exe"}, 1},
    /* Windows Defender 可从多个服务宿主启动 */
    {L"msmpeng.exe",  {L"services.exe", L"svchost.exe"}, 2},
    /* Windows Update */
    {L"trustedinstaller.exe", {L"services.exe", L"svchost.exe"}, 2},
};
#define PES_EXPECTED_PARENT_COUNT (sizeof(s_ExpectedParents) / sizeof(s_ExpectedParents[0]))

/**************************************************/
/*          可疑 API 名列表                        */
/*  ANTI_DEBUG_APIS / INJECTION_APIS /    */
/*        PRIVILEGE_APIS                          */
/**************************************************/

static const PCSTR s_AntiDebugApis[] = {
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "NtSetInformationThread",
    "NtQuerySystemInformation",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "GetTickCount",
    "GetTickCount64",
    "QueryPerformanceCounter",
    "rdtsc"
};
#define PES_ANTIDEBUG_API_COUNT (sizeof(s_AntiDebugApis) / sizeof(s_AntiDebugApis[0]))

static const PCSTR s_InjectionApis[] = {
    "VirtualAllocEx",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "QueueUserAPC",
    "NtQueueApcThread",
    "SetThreadContext",
    "NtSetContextThread",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection"
};
#define PES_INJECTION_API_COUNT (sizeof(s_InjectionApis) / sizeof(s_InjectionApis[0]))

static const PCSTR s_PrivilegeApis[] = {
    "AdjustTokenPrivileges",
    "LookupPrivilegeValueW",
    "OpenProcessToken",
    "DuplicateTokenEx",
    "ImpersonateLoggedOnUser",
    "SetTokenInformation",
    "CreateProcessAsUserW",
    "CreateProcessWithTokenW"
};
#define PES_PRIVILEGE_API_COUNT (sizeof(s_PrivilegeApis) / sizeof(s_PrivilegeApis[0]))

/**************************************************/
/*          已知 Shellcode 字节模式                */
/*  SHELLCODE_PATTERNS                    */
/**************************************************/

typedef struct _PES_SHELLCODE_PATTERN {
    const UINT8* Bytes;
    SIZE_T       Length;
    PCWSTR       Description;
} PES_SHELLCODE_PATTERN;

static const UINT8 s_ScPatternGetPcEax[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x58};
static const UINT8 s_ScPatternGetPcEbx[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B};
static const UINT8 s_ScPatternHashRes[] = {0x60, 0xFC, 0x31, 0xD2, 0x64, 0x8B};
static const UINT8 s_ScPatternMeta1[]   = {0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00};
static const UINT8 s_ScPatternMeta2[]   = {0xFC, 0xE8, 0x89, 0x00, 0x00, 0x00};
static const UINT8 s_ScPatternReflPE[]  = {0x4D, 0x5A, 0x41, 0x52, 0x55, 0x48};

static const PES_SHELLCODE_PATTERN s_ShellcodePatterns[] = {
    {s_ScPatternGetPcEax, sizeof(s_ScPatternGetPcEax), L"GetPC via CALL $+5 (pop eax)"},
    {s_ScPatternGetPcEbx, sizeof(s_ScPatternGetPcEbx), L"GetPC via CALL $+5 (pop ebx)"},
    {s_ScPatternHashRes,  sizeof(s_ScPatternHashRes),  L"Windows API Hash Resolution"},
    {s_ScPatternMeta1,    sizeof(s_ScPatternMeta1),    L"Metasploit Shellcode Pattern"},
    {s_ScPatternMeta2,    sizeof(s_ScPatternMeta2),    L"Metasploit Shellcode Pattern"},
    {s_ScPatternReflPE,   sizeof(s_ScPatternReflPE),   L"Reflective PE/DLL Pattern"},
};
#define PES_SHELLCODE_PATTERN_COUNT (sizeof(s_ShellcodePatterns) / sizeof(s_ShellcodePatterns[0]))

/**************************************************/
/*          合法用户目录路径白名单                  */
/*  LEGITIMATE_USER_PATHS (Issue #7 fix)   */
/**************************************************/

static const PCWSTR s_LegitUserPaths[] = {
    L"\\appdata\\local\\programs\\",       /* Electron (VS Code, Discord, Slack) */
    L"\\appdata\\roaming\\npm\\",          /* Node.js native modules */
    L"\\appdata\\local\\npm\\",            /* Node.js alternate */
    L"\\appdata\\local\\python",           /* Python .pyd */
    L"\\appdata\\roaming\\python",         /* Python alternate */
    L"\\.m2\\repository\\",                /* Maven */
    L"\\.gradle\\",                        /* Gradle */
    L"\\.nuget\\",                         /* NuGet */
    L"\\appdata\\local\\jetbrains\\",      /* JetBrains */
    L"\\appdata\\roaming\\code\\",         /* VS Code extensions */
    L"\\programdata\\",                    /* Shared data */
    L"\\appdata\\local\\microsoft\\",      /* Microsoft apps */
    L"\\appdata\\roaming\\microsoft\\",    /* Microsoft apps */
    L"\\appdata\\local\\google\\",         /* Chrome */
    L"\\appdata\\local\\mozilla\\",        /* Firefox */
    L"\\.vscode\\",                        /* VS Code extensions */
    L"\\.docker\\",                        /* Docker */
    L"\\appdata\\local\\docker\\",         /* Docker Desktop */
};
#define PES_LEGIT_USER_PATH_COUNT (sizeof(s_LegitUserPaths) / sizeof(s_LegitUserPaths[0]))

/**************************************************/
/*          关键 API 列表（Hook 检测）              */
/*  criticalModules                       */
/**************************************************/

typedef struct _PES_CRITICAL_MODULE {
    PCWSTR ModuleName;
    PCSTR  Functions[16];
    ULONG  FunctionCount;
} PES_CRITICAL_MODULE;

static const PES_CRITICAL_MODULE s_CriticalModules[] = {
    {L"ntdll.dll",
     {"NtQueryInformationProcess", "NtCreateThreadEx", "NtAllocateVirtualMemory",
      "NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtReadVirtualMemory",
      "NtOpenProcess", "NtClose", "NtQuerySystemInformation"},
     9},
    {L"kernel32.dll",
     {"VirtualAlloc", "VirtualProtect", "CreateRemoteThread",
      "WriteProcessMemory", "ReadProcessMemory", "OpenProcess",
      "IsDebuggerPresent", "GetTickCount"},
     8},
};
#define PES_CRITICAL_MODULE_COUNT (sizeof(s_CriticalModules) / sizeof(s_CriticalModules[0]))

/* ================================================================ */
/* Part 2：初始化与辅助函数                                           */
/* ================================================================ */

/**************************************************/
/*  NT 函数动态加载                               */
/**************************************************/

static
VOID
PesLoadNtFunctions(
    VOID
    )
{
    HMODULE hNtdll;

    if (g_NtFuncsLoaded) return;

    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    g_NtQueryInfoProcess = (PfnNtQueryInformationProcess)
        GetProcAddress(hNtdll, "NtQueryInformationProcess");
    g_NtQueryInfoThread = (PfnNtQueryInformationThread)
        GetProcAddress(hNtdll, "NtQueryInformationThread");

    g_NtFuncsLoaded = (g_NtQueryInfoProcess != NULL &&
                       g_NtQueryInfoThread != NULL);
}

/**************************************************/
/*  辅助：大小写不敏感字符串比较                   */
/**************************************************/

static
BOOLEAN
PesStringsEqualCI(
    _In_ PCWSTR A,
    _In_ PCWSTR B
    )
{
    if (!A || !B) return (A == B);
    return (_wcsicmp(A, B) == 0);
}

static
BOOLEAN
PesAsciiStringsEqualCI(
    _In_ PCSTR A,
    _In_ PCSTR B
    )
{
    if (!A || !B) return (A == B);
    return (_stricmp(A, B) == 0);
}

static
BOOLEAN
PesWideContainsAsciiCI(
    _In_ PCWSTR Haystack,
    _In_ PCWSTR Needle
    )
{
    WCHAR lowerHay[PES_MAX_PATH * 2];
    WCHAR lowerNeedle[PES_MAX_PATH];
    SIZE_T i;

    if (!Haystack || !Needle) return FALSE;

    for (i = 0; Haystack[i] && i < ARRAYSIZE(lowerHay) - 1; i++)
        lowerHay[i] = (WCHAR)_towlower(Haystack[i]);
    lowerHay[i] = L'\0';

    for (i = 0; Needle[i] && i < ARRAYSIZE(lowerNeedle) - 1; i++)
        lowerNeedle[i] = (WCHAR)_towlower(Needle[i]);
    lowerNeedle[i] = L'\0';

    return (wcsstr(lowerHay, lowerNeedle) != NULL);
}

/**************************************************/
/*  辅助：获取进程名称 (仅文件名)                  */
/**************************************************/

static
BOOLEAN
PesGetProcessName(
    _In_  ULONG  ProcessId,
    _Out_writes_(BufChars) PWCHAR Buffer,
    _In_  SIZE_T BufChars
    )
{
    HANDLE hProc = NULL;
    WCHAR  fullPath[PES_MAX_PATH];
    DWORD  size = PES_MAX_PATH;
    PCWSTR slash;

    if (!Buffer || BufChars == 0) return FALSE;
    Buffer[0] = L'\0';

    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (!hProc) return FALSE;

    if (!QueryFullProcessImageNameW(hProc, 0, fullPath, &size)) {
        CloseHandle(hProc);
        return FALSE;
    }
    CloseHandle(hProc);

    slash = wcsrchr(fullPath, L'\\');
    if (slash) {
        wcscpy_s(Buffer, BufChars, slash + 1);
    } else {
        wcscpy_s(Buffer, BufChars, fullPath);
    }
    return TRUE;
}

/**************************************************/
/*  辅助：获取进程完整路径                         */
/**************************************************/

static
BOOLEAN
PesGetProcessPath(
    _In_  ULONG  ProcessId,
    _Out_writes_(BufChars) PWCHAR Buffer,
    _In_  SIZE_T BufChars
    )
{
    HANDLE hProc;
    DWORD  size;

    if (!Buffer || BufChars == 0) return FALSE;
    Buffer[0] = L'\0';

    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (!hProc) return FALSE;

    size = (DWORD)BufChars;
    if (!QueryFullProcessImageNameW(hProc, 0, Buffer, &size)) {
        CloseHandle(hProc);
        return FALSE;
    }
    CloseHandle(hProc);
    return TRUE;
}

/**************************************************/
/*  辅助：获取父进程 PID                          */
/**************************************************/

static
ULONG
PesGetParentProcessId(
    _In_ ULONG ProcessId
    )
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    ULONG parentPid = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == ProcessId) {
                parentPid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return parentPid;
}

/**************************************************/
/*  辅助：判断进程是否为 64 位                     */
/**************************************************/

static
BOOLEAN
PesIsProcess64Bit(
    _In_ HANDLE hProcess
    )
{
    BOOL isWow64 = FALSE;
    if (IsWow64Process(hProcess, &isWow64)) {
        return !isWow64;
    }
#ifdef _WIN64
    return TRUE;
#else
    return FALSE;
#endif
}

/**************************************************/
/*  辅助：在结果中添加检测                         */
/**************************************************/

static
VOID
PesAddDetection(
    _Inout_ PPES_RESULT              Result,
    _In_    PES_TECHNIQUE            Technique,
    _In_    PES_SEVERITY             Severity,
    _In_    DOUBLE                   Confidence,
    _In_    PCWSTR                   Description,
    _In_opt_ PCWSTR                 Details
    )
{
    PPES_DETECTED_TECHNIQUE det;
    ULONG techIdx;

    if (!Result) return;
    if (Result->TotalDetections >= PES_MAX_DETECTIONS) return;

    det = &Result->Techniques[Result->TotalDetections];
    RtlZeroMemory(det, sizeof(*det));

    det->Technique  = Technique;
    det->Severity   = Severity;
    det->Confidence = Confidence;
    GetSystemTimeAsFileTime((LPFILETIME)&det->Timestamp);

    if (Description) wcscpy_s(det->Description, PES_MAX_DESCRIPTION, Description);
    if (Details)     wcscpy_s(det->Details, PES_MAX_DETAILS, Details);

    Result->TotalDetections++;

    /* 类别位码：按 50 分段 */
    techIdx = (ULONG)Technique;
    if (techIdx < 256) {
        Result->DetectedCategories |= (1u << (techIdx / 50));
    }

    /* 统计 */
    InterlockedIncrement64(&g_Stats.TotalDetections);
    {
        ULONG catIdx = (techIdx / 50) % 8;
        InterlockedIncrement64(&g_Stats.CategoryDetections[catIdx]);
    }

    /* 回调 */
    if (g_Callback) {
        g_Callback(Result->ProcessId, det, g_CallbackCtx);
    }
}

/**************************************************/
/*  辅助：签名验证                                 */
/*  IsSignatureValid                      */
/**************************************************/

static
BOOLEAN
PesIsSignatureValid(
    _In_ PCWSTR FilePath
    )
{
    WINTRUST_FILE_INFO fileInfo;
    WINTRUST_DATA     trustData;
    GUID              policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG              status;

    if (!FilePath || FilePath[0] == L'\0') return FALSE;

    RtlZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = FilePath;

    RtlZeroMemory(&trustData, sizeof(trustData));
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG;
    trustData.pFile = &fileInfo;

    status = WinVerifyTrust(NULL, &policyGuid, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGuid, &trustData);

    return (status == ERROR_SUCCESS);
}

/**************************************************/
/*  辅助：判断路径是否为异常位置                   */
/*  IsPathAnomaly                         */
/**************************************************/

static
BOOLEAN
PesIsPathAnomaly(
    _In_ PCWSTR ProcessName,
    _In_ PCWSTR ActualPath
    )
{
    SIZE_T i;
    WCHAR  lowerName[260];
    WCHAR  lowerPath[PES_MAX_PATH];
    WCHAR  lowerExpected[PES_MAX_PATH];
    SIZE_T n, p, e;

    if (!ProcessName || !ActualPath) return FALSE;

    for (n = 0; ProcessName[n] && n < 259; n++)
        lowerName[n] = (WCHAR)_towlower(ProcessName[n]);
    lowerName[n] = L'\0';

    for (p = 0; ActualPath[p] && p < PES_MAX_PATH - 1; p++)
        lowerPath[p] = (WCHAR)_towlower(ActualPath[p]);
    lowerPath[p] = L'\0';

    for (i = 0; i < PES_KNOWN_PROCESS_COUNT; i++) {
        if (PesStringsEqualCI(lowerName, s_KnownProcessPaths[i].Name)) {
            for (e = 0; s_KnownProcessPaths[i].Path[e] && e < PES_MAX_PATH - 1; e++)
                lowerExpected[e] = (WCHAR)_towlower(s_KnownProcessPaths[i].Path[e]);
            lowerExpected[e] = L'\0';

            if (wcscmp(lowerPath, lowerExpected) != 0) {
                return TRUE;  /* 路径异常 */
            }
        }
    }
    return FALSE;
}

/**************************************************/
/*  辅助：判断父进程是否被伪装                     */
/*  IsParentSpoofed                       */
/**************************************************/

static
BOOLEAN
PesIsParentSpoofed(
    _In_ PCWSTR ProcessName,
    _In_ PCWSTR ActualParent
    )
{
    SIZE_T i, j;
    WCHAR  lowerName[260];
    WCHAR  lowerParent[260];
    SIZE_T n, p;

    if (!ProcessName || !ActualParent) return FALSE;

    for (n = 0; ProcessName[n] && n < 259; n++)
        lowerName[n] = (WCHAR)_towlower(ProcessName[n]);
    lowerName[n] = L'\0';

    for (p = 0; ActualParent[p] && p < 259; p++)
        lowerParent[p] = (WCHAR)_towlower(ActualParent[p]);
    lowerParent[p] = L'\0';

    for (i = 0; i < PES_EXPECTED_PARENT_COUNT; i++) {
        if (PesStringsEqualCI(lowerName, s_ExpectedParents[i].ProcessName)) {
            BOOLEAN found = FALSE;
            for (j = 0; j < s_ExpectedParents[i].ParentCount; j++) {
                WCHAR lowerExpected[260];
                SIZE_T e;
                for (e = 0; s_ExpectedParents[i].ExpectedParents[j][e] && e < 259; e++)
                    lowerExpected[e] = (WCHAR)_towlower(s_ExpectedParents[i].ExpectedParents[j][e]);
                lowerExpected[e] = L'\0';

                if (wcscmp(lowerParent, lowerExpected) == 0) {
                    found = TRUE;
                    break;
                }
            }
            if (!found) {
                return TRUE;  /* 父进程伪装 */
            }
        }
    }
    return FALSE;
}

/**************************************************/
/*  辅助：判断路径是否位于合法白名单目录           */
/**************************************************/

static
BOOLEAN
PesIsWhitelistedUserPath(
    _In_ PCWSTR RawPath
    )
{
    WCHAR lowerPath[PES_MAX_PATH];
    SIZE_T i, p;
    SIZE_T j;
    WCHAR lowerLegit[PES_MAX_PATH];
    SIZE_T l;

    for (p = 0; RawPath[p] && p < PES_MAX_PATH - 1; p++)
        lowerPath[p] = (WCHAR)_towlower(RawPath[p]);
    lowerPath[p] = L'\0';

    for (i = 0; i < PES_LEGIT_USER_PATH_COUNT; i++) {
        for (l = 0; s_LegitUserPaths[i][l] && l < PES_MAX_PATH - 1; l++)
            lowerLegit[l] = (WCHAR)_towlower(s_LegitUserPaths[i][l]);
        lowerLegit[l] = L'\0';

        for (j = 0; j <= wcslen(lowerPath) - wcslen(lowerLegit); j++) {
            if (wcsncmp(&lowerPath[j], lowerLegit, wcslen(lowerLegit)) == 0)
                return TRUE;
        }
    }
    return FALSE;
}

/* ================================================================ */
/* Part 3：内存扫描与 Shellcode 检测                                  */
/* ================================================================ */

/**************************************************/
/*  判断内存区域是否可疑                           */
/*  IsMemoryRegionSuspicious              */
/**************************************************/

static
BOOLEAN
PesIsMemoryRegionSuspicious(
    _In_ const MEMORY_BASIC_INFORMATION* Mbi
    )
{
    if (!Mbi) return FALSE;

    /* RWX 内存非常可疑 */
    if ((Mbi->Protect & PAGE_EXECUTE_READWRITE) != 0) {
        return TRUE;
    }

    /* 私有可执行内存（未被文件映射）可疑 */
    if (Mbi->Type == MEM_PRIVATE &&
        (Mbi->Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                          PAGE_EXECUTE_READWRITE)) != 0) {
        return TRUE;
    }
    return FALSE;
}

/**************************************************/
/*  Shellcode 模式检测                            */
/*  DetectShellcodePatterns               */
/*  返回值：匹配的模式索引 (-1 = 无匹配)          */
/**************************************************/

static
LONG
PesDetectShellcodePatterns(
    _In_reads_(Size) const UINT8* Data,
    _In_ SIZE_T Size
    )
{
    SIZE_T patIdx;
    SIZE_T i;

    if (!Data || Size == 0) return -1;

    for (patIdx = 0; patIdx < PES_SHELLCODE_PATTERN_COUNT; patIdx++) {
        SIZE_T patLen = s_ShellcodePatterns[patIdx].Length;
        if (Size >= patLen) {
            for (i = 0; i <= Size - patLen; i++) {
                BOOLEAN match = TRUE;
                SIZE_T j;
                for (j = 0; j < patLen; j++) {
                    if (Data[i + j] != s_ShellcodePatterns[patIdx].Bytes[j]) {
                        match = FALSE;
                        break;
                    }
                }
                if (match) return (LONG)patIdx;
            }
        }
    }
    return -1;
}

/**************************************************/
/*  内存内容扫描 — 为可疑区域追加描述              */
/**************************************************/

static
VOID
PesAnalyzeRegionContent(
    _In_    HANDLE   hProcess,
    _In_    PVOID    BaseAddress,
    _In_    SIZE_T   RegionSize,
    _Inout_ PWCHAR   Description,
    _In_    SIZE_T   DescChars
    )
{
    UINT8 buffer[PES_MEMORY_SCAN_BUFFER];
    SIZE_T bytesRead = 0;
    SIZE_T scanSize;
    LONG  patternIdx;
    SIZE_T i;
    ULONG nopRun = 0, maxNopRun = 0;

    if (!Description || DescChars == 0) return;

    scanSize = (RegionSize < PES_MEMORY_SCAN_BUFFER) ? RegionSize
                                                     : PES_MEMORY_SCAN_BUFFER;
    if (scanSize == 0) return;

    if (!ReadProcessMemory(hProcess, BaseAddress, buffer, scanSize, &bytesRead))
        return;

    /* 1. Shellcode 模式 */
    patternIdx = PesDetectShellcodePatterns(buffer, bytesRead);
    if (patternIdx >= 0) {
        _snwprintf_s(Description, DescChars, _TRUNCATE,
            L"%s [Shellcode: %s]",
            Description, s_ShellcodePatterns[patternIdx].Description);
    }

    /* 2. 浮动 PE 头 (反射 DLL) */
    if (bytesRead > 2 && buffer[0] == 'M' && buffer[1] == 'Z') {
        _snwprintf_s(Description, DescChars, _TRUNCATE,
            L"%s [Floating PE Header]", Description);
    }

    /* 3. NOP 雪橇检测 */
    for (i = 0; i < bytesRead; i++) {
        if (buffer[i] == 0x90) nopRun++;
        else {
            if (nopRun > maxNopRun) maxNopRun = nopRun;
            nopRun = 0;
        }
    }
    if (nopRun > maxNopRun) maxNopRun = nopRun;

    if (maxNopRun > 16) {
        _snwprintf_s(Description, DescChars, _TRUNCATE,
            L"%s [NOP Sled: %lu bytes]", Description, (ULONG)maxNopRun);
    }
}

/**************************************************/
/*  进程内存扫描                                   */
/*  ScanProcessMemory — 含防 DoS 限制      */
/**************************************************/

static
BOOLEAN
PesScanProcessMemory(
    _In_  HANDLE     hProcess,
    _Out_ PPES_MEMORY_REGION Regions,
    _In_  ULONG      MaxRegions,
    _Out_ PULONG     ActualCount
    )
{
    MEMORY_BASIC_INFORMATION mbi;
    PUCHAR address = NULL;
    SIZE_T iterations = 0;
    ULONG64 totalScanned = 0;
    ULONG regionCount = 0;
    SIZE_T ret;

    if (!hProcess || !Regions || !ActualCount) return FALSE;
    *ActualCount = 0;

    while ((ret = VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) == sizeof(mbi)) {
        UINT_PTR baseAddr;

        if (++iterations > PES_MAX_SCAN_ITERATIONS) break;
        if (totalScanned > PES_MAX_SCAN_SIZE_BYTES) break;
        if (regionCount >= MaxRegions) break;

        if (mbi.State == MEM_COMMIT) {
            PPES_MEMORY_REGION region;
            UINT32 protect = mbi.Protect;

            totalScanned += mbi.RegionSize;

            region = &Regions[regionCount];
            RtlZeroMemory(region, sizeof(*region));

            region->BaseAddress = (ULONG64)(UINT_PTR)mbi.BaseAddress;
            region->Size        = mbi.RegionSize;
            region->Protection  = protect;
            region->Type        = mbi.Type;

            region->IsExecutable = (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            region->IsWritable   = (protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            region->IsReadable   = (protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                               PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                               PAGE_EXECUTE_WRITECOPY)) != 0;

            region->IsSuspicious = PesIsMemoryRegionSuspicious(&mbi);

            if (region->IsSuspicious) {
                if (region->IsExecutable && region->IsWritable) {
                    wcscpy_s(region->Description, PES_MAX_DESCRIPTION,
                        L"RWX memory (Write+Execute) - highly suspicious");
                } else if (mbi.Type == MEM_PRIVATE && region->IsExecutable) {
                    wcscpy_s(region->Description, PES_MAX_DESCRIPTION,
                        L"Private executable memory - potential shellcode");
                }

                PesAnalyzeRegionContent(hProcess, mbi.BaseAddress,
                    mbi.RegionSize, region->Description,
                    PES_MAX_DESCRIPTION);
            }

            regionCount++;
        }

        /* 防溢出推进 */
        baseAddr = (UINT_PTR)mbi.BaseAddress;
        if (mbi.RegionSize > (SIZE_T)(UINTPTR_MAX - baseAddr)) break;
        address = (PUCHAR)mbi.BaseAddress + mbi.RegionSize;

        /* 环绕保护 */
        if (address <= (PUCHAR)mbi.BaseAddress) break;
    }

    *ActualCount = regionCount;
    return TRUE;
}

/* ================================================================ */
/* Part 4：注入检测助手                                               */
/* ================================================================ */

/**************************************************/
/*  检测远程线程（线程起始地址分析）                */
/*  HasRemoteThreads                      */
/*  输出：注入线程数 + 细节字符串                  */
/**************************************************/

static
ULONG
PesHasRemoteThreads(
    _In_  HANDLE   hProcess,
    _Out_writes_(DetailsCapacity) PWCHAR Details,
    _In_  SIZE_T   DetailsCapacity,
    _Out_ PULONG   DetailCount
    )
{
    ULONG suspiciousThreads = 0;
    ULONG detailCount = 0;
    DWORD processId;
    HANDLE snap;
    THREADENTRY32 te;
    FARPROC pLoadLibraryA = NULL;
    FARPROC pLoadLibraryW = NULL;
    BOOLEAN targetIs64;
    BOOLEAN edrIs64;
    WCHAR detailBuf[512];

    if (DetailCount) *DetailCount = 0;
    processId = GetProcessId(hProcess);
    if (processId == 0) return 0;
    if (!g_NtQueryInfoThread) return 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    targetIs64 = PesIsProcess64Bit(hProcess);
#ifdef _WIN64
    edrIs64 = TRUE;
#else
    edrIs64 = FALSE;
#endif

    /* 同一架构下 kernel32 基址一致（每启动 ASLR） */
    if (targetIs64 == edrIs64) {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (hKernel32) {
            pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
            pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
        }
    }
    /* 跨架构 (WoW64) 跳过 LoadLibrary 比较 */

    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            HANDLE hThread;
            PVOID startAddress = NULL;
            ULONG returnLen = 0;
            NTSTATUS status;

            if (te.th32OwnerProcessID != processId) continue;

            hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE,
                                 te.th32ThreadID);
            if (!hThread) continue;

            status = g_NtQueryInfoThread(
                hThread,
                (ULONG)ThreadQuerySetWin32StartAddress,
                &startAddress,
                sizeof(startAddress),
                &returnLen);
            CloseHandle(hThread);

            if (status >= 0 && startAddress) {
                MEMORY_BASIC_INFORMATION mbi;

                if (VirtualQueryEx(hProcess, startAddress, &mbi,
                                   sizeof(mbi)) == sizeof(mbi)) {
                    /* 线程起始于私有 RWX 内存 — 可疑 */
                    if (mbi.Type == MEM_PRIVATE &&
                        (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                        suspiciousThreads++;
                        if (Details && detailCount < DetailsCapacity) {
                            _snwprintf_s(detailBuf, ARRAYSIZE(detailBuf),
                                _TRUNCATE,
                                L"Thread %lu starts in private RWX memory at 0x%llX",
                                (ULONG)te.th32ThreadID,
                                (ULONGLONG)(UINT_PTR)startAddress);
                            wcscpy_s(&Details[detailCount * PES_MAX_DESCRIPTION],
                                PES_MAX_DESCRIPTION, detailBuf);
                            detailCount++;
                        }
                    }

                    /* 线程起始于 LoadLibrary — DLL 注入特征 */
                    if ((pLoadLibraryA && startAddress == (PVOID)pLoadLibraryA) ||
                        (pLoadLibraryW && startAddress == (PVOID)pLoadLibraryW)) {
                        suspiciousThreads++;
                        if (Details && detailCount < DetailsCapacity) {
                            _snwprintf_s(detailBuf, ARRAYSIZE(detailBuf),
                                _TRUNCATE,
                                L"Thread %lu starts at LoadLibrary (DLL injection indicator)",
                                (ULONG)te.th32ThreadID);
                            wcscpy_s(&Details[detailCount * PES_MAX_DESCRIPTION],
                                PES_MAX_DESCRIPTION, detailBuf);
                            detailCount++;
                        }
                    }
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    if (DetailCount) *DetailCount = detailCount;
    return suspiciousThreads;
}

/**************************************************/
/*  检测可疑 DLL（临时目录/用户目录未签名）         */
/*  HasSuspiciousDLLs — 含白名单 (Issue#7) */
/**************************************************/

static
BOOLEAN
PesHasSuspiciousDLLs(
    _In_  HANDLE                        hProcess,
    _Out_ PWCHAR                        SuspiciousDlls,   /* [PES_MAX_INJECTED_DLLS][PES_MAX_PATH] */
    _In_  SIZE_T                        MaxDlls,
    _Out_ PULONG                        DllCount
    )
{
    HMODULE hModules[PES_MAX_MODULES];
    DWORD cbNeeded = 0;
    DWORD moduleCount;
    DWORD i;
    ULONG count = 0;

    if (DllCount) *DllCount = 0;

    if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        return FALSE;
    }

    moduleCount = cbNeeded / sizeof(HMODULE);
    if (moduleCount > PES_MAX_MODULES) moduleCount = PES_MAX_MODULES;

    for (i = 0; i < moduleCount; i++) {
        WCHAR modulePath[PES_MAX_PATH];

        if (GetModuleFileNameExW(hProcess, hModules[i], modulePath,
                                 PES_MAX_PATH) == 0)
            continue;

        /* 1. 从临时目录加载 */
        if (PesWideContainsAsciiCI(modulePath, L"\\temp\\") ||
            PesWideContainsAsciiCI(modulePath, L"\\tmp\\") ||
            PesWideContainsAsciiCI(modulePath, L"\\appdata\\local\\temp\\")) {

            if (count < MaxDlls) {
                _snwprintf_s(&SuspiciousDlls[count * PES_MAX_PATH],
                    PES_MAX_PATH, _TRUNCATE,
                    L"%s [Loaded from temp directory]", modulePath);
            }
            count++;
            continue;
        }

        /* 2. 用户目录未签名 DLL（排除白名单与插件格式） */
        if (!PesIsWhitelistedUserPath(modulePath) &&
            !PesWideContainsAsciiCI(modulePath, L"\\windows\\") &&
            !PesWideContainsAsciiCI(modulePath, L"\\program files") &&
            !PesWideContainsAsciiCI(modulePath, L"\\winsxs\\") &&
            PesWideContainsAsciiCI(modulePath, L"\\users\\")) {

            /* 排除合法插件扩展名 */
            {
                SIZE_T len = wcslen(modulePath);
                BOOLEAN isPlugin = FALSE;
                if (len >= 5) {
                    PCWSTR ext = modulePath + len - 4;
                    if (_wcsicmp(ext, L".pyd")  == 0 ||
                        _wcsicmp(ext, L".node") == 0 ||
                        _wcsicmp(ext, L".vsix") == 0 ||
                        _wcsicmp(ext, L".jar")  == 0) {
                        isPlugin = TRUE;
                    }
                }

                if (!isPlugin && !PesIsSignatureValid(modulePath)) {
                    if (count < MaxDlls) {
                        _snwprintf_s(&SuspiciousDlls[count * PES_MAX_PATH],
                            PES_MAX_PATH, _TRUNCATE,
                            L"%s [Unsigned DLL from user directory]", modulePath);
                    }
                    count++;
                }
            }
        }

        if (count >= MaxDlls) break;
    }

    if (DllCount) *DllCount = count;
    return (count > 0);
}

/**************************************************/
/*  检测进程空心化 (RunPE)                         */
/*  DetectProcessHollowing                */
/*  - TOCTOU 防护：先开文件句柄再读                */
/*  - e_lfanew 边界校验                           */
/**************************************************/

static
BOOLEAN
PesDetectProcessHollowing(
    _In_ HANDLE hProcess,
    _In_ ULONG  ProcessId
    )
{
    HMODULE hModules[1];
    DWORD cbNeeded = 0;
    UINT8  memHeader[PES_HEADER_BUFFER];
    UINT8  diskHeader[PES_HEADER_BUFFER];
    SIZE_T memBytes = 0;
    SIZE_T t;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD diskBytes = 0;
    BOOLEAN hollowed = FALSE;
    WCHAR processPath[PES_MAX_PATH];
    UINT16* memDos = NULL;
    UINT16* diskDos = NULL;
    ULONG*  memPeSig = NULL;
    ULONG*  diskPeSig = NULL;

    /* 获取主模块基址 */
    if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded) ||
        cbNeeded == 0) {
        return FALSE;
    }

    /* 读取内存中的 PE 头 */
    if (!ReadProcessMemory(hProcess, hModules[0], memHeader,
                           sizeof(memHeader), &memBytes)) {
        return FALSE;
    }
    if (memBytes < sizeof(IMAGE_DOS_HEADER)) return FALSE;

    memDos = (UINT16*)memHeader;
    if (memDos[0] != PES_DOS_MAGIC) {
        /* 无 MZ 头 — 可能已被掏空 */
        return TRUE;
    }

    /* e_lfanew 边界校验（攻击者可控制） */
    {
        LONG e_lfanew = *(LONG*)(memHeader + 0x3C);
        if (e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) ||
            e_lfanew >= (LONG)(PES_HEADER_BUFFER - PES_MIN_PE_HEADER_SPACE)) {
            return TRUE;  /* 无效 e_lfanew 可能是空心化或损坏 */
        }
        if (memBytes <= (SIZE_T)e_lfanew + PES_MIN_PE_HEADER_SPACE) {
            return FALSE;
        }

        memPeSig = (ULONG*)(memHeader + e_lfanew);
        if (*memPeSig != PES_PE_MAGIC) {
            /* 内存中 PE 签名无效 — 空心化 */
            return TRUE;
        }
    }

    /* TOCTOU 防护：先获取路径，再打开文件（共享读） */
    if (!PesGetProcessPath(ProcessId, processPath, PES_MAX_PATH)) {
        return FALSE;
    }

    hFile = CreateFileW(processPath, GENERIC_READ,
                        FILE_SHARE_READ,   /* 允许读，禁止写 */
                        NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;  /* 无法打开文件 */
    }

    /* 从文件句柄读取（不用路径 — 防 TOCTOU） */
    if (!ReadFile(hFile, diskHeader, sizeof(diskHeader), &diskBytes, NULL) ||
        diskBytes < sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(hFile);
        return FALSE;
    }

    diskDos = (UINT16*)diskHeader;
    if (diskDos[0] != PES_DOS_MAGIC) {
        CloseHandle(hFile);
        return FALSE;  /* 磁盘文件无效 */
    }

    {
        LONG e_lfanew = *(LONG*)(diskHeader + 0x3C);
        if (e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) ||
            e_lfanew >= (LONG)(diskBytes - PES_MIN_PE_HEADER_SPACE)) {
            CloseHandle(hFile);
            return FALSE;
        }

        diskPeSig = (ULONG*)(diskHeader + e_lfanew);
        if (*diskPeSig != PES_PE_MAGIC) {
            CloseHandle(hFile);
            return FALSE;
        }

        /* 解引用内存/磁盘 PE 签名 */
        memPeSig = (ULONG*)(memHeader + (*(LONG*)(memHeader + 0x3C)));
        if (*memPeSig != PES_PE_MAGIC) {
            CloseHandle(hFile);
            return TRUE;
        }

        /* 比较入口点 */
        {
            UINT16* memOptMagic = (UINT16*)((PUCHAR)memPeSig + 4 + 20);
            UINT16* diskOptMagic = (UINT16*)((PUCHAR)diskPeSig + 4 + 20);
            ULONG memEntryPoint = 0;
            ULONG diskEntryPoint = 0;
            WORD  memSections = 0;
            WORD  diskSections = 0;

            if (*memOptMagic == PES_OPT_MAGIC_PE64) {
                memEntryPoint = *(ULONG*)((PUCHAR)memOptMagic + 16);
                memSections = *(WORD*)((PUCHAR)memPeSig + 2);
            } else if (*memOptMagic == PES_OPT_MAGIC_PE32) {
                memEntryPoint = *(ULONG*)((PUCHAR)memOptMagic + 16);
                memSections = *(WORD*)((PUCHAR)memPeSig + 2);
            }

            if (*diskOptMagic == PES_OPT_MAGIC_PE64) {
                diskEntryPoint = *(ULONG*)((PUCHAR)diskOptMagic + 16);
                diskSections = *(WORD*)((PUCHAR)diskPeSig + 2);
            } else if (*diskOptMagic == PES_OPT_MAGIC_PE32) {
                diskEntryPoint = *(ULONG*)((PUCHAR)diskOptMagic + 16);
                diskSections = *(WORD*)((PUCHAR)diskPeSig + 2);
            }

            /* 入口点不匹配 → 空心化 */
            if (memEntryPoint != 0 && diskEntryPoint != 0 &&
                memEntryPoint != diskEntryPoint) {
                hollowed = TRUE;
            }

            /* 节数量差异显著 → 空心化 */
            if (memSections != 0 && diskSections != 0 &&
                memSections != diskSections) {
                hollowed = TRUE;
            }
        }
    }

    CloseHandle(hFile);

    UNREFERENCED_PARAMETER(t);
    return hollowed;
}

/**************************************************/
/*  检测反射 DLL 注入                              */
/*  DetectReflectiveDLLInjection          */
/*  在可疑内存区域中查找浮动 PE 头                 */
/**************************************************/

static
BOOLEAN
PesDetectReflectiveDLL(
    _In_ PPES_MEMORY_REGION Regions,
    _In_ ULONG              RegionCount
    )
{
    ULONG i;
    for (i = 0; i < RegionCount; i++) {
        if (wcsstr(Regions[i].Description, L"Floating PE Header") != NULL) {
            return TRUE;
        }
    }
    return FALSE;
}

/* ================================================================ */
/* Part 5：Hook 检测 (Inline/IAT)                                    */
/*  不使用 PhantomDisassembler — 用原始字节模式等价替代              */
/* ================================================================ */

/**************************************************/
/*  分析函数序言 — 检测 Hook 类型                 */
/*  AnalyzeFunctionPrologue               */
/*  返回 TRUE 且输出 Hook 类型字符串              */
/**************************************************/

static
BOOLEAN
PesAnalyzeFunctionPrologue(
    _In_reads_(Size) const UINT8* Code,
    _In_ SIZE_T Size,
    _In_ BOOLEAN Is64Bit,
    _Out_writes_(BufChars) PWCHAR HookType,
    _In_ SIZE_T BufChars
    )
{
    if (!Code || Size == 0 || !HookType || BufChars == 0)
        return FALSE;
    HookType[0] = L'\0';

    /* JMP rel32 (5字节内联钩子) */
    if (Size >= 5 && Code[0] == 0xE9) {
        wcscpy_s(HookType, BufChars, L"JMP rel32 (5-byte inline hook)");
        return TRUE;
    }

    /* JMP [RIP+disp32] (间接跳转钩子) */
    if (Size >= 6 && Code[0] == 0xFF && Code[1] == 0x25) {
        wcscpy_s(HookType, BufChars, L"JMP [RIP+disp32] (indirect hook)");
        return TRUE;
    }

    /* JMP rel8 (短跳钩子) */
    if (Size >= 2 && Code[0] == 0xEB) {
        wcscpy_s(HookType, BufChars, L"JMP rel8 (short jump hook)");
        return TRUE;
    }

    /* CALL rel32 (detour 钩子) */
    if (Size >= 5 && Code[0] == 0xE8) {
        wcscpy_s(HookType, BufChars, L"CALL instruction (detour hook)");
        return TRUE;
    }

    /* INT3 (断点钩子) */
    if (Code[0] == 0xCC) {
        wcscpy_s(HookType, BufChars, L"INT3 (breakpoint hook)");
        return TRUE;
    }

    /* INT 2D (调试钩子) */
    if (Size >= 2 && Code[0] == 0xCD && Code[1] == 0x2D) {
        wcscpy_s(HookType, BufChars, L"INT 2D (debug hook)");
        return TRUE;
    }

    /* PUSH imm; RET (trampoline 钩子) */
    if (Size >= 6 && Code[0] == 0x68 && Code[1] == 0x00 &&
        Code[5] == 0xC3) {
        /* 0x68 + imm32 + 0xC3 */
        if (Code[1] == Code[2] && Code[2] == Code[3] && Code[3] == Code[4]
            && Code[1] == 0x00) {
            /* 空 imm — 仍视为 PUSH/RET 型 */
        }
        if (Size == 6 || Size >= 6) {
            wcscpy_s(HookType, BufChars, L"PUSH/RET gadget (trampoline hook)");
            return TRUE;
        }
    }

    /* MOV RAX, imm64; JMP RAX (12字节 trampoline) — 仅 64 位 */
    if (Is64Bit && Size >= 12) {
        /* 48 B8 <imm64> FF E0 */
        if (Code[0] == 0x48 && Code[1] == 0xB8 &&
            Code[10] == 0xFF && Code[11] == 0xE0) {
            wcscpy_s(HookType, BufChars,
                L"MOV RAX, imm64; JMP RAX (12-byte trampoline)");
            return TRUE;
        }
        /* 49 BB <imm64> 41 FF E3 (MOV R11, imm64; JMP R11) */
        if (Code[0] == 0x49 && Code[1] == 0xBB &&
            Code[10] == 0x41 && Code[11] == 0xFF && Code[12] == 0xE3 &&
            Size >= 13) {
            wcscpy_s(HookType, BufChars,
                L"MOV R11, imm64; JMP R11 (13-byte trampoline)");
            return TRUE;
        }
    }

    return FALSE;
}

/**************************************************/
/*  检测内联钩子（跨进程读取目标模块）              */
/*  DetectInlineHooks                      */
/**************************************************/

static
BOOLEAN
PesDetectInlineHooks(
    _In_  HANDLE                      hProcess,
    _In_  BOOLEAN                     Is64Bit,
    _Out_writes_(MaxHooked) PWCHAR    HookedFunctions,
    _In_  SIZE_T                      MaxHooked,
    _Out_ PULONG                      HookedCount
    )
{
    SIZE_T modIdx;
    ULONG count = 0;

    if (HookedCount) *HookedCount = 0;

    for (modIdx = 0; modIdx < PES_CRITICAL_MODULE_COUNT; modIdx++) {
        HMODULE hLocalMod;
        HMODULE hTargetMod = NULL;
        HMODULE hMods[PES_MAX_ENUM_MODS];
        DWORD cbNeeded = 0;
        DWORD modCount;
        DWORD i;
        SIZE_T fnIdx;

        hLocalMod = GetModuleHandleW(s_CriticalModules[modIdx].ModuleName);
        if (!hLocalMod) continue;

        /* 枚举目标进程模块，找到同名模块基址 */
        if (!EnumProcessModulesEx(hProcess, hMods, sizeof(hMods),
                                  &cbNeeded, LIST_MODULES_ALL)) {
            continue;
        }
        modCount = cbNeeded / sizeof(HMODULE);
        if (modCount > PES_MAX_ENUM_MODS) modCount = PES_MAX_ENUM_MODS;

        for (i = 0; i < modCount; i++) {
            WCHAR modName[MAX_PATH];
            if (GetModuleBaseNameW(hProcess, hMods[i], modName, MAX_PATH)) {
                if (_wcsicmp(modName, s_CriticalModules[modIdx].ModuleName) == 0) {
                    hTargetMod = hMods[i];
                    break;
                }
            }
        }
        if (!hTargetMod) continue;

        for (fnIdx = 0; fnIdx < s_CriticalModules[modIdx].FunctionCount; fnIdx++) {
            FARPROC localProc;
            PVOID targetFuncAddr;
            UINT8  codeBuf[PES_MAX_HOOK_SCAN_BYTES];
            SIZE_T bytesRead = 0;
            UINT_PTR funcOffset;
            WCHAR hookType[128];

            localProc = GetProcAddress(hLocalMod,
                                       s_CriticalModules[modIdx].Functions[fnIdx]);
            if (!localProc) continue;

            /* 计算函数在模块内的偏移，套用到目标基址 */
            funcOffset = (UINT_PTR)localProc - (UINT_PTR)hLocalMod;
            targetFuncAddr = (PVOID)((UINT_PTR)hTargetMod + funcOffset);

            if (!ReadProcessMemory(hProcess, targetFuncAddr, codeBuf,
                                   PES_MAX_HOOK_SCAN_BYTES, &bytesRead)) {
                continue;
            }

            if (PesAnalyzeFunctionPrologue(codeBuf, bytesRead, Is64Bit,
                                           hookType, ARRAYSIZE(hookType))) {
                if (HookedFunctions && count < MaxHooked) {
                    _snwprintf_s(&HookedFunctions[count * PES_MAX_DESCRIPTION],
                        PES_MAX_DESCRIPTION, _TRUNCATE,
                        L"%s!%S - %s",
                        s_CriticalModules[modIdx].ModuleName,
                        s_CriticalModules[modIdx].Functions[fnIdx],
                        hookType);
                }
                count++;
                if (count >= MaxHooked) break;
            }
        }
    }

    if (HookedCount) *HookedCount = count;
    return (count > 0);
}

/**************************************************/
/*  PE 导入表内联解析（供 IAT Hook 检测使用）       */
/*  PEParser::ParseImports                 */
/**************************************************/

typedef struct _PES_PE_IMPORT_FUNC {
    CHAR    Name[PES_MAX_IMPORT_NAME];
    BOOLEAN ByOrdinal;
    ULONG   IatRva;
} PES_PE_IMPORT_FUNC;

typedef struct _PES_PE_IMPORT_DLL {
    CHAR              DllName[PES_MAX_DLL_NAME];
    PES_PE_IMPORT_FUNC Functions[PES_MAX_IMPORT_FUNCS];
    ULONG             FunctionCount;
} PES_PE_IMPORT_DLL;

typedef struct _PES_PE_IMPORT_RESULT {
    PES_PE_IMPORT_DLL  Dlls[PES_MAX_IMPORT_DLLS];
    ULONG              DllCount;
    BOOLEAN            Is64Bit;
    ULONG              ImageBase;
} PES_PE_IMPORT_RESULT;

/**************************************************/
/*  解析 PE 导入表（纯 C 内联实现）                */
/*  返回 TRUE = 有导入表                           */
/**************************************************/

static
BOOLEAN
PesParsePeImports(
    _In_reads_bytes_(FileSize) const UINT8* FileData,
    _In_ SIZE_T FileSize,
    _Out_ PES_PE_IMPORT_RESULT* Imports
    )
{
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS* nt;
    const IMAGE_IMPORT_DESCRIPTOR* idesc;
    ULONG i;
    SIZE_T numDescriptors;
    const UINT8* base = FileData;

    if (!FileData || !Imports || FileSize < sizeof(IMAGE_DOS_HEADER)) {
        return FALSE;
    }
    RtlZeroMemory(Imports, sizeof(*Imports));

    dos = (const IMAGE_DOS_HEADER*)FileData;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    if (dos->e_lfanew == 0 || (SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > FileSize)
        return FALSE;

    nt = (const IMAGE_NT_HEADERS*)(FileData + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        const IMAGE_OPTIONAL_HEADER32* opt32 =
            &nt->OptionalHeader;
        Imports->Is64Bit = FALSE;
        Imports->ImageBase = opt32->ImageBase;
        if (opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
            return FALSE;
        idesc = (const IMAGE_IMPORT_DESCRIPTOR*)
            (base + opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        numDescriptors = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size /
                         sizeof(IMAGE_IMPORT_DESCRIPTOR);
    } else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_OPTIONAL_HEADER64* opt64 =
            (const IMAGE_OPTIONAL_HEADER64*)&nt->OptionalHeader;
        Imports->Is64Bit = TRUE;
        Imports->ImageBase = (ULONG)opt64->ImageBase;
        if (opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
            return FALSE;
        idesc = (const IMAGE_IMPORT_DESCRIPTOR*)
            (base + opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        numDescriptors = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size /
                         sizeof(IMAGE_IMPORT_DESCRIPTOR);
    } else {
        return FALSE;
    }

    /* 安全上限 */
    if (numDescriptors > 512) numDescriptors = 512;

    for (i = 0; i < numDescriptors && Imports->DllCount < PES_MAX_IMPORT_DLLS; i++) {
        PES_PE_IMPORT_DLL* dll;
        const IMAGE_IMPORT_DESCRIPTOR* desc = &idesc[i];
        const CHAR* dllName;
        const IMAGE_THUNK_DATA32* origThunk;
        const IMAGE_THUNK_DATA32* iat;
        ULONG j = 0;

        if (desc->Name == 0 && desc->OriginalFirstThunk == 0 &&
            desc->FirstThunk == 0) {
            break;  /* 结束哨兵 */
        }
        if (desc->Name == 0 || desc->Name >= FileSize) continue;

        dllName = (const CHAR*)(base + desc->Name);
        if ((SIZE_T)((UINT_PTR)dllName - (UINT_PTR)base) + 2 > FileSize)
            continue;

        dll = &Imports->Dlls[Imports->DllCount];
        RtlZeroMemory(dll, sizeof(*dll));
        strncpy_s(dll->DllName, PES_MAX_DLL_NAME, dllName, _TRUNCATE);

        origThunk = desc->OriginalFirstThunk
            ? (const IMAGE_THUNK_DATA32*)(base + desc->OriginalFirstThunk)
            : NULL;

        if (!origThunk) {
            /* 有些 PE 没有 OriginalFirstThunk — 尝试 FirstThunk 中的名称入口 */
            origThunk = (const IMAGE_THUNK_DATA32*)(base + desc->FirstThunk);
        }

        iat = (const IMAGE_THUNK_DATA32*)(base + desc->FirstThunk);

        while (origThunk->u1.AddressOfData != 0 &&
               j < PES_MAX_IMPORT_FUNCS) {
            ULONG64 thunkVal = (ULONG64)(UINT_PTR)origThunk->u1.AddressOfData;

            if (thunkVal & IMAGE_ORDINAL_FLAG32) {
                dll->Functions[j].ByOrdinal = TRUE;
                dll->Functions[j].IatRva = desc->FirstThunk + j * sizeof(IMAGE_THUNK_DATA32);
            } else {
                const IMAGE_IMPORT_BY_NAME* ibn;
                if (thunkVal >= FileSize) break;
                ibn = (const IMAGE_IMPORT_BY_NAME*)(base + thunkVal);
                if ((SIZE_T)thunkVal + 2 >= FileSize) break;
                strncpy_s(dll->Functions[j].Name, PES_MAX_IMPORT_NAME,
                          (const CHAR*)ibn->Name, _TRUNCATE);
                dll->Functions[j].IatRva = desc->FirstThunk + j * sizeof(IMAGE_THUNK_DATA32);
            }
            j++;
            origThunk++;
            iat++;
        }

        if (j > 0) {
            dll->FunctionCount = j;
            Imports->DllCount++;
        }
    }

    return (Imports->DllCount > 0);
}

/**************************************************/
/*  检测 IAT Hook                                  */
/*  DetectIATHooks                         */
/*  验证 IAT 条目是否指向导入模块之外              */
/**************************************************/

static
BOOLEAN
PesDetectIATHooks(
    _In_  HANDLE                     hProcess,
    _In_  PCWSTR                     ModulePath,
    _Out_writes_(MaxHooked) PWCHAR   HookedImports,
    _In_  SIZE_T                     MaxHooked,
    _Out_ PULONG                     HookedCount
    )
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    ULONG  fileSize = 0;
    UINT8* fileData = NULL;
    PES_PE_IMPORT_RESULT imports;
    HMODULE hModules[PES_MAX_MODULES];
    DWORD cbNeeded = 0;
    HMODULE targetModule = NULL;
    DWORD modCount;
    DWORD i;
    ULONG count = 0;

    if (HookedCount) *HookedCount = 0;

    /* 读取并解析磁盘上的 PE 文件 */
    hFile = CreateFileW(ModulePath, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return FALSE;
    }
    if (fileSize > 64 * 1024 * 1024) {  /* 64MB 上限 */
        CloseHandle(hFile);
        return FALSE;
    }

    fileData = (UINT8*)malloc(fileSize);
    if (!fileData) {
        CloseHandle(hFile);
        return FALSE;
    }

    if (!ReadFile(hFile, fileData, fileSize, &fileSize, NULL)) {
        free(fileData);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    if (!PesParsePeImports(fileData, fileSize, &imports)) {
        free(fileData);
        return FALSE;
    }
    free(fileData);

    /* 在目标进程中找到同名模块基址 */
    if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        return FALSE;
    }
    modCount = cbNeeded / sizeof(HMODULE);
    if (modCount > PES_MAX_MODULES) modCount = PES_MAX_MODULES;

    for (i = 0; i < modCount; i++) {
        WCHAR modPath[PES_MAX_PATH];
        if (GetModuleFileNameExW(hProcess, hModules[i], modPath,
                                 PES_MAX_PATH)) {
            if (_wcsicmp(modPath, ModulePath) == 0) {
                targetModule = hModules[i];
                break;
            }
        }
    }
    if (!targetModule) {
        return FALSE;
    }

    /* 对每个导入 DLL，验证 IAT 条目地址 */
    {
        ULONG dllIdx;
        for (dllIdx = 0; dllIdx < imports.DllCount; dllIdx++) {
            PES_PE_IMPORT_DLL* dll = &imports.Dlls[dllIdx];
            HMODULE hTargetImportDll = NULL;
            MODULEINFO modInfo;

            /* 在目标进程中解析导入 DLL 基址 */
            for (i = 0; i < modCount; i++) {
                WCHAR modBaseName[MAX_PATH];
                if (GetModuleBaseNameW(hProcess, hModules[i],
                                       modBaseName, MAX_PATH)) {
                    if (_stricmp(modBaseName, dll->DllName) == 0) {
                        hTargetImportDll = hModules[i];
                        break;
                    }
                }
            }
            if (!hTargetImportDll) continue;

            if (!GetModuleInformation(hProcess, hTargetImportDll,
                                      &modInfo, sizeof(modInfo))) {
                continue;
            }

            {
                ULONG fnIdx;
                for (fnIdx = 0; fnIdx < dll->FunctionCount; fnIdx++) {
                    PES_PE_IMPORT_FUNC* func = &dll->Functions[fnIdx];
                    ULONG64 iatValue = 0;
                    SIZE_T readLen = 0;
                    PVOID iatAddress;
                    UINT_PTR modBase;
                    UINT_PTR modEnd;

                    if (func->ByOrdinal) continue;

                    iatAddress = (PVOID)((UINT_PTR)targetModule + func->IatRva);
                    if (!ReadProcessMemory(hProcess, iatAddress, &iatValue,
                                           imports.Is64Bit ? 8 : 4, &readLen)) {
                        continue;
                    }

                    modBase = (UINT_PTR)modInfo.lpBaseOfDll;
                    modEnd  = modBase + modInfo.SizeOfImage;

                    /* IAT 值指向模块外 → Hooked */
                    if (iatValue != 0 &&
                        (iatValue < modBase || iatValue >= modEnd)) {

                        if (HookedImports && count < MaxHooked) {
                            _snwprintf_s(&HookedImports[count * PES_MAX_DESCRIPTION],
                                PES_MAX_DESCRIPTION, _TRUNCATE,
                                L"%S!%S -> 0x%llX (outside %S)",
                                dll->DllName, func->Name,
                                iatValue, dll->DllName);
                        }
                        count++;
                        if (count >= MaxHooked) break;
                    }
                }
            }
        }
    }

    if (HookedCount) *HookedCount = count;
    return (count > 0);
}

/* ================================================================ */
/* Part 6：反调试检测                                                 */
/* ================================================================ */

/**************************************************/
/*  CheckDebuggerPresent                         */
/*  CheckDebuggerPresent                  */
/**************************************************/

static
BOOLEAN
PesCheckDebuggerPresent(
    _In_ HANDLE hProcess
    )
{
    BOOL isBeingDebugged = FALSE;
    if (CheckRemoteDebuggerPresent(hProcess, &isBeingDebugged)) {
        return (isBeingDebugged != FALSE);
    }
    return FALSE;
}

/**************************************************/
/*  CheckDebugPort                               */
/*  CheckDebugPort                        */
/**************************************************/

static
BOOLEAN
PesCheckDebugPort(
    _In_ HANDLE hProcess
    )
{
    DWORD_PTR debugPort = 0;
    ULONG returnLen = 0;
    NTSTATUS status;

    if (!g_NtQueryInfoProcess) return FALSE;

    status = g_NtQueryInfoProcess(hProcess, ProcessDebugPort,
                                  &debugPort, sizeof(debugPort),
                                  &returnLen);
    return (status >= 0 && debugPort != 0);
}

/**************************************************/
/*  CheckDebugFlags                               */
/*  CheckDebugFlags                        */
/**************************************************/

static
BOOLEAN
PesCheckDebugFlags(
    _In_ HANDLE hProcess
    )
{
    DWORD debugFlags = 0;
    ULONG returnLen = 0;
    NTSTATUS status;

    if (!g_NtQueryInfoProcess) return FALSE;

    status = g_NtQueryInfoProcess(hProcess, ProcessDebugFlags,
                                  &debugFlags, sizeof(debugFlags),
                                  &returnLen);
    /* NoDebugInherit 标志被清除 = 正在被调试 */
    return (status >= 0 && debugFlags == 0);
}

/**************************************************/
/*  CheckHardwareBreakpoints                      */
/*  CheckHardwareBreakpoints               */
/*  检查 DR0-DR7 调试寄存器                        */
/**************************************************/

static
BOOLEAN
PesCheckHardwareBreakpoints(
    _In_ HANDLE hProcess
    )
{
    DWORD processId;
    HANDLE snap;
    THREADENTRY32 te;
    BOOLEAN detected = FALSE;
    SIZE_T threadsChecked = 0;

    processId = GetProcessId(hProcess);
    if (processId == 0) return FALSE;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;

    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            HANDLE hThread;
            DWORD suspendResult;

            if (te.th32OwnerProcessID != processId) continue;

            if (++threadsChecked > PES_MAX_THREADS_CHECK) break;

            hThread = OpenThread(THREAD_GET_CONTEXT |
                                 THREAD_SUSPEND_RESUME |
                                 THREAD_QUERY_INFORMATION,
                                 FALSE, te.th32ThreadID);
            if (!hThread) continue;

            suspendResult = SuspendThread(hThread);
            if (suspendResult != (DWORD)-1) {
                CONTEXT ctx;
                RtlZeroMemory(&ctx, sizeof(ctx));
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                if (GetThreadContext(hThread, &ctx)) {
                    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 ||
                        ctx.Dr3 != 0) {
                        detected = TRUE;
                    }
                    if ((ctx.Dr7 & 0xFF) != 0) {
                        detected = TRUE;
                    }
                }
                ResumeThread(hThread);
            }
            CloseHandle(hThread);

        } while (!detected && Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return detected;
}

/**************************************************/
/*  CheckSeDebugPrivilege                         */
/*  CheckSeDebugPrivilege                  */
/**************************************************/

static
BOOLEAN
PesCheckSeDebugPrivilege(
    _In_ HANDLE hProcess
    )
{
    HANDLE hToken = NULL;
    DWORD returnLen = 0;
    PTOKEN_PRIVILEGES privileges;
    LUID luid;
    DWORD i;
    BOOLEAN found = FALSE;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &returnLen);
    if (returnLen == 0) {
        CloseHandle(hToken);
        return FALSE;
    }

    privileges = (PTOKEN_PRIVILEGES)malloc(returnLen);
    if (!privileges) {
        CloseHandle(hToken);
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenPrivileges, privileges,
                             returnLen, &returnLen)) {
        free(privileges);
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);

    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        free(privileges);
        return FALSE;
    }

    for (i = 0; i < privileges->PrivilegeCount; i++) {
        if (privileges->Privileges[i].Luid.LowPart == luid.LowPart &&
            privileges->Privileges[i].Luid.HighPart == luid.HighPart) {
            if (privileges->Privileges[i].Attributes &
                (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT)) {
                found = TRUE;
            }
            break;
        }
    }

    free(privileges);
    return found;
}

/**************************************************/
/*  CheckTokenIntegrity                            */
/*  CheckTokenIntegrity                    */
/*  返回完整性级别名称                              */
/**************************************************/

static
BOOLEAN
PesCheckTokenIntegrity(
    _In_  HANDLE   hProcess,
    _Out_writes_(BufChars) PWCHAR IntegrityLevel,
    _In_  SIZE_T   BufChars
    )
{
    HANDLE hToken = NULL;
    DWORD returnLen = 0;
    PTOKEN_MANDATORY_LABEL tml;
    PUCHAR subAuthCount;
    DWORD integrityValue;
    PCWSTR levelStr = L"";

    if (IntegrityLevel && BufChars > 0)
        IntegrityLevel[0] = L'\0';

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &returnLen);
    if (returnLen == 0) {
        CloseHandle(hToken);
        return FALSE;
    }

    tml = (PTOKEN_MANDATORY_LABEL)malloc(returnLen);
    if (!tml) {
        CloseHandle(hToken);
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, tml,
                             returnLen, &returnLen)) {
        free(tml);
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);

    /* 防止畸形 SID */
    subAuthCount = GetSidSubAuthorityCount(tml->Label.Sid);
    if (!subAuthCount || *subAuthCount == 0) {
        free(tml);
        return FALSE;
    }

    integrityValue = *GetSidSubAuthority(tml->Label.Sid,
                                         (DWORD)(*subAuthCount - 1));
    free(tml);

    if (integrityValue >= SECURITY_MANDATORY_SYSTEM_RID) {
        levelStr = L"System";
    } else if (integrityValue >= SECURITY_MANDATORY_HIGH_RID) {
        levelStr = L"High";
    } else if (integrityValue >= SECURITY_MANDATORY_MEDIUM_RID) {
        levelStr = L"Medium";
    } else if (integrityValue >= SECURITY_MANDATORY_LOW_RID) {
        levelStr = L"Low";
    } else {
        levelStr = L"Untrusted";
    }

    if (IntegrityLevel && BufChars > 0) {
        wcscpy_s(IntegrityLevel, BufChars, levelStr);
    }
    return TRUE;
}

/**************************************************/
/*  在磁盘模块的代码节中扫描反调试指令              */
/*  DetectAntiDebugInstructions            */
/*  (不使用 PhantomDisasm — 用字节模式)            */
/**************************************************/

static
BOOLEAN
PesDetectAntiDebugInstructions(
    _In_  PCWSTR ModulePath,
    _Out_writes_(MaxTechs) PWCHAR Techniques,
    _In_  SIZE_T MaxTechs,
    _Out_ PULONG TechCount
    )
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    ULONG filesize = 0;
    UINT8* data = NULL;
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS* nt;
    const IMAGE_SECTION_HEADER* sections;
    WORD numSections;
    WORD i;
    ULONG rdtscCount = 0;
    ULONG int2dCount = 0;
    ULONG int3Count = 0;
    ULONG count = 0;
    SIZE_T offset;

    if (TechCount) *TechCount = 0;

    hFile = CreateFileW(ModulePath, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    filesize = GetFileSize(hFile, NULL);
    if (filesize == 0 || filesize == INVALID_FILE_SIZE ||
        filesize > 64 * 1024 * 1024) {
        CloseHandle(hFile);
        return FALSE;
    }

    data = (UINT8*)malloc(filesize);
    if (!data) {
        CloseHandle(hFile);
        return FALSE;
    }
    if (!ReadFile(hFile, data, filesize, &filesize, NULL)) {
        free(data);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    dos = (const IMAGE_DOS_HEADER*)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        dos->e_lfanew == 0 ||
        (SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > filesize) {
        free(data);
        return FALSE;
    }

    nt = (const IMAGE_NT_HEADERS*)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        free(data);
        return FALSE;
    }

    numSections = nt->FileHeader.NumberOfSections;
    sections = (const IMAGE_SECTION_HEADER*)(
        (PUCHAR)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    if (numSections > 96) numSections = 96;

    /* 遍历代码节，对节内容做字节模式统计 */
    for (i = 0; i < numSections; i++) {
        const IMAGE_SECTION_HEADER* sec = &sections[i];
        ULONG codeChars;
        SIZE_T scanLen;
        SIZE_T sizeOfRaw;

        if (sec->Characteristics == 0) break;  /* 结束 */
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (sec->SizeOfRawData == 0 || sec->PointerToRawData == 0) continue;

        /* 节基址必须在文件范围内 */
        if (sec->PointerToRawData >= filesize) continue;
        sizeOfRaw = min(sec->SizeOfRawData, filesize - sec->PointerToRawData);
        /* 最大扫描 1MB */
        scanLen = min(sizeOfRaw, 1024 * 1024u);

        codeChars = 0;  /* 未使用，保留占位 */

        /* 线性扫描反调试指令字节模式 */
        for (offset = 0; offset + 1 < scanLen; offset++) {
            UINT8 b0 = data[sec->PointerToRawData + offset];
            UINT8 b1 = data[sec->PointerToRawData + offset + 1];

            /* RDTSC: 0F 31 / RDTSCP: 0F 01 F9 */
            if (b0 == 0x0F && b1 == 0x31) {
                rdtscCount++;
            } else if (b0 == 0x0F && b1 == 0x01 &&
                       offset + 2 < scanLen &&
                       data[sec->PointerToRawData + offset + 2] == 0xF9) {
                rdtscCount++;
            }
            /* INT 2D: CD 2D */
            else if (b0 == 0xCD && b1 == 0x2D) {
                int2dCount++;
            }
            /* INT3: CC */
            else if (b0 == 0xCC) {
                int3Count++;
            }
        }
    }
    free(data);

    /* RDTSC 阈值 (Issue #6: 减少误报) */
    if (rdtscCount > PES_RDTSC_SUSPICIOUS_THRESHOLD &&
        (int2dCount > 0 || int3Count > 5)) {
        if (Techniques && count < MaxTechs) {
            _snwprintf_s(&Techniques[count * PES_MAX_DESCRIPTION],
                PES_MAX_DESCRIPTION, _TRUNCATE,
                L"RDTSC/RDTSCP with anti-debug: %lu occurrences + %lu INT2D + %lu INT3",
                rdtscCount, int2dCount, int3Count);
        }
        count++;
    }

    /* INT 2D 几乎专门用于反调试 */
    if (int2dCount > 0) {
        if (Techniques && count < MaxTechs) {
            _snwprintf_s(&Techniques[count * PES_MAX_DESCRIPTION],
                PES_MAX_DESCRIPTION, _TRUNCATE,
                L"INT 2D instructions detected: %lu occurrences (debugger detection)",
                int2dCount);
        }
        count++;
    }

    /* INT3 阈值 (减少误报) */
    if (int3Count > PES_INT3_THRESHOLD) {
        if (Techniques && count < MaxTechs) {
            _snwprintf_s(&Techniques[count * PES_MAX_DESCRIPTION],
                PES_MAX_DESCRIPTION, _TRUNCATE,
                L"Excessive INT3 instructions: %lu occurrences (possible anti-debug)",
                int3Count);
        }
        count++;
    }

    if (TechCount) *TechCount = count;
    return (count > 0);
}

/**************************************************/
/*  检查模块导入表中是否含反调试 API               */
/*  HasAntiDebugAPIs                       */
/**************************************************/

static
BOOLEAN
PesHasAntiDebugAPIs(
    _In_  PCWSTR ModulePath,
    _Out_writes_(MaxApis) PWCHAR Apis,
    _In_  SIZE_T MaxApis,
    _Out_ PULONG ApiCount
    )
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    ULONG filesize = 0;
    UINT8* data = NULL;
    PES_PE_IMPORT_RESULT imports;
    ULONG count = 0;
    ULONG dllIdx;

    if (ApiCount) *ApiCount = 0;

    hFile = CreateFileW(ModulePath, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    filesize = GetFileSize(hFile, NULL);
    if (filesize == 0 || filesize == INVALID_FILE_SIZE ||
        filesize > 64 * 1024 * 1024) {
        CloseHandle(hFile);
        return FALSE;
    }

    data = (UINT8*)malloc(filesize);
    if (!data) {
        CloseHandle(hFile);
        return FALSE;
    }
    if (!ReadFile(hFile, data, filesize, &filesize, NULL)) {
        free(data);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    if (!PesParsePeImports(data, filesize, &imports)) {
        free(data);
        return FALSE;
    }
    free(data);

    for (dllIdx = 0; dllIdx < imports.DllCount; dllIdx++) {
        ULONG fnIdx;
        for (fnIdx = 0; fnIdx < imports.Dlls[dllIdx].FunctionCount; fnIdx++) {
            PES_PE_IMPORT_FUNC* func = &imports.Dlls[dllIdx].Functions[fnIdx];
            SIZE_T a;

            if (func->ByOrdinal) continue;

            for (a = 0; a < PES_ANTIDEBUG_API_COUNT; a++) {
                if (PesAsciiStringsEqualCI(func->Name, s_AntiDebugApis[a])) {
                    if (Apis && count < MaxApis) {
                        _snwprintf_s(&Apis[count * PES_MAX_DESCRIPTION],
                            PES_MAX_DESCRIPTION, _TRUNCATE,
                            L"%S!%S", imports.Dlls[dllIdx].DllName, func->Name);
                    }
                    count++;
                    if (count >= MaxApis) break;
                }
            }
        }
    }

    if (ApiCount) *ApiCount = count;
    return (count > 0);
}

/* ================================================================ */
/* Part 6B：权限分析 + 可疑导入分析                                   */
/* ================================================================ */

/**************************************************/
/*  分析可疑导入 (注入/反调试/提权 API)             */
/*  AnalyzeSuspiciousImports               */
/*  输出分类统计                                   */
/**************************************************/

typedef struct _PES_SUSPICIOUS_IMPORTS {
    ULONG InjectionApiCount;
    ULONG AntiDebugApiCount;
    ULONG PrivilegeApiCount;
    WCHAR Details[PES_MAX_TECHNIQUE_STRINGS][PES_MAX_DESCRIPTION];
    ULONG DetailCount;
} PES_SUSPICIOUS_IMPORTS;

static
BOOLEAN
PesAnalyzeSuspiciousImports(
    _In_  PCWSTR ModulePath,
    _Out_ PES_SUSPICIOUS_IMPORTS* Out
    )
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    ULONG filesize = 0;
    UINT8* data = NULL;
    PES_PE_IMPORT_RESULT imports;
    ULONG dllIdx;

    if (!Out) return FALSE;
    RtlZeroMemory(Out, sizeof(*Out));

    hFile = CreateFileW(ModulePath, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    filesize = GetFileSize(hFile, NULL);
    if (filesize == 0 || filesize == INVALID_FILE_SIZE ||
        filesize > 64 * 1024 * 1024) {
        CloseHandle(hFile);
        return FALSE;
    }

    data = (UINT8*)malloc(filesize);
    if (!data) {
        CloseHandle(hFile);
        return FALSE;
    }
    if (!ReadFile(hFile, data, filesize, &filesize, NULL)) {
        free(data);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    if (!PesParsePeImports(data, filesize, &imports)) {
        free(data);
        return FALSE;
    }
    free(data);

    /* 按三类 API 分类统计 */
    for (dllIdx = 0; dllIdx < imports.DllCount; dllIdx++) {
        ULONG fnIdx;
        for (fnIdx = 0; fnIdx < imports.Dlls[dllIdx].FunctionCount; fnIdx++) {
            PES_PE_IMPORT_FUNC* func = &imports.Dlls[dllIdx].Functions[fnIdx];
            SIZE_T a;
            WCHAR detailBuf[PES_MAX_DESCRIPTION];

            if (func->ByOrdinal) continue;

            /* 注入类 API */
            for (a = 0; a < PES_INJECTION_API_COUNT; a++) {
                if (PesAsciiStringsEqualCI(func->Name, s_InjectionApis[a])) {
                    Out->InjectionApiCount++;
                    _snwprintf_s(detailBuf, ARRAYSIZE(detailBuf), _TRUNCATE,
                        L"[INJECTION] %S!%S",
                        imports.Dlls[dllIdx].DllName, func->Name);
                    if (Out->DetailCount < PES_MAX_TECHNIQUE_STRINGS) {
                        wcscpy_s(Out->Details[Out->DetailCount++],
                            PES_MAX_DESCRIPTION, detailBuf);
                    }
                    break;
                }
            }

            /* 反调试类 API */
            for (a = 0; a < PES_ANTIDEBUG_API_COUNT; a++) {
                if (PesAsciiStringsEqualCI(func->Name, s_AntiDebugApis[a])) {
                    Out->AntiDebugApiCount++;
                    _snwprintf_s(detailBuf, ARRAYSIZE(detailBuf), _TRUNCATE,
                        L"[ANTI-DEBUG] %S!%S",
                        imports.Dlls[dllIdx].DllName, func->Name);
                    if (Out->DetailCount < PES_MAX_TECHNIQUE_STRINGS) {
                        wcscpy_s(Out->Details[Out->DetailCount++],
                            PES_MAX_DESCRIPTION, detailBuf);
                    }
                    break;
                }
            }

            /* 提权类 API */
            for (a = 0; a < PES_PRIVILEGE_API_COUNT; a++) {
                if (PesAsciiStringsEqualCI(func->Name, s_PrivilegeApis[a])) {
                    Out->PrivilegeApiCount++;
                    _snwprintf_s(detailBuf, ARRAYSIZE(detailBuf), _TRUNCATE,
                        L"[PRIVILEGE] %S!%S",
                        imports.Dlls[dllIdx].DllName, func->Name);
                    if (Out->DetailCount < PES_MAX_TECHNIQUE_STRINGS) {
                        wcscpy_s(Out->Details[Out->DetailCount++],
                            PES_MAX_DESCRIPTION, detailBuf);
                    }
                    break;
                }
            }
        }
    }

    /* 高计数警报 */
    if (Out->InjectionApiCount >= 3) {
        WCHAR buf[128];
        _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
            L"[WARNING] %lu injection-related APIs", Out->InjectionApiCount);
        if (Out->DetailCount < PES_MAX_TECHNIQUE_STRINGS) {
            wcscpy_s(Out->Details[Out->DetailCount++],
                PES_MAX_DESCRIPTION, buf);
        }
    }
    if (Out->AntiDebugApiCount >= 2) {
        WCHAR buf[128];
        _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
            L"[WARNING] %lu anti-debug APIs", Out->AntiDebugApiCount);
        if (Out->DetailCount < PES_MAX_TECHNIQUE_STRINGS) {
            wcscpy_s(Out->Details[Out->DetailCount++],
                PES_MAX_DESCRIPTION, buf);
        }
    }

    return (Out->DetailCount > 0);
}

/**************************************************/
/*  TLS 回调分析                                  */
/*  AnalyzeTLSCallbacks                    */
/*  返回 TLS 回调数量                               */
/**************************************************/

static
ULONG
PesAnalyzeTLSCallbacks(
    _In_ PCWSTR ModulePath
    )
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    ULONG filesize = 0;
    UINT8* data = NULL;
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS* nt;
    DWORD tlsDirRva = 0;
    SIZE_T tlsDirSize = 0;
    ULONG callbackCount = 0;
    ULONG rva;
    PVOID callbacksAddr = NULL;
    ULONG numCallbacks = 0;

    hFile = CreateFileW(ModulePath, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    filesize = GetFileSize(hFile, NULL);
    if (filesize == 0 || filesize == INVALID_FILE_SIZE ||
        filesize > 64 * 1024 * 1024) {
        CloseHandle(hFile);
        return 0;
    }

    data = (UINT8*)malloc(filesize);
    if (!data) {
        CloseHandle(hFile);
        return 0;
    }
    if (!ReadFile(hFile, data, filesize, &filesize, NULL)) {
        free(data);
        CloseHandle(hFile);
        return 0;
    }
    CloseHandle(hFile);

    dos = (const IMAGE_DOS_HEADER*)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        dos->e_lfanew == 0 ||
        (SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > filesize) {
        free(data);
        return 0;
    }

    nt = (const IMAGE_NT_HEADERS*)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        free(data);
        return 0;
    }

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_OPTIONAL_HEADER64* opt64 =
            (const IMAGE_OPTIONAL_HEADER64*)&nt->OptionalHeader;
        tlsDirRva = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        tlsDirSize = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    } else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        tlsDirRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        tlsDirSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    }

    if (tlsDirRva == 0 || tlsDirSize == 0) {
        free(data);
        return 0;
    }

    /* 将 TLS 目录 RVA 转为文件偏移 */
    rva = tlsDirRva;
    {
        const IMAGE_SECTION_HEADER* sections;
        WORD numSections = nt->FileHeader.NumberOfSections;
        WORD i;
        ULONG rawOffset = 0;

        sections = (const IMAGE_SECTION_HEADER*)(
            (PUCHAR)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
        if (numSections > 96) numSections = 96;

        for (i = 0; i < numSections; i++) {
            if (sections[i].VirtualAddress == 0) break;
            if (rva >= sections[i].VirtualAddress &&
                rva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) {
                rawOffset = sections[i].PointerToRawData +
                            (rva - sections[i].VirtualAddress);
                break;
            }
        }
        if (rawOffset == 0 || rawOffset >= filesize) {
            free(data);
            return 0;
        }

        /* TLS 目录结构：AddressOfCallBacks 位于偏移 24 (x64) / 24 (x86) 处 */
        /* IMAGE_TLS_DIRECTORY: StartAddressOfRawData(0) End(8) AddressOfIndex(16) */
        /*                     AddressOfCallBacks(24) SizeOfZeroFill(32) Random(40) */
        callbacksAddr = (PVOID)(UINT_PTR)(
            *(ULONG64*)(data + rawOffset + 24));
    }

    /* 回读回调数组 */
    if (callbacksAddr) {
        /* 将回调数组 VA 转文件偏移：需要节映射 */
        ULONG64 va = (ULONG64)(UINT_PTR)callbacksAddr;
        ULONG64 imageBase;
        ULONG rva2;
        ULONG rawOffset2 = 0;
        const IMAGE_SECTION_HEADER* sections;
        WORD numSections = nt->FileHeader.NumberOfSections;
        WORD i;

        if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            imageBase = ((const IMAGE_OPTIONAL_HEADER64*)&nt->OptionalHeader)->ImageBase;
        } else {
            imageBase = nt->OptionalHeader.ImageBase;
        }
        if (va < imageBase) {
            free(data);
            return 0;
        }
        rva2 = (ULONG)(va - imageBase);

        sections = (const IMAGE_SECTION_HEADER*)(
            (PUCHAR)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
        if (numSections > 96) numSections = 96;

        for (i = 0; i < numSections; i++) {
            if (sections[i].VirtualAddress == 0) break;
            if (rva2 >= sections[i].VirtualAddress &&
                rva2 < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) {
                rawOffset2 = sections[i].PointerToRawData +
                             (rva2 - sections[i].VirtualAddress);
                break;
            }
        }

        if (rawOffset2 != 0 && rawOffset2 < filesize) {
            /* 读取回调指针数组（空指针结束） */
            for (numCallbacks = 0; numCallbacks < 64; numCallbacks++) {
                ULONG64 cb;
                if (rawOffset2 + (numCallbacks + 1) * 8 > filesize) break;
                RtlCopyMemory(&cb, data + rawOffset2 + numCallbacks * 8, 8);
                if (cb == 0) break;
                callbackCount++;
            }
        }
    }

    free(data);
    return callbackCount;
}

/* ================================================================ */
/* Part 7：编排核心、评分引擎与公共 API                               */
/* ================================================================ */

/**************************************************/
/*  名称查询：检测技术名称                        */
/*  ProcessEvasionTechniqueToString       */
/**************************************************/

PCWSTR
PesTechniqueName(
    _In_ PES_TECHNIQUE Technique
    )
{
    switch (Technique) {
    case PES_TECHNIQUE_INJ_ClassicDLL:          return L"Classic DLL Injection";
    case PES_TECHNIQUE_INJ_ReflectiveDLL:       return L"Reflective DLL Injection";
    case PES_TECHNIQUE_INJ_ProcessHollowing:    return L"Process Hollowing";
    case PES_TECHNIQUE_INJ_ThreadHijacking:     return L"Thread Hijacking";
    case PES_TECHNIQUE_INJ_APCInjection:        return L"APC Injection";
    case PES_TECHNIQUE_INJ_AtomBombing:         return L"Atom Bombing";
    case PES_TECHNIQUE_INJ_Doppelganging:       return L"Process Doppelganging";
    case PES_TECHNIQUE_INJ_Herpaderping:        return L"Process Herpaderping";
    case PES_TECHNIQUE_INJ_EarlyBird:           return L"Early Bird APC Injection";
    case PES_TECHNIQUE_INJ_ExtraWindowMemory:   return L"Extra Window Memory Injection";
    case PES_TECHNIQUE_CODE_SuspiciousRWX:      return L"Suspicious RWX Memory";
    case PES_TECHNIQUE_CODE_CrossProcessWrite:  return L"Cross-Process Memory Write";
    case PES_TECHNIQUE_CODE_RemoteThread:       return L"Suspicious Remote Thread";
    case PES_TECHNIQUE_CODE_ShellcodePattern:   return L"Shellcode Pattern Detected";
    case PES_TECHNIQUE_CODE_IATHooking:         return L"IAT Hooking";
    case PES_TECHNIQUE_CODE_InlineHooking:      return L"Inline Hooking";
    case PES_TECHNIQUE_CODE_VEHHooking:         return L"VEH Hooking";
    case PES_TECHNIQUE_CODE_TrampolineHook:     return L"Trampoline Hook";
    case PES_TECHNIQUE_MASK_NameAbuse:          return L"Process Name Abuse";
    case PES_TECHNIQUE_MASK_ParentSpoofing:     return L"Parent Process Spoofing";
    case PES_TECHNIQUE_MASK_PathAnomaly:        return L"Process Path Anomaly";
    case PES_TECHNIQUE_MASK_CmdLineInconsist:   return L"Command Line Inconsistency";
    case PES_TECHNIQUE_MASK_SignatureFailure:   return L"Signature Verification Failure";
    case PES_TECHNIQUE_MASK_DoubleExtension:    return L"Double File Extension";
    case PES_TECHNIQUE_MASK_IconMismatch:       return L"Icon Mismatch";
    case PES_TECHNIQUE_ANTI_DebuggerPresent:    return L"Anti-Debug: Debugger Present";
    case PES_TECHNIQUE_ANTI_CheckRemoteDbg:     return L"Anti-Debug: Remote Debugger Check";
    case PES_TECHNIQUE_ANTI_NtQueryDebugPort:   return L"Anti-Debug: NtQueryInformationProcess";
    case PES_TECHNIQUE_ANTI_DebugObject:        return L"Anti-Debug: Debug Object";
    case PES_TECHNIQUE_ANTI_HWBreakpoint:       return L"Anti-Debug: Hardware Breakpoints";
    case PES_TECHNIQUE_ANTI_SWBreakpoint:       return L"Anti-Debug: Software Breakpoints";
    case PES_TECHNIQUE_ANTI_TimingDetection:    return L"Anti-Debug: Timing Detection";
    case PES_TECHNIQUE_ANTI_ParentDebugger:     return L"Anti-Debug: Parent Debugger";
    case PES_TECHNIQUE_ANTI_SEH:                return L"Anti-Debug: SEH Manipulation";
    case PES_TECHNIQUE_ANTI_OutputDebugString:  return L"Anti-Debug: OutputDebugString";
    case PES_TECHNIQUE_ANTI_TLSCallback:        return L"Anti-Debug: TLS Callbacks";
    case PES_TECHNIQUE_PRIV_SeDebug:            return L"Privilege: SeDebugPrivilege";
    case PES_TECHNIQUE_PRIV_TokenManip:         return L"Privilege: Token Manipulation";
    case PES_TECHNIQUE_PRIV_UACBypass:          return L"Privilege: UAC Bypass";
    case PES_TECHNIQUE_PRIV_IntegrityAnomaly:   return L"Privilege: Integrity Anomaly";
    case PES_TECHNIQUE_PRIV_ImpersonationToken: return L"Privilege: Token Impersonation";
    case PES_TECHNIQUE_ENUM_HiddenProcess:      return L"Enumeration: Hidden Process";
    case PES_TECHNIQUE_ENUM_DKOM:               return L"Enumeration: DKOM";
    case PES_TECHNIQUE_ENUM_PEBManipulation:    return L"Enumeration: PEB Manipulation";
    case PES_TECHNIQUE_ENUM_NameRandomization:  return L"Enumeration: Name Randomization";
    case PES_TECHNIQUE_ENUM_TempProcess:        return L"Enumeration: Temp Process";
    default:                                    return L"Unknown";
    }
}

/**************************************************/
/*  名称查询：严重度名称                           */
/**************************************************/

PCWSTR
PesSeverityName(
    _In_ PES_SEVERITY Severity
    )
{
    switch (Severity) {
    case PES_SEVERITY_Critical: return L"Critical";
    case PES_SEVERITY_High:     return L"High";
    case PES_SEVERITY_Medium:   return L"Medium";
    case PES_SEVERITY_Low:      return L"Low";
    default:                    return L"Unknown";
    }
}

/**************************************************/
/*  名称查询：注入方法名称                         */
/**************************************************/

PCWSTR
PesMethodName(
    _In_ PES_METHOD Method
    )
{
    switch (Method) {
    case PES_METHOD_ClassicDLL:    return L"Classic DLL Injection";
    case PES_METHOD_ReflectiveDLL: return L"Reflective DLL Injection";
    case PES_METHOD_Hollowing:     return L"Process Hollowing";
    case PES_METHOD_ThreadHijack:  return L"Thread Hijacking";
    case PES_METHOD_APC:           return L"APC Injection";
    case PES_METHOD_AtomBombing:   return L"Atom Bombing";
    case PES_METHOD_Doppelganging: return L"Process Doppelganging";
    case PES_METHOD_Herpaderping:  return L"Process Herpaderping";
    default:                       return L"Unknown";
    }
}

/**************************************************/
/*  名称查询：MITRE ATT&CK 映射                    */
/**************************************************/

PCSTR
PesTechniqueMitreId(
    _In_ PES_TECHNIQUE Technique
    )
{
    switch (Technique) {
    case PES_TECHNIQUE_INJ_ClassicDLL:
    case PES_TECHNIQUE_INJ_ReflectiveDLL:       return "T1055.001";
    case PES_TECHNIQUE_INJ_ProcessHollowing:    return "T1055.012";
    case PES_TECHNIQUE_INJ_ThreadHijacking:     return "T1055.003";
    case PES_TECHNIQUE_INJ_APCInjection:
    case PES_TECHNIQUE_INJ_EarlyBird:           return "T1055.004";
    case PES_TECHNIQUE_INJ_AtomBombing:         return "T1055.005";
    case PES_TECHNIQUE_INJ_Doppelganging:       return "T1055.013";
    case PES_TECHNIQUE_INJ_Herpaderping:        return "T1055.012";
    case PES_TECHNIQUE_INJ_ExtraWindowMemory:   return "T1055.008";
    case PES_TECHNIQUE_CODE_SuspiciousRWX:      return "T1055";
    case PES_TECHNIQUE_CODE_CrossProcessWrite:  return "T1055";
    case PES_TECHNIQUE_CODE_RemoteThread:       return "T1055";
    case PES_TECHNIQUE_CODE_ShellcodePattern:   return "T1055";
    case PES_TECHNIQUE_CODE_IATHooking:
    case PES_TECHNIQUE_CODE_InlineHooking:
    case PES_TECHNIQUE_CODE_VEHHooking:
    case PES_TECHNIQUE_CODE_TrampolineHook:     return "T1574.002";
    case PES_TECHNIQUE_MASK_NameAbuse:          return "T1036.003";
    case PES_TECHNIQUE_MASK_ParentSpoofing:     return "T1036.004";
    case PES_TECHNIQUE_MASK_PathAnomaly:        return "T1036";
    case PES_TECHNIQUE_MASK_CmdLineInconsist:   return "T1036";
    case PES_TECHNIQUE_MASK_SignatureFailure:   return "T1036";
    case PES_TECHNIQUE_MASK_DoubleExtension:    return "T1036.003";
    case PES_TECHNIQUE_MASK_IconMismatch:       return "T1036";
    case PES_TECHNIQUE_ANTI_DebuggerPresent:
    case PES_TECHNIQUE_ANTI_CheckRemoteDbg:
    case PES_TECHNIQUE_ANTI_NtQueryDebugPort:
    case PES_TECHNIQUE_ANTI_DebugObject:
    case PES_TECHNIQUE_ANTI_HWBreakpoint:
    case PES_TECHNIQUE_ANTI_SWBreakpoint:
    case PES_TECHNIQUE_ANTI_TimingDetection:
    case PES_TECHNIQUE_ANTI_ParentDebugger:
    case PES_TECHNIQUE_ANTI_SEH:
    case PES_TECHNIQUE_ANTI_OutputDebugString:
    case PES_TECHNIQUE_ANTI_TLSCallback:        return "T1622";
    case PES_TECHNIQUE_PRIV_SeDebug:            return "T1134";
    case PES_TECHNIQUE_PRIV_TokenManip:         return "T1134.001";
    case PES_TECHNIQUE_PRIV_UACBypass:          return "T1548";
    case PES_TECHNIQUE_PRIV_IntegrityAnomaly:   return "T1134";
    case PES_TECHNIQUE_PRIV_ImpersonationToken: return "T1134.002";
    case PES_TECHNIQUE_ENUM_HiddenProcess:      return "T1057";
    case PES_TECHNIQUE_ENUM_DKOM:               return "T1057";
    case PES_TECHNIQUE_ENUM_PEBManipulation:    return "T1055";
    case PES_TECHNIQUE_ENUM_NameRandomization:  return "T1036";
    case PES_TECHNIQUE_ENUM_TempProcess:        return "T1036";
    default:                                    return "T0000";
    }
}

/**************************************************/
/*  评分引擎                                      */
/*  CalculateEvasionScore                 */
/*  类别权重：注入0.35 代码0.30 伪装0.20          */
/*            反调试0.10 提权0.05                 */
/**************************************************/

static
FLOAT
PesCalculateEvasionScore(
    _In_ const PES_RESULT* Result
    )
{
    DOUBLE injScore    = 0.0;
    DOUBLE codeScore   = 0.0;
    DOUBLE masqScore   = 0.0;
    DOUBLE antiScore   = 0.0;
    DOUBLE privScore   = 0.0;
    ULONG i;

    if (!Result) return 0.0f;

    for (i = 0; i < Result->TotalDetections; i++) {
        ULONG idx = (ULONG)Result->Techniques[i].Technique;
        DOUBLE conf = Result->Techniques[i].Confidence;

        if (conf <= 0.0) conf = 0.1;

        if (idx >= 1 && idx <= 50) {
            if (conf > injScore) injScore = conf;
        } else if (idx >= 51 && idx <= 100) {
            if (conf > codeScore) codeScore = conf;
        } else if (idx >= 101 && idx <= 150) {
            if (conf > masqScore) masqScore = conf;
        } else if (idx >= 151 && idx <= 200) {
            if (conf > antiScore) antiScore = conf;
        } else if (idx >= 201 && idx <= 250) {
            if (conf > privScore) privScore = conf;
        } else if (idx >= 251 && idx <= 300) {
            /* 枚举类并入伪装权重（轻量） */
            if (conf > masqScore) masqScore = conf * 0.8;
        }
    }

    return (FLOAT)((injScore * 0.35 + codeScore * 0.30 +
                    masqScore * 0.20 + antiScore * 0.10 +
                    privScore * 0.05) * 100.0);
}

/**************************************************/
/*  判定                                          */
/*  DetermineVerdict                      */
/**************************************************/

static
BOOLEAN
PesDetermineVerdict(
    _Inout_ PPES_RESULT Result
    )
{
    ULONG i;
    if (!Result) return FALSE;

    Result->EvasionScore = PesCalculateEvasionScore(Result);

    /* 取最高严重度 */
    Result->MaxSeverity = PES_SEVERITY_Low;
    if (Result->TotalDetections > 0) {
        Result->MaxSeverity = Result->Techniques[0].Severity;
        for (i = 1; i < Result->TotalDetections; i++) {
            if (Result->Techniques[i].Severity > Result->MaxSeverity) {
                Result->MaxSeverity = Result->Techniques[i].Severity;
            }
        }
    }

    /* 判定阈值 */
    if (Result->EvasionScore >= PES_HIGH_CONFIDENCE_SCORE) {
        Result->IsEvasive = TRUE;
        wcscpy_s(Result->ConfidenceLevel, 32, L"High");
    } else if (Result->EvasionScore >= PES_MIN_EVASION_SCORE) {
        Result->IsEvasive = TRUE;
        wcscpy_s(Result->ConfidenceLevel, 32, L"Medium");
    } else {
        Result->IsEvasive = FALSE;
        wcscpy_s(Result->ConfidenceLevel, 32, L"Low");
    }

    /* 高严重度单项直接提升判定 */
    if (!Result->IsEvasive) {
        for (i = 0; i < Result->TotalDetections; i++) {
            if (Result->Techniques[i].Severity == PES_SEVERITY_Critical) {
                Result->IsEvasive = TRUE;
                wcscpy_s(Result->ConfidenceLevel, 32, L"High");
                break;
            }
        }
    }

    return Result->IsEvasive;
}

/**************************************************/
/*  注入检测编排（内部）                          */
/*  AnalyzeInjection + AnalyzeCodeInjecet */
/*  Poison: 添加检测 + 填充 Info                  */
/**************************************************/

static
VOID
PesPrepareInjectionInfo(
    _In_    ULONG           ProcessId,
    _In_    HANDLE          hProcess,
    _Inout_ PPES_RESULT     Result,
    _Inout_ PPES_INJECTION_INFO Info
    )
{
    PPES_MEMORY_REGION regions;
    ULONG regionCount = 0;
    ULONG remoteThreads = 0;
    ULONG suspiciousRegions = 0;
    ULONG i;
    BOOLEAN hasRefl;
    BOOLEAN hasHollow;
    WCHAR   dllDetails[PES_MAX_INJECTED_DLLS][PES_MAX_PATH];
    ULONG   dllCount = 0;
    WCHAR   threadDetails[PES_MAX_TECHNIQUE_STRINGS][PES_MAX_DESCRIPTION];
    ULONG   threadDetailCount = 0;
    WCHAR   buf[PES_MAX_DETAILS];

    if (!Info || !Result) return;
    RtlZeroMemory(Info, sizeof(*Info));

    /* 内存扫描（RWX / Shellcode） */
    regions = (PPES_MEMORY_REGION)malloc(sizeof(PES_MEMORY_REGION) *
                                         PES_MAX_MEMORY_REGIONS);
    if (!regions) {
        Info->Valid = FALSE;
        return;
    }
    RtlZeroMemory(regions, sizeof(PES_MEMORY_REGION) * PES_MAX_MEMORY_REGIONS);

    PesScanProcessMemory(hProcess, regions, PES_MAX_MEMORY_REGIONS,
                         &regionCount);

    /* RWX / 可疑区域统计 */
    for (i = 0; i < regionCount; i++) {
        if (!regions[i].IsSuspicious) continue;
        suspiciousRegions++;
        if (regions[i].IsExecutable && regions[i].IsWritable) {
            if (Info->RwxAddressCount < PES_MAX_RWX_ADDRESSES) {
                Info->RwxAddresses[Info->RwxAddressCount++] =
                    regions[i].BaseAddress;
            }
        }
        if (wcsstr(regions[i].Description, L"Shellcode") != NULL) {
            _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
                L"Shellcode pattern at 0x%llX: %s",
                regions[i].BaseAddress, regions[i].Description);
            PesAddDetection(Result, PES_TECHNIQUE_CODE_ShellcodePattern,
                PES_SEVERITY_Critical, 0.85, buf, NULL);
        }
    }

    Info->SuspiciousMemoryRegions = suspiciousRegions;
    Info->Valid = TRUE;

    /* RWX 内存 → 高置信度代码注入信号 */
    if (Info->RwxAddressCount > 0) {
        _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
            L"Process has %lu RWX memory region(s) (write+execute)",
            Info->RwxAddressCount);
        PesAddDetection(Result, PES_TECHNIQUE_CODE_SuspiciousRWX,
            PES_SEVERITY_Critical, 0.95, buf, NULL);
    }

    /* 远程线程检测 */
    remoteThreads = PesHasRemoteThreads(hProcess, threadDetails[0],
                                        PES_MAX_TECHNIQUE_STRINGS,
                                        &threadDetailCount);
    if (remoteThreads > 0) {
        Info->HasRemoteThreads = TRUE;
        Info->InjectedThreadCount = remoteThreads;

        _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
            L"Process has %lu suspicious remote thread(s)", remoteThreads);
        PesAddDetection(Result, PES_TECHNIQUE_CODE_RemoteThread,
            PES_SEVERITY_High, 0.7, buf,
            (threadDetailCount > 0) ? threadDetails[0] : NULL);
        if (Info->InjectedThreadCount >= 2) {
            Info->Method = PES_METHOD_ThreadHijack;
            PesAddDetection(Result, PES_TECHNIQUE_INJ_ThreadHijacking,
                PES_SEVERITY_Critical, 0.85,
                L"Multiple suspicious thread start addresses", NULL);
        }
    }

    /* 可疑 DLL 检测 */
    if (PesHasSuspiciousDLLs(hProcess, dllDetails[0], PES_MAX_INJECTED_DLLS,
                             &dllCount) && dllCount > 0) {
        Info->InjectedDLLCount = (dllCount < PES_MAX_INJECTED_DLLS) ?
                                 dllCount : PES_MAX_INJECTED_DLLS;
        for (i = 0; i < Info->InjectedDLLCount; i++) {
            wcscpy_s(Info->InjectedDLLs[i], PES_MAX_PATH, dllDetails[i]);
        }
        Info->HasInjection = TRUE;
        Info->Method = PES_METHOD_ClassicDLL;

        _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
            L"Process loaded %lu suspicious DLL(s)", dllCount);
        PesAddDetection(Result, PES_TECHNIQUE_INJ_ClassicDLL,
            PES_SEVERITY_Critical, 0.7, buf,
            (dllCount > 0) ? dllDetails[0] : NULL);
    }

    /* 进程空心化 */
    hasHollow = PesDetectProcessHollowing(hProcess, ProcessId);
    if (hasHollow) {
        Info->HasHollowedImage = TRUE;
        Info->HasInjection = TRUE;
        Info->Method = PES_METHOD_Hollowing;
        PesAddDetection(Result, PES_TECHNIQUE_INJ_ProcessHollowing,
            PES_SEVERITY_Critical, 0.9,
            L"Process image in memory differs from disk (hollowing)", NULL);
    }

    /* 反射 DLL 注入 */
    hasRefl = PesDetectReflectiveDLL(regions, regionCount);
    if (hasRefl) {
        Info->HasInjection = TRUE;
        Info->Method = (Info->Method == PES_METHOD_Unknown) ?
                       PES_METHOD_ReflectiveDLL : Info->Method;
        PesAddDetection(Result, PES_TECHNIQUE_INJ_ReflectiveDLL,
            PES_SEVERITY_Critical, 0.9,
            L"Reflective PE header found in process memory", NULL);
    }

    /* 主模块导入表分析：注入相关 API */
    {
        WCHAR processPath[PES_MAX_PATH];
        if (PesGetProcessPath(ProcessId, processPath, PES_MAX_PATH)) {
            PES_SUSPICIOUS_IMPORTS imp;
            if (PesAnalyzeSuspiciousImports(processPath, &imp)) {
                if (imp.InjectionApiCount >= 3 && !Info->HasInjection &&
                    remoteThreads == 0) {
                    _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
                        L"Module imports %lu injection-related APIs",
                        imp.InjectionApiCount);
                    PesAddDetection(Result, PES_TECHNIQUE_INJ_ClassicDLL,
                        PES_SEVERITY_High, 0.6, buf,
                        (imp.DetailCount > 0) ? imp.Details[0] : NULL);
                }
            }
        }
    }

    /* 结果汇总 */
    if (Info->HasInjection) {
        /* 已由单项添加检测 */
    }

    /* 复制内存区域到结果（供上层使用） */
    {
        ULONG copy = (regionCount < PES_MAX_MEMORY_REGIONS) ?
                     regionCount : PES_MAX_MEMORY_REGIONS;
        RtlCopyMemory(Result->MemoryRegions, regions,
                      copy * sizeof(PES_MEMORY_REGION));
        Result->MemoryRegionCount = copy;
    }

    free(regions);
}

/**************************************************/
/*  伪装检测（内部）                              */
/*  AnalyzeMasquerading                   */
/**************************************************/

static
VOID
PesAnalyzeMasqueradeInternal(
    _In_    ULONG               ProcessId,
    _Inout_ PPES_RESULT         Result,
    _Inout_ PPES_MASQUERADE_INFO Info
    )
{
    WCHAR processName[MAX_PATH];
    WCHAR processPath[PES_MAX_PATH];
    ULONG parentId;
    WCHAR expectedPath[PES_MAX_PATH];
    WCHAR expectedParent[PES_MAX_PATH];
    WCHAR actualParent[MAX_PATH];
    BOOLEAN pathAnomaly;
    BOOLEAN parentSpoof;
    BOOLEAN sigFail = FALSE;
    BOOLEAN knownProcess = FALSE;
    WCHAR buf[PES_MAX_DETAILS];
    SIZE_T i;

    if (!Info || !Result) return;
    RtlZeroMemory(Info, sizeof(*Info));
    Info->Valid = FALSE;

    if (!PesGetProcessName(ProcessId, processName, MAX_PATH)) {
        return;
    }
    if (!PesGetProcessPath(ProcessId, processPath, PES_MAX_PATH)) {
        return;
    }
    parentId = PesGetParentProcessId(ProcessId);
    Info->Valid = TRUE;

    wcscpy_s(Info->ActualPath, PES_MAX_PATH, processPath);
    if (parentId != 0 && parentId != (ULONG)-1) {
        PesGetProcessName(parentId, Info->ActualParent,
                          PES_MAX_PATH);
    }

    /* 期望路径与父进程 */
    expectedPath[0] = L'\0';
    expectedParent[0] = L'\0';
    knownProcess = FALSE;
    for (i = 0; i < PES_KNOWN_PROCESS_COUNT; i++) {
        if (PesStringsEqualCI(processName, s_KnownProcessPaths[i].Name)) {
            wcscpy_s(expectedPath, PES_MAX_PATH, s_KnownProcessPaths[i].Path);
            knownProcess = TRUE;
            break;
        }
    }
    for (i = 0; i < PES_EXPECTED_PARENT_COUNT; i++) {
        if (PesStringsEqualCI(processName, s_ExpectedParents[i].ProcessName)) {
            if (s_ExpectedParents[i].ExpectedParents[0][0]) {
                wcscpy_s(expectedParent, PES_MAX_PATH,
                         s_ExpectedParents[i].ExpectedParents[0]);
            }
            break;
        }
    }

    /* 路径异常 */
    pathAnomaly = PesIsPathAnomaly(processName, processPath);
    Info->HasPathAnomaly = pathAnomaly;
    if (expectedPath[0]) {
        wcscpy_s(Info->ExpectedPath, PES_MAX_PATH, expectedPath);
    }

    /* 父进程伪造 */
    parentSpoof = PesIsParentSpoofed(ProcessId, parentId);
    Info->HasParentSpoof = parentSpoof;
    if (expectedParent[0]) {
        wcscpy_s(Info->ExpectedParent, PES_MAX_PATH, expectedParent);
    }

    /* 签名验证失败（冒充系统进程时权重更高） */
    if (knownProcess || pathAnomaly || parentSpoof) {
        if (!PesIsSignatureValid(processPath)) {
            sigFail = TRUE;
            Info->HasSignatureFailure = TRUE;
        }
    }

    /* 综合判定 */
    Info->IsMasquerading = (pathAnomaly || parentSpoof || sigFail);

    if (pathAnomaly) {
        _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
            L"Process path anomaly: '%s' (expected '%s')",
            processPath, expectedPath);
        PesAddDetection(Result, PES_TECHNIQUE_MASK_PathAnomaly,
            PES_SEVERITY_High, 0.7, buf, NULL);
    }

    if (parentSpoof) {
        _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
            L"Parent process spoofing: parent=%lu ('%s'), expected '%s'",
            parentId, actualParent, expectedParent);
        PesAddDetection(Result, PES_TECHNIQUE_MASK_ParentSpoofing,
            PES_SEVERITY_High, 0.65, buf, NULL);
    }

    if (sigFail) {
        _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
            L"Signature verification failed: '%s'", processPath);
        if (pathAnomaly) {
            /* 伪造系统进程 + 无签名 → 高置信度 */
            PesAddDetection(Result, PES_TECHNIQUE_MASK_SignatureFailure,
                PES_SEVERITY_Critical, 0.75, buf, NULL);
        } else {
            PesAddDetection(Result, PES_TECHNIQUE_MASK_SignatureFailure,
                PES_SEVERITY_Medium, 0.5, buf, NULL);
        }
        Info->IsMasquerading = TRUE;
    }
}

/**************************************************/
/*  反调试检测（内部）                            */
/*  AnalyzeAntiDebug                      */
/**************************************************/

static
VOID
PesAnalyzeAntiDebugInternal(
    _In_    HANDLE              hProcess,
    _In_    ULONG               ProcessId,
    _Inout_ PPES_RESULT         Result,
    _Inout_ PPES_ANTIDEBUG_INFO Info
    )
{
    WCHAR processPath[PES_MAX_PATH];
    WCHAR dbgTechs[PES_MAX_TECHNIQUE_STRINGS][PES_MAX_DESCRIPTION];
    ULONG dbgTechCount = 0;
    WCHAR antiApis[PES_MAX_TECHNIQUE_STRINGS][PES_MAX_DESCRIPTION];
    ULONG antiApiCount = 0;
    ULONG tlsCallbacks = 0;
    BOOLEAN isDebugged = FALSE;
    BOOLEAN hasHwBp = FALSE;
    WCHAR buf[PES_MAX_DETAILS];

    if (!Info || !Result) return;
    RtlZeroMemory(Info, sizeof(*Info));
    Info->Valid = FALSE;

    /* 1. 活动调试器检测 */
    if (hProcess) {
        if (PesCheckDebuggerPresent(hProcess)) {
            isDebugged = TRUE;
            Info->IsDebuggerPresent = TRUE;
            PesAddDetection(Result, PES_TECHNIQUE_ANTI_DebuggerPresent,
                PES_SEVERITY_High, 0.7,
                L"IsDebuggerPresent / CheckRemoteDebuggerPresent active", NULL);
        }
        if (PesCheckDebugPort(hProcess)) {
            isDebugged = TRUE;
            PesAddDetection(Result, PES_TECHNIQUE_ANTI_NtQueryDebugPort,
                PES_SEVERITY_High, 0.75,
                L"Debug port detected via NtQueryInformationProcess", NULL);
        }
        if (PesCheckDebugFlags(hProcess)) {
            isDebugged = TRUE;
            PesAddDetection(Result, PES_TECHNIQUE_ANTI_NtQueryDebugPort,
                PES_SEVERITY_High, 0.7,
                L"ProcessDebugFlags cleared (NoDebugInherit removed)", NULL);
        }
        hasHwBp = PesCheckHardwareBreakpoints(hProcess);
        if (hasHwBp) {
            Info->HasHWBreakpoints = TRUE;
            Info->HasAntiDebug = TRUE;
            PesAddDetection(Result, PES_TECHNIQUE_ANTI_HWBreakpoint,
                PES_SEVERITY_High, 0.8,
                L"Hardware breakpoints (DR0-DR3/DR7) set on threads", NULL);
        }
    } else {
        Info->Valid = FALSE;
        return;
    }

    /* 2. 磁盘模块静态分析（反调试指令 + API 导入） */
    if (PesGetProcessPath(ProcessId, processPath, PES_MAX_PATH)) {
        if (PesDetectAntiDebugInstructions(processPath,
                                           dbgTechs[0],
                                           PES_MAX_TECHNIQUE_STRINGS,
                                           &dbgTechCount)) {
            ULONG i;
            Info->HasAntiDebug = TRUE;
            if (dbgTechCount > 0) {
                Info->HasSWBreakpoints = TRUE;
            }
            for (i = 0; i < dbgTechCount &&
                        Info->TechniqueCount < PES_MAX_TECHNIQUE_STRINGS; i++) {
                wcscpy_s(Info->TechniqueStrings[Info->TechniqueCount++],
                    PES_MAX_DESCRIPTION, dbgTechs[i]);
            }
            _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
                L"Anti-debug instruction patterns in module: %s", dbgTechs[0]);
            PesAddDetection(Result, PES_TECHNIQUE_ANTI_SWBreakpoint,
                PES_SEVERITY_High, 0.75, buf, NULL);
        }

        if (PesHasAntiDebugAPIs(processPath, antiApis[0],
                                PES_MAX_TECHNIQUE_STRINGS,
                                &antiApiCount) && antiApiCount >= 2) {
            ULONG i;
            Info->HasAntiDebug = TRUE;
            for (i = 0; i < antiApiCount &&
                        Info->TechniqueCount < PES_MAX_TECHNIQUE_STRINGS; i++) {
                wcscpy_s(Info->TechniqueStrings[Info->TechniqueCount++],
                    PES_MAX_DESCRIPTION, antiApis[i]);
            }
            _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
                L"Anti-debug APIs imported: %s", antiApis[0]);
            PesAddDetection(Result, PES_TECHNIQUE_ANTI_CheckRemoteDbg,
                PES_SEVERITY_Medium, 0.6, buf, NULL);
        }

        /* TLS 回调（反调试常用载体） */
        tlsCallbacks = PesAnalyzeTLSCallbacks(processPath);
        if (tlsCallbacks > 0) {
            _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
                L"Module has %lu TLS callback(s) (common anti-debug vector)",
                tlsCallbacks);
            if (tlsCallbacks >= 3) {
                PesAddDetection(Result, PES_TECHNIQUE_ANTI_TLSCallback,
                    PES_SEVERITY_High, 0.75, buf, NULL);
            } else {
                PesAddDetection(Result, PES_TECHNIQUE_ANTI_TLSCallback,
                    PES_SEVERITY_Medium, 0.5, buf, NULL);
            }
        }
    }

    /* 3. 无活动调试器时的静态信号 */
    if (!isDebugged && (dbgTechCount > 0 || antiApiCount > 0 ||
                        tlsCallbacks > 0)) {
        Info->HasAntiDebug = TRUE;
    }

    Info->Valid = TRUE;
}

/**************************************************/
/*  编排核心：完整进程分析                        */
/*  AnalyzeProcess                        */
/**************************************************/

static
NTSTATUS
PesAnalyzeProcessInternal(
    _In_  ULONG        ProcessId,
    _In_  HANDLE       hProcess,     /* 可为 NULL — 自动打开 */
    _In_  PPES_CONFIG  Config,
    _Out_ PPES_RESULT  Result
    )
{
    HANDLE hOwn = NULL;
    HANDLE hUse;
    ULONG parentId;
    ULONG64 startMs;
    WCHAR buf[PES_MAX_DETAILS];

    if (!Result) return STATUS_INVALID_PARAMETER;

    PES_INIT_RESULT(Result);
    Result->ProcessId = ProcessId;
    startMs = GetTickCount64();
    Result->AnalysisStartMs = startMs;

    if (Config) {
        Result->Config = *Config;
    } else {
        /* MSVC C 模式不支持 designated initializer — 运行时赋值 */
        RtlZeroMemory(&Result->Config, sizeof(Result->Config));
        Result->Config.Flags          = PES_FLAG_Default;
        Result->Config.CacheTtlSec    = PES_CACHE_TTL_SECONDS;
        Result->Config.EnableDeepScan = FALSE;
        Result->Config.CheckAllThreads = TRUE;
        Result->Config.CheckAllModules = TRUE;
        Result->Config.HasKernelCtx   = FALSE;
        Config = &Result->Config;
    }

    /* 打开进程句柄（若未提供） */
    if (hProcess) {
        hUse = hProcess;
    } else {
        hOwn = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                           PROCESS_VM_QUERY | PROCESS_QUERY_LIMITED_INFORMATION,
                           FALSE, ProcessId);
        if (!hOwn) {
            Result->AnalysisComplete = FALSE;
            InterlockedIncrement64(&g_Stats.AnalysisErrors);
            return STATUS_ACCESS_DENIED;
        }
        hUse = hOwn;
    }

    /* 基本信息 */
    PesGetProcessName(ProcessId, Result->ProcessName, MAX_PATH);
    PesGetProcessPath(ProcessId, Result->ProcessPath, PES_MAX_PATH);
    parentId = PesGetParentProcessId(ProcessId);
    Result->ParentProcessId = parentId;
    if (parentId != 0 && parentId != (ULONG)-1) {
        PesGetProcessName(parentId, Result->ParentProcessName, MAX_PATH);
    }

    /* ---- 注入检测 ---- */
    if (Config->Flags & PES_FLAG_CheckInjection) {
        PesPrepareInjectionInfo(ProcessId, hUse, Result,
                                &Result->InjectionInfo);
    }

    /* ---- Hook 检测 ---- */
    if (Config->Flags & PES_FLAG_CheckModules) {
        WCHAR hookedFuncs[PES_MAX_TECHNIQUE_STRINGS][PES_MAX_DESCRIPTION];
        ULONG hookedFuncCount = 0;
        WCHAR hookedImports[PES_MAX_TECHNIQUE_STRINGS][PES_MAX_DESCRIPTION];
        ULONG hookedImportCount = 0;
        BOOLEAN is64Proc = PesIsProcess64Bit(hUse);

        /* 内联 Hook（跨进程读取关键模块函数序言） */
        if (PesDetectInlineHooks(hUse, is64Proc, hookedFuncs[0],
                                 PES_MAX_TECHNIQUE_STRINGS,
                                 &hookedFuncCount) && hookedFuncCount > 0) {
            _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
                L"Inline hook(s) detected in critical modules (%lu)",
                hookedFuncCount);
            PesAddDetection(Result, PES_TECHNIQUE_CODE_InlineHooking,
                PES_SEVERITY_Critical, 0.75, buf, hookedFuncs[0]);
        }

        /* IAT Hook（磁盘 PE 导入表 vs 进程 IAT 条目） */
        if (Result->ProcessPath[0]) {
            if (PesDetectIATHooks(hUse, Result->ProcessPath,
                                  hookedImports[0],
                                  PES_MAX_TECHNIQUE_STRINGS,
                                  &hookedImportCount) &&
                hookedImportCount > 0) {
                _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
                    L"IAT hook(s) detected (%lu entries redirected)",
                    hookedImportCount);
                PesAddDetection(Result, PES_TECHNIQUE_CODE_IATHooking,
                    PES_SEVERITY_Critical, 0.8, buf, hookedImports[0]);
            }
        }
    }

    /* ---- 伪装检测 ---- */
    if (Config->Flags & PES_FLAG_CheckMasquerading) {
        PesAnalyzeMasqueradeInternal(ProcessId, Result,
                                     &Result->MasqueradeInfo);
    }

    /* ---- 反调试检测 ---- */
    if (Config->Flags & PES_FLAG_CheckAntiDebug) {
        PesAnalyzeAntiDebugInternal(hUse, ProcessId, Result,
                                    &Result->AntiDebugInfo);
    }

    /* ---- 权限与完整性 ---- */
    if (Config->Flags & PES_FLAG_CheckPrivilege) {
        if (PesCheckSeDebugPrivilege(hUse)) {
            PesAddDetection(Result, PES_TECHNIQUE_PRIV_SeDebug,
                PES_SEVERITY_High, 0.6,
                L"Process has SeDebugPrivilege enabled", NULL);
        }
        {
            WCHAR integrity[32];
            if (PesCheckTokenIntegrity(hUse, integrity, 32)) {
                if (_wcsicmp(integrity, L"System") == 0 ||
                    _wcsicmp(integrity, L"High") == 0) {
                    /* 高完整性本身合法，仅记录 */
                }
            }
        }
        {
            WCHAR processPath[PES_MAX_PATH];
            if (PesGetProcessPath(ProcessId, processPath, PES_MAX_PATH)) {
                PES_SUSPICIOUS_IMPORTS imp;
                if (PesAnalyzeSuspiciousImports(processPath, &imp) &&
                    imp.PrivilegeApiCount >= 2) {
                    _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
                        L"Module imports %lu privilege-related APIs",
                        imp.PrivilegeApiCount);
                    PesAddDetection(Result, PES_TECHNIQUE_PRIV_TokenManip,
                        PES_SEVERITY_Critical, 0.75, buf,
                        (imp.DetailCount > 0) ? imp.Details[0] : NULL);
                }
            }
        }
    }

    /* ---- 枚举规避（轻量） ---- */
    if (Config->Flags & PES_FLAG_CheckEnumeration) {
        if (Result->ProcessPath[0]) {
            if (PesWideContainsAsciiCI(Result->ProcessPath, L"\\temp\\") ||
                PesWideContainsAsciiCI(Result->ProcessPath, L"\\tmp\\")) {
                _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
                    L"Process running from temp directory: '%s'",
                    Result->ProcessPath);
                PesAddDetection(Result, PES_TECHNIQUE_ENUM_TempProcess,
                    PES_SEVERITY_Medium, 0.4, buf, NULL);
            }
        }
        /* 名称随机化启发式 */
        if (Result->ProcessName[0]) {
            WCHAR baseName[MAX_PATH];
            SIZE_T len;
            SIZE_T digits = 0;
            SIZE_T j;
            BOOLEAN allHexLike = TRUE;

            RtlZeroMemory(baseName, sizeof(baseName));
            /* 去扩展名 */
            {
                SIZE_T n = wcslen(Result->ProcessName);
                SIZE_T k = 0;
                for (k = 0; k < n && k < MAX_PATH - 1; k++) {
                    if (Result->ProcessName[k] == L'.') break;
                    baseName[k] = Result->ProcessName[k];
                }
            }

            len = wcslen(baseName);
            if (len >= 8 && len <= 16) {
                for (j = 0; j < len; j++) {
                    WCHAR c = baseName[j];
                    if (iswdigit(c)) {
                        digits++;
                    } else if (!((c >= L'a' && c <= L'f') ||
                                 (c >= L'A' && c <= L'F'))) {
                        allHexLike = FALSE;
                    }
                }
                /* 8-16 位全十六进制 → 高概率随机名 */
                if (allHexLike && digits >= 2) {
                    _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE,
                        L"Process name appears randomized (hex-like): '%s'",
                        Result->ProcessName);
                    PesAddDetection(Result, PES_TECHNIQUE_ENUM_NameRandomization,
                        PES_SEVERITY_Medium, 0.5, buf, NULL);
                }
            }
        }
    }

    /* ---- 评分与判定 ---- */
    PesDetermineVerdict(Result);

    Result->AnalysisEndMs = GetTickCount64();
    Result->AnalysisDurationMs = Result->AnalysisEndMs - startMs;
    Result->AnalysisComplete = TRUE;

    if (hOwn) CloseHandle(hOwn);

    /* 统计 */
    InterlockedIncrement64(&g_Stats.TotalAnalyses);
    InterlockedIncrement64(&g_Stats.TotalAnalysisTimeUs,
                           (LONG64)(Result->AnalysisDurationMs * 1000));
    if (Result->IsEvasive) {
        InterlockedIncrement64(&g_Stats.EvasiveProcesses);
    }
    if (Result->InjectionInfo.HasInjection) {
        InterlockedIncrement64(&g_Stats.InjectionsDetected);
    }
    if (Result->MasqueradeInfo.IsMasquerading) {
        InterlockedIncrement64(&g_Stats.MasqueradingDetected);
    }
    if (Result->AntiDebugInfo.HasAntiDebug) {
        InterlockedIncrement64(&g_Stats.AntiDebugDetected);
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*  公共 API — 初始化                              */
/**************************************************/

NTSTATUS
PesInitialize(
    _In_opt_ PPES_CONFIG Config
    )
{
    if (g_Initialized) return STATUS_SUCCESS;

    RtlZeroMemory(&g_Stats, sizeof(g_Stats));
    InitializeSRWLock(&g_Lock);
    g_Callback = NULL;
    g_CallbackCtx = NULL;

    PesLoadNtFunctions();

    g_Initialized = TRUE;
    return STATUS_SUCCESS;
}

/**************************************************/
/*  公共 API — 关闭                                */
/**************************************************/

NTSTATUS
PesShutdown(
    VOID
    )
{
    if (!g_Initialized) return STATUS_SUCCESS;

    AcquireSRWLockExclusive(&g_Lock);
    g_Callback = NULL;
    g_CallbackCtx = NULL;
    g_Initialized = FALSE;
    ReleaseSRWLockExclusive(&g_Lock);

    return STATUS_SUCCESS;
}

/**************************************************/
/*  公共 API — 注入检测                            */
/**************************************************/

NTSTATUS
PesDetectInjection(
    _In_  HANDLE              ProcessHandle,
    _Out_ PPES_INJECTION_INFO Info
    )
{
    PES_RESULT result;
    ULONG processId;

    if (!ProcessHandle || !Info) return STATUS_INVALID_PARAMETER;
    processId = GetProcessId(ProcessHandle);
    if (processId == 0) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(&result, sizeof(result));
    result.ProcessId = processId;

    PesPrepareInjectionInfo(processId, ProcessHandle, &result, Info);

    return (Info->Valid) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/**************************************************/
/*  公共 API — 伪装检测                            */
/**************************************************/

NTSTATUS
PesDetectMasquerading(
    _In_  ULONG               ProcessId,
    _Out_ PPES_MASQUERADE_INFO Info
    )
{
    PES_RESULT result;

    if (!Info || ProcessId == 0) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(&result, sizeof(result));
    result.ProcessId = ProcessId;

    PesAnalyzeMasqueradeInternal(ProcessId, &result, Info);

    return (Info->Valid) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/**************************************************/
/*  公共 API — 反调试检测                          */
/**************************************************/

NTSTATUS
PesDetectAntiDebug(
    _In_  HANDLE              ProcessHandle,
    _In_  ULONG               ProcessId,
    _Out_ PPES_ANTIDEBUG_INFO Info
    )
{
    PES_RESULT result;

    if (!ProcessHandle || !Info) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(&result, sizeof(result));
    result.ProcessId = ProcessId;

    PesAnalyzeAntiDebugInternal(ProcessHandle, ProcessId, &result, Info);

    return (Info->Valid) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/**************************************************/
/*  公共 API — 内存扫描                            */
/**************************************************/

NTSTATUS
PesScanMemory(
    _In_  HANDLE             ProcessHandle,
    _Out_ PPES_MEMORY_REGION Regions,
    _In_  ULONG              MaxRegions,
    _Out_ PULONG             ActualCount
    )
{
    if (!ProcessHandle || !Regions || !ActualCount) {
        return STATUS_INVALID_PARAMETER;
    }
    if (MaxRegions == 0) return STATUS_INVALID_PARAMETER;

    if (PesScanProcessMemory(ProcessHandle, Regions, MaxRegions,
                             ActualCount)) {
        return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;
}

/**************************************************/
/*  公共 API — 完整分析（句柄）                    */
/**************************************************/

NTSTATUS
PesAnalyzeProcess(
    _In_  HANDLE      ProcessHandle,
    _In_  PPES_CONFIG Config,
    _Out_ PPES_RESULT Result
    )
{
    ULONG processId;

    if (!ProcessHandle || !Result) return STATUS_INVALID_PARAMETER;
    processId = GetProcessId(ProcessHandle);
    if (processId == 0) return STATUS_INVALID_PARAMETER;

    return PesAnalyzeProcessInternal(processId, ProcessHandle,
                                     Config, Result);
}

/**************************************************/
/*  公共 API — 完整分析（PID）                     */
/**************************************************/

NTSTATUS
PesAnalyzeProcessById(
    _In_  ULONG       ProcessId,
    _In_  PPES_CONFIG Config,
    _Out_ PPES_RESULT Result
    )
{
    if (ProcessId == 0 || !Result) return STATUS_INVALID_PARAMETER;

    return PesAnalyzeProcessInternal(ProcessId, NULL, Config, Result);
}

/**************************************************/
/*  公共 API — 检测回调                            */
/**************************************************/

NTSTATUS
PesSetDetectionCallback(
    _In_opt_ PES_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID                  Context
    )
{
    AcquireSRWLockExclusive(&g_Lock);
    g_Callback = Callback;
    g_CallbackCtx = Context;
    ReleaseSRWLockExclusive(&g_Lock);
    return STATUS_SUCCESS;
}

/**************************************************/
/*  公共 API — 统计                               */
/**************************************************/

NTSTATUS
PesGetStatistics(
    _Out_ PPES_STATS Stats
    )
{
    if (!Stats) return STATUS_INVALID_PARAMETER;
    AcquireSRWLockShared(&g_Lock);
    RtlCopyMemory(Stats, &g_Stats, sizeof(g_Stats));
    ReleaseSRWLockShared(&g_Lock);
    return STATUS_SUCCESS;
}

/**************************************************/
/*  公共 API — 重置统计                            */
/**************************************************/

NTSTATUS
PesResetStatistics(
    VOID
    )
{
    AcquireSRWLockExclusive(&g_Lock);
    RtlZeroMemory(&g_Stats, sizeof(g_Stats));
    ReleaseSRWLockExclusive(&g_Lock);
    return STATUS_SUCCESS;
}

/**************************************************/
/*  文件结束 — ProcessEvasionDetector.c           */
/**************************************************/