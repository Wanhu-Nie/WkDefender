/**************************************************/
/*  WkDefender Agent — 沙箱逃逸检测引擎             */
/*  AntiEvasio / SandboxEvasionDetector.c          */
/*                                                  */
/*  迁移自 ShadowStrike SandboxEvasionDetector      */
/*  (.hpp 2672行 + .cpp 4043行)。纯 C 实现。         */
/*                                                  */
/*  架构：                                           */
/*    类型A：主机上下文收集（用于行为评分校准）        */
/*      - AnalyzeHardware / AnalyzeWearAndTear       */
/*      - AnalyzeEnvironment / ScanArtifacts         */
/*      - AnalyzeHumanInteraction                    */
/*      - ScanSystem 两阶段编排（上下文+行为）        */
/*    类型B：目标进程沙箱逃避行为分析（主要检测）      */
/*      - 导入分类 / 内存字符串 / 时序代码模式        */
/*                                                  */
/*  降级决策（详见头文件）：                          */
/*    - PhantomDisassembler   → 字节模式扫描          */
/*    - PEParser              → 内联 PE 导入解析      */
/*    - asm 时序函数          → 全部省略              */
/*    - ThreadPool/WMI/COM    → 省略                  */
/*                                                  */
/*  编码：UTF-8 with BOM（铁律）                     */
/**************************************************/

#include "SandboxEvasionDetector.h"

#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
#include <math.h>
#include <intrin.h>

#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>
#include <iphlpapi.h>
#include <mmsystem.h>   /* waveOutGetNumDevs */

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "psapi.lib")

/* M_PI 兜底（MSVC 不保证定义） */
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define SED_TAG 'deSx'

/**************************************************/
/*          内部工具宏                             */
/**************************************************/

#define SED_ARRAY_COUNT(a)  (sizeof(a) / sizeof((a)[0]))

#define SED_CLAMP_FLOAT(v, lo, hi) \
    (((v) < (lo)) ? (lo) : (((v) > (hi)) ? (hi) : (v)))

#define SED_CLAMP_ULONG(v, lo, hi) \
    (((v) < (lo)) ? (lo) : (((v) > (hi)) ? (hi) : (v)))

/* 宽字符串安全拷贝（带 NUL 终止） */
#define SED_WCOPY(dst, src, cap) \
    do { \
        if ((src) != NULL) { \
            (void)wcsncpy_s((dst), (cap), (src), _TRUNCATE); \
        } else { \
            (dst)[0] = L'\0'; \
        } \
    } while (0)

#define SED_ACOPY(dst, src, cap) \
    do { \
        if ((src) != NULL) { \
            (void)strncpy_s((dst), (cap), (src), _TRUNCATE); \
        } else { \
            (dst)[0] = '\0'; \
        } \
    } while (0)

/* 将 FILETIME 字节换算为秒（低32位加法，保持 64 位精度） */
#define SED_FILE_TIME_SECONDS(ft) \
    (((ULONGLONG)(ft).dwHighDateTime << 32) | (ft).dwLowDateTime)

/**************************************************/
/*          数据表：BIOS/厂商字符串                */
/**************************************************/

/* 已知 VM 沙箱 BIOS 字符串（score += 10） */
/* 注意：已按源移除 VMWARE/VIRTUAL/XEN 等合法项 */
static const WCHAR* const g_SedVmBiosStrings[] = {
    L"VBOX",        /* VirtualBox（常用于沙箱） */
    L"QEMU",        /* QEMU（Cuckoo/CAPE 常用） */
    L"BOCHS",       /* Bochs 模拟器（分析工具） */
    L"INNOTEK"      /* 旧 VirtualBox 标识 */
};

/* 确定性沙箱环境字符串（score += 40） */
static const WCHAR* const g_SedDefinitiveSandboxStrings[] = {
    L"CUCKOO",      /* Cuckoo Sandbox */
    L"CAPE",        /* CAPE Sandbox */
    L"JOEBOX",      /* Joe Sandbox */
    L"ANYRUN",      /* ANY.RUN */
    L"VMRAY",       /* VMRay */
    L"TRIA.GE",     /* Triage 沙箱 */
    L"HYBRID",      /* Hybrid Analysis */
    L"SANDBOX"      /* 通用沙箱标识 */
};

/* 已知 VM/沙箱 MAC OUI 前缀（前 3 字节） */
static const UCHAR g_SedVmMacPrefixes[][3] = {
    { 0x00, 0x05, 0x69 },  /* VMware */
    { 0x00, 0x0C, 0x29 },  /* VMware */
    { 0x00, 0x1C, 0x14 },  /* VMware */
    { 0x00, 0x50, 0x56 },  /* VMware */
    { 0x08, 0x00, 0x27 },  /* VirtualBox */
    { 0x52, 0x54, 0x00 },  /* QEMU/KVM */
    { 0x00, 0x16, 0x3E },  /* Xen */
    { 0x00, 0x1C, 0x42 },  /* Parallels */
    { 0x00, 0x03, 0xFF },  /* Microsoft Hyper-V */
    { 0x00, 0x15, 0x5D }   /* Microsoft Hyper-V */
};

/* 沙箱特征用户名（小写，精确匹配） */
static const WCHAR* const g_SedSandboxUsernames[] = {
    L"sandbox", L"virus", L"malware", L"maltest", L"test", L"sample",
    L"vboxuser", L"vmware", L"user", L"admin", L"administrator",
    L"currentuser", L"cuckoo", L"wilbert", L"analysis", L"analyst"
};

/* 沙箱特征计算机名（大写，包含匹配） */
static const WCHAR* const g_SedSandboxComputernames[] = {
    L"SANDBOX", L"VIRUS", L"MALWARE", L"MALTEST", L"TEST", L"SAMPLE",
    L"TEQUILABOOMBOOM", L"PC", L"DESKTOP", L"JOHN-PC", L"ANALYSIS",
    L"WIN7-PC", L"WIN10-PC", L"CUCKOO", L"VMWARE", L"VBOX"
};

/**************************************************/
/*          数据表：类型A 沙箱 DLL 工件            */
/**************************************************/

typedef struct _SED_SANDBOX_DLL_ENTRY {
    PCWSTR     Name;
    SED_PRODUCT Product;   /* SED_PRODUCT_Unknown = 不映射产品 */
} SED_SANDBOX_DLL_ENTRY;

/* 15 项（含 GetModuleHandleW 检查列表） */
static const SED_SANDBOX_DLL_ENTRY g_SedSandboxDlls[] = {
    { L"SbieDll.dll",       SED_PRODUCT_Sandboxie       },
    { L"cuckoomon.dll",     SED_PRODUCT_Cuckoo          },
    { L"snxhk.dll",         SED_PRODUCT_AvastDeepScreen },
    { L"vmray_api.dll",     SED_PRODUCT_VMRay           },
    { L"joeboxcontrol.dll", SED_PRODUCT_JoeSandbox      },
    { L"apimonitor.dll",    SED_PRODUCT_Unknown         },
    { L"guard32.dll",       SED_PRODUCT_ComodoSandbox   },
    { L"guard64.dll",       SED_PRODUCT_ComodoSandbox   },
    { L"wpepro.dll",        SED_PRODUCT_Unknown         },
    { L"cmdvrt32.dll",      SED_PRODUCT_Unknown         },  /* Comodo */
    { L"cmdvrt64.dll",      SED_PRODUCT_Unknown         },  /* Comodo */
    { L"pstorec.dll",       SED_PRODUCT_Unknown         },  /* SunBelt */
    { L"dir_watch.dll",     SED_PRODUCT_Unknown         },
    { L"wpespy.dll",        SED_PRODUCT_Unknown         },  /* WPE Pro */
    { L"dbghelp.dll",       SED_PRODUCT_Unknown         }   /* 分析环境常见 */
};

/**************************************************/
/*          数据表：类型A 沙箱进程工件             */
/**************************************************/

typedef struct _SED_SANDBOX_PROC_ENTRY {
    PCWSTR    NameLower;       /* 小写名称（比较时进程名同样转小写） */
    BOOLEAN   IsAnalysisTool;  /* 归入 analysisToolProcesses */
} SED_SANDBOX_PROC_ENTRY;

/* 33 项（源 35 项，去除 joeboxserver/joeboxcontrol 重复笔误） */
static const SED_SANDBOX_PROC_ENTRY g_SedSandboxProcesses[] = {
    { L"joeboxserver.exe",         FALSE },
    { L"joeboxcontrol.exe",        FALSE },
    { L"sbiectrl.exe",             FALSE },
    { L"sbiesvc.exe",              FALSE },
    { L"vmray-service.exe",        FALSE },
    { L"windowssandboxclient.exe", FALSE },
    { L"wireshark.exe",            TRUE  },
    { L"procmon.exe",              TRUE  },
    { L"procmon64.exe",            TRUE  },
    { L"fiddler.exe",              TRUE  },
    { L"ollydbg.exe",              TRUE  },
    { L"x64dbg.exe",               TRUE  },
    { L"x32dbg.exe",               TRUE  },
    { L"ida.exe",                  TRUE  },
    { L"ida64.exe",                TRUE  },
    { L"regmon.exe",               FALSE },
    { L"filemon.exe",              FALSE },
    { L"autoruns.exe",             FALSE },
    { L"tcpview.exe",              FALSE },
    { L"idaq.exe",                 FALSE },
    { L"idaq64.exe",               FALSE },
    { L"immunitydebugger.exe",     FALSE },
    { L"windbg.exe",               FALSE },
    { L"dumpcap.exe",              FALSE },
    { L"hookexplorer.exe",         FALSE },
    { L"importrec.exe",            FALSE },
    { L"petools.exe",              FALSE },
    { L"lordpe.exe",               FALSE },
    { L"sysinspector.exe",         FALSE },
    { L"proc_analyzer.exe",        FALSE },
    { L"sysanalyzer.exe",          FALSE },
    { L"sniff_hit.exe",            FALSE },
    { L"resourcehacker.exe",       FALSE }
};

/**************************************************/
/*          数据表：类型A 沙箱互斥体工件           */
/**************************************************/

/* 6 项 */
static const WCHAR* const g_SedSandboxMutexes[] = {
    L"Sandboxie_SingleInstanceMutex_Control",
    L"CuckooMutex",
    L"JoeBoxMutex",
    L"VMRayMutex",
    L"Frz_State",        /* Deep Freeze */
    L"SBIE_BOXED_ServiceInitComplete_Mutex"   /* Sandboxie */
};

/**************************************************/
/*          数据表：类型A 沙箱注册表键             */
/**************************************************/

typedef struct _SED_REGKEY_ENTRY {
    HKEY   Hive;
    PCWSTR Path;
} SED_REGKEY_ENTRY;

/* 14 项 */
static const SED_REGKEY_ENTRY g_SedSandboxRegistryKeys[] = {
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters" },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools" },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Oracle\\VirtualBox Guest Additions" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmci" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmmouse" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmrawdsk" },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wine" },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Cuckoo" },
    { HKEY_CURRENT_USER,  L"SOFTWARE\\Cuckoo" }
};

/**************************************************/
/*          数据表：类型A 沙箱文件                */
/**************************************************/

/* 14 项 */
static const WCHAR* const g_SedSandboxFiles[] = {
    L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
    L"C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
    L"C:\\Windows\\System32\\drivers\\VBoxSF.sys",
    L"C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
    L"C:\\Windows\\System32\\vboxdisp.dll",
    L"C:\\Windows\\System32\\vboxhook.dll",
    L"C:\\Windows\\System32\\vboxogl.dll",
    L"C:\\Windows\\System32\\drivers\\vmmouse.sys",
    L"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
    L"C:\\Windows\\System32\\drivers\\vm3dmp.sys",
    L"C:\\agent\\agent.py",          /* Cuckoo */
    L"C:\\cuckoo\\agent\\agent.py",  /* Cuckoo */
    L"C:\\sandbox\\starter.exe",
    L"C:\\analysis\\analyzer.py"
};

/**************************************************/
/*          数据表：类型A 沙箱服务                */
/**************************************************/

typedef struct _SED_SERVICE_ENTRY {
    PCWSTR     Name;      /* 服务名（大小写不敏感） */
    SED_PRODUCT Product;
} SED_SERVICE_ENTRY;

/* 4 项（CheckServices） */
static const SED_SERVICE_ENTRY g_SedSandboxServices[] = {
    { L"SbieSvc",       SED_PRODUCT_Sandboxie       },
    { L"VBoxService",   SED_PRODUCT_GenericAnalysis },
    { L"VMTools",       SED_PRODUCT_GenericAnalysis },
    { L"vmicheartbeat", SED_PRODUCT_GenericAnalysis }
};

/**************************************************/
/*          数据表：API 钩子检测目标               */
/**************************************************/

typedef struct _SED_CRITICAL_API {
    PCSTR Module;     /* "ntdll.dll" / "kernel32.dll" */
    PCSTR Function;
} SED_CRITICAL_API;

/* 17 项（CheckAPIHooks） */
static const SED_CRITICAL_API g_SedCriticalApis[] = {
    { "ntdll.dll",    "NtQueryInformationProcess" },
    { "ntdll.dll",    "NtQuerySystemInformation" },
    { "ntdll.dll",    "NtCreateFile" },
    { "ntdll.dll",    "NtOpenProcess" },
    { "ntdll.dll",    "NtQueryVirtualMemory" },
    { "ntdll.dll",    "NtReadVirtualMemory" },
    { "ntdll.dll",    "NtWriteVirtualMemory" },
    { "ntdll.dll",    "NtDelayExecution" },
    { "kernel32.dll", "IsDebuggerPresent" },
    { "kernel32.dll", "GetTickCount" },
    { "kernel32.dll", "GetTickCount64" },
    { "kernel32.dll", "QueryPerformanceCounter" },
    { "kernel32.dll", "GetSystemTimeAsFileTime" },
    { "kernel32.dll", "CreateFileW" },
    { "kernel32.dll", "ReadFile" },
    { "kernel32.dll", "VirtualAlloc" },
    { "kernel32.dll", "VirtualProtect" }
};

/**************************************************/
/*          数据表：类型B 导入分类 API 簇          */
/**************************************************/

/* 硬件指纹化 (10) */
static const char* const g_SedHardwareApis[] = {
    "GlobalMemoryStatusEx", "GetSystemInfo", "GetNativeSystemInfo",
    "GetDiskFreeSpaceExW", "GetDiskFreeSpaceExA",
    "GetLogicalProcessorInformation", "GetLogicalProcessorInformationEx",
    "SetupDiGetClassDevsW", "SetupDiEnumDeviceInfo",
    "GetDeviceCaps"
};

/* 时序 API (6) */
static const char* const g_SedTimingApis[] = {
    "GetTickCount", "GetTickCount64",
    "QueryPerformanceCounter", "QueryPerformanceFrequency",
    "NtQuerySystemTime", "GetSystemTimeAsFileTime"
};

/* 环境查询 (11) */
static const char* const g_SedEnvironmentApis[] = {
    "GetSystemMetrics", "EnumDisplayDevicesW", "EnumDisplaySettingsW",
    "GetComputerNameW", "GetComputerNameA",
    "GetUserNameW", "GetUserNameA",
    "GetTimeZoneInformation", "GetLocaleInfoW",
    "GetUserDefaultLCID", "GetSystemDefaultLCID"
};

/* 工件检查 (12) */
static const char* const g_SedArtifactApis[] = {
    "GetModuleHandleW", "GetModuleHandleA",
    "OpenMutexW", "OpenMutexA",
    "CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW",
    "EnumServicesStatusExW",
    "RegOpenKeyExW", "RegQueryValueExW",
    "FindFirstFileW", "FindNextFileW"
};

/* 人机交互检查 (8) */
static const char* const g_SedHumanInteractionApis[] = {
    "GetCursorPos", "GetAsyncKeyState", "GetKeyState",
    "GetLastInputInfo", "GetForegroundWindow",
    "GetWindowTextW", "EnumWindows",
    "SetWindowsHookExW"
};

/**************************************************/
/*          数据表：类型B 内存字符串模式           */
/**************************************************/

/* 沙箱 DLL 名 (12) */
static const WCHAR* const g_SedStringDlls[] = {
    L"sbiedll.dll", L"api_log.dll", L"dir_watch.dll",
    L"pstorec.dll", L"vmcheck.dll", L"wpespy.dll",
    L"SbieDll.dll", L"SxIn.dll", L"Sf2.dll",
    L"snxhk.dll", L"cmdvrt32.dll", L"cmdvrt64.dll"
};

/* 沙箱进程名 (20) */
static const WCHAR* const g_SedStringProcesses[] = {
    L"vmsrvc.exe", L"vboxservice.exe", L"vboxtray.exe",
    L"vmtoolsd.exe", L"vmwaretray.exe", L"vmwareuser.exe",
    L"wireshark.exe", L"procmon.exe", L"procmon64.exe",
    L"ollydbg.exe", L"x64dbg.exe", L"x32dbg.exe",
    L"idaq.exe", L"idaq64.exe", L"pestudio.exe",
    L"regmon.exe", L"filemon.exe", L"autoruns.exe",
    L"agent.py", L"analyzer.py"
};

/* 沙箱互斥体名 (7) */
static const WCHAR* const g_SedStringMutexes[] = {
    L"CuckooMutex", L"SbieSandbox", L"SBIE_BOXED_",
    L"JoeBoxMutex", L"Anubis_Sandbox",
    L"ThreatExpert", L"HookSwitchMutex"
};

/* VM 厂商字符串 (11) */
static const WCHAR* const g_SedStringVmVendors[] = {
    L"VMware", L"VirtualBox", L"QEMU", L"Xen",
    L"Virtual HD", L"VBOX HARDDISK",
    L"VMware Virtual", L"VMWARE", L"innotek GmbH",
    L"Oracle Corporation", L"Parallels"
};

/* 沙箱注册表路径 (8) */
static const WCHAR* const g_SedStringRegistryPaths[] = {
    L"SOFTWARE\\Oracle\\VirtualBox",
    L"SOFTWARE\\VMware, Inc.\\VMware Tools",
    L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
    L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
    L"SYSTEM\\CurrentControlSet\\Services\\vmci",
    L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs",
    L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0",
    L"HARDWARE\\Description\\System\\SystemBiosVersion"
};

/* 快速扫描短路清单（QuickScan） */
static const WCHAR* const g_SedQuickDlls[] = {
    L"SbieDll.dll", L"cuckoomon.dll", L"snxhk.dll",
    L"vmray_api.dll", L"joeboxcontrol.dll"
};

static const WCHAR* const g_SedQuickMutexes[] = {
    L"Sandboxie_SingleInstanceMutex_Control",
    L"CuckooMutex", L"JoeBoxMutex", L"VMRayMutex"
};

static const WCHAR* const g_SedQuickProcesses[] = {
    L"sbietrl.exe", L"joeboxserver.exe", L"windowssandboxclient.exe"
};

/* 钩子检测：API 前序字节扫描上限 */
#define SED_MAX_PROLOGUE_BYTES 32

/* 内存字符串扫描常量 */
#define SED_SCAN_BUFFER_SIZE        (64 * 1024)
#define SED_MAX_STRING_FINDINGS     200

/* 目录文件计数上限（防 DoS） */
#define SED_MAX_FILE_COUNT          100000

/* 类型B 区域扫描上限 */
#define SED_MAX_REGION_SCAN_BYTES   (1024 * 1024)

/* 类型B 代码节扫描上限 */
#define SED_MAX_SECTION_SCAN_BYTES  (1024 * 1024)

/* 类型B 最大模块枚举数 */
#define SED_MAX_MODULES             256

/**************************************************/
/*          全局状态                               */
/**************************************************/

#define SED_MAX_CALLBACKS 16

typedef struct _SED_CALLBACK_ENTRY {
    SED_DETECTION_CALLBACK Callback;
    PVOID                  Context;
    ULONG64                Id;
    BOOLEAN                InUse;
} SED_CALLBACK_ENTRY;

typedef struct _SED_GLOBAL_STATE {
    /* 生命周期 */
    volatile LONG Initialized;
    volatile LONG ShutdownRequested;

    /* 配置 */
    SED_CONFIG Config;
    SRWLOCK    ConfigLock;

    /* 结果缓存 */
    struct {
        SED_RESULT  Result;
        ULONGLONG   TimestampFileTime;
        BOOLEAN     Valid;
    } Cache;
    SRWLOCK    CacheLock;

    /* 硬件画像缓存 */
    struct {
        SED_HARDWARE_PROFILE Profile;
        ULONGLONG            TimestampFileTime;
        BOOLEAN              Valid;
    } HwCache;
    SRWLOCK    HwCacheLock;

    /* 系统扫描回调 */
    SED_CALLBACK_ENTRY Callbacks[SED_MAX_CALLBACKS];
    SRWLOCK            CallbackLock;
    volatile LONG64    CallbackIdCounter;

    /* 进程分析回调（受 ConfigLock 保护，与源一致） */
    SED_PROCESS_CALLBACK ProcessCallback;
    PVOID                ProcessCallbackContext;

    /* 统计 */
    SED_STATS Stats;
} SED_GLOBAL_STATE;

static SED_GLOBAL_STATE g_SedState;

/* 单线程伪初始化：保证 SRWLOCK 等零值正确 */
static void SedInitGlobalState(void)
{
    RtlZeroMemory(&g_SedState, sizeof(g_SedState));
    InitializeSRWLock(&g_SedState.ConfigLock);
    InitializeSRWLock(&g_SedState.CacheLock);
    InitializeSRWLock(&g_SedState.HwCacheLock);
    InitializeSRWLock(&g_SedState.CallbackLock);
}

static BOOLEAN SedStateInitialized(void)
{
    return (InterlockedCompareExchange(&g_SedState.Initialized, 0, 0) != 0);
}

/**************************************************/
/*          内部工具：目录文件计数                 */
/**************************************************/

/* 非递归统计目录内文件数（上限 SED_MAX_FILE_COUNT 防 DoS） */
static SIZE_T SedCountFilesInDirectory(PCWSTR DirPath)
{
    SIZE_T count = 0;
    WCHAR searchPath[SED_MAX_PATH];
    WIN32_FIND_DATAW findData;
    HANDLE hFind;
    SIZE_T pathLen;

    if (DirPath == NULL || DirPath[0] == L'\0') {
        return 0;
    }

    pathLen = wcslen(DirPath);
    if (pathLen >= (SED_MAX_PATH - 3)) {
        return 0;
    }

    wcscpy_s(searchPath, SED_MAX_PATH, DirPath);
    if (searchPath[pathLen - 1] != L'\\' && searchPath[pathLen - 1] != L'/') {
        searchPath[pathLen] = L'\\';
        searchPath[pathLen + 1] = L'*';
        searchPath[pathLen + 2] = L'\0';
    } else {
        searchPath[pathLen] = L'*';
        searchPath[pathLen + 1] = L'\0';
    }

    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return 0;
    }

    do {
        /* 跳过 . 和 .. */
        if (findData.cFileName[0] == L'.' &&
            (findData.cFileName[1] == L'\0' ||
             (findData.cFileName[1] == L'.' && findData.cFileName[2] == L'\0'))) {
            continue;
        }

        /* 仅统计文件 */
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            ++count;
        }

        if (count >= SED_MAX_FILE_COUNT) {
            break;
        }

    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
    return count;
}

/**************************************************/
/*          内部工具：注册表字符串读取             */
/**************************************************/

/* 安全读取 REG_SZ/REG_EXPAND_SZ：验证类型、钳制大小、强制 NUL 终止 */
static BOOLEAN SedReadRegSz(HKEY hKey, PCWSTR Name, PWSTR Out, SIZE_T OutChars)
{
    WCHAR buffer[512];
    DWORD bufferSize = sizeof(buffer) - sizeof(WCHAR);   /* 保留 NUL */
    DWORD valueType = 0;
    SIZE_T wcount;
    LSTATUS status;

    if (Out == NULL || OutChars == 0) {
        return FALSE;
    }
    Out[0] = L'\0';

    status = RegQueryValueExW(hKey, Name, NULL, &valueType,
                              (LPBYTE)buffer, &bufferSize);
    if (status != ERROR_SUCCESS) {
        return FALSE;
    }
    if (valueType != REG_SZ && valueType != REG_EXPAND_SZ) {
        return FALSE;
    }

    wcount = bufferSize / sizeof(WCHAR);
    if (wcount > (sizeof(buffer) / sizeof(WCHAR)) - 1) {
        wcount = (sizeof(buffer) / sizeof(WCHAR)) - 1;
    }
    buffer[wcount] = L'\0';

    if (wcount >= OutChars) {
        wcount = OutChars - 1;
    }
    memcpy(Out, buffer, wcount * sizeof(WCHAR));
    Out[wcount] = L'\0';
    return TRUE;
}

/**************************************************/
/*          内部工具：EMA 统计更新                 */
/**************************************************/

/* alpha = 1/8：next = prev - (prev>>3) + (val>>3)，CAS 循环防竞争 */
static void SedUpdateEma(volatile LONG64* pAvg, ULONGLONG Value)
{
    LONG64 prev = InterlockedCompareExchange64(pAvg, 0, 0);
    LONG64 current;
    for (;;) {
        LONG64 next = (prev == 0)
            ? (LONG64)Value
            : prev - (prev >> 3) + ((LONG64)Value >> 3);
        current = InterlockedCompareExchange64(pAvg, next, prev);
        if (current == prev) {
            break;
        }
        prev = current;
    }
}

/* 记录检测产品统计（索引=产品值，源行为） */
static void SedRecordProductDetection(SED_PRODUCT Product)
{
    if (Product != SED_PRODUCT_Unknown &&
        (ULONG)Product < SED_ARRAY_COUNT(g_SedState.Stats.DetectionsByProduct)) {
        InterlockedIncrement64(&g_SedState.Stats.DetectionsByProduct[(ULONG)Product]);
    }
}

/**************************************************/
/*          内部工具：宽字符串小写化               */
/**************************************************/

static void SedToLowerW(PWSTR Str)
{
    if (Str == NULL) {
        return;
    }
    for (; *Str != L'\0'; ++Str) {
        *Str = (WCHAR)towlower(*Str);
    }
}

/**************************************************/
/*          内部：AddIndicator                     */
/**************************************************/

static void SedAddIndicator(
    PSED_RESULT Result,
    SED_CHECK_TYPE CheckType,
    SED_INDICATOR_CATEGORY Category,
    SED_SEVERITY Severity,
    FLOAT Weight,
    FLOAT Confidence,
    PCWSTR Description,
    PCWSTR TechnicalDetails,
    PCWSTR ObservedValue,
    PCWSTR ExpectedValue,
    SED_PRODUCT SuspectedProduct,
    BOOLEAN IsConclusive)
{
    PSED_INDICATOR indicator;
    FILETIME now;

    if (Result == NULL) {
        return;
    }
    if (Result->IndicatorCount >= SED_MAX_INDICATORS) {
        return;   /* 超限跳过（源行为：记 WARN 后跳过） */
    }

    indicator = &Result->Indicators[Result->IndicatorCount];
    RtlZeroMemory(indicator, sizeof(*indicator));

    indicator->CheckType = CheckType;
    indicator->Category = Category;
    indicator->Severity = Severity;
    indicator->Weight = Weight;
    indicator->Confidence = Confidence;
    indicator->SuspectedProduct = SuspectedProduct;
    indicator->IsConclusive = IsConclusive;

    SED_WCOPY(indicator->Description, Description, SED_ARRAY_COUNT(indicator->Description));
    SED_WCOPY(indicator->TechnicalDetails, TechnicalDetails, SED_ARRAY_COUNT(indicator->TechnicalDetails));
    SED_WCOPY(indicator->ObservedValue, ObservedValue, SED_ARRAY_COUNT(indicator->ObservedValue));
    SED_WCOPY(indicator->ExpectedValue, ExpectedValue, SED_ARRAY_COUNT(indicator->ExpectedValue));
    SED_ACOPY(indicator->MitreId, SedCheckTypeMitreId(CheckType), SED_ARRAY_COUNT(indicator->MitreId));

    GetSystemTimeAsFileTime(&now);
    indicator->DetectionTime = SED_FILE_TIME_SECONDS(now);

    ++Result->IndicatorCount;
}

/**************************************************/
/*          内部：事件回调调用                     */
/**************************************************/

/* 快照后锁外调用（防死锁，源模式） */
static void SedInvokeCallbacks(const SED_RESULT* Result)
{
    SED_CALLBACK_ENTRY snapshot[SED_MAX_CALLBACKS];
    ULONG snapshotCount = 0;
    ULONG i;

    if (Result == NULL) {
        return;
    }

    AcquireSRWLockShared(&g_SedState.CallbackLock);
    for (i = 0; i < SED_MAX_CALLBACKS; ++i) {
        if (g_SedState.Callbacks[i].InUse &&
            g_SedState.Callbacks[i].Callback != NULL) {
            snapshot[snapshotCount++] = g_SedState.Callbacks[i];
        }
    }
    ReleaseSRWLockShared(&g_SedState.CallbackLock);

    for (i = 0; i < snapshotCount; ++i) {
        snapshot[i].Callback(Result, snapshot[i].Context);
    }
}

/**************************************************/
/*          公共 API — 生命周期                    */
/**************************************************/

/*++

SedInitialize

    初始化沙箱逃逸检测引擎。幂等：已初始化时直接返回成功。
    使用默认配置（Config 为 NULL）或调用者提供的配置。

--*/
_Use_decl_annotations_
NTSTATUS
SedInitialize(
    _In_opt_ PSED_CONFIG Config
    )
{
    SED_CONFIG defaultConfig;

    if (SedStateInitialized()) {
        return STATUS_SUCCESS;
    }

    SedInitGlobalState();

    if (Config != NULL) {
        g_SedState.Config = *Config;
    } else {
        SedApplyDefaultConfig(&defaultConfig);
        g_SedState.Config = defaultConfig;
    }

    InterlockedExchange(&g_SedState.ShutdownRequested, 0);
    InterlockedExchange(&g_SedState.Initialized, 1);
    return STATUS_SUCCESS;
}

/*++

SedShutdown

    关闭检测引擎，清理回调与缓存。

--*/
_Use_decl_annotations_
VOID
SedShutdown(
    VOID
    )
{
    ULONG i;
    SED_GLOBAL_STATE empty;

    if (!SedStateInitialized()) {
        return;
    }

    InterlockedExchange(&g_SedState.ShutdownRequested, 1);

    /* 清理回调 */
    AcquireSRWLockExclusive(&g_SedState.CallbackLock);
    for (i = 0; i < SED_MAX_CALLBACKS; ++i) {
        g_SedState.Callbacks[i].Callback = NULL;
        g_SedState.Callbacks[i].Context = NULL;
        g_SedState.Callbacks[i].InUse = FALSE;
    }
    ReleaseSRWLockExclusive(&g_SedState.CallbackLock);

    /* 清理进程回调（受 ConfigLock 保护） */
    AcquireSRWLockExclusive(&g_SedState.ConfigLock);
    g_SedState.ProcessCallback = NULL;
    g_SedState.ProcessCallbackContext = NULL;
    ReleaseSRWLockExclusive(&g_SedState.ConfigLock);

    /* 清理缓存 */
    AcquireSRWLockExclusive(&g_SedState.CacheLock);
    g_SedState.Cache.Valid = FALSE;
    ReleaseSRWLockExclusive(&g_SedState.CacheLock);

    AcquireSRWLockExclusive(&g_SedState.HwCacheLock);
    g_SedState.HwCache.Valid = FALSE;
    ReleaseSRWLockExclusive(&g_SedState.HwCacheLock);

    RtlZeroMemory(&empty, sizeof(empty));
    g_SedState.Config = empty.Config;
    InterlockedExchange(&g_SedState.Initialized, 0);
}

/*++

SedIsInitialized

    查询引擎是否已初始化。

--*/
_Use_decl_annotations_
BOOLEAN
SedIsInitialized(
    VOID
    )
{
    return SedStateInitialized();
}

/*++

SedUpdateConfig

    运行时更新检测配置（受 ConfigLock 保护）。

--*/
_Use_decl_annotations_
VOID
SedUpdateConfig(
    _In_ PSED_CONFIG Config
    )
{
    if (Config == NULL) {
        return;
    }

    AcquireSRWLockExclusive(&g_SedState.ConfigLock);
    g_SedState.Config = *Config;
    ReleaseSRWLockExclusive(&g_SedState.ConfigLock);
}

/*++

SedGetConfig

    获取当前配置副本。

--*/
_Use_decl_annotations_
VOID
SedGetConfig(
    _Out_ PSED_CONFIG Config
    )
{
    if (Config == NULL) {
        return;
    }

    AcquireSRWLockShared(&g_SedState.ConfigLock);
    *Config = g_SedState.Config;
    ReleaseSRWLockShared(&g_SedState.ConfigLock);
}

/*++

SedApplyDefaultConfig

    将默认值写入配置结构（运行时字段赋值，
    规避 MSVC C 对复杂初始化器的限制）。

--*/
_Use_decl_annotations_
VOID
SedApplyDefaultConfig(
    _Out_ PSED_CONFIG Config
    )
{
    if (Config == NULL) {
        return;
    }

    RtlZeroMemory(Config, sizeof(*Config));

    Config->Enabled = TRUE;
    Config->ProbabilityThreshold = SED_PROBABILITY_THRESHOLD;
    Config->EnableCache = TRUE;
    Config->CacheTtlMinutes = SED_CACHE_TTL_MINUTES;

    Config->CheckHardware = TRUE;
    Config->CheckWearAndTear = TRUE;
    Config->CheckHumanInteraction = TRUE;
    Config->CheckEnvironment = TRUE;
    Config->CheckArtifacts = TRUE;
    Config->CheckTiming = TRUE;
    Config->CheckNetwork = TRUE;
    Config->CheckFileSystem = TRUE;

    Config->MinRam = SED_MIN_RAM_BYTES;
    Config->MinCpuCores = SED_MIN_CPU_CORES;
    Config->MinDiskSize = SED_MIN_DISK_BYTES;
    Config->MinUptime = SED_MIN_UPTIME_MS;
    Config->MinInstallAgeDays = SED_MIN_INSTALL_AGE_DAYS;
    Config->MinRecentDocuments = SED_MIN_RECENT_DOCUMENTS;
    Config->MinInstalledPrograms = SED_MIN_INSTALLED_PROGRAMS;
    Config->MinBrowserHistory = SED_MIN_BROWSER_HISTORY;
    Config->HumanInteractionMonitorMs = SED_DEFAULT_INTERACTION_MS;
    Config->MinMouseMovements = SED_MIN_MOUSE_MOVEMENTS;
    Config->MinMouseDistance = SED_MIN_MOUSE_DISTANCE;
    Config->SuspiciousScreenWidth = SED_SUSPICIOUS_SCREEN_WIDTH;
    Config->SuspiciousScreenHeight = SED_SUSPICIOUS_SCREEN_HEIGHT;

    Config->HardwareWeight = 1.5f;
    Config->WearAndTearWeight = 1.0f;
    Config->HumanInteractionWeight = 2.0f;
    Config->EnvironmentWeight = 1.0f;
    Config->ArtifactWeight = 3.0f;
    Config->TimingWeight = 1.2f;
    Config->NetworkWeight = 0.8f;
}

/**************************************************/
/*          公共 API — 回调/统计/缓存              */
/**************************************************/

/*++

SedRegisterCallback

    注册系统扫描完成回调。返回回调 ID（0 = 失败/表满）。

--*/
_Use_decl_annotations_
ULONG64
SedRegisterCallback(
    _In_ SED_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID              Context
    )
{
    ULONG64 id;
    ULONG i;

    if (Callback == NULL) {
        return 0;
    }

    id = (ULONG64)InterlockedIncrement64(&g_SedState.CallbackIdCounter);

    AcquireSRWLockExclusive(&g_SedState.CallbackLock);
    for (i = 0; i < SED_MAX_CALLBACKS; ++i) {
        if (!g_SedState.Callbacks[i].InUse) {
            g_SedState.Callbacks[i].Callback = Callback;
            g_SedState.Callbacks[i].Context = Context;
            g_SedState.Callbacks[i].Id = id;
            g_SedState.Callbacks[i].InUse = TRUE;
            ReleaseSRWLockExclusive(&g_SedState.CallbackLock);
            return id;
        }
    }
    ReleaseSRWLockExclusive(&g_SedState.CallbackLock);

    return 0;   /* 表满 */
}

/*++

SedUnregisterCallback

    按 ID 注销回调。

--*/
_Use_decl_annotations_
BOOLEAN
SedUnregisterCallback(
    _In_ ULONG64 CallbackId
    )
{
    ULONG i;
    BOOLEAN found = FALSE;

    AcquireSRWLockExclusive(&g_SedState.CallbackLock);
    for (i = 0; i < SED_MAX_CALLBACKS; ++i) {
        if (g_SedState.Callbacks[i].InUse &&
            g_SedState.Callbacks[i].Id == CallbackId) {
            g_SedState.Callbacks[i].Callback = NULL;
            g_SedState.Callbacks[i].Context = NULL;
            g_SedState.Callbacks[i].InUse = FALSE;
            found = TRUE;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_SedState.CallbackLock);

    return found;
}

/*++

SedGetStatistics

    获取统计快照（原子字段）。

--*/
_Use_decl_annotations_
NTSTATUS
SedGetStatistics(
    _Out_ PSED_STATS Stats
    )
{
    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(*Stats));
    Stats->TotalScans = InterlockedCompareExchange64(&g_SedState.Stats.TotalScans, 0, 0);
    Stats->SandboxesDetected = InterlockedCompareExchange64(&g_SedState.Stats.SandboxesDetected, 0, 0);
    Stats->DefinitiveDetections = InterlockedCompareExchange64(&g_SedState.Stats.DefinitiveDetections, 0, 0);
    Stats->HumanInteractionChecks = InterlockedCompareExchange64(&g_SedState.Stats.HumanInteractionChecks, 0, 0);
    Stats->CacheHits = InterlockedCompareExchange64(&g_SedState.Stats.CacheHits, 0, 0);
    Stats->CacheMisses = InterlockedCompareExchange64(&g_SedState.Stats.CacheMisses, 0, 0);
    Stats->AvgAnalysisDurationUs = InterlockedCompareExchange64(&g_SedState.Stats.AvgAnalysisDurationUs, 0, 0);
    memcpy(Stats->DetectionsByProduct, g_SedState.Stats.DetectionsByProduct,
           sizeof(Stats->DetectionsByProduct));

    return STATUS_SUCCESS;
}

/*++

SedResetStatistics

    清零所有统计。

--*/
_Use_decl_annotations_
VOID
SedResetStatistics(
    VOID
    )
{
    InterlockedExchange64(&g_SedState.Stats.TotalScans, 0);
    InterlockedExchange64(&g_SedState.Stats.SandboxesDetected, 0);
    InterlockedExchange64(&g_SedState.Stats.DefinitiveDetections, 0);
    InterlockedExchange64(&g_SedState.Stats.HumanInteractionChecks, 0);
    InterlockedExchange64(&g_SedState.Stats.CacheHits, 0);
    InterlockedExchange64(&g_SedState.Stats.CacheMisses, 0);
    InterlockedExchange64(&g_SedState.Stats.AvgAnalysisDurationUs, 0);
    RtlZeroMemory(g_SedState.Stats.DetectionsByProduct,
                  sizeof(g_SedState.Stats.DetectionsByProduct));
}

/*++

SedGetCachedResult

    获取缓存的结果副本。

--*/
_Use_decl_annotations_
BOOLEAN
SedGetCachedResult(
    _Out_ PSED_RESULT Result
    )
{
    BOOLEAN available = FALSE;

    if (Result == NULL) {
        return FALSE;
    }

    AcquireSRWLockShared(&g_SedState.CacheLock);
    if (g_SedState.Cache.Valid) {
        RtlCopyMemory(Result, &g_SedState.Cache.Result, sizeof(SED_RESULT));
        available = TRUE;
    }
    ReleaseSRWLockShared(&g_SedState.CacheLock);

    return available;
}

/*++

SedClearCache

    清空结果缓存。

--*/
_Use_decl_annotations_
VOID
SedClearCache(
    VOID
    )
{
    AcquireSRWLockExclusive(&g_SedState.CacheLock);
    g_SedState.Cache.Valid = FALSE;
    ReleaseSRWLockExclusive(&g_SedState.CacheLock);
}

/*++

SedGetHardwareProfile

    获取缓存的硬件画像（由 AnalyzeHardware 填充）。

--*/
_Use_decl_annotations_
BOOLEAN
SedGetHardwareProfile(
    _Out_ PSED_HARDWARE_PROFILE Profile
    )
{
    BOOLEAN available = FALSE;

    if (Profile == NULL) {
        return FALSE;
    }

    AcquireSRWLockShared(&g_SedState.HwCacheLock);
    if (g_SedState.HwCache.Valid) {
        RtlCopyMemory(Profile, &g_SedState.HwCache.Profile, sizeof(SED_HARDWARE_PROFILE));
        available = TRUE;
    }
    ReleaseSRWLockShared(&g_SedState.HwCacheLock);

    return available;
}

/**************************************************/
/*          公共 API — 名称/工具                   */
/**************************************************/

/*++

SedSandboxProductName

    返回沙箱产品的可读名称。

--*/
_Use_decl_annotations_
PCWSTR
SedSandboxProductName(
    _In_ SED_PRODUCT Product
    )
{
    switch (Product) {
    case SED_PRODUCT_Unknown:           return L"Unknown";
    case SED_PRODUCT_Cuckoo:            return L"Cuckoo Sandbox";
    case SED_PRODUCT_CAPE:              return L"CAPE Sandbox";
    case SED_PRODUCT_Drakvuf:           return L"Drakvuf";
    case SED_PRODUCT_LiSa:              return L"LiSa Sandbox";
    case SED_PRODUCT_JoeSandbox:        return L"Joe Sandbox";
    case SED_PRODUCT_AnyRun:            return L"ANY.RUN";
    case SED_PRODUCT_HybridAnalysis:    return L"Hybrid Analysis";
    case SED_PRODUCT_VirusTotal:        return L"VirusTotal";
    case SED_PRODUCT_VMRay:             return L"VMRay";
    case SED_PRODUCT_FireEyeAX:         return L"FireEye AX";
    case SED_PRODUCT_WildFire:          return L"Palo Alto WildFire";
    case SED_PRODUCT_ThreatGrid:        return L"Cisco Threat Grid";
    case SED_PRODUCT_Triage:            return L"Triage (Hatching)";
    case SED_PRODUCT_Intezer:           return L"Intezer Analyze";
    case SED_PRODUCT_Lastline:          return L"Lastline";
    case SED_PRODUCT_RecordedFuture:    return L"Recorded Future";
    case SED_PRODUCT_Sandboxie:         return L"Sandboxie";
    case SED_PRODUCT_WindowsSandbox:    return L"Windows Sandbox";
    case SED_PRODUCT_ComodoSandbox:     return L"Comodo Sandbox";
    case SED_PRODUCT_AvastDeepScreen:   return L"Avast DeepScreen";
    case SED_PRODUCT_BitdefenderATC:    return L"Bitdefender ATC";
    case SED_PRODUCT_KasperskySafeRun:  return L"Kaspersky Safe Run";
    case SED_PRODUCT_NortonSandbox:     return L"Norton Sandbox";
    case SED_PRODUCT_ESETLiveGuard:     return L"ESET LiveGuard";
    case SED_PRODUCT_FalconSandbox:     return L"CrowdStrike Falcon Sandbox";
    case SED_PRODUCT_DefenderATP:       return L"Microsoft Defender ATP";
    case SED_PRODUCT_CarbonBlack:       return L"Carbon Black";
    case SED_PRODUCT_SentinelOne:       return L"SentinelOne";
    case SED_PRODUCT_Cybereason:        return L"Cybereason";
    case SED_PRODUCT_SophosInterceptX:  return L"Sophos Intercept X";
    case SED_PRODUCT_TrendMicroDD:      return L"Trend Micro Deep Discovery";
    case SED_PRODUCT_McAfeeATD:         return L"McAfee ATD";
    case SED_PRODUCT_GenericAnalysis:   return L"Generic Analysis Environment";
    case SED_PRODUCT_CustomSandbox:     return L"Custom Sandbox";
    case SED_PRODUCT_Multiple:          return L"Multiple Sandboxes";
    default:                            return L"Unknown";
    }
}

/*++

SedCategoryName

    返回指示器类别可读名称。

--*/
_Use_decl_annotations_
PCWSTR
SedCategoryName(
    _In_ SED_INDICATOR_CATEGORY Category
    )
{
    switch (Category) {
    case SED_CATEGORY_Unknown:          return L"Unknown";
    case SED_CATEGORY_HumanInteraction: return L"Human Interaction";
    case SED_CATEGORY_Hardware:         return L"Hardware";
    case SED_CATEGORY_WearAndTear:      return L"Wear and Tear";
    case SED_CATEGORY_Timing:           return L"Timing";
    case SED_CATEGORY_Artifact:         return L"Artifact";
    case SED_CATEGORY_Environment:      return L"Environment";
    case SED_CATEGORY_Network:          return L"Network";
    case SED_CATEGORY_FileSystem:       return L"File System";
    case SED_CATEGORY_Process:          return L"Process";
    case SED_CATEGORY_Registry:         return L"Registry";
    case SED_CATEGORY_Kernel:           return L"Kernel";
    default:                            return L"Unknown";
    }
}

/*++

SedCheckTypeMitreId

    返回检测类型的 MITRE ATT&CK 技术 ID（默认 T1497.001）。

--*/
_Use_decl_annotations_
PCSTR
SedCheckTypeMitreId(
    _In_ SED_CHECK_TYPE CheckType
    )
{
    switch (CheckType) {
    case SED_CHECK_MouseMovement:
    case SED_CHECK_MouseClicks:
    case SED_CHECK_KeyboardInput:
    case SED_CHECK_WindowFocus:
        return "T1497.001";   /* 用户活动检测 */

    case SED_CHECK_SystemUptime:
    case SED_CHECK_InstallDate:
    case SED_CHECK_LastBootTime:
        return "T1497.003";   /* 时序逃避 */

    case SED_CHECK_SandboxDLLs:
    case SED_CHECK_SandboxProcesses:
    case SED_CHECK_SandboxServices:
    case SED_CHECK_HookDetection:
        return "T1497.001";   /* 软件检测 */

    default:
        return "T1497.001";
    }
}

/*++

SedCalculateWeightedProbability

    加权概率：Σ(score*weight) / Σ(weight)。

--*/
_Use_decl_annotations_
FLOAT
SedCalculateWeightedProbability(
    _In_reads_(Count) const FLOAT* Scores,
    _In_reads_(Count) const FLOAT* Weights,
    _In_ ULONG Count
    )
{
    FLOAT weightedSum = 0.0f;
    FLOAT totalWeight = 0.0f;
    ULONG i;

    if (Scores == NULL || Weights == NULL || Count == 0) {
        return 0.0f;
    }

    for (i = 0; i < Count; ++i) {
        weightedSum += Scores[i] * Weights[i];
        totalWeight += Weights[i];
    }

    return (totalWeight > 0.0f) ? (weightedSum / totalWeight) : 0.0f;
}

/*++

SedScoreToSeverity

    分数 → 严重度映射。

--*/
_Use_decl_annotations_
SED_SEVERITY
SedScoreToSeverity(
    _In_ FLOAT Score
    )
{
    if (Score >= 90.0f) return SED_SEVERITY_Critical;
    if (Score >= 70.0f) return SED_SEVERITY_High;
    if (Score >= 40.0f) return SED_SEVERITY_Medium;
    if (Score >= 15.0f) return SED_SEVERITY_Low;
    return SED_SEVERITY_Info;
}

/* === Part 2 结束：生命周期/名称/工具 === */

/**************************************************/
/*      Part 3：主机上下文收集（类型A）            */
/**************************************************/

/* 源 SandboxConstants 补充常量（头文件未收录部分） */
#define SED_VERY_SUSPICIOUS_UPTIME_MS    (2 * 60 * 1000)   /* 2分钟 */
#define SED_SUSPICIOUS_UPTIME_MS         (5 * 60 * 1000)   /* 5分钟 */
#define SED_VERY_SUSPICIOUS_SCREEN_WIDTH 800
#define SED_VERY_SUSPICIOUS_SCREEN_HEIGHT 600

/* 本地(system root)目录缓冲上限，与 SED_MAX_PATH 一致 */
#define SED_LOCAL_PATH_MAX 512

/* MB → 宽字符（CP_ACP，截断安全） */
static void SedMbToWideBuf(PCSTR Src, PWSTR Dst, SIZE_T DstChars)
{
    int len;

    if (Dst == NULL || DstChars == 0) {
        return;
    }
    if (Src == NULL || Src[0] == '\0') {
        Dst[0] = L'\0';
        return;
    }

    len = MultiByteToWideChar(CP_ACP, 0, Src, -1, Dst, (int)DstChars);
    if (len <= 0) {
        /* 转换失败：退化为逐字节展开，避免空串误判 */
        SIZE_T i = 0;
        while (Src[i] != '\0' && i < (DstChars - 1)) {
            Dst[i] = (WCHAR)(UCHAR)Src[i];
            ++i;
        }
        Dst[i] = L'\0';
    }
}

/**************************************************/
/*          公共 API — 硬件分析                    */
/**************************************************/

/*++

SedAnalyzeHardware

    收集系统硬件信息并计算硬件可疑度。
    结果写入 HwCache（供 SedGetHardwareProfile 查询）。

    分数约定（源保持一致）：
      totalRAM < 1GB            +15
      totalRAM < 512MB          +10（叠加）
      逻辑核 <= 0               +15
      磁盘 < 20GB               +10
      USB 历史 < 3              +10（哨兵 UINT32_MAX 跳过）
      无音频设备                +5
      BIOS 确定性沙箱串         +40（优先）
      否则 VM BIOS 串           +10
    isSandboxLike = score >= 50

--*/
_Use_decl_annotations_
NTSTATUS
SedAnalyzeHardware(
    _Out_ PSED_HARDWARE_PROFILE Profile
    )
{
    SED_HARDWARE_PROFILE profile;
    MEMORYSTATUSEX memStatus;
    SYSTEM_INFO sysInfo;
    DWORD bufferLen;
    DWORD subkeyCount;
    HKEY key;
    WCHAR systemDrive[SED_LOCAL_PATH_MAX];
    WCHAR biosCombo[SED_MAX_NAME + SED_MAX_NAME + 128];
    WCHAR biosComboUpper[SED_MAX_NAME + SED_MAX_NAME + 128];
    FLOAT suspicionScore = 0.0f;
    BOOLEAN definiteSandboxFound = FALSE;
    ULONG i;
    int cpuInfo[4];
    char cpuBrand[49];
    char vendor[13];

    if (Profile == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!SedStateInitialized()) {
        return STATUS_NOT_INITIALIZED;
    }

    RtlZeroMemory(&profile, sizeof(profile));
    profile.UsbHistoryCount = UINT32_MAX;   /* 哨兵：查询失败时不参与打分 */
    profile.DiskCount = 1;                  /* 源简化实现 */

    /* -- 内存 --------------------------------------------------- */
    RtlZeroMemory(&memStatus, sizeof(memStatus));
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        profile.TotalRam = memStatus.ullTotalPhys;
        profile.AvailableRam = memStatus.ullAvailPhys;
        profile.VirtualMemoryLimit = memStatus.ullTotalVirtual;
    }

    /* -- CPU 逻辑核 --------------------------------------------- */
    GetSystemInfo(&sysInfo);
    profile.LogicalProcessors = sysInfo.dwNumberOfProcessors;

    /* -- CPU 物理核 --------------------------------------------- */
    bufferLen = 0;
    GetLogicalProcessorInformation(NULL, &bufferLen);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && bufferLen > 0) {
        ULONG entryCount = bufferLen / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION* lpBuffer;
        ULONG physicalCores = 0;

        if (entryCount > 0 && (bufferLen % sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION)) == 0) {
            lpBuffer = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION*)
                HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferLen);
            if (lpBuffer != NULL) {
                if (GetLogicalProcessorInformation(lpBuffer, &bufferLen)) {
                    for (i = 0; i < entryCount; ++i) {
                        if (lpBuffer[i].Relationship == RelationProcessorCore) {
                            ++physicalCores;
                        }
                    }
                    profile.PhysicalCores = physicalCores;
                }
                HeapFree(GetProcessHeap(), 0, lpBuffer);
            }
        }
    }

    /* -- CPU 型号（CPUID 0x80000002~04） ------------------------ */
    __cpuid(cpuInfo, 0x80000000);
    if ((unsigned int)cpuInfo[0] >= 0x80000004) {
        int regs[4];

        __cpuid(regs, 0x80000002);
        memcpy(cpuBrand, regs, sizeof(regs));
        __cpuid(regs, 0x80000003);
        memcpy(cpuBrand + 16, regs, sizeof(regs));
        __cpuid(regs, 0x80000004);
        memcpy(cpuBrand + 32, regs, sizeof(regs));
        cpuBrand[48] = '\0';
        SedMbToWideBuf(cpuBrand, profile.CpuModel, SED_ARRAY_COUNT(profile.CpuModel));
    }

    /* -- CPU 厂商（[EBX][EDX][ECX] 规范布局） ------------------- */
    __cpuid(cpuInfo, 0);
    memcpy(vendor, &cpuInfo[1], 4);      /* EBX */
    memcpy(vendor + 4, &cpuInfo[3], 4);  /* EDX */
    memcpy(vendor + 8, &cpuInfo[2], 4);  /* ECX */
    vendor[12] = '\0';
    SedMbToWideBuf(vendor, profile.CpuVendor, SED_ARRAY_COUNT(profile.CpuVendor));

    /* -- 磁盘 ---------------------------------------------------- */
    if (GetWindowsDirectoryW(systemDrive, SED_ARRAY_COUNT(systemDrive))) {
        ULARGE_INTEGER freeBytesAvailable;
        ULARGE_INTEGER totalBytes;
        ULARGE_INTEGER freeBytes;

        systemDrive[3] = L'\0';   /* Windows 目录 → "C:\" */
        RtlZeroMemory(&freeBytesAvailable, sizeof(freeBytesAvailable));
        RtlZeroMemory(&totalBytes, sizeof(totalBytes));
        RtlZeroMemory(&freeBytes, sizeof(freeBytes));
        if (GetDiskFreeSpaceExW(systemDrive, &freeBytesAvailable, &totalBytes, &freeBytes)) {
            profile.TotalDiskSpace = totalBytes.QuadPart;
            profile.FreeDiskSpace = freeBytes.QuadPart;
        }
    }

    /* -- GPU ----------------------------------------------------- */
    {
        DISPLAY_DEVICEW displayDevice;

        RtlZeroMemory(&displayDevice, sizeof(displayDevice));
        displayDevice.cb = sizeof(displayDevice);
        if (EnumDisplayDevicesW(NULL, 0, &displayDevice, 0)) {
            profile.GpuPresent = TRUE;
            SED_WCOPY(profile.GpuModel, displayDevice.DeviceString,
                      SED_ARRAY_COUNT(profile.GpuModel));
        }
    }

    /* -- 网卡（iphlpapi） ---------------------------------------- */
    {
        ULONG adaptersSize = 0;
        GetAdaptersInfo(NULL, &adaptersSize);
        if (adaptersSize > 0) {
            PIP_ADAPTER_INFO adapters;
            ULONG adapterCount = 0;

            adapters = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, adaptersSize);
            if (adapters != NULL) {
                if (GetAdaptersInfo(adapters, &adaptersSize) == ERROR_SUCCESS) {
                    PIP_ADAPTER_INFO adj;
                    for (adj = adapters; adj != NULL; adj = adj->Next) {
                        ++adapterCount;
                        if (adj->Type == MIB_IF_TYPE_ETHERNET) {
                            profile.PhysicalNicPresent = TRUE;
                        }
                        if (adj->Type == IF_TYPE_IEEE80211) {
                            profile.WifiPresent = TRUE;
                        }
                    }
                    profile.NetworkAdapterCount = adapterCount;
                }
                HeapFree(GetProcessHeap(), 0, adapters);
            }
        }
    }

    /* -- USB 设备历史（注册表） ---------------------------------- */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
                      0, KEY_READ, &key) == ERROR_SUCCESS) {
        subkeyCount = 0;
        if (RegQueryInfoKeyW(key, NULL, NULL, NULL, &subkeyCount,
                             NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            profile.UsbHistoryCount = subkeyCount;
        }
        RegCloseKey(key);
    }

    /* -- BIOS 信息（注册表） ------------------------------------- */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                      0, KEY_READ, &key) == ERROR_SUCCESS) {
        SedReadRegSz(key, L"SystemManufacturer", profile.SystemManufacturer,
                     SED_ARRAY_COUNT(profile.SystemManufacturer));
        SedReadRegSz(key, L"SystemProductName", profile.SystemModel,
                     SED_ARRAY_COUNT(profile.SystemModel));
        SedReadRegSz(key, L"BIOSVendor", profile.BiosVendor,
                     SED_ARRAY_COUNT(profile.BiosVendor));
        SedReadRegSz(key, L"BIOSVersion", profile.BiosVersion,
                     SED_ARRAY_COUNT(profile.BiosVersion));
        RegCloseKey(key);
    }

    /* -- 音频设备 ------------------------------------------------ */
    profile.AudioDevicePresent = (waveOutGetNumDevs() > 0);

    /* -- 可疑度计算 ---------------------------------------------- */
    if (profile.TotalRam < SED_MIN_RAM_BYTES) {
        suspicionScore += 15.0f;
        if (profile.IssueCount < SED_MAX_ISSUES) {
            swprintf_s(profile.Issues[profile.IssueCount++], SED_MAX_DESC,
                       L"Low RAM: %llu MB",
                       (unsigned long long)(profile.TotalRam / (1024 * 1024)));
        }
    }
    if (profile.TotalRam < SED_SUSPICIOUS_RAM_BYTES) {
        suspicionScore += 10.0f;
    }

    if (profile.LogicalProcessors <= SED_SUSPICIOUS_CPU_CORES) {
        suspicionScore += 15.0f;
        if (profile.IssueCount < SED_MAX_ISSUES) {
            swprintf_s(profile.Issues[profile.IssueCount++], SED_MAX_DESC,
                       L"Low CPU cores: %lu", (unsigned long)profile.LogicalProcessors);
        }
    }

    if (profile.TotalDiskSpace < SED_MIN_DISK_BYTES) {
        suspicionScore += 10.0f;
        if (profile.IssueCount < SED_MAX_ISSUES) {
            swprintf_s(profile.Issues[profile.IssueCount++], SED_MAX_DESC,
                       L"Small disk: %llu GB",
                       (unsigned long long)(profile.TotalDiskSpace / (1024 * 1024 * 1024)));
        }
    }

    if (profile.UsbHistoryCount != UINT32_MAX && profile.UsbHistoryCount < 3) {
        suspicionScore += 10.0f;
        if (profile.IssueCount < SED_MAX_ISSUES) {
            swprintf_s(profile.Issues[profile.IssueCount++], SED_MAX_DESC,
                       L"Few USB devices in history: %lu",
                       (unsigned long)profile.UsbHistoryCount);
        }
    }

    if (!profile.AudioDevicePresent) {
        suspicionScore += 5.0f;
        if (profile.IssueCount < SED_MAX_ISSUES) {
            wcscpy_s(profile.Issues[profile.IssueCount++], SED_MAX_DESC,
                     L"No audio device detected");
        }
    }

    /* BIOS 组合串（大写化后匹配） */
    swprintf_s(biosCombo, SED_ARRAY_COUNT(biosCombo), L"%s %s %s",
               profile.BiosVendor, profile.SystemManufacturer, profile.SystemModel);
    wcscpy_s(biosComboUpper, SED_ARRAY_COUNT(biosComboUpper), biosCombo);
    _wcsupr_s(biosComboUpper, SED_ARRAY_COUNT(biosComboUpper));

    for (i = 0; i < SED_ARRAY_COUNT(g_SedDefinitiveSandboxStrings); ++i) {
        if (wcsstr(biosComboUpper, g_SedDefinitiveSandboxStrings[i]) != NULL) {
            suspicionScore += 40.0f;
            if (profile.IssueCount < SED_MAX_ISSUES) {
                swprintf_s(profile.Issues[profile.IssueCount++], SED_MAX_DESC,
                           L"Known sandbox environment detected: %s",
                           g_SedDefinitiveSandboxStrings[i]);
            }
            definiteSandboxFound = TRUE;
            break;
        }
    }

    if (!definiteSandboxFound) {
        for (i = 0; i < SED_ARRAY_COUNT(g_SedVmBiosStrings); ++i) {
            if (wcsstr(biosComboUpper, g_SedVmBiosStrings[i]) != NULL) {
                suspicionScore += 10.0f;   /* 通用 VM 低分（云主机常见） */
                if (profile.IssueCount < SED_MAX_ISSUES) {
                    swprintf_s(profile.Issues[profile.IssueCount++], SED_MAX_DESC,
                               L"VM BIOS string detected: %s", g_SedVmBiosStrings[i]);
                }
                break;
            }
        }
    }

    profile.SuspicionScore = (FLOAT)((suspicionScore > 100.0f) ? 100.0f : suspicionScore);
    profile.IsSandboxLike = (suspicionScore >= 50.0f);   /* 源阈值 50 */

    /* 更新硬件缓存（HwCacheLock） */
    AcquireSRWLockExclusive(&g_SedState.HwCacheLock);
    g_SedState.HwCache.Profile = profile;
    GetSystemTimeAsFileTime((LPFILETIME)&g_SedState.HwCache.TimestampFileTime);
    g_SedState.HwCache.Valid = TRUE;
    ReleaseSRWLockExclusive(&g_SedState.HwCacheLock);

    *Profile = profile;
    return STATUS_SUCCESS;
}

/**************************************************/
/*          公共 API — 系统磨损分析                */
/**************************************************/

/*++

SedAnalyzeWearAndTear

    统计真实用户系统的"磨损"（使用痕迹）指标。
    installedProgramCount 哨兵 UINT32_MAX = 查询失败，不参与打分。

--*/
_Use_decl_annotations_
NTSTATUS
SedAnalyzeWearAndTear(
    _Out_ PSED_WEAR_TEAR Analysis
    )
{
    SED_WEAR_TEAR analysis;
    WCHAR folderPath[SED_LOCAL_PATH_MAX];
    WCHAR tempPath[SED_LOCAL_PATH_MAX];
    HKEY key;
    DWORD subkeyCount;
    FLOAT usageScore = 0.0f;

    if (Analysis == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!SedStateInitialized()) {
        return STATUS_NOT_INITIALIZED;
    }

    RtlZeroMemory(&analysis, sizeof(analysis));

    /* -- 最近文档 ------------------------------------------------- */
    if (SHGetFolderPathW(NULL, CSIDL_RECENT, NULL, 0, folderPath) == S_OK) {
        analysis.RecentDocumentsCount = SedCountFilesInDirectory(folderPath);
    }

    /* -- 桌面 ----------------------------------------------------- */
    if (SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, folderPath) == S_OK) {
        analysis.DesktopFileCount = SedCountFilesInDirectory(folderPath);
    }

    /* -- 下载 ----------------------------------------------------- */
    if (SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, folderPath) == S_OK) {
        SIZE_T len = wcslen(folderPath);
        if (len + 10 < SED_ARRAY_COUNT(folderPath)) {
            wcscat_s(folderPath, SED_ARRAY_COUNT(folderPath), L"\\Downloads");
            analysis.DownloadsFileCount = SedCountFilesInDirectory(folderPath);
        }
    }

    /* -- 文档 ----------------------------------------------------- */
    if (SHGetFolderPathW(NULL, CSIDL_PERSONAL, NULL, 0, folderPath) == S_OK) {
        analysis.DocumentsFileCount = SedCountFilesInDirectory(folderPath);
    }

    /* -- 图片 ----------------------------------------------------- */
    if (SHGetFolderPathW(NULL, CSIDL_MYPICTURES, NULL, 0, folderPath) == S_OK) {
        analysis.PicturesFileCount = SedCountFilesInDirectory(folderPath);
    }

    /* -- 已安装程序（64位 + Wow6432Node 累加） -------------------- */
    analysis.InstalledProgramCount = UINT32_MAX;   /* 哨兵 */
    subkeyCount = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                      0, KEY_READ, &key) == ERROR_SUCCESS) {
        if (RegQueryInfoKeyW(key, NULL, NULL, NULL, &subkeyCount,
                             NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            analysis.InstalledProgramCount = subkeyCount;
        }
        RegCloseKey(key);
    }

    subkeyCount = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                      0, KEY_READ, &key) == ERROR_SUCCESS) {
        if (RegQueryInfoKeyW(key, NULL, NULL, NULL, &subkeyCount,
                             NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            if (analysis.InstalledProgramCount == UINT32_MAX) {
                analysis.InstalledProgramCount = subkeyCount;
            } else {
                analysis.InstalledProgramCount += subkeyCount;
            }
        }
        RegCloseKey(key);
    }

    /* -- Prefetch -------------------------------------------------- */
    if (GetWindowsDirectoryW(folderPath, SED_ARRAY_COUNT(folderPath))) {
        wcscat_s(folderPath, SED_ARRAY_COUNT(folderPath), L"\\Prefetch");
        analysis.PrefetchFileCount = SedCountFilesInDirectory(folderPath);
    }

    /* -- 临时目录 --------------------------------------------------- */
    if (GetTempPathW(SED_ARRAY_COUNT(tempPath), tempPath)) {
        analysis.TempFileCount = SedCountFilesInDirectory(tempPath);
    }

    /* -- 用户配置文件数 --------------------------------------------- */
    subkeyCount = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
                      0, KEY_READ, &key) == ERROR_SUCCESS) {
        if (RegQueryInfoKeyW(key, NULL, NULL, NULL, &subkeyCount,
                             NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            /* 减去系统内置配置文件（通常 4 个） */
            analysis.UserProfileCount = (subkeyCount > 4) ? (subkeyCount - 4) : 1;
        }
        RegCloseKey(key);
    }

    /* -- 字体 -------------------------------------------------------- */
    if (GetWindowsDirectoryW(folderPath, SED_ARRAY_COUNT(folderPath))) {
        wcscat_s(folderPath, SED_ARRAY_COUNT(folderPath), L"\\Fonts");
        analysis.FontCount = SedCountFilesInDirectory(folderPath);
    }

    /* -- 自定义壁纸 --------------------------------------------------- */
    {
        WCHAR wallpaperPath[SED_LOCAL_PATH_MAX] = L"";
        SystemParametersInfoW(SPI_GETDESKWALLPAPER, SED_LOCAL_PATH_MAX, wallpaperPath, 0);
        analysis.CustomWallpaper = (wallpaperPath[0] != L'\0');
    }

    /* -- 使用度评分 ---------------------------------------------------- */
    if (analysis.RecentDocumentsCount >= 50) usageScore += 15.0f;
    else if (analysis.RecentDocumentsCount >= 20) usageScore += 10.0f;
    else if (analysis.RecentDocumentsCount >= 5) usageScore += 5.0f;

    if (analysis.DesktopFileCount >= 20) usageScore += 10.0f;
    else if (analysis.DesktopFileCount >= 5) usageScore += 5.0f;

    if (analysis.InstalledProgramCount != UINT32_MAX) {
        if (analysis.InstalledProgramCount >= 50) usageScore += 20.0f;
        else if (analysis.InstalledProgramCount >= 30) usageScore += 15.0f;
        else if (analysis.InstalledProgramCount >= 15) usageScore += 10.0f;
    }

    if (analysis.PrefetchFileCount >= 100) usageScore += 15.0f;
    else if (analysis.PrefetchFileCount >= 50) usageScore += 10.0f;
    else if (analysis.PrefetchFileCount >= 20) usageScore += 5.0f;

    if (analysis.TempFileCount >= 500) usageScore += 10.0f;
    else if (analysis.TempFileCount >= 100) usageScore += 5.0f;

    if (analysis.FontCount >= 300) usageScore += 10.0f;
    else if (analysis.FontCount >= 200) usageScore += 5.0f;

    if (analysis.CustomWallpaper) usageScore += 5.0f;

    if (analysis.UserProfileCount >= 3) usageScore += 10.0f;
    else if (analysis.UserProfileCount >= 2) usageScore += 5.0f;

    analysis.UsageScore = (FLOAT)((usageScore > 100.0f) ? 100.0f : usageScore);
    analysis.AppearsFresh = (usageScore < 30.0f);

    /* -- 问题清单 ------------------------------------------------------- */
    if (analysis.RecentDocumentsCount < SED_MIN_RECENT_DOCUMENTS) {
        if (analysis.IssueCount < SED_MAX_ISSUES) {
            swprintf_s(analysis.Issues[analysis.IssueCount++], SED_MAX_DESC,
                       L"Few recent documents: %zu", analysis.RecentDocumentsCount);
        }
    }
    if (analysis.DesktopFileCount < SED_MIN_DESKTOP_FILES) {
        if (analysis.IssueCount < SED_MAX_ISSUES) {
            wcscpy_s(analysis.Issues[analysis.IssueCount++], SED_MAX_DESC,
                     L"Empty desktop");
        }
    }
    if (analysis.InstalledProgramCount != UINT32_MAX &&
        analysis.InstalledProgramCount < SED_MIN_INSTALLED_PROGRAMS) {
        if (analysis.IssueCount < SED_MAX_ISSUES) {
            swprintf_s(analysis.Issues[analysis.IssueCount++], SED_MAX_DESC,
                       L"Few installed programs: %zu", analysis.InstalledProgramCount);
        }
    }
    if (analysis.PrefetchFileCount < 20) {
        if (analysis.IssueCount < SED_MAX_ISSUES) {
            swprintf_s(analysis.Issues[analysis.IssueCount++], SED_MAX_DESC,
                       L"Few prefetch files: %zu", analysis.PrefetchFileCount);
        }
    }

    *Analysis = analysis;
    return STATUS_SUCCESS;
}

/**************************************************/
/*          公共 API — 环境分析                    */
/**************************************************/

/*++

SedAnalyzeEnvironment

    收集显示器/区域/系统标识等环境信息。
    用户名精确匹配（小写）、计算机名包含匹配（大写）。

--*/
_Use_decl_annotations_
NTSTATUS
SedAnalyzeEnvironment(
    _Out_ PSED_ENV_ANALYSIS Analysis
    )
{
    SED_ENV_ANALYSIS analysis;
    LONG screenWidth;
    LONG screenHeight;
    HDC hdc;
    TIME_ZONE_INFORMATION tzInfo;
    WCHAR localeName[LOCALE_NAME_MAX_LENGTH];
    WCHAR layoutName[KL_NAMELENGTH];
    WCHAR computerNameBuf[MAX_COMPUTERNAME_LENGTH + 1];
    WCHAR userNameBuf[UNLEN + 1];
    WCHAR lowerUserName[UNLEN + 1];
    WCHAR upperComputerName[MAX_COMPUTERNAME_LENGTH + 1];
    WCHAR productName[512];
    SIZE_T productNameChars = SED_ARRAY_COUNT(productName);
    HKEY key;
    DWORD valueType;
    DWORD sizeInBytes;
    FLOAT suspicionScore = 0.0f;
    ULONG i;

    if (Analysis == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!SedStateInitialized()) {
        return STATUS_NOT_INITIALIZED;
    }

    RtlZeroMemory(&analysis, sizeof(analysis));

    /* -- 屏幕分辨率 --------------------------------------------------- */
    screenWidth = GetSystemMetrics(SM_CXSCREEN);
    screenHeight = GetSystemMetrics(SM_CYSCREEN);
    analysis.ScreenWidth = (ULONG)screenWidth;
    analysis.ScreenHeight = (ULONG)screenHeight;

    if ((screenWidth == 800 && screenHeight == 600) ||
        (screenWidth == 1024 && screenHeight == 768) ||
        (screenWidth == 1280 && screenHeight == 720)) {
        analysis.IsVmResolution = TRUE;
    }

    /* -- 色深 --------------------------------------------------------- */
    hdc = GetDC(NULL);
    if (hdc != NULL) {
        analysis.ColorDepth = (ULONG)GetDeviceCaps(hdc, BITSPIXEL);
        ReleaseDC(NULL, hdc);
    }

    /* -- 监视器数量 --------------------------------------------------- */
    analysis.MonitorCount = (ULONG)GetSystemMetrics(SM_CMONITORS);

    /* -- DPI ----------------------------------------------------------- */
    hdc = GetDC(NULL);
    if (hdc != NULL) {
        analysis.Dpi = (ULONG)GetDeviceCaps(hdc, LOGPIXELSX);
        ReleaseDC(NULL, hdc);
    }

    /* -- 时区 ----------------------------------------------------------- */
    RtlZeroMemory(&tzInfo, sizeof(tzInfo));
    GetTimeZoneInformation(&tzInfo);
    SED_WCOPY(analysis.Timezone, tzInfo.StandardName, SED_ARRAY_COUNT(analysis.Timezone));

    /* -- 区域 ----------------------------------------------------------- */
    if (GetUserDefaultLocaleName(localeName, SED_ARRAY_COUNT(localeName))) {
        SED_WCOPY(analysis.Locale, localeName, SED_ARRAY_COUNT(analysis.Locale));
    }

    /* -- 键盘布局 ------------------------------------------------------- */
    GetKeyboardLayout(0);   /* 激活布局（返回值仅用于保持唤醒） */
    if (GetKeyboardLayoutNameW(layoutName)) {
        SED_WCOPY(analysis.KeyboardLayout, layoutName, SED_ARRAY_COUNT(analysis.KeyboardLayout));
    }

    /* -- 计算机名 ------------------------------------------------------- */
    {
        DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
        if (GetComputerNameW(computerNameBuf, &size)) {
            SED_WCOPY(analysis.ComputerName, computerNameBuf, SED_ARRAY_COUNT(analysis.ComputerName));
        }
    }

    /* -- 用户名 --------------------------------------------------------- */
    {
        DWORD size = UNLEN + 1;
        if (GetUserNameW(userNameBuf, &size)) {
            SED_WCOPY(analysis.UserName, userNameBuf, SED_ARRAY_COUNT(analysis.UserName));
        }
    }

    /* -- Windows 版本 / 构建号 ------------------------------------------ */
    RtlZeroMemory(&productName, sizeof(productName));
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_READ, &key) == ERROR_SUCCESS) {
        valueType = 0;
        sizeInBytes = (DWORD)(sizeof(productName) - sizeof(WCHAR));   /* 预留 NUL */
        if (RegQueryValueExW(key, L"ProductName", NULL, &valueType,
                             (LPBYTE)productName, &sizeInBytes) == ERROR_SUCCESS &&
            (valueType == REG_SZ || valueType == REG_EXPAND_SZ)) {
            productName[productNameChars - 1] = L'\0';
            SED_WCOPY(analysis.WindowsVersion, productName, SED_ARRAY_COUNT(analysis.WindowsVersion));
        }

        {
            WCHAR buildStr[32] = L"";
            sizeInBytes = (DWORD)(sizeof(buildStr) - sizeof(WCHAR));
            valueType = 0;
            if (RegQueryValueExW(key, L"CurrentBuildNumber", NULL, &valueType,
                                 (LPBYTE)buildStr, &sizeInBytes) == ERROR_SUCCESS &&
                (valueType == REG_SZ || valueType == REG_EXPAND_SZ)) {
                buildStr[31] = L'\0';
                analysis.WindowsBuild = (ULONG)_wtoi(buildStr);
            }
        }
        RegCloseKey(key);
    }

    /* -- 可疑度计算 ----------------------------------------------------- */
    if (analysis.IsVmResolution) {
        suspicionScore += 15.0f;
        if (analysis.IssueCount < SED_MAX_ISSUES) {
            swprintf_s(analysis.Issues[analysis.IssueCount++], SED_MAX_DESC,
                       L"Typical VM/sandbox resolution: %lux%lu",
                       (unsigned long)screenWidth, (unsigned long)screenHeight);
        }
    }

    if (analysis.ColorDepth < SED_MIN_COLOR_DEPTH) {
        suspicionScore += 10.0f;
        if (analysis.IssueCount < SED_MAX_ISSUES) {
            swprintf_s(analysis.Issues[analysis.IssueCount++], SED_MAX_DESC,
                       L"Low color depth: %lu bits", (unsigned long)analysis.ColorDepth);
        }
    }

    if (analysis.MonitorCount == 0) {
        suspicionScore += 20.0f;
        if (analysis.IssueCount < SED_MAX_ISSUES) {
            wcscpy_s(analysis.Issues[analysis.IssueCount++], SED_MAX_DESC,
                     L"No monitors detected");
        }
    }

    /* 可疑用户名（小写精确匹配） */
    wcscpy_s(lowerUserName, SED_ARRAY_COUNT(lowerUserName), analysis.UserName);
    _wcslwr_s(lowerUserName, SED_ARRAY_COUNT(lowerUserName));
    for (i = 0; i < SED_ARRAY_COUNT(g_SedSandboxUsernames); ++i) {
        if (wcscmp(lowerUserName, g_SedSandboxUsernames[i]) == 0) {
            suspicionScore += 25.0f;
            if (analysis.IssueCount < SED_MAX_ISSUES) {
                swprintf_s(analysis.Issues[analysis.IssueCount++], SED_MAX_DESC,
                           L"Suspicious username: %s", analysis.UserName);
            }
            break;
        }
    }

    /* 可疑计算机名（大写包含匹配） */
    wcscpy_s(upperComputerName, SED_ARRAY_COUNT(upperComputerName), analysis.ComputerName);
    _wcsupr_s(upperComputerName, SED_ARRAY_COUNT(upperComputerName));
    for (i = 0; i < SED_ARRAY_COUNT(g_SedSandboxComputernames); ++i) {
        if (wcsstr(upperComputerName, g_SedSandboxComputernames[i]) != NULL) {
            suspicionScore += 20.0f;
            if (analysis.IssueCount < SED_MAX_ISSUES) {
                swprintf_s(analysis.Issues[analysis.IssueCount++], SED_MAX_DESC,
                           L"Suspicious computer name: %s", analysis.ComputerName);
            }
            break;
        }
    }

    analysis.SuspicionScore = (FLOAT)((suspicionScore > 100.0f) ? 100.0f : suspicionScore);

    *Analysis = analysis;
    return STATUS_SUCCESS;
}

/* === Part 3 结束：硬件/磨损/环境 === */

/**************************************************/
/*      Part 4：工件扫描与 Check* 系列             */
/**************************************************/

/*++

SedScanArtifacts

    扫描沙箱工件：DLL / 进程 / 互斥体 / 注册表键 / 文件。
    计算总工件数、可疑度与确定性判定。

    源 35 项进程表已去重（joeboxserver/joeboxcontrol 各 2 份笔误 → 1 份）。

--*/
_Use_decl_annotations_
NTSTATUS
SedScanArtifacts(
    _Out_ PSED_ARTIFACT_ANALYSIS Analysis
    )
{
    SED_ARTIFACT_ANALYSIS analysis;
    HANDLE snapshot;
    PROCESSENTRY32W pe;
    ULONG i;
    FLOAT rawScore;

    if (Analysis == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!SedStateInitialized()) {
        return STATUS_NOT_INITIALIZED;
    }

    RtlZeroMemory(&analysis, sizeof(analysis));

    /* -- A) 沙箱 DLL 检查（15 项） -------------------------------- */
    for (i = 0; i < SED_ARRAY_COUNT(g_SedSandboxDlls); ++i) {
        if (GetModuleHandleW(g_SedSandboxDlls[i].Name) != NULL) {
            if (analysis.SandboxDllCount < SED_MAX_DLLS) {
                SED_WCOPY(analysis.SandboxDlls[analysis.SandboxDllCount],
                          g_SedSandboxDlls[i].Name, SED_MAX_NAME);
                ++analysis.SandboxDllCount;
            }
            ++analysis.SuspiciousDllCount;

            /* 产品映射（DLL 工件是强证据） */
            if (g_SedSandboxDlls[i].Product != SED_PRODUCT_Unknown &&
                analysis.IdentifiedProductCount < SED_MAX_IDENTIFIED) {
                analysis.IdentifiedProducts[analysis.IdentifiedProductCount++] =
                    g_SedSandboxDlls[i].Product;
            }
        }
    }

    /* -- B) 进程检查（33 项，小写比较） ---------------------------- */
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        RtlZeroMemory(&pe, sizeof(pe));
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(snapshot, &pe)) {
            do {
                WCHAR lowerName[SED_MAX_NAME];

                SED_WCOPY(lowerName, pe.szExeFile, SED_ARRAY_COUNT(lowerName));
                SedToLowerW(lowerName);

                for (i = 0; i < SED_ARRAY_COUNT(g_SedSandboxProcesses); ++i) {
                    if (wcscmp(lowerName, g_SedSandboxProcesses[i].NameLower) == 0) {
                        if (g_SedSandboxProcesses[i].IsAnalysisTool) {
                            if (analysis.AnalysisToolProcessCount < SED_MAX_ANALYSIS_TOOLS) {
                                SED_WCOPY(analysis.AnalysisToolProcesses[analysis.AnalysisToolProcessCount],
                                          pe.szExeFile, SED_MAX_NAME);
                                ++analysis.AnalysisToolProcessCount;
                            }
                        } else {
                            if (analysis.SandboxProcessCount < SED_MAX_PROCESSES) {
                                SED_WCOPY(analysis.SandboxProcesses[analysis.SandboxProcessCount],
                                          pe.szExeFile, SED_MAX_NAME);
                                ++analysis.SandboxProcessCount;
                            }
                        }
                        ++analysis.SuspiciousProcessCount;
                        break;
                    }
                }
            } while (Process32NextW(snapshot, &pe));
        }
        CloseHandle(snapshot);
    }

    /* -- C) 互斥体检查（6 项） -------------------------------------- */
    for (i = 0; i < SED_ARRAY_COUNT(g_SedSandboxMutexes); ++i) {
        HANDLE hMutex = OpenMutexW(SYNCHRONIZE, FALSE, g_SedSandboxMutexes[i]);
        if (hMutex != NULL) {
            if (analysis.SandboxMutexCount < SED_MAX_MUTEXES) {
                SED_WCOPY(analysis.SandboxMutexes[analysis.SandboxMutexCount],
                          g_SedSandboxMutexes[i], SED_MAX_NAME);
                ++analysis.SandboxMutexCount;
            }
            CloseHandle(hMutex);
        }
    }

    /* -- D) 注册表键检查（14 项） ----------------------------------- */
    for (i = 0; i < SED_ARRAY_COUNT(g_SedSandboxRegistryKeys); ++i) {
        HKEY hKey;
        if (RegOpenKeyExW(g_SedSandboxRegistryKeys[i].Hive,
                          g_SedSandboxRegistryKeys[i].Path,
                          0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (analysis.SandboxRegistryKeyCount < SED_MAX_REGKEYS) {
                SED_WCOPY(analysis.SandboxRegistryKeys[analysis.SandboxRegistryKeyCount],
                          g_SedSandboxRegistryKeys[i].Path, SED_MAX_PATH);
                ++analysis.SandboxRegistryKeyCount;
            }
            ++analysis.SuspiciousRegistryCount;
            RegCloseKey(hKey);
        }
    }

    /* -- E) 文件检查（14 项） ---------------------------------------- */
    for (i = 0; i < SED_ARRAY_COUNT(g_SedSandboxFiles); ++i) {
        if (GetFileAttributesW(g_SedSandboxFiles[i]) != INVALID_FILE_ATTRIBUTES) {
            if (analysis.SandboxFileCount < SED_MAX_FILES) {
                SED_WCOPY(analysis.SandboxFiles[analysis.SandboxFileCount],
                          g_SedSandboxFiles[i], SED_MAX_PATH);
                ++analysis.SandboxFileCount;
            }
        }
    }

    /* -- F) 汇总计算 ------------------------------------------------ */
    analysis.TotalArtifactsFound =
        (SIZE_T)analysis.SandboxDllCount +
        (SIZE_T)analysis.SandboxProcessCount +
        (SIZE_T)analysis.AnalysisToolProcessCount +
        (SIZE_T)analysis.SandboxMutexCount +
        (SIZE_T)analysis.SandboxRegistryKeyCount +
        (SIZE_T)analysis.SandboxFileCount;

    /* 主嫌疑产品（首个识别出的产品，与源一致） */
    if (analysis.IdentifiedProductCount > 0) {
        analysis.PrimarySuspect = analysis.IdentifiedProducts[0];
    }

    rawScore =
        (FLOAT)analysis.SandboxDllCount * 25.0f +
        (FLOAT)analysis.SandboxProcessCount * 20.0f +
        (FLOAT)analysis.AnalysisToolProcessCount * 15.0f +
        (FLOAT)analysis.SandboxMutexCount * 25.0f +
        (FLOAT)analysis.SandboxRegistryKeyCount * 10.0f +
        (FLOAT)analysis.SandboxFileCount * 15.0f;
    analysis.SuspicionScore = (rawScore > 100.0f) ? 100.0f : rawScore;

    /* 确定性判定：直接证据（DLL/互斥体/沙箱进程） */
    analysis.DefinitiveDetection =
        (analysis.SandboxDllCount > 0) ||
        (analysis.SandboxMutexCount > 0) ||
        (analysis.SandboxProcessCount > 0);

    *Analysis = analysis;
    return STATUS_SUCCESS;
}

/**************************************************/
/*      Phase 1 Check* 系列（ScanSystem 内部）     */
/**************************************************/

/* CheckHardwareSpecs：硬件画像 + 硬件指示器 */
static void SedCheckHardwareSpecs(PSED_RESULT Result)
{
    SED_HARDWARE_PROFILE hardware;
    WCHAR observed[64];

    RtlZeroMemory(&hardware, sizeof(hardware));
    SedAnalyzeHardware(&hardware);

    Result->Hardware = hardware;
    Result->HardwareScore = 100.0f - hardware.SuspicionScore;

    if (hardware.TotalRam < SED_SUSPICIOUS_RAM_BYTES) {
        swprintf_s(observed, SED_ARRAY_COUNT(observed), L"%llu MB",
                   (unsigned long long)(hardware.TotalRam / (1024 * 1024)));
        SedAddIndicator(Result, SED_CHECK_RAMSize, SED_CATEGORY_Hardware,
            SED_SEVERITY_High, 3.0f, 85.0f,
            L"Suspiciously low RAM detected",
            L"RAM below typical user systems",
            observed, L">= 4096 MB",
            SED_PRODUCT_Unknown, FALSE);
    } else if (hardware.TotalRam < SED_MIN_RAM_BYTES) {
        swprintf_s(observed, SED_ARRAY_COUNT(observed), L"%llu MB",
                   (unsigned long long)(hardware.TotalRam / (1024 * 1024)));
        SedAddIndicator(Result, SED_CHECK_RAMSize, SED_CATEGORY_Hardware,
            SED_SEVERITY_Medium, 2.0f, 60.0f,
            L"Low RAM detected",
            L"RAM below recommended minimum",
            observed, L">= 4096 MB",
            SED_PRODUCT_Unknown, FALSE);
    }

    if (hardware.LogicalProcessors <= SED_SUSPICIOUS_CPU_CORES) {
        swprintf_s(observed, SED_ARRAY_COUNT(observed), L"%lu",
                   (unsigned long)hardware.LogicalProcessors);
        SedAddIndicator(Result, SED_CHECK_CPUCores, SED_CATEGORY_Hardware,
            SED_SEVERITY_High, 3.0f, 80.0f,
            L"Single CPU core detected",
            L"Most modern systems have multiple cores",
            observed, L">= 2",
            SED_PRODUCT_Unknown, FALSE);
    }

    if (hardware.TotalDiskSpace < SED_SUSPICIOUS_DISK_BYTES) {
        swprintf_s(observed, SED_ARRAY_COUNT(observed), L"%llu GB",
                   (unsigned long long)(hardware.TotalDiskSpace / (1024 * 1024 * 1024)));
        SedAddIndicator(Result, SED_CHECK_DiskSize, SED_CATEGORY_Hardware,
            SED_SEVERITY_Medium, 2.0f, 70.0f,
            L"Small disk detected",
            L"Disk size typical of sandbox environments",
            observed, L">= 80 GB",
            SED_PRODUCT_Unknown, FALSE);
    }

    if (!hardware.AudioDevicePresent) {
        SedAddIndicator(Result, SED_CHECK_AudioDevices, SED_CATEGORY_Hardware,
            SED_SEVERITY_Low, 1.0f, 40.0f,
            L"No audio device detected",
            L"Absence of audio devices is common in sandboxes",
            L"", L"",
            SED_PRODUCT_Unknown, FALSE);
    }

    ++Result->TotalChecks;
    if (hardware.IsSandboxLike) {
        ++Result->FailedChecks;
    } else {
        ++Result->PassedChecks;
    }
}

/* CheckUptime：系统运行时长（时序指示器） */
static void SedCheckUptime(PSED_RESULT Result)
{
    ULONGLONG uptime = GetTickCount64();
    WCHAR observed[64];

    if (uptime < SED_VERY_SUSPICIOUS_UPTIME_MS) {
        swprintf_s(observed, SED_ARRAY_COUNT(observed), L"%llu seconds",
                   (unsigned long long)(uptime / 1000));
        SedAddIndicator(Result, SED_CHECK_SystemUptime, SED_CATEGORY_Timing,
            SED_SEVERITY_High, 4.0f, 90.0f,
            L"Very short system uptime",
            L"System was recently booted, typical of fresh sandbox",
            observed, L">= 120 seconds",
            SED_PRODUCT_Unknown, TRUE);
        Result->TimingScore += 40.0f;
        ++Result->FailedChecks;
    } else if (uptime < SED_SUSPICIOUS_UPTIME_MS) {
        swprintf_s(observed, SED_ARRAY_COUNT(observed), L"%llu seconds",
                   (unsigned long long)(uptime / 1000));
        SedAddIndicator(Result, SED_CHECK_SystemUptime, SED_CATEGORY_Timing,
            SED_SEVERITY_Medium, 2.5f, 70.0f,
            L"Short system uptime",
            L"System uptime below typical threshold",
            observed, L">= 300 seconds",
            SED_PRODUCT_Unknown, FALSE);
        Result->TimingScore += 25.0f;
        ++Result->FailedChecks;
    } else if (uptime < SED_MIN_UPTIME_MS) {
        swprintf_s(observed, SED_ARRAY_COUNT(observed), L"%llu minutes",
                   (unsigned long long)(uptime / 60000));
        SedAddIndicator(Result, SED_CHECK_SystemUptime, SED_CATEGORY_Timing,
            SED_SEVERITY_Low, 1.5f, 50.0f,
            L"Relatively short system uptime",
            L"System uptime below minimum threshold",
            observed, L">= 10 minutes",
            SED_PRODUCT_Unknown, FALSE);
        Result->TimingScore += 15.0f;
    } else {
        ++Result->PassedChecks;
    }

    ++Result->TotalChecks;
}

/* CheckLoadedModules：已加载沙箱 DLL（7 项强证据） */
static void SedCheckLoadedModules(PSED_RESULT Result)
{
    SED_PRODUCT products[] = {
        SED_PRODUCT_Sandboxie,       /* SbieDll.dll */
        SED_PRODUCT_Cuckoo,          /* cuckoomon.dll */
        SED_PRODUCT_AvastDeepScreen, /* snxhk.dll */
        SED_PRODUCT_VMRay,           /* vmray_api.dll */
        SED_PRODUCT_JoeSandbox,      /* joeboxcontrol.dll */
        SED_PRODUCT_ComodoSandbox,   /* guard32.dll */
        SED_PRODUCT_ComodoSandbox    /* guard64.dll */
    };
    ULONG i;

    for (i = 0; i < 7 && i < SED_ARRAY_COUNT(g_SedSandboxDlls); ++i) {
        if (GetModuleHandleW(g_SedSandboxDlls[i].Name) != NULL) {
            SedAddIndicator(Result, SED_CHECK_SandboxDLLs, SED_CATEGORY_Artifact,
                SED_SEVERITY_Critical, 5.0f, 99.0f,
                L"Sandbox DLL detected",   /* 描述拼接在 ObservedValue */
                L"Direct evidence of sandbox environment",
                g_SedSandboxDlls[i].Name, L"Not loaded",
                products[i], TRUE);

            /* 描述含 DLL 名（源：L"Sandbox DLL detected: " + dll） */
            {
                PSED_INDICATOR pInd = &Result->Indicators[Result->IndicatorCount - 1];
                swprintf_s(pInd->Description, SED_MAX_DESC,
                           L"Sandbox DLL detected: %s", g_SedSandboxDlls[i].Name);
            }

            Result->ArtifactScore += 30.0f;
            if (Result->Artifacts.SandboxDllCount < SED_MAX_DLLS) {
                SED_WCOPY(Result->Artifacts.SandboxDlls[Result->Artifacts.SandboxDllCount],
                          g_SedSandboxDlls[i].Name, SED_MAX_NAME);
                ++Result->Artifacts.SandboxDllCount;
            }
            if (Result->Artifacts.IdentifiedProductCount < SED_MAX_IDENTIFIED) {
                Result->Artifacts.IdentifiedProducts[Result->Artifacts.IdentifiedProductCount++] =
                    products[i];
            }
            ++Result->FailedChecks;
        } else {
            ++Result->PassedChecks;
        }
        ++Result->TotalChecks;
    }
}

/* CheckNamedObjects：沙箱互斥体（4 项强证据） */
static void SedCheckNamedObjects(PSED_RESULT Result)
{
    typedef struct {
        PCWSTR       Name;
        SED_PRODUCT  Product;
    } MUTEX_PRODUCT;

    static const MUTEX_PRODUCT sandboxMutexes[] = {
        { L"Sandboxie_SingleInstanceMutex_Control", SED_PRODUCT_Sandboxie },
        { L"CuckooMutex",                            SED_PRODUCT_Cuckoo      },
        { L"JoeBoxMutex",                            SED_PRODUCT_JoeSandbox  },
        { L"VMRayMutex",                             SED_PRODUCT_VMRay       }
    };
    ULONG i;

    for (i = 0; i < SED_ARRAY_COUNT(sandboxMutexes); ++i) {
        HANDLE hMutex = OpenMutexW(SYNCHRONIZE, FALSE, sandboxMutexes[i].Name);
        if (hMutex != NULL) {
            CloseHandle(hMutex);
            SedAddIndicator(Result, SED_CHECK_SandboxMutexes, SED_CATEGORY_Artifact,
                SED_SEVERITY_Critical, 5.0f, 99.0f,
                L"Sandbox mutex detected",   /* 描述拼接在 ObservedValue */
                L"Direct evidence of sandbox environment",
                sandboxMutexes[i].Name, L"Not present",
                sandboxMutexes[i].Product, TRUE);
            {
                PSED_INDICATOR pInd = &Result->Indicators[Result->IndicatorCount - 1];
                swprintf_s(pInd->Description, SED_MAX_DESC,
                           L"Sandbox mutex detected: %s", sandboxMutexes[i].Name);
            }
            Result->ArtifactScore += 35.0f;
            if (Result->Artifacts.SandboxMutexCount < SED_MAX_MUTEXES) {
                SED_WCOPY(Result->Artifacts.SandboxMutexes[Result->Artifacts.SandboxMutexCount],
                          sandboxMutexes[i].Name, SED_MAX_NAME);
                ++Result->Artifacts.SandboxMutexCount;
            }
            ++Result->FailedChecks;
        } else {
            ++Result->PassedChecks;
        }
        ++Result->TotalChecks;
    }
}

/* CheckSystemWearAndTear：磨损分析 → 指示器 */
static void SedCheckSystemWearAndTear(PSED_RESULT Result)
{
    SED_WEAR_TEAR wear;
    WCHAR observed[64];

    RtlZeroMemory(&wear, sizeof(wear));
    SedAnalyzeWearAndTear(&wear);

    Result->WearAndTear = wear;
    Result->WearAndTearScore = wear.UsageScore;

    if (wear.AppearsFresh) {
        SedAddIndicator(Result, SED_CHECK_InstalledPrograms, SED_CATEGORY_WearAndTear,
            SED_SEVERITY_Medium, 2.0f, 65.0f,
            L"System appears freshly installed",
            L"Minimal system usage indicators detected",
            L"", L"",
            SED_PRODUCT_Unknown, FALSE);
        ++Result->FailedChecks;
    } else {
        ++Result->PassedChecks;
    }

    if (wear.InstalledProgramCount != UINT32_MAX &&
        wear.InstalledProgramCount < SED_MIN_INSTALLED_PROGRAMS) {
        swprintf_s(observed, SED_ARRAY_COUNT(observed), L"%zu", wear.InstalledProgramCount);
        SedAddIndicator(Result, SED_CHECK_InstalledPrograms, SED_CATEGORY_WearAndTear,
            SED_SEVERITY_Low, 1.5f, 55.0f,
            L"Few installed programs",
            L"Typical user systems have more software installed",
            observed, L">= 20",
            SED_PRODUCT_Unknown, FALSE);
    }

    if (wear.RecentDocumentsCount < 5) {
        swprintf_s(observed, SED_ARRAY_COUNT(observed), L"%zu", wear.RecentDocumentsCount);
        SedAddIndicator(Result, SED_CHECK_RecentDocuments, SED_CATEGORY_WearAndTear,
            SED_SEVERITY_Low, 1.0f, 45.0f,
            L"Very few recent documents",
            L"No document activity history",
            observed, L">= 10",
            SED_PRODUCT_Unknown, FALSE);
    }

    ++Result->TotalChecks;
}

/* === Part 4a 结束 === */

/* CheckScreenResolution：屏幕分辨率环境指示器 */
static void SedCheckScreenResolution(PSED_RESULT Result)
{
    LONG width = GetSystemMetrics(SM_CXSCREEN);
    LONG height = GetSystemMetrics(SM_CYSCREEN);
    WCHAR observed[64];
    BOOLEAN isSuspicious = FALSE;

    Result->Environment.ScreenWidth = (ULONG)width;
    Result->Environment.ScreenHeight = (ULONG)height;

    if (width <= SED_VERY_SUSPICIOUS_SCREEN_WIDTH &&
        height <= SED_VERY_SUSPICIOUS_SCREEN_HEIGHT) {
        swprintf_s(observed, SED_ARRAY_COUNT(observed), L"%lux%lu",
                   (unsigned long)width, (unsigned long)height);
        SedAddIndicator(Result, SED_CHECK_ScreenResolution, SED_CATEGORY_Environment,
            SED_SEVERITY_High, 3.0f, 85.0f,
            L"Very low screen resolution",
            L"800x600 is extremely common in sandboxes",
            observed, L">= 1280x720",
            SED_PRODUCT_Unknown, FALSE);
        Result->EnvironmentScore += 25.0f;
        isSuspicious = TRUE;
    } else if (width <= SED_SUSPICIOUS_SCREEN_WIDTH &&
               height <= SED_SUSPICIOUS_SCREEN_HEIGHT) {
        swprintf_s(observed, SED_ARRAY_COUNT(observed), L"%lux%lu",
                   (unsigned long)width, (unsigned long)height);
        SedAddIndicator(Result, SED_CHECK_ScreenResolution, SED_CATEGORY_Environment,
            SED_SEVERITY_Medium, 2.0f, 65.0f,
            L"Low screen resolution",
            L"1024x768 is common in sandbox environments",
            observed, L">= 1280x720",
            SED_PRODUCT_Unknown, FALSE);
        Result->EnvironmentScore += 15.0f;
        isSuspicious = TRUE;
    }

    ++Result->TotalChecks;
    if (isSuspicious) {
        Result->Environment.IsVmResolution = TRUE;
        ++Result->FailedChecks;
    } else {
        ++Result->PassedChecks;
    }
}

/* CheckProcesses：进程工件指示器（复制工件结构） */
static void SedCheckProcesses(PSED_RESULT Result, PSED_ARTIFACT_ANALYSIS Artifacts)
{
    ULONG i;

    for (i = 0; i < Artifacts->SandboxProcessCount; ++i) {
        if (i >= SED_MAX_PROCESSES) break;
        SedAddIndicator(Result, SED_CHECK_SandboxProcesses, SED_CATEGORY_Artifact,
            SED_SEVERITY_High, 4.0f, 90.0f,
            L"Sandbox process detected",   /* 描述在 ObservedValue */
            L"Sandbox control process running",
            Artifacts->SandboxProcesses[i], L"Not running",
            SED_PRODUCT_Unknown, FALSE);
        {
            PSED_INDICATOR pInd = &Result->Indicators[Result->IndicatorCount - 1];
            swprintf_s(pInd->Description, SED_MAX_DESC,
                       L"Sandbox process detected: %s", Artifacts->SandboxProcesses[i]);
        }
        ++Result->FailedChecks;
    }

    for (i = 0; i < Artifacts->AnalysisToolProcessCount; ++i) {
        if (i >= SED_MAX_ANALYSIS_TOOLS) break;
        SedAddIndicator(Result, SED_CHECK_AnalysisTools, SED_CATEGORY_Artifact,
            SED_SEVERITY_Medium, 2.5f, 75.0f,
            L"Analysis tool detected",   /* 描述在 ObservedValue */
            L"Common malware analysis tool running",
            Artifacts->AnalysisToolProcesses[i], L"Not running",
            SED_PRODUCT_Unknown, FALSE);
        {
            PSED_INDICATOR pInd = &Result->Indicators[Result->IndicatorCount - 1];
            swprintf_s(pInd->Description, SED_MAX_DESC,
                       L"Analysis tool detected: %s", Artifacts->AnalysisToolProcesses[i]);
        }
        ++Result->FailedChecks;
    }

    /* 复制工件到结果 */
    RtlCopyMemory(Result->Artifacts.SandboxProcesses, Artifacts->SandboxProcesses,
                  sizeof(Result->Artifacts.SandboxProcesses));
    Result->Artifacts.SandboxProcessCount = Artifacts->SandboxProcessCount;
    RtlCopyMemory(Result->Artifacts.AnalysisToolProcesses, Artifacts->AnalysisToolProcesses,
                  sizeof(Result->Artifacts.AnalysisToolProcesses));
    Result->Artifacts.AnalysisToolProcessCount = Artifacts->AnalysisToolProcessCount;

    Result->TotalChecks += Result->Artifacts.SandboxProcessCount +
                           Result->Artifacts.AnalysisToolProcessCount;
    if (Result->Artifacts.SandboxProcessCount == 0 &&
        Result->Artifacts.AnalysisToolProcessCount == 0) {
        ++Result->PassedChecks;
        ++Result->TotalChecks;
    }
}

/* CheckServices：沙箱服务检测 */
static void SedCheckServices(PSED_RESULT Result)
{
    SC_HANDLE scManager;
    ULONG i;

    scManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scManager == NULL) {
        return;
    }

    for (i = 0; i < SED_ARRAY_COUNT(g_SedSandboxServices); ++i) {
        SC_HANDLE hService = OpenServiceW(scManager, g_SedSandboxServices[i].Name,
                                          SERVICE_QUERY_STATUS);
        if (hService != NULL) {
            SERVICE_STATUS status;
            RtlZeroMemory(&status, sizeof(status));
            if (QueryServiceStatus(hService, &status)) {
                if (status.dwCurrentState == SERVICE_RUNNING) {
                    SedAddIndicator(Result, SED_CHECK_SandboxServices, SED_CATEGORY_Artifact,
                        SED_SEVERITY_High, 3.5f, 85.0f,
                        L"Sandbox service running",   /* 描述在 ObservedValue */
                        L"Sandbox-related service detected",
                        g_SedSandboxServices[i].Name, L"Not running",
                        g_SedSandboxServices[i].Product, FALSE);
                    {
                        PSED_INDICATOR pInd = &Result->Indicators[Result->IndicatorCount - 1];
                        swprintf_s(pInd->Description, SED_MAX_DESC,
                                   L"Sandbox service running: %s",
                                   g_SedSandboxServices[i].Name);
                    }
                    if (Result->Artifacts.SandboxServiceCount < SED_MAX_SERVICES) {
                        SED_WCOPY(Result->Artifacts.SandboxServices[Result->Artifacts.SandboxServiceCount],
                                  g_SedSandboxServices[i].Name, SED_MAX_NAME);
                        ++Result->Artifacts.SandboxServiceCount;
                    }
                    ++Result->FailedChecks;
                }
            }
            CloseServiceHandle(hService);
        }
        ++Result->TotalChecks;
    }

    CloseServiceHandle(scManager);

    if (Result->Artifacts.SandboxServiceCount == 0) {
        ++Result->PassedChecks;
    }
}

/* CheckRegistry：环境分析 → 注册表环境指示器 */
static void SedCheckRegistry(PSED_RESULT Result)
{
    SED_ENV_ANALYSIS env;
    ULONG i;

    RtlZeroMemory(&env, sizeof(env));
    SedAnalyzeEnvironment(&env);

    Result->Environment = env;
    Result->EnvironmentScore = 100.0f - env.SuspicionScore;

    if (env.IssueCount > 0) {
        for (i = 0; i < env.IssueCount && i < SED_MAX_ISSUES; ++i) {
            SedAddIndicator(Result, SED_CHECK_SandboxRegistry, SED_CATEGORY_Environment,
                SED_SEVERITY_Medium, 2.0f, 60.0f,
                env.Issues[i], L"Environment anomaly detected",
                L"", L"",
                SED_PRODUCT_Unknown, FALSE);
        }
        Result->FailedChecks += env.IssueCount;
    } else {
        ++Result->PassedChecks;
    }

    Result->TotalChecks += env.IssueCount + 1;
}

/* CheckFileSystem：文件工件指示器 */
static void SedCheckFileSystem(PSED_RESULT Result, PSED_ARTIFACT_ANALYSIS Artifacts)
{
    ULONG i;

    for (i = 0; i < Artifacts->SandboxFileCount && i < SED_MAX_FILES; ++i) {
        SedAddIndicator(Result, SED_CHECK_SandboxFiles, SED_CATEGORY_FileSystem,
            SED_SEVERITY_High, 3.5f, 88.0f,
            L"Sandbox file detected",   /* 描述在 ObservedValue */
            L"File typically found in sandbox environments",
            Artifacts->SandboxFiles[i], L"Not present",
            SED_PRODUCT_Unknown, FALSE);
        {
            PSED_INDICATOR pInd = &Result->Indicators[Result->IndicatorCount - 1];
            swprintf_s(pInd->Description, SED_MAX_DESC,
                       L"Sandbox file detected: %s", Artifacts->SandboxFiles[i]);
        }
        ++Result->FailedChecks;
    }

    RtlCopyMemory(Result->Artifacts.SandboxFiles, Artifacts->SandboxFiles,
                  sizeof(Result->Artifacts.SandboxFiles));
    Result->Artifacts.SandboxFileCount = Artifacts->SandboxFileCount;

    ++Result->TotalChecks;
    if (Result->Artifacts.SandboxFileCount == 0) {
        ++Result->PassedChecks;
    }
}

/**************************************************/
/*      API 钩子检测（字节模式，替代反汇编）        */
/**************************************************/

/* 前序字节模式映射（源 PhantomDisassembler 语义降级）：
   CC                → INT3
   CD 2D             → INT 2D
   E9 xx xx xx xx    → JMP rel32 (inline hook)
   FF 25 xx xx xx xx → JMP [RIP+disp32] (indirect hook)
   E8 xx xx xx xx    → CALL rel32 (detour)
   FF D0-FF D7       → CALL reg (detour)
   FF E0-FF E7       → JMP reg (hook)
   68 imm32 C3       → PUSH imm32; RET
   6A imm8  C3       → PUSH imm8;  RET
   48 B8 imm64 FF E0 → MOV RAX; JMP RAX (trampoline)    */
static BOOLEAN SedIsApiPrologueHooked(
    _In_reads_(MaxBytes) const UCHAR* Bytes,
    _In_ SIZE_T MaxBytes,
    _Out_writes_(HookTypeChars) PWSTR HookType,
    _In_ SIZE_T HookTypeChars)
{
    if (Bytes == NULL || MaxBytes < 1 || HookType == NULL || HookTypeChars == 0) {
        return FALSE;
    }

    /* INT3 / INT 2D */
    if (MaxBytes >= 1 && Bytes[0] == 0xCC) {
        wcscpy_s(HookType, HookTypeChars, L"INT3 breakpoint (debug hook)");
        return TRUE;
    }
    if (MaxBytes >= 2 && Bytes[0] == 0xCD && Bytes[1] == 0x2D) {
        wcscpy_s(HookType, HookTypeChars, L"INT 2D (debug hook)");
        return TRUE;
    }

    /* JMP rel32 */
    if (MaxBytes >= 5 && Bytes[0] == 0xE9) {
        wcscpy_s(HookType, HookTypeChars, L"JMP rel32 (inline hook)");
        return TRUE;
    }

    /* JMP [RIP+disp32] */
    if (MaxBytes >= 6 && Bytes[0] == 0xFF && Bytes[1] == 0x25) {
        wcscpy_s(HookType, HookTypeChars, L"JMP [RIP+disp32] (indirect hook)");
        return TRUE;
    }

    /* CALL rel32 */
    if (MaxBytes >= 5 && Bytes[0] == 0xE8) {
        wcscpy_s(HookType, HookTypeChars, L"CALL instruction (detour)");
        return TRUE;
    }

    /* FF /2 CALL reg（FF D0-D7） */
    if (MaxBytes >= 2 && Bytes[0] == 0xFF &&
        (Bytes[1] >= 0xD0 && Bytes[1] <= 0xD7)) {
        wcscpy_s(HookType, HookTypeChars, L"CALL instruction (detour)");
        return TRUE;
    }

    /* FF /4 JMP reg（FF E0-E7） */
    if (MaxBytes >= 2 && Bytes[0] == 0xFF &&
        (Bytes[1] >= 0xE0 && Bytes[1] <= 0xE7)) {
        wcscpy_s(HookType, HookTypeChars, L"JMP instruction (hook)");
        return TRUE;
    }

    /* PUSH imm32; RET (68 xx xx xx xx C3) */
    if (MaxBytes >= 7 && Bytes[0] == 0x68 && Bytes[5] == 0xC3) {
        wcscpy_s(HookType, HookTypeChars, L"PUSH/RET gadget (hook)");
        return TRUE;
    }

    /* PUSH imm8; RET (6A xx C3) */
    if (MaxBytes >= 3 && Bytes[0] == 0x6A && Bytes[2] == 0xC3) {
        wcscpy_s(HookType, HookTypeChars, L"PUSH/RET gadget (hook)");
        return TRUE;
    }

    /* MOV RAX, imm64; JMP RAX (48 B8 <8> FF E0) */
    if (MaxBytes >= 12 && Bytes[0] == 0x48 && Bytes[1] == 0xB8 &&
        Bytes[10] == 0xFF && Bytes[11] == 0xE0) {
        wcscpy_s(HookType, HookTypeChars, L"MOV RAX, imm64; JMP RAX (trampoline)");
        return TRUE;
    }

    return FALSE;
}

/* CheckAPIHooks：检测 17 个关键 API 的内联钩子 */
static void SedCheckAPIHooks(PSED_RESULT Result)
{
    SIZE_T hookedCount = 0;
    ULONG i;

    for (i = 0; i < SED_ARRAY_COUNT(g_SedCriticalApis); ++i) {
        HMODULE hMod = GetModuleHandleA(g_SedCriticalApis[i].Module);
        FARPROC proc;
        UCHAR prologue[SED_MAX_PROLOGUE_BYTES];
        WCHAR hookType[96];
        WCHAR apiName[160];

        if (hMod == NULL) {
            continue;
        }
        proc = GetProcAddress(hMod, g_SedCriticalApis[i].Function);
        if (proc == NULL) {
            continue;
        }

        memcpy(prologue, (const UCHAR*)proc, SED_MAX_PROLOGUE_BYTES);

        if (SedIsApiPrologueHooked(prologue, SED_MAX_PROLOGUE_BYTES,
                                   hookType, SED_ARRAY_COUNT(hookType))) {
            ++hookedCount;

            swprintf_s(apiName, SED_ARRAY_COUNT(apiName), "%s!%s",
                       g_SedCriticalApis[i].Module, g_SedCriticalApis[i].Function);
            {
                WCHAR fullName[SED_MAX_NAME];
                swprintf_s(fullName, SED_ARRAY_COUNT(fullName), L"%s - %s",
                           apiName, hookType);
                if (Result->Artifacts.HookedApiCount < SED_MAX_HOOKED_APIS) {
                    SED_WCOPY(Result->Artifacts.HookedApis[Result->Artifacts.HookedApiCount],
                              fullName, SED_MAX_NAME);
                    ++Result->Artifacts.HookedApiCount;
                }
            }
        }
        /* ntdll syscall 存根被篡改的可疑标记：源仅标记不计数，此处从简 */
    }

    if (hookedCount > 0) {
        WCHAR desc[96];
        swprintf_s(desc, SED_ARRAY_COUNT(desc), L"API hooks detected: %zu functions",
                   hookedCount);
        SedAddIndicator(Result, SED_CHECK_HookDetection, SED_CATEGORY_Artifact,
            SED_SEVERITY_High, 4.0f, 85.0f,
            desc,
            L"Inline hooks indicate monitoring/sandbox environment",
            L"", L"0 hooks",
            SED_PRODUCT_Unknown, FALSE);
        Result->Artifacts.ApiHooksDetected = TRUE;
        Result->Artifacts.HookedApiCount = (ULONG)hookedCount;
        ++Result->FailedChecks;
    } else {
        ++Result->PassedChecks;
    }

    ++Result->TotalChecks;
}

/* CheckNetworkCharacteristics：VM MAC OUI 前缀检测 */
static void SedCheckNetworkCharacteristics(PSED_RESULT Result)
{
    ULONG adaptersSize = 0;
    GetAdaptersInfo(NULL, &adaptersSize);

    if (adaptersSize > 0) {
        PIP_ADAPTER_INFO adapters;
        adapters = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, adaptersSize);
        if (adapters != NULL) {
            if (GetAdaptersInfo(adapters, &adaptersSize) == ERROR_SUCCESS) {
                PIP_ADAPTER_INFO adj;
                for (adj = adapters; adj != NULL; adj = adj->Next) {
                    ULONG j;
                    if (adj->AddressLength < 3) {
                        continue;
                    }
                    for (j = 0; j < SED_ARRAY_COUNT(g_SedVmMacPrefixes); ++j) {
                        if (adj->Address[0] == g_SedVmMacPrefixes[j][0] &&
                            adj->Address[1] == g_SedVmMacPrefixes[j][1] &&
                            adj->Address[2] == g_SedVmMacPrefixes[j][2]) {
                            WCHAR macStr[32];
                            swprintf_s(macStr, SED_ARRAY_COUNT(macStr), L"%02X:%02X:%02X:*",
                                       adj->Address[0], adj->Address[1], adj->Address[2]);
                            SedAddIndicator(Result, SED_CHECK_MACAddress, SED_CATEGORY_Network,
                                SED_SEVERITY_Medium, 2.5f, 75.0f,
                                L"VM/Sandbox MAC address prefix detected",
                                L"Network adapter has known virtual machine OUI",
                                macStr, L"Physical adapter OUI",
                                SED_PRODUCT_Unknown, FALSE);
                            Result->NetworkScore += 20.0f;
                            break;
                        }
                    }
                }
            }
            HeapFree(GetProcessHeap(), 0, adapters);
        }
    }

    ++Result->TotalChecks;
    ++Result->PassedChecks;   /* 网络本身不构成确定性证据 */
}

/* === Part 4b 结束：ScanArtifacts 与 Check* 系列 === */

/**************************************************/
/*      Part 5：概率计算 / 产品识别 / 系统扫描     */
/**************************************************/

/* 缓存有效性：缓存使能 && 存在 && 未超过 TTL（分钟），时间戳以秒计 */
static BOOLEAN SedIsCacheValid(void)
{
    FILETIME nowFt;
    ULONGLONG now;
    ULONGLONG ttlSeconds;
    SED_CONFIG cfg;

    GetSystemTimeAsFileTime(&nowFt);
    now = SED_FILE_TIME_SECONDS(nowFt);

    SedGetConfig(&cfg);
    if (!cfg.EnableCache) {
        return FALSE;
    }

    if (!g_SedState.Cache.Valid) {
        return FALSE;
    }

    ttlSeconds = (ULONGLONG)g_SedState.Config.CacheTtlMinutes * 60ull;

    return (now - g_SedState.Cache.TimestampFileTime) <= ttlSeconds;
}

/*++

SedCalculateProbability

    分类分数 → 沙箱概率。
    各分数含义为"干净度"（硬件/环境/工件/时序/网络取反），
    加权后取反得沙箱概率；存在确定性证据时概率至少 95。

--*/
static void SedCalculateProbability(PSED_RESULT Result)
{
    FLOAT scores[SED_ARRAY_COUNT_7];
    FLOAT weights[SED_ARRAY_COUNT_7];
    SED_CONFIG currentConfig;
    FLOAT cleanProbability;
    BOOLEAN hasDefinitiveEvidence;
    FLOAT checksRatio;
    ULONG criticalCount = 0;
    ULONG highCount = 0;
    ULONG i;

    SedGetConfig(&currentConfig);

    /* 收集七类分数（源顺序固定） */
    scores[0] = 100.0f - Result->Hardware.SuspicionScore;        /* 硬件（取反） */
    scores[1] = Result->WearAndTear.UsageScore;                  /* 磨损 */
    scores[2] = Result->HasHumanInteraction
        ? Result->HumanInteraction.HumanConfidence               /* 人机交互 */
        : 50.0f;
    scores[3] = 100.0f - Result->Environment.SuspicionScore;     /* 环境（取反） */
    scores[4] = 100.0f - Result->Artifacts.SuspicionScore;       /* 工件（取反） */
    scores[5] = 100.0f - Result->TimingScore;                    /* 时序（取反） */
    scores[6] = 100.0f - Result->NetworkScore;                   /* 网络（取反） */

    weights[0] = currentConfig.HardwareWeight;
    weights[1] = currentConfig.WearAndTearWeight;
    weights[2] = currentConfig.HumanInteractionWeight;
    weights[3] = currentConfig.EnvironmentWeight;
    weights[4] = currentConfig.ArtifactWeight;
    weights[5] = currentConfig.TimingWeight;
    weights[6] = currentConfig.NetworkWeight;

    /* 加权"干净"概率 → 取反 = 沙箱概率 */
    cleanProbability = SedCalculateWeightedProbability(scores, weights, 7);
    Result->Probability = 100.0f - cleanProbability;

    /* 确定性证据提升 */
    hasDefinitiveEvidence = Result->Artifacts.DefinitiveDetection;
    for (i = 0; i < Result->IndicatorCount; ++i) {
        if (Result->Indicators[i].IsConclusive) {
            hasDefinitiveEvidence = TRUE;
            break;
        }
    }
    if (hasDefinitiveEvidence) {
        if (Result->Probability < 95.0f) {
            Result->Probability = 95.0f;
        }
        Result->IsDefinitive = TRUE;
    }

    /* 钳制与阈值判定 */
    Result->Probability = (FLOAT)((Result->Probability > 100.0f) ? 100.0f :
                           ((Result->Probability < 0.0f) ? 0.0f : Result->Probability));
    Result->IsSandboxLikely = (Result->Probability >= currentConfig.ProbabilityThreshold);

    /* 置信度：已完成检查占比 */
    checksRatio = (Result->TotalChecks > 0)
        ? (FLOAT)(Result->FailedChecks + Result->PassedChecks) / (FLOAT)Result->TotalChecks
        : 0.0f;
    Result->Confidence = SED_CLAMP_FLOAT(checksRatio * 100.0f, 0.0f, 100.0f);

    /* 严重度分布加成 */
    for (i = 0; i < Result->IndicatorCount; ++i) {
        if (Result->Indicators[i].Severity == SED_SEVERITY_Critical) ++criticalCount;
        else if (Result->Indicators[i].Severity == SED_SEVERITY_High) ++highCount;
    }
    if (criticalCount > 0) {
        Result->Confidence = (FLOAT)((Result->Confidence + 20.0f > 100.0f)
            ? 100.0f : Result->Confidence + 20.0f);
    }
    if (highCount >= 3) {
        Result->Confidence = (FLOAT)((Result->Confidence + 10.0f > 100.0f)
            ? 100.0f : Result->Confidence + 10.0f);
    }

    /* 摘要信息 */
    if (Result->SummaryMessageCount < SED_MAX_SUMMARY) {
        if (Result->IsSandboxLikely) {
            swprintf_s(Result->SummaryMessages[Result->SummaryMessageCount++], SED_MAX_DESC,
                       L"Sandbox environment detected with %d%% probability",
                       (int)Result->Probability);
        } else {
            swprintf_s(Result->SummaryMessages[Result->SummaryMessageCount++], SED_MAX_DESC,
                       L"No sandbox detected (probability: %d%%)",
                       (int)Result->Probability);
        }
    }
}

/*++

SedIdentifySandboxProduct

    根据投票（指示器 1 票 / 工件识别 2 票）确定主嫌疑产品。
    多个产品有票 → 判定 Multiple。

--*/
static void SedIdentifySandboxProduct(PSED_RESULT Result)
{
    ULONG votes[256];
    SED_PRODUCT bestProduct = SED_PRODUCT_Unknown;
    ULONG maxVotes = 0;
    ULONG votingProducts = 0;
    ULONG i;

    RtlZeroMemory(votes, sizeof(votes));

    /* 指示器投票（1 票） */
    for (i = 0; i < Result->IndicatorCount; ++i) {
        if (Result->Indicators[i].SuspectedProduct != SED_PRODUCT_Unknown) {
            votes[(ULONG)Result->Indicators[i].SuspectedProduct]++;
        }
    }

    /* 工件投票（2 票，更强证据） */
    for (i = 0; i < Result->Artifacts.IdentifiedProductCount; ++i) {
        votes[(ULONG)Result->Artifacts.IdentifiedProducts[i]] += 2;
    }

    /* 统计投票产品数 + 最大票 */
    for (i = 1; i < 256; ++i) {   /* 0 = Unknown 不计 */
        if (votes[i] > 0) {
            ++votingProducts;
            if (votes[i] > maxVotes) {
                maxVotes = votes[i];
                bestProduct = (SED_PRODUCT)i;
            }
        }
    }

    Result->IdentifiedSandbox = bestProduct;
    Result->SuspectedProductCount = 0;
    for (i = 1; i < 256; ++i) {
        if (votes[i] > 0 && Result->SuspectedProductCount < SED_MAX_IDENTIFIED) {
            Result->SuspectedProducts[Result->SuspectedProductCount++] = (SED_PRODUCT)i;
        }
    }

    /* 沙箱名称 */
    if (bestProduct != SED_PRODUCT_Unknown) {
        SED_WCOPY(Result->SandboxName, SedSandboxProductName(bestProduct),
                  SED_ARRAY_COUNT(Result->SandboxName));
    }

    /* 多个沙箱共存 */
    if (votingProducts > 1) {
        Result->IdentifiedSandbox = SED_PRODUCT_Multiple;
        SED_WCOPY(Result->SandboxName, L"Multiple sandbox indicators",
                  SED_ARRAY_COUNT(Result->SandboxName));
    }
}

/*++

SedAddMitreMappings

    汇总指示器的 MITRE 技术 ID（去重）。
    主战术固定为 TA0005（Defense Evasion）。

--*/
static void SedAddMitreMappings(PSED_RESULT Result)
{
    ULONG i;

    Result->MitreIdCount = 0;
    for (i = 0; i < Result->IndicatorCount; ++i) {
        PCSTR mitre = SedCheckTypeMitreId(Result->Indicators[i].CheckType);
        ULONG j;
        BOOLEAN exists = FALSE;

        if (mitre == NULL || mitre[0] == '\0') {
            continue;
        }
        for (j = 0; j < Result->MitreIdCount; ++j) {
            if (strcmp(Result->MitreIds[j], mitre) == 0) {
                exists = TRUE;
                break;
            }
        }
        if (!exists && Result->MitreIdCount < SED_MAX_MITRE) {
            SED_ACOPY(Result->MitreIds[Result->MitreIdCount], mitre, 16);
            ++Result->MitreIdCount;
        }
    }

    SED_ACOPY(Result->MitreTactic, "TA0005", 16);
}

/**************************************************/
/*          公共 API — 系统扫描                    */
/**************************************************/

/*++

SedScanSystem

    两阶段系统级扫描：
      Phase 1  宿主上下文收集（行为评分校准的来源）
      Phase 2  全进程行为扫描（主要检测：沙箱逃避导入/
               内存沙箱字符串/时序代码模式）

    全部 Check* 门控受 Config 开关控制；结果缓存 + 统计 +
    回调（快照后锁外调用）。

--*/
_Use_decl_annotations_
NTSTATUS
SedScanSystem(
    _Out_ PSED_RESULT Result
    )
{
    SED_RESULT result;
    SED_CONFIG currentConfig;
    SED_ARTIFACT_ANALYSIS scannedArtifacts;
    ULONGLONG startTick;
    ULONGLONG startFileTime;
    ULONGLONG endTick;
    ULONGLONG durationMs;
    ULONGLONG durationUs;

    if (Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!SedStateInitialized()) {
        return STATUS_NOT_INITIALIZED;
    }

    SedGetConfig(&currentConfig);

    /* 缓存命中直接返回 */
    if (currentConfig.EnableCache && SedIsCacheValid()) {
        InterlockedIncrement64(&g_SedState.Stats.CacheHits);
        AcquireSRWLockShared(&g_SedState.CacheLock);
        if (g_SedState.Cache.Valid) {
            RtlCopyMemory(Result, &g_SedState.Cache.Result, sizeof(SED_RESULT));
            ReleaseSRWLockShared(&g_SedState.CacheLock);
            return STATUS_SUCCESS;
        }
        ReleaseSRWLockShared(&g_SedState.CacheLock);
    }
    InterlockedIncrement64(&g_SedState.Stats.CacheMisses);

    SED_INIT_RESULT(&result);
    GetSystemTimeAsFileTime((LPFILETIME)&startFileTime);
    result.AnalysisStartTime = SED_FILE_TIME_SECONDS(startFileTime);
    startTick = GetTickCount64();

    /* ===== Phase 1：宿主上下文收集 ===== */
    if (currentConfig.CheckHardware) {
        SedCheckHardwareSpecs(&result);
    }
    if (currentConfig.CheckTiming) {
        SedCheckUptime(&result);
    }
    if (currentConfig.CheckArtifacts) {
        SedCheckLoadedModules(&result);
        SedCheckNamedObjects(&result);
    }

    RtlZeroMemory(&scannedArtifacts, sizeof(scannedArtifacts));
    if (currentConfig.CheckArtifacts || currentConfig.CheckFileSystem) {
        SedScanArtifacts(&scannedArtifacts);
    }

    if (currentConfig.CheckArtifacts) {
        SedCheckProcesses(&result, &scannedArtifacts);
        SedCheckServices(&result);
        SedCheckAPIHooks(&result);
    }
    if (currentConfig.CheckWearAndTear) {
        SedCheckSystemWearAndTear(&result);
    }
    if (currentConfig.CheckEnvironment) {
        SedCheckScreenResolution(&result);
        SedCheckRegistry(&result);
    }
    if (currentConfig.CheckFileSystem) {
        SedCheckFileSystem(&result, &scannedArtifacts);
    }
    if (currentConfig.CheckNetwork) {
        SedCheckNetworkCharacteristics(&result);
    }
    if (currentConfig.CheckHumanInteraction) {
        result.HasHumanInteraction = TRUE;
        SedAnalyzeHumanInteraction(currentConfig.HumanInteractionMonitorMs,
                                   &result.HumanInteraction);
        result.HumanInteractionScore = result.HumanInteraction.HumanConfidence;
    }

    /* ===== Phase 2：全进程行为扫描 ===== */
    {
        BOOLEAN hostIsSandbox =
            result.Artifacts.DefinitiveDetection ||
            result.ArtifactScore >= 60.0f ||
            result.TimingScore >= 60.0f ||
            result.Environment.SuspicionScore >= 60.0f ||
            result.Hardware.SuspicionScore >= 70.0f;

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            SED_PROCESS_CONFIG procConfig;

            /* 系统级扫描预算收紧（默认 64MB/4MB → 4MB/1MB，避免分钟级卡顿） */
            RtlZeroMemory(&procConfig, sizeof(procConfig));
            procConfig.CheckImports = TRUE;
            procConfig.CheckMemoryStrings = TRUE;
            procConfig.CheckCodePatterns = TRUE;
            procConfig.MaxMemoryScanBytes = 4ULL * 1024 * 1024;
            procConfig.MaxCodeScanBytes = 1ULL * 1024 * 1024;

            RtlZeroMemory(&pe, sizeof(pe));
            pe.dwSize = sizeof(pe);

            if (Process32FirstW(hSnapshot, &pe)) {
                do {
                    HANDLE hTarget;
                    WCHAR verifyPath[SED_MAX_PATH];
                    DWORD verifyLen = SED_MAX_PATH;
                    PCWSTR base;
                    SED_PROCESS_RESULT procResult;
                    NTSTATUS analyzeStatus;

                    if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) {
                        continue;   /* System Idle / System */
                    }

                    /* TOCTOU 防护：打开句柄后校验映像路径基名仍与快照一致 */
                    hTarget = OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                        FALSE, pe.th32ProcessID);
                    if (hTarget == NULL) {
                        continue;
                    }

                    if (!QueryFullProcessImageNameW(hTarget, 0, verifyPath, &verifyLen)) {
                        CloseHandle(hTarget);
                        continue;
                    }

                    base = wcsrchr(verifyPath, L'\\');
                    if (base == NULL) base = wcsrchr(verifyPath, L'/');
                    base = (base != NULL) ? (base + 1) : verifyPath;

                    if (_wcsicmp(base, pe.szExeFile) != 0) {
                        /* PID 已被回收：映像不一致 */
                        CloseHandle(hTarget);
                        continue;
                    }

                    SED_INIT_PROCESS_RESULT(&procResult);
                    analyzeStatus = SedAnalyzeProcess(hTarget, pe.th32ProcessID,
                                                      &procConfig, &procResult);
                    CloseHandle(hTarget);

                    if (NT_SUCCESS(analyzeStatus) && procResult.HasEvasionCapability) {
                        /* 校准：真实沙箱宿主上，反沙箱检测的嫌疑度减权 */
                        FLOAT calibratedScore = procResult.EvasionScore;
                        if (hostIsSandbox && calibratedScore > 20.0f) {
                            calibratedScore *= 0.6f;
                        }

                        SedAddIndicator(&result,
                            SED_CHECK_SandboxProcesses,
                            SED_CATEGORY_Artifact,
                            calibratedScore >= 80.0f ? SED_SEVERITY_Critical :
                            calibratedScore >= 50.0f ? SED_SEVERITY_High :
                                                       SED_SEVERITY_Medium,
                            calibratedScore / 25.0f,
                            calibratedScore,
                            L"Process exhibits anti-sandbox evasion behavior",
                            L"",   /* 技术细节在下方拼接 */
                            L"", L"None",
                            SED_PRODUCT_Unknown, FALSE);
                        {
                            PSED_INDICATOR pInd =
                                &result.Indicators[result.IndicatorCount - 1];
                            WCHAR detail[128];
                            swprintf_s(detail, SED_ARRAY_COUNT(detail),
                                       L"PID %lu (%s)",
                                       (unsigned long)pe.th32ProcessID, pe.szExeFile);
                            SED_WCOPY(pInd->TechnicalDetails, detail,
                                      SED_ARRAY_COUNT(pInd->TechnicalDetails));
                            swprintf_s(detail, SED_ARRAY_COUNT(detail),
                                       L"Score: %d", (int)calibratedScore);
                            SED_WCOPY(pInd->ObservedValue, detail,
                                      SED_ARRAY_COUNT(pInd->ObservedValue));
                        }
                    }
                } while (Process32NextW(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        }
    }

    /* ===== 最终计算 ===== */
    SedCalculateProbability(&result);
    SedIdentifySandboxProduct(&result);
    SedAddMitreMappings(&result);

    endTick = GetTickCount64();
    durationMs = endTick - startTick;
    durationUs = durationMs * 1000;

    GetSystemTimeAsFileTime((LPFILETIME)&startFileTime);   /* 复用变量作尾部时间戳 */
    result.AnalysisEndTime = SED_FILE_TIME_SECONDS(startFileTime);
    result.AnalysisDurationMs = durationMs;
    result.AnalysisComplete = TRUE;

    /* ===== 统计更新 ===== */
    InterlockedIncrement64(&g_SedState.Stats.TotalScans);
    SedUpdateEma(&g_SedState.Stats.AvgAnalysisDurationUs, durationUs);

    if (result.IsSandboxLikely) {
        InterlockedIncrement64(&g_SedState.Stats.SandboxesDetected);
        if (result.IsDefinitive) {
            InterlockedIncrement64(&g_SedState.Stats.DefinitiveDetections);
        }
        if (result.IdentifiedSandbox != SED_PRODUCT_Unknown) {
            SedRecordProductDetection(result.IdentifiedSandbox);
        }
    }

    /* ===== 缓存与回调 ===== */
    AcquireSRWLockExclusive(&g_SedState.CacheLock);
    g_SedState.Cache.Result = result;
    GetSystemTimeAsFileTime((LPFILETIME)&g_SedState.Cache.TimestampFileTime);
    g_SedState.Cache.Valid = TRUE;
    ReleaseSRWLockExclusive(&g_SedState.CacheLock);

    SedInvokeCallbacks(&result);

    *Result = result;
    return STATUS_SUCCESS;
}

/*++

SedQuickScan

    快速短路检查（最可靠指示器）：
    沙箱 DLL → 互斥体 → 进程 → 内存 → CPU → 运行时长。

--*/
_Use_decl_annotations_
BOOLEAN
SedQuickScan(
    VOID
    )
{
    ULONG i;

    if (!SedStateInitialized()) {
        return FALSE;
    }

    /* 1. 沙箱 DLL */
    for (i = 0; i < SED_ARRAY_COUNT(g_SedQuickDlls); ++i) {
        if (GetModuleHandleW(g_SedQuickDlls[i]) != NULL) {
            return TRUE;
        }
    }

    /* 2. 沙箱互斥体 */
    for (i = 0; i < SED_ARRAY_COUNT(g_SedQuickMutexes); ++i) {
        HANDLE hMutex = OpenMutexW(SYNCHRONIZE, FALSE, g_SedQuickMutexes[i]);
        if (hMutex != NULL) {
            CloseHandle(hMutex);
            return TRUE;
        }
    }

    /* 3. 沙箱进程 */
    for (i = 0; i < SED_ARRAY_COUNT(g_SedQuickProcesses); ++i) {
        if (SedIsSandboxProcessRunning(g_SedQuickProcesses[i])) {
            return TRUE;
        }
    }

    /* 4. 硬件快速检查 */
    {
        MEMORYSTATUSEX memStatus;
        SYSTEM_INFO sysInfo;

        RtlZeroMemory(&memStatus, sizeof(memStatus));
        memStatus.dwLength = sizeof(memStatus);
        if (GlobalMemoryStatusEx(&memStatus)) {
            if (memStatus.ullTotalPhys < SED_SUSPICIOUS_RAM_BYTES) {
                return TRUE;
            }
        }

        GetSystemInfo(&sysInfo);
        if (sysInfo.dwNumberOfProcessors <= SED_SUSPICIOUS_CPU_CORES) {
            return TRUE;
        }
    }

    /* 5. 运行时长快速检查 */
    if (GetTickCount64() < SED_VERY_SUSPICIOUS_UPTIME_MS) {
        return TRUE;
    }

    return FALSE;
}

/**************************************************/
/*          公共 API — 专项查询                    */
/**************************************************/

/*++

SedIsSandboxProductDetected

    扫描工件并判断指定沙箱产品是否被识别。

--*/
_Use_decl_annotations_
BOOLEAN
SedIsSandboxProductDetected(
    _In_ SED_PRODUCT Product
    )
{
    SED_ARTIFACT_ANALYSIS artifacts;
    ULONG i;

    RtlZeroMemory(&artifacts, sizeof(artifacts));
    if (!NT_SUCCESS(SedScanArtifacts(&artifacts))) {
        return FALSE;
    }

    for (i = 0; i < artifacts.IdentifiedProductCount; ++i) {
        if (artifacts.IdentifiedProducts[i] == Product) {
            return TRUE;
        }
    }
    return FALSE;
}

/*++

SedGetSystemUptime

    系统运行时间（毫秒）。

--*/
_Use_decl_annotations_
ULONGLONG
SedGetSystemUptime(
    VOID
    )
{
    return GetTickCount64();
}

/*++

SedGetScreenResolution

    获取主屏幕分辨率。

--*/
_Use_decl_annotations_
VOID
SedGetScreenResolution(
    _Out_ PULONG Width,
    _Out_ PULONG Height
    )
{
    if (Width != NULL) {
        *Width = (ULONG)GetSystemMetrics(SM_CXSCREEN);
    }
    if (Height != NULL) {
        *Height = (ULONG)GetSystemMetrics(SM_CYSCREEN);
    }
}

/*++

SedIsSandboxDllLoaded

    检查 DLL 是否已加载到当前进程。

--*/
_Use_decl_annotations_
BOOLEAN
SedIsSandboxDllLoaded(
    _In_ PCWSTR DllName
    )
{
    if (DllName == NULL || DllName[0] == L'\0') {
        return FALSE;
    }
    return (GetModuleHandleW(DllName) != NULL);
}

/*++

SedIsSandboxProcessRunning

    按进程名（大小写不敏感）检测进程是否在运行。

--*/
_Use_decl_annotations_
BOOLEAN
SedIsSandboxProcessRunning(
    _In_ PCWSTR ProcessName
    )
{
    HANDLE snapshot;
    PROCESSENTRY32W pe;
    WCHAR lowerTarget[SED_MAX_NAME];
    BOOLEAN found = FALSE;

    if (ProcessName == NULL || ProcessName[0] == L'\0') {
        return FALSE;
    }

    SED_WCOPY(lowerTarget, ProcessName, SED_ARRAY_COUNT(lowerTarget));
    SedToLowerW(lowerTarget);

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    RtlZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snapshot, &pe)) {
        do {
            WCHAR currentName[SED_MAX_NAME];
            SED_WCOPY(currentName, pe.szExeFile, SED_ARRAY_COUNT(currentName));
            SedToLowerW(currentName);
            if (wcscmp(currentName, lowerTarget) == 0) {
                found = TRUE;
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return found;
}

/*++

SedDoesMutexExist

    检查命名互斥体是否存在。

--*/
_Use_decl_annotations_
BOOLEAN
SedDoesMutexExist(
    _In_ PCWSTR MutexName
    )
{
    HANDLE hMutex;

    if (MutexName == NULL || MutexName[0] == L'\0') {
        return FALSE;
    }

    hMutex = OpenMutexW(SYNCHRONIZE, FALSE, MutexName);
    if (hMutex != NULL) {
        CloseHandle(hMutex);
        return TRUE;
    }
    return FALSE;
}

/* === Part 5 结束：系统扫描/专项查询 === */

/**************************************************/
/*       Part 6：人机交互检测                      */
/**************************************************/

/* 内部采样点（固定容量：50ms 采样 × 最长 60s = 1200 点，留裕量） */
#define SED_MAX_MOUSE_SAMPLES  2048

typedef struct _SED_TRACK_POINT {
    LONG      X;
    LONG      Y;
    ULONGLONG Tick;
} SED_TRACK_POINT;

/* TLS 状态（跨调用污染防护）：每次调用开头重置 */
static __declspec(thread) BOOLEAN sedTlsLastLeftButton = FALSE;
static __declspec(thread) BOOLEAN sedTlsLastRightButton = FALSE;
static __declspec(thread) BOOLEAN sedTlsPreviousKeys[256];

/*++

SedCalculateMousePathEntropy

    鼠标轨迹角度分布 Shannon 熵（8 桶），归一化至 0.0-1.0。
    人类轨迹转向角度分布更均匀 → 熵更高；机器人轨迹近似直线 → 熵趋近 0。

--*/
static DOUBLE
SedCalculateMousePathEntropy(
    _In_reads_(Count) const SED_TRACK_POINT* Movements,
    _In_ ULONG Count
    )
{
    ULONG histogram[8];
    DOUBLE entropy = 0.0;
    DOUBLE total;
    ULONG i;

    if (Movements == NULL || Count < 3) {
        return 0.0;
    }

    RtlZeroMemory(histogram, sizeof(histogram));

    for (i = 1; i + 1 < Count; ++i) {
        DOUBLE dx1 = (DOUBLE)(Movements[i].X - Movements[i - 1].X);
        DOUBLE dy1 = (DOUBLE)(Movements[i].Y - Movements[i - 1].Y);
        DOUBLE dx2 = (DOUBLE)(Movements[i + 1].X - Movements[i].X);
        DOUBLE dy2 = (DOUBLE)(Movements[i + 1].Y - Movements[i].Y);
        DOUBLE len1 = sqrt(dx1 * dx1 + dy1 * dy1);
        DOUBLE len2 = sqrt(dx2 * dx2 + dy2 * dy2);
        DOUBLE cosAngle;
        DOUBLE angle;
        ULONG bucket;

        if (len1 <= 0.001 || len2 <= 0.001) {
            continue;
        }

        cosAngle = (dx1 * dx2 + dy1 * dy2) / (len1 * len2);
        if (cosAngle > 1.0)  cosAngle = 1.0;
        if (cosAngle < -1.0) cosAngle = -1.0;
        angle = acos(cosAngle);

        /* 分桶：0-45°, 45-90° ... （0..7） */
        bucket = (ULONG)((angle / M_PI) * 8.0);
        if (bucket > 7) bucket = 7;
        ++histogram[bucket];
    }

    total = 0.0;
    for (i = 0; i < 8; ++i) {
        total += (DOUBLE)histogram[i];
    }
    if (total < 1.0) {
        return 0.0;
    }

    for (i = 0; i < 8; ++i) {
        if (histogram[i] > 0) {
            DOUBLE p = (DOUBLE)histogram[i] / total;
            entropy -= p * (log(p) / log(2.0));   /* log2(p) */
        }
    }

    /* 归一化：max entropy = log2(8) = 3.0 */
    return entropy / 3.0;
}

/*++

SedCalculateStraightLineRatio

    直线距离 / 实际路径长度。1.0 = 完美直线（机器人特征）。

--*/
static DOUBLE
SedCalculateStraightLineRatio(
    _In_reads_(Count) const SED_TRACK_POINT* Movements,
    _In_ ULONG Count
    )
{
    DOUBLE pathLength = 0.0;
    DOUBLE dx;
    DOUBLE dy;
    DOUBLE straightDistance;
    ULONG i;

    if (Movements == NULL || Count < 2) {
        return 1.0;
    }

    for (i = 1; i < Count; ++i) {
        dx = (DOUBLE)(Movements[i].X - Movements[i - 1].X);
        dy = (DOUBLE)(Movements[i].Y - Movements[i - 1].Y);
        pathLength += sqrt(dx * dx + dy * dy);
    }

    dx = (DOUBLE)(Movements[Count - 1].X - Movements[0].X);
    dy = (DOUBLE)(Movements[Count - 1].Y - Movements[0].Y);
    straightDistance = sqrt(dx * dx + dy * dy);

    if (pathLength < 0.001) {
        return 1.0;
    }

    return straightDistance / pathLength;
}

/*++

SedAnalyzeHumanInteraction

    在监控窗口内采样鼠标/键盘/点击行为：
      - 鼠标移动计数、距离、路径熵、直线段比例
      - 点击与按键的"上升沿"计数（按住不计）
    输出人类/机器人/模拟交互置信度。

--*/
_Use_decl_annotations_
NTSTATUS
SedAnalyzeHumanInteraction(
    _In_ ULONG MonitoringDurationMs,
    _Out_ PSED_HUMAN_INTERACTION Analysis
    )
{
    SED_HUMAN_INTERACTION analysis;
    SED_CONFIG currentConfig;
    SED_TRACK_POINT samples[SED_MAX_MOUSE_SAMPLES];
    ULONG sampleCount = 0;
    POINT lastPos;
    ULONG durationMs;
    const ULONG sampleIntervalMs = 50;
    ULONG samples;
    ULONGLONG startTick;
    ULONGLONG endTick;
    ULONGLONG totalTimeMs;
    ULONGLONG distance = 0;
    BOOLEAN hasMovement;
    BOOLEAN hasDistance;
    BOOLEAN hasNaturalPath;
    ULONG i;

    if (Analysis == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&analysis, sizeof(analysis));

    /* 监控时长钳制 */
    durationMs = (MonitoringDurationMs < SED_MIN_INTERACTION_MS) ? SED_MIN_INTERACTION_MS :
                 (MonitoringDurationMs > SED_MAX_INTERACTION_MS) ? SED_MAX_INTERACTION_MS :
                 MonitoringDurationMs;
    analysis.MonitoringDurationMs = durationMs;

    InterlockedIncrement64(&g_SedState.Stats.HumanInteractionChecks);
    SedGetConfig(&currentConfig);

    /* 重置 TLS 状态，避免上次调用尾态导致首次采样的"幽灵跳变" */
    sedTlsLastLeftButton = FALSE;
    sedTlsLastRightButton = FALSE;
    RtlZeroMemory(sedTlsPreviousKeys, sizeof(sedTlsPreviousKeys));

    startTick = GetTickCount64();

    GetCursorPos(&lastPos);
    if (sampleCount < SED_MAX_MOUSE_SAMPLES) {
        samples[sampleCount].X = lastPos.x;
        samples[sampleCount].Y = lastPos.y;
        samples[sampleCount].Tick = startTick;
        ++sampleCount;
    }

    samples = durationMs / sampleIntervalMs;

    for (i = 0; i < samples; ++i) {
        POINT currentPos;
        BOOLEAN leftDown;
        BOOLEAN rightDown;
        BOOLEAN currentKeys[256];
        int key;

        Sleep(sampleIntervalMs);
        GetCursorPos(&currentPos);

        /* 鼠标移动 */
        if (currentPos.x != lastPos.x || currentPos.y != lastPos.y) {
            LONG dx;
            LONG dy;

            ++analysis.MouseMovementCount;
            dx = currentPos.x - lastPos.x;
            dy = currentPos.y - lastPos.y;
            distance += (ULONGLONG)sqrt((DOUBLE)(dx * dx) + (DOUBLE)(dy * dy));

            if (sampleCount < SED_MAX_MOUSE_SAMPLES) {
                samples[sampleCount].X = currentPos.x;
                samples[sampleCount].Y = currentPos.y;
                samples[sampleCount].Tick = GetTickCount64();
                ++sampleCount;
            }
        }
        lastPos = currentPos;

        /* 点击（状态变化检测，按住不重复计数） */
        leftDown  = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
        rightDown = (GetAsyncKeyState(VK_RBUTTON) & 0x8000) != 0;

        if (leftDown && !sedTlsLastLeftButton) {
            ++analysis.LeftClickCount;
            ++analysis.MouseClickCount;
        }
        if (rightDown && !sedTlsLastRightButton) {
            ++analysis.RightClickCount;
            ++analysis.MouseClickCount;
        }
        sedTlsLastLeftButton = leftDown;
        sedTlsLastRightButton = rightDown;

        /* 键盘（仅统计 UP→DOWN 的新按压） */
        RtlZeroMemory(currentKeys, sizeof(currentKeys));
        for (key = 0x08; key <= 0xFE; ++key) {
            if (GetAsyncKeyState(key) & 0x8000) {
                currentKeys[key] = TRUE;
            }
        }
        for (key = 0x08; key <= 0xFE; ++key) {
            if (currentKeys[key] && !sedTlsPreviousKeys[key]) {
                ++analysis.KeyPressCount;
            }
        }
        RtlCopyMemory(sedTlsPreviousKeys, currentKeys, sizeof(currentKeys));
    }

    endTick = GetTickCount64();
    analysis.MouseDistanceTraveled = distance;

    /* 平均速度（像素/秒） */
    totalTimeMs = endTick - startTick;
    if (totalTimeMs > 0) {
        analysis.AvgMouseVelocity = (DOUBLE)analysis.MouseDistanceTraveled /
                                    ((DOUBLE)totalTimeMs / 1000.0);
    }

    /* 路径熵与直线比 */
    if (sampleCount >= 3) {
        analysis.PathEntropy = SedCalculateMousePathEntropy(samples, sampleCount);
        analysis.StraightLineRatio = SedCalculateStraightLineRatio(samples, sampleCount);
    }

    /* 决策（与源语义一致） */
    hasMovement  = analysis.MouseMovementCount >= currentConfig.MinMouseMovements;
    hasDistance  = analysis.MouseDistanceTraveled >= currentConfig.MinMouseDistance;
    hasNaturalPath = analysis.StraightLineRatio < SED_MAX_STRAIGHT_LINE_RATIO;

    if (hasMovement && hasDistance && hasNaturalPath) {
        analysis.Result = SED_INTERACTION_HumanDetected;
        analysis.HumanConfidence = 80.0f + (FLOAT)analysis.PathEntropy * 20.0f;
    } else if (hasMovement && analysis.StraightLineRatio >= SED_MAX_STRAIGHT_LINE_RATIO) {
        analysis.Result = SED_INTERACTION_BotPatterns;
        analysis.BotConfidence = 70.0f + (FLOAT)analysis.StraightLineRatio * 30.0f;
    } else if (hasMovement) {
        analysis.Result = SED_INTERACTION_SimulatedInteraction;
        analysis.SimulatedConfidence = 60.0f;
    } else {
        analysis.Result = SED_INTERACTION_NoInteraction;
        analysis.BotConfidence = 90.0f;
    }

    analysis.HumanConfidence = SED_CLAMP_FLOAT(analysis.HumanConfidence, 0.0f, 100.0f);
    analysis.BotConfidence   = SED_CLAMP_FLOAT(analysis.BotConfidence, 0.0f, 100.0f);

    /* 发现项 */
    analysis.FindingCount = 0;
    if (!hasMovement && analysis.FindingCount < 8) {
        SED_WCOPY(analysis.Findings[analysis.FindingCount++],
                  L"No significant mouse movement detected", SED_MAX_DESC);
    }
    if (analysis.StraightLineRatio >= SED_MAX_STRAIGHT_LINE_RATIO &&
        analysis.FindingCount < 8) {
        SED_WCOPY(analysis.Findings[analysis.FindingCount++],
                  L"Mouse movements appear robotic (high straight-line ratio)",
                  SED_MAX_DESC);
    }
    if (analysis.MouseClickCount == 0 && analysis.KeyPressCount == 0 &&
        analysis.FindingCount < 8) {
        SED_WCOPY(analysis.Findings[analysis.FindingCount++],
                  L"No user input (clicks/keys) detected", SED_MAX_DESC);
    }

    analysis.AnalysisComplete = TRUE;

    *Analysis = analysis;
    return STATUS_SUCCESS;
}

/*++

SedVerifyHumanInteraction

    快速判定是否存在人类交互。

--*/
_Use_decl_annotations_
BOOLEAN
SedVerifyHumanInteraction(
    _In_ ULONG MonitoringDurationMs
    )
{
    SED_HUMAN_INTERACTION analysis;

    RtlZeroMemory(&analysis, sizeof(analysis));
    if (!NT_SUCCESS(SedAnalyzeHumanInteraction(MonitoringDurationMs, &analysis))) {
        return FALSE;
    }
    return (analysis.Result == SED_INTERACTION_HumanDetected);
}

/* === Part 6 结束：人机交互检测 === */

/**************************************************/
/*   Part 7a：类型B 进程分析 — PE 导入解析          */
/**************************************************/

/* 内部 PE 上下文（文件模式，仅节表/导入表访问） */
typedef struct _SED_PE_FILE {
    const UINT8*               Data;
    SIZE_T                     Size;
    BOOLEAN                    Is64Bit;
    const IMAGE_SECTION_HEADER* Sections;
    ULONG                      SectionCount;
    ULONG                      ImportDirRva;
    ULONG                      ImportDirSize;
} SED_PE_FILE;

/*++

SedPeRvaToOffset

    RVA → 文件偏移（节内映射；头部区 RVA 直接按平铺处理）。

--*/
static BOOLEAN
SedPeRvaToOffset(
    _In_ const SED_PE_FILE* Pe,
    _In_ ULONG Rva,
    _Out_ PSIZE_T Offset
    )
{
    ULONG i;

    if (Pe == NULL || Offset == NULL || Pe->Data == NULL) {
        return FALSE;
    }

    /* 头部区（RVA 小于首个节 VA 前 0x1000 对齐，直接按平铺近似） */
    if (Pe->SectionCount == 0) {
        if (Rva < Pe->Size) {
            *Offset = Rva;
            return TRUE;
        }
        return FALSE;
    }

    for (i = 0; i < Pe->SectionCount; ++i) {
        const IMAGE_SECTION_HEADER* s = &Pe->Sections[i];
        ULONG extent = (s->Misc.VirtualSize > s->SizeOfRawData)
            ? s->Misc.VirtualSize : s->SizeOfRawData;

        if (Rva >= s->VirtualAddress && Rva < s->VirtualAddress + extent) {
            if (s->SizeOfRawData == 0) {
                return FALSE;
            }
            *Offset = s->PointerToRawData + ((SIZE_T)Rva - s->VirtualAddress);
            return (*Offset < Pe->Size);
        }
    }
    return FALSE;
}

/*++

SedPeLoad

    读取磁盘 PE 文件到堆缓冲并初始化解析上下文。
    调用者负责 HeapFree(*OutData)。

--*/
static BOOLEAN
SedPeLoad(
    _In_ PCWSTR Path,
    _Out_ PBYTE* OutData,
    _Out_ PSIZE_T OutSize,
    _Out_ SED_PE_FILE* Pe
    )
{
    HANDLE hFile;
    LARGE_INTEGER fileSize;
    PBYTE data;
    DWORD bytesRead;
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS* nt;

    if (Path == NULL || OutData == NULL || OutSize == NULL || Pe == NULL) {
        return FALSE;
    }

    hFile = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <= 0 ||
        fileSize.QuadPart > (LONGLONG)(256 * 1024 * 1024)) {
        CloseHandle(hFile);
        return FALSE;
    }

    data = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                            (SIZE_T)fileSize.QuadPart);
    if (data == NULL) {
        CloseHandle(hFile);
        return FALSE;
    }

    if (!ReadFile(hFile, data, (DWORD)fileSize.QuadPart, &bytesRead, NULL) ||
        bytesRead != (DWORD)fileSize.QuadPart) {
        HeapFree(GetProcessHeap(), 0, data);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    /* --- 头校验 --- */
    if ((SIZE_T)fileSize.QuadPart < sizeof(IMAGE_DOS_HEADER)) {
        HeapFree(GetProcessHeap(), 0, data);
        return FALSE;
    }
    dos = (const IMAGE_DOS_HEADER*)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        (SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > (SIZE_T)fileSize.QuadPart) {
        HeapFree(GetProcessHeap(), 0, data);
        return FALSE;
    }
    nt = (const IMAGE_NT_HEADERS*)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        HeapFree(GetProcessHeap(), 0, data);
        return FALSE;
    }

    RtlZeroMemory(Pe, sizeof(*Pe));
    Pe->Data = data;
    Pe->Size = (SIZE_T)fileSize.QuadPart;
    Pe->SectionCount = nt->FileHeader.NumberOfSections;

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        const IMAGE_OPTIONAL_HEADER32* opt32 =
            (const IMAGE_OPTIONAL_HEADER32*)&nt->OptionalHeader;
        Pe->Is64Bit = FALSE;
        Pe->ImportDirRva = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        Pe->ImportDirSize = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_OPTIONAL_HEADER64* opt64 =
            (const IMAGE_OPTIONAL_HEADER64*)&nt->OptionalHeader;
        Pe->Is64Bit = TRUE;
        Pe->ImportDirRva = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        Pe->ImportDirSize = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else {
        HeapFree(GetProcessHeap(), 0, data);
        return FALSE;
    }

    /* 节表边界校验 */
    if (Pe->SectionCount > 0) {
        const UINT8* p = (const UINT8*)IMAGE_FIRST_SECTION(nt);
        if ((SIZE_T)(p - data) + (SIZE_T)Pe->SectionCount * sizeof(IMAGE_SECTION_HEADER)
            > Pe->Size) {
            HeapFree(GetProcessHeap(), 0, data);
            RtlZeroMemory(Pe, sizeof(*Pe));
            return FALSE;
        }
        Pe->Sections = (const IMAGE_SECTION_HEADER*)p;
    }

    *OutData = data;
    *OutSize = Pe->Size;
    return TRUE;
}

/*++

SedPeImportsContain

    遍历 PE 导入表，判断函数 `FunctionName` 是否被导入。
    命中时（可选）经 OutWide 输出宽字符函数名。

--*/
static BOOLEAN
SedPeImportsContain(
    _In_ const SED_PE_FILE* Pe,
    _In_ PCSTR FunctionName,
    _Out_opt_ _Out_writes_(OutChars) PWSTR OutWide,
    _In_ SIZE_T OutChars
    )
{
    SIZE_T idescOff;
    const IMAGE_IMPORT_DESCRIPTOR* idesc;
    SIZE_T numDesc;
    SIZE_T i;

    if (Pe == NULL || Pe->Data == NULL || FunctionName == NULL ||
        Pe->ImportDirRva == 0 || Pe->ImportDirSize == 0) {
        return FALSE;
    }

    if (!SedPeRvaToOffset(Pe, Pe->ImportDirRva, &idescOff) ||
        idescOff + Pe->ImportDirSize > Pe->Size) {
        return FALSE;
    }

    idesc = (const IMAGE_IMPORT_DESCRIPTOR*)(Pe->Data + idescOff);
    numDesc = Pe->ImportDirSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    if (numDesc > 512) numDesc = 512;

    for (i = 0; i < numDesc; ++i) {
        ULONG thunkRva;
        SIZE_T thunkOff;
        ULONG_PTR ordinalFlag;
        SIZE_T orgThunkSize;

        /* 全零描述符 = 表尾 */
        if (idesc[i].OriginalFirstThunk == 0 && idesc[i].FirstThunk == 0) {
            break;
        }

        /* 优先 INT（OriginalFirstThunk），无则用 IAT（FirstThunk） */
        thunkRva = (idesc[i].OriginalFirstThunk != 0)
            ? idesc[i].OriginalFirstThunk : idesc[i].FirstThunk;
        if (!SedPeRvaToOffset(Pe, thunkRva, &thunkOff) ||
            thunkOff >= Pe->Size) {
            continue;
        }

        orgThunkSize = Pe->Is64Bit ? 8 : 4;
        ordinalFlag = Pe->Is64Bit ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;

        for (;;) {
            ULONGLONG thunkValue = 0;
            SIZE_T byNameOff = 0;
            const IMAGE_IMPORT_BY_NAME* byName;

            if (thunkOff + orgThunkSize > Pe->Size) break;
            RtlCopyMemory(&thunkValue, Pe->Data + thunkOff, orgThunkSize);

            if (thunkValue == 0) break;               /* 表尾 */
            if (thunkValue & ordinalFlag) {           /* 序号导入，跳过 */
                thunkOff += orgThunkSize;
                continue;
            }

            if (!SedPeRvaToOffset(Pe, (ULONG)thunkValue, &byNameOff) ||
                byNameOff + sizeof(IMAGE_IMPORT_BY_NAME) > Pe->Size) {
                thunkOff += orgThunkSize;
                continue;
            }
            byName = (const IMAGE_IMPORT_BY_NAME*)(Pe->Data + byNameOff);

            if (strcmp(byName->Name, FunctionName) == 0) {
                if (OutWide != NULL && OutChars > 0) {
                    MultiByteToWideChar(CP_ACP, 0, byName->Name, -1,
                                        OutWide, (int)OutChars);
                }
                return TRUE;
            }

            thunkOff += orgThunkSize;
        }
    }
    return FALSE;
}

/*++

SedCheckTargetSandboxImports

    TYPE B Check 1：解析目标进程映像（磁盘文件）导入表，
    按五类"沙箱检测 API"分类统计，组合计分。

--*/
static VOID
SedCheckTargetSandboxImports(
    _In_ PCWSTR ProcessPath,
    _Inout_ PSED_PROCESS_RESULT Result
    )
{
    PBYTE data = NULL;
    SIZE_T size = 0;
    SED_PE_FILE pe;
    FLOAT importScore = 0.0f;
    SIZE_T hwCount, timCount, envCount, artCount, humCount;
    SIZE_T categoriesHit = 0;
    ULONG i;

    if (ProcessPath == NULL || ProcessPath[0] == L'\0' || Result == NULL) {
        return;
    }

    if (!SedPeLoad(ProcessPath, &data, &size, &pe)) {
        return;
    }

    /* 硬件指纹类 */
    for (i = 0; i < SED_ARRAY_COUNT(g_SedHardwareApis); ++i) {
        if (Result->Imports.HardwareFingerprintingCount >= SED_MAX_HW_IMPORTS) break;
        if (SedPeImportsContain(&pe, g_SedHardwareApis[i],
                                Result->Imports.HardwareFingerprinting[Result->Imports.HardwareFingerprintingCount],
                                SED_MAX_NAME)) {
            ++Result->Imports.HardwareFingerprintingCount;
        }
    }

    /* 时序类 */
    for (i = 0; i < SED_ARRAY_COUNT(g_SedTimingApis); ++i) {
        if (Result->Imports.TimingApiCount >= SED_MAX_TIM_IMPORTS) break;
        if (SedPeImportsContain(&pe, g_SedTimingApis[i],
                                Result->Imports.TimingApis[Result->Imports.TimingApiCount],
                                SED_MAX_NAME)) {
            ++Result->Imports.TimingApiCount;
        }
    }

    /* 环境查询类 */
    for (i = 0; i < SED_ARRAY_COUNT(g_SedEnvironmentApis); ++i) {
        if (Result->Imports.EnvironmentQueryCount >= SED_MAX_ENV_IMPORTS) break;
        if (SedPeImportsContain(&pe, g_SedEnvironmentApis[i],
                                Result->Imports.EnvironmentQueries[Result->Imports.EnvironmentQueryCount],
                                SED_MAX_NAME)) {
            ++Result->Imports.EnvironmentQueryCount;
        }
    }

    /* 工件检测类 */
    for (i = 0; i < SED_ARRAY_COUNT(g_SedArtifactApis); ++i) {
        if (Result->Imports.ArtifactCheckCount >= SED_MAX_ART_IMPORTS) break;
        if (SedPeImportsContain(&pe, g_SedArtifactApis[i],
                                Result->Imports.ArtifactChecks[Result->Imports.ArtifactCheckCount],
                                SED_MAX_NAME)) {
            ++Result->Imports.ArtifactCheckCount;
        }
    }

    /* 人机交互类 */
    for (i = 0; i < SED_ARRAY_COUNT(g_SedHumanInteractionApis); ++i) {
        if (Result->Imports.HumanInteractionCheckCount >= SED_MAX_HUM_IMPORTS) break;
        if (SedPeImportsContain(&pe, g_SedHumanInteractionApis[i],
                                Result->Imports.HumanInteractionChecks[Result->Imports.HumanInteractionCheckCount],
                                SED_MAX_NAME)) {
            ++Result->Imports.HumanInteractionCheckCount;
        }
    }

    HeapFree(GetProcessHeap(), 0, data);

    /* --- 计分（与源组合语义一致） --- */
    hwCount  = Result->Imports.HardwareFingerprintingCount;
    timCount = Result->Imports.TimingApiCount;
    envCount = Result->Imports.EnvironmentQueryCount;
    artCount = Result->Imports.ArtifactCheckCount;
    humCount = Result->Imports.HumanInteractionCheckCount;

    if (hwCount >= 3) importScore += 15.0f;
    else if (hwCount >= 2) importScore += 5.0f;

    if (timCount >= 2 && hwCount >= 2) importScore += 20.0f;

    if (artCount >= 4) importScore += 15.0f;
    else if (artCount >= 2) importScore += 5.0f;

    if (humCount >= 3) importScore += 15.0f;
    else if (humCount >= 2) importScore += 5.0f;

    if (envCount >= 3) importScore += 10.0f;

    /* 跨类组合（最强信号） */
    if (hwCount >= 2) ++categoriesHit;
    if (timCount >= 2) ++categoriesHit;
    if (artCount >= 2) ++categoriesHit;
    if (humCount >= 2) ++categoriesHit;
    if (envCount >= 2) ++categoriesHit;

    if (categoriesHit >= 4) importScore += 25.0f;
    else if (categoriesHit >= 3) importScore += 15.0f;
    else if (categoriesHit >= 2) importScore += 5.0f;

    Result->Imports.Score = (importScore > 100.0f) ? 100.0f : importScore;
}

/* === Part 7a 结束 === */

/**************************************************/
/*   Part 7b：类型B 进程分析 — 内存字符串/代码模式  */
/**************************************************/

/* 宽字节 needle 在字节缓冲内查找（与 std::wstring_view::find 语义一致） */
static BOOLEAN
SedWideNeedleInBytes(
    _In_reads_bytes_(HayBytes) const UCHAR* Haystack,
    _In_ SIZE_T HayBytes,
    _In_ PCWSTR Needle
    )
{
    SIZE_T needleBytes;
    SIZE_T i;

    if (Haystack == NULL || Needle == NULL) {
        return FALSE;
    }
    needleBytes = wcslen(Needle) * sizeof(WCHAR);
    if (needleBytes == 0 || HayBytes < needleBytes) {
        return FALSE;
    }

    for (i = 0; i + needleBytes <= HayBytes; ++i) {
        if (memcmp(Haystack + i, Needle, needleBytes) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/* ANSI（ASCII 子集）needle 查找：取宽串低字节序列 */
static BOOLEAN
SedAnsiNeedleInBytes(
    _In_reads_bytes_(HayBytes) const UCHAR* Haystack,
    _In_ SIZE_T HayBytes,
    _In_ PCWSTR Needle
    )
{
    SIZE_T n;
    SIZE_T i;
    SIZE_T k;

    if (Haystack == NULL || Needle == NULL) {
        return FALSE;
    }
    n = wcslen(Needle);
    if (n == 0 || HayBytes < n) {
        return FALSE;
    }

    for (i = 0; i + n <= HayBytes; ++i) {
        for (k = 0; k < n; ++k) {
            if (Haystack[i + k] != (UCHAR)(Needle[k] & 0xFF)) {
                break;
            }
        }
        if (k == n) {
            return TRUE;
        }
    }
    return FALSE;
}

/* 宽字符串列表去重判断（精确匹配，与源 std::find 一致） */
static BOOLEAN
SedWideListContains(
    _In_reads_(Count) WCHAR(*List)[SED_MAX_NAME],
    _In_ ULONG Count,
    _In_ PCWSTR Item
    )
{
    ULONG i;

    for (i = 0; i < Count; ++i) {
        if (wcscmp(List[i], Item) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/*++

SedCheckTargetSandboxStrings

    TYPE B Check 2：扫描目标进程提交内存中的
    沙箱 DLL / 进程 / 互斥体 / VM 厂商 / 注册表路径字符串
    （宽 + ANSI 两种编码），按命中组合计分。

--*/
static VOID
SedCheckTargetSandboxStrings(
    _In_ HANDLE ProcessHandle,
    _Inout_ PSED_PROCESS_RESULT Result,
    _In_ SIZE_T MaxScanBytes
    )
{
    UCHAR buffer[SED_SCAN_BUFFER_SIZE];
    MEMORY_BASIC_INFORMATION mbi;
    UCHAR* address = NULL;
    SIZE_T totalScanned = 0;
    BOOLEAN done = FALSE;
    ULONG i;

    if (ProcessHandle == NULL || Result == NULL) {
        return;
    }

    while (!done) {
        SIZE_T bytesRead;
        SIZE_T regionScanSize;
        SIZE_T offset = 0;

        if (VirtualQueryEx(ProcessHandle, (PVOID)address, &mbi, sizeof(mbi))
            != sizeof(mbi)) {
            break;
        }
        if (totalScanned >= MaxScanBytes) break;

        /* 指针溢出防护 */
        if (((SIZE_T)mbi.BaseAddress + mbi.RegionSize) < (SIZE_T)mbi.BaseAddress) {
            break;
        }
        address = (UCHAR*)mbi.BaseAddress + mbi.RegionSize;

        if (mbi.State != MEM_COMMIT) continue;
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) continue;

        regionScanSize = (mbi.RegionSize < SED_MAX_REGION_SCAN_BYTES)
            ? mbi.RegionSize : SED_MAX_REGION_SCAN_BYTES;

        while (offset < regionScanSize) {
            SIZE_T chunkSize = regionScanSize - offset;
            if (chunkSize > SED_SCAN_BUFFER_SIZE) chunkSize = SED_SCAN_BUFFER_SIZE;

            if (!ReadProcessMemory(ProcessHandle,
                                   (UCHAR*)mbi.BaseAddress + offset,
                                   buffer, chunkSize, &bytesRead) ||
                bytesRead == 0) {
                break;
            }

            totalScanned += bytesRead;

            /* 宽字符串（大多数 Windows API） */
            /* 沙箱 DLL */
            for (i = 0; i < SED_ARRAY_COUNT(g_SedStringDlls); ++i) {
                if (Result->Strings.SandboxDllNameCount >= SED_MAX_STRING_FINDINGS) break;
                if (SedWideNeedleInBytes(buffer, bytesRead, g_SedStringDlls[i])) {
                    if (!SedWideListContains(Result->Strings.SandboxDllNames,
                                             Result->Strings.SandboxDllNameCount,
                                             g_SedStringDlls[i])) {
                        SED_WCOPY(Result->Strings.SandboxDllNames[Result->Strings.SandboxDllNameCount],
                                  g_SedStringDlls[i], SED_MAX_NAME);
                        ++Result->Strings.SandboxDllNameCount;
                    }
                }
            }
            /* 沙箱进程 */
            for (i = 0; i < SED_ARRAY_COUNT(g_SedStringProcesses); ++i) {
                if (Result->Strings.SandboxProcessNameCount >= SED_MAX_STRING_FINDINGS) break;
                if (SedWideNeedleInBytes(buffer, bytesRead, g_SedStringProcesses[i])) {
                    if (!SedWideListContains(Result->Strings.SandboxProcessNames,
                                             Result->Strings.SandboxProcessNameCount,
                                             g_SedStringProcesses[i])) {
                        SED_WCOPY(Result->Strings.SandboxProcessNames[Result->Strings.SandboxProcessNameCount],
                                  g_SedStringProcesses[i], SED_MAX_NAME);
                        ++Result->Strings.SandboxProcessNameCount;
                    }
                }
            }
            /* 沙箱互斥体 */
            for (i = 0; i < SED_ARRAY_COUNT(g_SedStringMutexes); ++i) {
                if (Result->Strings.SandboxMutexNameCount >= SED_MAX_STRING_FINDINGS) break;
                if (SedWideNeedleInBytes(buffer, bytesRead, g_SedStringMutexes[i])) {
                    if (!SedWideListContains(Result->Strings.SandboxMutexNames,
                                             Result->Strings.SandboxMutexNameCount,
                                             g_SedStringMutexes[i])) {
                        SED_WCOPY(Result->Strings.SandboxMutexNames[Result->Strings.SandboxMutexNameCount],
                                  g_SedStringMutexes[i], SED_MAX_NAME);
                        ++Result->Strings.SandboxMutexNameCount;
                    }
                }
            }
            /* VM 厂商字符串 */
            for (i = 0; i < SED_ARRAY_COUNT(g_SedStringVmVendors); ++i) {
                if (Result->Strings.VmVendorStringCount >= SED_MAX_STRING_FINDINGS) break;
                if (SedWideNeedleInBytes(buffer, bytesRead, g_SedStringVmVendors[i])) {
                    if (!SedWideListContains(Result->Strings.VmVendorStrings,
                                             Result->Strings.VmVendorStringCount,
                                             g_SedStringVmVendors[i])) {
                        SED_WCOPY(Result->Strings.VmVendorStrings[Result->Strings.VmVendorStringCount],
                                  g_SedStringVmVendors[i], SED_MAX_NAME);
                        ++Result->Strings.VmVendorStringCount;
                    }
                }
            }
            /* 沙箱注册表路径 */
            for (i = 0; i < SED_ARRAY_COUNT(g_SedStringRegistryPaths); ++i) {
                if (Result->Strings.SandboxRegistryPathCount >= SED_MAX_STRING_FINDINGS) break;
                if (SedWideNeedleInBytes(buffer, bytesRead, g_SedStringRegistryPaths[i])) {
                    if (!SedWideListContains(Result->Strings.SandboxRegistryPaths,
                                             Result->Strings.SandboxRegistryPathCount,
                                             g_SedStringRegistryPaths[i])) {
                        SED_WCOPY(Result->Strings.SandboxRegistryPaths[Result->Strings.SandboxRegistryPathCount],
                                  g_SedStringRegistryPaths[i], SED_MAX_NAME);
                        ++Result->Strings.SandboxRegistryPathCount;
                    }
                }
            }

            /* ANSI 补充：进程名以窄字符串存储的情况 */
            for (i = 0; i < SED_ARRAY_COUNT(g_SedStringProcesses); ++i) {
                if (Result->Strings.SandboxProcessNameCount >= SED_MAX_STRING_FINDINGS) break;
                if (SedAnsiNeedleInBytes(buffer, bytesRead, g_SedStringProcesses[i])) {
                    if (!SedWideListContains(Result->Strings.SandboxProcessNames,
                                             Result->Strings.SandboxProcessNameCount,
                                             g_SedStringProcesses[i])) {
                        SED_WCOPY(Result->Strings.SandboxProcessNames[Result->Strings.SandboxProcessNameCount],
                                  g_SedStringProcesses[i], SED_MAX_NAME);
                        ++Result->Strings.SandboxProcessNameCount;
                    }
                }
            }

            offset += bytesRead;
            if (totalScanned >= MaxScanBytes) break;
        }

        if (address == NULL) {   /* 不可能发生，防御 */
            done = TRUE;
        }
    }

    /* --- 计分 --- */
    {
        FLOAT stringScore = 0.0f;
        SIZE_T dllCount   = Result->Strings.SandboxDllNameCount;
        SIZE_T procCount  = Result->Strings.SandboxProcessNameCount;
        SIZE_T mutexCount = Result->Strings.SandboxMutexNameCount;
        SIZE_T vmCount    = Result->Strings.VmVendorStringCount;
        SIZE_T regCount   = Result->Strings.SandboxRegistryPathCount;

        if (dllCount >= 3) stringScore += 30.0f;
        else if (dllCount >= 1) stringScore += 15.0f;

        if (procCount >= 5) stringScore += 20.0f;
        else if (procCount >= 2) stringScore += 10.0f;

        if (mutexCount >= 2) stringScore += 25.0f;
        else if (mutexCount >= 1) stringScore += 15.0f;

        if (vmCount >= 3) stringScore += 10.0f;
        else if (vmCount >= 1) stringScore += 5.0f;

        if (regCount >= 3) stringScore += 15.0f;
        else if (regCount >= 1) stringScore += 8.0f;

        Result->Strings.Score = (stringScore > 100.0f) ? 100.0f : stringScore;
    }
}

/*++

SedCheckTargetTimingPatterns

    TYPE B Check 3：扫描目标映像代码节中的
    反沙箱指令模式（源为反汇编器，此处降级为字节模式）：

      0F 31            RDTSC
      0F 01 F9         RDTSCP
      0F A2            CPUID
      ED / EC          IN EAX,DX / IN AL,DX（VMware 背板端口：前 8 字节内 MOV DX,5658h）

    RDTSC 连续两次间距 ≤ ~80 字节 → TimingSandwiches
    CPUID 距上次 RDTSC ≤ ~40 字节    → VmExitProbes
    （间距为反汇编"指令数量"的字节近似，注释保留差异说明）

--*/
static VOID
SedCheckTargetTimingPatterns(
    _In_ PCWSTR ProcessPath,
    _In_ BOOLEAN Is64Bit,
    _Inout_ PSED_PROCESS_RESULT Result,
    _In_ SIZE_T MaxCodeScanBytes
    )
{
    PBYTE data = NULL;
    SIZE_T size = 0;
    SED_PE_FILE pe;
    SIZE_T totalCodeScanned = 0;
    ULONG i;

    UNREFERENCED_PARAMETER(Is64Bit);

    if (ProcessPath == NULL || ProcessPath[0] == L'\0' || Result == NULL) {
        return;
    }

    if (!SedPeLoad(ProcessPath, &data, &size, &pe)) {
        return;
    }

    for (i = 0; i < pe.SectionCount; ++i) {
        const IMAGE_SECTION_HEADER* sec = &pe.Sections[i];
        SIZE_T scanSize;
        SIZE_T fileOff;
        SIZE_T bytesToRead;
        SIZE_T pos;
        SIZE_T lastRdtcOffset = (SIZE_T)-1;

        if ((sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
            continue;
        }
        if (totalCodeScanned >= MaxCodeScanBytes) break;

        /* 文件模式读取，节大小采用磁盘 raw（运行时虚拟节可能更大，属已知差异） */
        scanSize = (sec->SizeOfRawData < SED_MAX_SECTION_SCAN_BYTES)
            ? sec->SizeOfRawData : SED_MAX_SECTION_SCAN_BYTES;
        if (scanSize == 0) continue;

        /* 节范围边界检查（文件越界则裁剪） */
        fileOff = sec->PointerToRawData;
        if (fileOff >= pe.Size) continue;
        if (fileOff + scanSize > pe.Size) {
            scanSize = pe.Size - fileOff;
        }

        bytesToRead = (scanSize < SED_SCAN_BUFFER_SIZE) ? scanSize : SED_SCAN_BUFFER_SIZE;
        {
            UCHAR codeBuffer[SED_SCAN_BUFFER_SIZE];
            SIZE_T remaining = scanSize;
            SIZE_T fileCursor = fileOff;
            SIZE_T scannedInSection = 0;

            while (remaining > 0 && totalCodeScanned < MaxCodeScanBytes) {
                SIZE_T chunk = (remaining < SED_SCAN_BUFFER_SIZE) ? remaining : SED_SCAN_BUFFER_SIZE;

                RtlCopyMemory(codeBuffer, data + fileCursor, chunk);
                totalCodeScanned += chunk;
                remaining -= chunk;
                fileCursor += chunk;

                /* 字节模式扫描 */
                for (pos = 0; pos + 3 < chunk; ++pos) {
                    /* RDTSCP: 0F 01 F9 */
                    if (codeBuffer[pos] == 0x0F && codeBuffer[pos + 1] == 0x01 &&
                        codeBuffer[pos + 2] == 0xF9) {
                        ++Result->CodePatterns.RdtscInstructions;
                        if (lastRdtcOffset != (SIZE_T)-1 &&
                            (scannedInSection + pos - lastRdtcOffset) <= 80) {
                            ++Result->CodePatterns.TimingSandwiches;
                        }
                        lastRdtcOffset = scannedInSection + pos;
                        pos += 2;
                        continue;
                    }
                    /* RDTSC: 0F 31 */
                    if (codeBuffer[pos] == 0x0F && codeBuffer[pos + 1] == 0x31) {
                        ++Result->CodePatterns.RdtscInstructions;
                        if (lastRdtcOffset != (SIZE_T)-1 &&
                            (scannedInSection + pos - lastRdtcOffset) <= 80) {
                            ++Result->CodePatterns.TimingSandwiches;
                        }
                        lastRdtcOffset = scannedInSection + pos;
                        pos += 1;
                        continue;
                    }
                    /* CPUID: 0F A2 */
                    if (codeBuffer[pos] == 0x0F && codeBuffer[pos + 1] == 0xA2) {
                        ++Result->CodePatterns.CpuidInstructions;
                        if (lastRdtcOffset != (SIZE_T)-1 &&
                            (scannedInSection + pos - lastRdtcOffset) <= 40) {
                            ++Result->CodePatterns.VmExitProbes++;
                        }
                        pos += 1;
                        continue;
                    }
                    /* IN EAX,DX (ED) / IN AL,DX (EC)：前 8 字节内 MOV DX,5658h (66 BA 58 56) */
                    if (codeBuffer[pos] == 0xED || codeBuffer[pos] == 0xEC) {
                        SIZE_T lookStart = (pos >= 8) ? (pos - 8) : 0;
                        SIZE_T j;
                        for (j = lookStart; j < pos; ++j) {
                            if (codeBuffer[j] == 0x66 && codeBuffer[j + 1] == 0xBA &&
                                codeBuffer[j + 2] == 0x58 && codeBuffer[j + 3] == 0x56) {
                                ++Result->CodePatterns.PortProbes;
                                break;
                            }
                        }
                    }
                }
                scannedInSection += chunk;
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, data);

    /* --- 计分 --- */
    {
        FLOAT codeScore = 0.0f;

        if (Result->CodePatterns.TimingSandwiches >= 3) codeScore += 35.0f;
        else if (Result->CodePatterns.TimingSandwiches >= 1) codeScore += 20.0f;

        if (Result->CodePatterns.VmExitProbes >= 2) codeScore += 25.0f;
        else if (Result->CodePatterns.VmExitProbes >= 1) codeScore += 15.0f;

        if (Result->CodePatterns.PortProbes >= 1) codeScore += 20.0f;

        if (Result->CodePatterns.CpuidInstructions >= 10) codeScore += 10.0f;

        if (Result->CodePatterns.RdtscInstructions >= 20) codeScore += 10.0f;

        Result->CodePatterns.Score = (codeScore > 100.0f) ? 100.0f : codeScore;
    }
}

/*++

SedCalculateProcessEvasionScore

    三分组加权：导入 0.30 / 字符串 0.40 / 代码 0.30；
    阈值 25 → HasEvasionCapability；附 MITRE 映射。

--*/
static VOID
SedCalculateProcessEvasionScore(
    _Inout_ PSED_PROCESS_RESULT Result
    )
{
    const FLOAT importWeight = 0.30f;
    const FLOAT stringWeight = 0.40f;
    const FLOAT codeWeight   = 0.30f;
    const FLOAT evasionThreshold = 25.0f;
    FLOAT score;

    if (Result == NULL) {
        return;
    }

    score = Result->Imports.Score * importWeight +
            Result->Strings.Score * stringWeight +
            Result->CodePatterns.Score * codeWeight;
    Result->EvasionScore = (score > 100.0f) ? 100.0f : score;
    Result->HasEvasionCapability = (Result->EvasionScore >= evasionThreshold);

    /* MITRE 映射 */
    Result->MitreIdCount = 0;
    if (Result->Imports.Score > 0.0f || Result->Strings.Score > 0.0f ||
        Result->CodePatterns.Score > 0.0f) {
        if (Result->MitreIdCount < SED_MAX_PROC_MITRE) {
            SED_ACOPY(Result->MitreIds[Result->MitreIdCount++], "T1497", 16);
        }
        if (Result->MitreIdCount < SED_MAX_PROC_MITRE) {
            SED_ACOPY(Result->MitreIds[Result->MitreIdCount++], "T1497.001", 16);
        }
    }
    if ((Result->CodePatterns.TimingSandwiches > 0 ||
         Result->CodePatterns.VmExitProbes > 0) &&
        Result->MitreIdCount < SED_MAX_PROC_MITRE) {
        SED_ACOPY(Result->MitreIds[Result->MitreIdCount++], "T1497.003", 16);
    }
    if ((Result->Strings.SandboxProcessNameCount > 0 ||
         Result->Imports.ArtifactCheckCount > 0) &&
        Result->MitreIdCount < SED_MAX_PROC_MITRE) {
        SED_ACOPY(Result->MitreIds[Result->MitreIdCount++], "T1057", 16);
    }
    if (Result->Strings.SandboxRegistryPathCount > 0 &&
        Result->MitreIdCount < SED_MAX_PROC_MITRE) {
        SED_ACOPY(Result->MitreIds[Result->MitreIdCount++], "T1012", 16);
    }
    if (Result->Imports.HumanInteractionCheckCount > 0 &&
        Result->MitreIdCount < SED_MAX_PROC_MITRE) {
        SED_ACOPY(Result->MitreIds[Result->MitreIdCount++], "T1497.002", 16);
    }
}

/**************************************************/
/*          公共 API — 类型B 进程分析              */
/**************************************************/

/*++

SedAnalyzeProcess

    单进程反沙箱能力分析：
      1. 导入表（磁盘）  2. 内存字符串（运行时）  3. 代码模式（磁盘）
    命中即回调 + 统计（与 ScanSystem 复用同一计数）。

--*/
_Use_decl_annotations_
NTSTATUS
SedAnalyzeProcess(
    _In_  HANDLE                ProcessHandle,
    _In_  ULONG                 ProcessId,
    _In_opt_ PSED_PROCESS_CONFIG Config,
    _Out_ PSED_PROCESS_RESULT   Result
    )
{
    SED_PROCESS_CONFIG config;
    SED_PROCESS_RESULT result;
    WCHAR processPath[SED_MAX_PATH];
    DWORD pathLen = SED_MAX_PATH;
    BOOLEAN is64Bit = TRUE;
    BOOL isWow64 = FALSE;
    ULONGLONG startTick;
    ULONGLONG endTick;
    SED_PROCESS_CALLBACK callback = NULL;
    PVOID callbackCtx = NULL;

    if (ProcessHandle == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!SedStateInitialized()) {
        return STATUS_NOT_INITIALIZED;
    }

    /* 配置：默认或调用者提供 */
    if (Config != NULL) {
        config = *Config;
    } else {
        RtlZeroMemory(&config, sizeof(config));
        config.CheckImports = TRUE;
        config.CheckMemoryStrings = TRUE;
        config.CheckCodePatterns = TRUE;
        config.MaxMemoryScanBytes = 64ULL * 1024 * 1024;   /* 64MB */
        config.MaxCodeScanBytes   = 4ULL * 1024 * 1024;    /* 4MB */
    }

    RtlZeroMemory(&result, sizeof(result));
    result.ProcessId = ProcessId;
    startTick = GetTickCount64();

    /* 映像路径：内核上下文优先，否则运行时查询 */
    processPath[0] = L'\0';
    if (config.HasKernelCtx && config.KernelContext.ImagePath[0] != L'\0') {
        SED_WCOPY(processPath, config.KernelContext.ImagePath, SED_ARRAY_COUNT(processPath));
    } else {
        if (!QueryFullProcessImageNameW(ProcessHandle, 0, processPath, &pathLen)) {
            processPath[0] = L'\0';
        }
    }

    if (IsWow64Process(ProcessHandle, &isWow64)) {
        is64Bit = !isWow64;
    }

    /* TYPE B Check 1-3 */
    if (config.CheckImports && processPath[0] != L'\0') {
        SedCheckTargetSandboxImports(processPath, &result);
    }
    if (config.CheckMemoryStrings) {
        SedCheckTargetSandboxStrings(ProcessHandle, &result,
                                     config.MaxMemoryScanBytes);
    }
    if (config.CheckCodePatterns && processPath[0] != L'\0') {
        SedCheckTargetTimingPatterns(processPath, is64Bit, &result,
                                     config.MaxCodeScanBytes);
    }

    SedCalculateProcessEvasionScore(&result);

    endTick = GetTickCount64();
    result.AnalysisDurationUs = (endTick - startTick) * 1000;

    /* 回调（锁内取指针，锁外调用） */
    if (result.HasEvasionCapability) {
        AcquireSRWLockShared(&g_SedState.ConfigLock);
        callback = g_SedState.ProcessCallback;
        callbackCtx = g_SedState.ProcessCallbackContext;
        ReleaseSRWLockShared(&g_SedState.ConfigLock);

        if (callback != NULL) {
            callback(&result, callbackCtx);
        }
    }

    /* 统计 */
    InterlockedIncrement64(&g_SedState.Stats.TotalScans);
    if (result.HasEvasionCapability) {
        InterlockedIncrement64(&g_SedState.Stats.SandboxesDetected);
    }
    SedUpdateEma(&g_SedState.Stats.AvgAnalysisDurationUs, result.AnalysisDurationUs);

    *Result = result;
    return STATUS_SUCCESS;
}

/*++

SedAnalyzeProcessById

    按 PID 打开进程后委托 SedAnalyzeProcess。

--*/
_Use_decl_annotations_
NTSTATUS
SedAnalyzeProcessById(
    _In_  ULONG                 ProcessId,
    _In_opt_ PSED_PROCESS_CONFIG Config,
    _Out_ PSED_PROCESS_RESULT   Result
    )
{
    HANDLE hProcess;
    NTSTATUS status;

    if (Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                           FALSE, ProcessId);
    if (hProcess == NULL) {
        return STATUS_ACCESS_DENIED;
    }

    status = SedAnalyzeProcess(hProcess, ProcessId, Config, Result);
    CloseHandle(hProcess);
    return status;
}

/*++

SedSetProcessDetectionCallback

    设置进程级检测回调（ConfigLock 保护）。

--*/
_Use_decl_annotations_
VOID
SedSetProcessDetectionCallback(
    _In_opt_ SED_PROCESS_CALLBACK Callback,
    _In_opt_ PVOID                Context
    )
{
    AcquireSRWLockExclusive(&g_SedState.ConfigLock);
    g_SedState.ProcessCallback = Callback;
    g_SedState.ProcessCallbackContext = Context;
    ReleaseSRWLockExclusive(&g_SedState.ConfigLock);
}

/* === Part 7b 结束：类型B 进程分析 === */

/* 文件末尾哨兵 */