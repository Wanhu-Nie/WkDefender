/**************************************************/
/*  WkDefender IOA — 内核利用 (KED) 模式检测器实现  */
/*                                                  */
/*  迁移自 ShadowStrike KernelExploitDetector.cpp   */
/*  (v3.0.1) 功能重实现 (C 重写), 非源码复制。      */
/*                                                  */
/*  已核实并复用 WkDefender 现有设施:                */
/*    - Common/BCrypUtils.h  IocScanner_            */
/*      ComputeFileHashMulti (MD5/SHA1/SHA256)       */
/*      → 替代 SS HashUtils                          */
/*    - vcxproj 已链接 wintrust.lib / version.lib    */
/*  新引入链接: psapi.lib (#pragma, 多文件先例)。    */
/*                                                  */
/*  与 SS 源码的对齐/差异 (注释就地标注):            */
/*    - driversBlocked 计数 SS 无自增点 (stub),      */
/*      此处按配置语义补齐                           */
/*    - kernelModulePaths 路径格式归一化 (\SystemRoot\ */
/*      \??\C:\ 设备路径 → DOS), SS 直接比较导致     */
/*      三方交叉永不匹配的缺陷此处修正                */
/*    - BSOD MDMP/SiPolicy 缺口与 SS 一致 (遥测)     */
/**************************************************/

#include "KedPatternDetector.h"

#include <windows.h>
#include <ntstatus.h>
#include <psapi.h>
#include <softpub.h>
#include <wintrust.h>
#include <winreg.h>
#include <winver.h>
#include <string.h>
#include <stdio.h>

#include "../../Common/BCrypUtils.h"    /* IocScanner_ComputeFileHashMulti */
#include "../../IOC/IocTypes.h"         /* WKD_FILE_HASH_SET / WKD_HASH_ALG */

#pragma comment(lib, "psapi.lib")       /* EnumDeviceDrivers / GetDeviceDriverFileNameW */

/**************************************************/
/*               内置常量                           */
/**************************************************/

/* SS 已知易受攻击驱动 IOCTL (KernelExploitConstants::VULNERABLE_IOCTLS) */
static const ULONG g_VulnerableIoctls[KED_VULNERABLE_IOCTLS_COUNT] = {
    0x9C406104,     /* gdrv.sys 物理内存读 */
    0x9C406108,     /* gdrv.sys 物理内存写 */
    0x9C40A0D8,     /* MSI 驱动 */
    0x80002000,     /* RWEverything */
    0x222808,       /* CPU-Z (易受攻击) */
    0x226003        /* ASUS 驱动 */
};

/* 系统服务注册表路径 (FindHiddenDrivers 用) */
#define KED_SERVICES_REG_PATH   L"SYSTEM\\CurrentControlSet\\Services"

/* DUMP_HEADER64 字段偏移 (SS AnalyzeBSODDump 注释) */
#define KED_DUMP_BUGCHECK_CODE_OFFSET   0x38
#define KED_DUMP_BUGCHECK_PARAM_OFFSET  0x40

/* MDMP/PAGE/DUMP 魔数 (SS) */
#define KED_MDMP_SIGNATURE      0x504D444Du  /* 'MDMP' */
#define KED_PAGE_SIGNATURE      0x45474150u  /* 'PAGE' */
#define KED_DUMP_SIGNATURE      0x504D5544u  /* 'DUMP' */
#define KED_DU64_SIGNATURE      0x34365544u  /* 'DU64' */

/**************************************************/
/*               内置 LOLDrivers 库                */
/*  BUILTIN_LOL_DRIVERS (15 条基线,        */
/*  不实现在线拉取, 注释见头文件)。                */
/**************************************************/

typedef struct _KED_LOL_DRIVER_ENTRY {
    const char* Sha256Hex;
    const char* Cves;
    KED_VULN_CLASS VulnClass;
    const char* DriverName;
} KED_LOL_DRIVER_ENTRY;

static const KED_LOL_DRIVER_ENTRY g_BuiltinLolDrivers[] = {
    {"1A96F0AB9A6328A07CE61419802D0D1C8C6E3E1BC4E12A8E3C4C1D7F0D7E6C8B",
     "CVE-2019-16098,CVE-2020-12138", KedVuln_Multiple, "RTCore64.sys"},
    {"7467DA0C5E9EEF1E4FBD21433C1B087FFD96AD8C6E1CD3E0F3C9C1F0F0F0F0F0",
     "CVE-2021-21551", KedVuln_Multiple, "DBUtil_2_3.sys"},
    {"F38A2D2BB24F1E78F6E343F7845FAB4389E57B3F5A8EA3D9258B89F08E3EBB34",
     "CVE-2019-18845", KedVuln_ArbitraryPhysAccess, "AsIO.sys"},
    {"887BA3C6E7E1FFD49E0D3DAAF3E9F86E53C67BF3E0A89693D29D81BD4A856372",
     "CVE-2020-12138", KedVuln_Multiple, "RTCore64.sys"},
    {"A5CD63E41A1E6385B3B4A17E08F6626BEB12CE40DD0B3E28F0D66026E68C44CD",
     "CVE-2019-16098", KedVuln_Multiple, "RTCore64.sys"},
    {"01AA29F68D8A5B9E6D4A1E3B75CFD97B7B29F50E4F8E047CB18EF56C1CC9EBAF",
     "CVE-2021-34550", KedVuln_PrivilegeEscalation, "lenovo.sys"},
    {"B9C5384E0DA2CB2449033E3B9AC30E3ED9A5B3D98F53E19E4F88353962E2C55B",
     "CVE-2021-21551", KedVuln_Multiple, "DBUtil_2_3.sys"},
    {"D708F9A6F49AE0466E3DE078E0A96509E1A3AB9DFEB85FC6FC5D3B8B9D772025",
     "CVE-2021-36755", KedVuln_DenialOfService, "heat.exe"},
    {"5059418D9D2A03F09543E0E8E650A3AA7B121ACEF3F065FD44AE6643B7AB71FC",
     "CVE-2021-36755", KedVuln_Multiple, "heat.exe"},
    {"A3D55DD773CD002603BEA76574C9FA41B1FFD3BB8BEE50DA4AF35F9A9E509CF2",
     "CVE-2020-12138", KedVuln_Multiple, "gdrv.sys"},
    {"0296E2F1AA06F0E6AF52CBFA4E0A6E74E938A0FA8CEC4E3C4ABD5F8C4B47A68D",
     "CVE-2023-40140", KedVuln_Multiple, "libishield.sys"},
    {"C1666FB58F9F4B46B8DE41E5D08BF625037D781C93B2A25945E3C935B3596264",
     "CVE-2024-21351", KedVuln_Multiple, "HwOs2Dat.sys"},
    {"C172857F45E78BECB1C34B4BA2E4EA3A7E04A66AFC922CA8A17E3E52CFA25B8F",
     "CVE-2024-21345", KedVuln_Multiple, "BS_RCIO64.sys"},
    {"ED9EA6A9337E3FC3E6D0D4AAE70A1D361F8B1C9AF80FEFA7C6C7AF7C32F8B44B",
     "CVE-2023-6241", KedVuln_Multiple, "gameux.dll"},
    {"E0552F54E62C8EABFDAA02513B3C9A8AF9A7E38D02E48DFE8B553F13B4DC9A85",
     "CVE-2024-38080", KedVuln_PrivilegeEscalation, "win32k.sys"}
};

#define KED_LOL_DRIVER_COUNT \
    (sizeof(g_BuiltinLolDrivers) / sizeof(g_BuiltinLolDrivers[0]))

/**************************************************/
/*               已知崩溃码表                      */
/*  KNOWN_BUGCHECKS (10 条)。              */
/**************************************************/

typedef struct _KED_BUGCHECK_ENTRY {
    ULONG                 Code;
    const char*           Name;
    KED_BUGCHECK_CATEGORY Category;
    BOOLEAN               IsExploitIndicator;
} KED_BUGCHECK_ENTRY;

static const KED_BUGCHECK_ENTRY g_KnownBugChecks[] = {
    {0x0000001E, "KMODE_EXCEPTION_NOT_HANDLED", KedBcc_InvalidAccess, TRUE},
    {0x00000050, "PAGE_FAULT_IN_NONPAGED_AREA", KedBcc_InvalidAccess, TRUE},
    {0x0000007F, "UNEXPECTED_KERNEL_MODE_TRAP", KedBcc_ExploitIndicator, TRUE},
    {0x000000C4, "DRIVER_VERIFIER_DETECTED_VIOLATION", KedBcc_DriverFault, FALSE},
    {0x000000D1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL", KedBcc_DriverFault, TRUE},
    {0x000000BE, "ATTEMPTED_WRITE_TO_READONLY_MEMORY", KedBcc_ExploitIndicator, TRUE},
    {0x0000003B, "SYSTEM_SERVICE_EXCEPTION", KedBcc_InvalidAccess, TRUE},
    {0x00000019, "BAD_POOL_HEADER", KedBcc_PoolCorruption, TRUE},
    {0x000000C2, "BAD_POOL_CALLER", KedBcc_PoolCorruption, TRUE},
    {0x0000000A, "IRQL_NOT_LESS_OR_EQUAL", KedBcc_InvalidAccess, TRUE}
};

#define KED_BUGCHECK_COUNT \
    (sizeof(g_KnownBugChecks) / sizeof(g_KnownBugChecks[0]))

/**************************************************/
/*               本地重声明结构                    */
/*  本地重定义 RTL_PROCESS_MODULE_         */
/*  INFORMATION_EX (非系统 winternl.h 定义)。      */
/**************************************************/

typedef struct _KED_RTL_PROCESS_MODULE_INFORMATION_EX {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} KED_RTL_PROCESS_MODULE_INFORMATION_EX;

/**************************************************/
/*               模块全局状态                      */
/**************************************************/

static SRWLOCK  g_Lock = SRWLOCK_INIT;       /* 保护全部状态 (shared_mutex) */

static volatile KED_STATUS g_Status = KedStatus_Uninitialized;
static KED_CONFIG  g_Config;                  /* 生效配置 */
static KED_STATISTICS g_Stats;                /* 统计 (计数经 Interlocked) */

static volatile LONG g_EventSeq = 0;          /* 事件 ID 自增 (SS GenerateEventId) */

static KED_DETECTED_CALLBACK g_Callback = NULL;
static PVOID                 g_CallbackContext = NULL;

/* 默认微软签名者白名单 (SS Initialize 硬编码) + 运行时配置白名单 */
typedef struct _KED_SIGNER_ENTRY {
    WCHAR Name[256];
} KED_SIGNER_ENTRY;

static KED_SIGNER_ENTRY g_WhitelistedSigners[KED_MAX_WHITELISTED_SIGNERS];
static ULONG g_WhitelistedSignerCount = 0;

/* 自定义黑名单: SHA256 hex (64) + 原因 (SS m_customBlacklist map → C 定长) */
typedef struct _KED_BLACKLIST_ENTRY {
    CHAR  Sha256Hex[64 + 1];
    CHAR  Reason[128];
} KED_BLACKLIST_ENTRY;

static KED_BLACKLIST_ENTRY g_Blacklist[KED_MAX_BLACKLIST_ENTRIES];
static ULONG g_BlacklistCount = 0;

/* 每进程 IOCTL 速率限制槽 (SS m_ioctlRate unordered_map → C 定长) */
typedef struct _KED_RATE_SLOT {
    ULONG    ProcessId;
    ULONG64  WindowStartTick;     /* GetTickCount64 窗口起点 */
    ULONG    Count;               /* 当前窗口计数 */
    ULONG    Dropped;             /* 当前窗口丢弃数 */
    ULONG64  LastUsedTick;        /* 最近使用 (过期淘汰) */
} KED_RATE_SLOT;

static KED_RATE_SLOT g_RateSlots[KED_MAX_RATE_SLOTS];

/**************************************************/
/*               内部工具函数                      */
/**************************************************/

/* 二进制 → 大写 hex 字符串 (SS BytesToHexString 语义) */
static VOID
KedBinToHexUpper(
    _In_reads_bytes_(Len) const BYTE* Bin,
    _In_ ULONG Len,
    _Out_writes_z_(Len * 2 + 1) PCHAR HexOut
)
{
    static const char kHex[] = "0123456789ABCDEF";
    ULONG i;

    for (i = 0; i < Len; ++i) {
        HexOut[i * 2]     = kHex[(Bin[i] >> 4) & 0x0F];
        HexOut[i * 2 + 1] = kHex[Bin[i] & 0x0F];
    }
    HexOut[Len * 2] = '\0';
}

/* 校验字符串是否为 64 位 hex (SS IsValid 白名单哈希校验语义) */
static BOOLEAN
KedIsValidSha256Hex(
    _In_z_ PCSTR Hex
)
{
    ULONG i;

    if (Hex == NULL || strlen(Hex) != 64) {
        return FALSE;
    }
    for (i = 0; i < 64; ++i) {
        CHAR c = Hex[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return FALSE;
        }
    }
    return TRUE;
}

/* 宽字符串 → 小写 (SS ToLowerCopy 语义, 用于路径比较) */
static VOID
KedLowerCopyW(
    _In_z_ PCWSTR In,
    _Out_writes_z_(Cch) PWSTR Out,
    _In_ ULONG Cch
)
{
    ULONG i;

    if (In == NULL || Out == NULL || Cch == 0) {
        return;
    }
    for (i = 0; i + 1 < Cch; ++i) {
        WCHAR c = In[i];
        if (c == L'\0') {
            break;
        }
        /* 仅 ASCII 转小写, 路径比较够用 */
        if (c >= L'A' && c <= L'Z') {
            c += (L'a' - L'A');
        }
        Out[i] = c;
    }
    Out[Cch - 1] = L'\0';
}

/* 当前系统时间 → LARGE_INTEGER FILETIME (SS system_clock 语义替代) */
static VOID
KedGetNow(
    _Out_ PLARGE_INTEGER Now
)
{
    FILETIME ft;

    GetSystemTimeAsFileTime(&ft);
    Now->LowPart  = ft.dwLowDateTime;
    Now->HighPart = ft.dwHighDateTime;
}

/* 事件 ID 自增 (SS GenerateEventId "KE-"+ms+seq → C 纯自增) */
static ULONG
KedNextEventId(VOID)
{
    return (ULONG)InterlockedIncrement(&g_EventSeq);
}

/* 格式化 ULONG64 为 "0x%08X" (SS FormatHexValue 语义) */
static VOID
KedFormatHex64(
    _In_ ULONG64 Value,
    _Out_writes_z_(24) PCHAR Buffer
)
{
    sprintf_s(Buffer, 24, "0x%016llX", (unsigned long long)Value);
}

/**************************************************/
/*               事件上报                          */
/*  统一记录: 事件 ID/时间戳/统计/单回调派发       */
/*  (RecordDetection + Notify* 系列:       */
/*  回调先拷贝再锁外调用, 防死锁。C 版单回调,      */
/*  仅拷贝指针值即可)。                            */
/**************************************************/

static VOID
KedRecordEvent(
    _In_ PKED_EVENT Event
)
{
    KED_DETECTED_CALLBACK cb;
    PVOID                 ctx;

    Event->EventId    = KedNextEventId();
    KedGetNow(&Event->Timestamp);

    InterlockedIncrement(&g_Stats.EventsReported);

    /* 锁内快照回调, 锁外调用 (Notify*) */
    AcquireSRWLockShared(&g_Lock);
    cb = g_Callback;
    ctx = g_CallbackContext;
    ReleaseSRWLockShared(&g_Lock);

    if (cb != NULL) {
        cb(Event, ctx);
    }
}

/**************************************************/
/*               DOS 路径转换 (修正 SS 缺陷)       */
/*  SS EnumerateLoadedDrivers/FindHiddenDrivers   */
/*  直接比较 \Device\... 与 \SystemRoot\... 路径   */
/*  格式不一致导致交叉永不匹配; 此处统一归一化     */
/*  (设备路径→盘符, \SystemRoot\→windir, \??\→剥离) */
/**************************************************/

typedef struct _KED_DOS_MAP {
    WCHAR   Drive[4];            /* L"C:\\" */
    WCHAR   Target[128];         /* L"\\Device\\HarddiskVolume1" */
    SIZE_T  TargetLen;           /* Target 字符长度 (不含尾 0) */
} KED_DOS_MAP;

#define KED_MAX_DOS_MAP 32

/*
 * 构建逻辑盘符 → 设备路径映射 (C:\..Z:\ 经 QueryDosDeviceW).
 * 返回映射条目数。
 */
static ULONG
KedBuildDosMap(
    _Out_writes_(MaxEntries) KED_DOS_MAP* Map,
    _In_ ULONG MaxEntries
)
{
    ULONG count = 0;
    CHAR  driveLetter;

    if (Map == NULL || MaxEntries == 0) {
        return 0;
    }

    for (driveLetter = 'A'; driveLetter <= 'Z' && count < MaxEntries; ++driveLetter) {
        WCHAR driveRoot[4];
        WCHAR deviceName[128];
        DWORD len;

        driveRoot[0] = (WCHAR)driveLetter;
        driveRoot[1] = L':';
        driveRoot[2] = L'\\';
        driveRoot[3] = L'\0';

        len = QueryDosDeviceW(driveRoot, deviceName, 128);
        if (len == 0 || len >= 128) {
            continue;   /* 不存在的盘符 */
        }

        /* 跳过网络/可移动等不适用于驱动路径的映射: 仅保留 \Device\ 前缀 */
        if (wcsncmp(deviceName, L"\\Device\\", 8) != 0) {
            continue;
        }

        Map[count].Drive[0] = (WCHAR)driveLetter;
        Map[count].Drive[1] = L':';
        Map[count].Drive[2] = L'\\';
        Map[count].Drive[3] = L'\0';
        wcsncpy_s(Map[count].Target, 128, deviceName, _TRUNCATE);
        Map[count].TargetLen = wcslen(Map[count].Target);
        ++count;
    }

    return count;
}

/*
 * 设备路径 → DOS 路径: 遍历映射找最长设备前缀替换。
 * 返回 TRUE 且 Out 有效。
 */
static BOOLEAN
KedConvertDevicePath(
    _In_z_ PCWSTR DevicePath,
    _In_reads_(MapCount) const KED_DOS_MAP* Map,
    _In_ ULONG MapCount,
    _Out_writes_z_(OutCch) PWSTR Out,
    _In_ ULONG OutCch
)
{
    ULONG i;
    ULONG bestLen = 0;
    ULONG bestIdx = 0;
    size_t pathLen;

    if (DevicePath == NULL || Out == NULL || OutCch == 0) {
        return FALSE;
    }
    Out[0] = L'\0';
    if (Map == NULL || MapCount == 0) {
        return FALSE;
    }

    pathLen = wcslen(DevicePath);
    if (pathLen == 0) {
        return FALSE;
    }

    /* 最长前缀匹配 (避免 \Device\HarddiskVolume1 与 \Device\HarddiskVolume10 串扰) */
    for (i = 0; i < MapCount; ++i) {
        SIZE_T tlen = Map[i].TargetLen;
        if (tlen > 0 && tlen > bestLen && tlen <= pathLen &&
            _wcsnicmp(DevicePath, Map[i].Target, tlen) == 0) {
            /* 边界检查: 设备名后必须是 '\' 或串尾 */
            if (tlen == pathLen || DevicePath[tlen] == L'\\') {
                bestLen = (ULONG)tlen;
                bestIdx = i;
            }
        }
    }

    if (bestLen == 0) {
        return FALSE;
    }

    if (OutCch > (ULONG)wcslen(Map[bestIdx].Drive) + (ULONG)(pathLen - bestLen) + 1) {
        wcscpy_s(Out, OutCch, Map[bestIdx].Drive);
        wcscat_s(Out, OutCch, DevicePath + bestLen);
        return TRUE;
    }
    return FALSE;
}

/*
 * 模块路径归一化 (统一三方交叉比较基准):
 *   \SystemRoot\...            → windir + 尾部
 *   \??\C:\... / \??\C:...     → 剥离 \??\
 *   纯设备路径 \Device\...      → 盘符转换
 *   已 C:\ 形式                 → 原样
 */
static BOOLEAN
KedNormalizeModulePath(
    _In_z_ PCWSTR In,
    _In_reads_(MapCount) const KED_DOS_MAP* Map,
    _In_ ULONG MapCount,
    _Out_writes_z_(OutCch) PWSTR Out,
    _In_ ULONG OutCch
)
{
    size_t len;

    if (In == NULL || Out == NULL || OutCch == 0) {
        return FALSE;
    }
    Out[0] = L'\0';
    len = wcslen(In);
    if (len == 0) {
        return FALSE;
    }

    /* 1) \SystemRoot\ → %windir% (SS FindHiddenDrivers 同款处理) */
    if (_wcsnicmp(In, L"\\SystemRoot\\", 12) == 0) {
        WCHAR winDir[DEF_MAX_PATH];
        UINT  wlen = GetWindowsDirectoryW(winDir, DEF_MAX_PATH);
        if (wlen == 0 || wlen >= DEF_MAX_PATH) {
            return FALSE;
        }
        if (OutCch > (ULONG)wlen + (ULONG)(len - 12) + 1) {
            wcscpy_s(Out, OutCch, winDir);
            wcscat_s(Out, OutCch, L"\\");
            wcscat_s(Out, OutCch, In + 12);
            return TRUE;
        }
        return FALSE;
    }

    /* 2) \??\C:\... → 剥离 \??\ */
    if (_wcsnicmp(In, L"\\??\\", 4) == 0) {
        if (len > 6 && In[5] == L':' && In[6] == L'\\') {
            if (OutCch > len - 4) {
                wcscpy_s(Out, OutCch, In + 4);
                return TRUE;
            }
            return FALSE;
        }
        /* \??\ 后非盘符形式, 转设备映射尝试 */
        return KedConvertDevicePath(In + 4, Map, MapCount, Out, OutCch);
    }

    /* 3) 已是 DOS 形式 (x:\...) */
    if (len >= 3 && In[1] == L':' && (In[2] == L'\\' || In[2] == L'/')) {
        wcscpy_s(Out, OutCch, In);
        return TRUE;
    }

    /* 4) 设备路径 */
    return KedConvertDevicePath(In, Map, MapCount, Out, OutCch);
}

/**************************************************/
/*               进程路径查询                      */
/*  Utils::ProcessUtils::GetProcessPath    */
/**************************************************/

static VOID
KedQueryProcessPathEx(
    _In_ ULONG ProcessId,
    _Out_writes_z_(PathCch) PWSTR Path,
    _In_ ULONG PathCch,
    _Out_writes_z_(NameCch) PWSTR Name,
    _In_ ULONG NameCch
)
{
    HANDLE hProcess;
    DWORD  size = PathCch * sizeof(WCHAR);
    WCHAR* slash;

    /* 主缓冲 Path 必填; Name 可选 (SS GetProcessPath 语义) */
    if (Path == NULL || PathCch == 0) {
        return;
    }
    Path[0] = L'\0';
    if (Name != NULL && NameCch > 0) {
        Name[0] = L'\0';
    }

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (hProcess == NULL) {
        wcscpy_s(Path, PathCch, L"<unknown>");
        if (Name != NULL && NameCch > 0) {
            wcscpy_s(Name, NameCch, L"<unknown>");
        }
        return;
    }

    if (QueryFullProcessImageNameW(hProcess, 0, Path, &size) && size > 0) {
        if (Name != NULL && NameCch > 0) {
            slash = wcsrchr(Path, L'\\');
            if (slash != NULL && slash[1] != L'\0') {
                wcscpy_s(Name, NameCch, slash + 1);
            } else if (Name != Path) {
                /* 同缓冲 (调用方传同一数组) 时 Name 已含该内容, 免自我复制 */
                wcscpy_s(Name, NameCch, Path);
            }
        }
    } else {
        wcscpy_s(Path, PathCch, L"<unknown>");
        if (Name != NULL && NameCch > 0) {
            wcscpy_s(Name, NameCch, L"<unknown>");
        }
    }

    CloseHandle(hProcess);
}

/**************************************************/
/*               哈希计算                          */
/*  复用 WkDefender Common/BCrypUtils.h            */
/*  IocScanner_ComputeFileHashMulti (3 算法单遍).  */
/**************************************************/

static VOID
KedComputeFileHashes(
    _In_z_ PCWSTR FilePath,
    _Out_writes_z_(65) PCHAR Sha256Hex,
    _Out_writes_z_(41) PCHAR Sha1Hex,
    _Out_writes_z_(33) PCHAR Md5Hex
)
{
    WKD_FILE_HASH_SET hashes;

    Sha256Hex[0] = '\0';
    Sha1Hex[0]   = '\0';
    Md5Hex[0]    = '\0';

    RtlZeroMemory(&hashes, sizeof(hashes));
    if (!IocScanner_ComputeFileHashMulti(FilePath,
                                         WkdHash_SHA256 | WkdHash_SHA1 | WkdHash_MD5,
                                         &hashes) || hashes.HasErrors) {
        return;   /* 哈希失败不致命, 留空 (SS catch 同语义) */
    }

    if (hashes.Sha256Valid) {
        KedBinToHexUpper(hashes.Sha256, 32, Sha256Hex);
    }
    if (hashes.Sha1Valid) {
        KedBinToHexUpper(hashes.Sha1, 20, Sha1Hex);
    }
    if (hashes.Md5Valid) {
        KedBinToHexUpper(hashes.Md5, 16, Md5Hex);
    }
}

/**************************************************/
/*               签名验证                          */
/*  VerifyDriverSignature:                 */
/*  WinVerifyTrust V2 + 吊销检查, 结果映射。       */
/**************************************************/

static LONG
KedWinVerifyTrust(
    _In_z_ PCWSTR FilePath,
    _Inout_ PWINTRUST_DATA TrustData,
    _In_ GUID* ActionGuid
)
{
    WINTRUST_FILE_INFO fileInfo;

    RtlZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = FilePath;
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    TrustData->dwUnionChoice = WTD_CHOICE_FILE;
    TrustData->pFile = &fileInfo;
    TrustData->dwStateAction = WTD_STATEACTION_VERIFY;
    TrustData->hWVTStateData = NULL;
    TrustData->pwszURLReference = NULL;

    return WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, ActionGuid, TrustData);
}

static KED_SIGNATURE_STATUS
KedVerifyDriverSignature(
    _In_z_ PCWSTR FilePath
)
{
    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData;
    LONG result;
    KED_SIGNATURE_STATUS status;

    RtlZeroMemory(&trustData, sizeof(trustData));
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.pPolicyCallbackData = NULL;
    trustData.pSIPClientData = NULL;
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwProvFlags = WTD_SAFER_FLAG | WTD_REVOCATION_CHECK_CHAIN |
                            WTD_CACHE_ONLY_URL_RETRIEVAL;

    result = KedWinVerifyTrust(FilePath, &trustData, &actionGuid);

    /* 关闭信任数据状态 (SS 同款两阶段) */
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &actionGuid, &trustData);

    if (result == ERROR_SUCCESS) {
        status = KedSig_ValidSigned;
    } else if (result == TRUST_E_NOSIGNATURE) {
        status = KedSig_Unsigned;
    } else if (result == TRUST_E_EXPLICIT_DISTRUST ||
               result == CERT_E_REVOKED ||
               result == CRYPT_E_REVOKED) {
        status = KedSig_RevokedCertificate;
    } else if (result == TRUST_E_BAD_DIGEST) {
        status = KedSig_InvalidSignature;
    } else if (result == CERT_E_EXPIRED) {
        status = KedSig_ExpiredCertificate;
    } else if (result == CERT_E_UNTRUSTEDROOT ||
               result == CERT_E_CHAINING) {
        status = KedSig_InvalidSignature;
    } else {
        status = KedSig_Unknown;
    }

    return status;
}

/**************************************************/
/*               版本信息提取                      */
/*  ExtractVersionInfo (VerQueryValueW).   */
/**************************************************/

typedef struct _KED_LANG_CODEPAGE {
    WORD wLanguage;
    WORD wCodePage;
} KED_LANG_CODEPAGE;

static VOID
KedExtractVersionInfo(
    _In_z_ PCWSTR FilePath,
    _Out_ PKED_DRIVER_INFO Info
)
{
    DWORD handle = 0;
    DWORD size;
    BYTE* buffer;
    KED_LANG_CODEPAGE* translate;
    UINT cbTranslate = 0;
    WCHAR base[64];
    WCHAR subPath[DEF_MAX_PATH];

    /* 版本资源字段: 语言+代码页 4 位 hex 各*/
    size = GetFileVersionInfoSizeW(FilePath, &handle);
    if (size == 0) {
        return;
    }

    buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
    if (buffer == NULL) {
        return;
    }

    if (GetFileVersionInfoW(FilePath, 0, size, buffer) &&
        VerQueryValueW(buffer, L"\\VarFileInfo\\Translation",
                       (LPVOID*)&translate, &cbTranslate) &&
        cbTranslate >= sizeof(KED_LANG_CODEPAGE)) {

        wsprintfW(base, L"\\StringFileInfo\\%04x%04x\\",
                  translate[0].wLanguage, translate[0].wCodePage);

#define KED_QV(FIELD, STR)                                                    \
        do {                                                                  \
            WCHAR* value = NULL;                                              \
            UINT  vlen = 0;                                                   \
            wsprintfW(subPath, L"%s%s", base, STR);                           \
            if (VerQueryValueW(buffer, subPath, (LPVOID*)&value, &vlen) &&    \
                value != NULL && vlen >= 2) {                                 \
                wcsncpy_s(Info->FIELD, _countof(Info->FIELD), value,          \
                          (vlen - 1 < _countof(Info->FIELD) - 1) ?            \
                          vlen - 1 : _countof(Info->FIELD) - 1);             \
            }                                                                 \
        } while (0)

        KED_QV(FileVersion,   L"FileVersion");
        KED_QV(ProductName,   L"ProductName");
        KED_QV(CompanyName,   L"CompanyName");
        KED_QV(Description,   L"FileDescription");

#undef KED_QV
    }

    HeapFree(GetProcessHeap(), 0, buffer);
}

/**************************************************/
/*               三库查表 (LOL/MS/自定义)          */
/*  ScanDriver 中 m_lolDrivers /           */
/*  m_microsoftBlocklist / m_customBlacklist 查询。 */
/**************************************************/

static BOOLEAN
KedLolLookup(
    _In_z_ PCSTR Sha256Hex,
    _Out_opt_ PCSTR* Cves,
    _Out_opt_ PKED_VULN_CLASS VulnClass
)
{
    ULONG i;

    if (Sha256Hex == NULL) {
        return FALSE;
    }
    for (i = 0; i < KED_LOL_DRIVER_COUNT; ++i) {
        if (_stricmp(Sha256Hex, g_BuiltinLolDrivers[i].Sha256Hex) == 0) {
            if (Cves != NULL) {
                *Cves = g_BuiltinLolDrivers[i].Cves;
            }
            if (VulnClass != NULL) {
                *VulnClass = g_BuiltinLolDrivers[i].VulnClass;
            }
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
KedMicrosoftBlocklistLookup(
    _In_z_ PCSTR Sha256Hex
)
{
    ULONG i;

    if (Sha256Hex == NULL) {
        return FALSE;
    }
    /* SS: MS 阻止列表 = 内置库中漏洞类为 Multiple/物理内存/提权/代码执行的子集 */
    for (i = 0; i < KED_LOL_DRIVER_COUNT; ++i) {
        if (_stricmp(Sha256Hex, g_BuiltinLolDrivers[i].Sha256Hex) == 0) {
            if (g_BuiltinLolDrivers[i].VulnClass == KedVuln_Multiple ||
                g_BuiltinLolDrivers[i].VulnClass == KedVuln_ArbitraryPhysAccess ||
                g_BuiltinLolDrivers[i].VulnClass == KedVuln_PrivilegeEscalation ||
                g_BuiltinLolDrivers[i].VulnClass == KedVuln_CodeExecution) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static BOOLEAN
KedCustomBlacklistLookup(
    _In_z_ PCSTR Sha256Hex,
    _Out_writes_z_(128) PCHAR Reason,
    _In_ ULONG ReasonCch
)
{
    ULONG i;
    BOOLEAN hit = FALSE;

    for (i = 0; i < g_BlacklistCount; ++i) {
        if (_stricmp(Sha256Hex, g_Blacklist[i].Sha256Hex) == 0) {
            if (Reason != NULL && ReasonCch > 0) {
                strncpy_s(Reason, ReasonCch, g_Blacklist[i].Reason, _TRUNCATE);
            }
            hit = TRUE;
            break;
        }
    }
    return hit;
}

/**************************************************/
/*               IOCTL 速率限制                    */
/*  AnalyzeIOCTL 速率限制 + 30s GC.        */
/*  C 定长槽: 命中/空槽/过期槽/FIFO 覆盖.         */
/**************************************************/

static BOOLEAN
KedRateLimitCheck(
    _In_ ULONG ProcessId
)
{
    ULONG64 now = GetTickCount64();
    ULONG i;
    ULONG emptySlot = KED_MAX_RATE_SLOTS;
    ULONG64 oldestUsed = (ULONG64)-1;
    ULONG oldestIdx = 0;

    /* 1) 命中已存在进程槽 */
    for (i = 0; i < KED_MAX_RATE_SLOTS; ++i) {
        if (g_RateSlots[i].ProcessId == ProcessId) {
            if (now - g_RateSlots[i].WindowStartTick >= KED_IOCTL_RATE_WINDOW_MS) {
                /* 窗口翻转 (SS: 顺带记录丢弃数后重置) */
                g_RateSlots[i].WindowStartTick = now;
                g_RateSlots[i].Count = 0;
                g_RateSlots[i].Dropped = 0;
            }
            g_RateSlots[i].LastUsedTick = now;
            if (g_RateSlots[i].Count >= KED_IOCTL_RATE_LIMIT_PER_SEC) {
                g_RateSlots[i].Dropped++;
                return FALSE;   /* 丢弃: 不分析不记事件 */
            }
            g_RateSlots[i].Count++;
            return TRUE;
        }
    }

    /* 2) 未命中: 找空槽或 30s 过期槽 (SS 30s GC 语义) */
    for (i = 0; i < KED_MAX_RATE_SLOTS; ++i) {
        if (g_RateSlots[i].LastUsedTick == 0 ||
            now - g_RateSlots[i].LastUsedTick > 30000) {
            g_RateSlots[i].ProcessId = ProcessId;
            g_RateSlots[i].WindowStartTick = now;
            g_RateSlots[i].Count = 1;
            g_RateSlots[i].Dropped = 0;
            g_RateSlots[i].LastUsedTick = now;
            return TRUE;
        }
        if (g_RateSlots[i].LastUsedTick < oldestUsed) {
            oldestUsed = g_RateSlots[i].LastUsedTick;
            oldestIdx = i;
        }
    }

    /* 3) 全满: 覆盖最久未用槽 (进程 PID 翻转防御) */
    g_RateSlots[oldestIdx].ProcessId = ProcessId;
    g_RateSlots[oldestIdx].WindowStartTick = now;
    g_RateSlots[oldestIdx].Count = 1;
    g_RateSlots[oldestIdx].Dropped = 0;
    g_RateSlots[oldestIdx].LastUsedTick = now;
    return TRUE;
}

/**************************************************/
/*               生命周期                           */
/**************************************************/

/* Configuration::IsValid (至少一能力开启) */
static BOOLEAN
KedConfigIsValid(
    _In_ const KED_CONFIG* Config
)
{
    if (Config == NULL) {
        return FALSE;
    }
    return (Config->EnableDriverMonitoring ||
            Config->MonitorIoctl ||
            Config->DetectKaslrLeaks ||
            Config->AnalyzeBsodDumps);
}

/* 装载生效白名单签名者 (配置 + 硬编码微软 3 个, 对齐 SS) */
static VOID
KedInstallWhitelistedSigners(
    _In_ const KED_CONFIG* Config
)
{
    ULONG n = 0;
    ULONG i;

    static const WCHAR kDefaultSigners[][64] = {
        L"Microsoft Windows",
        L"Microsoft Corporation",
        L"Microsoft Windows Hardware Compatibility Publisher"
    };
    static const ULONG kDefaultSignerCount =
        sizeof(kDefaultSigners) / sizeof(kDefaultSigners[0]);

    g_WhitelistedSignerCount = 0;

    /* 配置白名单 (SS: 遍历 config.whitelistedSigners insert) */
    for (i = 0; i < Config->WhitelistedSignerCount && n < KED_MAX_WHITELISTED_SIGNERS; ++i) {
        if (Config->WhitelistedSigners[i][0] != L'\0') {
            wcsncpy_s(g_WhitelistedSigners[n].Name, 256,
                      Config->WhitelistedSigners[i], _TRUNCATE);
            ++n;
        }
    }

    /* 默认微软签名者 (SS Initialize 硬编码 insert) */
    for (i = 0; i < kDefaultSignerCount && n < KED_MAX_WHITELISTED_SIGNERS; ++i) {
        wcsncpy_s(g_WhitelistedSigners[n].Name, 256, kDefaultSigners[i], _TRUNCATE);
        ++n;
    }

    g_WhitelistedSignerCount = n;
}

NTSTATUS
KedInitialize(
    _In_opt_ const KED_CONFIG* Config
)
{
    KED_STATUS current;

    /* CAS 抢占初始化权 (SS 同款门控), 返回值即旧状态 */
    current = (KED_STATUS)InterlockedCompareExchange(
        (volatile LONG*)&g_Status, KedStatus_Initializing, KedStatus_Uninitialized);

    AcquireSRWLockExclusive(&g_Lock);

    /*
     * 门控判定必须基于 CAS 旧值 current 而非 g_Status 即时值:
     * 首次调用时 CAS 已把 Uninitialized→Initializing, 若再判断
     * g_Status 会误拒初始化自身 (原 SS 移植缺陷, 此处修正)。
     */
    if (current != KedStatus_Uninitialized && current != KedStatus_Stopped) {
        ReleaseSRWLockExclusive(&g_Lock);
        return STATUS_INVALID_DEVICE_STATE;
    }

    g_Status = KedStatus_Initializing;

    if (Config == NULL) {
        g_Config = KED_DEFAULT_CONFIG;
    } else {
        g_Config = *Config;
    }

    if (!KedConfigIsValid(&g_Config)) {
        g_Status = KedStatus_Error;
        ReleaseSRWLockExclusive(&g_Lock);
        return STATUS_INVALID_PARAMETER;
    }

    /* 装载白名单签名者 (含默认微软签名者) */
    KedInstallWhitelistedSigners(&g_Config);

    /* 清空自定义黑名单 (SS: config.customBlacklistPath 加载, C 版由调用方 Add) */
    g_BlacklistCount = 0;

    /* 清空速率槽 */
    RtlZeroMemory(g_RateSlots, sizeof(g_RateSlots));

    /* 重置统计 (SS: m_stats.Reset() + startTime) */
    RtlZeroMemory(&g_Stats, sizeof(g_Stats));
    g_EventSeq = 0;

    g_Status = KedStatus_Running;
    ReleaseSRWLockExclusive(&g_Lock);

    return STATUS_SUCCESS;
}

VOID
KedShutdown(VOID)
{
    AcquireSRWLockExclusive(&g_Lock);

    if (g_Status == KedStatus_Uninitialized || g_Status == KedStatus_Stopped) {
        ReleaseSRWLockExclusive(&g_Lock);
        return;   /* SS Shutdown 同款早退 */
    }

    g_Status = KedStatus_Stopping;

    /* 清空全部数据库/白名单/回调 (SS Shutdown 同款) */
    g_WhitelistedSignerCount = 0;
    g_BlacklistCount = 0;
    RtlZeroMemory(g_RateSlots, sizeof(g_RateSlots));
    g_Callback = NULL;
    g_CallbackContext = NULL;

    g_Status = KedStatus_Stopped;
    ReleaseSRWLockExclusive(&g_Lock);
}

BOOLEAN
KedIsInitialized(VOID)
{
    KED_STATUS s = (KED_STATUS)InterlockedCompareExchange(
        (volatile LONG*)&g_Status, KedStatus_Running, KedStatus_Running);
    return (s == KedStatus_Running || s == KedStatus_Paused);
}

KED_STATUS
KedGetStatus(VOID)
{
    return (KED_STATUS)InterlockedCompareExchange(
        (volatile LONG*)&g_Status, KedStatus_Running, KedStatus_Running);
}

PCSTR
KedGetVersionString(VOID)
{
    return KED_VERSION_STRING;
}

/**************************************************/
/*               驱动扫描                          */
/*  ScanDriver 全流程: 文件校验 → 哈希 →   */
/*  签名 → 版本 → 三库查表 → 统计。               */
/**************************************************/

NTSTATUS
KedScanDriver(
    _In_  PCWSTR          DriverPath,
    _Out_ PKED_DRIVER_INFO Info
)
{
    WIN32_FILE_ATTRIBUTE_DATA fad;
    LARGE_INTEGER fileSize;
    PCSTR cves = NULL;
    CHAR customReason[128];
    BOOLEAN inLol, inMs, inCustom;
    KED_VULN_CLASS lolClass = KedVuln_Unknown;
    WCHAR* slash;

    if (DriverPath == NULL || Info == NULL || DriverPath[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Info, sizeof(*Info));

    /* 文件存在性 + 大小上限 (SS: exists + MAX_DRIVER_SIZE) */
    if (!GetFileAttributesExW(DriverPath, GetFileExInfoStandard, &fad)) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    fileSize.LowPart  = fad.nFileSizeLow;
    fileSize.HighPart = fad.nFileSizeHigh;
    if (fileSize.QuadPart > KED_MAX_DRIVER_SIZE) {
        return STATUS_FILE_TOO_LARGE;   /* 上限 20MB */
    }
    Info->Size = (fileSize.QuadPart > 0xFFFFFFFFULL)
                     ? 0xFFFFFFFFu : (ULONG)fileSize.QuadPart;

    /* 路径与文件名 (SS: filePath + filesystem::path filename) */
    wcsncpy_s(Info->FilePath, _countof(Info->FilePath), DriverPath, _TRUNCATE);
    slash = wcsrchr(Info->FilePath, L'\\');
    if (slash != NULL && slash[1] != L'\0') {
        wcsncpy_s(Info->FileName, _countof(Info->FileName),
                  slash + 1, _TRUNCATE);
    } else {
        wcsncpy_s(Info->FileName, _countof(Info->FileName),
                  DriverPath, _TRUNCATE);
    }

    InterlockedIncrement(&g_Stats.DriversScanned);

    /* 哈希: SHA256/SHA1/MD5 (SS HashUtils 三算法) */
    KedComputeFileHashes(DriverPath, Info->Sha256Hex, Info->Sha1Hex, Info->Md5Hex);

    /* 签名验证 (SS VerifyDriverSignature) */
    Info->SignatureStatus = KedVerifyDriverSignature(DriverPath);
    if (Info->SignatureStatus == KedSig_Unsigned) {
        InterlockedIncrement(&g_Stats.UnsignedDriversDetected);
    }

    /* 版本信息 (SS ExtractVersionInfo) */
    KedExtractVersionInfo(DriverPath, Info);

    /* 三库查表 (SS ScanDriver 查表段) */
    if (Info->Sha256Hex[0] != '\0') {
        inLol = KedLolLookup(Info->Sha256Hex, &cves, &lolClass);
        inMs  = KedMicrosoftBlocklistLookup(Info->Sha256Hex);
        inCustom = KedCustomBlacklistLookup(Info->Sha256Hex,
                                            customReason,
                                            _countof(customReason));

        if (inLol) {
            Info->IsLolDriver = TRUE;
            Info->IsVulnerable = TRUE;
            Info->VulnerabilityClass = lolClass;
            strncpy_s(Info->ThreatIntelSource, _countof(Info->ThreatIntelSource),
                      "LOLDrivers", _TRUNCATE);
            if (cves != NULL) {
                strncpy_s(Info->CveIds, _countof(Info->CveIds), cves, _TRUNCATE);
            }
            InterlockedIncrement(&g_Stats.LolDriversDetected);
        }

        if (inMs) {
            Info->IsMicrosoftBlocked = TRUE;
            Info->IsVulnerable = TRUE;
            strncpy_s(Info->ThreatIntelSource, _countof(Info->ThreatIntelSource),
                      "Microsoft Blocklist", _TRUNCATE);
        }

        if (inCustom) {
            Info->IsVulnerable = TRUE;
            strncpy_s(Info->ThreatIntelSource, _countof(Info->ThreatIntelSource),
                      "Custom Blacklist", _TRUNCATE);
        }
    }

    if (Info->IsVulnerable) {
        InterlockedIncrement(&g_Stats.VulnerableDriversDetected);
        /*
         * SS 中 driversBlocked 无自增点 (stub 缺口, Exploits.md 未标注,
         * 逐行核对确认); 此处按配置语义补齐: 命中且允许拦截时计数。
         * 注意: 本模块为纯分析引擎, 不实际阻止加载, 仅记录判定。
         */
        if (g_Config.BlockVulnerableDrivers) {
            InterlockedIncrement(&g_Stats.DriversBlocked);
        }
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*               三库查询 API                      */
/**************************************************/

BOOLEAN
KedIsVulnerableDriver(
    _In_ PCSTR Sha256Hex
)
{
    BOOLEAN hit;

    if (!KedIsValidSha256Hex(Sha256Hex)) {
        return FALSE;   /* SS: 空或长度!=64 直接 false */
    }

    AcquireSRWLockShared(&g_Lock);
    hit = KedLolLookup(Sha256Hex, NULL, NULL) ||
          KedMicrosoftBlocklistLookup(Sha256Hex) ||
          KedCustomBlacklistLookup(Sha256Hex, NULL, 0);
    ReleaseSRWLockShared(&g_Lock);

    return hit;
}

BOOLEAN
KedIsMicrosoftBlocked(
    _In_ PCSTR Sha256Hex
)
{
    BOOLEAN hit;

    if (!KedIsValidSha256Hex(Sha256Hex)) {
        return FALSE;
    }

    AcquireSRWLockShared(&g_Lock);
    hit = KedMicrosoftBlocklistLookup(Sha256Hex);
    ReleaseSRWLockShared(&g_Lock);

    return hit;
}

BOOLEAN
KedIsLolDriver(
    _In_ PCSTR Sha256Hex
)
{
    BOOLEAN hit;

    if (!KedIsValidSha256Hex(Sha256Hex)) {
        return FALSE;
    }

    AcquireSRWLockShared(&g_Lock);
    hit = KedLolLookup(Sha256Hex, NULL, NULL);
    ReleaseSRWLockShared(&g_Lock);

    return hit;
}

ULONG
KedGetDriverCves(
    _In_  PCSTR  Sha256Hex,
    _Out_writes_to_opt_(CveBufferCch, return) PCHAR CveBuffer,
    _In_  ULONG  CveBufferCch
)
{
    PCSTR cves = NULL;
    size_t len;

    if (CveBuffer == NULL || CveBufferCch == 0) {
        return 0;
    }
    CveBuffer[0] = '\0';

    if (!KedIsValidSha256Hex(Sha256Hex)) {
        return 0;
    }

    AcquireSRWLockShared(&g_Lock);
    if (KedLolLookup(Sha256Hex, &cves, NULL) && cves != NULL) {
        len = strlen(cves);
        if (len + 1 <= CveBufferCch) {
            memcpy(CveBuffer, cves, len + 1);
        } else {
            strncpy_s(CveBuffer, CveBufferCch, cves, _TRUNCATE);
            len = CveBufferCch - 1;
        }
    } else {
        len = 0;
    }
    ReleaseSRWLockShared(&g_Lock);

    return (ULONG)len + 1;   /* 含尾 0 (SS vector 语义, 调用方按字符串使用) */
}

/**************************************************/
/*              枚举已加载驱动                     */
/*  EnumerateLoadedDrivers:                */
/*  EnumDeviceDrivers 两遍扩容 (cap 64K) +         */
/*  GetDeviceDriverFileNameW + 逐驱动 ScanDriver.  */
/**************************************************/

ULONG
KedEnumerateLoadedDrivers(
    _Out_writes_to_opt_(MaxDrivers, *pReturned) PKED_DRIVER_INFO Drivers,
    _In_                               ULONG            MaxDrivers,
    _Out_opt_                          PULONG           pReturned
)
{
    LPVOID* addresses = NULL;
    DWORD   bytesNeeded = 0;
    DWORD   bufferBytes;
    SIZE_T  allocCount = KED_MAX_DRIVER_ADDRS_INIT;
    ULONG   driverCount = 0;
    ULONG   outCount = 0;
    ULONG   i;
    ULONG   attempt;
    KED_DOS_MAP dosMap[KED_MAX_DOS_MAP];
    ULONG   mapCount;
    WCHAR   dosPath[DEF_MAX_PATH * 2];

    if (pReturned != NULL) {
        *pReturned = 0;
    }
    if (Drivers == NULL || MaxDrivers == 0) {
        return 0;
    }

    mapCount = KedBuildDosMap(dosMap, KED_MAX_DOS_MAP);

    /* SS: 两遍扩容循环 (EnumDeviceDrivers 静默截断), cap 65536 */
    for (attempt = 0; attempt < 4; ++attempt) {
        addresses = (LPVOID*)HeapAlloc(GetProcessHeap(), 0,
                                       allocCount * sizeof(LPVOID));
        if (addresses == NULL) {
            return 0;
        }

        bufferBytes = (DWORD)(allocCount * sizeof(LPVOID));
        if (!EnumDeviceDrivers(addresses, bufferBytes, &bytesNeeded)) {
            HeapFree(GetProcessHeap(), 0, addresses);
            return 0;
        }
        if (bytesNeeded <= bufferBytes) {
            break;   /* 一次拿全 */
        }

        {
            SIZE_T newCount = (SIZE_T)(bytesNeeded / sizeof(LPVOID)) + 64;
            if (newCount > KED_MAX_DRIVER_COUNT) {
                newCount = KED_MAX_DRIVER_COUNT;
            }
            if (newCount <= allocCount) {
                break;   /* 到达上限无法再扩 */
            }
            HeapFree(GetProcessHeap(), 0, addresses);
            allocCount = newCount;
            addresses = NULL;
        }
    }

    if (addresses == NULL) {
        return 0;
    }

    driverCount = (ULONG)min((SIZE_T)(bytesNeeded / sizeof(LPVOID)), allocCount);

    for (i = 0; i < driverCount && outCount < MaxDrivers; ++i) {
        WCHAR devicePath[DEF_MAX_PATH * 2];
        NTSTATUS status;

        devicePath[0] = L'\0';
        if (!GetDeviceDriverFileNameW(addresses[i], devicePath,
                                      DEF_MAX_PATH * 2)) {
            continue;
        }

        /* 设备路径 → DOS (修正 SS 未实现的 "Convert device path to DOS") */
        if (!KedNormalizeModulePath(devicePath, dosMap, mapCount,
                                    dosPath, DEF_MAX_PATH * 2)) {
            continue;   /* 无法转换的路径 (如非盘符设备) 跳过 */
        }

        status = KedScanDriver(dosPath, &Drivers[outCount]);
        if (NT_SUCCESS(status)) {
            Drivers[outCount].BaseAddress = (ULONG64)(ULONG_PTR)addresses[i];
            ++outCount;
        }
    }

    HeapFree(GetProcessHeap(), 0, addresses);

    if (pReturned != NULL) {
        *pReturned = outCount;
    }
    return outCount;
}

/**************************************************/
/*              隐藏驱动检测 (DKOM)                */
/*  FindHiddenDrivers 三方交叉比对:        */
/*    EnumDeviceDrivers vs SCM 服务注册表          */
/*    vs NtQuerySystemInformation(模块列表).       */
/*  修正: 路径统一归一化 (见 KedNormalizeModulePath) */
/**************************************************/

typedef NTSTATUS (NTAPI *KED_NT_QUERY_SYSTEM_INFORMATION)(
    _In_ ULONG SystemInformationClass,
    _Inout_opt_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

/* 路径集合条目 (小写 DOS 路径, 供三方交叉比对) */
typedef struct _KED_PATH_ENTRY {
    WCHAR Path[DEF_MAX_PATH * 2];
} KED_PATH_ENTRY;

/*
 * KedPathSetAdd — 集合动态追加 (替代一次性 3×64K×1KB ≈ 192MB 预分配,
 * vector 动态增长语义): 满则翻倍扩容 (起点 1024, 上限 64K)。
 * 返回 FALSE 表示扩容失败或已达上限, 调用方应停止收集该集合。
 */
static BOOLEAN
KedPathSetAdd(
    _Inout_ KED_PATH_ENTRY** Set,
    _Inout_ PULONG           Count,
    _Inout_ PULONG           Cap,
    _In_z_  PCWSTR           Path
)
{
    KED_PATH_ENTRY* newSet;
    ULONG newCap;

    if (*Count >= *Cap) {
        newCap = (*Cap == 0) ? 1024 : (*Cap * 2);
        if (newCap > KED_MAX_DRIVER_COUNT) {
            newCap = KED_MAX_DRIVER_COUNT;
        }
        if (newCap <= *Cap) {
            return FALSE;   /* 已达上限 */
        }
        newSet = (KED_PATH_ENTRY*)HeapReAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, *Set,
            newCap * sizeof(KED_PATH_ENTRY));
        if (newSet == NULL) {
            return FALSE;
        }
        *Set = newSet;
        *Cap = newCap;
    }

    wcsncpy_s((*Set)[*Count].Path, DEF_MAX_PATH * 2, Path, _TRUNCATE);
    ++*Count;
    return TRUE;
}

ULONG
KedFindHiddenDrivers(
    _Out_writes_to_opt_(MaxDrivers, *pReturned) PKED_DRIVER_INFO Drivers,
    _In_                               ULONG            MaxDrivers,
    _Out_opt_                          PULONG           pReturned
)
{
    /* 路径集合 (小写 DOS 路径, 动态扩容见 KedPathSetAdd) */
    KED_PATH_ENTRY* enumPaths = NULL;
    KED_PATH_ENTRY* kernelPaths = NULL;
    KED_PATH_ENTRY* servicePaths = NULL;
    ULONG enumCount = 0;
    ULONG kernelCount = 0;
    ULONG serviceCount = 0;
    ULONG enumCap = 0, kernelCap = 0, serviceCap = 0;
    ULONG outCount = 0;
    ULONG suspectCount = 0;
    ULONG i, j;
    KED_DOS_MAP dosMap[KED_MAX_DOS_MAP];
    ULONG mapCount;
    ULONG sysInfoClass = 11;    /* SystemModuleInformation */
    KED_NT_QUERY_SYSTEM_INFORMATION pNtQuery;
    ULONG bufSize = 0;
    BYTE* moduleBuf = NULL;
    NTSTATUS nts;
    ULONG moduleCount = 0;
    KED_RTL_PROCESS_MODULE_INFORMATION_EX* modInfo;
    HKEY hServicesKey = NULL;
    ULONG svcIdx = 0;
    BOOLEAN hiddenReported = FALSE;

    if (pReturned != NULL) {
        *pReturned = 0;
    }
    if (Drivers == NULL || MaxDrivers == 0) {
        return 0;
    }

    /* Running 门控 (SS: status != Running 直接返回空) */
    if (KedGetStatus() != KedStatus_Running) {
        return 0;
    }

    mapCount = KedBuildDosMap(dosMap, KED_MAX_DOS_MAP);

    /* 集合采用动态扩容 (KedPathSetAdd), 避免一次性 192MB 预分配 */

    /* ---- 1) EnumDeviceDrivers 路径集 ---- */
    {
        LPVOID* addrs = NULL;
        DWORD   bytesNeeded = 0;
        SIZE_T  allocCount = KED_MAX_DRIVER_ADDRS_INIT;
        ULONG   attempt;

        for (attempt = 0; attempt < 4; ++attempt) {
            addrs = (LPVOID*)HeapAlloc(GetProcessHeap(), 0,
                                       allocCount * sizeof(LPVOID));
            if (addrs == NULL) {
                goto done;
            }
            if (!EnumDeviceDrivers(addrs, (DWORD)(allocCount * sizeof(LPVOID)),
                                   &bytesNeeded)) {
                HeapFree(GetProcessHeap(), 0, addrs);
                goto done;
            }
            if (bytesNeeded <= (DWORD)(allocCount * sizeof(LPVOID))) {
                break;
            }
            {
                SIZE_T nc = (SIZE_T)(bytesNeeded / sizeof(LPVOID)) + 64;
                if (nc > KED_MAX_DRIVER_COUNT) nc = KED_MAX_DRIVER_COUNT;
                if (nc <= allocCount) { HeapFree(GetProcessHeap(), 0, addrs); goto done; }
                HeapFree(GetProcessHeap(), 0, addrs);
                allocCount = nc;
                addrs = NULL;
            }
        }
        if (addrs != NULL) {
            ULONG cnt = (ULONG)min((SIZE_T)(bytesNeeded / sizeof(LPVOID)),
                                   allocCount);
            WCHAR dev[DEF_MAX_PATH * 2];
            WCHAR dos[DEF_MAX_PATH * 2];
            WCHAR dosLower[DEF_MAX_PATH * 2];

            for (i = 0; i < cnt; ++i) {
                if (GetDeviceDriverFileNameW(addrs[i], dev, DEF_MAX_PATH * 2) &&
                    KedNormalizeModulePath(dev, dosMap, mapCount,
                                           dos, DEF_MAX_PATH * 2)) {
                    KedLowerCopyW(dos, dosLower, DEF_MAX_PATH * 2);
                    if (!KedPathSetAdd(&enumPaths, &enumCount, &enumCap,
                                       dosLower)) {
                        break;   /* 扩容失败/达上限: 停止收集该集合 */
                    }
                }
            }
            HeapFree(GetProcessHeap(), 0, addrs);
        }
    }

    /* ---- 2) SCM 服务注册表 ImagePath 集 (SS 同款) ---- */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, KED_SERVICES_REG_PATH,
                      0, KEY_READ, &hServicesKey) == ERROR_SUCCESS) {
        WCHAR dosLower[DEF_MAX_PATH * 2];

        for (svcIdx = 0; svcIdx < 8192; ++svcIdx) {
            WCHAR subKey[256];
            WCHAR imagePath[DEF_MAX_PATH * 2];
            DWORD dataSize;
            WCHAR dos[DEF_MAX_PATH * 2];

            if (RegEnumKeyW(hServicesKey, svcIdx, subKey, 256) != ERROR_SUCCESS) {
                break;
            }
            dataSize = sizeof(imagePath);
            if (RegGetValueW(hServicesKey, subKey, L"ImagePath",
                             RRF_RT_REG_SZ, NULL,
                             (LPBYTE)imagePath, &dataSize) != ERROR_SUCCESS) {
                continue;
            }
            if (!KedNormalizeModulePath(imagePath, dosMap, mapCount,
                                        dos, DEF_MAX_PATH * 2)) {
                continue;
            }
            KedLowerCopyW(dos, dosLower, DEF_MAX_PATH * 2);
            if (!KedPathSetAdd(&servicePaths, &serviceCount, &serviceCap,
                               dosLower)) {
                break;
            }
        }
        RegCloseKey(hServicesKey);
    }

    /* ---- 3) NtQuerySystemInformation(SystemModuleInformation) ---- */
    pNtQuery = (KED_NT_QUERY_SYSTEM_INFORMATION)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                       "NtQuerySystemInformation");
    if (pNtQuery != NULL) {
        nts = pNtQuery(sysInfoClass, NULL, 0, &bufSize);
        if (bufSize > 0 && bufSize < KED_SYSTEM_MODULE_CAP) {   /* 16MB 上限 */
            moduleBuf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bufSize);
            if (moduleBuf != NULL) {
                nts = pNtQuery(sysInfoClass, moduleBuf, bufSize, &bufSize);
                if (NT_SUCCESS(nts)) {
                    moduleCount = *(ULONG*)moduleBuf;
                    modInfo = (KED_RTL_PROCESS_MODULE_INFORMATION_EX*)
                        (moduleBuf + sizeof(ULONG));
                    {
                        WCHAR dosLower[DEF_MAX_PATH * 2];

                        for (i = 0; i < moduleCount; ++i) {
                            WCHAR wFull[256];
                            WCHAR dos[DEF_MAX_PATH * 2];

                            MultiByteToWideChar(CP_ACP, 0,
                                                (const char*)modInfo[i].FullPathName,
                                                -1, wFull, 256);
                            wFull[255] = L'\0';
                            if (KedNormalizeModulePath(wFull, dosMap, mapCount,
                                                       dos, DEF_MAX_PATH * 2)) {
                                KedLowerCopyW(dos, dosLower, DEF_MAX_PATH * 2);
                                if (!KedPathSetAdd(&kernelPaths, &kernelCount,
                                                   &kernelCap, dosLower)) {
                                    break;
                                }
                            }
                        }
                    }
                }
                HeapFree(GetProcessHeap(), 0, moduleBuf);
            }
        }
    }

    /* ---- 4) 内核模块对 EnumDeviceDrivers 不可见 = 疑似 DKOM 隐藏 ---- */
    for (i = 0; i < kernelCount; ++i) {
        BOOLEAN visible = FALSE;
        for (j = 0; j < enumCount; ++j) {
            if (wcscmp(kernelPaths[i].Path, enumPaths[j].Path) == 0) {
                visible = TRUE;
                break;
            }
        }
        if (!visible) {
            if (outCount < MaxDrivers) {
                PKED_DRIVER_INFO di = &Drivers[outCount];
                RtlZeroMemory(di, sizeof(*di));
                wcsncpy_s(di->FilePath, _countof(di->FilePath),
                          kernelPaths[i].Path, _TRUNCATE);
                wcsncpy_s(di->FileName, _countof(di->FileName),
                          kernelPaths[i].Path, _TRUNCATE);
                di->IsVulnerable = TRUE;   /* SS 同款标记 */
                strncpy_s(di->ThreatIntelSource,
                          _countof(di->ThreatIntelSource),
                          "Hidden driver detection (DKOM)", _TRUNCATE);
                ++outCount;
            }
            ++suspectCount;
        }
    }

    if (suspectCount > 0 && !hiddenReported) {
        KED_EVENT ev;
        RtlZeroMemory(&ev, sizeof(ev));
        ev.Kind = KedEvent_HiddenDriver;
        ev.ThreatType = KedThreat_HiddenDriver;
        ev.ConfidenceScore = 70;                         /* SS confidence=70 */
        ev.Action = KedAction_Alert;
        sprintf_s(ev.Details, _countof(ev.Details),
                  "DKOM analysis detected %lu hidden driver(s) in kernel modules",
                  suspectCount);
        hiddenReported = TRUE;

        InterlockedExchangeAdd(&g_Stats.HiddenDriversDetected, suspectCount);

        KedRecordEvent(&ev);   /* SS: RecordDetection + NotifyKernelExploit */
    }

done:
    if (enumPaths)   HeapFree(GetProcessHeap(), 0, enumPaths);
    if (kernelPaths) HeapFree(GetProcessHeap(), 0, kernelPaths);
    if (servicePaths) HeapFree(GetProcessHeap(), 0, servicePaths);

    if (pReturned != NULL) {
        *pReturned = outCount;
    }
    return outCount;
}

/**************************************************/
/*               黑名单管理                        */
/**************************************************/

VOID
KedAddToBlacklist(
    _In_ PCWSTR Sha256Hex,
    _In_opt_ PCWSTR Reason
)
{
    CHAR hex[65];
    CHAR reason[128];
    ULONG i;

    if (Sha256Hex == NULL) {
        return;
    }

    hex[0] = '\0';   /* 转换失败防未初始化读 */
    WideCharToMultiByte(CP_ACP, 0, Sha256Hex, -1, hex, 65, NULL, NULL);
    if (!KedIsValidSha256Hex(hex)) {
        return;   /* SS: 无效 SHA256 拒绝 */
    }

    reason[0] = '\0';   /* 转换失败防未初始化读 */
    if (Reason != NULL) {
        WideCharToMultiByte(CP_ACP, 0, Reason, -1, reason, 128, NULL, NULL);
    }

    AcquireSRWLockExclusive(&g_Lock);

    for (i = 0; i < g_BlacklistCount; ++i) {
        if (_stricmp(g_Blacklist[i].Sha256Hex, hex) == 0) {
            strncpy_s(g_Blacklist[i].Reason, 128, reason, _TRUNCATE);
            ReleaseSRWLockExclusive(&g_Lock);
            return;   /* 已存在: 更新原因 */
        }
    }

    if (g_BlacklistCount >= KED_MAX_BLACKLIST_ENTRIES) {
        ReleaseSRWLockExclusive(&g_Lock);
        return;
    }

    strncpy_s(g_Blacklist[g_BlacklistCount].Sha256Hex, 65, hex, _TRUNCATE);
    strncpy_s(g_Blacklist[g_BlacklistCount].Reason, 128, reason, _TRUNCATE);
    ++g_BlacklistCount;

    ReleaseSRWLockExclusive(&g_Lock);
}

VOID
KedRemoveFromBlacklist(
    _In_ PCWSTR Sha256Hex
)
{
    CHAR hex[65];
    ULONG i;

    if (Sha256Hex == NULL) {
        return;
    }
    hex[0] = '\0';   /* 转换失败防未初始化读 */
    WideCharToMultiByte(CP_ACP, 0, Sha256Hex, -1, hex, 65, NULL, NULL);

    AcquireSRWLockExclusive(&g_Lock);

    for (i = 0; i < g_BlacklistCount; ++i) {
        if (_stricmp(g_Blacklist[i].Sha256Hex, hex) == 0) {
            if (i + 1 < g_BlacklistCount) {
                memmove(&g_Blacklist[i], &g_Blacklist[i + 1],
                        (g_BlacklistCount - i - 1) * sizeof(KED_BLACKLIST_ENTRY));
            }
            --g_BlacklistCount;
            break;
        }
    }

    ReleaseSRWLockExclusive(&g_Lock);
}

VOID
KedWhitelistSigner(
    _In_ PCWSTR SignerName
)
{
    ULONG i;

    if (SignerName == NULL || SignerName[0] == L'\0') {
        return;
    }

    AcquireSRWLockExclusive(&g_Lock);

    for (i = 0; i < g_WhitelistedSignerCount; ++i) {
        if (_wcsicmp(g_WhitelistedSigners[i].Name, SignerName) == 0) {
            ReleaseSRWLockExclusive(&g_Lock);
            return;
        }
    }

    if (g_WhitelistedSignerCount < KED_MAX_WHITELISTED_SIGNERS) {
        wcsncpy_s(g_WhitelistedSigners[g_WhitelistedSignerCount].Name, 256,
                  SignerName, _TRUNCATE);
        ++g_WhitelistedSignerCount;
    }

    ReleaseSRWLockExclusive(&g_Lock);
}

BOOLEAN
KedIsSignerWhitelisted(
    _In_ PCWSTR SignerName
)
{
    ULONG i;
    BOOLEAN hit = FALSE;

    if (SignerName == NULL || SignerName[0] == L'\0') {
        return FALSE;
    }

    AcquireSRWLockShared(&g_Lock);
    for (i = 0; i < g_WhitelistedSignerCount; ++i) {
        if (_wcsicmp(g_WhitelistedSigners[i].Name, SignerName) == 0) {
            hit = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(&g_Lock);

    return hit;
}

/**************************************************/
/*               IOCTL 分析                        */
/*  AnalyzeIOCTL: 速率限制 → 进程信息 →   */
/*  采样 → 可疑判定 → 拦截事件。                  */
/**************************************************/

BOOLEAN
KedIsSuspiciousIoctl(
    _In_ ULONG IoctlCode
)
{
    ULONG i;
    ULONG method;
    ULONG access;

    /* 已知漏洞 IOCTL 表 (SS) */
    for (i = 0; i < KED_VULNERABLE_IOCTLS_COUNT; ++i) {
        if (IoctlCode == g_VulnerableIoctls[i]) {
            return TRUE;
        }
    }

    /* 启发式: METHOD_NEITHER + FILE_ANY_ACCESS (SS) */
    method = IoctlCode & 0x3;
    access = (IoctlCode >> 14) & 0x3;
    if (method == 3 && access == 3) {
        return TRUE;
    }

    return FALSE;
}

NTSTATUS
KedAnalyzeIoctl(
    _In_      ULONG       ProcessId,
    _In_      PCWSTR      DevicePath,
    _In_      ULONG       IoctlCode,
    _In_reads_bytes_opt_(InputSize) const UCHAR* InputBuffer,
    _In_      ULONG       InputSize,
    _Out_opt_ PKED_IOCTL_INFO Event
)
{
    KED_IOCTL_INFO ioctlInfo;
    KED_EVENT ev;
    BOOLEAN rateOk;
    ULONG sampleSize;

    if (DevicePath == NULL) {
        DevicePath = L"";
    }

    RtlZeroMemory(&ioctlInfo, sizeof(ioctlInfo));
    ioctlInfo.ProcessId = ProcessId;
    ioctlInfo.IoctlCode = IoctlCode;
    ioctlInfo.InputBufferSize = InputSize;
    ioctlInfo.OutputBufferSize = 0;   /* 无输出缓冲信息 (SS 亦不填) */
    wcsncpy_s(ioctlInfo.DevicePath, _countof(ioctlInfo.DevicePath),
              DevicePath, _TRUNCATE);

    /* 设备路径尾部 → 驱动名 (SS: driverName 由字段承载) */
    {
        PCWSTR slash = wcsrchr(DevicePath, L'\\');
        if (slash != NULL && slash[1] != L'\0') {
            wcsncpy_s(ioctlInfo.DriverName, _countof(ioctlInfo.DriverName),
                      slash + 1, _TRUNCATE);
        } else if (DevicePath[0] != L'\0') {
            wcsncpy_s(ioctlInfo.DriverName, _countof(ioctlInfo.DriverName),
                      DevicePath, _TRUNCATE);
        }
    }

    /* Running 门控 (SS: status != Running 返回空事件) */
    if (KedGetStatus() != KedStatus_Running) {
        if (Event != NULL) {
            *Event = ioctlInfo;
        }
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* 每进程速率限制 (SS) */
    AcquireSRWLockExclusive(&g_Lock);
    rateOk = KedRateLimitCheck(ProcessId);
    ReleaseSRWLockExclusive(&g_Lock);
    if (!rateOk) {
        if (Event != NULL) {
            *Event = ioctlInfo;   /* 被丢弃事件仅填充基础字段 (SS 同款) */
        }
        return STATUS_SUCCESS;
    }

    /* 进程信息 (SS ProcessUtils::GetProcessPath) */
    KedQueryProcessPathEx(ProcessId, ioctlInfo.ProcessName,
                          _countof(ioctlInfo.ProcessName),
                          ioctlInfo.ProcessName,
                          _countof(ioctlInfo.ProcessName));
    KedQueryProcessPathEx(ProcessId, ioctlInfo.ProcessPath,
                          _countof(ioctlInfo.ProcessPath),
                          NULL, 0);

    /* 输入采样 (SS: min(size, MAX_IOCTL_SAMPLE_SIZE)) */
    sampleSize = (InputSize > KED_MAX_IOCTL_SAMPLE_SIZE)
                     ? KED_MAX_IOCTL_SAMPLE_SIZE : InputSize;
    if (InputBuffer != NULL && sampleSize > 0) {
        memcpy(ioctlInfo.InputSample, InputBuffer, sampleSize);
        ioctlInfo.InputSampleSize = sampleSize;
    }

    /* 可疑判定 (SS IsSuspiciousIOCTL) */
    ioctlInfo.IsSuspicious = KedIsSuspiciousIoctl(IoctlCode);
    if (ioctlInfo.IsSuspicious) {
        ioctlInfo.ThreatType = KedThreat_IoctlAbuse;
        strncpy_s(ioctlInfo.SuspicionReason,
                  _countof(ioctlInfo.SuspicionReason),
                  "Known vulnerable IOCTL code", _TRUNCATE);

        InterlockedIncrement(&g_Stats.SuspiciousIoctlsDetected);
        InterlockedIncrement(&g_Stats.IoctlEventsAnalyzed);

        /* 拦截策略 (SS: blockSuspiciousIOCTL) */
        if (g_Config.BlockSuspiciousIoctl) {
            ioctlInfo.WasBlocked = TRUE;
            InterlockedIncrement(&g_Stats.ExploitAttemptsBlocked);

            RtlZeroMemory(&ev, sizeof(ev));
            ev.Kind = KedEvent_Ioctl;
            ev.ThreatType = KedThreat_IoctlAbuse;
            ev.SourceProcessId = ProcessId;
            wcsncpy_s(ev.SourceProcessName, _countof(ev.SourceProcessName),
                      ioctlInfo.ProcessName, _TRUNCATE);
            wcsncpy_s(ev.SourceProcessPath, _countof(ev.SourceProcessPath),
                      ioctlInfo.ProcessPath, _TRUNCATE);
            ev.ConfidenceScore = 85;                    /* SS confidence=85 */
            ev.Action = KedAction_Block;
            ev.WasBlocked = TRUE;
            sprintf_s(ev.Details, _countof(ev.Details),
                       "Blocked suspicious IOCTL 0x%08X device %ls",
                       IoctlCode, DevicePath);
            ev.Info.Ioctl = ioctlInfo;

            KedRecordEvent(&ev);   /* SS: RecordDetection + NotifyKernelExploit */
        }
    } else {
        InterlockedIncrement(&g_Stats.IoctlEventsAnalyzed);
    }

    if (Event != NULL) {
        *Event = ioctlInfo;
    }
    return STATUS_SUCCESS;
}

/**************************************************/
/*               KASLR 泄漏检测                    */
/*  DetectKASLRLeak: 进程虚拟地址空间      */
/*  内核指针扫描, 阈值 3 判定泄漏。               */
/**************************************************/

BOOLEAN
KedIsKernelAddress(
    _In_ ULONG64 Address
)
{
    return (Address >= KED_KERNEL_ADDRESS_MIN &&
            Address <= KED_KERNEL_ADDRESS_MAX);
}

BOOLEAN
KedDetectKaslrLeak(
    _In_ ULONG ProcessId
)
{
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    UCHAR* addr = NULL;
    ULONG kernelAddrCount = 0;
    BOOLEAN leakDetected = FALSE;
    UCHAR buffer[4096];
    KED_EVENT ev;

    /* Running 门控 (SS) */
    if (KedGetStatus() != KedStatus_Running) {
        return FALSE;
    }

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                           FALSE, ProcessId);
    if (hProcess == NULL) {
        return FALSE;
    }

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != 0) {
        SIZE_T bytesRead = 0;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
                            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD)) {

            /* 每区采样前 4KB (SS SAMPLE_SIZE=4096) */
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer,
                                  sizeof(buffer), &bytesRead) &&
                bytesRead >= 8) {
                SIZE_T i;
                /* 逐 8 字节扫描内核指针 (SS memcpy 避 UB) */
                for (i = 0; i + 8 <= bytesRead; i += 8) {
                    ULONG64 val = 0;
                    memcpy(&val, buffer + i, sizeof(val));
                    if (KedIsKernelAddress(val)) {
                        ++kernelAddrCount;
                        if (kernelAddrCount >= KED_KASLR_LEAK_THRESHOLD) {
                            leakDetected = TRUE;
                            break;
                        }
                    }
                }
            }
        }

        if (leakDetected) {
            break;
        }

        /* 防御: 零尺寸/不前进则退出 (SS 同款防死循环) */
        if (mbi.RegionSize == 0) {
            break;
        }
        if ((UCHAR*)mbi.BaseAddress + mbi.RegionSize <= addr) {
            break;
        }
        addr = (UCHAR*)mbi.BaseAddress + mbi.RegionSize;
    }

    CloseHandle(hProcess);

    if (leakDetected) {
        WCHAR procName[DEF_MAX_IMAGE_NAME];
        WCHAR procPath[DEF_MAX_PATH * 2];

        InterlockedIncrement(&g_Stats.KaslrLeaksDetected);

        RtlZeroMemory(&ev, sizeof(ev));
        ev.Kind = KedEvent_KaslrLeak;
        ev.ThreatType = KedThreat_KaslrLeak;
        ev.SourceProcessId = ProcessId;
        ev.ConfidenceScore = 75;                    /* SS confidence=75 */
        ev.Action = KedAction_Alert;
        sprintf_s(ev.Details, _countof(ev.Details),
                  "Potential KASLR information disclosure detected (%lu kernel addresses)",
                  kernelAddrCount);

        KedQueryProcessPathEx(ProcessId, procPath, _countof(procPath),
                              procName, _countof(procName));
        wcsncpy_s(ev.SourceProcessName, _countof(ev.SourceProcessName),
                  procName, _TRUNCATE);
        wcsncpy_s(ev.SourceProcessPath, _countof(ev.SourceProcessPath),
                  procPath, _TRUNCATE);

        KedRecordEvent(&ev);   /* SS: RecordDetection + NotifyKernelExploit */
    }

    return leakDetected;
}

/**************************************************/
/*               BSOD 分析                         */
/*  AnalyzeBSODDump: MDMP 仅遥测;         */
/*  DUMP_HEADER64 0x38 崩溃码 + 0x40 四参数.      */
/**************************************************/

NTSTATUS
KedAnalyzeBsodDump(
    _In_  PCWSTR             DumpPath,
    _Out_ PKED_BUGCHECK_INFO Analysis
)
{
    WIN32_FILE_ATTRIBUTE_DATA fad;
    LARGE_INTEGER fileSize;
    HANDLE hFile;
    BYTE header[KED_MIN_DUMP_HEADER_SIZE];
    DWORD bytesRead = 0;
    ULONG signature;
    ULONG validDump;
    ULONG i;
    ULONG bugCheckCode;
    ULONG64 params[4];
    KED_EVENT ev;
    BOOLEAN knownMatch = FALSE;

    if (DumpPath == NULL || Analysis == NULL || DumpPath[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Analysis, sizeof(*Analysis));
    wcsncpy_s(Analysis->DumpFilePath, _countof(Analysis->DumpFilePath),
              DumpPath, _TRUNCATE);

    /* 文件存在 + 大小上限 (SS: exists + MAX_DRIVER_SIZE 同款复用) */
    if (!GetFileAttributesExW(DumpPath, GetFileExInfoStandard, &fad)) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    fileSize.LowPart  = fad.nFileSizeLow;
    fileSize.HighPart = fad.nFileSizeHigh;
    if (fileSize.QuadPart > KED_MAX_DRIVER_SIZE) {
        return STATUS_FILE_TOO_LARGE;
    }

    hFile = CreateFileW(DumpPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return STATUS_ACCESS_DENIED;
    }

    /* 读取头部 (含 0x38..0x58 字段) */
    if (!ReadFile(hFile, header, sizeof(header), &bytesRead, NULL) ||
        bytesRead < 0x58 + 8) {
        CloseHandle(hFile);
        return STATUS_BUFFER_TOO_SMALL;   /* SS: 短读即返回 */
    }
    CloseHandle(hFile);

    memcpy(&signature, header, 4);

    /* ---- MDMP: 结构化解析未实现, 仅遥测 (SS 对齐注释) ---- */
    if (signature == KED_MDMP_SIGNATURE) {
        strncpy_s(Analysis->BugCheckName, _countof(Analysis->BugCheckName),
                  "MINIDUMP_FORMAT_NOT_PARSED", _TRUNCATE);
        strncpy_s(Analysis->Summary, _countof(Analysis->Summary),
                  "Minidump (MDMP) format detected; structured parser pending",
                  _TRUNCATE);
        Analysis->IsExploitIndicator = FALSE;

        InterlockedIncrement(&g_Stats.BugChecksAnalyzed);

        RtlZeroMemory(&ev, sizeof(ev));
        ev.Kind = KedEvent_BugCheck;
        ev.ThreatType = KedThreat_Unknown;
        ev.ConfidenceScore = 0;
        ev.Action = KedAction_None;
        sprintf_s(ev.Details, _countof(ev.Details),
                  "BSOD dump %ls is MINIDUMP - structured parse not yet implemented",
                  DumpPath);
        ev.Info.BugCheck = *Analysis;

        KedRecordEvent(&ev);
        return STATUS_SUCCESS;
    }

    /* ---- 非 PAGE 头: 无法解析 ---- */
    if (signature != KED_PAGE_SIGNATURE) {
        return STATUS_UNRECOGNIZED_MEDIA;
    }

    memcpy(&validDump, header + 4, 4);
    if (validDump != KED_DUMP_SIGNATURE && validDump != KED_DU64_SIGNATURE) {
        return STATUS_UNRECOGNIZED_MEDIA;
    }

    /* DUMP_HEADER64: BugCheckCode @0x38, Parameter1..4 @0x40 (SS) */
    memcpy(&bugCheckCode, header + KED_DUMP_BUGCHECK_CODE_OFFSET, sizeof(bugCheckCode));
    for (i = 0; i < 4; ++i) {
        memcpy(&params[i], header + KED_DUMP_BUGCHECK_PARAM_OFFSET + i * 8,
               sizeof(params[i]));
    }

    Analysis->BugCheckCode = bugCheckCode;
    strncpy_s(Analysis->BugCheckName, _countof(Analysis->BugCheckName),
              KedGetBugCheckCodeName(bugCheckCode), _TRUNCATE);

    /* 已知崩溃码分类 (SS) */
    for (i = 0; i < KED_BUGCHECK_COUNT; ++i) {
        if (g_KnownBugChecks[i].Code == bugCheckCode) {
            Analysis->Category = g_KnownBugChecks[i].Category;
            Analysis->IsExploitIndicator = g_KnownBugChecks[i].IsExploitIndicator;
            knownMatch = TRUE;
            break;
        }
    }
    if (!knownMatch) {
        Analysis->Category = KedBcc_Unknown;
        Analysis->IsExploitIndicator = FALSE;
    }

    memcpy(Analysis->Parameters, params, sizeof(params));

    /* 参数 1 指向内核空间 → 故障地址 (SS) */
    if (params[0] != 0) {
        Analysis->FaultingAddress = params[0];
        if (KedIsKernelAddress(params[0])) {
            wcscpy_s(Analysis->FaultingModule, _countof(Analysis->FaultingModule),
                     L"<kernel>");
        }
    }

    /* 参数 2/3 模块提示: 占位启发式 (SS 对齐注释: 未做真实解析) */
    if (Analysis->FaultingModule[0] == L'\0' &&
        (params[1] != 0 || params[2] != 0)) {
        wcscpy_s(Analysis->FaultingModule, _countof(Analysis->FaultingModule),
                 L"<unknown_module>");
    }
    if (Analysis->FaultingModule[0] == L'\0') {
        wcscpy_s(Analysis->FaultingModule, _countof(Analysis->FaultingModule),
                 L"<unknown>");
    }

    /* 摘要 (SS std::format 语义) */
    if (Analysis->IsExploitIndicator) {
        sprintf_s(Analysis->Summary, _countof(Analysis->Summary),
                  "Exploit-indicator crash: %s (0x%08X) at module %ls - possible kernel exploitation attempt",
                  Analysis->BugCheckName, bugCheckCode,
                  Analysis->FaultingModule);
    } else {
        sprintf_s(Analysis->Summary, _countof(Analysis->Summary),
                  "Bug check: %s (0x%08X) at module %ls",
                  Analysis->BugCheckName, bugCheckCode,
                  Analysis->FaultingModule);
    }

    InterlockedIncrement(&g_Stats.BugChecksAnalyzed);

    RtlZeroMemory(&ev, sizeof(ev));
    ev.Kind = KedEvent_BugCheck;
    ev.ThreatType = KedThreat_Unknown;
    ev.ConfidenceScore = 0;
    ev.Action = KedAction_None;
    if (Analysis->IsExploitIndicator) {
        ev.ThreatType = KedThreat_PrivilegeEscalation;   /* 利用指示崩溃 */
        ev.ConfidenceScore = 70;
        ev.Action = KedAction_Alert;
    }
    sprintf_s(ev.Details, _countof(ev.Details),
              "Analyzed BSOD dump: %s (0x%08X, exploit: %s)",
              Analysis->BugCheckName, bugCheckCode,
              Analysis->IsExploitIndicator ? "yes" : "no");
    ev.Info.BugCheck = *Analysis;

    KedRecordEvent(&ev);   /* SS: RecordBSODAnalysis → C 统一事件 */

    return STATUS_SUCCESS;
}

/**************************************************/
/*               回调 / 统计                        */
/**************************************************/

VOID
KedRegisterCallback(
    _In_opt_ KED_DETECTED_CALLBACK Callback,
    _In_opt_ PVOID                 Context
)
{
    AcquireSRWLockExclusive(&g_Lock);
    g_Callback = Callback;
    g_CallbackContext = Context;
    ReleaseSRWLockExclusive(&g_Lock);
}

VOID
KedGetStatistics(
    _Out_ PKED_STATISTICS Stats
)
{
    if (Stats == NULL) {
        return;
    }

    Stats->DriversScanned            = g_Stats.DriversScanned;
    Stats->DriversBlocked            = g_Stats.DriversBlocked;
    Stats->VulnerableDriversDetected = g_Stats.VulnerableDriversDetected;
    Stats->LolDriversDetected        = g_Stats.LolDriversDetected;
    Stats->UnsignedDriversDetected   = g_Stats.UnsignedDriversDetected;
    Stats->IoctlEventsAnalyzed       = g_Stats.IoctlEventsAnalyzed;
    Stats->SuspiciousIoctlsDetected  = g_Stats.SuspiciousIoctlsDetected;
    Stats->KaslrLeaksDetected        = g_Stats.KaslrLeaksDetected;
    Stats->ExploitAttemptsBlocked    = g_Stats.ExploitAttemptsBlocked;
    Stats->BugChecksAnalyzed         = g_Stats.BugChecksAnalyzed;
    Stats->HiddenDriversDetected     = g_Stats.HiddenDriversDetected;
    Stats->EventsReported            = g_Stats.EventsReported;
}

VOID
KedResetStatistics(VOID)
{
    AcquireSRWLockExclusive(&g_Lock);
    RtlZeroMemory(&g_Stats, sizeof(g_Stats));
    g_EventSeq = 0;
    ReleaseSRWLockExclusive(&g_Lock);
}

/**************************************************/
/*               SelfTest                          */
/*  SelfTest 4 测试项。                    */
/**************************************************/

BOOLEAN
KedSelfTest(VOID)
{
    KED_CONFIG cfg = KED_DEFAULT_CONFIG;
    ULONG i;
    BOOLEAN allPassed = TRUE;
    ULONG id1, id2;

    /* 测试 1: 默认配置有效 (SS Test 1) */
    if (!KedConfigIsValid(&cfg)) {
        allPassed = FALSE;
    }

    /* 测试 2: 全部已知漏洞 IOCTL 可识别 (SS Test 2) */
    for (i = 0; i < KED_VULNERABLE_IOCTLS_COUNT; ++i) {
        if (!KedIsSuspiciousIoctl(g_VulnerableIoctls[i])) {
            allPassed = FALSE;
        }
    }

    /* 测试 3: 内核地址范围判定 (SS Test 3) */
    if (!KedIsKernelAddress(0xFFFFF80000000000ULL)) {
        allPassed = FALSE;
    }
    if (KedIsKernelAddress(0x0000000000001000ULL)) {
        allPassed = FALSE;
    }

    /* 测试 4: 事件 ID 唯一性 (SS Test 4) */
    id1 = KedNextEventId();
    id2 = KedNextEventId();
    if (id1 == id2) {
        allPassed = FALSE;
    }

    return allPassed;
}

/**************************************************/
/*               工具函数                           */
/*  Get*Name 名称解析函数族。               */
/**************************************************/

PCSTR
KedGetThreatTypeName(
    _In_ KED_THREAT_TYPE Type
)
{
    switch (Type) {
        case KedThreat_VulnerableDriverLoad:    return "VulnerableDriverLoad";
        case KedThreat_MaliciousDriverLoad:     return "MaliciousDriverLoad";
        case KedThreat_UnsignedDriverLoad:      return "UnsignedDriverLoad";
        case KedThreat_TokenStealing:           return "TokenStealing";
        case KedThreat_NullPointerDeref:        return "NullPointerDeref";
        case KedThreat_PoolCorruption:          return "PoolCorruption";
        case KedThreat_TypeConfusion:           return "TypeConfusion";
        case KedThreat_IntegerOverflow:         return "IntegerOverflow";
        case KedThreat_UseAfterFree:            return "UseAfterFree";
        case KedThreat_HiddenDriver:            return "HiddenDriver";
        case KedThreat_Ssdthooking:             return "SSDTHooking";
        case KedThreat_KaslrLeak:               return "KASLRLeak";
        case KedThreat_CallbackTampering:       return "CallbackTampering";
        case KedThreat_DkomAttack:              return "DKOMAttack";
        case KedThreat_PrivilegeEscalation:     return "PrivilegeEscalation";
        case KedThreat_ArbitraryRead:           return "ArbitraryRead";
        case KedThreat_ArbitraryWrite:          return "ArbitraryWrite";
        case KedThreat_IoctlAbuse:              return "IOCTLAbuse";
        case KedThreat_DriverBlocklistViolation: return "DriverBlocklistViolation";
        default:                                return "Unknown";
    }
}

PCSTR
KedGetSignatureStatusName(
    _In_ KED_SIGNATURE_STATUS Status
)
{
    switch (Status) {
        case KedSig_ValidSigned:        return "ValidSigned";
        case KedSig_InvalidSignature:   return "InvalidSignature";
        case KedSig_Unsigned:           return "Unsigned";
        case KedSig_RevokedCertificate: return "RevokedCertificate";
        case KedSig_ExpiredCertificate: return "ExpiredCertificate";
        case KedSig_TestSigned:         return "TestSigned";
        case KedSig_WhqlSigned:         return "WhqlSigned";
        case KedSig_AttestationSigned:  return "AttestationSigned";
        case KedSig_SelfSigned:         return "SelfSigned";
        default:                        return "Unknown";
    }
}

PCSTR
KedGetVulnerabilityClassName(
    _In_ KED_VULN_CLASS Class
)
{
    switch (Class) {
        case KedVuln_ArbitraryMemoryRead:   return "ArbitraryMemoryRead";
        case KedVuln_ArbitraryMemoryWrite:  return "ArbitraryMemoryWrite";
        case KedVuln_ArbitraryMsrAccess:    return "ArbitraryMSRAccess";
        case KedVuln_ArbitraryPortAccess:   return "ArbitraryPortAccess";
        case KedVuln_ArbitraryPhysAccess:   return "ArbitraryPhysicalAccess";
        case KedVuln_PrivilegeEscalation:   return "PrivilegeEscalation";
        case KedVuln_CodeExecution:         return "CodeExecution";
        case KedVuln_InformationDisclosure: return "InformationDisclosure";
        case KedVuln_DenialOfService:       return "DenialOfService";
        case KedVuln_Multiple:              return "Multiple";
        default:                            return "Unknown";
    }
}

PCSTR
KedGetBugCheckCategoryName(
    _In_ KED_BUGCHECK_CATEGORY Category
)
{
    switch (Category) {
        case KedBcc_MemoryCorruption: return "MemoryCorruption";
        case KedBcc_NullDereference:  return "NullDereference";
        case KedBcc_PoolCorruption:   return "PoolCorruption";
        case KedBcc_StackOverflow:    return "StackOverflow";
        case KedBcc_InvalidAccess:    return "InvalidAccess";
        case KedBcc_DriverFault:      return "DriverFault";
        case KedBcc_ExploitIndicator: return "ExploitIndicator";
        default:                      return "Unknown";
    }
}

PCSTR
KedGetBugCheckCodeName(
    _In_ ULONG BugCheckCode
)
{
    static char s_unknown[32];
    ULONG i;

    for (i = 0; i < KED_BUGCHECK_COUNT; ++i) {
        if (g_KnownBugChecks[i].Code == BugCheckCode) {
            return g_KnownBugChecks[i].Name;
        }
    }

    /* SS: "UNKNOWN_BUGCHECK_" + hex */
    sprintf_s(s_unknown, sizeof(s_unknown), "UNKNOWN_0x%08X", BugCheckCode);
    return s_unknown;
}