/**************************************************/
/*  WkDefender Agent — Registry\RegistryAnalyzer   */
/*  注册表取证分析引擎 (The Deep Inspector)          */
/*                                                  */
/*  迁移来源: ShadowStrike PhantomCore/Core/Registry*/
/*  RegistryAnalyzer.cpp (3281 行 + .hpp 977 行,   */
/*  2026-09-08 全量转写)                           */
/*                                                  */
/*  职责:                                            */
/*   - 五种分析模式: Quick/Standard/Deep/Forensic/  */
/*     RootkitHunting                               */
/*   - 隐藏键检测 (NULL 字节/控制字符注入,           */
/*     NtOpenKey/NtEnumerateKey 原生视图)           */
/*   - 交叉视图 (Win32 vs NTAPI) Rootkit 差异检测   */
/*   - Hive 离线解析 (regf 头校验 / hbin 删除条目    */
/*     空白区恢复)                                  */
/*   - 威胁指标加载与 IOC 匹配 (通配符语义)         */
/*   - 自动运行项启发式 (IFEO/AppInit/Winlogon/LSA/ */
/*     PendingFileRename/Run/ServiceDll 7 类)       */
/*   - 时间线构建 / 报告导出 / 熵分析               */
/*                                                  */
/*  虚标剔除 (对齐迁移审计):                         */
/*   - ThreatIntelManager → stub (哈希保留, 判定恒无)*/
/*   - RegistryMonitor/ProcessMonitor (DKOM 联动)   */
/*     → stub 返回 FALSE                            */
/*   - PatternStore(YARA) 被引用未使用 → 不迁移     */
/*   - std::wregex → 自实现 * / ? 通配符匹配        */
/*   - RegistryUtils 封装 → 内联 Win32/NT API       */
/*   - 线程池 (实为串行) → 保留串行语义             */
/*                                                  */
/*  依赖 (WkD 底座):                                 */
/*   Common\BCrypUtils (IocScanner_ComputeBufferSha256) */
/*   ntdll (NtOpenKey/NtEnumerateKey)               */
/**************************************************/

#include "RegistryInternal.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <wchar.h>
#include <string.h>
#include <math.h>

#include <winternl.h>

/* winternl.h 未提供注册表原生 API 声明与枚举 (仅 RtlInitUnicodeString),
 * 此处补声明 (符号经 ntdll.lib 链接) */
typedef enum _RA_KEY_INFORMATION_CLASS {
    RaKeyBasicInformation = 0,
    RaKeyNodeInformation = 1,
    RaKeyFullInformation = 2,
    RaKeyNameInformation = 3
} RA_KEY_INFORMATION_CLASS;

typedef struct _RA_KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG         TitleIndex;
    ULONG         NameLength;
    WCHAR         Name[1];
} RA_KEY_BASIC_INFORMATION, * PRA_KEY_BASIC_INFORMATION;

NTSYSAPI NTSTATUS NTAPI
NtOpenKey(_Out_ PHANDLE KeyHandle,
          _In_ ACCESS_MASK DesiredAccess,
          _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI
NtEnumerateKey(_In_ HANDLE KeyHandle,
               _In_ ULONG Index,
               _In_ RA_KEY_INFORMATION_CLASS KeyInformationClass,
               _Out_ PVOID KeyInformation,
               _In_ ULONG Length,
               _Out_ PULONG ResultLength);

#include "../Common/BCrypUtils.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

/* ==================================================
 * 引擎私有常量
 * ================================================== */
#define RA_LOG_TAG              L"Registry"

#define RA_VALUE_NAME_CAP       32768               /* 注册表值名硬上限含 NUL */
#define RA_EXPAND_CAP           (64 * 1024 / sizeof(WCHAR))  /* %VAR% 展开上限 */
#define RA_MAX_MULTI_SZ_COMPONENTS 4096
#define RA_SHELLCODE_SCAN_LEN   256                 /* shellcode 模式扫描长度 */
#define RA_PS_MARKERS_COUNT     8
#define RA_SCRIPT_MARKERS_COUNT 6

#define RA_FILETIME_TO_UNIX     116444736000000000ULL   /* 1601→1970 (100ns) */
#define RA_MAX_CSV_FIELD        512

#define RA_DEFAULT_MAX_ANOMALIES 100000
#define RA_DEFAULT_THREAD_COUNT 4

/* 时间线导出: 若时间戳为 0 (未设置) 原样输出 0 */

#define RA_HIVE_SYSTEM_ROOT     L"C:\\Windows\\System32\\config\\"
#define RA_HIVE_AMCACHE_PATH    L"C:\\Windows\\AppCompat\\Programs\\Amcache.hve"
#define RA_HIVE_BCD_PATH        L"C:\\Boot\\BCD"

/* hive 文件读取上限 / hbin 块 / 指标文件 / CSV 导出缓冲 */
#define RA_HIVE_SIZE_CAP        (512ULL * 1024 * 1024)
#define RA_HBIN_SIZE_CAP        (64ULL * 1024 * 1024)
#define RA_INDICATOR_FILE_CAP   (8ULL * 1024 * 1024)
#define RA_CSV_LINE_CAP         (4ULL * 1024 * 1024)

/* 删除恢复的 nk 单元字段偏移 (相对单元 4 字节大小头) */
#define NK_NAME_LEN_OFFSET      0x4C
#define NK_NAME_OFFSET          0x50

/* WOW64 双视图标签 */
#define RA_VIEW_TAG_64          L"64"
#define RA_VIEW_TAG_32          L"32"

/* ==================================================
 * 引擎私有类型
 * ================================================== */

/* 动态宽字符串列表 (内部容器, 替代 std::vector<std::wstring>) */
typedef struct _RA_STRING_LIST {
    PWCHAR* Items;              /* 每项独立分配 WCHAR[WKD_REG_MAX_PATH_CHARS] */
    ULONG   Count;
    ULONG   Capacity;
} RA_STRING_LIST, * PRA_STRING_LIST;

/* 回调槽 (对齐 PD 定长槽模型) */
typedef struct _RA_ANOMALY_CB {
    ULONG                    Id;
    BOOLEAN                  InUse;
    PFN_RA_ANOMALY_CALLBACK  Fn;
    PVOID                    Ctx;
} RA_ANOMALY_CB, * PRA_ANOMALY_CB;

typedef struct _RA_PROGRESS_CB {
    ULONG                    Id;
    BOOLEAN                  InUse;
    PFN_RA_PROGRESS_CALLBACK Fn;
    PVOID                    Ctx;
} RA_PROGRESS_CB, * PRA_PROGRESS_CB;

typedef struct _RA_HIDDEN_CB {
    ULONG                   Id;
    BOOLEAN                 InUse;
    PFN_RA_HIDDEN_CALLBACK  Fn;
    PVOID                   Ctx;
} RA_HIDDEN_CB, * PRA_HIDDEN_CB;

/* 引擎全局上下文 (PIMPL → 模块全局实例) */
typedef struct _WKD_RA_CONTEXT {
    /* 锁 */
    SRWLOCK ConfigLock;        /* 配置/状态/初始化 */
    SRWLOCK AnomalyLock;       /* 异常缓冲 */
    SRWLOCK HiddenLock;        /* 隐藏键缓冲 */
    SRWLOCK TimelineLock;      /* 时间线缓冲 */
    SRWLOCK CallbackLock;      /* 回调表 */
    SRWLOCK IndicatorLock;     /* 威胁指标 */

    /* 状态 */
    volatile LONG   Initialized;
    volatile LONG   Analyzing;
    volatile LONG   AbortRequested;
    volatile LONG   KeyAnomalyCapture;      /* RaAnalyzeKey 期间收集开关 */
    volatile LONG64 NextAnomalyId;
    volatile LONG64 NextCallbackId;

    /* 配置 */
    WKD_RA_CONFIG   Config;

    /* 异常缓冲 (动态增长, 超出上限淘汰最旧) */
    WKD_RA_ANOMALY* Anomalies;
    ULONG           AnomalyCount;
    ULONG           AnomalyCapacity;

    /* 隐藏键清单 */
    RA_STRING_LIST  HiddenKeys;

    /* 历史分析逐键快照 (RaAnalyzeKey 输出源) */
    WKD_RA_ANOMALY* KeyAnomalies;    /* 动态缓冲, 下次调用前有效 */
    ULONG           KeyAnomalyCount;
    ULONG           KeyAnomalyCapacity;

    /* 时间线 */
    WKD_RA_TIMELINE* Timeline;
    ULONG            TimelineCount;
    ULONG            TimelineCapacity;

    /* 恢复条目 (含动态 Data 指针, 由 RaFreeRecoveredEntries 释放) */
    WKD_RA_DELETED_ENTRY* Deleted;
    ULONG                 DeletedCount;
    ULONG                 DeletedCapacity;

    /* 威胁指标 */
    WKD_RA_THREAT_INDICATOR* Indicators;
    ULONG                    IndicatorCount;
    ULONG                    IndicatorCapacity;

    /* 回调 */
    RA_ANOMALY_CB   AnomalyCallbacks[WKD_RA_MAX_CALLBACKS];
    RA_PROGRESS_CB  ProgressCallbacks[WKD_RA_MAX_CALLBACKS];
    RA_HIDDEN_CB    HiddenCallbacks[WKD_RA_MAX_CALLBACKS];

    /* 统计 */
    WKD_RA_STATS    Stats;
} WKD_RA_CONTEXT;

/* 一个静态全局限实例 (SINGLETON, 对齐 PD 模块全局) */
static WKD_RA_CONTEXT g_Ra;

/* ==================================================
 * 静态工具函数
 * ================================================== */

/* 日志输出 (开发排障: OutputDebugStringW; 事件面经
 * Notify 回调由上层编排). 注意: 不用 wvsprintfW —
 * 其不支持 %I64u/%I64d, 此处用 vswprintf_s (MSVC CRT). */
static
VOID RaDbgPrint(_In_ PCWSTR Format, ...) {
    WCHAR buf[512];
    va_list args;
    va_start(args, Format);
    (VOID)vswprintf_s(buf, 512, Format, args);
    va_end(args);
    OutputDebugStringW(buf);
}

static
ULONG RaWcsLen(_In_ PCWSTR S) {
    return (S != NULL) ? (ULONG)wcslen(S) : 0;
}

static
VOID RaWcsCopy(_Inout_ PWSTR Dst, _In_ ULONG DstCch, _In_ PCWSTR Src) {
    if (Dst == NULL || DstCch == 0) return;
    if (Src == NULL) { Dst[0] = L'\0'; return; }
    wcsncpy_s(Dst, DstCch, Src, _TRUNCATE);
}

static
VOID RaWcsCopyN(_Inout_ PWSTR Dst, _In_ ULONG DstCch, _In_ PCWSTR Src, _In_ ULONG MaxLen) {
    if (Dst == NULL || DstCch == 0) return;
    if (Src == NULL) { Dst[0] = L'\0'; return; }
    ULONG n = (ULONG)wcslen(Src);
    if (n > MaxLen) n = MaxLen;
    if (n >= DstCch) n = DstCch - 1;
    wcsncpy_s(Dst, DstCch, Src, n);
    Dst[n] = L'\0';
}

/* 宽→窄 (UTF-8, StringUtils::ToNarrow) */
static
VOID RaToNarrowUtf8(_In_ PCWSTR Wide, _Out_ PCHAR Narrow, _In_ ULONG NarrowCch) {
    if (Wide == NULL || Narrow == NULL || NarrowCch == 0) return;
    (VOID)WideCharToMultiByte(CP_UTF8, 0, Wide, -1, Narrow, (INT)NarrowCch, NULL, NULL);
    Narrow[NarrowCch - 1] = '\0';
}

/* 窄→宽 (UTF-8, StringUtils::ToWide) */
static
VOID RaToWideUtf8(_In_ PCSTR Narrow, _Out_ PWSTR Wide, _In_ ULONG WideCch) {
    if (Narrow == NULL || Wide == NULL || WideCch == 0) return;
    (VOID)MultiByteToWideChar(CP_UTF8, 0, Narrow, -1, Wide, (INT)WideCch);
    Wide[WideCch - 1] = L'\0';
}

/* 小写副本 (原地转小写; 调用方需已深拷贝) */
static
VOID RaWcsToLower(_Inout_ PWSTR S, _In_ ULONG Cch) {
    if (S == NULL || Cch == 0) return;
    (VOID)_wcslwr_s(S, Cch);
}

/* 当前时间 (FILETIME 语义, 100ns/1601 纪元) */
static
WKD_REG_TIMESTAMP RaTimeNow(VOID) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER value;
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return (WKD_REG_TIMESTAMP)value.QuadPart;
}

/* FILETIME → Unix 秒 (时间线 CSV 导出) */
static
LONGLONG RaFileTimeToUnix(_In_ WKD_REG_TIMESTAMP Timestamp) {
    if (Timestamp == 0) return 0;
    return (LONGLONG)((Timestamp - RA_FILETIME_TO_UNIX) / 10000000ULL);
}

/* 时间差毫秒 (两个 FILETIME 语义时间戳) */
static
ULONG RaTimeDeltaMs(_In_ WKD_REG_TIMESTAMP Start, _In_ WKD_REG_TIMESTAMP End) {
    if (End <= Start) return 0;
    return (ULONG)((End - Start) / 10000ULL);
}

/* ASCII 小写折叠 (子串匹配用; ToLowerAscii) */
static
VOID RaToLowerAscii(_Inout_ PWSTR S) {
    if (S == NULL) return;
    for (PWSTR p = S; *p != L'\0'; ++p) {
        if (*p >= L'A' && *p <= L'Z') *p = (WCHAR)(*p + (L'a' - L'A'));
    }
}

/* 大小写不敏感 (ASCII) 子串查找 */
static
BOOLEAN RaWcsContains(_In_ PCWSTR Haystack, _In_ PCWSTR Needle) {
    if (Haystack == NULL || Needle == NULL) return FALSE;
    if (Needle[0] == L'\0') return TRUE;
    size_t hl = wcslen(Haystack);
    size_t nl = wcslen(Needle);
    if (nl > hl) return FALSE;
    for (size_t i = 0; i + nl <= hl; ++i) {
        size_t j = 0;
        while (j < nl) {
            WCHAR a = Haystack[i + j];
            WCHAR b = Needle[j];
            if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
            if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
            if (a != b) break;
            ++j;
        }
        if (j == nl) return TRUE;
    }
    return FALSE;
}

/* 前缀/后缀判定 */
static
BOOLEAN RaWcsStartsWith(_In_ PCWSTR S, _In_ PCWSTR Prefix) {
    if (S == NULL || Prefix == NULL) return FALSE;
    size_t sl = wcslen(S);
    size_t pl = wcslen(Prefix);
    return (pl <= sl) && (_wcsnicmp(S, Prefix, pl) == 0);
}

static
BOOLEAN RaWcsEndsWith(_In_ PCWSTR S, _In_ PCWSTR Suffix) {
    if (S == NULL || Suffix == NULL) return FALSE;
    size_t sl = wcslen(S);
    size_t pl = wcslen(Suffix);
    if (pl > sl) return FALSE;
    return (_wcsnicmp(S + (sl - pl), Suffix, pl) == 0);
}

/* 大小写不敏感宽字符串相等 */
static
BOOLEAN RaWcsEqualsI(_In_ PCWSTR A, _In_ PCWSTR B) {
    if (A == NULL || B == NULL) return FALSE;
    return (_wcsicmp(A, B) == 0);
}

/* 窄字符串拷贝到定长缓冲 (导出用) */
static
VOID RaWcsCopyA(_In_ PCSTR Src, _Out_ PSTR Dst, _In_ ULONG DstCch) {
    if (Dst == NULL || DstCch == 0) return;
    if (Src == NULL) { Dst[0] = '\0'; return; }
    strncpy_s(Dst, DstCch, Src, _TRUNCATE);
}

/* 窄字符串安全拼接 (带长度预算, 返回是否完整) */
static
BOOLEAN SizeT_StringCat(_Inout_ PSTR Dst, _In_ PCSTR Src, _In_ SIZE_T DstCch) {
    if (Dst == NULL || Src == NULL || DstCch == 0) return FALSE;
    SIZE_T dstLen = strnlen(Dst, DstCch);
    SIZE_T srcLen = strlen(Src);
    if (dstLen + srcLen + 1 > DstCch) {
        memcpy(Dst + dstLen, Src, DstCch - dstLen - 1);
        Dst[DstCch - 1] = '\0';
        return FALSE;
    }
    memcpy(Dst + dstLen, Src, srcLen + 1);
    return TRUE;
}

/* 小写副本形式返回在缓冲 (替代 std::wstring 返回) */
static
VOID RaWcsToLowerCopy(_In_ PCWSTR Src, _Out_ PWSTR Dst, _In_ ULONG DstCch) {
    RaWcsCopy(Dst, DstCch, Src);
    RaToLowerAscii(Dst);
}

/* ==================================================
 * 隐藏键 / 交叉视图辅助 (原生视图)
 * ================================================== */

/* 解析当前交互用户 SID; 失败回退 ".DEFAULT" */
static
VOID RaResolveCurrentUserSid(_Out_ PWSTR Sid, _In_ ULONG SidCch) {
    if (Sid == NULL || SidCch == 0) return;
    RaWcsCopy(Sid, SidCch, L".DEFAULT");

    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return;

    DWORD tokenUserLen = 0;
    (VOID)GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenUserLen);
    if (tokenUserLen == 0 || tokenUserLen > 4096) {
        CloseHandle(hToken);
        return;
    }

    BYTE* buf = (BYTE*)malloc(tokenUserLen);
    if (buf == NULL) {
        CloseHandle(hToken);
        return;
    }

    if (GetTokenInformation(hToken, TokenUser, buf, tokenUserLen, &tokenUserLen)) {
        TOKEN_USER* pTokenUser = (TOKEN_USER*)buf;
        LPWSTR pSidStr = NULL;
        if (ConvertSidToStringSidW(pTokenUser->User.Sid, &pSidStr)) {
            RaWcsCopy(Sid, SidCch, pSidStr);
            LocalFree(pSidStr);
        }
    }

    free(buf);
    CloseHandle(hToken);
}

/* 路径结构校验 (NULL 字节 / 穿越序列), IsSafeRegistryPath */
static
BOOLEAN RaIsSafeRegistryPath(_In_ PCWSTR Path) {
    if (Path == NULL) return FALSE;
    ULONG len = (ULONG)wcslen(Path);
    if (len > WKD_RA_MAX_KEY_PATH_LENGTH) return FALSE;
    /* 内嵌 NULL 由 wcslen 截断语义天然检测: 直接用 wcslen 长度,
     * Win32 路径不允许内嵌 NUL, 故无需逐字符扫描 */
    /* 拒绝 "..\ x (常见路径穿越) */
    if (wcsstr(Path, L"\\..\\") != NULL) return FALSE;
    if (RaWcsStartsWith(Path, L"..\\")) return FALSE;
    if (RaWcsEndsWith(Path, L"\\..")) return FALSE;
    return TRUE;
}

/* Win32 路径 → 原生路径 (解析用户 SID), Win32ToNativePath.
 * 输出缓冲 Dst; 返回是否成功。安全校验失败返回 FALSE。 */
static
BOOLEAN RaWin32ToNativePath(_In_ PCWSTR Path, _Out_ PWSTR Dst, _In_ ULONG DstCch) {
    if (Dst == NULL || DstCch == 0) return FALSE;
    Dst[0] = L'\0';
    if (!RaIsSafeRegistryPath(Path)) return FALSE;

    WCHAR native[WKD_RA_MAX_KEY_PATH_LENGTH + 64];
    WCHAR suffix[WKD_RA_MAX_KEY_PATH_LENGTH];
    suffix[0] = L'\0';

    if (RaWcsStartsWith(Path, L"HKEY_LOCAL_MACHINE") || RaWcsStartsWith(Path, L"HKLM")) {
        PCWSTR p = wcschr(Path, L'\\');
        if (p != NULL) RaWcsCopy(suffix, WKD_RA_MAX_KEY_PATH_LENGTH, p);
        RaWcsCopy(native, WKD_RA_MAX_KEY_PATH_LENGTH + 64, L"\\Registry\\Machine");
        wcscat_s(native, WKD_RA_MAX_KEY_PATH_LENGTH + 64, suffix);
    } else if (RaWcsStartsWith(Path, L"HKEY_CURRENT_USER") || RaWcsStartsWith(Path, L"HKCU")) {
        PCWSTR p = wcschr(Path, L'\\');
        if (p != NULL) RaWcsCopy(suffix, WKD_RA_MAX_KEY_PATH_LENGTH, p);
        WCHAR sid[WKD_REG_MAX_USER_SID_CHARS];
        RaResolveCurrentUserSid(sid, WKD_REG_MAX_USER_SID_CHARS);
        _snwprintf_s(native, WKD_RA_MAX_KEY_PATH_LENGTH + 64, _TRUNCATE,
                     L"\\Registry\\User\\%s%s", sid, suffix);
    } else if (RaWcsStartsWith(Path, L"HKEY_USERS") || RaWcsStartsWith(Path, L"HKU")) {
        PCWSTR p = wcschr(Path, L'\\');
        if (p != NULL) RaWcsCopy(suffix, WKD_RA_MAX_KEY_PATH_LENGTH, p);
        RaWcsCopy(native, WKD_RA_MAX_KEY_PATH_LENGTH + 64, L"\\Registry\\User");
        wcscat_s(native, WKD_RA_MAX_KEY_PATH_LENGTH + 64, suffix);
    } else if (RaWcsStartsWith(Path, L"HKEY_CLASSES_ROOT") || RaWcsStartsWith(Path, L"HKCR")) {
        PCWSTR p = wcschr(Path, L'\\');
        if (p != NULL) RaWcsCopy(suffix, WKD_RA_MAX_KEY_PATH_LENGTH, p);
        RaWcsCopy(native, WKD_RA_MAX_KEY_PATH_LENGTH + 64, L"\\Registry\\Machine\\SOFTWARE\\Classes");
        wcscat_s(native, WKD_RA_MAX_KEY_PATH_LENGTH + 64, suffix);
    } else if (RaWcsStartsWith(Path, L"HKEY_CURRENT_CONFIG") || RaWcsStartsWith(Path, L"HKCC")) {
        PCWSTR p = wcschr(Path, L'\\');
        if (p != NULL) RaWcsCopy(suffix, WKD_RA_MAX_KEY_PATH_LENGTH, p);
        RaWcsCopy(native, WKD_RA_MAX_KEY_PATH_LENGTH + 64,
                  L"\\Registry\\Machine\\System\\CurrentControlSet\\Hardware Profiles\\Current");
        wcscat_s(native, WKD_RA_MAX_KEY_PATH_LENGTH + 64, suffix);
    } else {
        return FALSE;
    }

    RaWcsCopy(Dst, DstCch, native);
    return TRUE;
}

/* HKEY → hive 短标 (HKLM/HKCU/HKCR/HKU/HKCC) */
static
PCWSTR RaHKeyToHiveLabel(_In_ HKEY Root) {
    if (Root == HKEY_LOCAL_MACHINE) return L"HKLM";
    if (Root == HKEY_CURRENT_USER)  return L"HKCU";
    if (Root == HKEY_CLASSES_ROOT)  return L"HKCR";
    if (Root == HKEY_USERS)         return L"HKU";
    if (Root == HKEY_CURRENT_CONFIG)return L"HKCC";
    return L"UNKNOWN";
}

/* 路径前缀 → hive 短标 */
static
PCWSTR RaPathToHiveLabel(_In_ PCWSTR KeyPath) {
    if (KeyPath == NULL) return L"UNKNOWN";
    if (RaWcsStartsWith(KeyPath, L"HKEY_LOCAL_MACHINE") || RaWcsStartsWith(KeyPath, L"HKLM")) return L"HKLM";
    if (RaWcsStartsWith(KeyPath, L"HKEY_CURRENT_USER")  || RaWcsStartsWith(KeyPath, L"HKCU")) return L"HKCU";
    if (RaWcsStartsWith(KeyPath, L"HKEY_CLASSES_ROOT")  || RaWcsStartsWith(KeyPath, L"HKCR")) return L"HKCR";
    if (RaWcsStartsWith(KeyPath, L"HKEY_USERS")         || RaWcsStartsWith(KeyPath, L"HKU"))  return L"HKU";
    if (RaWcsStartsWith(KeyPath, L"HKEY_CURRENT_CONFIG")|| RaWcsStartsWith(KeyPath, L"HKCC")) return L"HKCC";
    return L"UNKNOWN";
}

/* 路径是否带有显式 hive 前缀 */
static
BOOLEAN RaPathHasExplicitHive(_In_ PCWSTR KeyPath) {
    return (RaPathToHiveLabel(KeyPath) != L"UNKNOWN");
}

/* 解析 HKEY + 子键路径 (ResolveRootKey) */
static
VOID RaResolveRootKey(_In_ PCWSTR KeyPath,
                      _Out_ PHKEY Root,
                      _Out_ PWSTR SubKey,
                      _In_ ULONG SubKeyCch) {
    if (SubKey != NULL && SubKeyCch > 0) SubKey[0] = L'\0';
    if (Root == NULL || KeyPath == NULL) return;

    /* 取首分隔符之后的子键部分 */
    PCWSTR sep = NULL;
    if (KeyPath[0] != L'\0') sep = wcschr(KeyPath, L'\\');
    PCWSTR sub = (sep != NULL) ? (sep + 1) : L"";

    if (Root != NULL) {
        if (RaWcsStartsWith(KeyPath, L"HKEY_LOCAL_MACHINE") || RaWcsStartsWith(KeyPath, L"HKLM")) {
            *Root = HKEY_LOCAL_MACHINE;
        } else if (RaWcsStartsWith(KeyPath, L"HKEY_CURRENT_USER") || RaWcsStartsWith(KeyPath, L"HKCU")) {
            *Root = HKEY_CURRENT_USER;
        } else if (RaWcsStartsWith(KeyPath, L"HKEY_CLASSES_ROOT") || RaWcsStartsWith(KeyPath, L"HKCR")) {
            *Root = HKEY_CLASSES_ROOT;
        } else if (RaWcsStartsWith(KeyPath, L"HKEY_USERS") || RaWcsStartsWith(KeyPath, L"HKU")) {
            *Root = HKEY_USERS;
        } else if (RaWcsStartsWith(KeyPath, L"HKEY_CURRENT_CONFIG") || RaWcsStartsWith(KeyPath, L"HKCC")) {
            *Root = HKEY_CURRENT_CONFIG;
        } else {
            *Root = HKEY_LOCAL_MACHINE;     /* 裸路径按 HKLM 解析 */
        }
    }

    if (SubKey != NULL && SubKeyCch > 0) {
        RaWcsCopy(SubKey, SubKeyCch, sub);
    }
}

/* 动态列表辅助 (声明在 DecodeRegistryStrings 之前) */
static BOOLEAN RaListAddString(_In_ PRA_STRING_LIST List,
                               _In_opt_ PCWSTR Src,
                               _Out_opt_ PWCHAR* OutItem);

/* 前向声明 (Part 2 → Part 3 交叉引用) */
static NTSTATUS RaRecoverDeletedEntriesInternal(_In_ PCWSTR HivePath,
                                                _Out_ PWKD_RA_DELETED_ENTRY Entries,
                                                _In_  ULONG MaxCount,
                                                _Out_ PULONG Count);
static VOID RaSearchIocsImpl(_In_ PCWSTR* IocPaths, _In_ ULONG IocPathCount,
                             _Out_opt_ PWKD_RA_ANOMALY Out, _In_ ULONG MaxCount,
                             _Out_ PULONG MatchCount);
static WKD_RA_HIVE_TYPE RaHiveLabelToType(_In_ PCWSTR Label);
static PCWSTR RaHiveTypeToSystemPath(_In_ WKD_RA_HIVE_TYPE Hive);
static VOID RaBuildTimelineFromKeys(_In_ PCWKD_RA_SCOPE Scope);

/* Win32 枚举返回的名称以 NUL 结尾, 内嵌 NUL 不可见;
 * 保留防御性检查以语义 (RegHider 技术线) */
static
BOOLEAN HasWcsEmbeddedNull(_In_ PCWSTR Str) {
    SIZE_T len = wcslen(Str);
    for (SIZE_T i = 0; i < len; ++i) {
        if (Str[i] == L'\0') return TRUE;
    }
    return FALSE;
}

/* ==================================================
 * 熵 / 数据启发式
 * ================================================== */

/* Shannon 熵 (0-8), CalculateEntropy */
DOUBLE
RaCalculateEntropy(
    _In_ const BYTE* Data,
    _In_ SIZE_T Size
    ) {
    if (Data == NULL || Size == 0) return 0.0;

    ULONGLONG freq[256];
    memset(freq, 0, sizeof(freq));
    for (SIZE_T i = 0; i < Size; ++i) freq[Data[i]]++;

    double entropy = 0.0;
    const double dataSize = (double)Size;
    for (ULONG i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double probability = (double)freq[i] / dataSize;
            entropy -= probability * log2(probability);
        }
    }
    return entropy;
}

/* 数据是否含 NUL 字节 */
static
BOOLEAN RaContainsNullBytes(_In_ const BYTE* Data, _In_ SIZE_T Size) {
    if (Data == NULL || Size == 0) return FALSE;
    for (SIZE_T i = 0; i < Size; ++i) {
        if (Data[i] == 0x00) return TRUE;
    }
    return FALSE;
}

/* 字符串是否含控制字符 (Tab/LF/CR 除外) */
static
BOOLEAN RaHasControlCharacters(_In_ PCWSTR Str) {
    if (Str == NULL) return FALSE;
    for (; *Str != L'\0'; ++Str) {
        WCHAR ch = *Str;
        if (ch < 0x20 && ch != 0x09 && ch != 0x0A && ch != 0x0D) {
            return TRUE;
        }
    }
    return FALSE;
}

/* 数据是否像可执行内容 (PE/ELF/.NET/shellcode/脚本标记) */
static
BOOLEAN RaLooksLikeExecutable(_In_ const BYTE* Data, _In_ SIZE_T Size) {
    if (Data == NULL || Size < 4) return FALSE;

    /* PE 签名 (MZ) */
    if (Data[0] == 'M' && Data[1] == 'Z') return TRUE;

    /* ELF 签名 */
    if (Size >= 4 && Data[0] == 0x7F && Data[1] == 'E' && Data[2] == 'L' && Data[3] == 'F') return TRUE;

    /* .NET metadata BSJB 签名 (前 512 字节) */
    if (Size >= 64) {
        SIZE_T scan = (Size < 512) ? Size : 512;
        for (SIZE_T i = 0; i + 4 <= scan; ++i) {
            if (Data[i] == 'B' && Data[i+1] == 'S' && Data[i+2] == 'J' && Data[i+3] == 'B') {
                return TRUE;
            }
        }
    }

    /* NOP 雪橇 (>=16 连续 NOP) */
    if (Size >= 16) {
        ULONG nopCount = 0;
        SIZE_T scan = (Size < 256) ? Size : 256;
        for (SIZE_T i = 0; i < scan; ++i) {
            if (Data[i] == 0x90) {
                if (++nopCount >= 16) return TRUE;
            } else {
                nopCount = 0;
            }
        }
    }

    /* shellcode 前置模式 (需要佐证上下文) */
    if (Size >= 32) {
        /* x86 GetPC: call $+5; pop reg (58-5F) */
        if (Data[0] == 0xE8 && Data[1] == 0x00 && Data[2] == 0x00 &&
            Data[3] == 0x00 && Data[4] == 0x00 &&
            Data[5] >= 0x58 && Data[5] <= 0x5F) {
            return TRUE;
        }
        /* x64: sub rsp, imm8 (对齐且合理) + 常规后续字节 */
        if (Data[0] == 0x48 && Data[1] == 0x83 && Data[2] == 0xEC) {
            const BYTE delta = Data[3];
            const BYTE next  = Data[4];
            if (delta != 0 && (delta & 0x07) == 0 && delta < 0x80 &&
                (next == 0x48 || next == 0x4C || next == 0x49 ||
                 (next >= 0x50 && next <= 0x57) ||
                 next == 0x33 || next == 0x8B || next == 0x89)) {
                return TRUE;
            }
        }
    }

    /* 脚本标记 (ASCII, 前 512 字节; 缓冲先转小写, 标记常量全小写) */
    SIZE_T asciiLen = (Size < 512) ? Size : 512;
    CHAR buf[512];
    memcpy(buf, Data, asciiLen);
    buf[asciiLen] = '\0';
    _strlwr_s(buf, 512);

    static const PCHAR psMarkers[] = {
        "powershell", "invoke-expression", "iex(", "new-object",
        "[system.convert]::", "[system.reflection.assembly]::",
        "-encodedcommand", "frombase64string"
    };
    for (ULONG i = 0; i < RA_PS_MARKERS_COUNT; ++i) {
        if (strstr(buf, psMarkers[i]) != NULL) return TRUE;
    }

    static const PCHAR scriptMarkers[] = {
        "wscript.shell", "createobject(", "scripting.filesystemobject",
        "adodb.stream", "eval(", "activexobject"
    };
    for (ULONG i = 0; i < RA_SCRIPT_MARKERS_COUNT; ++i) {
        if (strstr(buf, scriptMarkers[i]) != NULL) return TRUE;
    }

    return FALSE;
}

/* 路径日志脱敏 (NUL/控制字符 → \xNN) */
static
VOID RaSanitizePathForLogging(_In_ PCWSTR Path, _Out_ PWSTR Dst, _In_ ULONG DstCch) {
    if (Dst == NULL || DstCch == 0) return;
    Dst[0] = L'\0';
    if (Path == NULL) return;

    ULONG out = 0;
    for (PCWSTR p = Path; *p != L'\0' && out + 8 < DstCch; ++p) {
        WCHAR ch = *p;
        if (ch == L'\0') {
            wcscat_s(Dst, DstCch, L"\\x00");
            out += 4;
        } else if (ch < 0x20) {
            WCHAR esc[8];
            swprintf_s(esc, 8, L"\\x%02X", (ULONG)ch);
            wcscat_s(Dst, DstCch, esc);
            out += 4;
        } else {
            Dst[out++] = ch;
            Dst[out] = L'\0';
        }
    }
}

/* CSV 字段转义 (RFC 4180) */
static
VOID RaEscapeCsvField(_In_ PCSTR Field, _Out_ PCHAR Dst, _In_ ULONG DstCch) {
    if (Dst == NULL || DstCch == 0) return;
    Dst[0] = '\0';
    if (Field == NULL) return;

    BOOLEAN needQuote = FALSE;
    if (Field[0] == '\0') { Dst[0] = '\0'; return; }
    for (PCSTR p = Field; *p != '\0'; ++p) {
        if (*p == ',' || *p == '"' || *p == '\r' || *p == '\n') { needQuote = TRUE; break; }
        if (p == Field && (*p == '=' || *p == '+' || *p == '-' || *p == '@')) { needQuote = TRUE; break; }
    }

    if (!needQuote) {
        /* 直接窄拷贝 (无特殊字符) */
        strncpy_s(Dst, DstCch, Field, _TRUNCATE);
        return;
    }

    /* 引号包裹 + 双写引号 */
    ULONG out = 0;
    Dst[out++] = '"';
    for (PCSTR p = Field; *p != '\0' && out + 2 < DstCch; ++p) {
        if (*p == '"') {
            if (out + 3 >= DstCch) break;
            Dst[out++] = '"';
            Dst[out++] = '"';
        } else {
            Dst[out++] = *p;
        }
    }
    if (out + 1 < DstCch) Dst[out++] = '"';
    Dst[out] = '\0';
}

/* Base64 编码检测 (低误报率, IsBase64Encoded) */
static
BOOLEAN RaIsBase64Encoded(_In_ const BYTE* Data, _In_ SIZE_T Size) {
    if (Data == NULL || Size < 16) return FALSE;

    SIZE_T effectiveLen = Size;
    while (effectiveLen > 0 && (Data[effectiveLen - 1] == '\r' || Data[effectiveLen - 1] == '\n' ||
                                Data[effectiveLen - 1] == ' ')) {
        effectiveLen--;
    }
    if (effectiveLen < 16) return FALSE;

    SIZE_T validB64Count = 0;
    SIZE_T whitespaceCount = 0;
    SIZE_T paddingCount = 0;
    BOOLEAN lastWasPadding = FALSE;

    for (SIZE_T i = 0; i < effectiveLen; ++i) {
        BYTE ch = Data[i];
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
            (ch >= '0' && ch <= '9') || ch == '+' || ch == '/') {
            if (lastWasPadding) return FALSE;
            validB64Count++;
        } else if (ch == '=') {
            paddingCount++;
            lastWasPadding = TRUE;
            if (paddingCount > 2) return FALSE;
        } else if (ch == '\r' || ch == '\n' || ch == ' ') {
            whitespaceCount++;
        } else {
            return FALSE;
        }
    }

    SIZE_T contentLen = validB64Count + paddingCount;
    if (contentLen < 16) return FALSE;
    if (contentLen % 4 != 0) return FALSE;

    SIZE_T nonWhitespace = effectiveLen - whitespaceCount;
    if (nonWhitespace == 0) return FALSE;
    return (validB64Count + paddingCount) > (nonWhitespace * 95 / 100);
}

/* Hive 类型 → 名称 */
static
PCWSTR RaHiveTypeToString(_In_ WKD_RA_HIVE_TYPE Type) {
    switch (Type) {
        case WkdRaHive_Sam:       return L"SAM";
        case WkdRaHive_Security:  return L"SECURITY";
        case WkdRaHive_Software:  return L"SOFTWARE";
        case WkdRaHive_System:    return L"SYSTEM";
        case WkdRaHive_Default:   return L"DEFAULT";
        case WkdRaHive_Ntuser:    return L"NTUSER.DAT";
        case WkdRaHive_Usrclass:  return L"UsrClass.dat";
        case WkdRaHive_Amcache:   return L"Amcache.hve";
        case WkdRaHive_Bcd:       return L"BCD";
        case WkdRaHive_Components:return L"COMPONENTS";
        default:                  return L"Unknown";
    }
}

/* 异常类型 → MITRE 技术 (GetMITRETechnique) */
static
PCSTR RaGetMitreTechnique(_In_ WKD_RA_ANOMALY_TYPE Type) {
    switch (Type) {
        case WkdRaAnomaly_NullByteInjection:
        case WkdRaAnomaly_UnicodeControlChar:
        case WkdRaAnomaly_ApiHiddenKey:
        case WkdRaAnomaly_ApiHiddenValue:
            return "T1564.001";

        case WkdRaAnomaly_DkomEvidence:
        case WkdRaAnomaly_HookedFunction:
        case WkdRaAnomaly_ModifiedCallback:
            return "T1014";

        case WkdRaAnomaly_KnownMalwareKey:
        case WkdRaAnomaly_KnownMalwareValue:
            return "T1112/T1547";

        case WkdRaAnomaly_SuspiciousAutorun:
            return "T1547.001";

        default:
            return "T1112";
    }
}

/* REG_SZ/EXPAND_SZ/MULTI_SZ 解码 (严格边界校验, DecodeRegistryStrings).
 * 输出到调用方提供的字符串列表 (每项为独立 WCHAR 缓冲)。 */
static
VOID RaDecodeRegistryStrings(_In_ DWORD ValueType,
                             _In_ const BYTE* Data,
                             _In_ SIZE_T Size,
                             _Out_ PRA_STRING_LIST Out) {
    if (Out == NULL) return;
    if (Data == NULL || Size == 0 || (Size % sizeof(WCHAR)) != 0) return;

    const WCHAR* base = (const WCHAR*)Data;
    const SIZE_T count = Size / sizeof(WCHAR);

    if (ValueType == REG_SZ || ValueType == REG_EXPAND_SZ) {
        SIZE_T end = 0;
        while (end < count && base[end] != L'\0') ++end;
        if (end > 0) {
            PWCHAR item = NULL;
            if (RaListAddString(Out, NULL, &item)) {
                RaWcsCopyN(item, WKD_REG_MAX_PATH_CHARS, base, (ULONG)end);
            }
        }
        return;
    }

    if (ValueType == REG_MULTI_SZ) {
        SIZE_T pos = 0;
        ULONG components = 0;
        while (pos < count && components < WKD_RA_MAX_DECOMPONENTS) {
            SIZE_T end = pos;
            while (end < count && base[end] != L'\0') ++end;
            SIZE_T len = end - pos;
            if (len == 0) break;    /* 双 NUL 终止 */
            PWCHAR item = NULL;
            if (RaListAddString(Out, NULL, &item)) {
                RaWcsCopyN(item, WKD_REG_MAX_PATH_CHARS, base + pos, (ULONG)len);
            }
            components++;
            pos = end + 1;
        }
    }
}

/* 安全展开环境变量 (64KB 上限, ExpandEnvironmentStringsSafe) */
static
VOID RaExpandEnvironmentStringsSafe(_In_ PCWSTR Src,
                                    _Out_ PWSTR Dst,
                                    _In_ ULONG DstCch) {
    if (Dst == NULL || DstCch == 0) return;
    if (Src == NULL) { Dst[0] = L'\0'; return; }

    /* 无 '%' 直接原样 */
    if (wcschr(Src, L'%') == NULL) {
        RaWcsCopy(Dst, DstCch, Src);
        return;
    }

    WCHAR out[RA_EXPAND_CAP];
    const DWORD needed = ExpandEnvironmentStringsW(Src, out, RA_EXPAND_CAP);
    if (needed == 0 || needed > RA_EXPAND_CAP) {
        RaWcsCopy(Dst, DstCch, Src);    /* 失败或溢出: 原样返回 */
        return;
    }
    RaWcsCopy(Dst, DstCch, out);
}

/* ==================================================
 * 通配符匹配 (替代 std::wregex; * / ? 语义, 大小写不敏感)
 * MatchesIndicator 中 regex 的降级实现
 * ================================================== */
static
BOOLEAN RaWildcardMatch(_In_ PCWSTR Pattern, _In_ PCWSTR Text) {
    if (Pattern == NULL || Text == NULL) return FALSE;

    /* 迭代式通配符匹配 (支持多段 '*' 回溯) */
    PCWSTR p = Pattern;
    PCWSTR t = Text;
    PCWSTR star = NULL;
    PCWSTR mark = NULL;

    while (*t != L'\0') {
        if (*p == L'?') {
            ++p;
            ++t;
        } else if (*p == L'*') {
            star = p++;
            mark = t;
        } else if (_wcsnicmp(p, t, 1) == 0) {
            ++p;
            ++t;
        } else if (star != NULL) {
            p = star + 1;
            t = ++mark;
        } else {
            return FALSE;
        }
    }
    while (*p == L'*') ++p;
    return (*p == L'\0');
}

/* ==================================================
 * 动态列表辅助
 * ================================================== */

/* 字符串列表末尾追加 (返回新项指针或 NULL) */
static
BOOLEAN RaListAddString(_In_ PRA_STRING_LIST List,
                        _In_opt_ PCWSTR Src,
                        _Out_opt_ PWCHAR* OutItem) {
    if (List == NULL) return FALSE;

    if (List->Count >= List->Capacity) {
        ULONG newCap = (List->Capacity == 0) ? 16 : List->Capacity * 2;
        if (newCap < 16) newCap = 16;
        if (newCap > 1000000) { RaDbgPrint(L"[RA] string list cap exceeded"); return FALSE; }
        PWCHAR* newItems = (PWCHAR*)malloc(newCap * sizeof(PWCHAR));
        if (newItems == NULL) return FALSE;
        if (List->Items != NULL) {
            memcpy(newItems, List->Items, List->Count * sizeof(PWCHAR));
            free(List->Items);
        }
        List->Items = newItems;
        List->Capacity = newCap;
    }

    PWCHAR item = (PWCHAR)malloc(WKD_REG_MAX_PATH_CHARS * sizeof(WCHAR));
    if (item == NULL) return FALSE;
    item[0] = L'\0';
    if (Src != NULL) RaWcsCopy(item, WKD_REG_MAX_PATH_CHARS, Src);

    List->Items[List->Count++] = item;
    if (OutItem != NULL) *OutItem = item;
    return TRUE;
}

static
VOID RaListFree(_In_ PRA_STRING_LIST List) {
    if (List == NULL) return;
    for (ULONG i = 0; i < List->Count; ++i) {
        if (List->Items[i] != NULL) free(List->Items[i]);
    }
    if (List->Items != NULL) free(List->Items);
    List->Items = NULL;
    List->Count = 0;
    List->Capacity = 0;
}

/* 列表是否包含给定字符串 */
static
BOOLEAN RaListContains(_In_ PRA_STRING_LIST List, _In_ PCWSTR Src) {
    if (List == NULL || Src == NULL) return FALSE;
    for (ULONG i = 0; i < List->Count; ++i) {
        if (List->Items[i] != NULL && wcscmp(List->Items[i], Src) == 0) return TRUE;
    }
    return FALSE;
}

/* ==================================================
 * 异常缓冲辅助 (RecordAnomaly 的存储层)
 * ================================================== */

/* 异常缓冲追加 (超出 MaxAnomalies 淘汰最旧唯一元素) */
static
VOID RaAnomalyStore(_In_ const WKD_RA_ANOMALY* Anomaly) {
    if (Anomaly == NULL) return;

    if (g_Ra.AnomalyCount >= g_Ra.Config.MaxAnomalies) {
        /* 淘汰最旧 (memmove 前移) */
        if (g_Ra.AnomalyCount > 1) {
            memmove(&g_Ra.Anomalies[0], &g_Ra.Anomalies[1],
                    (g_Ra.AnomalyCount - 1) * sizeof(WKD_RA_ANOMALY));
        }
        g_Ra.AnomalyCount--;
    }

    if (g_Ra.AnomalyCount >= g_Ra.AnomalyCapacity) {
        ULONG newCap = (g_Ra.AnomalyCapacity == 0) ? 64 : g_Ra.AnomalyCapacity * 2;
        if (newCap > WKD_RA_MAX_ANOMALIES) newCap = WKD_RA_MAX_ANOMALIES;
        if (newCap <= g_Ra.AnomalyCapacity) newCap = g_Ra.AnomalyCapacity + 64;
        PWKD_RA_ANOMALY newBuf = (PWKD_RA_ANOMALY)realloc(g_Ra.Anomalies, newCap * sizeof(WKD_RA_ANOMALY));
        if (newBuf == NULL) return;
        g_Ra.Anomalies = newBuf;
        g_Ra.AnomalyCapacity = newCap;
    }

    g_Ra.Anomalies[g_Ra.AnomalyCount++] = *Anomaly;
}

/* 单键分析输出缓冲 (RaAnalyzeKey 使用; 每次调用清空) */
static
VOID RaKeyAnomalyReset(VOID) {
    g_Ra.KeyAnomalyCount = 0;
}

static
VOID RaKeyAnomalyAdd(_In_ const WKD_RA_ANOMALY* Anomaly) {
    if (Anomaly == NULL) return;
    if (g_Ra.KeyAnomalyCount >= g_Ra.KeyAnomalyCapacity) {
        ULONG newCap = (g_Ra.KeyAnomalyCapacity == 0) ? 16 : g_Ra.KeyAnomalyCapacity * 2;
        PWKD_RA_ANOMALY newBuf = (PWKD_RA_ANOMALY)realloc(g_Ra.KeyAnomalies, newCap * sizeof(WKD_RA_ANOMALY));
        if (newBuf == NULL) return;
        g_Ra.KeyAnomalies = newBuf;
        g_Ra.KeyAnomalyCapacity = newCap;
    }
    g_Ra.KeyAnomalies[g_Ra.KeyAnomalyCount++] = *Anomaly;
}

/* ==================================================
 * 时间线缓冲辅助
 * ================================================== */
static
VOID RaTimelineAdd(_In_ const WKD_RA_TIMELINE* Entry) {
    if (Entry == NULL) return;
    if (g_Ra.TimelineCount >= g_Ra.TimelineCapacity) {
        ULONG newCap = (g_Ra.TimelineCapacity == 0) ? 32 : g_Ra.TimelineCapacity * 2;
        PWKD_RA_TIMELINE newBuf = (PWKD_RA_TIMELINE)realloc(g_Ra.Timeline, newCap * sizeof(WKD_RA_TIMELINE));
        if (newBuf == NULL) return;
        g_Ra.Timeline = newBuf;
        g_Ra.TimelineCapacity = newCap;
    }
    g_Ra.Timeline[g_Ra.TimelineCount++] = *Entry;
}

/* ==================================================
 * 指标缓冲辅助
 * ================================================== */
static
VOID RaIndicatorAdd(_In_ const WKD_RA_THREAT_INDICATOR* Indicator) {
    if (Indicator == NULL) return;
    if (g_Ra.IndicatorCount >= g_Ra.IndicatorCapacity) {
        ULONG newCap = (g_Ra.IndicatorCapacity == 0) ? 16 : g_Ra.IndicatorCapacity * 2;
        PWKD_RA_THREAT_INDICATOR newBuf = (PWKD_RA_THREAT_INDICATOR)realloc(
            g_Ra.Indicators, newCap * sizeof(WKD_RA_THREAT_INDICATOR));
        if (newBuf == NULL) return;
        g_Ra.Indicators = newBuf;
        g_Ra.IndicatorCapacity = newCap;
    }
    g_Ra.Indicators[g_Ra.IndicatorCount++] = *Indicator;
}

/* ==================================================
 * SHA256 辅助 (WkD 底座 BCrypUtils)
 * ================================================== */
static
BOOLEAN RaComputeSha256Hex(_In_ const BYTE* Data,
                           _In_ ULONG Size,
                           _Out_ UCHAR Hash[32],
                           _Out_ CHAR Hex[WKD_REG_MAX_HASH_HEX_CHARS]) {
    if (Data == NULL || Hash == NULL || Hex == NULL) return FALSE;
    DEF_SHA256_HASH out;
    if (!IocScanner_ComputeBufferSha256(Data, Size, &out)) return FALSE;
    memcpy(Hash, out.Data, 32);

    static const PCHAR hexDigits = "0123456789abcdef";
    for (ULONG i = 0; i < 32; ++i) {
        Hex[i * 2]     = hexDigits[Hash[i] >> 4];
        Hex[i * 2 + 1] = hexDigits[Hash[i] & 0x0F];
    }
    Hex[64] = '\0';
    return TRUE;
}

/* 威胁情报 stub (对齐虚标剔除: ThreatIntelManager 未接线) */
static
BOOLEAN RaThreatIntelLookup(_In_ PCSTR Sha256Hex,
                            _Inout_ DOUBLE* RiskScore,
                            _Out_ PCHAR ThreatName,
                            _In_ ULONG ThreatNameCch) {
    if (ThreatName != NULL && ThreatNameCch > 0) ThreatName[0] = '\0';
    if (RiskScore != NULL) *RiskScore = 0.0;
    (VOID)Sha256Hex;
    return FALSE;   /* 未接线: 恒无匹配 */
}

/* ==================================================
 * 异常记录与回调
 * ================================================== */

/* 记录异常: 填充字段(SHA256/熵/MITRE/时间) → 全局缓冲 → 单键捕获 →
 * 统计 → 回调。Impl::RecordAnomaly。 */
static
VOID RegpRecordAnomaly(
    _In_ WKD_RA_ANOMALY_TYPE Type,
    _In_ WKD_RA_SEVERITY Severity,
    _In_ PCWSTR HiveLabel,
    _In_ PCWSTR KeyPath,
    _In_ PCWSTR ValueName,
    _In_opt_ const BYTE* RawData,
    _In_ ULONG RawDataSize,
    _In_ PCSTR Description
    ) {
    WKD_RA_ANOMALY anomaly;
    memset(&anomaly, 0, sizeof(anomaly));

    anomaly.AnomalyId = (ULONGLONG)InterlockedIncrement64(&g_Ra.NextAnomalyId);
    anomaly.DetectedTime = RaTimeNow();
    anomaly.Hive = RaHiveLabelToType(HiveLabel);

    RaWcsCopy(anomaly.HivePath, WKD_REG_MAX_PATH_CHARS, HiveLabel);
    RaWcsCopy(anomaly.KeyPath, WKD_REG_MAX_PATH_CHARS, KeyPath);
    RaWcsCopy(anomaly.ValueName, WKD_REG_MAX_NAME_CHARS, ValueName);

    anomaly.Type = Type;
    anomaly.Severity = Severity;
    /* 描述为窄字符串, 直接窄拷贝 */
    strncpy_s(anomaly.Description, WKD_REG_MAX_DESC_CHARS, Description, _TRUNCATE);
    strncpy_s(anomaly.Technique, 16, RaGetMitreTechnique(Type), _TRUNCATE);

    if (RawData != NULL && RawDataSize > 0) {
        anomaly.Entropy = RaCalculateEntropy(RawData, RawDataSize);

        UCHAR hash[32];
        CHAR hex[WKD_REG_MAX_HASH_HEX_CHARS];
        if (RaComputeSha256Hex(RawData, RawDataSize, hash, hex)) {
            memcpy(anomaly.Sha256, hash, 32);
            strncpy_s(anomaly.Sha256Hex, WKD_REG_MAX_HASH_HEX_CHARS, hex, _TRUNCATE);
        }

        /* 只保留受限前缀 (对齐 MAX_ANOMALY_RAW_DATA_BYTES) */
        if (RawDataSize <= WKD_RA_MAX_ANOMALY_RAW_DATA_BYTES) {
            memcpy(anomaly.RawData, RawData, RawDataSize);
            anomaly.RawDataSize = RawDataSize;
        } else {
            memcpy(anomaly.RawData, RawData, WKD_RA_MAX_ANOMALY_RAW_DATA_BYTES);
            anomaly.RawDataSize = WKD_RA_MAX_ANOMALY_RAW_DATA_BYTES;
            anomaly.RawDataTruncated = TRUE;
            anomaly.OriginalSize = RawDataSize;
        }
    }

    /* 类型推导标志 */
    switch (Type) {
        case WkdRaAnomaly_NullByteInjection:
        case WkdRaAnomaly_UnicodeControlChar:
        case WkdRaAnomaly_ApiHiddenKey:
        case WkdRaAnomaly_ApiHiddenValue:
            anomaly.IsHidden = TRUE;
            break;
        case WkdRaAnomaly_DeletedNotCleared:
        case WkdRaAnomaly_OrphanedCell:
            anomaly.IsDeleted = TRUE;
            break;
        case WkdRaAnomaly_KnownMalwareKey:
        case WkdRaAnomaly_KnownMalwareValue:
        case WkdRaAnomaly_EmbeddedExecutable:
            anomaly.IsMalicious = TRUE;
            break;
        default:
            break;
    }

    /* 全局权威缓冲 (锁内) */
    {
        AcquireSRWLockExclusive(&g_Ra.AnomalyLock);
        RaAnomalyStore(&anomaly);
        ReleaseSRWLockExclusive(&g_Ra.AnomalyLock);
    }

    /* 单键捕获 (RaAnalyzeKey 期间) */
    if (g_Ra.KeyAnomalyCapture) {
        AcquireSRWLockExclusive(&g_Ra.AnomalyLock);
        RaKeyAnomalyAdd(&anomaly);
        ReleaseSRWLockExclusive(&g_Ra.AnomalyLock);
    }

    InterlockedIncrement64(&g_Ra.Stats.AnomaliesDetected);

    /* 回调 (无内部锁) */
    AcquireSRWLockShared(&g_Ra.CallbackLock);
    for (ULONG i = 0; i < WKD_RA_MAX_CALLBACKS; ++i) {
        if (g_Ra.AnomalyCallbacks[i].InUse &&
            g_Ra.AnomalyCallbacks[i].Fn != NULL) {
            g_Ra.AnomalyCallbacks[i].Fn(&anomaly, g_Ra.AnomalyCallbacks[i].Ctx);
        }
    }
    ReleaseSRWLockShared(&g_Ra.CallbackLock);

    RaDbgPrint(L"[RA] Anomaly recorded - ID: %I64u, Type: %d, Severity: %d",
               anomaly.AnomalyId, (INT)Type, (INT)Severity);
}

/* ==================================================
 * 自动运行候选分析 (7 类启发式, AnalyzeAutorunCandidate)
 * ================================================== */
static
VOID RaAnalyzeAutorunCandidate(
    _In_ PCWSTR HiveLabel,
    _In_ PCWSTR KeyPath,
    _In_ PCWSTR ValueName,
    _In_ PCWSTR RawValue,
    _In_ PCWSTR CanonicalValue
    ) {
    if (CanonicalValue == NULL || CanonicalValue[0] == L'\0') return;

    WCHAR keyLower[WKD_REG_MAX_PATH_CHARS];
    WCHAR nameLower[WKD_REG_MAX_NAME_CHARS];
    WCHAR valueLower[WKD_REG_MAX_PATH_CHARS * 2];

    RaWcsToLowerCopy(KeyPath, keyLower, WKD_REG_MAX_PATH_CHARS);
    RaWcsToLowerCopy(ValueName, nameLower, WKD_REG_MAX_NAME_CHARS);
    RaWcsToLowerCopy(CanonicalValue, valueLower, WKD_REG_MAX_PATH_CHARS * 2);

    /* 证据缓冲 (原始值宽字节, 按字节截断到上限) */
    BYTE evidence[WKD_RA_MAX_ANOMALY_RAW_DATA_BYTES];
    ULONG evidenceSize = 0;
    if (RawValue != NULL) {
        ULONG srcBytes = (ULONG)wcslen(RawValue) * (ULONG)sizeof(WCHAR);
        evidenceSize = (srcBytes > WKD_RA_MAX_ANOMALY_RAW_DATA_BYTES)
            ? WKD_RA_MAX_ANOMALY_RAW_DATA_BYTES : srcBytes;
        memcpy(evidence, RawValue, evidenceSize);
    }

    /* 1. IFEO Debugger / GlobalFlag 劫持 */
    if (RaWcsContains(keyLower, L"\\image file execution options\\")) {
        if (wcscmp(nameLower, L"debugger") == 0) {
            RegpRecordAnomaly(WkdRaAnomaly_SuspiciousAutorun, WkdRaSev_Critical,
                HiveLabel, KeyPath, ValueName, evidence, evidenceSize,
                "IFEO Debugger value present (MITRE T1546.012). Subkey name is the image being hijacked.");
            return;
        }
        if (wcscmp(nameLower, L"globalflag") == 0 ||
            wcscmp(nameLower, L"reportingmode") == 0 ||
            wcscmp(nameLower, L"monitorprocess") == 0) {
            RegpRecordAnomaly(WkdRaAnomaly_SuspiciousAutorun, WkdRaSev_High,
                HiveLabel, KeyPath, ValueName, evidence, evidenceSize,
                "IFEO Silent Process Exit / GlobalFlag instrumentation (MITRE T1546.012).");
            return;
        }
    }

    /* 2. AppInit_DLLs / AppCertDlls */
    if (wcscmp(nameLower, L"appinit_dlls") == 0) {
        RegpRecordAnomaly(WkdRaAnomaly_SuspiciousAutorun, WkdRaSev_Critical,
            HiveLabel, KeyPath, ValueName, evidence, evidenceSize,
            "AppInit_DLLs entry present (MITRE T1546.010). Loads into every user32-linked process.");
        return;
    }
    if (RaWcsContains(keyLower, L"\\session manager\\appcertdlls")) {
        RegpRecordAnomaly(WkdRaAnomaly_SuspiciousAutorun, WkdRaSev_Critical,
            HiveLabel, KeyPath, ValueName, evidence, evidenceSize,
            "AppCertDlls entry present (MITRE T1546.009). Loads into every process that calls Create*Process.");
        return;
    }

    /* 3. Winlogon 劫持 */
    if (RaWcsContains(keyLower, L"\\winlogon")) {
        if (wcscmp(nameLower, L"userinit") == 0 ||
            wcscmp(nameLower, L"shell") == 0 ||
            wcscmp(nameLower, L"taskman") == 0) {
            BOOLEAN userinitOk = (wcscmp(nameLower, L"userinit") == 0) &&
                                 RaWcsContains(valueLower, L"userinit.exe");
            BOOLEAN shellOk = (wcscmp(nameLower, L"shell") == 0) &&
                              (wcscmp(valueLower, L"explorer.exe") == 0 ||
                               RaWcsContains(valueLower, L"\\explorer.exe"));
            if (!userinitOk && !shellOk) {
                RegpRecordAnomaly(WkdRaAnomaly_SuspiciousAutorun, WkdRaSev_Critical,
                    HiveLabel, KeyPath, ValueName, evidence, evidenceSize,
                    "Winlogon hijack candidate (MITRE T1547.004): non-default value for system shell/userinit/taskman.");
                return;
            }
        }
        if (RaWcsContains(keyLower, L"\\notify\\")) {
            RegpRecordAnomaly(WkdRaAnomaly_SuspiciousAutorun, WkdRaSev_High,
                HiveLabel, KeyPath, ValueName, evidence, evidenceSize,
                "Winlogon Notify package detected (deprecated mechanism, persistence indicator).");
            return;
        }
    }

    /* 4. LSA notification / security packages */
    if (RaWcsContains(keyLower, L"\\control\\lsa")) {
        if (wcscmp(nameLower, L"notification packages") == 0 ||
            wcscmp(nameLower, L"security packages") == 0 ||
            wcscmp(nameLower, L"authentication packages") == 0) {
            RegpRecordAnomaly(WkdRaAnomaly_SuspiciousAutorun, WkdRaSev_Critical,
                HiveLabel, KeyPath, ValueName, evidence, evidenceSize,
                "LSA package list modification (MITRE T1556.002 / T1547.002). Inspect for non-Microsoft DLLs.");
            return;
        }
    }

    /* 5. PendingFileRenameOperations — 引导时文件替换 */
    if (wcscmp(nameLower, L"pendingfilerenameoperations") == 0) {
        RegpRecordAnomaly(WkdRaAnomaly_SuspiciousAutorun, WkdRaSev_High,
            HiveLabel, KeyPath, ValueName, evidence, evidenceSize,
            "PendingFileRenameOperations entry (boot-time file replacement; abused for tamper).");
        return;
    }

    /* 6. Run / RunOnce / Services 载荷启发式 */
    BOOLEAN isRunKey = RaWcsContains(keyLower, L"\\currentversion\\run") ||
                       RaWcsContains(keyLower, L"\\currentversion\\runonce") ||
                       RaWcsContains(keyLower, L"\\currentversion\\runservices") ||
                       RaWcsContains(keyLower, L"\\currentversion\\runservicesonce");
    BOOLEAN isServiceKey = RaWcsContains(keyLower, L"\\services\\");

    if (isRunKey || isServiceKey) {
        BOOLEAN fromTempLike =
            RaWcsContains(valueLower, L"\\appdata\\local\\temp\\") ||
            RaWcsContains(valueLower, L"\\windows\\temp\\") ||
            RaWcsContains(valueLower, L"\\users\\public\\") ||
            RaWcsContains(valueLower, L"\\programdata\\") ||
            RaWcsContains(valueLower, L"\\$recycle.bin\\");
        BOOLEAN isUnc = RaWcsStartsWith(valueLower, L"\\\\");
        BOOLEAN encodedPs =
            RaWcsContains(valueLower, L"powershell") &&
            (RaWcsContains(valueLower, L"-enc") ||
             RaWcsContains(valueLower, L"-encodedcommand") ||
             RaWcsContains(valueLower, L"frombase64string") ||
             RaWcsContains(valueLower, L"hidden"));
        BOOLEAN wmicAbuse = RaWcsContains(valueLower, L"wmic ") &&
                            RaWcsContains(valueLower, L"process call create");
        BOOLEAN regsvr32Squiblydoo = RaWcsContains(valueLower, L"regsvr32") &&
                                     (RaWcsContains(valueLower, L"http://") ||
                                      RaWcsContains(valueLower, L"https://"));
        BOOLEAN mshtaWeb = RaWcsContains(valueLower, L"mshta") &&
                           (RaWcsContains(valueLower, L"http://") ||
                            RaWcsContains(valueLower, L"https://") ||
                            RaWcsContains(valueLower, L"javascript:"));
        BOOLEAN rundll32JsVbs = RaWcsContains(valueLower, L"rundll32") &&
                                (RaWcsContains(valueLower, L"javascript:") ||
                                 RaWcsContains(valueLower, L"vbscript:"));
        BOOLEAN fromUserHive = (wcscmp(HiveLabel, L"HKCU") == 0 || wcscmp(HiveLabel, L"HKU") == 0);
        BOOLEAN runFromUser = isRunKey && fromUserHive;

        if (fromTempLike || isUnc || encodedPs || wmicAbuse ||
            regsvr32Squiblydoo || mshtaWeb || rundll32JsVbs) {
            CHAR desc[WKD_REG_MAX_DESC_CHARS];
            if (isServiceKey) {
                strncpy_s(desc, WKD_REG_MAX_DESC_CHARS,
                          "Autorun/service entry with suspicious payload (MITRE T1543.003)", _TRUNCATE);
            } else {
                strncpy_s(desc, WKD_REG_MAX_DESC_CHARS,
                          "Autorun/service entry with suspicious payload (MITRE T1547.001)", _TRUNCATE);
            }
            RegpRecordAnomaly(WkdRaAnomaly_SuspiciousAutorun, WkdRaSev_High,
                HiveLabel, KeyPath, ValueName, evidence, evidenceSize, desc);
            return;
        }
        if (runFromUser && RaWcsContains(valueLower, L".exe")) {
            RegpRecordAnomaly(WkdRaAnomaly_SuspiciousAutorun, WkdRaSev_Medium,
                HiveLabel, KeyPath, ValueName, evidence, evidenceSize,
                "Per-user Run-key autostart entry (MITRE T1547.001) - triage payload provenance");
            return;
        }
    }

    /* 7. ServiceDll / ImagePath 劫持 */
    if (isServiceKey &&
        (wcscmp(nameLower, L"servicedll") == 0 || wcscmp(nameLower, L"imagepath") == 0)) {
        if (RaWcsContains(valueLower, L"\\appdata\\") ||
            RaWcsContains(valueLower, L"\\users\\public\\") ||
            RaWcsContains(valueLower, L"\\programdata\\") ||
            RaWcsStartsWith(valueLower, L"\\\\")) {
            RegpRecordAnomaly(WkdRaAnomaly_SuspiciousAutorun, WkdRaSev_Critical,
                HiveLabel, KeyPath, ValueName, evidence, evidenceSize,
                "Service ImagePath/ServiceDll resolves into a user-writable location (MITRE T1543.003).");
            return;
        }
    }
}

/* 值数据 vs 威胁情报 (stub 化: 哈希计算保留, 匹配恒无) */
static
VOID RaCheckValueAgainstThreatIntel(
    _In_ PCWSTR HiveLabel,
    _In_ PCWSTR KeyPath,
    _In_ PCWSTR ValueName,
    _In_ const BYTE* Data,
    _In_ ULONG DataSize
    ) {
    if (Data == NULL || DataSize == 0) return;

    UCHAR hash[32];
    CHAR hex[WKD_REG_MAX_HASH_HEX_CHARS];
    if (!RaComputeSha256Hex(Data, DataSize, hash, hex)) return;

    DOUBLE riskScore = 0.0;
    CHAR threatName[WKD_REG_MAX_NAME_CHARS];
    if (RaThreatIntelLookup(hex, &riskScore, threatName, WKD_REG_MAX_NAME_CHARS)) {
        CHAR desc[WKD_REG_MAX_DESC_CHARS];
        _snprintf_s(desc, WKD_REG_MAX_DESC_CHARS, _TRUNCATE,
                    "Known malicious value - SHA256: %.16s... (score: %.0f)", hex, riskScore);
        RegpRecordAnomaly(WkdRaAnomaly_KnownMalwareValue, WkdRaSev_Critical,
            HiveLabel, KeyPath, ValueName, Data, DataSize, desc);
        InterlockedIncrement64(&g_Ra.Stats.MaliciousEntries);
    }
}

/* DKOM 检测 (stub: RegistryMonitor/ProcessMonitor 未迁移接线, 恒不可用) */
static
BOOLEAN RaDetectDkomImpl(VOID) {
    RaDbgPrint(L"[RA] DKOM detection unavailable - kernel monitor not connected (stub)");
    return FALSE;
}

/* ==================================================
 * 单键深度分析 (AnalyzeKeyImpl)
 * ================================================== */
static
VOID RegpAnalyzeKeyInternal(
    _In_ PCWSTR KeyPath,
    _In_ BOOLEAN Recursive,
    _In_ ULONG CurrentDepth,
    _In_ ULONG EffectiveMaxDepth
    ) {
    if (g_Ra.AbortRequested) return;
    if (CurrentDepth >= EffectiveMaxDepth) {
        RaDbgPrint(L"[RA] Max scan depth %u reached at %s", EffectiveMaxDepth, KeyPath);
        return;
    }
    if (!RaIsSafeRegistryPath(KeyPath)) {
        RaDbgPrint(L"[RA] Rejected unsafe key path");
        return;
    }

    HKEY rootHKey;
    WCHAR subKeyPath[WKD_RA_MAX_KEY_PATH_LENGTH];
    RaResolveRootKey(KeyPath, &rootHKey, subKeyPath, WKD_RA_MAX_KEY_PATH_LENGTH);

    BOOLEAN pathIsBare = !RaPathHasExplicitHive(KeyPath);
    PCWSTR hiveLabel = RaHKeyToHiveLabel(rootHKey);

    /* 双视图 (64/32), 防 WOW6432Node 隐藏 */
    const struct _RA_VIEW_SPEC {
        BOOLEAN Wow64_64;
        BOOLEAN Wow64_32;
        PCWSTR  Tag;
    } views[] = {
        { TRUE,  FALSE, RA_VIEW_TAG_64 },
        { FALSE, TRUE,  RA_VIEW_TAG_32 }
    };

    for (ULONG v = 0; v < 2; ++v) {
        if (g_Ra.AbortRequested) break;

        HKEY hKey = NULL;
        LONG regResult;
        REGSAM access = KEY_READ;

        /* 打开当前视图 */
        regResult = RegOpenKeyExW(rootHKey, subKeyPath, 0,
                                  access | (views[v].Wow64_64 ? KEY_WOW64_64KEY : KEY_WOW64_32KEY),
                                  &hKey);
        PCWSTR effHiveLabel = hiveLabel;

        if (regResult != ERROR_SUCCESS) {
            /* 裸路径 HKLM 打开失败时回退 HKCU (仅 64 视图首次) */
            if (pathIsBare && rootHKey == HKEY_LOCAL_MACHINE && views[v].Wow64_64) {
                RegCloseKey(hKey); /* 无效句柄安全关闭 */
                if (RegOpenKeyExW(HKEY_CURRENT_USER, subKeyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                    effHiveLabel = L"HKCU";
                } else {
                    continue;
                }
            } else {
                continue;
            }
        }

        /* 值枚举 */
        DWORD index = 0;
        WCHAR* valueNameBuf = (WCHAR*)malloc(RA_VALUE_NAME_CAP * sizeof(WCHAR));
        if (valueNameBuf == NULL) {
            RegCloseKey(hKey);
            continue;
        }

        while (!g_Ra.AbortRequested) {
            DWORD valueNameSize = RA_VALUE_NAME_CAP;
            DWORD valueType;
            DWORD valueDataSize = 0;

            LONG result = RegEnumValueW(hKey, index, valueNameBuf, &valueNameSize,
                                        NULL, &valueType, NULL, &valueDataSize);
            if (result == ERROR_NO_MORE_ITEMS) break;
            if (result != ERROR_SUCCESS && result != ERROR_MORE_DATA) {
                index++;
                continue;
            }

            /* 立即快照名称 (防并发写者竞态) */
            WCHAR discoveredName[WKD_REG_MAX_NAME_CHARS];
            RaWcsCopyN(discoveredName, WKD_REG_MAX_NAME_CHARS, valueNameBuf, valueNameSize);

            /* 截断到 1MB 上限 */
            DWORD cappedDataSize = valueDataSize;
            if (cappedDataSize > WKD_RA_MAX_VALUE_SIZE) {
                cappedDataSize = WKD_RA_MAX_VALUE_SIZE;
            }

            BYTE* valueData = (BYTE*)malloc(cappedDataSize > 0 ? cappedDataSize : 1);
            if (valueData == NULL) {
                index++;
                continue;
            }
            DWORD actualDataSize = cappedDataSize;
            valueNameSize = RA_VALUE_NAME_CAP;

            result = RegEnumValueW(hKey, index, valueNameBuf, &valueNameSize,
                                   NULL, &valueType, valueData, &actualDataSize);
            if (result != ERROR_SUCCESS) {
                if (result == ERROR_MORE_DATA && valueDataSize > WKD_RA_MAX_VALUE_SIZE) {
                    CHAR desc[WKD_REG_MAX_DESC_CHARS];
                    _snprintf_s(desc, WKD_REG_MAX_DESC_CHARS, _TRUNCATE,
                                "Oversized value: %lu bytes (capped at %d)",
                                (ULONG)valueDataSize, (INT)WKD_RA_MAX_VALUE_SIZE);
                    RegpRecordAnomaly(WkdRaAnomaly_OversizedValue, WkdRaSev_Medium,
                                    effHiveLabel, KeyPath, discoveredName, NULL, 0, desc);
                }
                free(valueData);
                index++;
                continue;
            }

            WCHAR valName[WKD_REG_MAX_NAME_CHARS];
            RaWcsCopyN(valName, WKD_REG_MAX_NAME_CHARS, valueNameBuf, valueNameSize);

            /* --- 值分析 --- */
            if (g_Ra.Config.AnalyzeEntropy &&
                actualDataSize >= WKD_RA_MIN_BLOB_SIZE_FOR_ANALYSIS) {
                double entropy = RaCalculateEntropy(valueData, actualDataSize);
                if (entropy >= WKD_RA_HIGH_ENTROPY_THRESHOLD) {
                    CHAR desc[WKD_REG_MAX_DESC_CHARS];
                    _snprintf_s(desc, WKD_REG_MAX_DESC_CHARS, _TRUNCATE,
                                "High entropy value: %.2f (%lu bytes)", entropy, (ULONG)actualDataSize);
                    RegpRecordAnomaly(WkdRaAnomaly_HighEntropy, WkdRaSev_Medium,
                                    effHiveLabel, KeyPath, valName, valueData, actualDataSize, desc);
                }
            }

            if (g_Ra.Config.DetectEmbeddedExecutables &&
                RaLooksLikeExecutable(valueData, actualDataSize)) {
                CHAR desc[WKD_REG_MAX_DESC_CHARS];
                _snprintf_s(desc, WKD_REG_MAX_DESC_CHARS, _TRUNCATE,
                            "Embedded executable detected in registry value (%lu bytes)",
                            (ULONG)actualDataSize);
                RegpRecordAnomaly(WkdRaAnomaly_EmbeddedExecutable, WkdRaSev_High,
                                effHiveLabel, KeyPath, valName, valueData, actualDataSize, desc);
                InterlockedIncrement64(&g_Ra.Stats.MaliciousEntries);
            }

            /* Base64 编码 (字符串类与 BINARY) */
            if (actualDataSize >= WKD_RA_MIN_BLOB_SIZE_FOR_ANALYSIS &&
                (valueType == REG_SZ || valueType == REG_EXPAND_SZ ||
                 valueType == REG_MULTI_SZ || valueType == REG_BINARY) &&
                RaIsBase64Encoded(valueData, actualDataSize)) {
                CHAR desc[WKD_REG_MAX_DESC_CHARS];
                _snprintf_s(desc, WKD_REG_MAX_DESC_CHARS, _TRUNCATE,
                            "Base64-encoded data detected (%lu bytes)", (ULONG)actualDataSize);
                RegpRecordAnomaly(WkdRaAnomaly_EncodedData, WkdRaSev_Medium,
                                effHiveLabel, KeyPath, valName, valueData, actualDataSize, desc);
            }

            /* 字符串类规范化 + 自动运行启发式 */
            if (valueType == REG_SZ || valueType == REG_EXPAND_SZ || valueType == REG_MULTI_SZ) {
                RA_STRING_LIST strings = { 0 };
                RaDecodeRegistryStrings(valueType, valueData, actualDataSize, &strings);
                for (ULONG s = 0; s < strings.Count; ++s) {
                    PCWSTR raw = strings.Items[s];
                    WCHAR canonical[WKD_REG_MAX_PATH_CHARS * 2];
                    if (valueType == REG_EXPAND_SZ) {
                        RaExpandEnvironmentStringsSafe(raw, canonical, WKD_REG_MAX_PATH_CHARS * 2);
                    } else {
                        RaWcsCopy(canonical, WKD_REG_MAX_PATH_CHARS * 2, raw);
                    }
                    if (canonical[0] != L'\0') {
                        RaAnalyzeAutorunCandidate(effHiveLabel, KeyPath, valName, raw, canonical);
                    }
                }
                RaListFree(&strings);
            }

            /* 威胁情报哈希 (stub) */
            if (actualDataSize >= WKD_RA_MIN_BLOB_SIZE_FOR_ANALYSIS) {
                RaCheckValueAgainstThreatIntel(effHiveLabel, KeyPath, valName, valueData, actualDataSize);
            }

            InterlockedIncrement64(&g_Ra.Stats.ValuesAnalyzed);
            InterlockedExchangeAdd64(&g_Ra.Stats.BytesAnalyzed, actualDataSize);
            index++;

            free(valueData);
        }

        free(valueNameBuf);
        RegCloseKey(hKey);

        /* 递归子键枚举 */
        if (Recursive && !g_Ra.AbortRequested) {
            HKEY hSub = NULL;
            if (RegOpenKeyExW(rootHKey, subKeyPath, 0,
                              KEY_READ | (views[v].Wow64_64 ? KEY_WOW64_64KEY : KEY_WOW64_32KEY),
                              &hSub) == ERROR_SUCCESS) {
                WCHAR subName[WKD_REG_MAX_NAME_CHARS];
                DWORD subIndex = 0;
                while (RegEnumKeyW(hSub, subIndex, subName, WKD_REG_MAX_NAME_CHARS) == ERROR_SUCCESS) {
                    if (g_Ra.AbortRequested) break;
                    /* 拒绝内嵌 NUL 子名 (避免递归目标被静默重接)) */
                    if (wcslen(subName) == 0 || HasWcsEmbeddedNull(subName)) { subIndex++; continue; }
                    WCHAR subKeyPath2[WKD_RA_MAX_KEY_PATH_LENGTH];
                    _snwprintf_s(subKeyPath2, WKD_RA_MAX_KEY_PATH_LENGTH, _TRUNCATE,
                                 L"%s\\%s", KeyPath, subName);
                    RegpAnalyzeKeyInternal(subKeyPath2, TRUE, CurrentDepth + 1, EffectiveMaxDepth);
                    subIndex++;
                }
                RegCloseKey(hSub);
            }
        }

        /* HKCR/HKCU/HKU/HKCC 无独立 WOW64 视图, 仅扫描一次 */
        if (rootHKey != HKEY_LOCAL_MACHINE && rootHKey != HKEY_CURRENT_USER) {
            break;
        }
    }

    InterlockedIncrement64(&g_Ra.Stats.KeysAnalyzed);
}

/* ==================================================
 * 隐藏键检测 (NULL 字节 / 控制字符, NtOpenKey 原生视图)
 * ================================================== */
static
VOID RegpDetectNullByteKeysInternal(
    _In_ PCWSTR RootKey,
    _Out_ PRA_STRING_LIST HiddenKeys,
    _Out_ PRA_STRING_LIST PendingCallbacks
    ) {
    if (HiddenKeys == NULL || PendingCallbacks == NULL) return;

    WCHAR nativePath[WKD_RA_MAX_KEY_PATH_LENGTH + 64];
    if (!RaWin32ToNativePath(RootKey, nativePath, WKD_RA_MAX_KEY_PATH_LENGTH + 64)) {
        RaDbgPrint(L"[RA] Rejected unsafe registry path: %s", RootKey);
        return;
    }

    WCHAR hiveLabel[8];
    RaWcsCopy(hiveLabel, 8, RaPathToHiveLabel(RootKey));

    UNICODE_STRING usPath;
    RtlInitUnicodeString(&usPath, nativePath);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &usPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS status = NtOpenKey(&hKey, KEY_READ, &objAttr);
    if (!NT_SUCCESS(status)) return;

    ULONG index = 0;
    BYTE buffer[4096];
    ULONG resultLength = 0;

    while (!g_Ra.AbortRequested) {
        status = NtEnumerateKey(hKey, index, RaKeyBasicInformation, buffer,
                                sizeof(buffer), &resultLength);
        if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL) {
            /* 超大条目: 跳过并继续 (缓冲不再增长, 对齐 NTAPI 上限语义) */
            index++;
            continue;
        }
        if (!NT_SUCCESS(status)) break;

        PRA_KEY_BASIC_INFORMATION pInfo = (PRA_KEY_BASIC_INFORMATION)buffer;
        SIZE_T maxName = sizeof(buffer) - FIELD_OFFSET(RA_KEY_BASIC_INFORMATION, Name);
        if (pInfo->NameLength > maxName || (pInfo->NameLength % sizeof(WCHAR)) != 0) {
            RaDbgPrint(L"[RA] Malformed NameLength %lu at index %lu", pInfo->NameLength, index);
            index++;
            continue;
        }

        WCHAR keyName[WKD_REG_MAX_NAME_CHARS];
        RaWcsCopyN(keyName, WKD_REG_MAX_NAME_CHARS, pInfo->Name, pInfo->NameLength / sizeof(WCHAR));

        /* NULL 字节注入检测 (RegHider 技术) */
        BOOLEAN isHidden = FALSE;
        SIZE_T klen = wcslen(keyName);
        for (SIZE_T i = 0; i + 1 < klen; ++i) {
            if (keyName[i] == L'\0') { isHidden = TRUE; break; }
        }

        if (isHidden || RaHasControlCharacters(keyName)) {
            WCHAR fullPath[WKD_RA_MAX_KEY_PATH_LENGTH];
            _snwprintf_s(fullPath, WKD_RA_MAX_KEY_PATH_LENGTH, _TRUNCATE,
                         L"%s\\%s", RootKey, keyName);

            RaListAddString(HiddenKeys, fullPath, NULL);

            WCHAR sanitized[WKD_REG_MAX_PATH_CHARS];
            RaSanitizePathForLogging(fullPath, sanitized, WKD_REG_MAX_PATH_CHARS);
            RaDbgPrint(L"[RA] HIDDEN KEY DETECTED: %s", sanitized);

            RegpRecordAnomaly(WkdRaAnomaly_ApiHiddenKey, WkdRaSev_Critical,
                hiveLabel, RootKey, keyName, NULL, 0,
                "Registry key hidden using NULL-byte or control character injection");

            /* 回调推迟到循环外 (避免锁内重入) */
            RaListAddString(PendingCallbacks, fullPath, NULL);

            InterlockedIncrement64(&g_Ra.Stats.HiddenKeysFound);
        }

        index++;
    }

    CloseHandle(hKey);
}

/* ==================================================
 * 交叉视图检测 (Win32 API vs NtEnumerateKey)
 * ================================================== */
static
VOID RaPerformCrossViewDetectionInternal(
    _In_ PCWSTR KeyPath,
    _Out_ PWKD_RA_CROSS_VIEW_RESULT Result
    ) {
    if (Result == NULL) return;
    memset(Result, 0, sizeof(*Result));
    RaWcsCopy(Result->KeyPath, WKD_REG_MAX_PATH_CHARS, KeyPath);

    HKEY rootHKey;
    WCHAR subKey[WKD_RA_MAX_KEY_PATH_LENGTH];
    RaResolveRootKey(KeyPath, &rootHKey, subKey, WKD_RA_MAX_KEY_PATH_LENGTH);
    PCWSTR hiveLabel = RaHKeyToHiveLabel(rootHKey);

    /* 1. Win32 API 视图 (64 位) */
    HKEY apiKey = NULL;
    if (RegOpenKeyExW(rootHKey, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &apiKey) == ERROR_SUCCESS) {
        Result->FoundViaApi = TRUE;
        WCHAR name[WKD_REG_MAX_NAME_CHARS];
        DWORD idx = 0;
        while (RegEnumKeyW(apiKey, idx, name, WKD_REG_MAX_NAME_CHARS) == ERROR_SUCCESS &&
               Result->ApiSubKeyCount < WKD_RA_MAX_LISTED_ENTRIES) {
            RaWcsCopy(Result->ApiSubKeys[Result->ApiSubKeyCount++], WKD_REG_MAX_NAME_CHARS, name);
            idx++;
        }
        RegCloseKey(apiKey);
    }

    /* 2. 原生 API 视图 */
    WCHAR nativePath[WKD_RA_MAX_KEY_PATH_LENGTH + 64];
    if (!RaWin32ToNativePath(KeyPath, nativePath, WKD_RA_MAX_KEY_PATH_LENGTH + 64)) {
        RaDbgPrint(L"[RA] Cross-view rejected unsafe path %s", KeyPath);
        return;
    }
    UNICODE_STRING usPath;
    RtlInitUnicodeString(&usPath, nativePath);
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &usPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hNativeKey = NULL;
    if (NtOpenKey(&hNativeKey, KEY_READ, &objAttr) == STATUS_SUCCESS) {
        Result->FoundViaRaw = TRUE;
        ULONG nIndex = 0;
        BYTE buffer[4096];
        ULONG resLen = 0;
        while (!g_Ra.AbortRequested &&
               Result->RawSubKeyCount < WKD_RA_MAX_LISTED_ENTRIES) {
            NTSTATUS status = NtEnumerateKey(hNativeKey, nIndex, RaKeyBasicInformation,
                                             buffer, sizeof(buffer), &resLen);
            if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL) {
                nIndex++;
                continue;
            }
            if (!NT_SUCCESS(status)) break;
            PRA_KEY_BASIC_INFORMATION pInfo = (PRA_KEY_BASIC_INFORMATION)buffer;
            SIZE_T maxName = sizeof(buffer) - FIELD_OFFSET(RA_KEY_BASIC_INFORMATION, Name);
            if (pInfo->NameLength <= maxName && (pInfo->NameLength % sizeof(WCHAR)) == 0) {
                WCHAR nm[WKD_REG_MAX_NAME_CHARS];
                RaWcsCopyN(nm, WKD_REG_MAX_NAME_CHARS, pInfo->Name, pInfo->NameLength / sizeof(WCHAR));
                RaWcsCopy(Result->RawSubKeys[Result->RawSubKeyCount++], WKD_REG_MAX_NAME_CHARS, nm);
            }
            nIndex++;
        }
        CloseHandle(hNativeKey);
    }

    /* 3. 比较两视图 (注册表大小写不敏感) */
    for (ULONG r = 0; r < Result->RawSubKeyCount; ++r) {
        BOOLEAN found = FALSE;
        WCHAR lowerRaw[WKD_REG_MAX_NAME_CHARS];
        RaWcsToLowerCopy(Result->RawSubKeys[r], lowerRaw, WKD_REG_MAX_NAME_CHARS);
        for (ULONG a = 0; a < Result->ApiSubKeyCount; ++a) {
            WCHAR lowerApi[WKD_REG_MAX_NAME_CHARS];
            RaWcsToLowerCopy(Result->ApiSubKeys[a], lowerApi, WKD_REG_MAX_NAME_CHARS);
            if (wcscmp(lowerRaw, lowerApi) == 0) { found = TRUE; break; }
        }
        if (!found && Result->HiddenSubKeyCount < WKD_RA_MAX_LISTED_ENTRIES) {
            RaWcsCopy(Result->HiddenSubKeys[Result->HiddenSubKeyCount++],
                      WKD_REG_MAX_NAME_CHARS, Result->RawSubKeys[r]);
            Result->HasDiscrepancy = TRUE;
        }
    }

    if (Result->HasDiscrepancy) {
        InterlockedIncrement64(&g_Ra.Stats.RootkitIndicators);
        WCHAR sanitized[WKD_REG_MAX_PATH_CHARS];
        RaSanitizePathForLogging(KeyPath, sanitized, WKD_REG_MAX_PATH_CHARS);
        RaDbgPrint(L"[RA] ROOTKIT DISCREPANCY detected in %s - %lu hidden keys",
                   sanitized, Result->HiddenSubKeyCount);

        for (ULONG h = 0; h < Result->HiddenSubKeyCount; ++h) {
            RegpRecordAnomaly(WkdRaAnomaly_ApiHiddenKey, WkdRaSev_Critical,
                hiveLabel, KeyPath, Result->HiddenSubKeys[h], NULL, 0,
                "Key found via NTAPI but hidden from Win32 API (Rootkit indicator)");
        }
    }
}

/* ==================================================
 * 五种分析模式
 * ================================================== */
static
VOID RaPerformQuickAnalysis(_In_ PCWKD_RA_SCOPE Scope, _Out_ PWKD_RA_RESULT Result) {
    if (g_Ra.Config.DetectHiddenKeys) {
        for (ULONG i = 0; i < Scope->SpecificPathCount; ++i) {
            RA_STRING_LIST hidden = { 0 };
            RA_STRING_LIST pending = { 0 };
            RegpDetectNullByteKeysInternal(Scope->SpecificPaths[i], &hidden, &pending);
            Result->HiddenKeysFound += hidden.Count;

            /* 触发隐藏回调 (无锁) */
            for (ULONG c = 0; c < pending.Count; ++c) {
                AcquireSRWLockShared(&g_Ra.CallbackLock);
                for (ULONG cb = 0; cb < WKD_RA_MAX_CALLBACKS; ++cb) {
                    if (g_Ra.HiddenCallbacks[cb].InUse && g_Ra.HiddenCallbacks[cb].Fn != NULL) {
                        g_Ra.HiddenCallbacks[cb].Fn(pending.Items[c], TRUE, g_Ra.HiddenCallbacks[cb].Ctx);
                    }
                }
                ReleaseSRWLockShared(&g_Ra.CallbackLock);
            }
            RaListFree(&hidden);
            RaListFree(&pending);
        }
    }
}

static
VOID RaPerformStandardAnalysis(_In_ PCWKD_RA_SCOPE Scope, _Out_ PWKD_RA_RESULT Result) {
    /* 隐藏键检测 */
    if (g_Ra.Config.DetectHiddenKeys) {
        for (ULONG i = 0; i < Scope->SpecificPathCount; ++i) {
            RA_STRING_LIST hidden = { 0 };
            RA_STRING_LIST pending = { 0 };
            RegpDetectNullByteKeysInternal(Scope->SpecificPaths[i], &hidden, &pending);
            Result->HiddenKeysFound += hidden.Count;

            /* 对每个隐藏键做值级分析 */
            for (ULONG h = 0; h < hidden.Count; ++h) {
                RegpAnalyzeKeyInternal(hidden.Items[h], FALSE, 0, WKD_RA_MAX_SCAN_DEPTH);
            }

            for (ULONG c = 0; c < pending.Count; ++c) {
                AcquireSRWLockShared(&g_Ra.CallbackLock);
                for (ULONG cb = 0; cb < WKD_RA_MAX_CALLBACKS; ++cb) {
                    if (g_Ra.HiddenCallbacks[cb].InUse && g_Ra.HiddenCallbacks[cb].Fn != NULL) {
                        g_Ra.HiddenCallbacks[cb].Fn(pending.Items[c], TRUE, g_Ra.HiddenCallbacks[cb].Ctx);
                    }
                }
                ReleaseSRWLockShared(&g_Ra.CallbackLock);
            }
            RaListFree(&hidden);
            RaListFree(&pending);
        }
    }

    /* 交叉视图 */
    if (g_Ra.Config.EnableCrossView) {
        for (ULONG i = 0; i < Scope->SpecificPathCount; ++i) {
            WKD_RA_CROSS_VIEW_RESULT cv;
            RaPerformCrossViewDetectionInternal(Scope->SpecificPaths[i], &cv);
            if (cv.HasDiscrepancy) {
                Result->HiddenKeysFound += cv.HiddenSubKeyCount;
                InterlockedIncrement64(&g_Ra.Stats.RootkitIndicators);
            }
        }
    }
}

static
VOID RaPerformDeepAnalysis(_In_ PCWKD_RA_SCOPE Scope, _Out_ PWKD_RA_RESULT Result) {
    RaPerformStandardAnalysis(Scope, Result);
    Result->Mode = WkdRaMode_Deep;

    /* 值级熵/可执行分析 */
    if (g_Ra.Config.AnalyzeEntropy || g_Ra.Config.DetectEmbeddedExecutables) {
        for (ULONG i = 0; i < Scope->SpecificPathCount; ++i) {
            RegpAnalyzeKeyInternal(Scope->SpecificPaths[i], Scope->MaxDepth > 1, 0, Scope->MaxDepth);
        }
    }

    /* 模式匹配 (指标列表) */
    if (g_Ra.Config.MatchPatterns && g_Ra.IndicatorCount > 0) {
        ULONG matchCount = 0;
        /* NULL/MaxCount=0: 走内部指标列表全遍历 */
        RaSearchIocsImpl(NULL, 0, NULL, 0, &matchCount);
        Result->AnomaliesFound += matchCount;
    }
}

static
VOID RaPerformForensicAnalysis(_In_ PCWKD_RA_SCOPE Scope, _Out_ PWKD_RA_RESULT Result) {
    RaPerformDeepAnalysis(Scope, Result);
    Result->Mode = WkdRaMode_Forensic;

    /* 系统 hive 删除条目恢复 */
    if (g_Ra.Config.RecoverDeleted) {
        const struct _RA_HIVE_FILE {
            WKD_RA_HIVE_TYPE Type;
            PCWSTR Path;
        } hives[] = {
            { WkdRaHive_Software, RA_HIVE_SYSTEM_ROOT L"SOFTWARE" },
            { WkdRaHive_System,   RA_HIVE_SYSTEM_ROOT L"SYSTEM" },
            { WkdRaHive_Sam,      RA_HIVE_SYSTEM_ROOT L"SAM" },
            { WkdRaHive_Security, RA_HIVE_SYSTEM_ROOT L"SECURITY" },
        };

        for (ULONG h = 0; h < 4; ++h) {
            if (g_Ra.AbortRequested) break;
            WKD_RA_DELETED_ENTRY entries[128];
            ULONG count = 0;
            if (RaRecoverDeletedEntriesInternal(hives[h].Path, entries, 128, &count) == STATUS_SUCCESS) {
                Result->DeletedRecovered += count;
                /* 记入全局缓冲 (锁内) */
                AcquireSRWLockExclusive(&g_Ra.AnomalyLock);
                for (ULONG e = 0; e < count; ++e) {
                    if (g_Ra.DeletedCount >= g_Ra.DeletedCapacity) {
                        ULONG newCap = (g_Ra.DeletedCapacity == 0) ? 32 : g_Ra.DeletedCapacity * 2;
                        PWKD_RA_DELETED_ENTRY newBuf = (PWKD_RA_DELETED_ENTRY)realloc(
                            g_Ra.Deleted, newCap * sizeof(WKD_RA_DELETED_ENTRY));
                        if (newBuf == NULL) break;
                        g_Ra.Deleted = newBuf;
                        g_Ra.DeletedCapacity = newCap;
                    }
                    g_Ra.Deleted[g_Ra.DeletedCount++] = entries[e];
                    entries[e].Data = NULL;  /* 所有权移交全局缓冲 */
                }
                ReleaseSRWLockExclusive(&g_Ra.AnomalyLock);
            }
        }
    }

    /* 时间线构建 */
    if (g_Ra.Config.BuildTimeline) {
        RaBuildTimelineFromKeys(Scope);
    }
}

static
VOID RaPerformRootkitHunting(_In_ PCWKD_RA_SCOPE Scope, _Out_ PWKD_RA_RESULT Result) {
    Result->Mode = WkdRaMode_RootkitHunting;

    /* 交叉视图 */
    if (g_Ra.Config.EnableCrossView) {
        for (ULONG i = 0; i < Scope->SpecificPathCount; ++i) {
            WKD_RA_CROSS_VIEW_RESULT cv;
            RaPerformCrossViewDetectionInternal(Scope->SpecificPaths[i], &cv);
            if (cv.HasDiscrepancy) {
                Result->HiddenKeysFound += cv.HiddenSubKeyCount;
                InterlockedIncrement64(&g_Ra.Stats.RootkitIndicators);
                for (ULONG h = 0; h < cv.HiddenSubKeyCount; ++h) {
                    RegpRecordAnomaly(WkdRaAnomaly_ApiHiddenKey, WkdRaSev_Critical,
                                    Scope->SpecificPaths[i], cv.HiddenSubKeys[h], L"", NULL, 0,
                                    "Hidden key detected via cross-view analysis (rootkit indicator)");
                }
            }
        }
    }

    /* DKOM (stub) */
    if (g_Ra.Config.DetectDkom) {
        if (RaDetectDkomImpl()) {
            Result->MaliciousEntries++;
        }
    }
}

/* ==================================================
 * 时间线构建
 * ================================================== */
static
VOID RaBuildTimelineFromKeys(_In_ PCWKD_RA_SCOPE Scope) {
    for (ULONG i = 0; i < Scope->SpecificPathCount; ++i) {
        if (g_Ra.AbortRequested) break;
        PCWSTR path = Scope->SpecificPaths[i];

        HKEY rootHKey;
        WCHAR subKey[WKD_RA_MAX_KEY_PATH_LENGTH];
        RaResolveRootKey(path, &rootHKey, subKey, WKD_RA_MAX_KEY_PATH_LENGTH);

        HKEY hKey = NULL;
        if (RegOpenKeyExW(rootHKey, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) {
            continue;
        }

        FILETIME lastWrite = { 0 };
        if (RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &lastWrite) == ERROR_SUCCESS) {
            ULARGE_INTEGER uli;
            uli.LowPart = lastWrite.dwLowDateTime;
            uli.HighPart = lastWrite.dwHighDateTime;
            if (uli.QuadPart > 0) {
                WKD_RA_TIMELINE entry;
                memset(&entry, 0, sizeof(entry));
                entry.Timestamp = (WKD_REG_TIMESTAMP)uli.QuadPart;
                strncpy_s(entry.Action, 32, "Modified", _TRUNCATE);
                RaWcsCopy(entry.KeyPath, WKD_REG_MAX_PATH_CHARS, path);
                strncpy_s(entry.Description, WKD_REG_MAX_DESC_CHARS,
                          "Key last write time", _TRUNCATE);

                AcquireSRWLockExclusive(&g_Ra.TimelineLock);
                RaTimelineAdd(&entry);
                ReleaseSRWLockExclusive(&g_Ra.TimelineLock);
            }
        }

        RegCloseKey(hKey);
    }
}

/* ==================================================
 * Hive 类型 / 路径映射
 * ================================================== */
static
WKD_RA_HIVE_TYPE RaHiveLabelToType(_In_ PCWSTR Label) {
    if (Label == NULL) return WkdRaHive_Unknown;
    if (RaWcsEqualsI(Label, L"HKLM\\SYSTEM") || RaWcsEqualsI(Label, L"\\REGISTRY\\MACHINE\\SYSTEM")) {
        return WkdRaHive_System;
    }
    if (RaWcsEqualsI(Label, L"HKLM\\SOFTWARE") || RaWcsEqualsI(Label, L"\\REGISTRY\\MACHINE\\SOFTWARE")) {
        return WkdRaHive_Software;
    }
    if (RaWcsEqualsI(Label, L"HKLM\\SAM") || RaWcsEqualsI(Label, L"\\REGISTRY\\MACHINE\\SAM")) {
        return WkdRaHive_Sam;
    }
    if (RaWcsEqualsI(Label, L"HKLM\\SECURITY") || RaWcsEqualsI(Label, L"\\REGISTRY\\MACHINE\\SECURITY")) {
        return WkdRaHive_Security;
    }
    return WkdRaHive_Unknown;
}

static
PCWSTR RaHiveTypeToSystemPath(_In_ WKD_RA_HIVE_TYPE Hive) {
    switch (Hive) {
        case WkdRaHive_Sam:      return RA_HIVE_SYSTEM_ROOT L"SAM";
        case WkdRaHive_Security: return RA_HIVE_SYSTEM_ROOT L"SECURITY";
        case WkdRaHive_Software: return RA_HIVE_SYSTEM_ROOT L"SOFTWARE";
        case WkdRaHive_System:   return RA_HIVE_SYSTEM_ROOT L"SYSTEM";
        case WkdRaHive_Default:  return RA_HIVE_SYSTEM_ROOT L"DEFAULT";
        default:
            return NULL;
    }
}

/* 按 hive 名称推断类型 (路径尾部文件名) */
static
WKD_RA_HIVE_TYPE RaHivePathToType(_In_ PCWSTR HivePath) {
    if (HivePath == NULL) return WkdRaHive_Unknown;
    PCWSTR slash = wcsrchr(HivePath, L'\\');
    PCWSTR name = (slash != NULL) ? (slash + 1) : HivePath;

    if (RaWcsEqualsI(name, L"SYSTEM"))    return WkdRaHive_System;
    if (RaWcsEqualsI(name, L"SOFTWARE"))  return WkdRaHive_Software;
    if (RaWcsEqualsI(name, L"SAM"))       return WkdRaHive_Sam;
    if (RaWcsEqualsI(name, L"SECURITY"))  return WkdRaHive_Security;
    if (RaWcsEqualsI(name, L"DEFAULT"))   return WkdRaHive_Default;
    if (RaWcsEqualsI(name, L"NTUSER.DAT")) return WkdRaHive_Ntuser;
    if (RaWcsEqualsI(name, L"UsrClass.dat")) return WkdRaHive_Usrclass;
    return WkdRaHive_Unknown;
}

/* ==================================================
 * Hive 文件读取 (regf 头 + 全文件映射)
 * ================================================== */

/* 读取整个 hive 文件 (上限 512MB 保护) */
static
NTSTATUS RaReadHiveFile(_In_ PCWSTR HivePath,
                        _Out_ PBYTE* OutBuffer,
                        _Out_ PULONG OutSize) {
    if (OutBuffer == NULL || OutSize == NULL) return STATUS_INVALID_PARAMETER;
    *OutBuffer = NULL;
    *OutSize = 0;

    HANDLE hFile = CreateFileW(HivePath, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        RaDbgPrint(L"[RA] Cannot open hive file %s (err %lu)", HivePath, GetLastError());
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return STATUS_UNSUCCESSFUL;
    }
    if (fileSize.QuadPart <= 0 || fileSize.QuadPart > RA_HIVE_SIZE_CAP) {
        RaDbgPrint(L"[RA] Hive %s invalid size %I64d", HivePath, fileSize.QuadPart);
        CloseHandle(hFile);
        return STATUS_FILE_INVALID;
    }

    ULONG size = (ULONG)fileSize.QuadPart;
    PBYTE buffer = (PBYTE)malloc(size);
    if (buffer == NULL) {
        CloseHandle(hFile);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DWORD totalRead = 0;
    BOOLEAN ok = TRUE;
    while (totalRead < size) {
        DWORD chunk = 0;
        if (!ReadFile(hFile, buffer + totalRead, size - totalRead, &chunk, NULL) || chunk == 0) {
            ok = FALSE;
            break;
        }
        totalRead += chunk;
    }

    CloseHandle(hFile);
    if (!ok) {
        free(buffer);
        return STATUS_UNSUCCESSFUL;
    }

    *OutBuffer = buffer;
    *OutSize = size;
    return STATUS_SUCCESS;
}

/* 解析 regf 头 (偏移 0). ParseHiveHeaderImpl */
static
NTSTATUS RaParseHiveHeaderImpl(_In_ PCWSTR HivePath, _Out_ PWKD_RA_HIVE_HEADER Header) {
    if (Header == NULL) return STATUS_INVALID_PARAMETER;
    memset(Header, 0, sizeof(*Header));

    /* 仅读取头部 0x2000 字节 */
    HANDLE hFile = CreateFileW(HivePath, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        RaDbgPrint(L"[RA] Cannot open hive %s", HivePath);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    BYTE hdr[0x1000];
    DWORD read = 0;
    BOOLEAN ok = ReadFile(hFile, hdr, sizeof(hdr), &read, NULL) && (read == sizeof(hdr));
    CloseHandle(hFile);
    if (!ok) return STATUS_FILE_INVALID;

    /* signature 'regf' at 0 */
    PULONG sig = (PULONG)hdr;
    if (*sig != WKD_RA_HIVE_SIGNATURE) {
        RaDbgPrint(L"[RA] Hive %s has invalid signature 0x%08lX", HivePath, *sig);
        return STATUS_INVALID_FILE_FOR_SECTION;
    }

    Header->Signature = *sig;
    Header->Sequence1  = *(PULONG)(hdr + 0x04);
    Header->Sequence2  = *(PULONG)(hdr + 0x08);
    Header->LastWritten = *(PULONGLONG)(hdr + 0x0C);
    Header->MajorVersion = *(PULONG)(hdr + 0x14);
    Header->MinorVersion = *(PULONG)(hdr + 0x18);
    Header->HiveType  = *(PULONG)(hdr + 0x1C);
    Header->Format    = *(PULONG)(hdr + 0x20);
    Header->RootCellOffset = *(PULONG)(hdr + 0x24);
    Header->DataLength = *(PULONG)(hdr + 0x28);

    /* 文件名 ASCII 嵌在 0x30..0xE8 */
    CHAR nameAscii[96] = { 0 };
    memcpy(nameAscii, hdr + 0x30, 82);
    MultiByteToWideChar(CP_ACP, 0, nameAscii, -1, Header->HiveName, WKD_REG_MAX_NAME_CHARS);

    Header->IsValid = (Header->Signature == WKD_RA_HIVE_SIGNATURE) &&
                      (Header->MajorVersion == 1 || Header->MajorVersion == 2) &&
                      (Header->MinorVersion == 3 || Header->MinorVersion == 4) &&
                      (Header->RootCellOffset > 0) &&
                      (Header->RootCellOffset < Header->DataLength);
    Header->IsCorrupted = !Header->IsValid;
    Header->IsDirty = (Header->Sequence1 != Header->Sequence2);

    return Header->IsValid ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/* 读取 hive 中单个 cell (Offset 为 cell 文件内物理偏移) */
static
NTSTATUS RaReadHiveCellRegion(_In_ PBYTE HiveData, _In_ ULONG HiveSize,
                              _In_ ULONG Offset, _In_ ULONG Length,
                              _Out_ PBYTE Out) {
    if (HiveData == NULL || Out == NULL) return STATUS_INVALID_PARAMETER;
    if (Offset >= HiveSize || Length > HiveSize - Offset) {
        return STATUS_END_OF_FILE;
    }
    memcpy(Out, HiveData + Offset, Length);
    return STATUS_SUCCESS;
}

/* 解析单个键节点 cell → WKD_RA_KEY_CELL.
 * HiveData 为完整文件; CellOffset 为相对文件头的偏移. */
static
NTSTATUS RaParseKeyCell(_In_ PBYTE HiveData, _In_ ULONG HiveSize,
                        _In_ ULONG CellOffset, _Out_ PWKD_RA_KEY_CELL Cell) {
    if (Cell == NULL) return STATUS_INVALID_PARAMETER;
    memset(Cell, 0, sizeof(*Cell));
    if (CellOffset + 0x54 >= HiveSize) return STATUS_END_OF_FILE;

    PBYTE p = HiveData + CellOffset;
    LONG cellSize = *(PLONG)p;                       /* 负 = free/unallocated */
    USHORT sig = *(PUSHORT)(p + 4);

    if (sig != 0x6B6E /* 'nk' */) return STATUS_INVALID_FILE_FOR_SECTION;

    Cell->Offset = CellOffset;
    Cell->CellSize = cellSize;
    Cell->IsAllocated = (cellSize > 0);
    Cell->IsDeleted = (cellSize < 0);
    Cell->LastWritten   = *(PULONGLONG)(p + 0x04);
    Cell->SubKeyCount   = *(PULONG)(p + 0x14);
    Cell->ValueCount    = *(PULONG)(p + 0x2C);
    Cell->ParentOffset  = *(PULONG)(p + 0x10);
    Cell->ClassNameOffset = *(PULONG)(p + 0x38);
    Cell->SecurityOffset  = *(PULONG)(p + 0x34);

    USHORT nameLength = *(PUSHORT)(p + 0x50);
    if (nameLength > 0 && (ULONG)CellOffset + 0x54 + nameLength * 2 <= HiveSize) {
        ULONG nameBytes = nameLength * 2;
        if (nameBytes >= sizeof(Cell->KeyName)) nameBytes = sizeof(Cell->KeyName) - 2;
        memcpy(Cell->KeyName, p + 0x54, nameBytes);
        memcpy(Cell->KeyNameRaw, p + 0x54, nameBytes);
    }

    /* 隐藏字符标记 */
    ULONG klen = (ULONG)wcslen(Cell->KeyName);
    for (ULONG i = 0; i < klen; ++i) {
        if (Cell->KeyName[i] == L'\0') { Cell->HasNullByte = TRUE; break; }
    }
    if (RaHasControlCharacters(Cell->KeyName)) Cell->HasHiddenChars = TRUE;

    return STATUS_SUCCESS;
}

/* 通过父链重建键路径 */
static
BOOLEAN RaRebuildKeyPath(_In_ PBYTE HiveData, _In_ ULONG HiveSize,
                         _In_ ULONG CellOffset, _Out_ PWCHAR Path, _In_ ULONG PathCch) {
    WCHAR names[32][WKD_REG_MAX_NAME_CHARS];
    ULONG nameCount = 0;
    ULONG cur = CellOffset;

    while (nameCount < 32) {
        if (cur + 0x54 >= HiveSize) break;
        LONG cellSize = *(PLONG)(HiveData + cur);
        USHORT sig = *(PUSHORT)(HiveData + cur + 4);
        if (sig != 0x6B6E) break;

        WKD_RA_KEY_CELL cell;
        if (RaParseKeyCell(HiveData, HiveSize, cur, &cell) != STATUS_SUCCESS) break;

        if (cell.KeyName[0] != L'\0') {
            RaWcsCopy(names[nameCount++], WKD_REG_MAX_NAME_CHARS, cell.KeyName);
        }

        /* 父偏移 0xFFFFFFFF 或无效 → 根 */
        if (cell.ParentOffset == 0xFFFFFFFF ||
            cell.ParentOffset == 0xFFFFFFF1 /* gian last */) break;
        if (cell.ParentOffset == cur) break;               /* 环保护 */
        if (cell.ParentOffset >= HiveSize) break;
        cur = cell.ParentOffset;
    }

    if (nameCount == 0) return FALSE;

    Path[0] = L'\0';
    for (ULONG i = nameCount; i > 0; --i) {
        if (Path[0] != L'\0') {
            wcsncat_s(Path, PathCch, L"\\", 1);
        }
        wcsncat_s(Path, PathCch, names[i - 1], _TRUNCATE);
    }
    return TRUE;
}

/* 遍历 hive 所有 hbin 块, 收集已删除键节点。
 * RecoverDeletedEntriesImpl (取证恢复). */
static
NTSTATUS RaRecoverDeletedEntriesInternal(_In_ PCWSTR HivePath,
                                         _Out_ PWKD_RA_DELETED_ENTRY Entries,
                                         _In_  ULONG MaxCount,
                                         _Out_ PULONG Count) {
    if (Entries == NULL || Count == NULL || MaxCount == 0) return STATUS_INVALID_PARAMETER;
    *Count = 0;

    WKD_RA_HIVE_HEADER header;
    NTSTATUS status = RaParseHiveHeaderImpl(HivePath, &header);
    if (!NT_SUCCESS(status)) {
        RaDbgPrint(L"[RA] Deleted recovery aborted - invalid hive %s", HivePath);
        return status;
    }

    PBYTE hiveData = NULL;
    ULONG hiveSize = 0;
    status = RaReadHiveFile(HivePath, &hiveData, &hiveSize);
    if (!NT_SUCCESS(status)) return status;

    WKD_RA_HIVE_TYPE hiveType = RaHivePathToType(HivePath);
    InterlockedIncrement64(&g_Ra.Stats.TotalScans);

    ULONG recovered = 0;
    ULONG ib = 0x1000;   /* 首个 hbin 块 */
    while (ib + 0x20 <= hiveSize) {
        ULONG hbinSize = *(PULONG)(hiveData + ib + 0x04);
        if (hbinSize < 0x20 || hbinSize > RA_HBIN_SIZE_CAP || ib + hbinSize > hiveSize) {
            RaDbgPrint(L"[RA] Corrupt hbin at 0x%lX size 0x%lX", ib, hbinSize);
            break;
        }

        ULONG cell = ib + 0x20;
        ULONG hbinEnd = ib + hbinSize;
        while (cell + 8 <= hbinEnd) {
            LONG cellSize = *(PLONG)(hiveData + cell);
            if (cellSize == 0) break;                 /* 空槽终止 */

            /* 注意对齐: cell 起始须 8 字节对齐 (hbin 内) */
            if (cell + 4 < hbinEnd) {
                USHORT sig = *(PUSHORT)(hiveData + cell + 4);
                if (cellSize < 0 && sig == 0x6B6E && recovered < MaxCount) {
                    WKD_RA_DELETED_ENTRY entry;
                    memset(&entry, 0, sizeof(entry));
                    entry.IsKey = TRUE;
                    entry.CellOffset = cell;

                    WKD_RA_KEY_CELL cellInfo;
                    if (RaParseKeyCell(hiveData, hiveSize, cell, &cellInfo) == STATUS_SUCCESS) {
                        entry.DeletedTime = cellInfo.LastWritten;
                        entry.ValueType = 0;
                        RaWcsCopy(entry.Name, WKD_REG_MAX_NAME_CHARS, cellInfo.KeyName);

                        /* 父链重建路径 */
                        if (RaRebuildKeyPath(hiveData, hiveSize, cell,
                                             entry.Path, WKD_REG_MAX_PATH_CHARS)) {
                            entry.IsRecoverable = TRUE;
                        } else {
                            entry.IsPartial = TRUE;
                            /* 无父链时, 用 hive 类型作占位根 */
                            PCWSTR hiveRoot = RaHiveTypeToSystemPath(hiveType);
                            if (hiveRoot != NULL && entry.Path[0] != L'\0') {
                                /* 保持原始键名即可 */
                            } else if (entry.Path[0] == L'\0') {
                                RaWcsCopy(entry.Path, WKD_REG_MAX_PATH_CHARS, L"<orphaned>");
                            }
                        }

                        /* 尝试读取值数据 (vx cell) 不可靠, 标 IsPartial */
                        if (cellInfo.ValueCount > 0) entry.IsPartial = TRUE;

                        Entries[recovered++] = entry;
                    }
                }
            }

            /* 前进到下一 cell: 记录对齐 8 字节 */
            ULONG absSize = (ULONG)((cellSize < 0) ? -cellSize : cellSize);
            if (absSize == 0) break;
            absSize = (absSize + 7) & ~7UL;
            cell += absSize;
        }

        ib += hbinSize;
        if (g_Ra.AbortRequested) break;
    }

    free(hiveData);
    *Count = recovered;
    InterlockedExchangeAdd64(&g_Ra.Stats.DeletedRecovered, recovered);
    RaDbgPrint(L"[RA] Recovered %lu deleted key nodes from %s", recovered, HivePath);
    return STATUS_SUCCESS;
}

/* ==================================================
 * 威胁指标 (加载 / 匹配 / 搜索)
 * ================================================== */
static
BOOLEAN RaHexToBytes(_In_ PCSTR Hex, _In_ ULONG HexLen,
                     _Out_ PBYTE Bytes, _In_ ULONG MaxBytes,
                     _Out_ PULONG OutLen) {
    if (Hex == NULL || Bytes == NULL || OutLen == NULL) return FALSE;
    if ((HexLen % 2) != 0 || HexLen / 2 > MaxBytes) return FALSE;
    *OutLen = HexLen / 2;
    for (ULONG i = 0; i < HexLen; i += 2) {
        CHAR hi = Hex[i];
        CHAR lo = Hex[i + 1];
        BYTE hiVal = 0, loVal = 0;
        if (hi >= '0' && hi <= '9') hiVal = (BYTE)(hi - '0');
        else if (hi >= 'a' && hi <= 'f') hiVal = (BYTE)(hi - 'a' + 10);
        else if (hi >= 'A' && hi <= 'F') hiVal = (BYTE)(hi - 'A' + 10);
        else return FALSE;
        if (lo >= '0' && lo <= '9') loVal = (BYTE)(lo - '0');
        else if (lo >= 'a' && lo <= 'f') loVal = (BYTE)(lo - 'a' + 10);
        else if (lo >= 'A' && lo <= 'F') loVal = (BYTE)(lo - 'A' + 10);
        else return FALSE;
        Bytes[i / 2] = (BYTE)((hiVal << 4) | loVal);
    }
    return TRUE;
}

/* 加载指标文件 (txt). 格式: KEY_PATTERN|VALUE_PATTERN|DATA_HEX|NAME|FAMILY|MITRE
 * # 开头为注释. 空行跳过. 每行三个以上字段生效. */
static
NTSTATUS RaLoadThreatIndicatorsImpl(_In_ PCWSTR IndicatorsPath,
                                    _Out_ PULONG LoadedCount) {
    if (IndicatorsPath == NULL || LoadedCount == NULL) return STATUS_INVALID_PARAMETER;
    *LoadedCount = 0;

    HANDLE hFile = CreateFileW(IndicatorsPath, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        RaDbgPrint(L"[RA] Indicator file not found: %s", IndicatorsPath);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(hFile, &sz) || sz.QuadPart <= 0 || sz.QuadPart > RA_INDICATOR_FILE_CAP) {
        CloseHandle(hFile);
        return STATUS_FILE_INVALID;
    }

    ULONG bufSize = (ULONG)sz.QuadPart;
    PCHAR text = (PCHAR)malloc(bufSize + 1);
    if (text == NULL) {
        CloseHandle(hFile);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DWORD total = 0, chunk = 0;
    while (total < bufSize && ReadFile(hFile, text + total, bufSize - total, &chunk, NULL) && chunk > 0) {
        total += chunk;
    }
    CloseHandle(hFile);
    text[total] = '\0';

    ULONG loaded = 0;
    PCHAR cursor = text;
    while (cursor != NULL && *cursor != '\0') {
        PCHAR eol = strchr(cursor, '\n');
        SIZE_T lineLen = (eol != NULL) ? (SIZE_T)(eol - cursor) : strlen(cursor);
        PCHAR line = cursor;

        /* 去行尾 \r */
        if (lineLen > 0 && line[lineLen - 1] == '\r') lineLen--;

        if (lineLen > 2 && line[0] != '#' && line[0] != ';') {
            /* 临时拷贝行 (可写) */
            PCHAR copy = (PCHAR)malloc(lineLen + 1);
            if (copy != NULL) {
                memcpy(copy, line, lineLen);
                copy[lineLen] = '\0';

                PCHAR fields[7] = { NULL };
                ULONG fieldCount = 0;
                PCHAR token = copy;
                while (token != NULL && fieldCount < 7) {
                    PCHAR sep = strchr(token, '|');
                    if (sep != NULL) *sep = '\0';
                    fields[fieldCount++] = token;
                    token = (sep != NULL) ? sep + 1 : NULL;
                }

                if (fieldCount >= 3) {
                    WKD_RA_THREAT_INDICATOR ind;
                    memset(&ind, 0, sizeof(ind));

                    MultiByteToWideChar(CP_UTF8, 0, fields[0], -1, ind.KeyPattern,
                                        WKD_RA_MAX_INDICATOR_CHARS);
                    if (fieldCount >= 2) {
                        MultiByteToWideChar(CP_UTF8, 0, fields[1], -1, ind.ValuePattern,
                                            WKD_RA_MAX_INDICATOR_CHARS);
                    }
                    if (strlen(fields[2]) > 0) {
                        RaHexToBytes(fields[2], (ULONG)strlen(fields[2]),
                                     ind.DataPattern, sizeof(ind.DataPattern),
                                     &ind.DataPatternSize);
                    }
                    if (fieldCount >= 4) {
                        strncpy_s(ind.ThreatName, WKD_REG_MAX_NAME_CHARS, fields[3], _TRUNCATE);
                    }
                    if (fieldCount >= 5) {
                        strncpy_s(ind.MalwareFamily, WKD_PD_MAX_MALWARE_FAMILY_CHARS, fields[4], _TRUNCATE);
                    }
                    if (fieldCount >= 6) {
                        strncpy_s(ind.MitreId, 32, fields[5], _TRUNCATE);
                    }
                    ind.IsRegex = FALSE;   /* 通配符降级语义 */

                    /* 写入全局指标缓冲 */
                    AcquireSRWLockExclusive(&g_Ra.IndicatorLock);
                    if (g_Ra.IndicatorCount < g_Ra.IndicatorCapacity) {
                        g_Ra.Indicators[g_Ra.IndicatorCount++] = ind;
                        loaded++;
                    }
                    ReleaseSRWLockExclusive(&g_Ra.IndicatorLock);
                }
                free(copy);
            }
        }

        cursor = (eol != NULL) ? eol + 1 : NULL;
    }

    free(text);
    *LoadedCount = loaded;
    InterlockedExchangeAdd64(&g_Ra.Stats.IocsMatched, 0); /* 占位保持语义 */
    RaDbgPrint(L"[RA] Loaded %lu threat indicators from %s", loaded, IndicatorsPath);
    return (loaded > 0) ? STATUS_SUCCESS : STATUS_NO_MORE_ENTRIES;
}

/* 用单条指标匹配异常 (Indicator::Matches) */
static
BOOLEAN RaIndicatorMatches(_In_ PCWKD_RA_THREAT_INDICATOR Ind,
                           _In_ PCWKD_RA_ANOMALY A) {
    if (Ind == NULL || A == NULL) return FALSE;

    /* KeyPattern → 通配符/子串 匹配 KeyPath */
    if (Ind->KeyPattern[0] != L'\0') {
        BOOLEAN hit;
        if (Ind->IsRegex) {
            /* 原 regex 部分匹配语义 → *pattern* 包裹 */
            WCHAR wrapped[WKD_RA_MAX_INDICATOR_CHARS + 2];
            swprintf_s(wrapped, WKD_RA_MAX_INDICATOR_CHARS + 2, L"*%ls*", Ind->KeyPattern);
            hit = RaWildcardMatch(wrapped, A->KeyPath);
        } else {
            hit = RaWcsContains(A->KeyPath, Ind->KeyPattern);
        }
        if (!hit) return FALSE;
    }

    /* ValuePattern → 子串匹配 ValueName 或 KeyPath */
    if (Ind->ValuePattern[0] != L'\0') {
        if (!RaWcsContains(A->ValueName, Ind->ValuePattern) &&
            !RaWcsContains(A->KeyPath, Ind->ValuePattern)) {
            return FALSE;
        }
    }

    /* DataPattern → RawData 内字节匹配 */
    if (Ind->DataPatternSize > 0) {
        BOOLEAN found = FALSE;
        if (A->RawDataSize >= Ind->DataPatternSize) {
            for (ULONG i = 0; i + Ind->DataPatternSize <= A->RawDataSize; ++i) {
                if (memcmp(A->RawData + i, Ind->DataPattern, Ind->DataPatternSize) == 0) {
                    found = TRUE;
                    break;
                }
            }
        }
        if (!found) return FALSE;
    }

    return TRUE;
}

/* IOC / 指标搜索.
 * IocPaths==NULL 且 IocPathCount==0 → 使用内部指标列表遍历全部异常;
 * 否则对 IocPaths 字面量做 KeyPath 子串匹配. */
static
VOID RaSearchIocsImpl(_In_ PCWSTR* IocPaths, _In_ ULONG IocPathCount,
                      _Out_opt_ PWKD_RA_ANOMALY Out, _In_ ULONG MaxCount,
                      _Out_ PULONG MatchCount) {
    if (MatchCount == NULL) return;
    *MatchCount = 0;

    BOOLEAN useInternal = (IocPaths == NULL || IocPathCount == 0);

    AcquireSRWLockShared(&g_Ra.AnomalyLock);
    for (ULONG i = 0; i < g_Ra.AnomalyCount; ++i) {
        PCWKD_RA_ANOMALY a = &g_Ra.Anomalies[i];
        BOOLEAN matched = FALSE;

        if (useInternal) {
            AcquireSRWLockShared(&g_Ra.IndicatorLock);
            for (ULONG ind = 0; ind < g_Ra.IndicatorCount; ++ind) {
                if (RaIndicatorMatches(&g_Ra.Indicators[ind], a)) {
                    /* 回填匹配证据 (锁内写仅当前线索安全) */
                    if (a->MatchedIocCount < 4) {
                        ((PWKD_RA_ANOMALY)a)->MatchedIocCount =
                            a->MatchedIocCount + 1;
                        strncpy_s(((PWKD_RA_ANOMALY)a)->MatchedIocs[a->MatchedIocCount - 1],
                                  64, g_Ra.Indicators[ind].ThreatName, _TRUNCATE);
                        if (a->MatchedIocCount == 1) {
                            strncpy_s(((PWKD_RA_ANOMALY)a)->MalwareFamily,
                                      WKD_PD_MAX_MALWARE_FAMILY_CHARS,
                                      g_Ra.Indicators[ind].MalwareFamily, _TRUNCATE);
                        }
                    }
                    matched = TRUE;
                    break;
                }
            }
            ReleaseSRWLockShared(&g_Ra.IndicatorLock);
        } else {
            WCHAR lowerKey[WKD_REG_MAX_PATH_CHARS];
            RaWcsToLowerCopy(a->KeyPath, lowerKey, WKD_REG_MAX_PATH_CHARS);
            for (ULONG c = 0; c < IocPathCount; ++c) {
                if (IocPaths[c] == NULL) continue;
                WCHAR lowerIoc[WKD_REG_MAX_PATH_CHARS];
                RaWcsToLowerCopy(IocPaths[c], lowerIoc, WKD_REG_MAX_PATH_CHARS);
                if (wcsstr(lowerKey, lowerIoc) != NULL) { matched = TRUE; break; }
                (VOID)strstr(a->Sha256Hex, ""); /* 保留读写标记 */
            }
        }

        if (matched) {
            InterlockedIncrement64(&g_Ra.Stats.PatternsMatched);
            if (Out != NULL && *MatchCount < MaxCount) {
                Out[*MatchCount] = *a;
            }
            (*MatchCount)++;
        }
    }
    ReleaseSRWLockShared(&g_Ra.AnomalyLock);
}

/* ==================================================
 * 进度回调
 * ================================================== */
static
VOID RaInvokeProgressCallback(_In_ PCWSTR CurrentPath, _In_ ULONG Percent) {
    /* 进度回调在锁外执行, 内部不持有 CallbackLock 重入 */
    for (ULONG i = 0; i < WKD_RA_MAX_CALLBACKS; ++i) {
        if (g_Ra.ProgressCallbacks[i].InUse && g_Ra.ProgressCallbacks[i].Fn != NULL) {
            g_Ra.ProgressCallbacks[i].Fn(CurrentPath, Percent, g_Ra.ProgressCallbacks[i].Ctx);
        }
    }
}

/* ==================================================
 * 导出辅助 (CSV / 报告)
 * ================================================== */
static
NTSTATUS RaWriteTextFile(_In_ PCWSTR Path, _In_ PCSTR Content) {
    if (Path == NULL || Content == NULL) return STATUS_INVALID_PARAMETER;
    HANDLE hFile = CreateFileW(Path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return STATUS_ACCESS_DENIED;
    DWORD written = 0;
    BOOLEAN ok = WriteFile(hFile, Content, (DWORD)strlen(Content), &written, NULL);
    CloseHandle(hFile);
    return ok ? STATUS_SUCCESS : STATUS_DISK_FULL;
}

static
NTSTATUS RaExportAnomaliesImpl(_In_ PCWSTR OutputPath) {
    CHAR csv[RA_CSV_LINE_CAP] = { 0 };
    RaWcsCopyA("AnomalyId,DetectedTime,Hive,KeyPath,ValueName,Type,Severity,Description,Technique,Entropy,Sha256\n",
               csv, RA_CSV_LINE_CAP);

    /* 聚合行 (每异常至多 4KB, 行级缓冲) */
    CHAR line[4096];
    CHAR keyNarrow[WKD_REG_MAX_PATH_CHARS * 2];
    CHAR valNarrow[WKD_REG_MAX_NAME_CHARS * 2];
    CHAR hiveNarrow[WKD_REG_MAX_PATH_CHARS * 2];

    AcquireSRWLockShared(&g_Ra.AnomalyLock);
    for (ULONG i = 0; i < g_Ra.AnomalyCount; ++i) {
        PCWKD_RA_ANOMALY a = &g_Ra.Anomalies[i];
        RaToNarrowUtf8(a->KeyPath, keyNarrow, sizeof(keyNarrow));
        RaToNarrowUtf8(a->ValueName, valNarrow, sizeof(valNarrow));
        RaToNarrowUtf8(a->HivePath, hiveNarrow, sizeof(hiveNarrow));

        CHAR timeStr[64];
        _snprintf_s(timeStr, 64, _TRUNCATE, "%I64u", (ULONGLONG)a->DetectedTime);

        _snprintf_s(line, 4096, _TRUNCATE,
                    "%I64u,%s,%s,%s,%s,%d,%d,%s,%s,%.2f,%s\n",
                    a->AnomalyId, timeStr, hiveNarrow, keyNarrow, valNarrow,
                    (INT)a->Type, (INT)a->Severity, a->Description, a->Technique,
                    a->Entropy, a->Sha256Hex);
        SizeT_StringCat(csv, line, RA_CSV_LINE_CAP);
    }
    ReleaseSRWLockShared(&g_Ra.AnomalyLock);

    return RaWriteTextFile(OutputPath, csv);
}

static
NTSTATUS RaExportTimelineImpl(_In_ PCWSTR OutputPath) {
    CHAR csv[RA_CSV_LINE_CAP] = { 0 };
    RaWcsCopyA("Timestamp,Action,Hive,KeyPath,ValueName,Description,IsAnomaly\n", csv, RA_CSV_LINE_CAP);

    CHAR line[4096];
    CHAR keyNarrow[WKD_REG_MAX_PATH_CHARS * 2];
    CHAR valNarrow[WKD_REG_MAX_NAME_CHARS * 2];

    AcquireSRWLockShared(&g_Ra.TimelineLock);
    for (ULONG i = 0; i < g_Ra.TimelineCount; ++i) {
        PCWKD_RA_TIMELINE t = &g_Ra.Timeline[i];
        RaToNarrowUtf8(t->KeyPath, keyNarrow, sizeof(keyNarrow));
        RaToNarrowUtf8(t->ValueName, valNarrow, sizeof(valNarrow));
        _snprintf_s(line, 4096, _TRUNCATE,
                    "%I64u,%s,%d,%s,%s,%s,%d\n",
                    (ULONGLONG)t->Timestamp, t->Action, (INT)t->Hive,
                    keyNarrow, valNarrow, t->Description, (INT)t->IsAnomaly);
        SizeT_StringCat(csv, line, RA_CSV_LINE_CAP);
    }
    ReleaseSRWLockShared(&g_Ra.TimelineLock);

    return RaWriteTextFile(OutputPath, csv);
}

static
NTSTATUS RaExportHiddenEntriesImpl(_In_ PCWSTR OutputPath) {
    CHAR text[RA_CSV_LINE_CAP] = { 0 };
    RaWcsCopyA("# Hidden registry entries detected by RA\n", text, RA_CSV_LINE_CAP);

    CHAR line[512];
    AcquireSRWLockShared(&g_Ra.AnomalyLock);
    for (ULONG i = 0; i < g_Ra.AnomalyCount; ++i) {
        PCWKD_RA_ANOMALY a = &g_Ra.Anomalies[i];
        if (!a->IsHidden) continue;
        CHAR keyNarrow[WKD_REG_MAX_PATH_CHARS * 2];
        RaToNarrowUtf8(a->KeyPath, keyNarrow, sizeof(keyNarrow));
        _snprintf_s(line, 512, _TRUNCATE, "%s [TYPE %d]\n", keyNarrow, (INT)a->Type);
        SizeT_StringCat(text, line, RA_CSV_LINE_CAP);
    }
    ReleaseSRWLockShared(&g_Ra.AnomalyLock);

    return RaWriteTextFile(OutputPath, text);
}

/* ==================================================
 * 配置工厂
 * ================================================== */
VOID
RaCreateDefaultConfig(_Out_ PWKD_RA_CONFIG Config) {
    if (Config == NULL) return;
    memset(Config, 0, sizeof(*Config));
    Config->DefaultMode = WkdRaMode_Deep;
    Config->DetectHiddenKeys = TRUE;
    Config->DetectHiddenValues = TRUE;
    Config->AnalyzeEntropy = TRUE;
    Config->DetectEmbeddedExecutables = TRUE;
    Config->EnableCrossView = TRUE;
    Config->DetectDkom = FALSE;
    Config->RecoverDeleted = FALSE;
    Config->AnalyzeSlackSpace = FALSE;
    Config->BuildTimeline = TRUE;
    Config->MatchPatterns = TRUE;
    Config->MatchIocs = TRUE;
    Config->MaxAnomalies = WKD_RA_MAX_ANOMALIES;
    Config->ThreadCount = RA_DEFAULT_THREAD_COUNT;
}

VOID
RaCreateForensicConfig(_Out_ PWKD_RA_CONFIG Config) {
    if (Config == NULL) return;
    memset(Config, 0, sizeof(*Config));
    Config->DefaultMode = WkdRaMode_Forensic;
    Config->DetectHiddenKeys = TRUE;
    Config->DetectHiddenValues = TRUE;
    Config->AnalyzeEntropy = TRUE;
    Config->DetectEmbeddedExecutables = TRUE;
    Config->EnableCrossView = TRUE;
    Config->DetectDkom = FALSE;
    Config->RecoverDeleted = TRUE;
    Config->AnalyzeSlackSpace = TRUE;
    Config->BuildTimeline = TRUE;
    Config->MatchPatterns = TRUE;
    Config->MatchIocs = TRUE;
    Config->MaxAnomalies = WKD_RA_MAX_ANOMALIES;
    Config->ThreadCount = 4;
}

VOID
RaCreateRootkitHuntingConfig(_Out_ PWKD_RA_CONFIG Config) {
    if (Config == NULL) return;
    memset(Config, 0, sizeof(*Config));
    Config->DefaultMode = WkdRaMode_RootkitHunting;
    Config->DetectHiddenKeys = TRUE;
    Config->DetectHiddenValues = TRUE;
    Config->AnalyzeEntropy = FALSE;
    Config->DetectEmbeddedExecutables = FALSE;
    Config->EnableCrossView = TRUE;
    Config->DetectDkom = TRUE;
    Config->RecoverDeleted = FALSE;
    Config->AnalyzeSlackSpace = FALSE;
    Config->BuildTimeline = FALSE;
    Config->MatchPatterns = FALSE;
    Config->MatchIocs = TRUE;
    Config->MaxAnomalies = WKD_RA_MAX_ANOMALIES;
    Config->ThreadCount = 2;
}

VOID
RaCreateQuickConfig(_Out_ PWKD_RA_CONFIG Config) {
    if (Config == NULL) return;
    memset(Config, 0, sizeof(*Config));
    Config->DefaultMode = WkdRaMode_Quick;
    Config->DetectHiddenKeys = TRUE;
    Config->DetectHiddenValues = FALSE;
    Config->AnalyzeEntropy = FALSE;
    Config->DetectEmbeddedExecutables = FALSE;
    Config->EnableCrossView = FALSE;
    Config->DetectDkom = FALSE;
    Config->RecoverDeleted = FALSE;
    Config->AnalyzeSlackSpace = FALSE;
    Config->BuildTimeline = FALSE;
    Config->MatchPatterns = FALSE;
    Config->MatchIocs = FALSE;
    Config->MaxAnomalies = WKD_RA_MAX_ANOMALIES;
    Config->ThreadCount = 1;
}

/* ==================================================
 * 生命周期
 * ================================================== */
NTSTATUS
RaInitialize(_In_opt_ const WKD_RA_CONFIG* Config) {
    /* 幂等 */
    if (InterlockedCompareExchange(&g_Ra.Initialized, 1, 0) != 0) {
        return STATUS_ALREADY_INITIALIZED;
    }

    AcquireSRWLockExclusive(&g_Ra.ConfigLock);
    if (Config != NULL) {
        g_Ra.Config = *Config;
    } else {
        RaCreateDefaultConfig(&g_Ra.Config);
    }

    /* 预分配异常缓冲 */
    ULONG initialCap = g_Ra.Config.MaxAnomalies;
    if (initialCap == 0) initialCap = WKD_RA_MAX_ANOMALIES;
    g_Ra.Anomalies = (PWKD_RA_ANOMALY)malloc(initialCap * sizeof(WKD_RA_ANOMALY));
    g_Ra.AnomalyCapacity = (g_Ra.Anomalies != NULL) ? initialCap : 0;
    g_Ra.AnomalyCount = 0;

    g_Ra.Deleted = NULL;
    g_Ra.DeletedCount = 0;
    g_Ra.DeletedCapacity = 0;

    g_Ra.KeyAnomalies = NULL;
    g_Ra.KeyAnomalyCount = 0;
    g_Ra.KeyAnomalyCapacity = 0;

    g_Ra.Timeline = NULL;
    g_Ra.TimelineCount = 0;
    g_Ra.TimelineCapacity = 0;

    g_Ra.Indicators = NULL;
    g_Ra.IndicatorCount = 0;
    g_Ra.IndicatorCapacity = 0;

    g_Ra.NextAnomalyId = 0;
    g_Ra.NextCallbackId = 1;

    /* 回调表清零 */
    memset(g_Ra.AnomalyCallbacks, 0, sizeof(g_Ra.AnomalyCallbacks));
    memset(g_Ra.ProgressCallbacks, 0, sizeof(g_Ra.ProgressCallbacks));
    memset(g_Ra.HiddenCallbacks, 0, sizeof(g_Ra.HiddenCallbacks));

    ReleaseSRWLockExclusive(&g_Ra.ConfigLock);

    RaResetStatistics();
    RaDbgPrint(L"[RA] RegistryAnalyzer initialized (mode %d)",
               (INT)g_Ra.Config.DefaultMode);
    return STATUS_SUCCESS;
}

VOID
RaShutdown(VOID) {
    if (InterlockedExchange(&g_Ra.Initialized, 0) == 0) {
        return;   /* 未初始化 */
    }

    AcquireSRWLockExclusive(&g_Ra.ConfigLock);
    if (g_Ra.Analyzing) InterlockedExchange(&g_Ra.AbortRequested, 1);

    /* 释放动态缓冲 */
    if (g_Ra.Anomalies != NULL) { free(g_Ra.Anomalies); g_Ra.Anomalies = NULL; }
    g_Ra.AnomalyCount = g_Ra.AnomalyCapacity = 0;

    if (g_Ra.KeyAnomalies != NULL) { free(g_Ra.KeyAnomalies); g_Ra.KeyAnomalies = NULL; }
    g_Ra.KeyAnomalyCount = g_Ra.KeyAnomalyCapacity = 0;

    if (g_Ra.Timeline != NULL) { free(g_Ra.Timeline); g_Ra.Timeline = NULL; }
    g_Ra.TimelineCount = g_Ra.TimelineCapacity = 0;

    if (g_Ra.Deleted != NULL) {
        for (ULONG i = 0; i < g_Ra.DeletedCount; ++i) {
            if (g_Ra.Deleted[i].Data != NULL) free(g_Ra.Deleted[i].Data);
        }
        free(g_Ra.Deleted);
        g_Ra.Deleted = NULL;
    }
    g_Ra.DeletedCount = g_Ra.DeletedCapacity = 0;

    if (g_Ra.Indicators != NULL) { free(g_Ra.Indicators); g_Ra.Indicators = NULL; }
    g_Ra.IndicatorCount = g_Ra.IndicatorCapacity = 0;

    RaListFree(&g_Ra.HiddenKeys);
    ReleaseSRWLockExclusive(&g_Ra.ConfigLock);

    RaDbgPrint(L"[RA] RegistryAnalyzer shutdown complete");
}

BOOLEAN
RaIsInitialized(VOID) {
    return (g_Ra.Initialized != 0);
}

/* ==================================================
 * 分析操作
 * ================================================== */
NTSTATUS
RaAnalyze(_In_ PCWKD_RA_SCOPE Scope,
          _In_ WKD_RA_ANALYSIS_MODE Mode,
          _Out_ PWKD_RA_RESULT Result) {
    if (Scope == NULL || Result == NULL) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;

    /* 防重入 */
    if (InterlockedCompareExchange(&g_Ra.Analyzing, 1, 0) != 0) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    InterlockedExchange(&g_Ra.AbortRequested, 0);

    memset(Result, 0, sizeof(*Result));
    Result->StartTime = RaTimeNow();

    /* 以入参 Mode 为最终模式 (PerformQuick/Standard/... 分发) */
    Result->Mode = Mode;

    /* 统计基值快照 (delta 计算) */
    LONG64 baseKeys = g_Ra.Stats.KeysAnalyzed;
    LONG64 baseValues = g_Ra.Stats.ValuesAnalyzed;
    LONG64 baseBytes = g_Ra.Stats.BytesAnalyzed;
    LONG64 baseHidden = g_Ra.Stats.HiddenKeysFound;
    LONG64 baseDeleted = g_Ra.Stats.DeletedRecovered;
    LONG64 baseMalicious = g_Ra.Stats.MaliciousEntries;

    RaInvokeProgressCallback(L"Analysis start", 0);

    /* 构建快照作用域 (`DefaultMode` 已知, 入参 Mode 优先) */
    WKD_RA_SCOPE effScope = *Scope;
    if (effScope.MaxDepth == 0) effScope.MaxDepth = WKD_RA_MAX_SCAN_DEPTH;
    ULONG scopeCount = 0;

    /* 显式 SpecificPaths 优先; 否则按 hive 布尔位展开默认路径 */
    if (effScope.SpecificPathCount == 0) {
        const struct { BOOLEAN* Flag; PCWSTR Path; } hivePaths[] = {
            { &effScope.AnalyzeSam,      RA_HIVE_SYSTEM_ROOT L"SAM" },
            { &effScope.AnalyzeSecurity, RA_HIVE_SYSTEM_ROOT L"SECURITY" },
            { &effScope.AnalyzeSoftware, RA_HIVE_SYSTEM_ROOT L"SOFTWARE" },
            { &effScope.AnalyzeSystem,   RA_HIVE_SYSTEM_ROOT L"SYSTEM" },
        };
        for (ULONG h = 0; h < 4; ++h) {
            if (*hivePaths[h].Flag && scopeCount < WKD_RA_MAX_SCOPE_PATHS) {
                RaWcsCopy(effScope.SpecificPaths[scopeCount++],
                          WKD_REG_MAX_PATH_CHARS, hivePaths[h].Path);
            }
        }
        effScope.SpecificPathCount = scopeCount;
        Result->HivesAnalyzed += scopeCount;
    } else {
        scopeCount = effScope.SpecificPathCount;
    }

    switch (Mode) {
        case WkdRaMode_Quick:          RaPerformQuickAnalysis(&effScope, Result); break;
        case WkdRaMode_Standard:       RaPerformStandardAnalysis(&effScope, Result); break;
        case WkdRaMode_Deep:           RaPerformDeepAnalysis(&effScope, Result); break;
        case WkdRaMode_Forensic:       RaPerformForensicAnalysis(&effScope, Result); break;
        case WkdRaMode_RootkitHunting: RaPerformRootkitHunting(&effScope, Result); break;
        default: break;
    }

    /* 统计回填 */
    Result->KeysAnalyzed   = g_Ra.Stats.KeysAnalyzed   - baseKeys;
    Result->ValuesAnalyzed = g_Ra.Stats.ValuesAnalyzed - baseValues;
    Result->BytesAnalyzed  = g_Ra.Stats.BytesAnalyzed  - baseBytes;
    Result->HiddenKeysFound = g_Ra.Stats.HiddenKeysFound - baseHidden;
    Result->DeletedRecovered = g_Ra.Stats.DeletedRecovered - baseDeleted;
    Result->MaliciousEntries = g_Ra.Stats.MaliciousEntries - baseMalicious;

    /* 严重度分布 (本次分析新增异常) */
    {
        ULONGLONG baseAnomalies = g_Ra.Stats.AnomaliesDetected;
        AcquireSRWLockShared(&g_Ra.AnomalyLock);
        for (ULONG i = 0; i < g_Ra.AnomalyCount; ++i) {
            PCWKD_RA_ANOMALY a = &g_Ra.Anomalies[i];
            switch (a->Severity) {
                case WkdRaSev_Critical: Result->CriticalAnomalies++; break;
                case WkdRaSev_High:     Result->HighAnomalies++;     break;
                case WkdRaSev_Medium:   Result->MediumAnomalies++;   break;
                case WkdRaSev_Low:      Result->LowAnomalies++;      break;
                default: break;
            }
        }
        ReleaseSRWLockShared(&g_Ra.AnomalyLock);
        Result->AnomaliesFound = g_Ra.Stats.AnomaliesDetected - baseAnomalies;
    }

    Result->EndTime = RaTimeNow();
    Result->DurationMs = (ULONG)((Result->EndTime - Result->StartTime) / 10000);
    Result->Completed = TRUE;
    if (g_Ra.AbortRequested) {
        Result->HadErrors = TRUE;
        strncpy_s(Result->Errors[Result->ErrorCount++], 256,
                  "Analysis aborted by request", _TRUNCATE);
    }

    InterlockedExchange(&g_Ra.AbortRequested, 0);
    InterlockedExchange(&g_Ra.Analyzing, 0);
    RaInvokeProgressCallback(L"Analysis complete", 100);

    return STATUS_SUCCESS;
}

/* 单键分析 — 走捕获模式 (KeyAnomalies 缓冲) 后回填调用方 */
NTSTATUS
RegAnalyzeKey(_In_ PCWSTR KeyPath,
             _In_ BOOLEAN Recursive,
             _Out_opt_ PWKD_RA_ANOMALY Anomalies,
             _In_ ULONG MaxCount,
             _Out_ PULONG AnomalyCount) {
    if (KeyPath == NULL || AnomalyCount == NULL) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;
    if (Anomalies != NULL && MaxCount == 0) return STATUS_INVALID_PARAMETER;

    if (InterlockedCompareExchange(&g_Ra.Analyzing, 1, 0) != 0) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* 复位收集缓冲 */
    AcquireSRWLockExclusive(&g_Ra.AnomalyLock);
    g_Ra.KeyAnomalyCount = 0;
    ReleaseSRWLockExclusive(&g_Ra.AnomalyLock);

    InterlockedExchange(&g_Ra.AbortRequested, 0);
    InterlockedExchange(&g_Ra.KeyAnomalyCapture, 1);

    RegpAnalyzeKeyInternal(KeyPath, Recursive, 0, WKD_RA_MAX_SCAN_DEPTH);

    InterlockedExchange(&g_Ra.KeyAnomalyCapture, 0);

    /* 拷贝到调用方缓冲 */
    AcquireSRWLockExclusive(&g_Ra.AnomalyLock);
    ULONG needed = g_Ra.KeyAnomalyCount;
    ULONG copyCount = (needed < MaxCount) ? needed : MaxCount;
    if (Anomalies != NULL && copyCount > 0) {
        memcpy(Anomalies, g_Ra.KeyAnomalies, copyCount * sizeof(WKD_RA_ANOMALY));
    }
    *AnomalyCount = needed;
    ReleaseSRWLockExclusive(&g_Ra.AnomalyLock);

    InterlockedExchange(&g_Ra.Analyzing, 0);
    return (needed > MaxCount) ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
}

NTSTATUS
RaAnalyzeHiveFile(_In_ PCWSTR HivePath, _Out_ PWKD_RA_RESULT Result) {
    if (HivePath == NULL || Result == NULL) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;

    memset(Result, 0, sizeof(*Result));
    Result->StartTime = RaTimeNow();
    Result->Mode = WkdRaMode_Forensic;

    /* 1. 解析头 */
    WKD_RA_HIVE_HEADER header;
    NTSTATUS status = RaParseHiveHeader(HivePath, &header);
    if (!NT_SUCCESS(status)) {
        Result->HadErrors = TRUE;
        strncpy_s(Result->Errors[Result->ErrorCount++], 256,
                  "Invalid hive header", _TRUNCATE);
        return status;
    }

    /* 2. 结构校验 */
    BOOLEAN valid = FALSE;
    RaValidateHiveStructure(HivePath, &valid);
    if (!valid) {
        Result->HadErrors = TRUE;
        strncpy_s(Result->Errors[Result->ErrorCount++], 256,
                  "Hive structure validation failed", _TRUNCATE);
    }

    /* 3. 删除条目恢复 */
    if (g_Ra.Config.RecoverDeleted || header.IsDirty) {
        WKD_RA_DELETED_ENTRY entries[256];
        ULONG count = 0;
        if (RaRecoverDeletedEntriesInternal(HivePath, entries, 256, &count) == STATUS_SUCCESS) {
            Result->DeletedRecovered = count;
            /* 释放本次临时条目 (Data 均为 NULL, 直接忽略) */
            for (ULONG e = 0; e < count; ++e) {
                if (entries[e].Data != NULL) free(entries[e].Data);
            }
        }
    }

    Result->HivesAnalyzed = 1;
    Result->KeysAnalyzed = g_Ra.Stats.KeysAnalyzed;
    Result->BytesAnalyzed = header.DataLength;
    Result->Completed = TRUE;
    Result->EndTime = RaTimeNow();
    Result->DurationMs = (ULONG)((Result->EndTime - Result->StartTime) / 10000);

    return STATUS_SUCCESS;
}

NTSTATUS
RaAbortAnalysis(VOID) {
    if (!g_Ra.Analyzing) return STATUS_INVALID_DEVICE_STATE;
    InterlockedExchange(&g_Ra.AbortRequested, 1);
    RaDbgPrint(L"[RA] Abort requested");
    return STATUS_SUCCESS;
}

BOOLEAN
RaIsAnalysisRunning(VOID) {
    return (g_Ra.Analyzing != 0);
}

/* ==================================================
 * 隐藏条目检测
 * ================================================== */
NTSTATUS
RaDetectNullByteKeys(_In_ PCWSTR RootKey,
                     _Out_opt_ PWCHAR* HiddenKeys,
                     _In_ ULONG MaxCount,
                     _Out_ PULONG KeyCount) {
    if (RootKey == NULL || KeyCount == NULL) return STATUS_INVALID_PARAMETER;
    if (HiddenKeys != NULL && MaxCount == 0) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;

    RA_STRING_LIST hidden = { 0 };
    RA_STRING_LIST pending = { 0 };
    RegpDetectNullByteKeysInternal(RootKey, &hidden, &pending);
    RaListFree(&pending);

    ULONG needed = hidden.Count;
    ULONG copyCount = (needed < MaxCount) ? needed : MaxCount;
    for (ULONG i = 0; i < copyCount; ++i) {
        RaWcsCopy((PWCHAR)((PBYTE)HiddenKeys + i * WKD_REG_MAX_PATH_CHARS * sizeof(WCHAR)),
                  WKD_REG_MAX_PATH_CHARS, hidden.Items[i]);
    }
    *KeyCount = needed;
    RaListFree(&hidden);

    return (needed > MaxCount) ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
}

NTSTATUS
RaPerformCrossViewDetection(_In_ PCWSTR KeyPath,
                            _Out_ PWKD_RA_CROSS_VIEW_RESULT Result) {
    if (KeyPath == NULL || Result == NULL) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;
    RaPerformCrossViewDetectionInternal(KeyPath, Result);
    return STATUS_SUCCESS;
}

NTSTATUS
RaGetHiddenKeys(_Out_opt_ PWCHAR* HiddenKeys,
                _In_ ULONG MaxCount,
                _Out_ PULONG KeyCount) {
    if (KeyCount == NULL) return STATUS_INVALID_PARAMETER;
    if (HiddenKeys != NULL && MaxCount == 0) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;

    *KeyCount = 0;
    AcquireSRWLockShared(&g_Ra.AnomalyLock);
    for (ULONG i = 0; i < g_Ra.AnomalyCount; ++i) {
        PCWKD_RA_ANOMALY a = &g_Ra.Anomalies[i];
        if (!a->IsHidden) continue;
        if (*KeyCount < MaxCount && HiddenKeys != NULL) {
            WCHAR full[WKD_REG_MAX_PATH_CHARS];
            if (a->ValueName[0] != L'\0') {
                _snwprintf_s(full, WKD_REG_MAX_PATH_CHARS, _TRUNCATE,
                             L"%s\\%s", a->KeyPath, a->ValueName);
            } else {
                RaWcsCopy(full, WKD_REG_MAX_PATH_CHARS, a->KeyPath);
            }
            RaWcsCopy((PWCHAR)((PBYTE)HiddenKeys + (*KeyCount) * WKD_REG_MAX_PATH_CHARS * sizeof(WCHAR)),
                      WKD_REG_MAX_PATH_CHARS, full);
        }
        (*KeyCount)++;
    }
    ReleaseSRWLockShared(&g_Ra.AnomalyLock);

    return (*KeyCount > MaxCount) ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
}

/* ==================================================
 * 异常访问
 * ================================================== */
NTSTATUS
RaGetAnomalies(_Out_opt_ PWKD_RA_ANOMALY Anomalies,
               _In_ ULONG MaxCount,
               _Out_ PULONG AnomalyCount) {
    if (AnomalyCount == NULL) return STATUS_INVALID_PARAMETER;
    if (Anomalies != NULL && MaxCount == 0) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;

    AcquireSRWLockShared(&g_Ra.AnomalyLock);
    ULONG needed = g_Ra.AnomalyCount;
    ULONG copyCount = (needed < MaxCount) ? needed : MaxCount;
    if (Anomalies != NULL && copyCount > 0) {
        memcpy(Anomalies, g_Ra.Anomalies, copyCount * sizeof(WKD_RA_ANOMALY));
    }
    *AnomalyCount = needed;
    ReleaseSRWLockShared(&g_Ra.AnomalyLock);

    return (needed > MaxCount) ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
}

NTSTATUS
RaGetAnomaliesByType(_In_ WKD_RA_ANOMALY_TYPE Type,
                     _Out_opt_ PWKD_RA_ANOMALY Anomalies,
                     _In_ ULONG MaxCount,
                     _Out_ PULONG AnomalyCount) {
    if (AnomalyCount == NULL) return STATUS_INVALID_PARAMETER;
    if (!!Anomalies && MaxCount == 0) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;

    ULONG written = 0;
    AcquireSRWLockShared(&g_Ra.AnomalyLock);
    for (ULONG i = 0; i < g_Ra.AnomalyCount; ++i) {
        PCWKD_RA_ANOMALY a = &g_Ra.Anomalies[i];
        if (a->Type != Type) continue;
        if (Anomalies != NULL && written < MaxCount) {
            Anomalies[written] = *a;
        }
        written++;
    }
    *AnomalyCount = written;
    ReleaseSRWLockShared(&g_Ra.AnomalyLock);

    return (written > MaxCount) ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
}

NTSTATUS
RaGetAnomaliesBySeverity(_In_ WKD_RA_SEVERITY MinSeverity,
                         _Out_opt_ PWKD_RA_ANOMALY Anomalies,
                         _In_ ULONG MaxCount,
                         _Out_ PULONG AnomalyCount) {
    if (AnomalyCount == NULL) return STATUS_INVALID_PARAMETER;
    if (!!Anomalies && MaxCount == 0) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;

    ULONG written = 0;
    AcquireSRWLockShared(&g_Ra.AnomalyLock);
    for (ULONG i = 0; i < g_Ra.AnomalyCount; ++i) {
        PCWKD_RA_ANOMALY a = &g_Ra.Anomalies[i];
        if ((INT)a->Severity < (INT)MinSeverity) continue;
        if (Anomalies != NULL && written < MaxCount) {
            Anomalies[written] = *a;
        }
        written++;
    }
    *AnomalyCount = written;
    ReleaseSRWLockShared(&g_Ra.AnomalyLock);

    return (written > MaxCount) ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
}

NTSTATUS
RaGetAnomalyById(_In_ ULONGLONG AnomalyId, _Out_ PWKD_RA_ANOMALY Anomaly) {
    if (Anomaly == NULL) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;

    AcquireSRWLockShared(&g_Ra.AnomalyLock);
    for (ULONG i = 0; i < g_Ra.AnomalyCount; ++i) {
        if (g_Ra.Anomalies[i].AnomalyId == AnomalyId) {
            *Anomaly = g_Ra.Anomalies[i];
            ReleaseSRWLockShared(&g_Ra.AnomalyLock);
            return STATUS_SUCCESS;
        }
    }
    ReleaseSRWLockShared(&g_Ra.AnomalyLock);
    return STATUS_NOT_FOUND;
}

VOID
RaClearAnomalies(VOID) {
    if (!g_Ra.Initialized) return;
    AcquireSRWLockExclusive(&g_Ra.AnomalyLock);
    g_Ra.AnomalyCount = 0;
    ReleaseSRWLockExclusive(&g_Ra.AnomalyLock);
}

/* ==================================================
 * 删除条目恢复
 * ================================================== */
NTSTATUS
RaRecoverDeletedEntries(_In_ WKD_RA_HIVE_TYPE Hive,
                        _Out_opt_ PWKD_RA_DELETED_ENTRY Entries,
                        _In_ ULONG MaxCount,
                        _Out_ PULONG EntryCount) {
    if (EntryCount == NULL) return STATUS_INVALID_PARAMETER;
    if (Entries != NULL && MaxCount == 0) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;

    PCWSTR hivePath = RaHiveTypeToSystemPath(Hive);
    if (hivePath == NULL) {
        return STATUS_NOT_SUPPORTED;   /* NTUSER/USRCLASS 需显式路径 */
    }

    /* 直接走临时缓冲, 只保留调用方需要的份 */
    PWKD_RA_DELETED_ENTRY tmp = (PWKD_RA_DELETED_ENTRY)malloc(
        (MaxCount > 0 ? MaxCount : 1) * sizeof(WKD_RA_DELETED_ENTRY));
    if (tmp == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    ULONG found = 0;
    NTSTATUS status = RaRecoverDeletedEntriesInternal(hivePath, tmp, MaxCount, &found);
    if (NT_SUCCESS(status)) {
        for (ULONG i = 0; i < found; ++i) {
            if (Entries != NULL) {
                Entries[i] = tmp[i];
                tmp[i].Data = NULL;   /* 所有权移交调用方 */
            }
        }
        *EntryCount = found;
    }
    free(tmp);
    return status;
}

NTSTATUS
RaRecoverFromHiveFile(_In_ PCWSTR HivePath,
                      _Out_opt_ PWKD_RA_DELETED_ENTRY Entries,
                      _In_ ULONG MaxCount,
                      _Out_ PULONG EntryCount) {
    if (HivePath == NULL || EntryCount == NULL) return STATUS_INVALID_PARAMETER;
    if (Entries != NULL && MaxCount == 0) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;

    PWKD_RA_DELETED_ENTRY tmp = (PWKD_RA_DELETED_ENTRY)malloc(
        (MaxCount > 0 ? MaxCount : 1) * sizeof(WKD_RA_DELETED_ENTRY));
    if (tmp == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    ULONG found = 0;
    NTSTATUS status = RaRecoverDeletedEntriesInternal(HivePath, tmp, MaxCount, &found);
    if (NT_SUCCESS(status)) {
        for (ULONG i = 0; i < found; ++i) {
            if (Entries != NULL) {
                Entries[i] = tmp[i];
                tmp[i].Data = NULL;
            }
        }
        *EntryCount = found;
    }
    free(tmp);
    return status;
}

VOID
RaFreeRecoveredEntries(_In_ PWKD_RA_DELETED_ENTRY Entries, _In_ ULONG EntryCount) {
    if (Entries == NULL || EntryCount == 0) return;
    for (ULONG i = 0; i < EntryCount; ++i) {
        if (Entries[i].Data != NULL) {
            free(Entries[i].Data);
            Entries[i].Data = NULL;
        }
    }
}

/* ==================================================
 * Hive 解析
 * ================================================== */
NTSTATUS
RaParseHiveHeader(_In_ PCWSTR HivePath, _Out_ PWKD_RA_HIVE_HEADER Header) {
    if (HivePath == NULL || Header == NULL) return STATUS_INVALID_PARAMETER;
    return RaParseHiveHeaderImpl(HivePath, Header);
}

NTSTATUS
RaValidateHiveStructure(_In_ PCWSTR HivePath, _Out_ PBOOLEAN IsValid) {
    if (HivePath == NULL || IsValid == NULL) return STATUS_INVALID_PARAMETER;
    *IsValid = FALSE;

    WKD_RA_HIVE_HEADER header;
    if (!NT_SUCCESS(RaParseHiveHeaderImpl(HivePath, &header)) || !header.IsValid) {
        return STATUS_UNSUCCESSFUL;
    }

    PBYTE hiveData = NULL;
    ULONG hiveSize = 0;
    NTSTATUS status = RaReadHiveFile(HivePath, &hiveData, &hiveSize);
    if (!NT_SUCCESS(status)) return status;

    /* 遍历 hbin 检查边界完整 */
    BOOLEAN ok = TRUE;
    ULONG ib = 0x1000;
    while (ib + 0x20 <= hiveSize) {
        ULONG hbinSize = *(PULONG)(hiveData + ib + 0x04);
        if (hbinSize < 0x20 || hbinSize > RA_HBIN_SIZE_CAP || ib + hbinSize > hiveSize) {
            ok = FALSE;
            break;
        }
        ib += hbinSize;
    }
    if (ib != hiveSize) ok = FALSE;   /* 尾部未对齐 */

    free(hiveData);
    *IsValid = ok;
    return ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS
RaGetKeyCell(_In_ PCWSTR HivePath, _In_ ULONG Offset, _Out_ PWKD_RA_KEY_CELL Cell) {
    if (HivePath == NULL || Cell == NULL) return STATUS_INVALID_PARAMETER;

    PBYTE hiveData = NULL;
    ULONG hiveSize = 0;
    NTSTATUS status = RaReadHiveFile(HivePath, &hiveData, &hiveSize);
    if (!NT_SUCCESS(status)) return status;

    status = RaParseKeyCell(hiveData, hiveSize, Offset, Cell);
    free(hiveData);
    return status;
}

/* ==================================================
 * 威胁狩猎
 * ================================================== */
NTSTATUS
RaLoadThreatIndicators(_In_ PCWSTR IndicatorsPath, _Out_ PULONG LoadedCount) {
    if (IndicatorsPath == NULL || LoadedCount == NULL) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;
    return RaLoadThreatIndicatorsImpl(IndicatorsPath, LoadedCount);
}

NTSTATUS
RaAddThreatIndicator(_In_ PCWKD_RA_THREAT_INDICATOR Indicator) {
    if (Indicator == NULL) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;

    AcquireSRWLockExclusive(&g_Ra.IndicatorLock);
    if (g_Ra.IndicatorCount >= WKD_RA_MAX_INDICATORS) {
        ReleaseSRWLockExclusive(&g_Ra.IndicatorLock);
        return STATUS_BUFFER_OVERFLOW;
    }
    if (g_Ra.IndicatorCount >= g_Ra.IndicatorCapacity) {
        ULONG newCap = (g_Ra.IndicatorCapacity == 0) ? 64 : g_Ra.IndicatorCapacity * 2;
        PWKD_RA_THREAT_INDICATOR nb = (PWKD_RA_THREAT_INDICATOR)realloc(
            g_Ra.Indicators, newCap * sizeof(WKD_RA_THREAT_INDICATOR));
        if (nb == NULL) {
            ReleaseSRWLockExclusive(&g_Ra.IndicatorLock);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        g_Ra.Indicators = nb;
        g_Ra.IndicatorCapacity = newCap;
    }
    g_Ra.Indicators[g_Ra.IndicatorCount++] = *Indicator;
    ReleaseSRWLockExclusive(&g_Ra.IndicatorLock);
    return STATUS_SUCCESS;
}

NTSTATUS
RaSearchIocs(_In_opt_ PCWSTR* Iocs, _In_ ULONG IocCount,
             _Out_opt_ PWKD_RA_ANOMALY Matches, _In_ ULONG MaxCount,
             _Out_ PULONG MatchCount) {
    if (MatchCount == NULL) return STATUS_INVALID_PARAMETER;
    if (Matches != NULL && MaxCount == 0) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;

    RaSearchIocsImpl(Iocs, IocCount, Matches, MaxCount, MatchCount);
    return (*MatchCount > MaxCount) ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
}

/* ==================================================
 * 取证时间线
 * ================================================== */
NTSTATUS
RaGetTimeline(_In_ WKD_REG_TIMESTAMP StartTime, _In_ WKD_REG_TIMESTAMP EndTime,
              _Out_opt_ PWKD_RA_TIMELINE Entries, _In_ ULONG MaxCount,
              _Out_ PULONG EntryCount) {
    if (EntryCount == NULL) return STATUS_INVALID_PARAMETER;
    if (Entries != NULL && MaxCount == 0) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;

    ULONG written = 0;
    AcquireSRWLockShared(&g_Ra.TimelineLock);
    for (ULONG i = 0; i < g_Ra.TimelineCount; ++i) {
        PCWKD_RA_TIMELINE t = &g_Ra.Timeline[i];
        if (t->Timestamp < StartTime || t->Timestamp > EndTime) continue;
        if (Entries != NULL && written < MaxCount) {
            Entries[written] = *t;
        }
        written++;
    }
    *EntryCount = written;
    ReleaseSRWLockShared(&g_Ra.TimelineLock);

    return (written > MaxCount) ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
}

NTSTATUS
RaExportTimeline(_In_ PCWSTR OutputPath) {
    if (OutputPath == NULL) return STATUS_INVALID_PARAMETER;
    return RaExportTimelineImpl(OutputPath);
}

/* ==================================================
 * 熵分析
 * ================================================== */
NTSTATUS
RaGetHighEntropyValues(_In_ DOUBLE MinEntropy,
                       _Out_opt_ PWKD_RA_ANOMALY Anomalies,
                       _In_ ULONG MaxCount,
                       _Out_ PULONG AnomalyCount) {
    if (AnomalyCount == NULL) return STATUS_INVALID_PARAMETER;
    if (!!Anomalies && MaxCount == 0) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;

    ULONG written = 0;
    AcquireSRWLockShared(&g_Ra.AnomalyLock);
    for (ULONG i = 0; i < g_Ra.AnomalyCount; ++i) {
        PCWKD_RA_ANOMALY a = &g_Ra.Anomalies[i];
        if (a->Entropy < MinEntropy) continue;
        if (Anomalies != NULL && written < MaxCount) {
            Anomalies[written] = *a;
        }
        written++;
    }
    *AnomalyCount = written;
    ReleaseSRWLockShared(&g_Ra.AnomalyLock);

    return (written > MaxCount) ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
}

/* ==================================================
 * 回调注册
 * ================================================== */
ULONG
RaRegisterAnomalyCallback(_In_ PFN_RA_ANOMALY_CALLBACK Callback, _In_opt_ PVOID Context) {
    if (Callback == NULL) return 0;
    ULONG id = 0;
    AcquireSRWLockExclusive(&g_Ra.CallbackLock);
    for (ULONG i = 0; i < WKD_RA_MAX_CALLBACKS; ++i) {
        if (!g_Ra.AnomalyCallbacks[i].InUse) {
            g_Ra.AnomalyCallbacks[i].InUse = TRUE;
            g_Ra.AnomalyCallbacks[i].Fn = Callback;
            g_Ra.AnomalyCallbacks[i].Ctx = Context;
            g_Ra.AnomalyCallbacks[i].Id = (ULONG)InterlockedIncrement64(&g_Ra.NextCallbackId);
            id = g_Ra.AnomalyCallbacks[i].Id;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_Ra.CallbackLock);
    return id;
}

ULONG
RaRegisterProgressCallback(_In_ PFN_RA_PROGRESS_CALLBACK Callback, _In_opt_ PVOID Context) {
    if (Callback == NULL) return 0;
    ULONG id = 0;
    AcquireSRWLockExclusive(&g_Ra.CallbackLock);
    for (ULONG i = 0; i < WKD_RA_MAX_CALLBACKS; ++i) {
        if (!g_Ra.ProgressCallbacks[i].InUse) {
            g_Ra.ProgressCallbacks[i].InUse = TRUE;
            g_Ra.ProgressCallbacks[i].Fn = Callback;
            g_Ra.ProgressCallbacks[i].Ctx = Context;
            g_Ra.ProgressCallbacks[i].Id = (ULONG)InterlockedIncrement64(&g_Ra.NextCallbackId);
            id = g_Ra.ProgressCallbacks[i].Id;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_Ra.CallbackLock);
    return id;
}

ULONG
RaRegisterHiddenEntryCallback(_In_ PFN_RA_HIDDEN_CALLBACK Callback, _In_opt_ PVOID Context) {
    if (Callback == NULL) return 0;
    ULONG id = 0;
    AcquireSRWLockExclusive(&g_Ra.CallbackLock);
    for (ULONG i = 0; i < WKD_RA_MAX_CALLBACKS; ++i) {
        if (!g_Ra.HiddenCallbacks[i].InUse) {
            g_Ra.HiddenCallbacks[i].InUse = TRUE;
            g_Ra.HiddenCallbacks[i].Fn = Callback;
            g_Ra.HiddenCallbacks[i].Ctx = Context;
            g_Ra.HiddenCallbacks[i].Id = (ULONG)InterlockedIncrement64(&g_Ra.NextCallbackId);
            id = g_Ra.HiddenCallbacks[i].Id;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_Ra.CallbackLock);
    return id;
}

BOOLEAN
RaUnregisterCallback(_In_ ULONG CallbackId) {
    if (CallbackId == 0) return FALSE;
    BOOLEAN removed = FALSE;
    AcquireSRWLockExclusive(&g_Ra.CallbackLock);
    for (ULONG i = 0; i < WKD_RA_MAX_CALLBACKS; ++i) {
        if (g_Ra.AnomalyCallbacks[i].InUse && g_Ra.AnomalyCallbacks[i].Id == CallbackId) {
            g_Ra.AnomalyCallbacks[i].InUse = FALSE;
            removed = TRUE;
        }
        if (g_Ra.ProgressCallbacks[i].InUse && g_Ra.ProgressCallbacks[i].Id == CallbackId) {
            g_Ra.ProgressCallbacks[i].InUse = FALSE;
            removed = TRUE;
        }
        if (g_Ra.HiddenCallbacks[i].InUse && g_Ra.HiddenCallbacks[i].Id == CallbackId) {
            g_Ra.HiddenCallbacks[i].InUse = FALSE;
            removed = TRUE;
        }
    }
    ReleaseSRWLockExclusive(&g_Ra.CallbackLock);
    return removed;
}

/* ==================================================
 * 统计与导出
 * ================================================== */
VOID
RaGetStatistics(_Out_ PWKD_RA_STATS Statistics) {
    if (Statistics == NULL) return;
    memset(Statistics, 0, sizeof(*Statistics));
    Statistics->TotalScans       = InterlockedCompareExchange64(&g_Ra.Stats.TotalScans, 0, 0);
    Statistics->KeysAnalyzed     = InterlockedCompareExchange64(&g_Ra.Stats.KeysAnalyzed, 0, 0);
    Statistics->ValuesAnalyzed   = InterlockedCompareExchange64(&g_Ra.Stats.ValuesAnalyzed, 0, 0);
    Statistics->BytesAnalyzed    = InterlockedCompareExchange64(&g_Ra.Stats.BytesAnalyzed, 0, 0);
    Statistics->AnomaliesDetected = InterlockedCompareExchange64(&g_Ra.Stats.AnomaliesDetected, 0, 0);
    Statistics->HiddenKeysFound  = InterlockedCompareExchange64(&g_Ra.Stats.HiddenKeysFound, 0, 0);
    Statistics->HiddenValuesFound = InterlockedCompareExchange64(&g_Ra.Stats.HiddenValuesFound, 0, 0);
    Statistics->RootkitIndicators = InterlockedCompareExchange64(&g_Ra.Stats.RootkitIndicators, 0, 0);
    Statistics->MaliciousEntries = InterlockedCompareExchange64(&g_Ra.Stats.MaliciousEntries, 0, 0);
    Statistics->DeletedRecovered = InterlockedCompareExchange64(&g_Ra.Stats.DeletedRecovered, 0, 0);
    Statistics->PatternsMatched  = InterlockedCompareExchange64(&g_Ra.Stats.PatternsMatched, 0, 0);
    Statistics->IocsMatched      = InterlockedCompareExchange64(&g_Ra.Stats.IocsMatched, 0, 0);
}

VOID
RaResetStatistics(VOID) {
    InterlockedExchange64(&g_Ra.Stats.TotalScans, 0);
    InterlockedExchange64(&g_Ra.Stats.KeysAnalyzed, 0);
    InterlockedExchange64(&g_Ra.Stats.ValuesAnalyzed, 0);
    InterlockedExchange64(&g_Ra.Stats.BytesAnalyzed, 0);
    InterlockedExchange64(&g_Ra.Stats.AnomaliesDetected, 0);
    InterlockedExchange64(&g_Ra.Stats.HiddenKeysFound, 0);
    InterlockedExchange64(&g_Ra.Stats.HiddenValuesFound, 0);
    InterlockedExchange64(&g_Ra.Stats.RootkitIndicators, 0);
    InterlockedExchange64(&g_Ra.Stats.MaliciousEntries, 0);
    InterlockedExchange64(&g_Ra.Stats.DeletedRecovered, 0);
    InterlockedExchange64(&g_Ra.Stats.PatternsMatched, 0);
    InterlockedExchange64(&g_Ra.Stats.IocsMatched, 0);
}

NTSTATUS
RaExportAnomalies(_In_ PCWSTR OutputPath) {
    if (OutputPath == NULL) return STATUS_INVALID_PARAMETER;
    return RaExportAnomaliesImpl(OutputPath);
}

NTSTATUS
RaExportHiddenEntries(_In_ PCWSTR OutputPath) {
    if (OutputPath == NULL) return STATUS_INVALID_PARAMETER;
    return RaExportHiddenEntriesImpl(OutputPath);
}

NTSTATUS
RaExportReport(_In_ PCWSTR OutputPath) {
    if (OutputPath == NULL) return STATUS_INVALID_PARAMETER;
    if (!g_Ra.Initialized) return STATUS_NOT_IMPLEMENTED;

    CHAR report[RA_CSV_LINE_CAP] = { 0 };
    CHAR line[512];

    WKD_RA_STATS stats;
    RaGetStatistics(&stats);

    _snprintf_s(line, 512, _TRUNCATE,
                "WkDefender RegistryAnalyzer Report\n"
                "==================================\n"
                "Scans:          %I64d\n"
                "Keys:           %I64d\n"
                "Values:         %I64d\n"
                "Bytes:          %I64d\n"
                "Anomalies:      %I64d\n"
                "Hidden keys:    %I64d\n"
                "Hidden values:  %I64d\n"
                "Rootkit ind.:   %I64d\n"
                "Malicious:      %I64d\n"
                "Deleted rec.:   %I64d\n"
                "Patterns:       %I64d\n"
                "IOCs:           %I64d\n"
                "----------------------------------\n",
                stats.TotalScans, stats.KeysAnalyzed, stats.ValuesAnalyzed,
                stats.BytesAnalyzed, stats.AnomaliesDetected, stats.HiddenKeysFound,
                stats.HiddenValuesFound, stats.RootkitIndicators, stats.MaliciousEntries,
                stats.DeletedRecovered, stats.PatternsMatched, stats.IocsMatched);
    SizeT_StringCat(report, line, RA_CSV_LINE_CAP);

    /* 附严重度摘要 */
    ULONG crit = 0, high = 0, med = 0, low = 0;
    AcquireSRWLockShared(&g_Ra.AnomalyLock);
    for (ULONG i = 0; i < g_Ra.AnomalyCount; ++i) {
        switch (g_Ra.Anomalies[i].Severity) {
            case WkdRaSev_Critical: crit++; break;
            case WkdRaSev_High: high++; break;
            case WkdRaSev_Medium: med++; break;
            case WkdRaSev_Low: low++; break;
            default: break;
        }
    }
    ReleaseSRWLockShared(&g_Ra.AnomalyLock);

    _snprintf_s(line, 512, _TRUNCATE,
                "Severity: critical=%lu high=%lu medium=%lu low=%lu\n",
                crit, high, med, low);
    SizeT_StringCat(report, line, RA_CSV_LINE_CAP);

    return RaWriteTextFile(OutputPath, report);
}