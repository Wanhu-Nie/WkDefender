/**************************************************/
/*  WkDefender Agent — Registry\PersistenceDetector */
/*  持久化检测引擎 (The Watchman / ASEP Detection)   */
/*                                                  */
/*  迁移来源: ShadowStrike PhantomCore/Core/Registry */
/*  PersistenceDetector.cpp (2894 行, 2026-09-08)   */
/*                                                  */
/*  职责:                                            */
/*   - 全量 ASEP 位置扫描 (RunKey/Winlogon/IFEO/...  */
/*     DLL 注入/引导/Shell/COM/WMI 等 39 处已知位置)  */
/*   - WOW64 双视图枚举 + 去重                       */
/*   - 服务 / 计划任务 / WMI 订阅专项枚举(COM)       */
/*   - 目标解析 (引号/环境变量/短路径/参数/LOLBin)   */
/*   - 签名验证(IOC 统一入口) / SHA256 / 熵分析      */
/*   - 风险评分 (Pillar-4 权重) + 实时分析 + 告警    */
/*                                                  */
/*  虚标剔除 (对齐迁移审计):                         */
/*   - HashStore / ThreatIntelLookup 未接线 → stub   */
/*   - WhiteListStore → config 级白名单(路径/签名/   */
/*     哈希), WkD Exempts 门面由上层编排接入         */
/*   - 并行扫描(实为串行) → 保留串行语义             */
/*                                                  */
/*  依赖 (WkD 底座):                                 */
/*   Common\Utils (UtHexEncode)                     */
/*   Common\BCrypUtils (CoComputeFileSha256)         */
/*   IOC\Signature\SignatureVerifier (IocVerifySignature) */
/**************************************************/

#include "RegistryInternal.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <wchar.h>
#include <string.h>
#include <math.h>

#include <winsvc.h>
#include <taskschd.h>
#include <wbemidl.h>

#include "../Common/Utils.h"
#include "../Common/BCrypUtils.h"
#include "../IOC/IocTypes.h"
#include "../IOC/Signature/SignatureVerifier.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "wbemuuid.lib")

/* ==================================================
 * 引擎私有常量
 * ================================================== */
#define PD_RAW_COMMAND_CAP            (32 * 1024)          /* kMaxRawCommandChars */
#define PD_MULTI_SZ_CAP               1024                 /* kMaxMultiStringEntries */
#define PD_BASE64_INPUT_CAP           (1 * 1024 * 1024)    /* kMaxBase64InputChars */
#define PD_BASE64_DECODED_CAP         (2 * 1024 * 1024)    /* kMaxBase64DecodedBytes */
#define PD_EXPANDED_PATH_CAP          32767                /* kMaxExpandedPathChars */
#define PD_TASK_RECURSION_CAP         16                   /* kMaxTaskRecursionDepth */
#define PD_ARGUMENT_CAP               (32 * 1024)          /* kMaxArgumentChars */
#define PD_LOG_FIELD_CAP              1024                 /* kMaxLogFieldChars */

#define PD_ENTROPY_SAMPLE_SIZE        65536                /* 熵采样前 64KB */
#define PD_HASH_MAX_FILE_SIZE         (512ULL * 1024 * 1024)

#define PD_TARGET_CACHE_SLOTS         48                   /* 目标解析缓存槽 */
#define PD_SIG_CACHE_SLOTS            64                   /* 签名缓存槽 */
#define PD_TASK_MAX_ACTIONS           4
#define PD_TASK_MAX_TRIGGERS          4

#define PD_DEFAULT_TIMEOUT_MS         300000
#define PD_FORENSIC_TIMEOUT_MS        600000

/* ==================================================
 * 引擎私有类型
 * ================================================== */

/* 持久化位置表项 (SS PersistenceLocation 迁移) */
typedef struct _PD_LOCATION {
    WKD_REG_PERSISTENCE_TYPE Type;
    HKEY                     Hive;
    PCWSTR                   SubKey;
    PCWSTR                   ValueName;     /* NULL = 枚举全部值 */
    BOOLEAN                  Critical;
    PCSTR                    Mitre;
} PD_LOCATION, * PPD_LOCATION;

/* 回调槽 (WKD_PD_MAX_CALLBACKS = 16) */
typedef struct _PD_CALLBACK_SLOT {
    ULONG     Id;
    BOOLEAN   InUse;
    PVOID     Callback;
    PVOID     Context;
} PD_CALLBACK_SLOT, * PPD_CALLBACK_SLOT;

/* 目标解析缓存槽 */
typedef struct _PD_TARGET_CACHE_ENTRY {
    BOOLEAN              InUse;
    WCHAR                Command[WKD_PD_MAX_CMD_BUFFER];
    WKD_PERSISTENCE_TARGET Target;
} PD_TARGET_CACHE_ENTRY, * PPD_TARGET_CACHE_ENTRY;

/* 签名缓存槽 */
typedef struct _PD_SIG_CACHE_ENTRY {
    BOOLEAN InUse;
    WCHAR   Path[WKD_REG_MAX_PATH_CHARS];
    WKD_REG_SIGNATURE_STATUS Status;
} PD_SIG_CACHE_ENTRY, * PPD_SIG_CACHE_ENTRY;

/* 计划任务动作内部枚举 (WOW64 COM 预取) */
typedef struct _PD_TASK_ACTION_RAW {
    WCHAR Type[32];
    WCHAR Path[WKD_REG_MAX_PATH_CHARS];
    WCHAR Arguments[WKD_PD_MAX_CMD_BUFFER];
    WCHAR WorkingDirectory[WKD_REG_MAX_PATH_CHARS];
} PD_TASK_ACTION_RAW, * PPD_TASK_ACTION_RAW;

typedef struct _PD_TASK_TRIGGER_RAW {
    WCHAR   Type[32];
    WCHAR   Details[WKD_REG_MAX_PATH_CHARS];
    BOOLEAN Enabled;
} PD_TASK_TRIGGER_RAW, * PPD_TASK_TRIGGER_RAW;

/* 引擎全局上下文 (PIMPL → 模块全局实例) */
typedef struct _WKD_PD_CONTEXT {
    /* 锁 */
    SRWLOCK          ConfigLock;      /* 配置/状态 */
    SRWLOCK          CacheLock;       /* 缓存 */
    SRWLOCK          CallbackLock;    /* 回调表 */
    CRITICAL_SECTION ScanMutex;       /* 扫描互斥 (串行) */

    /* 状态 */
    volatile LONG    Initialized;
    volatile LONG    Scanning;
    volatile LONG    CancelRequested;
    volatile LONG    ComInitialized;

    /* 配置与统计 */
    WKD_PERSISTENCE_CONFIG Config;
    WKD_PERSISTENCE_STATS  Stats;

    /* 独立计数 (SS 同类计数分离, 防回调 ID 与告警 ID 别名) */
    volatile LONG64  NextCallbackId;
    volatile LONG64  NextAlertId;

    /* 回调表 */
    PD_CALLBACK_SLOT ProgressCallbacks[WKD_PD_MAX_CALLBACKS];
    PD_CALLBACK_SLOT EntryCallbacks[WKD_PD_MAX_CALLBACKS];
    PD_CALLBACK_SLOT AlertCallbacks[WKD_PD_MAX_CALLBACKS];

    /* 缓存 */
    PD_TARGET_CACHE_ENTRY TargetCache[PD_TARGET_CACHE_SLOTS];
    ULONG                 TargetCacheCount;
    PD_SIG_CACHE_ENTRY    SignatureCache[PD_SIG_CACHE_SLOTS];
    ULONG                 SignatureCacheCount;
} WKD_PD_CONTEXT, * PWKD_PD_CONTEXT;

static WKD_PD_CONTEXT g_Pd = { 0 };

/* ==================================================
 * 静态工具函数 (匿名命名空间辅助集)
 * ================================================== */

/* 日志输出 (开发排障: OutputDebugStringW; 事件面经
 * Notify 回调由上层编排; 生产接入 LogManager 由编排层完成) */
static
VOID PdDbgPrint(_In_ PCWSTR Format, ...) {
    WCHAR buf[512];
    va_list args;
    va_start(args, Format);
    (VOID)wvsprintfW(buf, Format, args);
    va_end(args);
    OutputDebugStringW(buf);
}

static
ULONG PdWcsLen(_In_ PCWSTR S) {
    return (S != NULL) ? (ULONG)wcslen(S) : 0;
}

static
BOOLEAN PdWcsEmpty(_In_ PCWSTR S) {
    return (S == NULL || S[0] == L'\0');
}

static
VOID PdWcsCopy(_Inout_ PWSTR Dst, _In_ ULONG DstCch, _In_ PCWSTR Src) {
    if (Dst == NULL || DstCch == 0) return;
    if (Src == NULL) { Dst[0] = L'\0'; return; }
    wcsncpy_s(Dst, DstCch, Src, _TRUNCATE);
}

static
VOID PdWcsCopyN(_Inout_ PWSTR Dst, _In_ ULONG DstCch, _In_ PCWSTR Src, _In_ ULONG MaxLen) {
    if (Dst == NULL || DstCch == 0) return;
    if (Src == NULL) { Dst[0] = L'\0'; return; }
    ULONG n = (ULONG)wcslen(Src);
    if (n > MaxLen) n = MaxLen;
    if (n >= DstCch) n = DstCch - 1;
    wcsncpy_s(Dst, DstCch, Src, n);
    Dst[n] = L'\0';
}

/* 宽→窄 (UTF-8, ToNarrow 日志/导出面) */
static
VOID PdToNarrowUtf8(_In_ PCWSTR Wide, _Out_ PCHAR Narrow, _In_ ULONG NarrowCch) {
    if (Wide == NULL || Narrow == NULL || NarrowCch == 0) return;
    (VOID)WideCharToMultiByte(CP_UTF8, 0, Wide, -1, Narrow, (INT)NarrowCch, NULL, NULL);
    Narrow[NarrowCch - 1] = '\0';
}

/* 小写副本 (原地转小写, 简化; 调用方需已深拷贝) */
static
VOID PdWcsToLower(_Inout_ PWSTR S) {
    if (S == NULL) return;
    (VOID)_wcslwr_s(S, wcslen(S) + 1);
}

static
VOID PdWcsToUpper(_Inout_ PWSTR S) {
    if (S == NULL) return;
    for (PWSTR p = S; *p; ++p) {
        if (*p >= L'a' && *p <= L'z') *p -= (L'a' - L'A');
    }
}

static
BOOLEAN PdWcsIEquals(_In_ PCWSTR A, _In_ PCWSTR B) {
    if (A == NULL || B == NULL) return (A == B);
    return (_wcsicmp(A, B) == 0);
}

static
BOOLEAN PdWcsStartsWith(_In_ PCWSTR S, _In_ PCWSTR Prefix) {
    if (S == NULL || Prefix == NULL) return FALSE;
    return (wcsncmp(S, Prefix, wcslen(Prefix)) == 0);
}

static
BOOLEAN PdWcsIContains(_In_ PCWSTR Haystack, _In_ PCWSTR Needle) {
    if (Haystack == NULL || Needle == NULL || Needle[0] == L'\0') return FALSE;
    /* 大小写不敏感包含: 小写拷贝后 wcsstr */
    WCHAR lower[WKD_REG_MAX_PATH_CHARS * 2 + 1];
    WCHAR lowerN[WKD_REG_MAX_NAME_CHARS * 2 + 1];
    ULONG hl = PdWcsLen(Haystack);
    ULONG nl = PdWcsLen(Needle);
    if (hl == 0 || nl == 0) return FALSE;
    if (hl > WKD_REG_MAX_PATH_CHARS * 2 || nl > WKD_REG_MAX_NAME_CHARS * 2) {
        /* 超长回退: 逐段 wcsnicmp 近似 (罕见) */
        return (wcsstr(Haystack, Needle) != NULL);
    }
    wcsncpy_s(lower, _countof(lower), Haystack, _TRUNCATE);
    wcsncpy_s(lowerN, _countof(lowerN), Needle, _TRUNCATE);
    PdWcsToLower(lower);
    PdWcsToLower(lowerN);
    return (wcsstr(lower, lowerN) != NULL);
}

static
VOID PdWcsTrim(_In_ PCWSTR Src, _Out_ PWSTR Dst, _In_ ULONG DstCch) {
    if (Src == NULL || Dst == NULL || DstCch == 0) return;
    PCWSTR begin = Src;
    PCWSTR end = Src + wcslen(Src);
    while (begin < end && (*begin == L' ' || *begin == L'\t')) begin++;
    while (end > begin && (*(end - 1) == L' ' || *(end - 1) == L'\t')) end--;
    ULONG len = (ULONG)(end - begin);
    if (len >= DstCch) len = DstCch - 1;
    wcsncpy_s(Dst, DstCch, begin, len);
    Dst[len] = L'\0';
}

/* ==================================================
 * 日志消毒 (SS SanitizeForLog 迁移; 宽串→UTF8 窄 + 
 * 控制字符替换; 防日志注入)
 * ================================================== */
static
VOID PdSanitizeForLogW(_In_ PCWSTR Wide, _Out_ PCHAR Out, _In_ ULONG OutCch) {
    CHAR narrow[PD_LOG_FIELD_CAP + 32];
    WCHAR temp[PD_LOG_FIELD_CAP + 32];
    if (Out == NULL || OutCch == 0) return;

    PdWcsCopyN(temp, _countof(temp) - 8, Wide, PD_LOG_FIELD_CAP);
    if (PdWcsLen(temp) >= PD_LOG_FIELD_CAP) {
        wcscat_s(temp, _countof(temp), L"<truncated>");
    }
    PdToNarrowUtf8(temp, narrow, sizeof(narrow));

    ULONG outIdx = 0;
    for (ULONG i = 0; narrow[i] != '\0' && outIdx + 1 < OutCch; i++) {
        UCHAR uc = (UCHAR)narrow[i];
        if (uc < 0x20 || uc == 0x7F) {
            Out[outIdx++] = '?';
        } else {
            Out[outIdx++] = narrow[i];
        }
    }
    Out[outIdx] = '\0';
}

/* ==================================================
 * 环境变量安全展开 (SS ExpandEnvVarsSafe 迁移;
 * 动态缓冲, 硬上限 kMaxExpandedPathChars; 防止
 * %ENV% 路径遮蔽绕过可疑路径启发)
 * ================================================== */
static
BOOLEAN PdExpandEnvVarsSafe(_In_ PCWSTR Input, _Out_ PWSTR Out, _In_ ULONG OutCch) {
    DWORD required;
    DWORD written;

    if (Out == NULL || OutCch == 0) return FALSE;
    if (PdWcsEmpty(Input)) { Out[0] = L'\0'; return TRUE; }

    /* 无 '%' 直接拷贝 */
    if (wcschr(Input, L'%') == NULL) {
        PdWcsCopy(Out, OutCch, Input);
        return TRUE;
    }

    required = ExpandEnvironmentStringsW(Input, NULL, 0);
    if (required == 0 || required > PD_EXPANDED_PATH_CAP) {
        PdWcsCopy(Out, OutCch, Input);
        return TRUE;
    }
    if (required > OutCch) {
        /* 调用方缓冲不足: 回退原文 (前缀裁剪风险已由上层边界控制) */
        PdWcsCopy(Out, OutCch, Input);
        return TRUE;
    }

    written = ExpandEnvironmentStringsW(Input, Out, required);
    if (written == 0 || written > required) {
        PdWcsCopy(Out, OutCch, Input);
        return TRUE;
    }
    return TRUE;
}

/* ==================================================
 * 短路径 → 长路径 (SS NormalizeLongPath 迁移)
 * ================================================== */
static
VOID PdNormalizeLongPath(_In_ PCWSTR Input, _Out_ PWSTR Out, _In_ ULONG OutCch) {
    DWORD required;

    if (Out == NULL || OutCch == 0) return;
    if (PdWcsEmpty(Input)) { Out[0] = L'\0'; return; }

    required = GetLongPathNameW(Input, NULL, 0);
    if (required == 0 || required > PD_EXPANDED_PATH_CAP) {
        PdWcsCopy(Out, OutCch, Input);
        return;
    }
    if (required > OutCch) {
        PdWcsCopy(Out, OutCch, Input);
        return;
    }

    DWORD written = GetLongPathNameW(Input, Out, required);
    if (written == 0 || written >= required) {
        PdWcsCopy(Out, OutCch, Input);
    }
}

/* ==================================================
 * ADS 保守检测 (SS DetectAlternateDataStream 迁移;
 * 仅文件名分量内的冒号触发, 忽略驱动器/UNC)
 * ================================================== */
static
BOOLEAN PdDetectAlternateDataStream(_In_ PCWSTR Path) {
    ULONG len = PdWcsLen(Path);
    ULONG lastSlash;
    ULONG scanFrom;

    if (Path == NULL || len < 4) return FALSE;

    lastSlash = 0;
    for (ULONG i = 0; i < len; i++) {
        if (Path[i] == L'\\' || Path[i] == L'/') lastSlash = i;
    }
    scanFrom = lastSlash + 1;
    for (ULONG i = scanFrom; i < len; i++) {
        if (Path[i] == L':') return TRUE;
    }
    return FALSE;
}

/* ==================================================
 * Shannon 熵 (SS CalculateEntropy 迁移)
 * ================================================== */
static
DOUBLE PdCalculateEntropy(_In_ const BYTE* Data, _In_ ULONG Size) {
    UINT64 freq[256] = { 0 };
    DOUBLE entropy = 0.0;
    DOUBLE dataSize;

    if (Data == NULL || Size == 0) return 0.0;

    for (ULONG i = 0; i < Size; i++) freq[Data[i]]++;

    dataSize = (DOUBLE)Size;
    for (ULONG i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            DOUBLE prob = (DOUBLE)freq[i] / dataSize;
            entropy -= prob * (log(prob) / log(2.0));
        }
    }
    return entropy;
}

/* ==================================================
 * 命令→可执行路径提取 (SS ExtractExecutablePath 迁移)
 * 引号/空白/制表/rundll32 逗号/尾部 ":disabled" 处理
 * ================================================== */
static
VOID PdExtractExecutablePath(_In_ PCWSTR CommandLine, _Out_ PWSTR Out, _In_ ULONG OutCch) {
    WCHAR trimmed[WKD_PD_MAX_CMD_BUFFER + 1];
    ULONG len;

    Out[0] = L'\0';
    if (CommandLine == NULL) return;
    if (PdWcsLen(CommandLine) >= _countof(trimmed) - 1) return;

    PdWcsTrim(CommandLine, trimmed, _countof(trimmed));
    if (trimmed[0] == L'\0') return;

    len = PdWcsLen(trimmed);

    if (trimmed[0] == L'"') {
        PCWSTR endQuote = wcschr(trimmed + 1, L'"');
        if (endQuote != NULL) {
            PdWcsCopyN(Out, OutCch, trimmed + 1, (ULONG)(endQuote - (trimmed + 1)));
        } else {
            PdWcsCopy(Out, OutCch, trimmed + 1);
        }
        return;
    }

    /* 未引号: 首个空白/制表/逗号/NUL 终止 */
    for (ULONG i = 0; i < len; i++) {
        WCHAR c = trimmed[i];
        if (c == L' ' || c == L'\t' || c == L',' || c == L'\0') {
            PdWcsCopyN(Out, OutCch, trimmed, i);
            return;
        }
    }
    PdWcsCopy(Out, OutCch, trimmed);
}

/* ==================================================
 * 可疑路径判定 (SS IsSuspiciousPath 迁移;
 * 规范化消除 ..\ 逃逸; 临时/用户/回收站/公共/
 * ProgramData/可疑扩展名)
 * ================================================== */
static
BOOLEAN PdIsSuspiciousPath(_In_ PCWSTR Path) {
    WCHAR canonical[WKD_REG_MAX_PATH_CHARS * 2 + 1];
    WCHAR lower[WKD_REG_MAX_PATH_CHARS * 2 + 1];
    WCHAR ext[16];

    if (PdWcsEmpty(Path)) return FALSE;

    /* 词法规范化 (GetFullPathNameW 消除 ../; 不完全等价
     * C++ std::filesystem::weakly_canonical 的符号链接解析, 对 ..\ 逃逸检测足够) */
    DWORD n = GetFullPathNameW(Path, _countof(canonical), canonical, NULL);
    if (n == 0 || n >= _countof(canonical)) {
        PdWcsCopy(canonical, _countof(canonical), Path);
    }

    wcsncpy_s(lower, _countof(lower), canonical, _TRUNCATE);
    PdWcsToLower(lower);

    if (wcsstr(lower, L"\\temp\\") != NULL ||
        wcsstr(lower, L"\\tmp\\") != NULL ||
        wcsstr(lower, L"\\appdata\\local\\temp\\") != NULL) {
        return TRUE;
    }

    if (wcsstr(lower, L"\\appdata\\roaming\\") != NULL &&
        wcsstr(lower, L"\\microsoft\\") == NULL) {
        return TRUE;
    }

    if (wcsstr(lower, L"\\$recycle.bin\\") != NULL) {
        return TRUE;
    }

    if (wcsstr(lower, L"\\public\\") != NULL) {
        return TRUE;
    }

    if (wcsstr(lower, L"\\programdata\\") != NULL &&
        wcsstr(lower, L"\\programdata\\microsoft\\") == NULL) {
        return TRUE;
    }

    /* 可疑扩展名 */
    PdWcsCopy(ext, _countof(ext), L"");
    {
        ULONG l = PdWcsLen(lower);
        for (ULONG i = l; i > 0; i--) {
            if (lower[i - 1] == L'.') {
                PdWcsCopyN(ext, _countof(ext), lower + i - 1, 12);
                break;
            }
            if (lower[i - 1] == L'\\') break;
        }
    }
    if (PdWcsIEquals(ext, L".tmp") || PdWcsIEquals(ext, L".temp") ||
        PdWcsIEquals(ext, L".dat") || PdWcsIEquals(ext, L".bin")) {
        return TRUE;
    }

    return FALSE;
}

/* MITRE 技术映射 (SS GetMITRETechnique 迁移;
 * 依赖下方 g_PdLocations 位置表, 定义于库表之后) */

/* ==================================================
 * ═══ 持久化位置数据库 ═══
 * (SS PERSISTENCE_LOCATIONS 全量 39 项迁移;
 *  关键项 critical=true)
 * ================================================== */
static const PD_LOCATION g_PdLocations[] = {
    /* Run Keys (T1547.001) */
    { WkdRegPersist_RunKey,          HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",                          L"", TRUE,  "T1547.001" },
    { WkdRegPersist_RunKey,          HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",                          L"", TRUE,  "T1547.001" },
    { WkdRegPersist_RunKeyOnce,      HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",                      L"", TRUE,  "T1547.001" },
    { WkdRegPersist_RunKeyOnce,      HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",                      L"", TRUE,  "T1547.001" },
    { WkdRegPersist_RunServices,     HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",                  L"", FALSE, "T1547.001" },
    { WkdRegPersist_RunServicesOnce, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",              L"", FALSE, "T1547.001" },
    { WkdRegPersist_PoliciesRun,     HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",      L"", TRUE,  "T1547.001" },
    { WkdRegPersist_PoliciesRun,     HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",      L"", TRUE,  "T1547.001" },
    { WkdRegPersist_ExplorerRun,     HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",                   L"run", FALSE, "T1547.001" },

    /* Winlogon (T1547.004) */
    { WkdRegPersist_WinlogonShell,   HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",                  L"Shell",    TRUE,  "T1547.004" },
    { WkdRegPersist_WinlogonUserinit,HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",                  L"Userinit", TRUE,  "T1547.004" },
    { WkdRegPersist_WinlogonTaskman, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",                  L"Taskman",  FALSE, "T1547.004" },
    { WkdRegPersist_WinlogonSystem,  HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",                  L"System",   FALSE, "T1547.004" },
    { WkdRegPersist_WinlogonVMApplet,HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",                  L"VMApplet", FALSE, "T1547.004" },

    /* Image File Execution Options (T1546.012) */
    { WkdRegPersist_IFeoDebugger,    HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", L"", TRUE,  "T1546.012" },
    { WkdRegPersist_IFeoGlobalFlag,  HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", L"GlobalFlag", FALSE, "T1546.012" },
    { WkdRegPersist_SilentProcessExit, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",       L"", FALSE, "T1546.012" },

    /* DLL Injection (T1574.001, T1547.008) */
    { WkdRegPersist_AppInitDlls,     HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",                   L"AppInit_DLLs", TRUE,  "T1574.001" },
    { WkdRegPersist_LoadAppInit,     HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",                   L"LoadAppInit_DLLs", TRUE, "T1574.001" },
    { WkdRegPersist_AppCertDlls,     HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",                        L"AppCertDlls", TRUE, "T1547.008" },
    { WkdRegPersist_PrintMonitors,   HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors",                        L"", FALSE, "T1547.010" },
    { WkdRegPersist_LsaAuthentication, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa",                                  L"Authentication Packages", TRUE, "T1547.002" },
    { WkdRegPersist_LsaNotification, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa",                                     L"Notification Packages", TRUE, "T1547.002" },
    { WkdRegPersist_LsaSecurity,     HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa",                                     L"Security Packages", TRUE, "T1547.002" },

    /* Boot/Session (T1547.001) */
    { WkdRegPersist_BootExecute,     HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",                        L"BootExecute", TRUE, "T1547.001" },
    { WkdRegPersist_SetupExecute,    HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",                        L"SetupExecute", FALSE, "T1547.001" },
    { WkdRegPersist_KnownDlls,       HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",             L"", FALSE, "T1574.001" },

    /* Shell Extensions (T1546.015) */
    { WkdRegPersist_ShellServiceObjects, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad", L"", FALSE, "T1546.015" },
    { WkdRegPersist_ShellIconOverlay, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers", L"", FALSE, "T1546.015" },
    { WkdRegPersist_ContextMenuHandlers, HKEY_CLASSES_ROOT, L"*\\shellex\\ContextMenuHandlers",                                            L"", FALSE, "T1546.015" },

    /* Active Setup (T1547.014) */
    { WkdRegPersist_ActiveSetup,     HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components",                    L"", TRUE, "T1547.014" },

    /* Browser (T1176) */
    { WkdRegPersist_BrowserHelperObject, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", L"", FALSE, "T1176" },
    { WkdRegPersist_BrowserHelperObject, HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", L"", FALSE, "T1176" },

    /* Office (T1137) */
    { WkdRegPersist_OfficeAddins,    HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Office\\*\\Addins",                                      L"", FALSE, "T1137" },
    { WkdRegPersist_OfficeStartup,   HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Office\\*\\*\\Options",                                  L"OPEN", FALSE, "T1137.001" },

    /* Other */
    { WkdRegPersist_Screensaver,     HKEY_CURRENT_USER,  L"Control Panel\\Desktop",                                                      L"SCRNSAVE.EXE", FALSE, "T1546.002" },
    { WkdRegPersist_NetshHelper,     HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\NetSh",                                                   L"", FALSE, "T1546.007" },
    { WkdRegPersist_SecurityProviders, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders",                    L"SecurityProviders", FALSE, "T1547.002" },
    { WkdRegPersist_TimeProvider,    HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders",                L"", FALSE, "T1547.003" },
};

#define PD_LOCATION_COUNT (sizeof(g_PdLocations)/sizeof(g_PdLocations[0]))

/* ==================================================
 * MITRE 技术映射 (SS GetMITRETechnique 迁移)
 * ================================================== */
static
PCSTR PdGetMitreTechnique(_In_ WKD_REG_PERSISTENCE_TYPE Type) {
    for (ULONG i = 0; i < PD_LOCATION_COUNT; i++) {
        if (g_PdLocations[i].Type == Type && g_PdLocations[i].Mitre != NULL &&
            g_PdLocations[i].Mitre[0] != '\0') {
            return g_PdLocations[i].Mitre;
        }
    }
    return "T1547";
}

/* ==================================================
 * 内部函数前向声明 (C 风格, 由实现处定义)
 * ================================================== */
static WKD_PERSISTENCE_TARGET PdResolveTargetImpl(PCWSTR Command);
static NTSTATUS PdScanRegistryLocation(const PD_LOCATION* Location, WKD_REG_SCAN_SCOPE Scope,
                                       PWKD_PERSISTENCE_ENTRY Out, ULONG OutCapacity,
                                       PULONG EntryCount);
static WKD_REG_RISK_LEVEL PdAssessRisk(PCWKD_PERSISTENCE_ENTRY Entry);
static UCHAR PdCalculateRiskScore(PCWKD_PERSISTENCE_ENTRY Entry);
static BOOLEAN PdIsWhitelisted(PCWKD_PERSISTENCE_ENTRY Entry);
static WKD_REG_PERSISTENCE_TYPE PdIsPersistenceLocationImpl(PCWSTR KeyPath);
static VOID PdGenerateRealTimeAlert(PCWSTR KeyPath, PCWSTR ValueName, PCWSTR Data,
                                    PCWKD_REALTIME_ANALYSIS Analysis);

/* ==================================================
 * 计数器辅助 (Interlocked 原子)
 * ================================================== */
static
LONG64 PdAtomicIncrement(_Inout_ volatile LONG64* Value) {
    return InterlockedIncrement64(Value);
}

/* ==================================================
 * ═══ 签署验证 / 哈希 / 熵 (目标富化) ═══
 * ================================================== */

static
VOID PdVerifyTargetSignature(_Inout_ PWKD_PERSISTENCE_TARGET Target) {
    IOC_SCAN_RESULT result;
    memset(&result, 0, sizeof(result));

    if (PdWcsEmpty(Target->Path)) {
        Target->SignatureStatus = WkdRegSig_Unknown;
        return;
    }

    /* IOC 统一签名验证 (WinTrust + catalog fallback + 吊销门控由
     * SignatureVerifier 内部管理; 与 SS PEFileSignatureVerifier 等价) */
    NTSTATUS status = IocVerifySignature(Target->Path, &result);
    if (!NT_SUCCESS(status)) {
        Target->SignatureStatus = WkdRegSig_Unknown;
        return;
    }

    /* 证书状态映射 */
    switch (result.CertStatus) {
        case DefCertStatus_Valid:        Target->SignatureStatus = WkdRegSig_SignedValid; break;
        case DefCertStatus_ValidCatalog: Target->SignatureStatus = WkdRegSig_SignedCatalog; break;
        case DefCertStatus_Revoked:      Target->SignatureStatus = WkdRegSig_SignedRevoked; break;
        case DefCertStatus_Expired:      Target->SignatureStatus = WkdRegSig_SignedExpired; break;
        case DefCertStatus_Invalid:
        case DefCertStatus_UntrustedRoot: Target->SignatureStatus = WkdRegSig_SignedInvalid; break;
        case DefCertStatus_Unsigned:     Target->SignatureStatus = WkdRegSig_NotSigned; break;
        default:                         Target->SignatureStatus = WkdRegSig_Unknown; break;
    }

    PdWcsCopy(Target->SignerName, _countof(Target->SignerName), result.SignerName);
    PdWcsCopy(Target->IssuerName, _countof(Target->IssuerName), result.IssuerName);
    Target->IsTrusted = result.IsTrustedStrict;
    Target->IsMicrosoftSigned = IocScan_IsMicrosoftSigned(&result);

    InterlockedIncrement64(&g_Pd.Stats.SignaturesVerified);
}

static
VOID PdComputeTargetHash(_Inout_ PWKD_PERSISTENCE_TARGET Target) {
    DEF_SHA256_HASH hash;

    if (PdWcsEmpty(Target->Path)) return;

    NTSTATUS status = CoComputeFileSha256(Target->Path, &hash);
    if (NT_SUCCESS(status)) {
        memcpy(Target->Sha256, hash.Data, 32);
        (VOID)UtHexEncode(hash.Data, 32, Target->Sha256Hex,
                          (ULONG)_countof(Target->Sha256Hex), FALSE);
    }
    InterlockedIncrement64(&g_Pd.Stats.HashesChecked);
}

static
VOID PdAnalyzeTargetEntropy(_Inout_ PWKD_PERSISTENCE_TARGET Target) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BYTE buffer[PD_ENTROPY_SAMPLE_SIZE];
    DWORD bytesRead = 0;

    if (PdWcsEmpty(Target->Path)) return;

    hFile = CreateFileW(Target->Path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    if (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        Target->Entropy = PdCalculateEntropy(buffer, bytesRead);
        Target->IsPacked = (Target->Entropy > WKD_REG_SUSPICIOUS_ENTROPY);
    }
    CloseHandle(hFile);
}

/* ==================================================
 * 白名单判定 (SS IsWhitelisted 迁移)
 * 路径前缀匹配(小写规范) → 签名者(忽略大小写) → 哈希(hex 折叠)
 * ================================================== */
static
BOOLEAN PdIsWhitelisted(_In_ PCWKD_PERSISTENCE_ENTRY Entry) {
    WCHAR lowerPath[WKD_REG_MAX_PATH_CHARS * 2 + 1];
    WCHAR lowerWp[WKD_REG_MAX_PATH_CHARS * 2 + 1];

    if (Entry == NULL) return FALSE;

    /* 路径前缀匹配 */
    if (!PdWcsEmpty(Entry->Target.Path)) {
        wcsncpy_s(lowerPath, _countof(lowerPath), Entry->Target.Path, _TRUNCATE);
        PdWcsToLower(lowerPath);

        for (ULONG i = 0; i < WKD_REG_MAX_PATH_CHARS && i < 8; i++) {
            if (g_Pd.Config.WhitelistedPaths[i][0] == L'\0') continue;
            wcsncpy_s(lowerWp, _countof(lowerWp), g_Pd.Config.WhitelistedPaths[i], _TRUNCATE);
            PdWcsToLower(lowerWp);
            ULONG wpl = PdWcsLen(lowerWp);
            if (wpl > 0 && lowerWp[wpl - 1] != L'\\' && lowerWp[wpl - 1] != L'/') {
                if (wpl < _countof(lowerWp) - 1) { lowerWp[wpl] = L'\\'; lowerWp[wpl + 1] = L'\0'; }
            }
            wpl = PdWcsLen(lowerWp);
            if (PdWcsLen(lowerPath) >= wpl && wcsncmp(lowerPath, lowerWp, wpl) == 0) {
                return TRUE;
            }
        }
    }

    /* 签名者白名单 (IEquals) */
    if (!PdWcsEmpty(Entry->Target.SignerName)) {
        for (ULONG i = 0; i < 8; i++) {
            if (g_Pd.Config.WhitelistedSigners[i][0] == L'\0') continue;
            if (PdWcsIEquals(Entry->Target.SignerName, g_Pd.Config.WhitelistedSigners[i])) {
                return TRUE;
            }
        }
    }

    /* 哈希白名单 — hex 大小写折叠比较 */
    if (Entry->Target.Sha256Hex[0] != '\0') {
        for (ULONG i = 0; i < 8; i++) {
            if (g_Pd.Config.WhitelistedHashes[i][0] == '\0') continue;
            if (_stricmp(Entry->Target.Sha256Hex, g_Pd.Config.WhitelistedHashes[i]) == 0) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

/* ==================================================
 * 哈希信誉 / 威胁情报富化 (SS stub 迁移)
 * HashStore / ThreatIntel 未接线 → 保留空实现;
 * config 级 known-bad 判定由上层 Exempts/情报库注入
 * ================================================== */
static
VOID PdEnrichWithHashLookup(_Inout_ PWKD_PERSISTENCE_ENTRY Entry) {
    (VOID)Entry;
}

static
VOID PdEnrichWithThreatIntel(_Inout_ PWKD_PERSISTENCE_ENTRY Entry) {
    (VOID)Entry;
}

/* ==================================================
 * LOLBin 判定 (SS IsLOLBin 迁移)
 * ================================================== */
static
BOOLEAN PdIsLolBin(_In_ PCWSTR Path) {
    static const PCWSTR kLolBins[] = {
        L"rundll32.exe", L"regsvr32.exe", L"mshta.exe", L"powershell.exe",
        L"cmd.exe", L"certutil.exe", L"bitsadmin.exe", L"scrcons.exe",
        L"wmic.exe", L"msiexec.exe", L"cscript.exe", L"wscript.exe"
    };
    WCHAR lower[WKD_REG_MAX_PATH_CHARS];

    if (PdWcsEmpty(Path)) return FALSE;
    PdWcsCopyN(lower, _countof(lower), Path, _countof(lower) - 1);
    PdWcsToLower(lower);

    for (ULONG i = 0; i < _countof(kLolBins); i++) {
        if (wcsstr(lower, kLolBins[i]) != NULL) return TRUE;
    }
    return FALSE;
}

/* ==================================================
 * 目标解析 (SS ResolveTargetImpl 迁移)
 * 缓存 → 路径提取 → 环境变量展开 → 短路径规范化 →
 * 参数提取 → 文件元数据 → 类型/路径分类 → 隐藏/ADS →
 * 签名/哈希/熵
 * ================================================== */
static
WKD_PERSISTENCE_TARGET PdResolveTargetImpl(PCWSTR Command) {
    WKD_PERSISTENCE_TARGET target;
    WCHAR rawPath[WKD_REG_MAX_PATH_CHARS];
    WCHAR expanded[WKD_REG_MAX_PATH_CHARS];
    WCHAR trimmedCmd[WKD_PD_MAX_CMD_BUFFER + 1];
    WCHAR lowerPath[WKD_REG_MAX_PATH_CHARS * 2 + 1];
    WCHAR ext[16];
    WIN32_FILE_ATTRIBUTE_DATA fad;
    ULONG i;

    memset(&target, 0, sizeof(target));

    if (PdWcsEmpty(Command)) return target;
    PdWcsCopy(target.OriginalPath, _countof(target.OriginalPath), Command);

    /* 缓存命中 */
    if (g_Pd.Config.UseCache) {
        AcquireSRWLockShared(&g_Pd.CacheLock);
        for (i = 0; i < g_Pd.TargetCacheCount; i++) {
            if (g_Pd.TargetCache[i].InUse &&
                wcscmp(g_Pd.TargetCache[i].Command, Command) == 0) {
                target = g_Pd.TargetCache[i].Target;
                InterlockedIncrement64(&g_Pd.Stats.CacheHits);
                ReleaseSRWLockShared(&g_Pd.CacheLock);
                return target;
            }
        }
        ReleaseSRWLockShared(&g_Pd.CacheLock);
    }

    /* 路径提取 */
    PdExtractExecutablePath(Command, rawPath, _countof(rawPath));
    if (rawPath[0] == L'\0') return target;

    /* 环境变量展开 + 短路径规范化 */
    PdExpandEnvVarsSafe(rawPath, expanded, _countof(expanded));
    PdNormalizeLongPath(expanded, target.Path, _countof(target.Path));

    /* 参数提取 */
    PdWcsTrim(Command, trimmedCmd, _countof(trimmedCmd));
    target.Arguments[0] = L'\0';
    if (trimmedCmd[0] == L'"') {
        PCWSTR endQuote = wcschr(trimmedCmd + 1, L'"');
        if (endQuote != NULL && endQuote[1] != L'\0') {
            PdWcsTrim(endQuote + 1, target.Arguments, _countof(target.Arguments));
        }
    } else {
        PCWSTR spacePos = wcschr(trimmedCmd, L' ');
        if (spacePos != NULL) {
            PdWcsTrim(spacePos + 1, target.Arguments, _countof(target.Arguments));
        }
    }

    /* 文件存在性与元数据 (fs::exists/file_size/last_write_time 迁移) */
    target.Exists = FALSE;
    if (GetFileAttributesExW(target.Path, GetFileExInfoStandard, &fad)) {
        target.Exists = TRUE;
        target.FileSize = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
        target.CreatedTime = ((ULONGLONG)fad.ftCreationTime.dwHighDateTime << 32) |
                             fad.ftCreationTime.dwLowDateTime;
        target.ModifiedTime = ((ULONGLONG)fad.ftLastWriteTime.dwHighDateTime << 32) |
                              fad.ftLastWriteTime.dwLowDateTime;

        /* 文件类型判定 (扩展名, 对齐 SS) */
        ext[0] = L'\0';
        {
            ULONG pl = PdWcsLen(target.Path);
            for (ULONG j = pl; j > 0; j--) {
                if (target.Path[j - 1] == L'.') {
                    PdWcsCopyN(ext, _countof(ext), target.Path + j - 1, 12);
                    break;
                }
                if (target.Path[j - 1] == L'\\' || target.Path[j - 1] == L'/') break;
            }
        }
        if (PdWcsIEquals(ext, L".exe") || PdWcsIEquals(ext, L".com") || PdWcsIEquals(ext, L".scr")) {
            target.IsExecutable = TRUE;
            strcpy_s(target.FileType, sizeof(target.FileType), "PE_Executable");
        } else if (PdWcsIEquals(ext, L".dll") || PdWcsIEquals(ext, L".ocx") || PdWcsIEquals(ext, L".cpl")) {
            target.IsDll = TRUE;
            strcpy_s(target.FileType, sizeof(target.FileType), "PE_DLL");
        } else if (PdWcsIEquals(ext, L".sys")) {
            target.IsDll = TRUE;
            strcpy_s(target.FileType, sizeof(target.FileType), "PE_Driver");
        } else if (PdWcsIEquals(ext, L".ps1") || PdWcsIEquals(ext, L".vbs") ||
                   PdWcsIEquals(ext, L".js") || PdWcsIEquals(ext, L".bat") ||
                   PdWcsIEquals(ext, L".cmd") || PdWcsIEquals(ext, L".wsf") ||
                   PdWcsIEquals(ext, L".hta") || PdWcsIEquals(ext, L".wsh")) {
            target.IsScript = TRUE;
            strcpy_s(target.FileType, sizeof(target.FileType), "Script");
        }

        /* 路径分类 */
        wcsncpy_s(lowerPath, _countof(lowerPath), target.Path, _TRUNCATE);
        PdWcsToLower(lowerPath);
        target.InSystemPath = (wcsstr(lowerPath, L"\\windows\\") != NULL ||
                               wcsstr(lowerPath, L"\\program files") != NULL);
        target.InTempPath = (wcsstr(lowerPath, L"\\temp\\") != NULL ||
                             wcsstr(lowerPath, L"\\tmp\\") != NULL ||
                             wcsstr(lowerPath, L"\\appdata\\local\\temp\\") != NULL);

        /* 隐藏属性 + ADS */
        DWORD attrs = GetFileAttributesW(target.Path);
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            target.IsHidden = (attrs & FILE_ATTRIBUTE_HIDDEN) != 0;
        }
        target.HasAds = PdDetectAlternateDataStream(target.Path);

        /* 签名 / 哈希 / 熵 (按配置门控) */
        if (g_Pd.Config.VerifySignatures && (target.IsExecutable || target.IsDll)) {
            PdVerifyTargetSignature(&target);
        }
        if (g_Pd.Config.CheckHashes && target.FileSize > 0 &&
            target.FileSize < PD_HASH_MAX_FILE_SIZE) {
            PdComputeTargetHash(&target);
        }
        if (target.IsExecutable || target.IsDll) {
            PdAnalyzeTargetEntropy(&target);
        }
    }
    /* 不存在 → 保持 Exists=FALSE (孤儿条目由上层判定) */

    /* 缓存写入 (单条目淘汰, erase(begin)) */
    if (g_Pd.Config.UseCache) {
        AcquireSRWLockExclusive(&g_Pd.CacheLock);
        if (g_Pd.TargetCacheCount >= PD_TARGET_CACHE_SLOTS && g_Pd.TargetCacheCount > 0) {
            /* 淘汰队首 */
            if (g_Pd.TargetCacheCount > 1) {
                memmove(&g_Pd.TargetCache[0], &g_Pd.TargetCache[1],
                        (g_Pd.TargetCacheCount - 1) * sizeof(PD_TARGET_CACHE_ENTRY));
            }
            g_Pd.TargetCacheCount--;
            memset(&g_Pd.TargetCache[g_Pd.TargetCacheCount], 0,
                     sizeof(PD_TARGET_CACHE_ENTRY));
        }
        if (g_Pd.TargetCacheCount < PD_TARGET_CACHE_SLOTS) {
            PD_TARGET_CACHE_ENTRY* slot = &g_Pd.TargetCache[g_Pd.TargetCacheCount];
            memset(slot, 0, sizeof(*slot));
            PdWcsCopyN(slot->Command, _countof(slot->Command), Command, _countof(slot->Command) - 1);
            slot->Target = target;
            slot->InUse = TRUE;
            g_Pd.TargetCacheCount++;
        }
        ReleaseSRWLockExclusive(&g_Pd.CacheLock);
    }

    return target;
}

/* ==================================================
 * 复杂命令解析 (SS ResolveComplexCommandImpl 迁移)
 * rundll32 / regsvr32 / mshta / powershell -EncodedCommand
 * ================================================== */

/* Base64 解码 (宽容: 忽略空白 + 接受缺失 padding;
 * Base64DecodeOptions{ignoreWhitespace, acceptMissingPadding}) */
static
BOOLEAN PdBase64Decode(_In_ PCSTR Encoded, _In_ ULONG EncodedLen,
                       _Out_ PBYTE Out, _In_ ULONG OutCapacity,
                       _Out_ PULONG Written) {
    static const CHAR kTable[256] = {
        /* -1 表示非法; 索引即 ASCII 码 */
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59, 60,61,-1,-1,-1, 0,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6,  7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22, 23,24,25,-1,-1,-1,-1,63,
        -1,26,27,28,29,30,31,32, 33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48, 49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    };
    ULONG outPos = 0;
    ULONG srcPos = 0;
    UCHAR quad[4];
    UCHAR n = 0;

    if (Encoded == NULL || Out == NULL || Written == NULL) return FALSE;
    *Written = 0;

    while (srcPos < EncodedLen) {
        CHAR c = Encoded[srcPos];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { srcPos++; continue; }
        if (c == '=') { srcPos++; break; }   /* padding: 终止 */
        CHAR v = kTable[(UCHAR)c];
        if (v < 0) { srcPos++; continue; }   /* 非法字符跳过 */
        quad[n++] = (UCHAR)v;
        if (n == 4) {
            if (outPos + 3 > OutCapacity) return FALSE;
            Out[outPos++] = (BYTE)((quad[0] << 2) | (quad[1] >> 4));
            Out[outPos++] = (BYTE)((quad[1] << 4) | (quad[2] >> 2));
            Out[outPos++] = (BYTE)((quad[2] << 6) | quad[3]);
            n = 0;
        }
        srcPos++;
    }
    /* 剩余 2/3 码 (缺失 padding) */
    if (n == 2) {
        if (outPos + 1 > OutCapacity) return FALSE;
        Out[outPos++] = (BYTE)((quad[0] << 2) | (quad[1] >> 4));
    } else if (n == 3) {
        if (outPos + 2 > OutCapacity) return FALSE;
        Out[outPos++] = (BYTE)((quad[0] << 2) | (quad[1] >> 4));
        Out[outPos++] = (BYTE)((quad[1] << 4) | (quad[2] >> 2));
    } else if (n == 1) {
        return FALSE;
    }

    *Written = outPos;
    return TRUE;
}

/* 追加目标到数组 (附加目标槽, 边界 4) */
static
VOID PdAppendAdditionalTarget(_Inout_ PWKD_PERSISTENCE_ENTRY Entry,
                              _In_ WKD_PERSISTENCE_TARGET* Target) {
    if (Entry->AdditionalTargetCount >= WKD_PD_MAX_ADDITIONAL_TARGETS) return;
    Entry->AdditionalTargets[Entry->AdditionalTargetCount] = *Target;
    Entry->AdditionalTargetCount++;
}

static
NTSTATUS PdResolveComplexCommandImpl(_In_ PCWSTR Command,
                                     _Out_ WKD_PERSISTENCE_TARGET* Targets,
                                     _In_ ULONG MaxTargets,
                                     _Out_ PULONG TargetCount) {
    WCHAR lowerCmd[WKD_PD_MAX_CMD_BUFFER + 1];
    WCHAR tmpPath[WKD_REG_MAX_PATH_CHARS];
    WCHAR tmpArg[WKD_PD_MAX_CMD_BUFFER + 1];
    WKD_PERSISTENCE_TARGET primary;
    ULONG count = 0;

    if (Targets == NULL || TargetCount == NULL || MaxTargets == 0) return STATUS_INVALID_PARAMETER;
    *TargetCount = 0;
    if (PdWcsEmpty(Command)) return STATUS_SUCCESS;

    /* 1. 主命令解析 */
    primary = PdResolveTargetImpl(Command);
    if (count < MaxTargets) { Targets[count++] = primary; }

    if (PdWcsLen(Command) >= _countof(lowerCmd) - 1) return STATUS_SUCCESS;
    wcscpy_s(lowerCmd, _countof(lowerCmd), Command);
    PdWcsToLower(lowerCmd);

    /* 2. LOLBin 拆解 */
    if (wcsstr(lowerCmd, L"rundll32.exe") != NULL) {
        /* rundll32.exe <dllname>,<entrypoint> <args> */
        PdWcsTrim(primary.Arguments, tmpArg, _countof(tmpArg));
        PCWSTR commaPos = wcschr(tmpArg, L',');
        if (commaPos != NULL) {
            PdWcsCopyN(tmpPath, _countof(tmpPath), tmpArg, (ULONG)(commaPos - tmpArg));
        } else {
            PdWcsCopy(tmpPath, _countof(tmpPath), tmpArg);
        }
        PdWcsTrim(tmpPath, tmpPath, _countof(tmpPath));
        if (tmpPath[0] != L'\0' && count < MaxTargets) {
            WKD_PERSISTENCE_TARGET dllTarget = PdResolveTargetImpl(tmpPath);
            PdWcsCopy(dllTarget.Description, _countof(dllTarget.Description),
                      L"Target DLL loaded via rundll32");
            Targets[count++] = dllTarget;
        }
    } else if (wcsstr(lowerCmd, L"regsvr32.exe") != NULL) {
        /* regsvr32.exe [/u] [/s] [/n] [/i[:cmdline]] <dllname> */
        WCHAR token[WKD_REG_MAX_PATH_CHARS];
        ULONG tokenStart = 0;
        ULONG argLen = PdWcsLen(primary.Arguments);
        for (ULONG pos = 0; pos <= argLen && count < MaxTargets; pos++) {
            if (pos == argLen || primary.Arguments[pos] == L' ') {
                if (pos > tokenStart) {
                    PdWcsCopyN(token, _countof(token), primary.Arguments + tokenStart, pos - tokenStart);
                    if (token[0] != L'/' && token[0] != L'-') {
                        WKD_PERSISTENCE_TARGET dllTarget = PdResolveTargetImpl(token);
                        PdWcsCopy(dllTarget.Description, _countof(dllTarget.Description),
                                  L"Target DLL registered via regsvr32");
                        Targets[count++] = dllTarget;
                    }
                }
                tokenStart = pos + 1;
            }
        }
    } else if (wcsstr(lowerCmd, L"mshta.exe") != NULL) {
        /* mshta.exe <url/path> */
        if (primary.Arguments[0] != L'\0' && count < MaxTargets) {
            WKD_PERSISTENCE_TARGET htaTarget = PdResolveTargetImpl(primary.Arguments);
            PdWcsCopy(htaTarget.Description, _countof(htaTarget.Description),
                      L"HTA/Script target executed via mshta");
            Targets[count++] = htaTarget;
        }
    } else if (wcsstr(lowerCmd, L"cmd.exe") != NULL ||
               wcsstr(lowerCmd, L"powershell.exe") != NULL ||
               wcsstr(lowerCmd, L"pwsh.exe") != NULL) {

        /* PowerShell -EncodedCommand (Base64, UTF-16LE) */
        if (wcsstr(lowerCmd, L"-enc") != NULL || wcsstr(lowerCmd, L"-encodedcommand") != NULL) {
            WCHAR token[WKD_REG_MAX_PATH_CHARS];
            ULONG tokenStart = 0;
            ULONG argLen = PdWcsLen(primary.Arguments);
            for (ULONG pos = 0; pos <= argLen; pos++) {
                if (pos == argLen || primary.Arguments[pos] == L' ') {
                    if (pos > tokenStart) {
                        PdWcsCopyN(token, _countof(token), primary.Arguments + tokenStart, pos - tokenStart);
                        if (PdWcsIEquals(token, L"-enc") || PdWcsIEquals(token, L"-encodedcommand")) {
                            /* 取下一个 token 作为编码载荷 (边界: 先行探测) */
                            ULONG nextStart = pos + 1;
                            ULONG nextEnd = nextStart;
                            while (nextEnd < argLen && primary.Arguments[nextEnd] != L' ') nextEnd++;
                            if (nextEnd > nextStart && count < MaxTargets) {
                                WCHAR encoded[WKD_REG_MAX_PATH_CHARS];
                                PdWcsCopyN(encoded, _countof(encoded),
                                           primary.Arguments + nextStart, nextEnd - nextStart);
                                CHAR narrow[PD_BASE64_INPUT_CAP + 1];
                                ULONG narrowLen = (ULONG)(nextEnd - nextStart);
                                if (narrowLen > PD_BASE64_INPUT_CAP) {
                                    PdDbgPrint(L"[PD] -EncodedCommand exceeds cap; skipping");
                                } else {
                                    for (ULONG k = 0; k < narrowLen; k++) {
                                        narrow[k] = (CHAR)encoded[k];
                                    }
                                    narrow[narrowLen] = '\0';

                                    BYTE* decoded = (BYTE*)malloc(PD_BASE64_DECODED_CAP);
                                    if (decoded != NULL) {
                                        ULONG decodedLen = 0;
                                        if (PdBase64Decode(narrow, narrowLen, decoded,
                                                           PD_BASE64_DECODED_CAP, &decodedLen) &&
                                            decodedLen > 0) {
                                            /* UTF-16LE: 剥离 BOM + 对齐偶数长度 */
                                            ULONG dataLen = decodedLen;
                                            ULONG dataOff = 0;
                                            if (dataLen >= 2 && decoded[0] == 0xFF && decoded[1] == 0xFE) {
                                                dataOff = 2; dataLen -= 2;
                                            }
                                            dataLen -= (dataLen % 2);

                                            WKD_PERSISTENCE_TARGET encTarget;
                                            memset(&encTarget, 0, sizeof(encTarget));
                                            PdWcsCopyN(encTarget.OriginalPath, _countof(encTarget.OriginalPath),
                                                       encoded, _countof(encTarget.OriginalPath) - 1);
                                            PdWcsCopy(encTarget.Path, _countof(encTarget.Path), L"DECODED_SCRIPT");
                                            if (dataLen >= 2 && dataLen / 2 < _countof(encTarget.Arguments)) {
                                                wcsncpy_s(encTarget.Arguments, _countof(encTarget.Arguments),
                                                          (PCWSTR)(decoded + dataOff), dataLen / 2);
                                            }
                                            encTarget.IsScript = TRUE;
                                            PdWcsCopy(encTarget.Description, _countof(encTarget.Description),
                                                      L"De-obfuscated PowerShell command");
                                            Targets[count++] = encTarget;
                                        }
                                        free(decoded);
                                    }
                                }
                            }
                        }
                    }
                    tokenStart = pos + 1;
                    if (pos == argLen) break;
                }
            }
        }
    }

    *TargetCount = count;
    return STATUS_SUCCESS;
}

/* ==================================================
 * ═══ 注册表位置扫描 (SS ScanRegistryLocation 迁移) ═══
 * WOW64 双视图 + (entryName,rawCommand) 去重
 * ================================================== */
static
NTSTATUS PdScanRegistryLocation(_In_ const PD_LOCATION* Location, _In_ WKD_REG_SCAN_SCOPE Scope,
                                _Out_ PWKD_PERSISTENCE_ENTRY Out, _In_ ULONG OutCapacity,
                                _Out_ PULONG EntryCount) {
    WCHAR subKeyPath[WKD_REG_MAX_PATH_CHARS];
    WCHAR dedupA[WKD_PD_MAX_CMD_BUFFER + 1];
    WCHAR dedupB[WKD_PD_MAX_CMD_BUFFER + 1];
    ULONG count = 0;
    ULONG pass;

    (VOID)Scope;
    *EntryCount = 0;

    for (pass = 0; pass < 2; pass++) {
        /* pass 0: WOW64_64KEY; pass 1: WOW64_32KEY */
        REGSAM access = KEY_READ | ((pass == 0) ? KEY_WOW64_64KEY : KEY_WOW64_32KEY);
        HKEY hKey = NULL;
        WCHAR valueName[WKD_REG_MAX_NAME_CHARS];
        BYTE data[WKD_PD_MAX_CMD_BUFFER + 8];
        DWORD valueNameCch = _countof(valueName);
        DWORD dataSize = sizeof(data);
        DWORD valueType = 0;
        LONG lRet;
        DWORD index = 0;

        if (Location->SubKey == NULL) continue;

        /* 位置显示路径: HKLM/HKCU/HKCR */
        PCWSTR hiveName = (Location->Hive == HKEY_LOCAL_MACHINE) ? L"HKLM" :
                          (Location->Hive == HKEY_CURRENT_USER) ? L"HKCU" : L"HKCR";

        lRet = RegOpenKeyExW(Location->Hive, Location->SubKey, 0, access, &hKey);
        if (lRet != ERROR_SUCCESS) continue;

        for (;;) {
            WKD_PERSISTENCE_ENTRY entry;
            WCHAR raw[WKD_PD_MAX_CMD_BUFFER + 1];
            ULONG rawLen = 0;

            valueNameCch = _countof(valueName);
            valueName[0] = L'\0';
            dataSize = sizeof(data);
            valueType = 0;

            lRet = RegEnumValueW(hKey, index, valueName, &valueNameCch, NULL,
                                 &valueType, data, &dataSize);
            if (lRet == ERROR_NO_MORE_ITEMS) break;
            if (lRet != ERROR_SUCCESS) { index++; continue; }
            index++;

            /* 值名过滤 */
            if (!PdWcsEmpty(Location->ValueName) &&
                !PdWcsIEquals(Location->ValueName, valueName)) {
                continue;
            }

            memset(&entry, 0, sizeof(entry));
            entry.Type = Location->Type;
            PdWcsCopyN(entry.EntryName, _countof(entry.EntryName), valueName, _countof(entry.EntryName) - 1);
            wsprintfW(subKeyPath, L"%s\\%s [view=%s]", hiveName, Location->SubKey,
                      (pass == 0) ? L"64" : L"32");
            PdWcsCopyN(entry.Location, _countof(entry.Location), subKeyPath,
                       _countof(entry.Location) - 1);
            entry.IsUserEntry = (Location->Hive == HKEY_CURRENT_USER);
            strcpy_s(entry.MitreTechnique, sizeof(entry.MitreTechnique), Location->Mitre);

            /* 按类型提取命令 (含硬上限) */
            if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
                ULONG len = dataSize / sizeof(WCHAR);
                if (len > 0 && data[len - 1] == 0) len--;
                if (len > PD_RAW_COMMAND_CAP / sizeof(WCHAR)) {
                    len = PD_RAW_COMMAND_CAP / sizeof(WCHAR);
                    PdDbgPrint(L"[PD] REG_SZ '%.64s' exceeds %u chars; truncating", valueName,
                               PD_RAW_COMMAND_CAP / sizeof(WCHAR));
                }
                PdWcsCopyN(raw, _countof(raw), (PCWSTR)data, len);
                rawLen = len;

                if (valueType == REG_EXPAND_SZ) {
                    /* ReadExpandString(+expand) 语义 */
                    PdExpandEnvVarsSafe(raw, raw, _countof(raw));
                    rawLen = PdWcsLen(raw);
                }
            } else if (valueType == REG_MULTI_SZ) {
                /* MULTI_SZ: 以 ';' 拼接, 上限 1024 条 */
                PCWSTR p = (PCWSTR)data;
                ULONG remain = dataSize / sizeof(WCHAR);
                ULONG items = 0;
                raw[0] = L'\0';
                while (remain > 1 && *p != L'\0' && items < PD_MULTI_SZ_CAP &&
                       PdWcsLen(raw) < PD_RAW_COMMAND_CAP / sizeof(WCHAR) - 8) {
                    ULONG itemLen = PdWcsLen(p);
                    if (raw[0] != L'\0') wcscat_s(raw, _countof(raw), L";");
                    if (PdWcsLen(raw) + itemLen < _countof(raw) - 1) {
                        wcscat_s(raw, _countof(raw), p);
                    } else {
                        PdWcsCopyN(raw + PdWcsLen(raw), _countof(raw) - PdWcsLen(raw) - 1,
                                   p, _countof(raw) - PdWcsLen(raw) - 2);
                        break;
                    }
                    items++;
                    p += itemLen + 1;
                    if (p - (PCWSTR)data >= remain) break;
                }
                rawLen = PdWcsLen(raw);
            } else {
                /* 非字符串类型: 忽略 */
                continue;
            }
            if (rawLen > 0) raw[rawLen] = L'\0';
            PdWcsCopyN(entry.RawCommand, _countof(entry.RawCommand), raw, _countof(entry.RawCommand) - 1);

            /* 双视图去重: (entryName|rawCommand) 小写 */
            wcscpy_s(dedupA, _countof(dedupA), entry.EntryName);
            wcscpy_s(dedupB, _countof(dedupB), entry.RawCommand);
            PdWcsToLower(dedupA);
            PdWcsToLower(dedupB);
            {
                BOOLEAN dup = FALSE;
                for (ULONG k = 0; k < count; k++) {
                    WCHAR exA[WKD_REG_MAX_NAME_CHARS];
                    WCHAR exB[WKD_PD_MAX_CMD_BUFFER + 1];
                    wcscpy_s(exA, _countof(exA), Out[k].EntryName);
                    wcscpy_s(exB, _countof(exB), Out[k].RawCommand);
                    PdWcsToLower(exA);
                    PdWcsToLower(exB);
                    if (wcscmp(exA, dedupA) == 0 && wcscmp(exB, dedupB) == 0) { dup = TRUE; break; }
                }
                if (dup) continue;
            }

            /* 最后扫描时间 */
            GetSystemTimeAsFileTime((LPFILETIME)&entry.LastScanned);

            /* 目标解析 + 白名单/信誉/风险 */
            if (g_Pd.Config.ResolveTargets && entry.RawCommand[0] != L'\0') {
                entry.Target = PdResolveTargetImpl(entry.RawCommand);

                if (PdIsWhitelisted(&entry)) {
                    entry.Risk = WkdRegRisk_Safe;
                    entry.RiskScore = 0;
                    entry.IsKnownGood = TRUE;
                } else {
                    PdEnrichWithHashLookup(&entry);
                    PdEnrichWithThreatIntel(&entry);
                    entry.Risk = PdAssessRisk(&entry);
                    entry.RiskScore = PdCalculateRiskScore(&entry);
                }
            }

            if (count < OutCapacity) {
                Out[count++] = entry;
            } else {
                break;
            }
        }
        RegCloseKey(hKey);
    }

    *EntryCount = count;
    return STATUS_SUCCESS;
}

/* ==================================================
 * IFEO / SilentProcessExit 子键扫描 (SS ScanIFEOSubkeys 迁移)
 * 逐镜像子键枚举 Debugger / MonitorProcess 值
 * ================================================== */
static
NTSTATUS PdScanIfeoSubkeys(_Out_ PWKD_PERSISTENCE_ENTRY Out, _In_ ULONG OutCapacity,
                           _Out_ PULONG EntryCount) {
    struct PD_IFEO_SCOPE {
        WKD_REG_PERSISTENCE_TYPE Type;
        PCWSTR Root;
        PCWSTR ValueName;
        PCWSTR Friendly;
        PCSTR  Mitre;
    };
    static const struct PD_IFEO_SCOPE kScopes[] = {
        { WkdRegPersist_IFeoDebugger,
          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
          L"Debugger", L"IFEO", "T1546.012" },
        { WkdRegPersist_SilentProcessExit,
          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",
          L"MonitorProcess", L"SilentProcessExit", "T1546.012" },
    };
    ULONG count = 0;

    *EntryCount = 0;

    for (ULONG s = 0; s < 2; s++) {
        for (ULONG view = 0; view < 2; view++) {
            REGSAM access = KEY_READ | ((view == 0) ? KEY_WOW64_64KEY : KEY_WOW64_32KEY);
            HKEY hParent = NULL;
            WCHAR imageName[WKD_REG_MAX_NAME_CHARS];
            DWORD imageNameCch = _countof(imageName);
            LONG lRet;
            DWORD index = 0;

            lRet = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kScopes[s].Root, 0, access, &hParent);
            if (lRet != ERROR_SUCCESS) continue;

            for (;;) {
                HKEY hChild = NULL;
                WCHAR fullPath[WKD_REG_MAX_PATH_CHARS];
                WCHAR valueData[WKD_PD_MAX_CMD_BUFFER + 1];
                DWORD valueDataCch = sizeof(valueData) - sizeof(WCHAR);
                DWORD valueType = 0;
                WKD_PERSISTENCE_ENTRY entry;
                BOOLEAN dup = FALSE;

                imageNameCch = _countof(imageName);
                lRet = RegEnumKeyExW(hParent, index, imageName, &imageNameCch,
                                     NULL, NULL, NULL, NULL);
                if (lRet == ERROR_NO_MORE_ITEMS) break;
                if (lRet != ERROR_SUCCESS) { index++; continue; }
                index++;
                if (imageName[0] == L'\0') continue;

                wsprintfW(fullPath, L"%s\\%s", kScopes[s].Root, imageName);
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, fullPath, 0, access, &hChild) != ERROR_SUCCESS) {
                    continue;
                }

                valueData[0] = L'\0';
                lRet = RegQueryValueExW(hChild, kScopes[s].ValueName, NULL, &valueType,
                                        (LPBYTE)valueData, &valueDataCch);
                if (lRet == ERROR_FILE_NOT_FOUND || valueData[0] == L'\0') {
                    /* EXPAND_SZ 回退 */
                    valueDataCch = sizeof(valueData) - sizeof(WCHAR);
                    lRet = RegQueryValueExW(hChild, kScopes[s].ValueName, NULL, &valueType,
                                            (LPBYTE)valueData, &valueDataCch);
                    if (lRet != ERROR_SUCCESS || valueData[0] == L'\0') {
                        RegCloseKey(hChild);
                        continue;
                    }
                }
                if (valueDataCch > PD_RAW_COMMAND_CAP) {
                    valueData[PD_RAW_COMMAND_CAP / sizeof(WCHAR)] = L'\0';
                }

                memset(&entry, 0, sizeof(entry));
                entry.Type = kScopes[s].Type;
                PdWcsCopyN(entry.EntryName, _countof(entry.EntryName), imageName,
                           _countof(entry.EntryName) - 1);
                wsprintfW(fullPath, L"HKLM\\%s\\%s [%s; view=%s]", kScopes[s].Root,
                          imageName, kScopes[s].Friendly, (view == 0) ? L"64" : L"32");
                PdWcsCopyN(entry.Location, _countof(entry.Location), fullPath,
                           _countof(entry.Location) - 1);
                entry.IsUserEntry = FALSE;
                strcpy_s(entry.MitreTechnique, sizeof(entry.MitreTechnique), kScopes[s].Mitre);
                PdWcsCopyN(entry.RawCommand, _countof(entry.RawCommand), valueData,
                           _countof(entry.RawCommand) - 1);
                GetSystemTimeAsFileTime((LPFILETIME)&entry.LastScanned);

                if (g_Pd.Config.ResolveTargets && entry.RawCommand[0] != L'\0') {
                    entry.Target = PdResolveTargetImpl(entry.RawCommand);
                    if (PdIsWhitelisted(&entry)) {
                        entry.Risk = WkdRegRisk_Safe;
                        entry.RiskScore = 0;
                        entry.IsKnownGood = TRUE;
                    } else {
                        PdEnrichWithHashLookup(&entry);
                        PdEnrichWithThreatIntel(&entry);
                        entry.Risk = PdAssessRisk(&entry);
                        entry.RiskScore = PdCalculateRiskScore(&entry);
                    }
                }

                /* 去重检查 */
                for (ULONG k = 0; k < count; k++) {
                    WCHAR exA[WKD_REG_MAX_NAME_CHARS], exB[WKD_PD_MAX_CMD_BUFFER + 1];
                    wcscpy_s(exA, _countof(exA), Out[k].EntryName);
                    wcscpy_s(exB, _countof(exB), Out[k].RawCommand);
                    PdWcsToLower(exA); PdWcsToLower(exB);
                    WCHAR inA[WKD_REG_MAX_NAME_CHARS], inB[WKD_PD_MAX_CMD_BUFFER + 1];
                    wcscpy_s(inA, _countof(inA), entry.EntryName);
                    wcscpy_s(inB, _countof(inB), entry.RawCommand);
                    PdWcsToLower(inA); PdWcsToLower(inB);
                    if (wcscmp(exA, inA) == 0 && wcscmp(exB, inB) == 0) { dup = TRUE; break; }
                }

                RegCloseKey(hChild);

                if (dup) continue;
                if (count < OutCapacity) {
                    Out[count++] = entry;
                } else {
                    break;
                }
            }
            RegCloseKey(hParent);
        }
    }

    *EntryCount = count;
    return STATUS_SUCCESS;
}

/* ==================================================
 * ═══ 服务扫描 (SS ScanServicesImpl 迁移) ═══
 * EnumServicesStatusExW + QueryServiceConfigW
 * ================================================== */
static
NTSTATUS PdScanServicesImpl(_Out_ PWKD_SERVICE_ENTRY Entries, _In_ ULONG MaxEntries,
                            _Out_ PULONG EntryCount) {
    SC_HANDLE hSCManager = NULL;
    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;
    PBYTE buffer = NULL;
    ULONG count = 0;

    *EntryCount = 0;
    if (Entries == NULL || MaxEntries == 0) return STATUS_INVALID_PARAMETER;

    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL) return STATUS_ACCESS_DENIED;

    /* 首次调用获取所需缓冲大小 */
    EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);
    if (bytesNeeded == 0) {
        CloseServiceHandle(hSCManager);
        return STATUS_SUCCESS;
    }

    buffer = (PBYTE)malloc(bytesNeeded);
    if (buffer == NULL) {
        CloseServiceHandle(hSCManager);
        return STATUS_NO_MEMORY;
    }

    if (!EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                               buffer, bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, NULL)) {
        free(buffer);
        CloseServiceHandle(hSCManager);
        return STATUS_UNSUCCESSFUL;
    }

    {
        LPENUM_SERVICE_STATUS_PROCESSW pServices = (LPENUM_SERVICE_STATUS_PROCESSW)buffer;
        for (DWORD i = 0; i < servicesReturned && count < MaxEntries; i++) {
            WKD_SERVICE_ENTRY* entry = &Entries[count];
            SC_HANDLE hService = NULL;
            DWORD configBytesNeeded = 0;

            memset(entry, 0, sizeof(*entry));
            PdWcsCopyN(entry->ServiceName, _countof(entry->ServiceName),
                       pServices[i].lpServiceName, _countof(entry->ServiceName) - 1);
            PdWcsCopyN(entry->DisplayName, _countof(entry->DisplayName),
                       pServices[i].lpDisplayName, _countof(entry->DisplayName) - 1);
            entry->CurrentState = pServices[i].ServiceStatusProcess.dwCurrentState;
            entry->ServiceType = pServices[i].ServiceStatusProcess.dwServiceType;
            entry->ProcessId = pServices[i].ServiceStatusProcess.dwProcessId;

            hService = OpenServiceW(hSCManager, pServices[i].lpServiceName, SERVICE_QUERY_CONFIG);
            if (hService != NULL) {
                QueryServiceConfigW(hService, NULL, 0, &configBytesNeeded);
                if (configBytesNeeded > 0) {
                    PBYTE configBuffer = (PBYTE)malloc(configBytesNeeded);
                    if (configBuffer != NULL) {
                        LPQUERY_SERVICE_CONFIGW pConfig = (LPQUERY_SERVICE_CONFIGW)configBuffer;
                        if (QueryServiceConfigW(hService, pConfig, configBytesNeeded, &configBytesNeeded)) {
                            if (pConfig->lpBinaryPathName != NULL) {
                                PdWcsCopyN(entry->ImagePath, _countof(entry->ImagePath),
                                           pConfig->lpBinaryPathName, _countof(entry->ImagePath) - 1);
                            }
                            entry->StartType = pConfig->dwStartType;
                            entry->ErrorControl = pConfig->dwErrorControl;
                            if (pConfig->lpServiceStartName != NULL) {
                                PdWcsCopyN(entry->ObjectName, _countof(entry->ObjectName),
                                           pConfig->lpServiceStartName, _countof(entry->ObjectName) - 1);
                            }
                        }
                        free(configBuffer);
                    }
                }
                CloseServiceHandle(hService);
            }
            count++;
        }
    }

    free(buffer);
    CloseServiceHandle(hSCManager);
    *EntryCount = count;
    return STATUS_SUCCESS;
}

/* 服务 → 持久化条目 (SS ServiceEntry::asPersistenceEntry 迁移) */
static
VOID PdServiceAsEntry(_In_ PCWKD_SERVICE_ENTRY Svc, _Out_ PWKD_PERSISTENCE_ENTRY Entry) {
    memset(Entry, 0, sizeof(*Entry));
    Entry->Type = (Svc->ServiceType == SERVICE_KERNEL_DRIVER ||
                   Svc->ServiceType == SERVICE_FILE_SYSTEM_DRIVER) ?
                  WkdRegPersist_KernelDriver : WkdRegPersist_Service;
    PdWcsCopy(Entry->Location, _countof(Entry->Location),
              L"HKLM\\SYSTEM\\CurrentControlSet\\Services");
    PdWcsCopyN(Entry->EntryName, _countof(Entry->EntryName), Svc->ServiceName,
               _countof(Entry->EntryName) - 1);
    PdWcsCopyN(Entry->RawCommand, _countof(Entry->RawCommand), Svc->ImagePath,
               _countof(Entry->RawCommand) - 1);
    PdWcsCopyN(Entry->Description, _countof(Entry->Description), Svc->Description,
               _countof(Entry->Description) - 1);
    PdWcsCopyN(Entry->Target.Path, _countof(Entry->Target.Path), Svc->ImagePath,
               _countof(Entry->Target.Path) - 1);
    PdWcsCopyN(Entry->Target.OriginalPath, _countof(Entry->Target.OriginalPath), Svc->ImagePath,
               _countof(Entry->Target.OriginalPath) - 1);

    if (Svc->StartType == SERVICE_AUTO_START || Svc->StartType == SERVICE_BOOT_START ||
        Svc->StartType == SERVICE_SYSTEM_START) {
        Entry->Status = WkdRegEntry_Active;
    } else if (Svc->StartType == SERVICE_DISABLED) {
        Entry->Status = WkdRegEntry_Disabled;
    }
    strcpy_s(Entry->MitreTechnique, sizeof(Entry->MitreTechnique), "T1543.003");
}

/* ==================================================
 * ═══ 计划任务扫描 (COM; SS ScanScheduledTasksImpl 迁移) ═══
 * 递归枚举文件夹 + 动作/触发器提取 (防递归上限 16)
 * ================================================== */
static
VOID PdExtractTaskInfo(_In_ IRegisteredTask* pTask, _Out_ PWKD_SCHEDULED_TASK_ENTRY Entry) {
    BSTR bstr = NULL;
    TASK_STATE state;

    memset(Entry, 0, sizeof(*Entry));

    if (SUCCEEDED(pTask->lpVtbl->get_Name(pTask, &bstr)) && bstr != NULL) {
        PdWcsCopyN(Entry->TaskName, _countof(Entry->TaskName), bstr, _countof(Entry->TaskName) - 1);
        SysFreeString(bstr); bstr = NULL;
    }
    if (SUCCEEDED(pTask->lpVtbl->get_Path(pTask, &bstr)) && bstr != NULL) {
        PdWcsCopyN(Entry->TaskPath, _countof(Entry->TaskPath), bstr, _countof(Entry->TaskPath) - 1);
        SysFreeString(bstr); bstr = NULL;
    }
    if (SUCCEEDED(pTask->lpVtbl->get_State(pTask, &state))) {
        Entry->Enabled = (state != TASK_STATE_DISABLED);
    }

    {
        ITaskDefinition* pDefinition = NULL;
        if (SUCCEEDED(pTask->lpVtbl->get_Definition(pTask, &pDefinition)) && pDefinition != NULL) {
            IRegistrationInfo* pRegInfo = NULL;
            if (SUCCEEDED(pDefinition->lpVtbl->get_RegistrationInfo(pDefinition, &pRegInfo)) && pRegInfo != NULL) {
                if (SUCCEEDED(pRegInfo->lpVtbl->get_Description(pRegInfo, &bstr)) && bstr != NULL) {
                    PdWcsCopyN(Entry->Description, _countof(Entry->Description), bstr,
                               _countof(Entry->Description) - 1);
                    SysFreeString(bstr); bstr = NULL;
                }
                pRegInfo->lpVtbl->Release(pRegInfo);
            }

            /* 动作 */
            IActionCollection* pActions = NULL;
            if (SUCCEEDED(pDefinition->lpVtbl->get_Actions(pDefinition, &pActions)) && pActions != NULL) {
                LONG actionCount = 0;
                pActions->lpVtbl->get_Count(pActions, &actionCount);
                for (LONG i = 1; i <= actionCount && Entry->ActionCount < PD_TASK_MAX_ACTIONS; i++) {
                    IAction* pAction = NULL;
                    if (SUCCEEDED(pActions->lpVtbl->get_Item(pActions, i, &pAction)) && pAction != NULL) {
                        TASK_ACTION_TYPE actionType = TASK_ACTION_EXEC;
                        pAction->lpVtbl->get_Type(pAction, &actionType);
                        if (actionType == TASK_ACTION_EXEC) {
                            IExecAction* pExecAction = NULL;
                            if (SUCCEEDED(pAction->lpVtbl->QueryInterface(pAction, &IID_IExecAction,
                                        (void**)&pExecAction)) && pExecAction != NULL) {
                                PWKD_TASK_ACTION action = &Entry->Actions[Entry->ActionCount];
                                PdWcsCopy(action->Type, _countof(action->Type), L"Exec");
                                if (SUCCEEDED(pExecAction->lpVtbl->get_Path(pExecAction, &bstr)) && bstr != NULL) {
                                    PdWcsCopyN(action->Path, _countof(action->Path), bstr,
                                               _countof(action->Path) - 1);
                                    SysFreeString(bstr); bstr = NULL;
                                }
                                if (SUCCEEDED(pExecAction->lpVtbl->get_Arguments(pExecAction, &bstr)) && bstr != NULL) {
                                    ULONG argLen = (ULONG)SysStringLen(bstr);
                                    if (argLen > PD_ARGUMENT_CAP / sizeof(WCHAR)) {
                                        argLen = PD_ARGUMENT_CAP / sizeof(WCHAR);
                                    }
                                    PdWcsCopyN(action->Arguments, _countof(action->Arguments),
                                               bstr, argLen);
                                    SysFreeString(bstr); bstr = NULL;
                                }
                                if (SUCCEEDED(pExecAction->lpVtbl->get_WorkingDirectory(pExecAction, &bstr)) && bstr != NULL) {
                                    PdWcsCopyN(action->WorkingDirectory, _countof(action->WorkingDirectory),
                                               bstr, _countof(action->WorkingDirectory) - 1);
                                    SysFreeString(bstr); bstr = NULL;
                                }
                                pExecAction->lpVtbl->Release(pExecAction);
                                Entry->ActionCount++;
                            }
                        }
                        pAction->lpVtbl->Release(pAction);
                    }
                }
                pActions->lpVtbl->Release(pActions);
            }

            /* 触发器 */
            ITriggerCollection* pTriggers = NULL;
            if (SUCCEEDED(pDefinition->lpVtbl->get_Triggers(pDefinition, &pTriggers)) && pTriggers != NULL) {
                LONG triggerCount = 0;
                pTriggers->lpVtbl->get_Count(pTriggers, &triggerCount);
                for (LONG i = 1; i <= triggerCount && Entry->TriggerCount < PD_TASK_MAX_TRIGGERS; i++) {
                    ITrigger* pTrigger = NULL;
                    if (SUCCEEDED(pTriggers->lpVtbl->get_Item(pTriggers, i, &pTrigger)) && pTrigger != NULL) {
                        PWKD_TASK_TRIGGER trig = &Entry->Triggers[Entry->TriggerCount];
                        TASK_TRIGGER_TYPE2 ttype = TASK_TRIGGER_DAILY;
                        VARIANT_BOOL enabled = VARIANT_TRUE;

                        pTrigger->lpVtbl->get_Type(pTrigger, &ttype);
                        switch (ttype) {
                            case TASK_TRIGGER_EVENT:       PdWcsCopy(trig->Type, _countof(trig->Type), L"Event"); break;
                            case TASK_TRIGGER_TIME:        PdWcsCopy(trig->Type, _countof(trig->Type), L"Time"); break;
                            case TASK_TRIGGER_DAILY:       PdWcsCopy(trig->Type, _countof(trig->Type), L"Daily"); break;
                            case TASK_TRIGGER_WEEKLY:      PdWcsCopy(trig->Type, _countof(trig->Type), L"Weekly"); break;
                            case TASK_TRIGGER_MONTHLY:     PdWcsCopy(trig->Type, _countof(trig->Type), L"Monthly"); break;
                            case TASK_TRIGGER_MONTHLYDOW:  PdWcsCopy(trig->Type, _countof(trig->Type), L"MonthlyDOW"); break;
                            case TASK_TRIGGER_IDLE:        PdWcsCopy(trig->Type, _countof(trig->Type), L"Idle"); break;
                            case TASK_TRIGGER_REGISTRATION: PdWcsCopy(trig->Type, _countof(trig->Type), L"Registration"); break;
                            case TASK_TRIGGER_BOOT:        PdWcsCopy(trig->Type, _countof(trig->Type), L"Boot"); break;
                            case TASK_TRIGGER_LOGON:       PdWcsCopy(trig->Type, _countof(trig->Type), L"Logon"); break;
                            case TASK_TRIGGER_SESSION_STATE_CHANGE: PdWcsCopy(trig->Type, _countof(trig->Type), L"SessionStateChange"); break;
                            default:                       PdWcsCopy(trig->Type, _countof(trig->Type), L"Unknown"); break;
                        }
                        if (SUCCEEDED(pTrigger->lpVtbl->get_Enabled(pTrigger, &enabled))) {
                            trig->Enabled = (enabled != VARIANT_FALSE);
                        }
                        if (SUCCEEDED(pTrigger->lpVtbl->get_Id(pTrigger, &bstr)) && bstr != NULL) {
                            PdWcsCopyN(trig->Details, _countof(trig->Details), bstr,
                                       _countof(trig->Details) - 1);
                            SysFreeString(bstr); bstr = NULL;
                        }
                        if (trig->Details[0] == L'\0') {
                            if (SUCCEEDED(pTrigger->lpVtbl->get_StartBoundary(pTrigger, &bstr)) && bstr != NULL) {
                                PdWcsCopyN(trig->Details, _countof(trig->Details), bstr,
                                           _countof(trig->Details) - 1);
                                SysFreeString(bstr); bstr = NULL;
                            }
                        }
                        Entry->TriggerCount++;
                        pTrigger->lpVtbl->Release(pTrigger);
                    }
                }
                pTriggers->lpVtbl->Release(pTriggers);
            }
            pDefinition->lpVtbl->Release(pDefinition);
        }
    }
}

static
VOID PdEnumerateTaskFolder(_In_ ITaskFolder* pFolder,
                           _Inout_ PWKD_SCHEDULED_TASK_ENTRY Entries,
                           _In_ ULONG MaxEntries,
                           _Inout_ PULONG EntryCount,
                           _In_ ULONG Depth) {
    IRegisteredTaskCollection* pTaskCollection = NULL;
    HRESULT hr;

    /* 递归上限 (防恶意/环状任务树耗尽栈) */
    if (Depth >= PD_TASK_RECURSION_CAP || *EntryCount >= MaxEntries) return;

    hr = pFolder->lpVtbl->GetTasks(pFolder, TASK_ENUM_HIDDEN, &pTaskCollection);
    if (SUCCEEDED(hr) && pTaskCollection != NULL) {
        LONG taskCount = 0;
        pTaskCollection->lpVtbl->get_Count(pTaskCollection, &taskCount);
        for (LONG i = 1; i <= taskCount && *EntryCount < MaxEntries; i++) {
            IRegisteredTask* pTask = NULL;
            VARIANT vt = { 0 };
            vt.vt = VT_I4;
            vt.lVal = i;
            hr = pTaskCollection->lpVtbl->get_Item(pTaskCollection, vt, &pTask);
            if (SUCCEEDED(hr) && pTask != NULL) {
                PdExtractTaskInfo(pTask, &Entries[*EntryCount]);
                (*EntryCount)++;
                pTask->lpVtbl->Release(pTask);
            }
        }
        pTaskCollection->lpVtbl->Release(pTaskCollection);
    }

    {
        ITaskFolderCollection* pFolderCollection = NULL;
        hr = pFolder->lpVtbl->GetFolders(pFolder, 0, &pFolderCollection);
        if (SUCCEEDED(hr) && pFolderCollection != NULL) {
            LONG folderCount = 0;
            pFolderCollection->lpVtbl->get_Count(pFolderCollection, &folderCount);
            for (LONG i = 1; i <= folderCount && *EntryCount < MaxEntries; i++) {
                ITaskFolder* pSubFolder = NULL;
                VARIANT vt = { 0 };
                vt.vt = VT_I4;
                vt.lVal = i;
                hr = pFolderCollection->lpVtbl->get_Item(pFolderCollection, vt, &pSubFolder);
                if (SUCCEEDED(hr) && pSubFolder != NULL) {
                    PdEnumerateTaskFolder(pSubFolder, Entries, MaxEntries, EntryCount, Depth + 1);
                    pSubFolder->lpVtbl->Release(pSubFolder);
                }
            }
            pFolderCollection->lpVtbl->Release(pFolderCollection);
        }
    }
}

static
NTSTATUS PdScanScheduledTasksImpl(_Out_ PWKD_SCHEDULED_TASK_ENTRY Entries,
                                  _In_ ULONG MaxEntries, _Out_ PULONG EntryCount) {
    ITaskService* pService = NULL;
    HRESULT hr;
    VARIANT vtEmpty = { 0 };
    BSTR rootFolder = NULL;

    *EntryCount = 0;
    if (Entries == NULL || MaxEntries == 0) return STATUS_INVALID_PARAMETER;

    hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                          &IID_ITaskService, (void**)&pService);
    if (FAILED(hr) || pService == NULL) return STATUS_UNSUCCESSFUL;

    /* SS 使用 _variant_t() (VT_ERROR/DISP_E_PARAMNOTFOUND); 构造等价 VARIANT */
    vtEmpty.vt = VT_ERROR;
    vtEmpty.scode = DISP_E_PARAMNOTFOUND;

    hr = pService->lpVtbl->Connect(pService, vtEmpty, vtEmpty, vtEmpty, vtEmpty);
    if (FAILED(hr)) {
        pService->lpVtbl->Release(pService);
        return STATUS_UNSUCCESSFUL;
    }

    rootFolder = SysAllocString(L"\\");
    if (rootFolder != NULL) {
        ITaskFolder* pRootFolder = NULL;
        hr = pService->lpVtbl->GetFolder(pService, rootFolder, &pRootFolder);
        if (SUCCEEDED(hr) && pRootFolder != NULL) {
            PdEnumerateTaskFolder(pRootFolder, Entries, MaxEntries, EntryCount, 0);
            pRootFolder->lpVtbl->Release(pRootFolder);
        }
        SysFreeString(rootFolder);
    }

    pService->lpVtbl->Release(pService);
    return STATUS_SUCCESS;
}

/* 计划任务 → 持久化条目 (SS ScheduledTaskEntry::asPersistenceEntry 迁移) */
static
VOID PdTaskAsEntry(_In_ PCWKD_SCHEDULED_TASK_ENTRY Task, _Out_ PWKD_PERSISTENCE_ENTRY Entry) {
    memset(Entry, 0, sizeof(*Entry));
    Entry->Type = WkdRegPersist_ScheduledTask;
    PdWcsCopy(Entry->Location, _countof(Entry->Location), L"Task Scheduler");
    PdWcsCopyN(Entry->EntryName, _countof(Entry->EntryName), Task->TaskName,
               _countof(Entry->EntryName) - 1);
    PdWcsCopyN(Entry->Description, _countof(Entry->Description), Task->Description,
               _countof(Entry->Description) - 1);

    if (Task->ActionCount > 0) {
        WCHAR combined[WKD_PD_MAX_CMD_BUFFER + 1];
        wsprintfW(combined, L"%s %s", Task->Actions[0].Path, Task->Actions[0].Arguments);
        PdWcsCopyN(Entry->RawCommand, _countof(Entry->RawCommand), combined,
                   _countof(Entry->RawCommand) - 1);
        PdWcsCopyN(Entry->Target.Path, _countof(Entry->Target.Path),
                   Task->Actions[0].Path, _countof(Entry->Target.Path) - 1);
        PdWcsCopyN(Entry->Target.OriginalPath, _countof(Entry->Target.OriginalPath),
                   Task->Actions[0].Path, _countof(Entry->Target.OriginalPath) - 1);
        PdWcsCopyN(Entry->Target.Arguments, _countof(Entry->Target.Arguments),
                   Task->Actions[0].Arguments, _countof(Entry->Target.Arguments) - 1);
        PdWcsCopyN(Entry->Target.WorkingDirectory, _countof(Entry->Target.WorkingDirectory),
                   Task->Actions[0].WorkingDirectory, _countof(Entry->Target.WorkingDirectory) - 1);
    }

    Entry->Status = Task->Enabled ? WkdRegEntry_Active : WkdRegEntry_Disabled;
    strcpy_s(Entry->MitreTechnique, sizeof(Entry->MitreTechnique), "T1053.005");
}

/* ==================================================
 * ═══ WMI 订阅扫描 (COM; SS ScanWMISubscriptionsImpl 迁移) ═══
 * __FilterToConsumerBinding → Filter(Query) → Consumer(payload)
 * ================================================== */
static
NTSTATUS PdScanWmiSubscriptionsImpl(_Out_ PWKD_WMI_SUBSCRIPTION Subs,
                                    _In_ ULONG MaxSubs, _Out_ PULONG SubCount) {
    IWbemLocator* pLocator = NULL;
    IWbemServices* pServices = NULL;
    IEnumWbemClassObject* pBindingEnum = NULL;
    HRESULT hr;
    BSTR ns = NULL;
    BSTR wql = NULL;
    BSTR query = NULL;
    ULONG count = 0;

    *SubCount = 0;
    if (Subs == NULL || MaxSubs == 0) return STATUS_INVALID_PARAMETER;

    hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IWbemLocator, (void**)&pLocator);
    if (FAILED(hr) || pLocator == NULL) return STATUS_UNSUCCESSFUL;

    ns = SysAllocString(L"ROOT\\subscription");
    if (ns == NULL) { pLocator->lpVtbl->Release(pLocator); return STATUS_NO_MEMORY; }

    hr = pLocator->lpVtbl->ConnectServer(pLocator, ns, NULL, NULL, NULL, 0, NULL, NULL, &pServices);
    if (FAILED(hr) || pServices == NULL) {
        SysFreeString(ns);
        pLocator->lpVtbl->Release(pLocator);
        return STATUS_UNSUCCESSFUL;
    }
    SysFreeString(ns);

    /* 安全级别 (显式转 IUnknown* 满足 C 模式类型检查) */
    CoSetProxyBlanket((IUnknown*)pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    wql = SysAllocString(L"WQL");
    query = SysAllocString(L"SELECT * FROM __FilterToConsumerBinding");
    if (wql == NULL || query == NULL) {
        if (wql) SysFreeString(wql);
        if (query) SysFreeString(query);
        pServices->lpVtbl->Release(pServices);
        pLocator->lpVtbl->Release(pLocator);
        return STATUS_NO_MEMORY;
    }

    hr = pServices->lpVtbl->ExecQuery(pServices, wql, query,
                              WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                              NULL, &pBindingEnum);
    SysFreeString(wql);
    SysFreeString(query);

    if (SUCCEEDED(hr) && pBindingEnum != NULL) {
        IWbemClassObject* pBindingObj = NULL;
        ULONG returned = 0;

        while (SUCCEEDED(pBindingEnum->lpVtbl->Next(pBindingEnum, WBEM_INFINITE, 1, &pBindingObj, &returned)) &&
               returned > 0 && count < MaxSubs) {
            VARIANT vtFilter = { 0 };
            VARIANT vtConsumer = { 0 };
            WKD_WMI_SUBSCRIPTION* sub = &Subs[count];

            memset(sub, 0, sizeof(*sub));

            if (SUCCEEDED(pBindingObj->lpVtbl->Get(pBindingObj, L"Filter", 0, &vtFilter, NULL, NULL)) &&
                SUCCEEDED(pBindingObj->lpVtbl->Get(pBindingObj, L"Consumer", 0, &vtConsumer, NULL, NULL))) {

                if (vtFilter.vt == VT_BSTR && vtConsumer.vt == VT_BSTR) {
                    PdWcsCopyN(sub->BindingName, _countof(sub->BindingName), vtFilter.bstrVal,
                               _countof(sub->BindingName) - 1);

                    /* 解析 Filter (触发器) */
                    IWbemClassObject* pFilterObj = NULL;
                    if (SUCCEEDED(pServices->lpVtbl->GetObject(pServices, vtFilter.bstrVal, 0, NULL, &pFilterObj, NULL)) &&
                        pFilterObj != NULL) {
                        VARIANT vtQ = { 0 }, vtN = { 0 }, vtL = { 0 };
                        if (SUCCEEDED(pFilterObj->lpVtbl->Get(pFilterObj, L"Query", 0, &vtQ, NULL, NULL)) && vtQ.vt == VT_BSTR) {
                            PdWcsCopyN(sub->FilterQuery, _countof(sub->FilterQuery), vtQ.bstrVal,
                                       _countof(sub->FilterQuery) - 1);
                        }
                        if (SUCCEEDED(pFilterObj->lpVtbl->Get(pFilterObj, L"Name", 0, &vtN, NULL, NULL)) && vtN.vt == VT_BSTR) {
                            PdWcsCopyN(sub->FilterName, _countof(sub->FilterName), vtN.bstrVal,
                                       _countof(sub->FilterName) - 1);
                        }
                        if (SUCCEEDED(pFilterObj->lpVtbl->Get(pFilterObj, L"QueryLanguage", 0, &vtL, NULL, NULL)) && vtL.vt == VT_BSTR) {
                            PdWcsCopyN(sub->FilterLanguage, _countof(sub->FilterLanguage), vtL.bstrVal,
                                       _countof(sub->FilterLanguage) - 1);
                        }
                        VariantClear(&vtQ); VariantClear(&vtN); VariantClear(&vtL);
                        pFilterObj->lpVtbl->Release(pFilterObj);
                    }

                    /* 解析 Consumer (载荷) */
                    IWbemClassObject* pConsumerObj = NULL;
                    if (SUCCEEDED(pServices->lpVtbl->GetObject(pServices, vtConsumer.bstrVal, 0, NULL, &pConsumerObj, NULL)) &&
                        pConsumerObj != NULL) {
                        VARIANT vtCName = { 0 }, vtClass = { 0 };
                        if (SUCCEEDED(pConsumerObj->lpVtbl->Get(pConsumerObj, L"Name", 0, &vtCName, NULL, NULL)) && vtCName.vt == VT_BSTR) {
                            PdWcsCopyN(sub->ConsumerName, _countof(sub->ConsumerName), vtCName.bstrVal,
                                       _countof(sub->ConsumerName) - 1);
                        }
                        if (SUCCEEDED(pConsumerObj->lpVtbl->Get(pConsumerObj, L"__CLASS", 0, &vtClass, NULL, NULL)) && vtClass.vt == VT_BSTR) {
                            PdWcsCopyN(sub->ConsumerType, _countof(sub->ConsumerType), vtClass.bstrVal,
                                       _countof(sub->ConsumerType) - 1);
                            if (PdWcsIEquals(sub->ConsumerType, L"CommandLineEventConsumer")) {
                                VARIANT vtCmd = { 0 };
                                if (SUCCEEDED(pConsumerObj->lpVtbl->Get(pConsumerObj, L"CommandLineTemplate", 0, &vtCmd, NULL, NULL)) &&
                                    vtCmd.vt == VT_BSTR) {
                                    PdWcsCopyN(sub->ConsumerCommand, _countof(sub->ConsumerCommand),
                                               vtCmd.bstrVal, _countof(sub->ConsumerCommand) - 1);
                                }
                                VariantClear(&vtCmd);
                            } else if (PdWcsIEquals(sub->ConsumerType, L"ActiveScriptEventConsumer")) {
                                VARIANT vtScript = { 0 };
                                if (SUCCEEDED(pConsumerObj->lpVtbl->Get(pConsumerObj, L"ScriptText", 0, &vtScript, NULL, NULL)) &&
                                    vtScript.vt == VT_BSTR) {
                                    PdWcsCopyN(sub->ConsumerCommand, _countof(sub->ConsumerCommand),
                                               vtScript.bstrVal, _countof(sub->ConsumerCommand) - 1);
                                }
                                VariantClear(&vtScript);
                            }
                        }
                        VariantClear(&vtCName); VariantClear(&vtClass);
                        pConsumerObj->lpVtbl->Release(pConsumerObj);
                    }
                }
            }

            VariantClear(&vtFilter);
            VariantClear(&vtConsumer);

            if (sub->ConsumerCommand[0] != L'\0') {
                count++;
            }
            pBindingObj->lpVtbl->Release(pBindingObj);
        }
        pBindingEnum->lpVtbl->Release(pBindingEnum);
    }

    pServices->lpVtbl->Release(pServices);
    pLocator->lpVtbl->Release(pLocator);
    *SubCount = count;
    return STATUS_SUCCESS;
}

/* WMI 订阅 → 持久化条目 (SS WMISubscription::asPersistenceEntry 迁移) */
static
VOID PdWmiAsEntry(_In_ PCWKD_WMI_SUBSCRIPTION Sub, _Out_ PWKD_PERSISTENCE_ENTRY Entry) {
    memset(Entry, 0, sizeof(*Entry));
    Entry->Type = WkdRegPersist_WmiEventConsumer;
    PdWcsCopy(Entry->Location, _countof(Entry->Location), L"WMI Repository");
    wsprintfW(Entry->EntryName, L"%s -> %s", Sub->FilterName, Sub->ConsumerName);
    PdWcsCopyN(Entry->RawCommand, _countof(Entry->RawCommand), Sub->ConsumerCommand,
               _countof(Entry->RawCommand) - 1);
    PdWcsCopyN(Entry->Description, _countof(Entry->Description), Sub->FilterQuery,
               _countof(Entry->Description) - 1);
    PdWcsCopyN(Entry->Target.Path, _countof(Entry->Target.Path), Sub->ConsumerCommand,
               _countof(Entry->Target.Path) - 1);
    PdWcsCopyN(Entry->Target.OriginalPath, _countof(Entry->Target.OriginalPath),
               Sub->ConsumerCommand, _countof(Entry->Target.OriginalPath) - 1);
    strcpy_s(Entry->MitreTechnique, sizeof(Entry->MitreTechnique), "T1546.003");
}

/* ==================================================
 * ═══ 风险评分 (SS AssessRisk / CalculateRiskScore 迁移) ═══
 * ================================================== */
static
UCHAR PdCalculateRiskScore(_In_ PCWKD_PERSISTENCE_ENTRY Entry) {
    ULONG score = 0;
    WCHAR ext[16];

    /* 1. 可用性与路径 (基 0-40) */
    if (!Entry->Target.Exists && !Entry->Target.IsScript) score += 40;
    if (PdIsSuspiciousPath(Entry->Target.Path)) score += 30;
    if (Entry->Target.InTempPath) score += 35;

    /* 2. 二进制特征 (基 0-45) */
    if (Entry->Target.SignatureStatus == WkdRegSig_NotSigned && Entry->Target.IsExecutable) {
        score += 20;
    }
    if (Entry->Target.IsPacked) score += 25;

    /* 3. 高级持久化启发 (Pillar-4 权重) */
    if (PdIsLolBin(Entry->Target.Path)) score += 25;

    if (Entry->Type == WkdRegPersist_WmiEventConsumer ||
        Entry->Type == WkdRegPersist_WmiFilterToConsumer) {
        score += 40;
    }

    /* 非标准扩展名 (+15) */
    {
        ULONG pl = PdWcsLen(Entry->Target.Path);
        ext[0] = L'\0';
        for (ULONG j = pl; j > 0; j--) {
            if (Entry->Target.Path[j - 1] == L'.') {
                PdWcsCopyN(ext, _countof(ext), Entry->Target.Path + j - 1, 12);
                break;
            }
            if (Entry->Target.Path[j - 1] == L'\\' || Entry->Target.Path[j - 1] == L'/') break;
        }
    }
    if (ext[0] != L'\0' && Entry->Target.IsExecutable) {
        if (!PdWcsIEquals(ext, L".exe") && !PdWcsIEquals(ext, L".dll") &&
            !PdWcsIEquals(ext, L".sys")) {
            score += 15;
        }
    }

    /* 4. 覆盖 */
    if (Entry->IsKnownBad) score = 100;

    /* 可信微软二进制下限 */
    if (Entry->Target.IsMicrosoftSigned && score > 10) {
        ULONG reduced = (score > 20) ? (score - 20) : 10;
        score = reduced;
    }

    return (UCHAR)((score > 100) ? 100 : score);
}

static
WKD_REG_RISK_LEVEL PdAssessRisk(_In_ PCWKD_PERSISTENCE_ENTRY Entry) {
    UCHAR riskScore = PdCalculateRiskScore(Entry);

    if (Entry->IsKnownBad) return WkdRegRisk_Malicious;
    if (Entry->IsKnownGood || Entry->Target.IsMicrosoftSigned) return WkdRegRisk_Safe;

    if (riskScore >= 75) return WkdRegRisk_Malicious;
    if (riskScore >= 45) return WkdRegRisk_Suspicious;
    if (riskScore >= 20) return WkdRegRisk_Unknown;
    if (Entry->Target.IsTrusted) return WkdRegRisk_Safe;

    return WkdRegRisk_Low;
}

/* ==================================================
 * ═══ 持久化位置判定 (SS IsPersistenceLocationImpl 迁移) ═══
 * 内核路径 (\REGISTRY\MACHINE\...) 归一化 (HKLM/HKCU/HKCR)
 * ================================================== */
static
BOOLEAN PdMatchesLocation(_In_ PCWSTR Path, _In_ PCWSTR Location) {
    PCWSTR matchPos = wcsstr(Path, Location);

    if (matchPos == NULL) return FALSE;
    /* 必须整段或后跟 '\' (防前缀误配) */
    ULONG matchEnd = (ULONG)(matchPos - Path) + (ULONG)wcslen(Location);
    return (matchEnd == PdWcsLen(Path) || Path[matchEnd] == L'\\');
}

static
WKD_REG_PERSISTENCE_TYPE PdIsPersistenceLocationImpl(_In_ PCWSTR KeyPath) {
    WCHAR upper[WKD_REG_MAX_PATH_CHARS * 2 + 1];
    WCHAR normalized[WKD_REG_MAX_PATH_CHARS * 2 + 1];
    WCHAR check[WKD_REG_MAX_PATH_CHARS * 2 + 1];
    ULONG i;

    if (PdWcsEmpty(KeyPath) || PdWcsLen(KeyPath) + 8 >= _countof(upper)) {
        return WkdRegPersist_Unknown;
    }

    wcscpy_s(upper, _countof(upper), KeyPath);
    PdWcsToUpper(upper);

    /* 内核路径 → 用户态路径 */
    wcscpy_s(normalized, _countof(normalized), upper);
    {
        PCWSTR mk = wcsstr(normalized, L"\\REGISTRY\\MACHINE\\");
        if (mk != NULL) {
            ULONG off = (ULONG)(mk - normalized);
            ULONG tailLen = PdWcsLen(normalized + off + 18);
            memmove(normalized + off + 18, normalized + off + 18, (tailLen + 1) * sizeof(WCHAR));
            memcpy(normalized + off, L"HKEY_LOCAL_MACHINE\\", 19 * sizeof(WCHAR));
        } else {
            PCWSTR ur = wcsstr(normalized, L"\\REGISTRY\\USER\\");
            if (ur != NULL) {
                ULONG off = (ULONG)(ur - normalized);
                PCWSTR sidEnd = wcschr(ur + 15, L'\\');
                if (sidEnd != NULL) {
                    ULONG sidOff = (ULONG)(sidEnd - normalized);
                    memmove(normalized + off, L"HKEY_CURRENT_USER\\", 19 * sizeof(WCHAR));
                    memmove(normalized + off + 19, sidEnd, (PdWcsLen(sidEnd) + 1) * sizeof(WCHAR));
                } else {
                    wcscpy_s(normalized, _countof(normalized), L"HKEY_CURRENT_USER\\");
                }
            }
        }
    }

    /* 完整路径匹配 */
    for (i = 0; i < PD_LOCATION_COUNT; i++) {
        PCWSTR hiveName = (g_PdLocations[i].Hive == HKEY_LOCAL_MACHINE) ? L"HKEY_LOCAL_MACHINE" :
                          (g_PdLocations[i].Hive == HKEY_CURRENT_USER) ? L"HKEY_CURRENT_USER" :
                          L"HKEY_CLASSES_ROOT";
        wsprintfW(check, L"%s\\%s", hiveName, g_PdLocations[i].SubKey);
        if (PdMatchesLocation(normalized, check)) {
            return g_PdLocations[i].Type;
        }
    }

    /* 短格式 (HKLM\ / HKCU\ / HKCR\) */
    {
        WCHAR shortForm[WKD_REG_MAX_PATH_CHARS * 2 + 1];
        wcscpy_s(shortForm, _countof(shortForm), normalized);

        if (PdWcsStartsWith(shortForm, L"HKLM\\")) {
            memmove(shortForm + 18, shortForm + 5, (PdWcsLen(shortForm + 5) + 1) * sizeof(WCHAR));
            memcpy(shortForm, L"HKEY_LOCAL_MACHINE\\", 18 * sizeof(WCHAR));
        } else if (PdWcsStartsWith(shortForm, L"HKCU\\")) {
            memmove(shortForm + 18, shortForm + 5, (PdWcsLen(shortForm + 5) + 1) * sizeof(WCHAR));
            memcpy(shortForm, L"HKEY_CURRENT_USER\\", 18 * sizeof(WCHAR));
        } else if (PdWcsStartsWith(shortForm, L"HKCR\\")) {
            memmove(shortForm + 18, shortForm + 5, (PdWcsLen(shortForm + 5) + 1) * sizeof(WCHAR));
            memcpy(shortForm, L"HKEY_CLASSES_ROOT\\", 18 * sizeof(WCHAR));
        }

        if (wcscmp(shortForm, normalized) != 0) {
            for (i = 0; i < PD_LOCATION_COUNT; i++) {
                PCWSTR hiveName = (g_PdLocations[i].Hive == HKEY_LOCAL_MACHINE) ? L"HKEY_LOCAL_MACHINE" :
                                  (g_PdLocations[i].Hive == HKEY_CURRENT_USER) ? L"HKEY_CURRENT_USER" :
                                  L"HKEY_CLASSES_ROOT";
                wsprintfW(check, L"%s\\%s", hiveName, g_PdLocations[i].SubKey);
                if (PdMatchesLocation(shortForm, check)) {
                    return g_PdLocations[i].Type;
                }
            }
        }
    }

    return WkdRegPersist_Unknown;
}

/* ==================================================
 * ═══ 回调分发 (SS Invoke*Callbacks 迁移) ═══
 * ================================================== */
static
VOID PdInvokeProgressCallbacks(ULONG Current, ULONG Total, PCWSTR Path) {
    PD_CALLBACK_SLOT slot;
    PFN_PD_PROGRESS_CALLBACK cb;

    AcquireSRWLockShared(&g_Pd.CallbackLock);
    for (ULONG i = 0; i < WKD_PD_MAX_CALLBACKS; i++) {
        if (g_Pd.ProgressCallbacks[i].InUse) {
            slot = g_Pd.ProgressCallbacks[i];
            cb = (PFN_PD_PROGRESS_CALLBACK)slot.Callback;
            ReleaseSRWLockShared(&g_Pd.CallbackLock);
            cb(Current, Total, Path, slot.Context);
            AcquireSRWLockShared(&g_Pd.CallbackLock);
        }
    }
    ReleaseSRWLockShared(&g_Pd.CallbackLock);
}

static
VOID PdInvokeEntryCallbacks(PCWKD_PERSISTENCE_ENTRY Entry) {
    PD_CALLBACK_SLOT slot;
    PFN_PD_ENTRY_CALLBACK cb;

    AcquireSRWLockShared(&g_Pd.CallbackLock);
    for (ULONG i = 0; i < WKD_PD_MAX_CALLBACKS; i++) {
        if (g_Pd.EntryCallbacks[i].InUse) {
            slot = g_Pd.EntryCallbacks[i];
            cb = (PFN_PD_ENTRY_CALLBACK)slot.Callback;
            ReleaseSRWLockShared(&g_Pd.CallbackLock);
            cb(Entry, slot.Context);
            AcquireSRWLockShared(&g_Pd.CallbackLock);
        }
    }
    ReleaseSRWLockShared(&g_Pd.CallbackLock);
}

static
VOID PdInvokeAlertCallbacks(PCWKD_PERSISTENCE_ALERT Alert) {
    PD_CALLBACK_SLOT slot;
    PFN_PD_ALERT_CALLBACK cb;

    AcquireSRWLockShared(&g_Pd.CallbackLock);
    for (ULONG i = 0; i < WKD_PD_MAX_CALLBACKS; i++) {
        if (g_Pd.AlertCallbacks[i].InUse) {
            slot = g_Pd.AlertCallbacks[i];
            cb = (PFN_PD_ALERT_CALLBACK)slot.Callback;
            ReleaseSRWLockShared(&g_Pd.CallbackLock);
            cb(Alert, slot.Context);
            AcquireSRWLockShared(&g_Pd.CallbackLock);
        }
    }
    ReleaseSRWLockShared(&g_Pd.CallbackLock);
}

/* ==================================================
 * ═══ 实时分析 (SS AnalyzeRealTimeImpl 迁移) ═══
 * ================================================== */
static
NTSTATUS PdAnalyzeRealTimeInternal(_In_ PCWSTR KeyPath, _In_ PCWSTR ValueName,
                                   _In_opt_ const BYTE* Data, _In_ ULONG DataSize,
                                   _Out_ PWKD_REALTIME_ANALYSIS Analysis) {
    WCHAR cmd[WKD_PD_MAX_CMD_BUFFER + 1];
    WKD_PERSISTENCE_TARGET target;
    WKD_PERSISTENCE_ENTRY tempEntry;
    ULONG score = 0;

    memset(Analysis, 0, sizeof(*Analysis));
    InterlockedIncrement64(&g_Pd.Stats.RealTimeAnalyses);

    /* 命令提取: 对 REG_SZ / REG_EXPAND_SZ 类数据按宽串处理 */
    cmd[0] = L'\0';
    if (Data != NULL && DataSize > 0) {
        ULONG wchars = (Data != NULL && DataSize >= 2) ? (DataSize / 2) : 0;
        if (wchars > WKD_PD_MAX_CMD_BUFFER) wchars = WKD_PD_MAX_CMD_BUFFER;
        if (wchars > 0) {
            wcsncpy_s(cmd, _countof(cmd), (PCWSTR)Data, wchars);
        }
    }

    /* 已知持久化位置? */
    Analysis->DetectedType = PdIsPersistenceLocationImpl(KeyPath);
    Analysis->IsPersistenceAttempt = (Analysis->DetectedType != WkdRegPersist_Unknown);

    if (!Analysis->IsPersistenceAttempt) {
        return STATUS_SUCCESS;
    }
    InterlockedIncrement64(&g_Pd.Stats.PersistenceAttempts);

    /* 目标解析 */
    target = PdResolveTargetImpl(cmd);
    PdWcsCopyN(Analysis->ResolvedTarget, _countof(Analysis->ResolvedTarget), target.Path,
               _countof(Analysis->ResolvedTarget) - 1);

    /* 白名单优先 */
    memset(&tempEntry, 0, sizeof(tempEntry));
    tempEntry.Target = target;
    tempEntry.Type = Analysis->DetectedType;
    if (PdIsWhitelisted(&tempEntry)) {
        Analysis->Risk = WkdRegRisk_Safe;
        Analysis->RiskScore = 0;
        strcpy_s(Analysis->Recommendation, sizeof(Analysis->Recommendation), "Allow (whitelisted)");
        return STATUS_SUCCESS;
    }

    /* 哈希/信誉 (stub; HashStore 未接线) */
    if (target.Sha256Hex[0] != '\0') {
        PdEnrichWithHashLookup(&tempEntry);
        if (tempEntry.IsKnownBad) {
            Analysis->IsKnownBad = TRUE;
            strcpy_s(Analysis->Indicators[Analysis->IndicatorCount],
                     sizeof(Analysis->Indicators[0]), "Known malicious hash");
            Analysis->IndicatorCount++;
        }
    }

    /* 标志 */
    Analysis->IsSuspiciousLocation = PdIsSuspiciousPath(target.Path);
    Analysis->IsSuspiciousTarget = !target.Exists || target.InTempPath;
    Analysis->IsUnsigned = (target.SignatureStatus == WkdRegSig_NotSigned);

    if (Analysis->IsSuspiciousLocation && Analysis->IndicatorCount < WKD_PD_MAX_INDICATORS) {
        strcpy_s(Analysis->Indicators[Analysis->IndicatorCount], sizeof(Analysis->Indicators[0]),
                 "Suspicious file path");
        Analysis->IndicatorCount++;
    }
    if (Analysis->IsSuspiciousTarget && Analysis->IndicatorCount < WKD_PD_MAX_INDICATORS) {
        strcpy_s(Analysis->Indicators[Analysis->IndicatorCount], sizeof(Analysis->Indicators[0]),
                 "Target missing or in temp directory");
        Analysis->IndicatorCount++;
    }
    if (Analysis->IsUnsigned && Analysis->IndicatorCount < WKD_PD_MAX_INDICATORS) {
        strcpy_s(Analysis->Indicators[Analysis->IndicatorCount], sizeof(Analysis->Indicators[0]),
                 "Unsigned binary");
        Analysis->IndicatorCount++;
    }
    if (target.IsPacked && Analysis->IndicatorCount < WKD_PD_MAX_INDICATORS) {
        strcpy_s(Analysis->Indicators[Analysis->IndicatorCount], sizeof(Analysis->Indicators[0]),
                 "High entropy - possible packing");
        Analysis->IndicatorCount++;
    }
    if (target.HasAds && Analysis->IndicatorCount < WKD_PD_MAX_INDICATORS) {
        strcpy_s(Analysis->Indicators[Analysis->IndicatorCount], sizeof(Analysis->Indicators[0]),
                 "Alternate Data Stream detected");
        Analysis->IndicatorCount++;
    }
    if (PdIsLolBin(target.Path) && Analysis->IndicatorCount < WKD_PD_MAX_INDICATORS) {
        strcpy_s(Analysis->Indicators[Analysis->IndicatorCount], sizeof(Analysis->Indicators[0]),
                 "LOLBin usage detected");
        Analysis->IndicatorCount++;
    }

    /* 评分 */
    if (Analysis->IsKnownBad) {
        score = 100;
    } else {
        if (Analysis->IsSuspiciousLocation) score += 30;
        if (Analysis->IsSuspiciousTarget) score += 40;
        if (Analysis->IsUnsigned) score += 20;
        if (target.IsPacked) score += 25;
        if (target.HasAds) score += 30;
        if (PdIsLolBin(target.Path)) score += 25;
    }
    Analysis->RiskScore = (UCHAR)((score > 100) ? 100 : score);

    if (Analysis->RiskScore >= 70) {
        Analysis->Risk = WkdRegRisk_Malicious;
        strcpy_s(Analysis->Recommendation, sizeof(Analysis->Recommendation),
                 "Block this persistence attempt");
    } else if (Analysis->RiskScore >= 40) {
        Analysis->Risk = WkdRegRisk_Suspicious;
        strcpy_s(Analysis->Recommendation, sizeof(Analysis->Recommendation), "Alert and monitor");
    } else {
        Analysis->Risk = WkdRegRisk_Low;
        strcpy_s(Analysis->Recommendation, sizeof(Analysis->Recommendation), "Allow");
    }

    /* 告警触发 (AnalyzeRealTimeImpl: Suspicious 及以上且配置开启时生成) */
    if (Analysis->Risk == WkdRegRisk_Malicious ||
        (Analysis->Risk == WkdRegRisk_Suspicious && g_Pd.Config.AlertOnSuspicious)) {
        PdGenerateRealTimeAlert(KeyPath, ValueName, cmd, Analysis);
    }

    return STATUS_SUCCESS;
}

/* 实时告警生成 (SS GenerateRealTimeAlert 迁移) */
static
VOID PdGenerateRealTimeAlert(_In_ PCWSTR KeyPath, _In_ PCWSTR ValueName,
                             _In_ PCWSTR Data, _In_ PCWKD_REALTIME_ANALYSIS Analysis) {
    WKD_PERSISTENCE_ALERT alert;
    memset(&alert, 0, sizeof(alert));

    alert.AlertId = (ULONGLONG)InterlockedIncrement64(&g_Pd.NextAlertId);
    GetSystemTimeAsFileTime((LPFILETIME)&alert.Timestamp);
    alert.Type = Analysis->DetectedType;
    alert.Risk = Analysis->Risk;
    strcpy_s(alert.Description, sizeof(alert.Description), Analysis->Recommendation);
    PdWcsCopyN(alert.Location, _countof(alert.Location), KeyPath, _countof(alert.Location) - 1);
    PdWcsCopyN(alert.EntryName, _countof(alert.EntryName), ValueName, _countof(alert.EntryName) - 1);
    PdWcsCopyN(alert.Command, _countof(alert.Command), Data, _countof(alert.Command) - 1);
    PdWcsCopyN(alert.TargetPath, _countof(alert.TargetPath), Analysis->ResolvedTarget,
               _countof(alert.TargetPath) - 1);
    alert.Analysis = *Analysis;
    strcpy_s(alert.MitreTechnique, sizeof(alert.MitreTechnique),
             PdGetMitreTechnique(Analysis->DetectedType));
    alert.ProcessId = GetCurrentProcessId();

    InterlockedIncrement64(&g_Pd.Stats.AlertsGenerated);
    PdInvokeAlertCallbacks(&alert);
}

/* ==================================================
 * ═══ 全量扫描编排 (SS ScanImpl 迁移) ═══
 * 当前位置 → 服务 → 计划任务 → IFEO 子键 → WMI
 * ================================================== */
static
NTSTATUS PdScanInternal(_In_ WKD_REG_SCAN_SCOPE Scope,
                        _Out_ PWKD_SCAN_RESULT Result,
                        _In_ PWKD_PERSISTENCE_ENTRY EntryBuffer,
                        _In_ ULONG EntryCapacity) {
    NTSTATUS status = STATUS_SUCCESS;
    ULONG total = 0;
    ULONG currentLocation = 0;
    ULONG locationsScanned = 0;
    ULONG i;

    if (Result == NULL || EntryBuffer == NULL || EntryCapacity == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 串行互斥: 拒绝并发扫描 */
    if (!TryEnterCriticalSection(&g_Pd.ScanMutex)) {
        return STATUS_DEVICE_BUSY;
    }

    g_Pd.Scanning = TRUE;
    g_Pd.CancelRequested = FALSE;

    Result->StartTime = 0;
    Result->Scope = Scope;

    /* 1. 位置筛选 */
    for (i = 0; i < PD_LOCATION_COUNT; i++) {
        BOOLEAN shouldScan = FALSE;
        switch (Scope) {
            case WkdRegScope_Critical: shouldScan = g_PdLocations[i].Critical; break;
            case WkdRegScope_Standard:
            case WkdRegScope_Extended:
            case WkdRegScope_Full:
            case WkdRegScope_Custom:
            default: shouldScan = TRUE; break;
        }
        if (!shouldScan) continue;

        locationsScanned++;
        if (g_Pd.CancelRequested) break;

        currentLocation++;
        PdInvokeProgressCallbacks(currentLocation, locationsScanned, g_PdLocations[i].SubKey);

        {
            ULONG subCount = 0;
            status = PdScanRegistryLocation(&g_PdLocations[i], Scope,
                                            EntryBuffer + total,
                                            (total < EntryCapacity) ? (EntryCapacity - total) : 0,
                                            &subCount);
            total += subCount;
        }
    }
    Result->LocationsScanned = locationsScanned;

    /* 2. 服务 (Standard+) */
    if (Scope >= WkdRegScope_Standard && !g_Pd.CancelRequested) {
        WKD_SERVICE_ENTRY services[128];
        ULONG svcCount = 0;
        if (PdScanServicesImpl(services, _countof(services), &svcCount) == STATUS_SUCCESS) {
            for (ULONG k = 0; k < svcCount && total < EntryCapacity; k++) {
                PdServiceAsEntry(&services[k], &EntryBuffer[total]);
                total++;
            }
        }
    }

    /* 3. 计划任务 (Standard+) */
    if (Scope >= WkdRegScope_Standard && !g_Pd.CancelRequested) {
        WKD_SCHEDULED_TASK_ENTRY tasks[64];
        ULONG taskCount = 0;
        if (PdScanScheduledTasksImpl(tasks, _countof(tasks), &taskCount) == STATUS_SUCCESS) {
            for (ULONG k = 0; k < taskCount && total < EntryCapacity; k++) {
                PdTaskAsEntry(&tasks[k], &EntryBuffer[total]);
                total++;
            }
        }
    }

    /* 4. IFEO / SilentProcessExit 子键 (Standard+) */
    if (Scope >= WkdRegScope_Standard && !g_Pd.CancelRequested) {
        ULONG ifeoCount = 0;
        if (total < EntryCapacity) {
            PdScanIfeoSubkeys(EntryBuffer + total, EntryCapacity - total, &ifeoCount);
            total += ifeoCount;
        }
    }

    /* 5. WMI 订阅 (Extended+) */
    if (Scope >= WkdRegScope_Extended && !g_Pd.CancelRequested) {
        WKD_WMI_SUBSCRIPTION subs[32];
        ULONG subCount = 0;
        if (PdScanWmiSubscriptionsImpl(subs, _countof(subs), &subCount) == STATUS_SUCCESS) {
            for (ULONG k = 0; k < subCount && total < EntryCapacity; k++) {
                PdWmiAsEntry(&subs[k], &EntryBuffer[total]);
                total++;
            }
        }
    }

    /* 6. 汇总统计 */
    Result->TotalEntries = total;
    Result->EntryCount = total;
    Result->Entries = EntryBuffer;
    for (i = 0; i < total; i++) {
        PCWKD_PERSISTENCE_ENTRY e = &EntryBuffer[i];
        switch (e->Risk) {
            case WkdRegRisk_Safe:
            case WkdRegRisk_Low:   Result->SafeEntries++; break;
            case WkdRegRisk_Suspicious: Result->SuspiciousEntries++; break;
            case WkdRegRisk_Malicious:  Result->MaliciousEntries++; break;
            default:               Result->UnknownEntries++; break;
        }
        if (e->Status == WkdRegEntry_Orphaned) Result->OrphanedEntries++;
        InterlockedIncrement64(&g_Pd.Stats.EntriesScanned);
    }
    GetSystemTimeAsFileTime((LPFILETIME)&Result->EndTime);

    InterlockedIncrement64(&g_Pd.Stats.TotalScans);
    InterlockedIncrement64(&g_Pd.Stats.SafeEntriesFound);
    InterlockedIncrement64(&g_Pd.Stats.SuspiciousEntriesFound);
    InterlockedIncrement64(&g_Pd.Stats.MaliciousEntriesFound);

    g_Pd.Scanning = FALSE;
    LeaveCriticalSection(&g_Pd.ScanMutex);
    return status;
}

/* ==================================================
 * ═══ 公开 API 实现 ═══
 * (对齐 RegistryInternal.h 声明)
 * ================================================== */

_Use_decl_annotations_
NTSTATUS
PdInitialize(
    _In_opt_ const WKD_PERSISTENCE_CONFIG* Config
    ) {
    HRESULT hr;

    AcquireSRWLockExclusive(&g_Pd.ConfigLock);

    if (g_Pd.Initialized) {
        ReleaseSRWLockExclusive(&g_Pd.ConfigLock);
        return STATUS_SUCCESS;
    }

    /* 配置 */
    if (Config != NULL) {
        g_Pd.Config = *Config;
    } else {
        PdCreateDefaultConfig(&g_Pd.Config);
    }

    /* 统计清零 */
    memset(&g_Pd.Stats, 0, sizeof(g_Pd.Stats));
    g_Pd.NextCallbackId = 1;
    g_Pd.NextAlertId = 1;

    /* COM 初始化 (任务计划 + WMI) */
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) {
        g_Pd.ComInitialized = TRUE;
    } else if (hr == RPC_E_CHANGED_MODE) {
        /* 已以不同线程模型初始化 — 可接受 */
        g_Pd.ComInitialized = FALSE;
    } else {
        PdDbgPrint(L"[PD] COM initialization failed: 0x%x", (ULONG)hr);
        ReleaseSRWLockExclusive(&g_Pd.ConfigLock);
        return STATUS_UNSUCCESSFUL;
    }

    /* 锁初始化 (一次性) */
    InitializeSRWLock(&g_Pd.CacheLock);
    InitializeSRWLock(&g_Pd.CallbackLock);
    InitializeCriticalSection(&g_Pd.ScanMutex);
    memset(g_Pd.ProgressCallbacks, 0, sizeof(g_Pd.ProgressCallbacks));
    memset(g_Pd.EntryCallbacks, 0, sizeof(g_Pd.EntryCallbacks));
    memset(g_Pd.AlertCallbacks, 0, sizeof(g_Pd.AlertCallbacks));
    memset(g_Pd.TargetCache, 0, sizeof(g_Pd.TargetCache));
    g_Pd.TargetCacheCount = 0;
    memset(g_Pd.SignatureCache, 0, sizeof(g_Pd.SignatureCache));
    g_Pd.SignatureCacheCount = 0;

    InterlockedExchange(&g_Pd.Initialized, 1);
    ReleaseSRWLockExclusive(&g_Pd.ConfigLock);

    PdDbgPrint(L"[PD] Initialized (scope=%d resolve=%d sig=%d hash=%d)",
        (INT)g_Pd.Config.DefaultScope,
        g_Pd.Config.ResolveTargets ? 1 : 0,
        g_Pd.Config.VerifySignatures ? 1 : 0,
        g_Pd.Config.CheckHashes ? 1 : 0);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PdShutdown(
    VOID
    ) {
    AcquireSRWLockExclusive(&g_Pd.ConfigLock);

    if (!g_Pd.Initialized) {
        ReleaseSRWLockExclusive(&g_Pd.ConfigLock);
        return;
    }

    /* 清缓存与回调 */
    memset(g_Pd.TargetCache, 0, sizeof(g_Pd.TargetCache));
    g_Pd.TargetCacheCount = 0;
    memset(g_Pd.SignatureCache, 0, sizeof(g_Pd.SignatureCache));
    g_Pd.SignatureCacheCount = 0;
    memset(g_Pd.ProgressCallbacks, 0, sizeof(g_Pd.ProgressCallbacks));
    memset(g_Pd.EntryCallbacks, 0, sizeof(g_Pd.EntryCallbacks));
    memset(g_Pd.AlertCallbacks, 0, sizeof(g_Pd.AlertCallbacks));

    if (g_Pd.ComInitialized) {
        CoUninitialize();
        g_Pd.ComInitialized = FALSE;
    }

    DeleteCriticalSection(&g_Pd.ScanMutex);
    InterlockedExchange(&g_Pd.Initialized, 0);
    ReleaseSRWLockExclusive(&g_Pd.ConfigLock);
    PdDbgPrint(L"[PD] Shutdown complete");
}

_Use_decl_annotations_
BOOLEAN
PdIsInitialized(
    VOID
    ) {
    return (g_Pd.Initialized != 0);
}

_Use_decl_annotations_
VOID
PdCreateDefaultConfig(
    _Out_ PWKD_PERSISTENCE_CONFIG Config
    ) {
    if (Config == NULL) return;
    memset(Config, 0, sizeof(*Config));
    Config->DefaultScope = WkdRegScope_Standard;
    Config->MaxScanThreads = 4;
    Config->ScanTimeoutMs = PD_DEFAULT_TIMEOUT_MS;
    Config->ResolveTargets = TRUE;
    Config->VerifySignatures = TRUE;
    Config->CheckHashes = TRUE;
    Config->CheckReputation = TRUE;
    Config->DetectHidden = TRUE;
    Config->EnableRealTimeAnalysis = TRUE;
    Config->AlertOnSuspicious = TRUE;
    Config->AlertOnUnknown = FALSE;
    Config->UseCache = TRUE;
    Config->CacheTtlSeconds = WKD_REG_CACHE_TTL_SECONDS;
    Config->LogAllEntries = FALSE;
    Config->LogSuspiciousOnly = TRUE;
}

_Use_decl_annotations_
VOID
PdCreateQuickConfig(
    _Out_ PWKD_PERSISTENCE_CONFIG Config
    ) {
    if (Config == NULL) return;
    memset(Config, 0, sizeof(*Config));
    Config->DefaultScope = WkdRegScope_Critical;
    Config->MaxScanThreads = 4;
    Config->ScanTimeoutMs = PD_DEFAULT_TIMEOUT_MS;
    Config->ResolveTargets = TRUE;
    Config->VerifySignatures = FALSE;   /* 提速 */
    Config->CheckHashes = FALSE;
    Config->CheckReputation = FALSE;
    Config->DetectHidden = FALSE;
    Config->UseCache = TRUE;
    Config->LogSuspiciousOnly = TRUE;
}

_Use_decl_annotations_
VOID
PdCreateThoroughConfig(
    _Out_ PWKD_PERSISTENCE_CONFIG Config
    ) {
    if (Config == NULL) return;
    memset(Config, 0, sizeof(*Config));
    Config->DefaultScope = WkdRegScope_Extended;
    Config->MaxScanThreads = 8;
    Config->ScanTimeoutMs = PD_DEFAULT_TIMEOUT_MS;
    Config->ResolveTargets = TRUE;
    Config->VerifySignatures = TRUE;
    Config->CheckHashes = TRUE;
    Config->CheckReputation = TRUE;
    Config->DetectHidden = TRUE;
    Config->UseCache = TRUE;
    Config->LogSuspiciousOnly = TRUE;
}

_Use_decl_annotations_
VOID
PdCreateForensicConfig(
    _Out_ PWKD_PERSISTENCE_CONFIG Config
    ) {
    if (Config == NULL) return;
    memset(Config, 0, sizeof(*Config));
    Config->DefaultScope = WkdRegScope_Full;
    Config->MaxScanThreads = 16;
    Config->ScanTimeoutMs = PD_FORENSIC_TIMEOUT_MS;
    Config->ResolveTargets = TRUE;
    Config->VerifySignatures = TRUE;
    Config->CheckHashes = TRUE;
    Config->CheckReputation = TRUE;
    Config->DetectHidden = TRUE;
    Config->EnableRealTimeAnalysis = FALSE;
    Config->UseCache = TRUE;
    Config->LogAllEntries = TRUE;
    Config->LogSuspiciousOnly = FALSE;
}

_Use_decl_annotations_
NTSTATUS
PdScanAll(
    _Out_ PWKD_SCAN_RESULT Result
    ) {
    return PdScan(WkdRegScope_Standard, Result);
}

_Use_decl_annotations_
NTSTATUS
PdScanCritical(
    _Out_ PWKD_SCAN_RESULT Result
    ) {
    return PdScan(WkdRegScope_Critical, Result);
}

/* 前向声明 (实现次序: PdScanAll/Critical 依赖 PdScan) */
NTSTATUS
PdScan(
    _In_ WKD_REG_SCAN_SCOPE Scope,
    _Out_ PWKD_SCAN_RESULT Result
    );

_Use_decl_annotations_
NTSTATUS
PdScan(
    _In_ WKD_REG_SCAN_SCOPE Scope,
    _Out_ PWKD_SCAN_RESULT Result
    ) {
    /* 引擎内部条目缓冲: 动态按需 (上限 WKD_PD_MAX_SCAN_ENTRIES) */
    PWKD_PERSISTENCE_ENTRY entries = NULL;
    NTSTATUS status;

    if (Result == NULL) return STATUS_INVALID_PARAMETER;
    memset(Result, 0, sizeof(*Result));
    if (!g_Pd.Initialized) return STATUS_NOT_INITIALIZED;

    entries = (PWKD_PERSISTENCE_ENTRY)malloc(sizeof(WKD_PERSISTENCE_ENTRY) * WKD_PD_MAX_SCAN_ENTRIES);
    if (entries == NULL) return STATUS_NO_MEMORY;
    memset(entries, 0, sizeof(WKD_PERSISTENCE_ENTRY) * WKD_PD_MAX_SCAN_ENTRIES);

    status = PdScanInternal(Scope, Result, entries, WKD_PD_MAX_SCAN_ENTRIES);

    if (!NT_SUCCESS(status)) {
        free(entries);
        memset(Result, 0, sizeof(*Result));
        return status;
    }

    /* 条目缓冲移交 Result (调用方负责 PdFreeScanResult 释放) */
    Result->Entries = entries;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PdFreeScanResult(
    _Inout_ PWKD_SCAN_RESULT Result
    ) {
    if (Result == NULL) return;
    if (Result->Entries != NULL) {
        free(Result->Entries);
        Result->Entries = NULL;
    }
    Result->EntryCount = 0;
}

_Use_decl_annotations_
VOID
PdCancelScan(
    VOID
    ) {
    InterlockedExchange(&g_Pd.CancelRequested, 1);
}

_Use_decl_annotations_
WKD_REG_RISK_LEVEL
PdAnalyzeRealTime(
    _In_ PCWSTR KeyPath,
    _In_ PCWSTR ValueName,
    _In_opt_ const BYTE* Data,
    _In_ ULONG DataSize
    ) {
    WKD_REALTIME_ANALYSIS analysis;

    if (!g_Pd.Initialized) return WkdRegRisk_Unknown;
    if (PdAnalyzeRealTimeInternal(KeyPath, ValueName, Data, DataSize, &analysis) != STATUS_SUCCESS) {
        return WkdRegRisk_Unknown;
    }
    return analysis.Risk;
}

_Use_decl_annotations_
NTSTATUS
PdAnalyzeRealTimeFull(
    _In_ PCWSTR KeyPath,
    _In_ PCWSTR ValueName,
    _In_opt_ const BYTE* Data,
    _In_ ULONG DataSize,
    _Out_ PWKD_REALTIME_ANALYSIS Analysis
    ) {
    if (Analysis == NULL) return STATUS_INVALID_PARAMETER;
    if (!g_Pd.Initialized) return STATUS_NOT_INITIALIZED;
    return PdAnalyzeRealTimeInternal(KeyPath, ValueName, Data, DataSize, Analysis);
}

_Use_decl_annotations_
WKD_REG_PERSISTENCE_TYPE
PdIsPersistenceLocation(
    _In_ PCWSTR KeyPath
    ) {
    if (!g_Pd.Initialized) return WkdRegPersist_Unknown;
    return PdIsPersistenceLocationImpl(KeyPath);
}

_Use_decl_annotations_
NTSTATUS
PdResolveTarget(
    _In_ PCWSTR Command,
    _Out_ PWKD_PERSISTENCE_TARGET Target
    ) {
    if (Target == NULL) return STATUS_INVALID_PARAMETER;
    if (!g_Pd.Initialized) return STATUS_NOT_INITIALIZED;
    *Target = PdResolveTargetImpl(Command);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PdResolveComplexCommand(
    _In_ PCWSTR Command,
    _In_ ULONG MaxTargets,
    _Out_ PWKD_PERSISTENCE_TARGET Targets,
    _Out_ PULONG TargetCount
    ) {
    if (Targets == NULL || TargetCount == NULL || MaxTargets == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_Pd.Initialized) return STATUS_NOT_INITIALIZED;
    return PdResolveComplexCommandImpl(Command, Targets, MaxTargets, TargetCount);
}

_Use_decl_annotations_
NTSTATUS
PdScanServices(
    _In_ ULONG MaxEntries,
    _Out_ PWKD_SERVICE_ENTRY Entries,
    _Out_ PULONG EntryCount
    ) {
    if (Entries == NULL || EntryCount == NULL) return STATUS_INVALID_PARAMETER;
    if (!g_Pd.Initialized) return STATUS_NOT_INITIALIZED;
    return PdScanServicesImpl(Entries, MaxEntries, EntryCount);
}

_Use_decl_annotations_
NTSTATUS
PdGetService(
    _In_ PCWSTR ServiceName,
    _Out_ PWKD_SERVICE_ENTRY Entry
    ) {
    WKD_SERVICE_ENTRY services[128];
    ULONG count = 0;
    NTSTATUS status;

    if (ServiceName == NULL || Entry == NULL) return STATUS_INVALID_PARAMETER;
    if (!g_Pd.Initialized) return STATUS_NOT_INITIALIZED;

    status = PdScanServicesImpl(services, _countof(services), &count);
    if (!NT_SUCCESS(status)) return status;

    for (ULONG i = 0; i < count; i++) {
        if (PdWcsIEquals(services[i].ServiceName, ServiceName)) {
            *Entry = services[i];
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
PdScanScheduledTasks(
    _In_ ULONG MaxEntries,
    _Out_ PWKD_SCHEDULED_TASK_ENTRY Entries,
    _Out_ PULONG EntryCount
    ) {
    if (Entries == NULL || EntryCount == NULL) return STATUS_INVALID_PARAMETER;
    if (!g_Pd.Initialized) return STATUS_NOT_INITIALIZED;
    return PdScanScheduledTasksImpl(Entries, MaxEntries, EntryCount);
}

_Use_decl_annotations_
NTSTATUS
PdScanWmiSubscriptions(
    _In_ ULONG MaxEntries,
    _Out_ PWKD_WMI_SUBSCRIPTION Entries,
    _Out_ PULONG EntryCount
    ) {
    if (Entries == NULL || EntryCount == NULL) return STATUS_INVALID_PARAMETER;
    if (!g_Pd.Initialized) return STATUS_NOT_INITIALIZED;
    return PdScanWmiSubscriptionsImpl(Entries, MaxEntries, EntryCount);
}

_Use_decl_annotations_
ULONG
PdRegisterProgressCallback(
    _In_ PFN_PD_PROGRESS_CALLBACK Callback,
    _In_opt_ PVOID Context
    ) {
    ULONG id = 0;
    if (Callback == NULL) return 0;

    AcquireSRWLockExclusive(&g_Pd.CallbackLock);
    for (ULONG i = 0; i < WKD_PD_MAX_CALLBACKS; i++) {
        if (!g_Pd.ProgressCallbacks[i].InUse) {
            g_Pd.ProgressCallbacks[i].InUse = TRUE;
            g_Pd.ProgressCallbacks[i].Callback = (PVOID)Callback;
            g_Pd.ProgressCallbacks[i].Context = Context;
            g_Pd.ProgressCallbacks[i].Id =
                (ULONG)InterlockedIncrement64(&g_Pd.NextCallbackId);
            id = g_Pd.ProgressCallbacks[i].Id;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_Pd.CallbackLock);
    return id;
}

_Use_decl_annotations_
ULONG
PdRegisterEntryCallback(
    _In_ PFN_PD_ENTRY_CALLBACK Callback,
    _In_opt_ PVOID Context
    ) {
    ULONG id = 0;
    if (Callback == NULL) return 0;

    AcquireSRWLockExclusive(&g_Pd.CallbackLock);
    for (ULONG i = 0; i < WKD_PD_MAX_CALLBACKS; i++) {
        if (!g_Pd.EntryCallbacks[i].InUse) {
            g_Pd.EntryCallbacks[i].InUse = TRUE;
            g_Pd.EntryCallbacks[i].Callback = (PVOID)Callback;
            g_Pd.EntryCallbacks[i].Context = Context;
            g_Pd.EntryCallbacks[i].Id =
                (ULONG)InterlockedIncrement64(&g_Pd.NextCallbackId);
            id = g_Pd.EntryCallbacks[i].Id;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_Pd.CallbackLock);
    return id;
}

_Use_decl_annotations_
ULONG
PdRegisterAlertCallback(
    _In_ PFN_PD_ALERT_CALLBACK Callback,
    _In_opt_ PVOID Context
    ) {
    ULONG id = 0;
    if (Callback == NULL) return 0;

    AcquireSRWLockExclusive(&g_Pd.CallbackLock);
    for (ULONG i = 0; i < WKD_PD_MAX_CALLBACKS; i++) {
        if (!g_Pd.AlertCallbacks[i].InUse) {
            g_Pd.AlertCallbacks[i].InUse = TRUE;
            g_Pd.AlertCallbacks[i].Callback = (PVOID)Callback;
            g_Pd.AlertCallbacks[i].Context = Context;
            g_Pd.AlertCallbacks[i].Id =
                (ULONG)InterlockedIncrement64(&g_Pd.NextCallbackId);
            id = g_Pd.AlertCallbacks[i].Id;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_Pd.CallbackLock);
    return id;
}

_Use_decl_annotations_
BOOLEAN
PdUnregisterCallback(
    _In_ ULONG CallbackId
    ) {
    BOOLEAN removed = FALSE;

    if (CallbackId == 0) return FALSE;
    AcquireSRWLockExclusive(&g_Pd.CallbackLock);

    for (ULONG i = 0; i < WKD_PD_MAX_CALLBACKS; i++) {
        if (g_Pd.ProgressCallbacks[i].InUse && g_Pd.ProgressCallbacks[i].Id == CallbackId) {
            g_Pd.ProgressCallbacks[i].InUse = FALSE;
            removed = TRUE;
        }
        if (g_Pd.EntryCallbacks[i].InUse && g_Pd.EntryCallbacks[i].Id == CallbackId) {
            g_Pd.EntryCallbacks[i].InUse = FALSE;
            removed = TRUE;
        }
        if (g_Pd.AlertCallbacks[i].InUse && g_Pd.AlertCallbacks[i].Id == CallbackId) {
            g_Pd.AlertCallbacks[i].InUse = FALSE;
            removed = TRUE;
        }
    }
    ReleaseSRWLockExclusive(&g_Pd.CallbackLock);
    return removed;
}

_Use_decl_annotations_
VOID
PdGetStatistics(
    _Out_ PWKD_PERSISTENCE_STATS Statistics
    ) {
    if (Statistics == NULL) return;
    *Statistics = g_Pd.Stats;
}

_Use_decl_annotations_
VOID
PdResetStatistics(
    VOID
    ) {
    memset(&g_Pd.Stats, 0, sizeof(g_Pd.Stats));
}

_Use_decl_annotations_
BOOLEAN
PdPerformDiagnostics(
    VOID
    ) {
    HKEY hKey = NULL;
    SC_HANDLE hSCM = NULL;
    BOOLEAN ok = TRUE;

    if (!g_Pd.Initialized) return FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        ok = FALSE;
    } else {
        RegCloseKey(hKey);
    }

    if (ok) {
        hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        if (hSCM == NULL) {
            ok = FALSE;
        } else {
            CloseServiceHandle(hSCM);
        }
    }
    return ok;
}

/* 文本报告导出核心 (SS ExportDiagnostics / ExportScanReport 迁移) */
static
NTSTATUS PdWriteTextFile(_In_ PCWSTR OutputPath, _In_ PCSTR Content) {
    HANDLE hFile;
    DWORD written;

    if (OutputPath == NULL || Content == NULL) return STATUS_INVALID_PARAMETER;
    hFile = CreateFileW(OutputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return STATUS_ACCESS_DENIED;
    WriteFile(hFile, Content, (DWORD)strlen(Content), &written, NULL);
    CloseHandle(hFile);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PdExportDiagnostics(
    _In_ PCWSTR OutputPath
    ) {
    CHAR text[4096];
    CHAR line[512];

    if (OutputPath == NULL || !g_Pd.Initialized) return STATUS_NOT_INITIALIZED;

    strcpy_s(text, sizeof(text),
        "=== WkDefender PersistenceDetector Diagnostics ===\r\n");
    wsprintfA(line, "Total Scans: %I64d\r\n", g_Pd.Stats.TotalScans);
    strcat_s(text, sizeof(text), line);
    wsprintfA(line, "Entries Scanned: %I64d\r\n", g_Pd.Stats.EntriesScanned);
    strcat_s(text, sizeof(text), line);
    wsprintfA(line, "Locations Scanned: %I64d\r\n", g_Pd.Stats.LocationsScanned);
    strcat_s(text, sizeof(text), line);
    wsprintfA(line, "Safe Entries: %I64d\r\n", g_Pd.Stats.SafeEntriesFound);
    strcat_s(text, sizeof(text), line);
    wsprintfA(line, "Suspicious Entries: %I64d\r\n", g_Pd.Stats.SuspiciousEntriesFound);
    strcat_s(text, sizeof(text), line);
    wsprintfA(line, "Malicious Entries: %I64d\r\n", g_Pd.Stats.MaliciousEntriesFound);
    strcat_s(text, sizeof(text), line);
    wsprintfA(line, "Real-Time Analyses: %I64d\r\n", g_Pd.Stats.RealTimeAnalyses);
    strcat_s(text, sizeof(text), line);
    wsprintfA(line, "Persistence Attempts: %I64d\r\n", g_Pd.Stats.PersistenceAttempts);
    strcat_s(text, sizeof(text), line);
    wsprintfA(line, "Blocked Attempts: %I64d\r\n", g_Pd.Stats.BlockedAttempts);
    strcat_s(text, sizeof(text), line);
    wsprintfA(line, "Signatures Verified: %I64d\r\n", g_Pd.Stats.SignaturesVerified);
    strcat_s(text, sizeof(text), line);
    wsprintfA(line, "Hashes Checked: %I64d\r\n", g_Pd.Stats.HashesChecked);
    strcat_s(text, sizeof(text), line);
    wsprintfA(line, "Cache Hits: %I64d\r\n", g_Pd.Stats.CacheHits);
    strcat_s(text, sizeof(text), line);
    wsprintfA(line, "Alerts Generated: %I64d\r\n", g_Pd.Stats.AlertsGenerated);
    strcat_s(text, sizeof(text), line);

    return PdWriteTextFile(OutputPath, text);
}

_Use_decl_annotations_
NTSTATUS
PdExportScanReport(
    _In_ const WKD_SCAN_RESULT* Result,
    _In_ PCWSTR OutputPath
    ) {
    CHAR* text;
    SIZE_T capacity;
    SIZE_T len = 0;

    if (Result == NULL || OutputPath == NULL) return STATUS_INVALID_PARAMETER;

    /* 预算: 每个条目 ~256 字节 + 头部 1KB */
    capacity = 1024 + (SIZE_T)Result->EntryCount * 256;
    text = (CHAR*)malloc(capacity);
    if (text == NULL) return STATUS_NO_MEMORY;
    text[0] = '\0';

    {
        CHAR line[256];
        wsprintfA(line, "=== WkDefender Persistence Scan Report ===\r\n");
        strcat_s(text, capacity, line);
        wsprintfA(line, "Scope: %d\r\n", (INT)Result->Scope);
        strcat_s(text, capacity, line);
        wsprintfA(line, "Locations Scanned: %u\r\n", Result->LocationsScanned);
        strcat_s(text, capacity, line);
        wsprintfA(line, "Total Entries: %u\r\n", Result->TotalEntries);
        strcat_s(text, capacity, line);
        wsprintfA(line, "Safe: %u\r\n", Result->SafeEntries);
        strcat_s(text, capacity, line);
        wsprintfA(line, "Suspicious: %u\r\n", Result->SuspiciousEntries);
        strcat_s(text, capacity, line);
        wsprintfA(line, "Malicious: %u\r\n", Result->MaliciousEntries);
        strcat_s(text, capacity, line);
        wsprintfA(line, "Unknown: %u\r\n", Result->UnknownEntries);
        strcat_s(text, capacity, line);
        wsprintfA(line, "Orphaned: %u\r\n", Result->OrphanedEntries);
        strcat_s(text, capacity, line);
        wsprintfA(line, "Errors: 0\r\n\r\n");
        strcat_s(text, capacity, line);
    }

    for (ULONG i = 0; i < Result->EntryCount; i++) {
        PCWKD_PERSISTENCE_ENTRY e = &Result->Entries[i];
        CHAR loc[512];
        CHAR name[WKD_REG_MAX_NAME_CHARS * 3];
        CHAR cmd[WKD_PD_MAX_CMD_BUFFER + 32];
        CHAR targetPath[WKD_REG_MAX_PATH_CHARS * 3];
        CHAR line[2048];

        if (e->Risk < WkdRegRisk_Suspicious && !g_Pd.Config.LogAllEntries) continue;

        PdSanitizeForLogW(e->Location, loc, sizeof(loc));
        PdSanitizeForLogW(e->EntryName, name, sizeof(name));
        PdSanitizeForLogW(e->RawCommand, cmd, sizeof(cmd));
        PdSanitizeForLogW(e->Target.Path, targetPath, sizeof(targetPath));

        wsprintfA(line, "--- Entry %u ---\r\n  Type: %d\r\n  Location: %s\r\n  Name: %s\r\n"
                        "  Command: %s\r\n  Target: %s\r\n  Exists: %s\r\n  Risk: %d (Score: %u)\r\n"
                        "  MITRE: %s\r\n",
                  i, (INT)e->Type, loc, name, cmd, targetPath,
                  e->Target.Exists ? "Yes" : "No",
                  (INT)e->Risk, (UINT)e->RiskScore, e->MitreTechnique);
        len = strlen(text);
        if (len + strlen(line) + 64 < capacity) {
            strcat_s(text, capacity, line);
            if (e->Target.Sha256Hex[0] != '\0') {
                wsprintfA(line, "  SHA256: %s\r\n", e->Target.Sha256Hex);
                strcat_s(text, capacity, line);
            }
            if (e->Target.SignerName[0] != L'\0') {
                CHAR signer[WKD_PD_MAX_SIGNER_CHARS * 3];
                PdSanitizeForLogW(e->Target.SignerName, signer, sizeof(signer));
                wsprintfA(line, "  Signer: %s\r\n", signer);
                strcat_s(text, capacity, line);
            }
            for (ULONG f = 0; f < e->RiskFactorCount; f++) {
                if (e->RiskFactors[f][0] != '\0') {
                    wsprintfA(line, "  RiskFactor: %s\r\n", e->RiskFactors[f]);
                    strcat_s(text, capacity, line);
                }
            }
            strcat_s(text, capacity, "\r\n");
        }
    }

    (VOID)PdWriteTextFile(OutputPath, text);
    free(text);
    return STATUS_SUCCESS;
}

/* ==================================================
 * 引擎函数尾部: ScanPath / ScanType (SS 便捷扫描)
 * ================================================== */

_Use_decl_annotations_
NTSTATUS
PdScanPath(
    _In_ PCWSTR TargetPath,
    _Out_ PWKD_SCAN_RESULT Result
    ) {
    WKD_SCAN_RESULT fullResult;
    PWKD_PERSISTENCE_ENTRY matches = NULL;
    WCHAR lowerTarget[WKD_REG_MAX_PATH_CHARS];
    ULONG matchCount = 0;
    NTSTATUS status;

    if (TargetPath == NULL || Result == NULL) return STATUS_INVALID_PARAMETER;
    memset(Result, 0, sizeof(*Result));
    if (!g_Pd.Initialized) return STATUS_NOT_INITIALIZED;

    /* 全量扫描 (Extended) 后按目标路径过滤 (ScanPathImpl) */
    status = PdScan(WkdRegScope_Extended, &fullResult);
    if (!NT_SUCCESS(status)) return status;

    wcsncpy_s(lowerTarget, _countof(lowerTarget), TargetPath, _TRUNCATE);
    PdWcsToLower(lowerTarget);

    matches = (PWKD_PERSISTENCE_ENTRY)malloc(sizeof(WKD_PERSISTENCE_ENTRY) *
                                            (fullResult.EntryCount ? fullResult.EntryCount : 1));
    if (matches == NULL) {
        PdFreeScanResult(&fullResult);
        return STATUS_NO_MEMORY;
    }

    for (ULONG i = 0; i < fullResult.EntryCount; i++) {
        PWKD_PERSISTENCE_ENTRY e = &fullResult.Entries[i];
        WCHAR lower[WKD_REG_MAX_PATH_CHARS * 2];
        BOOLEAN hit = FALSE;

        wcsncpy_s(lower, _countof(lower), e->Target.Path, _TRUNCATE);
        PdWcsToLower(lower);
        if (wcsstr(lower, lowerTarget) != NULL) hit = TRUE;

        if (!hit) {
            for (ULONG a = 0; a < e->AdditionalTargetCount; a++) {
                wcsncpy_s(lower, _countof(lower), e->AdditionalTargets[a].Path, _TRUNCATE);
                PdWcsToLower(lower);
                if (wcsstr(lower, lowerTarget) != NULL) { hit = TRUE; break; }
            }
        }
        if (!hit) {
            wcsncpy_s(lower, _countof(lower), e->RawCommand, _TRUNCATE);
            if (PdWcsLen(lower) >= _countof(lower)) {
                lower[_countof(lower) - 1] = L'\0';
            }
            PdWcsToLower(lower);
            if (wcsstr(lower, lowerTarget) != NULL) hit = TRUE;
        }

        if (hit) {
            matches[matchCount++] = *e;
            if (matchCount >= WKD_PD_MAX_SCAN_ENTRIES) break;
        }
    }

    Result->Entries = matches;
    Result->EntryCount = matchCount;
    Result->TotalEntries = matchCount;
    GetSystemTimeAsFileTime((LPFILETIME)&Result->EndTime);
    Result->Scope = WkdRegScope_Extended;
    Result->LocationsScanned = fullResult.LocationsScanned;

    PdFreeScanResult(&fullResult);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PdScanType(
    _In_ WKD_REG_PERSISTENCE_TYPE Type,
    _Out_ PWKD_SCAN_RESULT Result
    ) {
    WKD_SCAN_RESULT fullResult;
    PWKD_PERSISTENCE_ENTRY matches = NULL;
    ULONG matchCount = 0;
    NTSTATUS status;

    if (Result == NULL) return STATUS_INVALID_PARAMETER;
    memset(Result, 0, sizeof(*Result));
    if (!g_Pd.Initialized) return STATUS_NOT_INITIALIZED;

    status = PdScan(WkdRegScope_Standard, &fullResult);
    if (!NT_SUCCESS(status)) return status;

    matches = (PWKD_PERSISTENCE_ENTRY)malloc(sizeof(WKD_PERSISTENCE_ENTRY) *
                                            (fullResult.EntryCount ? fullResult.EntryCount : 1));
    if (matches == NULL) {
        PdFreeScanResult(&fullResult);
        return STATUS_NO_MEMORY;
    }

    for (ULONG i = 0; i < fullResult.EntryCount; i++) {
        if (fullResult.Entries[i].Type == Type) {
            matches[matchCount++] = fullResult.Entries[i];
        }
    }

    Result->Entries = matches;
    Result->EntryCount = matchCount;
    Result->TotalEntries = matchCount;
    GetSystemTimeAsFileTime((LPFILETIME)&Result->EndTime);
    Result->Scope = fullResult.Scope;
    Result->LocationsScanned = fullResult.LocationsScanned;

    PdFreeScanResult(&fullResult);
    return STATUS_SUCCESS;
}