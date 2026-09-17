/**************************************************/
/*  WkDefender Agent — Registry\RegistryMonitor     */
/*  注册表实时监控 (The Gatekeeper)                  */
/*                                                   */
/*  迁移来源: ShadowStrike PhantomCore/Core/Registry */
/*  RegistryMonitor.cpp (2731 行, 2026-09-08)        */
/*                                                   */
/*  职责:                                            */
/*   - 事件裁决链: 隐写防护 → 自防御 → 规则 → 策略 →  */
/*     威胁检测 → 风险定级 → 告警 (含 FNV-1a 去重环)  */
/*   - 关键路径监控 (Run/Service/Winlogon/IFEO/      */
/*     COM/安全/网络) + 值内容分析 (熵/可执行/脚本/   */
/*     路径/URL/环境展开/多字符串/嵌入空字节)          */
/*   - 规则引擎 (优先级/过期/操作/类型/进程/用户条件)  */
/*   - 受保护键 (自防御) / 欺骗模式 (蜜罐)             */
/*                                                   */
/*  虚标剔除 (对齐迁移审计):                         */
/*   - 内核过滤端口 (FilterConnection/                */
/*     MessageDispatcher) + worker 消息泵 → stub;     */
/*     RmIsKernelConnected 恒 FALSE; 事件唯一入口为   */
/*     RmProcessEvent (调用方手动构造/喂入)            */
/*   - WhiteListStore / ThreatIntelLookup /           */
/*     ProcessUtils(进程 enrich) → 剔除               */
/*   - useUserModeHooks → 字段保留恒不生效            */
/*                                                   */
/*  迁移审计修复 (2026-09-14, P0-P2 批次):            */
/*   - P0-1 内嵌 NUL 隐写检测: 事件新增                */
/*     KeyPathCharCount/ValueNameCharCount 权威长度   */
/*     字段; RmContainsNullBytes 改长度界扫描          */
/*   - P0-2 规则过期判定: ExpiresAt 按 FILETIME 语义  */
/*     真实比较 (GetSystemTimeAsFileTime)             */
/*   - P1-1 post-op 降级: 隐写/自防御/规则/策略/检测   */
/*     五处 Block 在事后操作降级 Allow/Alert (对齐     */
/*     SS: resultVerdict = isPreOperation ? v : Allow)*/
/*   - P1-2 去重哈希混入威胁类型 (对齐 SS hash^threat) */
/*   - P1-3 低风险威胁 → Alert 裁决 + 告警             */
/*   - P1-4 RmAnalyzeValue 补全: EXPAND_SZ 两步展开/  */
/*     内嵌 NUL cloaking 风险/RiskFactors 聚合/URL     */
/*     提取; RmDetectThreat 补 COM_HIJACK/AMSI/ETW    */
/*   - P2-1 自防御键补 HKLM/HKEY_LOCAL_MACHINE 记法   */
/*     + Wow6432Node 变体                             */
/*   - P2-2 风险定级对齐源 (RunKey/ComHijack/Encoded/ */
/*     Powershell→Medium, Defender/Amsi/Etw→Critical) */
/*   - P2-3 回调耗时改 EMA + CAS Max (对齐 SS 128 窗)  */
/*   - P2-4 配置工厂语义对齐 (默认 Security/Txn 关,    */
/*     性能保留关键检测, 取证只观察不阻止)             */
/*                                                   */
/*  依赖 (WkD 底座): 无第三方库, 纯 Win32 + WkD 头    */
/**************************************************/

#include "RegistryInternal.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <wchar.h>
#include <string.h>
#include <math.h>
#include <strsafe.h>

/* ==================================================
 * 引擎私有常量
 * ================================================== */
#define RM_LOG_FIELD_CAP              1024        /* kMaxLogFieldChars */
#define RM_RECENT_EVENT_PREVIEW       256         /* 事件驻留数据预览上限 */
#define RM_RULE_NAME_CAP              256
#define RM_RULE_DESC_CAP              1024
#define RM_URL_MAX_UNITS              64
#define RM_EXPANDED_PATH_CAP          32767       /* ExpandEnvironmentStringsW 上限 */
#define RM_MULTI_SZ_ENTRY_CAP         1024

/* ==================================================
 * 引擎私有类型
 * ================================================== */

/* 回调槽 (对齐 PD_CALLBACK_SLOT) */
typedef struct _RM_CALLBACK_SLOT {
    ULONG   Id;
    BOOLEAN InUse;
    PVOID   Callback;
    PVOID   Context;
} RM_CALLBACK_SLOT, * PRM_CALLBACK_SLOT;

/* 告警去重环条目 (FNV-1a 事件哈希 + 毫秒时间戳) */
typedef struct _RM_DEDUP_ENTRY {
    ULONGLONG Hash;
    ULONGLONG LastSeenTick;
} RM_DEDUP_ENTRY, * PRM_DEDUP_ENTRY;

/* 引擎全局上下文 (PIMPL → 模块全局实例) */
typedef struct _WKD_RM_CONTEXT {
    /* 锁 */
    SRWLOCK Lock;               /* 状态/配置/规则/保护键/蜜罐/事件环/去重环 */
    SRWLOCK CallbackLock;       /* 回调表 (独立锁: 快照后锁外调用) */

    /* 状态 */
    volatile LONG Initialized;
    volatile LONG Running;
    volatile LONG KernelConnected;
    volatile LONG StopRequested;

    /* 配置与统计 */
    WKD_RM_CONFIG Config;
    WKD_RM_STATS  Stats;

    /* 策略回调 (单槽) */
    PFN_RM_POLICY_CALLBACK PolicyCallback;
    PVOID                  PolicyContext;

    /* 规则表 (懒分配动态缓冲) */
    PWKD_RM_RULE Rules;
    ULONG        RuleCount;
    ULONG        RuleCapacity;

    /* 受保护键 (动态集 + 小写并行缓存, 1:1 同步) */
    PWKD_RM_PROTECTED_KEY ProtectedKeys;
    PWSTR*                ProtectedKeysLower;
    ULONG                 ProtectedKeyCount;
    ULONG                 ProtectedKeyCapacity;

    /* 蜜罐键 (动态集) */
    PWSTR HoneypotKeys;
    ULONG HoneypotKeyCount;
    ULONG HoneypotKeyCapacity;

    /* 最近事件环形缓冲 (覆盖最旧; 驻留数据已截断) */
    PWKD_RM_EVENT RecentEvents;
    ULONG         RecentEventCount;
    ULONG         RecentEventCapacity;
    ULONG         RecentEventHead;    /* 最旧槽 */
    ULONG         RecentEventNext;    /* 下一写入槽 */

    /* 告警去重环 (固定大小 FIFO) */
    RM_DEDUP_ENTRY DedupRing[WKD_RM_DEDUP_RING_SIZE];
    ULONG          DedupSlotCount;
    ULONG          DedupNextSlot;

    /* 回调表 (Alert/Event/Value 三类, 共享 NextCallbackId) */
    RM_CALLBACK_SLOT AlertCallbacks[WKD_RM_MAX_CALLBACKS];
    RM_CALLBACK_SLOT EventCallbacks[WKD_RM_MAX_CALLBACKS];
    RM_CALLBACK_SLOT ValueCallbacks[WKD_RM_MAX_CALLBACKS];

    volatile ULONG       NextCallbackId;
    volatile ULONGLONG   NextRuleId;
    volatile ULONGLONG   NextAlertId;
} WKD_RM_CONTEXT, * PWKD_RM_CONTEXT;

static WKD_RM_CONTEXT g_Rm = { 0 };

/* ==================================================
 * 关键路径模式表 (匿名命名空间)
 * 路径采用内核记法 (\Registry\...); 匹配为大小写
 * 不敏感子串/前缀通配, 用户态 \Registry\Machine\...
 * 记法与  HKLM\... 的区别由上层事件构造保持一致。
 * ================================================== */

static const PCWSTR RM_PERSISTENCE_KEYS[] = {
    L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"\\Registry\\User\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\Registry\\User\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
    L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule",
};
#define RM_PERSISTENCE_KEY_COUNT (sizeof(RM_PERSISTENCE_KEYS) / sizeof(RM_PERSISTENCE_KEYS[0]))

static const PCWSTR RM_SECURITY_KEYS[] = {
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows Defender",
    L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy",
    L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\AMSI",
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger",
};
#define RM_SECURITY_KEY_COUNT (sizeof(RM_SECURITY_KEYS) / sizeof(RM_SECURITY_KEYS[0]))

static const PCWSTR RM_NETWORK_KEYS[] = {
    L"\\Registry\\User\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters",
};
#define RM_NETWORK_KEY_COUNT (sizeof(RM_NETWORK_KEYS) / sizeof(RM_NETWORK_KEYS[0]))

static const PCWSTR RM_COM_KEYS[] = {
    L"\\Registry\\User\\*\\Software\\Classes\\CLSID",
    L"\\Registry\\Machine\\SOFTWARE\\Classes\\CLSID",
    L"\\Registry\\Machine\\SOFTWARE\\Wow6432Node\\Classes\\CLSID",
};
#define RM_COM_KEY_COUNT (sizeof(RM_COM_KEYS) / sizeof(RM_COM_KEYS[0]))

/* 宽字符脚本签名标记 (REG_SZ/REG_EXPAND_SZ 常以 UTF-16 存储,
 * 窄扫描因零字节交错漏报, 需宽扫描) */
static const PCWSTR RM_SCRIPT_MARKERS_WIDE[] = {
    L"powershell", L"Invoke-", L"IEX",
    L"@echo", L"cmd.exe",
    L"WScript", L"CreateObject",
    L"ActiveXObject",
};
#define RM_SCRIPT_MARKERS_WIDE_COUNT (sizeof(RM_SCRIPT_MARKERS_WIDE) / sizeof(RM_SCRIPT_MARKERS_WIDE[0]))

/* ==================================================
 * 静态工具函数 (匿名命名空间辅助集)
 * ================================================== */

/* 日志输出 (开发排障: OutputDebugStringW; %I64u 支持 →
 * vswprintf_s, 对齐 RaDbgPrint) */
static
VOID RmDbgPrint(_In_ PCWSTR Format, ...) {
    WCHAR buf[512];
    va_list args;
    va_start(args, Format);
    (VOID)vswprintf_s(buf, 512, Format, args);
    va_end(args);
    OutputDebugStringW(buf);
}

static
ULONG RmWcsLen(_In_ PCWSTR S) {
    return (S != NULL) ? (ULONG)wcslen(S) : 0;
}

static
BOOLEAN RmWcsEmpty(_In_ PCWSTR S) {
    return (S == NULL || S[0] == L'\0');
}

static
VOID RmWcsCopy(_Inout_ PWSTR Dst, _In_ ULONG DstCch, _In_ PCWSTR Src) {
    if (Dst == NULL || DstCch == 0) return;
    if (Src == NULL) { Dst[0] = L'\0'; return; }
    wcsncpy_s(Dst, DstCch, Src, _TRUNCATE);
}

static
VOID RmWcsCopyN(_Inout_ PWSTR Dst, _In_ ULONG DstCch, _In_ PCWSTR Src, _In_ ULONG MaxLen) {
    if (Dst == NULL || DstCch == 0) return;
    if (Src == NULL) { Dst[0] = L'\0'; return; }
    ULONG n = (ULONG)wcslen(Src);
    if (n > MaxLen) n = MaxLen;
    if (n >= DstCch) n = DstCch - 1;
    wcsncpy_s(Dst, DstCch, Src, n);
}

/* 窄字符串拷贝 (截断) */
static
VOID RmCharCopy(_Inout_ PCHAR Dst, _In_ ULONG DstCch, _In_ PCSTR Src) {
    if (Dst == NULL || DstCch == 0) return;
    if (Src == NULL) { Dst[0] = '\0'; return; }
    strncpy_s(Dst, DstCch, Src, _TRUNCATE);
}

/* 大小写不敏感子串检索 (无需分配; 对齐 IContainsRaw 语义) */
static
BOOLEAN RmWcsIContains(_In_ PCWSTR Haystack, _In_ PCWSTR Needle) {
    if (Needle == NULL || Needle[0] == L'\0') return TRUE;
    if (Haystack == NULL) return FALSE;
    SIZE_T hLen = wcslen(Haystack);
    SIZE_T nLen = wcslen(Needle);
    if (hLen < nLen) return FALSE;
    for (SIZE_T i = 0; i <= hLen - nLen; ++i) {
        BOOLEAN match = TRUE;
        for (SIZE_T j = 0; j < nLen; ++j) {
            if (towlower(Haystack[i + j]) != towlower(Needle[j])) {
                match = FALSE;
                break;
            }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

/* 大小写不敏感前缀检索 */
static
BOOLEAN RmWcsIStartsWith(_In_ PCWSTR Haystack, _In_ PCWSTR Prefix) {
    if (Prefix == NULL || Prefix[0] == L'\0') return TRUE;
    if (Haystack == NULL) return FALSE;
    SIZE_T h = wcslen(Haystack), p = wcslen(Prefix);
    if (h < p) return FALSE;
    for (SIZE_T i = 0; i < p; ++i) {
        if (towlower(Haystack[i]) != towlower(Prefix[i])) return FALSE;
    }
    return TRUE;
}

/* 大小写不敏感相等比较 */
static
BOOLEAN RmWcsIEquals(_In_ PCWSTR A, _In_ PCWSTR B) {
    if (A == NULL || B == NULL) return (A == B);
    if (wcslen(A) != wcslen(B)) return FALSE;
    for (SIZE_T i = 0; A[i] != L'\0'; ++i) {
        if (towlower(A[i]) != towlower(B[i])) return FALSE;
    }
    return TRUE;
}

/* 小写宽串拷贝 */
static
VOID RmWcsToLowerCopy(_Inout_ PWSTR Dst, _In_ ULONG DstCch, _In_ PCWSTR Src) {
    RmWcsCopy(Dst, DstCch, Src);
    if (Dst == NULL || Dst[0] == L'\0') return;
    for (PWSTR p = Dst; *p != L'\0'; ++p) {
        *p = (WCHAR)towlower(*p);
    }
}

/* 嵌入空字节检测 (注册表键名隐写攻击)
 *
 * CharCount 为调用方提供的宽字符权威长度 (不含终止 NUL, 对齐 SS
 * wstring_view 语义)。在该长度界内扫描任何 \0 即判定为隐写:
 * 合法的键名/值名在 [0, CharCount) 内不包含空字节。
 * CharCount == 0 → 调用方未提供权威长度 (上层未填充长度字段),
 * 退化为 C 字符串语义 (仅检查首字符, 无法检出内嵌 NUL)。 */
static
BOOLEAN RmContainsNullBytes(_In_ PCWSTR Path, _In_ ULONG CharCount) {
    if (Path == NULL) return FALSE;
    if (CharCount == 0) {
        return (Path[0] == L'\0');
    }
    if (CharCount > WKD_RM_MAX_KEY_PATH_CHARS) {
        CharCount = WKD_RM_MAX_KEY_PATH_CHARS;
    }
    for (ULONG i = 0; i < CharCount; ++i) {
        if (Path[i] == L'\0') return TRUE;
    }
    return FALSE;
}

/* URL 前缀检查 (避免回调热路径上的 regex ReDoS 风险) */
static
BOOLEAN RmContainsUrlPrefix(_In_ PCSTR S) {
    if (S == NULL) return FALSE;
    CHAR lower[512];
    RmCharCopy(lower, 512, S);
    for (PCHAR p = lower; *p != '\0'; ++p) {
        *p = (CHAR)tolower((UCHAR)*p);
    }
    return (strstr(lower, "http://") != NULL ||
            strstr(lower, "https://") != NULL ||
            strstr(lower, "ftp://") != NULL);
}

/* --------------------------------------------------
 * 日志注入加固: 攻击者可控的路径/值名/进程路径可能携带
 * CR/LF/控制字符, 用于伪造日志行或投毒 SIEM 摄取;
 * 输出截断至 1024 字符防日志洪泛。
 * -------------------------------------------------- */
static
VOID RmSanitizeForLog(_In_ PCWSTR Wide, _Out_ PCHAR Out, _In_ ULONG OutCch) {
    if (Out == NULL || OutCch == 0) return;
    if (Wide == NULL) { Out[0] = '\0'; return; }
    /* 宽 → 窄 (系统 ANSI 代码页, ToNarrow) */
    int n = WideCharToMultiByte(CP_ACP, 0, Wide, -1, Out, (int)OutCch - 1, NULL, NULL);
    if (n <= 0) { Out[0] = '\0'; return; }
    Out[n] = '\0';
    SIZE_T len = (SIZE_T)n;
    if (len > RM_LOG_FIELD_CAP) {
        len = RM_LOG_FIELD_CAP;
        memcpy(Out + (len - 15), " ...<truncated>", 16);
    }
    for (SIZE_T i = 0; i < len && Out[i] != '\0'; ++i) {
        UCHAR uc = (UCHAR)Out[i];
        if (uc < 0x20 || uc == 0x7F) Out[i] = '?';
    }
    Out[len] = '\0';
}

/* FNV-1a 64 位事件哈希 (告警去重环; 抑制同一键上的重复告警洪泛,
 * 但裁决答复仍需每次发出 —— WkD 无内核答复, 对齐语义仅限用户面) */
static
ULONGLONG RmHashEventForDedup(_In_ ULONG Pid, _In_ ULONG Op,
                              _In_ PCWSTR KeyPath, _In_ PCWSTR ValueName) {
    ULONGLONG h = 0xcbf29ce484222325ULL;
    const UCHAR pidBytes[5] = {
        (UCHAR)(Pid & 0xFF), (UCHAR)((Pid >> 8) & 0xFF),
        (UCHAR)((Pid >> 16) & 0xFF), (UCHAR)((Pid >> 24) & 0xFF),
        (UCHAR)(Op & 0xFF),
    };
    for (ULONG i = 0; i < 5; ++i) { h ^= pidBytes[i]; h *= 0x100000001b3ULL; }
    if (KeyPath != NULL) {
        for (PCWSTR p = KeyPath; *p != L'\0'; ++p) {
            WCHAR lc = (WCHAR)towlower(*p);
            h ^= (UCHAR)(lc & 0xFF); h *= 0x100000001b3ULL;
            h ^= (UCHAR)((lc >> 8) & 0xFF); h *= 0x100000001b3ULL;
        }
    }
    h ^= 0xFF; h *= 0x100000001b3ULL;
    if (ValueName != NULL) {
        for (PCWSTR p = ValueName; *p != L'\0'; ++p) {
            WCHAR lc = (WCHAR)towlower(*p);
            h ^= (UCHAR)(lc & 0xFF); h *= 0x100000001b3ULL;
            h ^= (UCHAR)((lc >> 8) & 0xFF); h *= 0x100000001b3ULL;
        }
    }
    return h;
}

/* 进程可执行名 ("filename.exe") 提取 (对齐 ProcessBaseName) */
static
VOID RmProcessBaseName(_In_ PCWSTR FullPath, _Out_ PCHAR Out, _In_ ULONG OutCch) {
    if (Out == NULL || OutCch == 0) return;
    Out[0] = '\0';
    if (FullPath == NULL) return;
    SIZE_T len = wcslen(FullPath);
    SIZE_T pos = len;
    for (SIZE_T i = len; i > 0; --i) {
        if (FullPath[i - 1] == L'\\' || FullPath[i - 1] == L'/') { pos = i; break; }
    }
    if (pos >= len) return;
    int n = WideCharToMultiByte(CP_ACP, 0, FullPath + pos, -1, Out, (int)OutCch - 1, NULL, NULL);
    if (n > 0) Out[n] = '\0';
}

/* 事件驻留截断 (对齐 TruncateEventForRetention: 数据预览 256 B) */
static
VOID RmTruncateEventForRetention(_Inout_ PWKD_RM_EVENT Event) {
    if (Event == NULL) return;
    if (Event->ValueDataSize > RM_RECENT_EVENT_PREVIEW) {
        Event->ValueDataSize = RM_RECENT_EVENT_PREVIEW;
    }
}

/* 通配模式匹配: 无 '*' → 子串检索; 有 '*' → 前缀+后缀子串
 * (MatchesRegistryKeyPattern: 单一 '*' 语义) */
static
BOOLEAN RmMatchesRegistryKeyPattern(_In_ PCWSTR LowerPath, _In_ PCWSTR Pattern) {
    if (LowerPath == NULL || Pattern == NULL) return FALSE;
    WCHAR lowerPattern[WKD_RM_MAX_KEY_PATH_CHARS];
    RmWcsToLowerCopy(lowerPattern, WKD_RM_MAX_KEY_PATH_CHARS, Pattern);

    const PWSTR star = wcschr(lowerPattern, L'*');
    if (star == NULL) {
        return (wcsstr(LowerPath, lowerPattern) != NULL);
    }
    SIZE_T prefixLen = (SIZE_T)(star - lowerPattern);
    SIZE_T suffixLen = wcslen(star + 1);

    WCHAR prefix[WKD_RM_MAX_KEY_PATH_CHARS];
    if (prefixLen > 0 && prefixLen < WKD_RM_MAX_KEY_PATH_CHARS) {
        wcsncpy_s(prefix, WKD_RM_MAX_KEY_PATH_CHARS, lowerPattern, prefixLen);
        prefix[prefixLen] = L'\0';
    } else {
        prefix[0] = L'\0';
    }

    const PWSTR prefixPos = (prefix[0] != L'\0') ? wcsstr(LowerPath, prefix) : (PWSTR)LowerPath;
    if (prefixPos == NULL) return FALSE;
    if (suffixLen == 0) return TRUE;

    WCHAR suffix[WKD_RM_MAX_KEY_PATH_CHARS];
    wcsncpy_s(suffix, WKD_RM_MAX_KEY_PATH_CHARS, star + 1, suffixLen);
    suffix[suffixLen] = L'\0';

    SIZE_T searchFrom = (SIZE_T)(prefixPos - LowerPath) + prefixLen;
    if (searchFrom > wcslen(LowerPath)) return FALSE;
    return (wcsstr(LowerPath + searchFrom, suffix) != NULL);
}

/* 宽串内嵌空字节前的有效长度 (REG_SZ 常带尾部 NUL) */
static
SIZE_T RmWcsTrimTrailingNulls(_In_ const WCHAR* Base, _In_ SIZE_T CharCount) {
    SIZE_T n = CharCount;
    while (n > 0 && Base[n - 1] == L'\0') --n;
    return n;
}

/* 脚本签名检查 (宽) — REG_SZ/EXPAND_SZ/MULTI_SZ UTF-16 载荷 */
static
BOOLEAN RmContainsScriptSignatureWide(_In_ PCWSTR Value) {
    if (Value == NULL || wcslen(Value) < 5) return FALSE;
    for (ULONG i = 0; i < RM_SCRIPT_MARKERS_WIDE_COUNT; ++i) {
        if (RmWcsIContains(Value, RM_SCRIPT_MARKERS_WIDE[i])) return TRUE;
    }
    return FALSE;
}

/* 脚本签名检查 (窄) — REG_BINARY 原始字节载荷 */
static
BOOLEAN RmContainsScriptSignature(_In_ const BYTE* Data, _In_ SIZE_T Size) {
    if (Data == NULL || Size < 10) return FALSE;
    CHAR str[101];
    SIZE_T n = (Size < 100) ? Size : 100;
    memcpy(str, Data, n);
    str[n] = '\0';
    return (strstr(str, "powershell") != NULL ||
            strstr(str, "Invoke-") != NULL ||
            strstr(str, "IEX") != NULL ||
            strstr(str, "@echo") != NULL ||
            strstr(str, "cmd.exe") != NULL ||
            strstr(str, "WScript") != NULL ||
            strstr(str, "CreateObject") != NULL ||
            strstr(str, "ActiveXObject") != NULL);
}

/* 熵计算 (Shannon, 对输入全量) */
static
DOUBLE RmCalculateEntropy(_In_ const BYTE* Data, _In_ SIZE_T Size) {
    if (Data == NULL || Size == 0) return 0.0;
    ULONGLONG frequency[256];
    memset(frequency, 0, sizeof(frequency));
    for (SIZE_T i = 0; i < Size; ++i) {
        frequency[Data[i]]++;
    }
    DOUBLE entropy = 0.0;
    DOUBLE dataSize = (DOUBLE)Size;
    for (ULONG i = 0; i < 256; ++i) {
        if (frequency[i] > 0) {
            DOUBLE probability = (DOUBLE)frequency[i] / dataSize;
            entropy -= probability * log2(probability);
        }
    }
    return entropy;
}

/* 可执行签名 (MZ / PE\0\0) */
static
BOOLEAN RmContainsExecutableSignature(_In_ const BYTE* Data, _In_ SIZE_T Size) {
    if (Data == NULL || Size < 2) return FALSE;
    if (Data[0] == 'M' && Data[1] == 'Z') return TRUE;
    if (Size >= 4 && Data[0] == 'P' && Data[1] == 'E' && Data[2] == 0 && Data[3] == 0) {
        return TRUE;
    }
    return FALSE;
}

/* 路径形字符串 (C:\... / \\... 需 ≥3 字符) */
static
BOOLEAN RmIsPathLike(_In_ PCWSTR Str) {
    if (Str == NULL || wcslen(Str) < 3) return FALSE;
    if (Str[1] == L':' && Str[2] == L'\\') return TRUE;
    if (Str[0] == L'\\' && Str[1] == L'\\') return TRUE;
    return FALSE;
}

/* ==================================================
 * ═══ 事件辅助 (RegistryEvent 的
 *     isPersistenceKey / isServiceKey / ... )
 *     匹配为大小写不敏感子串语义; 键表含通配符
 *     \Registry\User\* 时, 子串匹配即命中所有用户前缀。
 * ================================================== */

BOOLEAN
RmEventIsPersistenceKey(_In_ PCWKD_RM_EVENT Event) {
    if (Event == NULL) return FALSE;
    for (ULONG i = 0; i < RM_PERSISTENCE_KEY_COUNT; ++i) {
        if (RmWcsIContains(Event->KeyPath, RM_PERSISTENCE_KEYS[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
RmEventIsServiceKey(_In_ PCWKD_RM_EVENT Event) {
    if (Event == NULL) return FALSE;
    /* 要求子键级匹配 (\Services\) 以避免"创建 Services 本身"误报 */
    return RmWcsIContains(Event->KeyPath, L"\\SYSTEM\\CurrentControlSet\\Services\\");
}

BOOLEAN
RmEventIsSecurityKey(_In_ PCWKD_RM_EVENT Event) {
    if (Event == NULL) return FALSE;
    for (ULONG i = 0; i < RM_SECURITY_KEY_COUNT; ++i) {
        if (RmWcsIContains(Event->KeyPath, RM_SECURITY_KEYS[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
RmEventIsComKey(_In_ PCWKD_RM_EVENT Event) {
    if (Event == NULL) return FALSE;
    for (ULONG i = 0; i < RM_COM_KEY_COUNT; ++i) {
        if (RmWcsIContains(Event->KeyPath, RM_COM_KEYS[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
RmEventIsNetworkKey(_In_ PCWKD_RM_EVENT Event) {
    if (Event == NULL) return FALSE;
    for (ULONG i = 0; i < RM_NETWORK_KEY_COUNT; ++i) {
        if (RmWcsIContains(Event->KeyPath, RM_NETWORK_KEYS[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
RmIsCriticalKey(_In_ PCWSTR KeyPath) {
    if (KeyPath == NULL) return FALSE;
    for (ULONG i = 0; i < RM_PERSISTENCE_KEY_COUNT; ++i) {
        if (RmWcsIContains(KeyPath, RM_PERSISTENCE_KEYS[i])) return TRUE;
    }
    for (ULONG i = 0; i < RM_SECURITY_KEY_COUNT; ++i) {
        if (RmWcsIContains(KeyPath, RM_SECURITY_KEYS[i])) return TRUE;
    }
    for (ULONG i = 0; i < RM_NETWORK_KEY_COUNT; ++i) {
        if (RmWcsIContains(KeyPath, RM_NETWORK_KEYS[i])) return TRUE;
    }
    for (ULONG i = 0; i < RM_COM_KEY_COUNT; ++i) {
        if (RmWcsIContains(KeyPath, RM_COM_KEYS[i])) return TRUE;
    }
    return FALSE;
}

ULONG
RmEventGetCategory(_In_ PCWKD_RM_EVENT Event) {
    if (Event == NULL) return WkdRmCategory_Unknown;
    if (RmIsCriticalKey(Event->KeyPath)) {
        if (RmEventIsServiceKey(Event)) return WkdRmCategory_Persistence;
        if (RmEventIsSecurityKey(Event)) return WkdRmCategory_Security;
        if (RmEventIsNetworkKey(Event)) return WkdRmCategory_Network;
        if (RmEventIsComKey(Event)) return WkdRmCategory_Com;
        if (RmWcsIContains(Event->KeyPath, L"\\Shell\\") ||
            RmWcsIContains(Event->KeyPath, L"\\ShellExecuteHooks\\")) {
            return WkdRmCategory_Shell;
        }
        return WkdRmCategory_Persistence;
    }
    /* 孤立键 (非 \Registry\ 前缀 — 用户态手工构造域外事件) */
    if (wcsstr(Event->KeyPath, L"\\Registry\\") == NULL) {
        return WkdRmCategory_Application;
    }
    return WkdRmCategory_Unknown;
}

VOID
RmEventGetHive(_In_ PCWKD_RM_EVENT Event,
               _Out_writes_(MaxCch) PWSTR Hive,
               _In_ ULONG MaxCch) {
    static const PWSTR hklm = L"HKLM";
    static const PWSTR hkcu = L"HKCU";
    static const PWSTR hku = L"HKU";
    static const PWSTR hkcr = L"HKCR";
    static const PWSTR hkcc = L"HKCC";
    static const PWSTR unknown = L"Unknown";

    PWSTR result = (PWSTR)unknown;
    if (Event != NULL) {
        if (RmWcsIStartsWith(Event->KeyPath, L"\\Registry\\Machine\\")) {
            if (RmWcsIStartsWith(Event->KeyPath,
                                 L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Hardware\\")) {
                result = (PWSTR)hkcc;
            } else if (RmWcsIStartsWith(Event->KeyPath,
                                        L"\\Registry\\Machine\\SOFTWARE\\Classes\\")) {
                result = (PWSTR)hkcr;
            } else {
                result = (PWSTR)hklm;
            }
        } else if (RmWcsIStartsWith(Event->KeyPath, L"\\Registry\\User\\")) {
            if (RmWcsIStartsWith(Event->KeyPath, L"\\Registry\\Users\\") ||
                RmWcsIContains(Event->KeyPath, L"\\\\.DEFAULT\\")) {
                result = (PWSTR)hku;
            } else {
                result = (PWSTR)hkcu;
            }
        }
        /* \Registry\Classes 等非标准前缀 → Unknown */
    }
    RmWcsCopy(Hive, MaxCch, result);
}

/* ==================================================
 * ═══ 统计内部清零 (生命周期与 ISR 取消钩子共用)
 * ================================================== */
static
VOID RmResetStatsInternal(VOID) {
    ZeroMemory(&g_Rm.Stats, sizeof(g_Rm.Stats));
}

/* ==================================================
 * ═══ 配置工厂 (createDefaultConfig 等)
 *
 *  对齐 SS CreateDefault 语义: MonitorSecurity / 
 *  MonitorTransactions 默认关闭 (安全键仍经由
 *  DetectThreat 检测链覆盖, 双通道冗余设计);
 *  高安全/取证工厂显式开启。
 * ================================================== */

static
VOID RmApplyCommonBaseline(_Out_ PWKD_RM_CONFIG Config) {
    ZeroMemory(Config, sizeof(*Config));
    Config->Enabled               = TRUE;
    Config->UseKernelCallback     = TRUE;
    Config->UseUserModeHooks      = FALSE;   /* WkD 无挂钩设施 */
    Config->MonitorCreateKey      = TRUE;
    Config->MonitorSetValue       = TRUE;
    Config->MonitorDeleteKey      = TRUE;
    Config->MonitorDeleteValue    = TRUE;
    Config->MonitorRename         = TRUE;
    Config->MonitorLoadHive       = TRUE;
    Config->MonitorSecurity       = FALSE;   /* 对齐 SS 默认 */
    Config->MonitorTransactions   = FALSE;   /* 对齐 SS 默认 */
    Config->AnalyzeValues         = TRUE;
    Config->DetectFileless        = TRUE;
    Config->DetectPersistence     = TRUE;
    Config->DetectSecurityChanges = TRUE;
    Config->LargeValueThreshold   = WKD_RM_LARGE_VALUE_THRESHOLD;
    Config->SelfDefenseEnabled    = TRUE;
    Config->ProtectWkDefenderKeys = TRUE;
    Config->EventQueueSize        = WKD_RM_EVENT_QUEUE_SIZE;
    Config->CallbackTimeoutMs     = WKD_RM_CALLBACK_TIMEOUT_MS;
    Config->LogAllOperations      = FALSE;
    Config->LogBlockedOnly        = TRUE;
    Config->LogPersistenceKeys    = TRUE;
}

VOID
RmCreateDefaultConfig(_Out_ PWKD_RM_CONFIG Config) {
    if (Config == NULL) return;
    RmApplyCommonBaseline(Config);
    Config->WorkerThreads = 4;
    Config->Deception.Enabled          = FALSE;
    Config->Deception.SilentDropEnabled = FALSE;
    Config->Deception.HoneypotEnabled  = FALSE;
    Config->Deception.FakeSuccessEnabled = FALSE;
}

VOID
RmCreateHighSecurityConfig(_Out_ PWKD_RM_CONFIG Config) {
    if (Config == NULL) return;
    RmApplyCommonBaseline(Config);
    Config->MonitorSecurity       = TRUE;   /* 显式开启 (对齐 SS) */
    Config->MonitorTransactions   = TRUE;   /* 显式开启 (对齐 SS) */
    Config->LargeValueThreshold   = 32 * 1024;  /* 更激进 (对齐 SS) */
    Config->WorkerThreads         = 8;
    Config->Deception.Enabled            = TRUE;
    Config->Deception.SilentDropEnabled  = TRUE;
    Config->Deception.HoneypotEnabled    = TRUE;
    Config->Deception.FakeSuccessEnabled = TRUE;
    Config->LogAllOperations             = TRUE;
    Config->LogBlockedOnly               = FALSE;
}

VOID
RmCreatePerformanceConfig(_Out_ PWKD_RM_CONFIG Config) {
    if (Config == NULL) return;
    RmApplyCommonBaseline(Config);
    /* 降耗配置 (对齐 SS CreatePerformance): 关闭内容分析与部分
     * 监测, 保留持久化/安全关键检测; 关闭值级与安全/事务监测 */
    Config->MonitorDeleteValue     = FALSE;
    Config->MonitorRename          = FALSE;
    Config->MonitorLoadHive        = FALSE;
    Config->MonitorSecurity        = FALSE;
    Config->MonitorTransactions    = FALSE;
    Config->AnalyzeValues          = FALSE;
    Config->DetectFileless         = FALSE;
    Config->DetectPersistence      = TRUE;   /* 保留关键检测 (对齐 SS) */
    Config->DetectSecurityChanges  = TRUE;   /* 保留关键检测 (对齐 SS) */
    Config->EventQueueSize         = 20000;  /* 大队列 (对齐 SS) */
    Config->WorkerThreads          = 4;      /* 多工作者 (对齐 SS) */
    Config->LogAllOperations       = FALSE;
    Config->LogBlockedOnly         = TRUE;
    Config->LogPersistenceKeys     = FALSE;  /* 对齐 SS 降噪 */
}

VOID
RmCreateForensicConfig(_Out_ PWKD_RM_CONFIG Config) {
    if (Config == NULL) return;
    RmApplyCommonBaseline(Config);
    /* 取证模式 (对齐 SS CreateForensic): 全量记录, 禁静默丢弃;
     * 不阻止操作, 只观察 (SelfDefenseEnabled=FALSE) */
    Config->MonitorSecurity       = TRUE;
    Config->MonitorTransactions   = TRUE;
    Config->SelfDefenseEnabled    = FALSE;   /* 对齐 SS: 只观察不阻止 */
    Config->WorkerThreads         = 16;
    Config->Deception.Enabled     = FALSE;   /* 取证要求真实结果 */
    Config->LogAllOperations      = TRUE;
    Config->LogBlockedOnly        = FALSE;
    Config->LogPersistenceKeys    = TRUE;
}

/* ==================================================
 * ═══ 生命周期
 * ================================================== */

static
BOOLEAN RmIsInitialized(VOID) {
    return (InterlockedCompareExchange(&g_Rm.Initialized, 0, 0) != 0);
}

BOOLEAN
RmInitialize(_In_opt_ PCWKD_RM_CONFIG Config) {
    /* 可重入: 先整体清场 */
    RmShutdown();

    WKD_RM_CONFIG cfg;
    if (Config == NULL) {
        RmCreateDefaultConfig(&cfg);
    } else {
        cfg = *Config;
    }

    /* 输入钳制: 阈值必须落在有效域 */
    if (cfg.LargeValueThreshold == 0 ||
        cfg.LargeValueThreshold > WKD_RM_MAX_VALUE_DATA_SIZE) {
        cfg.LargeValueThreshold = WKD_RM_LARGE_VALUE_THRESHOLD;
    }
    if (cfg.WorkerThreads > WKD_RM_MAX_WORKER_THREADS) {
        cfg.WorkerThreads = WKD_RM_MAX_WORKER_THREADS;
    }
    if (cfg.CallbackTimeoutMs == 0) {
        cfg.CallbackTimeoutMs = WKD_RM_CALLBACK_TIMEOUT_MS;
    }

    AcquireSRWLockExclusive(&g_Rm.Lock);
    g_Rm.Config = cfg;
    g_Rm.Initialized = 1;
    g_Rm.Running = 0;
    g_Rm.KernelConnected = 0;
    g_Rm.StopRequested = 0;
    g_Rm.NextRuleId = 1;
    g_Rm.NextAlertId = 1;
    RmResetStatsInternal();
    ReleaseSRWLockExclusive(&g_Rm.Lock);

    RmDbgPrint(L"[RM] registry monitor initialized (v%d.%d.%d)",
               WKD_RM_VERSION_MAJOR, WKD_RM_VERSION_MINOR, WKD_RM_VERSION_PATCH);
    return TRUE;
}

BOOLEAN
RmStart(VOID) {
    if (!RmIsInitialized()) {
        RmDbgPrint(L"[RM] start rejected: not initialized");
        return FALSE;
    }
    AcquireSRWLockExclusive(&g_Rm.Lock);
    if (g_Rm.Running) {
        ReleaseSRWLockExclusive(&g_Rm.Lock);
        return TRUE;    /* 幂等 */
    }
    g_Rm.Running = 1;
    g_Rm.StopRequested = 0;
    /* 内核过滤端口未迁移: 对外连接恒失败, 事件由上层经
     * RmProcessEvent 手动喂入 (对齐迁移审计 stub 决策) */
    g_Rm.KernelConnected = 0;
    ReleaseSRWLockExclusive(&g_Rm.Lock);

    RmDbgPrint(L"[RM] registry monitor started (kernel callback interface not connected - stub)");
    return TRUE;
}

VOID
RmStop(VOID) {
    if (!RmIsInitialized()) return;
    AcquireSRWLockExclusive(&g_Rm.Lock);
    g_Rm.Running = 0;
    g_Rm.KernelConnected = 0;
    g_Rm.StopRequested = 1;
    ReleaseSRWLockExclusive(&g_Rm.Lock);
    RmDbgPrint(L"[RM] registry monitor stopped");
}

VOID
RmShutdown(VOID) {
    AcquireSRWLockExclusive(&g_Rm.Lock);
    g_Rm.Initialized = 0;
    g_Rm.Running = 0;
    g_Rm.KernelConnected = 0;
    g_Rm.StopRequested = 0;
    g_Rm.PolicyCallback = NULL;
    g_Rm.PolicyContext = NULL;
    g_Rm.DedupSlotCount = 0;
    g_Rm.DedupNextSlot = 0;
    g_Rm.RecentEventCount = 0;
    g_Rm.RecentEventHead = 0;
    g_Rm.RecentEventNext = 0;

    if (g_Rm.Rules != NULL) {
        HeapFree(GetProcessHeap(), 0, g_Rm.Rules);
        g_Rm.Rules = NULL;
    }
    g_Rm.RuleCount = 0;
    g_Rm.RuleCapacity = 0;

    if (g_Rm.ProtectedKeys != NULL) {
        HeapFree(GetProcessHeap(), 0, g_Rm.ProtectedKeys);
        g_Rm.ProtectedKeys = NULL;
    }
    if (g_Rm.ProtectedKeysLower != NULL) {
        for (ULONG i = 0; i < g_Rm.ProtectedKeyCapacity; ++i) {
            if (g_Rm.ProtectedKeysLower[i] != NULL) {
                HeapFree(GetProcessHeap(), 0, g_Rm.ProtectedKeysLower[i]);
            }
        }
        HeapFree(GetProcessHeap(), 0, g_Rm.ProtectedKeysLower);
        g_Rm.ProtectedKeysLower = NULL;
    }
    g_Rm.ProtectedKeyCount = 0;
    g_Rm.ProtectedKeyCapacity = 0;

    if (g_Rm.HoneypotKeys != NULL) {
        HeapFree(GetProcessHeap(), 0, g_Rm.HoneypotKeys);
        g_Rm.HoneypotKeys = NULL;
    }
    g_Rm.HoneypotKeyCount = 0;
    g_Rm.HoneypotKeyCapacity = 0;

    if (g_Rm.RecentEvents != NULL) {
        HeapFree(GetProcessHeap(), 0, g_Rm.RecentEvents);
        g_Rm.RecentEvents = NULL;
    }
    g_Rm.RecentEventCapacity = 0;
    ReleaseSRWLockExclusive(&g_Rm.Lock);

    AcquireSRWLockExclusive(&g_Rm.CallbackLock);
    ZeroMemory(g_Rm.AlertCallbacks, sizeof(g_Rm.AlertCallbacks));
    ZeroMemory(g_Rm.EventCallbacks, sizeof(g_Rm.EventCallbacks));
    ZeroMemory(g_Rm.ValueCallbacks, sizeof(g_Rm.ValueCallbacks));
    g_Rm.NextCallbackId = 1;
    ReleaseSRWLockExclusive(&g_Rm.CallbackLock);

    RmResetStatsInternal();
    RmDbgPrint(L"[RM] shutdown complete");
}

BOOLEAN
RmIsRunning(VOID) {
    return (InterlockedCompareExchange(&g_Rm.Running, 0, 0) != 0);
}

BOOLEAN
RmIsKernelConnected(VOID) {
    /* stub: 内核过滤端口未迁移, 恒 FALSE */
    return FALSE;
}

/* ==================================================
 * ═══ 策略管理 (回调 + 规则表)
 * ================================================== */

VOID
RmSetPolicyCallback(_In_opt_ PFN_RM_POLICY_CALLBACK Callback,
                    _In_opt_ PVOID Context) {
    AcquireSRWLockExclusive(&g_Rm.Lock);
    g_Rm.PolicyCallback = Callback;
    g_Rm.PolicyContext = Context;
    ReleaseSRWLockExclusive(&g_Rm.Lock);
    RmDbgPrint(L"[RM] policy callback %s", (Callback != NULL) ? L"registered" : L"cleared");
}

/* 规则表容量保障 (懒分配 + 倍增, 上限 WKD_RM_MAX_RULES) */
static
BOOLEAN RmEnsureRuleCapacity(_In_ ULONG Needed) {
    if (g_Rm.Rules == NULL) {
        ULONG cap = (Needed > 16) ? Needed : 16;
        if (cap > WKD_RM_MAX_RULES) cap = WKD_RM_MAX_RULES;
        if (cap < Needed) return FALSE;
        g_Rm.Rules = (PWKD_RM_RULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                             cap * sizeof(WKD_RM_RULE));
        if (g_Rm.Rules == NULL) return FALSE;
        g_Rm.RuleCapacity = cap;
        return TRUE;
    }
    if (Needed > g_Rm.RuleCapacity) {
        ULONG cap = g_Rm.RuleCapacity * 2;
        while (cap < Needed) cap *= 2;
        if (cap > WKD_RM_MAX_RULES) cap = WKD_RM_MAX_RULES;
        if (cap < Needed) return FALSE;
        PWKD_RM_RULE nb = (PWKD_RM_RULE)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                    g_Rm.Rules, cap * sizeof(WKD_RM_RULE));
        if (nb == NULL) return FALSE;
        g_Rm.Rules = nb;
        g_Rm.RuleCapacity = cap;
    }
    return TRUE;
}

BOOLEAN
RmRuleMatches(_In_ PCWKD_RM_RULE Rule, _In_ PCWKD_RM_EVENT Event) {
    if (Rule == NULL || Event == NULL || !Rule->Enabled) return FALSE;

    /* 过期规则不参与匹配 (ExpiresAt 为 FILETIME 语义, 与事件时间戳同源) */
    if (Rule->IsPermanent == FALSE && Rule->ExpiresAt != 0) {
        FILETIME nowFt;
        GetSystemTimeAsFileTime(&nowFt);
        ULARGE_INTEGER now;
        now.LowPart = nowFt.dwLowDateTime;
        now.HighPart = nowFt.dwHighDateTime;
        if (now.QuadPart > Rule->ExpiresAt) {
            return FALSE;
        }
    }

    if (!Rule->HasOperation || Rule->Operation == Event->Operation) {
        /* 操作条件满足 → 继续 (与 SS 相同: 默认即匹配) */
    } else {
        return FALSE;
    }
    if (Rule->HasValueType && Rule->ValueType != Event->ValueType) {
        return FALSE;
    }
    if (!RmWcsEmpty(Rule->KeyPathPattern)) {
        WCHAR lowerPath[WKD_RM_MAX_KEY_PATH_CHARS];
        RmWcsToLowerCopy(lowerPath, WKD_RM_MAX_KEY_PATH_CHARS, Event->KeyPath);
        if (!RmMatchesRegistryKeyPattern(lowerPath, Rule->KeyPathPattern)) {
            return FALSE;
        }
    }
    if (!RmWcsEmpty(Rule->ProcessPathPattern)) {
        WCHAR lowerProc[WKD_RM_MAX_KEY_PATH_CHARS];
        RmWcsToLowerCopy(lowerProc, WKD_RM_MAX_KEY_PATH_CHARS, Event->ProcessPath);
        if (!RmMatchesRegistryKeyPattern(lowerProc, Rule->ProcessPathPattern)) {
            return FALSE;
        }
    }
    if (Rule->ProcessIdCount > 0) {
        BOOLEAN pidMatch = FALSE;
        for (ULONG i = 0; i < Rule->ProcessIdCount; ++i) {
            if (Rule->ProcessIds[i] == Event->ProcessId) { pidMatch = TRUE; break; }
        }
        if (!pidMatch) return FALSE;
    }
    if (!RmWcsEmpty(Rule->UserSidPattern)) {
        if (!RmWcsIContains(Event->UserSid, Rule->UserSidPattern)) {
            return FALSE;
        }
    }
    return TRUE;
}

ULONGLONG
RmAddRule(_In_ PCWKD_RM_RULE Rule) {
    if (!RmIsInitialized() || Rule == NULL) return 0;

    AcquireSRWLockExclusive(&g_Rm.Lock);
    if (g_Rm.RuleCount >= WKD_RM_MAX_RULES) {
        ReleaseSRWLockExclusive(&g_Rm.Lock);
        RmDbgPrint(L"[RM] addRule rejected: rule limit (%d) reached", WKD_RM_MAX_RULES);
        return 0;
    }

    /* 同名键路径规则 → 就地更新 (保留原 RuleId, 对齐 SS) */
    for (ULONG i = 0; i < g_Rm.RuleCount; ++i) {
        if (RmWcsIEquals(g_Rm.Rules[i].KeyPathPattern, Rule->KeyPathPattern)) {
            ULONGLONG oldId = g_Rm.Rules[i].RuleId;
            g_Rm.Rules[i] = *Rule;
            g_Rm.Rules[i].RuleId = oldId;
            ReleaseSRWLockExclusive(&g_Rm.Lock);
            return oldId;
        }
    }

    if (!RmEnsureRuleCapacity(g_Rm.RuleCount + 1)) {
        ReleaseSRWLockExclusive(&g_Rm.Lock);
        return 0;
    }
    PWKD_RM_RULE slot = &g_Rm.Rules[g_Rm.RuleCount];
    *slot = *Rule;
    slot->RuleId = g_Rm.NextRuleId++;
    g_Rm.RuleCount++;
    ReleaseSRWLockExclusive(&g_Rm.Lock);

    RmDbgPrint(L"[RM] rule added (id=%I64u, key=%ls)",
               slot->RuleId, slot->KeyPathPattern);
    return slot->RuleId;
}

BOOLEAN
RmRemoveRule(_In_ ULONGLONG RuleId) {
    if (!RmIsInitialized()) return FALSE;
    AcquireSRWLockExclusive(&g_Rm.Lock);
    for (ULONG i = 0; i < g_Rm.RuleCount; ++i) {
        if (g_Rm.Rules[i].RuleId == RuleId) {
            if (i + 1 < g_Rm.RuleCount) {
                memmove(&g_Rm.Rules[i], &g_Rm.Rules[i + 1],
                        (g_Rm.RuleCount - i - 1) * sizeof(WKD_RM_RULE));
            }
            g_Rm.RuleCount--;
            ReleaseSRWLockExclusive(&g_Rm.Lock);
            return TRUE;
        }
    }
    ReleaseSRWLockExclusive(&g_Rm.Lock);
    return FALSE;
}

ULONG
RmGetRules(_Out_opt_ PWKD_RM_RULE Rules, _In_ ULONG MaxCount) {
    if (!RmIsInitialized()) return 0;
    AcquireSRWLockShared(&g_Rm.Lock);
    ULONG n = g_Rm.RuleCount;
    if (Rules != NULL) {
        n = (n < MaxCount) ? n : MaxCount;
        if (n > 0) {
            memcpy(Rules, g_Rm.Rules, n * sizeof(WKD_RM_RULE));
        }
    }
    ULONG result = (Rules != NULL) ? n : g_Rm.RuleCount;
    ReleaseSRWLockShared(&g_Rm.Lock);
    return result;
}

BOOLEAN
RmSetRuleEnabled(_In_ ULONGLONG RuleId, _In_ BOOLEAN Enabled) {
    if (!RmIsInitialized()) return FALSE;
    AcquireSRWLockExclusive(&g_Rm.Lock);
    for (ULONG i = 0; i < g_Rm.RuleCount; ++i) {
        if (g_Rm.Rules[i].RuleId == RuleId) {
            g_Rm.Rules[i].Enabled = Enabled;
            ReleaseSRWLockExclusive(&g_Rm.Lock);
            return TRUE;
        }
    }
    ReleaseSRWLockExclusive(&g_Rm.Lock);
    return FALSE;
}

/* 事件 → 裁决 (规则链: 全部匹配规则中按最高优先级的裁决; 
 * MatchCount 内联 bump 快照计数) */
static
WKD_RM_VERDICT RmEvaluateRules(_In_ PCWKD_RM_EVENT Event) {
    PCWKD_RM_RULE best = NULL;
    for (ULONG i = 0; i < g_Rm.RuleCount; ++i) {
        if (!RmRuleMatches(&g_Rm.Rules[i], Event)) continue;
        g_Rm.Rules[i].MatchCount++;
        if (best == NULL || g_Rm.Rules[i].Priority > best->Priority) {
            best = &g_Rm.Rules[i];
        }
    }
    return (best != NULL) ? (WKD_RM_VERDICT)best->Verdict : WkdRmVerdict_Allow;
}

/* ==================================================
 * ═══ 键保护 (自防御键集 + 小写并行缓存)
 * ================================================== */

static
BOOLEAN RmEnsureProtectedCapacity(_In_ ULONG Needed) {
    if (g_Rm.ProtectedKeys == NULL) {
        ULONG cap = (Needed > 8) ? Needed : 8;
        g_Rm.ProtectedKeys = (PWKD_RM_PROTECTED_KEY)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, cap * sizeof(WKD_RM_PROTECTED_KEY));
        g_Rm.ProtectedKeysLower = (PWSTR*)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, cap * sizeof(PWSTR));
        if (g_Rm.ProtectedKeys == NULL || g_Rm.ProtectedKeysLower == NULL) {
            if (g_Rm.ProtectedKeys != NULL) {
                HeapFree(GetProcessHeap(), 0, g_Rm.ProtectedKeys);
                g_Rm.ProtectedKeys = NULL;
            }
            if (g_Rm.ProtectedKeysLower != NULL) {
                HeapFree(GetProcessHeap(), 0, g_Rm.ProtectedKeysLower);
                g_Rm.ProtectedKeysLower = NULL;
            }
            return FALSE;
        }
        g_Rm.ProtectedKeyCapacity = cap;
        return TRUE;
    }
    if (Needed > g_Rm.ProtectedKeyCapacity) {
        ULONG cap = g_Rm.ProtectedKeyCapacity * 2;
        if (cap > WKD_RM_MAX_PROTECTED_KEYS) cap = WKD_RM_MAX_PROTECTED_KEYS;
        if (cap < Needed) return FALSE;
        PWKD_RM_PROTECTED_KEY nb = (PWKD_RM_PROTECTED_KEY)HeapReAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, g_Rm.ProtectedKeys,
            cap * sizeof(WKD_RM_PROTECTED_KEY));
        PWSTR* nl = (PWSTR*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                        g_Rm.ProtectedKeysLower, cap * sizeof(PWSTR));
        if (nb == NULL || nl == NULL) {
            if (nb != NULL) g_Rm.ProtectedKeys = nb;
            if (nl != NULL) g_Rm.ProtectedKeysLower = nl;
            return FALSE;
        }
        g_Rm.ProtectedKeys = nb;
        g_Rm.ProtectedKeysLower = nl;
        g_Rm.ProtectedKeyCapacity = cap;
    }
    return TRUE;
}

static VOID
RegpAddProtectedKey(_In_ PCWSTR KeyPath) {
    if (KeyPath == NULL || RmWcsEmpty(KeyPath)) return;
    WKD_RM_PROTECTED_KEY entry;
    ZeroMemory(&entry, sizeof(entry));
    RmWcsCopy(entry.KeyPath, WKD_RM_MAX_KEY_PATH_CHARS, KeyPath);
    entry.IncludeSubkeys = TRUE;
    entry.ProtectValues = TRUE;
    entry.ProtectDelete = TRUE;
    entry.ProtectRename = TRUE;
    entry.ProtectSecurity = TRUE;
    entry.IsSelfDefense = TRUE;   /* 默认按自防御键处理 */
    RegpAddProtectedKeyConfig(&entry);
}

VOID
RegpAddProtectedKeyConfig(_In_ PCWKD_RM_PROTECTED_KEY Config) {
    if (!RmIsInitialized() || Config == NULL || RmWcsEmpty(Config->KeyPath)) return;

    AcquireSRWLockExclusive(&g_Rm.Lock);
    if (g_Rm.ProtectedKeyCount >= WKD_RM_MAX_PROTECTED_KEYS) {
        ReleaseSRWLockExclusive(&g_Rm.Lock);
        RmDbgPrint(L"[RM] addProtectedKey rejected: capacity (%d)", WKD_RM_MAX_PROTECTED_KEYS);
        return;
    }
    /* 去重: 同路径就地替换 */
    for (ULONG i = 0; i < g_Rm.ProtectedKeyCount; ++i) {
        if (RmWcsIEquals(g_Rm.ProtectedKeysLower[i], Config->KeyPath)) {
            g_Rm.ProtectedKeys[i] = *Config;
            RmWcsToLowerCopy(g_Rm.ProtectedKeysLower[i],
                             WKD_RM_MAX_KEY_PATH_CHARS, Config->KeyPath);
            ReleaseSRWLockExclusive(&g_Rm.Lock);
            return;
        }
    }
    if (!RmEnsureProtectedCapacity(g_Rm.ProtectedKeyCount + 1)) {
        ReleaseSRWLockExclusive(&g_Rm.Lock);
        return;
    }
    PWKD_RM_PROTECTED_KEY slot = &g_Rm.ProtectedKeys[g_Rm.ProtectedKeyCount];
    *slot = *Config;
    g_Rm.ProtectedKeysLower[g_Rm.ProtectedKeyCount] =
        (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                         WKD_RM_MAX_KEY_PATH_CHARS * sizeof(WCHAR));
    if (g_Rm.ProtectedKeysLower[g_Rm.ProtectedKeyCount] == NULL) {
        ReleaseSRWLockExclusive(&g_Rm.Lock);
        return;
    }
    RmWcsToLowerCopy(g_Rm.ProtectedKeysLower[g_Rm.ProtectedKeyCount],
                     WKD_RM_MAX_KEY_PATH_CHARS, Config->KeyPath);
    g_Rm.ProtectedKeyCount++;
    ReleaseSRWLockExclusive(&g_Rm.Lock);

    RmDbgPrint(L"[RM] protected key added: %ls", Config->KeyPath);
}

VOID
RmRemoveProtectedKey(_In_ PCWSTR KeyPath) {
    if (!RmIsInitialized() || KeyPath == NULL) return;
    AcquireSRWLockExclusive(&g_Rm.Lock);
    for (ULONG i = 0; i < g_Rm.ProtectedKeyCount; ++i) {
        if (RmWcsIEquals(g_Rm.ProtectedKeysLower[i], KeyPath)) {
            HeapFree(GetProcessHeap(), 0, g_Rm.ProtectedKeysLower[i]);
            if (i + 1 < g_Rm.ProtectedKeyCount) {
                memmove(&g_Rm.ProtectedKeys[i], &g_Rm.ProtectedKeys[i + 1],
                        (g_Rm.ProtectedKeyCount - i - 1) * sizeof(WKD_RM_PROTECTED_KEY));
                memmove(&g_Rm.ProtectedKeysLower[i], &g_Rm.ProtectedKeysLower[i + 1],
                        (g_Rm.ProtectedKeyCount - i - 1) * sizeof(PWSTR));
            }
            g_Rm.ProtectedKeyCount--;
            ReleaseSRWLockExclusive(&g_Rm.Lock);
            RmDbgPrint(L"[RM] protected key removed: %ls", KeyPath);
            return;
        }
    }
    ReleaseSRWLockExclusive(&g_Rm.Lock);
}

BOOLEAN
RmIsProtectedKey(_In_ PCWSTR KeyPath) {
    if (!RmIsInitialized() || KeyPath == NULL) return FALSE;

    WCHAR lowerPath[WKD_RM_MAX_KEY_PATH_CHARS];
    RmWcsToLowerCopy(lowerPath, WKD_RM_MAX_KEY_PATH_CHARS, KeyPath);

    AcquireSRWLockShared(&g_Rm.Lock);
    for (ULONG i = 0; i < g_Rm.ProtectedKeyCount; ++i) {
        PCWSTR entry = g_Rm.ProtectedKeysLower[i];
        if (entry == NULL) continue;
        if (wcscmp(lowerPath, entry) == 0) {
            ReleaseSRWLockShared(&g_Rm.Lock);
            return TRUE;
        }
        if (g_Rm.ProtectedKeys[i].IncludeSubkeys) {
            SIZE_T len = wcslen(entry);
            if (wcsncmp(lowerPath, entry, len) == 0 && lowerPath[len] == L'\\') {
                ReleaseSRWLockShared(&g_Rm.Lock);
                return TRUE;
            }
        }
    }
    ReleaseSRWLockShared(&g_Rm.Lock);
    return FALSE;
}

ULONG
RmGetProtectedKeys(_Out_opt_ PWKD_RM_PROTECTED_KEY Keys, _In_ ULONG MaxCount) {
    if (!RmIsInitialized()) return 0;
    AcquireSRWLockShared(&g_Rm.Lock);
    ULONG n = g_Rm.ProtectedKeyCount;
    if (Keys != NULL) {
        n = (n < MaxCount) ? n : MaxCount;
        if (n > 0) memcpy(Keys, g_Rm.ProtectedKeys, n * sizeof(WKD_RM_PROTECTED_KEY));
    }
    ULONG result = (Keys != NULL) ? n : g_Rm.ProtectedKeyCount;
    ReleaseSRWLockShared(&g_Rm.Lock);
    return result;
}

/* ==================================================
 * ═══ 键类别判定（路径版; 事件版共用静态实现）
 * ================================================== */

static
ULONG RmPathCategory(_In_ PCWSTR KeyPath) {
    if (KeyPath == NULL) return WkdRmCategory_Unknown;
    if (RmIsCriticalKey(KeyPath)) {
        if (RmWcsIContains(KeyPath, L"\\SYSTEM\\CurrentControlSet\\Services\\")) {
            return WkdRmCategory_Persistence;
        }
        for (ULONG i = 0; i < RM_SECURITY_KEY_COUNT; ++i) {
            if (RmWcsIContains(KeyPath, RM_SECURITY_KEYS[i])) {
                return WkdRmCategory_Security;
            }
        }
        for (ULONG i = 0; i < RM_NETWORK_KEY_COUNT; ++i) {
            if (RmWcsIContains(KeyPath, RM_NETWORK_KEYS[i])) {
                return WkdRmCategory_Network;
            }
        }
        for (ULONG i = 0; i < RM_COM_KEY_COUNT; ++i) {
            if (RmWcsIContains(KeyPath, RM_COM_KEYS[i])) {
                return WkdRmCategory_Com;
            }
        }
        if (RmWcsIContains(KeyPath, L"\\Shell\\") ||
            RmWcsIContains(KeyPath, L"\\ShellExecuteHooks\\")) {
            return WkdRmCategory_Shell;
        }
        return WkdRmCategory_Persistence;
    }
    if (wcsstr(KeyPath, L"\\Registry\\") == NULL) {
        return WkdRmCategory_Application;
    }
    return WkdRmCategory_Unknown;
}

ULONG
RmGetKeyCategory(_In_ PCWSTR KeyPath) {
    return RmPathCategory(KeyPath);
}

/* ==================================================
 * ═══ 欺骗模式 (蜜罐键集 + 投毒开关)
 * ================================================== */

VOID
RmConfigureDeception(_In_ PCWKD_RM_DECEPTION_CONFIG Config) {
    if (!RmIsInitialized() || Config == NULL) return;
    AcquireSRWLockExclusive(&g_Rm.Lock);
    g_Rm.Config.Deception = *Config;
    ReleaseSRWLockExclusive(&g_Rm.Lock);
    RmDbgPrint(L"[RM] deception configured (silentDrop=%d honeypot=%d fakeSuccess=%d)",
               (INT)Config->SilentDropEnabled, (INT)Config->HoneypotEnabled,
               (INT)Config->FakeSuccessEnabled);
}

VOID
RmAddHoneypotKey(_In_ PCWSTR KeyPath) {
    if (!RmIsInitialized() || KeyPath == NULL || RmWcsEmpty(KeyPath)) return;

    AcquireSRWLockExclusive(&g_Rm.Lock);
    if (g_Rm.HoneypotKeyCount >= WKD_RM_MAX_HONEYPOT_KEYS) {
        ReleaseSRWLockExclusive(&g_Rm.Lock);
        return;
    }
    for (ULONG i = 0; i < g_Rm.HoneypotKeyCount; ++i) {
        if (RmWcsIEquals(g_Rm.HoneypotKeys + (SIZE_T)i * WKD_RM_MAX_KEY_PATH_CHARS,
                         KeyPath)) {
            ReleaseSRWLockExclusive(&g_Rm.Lock);
            return;
        }
    }
    if (g_Rm.HoneypotKeys == NULL) {
        ULONG cap = 8;
        g_Rm.HoneypotKeys = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                             cap * WKD_RM_MAX_KEY_PATH_CHARS * sizeof(WCHAR));
        if (g_Rm.HoneypotKeys == NULL) {
            ReleaseSRWLockExclusive(&g_Rm.Lock);
            return;
        }
        g_Rm.HoneypotKeyCapacity = cap;
    } else if (g_Rm.HoneypotKeyCount >= g_Rm.HoneypotKeyCapacity) {
        ULONG cap = g_Rm.HoneypotKeyCapacity * 2;
        if (cap > WKD_RM_MAX_HONEYPOT_KEYS) cap = WKD_RM_MAX_HONEYPOT_KEYS;
        if (cap < g_Rm.HoneypotKeyCount + 1) {
            ReleaseSRWLockExclusive(&g_Rm.Lock);
            return;
        }
        PWSTR nb = (PWSTR)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                      g_Rm.HoneypotKeys,
                                      cap * WKD_RM_MAX_KEY_PATH_CHARS * sizeof(WCHAR));
        if (nb == NULL) {
            ReleaseSRWLockExclusive(&g_Rm.Lock);
            return;
        }
        g_Rm.HoneypotKeys = nb;
        g_Rm.HoneypotKeyCapacity = cap;
    }
    RmWcsCopy(g_Rm.HoneypotKeys + (SIZE_T)g_Rm.HoneypotKeyCount * WKD_RM_MAX_KEY_PATH_CHARS,
              WKD_RM_MAX_KEY_PATH_CHARS, KeyPath);
    g_Rm.HoneypotKeyCount++;
    ReleaseSRWLockExclusive(&g_Rm.Lock);

    RmDbgPrint(L"[RM] honeypot key registered: %ls", KeyPath);
}

/* 蜜罐命中检测 (路径前缀匹配; 事件前操作拦截用) */
static
BOOLEAN RmIsHoneypotPath(_In_ PCWSTR KeyPath) {
    if (KeyPath == NULL || g_Rm.HoneypotKeyCount == 0) return FALSE;
    for (ULONG i = 0; i < g_Rm.HoneypotKeyCount; ++i) {
        PCWSTR hp = g_Rm.HoneypotKeys + (SIZE_T)i * WKD_RM_MAX_KEY_PATH_CHARS;
        if (RmWcsIEquals(hp, KeyPath)) return TRUE;
    }
    return FALSE;
}

/* ==================================================
 * ═══ 值分析 (analyzeValue; 输入上限 1 MB,
 *     事件内联预览 4096 B 时的启发式为预览级评估)
 *
 *  对齐 SS AnalyzeValue 实现: RiskFactors 聚合 / EXPAND_SZ
 *  两步展开 / 内嵌 NUL cloaking / URL 提取 / 风险评分。
 * ================================================== */

/* 风险因子追加 (对齐 SS riskFactors.push_back; 容量 WKD_RM_MAX_RISK_FACTORS) */
static
VOID RmAddRiskFactor(_Inout_ PWKD_RM_VALUE_ANALYSIS Analysis,
                     _In_ PCSTR Factor) {
    if (Analysis == NULL || Factor == NULL) return;
    if (Analysis->RiskFactorCount >= WKD_RM_MAX_RISK_FACTORS) return;
    RmCharCopy(Analysis->RiskFactors[Analysis->RiskFactorCount],
               WKD_REG_MAX_DESC_CHARS, Factor);
    Analysis->RiskFactorCount++;
}

/* 宽串 URL 窄化提取 (ToNarrow + 路由到 ExtractedUrls 缓冲) */
static
VOID RmExtractUrlToAnalysis(_In_ PCWSTR Wide,
                             _Inout_ PWKD_RM_VALUE_ANALYSIS Analysis) {
    if (Wide == NULL || Analysis == NULL) return;
    if (Analysis->ExtractedUrlCount >= WKD_RM_MAX_EXTRACTED_URLS) return;
    CHAR narrow[128];
    int n = WideCharToMultiByte(CP_ACP, 0, Wide, -1, narrow, (int)(sizeof(narrow) - 1), NULL, NULL);
    if (n <= 0) return;
    narrow[n] = '\0';
    RmCharCopy(Analysis->ExtractedUrls[Analysis->ExtractedUrlCount], 128, narrow);
    Analysis->ExtractedUrlCount++;
}

VOID
RmAnalyzeValue(_In_ const BYTE* Data,
               _In_ ULONG DataSize,
               _In_ ULONG Type,
               _Out_ PWKD_RM_VALUE_ANALYSIS Analysis) {
    if (Analysis == NULL) return;
    ZeroMemory(Analysis, sizeof(*Analysis));
    if (DataSize > WKD_RM_MAX_VALUE_DATA_SIZE) return;

    Analysis->DataSize = DataSize;
    Analysis->Type = Type;

    if (Data == NULL || DataSize == 0) return;

    /* --- 公共启发 (对齐 SS: 熵/大值/签名 跨类型统一检查) --- */

    if (DataSize > WKD_RM_LARGE_VALUE_THRESHOLD) {
        Analysis->IsLargeValue = TRUE;
        RmAddRiskFactor(Analysis, "Large value size");
    }

    if (DataSize >= WKD_RM_MIN_BLOB_SIZE) {
        Analysis->Entropy = RmCalculateEntropy(Data, DataSize);
        Analysis->IsHighEntropy = (Analysis->Entropy > WKD_RM_ENTROPY_THRESHOLD);
        if (Analysis->IsHighEntropy) {
            RmAddRiskFactor(Analysis, "High entropy (possibly encrypted/encoded)");
        }
    }

    if (Type == WkdRmVal_Binary && DataSize > 1024) {
        Analysis->IsBinaryBlob = TRUE;
        RmAddRiskFactor(Analysis, "Large binary blob");
    }

    if (RmContainsExecutableSignature(Data, DataSize)) {
        Analysis->ContainsExecutable = TRUE;
        RmAddRiskFactor(Analysis, "Contains executable signature");
    }

    /* 窄扫描 (REG_BINARY 原始字节载荷; 对齐 SS 窄脚本签名通道) */
    if (RmContainsScriptSignature(Data, DataSize)) {
        Analysis->ContainsScript = TRUE;
        RmAddRiskFactor(Analysis, "Contains script content");
    }

    /* --- REG_BINARY: 窄 URL 检测 --- */
    if (Type == WkdRmVal_Binary) {
        if (DataSize >= 8 && RmContainsUrlPrefix((PCSTR)Data)) {
            Analysis->ContainsUrl = TRUE;
        }
        goto Finalize;
    }

    /* --- 字符串型: 宽字符串通道 (REG_SZ/EXPAND_SZ/MULTI_SZ/资源型) --- */
    BOOLEAN isStringType =
        (Type == WkdRmVal_Sz || Type == WkdRmVal_ExpandSz ||
         Type == WkdRmVal_MultiSz || Type == WkdRmVal_Link);
    if (!isStringType) goto Finalize;

    SIZE_T charCount = (SIZE_T)DataSize / sizeof(WCHAR);
    if (charCount > RM_EXPANDED_PATH_CAP) charCount = RM_EXPANDED_PATH_CAP;
    SIZE_T effective = RmWcsTrimTrailingNulls((const WCHAR*)Data, charCount);
    if (effective == 0) goto Finalize;

    /* 内嵌 NUL cloaking 检测 (对齐 SS: charCount > value.size() + 1) */
    if (charCount > effective + 1) {
        RmAddRiskFactor(Analysis, "Embedded null bytes (cloaking attempt)");
    }

    /* 宽字符串脚本签名扫描 (REG_SZ UTF-16 存储, 窄扫描零字节交错漏报) */
    if (!Analysis->ContainsScript && RmContainsScriptSignatureWide((PCWSTR)Data)) {
        Analysis->ContainsScript = TRUE;
        RmAddRiskFactor(Analysis, "Contains script content");
    }

    /* 编码声明 (简化: UTF-16LE) */
    RmCharCopy(Analysis->DetectedEncoding, 32, "utf-16le");

    /* --- EXPAND_SZ: 两步展开 + cloaking 风险因子 (对齐 SS) --- */
    if (Type == WkdRmVal_ExpandSz && effective > 0) {
        /* 构造 NUL 结尾副本 (事件预览数据可能非 NUL 结尾) */
        SIZE_T termLen = effective + 1;
        PWCHAR term = (PWCHAR)HeapAlloc(GetProcessHeap(), 0, termLen * sizeof(WCHAR));
        if (term != NULL) {
            memcpy(term, Data, effective * sizeof(WCHAR));
            term[effective] = L'\0';
            DWORD required = ExpandEnvironmentStringsW(term, NULL, 0);
            if (required > 0 && required <= (DWORD)WKD_RM_MAX_KEY_PATH_CHARS) {
                PWCHAR expanded = (PWCHAR)HeapAlloc(GetProcessHeap(), 0,
                                                     (SIZE_T)required * sizeof(WCHAR));
                if (expanded != NULL) {
                    DWORD wrote = ExpandEnvironmentStringsW(term, expanded, required);
                    if (wrote > 0 && wrote <= required) {
                        SIZE_T expandedLen = (wrote > 1) ? (SIZE_T)(wrote - 1) : 0;
                        /* 展开后 != 原串 → 含环境变量引用 (cloaking 载体) */
                        if (expandedLen != effective ||
                            wcsncmp(expanded, term, effective) != 0) {
                            RmAddRiskFactor(Analysis,
                                "Contains expandable environment variables");
                        }
                        /* 展开后是路径 → 提取 (对齐 SS IsPathLike) */
                        if (expandedLen >= 3 && Analysis->ExtractedPathCount < WKD_RM_MAX_EXTRACTED_PATHS) {
                            if (RmIsPathLike(expanded)) {
                                RmWcsCopyN(Analysis->ExtractedPaths[Analysis->ExtractedPathCount],
                                           WKD_REG_MAX_PATH_CHARS, expanded,
                                           (ULONG)expandedLen);
                                Analysis->ExtractedPathCount++;
                                Analysis->ContainsPath = TRUE;
                            }
                        }
                    }
                    HeapFree(GetProcessHeap(), 0, expanded);
                }
            }
            HeapFree(GetProcessHeap(), 0, term);
        }
    }

    /* --- MULTI_SZ: 逐条目拆分 --- */
    if (Type == WkdRmVal_MultiSz) {
        PCWSTR cursor = (PCWSTR)Data;
        SIZE_T remaining = effective;
        ULONG entries = 0;
        while (remaining > 0 && entries < RM_MULTI_SZ_ENTRY_CAP) {
            SIZE_T len = wcsnlen(cursor, remaining);
            if (len == 0) break;   /* 空条目终止 */
            if (RmIsPathLike(cursor)) {
                if (Analysis->ExtractedPathCount < WKD_RM_MAX_EXTRACTED_PATHS) {
                    RmWcsCopyN(Analysis->ExtractedPaths[Analysis->ExtractedPathCount],
                               WKD_REG_MAX_PATH_CHARS, cursor, WKD_REG_MAX_PATH_CHARS - 1);
                    Analysis->ExtractedPathCount++;
                }
                Analysis->ContainsPath = TRUE;
            }
            /* 条目级 URL 提取 (对齐 SS: ToNarrow + ContainsUrlPrefix) */
            if (Analysis->ExtractedUrlCount < WKD_RM_MAX_EXTRACTED_URLS) {
                CHAR narrow[256];
                int n = WideCharToMultiByte(CP_ACP, 0, cursor, (int)len,
                                            narrow, (int)(sizeof(narrow) - 1), NULL, NULL);
                if (n > 0) {
                    narrow[n] = '\0';
                    if (RmContainsUrlPrefix(narrow)) {
                        Analysis->ContainsUrl = TRUE;
                        RmCharCopy(Analysis->ExtractedUrls[Analysis->ExtractedUrlCount],
                                   128, narrow);
                        Analysis->ExtractedUrlCount++;
                    }
                }
            }
            entries++;
            cursor += len + 1;
            remaining -= (len + 1);
        }
        goto Finalize;
    }

    /* --- 单字符串: 路径/URL 提取 --- */
    if (RmIsPathLike((PCWSTR)Data)) {
        RmWcsCopyN(Analysis->ExtractedPaths[0], WKD_REG_MAX_PATH_CHARS,
                   (PCWSTR)Data, WKD_REG_MAX_PATH_CHARS - 1);
        Analysis->ExtractedPathCount = 1;
        Analysis->ContainsPath = TRUE;
    }
    /* 单串 URL 检测 (宽字面量前缀 → 窄化提取, 对齐 SS ToNarrow) */
    {
        static const PCWSTR urlPrefixes[] = {
            L"http://", L"https://", L"ftp://",
        };
        for (ULONG u = 0; u < 3; ++u) {
            if (RmWcsIContains((PCWSTR)Data, urlPrefixes[u])) {
                Analysis->ContainsUrl = TRUE;
                RmExtractUrlToAnalysis((PCWSTR)Data, Analysis);
                break;
            }
        }
    }

Finalize:
    /* 风险聚合 (对齐 SS: riskFactors.size() >= 3 → High / 2 → Medium / 1 → Low / 0 → Safe) */
    if (Analysis->RiskFactorCount >= 3) {
        Analysis->Risk = WkdRmRisk_High;
    } else if (Analysis->RiskFactorCount >= 2) {
        Analysis->Risk = WkdRmRisk_Medium;
    } else if (Analysis->RiskFactorCount >= 1) {
        Analysis->Risk = WkdRmRisk_Low;
    } else {
        Analysis->Risk = WkdRmRisk_Safe;
    }
}

/* 事件内值分析 (预览截断数据上执行; 与 RmAnalyzeValue 共用启发) */
static
VOID RmAnalyzeEventValue(_In_ PCWKD_RM_EVENT Event,
                         _Out_ PWKD_RM_VALUE_ANALYSIS Analysis) {
    RmAnalyzeValue(Event->ValueData, Event->ValueDataSize,
                   Event->ValueType, Analysis);
    /* 显式标注: 输入为预览窗口, 完整长度记录在 originalSize */
    Analysis->DataSize = Event->ValueDataOriginalSize;
}

/* ==================================================
 * ═══ 威胁分类与风险定级 (DetectThreat/Assess)
 * ================================================== */

static
ULONG RmDetectThreat(_In_ PCWKD_RM_EVENT Event,
                     _In_opt_ PCWKD_RM_VALUE_ANALYSIS Analysis) {
    if (Event == NULL) return WkdRmThreat_None;

        /* 1. 自防御/安全软件密钥篡改 (最高优先级) */
    if (RmWcsIContains(Event->KeyPath, L"\\WkDefender")) {
        return WkdRmThreat_SelfDefenseTamper;
    }
    if (RmWcsIContains(Event->KeyPath, L"\\Windows Defender") ||
        RmWcsIContains(Event->KeyPath, L"\\SharedAccess\\Parameters\\FirewallPolicy")) {
        return WkdRmThreat_DefenderDisable;
    }
    /* AMSI / ETW 绕过检测 (对齐 SS DetectThreat security 分支;
     * C 版拆为独立威胁类型以支持精细化风险定级) */
    if (RmWcsIContains(Event->KeyPath, L"\\Microsoft\\AMSI")) {
        return WkdRmThreat_AmsiBypass;
    }
    if (RmWcsIContains(Event->KeyPath, L"\\WMI\\Autologger") ||
        RmWcsIContains(Event->KeyPath, L"\\ETW")) {
        return WkdRmThreat_EtwBypass;
    }

    /* 2. 载荷威胁 (值内容分析) */
    if (Analysis != NULL && Analysis->DataSize > 0) {
        if (Analysis->ContainsExecutable || Analysis->ContainsScript) {
            return WkdRmThreat_FilelessPayload;
        }
        if (Analysis->IsHighEntropy && Event->ValueDataSize > WKD_RM_MIN_BLOB_SIZE) {
            return WkdRmThreat_FilelessPayload;
        }
        if (Analysis->ContainsScript) {
            return WkdRmThreat_PowershellCommand;
        }
    }

    /* 3. 持久化/劫持/网络类键映射 */
    if (RmEventIsPersistenceKey(Event)) {
        if (RmWcsIContains(Event->KeyPath, L"\\Services\\")) {
            return WkdRmThreat_PersistenceService;
        }
        if (RmWcsIContains(Event->KeyPath, L"\\Winlogon")) {
            return WkdRmThreat_PersistenceWinlogon;
        }
        if (RmWcsIContains(Event->KeyPath, L"\\Image File Execution Options")) {
            return WkdRmThreat_PersistenceIfeo;
        }
        if (RmWcsIContains(Event->KeyPath, L"\\AppInit_DLLs")) {
            return WkdRmThreat_PersistenceAppInit;
        }
        if (RmWcsIContains(Event->KeyPath, L"\\BootExecute") ||
            RmWcsIContains(Event->KeyPath, L"\\Session Manager")) {
            return WkdRmThreat_PersistenceBootExecute;
        }
        return WkdRmThreat_PersistenceRunKey;
    }
    /* COM 劫持 (对齐 SS: IsCOMKey 在 persistence 之后检查) */
    if (RmEventIsComKey(Event)) {
        return WkdRmThreat_ComHijack;
    }
    if (RmEventIsNetworkKey(Event)) {
        if (RmWcsIContains(Event->KeyPath, L"\\Internet Settings")) {
            return WkdRmThreat_ProxyModification;
        }
        return WkdRmThreat_DnsModification;
    }
    /* UAC 策略键 */
    if (RmWcsIContains(Event->KeyPath,
                       L"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System")) {
        return WkdRmThreat_UacBypass;
    }
    return WkdRmThreat_None;
}

static
ULONG RmAssessRisk(_In_ ULONG ThreatType,
                   _In_opt_ PCWKD_RM_VALUE_ANALYSIS Analysis) {
    ULONG risk = WkdRmRisk_Medium;
    switch (ThreatType) {
    /* 对齐 SS AssessRisk: 安全机制破坏 → Critical */
    case WkdRmThreat_SelfDefenseTamper:
    case WkdRmThreat_LogTampering:
    case WkdRmThreat_AuditDisable:
    case WkdRmThreat_DefenderDisable:
    case WkdRmThreat_AmsiBypass:
    case WkdRmThreat_EtwBypass:
        risk = WkdRmRisk_Critical;
        break;
    /* 对齐 SS: 服务/登录/IFEO 持久化 + 无文件载荷 → High */
    case WkdRmThreat_FilelessPayload:
    case WkdRmThreat_PersistenceService:
    case WkdRmThreat_PersistenceWinlogon:
    case WkdRmThreat_PersistenceIfeo:
        risk = WkdRmRisk_High;
        break;
    /* 对齐 SS: RunKey / COM 劫持 / 编码脚本 → Medium */
    case WkdRmThreat_EncodedScript:
    case WkdRmThreat_PowershellCommand:
    case WkdRmThreat_PersistenceRunKey:
    case WkdRmThreat_ComHijack:
        risk = WkdRmRisk_Medium;
        break;
    /* WkD 扩展威胁 (SS 无对应枚举): 保留原定级, 不强行降级 */
    case WkdRmThreat_PersistenceAppInit:
    case WkdRmThreat_PersistenceBootExecute:
    case WkdRmThreat_ShellExtension:
    case WkdRmThreat_UacBypass:
    case WkdRmThreat_FileAssociation:
    case WkdRmThreat_DllSearchOrder:
    case WkdRmThreat_FirewallDisable:
        risk = WkdRmRisk_High;
        break;
    default:
        risk = WkdRmRisk_Low;
        break;
    }
    /* 载荷加成 (WkD 扩展, SS 为静态映射): 可信脚本/载荷 → 升一级 (封顶 Critical) */
    if (Analysis != NULL &&
        (Analysis->ContainsExecutable || Analysis->ContainsScript) &&
        risk < WkdRmRisk_Critical) {
        risk++;
    }
    return risk;
}

/* ==================================================
 * ═══ MITRE ATT&CK 映射 (strategy 映射)
 * ================================================== */

static
VOID RmMapMitreForThreat(_In_ ULONG ThreatType,
                         _Out_writes_(32) PCHAR Technique,
                         _Out_writes_(32) PCHAR SubTechnique) {
    PCSTR tech = "T1078";       /* 默认: 有效账户 */
    PCSTR sub = "";
    switch (ThreatType) {
    case WkdRmThreat_PersistenceRunKey:      tech = "T1547"; sub = "T1547.001"; break;
    case WkdRmThreat_PersistenceService:     tech = "T1543"; sub = "T1543.003"; break;
    case WkdRmThreat_PersistenceWinlogon:    tech = "T1547"; sub = "T1547.004"; break;
    case WkdRmThreat_PersistenceIfeo:        tech = "T1546"; sub = "T1546.012"; break;
    case WkdRmThreat_PersistenceAppInit:     tech = "T1546"; sub = "T1546.010"; break;
    case WkdRmThreat_PersistenceBootExecute: tech = "T1547"; sub = "T1547.001"; break;
    case WkdRmThreat_ComHijack:              tech = "T1546"; sub = "T1546.015"; break;
    case WkdRmThreat_DllSearchOrder:         tech = "T1574"; sub = "T1574.001"; break;
    case WkdRmThreat_ShellExtension:         tech = "T1547"; sub = "";           break;
    case WkdRmThreat_FileAssociation:        tech = "T1546"; sub = "T1546.001"; break;
    case WkdRmThreat_UacBypass:              tech = "T1548"; sub = "T1548.002"; break;
    case WkdRmThreat_FirewallDisable:        tech = "T1562"; sub = "T1562.004"; break;
    case WkdRmThreat_DefenderDisable:        tech = "T1562"; sub = "T1562.001"; break;
    case WkdRmThreat_AmsiBypass:             tech = "T1562"; sub = "T1562.010"; break;
    case WkdRmThreat_EtwBypass:              tech = "T1562"; sub = "T1562.006"; break;
    case WkdRmThreat_FilelessPayload:        tech = "T1059"; sub = "T1059.001"; break;
    case WkdRmThreat_EncodedScript:          tech = "T1027"; sub = "T1027.010"; break;
    case WkdRmThreat_PowershellCommand:      tech = "T1059"; sub = "T1059.001"; break;
    case WkdRmThreat_SelfDefenseTamper:      tech = "T1562"; sub = "T1562.001"; break;
    case WkdRmThreat_LogTampering:           tech = "T1070"; sub = "T1070.001"; break;
    case WkdRmThreat_AuditDisable:           tech = "T1562"; sub = "T1562.002"; break;
    case WkdRmThreat_ProxyModification:      tech = "T1090"; sub = "T1090.001"; break;
    case WkdRmThreat_DnsModification:        tech = "T1553"; sub = "";           break;
    case WkdRmThreat_HostsRedirect:          tech = "T1553"; sub = "T1553.004"; break;
    default:                                 tech = "T1078"; sub = "";           break;
    }
    if (Technique != NULL) RmCharCopy(Technique, 32, tech);
    if (SubTechnique != NULL) RmCharCopy(SubTechnique, 32, sub);
}

/* ==================================================
 * ═══ 告警去重环 (FNV-1a, 2000 ms 窗口, Critical 绕过)
 * ================================================== */

static
BOOLEAN RmShouldSuppressAlert(_In_ ULONGLONG Hash) {
    ULONGLONG now = GetTickCount64();
    BOOLEAN duplicate = FALSE;
    AcquireSRWLockExclusive(&g_Rm.Lock);
    for (ULONG i = 0; i < g_Rm.DedupSlotCount; ++i) {
        if (g_Rm.DedupRing[i].Hash == Hash &&
            (now - g_Rm.DedupRing[i].LastSeenTick) < WKD_RM_DEDUP_WINDOW_MS) {
            duplicate = TRUE;
            break;
        }
    }
    g_Rm.DedupRing[g_Rm.DedupNextSlot].Hash = Hash;
    g_Rm.DedupRing[g_Rm.DedupNextSlot].LastSeenTick = now;
    g_Rm.DedupNextSlot = (g_Rm.DedupNextSlot + 1) % WKD_RM_DEDUP_RING_SIZE;
    if (g_Rm.DedupSlotCount < WKD_RM_DEDUP_RING_SIZE) g_Rm.DedupSlotCount++;
    ReleaseSRWLockExclusive(&g_Rm.Lock);
    return duplicate;
}

/* 告警上报 → 去重 → 回调 → 计数 (Critical 绕过去重) */
static
VOID RmReportAlert(_In_ PCWKD_RM_EVENT Event,
                   _In_ ULONG ThreatType,
                   _In_ ULONG Risk,
                   _In_ PCSTR Description,
                   _In_ ULONG Verdict,
                   _In_ BOOLEAN WasBlocked) {
    if (Event == NULL) return;

    /* 去重哈希: 混入威胁类型 (对齐 SS GenerateAlert: hash ^= threat),
     * 避免同一键上不同威胁被错误抑制 */
    ULONGLONG hash = RmHashEventForDedup(Event->ProcessId, Event->Operation,
                                         Event->KeyPath, Event->ValueName)
                     ^ (ULONGLONG)ThreatType;
    if (Risk < WkdRmRisk_Critical && RmShouldSuppressAlert(hash)) {
        InterlockedIncrement64(&g_Rm.Stats.AlertsGenerated);
        return;
    }

    WKD_RM_ALERT alert;
    ZeroMemory(&alert, sizeof(alert));
    alert.AlertId = (ULONGLONG)InterlockedIncrement64((volatile LONG64*)&g_Rm.NextAlertId);
    alert.EventId = Event->EventId;
    alert.Timestamp = Event->Timestamp;
    alert.ThreatType = ThreatType;
    alert.Risk = Risk;
    RmCharCopy(alert.Description, WKD_REG_MAX_DESC_CHARS, Description);
    alert.Operation = Event->Operation;
    RmWcsCopy(alert.KeyPath, WKD_RM_MAX_KEY_PATH_CHARS, Event->KeyPath);
    RmWcsCopy(alert.ValueName, WKD_RM_MAX_VALUE_NAME_CHARS, Event->ValueName);
    alert.ProcessId = Event->ProcessId;
    RmWcsCopy(alert.ProcessPath, WKD_REG_MAX_PATH_CHARS, Event->ProcessPath);
    RmCharCopy(alert.UserName, WKD_REG_MAX_NAME_CHARS, Event->UserName);
    alert.Verdict = Verdict;
    alert.WasBlocked = WasBlocked;
    RmMapMitreForThreat(ThreatType, alert.MitreTechnique, alert.MitreSubTechnique);

    InterlockedIncrement64(&g_Rm.Stats.AlertsGenerated);
    if (Risk >= WkdRmRisk_Critical) {
        InterlockedIncrement64(&g_Rm.Stats.CriticalAlerts);
    }

    /* 告警回调触发 (锁外) */
    AcquireSRWLockShared(&g_Rm.CallbackLock);
for (ULONG i = 0; i < WKD_RM_MAX_CALLBACKS; ++i) {
            if (g_Rm.AlertCallbacks[i].InUse && g_Rm.AlertCallbacks[i].Callback != NULL) {
                PFN_RM_ALERT_CALLBACK fn = (PFN_RM_ALERT_CALLBACK)g_Rm.AlertCallbacks[i].Callback;
                VOID* ctx = g_Rm.AlertCallbacks[i].Context;
                ULONGLONG t0 = GetTickCount64();
                fn(&alert, ctx);
                ULONGLONG elapsed = GetTickCount64() - t0;
                LONG64 sampleUs = (LONG64)elapsed * 1000;

                /* EMA 近似 (对齐 SS UpdatePerformanceStats):
                 * newAvg ≈ oldAvg*0.99 + sample*0.01; 首样本直存 */
                LONG64 currentAvg = InterlockedExchangeAdd64(&g_Rm.Stats.AvgCallbackTimeUs, 0);
                LONG64 newAvg = (currentAvg == 0)
                                    ? sampleUs
                                    : currentAvg - (currentAvg / 128) + (sampleUs / 128);
                InterlockedExchange64(&g_Rm.Stats.AvgCallbackTimeUs, newAvg);

                /* Max: CAS 循环 (对齐 SS compare_exchange_weak 语义) */
                LONG64 currentMax = InterlockedCompareExchange64(
                    &g_Rm.Stats.MaxCallbackTimeUs, 0, 0);
                while (sampleUs > currentMax) {
                    LONG64 observed = InterlockedCompareExchange64(
                        &g_Rm.Stats.MaxCallbackTimeUs, sampleUs, currentMax);
                    if (observed == currentMax) break;
                    currentMax = observed;
                }
            }
        }
    ReleaseSRWLockShared(&g_Rm.CallbackLock);

    RmDbgPrint(L"[RM] ALERT id=%I64u threat=%u risk=%u pid=%lu %ls blocked=%d",
               alert.AlertId, alert.ThreatType, alert.Risk,
               alert.ProcessId, alert.KeyPath, (INT)alert.WasBlocked);
}

/* ==================================================
 * ═══ 回调触发 (值/事件回调; 共享锁内快照 → 锁外调用)
 * ================================================== */

static
VOID RmInvokeValueCallbacks(_In_ PCWKD_RM_EVENT Event,
                            _In_ PCWKD_RM_VALUE_ANALYSIS Analysis) {
    AcquireSRWLockShared(&g_Rm.CallbackLock);
    for (ULONG i = 0; i < WKD_RM_MAX_CALLBACKS; ++i) {
        if (!g_Rm.ValueCallbacks[i].InUse || g_Rm.ValueCallbacks[i].Callback == NULL) continue;
        PFN_RM_VALUE_CALLBACK fn = (PFN_RM_VALUE_CALLBACK)g_Rm.ValueCallbacks[i].Callback;
        VOID* ctx = g_Rm.ValueCallbacks[i].Context;
        fn(Event, Analysis, ctx);
    }
    ReleaseSRWLockShared(&g_Rm.CallbackLock);
}

static
VOID RmInvokeEventCallbacks(_In_ PCWKD_RM_EVENT Event,
                            _In_ WKD_RM_VERDICT Verdict) {
    AcquireSRWLockShared(&g_Rm.CallbackLock);
    for (ULONG i = 0; i < WKD_RM_MAX_CALLBACKS; ++i) {
        if (!g_Rm.EventCallbacks[i].InUse || g_Rm.EventCallbacks[i].Callback == NULL) continue;
        PFN_RM_EVENT_CALLBACK fn = (PFN_RM_EVENT_CALLBACK)g_Rm.EventCallbacks[i].Callback;
        VOID* ctx = g_Rm.EventCallbacks[i].Context;
        fn(Event, Verdict, ctx);
    }
    ReleaseSRWLockShared(&g_Rm.CallbackLock);
}

/* ==================================================
 * ═══ 事件环保留 (环形缓冲, 覆盖最旧; 数据预览截断)
 * ================================================== */

static
VOID RmRingPushEvent(_In_ PCWKD_RM_EVENT Event) {
    AcquireSRWLockExclusive(&g_Rm.Lock);
    if (g_Rm.RecentEvents == NULL) {
        g_Rm.RecentEvents = (PWKD_RM_EVENT)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY,
            WKD_RM_MAX_RECENT_EVENTS * sizeof(WKD_RM_EVENT));
        if (g_Rm.RecentEvents == NULL) {
            ReleaseSRWLockExclusive(&g_Rm.Lock);
            return;
        }
        g_Rm.RecentEventCapacity = WKD_RM_MAX_RECENT_EVENTS;
    }
    PWKD_RM_EVENT slot = &g_Rm.RecentEvents[g_Rm.RecentEventNext];
    *slot = *Event;
    RmTruncateEventForRetention(slot);
    g_Rm.RecentEventNext = (g_Rm.RecentEventNext + 1) % g_Rm.RecentEventCapacity;
    if (g_Rm.RecentEventCount < g_Rm.RecentEventCapacity) {
        g_Rm.RecentEventCount++;
    } else {
        g_Rm.RecentEventHead = (g_Rm.RecentEventHead + 1) % g_Rm.RecentEventCapacity;
    }
    ReleaseSRWLockExclusive(&g_Rm.Lock);
}

/* ==================================================
 * ═══ 自防御键 (WkDefender 固有键集, 与保护表双轨)
 *
 *  对齐 SS SetupSelfDefenseKeys: 内核 \Registry\Machine 记法
 *  + 用户态 HKLM/HKEY_LOCAL_MACHINE 记法 + Wow6432Node 变体
 *  (防 32 位重定向绕过)。事件可能来自上层用户态转译端点,
 *  故 HKLM 前缀形式必须同样命中。
 * ================================================== */

static
BOOLEAN RmIsWkDefenderKeyPath(_In_ PCWSTR KeyPath) {
    if (KeyPath == NULL) return FALSE;
    /* 软件键: 内核记法 / HKLM 记法 / 完整 HKEY_LOCAL_MACHINE 记法 */
    if (RmWcsIContains(KeyPath, L"\\SOFTWARE\\WkDefender") ||
        RmWcsIContains(KeyPath, L"HKLM\\SOFTWARE\\WkDefender") ||
        RmWcsIContains(KeyPath, L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WkDefender")) {
        return TRUE;
    }
    /* Wow6432Node 变体: 32 位进程重定向绕过防护 */
    if (RmWcsIContains(KeyPath, L"\\SOFTWARE\\Wow6432Node\\WkDefender") ||
        RmWcsIContains(KeyPath, L"HKLM\\SOFTWARE\\Wow6432Node\\WkDefender")) {
        return TRUE;
    }
    /* 服务键: 内核记法 / HKLM 记法 */
    if (RmWcsIContains(KeyPath, L"\\Services\\WkDefender") ||
        RmWcsIContains(KeyPath, L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\WkDefender") ||
        RmWcsIContains(KeyPath, L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WkDefender")) {
        return TRUE;
    }
    return FALSE;
}

/* ==================================================
 * ═══ 事件处理链 (统一 Finalize 出口)
 *
 *  链序: 计数 → 隐写防护 → 蜜罐 → 自防御 → 规则 →
 *       策略回调 → 威胁检测 → 风险定级 → 裁决 →
 *       环保留 + 事件回调 + 统计
 *
 *  Redirect/Delay 裁决: WkD 无内核应答设施, 语义降级为
 *  Allow + 告警 (注释于 Finalize)
 * ================================================== */

WKD_RM_VERDICT
RmProcessEvent(_Inout_ PCWKD_RM_EVENT Event) {
    WKD_RM_VERDICT verdict = WkdRmVerdict_Allow;
    BOOLEAN blocked = FALSE;
    BOOLEAN silentDrop = FALSE;
    if (Event == NULL) return verdict;

    InterlockedIncrement64(&g_Rm.Stats.TotalEvents);

    /* 操作计数 (忽略未知/半已知操作; switch 语义) */
    switch (Event->Operation) {
    case WkdRmOp_CreateKey:  InterlockedIncrement64(&g_Rm.Stats.CreateKeyEvents);  break;
    case WkdRmOp_SetValue:   InterlockedIncrement64(&g_Rm.Stats.SetValueEvents);   break;
    case WkdRmOp_DeleteKey:  InterlockedIncrement64(&g_Rm.Stats.DeleteKeyEvents);  break;
    case WkdRmOp_DeleteValue:InterlockedIncrement64(&g_Rm.Stats.DeleteValueEvents);break;
    case WkdRmOp_RenameKey:  InterlockedIncrement64(&g_Rm.Stats.RenameEvents);     break;
    default: break;
    }

    /* 引擎状态守卫: 未初始化/未运行 → 透传允许 */
    if (!RmIsInitialized() || !RmIsRunning()) return verdict;

    /* 快照配置 (共享锁) */
    WKD_RM_CONFIG cfg;
    AcquireSRWLockShared(&g_Rm.Lock);
    cfg = g_Rm.Config;
    ReleaseSRWLockShared(&g_Rm.Lock);

    /* 1) 隐写防护: 键名/值名内嵌 NUL 字节 = 日志伪造/劫持试探
     *    post-op 无法改回键名/值名 → 降级 Allow (仅告警, 对齐 SS) */
    if (RmContainsNullBytes(Event->KeyPath, Event->KeyPathCharCount) ||
        RmContainsNullBytes(Event->ValueName, Event->ValueNameCharCount)) {
        InterlockedIncrement64(&g_Rm.Stats.SelfDefenseBlocks);
        if (Event->IsPreOperation) {
            RmReportAlert(Event, WkdRmThreat_SelfDefenseTamper,
                          WkdRmRisk_Critical, "null-byte cloaking attempt on registry path",
                          WkdRmVerdict_Block, TRUE);
            blocked = TRUE;
            verdict = WkdRmVerdict_Block;
        } else {
            RmReportAlert(Event, WkdRmThreat_SelfDefenseTamper,
                          WkdRmRisk_Critical, "null-byte cloaking registry path created (post-op)",
                          WkdRmVerdict_Alert, FALSE);
            verdict = WkdRmVerdict_Alert;
        }
        goto Finish;
    }

    /* 2) 蜜罐: 衰减模式投放 (命中蜜罐 → 静默丢包, 对齐 SS) */
    if (cfg.Deception.Enabled && cfg.Deception.HoneypotEnabled &&
        Event->IsPreOperation && RmIsHoneypotPath(Event->KeyPath)) {
        InterlockedIncrement64(&g_Rm.Stats.SilentDropped);
        silentDrop = TRUE;
        verdict = WkdRmVerdict_SilentDrop;
        goto Finish;
    }

    /* 3) 自防御: 受保护键 / WkDefender 固有键 */
    if (cfg.SelfDefenseEnabled) {
        BOOLEAN isDefended = RmIsWkDefenderKeyPath(Event->KeyPath) ||
                             RmIsProtectedKey(Event->KeyPath);
        if (isDefended) {
            InterlockedIncrement64(&g_Rm.Stats.SelfDefenseBlocks);
            if (Event->IsPreOperation) {
                RmReportAlert(Event, WkdRmThreat_SelfDefenseTamper,
                              WkdRmRisk_Critical, "blocked self-defense key access",
                              WkdRmVerdict_Block, TRUE);
                blocked = TRUE;
                verdict = WkdRmVerdict_Block;
            } else {
                /* 事后操作: 无法阻止, 仅告警 */
                RmReportAlert(Event, WkdRmThreat_SelfDefenseTamper,
                              WkdRmRisk_Critical, "self-defense key modified (post-op)",
                              WkdRmVerdict_Alert, FALSE);
                verdict = WkdRmVerdict_Alert;
            }
            goto Finish;
        }
    }

    /* 4) 规则链裁决 (MatchCount 计数在 RmEvaluateRules 内联完成,
     *    避免双重计数; post-op 无法阻止/无法静默 → 降级 Allow,
     *    对齐 SS: resultVerdict = isPreOperation ? ruleVerdict : Allow) */
    {
        WKD_RM_VERDICT rv = RmEvaluateRules(Event);
        if (rv != WkdRmVerdict_Allow) {
            if (rv == WkdRmVerdict_Block) {
                if (Event->IsPreOperation) {
                    blocked = TRUE;
                    verdict = WkdRmVerdict_Block;
                } else {
                    /* post-op: 操作已发生, 无法回溯, 降级 Allow */
                    verdict = WkdRmVerdict_Allow;
                }
                goto Finish;
            }
            if (rv == WkdRmVerdict_SilentDrop) {
                if (Event->IsPreOperation) {
                    silentDrop = TRUE;
                    verdict = WkdRmVerdict_SilentDrop;
                } else {
                    /* post-op: 静默丢弃不可行, 降级 Allow */
                    verdict = WkdRmVerdict_Allow;
                }
                goto Finish;
            }
            /* Alert/Redirect/Delay → 保留裁决继续走检测链
             * (WkD 无内核应答设施, Redirect/Delay 仅告警语义降级,
             *  由上层持久日志消费者处理; 见迁移说明) */
            verdict = rv;
        }
    }

    /* 6) 策略回调 (单槽, 锁外调用; 同规则链: post-op 降级 Allow) */
    {
        PFN_RM_POLICY_CALLBACK policy = NULL;
        VOID* policyCtx = NULL;
        AcquireSRWLockShared(&g_Rm.Lock);
        policy = g_Rm.PolicyCallback;
        policyCtx = g_Rm.PolicyContext;
        ReleaseSRWLockShared(&g_Rm.Lock);
        if (policy != NULL) {
            WKD_RM_VERDICT pv = policy(Event, policyCtx);
            if (pv != WkdRmVerdict_Allow) {
                if (pv == WkdRmVerdict_Block) {
                    if (Event->IsPreOperation) {
                        blocked = TRUE;
                        verdict = WkdRmVerdict_Block;
                    } else {
                        verdict = WkdRmVerdict_Allow;
                    }
                    goto Finish;
                }
                if (pv == WkdRmVerdict_SilentDrop) {
                    if (Event->IsPreOperation) {
                        silentDrop = TRUE;
                        verdict = WkdRmVerdict_SilentDrop;
                    } else {
                        verdict = WkdRmVerdict_Allow;
                    }
                    goto Finish;
                }
                /* Alert/Redirect/Delay → 保留裁决继续走检测链 */
                verdict = pv;
            }
        }
    }

    /* 7) 值分析 + 威胁检测 + 风险定级
     *    裁决: risk>=High → pre-op 阻止 / post-op 仅告警;
     *          低风险威胁 (识别但 <High) → 告警不干预 (对齐 SS) */
    if (cfg.AnalyzeValues && Event->ValueDataSize > 0) {
        WKD_RM_VALUE_ANALYSIS analysis;
        RmAnalyzeEventValue(Event, &analysis);

        if (cfg.DetectFileless || cfg.DetectPersistence || cfg.DetectSecurityChanges) {
            ULONG threat = RmDetectThreat(Event, &analysis);
            if (threat != WkdRmThreat_None) {
                ULONG risk = RmAssessRisk(threat, &analysis);
                InterlockedIncrement64(&g_Rm.Stats.PersistenceAttempts);
                if (threat == WkdRmThreat_FilelessPayload ||
                    threat == WkdRmThreat_PowershellCommand) {
                    InterlockedIncrement64(&g_Rm.Stats.FilelessPayloads);
                }
                if (risk >= WkdRmRisk_High) {
                    CHAR desc[WKD_REG_MAX_DESC_CHARS];
                    RmCharCopy(desc, WKD_REG_MAX_DESC_CHARS,
                               (threat == WkdRmThreat_FilelessPayload)
                                   ? "fileless payload in registry value"
                                   : "suspicious registry persistence");
                    if (Event->IsPreOperation) {
                        RmReportAlert(Event, threat, risk, desc,
                                      WkdRmVerdict_Block, TRUE);
                        blocked = TRUE;
                        verdict = WkdRmVerdict_Block;
                    } else {
                        /* post-op: 无法阻止, 仅告警 (WasBlocked=FALSE) */
                        RmReportAlert(Event, threat, risk, desc,
                                      WkdRmVerdict_Alert, FALSE);
                        verdict = WkdRmVerdict_Alert;
                    }
                    goto Finish;
                }
                /* 低风险威胁: 告警不干预, 继续值回调 */
                {
                    CHAR desc[WKD_REG_MAX_DESC_CHARS];
                    RmCharCopy(desc, WKD_REG_MAX_DESC_CHARS,
                               "low-risk registry activity (monitored)");
                    RmReportAlert(Event, threat, risk, desc,
                                  WkdRmVerdict_Alert, FALSE);
                    verdict = WkdRmVerdict_Alert;
                }
            }
        }

        /* 8) 值回调 (分析结果外发) */
        RmInvokeValueCallbacks(Event, &analysis);
    }

Finish:
    /* 统一出口: 统计 + 环保留 + 事件回调 */

    if (blocked) {
        InterlockedIncrement64(&g_Rm.Stats.BlockedOperations);
    } else if (silentDrop) {
        /* 已计 silentDropped */
    } else {
        InterlockedIncrement64(&g_Rm.Stats.AllowedOperations);
    }

    RmRingPushEvent(Event);
    RmInvokeEventCallbacks(Event, verdict);

    /* LogBlockedOnly 策略由上层接入持久日志时消费 (见迁移说明) */

    return verdict;
}

ULONG
RmGetRecentEvents(_Out_opt_ PWKD_RM_EVENT Events, _In_ ULONG MaxCount) {
    if (Events == NULL || MaxCount == 0) return 0;
    AcquireSRWLockShared(&g_Rm.Lock);
    ULONG n = (g_Rm.RecentEventCount < MaxCount) ? g_Rm.RecentEventCount : MaxCount;
    /* 倒序导出: 最新优先 (从 Next-1 逆推) */
    ULONG outIdx = 0;
    for (ULONG i = 0; i < n; ++i) {
        ULONG src = (g_Rm.RecentEventNext + g_Rm.RecentEventCapacity - 1 - i)
                    % g_Rm.RecentEventCapacity;
        Events[outIdx++] = g_Rm.RecentEvents[src];
    }
    ReleaseSRWLockShared(&g_Rm.Lock);
    return n;
}

/* ==================================================
 * ═══ 回调注册 (Alert/Event/Value 三类槽表, 共享
 *     NextCallbackId 计数, 单一 ID 空间)
 * ================================================== */

static
ULONG RmAllocateCallbackSlot(_Inout_ PRM_CALLBACK_SLOT Table,
                             _In_ PVOID Callback, _In_ PVOID Context) {
    AcquireSRWLockExclusive(&g_Rm.CallbackLock);
    for (ULONG i = 0; i < WKD_RM_MAX_CALLBACKS; ++i) {
        if (!Table[i].InUse) {
            Table[i].InUse = TRUE;
            Table[i].Callback = Callback;
            Table[i].Context = Context;
            Table[i].Id = (ULONG)InterlockedIncrement((volatile LONG*)&g_Rm.NextCallbackId);
            ULONG id = Table[i].Id;
            ReleaseSRWLockExclusive(&g_Rm.CallbackLock);
            return id;
        }
    }
    ReleaseSRWLockExclusive(&g_Rm.CallbackLock);
    return 0;
}

ULONG
RmRegisterAlertCallback(_In_ PFN_RM_ALERT_CALLBACK Callback,
                        _In_opt_ PVOID Context) {
    if (!RmIsInitialized() || Callback == NULL) return 0;
    return RmAllocateCallbackSlot(g_Rm.AlertCallbacks, (PVOID)Callback, Context);
}

ULONG
RmRegisterEventCallback(_In_ PFN_RM_EVENT_CALLBACK Callback,
                        _In_opt_ PVOID Context) {
    if (!RmIsInitialized() || Callback == NULL) return 0;
    return RmAllocateCallbackSlot(g_Rm.EventCallbacks, (PVOID)Callback, Context);
}

ULONG
RmRegisterValueCallback(_In_ PFN_RM_VALUE_CALLBACK Callback,
                        _In_opt_ PVOID Context) {
    if (!RmIsInitialized() || Callback == NULL) return 0;
    return RmAllocateCallbackSlot(g_Rm.ValueCallbacks, (PVOID)Callback, Context);
}

BOOLEAN
RmUnregisterCallback(_In_ ULONG CallbackId) {
    if (CallbackId == 0) return FALSE;
    AcquireSRWLockExclusive(&g_Rm.CallbackLock);
    PRM_CALLBACK_SLOT tables[3] = {
        g_Rm.AlertCallbacks, g_Rm.EventCallbacks, g_Rm.ValueCallbacks
    };
    for (ULONG t = 0; t < 3; ++t) {
        for (ULONG i = 0; i < WKD_RM_MAX_CALLBACKS; ++i) {
            if (tables[t][i].InUse && tables[t][i].Id == CallbackId) {
                tables[t][i].InUse = FALSE;
                tables[t][i].Callback = NULL;
                tables[t][i].Context = NULL;
                ReleaseSRWLockExclusive(&g_Rm.CallbackLock);
                return TRUE;
            }
        }
    }
    ReleaseSRWLockExclusive(&g_Rm.CallbackLock);
    return FALSE;
}

/* ==================================================
 * ═══ 统计 (原子计数快照)
 * ================================================== */

VOID
RmGetStatistics(_Out_ PWKD_RM_STATS Statistics) {
    if (Statistics == NULL) return;
    AcquireSRWLockShared(&g_Rm.Lock);
    *Statistics = g_Rm.Stats;
    ReleaseSRWLockShared(&g_Rm.Lock);
}

VOID
RmResetStatistics(VOID) {
    AcquireSRWLockExclusive(&g_Rm.Lock);
    RmResetStatsInternal();
    ReleaseSRWLockExclusive(&g_Rm.Lock);
}

/* ==================================================
 * ═══ 诊断与导出 (PerformDiagnostics; 导出为
 *     UTF-8 窄行文件, 对齐 RaWriteTextFile 样式)
 * ================================================== */

static
VOID RmWriteDiagLine(_In_ HANDLE File, _In_ PCSTR Line) {
    DWORD written = 0;
    WriteFile(File, Line, (DWORD)strlen(Line), &written, NULL);
    WriteFile(File, "\r\n", 2, &written, NULL);
}

static
VOID RmWriteDiagWide(_In_ HANDLE File, _In_ PCWSTR Label, _In_ PCWSTR Value) {
    CHAR narrow[WKD_RM_MAX_KEY_PATH_CHARS + 64];
    CHAR line[WKD_RM_MAX_KEY_PATH_CHARS + 128];
    RmSanitizeForLog(Value, narrow, WKD_RM_MAX_KEY_PATH_CHARS + 64);
    StringCchPrintfA(line, WKD_RM_MAX_KEY_PATH_CHARS + 128, "%ls: %s", Label, narrow);
    RmWriteDiagLine(File, line);
}

BOOLEAN
RmPerformDiagnostics(VOID) {
    BOOLEAN ok = TRUE;
    AcquireSRWLockShared(&g_Rm.Lock);

    /* 规则表一致性 */
    if (g_Rm.Rules == NULL && g_Rm.RuleCount != 0) {
        RmDbgPrint(L"[RM] diagnostics: rule table inconsistent (null storage)");
        ok = FALSE;
    }
    if (g_Rm.RuleCount > g_Rm.RuleCapacity) {
        RmDbgPrint(L"[RM] diagnostics: rule count exceeds capacity");
        ok = FALSE;
    }

    /* 保护键表一致性 */
    if ((g_Rm.ProtectedKeys == NULL) != (g_Rm.ProtectedKeysLower == NULL)) {
        RmDbgPrint(L"[RM] diagnostics: protected key mirror tables out of sync");
        ok = FALSE;
    }
    if (g_Rm.ProtectedKeyCount > g_Rm.ProtectedKeyCapacity) {
        RmDbgPrint(L"[RM] diagnostics: protected key count exceeds capacity");
        ok = FALSE;
    }

    /* 事件环一致性 */
    if (g_Rm.RecentEventCount > g_Rm.RecentEventCapacity) {
        RmDbgPrint(L"[RM] diagnostics: event ring count exceeds capacity");
        ok = FALSE;
    }

    /* 配置有效性 */
    if (g_Rm.Config.LargeValueThreshold > WKD_RM_MAX_VALUE_DATA_SIZE) {
        RmDbgPrint(L"[RM] diagnostics: large value threshold out of range");
        ok = FALSE;
    }
    if (g_Rm.Config.WorkerThreads > WKD_RM_MAX_WORKER_THREADS) {
        RmDbgPrint(L"[RM] diagnostics: worker thread count out of range (record-only)");
        ok = FALSE;
    }

    ReleaseSRWLockShared(&g_Rm.Lock);
    RmDbgPrint(L"[RM] diagnostics %s", ok ? L"passed" : L"failed");
    return ok;
}

BOOLEAN
RmExportDiagnostics(_In_ PCWSTR OutputPath) {
    if (OutputPath == NULL || RmWcsEmpty(OutputPath)) return FALSE;

    HANDLE file = CreateFileW(OutputPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        RmDbgPrint(L"[RM] export diagnostics: cannot open %ls (err=%lu)",
                   OutputPath, GetLastError());
        return FALSE;
    }

    CHAR line[WKD_RM_MAX_KEY_PATH_CHARS + 128];

    StringCchPrintfA(line, WKD_RM_MAX_KEY_PATH_CHARS + 128,
                     "WkDefender RegistryMonitor diagnostics v%d.%d.%d",
                     WKD_RM_VERSION_MAJOR, WKD_RM_VERSION_MINOR, WKD_RM_VERSION_PATCH);
    RmWriteDiagLine(file, line);

    WKD_RM_STATS stats;
    WKD_RM_CONFIG cfg;
    AcquireSRWLockShared(&g_Rm.Lock);
    stats = g_Rm.Stats;
    cfg = g_Rm.Config;
    ReleaseSRWLockShared(&g_Rm.Lock);

    StringCchPrintfA(line, WKD_RM_MAX_KEY_PATH_CHARS + 128,
                     "State: initialized=%d running=%d kernelCallback=%ls",
                     RmIsInitialized() ? 1 : 0, RmIsRunning() ? 1 : 0,
                     RmIsKernelConnected() ? L"connected" : L"not-connected(stub)");
    RmWriteDiagLine(file, line);

    StringCchPrintfA(line, WKD_RM_MAX_KEY_PATH_CHARS + 128,
                     "Monitoring: create=%d set=%d delKey=%d delVal=%d rename=%d "
                     "hive=%d sec=%d txn=%d",
                     (INT)cfg.MonitorCreateKey, (INT)cfg.MonitorSetValue,
                     (INT)cfg.MonitorDeleteKey, (INT)cfg.MonitorDeleteValue,
                     (INT)cfg.MonitorRename, (INT)cfg.MonitorLoadHive,
                     (INT)cfg.MonitorSecurity, (INT)cfg.MonitorTransactions);
    RmWriteDiagLine(file, line);

    StringCchPrintfA(line, WKD_RM_MAX_KEY_PATH_CHARS + 128,
                     "Detection: analyze=%d fileless=%d persistence=%d security=%d",
                     (INT)cfg.AnalyzeValues, (INT)cfg.DetectFileless,
                     (INT)cfg.DetectPersistence, (INT)cfg.DetectSecurityChanges);
    RmWriteDiagLine(file, line);

    StringCchPrintfA(line, WKD_RM_MAX_KEY_PATH_CHARS + 128,
                     "Stats: total=%I64d create=%I64d set=%I64d delKey=%I64d delVal=%I64d",
                     stats.TotalEvents, stats.CreateKeyEvents, stats.SetValueEvents,
                     stats.DeleteKeyEvents, stats.DeleteValueEvents);
    RmWriteDiagLine(file, line);

    StringCchPrintfA(line, WKD_RM_MAX_KEY_PATH_CHARS + 128,
                     "Stats: allowed=%I64d blocked=%I64d silentDrop=%I64d persist=%I64d",
                     stats.AllowedOperations, stats.BlockedOperations,
                     stats.SilentDropped, stats.PersistenceAttempts);
    RmWriteDiagLine(file, line);

    StringCchPrintfA(line, WKD_RM_MAX_KEY_PATH_CHARS + 128,
                     "Stats: alerts=%I64d critical=%I64d selfDefenseBlocks=%I64d",
                     stats.AlertsGenerated, stats.CriticalAlerts, stats.SelfDefenseBlocks);
    RmWriteDiagLine(file, line);

    StringCchPrintfA(line, WKD_RM_MAX_KEY_PATH_CHARS + 128,
                     "Rules: %lu / %lu entries", g_Rm.RuleCount, WKD_RM_MAX_RULES);
    RmWriteDiagLine(file, line);

    StringCchPrintfA(line, WKD_RM_MAX_KEY_PATH_CHARS + 128,
                     "ProtectedKeys: %lu / %lu  HoneypotKeys: %lu / %lu  Ring: %lu / %lu",
                     g_Rm.ProtectedKeyCount, WKD_RM_MAX_PROTECTED_KEYS,
                     g_Rm.HoneypotKeyCount, WKD_RM_MAX_HONEYPOT_KEYS,
                     g_Rm.RecentEventCount, WKD_RM_MAX_RECENT_EVENTS);
    RmWriteDiagLine(file, line);

    /* 最近事件摘要 (最多 16 条) */
    StringCchPrintfA(line, WKD_RM_MAX_KEY_PATH_CHARS + 128, "RecentEvents:");
    RmWriteDiagLine(file, line);
    {
        WKD_RM_EVENT ring[16];
        ULONG got = RmGetRecentEvents(ring, 16);
        for (ULONG i = 0; i < got; ++i) {
            CHAR keyNarrow[WKD_RM_MAX_KEY_PATH_CHARS];
            RmSanitizeForLog(ring[i].KeyPath, keyNarrow, WKD_RM_MAX_KEY_PATH_CHARS);
            StringCchPrintfA(line, WKD_RM_MAX_KEY_PATH_CHARS + 128,
                             "  op=%lu pid=%lu verdictPath=%s",
                             ring[i].Operation, ring[i].ProcessId, keyNarrow);
            RmWriteDiagLine(file, line);
        }
    }

    /* 自防御键 (只读遍历) */
    {
        WCHAR wk[WKD_RM_MAX_KEY_PATH_CHARS];
        RmWcsCopy(wk, WKD_RM_MAX_KEY_PATH_CHARS,
                  L"\\Registry\\Machine\\SOFTWARE\\WkDefender");
        RmWriteDiagWide(file, L"SelfDefenseKey", wk);
    }

    FlushFileBuffers(file);
    CloseHandle(file);

    RmDbgPrint(L"[RM] diagnostics exported: %ls", OutputPath);
    return TRUE;
}

/* ==================================================
 * RegistryMonitor.c — 迁移完成 (2026-09-08)
 * 虚标 stub 清单: FilterConnection/MessageDispatcher/
 * worker 线程泵 / WhiteListStore / ThreatIntelLookup /
 * ProcessUtils(enrich)。
 * ================================================== */