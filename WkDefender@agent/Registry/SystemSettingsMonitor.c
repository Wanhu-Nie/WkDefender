/**************************************************/
/*  WkDefender Agent — Registry\SystemSettingsMonitor */
/*  OS 安全配置监控引擎 (The Config Guardian)         */
/*                                                  */
/*  迁移来源: ShadowStrike PhantomCore/Core/Registry */
/*  SystemSettingsMonitor.cpp (2816 行 + .hpp 1116  */
/*  行, 2026-09-09 全量转写)                         */
/*                                                  */
/*  职责:                                            */
/*   - 配置读取 (轮询): UAC (EnableLUA/ConsentPrompt- */
/*     BehaviorAdmin/PromptOnSecureDesktop/...),     */
/*     Defender (DisableAntiSpyware/RTM/Behavior/    */
/*     IOAV/Spynet/NetworkProtection/CFA/PUA/        */
/*     TamperProtection), Firewall (Domain/Standard/ */
/*     Public 三 profile), Exploit (MoveImages/      */
/*     EnableCfg/SEHOP), LSA (RunAsPPL/Restrict-     */
/*     Anonymous/NoLMHash/LmCompatibilityLevel),     */
/*     Proxy (HKCU ProxyEnable/ProxyServer/          */
/*     AutoConfigURL), DNS (Global NameServer + 网卡 */
/*     NameServer/DhcpNameServer 枚举 256 上限, 去重) */
/*   - 轮询线程 (默认 1000ms, 钳位 [250, 60000]):    */
/*     快照比较 (DetectChanges) → 变更事件/告警/自动  */
/*     补救 (Restore*Defaults 真实写回)              */
/*   - 基线: Create/Get/Active/SetActive/RestoreTo/  */
/*     CompareTo (逐字段 diff)                       */
/*   - 合规: CheckCompliance (UAC/Defender/RTP/Public */
/*     Firewall 为 failed; ASLR/DEP 仅 warning),     */
/*     CheckPolicyCompliance (存在性 + 委托, 承袭 SS 偏弱) */
/*   - 历史: 环形缓冲 (最新优先), 按类过滤            */
/*   - 告警: 有界池 + 三级驱逐 (保护 Critical) +      */
/*     Acknowledge 取证保留                          */
/*   - 导出: 报告/设置 JSON (全字段转义)/历史, 路径   */
/*     规范化 + 日志注入防护                          */
/*                                                  */
/*  工程收敛 (虚标剔除/底座替代, 对齐迁移审计):       */
/*   - MonitorShell/MonitorPolicy: SS RefreshAllImpl */
/*     忽略对应开关 (接口虚标), 字段保留, 不实现      */
/*   - RegistryPaths 仅保留真实使用路径 (AMSI/ETW/PS */
/*     等 SS 未使用虚标路径不引入)                   */
/*   - ThreatIntelLookup/RegistryMonitor/ProcessMonitor */
/*     /wininet/fwpmu: 死依赖剔除                    */
/*   - IsDNSSuspicious: 承袭 SS 硬编码错拼暗桩列表     */
/*     {8.8.4.4(Google typo诱饵), 1.1.1.2(Cloudflare  */
/*     恶意软件过滤)}; 增强 #95: 可经 Config.          */
/*     SuspiciousDnsCheckEnabled 关闭 (默认 TRUE)      */
/*   - WDigest/LsaCfgFlags: 增强 #95 由"仅日志盲点"    */
/*     升级为边缘检测结构化告警 (T1003.001/T1112)      */
/*   - UAC RunAllAdminsInAAM 命名错位: 增强 #95 删除   */
/*     错位字段, EnableInstallerDetection 改入          */
/*     DetectInstallations (语义正确配对)              */
/*   - shared_mutex/mutex → SRWLOCK/CRITICAL_SECTION */
/*   - unordered_map/map/deque/vector → 线性槽表/    */
/*     环形数组/动态指针池 (查询低频, 文档注明)       */
/*   - 无 SS 缺陷修正清单见迁移档案 #92               */
/*                                                  */
/*  依赖 (WkD 底座):                                 */
/*   Common\Utils (UtHeapAlloc/UtHeapFree)          */
/*   Registry 子系统其余引擎: 无 (独立轮询引擎)       */
/**************************************************/

#include "RegistryInternal.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <wchar.h>
#include <string.h>
#include <strsafe.h>

#include "../Common/Utils.h"

#pragma comment(lib, "advapi32.lib")

/* ==================================================
 * 内部上下文 (对齐 SA_CONTEXT 模式; SS PIMPL Impl
 * 的模块级静态实例)
 * ================================================== */

typedef struct _SSM_CONTEXT {
    /* 生命周期与配置 */
    volatile LONG   Initialized;
    BOOLEAN         LocksInitialized;
    WKD_SSM_CONFIG  Config;
    SRWLOCK         Lock;            /* 保护状态/配置 (对应 SS m_mutex) */

    /* 当前状态 (对应 SS m_currentState) */
    WKD_SSM_UAC_SETTINGS       Uac;
    WKD_SSM_DEFENDER_SETTINGS  Defender;
    WKD_SSM_FIREWALL_SETTINGS  Firewall;
    WKD_SSM_EXPLOIT_SETTINGS   Exploit;
    WKD_SSM_LSA_SETTINGS       Lsa;
    WKD_SSM_PROXY_SETTINGS     Proxy;
    WKD_SSM_DNS_SETTINGS       Dns;

    /* 内部告警状态 (增强 #95: WDigest/LsaCfgFlags 边缘检测标志,
     * 置位后静默直至复位再触发, 防监控轮询重复轰炸) */
    BOOLEAN                    WdigestAlertSent;
    BOOLEAN                    LsaCfgAlertSent;

    /* 基线槽表 (对应 SS BaselineManager; 只增不删,
     * SS 无删除 API; 满 32 槽后 CreateBaseline 返回 0) */
    WKD_SSM_SNAPSHOT Baselines[WKD_SSM_MAX_BASELINES];
    ULONG            BaselineCount;
    volatile LONG64  NextBaselineId;
    BOOLEAN          HasActiveBaseline;
    ULONGLONG        ActiveBaselineId;

    /* 变更历史环形 (对应 SS ChangeTracker deque; 上限
     * HistoryMax 可经 SetMaxHistory 下调) */
    WKD_SSM_CHANGE   History[WKD_SSM_MAX_HISTORY];
    ULONG            HistoryHead;    /* 最旧条目下标 */
    ULONG            HistoryCount;
    ULONG            HistoryMax;
    CRITICAL_SECTION HistoryLock;

    /* 告警池 (对应 SS AlertManager map; 动态指针池,
     * 插入序即 id 升序; 驱逐释放堆块) */
    PWKD_SSM_ALERT*  Alerts;
    ULONG            AlertCount;
    ULONG            AlertCapacity;
    volatile LONG64  NextAlertId;
    CRITICAL_SECTION AlertsLock;

    /* 回调 (平行 id 槽精确注销, 对齐 SA 修正) */
    PFN_SSM_CHANGE_CALLBACK  ChangeCallbacks[WKD_SSM_MAX_CALLBACKS];
    PVOID       ChangeContexts[WKD_SSM_MAX_CALLBACKS];
    ULONG       ChangeCallbackIds[WKD_SSM_MAX_CALLBACKS];
    BOOLEAN     ChangeSlotFree[WKD_SSM_MAX_CALLBACKS];

    PFN_SSM_ALERT_CALLBACK    AlertCallbacks[WKD_SSM_MAX_CALLBACKS];
    PVOID       AlertContexts[WKD_SSM_MAX_CALLBACKS];
    ULONG       AlertCallbackIds[WKD_SSM_MAX_CALLBACKS];
    BOOLEAN     AlertSlotFree[WKD_SSM_MAX_CALLBACKS];

    PFN_SSM_COMPLIANCE_CALLBACK ComplianceCallbacks[WKD_SSM_MAX_CALLBACKS];
    PVOID       ComplianceContexts[WKD_SSM_MAX_CALLBACKS];
    ULONG       ComplianceCallbackIds[WKD_SSM_MAX_CALLBACKS];
    BOOLEAN     ComplianceSlotFree[WKD_SSM_MAX_CALLBACKS];
    CRITICAL_SECTION CallbacksLock;

    /* 监控线程 (对应 SS m_monitorThread) */
    HANDLE          MonitorThread;
    volatile LONG   Monitoring;      /* 对应 SS atomic<bool> m_monitoring */

    /* ID 分配 (Interlocked) */
    volatile LONG64 NextChangeId;
    volatile LONG   NextCallbackId;   /* 回调 id 全局递增 (三类共享, CallbackManager) */

    /* 统计 */
    WKD_SSM_STATS   Stats;
} SSM_CONTEXT;

static SSM_CONTEXT g_ssm = { 0 };

/* ==================================================
 * 静态工具函数 (匿名命名空间辅助集)
 * ================================================== */

/* 日志输出 (开发排障: OutputDebugStringW) */
static
VOID SsmDbgPrint(_In_ PCWSTR Format, ...) {
    WCHAR buf[1024];
    va_list args;
    va_start(args, Format);
    (VOID)vswprintf_s(buf, 1024, Format, args);
    va_end(args);
    OutputDebugStringW(buf);
}

/* 当前时间 (UTC FILETIME, 对齐 WKD_REG_TIMESTAMP) */
static
WKD_REG_TIMESTAMP SsmGetNow(VOID) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return (((ULONGLONG)ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

/* 日志字段清洗 (SanitizeForLog):
 * 宽→窄 UTF-8 + 1024 字符硬顶 + 控制字符替换 '?'。
 * 多字节 UTF-8 续字节恒 >= 0x80, 替换 <0x20 单字节安全。 */
static
VOID SsmSanitizeLogW(_In_ PCWSTR Wide, _Out_ CHAR* Out, _In_ ULONG OutCch) {
    if (Out == NULL || OutCch == 0) return;
    Out[0] = '\0';
    if (Wide == NULL) return;

    CHAR tmp[WKD_SSM_MAX_LOG_FIELD_CHARS + 64];
    int len = WideCharToMultiByte(CP_UTF8, 0, Wide, -1,
                                  tmp, (int)(sizeof(tmp) / sizeof(tmp[0])), NULL, NULL);
    if (len <= 0) return;
    if ((ULONG)(len - 1) > WKD_SSM_MAX_LOG_FIELD_CHARS) {
        tmp[WKD_SSM_MAX_LOG_FIELD_CHARS] = '\0';
        (VOID)StringCchCatA(tmp, _countof(tmp), "...<truncated>");
    }
    for (CHAR* c = tmp; *c != '\0'; ++c) {
        const unsigned char uc = (unsigned char)*c;
        if (uc < 0x20 || uc == 0x7F) *c = '?';
    }
    (VOID)StringCchCopyA(Out, OutCch, tmp);
}

static
VOID SsmSanitizeLogA(_In_ PCSTR Narrow, _Out_ CHAR* Out, _In_ ULONG OutCch) {
    if (Out == NULL || OutCch == 0) return;
    Out[0] = '\0';
    if (Narrow == NULL) return;

    CHAR tmp[WKD_SSM_MAX_LOG_FIELD_CHARS + 64];
    if (FAILED(StringCchCopyA(tmp, _countof(tmp), Narrow))) {
        tmp[WKD_SSM_MAX_LOG_FIELD_CHARS] = '\0';
        (VOID)StringCchCatA(tmp, _countof(tmp), "...<truncated>");
    }
    for (CHAR* c = tmp; *c != '\0'; ++c) {
        const unsigned char uc = (unsigned char)*c;
        if (uc < 0x20 || uc == 0x7F) *c = '?';
    }
    (VOID)StringCchCopyA(Out, OutCch, tmp);
}

/* 注册表读取 (ReadRegistryDwordSafe/ReadRegistryStringSafe;
 * ERROR 静默 + 保守默认值语义; Wow6464 Wow64ReadOpts) */
static
DWORD SsmRegQueryDword(_In_ HKEY hRoot, _In_ PCWSTR SubPath, _In_ PCWSTR ValueName,
                       _In_ DWORD DefaultValue, _In_ BOOLEAN Wow6464) {
    DWORD result = DefaultValue;
    if (SubPath == NULL || ValueName == NULL) return result;

    HKEY hKey = NULL;
    const REGSAM access = KEY_READ | (Wow6464 ? KEY_WOW64_64KEY : 0);
    if (RegOpenKeyExW(hRoot, SubPath, 0, access, &hKey) == ERROR_SUCCESS && hKey != NULL) {
        DWORD type = 0;
        DWORD size = sizeof(result);
        if (RegQueryValueExW(hKey, ValueName, NULL, &type, (LPBYTE)&result, &size)
                != ERROR_SUCCESS || type != REG_DWORD) {
            result = DefaultValue;
        }
        RegCloseKey(hKey);
    }
    return result;
}

static
BOOLEAN SsmRegQueryString(_In_ HKEY hRoot, _In_ PCWSTR SubPath, _In_ PCWSTR ValueName,
                          _Out_ PWSTR Out, _In_ ULONG OutCch, _In_ BOOLEAN Wow6464) {
    BOOLEAN ok = FALSE;
    if (Out == NULL || OutCch == 0) return FALSE;
    Out[0] = L'\0';
    if (SubPath == NULL || ValueName == NULL) return FALSE;

    HKEY hKey = NULL;
    const REGSAM access = KEY_READ | (Wow6464 ? KEY_WOW64_64KEY : 0);
    if (RegOpenKeyExW(hRoot, SubPath, 0, access, &hKey) == ERROR_SUCCESS && hKey != NULL) {
        DWORD type = 0;
        DWORD cb = OutCch * sizeof(WCHAR);
        if (RegQueryValueExW(hKey, ValueName, NULL, &type, (LPBYTE)Out, &cb) == ERROR_SUCCESS
                && (type == REG_SZ || type == REG_EXPAND_SZ)) {
            Out[OutCch - 1] = L'\0';   /* 强制终止 */
            ok = TRUE;
        } else {
            Out[0] = L'\0';
        }
        RegCloseKey(hKey);
    }
    return ok;
}

/* 枚举子键 (RegistryKey::EnumKeys; kMaxAdapters 语义
 * 由调用方提供 MaxCount 上限) */
static
BOOLEAN SsmEnumSubKeys(_In_ PCWSTR SubPath, _Out_ PWCHAR Names,
                       _In_ ULONG NamesCapacity, _In_ ULONG MaxCount, _Out_ PULONG Count) {
    if (Count == NULL) return FALSE;
    *Count = 0;
    if (SubPath == NULL || Names == NULL) return FALSE;

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SubPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    ULONG n = 0;
    for (ULONG i = 0; i < MaxCount; ++i) {
        PWSTR name = Names + ((ULONGLONG)i * WKD_REG_MAX_NAME_CHARS);
        DWORD nameCch = WKD_REG_MAX_NAME_CHARS;
        const LONG status = RegEnumKeyExW(hKey, i, name, &nameCch, NULL, NULL, NULL, NULL);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) break;
        ++n;
    }
    RegCloseKey(hKey);
    *Count = n;
    return TRUE;
}

/* 导出路径规范化 (TryCanonicaliseOutputPath):
 * 拒绝空/相对路径; GetFullPathNameW 归一 ./..; 不追符号链接 */
static
BOOLEAN SsmIsAbsolutePath(_In_ PCWSTR Path) {
    if (Path == NULL) return FALSE;
    if (Path[0] == L'\\' && Path[1] == L'\\') return TRUE;   /* UNC / \?\ */
    if ((Path[0] >= L'A' && Path[0] <= L'Z') || (Path[0] >= L'a' && Path[0] <= L'z')) {
        if (Path[1] == L':') return TRUE;                     /* X:\ */
    }
    return FALSE;
}

static
BOOLEAN SsmCanonicaliseExportPath(_In_ PCWSTR In, _Out_ PWSTR Out, _In_ ULONG OutCch) {
    if (Out == NULL || OutCch == 0) return FALSE;
    Out[0] = L'\0';
    if (!SsmIsAbsolutePath(In)) return FALSE;

    const DWORD len = GetFullPathNameW(In, OutCch, Out, NULL);
    if (len == 0 || len >= OutCch) {
        Out[0] = L'\0';
        return FALSE;
    }
    return TRUE;
}

/* JSON 字符串转义输出 (WriteJsonStringW/EscapeJson);
 * 防注册表值逃出 JSON 字符串上下文 (文档注入防护) */
static
VOID SsmWriteJsonEscapedW(_In_ FILE* File, _In_ PCWSTR Value) {
    if (File == NULL || Value == NULL) return;
    for (PCWSTR p = Value; *p != L'\0'; ++p) {
        const WCHAR c = *p;
        switch (c) {
            case L'"':  fputws(L"\\\"", File); break;
            case L'\\': fputws(L"\\\\", File); break;
            case L'\b': fputws(L"\\b", File);  break;
            case L'\f': fputws(L"\\f", File);  break;
            case L'\n': fputws(L"\\n", File);  break;
            case L'\r': fputws(L"\\r", File);  break;
            case L'\t': fputws(L"\\t", File);  break;
            default:
                if (c < 0x20) {
                    fwprintf(File, L"\\u%04x", (UINT)c);
                } else {
                    fputwc(c, File);
                }
                break;
        }
    }
}

/* 转换函数 (CategoryToString/SeverityToString/UACLevelToString) */
static
LPCSTR SsmCategoryToString(_In_ ULONG Category) {
    switch (Category) {
        case WkdSsmCat_Security: return "Security";
        case WkdSsmCat_Network: return "Network";
        case WkdSsmCat_Shell: return "Shell";
        case WkdSsmCat_Policy: return "Policy";
        case WkdSsmCat_Authentication: return "Authentication";
        case WkdSsmCat_Update: return "Update";
        case WkdSsmCat_Privacy: return "Privacy";
        case WkdSsmCat_Performance: return "Performance";
        default: return "Unknown";
    }
}

static
LPCSTR SsmSeverityToString(_In_ ULONG Severity) {
    switch (Severity) {
        case WkdSsmSev_Info: return "Info";
        case WkdSsmSev_Low: return "Low";
        case WkdSsmSev_Medium: return "Medium";
        case WkdSsmSev_High: return "High";
        case WkdSsmSev_Critical: return "Critical";
        default: return "Unknown";
    }
}

static
LPCWSTR SsmUacLevelToString(_In_ ULONG Level) {
    switch (Level) {
        case WkdSsmUac_Disabled: return L"Disabled";
        case WkdSsmUac_NotifyChanges: return L"Notify Changes";
        case WkdSsmUac_NotifyChangesNoDim: return L"Notify Changes (No Dim)";
        case WkdSsmUac_NotifyAll: return L"Notify All";
        case WkdSsmUac_AlwaysNotify: return L"Always Notify";
        default: return L"Unknown";
    }
}

/* 注册表路径常量 (仅真实使用路径; SS 虚标路径不引入) */
static const WCHAR SsmRegPath_Uac[] =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
static const WCHAR SsmRegPath_DefenderPolicy[] =
    L"SOFTWARE\\Policies\\Microsoft\\Windows Defender";
static const WCHAR SsmRegPath_DefenderFeatures[] =
    L"SOFTWARE\\Microsoft\\Windows Defender\\Features";
static const WCHAR SsmRegPath_Firewall[] =
    L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy";
static const WCHAR SsmRegPath_Proxy[] =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
static const WCHAR SsmRegPath_TcpParams[] =
    L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";
static const WCHAR SsmRegPath_TcpInterfaces[] =
    L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";
static const WCHAR SsmRegPath_Lsa[] =
    L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
static const WCHAR SsmRegPath_MemoryMgmt[] =
    L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management";
static const WCHAR SsmRegPath_ExploitKernel[] =
    L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel";
static const WCHAR SsmRegPath_WDigest[] =
    L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest";

/* ==================================================
 * 轮询间隔钳位 (MonitorThreadFunc clamp)
 * ================================================== */
static
ULONG SsmClampPollInterval(_In_ ULONG Ms) {
    if (Ms < WKD_SSM_MIN_POLL_INTERVAL_MS) return WKD_SSM_MIN_POLL_INTERVAL_MS;
    if (Ms > WKD_SSM_MAX_POLL_INTERVAL_MS) return WKD_SSM_MAX_POLL_INTERVAL_MS;
    return Ms;
}

/* ==================================================
 * 配置工厂 (CreateDefault/HighSecurity/MonitorOnly)
 * ================================================== */

VOID
SsmCreateDefaultConfig(_Out_ PWKD_SSM_CONFIG Config) {
    if (Config == NULL) return;
    memset(Config, 0, sizeof(*Config));

    Config->MonitorUAC = TRUE;
    Config->MonitorDefender = TRUE;
    Config->MonitorFirewall = TRUE;
    Config->MonitorExploitProtection = TRUE;
    Config->MonitorLSA = TRUE;
    Config->MonitorProxy = TRUE;
    Config->MonitorDNS = TRUE;
    Config->MonitorShell = TRUE;    /* SS 默认值 (未实现, 保留字段面) */
    Config->MonitorPolicy = TRUE;   /* 同上 */
    Config->SuspiciousDnsCheckEnabled = TRUE;   /* 增强 #95 */

    Config->EnableAutoRemediation = FALSE;
    Config->RemediateUAC = FALSE;
    Config->RemediateDefender = TRUE;
    Config->RemediateFirewall = TRUE;

    Config->MinimumAlertSeverity = WkdSsmSev_Medium;
    Config->AlertOnAnyChange = FALSE;
    Config->AlertOnSecurityDegrade = TRUE;

    Config->UseBaseline = TRUE;
    Config->AutoCreateBaseline = TRUE;

    Config->MaxHistoryEntries = WKD_SSM_MAX_HISTORY;
    Config->MonitorPollIntervalMs = WKD_SSM_DEFAULT_POLL_INTERVAL_MS;
}

VOID
SsmCreateHighSecurityConfig(_Out_ PWKD_SSM_CONFIG Config) {
    if (Config == NULL) return;
    memset(Config, 0, sizeof(*Config));

    Config->MonitorUAC = TRUE;
    Config->MonitorDefender = TRUE;
    Config->MonitorFirewall = TRUE;
    Config->MonitorExploitProtection = TRUE;
    Config->MonitorLSA = TRUE;
    Config->MonitorProxy = TRUE;
    Config->MonitorDNS = TRUE;
    Config->MonitorShell = TRUE;    /* SS 默认值 (未实现, 保留字段面) */
    Config->MonitorPolicy = TRUE;   /* 同上 */
    Config->SuspiciousDnsCheckEnabled = TRUE;   /* 增强 #95 */

    Config->EnableAutoRemediation = TRUE;
    Config->RemediateUAC = TRUE;
    Config->RemediateDefender = TRUE;
    Config->RemediateFirewall = TRUE;

    Config->MinimumAlertSeverity = WkdSsmSev_Low;
    Config->AlertOnAnyChange = TRUE;
    Config->AlertOnSecurityDegrade = TRUE;

    Config->UseBaseline = TRUE;
    Config->AutoCreateBaseline = TRUE;

    Config->MaxHistoryEntries = WKD_SSM_MAX_HISTORY;
    Config->MonitorPollIntervalMs = WKD_SSM_DEFAULT_POLL_INTERVAL_MS;
}

VOID
SsmCreateMonitorOnlyConfig(_Out_ PWKD_SSM_CONFIG Config) {
    if (Config == NULL) return;
    memset(Config, 0, sizeof(*Config));

    Config->MonitorUAC = TRUE;
    Config->MonitorDefender = TRUE;
    Config->MonitorFirewall = TRUE;
    Config->MonitorExploitProtection = TRUE;
    Config->MonitorLSA = TRUE;
    Config->MonitorProxy = TRUE;
    Config->MonitorDNS = TRUE;
    Config->MonitorShell = TRUE;    /* SS 默认值 (未实现, 保留字段面) */
    Config->MonitorPolicy = TRUE;   /* 同上 */
    Config->SuspiciousDnsCheckEnabled = TRUE;   /* 增强 #95 */

    Config->EnableAutoRemediation = FALSE;
    Config->RemediateUAC = FALSE;
    Config->RemediateDefender = FALSE;
    Config->RemediateFirewall = FALSE;

    Config->MinimumAlertSeverity = WkdSsmSev_Medium;
    Config->AlertOnAnyChange = FALSE;
    Config->AlertOnSecurityDegrade = TRUE;

    Config->UseBaseline = TRUE;
    Config->AutoCreateBaseline = TRUE;

    Config->MaxHistoryEntries = WKD_SSM_MAX_HISTORY;
    Config->MonitorPollIntervalMs = WKD_SSM_DEFAULT_POLL_INTERVAL_MS;
}

/* ==================================================
 * 统计 (SystemSettingsMonitorStatistics::Reset)
 * ================================================== */
static
VOID SsmResetStatsLocked(_Inout_ PWKD_SSM_STATS Stats) {
    InterlockedExchange64(&Stats->ChangesDetected, 0);
    InterlockedExchange64(&Stats->SecurityDegrades, 0);
    InterlockedExchange64(&Stats->AlertsGenerated, 0);
    InterlockedExchange64(&Stats->RemediationsPerformed, 0);
    InterlockedExchange64(&Stats->RemediationsFailed, 0);
    InterlockedExchange64(&Stats->UacChanges, 0);
    InterlockedExchange64(&Stats->DefenderChanges, 0);
    InterlockedExchange64(&Stats->FirewallChanges, 0);
    InterlockedExchange64(&Stats->NetworkChanges, 0);
    InterlockedExchange64(&Stats->ShellChanges, 0);
}

/* ==================================================
 * 回调管理器 (对应 SS CallbackManager)
 * 锁约定: 槽表由 CallbacksLock 保护; 调用时先拷贝槽
 * 内容到局部数组再释放锁执行, 防回调重入死锁。
 * 注销按 id 在平行 id 槽精确匹配 (对齐 SA 修正)。
 * ================================================== */

ULONG
SsmRegisterChangeCallback(
    _In_ PFN_SSM_CHANGE_CALLBACK Callback,
    _In_opt_ PVOID Context
    ) {
    ULONG id = 0;
    if (Callback == NULL) return 0;
    if (g_ssm.LocksInitialized == FALSE) return 0;

    EnterCriticalSection(&g_ssm.CallbacksLock);
    for (ULONG i = 0; i < WKD_SSM_MAX_CALLBACKS; ++i) {
        if (g_ssm.ChangeSlotFree[i]) {
            g_ssm.ChangeSlotFree[i] = FALSE;
            g_ssm.ChangeCallbacks[i] = Callback;
            g_ssm.ChangeContexts[i] = Context;
            id = (ULONG)InterlockedIncrement(&g_ssm.NextCallbackId);
            if (id == 0) id = (ULONG)InterlockedIncrement(&g_ssm.NextCallbackId); /* 防 0 哨兵 */
            g_ssm.ChangeCallbackIds[i] = id;
            break;
        }
    }
    LeaveCriticalSection(&g_ssm.CallbacksLock);
    return id;
}

ULONG
SsmRegisterAlertCallback(
    _In_ PFN_SSM_ALERT_CALLBACK Callback,
    _In_opt_ PVOID Context
    ) {
    ULONG id = 0;
    if (Callback == NULL) return 0;
    if (g_ssm.LocksInitialized == FALSE) return 0;

    EnterCriticalSection(&g_ssm.CallbacksLock);
    for (ULONG i = 0; i < WKD_SSM_MAX_CALLBACKS; ++i) {
        if (g_ssm.AlertSlotFree[i]) {
            g_ssm.AlertSlotFree[i] = FALSE;
            g_ssm.AlertCallbacks[i] = Callback;
            g_ssm.AlertContexts[i] = Context;
            id = (ULONG)InterlockedIncrement(&g_ssm.NextCallbackId);
            if (id == 0) id = (ULONG)InterlockedIncrement(&g_ssm.NextCallbackId);
            g_ssm.AlertCallbackIds[i] = id;
            break;
        }
    }
    LeaveCriticalSection(&g_ssm.CallbacksLock);
    return id;
}

ULONG
SsmRegisterComplianceCallback(
    _In_ PFN_SSM_COMPLIANCE_CALLBACK Callback,
    _In_opt_ PVOID Context
    ) {
    ULONG id = 0;
    if (Callback == NULL) return 0;
    if (g_ssm.LocksInitialized == FALSE) return 0;

    EnterCriticalSection(&g_ssm.CallbacksLock);
    for (ULONG i = 0; i < WKD_SSM_MAX_CALLBACKS; ++i) {
        if (g_ssm.ComplianceSlotFree[i]) {
            g_ssm.ComplianceSlotFree[i] = FALSE;
            g_ssm.ComplianceCallbacks[i] = Callback;
            g_ssm.ComplianceContexts[i] = Context;
            id = (ULONG)InterlockedIncrement(&g_ssm.NextCallbackId);
            if (id == 0) id = (ULONG)InterlockedIncrement(&g_ssm.NextCallbackId);
            g_ssm.ComplianceCallbackIds[i] = id;
            break;
        }
    }
    LeaveCriticalSection(&g_ssm.CallbacksLock);
    return id;
}

BOOLEAN
SsmUnregisterCallback(
    _In_ ULONG CallbackId
    ) {
    BOOLEAN found = FALSE;
    if (CallbackId == 0) return FALSE;
    if (g_ssm.LocksInitialized == FALSE) return FALSE;

    EnterCriticalSection(&g_ssm.CallbacksLock);

    for (ULONG i = 0; i < WKD_SSM_MAX_CALLBACKS && !found; ++i) {
        if (!g_ssm.ChangeSlotFree[i] && g_ssm.ChangeCallbackIds[i] == CallbackId) {
            found = TRUE;
            g_ssm.ChangeSlotFree[i] = TRUE;
            g_ssm.ChangeCallbacks[i] = NULL;
            g_ssm.ChangeContexts[i] = NULL;
            g_ssm.ChangeCallbackIds[i] = 0;
        }
    }
    for (ULONG i = 0; i < WKD_SSM_MAX_CALLBACKS && !found; ++i) {
        if (!g_ssm.AlertSlotFree[i] && g_ssm.AlertCallbackIds[i] == CallbackId) {
            found = TRUE;
            g_ssm.AlertSlotFree[i] = TRUE;
            g_ssm.AlertCallbacks[i] = NULL;
            g_ssm.AlertContexts[i] = NULL;
            g_ssm.AlertCallbackIds[i] = 0;
        }
    }
    for (ULONG i = 0; i < WKD_SSM_MAX_CALLBACKS && !found; ++i) {
        if (!g_ssm.ComplianceSlotFree[i] && g_ssm.ComplianceCallbackIds[i] == CallbackId) {
            found = TRUE;
            g_ssm.ComplianceSlotFree[i] = TRUE;
            g_ssm.ComplianceCallbacks[i] = NULL;
            g_ssm.ComplianceContexts[i] = NULL;
            g_ssm.ComplianceCallbackIds[i] = 0;
        }
    }

    LeaveCriticalSection(&g_ssm.CallbacksLock);
    return found;
}

/* 锁外调用 (槽内容拷贝后释放锁; SEH 防回调异常逃逸) */
static
VOID SsmInvokeChangeCallbacks(_In_ PCWKD_SSM_CHANGE Change) {
    PFN_SSM_CHANGE_CALLBACK fns[WKD_SSM_MAX_CALLBACKS];
    PVOID ctxs[WKD_SSM_MAX_CALLBACKS];
    ULONG n = 0;

    EnterCriticalSection(&g_ssm.CallbacksLock);
    for (ULONG i = 0; i < WKD_SSM_MAX_CALLBACKS; ++i) {
        if (!g_ssm.ChangeSlotFree[i] && g_ssm.ChangeCallbacks[i] != NULL) {
            fns[n] = g_ssm.ChangeCallbacks[i];
            ctxs[n] = g_ssm.ChangeContexts[i];
            if (++n >= _countof(fns)) break;
        }
    }
    LeaveCriticalSection(&g_ssm.CallbacksLock);

    for (ULONG j = 0; j < n; ++j) {
        __try {
            fns[j](Change, ctxs[j]);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SsmDbgPrint(L"[SSM] Change callback %lu faulted", j);
        }
    }
}

static
VOID SsmInvokeAlertCallbacks(_In_ PCWKD_SSM_ALERT Alert) {
    PFN_SSM_ALERT_CALLBACK fns[WKD_SSM_MAX_CALLBACKS];
    PVOID ctxs[WKD_SSM_MAX_CALLBACKS];
    ULONG n = 0;

    EnterCriticalSection(&g_ssm.CallbacksLock);
    for (ULONG i = 0; i < WKD_SSM_MAX_CALLBACKS; ++i) {
        if (!g_ssm.AlertSlotFree[i] && g_ssm.AlertCallbacks[i] != NULL) {
            fns[n] = g_ssm.AlertCallbacks[i];
            ctxs[n] = g_ssm.AlertContexts[i];
            if (++n >= _countof(fns)) break;
        }
    }
    LeaveCriticalSection(&g_ssm.CallbacksLock);

    for (ULONG j = 0; j < n; ++j) {
        __try {
            fns[j](Alert, ctxs[j]);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SsmDbgPrint(L"[SSM] Alert callback %lu faulted", j);
        }
    }
}

static
VOID SsmInvokeComplianceCallbacks(_In_ PCWKD_SSM_COMPLIANCE Status) {
    PFN_SSM_COMPLIANCE_CALLBACK fns[WKD_SSM_MAX_CALLBACKS];
    PVOID ctxs[WKD_SSM_MAX_CALLBACKS];
    ULONG n = 0;

    EnterCriticalSection(&g_ssm.CallbacksLock);
    for (ULONG i = 0; i < WKD_SSM_MAX_CALLBACKS; ++i) {
        if (!g_ssm.ComplianceSlotFree[i] && g_ssm.ComplianceCallbacks[i] != NULL) {
            fns[n] = g_ssm.ComplianceCallbacks[i];
            ctxs[n] = g_ssm.ComplianceContexts[i];
            if (++n >= _countof(fns)) break;
        }
    }
    LeaveCriticalSection(&g_ssm.CallbacksLock);

    for (ULONG j = 0; j < n; ++j) {
        __try {
            fns[j](Status, ctxs[j]);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SsmDbgPrint(L"[SSM] Compliance callback %lu faulted", j);
        }
    }
}

/* ==================================================
 * 基线管理器 (对应 SS BaselineManager)
 * 锁约定: 槽表由 g_ssm.Lock 保护 (SS 独立锁收敛为
 * 单一 SRW; 行为等价, 文档注明)。只增不删, 满
 * WKD_SSM_MAX_BASELINES 后 Create 返回 0。
 * ================================================== */

/* 调用方须持 g_ssm.Lock 独占 */
static
ULONGLONG SsmBaselineCreateLocked(_In_ PCWKD_SSM_SNAPSHOT Snapshot) {
    if (Snapshot == NULL) return 0;
    if (g_ssm.BaselineCount >= WKD_SSM_MAX_BASELINES) return 0;

    PWKD_SSM_SNAPSHOT dst = &g_ssm.Baselines[g_ssm.BaselineCount];
    *dst = *Snapshot;
    ULONGLONG id = (ULONGLONG)InterlockedIncrement64(&g_ssm.NextBaselineId);
    if (id == 0) id = (ULONGLONG)InterlockedIncrement64(&g_ssm.NextBaselineId);
    dst->SnapshotId = id;
    ++g_ssm.BaselineCount;

    CHAR desc[WKD_REG_MAX_DESC_CHARS];
    SsmSanitizeLogA(dst->Description, desc, _countof(desc));
    SsmDbgPrint(L"[SSM] Created baseline %I64u - %hs", id, desc);
    return id;
}

/* 调用方须持 g_ssm.Lock (共享/独占均可) */
static
BOOLEAN SsmBaselineFindLocked(_In_ ULONGLONG BaselineId, _Out_ PULONG Index) {
    for (ULONG i = 0; i < g_ssm.BaselineCount; ++i) {
        if (g_ssm.Baselines[i].SnapshotId == BaselineId) {
            if (Index != NULL) *Index = i;
            return TRUE;
        }
    }
    return FALSE;
}

/* 调用方须持 g_ssm.Lock (共享/独占均可); 输出活动基线快照 */
static
BOOLEAN SsmBaselineActiveLocked(_Out_ PWKD_SSM_SNAPSHOT Out) {
    if (!g_ssm.HasActiveBaseline) return FALSE;
    if (Out == NULL) return FALSE;

    for (ULONG i = 0; i < g_ssm.BaselineCount; ++i) {
        if (g_ssm.Baselines[i].SnapshotId == g_ssm.ActiveBaselineId) {
            *Out = g_ssm.Baselines[i];
            return TRUE;
        }
    }
    return FALSE;
}

/* ==================================================
 * 变更跟踪器 (对应 SS ChangeTracker deque 环形)
 * 锁约定: HistoryLock 保护。GetHistory 返回尾部片段
 * (旧→新, assign(first, end)); GetByCategory
 * 从尾部向前收集 (新→旧, rbegin 遍历)。
 * ================================================== */

/* 环形后继下标 (物理数组大小取模) */
static
ULONG SsmHistoryNext(_In_ ULONG Index) {
    return (Index + 1) % WKD_SSM_MAX_HISTORY;
}

/* 环形物理下标 → 逻辑序号 (0=最旧) */
static
ULONG SsmHistoryIndex(_In_ ULONG Logical) {
    return (g_ssm.HistoryHead + Logical) % WKD_SSM_MAX_HISTORY;
}

/* 调用方须持 HistoryLock */
static
VOID SsmTrackerRecordLocked(_In_ PCWKD_SSM_CHANGE Change) {
    if (Change == NULL) return;

    /* RecordChange: push_back + 超限 pop_front。
     * SetMaxLocked 已保证 HistoryCount <= HistoryMax, 故只需弹出头部。 */
    if (g_ssm.HistoryCount >= g_ssm.HistoryMax) {
        g_ssm.HistoryHead = SsmHistoryNext(g_ssm.HistoryHead);
        g_ssm.HistoryCount--;
    }

    const ULONG slot = SsmHistoryIndex(g_ssm.HistoryCount);
    g_ssm.History[slot] = *Change;
    g_ssm.HistoryCount++;
}

/* 调用方须持 HistoryLock; 返回已拷贝条数 (旧→新; Out 可为 NULL 仅计数,
 * 对齐头文件 "Changes 可为 NULL (仅取 Count)" 约定) */
static
ULONG SsmTrackerGetHistoryLocked(_In_ ULONG MaxCount, _Out_opt_ PWKD_SSM_CHANGE Out,
                                 _In_ ULONG Capacity) {
    if (g_ssm.HistoryCount == 0 || MaxCount == 0) return 0;

    ULONG toCopy = (MaxCount < g_ssm.HistoryCount) ? MaxCount : g_ssm.HistoryCount;
    if (Out != NULL && toCopy > Capacity) toCopy = Capacity;

    const ULONG startLog = g_ssm.HistoryCount - toCopy;
    if (Out != NULL) {
        for (ULONG k = 0; k < toCopy; ++k) {
            Out[k] = g_ssm.History[SsmHistoryIndex(startLog + k)];
        }
    }
    return toCopy;
}

/* 调用方须持 HistoryLock; 返回已拷贝条数 (新→旧; Out 可为 NULL 仅计数) */
static
ULONG SsmTrackerGetByCategoryLocked(_In_ ULONG Category, _In_ ULONG MaxCount,
                                    _Out_opt_ PWKD_SSM_CHANGE Out, _In_ ULONG Capacity) {
    if (g_ssm.HistoryCount == 0 || MaxCount == 0) return 0;

    ULONG n = 0;
    for (LONG l = (LONG)g_ssm.HistoryCount - 1;
         l >= 0 && (Out == NULL || n < Capacity) && n < MaxCount; --l) {
        const ULONG slot = SsmHistoryIndex((ULONG)l);
        if (g_ssm.History[slot].Category == Category) {
            if (Out != NULL) {
                Out[n] = g_ssm.History[slot];
            }
            ++n;
        }
    }
    return n;
}

/* 调用方须持 HistoryLock */
static
VOID SsmTrackerSetMaxLocked(_In_ ULONG Max) {
    g_ssm.HistoryMax = (Max == 0) ? 1 : Max;
    if (g_ssm.HistoryMax > WKD_SSM_MAX_HISTORY) {
        g_ssm.HistoryMax = WKD_SSM_MAX_HISTORY;
    }
    while (g_ssm.HistoryCount > g_ssm.HistoryMax) {
        g_ssm.HistoryHead = SsmHistoryNext(g_ssm.HistoryHead);
        g_ssm.HistoryCount--;
    }
}

/* ==================================================
 * 告警池 (对应 SS AlertManager; map → 动态指针池)
 * 锁约定: AlertsLock 保护。插入序即 id 升序 (数组头
 * 为最旧, ordered map begin())。三级驱逐:
 * ① 最旧 acknowledged 且 <Critical ② 最旧 <Critical
 * ③ 最旧任意。Acknowledge 取证保留 (不删除)。
 * ================================================== */

/* 调用方须持 AlertsLock */
static
VOID SsmAlertEvictOneLocked(VOID) {
    if (g_ssm.AlertCount == 0) return;

    LONG victim = -1;

    /* Pass 1: 最旧 acknowledged 且低于 Critical */
    for (LONG i = 0; i < (LONG)g_ssm.AlertCount; ++i) {
        if (g_ssm.Alerts[i]->Acknowledged &&
            g_ssm.Alerts[i]->Severity < WkdSsmSev_Critical) {
            victim = i;
            break;
        }
    }
    /* Pass 2: 最旧非 Critical (不论确认) */
    if (victim < 0) {
        for (LONG i = 0; i < (LONG)g_ssm.AlertCount; ++i) {
            if (g_ssm.Alerts[i]->Severity < WkdSsmSev_Critical) {
                victim = i;
                break;
            }
        }
    }
    /* Pass 3: 池满且全为 Critical → 驱逐最旧 */
    if (victim < 0) {
        victim = 0;
    }

    if (victim >= 0) {
        UtHeapFree(g_ssm.Alerts[victim]);
        if ((ULONG)victim + 1 < g_ssm.AlertCount) {
            memmove(&g_ssm.Alerts[victim], &g_ssm.Alerts[victim + 1],
                    (g_ssm.AlertCount - (ULONG)victim - 1) * sizeof(PWKD_SSM_ALERT));
        }
        g_ssm.AlertCount--;
    }
}

static
ULONGLONG SsmAlertCreate(_In_ PCWKD_SSM_ALERT Alert) {
    ULONGLONG id = 0;
    if (Alert == NULL) return 0;

    EnterCriticalSection(&g_ssm.AlertsLock);

    if (g_ssm.AlertCount >= WKD_SSM_MAX_ALERTS) {
        SsmAlertEvictOneLocked();
    }

    PWKD_SSM_ALERT copy = (PWKD_SSM_ALERT)UtHeapAlloc(sizeof(WKD_SSM_ALERT));
    if (copy == NULL) {
        LeaveCriticalSection(&g_ssm.AlertsLock);
        return 0;
    }
    *copy = *Alert;

    id = (ULONGLONG)InterlockedIncrement64(&g_ssm.NextAlertId);
    if (id == 0) id = (ULONGLONG)InterlockedIncrement64(&g_ssm.NextAlertId);
    copy->AlertId = id;

    if (g_ssm.AlertCount >= g_ssm.AlertCapacity) {
        ULONG newCap = (g_ssm.AlertCapacity == 0) ? 64 : g_ssm.AlertCapacity * 2;
        if (newCap > WKD_SSM_MAX_ALERTS) newCap = WKD_SSM_MAX_ALERTS;
        if (newCap > g_ssm.AlertCapacity) {
            PWKD_SSM_ALERT* newArr = (PWKD_SSM_ALERT*)UtHeapAlloc(newCap * sizeof(PWKD_SSM_ALERT));
            if (newArr == NULL) {
                UtHeapFree(copy);
                LeaveCriticalSection(&g_ssm.AlertsLock);
                return 0;
            }
            if (g_ssm.AlertCount > 0) {
                memcpy(newArr, g_ssm.Alerts, g_ssm.AlertCount * sizeof(PWKD_SSM_ALERT));
            }
            UtHeapFree(g_ssm.Alerts);
            g_ssm.Alerts = newArr;
            g_ssm.AlertCapacity = newCap;
        }
    }

    g_ssm.Alerts[g_ssm.AlertCount] = copy;
    g_ssm.AlertCount++;

    LeaveCriticalSection(&g_ssm.AlertsLock);

    /* 日志AlertManager::CreateAlert (SS_LOG_WARN) */
    CHAR title[WKD_REG_MAX_NAME_CHARS];
    SsmSanitizeLogA(copy->Title, title, _countof(title));
    SsmDbgPrint(L"[SSM] Alert #%I64u [%hs] - %hs", id,
                SsmSeverityToString(copy->Severity), title);
    return id;
}

static
ULONG SsmAlertGetActiveLocked(_Out_ PWKD_SSM_ALERT Out, _In_ ULONG Capacity) {
    if (Out == NULL || Capacity == 0) return 0;
    ULONG n = 0;
    for (ULONG i = 0; i < g_ssm.AlertCount && n < Capacity; ++i) {
        /* GetActiveAlerts 过滤: 未补救且未确认 (对齐 SS) */
        if (!g_ssm.Alerts[i]->WasRemediated && !g_ssm.Alerts[i]->Acknowledged) {
            Out[n] = *g_ssm.Alerts[i];
            ++n;
        }
    }
    return n;
}

static
BOOLEAN SsmAlertAcknowledgeLocked(_In_ ULONGLONG AlertId) {
    /* Acknowledge 取证保留: 置 acknowledged + wasRemediated, 不删除 (对齐 SS) */
    for (ULONG i = 0; i < g_ssm.AlertCount; ++i) {
        if (g_ssm.Alerts[i]->AlertId == AlertId) {
            g_ssm.Alerts[i]->Acknowledged = TRUE;
            g_ssm.Alerts[i]->WasRemediated = TRUE;
            return TRUE;
        }
    }
    return FALSE;
}

static
VOID SsmAlertClearAllLocked(VOID) {
    for (ULONG i = 0; i < g_ssm.AlertCount; ++i) {
        UtHeapFree(g_ssm.Alerts[i]);
        g_ssm.Alerts[i] = NULL;
    }
    g_ssm.AlertCount = 0;
    if (g_ssm.Alerts != NULL) {
        UtHeapFree(g_ssm.Alerts);
        g_ssm.Alerts = NULL;
        g_ssm.AlertCapacity = 0;
    }
}

/* ==================================================
 * 注册表写入辅助 (Utils::RegistryUtils::QuickWriteDWord;
 * Wow6464 Wow64WriteOpts; CreateKeyEx 语义 ≥ 原实现)
 * ================================================== */
static
BOOLEAN SsmRegWriteDword(_In_ HKEY hRoot, _In_ PCWSTR SubPath, _In_ PCWSTR ValueName,
                         _In_ DWORD Value, _In_ BOOLEAN Wow6464) {
    if (SubPath == NULL || ValueName == NULL) return FALSE;

    HKEY hKey = NULL;
    const REGSAM access = KEY_SET_VALUE | (Wow6464 ? KEY_WOW64_64KEY : 0);
    if (RegCreateKeyExW(hRoot, SubPath, 0, NULL, 0, access, NULL, &hKey, NULL)
            != ERROR_SUCCESS || hKey == NULL) {
        return FALSE;
    }
    const BOOLEAN ok = (RegSetValueExW(hKey, ValueName, 0, REG_DWORD,
                                       (const BYTE*)&Value, sizeof(Value)) == ERROR_SUCCESS);
    RegCloseKey(hKey);
    return ok;
}

/* ==================================================
 * DNS CSV 解析 (RefreshDNSImpl append_csv:
 * find_first_of(L", ") 切分; 上限 WKD_SSM_DNS_MAX_SERVERS)
 * ================================================== */
static
VOID SsmDnsAppendCsv(_Inout_ PWKD_SSM_DNS_SETTINGS Dns, _In_ PCWSTR Csv) {
    if (Dns == NULL || Csv == NULL || Csv[0] == L'\0') return;

    WCHAR tmp[512];
    if (FAILED(StringCchCopyW(tmp, _countof(tmp), Csv))) return;   /* 超长截断失败则放弃 */

    WCHAR* token = tmp;
    WCHAR* p = tmp;
    BOOLEAN done = FALSE;
    while (!done) {
        if (*p == L',' || *p == L' ' || *p == L'\0') {
            if (p > token) {
                const WCHAR c = *p;
                *p = L'\0';
                if (Dns->DnsServerCount < WKD_SSM_DNS_MAX_SERVERS) {
                    StringCchCopyW(Dns->DnsServers[Dns->DnsServerCount],
                                   WKD_SSM_DNS_MAX_IP_CHARS, token);
                    Dns->DnsServerCount++;
                }
                *p = c;
                if (c == L'\0') done = TRUE;
                token = p + 1;
            } else {
                if (*p == L'\0') done = TRUE;
                token = p + 1;
            }
        }
        ++p;
    }
}

/* 保序去重 (find-on-vector; 大小写敏感 wcscmp) */
static
VOID SsmDnsDedupe(_Inout_ PWKD_SSM_DNS_SETTINGS Dns) {
    if (Dns == NULL) return;
    ULONG w = 0;
    for (ULONG r = 0; r < Dns->DnsServerCount; ++r) {
        BOOLEAN dup = FALSE;
        for (ULONG k = 0; k < w; ++k) {
            if (wcscmp(Dns->DnsServers[k], Dns->DnsServers[r]) == 0) { dup = TRUE; break; }
        }
        if (!dup) {
            if (w != r) {
                StringCchCopyW(Dns->DnsServers[w], WKD_SSM_DNS_MAX_IP_CHARS,
                               Dns->DnsServers[r]);
            }
            ++w;
        }
    }
    Dns->DnsServerCount = w;
}

/* ==================================================
 * 状态刷新实现 (对应 SS Refresh*Impl; 调用方须持 Lock 独占;
 * 增强 #95: WDigest/LsaCfgFlags 由"仅日志盲点"升级为
 * 边缘检测结构化告警)
 * ================================================== */
static
VOID SsmRefreshUacLocked(VOID) {
    /* Wow64 视图读取 (Wow64ReadOpts) */
    g_ssm.Uac.Enabled =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_Uac, L"EnableLUA", 1, TRUE) != 0);

    g_ssm.Uac.ConsentPromptAdmin =
        SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_Uac, L"ConsentPromptBehaviorAdmin", 5, TRUE);

    g_ssm.Uac.PromptOnSecureDesktop =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_Uac, L"PromptOnSecureDesktop", 1, TRUE) != 0);

    g_ssm.Uac.FilterAdministratorToken =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_Uac, L"FilterAdministratorToken", 0, TRUE) != 0);

    /* 规范化 #95: 原 SS 把 EnableInstallerDetection 错位读入
     * RunAllAdminsInAAM (错位字段已删), 现写入语义正确的
     * DetectInstallations (检测安装程序提示) */
    g_ssm.Uac.DetectInstallations =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_Uac, L"EnableInstallerDetection", 1, TRUE) != 0);

    g_ssm.Uac.ValidateAdminCodeSignatures =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_Uac, L"ValidateAdminCodeSignatures", 0, TRUE) != 0);

    /* UAC 级别映射 (对齐 SS; consentPromptAdmin==0 视同禁用 T1548.002) */
    if (!g_ssm.Uac.Enabled) {
        g_ssm.Uac.Level = WkdSsmUac_Disabled;
    } else if (g_ssm.Uac.ConsentPromptAdmin == 0) {
        g_ssm.Uac.Level = WkdSsmUac_Disabled;
    } else if (g_ssm.Uac.ConsentPromptAdmin == 5) {
        g_ssm.Uac.Level = g_ssm.Uac.PromptOnSecureDesktop ?
            WkdSsmUac_NotifyChanges : WkdSsmUac_NotifyChangesNoDim;
    } else if (g_ssm.Uac.ConsentPromptAdmin == 2 || g_ssm.Uac.ConsentPromptAdmin == 1) {
        g_ssm.Uac.Level = WkdSsmUac_AlwaysNotify;
    } else {
        g_ssm.Uac.Level = WkdSsmUac_NotifyAll;
    }

    g_ssm.Uac.LastChecked = SsmGetNow();
}

static
VOID SsmRefreshDefenderLocked(VOID) {
    /* 策略覆写: DisableAntiSpyware==0 视为启用 (Wow64 视图) */
    const DWORD disableDefender = SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_DefenderPolicy,
                                                   L"DisableAntiSpyware", 0, TRUE);
    g_ssm.Defender.Enabled = (disableDefender == 0);

    /* Real-Time Protection 子键 */
    WCHAR rtPath[WKD_REG_MAX_PATH_CHARS];
    if (FAILED(StringCchPrintfW(rtPath, _countof(rtPath), L"%s\\Real-Time Protection",
                                SsmRegPath_DefenderPolicy))) {
        rtPath[0] = L'\0';
    }

    g_ssm.Defender.RealTimeProtection =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, rtPath, L"DisableRealtimeMonitoring", 0, TRUE) == 0);
    g_ssm.Defender.BehaviorMonitoring =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, rtPath, L"DisableBehaviorMonitoring", 0, TRUE) == 0);
    g_ssm.Defender.IoavProtection =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, rtPath, L"DisableIOAVProtection", 0, TRUE) == 0);

    /* Spynet / 云保护 */
    WCHAR spynetPath[WKD_REG_MAX_PATH_CHARS];
    if (FAILED(StringCchPrintfW(spynetPath, _countof(spynetPath), L"%s\\Spynet",
                                SsmRegPath_DefenderPolicy))) {
        spynetPath[0] = L'\0';
    }
    g_ssm.Defender.CloudProtection =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, spynetPath, L"SpynetReporting", 2, TRUE) != 0);

    /* Exploit Guard: Network Protection (值 1/2 视为开启) */
    WCHAR npPath[WKD_REG_MAX_PATH_CHARS];
    if (FAILED(StringCchPrintfW(npPath, _countof(npPath),
                                L"%s\\Windows Defender Exploit Guard\\Network Protection",
                                SsmRegPath_DefenderPolicy))) {
        npPath[0] = L'\0';
    }
    const DWORD npEnable = SsmRegQueryDword(HKEY_LOCAL_MACHINE, npPath, L"EnableNetworkProtection", 0, TRUE);
    g_ssm.Defender.NetworkProtection = (npEnable == 1 || npEnable == 2);

    /* Exploit Guard: Controlled Folder Access (值==1 视为开启) */
    WCHAR cfaPath[WKD_REG_MAX_PATH_CHARS];
    if (FAILED(StringCchPrintfW(cfaPath, _countof(cfaPath),
                                L"%s\\Windows Defender Exploit Guard\\Controlled Folder Access",
                                SsmRegPath_DefenderPolicy))) {
        cfaPath[0] = L'\0';
    }
    g_ssm.Defender.ControlledFolderAccess =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, cfaPath, L"EnableControlledFolderAccess", 0, TRUE) == 1);

    g_ssm.Defender.PotentiallyUnwantedApps =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_DefenderPolicy, L"PUAProtection", 0, TRUE) != 0);

    /* Tamper Protection: Features 键值==5 视为开启 */
    g_ssm.Defender.TamperProtection =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_DefenderFeatures, L"TamperProtection", 0, TRUE) == 5);

    g_ssm.Defender.LastChecked = SsmGetNow();
}

static
VOID SsmRefreshFirewallLocked(VOID) {
    /* 三 profile (默认视图, 不传 Wow64 选项) */
    WCHAR domainPath[WKD_REG_MAX_PATH_CHARS];
    WCHAR privatePath[WKD_REG_MAX_PATH_CHARS];
    WCHAR publicPath[WKD_REG_MAX_PATH_CHARS];
    (VOID)StringCchPrintfW(domainPath, _countof(domainPath), L"%s\\DomainProfile", SsmRegPath_Firewall);
    (VOID)StringCchPrintfW(privatePath, _countof(privatePath), L"%s\\StandardProfile", SsmRegPath_Firewall);
    (VOID)StringCchPrintfW(publicPath, _countof(publicPath), L"%s\\PublicProfile", SsmRegPath_Firewall);

    g_ssm.Firewall.DomainEnabled =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, domainPath, L"EnableFirewall", 1, FALSE) != 0);
    g_ssm.Firewall.PrivateEnabled =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, privatePath, L"EnableFirewall", 1, FALSE) != 0);
    g_ssm.Firewall.PublicEnabled =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, publicPath, L"EnableFirewall", 1, FALSE) != 0);
    g_ssm.Firewall.PublicDefaultInbound =
        SsmRegQueryDword(HKEY_LOCAL_MACHINE, publicPath, L"DefaultInboundAction", 1, FALSE);

    /* Domain/Private 的 DefaultInbound 等字段 SS 从不刷新 (保持构造默认, 见 Initialize) */
    g_ssm.Firewall.LastChecked = SsmGetNow();
}

static
VOID SsmRefreshExploitLocked(VOID) {
    /* MoveImages == 0xFFFFFFFF 视为强制关闭 ASLR */
    const DWORD moveImages = SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_MemoryMgmt,
                                              L"MoveImages", 0, FALSE);
    g_ssm.Exploit.AslrEnabled = (moveImages != 0xFFFFFFFF);

    /* DEP 在 64 位 Win10+ 恒开 (注册表不可关闭, 对齐 SS) */
    g_ssm.Exploit.DepEnabled = TRUE;

    const DWORD enableCfg = SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_MemoryMgmt,
                                             L"EnableCfg", 1, FALSE);
    g_ssm.Exploit.CfgEnabled = (enableCfg != 0);

    const DWORD sehop = SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_ExploitKernel,
                                         L"DisableExceptionChainValidation", 0, FALSE);
    g_ssm.Exploit.SehopEnabled = (sehop == 0);

    g_ssm.Exploit.LastChecked = SsmGetNow();
}

/* ==================================================
 * 内部告警发射 (增强 #95: SS 仅日志盲点信号的结构化出口)
 * 在 Refresh*Locked (SRW Lock 独占) 内调用: 入池走 AlertsLock,
 * 派发走 CallbacksLock (槽拷贝后锁外调用, SEH 保护), 均与外层
 * Lock 单向嵌套, 无死锁路径。边缘检测语义由调用方通过
 * *_AlertSent 标志维护, 防监控轮询重复轰炸。
 * ================================================== */
static
VOID SsmEmitInternalAlert(
    _In_ ULONG  Severity,          /* WKD_SSM_SEVERITY */
    _In_ ULONG  SettingType,       /* WKD_SSM_SETTING_TYPE */
    _In_ PCSTR  AlertType,         /* 简短类型串 */
    _In_ PCWSTR Title,
    _In_ PCWSTR Description,
    _In_ PCSTR  MitreId,
    _In_ PCSTR  MitreTactic
    )
{
    WKD_SSM_ALERT alert;

    memset(&alert, 0, sizeof(alert));
    alert.AlertId = (ULONGLONG)InterlockedIncrement64(&g_ssm.NextAlertId);
    alert.Timestamp = SsmGetNow();
    alert.Severity = Severity;
    alert.Category = WkdSsmCat_Authentication;
    alert.SettingType = SettingType;
    alert.CanRemediate = FALSE;
    alert.RecommendedAction = WkdSsmRem_Alert;

    (VOID)StringCchCopyA(alert.AlertType, _countof(alert.AlertType), AlertType);
    WideCharToMultiByte(CP_UTF8, 0, Title, -1,
                        alert.Title, _countof(alert.Title), NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, Description, -1,
                        alert.Description, _countof(alert.Description), NULL, NULL);
    if (MitreId != NULL) {
        (VOID)StringCchCopyA(alert.MitreId, _countof(alert.MitreId), MitreId);
    }
    if (MitreTactic != NULL) {
        (VOID)StringCchCopyA(alert.MitreTactic, _countof(alert.MitreTactic), MitreTactic);
    }

    /* 入池 (AlertsLock, 池满按既有三级驱逐) + 派发 (CallbacksLock 拷贝后锁外调用) */
    (VOID)SsmAlertCreate(&alert);
    SsmInvokeAlertCallbacks(&alert);
    InterlockedIncrement64(&g_ssm.Stats.AlertsGenerated);
}

static
VOID SsmRefreshLsaLocked(VOID) {
    g_ssm.Lsa.RunAsPpl =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_Lsa, L"RunAsPPL", 0, FALSE) != 0);
    g_ssm.Lsa.RestrictAnonymous =
        SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_Lsa, L"RestrictAnonymous", 0, FALSE);
    g_ssm.Lsa.LimitBlankPasswordUse =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_Lsa, L"LimitBlankPasswordUse", 1, FALSE) != 0);
    g_ssm.Lsa.NoLmHash =
        (SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_Lsa, L"NoLMHash", 1, FALSE) != 0);
    g_ssm.Lsa.LmCompatibilityLevel =
        SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_Lsa, L"LmCompatibilityLevel", 5, FALSE);

    /* WDigest UseLogonCredential=1: LSASS 明文凭据保留 (T1003.001)。
     * 增强 #95: 由 SS "仅日志盲点" 升级为边缘检测结构化告警 —
     * 置位后静默直至值复位再启用才重新告警, 防轮询重复轰炸。 */
    const DWORD wdigest = SsmRegQueryDword(HKEY_LOCAL_MACHINE, SsmRegPath_WDigest,
                                           L"UseLogonCredential", 0, FALSE);
    if (wdigest != 0) {
        if (!g_ssm.WdigestAlertSent) {
            SsmEmitInternalAlert(WkdSsmSev_Critical, WkdSsmSt_LsaRunAsPpl,
                "CredentialExposure",
                L"WDigest UseLogonCredential enabled",
                L"LSASS retains cleartext credentials (Mimikatz precondition)",
                "T1003.001", "Credential Access - LSASS Memory");
            g_ssm.WdigestAlertSent = TRUE;
        }
        SsmDbgPrint(L"[SSM] WDigest UseLogonCredential enabled - "
                    L"LSASS cleartext credentials retained (T1003.001)");
    } else {
        g_ssm.WdigestAlertSent = FALSE;
    }

    /* LsaCfgFlags 显式为 0 → Credential Guard 被关闭。
     * 增强 #95: 由 "仅日志" 升级为边缘检测告警 (T1112 注册表篡改面)。 */
    DWORD lsaCfg = 0;
    DWORD lsaCfgType = 0;
    DWORD lsaCfgSize = sizeof(lsaCfg);
    const LSTATUS lsaCfgStatus = RegGetValueW(HKEY_LOCAL_MACHINE, SsmRegPath_Lsa, L"LsaCfgFlags",
                                             RRF_RT_REG_DWORD, &lsaCfgType, &lsaCfg, &lsaCfgSize);
    if (lsaCfgStatus == ERROR_SUCCESS && lsaCfg == 0) {
        if (!g_ssm.LsaCfgAlertSent) {
            SsmEmitInternalAlert(WkdSsmSev_High, WkdSsmSt_CredGuardEnabled,
                "CredentialGuardDisabled",
                L"LsaCfgFlags explicitly zero - Credential Guard disabled",
                L"Credential Guard opted out post-deployment (registry tampering suspicion)",
                "T1112", "Defense Evasion - Modify Registry");
            g_ssm.LsaCfgAlertSent = TRUE;
        }
        SsmDbgPrint(L"[SSM] LsaCfgFlags explicitly zero - Credential Guard disabled");
    } else {
        g_ssm.LsaCfgAlertSent = FALSE;
    }

    g_ssm.Lsa.LastChecked = SsmGetNow();
}

static
VOID SsmRefreshProxyLocked(VOID) {
    /* HKCU 代理 (默认视图, 对齐 SS) */
    g_ssm.Proxy.ProxyEnabled =
        (SsmRegQueryDword(HKEY_CURRENT_USER, SsmRegPath_Proxy, L"ProxyEnable", 0, FALSE) != 0);

    g_ssm.Proxy.ProxyServer[0] = L'\0';
    (VOID)SsmRegQueryString(HKEY_CURRENT_USER, SsmRegPath_Proxy, L"ProxyServer",
                            g_ssm.Proxy.ProxyServer, _countof(g_ssm.Proxy.ProxyServer), FALSE);

    g_ssm.Proxy.AutoConfigUrl[0] = L'\0';
    (VOID)SsmRegQueryString(HKEY_CURRENT_USER, SsmRegPath_Proxy, L"AutoConfigURL",
                            g_ssm.Proxy.AutoConfigUrl, _countof(g_ssm.Proxy.AutoConfigUrl), FALSE);

    g_ssm.Proxy.LastChecked = SsmGetNow();
}

static
VOID SsmRefreshDnsLocked(VOID) {
    PWKD_SSM_DNS_SETTINGS dns = &g_ssm.Dns;
    dns->DnsServerCount = 0;

    /* 1) 全局 Tcpip\Parameters\NameServer (仅存在时有效) */
    WCHAR csv[WKD_REG_MAX_PATH_CHARS];
    if (SsmRegQueryString(HKEY_LOCAL_MACHINE, SsmRegPath_TcpParams, L"NameServer",
                          csv, _countof(csv), FALSE)) {
        SsmDnsAppendCsv(dns, csv);
    }

    /* 2) 网卡子键 NameServer/DhcpNameServer (上限 256 kMaxAdapters;
     *    堆缓冲枚举避免大栈) */
    PWCHAR names = (PWCHAR)UtHeapAlloc(256 * WKD_REG_MAX_NAME_CHARS * sizeof(WCHAR));
    if (names != NULL) {
        ULONG count = 0;
        if (SsmEnumSubKeys(SsmRegPath_TcpInterfaces, names, 256, 256, &count)) {
            WCHAR adapterPath[WKD_REG_MAX_PATH_CHARS];
            WCHAR adapterValue[WKD_REG_MAX_PATH_CHARS];
            for (ULONG i = 0; i < count; ++i) {
                PCWSTR guid = names + ((ULONGLONG)i * WKD_REG_MAX_NAME_CHARS);
                if (FAILED(StringCchPrintfW(adapterPath, _countof(adapterPath),
                                            L"%s\\%s", SsmRegPath_TcpInterfaces, guid))) {
                    continue;
                }
                if (SsmRegQueryString(HKEY_LOCAL_MACHINE, adapterPath, L"NameServer",
                                      adapterValue, _countof(adapterValue), FALSE)) {
                    SsmDnsAppendCsv(dns, adapterValue);
                }
                if (SsmRegQueryString(HKEY_LOCAL_MACHINE, adapterPath, L"DhcpNameServer",
                                      adapterValue, _countof(adapterValue), FALSE)) {
                    SsmDnsAppendCsv(dns, adapterValue);
                }
            }
        }
        UtHeapFree(names);
    }

    /* 去重 (保序) */
    SsmDnsDedupe(dns);

    /* 3) DNS 后缀 */
    dns->DnsSuffix[0] = L'\0';
    (VOID)SsmRegQueryString(HKEY_LOCAL_MACHINE, SsmRegPath_TcpParams, L"Domain",
                            dns->DnsSuffix, _countof(dns->DnsSuffix), FALSE);

    dns->LastChecked = SsmGetNow();
}

/* 按配置开关全量刷新 (RefreshAllImpl) */
static
VOID SsmRefreshAllLocked(VOID) {
    if (g_ssm.Config.MonitorUAC) SsmRefreshUacLocked();
    if (g_ssm.Config.MonitorDefender) SsmRefreshDefenderLocked();
    if (g_ssm.Config.MonitorFirewall) SsmRefreshFirewallLocked();
    if (g_ssm.Config.MonitorExploitProtection) SsmRefreshExploitLocked();
    if (g_ssm.Config.MonitorLSA) SsmRefreshLsaLocked();
    if (g_ssm.Config.MonitorProxy) SsmRefreshProxyLocked();
    if (g_ssm.Config.MonitorDNS) SsmRefreshDnsLocked();
    /* MonitorShell/MonitorPolicy: SS 未实现, 忽略 (承袭) */
}

/* 快照捕获 (复制 currentState; 调用方持 Lock 共享/独占) */
static
VOID SsmCaptureSnapshotLocked(_Out_ PWKD_SSM_SNAPSHOT Out) {
    if (Out == NULL) return;
    memset(Out, 0, sizeof(*Out));
    Out->Uac = g_ssm.Uac;
    Out->Defender = g_ssm.Defender;
    Out->Firewall = g_ssm.Firewall;
    Out->Exploit = g_ssm.Exploit;
    Out->Lsa = g_ssm.Lsa;
    Out->Proxy = g_ssm.Proxy;
    Out->Dns = g_ssm.Dns;
    Out->Created = SsmGetNow();
}

/* ==================================================
 * 监控线程 (实现在 Part 5; SsmStart 使用须前向声明)
 * ================================================== */
static DWORD WINAPI SsmMonitorThreadProc(_In_ LPVOID Param);

/* ==================================================
 * 生命周期 (对应 SS Initialize/Shutdown; 重建
 * 管理器语义: 重复 Initialize 全清回调/历史/告警/基线,
 * 文档注明)
 * ================================================== */

NTSTATUS
SsmInitialize(_In_opt_ PCWKD_SSM_CONFIG Config) {
    if (!g_ssm.LocksInitialized) {
        InitializeSRWLock(&g_ssm.Lock);
        InitializeCriticalSection(&g_ssm.HistoryLock);
        InitializeCriticalSection(&g_ssm.AlertsLock);
        InitializeCriticalSection(&g_ssm.CallbacksLock);
        g_ssm.LocksInitialized = TRUE;
    }

    /* 重建语义: 若轮询线程在运行先停止 (WkD 健壮性增强, 防清空竞态) */
    if (g_ssm.Monitoring != 0) {
        SsmStop();
    }

    AcquireSRWLockExclusive(&g_ssm.Lock);
    g_ssm.Initialized = FALSE;

    if (Config != NULL) {
        g_ssm.Config = *Config;
    } else {
        SsmCreateDefaultConfig(&g_ssm.Config);
    }

    /* 重建管理器: 回调槽/历史/告警/基线全清 + id 重置 */
    EnterCriticalSection(&g_ssm.CallbacksLock);
    for (ULONG i = 0; i < WKD_SSM_MAX_CALLBACKS; ++i) {
        g_ssm.ChangeSlotFree[i] = TRUE;
        g_ssm.ChangeCallbacks[i] = NULL;
        g_ssm.ChangeContexts[i] = NULL;
        g_ssm.ChangeCallbackIds[i] = 0;
        g_ssm.AlertSlotFree[i] = TRUE;
        g_ssm.AlertCallbacks[i] = NULL;
        g_ssm.AlertContexts[i] = NULL;
        g_ssm.AlertCallbackIds[i] = 0;
        g_ssm.ComplianceSlotFree[i] = TRUE;
        g_ssm.ComplianceCallbacks[i] = NULL;
        g_ssm.ComplianceContexts[i] = NULL;
        g_ssm.ComplianceCallbackIds[i] = 0;
    }
    LeaveCriticalSection(&g_ssm.CallbacksLock);

    EnterCriticalSection(&g_ssm.HistoryLock);
    g_ssm.HistoryHead = 0;
    g_ssm.HistoryCount = 0;
    SsmTrackerSetMaxLocked(g_ssm.Config.MaxHistoryEntries);
    LeaveCriticalSection(&g_ssm.HistoryLock);

    EnterCriticalSection(&g_ssm.AlertsLock);
    SsmAlertClearAllLocked();
    LeaveCriticalSection(&g_ssm.AlertsLock);

    memset(g_ssm.Baselines, 0, sizeof(g_ssm.Baselines));
    g_ssm.BaselineCount = 0;
    g_ssm.HasActiveBaseline = FALSE;
    g_ssm.ActiveBaselineId = 0;
    g_ssm.NextBaselineId = 0;
    g_ssm.NextChangeId = 0;
    g_ssm.NextAlertId = 0;
    g_ssm.NextCallbackId = 0;
    SsmResetStatsLocked(&g_ssm.Stats);

    /* 结构体构造默认 (Refresh 从不刷新的字段):
     *   UAC: consentPromptUser=3 (detectInstallations 由 Refresh 实读,
     *     增强 #95 删除原硬编码 TRUE)
     *   Firewall: inbound=1/outbound=0, notifyOnBlocked=true, allowLocalPolicyMerge=true
     *   Exploit: heapTerminationEnabled=true
     *   Proxy: autoDetect=true */
    g_ssm.Uac.ConsentPromptUser = 3;
    g_ssm.Firewall.DomainDefaultInbound = 1;
    g_ssm.Firewall.PrivateDefaultInbound = 1;
    g_ssm.Firewall.PublicDefaultOutbound = 0;
    g_ssm.Firewall.NotifyOnBlocked = TRUE;
    g_ssm.Firewall.AllowLocalPolicyMerge = TRUE;
    g_ssm.Exploit.HeapTerminationEnabled = TRUE;
    g_ssm.Proxy.AutoDetect = TRUE;

    /* 增强 #95: WDigest/LsaCfgFlags 边缘检测标志重建复位 */
    g_ssm.WdigestAlertSent = FALSE;
    g_ssm.LsaCfgAlertSent = FALSE;

    /* 全量刷新 (锁内) */
    SsmRefreshAllLocked();

    /* 自动基线 (Initialize: autoCreateBaseline && useBaseline) */
    if (g_ssm.Config.AutoCreateBaseline && g_ssm.Config.UseBaseline) {
        WKD_SSM_SNAPSHOT snap;
        SsmCaptureSnapshotLocked(&snap);
        StringCchCopyA(snap.Description, _countof(snap.Description), "Baseline");
        snap.IsDefault = TRUE;
        (VOID)SsmBaselineCreateLocked(&snap);
    }

    g_ssm.Initialized = TRUE;
    ReleaseSRWLockExclusive(&g_ssm.Lock);

    SsmDbgPrint(L"[SSM] Initialized (v%u.%u.%u, poll=%lu ms)",
                WKD_SSM_VERSION_MAJOR, WKD_SSM_VERSION_MINOR, WKD_SSM_VERSION_PATCH,
                SsmClampPollInterval(g_ssm.Config.MonitorPollIntervalMs));
    return STATUS_SUCCESS;
}

VOID
SsmShutdown(VOID) {
    if (!g_ssm.LocksInitialized) return;

    if (g_ssm.Monitoring != 0) {
        SsmStop();
    }

    AcquireSRWLockExclusive(&g_ssm.Lock);
    g_ssm.Initialized = FALSE;

    /* 释放告警动态池 (防堆泄漏; SS 在析构时释放, WkD Shutdown 显式化) */
    EnterCriticalSection(&g_ssm.AlertsLock);
    SsmAlertClearAllLocked();
    LeaveCriticalSection(&g_ssm.AlertsLock);

    ReleaseSRWLockExclusive(&g_ssm.Lock);
    SsmDbgPrint(L"[SSM] Shutdown complete");
}

BOOLEAN
SsmIsInitialized(VOID) {
    return (g_ssm.Initialized != 0);
}

/* ==================================================
 * 监控控制 (对应 SS Start/Stop/IsMonitoring)
 * ================================================== */

VOID
SsmStart(VOID) {
    if (!g_ssm.LocksInitialized) return;

    AcquireSRWLockExclusive(&g_ssm.Lock);
    if (g_ssm.Initialized == FALSE) {
        ReleaseSRWLockExclusive(&g_ssm.Lock);
        SsmDbgPrint(L"[SSM] Start ignored: not initialized");
        return;
    }
    if (g_ssm.Monitoring != 0) {
        ReleaseSRWLockExclusive(&g_ssm.Lock);
        SsmDbgPrint(L"[SSM] Start ignored: already monitoring");
        return;
    }
    g_ssm.Monitoring = TRUE;
    ReleaseSRWLockExclusive(&g_ssm.Lock);

    g_ssm.MonitorThread = CreateThread(NULL, 0, SsmMonitorThreadProc, NULL, 0, NULL);
    if (g_ssm.MonitorThread == NULL) {
        AcquireSRWLockExclusive(&g_ssm.Lock);
        g_ssm.Monitoring = FALSE;
        ReleaseSRWLockExclusive(&g_ssm.Lock);
        SsmDbgPrint(L"[SSM] Failed to create monitor thread (%lu)", GetLastError());
    } else {
        SsmDbgPrint(L"[SSM] Monitor thread started");
    }
}

VOID
SsmStop(VOID) {
    HANDLE thread = NULL;
    BOOLEAN wasMonitoring = FALSE;

    if (!g_ssm.LocksInitialized) return;

    AcquireSRWLockExclusive(&g_ssm.Lock);
    wasMonitoring = (g_ssm.Monitoring != 0);
    g_ssm.Monitoring = FALSE;
    if (g_ssm.MonitorThread != NULL) {
        thread = g_ssm.MonitorThread;
        g_ssm.MonitorThread = NULL;
    }
    ReleaseSRWLockExclusive(&g_ssm.Lock);

    if (wasMonitoring && thread != NULL) {
        WaitForSingleObject(thread, 5000);   /* join 语义 */
        CloseHandle(thread);
        SsmDbgPrint(L"[SSM] Monitor thread stopped");
    }
}

BOOLEAN
SsmIsMonitoring(VOID) {
    return (g_ssm.Monitoring != 0);
}

/* ==================================================
 * 设置查询 (UAC; 共享锁读)
 * ================================================== */

VOID
SsmGetUacSettings(_Out_ PWKD_SSM_UAC_SETTINGS Settings) {
    if (Settings == NULL) return;
    AcquireSRWLockShared(&g_ssm.Lock);
    *Settings = g_ssm.Uac;
    ReleaseSRWLockShared(&g_ssm.Lock);
}

BOOLEAN
SsmIsUacDisabled(VOID) {
    AcquireSRWLockShared(&g_ssm.Lock);
    const BOOLEAN disabled = !g_ssm.Uac.Enabled;
    ReleaseSRWLockShared(&g_ssm.Lock);
    return disabled;
}

ULONG
SsmGetUacLevel(VOID) {
    AcquireSRWLockShared(&g_ssm.Lock);
    const ULONG level = g_ssm.Uac.Level;
    ReleaseSRWLockShared(&g_ssm.Lock);
    return level;
}

BOOLEAN
SsmRestoreUacDefaults(VOID) {
    /* 对齐 SS: 任一次写失败立即返回 (不刷新); 全成功后锁内刷新。
     * 写回 Wow64 视图 (Wow64WriteOpts) */
    if (!SsmRegWriteDword(HKEY_LOCAL_MACHINE, SsmRegPath_Uac, L"EnableLUA", 1, TRUE)) {
        SsmDbgPrint(L"[SSM] RestoreUACDefaults failed (EnableLUA)");
        return FALSE;
    }
    if (!SsmRegWriteDword(HKEY_LOCAL_MACHINE, SsmRegPath_Uac, L"ConsentPromptBehaviorAdmin", 5, TRUE)) {
        SsmDbgPrint(L"[SSM] RestoreUACDefaults failed (ConsentPromptBehaviorAdmin)");
        return FALSE;
    }
    if (!SsmRegWriteDword(HKEY_LOCAL_MACHINE, SsmRegPath_Uac, L"PromptOnSecureDesktop", 1, TRUE)) {
        SsmDbgPrint(L"[SSM] RestoreUACDefaults failed (PromptOnSecureDesktop)");
        return FALSE;
    }

    AcquireSRWLockExclusive(&g_ssm.Lock);
    SsmRefreshUacLocked();
    ReleaseSRWLockExclusive(&g_ssm.Lock);

    SsmDbgPrint(L"[SSM] UAC restored to secure defaults");
    return TRUE;
}

/* ==================================================
 * 设置查询 (Defender)
 * ================================================== */

VOID
SsmGetDefenderSettings(_Out_ PWKD_SSM_DEFENDER_SETTINGS Settings) {
    if (Settings == NULL) return;
    AcquireSRWLockShared(&g_ssm.Lock);
    *Settings = g_ssm.Defender;
    ReleaseSRWLockShared(&g_ssm.Lock);
}

BOOLEAN
SsmIsDefenderDisabled(VOID) {
    AcquireSRWLockShared(&g_ssm.Lock);
    const BOOLEAN disabled = !g_ssm.Defender.Enabled;
    ReleaseSRWLockShared(&g_ssm.Lock);
    return disabled;
}

BOOLEAN
SsmIsRealtimeProtectionDisabled(VOID) {
    AcquireSRWLockShared(&g_ssm.Lock);
    const BOOLEAN disabled = !g_ssm.Defender.RealTimeProtection;
    ReleaseSRWLockShared(&g_ssm.Lock);
    return disabled;
}

NTSTATUS
SsmGetDefenderExclusions(_Out_opt_ PWCHAR Paths, _In_ ULONG Capacity, _Inout_ PULONG Count) {
    /* 对齐 SS: 排除项恒空 (SS 从不填充 excludedPaths) */
    if (Count == NULL) return STATUS_INVALID_PARAMETER;

    AcquireSRWLockShared(&g_ssm.Lock);
    *Count = 0;
    (VOID)Paths;
    (VOID)Capacity;
    ReleaseSRWLockShared(&g_ssm.Lock);
    return STATUS_SUCCESS;
}

BOOLEAN
SsmRestoreDefenderDefaults(VOID) {
    /* 对齐 SS: 部分失败仍继续刷新 (仅返回 false) */
    const BOOLEAN ok1 = SsmRegWriteDword(HKEY_LOCAL_MACHINE, SsmRegPath_DefenderPolicy,
                                         L"DisableAntiSpyware", 0, TRUE);

    WCHAR rtPath[WKD_REG_MAX_PATH_CHARS];
    if (FAILED(StringCchPrintfW(rtPath, _countof(rtPath), L"%s\\Real-Time Protection",
                                SsmRegPath_DefenderPolicy))) {
        rtPath[0] = L'\0';
    }
    const BOOLEAN ok2 = SsmRegWriteDword(HKEY_LOCAL_MACHINE, rtPath, L"DisableRealtimeMonitoring", 0, TRUE);
    const BOOLEAN ok3 = SsmRegWriteDword(HKEY_LOCAL_MACHINE, rtPath, L"DisableBehaviorMonitoring", 0, TRUE);
    const BOOLEAN ok4 = SsmRegWriteDword(HKEY_LOCAL_MACHINE, rtPath, L"DisableIOAVProtection", 0, TRUE);

    if (!ok1 || !ok2 || !ok3 || !ok4) {
        SsmDbgPrint(L"[SSM] RestoreDefenderDefaults partial failure: %u/%u/%u/%u",
                    (UINT)ok1, (UINT)ok2, (UINT)ok3, (UINT)ok4);
    }

    AcquireSRWLockExclusive(&g_ssm.Lock);
    SsmRefreshDefenderLocked();
    ReleaseSRWLockExclusive(&g_ssm.Lock);

    SsmDbgPrint(L"[SSM] Defender restored to secure defaults");
    return (ok1 && ok2 && ok3 && ok4);
}

/* ==================================================
 * 设置查询 (Firewall)
 * ================================================== */

VOID
SsmGetFirewallSettings(_Out_ PWKD_SSM_FIREWALL_SETTINGS Settings) {
    if (Settings == NULL) return;
    AcquireSRWLockShared(&g_ssm.Lock);
    *Settings = g_ssm.Firewall;
    ReleaseSRWLockShared(&g_ssm.Lock);
}

BOOLEAN
SsmIsFirewallDisabled(_In_ ULONG Profile) {
    AcquireSRWLockShared(&g_ssm.Lock);
    BOOLEAN disabled = FALSE;
    switch (Profile) {
        case WkdSsmFw_Domain:
            disabled = !g_ssm.Firewall.DomainEnabled;
            break;
        case WkdSsmFw_Private:
            disabled = !g_ssm.Firewall.PrivateEnabled;
            break;
        case WkdSsmFw_Public:
            disabled = !g_ssm.Firewall.PublicEnabled;
            break;
        case WkdSsmFw_All:
            disabled = !g_ssm.Firewall.DomainEnabled ||
                       !g_ssm.Firewall.PrivateEnabled ||
                       !g_ssm.Firewall.PublicEnabled;
            break;
        default:
            disabled = FALSE;
            break;
    }
    ReleaseSRWLockShared(&g_ssm.Lock);
    return disabled;
}

BOOLEAN
SsmIsAnyFirewallDisabled(VOID) {
    AcquireSRWLockShared(&g_ssm.Lock);
    const BOOLEAN disabled = !g_ssm.Firewall.DomainEnabled ||
                             !g_ssm.Firewall.PrivateEnabled ||
                             !g_ssm.Firewall.PublicEnabled;
    ReleaseSRWLockShared(&g_ssm.Lock);
    return disabled;
}

BOOLEAN
SsmRestoreFirewallDefaults(VOID) {
    /* 对齐 SS: 三 profile EnableFirewall=1 (默认视图, 不 Wow64) */
    WCHAR domainPath[WKD_REG_MAX_PATH_CHARS];
    WCHAR privatePath[WKD_REG_MAX_PATH_CHARS];
    WCHAR publicPath[WKD_REG_MAX_PATH_CHARS];
    (VOID)StringCchPrintfW(domainPath, _countof(domainPath), L"%s\\DomainProfile", SsmRegPath_Firewall);
    (VOID)StringCchPrintfW(privatePath, _countof(privatePath), L"%s\\StandardProfile", SsmRegPath_Firewall);
    (VOID)StringCchPrintfW(publicPath, _countof(publicPath), L"%s\\PublicProfile", SsmRegPath_Firewall);

    const BOOLEAN ok1 = SsmRegWriteDword(HKEY_LOCAL_MACHINE, domainPath, L"EnableFirewall", 1, FALSE);
    const BOOLEAN ok2 = SsmRegWriteDword(HKEY_LOCAL_MACHINE, privatePath, L"EnableFirewall", 1, FALSE);
    const BOOLEAN ok3 = SsmRegWriteDword(HKEY_LOCAL_MACHINE, publicPath, L"EnableFirewall", 1, FALSE);

    if (!ok1 || !ok2 || !ok3) {
        SsmDbgPrint(L"[SSM] RestoreFirewallDefaults partial failure: %u/%u/%u",
                    (UINT)ok1, (UINT)ok2, (UINT)ok3);
    }

    AcquireSRWLockExclusive(&g_ssm.Lock);
    SsmRefreshFirewallLocked();
    ReleaseSRWLockExclusive(&g_ssm.Lock);

    SsmDbgPrint(L"[SSM] Firewall restored to secure defaults");
    return (ok1 && ok2 && ok3);
}

/* ==================================================
 * 设置查询 (Exploit Protection / LSA / Proxy / DNS)
 * ================================================== */

VOID
SsmGetExploitSettings(_Out_ PWKD_SSM_EXPLOIT_SETTINGS Settings) {
    if (Settings == NULL) return;
    AcquireSRWLockShared(&g_ssm.Lock);
    *Settings = g_ssm.Exploit;
    ReleaseSRWLockShared(&g_ssm.Lock);
}

BOOLEAN
SsmIsAslrDisabled(VOID) {
    AcquireSRWLockShared(&g_ssm.Lock);
    const BOOLEAN disabled = !g_ssm.Exploit.AslrEnabled;
    ReleaseSRWLockShared(&g_ssm.Lock);
    return disabled;
}

BOOLEAN
SsmIsDepDisabled(VOID) {
    AcquireSRWLockShared(&g_ssm.Lock);
    const BOOLEAN disabled = !g_ssm.Exploit.DepEnabled;
    ReleaseSRWLockShared(&g_ssm.Lock);
    return disabled;
}

VOID
SsmGetLsaSettings(_Out_ PWKD_SSM_LSA_SETTINGS Settings) {
    if (Settings == NULL) return;
    AcquireSRWLockShared(&g_ssm.Lock);
    *Settings = g_ssm.Lsa;
    ReleaseSRWLockShared(&g_ssm.Lock);
}

BOOLEAN
SsmIsLsaPplEnabled(VOID) {
    AcquireSRWLockShared(&g_ssm.Lock);
    const BOOLEAN enabled = g_ssm.Lsa.RunAsPpl;
    ReleaseSRWLockShared(&g_ssm.Lock);
    return enabled;
}

VOID
SsmGetProxySettings(_Out_ PWKD_SSM_PROXY_SETTINGS Settings) {
    if (Settings == NULL) return;
    AcquireSRWLockShared(&g_ssm.Lock);
    *Settings = g_ssm.Proxy;
    ReleaseSRWLockShared(&g_ssm.Lock);
}

BOOLEAN
SsmIsProxyEnabled(VOID) {
    AcquireSRWLockShared(&g_ssm.Lock);
    const BOOLEAN enabled = g_ssm.Proxy.ProxyEnabled;
    ReleaseSRWLockShared(&g_ssm.Lock);
    return enabled;
}

VOID
SsmGetDnsSettings(_Out_ PWKD_SSM_DNS_SETTINGS Settings) {
    if (Settings == NULL) return;
    AcquireSRWLockShared(&g_ssm.Lock);
    *Settings = g_ssm.Dns;
    ReleaseSRWLockShared(&g_ssm.Lock);
}

/* 增强 #95: 具名常量 + 可配置开关 (SuspiciousDnsCheckEnabled)。
 * 列表承袭 SS 硬编码的"错拼暗桩"检测语义:
 *   8.8.4.4  = Google 备用 DNS (攻击者常用诱饵, 与 8.8.8.8 拼错混淆)
 *   1.1.1.2  = Cloudflare 恶意软件过滤 DNS (合法但非通用默认)
 * SS 注释误称其为 "Typo"; 判定为配置比对语义, 不声明恶意性。
 * 检测开关默认 TRUE, 可经 Config.SuspiciousDnsCheckEnabled 关闭。 */
static const WCHAR* const SsmSuspiciousDnsList[] = { L"8.8.4.4", L"1.1.1.2" };

BOOLEAN
SsmIsDnsSuspicious(VOID) {
    if (!g_ssm.Config.SuspiciousDnsCheckEnabled) {
        return FALSE;
    }

    AcquireSRWLockShared(&g_ssm.Lock);
    BOOLEAN found = FALSE;
    for (ULONG i = 0; i < g_ssm.Dns.DnsServerCount && !found; ++i) {
        for (ULONG k = 0; k < _countof(SsmSuspiciousDnsList); ++k) {
            if (wcscmp(g_ssm.Dns.DnsServers[i], SsmSuspiciousDnsList[k]) == 0) {
                found = TRUE;
                break;
            }
        }
    }
    ReleaseSRWLockShared(&g_ssm.Lock);
    return found;
}

/* ==================================================
 * 基线管理 (对应 SS CreateBaseline/GetBaseline/GetActiveBaseline/
 * SetActiveBaseline/RestoreToBaseline/CompareToBaseline)
 * ================================================== */

ULONGLONG
SsmCreateBaseline(_In_ PCSTR Description) {
    /* SS 公共 CreateBaseline 用 shared_lock + 内部管理器独占写,
     * WkD 收敛为单一独占锁 (行为等价) */
    AcquireSRWLockExclusive(&g_ssm.Lock);

    WKD_SSM_SNAPSHOT snap;
    SsmCaptureSnapshotLocked(&snap);
    if (Description != NULL && Description[0] != '\0') {
        (VOID)StringCchCopyA(snap.Description, _countof(snap.Description), Description);
    } else {
        (VOID)StringCchCopyA(snap.Description, _countof(snap.Description), "Baseline");
    }
    snap.IsDefault = FALSE;
    const ULONGLONG id = SsmBaselineCreateLocked(&snap);

    ReleaseSRWLockExclusive(&g_ssm.Lock);
    return id;
}

NTSTATUS
SsmGetBaseline(_In_ ULONGLONG BaselineId, _Out_ PWKD_SSM_SNAPSHOT Snapshot) {
    if (Snapshot == NULL) return STATUS_INVALID_PARAMETER;

    AcquireSRWLockShared(&g_ssm.Lock);
    ULONG idx;
    NTSTATUS st = STATUS_NOT_FOUND;
    if (SsmBaselineFindLocked(BaselineId, &idx)) {
        *Snapshot = g_ssm.Baselines[idx];
        st = STATUS_SUCCESS;
    }
    ReleaseSRWLockShared(&g_ssm.Lock);
    return st;
}

NTSTATUS
SsmGetActiveBaseline(_Out_ PWKD_SSM_SNAPSHOT Snapshot) {
    if (Snapshot == NULL) return STATUS_INVALID_PARAMETER;

    AcquireSRWLockShared(&g_ssm.Lock);
    const NTSTATUS st = SsmBaselineActiveLocked(Snapshot) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
    ReleaseSRWLockShared(&g_ssm.Lock);
    return st;
}

BOOLEAN
SsmSetActiveBaseline(_In_ ULONGLONG BaselineId) {
    AcquireSRWLockShared(&g_ssm.Lock);
    ULONG idx;
    BOOLEAN ok = SsmBaselineFindLocked(BaselineId, &idx);
    if (ok) {
        g_ssm.HasActiveBaseline = TRUE;
        g_ssm.ActiveBaselineId = BaselineId;
    }
    ReleaseSRWLockShared(&g_ssm.Lock);

    if (!ok) {
        SsmDbgPrint(L"[SSM] Attempted to activate unknown baseline %I64u", BaselineId);
    } else {
        SsmDbgPrint(L"[SSM] Set active baseline to %I64u", BaselineId);
    }
    return ok;
}

BOOLEAN
SsmRestoreToBaseline(_In_ ULONGLONG BaselineId) {
    /* 对齐 SS: 仅当基线断言对应防护开启时才“恢复”到安全默认,
     * 防静默改变主机姿态。调用 Restore*Defaults（内部自加锁）,
     * 本函数持锁期间绝不嵌套调用。 */
    WKD_SSM_SNAPSHOT baseline;
    WKD_SSM_CONFIG cfg;
    BOOLEAN found = FALSE;

    AcquireSRWLockShared(&g_ssm.Lock);
    cfg = g_ssm.Config;
    ULONG idx;
    if (SsmBaselineFindLocked(BaselineId, &idx)) {
        baseline = g_ssm.Baselines[idx];
        found = TRUE;
    }
    ReleaseSRWLockShared(&g_ssm.Lock);

    if (!found) {
        SsmDbgPrint(L"[SSM] Baseline %I64u not found", BaselineId);
        return FALSE;
    }

    if (cfg.RemediateUAC && baseline.Uac.Enabled) {
        (VOID)SsmRestoreUacDefaults();
    }

    if (cfg.RemediateDefender && baseline.Defender.Enabled) {
        (VOID)SsmRestoreDefenderDefaults();
    }

    if (cfg.RemediateFirewall) {
        const BOOLEAN baselineHasFw = baseline.Firewall.DomainEnabled ||
                                      baseline.Firewall.PrivateEnabled ||
                                      baseline.Firewall.PublicEnabled;
        BOOLEAN currentDegraded = FALSE;
        AcquireSRWLockShared(&g_ssm.Lock);
        currentDegraded =
            (baseline.Firewall.DomainEnabled  && !g_ssm.Firewall.DomainEnabled) ||
            (baseline.Firewall.PrivateEnabled && !g_ssm.Firewall.PrivateEnabled) ||
            (baseline.Firewall.PublicEnabled  && !g_ssm.Firewall.PublicEnabled);
        ReleaseSRWLockShared(&g_ssm.Lock);

        if (baselineHasFw && currentDegraded) {
            (VOID)SsmRestoreFirewallDefaults();
        }
    }

    InterlockedIncrement64(&g_ssm.Stats.RemediationsPerformed);
    SsmDbgPrint(L"[SSM] Restored to baseline %I64u", BaselineId);
    return TRUE;
}

/* 布尔差异辅助 (CompareToBaseline): 计数恒递增; 仅当 Out!=NULL 且
 * 有容量时写入。addDiff lambda (previous "1"/"0") */
static
VOID SsmCompareBoolDiff(_Inout_opt_ PWKD_SSM_CHANGE Out, _In_ ULONG Capacity, _Inout_ PULONG N,
                        _In_ ULONG Category, _In_ ULONG Type, _In_ PCWSTR Name,
                        _In_ BOOLEAN Current, _In_ BOOLEAN Base) {
    if (Current == Base || N == NULL) return;

    ULONG i = (*N)++;
    if (Out != NULL && i < Capacity) {
        WKD_SSM_CHANGE* c = &Out[i];
        memset(c, 0, sizeof(*c));
        c->Category = Category;
        c->SettingType = Type;
        (VOID)StringCchCopyW(c->SettingName, _countof(c->SettingName), Name);
        c->PreviousValue[0] = Base ? L'1' : L'0';
        c->PreviousValue[1] = L'\0';
        c->NewValue[0] = Current ? L'1' : L'0';
        c->NewValue[1] = L'\0';
        c->IsSecurityDegrade = (Base && !Current);
    }
}

NTSTATUS
SsmCompareToBaseline(_In_ ULONGLONG BaselineId, _Out_opt_ PWKD_SSM_CHANGE Changes,
                     _In_ ULONG Capacity, _Inout_ PULONG Count) {
    if (Count == NULL) return STATUS_INVALID_PARAMETER;
    *Count = 0;

    ULONG n = 0;
    AcquireSRWLockShared(&g_ssm.Lock);

    ULONG idx;
    if (!SsmBaselineFindLocked(BaselineId, &idx)) {
        ReleaseSRWLockShared(&g_ssm.Lock);
        return STATUS_NOT_FOUND;
    }
    const PWKD_SSM_SNAPSHOT base = &g_ssm.Baselines[idx];

    /* UAC */
    SsmCompareBoolDiff(Changes, Capacity, &n, WkdSsmCat_Security, WkdSsmSt_UacEnabled,
                       L"UAC Enabled", g_ssm.Uac.Enabled, base->Uac.Enabled);
    if (g_ssm.Uac.ConsentPromptAdmin != base->Uac.ConsentPromptAdmin) {
        ULONG i = n++;
        if (Changes != NULL && i < Capacity) {
            WKD_SSM_CHANGE* c = &Changes[i];
            memset(c, 0, sizeof(*c));
            c->Category = WkdSsmCat_Security;
            c->SettingType = WkdSsmSt_UacConsentPromptAdmin;
            (VOID)StringCchCopyW(c->SettingName, _countof(c->SettingName), L"ConsentPromptBehaviorAdmin");
            (VOID)StringCchPrintfW(c->PreviousValue, _countof(c->PreviousValue), L"%lu", base->Uac.ConsentPromptAdmin);
            (VOID)StringCchPrintfW(c->NewValue, _countof(c->NewValue), L"%lu", g_ssm.Uac.ConsentPromptAdmin);
            c->IsSecurityDegrade = (g_ssm.Uac.ConsentPromptAdmin < base->Uac.ConsentPromptAdmin);
        }
    }

    /* Defender */
    SsmCompareBoolDiff(Changes, Capacity, &n, WkdSsmCat_Security, WkdSsmSt_DefenderEnabled,
                       L"Defender Enabled", g_ssm.Defender.Enabled, base->Defender.Enabled);
    SsmCompareBoolDiff(Changes, Capacity, &n, WkdSsmCat_Security, WkdSsmSt_DefenderRealtimeProtection,
                       L"Real-Time Protection", g_ssm.Defender.RealTimeProtection, base->Defender.RealTimeProtection);
    SsmCompareBoolDiff(Changes, Capacity, &n, WkdSsmCat_Security, WkdSsmSt_DefenderBehaviorMonitoring,
                       L"Behavior Monitoring", g_ssm.Defender.BehaviorMonitoring, base->Defender.BehaviorMonitoring);
    SsmCompareBoolDiff(Changes, Capacity, &n, WkdSsmCat_Security, WkdSsmSt_DefenderTamperProtection,
                       L"Tamper Protection", g_ssm.Defender.TamperProtection, base->Defender.TamperProtection);
    SsmCompareBoolDiff(Changes, Capacity, &n, WkdSsmCat_Security, WkdSsmSt_DefenderCloudProtection,
                       L"Cloud Protection", g_ssm.Defender.CloudProtection, base->Defender.CloudProtection);

    /* Firewall 三 profile */
    SsmCompareBoolDiff(Changes, Capacity, &n, WkdSsmCat_Security, WkdSsmSt_FirewallDomainEnabled,
                       L"Firewall Domain Profile", g_ssm.Firewall.DomainEnabled, base->Firewall.DomainEnabled);
    SsmCompareBoolDiff(Changes, Capacity, &n, WkdSsmCat_Security, WkdSsmSt_FirewallPrivateEnabled,
                       L"Firewall Private Profile", g_ssm.Firewall.PrivateEnabled, base->Firewall.PrivateEnabled);
    SsmCompareBoolDiff(Changes, Capacity, &n, WkdSsmCat_Security, WkdSsmSt_FirewallPublicEnabled,
                       L"Firewall Public Profile", g_ssm.Firewall.PublicEnabled, base->Firewall.PublicEnabled);

    /* LSA */
    SsmCompareBoolDiff(Changes, Capacity, &n, WkdSsmCat_Authentication, WkdSsmSt_LsaRunAsPpl,
                       L"LSASS RunAsPPL", g_ssm.Lsa.RunAsPpl, base->Lsa.RunAsPpl);
    SsmCompareBoolDiff(Changes, Capacity, &n, WkdSsmCat_Authentication, WkdSsmSt_LsaNoLmHash,
                       L"LSA NoLMHash", g_ssm.Lsa.NoLmHash, base->Lsa.NoLmHash);

    /* Exploit protection */
    SsmCompareBoolDiff(Changes, Capacity, &n, WkdSsmCat_Security, WkdSsmSt_ExploitSehop,
                       L"SEHOP", g_ssm.Exploit.SehopEnabled, base->Exploit.SehopEnabled);
    SsmCompareBoolDiff(Changes, Capacity, &n, WkdSsmCat_Security, WkdSsmSt_ExploitAslr,
                       L"ASLR", g_ssm.Exploit.AslrEnabled, base->Exploit.AslrEnabled);

    /* Proxy — 透明代理注入 C2 重定向 (对齐 SS; SettingType=Unknown) */
    if (g_ssm.Proxy.ProxyEnabled != base->Proxy.ProxyEnabled ||
        wcscmp(g_ssm.Proxy.ProxyServer, base->Proxy.ProxyServer) != 0) {
        ULONG i = n++;
        if (Changes != NULL && i < Capacity) {
            WKD_SSM_CHANGE* c = &Changes[i];
            memset(c, 0, sizeof(*c));
            c->Category = WkdSsmCat_Network;
            c->SettingType = WkdSsmSt_Unknown;
            (VOID)StringCchCopyW(c->SettingName, _countof(c->SettingName), L"Proxy");
            if (base->Proxy.ProxyEnabled) {
                (VOID)StringCchPrintfW(c->PreviousValue, _countof(c->PreviousValue),
                                       L"on:%s", base->Proxy.ProxyServer);
            } else {
                (VOID)StringCchCopyW(c->PreviousValue, _countof(c->PreviousValue), L"off");
            }
            if (g_ssm.Proxy.ProxyEnabled) {
                (VOID)StringCchPrintfW(c->NewValue, _countof(c->NewValue),
                                       L"on:%s", g_ssm.Proxy.ProxyServer);
            } else {
                (VOID)StringCchCopyW(c->NewValue, _countof(c->NewValue), L"off");
            }
            c->IsSecurityDegrade = (wcscmp(g_ssm.Proxy.ProxyServer, base->Proxy.ProxyServer) != 0);
        }
    }

    /* DNS — 解析器集合漂移 (向量比较 + 逗号拼接) */
    {
        BOOLEAN dnsDiff = (g_ssm.Dns.DnsServerCount != base->Dns.DnsServerCount);
        if (!dnsDiff) {
            for (ULONG k = 0; k < g_ssm.Dns.DnsServerCount; ++k) {
                if (wcscmp(g_ssm.Dns.DnsServers[k], base->Dns.DnsServers[k]) != 0) {
                    dnsDiff = TRUE;
                    break;
                }
            }
        }
        if (dnsDiff) {
            ULONG i = n++;
            if (Changes != NULL && i < Capacity) {
                WKD_SSM_CHANGE* c = &Changes[i];
                memset(c, 0, sizeof(*c));
                c->Category = WkdSsmCat_Network;
                c->SettingType = WkdSsmSt_Unknown;
                (VOID)StringCchCopyW(c->SettingName, _countof(c->SettingName), L"DNS Servers");
                WCHAR* p = c->PreviousValue;
                size_t remain = _countof(c->PreviousValue);
                for (ULONG k = 0; k < base->Dns.DnsServerCount; ++k) {
                    size_t written;
                    p[0] = L'\0';
                    if (FAILED(StringCchPrintfW(p, remain, L"%s,", base->Dns.DnsServers[k]))) {
                        break;
                    }
                    written = wcslen(p);
                    p += written;
                    remain -= written;
                }
                p[0] = L'\0';
                p = c->NewValue;
                remain = _countof(c->NewValue);
                for (ULONG k = 0; k < g_ssm.Dns.DnsServerCount; ++k) {
                    size_t written;
                    p[0] = L'\0';
                    if (FAILED(StringCchPrintfW(p, remain, L"%s,", g_ssm.Dns.DnsServers[k]))) {
                        break;
                    }
                    written = wcslen(p);
                    p += written;
                    remain -= written;
                }
                p[0] = L'\0';
                c->IsSecurityDegrade = TRUE;   /* 对齐 SS: DNS 漂移恒视为降级 */
            }
        }
    }

    *Count = n;
    ReleaseSRWLockShared(&g_ssm.Lock);
    return STATUS_SUCCESS;
}

/* ==================================================
 * 合规 (对应 SS CheckCompliance/CheckPolicyCompliance)
 * ================================================== */

static
VOID SsmAddComplianceFailure(_Inout_ PWKD_SSM_COMPLIANCE Status, _In_ PCSTR Text) {
    if (Status->FailureCount < WKD_SSM_MAX_COMPLIANCE_FAILURES) {
        (VOID)StringCchCopyA(Status->Failures[Status->FailureCount],
                             WKD_REG_MAX_DESC_CHARS, Text);
        Status->FailureCount++;
    }
}

static
VOID SsmAddComplianceWarning(_Inout_ PWKD_SSM_COMPLIANCE Status, _In_ PCSTR Text) {
    if (Status->WarningCount < WKD_SSM_MAX_COMPLIANCE_WARNINGS) {
        (VOID)StringCchCopyA(Status->WarningList[Status->WarningCount],
                             WKD_REG_MAX_DESC_CHARS, Text);
        Status->WarningCount++;
    }
}

VOID
SsmCheckCompliance(_Out_ PWKD_SSM_COMPLIANCE Status) {
    if (Status == NULL) return;
    memset(Status, 0, sizeof(*Status));
    Status->LastChecked = SsmGetNow();

    AcquireSRWLockShared(&g_ssm.Lock);

    /* 6 项检查: UAC/Defender/Public Firewall/RTP 为 failed;
     * ASLR/DEP 仅 warning */

    Status->TotalChecks++;
    if (g_ssm.Uac.Enabled) {
        Status->PassedChecks++;
    } else {
        Status->FailedChecks++;
        SsmAddComplianceFailure(Status, "UAC is disabled");
    }

    Status->TotalChecks++;
    if (g_ssm.Defender.Enabled) {
        Status->PassedChecks++;
    } else {
        Status->FailedChecks++;
        SsmAddComplianceFailure(Status, "Windows Defender is disabled");
    }

    Status->TotalChecks++;
    if (g_ssm.Firewall.PublicEnabled) {
        Status->PassedChecks++;
    } else {
        Status->FailedChecks++;
        SsmAddComplianceFailure(Status, "Public firewall is disabled");
    }

    Status->TotalChecks++;
    if (g_ssm.Defender.RealTimeProtection) {
        Status->PassedChecks++;
    } else {
        Status->FailedChecks++;
        SsmAddComplianceFailure(Status, "Real-time protection is disabled");
    }

    Status->TotalChecks++;
    if (g_ssm.Exploit.AslrEnabled) {
        Status->PassedChecks++;
    } else {
        Status->Warnings++;
        SsmAddComplianceWarning(Status, "ASLR may not be fully enabled");
    }

    Status->TotalChecks++;
    if (g_ssm.Exploit.DepEnabled) {
        Status->PassedChecks++;
    } else {
        Status->Warnings++;
        SsmAddComplianceWarning(Status, "DEP may not be fully enabled");
    }

    Status->IsCompliant = (Status->FailedChecks == 0);
    ReleaseSRWLockShared(&g_ssm.Lock);
}

VOID
SsmCheckPolicyCompliance(_In_ PCWSTR PolicyPath, _Out_ PWKD_SSM_COMPLIANCE Status) {
    /* 承袭 SS 偏弱语义: 绝对路径 + 存在性校验后委托 CheckCompliance
     * (SS: weakly_canonical + fs::exists; WkD: GetFullPathNameW 规范化
     * + GetFileAttributesW 存在性, 不解析符号链接) */
    if (Status == NULL) return;
    memset(Status, 0, sizeof(*Status));
    Status->LastChecked = SsmGetNow();

    WCHAR canonical[WKD_REG_MAX_PATH_CHARS];
    canonical[0] = L'\0';
    BOOLEAN pathOk = (PolicyPath != NULL && PolicyPath[0] != L'\0' &&
                      SsmCanonicaliseExportPath(PolicyPath, canonical, _countof(canonical)));

    if (!pathOk || GetFileAttributesW(canonical) == INVALID_FILE_ATTRIBUTES) {
        Status->IsCompliant = FALSE;
        Status->FailedChecks = 1;
        Status->TotalChecks = 1;

        CHAR pathA[WKD_REG_MAX_PATH_CHARS];
        CHAR msg[WKD_REG_MAX_DESC_CHARS];
        SsmSanitizeLogW(canonical, pathA, _countof(pathA));
        (VOID)StringCchPrintfA(msg, _countof(msg), "Policy file not found: %s", pathA);
        SsmAddComplianceFailure(Status, msg);
        return;
    }

    SsmCheckCompliance(Status);

    CHAR pathA[WKD_REG_MAX_PATH_CHARS];
    SsmSanitizeLogW(canonical, pathA, _countof(pathA));
    SsmDbgPrint(L"[SSM] Policy compliance evaluated against: %hs", pathA);
}

/* ==================================================
 * 历史 (GetHistory/GetHistoryByCategory)
 * ================================================== */

NTSTATUS
SsmGetHistory(_In_ ULONG MaxCount, _Out_opt_ PWKD_SSM_CHANGE Changes,
              _In_ ULONG Capacity, _Inout_ PULONG Count) {
    if (Count == NULL) return STATUS_INVALID_PARAMETER;
    *Count = 0;

    EnterCriticalSection(&g_ssm.HistoryLock);
    *Count = SsmTrackerGetHistoryLocked(MaxCount, Changes, Capacity);
    LeaveCriticalSection(&g_ssm.HistoryLock);
    return STATUS_SUCCESS;
}

NTSTATUS
SsmGetHistoryByCategory(_In_ ULONG Category, _In_ ULONG MaxCount,
                        _Out_opt_ PWKD_SSM_CHANGE Changes, _In_ ULONG Capacity,
                        _Inout_ PULONG Count) {
    if (Count == NULL) return STATUS_INVALID_PARAMETER;
    *Count = 0;

    EnterCriticalSection(&g_ssm.HistoryLock);
    *Count = SsmTrackerGetByCategoryLocked(Category, MaxCount, Changes, Capacity);
    LeaveCriticalSection(&g_ssm.HistoryLock);
    return STATUS_SUCCESS;
}

/* ==================================================
 * 告警 (GetActiveAlerts/AcknowledgeAlert/ClearAlerts)
 * ================================================== */

NTSTATUS
SsmGetActiveAlerts(_Out_opt_ PWKD_SSM_ALERT Alerts, _In_ ULONG Capacity, _Inout_ PULONG Count) {
    if (Count == NULL) return STATUS_INVALID_PARAMETER;
    *Count = 0;

    EnterCriticalSection(&g_ssm.AlertsLock);
    *Count = SsmAlertGetActiveLocked(Alerts, Capacity);
    LeaveCriticalSection(&g_ssm.AlertsLock);
    return STATUS_SUCCESS;
}

BOOLEAN
SsmAcknowledgeAlert(_In_ ULONGLONG AlertId) {
    EnterCriticalSection(&g_ssm.AlertsLock);
    const BOOLEAN found = SsmAlertAcknowledgeLocked(AlertId);
    LeaveCriticalSection(&g_ssm.AlertsLock);
    return found;
}

VOID
SsmClearAlerts(VOID) {
    EnterCriticalSection(&g_ssm.AlertsLock);
    SsmAlertClearAllLocked();
    LeaveCriticalSection(&g_ssm.AlertsLock);
}

/* ==================================================
 * 补救 (对应 SS Remediate/SetAutoRemediation/IsAutoRemediationEnabled;
 * RemediateChange 实现在 Part 5) 
 * ================================================== */

static BOOLEAN SsmRemediateChange(_In_ PCWKD_SSM_CHANGE Change);

BOOLEAN
SsmRemediate(_In_ ULONGLONG ChangeId) {
    /* 对齐 SS: GetHistory(1000) 回查 changeId 后委托 RemediateChange。
     * 历史条目约 6KB/条, 堆缓冲避免大栈。 */
    PWKD_SSM_CHANGE changes = (PWKD_SSM_CHANGE)UtHeapAlloc(
        WKD_SSM_HISTORY_RETURN_CAP * sizeof(WKD_SSM_CHANGE));
    if (changes == NULL) return FALSE;

    ULONG count = 0;
    (VOID)SsmGetHistory(WKD_SSM_HISTORY_RETURN_CAP, changes,
                        WKD_SSM_HISTORY_RETURN_CAP, &count);

    BOOLEAN matched = FALSE;
    BOOLEAN result = FALSE;
    for (ULONG i = 0; i < count; ++i) {
        if (changes[i].ChangeId == ChangeId) {
            matched = TRUE;
            result = SsmRemediateChange(&changes[i]);
            break;
        }
    }
    UtHeapFree(changes);

    if (!matched) {
        SsmDbgPrint(L"[SSM] Change %I64u not found", ChangeId);
        return FALSE;
    }
    return result;
}

VOID
SsmSetAutoRemediation(_In_ BOOLEAN Enable) {
    AcquireSRWLockExclusive(&g_ssm.Lock);
    g_ssm.Config.EnableAutoRemediation = Enable;
    ReleaseSRWLockExclusive(&g_ssm.Lock);
    SsmDbgPrint(L"[SSM] Auto-remediation %ls", Enable ? L"enabled" : L"disabled");
}

BOOLEAN
SsmIsAutoRemediationEnabled(VOID) {
    AcquireSRWLockShared(&g_ssm.Lock);
    const BOOLEAN enabled = g_ssm.Config.EnableAutoRemediation;
    ReleaseSRWLockShared(&g_ssm.Lock);
    return enabled;
}

/* ==================================================
 * 统计与版本 (GetStatistics/ResetStatistics/GetVersionString)
 * ================================================== */

VOID
SsmGetStatistics(_Out_ PWKD_SSM_STATS Statistics) {
    if (Statistics == NULL) return;
    Statistics->ChangesDetected = InterlockedCompareExchange64(&g_ssm.Stats.ChangesDetected, 0, 0);
    Statistics->SecurityDegrades = InterlockedCompareExchange64(&g_ssm.Stats.SecurityDegrades, 0, 0);
    Statistics->AlertsGenerated = InterlockedCompareExchange64(&g_ssm.Stats.AlertsGenerated, 0, 0);
    Statistics->RemediationsPerformed = InterlockedCompareExchange64(&g_ssm.Stats.RemediationsPerformed, 0, 0);
    Statistics->RemediationsFailed = InterlockedCompareExchange64(&g_ssm.Stats.RemediationsFailed, 0, 0);
    Statistics->UacChanges = InterlockedCompareExchange64(&g_ssm.Stats.UacChanges, 0, 0);
    Statistics->DefenderChanges = InterlockedCompareExchange64(&g_ssm.Stats.DefenderChanges, 0, 0);
    Statistics->FirewallChanges = InterlockedCompareExchange64(&g_ssm.Stats.FirewallChanges, 0, 0);
    Statistics->NetworkChanges = InterlockedCompareExchange64(&g_ssm.Stats.NetworkChanges, 0, 0);
    Statistics->ShellChanges = InterlockedCompareExchange64(&g_ssm.Stats.ShellChanges, 0, 0);
}

VOID
SsmResetStatistics(VOID) {
    SsmResetStatsLocked(&g_ssm.Stats);
}

PCSTR
SsmGetVersionString(VOID) {
    /* 编译期拼接 (版本常量; 静态缓冲线程安全) */
    static char version[32];
    if (version[0] == '\0') {
        (VOID)StringCchPrintfA(version, _countof(version), "%u.%u.%u",
                               WKD_SSM_VERSION_MAJOR, WKD_SSM_VERSION_MINOR,
                               WKD_SSM_VERSION_PATCH);
    }
    return version;
}

/* ==================================================
 * 刷新 (RefreshAll/RefreshCategory)
 * ================================================== */

VOID
SsmRefreshAll(VOID) {
    AcquireSRWLockExclusive(&g_ssm.Lock);
    SsmRefreshAllLocked();
    ReleaseSRWLockExclusive(&g_ssm.Lock);
}

VOID
SsmRefreshCategory(_In_ ULONG Category) {
    AcquireSRWLockExclusive(&g_ssm.Lock);
    switch (Category) {
        case WkdSsmCat_Security:
            SsmRefreshUacLocked();
            SsmRefreshDefenderLocked();
            SsmRefreshFirewallLocked();
            SsmRefreshExploitLocked();
            break;
        case WkdSsmCat_Network:
            SsmRefreshProxyLocked();
            SsmRefreshDnsLocked();
            break;
        case WkdSsmCat_Authentication:
            SsmRefreshLsaLocked();
            break;
        default:
            break;
    }
    ReleaseSRWLockExclusive(&g_ssm.Lock);
}

/* ==================================================
 * 变更检测与派发 (DetectChanges + On* 系列)
 * ================================================== */

/* 下一个变更 ID (m_nextChangeId.fetch_add; 防 0 回绕) */
static ULONGLONG
SsmNextChangeId(VOID) {
    ULONGLONG Id = (ULONGLONG)InterlockedIncrement64(&g_ssm.NextChangeId);
    if (Id == 0) {
        Id = (ULONGLONG)InterlockedIncrement64(&g_ssm.NextChangeId);
    }
    return Id;
}

/* 读取配置快照。SS 在 On* 派发阶段(锁外)直读 m_config,
 * 存在与 Restore*Defaults 写配置的理论竞态; WkD 用共享锁拷贝,
 * 行为等价且消除数据竞争。自动补救/告警阈值的判断一律基于快照。 */
static VOID
SsmGetConfigSnapshot(_Out_ PWKD_SSM_CONFIG Out) {
    AcquireSRWLockShared(&g_ssm.Lock);
    *Out = g_ssm.Config;
    ReleaseSRWLockShared(&g_ssm.Lock);
}

/* 安全检查告警 (CreateSecurityAlert; 定义见后, On* 前置引用) */
static VOID
SsmCreateSecurityAlert(_In_ PCWKD_SSM_CHANGE Change);

/* 变更动作表条目 (ChangeAction 结构) */
typedef struct _SSM_CHANGE_ACTION {
    ULONG   Kind;      /* SSM_CA_* */
    BOOLEAN PrevB;
    BOOLEAN CurB;
    ULONG   PrevU;
    ULONG   CurU;
} SSM_CHANGE_ACTION;

/* 动作种类 (ChangeAction::Kind) */
#define SSM_CA_UAC_ENABLE      0
#define SSM_CA_UAC_CONSENT     1
#define SSM_CA_DEFENDER        2
#define SSM_CA_DEFENDER_RTP    3
#define SSM_CA_DEFENDER_BEHAVIOR 4
#define SSM_CA_FW_DOMAIN       5
#define SSM_CA_FW_PRIVATE      6
#define SSM_CA_FW_PUBLIC       7
#define SSM_CA_LSA_RUN_AS_PPL  8
#define SSM_CA_LSA_NO_LM_HASH  9
#define SSM_CA_EXPLOIT_SEHOP   10

/* 通用安全降级 (OnGenericSecurityDegrade; 告警不经最低严重度过滤) */
static VOID
SsmOnGenericSecurityDegrade(_In_ ULONG SettingType, _In_ PCWSTR Name,
                            _In_ ULONG Severity, _In_ PCSTR MitreId) {
    WKD_SSM_CHANGE change;
    WKD_SSM_ALERT alert;
    CHAR          nameA[WKD_REG_MAX_NAME_CHARS];
    CHAR          titleA[WKD_REG_MAX_DESC_CHARS];

    memset(&change, 0, sizeof(change));
    memset(&alert, 0, sizeof(alert));

    change.ChangeId = SsmNextChangeId();
    change.Timestamp = SsmGetNow();
    change.Category = WkdSsmCat_Security;
    change.SettingType = SettingType;
    (VOID)StringCchCopyW(change.SettingName,
                         _countof(change.SettingName), Name);
    change.PreviousValue[0] = L'1';
    change.PreviousValue[1] = L'\0';
    change.NewValue[0] = L'0';
    change.NewValue[1] = L'\0';
    change.IsSecurityDegrade = TRUE;
    change.IsMalwareIndicator = (Severity >= WkdSsmSev_High);
    change.Severity = Severity;

    /* riskDescription = "Security degraded: " + 窄化名 (sanitize 防注入) */
    SsmSanitizeLogW(Name, titleA, _countof(titleA));
    (VOID)StringCchPrintfA(change.RiskDescription,
                           _countof(change.RiskDescription),
                           "Security degraded: %s", titleA);

    InterlockedIncrement64(&g_ssm.Stats.ChangesDetected);
    InterlockedIncrement64(&g_ssm.Stats.SecurityDegrades);

    EnterCriticalSection(&g_ssm.HistoryLock);
    SsmTrackerRecordLocked(&change);
    LeaveCriticalSection(&g_ssm.HistoryLock);
    SsmInvokeChangeCallbacks(&change);

    /* 对齐 SS: 泛型降级无条件告警, 不检查 minimumAlertSeverity */
    alert.Timestamp = change.Timestamp;
    alert.Severity = Severity;
    (VOID)StringCchCopyA(alert.AlertType, _countof(alert.AlertType),
                         "SecurityDegradation");
    (VOID)StringCchCopyA(alert.Title, _countof(alert.Title),
                         change.RiskDescription);
    SsmSanitizeLogW(Name, nameA, _countof(nameA));
    (VOID)StringCchPrintfA(alert.Description, _countof(alert.Description),
                           "Security protection disabled: %s", nameA);
    alert.Category = change.Category;
    alert.SettingType = SettingType;
    (VOID)StringCchCopyA(alert.MitreId, _countof(alert.MitreId), MitreId);
    (VOID)StringCchCopyA(alert.MitreTactic, _countof(alert.MitreTactic),
                         "Defense Evasion");
    alert.CanRemediate = FALSE;

    (VOID)SsmAlertCreate(&alert);
    SsmInvokeAlertCallbacks(&alert);
    InterlockedIncrement64(&g_ssm.Stats.AlertsGenerated);
}

/* UAC 启用状态变化 (OnUACChange) */
static VOID
SsmOnUacChange(_In_ BOOLEAN WasEnabled, _In_ BOOLEAN IsEnabled) {
    WKD_SSM_CHANGE change;
    memset(&change, 0, sizeof(change));

    change.ChangeId = SsmNextChangeId();
    change.Timestamp = SsmGetNow();
    change.Category = WkdSsmCat_Security;
    change.SettingType = WkdSsmSt_UacEnabled;
    (VOID)StringCchCopyW(change.SettingPath, _countof(change.SettingPath),
                         SsmRegPath_Uac);
    (VOID)StringCchCopyW(change.SettingName, _countof(change.SettingName),
                         L"UAC Enabled");
    change.PreviousValue[0] = WasEnabled ? L'1' : L'0';
    change.PreviousValue[1] = L'\0';
    change.NewValue[0] = IsEnabled ? L'1' : L'0';
    change.NewValue[1] = L'\0';
    change.IsSecurityDegrade = !IsEnabled;
    change.Severity = IsEnabled ? WkdSsmSev_Info : WkdSsmSev_Critical;
    if (!IsEnabled) {
        (VOID)StringCchCopyA(change.RiskDescription,
                             _countof(change.RiskDescription),
                             "UAC has been disabled - system is vulnerable to privilege escalation");
    }

    InterlockedIncrement64(&g_ssm.Stats.ChangesDetected);
    InterlockedIncrement64(&g_ssm.Stats.UacChanges);
    if (change.IsSecurityDegrade) {
        InterlockedIncrement64(&g_ssm.Stats.SecurityDegrades);
    }

    EnterCriticalSection(&g_ssm.HistoryLock);
    SsmTrackerRecordLocked(&change);
    LeaveCriticalSection(&g_ssm.HistoryLock);
    SsmInvokeChangeCallbacks(&change);

    /* 告警 */
    WKD_SSM_CONFIG cfg;
    SsmGetConfigSnapshot(&cfg);
    if (change.Severity >= cfg.MinimumAlertSeverity) {
        SsmCreateSecurityAlert(&change);
    }

    /* 自动补救 (对齐 SS: 记录/告警完成后执行; 局部副本的 WasRemediated
     * 修改不会回写已录制历史, 承袭 SS 时序) */
    if (cfg.EnableAutoRemediation && cfg.RemediateUAC && !IsEnabled) {
        SsmDbgPrint(L"[SSM] Auto-remediating UAC disable");
        (VOID)SsmRestoreUacDefaults();
        change.ActionTaken = WkdSsmRem_Restore;
        change.WasRemediated = TRUE;
    }
}

/* UAC 同意提示级别变化 (OnUACConsentChange) */
static VOID
SsmOnUacConsentChange(_In_ ULONG WasValue, _In_ ULONG IsValue) {
    WKD_SSM_CHANGE change;
    memset(&change, 0, sizeof(change));

    change.ChangeId = SsmNextChangeId();
    change.Timestamp = SsmGetNow();
    change.Category = WkdSsmCat_Security;
    change.SettingType = WkdSsmSt_UacConsentPromptAdmin;
    (VOID)StringCchCopyW(change.SettingPath, _countof(change.SettingPath),
                         SsmRegPath_Uac);
    (VOID)StringCchCopyW(change.SettingName, _countof(change.SettingName),
                         L"ConsentPromptBehaviorAdmin");
    (VOID)StringCchPrintfW(change.PreviousValue,
                           _countof(change.PreviousValue), L"%lu", WasValue);
    (VOID)StringCchPrintfW(change.NewValue,
                           _countof(change.NewValue), L"%lu", IsValue);
    change.IsSecurityDegrade = (IsValue < WasValue);

    if (IsValue == 0) {
        change.Severity = WkdSsmSev_Critical;
        change.IsMalwareIndicator = TRUE;
        (VOID)StringCchCopyA(change.RiskDescription,
                             _countof(change.RiskDescription),
                             "ConsentPromptBehaviorAdmin=0: silent elevation (UAC bypass T1548.002)");
    } else if (IsValue < WasValue) {
        change.Severity = WkdSsmSev_High;
        (VOID)StringCchCopyA(change.RiskDescription,
                             _countof(change.RiskDescription),
                             "UAC consent prompt weakened");
    } else {
        change.Severity = WkdSsmSev_Info;
    }

    InterlockedIncrement64(&g_ssm.Stats.ChangesDetected);
    InterlockedIncrement64(&g_ssm.Stats.UacChanges);
    if (change.IsSecurityDegrade) {
        InterlockedIncrement64(&g_ssm.Stats.SecurityDegrades);
    }

    EnterCriticalSection(&g_ssm.HistoryLock);
    SsmTrackerRecordLocked(&change);
    LeaveCriticalSection(&g_ssm.HistoryLock);
    SsmInvokeChangeCallbacks(&change);

    WKD_SSM_CONFIG cfg;
    SsmGetConfigSnapshot(&cfg);
    if (change.Severity >= cfg.MinimumAlertSeverity) {
        SsmCreateSecurityAlert(&change);
    }
}

/* Defender 启用状态变化 (OnDefenderChange) */
static VOID
SsmOnDefenderChange(_In_ BOOLEAN WasEnabled, _In_ BOOLEAN IsEnabled) {
    WKD_SSM_CHANGE change;
    memset(&change, 0, sizeof(change));

    change.ChangeId = SsmNextChangeId();
    change.Timestamp = SsmGetNow();
    change.Category = WkdSsmCat_Security;
    change.SettingType = WkdSsmSt_DefenderEnabled;
    (VOID)StringCchCopyW(change.SettingPath, _countof(change.SettingPath),
                         SsmRegPath_DefenderPolicy);
    (VOID)StringCchCopyW(change.SettingName, _countof(change.SettingName),
                         L"Windows Defender Enabled");
    change.PreviousValue[0] = WasEnabled ? L'1' : L'0';
    change.PreviousValue[1] = L'\0';
    change.NewValue[0] = IsEnabled ? L'1' : L'0';
    change.NewValue[1] = L'\0';
    change.IsSecurityDegrade = !IsEnabled;
    change.Severity = IsEnabled ? WkdSsmSev_Info : WkdSsmSev_Critical;
    change.IsMalwareIndicator = !IsEnabled;
    if (!IsEnabled) {
        (VOID)StringCchCopyA(change.RiskDescription,
                             _countof(change.RiskDescription),
                             "Windows Defender has been disabled - common malware tactic");
    }

    InterlockedIncrement64(&g_ssm.Stats.ChangesDetected);
    InterlockedIncrement64(&g_ssm.Stats.DefenderChanges);
    if (change.IsSecurityDegrade) {
        InterlockedIncrement64(&g_ssm.Stats.SecurityDegrades);
    }

    EnterCriticalSection(&g_ssm.HistoryLock);
    SsmTrackerRecordLocked(&change);
    LeaveCriticalSection(&g_ssm.HistoryLock);
    SsmInvokeChangeCallbacks(&change);

    WKD_SSM_CONFIG cfg;
    SsmGetConfigSnapshot(&cfg);
    if (change.Severity >= cfg.MinimumAlertSeverity) {
        SsmCreateSecurityAlert(&change);
    }

    /* 自动补救 (对齐 SS: 禁用为可恢复事件, 日志降级为 Warning) */
    if (cfg.EnableAutoRemediation && cfg.RemediateDefender && !IsEnabled) {
        SsmDbgPrint(L"[SSM] Auto-remediating Defender disable (T1562.001)");
        (VOID)SsmRestoreDefenderDefaults();
        change.ActionTaken = WkdSsmRem_Restore;
        change.WasRemediated = TRUE;
    }
}

/* Defender 实时保护变化 (OnRealTimeProtectionChange;
 * 注意: SS 此处不递增 ChangesDetected/SecurityDegrades, 承袭) */
static VOID
SsmOnRealTimeProtectionChange(_In_ BOOLEAN WasEnabled, _In_ BOOLEAN IsEnabled) {
    WKD_SSM_CHANGE change;
    memset(&change, 0, sizeof(change));

    change.ChangeId = SsmNextChangeId();
    change.Timestamp = SsmGetNow();
    change.Category = WkdSsmCat_Security;
    change.SettingType = WkdSsmSt_DefenderRealtimeProtection;
    (VOID)StringCchCopyW(change.SettingName, _countof(change.SettingName),
                         L"Real-Time Protection");
    change.PreviousValue[0] = WasEnabled ? L'1' : L'0';
    change.PreviousValue[1] = L'\0';
    change.NewValue[0] = IsEnabled ? L'1' : L'0';
    change.NewValue[1] = L'\0';
    change.IsSecurityDegrade = !IsEnabled;
    change.Severity = IsEnabled ? WkdSsmSev_Info : WkdSsmSev_High;
    change.IsMalwareIndicator = !IsEnabled;

    InterlockedIncrement64(&g_ssm.Stats.DefenderChanges);

    EnterCriticalSection(&g_ssm.HistoryLock);
    SsmTrackerRecordLocked(&change);
    LeaveCriticalSection(&g_ssm.HistoryLock);
    SsmInvokeChangeCallbacks(&change);

    WKD_SSM_CONFIG cfg;
    SsmGetConfigSnapshot(&cfg);
    if (change.Severity >= cfg.MinimumAlertSeverity) {
        SsmCreateSecurityAlert(&change);
    }
}

/* 防火墙档案变化 (OnFirewallChange; 恢复历史按档案区分,
 * 不再全局打为 Public 类型) */
static VOID
SsmOnFirewallChange(_In_ ULONG Profile, _In_ BOOLEAN WasEnabled,
                    _In_ BOOLEAN IsEnabled) {
    WKD_SSM_CHANGE change;
    memset(&change, 0, sizeof(change));

    change.ChangeId = SsmNextChangeId();
    change.Timestamp = SsmGetNow();
    change.Category = WkdSsmCat_Security;

    switch (Profile) {
        case WkdSsmFw_Domain:
            change.SettingType = WkdSsmSt_FirewallDomainEnabled;
            (VOID)StringCchCopyW(change.SettingName, _countof(change.SettingName),
                                 L"Firewall Domain Profile");
            break;
        case WkdSsmFw_Private:
            change.SettingType = WkdSsmSt_FirewallPrivateEnabled;
            (VOID)StringCchCopyW(change.SettingName, _countof(change.SettingName),
                                 L"Firewall Private Profile");
            break;
        case WkdSsmFw_Public:
        default:
            change.SettingType = WkdSsmSt_FirewallPublicEnabled;
            (VOID)StringCchCopyW(change.SettingName, _countof(change.SettingName),
                                 L"Firewall Public Profile");
            break;
    }

    change.PreviousValue[0] = WasEnabled ? L'1' : L'0';
    change.PreviousValue[1] = L'\0';
    change.NewValue[0] = IsEnabled ? L'1' : L'0';
    change.NewValue[1] = L'\0';
    change.IsSecurityDegrade = !IsEnabled;
    change.Severity = IsEnabled ? WkdSsmSev_Info : WkdSsmSev_High;

    /* 对齐 SS: 防火墙变更只递增 FirewallChanges, 不递增 ChangesDetected */
    InterlockedIncrement64(&g_ssm.Stats.FirewallChanges);

    EnterCriticalSection(&g_ssm.HistoryLock);
    SsmTrackerRecordLocked(&change);
    LeaveCriticalSection(&g_ssm.HistoryLock);
    SsmInvokeChangeCallbacks(&change);

    WKD_SSM_CONFIG cfg;
    SsmGetConfigSnapshot(&cfg);
    if (change.Severity >= cfg.MinimumAlertSeverity) {
        SsmCreateSecurityAlert(&change);
    }

    /* 自动补救 (对齐 SS: 仅对实际禁用执行) */
    if (cfg.EnableAutoRemediation && cfg.RemediateFirewall && !IsEnabled) {
        SsmDbgPrint(L"[SSM] Auto-remediating firewall disable (profile=%lu)", Profile);
        (VOID)SsmRestoreFirewallDefaults();
        change.ActionTaken = WkdSsmRem_Restore;
        change.WasRemediated = TRUE;
    }
}

/* 安全检查告警 (CreateSecurityAlert; MITRE 映射) */
static VOID
SsmCreateSecurityAlert(_In_ PCWKD_SSM_CHANGE Change) {
    WKD_SSM_ALERT alert;
    CHAR          nameA[WKD_REG_MAX_NAME_CHARS];
    CHAR          prevA[WKD_REG_MAX_NAME_CHARS];
    CHAR          newA[WKD_REG_MAX_NAME_CHARS];

    memset(&alert, 0, sizeof(alert));

    alert.Timestamp = Change->Timestamp;
    alert.Severity = Change->Severity;
    (VOID)StringCchCopyA(alert.AlertType, _countof(alert.AlertType),
                         "SettingChange");
    (VOID)StringCchCopyA(alert.Title, _countof(alert.Title),
                         "Security Setting Modified");

    /* 描述三要素全部经 sanitize, 防注册表内容注入日志/SIEM (对齐 SS) */
    SsmSanitizeLogW(Change->SettingName, nameA, _countof(nameA));
    SsmSanitizeLogW(Change->PreviousValue, prevA, _countof(prevA));
    SsmSanitizeLogW(Change->NewValue, newA, _countof(newA));
    (VOID)StringCchPrintfA(alert.Description, _countof(alert.Description),
                           "Setting '%s' changed from '%s' to '%s'",
                           nameA, prevA, newA);

    alert.Category = Change->Category;
    alert.SettingType = Change->SettingType;
    (VOID)StringCchCopyW(alert.SettingPath, _countof(alert.SettingPath),
                         Change->SettingPath);
    (VOID)StringCchCopyW(alert.PreviousValue, _countof(alert.PreviousValue),
                         Change->PreviousValue);
    (VOID)StringCchCopyW(alert.CurrentValue, _countof(alert.CurrentValue),
                         Change->NewValue);

    alert.CanRemediate = TRUE;
    alert.RecommendedAction = WkdSsmRem_Restore;
    alert.WasRemediated = Change->WasRemediated;

    /* MITRE ATT&CK 映射 (全表; 扩展覆盖各档案防火墙) */
    switch (Change->SettingType) {
        case WkdSsmSt_DefenderEnabled:
        case WkdSsmSt_DefenderRealtimeProtection:
        case WkdSsmSt_DefenderBehaviorMonitoring:
        case WkdSsmSt_DefenderTamperProtection:
        case WkdSsmSt_DefenderCloudProtection:
            (VOID)StringCchCopyA(alert.MitreId, _countof(alert.MitreId),
                                 "T1562.001");
            (VOID)StringCchCopyA(alert.MitreTactic, _countof(alert.MitreTactic),
                                 "Defense Evasion - Disable or Modify Tools");
            break;
        case WkdSsmSt_FirewallDomainEnabled:
        case WkdSsmSt_FirewallPrivateEnabled:
        case WkdSsmSt_FirewallPublicEnabled:
            (VOID)StringCchCopyA(alert.MitreId, _countof(alert.MitreId),
                                 "T1562.004");
            (VOID)StringCchCopyA(alert.MitreTactic, _countof(alert.MitreTactic),
                                 "Defense Evasion - Disable or Modify System Firewall");
            break;
        case WkdSsmSt_UacEnabled:
        case WkdSsmSt_UacConsentPromptAdmin:
            (VOID)StringCchCopyA(alert.MitreId, _countof(alert.MitreId),
                                 "T1548.002");
            (VOID)StringCchCopyA(alert.MitreTactic, _countof(alert.MitreTactic),
                                 "Privilege Escalation - Bypass UAC");
            break;
        case WkdSsmSt_LsaRunAsPpl:
        case WkdSsmSt_LsaNoLmHash:
            (VOID)StringCchCopyA(alert.MitreId, _countof(alert.MitreId),
                                 "T1003.001");
            (VOID)StringCchCopyA(alert.MitreTactic, _countof(alert.MitreTactic),
                                 "Credential Access - LSASS Memory");
            break;
        case WkdSsmSt_ExploitSehop:
        case WkdSsmSt_ExploitAslr:
        case WkdSsmSt_ExploitCfg:
            (VOID)StringCchCopyA(alert.MitreId, _countof(alert.MitreId), "T1068");
            (VOID)StringCchCopyA(alert.MitreTactic, _countof(alert.MitreTactic),
                                 "Privilege Escalation - Exploitation");
            break;
        default:
            if (Change->Category == WkdSsmCat_Network) {
                (VOID)StringCchCopyA(alert.MitreId, _countof(alert.MitreId),
                                     "T1071.004");
                (VOID)StringCchCopyA(alert.MitreTactic, _countof(alert.MitreTactic),
                                     "Command and Control - DNS");
            }
            break;
    }

    (VOID)SsmAlertCreate(&alert);
    SsmInvokeAlertCallbacks(&alert);
    InterlockedIncrement64(&g_ssm.Stats.AlertsGenerated);
}

/* ==================================================
 * 变更检测 (DetectChanges)
 * 共享锁内比较并收集动作表, 释放锁后逐项派发 On*,
 * 保证 Restore*Defaults 可安全获取独占锁 (无自杀死锁)。
 * ================================================== */

static VOID
SsmDetectChanges(_In_ PCWKD_SSM_SNAPSHOT Previous) {
    SSM_CHANGE_ACTION actions[11];
    ULONG             actionCount = 0;
    WKD_SSM_CONFIG    cfg;

    /* 锁内收集比较决策 */
    AcquireSRWLockShared(&g_ssm.Lock);
    cfg = g_ssm.Config;

    if (cfg.MonitorUAC) {
        if (g_ssm.Uac.Enabled != Previous->Uac.Enabled) {
            actions[actionCount].Kind = SSM_CA_UAC_ENABLE;
            actions[actionCount].PrevB = Previous->Uac.Enabled;
            actions[actionCount].CurB = g_ssm.Uac.Enabled;
            actionCount++;
        }
        if (g_ssm.Uac.ConsentPromptAdmin != Previous->Uac.ConsentPromptAdmin) {
            actions[actionCount].Kind = SSM_CA_UAC_CONSENT;
            actions[actionCount].PrevU = Previous->Uac.ConsentPromptAdmin;
            actions[actionCount].CurU = g_ssm.Uac.ConsentPromptAdmin;
            actionCount++;
        }
    }

    if (cfg.MonitorDefender) {
        if (g_ssm.Defender.Enabled != Previous->Defender.Enabled) {
            actions[actionCount].Kind = SSM_CA_DEFENDER;
            actions[actionCount].PrevB = Previous->Defender.Enabled;
            actions[actionCount].CurB = g_ssm.Defender.Enabled;
            actionCount++;
        }
        if (g_ssm.Defender.RealTimeProtection != Previous->Defender.RealTimeProtection) {
            actions[actionCount].Kind = SSM_CA_DEFENDER_RTP;
            actions[actionCount].PrevB = Previous->Defender.RealTimeProtection;
            actions[actionCount].CurB = g_ssm.Defender.RealTimeProtection;
            actionCount++;
        }
        if (Previous->Defender.BehaviorMonitoring && !g_ssm.Defender.BehaviorMonitoring) {
            actions[actionCount].Kind = SSM_CA_DEFENDER_BEHAVIOR;
            actionCount++;
        }
    }

    if (cfg.MonitorFirewall) {
        if (g_ssm.Firewall.DomainEnabled != Previous->Firewall.DomainEnabled) {
            actions[actionCount].Kind = SSM_CA_FW_DOMAIN;
            actions[actionCount].PrevB = Previous->Firewall.DomainEnabled;
            actions[actionCount].CurB = g_ssm.Firewall.DomainEnabled;
            actionCount++;
        }
        if (g_ssm.Firewall.PrivateEnabled != Previous->Firewall.PrivateEnabled) {
            actions[actionCount].Kind = SSM_CA_FW_PRIVATE;
            actions[actionCount].PrevB = Previous->Firewall.PrivateEnabled;
            actions[actionCount].CurB = g_ssm.Firewall.PrivateEnabled;
            actionCount++;
        }
        if (g_ssm.Firewall.PublicEnabled != Previous->Firewall.PublicEnabled) {
            actions[actionCount].Kind = SSM_CA_FW_PUBLIC;
            actions[actionCount].PrevB = Previous->Firewall.PublicEnabled;
            actions[actionCount].CurB = g_ssm.Firewall.PublicEnabled;
            actionCount++;
        }
    }

    if (cfg.MonitorLSA) {
        if (Previous->Lsa.RunAsPpl && !g_ssm.Lsa.RunAsPpl) {
            actions[actionCount].Kind = SSM_CA_LSA_RUN_AS_PPL;
            actionCount++;
        }
        if (Previous->Lsa.NoLmHash && !g_ssm.Lsa.NoLmHash) {
            actions[actionCount].Kind = SSM_CA_LSA_NO_LM_HASH;
            actionCount++;
        }
    }

    if (cfg.MonitorExploitProtection) {
        if (Previous->Exploit.SehopEnabled && !g_ssm.Exploit.SehopEnabled) {
            actions[actionCount].Kind = SSM_CA_EXPLOIT_SEHOP;
            actionCount++;
        }
    }
    ReleaseSRWLockShared(&g_ssm.Lock);

    /* 锁外派发 (对齐 SS: 共享锁释放后执行 On*) */
    for (ULONG i = 0; i < actionCount; ++i) {
        SSM_CHANGE_ACTION* a = &actions[i];
        switch (a->Kind) {
            case SSM_CA_UAC_ENABLE:
                SsmOnUacChange(a->PrevB, a->CurB);
                break;
            case SSM_CA_UAC_CONSENT:
                SsmOnUacConsentChange(a->PrevU, a->CurU);
                break;
            case SSM_CA_DEFENDER:
                SsmOnDefenderChange(a->PrevB, a->CurB);
                break;
            case SSM_CA_DEFENDER_RTP:
                SsmOnRealTimeProtectionChange(a->PrevB, a->CurB);
                break;
            case SSM_CA_DEFENDER_BEHAVIOR:
                SsmOnGenericSecurityDegrade(WkdSsmSt_DefenderBehaviorMonitoring,
                                            L"Defender Behavior Monitoring",
                                            WkdSsmSev_High, "T1562.001");
                break;
            case SSM_CA_FW_DOMAIN:
                SsmOnFirewallChange(WkdSsmFw_Domain, a->PrevB, a->CurB);
                break;
            case SSM_CA_FW_PRIVATE:
                SsmOnFirewallChange(WkdSsmFw_Private, a->PrevB, a->CurB);
                break;
            case SSM_CA_FW_PUBLIC:
                SsmOnFirewallChange(WkdSsmFw_Public, a->PrevB, a->CurB);
                break;
            case SSM_CA_LSA_RUN_AS_PPL:
                SsmOnGenericSecurityDegrade(WkdSsmSt_LsaRunAsPpl,
                                            L"LSASS RunAsPPL removed",
                                            WkdSsmSev_Critical, "T1003.001");
                break;
            case SSM_CA_LSA_NO_LM_HASH:
                SsmOnGenericSecurityDegrade(WkdSsmSt_LsaNoLmHash,
                                            L"LM Hash storage enabled",
                                            WkdSsmSev_High, "T1003");
                break;
            case SSM_CA_EXPLOIT_SEHOP:
                SsmOnGenericSecurityDegrade(WkdSsmSt_ExploitSehop,
                                            L"SEHOP disabled",
                                            WkdSsmSev_Medium, "T1068");
                break;
            default:
                break;
        }
    }
}

/* ==================================================
 * 变更补救 (RemediateChange)
 * 仅 4 类可补救: UAC_Enabled / Defender_Enabled /
 * Defender_RealtimeProtection / Firewall_PublicEnabled。
 * 注意: 公共路径 SsmRemediate 先出锁再调用本函数,
 * 此处直读配置字段无锁 (锁外读 m_config)。
 * ================================================== */

static BOOLEAN
SsmRemediateChange(_In_ PCWKD_SSM_CHANGE Change) {
    switch (Change->SettingType) {
        case WkdSsmSt_UacEnabled:
            if (g_ssm.Config.RemediateUAC) {
                return SsmRestoreUacDefaults();
            }
            break;
        case WkdSsmSt_DefenderEnabled:
        case WkdSsmSt_DefenderRealtimeProtection:
            if (g_ssm.Config.RemediateDefender) {
                return SsmRestoreDefenderDefaults();
            }
            break;
        case WkdSsmSt_FirewallPublicEnabled:
            if (g_ssm.Config.RemediateFirewall) {
                return SsmRestoreFirewallDefaults();
            }
            break;
        default:
            SsmDbgPrint(L"[SSM] No remediation for setting type %lu",
                        Change->SettingType);
            return FALSE;
    }
    return FALSE;
}

/* ==================================================
 * 监控线程 (MonitorThreadFunc)
 * 每周期: 共享锁快照 → 独占锁刷新 → 检测并派发 → 分段休眠。
 * 休眠分段为 50ms 并在每段检查 Monitoring, 使 Stop 响应延迟
 * 上限 50ms (SS 为最长整个轮询间隔, 行为等价且更灵敏)。
 * ================================================== */

static DWORD WINAPI
SsmMonitorThreadProc(_In_ LPVOID Param) {
    (VOID)Param;

    SsmDbgPrint(L"[SSM] Monitor thread started (PID %lu)", GetCurrentProcessId());

    /* 钳位轮询间隔, 防 0→忙等 / 极大值→停滞 (clamp) */
    ULONG intervalMs = SsmClampPollInterval(g_ssm.Config.MonitorPollIntervalMs);

    while (g_ssm.Monitoring != 0) {
        /* 1) 共享锁: 快照完整前状态 */
        WKD_SSM_SNAPSHOT previous;
        AcquireSRWLockShared(&g_ssm.Lock);
        SsmCaptureSnapshotLocked(&previous);
        ReleaseSRWLockShared(&g_ssm.Lock);

        /* 2) 独占锁: 全量刷新当前状态 */
        AcquireSRWLockExclusive(&g_ssm.Lock);
        SsmRefreshAllLocked();
        ReleaseSRWLockExclusive(&g_ssm.Lock);

        /* 3) 比较并派发 (内部短时共享锁; On* 全程锁外, 可安全补救) */
        SsmDetectChanges(&previous);

        /* 4) 可中断休眠 */
        ULONG waited = 0;
        while (waited < intervalMs && g_ssm.Monitoring != 0) {
            Sleep(50);
            waited += 50;
        }
    }

    SsmDbgPrint(L"[SSM] Monitor thread stopped");
    return 0;
}

/* ==================================================
 * 导出 (ExportReport/ExportSettings/ExportHistory)
 * 统一 _wfopen_s + L"w, ccs=UTF-8" + fwprintf (SA 导出风格);
 * 字符串字段一律 SsmSanitizeLogW/SsmWriteJsonEscapedW 防注入。
 * ================================================== */

BOOLEAN
SsmExportReport(_In_ PCWSTR OutputPath) {
    WCHAR canonical[WKD_REG_MAX_PATH_CHARS];

    /* 路径规范化: 相对路径→绝对, 拒绝无效输入 (拒绝非绝对路径) */
    if (!SsmCanonicaliseExportPath(OutputPath, canonical, _countof(canonical))) {
        SsmDbgPrint(L"[SSM] ExportReport rejected output path");
        return FALSE;
    }

    FILE* file = NULL;
    if (_wfopen_s(&file, canonical, L"w, ccs=UTF-8") != 0 || file == NULL) {
        return FALSE;
    }

    fwprintf(file, L"=== WkDefender System Settings Monitor Report ===\n\n");

    AcquireSRWLockShared(&g_ssm.Lock);

    fwprintf(file, L"UAC Status:\n");
    fwprintf(file, L"  Enabled: %s\n", g_ssm.Uac.Enabled ? L"Yes" : L"NO");
    {
        CHAR levelA[64];
        SsmSanitizeLogW(SsmUacLevelToString(g_ssm.Uac.Level),
                        levelA, _countof(levelA));
        fwprintf(file, L"  Level: %hs\n\n", levelA);
    }

    fwprintf(file, L"Windows Defender Status:\n");
    fwprintf(file, L"  Enabled: %s\n", g_ssm.Defender.Enabled ? L"Yes" : L"NO");
    fwprintf(file, L"  Real-time: %s\n",
             g_ssm.Defender.RealTimeProtection ? L"Yes" : L"NO");
    fwprintf(file, L"  Tamper Protection: %s\n",
             g_ssm.Defender.TamperProtection ? L"Yes" : L"NO");
    fwprintf(file, L"  Cloud Protection: %s\n\n",
             g_ssm.Defender.CloudProtection ? L"Yes" : L"NO");

    fwprintf(file, L"Firewall Status:\n");
    fwprintf(file, L"  Domain: %s\n", g_ssm.Firewall.DomainEnabled ? L"Enabled" : L"DISABLED");
    fwprintf(file, L"  Private: %s\n", g_ssm.Firewall.PrivateEnabled ? L"Enabled" : L"DISABLED");
    fwprintf(file, L"  Public: %s\n\n", g_ssm.Firewall.PublicEnabled ? L"Enabled" : L"DISABLED");

    ReleaseSRWLockShared(&g_ssm.Lock);

    WKD_SSM_STATS stats;
    SsmGetStatistics(&stats);
    fwprintf(file, L"Statistics:\n");
    fwprintf(file, L"  Changes Detected: %I64u\n", stats.ChangesDetected);
    fwprintf(file, L"  Security Degrades: %I64u\n", stats.SecurityDegrades);
    fwprintf(file, L"  Alerts Generated: %I64u\n", stats.AlertsGenerated);
    fwprintf(file, L"  Remediations: %I64u\n", stats.RemediationsPerformed);

    fclose(file);

    SsmDbgPrint(L"[SSM] Exported report to %ls", canonical);
    return TRUE;
}

BOOLEAN
SsmExportSettings(_In_ PCWSTR OutputPath) {
    WCHAR canonical[WKD_REG_MAX_PATH_CHARS];

    if (!SsmCanonicaliseExportPath(OutputPath, canonical, _countof(canonical))) {
        SsmDbgPrint(L"[SSM] ExportSettings rejected output path");
        return FALSE;
    }

    FILE* file = NULL;
    if (_wfopen_s(&file, canonical, L"w, ccs=UTF-8") != 0 || file == NULL) {
        return FALSE;
    }

    AcquireSRWLockShared(&g_ssm.Lock);

    /* 所有字符串字段经 WriteJsonEscapedW: 代理服务器/DNS 列表等注册表
     * 内容可受攻击者影响, 裸写会破坏 JSON 契约 (反注入注记) */
    fwprintf(file, L"{\n");

    fwprintf(file, L"  \"uac\": {\n");
    fwprintf(file, L"    \"enabled\": %s,\n", g_ssm.Uac.Enabled ? L"true" : L"false");
    fwprintf(file, L"    \"level\": ");
    SsmWriteJsonEscapedW(file, SsmUacLevelToString(g_ssm.Uac.Level));
    fwprintf(file, L",\n");
    fwprintf(file, L"    \"consentPromptAdmin\": %lu,\n", g_ssm.Uac.ConsentPromptAdmin);
    fwprintf(file, L"    \"promptOnSecureDesktop\": %s\n",
             g_ssm.Uac.PromptOnSecureDesktop ? L"true" : L"false");
    fwprintf(file, L"  },\n");

    fwprintf(file, L"  \"defender\": {\n");
    fwprintf(file, L"    \"enabled\": %s,\n", g_ssm.Defender.Enabled ? L"true" : L"false");
    fwprintf(file, L"    \"realTimeProtection\": %s,\n",
             g_ssm.Defender.RealTimeProtection ? L"true" : L"false");
    fwprintf(file, L"    \"behaviorMonitoring\": %s,\n",
             g_ssm.Defender.BehaviorMonitoring ? L"true" : L"false");
    fwprintf(file, L"    \"tamperProtection\": %s,\n",
             g_ssm.Defender.TamperProtection ? L"true" : L"false");
    fwprintf(file, L"    \"cloudProtection\": %s,\n",
             g_ssm.Defender.CloudProtection ? L"true" : L"false");
    fwprintf(file, L"    \"networkProtection\": %s,\n",
             g_ssm.Defender.NetworkProtection ? L"true" : L"false");
    fwprintf(file, L"    \"controlledFolderAccess\": %s\n",
             g_ssm.Defender.ControlledFolderAccess ? L"true" : L"false");
    fwprintf(file, L"  },\n");

    fwprintf(file, L"  \"firewall\": {\n");
    fwprintf(file, L"    \"domainEnabled\": %s,\n",
             g_ssm.Firewall.DomainEnabled ? L"true" : L"false");
    fwprintf(file, L"    \"privateEnabled\": %s,\n",
             g_ssm.Firewall.PrivateEnabled ? L"true" : L"false");
    fwprintf(file, L"    \"publicEnabled\": %s\n",
             g_ssm.Firewall.PublicEnabled ? L"true" : L"false");
    fwprintf(file, L"  },\n");

    fwprintf(file, L"  \"proxy\": {\n");
    fwprintf(file, L"    \"enabled\": %s,\n",
             g_ssm.Proxy.ProxyEnabled ? L"true" : L"false");
    fwprintf(file, L"    \"server\": ");
    SsmWriteJsonEscapedW(file, g_ssm.Proxy.ProxyServer);
    fwprintf(file, L"\n  },\n");

    fwprintf(file, L"  \"dns\": {\n");
    fwprintf(file, L"    \"servers\": [");
    for (ULONG i = 0; i < g_ssm.Dns.DnsServerCount; ++i) {
        if (i != 0) fwprintf(file, L", ");
        SsmWriteJsonEscapedW(file, g_ssm.Dns.DnsServers[i]);
    }
    fwprintf(file, L"],\n");
    fwprintf(file, L"    \"suffix\": ");
    SsmWriteJsonEscapedW(file, g_ssm.Dns.DnsSuffix);
    fwprintf(file, L"\n  }\n");

    fwprintf(file, L"}\n");

    ReleaseSRWLockShared(&g_ssm.Lock);
    fclose(file);

    SsmDbgPrint(L"[SSM] Exported settings to %ls", canonical);
    return TRUE;
}

BOOLEAN
SsmExportHistory(_In_ PCWSTR OutputPath) {
    WCHAR canonical[WKD_REG_MAX_PATH_CHARS];

    if (!SsmCanonicaliseExportPath(OutputPath, canonical, _countof(canonical))) {
        SsmDbgPrint(L"[SSM] ExportHistory rejected output path");
        return FALSE;
    }

    /* 历史条目约 6KB/条, 堆缓冲 (GetHistory 上限 1000 对齐 SS) */
    PWKD_SSM_CHANGE changes = (PWKD_SSM_CHANGE)UtHeapAlloc(
        WKD_SSM_HISTORY_RETURN_CAP * sizeof(WKD_SSM_CHANGE));
    if (changes == NULL) return FALSE;

    ULONG count = 0;
    (VOID)SsmGetHistory(WKD_SSM_HISTORY_RETURN_CAP, changes,
                        WKD_SSM_HISTORY_RETURN_CAP, &count);

    FILE* file = NULL;
    if (_wfopen_s(&file, canonical, L"w, ccs=UTF-8") != 0 || file == NULL) {
        UtHeapFree(changes);
        return FALSE;
    }

    fwprintf(file, L"=== System Settings Change History ===\n\n");

    for (ULONG i = 0; i < count; ++i) {
        CHAR nameA[WKD_REG_MAX_NAME_CHARS];
        CHAR prevA[WKD_REG_MAX_NAME_CHARS];
        CHAR newA[WKD_REG_MAX_NAME_CHARS];

        SsmSanitizeLogW(changes[i].SettingName, nameA, _countof(nameA));
        SsmSanitizeLogW(changes[i].PreviousValue, prevA, _countof(prevA));
        SsmSanitizeLogW(changes[i].NewValue, newA, _countof(newA));

        fwprintf(file, L"Change ID: %I64u\n", changes[i].ChangeId);
        fwprintf(file, L"Category: %hs\n", SsmCategoryToString(changes[i].Category));
        fwprintf(file, L"Setting: %hs\n", nameA);
        fwprintf(file, L"Previous: %hs\n", prevA);
        fwprintf(file, L"New: %hs\n", newA);
        fwprintf(file, L"Security Degrade: %hs\n",
                 changes[i].IsSecurityDegrade ? "YES" : "No");
        fwprintf(file, L"\n");
    }

    fclose(file);
    UtHeapFree(changes);

    SsmDbgPrint(L"[SSM] Exported history (%lu entries) to %ls", count, canonical);
    return TRUE;
}

/* ==================================================
 * SystemSettingsMonitor 迁移完成
 * SystemSettingsMonitor.cpp 全量语义
 * (回调槽表/基线/历史/告警池差异见各节注记)
 * ================================================== */