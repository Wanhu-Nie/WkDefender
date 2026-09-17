/*++
    SelfProtection/RegistryProtection.c - 注册表自保护实现

    Purpose:
        作为独立 CM 回调节点（Callbacks/RegistryCallback.c）的消费者，
        提供注册表自保护的判定能力。维护受保护键列表（静态数组 + 前缀
        匹配），结合引擎注入的豁免回调（受保护进程自改自键放行）对危险
        操作判定 BLOCK 并上报。

        对齐 ShadowStrike SelfProtect.c 的：
        - SHADOWSTRIKE_PROTECTED_REGKEY 键列表 + EX_SPIN_LOCK
        - SspPrefixMatch 前缀匹配
        - ShadowStrikeShouldBlockRegistryAccess 判定链

    Synchronization:
        - EX_SPIN_LOCK 保护键列表；判定路径取共享读、管理路径取排他。

    Copyright (c) WkDefender Team
--*/

#include "RegistryProtection.h"
#include <ntstrsafe.h>
#include "../Process/ProcessMonitor.h"   /* WKD_PROCESS / PsLookupWkdProcessByProcessId / PsLookupWkdProcessByName（2026-09-09 画像迁移 + 评分联动） */
#include "../AnalysisEngine/AnalysisEngine.h"   /* AeReportIndicatorPair / TsSourceBehavioral / TsIndicator_Ioa_SecurityEvent（2026-09-09 评分联动） */
#include "../Common/Constants.h"                 /* AE_THREAT_SEVERITY（2026-09-09 评分联动） */
#include "../Common/Utils.h"

/* ============================================================================
 * 常量定义
 * ============================================================================ */

#define WKD_RG_POOL_TAG                 'tRgW'      /* 保护器池标签 */

#define WKD_RG_MAX_REG_DATA_CAPTURE     4096        /* 值数据截断上限（SHADOWSTRIKE_MAX_REG_DATA_CAPTURE） */

/* 进程上下文行为标志位（RegThreatIndicator 高位保留区，一次性上报语义） */
#define WKD_RG_PROCCTX_FLAG_MULTI_SPRAY       0x80000000  /* 多持久化喷洒已上报 */
#define WKD_RG_PROCCTX_FLAG_DEFEVASION_COMBO  0x40000000  /* 防御规避+持久化组合已上报 */
#define WKD_RG_PROCCTX_FLAG_RANSOMWARE_PREP   0x20000000  /* 勒索准备模式已上报 */

/* ============================================================================
 * 注册表保护器结构（不透明句柄的定义）
 * ============================================================================ */

typedef struct _WKD_REGISTRY_PROTECTION {
    EX_SPIN_LOCK               KeyLock;                     /* 键列表保护（共享读/排他写） */
    WKD_RG_PROTECTED_KEY      Keys[WKD_RG_MAX_PROTECTED_KEYS];
    BOOLEAN                   Initialized;

    /* 引擎注入的豁免回调（查 AU：受保护进程自改自键放行） */
    WKD_RG_EXEMPT_CALLBACK    ExemptCallback;
    PVOID                     ExemptContext;

    /* === 检测/分析面（迁移自 ShadowStrike RegistryCallback，2026-09-08 增厚） === */
    /* 2026-09-09 架构重构：按进程行为上下文已并入 WKD_PROCESS.RegistryProfile
     * （ProcessMonitor.h，随进程退出统一回收），此处不再维护独立哈希表。 */

    /* 监控键哈希表（2026-09-09 架构重构：手写 64 桶 LIST_ENTRY 换用
     * Common/HashMap 全局推锁模式 + no-op 引用回调，上限 128 键对齐 SS，
     * 容量由 ActiveEntries 承载（无独立计数）） */
    WKD_HASH_MAP              MonitoredKeys;

    /* 统计与配置 */
    WKD_RG_STATISTICS         Statistics;
    WKD_RG_CONFIG             Config;
    EX_PUSH_LOCK              ConfigLock;

    /* 通知速率限制（NotificationCount/WindowStart） */
    volatile LONG64           NotificationCount;
    LARGE_INTEGER             NotificationWindowStart;
} WKD_REGISTRY_PROTECTION;

/* ============================================================================
 * ALLOC_PRAGMA
 * ============================================================================ */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, AcInitializeRegistryProtection)
#pragma alloc_text(PAGE, RgpShutdown)
#pragma alloc_text(PAGE, RgpProtectKey)
#pragma alloc_text(PAGE, RgpUnprotectKey)
#pragma alloc_text(PAGE, RgpShouldBlockRegistryAccess)
#pragma alloc_text(PAGE, RgpClassifyRegistryKey)
#pragma alloc_text(PAGE, RgpAnalyzeRegistryPersistence)
#pragma alloc_text(PAGE, RgpDetectRansomwareRegistryBehavior)
#pragma alloc_text(PAGE, RgpDetectDefenseEvasionRegistry)
#pragma alloc_text(PAGE, RgpAnalyzeRegistryAccess)
#pragma alloc_text(PAGE, AcRegisterProtectedRegistryKey)
#pragma alloc_text(PAGE, AcpUnregisterProtectedRegistryKey)
#pragma alloc_text(PAGE, RgpUpdateRegistryConfig)
#pragma alloc_text(PAGE, RgpResetRegistryStatistics)
#endif

/* 前向声明：RgpReportDetection 定义位于本文件后部，而 RgpAnalyzeRegistryPersistence
 * （定义在前）即调用之，故在此前置 static 声明（项目"内部函数不前置声明"约定在此让位）。 */
static
VOID
RgpReportDetection(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ ULONG SubType,
    _In_ ULONG Severity,
    _In_ HANDLE ProcessId,
    _In_ PCWSTR Description
    );

/*++
    Routine Description:
        安全读取 DWORD 值（带异常保护，捕获 CM 传递的数据缓冲）。

    Arguments:
        Data     — 数据缓冲。
        DataSize — 数据大小（字节）。
        Value    — 输出 DWORD。

    Returns:
        TRUE — 读取成功；FALSE — 数据不足或访问异常。
--*/
static
BOOLEAN
RgpTryReadDwordValue(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PULONG Value
    )
{
    ULONG localValue;

    if (Data == NULL || Value == NULL || DataSize < sizeof(ULONG)) {
        return FALSE;
    }

    __try {
        localValue = *(volatile ULONG*)Data;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    *Value = localValue;
    return TRUE;
}

/*++
    Routine Description:
        判断服务 Start 值是否被置为禁用（=4），RegpIsServiceDisabledStartValue。

    Arguments:
        ValueName — 值名。
        Data      — 值数据。
        DataSize  — 数据大小。

    Returns:
        TRUE — Start=4（禁用）；FALSE — 其他。
--*/
static
BOOLEAN
RgpIsServiceDisabledStartValue(
    _In_opt_ PCUNICODE_STRING ValueName,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize
    )
{
    UNICODE_STRING startValue;
    ULONG dwordValue;

    if (ValueName == NULL || ValueName->Buffer == NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&startValue, L"Start");
    if (!RtlEqualUnicodeString(ValueName, &startValue, TRUE)) {
        return FALSE;
    }

    return RgpTryReadDwordValue(Data, DataSize, &dwordValue) && dwordValue == 4;
}

/*++
    Routine Description:
        REG_NOTIFY_CLASS 到内部操作枚举映射（RegpNotifyClassToOperation）。

    Arguments:
        NotifyClass — CM 通知类。

    Returns:
        内部操作枚举；未知返回 WkdRgOpNone。
--*/
static
WKD_RG_REG_OPERATION
RgpNotifyClassToOperation(
    _In_ REG_NOTIFY_CLASS NotifyClass
    )
{
    switch (NotifyClass) {
        case RegNtPreCreateKey:
        case RegNtPreCreateKeyEx:
            return WkdRgOpCreateKey;
        case RegNtPreOpenKey:
        case RegNtPreOpenKeyEx:
            return WkdRgOpOpenKey;
        case RegNtPreDeleteKey:
            return WkdRgOpDeleteKey;
        case RegNtPreRenameKey:
            return WkdRgOpRenameKey;
        case RegNtPreSetValueKey:
            return WkdRgOpSetValue;
        case RegNtPreDeleteValueKey:
            return WkdRgOpDeleteValue;
        case RegNtPreQueryValueKey:
            return WkdRgOpQueryValue;
        case RegNtPreEnumerateKey:
            return WkdRgOpEnumerateKey;
        case RegNtPreEnumerateValueKey:
            return WkdRgOpEnumerateValue;
        case RegNtPreQueryKey:
            return WkdRgOpQueryKey;
        case RegNtPreSetKeySecurity:
            return WkdRgOpSetKeySecurity;
        default:
            return WkdRgOpNone;
    }
}

/*++
    Routine Description:
        通知速率限制检查（RegpCheckRateLimit，基于 KeQuerySystemTime
        滑动窗口 + InterlockedCompareExchange64 无锁重置）。

    Arguments:
        Protector — 保护器句柄。

    Returns:
        TRUE — 允许发送通知；FALSE — 被限速丢弃。
--*/
static
BOOLEAN
RgpCheckRateLimit(
    _In_ PWKD_REGISTRY_PROTECTION Protector
    )
{
    LARGE_INTEGER currentTime;
    LONG64 windowStart;
    LONG64 elapsed;
    LONG64 count;

    if (Protector == NULL) {
        return FALSE;
    }

    KeQuerySystemTime(&currentTime);

    windowStart = ReadNoFence64(
        (volatile LONG64*)&Protector->NotificationWindowStart.QuadPart);
    elapsed = currentTime.QuadPart - windowStart;

    if (elapsed > (1000 * 10000LL)) {
        /* 新窗口 — 尝试原子重置；CAS 竞争失败的线程正常计数 */
        if (InterlockedCompareExchange64(
                (volatile LONG64*)&Protector->NotificationWindowStart.QuadPart,
                currentTime.QuadPart,
                windowStart) == windowStart) {
            InterlockedExchange64(&Protector->NotificationCount, 1);
            return TRUE;
        }
    }

    count = InterlockedIncrement64(&Protector->NotificationCount);

    if (count > Protector->Config.NotificationRateLimitPerSec) {
        InterlockedIncrement64(&Protector->Statistics.NotificationsDropped);
        return FALSE;
    }

    return TRUE;
}

/* ============================================================================
 * 键路径分类（ShadowStrikeClassifyRegistryKey L1003-1205）
 * ============================================================================ */

/*++
    Routine Description:
        将键路径分类为持久化/安全/服务/证书等类别位图（WKD_RG_REG_FLAGS）。

        分类覆盖（MITRE ATT&CK）：
        - T1547.001 Run/RunOnce（HKLM + HKCU SID 解析）
        - T1543.003 Services（CurrentControlSet + ControlSet001）
        - T1546.012 IFEO / AppInit / Winlogon
        - T1546.015 COM（CLSID）/ 计划任务
        - T1562.001 Defender / T1562.004 防火墙 / 安全中心 / Policies
        - T1490 VSS/wbengine（勒索指示）
        - T1553.004 根证书/AuthRoot
        - 驱动自身自保护键（服务键 + 软件键）

    Arguments:
        KeyPath — 完整键路径。

    Returns:
        WKD_RG_REG_FLAGS 位图；无效输入返回 WkdRgFlagNone。
--*/
_Use_decl_annotations_
ULONG
RgpClassifyRegistryKey(
    _In_ PCUNICODE_STRING KeyPath
    )
{
    ULONG flags = WkdRgFlagNone;
    UNICODE_STRING testPath;

    if (KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0) {
        return WkdRgFlagNone;
    }

    /* Run Keys — HKLM (T1547.001) */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_RUN_KEY);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagRunKey | WkdRgFlagPersistenceKey;
    }

    RtlInitUnicodeString(&testPath, WKD_RG_PATH_RUNONCE_KEY);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagRunKey | WkdRgFlagPersistenceKey;
    }

    RtlInitUnicodeString(&testPath, WKD_RG_PATH_RUNONCEEX_KEY);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagRunKey | WkdRgFlagPersistenceKey;
    }

    /* Run Keys — HKCU (T1547.001)：用户配置单元 \REGISTRY\USER\<SID>\...Run */
    {
        static const UNICODE_STRING UserHivePrefix = RTL_CONSTANT_STRING(WKD_RG_PATH_USER_HIVE_PREFIX);
        if (RtlPrefixUnicodeString(&UserHivePrefix, KeyPath, TRUE)) {
            /* 跳过 \REGISTRY\USER\ 与 SID 组件，找其后第一个反斜杠 */
            USHORT prefixChars = UserHivePrefix.Length / sizeof(WCHAR);
            USHORT pathChars = KeyPath->Length / sizeof(WCHAR);
            USHORT sidEnd = prefixChars;

            while (sidEnd < pathChars && KeyPath->Buffer[sidEnd] != L'\\') {
                sidEnd++;
            }

            if (sidEnd < pathChars) {
                UNICODE_STRING remainder;
                remainder.Buffer = &KeyPath->Buffer[sidEnd];
                remainder.Length = (pathChars - sidEnd) * sizeof(WCHAR);
                remainder.MaximumLength = remainder.Length;

                RtlInitUnicodeString(&testPath, L"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
                if (RtlPrefixUnicodeString(&testPath, &remainder, TRUE)) {
                    flags |= WkdRgFlagRunKey | WkdRgFlagPersistenceKey;
                }

                RtlInitUnicodeString(&testPath, L"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
                if (RtlPrefixUnicodeString(&testPath, &remainder, TRUE)) {
                    flags |= WkdRgFlagRunKey | WkdRgFlagPersistenceKey;
                }
            }
        }
    }

    /* Services (T1543.003) */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_SERVICES);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagServiceKey | WkdRgFlagPersistenceKey;
    }

    RtlInitUnicodeString(&testPath, WKD_RG_PATH_SERVICES_ALT);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagServiceKey | WkdRgFlagPersistenceKey;
    }

    /* IFEO (T1546.012) */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_IFEO);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagIFEOKey | WkdRgFlagPersistenceKey | WkdRgFlagHighRisk;
    }

    /* AppInit_DLLs */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_APPINIT);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagAppInitKey | WkdRgFlagPersistenceKey | WkdRgFlagHighRisk;
    }

    /* Winlogon */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_WINLOGON);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagWinlogonKey | WkdRgFlagPersistenceKey;
    }

    /* COM 对象 (T1546.015) */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_CLSID);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagCOMKey | WkdRgFlagPersistenceKey;
    }

    /* 计划任务 */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_SCHEDULED_TASKS);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagScheduledTaskKey | WkdRgFlagPersistenceKey;
    }

    /* Windows Defender (T1562.001) */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_WINDOWS_DEFENDER);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagDefenderKey | WkdRgFlagSecurityKey;
    }

    /* 安全中心 */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_SECURITY_CENTER);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagSecurityKey;
    }

    /* 防火墙 (T1562.004) */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_FIREWALL);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagFirewallKey | WkdRgFlagSecurityKey;
    }

    /* VSS / 备份服务 (T1490) */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_VSS_ADMIN);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagVSSKey | WkdRgFlagSecurityKey;
    }

    RtlInitUnicodeString(&testPath, WKD_RG_PATH_WBENGINE);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagVSSKey | WkdRgFlagSecurityKey;
    }

    /* 证书存储 (T1553.004) */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_ROOT_CERTS);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagCertificateKey | WkdRgFlagSecurityKey | WkdRgFlagHighRisk;
    }

    RtlInitUnicodeString(&testPath, WKD_RG_PATH_AUTH_ROOT);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagCertificateKey | WkdRgFlagSecurityKey | WkdRgFlagHighRisk;
    }

    /* 策略 */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_POLICIES);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagSecurityKey;
    }

    /* 自保护键（驱动自身服务/软件键） */
    RtlInitUnicodeString(&testPath, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WkDefender@driver");
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagProtectedKey;
    }

    RtlInitUnicodeString(&testPath, L"\\REGISTRY\\MACHINE\\SOFTWARE\\WkDefender");
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        flags |= WkdRgFlagProtectedKey;
    }

    return flags;
}

/* ============================================================================
 * 勒索行为检测（ShadowStrikeDetectRansomwareRegistryBehavior L1239-1320）
 * ============================================================================ */

/*++
    Routine Description:
        检视 VSS/wbengine/SystemRestore/Backup Exec 路径上的恢复销毁或服务
        禁用行为（T1490 Inhibit System Recovery）。

        仅在写类操作（SetValue/DeleteKey/DeleteValue）上判定；正常 Windows
        启动对 Services\VSS 与 Services\wbengine 的维护写入不算勒索准备。

    Arguments:
        KeyPath   — 完整键路径。
        ValueName — 值名（可选）。
        Operation — 内部操作枚举。
        Data      — 值数据（可选）。
        DataSize  — 数据大小。

    Returns:
        TRUE — 命中勒索指示器；FALSE — 非勒索行为。
--*/
_Use_decl_annotations_
BOOLEAN
RgpDetectRansomwareRegistryBehavior(
    _In_ PCUNICODE_STRING KeyPath,
    _In_opt_ PCUNICODE_STRING ValueName,
    _In_ WKD_RG_REG_OPERATION Operation,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize
    )
{
    UNICODE_STRING testPath;
    UNICODE_STRING systemRestorePath;
    UNICODE_STRING disableSrValue;
    UNICODE_STRING disableConfigValue;
    BOOLEAN isRansomwareIndicator = FALSE;

    PAGED_CODE();

    if (KeyPath == NULL || KeyPath->Buffer == NULL) {
        return FALSE;
    }

    if (Operation != WkdRgOpSetValue &&
        Operation != WkdRgOpDeleteKey &&
        Operation != WkdRgOpDeleteValue) {
        return FALSE;
    }

    RtlInitUnicodeString(&testPath, WKD_RG_PATH_VSS_ADMIN);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        if (Operation == WkdRgOpDeleteKey || Operation == WkdRgOpDeleteValue) {
            isRansomwareIndicator = TRUE;
        } else if (RgpIsServiceDisabledStartValue(ValueName, (PVOID)Data, DataSize)) {
            isRansomwareIndicator = TRUE;
        }
    }

    RtlInitUnicodeString(&testPath, WKD_RG_PATH_WBENGINE);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        if (Operation == WkdRgOpDeleteKey || Operation == WkdRgOpDeleteValue) {
            isRansomwareIndicator = TRUE;
        } else if (RgpIsServiceDisabledStartValue(ValueName, (PVOID)Data, DataSize)) {
            isRansomwareIndicator = TRUE;
        }
    }

    RtlInitUnicodeString(&systemRestorePath, WKD_RG_PATH_SYSTEM_RESTORE);
    if (RtlPrefixUnicodeString(&systemRestorePath, KeyPath, TRUE) &&
        Operation == WkdRgOpSetValue &&
        ValueName != NULL) {
        ULONG dwordValue;

        RtlInitUnicodeString(&disableSrValue, L"DisableSR");
        RtlInitUnicodeString(&disableConfigValue, L"DisableConfig");

        if ((RtlEqualUnicodeString(ValueName, &disableSrValue, TRUE) ||
             RtlEqualUnicodeString(ValueName, &disableConfigValue, TRUE)) &&
            RgpTryReadDwordValue((PVOID)Data, DataSize, &dwordValue) &&
            dwordValue != 0) {
            isRansomwareIndicator = TRUE;
        }
    }

    RtlInitUnicodeString(&testPath, WKD_RG_PATH_BACKUP_EXEC);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        if (Operation == WkdRgOpDeleteKey || Operation == WkdRgOpDeleteValue) {
            isRansomwareIndicator = TRUE;
        }
    }

    return isRansomwareIndicator;
}

/* ============================================================================
 * 防御规避检测（ShadowStrikeDetectDefenseEvasionRegistry L1326-1470）
 * ============================================================================ */

/*++
    Routine Description:
        检视 Defender 禁用值（DisableAntiSpyware/DisableRealtimeMonitoring/
        DisableBehaviorMonitoring/DisableIOAVProtection/DisableScriptScanning）
        与 SecurityCenter/Firewall/Policies 篡改（T1562 Impair Defenses）。

        Defender：仅当值被置为非零（禁用防护）时标记；置 0 为重新启用（良性）。
        SecurityCenter/Firewall/Policies：任何写访问均标记防御规避。

    Arguments:
        KeyPath   — 完整键路径。
        ValueName — 值名（可选）。
        Data      — 值数据（可选）。
        DataSize  — 数据大小。

    Returns:
        WKD_RG_THREAT_INDICATOR 位图；未命中返回 WkdRgThreatNone。
--*/
_Use_decl_annotations_
ULONG
RgpDetectDefenseEvasionRegistry(
    _In_ PCUNICODE_STRING KeyPath,
    _In_opt_ PCUNICODE_STRING ValueName,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize
    )
{
    UNICODE_STRING testPath;
    UNICODE_STRING disableValue;
    ULONG threatIndicators = WkdRgThreatNone;
    ULONG dwordValue;

    PAGED_CODE();

    if (KeyPath == NULL || KeyPath->Buffer == NULL) {
        return WkdRgThreatNone;
    }

    /* Windows Defender 篡改 */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_WINDOWS_DEFENDER);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {

        if (ValueName != NULL) {
            RtlInitUnicodeString(&disableValue, L"DisableAntiSpyware");
            if (RtlEqualUnicodeString(ValueName, &disableValue, TRUE)) {
                if (Data != NULL && DataSize >= sizeof(ULONG)) {
                    __try {
                        dwordValue = *(volatile ULONG*)Data;
                        if (dwordValue != 0) {
                            threatIndicators |= WkdRgThreatDefenseEvasion | WkdRgThreatTampering;
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        threatIndicators |= WkdRgThreatDefenseEvasion | WkdRgThreatTampering;
                    }
                } else {
                    threatIndicators |= WkdRgThreatDefenseEvasion | WkdRgThreatTampering;
                }
            }

            RtlInitUnicodeString(&disableValue, L"DisableRealtimeMonitoring");
            if (RtlEqualUnicodeString(ValueName, &disableValue, TRUE)) {
                if (Data != NULL && DataSize >= sizeof(ULONG)) {
                    __try {
                        dwordValue = *(volatile ULONG*)Data;
                        if (dwordValue != 0) {
                            threatIndicators |= WkdRgThreatDefenseEvasion | WkdRgThreatTampering;
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        threatIndicators |= WkdRgThreatDefenseEvasion | WkdRgThreatTampering;
                    }
                } else {
                    threatIndicators |= WkdRgThreatDefenseEvasion | WkdRgThreatTampering;
                }
            }

            RtlInitUnicodeString(&disableValue, L"DisableBehaviorMonitoring");
            if (RtlEqualUnicodeString(ValueName, &disableValue, TRUE)) {
                if (Data != NULL && DataSize >= sizeof(ULONG)) {
                    __try {
                        dwordValue = *(volatile ULONG*)Data;
                        if (dwordValue != 0) {
                            threatIndicators |= WkdRgThreatDefenseEvasion | WkdRgThreatTampering;
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        threatIndicators |= WkdRgThreatDefenseEvasion | WkdRgThreatTampering;
                    }
                } else {
                    threatIndicators |= WkdRgThreatDefenseEvasion | WkdRgThreatTampering;
                }
            }

            RtlInitUnicodeString(&disableValue, L"DisableIOAVProtection");
            if (RtlEqualUnicodeString(ValueName, &disableValue, TRUE)) {
                if (Data != NULL && DataSize >= sizeof(ULONG)) {
                    __try {
                        dwordValue = *(volatile ULONG*)Data;
                        if (dwordValue != 0) {
                            threatIndicators |= WkdRgThreatDefenseEvasion | WkdRgThreatTampering;
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        threatIndicators |= WkdRgThreatDefenseEvasion | WkdRgThreatTampering;
                    }
                } else {
                    threatIndicators |= WkdRgThreatDefenseEvasion | WkdRgThreatTampering;
                }
            }

            RtlInitUnicodeString(&disableValue, L"DisableScriptScanning");
            if (RtlEqualUnicodeString(ValueName, &disableValue, TRUE)) {
                if (Data != NULL && DataSize >= sizeof(ULONG)) {
                    __try {
                        dwordValue = *(volatile ULONG*)Data;
                        if (dwordValue != 0) {
                            threatIndicators |= WkdRgThreatDefenseEvasion | WkdRgThreatTampering;
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        threatIndicators |= WkdRgThreatDefenseEvasion | WkdRgThreatTampering;
                    }
                } else {
                    threatIndicators |= WkdRgThreatDefenseEvasion | WkdRgThreatTampering;
                }
            }
        }
    }

    /* 安全中心篡改 */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_SECURITY_CENTER);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        threatIndicators |= WkdRgThreatDefenseEvasion;
    }

    /* 防火墙篡改 */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_FIREWALL);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        threatIndicators |= WkdRgThreatDefenseEvasion;
    }

    /* 策略篡改 */
    RtlInitUnicodeString(&testPath, WKD_RG_PATH_POLICIES);
    if (RtlPrefixUnicodeString(&testPath, KeyPath, TRUE)) {
        threatIndicators |= WkdRgThreatDefenseEvasion;
    }

    return threatIndicators;
}

/* ============================================================================
 * 持久化机制分析（ShadowStrikeAnalyzeRegistryPersistence L1576-1746）
 * ============================================================================ */

/*++
    Routine Description:
        对注册表写操作分类并判定持久化/防御规避/证书/勒索威胁指示。

        平台差异适配：SS 在命中时提交 BehaviorEngine（BeEngineSubmitEvent）/
        威胁评分（TsAddFactor）/遥测日志（TeLogRegistryEvent）/Batch 通知；
        WkD 无这些子系统，统一收敛为 RgpReportDetection（0x5035 段事件上报
        + 统计计数），供 Agent 侧消费。速率限制沿用 SS 语义。

    Arguments:
        Protector   — 保护器句柄。
        ProcessId   — 写入者进程（CM 回调 RequestorProcessId），透传给
                      RgpReportDetection 评分联动定位进程对 Source。
        RegistryPath — 完整键路径。
        ValueName   — 值名。
        Data        — 值数据（可选）。
        DataSize    — 数据大小。
        DataType    — 数据类型（REG_*）。

    Returns:
        无。
--*/
_Use_decl_annotations_
VOID
RgpAnalyzeRegistryPersistence(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PUNICODE_STRING ValueName,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize,
    _In_ ULONG DataType
    )
{
    ULONG keyFlags;
    ULONG threatIndicators = WkdRgThreatNone;
    BOOLEAN shouldNotify = FALSE;
    ULONG captureSize;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized ||
        RegistryPath == NULL || RegistryPath->Buffer == NULL) {
        return;
    }

    /* 分类 */
    keyFlags = RgpClassifyRegistryKey(RegistryPath);

    /* 持久化指示 */
    if (keyFlags & WkdRgFlagPersistenceKey) {
        threatIndicators |= WkdRgThreatPersistence;
        shouldNotify = TRUE;
        InterlockedIncrement64(&Protector->Statistics.PersistenceDetections);

        if (keyFlags & WkdRgFlagRunKey) {
            InterlockedIncrement64(&Protector->Statistics.RunKeyModifications);
        }
        if (keyFlags & WkdRgFlagServiceKey) {
            InterlockedIncrement64(&Protector->Statistics.ServiceCreations);
        }
        if (keyFlags & WkdRgFlagIFEOKey) {
            InterlockedIncrement64(&Protector->Statistics.IFEOModifications);
        }
    }

    /* 安全相关修改 */
    if (keyFlags & WkdRgFlagSecurityKey) {
        threatIndicators |= RgpDetectDefenseEvasionRegistry(
            RegistryPath,
            ValueName,
            Data,
            DataSize
            );
        shouldNotify = TRUE;
    }

    /* 证书修改 */
    if (keyFlags & WkdRgFlagCertificateKey) {
        threatIndicators |= WkdRgThreatPrivilegeEsc;
        shouldNotify = TRUE;
        InterlockedIncrement64(&Protector->Statistics.CertificateStoreChanges);
    }

    /* 勒索行为 */
    if (RgpDetectRansomwareRegistryBehavior(
            RegistryPath, ValueName, WkdRgOpSetValue, Data, DataSize)) {
        threatIndicators |= WkdRgThreatRansomware;
        shouldNotify = TRUE;
        InterlockedIncrement64(&Protector->Statistics.RansomwareIndicators);
    }

    /* 命中：按主导威胁上报 0x5035-0x5038 段 */
    if (shouldNotify && threatIndicators != WkdRgThreatNone) {
        if (threatIndicators & WkdRgThreatRansomware) {
            RgpReportDetection(Protector, RG_EVENT_SUBTYPE_RANSOMWARE, 9, ProcessId,
                L"Registry: ransomware indicator (VSS/backup/restore tampering)");
        } else if (threatIndicators & WkdRgThreatPrivilegeEsc) {
            RgpReportDetection(Protector, RG_EVENT_SUBTYPE_CERTIFICATE, 8, ProcessId,
                L"Registry: certificate store modification (root/AuthRoot)");
        } else if (threatIndicators & WkdRgThreatDefenseEvasion) {
            RgpReportDetection(Protector, RG_EVENT_SUBTYPE_DEFENSE_EVASION, 8, ProcessId,
                L"Registry: defense evasion (Defender/firewall/policy tampering)");
        } else if (keyFlags & WkdRgFlagPersistenceKey) {
            RgpReportDetection(Protector, RG_EVENT_SUBTYPE_PERSISTENCE, 6, ProcessId,
                L"Registry: persistence mechanism modification (Run/Services/IFEO)");
        }

        /* 详细通知（带速率限制，DetailedNotificationsEnabled + RegpCheckRateLimit） */
        if (Protector->Config.DetailedNotificationsEnabled &&
            RgpCheckRateLimit(Protector)) {
            captureSize = DataSize;
            /* 描述缓冲（SendRegistryNotification 的详情语义，截断值数据） */
            {
                WCHAR descBuf[512];
                NTSTATUS s;

                if (captureSize > 128) {
                    captureSize = 128;   /* 仅取值数据开头用于诊断 */
                }

                s = RtlStringCchPrintfW(
                    descBuf, RTL_NUMBER_OF(descBuf),
                    L"Registry persistence/security: %wZ (PID=%lu, Type=%lu, DataSize=%lu)",
                    RegistryPath, HandleToULong(ProcessId),
                    DataType, captureSize);
                if (NT_SUCCESS(s)) {
                    RgpReportDetection(Protector,
                        RG_EVENT_SUBTYPE_PERSISTENCE, 6, ProcessId, descBuf);
                }
            }
        }
    }
}

/*++
    Routine Description:
        内部辅助：按子类型上报检测事件（0x5035 段）并累计统计。

    Arguments:
        Protector   — 保护器句柄。
        SubType     — 事件子类型。
        Severity    — 严重度（1-10）。
        ProcessId   — 触发进程（CM 回调 RequestorProcessId；评分联动进程对 Source）。
        Description — 描述。

    Returns:
        无。
--*/
static
VOID
RgpReportDetection(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ ULONG SubType,
    _In_ ULONG Severity,
    _In_ HANDLE ProcessId,
    _In_ PCWSTR Description
    )
{
    if (Protector == NULL) {
        return;
    }

    /* 2026-09-09 评分联动（方案 A）：
     * RG 告警 → 进程对 <写入者, Registry> → 评分链（TsIndicator_Ioa_SecurityEvent）。
     * Target 经 PsLookupWkdProcessByName(L"Registry") 定位系统自带 Registry
     * 进程（PmEnumerateProcesses 全量收录，快照方法按名匹配），显式表达
     * "进程 → 注册表子系统"交互语义；与 IocProcess/Filter 的"自我对 <pid,pid>"
     * 先例不同，此处 Target 为真实交互对象。
     * Severity 映射：0x5035 段严重级(6/8/9/10) → AE_THREAT_SEVERITY(2/3/4)，
     * TsAddFactor(85/80/95) 的 Critical/High/Medium 分档。
     * Registry 进程未收录/匹配失败时尽力而为跳过（返回 NULL 不注入）。
     */
    if (ProcessId != NULL) {
        PWKD_PROCESS registryProcess = PsLookupWkdProcessByName(L"Registry");
        if (registryProcess != NULL) {
            AE_THREAT_SEVERITY aeSeverity;

            if (Severity >= 9) {
                aeSeverity = AeThreatSeverityCritical;
            } else if (Severity >= 8) {
                aeSeverity = AeThreatSeverityHigh;
            } else {
                aeSeverity = AeThreatSeverityMedium;
            }

            (VOID)AeReportIndicatorPair(
                ProcessId,
                registryProcess->Core.ProcessId,
                TsSourceBehavioral,
                TsIndicator_Ioa_SecurityEvent,
                (UCHAR)aeSeverity);

            /* 配对释放（PsLookupWkdProcessByName 查找即 +1） */
            PsDereferenceWkdProcess(registryProcess);
        }
    }

    InterlockedIncrement64(&Protector->Statistics.NotificationsSent);

    (VOID)WkdReportSelfProtectionEvent(SubType, Severity, Description);

#if DBG
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "[WkDefender/RG] Detection (SubType=0x%04X, Sev=%lu): %ls\n",
        SubType, Severity, Description);
#endif
}

/* ============================================================================
 * 私有: 前缀匹配
 * ============================================================================ */

/*++
    Routine Description:
        判断 KeyPath 是否以存储的键前缀（KeyPath[]）开头（大小写不敏感）。

        对齐 ShadowStrike SspPrefixMatch：纯前缀匹配，不要求完全相等。

    Arguments:
        TestPath    — 待判定的完整键路径。
        Prefix      — 存储的键前缀（WCHAR[]）。
        PrefixCch   — 键前缀字符数。

    Returns:
        TRUE — TestPath 以 Prefix 开头；FALSE — 不匹配。
--*/
static
BOOLEAN
RgpPrefixMatch(
    _In_ PCUNICODE_STRING TestPath,
    _In_ PCWCH Prefix,
    _In_ USHORT PrefixCch
    )
{
    UNICODE_STRING prefixStr;
    UNICODE_STRING testPrefix;

    if (PrefixCch == 0) {
        return FALSE;
    }

    prefixStr.Buffer = (PWCH)Prefix;
    prefixStr.Length = PrefixCch * sizeof(WCHAR);
    prefixStr.MaximumLength = prefixStr.Length;

    if (TestPath->Length < prefixStr.Length) {
        return FALSE;
    }

    testPrefix.Buffer = TestPath->Buffer;
    testPrefix.Length = prefixStr.Length;
    testPrefix.MaximumLength = prefixStr.Length;

    return (RtlCompareUnicodeString(&testPrefix, &prefixStr, TRUE) == 0);
}

/* ============================================================================
 * 私有: 键前缀匹配判定
 * ============================================================================ */

/*++
    Routine Description:
        判断 KeyPath 是否命中受保护键列表（前缀匹配）。

    Arguments:
        KeyPath — 待判定的完整键路径。

    Returns:
        TRUE — 命中受保护键前缀；FALSE — 未命中。
--*/
_IRQL_requires_(PASSIVE_LEVEL)
static
BOOLEAN
RgpIsKeyProtected(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCUNICODE_STRING KeyPath
    )
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN isProtected = FALSE;

    if (Protector == NULL || !Protector->Initialized ||
        KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0) {
        return FALSE;
    }

    oldIrql = ExAcquireSpinLockShared(&Protector->KeyLock);

    for (i = 0; i < WKD_RG_MAX_PROTECTED_KEYS; i++) {
        if (Protector->Keys[i].InUse) {
            if (RgpPrefixMatch(KeyPath,
                               Protector->Keys[i].KeyPath,
                               Protector->Keys[i].KeyPathLength)) {
                isProtected = TRUE;
                break;
            }
        }
    }

    ExReleaseSpinLockShared(&Protector->KeyLock, oldIrql);

    return isProtected;
}

/* ============================================================================
 * 私有: 事件子类型映射与上报
 * ============================================================================ */

/*++
    Routine Description:
        将 REG_NOTIFY_CLASS 映射到 0x5030 段事件子类型。

    Arguments:
        Operation — REG_NOTIFY_CLASS。

    Returns:
        对应事件子类型；未知操作返回 0。
--*/
static
ULONG
RgpOperationToEventSubtype(
    _In_ REG_NOTIFY_CLASS Operation
    )
{
    switch (Operation) {
        case RegNtPreDeleteKey:      return RG_EVENT_SUBTYPE_DELETE_KEY;
        case RegNtPreSetValueKey:    return RG_EVENT_SUBTYPE_SET_VALUE;
        case RegNtPreDeleteValueKey: return RG_EVENT_SUBTYPE_DELETE_VALUE;
        case RegNtPreRenameKey:      return RG_EVENT_SUBTYPE_RENAME_KEY;
        case RegNtPreSetKeySecurity: return RG_EVENT_SUBTYPE_SET_SECURITY;
        default:                     return 0;
    }
}

/* ============================================================================
 * 公共 API
 * ============================================================================ */

/*++
    Routine Description:
        分配并初始化注册表保护器，注入豁免回调。

        豁免回调由引擎提供（Context = Engine），2026-09-05 起受保护判定
        收敛为 Pap 画像（PapProfile 非零），使受保护进程自改自键放行。

    Arguments:
        Protector      — 输出保护器句柄。
        ExemptCallback — 豁免判定回调（引擎注入）。
        Context        — 豁免回调上下文（Engine）。

    Returns:
        STATUS_SUCCESS / STATUS_NO_MEMORY / STATUS_INVALID_PARAMETER。
--*/
_Use_decl_annotations_
NTSTATUS
AcInitializeRegistryProtection(
    _Out_ PWKD_REGISTRY_PROTECTION* Protector,
    _In_ const WKD_RG_EXEMPT_CALLBACK ExemptCallback,
    _In_opt_ const PVOID Context
    )
{
    PWKD_REGISTRY_PROTECTION protector;
    NTSTATUS status;

    PAGED_CODE();

    if (!Protector || !ExemptCallback) {
        return STATUS_INVALID_PARAMETER;
    }
    *Protector = NULL;

    protector = (PWKD_REGISTRY_PROTECTION)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(WKD_REGISTRY_PROTECTION),
        WKD_RG_POOL_TAG
    );
    if (!protector) return STATUS_NO_MEMORY;

    KeInitializeSpinLock(&protector->KeyLock);
    protector->ExemptCallback = ExemptCallback;
    protector->ExemptContext = Context;

    /* 初始化监控键哈希表（2026-09-09 架构重构：换用 Common/HashMap 全局推锁
     * 模式，纯值语义 no-op 引用回调；沿 CoInitializeHashMap 的 PASSIVE_LEVEL 约束） */
    status = CoInitializeHashMap(
        &protector->MonitoredKeys,
        AC_REG_MAX_PROTECTED_KEYS,          /* 桶数：直接取监控键上限，规避扩桶 */
        FALSE,                              /* PerBucketLock = FALSE：全局推锁 */
        CoHashMapNoopReference,             /* 纯值语义，无引用计数 */
        NULL,                               /* ShouldRemove：无存活裁决 */
        CoHashMapNoopDereference
        );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(protector, WKD_RG_POOL_TAG);
        return status;
    }

    /* 配置锁 + 默认配置（默认值） */
    ExInitializePushLock(&protector->ConfigLock);
    protector->Config.Enabled = TRUE;
    protector->Config.SelfProtectionEnabled = TRUE;
    protector->Config.PersistenceMonitoringEnabled = TRUE;
    protector->Config.SecurityPolicyMonitoringEnabled = TRUE;
    protector->Config.ServiceMonitoringEnabled = TRUE;
    protector->Config.CertificateMonitoringEnabled = TRUE;
    protector->Config.DetailedNotificationsEnabled = TRUE;
    protector->Config.BlockHighRiskOperations = FALSE;
    protector->Config.MinBlockScore = 80;
    protector->Config.PersistenceAlertScore = 50;
    protector->Config.AnalysisTimeoutMs = 1000;
    protector->Config.NotificationRateLimitPerSec = 100;   /* REG_NOTIFICATION_RATE_LIMIT */

    /* 统计时间戳 + 速率限制窗口 */
    KeQuerySystemTime(&protector->Statistics.StartTime);
    KeQuerySystemTime(&protector->NotificationWindowStart);

    protector->Initialized = TRUE;

    *Protector = protector;
    return STATUS_SUCCESS;
}

/*++
    Routine Description:
        释放注册表保护器。

        调用前提：CM 回调节点已注销（Callbacks/RegistryCallback.c 的
        CbShutdownRegistryNotify 已执行），无并发 RgpShouldBlockRegistryAccess 进入。

    Arguments:
        Protector — 保护器句柄（NULL 安全）。

    Returns:
        无。
--*/
_Use_decl_annotations_
VOID
RgpShutdown(
    _Inout_ PWKD_REGISTRY_PROTECTION Protector
    )
{
    if (Protector == NULL) {
        return;
    }

    Protector->Initialized = FALSE;

    /* 释放监控键哈希表（2026-09-09 架构重构：CoFreeHashMap 自动释放
     * 键副本与条目节点；进程行为上下文随 WKD_PROCESS 由 ProcessMonitor
     * 统一回收，此处不再清理） */
    CoFreeHashMap(&Protector->MonitoredKeys);

    ExFreePoolWithTag(Protector, WKD_RG_POOL_TAG);
}

/*++
    Routine Description:
        保护一个注册表键/键前缀（前缀匹配生效）。

        在静态数组中找到第一个空闲槽位填充。重复保护同一前缀返回
        STATUS_OBJECT_NAME_EXISTS。

    Arguments:
        Protector — 保护器句柄。
        KeyPath   — 待保护键路径（宽字符串，最大 511 字符）。

    Returns:
        STATUS_SUCCESS / STATUS_OBJECT_NAME_EXISTS / STATUS_INSUFFICIENT_RESOURCES
        / STATUS_INVALID_PARAMETER / STATUS_NO_MEMORY。
--*/
_Use_decl_annotations_
NTSTATUS
RgpProtectKey(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCWSTR KeyPath
    )
{
    SIZE_T pathLen = 0;
    KIRQL oldIrql;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    ULONG i;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized || KeyPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 安全测量长度（含 NUL），上限 WKD_RG_MAX_KEY_PATH_LEN */
    status = RtlStringCchLengthW(KeyPath, MAX_PATH, (size_t*)&pathLen);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* pathLen 为字符数（不含 NUL） */

    oldIrql = ExAcquireSpinLockExclusive(&Protector->KeyLock);

    /* 判重：相同前缀已保护 */
    for (i = 0; i < WKD_RG_MAX_PROTECTED_KEYS; i++) {
        if (Protector->Keys[i].InUse &&
            Protector->Keys[i].KeyPathLength == (USHORT)pathLen &&
            RtlCompareMemory(Protector->Keys[i].KeyPath, KeyPath,
                             pathLen * sizeof(WCHAR)) == pathLen * sizeof(WCHAR)) {
            ExReleaseSpinLockExclusive(&Protector->KeyLock, oldIrql);
            return STATUS_OBJECT_NAME_EXISTS;
        }
    }

    /* 找空闲槽位 */
    for (i = 0; i < WKD_RG_MAX_PROTECTED_KEYS; i++) {
        if (!Protector->Keys[i].InUse) {
            Protector->Keys[i].KeyPathLength = (USHORT)pathLen;
            RtlCopyMemory(Protector->Keys[i].KeyPath, KeyPath, pathLen * sizeof(WCHAR));
            Protector->Keys[i].KeyPath[pathLen] = L'\0';
            Protector->Keys[i].InUse = TRUE;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleaseSpinLockExclusive(&Protector->KeyLock, oldIrql);

    return status;
}

/*++
    Routine Description:
        注销对一个注册表键/键前缀的保护。

    Arguments:
        Protector — 保护器句柄。
        KeyPath   — 注销保护的键路径。

    Returns:
        无。
--*/
_Use_decl_annotations_
VOID
RgpUnprotectKey(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCWSTR KeyPath
    )
{
    SIZE_T pathLen = 0;
    KIRQL oldIrql;
    NTSTATUS status;
    ULONG i;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized || KeyPath == NULL) {
        return;
    }

    status = RtlStringCchLengthW(KeyPath, MAX_PATH, (size_t*)&pathLen);
    if (!NT_SUCCESS(status)) {
        return;
    }

    oldIrql = ExAcquireSpinLockExclusive(&Protector->KeyLock);

    for (i = 0; i < WKD_RG_MAX_PROTECTED_KEYS; i++) {
        if (Protector->Keys[i].InUse &&
            Protector->Keys[i].KeyPathLength == (USHORT)pathLen &&
            RtlCompareMemory(Protector->Keys[i].KeyPath, KeyPath,
                             pathLen * sizeof(WCHAR)) == pathLen * sizeof(WCHAR)) {
            RtlZeroMemory(&Protector->Keys[i], sizeof(Protector->Keys[i]));
            break;
        }
    }

    ExReleaseSpinLockExclusive(&Protector->KeyLock, oldIrql);
}

/*++
    Routine Description:
        判定是否应 BLOCK 对路径的注册表操作。

        由 CM 回调节点（RegistryCallback.c）经引擎公共入口
        SpEngineShouldBlockRegistryAccess 转调。决策链：
          1. 豁免回调（引擎注入，查 AU：受保护进程自改自键放行）
          2. 键前缀匹配（RgpIsKeyProtected）
          3. 危险操作过滤（DeleteKey/SetValue/DeleteValue/Rename/SetSecurity；
             注：CreateKeyEx 不拦截——新键创建后可被后续操作拦截）
          4. 命中则计数 + 按操作上报 0x5030 段，返回 TRUE

    Arguments:
        Protector        — 保护器句柄。
        KeyPath          — 受操作键完整路径。
        Operation        — REG_NOTIFY_CLASS 操作类型。
        RequestorProcessId — 发起请求的进程 PID。

    Returns:
        TRUE — 应 BLOCK（调用方返回 STATUS_ACCESS_DENIED）；
        FALSE — 放行。
--*/
_Use_decl_annotations_
BOOLEAN
RgpShouldBlockRegistryAccess(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCUNICODE_STRING KeyPath,
    _In_ REG_NOTIFY_CLASS Operation,
    _In_ HANDLE RequestorProcessId
    )
{
    ULONG eventSubtype;

    if (Protector == NULL || !Protector->Initialized ||
        KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0) {
        return FALSE;
    }

    /* 1. 豁免：受保护进程自改自键放行 */
    if (Protector->ExemptCallback != NULL &&
        Protector->ExemptCallback(RequestorProcessId, Protector->ExemptContext)) {
        return FALSE;
    }

    /* 2. 键前缀匹配 */
    if (!RgpIsKeyProtected(Protector, KeyPath)) {
        return FALSE;
    }

    /* 3. 危险操作过滤 */
    switch (Operation) {
        case RegNtPreDeleteKey:
        case RegNtPreSetValueKey:
        case RegNtPreDeleteValueKey:
        case RegNtPreRenameKey:
        case RegNtPreSetKeySecurity:
            break;
        default:
            /* RegNtPreCreateKeyEx 等不拦截 */
            return FALSE;
    }

    /* 4. 命中：上报 0x5030 段事件 */
    eventSubtype = RgpOperationToEventSubtype(Operation);
    if (eventSubtype != 0) {
        (VOID)WkdReportSelfProtectionEvent(
            eventSubtype,
            7,   /* Severity */
            L"Blocked registry change to protected key"
            );
    }

    return TRUE;
}

/* ============================================================================
 * 统计快照与重置（ShadowStrikeGetRegistryStatistics / Reset，L2668-2740）
 * ============================================================================ */

/*++
    Routine Description:
        原子快照统计。每个 LONG64 计数器用 ReadNoFence64（单次 8 字节对齐读）
        读取，避免与并发 InterlockedIncrement64 生产者竞争产生撕裂读
        （的安全性说明）。

    Arguments:
        Protector  — 保护器句柄。
        Statistics — 输出快照。

    Returns:
        无。
--*/
_Use_decl_annotations_
VOID
RgpGetRegistryStatistics(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _Out_ PWKD_RG_STATISTICS Statistics
    )
{
    PWKD_RG_STATISTICS s;

    if (Protector == NULL || Statistics == NULL) {
        return;
    }

    s = &Protector->Statistics;

    Statistics->TotalOperations       = ReadNoFence64(&s->TotalOperations);
    Statistics->CreateKeyOperations   = ReadNoFence64(&s->CreateKeyOperations);
    Statistics->OpenKeyOperations     = ReadNoFence64(&s->OpenKeyOperations);
    Statistics->DeleteKeyOperations   = ReadNoFence64(&s->DeleteKeyOperations);
    Statistics->RenameKeyOperations   = ReadNoFence64(&s->RenameKeyOperations);
    Statistics->SetValueOperations    = ReadNoFence64(&s->SetValueOperations);
    Statistics->DeleteValueOperations = ReadNoFence64(&s->DeleteValueOperations);
    Statistics->QueryOperations       = ReadNoFence64(&s->QueryOperations);

    Statistics->PersistenceDetections    = ReadNoFence64(&s->PersistenceDetections);
    Statistics->DefenseEvasionDetections = ReadNoFence64(&s->DefenseEvasionDetections);
    Statistics->RansomwareIndicators     = ReadNoFence64(&s->RansomwareIndicators);
    Statistics->SecurityPolicyChanges    = ReadNoFence64(&s->SecurityPolicyChanges);
    Statistics->CertificateStoreChanges  = ReadNoFence64(&s->CertificateStoreChanges);
    Statistics->ServiceCreations         = ReadNoFence64(&s->ServiceCreations);
    Statistics->RunKeyModifications      = ReadNoFence64(&s->RunKeyModifications);
    Statistics->IFEOModifications        = ReadNoFence64(&s->IFEOModifications);

    Statistics->SelfProtectionBlocks = ReadNoFence64(&s->SelfProtectionBlocks);
    Statistics->ThreatBlocks         = ReadNoFence64(&s->ThreatBlocks);
    Statistics->PolicyBlocks         = ReadNoFence64(&s->PolicyBlocks);

    Statistics->NotificationsSent    = ReadNoFence64(&s->NotificationsSent);
    Statistics->NotificationsDropped = ReadNoFence64(&s->NotificationsDropped);

    Statistics->PathResolutionErrors    = ReadNoFence64(&s->PathResolutionErrors);
    Statistics->ContextAllocationErrors = ReadNoFence64(&s->ContextAllocationErrors);
    Statistics->AnalysisErrors          = ReadNoFence64(&s->AnalysisErrors);

    Statistics->TotalLatencyUs = ReadNoFence64(&s->TotalLatencyUs);
    Statistics->MaxLatencyUs   = ReadNoFence64(&s->MaxLatencyUs);

    Statistics->StartTime.QuadPart = ReadNoFence64(
        (volatile LONG64*)&s->StartTime.QuadPart);
}

/*++
    Routine Description:
        重置全部统计并将 StartTime 置为当前系统时间。

    Arguments:
        Protector — 保护器句柄。

    Returns:
        无。
--*/
_Use_decl_annotations_
VOID
RgpResetRegistryStatistics(
    _In_ PWKD_REGISTRY_PROTECTION Protector
    )
{
    if (Protector == NULL) {
        return;
    }

    RtlZeroMemory(&Protector->Statistics, sizeof(WKD_RG_STATISTICS));
    KeQuerySystemTime(&Protector->Statistics.StartTime);
}

/* ============================================================================
 * 配置读写（ShadowStrikeUpdateRegistryConfig / Get，L2742-2780）
 * ============================================================================ */

/*++
    Routine Description:
        全量更新配置（ConfigLock 排他 + KeEnterCriticalRegion）。

    Arguments:
        Protector — 保护器句柄。
        Config    — 新配置。

    Returns:
        无。
--*/
_Use_decl_annotations_
VOID
RgpUpdateRegistryConfig(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PWKD_RG_CONFIG Config
    )
{
    PAGED_CODE();

    if (Protector == NULL || Config == NULL) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Protector->ConfigLock);

    RtlCopyMemory(&Protector->Config, Config, sizeof(WKD_RG_CONFIG));

    ExReleasePushLockExclusive(&Protector->ConfigLock);
    KeLeaveCriticalRegion();
}

/*++
    Routine Description:
        快照读取配置（ConfigLock 共享）。

    Arguments:
        Protector — 保护器句柄。
        Config    — 输出配置。

    Returns:
        无。
--*/
_Use_decl_annotations_
VOID
RgpGetRegistryConfig(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _Out_ PWKD_RG_CONFIG Config
    )
{
    if (Protector == NULL || Config == NULL) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Protector->ConfigLock);

    RtlCopyMemory(Config, &Protector->Config, sizeof(WKD_RG_CONFIG));

    ExReleasePushLockShared(&Protector->ConfigLock);
    KeLeaveCriticalRegion();
}

/* ============================================================================
 * 监控键哈希表管理（ShadowStrikeRegAddMonitoredKey / Remove / IsKeyMonitored，
 * L2786-3001；2026-09-09 架构重构：手写 64 桶 LIST_ENTRY 换用 Common/HashMap
 * 全局推锁模式 + no-op 引用回调。键统一以 CoDowncaseUnicodeString 规范化为
 * 小写字节序列存储 —— HashMap 键比较为大小写敏感字节比较（CopKeyEqual →
 * RtlCompareMemory），查询端（RgpIsKeyMonitored）同向小写规范化后匹配，
 * 与原 RtlEqualUnicodeString(..., TRUE) 大小写不敏感语义对齐。
 * Value 槽未使用（纯存在性语义），上限由 ActiveEntries 准实时承载）
 * ============================================================================ */

/*++
    Routine Description:
        向监控键哈希表注册一个键（前缀命中语义）。已存在返回
        STATUS_OBJECT_NAME_COLLISION（不再携带 Flags，调用方经 NTSTATUS
        判断插入结果）。上限 AC_REG_MAX_PROTECTED_KEYS 由 HashMap
        ActiveEntries 承载（插入前检查，管理面低频无 TOCTOU 压力）。

    Arguments:
        Protector — 保护器句柄。
        KeyPath   — 键路径（最长 WKD_RG_MAX_KEY_PATH_LEN 字符）。

    Returns:
        STATUS_SUCCESS / STATUS_OBJECT_NAME_COLLISION / STATUS_NAME_TOO_LONG /
        STATUS_INVALID_PARAMETER / STATUS_INSUFFICIENT_RESOURCES / STATUS_NO_MEMORY。
--*/
_Use_decl_annotations_
NTSTATUS
AcRegisterProtectedRegistryKey(
    _Inout_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCUNICODE_STRING KeyPath
    )
{
    PUNICODE_STRING downcaseKey = NULL;
    NTSTATUS status;

    PAGED_CODE();

    if (!Protector || !CoCheckUnicodeStringValidity(KeyPath)) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 上限预检（插入前，避免无谓分配） */
    if (InterlockedCompareExchange(&Protector->MonitoredKeys.ActiveEntries, 0, 0) >=
        AC_REG_MAX_PROTECTED_KEYS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = CoDowncaseUnicodeString(&downcaseKey, KeyPath);
    if (!NT_SUCCESS(status)) return status;

    status = CoInsertHashMap(
        &Protector->MonitoredKeys,
        downcaseKey->Buffer,
        downcaseKey->Length,
        1,                          /* 哨兵 Value（存在性语义，非 0 必须）：
                                     * CoLookupHashMapEntry 以 (PVOID)Value 判定命中，
                                     * Value=0 会把已存在项误判为未找到 */
        NULL);
    
    CoFreeUnicodeStringSafe(downcaseKey);
    return status;
}

/*++
    Routine Description:
        从监控键哈希表移除一个键（规范化为小写后精确匹配删除）。

    Arguments:
        Protector — 保护器句柄。
        KeyPath   — 键路径。

    Returns:
        TRUE — 已移除；FALSE — 不存在。
--*/
_Use_decl_annotations_
BOOLEAN
AcpUnregisterProtectedRegistryKey(
    _Inout_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCUNICODE_STRING KeyPath
    )
{
    NTSTATUS status;
    PUNICODE_STRING downcaseKey = NULL;
    BOOLEAN removed;

    PAGED_CODE();

    if (!Protector || !CoCheckUnicodeStringValidity(KeyPath)) {
        return FALSE;
    }

    status = CoDowncaseUnicodeString(&downcaseKey, KeyPath);
    if (!NT_SUCCESS(status)) return FALSE;

    removed = CoRemoveHashMapEntry(&Protector->MonitoredKeys,
                                   downcaseKey->Buffer,
                                   downcaseKey->Length);

    CoFreeUnicodeStringSafe(downcaseKey);
    return removed;
}

/*++
    Routine Description:
        判断键是否被监控（前缀命中语义，RegIsKeyMonitored 两步法）：
        1. 自身规范化（小写）后精确匹配；
        2. 沿反斜杠逐前缀规范化后查询，命中被监控父键（如 \REGISTRY\MACHINE\
           SOFTWARE\X 的子键查询命中 X 的监控条目）。
        每一步均为 O(1) HashMap 查询（全局推锁共享读）。

    Arguments:
        Protector — 保护器句柄。
        KeyPath   — 待判定完整键路径。

    Returns:
        TRUE — 命中监控键；FALSE — 未命中。
--*/
_Use_decl_annotations_
BOOLEAN
RgpIsKeyMonitored(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCUNICODE_STRING KeyPath
    )
{
    NTSTATUS status;
    PWCH lowerBuf;
    UNICODE_STRING lowerPrefix;
    UNICODE_STRING prefix;
    USHORT i;
    USHORT charCount;
    BOOLEAN hit = FALSE;

    if (Protector == NULL || !Protector->Initialized ||
        KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0) {
        return FALSE;
    }

    /* Step 1: 自身规范化（小写）后精确匹配（单次 O(1) 查询） */
    {
        PUNICODE_STRING lowerKey = NULL;
        PVOID found;

        status = CoDowncaseUnicodeString(&lowerKey, KeyPath);
        if (!NT_SUCCESS(status)) {
            return FALSE;
        }

        found = CoLookupHashMapEntry(
            &Protector->MonitoredKeys,
            lowerKey->Buffer,
            lowerKey->Length);

        CoFreeUnicodeStringSafe(lowerKey);

        if (found != NULL) {
            return TRUE;
        }
    }

    /* Step 2: 逐反斜杠前缀查询（前缀规范化复用单块缓冲，同向下小写） */
    charCount = KeyPath->Length / sizeof(WCHAR);
    lowerBuf = (PWCH)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        KeyPath->Length + sizeof(WCHAR),
        WKD_RG_POOL_TAG);
    if (lowerBuf == NULL) {
        return FALSE;
    }

    prefix.Buffer = KeyPath->Buffer;
    prefix.MaximumLength = KeyPath->Length;

    for (i = 1; i < charCount && !hit; i++) {
        if (KeyPath->Buffer[i] == L'\\') {
            prefix.Length = i * sizeof(WCHAR);

            RtlInitEmptyUnicodeString(&lowerPrefix, lowerBuf,
                (USHORT)(i * sizeof(WCHAR) + sizeof(WCHAR)));
            RtlDowncaseUnicodeString(&lowerPrefix, &prefix, FALSE);

            if (CoLookupHashMapEntry(
                    &Protector->MonitoredKeys,
                    lowerBuf,
                    i * sizeof(WCHAR)) != NULL) {
                hit = TRUE;
            }
        }
    }

    ExFreePoolWithTag(lowerBuf, WKD_RG_POOL_TAG);

    return hit;
}

/* ============================================================================
 * 注册表操作分析总入口（回调例程分析段 L2019-2422）
 * ============================================================================ */

/*++
    Routine Description:
        注册表操作分析总入口。由 CM 回调节点（RegistryNotification.c）经引擎公共入口
        AcAuditRegistryAccess 转调。内部顺序（回调例程分析段）：

        1. 键分类（RgpClassifyRegistryKey）
        2. 持久化分析（SetValue 且 PersistenceMonitoringEnabled）
        3. 勒索语义检测 -> BlockHighRiskOperations 联动（ThreatBlocks）
        4. 按进程行为关联（仅写类操作且命中分类）：
           - 操作计数 / 分类计数 / 威胁指示累计
           - 时序环形缓冲（32 项）
           - 行为模式：多持久化喷洒（3+ 类）/ 防御规避+持久化组合 /
             勒索准备（VSS+持久化）-> 0x5039/0x503A 段上报
        5. 全局统计累计

        SS 的 BeEngineSubmitEvent / TsAddFactor / TeLogRegistryEvent / 告警均在
        WkD 收敛为 RgpReportDetection + DbgPrint（见各模式分支）。

    Arguments:
        Protector      — 保护器句柄。
        KeyPath        — 受操作键完整路径。
        Operation      — REG_NOTIFY_CLASS 操作类型。
        RequestorProcessId — 发起请求的进程 PID。
        ValueName      — 值名（SetValue/DeleteValue；其他可 NULL）。
        Data           — 值数据（SetValue；CM 回调上下文中有效期内安全）。
        DataSize       — 值数据大小。
        DataType       — 值类型（REG_*）。

    Returns:
        TRUE — 命中 BlockHighRiskOperations 配置的阻断点（调用方应阻断）；
        FALSE — 放行。
--*/
_Use_decl_annotations_
BOOLEAN
RgpAnalyzeRegistryAccess(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCUNICODE_STRING KeyPath,
    _In_ REG_NOTIFY_CLASS Operation,
    _In_ HANDLE RequestorProcessId,
    _In_opt_ PCUNICODE_STRING ValueName,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize,
    _In_ ULONG DataType
    )
{
    WKD_RG_REG_OPERATION operation;
    UNICODE_STRING emptyValueName;
    UNICODE_STRING analysisValueName;
    PVOID analysisData;
    ULONG analysisDataSize;
    ULONG keyFlags;
    BOOLEAN blockOperation = FALSE;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized ||
        KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0) {
        return FALSE;
    }

    operation = RgpNotifyClassToOperation(Operation);
    keyFlags = RgpClassifyRegistryKey(KeyPath);

    /* ValueName 兜底：NULL 时以空串参与分析 */
    RtlInitUnicodeString(&emptyValueName, L"");
    if (ValueName != NULL) {
        analysisValueName = *ValueName;
    } else {
        analysisValueName = emptyValueName;
    }

    /* Data 截断：SHADOWSTRIKE_MAX_REG_DATA_CAPTURE */
    analysisData = Data;
    analysisDataSize = (DataSize > WKD_RG_MAX_REG_DATA_CAPTURE)
                           ? WKD_RG_MAX_REG_DATA_CAPTURE
                           : DataSize;

    if (Protector->Config.Enabled) {
        /* 1. 持久化分析（仅 SetValue） */
        if (operation == WkdRgOpSetValue &&
            Protector->Config.PersistenceMonitoringEnabled) {
            RgpAnalyzeRegistryPersistence(
                Protector,
                RequestorProcessId,
                (PUNICODE_STRING)KeyPath,
                &analysisValueName,
                analysisData,
                analysisDataSize,
                DataType);
        }

        /* 2. 勒索语义 -> 配置化阻断 */
        if (RgpDetectRansomwareRegistryBehavior(
                KeyPath, &analysisValueName, operation,
                analysisData, analysisDataSize)) {
            if (Protector->Config.BlockHighRiskOperations) {
                blockOperation = TRUE;
                InterlockedIncrement64(&Protector->Statistics.ThreatBlocks);
            }
        }

        /* 3. 按进程行为关联（仅写类操作且命中分类）。
         * 2026-09-09 架构重构：进程上下文并入 WKD_PROCESS.RegistryProfile，
         * 经 PsLookupWkdProcessByProcessId 获取（查找即 +1，配对
         * PsDereferenceWkdProcess 释放）；进程表未收录（池满/枚举遗漏）
         * 时行为关联尽力而为跳过。 */
        if (keyFlags != WkdRgFlagNone &&
            (operation == WkdRgOpSetValue || operation == WkdRgOpDeleteKey ||
             operation == WkdRgOpDeleteValue || operation == WkdRgOpCreateKey ||
             operation == WkdRgOpRenameKey || operation == WkdRgOpSetKeySecurity)) {

            PWKD_PROCESS wkdProcess =
                PsLookupWkdProcessByProcessId(RequestorProcessId);

            if (wkdProcess != NULL) {
                PWKD_RG_PROCESS_PROFILE profile = &wkdProcess->RegistryProfile;
                ULONG ringIdx;
                ULONG distinctCategories = 0;
                ULONG semanticThreatIndicators = WkdRgThreatNone;

                /* (1) 操作计数 */
                InterlockedIncrement64(&profile->TotalOperations);

                switch (operation) {
                    case WkdRgOpCreateKey:
                        InterlockedIncrement64(&profile->CreateKeyCount);
                        break;
                    case WkdRgOpSetValue:
                        InterlockedIncrement64(&profile->SetValueCount);
                        break;
                    case WkdRgOpDeleteKey:
                        InterlockedIncrement64(&profile->DeleteKeyCount);
                        break;
                    case WkdRgOpDeleteValue:
                        InterlockedIncrement64(&profile->DeleteValueCount);
                        break;
                    default:
                        break;
                }

                /* (2) 分类跟踪（语义指示需值语义，避免把常规维护当攻击） */
                if (keyFlags & WkdRgFlagSecurityKey) {
                    InterlockedIncrement64(&profile->SecurityKeyAccesses);

                    semanticThreatIndicators |= RgpDetectDefenseEvasionRegistry(
                        KeyPath, &analysisValueName, analysisData, analysisDataSize);
                }

                if (RgpDetectRansomwareRegistryBehavior(
                        KeyPath, &analysisValueName, operation,
                        analysisData, analysisDataSize)) {
                    semanticThreatIndicators |= WkdRgThreatRansomware;
                }

                if (keyFlags & WkdRgFlagPersistenceKey) {
                    InterlockedIncrement64(&profile->PersistenceAttempts);
                    InterlockedOr((volatile LONG*)&profile->ThreatIndicators,
                                  (LONG)WkdRgThreatPersistence);
                }
                if (keyFlags & WkdRgFlagRunKey) {
                    InterlockedIncrement((volatile LONG*)&profile->RunKeyModifications);
                }
                if (keyFlags & WkdRgFlagServiceKey) {
                    InterlockedIncrement((volatile LONG*)&profile->ServiceModifications);
                }
                if (keyFlags & WkdRgFlagIFEOKey) {
                    InterlockedIncrement((volatile LONG*)&profile->IFEOModifications);
                }
                if (semanticThreatIndicators & WkdRgThreatDefenseEvasion) {
                    InterlockedIncrement((volatile LONG*)&profile->SecurityPolicyModifications);
                    InterlockedOr((volatile LONG*)&profile->ThreatIndicators,
                                  (LONG)WkdRgThreatDefenseEvasion);
                }
                if (semanticThreatIndicators & WkdRgThreatRansomware) {
                    InterlockedOr((volatile LONG*)&profile->ThreatIndicators,
                                  (LONG)WkdRgThreatRansomware);
                }
                if (keyFlags & WkdRgFlagCertificateKey) {
                    InterlockedOr((volatile LONG*)&profile->ThreatIndicators,
                                  (LONG)WkdRgThreatPrivilegeEsc);
                }

                /* (3) 时序环形缓冲 */
                ringIdx = (ULONG)InterlockedIncrement(
                              (volatile LONG*)&profile->RecentOpIndex) &
                          (WKD_RG_RING_BUFFER_SIZE - 1);
                profile->RecentOps[ringIdx] = (ULONG)operation;
                KeQuerySystemTime(&profile->RecentOpTimes[ringIdx]);

                /* (4) 行为模式判定（多技术攻击） */
                if (profile->RunKeyModifications > 0)       distinctCategories++;
                if (profile->ServiceModifications > 0)      distinctCategories++;
                if (profile->IFEOModifications > 0)         distinctCategories++;
                if (profile->ThreatIndicators & WkdRgThreatRansomware)     distinctCategories++;
                if (profile->ThreatIndicators & WkdRgThreatDefenseEvasion) distinctCategories++;

                /* 4a. 多持久化喷洒（3+ 类，T1547+T1543+T1546） */
                if (distinctCategories >= WKD_RG_DISTINCT_CATEGORY_THRESHOLD &&
                    !(profile->ThreatIndicators & WKD_RG_PROCCTX_FLAG_MULTI_SPRAY)) {

                    InterlockedOr((volatile LONG*)&profile->ThreatIndicators,
                                  (LONG)WKD_RG_PROCCTX_FLAG_MULTI_SPRAY);

                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "[WkDefender/RG] BEHAVIORAL: Multi-technique registry attack! "
                        "PID=%lu, Categories=%lu (Run=%lu, Svc=%lu, IFEO=%lu)\n",
                        HandleToULong(RequestorProcessId), distinctCategories,
                        profile->RunKeyModifications,
                        profile->ServiceModifications,
                        profile->IFEOModifications);

RgpReportDetection(Protector, RG_EVENT_SUBTYPE_BEHAVIORAL_ALERT, 9, RequestorProcessId,
                    L"Registry: multi-technique persistence spray (Run/Services/IFEO)");
                }

                /* 4b. 防御规避 + 持久化组合（禁用安全组件 + 植入持久化） */
                if (distinctCategories >= WKD_RG_COMBO_CATEGORY_THRESHOLD &&
                    (profile->ThreatIndicators & WkdRgThreatDefenseEvasion) &&
                    (profile->ThreatIndicators & WkdRgThreatPersistence) &&
                    !(profile->ThreatIndicators & WKD_RG_PROCCTX_FLAG_DEFEVASION_COMBO)) {

                    InterlockedOr((volatile LONG*)&profile->ThreatIndicators,
                                  (LONG)WKD_RG_PROCCTX_FLAG_DEFEVASION_COMBO);

                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                        "[WkDefender/RG] BEHAVIORAL: Defense evasion + persistence combo! "
                        "PID=%lu, SecPolicy=%lu, Persistence=%lld\n",
                        HandleToULong(RequestorProcessId),
                        profile->SecurityPolicyModifications,
                        profile->PersistenceAttempts);

RgpReportDetection(Protector, RG_EVENT_SUBTYPE_BEHAVIORAL_COMBO, 8, RequestorProcessId,
                    L"Registry: defense evasion + persistence combo "
                    L"(security disable + implant)");
                }

                /* 4c. 勒索准备（T1490 + T1547/T1543） */
                if ((profile->ThreatIndicators & WkdRgThreatRansomware) &&
                    (profile->ThreatIndicators & WkdRgThreatPersistence) &&
                    !(profile->ThreatIndicators & WKD_RG_PROCCTX_FLAG_RANSOMWARE_PREP)) {

                    InterlockedOr((volatile LONG*)&profile->ThreatIndicators,
                                  (LONG)WKD_RG_PROCCTX_FLAG_RANSOMWARE_PREP);

                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "[WkDefender/RG] CRITICAL: Ransomware preparation pattern! "
                        "PID=%lu, VSS+Persistence combo detected\n",
                        HandleToULong(RequestorProcessId));

RgpReportDetection(Protector, RG_EVENT_SUBTYPE_BEHAVIORAL_COMBO, 10, RequestorProcessId,
                    L"Registry: ransomware preparation (VSS + persistence combo)");
                }

                /* 配对的引用释放（查找即 +1） */
                PsDereferenceWkdProcess(wkdProcess);
            }
        }

        /* 4. 全局统计（回调主段操作分类计数） */
        switch (operation) {
            case WkdRgOpCreateKey:
                InterlockedIncrement64(&Protector->Statistics.CreateKeyOperations);
                break;
            case WkdRgOpDeleteKey:
                InterlockedIncrement64(&Protector->Statistics.DeleteKeyOperations);
                break;
            case WkdRgOpRenameKey:
                InterlockedIncrement64(&Protector->Statistics.RenameKeyOperations);
                break;
            case WkdRgOpSetValue:
                InterlockedIncrement64(&Protector->Statistics.SetValueOperations);
                break;
            case WkdRgOpDeleteValue:
                InterlockedIncrement64(&Protector->Statistics.DeleteValueOperations);
                break;
            default:
                break;
        }

        InterlockedIncrement64(&Protector->Statistics.TotalOperations);
    }

    return blockOperation;
}