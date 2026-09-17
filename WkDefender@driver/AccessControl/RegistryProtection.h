/*++
    SelfProtection/RegistryProtection.h - 注册表自保护（自防护的消费者组件）

    Purpose:
        作为独立 CM 回调节点（Callbacks/RegistryCallback.c）的【消费者】，
        为注册表自保护提供判定能力。本组件：
        - 【不】注册/持有 CM 回调（注册/注销由 RegistryCallback 管理）。
        - 维护受保护键列表（静态数组，前缀匹配）。
        - 提供 RgpShouldBlockRegistryAccess：结合引擎注入的豁免回调
          （受保护进程自改自键放行）与键前缀匹配，对危险操作（删除键/
          设置值/删除值/重命名/SetSecurity）判定 BLOCK 并上报 0x5030 段。

        事件子类型使用 0x5030 段：
        - RG_EVENT_SUBTYPE_DELETE_KEY   = 0x5030（删除受保护键被拦截）
        - RG_EVENT_SUBTYPE_SET_VALUE    = 0x5031（设置受保护键值被拦截）
        - RG_EVENT_SUBTYPE_DELETE_VALUE = 0x5032（删除受保护键值被拦截）
        - RG_EVENT_SUBTYPE_RENAME_KEY   = 0x5033（重命名受保护键被拦截）
        - RG_EVENT_SUBTYPE_SET_SECURITY = 0x5034（修改受保护键安全描述符被拦截）

    豁免回调（AcInitializeRegistryProtection 注入，由引擎提供）：
        自防护引擎注入的内部回调（SpEngineIsRegistryProcessExempt）判
        受保护进程（Pap 画像，PapProfile 非零，如主服务），使其对自身
        注册表键的修改不被 BLOCK——对齐 ShadowStrike 的
        ShadowStrikeIsProcessProtected 豁免语义。
        （2026-09-05：原查 AntiUnload 的 AuIsProcessProtectedById，该表已删除）

    Synchronization:
        - EX_SPIN_LOCK 保护键列表（管理路径排他，判定路径共享读，
          对齐 ShadowStrike g_ProtectedRegKeyLock）。

    Copyright (c) WkDefender Team
--*/

#pragma once

#include <ntifs.h>
#include "SelfProtectionCompat.h"
#include "../Common/HashMap.h"   /* WKD_HASH_MAP（2026-09-09 监控键表迁移） */

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 常量定义
 * ============================================================================ */

#define WKD_RG_MAX_PROTECTED_KEYS      32          /* 同时受保护的最大键数 */

/* 事件子类型（0x5030 段，对齐 AD 0x5010 / IM 0x5020 分配方案） */
#define RG_EVENT_SUBTYPE_DELETE_KEY    0x5030      /* 删除受保护键被拦截 */
#define RG_EVENT_SUBTYPE_SET_VALUE     0x5031      /* 设置受保护键值被拦截 */
#define RG_EVENT_SUBTYPE_DELETE_VALUE  0x5032      /* 删除受保护键值被拦截 */
#define RG_EVENT_SUBTYPE_RENAME_KEY    0x5033      /* 重命名受保护键被拦截 */
#define RG_EVENT_SUBTYPE_SET_SECURITY  0x5034      /* 修改受保护键安全描述符被拦截 */

/* 检测类事件子类型（0x5035 段，迁移自 ShadowStrike RegistryCallback 分析面） */
#define RG_EVENT_SUBTYPE_PERSISTENCE       0x5035  /* 持久化机制检测（Run/Services/IFEO 等） */
#define RG_EVENT_SUBTYPE_RANSOMWARE        0x5036  /* 勒索行为检测（VSS/备份/系统还原禁用） */
#define RG_EVENT_SUBTYPE_DEFENSE_EVASION   0x5037  /* 防御规避检测（Defender/防火墙/策略篡改） */
#define RG_EVENT_SUBTYPE_CERTIFICATE       0x5038  /* 证书存储篡改（根证书/AuthRoot） */
#define RG_EVENT_SUBTYPE_BEHAVIORAL_ALERT  0x5039  /* 行为关联告警（多技术组合攻击模式） */
#define RG_EVENT_SUBTYPE_BEHAVIORAL_COMBO  0x503A  /* 行为组合告警（防御规避+持久化/勒索准备） */

/* ============================================================================
 * 路径常量（迁移自 ShadowStrike RegistryCallback.h 的 SHADOWSTRIKE_REG_*）
 * ============================================================================ */

/* 持久化位置 - Run/RunOnce 键（T1547.001） */
#define WKD_RG_PATH_RUN_KEY \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define WKD_RG_PATH_RUNONCE_KEY \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
#define WKD_RG_PATH_RUNONCEEX_KEY \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"

/* 持久化位置 - Services（T1543.003） */
#define WKD_RG_PATH_SERVICES \
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services"
#define WKD_RG_PATH_SERVICES_ALT \
    L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services"

/* 持久化位置 - IFEO（T1546.012） */
#define WKD_RG_PATH_IFEO \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"

/* 持久化位置 - AppInit_DLLs / Winlogon */
#define WKD_RG_PATH_APPINIT \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
#define WKD_RG_PATH_WINLOGON \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

/* 持久化位置 - COM 对象（T1546.015） */
#define WKD_RG_PATH_CLSID \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID"

/* 持久化位置 - 计划任务（Legacy） */
#define WKD_RG_PATH_SCHEDULED_TASKS \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"

/* 安全策略位置（T1562.001 / T1562.004） */
#define WKD_RG_PATH_SECURITY_CENTER \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Security Center"
#define WKD_RG_PATH_WINDOWS_DEFENDER \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows Defender"
#define WKD_RG_PATH_POLICIES \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft"
#define WKD_RG_PATH_FIREWALL \
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy"

/* 勒索指示器（T1490） */
#define WKD_RG_PATH_VSS_ADMIN \
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\VSS"
#define WKD_RG_PATH_WBENGINE \
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\wbengine"
#define WKD_RG_PATH_BACKUP_EXEC \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Symantec\\Backup Exec"
#define WKD_RG_PATH_SYSTEM_RESTORE \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore"

/* 证书存储（T1553.004） */
#define WKD_RG_PATH_ROOT_CERTS \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates"
#define WKD_RG_PATH_AUTH_ROOT \
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates"

/* HKCU 用户配置单元前缀（SID 组件需跳过解析） */
#define WKD_RG_PATH_USER_HIVE_PREFIX \
    L"\\REGISTRY\\USER\\"

/* ============================================================================
 * 操作枚举（迁移自 ShadowStrike SHADOWSTRIKE_REG_OPERATION，裁剪到回调实际使用集）
 * ============================================================================ */

typedef enum _WKD_RG_REG_OPERATION {
    WkdRgOpNone = 0,
    WkdRgOpCreateKey,
    WkdRgOpOpenKey,
    WkdRgOpDeleteKey,
    WkdRgOpRenameKey,
    WkdRgOpSetValue,
    WkdRgOpDeleteValue,
    WkdRgOpQueryValue,
    WkdRgOpEnumerateKey,
    WkdRgOpEnumerateValue,
    WkdRgOpQueryKey,
    WkdRgOpSetKeySecurity,
    WkdRgOpMax
} WKD_RG_REG_OPERATION, *PWKD_RG_REG_OPERATION;

/* ============================================================================
 * 键分类标志（迁移自 ShadowStrike SHADOWSTRIKE_REG_FLAGS）
 * ============================================================================ */

typedef enum _WKD_RG_REG_FLAGS {
    WkdRgFlagNone            = 0x00000000,
    WkdRgFlagPersistenceKey  = 0x00000001,   /* 已知持久化位置 */
    WkdRgFlagSecurityKey     = 0x00000002,   /* 安全相关键 */
    WkdRgFlagServiceKey      = 0x00000004,   /* 服务配置 */
    WkdRgFlagProtectedKey    = 0x00000008,   /* 自保护键 */
    WkdRgFlagRunKey          = 0x00000010,   /* Run/RunOnce 键 */
    WkdRgFlagIFEOKey         = 0x00000020,   /* IFEO */
    WkdRgFlagCOMKey          = 0x00000040,   /* COM 对象注册 */
    WkdRgFlagCertificateKey  = 0x00000080,   /* 证书存储 */
    WkdRgFlagFirewallKey     = 0x00000100,   /* 防火墙配置 */
    WkdRgFlagDefenderKey     = 0x00000200,   /* Windows Defender */
    WkdRgFlagVSSKey          = 0x00000400,   /* 卷影复制 */
    WkdRgFlagScheduledTaskKey= 0x00000800,   /* 计划任务 */
    WkdRgFlagWinlogonKey     = 0x00001000,   /* Winlogon */
    WkdRgFlagAppInitKey      = 0x00002000,   /* AppInit_DLLs */
    WkdRgFlagHighRisk        = 0x80000000    /* 高风险修改 */
} WKD_RG_REG_FLAGS;

/* ============================================================================
 * 威胁指示器（迁移自 ShadowStrike SHADOWSTRIKE_REG_THREAT_INDICATOR）
 * ============================================================================ */

typedef enum _WKD_RG_THREAT_INDICATOR {
    WkdRgThreatNone            = 0x00000000,
    WkdRgThreatPersistence     = 0x00000001,   /* 持久化机制 */
    WkdRgThreatDefenseEvasion  = 0x00000002,   /* 安全绕过 */
    WkdRgThreatPrivilegeEsc    = 0x00000004,   /* 权限提升 */
    WkdRgThreatCredentialAccess= 0x00000008,   /* 凭据访问 */
    WkdRgThreatLateralMovement = 0x00000010,   /* 横向移动准备 */
    WkdRgThreatRansomware      = 0x00000020,   /* 勒索行为 */
    WkdRgThreatRootkit         = 0x00000040,   /* 内核隐蔽 */
    WkdRgThreatInfoStealer     = 0x00000080,   /* 窃密行为 */
    WkdRgThreatTampering       = 0x00000100    /* AV/EDR 篡改 */
} WKD_RG_THREAT_INDICATOR;

/* 行为模式标志（REG_PATTERN_*） */
#define WKD_RG_PATTERN_MULTI_PERSISTENCE    0x1     /* 多技术持久化喷洒（T1547+T1543+T1546） */
#define WKD_RG_PATTERN_DEFEVASION_PERSIST   0x2     /* 防御规避+持久化组合 */
#define WKD_RG_PATTERN_RANSOMWARE_PREP      0x4     /* 勒索准备（VSS+持久化） */

/* 行为关联阈值（回调例程） */
#define WKD_RG_DISTINCT_CATEGORY_THRESHOLD  3       /* 多持久化喷洒：3+ 类须告警 */
#define WKD_RG_COMBO_CATEGORY_THRESHOLD     2       /* 组合模式：2+ 类须关注 */

/* ============================================================================
 * 受保护键条目（Consumer 内，静态数组，前缀匹配）
 * ============================================================================ */

typedef struct _WKD_RG_PROTECTED_KEY {
    BOOLEAN InUse;           /* 槽位占用标记 */
    USHORT  KeyPathLength;   /* 键路径字符数（不含 NUL） */
    WCHAR   KeyPath[MAX_PATH];
} WKD_RG_PROTECTED_KEY, *PWKD_RG_PROTECTED_KEY;


#define AC_REG_MAX_PROTECTED_KEYS           128

/* ============================================================================
 * 进程行为上下文（迁移自 ShadowStrike SHADOWSTRIKE_REG_PROCESS_CONTEXT）
 * 2026-09-09 架构重构：进程上下文并入 WKD_PROCESS.RegistryProfile
 * （ProcessMonitor.h，内嵌值类型随进程回收），本头不再定义/管理。
 * WKD_RG_RING_BUFFER_SIZE 已提升至 Common/Constants.h。
 * ============================================================================ */

/* ============================================================================
 * 统计（迁移自 ShadowStrike SHADOWSTRIKE_REG_STATISTICS）
 * ============================================================================ */

typedef struct _WKD_RG_STATISTICS {
    /* 操作计数 */
    volatile LONG64 TotalOperations;
    volatile LONG64 CreateKeyOperations;
    volatile LONG64 OpenKeyOperations;
    volatile LONG64 DeleteKeyOperations;
    volatile LONG64 RenameKeyOperations;
    volatile LONG64 SetValueOperations;
    volatile LONG64 DeleteValueOperations;
    volatile LONG64 QueryOperations;

    /* 检测计数 */
    volatile LONG64 PersistenceDetections;
    volatile LONG64 DefenseEvasionDetections;
    volatile LONG64 RansomwareIndicators;
    volatile LONG64 SecurityPolicyChanges;
    volatile LONG64 CertificateStoreChanges;
    volatile LONG64 ServiceCreations;
    volatile LONG64 RunKeyModifications;
    volatile LONG64 IFEOModifications;

    /* 阻断计数 */
    volatile LONG64 SelfProtectionBlocks;
    volatile LONG64 ThreatBlocks;
    volatile LONG64 PolicyBlocks;

    /* 通知计数 */
    volatile LONG64 NotificationsSent;
    volatile LONG64 NotificationsDropped;

    /* 错误计数 */
    volatile LONG64 PathResolutionErrors;
    volatile LONG64 ContextAllocationErrors;
    volatile LONG64 AnalysisErrors;

    /* 时序 */
    LARGE_INTEGER  StartTime;
    volatile LONG64 TotalLatencyUs;
    volatile LONG64 MaxLatencyUs;
} WKD_RG_STATISTICS, *PWKD_RG_STATISTICS;

/* ============================================================================
 * 配置（迁移自 ShadowStrike SHADOWSTRIKE_REG_CONFIG）
 * ============================================================================ */

typedef struct _WKD_RG_CONFIG {
    /* 监控开关 */
    BOOLEAN Enabled;
    BOOLEAN SelfProtectionEnabled;
    BOOLEAN PersistenceMonitoringEnabled;
    BOOLEAN SecurityPolicyMonitoringEnabled;
    BOOLEAN ServiceMonitoringEnabled;
    BOOLEAN CertificateMonitoringEnabled;
    BOOLEAN DetailedNotificationsEnabled;
    BOOLEAN BlockHighRiskOperations;

    /* 阈值 */
    ULONG MinBlockScore;
    ULONG PersistenceAlertScore;
    ULONG AnalysisTimeoutMs;
    ULONG NotificationRateLimitPerSec;
} WKD_RG_CONFIG, *PWKD_RG_CONFIG;

/* ============================================================================
 * 豁免回调
 * ============================================================================ */

//
// 豁免判定回调。由引擎注入（Context = Engine），2026-09-05 起受保护
// 判定收敛为 Pap 画像（PapProfile 非零，受保护进程自改自键放行）。
//
typedef BOOLEAN (*WKD_RG_EXEMPT_CALLBACK)(
    _In_ HANDLE RequestorProcessId,
    _In_opt_ PVOID Context
    );

/* ============================================================================
 * 注册表保护器（不透明句柄，结构定义在 .c 中）
 * ============================================================================ */

typedef struct _WKD_REGISTRY_PROTECTION WKD_REGISTRY_PROTECTION, *PWKD_REGISTRY_PROTECTION;

/* ============================================================================
 * 公共 API（内部组件前缀 Rgp*，仅供引擎调用）
 * ============================================================================ */

//
// 初始化注册表自保护（分配保护器，注入豁免回调）。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AcInitializeRegistryProtection(
    _Out_ PWKD_REGISTRY_PROTECTION* Protector,
    _In_ const WKD_RG_EXEMPT_CALLBACK ExemptCallback,
    _In_opt_ const PVOID Context
    );

//
// 关闭注册表自保护（释放保护器）。
// 调用前提：CM 回调节点已注销（无并发 RgpShouldBlockRegistryAccess 进入）。
// NULL 安全。运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
RgpShutdown(
    _Inout_ PWKD_REGISTRY_PROTECTION Protector
    );

//
// 保护一个注册表键/键前缀（前缀匹配生效）。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
RgpProtectKey(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCWSTR KeyPath
    );

//
// 注销对一个注册表键/键前缀的保护。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
RgpUnprotectKey(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCWSTR KeyPath
    );

//
// 判定是否应 BLOCK 对路径的注册表操作。
// 由 CM 回调节点（RegistryCallback.c）经引擎公共入口 SpEngineShouldBlockRegistryAccess
// 转调本函数。内部：
//   1. 豁免回调（受保护进程自改自键放行）
//   2. 键前缀匹配（RgpIsKeyProtected）
//   3. 危险操作过滤（DeleteKey/SetValue/DeleteValue/Rename/SetSecurity）
//   4. 命中则计数 + 上报 0x5030 段，返回 TRUE
// 运行环境: PASSIVE_LEVEL（CM 回调上下文；调用方已获取引擎 rundown）
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
RgpShouldBlockRegistryAccess(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCUNICODE_STRING KeyPath,
    _In_ REG_NOTIFY_CLASS Operation,
    _In_ HANDLE RequestorProcessId
    );

//
// 键路径分类（迁移自 ShadowStrike ShadowStrikeClassifyRegistryKey）。
// 将键路径分类为持久化/安全/服务/证书等类别位图（WKD_RG_REG_FLAGS）。
// 运行环境: PASSIVE_LEVEL（内部仅做前缀比较，无阻塞操作）
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
RgpClassifyRegistryKey(
    _In_ PCUNICODE_STRING KeyPath
    );

//
// 持久化机制分析（迁移自 ShadowStrike ShadowStrikeAnalyzeRegistryPersistence）。
// 对 SetValue 操作分类并累计持久化/防御规避/证书/勒索威胁指示。
// 检测命中时上报 0x5035/0x5036/0x5037/0x5038 段并在统计中计数。
// ProcessId 为写入者进程（CM 回调 RequestorProcessId），透传给出上报
// 链（RgpReportDetection）供评分联动定位进程对 Source。
// 运行环境: PASSIVE_LEVEL（CM 回调上下文；Data 缓冲区由 CM 提供有效期内安全）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
RgpAnalyzeRegistryPersistence(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PUNICODE_STRING ValueName,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize,
    _In_ ULONG DataType
    );

//
// 勒索行为检测（迁移自 ShadowStrike ShadowStrikeDetectRansomwareRegistryBehavior）。
// 检视 VSS/wbengine/SystemRestore/Backup Exec 路径上的删除与 Start=4/DisableSR 置位。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
RgpDetectRansomwareRegistryBehavior(
    _In_ PCUNICODE_STRING KeyPath,
    _In_opt_ PCUNICODE_STRING ValueName,
    _In_ WKD_RG_REG_OPERATION Operation,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize
    );

//
// 防御规避检测（迁移自 ShadowStrike ShadowStrikeDetectDefenseEvasionRegistry）。
// 检视 Defender 禁用值（DisableAntiSpyware/DisableRealtimeMonitoring 等）与
// SecurityCenter/Firewall/Policies 篡改。返回 WKD_RG_THREAT_INDICATOR 位图。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
RgpDetectDefenseEvasionRegistry(
    _In_ PCUNICODE_STRING KeyPath,
    _In_opt_ PCUNICODE_STRING ValueName,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize
    );

//
// 注册表操作分析总入口（迁移自 ShadowStrike 回调例程分析段）。
// 由 CM 回调节点经引擎公共入口 AcAuditRegistryAccess 转调。内部:
//   1. 分类（RgpClassifyRegistryKey）
//   2. 持久化分析（SetValue，若配置启用）
//   3. 勒索/防御规避语义检测
//   4. 按进程行为关联（阈值 WKD_RG_DISTINCT_CATEGORY_THRESHOLD / COMBO）
//   5. 统计累计
// 按进程行为上下文已并入 WKD_PROCESS.RegistryProfile（2026-09-09 架构重构），
// 内部经 PsLookupWkdProcessByProcessId 获取（查找即 +1，须配对
// PsDereferenceWkdProcess），随进程退出由 ProcessMonitor 统一回收。
// 返回 TRUE 表示命中 BlockHighRiskOperations 配置的阻断点（调用方决定是否阻断）。
// 运行环境: PASSIVE_LEVEL（CM 回调上下文；调用方已获取引擎 rundown；Data 有效期内安全）
//
_IRQL_requires_(PASSIVE_LEVEL)
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
    );

//
// 监控键哈希表管理（迁移自 ShadowStrike RegAddMonitoredKey/Remove/IsKeyMonitored）。
// 与静态受保护数组（RgpProtectKey）并存：此哈希表供动态监控键的检测覆盖面。
// 2026-09-09 架构重构：手写哈希桶换用 Common/HashMap（全局推锁 + no-op 引用
// 回调 CoHashMapNoopReference/Dereference，纯值语义）；键路径统一规范化为
// 全大写后按二进制键比较（对齐注册表键名大小写不敏感语义）。
// 已存在条目语义：AcRegisterProtectedRegistryKey 已存在返回 STATUS_OBJECT_NAME_COLLISION
// （不再携带 Flags —— 监控键无标志位，NTSTATUS 即表达插入结果）。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AcRegisterProtectedRegistryKey(
    _Inout_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCUNICODE_STRING KeyPath
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
AcpUnregisterProtectedRegistryKey(
    _Inout_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCUNICODE_STRING KeyPath
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
RgpIsKeyMonitored(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCUNICODE_STRING KeyPath
    );

//
// 统计与配置（迁移自 ShadowStrike GetRegistryStatistics/Config）。
// 运行环境: <= DISPATCH_LEVEL（统计）/ PASSIVE_LEVEL（配置）
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RgpGetRegistryStatistics(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _Out_ PWKD_RG_STATISTICS Statistics
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RgpResetRegistryStatistics(
    _In_ PWKD_REGISTRY_PROTECTION Protector
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
RgpUpdateRegistryConfig(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PWKD_RG_CONFIG Config
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
RgpGetRegistryConfig(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _Out_ PWKD_RG_CONFIG Config
    );

#ifdef __cplusplus
}
#endif