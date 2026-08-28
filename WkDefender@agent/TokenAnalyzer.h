/**************************************************/
/*  WkDefender — 令牌分析引擎（全功能版）            */
/*  参考 PhantomSensor: TokenAnalyzer.c/h +          */
/*  PrivilegeMonitor.c/h (2026-08-05 融合迁移)       */
/*  TaAnalyzeToken / TaDetectTokenManipulation /     */
/*  TapDetectAttackType / TapCalculateSuspicionScore/ */
/*  PmRecordBaseline / PmCheckForEscalation /         */
/*  PmpDetermineEscalationType / PmpCalculateScore /  */
/*  PmpIsLegitimateEscalation / PmpDetectUACBypass    */
/**************************************************/

#pragma once

#include <windows.h>
#include "DefendTypes.h"   /* 列表宏: InsertTailList/RemoveEntryList/InitializeListHead 等 */

//
// 完整性级别常量（对齐 SS TA_INTEGRITY_* / PM_INTEGRITY_*）
//
#define WPA_INTEGRITY_UNTRUSTED     0x00000000UL
#define WPA_INTEGRITY_LOW           0x00001000UL
#define WPA_INTEGRITY_MEDIUM        0x00002000UL
#define WPA_INTEGRITY_MEDIUM_PLUS   0x00002100UL
#define WPA_INTEGRITY_HIGH          0x00003000UL
#define WPA_INTEGRITY_SYSTEM        0x00004000UL
#define WPA_INTEGRITY_PROTECTED     0x00005000UL

//
// 兼容回退: SE_*_PRIVILEGE 数值宏仅定义于内核头 (wdm.h),
// 用户态包含链 (winnt.h) 只提供 SE_*_NAME 字符串, 此处按
// wdm.h 取值补全 (特权 LUID 低32位即此值)。
//
#ifndef SE_CREATE_TOKEN_PRIVILEGE
#define SE_CREATE_TOKEN_PRIVILEGE           (2L)
#endif
#ifndef SE_ASSIGNPRIMARYTOKEN_PRIVILEGE
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE     (3L)
#endif
#ifndef SE_TCB_PRIVILEGE
#define SE_TCB_PRIVILEGE                    (7L)
#endif
#ifndef SE_SECURITY_PRIVILEGE
#define SE_SECURITY_PRIVILEGE               (8L)
#endif
#ifndef SE_TAKE_OWNERSHIP_PRIVILEGE
#define SE_TAKE_OWNERSHIP_PRIVILEGE         (9L)
#endif
#ifndef SE_LOAD_DRIVER_PRIVILEGE
#define SE_LOAD_DRIVER_PRIVILEGE            (10L)
#endif
#ifndef SE_BACKUP_PRIVILEGE
#define SE_BACKUP_PRIVILEGE                 (17L)
#endif
#ifndef SE_RESTORE_PRIVILEGE
#define SE_RESTORE_PRIVILEGE                (18L)
#endif
#ifndef SE_DEBUG_PRIVILEGE
#define SE_DEBUG_PRIVILEGE                  (20L)
#endif
#ifndef SE_IMPERSONATE_PRIVILEGE
#define SE_IMPERSONATE_PRIVILEGE            (29L)
#endif

//
// ��Ȩλͼ������ SS PM_PRIV_* λֵ��
//
#define WPA_PRIV_DEBUG              0x00000001
#define WPA_PRIV_IMPERSONATE        0x00000002
#define WPA_PRIV_ASSIGN_PRIMARY     0x00000004
#define WPA_PRIV_TCB                0x00000008
#define WPA_PRIV_LOAD_DRIVER        0x00000010
#define WPA_PRIV_BACKUP             0x00000020
#define WPA_PRIV_RESTORE            0x00000040
#define WPA_PRIV_TAKE_OWNERSHIP     0x00000080
#define WPA_PRIV_CREATE_TOKEN       0x00000100
#define WPA_PRIV_SECURITY           0x00000200
#define WPA_PRIV_SYSTEM_ENVIRONMENT 0x00000400
#define WPA_PRIV_INCREASE_QUOTA     0x00000800
#define WPA_PRIV_INCREASE_PRIORITY  0x00001000
#define WPA_PRIV_CREATE_PAGEFILE    0x00002000
#define WPA_PRIV_SHUTDOWN           0x00004000
#define WPA_PRIV_AUDIT              0x00008000
#define WPA_PRIV_SYSTEM_PROFILE     0x00010000
#define WPA_PRIV_SYSTEMTIME         0x00020000
#define WPA_PRIV_MANAGE_VOLUME      0x00040000

//
// 敏感特权掩码（对齐 SS PmCheckForEscalation 敏感集）
//
#define WPA_PRIV_SENSITIVE_MASK     (WPA_PRIV_DEBUG | WPA_PRIV_TCB | \
                                     WPA_PRIV_LOAD_DRIVER | WPA_PRIV_CREATE_TOKEN | \
                                     WPA_PRIV_ASSIGN_PRIMARY | WPA_PRIV_SECURITY | \
                                     WPA_PRIV_TAKE_OWNERSHIP)

//
// 危险特权组合（对齐 SS TokenAnalyzer 无条件检测）
//
#define WPA_PRIV_DANGEROUS_COMBO    (WPA_PRIV_DEBUG | WPA_PRIV_IMPERSONATE | \
                                     WPA_PRIV_ASSIGN_PRIMARY)

//
// 阈值与上限
//
#define WPA_TA_HASH_BUCKETS         128
#define WPA_TA_HASH_MASK            (WPA_TA_HASH_BUCKETS - 1)
#define WPA_TA_MAX_BASELINES        4096
#define WPA_TA_MAX_EVENTS           4096
#define WPA_TA_MAX_PROCESS_NAME     260
#define WPA_TA_MAX_TECHNIQUE        64
#define WPA_TA_DEFAULT_MIN_ALERT    50
#define WPA_TA_DEFAULT_BLOCK_SCORE  90

//
// 可疑分阈值（对齐 SS PM_SUSPICION_*）
//
#define WPA_SUSPICION_NONE          0
#define WPA_SUSPICION_LOW           20
#define WPA_SUSPICION_MEDIUM        45
#define WPA_SUSPICION_HIGH          70
#define WPA_SUSPICION_CRITICAL      90

//
// 事件标志（对齐 SS PM_EVENT_FLAG_*）
//
#define WPA_EVENT_FLAG_LEGITIMATE   0x00000001
#define WPA_EVENT_FLAG_ALERTABLE    0x00000002
#define WPA_EVENT_FLAG_BLOCKED      0x00000004
#define WPA_EVENT_FLAG_REPORTED     0x00000008

//
// 令牌攻击类型（对齐 SS TA_TOKEN_ATTACK）
//
typedef enum _WPA_TOKEN_ATTACK {
    WpaAttack_None = 0,
    WpaAttack_Impersonation,
    WpaAttack_TokenStealing,
    WpaAttack_PrivilegeEscalation,
    WpaAttack_SIDInjection,
    WpaAttack_IntegrityDowngrade,
    WpaAttack_GroupModification,
    WpaAttack_PrimaryTokenReplace,
    WpaAttack_MaxValue
} WPA_TOKEN_ATTACK;

//
// 提权类型（对齐 SS PM_ESCALATION_TYPE 9 类）
//
typedef enum _WPA_ESCALATION_TYPE {
    WpaEscalation_None = 0,
    WpaEscalation_PrivilegeEnable,
    WpaEscalation_TokenElevation,
    WpaEscalation_IntegrityIncrease,
    WpaEscalation_UACBypass,
    WpaEscalation_ServiceCreation,
    WpaEscalation_DriverLoad,
    WpaEscalation_ExploitKernel,
    WpaEscalation_TokenManipulation,
    WpaEscalation_CrossSession,
    WpaEscalation_Max
} WPA_ESCALATION_TYPE;

/**************************************************/
/*                      结构体声明                 */
/**************************************************/

//
// 令牌信息结构体（全量采集快照）
//
typedef struct _WPA_TOKEN_INFO {
    HANDLE  ProcessId;
    LUID    AuthenticationId;
    LUID    TokenId;                /* TokenStatistics.TokenId (令牌标识, 更换检测) */
    ULONG   TokenType;              // 1=Primary, 2=Impersonation
    ULONG   ImpersonationLevel;     // 0=Anonymous..3=Delegation
    ULONG   IntegrityLevel;
    ULONG   PrivilegeBitmap;        /* 启用特权位图 (WPA_PRIV_*) */
    ULONG   EnabledPrivileges;      /* 启用特权计数 */
    ULONG   PrivilegeCount;         /* 特权总数 */
    ULONG   GroupCount;             /* 组总数 (SIDInjection 组数激增检测) */
    BOOLEAN HasDebugPrivilege;
    BOOLEAN HasImpersonatePrivilege;
    BOOLEAN HasAssignPrimaryPrivilege;
    BOOLEAN HasTcbPrivilege;
    BOOLEAN HasLoadDriverPrivilege;
    BOOLEAN HasBackupPrivilege;
    BOOLEAN HasRestorePrivilege;
    BOOLEAN IsAdmin;
    BOOLEAN IsSystem;
    BOOLEAN IsService;
    BOOLEAN IsNetworkService;
    BOOLEAN IsLocalService;
    BOOLEAN IsRestricted;
    BOOLEAN IsFiltered;             /* UAC 受限令牌 (TokenElevationTypeLimited) */
    BOOLEAN IsVirtualized;
    BOOLEAN IsSandboxed;
    BOOLEAN IsAppContainer;
    BOOLEAN IsElevated;
    ULONG   SessionId;
    ULONG   DetectedAttack;
    ULONG   SuspicionScore;
} WPA_TOKEN_INFO, *PWPA_TOKEN_INFO;

//
// UAC 绕过模式（对齐 SS g_UACBypassPatterns）
// 注: CommandLinePattern 为死代码 — SS PmpDetectUACBypass 从不比对命令行。
//
typedef struct _WPA_UAC_PATTERN {
    PCWSTR ProcessName;
    PCWSTR ParentProcessName;
    PCWSTR CommandLinePattern;      /* ※死代码: 对齐 SS, 仅记录不比对 */
    PCSTR  TechniqueName;
    ULONG  SuspicionScore;
} WPA_UAC_PATTERN, *PWPA_UAC_PATTERN;

//
// 进程令牌基线（吸收 SS PM_PROCESS_BASELINE + wkd PrivilegeMonitor）
// Original = 进程创建时快照；Current = 最近一次检查快照。
//
typedef struct _WPA_TOKEN_BASELINE {
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;

    HANDLE ProcessId;
    HANDLE ParentProcessId;
    WCHAR  ProcessName[WPA_TA_MAX_PROCESS_NAME];
    WCHAR  ParentProcessName[WPA_TA_MAX_PROCESS_NAME];

    /* 原始状态（进程创建时） */
    LUID    AuthenticationId;
    ULONG   TokenType;
    ULONG   OriginalIntegrityLevel;
    ULONG   OriginalPrivileges;
    ULONG   OriginalPrivilegeCount; /* 启用特权计数 */
    ULONG   OriginalGroupCount;     /* 组总数 (SIDInjection 组数激增检测) */
    BOOLEAN OriginalIsElevated;
    BOOLEAN OriginalIsAdmin;        /* SID 语义: 组含 Administrators */
    BOOLEAN OriginalIsSystem;       /* 行为化: Session0 + System 完整性 */
    BOOLEAN OriginalIsService;      /* 行为化: Session0 + elevated + 非System */
    ULONG   OriginalSessionId;

    /* 当前状态（最近一次检查） */
    ULONG   CurrentIntegrityLevel;
    ULONG   CurrentPrivileges;
    BOOLEAN CurrentIsElevated;
    ULONG   CurrentSessionId;
    LUID    CurrentAuthenticationId;

    /* 追踪 */
    LARGE_INTEGER BaselineTime;
    LARGE_INTEGER LastCheckTime;
    ULONG   CheckCount;
    ULONG   EscalationCount;
    ULONG   Flags;
    BOOLEAN IsTerminated;
    BOOLEAN HasEscalated;

    /* 引用计数（列表持有 1 + 外部 Lookup 持有） */
    volatile LONG RefCount;
} WPA_TOKEN_BASELINE, *PWPA_TOKEN_BASELINE;

//
// 提权事件（自包含，不依赖外部引用）
//
typedef struct _WPA_ESCALATION_EVENT {
    WPA_ESCALATION_TYPE Type;
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    WCHAR  ProcessName[WPA_TA_MAX_PROCESS_NAME];
    WCHAR  ParentProcessName[WPA_TA_MAX_PROCESS_NAME];

    ULONG OldIntegrityLevel;
    ULONG NewIntegrityLevel;
    ULONG OldPrivileges;
    ULONG NewPrivileges;
    BOOLEAN OldIsElevated;
    BOOLEAN NewIsElevated;
    ULONG OldSessionId;
    ULONG NewSessionId;
    LUID OldAuthenticationId;
    LUID NewAuthenticationId;

    ULONG Flags;
    ULONG SuspicionScore;
    CHAR  Technique[WPA_TA_MAX_TECHNIQUE];

    FILETIME Timestamp;
    FILETIME BaselineTime;

    LIST_ENTRY ListEntry;
} WPA_ESCALATION_EVENT, *PWPA_ESCALATION_EVENT;

//
// 引擎配置（对齐 SS PM_CONFIG）
//
typedef struct _WPA_TOKEN_CONFIG {
    BOOLEAN EnableIntegrityMonitoring;
    BOOLEAN EnablePrivilegeMonitoring;
    BOOLEAN EnableUACBypassDetection;
    BOOLEAN EnableTokenManipulationDetection;
    BOOLEAN EnableCrossSessionDetection;
    BOOLEAN AlertOnEscalation;      /* 对齐 SS PM_CONFIG (SS 未实际消费, 预留) */
    BOOLEAN BlockHighRiskEscalation;
    ULONG   MinAlertScore;
    ULONG   BlockThresholdScore;
} WPA_TOKEN_CONFIG, *PWPA_TOKEN_CONFIG;

//
// 引擎统计（对齐 SS PM_STATISTICS，PrivilegeMonitor 迁移 2026-08-06 补漏）
//
typedef struct _WPA_TOKEN_STATISTICS {
    LONG      EscalationsDetected;    /* 检测到提权次数 */
    LONG      LegitimateEscalations;  /* 判定合法提权次数 */
    LONG      BlockedEscalations;     /* 标记阻断次数 (monitor-only 未消费) */
    LONG      BaselinesCaptured;      /* 已建立基线数 */
    LONG      BaselinesRemoved;       /* 已移除基线数 */
    LONG      CurrentBaselineCount;   /* 当前活跃基线数 */
    LONG      CurrentEventCount;      /* 当前提权事件队列数 */
    FILETIME  StartTime;              /* 引擎启动时间 */
    FILETIME  LastCleanupTime;        /* 最近一次清理时间 */
} WPA_TOKEN_STATISTICS, *PWPA_TOKEN_STATISTICS;

/**************************************************/
/*                      函数声明                   */
/**************************************************/

//
// 引擎初始化/关闭
//
_Check_return_
HRESULT
WpaTokenAnalyzerInitialize(
    VOID
    );

VOID
WpaTokenAnalyzerShutdown(
    VOID
    );

//
// 全量令牌分析（对齐 SS TaAnalyzeToken:784-1092）
// 采集 + 无条件攻击检测 + 评分。结果写 Info。
//
_Check_return_
HRESULT
WpaAnalyzeToken(
    _In_  HANDLE        ProcessId,
    _Out_ PWPA_TOKEN_INFO Info
    );

//
// 检测令牌篡改（对齐 SS TaDetectTokenManipulation:1096-1255）
// 需先 WpaRecordBaseline 建立基线；无基线时退化为无条件检测。
//
_Check_return_
HRESULT
WpaDetectTokenManipulation(
    _In_  HANDLE  ProcessId,
    _Out_ PULONG  Attack,
    _Out_ PULONG  Score
    );

//
// 比较两个令牌快照（对齐 SS TaCompareTokens:1256-1410）
// 补权限/组 SID 增量对比（SS TapComparePrivileges/TapCompareGroups）。
//
_Check_return_
HRESULT
WpaCompareTokens(
    _In_  PWPA_TOKEN_INFO Original,
    _In_  PWPA_TOKEN_INFO Current,
    _Out_ PBOOLEAN        Changed
    );

//
// 记录进程令牌基线（对齐 SS PmRecordBaseline:1095）
// ProcessName/ParentProcessName 可为 NULL（调用者无父信息时 UAC 父匹配降半）。
//
_Check_return_
HRESULT
WpaRecordBaseline(
    _In_ HANDLE  ProcessId,
    _In_opt_ PCWSTR ProcessName,
    _In_ HANDLE  ParentProcessId,
    _In_opt_ PCWSTR ParentProcessName
    );

//
// 移除进程基线
//
_Check_return_
HRESULT
WpaRemoveBaseline(
    _In_ HANDLE ProcessId
    );

//
// 获取基线快照（对齐 SS TaGetBaselineSnapshot:1471）
//
_Check_return_
HRESULT
WpaGetBaselineSnapshot(
    _In_  HANDLE ProcessId,
    _Out_ PWPA_TOKEN_BASELINE Snapshot
    );

//
// 提权检测（对齐 SS PmCheckForEscalation:1364 + PmpDetermineEscalationType）
// Event 可为 NULL（仅刷新 Current 状态不产事件，对齐 wkd 周期检查用法）。
//
_Check_return_
HRESULT
WpaCheckForEscalation(
    _In_  HANDLE ProcessId,
    _Out_opt_ PWPA_ESCALATION_EVENT* Event
    );

//
// UAC 绕过检测（对齐 SS PmpDetectUACBypass:2868，10 模式）
//
BOOLEAN
WpaDetectUACBypass(
    _In_  PWPA_TOKEN_BASELINE Baseline,
    _Out_writes_(WPA_TA_MAX_TECHNIQUE) PCHAR TechniqueBuffer,
    _Out_ PULONG PatternScore
    );

//
// 进程终止清理基线（对齐 SS TaOnProcessTerminated:1516）
//
VOID
WpaOnProcessTerminated(
    _In_ HANDLE ProcessId
    );

//
// 获取待处理提权事件（对齐 SS PmGetEvents; 调用者 HeapFree 释放出队项）
// ※死代码: 当前无消费方, 事件已由 WpaCheckForEscalation 入队。
//
_Check_return_
HRESULT
WpaGetEscalationEvents(
    _Out_writes_(MaxEvents) WPA_ESCALATION_EVENT* Events,
    _In_  ULONG             MaxEvents,
    _Out_ PULONG            EventCount
    );

//
// 清空提权事件队列（对齐 SS PmClearEvents）
//
_Check_return_
HRESULT
WpaClearEscalationEvents(
    VOID
    );

//
// 查询进程是否已提权（对齐 SS PmQueryProcessEscalation）
// ※死代码: 无消费方。
//
_Check_return_
HRESULT
WpaQueryProcessEscalation(
    _In_  HANDLE   ProcessId,
    _Out_ PBOOLEAN HasEscalated,
    _Out_ PULONG   EscalationCount,
    _Out_ PULONG   CurrentIntegrityLevel
    );

//
// 获取/设置引擎配置（对齐 SS PmGetConfiguration/PmSetConfiguration）
// ※死代码: 配置默认值硬编码, 无外部接口消费。
//
_Check_return_
HRESULT
WpaGetConfig(
    _Out_ PWPA_TOKEN_CONFIG Config
    );

_Check_return_
HRESULT
WpaSetConfig(
    _In_ PWPA_TOKEN_CONFIG Config
    );

//
// 获取引擎统计（对齐 SS PmGetStatistics:1964-1996）
// ※死代码: 无消费方, 供状态查询/调优。
//
_Check_return_
HRESULT
WpaGetStatistics(
    _Out_ PWPA_TOKEN_STATISTICS Stats
    );

//
// 清理过期基线（对齐 SS PmpCleanupStaleBaselines, 进程消失则移除）
// ※死代码: wkd 进程退出回调 (ProcessExit 事件) 已触发 WpaOnProcessTerminated
//   立即清理, 此为 SS 周期兜底迁移, 无周期触发源。
//
VOID
WpaCleanupStaleBaselines(
    VOID
    );

//
// 工具函数
//
PCWSTR
WpaAttackTypeToString(
    _In_ ULONG Attack
    );

PCWSTR
WpaIntegrityLevelToString(
    _In_ ULONG IntegrityLevel
    );

PCWSTR
WpaEscalationTypeToString(
    _In_ ULONG EscalationType
    );
