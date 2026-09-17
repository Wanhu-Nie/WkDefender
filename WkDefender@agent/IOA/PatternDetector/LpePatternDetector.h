/**************************************************/
/*  WkDefender IOA — 本地提权 (LPE) 模式检测器      */
/*                                                  */
/*  迁移自 ShadowStrike PrivilegeEscalationDetector */
/*  (PrivilegeEscalationDetector.cpp/.hpp, v3.0.1)  */
/*  功能重实现 (C 重写), 非源码复制。                */
/*                                                  */
/*  独立模块: 不含 Token 操控检测 (已由 TokenAnalyzer */
/*  / PrivilegeMonitor 覆盖), 聚焦 7 类"模式"(Pattern) */
/*  级提权检测:                                     */
/*    ├─ UAC 绕过 (fodhelper/eventvwr/computerdefaults/
/*    │   COM 键/自动提升二进制滥用)  T1548.002     */
/*    ├─ 服务滥用 (未加引号路径/可写目录/弱文件 ACL)  */
/*    │                                     T1543.003 */
/*    ├─ DLL 搜索顺序劫持 (目录 ACL)      T1574.001  */
/*    ├─ 注册表滥用 (AlwaysInstallElevated/IFEO)     */
/*    │                               T1548.002/T1546.012 */
/*    ├─ Potato 家族 (Juicy/Rogue/Sweet/PrintSpoofer) */
/*    │   + SeImpersonatePrivilege          T1068    */
/*    ├─ 命名管道模拟 (可疑管道名+属主)    T1055.003  */
/*    └─ 计划任务滥用 (SYSTEM 任务非内置作者)         */
/*                                         T1053.005 */
/*                                                  */
/*  实用工具 (自 ShadowStrike 同文件迁移):           */
/*    - 二进制路径提取 (CommandLineToArgvW)          */
/*    - 目录/文件 ACL 写检查 (GetEffectiveRightsFromAclW) */
/*    - 白名单/自动响应 (高置信度终止进程)            */
/*                                                  */
/*  接入状态: 独立模块 (死代码), 未挂接 IoaObserve   */
/*  事件流水线。调用方按需周期调用 LpdRunSweep 或     */
/*  各分类入口。                                     */
/*                                                  */
/*  MITRE ATT&CK 对齐 ShadowStrike 事件硬编码 ID。   */
/**************************************************/

#pragma once

#include "../../DefendTypes.h"

/**************************************************/
/*               容量常量                           */
/**************************************************/

#define LPD_MAX_WHITELIST           8           /* 白名单进程子串上限 */
#define LPD_MAX_IFEO_ENTRIES        1024        /* IFEO 枚举上限 (SS PrivEscConstants) */
#define LPD_MAX_NAMED_PIPES         4096        /* 命名管道枚举上限 (SS) */
#define LPD_MAX_SCHEDULED_TASKS     2048        /* 计划任务解析上限 (SS) */
#define LPD_AUTO_BLOCK_THRESHOLD    75          /* 自动响应置信度阈值 (SS AUTO_BLOCK=75.0) */
#define LPD_DEFAULT_SWEEP_EVENTS    256         /* LpdRunSweep 建议事件缓冲容量 */

/**************************************************/
/*               技术类型枚举                       */
/**************************************************/

typedef enum _LPD_TECHNIQUE {
    LpdTech_Unknown = 0,

    /* UAC 绕过 (T1548.002) */
    LpdTech_FodhelperBypass,            /* fodhelper.exe 注册表劫持      */
    LpdTech_EventViewerBypass,          /* eventvwr.msc mscfile 劫持     */
    LpdTech_ComputerDefaultsBypass,     /* computerdefaults.exe 劫持     */
    LpdTech_UacBypassCom,               /* COM 对象 UAC 绕过             */
    LpdTech_UacBypassAutoElevate,       /* 自动提升二进制非标准路径运行   */
    LpdTech_UacBypassRegistry,          /* 已知 UAC 绕过注册表路径篡改    */

    /* 服务滥用 (T1543.003) */
    LpdTech_ServiceUnquotedPath,        /* 未加引号服务路径              */
    LpdTech_ServiceWritableDir,         /* 服务二进制目录用户可写         */
    LpdTech_ServiceWeakFilePerms,       /* 服务二进制弱文件 ACL           */

    /* DLL 劫持 (T1574.001) */
    LpdTech_DllHijack,                  /* DLL 搜索顺序劫持 (目录 ACL)    */

    /* 注册表滥用 */
    LpdTech_RegistryAlwaysInstall,      /* AlwaysInstallElevated (T1548.002) */
    LpdTech_RegistryIfeo,               /* IFEO Debugger (T1546.012)     */

    /* 提权利用工具 */
    LpdTech_PotatoAttack,               /* Potato 家族 (T1068)           */
    LpdTech_NamedPipeImpersonation,     /* 命名管道模拟 (T1055.003)      */
    LpdTech_ScheduledTaskAbuse,         /* 计划任务滥用 (T1053.005)      */

    LpdTech_Max
} LPD_TECHNIQUE;

/**************************************************/
/*               置信度枚举                         */
/**************************************************/

typedef enum _LPD_CONFIDENCE {
    LpdConf_Low = 0,
    LpdConf_Medium,
    LpdConf_High,
    LpdConf_VeryHigh,
    LpdConf_Confirmed
} LPD_CONFIDENCE;

/* 置信度 → 分数换算 (SS: High=80/VeryHigh=95/Confirmed=99) */
#define LPD_CONFIDENCE_SCORE(Level)                     \
    (((Level) == LpdConf_Confirmed) ? 99 :             \
     ((Level) == LpdConf_VeryHigh)   ? 95 :             \
     ((Level) == LpdConf_High)       ? 80 :             \
     ((Level) == LpdConf_Medium)     ? 50 : 20)

/**************************************************/
/*               服务漏洞类型                       */
/**************************************************/

typedef enum _LPD_SERVICE_VULN {
    LpdSvcVuln_None = 0,
    LpdSvcVuln_UnquotedPath,            /* 未加引号路径                  */
    LpdSvcVuln_WritableDirectory,       /* 二进制目录可写                */
    LpdSvcVuln_WeakFilePermissions,     /* 二进制文件弱 ACL              */
    LpdSvcVuln_DllHijackable,           /* 服务目录 DLL 劫持             */
    LpdSvcVuln_ModifiableConfig         /* 服务配置可修改                */
} LPD_SERVICE_VULN;

/**************************************************/
/*               检测事件结构                       */
/*  LpeEvent 核心字段, 去掉 JSON 序列化。    */
/**************************************************/

typedef struct _LPD_EVENT {
    ULONG           EventId;            /* 全局自增序号 (替代 SS 字符串 ID) */
    ULONG           ProcessId;          /* 嫌疑进程 PID (0=系统级) */
    WCHAR           ProcessName[DEF_MAX_IMAGE_NAME];
    WCHAR           ProcessPath[DEF_MAX_PATH * 2];
    ULONG           ParentProcessId;

    LPD_TECHNIQUE   Technique;
    ULONG           ConfidenceScore;    /* [0,100] */
    CHAR            MitreAttackId[24];

    WCHAR           TargetRegistryKey[DEF_MAX_PATH * 2];
    WCHAR           TargetFilePath[DEF_MAX_PATH * 2];

    BOOLEAN         WasBlocked;         /* 是否触发自动响应 */

    LARGE_INTEGER   Timestamp;
    WCHAR           Details[512];       /* 人类可读细节 (多行, 宽字符) */
} LPD_EVENT, *PLPD_EVENT;

/**************************************************/
/*               服务安全信息结构                   */
/**************************************************/

typedef struct _LPD_SERVICE_INFO {
    WCHAR           ServiceName[256];
    WCHAR           DisplayName[256];
    WCHAR           BinaryPath[DEF_MAX_PATH * 2];
    ULONG           StartType;          /* SERVICE_*_START */
    ULONG           ServiceType;        /* SERVICE_WIN32_* */
    ULONG           CurrentState;       /* SERVICE_*_STATE */
    WCHAR           RunAsAccount[256];  /* lpServiceStartName */

    BOOLEAN         HasUnquotedPath;
    BOOLEAN         IsPathWritable;
    BOOLEAN         IsConfigModifiable;
    BOOLEAN         IsDllHijackable;
    LPD_SERVICE_VULN Vulnerability;     /* 最高优先级漏洞 (仅列出风险服务) */
} LPD_SERVICE_INFO, *PLPD_SERVICE_INFO;

/**************************************************/
/*               IFEO Debugger 条目                 */
/**************************************************/

typedef struct _LPD_IFEO_ENTRY {
    WCHAR           TargetExecutable[256];      /* 被劫持目标映像名 */
    WCHAR           Debugger[DEF_MAX_PATH * 4]; /* Debugger 值 */
    BOOLEAN         FromHkcu;                   /* HKCU 分支 = 标准用户可写, 高危 */
} LPD_IFEO_ENTRY, *PLPD_IFEO_ENTRY;

/**************************************************/
/*               配置结构                           */
/**************************************************/

typedef struct _LPD_CONFIG {
    BOOLEAN         MonitorUacBypass;       /* UAC 绕过检测开关 */
    BOOLEAN         MonitorServiceConfig;   /* 服务漏洞扫描开关 */
    BOOLEAN         MonitorIfeo;            /* IFEO 枚举开关 */
    BOOLEAN         DetectDllHijacking;     /* DLL 劫持 (目录 ACL) 开关 */
    BOOLEAN         DetectPotato;           /* Potato 家族开关 */
    BOOLEAN         DetectNamedPipe;        /* 命名管道模拟开关 */
    BOOLEAN         DetectScheduledTasks;   /* 计划任务滥用开关 */
    BOOLEAN         DetectComBypass;        /* COM UAC 绕过开关 */

    BOOLEAN         BlockOnDetection;       /* 高置信度自动响应总开关 */
    BOOLEAN         TerminateOnHighConfidence; /* 终止嫌疑进程 */

    WCHAR           WhitelistedProcesses[LPD_MAX_WHITELIST][DEF_MAX_PATH * 2];
    ULONG           WhitelistCount;         /* 有效白名单条目数 */
} LPD_CONFIG, *PLPD_CONFIG;

#define LPD_DEFAULT_CONFIG                                              \
    { TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE,                  \
      TRUE, TRUE, { { 0 } }, 0 }

/**************************************************/
/*               统计结构                           */
/**************************************************/

typedef struct _LPD_STATISTICS {
    volatile LONG   SweepsRun;              /* 全量扫描轮次 */
    volatile LONG   UacBypassesDetected;    /* UAC 绕过命中 */
    volatile LONG   ServiceAbusesDetected;  /* 服务漏洞命中 */
    volatile LONG   DllHijacksDetected;     /* DLL 劫持命中 */
    volatile LONG   RegistryAbusesDetected; /* 注册表滥用命中 */
    volatile LONG   PotatoAttacksDetected;  /* Potato 命中 */
    volatile LONG   NamedPipeImpersonations;/* 管道模拟命中 */
    volatile LONG   ScheduledTaskAbuses;    /* 任务滥用命中 */
    volatile LONG   ComBypassesDetected;    /* COM 绕过命中 */
    volatile LONG   IfeoAbusesDetected;     /* IFEO 命中 */
    volatile LONG   EscalationsBlocked;     /* 自动响应拦截 */
    volatile LONG   ProcessesTerminated;    /* 终止进程数 */
    volatile LONG   EventsReported;         /* 上报事件总数 */
} LPD_STATISTICS, *PLPD_STATISTICS;

/**************************************************/
/*               检测回调                           */
/**************************************************/

typedef VOID (*LPD_DETECTED_CALLBACK)(
    _In_    const LPD_EVENT* Event,
    _In_opt_ PVOID          Context
    );

/**************************************************/
/*               生命周期                           */
/**************************************************/

NTSTATUS
LpdInitialize(
    _In_ const LPD_CONFIG* Config          /* NULL = LPD_DEFAULT_CONFIG */
    );

VOID
LpdShutdown(VOID);

BOOLEAN
LpdIsInitialized(VOID);

/**************************************************/
/*               扫描入口                           */
/**************************************************/

/*
 * LpdRunSweep — 单次全量扫描 (监控线程一轮)。
 *
 * 依次执行 UAC 绕过 / 服务 / IFEO / Potato / 命名管道 /
 * 计划任务 / COM 检测, 事件写入调用者缓冲 (写满后仍经
 * 回调实时上报, 不丢事件)。返回本轮命中事件总数 (含回调)。
 */
ULONG
LpdRunSweep(
    _Out_writes_to_opt_(MaxEvents, *pReturned) PLPD_EVENT Events,
    _In_                               ULONG       MaxEvents,
    _Out_opt_                          PULONG      pReturned
    );

/* 分类检测入口 (供精细调用) */

ULONG
LpdDetectUacBypasses(
    _Out_writes_to_opt_(MaxEvents, *pReturned) PLPD_EVENT Events,
    _In_                               ULONG       MaxEvents,
    _Out_opt_                          PULONG      pReturned
    );

ULONG
LpdDetectComBypasses(
    _Out_writes_to_opt_(MaxEvents, *pReturned) PLPD_EVENT Events,
    _In_                               ULONG       MaxEvents,
    _Out_opt_                          PULONG      pReturned
    );

ULONG
LpdDetectPotatoAttacks(
    _Out_writes_to_opt_(MaxEvents, *pReturned) PLPD_EVENT Events,
    _In_                               ULONG       MaxEvents,
    _Out_opt_                          PULONG      pReturned
    );

ULONG
LpdDetectNamedPipeImpersonation(
    _Out_writes_to_opt_(MaxEvents, *pReturned) PLPD_EVENT Events,
    _In_                               ULONG       MaxEvents,
    _Out_opt_                          PULONG      pReturned
    );

ULONG
LpdDetectScheduledTaskAbuse(
    _Out_writes_to_opt_(MaxEvents, *pReturned) PLPD_EVENT Events,
    _In_                               ULONG       MaxEvents,
    _Out_opt_                          PULONG      pReturned
    );

/**************************************************/
/*               服务分析                           */
/**************************************************/

/*
 * LpdScanServices — 枚举全部服务并分析漏洞。
 * 仅返回存在漏洞 (Vulnerability != None) 的服务。
 */
ULONG
LpdScanServices(
    _Out_writes_to_opt_(MaxInfos, *pReturned) PLPD_SERVICE_INFO Infos,
    _In_                               ULONG              MaxInfos,
    _Out_opt_                          PULONG             pReturned
    );

NTSTATUS
LpdAnalyzeService(
    _In_  PCWSTR           ServiceName,
    _Out_ PLPD_SERVICE_INFO Info
    );

BOOLEAN
LpdIsAlwaysInstallElevatedEnabled(VOID);

/**************************************************/
/*               IFEO 分析                         */
/**************************************************/

ULONG
LpdGetIfeoDebuggers(
    _Out_writes_to_opt_(MaxEntries, *pReturned) PLPD_IFEO_ENTRY Entries,
    _In_                               ULONG           MaxEntries,
    _Out_opt_                          PULONG          pReturned
    );

/**************************************************/
/*               DLL 劫持                          */
/**************************************************/

/*
 * LpdIsDllHijackVulnerable — 系统级 DLL 劫持面检查:
 *  %SystemRoot% 目录 WriteDAC 可写 (Everyone/Auth Users/Users) 即判定漏洞。
 */
BOOLEAN
LpdIsDllHijackVulnerable(VOID);

/**************************************************/
/*               回调 / 统计                        */
/**************************************************/

VOID
LpdRegisterCallback(
    _In_opt_ LPD_DETECTED_CALLBACK Callback,
    _In_opt_ PVOID                 Context
    );

VOID
LpdGetStatistics(
    _Out_ PLPD_STATISTICS Stats
    );

VOID
LpdResetStatistics(VOID);

/**************************************************/
/*               工具函数                           */
/**************************************************/

PCSTR
LpdGetTechniqueName(
    _In_ LPD_TECHNIQUE Technique
    );

PCSTR
LpdGetTechniqueMitreId(
    _In_ LPD_TECHNIQUE Technique
    );