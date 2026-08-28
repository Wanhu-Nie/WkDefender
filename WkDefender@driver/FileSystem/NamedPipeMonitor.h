/**************************************************/
/*  WkDefender — 命名管道 C2/横向移动监控公共接口    */
/*                                                   */
/*  迁移自 ShadowStrike NamedPipeMonitor.c/h          */
/*  （重功能实现，非源码复制）                        */
/**************************************************/

#pragma once

#include <fltKernel.h>
#include <ntifs.h>

/**************************************************/
/*                      常量定义                   */
/**************************************************/

#define WKD_NPM_POOL_TAG               'mNWK'  /* WkNm */

#define WKD_NPM_MAX_PIPE_NAME_CCH      256
#define WKD_NPM_RATE_LIMIT_WINDOW_MS   1000
#define WKD_NPM_RATE_LIMIT_MAX_CREATES 50
#define WKD_NPM_BOOT_PHASE_MS          120000  /* boot 期跳过窗口（对齐 SS ShadowFsIsBootPhase） */

#define WKD_NPM_STATE_UNINITIALIZED    0
#define WKD_NPM_STATE_INITIALIZING     1
#define WKD_NPM_STATE_READY            2

/**************************************************/
/*                      枚举类型                   */
/**************************************************/

/* 威胁等级（对齐 SS NpmThreat_*） */
typedef enum _WKD_NPM_THREAT_LEVEL {
    WkdNpmThreat_None      = 0,
    WkdNpmThreat_Low       = 25,
    WkdNpmThreat_Medium    = 50,
    WkdNpmThreat_High      = 75,
    WkdNpmThreat_Critical  = 100
} WKD_NPM_THREAT_LEVEL, *PWKD_NPM_THREAT_LEVEL;

/* 管道分类（对齐 SS NpmClass_* 11 类） */
typedef enum _WKD_NPM_PIPE_CLASS {
    WkdNpmClass_Unknown         = 0,
    WkdNpmClass_System,                 /* Windows 系统管道（lsass 等） */
    WkdNpmClass_KnownApplication,       /* 已知合法应用管道 */
    WkdNpmClass_C2_CobaltStrike,        /* CobaltStrike beacon 模式 */
    WkdNpmClass_C2_Meterpreter,         /* Meterpreter 管道模式 */
    WkdNpmClass_C2_PsExec,              /* PsExec 服务管道 */
    WkdNpmClass_C2_Impacket,            /* Impacket/WMIExec 管道 */
    WkdNpmClass_C2_Generic,             /* 通用 C2 模式 */
    WkdNpmClass_HighEntropy,            /* 可疑随机化名 */
    WkdNpmClass_Suspicious,             /* 其他可疑模式 */
    WkdNpmClass_SpoofedSystem           /* 系统管道名被非预期进程创建（T1036） */
} WKD_NPM_PIPE_CLASS, *PWKD_NPM_PIPE_CLASS;

/* 系统管道验证结果（对齐 SS NpmSysPipe_*） */
typedef enum _WKD_NPM_SYS_PIPE_RESULT {
    WkdNpmSysPipe_NotSystem = 0,
    WkdNpmSysPipe_Validated = 1,
    WkdNpmSysPipe_Spoofed   = 2
} WKD_NPM_SYS_PIPE_RESULT, *PWKD_NPM_SYS_PIPE_RESULT;

/**************************************************/
/*                      统计结构                   */
/**************************************************/

/* 对齐 SS NPM_STATISTICS 10 计数器 */
typedef struct _WKD_NPM_STATISTICS {
    volatile LONG64 TotalPipesCreated;
    volatile LONG64 TotalPipesConnected;        /* 连接检测未接入（死代码字段），恒 0 */
    volatile LONG64 TotalPipesBlocked;
    volatile LONG64 SuspiciousPipesDetected;
    volatile LONG64 C2PipesDetected;
    volatile LONG64 HighEntropyPipesDetected;
    volatile LONG64 CrossProcessConnections;    /* 连接检测未接入（死代码字段），恒 0 */
    volatile LONG64 SpoofedSystemPipes;
    volatile LONG64 EventsQueued;
    volatile LONG64 EventsDropped;
} WKD_NPM_STATISTICS, *PWKD_NPM_STATISTICS;

/**************************************************/
/*                      函数声明                   */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdNpmInitialize(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdNpmShutdown(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdNpmIsActive(
    VOID
    );

/*++
 * WkdNpmPreCreateNamedPipe
 *   命名管道创建分析（纯分类引擎，供 minifilter 回调调用）。
 *   内部编排：系统管道验证（限速豁免）→ 速率限制 → C2 模式/熵分类，
 *   并同步累计统计计数。不执行阻断/上送（接入层职责）。
 *
 * Arguments:
 *   PipeName        - 管道名（去除 \Device\NamedPipe\ 前缀后的最终组件）。
 *   NameLengthBytes - 管道名字节长（不含 NUL）。
 *   CreatorImageName- 创建者进程映像名（PsGetProcessImageFileName，ANSI）。
 *   OutThreatScore  - 输出威胁分 [0,100]。
 *
 * Return Value:
 *   WKD_NPM_PIPE_CLASS 分类；Unknown/System 表示无害。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
WKD_NPM_PIPE_CLASS
WkdNpmPreCreateNamedPipe(
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes,
    _In_z_ PCSTR CreatorImageName,
    _Out_ PULONG OutThreatScore
    );

/*++
 * WkdNpmIsBlockworthy
 *   阻断判定：系统管道冒充无条件；C2 类管道威胁分 >= 90（对齐 SS）。
 *
 * Return Value:
 *   TRUE 应阻断 / FALSE 仅上报。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdNpmIsBlockworthy(
    _In_ WKD_NPM_PIPE_CLASS Classification,
    _In_ ULONG ThreatScore
    );

/*++
 * WkdNpmClassToThreatLevel
 *   分类+威胁分 → 威胁等级（对齐 SS 分级：>=90 Critical / >=70 High /
 *   >=50 Medium / >=25 Low）。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
WKD_NPM_THREAT_LEVEL
WkdNpmClassToThreatLevel(
    _In_ WKD_NPM_PIPE_CLASS Classification,
    _In_ ULONG ThreatScore
    );

/*++
 * WkdNpmNoteBlocked
 *   接入层执行阻断后调用，累计 TotalPipesBlocked 统计。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdNpmNoteBlocked(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdNpmGetStatistics(
    _Out_ PWKD_NPM_STATISTICS Stats
    );

/*++
 * WkdNpmNoteEventQueued / WkdNpmNoteEventDropped
 *   接入层上送命名管道事件成功/失败时调用，对齐 SS NpmQueueEvent 的
 *   EventsQueued / EventsDropped 统计语义（wkd 事件队列由 NotificationManager
 *   承载，此处只累计命名管道模块自身视角的入队/丢弃计数）。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdNpmNoteEventQueued(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdNpmNoteEventDropped(
    VOID
    );
