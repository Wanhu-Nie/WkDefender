/**************************************************/
/*  WkDefender Agent — 进程保护决策引擎               */
/*  (ProcessProtection)                              */
/*                                                   */
/*  纯 C 实现 ShadowStrike ProcessProtection.cpp/hpp  */
/*  迁移。职责：对"谁(调用方)→谁(受保护目标)→做什么   */
/*  (desiredAccess)"的访问请求做权限决策，分类威胁、   */
/*  剥离危险访问位、记账并上报 UI。                    */
/*                                                   */
/*  与驱动端 ProcessProtection（内核 ObRegister-      */
/*  Callbacks 句柄过滤 / PPL 提升）互补：本引擎为      */
/*  用户态访问决策层。依赖驱动的活性动作（PPL 提升、   */
/*  句柄过滤、终止源处置）在本引擎保留表达与记账逻辑，  */
/*  以"待驱动桥接"占位，不影响 Agent 侧流水线。        */
/*                                                   */
/*  生命周期：PpInitialize -> (运行) -> PpCleanup。 */
/*  访问决策核心：PpFilterAccessRequest。             */
/*                                                   */
/*  全部函数 PASSIVE_LEVEL。                          */
/*  编码：UTF-8 with BOM（铁律）                     */
/**************************************************/

#pragma once

#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <stdint.h>

/* 2026-09-06 受保护进程域化：本头声明引用 wkd 进程域对象
 * （AcAllocateProcessAccessControlContextLazy 等）；类型源头为 Process 域。 */
#include "../Process/ProcessTree.h"

#ifdef __cplusplus
extern "C" {
#endif

    /**************************************************/
    /*               常量定义                           */
    /*  对齐 ShadowStrike ProcessProtectionConstants。  */
    /**************************************************/

#define PP_MAX_PROTECTED_PROCESSES      50      /* 受保护进程上限（SS MAX_PROTECTED_PROCESSES） */
#define PP_MAX_ACCESS_RULES             100     /* 访问规则上限（SS MAX_ACCESS_RULES） */
#define PP_MAX_BLOCKED_ATTEMPTS_LOG     1000    /* 阻断日志上限（SS MAX_BLOCKED_ATTEMPTS_LOG） */
#define PP_MAX_WHITELIST                256     /* 白名单调用方上限 */
#define PP_MAX_DESCRIPTION              256     /* 描述最大长度 */
#define PP_MAX_CALLBACKS                32      /* 注册回调上限（每组） */
#define PP_MAX_CONFIG_WHITELIST         32      /* 配置内联白名单上限 */
#define PP_MAX_CONFIG_PIDS              16      /* 配置内联附加保护 PID 上限 */
#define PP_MAX_IMAGE_HASH               32      /* 镜像 SHA-256 摘要长度 */
#define PP_SELF_TEST_CHECKS             4       /* 自检项数 */

/* 监测间隔（毫秒，对齐 SS MONITOR/HEALTH_CHECK） */
#define PP_MONITOR_INTERVAL_MS          5000
#define PP_HEALTH_CHECK_INTERVAL_MS     10000

/* 危险进程/线程访问位（对齐 SS DANGEROUS_*_ACCESS） */
#define PP_DANGEROUS_PROCESS_ACCESS     (PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | \
                                         PROCESS_VM_WRITE | PROCESS_VM_OPERATION |   \
                                         PROCESS_CREATE_THREAD | PROCESS_SET_INFORMATION)
#define PP_DANGEROUS_THREAD_ACCESS      (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | \
                                         THREAD_SET_CONTEXT | THREAD_SET_INFORMATION | \
                                         THREAD_SET_THREAD_TOKEN)

/* 安全进程/线程访问位（对齐 SS SAFE_*_ACCESS） */
#define PP_SAFE_PROCESS_ACCESS          (PROCESS_QUERY_INFORMATION | \
                                         PROCESS_QUERY_LIMITED_INFORMATION | \
                                         PROCESS_VM_READ | SYNCHRONIZE)
#define PP_SAFE_THREAD_ACCESS           (THREAD_QUERY_INFORMATION | \
                                         THREAD_QUERY_LIMITED_INFORMATION | \
                                         THREAD_GET_CONTEXT | SYNCHRONIZE)

/* 完整性级别常量（对齐 SS INTEGRITY_*） */
#define PP_INTEGRITY_UNTRUSTED          0x00000000
#define PP_INTEGRITY_LOW                0x00001000
#define PP_INTEGRITY_MEDIUM             0x00002000
#define PP_INTEGRITY_HIGH               0x00003000
#define PP_INTEGRITY_SYSTEM             0x00004000

/* 内核句柄告警"高度可疑"阈值（对齐 SS 机器学习高置信线 70） */
#define PP_KERNEL_ALERT_SUSPICION_THRESHOLD 70

/* 核对占位：PPL 提升 ALPC 消息类型（SS 0x00BB0001，待与驱动核对） */
#define PP_KERNEL_PPL_REQUEST_TYPE      0x00BB0001u
/* 核对占位：进程阻断 ALPC 消息类型（SS 0x00BB0002，待与驱动核对） */
#define PP_KERNEL_BLOCK_REQUEST_TYPE    0x00BB0002u

/* 保护标志（复用/扩展 AcRegisterProtectedProcess 语义） */
#define PP_PROTECT_FLAG_NONE            0x00000000
#define PP_PROTECT_FLAG_PREVENT_TERMINATION 0x00000001
#define PP_PROTECT_FLAG_PREVENT_OPEN    0x00000002
#define PP_PROTECT_FLAG_PREVENT_INJECT  0x00000004

/**************************************************/
/*               本地状态码别名                     */
/*  参照 AccessControlEngine.h 的本地别名惯例：           */
/*  ntstatus.h 在不同 SDK 覆盖度不同，统一映射到    */
/*  确定存在的 NTSTATUS 值，避免跨 SDK 编译差异。    */
/**************************************************/

#ifndef PP_STATUS_ALREADY_EXISTS
#define PP_STATUS_ALREADY_EXISTS   STATUS_UNSUCCESSFUL   /* 语义：白名单项已存在 */
#endif

/**************************************************/
/*               访问请求类型枚举                   */
/*  对齐 SS ProcessProtectionAccessRequestType。    */
/**************************************************/

typedef enum _PP_ACCESS_REQUEST_TYPE {
    PpAccessProcessOpen = 0,   /* 打开进程句柄 */
    PpAccessProcessDuplicate = 1,   /* 复制进程句柄 */
    PpAccessThreadOpen = 2,   /* 打开线程句柄 */
    PpAccessThreadDuplicate = 3,   /* 复制线程句柄 */
    PpAccessHandleDuplicate = 4,   /* 句柄复制 */
    PpAccessMemoryRead = 5,   /* 内存读取 */
    PpAccessMemoryWrite = 6,   /* 内存写入 */
    PpAccessThreadCreate = 7,   /* 创建远程线程 */
    PpAccessApcQueue = 8    /* APC 注入 */
} PP_ACCESS_REQUEST_TYPE, * PPP_ACCESS_REQUEST_TYPE;

/**************************************************/
/*               访问决策枚举                       */
/*  对齐 SS ProcessProtectionAccessDecision。       */
/**************************************************/

typedef enum _PP_ACCESS_DECISION {
    PpAccessDecisionAllow = 0,  /* 允许全部访问 */
    PpAccessDecisionAllowReduced = 1,  /* 允许但裁剪危险位 */
    PpAccessDecisionDeny = 2,  /* 拒绝访问 */
    PpAccessDecisionDenyAndAlert = 3   /* 拒绝并告警 */
} PP_ACCESS_DECISION, * PPP_ACCESS_DECISION;

/**************************************************/
/*               威胁动作枚举                       */
/*  对齐 SS ThreatAction（位域）。                  */
/**************************************************/

typedef enum _PP_THREAT_ACTION {
    PpThreatNone = 0x00000000,
    PpThreatProcessTerminate = 0x00000001,
    PpThreatProcessSuspend = 0x00000002,
    PpThreatThreadTerminate = 0x00000004,
    PpThreatThreadSuspend = 0x00000008,
    PpThreatMemoryWrite = 0x00000010,
    PpThreatMemoryAlloc = 0x00000020,
    PpThreatThreadCreate = 0x00000040,
    PpThreatApcQueue = 0x00000080,
    PpThreatHandleDuplicate = 0x00000100,
    PpThreatTokenSteal = 0x00000200,
    PpThreatContextModify = 0x00000400,
    PpThreatDebugAttach = 0x00000800
} PP_THREAT_ACTION, * PPP_THREAT_ACTION;

/**************************************************/
/*               威胁响应策略枚举                   */
/*  对齐 SS ProcessProtectionThreatResponse（位域）。*/
/**************************************************/

typedef enum _PP_THREAT_RESPONSE {
    PpResponseNone = 0x00000000,
    PpResponseLog = 0x00000001,
    PpResponseAlert = 0x00000002,
    PpResponseBlock = 0x00000004,
    PpResponseTerminateSource = 0x00000008,
    PpResponseQuarantineSource = 0x00000010,
    PpResponseEscalate = 0x00000020,
    PpResponsePassive = PpResponseLog | PpResponseAlert,
    PpResponseActive = PpResponseLog | PpResponseAlert | PpResponseBlock,
    PpResponseAggressive = PpResponseLog | PpResponseAlert | PpResponseBlock | PpResponseTerminateSource
} PP_THREAT_RESPONSE, * PPP_THREAT_RESPONSE;

/**************************************************/
/*               模块状态枚举                       */
/*  对齐 SS ModuleStatus。                          */
/**************************************************/

typedef enum _PP_MODULE_STATUS {
    PpModuleUninitialized = 0,
    PpModuleInitializing,
    PpModuleRunning,
    PpModuleStopping,
    PpModuleStopped,
    PpModuleError
} PP_MODULE_STATUS, * PPP_MODULE_STATUS;

/**************************************************/
/*               保护状态枚举                       */
/*  对齐 SS ProtectionStatus。                      */
/**************************************************/

typedef enum _PP_PROTECTION_STATUS {
    PpProtectionUnprotected = 0,
    PpProtectionUserModeOnly = 1,
    PpProtectionKernelProtected = 2,
    PpProtectionPplProtected = 3,
    PpProtectionCritical = 4
} PP_PROTECTION_STATUS, * PPP_PROTECTION_STATUS;

/**************************************************/
/*               保护类型 / 签名人                  */
/*  对齐 SS ProcessProtectionType / ProtectionSigner*/
/**************************************************/

typedef enum _PP_PROTECTION_TYPE {
    PpProtectionTypeNone = 0,   /* PS_PROTECTED_TYPE_NONE */
    PpProtectionTypeProtectedLight = 1, /* PS_PROTECTED_TYPE_PROTECTED_LIGHT */
    PpProtectionTypeProtected = 2    /* PS_PROTECTED_TYPE_PROTECTED */
} PP_PROTECTION_TYPE, * PPP_PROTECTION_TYPE;

typedef enum _PP_PROTECTION_SIGNER {
    PpProtectionSignerNone = 0,
    PpProtectionSignerAuthenticode = 1,
    PpProtectionSignerCodeGen = 2,
    PpProtectionSignerAntimalware = 3,
    PpProtectionSignerLsa = 4,
    PpProtectionSignerWindows = 5,
    PpProtectionSignerWinTcb = 6
} PP_PROTECTION_SIGNER, * PPP_PROTECTION_SIGNER;

/**************************************************/
/*               保护级别                           */
/*  对齐 SS ProcessProtectionLevel。                */
/**************************************************/

typedef struct _PP_PROTECTION_LEVEL {
    PP_PROTECTION_TYPE  Type;       /* 保护类型 */
    PP_PROTECTION_SIGNER Signer;    /* 签名人 */
    UCHAR               RawLevel;   /* 原始保护级别值 */
} PP_PROTECTION_LEVEL, * PPP_PROTECTION_LEVEL;

/* 判断是否为 PPL（对齐 SS IsPPL） */
#define PP_LEVEL_IS_PPL(_p)     ((_p).Type != PpProtectionTypeNone)
/* 判断是否为反恶意软件保护（对齐 SS IsAntimalware） */
#define PP_LEVEL_IS_ANTIMALWARE(_p) ((_p).Signer == PpProtectionSignerAntimalware)
/* 组合级别（type<<4 | signer，对齐 SS GetCombinedLevel） */
#define PP_LEVEL_COMBINED(_p)   (((ULONG)(_p).Type << 4) | (ULONG)(_p).Signer)

/* 保护级别 >= 比较（对齐 SS operator>=） */
#define PP_LEVEL_GE(_a, _b)     (PP_LEVEL_COMBINED(_a) >= PP_LEVEL_COMBINED(_b))

/**************************************************/
/* 进程缓解加固位域（2026-09-08 从 MemoryProtection
 * MpApplyProcessHardening 迁移；进程保护登记流水线
 * AcRegisterProtectedProcessInternal 消费）。     */
/* 语义：自身进程=Set 后事实；第三方进程=Get 观察事实。 */
/**************************************************/

#define PP_HARDENING_ASLR           0x00000001  /* 地址空间布局随机化 */
#define PP_HARDENING_DEP            0x00000002  /* 数据执行保护 */
#define PP_HARDENING_CFG            0x00000004  /* 控制流保护 */
#define PP_HARDENING_STRICT_HANDLE  0x00000008  /* 严格句柄检查（永久） */
#define PP_HARDENING_DYNAMIC_CODE   0x00000010  /* 动态代码策略 */
#define PP_HARDENING_SIGNATURE      0x00000020  /* 微软签名策略（SignaturePolicy） */

/**************************************************/
/*               配置结构                           */
/*  对齐 SS ProcessProtectionConfiguration。        */
/**************************************************/

typedef struct _PP_CONFIGURATION {
    /* 功能开关（对齐 SS 布尔开关） */
    BOOLEAN EnablePPL;                  /* 启用 PPL 保护（需驱动/ELAM） */
    BOOLEAN EnableHandleFiltering;      /* 启用句柄过滤 */
    BOOLEAN EnableAntiTermination;      /* 启用防终止 */
    BOOLEAN EnableAntiSuspension;       /* 启用防挂起 */
    BOOLEAN EnableAntiInjection;        /* 启用防注入 */
    BOOLEAN EnableIntegrityVerification;/* 启用完整性校验 */
    BOOLEAN SetCriticalProcess;         /* 保护时设置关键进程标志 */

    /* 进程缓解加固（2026-09-08 从 MemoryProtection 迁移）：登记受保护
     * 进程时——自身进程=施加（Set），第三方进程=校验（Get）不符告警。 */
    BOOLEAN EnableASLR;                 /* 期望 ASLR（默认 TRUE） */
    BOOLEAN EnableDEP;                  /* 期望 DEP（默认 TRUE） */
    BOOLEAN EnableCFG;                  /* 期望 CFG（默认 TRUE） */

    /* 策略 */
    PP_THREAT_RESPONSE  DefaultResponse;    /* 默认威胁响应（对齐 SS defaultResponse） */
    ULONG               BlockedProcessAccess;  /* 进程危险访问掩码 */
    ULONG               BlockedThreadAccess;   /* 线程危险访问掩码 */

    /* 运行时 */
    BOOLEAN             VerboseLogging;     /* 详细日志 */
    BOOLEAN             SendTelemetry;      /* 发送遥测 */

    /* 配置内联白名单（小写镜像名；对齐 SS whitelistedCallers） */
    WCHAR               WhitelistedCallers[PP_MAX_CONFIG_WHITELIST][PP_MAX_DESCRIPTION];
    ULONG               WhitelistedCallerCount;

    /* 配置附加保护 PID 集（对齐 SS additionalProtectedPids） */
    ULONG               AdditionalProtectedPids[PP_MAX_CONFIG_PIDS];
    ULONG               AdditionalProtectedPidCount;
} PP_CONFIGURATION, * PPP_CONFIGURATION;

/* 取默认配置（对齐 SS 默认值：全部启用，DefaultResponse=Active，
    * 危险掩码=DANGEROUS_*_ACCESS；2026-09-06 线程保护/Monitor 已移除）。PASSIVE_LEVEL */
VOID
    PpGetDefaultConfiguration(
        _Out_ PPP_CONFIGURATION Config
    );

/**************************************************/
/*               访问请求结构                       */
/*  对齐 SS ProcessProtectionAccessRequest。        */
/**************************************************/

typedef struct _PP_ACCESS_REQUEST {
    PP_ACCESS_REQUEST_TYPE  Type;               /* 访问类型 */
    ULONG                   CallerProcessId;    /* 调用方进程 ID */
    ULONG                   CallerThreadId;     /* 调用方线程 ID（对齐 SS） */
    ULONG                   TargetProcessId;    /* 目标进程 ID */
    ULONG                   TargetThreadId;     /* 目标线程 ID（对齐 SS） */
    ULONG                   DesiredAccess;      /* 请求的访问位 */
    BOOLEAN                 CallerIsWhitelisted;/* 调用方是否白名单 */
    ULONG                   CallerIntegrityLevel;   /* 调用方完整性级别（对齐 SS） */
    BOOLEAN                 CallerIsElevated;   /* 调用方是否提权（对齐 SS） */
    BOOLEAN                 CallerIsSystem;     /* 调用方是否 SYSTEM（对齐 SS） */
    PP_PROTECTION_LEVEL     CallerProtectionLevel;  /* 调用方保护级别（对齐 SS） */
    WCHAR                   CallerImagePath[PP_MAX_DESCRIPTION]; /* 调用方镜像路径/名 */
} PP_ACCESS_REQUEST, * PPP_ACCESS_REQUEST;

/**************************************************/
/*               访问决策结果                       */
/*  对齐 SS ProcessProtectionAccessDecisionResult。 */
/**************************************************/

typedef struct _PP_ACCESS_DECISION_RESULT {
    PP_ACCESS_DECISION      Decision;       /* 决策 */
    ULONG                   GrantedAccess;  /* 实际授予的访问位 */
    ULONG                   StrippedAccess; /* 被剥离的危险访问位 */
    PP_THREAT_ACTION        ThreatAction;   /* 分类威胁 */
    PP_THREAT_RESPONSE      Response;       /* 建议处置 */
    BOOLEAN                 ShouldLog;      /* 是否需要记录日志 */
    BOOLEAN                 ShouldAlert;    /* 是否需要告警 */
    WCHAR                   Reason[PP_MAX_DESCRIPTION]; /* 决策理由 */
} PP_ACCESS_DECISION_RESULT, * PPP_ACCESS_DECISION_RESULT;

/**************************************************/
/*               阻断访问事件快照                   */
/**************************************************/

typedef struct _PP_BLOCKED_ACCESS_EVENT {
    ULONG                   EventId;        /* 事件 ID */
    PP_ACCESS_REQUEST       Request;        /* 原请求 */
    PP_ACCESS_DECISION_RESULT Decision;     /* 决策 */
    PP_THREAT_ACTION        ThreatAction;   /* 威胁分类 */
    ULONG                   ResponseTaken;  /* 实际处置 */
    LARGE_INTEGER           Timestamp;      /* 时间戳 */
} PP_BLOCKED_ACCESS_EVENT, * PPP_BLOCKED_ACCESS_EVENT;

/**************************************************/
/*               受保护进程信息                     */
/*  对齐 SS ProtectedProcessInfo。                  */
/**************************************************/

typedef struct _PP_PROTECTED_PROCESS_INFO {
    ULONG                   ProcessId;          /* 进程 ID */
    WCHAR                   ImageName[PP_MAX_DESCRIPTION];  /* 镜像文件名 */
    WCHAR                   ImagePath[PP_MAX_DESCRIPTION];  /* 镜像完整路径 */
    UCHAR                   ImageHash[PP_MAX_IMAGE_HASH];   /* SHA-256（0=未计算，Agent 侧不计算） */
    PP_PROTECTION_LEVEL     ProtectionLevel;    /* 保护级别（保护时采集） */
    PP_PROTECTION_STATUS    Status;             /* 保护状态 */
    BOOLEAN                 IsWkdComponent;     /* 是否本产品组件（对齐 SS isShadowStrikeComponent） */
    BOOLEAN                 IsCritical;         /* 是否关键进程 */
    LARGE_INTEGER           ProtectedSince;     /* 保护起始时间戳 */
    ULONG                   ThreadCount;        /* 线程数 */
    ULONG                   HandleCount;        /* 句柄数 */
    ULONG                   IntegrityLevel;     /* 完整性级别 */
    ULONG                   SessionId;          /* 会话 ID */
    volatile LONG64         BlockedAttempts;    /* 被阻断次数 */
    LARGE_INTEGER           LastBlockedAttempt; /* 最近被阻断时间 */
    LARGE_INTEGER           LastVerified;       /* 最近校验时间 */
} PP_PROTECTED_PROCESS_INFO, * PPP_PROTECTED_PROCESS_INFO;

/**************************************************/
/*               统计                              */
/**************************************************/

typedef struct _PP_STATISTICS {
    volatile LONG64         TotalAccessRequests;    /* 收到的访问请求总数 */
    volatile LONG64         TotalAccessReduced;     /* 允许但裁剪次数 */
    volatile LONG64         TotalAccessBlocked;     /* 完全阻断次数 */
    volatile LONG64         ProcessTerminationBlocked;  /* 进程终止被阻 */
    volatile LONG64         SuspensionBlocked;          /* 挂起被阻 */
    volatile LONG64         MemoryWriteBlocked;         /* 内存写入被阻 */
    volatile LONG64         ThreadCreationBlocked;      /* 远程线程创建被阻 */
    volatile LONG64         HandleDuplicationBlocked;   /* 句柄复制被阻 */
    volatile LONG64         ThreadTerminationBlocked;   /* 线程终止被阻 */
    volatile LONG64         ApcInjectionBlocked;        /* APC 注入被阻 */
    volatile LONG64         KernelHandleOperations;     /* 内核句柄操作数 */
    volatile LONG64         TotalElevations;            /* PPL 提升请求数 */
    volatile LONG64         IntegrityViolations;        /* 完整性违规数 */
    volatile LONG64         AlertsRaised;               /* 告警次数（对齐 SS alertsRaised） */
    volatile LONG64         HardeningMismatchCount;     /* 加固不符告警数（2026-09-08 迁移） */
    volatile LONG           TotalProtected;    /* 受保护进程总数（累计，对齐 SS） */
    volatile LONG           ActiveProtected;      /* 当前受保护进程数 */
    volatile LONG           WhitelistCount;             /* 白名单调用方数 */
    LARGE_INTEGER           StartTime;                  /* 引擎启动时间（对齐 SS startTime） */
    LARGE_INTEGER           LastEventTime;              /* 最近事件时间（对齐 SS lastEventTime） */
} PP_STATISTICS, * PPP_STATISTICS;

/**************************************************/
/*               回调类型                           */
/*  对齐 SS 4 类回调。                              */
/**************************************************/

/* 访问决策覆盖回调：返回 TRUE 表示已覆盖（OverrideResult 生效）。 */
typedef BOOLEAN(*PP_ACCESS_DECISION_CALLBACK)(
    _In_  PPP_ACCESS_REQUEST          Request,
    _Out_ PPP_ACCESS_DECISION_RESULT  OverrideResult,
    _In_opt_ PVOID                    Context
    );

/* 阻断访问事件回调。返回 STATUS_SUCCESS 表示已消费（对齐既有编排层签名）。
    * 后缀回调可链式返回（暂保留 NTSTATUS 以兼容 SelfDefense 桥接）。 */
typedef NTSTATUS(*PP_BLOCKED_ACCESS_CALLBACK)(
    _In_ PPP_BLOCKED_ACCESS_EVENT Event,
    _In_opt_ PVOID                Context
    );

/* 保护状态变更回调。 */
typedef VOID(*PP_PROTECTION_STATUS_CALLBACK)(
    _In_ ULONG                    ProcessId,
    _In_ PP_PROTECTION_STATUS     NewStatus,
    _In_opt_ PVOID                Context
    );

/* 威胁检测回调。返回 STATUS_SUCCESS 表示已消费（对齐既有编排层签名）。 */
typedef NTSTATUS(*PP_THREAT_CALLBACK)(
    _In_ PP_THREAT_ACTION     Action,
    _In_ PPP_ACCESS_REQUEST   Request,
    _In_opt_ PVOID            Context
    );

/**************************************************/
/*               事件回调集合（初始化静态注入）      */
/**************************************************/

typedef struct _PP_CALLBACKS {
    /* 检测到阻断/告警事件时触发（对齐 NotifyBlockedAccess） */
    PP_BLOCKED_ACCESS_CALLBACK  OnBlockedAccess;
    /* 威胁分类触发时触发（对齐 NotifyThreat） */
    PP_THREAT_CALLBACK          OnThreat;
    _In_opt_ PVOID              Context; /* 透传给所有回调 */
} PP_CALLBACKS, * PPP_CALLBACKS;

/**************************************************/
/*               引擎上下文（不透明句柄）          */
/**************************************************/

typedef struct _PP_ENGINE PP_ENGINE, * PPP_ENGINE;

/**************************************************/
/*               公共 API                          */
/**************************************************/

/* 初始化进程保护决策引擎（创建上下文，不启动）。PASSIVE_LEVEL */
NTSTATUS
    PpInitialize(
        _Out_ PPP_ENGINE* Engine,
        _In_opt_ PPP_CALLBACKS Callbacks
    );

/* 释放引擎资源。NULL 安全。PASSIVE_LEVEL */
VOID
    PpCleanup(
        _In_opt_ _Post_invalid_ PPP_ENGINE Engine
    );

/* 查询引擎是否已初始化。PASSIVE_LEVEL */
BOOLEAN
    PpIsInitialized(
        _In_ PPP_ENGINE Engine
    );

/* 查询引擎状态（对齐 SS GetStatus）。PASSIVE_LEVEL */
PP_MODULE_STATUS
    PpGetStatus(
        _In_ PPP_ENGINE Engine
    );

/* ------------------------------------------------ */
/* 配置（对齐 SS SetConfiguration/GetConfiguration/  */
/*        SetDefaultResponse/SetThreatResponse）     */
/* ------------------------------------------------ */

/* 更新配置（同步白名单与附加保护 PID）。PASSIVE_LEVEL */
NTSTATUS
    PpSetConfiguration(
        _In_ PPP_ENGINE Engine,
        _In_ PPP_CONFIGURATION Config
    );

/* 获取当前配置快照。PASSIVE_LEVEL */
NTSTATUS
    PpGetConfiguration(
        _In_ PPP_ENGINE Engine,
        _Out_ PPP_CONFIGURATION Config
    );

/* 设置默认威胁响应。PASSIVE_LEVEL */
VOID
    PpSetDefaultResponse(
        _In_ PPP_ENGINE Engine,
        _In_ PP_THREAT_RESPONSE Response
    );

/* 设置特定威胁动作的响应（对齐 SS m_threatResponses）。PASSIVE_LEVEL */
VOID
    PpSetThreatResponse(
        _In_ PPP_ENGINE Engine,
        _In_ PP_THREAT_ACTION Action,
        _In_ PP_THREAT_RESPONSE Response
    );

/* ------------------------------------------------ */
/* PPL（对齐 SS ElevateToPPL/IsPPLProtected/         */
/*      GetProtectionLevelRaw/HasRequiredProtectionLevel） */
/* ------------------------------------------------ */

/* 尝试提升当前进程到 PPL（经内核驱动；Agent 侧占位）。PASSIVE_LEVEL */
BOOLEAN
    PpElevateToPPL(
        _In_ PPP_ENGINE Engine
    );

/* 查询当前进程是否已 PPL 保护。PASSIVE_LEVEL */
BOOLEAN
    PpIsPPLProtected(
        _In_ PPP_ENGINE Engine
    );

/* 获取进程原始保护级别字节。PASSIVE_LEVEL */
ULONG
    PpGetProtectionLevelRaw(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG ProcessId
    );

/* 进程是否达到要求的保护级别。PASSIVE_LEVEL */
BOOLEAN
    PpHasRequiredProtectionLevel(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG ProcessId,
        _In_ PP_PROTECTION_LEVEL Required
    );

/* ------------------------------------------------ */
/* 进程保护                                          */
/* ------------------------------------------------ */

/* 确保进程访问控制上下文存在（惰性构建, 2026-09-06 受保护进程域化）。
    * 公开入口：进程创建主动预建（Orchestrator）与注册兜底（Sdf 门面）。
    * Ctx 可选输出：构建/已存在时回填访问控制上下文指针（仍归进程对象所有）。
    * PASSIVE_LEVEL */
_Must_inspect_result_
NTSTATUS
AcAllocateProcessAccessControlContextLazy(
    _Inout_ PWKD_PROCESS WkdProcess,
    _Out_opt_ PWKD_ACCESS_CONTROL_CONTEXT* Context
    );

/* 注册受保护进程（收集信息并保护线程；对齐 SS ProtectProcess）。PASSIVE_LEVEL */
_Must_inspect_result_
NTSTATUS
AcRegisterProtectedProcessInternal(
    _Inout_opt_ PPP_ENGINE Engine,
    _Inout_ PWKD_PROCESS WkdProcess,
    _In_ ULONG ProtectionFlags
    );

/* 注销受保护进程（连带清理其受保护线程）。PASSIVE_LEVEL */
NTSTATUS
    PpUnprotectProcess(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG ProcessId
    );

/* 校验进程是否受保护。PASSIVE_LEVEL */
BOOLEAN
    PpIsProcessProtected(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG ProcessId
    );

/* 获取受保护进程详细信息（对齐 SS GetProtectedProcessInfo）。PASSIVE_LEVEL */
NTSTATUS
    PpGetProtectedProcessInfo(
        _In_  PPP_ENGINE Engine,
        _In_  ULONG ProcessId,
        _Out_ PPP_PROTECTED_PROCESS_INFO Info
    );

/* 获取全部受保护进程信息（对齐 SS GetAllProtectedProcesses）。
    *  Buffer=NULL 时返回所需条目数（*Count）。PASSIVE_LEVEL */
NTSTATUS
    PpGetAllProtectedProcesses(
        _In_      PPP_ENGINE Engine,
        _Out_writes_opt_(*Count) PPP_PROTECTED_PROCESS_INFO Buffer,
        _Inout_   PULONG Count
    );

/* 设置进程为关键进程（仅当前进程，RtlSetProcessIsCritical）。
    * 对齐 SS SetCriticalProcess。PASSIVE_LEVEL */
NTSTATUS
    PpSetCriticalProcess(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG ProcessId,
        _In_ BOOLEAN Critical
    );

/* 查询进程是否关键进程。PASSIVE_LEVEL */
BOOLEAN
    PpIsCriticalProcess(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG ProcessId
    );

/* ------------------------------------------------ */
/* 进程缓解加固（2026-09-08 从 MemoryProtection      */
/* MpApplyProcessHardening 迁移）。                   */
/* 粒度=受保护进程访问控制上下文（WKD_ACCESS_CONTROL_ */
/* CONTEXT::HardeningMask，PP_HARDENING_* 位域）：    */
/*   自身进程：Set 施加；第三方：Get 校验+不符告警。  */
/* ------------------------------------------------ */

/* 对受保护进程应用缓解加固（登记流水线 AcRegisterProtectedProcessInternal
 * 调用；EnableASLR/DEP/CFG 任一开启时执行）。
 * 自身（ProcessId==Current）：DEP/StrictHandle/DynamicCode 施加 + 全项查询；
 * 第三方：ASLR/DEP/CFG/StrictHandle/DynamicCode/Signature 全项 Get 校验，
 * 配置期望项缺失 → 统计计数 + 日志告警。结果写 ctx->HardeningMask。PASSIVE_LEVEL */
VOID
    AcApplyProcessHardening(
        _In_ PPP_ENGINE Engine,
        _In_ PWKD_PROCESS WkdProcess
    );

/* 校验并登记目标进程 ASLR 状态（Get 观测；自身亦不可运行期设置）。PASSIVE_LEVEL */
BOOLEAN
    PpEnableASLR(
        _In_ PPP_ENGINE Engine,
        _In_ PWKD_PROCESS WkdProcess
    );

/* 查询目标进程 ASLR 加固位（读 ctx->HardeningMask）。PASSIVE_LEVEL */
BOOLEAN
    PpIsASLREnabled(
        _In_ PWKD_PROCESS WkdProcess
    );

/* 登记目标进程 DEP 状态：自身=SetProcessDEPPolicy 施加（含 AlwaysOn 降级查询）；
 * 第三方=Get 观测。PASSIVE_LEVEL */
BOOLEAN
    AcpEnableDEP(
        _In_ PPP_ENGINE Engine,
        _In_ PWKD_PROCESS WkdProcess
    );

/* 查询目标进程 DEP 加固位（读 ctx->HardeningMask）。PASSIVE_LEVEL */
BOOLEAN
    PpIsDEPEnabled(
        _In_ PWKD_PROCESS WkdProcess
    );

/* 校验并登记目标进程 CFG 状态（Get 观测；编译期决定不可运行期设置）。PASSIVE_LEVEL */
BOOLEAN
    PpEnableCFG(
        _In_ PPP_ENGINE Engine,
        _In_ PWKD_PROCESS WkdProcess
    );

/* 查询目标进程 CFG 加固位（读 ctx->HardeningMask）。PASSIVE_LEVEL */
BOOLEAN
    PpIsCFGEnabled(
        _In_ PWKD_PROCESS WkdProcess
    );

/* ------------------------------------------------ */
/* 访问控制                                          */
/* ------------------------------------------------ */

/* 便捷判定：访问是否允许（对齐 SS IsAccessAllowed，决策为 Allow/AllowReduced）。PASSIVE_LEVEL */
BOOLEAN
    PpIsAccessAllowed(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG CallerProcessId,
        _In_ ULONG TargetProcessId,
        _In_ ULONG DesiredAccess
    );

/* 核心：访问过滤决策（对齐 SS FilterAccessRequest）。PASSIVE_LEVEL */
NTSTATUS
    PpFilterAccessRequest(
        _In_  PPP_ENGINE Engine,
        _In_  PPP_ACCESS_REQUEST Request,
        _Out_ PPP_ACCESS_DECISION_RESULT Result
    );

/* 威胁分类（对齐 SS ClassifyAccessRequest）。PASSIVE_LEVEL */
PP_THREAT_ACTION
    PpClassifyAccessRequest(
        _In_  PPP_ACCESS_REQUEST Request
    );

/* 剥离危险访问位（对齐 SS StripDangerousAccess，使用配置掩码）。PASSIVE_LEVEL */
ULONG
    PpStripDangerousAccess(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG DesiredAccess,
        _In_ BOOLEAN IsThread
    );

/* 设置配置中的进程危险访问掩码（对齐 SS SetBlockedProcessAccess）。PASSIVE_LEVEL */
VOID
    PpSetBlockedProcessAccess(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG AccessMask
    );

/* 设置配置中的线程危险访问掩码（对齐 SS SetBlockedThreadAccess）。PASSIVE_LEVEL */
VOID
    PpSetBlockedThreadAccess(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG AccessMask
    );

/* ------------------------------------------------ */
/* 安全描述符管理（对齐 SS ApplyRestrictiveSecurityDescriptor 系列） */
/* ------------------------------------------------ */

/* 应用限制性安全描述符（SDDL 拒绝优先 DACL，仅被保护进程）。PASSIVE_LEVEL */
NTSTATUS
    PpApplyRestrictiveSecurityDescriptor(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG ProcessId
    );

/* 获取进程安全描述符（DACL+Owner 二进制）。Buffer=NULL 时返回所需字节数（*Length）。PASSIVE_LEVEL */
NTSTATUS
    PpGetProcessSecurityDescriptor(
        _In_  PPP_ENGINE Engine,
        _In_  ULONG ProcessId,
        _Out_writes_bytes_opt_(*Length) PUCHAR Buffer,
        _Inout_ PULONG Length
    );

/* 设置进程完整性级别（TokenIntegrityLevel）。PASSIVE_LEVEL */
NTSTATUS
    PpSetProcessIntegrityLevel(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG ProcessId,
        _In_ ULONG IntegrityLevel
    );

/* 查询进程完整性级别（对齐 SS GetProcessIntegrityLevel）。PASSIVE_LEVEL */
ULONG
    PpGetProcessIntegrityLevel(
        _In_ ULONG ProcessId
    );

/* SYSTEM 进程判定（TokenUser → SYSTEM SID，对齐 SS IsSystemProcess）。PASSIVE_LEVEL */
BOOLEAN
    PpIsSystemProcess(
        _In_ ULONG ProcessId
    );

/* 进程保护级别（NtQueryInformationProcess，class 需与驱动核对）。PASSIVE_LEVEL */
PP_PROTECTION_LEVEL
    PpGetProtectionLevel(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG ProcessId
    );

/* ------------------------------------------------ */
/* 白名单管理（对齐 SS AddToWhitelist/RemoveFromWhitelist） */
/* ------------------------------------------------ */

/* 添加白名单调用方（镜像名，不区分大小写）。PASSIVE_LEVEL */
NTSTATUS
    PpAddToWhitelist(
        _In_ PPP_ENGINE Engine,
        _In_ PCWSTR ProcessName
    );

/* 移除白名单调用方。PASSIVE_LEVEL */
NTSTATUS
    PpRemoveFromWhitelist(
        _In_ PPP_ENGINE Engine,
        _In_ PCWSTR ProcessName
    );

/* 按 PID 查询是否白名单。PASSIVE_LEVEL */
BOOLEAN
    PpIsWhitelisted(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG ProcessId
    );

/* 按镜像名查询是否白名单（对齐 SS IsWhitelisted(name)）。PASSIVE_LEVEL */
BOOLEAN
    PpIsWhitelistedName(
        _In_ PPP_ENGINE Engine,
        _In_ PCWSTR ProcessName
    );

/* ------------------------------------------------ */
/* 回调管理（对齐 SS Register/Unregister 系列） */
/* ------------------------------------------------ */

/* 注册访问决策覆盖回调，返回回调 ID。PASSIVE_LEVEL */
NTSTATUS
    PpRegisterAccessCallback(
        _In_  PPP_ENGINE Engine,
        _In_  PP_ACCESS_DECISION_CALLBACK Callback,
        _In_opt_ PVOID Context,
        _Out_ PULONG64 CallbackId
    );

VOID
    PpUnregisterAccessCallback(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG64 CallbackId
    );

/* 注册阻断访问回调。PASSIVE_LEVEL */
NTSTATUS
    PpRegisterBlockedAccessCallback(
        _In_  PPP_ENGINE Engine,
        _In_  PP_BLOCKED_ACCESS_CALLBACK Callback,
        _In_opt_ PVOID Context,
        _Out_ PULONG64 CallbackId
    );

VOID
    PpUnregisterBlockedAccessCallback(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG64 CallbackId
    );

/* 注册保护状态变更回调。PASSIVE_LEVEL */
NTSTATUS
    PpRegisterProtectionStatusCallback(
        _In_  PPP_ENGINE Engine,
        _In_  PP_PROTECTION_STATUS_CALLBACK Callback,
        _In_opt_ PVOID Context,
        _Out_ PULONG64 CallbackId
    );

VOID
    PpUnregisterProtectionStatusCallback(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG64 CallbackId
    );

/* 注册威胁检测回调。PASSIVE_LEVEL */
NTSTATUS
    PpRegisterThreatCallback(
        _In_  PPP_ENGINE Engine,
        _In_  PP_THREAT_CALLBACK Callback,
        _In_opt_ PVOID Context,
        _Out_ PULONG64 CallbackId
    );

VOID
    PpUnregisterThreatCallback(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG64 CallbackId
    );

/* ------------------------------------------------ */
/* 统计 / 历史 / 报告 / 自检                         */
/* ------------------------------------------------ */

/* 取统计快照（对齐 SS GetStatistics）。PASSIVE_LEVEL */
NTSTATUS
    PpGetStatistics(
        _In_ PPP_ENGINE Engine,
        _Out_ PPP_STATISTICS Stats
    );

/* 重置统计。SS 需授权令牌，Agent 内部 API 免鉴权。PASSIVE_LEVEL */
VOID
    PpResetStatistics(
        _In_ PPP_ENGINE Engine
    );

/* 取阻断历史（最新在前，最多 maxEntries 条；对齐 SS GetBlockedAccessHistory）。PASSIVE_LEVEL */
NTSTATUS
    PpGetBlockedAccessHistory(
        _In_      PPP_ENGINE Engine,
        _In_      ULONG MaxEntries,
        _Out_writes_opt_(*Count) PPP_BLOCKED_ACCESS_EVENT Buffer,
        _Inout_   PULONG Count
    );

/* 清空阻断历史。PASSIVE_LEVEL */
VOID
    PpClearBlockedAccessHistory(
        _In_ PPP_ENGINE Engine
    );

/* 导出 JSON 报告。Buffer=NULL 时返回所需字符数（*Length，含 null）。PASSIVE_LEVEL */
NTSTATUS
    PpExportReport(
        _In_      PPP_ENGINE Engine,
        _Out_writes_opt_(*Length) PWSTR Buffer,
        _Inout_   PULONG Length
    );

/* 自检（对齐 SS SelfTest：配置有效性/级别查询/完整性查询/访问过滤）。PASSIVE_LEVEL */
BOOLEAN
    PpSelfTest(
        _In_ PPP_ENGINE Engine
    );

/* 版本字符串（对齐 SS GetVersionString）。返回静态串。PASSIVE_LEVEL */
PCWSTR
    PpGetVersionString(
        VOID
    );

/* ------------------------------------------------ */
/* 内核桥（待驱动桥接，保留对齐签名）               */
/* ------------------------------------------------ */

/* 消费内核句柄告警（对齐 SS OnKernelHandleAlert，输入来自未来驱动桥接）。PASSIVE_LEVEL */
VOID
    PpOnKernelHandleAlert(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG SourceProcessId,
        _In_ ULONG TargetProcessId,
        _In_ ULONG RequestedAccess,
        _In_ ULONG GrantedAccess,
        _In_ ULONG SuspicionScore,
        _In_ ULONG SuspiciousFlags
    );

/* 请求内核 PPL 提升（待驱动桥接→当前占位返回未实现）。PASSIVE_LEVEL */
NTSTATUS
    PpRequestKernelPplElevation(
        _In_ PPP_ENGINE Engine
    );

/* 请求内核阻断进程（待驱动桥接→当前占位返回未实现；对齐 SS RequestKernelProcessBlock）。PASSIVE_LEVEL */
NTSTATUS
    PpRequestKernelProcessBlock(
        _In_ PPP_ENGINE Engine,
        _In_ ULONG ProcessId,
        _In_ PCWSTR Reason
    );

/* ------------------------------------------------ */
/* 名称工具（对齐 SS Get*Name 系列）                 */
/* ------------------------------------------------ */

/* 威胁动作 → 可读名。PASSIVE_LEVEL */
PCWSTR
    PpThreatActionName(
        _In_ PP_THREAT_ACTION Action
    );

/* 访问请求类型 → 可读名。PASSIVE_LEVEL */
PCWSTR
    PpAccessRequestTypeName(
        _In_ PP_ACCESS_REQUEST_TYPE Type
    );

/* 决策结果 → 可读名。PASSIVE_LEVEL */
PCWSTR
    PpDecisionName(
        _In_ PP_ACCESS_DECISION Decision
    );

/* 保护类型 → 可读名。PASSIVE_LEVEL */
PCWSTR
    PpProtectionTypeName(
        _In_ PP_PROTECTION_TYPE Type
    );

/* 保护签名人 → 可读名。PASSIVE_LEVEL */
PCWSTR
    PpProtectionSignerName(
        _In_ PP_PROTECTION_SIGNER Signer
    );

/* 保护状态 → 可读名。PASSIVE_LEVEL */
PCWSTR
    PpProtectionStatusName(
        _In_ PP_PROTECTION_STATUS Status
    );

/* 授权访问位格式化为可读串（对齐 SS FormatAccessRights）。PASSIVE_LEVEL */
VOID
    PpFormatAccessRights(
        _In_ ULONG AccessRights,
        _In_ BOOLEAN IsThread,
        _Out_writes_(BufferChars) PWSTR Buffer,
        _In_ ULONG BufferChars
    );

#ifdef __cplusplus
}
#endif