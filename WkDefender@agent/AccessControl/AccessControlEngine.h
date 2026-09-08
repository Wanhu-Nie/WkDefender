/**************************************************/
/*  WkDefender Agent — 自保护子系统公共头            */
/*  自保护（SelfProtection）子系统：用户态主动防御     */
/*   + 消费驱动端上报的自保护/安全事件。              */
/*  此头为整个子系统的公共契约：枚举、常量、回调、    */
/*  与驱动端对齐的事件子类型定义。                    */
/*                                                   */
/*  架构定位（2026-09-01 纯 C 重写 ShadowStrike       */
/*   SelfDefense/AntiDebug 迁移；2026-09-05 编排门面   */
/*   SelfDefense.h 并入，收敛为子系统唯一公共头）：    */
/*   - 编排层门面（Sdf* API）+ 反调试检测引擎          */
/*     (AntiDebug)，均不依赖 C++/SS 私有工具链。      */
/*   - 消费驱动端 WkdAlpcMessage_SecurityEvent(0x300D) */
/*     载荷 = WKD_MESSAGE_BODY_SECURITY_EVENT。        */
/*   - 主动检测告警经 WkdAlpcSendToUi 的                */
/*     WkdAlpcMsg_SecurityNotification(0x6004) 上报 UI。*/
/*                                                   */
/*  编码：UTF-8 with BOM（铁律）                     */
/**************************************************/

#pragma once

#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <stdint.h>

#include "../WkDefenderHeader.h"
#include "AntiDebug.h"
#include "ProcessProtection.h"
#include "MemoryProtection.h"

/* 说明：本头为自保护子系统唯一公共头（2026-09-05 并入
 * 原 SelfDefense.h 编排门面）。三个引擎头在此被包含：
 * Sdf* API 引用的 PAC_ANTIDEBUG_PROTECTION/PPP_ENGINE/PAC_MEMORY_INTEGRITY_ENGINE 等
 * 类型定义于其中；引擎头不再反向包含本头。 */

#ifdef __cplusplus
extern "C" {
#endif

    /**************************************************/
/*              版本标识                           */
/**************************************************/

#define WKD_SELF_PROTECTION_VERSION_MAJOR   1
#define WKD_SELF_PROTECTION_VERSION_MINOR   0
#define WKD_SELF_PROTECTION_VERSION_PATCH   0

/**************************************************/
/*  与驱动端对齐的自保护事件子类型（EventSubType）  */
/*  —— 必须与 driver SelfProtection 各模块一致，    */
/*     不得改动，否则 Agent 无法正确归类告警。      */
/**************************************************/

/* 回调篡改（CallbackProtection 模块） */
#define SP_EVENT_SUBTYPE_CALLBACK_TAMPER      0x5001   /* 回调完整性篡改 */

/* 驱动防卸载（AntiUnload 模块） */
#define SP_EVENT_SUBTYPE_ANTIUNLOAD           0x5002   /* 驱动卸载尝试 */

/* 防调试（AntiDebug 模块，AD） */
#define SP_EVENT_SUBTYPE_KERNEL_DEBUGGER      0x5010   /* 内核调试器 */
#define SP_EVENT_SUBTYPE_USER_DEBUGGER        0x5011   /* 用户态调试器 */
#define SP_EVENT_SUBTYPE_HYPERVISOR           0x5012   /* 虚拟化/Hypervisor */
#define SP_EVENT_SUBTYPE_DRIVER_VERIFIER      0x5013   /* 驱动验证器 */
#define SP_EVENT_SUBTYPE_MEMORY_DUMP          0x5014   /* 完整内存转储 */

/* 完整性监控（IntegrityMonitor 模块，IM） */
#define SP_EVENT_SUBTYPE_IM_BASE              0x5020   /* IM 子类型段起始 */

/* 注册表保护（RegistryProtection 模块，RG） */
#define SP_EVENT_SUBTYPE_REG_BASE             0x5030   /* RG 子类型段起始 */

/* 进程保护决策引擎（ProcessProtection 模块，PP） */
#define SP_EVENT_SUBTYPE_PP_BASE              0x5040   /* PP 子类型段起始 */
#define SP_EVENT_SUBTYPE_PP_ACCESS_BLOCKED    0x5041   /* 访问被阻断（危险访问剥离/拒绝） */
#define SP_EVENT_SUBTYPE_PP_THREAT            0x5042   /* 威胁分类触发 */
#define SP_EVENT_SUBTYPE_PP_KERNEL_ALERT      0x5043   /* 内核句柄高可疑告警 */
#define SP_EVENT_SUBTYPE_PP_INTEGRITY         0x5044   /* 受保护进程完整性校验失败 */

/* 内存保护引擎（MemoryProtection 模块，MP） */
#define SP_EVENT_SUBTYPE_MP_BASE              0x5050   /* MP 子类型段起始 */
#define SP_EVENT_SUBTYPE_MP_INTEGRITY         0x5051   /* 受保护内存区域完整性违规 */
#define SP_EVENT_SUBTYPE_MP_MEMORY_WRITE      0x5052   /* 关键内存写入/权限变更被拦截 */
#define SP_EVENT_SUBTYPE_MP_HOOK              0x5053   /* 内联 hook 特征检测 */
#define SP_EVENT_SUBTYPE_MP_HEAP_CORRUPTION   0x5054   /* 堆损坏 */
#define SP_EVENT_SUBTYPE_MP_DUMP_ATTEMPT      0x5056   /* 进程内存转储尝试被拦截 */

/**************************************************/
/*               严重程度常量                       */
/**************************************************/

#define SP_SEVERITY_LOW       1
#define SP_SEVERITY_MEDIUM    5
#define SP_SEVERITY_HIGH      8
#define SP_SEVERITY_CRITICAL  10

/**************************************************/
/*               保护级别枚举                       */
/*  对齐 ShadowStrike SelfDefense ProtectionLevel  */
/**************************************************/

typedef enum _SELF_PROTECTION_LEVEL {
    SpProtectionPassive = 0,      /* 仅记录，不采取主动动作 */
    SpProtectionMinimum,          /* 最低：仅关键进程/关键文件 */
    SpProtectionStandard,         /* 标准（默认）：常见保护全面开启 */
    SpProtectionAggressive,       /* 激进：加强检测与响应 */
    SpProtectionParanoid,         /* 偏执：最大限度保护，可能影响性能 */
    SpProtectionLevelCount
} SELF_PROTECTION_LEVEL, * PSELF_PROTECTION_LEVEL;

/**************************************************/
/*               保护组件枚举                       */
/*  对齐 ShadowStrike 8 大类保护。                  */
/**************************************************/

typedef enum _SP_COMPONENT {
    SpComponentProcess = 0,       /* 进程保护 */
    SpComponentService,           /* 服务保护 */
    SpComponentDriver,            /* 驱动保护 */
    SpComponentFile,              /* 文件保护 */
    SpComponentRegistry,          /* 注册表保护 */
    SpComponentMemory,            /* 内存保护 */
    SpComponentWatchdog,          /* 看门狗 */
    SpComponentAccessControl,     /* 访问控制 */
    SpComponentAntiDebug,         /* 反调试（Agent 主动引擎） */
    SpComponentCount
} SP_COMPONENT, * PSP_COMPONENT;

/**************************************************/
/*               威胁响应策略枚举                   */
/*  对齐 ShadowStrike ThreatResponsePolicy。        */
/**************************************************/

typedef enum _SP_THREAT_RESPONSE {
    SpThreatIgnore = 0,           /* 忽略 */
    SpThreatAlert,                /* 仅告警（UI 通知 + 日志） */
    SpThreatBlock,                /* 阻断（禁止操作） */
    SpThreatTerminate,            /* 终止（终止关联进程） */
    SpThreatKillProcess,          /* 强制结束进程 */
    SpThreatResponseCount
} SP_THREAT_RESPONSE, * PSP_THREAT_RESPONSE;

/**************************************************/
/*               自保护事件回调                     */
/*  Agent 主动检测到自保护/反调试威胁时触发，         */
/*  由编排层向 UI 上报（WkdAlpcSendToUi 0x6004）。  */
/**************************************************/

typedef struct _SP_EVENT_INFO {
    ULONG           EventSubType;           /* SP_EVENT_SUBTYPE_* */
    ULONG           Severity;               /* 1-10 */
    ULONG           Category;               /* 事件类别（预留） */
    HANDLE          ProcessId;              /* 相关进程 ID */
    WCHAR           ProcessName[64];        /* 相关进程名 */
    WCHAR           Description[256];       /* 描述 */
    LARGE_INTEGER   Timestamp;              /* 时间戳 */
} SP_EVENT_INFO, * PSP_EVENT_INFO;

/*
 * 自保护事件回调：模块向编排层上报检测到的事件。
 * 参数：EventSubType/Severity/Description（Unicode，最长 256）。
 * 返回：NTSTATUS。
 */
typedef NTSTATUS(*SP_EVENT_CALLBACK)(
    _In_ ULONG          EventSubType,
    _In_ ULONG          Severity,
    _In_ PCWSTR         Description
    );

/**************************************************/
/*               公共函数声明                       */
/**************************************************/

/* 判断子类型是否属于自保护子系统（驱动端分配段）。 */
BOOLEAN
    SpIsSelfProtectionSubType(
        _In_ ULONG EventSubType
    );

/* 将驱动端 SecurityEvent 子类型映射为可读事件名。 */
PCWSTR
    SpSubTypeToName(
        _In_ ULONG EventSubType
    );

/**************************************************/
/*               常量定义（编排层）                 */
/*  2026-09-05 由原 SelfDefense.h 并入。           */
/**************************************************/

#define SDF_MAX_PROTECTED_PROCESSES     256     /* 受保护进程表上限 */
#define SDF_MAX_AUTH_TOKEN_LENGTH       128     /* 授权令牌最大长度（字节） */
#define SDF_AUTH_HASH_LENGTH            32      /* HMAC-SHA256 输出 32 字节 */
#define SDF_WATCHDOG_DEFAULT_INTERVAL_MS 30000  /* 看门狗默认心跳间隔 */
#define SDF_MAX_CALLBACKS               8       /* 事件回调注册上限 */

/**************************************************/
/*               组件开关位图                       */
/**************************************************/

typedef struct _SP_COMPONENT_FLAGS {
    ULONG Process : 1;   /* SpComponentProcess */
    ULONG Service : 1;   /* SpComponentService */
    ULONG Driver : 1;   /* SpComponentDriver */
    ULONG File : 1;   /* SpComponentFile */
    ULONG Registry : 1;   /* SpComponentRegistry */
    ULONG Memory : 1;   /* SpComponentMemory */
    ULONG Watchdog : 1;   /* SpComponentWatchdog */
    ULONG AccessControl : 1;   /* SpComponentAccessControl */
    ULONG AntiDebug : 1;   /* SpComponentAntiDebug */
    ULONG Reserved : 23;
} SP_COMPONENT_FLAGS, * PSP_COMPONENT_FLAGS;

/**************************************************/
/*               受保护进程保护标志位域              */
/* 2026-09-06 受保护进程域化：SELF_PROTECTED_PROCESS   */
/* 记录结构已删，位域经 Sdf 门面写入 WKD_PROCESS::      */
/* AccessControlContext.ProtectionFlags。                      */
/**************************************************/

#define SP_PROTECT_FLAG_NONE        0x00000000
#define SP_PROTECT_FLAG_PREVENT_TERMINATION 0x00000001  /* 禁止终止 */
#define SP_PROTECT_FLAG_PREVENT_OPEN        0x00000002  /* 禁止句柄打开 */
#define SP_PROTECT_FLAG_PREVENT_INJECT      0x00000004  /* 禁止注入 */
/* 子能力位（2026-09-06 策略 Y：进程为防护容器，位域按等级控制子能力开关） */
#define SP_PROTECT_FLAG_HIDE_THREADS        0x00000008  /* 线程 HideFromDebugger（Sdf→Ad 引擎） */
#define SP_PROTECT_FLAG_CODE_INTEGRITY      0x00000010  /* 模块代码完整性（AcEnableCodeIntegrityProtection） */
#define SP_PROTECT_FLAG_HEAP_CANARY         0x00000020  /* 堆金丝雀/终止于损坏（引擎级能力声明） */
#define SP_PROTECT_FLAG_ANTI_DEBUG          0x00000040  /* 反调试全套（清断点 + CRC32） */

/**************************************************/
/*               威胁响应策略映射                   */
/**************************************************/

typedef struct _SP_THREAT_RESPONSE_MAP {
    ULONG   ComponentMask;          /* SP_COMPONENT 位图掩码 */
    SP_THREAT_RESPONSE Response;    /* 该组件的响应策略 */
} SP_THREAT_RESPONSE_MAP, * PSP_THREAT_RESPONSE_MAP;

/**************************************************/
/*               状态 / 统计                       */
/**************************************************/

typedef struct _SP_STATE_BLOCK {
    SELF_PROTECTION_LEVEL ProtectionLevel;   /* 当前保护级别 */
    SP_COMPONENT_FLAGS  EnabledComponents; /* 已启用组件 */
    BOOLEAN             Running;           /* 编排是否在运行 */
    BOOLEAN             Paused;            /* 是否暂停 */
    ULONG               ActiveProtected;   /* 受保护进程数 */
    LARGE_INTEGER       StartTime;          /* 编排启动时间 */
    LARGE_INTEGER       LastHeartbeat;      /* 最近心跳 */
    ULONG               HeartbeatMissCount; /* 心跳丢失计数 */
} SP_STATE_BLOCK, * PSP_STATE_BLOCK;

typedef struct _SP_STATISTICS {
    volatile LONG64     TotalEvents;        /* 上报事件总数 */
    volatile LONG64     TotalAlerts;        /* 告警总数 */
    volatile LONG64     TotalBlocks;        /* 阻断总数 */
    volatile LONG64     TotalTamperAttempts; /* 篡改尝试总数（驱动端事件） */
    volatile LONG64     TotalSelfChecks;    /* 自检次数 */
    ULONG               WatchdogStartCount; /* 看门狗重启次数 */
    LARGE_INTEGER       LastEventTime;
} SP_STATISTICS, * PSP_STATISTICS;

/**************************************************/
/*               看门狗状态                        */
/**************************************************/

typedef enum _SP_WATCHDOG_STATE {
    SpWatchdogStopped = 0,
    SpWatchdogRunning,
    SpWatchdogRecovering,
    SpWatchdogFailed
} SP_WATCHDOG_STATE, * PSP_WATCHDOG_STATE;

/**************************************************/
/*               脚本/授权令牌                      */
/*  对齐 SS 授权令牌（HMAC-SHA256）。骨架：          */
/*  SdfSetAuthToken 设置密钥，SdfVerifyAuthToken    */
/*  校验 bearer token 是否由该密钥签发。            */
/**************************************************/

typedef struct _SP_AUTH_TOKEN {
    UCHAR   Data[SDF_AUTH_HASH_LENGTH];  /* HMAC-SHA256 结果 */
    ULONG   DataLength;                  /* 实际长度 */
} SP_AUTH_TOKEN, * PSP_AUTH_TOKEN;

/**************************************************/
/*               编排上下文（不透明句柄）          */
/**************************************************/

typedef struct _ACCESS_CONTROL_ENGINE ACCESS_CONTROL_ENGINE, * PACCESS_CONTROL_ENGINE;

/**************************************************/
/*               公共 API（编排层）                 */
/**************************************************/

/* 初始化自保护编排（创建唯一全局引擎上下文、加载默认策略，不启动）。
 * 单例契约（2026-09-08）：创建成功后模块内部登记为全局对象，跨 TU 消费方
 * 经 AcGetAccessControlEngine 获取；PASSIVE_LEVEL */
NTSTATUS
SpInitializeSelfProtectionEngine(
    _In_ SELF_PROTECTION_LEVEL Level
    );

/* 启动自保护编排（启动看门狗、反调试监测、应用组件），作用于全局引擎。
 * PASSIVE_LEVEL */
NTSTATUS
AcStartAccessControlEngine(
    VOID
    );

/* 暂停编排（停止主动检测但保留上下文）。PASSIVE_LEVEL */
NTSTATUS
    SdfPause(
        VOID
    );

/* 恢复编排。PASSIVE_LEVEL */
NTSTATUS
    SdfResume(
        VOID
    );

/* 设置保护级别（影响默认组件开关与响应阈值）。PASSIVE_LEVEL */
NTSTATUS
    SdfSetProtectionLevel(
        _In_ SELF_PROTECTION_LEVEL Level
    );

/* 查询当前保护级别。返回 SpProtectionPassive（全局引擎不可用时）。PASSIVE_LEVEL */
SELF_PROTECTION_LEVEL
    SdfGetProtectionLevel(
        VOID
    );

/* 按保护等级取默认能力位集合（policy 位域映射，2026-09-06 策略 Y）。
 * 语义对齐 SpApplyDefaultComponents 组件开关：Passive 全关、Minimum 仅
 * 进程+反调试、Standard 起全位。PASSIVE_LEVEL */
ULONG
SdfGetDefaultProtectionFlags(
    _In_ SELF_PROTECTION_LEVEL Level
    );

/* 对指定线程实施 HideFromDebugger（经 Ad 引擎；ThreadId=0 表示当前线程）。
 * HIDE_THREADS 位按进程枚举现存线程的分发入口。PASSIVE_LEVEL */
NTSTATUS
SdfApplyAntiDebugToThread(
    _In_ ULONG ThreadId
    );

/* 启用组件。PASSIVE_LEVEL */
NTSTATUS
    SdfEnableComponent(
        _In_ SP_COMPONENT Component
    );

/* 禁用组件。PASSIVE_LEVEL */
NTSTATUS
    SdfDisableComponent(
        _In_ SP_COMPONENT Component
    );

/* 查询组件是否启用（全局引擎不可用时视为不启用）。PASSIVE_LEVEL */
BOOLEAN
    SdfIsComponentEnabled(
        _In_ SP_COMPONENT Component
    );

/* 设置某类组件的威胁响应策略。PASSIVE_LEVEL */
NTSTATUS
    SdfSetThreatResponse(
        _In_ ULONG ComponentMask,
        _In_ SP_THREAT_RESPONSE Response
    );

/* 注册自防护事件回调（供 UI 上报接入）。PASSIVE_LEVEL */
NTSTATUS
    SdfRegisterEventCallback(
        _In_ SP_EVENT_CALLBACK Callback,
        _In_opt_ PVOID Context
    );

/* 反调试引擎句柄获取（供门户/集成接入）。PASSIVE_LEVEL */
NTSTATUS
    SdfGetAntiDebugEngine(
        _Out_ PAC_ANTIDEBUG_PROTECTION* AntiDebugEngine
    );

/* 进程保护决策引擎句柄获取（供门户/集成接入）。PASSIVE_LEVEL */
NTSTATUS
    SdfGetProcessProtectionEngine(
        _Out_ PPP_ENGINE* ProcessProtectionEngine
    );

/* 内存保护引擎句柄获取（供门户/集成接入）。PASSIVE_LEVEL */
NTSTATUS
    SdfGetMemoryProtectionEngine(
        _Out_ PAC_MEMORY_INTEGRITY_ENGINE* MemoryProtectionEngine
    );

/* 便捷封装：对访问请求做进程保护过滤决策（桥接 PpFilterAccessRequest，
    *  并将阻断/威胁事件经编排层告警上报）。PASSIVE_LEVEL */
NTSTATUS
    SdfFilterProcessAccess(
        _In_ PPP_ACCESS_REQUEST Request,
        _Out_ PPP_ACCESS_DECISION_RESULT Result
    );

/**************************************************/
/*          消费驱动端 SecurityEvent               */
/*  由 Agent ALPC 路由 [0x300D] 调用。            */
/**************************************************/

/* 消费驱动端上报的一条 SecurityEvent（WKD_MESSAGE_BODY_SECURITY_EVENT）。
    *  归类子类型 → 升级统计 → 触发事件回调上报 UI。PASSIVE_LEVEL */
NTSTATUS
    SdfIngestSecurityEvent(
        _In_ ULONG EventSubType,
        _In_ ULONG Severity,
        _In_opt_ PCWSTR Description
    );

/* 主动上报一条自保护/反调试告警（内部经 SP_EVENT_CALLBACK 走 UI）。PASSIVE_LEVEL */
NTSTATUS
    SdfNotifyAlert(
        _In_ ULONG EventSubType,
        _In_ ULONG Severity,
        _In_opt_ PCWSTR Description
    );

/* 对当前线程应用反调试防护（便捷封装 AdApplyThreadProtection）。PASSIVE_LEVEL */
NTSTATUS
    SdfApplyAntiDebugToCurrentThread(
        VOID
    );

/**************************************************/
/*               看门狗 / 心跳                     */
/**************************************************/

/* 手动记录一次心跳（外部系统存活校验）。PASSIVE_LEVEL */
NTSTATUS
    SdfHeartbeat(
        VOID
    );

/* 查询看门狗状态。PASSIVE_LEVEL */
SP_WATCHDOG_STATE
    SdfGetWatchdogState(
        VOID
    );

/**************************************************/
/*               状态 / 统计 / 自检                */
/**************************************************/

/* 取编排状态快照。PASSIVE_LEVEL */
NTSTATUS
    SdfGetState(
        _Out_ PSP_STATE_BLOCK State
    );

/* 取统计快照。PASSIVE_LEVEL */
NTSTATUS
    SdfGetStatistics(
        _Out_ PSP_STATISTICS Stats
    );

/* 执行自检（本进程受保护状态、自身代码节完整性），
    *  返回是否通过。PASSIVE_LEVEL */
BOOLEAN
    SdfSelfCheck(
        _Out_opt_ PULONG FailedChecks
    );

/**************************************************/
/*               受保护进程 / 内存管理             */
/**************************************************/

/* 注册受保护进程（禁止终止/打开/注入）。
 *  Profile：进程类型（AdPolicyProfileEdr/SystemService/Normal），结合
 *   AntidebugMask 决定反调试检测 policy：AntidebugMask=AD_MASK_ALL（全位）
 *   时按 Profile 取默认（AdGetDefaultMask，EDR/系统服务=全激活、普通=去
 *   自省位）；其余任意值（含 AD_MASK_NONE=0 全关闭）为显式最终位图，Profile
 *   仅作记账（2026-09-07 废除 0=全激活哨兵，位图即最终使能）。
 *   EF：ProtectionFlags 沿用 SP_PROTECT_FLAG_*。PASSIVE_LEVEL */
_Must_inspect_result_
NTSTATUS
AcRegisterProtectedProcess(
    _In_ HANDLE ProcessId,
    _In_ ULONG ProtectionFlags,
    _In_ AD_POLICY_PROFILE Profile,
    _In_ ULONG64 AntidebugMask
    );

/* 枚举受保护进程链（2026-09-06 编排层所有；PP_ENGINE 未来取消，受保护进程
 * 枚举改经编排层链数据面）。Shared 锁内逐个 Reference，调用方须逐个
 * PsDereferenceWkdProcess。Buffer=NULL 时返回所需条目数（*Count）。
 * Capacity 为缓冲容量（计数模式传 0）：计数超容返回 STATUS_BUFFER_TOO_SMALL，
 * *Count 恒为所需条目数。PASSIVE_LEVEL */
NTSTATUS
AcEnumerateProtectedProcessPtrs(
    _Out_writes_opt_(Capacity) PWKD_PROCESS* Buffer,
    _In_ ULONG Capacity,
    _Out_ PULONG Count
    );

/* 注销受保护进程。PASSIVE_LEVEL */
NTSTATUS
    SdfUnprotectProcess(
        _In_ HANDLE ProcessId
    );

/* 进程退出强制注销（2026-09-06 受保护进程域化）：WkdEvent_ProcessExit 分发
 * 调用，直接收进程域对象指针规避 PID 复用竞态；摘受保护进程链 + 清权威状态
 * 不发事件。PASSIVE_LEVEL */
NTSTATUS
    SdfForceUnprotectProcessObject(
        _Inout_ PWKD_PROCESS Proc
    );

/* 进程创建主动构建访问控制上下文（Orchestrator ProcessCreate 挂点，
 * 2026-09-06）：预建后注册保护路径仅惰性兜底。PASSIVE_LEVEL */
NTSTATUS
    SdfEnsureAccessControlContextObject(
        _Inout_ PWKD_PROCESS Proc
    );

/* 全局自保护引擎获取（读取语义，2026-09-08 单例化修复：不再清空全局）。
 * 单例对象由 SpInitializeSelfProtectionEngine 在模块内登记，生命周期即
 * agent 进程生命周期；跨 TU（main/AntiDebug/ProcessProtection/
 * MemoryProtection/Engine）统一经此取实体。PASSIVE_LEVEL */
PACCESS_CONTROL_ENGINE
AcGetAccessControlEngine(
    VOID
    );

/**************************************************/
/*               授权令牌（骨架）                  */
/**************************************************/

/* 设置授权密钥（HMAC-SHA256 用）。PASSIVE_LEVEL */
NTSTATUS
    SdfSetAuthKey(
        _In_reads_bytes_(KeyLength) const UCHAR* Key,
        _In_ ULONG KeyLength
    );

/* 校验 bearer token 是否由当前密钥签发。PASSIVE_LEVEL */
BOOLEAN
    SdfVerifyAuthToken(
        _In_ PSP_AUTH_TOKEN Token
    );

/**************************************************/
/*               本地状态码别名                     */
/*  ntstatus.h 在不同 SDK 版本中覆盖度不同，         */
/*  自保护子系统统一使用本地别名，映射到确定存在     */
/*  的 NTSTATUS 值，避免跨 SDK 编译差异。           */
/**************************************************/

#ifndef SP_STATUS_ALREADY_RUNNING
#define SP_STATUS_ALREADY_RUNNING   STATUS_UNSUCCESSFUL   /* 语义：已在运行 */
#endif

#ifndef SP_STATUS_INVALID_STATE
#define SP_STATUS_INVALID_STATE     STATUS_UNSUCCESSFUL   /* 语义：状态非法 */
#endif

#ifdef __cplusplus
}
#endif
