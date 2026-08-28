/**************************************************/
/*  WkDefender — 排除子系统内部接口                  */
/*                                                   */
/*  私有头文件：仅 Exempts 子系统的 7 个 .c 编译单元  */
/*  包含。集中定义 EXEMPT_ENGINE 全局结构体与各组件   */
/*  上下文，实现"门面集中持有各组件状态"。            */
/*  外部模块只依赖 Exempts.h（门面接口）。            */
/*                                                   */
/*  职责划分:                                        */
/*    Exempts.c          — 门面/管理引擎（唯一对外） */
/*    ExemptsManager.c   — 纯存储仓库（统一规则表）  */
/*    ExemptHash.c       — 哈希判定逻辑             */
/*    ExemptPath.c       — 无状态路径算法            */
/*    ExemptCert.c       — 证书/发布者判定           */
/*    ExemptPush.c       — 系统组件采集 + ALPC 推送  */
/*    ExemptInjection.c  — 注入场景豁免              */
/*    ExemptProcess.c    — 进程身份豁免（无镜像假进程）*/
/**************************************************/

#ifndef WKD_AGENT_EXEMPTS_INTERNAL_H
#define WKD_AGENT_EXEMPTS_INTERNAL_H

#include "Exempts.h"

#include "../Utils.h"        /* UtHeapAlloc / UtHeapFree */
#include "../TextSanitize.h" /* TxtSanitizeForDisplay */

/**************************************************/
/*                  内部常量                        */
/**************************************************/

/* 子系统状态机（集中于 EXEMPT_ENGINE.State） */
#define EXEMPT_STATE_UNINITIALIZED   0
#define EXEMPT_STATE_INITIALIZING     1
#define EXEMPT_STATE_READY            2
#define EXEMPT_STATE_SHUTTING_DOWN    3

/* 规则存储上限（量级小，固定上限防滥用增长） */
#define EXEMPT_MAX_RULES             4096

/* ALPC 推送版本号初值 */
#define EXEMPT_PUSH_VERSION_INIT     1

/**************************************************/
/*                  存储仓库结构                    */
/**************************************************/

/* 纯存储仓库：统一规则数组（Type 区分四维），CRITICAL_SECTION 保护 */
typedef struct _EXEMPT_MANAGER {
    CRITICAL_SECTION Lock;      /* 全局锁（读共享/写独占，用户态 CRITICAL_SECTION） */
    PEXEMPT_RULE Rules;         /* 规则动态数组 */
    UINT64 RuleCount;           /* 有效规则数 */
    UINT64 RuleCapacity;        /* 数组容量 */
    UINT64 NextRuleId;          /* 自增规则 ID */
    BOOLEAN Initialized;
} EXEMPT_MANAGER, *PEXEMPT_MANAGER;

/**************************************************/
/*                  子系统全局结构                  */
/**************************************************/

/* 门面 Exempts.c 持有唯一实例，组件函数以 PEXEMPT_ENGINE 首参访问 */
typedef struct _EXEMPT_ENGINE {
    volatile LONG State;        /* 子系统状态机（EXEMPT_STATE_*） */
    BOOLEAN Enabled;            /* 启用标志 */
    EXEMPT_MANAGER Manager;     /* 内嵌存储仓库 */
    UINT64 PushVersion;         /* ALPC 推送版本号（单调递增） */
} EXEMPT_ENGINE, *PEXEMPT_ENGINE;

/**************************************************/
/*              组件函数原型（内部）                 */
/*  全部参数化 PEXEMPT_ENGINE，由门面持有并传入     */
/**************************************************/

/*---------------------------------------------------------------------------
 * ExemptsManager.c — 纯存储仓库
 *---------------------------------------------------------------------------*/

NTSTATUS
ExemptsMgr_Initialize(
    _Inout_ PEXEMPT_ENGINE Engine
    );

VOID
ExemptsMgr_Shutdown(
    _Inout_ PEXEMPT_ENGINE Engine
    );

/* 添加规则（四维通用），去重幂等。IsNew 输出是否新插入 */
NTSTATUS
ExemptsMgr_AddRule(
    _Inout_ PEXEMPT_ENGINE Engine,
    _In_    PEXEMPT_RULE    Rule,
    _Out_opt_ PBOOLEAN      IsNew
    );

/* 按 RuleId 移除 */
VOID
ExemptsMgr_RemoveRule(
    _Inout_ PEXEMPT_ENGINE Engine,
    _In_ UINT64 RuleId
    );

/* 按哈希移除（哈希层） */
VOID
ExemptsMgr_RemoveHashRule(
    _Inout_ PEXEMPT_ENGINE Engine,
    _In_ PDEF_SHA256_HASH   Hash
    );

/* 按模式移除（路径/证书/发布者层，type+pattern+mode 定位） */
VOID
ExemptsMgr_RemovePatternRule(
    _Inout_ PEXEMPT_ENGINE Engine,
    _In_ UINT8 Type,
    _In_ PCWSTR Pattern,
    _In_ UINT8 MatchMode
    );

/* 按类型清空（ExemptRule_MaxValue=全部） */
VOID
ExemptsMgr_ClearRules(
    _Inout_ PEXEMPT_ENGINE Engine,
    _In_ UINT8 Type
    );

/* 哈希规则查找（活跃校验：enabled + 未过期） */
BOOLEAN
ExemptsMgr_FindHashRule(
    _In_  PEXEMPT_ENGINE Engine,
    _In_  PDEF_SHA256_HASH Hash,
    _Out_opt_ PEXEMPT_RULE Out
    );

/* 路径规则查找（活跃校验 + 路径匹配） */
BOOLEAN
ExemptsMgr_FindPathRule(
    _In_  PEXEMPT_ENGINE Engine,
    _In_  PCWSTR Path,
    _In_  UINT8 Mode,
    _Out_opt_ PEXEMPT_RULE Out
    );

/* 证书/发布者规则查找（活跃校验 + 指纹/名称匹配） */
BOOLEAN
ExemptsMgr_FindPatternRule(
    _In_  PEXEMPT_ENGINE Engine,
    _In_  UINT8 Type,
    _In_  PCWSTR Pattern,
    _Out_opt_ PEXEMPT_RULE Out
    );

/* 全量快照（堆分配数组，调用方 UtHeapFree；Count 返回有效数） */
NTSTATUS
ExemptsMgr_GetRules(
    _In_  PEXEMPT_ENGINE Engine,
    _Out_ PEXEMPT_RULE*  OutRules,
    _Out_ PULONG         Count
    );

/* 指定类型规则数（ExemptRule_MaxValue=全部） */
UINT64
ExemptsMgr_GetRuleCount(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ UINT8 Type
    );

/* 惰性过期清理（查询路径内置调用） */
VOID
ExemptsMgr_CleanupExpired(
    _Inout_ PEXEMPT_ENGINE Engine
    );

/*---------------------------------------------------------------------------
 * ExemptHash.c — 哈希判定逻辑
 *---------------------------------------------------------------------------*/

/* 哈希规则命中判定（门面转发，内部查 Manager） */
BOOLEAN
ExemptHash_IsWhitelisted(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PDEF_SHA256_HASH Hash
    );

/*---------------------------------------------------------------------------
 * ExemptPath.c — 无状态路径算法（纯函数，零全局状态）
 *---------------------------------------------------------------------------*/

/* 路径归一化（防绕过：小写折叠 + \→/ + 去尾斜杠 + . / .. 解析 + ADS 剥离）。
 * 短名(GetLongPathNameW)/NFC 归一化依赖标注为可选（agent 查询路径来自内核镜像，
 * 已为规范 Dos 路径）。成功返回 TRUE，Out 为归一化结果。 */
BOOLEAN
ExemptPath_Normalize(
    _In_ PCWSTR Path,
    _Out_writes_(MaxLen) WCHAR* Out,
    _In_ ULONG MaxLen
    );

/* 路径模式匹配（Exact/Prefix/Suffix/Contains/Glob，归一化后比较） */
BOOLEAN
ExemptPath_Match(
    _In_ PCWSTR Path,
    _In_ PCWSTR Pattern,
    _In_ UINT8  Mode
    );

/* 路径规则命中判定（遍历 Manager 路径规则 + Match） */
BOOLEAN
ExemptPath_IsWhitelisted(
    _In_  PEXEMPT_ENGINE Engine,
    _In_  PCWSTR Path,
    _In_  UINT8 Mode,
    _Out_opt_ PEXEMPT_REASON Reason
    );

/*---------------------------------------------------------------------------
 * ExemptCert.c — 证书/发布者判定（委托 Signature 子系统）
 *---------------------------------------------------------------------------*/

/* 微软签名判定（内置信任，IocScan_IsMicrosoftSigned 统一入口） */
BOOLEAN
ExemptCert_IsTrustedSigner(
    _In_ PIOC_SCAN_RESULT Result
    );

/* 证书/发布者规则命中判定（指纹 + 发布者名两通道，返回命中原因） */
BOOLEAN
ExemptCert_IsWhitelisted(
    _In_  PEXEMPT_ENGINE Engine,
    _In_  PIOC_SCAN_RESULT Result,
    _Out_opt_ PEXEMPT_REASON Reason
    );

/*---------------------------------------------------------------------------
 * ExemptPush.c — 系统组件采集 + ALPC 推送
 *---------------------------------------------------------------------------*/

/* 采集核心系统组件哈希 → 写规则库（FileHash 类型，驱动 TrustedHash 消费） */
NTSTATUS
ExemptPush_CollectSystemHashes(
    _Inout_ PEXEMPT_ENGINE Engine
    );

/* 全量推送：枚举规则 → ALPC 0x3105 增量推送（首条 Clear+Replace，其余 Add） */
NTSTATUS
ExemptPush_PushAll(
    _Inout_ PEXEMPT_ENGINE Engine
    );

/*---------------------------------------------------------------------------
 * ExemptInjection.c — 注入场景豁免
 *---------------------------------------------------------------------------*/

/* 进程对名称级白名单预过滤（仅名称匹配，不豁免） */
BOOLEAN
ExemptInjection_IsPairWhitelisted(
    _In_ PCWSTR SourceName,
    _In_opt_ PCWSTR TargetName
    );

/* 注入豁免完整判定（三步：进程对+受保护目录+签名 / 微软签名+非LOLBin+受保护目录） */
BOOLEAN
ExemptInjection_ShouldWhitelist(
    _In_ struct _WKD_PROCESS* SrcNode,
    _In_ struct _WKD_PROCESS* TgtNode
    );

/*---------------------------------------------------------------------------
 * ExemptProcess.c — 进程身份豁免（无镜像内核假进程，纯静态判定）
 *
 * 红线：名单只允许收录"无镜像内核假进程"（System/Registry/Secure
 * System/Memory Compression）。有真实文件的进程禁止按名豁免——用户态
 * 改名即可伪装绕过；有文件进程的豁免必须走 ExemptsEvaluate 文件四维。
 *---------------------------------------------------------------------------*/

/* 判定进程名是否为无镜像内核假进程（大小写不敏感精确匹配） */
BOOLEAN
CopExemptPseudoSystemProcessInternal(
    _In_ PCWSTR ProcessName
    );

#endif /* WKD_AGENT_EXEMPTS_INTERNAL_H */
