/**************************************************/
/*  WkDefender PolicyEngine — 策略引擎              */
/*  接收 IOC + IOA 双路输入，规则评估 + 告警        */
/**************************************************/

#pragma once

#include "PolicyRules.h"
#include "../IOA/IoaTypes.h"
#include "../Notification/EventTypes.h"

/**************************************************/
/*               告警去重条目                       */
/**************************************************/

typedef struct _POLICY_DEDUP {
    GUID     ProcessNodeId;
    WCHAR           RuleName[128];
    LARGE_INTEGER   LastAlertTime;
} POLICY_DEDUP;

#define POLICY_DEDUP_MAX    64

/**************************************************/
/*               策略引擎                           */
/**************************************************/

typedef struct _POLICY_ENGINE {
    BOOLEAN         Initialized;
    ULONG           ThrottleSeconds;
    ULONG           DedupCount;
    POLICY_DEDUP    DedupTable[POLICY_DEDUP_MAX];
    volatile LONG64 AlertsGenerated;
    volatile LONG64 AlertsThrottled;

    /* ── 运行时规则引擎 (ThreatDetector 迁移, 2026-08-04) ──
     * EnableRuntimeRules=FALSE 默认关闭, 注册表 API 为活代码。
     * 2026-08 RuleEngine 迁移: 多条件 AND 组合评估 + 优先级 +
     * 规则级统计, 评估逻辑完整实现 (见 PolicyEngine.c)。 */
    BOOLEAN            EnableRuntimeRules;
    ULONG              RuntimeRuleCount;
    WKD_DETECTION_RULE RuntimeRules[POLICY_RUNTIME_RULES_MAX];

    /* ── 引擎级统计 (RuleEngine 迁移, 对齐 SS RE_ENGINE_STATS
     *   Evaluations/Matches/Blocks, RuleEngine.h L211-218) ── */
    volatile LONG64    Evaluations;
    volatile LONG64    Matches;
    volatile LONG64    Blocks;

    CRITICAL_SECTION Lock;
} POLICY_ENGINE;

extern POLICY_ENGINE g_PolicyEngine;

NTSTATUS PolicyEngine_Initialize(_In_ ULONG ThrottleSeconds);
VOID     PolicyEngine_Cleanup(VOID);
NTSTATUS PolicyEngine_Evaluate(_In_ PWKD_EVENT_HEADER Event, _In_opt_ PWKD_PROCESS Node);

/* ── 运行时规则注册表 (SS DetectionRule 迁移) ── */
NTSTATUS PolicyEngine_AddRule(_In_ const WKD_DETECTION_RULE* Rule);
NTSTATUS PolicyEngine_RemoveRule(_In_ PCWSTR RuleId);
VOID     PolicyEngine_SetRuleEnabled(_In_ PCWSTR RuleId, _In_ BOOLEAN Enabled);
ULONG    PolicyEngine_GetRuleCount(VOID);
ULONG    PolicyEngine_GetRules(_Out_ PWKD_DETECTION_RULE Out, _In_ ULONG MaxCount);

/* 评估上下文 (RuleEngine 迁移, 对齐 SS RE_EVALUATION_CONTEXT,
 * RuleEngine.h L171-187; 用户态, 字段缺省=条件不命中)。
 * 由 PolicyEngine.c 的 Policy_BuildEvalContext 从 Event+Node 填充。 */
typedef struct _WKD_EVAL_CONTEXT {
    PWKD_EVENT_HEADER  Event;
    PWKD_PROCESS  Node;
    PCWSTR ProcessName;         /* Node->ImageFileName->Buffer */
    PCWSTR ParentName;          /* Node->Parent->ImageFileName->Buffer */
    PCWSTR CommandLine;         /* Node->CommandLine->Buffer */
    PCWSTR FilePath;            /* Node->ImagePath->Buffer */
    PCWSTR FileHash;            /* 恒 NULL (※死代码条件) */
    PCWSTR RegistryPath;        /* 恒 NULL (※死代码条件) */
    PCWSTR NetworkAddress;      /* 恒 NULL (※死代码条件) */
    PCWSTR Domain;              /* 恒 NULL (※死代码条件) */
    PCWSTR MitreTechnique;      /* 恒 NULL (※死代码条件) */
    ULONG  ThreatScore;         /* Node->CumulativeRiskScore */
    ULONG  BehaviorFlags;       /* Node->BehaviorFlags | Event->BehaviorFlags */
    SYSTEMTIME CurrentTime;     /* GetLocalTime */
} WKD_EVAL_CONTEXT, *PWKD_EVAL_CONTEXT;
typedef const WKD_EVAL_CONTEXT *PCWKD_EVAL_CONTEXT;

/* 运行时规则评估 (默认 EnableRuntimeRules=FALSE 不调用;
 * Score 输出命中规则的最高加分)。
 * 2026-08 RuleEngine 迁移: 规则 ConditionCount>0 走多条件 AND
 * 组合评估 (Policy_EvaluateCondition), =0 回退便捷字段 (既有
 * Policy_RuntimeRuleMatch 路径); 命中更新规则级统计并分派动作
 * (Alert→IOA_ALERT 入队, Block/Terminate/Quarantine→VerdictEngine
 * 统一出口, monitor-only 门控)。 */
NTSTATUS PolicyEngine_EvaluateRuntime(_In_ PWKD_EVENT_HEADER Event, _In_opt_ PWKD_PROCESS Node, _Inout_opt_ PULONG Score);

/* 引擎级统计 (RuleEngine 迁移, 对齐 SS ReGetStatistics,
 * RuleEngine.c L1388-1420) */
VOID PolicyEngine_GetStats(_Out_opt_ PULONG64 Evaluations, _Out_opt_ PULONG64 Matches, _Out_opt_ PULONG64 Blocks);

/* 完整通配匹配: '*' 任意串 + '?' 单字符 + 大小写折叠 + 迭代上限防 ReDoS。
 * 供 Policy_RuntimeRuleMatch 与序列规则引擎共用 (PolicyEngine.c 实现)。 */
BOOLEAN Policy_WildcardMatch(_In_ PCWSTR Pattern, _In_ PCWSTR Text);

/* ── 规则文件持久化 (※死代码: JSON/YAML 序列化未实现, 对齐 SS
 *   LoadRulesFromFile/SaveRulesToFile stub) ── */
NTSTATUS PolicyEngine_LoadRulesFromFile(_In_ PCWSTR FilePath);
NTSTATUS PolicyEngine_SaveRulesToFile(_In_ PCWSTR FilePath);

/**************************************************/
/*       序列规则引擎 (ShadowStrike PatternMatcher 迁移)  */
/*                                                  */
/*  实现 WKD_DETECTION_RULE.IsAtomic=FALSE 序列分支:  */
/*  数据驱动事件序列模式匹配 (边类型 + 通配符 + 时序   */
/*  窗口 + Optional/Terminal + 部分匹配)。            */
/*                                                  */
/*  ※注册 API 为活代码 (可经 ALPC/UI 调用);           */
/*    评估默认 EnableSequenceRules=FALSE 不执行       */
/*    (死代码), 后续再决定是否接入流水线。             */
/*    数据源依赖: 步骤 ValuePattern 多数事件无载荷值,  */
/*    详见 PolicyEngine.c 的 SeqExtractEventValue。  */
/**************************************************/

/* ── 序列规则注册表 ── */
NTSTATUS PolicyEngine_AddSequenceRule(_In_ const WKD_SEQUENCE_RULE* Rule);
NTSTATUS PolicyEngine_RemoveSequenceRule(_In_ PCWSTR RuleId);
VOID     PolicyEngine_SetSequenceRuleEnabled(_In_ PCWSTR RuleId, _In_ BOOLEAN Enabled);
ULONG    PolicyEngine_GetSequenceRuleCount(VOID);
ULONG    PolicyEngine_GetSequenceRules(_Out_ PWKD_SEQUENCE_RULE Out, _In_ ULONG MaxCount);
VOID     PolicyEngine_SetSequenceRulesEnabled(_In_ BOOLEAN Enabled);

/* ── 序列规则评估 (IoaObserve 阶段4.6 调用; 默认开关 FALSE 短路) ──
 * 双阶段对齐 SS PmSubmitEvent: 阶段1 推进已有状态, 阶段2 启动新状态。
 * 命中产分写入 MaxScoreOut (供阶段6c2 合并进 finalScore), 并构造
 * IOA_ALERT → IoaPersistQueueEnqueue。 */
NTSTATUS PolicyEngine_EvaluateSequenceRules(
    _In_  PAE_PROCESS_PAIR PairCtx,
    _In_  PWKD_EVENT_HEADER         Event,
    _In_opt_ PWKD_PROCESS      SrcNode,
    _In_opt_ PWKD_PROCESS      TgtNode,
    _In_  IOA_GRAPH_EDGE_TYPE       EdgeType,
    _Out_opt_ PULONG                MaxScoreOut);

/* ── 序列规则状态查询 (※死代码: 无调用者, 对齐 SS
 *   PmGetActiveStates/PmReleaseState) ── */
NTSTATUS PolicyEngine_GetSequenceStates(
    _In_  GUID SrcNodeId,
    _In_  GUID TgtNodeId,
    _Out_ PWKD_SEQ_MATCH_STATE* States,
    _In_  ULONG                  MaxStates,
    _Out_ PULONG                 StateCount);
VOID     PolicyEngine_ReleaseSequenceState(_In_ PWKD_SEQ_MATCH_STATE State);

/* ── 进程对淘汰时回收其全部序列状态 (IoaProcessPair 调用) ── */
VOID     PolicyEngine_RemovePairSequenceStates(_In_ PAE_PROCESS_PAIR PairCtx);

/* ── 超时状态清理 (CgFsmCleanupThread 周期调用, 对齐 SS PmpCleanupStaleStates) ── */
VOID     PolicyEngine_CleanupSequenceStates(VOID);

/* ── 序列规则持久化 (※死代码: 对齐 LoadRulesFromFile stub) ── */
NTSTATUS PolicyEngine_LoadSequenceRulesFromFile(_In_ PCWSTR FilePath);
NTSTATUS PolicyEngine_SaveSequenceRulesToFile(_In_ PCWSTR FilePath);
