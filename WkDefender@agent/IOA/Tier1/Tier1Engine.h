/**************************************************/
/*  WkDefender — Tier 1 语义进化引擎                 */
/*                                                    */
/*  设计原则:                                          */
/*    - 数据层 (低64位) = 客观事实, 事件到达无条件设置    */
/*    - 语义层 (高64位) = 由 T1Evaluate 多轮推导         */
/*    - T1_EVOLUTION_RULE 描述"条件→语义位"的映射       */
/*    - IoaCollectFeatures 采集不可推导的特征(速率/谱系)  */
/*                                                    */
/*  职责:                                              */
/*    1. 数据层无条件写入 (事件到达 → 位图 OR)           */
/*    2. 语义进化 (Priority 1→2→3 多轮规则执行)         */
/*    3. 特征采集 → 填充 T1Feature (速率/谱系)           */
/*    4. RecentEdgeMask 窗口衰减维护                    */
/**************************************************/

#pragma once

#include "../IoaCarsalGraph.h"
#include "../IoaPersistQueue.h"
#include "../../DefendTypes.h"

/**************************************************/
/*         评分策略 — Policy 根据位图丰富度选择       */
/**************************************************/

typedef enum _SCORE_STRATEGY {
    SCORE_BY_BASELINE       = 0,  /* 无异常 → 轻量基线 */
    SCORE_BY_TEMPLATE       = 1,  /* 语义层命中 → 攻击模板匹配 */
    SCORE_BY_ACCUMULATE     = 2,  /* 多个弱信号共现 → 累积评估 */
    SCORE_BY_ANOMALY        = 3,  /* 仅统计异常 → 稀有度兜底 */
    SCORE_BY_CONTEXT        = 4,  /* 目标为系统进程 → 上下文敏感 */
    SCORE_BY_T2_FEEDBACK    = 5,  /* T2 已有结论 → 反馈修正 */
} SCORE_STRATEGY;

/**************************************************/
/*         分级调度级别 — Policy/编排器用           */
/**************************************************/

typedef enum _T1_DISPATCH_LEVEL {
    T1_DISPATCH_FILTER         = 0,  /* 过滤 */
    T1_DISPATCH_MARK           = 1,  /* 仅标记 */
    T1_DISPATCH_T2_ASYNC       = 2,  /* 异步 Tier2 */
    T1_DISPATCH_T2_SYNC        = 3,  /* 同步 Tier2 */
    T1_DISPATCH_T3_DIRECT      = 4,  /* 直达 Tier3 */
} T1_DISPATCH_LEVEL;

/**************************************************/
/*               Tier 1 引擎状态                    */
/**************************************************/

typedef struct _IOA_TIER1_ENGINE {
    BOOLEAN             Initialized;
    CRITICAL_SECTION    Lock;
    PIOA_PERSIST_QUEUE  PersistQueue;        /* 持久化队列 (不拥有) */

    /* 统计 */
    volatile LONG64     TotalEvaluations;
    volatile LONG64     RuleHits;           /* 命中规则数 */
    volatile LONG64     FeatureCollects;    /* 特征采集次数 */
    volatile LONG64     Decisions[T1_DISPATCH_T3_DIRECT + 1];  /* 各调度级累计 (编排器更新) */
} IOA_TIER1_ENGINE, *PIOA_TIER1_ENGINE;

/**************************************************/
/*               函数声明                           */
/**************************************************/

NTSTATUS
T1Initialize(
    _Out_ PIOA_TIER1_ENGINE* Out,
    _In_  PIOA_PERSIST_QUEUE PersistQueue
    );

VOID
T1Cleanup(
    _In_ PIOA_TIER1_ENGINE Engine
    );



/*
 * IoaCollectFeatures — Tier1 纯特征采集入口。
 *
 * 采集速率/谱系特征, 填充 PairCtx->T1Feature。
 * 语义层在开头清零 (由后续 T1Evaluate 重新推导)。
 * RecentEdgeMask 的窗口衰减在内部完成。
 *
 * 参数:
 *   Engine      — Tier 1 引擎实例。
 *   PairCtx     — 当前事件的进程对上下文。
 *   SrcNode     — 源进程节点 (可 NULL)。
 *   TgtNode     — 目标进程节点 (可 NULL)。
 *   Now         — 当前时间戳。
 */
NTSTATUS
IoaCollectFeatures(
    _In_    PIOA_TIER1_ENGINE         Engine,
    _Inout_ PAE_PROCESS_PAIR PairCtx,
    _In_opt_ PWKD_PROCESS         SrcNode,
    _In_opt_ PWKD_PROCESS         TgtNode,
    _In_    LARGE_INTEGER              Now
    );

/*
 * T1Evaluate — 语义进化引擎。
 *
 * 阶段1: 数据层无条件写入。
 *         事件边类型 → BM_DATA_SET(InteractionBitmap, edgeType)。
 *
 * 阶段2: 语义多轮进化。
 *         Priority 1 → 2 → 3 依次执行规则表,
 *         低级语义 → 高级语义 → 进程固有标志在同一调用内完成进化。
 *
 * 进程固有标志 (PPID_SPOOF/CROSS_SESSION等) 返回给调用者写入 SrcNode。
 *
 * 不读因果图, 无 IO, 纯位图操作。
 *
 * 参数:
 *   Engine    — Tier 1 引擎实例。
 *   EdgeType  — 当前事件的边类型。
 *   Event     — 当前事件 (仅用于 EventFlagMatch 检查)。
 *   SrcNode   — 源进程节点 (可 NULL, 用于进程固有标志回写 + 上下文检查)。
 *   TgtNode   — 目标进程节点 (可 NULL, 用于 TgtMustBeSystem 检查)。
 *   PairCtx   — 进程对上下文 (读写 InteractionBitmap)。
 *
 * 返回值:
 *   TRUE = 至少一条规则命中 (语义层有新位被设置)。
 */
BOOLEAN
T1Evaluate(
    _In_    PIOA_TIER1_ENGINE            Engine,
    _In_    IOA_GRAPH_EDGE_TYPE          EdgeType,
    _In_    PWKD_EVENT_HEADER            Event,
    _Inout_opt_ PWKD_PROCESS         SrcNode,
    _In_opt_ PWKD_PROCESS           TgtNode,
    _Inout_ PAE_PROCESS_PAIR    PairCtx
    );
