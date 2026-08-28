/**************************************************/
/*  WkDefender IOA — 图模式匹配器                    */
/*  基于因果图的攻击链检测                            */
/*                                                  */
/*  对标商业 EDR 的 Graph Pattern Matching 层:       */
/*  - 攻击链定义为边类型模板（非位掩码）              */
/*  - 匹配时实时查询因果图（无独立缓冲区）            */
/*  - 行为标志通过进程节点累积后复用                  */
/*                                                  */
/*  与 IoaTemporal 的关系:                           */
/*  - 替代旧 Temporal 的攻击链检测能力               */
/*  - Temporal 重写后委托 GmEvaluate 工作            */
/**************************************************/

#pragma once

#include "../IoaCarsalGraph.h"
#include "IoaGraphWalker.h"

/**************************************************/
/*               边约束                             */
/**************************************************/

typedef struct _GM_EDGE_CONSTRAINT {
    IOA_GRAPH_EDGE_TYPE       EdgeType;           /* 需要的边类型 (DefEdge_Unknown = 纯行为标志步骤) */
    ULONG               TargetRole;         /* 0=必须指向事件目标进程; 1=指向任意节点 */
    ULONG               MinBehaviorFlags;   /* 最小行为标志 (0=不检查). 若 CheckProcessFlag=TRUE 则检查源进程累积标志 */
    BOOLEAN             CheckProcessFlag;   /* TRUE=检查源进程节点 BehaviorFlags; FALSE=检查边上的 BehaviorFlags */
    PCWSTR              Description;        /* 步骤描述 (调试日志用) */
} GM_EDGE_CONSTRAINT, *PGM_EDGE_CONSTRAINT, *PCGM_EDGE_CONSTRAINT;

#define GM_TARGET_ROLE_DIRECT       0        /* 边必须指向事件目标进程 */
#define GM_TARGET_ROLE_INTERMEDIATE 1        /* 边可指向任意中间实体 */

/**************************************************/
/*               攻击链模板                         */
/**************************************************/

typedef struct _GM_ATTACK_CHAIN_TEMPLATE {
    PCWSTR              Name;               /* 攻击链名称 */
    PCWSTR              MitreId;            /* MITRE ATT&CK ID */
    ULONG               StepCount;          /* 步骤数量 */
    GM_EDGE_CONSTRAINT  Steps[8];           /* 步骤列表 */
    ULONG               MinRatio;           /* 最小匹配比例 (0-100) */
    ULONG               MinScore;           /* 最低威胁评分 */
} GM_ATTACK_CHAIN_TEMPLATE, *PGM_ATTACK_CHAIN_TEMPLATE, *PCGM_ATTACK_CHAIN_TEMPLATE;

/**************************************************/
/*               图模式匹配器                       */
/**************************************************/

typedef struct _IOA_GRAPH_MATCHER {
    BOOLEAN             Initialized;
    CRITICAL_SECTION    Lock;
    volatile LONG64     TotalEvaluations;   /* 累计评估次数 */
    volatile LONG64     ChainHits;          /* 累计攻击链命中次数 */
} IOA_GRAPH_MATCHER, *PIOA_GRAPH_MATCHER;

/**************************************************/
/*               函数声明                           */
/**************************************************/

NTSTATUS
GmInitialize(
    _Out_ PIOA_GRAPH_MATCHER* Out
    );

VOID
GmCleanup(
    _In_ PIOA_GRAPH_MATCHER Matcher
    );

/* 评估当前事件：查因果图 → 匹配攻击链模板 → 命中则提升 Severity */
NTSTATUS
GmEvaluate(
    _In_ PIOA_GRAPH_MATCHER Matcher,
    _In_ PWKD_EVENT_HEADER  Event
    );

/*
 * Phase 5: 子图模式匹配 (Tier3 专用)。
 *
 * 在 GwWalkBidirectional 产出的扩展攻击图中，
 * 匹配预定义的多节点攻击模式（LSASS凭据窃取/持久化镂空/DLL侧加载+C2等）。
 *
 * 与 GmEvaluate 互补:
 *   - GmEvaluate: 单节点出边位图匹配
 *   - GmEvaluateSubgraph: 多节点子图约束匹配
 */
NTSTATUS
GmEvaluateSubgraph(
    _In_ PIOA_GRAPH_MATCHER        Matcher,
    _In_ PIOA_CARSAL_GRAPH_NODE    SeedNode,
    _In_ GW_PATH_NODE*             PathNodes,
    _In_ ULONG                     PathNodeCount
    );
