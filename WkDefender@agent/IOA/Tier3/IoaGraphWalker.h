/**************************************************/
/*  WkDefender IOA — 图游走器                       */
/*  因果图上的路径分析基础设施                       */
/*                                                  */
/*  商业 EDR 调查能力的核心:                         */
/*  - WalkBackward: 从嫌疑节点沿入边回溯根因         */
/*  - WalkForward:  从嫌疑节点沿出边追踪影响范围     */
/**************************************************/

#pragma once

#include "../IoaCarsalGraph.h"

/**************************************************/
/*               图游走器                           */
/**************************************************/

typedef struct _IOA_GRAPH_WALKER {
    BOOLEAN             Initialized;
} IOA_GRAPH_WALKER, *PIOA_GRAPH_WALKER;

/**************************************************/
/*               游走路径节点                       */
/**************************************************/

typedef struct _GW_PATH_NODE {
    GUID                NodeId;             /* 节点 GUID */
    DEF_NODE_TYPE       NodeType;           /* 节点类型 */
    IOA_GRAPH_EDGE_TYPE       IncomingEdgeType;   /* 到达该节点经过的边类型 */
    ULONG               HopDepth;           /* 从起点到该节点的跳数 */
    PWKD_PROCESS   ProcessNode;        /* 关联的谱系节点 (NULL if not process) */
    PWCHAR              EntityPath;         /* 实体路径 (指向图节点内部缓冲区) */
} GW_PATH_NODE, *PGW_PATH_NODE;

/**************************************************/
/*               函数声明                           */
/**************************************************/

NTSTATUS
GwInitialize(
    _Out_ PIOA_GRAPH_WALKER* Out
    );

VOID
GwCleanup(
    _In_ PIOA_GRAPH_WALKER Walker
    );

/*
 * 沿出边追踪：从 StartNodeId 出发，沿指定边类型向外遍历 maxHops 步。
 * 结果存于 OutNodes[]，OutCount 为实际节点数。
 */
NTSTATUS
GwWalkForward(
    _In_  PIOA_GRAPH_WALKER    Walker,
    _In_  GUID                 StartNodeId,
    _In_  IOA_GRAPH_EDGE_TYPE        EdgeTypeFilter,     /* DefEdge_Unknown = 不限 */
    _In_  ULONG                MaxHops,
    _Out_ GW_PATH_NODE         OutNodes[],
    _Inout_ PULONG             OutCount
    );

/*
 * 沿入边回溯：从 StartNodeId 出发，沿入边往回追踪 maxHops 步。
 */
NTSTATUS
GwWalkBackward(
    _In_  PIOA_GRAPH_WALKER    Walker,
    _In_  GUID                 StartNodeId,
    _In_  IOA_GRAPH_EDGE_TYPE        EdgeTypeFilter,
    _In_  ULONG                MaxHops,
    _Out_ GW_PATH_NODE         OutNodes[],
    _Inout_ PULONG             OutCount
    );

/*
 * ── P3 新增: 双向图游走 ──
 * 从种子节点同时回溯(入边) + 前向追踪(出边)，
 * 返回两条有序路径，拼接即为完整攻击链。
 *
 * 最多各游走 MaxHops 层，深度 ≤4；每条路径最大 32 节点。
 */
#define GW_CHAIN_MAX_NODES  32
#define GW_CHAIN_MAX_HOPS    4

NTSTATUS
GwWalkBidirectional(
    _In_  PIOA_GRAPH_WALKER  Walker,
    _In_  GUID               SeedNodeId,
    _In_  ULONG              MaxHops,
    _Out_ GW_PATH_NODE       BackwardPath[],
    _Inout_ PULONG           BackwardCount,
    _Out_ GW_PATH_NODE       ForwardPath[],
    _Inout_ PULONG           ForwardCount
    );
