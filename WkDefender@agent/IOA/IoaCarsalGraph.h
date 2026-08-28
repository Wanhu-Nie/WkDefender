/**************************************************/
/*  WkDefender IOA — 因果图引擎 (IOA 内部组件)      */
/**************************************************/

#pragma once

#include "IoaTypes.h"
#include "../Notification/EventTypes.h"

#define IOA_CARSAL_GRAPH_NODE_HASH_BUCKETS 4099

/**************************************************/
/*               因果图管理器                       */
/**************************************************/

typedef struct _IOA_CARSAL_GRAPH {
    BOOLEAN             Initialized;
    LIST_ENTRY          NodeHashBuckets[IOA_CARSAL_GRAPH_NODE_HASH_BUCKETS];
    LIST_ENTRY          NodeGlobalList;
    ULONG               NodeCount;
    LIST_ENTRY          EdgeGlobalList;
    ULONG               EdgeCount;
    CRITICAL_SECTION    Lock;
    volatile LONG64     TotalNodesCreated;
    volatile LONG64     TotalEdgesCreated;
    volatile LONG64     TotalEdgesCompacted;
} IOA_CARSAL_GRAPH, *PIOA_CARSAL_GRAPH;

/**************************************************/
/*               函数声明                           */
/**************************************************/

NTSTATUS
IoaCarsalGraphInitialize(
    _Out_ PIOA_CARSAL_GRAPH* Manager
    );

VOID
IoaCarsalGraphCleanup(
    _In_ PIOA_CARSAL_GRAPH Manager
    );

NTSTATUS
IoaCarsalGraphInsertEvent(
    _In_ PIOA_CARSAL_GRAPH   Manager,
    _In_ PWKD_EVENT_HEADER   Event
    );

PIOA_CARSAL_GRAPH_NODE
IoaCarsalGraphLookupNode(
    _In_ PIOA_CARSAL_GRAPH   Manager,
    _In_ GUID                NodeId
    );

VOID
IoaCarsalGraphPrune(
    _In_ PIOA_CARSAL_GRAPH  Manager,
    _In_ LARGE_INTEGER      WindowStart
    );

/*
 * 从 GRAPH_EDGE_DESCRIPTOR (环形缓冲区条目) 插入因果图边。
 * 供后台消费线程调用，替代同步路径上的 IoaCarsalGraphInsertEvent。
 */
NTSTATUS
IoaCarsalGraphInsertEdge(
    _In_ PIOA_CARSAL_GRAPH   Manager,
    _In_ PGRAPH_EDGE_DESCRIPTOR Desc
    );

/*
 * 按 (Src, Tgt, EdgeType) 精确查找因果图中的边。
 * 供 Tier 2 FSM 证据包交叉验证使用。
 *
 * 返回值: 找到的边指针 (不增加引用计数)，未找到返回 NULL。
 */
PIOA_GRAPH_EDGE
IoaCarsalGraphLookupEdge(
    _In_ PIOA_CARSAL_GRAPH   Manager,
    _In_ GUID                 SrcNodeId,
    _In_ GUID                 TgtNodeId,
    _In_ IOA_GRAPH_EDGE_TYPE        EdgeType
    );

/*
 * P3: LookupEdgeByEventId.
 */
PIOA_GRAPH_EDGE
IoaCarsalGraphLookupEdgeByEventId(
    _In_ PIOA_CARSAL_GRAPH   Manager,
    _In_ GUID                 EventId
    );

/**************************************************/
/*       关系查询 API (对齐 SS 进程关系图)            */
/*                                                  */
/*  [死代码] SS 侧这些查询 API 全项目零消费           */
/*  (PrGetNodeInfo/PrGetRelationships/PrGetChildren/ */
/*  PrGetStatistics 无调用者), wkd 提供等价物         */
/*  供 UI/主动查询/紧急分析接线。                    */
/*  返回拷贝 + 计数, 不返回裸指针。                  */
/**************************************************/

typedef struct _IOA_RELATIONSHIP_INFO {
    IOA_GRAPH_EDGE_TYPE Type;
    GUID                SrcNodeId;
    GUID                TgtNodeId;
    LARGE_INTEGER       Timestamp;      /* 边 LastSeen */
    ULONG               Score;          /* 边 Weight (0-100) */
} IOA_RELATIONSHIP_INFO, *PIOA_RELATIONSHIP_INFO;

typedef struct _IOA_NODE_INFO {
    GUID    NodeId;
    ULONG   OutDegree;          /* 因果图出度 */
    ULONG   InDegree;           /* 因果图入度 */
    ULONG   RelationshipCount;  /* 出边+入边 */
    ULONG   OutPairCount;       /* 进程对出度 (不同目标数) */
    ULONG   InPairCount;        /* 进程对入度 (不同源数) */
    BOOLEAN IsOrphan;           /* 父节点缺失 (对齐 SS PR_NODE_INFO.IsOrphan) */
    ULONG   TreeDepth;          /* 谱系深度 */
} IOA_NODE_INFO, *PIOA_NODE_INFO;

typedef struct _IOA_GRAPH_STATS_INFO {
    LARGE_INTEGER   StartTime;
    ULONG           NodeCount;
    ULONG           EdgeCount;
    volatile LONG64 TotalNodesCreated;
    volatile LONG64 TotalEdgesCreated;
    volatile LONG64 TotalEdgesCompacted;
} IOA_GRAPH_STATS_INFO, *PIOA_GRAPH_STATS_INFO;

/* 进程节点信息查询 (对齐 SS PrGetNodeInfo) */
NTSTATUS
IoaGqGetNodeInfo(
    _In_  PIOA_CARSAL_GRAPH Mgr,
    _In_  GUID              NodeId,
    _Out_ PIOA_NODE_INFO    Out
    );

/* 进程关系列表查询 (对齐 SS PrGetRelationships), EdgeFilter=DefEdge_Unknown 不过滤 */
NTSTATUS
IoaGqGetRelationships(
    _In_  PIOA_CARSAL_GRAPH Mgr,
    _In_  GUID              NodeId,
    _In_  IOA_GRAPH_EDGE_TYPE EdgeFilter,
    _Out_writes_to_(MaxCount, *Count) PIOA_RELATIONSHIP_INFO Out,
    _In_  ULONG             MaxCount,
    _Out_ ULONG*            Count
    );

/* 进程子节点查询 (对齐 SS PrGetChildren) */
NTSTATUS
IoaGqGetProcessChildren(
    _In_  PIOA_CARSAL_GRAPH Mgr,
    _In_  GUID              NodeId,
    _Out_writes_to_(MaxCount, *Count) GUID* Children,
    _In_  ULONG             MaxCount,
    _Out_ ULONG*            Count
    );

/* 因果图统计查询 (对齐 SS PrGetStatistics) */
NTSTATUS
IoaGqGetStatistics(
    _In_  PIOA_CARSAL_GRAPH Mgr,
    _Out_ PIOA_GRAPH_STATS_INFO Out
    );
