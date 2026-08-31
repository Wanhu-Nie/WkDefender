/**************************************************/
/*  WkDefender IOA — 全局边聚合表                    */
/*  Key: <SourceNodeId, TargetNodeId, EdgeType>           */
/*  Value: IOA_AGGREGATE_EDGE                        */
/*                                                  */
/*  设计约束: 内存常驻，仅存储统计 + RecentEventIds  */
/*  指针。具体事件参数通过 Causal Graph / SQLite 按需 */
/*  查询。大部分进程对无害，不缓存参数。              */
/**************************************************/

#pragma once

#include "IoaTypes.h"
#include "../Notification/EventTypes.h"

/**************************************************/
/*               边聚合表                            */
/**************************************************/

#define EDGE_AGGREGATE_HASH_BUCKETS  512
#define EDGE_AGGREGATE_MAX_ENTRIES   65536
#define EDGE_AGGREGATE_TTL_MS        30000      /* 5 分钟无活动则淘汰 */

/**************************************************/
/*               聚合边 key                          */
/**************************************************/

/*
 * 聚合边 key: <SourceNodeId, TargetNodeId, EdgeType> 三元组。
 * 固定 36 字节 (GUID 16 + GUID 16 + IOA_GRAPH_EDGE_TYPE 4), 作为 WKD_HASH_MAP 的 key。
 * 复用 WKD_BEHAVIOR_KEY 范式 (定长二进制 key + 字节级比较/哈希), 避免自制哈希。
 */
typedef struct _IOA_AGGREGATE_EDGE_KEY {
    GUID                SourceNodeId;
    GUID                TargetNodeId;
    IOA_GRAPH_EDGE_TYPE EdgeType;
} IOA_AGGREGATE_EDGE_KEY, *PIOA_AGGREGATE_EDGE_KEY;

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * 初始化全局边聚合表。
 */
NTSTATUS IoaInitializeAggregateEdgeTable(
    _Out_ PIOA_AGGREGATE_EDGE_TABLE* Table
    );

/*
 * 清理全局边聚合表。
 */
VOID IoaCleanupAggregateEdgeTable(
    _Inout_ PIOA_AGGREGATE_EDGE_TABLE Table
    );

/*
 * 按 (源/目标/类型) 精确查找聚合边。
 * UseRefCallbacks=TRUE 下命中即 pin (RefCount+1); 返回的边已被 pin,
 * 调用方用毕须调 IoaDereferenceAggregateEdge 归还引用。
 */
PIOA_AGGREGATE_EDGE IoaLookupAggregateEdge(
    _In_ PIOA_AGGREGATE_EDGE_TABLE Table,
    _In_ GUID SourceNodeId,
    _In_ GUID TargetNodeId,
    _In_ IOA_GRAPH_EDGE_TYPE EdgeType
    );

/*
 * 归还聚合边引用 (与 IoaLookupAggregateEdge / IoaFindOrCreateAggregateEdge 的
 * pin 配对)。归零时由内部 Dereference 回调释放具体边链表 + Edge 本体。
 * 对齐 driver 侧 AeDereferenceProcessPair。
 */
VOID IoaDereferenceAggregateEdge(
    _In_ PIOA_AGGREGATE_EDGE Edge
    );

/*
 * 增加聚合边引用 (与 IoaDereferenceAggregateEdge 配对)。归零释放由内部
 * Reference/Dereference 回调统一处理。供进程对刷新等路径在"移出锁保护域"
 * 前 pin 住边, 防 UAF (对齐 driver PsReferenceWkdBehavior)。
 */
LONG
IoaReferenceAggregateEdge(
    _In_ PIOA_AGGREGATE_EDGE AggEdge
    );

/*
 * 查找或创建边聚合条目。
 *
 * 参数:
 *   Table    — 边聚合表。
 *   SourceNodeId — 源进程 NodeId。
 *   TargetNodeId — 目标进程 NodeId。
 *   EdgeType  — 边类型。
 *
 * 返回值:
 *   找到或新创建的条目指针 (已被 pin, 调用方用毕须 IoaDereferenceAggregateEdge)。失败返回 NULL。
 */
PIOA_AGGREGATE_EDGE IoaFindOrCreateAggregateEdge(
    _Inout_opt_ PIOA_AGGREGATE_EDGE_TABLE Table,
    _In_ GUID SourceNodeId,
    _In_ GUID TargetNodeId,
    _In_ IOA_GRAPH_EDGE_TYPE EdgeType,
    _In_opt_ LARGE_INTEGER Timestamp
    );

/*
 * 更新边聚合条目。
 * 由 IoaObserve 阶段2 调用（先于阶段5环形缓冲写入，GUID 已预生成）。
 *
 * 更新: OccurrenceCount++, ActiveCount (窗口重算),
 *       LastSeen, Confidence (滚动平均),
 *       尾插具体边记录 (IoapInsertConcreteEdge).
 *
 * 参数:
 *   Entry  — 边聚合条目。
 *   Event  — 当前事件（用于提取 Confidence / Timestamp）。
 *   EdgeId — 当前边的 GUID。
 */
VOID
IoaUpdateAggregateEdge(
    _Inout_ PIOA_AGGREGATE_EDGE AggEdge,
    _In_ const PWKD_EVENT_HEADER Event
    );

/*
 * Tier1 窗口过期清理: 遍历具体边链表,
 * 将 Timestamp < (Now - WindowMs) 的节点标记为 Active=FALSE。
 */
VOID EdgeAgg_EvictInactive(
    _Inout_ PIOA_AGGREGATE_EDGE AggEdge,
    _In_    LONGLONG            WindowMs
    );

NTSTATUS
IoapInsertConcreteEdge(
    _Inout_ PIOA_AGGREGATE_EDGE AggEdge,
    _In_ GUID EventId,
    _In_ LARGE_INTEGER Timestamp,
    _In_ LARGE_INTEGER Now
    );
/*
 * 因果图边淘汰回调: 按 EdgeId 精确匹配并释放具体边节点。
 */
VOID EdgeAgg_OnGraphEdgeEvicted(
    _Inout_ PIOA_AGGREGATE_EDGE AggEdge,
    _In_    GUID                EdgeId
    );

/*
 * 刷新聚合边: 回收 EdgesHead 中超过 EDGE_AGGREGATE_TTL_MS 的具体边 (释放节点),
 * 返回是否仍含有效 (未过期) 具体边。聚合边是否存活取决于子对象 (具体边) 是否有效。
 * 快速路径: ExistEdges==0 或 EarliestExpireTime > Now 时直接返回 (全部有效,
 * 跳过遍历), 对齐 driver IoapReclaimExpiredRecordsLocked 的最早过期时间短路。
 * 对齐 driver 侧 IoaRefreshProcessPair 对行为记录 (具体边) 的回收语义, 供
 * IocCleanupExpiredProcessPair 经 AepRefreshProcessPair 统一回收聚合边时共用,
 * 统一"聚合边是否过期"判定。Now 为系统时间 (FILETIME 100ns 刻度)。
 */
ULONG
IoaRefreshAggregateEdgeLocked(
    _Inout_ PIOA_AGGREGATE_EDGE AggEdge,
    _In_ LARGE_INTEGER Now
    );

/*
 * 获取条目计数。
 */
ULONG EdgeAggTable_GetCount(
    _In_ PIOA_AGGREGATE_EDGE_TABLE Table
    );

NTSTATUS
T3GetAggregateEdgeTimeWindow(
    _In_        GUID                SourceNodeId,
    _In_        GUID                TargetNodeId,
    _In_        IOA_GRAPH_EDGE_TYPE EdgeType,
    _Out_opt_   PLARGE_INTEGER      Start,
    _Out_opt_   PLARGE_INTEGER      End
    );

NTSTATUS
IoaLookupAggregateEdgeByNodeId(
    _In_ GUID SourceNodeId,
    _In_ GUID TargetNodeId,
    _In_ IOA_GRAPH_EDGE_TYPE EdgeType,
    _Out_ PIOA_AGGREGATE_EDGE* Aggrate
    );

VOID
IoapDestroyAggregateEdge(
    _In_  PIOA_AGGREGATE_EDGE AggEdge
    );