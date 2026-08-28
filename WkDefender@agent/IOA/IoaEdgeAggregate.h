/**************************************************/
/*  WkDefender IOA — 全局边聚合表                    */
/*  Key: <SrcNodeId, TgtNodeId, EdgeType>           */
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

#define EDGE_AGGREGATE_HASH_BUCKETS  8192
#define EDGE_AGGREGATE_MAX_ENTRIES   65536
#define EDGE_AGGREGATE_TTL_MS        300000      /* 5 分钟无活动则淘汰 */

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * 初始化全局边聚合表。
 */
NTSTATUS EdgeAggTable_Initialize(
    _Out_ PIOA_AGGREGATE_EDGE_TABLE* Out
    );

/*
 * 清理全局边聚合表。
 */
VOID EdgeAggTable_Cleanup(
    _In_ PIOA_AGGREGATE_EDGE_TABLE Table
    );

/*
 * 查找或创建边聚合条目。
 *
 * 参数:
 *   Table    — 边聚合表。
 *   SrcNodeId — 源进程 NodeId。
 *   TgtNodeId — 目标进程 NodeId。
 *   EdgeType  — 边类型。
 *
 * 返回值:
 *   找到或新创建的条目指针。失败返回 NULL。
 */
PIOA_AGGREGATE_EDGE IoaGetOrCreateAggregateEdge(
    _In_ PIOA_AGGREGATE_EDGE_TABLE Table,
    _In_ GUID                      SrcNodeId,
    _In_ GUID                      TgtNodeId,
    _In_ IOA_GRAPH_EDGE_TYPE       EdgeType,
    _In_ LARGE_INTEGER             Timestamp
    );

/*
 * 查找边聚合条目（不创建）。
 *
 * 返回值:
 *   找到返回指针，未找到返回 NULL。
 */
PIOA_AGGREGATE_EDGE IoaLookupAggregateEdge(
    _In_ PIOA_AGGREGATE_EDGE_TABLE Table,
    _In_ GUID                      SrcNodeId,
    _In_ GUID                      TgtNodeId,
    _In_ IOA_GRAPH_EDGE_TYPE       EdgeType
    );

/*
 * 更新边聚合条目。
 * 由 IoaObserve 阶段2 调用（先于阶段5环形缓冲写入，GUID 已预生成）。
 *
 * 更新: OccurrenceCount++, ActiveCount (窗口重算),
 *       LastSeen, Confidence (滚动平均),
 *       尾插具体边记录 (EdgeAgg_InsertConcrete).
 *
 * 参数:
 *   Entry  — 边聚合条目。
 *   Event  — 当前事件（用于提取 Confidence / Timestamp）。
 *   EdgeId — 当前边的 GUID。
 */
VOID IoaUpdateProcessPairEdgeAggregate(
    _Inout_ PIOA_AGGREGATE_EDGE Entry,
    _In_    PWKD_EVENT_HEADER   Event,
    _In_    GUID                EdgeId
    );

/*
 * 尾插具体边记录到聚合边的 EdgesHead。
 * O(1) 快速路径: Timestamp >= 尾节点 → 直接追加。
 * 慢速路径: 从尾部 Blink 向前遍历（罕见，仅线程池乱序时触发）。
 *
 * 内部持有 EdgeLock 写锁保护链表操作。
 * 若链表长度超过 CONCRETE_EDGE_MAX_NODES, 淘汰最旧的节点。
 */
VOID EdgeAgg_InsertConcrete(
    _Inout_ PIOA_AGGREGATE_EDGE AggEdge,
    _In_    GUID                EdgeId,
    _In_    GUID                EventId,
    _In_    LARGE_INTEGER       Timestamp
    );

/*
 * Tier1 窗口过期清理: 遍历具体边链表,
 * 将 Timestamp < (Now - WindowMs) 的节点标记为 Active=FALSE。
 */
VOID EdgeAgg_EvictInactive(
    _Inout_ PIOA_AGGREGATE_EDGE AggEdge,
    _In_    LONGLONG            WindowMs
    );

/*
 * 因果图边淘汰回调: 按 EdgeId 精确匹配并释放具体边节点。
 */
VOID EdgeAgg_OnGraphEdgeEvicted(
    _Inout_ PIOA_AGGREGATE_EDGE AggEdge,
    _In_    GUID                EdgeId
    );

/*
 * 后台清理过期条目。
 * 移除所有超过 EDGE_AGGREGATE_TTL_MS 无活动的条目。
 */
VOID EdgeAggTable_CleanupExpired(
    _In_ PIOA_AGGREGATE_EDGE_TABLE Table
    );

/*
 * 获取条目计数。
 */
ULONG EdgeAggTable_GetCount(
    _In_ PIOA_AGGREGATE_EDGE_TABLE Table
    );

NTSTATUS
T3GetAggregateEdgeTimeWindow(
    _In_        GUID                SrcNodeId,
    _In_        GUID                TgtNodeId,
    _In_        IOA_GRAPH_EDGE_TYPE EdgeType,
    _Out_opt_   PLARGE_INTEGER      Start,
    _Out_opt_   PLARGE_INTEGER      End
    );