/**************************************************/
/*  WkDefender IOA — 无锁因果图环形缓冲区              */
/*                                                  */
/*  SPMC (Single Producer, Multiple Consumer)        */
/*  事件路径上无锁写入边描述符，后台线程批量消费。        */
/*                                                  */
/*  特性:                                             */
/*  - 64 位单调递增 WriteIndex / ReadIndex           */
/*  - Lock-free CAS 写入                             */
/*  - 背压自动降级 (丢弃 Layer 2 条目)                */
/*  - 分层决策: Layer 0/1/2/3                        */
/**************************************************/

#pragma once

#include "IoaTypes.h"
#include "../Notification/EventTypes.h"

/**************************************************/
/*               函数声明                           */
/**************************************************/

/* 初始化环形缓冲区 */
NTSTATUS GrbInitialize(
    _Out_ PIOA_GRAPH_RING_BUFFER* Out
    );

/* 清理环形缓冲区 (停止消费线程) */
VOID GrbCleanup(
    _In_ PIOA_GRAPH_RING_BUFFER Ring
    );

/*
 * 启动后台消费线程。
 * 消费线程使用 WakeEvent 等待，不再轮询休眠。
 * 内部通过 WkdIoaEngine.Graph 访问因果图。
 */
NTSTATUS GrbStartConsumer(
    _In_ PIOA_GRAPH_RING_BUFFER Ring
    );

/* 停止后台消费线程，等待退出后返回 */
VOID GrbStopConsumer(
    _In_ PIOA_GRAPH_RING_BUFFER Ring
    );

/*
 * 无锁写入边描述符。事件路径上调用。
 *
 * 使用 CAS 预留槽位，不阻塞。背压时:
 *   - Layer 0/1: 丢弃并递增 TotalDropped
 *   - Layer 2/3: 直接跳过 (调用者应在调用前决定)
 *
 * 返回: STATUS_SUCCESS / STATUS_BUFFER_OVERFLOW (被丢弃)
 */
NTSTATUS GrbWriteEdge(
    _In_ PIOA_GRAPH_RING_BUFFER    Ring,
    _In_ PGRAPH_EDGE_DESCRIPTOR    EdgeDesc,
    _In_ GRAPH_LAYER_DECISION      Layer
    );

/*
 * 批量读取边描述符。消费线程调用。
 *
 * 返回实际读取的条目数。
 * OutEdges 指向环形缓冲区内部存储 (不复制)，调用者应在
 * 下一次 GrbReadBatch 或 GrbCleanup 之前完成处理。
 */
ULONG GrbReadBatch(
    _In_  PIOA_GRAPH_RING_BUFFER        Ring,
    _Outptr_ PGRAPH_EDGE_DESCRIPTOR*    OutEdges,
    _In_  ULONG                         MaxCount
    );

/*
 * 分层决策函数。
 * 根据事件类型、进程属性和 FSM 状态决定边描述符的持久化层级。
 *
 * 返回值:
 *   GraphLayer_Hot  — 必须进图 (进程创建/退出/FSM活跃/高威胁)
 *   GraphLayer_Warm — 条件进图 (关键进程访问/跨进程内存操作)
 *   GraphLayer_Cold — 延迟 (待后续事件评估)
 *   GraphLayer_Skip — 跳过图示 (系统进程通信/自操作)
 */
GRAPH_LAYER_DECISION GrbDecideLayer(
    _In_ PWKD_EVENT_HEADER    Event,
    _In_ PWKD_PROCESS    SrcNode,
    _In_ PWKD_PROCESS    TgtNode,
    _In_ BOOLEAN              FsmActive
    );

/* 获取统计信息 */
VOID GrbGetStats(
    _In_  PIOA_GRAPH_RING_BUFFER Ring,
    _Out_ LONG64*                 TotalWritten,
    _Out_ LONG64*                 TotalConsumed,
    _Out_ LONG64*                 TotalDropped,
    _Out_ LONG64                  LayerCounts[4]
    );
