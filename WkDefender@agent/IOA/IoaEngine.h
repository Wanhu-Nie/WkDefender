/**************************************************/
/*  WkDefender IOA 引擎 — 编排层                    */
/*  行为分析核心 — 三层检测架构                      */
/*                                                  */
/*  ┌─ Tier 1.5: DFA+FSM 状态机 (同步、不读图)     */
/*  │   ├─ 单事件规则 (Tier 1.0, 同步)             */
/*  │   └─ DFA+FSM 时序追踪 (Tier 1.5, 同步)      */
/*  ├─ Tier 2: 异步有界回溯 (异步、按需读图)        */
/*  └─ Tier 3: 异步深度分析 (全量图匹配+游走)       */
/*                                                  */
/*  IOA 引擎 OWN 以下内部组件:                      */
/*    - WkdProcessTree: 进程谱系树（进程域全局，main.c 管理）  */
/*    - IoaCarsalGraph   : 因果图 (唯一数据源)       */
/*    - IoaFsmEngine     : DFA+FSM 时序追踪          */
/*    - IoaGraphRingBuffer: 无锁环形缓冲区            */
/*    - IoaPersistQueue  : 异步持久化队列            */
/*    - IoaTier1Engine   : Tier 1 单事件规则         */
/*    - IoaTier2Backtrack: Tier 2 异步回溯           */
/*    - IoaGraphMatcher  : 攻击链模板 (Tier 3 使用)  */
/*    - IoaGraphWalker   : 图游走器 (Tier 3 使用)    */
/*    - IoaRateAnalyzer  : 速率分析器                */
/*    - IoaThreatScorer  : 威胁评分聚合              */
/*    - IoaMitreMapper   : MITRE ATT&CK 映射         */
/*                                                  */
/*  外部通过以下接口驱动:                           */
/*    - IoaObserve(event) : 事件驱动入口             */
/**************************************************/

#pragma once

#include "IoaTypes.h"

/**************************************************/
/*               IOA 引擎上下文                     */
/**************************************************/

/* 前向声明 */
typedef struct _IOA_CARSAL_GRAPH IOA_CARSAL_GRAPH, *PIOA_CARSAL_GRAPH;
typedef struct _IOA_PERSIST_QUEUE IOA_PERSIST_QUEUE, *PIOA_PERSIST_QUEUE;
typedef struct _IOA_TIER1_ENGINE IOA_TIER1_ENGINE, *PIOA_TIER1_ENGINE;
typedef struct _IOA_TIER2_BACKTRACK IOA_TIER2_BACKTRACK, *PIOA_TIER2_BACKTRACK;
typedef struct _IOA_GRAPH_MATCHER IOA_GRAPH_MATCHER, *PIOA_GRAPH_MATCHER;
typedef struct _IOA_RATE_ANALYZER IOA_RATE_ANALYZER, *PIOA_RATE_ANALYZER;
typedef struct _IOA_GRAPH_WALKER IOA_GRAPH_WALKER, *PIOA_GRAPH_WALKER;
typedef struct _IOA_SCORER IOA_SCORER, *PIOA_SCORER;
typedef struct _IOA_FSM_ENGINE IOA_FSM_ENGINE, *PIOA_FSM_ENGINE;
typedef struct _IOA_GRAPH_RING_BUFFER IOA_GRAPH_RING_BUFFER, *PIOA_GRAPH_RING_BUFFER;
typedef struct _IOA_TIER3_ENGINE IOA_TIER3_ENGINE, *PIOA_TIER3_ENGINE;

#include "../Notification/EventTypes.h"



/**************************************************/
/*               函数声明                           */
/**************************************************/

NTSTATUS IoaEngine_Initialize(_In_ PIOA_ENGINE_CONFIG Config);
VOID     IoaEngine_Cleanup(VOID);

/* 核心入口: 事件驱动 */
NTSTATUS
IoaObserve(
    _Inout_ PAE_PROCESS_PAIR Pair,
    _In_ const PWKD_EVENT_HEADER Event
    );

/*
 * 实时内存监控事件处理 (对齐 SS ReflectiveDLLDetector
 *   OnMemoryAllocation / OnProtectionChange, cpp L1835-1901)。
 * RWX 分配 / RW→RX 保护变更 + PE 预判 → 定向扫描触发。
 * ※ 死代码: 依赖驱动 Sm (NtAllocateVirtualMemory/NtProtectVirtualMemory) 启用 +
 *   EVENT_PAYLOAD_SYSCALL 参数语义 (ParameterBase[5]=保护, [1]=地址, [3]=大小)。
 *   当前驱动未启用, 无真实事件到达。
 */
VOID IoaHandleRealTimeMemoryEvent(_In_ PWKD_EVENT_HEADER Event);


/* 查询接口 */
PWKD_PROCESS IoaEngine_LookupProcess(_In_ GUID NodeId);
PWKD_PROCESS IoaEngine_LookupProcessByPid(_In_ ULONG Pid, _In_opt_ PLARGE_INTEGER CreateTime);

VOID     IoaEngine_PrintStats(VOID);

