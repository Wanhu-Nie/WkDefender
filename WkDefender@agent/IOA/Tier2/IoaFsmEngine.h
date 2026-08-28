/**************************************************/
/*  WkDefender IOA — DFA+FSM 时序攻击链追踪引擎       */
/*                                                  */
/*  重构: 全局稀疏状态表 <spn, tpn, PatternIndex>     */
/*  IOA_FSM_TRACKER 按需分配，生命周期绑定 PairContext     */
/*                                                  */
/*  特性:                                             */
/*  - 同步路径运行 (不读图/不写图/不 I/O)              */
/*  - O(1) 哈希表查找 + 条件检查                      */
/*  - 懒分配 StateEntry (仅活跃模式占用内存)           */
/*  - 接受态输出 IOA_FSM_EVIDENCE (结构化攻击假设)    */
/*  - 过渡态输出归一化评分 (连续信号供 Tier1 聚合)     */
/*  - 5 种预定义攻击模式 (编译时常量)                   */
/**************************************************/

#pragma once

#include "../IoaTypes.h"
#include "../../Common/Utils.h"
#include "../../Notification/EventTypes.h"

/**************************************************/
/*       FSM 状态转移结果 (柔性数组，每个模式一个槽)   */
/*                                                  */
/*  Patterns[] 按需分配，容量 = FSM_PATTERN_COUNT。  */
/*  Evidence 按需分配 (IsAccept/IsPartialAccept 时)。*/
/**************************************************/

/*
 * FSM_PATTERN_RESULT — 单个模式的 FSM 评估结果。
 */
typedef struct _FSM_PATTERN_RESULT {
    BOOLEAN             IsValid;            /* 此槽位是否有效 */
    BOOLEAN             IsAccept;           /* 达到最终接受态 */
    BOOLEAN             IsPartialAccept;    /* 部分接受（ThreatScore >= AcceptThreshold/2 但未完成） */
    UINT8               PatternIndex;       /* 模式索引 */
    ULONG               ThreatScore;        /* 威胁得分 (已含步骤间隔+总耗时衰减) */
    ULONG               AcceptThreshold;    /* 该模式的接受阈值 */
    PIOA_FSM_EVIDENCE   Evidence;           /* 按需分配（接受态/部分接受态时分配，调用方释放） */
} FSM_PATTERN_RESULT, *PFSM_PATTERN_RESULT;

/*
 * FSM_TRANSITION_RESULT — 每次 FsmRefreshStateTransition 的结果集。
 * 使用柔性数组，分配时指定容量。
 * 调用方遍历 Patterns[0..PatternCount-1] 读取每个模式的结果。
 */
typedef struct _FSM_TRANSITION_RESULT {
    ULONG               PatternCount;             /* 有效结果数 */
    ULONG               Capacity;                 /* 分配容量 */
    BOOLEAN             HasAccept;                /* 是否有任意模式达到接受态 */
    BOOLEAN             Reserved[3];
    FSM_PATTERN_RESULT  Patterns[];               /* 柔性数组 */
} FSM_TRANSITION_RESULT, *PFSM_TRANSITION_RESULT;

/* 分配 FSM_TRANSITION_RESULT 的便捷宏 */
#define FSM_ALLOC_TRANSITION_RESULT(Cap) \
    ((PFSM_TRANSITION_RESULT)UtHeapAlloc(sizeof(FSM_TRANSITION_RESULT) + (Cap) * sizeof(FSM_PATTERN_RESULT)))

/*
 * IoaMapEventToEdgeType — 事件类型 → 边类型映射。
 */
IOA_GRAPH_EDGE_TYPE
IoaMapEventToEdgeType(
    _In_ WKD_EVENT_TYPE EventType
    );

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * 初始化 FSM 引擎。
 * 初始化稀疏状态哈希表、加载预定义攻击模式。
 */
NTSTATUS FsmInitialize(
    _Out_ PIOA_FSM_ENGINE*          Out
    );

/*
 * 清理 FSM 引擎。
 * 释放所有 StateEntry、销毁临界区、停止后台线程。
 */
VOID FsmCleanup(
    _In_ PIOA_FSM_ENGINE Engine
    );

/*
 * FSM 多路归并推进 — 从 PairCtx->EdgeListHead 收集具体边序列，
 * 驱动所有活跃攻击模式的状态转移。
 *
 * 流程:
 *   1. 遍历 EdgeListHead, 收集各聚合边的活跃具体边节点 (Active=TRUE)
 *   2. 确定空窗期起点 (模式未激活→CreationTime, 已激活→LastStepTime)
 *   3. 多路归并 (按 Timestamp) → 全局有序边序列
 *   4. 每条边驱动所有匹配模式的状态转移 (ThreatIncrement + 步骤间隔衰减)
 *   5. 达到接受态: 仅标记 localAcceptMask, 不销毁、不构造证据
 *   6. 统一威胁得分收集 + 证据构造: 遍历所有模式, 计算 ThreatScore,
 *      为接受态和部分接受态模式按需分配 Evidence
 *   7. 统一清理: 重置并释放接受态模式, 保留部分接受/活跃模式
 *
 * 参数:
 *   Engine  — FSM 引擎。
 *   PairCtx — 进程对上下文 (非 NULL, FsmTracker + EdgeListHead 从此读取)。
 *   Result  — [输出] 状态转移结果 (数组式, 遍历 Result->Patterns[] 获取)。
 *
 * 返回值:
 *   TRUE  = 有任意模式到达接受态 (Result->HasAccept==TRUE)
 *   FALSE = 未到达接受态
 *
 * 注意: 调用方负责释放 Result (UtHeapFree) 及各槽位的 Evidence (UtHeapFree)。
 */
BOOLEAN FsmRefreshStateTransition(
    _In_    PIOA_FSM_ENGINE              Engine,
    _In_    PAE_PROCESS_PAIR    PairCtx,
    _Out_   PFSM_TRANSITION_RESULT       Result
    );

/*
 * 后台清理过期状态条目。
 * 检查每个 StateEntry 的 LastStepTime 是否超过对应模式的步骤超时。
 * 超时条目: 部分报告 (半阈值) + 重置 + 释放。
 *
 * 应由后台线程周期性调用 (每 FSM_CLEANUP_INTERVAL_MS)。
 */
VOID FsmCleanupExpired(
    _In_ PIOA_FSM_ENGINE Engine
    );

/*
 * 获取 FSM 统计信息。
 */
VOID FsmGetStats(
    _In_  PIOA_FSM_ENGINE Engine,
    _Out_ ULONG*          ActiveTrackers,
    _Out_ ULONG*          PeakTrackers,
    _Out_ LONG64*         TotalProcessed,
    _Out_ LONG64*         TotalMatches,
    _Out_ LONG64*         TotalTimeouts
    );
