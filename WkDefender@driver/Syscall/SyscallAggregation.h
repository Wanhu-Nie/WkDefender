#pragma once

#include "SyscallMonitor.h"
#include "../Process/ProcessMonitor.h"

/**************************************************/
/*            事件聚合模块全局状态                  */
/**************************************************/

typedef struct _WKD_AGGREGATION_STATS {
    volatile LONG64 EventsSuppressed;       // Tier 1: 生产者侧抑制次数
    volatile LONG64 EventsCollapsed;        // Tier 2: 消费者侧折叠次数
    volatile LONG64 EventsForwarded;        // 通过两级聚合的事件数
} WKD_AGGREGATION_STATS;

extern WKD_AGGREGATION_STATS g_WkdAggregationStats;

/**************************************************/
/*                  函数声明                      */
/**************************************************/

//
// Tier 1: 在 ETW 回调中调用，判断是否应抑制此事件。
// 调用时机: ShpEtwCallback 中，参数解析后、ShpSendSyscallMessage 之前。
// 约束: PASSIVE_LEVEL，不能分配内存，不能获取互斥体。
// 返回: TRUE 表示应跳过队列提交，FALSE 表示放行。
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
SaSyscallSuppress(
    _In_ PWKD_PROCESS SourceProcess,
    _In_ HANDLE TargetProcessId,
    _In_ ULONG SyscallNumber
    );
