#include "SyscallAggregation.h"
#include "../Common/Constants.h"
#include "../AnalysisEngine/IoaEngine.h"
#include "../Notification/NotificationManager.h"

/**************************************************/
/*              全局聚合统计变量                   */
/**************************************************/

WKD_AGGREGATION_STATS g_WkdAggregationStats = {0};

/************************************************/
/*          Tier 1: 生产者侧无锁抑制检查          */
/************************************************/

//
// 实现单深度"上次事件"检查。
// 同一 (sourceProcessId, TargetProcessId, syscallNumber) 在抑制窗口内只放行第一次。
// 使用 volatile + InterlockedXxx 保证无锁安全，最坏情况（torn read）
// 只是多抑制或少抑制一个事件，不影响正确性。
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
SaSyscallSuppress(
    _In_ PWKD_PROCESS SourceProcess,
    _In_ HANDLE TargetProcessId,
    _In_ ULONG SyscallNumber
    )
{
    PWKD_SYSCALL_SUPPRESSION suppression;
    LARGE_INTEGER currentTime = { 0 };
    LONGLONG elapsedMs;

    if (!SourceProcess || !TargetProcessId || !SyscallNumber) {
        return FALSE;
    }

    suppression = &SourceProcess->SyscallSuppression;

    //
    // 快速路径：与上次事件不同的 (target, syscall) 直接放行
    //
    if (suppression->LastTargetProcessId != TargetProcessId ||
        suppression->LastSyscallNumber != SyscallNumber) {
        goto Forward;
    }

    //
    // 相同事件：检查是否在抑制窗口内
    //
    KeQuerySystemTime(&currentTime);
    elapsedMs = (currentTime.QuadPart - suppression->LastTimestamp.QuadPart) / 10000;

    if (elapsedMs > WKD_SYSCALL_SUPPRESS_WINDOW_MS) {
        //
        // 窗口已过期：更新为新的起始点并放行
        //
        suppression->LastTimestamp = currentTime;
        goto Forward;
    }

    //
    // 在窗口内：抑制此事件
    //
    InterlockedIncrement(&suppression->SuppressedCount);
    InterlockedIncrement64(&g_WkdAggregationStats.EventsSuppressed);
    return TRUE;

Forward:
    //
    // 更新抑制状态并放行
    //
    suppression->LastTargetProcessId = TargetProcessId;
    suppression->LastSyscallNumber = SyscallNumber;
    suppression->LastTimestamp = currentTime;
    InterlockedIncrement(&suppression->TotalEvents);
    InterlockedIncrement64(&g_WkdAggregationStats.EventsForwarded);
    return FALSE;
}
