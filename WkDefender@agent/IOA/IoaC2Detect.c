/**************************************************/
/*  WkDefender IOA — C2 通信行为检测实现 (死代码)   */
/*                                                  */
/*  迁移自 ShadowStrike BehaviorAnalyzer             */
/*  UpdateC2Score (BehaviorAnalyzer.cpp L1412-1508)。 */
/*  功能重实现, 非源码复制。                         */
/*                                                  */
/*  死代码: 无调用者, 未接入流水线。                  */
/*  情报命中/信标周期由接入层驱动 (见头文件注释)。     */
/**************************************************/

#include "IoaC2Detect.h"
#include "../DefendTypes.h"

#include <wchar.h>
#include <math.h>

/**************************************************/
/*           内部辅助函数 (文件内静态)                */
/**************************************************/

static
BOOLEAN
IoaC2_IsHighEntropyHost(
    _In_ PCWSTR Host
    )
/*++
Routine Description:
    DGA 判定: 域名字符唯一率 >0.7 视为高熵 (对齐 SS L1491-1504)。

Arguments:
    Host — 远程域名。

Return Value:
    TRUE 疑似 DGA / FALSE 否。
--*/
{
    ULONG len;
    ULONG unique;
    ULONG ratio;

    if (!Host) return FALSE;

    len = (ULONG)wcslen(Host);
    if (len <= WKD_C2_DGA_MIN_LEN) return FALSE;

    unique = 0;
    for (ULONG i = 0; i < len; i++) {
        BOOLEAN seen = FALSE;
        for (ULONG j = 0; j < i; j++) {
            if (Host[j] == Host[i]) { seen = TRUE; break; }
        }
        if (!seen) unique++;
    }

    ratio = unique * 100 / len;
    return ratio > WKD_C2_DGA_UNIQ_RATIO;
}

/**************************************************/
/*           主检测函数                             */
/**************************************************/

ULONG
IoaC2_UpdateScore(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_    const WKD_BEHAVIOR_EVENT*   Evt
    )
/*++
Routine Description:
    C2 通信行为评分。当前实现 DGA 域名判定;
    情报命中由接入层查 ThreatIntel 后递增
    State->ThreatIntelHits 并直接加分, 信标由
    IoaC2_IsBeaconing 确认后接入层递增 BeaconPeriods。

Arguments:
    State — 进程级行为状态 (读写)。
    Evt   — 归一化行为事件视图 (只读)。

Return Value:
    本次事件得分增量 [0,100]。
--*/
{
    ULONG scoreAdd = 0;

    if (!State || !Evt) return 0;

    switch (Evt->Type) {
        case WKD_EVT_NET_CONNECT:
        case WKD_EVT_NET_SEND:
        case WKD_EVT_NET_HTTP_REQUEST:
        case WKD_EVT_NET_HTTPS_REQUEST: {
            /* DGA: 高字符熵域名 */
            if (IoaC2_IsHighEntropyHost(Evt->RemoteHost)) {
                State->DgaDomains++;
                scoreAdd += WKD_C2_DGA_SCORE;
                State->DetectionFlags |= DEF_BEHAVIOR_FLAG_C2_COMMUNICATION;
            }
            break;
        }

        default:
            break;
    }

    if (scoreAdd > 0) {
        /* 并发安全重构 2026-08-23：饱和累加保 [0,100] 上限原子发布 */
        { LONG old, nw; do { old = State->MaliceScore; nw = min(old + scoreAdd, 100); }
          while (InterlockedCompareExchange(&State->MaliceScore, nw, old) != old); }
    }
    return min(scoreAdd, 100);
}

BOOLEAN
IoaC2_IsBeaconing(
    _In_reads_(Count) const ULONG* IntervalsMs,
    _In_                   ULONG   Count
    )
/*++
Routine Description:
    信标间隔规律性判定: 间隔变异系数 (CV=标准差/均值) <0.3
    视为规律信标 (对齐 SS L1465-1481)。

Arguments:
    IntervalsMs — 相邻连接间隔数组 (毫秒)。
    Count       — 间隔个数。

Return Value:
    TRUE 规律信标 / FALSE 否。
--*/
{
    double mean, variance, stddev, cv;

    if (!IntervalsMs || Count < WKD_C2_BEACON_MIN_INTERVALS) return FALSE;

    mean = 0.0;
    for (ULONG i = 0; i < Count; i++) mean += (double)IntervalsMs[i];
    mean /= (double)Count;

    if (mean <= 1.0) return FALSE;

    variance = 0.0;
    for (ULONG i = 0; i < Count; i++) {
        double diff = (double)IntervalsMs[i] - mean;
        variance += diff * diff;
    }
    variance /= (double)Count;

    stddev = sqrt(variance);
    if (mean <= 0.0) return FALSE;
    cv = stddev / mean;

    return (ULONG)(cv * 100.0) < WKD_C2_BEACON_MAX_CV;
}
