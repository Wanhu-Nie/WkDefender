/**************************************************/
/*  WkDefender IOA — 数据外渗行为检测实现 (死代码)   */
/*                                                  */
/*  迁移自 ShadowStrike BehaviorAnalyzer             */
/*  UpdateExfiltrationScore (BehaviorAnalyzer.cpp    */
/*  L1285-1357)。功能重实现, 非源码复制。            */
/*                                                  */
/*  死代码: 无调用者, 未接入流水线。                  */
/**************************************************/

#include "IoaExfilDetect.h"
#include "../DefendTypes.h"

#include <wchar.h>
#include <ctype.h>

/**************************************************/
/*           内部辅助函数 (文件内静态)                */
/**************************************************/

static
BOOLEAN
IoaExfil_IsArchiveExtension(
    _In_ PCWSTR Extension
    )
/*++
Routine Description:
    判断扩展名是否为归档压缩格式 (对齐 SS L1341-1345:
    .zip/.rar/.7z/.tar/.gz)。

Arguments:
    Extension — 扩展名 (含前导点)。

Return Value:
    TRUE 归档格式 / FALSE 否。
--*/
{
    static const PCWSTR archives[] = {
        L".zip", L".rar", L".7z", L".tar", L".gz",
    };

    WCHAR lower[16];
    size_t len;

    if (!Extension || !Extension[0]) return FALSE;

    len = wcslen(Extension);
    if (len >= 16) return FALSE;

    for (size_t i = 0; i < len; i++) lower[i] = (WCHAR)towlower(Extension[i]);
    lower[len] = L'\0';

    for (ULONG i = 0; i < 5; i++) {
        if (_wcsicmp(lower, archives[i]) == 0) return TRUE;
    }
    return FALSE;
}

/**************************************************/
/*           主检测函数                             */
/**************************************************/

ULONG
IoaExfil_UpdateScore(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_    const WKD_BEHAVIOR_EVENT*   Evt
    )
/*++
Routine Description:
    数据外渗行为评分。依据事件类型分支累计 State 计数器
    (含 TotalBytesSent), 命中时置位 EXFILTRATION 检测标志。
    累计传输阈值仅触发一次 (对齐 SS exfilThresholdTriggered)。

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
        case WKD_EVT_NET_SEND:
        case WKD_EVT_NET_UPLOAD: {
            /* 单次大传输 */
            if (Evt->BytesSent > WKD_EXFIL_SINGLE_BYTES) {
                scoreAdd += WKD_EXFIL_LARGE_SINGLE;
                State->DetectionFlags |= DEF_BEHAVIOR_FLAG_EXFILTRATION;
            }

            /* 累计大传输 (仅一次) */
            State->TotalBytesSent += Evt->BytesSent;
            if (!State->ExfilCumulTriggered &&
                State->TotalBytesSent > WKD_EXFIL_CUMUL_BYTES) {
                State->ExfilCumulTriggered = TRUE;
                scoreAdd += WKD_EXFIL_LARGE_CUMUL;
                State->DetectionFlags |= DEF_BEHAVIOR_FLAG_EXFILTRATION;
            }
            break;
        }

        case WKD_EVT_NET_DNS_QUERY: {
            State->DnsQueries++;

            /* DNS 隧道: 异常长的子域标签 */
            if (Evt->RemoteHost != NULL &&
                wcslen(Evt->RemoteHost) > WKD_EXFIL_DNS_TUNNEL_LEN) {
                scoreAdd += WKD_EXFIL_DNS_TUNNEL;
                State->DetectionFlags |= DEF_BEHAVIOR_FLAG_EXFILTRATION;
            }

            /* 高 DNS 查询率 */
            if (State->DnsQueries > WKD_EXFIL_DNS_RATE_MAX) {
                scoreAdd += WKD_EXFIL_DNS_RATE;
            }
            break;
        }

        case WKD_EVT_FILE_CREATE: {
            /* 归档创建 + 已有出站流量 */
            if (State->TotalBytesSent > WKD_EXFIL_ARCHIVE_FLOW &&
                IoaExfil_IsArchiveExtension(Evt->FileExtension)) {
                scoreAdd += WKD_EXFIL_ARCHIVE;
                State->DetectionFlags |= DEF_BEHAVIOR_FLAG_EXFILTRATION;
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
