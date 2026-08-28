/**************************************************/
/*  WkDefender IOA — 横向移动行为检测实现 (死代码)   */
/*                                                  */
/*  迁移自 ShadowStrike BehaviorAnalyzer             */
/*  UpdateLateralMovementScore (BehaviorAnalyzer.cpp */
/*  L1363-1406)。功能重实现, 非源码复制。            */
/*                                                  */
/*  死代码: 无调用者, 未接入流水线。                  */
/**************************************************/

#include "IoaLateralDetect.h"
#include "../DefendTypes.h"

/**************************************************/
/*           主检测函数                             */
/**************************************************/

ULONG
IoaLateral_UpdateScore(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_    const WKD_BEHAVIOR_EVENT*   Evt
    )
/*++
Routine Description:
    横向移动行为评分。依据事件类型/端口分支累计 State 计数器,
    命中时置位 LATERAL_MOVEMENT 检测标志。
    远程服务创建需 Evt->TargetProcessId 非 0 (目标≠自身,
    源进程即 State 对应进程, 由接入层保证)。

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
        case WKD_EVT_SERVICE_INSTALL: {
            if (Evt->TargetProcessId != 0) {
                State->RemoteServiceInstalls++;
                scoreAdd += WKD_LAT_SERVICE_SCORE;
                State->DetectionFlags |= DEF_BEHAVIOR_FLAG_LATERAL_MOVEMENT;
            }
            break;
        }

        case WKD_EVT_WMI_EXEC: {
            State->WmiExecHits++;
            scoreAdd += WKD_LAT_WMI_SCORE;
            State->DetectionFlags |= DEF_BEHAVIOR_FLAG_LATERAL_MOVEMENT;
            break;
        }

        case WKD_EVT_NET_CONNECT: {
            switch (Evt->RemotePort) {
                case WKD_LAT_PORT_SMB:
                    State->Port445++;
                    scoreAdd += WKD_LAT_SMB_SCORE;
                    State->DetectionFlags |= DEF_BEHAVIOR_FLAG_LATERAL_MOVEMENT;
                    break;

                case WKD_LAT_PORT_RDP:
                    State->Port3389++;
                    scoreAdd += WKD_LAT_RDP_SCORE;
                    State->DetectionFlags |= DEF_BEHAVIOR_FLAG_LATERAL_MOVEMENT;
                    break;

                case WKD_LAT_PORT_WINRM_1:
                case WKD_LAT_PORT_WINRM_2:
                    State->Port5985++;
                    scoreAdd += WKD_LAT_WINRM_SCORE;
                    State->DetectionFlags |= DEF_BEHAVIOR_FLAG_LATERAL_MOVEMENT;
                    break;

                default:
                    break;
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
