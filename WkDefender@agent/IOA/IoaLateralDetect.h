/**************************************************/
/*  WkDefender IOA — 横向移动行为检测 (死代码)        */
/*                                                  */
/*  迁移自 ShadowStrike BehaviorAnalyzer             */
/*  UpdateLateralMovementScore (BehaviorAnalyzer.cpp */
/*  L1363-1406)。功能重实现, 非源码复制。             */
/*                                                  */
/*  死代码: 依赖驱动网络/服务事件源未建立,             */
/*  检测逻辑完整但不接入流水线。                      */
/*  待接通: 驱动补网络事件源 (远程端口) + 服务事件     */
/*  源后激活。                                       */
/*                                                  */
/*  评分 (对齐 SS BehaviorConstants):                */
/*    远程服务创建 +20 (T1021.002)                   */
/*    WMI 远程执行 +15 (T1047)                       */
/*    SMB 445 +8, RDP 3389 +10, WinRM 5985/6 +12     */
/**************************************************/

#pragma once

#include "IoaTypes.h"

/**************************************************/
/*   SS BehaviorEventType 语义常量 (对齐 SS L485-662) */
/**************************************************/

#define WKD_EVT_SERVICE_INSTALL     500     /* ServiceInstall */
#define WKD_EVT_WMI_EXEC            602     /* WMIExec */
#define WKD_EVT_NET_CONNECT         400     /* NetworkConnect */

/**************************************************/
/*   评分常量 (对齐 SS BehaviorConstants)           */
/**************************************************/

#define WKD_LAT_SERVICE_SCORE       20      /* 远程服务创建 (目标≠自身) */
#define WKD_LAT_WMI_SCORE           15      /* WMI 远程执行 */
#define WKD_LAT_SMB_SCORE           8       /* 445 */
#define WKD_LAT_RDP_SCORE           10      /* 3389 */
#define WKD_LAT_WINRM_SCORE         12      /* 5985/5986 */

/**************************************************/
/*   高危端口 (对齐 SS L1384-1396)                  */
/**************************************************/

#define WKD_LAT_PORT_SMB            445
#define WKD_LAT_PORT_RDP            3389
#define WKD_LAT_PORT_WINRM_1        5985
#define WKD_LAT_PORT_WINRM_2        5986

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * IoaLateral_UpdateScore — 横向移动行为评分 (死代码)。
 *
 * 依据事件类型/端口分支累计 State 计数器, 返回得分增量,
 * 并在命中时置位 DEF_BEHAVIOR_FLAG_LATERAL_MOVEMENT。
 * 远程服务创建需 TargetProcessId != SourceProcessId
 * (由接入层在 Evt->TargetProcessId 区分)。
 *
 * 参数:
 *   State — 进程级行为状态 (读写)。
 *   Evt   — 归一化行为事件视图 (只读)。
 *
 * 返回值: 本次事件得分增量 [0,100]。
 */
ULONG
IoaLateral_UpdateScore(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_    const WKD_BEHAVIOR_EVENT*   Evt
    );
