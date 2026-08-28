/**************************************************/
/*  WkDefender IOA — 数据外渗行为检测 (死代码)        */
/*                                                  */
/*  迁移自 ShadowStrike BehaviorAnalyzer             */
/*  UpdateExfiltrationScore (BehaviorAnalyzer.cpp    */
/*  L1285-1357)。功能重实现, 非源码复制。             */
/*                                                  */
/*  死代码: 依赖驱动网络事件源未建立,                 */
/*  检测逻辑完整但不接入流水线。                      */
/*  待接通: 驱动补网络事件源 (字节/DNS) 后激活。       */
/*                                                  */
/*  评分 (对齐 SS BehaviorConstants):                */
/*    单次传输 >10MB +10 (T1048)                     */
/*    累计 >100MB +15, DNS 隧道 +12 (T1048.003)      */
/*    DNS 查询率 >100 +5, 归档+流量 +8 (T1560.001)   */
/**************************************************/

#pragma once

#include "IoaTypes.h"

/**************************************************/
/*   SS BehaviorEventType 语义常量 (对齐 SS L485-662) */
/**************************************************/

#define WKD_EVT_NET_SEND            403     /* NetworkSend */
#define WKD_EVT_NET_UPLOAD          409     /* NetworkUpload */
#define WKD_EVT_NET_DNS_QUERY       405     /* NetworkDNSQuery */
#define WKD_EVT_FILE_CREATE         200     /* FileCreate */

/**************************************************/
/*   评分常量 (对齐 SS BehaviorConstants)           */
/**************************************************/

#define WKD_EXFIL_LARGE_SINGLE      10      /* 单次 >10MB */
#define WKD_EXFIL_LARGE_CUMUL       15      /* 累计 >100MB (仅一次) */
#define WKD_EXFIL_DNS_TUNNEL        12      /* DNS 隧道长标签 */
#define WKD_EXFIL_DNS_RATE          5       /* DNS 查询率 >100 */
#define WKD_EXFIL_ARCHIVE           8       /* 归档创建 + 已有流量 */

/* 阈值 (对齐 SS L1307/1313/1326/1334) */
#define WKD_EXFIL_SINGLE_BYTES      (10ULL * 1024 * 1024)     /* 10MB */
#define WKD_EXFIL_CUMUL_BYTES       (100ULL * 1024 * 1024)    /* 100MB */
#define WKD_EXFIL_DNS_TUNNEL_LEN    50      /* 域名最长标签 */
#define WKD_EXFIL_DNS_RATE_MAX      100     /* DNS 查询数 */
#define WKD_EXFIL_ARCHIVE_FLOW      (1024 * 1024)             /* 已有流量 1MB */

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * IoaExfil_UpdateScore — 数据外渗行为评分 (死代码)。
 *
 * 依据事件类型分支累计 State 计数器 (含 TotalBytesSent),
 * 返回得分增量, 并在命中时置位 DEF_BEHAVIOR_FLAG_EXFILTRATION。
 * 累计传输阈值仅触发一次 (对齐 SS exfilThresholdTriggered)。
 *
 * 参数:
 *   State — 进程级行为状态 (读写)。
 *   Evt   — 归一化行为事件视图 (只读)。
 *
 * 返回值: 本次事件得分增量 [0,100]。
 */
ULONG
IoaExfil_UpdateScore(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_    const WKD_BEHAVIOR_EVENT*   Evt
    );
