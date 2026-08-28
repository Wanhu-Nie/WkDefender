/**************************************************/
/*  WkDefender IOA — C2 通信行为检测 (死代码)        */
/*                                                  */
/*  迁移自 ShadowStrike BehaviorAnalyzer             */
/*  UpdateC2Score (BehaviorAnalyzer.cpp L1412-1508)。 */
/*  功能重实现, 非源码复制。                          */
/*                                                  */
/*  死代码: 依赖驱动网络事件源未建立,                 */
/*  检测逻辑完整但不接入流水线。                      */
/*  待接通: 驱动补网络事件源 (ETW/WFP) +             */
/*  ThreatIntel 情报订阅后激活。                      */
/*                                                  */
/*  评分 (对齐 SS BehaviorConstants):                */
/*    信标周期 (CV<0.3) +20 (T1071)                  */
/*    DGA 高熵域名 +10 (T1568.002)                   */
/*    情报域名命中 +30 (T1071.001)                   */
/**************************************************/

#pragma once

#include "IoaTypes.h"

/**************************************************/
/*   SS BehaviorEventType 语义常量 (对齐 SS L485-662) */
/**************************************************/

#define WKD_EVT_NET_CONNECT         400     /* NetworkConnect */
#define WKD_EVT_NET_SEND            403     /* NetworkSend */
#define WKD_EVT_NET_HTTP_REQUEST    406     /* NetworkHTTPRequest */
#define WKD_EVT_NET_HTTPS_REQUEST   407     /* NetworkHTTPSRequest */

/**************************************************/
/*   评分常量 (对齐 SS BehaviorConstants)           */
/**************************************************/

#define WKD_C2_BEACON_SCORE         20      /* 信标 CV<0.3 */
#define WKD_C2_DGA_SCORE            10      /* DGA 高熵域名 */
#define WKD_C2_INTEL_SCORE          30      /* 情报域名命中 */

/* DGA 启发参数 (对齐 SS L1499) */
#define WKD_C2_DGA_MIN_LEN          15      /* 域名最短长度 */
#define WKD_C2_DGA_UNIQ_RATIO       70      /* 唯一字符率 >0.7 (百分制) */

/* 信标检测参数 (对齐 SS L1465-1481) */
#define WKD_C2_BEACON_MIN_INTERVALS 4       /* 最少间隔数 */
#define WKD_C2_BEACON_MAX_CV        30      /* 变异系数 <0.3 (百分制) */

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * IoaC2_UpdateScore — C2 通信行为评分 (死代码)。
 *
 * 依据网络事件分支累计 State 计数器, 返回得分增量, 并在
 * 命中时置位 DEF_BEHAVIOR_FLAG_C2_COMMUNICATION。
 * DGA 判定基于 RemoteHost 字符熵; 情报命中需接入层
 * 预填 Evt->ThreatIntelHits (见 WKD_BEHAVIOR_EVENT)。
 *
 * 参数:
 *   State — 进程级行为状态 (读写)。
 *   Evt   — 归一化行为事件视图 (只读)。
 *
 * 返回值: 本次事件得分增量 [0,100]。
 */
ULONG
IoaC2_UpdateScore(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_    const WKD_BEHAVIOR_EVENT*   Evt
    );

/*
 * IoaC2_IsBeaconing — 信标间隔规律性判定 (死代码, 纯统计)。
 *
 * 计算间隔数组的变异系数 (CV=标准差/均值), CV<0.3 视为
 * 规律信标。间隔由接入层从网络事件历史窗口提取。
 *
 * 参数:
 *   IntervalsMs — 相邻连接间隔数组 (毫秒)。
 *   Count       — 间隔个数 (>= WKD_C2_BEACON_MIN_INTERVALS)。
 *
 * 返回值: TRUE 规律信标 / FALSE 否。
 */
BOOLEAN
IoaC2_IsBeaconing(
    _In_reads_(Count) const ULONG* IntervalsMs,
    _In_                   ULONG   Count
    );
