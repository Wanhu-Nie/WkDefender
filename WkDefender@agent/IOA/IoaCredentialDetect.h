/**************************************************/
/*  WkDefender IOA — 凭证窃取行为检测 (补遗漏, 死代码) */
/*                                                  */
/*  迁移自 ShadowStrike BehaviorAnalyzer             */
/*  UpdateCredentialScore (BehaviorAnalyzer.cpp      */
/*  L1155-1220) + 凭据目标库 (L221-224,             */
/*  IsLSASSProcess L2810-2814)。                     */
/*  功能重实现, 非源码复制。                          */
/*                                                  */
/*  补遗漏: WkD 现有 CredentialDumping 模板/FSM      */
/*  (Opens+ReadsFrom 位图) 缺"目标进程名识别"一环。    */
/*  本模块实现凭据目标进程打开判定, 接入时融合进       */
/*  IoaEngine Opens 边生成处。                       */
/*                                                  */
/*  死代码: 无调用者, 未接入流水线。                  */
/*  待接通: 接入阶段由 IoaObserve 解析目标进程名       */
/*  (WKD_PROCESS.ImageFileName) 后调用。         */
/*                                                  */
/*  评分 (对齐 SS BehaviorConstants):                */
/*    LSASS/凭据目标打开(VM_READ|QUERY) +70 T1003.001 */
/*    SAM +65 T1003.002, 凭据存储 +40 T1555           */
/*    Token 窃取/复制 +20 T1134                       */
/**************************************************/

#pragma once

#include "IoaTypes.h"

/**************************************************/
/*   SS BehaviorEventType 语义常量 (对齐 SS L485-662) */
/**************************************************/

#define WKD_EVT_PROCESS_OPEN        3       /* ProcessOpen */
#define WKD_EVT_LSASS_ACCESS        701     /* LSASSAccess */
#define WKD_EVT_SAM_ACCESS          702     /* SAMAccess */
#define WKD_EVT_CREDENTIAL_ACCESS   700     /* CredentialAccess */
#define WKD_EVT_CREDENTIAL_DUMP     703     /* CredentialDump */
#define WKD_EVT_TOKEN_STEAL         704     /* TokenSteal */
#define WKD_EVT_TOKEN_DUPLICATE     705     /* TokenDuplicate */

/**************************************************/
/*   评分常量 (对齐 SS BehaviorConstants)           */
/**************************************************/

#define WKD_CRED_LSASS_SCORE        70      /* SS LSASS_ACCESS_SCORE */
#define WKD_CRED_SAM_SCORE          65      /* SS SAM_ACCESS_SCORE */
#define WKD_CRED_STORE_SCORE        40      /* SS CREDENTIAL_STORE_SCORE */
#define WKD_CRED_TOKEN_SCORE        20      /* Token 操纵 */

/* ProcessOpen 敏感访问位 (对齐 SS L1205: VM_READ|QUERY_INFORMATION) */
#define WKD_CRED_OPEN_MASK          (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)

/**************************************************/
/*   凭据目标进程库 (SS L221-224)                    */
/*   仅保留 lsass/csrss/winlogon (排除 svchost/     */
/*   services/wininit — 合法管理工具频繁打开易误报)   */
/**************************************************/

static const PCWSTR g_WkdCredentialTargets[] = {
    L"lsass.exe",
    L"lsaiso.exe",
    L"csrss.exe",
    L"winlogon.exe",
};
#define WKD_CRED_TARGET_COUNT \
    (sizeof(g_WkdCredentialTargets) / sizeof(g_WkdCredentialTargets[0]))

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * IoaCredential_UpdateScore — 凭证窃取行为评分 (死代码)。
 *
 * ProcessOpen 事件需由接入层解析目标进程名传入
 * (TargetProcessName, 可 NULL); 其余事件按 Type 分支。
 *
 * 参数:
 *   State              — 进程级行为状态 (读写)。
 *   Evt                — 归一化行为事件视图 (只读)。
 *   TargetProcessName  — 目标进程名 (如 L"lsass.exe", 可空)。
 *
 * 返回值: 本次事件得分增量 [0,100]。
 */
ULONG
IoaCredential_UpdateScore(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_    const WKD_BEHAVIOR_EVENT*   Evt,
    _In_opt_ PCWSTR                     TargetProcessName
    );
