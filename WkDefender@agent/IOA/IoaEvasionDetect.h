/**************************************************/
/*  WkDefender IOA — 防御规避行为检测 (死代码)        */
/*                                                  */
/*  迁移自 ShadowStrike BehaviorAnalyzer             */
/*  UpdateEvasionScore (BehaviorAnalyzer.cpp         */
/*  L1225-1279) + 文档/脚本解释器库 (L232-244)。      */
/*  功能重实现, 非源码复制。                          */
/*                                                  */
/*  死代码: 依赖驱动 syscall/文件/注册表事件源未激活,  */
/*  检测逻辑完整但不接入流水线。                      */
/*  待接通: 驱动补 SmInitialize (syscall) + 文件/     */
/*  注册表回调后激活。                               */
/*                                                  */
/*  评分 (对齐 SS BehaviorConstants):                */
/*    反调试 +20, VM/沙箱 +20, 日志清除 +35 T1070.001 */
/*    时间戳篡改 +25 T1070.006, 安全禁用 +60 T1562.001 */
/*    masquerade (脚本父+Temp/AppData) +10 T1036      */
/**************************************************/

#pragma once

#include "IoaTypes.h"

/**************************************************/
/*   SS BehaviorEventType 语义常量 (对齐 SS L485-662) */
/**************************************************/

#define WKD_EVT_PROCESS_CREATE      1       /* ProcessCreate */
#define WKD_EVT_ANTI_DEBUG          750     /* AntiDebugAttempt */
#define WKD_EVT_VM_DETECTION        751     /* VMDetectionAttempt */
#define WKD_EVT_SANDBOX_DETECTION   752     /* SandboxDetectionAttempt */
#define WKD_EVT_LOG_CLEAR           753     /* LogClear */
#define WKD_EVT_TIMESTOMP           754     /* Timestomp */
#define WKD_EVT_SECURITY_DISABLE    755     /* SecurityDisable */

/**************************************************/
/*   评分常量 (对齐 SS BehaviorConstants)           */
/**************************************************/

#define WKD_EVASION_ANTIDEBUG_SCORE 20      /* SS ANTI_DEBUG_SCORE */
#define WKD_EVASION_LOGCLEAR_SCORE  35      /* SS LOG_TAMPERING_SCORE */
#define WKD_EVASION_TIMESTOMP_SCORE 25      /* SS TIMESTOMPING_SCORE */
#define WKD_EVASION_SECURITY_SCORE  60      /* SS SECURITY_INTERFERENCE_SCORE */
#define WKD_EVASION_MASQUERADE_SCORE 10     /* 脚本父 + Temp/AppData */

/**************************************************/
/*   masquerade 可疑路径子串                        */
/**************************************************/

#define WKD_EVASION_TEMP_SUBSTR      L"\\temp\\"
#define WKD_EVASION_APPDATA_SUBSTR   L"\\appdata\\"

/**************************************************/
/*   文档应用库 (SS L232-236)                       */
/**************************************************/

static const PCWSTR g_WkdDocumentApps[] = {
    L"winword.exe", L"excel.exe",  L"powerpnt.exe", L"outlook.exe",
    L"onenote.exe", L"msaccess.exe", L"acrord32.exe", L"acrobat.exe",
    L"foxitreader.exe", L"visio.exe",
};
#define WKD_EVASION_DOCAPP_COUNT \
    (sizeof(g_WkdDocumentApps) / sizeof(g_WkdDocumentApps[0]))

/**************************************************/
/*   脚本解释器库 (SS L238-244)                     */
/**************************************************/

static const PCWSTR g_WkdScriptInterpreters[] = {
    L"powershell.exe", L"pwsh.exe", L"cmd.exe", L"wscript.exe",
    L"cscript.exe",  L"mshta.exe",  L"regsvr32.exe", L"rundll32.exe",
    L"msiexec.exe",  L"certutil.exe", L"bitsadmin.exe", L"wmic.exe",
    L"bash.exe",     L"python.exe", L"python3.exe",   L"perl.exe",
    L"ruby.exe",     L"node.exe",
};
#define WKD_EVASION_SCRIPT_COUNT \
    (sizeof(g_WkdScriptInterpreters) / sizeof(g_WkdScriptInterpreters[0]))

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * IoaEvasion_UpdateScore — 防御规避行为评分 (死代码)。
 *
 * 依据事件类型分支累计 State 计数器, 返回得分增量, 并在
 * 命中时置位 DEF_BEHAVIOR_FLAG_EVASION。
 *
 * 参数:
 *   State — 进程级行为状态 (读写)。
 *   Evt   — 归一化行为事件视图 (只读)。
 *
 * 返回值: 本次事件得分增量 [0,100]。
 */
ULONG
IoaEvasion_UpdateScore(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_    const WKD_BEHAVIOR_EVENT*   Evt
    );

/*
 * IoaEvasion_CheckMasquerade — 脚本解释器 masquerade 检测 (死代码)。
 *
 * 脚本解释器 (powershell/cmd 等) 从 Temp/AppData 路径启动
 * 视为进程伪装 (对齐 SS L1262-1272)。
 *
 * 参数:
 *   State          — 进程级行为状态 (读写 MasqueradeHits/标志)。
 *   ProcessPath    — 当前进程完整路径 (小写比较)。
 *   IsScriptParent — 父进程是否脚本解释器。
 *
 * 返回值: 本次得分增量 [0,100]。
 */
ULONG
IoaEvasion_CheckMasquerade(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_opt_ PCWSTR                     ProcessPath,
    _In_    BOOLEAN                     IsScriptParent
    );

/*
 * IoaEvasion_IsScriptInterpreter — 脚本解释器判定 (死代码)。
 *
 * 进程名是否命中脚本解释器库 (对齐 SS IsScriptInterpreter)。
 * 接入阶段用于判定父进程是否为脚本解释器 (masquerade 前置)。
 *
 * 参数:
 *   ProcessName — 进程名 (如 L"powershell.exe")。
 *
 * 返回值: TRUE 脚本解释器 / FALSE 否。
 */
BOOLEAN
IoaEvasion_IsScriptInterpreter(
    _In_ PCWSTR ProcessName
    );

/*
 * IoaEvasion_IsDocumentApp — 文档应用判定 (死代码)。
 *
 * 进程名是否命中文档应用库 (对齐 SS IsDocumentApplication)。
 * 供接入阶段标记"文档父进程"上下文。
 *
 * 参数:
 *   ProcessName — 进程名 (如 L"winword.exe")。
 *
 * 返回值: TRUE 文档应用 / FALSE 否。
 */
BOOLEAN
IoaEvasion_IsDocumentApp(
    _In_ PCWSTR ProcessName
    );
