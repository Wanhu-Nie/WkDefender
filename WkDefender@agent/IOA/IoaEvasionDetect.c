/**************************************************/
/*  WkDefender IOA — 防御规避行为检测实现 (死代码)   */
/*                                                  */
/*  迁移自 ShadowStrike BehaviorAnalyzer             */
/*  UpdateEvasionScore (BehaviorAnalyzer.cpp         */
/*  L1225-1279)。功能重实现, 非源码复制。            */
/*                                                  */
/*  死代码: 无调用者, 未接入流水线。                  */
/**************************************************/

#include "IoaEvasionDetect.h"
#include "../DefendTypes.h"

#include <wchar.h>
#include <ctype.h>

/**************************************************/
/*           内部辅助函数 (文件内静态)                */
/**************************************************/

static
BOOLEAN
IoaEvasion_ContainsSubstr(
    _In_ PCWSTR Haystack,
    _In_ PCWSTR Needle
    )
/*++
Routine Description:
    大小写不敏感子串包含判断。

Arguments:
    Haystack — 待查字符串。
    Needle   — 子串。

Return Value:
    TRUE 包含 / FALSE 否。
--*/
{
    WCHAR lower[DEF_MAX_PATH];
    WCHAR subLower[64];
    size_t len, subLen;

    if (!Haystack || !Needle) return FALSE;

    len = wcslen(Haystack);
    subLen = wcslen(Needle);
    if (len >= DEF_MAX_PATH || subLen >= 64) return FALSE;

    for (size_t i = 0; i < len; i++) lower[i] = (WCHAR)towlower(Haystack[i]);
    lower[len] = L'\0';
    for (size_t i = 0; i < subLen; i++) subLower[i] = (WCHAR)towlower(Needle[i]);
    subLower[subLen] = L'\0';

    return wcsstr(lower, subLower) != NULL;
}

/**************************************************/
/*           主检测函数                             */
/**************************************************/

ULONG
IoaEvasion_UpdateScore(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_    const WKD_BEHAVIOR_EVENT*   Evt
    )
/*++
Routine Description:
    防御规避行为评分。依据事件类型分支累计 State 计数器,
    命中时置位 EVASION 检测标志。

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
        case WKD_EVT_ANTI_DEBUG: {
            State->EvasionHits++;
            scoreAdd += WKD_EVASION_ANTIDEBUG_SCORE;
            State->DetectionFlags |= DEF_BEHAVIOR_FLAG_EVASION;
            break;
        }

        case WKD_EVT_VM_DETECTION:
        case WKD_EVT_SANDBOX_DETECTION: {
            State->EvasionHits++;
            scoreAdd += WKD_EVASION_ANTIDEBUG_SCORE;
            break;
        }

        case WKD_EVT_LOG_CLEAR: {
            State->LogClearOps++;
            scoreAdd += WKD_EVASION_LOGCLEAR_SCORE;
            State->DetectionFlags |= DEF_BEHAVIOR_FLAG_EVASION;
            break;
        }

        case WKD_EVT_TIMESTOMP: {
            State->TimestompOps++;
            scoreAdd += WKD_EVASION_TIMESTOMP_SCORE;
            State->DetectionFlags |= DEF_BEHAVIOR_FLAG_EVASION;
            break;
        }

        case WKD_EVT_SECURITY_DISABLE: {
            State->EvasionHits++;
            scoreAdd += WKD_EVASION_SECURITY_SCORE;
            State->DetectionFlags |= DEF_BEHAVIOR_FLAG_EVASION;
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

ULONG
IoaEvasion_CheckMasquerade(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_opt_ PCWSTR                     ProcessPath,
    _In_    BOOLEAN                     IsScriptParent
    )
/*++
Routine Description:
    脚本解释器 masquerade 检测 (对齐 SS L1262-1272):
    脚本解释器 (powershell/cmd 等) 从 Temp/AppData 路径启动
    视为进程伪装。

Arguments:
    State          — 进程级行为状态 (读写 MasqueradeHits/标志)。
    ProcessPath    — 当前进程完整路径。
    IsScriptParent — 父进程是否脚本解释器。

Return Value:
    本次得分增量 [0,100]。
--*/
{
    if (!State || !IsScriptParent || !ProcessPath || !ProcessPath[0]) {
        return 0;
    }

    if (IoaEvasion_ContainsSubstr(ProcessPath, WKD_EVASION_TEMP_SUBSTR) ||
        IoaEvasion_ContainsSubstr(ProcessPath, WKD_EVASION_APPDATA_SUBSTR)) {
        State->MasqueradeHits++;
        State->DetectionFlags |= DEF_BEHAVIOR_FLAG_MASQUERADE;
        if (WKD_EVASION_MASQUERADE_SCORE > 0) {
            /* 并发安全重构 2026-08-23：饱和累加保 [0,100] 上限原子发布 */
            LONG old, nw; do { old = State->MaliceScore; nw = min(old + WKD_EVASION_MASQUERADE_SCORE, 100); }
              while (InterlockedCompareExchange(&State->MaliceScore, nw, old) != old);
        }
        return WKD_EVASION_MASQUERADE_SCORE;
    }

    return 0;
}

BOOLEAN
IoaEvasion_IsScriptInterpreter(
    _In_ PCWSTR ProcessName
    )
/*++
Routine Description:
    脚本解释器判定 (对齐 SS IsScriptInterpreter L2831-2845):
    进程名大小写不敏感命中 g_WkdScriptInterpreters。

Arguments:
    ProcessName — 进程名。

Return Value:
    TRUE 脚本解释器 / FALSE 否。
--*/
{
    WCHAR lower[32];
    size_t len;

    if (!ProcessName || !ProcessName[0]) return FALSE;

    len = wcslen(ProcessName);
    if (len >= 32) return FALSE;

    for (size_t i = 0; i < len; i++) lower[i] = (WCHAR)towlower(ProcessName[i]);
    lower[len] = L'\0';

    for (ULONG i = 0; i < WKD_EVASION_SCRIPT_COUNT; i++) {
        if (_wcsicmp(lower, g_WkdScriptInterpreters[i]) == 0) return TRUE;
    }
    return FALSE;
}

BOOLEAN
IoaEvasion_IsDocumentApp(
    _In_ PCWSTR ProcessName
    )
/*++
Routine Description:
    文档应用判定 (对齐 SS IsDocumentApplication L2816-2829):
    进程名大小写不敏感命中 g_WkdDocumentApps。

Arguments:
    ProcessName — 进程名。

Return Value:
    TRUE 文档应用 / FALSE 否。
--*/
{
    WCHAR lower[32];
    size_t len;

    if (!ProcessName || !ProcessName[0]) return FALSE;

    len = wcslen(ProcessName);
    if (len >= 32) return FALSE;

    for (size_t i = 0; i < len; i++) lower[i] = (WCHAR)towlower(ProcessName[i]);
    lower[len] = L'\0';

    for (ULONG i = 0; i < WKD_EVASION_DOCAPP_COUNT; i++) {
        if (_wcsicmp(lower, g_WkdDocumentApps[i]) == 0) return TRUE;
    }
    return FALSE;
}
