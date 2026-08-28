/**************************************************/
/*  WkDefender IOA — 凭证窃取行为检测实现 (死代码)   */
/*                                                  */
/*  迁移自 ShadowStrike BehaviorAnalyzer             */
/*  UpdateCredentialScore (BehaviorAnalyzer.cpp      */
/*  L1155-1220) + IsLSASSProcess (L2810-2814)。      */
/*  功能重实现, 非源码复制。                         */
/*                                                  */
/*  补遗漏: 目标进程名识别 (现有 CredentialDumping    */
/*  位图模板缺此一环)。死代码, 无调用者。             */
/**************************************************/

#include "IoaCredentialDetect.h"
#include "../DefendTypes.h"

#include <wchar.h>
#include <ctype.h>

/**************************************************/
/*           内部辅助函数 (文件内静态)                */
/**************************************************/

static
BOOLEAN
IoaCred_IsCredentialTarget(
    _In_ PCWSTR ProcessName
    )
/*++
Routine Description:
    判断进程名是否命中凭据目标库 (大小写不敏感)。

Arguments:
    ProcessName — 目标进程名 (如 L"lsass.exe")。

Return Value:
    TRUE 凭据目标 / FALSE 否。
--*/
{
    WCHAR lower[32];
    size_t len;

    if (!ProcessName || !ProcessName[0]) return FALSE;

    len = wcslen(ProcessName);
    if (len >= 32) return FALSE;

    for (size_t i = 0; i < len; i++) {
        lower[i] = (WCHAR)towlower(ProcessName[i]);
    }
    lower[len] = L'\0';

    for (ULONG i = 0; i < WKD_CRED_TARGET_COUNT; i++) {
        if (_wcsicmp(lower, g_WkdCredentialTargets[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/**************************************************/
/*           主检测函数                             */
/**************************************************/

ULONG
IoaCredential_UpdateScore(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_    const WKD_BEHAVIOR_EVENT*   Evt,
    _In_opt_ PCWSTR                     TargetProcessName
    )
/*++
Routine Description:
    凭证窃取行为评分。ProcessOpen 依赖接入层解析目标进程名
    传入 (TargetProcessName); 其余事件按 Type 分支。

Arguments:
    State              — 进程级行为状态 (读写)。
    Evt                — 归一化行为事件视图 (只读)。
    TargetProcessName  — 目标进程名 (可空, ProcessOpen 必需)。

Return Value:
    本次事件得分增量 [0,100]。
--*/
{
    ULONG scoreAdd = 0;

    if (!State || !Evt) return 0;

    switch (Evt->Type) {
        case WKD_EVT_PROCESS_OPEN: {
            /* 目标进程名命中凭据目标 且 携带敏感访问权限 */
            if (TargetProcessName != NULL &&
                IoaCred_IsCredentialTarget(TargetProcessName) &&
                (Evt->AccessMask & WKD_CRED_OPEN_MASK)) {
                State->CredentialTargetOpens++;
                scoreAdd += WKD_CRED_LSASS_SCORE;
                State->DetectionFlags |= DEF_BEHAVIOR_FLAG_CREDENTIAL_TARGET;
            }
            break;
        }

        case WKD_EVT_LSASS_ACCESS: {
            State->CredentialTargetOpens++;
            scoreAdd += WKD_CRED_LSASS_SCORE;
            State->DetectionFlags |= DEF_BEHAVIOR_FLAG_CREDENTIAL_TARGET;
            break;
        }

        case WKD_EVT_SAM_ACCESS: {
            State->CredentialTargetOpens++;
            scoreAdd += WKD_CRED_SAM_SCORE;
            State->DetectionFlags |= DEF_BEHAVIOR_FLAG_CREDENTIAL_TARGET;
            break;
        }

        case WKD_EVT_CREDENTIAL_ACCESS:
        case WKD_EVT_CREDENTIAL_DUMP: {
            State->CredentialTargetOpens++;
            scoreAdd += WKD_CRED_STORE_SCORE;
            State->DetectionFlags |= DEF_BEHAVIOR_FLAG_CREDENTIAL_TARGET;
            break;
        }

        case WKD_EVT_TOKEN_STEAL:
        case WKD_EVT_TOKEN_DUPLICATE: {
            State->TokenStealOps++;
            scoreAdd += WKD_CRED_TOKEN_SCORE;
            State->DetectionFlags |= DEF_BEHAVIOR_FLAG_CREDENTIAL_TARGET;
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
