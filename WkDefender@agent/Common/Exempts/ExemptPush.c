/**************************************************/
/*  WkDefender — 排除子系统采集与推送                */
/*                                                   */
/*  职责（合并 IocWhitelistPush）：                   */
/*    - 采集核心系统组件哈希写入规则库（Hash 规则，    */
/*      驱动侧 TrustedHash 规则消费）                 */
/*    - 全量推送：枚举规则 → ALPC 0x3105 增量推送驱动  */
/*                                                   */
/*  推送协议：首条 BatchOp=0(Clear+Replace) 递增版本   */
/*  号，其余 BatchOp=1(Add)；同步回执校验 AppliedCount。*/
/*                                                   */
/*  推送维度：仅 Path（RuleType=0）。驱动侧 Exempts 为 */
/*  进程/路径/扩展名/PID 维度，不消费 TrustedHash      */
/*  （用户决策：driver 不需要 hash 匹配功能，2026-08-14*/
/*  重构 #67）。Hash 规则仅 agent 本地豁免消费；证书/  */
/*  发布者规则为 agent 文件维度，亦仅本地消费不推送。  */
/**************************************************/

#include "ExemptsInternal.h"
#include "../../IOC/IocScanner.h"        /* IocScanner_ComputeFileSha256 */
#include "../../Notification/AlpcService.h"
#include "../../DefendTypes.h"           /* DEF_SHA256_HASH / DEF_SHA256_SIZE */
#include <stdio.h>                       /* _snwprintf_s */
#include <string.h>                      /* memcpy */

/**************************************************/
/*              系统可信组件清单                    */
/**************************************************/

/*
 * 系统可信组件清单（system32 下可执行组件 + 核心 DLL）。
 * 对齐驱动侧 ExemptsDefaultSystemPaths 的 system32 集合。
 */
static const WCHAR* g_ExemptSystemTrustedPaths[] = {
    /* 核心系统进程 */
    L"C:\\Windows\\System32\\svchost.exe",
    L"C:\\Windows\\System32\\services.exe",
    L"C:\\Windows\\System32\\lsass.exe",
    L"C:\\Windows\\System32\\wininit.exe",
    L"C:\\Windows\\System32\\csrss.exe",
    L"C:\\Windows\\System32\\smss.exe",
    L"C:\\Windows\\System32\\winlogon.exe",
    L"C:\\Windows\\System32\\dwm.exe",
    L"C:\\Windows\\explorer.exe",
    L"C:\\Windows\\System32\\fontdrvhost.exe",

    /* 系统服务与后台任务 */
    L"C:\\Windows\\System32\\spoolsv.exe",
    L"C:\\Windows\\System32\\taskmgr.exe",
    L"C:\\Windows\\System32\\Conhost.exe",
    L"C:\\Windows\\System32\\rundll32.exe",
    L"C:\\Windows\\System32\\RuntimeBroker.exe",
    L"C:\\Windows\\System32\\ctfmon.exe",
    L"C:\\Windows\\System32\\taskhostw.exe",
    L"C:\\Windows\\System32\\sihost.exe",
    L"C:\\Windows\\System32\\smartscreen.exe",
    L"C:\\Windows\\System32\\audiodg.exe",

    /* 核心系统 DLL */
    L"C:\\Windows\\System32\\kernel32.dll",
    L"C:\\Windows\\System32\\ntdll.dll",
    L"C:\\Windows\\System32\\user32.dll",
    L"C:\\Windows\\System32\\shell32.dll",
    L"C:\\Windows\\System32\\gdi32.dll",
    L"C:\\Windows\\System32\\advapi32.dll",
};

/**************************************************/
/*                  采集与推送                      */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
ExemptPush_CollectSystemHashes(
    _Inout_ PEXEMPT_ENGINE Engine
    )
/*++
Routine Description:
    枚举系统可信组件清单，计算 SHA256 写入规则库。
    仅写 Hash 规则（驱动侧 TrustedHash 规则消费）。

Arguments:
    Engine - 子系统全局。

Return Value:
    STATUS_SUCCESS。
--*/
{
    ULONG i;

    if (Engine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < RTL_NUMBER_OF(g_ExemptSystemTrustedPaths); i++) {
        DEF_SHA256_HASH hash;
        EXEMPT_RULE rule;

        if (!IocScanner_ComputeFileSha256(g_ExemptSystemTrustedPaths[i], &hash)) {
            continue;
        }

        ZeroMemory(&rule, sizeof(rule));
        rule.Type = ExemptRule_Hash;
        rule.Reason = ExemptReason_HashMatch;
        rule.MatchMode = 0;
        rule.Flags = EXEMPT_FLAG_SYSTEM;    /* 系统采集规则不可移除 */
        rule.HashAlgorithm = 1;             /* SHA256 */
        rule.HashLength = DEF_SHA256_SIZE;
        memcpy(rule.HashData, hash.Data, DEF_SHA256_SIZE);
        _snwprintf_s(rule.Description, EXEMPT_MAX_DESCRIPTION, _TRUNCATE,
                     L"System: %ls", g_ExemptSystemTrustedPaths[i]);

        ExemptsMgr_AddRule(Engine, &rule, NULL);
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ExemptPush_PushAll(
    _Inout_ PEXEMPT_ENGINE Engine
    )
/*++
Routine Description:
    全量推送：采集系统哈希（agent 本地豁免）→ 枚举规则快照 →
    首条 Clear+Replace（版本号递增）→ 其余 Add → 逐条同步回执校验。
    仅推送 Path 维度（驱动可消费；驱动侧 Exempts 不消费 TrustedHash）。

Arguments:
    Engine - 子系统全局。

Return Value:
    STATUS_SUCCESS / 推送失败状态。
--*/
{
    PEXEMPT_RULE rules = NULL;
    ULONG count = 0;
    NTSTATUS status;
    ULONG i;
    BOOLEAN first = TRUE;
    UINT64 pushVersion;

    if (Engine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = ExemptPush_CollectSystemHashes(Engine);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ExemptsMgr_GetRules(Engine, &rules, &count);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (count == 0) {
        return STATUS_SUCCESS;
    }

    pushVersion = ++Engine->PushVersion;

    for (i = 0; i < count; i++) {
        WKD_ALPC_EXEMPT_UPDATE update;
        WKD_ALPC_EXEMPT_ACK ack;

        ZeroMemory(&update, sizeof(update));
        update.Version = (ULONG)pushVersion;
        update.BatchOp = first ? 0 : 1;     /* 首条 Clear+Replace，其余 Add */
        update.Flags = 0;
        update.TTLSeconds = 0;

        if (rules[i].Type == ExemptRule_Path &&
            rules[i].Pattern[0] != L'\0') {
            update.RuleType = 0;            /* Path，Value=WCHAR 路径 */
            wcsncpy_s(update.Value, RTL_NUMBER_OF(update.Value),
                      rules[i].Pattern, _TRUNCATE);
        } else {
            continue;   /* Hash/证书/发布者维度 agent 本地消费，驱动不消费不推送 */
        }

        ZeroMemory(&ack, sizeof(ack));
        status = WkdAlpcSendExemptsUpdate(&WkdDefaultAlpcServer, &update, &ack);
        if (!NT_SUCCESS(status)) {
            UtHeapFree(rules);
            return status;
        }

        first = FALSE;
    }

    UtHeapFree(rules);
    return STATUS_SUCCESS;
}
