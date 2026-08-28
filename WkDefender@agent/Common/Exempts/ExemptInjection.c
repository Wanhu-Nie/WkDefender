/**************************************************/
/*  WkDefender — 排除子系统注入场景豁免              */
/*                                                   */
/*  合并自 IocInjectionWhitelist（ShadowStrike        */
/*  ProcessInjectionDetector ShouldWhitelist 迁移）。 */
/*                                                   */
/*  三步判定:                                        */
/*    Step1: 进程对白名单命中 → 源受保护目录 + 微软    */
/*           签名 → 豁免                             */
/*    Step2: 微软签名 + 非LOLBin + 受保护目录 → 豁免   */
/*    Step3: 否则不豁免                              */
/*                                                   */
/*  安全要点:                                        */
/*    - 名称匹配仅作预过滤，必须叠加路径 + 签名验证    */
/*    - 受保护目录 (System32/SysWOW64/WinSxS) 防       */
/*      签名二进制重定位 (种植) 攻击                   */
/*    - LOLBin 排除: 微软签名的可滥用二进制不豁免       */
/**************************************************/

#include "ExemptsInternal.h"
#include "../../Process/ProcessTypes.h"  /* PWKD_PROCESS 完整类型（门面仅前向声明） */
#include "../../IOC/IocScanner.h"
#include "../../IOC/IocLolbinDb.h"
#include "../../IOC/Signature/SignatureVerifier.h"
#include <wchar.h>

/**************************************************/
/*           进程对白名单 (名称级预过滤)              */
/**************************************************/

typedef struct _WKD_EXEMPT_PAIR {
    PCWSTR Source;      /* 源进程名 (小写) */
    PCWSTR Target;      /* 目标进程名, L"*" = 任意 */
} WKD_EXEMPT_PAIR;

static const WKD_EXEMPT_PAIR g_ExemptPairWhitelist[] = {
    { L"csrss.exe",      L"*" },
    { L"wininit.exe",   L"services.exe" },
    { L"services.exe",  L"svchost.exe" },
    { L"smss.exe",      L"csrss.exe" },
    { NULL, NULL }
};

/**************************************************/
/*             静态辅助函数                         */
/**************************************************/

/*
 * 取进程节点可执行文件名 (ImageFileName 优先)。
 */
static
PCWSTR
ExemptInjp_GetProcessName(
    _In_opt_ PWKD_PROCESS Node,
    _Out_writes_(MaxLen) WCHAR* Out,
    _In_ ULONG MaxLen
    )
{
    PCWSTR src = NULL;

    if (!Node) {
        if (MaxLen > 0) Out[0] = L'\0';
        return Out;
    }

    if (Node->ImageFileName && Node->ImageFileName->Buffer) {
        src = Node->ImageFileName->Buffer;
    } else if (Node->ImagePath && Node->ImagePath->Buffer) {
        src = Node->ImagePath->Buffer;
    }

    if (!src) {
        if (MaxLen > 0) Out[0] = L'\0';
        return Out;
    }

    {
        PCWSTR last = src;
        for (PCWSTR p = src; *p; p++) {
            if (*p == L'\\' || *p == L'/') last = p + 1;
        }
        _snwprintf_s(Out, MaxLen, _TRUNCATE, L"%ls", last);
    }

    return Out;
}

/*
 * 取进程节点完整路径 (ImagePath)。
 */
static
PCWSTR
ExemptInjp_GetProcessPath(
    _In_opt_ PWKD_PROCESS Node
    )
{
    if (!Node || !Node->ImagePath || !Node->ImagePath->Buffer) {
        return NULL;
    }
    return Node->ImagePath->Buffer;
}

/*
 * 判断路径是否位于受保护系统目录。
 * 阻止"签名二进制被重定位/种植到用户可写目录"攻击。
 */
static
BOOLEAN
ExemptInjp_IsProtectedSystemDir(
    _In_ PCWSTR Path
    )
{
    WCHAR lower[EXEMPT_MAX_PATTERN * 2];

    if (!Path || !Path[0]) return FALSE;

    _snwprintf_s(lower, RTL_NUMBER_OF(lower), _TRUNCATE, L"%ls", Path);
    _wcslwr_s(lower, RTL_NUMBER_OF(lower));

    /* 设备路径 (\Device\HarddiskVolumeN\...) 同样含此子串 */
    if (wcsstr(lower, L"\\windows\\system32\\")) return TRUE;
    if (wcsstr(lower, L"\\windows\\syswow64\\")) return TRUE;
    if (wcsstr(lower, L"\\windows\\winsxs\\"))   return TRUE;

    return FALSE;
}

/*
 * 判断文件是否为微软签名 (WinVerifyTrust + 统一判定辅助)。
 */
static
BOOLEAN
ExemptInjp_IsMicrosoftSigned(
    _In_ PCWSTR Path
    )
{
    IOC_SCAN_RESULT result;
    NTSTATUS status;

    if (!Path || !Path[0]) return FALSE;

    RtlZeroMemory(&result, sizeof(result));
    status = IocVerifySignature(Path, &result);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    if (!result.CertValid || !result.CertTrusted) {
        return FALSE;
    }

    return IocScan_IsMicrosoftSigned(&result);
}

/*
 * 判断文件名是否为 LOLBin (可滥用的微软签名二进制)。
 */
static
BOOLEAN
ExemptInjp_IsLolBin(
    _In_ PCWSTR ProcessName
    )
{
    return (IocLolbinLookup(ProcessName) != NULL);
}

/**************************************************/
/*               公开 API                          */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
ExemptInjection_IsPairWhitelisted(
    _In_ PCWSTR SourceName,
    _In_opt_ PCWSTR TargetName
    )
/*++
Routine Description:
    进程对名称级白名单预过滤。仅名称匹配, 不豁免。

Arguments:
    SourceName - 源进程文件名。
    TargetName - 目标进程文件名 (可为 NULL 表示任意)。

Return Value:
    TRUE=命中名称级白名单 (调用方须继续路径+签名验证)。
--*/
{
    WCHAR srcLow[64];
    WCHAR tgtLow[64];

    if (!SourceName || !SourceName[0]) return FALSE;

    _snwprintf_s(srcLow, RTL_NUMBER_OF(srcLow), _TRUNCATE, L"%ls", SourceName);
    _wcslwr_s(srcLow, RTL_NUMBER_OF(srcLow));

    if (TargetName && TargetName[0]) {
        _snwprintf_s(tgtLow, RTL_NUMBER_OF(tgtLow), _TRUNCATE, L"%ls", TargetName);
        _wcslwr_s(tgtLow, RTL_NUMBER_OF(tgtLow));
    } else {
        tgtLow[0] = L'\0';
    }

    for (ULONG i = 0; g_ExemptPairWhitelist[i].Source; i++) {
        if (_wcsicmp(srcLow, g_ExemptPairWhitelist[i].Source) == 0) {
            if (_wcsicmp(g_ExemptPairWhitelist[i].Target, L"*") == 0 ||
                _wcsicmp(tgtLow, g_ExemptPairWhitelist[i].Target) == 0) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

_Use_decl_annotations_
BOOLEAN
ExemptInjection_ShouldWhitelist(
    _In_ PWKD_PROCESS SrcNode,
    _In_ PWKD_PROCESS TgtNode
    )
/*++
Routine Description:
    注入豁免完整三步判定。

Arguments:
    SrcNode - 源进程节点 (注入器)。
    TgtNode - 目标进程节点 (被注入)。

Return Value:
    TRUE=豁免, FALSE=不豁免。
--*/
{
    WCHAR srcName[64], tgtName[64];
    PCWSTR srcPath;

    if (!SrcNode) {
        return FALSE;
    }

    ExemptInjp_GetProcessName(SrcNode, srcName, RTL_NUMBER_OF(srcName));
    if (TgtNode) {
        ExemptInjp_GetProcessName(TgtNode, tgtName, RTL_NUMBER_OF(tgtName));
    } else {
        tgtName[0] = L'\0';
    }
    srcPath = ExemptInjp_GetProcessPath(SrcNode);

    /* ── Step 1: 进程对白名单 ── */
    if (ExemptInjection_IsPairWhitelisted(srcName, tgtName)) {
        /* 名称命中已知 OS 进程对。验证源为真实 OS 二进制:
         *   路径受保护目录 AND 微软签名, 两者缺一不可
         *   (仅路径可被种植绕过, 仅签名可被泄露证书绕过)。 */
        if (srcPath && ExemptInjp_IsProtectedSystemDir(srcPath) &&
            ExemptInjp_IsMicrosoftSigned(srcPath)) {
            return TRUE;
        }

        /* 名称匹配但路径/签名不符 → 疑似伪装, 不豁免 */
        return FALSE;
    }

    /* ── Step 2: 微软签名 + 非LOLBin + 受保护目录 ── */
    if (srcPath && ExemptInjp_IsProtectedSystemDir(srcPath)) {
        if (ExemptInjp_IsLolBin(srcName)) {
            return FALSE;   /* 可滥用二进制不豁免 */
        }
        if (ExemptInjp_IsMicrosoftSigned(srcPath)) {
            return TRUE;
        }
    }

    /* ── Step 3: 不豁免 ── */
    return FALSE;
}
