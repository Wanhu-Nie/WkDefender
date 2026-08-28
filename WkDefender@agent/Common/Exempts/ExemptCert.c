/**************************************************/
/*  WkDefender — 排除子系统证书/发布者判定           */
/*                                                   */
/*  职责：证书与发布者豁免判定。                      */
/*    - 微软签名判定：委托 IocScan_IsMicrosoftSigned  */
/*      （Signature 子系统统一入口，名称+指纹双通道） */
/*    - 证书规则匹配：扫描结果证书链指纹              */
/*      （ChainThumbprint，含叶证书）vs 用户规则      */
/*    - 发布者规则匹配：SignerName vs 用户规则        */
/*                                                   */
/*  不重复实现 Authenticode 验证，复用 IocScanner     */
/*  证书流水线（SS Whitelist 证书维度语义在此补齐）。 */
/**************************************************/

#include "ExemptsInternal.h"
#include "../../IOC/Signature/SignatureVerifier.h"
#include <string.h>   /* _stricmp */
#include <wchar.h>    /* _wcsicmp */

/**************************************************/
/*                  微软签名判定                    */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
ExemptCert_IsTrustedSigner(
    _In_ PIOC_SCAN_RESULT Result
    )
/*++
Routine Description:
    微软签名判定（内置信任层，对齐 IocFileWhitelist
    IsTrustedSigner：CertTrusted + SignerName 非空 +
    统一入口 IocScan_IsMicrosoftSigned）。

Arguments:
    Result - 已扫描的 IOC 结果（含证书字段）。

Return Value:
    TRUE 微软签名。
--*/
{
    if (Result == NULL || !Result->CertTrusted) {
        return FALSE;
    }
    if (Result->SignerName[0] == L'\0') {
        return FALSE;
    }
    return IocScan_IsMicrosoftSigned(Result);
}

/**************************************************/
/*                  规则匹配                        */
/**************************************************/

/*
 * 扫描结果证书链是否命中指纹规则（链元素逐项比较，小写 hex）。
 */
static BOOLEAN
ExemptCertp_ThumbprintHit(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PIOC_SCAN_RESULT Result,
    _Out_opt_ PEXEMPT_REASON Reason
    )
{
    BOOLEAN hit = FALSE;
    ULONG i;

    if (Engine == NULL || Result == NULL || Result->ChainDepth == 0) {
        return FALSE;
    }

    EnterCriticalSection(&Engine->Manager.Lock);
    for (i = 0; i < Engine->Manager.RuleCount; i++) {
        PEXEMPT_RULE r = &Engine->Manager.Rules[i];
        ULONG j;

        if (r->Type != ExemptRule_Certificate) {
            continue;
        }
        /* 活跃校验 */
        if (!(r->Flags & EXEMPT_FLAG_SYSTEM) && r->ExpirationTime != 0) {
            FILETIME ft;
            UINT64 now;
            GetSystemTimeAsFileTime(&ft);
            now = (((UINT64)ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
            if (now >= r->ExpirationTime) {
                continue;
            }
        }

        for (j = 0; j < Result->ChainDepth; j++) {
            if (_stricmp(r->Pattern, Result->ChainThumbprint[j]) == 0) {
                r->HitCount++;
                if (Reason) {
                    *Reason = ExemptReason_CertMatch;
                }
                hit = TRUE;
                goto Done;
            }
        }
    }
Done:
    LeaveCriticalSection(&Engine->Manager.Lock);
    return hit;
}

/*
 * 发布者名规则匹配（SignerName 大小写不敏感）。
 */
static BOOLEAN
ExemptCertp_PublisherHit(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PIOC_SCAN_RESULT Result,
    _Out_opt_ PEXEMPT_REASON Reason
    )
{
    BOOLEAN hit = FALSE;
    UINT64 i;

    if (Engine == NULL || Result == NULL || Result->SignerName[0] == L'\0') {
        return FALSE;
    }

    EnterCriticalSection(&Engine->Manager.Lock);
    for (i = 0; i < Engine->Manager.RuleCount; i++) {
        PEXEMPT_RULE r = &Engine->Manager.Rules[i];

        if (r->Type != ExemptRule_Publisher) {
            continue;
        }
        if (!(r->Flags & EXEMPT_FLAG_SYSTEM) && r->ExpirationTime != 0) {
            FILETIME ft;
            UINT64 now;
            GetSystemTimeAsFileTime(&ft);
            now = (((UINT64)ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
            if (now >= r->ExpirationTime) {
                continue;
            }
        }

        if (_wcsicmp(r->Pattern, Result->SignerName) == 0) {
            r->HitCount++;
            if (Reason) {
                *Reason = ExemptReason_PublisherMatch;
            }
            hit = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&Engine->Manager.Lock);

    return hit;
}

_Use_decl_annotations_
BOOLEAN
ExemptCert_IsWhitelisted(
    _In_  PEXEMPT_ENGINE Engine,
    _In_  PIOC_SCAN_RESULT Result,
    _Out_opt_ PEXEMPT_REASON Reason
    )
/*++
Routine Description:
    证书/发布者规则命中判定（指纹 + 发布者名两通道）。

Arguments:
    Engine - 子系统全局。
    Result - 已扫描的 IOC 结果（含证书字段）。
    Reason - 可选输出命中原因（CertMatch/PublisherMatch）。

Return Value:
    TRUE 命中证书/发布者规则。
--*/
{
    if (Reason) {
        *Reason = ExemptReason_None;
    }

    if (ExemptCertp_ThumbprintHit(Engine, Result, Reason)) {
        return TRUE;
    }
    if (ExemptCertp_PublisherHit(Engine, Result, Reason)) {
        return TRUE;
    }
    return FALSE;
}
