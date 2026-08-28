/**************************************************/
/*  WkDefender — 排除子系统门面/管理引擎             */
/*                                                   */
/*  本文件是排除子系统的唯一对外接口。持有全局子系统  */
/*  结构体 EXEMPT_ENGINE WkdExempts（集中记录各组件   */
/*  状态），编排 ExemptsEvaluate 统一判定，转发规则   */
/*  管理门面，编排采集推送与持久化。                  */
/*                                                   */
/*  组件职责:                                        */
/*    ExemptsManager.c — 纯存储仓库（统一规则表）    */
/*    ExemptHash.c      — 哈希判定逻辑              */
/*    ExemptPath.c      — 无状态路径算法            */
/*    ExemptCert.c      — 证书/发布者判定           */
/*    ExemptPush.c      — 系统组件采集 + ALPC 推送  */
/*    ExemptInjection.c — 注入场景豁免              */
/*    ExemptProcess.c   — 进程身份豁免（无镜像假进程）*/
/*                                                   */
/*  持久化: 复用 StorageEngine（SQLite exempt_rules   */
/*  表），规则加载于初始化，写操作同步落库。          */
/**************************************************/

#include "ExemptsInternal.h"
#include "../../Storage/StorageEngine.h"
#include "../../IOC/IocScanner.h"      /* IocVerifySignature（证书层补验证） */
#include <wchar.h>
#include <string.h>

/**************************************************/
/*                  全局子系统结构体                */
/**************************************************/

static EXEMPT_ENGINE WkdExempts;

/**************************************************/
/*                  生命周期                        */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
ExemptsInitialize(
    VOID
    )
/*++
Routine Description:
    初始化排除子系统：零初始化 → Manager → 加载 SQLite
    持久化规则 → READY。

Arguments:
    无。

Return Value:
    STATUS_SUCCESS / 任一步失败状态。
--*/
{
    NTSTATUS status;
    PEXEMPT_RULE rules = NULL;
    ULONG count = 0;
    ULONG i;

    if (InterlockedCompareExchange(&WkdExempts.State,
            EXEMPT_STATE_INITIALIZING, EXEMPT_STATE_UNINITIALIZED) !=
            EXEMPT_STATE_UNINITIALIZED) {
        return STATUS_ALREADY_INITIALIZED;
    }

    ZeroMemory(&WkdExempts, sizeof(EXEMPT_ENGINE));
    WkdExempts.PushVersion = EXEMPT_PUSH_VERSION_INIT;

    status = ExemptsMgr_Initialize(&WkdExempts);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    /* 加载持久化规则（SQLite exempt_rules 表） */
    status = StLoadExemptRules(&rules, &count);
    if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND) {
        ExemptsMgr_Shutdown(&WkdExempts);
        goto Cleanup;
    }
    for (i = 0; i < count; i++) {
        ExemptsMgr_AddRule(&WkdExempts, &rules[i], NULL);
    }
    if (rules != NULL) {
        UtHeapFree(rules);
    }

    MemoryBarrier();
    InterlockedExchange(&WkdExempts.State, EXEMPT_STATE_READY);
    WkdExempts.Enabled = TRUE;

    return STATUS_SUCCESS;

Cleanup:
    InterlockedExchange(&WkdExempts.State, EXEMPT_STATE_UNINITIALIZED);
    return status;
}

_Use_decl_annotations_
VOID
ExemptsCleanup(
    VOID
    )
/*++
Routine Description:
    关闭排除子系统：置 SHUTTING_DOWN → Manager 逆序 Shutdown →
    回 UNINITIALIZED。

Arguments:
    无。

Return Value:
    无。
--*/
{
    if (InterlockedCompareExchange(&WkdExempts.State,
            EXEMPT_STATE_SHUTTING_DOWN, EXEMPT_STATE_READY) != EXEMPT_STATE_READY) {
        return;
    }

    WkdExempts.Enabled = FALSE;
    ExemptsMgr_Shutdown(&WkdExempts);

    InterlockedExchange(&WkdExempts.State, EXEMPT_STATE_UNINITIALIZED);
}

/**************************************************/
/*                  统一豁免判定                    */
/**************************************************/

_Use_decl_annotations_
EXEMPT_VERDICT
ExemptsEvaluate(
    _In_opt_ PCWSTR             FilePath,
    _In_opt_ PDEF_SHA256_HASH   Sha256,
    _In_opt_ PIOC_SCAN_RESULT   Result,
    _Out_opt_ PEXEMPT_REASON    Reason
    )
/*++
Routine Description:
    统一豁免判定（唯一判定入口）。信任层级（对齐 SS IsWhitelisted）：
        Hash > Certificate > Publisher > Path，首匹配胜。
    任一维度命中即豁免。证书层缺 Result 时内部补做
    IocVerifySignature（对齐 IocFileWhitelist 行为）。

Arguments:
    FilePath - 文件完整路径（可空，路径层跳过）。
    Sha256   - 文件 SHA256（可空，哈希层跳过）。
    Result   - 已扫描的 IOC 结果（含证书字段）。NULL 时内部补做证书验证。
    Reason   - 可选输出命中原因。

Return Value:
    ExemptVerdict_Trusted / ExemptVerdict_NotTrusted。
--*/
{
    IOC_SCAN_RESULT localResult;
    PIOC_SCAN_RESULT effResult = Result;
    EXEMPT_REASON retReason = ExemptReason_None;

    if (Reason) {
        *Reason = ExemptReason_None;
    }
    if (InterlockedCompareExchange(&WkdExempts.State, 0, 0) != EXEMPT_STATE_READY) {
        return ExemptVerdict_NotTrusted;
    }

    /* ── ① 哈希层（快路径，内存查表） ── */
    if (Sha256 != NULL && ExemptHash_IsWhitelisted(&WkdExempts, Sha256)) {
        retReason = ExemptReason_HashMatch;
        goto Trusted;
    }

    /* ── ② 证书/发布者层 ── */
    if (effResult == NULL && FilePath != NULL && FilePath[0] != L'\0') {
        RtlZeroMemory(&localResult, sizeof(localResult));
        IocVerifySignature(FilePath, &localResult);
        effResult = &localResult;
    }

    if (effResult != NULL) {
        /* 微软签名（内置信任） */
        if (ExemptCert_IsTrustedSigner(effResult)) {
            retReason = ExemptReason_CertMatch;
            goto Trusted;
        }
        /* 证书指纹/发布者规则 */
        if (ExemptCert_IsWhitelisted(&WkdExempts, effResult, &retReason)) {
            goto Trusted;
        }
    }

    /* ── ③ 路径层 ── */
    if (FilePath != NULL && FilePath[0] != L'\0' &&
        ExemptPath_IsWhitelisted(&WkdExempts, FilePath, ExemptMode_Exact, &retReason)) {
        goto Trusted;
    }

    /* 无任何匹配 */
    return ExemptVerdict_NotTrusted;

Trusted:
    if (Reason) {
        *Reason = retReason;
    }
    return ExemptVerdict_Trusted;
}

_Use_decl_annotations_
BOOLEAN
ExemptsIsWhitelisted(
    _In_ PCWSTR             FilePath,
    _In_opt_ PDEF_SHA256_HASH Hash,
    _In_opt_ PIOC_SCAN_RESULT Result
    )
/*++
Routine Description:
    兼容旧调用 BOOL 版（= ExemptsEvaluate == Trusted）。

Arguments:
    FilePath - 文件完整路径。
    Hash     - 文件 SHA256。
    Result   - 已扫描的 IOC 结果。

Return Value:
    TRUE 豁免。
--*/
{
    return (ExemptsEvaluate(FilePath, Hash, Result, NULL) == ExemptVerdict_Trusted);
}

/**************************************************/
/*               哈希规则门面                       */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
ExemptsAddHash(
    _In_ PDEF_SHA256_HASH   Hash,
    _In_opt_ PCWSTR         Description
    )
{
    EXEMPT_RULE rule;
    BOOLEAN isNew = FALSE;

    if (Hash == NULL || InterlockedCompareExchange(&WkdExempts.State, 0, 0) != EXEMPT_STATE_READY) {
        return STATUS_INVALID_PARAMETER;
    }

    ZeroMemory(&rule, sizeof(rule));
    rule.Type = ExemptRule_Hash;
    rule.Reason = ExemptReason_HashMatch;
    rule.Flags = EXEMPT_FLAG_NONE;
    rule.HashAlgorithm = 1;
    rule.HashLength = EXEMPT_HASH_SIZE;
    memcpy(rule.HashData, Hash->Data, EXEMPT_HASH_SIZE);
    if (Description) {
        wcsncpy_s(rule.Description, EXEMPT_MAX_DESCRIPTION, Description, _TRUNCATE);
    }

    if (!NT_SUCCESS(ExemptsMgr_AddRule(&WkdExempts, &rule, &isNew))) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (isNew) {
        StPersistExemptRule(&rule, NULL);   /* 持久化 */
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ExemptsRemoveHash(
    _In_ PDEF_SHA256_HASH   Hash
    )
{
    EXEMPT_RULE found;

    if (Hash == NULL || InterlockedCompareExchange(&WkdExempts.State, 0, 0) != EXEMPT_STATE_READY) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ExemptsMgr_FindHashRule(&WkdExempts, Hash, &found)) {
        ExemptsMgr_RemoveHashRule(&WkdExempts, Hash);
        StRemoveExemptRule(found.RuleId);
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
BOOLEAN
ExemptsIsHashWhitelisted(
    _In_ PDEF_SHA256_HASH   Hash
    )
{
    if (Hash == NULL || InterlockedCompareExchange(&WkdExempts.State, 0, 0) != EXEMPT_STATE_READY) {
        return FALSE;
    }
    return ExemptHash_IsWhitelisted(&WkdExempts, Hash);
}

/**************************************************/
/*               路径规则门面                       */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
ExemptsAddPath(
    _In_ PCWSTR             Path,
    _In_ EXEMPT_PATH_MODE   Mode,
    _In_opt_ PCWSTR         Description
    )
{
    EXEMPT_RULE rule;
    BOOLEAN isNew = FALSE;
    WCHAR norm[EXEMPT_MAX_PATTERN];

    if (Path == NULL || Mode >= ExemptMode_MaxValue ||
        InterlockedCompareExchange(&WkdExempts.State, 0, 0) != EXEMPT_STATE_READY) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!ExemptPath_Normalize(Path, norm, EXEMPT_MAX_PATTERN)) {
        return STATUS_INVALID_PARAMETER;
    }

    ZeroMemory(&rule, sizeof(rule));
    rule.Type = ExemptRule_Path;
    rule.Reason = ExemptReason_PathMatch;
    rule.MatchMode = (UINT8)Mode;
    rule.Flags = EXEMPT_FLAG_NONE;
    wcsncpy_s(rule.Pattern, EXEMPT_MAX_PATTERN, norm, _TRUNCATE);
    if (Description) {
        wcsncpy_s(rule.Description, EXEMPT_MAX_DESCRIPTION, Description, _TRUNCATE);
    }

    if (!NT_SUCCESS(ExemptsMgr_AddRule(&WkdExempts, &rule, &isNew))) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (isNew) {
        StPersistExemptRule(&rule, NULL);
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ExemptsRemovePath(
    _In_ PCWSTR             Path,
    _In_ EXEMPT_PATH_MODE   Mode
    )
{
    EXEMPT_RULE found;
    WCHAR norm[EXEMPT_MAX_PATTERN];

    if (Path == NULL || Mode >= ExemptMode_MaxValue ||
        InterlockedCompareExchange(&WkdExempts.State, 0, 0) != EXEMPT_STATE_READY) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!ExemptPath_Normalize(Path, norm, EXEMPT_MAX_PATTERN)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ExemptsMgr_FindPathRule(&WkdExempts, Path, Mode, &found)) {
        ExemptsMgr_RemovePatternRule(&WkdExempts, ExemptRule_Path, norm, (UINT8)Mode);
        StRemoveExemptRule(found.RuleId);
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
BOOLEAN
ExemptsIsPathWhitelisted(
    _In_ PCWSTR             Path,
    _In_ EXEMPT_PATH_MODE   Mode,
    _Out_opt_ PEXEMPT_REASON Reason
    )
{
    if (Path == NULL || Mode >= ExemptMode_MaxValue ||
        InterlockedCompareExchange(&WkdExempts.State, 0, 0) != EXEMPT_STATE_READY) {
        return FALSE;
    }
    return ExemptPath_IsWhitelisted(&WkdExempts, Path, Mode, Reason);
}

/**************************************************/
/*             证书/发布者规则门面                  */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
ExemptsAddCertificate(
    _In_ PCWSTR             Thumbprint,
    _In_opt_ PCWSTR         Description
    )
{
    EXEMPT_RULE rule;
    BOOLEAN isNew = FALSE;
    WCHAR norm[128];

    if (Thumbprint == NULL || Thumbprint[0] == L'\0' ||
        InterlockedCompareExchange(&WkdExempts.State, 0, 0) != EXEMPT_STATE_READY) {
        return STATUS_INVALID_PARAMETER;
    }
    /* 归一化：去空格/冒号 + 小写（对齐证书指纹键约定） */
    {
        ULONG o = 0, j;
        for (j = 0; Thumbprint[j] && o < 127; j++) {
            WCHAR c = Thumbprint[j];
            if (c == L' ' || c == L':') continue;
            if (c >= L'A' && c <= L'F') c = (WCHAR)(c - L'A' + L'a');
            norm[o++] = c;
        }
        norm[o] = L'\0';
    }

    ZeroMemory(&rule, sizeof(rule));
    rule.Type = ExemptRule_Certificate;
    rule.Reason = ExemptReason_CertMatch;
    rule.Flags = EXEMPT_FLAG_NONE;
    wcsncpy_s(rule.Pattern, EXEMPT_MAX_PATTERN, norm, _TRUNCATE);
    if (Description) {
        wcsncpy_s(rule.Description, EXEMPT_MAX_DESCRIPTION, Description, _TRUNCATE);
    }

    if (!NT_SUCCESS(ExemptsMgr_AddRule(&WkdExempts, &rule, &isNew))) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (isNew) {
        StPersistExemptRule(&rule, NULL);
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ExemptsRemoveCertificate(
    _In_ PCWSTR             Thumbprint
    )
{
    EXEMPT_RULE found;
    WCHAR norm[128];

    if (Thumbprint == NULL || Thumbprint[0] == L'\0' ||
        InterlockedCompareExchange(&WkdExempts.State, 0, 0) != EXEMPT_STATE_READY) {
        return STATUS_INVALID_PARAMETER;
    }
    {
        ULONG o = 0, j;
        for (j = 0; Thumbprint[j] && o < 127; j++) {
            WCHAR c = Thumbprint[j];
            if (c == L' ' || c == L':') continue;
            if (c >= L'A' && c <= L'F') c = (WCHAR)(c - L'A' + L'a');
            norm[o++] = c;
        }
        norm[o] = L'\0';
    }

    if (ExemptsMgr_FindPatternRule(&WkdExempts, ExemptRule_Certificate, norm, &found)) {
        ExemptsMgr_RemovePatternRule(&WkdExempts, ExemptRule_Certificate, norm, 0);
        StRemoveExemptRule(found.RuleId);
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
ExemptsAddPublisher(
    _In_ PCWSTR             Publisher,
    _In_opt_ PCWSTR         Description
    )
{
    EXEMPT_RULE rule;
    BOOLEAN isNew = FALSE;

    if (Publisher == NULL || Publisher[0] == L'\0' ||
        InterlockedCompareExchange(&WkdExempts.State, 0, 0) != EXEMPT_STATE_READY) {
        return STATUS_INVALID_PARAMETER;
    }

    ZeroMemory(&rule, sizeof(rule));
    rule.Type = ExemptRule_Publisher;
    rule.Reason = ExemptReason_PublisherMatch;
    rule.Flags = EXEMPT_FLAG_NONE;
    wcsncpy_s(rule.Pattern, EXEMPT_MAX_PATTERN, Publisher, _TRUNCATE);
    if (Description) {
        wcsncpy_s(rule.Description, EXEMPT_MAX_DESCRIPTION, Description, _TRUNCATE);
    }

    if (!NT_SUCCESS(ExemptsMgr_AddRule(&WkdExempts, &rule, &isNew))) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (isNew) {
        StPersistExemptRule(&rule, NULL);
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
ExemptsRemovePublisher(
    _In_ PCWSTR             Publisher
    )
{
    EXEMPT_RULE found;

    if (Publisher == NULL || Publisher[0] == L'\0' ||
        InterlockedCompareExchange(&WkdExempts.State, 0, 0) != EXEMPT_STATE_READY) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ExemptsMgr_FindPatternRule(&WkdExempts, ExemptRule_Publisher, Publisher, &found)) {
        ExemptsMgr_RemovePatternRule(&WkdExempts, ExemptRule_Publisher, Publisher, 0);
        StRemoveExemptRule(found.RuleId);
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

/**************************************************/
/*               注入豁免门面                       */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
ExemptsInjectionIsPairWhitelisted(
    _In_ PCWSTR             SourceName,
    _In_opt_ PCWSTR         TargetName
    )
{
    return ExemptInjection_IsPairWhitelisted(SourceName, TargetName);
}

_Use_decl_annotations_
BOOLEAN
ExemptsShouldWhitelistInjection(
    _In_ struct _WKD_PROCESS*  SrcNode,
    _In_ struct _WKD_PROCESS*  TgtNode
    )
{
    return ExemptInjection_ShouldWhitelist(SrcNode, TgtNode);
}

/**************************************************/
/*               进程身份豁免门面                    */
/*                                                   */
/*  无镜像内核假进程快速通道。详见 Exempts.h 声明处   */
/*  安全边界注记：仅供无文件假进程，禁止通用进程名豁免 */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
CoExemptPseudoSystemProcess(
    _In_ PCWSTR ProcessName
    )
{
    return CopExemptPseudoSystemProcessInternal(ProcessName);
}

/**************************************************/
/*               规则管理门面                       */
/**************************************************/

_Use_decl_annotations_
VOID
ExemptsClearRules(
    _In_ EXEMPT_RULE_TYPE   Type
    )
{
    if (InterlockedCompareExchange(&WkdExempts.State, 0, 0) != EXEMPT_STATE_READY) {
        return;
    }
    ExemptsMgr_ClearRules(&WkdExempts, (UINT8)Type);
    StClearExemptRules((UINT8)Type);
}

_Use_decl_annotations_
NTSTATUS
ExemptsGetRules(
    _Out_ PEXEMPT_RULE*     OutRules,
    _Out_ PULONG            Count
    )
{
    if (InterlockedCompareExchange(&WkdExempts.State, 0, 0) != EXEMPT_STATE_READY) {
        return STATUS_INVALID_PARAMETER;
    }
    return ExemptsMgr_GetRules(&WkdExempts, OutRules, Count);
}

_Use_decl_annotations_
UINT64
ExemptsGetRuleCount(
    VOID
    )
{
    if (InterlockedCompareExchange(&WkdExempts.State, 0, 0) != EXEMPT_STATE_READY) {
        return 0;
    }
    return ExemptsMgr_GetRuleCount(&WkdExempts, ExemptRule_MaxValue);
}

/**************************************************/
/*               采集推送门面                       */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
ExemptsCollectSystemHashes(
    VOID
    )
{
    if (InterlockedCompareExchange(&WkdExempts.State, 0, 0) != EXEMPT_STATE_READY) {
        return STATUS_INVALID_PARAMETER;
    }
    return ExemptPush_CollectSystemHashes(&WkdExempts);
}

_Use_decl_annotations_
NTSTATUS
ExemptsPushAll(
    VOID
    )
{
    if (InterlockedCompareExchange(&WkdExempts.State, 0, 0) != EXEMPT_STATE_READY) {
        return STATUS_INVALID_PARAMETER;
    }
    return ExemptPush_PushAll(&WkdExempts);
}
