/**************************************************/
/*  WkDefender IOC — 签名者分类与信誉评分            */
/*  自 IocScanner.c 独立 (2026-08 重构)              */
/*  SS FileReputation 迁移, 按功能融合重实现         */
/**************************************************/

#include "SignatureReputation.h"
#include "../../Common/TextSanitize.h"   /* TxtSanitizeForDisplay (归因消毒) */

/**************************************************/
/*                  签名者静态表                    */
/**************************************************/

/* 微软签名者精确全串表 (对齐 SS MICROSOFT_PUBLISHERS L147-152, 大小写不敏感全串) */
static const WCHAR* g_IocMsSigners[4] = {
    L"Microsoft Corporation",
    L"Microsoft Windows",
    L"Microsoft Code Signing PCA",
    L"Microsoft Windows Hardware Compatibility Publisher"
};

/* 可信发行商精确全串表 (对齐 SS TRUSTED_PUBLISHERS L155-164) */
static const WCHAR* g_IocTrustedPublishers[8] = {
    L"Adobe Systems Incorporated",
    L"Google LLC",
    L"Apple Inc.",
    L"Mozilla Corporation",
    L"Oracle Corporation",
    L"Intel Corporation",
    L"NVIDIA Corporation",
    L"VMware, Inc."
};

/* 微软签名者证书 SHA1 指纹表 (对齐 SS DriverAnalyzer MICROSOFT_CERT_THUMBPRINTS
 * L306-309, 2026-08 指纹双通道)。
 * 指纹命中 = 强微软信号, 优先于名称匹配 — 名称可被 CA 冒名 (CN=Microsoft),
 * 证书指纹不可伪造。注意: 微软 PCA 会轮换, 此表需随 SS/微软维护更新;
 * 名称命中但叶证书指纹库外 → 降级 WKD_SIGNER_CATEGORY_VALID (弱微软)。 */
static const CHAR* g_IocMsThumbprints[] = {
    "3b1efd3a66ea28b16697394703a72ca340a05bd5",  /* Microsoft Windows Production PCA 2011 */
    "df545bf919cfa81dc4bd40aa30c0563ad7e76f44",  /* Microsoft Code Signing PCA 2011 */
    "7251adcf2c7f3c98becf143f40a68c27e2f61d3e"   /* Microsoft Windows Hardware Compatibility PCA */
};

/* 已知坏签名者表 (SS GetCertificateReputation 坏签名者分支 L873-886)
 * 功能: 签名者 thumbprint 黑名单, 命中 signerReputation=-50 且等级降级。
 * 2026-08 已激活: IocScan_ClassifySigner 优先查黑名单。
 * 2026-09-02 升级 (SS CertificateValidator BlockCertificate 增量迁移):
 *   静态预留空表 → 运行时 CRUD 黑名单 (512 槽 + SRW 锁),
 *   表填充来源 = 管理员静态填充 / 情报 feed (IocScan_BlockSigner 运行时注入);
 *   untrusted 语义另由 cert_reputation 表 (StUpsertCertReputation
 *   IsTrusted=FALSE) 活代码覆盖, 双通道冗余。 */
static WKD_BLOCKED_SIGNER_ENTRY g_IocBlockedSigners[WKD_BLOCKED_SIGNER_MAX];
static SRWLOCK                  g_IocBlockedLock = SRWLOCK_INIT;   /* 静态初始化, 无 Init/Cleanup 需求 */
static ULONG                    g_IocBlockedCount = 0;

static BOOLEAN
IocScan_IsKnownBadSigner(
    _In_ PCSTR Thumbprint
    )
{
    return IocScan_IsSignerBlocked(Thumbprint);
}

/**************************************************/
/*           运行时证书黑名单 (SS BlockCertificate) */
/**************************************************/

/* 指纹输入规范化: 非空 + 40 hex + 转小写 (对齐现有 hex 存储风格)。 */
static BOOLEAN
IocScan_NormalizeThumbprint(
    _In_  PCSTR In,
    _Out_ PCHAR Out,
    _In_  ULONG OutCch
    )
{
    ULONG i;
    if (!In || !Out || OutCch < 41) return FALSE;
    if (strnlen(In, 41) != 40) return FALSE;
    for (i = 0; i < 40; i++) {
        CHAR c = In[i];
        if (c >= 'A' && c <= 'F') c = (CHAR)(c - 'A' + 'a');
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return FALSE;
        Out[i] = c;
    }
    Out[40] = '\0';
    return TRUE;
}

BOOLEAN
IocScan_BlockSigner(
    _In_ PCSTR      Thumbprint,
    _In_opt_ PCWSTR Reason
    )
/*++
Routine Description:
    阻断签名者证书 (SHA1 thumbprint hex)。对齐 SS CertificateValidator
    的 BlockCertificate L2048-2069: 上限防无界 (kMaxBlockedCerts), 已存在
    条目重复 block 更新原因, 满时拒绝新条目。

Arguments:
    Thumbprint - 叶证书 SHA1 thumbprint hex (40 字符, 大小写不敏感)。
    Reason     - 阻断原因 (可为 NULL, 存空串)。

Return Value:
    TRUE = 已阻断(含更新原因), FALSE = 参数非法或黑名单满。
--*/
{
    ULONG i;
    ULONG freeSlot = ULONG_MAX;
    WKD_BLOCKED_SIGNER_ENTRY tmp;

    RtlZeroMemory(&tmp, sizeof(tmp));
    if (!IocScan_NormalizeThumbprint(Thumbprint, tmp.Thumbprint,
                                     RTL_NUMBER_OF(tmp.Thumbprint))) {
        return FALSE;
    }
    if (Reason && Reason[0]) {
        wcsncpy_s(tmp.Reason, RTL_NUMBER_OF(tmp.Reason), Reason, _TRUNCATE);
    }

    AcquireSRWLockExclusive(&g_IocBlockedLock);
    for (i = 0; i < g_IocBlockedCount; i++) {
        if (_stricmp(g_IocBlockedSigners[i].Thumbprint, tmp.Thumbprint) == 0) {
            g_IocBlockedSigners[i] = tmp;   /* 已存在 → 更新原因 */
            ReleaseSRWLockExclusive(&g_IocBlockedLock);
            return TRUE;
        }
    }
    if (g_IocBlockedCount >= WKD_BLOCKED_SIGNER_MAX) {
        ReleaseSRWLockExclusive(&g_IocBlockedLock);   /* 上限 (对齐 SS cap 语义) */
        return FALSE;
    }
    freeSlot = g_IocBlockedCount;
    g_IocBlockedSigners[freeSlot] = tmp;
    g_IocBlockedCount++;
    ReleaseSRWLockExclusive(&g_IocBlockedLock);
    return TRUE;
}

BOOLEAN
IocScan_UnblockSigner(
    _In_ PCSTR Thumbprint
    )
/*++
Routine Description:
    解除签名者阻断。对齐 SS UnblockCertificate L2071-2074 (erase)。

Return Value:
    TRUE = 原来处于阻断态并已移除, FALSE = 未命中/参数非法。
--*/
{
    CHAR  norm[64];
    ULONG i;

    if (!IocScan_NormalizeThumbprint(Thumbprint, norm, RTL_NUMBER_OF(norm))) {
        return FALSE;
    }

    AcquireSRWLockExclusive(&g_IocBlockedLock);
    for (i = 0; i < g_IocBlockedCount; i++) {
        if (_stricmp(g_IocBlockedSigners[i].Thumbprint, norm) == 0) {
            g_IocBlockedCount--;
            g_IocBlockedSigners[i] = g_IocBlockedSigners[g_IocBlockedCount];
            ReleaseSRWLockExclusive(&g_IocBlockedLock);
            return TRUE;
        }
    }
    ReleaseSRWLockExclusive(&g_IocBlockedLock);
    return FALSE;
}

BOOLEAN
IocScan_IsSignerBlocked(
    _In_ PCSTR Thumbprint
    )
/*++
Routine Description:
    查询签名者是否处于阻断态。对齐 SS IsBlocked (L2076-2078)。

Return Value:
    TRUE = 阻断命中。
--*/
{
    CHAR  norm[64];
    ULONG i;
    BOOLEAN blocked = FALSE;

    if (!IocScan_NormalizeThumbprint(Thumbprint, norm, RTL_NUMBER_OF(norm))) {
        return FALSE;
    }

    AcquireSRWLockShared(&g_IocBlockedLock);
    for (i = 0; i < g_IocBlockedCount; i++) {
        if (_stricmp(g_IocBlockedSigners[i].Thumbprint, norm) == 0) {
            blocked = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(&g_IocBlockedLock);
    return blocked;
}

ULONG
IocScan_GetBlockedSignerCount(
    VOID
    )
{
    ULONG count;
    AcquireSRWLockShared(&g_IocBlockedLock);
    count = g_IocBlockedCount;
    ReleaseSRWLockShared(&g_IocBlockedLock);
    return count;
}

NTSTATUS
IocScan_GetBlockedSigners(
    _Out_writes_to_(MaxEntries, *Count) PWKD_BLOCKED_SIGNER_ENTRY Entries,
    _In_  ULONG MaxEntries,
    _Out_ PULONG Count
    )
/*++
Routine Description:
    黑名单快照 (对齐 SS GetBlockedCertificates L2080-2093)。

Return Value:
    STATUS_SUCCESS; Count 恒返回表中条目数 (超过 MaxEntries 时截断)。
--*/
{
    ULONG i;
    ULONG n;

    if (!Entries || !Count || MaxEntries == 0) return STATUS_INVALID_PARAMETER;
    *Count = 0;

    AcquireSRWLockShared(&g_IocBlockedLock);
    n = (g_IocBlockedCount < MaxEntries) ? g_IocBlockedCount : MaxEntries;
    for (i = 0; i < n; i++) {
        Entries[i] = g_IocBlockedSigners[i];
    }
    *Count = n;
    ReleaseSRWLockShared(&g_IocBlockedLock);
    return STATUS_SUCCESS;
}

/**************************************************/
/*                归因与分类                        */
/**************************************************/

/* 归因追加 (cap 8 条, 经 TxtSanitizeForDisplay 消毒防日志/UI 注入) */
static VOID
IocScan_AppendReason(
    _Inout_ PWKD_FILE_REPUTATION Rep,
    _In_    PCWSTR              Reason
    )
{
    if (!Rep || !Reason || Rep->ReasonCount >= 8) return;
    TxtSanitizeForDisplay(Reason, Rep->Reasons[Rep->ReasonCount],
                          RTL_NUMBER_OF(Rep->Reasons[0]));
    Rep->ReasonCount++;
}

NTSTATUS
IocScan_ClassifySigner(
    _In_  PIOC_SCAN_RESULT       Result,
    _Out_opt_ PULONG             Reputation,
    _Out_opt_ PULONG             Category
    )
/*++
Routine Description:
    证书签名者分类 (对齐 SS FileReputation IsMicrosoftSigner/IsTrustedPublisher,
    精确全串大小写不敏感匹配 + 微软证书指纹强信号 + 坏签名者黑名单)。
    签名有效 (CertTrusted) 且 SignerName 非空才分类。

Arguments:
    Result     - 扫描结果 (须含 CertTrusted/SignerName/Thumbprint 证书字段)。
    Reputation - 可选输出签名者信誉 (-100..100)。
    Category   - 可选输出 WKD_SIGNER_CATEGORY_*。

Return Value:
    STATUS_SUCCESS。
--*/
{
    ULONG i;

    if (Reputation) *Reputation = 0;
    if (Category)   *Category = WKD_SIGNER_CATEGORY_UNKNOWN;

    if (!Result || !Result->CertTrusted || Result->SignerName[0] == L'\0') {
        return STATUS_SUCCESS;
    }

    /* 坏签名者 thumbprint 黑名单 (SS GetCertificateReputation 坏签名者分支 L873-886,
     * g_IocBadSigners 预留表, 2026-08 激活): 命中 → UNKNOWN + 强降分。 */
    if (IocScan_IsKnownBadSigner(Result->Thumbprint)) {
        if (Reputation) *Reputation = WKD_REP_WEIGHT_BAD_SIGNER;
        if (Category)   *Category = WKD_SIGNER_CATEGORY_UNKNOWN;
        return STATUS_SUCCESS;
    }

    /* 微软签名者证书 SHA1 指纹 (强信号, 优先于名称, 对齐 SS DriverAnalyzer
     * IsMicrosoftSigned 指纹表 L1270): 指纹不可伪造, 命中直接判微软。 */
    for (i = 0; i < RTL_NUMBER_OF(g_IocMsThumbprints); i++) {
        if (Result->Thumbprint[0] != '\0' &&
            _stricmp(Result->Thumbprint, g_IocMsThumbprints[i]) == 0) {
            if (Reputation) *Reputation = WKD_REP_WEIGHT_MICROSOFT_SIGNED;
            if (Category)   *Category = WKD_SIGNER_CATEGORY_MICROSOFT;
            return STATUS_SUCCESS;
        }
    }

    /* 微软签名者精确全串 (对齐 SS MICROSOFT_PUBLISHERS)。
     * 名称命中但叶证书指纹不在微软 PCA 库 → 降级 VALID (弱微软, 需路径等佐证),
     * 防 CA 冒名 CN=Microsoft 的伪造证书 (2026-08 指纹双通道)。 */
    for (i = 0; i < RTL_NUMBER_OF(g_IocMsSigners); i++) {
        if (_wcsicmp(Result->SignerName, g_IocMsSigners[i]) == 0) {
            if (Reputation) *Reputation = WKD_REP_WEIGHT_MS_NAME_ONLY;
            if (Category)   *Category = WKD_SIGNER_CATEGORY_VALID;
            return STATUS_SUCCESS;
        }
    }

    /* 可信发行商精确全串 (对齐 SS TRUSTED_PUBLISHERS) */
    for (i = 0; i < RTL_NUMBER_OF(g_IocTrustedPublishers); i++) {
        if (_wcsicmp(Result->SignerName, g_IocTrustedPublishers[i]) == 0) {
            if (Reputation) *Reputation = WKD_REP_WEIGHT_TRUSTED_CERT;
            if (Category)   *Category = WKD_SIGNER_CATEGORY_TRUSTED;
            return STATUS_SUCCESS;
        }
    }

    /* 有效签名但非已知发行商 */
    if (Reputation) *Reputation = WKD_REP_WEIGHT_VALID_CERT;
    if (Category)   *Category = WKD_SIGNER_CATEGORY_VALID;
    return STATUS_SUCCESS;
}

/* 等级判定 (对齐 SS CalculateFinalScore L2056-2087 + 阈值 L2442-2447)。
 * 微软签名者覆盖为最高等级, 但被强恶意信号 (score<0) 否决时降级。 */
static WKD_REPUTATION_LEVEL
IocScan_LevelFromScore(
    _In_ LONG  Score,
    _In_ ULONG SignerCategory
    )
{
    if (SignerCategory == WKD_SIGNER_CATEGORY_MICROSOFT && Score >= 0) {
        return WkdRep_MicrosoftSigned;
    }
    if (Score >= 70) return WkdRep_Trusted;          /* trustedThreshold=70 */
    if (Score >= 50) return WkdRep_KnownSafe;        /* SCORE_SAFE=50 */
    if (Score >= 0)  return WkdRep_Unknown;          /* SCORE_UNKNOWN=0 */
    if (Score >= -30) return WkdRep_Suspicious;      /* suspiciousThreshold=-30 */
    if (Score >= -70) return WkdRep_HighlyMalicious; /* malwareThreshold=-70 */
    return WkdRep_KnownMalware;
}

/* 置信度映射 (对齐 SS CalculateFinalScore: Trusted 0.9/KnownSafe 0.75/Unknown 0.5/
 * Suspicious 0.65/HighlyMalicious 0.85/KnownMalware 0.95, ×1000 整数化) */
static ULONG
IocScan_ConfidenceFromLevel(
    _In_ WKD_REPUTATION_LEVEL Level
    )
{
    switch (Level) {
    case WkdRep_MicrosoftSigned: return 900;
    case WkdRep_Trusted:         return 900;
    case WkdRep_KnownSafe:       return 750;
    case WkdRep_Unknown:         return 500;
    case WkdRep_Suspicious:      return 650;
    case WkdRep_HighlyMalicious: return 850;
    case WkdRep_KnownMalware:    return 950;
    default:                     return 500;
    }
}

/**************************************************/
/*               加权信誉分计算                      */
/**************************************************/

static LONG
IocScan_CalcWeightedScore(
    _In_    PIOC_SCAN_RESULT      Result,
    _Inout_ PWKD_FILE_REPUTATION  Rep,
    _In_    LONG                  SignerReputation,
    _In_    ULONG                 SignerCategory,
    _Inout_ PULONG                Sources
    )
{
    LONG score = 0;

    /* 哈希黑名单 (对齐 SS LocalBlacklist -100 + HashStore Critical -100) */
    if (Result->HashChecked && Result->HashVerdict == DefIocVerdict_Malicious) {
        score += WKD_REP_WEIGHT_BLACKLIST;
        *Sources |= (1u << DefDetSrc_IOC);
        IocScan_AppendReason(Rep, L"Hash match in malicious database");
    }

    /* 证书信号 (对齐 SS AnalyzeCertificate L1639-1691) */
    switch (Result->CertStatus) {
    case DefCertStatus_Valid:
    case DefCertStatus_ValidCatalog:
        score += SignerReputation;
        *Sources |= (1u << DefDetSrc_IOC);
        if (SignerCategory == WKD_SIGNER_CATEGORY_MICROSOFT) {
            IocScan_AppendReason(Rep, L"Signed by Microsoft");
        } else if (SignerCategory == WKD_SIGNER_CATEGORY_TRUSTED) {
            IocScan_AppendReason(Rep, L"Signed by trusted publisher");
        } else if (SignerCategory == WKD_SIGNER_CATEGORY_VALID) {
            IocScan_AppendReason(Rep, L"Valid digital signature");
        }
        if (Result->IsEvCert) {
            score += WKD_REP_WEIGHT_EV_BONUS;
            IocScan_AppendReason(Rep, L"Extended Validation certificate");
        }
        /* EKU/弱算法降分 (SS PE_sig_verf 迁移, 2026-08): 有效签名但非代码签名
         * EKU 或弱签名算法 (SHA-1/MD5) → 降信誉。不改 WinVerifyTrust 快速路径判定。 */
        if (!Result->IsCodeSigningEku) {
            score += WKD_REP_WEIGHT_NO_CODE_SIGNING;
            IocScan_AppendReason(Rep, L"Not a code-signing certificate");
        }
        if (Result->IsWeakSignature) {
            score += WKD_REP_WEIGHT_WEAK_SIG;
            IocScan_AppendReason(Rep, L"Weak signature algorithm (SHA-1/MD5)");
        }
        break;
    case DefCertStatus_Revoked:
        score += WKD_REP_WEIGHT_CERT_REVOKED;
        /* 吊销原因细分 (SS CertificateValidator GetRevocationStatus 增量迁移
         * 2026-09-02): RevokeReason 由 SignatureVerifier Revoked 分支填充,
         * 有细分则归因用细分文案 ("Certificate revoked (Reason: ...)")。 */
        if (Result->RevokeReason[0] != L'\0') {
            IocScan_AppendReason(Rep, Result->RevokeReason);
        } else {
            IocScan_AppendReason(Rep, L"Certificate revoked");
        }
        *Sources |= (1u << DefDetSrc_IOC);
        break;
    case DefCertStatus_Expired:
        score += WKD_REP_WEIGHT_CERT_EXPIRED;
        IocScan_AppendReason(Rep, L"Certificate expired");
        *Sources |= (1u << DefDetSrc_IOC);
        break;
    case DefCertStatus_Unsigned:
        score += WKD_REP_WEIGHT_UNSIGNED;
        IocScan_AppendReason(Rep, L"File is not digitally signed");
        *Sources |= (1u << DefDetSrc_IOC);
        break;
    default:
        break;   /* Invalid/UntrustedRoot/Unknown: 无评分 (对齐 SS 默认不叠加) */
    }

    /* cert_reputation 表接线 (SS GetCertificateTrust 迁移, 2026-08, 门控
     * g_IocCertReputationEnabled): 命中受信/不受信 → ±信誉, 独立于签名者分类。 */
    if (Result->CertReputationAdjust != 0) {
        score += Result->CertReputationAdjust;
        *Sources |= (1u << DefDetSrc_IOC);
        IocScan_AppendReason(Rep, (Result->CertReputationAdjust > 0)
                                  ? L"Certificate trust override (trusted)"
                                  : L"Certificate trust override (untrusted)");
    }

    /* LOLBin 使用 (对齐 SS 行为 createsExecutables -10 语义降权映射) */
    if (Result->IsLolbin) {
        score += WKD_REP_WEIGHT_LOLLBIN;
        IocScan_AppendReason(Rep, L"LOLBin binary usage");
        *Sources |= (1u << DefDetSrc_IOC);
    }

    /* 命令行高危模式 (对齐 SS 行为 C2 -40 语义映射) */
    if (Result->CmdlineFlags & (IOC_CMD_FLAG_PS_ENCODED | IOC_CMD_FLAG_DOWNLOADER |
                                IOC_CMD_FLAG_REFLECTIVE | IOC_CMD_FLAG_CREDENTIAL_DUMP |
                                IOC_CMD_FLAG_OBFUSCATED)) {
        score += WKD_REP_WEIGHT_CMD_HIGH;
        IocScan_AppendReason(Rep, L"Suspicious command line pattern");
        *Sources |= (1u << DefDetSrc_IOC);
    }

    /* 启发式静态分析 (对齐 SS ThreatIntel Medium/High 权重语义映射) */
    if (Result->HeuristicRan) {
        if (Result->HeuristicConfidence >= 700) {
            score += WKD_REP_WEIGHT_HEUR_HIGH;
            IocScan_AppendReason(Rep, L"Heuristic: high-risk characteristics");
        } else if (Result->HeuristicConfidence >= 300) {
            score += WKD_REP_WEIGHT_HEUR_MED;
            IocScan_AppendReason(Rep, L"Heuristic: suspicious characteristics");
        }
        *Sources |= (1u << DefDetSrc_IOC);
    }

    if (score > 100) score = 100;
    if (score < -100) score = -100;
    return score;
}

/**************************************************/
/*               信誉评分主入口                     */
/**************************************************/

NTSTATUS
IocScan_ReputationScore(
    _Inout_ IOC_SCAN_RESULT*    Result
    )
/*++
Routine Description:
    计算文件信誉评分。从 IOC_SCAN_RESULT 各检测源汇总为
    [-100,100] 信誉分 + 9 级信誉等级 + 置信度 + 来源归因。
    (对齐 SS FileReputation QueryInternal→CalculateFinalScore)
    仅填充 Reputation/SignerReputation/... 字段, 不改 FinalVerdict。
    统一证书验证入口 (SignatureVerifier) 内部调用。

Arguments:
    Result - 扫描结果 (须先经 IocVerifyTrust 填充证书字段)。

Return Value:
    STATUS_SUCCESS。
--*/
{
    WKD_FILE_REPUTATION* rep;
    LONG signerRep = 0;
    ULONG signerCategory = WKD_SIGNER_CATEGORY_UNKNOWN;
    ULONG sources = 0;
    LONG score;
    FILETIME ft;

    if (!Result) return STATUS_INVALID_PARAMETER;

    rep = &Result->Reputation;
    RtlZeroMemory(rep, sizeof(*rep));
    GetSystemTimeAsFileTime(&ft);
    rep->EvaluatedAt = ((ULONG64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

    /* 签名者分类 (供等级覆盖与签名者信誉字段) */
    IocScan_ClassifySigner(Result, &signerRep, &signerCategory);
    Result->SignerReputation = signerRep;
    Result->SignerCategory = signerCategory;

    score = IocScan_CalcWeightedScore(Result, rep, signerRep, signerCategory, &sources);

    rep->Score = score;
    rep->Level = IocScan_LevelFromScore(score, signerCategory);
    rep->Confidence = IocScan_ConfidenceFromLevel(rep->Level);
    rep->Sources = sources;

    return STATUS_SUCCESS;
}

/**************************************************/
/*        信任层级评估 (SS CertificateValidator)    */
/**************************************************/

WKD_TRUST_LEVEL
IocScan_EvaluateTrustLevel(
    _In_ PIOC_SCAN_RESULT Result
    )
/*++
Routine Description:
    统一证书信任层级评估 (对齐 SS CertificateValidator::GetTrustLevel
    L1938-1940 / GetTrustLevelInternal L2934)。
    按 WKD 信任判定能力诚实映射: WKD 链信任为 WinVerifyTrust
    二元结果, 无自定义根/企业根 store 区分, CustomRoot/EnterpriseRoot/
    SystemRoot 归并为 WkdTrust_Validated; EV 由 CERT_EV_PROP_ID
    提升为独立顶级 (对齐 SS TrustLevel::EVValidated 最高级)。

Arguments:
    Result - 扫描结果 (须含 CertStatus/CertTrusted/IsTrustedStrict/
             IsSelfSigned/IsEvCert 证书字段)。

Return Value:
    WKD_TRUST_LEVEL。
--*/
{
    if (!Result) return WkdTrust_Unknown;

    /* 证书级失败态 → Untrusted (对齐 SS: Revoked/Expired/UntrustedRoot/
     * ChainBuildingFailed 均低于 Unknown 信任域) */
    switch (Result->CertStatus) {
    case DefCertStatus_Revoked:
    case DefCertStatus_Expired:
    case DefCertStatus_Invalid:
    case DefCertStatus_UntrustedRoot:
        return WkdTrust_Untrusted;
    default:
        break;
    }

    /* 未签名/无法判定 → Unknown (对齐 SS TrustLevel::Unknown) */
    if (Result->CertStatus == DefCertStatus_Unsigned ||
        Result->CertStatus == DefCertStatus_Unknown) {
        return WkdTrust_Unknown;
    }

    /* Valid/ValidCatalog: 有效签名始得信任评估 */
    if (!Result->CertValid || !Result->CertTrusted) return WkdTrust_Unknown;

    /* EV 顶级 (对齐 SS TrustLevel::EVValidated, 隐含链受信) */
    if (Result->IsEvCert) return WkdTrust_EvValidated;

    /* 有效自签名 (对齐 SS TrustLevel::SelfSigned; 自签无链, 仅叶自证) */
    if (Result->IsSelfSigned) return WkdTrust_SelfSigned;

    /* 链验证通过 → Validated (系统/企业根归并) */
    if (Result->IsTrustedStrict) return WkdTrust_Validated;

    return WkdTrust_Unknown;
}

/**************************************************/
/*     证书级验证细分映射 (SS ValidationResult)     */
/**************************************************/

static WKD_CERT_DETAIL
IocScan_CertDetailFromStatus(
    _In_ DEF_CERT_STATUS Status
    )
{
    switch (Status) {
    case DefCertStatus_Valid:
    case DefCertStatus_ValidCatalog:
        return WkdCertDetail_Valid;
    case DefCertStatus_Revoked:
        return WkdCertDetail_Revoked;
    case DefCertStatus_Expired:
        return WkdCertDetail_Expired;
    case DefCertStatus_UntrustedRoot:
        return WkdCertDetail_UntrustedRoot;
    case DefCertStatus_Invalid:
        return WkdCertDetail_ChainBuildingFailed;
    case DefCertStatus_Unsigned:
        return WkdCertDetail_Unsigned;
    default:
        return WkdCertDetail_Unknown;
    }
}

WKD_CERT_DETAIL
IocScan_MapCertDetail(
    _In_ PIOC_SCAN_RESULT Result
    )
/*++
Routine Description:
    文件级 DEF_CERT_STATUS 8 态 → 证书级细分映射。
    对齐 SS ValidationResult 16 态语义 (SS 为证书级, WKD 为文件级
    Authenticode 判定), 用深度校验字段 (IsWeakSignature/IsCodeSigningEku)
    做 8 态无法表达处的细分:
      - Valid + IsWeakSignature → WeakAlgorithm (SS IsWeakAlgorithm 同判)
      - Valid + !IsCodeSigningEku → 仍 Valid (WKD 无独立 KeyUsageInvalid
        文件级态, 由 IsCodeSigningEku 字段承载, 不降级)
    消费面: 告警文案 / 信誉归因细分 (IocScan_CertDetailName)。

Arguments:
    Result - 扫描结果 (须含证书字段)。

Return Value:
    WKD_CERT_DETAIL。
--*/
{
    WKD_CERT_DETAIL detail;

    if (!Result) return WkdCertDetail_Unknown;

    detail = IocScan_CertDetailFromStatus(Result->CertStatus);

    /* 有效签名 + 弱算法 → WeakAlgorithm (对齐 SS L1356
     * IsWeakAlgorithm(signatureAlgorithm) 判定语义) */
    if (detail == WkdCertDetail_Valid && Result->IsWeakSignature) {
        return WkdCertDetail_WeakAlgorithm;
    }
    return detail;
}

PCWSTR
IocScan_CertDetailName(
    _In_ WKD_CERT_DETAIL Detail
    )
/*++
Routine Description:
    细分结果 → 名称 (对齐 SS GetValidationResultName)。

Return Value:
    名称串 (恒非 NULL)。
--*/
{
    switch (Detail) {
    case WkdCertDetail_Valid:               return L"Valid";
    case WkdCertDetail_Invalid:             return L"Invalid";
    case WkdCertDetail_Expired:             return L"Expired";
    case WkdCertDetail_Revoked:             return L"Revoked";
    case WkdCertDetail_UntrustedRoot:       return L"UntrustedRoot";
    case WkdCertDetail_ChainBuildingFailed: return L"ChainBuildingFailed";
    case WkdCertDetail_WeakAlgorithm:       return L"WeakAlgorithm";
    case WkdCertDetail_Unsigned:            return L"Unsigned";
    default:                                return L"Unknown";
    }
}
