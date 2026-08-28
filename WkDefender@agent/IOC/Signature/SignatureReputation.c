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
 * 功能: 内置坏签名者 thumbprint 黑名单, 命中 signerReputation=-50 且等级降级。
 * 2026-08 已激活: IocScan_ClassifySigner 优先查黑名单。表填充来源 = 管理员
 *   静态填充 / 情报 feed (当前预留空表); untrusted 语义同时由 cert_reputation
 *   表 (StUpsertCertReputation IsTrusted=FALSE) 活代码覆盖。 */
static CHAR g_IocBadSigners[32][64];   /* 预留空表: SHA1 thumbprint hex 小写 */

static BOOLEAN
IocScan_IsKnownBadSigner(
    _In_ PCSTR Thumbprint
    )
{
    ULONG i;
    if (!Thumbprint || Thumbprint[0] == '\0') return FALSE;
    for (i = 0; i < RTL_NUMBER_OF(g_IocBadSigners); i++) {
        if (g_IocBadSigners[i][0] == '\0') break;
        if (_stricmp(Thumbprint, g_IocBadSigners[i]) == 0) return TRUE;
    }
    return FALSE;
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
        IocScan_AppendReason(Rep, L"Certificate revoked");
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
