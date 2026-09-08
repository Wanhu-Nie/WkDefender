/**************************************************/
/*  WkDefender IOC — 签名者分类与信誉评分            */
/*  自 IocScanner.c 独立 (2026-08 重构)              */
/*  SS FileReputation 迁移, 按功能融合重实现         */
/**************************************************/

#pragma once

#include "../IocTypes.h"

/**************************************************/
/*              信誉权重宏                          */
/*  (对齐 SS FileReputation.cpp L104-116;           */
/*   SignatureDetails cert_reputation 接线复用)     */
/**************************************************/

#define WKD_REP_WEIGHT_WHITELIST        100
#define WKD_REP_WEIGHT_BLACKLIST       -100
#define WKD_REP_WEIGHT_MICROSOFT_SIGNED  90
#define WKD_REP_WEIGHT_TRUSTED_CERT      70
#define WKD_REP_WEIGHT_VALID_CERT        30
#define WKD_REP_WEIGHT_UNSIGNED          -10
#define WKD_REP_WEIGHT_CERT_REVOKED      -50
#define WKD_REP_WEIGHT_CERT_EXPIRED      -20
#define WKD_REP_WEIGHT_EV_BONUS           10
#define WKD_REP_WEIGHT_LOLLBIN           -25
#define WKD_REP_WEIGHT_CMD_HIGH          -40
#define WKD_REP_WEIGHT_HEUR_HIGH         -70
#define WKD_REP_WEIGHT_HEUR_MED          -30
#define WKD_REP_WEIGHT_NO_CODE_SIGNING   -30   /* 有效签名但无代码签名 EKU (SS PE_sig_verf 迁移, 2026-08) */
#define WKD_REP_WEIGHT_WEAK_SIG          -20   /* 弱签名算法 SHA-1/MD5 (SS PE_sig_verf 迁移, 2026-08) */
#define WKD_REP_WEIGHT_BAD_SIGNER         -50   /* 坏签名者 thumbprint 黑名单 (SS GetCertificateReputation L873-886) */
#define WKD_REP_WEIGHT_MS_NAME_ONLY        30   /* 名称命中微软但叶证书指纹库外 (弱微软, 防 CA 冒名 CN=Microsoft) */
#define WKD_REP_WEIGHT_CERT_REP_TRUSTED    30   /* cert_reputation 表命中受信 (SS GetCertificateTrust 接线) */
#define WKD_REP_WEIGHT_CERT_REP_UNTRUSTED -50   /* cert_reputation 表命中不受信 (SS GetCertificateTrust 接线) */

/**************************************************/
/*            信任层级与验证细分枚举                */
/*  (对齐 SS CertificateValidator TrustLevel /     */
/*   ValidationResult, 2026-09-02 增量迁移)        */
/**************************************************/

/* 统一信任层级 (对齐 SS TrustLevel 7 级, 按 WKD 信任判定能力归并:
 *  WKD 信任判定为 WinVerifyTrust 二元结果, 无自定义根 store,
 *  CustomRoot/EnterpriseRoot/SystemRoot 归并为 Validated;
 *  EV 由 CERT_EV_PROP_ID 提升为独立顶级。 */
typedef enum _WKD_TRUST_LEVEL {
    WkdTrust_Untrusted   = 0,  /* 未受信 (Revoked/Expired/Invalid/UntrustedRoot, 对齐 SS Untrusted) */
    WkdTrust_Unknown     = 1,  /* 未知 (无法判定/未签名, 对齐 SS Unknown) */
    WkdTrust_SelfSigned  = 2,  /* 有效自签名 (对齐 SS SelfSigned) */
    WkdTrust_Validated   = 3,  /* 链验证通过 (系统/企业根归并, 对齐 SS SystemRoot/EnterpriseRoot/CustomRoot) */
    WkdTrust_EvValidated = 4   /* EV 扩展验证 (对齐 SS EVValidated) */
} WKD_TRUST_LEVEL, *PWKD_TRUST_LEVEL;

/* 证书级验证细分结果 (对齐 SS ValidationResult 16 态, 按 WKD 文件级
 * DEF_CERT_STATUS 8 态 + 深度校验字段细化映射)。
 * 消费面: 告警文案 / 信誉归因细分。 */
typedef enum _WKD_CERT_DETAIL {
    WkdCertDetail_Valid               = 0,  /* SS ValidationResult::Valid */
    WkdCertDetail_Invalid             = 1,  /* SS Invalid */
    WkdCertDetail_Expired             = 2,  /* SS Expired */
    WkdCertDetail_Revoked             = 3,  /* SS Revoked */
    WkdCertDetail_UntrustedRoot       = 4,  /* SS UntrustedRoot */
    WkdCertDetail_ChainBuildingFailed = 5,  /* SS ChainBuildingFailed (链构建失败/断裂) */
    WkdCertDetail_WeakAlgorithm       = 6,  /* SS WeakAlgorithm (有效签名但 MD5/SHA-1) */
    WkdCertDetail_Unsigned            = 7,  /* 未签名 (SS 无独立态, 独立化归并) */
    WkdCertDetail_Unknown             = 8,  /* SS Error (无法判定) */
    WkdCertDetail_MaxValue
} WKD_CERT_DETAIL, *PWKD_CERT_DETAIL;

/* 运行时证书黑名单条 (对齐 SS BlockCertificate kMaxBlockedCerts 防无界;
 *  WKD 消费域为签名者指纹, 512 槽足矣, 拒绝恶意无限增长) */
#define WKD_BLOCKED_SIGNER_MAX   512
#define WKD_BLOCKED_REASON_CCH   96

typedef struct _WKD_BLOCKED_SIGNER_ENTRY {
    CHAR   Thumbprint[64];          /* SHA1 thumbprint hex 小写 (key) */
    WCHAR  Reason[WKD_BLOCKED_REASON_CCH]; /* 阻断原因 (对齐 SS BlockCertificate reason) */
} WKD_BLOCKED_SIGNER_ENTRY, *PWKD_BLOCKED_SIGNER_ENTRY;

/**************************************************/
/*                  函数声明                       */
/**************************************************/

/* 运行时证书黑名单 (对齐 SS BlockCertificate/UnblockCertificate/IsBlocked,
 * 2026-09-02 CertificateValidator 增量迁移)。
 * key = 叶证书 SHA1 thumbprint hex (小写, 大小写不敏感匹配)。 */
BOOLEAN
IocScan_BlockSigner(
    _In_ PCSTR          Thumbprint, /* SHA1 thumbprint hex (40 字符) */
    _In_opt_ PCWSTR     Reason      /* 阻断原因 (可为 NULL) */
    );

BOOLEAN
IocScan_UnblockSigner(
    _In_ PCSTR Thumbprint
    );

BOOLEAN
IocScan_IsSignerBlocked(
    _In_ PCSTR Thumbprint
    );

ULONG
IocScan_GetBlockedSignerCount(
    VOID
    );

NTSTATUS
IocScan_GetBlockedSigners(
    _Out_writes_to_(MaxEntries, *Count) PWKD_BLOCKED_SIGNER_ENTRY Entries,
    _In_  ULONG MaxEntries,
    _Out_ PULONG Count
    );

/* 统一信任层级评估 (对齐 SS CertificateValidator::GetTrustLevel) */
WKD_TRUST_LEVEL
IocScan_EvaluateTrustLevel(
    _In_ PIOC_SCAN_RESULT Result
    );

/* 证书级验证细分映射 (对齐 SS ValidationResult 语义) */
WKD_CERT_DETAIL
IocScan_MapCertDetail(
    _In_ PIOC_SCAN_RESULT Result
    );

/* 细分结果名 (供告警/归因文案) */
PCWSTR
IocScan_CertDetailName(
    _In_ WKD_CERT_DETAIL Detail
    );

/*++
Routine Description:
    证书签名者分类 (精确全串 + 微软证书指纹强信号 + 坏签名者黑名单)。
    统一证书验证链路内部 (ReputationScore) 调用; 供未来外部语义化复用。

Arguments:
    Result     - 扫描结果 (须含 CertTrusted/SignerName/Thumbprint 证书字段)。
    Reputation - 可选输出签名者信誉 (-100..100)。
    Category   - 可选输出 WKD_SIGNER_CATEGORY_*。

Return Value:
    STATUS_SUCCESS。
--*/
NTSTATUS
IocScan_ClassifySigner(
    _In_  PIOC_SCAN_RESULT       Result,
    _Out_opt_ PULONG             Reputation,
    _Out_opt_ PULONG             Category
    );

/*++
Routine Description:
    计算文件信誉评分。从 IOC_SCAN_RESULT 各检测源汇总为
    [-100,100] 信誉分 + 9 级信誉等级 + 置信度 + 来源归因。
    (对齐 SS FileReputation QueryInternal→CalculateFinalScore)
    仅填充 Reputation/SignerReputation/... 字段, 不改 FinalVerdict。
    统一证书验证入口 (SignatureVerifier_VerifySignature) 内部调用。

Arguments:
    Result - 扫描结果 (须先经 IocVerifyTrust 填充证书字段)。

Return Value:
    STATUS_SUCCESS。
--*/
NTSTATUS
IocScan_ReputationScore(
    _Inout_ IOC_SCAN_RESULT*    Result
    );
