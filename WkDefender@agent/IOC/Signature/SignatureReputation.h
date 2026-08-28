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
/*                  函数声明                       */
/**************************************************/

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
