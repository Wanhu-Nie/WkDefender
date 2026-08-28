/**************************************************/
/*  WkDefender IOC — 证书详情提取与时间戳            */
/*  自 IocScanner.c 独立 (2026-08 重构)              */
/*  对齐 SS ExtractCertificateDetailsImpl/PE_sig_verf */
/**************************************************/

#pragma once

#include "../IocTypes.h"
#include "SignatureReputation.h"   /* WKD_REP_WEIGHT_CERT_REP_* (cert_reputation 接线) */
#include "../../Storage/StorageEngine.h"   /* StGetCertReputation (cert_reputation 表) */

/**************************************************/
/*           门控开关 (定义于 SignatureVerifier.c)  */
/**************************************************/

/* 吊销 + Authenticode 策略验证门控 (SS CheckRevocationOnline 迁移) */
extern BOOLEAN g_IocRevocationCheckEnabled;
/* cert_reputation 表接线门控 (SS GetCertificateTrust 迁移) */
extern BOOLEAN g_IocCertReputationEnabled;

/**************************************************/
/*                  函数声明                       */
/**************************************************/

/*++
Routine Description:
    提取签名证书详情: 签名者/颁发者/SHA1 指纹/有效期/证书链(≤16)/严格信任/
    EV/EKU/弱算法/吊销(cache-only)/cert_reputation 表接线。
    对齐 SS ExecutableAnalyzer::ExtractCertificateDetailsImpl L3428-3561。

Arguments:
    FilePath - 文件路径。
    Result   - 扫描结果 (填充证书详情区, 含 SignerName 兼容原 ExtractSigner 语义)。

Return Value:
    无。
--*/
NTSTATUS
IocScan_ExtractCertDetails(
    _In_ PCWSTR FilePath,
    _Inout_ PIOC_SCAN_RESULT Result,
    _In_ HANDLE WvtStateData
    );

/*++
Routine Description:
    提取 legacy 计数器签名时间戳 (szOID_RSA_counterSign → signingTime)。
    对齐 SS PE_sig_verf L2238-2283。
    签名时间豁免 (SignatureVerifier CertVerify CERT_E_EXPIRED 分支) 激活调用。

Arguments:
    FilePath    - 文件路径。
    OutSignTime - 输出签名时间 (FILETIME; 失败保持 0)。

Return Value:
    TRUE=提取到签名时间。
--*/
BOOLEAN
IocScan_CertHasTimestamp(
    _In_    PCWSTR    FilePath,
    _Out_   PFILETIME OutSignTime,
    _In_opt_ HANDLE   WvtStateData
    );
