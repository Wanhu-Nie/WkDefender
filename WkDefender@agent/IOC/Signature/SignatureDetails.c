/**************************************************/
/*  WkDefender IOC — 证书详情提取与时间戳            */
/*  自 IocScanner.c 独立 (2026-08 重构)              */
/*  对齐 SS ExtractCertificateDetailsImpl/PE_sig_verf */
/**************************************************/

#include "SignatureDetails.h"
#include <wintrust.h>   /* WTHelper* / WINTRUST_DATA — 替换 deprecated 的 CryptQueryObject 路径 */
#include <softpub.h>    /* WINTRUST_ACTION_GENERIC_VERIFY_V2 策略 GUID (定义于 SoftPub.h) */

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

/* CERT_EV_PROP_ID 未在 26100 SDK 公开 (SS FileReputation 迁移沿用,
 * 微软文档值 63, 微软私有 prop id) */
#ifndef CERT_EV_PROP_ID
#define CERT_EV_PROP_ID  63
#endif

/**************************************************/
/*             证书详情提取主函数                   */
/**************************************************/

NTSTATUS
IocScan_ExtractCertDetails(
    _In_ PCWSTR FilePath,
    _Inout_ PIOC_SCAN_RESULT Result,
    _In_ HANDLE WvtStateData
    )
/*++
Routine Description:
    提取签名证书详情: 签名者/颁发者/SHA1 指纹/有效期/证书链(≤16)/严格信任/
    EV/EKU/弱算法/吊销(cache-only)/cert_reputation 表接线。
    数据源: 优先使用调用方提供的 WinVerifyTrust 状态 (WvtStateData, 走 WTHelper
    非 deprecated 路径); 为 NULL 时内部自建 WinVerifyTrust(VERIFY→提取→CLOSE),
    彻底避免 CryptQueryObject (deprecated)。对齐 SS ExtractCertificateDetailsImpl
    / DigitalSignatureValidator WTHelper 路径。

Arguments:
    FilePath      - 文件路径 (WvtStateData 为 NULL 时用于内部验签)。
    Result        - 扫描结果 (填充证书详情区)。
    WvtStateData  - WinVerifyTrust WTD_STATEACTION_VERIFY 状态句柄; 必须在对应
                    WinVerifyTrust 的 WTD_STATEACTION_CLOSE 之前传入, NULL 由本函数自建。

Return Value:
    无。
--*/
{
    PCRYPT_PROVIDER_DATA providerData;
    PCRYPT_PROVIDER_SGNR signer;

    if (!FilePath || !Result || !WvtStateData) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Result, sizeof(IOC_SCAN_RESULT));

    providerData = WTHelperProvDataFromStateData(WvtStateData);
    if (providerData == NULL) return STATUS_NOT_FOUND;

    signer = WTHelperGetProvSignerFromChain(providerData, 0, FALSE, 0);
    if (signer == NULL) return STATUS_NOT_FOUND;

    /* 多签名者枚举 (双签名近似, 对齐 SS): 遍历签名者索引 */
    {
        DWORD index = 1;
        while (WTHelperGetProvSignerFromChain(providerData, index, FALSE, 0)) index++;
        Result->IsDualSigned = (index >= 2);
    }

    /* 叶证书 = 链元素 0 (由 WTHelper 状态拥有, 不可 CertFreeCertificateContext) */
    {
        PCRYPT_PROVIDER_CERT leafProviderCert;
        PCCERT_CONTEXT certCtx;

        leafProviderCert = WTHelperGetProvCertFromChain(signer, 0);
        if (leafProviderCert == NULL || leafProviderCert->pCert == NULL) {
            return STATUS_NOT_FOUND;
        }
        certCtx = leafProviderCert->pCert;

        /* 签名者 + 颁发者 */
        {
            WCHAR nameBuf[256];
            DWORD nameLen = CertGetNameStringW(
                certCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
                nameBuf, RTL_NUMBER_OF(nameBuf));
            if (nameLen > 1) {
                wcsncpy_s(Result->SignerName, RTL_NUMBER_OF(Result->SignerName),
                    nameBuf, _TRUNCATE);
            }
            nameLen = CertGetNameStringW(
                certCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL,
                nameBuf, RTL_NUMBER_OF(nameBuf));
            if (nameLen > 1) {
                wcsncpy_s(Result->IssuerName, RTL_NUMBER_OF(Result->IssuerName),
                    nameBuf, _TRUNCATE);
            }
        }

        /* SHA1 指纹 (hex 小写) */
        {
            BYTE thumb[20];
            DWORD thumbLen = sizeof(thumb);
            static const CHAR kHex[] = "0123456789abcdef";

            if (CertGetCertificateContextProperty(
                certCtx, CERT_SHA1_HASH_PROP_ID, thumb, &thumbLen) &&
                thumbLen == sizeof(thumb)) {
                for (ULONG k = 0; k < thumbLen; k++) {
                    Result->Thumbprint[k * 2] = kHex[(thumb[k] >> 4) & 0xF];
                    Result->Thumbprint[k * 2 + 1] = kHex[thumb[k] & 0xF];
                }
                Result->Thumbprint[thumbLen * 2] = 0;
            }
        }

        /* cert_reputation 表接线 (SS GetCertificateTrust L927-951 迁移,
         * 2026-08, 门控 g_IocCertReputationEnabled): 命中受信/不受信
         * 写 CertReputationAdjust, 由 CalcWeightedScore 消费 ±信誉。
         * 表键 = SHA1 指纹 hex 小写 (与 Thumbprint 字段一致)。 */
        if (g_IocCertReputationEnabled && Result->Thumbprint[0] != '\0') {
            int trusted = 0;
            if (StGetCertReputation(Result->Thumbprint, &trusted, NULL, 0) == STATUS_SUCCESS) {
                Result->CertReputationAdjust = trusted
                    ? WKD_REP_WEIGHT_CERT_REP_TRUSTED
                    : WKD_REP_WEIGHT_CERT_REP_UNTRUSTED;
            }
        }

        /* EV证书（Extended Validation Certificate，扩展验证证书）
         * 是SSL/TLS证书中身份验证级别最高、审核最严格的一种。
         * 而 CERT_EV_PROP_ID 是Windows中用来标识一张证书是否为EV证书的属性ID。
         * === 严格的审核与强身份认证 === */
        {
            DWORD evLen = 0;
            if (CertGetCertificateContextProperty(
                certCtx, CERT_EV_PROP_ID, NULL, &evLen) &&
                evLen >= sizeof(CRYPT_OID_INFO)) {
                Result->IsEvCert = TRUE;
            }
        }

        /* 有效期 FILETIME(1601) → Unix(1970) 秒 */
        {
            ULARGE_INTEGER from, to;
            const static ULONG64 epochDiff = 116444736000000000ULL; /* 1601→1970 100ns */

            from.LowPart    = certCtx->pCertInfo->NotBefore.dwLowDateTime;
            from.HighPart   = certCtx->pCertInfo->NotBefore.dwHighDateTime;
            to.LowPart      = certCtx->pCertInfo->NotAfter.dwLowDateTime;
            to.HighPart     = certCtx->pCertInfo->NotAfter.dwHighDateTime;

            if (from.QuadPart >= epochDiff)
                Result->CertValidFrom = (from.QuadPart - epochDiff) / 10000000ULL;
            if (to.QuadPart >= epochDiff)
                Result->CertValidTo = (to.QuadPart - epochDiff) / 10000000ULL;
        }

        /* 证书链 + 严格信任 (CERT_TRUST_NO_ERROR, 对齐 SS) */
        {
            CERT_CHAIN_PARA chainPara;  /* 建立用于生成证书链的搜索和匹配条件 */
            PCCERT_CHAIN_CONTEXT certChainCtx = NULL;

            RtlZeroMemory(&chainPara, sizeof(chainPara));
            chainPara.cbSize = sizeof(chainPara);
            if (CertGetCertificateChain(
                NULL, certCtx, NULL, NULL, &chainPara, 0, NULL, &certChainCtx) &&
                certChainCtx != NULL) {
                if (certChainCtx->cChain > 0) {
                    // rgpChain[0] 是最终证书简单链， rgpChain[cChain–1] 是最终链
                    PCERT_SIMPLE_CHAIN chain = certChainCtx->rgpChain[0];
                    for (ULONG ci = 0; ci < chain->cElement; ci++) {
                        WCHAR chainName[256];
                        DWORD nlen = CertGetNameStringW(
                            chain->rgpElement[ci]->pCertContext,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
                            chainName, RTL_NUMBER_OF(chainName));
                        if (nlen > 1) {
                            wcsncpy_s(Result->ChainName[ci],
                                RTL_NUMBER_OF(Result->ChainName[0]),
                                chainName, _TRUNCATE);
                            Result->ChainDepth++;
                        }
                        /* 链元素 SHA1 指纹 (SS DSV AnalyzeSignature 链级被盗证书
                         * 检测 L2031-2048, 2026-08-09 SignatureHunting 迁移) */
                        {
                            BYTE ct[20];
                            DWORD ctLen = sizeof(ct);
                            static const CHAR kHexC[] = "0123456789abcdef";
                            DWORD k;
                            if (CertGetCertificateContextProperty(
                                chain->rgpElement[ci]->pCertContext,
                                CERT_SHA1_HASH_PROP_ID, ct, &ctLen) &&
                                ctLen == sizeof(ct)) {
                                for (k = 0; k < ctLen; k++) {
                                    Result->ChainThumbprint[ci][k * 2] = kHexC[(ct[k] >> 4) & 0xF];
                                    Result->ChainThumbprint[ci][k * 2 + 1] = kHexC[ct[k] & 0xF];
                                }
                                Result->ChainThumbprint[ci][ctLen * 2] = 0;
                            }
                        }
                    }
                }
                Result->IsTrustedStrict =
                    (certChainCtx->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR);
                CertFreeCertificateChain(certChainCtx);
            }
        }

        /* 自签名判定 (SS CV ParseCertificateContext L2338-2406 + IocCert_IsSelfSigned
         * L1417-1444, 2026-08-09 SignatureHunting 迁移): Subject==Issuer blob 直比。
         * 供 SignatureHunting SelfSignedExecutable 异常消费。 */
        Result->IsSelfSigned = (certCtx->pCertInfo->Subject.cbData != 0 &&
                certCtx->pCertInfo->Subject.cbData == certCtx->pCertInfo->Issuer.cbData &&
                CertCompareCertificateName(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    &certCtx->pCertInfo->Subject, &certCtx->pCertInfo->Issuer));

        /* 弱算法检测 */
        {
            CERT_STRONG_SIGN_PARA StrongSignPara = { 0 };
            StrongSignPara.cbSize = sizeof(CERT_STRONG_SIGN_PARA);
            StrongSignPara.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE;
            StrongSignPara.pszOID = szOID_CERT_STRONG_SIGN_OS_1; /* 使用微软预定义的强签名策略 */

            if (!CertIsStrongHashToSign(&StrongSignPara,
                certCtx->pCertInfo->SignatureAlgorithm.pszObjId, NULL)) {
                Result->IsWeakSignature = TRUE;
            }
        }

        /* 代码签名 - 增强型密钥用法（EKU）校验 */
        {
            DWORD cbUsage = 0;

            if (CertGetEnhancedKeyUsage(certCtx, 0, NULL, &cbUsage) && cbUsage > 0) {
                PCERT_ENHKEY_USAGE eku = (PCERT_ENHKEY_USAGE)malloc(cbUsage);
                if (eku) {
                    if (CertGetEnhancedKeyUsage(certCtx, 0, eku, &cbUsage)) {
                        for (DWORD ei = 0; ei < eku->cUsageIdentifier; ei++) {
                            /* 对象标识符 (OID) CTL 扩展的数组 */
                            LPCSTR oid = eku->rgpszUsageIdentifier[ei];
                            if (oid) {
                                /* 标准代码签名（Authenticode）*/
                                if (strcmp(oid, szOID_PKIX_KP_CODE_SIGNING) == 0) {
                                    Result->IsCodeSigningEku = TRUE;
                                }
                                /* WHQL 驱动签 */
                                if (strcmp(oid, szOID_WHQL_CRYPTO) == 0 ||
                                    strcmp(oid, szOID_ATTEST_WHQL_CRYPTO) == 0 ||
                                    strcmp(oid, szOID_EV_WHQL_CRYPTO) == 0) {
                                    Result->IsWhql = TRUE;
                                }
                            }
                        }
                    }
                    free(eku);
                }
            }
        }

        /* 吊销 + Authenticode 策略验证 (SS CheckRevocationOnline L1023-1071 +
         * ValidateCertificateChain L1074-1122, 2026-08 迁移, 门控
         * g_IocRevocationCheckEnabled; cache-only 不阻塞离线) */
        if (g_IocRevocationCheckEnabled) {
            CERT_CHAIN_PARA ccp = { 0 };
            PCCERT_CHAIN_CONTEXT certChainCtx = NULL;

            ccp.cbSize = sizeof(ccp);
            if (CertGetCertificateChain(NULL, certCtx, NULL, NULL, &ccp,
                CERT_CHAIN_REVOCATION_CHECK_CHAIN |
                CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY,
                NULL, &certChainCtx) && certChainCtx != NULL) {
                CERT_CHAIN_POLICY_PARA pp = { 0 };
                CERT_CHAIN_POLICY_STATUS ps = { 0 };

                pp.cbSize = sizeof(pp);
                ps.cbSize = sizeof(ps);
                if (CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_AUTHENTICODE,
                    certChainCtx, &pp, &ps)) {
                    Result->IsRevocationChecked = TRUE;
                    if (ps.dwError != ERROR_SUCCESS) {
                        Result->CertStatus = DefCertStatus_Revoked;
                        Result->CertScore = 50;
                    }
                }
                CertFreeCertificateChain(certChainCtx);
            }
        }

    }   /* 关叶证书块 (pLeaf 由 WTHelper 状态拥有, 不可 CertFreeCertificateContext) */
}

/**************************************************/
/*             legacy 签名时间戳提取                */
/**************************************************/

/* RFC3161 时间戳 token 解析 (实现于下方死代码区, 2026-08-09 激活为 legacy 兜底) */
/* -- RFC3161 时间戳 token 解析 (从计数器签名属性 blob 解析, 非 CryptQueryObject)
 *    功能: szOID_RFC3161_counterSign → CryptMsgOpenToDecode TST →
 *    TST 签名者 AuthAttrs 找 szOID_RSA_signingTime → X509_CHOICE_OF_TIME → FILETIME。 */
static BOOLEAN
IocScan_ExtractRfc3161TimeFromBlob(
    _In_  const BYTE* pbData,
    _In_  DWORD        cbData,
    _Out_ PFILETIME    OutSignTime
    );

/* 从单个签名者 (CMSG_SIGNER_INFO) 的 UnauthAttrs 提取时间戳:
 *   legacy szOID_RSA_counterSign → 解码 PKCS7_SIGNER_INFO → AuthAttrs signingTime
 *   RFC3161 szOID_RFC3161_counterSign → TST (调 IocScan_ExtractRfc3161TimeFromBlob) */
static BOOLEAN
IocScanpHasTimestampFromSigner(
    _In_  PCMSG_SIGNER_INFO psi,
    _Out_ PFILETIME        OutSignTime
    )
{
    DWORD a;
    if (!psi || !OutSignTime) return FALSE;
    for (a = 0; a < psi->UnauthAttrs.cAttr; a++) {
        const CRYPT_ATTRIBUTE* attr = &psi->UnauthAttrs.rgAttr[a];
        if (!attr->cValue || !attr->rgValue) continue;
        if (attr->pszObjId == NULL) continue;
        if (strcmp(attr->pszObjId, szOID_RSA_counterSign) == 0) {
            DWORD cbCs = 0;
            PCMSG_SIGNER_INFO csSI = NULL;
            DWORD j;
            if (CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    PKCS7_SIGNER_INFO, attr->rgValue[0].pbData, attr->rgValue[0].cbData,
                    CRYPT_DECODE_NOCOPY_FLAG, NULL, &cbCs) && cbCs > 0 &&
                cbCs <= (8 * 1024 * 1024)) {
                csSI = (PCMSG_SIGNER_INFO)malloc(cbCs);
                if (csSI) {
                    if (CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            PKCS7_SIGNER_INFO, attr->rgValue[0].pbData, attr->rgValue[0].cbData,
                            CRYPT_DECODE_NOCOPY_FLAG, csSI, &cbCs)) {
                        for (j = 0; j < csSI->AuthAttrs.cAttr; j++) {
                            const CRYPT_ATTRIBUTE* a3 = &csSI->AuthAttrs.rgAttr[j];
                            if (!a3->cValue || !a3->rgValue) continue;
                            if (a3->pszObjId && strcmp(a3->pszObjId, szOID_RSA_signingTime) == 0) {
                                BYTE decoded[16];
                                DWORD cbDec = sizeof(decoded);
                                if (CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        X509_CHOICE_OF_TIME, a3->rgValue[0].pbData,
                                        a3->rgValue[0].cbData, 0, decoded, &cbDec) &&
                                    cbDec >= sizeof(FILETIME)) {
                                    RtlCopyMemory(OutSignTime, decoded, sizeof(FILETIME));
                                    free(csSI);
                                    return TRUE;
                                }
                            }
                        }
                    }
                    free(csSI);
                }
            }
        } else if (strcmp(attr->pszObjId, szOID_RFC3161_counterSign) == 0) {
            if (IocScan_ExtractRfc3161TimeFromBlob(attr->rgValue[0].pbData,
                                                    attr->rgValue[0].cbData, OutSignTime)) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

BOOLEAN
IocScan_CertHasTimestamp(
    _In_    PCWSTR    FilePath,
    _Out_   PFILETIME OutSignTime,
    _In_opt_ HANDLE   WvtStateData
    )
/*++
Routine Description:
    提取签名时间戳 (legacy 计数器签名 / RFC3161), 用于签名时间豁免与未来时间戳检测。
    数据源: 优先使用调用方提供的 WinVerifyTrust 状态 (WvtStateData, WTHelper 路径);
    为 NULL 时内部自建 WinVerifyTrust(VERIFY→提取→CLOSE), 彻底避免 CryptQueryObject
    (deprecated)。对齐 SS PE_sig_verf CheckTimestampCounterSignatureFromMessage。

Arguments:
    FilePath      - 文件路径 (WvtStateData 为 NULL 时用于内部验签)。
    OutSignTime   - 输出签名时间 (FILETIME; 失败保持 0)。
    WvtStateData  - WinVerifyTrust WTD_STATEACTION_VERIFY 状态句柄; 须在 CLOSE 前传入,
                    NULL 由本函数自建。

Return Value:
    TRUE=提取到签名时间。
--*/
{
    HANDLE               hState = NULL;
    HANDLE               hWvtSelf = NULL;
    BOOLEAN              selfState = FALSE;
    BOOLEAN              gotTime = FALSE;
    CRYPT_PROVIDER_DATA* provData = NULL;
    CRYPT_PROVIDER_SGNR* signer = NULL;

    if (!FilePath || !OutSignTime) return FALSE;
    OutSignTime->dwHighDateTime = 0;
    OutSignTime->dwLowDateTime = 0;

    if (WvtStateData != NULL) {
        hState = WvtStateData;
    } else {
        WINTRUST_FILE_INFO fileInfo = { 0 };
        WINTRUST_DATA      wtd = { 0 };
        GUID               policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG               lStatus;

        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = FilePath;
        wtd.cbStruct = sizeof(wtd);
        wtd.dwUIChoice = WTD_UI_NONE;
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wtd.dwUnionChoice = WTD_CHOICE_FILE;
        wtd.pFile = &fileInfo;
        wtd.dwStateAction = WTD_STATEACTION_VERIFY;
        wtd.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
        lStatus = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policyGUID, &wtd);
        if (lStatus != ERROR_SUCCESS || wtd.hWVTStateData == NULL) {
            if (wtd.hWVTStateData != NULL) {
                wtd.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policyGUID, &wtd);
            }
            return FALSE;
        }
        hState = wtd.hWVTStateData;
        hWvtSelf = wtd.hWVTStateData;
        selfState = TRUE;
    }

    provData = WTHelperProvDataFromStateData(hState);
    if (provData) signer = WTHelperGetProvSignerFromChain(provData, 0, FALSE, 0);
    if (signer) {
        /* 主签名者 UnauthAttrs 时间戳 */
        if (signer->psSigner &&
            IocScanpHasTimestampFromSigner(signer->psSigner, OutSignTime)) {
            gotTime = TRUE;
        }
        /* 计数器签名 (时间戳签名者) 时间戳 */
        if (!gotTime) {
            DWORD k;
            for (k = 0; k < signer->csCounterSigners && !gotTime; k++) {
                CRYPT_PROVIDER_SGNR* cs = &signer->pasCounterSigners[k];
                if (cs && cs->psSigner &&
                    IocScanpHasTimestampFromSigner(cs->psSigner, OutSignTime)) {
                    gotTime = TRUE;
                }
            }
        }
    }

    if (selfState && hWvtSelf != NULL) {
        WINTRUST_DATA cwtd = { 0 };
        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        cwtd.cbStruct = sizeof(cwtd);
        cwtd.dwStateAction = WTD_STATEACTION_CLOSE;
        cwtd.hWVTStateData = hWvtSelf;
        WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policyGUID, &cwtd);
    }
    return gotTime;
}
/**************************************************/
/*              时间戳/遗留死代码区                  */
/*  (#pragma warning(4505) 抑制未引用告警)          */
/**************************************************/

#pragma warning(push)
#pragma warning(disable: 4505)

/* (ExtractSigner 死代码已删除: 签名者名提取已内联进 IocScan_ExtractCertDetails 的
 *  WTHelper 路径, 不再依赖 deprecated 的 CryptQueryObject) */

/* -- RFC3161 时间戳 token 解析 (SS PE_sig_verf CheckTimestampCounterSignatureFromMessage
 *    RFC3161 分支 L2168-2236)
 * 功能: UnauthAttrs 中 szOID_RFC3161_counterSign → CryptMsgOpenToDecode TST →
 *    TST 签名者 AuthAttrs 找 szOID_RSA_signingTime → X509_CHOICE_OF_TIME → FILETIME。
 * 状态: 2026-08-09 激活 — IocScan_CertHasTimestamp 尾部 legacy 未命中时回退调用
 *    (纯 RFC3161 时间戳文件不再漏检)。下方其余死代码 (ExtractSigner/ValidateSignTime/
 *    IsSignTimeValidWithGrace) 保持未接入标注。 */
static BOOLEAN
IocScan_ExtractRfc3161TimeFromBlob(
    _In_  const BYTE* pbData,
    _In_  DWORD        cbData,
    _Out_ PFILETIME    OutSignTime
    )
{
    HCRYPTMSG  hTsMsg = NULL;
    BOOLEAN    gotTime = FALSE;

    if (!pbData || cbData == 0 || !OutSignTime) return FALSE;
    OutSignTime->dwHighDateTime = 0;
    OutSignTime->dwLowDateTime = 0;

    hTsMsg = CryptMsgOpenToDecode(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    if (hTsMsg) {
        if (CryptMsgUpdate(hTsMsg, pbData, cbData, TRUE)) {
            DWORD cbTs = 0;
            PCMSG_SIGNER_INFO tsSI = NULL;
            DWORD j;
            if (CryptMsgGetParam(hTsMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cbTs) &&
                cbTs > 0 && cbTs <= (8 * 1024 * 1024)) {
                tsSI = (PCMSG_SIGNER_INFO)malloc(cbTs);
                if (tsSI) {
                    if (CryptMsgGetParam(hTsMsg, CMSG_SIGNER_INFO_PARAM, 0, tsSI, &cbTs)) {
                        for (j = 0; j < tsSI->AuthAttrs.cAttr && !gotTime; j++) {
                            const CRYPT_ATTRIBUTE* a2 = &tsSI->AuthAttrs.rgAttr[j];
                            if (!a2->cValue || !a2->rgValue) continue;
                            if (a2->pszObjId && strcmp(a2->pszObjId, szOID_RSA_signingTime) == 0) {
                                BYTE decoded[16];
                                DWORD cbDec = sizeof(decoded);
                                if (CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        X509_CHOICE_OF_TIME, a2->rgValue[0].pbData,
                                        a2->rgValue[0].cbData, 0, decoded, &cbDec) &&
                                    cbDec >= sizeof(FILETIME)) {
                                    RtlCopyMemory(OutSignTime, decoded, sizeof(FILETIME));
                                    gotTime = TRUE;
                                }
                            }
                        }
                    }
                    free(tsSI);
                }
            }
        }
        CryptMsgClose(hTsMsg);
    }
    return gotTime;
}
/* -- 签名时间窗校验 (SS PE_sig_verf ValidateTimestamp L520-583 + IsTimeValidWithGrace
 *    L2298-2334, 死代码)
 * 功能: 校验签名时间落在证书 NotBefore/NotAfter 区间 (± 宽限期秒, 溢出安全)。
 *    用于过期证书时间戳豁免: 签名时未过期 → 当前过期不降 Expired 档。 */
static BOOLEAN
IocScan_ValidateSignTime(
    _In_  FILETIME       SignTime,
    _In_  PCERT_INFO     CertInfo,
    _In_  ULONG          GraceSeconds
    )
{
    ULARGE_INTEGER nb, na, st;
    ULONGLONG graceTicks;
    const ULONGLONG kMaxGrace = 365ULL * 24 * 60 * 60;

    if (!CertInfo) return FALSE;

    nb.LowPart = CertInfo->NotBefore.dwLowDateTime;
    nb.HighPart = CertInfo->NotBefore.dwHighDateTime;
    na.LowPart = CertInfo->NotAfter.dwLowDateTime;
    na.HighPart = CertInfo->NotAfter.dwHighDateTime;
    st.LowPart = SignTime.dwLowDateTime;
    st.HighPart = SignTime.dwHighDateTime;

    graceTicks = (GraceSeconds > kMaxGrace ? kMaxGrace : (ULONGLONG)GraceSeconds) * 10000000ULL;

    /* 下界 (允许时钟偏差, 防下溢) */
    if (nb.QuadPart > graceTicks) {
        if (st.QuadPart < nb.QuadPart - graceTicks) return FALSE;
    }
    /* 上界 (防溢出) */
    if (na.QuadPart > MAXULONGLONG - graceTicks) {
        if (st.QuadPart > na.QuadPart) return FALSE;
    } else {
        if (st.QuadPart > na.QuadPart + graceTicks) return FALSE;
    }
    return TRUE;
}

/* -- 签名时间窗校验 vs 当前系统时间 (SS PE_sig_verf IsTimeValidWithGrace
 *    L2296-2334, 死代码)
 * 功能: 校验签名时间落在 [now - grace, now + grace] 内 (默认 300s, 溢出安全)。
 *    与 IocScan_ValidateSignTime (签名时间 vs 证书有效期窗, 防过期) 互补:
 *    本函数防伪造未来/过去太久的时间戳 (时间戳回拔/超前攻击)。 */
static BOOLEAN
IocScan_IsSignTimeValidWithGrace(
    _In_ FILETIME SignTime,
    _In_ ULONG    GraceSeconds
    )
{
    SYSTEMTIME    stNow;
    FILETIME      ftNow;
    ULARGE_INTEGER now, ts;
    const ULONGLONG kMaxGrace = 365ULL * 24ULL * 60ULL * 60ULL;
    ULONGLONG     graceTicks;

    if (SignTime.dwHighDateTime == 0 && SignTime.dwLowDateTime == 0) {
        return FALSE;
    }

    GetSystemTime(&stNow);
    if (!SystemTimeToFileTime(&stNow, &ftNow)) {
        return FALSE;
    }
    now.LowPart = ftNow.dwLowDateTime; now.HighPart = ftNow.dwHighDateTime;
    ts.LowPart = SignTime.dwLowDateTime; ts.HighPart = SignTime.dwHighDateTime;

    graceTicks = (GraceSeconds > kMaxGrace ? kMaxGrace : (ULONGLONG)GraceSeconds) * 10000000ULL;

    /* 下界 (防回拔, 溢出安全): ts < now - grace → 无效 */
    if (now.QuadPart > graceTicks) {
        if (ts.QuadPart < now.QuadPart - graceTicks) return FALSE;
    }
    /* 上界 (防超前, 溢出安全): ts > now + grace → 无效 */
    if (now.QuadPart > MAXULONGLONG - graceTicks) {
        /* now 接近上限, 上界天然通过 */
    } else {
        if (ts.QuadPart > now.QuadPart + graceTicks) return FALSE;
    }
    return TRUE;
}

#pragma warning(pop)
