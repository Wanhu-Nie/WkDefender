/**************************************************/
/*  WkDefender IOC — 统一证书验证入口                */
/*  自 IocScanner.c 独立 (2026-08 重构)              */
/*  融合 SS PE_sig_verf/DSV 多点校验                 */
/**************************************************/

#include "SignatureVerifier.h"
#include "SignatureHunting.h"    /* 签名 APT 狩猎 (门控 g_IoaSignatureHuntingEnabled) */

#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

/**************************************************/
/*           门控开关 (默认关闭, 零行为变化)         */
/**************************************************/

/* 吊销 + Authenticode 策略验证门控 (SS CheckRevocationOnline/ValidateCertificateChain
 * 迁移, 死代码开关默认关闭, 对齐 g_IoaCmdLineAnalyzerEnabled 惯例)。置 TRUE 后
 * IocScan_ExtractCertDetails 链阶段追加 cache-only 吊销检查 + Authenticode 策略验证
 * (CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY, 不阻塞离线), 兑现 DefCertStatus_Revoked (+50)。 */
BOOLEAN g_IocRevocationCheckEnabled = FALSE;

/* catalog 目录签名 fallback 门控 (SS VerifyCatalogSignature + DSV FindCatalogForFile
 * 迁移, 死代码开关默认关闭)。置 TRUE 后 CertVerify 的 NOSIGNATURE 分支补查系统目录
 * (CryptCATAdminEnumCatalogFromHash), 命中产 DefCertStatus_ValidCatalog + CatalogName。 */
BOOLEAN g_IocCatalogEnabled = FALSE;

/* 签名时间豁免门控 (SS PE_sig_verf ValidateTimestamp/IsTimeValidWithGrace 迁移,
 * 死代码开关默认关闭)。置 TRUE 后 CertVerify 的 CERT_E_EXPIRED 分支提取 legacy
 * 计数器签名时间, 签名落在证书有效期内 (±300s 宽限) 则轻罚 (CertScore 15→5)
 * 并回填 SignTime, 对齐 SS "签名时未过期即可信" 语义。 */
BOOLEAN g_IocSignTimeExemptionEnabled = FALSE;

/* cert_reputation 表接线门控 (SS GetCertificateTrust 迁移, 死代码开关默认关闭)。
 * 置 TRUE 后 ExtractCertDetails 提取 Thumbprint 后查询 cert_reputation
 * (StGetCertReputation), 命中受信/不受信写 CertReputationAdjust。 */
BOOLEAN g_IocCertReputationEnabled = FALSE;

/* 证书验证缓存门控 (SS DSV 验证缓存 L1766-1819 轻量迁移, 死代码开关默认关闭)。
 * 置 TRUE 后 VerifySignature 按 文件路径+LastWriteTime 缓存证书+信誉结果,
 * 避免逐模块验签 (IpeFindSuspiciousModules) 重复 WinVerifyTrust。 */
BOOLEAN g_IocCertCacheEnabled = FALSE;

/* 严格判定门控 (SS PE_sig_verf 拒绝语义 L740-789 迁移, 死代码开关默认关闭)。
 * 置 TRUE 后 CertVerify Valid 分支把 EKU 缺失/弱算法/链不受信从"仅记录字段"升级为
 * 影响 CertTrusted (白名单放行依据) 与 CertStatus:
 *   !IsTrustedStrict → DefCertStatus_UntrustedRoot + CertScore 30 (链不受信/根缺失)
 *   !IsCodeSigningEku → CertTrusted=FALSE (有效签名但无代码签名 EKU, SS 拒绝)
 *   IsWeakSignature  → CertTrusted=FALSE (弱签名算法, SS 拒绝)
 * 同时新增 TRUST_E_SUBJECT_NOT_TRUSTED 分支 (默认 SAFER_FLAG 抑制, 严格模式可达),
 * 补齐 DefCertStatus_UntrustedRoot 状态 (对齐 SS UntrustedRoot, 原枚举无生产者)。 */
BOOLEAN g_IocStrictSignatureEnabled = FALSE;

/**************************************************/
/*              WinVerifyTrust 主验证              */
/**************************************************/

NTSTATUS
IocVerifyTrust(
    _In_ PCWSTR FilePath,
    _In_ ULONG VerifyMode,
    _In_ ULONG VerifyFlags,
    _In_ BOOLEAN StrictSignature,
    _Inout_ PIOC_SCAN_RESULT Result
    )
/*++
Routine Description:
    WinVerifyTrust 主验证 + 签名状态细分 + 证书详情提取。
    (catalog fallback / 吊销 / 签名时间豁免由门控控制)
    完整扫描 (IocScanner_ScanFile) 与统一入口 (VerifySignature) 均调用。

Arguments:
    FilePath - 文件完整路径。
    Result   - 输出扫描结果 (证书字段)。

Return Value:
    无。
--*/
{
    
    WINTRUST_DATA wtd = { 0 };
    LONG lStatus;

    if (!CoCheckStringValidity(FilePath) || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(IOC_SCAN_RESULT));

    /* WINTRUST_DATA 构建 */
    {
        wtd.cbStruct = sizeof(WINTRUST_DATA);
        wtd.dwUIChoice = WTD_UI_NONE;   // 不显示UI界面

        if (StrictSignature) {
            wtd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;    // 吊销检查将在整个链上完成
            // 仅使用本地缓存进行吊销检查。 防止通过网络进行吊销检查。
            wtd.dwProvFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL;
        } else {
            /* 当 WTD_REVOKE_NONE 标志与 winVerifyTrust 函数的 pgActionID 参数中设置的
             * HTTPSPROV_ACTION 值结合使用时，不会进行额外的吊销检查。
             * 为了确保 WinVerifyTrust 函数在验证代码签名时不会尝试任何网络检索，
             * 必须在 dwProvFlags 参数中设置 WTD_CACHE_ONLY_URL_RETRIEVAL。*/
            wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
        }

        /* WTD_CHOICE_FILE      - WINTRUST_FILE_INFO（磁盘文件）
         * [+] 专用于 Windows 目录签名（Catalog Signing），校验.cat文件
         * WTD_CHOICE_CATALOG   - WINTRUST_CATALOG_INFO
         * [+] 内存校验——文件已经加载到内存中，且磁盘上的文件可能不存在或已变化时使用。
         * 例如，解包出来的 PE 镜像、从网络中收到的加密代码段。
         * Windows 会直接校验这个内存块中的 Authenticode 签名数据。
         * WTD_CHOICE_BLOB      - WINTRUST_BLOB_INFO
         * [+] 较旧的遗留选项，可忽略。
         * WTD_CHOICE_SIGNER    - WINTRUST_SGNR_INFO
         * [+] 证书校验——现成的证书上下文校验，
         * 想要验证该证书本身是否被系统信任（链是否完整、是否被吊销、是否符合特定策略）时使用。
         * WTD_CHOICE_CERT      - WINTRUST_CERT_INFO */
        wtd.dwUnionChoice = VerifyMode;
        switch (VerifyMode) {
        case WTD_CHOICE_FILE: {
            WINTRUST_FILE_INFO  fileInfo = { 0 };

            /* WINTRUST_FILE_INFO 构建 */
            fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
            fileInfo.pcwszFilePath = FilePath;
            fileInfo.hFile = NULL;          /* hFile - 文件句柄可选 */
            fileInfo.pgKnownSubject = NULL; /* 指向指定主题类型的 GUID 结构的指针 - 可选 */

            wtd.pFile = &fileInfo;
            break;
        }
        case WTD_CHOICE_CATALOG:
        case WTD_CHOICE_BLOB:
        case WTD_CHOICE_CERT:

        default:
            return STATUS_NOT_SUPPORTED;
        }
        
        /* hWVTStateData 成员将收到状态数据的句柄。
         * 必须在后续调用中指定 WTD_STATEACTION_CLOSE 操作来释放此句柄。*/
        wtd.dwStateAction = WTD_STATEACTION_VERIFY;

        /* 离线友好 (SS VerifyPESignature dwProvFlags L643-645):
         * CACHE_ONLY_URL_RETRIEVAL 阻止 WinVerifyTrust 联网取吊销 URL/AIA 中间证书,
         * 扫描路径不卡网 (仅用本地缓存); SAFER_FLAG 忽略不受信根告警 (轻量判定)。 */
        // https://learn.microsoft.com/zh-cn/windows/win32/api/wintrust/ns-wintrust-wintrust_data
        wtd.dwProvFlags |= VerifyFlags;

        /* 严格判定门控 (SS PE_sig_verf/KED 迁移, 2026-08-09): 去 SAFER_FLAG 使不受信根
         * 告警不被抑制 (TRUST_E_SUBJECT_NOT_TRUSTED → UntrustedRoot 分支可达), 开整链
         * 吊销 (WTD_REVOKE_WHOLECHAIN + cache-only, 对齐 SS KED/IPCManager 组合)。
         * 默认关闭零行为变化。 */
        //if (g_IocStrictSignatureEnabled) {
        //    wtd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        //    wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        //}
    }

    /* [+] 通用文件签名校验，使用标准的 Authenticode（验证码）策略提供程序，会校验签名有效性、证书链和吊销状态。
     * WINTRUST_ACTION_GENERIC_VERIFY_V2
     * [+] 验证从任何对象类型创建的证书链。通过使用每个签名者和计数器签名者的链上下文来实现最终链策略的回调。
     * WINTRUST_ACTION_GENERIC_CHAIN_VERIFY
     * [+] 验证 Windows 硬件质量实验室（WHQL）签名驱动程序的真实性。 这是 Authenticode 加载项策略提供程序。
     * DRIVER_ACTION_VERIFY
     * [+] 验证 WinINet 建立的 SSL/TLS 连接。
     * HTTPSPROV_ACTION
     * OFFICESIGN_ACTION_VERIFY - 已废弃
     * WINTRUST_ACTION_TRUSTPROVIDER_TEST   - 仅限调试/诊断
     * */
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    lStatus = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policyGUID, &wtd);

    /* 签名状态细分（对齐 PS VerifyFileSignatureInternal 的状态映射） */
    if (lStatus == ERROR_SUCCESS) {
        Result->CertValid = TRUE;
        Result->CertTrusted = TRUE;
        Result->CertStatus = DefCertStatus_Valid;
        /* 完整证书详情 (签名者/颁发者/链/有效期/thumbprint, 对齐 SS ExtractCertificateDetailsImpl;
         * 内部含 SignerName 填充, 兼容原 ExtractSigner 语义) — 传 wtd.hWVTStateData 走 WTHelper */
        IocScan_ExtractCertDetails(FilePath, Result, wtd.hWVTStateData);

        /* 严格判定门控 (SS PE_sig_verf 拒绝语义 L740-789 迁移, 2026-08-09,
         * 死代码开关默认关闭): 对齐 SS VerifyPESignature 的
         * isChainTrusted && isEKUValid && 签名强度 拒绝语义。 */
        if (g_IocStrictSignatureEnabled) {
            if (!Result->IsTrustedStrict) {
                /* 链不受信/根缺失/链断裂 (CERT_TRUST_NO_ERROR 未达成) */
                Result->CertTrusted = FALSE;
                Result->CertStatus = DefCertStatus_UntrustedRoot;
                Result->CertScore = 30;
            }
            if (Result->ChainDepth > 0 && !Result->IsCodeSigningEku) {
                Result->CertTrusted = FALSE;   /* 有效签名但无代码签名 EKU (SS 拒绝) */
            }
            if (Result->IsWeakSignature) {
                Result->CertTrusted = FALSE;   /* 弱签名算法 MD5/SHA-1 (SS 拒绝) */
            }
        }
    } else if (lStatus == TRUST_E_NOSIGNATURE ||
               lStatus == TRUST_E_SUBJECT_FORM_UNKNOWN ||
               lStatus == TRUST_E_PROVIDER_UNKNOWN) {
        /* 无签名或无法识别主体 */
        Result->CertStatus = DefCertStatus_Unsigned;
        Result->CertScore = 20;
        /* catalog 目录签名 fallback (SS VerifyCatalogSignature + DSV FindCatalogForFile
         * 迁移, 2026-08, 门控 g_IocCatalogEnabled):
         * 系统二进制多走目录签名 (无内嵌 PKCS7), 命中产 DefCertStatus_ValidCatalog,
         * 消除系统文件误报 Unsigned。 */
        if (g_IocCatalogEnabled) {
            WCHAR catPath[MAX_PATH];
            if (IocScan_CatalogFindForFile(FilePath, catPath, RTL_NUMBER_OF(catPath))) {
                if (IocScan_CatalogVerify(FilePath, catPath, Result)) {
                    Result->CertStatus = DefCertStatus_ValidCatalog;
                    Result->CertValid = TRUE;
                    Result->CertTrusted = TRUE;
                    Result->CertScore = 0;
                    wcsncpy_s(Result->CatalogName, RTL_NUMBER_OF(Result->CatalogName),
                              catPath, _TRUNCATE);
                }
            }
        }
    } else if (lStatus == CERT_E_REVOKED) {
        /* 证书被吊销（对齐 PS RISK_WEIGHT_REVOKED_CERT=50） */
        Result->CertValid = TRUE;
        Result->CertStatus = DefCertStatus_Revoked;
        Result->CertScore = 50;
    } else if (lStatus == CERT_E_EXPIRED) {
        /* 证书过期 */
        Result->CertValid = TRUE;
        Result->CertStatus = DefCertStatus_Expired;
        Result->CertScore = 15;

        /* 签名时间豁免 (SS PE_sig_verf ValidateTimestamp/IsTimeValidWithGrace 迁移,
         * 2026-08, 门控 g_IocSignTimeExemptionEnabled): 证书当前过期但签名发生在
         * 证书有效期内 → 轻罚 (CertScore 15→5), 对齐 SS "签名时未过期即可信"。
         * 提取 legacy 计数器签名时间 + 复用 ExtractCertDetails 有效期字段。 */
        if (g_IocSignTimeExemptionEnabled) {
            FILETIME signTime;
            if (IocScan_CertHasTimestamp(FilePath, &signTime, wtd.hWVTStateData) &&
                signTime.dwHighDateTime != 0) {
                IocScan_ExtractCertDetails(FilePath, Result, wtd.hWVTStateData);   /* 填充 CertValidFrom/To */
                if (Result->CertValidFrom != 0 && Result->CertValidTo != 0) {
                    ULARGE_INTEGER st;
                    const ULONG64 kEpochDiff = 116444736000000000ULL; /* 1601→1970 100ns */
                    st.LowPart = signTime.dwLowDateTime;
                    st.HighPart = signTime.dwHighDateTime;
                    if (st.QuadPart >= kEpochDiff) {
                        ULONG64 unix = (st.QuadPart - kEpochDiff) / 10000000ULL;
                        if (unix >= Result->CertValidFrom && unix <= Result->CertValidTo) {
                            Result->SignTime = unix;
                            Result->CertScore = 5;   /* 轻罚: 签名时证书有效, 仅当前过期 */
                        }
                    }
                }
            }
        }
    } else if (lStatus == TRUST_E_SUBJECT_NOT_TRUSTED) {
        /* 不受信根 (SS PE_sig_verf UntrustedRoot; 默认 SAFER_FLAG 抑制此分支,
         * 严格模式去掉抑制后可达)。补齐 DefCertStatus_UntrustedRoot 状态生产者。 */
        Result->CertValid = TRUE;
        Result->CertTrusted = FALSE;
        Result->CertStatus = DefCertStatus_UntrustedRoot;
        Result->CertScore = 30;
    } else {
        /* 有签名但验证失败（无效/不受信根等） */
        Result->CertValid = TRUE;
        Result->CertTrusted = FALSE;
        Result->CertStatus = DefCertStatus_Invalid;
        Result->CertScore = 15;
    }

    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policyGUID, &wtd);
}

/**************************************************/
/*          VerifyMemory 内部 (临时文件持句柄)       */
/**************************************************/

/* 内存缓冲验签: 写临时文件 (DELETE_ON_CLOSE 持句柄防替换) → 统一 CertVerify+Reputation。
 * 对齐 SS DSV "验证期间保持句柄" 防 TOCTOU (随机临时文件名 + DELETE_ON_CLOSE 等效防护)。 */
static NTSTATUS
IocScan_VerifyMemoryToTemp(
    _In_  const BYTE*      Data,
    _In_  ULONG            Size,
    _Out_ IOC_SCAN_RESULT* Result
    )
{
    WCHAR tmpDir[MAX_PATH];
    WCHAR tmpPath[MAX_PATH];
    HANDLE hFile;
    DWORD written;

    if (!Data || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(IOC_SCAN_RESULT));

    if (GetTempPathW(RTL_NUMBER_OF(tmpDir), tmpDir) == 0) return STATUS_UNSUCCESSFUL;
    if (GetTempFileNameW(tmpDir, L"wkdc", 0, tmpPath) == 0) return STATUS_UNSUCCESSFUL;

    hFile = CreateFileW(tmpPath, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DeleteFileW(tmpPath);
        return STATUS_UNSUCCESSFUL;
    }
    if (!WriteFile(hFile, Data, Size, &written, NULL) || written != Size) {
        CloseHandle(hFile);
        DeleteFileW(tmpPath);
        return STATUS_UNSUCCESSFUL;
    }
    CloseHandle(hFile);

    /* 以 DELETE_ON_CLOSE 只读句柄重开并持句柄验证, 验证期间文件不被替换 */
    hFile = CreateFileW(tmpPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DeleteFileW(tmpPath);
        return STATUS_UNSUCCESSFUL;
    }

    IocVerifyTrust(tmpPath, WTD_CHOICE_FILE,
                   (WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL), FALSE, Result);
    IocScan_ReputationScore(Result);

    /* 签名狩猎 (门控): 临时文件扩展名 .tmp, catalog-only/未签名驱动分支
     * 自然不触发 (扩展名判定), 其余异常检测可用 */
    if (g_IoaSignatureHuntingEnabled) {
        IoaSigHunt_AnalyzeSignature(tmpPath, Result, &Result->SignatureHunt);
    }

    CloseHandle(hFile);   /* DELETE_ON_CLOSE 自动删除 */
    return STATUS_SUCCESS;
}

/**************************************************/
/*                统一证书验证入口                   */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
IocVerifySignature(
    _In_ PCWSTR FilePath,
    _Out_ PIOC_SCAN_RESULT Result
    )
/*++
Routine Description:
    统一证书验证入口 (2026-08 融合 SS 多点校验)。
    签名状态细分 + 证书详情提取 + 签名者分类 + 信誉评分, 一步输出完整证书字段。
    门控 g_IocCertCacheEnabled 开启时按 文件路径+LastWriteTime 缓存证书结果,
    避免逐模块验签 (IpeFindSuspiciousModules) 重复 WinVerifyTrust。
    不触发哈希/LOLBin/命令行等其余静态扫描。

Arguments:
    FilePath - 文件完整路径。
    Result   - 输出扫描结果（证书+信誉字段有效）。

Return Value:
    NTSTATUS。
--*/
{
    if (!CoCheckStringValidity(FilePath) || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(IOC_SCAN_RESULT));

    /* 验证缓存 (门控 g_IocCertCacheEnabled): 按 文件路径+LastWriteTime 命中
     * → 复用证书+信誉结果, 避免逐模块验签重复 WinVerifyTrust。
     * 缓存快照不含 IsSelfSigned/链指纹/WHQL/SignatureHunt (消费点不读, 减小条目),
     * 签名狩猎门控开启时补跑详情提取 + 狩猎, 保持 hunting 结果完整性。 */
    if (g_IocCertCacheEnabled && IocScan_CertCacheLookup(FilePath, Result)) {
        if (g_IoaSignatureHuntingEnabled && !Result->SignatureHunt.Ran) {
            IocScan_ExtractCertDetails(FilePath, Result, NULL);
            IoaSigHunt_AnalyzeSignature(FilePath, Result, &Result->SignatureHunt);
        }
        return STATUS_SUCCESS;
    }

    /* 统一证书验证链 (2026-08 融合 SS 多点校验):
     * CertVerify = WinVerifyTrust 简化验证 + 证书详情提取 (EKU/弱算法/吊销/catalog/EV)
     * ReputationScore = 签名者分类 (名称+指纹双通道/黑名单) + 信誉评分
     * SignatureHunt (门控 g_IoaSignatureHuntingEnabled) = 签名 APT 狩猎 9 类异常
     *   (SS DSV AnalyzeSignature 迁移, 2026-08-09), 输出 RiskScore 内嵌 Result */
    IocVerifyTrust(FilePath, WTD_CHOICE_FILE,
                   (WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL), FALSE, Result);
    IocScan_ReputationScore(Result);

    if (g_IoaSignatureHuntingEnabled) {
        IoaSigHunt_AnalyzeSignature(FilePath, Result, &Result->SignatureHunt);
    }

    if (g_IocCertCacheEnabled) {
        IocScan_CertCacheStore(FilePath, Result);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
IocScanner_VerifyMemoryBuffer(
    _In_  const BYTE*      Data,
    _In_  ULONG            Size,
    _Out_ IOC_SCAN_RESULT* Result
    )
/*++
Routine Description:
    内存缓冲证书验证 (SS DigitalSignatureValidator VerifyMemory 迁移, 2026-08)。
    写临时文件 (DELETE_ON_CLOSE 持句柄防替换) → 复用统一 CertVerify + ReputationScore。

Arguments:
    Data   - 待验签的 PE 内存镜像。
    Size   - 缓冲长度。
    Result - 输出扫描结果 (证书+信誉字段)。

Return Value:
    NTSTATUS。
--*/
{
    return IocScan_VerifyMemoryToTemp(Data, Size, Result);
}

/**************************************************/
/*                统一判定辅助                       */
/**************************************************/

BOOLEAN
IocScan_IsMicrosoftSigned(
    _In_ PIOC_SCAN_RESULT Result
    )
/*++
Routine Description:
    统一判定辅助: 签名者是否为微软 (由 ClassifySigner 名称+指纹双通道产出)。
    供白名单/注入放行/进程富化语义化消费, 替代各自重复的 ClassifySigner 调用。
--*/
{
    return (Result != NULL && Result->SignerCategory == WKD_SIGNER_CATEGORY_MICROSOFT);
}

BOOLEAN
IocScan_IsTrustedPublisher(
    _In_ PIOC_SCAN_RESULT Result
    )
/*++
Routine Description:
    统一判定辅助: 签名者是否为可信发行商 (Adobe/Google/Apple 等 8 全串表)。
--*/
{
    return (Result != NULL && Result->SignerCategory == WKD_SIGNER_CATEGORY_TRUSTED);
}

BOOLEAN
IocScan_IsEvSigned(
    _In_ PIOC_SCAN_RESULT Result
    )
/*++
Routine Description:
    统一判定辅助: 是否为 EV 证书签名 (CERT_EV_PROP_ID 检测)。
--*/
{
    return (Result != NULL && Result->IsEvCert);
}
