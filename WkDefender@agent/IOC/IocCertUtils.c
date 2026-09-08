/**************************************************/
/*  WkDefender IOC — X.509 证书工具                */
/*  迁移自 ShadowStrike CertUtils.cpp (2832 行)     */
/*  按功能融合重实现, 非源码复制                    */
/*  裸证书能力域: 加载/导出/属性/验证/公钥           */
/**************************************************/

#include "IocCertUtils.h"
#include <string.h>   /* strcmp / memcmp */
#include <wchar.h>    /* wcsncpy_s / wcsnlen / _snwprintf_s */

/**************************************************/
/*                OID 常量定义                      */
/*  (对齐 SS L157-170, #ifndef 防 SDK 未定义)      */
/**************************************************/

#ifndef szOID_RSA_PSS
#define szOID_RSA_PSS   "1.2.840.113549.1.1.10"   /* PKCS#1 v2.1 */
#endif

#ifndef szOID_DSA_SHA1
#define szOID_DSA_SHA1  "1.2.840.10040.4.3"        /* DSA with SHA-1 */
#endif

#ifndef szOID_ECDSA_SHA1
#define szOID_ECDSA_SHA1 "1.2.840.10045.4.1"       /* ECDSA with SHA-1 */
#endif

/**************************************************/
/*               静态辅助函数                       */
/**************************************************/

/* 文件存在且非目录 (对齐 SS file_exists_w L89-95) */
static
BOOLEAN
IocCertpFileExistsW(
    _In_ PCWSTR Path
    )
{
    DWORD attrs;

    if (!Path || !Path[0]) return FALSE;
    attrs = GetFileAttributesW(Path);
    return (attrs != INVALID_FILE_ATTRIBUTES) && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

/* size_t → DWORD 溢出安全转换 (对齐 SS safe_size_to_dword L104-110) */
static
BOOLEAN
IocCertpSafeSizeToDword(
    _In_  SIZE_T Value,
    _Out_ DWORD* Out
    )
{
    if (Value > (SIZE_T)0xFFFFFFFFUL) {
        return FALSE;
    }
    *Out = (DWORD)Value;
    return TRUE;
}

/* hex 字符校验 (对齐 SS is_hex_char L118-122) */
static
BOOLEAN
IocCertpIsHexChar(
    _In_ WCHAR c
    )
{
    return (c >= L'0' && c <= L'9') ||
           (c >= L'A' && c <= L'F') ||
           (c >= L'a' && c <= L'f');
}

/* hex 字符 → 数值 (对齐 SS hex_char_to_value L130-135) */
static
BYTE
IocCertpHexCharToValue(
    _In_ WCHAR c
    )
{
    if (c >= L'0' && c <= L'9') return (BYTE)(c - L'0');
    if (c >= L'A' && c <= L'F') return (BYTE)(c - L'A' + 10);
    if (c >= L'a' && c <= L'f') return (BYTE)(c - L'a' + 10);
    return 0;
}

/* 字节 → 小写 hex (对齐 SS kHexChars L138 + GetThumbprint 循环 L946-950) */
static
VOID
IocCertpHexEncode(
    _In_  const BYTE* Bytes,
    _In_  ULONG       Count,
    _Out_ PCHAR       Hex
    )
{
    static const CHAR kHex[] = "0123456789abcdef";
    ULONG k;

    for (k = 0; k < Count; k++) {
        Hex[k * 2] = kHex[(Bytes[k] >> 4) & 0x0F];
        Hex[k * 2 + 1] = kHex[Bytes[k] & 0x0F];
    }
    Hex[Count * 2] = '\0';
}

/* FILETIME(1601 100ns) → Unix 秒 (对齐 SS 信誉时间窗语义, 防下溢) */
static
ULONG64
IocCertpFiletimeToUnix(
    _In_ FILETIME Ft
    )
{
    ULARGE_INTEGER li;
    const ULONG64 kEpochDiff = 116444736000000000ULL;   /* 1601→1970 100ns */

    li.LowPart = Ft.dwLowDateTime;
    li.HighPart = Ft.dwHighDateTime;
    if (li.QuadPart >= kEpochDiff) {
        return (li.QuadPart - kEpochDiff) / 10000000ULL;
    }
    return 0;
}

/* 签名算法 OID → 友好名 (对齐 SS GetInfo L1143-1181 + GetSignatureAlgorithm
 * L1604-1650 合并映射, 含 PSS/ECDSA/DSA; 未知返回 UNKNOWN) */
static
PCWSTR
IocCertpMapOidToName(
    _In_opt_ PCSTR Oid
    )
{
    if (!Oid) return L"UNKNOWN";
    if (strcmp(Oid, szOID_RSA_SHA256RSA) == 0) return L"RSA-SHA256";
    if (strcmp(Oid, szOID_RSA_SHA384RSA) == 0) return L"RSA-SHA384";
    if (strcmp(Oid, szOID_RSA_SHA512RSA) == 0) return L"RSA-SHA512";
    if (strcmp(Oid, szOID_RSA_SHA1RSA) == 0 ||
        strcmp(Oid, szOID_OIWSEC_sha1RSASign) == 0) return L"RSA-SHA1";
    if (strcmp(Oid, szOID_RSA_MD5RSA) == 0) return L"RSA-MD5";
    if (strcmp(Oid, szOID_RSA_MD2RSA) == 0) return L"RSA-MD2";
    if (strcmp(Oid, szOID_RSA_PSS) == 0) return L"RSA-PSS";
    if (strcmp(Oid, szOID_ECDSA_SHA256) == 0) return L"ECDSA-SHA256";
    if (strcmp(Oid, szOID_ECDSA_SHA384) == 0) return L"ECDSA-SHA384";
    if (strcmp(Oid, szOID_ECDSA_SHA512) == 0) return L"ECDSA-SHA512";
    if (strcmp(Oid, szOID_ECDSA_SHA1) == 0) return L"ECDSA-SHA1";
    if (strcmp(Oid, szOID_DSA_SHA1) == 0 ||
        strcmp(Oid, szOID_X957_SHA1DSA) == 0) return L"DSA-SHA1";
    return L"UNKNOWN";
}

/* 吊销模式 → 链 flags 附加位 (对齐 SS revocation_flags_for L179-194) */
static
DWORD
IocCertpRevocationFlagsFor(
    _In_ WKD_REVOCATION_MODE Mode
    )
{
    switch (Mode) {
    case WkdRevocation_OnlineOnly:
        /* 严格: 全链除根吊销在线检查 */
        return CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    case WkdRevocation_OfflineAllowed:
        /* 同链覆盖但累计超时, 容忍慢/离线 responder */
        return CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
               CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT;
    case WkdRevocation_Disabled:
        return 0;
    }
    return CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
}

/* 吊销模式 → 可忽略信任错误位 (对齐 SS ignorable_trust_errors_for L202-208) */
static
DWORD
IocCertpIgnorableTrustErrorsFor(
    _In_ WKD_REVOCATION_MODE Mode
    )
{
    if (Mode == WkdRevocation_OfflineAllowed) {
        return CERT_TRUST_IS_OFFLINE_REVOCATION |
               CERT_TRUST_REVOCATION_STATUS_UNKNOWN;
    }
    return 0;
}

/* 缓冲内字节搜索 (对齐 SS std::string_view::find PEM 头 L426-427) */
static
BOOLEAN
IocCertpBufferContains(
    _In_ const BYTE* Data,
    _In_ SIZE_T      Len,
    _In_ PCSTR       Needle
    )
{
    SIZE_T nlen;
    SIZE_T i;

    if (!Data || !Needle) return FALSE;
    nlen = strlen(Needle);
    if (Len < nlen) return FALSE;
    for (i = 0; i + nlen <= Len; i++) {
        if (Data[i] == (BYTE)Needle[0] && memcmp(Data + i, Needle, nlen) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/**************************************************/
/*               活代码: 加载                       */
/**************************************************/

BOOLEAN
IocCert_LoadFromFile(
    _In_  PCWSTR          FilePath,
    _Out_ PCCERT_CONTEXT* OutCert
    )
/*++
Routine Description:
    从文件加载证书 (DER/PEM/PKCS#7 容器自动识别)。
    对齐 SS Certificate::LoadFromFile L286-382。

Arguments:
    FilePath - 证书文件路径。
    OutCert  - 输出证书上下文 (调用方须 CertFreeCertificateContext)。

Return Value:
    TRUE=成功, FALSE=失败。
--*/
{
    WIN32_FILE_ATTRIBUTE_DATA fad;
    ULARGE_INTEGER fileSize;
    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT rawCtx = NULL;

    if (!OutCert) return FALSE;
    *OutCert = NULL;

    /* 1. 参数/存在/大小校验 */
    if (!FilePath || !FilePath[0]) return FALSE;
    if (!IocCertpFileExistsW(FilePath)) return FALSE;
    if (!GetFileAttributesExW(FilePath, GetFileExInfoStandard, &fad)) return FALSE;
    fileSize.LowPart = fad.nFileSizeLow;
    fileSize.HighPart = fad.nFileSizeHigh;
    if (fileSize.QuadPart > WKD_CERT_MAX_FILE_SIZE) return FALSE;

    /* 2. CryptQueryObject: 先 X.509 容器, 失败回退 PKCS#7 (对齐 L340-348) */
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, FilePath,
                          CERT_QUERY_CONTENT_FLAG_CERT,
                          CERT_QUERY_FORMAT_FLAG_ALL, 0,
                          &dwEncoding, &dwContentType, &dwFormatType,
                          &hStore, NULL, NULL)) {
        const DWORD pkcs7Flags = CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
                                 CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED |
                                 CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED;
        if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, FilePath, pkcs7Flags,
                              CERT_QUERY_FORMAT_FLAG_ALL, 0,
                              &dwEncoding, &dwContentType, &dwFormatType,
                              &hStore, NULL, NULL)) {
            return FALSE;
        }
    }
    if (!hStore) return FALSE;

    /* 3. 枚举第一个证书 (对齐 L358-364) */
    rawCtx = CertEnumCertificatesInStore(hStore, NULL);

    /* 4. 复制上下文以独立拥有 (对齐 L368-373) */
    if (rawCtx) {
        *OutCert = CertDuplicateCertificateContext(rawCtx);
        CertFreeCertificateContext(rawCtx);
    }

    CertCloseStore(hStore, 0);
    return (*OutCert != NULL);
}

BOOLEAN
IocCert_LoadFromMemory(
    _In_  const BYTE*     Data,
    _In_  SIZE_T          Len,
    _Out_ PCCERT_CONTEXT* OutCert
    )
/*++
Routine Description:
    从内存加载证书 (DER/PEM 自动检测)。
    对齐 SS Certificate::LoadFromMemory L397-507。

Arguments:
    Data    - 证书数据。
    Len     - 数据长度 (上限 WKD_CERT_MAX_CERT_SIZE)。
    OutCert - 输出证书上下文 (调用方须 CertFreeCertificateContext)。

Return Value:
    TRUE=成功, FALSE=失败。
--*/
{
    static const CHAR kPemHeader[] = "-----BEGIN CERTIFICATE-----";
    DWORD dataLen = 0;
    DWORD derSize = 0;
    BYTE* der = NULL;
    BOOLEAN isPem;
    PCCERT_CONTEXT ctx = NULL;

    if (!OutCert) return FALSE;
    *OutCert = NULL;

    /* 1. 参数校验 (对齐 L403-419) */
    if (!Data || Len == 0) return FALSE;
    if (Len > WKD_CERT_MAX_CERT_SIZE) return FALSE;
    if (!IocCertpSafeSizeToDword(Len, &dataLen)) return FALSE;

    /* 2. PEM 头检测 (对齐 L422-427) */
    isPem = IocCertpBufferContains(Data, Len, kPemHeader);

    if (isPem) {
        /* 3a. PEM: CryptStringToBinaryA 解码为 DER (对齐 L430-477) */
        if (!CryptStringToBinaryA((LPCSTR)Data, dataLen, CRYPT_STRING_BASE64HEADER,
                                  NULL, &derSize, NULL, NULL)) {
            return FALSE;
        }
        if (derSize == 0) return FALSE;
        der = (BYTE*)malloc(derSize);
        if (!der) return FALSE;
        if (!CryptStringToBinaryA((LPCSTR)Data, dataLen, CRYPT_STRING_BASE64HEADER,
                                  der, &derSize, NULL, NULL)) {
            free(der);
            return FALSE;
        }
        ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                           der, derSize);
        free(der);
    } else {
        /* 3b. DER 直建 (对齐 L487-500) */
        ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                           Data, dataLen);
    }

    if (!ctx) return FALSE;
    *OutCert = ctx;
    return TRUE;
}

BOOLEAN
IocCert_LoadFromPEM(
    _In_  PCSTR           Pem,
    _Out_ PCCERT_CONTEXT* OutCert
    )
/*++
Routine Description:
    从 PEM 字符串加载证书 (校验 BEGIN/END marker)。
    对齐 SS Certificate::LoadFromPEM L664-752。

Arguments:
    Pem     - PEM 编码证书字符串 (ASCII)。
    OutCert - 输出证书上下文 (调用方须 CertFreeCertificateContext)。

Return Value:
    TRUE=成功, FALSE=失败。
--*/
{
    static const char kPemHeader[] = "-----BEGIN CERTIFICATE-----";
    static const char kPemFooter[] = "-----END CERTIFICATE-----";
    DWORD pemLen = 0;
    DWORD derSize = 0;
    BYTE* der = NULL;
    PCCERT_CONTEXT ctx = NULL;

    if (!OutCert) return FALSE;
    *OutCert = NULL;

    /* 1. 参数校验 + marker 存在性 (对齐 L670-690) */
    if (!Pem || !Pem[0]) return FALSE;
    if (!strstr(Pem, kPemHeader) || !strstr(Pem, kPemFooter)) return FALSE;
    if (!IocCertpSafeSizeToDword((SIZE_T)strlen(Pem), &pemLen)) return FALSE;

    /* 2. 查询 DER 输出大小 (对齐 L693-709) */
    if (!CryptStringToBinaryA(Pem, pemLen, CRYPT_STRING_BASE64HEADER,
                              NULL, &derSize, NULL, NULL)) {
        return FALSE;
    }
    if (derSize == 0) return FALSE;

    /* 3. 分配 + 解码 (对齐 L711-739) */
    der = (BYTE*)malloc(derSize);
    if (!der) return FALSE;
    if (!CryptStringToBinaryA(Pem, pemLen, CRYPT_STRING_BASE64HEADER,
                              der, &derSize, NULL, NULL)) {
        free(der);
        return FALSE;
    }
    ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                       der, derSize);
    free(der);

    if (!ctx) return FALSE;
    *OutCert = ctx;
    return TRUE;
}

/**************************************************/
/*               活代码: 属性                       */
/**************************************************/

BOOLEAN
IocCert_GetThumbprint(
    _In_      PCCERT_CONTEXT Cert,
    _In_      BOOLEAN        Sha256,
    _Out_writes_(HexCch) PCHAR Hex,
    _In_      ULONG          HexCch
    )
/*++
Routine Description:
    获取证书指纹 (SHA1 20B 或 SHA256 32B, hex 字符串)。
    对齐 SS Certificate::GetThumbprint L902-959。

Arguments:
    Cert   - 证书上下文。
    Sha256 - TRUE=使用 CERT_SHA256_HASH_PROP_ID (SHA256), FALSE=使用 CERT_HASH_PROP_ID (SHA1)。
    Hex    - 输出 hex 缓冲 (SHA1 需 ≥41, SHA256 需 ≥65)。
    HexCch - Hex 缓冲大小 (字符)。

Return Value:
    TRUE=成功, FALSE=失败。
--*/
{
    DWORD propId;
    DWORD cb = 0;
    BYTE* hash = NULL;
    BOOLEAN ok = FALSE;

    if (!Cert || !Hex || HexCch == 0) return FALSE;
    Hex[0] = '\0';

    /* 1. 属性 ID 按哈希类型 (对齐 L912) */
    propId = Sha256 ? CERT_SHA256_HASH_PROP_ID : CERT_HASH_PROP_ID;

    /* 2. 查询大小 (对齐 L916-918) */
    if (!CertGetCertificateContextProperty(Cert, propId, NULL, &cb) || cb == 0) {
        return FALSE;
    }

    /* 3. 分配 + 获取 (对齐 L932-935) */
    hash = (BYTE*)malloc(cb);
    if (!hash) return FALSE;
    if (CertGetCertificateContextProperty(Cert, propId, hash, &cb)) {
        ULONG needCch = cb * 2 + 1;
        if (HexCch >= needCch) {
            IocCertpHexEncode(hash, cb, Hex);
            ok = TRUE;
        }
    }
    free(hash);
    return ok;
}

BOOLEAN
IocCert_GetInfo(
    _In_  PCCERT_CONTEXT Cert,
    _Out_ PWKD_CERT_DETAILS Info
    )
/*++
Routine Description:
    提取综合证书信息 (主题/颁发者/序列号/指纹/有效期/CA/自签名/签名算法友好名)。
    对齐 SS Certificate::GetInfo L971-1189。

Arguments:
    Cert - 证书上下文。
    Info - 输出信息结构。

Return Value:
    TRUE=成功, FALSE=失败 (Cert 或 pCertInfo 无效)。
--*/
{
    PCERT_INFO pi;
    DWORD charsNeeded;
    PCERT_EXTENSION extBC;
    FILETIME ftNow;
    SYSTEMTIME stNow;
    BOOLEAN isExpired = FALSE;
    BOOLEAN isSelfSigned = FALSE;
    BOOLEAN isCA = FALSE;
    LONG pathLen = -1;
    DWORD i;

    if (!Cert || !Info) return FALSE;
    RtlZeroMemory(Info, sizeof(*Info));
    Info->PathLenConstraint = -1;

    pi = Cert->pCertInfo;
    if (!pi) return FALSE;

    /* 1. 主题 (对齐 L987-1017) */
    charsNeeded = CertGetNameStringW(Cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
                                     NULL, 0);
    if (charsNeeded > 1) {
        CertGetNameStringW(Cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
                           Info->Subject, RTL_NUMBER_OF(Info->Subject));
    }

    /* 2. 颁发者 (对齐 L1019-1048) */
    charsNeeded = CertGetNameStringW(Cert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                     CERT_NAME_ISSUER_FLAG, NULL, NULL, 0);
    if (charsNeeded > 1) {
        CertGetNameStringW(Cert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                           CERT_NAME_ISSUER_FLAG, NULL,
                           Info->Issuer, RTL_NUMBER_OF(Info->Issuer));
    }

    /* 3. 序列号 (大端 MSB-first 展示, 对齐 L1050-1068; 定长 128 防溢出) */
    if (pi->SerialNumber.cbData > 0 && pi->SerialNumber.pbData) {
        DWORD cb = pi->SerialNumber.cbData;
        ULONG maxBytes = (ULONG)(RTL_NUMBER_OF(Info->SerialNumber) - 1) / 2;
        ULONG n = (cb < maxBytes) ? cb : maxBytes;
        static const CHAR kHex[] = "0123456789abcdef";
        for (i = 0; i < n; i++) {
            BYTE b = pi->SerialNumber.pbData[cb - 1 - i];
            Info->SerialNumber[i * 2] = (WCHAR)kHex[(b >> 4) & 0xF];
            Info->SerialNumber[i * 2 + 1] = (WCHAR)kHex[b & 0xF];
        }
        Info->SerialNumber[n * 2] = L'\0';
    }

    /* 4. SHA256 指纹 (对齐 L1070-1071, 失败留空) */
    IocCert_GetThumbprint(Cert, TRUE, Info->ThumbprintSha256,
                          RTL_NUMBER_OF(Info->ThumbprintSha256));
    IocCert_GetThumbprint(Cert, FALSE, Info->ThumbprintSha1,
                          RTL_NUMBER_OF(Info->ThumbprintSha1));

    /* 5. 有效期 (Unix 秒) (对齐 L1073-1075) */
    Info->NotBefore = IocCertpFiletimeToUnix(pi->NotBefore);
    Info->NotAfter = IocCertpFiletimeToUnix(pi->NotAfter);

    /* 6. 是否过期 (对齐 L1078-1085) */
    GetSystemTime(&stNow);
    if (SystemTimeToFileTime(&stNow, &ftNow)) {
        if (CompareFileTime(&ftNow, &pi->NotAfter) > 0) {
            isExpired = TRUE;
        }
    }

    /* 7. 自签名 (Subject/Issuer blob 直比, 对齐 L1087-1099) */
    if (pi->Subject.cbData > 0 && pi->Subject.cbData == pi->Issuer.cbData &&
        pi->Subject.pbData && pi->Issuer.pbData) {
        isSelfSigned = (memcmp(pi->Subject.pbData, pi->Issuer.pbData,
                               pi->Subject.cbData) == 0);
    }

    /* 8. BasicConstraints2 → isCA + pathLen (对齐 L1101-1141) */
    extBC = CertFindExtension(szOID_BASIC_CONSTRAINTS2, pi->cExtension,
                              pi->rgExtension);
    if (extBC && extBC->Value.pbData && extBC->Value.cbData > 0) {
        DWORD cbDec = 0;
        if (CryptDecodeObject(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                              extBC->Value.pbData, extBC->Value.cbData,
                              0, NULL, &cbDec) && cbDec > 0 &&
            cbDec <= WKD_CERT_MAX_DECODED) {
            BYTE* buf = (BYTE*)malloc(cbDec);
            if (buf) {
                if (CryptDecodeObject(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                                      extBC->Value.pbData, extBC->Value.cbData,
                                      0, buf, &cbDec)) {
                    PCERT_BASIC_CONSTRAINTS2_INFO bc = (PCERT_BASIC_CONSTRAINTS2_INFO)buf;
                    isCA = (bc->fCA != FALSE);
                    pathLen = bc->fPathLenConstraint
                                  ? (LONG)bc->dwPathLenConstraint
                                  : -1;
                }
                free(buf);
            }
        }
    }

    /* 9. 签名算法友好名 (对齐 L1143-1181) */
    wcsncpy_s(Info->SignatureAlgorithm, RTL_NUMBER_OF(Info->SignatureAlgorithm),
              IocCertpMapOidToName(pi->SignatureAlgorithm.pszObjId), _TRUNCATE);

    Info->IsExpired = isExpired;
    Info->IsSelfSigned = isSelfSigned;
    Info->IsCA = isCA;
    Info->PathLenConstraint = pathLen;
    return TRUE;
}

BOOLEAN
IocCert_IsSelfSigned(
    _In_ PCCERT_CONTEXT Cert
    )
/*++
Routine Description:
    判断证书是否自签名 (Subject == Issuer, blob 直比)。
    对齐 SS Certificate::IsSelfSigned L1417-1444。

Arguments:
    Cert - 证书上下文。

Return Value:
    TRUE=自签名, FALSE=非自签名或 Cert 无效。
--*/
{
    DWORD subjectLen, issuerLen;

    if (!Cert || !Cert->pCertInfo) return FALSE;
    subjectLen = Cert->pCertInfo->Subject.cbData;
    issuerLen = Cert->pCertInfo->Issuer.cbData;

    if (subjectLen == 0 || subjectLen != issuerLen) return FALSE;
    if (!Cert->pCertInfo->Subject.pbData || !Cert->pCertInfo->Issuer.pbData) {
        return FALSE;
    }
    return (memcmp(Cert->pCertInfo->Subject.pbData,
                   Cert->pCertInfo->Issuer.pbData, subjectLen) == 0);
}

LONG
IocCert_GetBasicConstraintsPathLen(
    _In_ PCCERT_CONTEXT Cert
    )
/*++
Routine Description:
    获取 Basic Constraints pathLen 约束。
    对齐 SS Certificate::GetBasicConstraintsPathLen L1454-1518。

Arguments:
    Cert - 证书上下文。

Return Value:
    pathLen 约束值, -1=无约束或解码失败。
--*/
{
    PCERT_EXTENSION ext;
    DWORD cbDec = 0;
    BYTE* buf = NULL;
    LONG result = -1;

    if (!Cert || !Cert->pCertInfo) return -1;

    /* 1. 定位 BasicConstraints2 扩展 (对齐 L1460-1469) */
    ext = CertFindExtension(szOID_BASIC_CONSTRAINTS2, Cert->pCertInfo->cExtension,
                            Cert->pCertInfo->rgExtension);
    if (!ext || !ext->Value.pbData || ext->Value.cbData == 0) return -1;

    /* 2. 查询解码大小 (对齐 L1472-1487) */
    if (!CryptDecodeObject(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                           ext->Value.pbData, ext->Value.cbData, 0, NULL, &cbDec)) {
        return -1;
    }
    if (cbDec == 0 || cbDec > WKD_CERT_MAX_DECODED) return -1;

    /* 3. 分配 + 解码 (对齐 L1490-1514) */
    buf = (BYTE*)malloc(cbDec);
    if (!buf) return -1;
    if (CryptDecodeObject(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                          ext->Value.pbData, ext->Value.cbData, 0, buf, &cbDec)) {
        PCERT_BASIC_CONSTRAINTS2_INFO bc = (PCERT_BASIC_CONSTRAINTS2_INFO)buf;
        if (bc && bc->fPathLenConstraint != FALSE) {
            result = (LONG)bc->dwPathLenConstraint;
        }
    }
    free(buf);
    return result;
}

BOOLEAN
IocCert_GetSignatureAlgorithm(
    _In_      PCCERT_CONTEXT Cert,
    _Out_writes_(AlgCch) PWCHAR Alg,
    _In_      ULONG          AlgCch
    )
/*++
Routine Description:
    获取签名算法友好名 (OID → "RSA-SHA256" 等)。
    对齐 SS Certificate::GetSignatureAlgorithm L1584-1657。

Arguments:
    Cert   - 证书上下文。
    Alg    - 输出友好名缓冲。
    AlgCch - Alg 缓冲大小 (字符)。

Return Value:
    TRUE=成功, FALSE=失败。
--*/
{
    LPCSTR oid;

    if (!Cert || !Alg || AlgCch == 0) return FALSE;
    if (!Cert->pCertInfo) return FALSE;
    oid = Cert->pCertInfo->SignatureAlgorithm.pszObjId;
    if (!oid || !oid[0]) return FALSE;

    wcsncpy_s(Alg, AlgCch, IocCertpMapOidToName(oid), _TRUNCATE);
    return TRUE;
}

BOOLEAN
IocCert_IsStrongSignatureAlgo(
    _In_ PCCERT_CONTEXT Cert,
    _In_ BOOLEAN        AllowSha1
    )
/*++
Routine Description:
    判定证书是否使用强签名算法。
    MD2/MD5 恒拒; SHA1 家族仅在 AllowSha1 时接受; SHA256/384/512 + RSA-PSS 恒强;
    未知算法保守拒绝。对齐 SS Certificate::IsStrongSignatureAlgo L1529-1573。

Arguments:
    Cert      - 证书上下文。
    AllowSha1 - TRUE=允许 SHA1 签名 (含 ecdsa/dsa-with-SHA1)。

Return Value:
    TRUE=强算法, FALSE=弱算法/未知/Cert 无效。
--*/
{
    LPCSTR oid;

    if (!Cert || !Cert->pCertInfo) return FALSE;
    oid = Cert->pCertInfo->SignatureAlgorithm.pszObjId;
    if (!oid || !oid[0]) return FALSE;

    /* MD2/MD5 恒拒 (对齐 L1541-1546) */
    if (strcmp(oid, szOID_RSA_MD2RSA) == 0 ||
        strcmp(oid, szOID_RSA_MD5RSA) == 0 ||
        strcmp(oid, szOID_RSA_MD2) == 0 ||
        strcmp(oid, szOID_RSA_MD5) == 0) {
        return FALSE;
    }

    /* SHA1 家族 — 仅显式允许 (对齐 L1549-1554) */
    if (strcmp(oid, szOID_RSA_SHA1RSA) == 0 ||
        strcmp(oid, szOID_OIWSEC_sha1RSASign) == 0 ||
        strcmp(oid, szOID_ECDSA_SHA1) == 0 ||
        strcmp(oid, szOID_DSA_SHA1) == 0) {
        return AllowSha1;
    }

    /* SHA256/384/512 + ECDSA + PSS 恒强 (对齐 L1557-1565) */
    if (strcmp(oid, szOID_RSA_SHA256RSA) == 0 ||
        strcmp(oid, szOID_RSA_SHA384RSA) == 0 ||
        strcmp(oid, szOID_RSA_SHA512RSA) == 0 ||
        strcmp(oid, szOID_ECDSA_SHA256) == 0 ||
        strcmp(oid, szOID_ECDSA_SHA384) == 0 ||
        strcmp(oid, szOID_ECDSA_SHA512) == 0 ||
        strcmp(oid, szOID_RSA_PSS) == 0) {
        return TRUE;
    }

    /* 未知算法 — 保守视为弱 (对齐 L1568) */
    return FALSE;
}

BOOLEAN
IocCert_HasEKU(
    _In_ PCCERT_CONTEXT Cert,
    _In_ PCSTR          Oid
    )
/*++
Routine Description:
    检查证书是否含指定 Enhanced Key Usage (EKU) OID。
    无 EKU 扩展 → any-use → TRUE (对齐 SS CRYPT_E_NOT_FOUND 语义 L2209-2213)。

Arguments:
    Cert - 证书上下文。
    Oid  - EKU OID 字符串 (如 "1.3.6.1.5.5.7.3.3" 代码签名)。

Return Value:
    TRUE=EKU 存在或无 EKU 扩展 (any-use), FALSE=不存在/Cert 无效。
--*/
{
    DWORD cbNeeded = 0;
    BYTE* buf = NULL;
    PCERT_ENHKEY_USAGE pUsage;
    DWORD i;
    BOOLEAN found = FALSE;

    if (!Cert || !Oid || !Oid[0]) return FALSE;

    /* 1. 查询大小 (对齐 L2206-2216) */
    if (!CertGetEnhancedKeyUsage(Cert, 0, NULL, &cbNeeded)) {
        DWORD lastError = GetLastError();
        if (lastError == CRYPT_E_NOT_FOUND) {
            return TRUE;    /* 无 EKU 扩展 = 允许任何用途 */
        }
        return FALSE;
    }
    if (cbNeeded == 0 || cbNeeded > WKD_CERT_MAX_DECODED) return FALSE;

    /* 2. 分配 + 获取 (对齐 L2224-2239) */
    buf = (BYTE*)malloc(cbNeeded);
    if (!buf) return FALSE;
    if (!CertGetEnhancedKeyUsage(Cert, 0, (PCERT_ENHKEY_USAGE)buf, &cbNeeded)) {
        free(buf);
        return FALSE;
    }
    pUsage = (PCERT_ENHKEY_USAGE)buf;

    /* 3. 搜索指定 OID (对齐 L2242-2248) */
    for (i = 0; i < pUsage->cUsageIdentifier; i++) {
        if (pUsage->rgpszUsageIdentifier &&
            pUsage->rgpszUsageIdentifier[i] &&
            strcmp(pUsage->rgpszUsageIdentifier[i], Oid) == 0) {
            found = TRUE;
            break;
        }
    }
    free(buf);
    return found;
}

BOOLEAN
IocCert_HasKeyUsage(
    _In_ PCCERT_CONTEXT Cert,
    _In_ DWORD          Flags
    )
/*++
Routine Description:
    检查证书是否含指定 Key Usage 位。
    无 KeyUsage 扩展 → any-use → TRUE (对齐 SS L2291-2295)。
    对齐 SS Certificate::HasKeyUsage L2267-2309。

Arguments:
    Cert  - 证书上下文。
    Flags - KeyUsage 位 (如 CERT_DIGITAL_SIGNATURE_KEY_USAGE)。

Return Value:
    TRUE=全部指定位已设置或无扩展, FALSE=未满足/Cert 无效。
--*/
{
    BYTE usage[2] = { 0, 0 };
    BYTE requestedBits;

    if (!Cert || !Cert->pCertInfo) return FALSE;
    if (Flags == 0) return TRUE;

    /* CertGetIntendedKeyUsage: 失败且 GetLastError==0 视为无扩展 any-use (对齐 L2286-2298) */
    if (!CertGetIntendedKeyUsage(X509_ASN_ENCODING, Cert->pCertInfo,
                                 usage, sizeof(usage))) {
        DWORD lastError = GetLastError();
        if (lastError == 0 || lastError == ERROR_SUCCESS) {
            return TRUE;
        }
        return FALSE;
    }

    requestedBits = (BYTE)(Flags & 0xFF);
    return ((usage[0] & requestedBits) == requestedBits);
}

/**************************************************/
/*               活代码: 链验证                    */
/**************************************************/

BOOLEAN
IocCert_VerifyChain(
    _In_      PCCERT_CONTEXT    Cert,
    _In_      WKD_REVOCATION_MODE Mode,
    _In_opt_  HCERTSTORE        AdditionalStore,
    _In_      DWORD             ChainFlags,
    _In_opt_  const FILETIME*   VerificationTime,
    _In_opt_  PCSTR             RequiredEkuOid
    )
/*++
Routine Description:
    验证证书链 (标准信任锚 + Authenticode 策略)。
    前置强签名算法校验; RevocationMode 三态映射 chain flags + ignorable errors;
    可选 hAdditionalStore 附加签发候选; 可选 RequiredEkuOid; 最终 Authenticode 策略验证。
    对齐 SS Certificate::VerifyChain L1866-1990。

Arguments:
    Cert             - 证书上下文。
    Mode             - 吊销模式 (WkdRevocation_OfflineAllowed 默认推荐)。
    AdditionalStore  - 附加证书存储 (链构建额外签发候选, 非信任锚; 可为 NULL)。
    ChainFlags       - 链构建 flags, 与 Mode 派生位 OR。
    VerificationTime - 验证时间点 (NULL=当前时间)。
    RequiredEkuOid   - 要求的 EKU OID (可为 NULL)。

Return Value:
    TRUE=链有效, FALSE=链验证失败。
--*/
{
    DWORD effectiveFlags;
    DWORD ignorableErrors;
    DWORD effectiveTrustStatus;
    CERT_CHAIN_PARA chainPara;
    CERT_ENHKEY_USAGE enhkeyUsage;
    LPSTR szOidArr[1] = { NULL };
    PCCERT_CHAIN_CONTEXT chainCtx = NULL;
    CERT_CHAIN_POLICY_PARA policyPara;
    CERT_CHAIN_POLICY_STATUS policyStatus;
    BOOLEAN ok = FALSE;

    if (!Cert) return FALSE;

    /* 1. 前置强签名算法策略 (对齐 L1879-1887) */
    if (!IocCert_IsStrongSignatureAlgo(Cert, FALSE)) {
        return FALSE;
    }

    /* 2. 组合有效链 flags (对齐 L1891-1893) */
    effectiveFlags = ChainFlags | IocCertpRevocationFlagsFor(Mode);
    ignorableErrors = IocCertpIgnorableTrustErrorsFor(Mode);

    /* 3. 链参数 + 可选 EKU (对齐 L1896-1909) */
    RtlZeroMemory(&chainPara, sizeof(chainPara));
    chainPara.cbSize = sizeof(chainPara);
    if (RequiredEkuOid && RequiredEkuOid[0]) {
        szOidArr[0] = (LPSTR)RequiredEkuOid;
        enhkeyUsage.cUsageIdentifier = 1;
        enhkeyUsage.rgpszUsageIdentifier = szOidArr;
        chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
        chainPara.RequestedUsage.Usage = enhkeyUsage;
    }

    /* 4. 构建链 (对齐 L1911-1924) */
    if (!CertGetCertificateChain(NULL, Cert, (LPFILETIME)VerificationTime,
                                 AdditionalStore, &chainPara, effectiveFlags,
                                 NULL, &chainCtx)) {
        return FALSE;
    }
    if (!chainCtx) return FALSE;

    /* 5. 信任状态 (mask 掉 Mode 容忍位, 对齐 L1932-1960) */
    effectiveTrustStatus = chainCtx->TrustStatus.dwErrorStatus & ~ignorableErrors;
    if (effectiveTrustStatus != CERT_TRUST_NO_ERROR) {
        CertFreeCertificateChain(chainCtx);
        return FALSE;
    }

    /* 6. Authenticode 策略 (对齐 L1962-1980) */
    RtlZeroMemory(&policyPara, sizeof(policyPara));
    policyPara.cbSize = sizeof(policyPara);
    RtlZeroMemory(&policyStatus, sizeof(policyStatus));
    policyStatus.cbSize = sizeof(policyStatus);
    ok = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_AUTHENTICODE,
                                          chainCtx, &policyPara, &policyStatus);
    ok = (ok && policyStatus.dwError == 0);

    CertFreeCertificateChain(chainCtx);
    return ok;
}

/**************************************************/
/*                死代码: 功能面覆盖               */
/*  (static + 4505, 对齐 SS 行号 + 不接入原因)      */
/**************************************************/
#pragma warning(push)
#pragma warning(disable: 4505)

/* 从系统证书存储按 SHA1 指纹加载 (对齐 SS LoadFromStore L519-653)。
 * Current User → Local Machine 回退; 不接入原因: 恶意根证书植入检测的未来
 * 消费点, 当前无调用者。 */
static
BOOLEAN
IocCert_LoadFromStore(
    _In_  PCWSTR          StoreName,
    _In_  PCWSTR          Thumbprint,
    _Out_ PCCERT_CONTEXT* OutCert
    )
{
    WCHAR thumbHex[DEF_MAX_PATH];
    size_t tlen;
    HCERTSTORE hStore = NULL;
    BYTE* thumbBytes = NULL;
    CRYPT_HASH_BLOB hashBlob;
    PCCERT_CONTEXT ctx = NULL;
    size_t i;

    if (!OutCert) return FALSE;
    *OutCert = NULL;
    if (!StoreName || !StoreName[0] || !Thumbprint || !Thumbprint[0]) {
        return FALSE;
    }

    /* 1. 打开 Current User store, 失败回退 Local Machine (对齐 L539-562) */
    hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                           CERT_SYSTEM_STORE_CURRENT_USER, StoreName);
    if (!hStore) {
        hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                               CERT_SYSTEM_STORE_LOCAL_MACHINE, StoreName);
        if (!hStore) return FALSE;
    }

    /* 2. 剥离分隔符 + hex 校验 (对齐 L566-590) */
    wcsncpy_s(thumbHex, RTL_NUMBER_OF(thumbHex), Thumbprint, _TRUNCATE);
    {
        size_t dst = 0;
        for (i = 0; thumbHex[i]; i++) {
            if (thumbHex[i] == L' ' || thumbHex[i] == L':' || thumbHex[i] == L'-') {
                continue;
            }
            thumbHex[dst++] = thumbHex[i];
        }
        thumbHex[dst] = L'\0';
    }
    tlen = wcslen(thumbHex);
    if (tlen == 0 || (tlen % 2) != 0) {
        CertCloseStore(hStore, 0);
        return FALSE;
    }
    for (i = 0; i < tlen; i++) {
        if (!IocCertpIsHexChar(thumbHex[i])) {
            CertCloseStore(hStore, 0);
            return FALSE;
        }
    }

    /* 3. hex → bytes (对齐 L592-607) */
    thumbBytes = (BYTE*)malloc(tlen / 2);
    if (!thumbBytes) {
        CertCloseStore(hStore, 0);
        return FALSE;
    }
    for (i = 0; i < tlen / 2; i++) {
        thumbBytes[i] = (BYTE)((IocCertpHexCharToValue(thumbHex[i * 2]) << 4) |
                                IocCertpHexCharToValue(thumbHex[i * 2 + 1]));
    }

    /* 4. 按 CERT_FIND_HASH 查找 (对齐 L609-628) */
    hashBlob.cbData = (DWORD)(tlen / 2);
    hashBlob.pbData = thumbBytes;
    ctx = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                     0, CERT_FIND_HASH, &hashBlob, NULL);
    if (ctx) {
        *OutCert = CertDuplicateCertificateContext(ctx);
        CertFreeCertificateContext(ctx);
    }

    free(thumbBytes);
    CertCloseStore(hStore, 0);
    return (*OutCert != NULL);
}

/* DER 导出 (对齐 SS Export L766-799)。不接入原因: 导出工具, 无消费方。 */
static
BOOLEAN
IocCert_ExportDER(
    _In_  PCCERT_CONTEXT Cert,
    _Out_writes_bytes_(BufCch) BYTE* Buf,
    _In_  ULONG          BufCch
    )
{
    if (!Cert || !Buf || BufCch == 0) return FALSE;
    if (!Cert->pbCertEncoded || Cert->cbCertEncoded == 0) return FALSE;
    if (Cert->cbCertEncoded > BufCch) return FALSE;
    memcpy(Buf, Cert->pbCertEncoded, Cert->cbCertEncoded);
    return TRUE;
}

/* PEM 导出 (对齐 SS ExportPEM L819-888)。不接入原因: 导出工具, 无消费方。 */
static
BOOLEAN
IocCert_ExportPEM(
    _In_  PCCERT_CONTEXT Cert,
    _Out_writes_(OutCch) PCHAR Out,
    _In_  ULONG          OutCch
    )
{
    DWORD charsNeeded = 0;
    BOOLEAN ok = FALSE;

    if (!Cert || !Out || OutCch == 0) return FALSE;
    if (!Cert->pbCertEncoded || Cert->cbCertEncoded == 0) return FALSE;

    /* 1. 查询大小 (对齐 L836-845) */
    if (!CryptBinaryToStringA(Cert->pbCertEncoded, Cert->cbCertEncoded,
                              CRYPT_STRING_BASE64HEADER, NULL, &charsNeeded)) {
        return FALSE;
    }
    if (charsNeeded == 0) return FALSE;

    /* 2. 转换 (对齐 L863-871) */
    if (charsNeeded <= OutCch) {
        if (CryptBinaryToStringA(Cert->pbCertEncoded, Cert->cbCertEncoded,
                                 CRYPT_STRING_BASE64HEADER, Out, &charsNeeded)) {
            ok = TRUE;
        }
    }
    if (ok) {
        /* 3. 去 NUL 终止符 (对齐 L874-879) */
        if (charsNeeded > 0 && Out[charsNeeded - 1] == '\0') {
            Out[charsNeeded - 1] = '\0';
        }
    }
    return ok;
}

/* SAN 提取 (对齐 SS GetSubjectAltNames L1204-1406)。
 * 不接入原因: 无消费方; DNS/IP/URL 分类保留 SS 三路语义。 */
static
BOOLEAN
IocCert_GetSubjectAltNames(
    _In_  PCCERT_CONTEXT Cert,
    _Out_writes_(MaxEntries) PWKD_CERT_SAN SanArray,
    _In_  ULONG          MaxEntries,
    _Out_ PULONG         pCount
    )
{
    PCERT_EXTENSION ext;
    DWORD cbDecoded = 0;
    BYTE* buf = NULL;
    PCERT_ALT_NAME_INFO names;
    ULONG count = 0;
    DWORD i;

    if (!Cert || !SanArray || MaxEntries == 0 || !pCount) return FALSE;
    *pCount = 0;

    if (!Cert->pCertInfo) return FALSE;

    /* 1. 定位 SAN 扩展 (对齐 L1225-1234) */
    ext = CertFindExtension(szOID_SUBJECT_ALT_NAME2, Cert->pCertInfo->cExtension,
                            Cert->pCertInfo->rgExtension);
    if (!ext) return TRUE;   /* 无 SAN 扩展非错误 */
    if (!ext->Value.pbData || ext->Value.cbData == 0) return TRUE;

    /* 2. 查询解码大小 (对齐 L1242-1259) */
    if (!CryptDecodeObject(X509_ASN_ENCODING, X509_ALTERNATE_NAME,
                           ext->Value.pbData, ext->Value.cbData, 0, NULL, &cbDecoded)) {
        return FALSE;
    }
    if (cbDecoded == 0 || cbDecoded > WKD_CERT_MAX_DECODED) return FALSE;

    /* 3. 分配 + 解码 (对齐 L1261-1288) */
    buf = (BYTE*)malloc(cbDecoded);
    if (!buf) return FALSE;
    if (!CryptDecodeObject(X509_ASN_ENCODING, X509_ALTERNATE_NAME,
                           ext->Value.pbData, ext->Value.cbData, 0, buf, &cbDecoded)) {
        free(buf);
        return FALSE;
    }
    names = (PCERT_ALT_NAME_INFO)buf;

    /* 4. 条目数 sanity (对齐 L1290-1295) */
    if (names->cAltEntry > WKD_CERT_MAX_SAN_ENTRIES) {
        free(buf);
        return FALSE;
    }

    /* 5. 逐条分类 (对齐 L1307-1396) */
    for (i = 0; i < names->cAltEntry && count < MaxEntries; i++) {
        const CERT_ALT_NAME_ENTRY* entry;
        if (!names->rgAltEntry) break;
        entry = &names->rgAltEntry[i];

        switch (entry->dwAltNameChoice) {
        case CERT_ALT_NAME_DNS_NAME:
            if (entry->pwszDNSName && entry->pwszDNSName[0]) {
                size_t len = wcsnlen(entry->pwszDNSName, 256);
                if (len > 0 && len < 256) {
                    SanArray[count].Type = WkdSan_DnsName;
                    wcsncpy_s(SanArray[count].Value, RTL_NUMBER_OF(SanArray[count].Value),
                              entry->pwszDNSName, _TRUNCATE);
                    count++;
                }
            }
            break;
        case CERT_ALT_NAME_URL:
            if (entry->pwszURL && entry->pwszURL[0]) {
                size_t len = wcsnlen(entry->pwszURL, 2048);
                if (len > 0 && len < 2048) {
                    SanArray[count].Type = WkdSan_Url;
                    wcsncpy_s(SanArray[count].Value, RTL_NUMBER_OF(SanArray[count].Value),
                              entry->pwszURL, _TRUNCATE);
                    count++;
                }
            }
            break;
        case CERT_ALT_NAME_IP_ADDRESS:
            if (entry->IPAddress.pbData && entry->IPAddress.cbData == 4) {
                SanArray[count].Type = WkdSan_IpAddress;
                _snwprintf_s(SanArray[count].Value, RTL_NUMBER_OF(SanArray[count].Value),
                             _TRUNCATE, L"%u.%u.%u.%u",
                             (unsigned)entry->IPAddress.pbData[0],
                             (unsigned)entry->IPAddress.pbData[1],
                             (unsigned)entry->IPAddress.pbData[2],
                             (unsigned)entry->IPAddress.pbData[3]);
                count++;
            } else if (entry->IPAddress.pbData && entry->IPAddress.cbData == 16) {
                SanArray[count].Type = WkdSan_IpAddress;
                _snwprintf_s(SanArray[count].Value, RTL_NUMBER_OF(SanArray[count].Value),
                             _TRUNCATE,
                             L"%02X%02X:%02X%02X:%02X%02X:%02X%02X:"
                             L"%02X%02X:%02X%02X:%02X%02X:%02X%02X",
                             (unsigned)entry->IPAddress.pbData[0],
                             (unsigned)entry->IPAddress.pbData[1],
                             (unsigned)entry->IPAddress.pbData[2],
                             (unsigned)entry->IPAddress.pbData[3],
                             (unsigned)entry->IPAddress.pbData[4],
                             (unsigned)entry->IPAddress.pbData[5],
                             (unsigned)entry->IPAddress.pbData[6],
                             (unsigned)entry->IPAddress.pbData[7],
                             (unsigned)entry->IPAddress.pbData[8],
                             (unsigned)entry->IPAddress.pbData[9],
                             (unsigned)entry->IPAddress.pbData[10],
                             (unsigned)entry->IPAddress.pbData[11],
                             (unsigned)entry->IPAddress.pbData[12],
                             (unsigned)entry->IPAddress.pbData[13],
                             (unsigned)entry->IPAddress.pbData[14],
                             (unsigned)entry->IPAddress.pbData[15]);
                count++;
            }
            break;
        case CERT_ALT_NAME_RFC822_NAME:
            if (entry->pwszRfc822Name && entry->pwszRfc822Name[0]) {
                size_t len = wcsnlen(entry->pwszRfc822Name, 256);
                if (len > 0 && len < 256) {
                    SanArray[count].Type = WkdSan_Email;
                    wcsncpy_s(SanArray[count].Value, RTL_NUMBER_OF(SanArray[count].Value),
                              entry->pwszRfc822Name, _TRUNCATE);
                    count++;
                }
            }
            break;
        case CERT_ALT_NAME_DIRECTORY_NAME:
            /* directoryName 为 X509_NAME 编码, 转显示串 (SS L1378-1383) */
            if (entry->DirectoryName.pbData && entry->DirectoryName.cbData > 0) {
                DWORD nlen = CertNameToStrW(X509_ASN_ENCODING, &entry->DirectoryName,
                                            CERT_X500_NAME_STR | CERT_NAME_STR_SEMICOLON_FLAG,
                                            SanArray[count].Value,
                                            (DWORD)RTL_NUMBER_OF(SanArray[count].Value));
                if (nlen > 1) {
                    SanArray[count].Type = WkdSan_DirectoryName;
                    count++;
                }
            }
            break;
        default:
            break;   /* 其余类型跳过 */
        }
    }

    free(buf);
    *pCount = count;
    return TRUE;
}

/* 裸数据验签 (对齐 SS VerifySignature L1676-1851)。
 * CryptImportPublicKeyInfoEx2 导公钥 + BCrypt SHA256 + RSA PKCS1/ECDSA 分派。
 * 不接入原因: 文件签名由 WinVerifyTrust 整体覆盖, 无裸数据验签消费方。
 * 预留: SS UpdateVerifier 包级公钥签名 (RSA/ECDSA, pinned 配置公钥, 非 Authenticode
 *   主判) 复用本函数验签核心 — wkd 无 ProgramUpdater 更新链, 死代码待更新链接线。 */
static
BOOLEAN
IocCert_VerifySignature(
    _In_ PCCERT_CONTEXT Cert,
    _In_ const BYTE*    Data,
    _In_ SIZE_T         DataLen,
    _In_ const BYTE*    Signature,
    _In_ SIZE_T         SignatureLen
    )
{
    BCRYPT_KEY_HANDLE hPubKey = NULL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    BYTE hash[32];
    DWORD cbHash = sizeof(hash);
    DWORD cbResult = 0;
    LPCSTR keyOid;
    BOOLEAN isRsa;
    BOOLEAN ok = FALSE;

    if (!Cert || !Cert->pCertInfo) return FALSE;
    if (!Data || DataLen == 0) return FALSE;
    if (!Signature || SignatureLen == 0) return FALSE;
    if (DataLen > WKD_CERT_MAX_FILE_SIZE || SignatureLen > WKD_CERT_MAX_CERT_SIZE) {
        return FALSE;
    }

    /* 1. 导入公钥 (对齐 L1704-1712) */
    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
                                     &Cert->pCertInfo->SubjectPublicKeyInfo,
                                     0, NULL, &hPubKey)) {
        return FALSE;
    }

    /* 2. 打开 SHA256 provider (对齐 L1722-1738) */
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status) || !hAlg) {
        BCryptDestroyKey(hPubKey);
        return FALSE;
    }

    /* 3. 计算哈希 (对齐 L1767-1798) */
    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status) || !hHash) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        BCryptDestroyKey(hPubKey);
        return FALSE;
    }
    status = BCryptHashData(hHash, (PUCHAR)Data, (ULONG)DataLen, 0);
    if (BCRYPT_SUCCESS(status)) {
        status = BCryptFinishHash(hHash, hash, cbHash, 0);
    }
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hPubKey);
        return FALSE;
    }

    /* 4. 密钥算法判定 RSA vs ECDSA (对齐 L1800-1806) */
    keyOid = Cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    isRsa = (keyOid && strcmp(keyOid, szOID_RSA_RSA) == 0);

    /* 5. 验签 (对齐 L1809-1840) */
    if (isRsa) {
        BCRYPT_PKCS1_PADDING_INFO padInfo;
        padInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        status = BCryptVerifySignature(hPubKey, &padInfo, hash, cbHash,
                                       (PUCHAR)Signature, (ULONG)SignatureLen,
                                       BCRYPT_PAD_PKCS1);
    } else {
        status = BCryptVerifySignature(hPubKey, NULL, hash, cbHash,
                                       (PUCHAR)Signature, (ULONG)SignatureLen, 0);
    }

    ok = BCRYPT_SUCCESS(status);
    BCryptDestroyKey(hPubKey);
    UNREFERENCED_PARAMETER(cbResult);
    return ok;
}

/* 指定时间点链验证 (对齐 SS VerifyChainAtTime L2004-2018)。
 * 包装 IocCert_VerifyChain 时间参数; 不接入原因: 死代码包装对齐 API 面。 */
static
BOOLEAN
IocCert_VerifyChainAtTime(
    _In_ PCCERT_CONTEXT     Cert,
    _In_ const FILETIME*    VerifyTime,
    _In_ WKD_REVOCATION_MODE Mode,
    _In_ DWORD              ChainFlags,
    _In_opt_ PCSTR          RequiredEkuOid
    )
{
    /* CertGetCertificateChain 不修改 verificationTime, const_cast 语义由
     * IocCert_VerifyChain 内部 (LPFILETIME) 转换承担; 无附加存储传 NULL */
    return IocCert_VerifyChain(Cert, Mode, NULL, ChainFlags, VerifyTime, RequiredEkuOid);
}

/* 自定义信任锚链验证 (对齐 SS VerifyChainWithStore L2034-2180)。
 * CertCreateCertificateChainEngine + hExclusiveRoot 绑定信任根; intermediates
 * 走 hAdditionalStore 作签发候选。不接入原因: 内部 PKI 验证未来消费点。 */
static
BOOLEAN
IocCert_VerifyChainWithStore(
    _In_ PCCERT_CONTEXT     Cert,
    _In_ HCERTSTORE         RootStore,
    _In_ HCERTSTORE         IntermediateStore,
    _In_ WKD_REVOCATION_MODE Mode,
    _In_ DWORD              ChainFlags,
    _In_opt_ const FILETIME* VerificationTime,
    _In_opt_ PCSTR          RequiredEkuOid
    )
{
    CERT_CHAIN_ENGINE_CONFIG config;
    HCERTCHAINENGINE hEngine = NULL;
    CERT_CHAIN_PARA chainPara;
    CERT_ENHKEY_USAGE enhkeyUsage;
    LPSTR szOidArr[1] = { NULL };
    PCCERT_CHAIN_CONTEXT chainCtx = NULL;
    DWORD effectiveFlags;
    DWORD ignorableErrors;
    DWORD effectiveTrustStatus;
    CERT_CHAIN_POLICY_PARA policyPara;
    CERT_CHAIN_POLICY_STATUS policyStatus;
    BOOLEAN ok = FALSE;

    if (!Cert) return FALSE;
    if (!RootStore && !IntermediateStore) return FALSE;

    /* 1. 前置强签名算法 (对齐 L2052-2060) */
    if (!IocCert_IsStrongSignatureAlgo(Cert, FALSE)) return FALSE;

    effectiveFlags = ChainFlags | IocCertpRevocationFlagsFor(Mode);
    ignorableErrors = IocCertpIgnorableTrustErrorsFor(Mode);

    /* 2. 自定义链引擎 (对齐 L2071-2086) */
    RtlZeroMemory(&config, sizeof(config));
    config.cbSize = sizeof(config);
    config.hExclusiveRoot = RootStore;
    if (CertCreateCertificateChainEngine(&config, &hEngine) != TRUE) return FALSE;
    if (!hEngine) return FALSE;

    /* 3. 链参数 + EKU (对齐 L2088-2101) */
    RtlZeroMemory(&chainPara, sizeof(chainPara));
    chainPara.cbSize = sizeof(chainPara);
    if (RequiredEkuOid && RequiredEkuOid[0]) {
        szOidArr[0] = (LPSTR)RequiredEkuOid;
        enhkeyUsage.cUsageIdentifier = 1;
        enhkeyUsage.rgpszUsageIdentifier = szOidArr;
        chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
        chainPara.RequestedUsage.Usage = enhkeyUsage;
    }

    /* 4. 构建链 (对齐 L2104-2119) */
    if (CertGetCertificateChain(hEngine, Cert, (LPFILETIME)VerificationTime,
                                IntermediateStore, &chainPara, effectiveFlags,
                                NULL, &chainCtx) != TRUE || !chainCtx) {
        CertFreeCertificateChainEngine(hEngine);
        return FALSE;
    }

    /* 5. 信任状态 (对齐 L2127-2149) */
    effectiveTrustStatus = chainCtx->TrustStatus.dwErrorStatus & ~ignorableErrors;
    if (effectiveTrustStatus != CERT_TRUST_NO_ERROR) {
        CertFreeCertificateChain(chainCtx);
        CertFreeCertificateChainEngine(hEngine);
        return FALSE;
    }

    /* 6. Authenticode 策略 (对齐 L2151-2168) */
    RtlZeroMemory(&policyPara, sizeof(policyPara));
    policyPara.cbSize = sizeof(policyPara);
    RtlZeroMemory(&policyStatus, sizeof(policyStatus));
    policyStatus.cbSize = sizeof(policyStatus);
    ok = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_AUTHENTICODE,
                                          chainCtx, &policyPara, &policyStatus);
    ok = (ok && policyStatus.dwError == 0);

    CertFreeCertificateChain(chainCtx);
    CertFreeCertificateChainEngine(hEngine);
    return ok;
}

/* 指定 CA 验证 (对齐 SS VerifyAgainstCA L2321-2435)。
 * 内存 store + 自定义 engine, CA 作独占根。不接入原因: 无消费方。 */
static
BOOLEAN
IocCert_VerifyAgainstCA(
    _In_ PCCERT_CONTEXT Cert,
    _In_ PCCERT_CONTEXT CaCert
    )
{
    HCERTSTORE hStore = NULL;
    CERT_CHAIN_ENGINE_CONFIG config;
    HCERTCHAINENGINE hEngine = NULL;
    CERT_CHAIN_PARA chainPara;
    PCCERT_CHAIN_CONTEXT chainCtx = NULL;
    BOOLEAN ok = FALSE;

    if (!Cert || !CaCert) return FALSE;

    /* 1. 内存 store + 添加 CA (对齐 L2334-2361) */
    hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
                           CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!hStore) return FALSE;
    if (!CertAddCertificateContextToStore(hStore, CaCert, CERT_STORE_ADD_ALWAYS, NULL)) {
        CertCloseStore(hStore, 0);
        return FALSE;
    }

    /* 2. 自定义引擎独占根 (对齐 L2363-2378) */
    RtlZeroMemory(&config, sizeof(config));
    config.cbSize = sizeof(config);
    config.hExclusiveRoot = hStore;
    if (CertCreateCertificateChainEngine(&config, &hEngine) != TRUE) {
        CertCloseStore(hStore, 0);
        return FALSE;
    }
    if (!hEngine) {
        CertCloseStore(hStore, 0);
        return FALSE;
    }

    /* 3. 构建链 (无吊销, 对齐 L2380-2399) */
    RtlZeroMemory(&chainPara, sizeof(chainPara));
    chainPara.cbSize = sizeof(chainPara);
    if (CertGetCertificateChain(hEngine, Cert, NULL, NULL, &chainPara, 0,
                                NULL, &chainCtx) != TRUE || !chainCtx) {
        CertFreeCertificateChainEngine(hEngine);
        CertCloseStore(hStore, 0);
        return FALSE;
    }

    /* 4. 信任状态 (对齐 L2407-2427) */
    ok = (chainCtx->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR);

    CertFreeCertificateChain(chainCtx);
    CertFreeCertificateChainEngine(hEngine);
    CertCloseStore(hStore, 0);
    return ok;
}

/* 独立吊销查询 (对齐 SS GetRevocationStatus L2450-2572)。
 * CertVerifyRevocation + CRL reason 6 细分。2026-09-02 由 static 升级导出:
 * SignatureVerifier Revoked 分支接线消费 (吊销原因细分, CertificateValidator
 * 增量迁移)。注意: CertVerifyRevocation 在网络可达时可能访问吊销分发点,
 * 调用方须处于吊销检查已启语境 (WKD cache-only 语义由链阶段判定把关)。 */
BOOLEAN
IocCert_GetRevocationStatus(
    _In_  PCCERT_CONTEXT Cert,
    _Out_ PBOOLEAN       IsRevoked,
    _Out_writes_(ReasonCch) PWCHAR Reason,
    _In_  ULONG          ReasonCch
    )
{
    CERT_REVOCATION_PARA revPara;
    CERT_REVOCATION_STATUS revStatus;
    void* certPtrs[1];
    BOOL ok;

    if (!Cert || !IsRevoked || !Reason || ReasonCch == 0) return FALSE;
    *IsRevoked = FALSE;
    Reason[0] = L'\0';

    /* 1. 参数初始化 (对齐 L2462-2472) */
    RtlZeroMemory(&revPara, sizeof(revPara));
    revPara.cbSize = sizeof(revPara);
    RtlZeroMemory(&revStatus, sizeof(revStatus));
    revStatus.cbSize = sizeof(revStatus);
    certPtrs[0] = (void*)Cert;

    /* 2. 执行吊销检查 (对齐 L2475-2483) */
    ok = CertVerifyRevocation(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                              CERT_CONTEXT_REVOCATION_TYPE, 1, certPtrs,
                              CERT_VERIFY_REV_CHAIN_FLAG, &revPara, &revStatus);

    if (ok && revStatus.dwError == ERROR_SUCCESS) {
        _snwprintf_s(Reason, ReasonCch, _TRUNCATE, L"Certificate is not revoked");
        return TRUE;
    }

    /* 3. 状态细分 (对齐 L2495-2565) */
    switch (revStatus.dwError) {
    case CRYPT_E_REVOKED:
        *IsRevoked = TRUE;
        switch (revStatus.dwReason) {
        case CRL_REASON_KEY_COMPROMISE:
            _snwprintf_s(Reason, ReasonCch, _TRUNCATE,
                         L"Certificate has been revoked (Reason: Key Compromise)");
            break;
        case CRL_REASON_CA_COMPROMISE:
            _snwprintf_s(Reason, ReasonCch, _TRUNCATE,
                         L"Certificate has been revoked (Reason: CA Compromise)");
            break;
        case CRL_REASON_AFFILIATION_CHANGED:
            _snwprintf_s(Reason, ReasonCch, _TRUNCATE,
                         L"Certificate has been revoked (Reason: Affiliation Changed)");
            break;
        case CRL_REASON_SUPERSEDED:
            _snwprintf_s(Reason, ReasonCch, _TRUNCATE,
                         L"Certificate has been revoked (Reason: Superseded)");
            break;
        case CRL_REASON_CESSATION_OF_OPERATION:
            _snwprintf_s(Reason, ReasonCch, _TRUNCATE,
                         L"Certificate has been revoked (Reason: Cessation of Operation)");
            break;
        case CRL_REASON_CERTIFICATE_HOLD:
            _snwprintf_s(Reason, ReasonCch, _TRUNCATE,
                         L"Certificate has been revoked (Reason: Certificate Hold)");
            break;
        default:
            _snwprintf_s(Reason, ReasonCch, _TRUNCATE,
                         L"Certificate has been revoked (Reason: 0x%lX)",
                         revStatus.dwReason);
            break;
        }
        return TRUE;

    case CRYPT_E_NO_REVOCATION_CHECK:
        _snwprintf_s(Reason, ReasonCch, _TRUNCATE,
                     L"No revocation information available (no CRL/OCSP endpoint)");
        return TRUE;

    case CRYPT_E_NO_REVOCATION_DLL:
        _snwprintf_s(Reason, ReasonCch, _TRUNCATE, L"No revocation handler available");
        return TRUE;

    case CRYPT_E_NOT_IN_REVOCATION_DATABASE:
        _snwprintf_s(Reason, ReasonCch, _TRUNCATE,
                     L"Certificate not found in revocation database");
        return TRUE;

    case CRYPT_E_REVOCATION_OFFLINE:
        _snwprintf_s(Reason, ReasonCch, _TRUNCATE,
                     L"Revocation server is offline or unreachable");
        return FALSE;

    default:
        _snwprintf_s(Reason, ReasonCch, _TRUNCATE,
                     L"Revocation check failed (error: 0x%08lX)", revStatus.dwError);
        return FALSE;
    }
}

/* RFC3161 时间戳令牌验证 (对齐 SS VerifyTimestampToken L2587-2682)。
 * CryptVerifyTimeStampSignature + ftTime 提取 + 年份 1990-2100 校验。
 * 不接入原因: wkd 死代码仅提取 counterSign 时间, 独立令牌验证无消费方。 */
static
BOOLEAN
IocCert_VerifyTimestampToken(
    _In_  const BYTE* TsToken,
    _In_  SIZE_T      Len,
    _Out_ PFILETIME   OutGenTime
    )
{
    DWORD cbToken;
    PCRYPT_TIMESTAMP_CONTEXT pTsContext = NULL;
    PCCERT_CONTEXT pTsSigner = NULL;
    BOOL ok;
    SYSTEMTIME stCheck;
    BOOLEAN valid = FALSE;

    if (!OutGenTime) return FALSE;
    OutGenTime->dwHighDateTime = 0;
    OutGenTime->dwLowDateTime = 0;

    if (!TsToken) return FALSE;
    if (Len == 0) return FALSE;
    if (Len > WKD_CERT_MAX_TS_TOKEN) return FALSE;
    if (!IocCertpSafeSizeToDword(Len, &cbToken)) return FALSE;

    /* 1. 验证时间戳签名 (跳过原数据哈希匹配, 对齐 L2621-2633) */
    ok = CryptVerifyTimeStampSignature(TsToken, cbToken, NULL, 0, NULL,
                                       &pTsContext, &pTsSigner, NULL);
    if (!ok || !pTsContext) {
        if (pTsSigner) CertFreeCertificateContext(pTsSigner);
        return FALSE;
    }

    /* 2. 提取 genTime (对齐 L2652-2658) */
    if (!pTsContext->pTimeStamp) {
        CryptMemFree(pTsContext);
        if (pTsSigner) CertFreeCertificateContext(pTsSigner);
        return FALSE;
    }
    *OutGenTime = pTsContext->pTimeStamp->ftTime;

    /* 3. 合理性校验 (对齐 L2660-2672) */
    if (FileTimeToSystemTime(OutGenTime, &stCheck) &&
        stCheck.wYear >= 1990 && stCheck.wYear <= 2100) {
        valid = TRUE;
    } else {
        OutGenTime->dwHighDateTime = 0;
        OutGenTime->dwLowDateTime = 0;
    }

    CryptMemFree(pTsContext);
    if (pTsSigner) CertFreeCertificateContext(pTsSigner);
    return valid;
}

/* 公钥提取 (CNG blob) (对齐 SS ExtractPublicKey L2694-2783)。
 * CryptImportPublicKeyInfoEx2 + BCryptExportKey; 不依赖 SS CryptoUtils 直接导出。
 * 不接入原因: 无消费方 (密钥材料提取归密码学能力域)。 */
static
BOOLEAN
IocCert_ExtractPublicKey(
    _In_  PCCERT_CONTEXT Cert,
    _Out_writes_bytes_(BlobCch) BYTE* Blob,
    _In_  ULONG          BlobCch,
    _Out_ PULONG         pBlobLen
    )
{
    BCRYPT_KEY_HANDLE hPubKey = NULL;
    DWORD cbBlob = 0;
    NTSTATUS status;
    BOOLEAN ok = FALSE;

    if (!Cert || !Cert->pCertInfo || !Blob || !pBlobLen) return FALSE;
    *pBlobLen = 0;

    /* 1. 导入公钥 (对齐 L2704-2713) */
    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
                                     &Cert->pCertInfo->SubjectPublicKeyInfo,
                                     0, NULL, &hPubKey)) {
        return FALSE;
    }

    /* 2. 查询 blob 大小 (对齐 L2722-2735) */
    status = BCryptExportKey(hPubKey, NULL, BCRYPT_PUBLIC_KEY_BLOB,
                             NULL, 0, &cbBlob, 0);
    if (!BCRYPT_SUCCESS(status) || cbBlob == 0) {
        BCryptDestroyKey(hPubKey);
        return FALSE;
    }
    if (cbBlob > WKD_CERT_MAX_DECODED || cbBlob > BlobCch) {
        BCryptDestroyKey(hPubKey);
        return FALSE;
    }

    /* 3. 导出 (对齐 L2754-2768) */
    status = BCryptExportKey(hPubKey, NULL, BCRYPT_PUBLIC_KEY_BLOB,
                             Blob, cbBlob, &cbBlob, 0);
    if (BCRYPT_SUCCESS(status)) {
        *pBlobLen = cbBlob;
        ok = TRUE;
    }

    BCryptDestroyKey(hPubKey);
    return ok;
}

#pragma warning(pop)
