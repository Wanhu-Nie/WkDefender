/**************************************************/
/*  WkDefender IOC — X.509 证书工具                */
/*  迁移自 ShadowStrike CertUtils.cpp (2832 行)     */
/*  按功能融合重实现, 非源码复制                    */
/*  裸证书能力域, 与 IocScanner.c Authenticode 流水线解耦 */
/**************************************************/

#pragma once

#include "../DefendTypes.h"
#include <wincrypt.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

/**************************************************/
/*                  常量定义                        */
/**************************************************/

/* 证书文件大小上限 (10 MB) — 防 DoS via huge files (对齐 SS kMaxFileSize L145) */
#define WKD_CERT_MAX_FILE_SIZE          (10ULL * 1024 * 1024)

/* 裸证书大小上限 (1 MB) — DER/PEM 合理限制 (对齐 SS kMaxCertificateSize L148) */
#define WKD_CERT_MAX_CERT_SIZE          (1ULL * 1024 * 1024)

/* CryptDecodeObject 输出上限 (64 KB) (对齐 SS kMaxDecodedStructureSize L151) */
#define WKD_CERT_MAX_DECODED             (64 * 1024)

/* SAN 条目数上限 — 防 DoS (对齐 SS kMaxSanEntries L1291) */
#define WKD_CERT_MAX_SAN_ENTRIES         10000

/* RFC3161 时间戳令牌大小上限 (64 KB) (对齐 SS kMaxTimestampTokenSize L2605) */
#define WKD_CERT_MAX_TS_TOKEN            (64 * 1024)

/**************************************************/
/*                  结构体声明                      */
/**************************************************/

/* 吊销检查模式 (对齐 SS RevocationMode L118-122)。
 * OfflineAllowed 默认: 同链覆盖但累计超时容忍慢/离线 responder,
 * offline/unknown 吊销信任错误不致命 (对齐 wkd #60 cache-only 语义)。 */
typedef enum _WKD_REVOCATION_MODE {
    WkdRevocation_OnlineOnly = 0,   /* 全链含根吊销在线检查 (最严格) */
    WkdRevocation_OfflineAllowed,   /* 离线失败容忍, 默认 */
    WkdRevocation_Disabled          /* 跳过吊销检查 */
} WKD_REVOCATION_MODE, *PWKD_REVOCATION_MODE;

/* 综合证书信息 (对齐 SS CertificateInfo L134-169) */
typedef struct _WKD_CERT_INFO {
    WCHAR   Subject[256];           /* 主题 CN (SIMPLE_DISPLAY_TYPE) */
    WCHAR   Issuer[256];            /* 颁发者 CN */
    WCHAR   SerialNumber[128];      /* 序列号 (hex 大端 MSB-first) */
    WCHAR   ThumbprintSha1[41];     /* SHA1 指纹 (hex 小写) */
    WCHAR   ThumbprintSha256[65];   /* SHA256 指纹 (hex 小写) */
    ULONG64 NotBefore;              /* 有效起始 Unix 秒 */
    ULONG64 NotAfter;               /* 有效截止 Unix 秒 */
    BOOLEAN IsCA;                   /* BasicConstraints fCA */
    BOOLEAN IsExpired;              /* 当前时间 > NotAfter */
    BOOLEAN IsRevoked;              /* 吊销查询确认 */
    BOOLEAN IsSelfSigned;           /* Subject == Issuer (blob 直比) */
    LONG    PathLenConstraint;      /* BasicConstraints pathLen (-1=无) */
    WCHAR   SignatureAlgorithm[64]; /* 签名算法友好名 "RSA-SHA256" */
} WKD_CERT_INFO, *PWKD_CERT_INFO;

/* SAN 条目类型 (对齐 SS GetSubjectAltNames 多类输出;
 * 2026-08-09 补 email/DIRECTORY_NAME, 对齐 SS L1378-1383) */
typedef enum _WKD_SAN_TYPE {
    WkdSan_DnsName = 0,             /* CERT_ALT_NAME_DNS_NAME */
    WkdSan_IpAddress,               /* CERT_ALT_NAME_IP_ADDRESS (4/16 字节) */
    WkdSan_Url,                     /* CERT_ALT_NAME_URL */
    WkdSan_Email,                   /* CERT_ALT_NAME_RFC822_NAME */
    WkdSan_DirectoryName            /* CERT_ALT_NAME_DIRECTORY_NAME (X509_NAME → 显示串) */
} WKD_SAN_TYPE, *PWKD_SAN_TYPE;

/* SAN 条目 (定长共用缓冲, Value 长度上限对齐 SS URL 上限 2048 L1330) */
typedef struct _WKD_CERT_SAN {
    WKD_SAN_TYPE Type;
    WCHAR        Value[2048];
} WKD_CERT_SAN, *PWKD_CERT_SAN;

/**************************************************/
/*                  函数声明                       */
/**************************************************/

/*++
Routine Description:
    从文件加载证书 (DER / PEM / PKCS#7 容器自动识别)。
    对齐 SS Certificate::LoadFromFile L286-382。

Arguments:
    FilePath - 证书文件路径。
    OutCert  - 输出证书上下文 (调用方须 CertFreeCertificateContext)。

Return Value:
    TRUE=成功, FALSE=失败。
--*/
BOOLEAN
IocCert_LoadFromFile(
    _In_  PCWSTR        FilePath,
    _Out_ PCCERT_CONTEXT* OutCert
    );

/*++
Routine Description:
    从内存加载证书 (DER / PEM 自动检测, PEM 头查找对齐 SS L422-428)。
    对齐 SS Certificate::LoadFromMemory L397-507。

Arguments:
    Data    - 证书数据。
    Len     - 数据长度 (上限 WKD_CERT_MAX_CERT_SIZE)。
    OutCert - 输出证书上下文 (调用方须 CertFreeCertificateContext)。

Return Value:
    TRUE=成功, FALSE=失败。
--*/
BOOLEAN
IocCert_LoadFromMemory(
    _In_  const BYTE*   Data,
    _In_  SIZE_T        Len,
    _Out_ PCCERT_CONTEXT* OutCert
    );

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
BOOLEAN
IocCert_LoadFromPEM(
    _In_  PCSTR         Pem,
    _Out_ PCCERT_CONTEXT* OutCert
    );

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
BOOLEAN
IocCert_GetThumbprint(
    _In_      PCCERT_CONTEXT Cert,
    _In_      BOOLEAN        Sha256,
    _Out_writes_(HexCch) PCHAR Hex,
    _In_      ULONG          HexCch
    );

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
BOOLEAN
IocCert_GetInfo(
    _In_  PCCERT_CONTEXT Cert,
    _Out_ PWKD_CERT_INFO Info
    );

/*++
Routine Description:
    判断证书是否自签名 (Subject == Issuer, blob 直比)。
    对齐 SS Certificate::IsSelfSigned L1417-1444。

Arguments:
    Cert - 证书上下文。

Return Value:
    TRUE=自签名, FALSE=非自签名或 Cert 无效。
--*/
BOOLEAN
IocCert_IsSelfSigned(
    _In_ PCCERT_CONTEXT Cert
    );

/*++
Routine Description:
    获取 Basic Constraints pathLen 约束。
    对齐 SS Certificate::GetBasicConstraintsPathLen L1454-1518。

Arguments:
    Cert - 证书上下文。

Return Value:
    pathLen 约束值, -1=无约束或解码失败。
--*/
LONG
IocCert_GetBasicConstraintsPathLen(
    _In_ PCCERT_CONTEXT Cert
    );

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
BOOLEAN
IocCert_GetSignatureAlgorithm(
    _In_      PCCERT_CONTEXT Cert,
    _Out_writes_(AlgCch) PWCHAR Alg,
    _In_      ULONG          AlgCch
    );

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
BOOLEAN
IocCert_IsStrongSignatureAlgo(
    _In_ PCCERT_CONTEXT Cert,
    _In_ BOOLEAN        AllowSha1
    );

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
BOOLEAN
IocCert_HasEKU(
    _In_ PCCERT_CONTEXT Cert,
    _In_ PCSTR          Oid
    );

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
BOOLEAN
IocCert_HasKeyUsage(
    _In_ PCCERT_CONTEXT Cert,
    _In_ DWORD          Flags
    );

/*++
Routine Description:
    验证证书链 (标准信任锚 + Authenticode 策略)。
    前置强签名算法校验 (MD2/MD5/未知 → 拒绝); RevocationMode 三态映射 chain flags
    + ignorable errors (OfflineAllowed 容忍 offline/unknown); 可选 RequiredEkuOid
    RequestedUsage; 可选 hAdditionalStore 附加签发候选存储; 最终
    CertVerifyCertificateChainPolicy(AUTHENTICODE)。
    对齐 SS Certificate::VerifyChain L1866-1990。

Arguments:
    Cert             - 证书上下文。
    Mode             - 吊销模式 (WkdRevocation_OfflineAllowed 默认推荐)。
    AdditionalStore  - 附加证书存储 (链构建额外签发候选, 非信任锚; 可为 NULL)。
    ChainFlags       - 链构建 flags (如 CERT_CHAIN_REVOCATION_CHECK_*), 与 Mode 派生位 OR。
    VerificationTime - 验证时间点 (NULL=当前时间)。
    RequiredEkuOid   - 要求的 EKU OID (可为 NULL)。

Return Value:
    TRUE=链有效, FALSE=链验证失败。
--*/
BOOLEAN
IocCert_VerifyChain(
    _In_      PCCERT_CONTEXT    Cert,
    _In_      WKD_REVOCATION_MODE Mode,
    _In_opt_  HCERTSTORE        AdditionalStore,
    _In_      DWORD             ChainFlags,
    _In_opt_  const FILETIME*   VerificationTime,
    _In_opt_  PCSTR             RequiredEkuOid
    );
