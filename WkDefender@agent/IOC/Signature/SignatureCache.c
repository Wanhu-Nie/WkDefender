/**************************************************/
/*  WkDefender IOC — 证书验证结果缓存               */
/*  自 IocScanner.c 独立 (2026-08 重构)              */
/*  SS DigitalSignatureValidator 缓存 L1766-1819 迁移 */
/**************************************************/

#include "SignatureCache.h"

/**************************************************/
/*              缓存结构与状态                       */
/**************************************************/

#define WKD_CERT_CACHE_SIZE 2048

/* 证书+信誉字段快照 (不含 ChainName — 消费点不读链名, 缓存命中后链名为零) */
typedef struct _WKD_CERT_CACHE_ENTRY {
    BOOLEAN  Used;                 /* 槽位有效 */
    ULONG64  KeyHash;              /* 文件路径 DJB2 */
    ULONG64  LastWrite;            /* 文件 LastWriteTime (FILETIME 100ns, TOCTOU 防护) */
    ULONG64  Timestamp;            /* 缓存写入 GetTickCount64 */
    DEF_CERT_STATUS CertStatus;
    BOOLEAN  CertValid;
    BOOLEAN  CertTrusted;
    WCHAR    SignerName[256];
    ULONG    CertScore;
    WCHAR    IssuerName[256];
    CHAR     Thumbprint[64];
    ULONG64  CertValidFrom;
    ULONG64  CertValidTo;
    ULONG    ChainDepth;
    BOOLEAN  IsTrustedStrict;
    BOOLEAN  IsCodeSigningEku;
    CHAR     SignatureAlgo[48];
    BOOLEAN  IsWeakSignature;
    BOOLEAN  IsRevocationChecked;
    ULONG64  SignTime;
    CHAR     CatalogName[260];
    WCHAR    RevokeReason[96];    /* 吊销原因细分 (SS CV 增量迁移 2026-09-02, Revoked 时有效) */
    LONG     SignerReputation;
    ULONG    SignerCategory;
    BOOLEAN  IsEvCert;
    LONG     CertReputationAdjust;
    WKD_FILE_REPUTATION Reputation;
} WKD_CERT_CACHE_ENTRY;

static WKD_CERT_CACHE_ENTRY g_IocCertCache[WKD_CERT_CACHE_SIZE];
static LONG g_IocCertCacheIndex = 0;    /* 轮转写入 (满则覆盖最旧) */

static ULONG64
IocScan_CertCacheHash(
    _In_ PCWSTR Path
    )
{
    ULONG64 h = 5381;
    const WCHAR* p = Path;
    while (*p) {
        h = h * 33 + (ULONG64)*p;
        p++;
    }
    return h;
}

/**************************************************/
/*                查找与写入                       */
/**************************************************/

BOOLEAN
IocScan_CertCacheLookup(
    _In_  PCWSTR          FilePath,
    _Inout_ IOC_SCAN_RESULT* Result
    )
/*++
Routine Description:
    证书验证缓存查找: 按 文件路径 DJB2 哈希 + LastWriteTime (mtime TOCTOU 防护)
    命中 → 重建 Result 证书+信誉字段。对齐 SS 缓存 mtime 校验 L1785-1790。

Arguments:
    FilePath - 文件完整路径。
    Result   - 输出 (证书+信誉字段由缓存快照恢复)。

Return Value:
    TRUE = 缓存命中。
--*/
{
    ULONG64 key;
    ULONG64 lastWrite;
    WIN32_FILE_ATTRIBUTE_DATA fad;
    ULONG i;

    if (!FilePath || !Result) return FALSE;
    if (GetFileAttributesExW(FilePath, GetFileExInfoStandard, &fad) == 0) return FALSE;

    key = IocScan_CertCacheHash(FilePath);
    lastWrite = ((ULONG64)fad.ftLastWriteTime.dwHighDateTime << 32) |
                fad.ftLastWriteTime.dwLowDateTime;

    for (i = 0; i < WKD_CERT_CACHE_SIZE; i++) {
        WKD_CERT_CACHE_ENTRY* e = &g_IocCertCache[i];
        if (!e->Used || e->KeyHash != key) continue;
        if (e->LastWrite != lastWrite) {
            e->Used = FALSE;   /* 文件已变 → 强制失效 */
            return FALSE;
        }
        Result->CertStatus = e->CertStatus;
        Result->CertValid = e->CertValid;
        Result->CertTrusted = e->CertTrusted;
        wcsncpy_s(Result->SignerName, RTL_NUMBER_OF(Result->SignerName),
                  e->SignerName, _TRUNCATE);
        Result->CertScore = e->CertScore;
        wcsncpy_s(Result->IssuerName, RTL_NUMBER_OF(Result->IssuerName),
                  e->IssuerName, _TRUNCATE);
        strncpy_s(Result->Thumbprint, sizeof(Result->Thumbprint),
                  e->Thumbprint, _TRUNCATE);
        Result->CertValidFrom = e->CertValidFrom;
        Result->CertValidTo = e->CertValidTo;
        Result->ChainDepth = e->ChainDepth;
        Result->IsTrustedStrict = e->IsTrustedStrict;
        Result->IsCodeSigningEku = e->IsCodeSigningEku;
        strncpy_s(Result->SignatureAlgorithm, sizeof(Result->SignatureAlgorithm),
                  e->SignatureAlgo, _TRUNCATE);
        Result->IsWeakSignature = e->IsWeakSignature;
        Result->IsRevocationChecked = e->IsRevocationChecked;
        Result->SignTime = e->SignTime;
        strncpy_s(Result->CatalogName, sizeof(Result->CatalogName),
                  e->CatalogName, _TRUNCATE);
        wcsncpy_s(Result->RevokeReason, RTL_NUMBER_OF(Result->RevokeReason),
                  e->RevokeReason, _TRUNCATE);
        Result->SignerReputation = e->SignerReputation;
        Result->SignerCategory = e->SignerCategory;
        Result->IsEvCert = e->IsEvCert;
        Result->CertReputationAdjust = e->CertReputationAdjust;
        Result->Reputation = e->Reputation;
        return TRUE;
    }
    return FALSE;
}

VOID
IocScan_CertCacheStore(
    _In_ PCWSTR          FilePath,
    _In_ PIOC_SCAN_RESULT Result
    )
/*++
Routine Description:
    证书验证缓存写入: 轮转槽位, 仅当证书已判定 (CertStatus != Unknown)。
    缓存证书+信誉字段 (不含 ChainName — 消费点不读链名)。

Arguments:
    FilePath - 文件完整路径。
    Result   - 扫描结果 (证书+信誉字段)。

Return Value:
    无。
--*/
{
    ULONG idx;
    WKD_CERT_CACHE_ENTRY* e;
    WIN32_FILE_ATTRIBUTE_DATA fad;

    if (!FilePath || !Result) return;
    if (Result->CertStatus == DefCertStatus_Unknown) return;
    if (GetFileAttributesExW(FilePath, GetFileExInfoStandard, &fad) == 0) return;

    idx = (ULONG)((ULONG)InterlockedIncrement(&g_IocCertCacheIndex) % WKD_CERT_CACHE_SIZE);
    e = &g_IocCertCache[idx];
    RtlZeroMemory(e, sizeof(*e));
    e->KeyHash = IocScan_CertCacheHash(FilePath);
    e->LastWrite = ((ULONG64)fad.ftLastWriteTime.dwHighDateTime << 32) |
                   fad.ftLastWriteTime.dwLowDateTime;
    e->Timestamp = GetTickCount64();
    e->CertStatus = Result->CertStatus;
    e->CertValid = Result->CertValid;
    e->CertTrusted = Result->CertTrusted;
    wcsncpy_s(e->SignerName, RTL_NUMBER_OF(e->SignerName),
              Result->SignerName, _TRUNCATE);
    e->CertScore = Result->CertScore;
    wcsncpy_s(e->IssuerName, RTL_NUMBER_OF(e->IssuerName),
              Result->IssuerName, _TRUNCATE);
    strncpy_s(e->Thumbprint, sizeof(e->Thumbprint), Result->Thumbprint, _TRUNCATE);
    e->CertValidFrom = Result->CertValidFrom;
    e->CertValidTo = Result->CertValidTo;
    e->ChainDepth = Result->ChainDepth;
    e->IsTrustedStrict = Result->IsTrustedStrict;
    e->IsCodeSigningEku = Result->IsCodeSigningEku;
    strncpy_s(e->SignatureAlgo, sizeof(e->SignatureAlgo),
              Result->SignatureAlgorithm, _TRUNCATE);
    e->IsWeakSignature = Result->IsWeakSignature;
    e->IsRevocationChecked = Result->IsRevocationChecked;
    e->SignTime = Result->SignTime;
    strncpy_s(e->CatalogName, sizeof(e->CatalogName), Result->CatalogName, _TRUNCATE);
    wcsncpy_s(e->RevokeReason, RTL_NUMBER_OF(e->RevokeReason),
              Result->RevokeReason, _TRUNCATE);
    e->SignerReputation = Result->SignerReputation;
    e->SignerCategory = Result->SignerCategory;
    e->IsEvCert = Result->IsEvCert;
    e->CertReputationAdjust = Result->CertReputationAdjust;
    e->Reputation = Result->Reputation;
    e->Used = TRUE;   /* 最后置位: 填充完成前并发 Lookup 跳过此槽 */
}
