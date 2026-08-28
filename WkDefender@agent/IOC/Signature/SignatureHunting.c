/**************************************************/
/*  WkDefender IOC — 签名 APT 狩猎引擎              */
/*  SS DigitalSignatureValidator 迁移 (2026-08-09)   */
/*  按功能融合重实现, 非复制                          */
/*  AnalyzeSignature L1998-2268 9 类 anomaly +       */
/*  被盗证书库 (AddStolenCertificate/LoadStolenCertDatabase) */
/**************************************************/

#include "SignatureHunting.h"
#include "SignatureDetails.h"    /* IocScan_CertHasTimestamp (未来时间戳) */

#include <windows.h>
#include <wincrypt.h>
#include <softpub.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "crypt32.lib")

/* 驱动 CI 签名状态 (对齐 WkDefenderHeader.h IMG_SIGNATURE_* 值, 避免引入协议头) */
#ifndef IMG_SIGNATURE_UNSIGNED
#define IMG_SIGNATURE_UNSIGNED  2
#endif

/**************************************************/
/*           门控开关 (默认关闭, 零行为变化)         */
/**************************************************/

/* 签名 APT 狩猎门控 (SS DSV AnalyzeSignature 迁移, 死代码开关默认关闭)。
 * 置 TRUE 后统一证书验证入口尾部追加 9 类签名异常分析 (IoaSigHunt_AnalyzeSignature),
 * 输出 RiskScore (0-100) 供信誉降分/镜像链/判定消费。 */
BOOLEAN g_IoaSignatureHuntingEnabled = FALSE;

/**************************************************/
/*           静态知识表 (SS DSV 对齐)               */
/**************************************************/

/* 测试签名关键字表 (SS DSV L2145-2150): 签名者 CN 转小写后包含任一命中 */
static const WCHAR* const g_WkdTestSignKeywords[13] = {
    L"test sign", L"testsign", L"test cert", L"testcert",
    L"test root", L"testroot", L"development sign", L"devsign",
    L"do not ship", L"do not trust", L"internal test",
    L"self-test", L"selftest"
};

/* 微软测试根证书 SHA1 指纹 hex 小写 (SS DSV L2165-2178) */
static const char* const g_WkdMsTestRoots[3] = {
    "2bd63d28d7bcd0e251195aeb519c2ae9563755c4",  /* Microsoft Testing Root Certificate Authority 2010 */
    "f53f74e1afecda302e6f117efb0e8c562da74975",  /* Microsoft Code Verification Root (test) */
    "d411a80d2e069db74f3f321ff95e53f4523b8823"   /* WDK test-signing cert */
};

/* EV OID 表 (SS DSV L1297-1313, 15 个: CA/BF + 主流 CA)。
 * 死代码表 — wkd IsEvCert 已由 CERT_EV_PROP_ID (SignatureDetails.c) 覆盖,
 * 此表为证书策略 OID 级 EV 判定增强预留 (策略扩展解码依赖未接入)。 */
static const char* const g_WkdEvOids[15] = {
    "2.23.140.1.3",                 /* CA/BF EV Code Signing */
    "2.23.140.1.1",                 /* CA/BF EV SSL (chain indicator) */
    "2.16.840.1.114028.10.1.2",     /* Entrust EV */
    "2.16.840.1.114412.2.1",        /* DigiCert EV */
    "2.16.840.1.114413.1.7.23.3",   /* GoDaddy EV */
    "1.3.6.1.4.1.14370.1.6",        /* GeoTrust EV */
    "1.3.6.1.4.1.6449.1.2.1.5.1",   /* Comodo/Sectigo EV */
    "2.16.840.1.113733.1.7.23.6",   /* Symantec/VeriSign EV */
    "2.16.840.1.113733.1.7.48.1",   /* Thawte EV */
    "2.16.756.1.89.1.2.1.1",        /* SwissSign EV */
    "1.3.6.1.4.1.34697.2.1",        /* AffirmTrust EV */
    "1.3.6.1.4.1.8024.0.2.100.1.2", /* QuoVadis EV */
    "2.16.840.1.114414.1.7.23.3",   /* Starfield EV */
    "1.2.616.1.113527.2.5.1.1",     /* Certum EV */
    "2.16.528.1.1003.1.2.7"         /* KPN EV */
};

/**************************************************/
/*           被盗证书数据库                         */
/*  定长数组 (WKD_STOLEN_CERT_MAX) + SRWLOCK        */
/*  (静态初始化免 main 接线; 对齐 SS 动态 map 降级)  */
/**************************************************/

#define WKD_STOLEN_CERT_MAX  256

static WKD_STOLEN_CERT_ENTRY g_StolenCertDb[WKD_STOLEN_CERT_MAX];
static ULONG                 g_StolenCertCount = 0;
static SRWLOCK               g_StolenCertLock = SRWLOCK_INIT;

/**************************************************/
/*                内部辅助函数                      */
/**************************************************/

/* 当前 Unix 时间 (GetSystemTimeAsFileTime 1601→1970) */
static ULONG64
IoaSigHunt_NowUnixSeconds(VOID)
{
    FILETIME ft;
    ULARGE_INTEGER li;
    GetSystemTimeAsFileTime(&ft);
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    return (li.QuadPart - 116444736000000000ULL) / 10000000ULL;
}

/* 路径是否系统目录: 小写后含 "\windows\" (SS L2060 语义) */
static BOOLEAN
IoaSigHunt_IsSystemPath(_In_ PCWSTR Path)
{
    WCHAR buf[1024];
    size_t len;

    if (!Path) return FALSE;
    len = wcslen(Path);
    if (len == 0 || len >= RTL_NUMBER_OF(buf)) return FALSE;
    wcscpy_s(buf, RTL_NUMBER_OF(buf), Path);
    _wcslwr_s(buf, RTL_NUMBER_OF(buf));
    return (wcsstr(buf, L"\\windows\\") != NULL);
}

/* 扩展名匹配 (大小写不敏感, 尾部比对) */
static BOOLEAN
IoaSigHunt_HasExtension(_In_ PCWSTR Path, _In_ PCWSTR Ext)
{
    size_t plen, elen;

    if (!Path || !Ext) return FALSE;
    plen = wcslen(Path);
    elen = wcslen(Ext);
    if (plen < elen) return FALSE;
    return (_wcsicmp(Path + plen - elen, Ext) == 0);
}

/* 是否为 PE 可执行扩展名 (.exe/.dll/.sys) */
static BOOLEAN
IoaSigHunt_IsPeExtension(_In_ PCWSTR Path)
{
    return IoaSigHunt_HasExtension(Path, L".exe") ||
           IoaSigHunt_HasExtension(Path, L".dll") ||
           IoaSigHunt_HasExtension(Path, L".sys");
}

/* 被盗证书查表 (指纹 hex 大小写不敏感) */
static const WKD_STOLEN_CERT_ENTRY*
IoaSigHunt_LookupStolenCert(_In_ PCSTR Thumbprint)
{
    const WKD_STOLEN_CERT_ENTRY* hit = NULL;
    ULONG i;

    if (!Thumbprint || Thumbprint[0] == '\0') return NULL;

    AcquireSRWLockShared(&g_StolenCertLock);
    for (i = 0; i < g_StolenCertCount; i++) {
        if (_stricmp(g_StolenCertDb[i].Thumbprint, Thumbprint) == 0) {
            hit = &g_StolenCertDb[i];
            break;
        }
    }
    ReleaseSRWLockShared(&g_StolenCertLock);

    /* 返回指向数组元素的指针: ClearStolenCertDb 仅置 count=0 不释放数组,
     * 调用方 (AnalyzeSignature) 在锁外短暂复制 ThreatActor/Campaign 后即弃用, 无 UAF。 */
    return hit;
}

/* 测试签名判定 (SS L2120-2203 三路):
 *   (a) 不受信根 + 签名有效
 *   (b) 签名者 CN 转小写含测试关键字
 *   (c) 链上任一证书指纹命中 3 个微软测试根 */
static BOOLEAN
IoaSigHunt_IsTestSigned(_In_ PIOC_SCAN_RESULT CertResult)
{
    WCHAR signerLower[256];
    ULONG i;

    if (!CertResult) return FALSE;

    /* (a) 不受信根 + 签名结构有效 (SS L2130)。wkd UntrustedRoot 由严格判定
     * 门控 (g_IocStrictSignatureEnabled) 开启后置位, 关闭时恒 FALSE 零影响。 */
    if (CertResult->CertStatus == DefCertStatus_UntrustedRoot &&
        CertResult->CertValid) {
        return TRUE;
    }

    /* (b) 签名者 CN 含测试关键字 (SS L2145-2150) */
    if (CertResult->SignerName[0] != L'\0') {
        wcscpy_s(signerLower, RTL_NUMBER_OF(signerLower), CertResult->SignerName);
        _wcslwr_s(signerLower, RTL_NUMBER_OF(signerLower));
        for (i = 0; i < RTL_NUMBER_OF(g_WkdTestSignKeywords); i++) {
            if (wcsstr(signerLower, g_WkdTestSignKeywords[i]) != NULL) {
                return TRUE;
            }
        }
    }

    /* (c) 链上任一证书指纹命中微软测试根 (SS L2165-2189) */
    for (i = 0; i < CertResult->ChainDepth && i < 16; i++) {
        ULONG r;
        for (r = 0; r < RTL_NUMBER_OF(g_WkdMsTestRoots); r++) {
            if (_stricmp(CertResult->ChainThumbprint[i], g_WkdMsTestRoots[r]) == 0) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

/* 未来时间戳判定: legacy 计数器签名时间 > now + 300s (SS L2222-2237,
 * CLOCK_SKEW_TOLERANCE_SECS=300) */
static BOOLEAN
IoaSigHunt_HasFutureTimestamp(_In_ PCWSTR FilePath)
{
    FILETIME signTime;
    FILETIME nowFt;
    ULARGE_INTEGER st, now;
    ULARGE_INTEGER skew;

    if (!IocScan_CertHasTimestamp(FilePath, &signTime, NULL)) return FALSE;
    if (signTime.dwHighDateTime == 0 && signTime.dwLowDateTime == 0) return FALSE;

    GetSystemTimeAsFileTime(&nowFt);
    st.LowPart = signTime.dwLowDateTime;
    st.HighPart = signTime.dwHighDateTime;
    now.LowPart = nowFt.dwLowDateTime;
    now.HighPart = nowFt.dwHighDateTime;
    skew.QuadPart = 300ULL * 10000000ULL;   /* 300s × 100ns */

    return (st.QuadPart > now.QuadPart + skew.QuadPart);
}

/* 追加单条 anomaly + 更新 RiskScore (max 聚合) */
static VOID
IoaSigHunt_AddAnomaly(
    _Inout_ PWKD_SIGNATURE_HUNT_RESULT HuntResult,
    _In_    WKD_SIG_ANOMALY_TYPE      Type,
    _In_    UCHAR                     Severity,
    _In_    PCSTR                     MitreId,
    _In_    ULONG                     Risk
    )
{
    if (HuntResult->AnomalyCount >= WKD_SIG_HUNT_MAX_ANOMALIES) return;
    HuntResult->Anomaly[HuntResult->AnomalyCount].Type = Type;
    HuntResult->Anomaly[HuntResult->AnomalyCount].Severity = Severity;
    strncpy_s(HuntResult->Anomaly[HuntResult->AnomalyCount].MitreId,
              sizeof(HuntResult->Anomaly[HuntResult->AnomalyCount].MitreId),
              MitreId, _TRUNCATE);
    HuntResult->Anomaly[HuntResult->AnomalyCount].RiskContribution = Risk;
    HuntResult->AnomalyCount++;
    if (Risk > HuntResult->RiskScore) HuntResult->RiskScore = Risk;
}

/**************************************************/
/*              被盗证书库管理 API                  */
/**************************************************/

NTSTATUS
IoaSigHunt_AddStolenCert(
    _In_ PCWKD_STOLEN_CERT_ENTRY Entry
    )
/*++
Routine Description:
    追加单条被盗证书 (SHA1 指纹 hex 小写为键, 对齐 SS AddStolenCertificate L1961)。
    定长数组满时返回 INSUFFICIENT_RESOURCES (对齐 SS 无上限 map 的降级)。

Arguments:
    Entry - 条目 (指纹/威胁组织/活动/MITRE 组/严重度)。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER / STATUS_INSUFFICIENT_RESOURCES。
--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (!Entry) return STATUS_INVALID_PARAMETER;

    AcquireSRWLockExclusive(&g_StolenCertLock);
    if (g_StolenCertCount < WKD_STOLEN_CERT_MAX) {
        g_StolenCertDb[g_StolenCertCount++] = *Entry;
    } else {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    ReleaseSRWLockExclusive(&g_StolenCertLock);

    return status;
}

ULONG
IoaSigHunt_LoadStolenCertDb(
    _In_reads_(Count) PCWKD_STOLEN_CERT_ENTRY Entries,
    _In_              ULONG                Count
    )
/*++
Routine Description:
    批量导入被盗证书库 (威胁情报 feed, 对齐 SS LoadStolenCertDatabase L1971)。

Arguments:
    Entries - 条目数组。
    Count   - 条目数。

Return Value:
    实际加载条数 (库满提前停止)。
--*/
{
    ULONG loaded = 0;
    ULONG i;

    if (!Entries) return 0;
    for (i = 0; i < Count; i++) {
        if (IoaSigHunt_AddStolenCert(&Entries[i]) != STATUS_SUCCESS) break;
        loaded++;
    }
    return loaded;
}

VOID
IoaSigHunt_ClearStolenCertDb(
    VOID
    )
/*++
Routine Description:
    清空被盗证书库 (对齐 SS 动态库 Clear)。

Return Value:
    无。
--*/
{
    AcquireSRWLockExclusive(&g_StolenCertLock);
    g_StolenCertCount = 0;
    ReleaseSRWLockExclusive(&g_StolenCertLock);
}

/**************************************************/
/*            签名狩猎核心分析                      */
/**************************************************/

NTSTATUS
IoaSigHunt_AnalyzeSignature(
    _In_    PCWSTR                    FilePath,
    _In_    PIOC_SCAN_RESULT          CertResult,
    _Out_   PWKD_SIGNATURE_HUNT_RESULT HuntResult
    )
/*++
Routine Description:
    9 类签名异常分析 (SS DSV AnalyzeSignature L1998-2268 迁移)。
    输入须先经 IocVerifyTrust + IocScan_ExtractCertDetails 填充
    (CertStatus/有效期/IsSelfSigned/链指纹/WHQL)。逐项判定 → max 聚合 RiskScore。

Arguments:
    FilePath   - 文件路径 (扩展名/系统目录判定)。
    CertResult - 已填充的扫描结果。
    HuntResult - 输出 (Ran/RiskScore/Anomaly[]/IsStolenCert/IsWhql/IsTestSigned)。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER。
--*/
{
    ULONG ci;

    if (!FilePath || !CertResult || !HuntResult) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(HuntResult, sizeof(*HuntResult));

    HuntResult->IsWhql = CertResult->IsWhql;

    /* Check 1 — 被盗证书 (叶 + 链, SS L2009-2049): 命中即 riskScore 直置 100 */
    {
        const WKD_STOLEN_CERT_ENTRY* hit = IoaSigHunt_LookupStolenCert(CertResult->Thumbprint);
        if (!hit) {
            for (ci = 0; ci < CertResult->ChainDepth && ci < 16; ci++) {
                hit = IoaSigHunt_LookupStolenCert(CertResult->ChainThumbprint[ci]);
                if (hit) break;
            }
        }
        if (hit) {
            HuntResult->IsStolenCert = TRUE;
            strncpy_s(HuntResult->ThreatActor, sizeof(HuntResult->ThreatActor),
                      hit->ThreatActor, _TRUNCATE);
            strncpy_s(HuntResult->Campaign, sizeof(HuntResult->Campaign),
                      hit->Campaign, _TRUNCATE);
            IoaSigHunt_AddAnomaly(HuntResult, WkdSigAnom_StolenCertificate,
                                  WKD_SIG_ANOMALY_SEVERITY_CRITICAL,
                                  "T1553.002", 100);
        }
    }

    /* Check 2 — 非系统目录自签名 (SS L2051-2068) */
    if (CertResult->CertValid && CertResult->IsSelfSigned &&
        !IoaSigHunt_IsSystemPath(FilePath)) {
        IoaSigHunt_AddAnomaly(HuntResult, WkdSigAnom_SelfSignedExecutable,
                              WKD_SIG_ANOMALY_SEVERITY_HIGH,
                              "T1553.002", 70);
    }

    /* Check 3 — 短有效期 <30 天 (SS L2070-2085, burner cert) */
    if (CertResult->CertValidFrom != 0 && CertResult->CertValidTo != 0 &&
        (CertResult->CertValidTo - CertResult->CertValidFrom) < (30ULL * 24 * 3600)) {
        IoaSigHunt_AddAnomaly(HuntResult, WkdSigAnom_ShortValidityCert,
                              WKD_SIG_ANOMALY_SEVERITY_HIGH,
                              "T1588.003", 65);
    }

    /* Check 4 — 刚签发 <7 天 (SS L2087-2102) */
    if (CertResult->CertValid && CertResult->CertValidFrom != 0) {
        ULONG64 now = IoaSigHunt_NowUnixSeconds();
        if (now >= CertResult->CertValidFrom &&
            (now - CertResult->CertValidFrom) < (7ULL * 24 * 3600)) {
            IoaSigHunt_AddAnomaly(HuntResult, WkdSigAnom_RecentlyIssuedCert,
                                  WKD_SIG_ANOMALY_SEVERITY_MEDIUM,
                                  "T1588.003", 50);
        }
    }

    /* Check 5 — 弱哈希算法 (SS L2104-2118; 合并 wkd IsWeakSignature 证书签名
     * 算法弱判定, SS fileHashAlgorithm 自身从未填充, wkd 判定更直接) */
    if (CertResult->IsWeakSignature) {
        IoaSigHunt_AddAnomaly(HuntResult, WkdSigAnom_WeakHashAlgorithm,
                              WKD_SIG_ANOMALY_SEVERITY_MEDIUM,
                              "T1553.002", 40);
    }

    /* Check 6 — 测试签名 (SS L2120-2203, 三路) */
    if (IoaSigHunt_IsTestSigned(CertResult)) {
        HuntResult->IsTestSigned = TRUE;
        IoaSigHunt_AddAnomaly(HuntResult, WkdSigAnom_TestSignatureInProd,
                              WKD_SIG_ANOMALY_SEVERITY_HIGH,
                              "T1553.006", 75);
    }

    /* Check 7 — catalog-only PE (SS L2205-2220, 仅目录签名无内嵌) */
    if (CertResult->CertStatus == DefCertStatus_ValidCatalog &&
        IoaSigHunt_IsPeExtension(FilePath)) {
        IoaSigHunt_AddAnomaly(HuntResult, WkdSigAnom_CatalogOnlyNoEmbedded,
                              WKD_SIG_ANOMALY_SEVERITY_LOW,
                              "T1553.002", 25);
    }

    /* Check 8 — 未来时间戳 (SS L2222-2237, counter-signer 时间 > now+300s) */
    if (IoaSigHunt_HasFutureTimestamp(FilePath)) {
        IoaSigHunt_AddAnomaly(HuntResult, WkdSigAnom_TimestampInFuture,
                              WKD_SIG_ANOMALY_SEVERITY_HIGH,
                              "T1070.006", 70);
    }

    /* Check 9 — 吊销证书仍使用 (SS L2239-2250) */
    if (CertResult->CertStatus == DefCertStatus_Revoked) {
        IoaSigHunt_AddAnomaly(HuntResult, WkdSigAnom_RevokedButStillUsed,
                              WKD_SIG_ANOMALY_SEVERITY_CRITICAL,
                              "T1553.002", 95);
    }

    HuntResult->Ran = TRUE;
    return STATUS_SUCCESS;
}

/**************************************************/
/*            镜像加载签名异常分析                   */
/**************************************************/

NTSTATUS
IoaSigHunt_AnalyzeImageLoad(
    _In_    PCWSTR           FilePath,
    _In_    UCHAR            KernelSigStatus,
    _Inout_ PIOC_SCAN_RESULT CertResult
    )
/*++
Routine Description:
    镜像加载签名异常 (SS DSV OnKernelImageLoad L2274-2338 迁移)。
    9 类分析之上叠加: 未签名驱动 (+100/T1014) + 签名等级不匹配 (+80/T1553.006)。
    若统一入口未做 hunting, 先补跑 AnalyzeSignature。

Arguments:
    FilePath        - 镜像完整路径。
    KernelSigStatus - 内核 CI 签名判定 (IMG_SIGNATURE_* 值)。
    CertResult      - 扫描结果 (已经 IocVerifyTrust)。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER。
--*/
{
    PWKD_SIGNATURE_HUNT_RESULT hunt;

    if (!FilePath || !CertResult) return STATUS_INVALID_PARAMETER;
    hunt = &CertResult->SignatureHunt;

    /* 统一入口 (g_IoaSignatureHuntingEnabled) 未做狩猎时补跑 9 类分析 */
    if (!hunt->Ran) {
        NTSTATUS st = IoaSigHunt_AnalyzeSignature(FilePath, CertResult, hunt);
        if (!NT_SUCCESS(st)) return st;
    }

    /* 未签名驱动 (SS L2299-2313): result==Unsigned && .sys → riskScore 直置 100,
     * "Unsigned driver loaded — possible rootkit", T1014 */
    if (CertResult->CertStatus == DefCertStatus_Unsigned &&
        IoaSigHunt_HasExtension(FilePath, L".sys")) {
        IoaSigHunt_AddAnomaly(hunt, WkdSigAnom_UnsignedDriver,
                              WKD_SIG_ANOMALY_SEVERITY_CRITICAL,
                              "T1014", 100);
    }

    /* 签名等级不匹配 (SS L2316-2328): 内核判未签名 (无 CI 缓存) 但用户态
     * WinVerifyTrust 判定签名有效 → 可能的 signing policy bypass (catalog-only/
     * cross-signed), SupplyChainAnomaly +80 */
    if (KernelSigStatus == IMG_SIGNATURE_UNSIGNED && CertResult->CertValid) {
        IoaSigHunt_AddAnomaly(hunt, WkdSigAnom_SupplyChainAnomaly,
                              WKD_SIG_ANOMALY_SEVERITY_HIGH,
                              "T1553.006", 80);
    }

    return STATUS_SUCCESS;
}
