/**************************************************/
/*  WkDefender IOC — Catalog 目录签名验证           */
/*  自 IocScanner.c 独立 (2026-08 重构)              */
/*  对齐 SS VerifyCatalogSignature + DSV FindCatalog */
/**************************************************/

#include "SignatureCatalog.h"
#include "SignatureDetails.h"   /* IocScan_ExtractCertDetails (catalog 签名者详情) */

#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>              /* CryptCATAdmin / EnumCatalogFromHash */

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

/**************************************************/
/*               Catalog 验证三函数                 */
/**************************************************/

/* hex 目录成员 tag 校验 (SS is_hex_catalog_member_tag L351-368): 偶数长度 hex,
 * ≤128 字符。catalog 成员 tag 即文件哈希 hex (SHA256=64 位; 弱哈希显式放行由调用方控制)。 */
static BOOLEAN
IocScan_CatalogIsHexMemberTag(
    _In_ PCWSTR Tag
    )
{
    SIZE_T len, i;

    if (!Tag) return FALSE;
    len = wcslen(Tag);
    if (len == 0 || (len % 2) != 0 || len > 128) return FALSE;
    for (i = 0; i < len; i++) {
        WCHAR c = Tag[i];
        if (!((c >= L'0' && c <= L'9') ||
              (c >= L'A' && c <= L'F') ||
              (c >= L'a' && c <= L'f'))) {
            return FALSE;
        }
    }
    return TRUE;
}

BOOLEAN
IocScan_CatalogFindForFile(
    _In_  PCWSTR FilePath,
    _Out_ PWCHAR CatalogPath,
    _In_  ULONG  CatalogPathCch
    )
/*++
Routine Description:
    按文件 SHA256 在系统目录 (CryptCATAdminEnumCatalogFromHash) 中查找命中的 .cat 目录文件。
    对齐 DigitalSignatureValidator::FindCatalogForFile L1124-1169 的系统目录段
    (wkd 无自定义目录路径注册表, 仅系统目录; 注册目录列表归 ScanManager 未来策略下发)。

Arguments:
    FilePath       - 目标文件完整路径。
    CatalogPath    - 输出命中目录文件路径。
    CatalogPathCch - CatalogPath 容量 (WCHAR 数)。

Return Value:
    TRUE = 命中系统目录。
--*/
{
    DEF_SHA256_HASH hash;
    HCATADMIN       hCatAdmin = NULL;
    HCATINFO        hCatInfo = NULL;
    CATALOG_INFO    catInfo;

    if (!FilePath || !CatalogPath || CatalogPathCch == 0) return FALSE;
    CatalogPath[0] = L'\0';

    /* catalog 成员哈希即文件哈希 (对齐 SS CalculateAuthenticodeHash 语义) */
    if (!IocScanner_ComputeFileSha256(FilePath, &hash)) {
        return FALSE;
    }

    if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) {
        return FALSE;
    }

    hCatInfo = CryptCATAdminEnumCatalogFromHash(
        hCatAdmin, hash.Data, DEF_SHA256_SIZE, 0, NULL);
    if (hCatInfo) {
        RtlZeroMemory(&catInfo, sizeof(catInfo));
        catInfo.cbStruct = sizeof(catInfo);
        if (CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
            wcsncpy_s(CatalogPath, CatalogPathCch, catInfo.wszCatalogFile, _TRUNCATE);
            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            return (CatalogPath[0] != L'\0');
        }
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    }
    CryptCATAdminReleaseContext(hCatAdmin, 0);
    return FALSE;
}

BOOLEAN
IocScan_CatalogVerify(
    _In_    PCWSTR           FilePath,
    _In_    PCWSTR           CatalogPath,
    _Inout_ IOC_SCAN_RESULT* Result
    )
/*++
Routine Description:
    验证目录文件签名 (WTD_CHOICE_CATALOG + WinVerifyTrust), 成功后从 catalog 文件
    提取签名者详情 (catalog 文件自身即 PKCS7 签名对象, 复用 IocScan_ExtractCertDetails)。
    对齐 SS VerifyCatalogSignature L828-1020 (memberTag 弱哈希门控; catalog 链/吊销
    由 WinVerifyTrust provider 内部处理, 深度校验走 ExtractCertDetails 门控吊销段)。

Arguments:
    FilePath    - 目标文件 (计算哈希作 memberTag)。
    CatalogPath - 已命中的目录文件路径。
    Result      - 输出 (填充证书详情字段; CertStatus 由调用方置 ValidCatalog)。

Return Value:
    TRUE = catalog 签名验证通过。
--*/
{
    WINTRUST_CATALOG_INFO catInfo;
    WINTRUST_DATA         wtd;
    GUID                  policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG                  lStatus;
    DEF_SHA256_HASH       hash;
    WCHAR                 memberTag[65];
    static const CHAR     kHex[] = "0123456789abcdef";
    ULONG                 k;

    if (!FilePath || !CatalogPath || !Result) return FALSE;

    if (!IocScanner_ComputeFileSha256(FilePath, &hash)) return FALSE;
    for (k = 0; k < DEF_SHA256_SIZE; k++) {
        memberTag[k * 2]     = (WCHAR)kHex[(hash.Data[k] >> 4) & 0xF];
        memberTag[k * 2 + 1] = (WCHAR)kHex[hash.Data[k] & 0xF];
    }
    memberTag[DEF_SHA256_SIZE * 2] = L'\0';

    if (!IocScan_CatalogIsHexMemberTag(memberTag)) return FALSE;

    RtlZeroMemory(&catInfo, sizeof(catInfo));
    catInfo.cbStruct = sizeof(catInfo);
    catInfo.pcwszCatalogFilePath = CatalogPath;
    catInfo.pcwszMemberTag = memberTag;

    RtlZeroMemory(&wtd, sizeof(wtd));
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
    wtd.pCatalog = &catInfo;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;

    lStatus = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policyGUID, &wtd);
    if (lStatus != ERROR_SUCCESS) {
        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policyGUID, &wtd);
        return FALSE;
    }

    /* 提取 catalog 签名者详情 (在 CLOSE 前传 hWVTStateData, 走 WTHelper 非 deprecated 路径) */
    IocScan_ExtractCertDetails(CatalogPath, Result, wtd.hWVTStateData);

    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policyGUID, &wtd);
    return TRUE;
}
