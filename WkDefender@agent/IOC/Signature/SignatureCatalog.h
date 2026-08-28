/**************************************************/
/*  WkDefender IOC — Catalog 目录签名验证           */
/*  自 IocScanner.c 独立 (2026-08 重构)              */
/*  对齐 SS VerifyCatalogSignature + DSV FindCatalog */
/**************************************************/

#pragma once

#include "../IocTypes.h"

/* IocScanner_ComputeFileSha256 (定义于 IocScanner.c, 前置声明避免循环 include) */
BOOLEAN IocScanner_ComputeFileSha256(_In_ PCWSTR FilePath, _Out_ PDEF_SHA256_HASH Hash);

/**************************************************/
/*                  函数声明                       */
/**************************************************/

/*++
Routine Description:
    按文件 SHA256 在系统目录 (CryptCATAdminEnumCatalogFromHash) 中查找命中的 .cat 目录文件。
    对齐 DigitalSignatureValidator::FindCatalogForFile L1124-1169 的系统目录段。

Arguments:
    FilePath       - 目标文件完整路径。
    CatalogPath    - 输出命中目录文件路径。
    CatalogPathCch - CatalogPath 容量 (WCHAR 数)。

Return Value:
    TRUE = 命中系统目录。
--*/
BOOLEAN
IocScan_CatalogFindForFile(
    _In_  PCWSTR FilePath,
    _Out_ PWCHAR CatalogPath,
    _In_  ULONG  CatalogPathCch
    );

/*++
Routine Description:
    验证目录文件签名 (WTD_CHOICE_CATALOG + WinVerifyTrust), 成功后从 catalog 文件
    提取签名者详情。对齐 SS VerifyCatalogSignature L828-1020。
    SignatureVerifier CertVerify 的 NOSIGNATURE 分支 (门控 g_IocCatalogEnabled) 调用。

Arguments:
    FilePath    - 目标文件 (计算哈希作 memberTag)。
    CatalogPath - 已命中的目录文件路径。
    Result      - 输出 (填充证书详情字段; CertStatus 由调用方置 ValidCatalog)。

Return Value:
    TRUE = catalog 签名验证通过。
--*/
BOOLEAN
IocScan_CatalogVerify(
    _In_    PCWSTR           FilePath,
    _In_    PCWSTR           CatalogPath,
    _Inout_ IOC_SCAN_RESULT* Result
    );
