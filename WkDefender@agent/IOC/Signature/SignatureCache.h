/**************************************************/
/*  WkDefender IOC — 证书验证结果缓存               */
/*  自 IocScanner.c 独立 (2026-08 重构)              */
/*  SS DigitalSignatureValidator 缓存 L1766-1819 迁移 */
/**************************************************/

#pragma once

#include "../IocTypes.h"

/**************************************************/
/*                  函数声明                       */
/**************************************************/

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
BOOLEAN
IocScan_CertCacheLookup(
    _In_  PCWSTR          FilePath,
    _Inout_ IOC_SCAN_RESULT* Result
    );

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
VOID
IocScan_CertCacheStore(
    _In_ PCWSTR          FilePath,
    _In_ PIOC_SCAN_RESULT Result
    );
