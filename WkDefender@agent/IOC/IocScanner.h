/**************************************************/
/*  WkDefender IOC 引擎 — 静态文件扫描器            */
/*  哈希/LOLBin/命令行/PE头/启发式                  */
/*  证书验证独立至 Signature/ (2026-08 重构)         */
/**************************************************/

#pragma once

#include "IocTypes.h"
#include "../IOA/IoaTypes.h"
#include "PEAnalyzer/PeAnalyzer.h"   /* PE_PARSER_CONTEXT (死代码节哈希/延迟导入分析) */

/* 证书验证模块 (统一入口 + 详情 + catalog + 缓存 + 信誉):
 * IocVerifySignature / IocScanner_VerifyMemoryBuffer /
 * IocScan_IsMicrosoftSigned / IocScan_IsTrustedPublisher / IocScan_IsEvSigned */
#include "Signature/SignatureVerifier.h"

/* 文件/哈希/类型判定工具层 (2026-08-15 自本头迁出, 声明移至 Common/FileUtils.h) */
#include "../Common/FileUtils.h"

NTSTATUS IocScanner_ScanFile(_In_ PCWSTR FilePath, _Out_ IOC_SCAN_RESULT* Result);
/* 带 PE_INFO 几何提示的扫描入口 (2026-08-19 Ctx 基座):
 * PeInfo 由调用方传入构建期 IocAnalyzePe 产物 (如 WKD_MODULE.PeInfo)，
 * 深度分析 (IocHeuristicPeAnalysis) 据此复用几何、免二次完整解析。
 * 无提示时传 NULL (等价 IocScanner_ScanFile)。 */
NTSTATUS IocScanner_ScanFileWithHint(_In_ PCWSTR FilePath, _In_opt_ const PE_INFO* PeInfo, _Out_ IOC_SCAN_RESULT* Result);
NTSTATUS IocScanner_ScanCmdline(_In_ PCWSTR CmdLine, _Out_ IOC_SCAN_RESULT* Result);
/* IocScanner_ScanProcess 已删除 (2026-08-15): 收敛至 IOC/ImageAnalyzer/ImageAnalyzer */

/* 合并语义 API (ImageAnalyzer Cmdline 合并用, 2026-08-15 导出):
 *   IocScan_Cmdline    — 不清空已有结果, 仅填 Cmdline 信号 (合并语义)
 *   IocScan_Aggregate  — 重新聚合全部信号 (含 Cmdline) → FinalVerdict
 * (IocScanner_ScanCmdline 为独立扫描, 入口 RtlZeroMemory 清空, 不适用于合并) */
VOID IocScan_Cmdline(_In_ PCWSTR CmdLine, _Inout_ IOC_SCAN_RESULT* Result);
VOID IocScan_Aggregate(_Inout_ IOC_SCAN_RESULT* Result);

/*++
 * IocScanner_QueryHash
 *   查询文件哈希是否命中 ioc_hashes 恶意库（布隆预检 + SQLite）。
 *--*/
NTSTATUS IocScanner_QueryHash(_In_ PDEF_SHA256_HASH Hash, _Out_ PBOOLEAN FoundMalicious);

/**************************************************/
/*  路径欺骗检测器 + 查询 API                      */
/*  2026-09-14: 实现已迁移至 FileSystem/FileAnalyzer.c */
/*  声明已迁移至 Include/FileSystem/FileAnalyzer.h   */
/*  本头仅保留 IocScanner_* 核心扫描 API。          */
/**************************************************/

/**************************************************/
/*     节哈希 / 延迟导入分析 (死代码, 对齐 SS)        */
/**************************************************/
typedef struct _IOC_SECTION_HASH {
    CHAR    Name[PE_MAX_SECTION_NAME + 1];
    BYTE    Sha256[DEF_SHA256_SIZE];
    BOOLEAN HasSha256;
} IOC_SECTION_HASH;

/* 逐节 SHA256 (ComputeSectionHashes, 死代码: 无 section-hash 布隆消费方) */
BOOLEAN IocScan_ComputeSectionHashes(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ IOC_SECTION_HASH*       Hashes,
    _In_  ULONG                   MaxHashes,
    _Out_ PULONG                  Count
    );

/**************************************************/
/*          媒体文件分析 (SS MediaFileScanner)       */
/*  格式验证/隐写检测/元数据·EXIF/漏洞载荷/追加数据  */
/*  (2026-08-06 迁移, 功能面全量; 枚举/结构在        */
/*   IocTypes.h; 接线点 ScanManager.ScanFileDirect  */
/*   步骤 5/6 间 TODO(媒体扫描))                    */
/**************************************************/

/*++
Routine Description:
    媒体文件安全分析主入口 (MediaFileScanner::Scan L626-730):
    类型判定 → 格式验证(JPEG/PNG/GIF/BMP/TIFF) → 隐写检测(LSB·DCT·EOF·Metadata)
    → 元数据/EXIF 提取 → 漏洞载荷检测(EmbeddedPe·Polyglot·ScriptInjection·
    TiffAttacks·MaliciousExif) → 追加数据分析(JPEG EOI/PNG IEND 后归档)。

Arguments:
    FilePath - 文件路径。
    Result   - 输出 WKD_MEDIA_SCAN_RESULT (~3.5KB, 调用方须堆分配)。

Return Value:
    STATUS_SUCCESS。Result 填充。
--*/
NTSTATUS
IocMedia_ScanFile(
    _In_  PCWSTR                   FilePath,
    _Out_ PWKD_MEDIA_SCAN_RESULT   Result
    );

/*++
Routine Description:
    媒体扫描结果合并进 IOC_SCAN_RESULT (对齐 IocDocument_ResultToIocScan):
    经 HeuristicConfidence 通道复用 IocScan_Aggregate 阈值
    (RiskScore*10: 80→800≥700 Malicious / 40→400≥300 Suspicious),
    按首个非 None 威胁写 ThreatName "Media.*"。

Arguments:
    Media - 媒体扫描结果 (IocMedia_ScanFile 输出)。
    Ioc   - IOC 扫描结果 (合并目标)。

Return Value:
    STATUS_SUCCESS。Ioc->HeuristicRan/HeuristicConfidence/ThreatName/EvidenceCount 更新。
--*/
NTSTATUS
IocMedia_ResultToIocScan(
    _In_  PWKD_MEDIA_SCAN_RESULT  Media,
    _Inout_ PIOC_SCAN_RESULT      Ioc
    );

/*-- 以下为死代码导出 (SS 独立 API, 功能面全量; 无流水线调用者亦不告警) --*/

/* 隐写检测独立入口 (DetectSteganography L1917-1925) */
NTSTATUS
IocMedia_DetectSteganography(
    _In_  PCWSTR                   FilePath,
    _Out_ PWKD_STEGO_ANALYSIS      Result
    );

/* 元数据提取独立入口 (ExtractMetadata L1927-1935) */
NTSTATUS
IocMedia_ExtractMetadata(
    _In_  PCWSTR                   FilePath,
    _Out_ PWKD_MEDIA_METADATA      Result
    );

/* 是否含追加数据 (HasAppendedData L1937-1944, 当前仅 JPEG) */
BOOLEAN
IocMedia_HasAppendedData(
    _In_ PCWSTR FilePath
    );

/* 提取追加数据 (ExtractAppendedData L1946-1953, 当前仅 JPEG;
 * *OutBuf 为 malloc 堆缓冲, 调用方 free) */
NTSTATUS
IocMedia_ExtractAppendedData(
    _In_  PCWSTR    FilePath,
    _Out_ BYTE**    OutBuf,
    _Out_ PULONG    OutLen
    );

/**************************************************/
/*    威胁情报匹配结构 (ThreatIntelMatch)    */
/*  原误迁至 FileUtils.c, 归位公共头 (2026-08-16)    */
/**************************************************/
typedef struct _WKD_THREAT_INTEL_MATCH {
    CHAR    MatchType[32];
    CHAR    MatchValue[128];
    CHAR    ThreatName[256];
    CHAR    MalwareFamily[128];
    CHAR    Severity[16];      /* Critical/High/Medium/Low */
    CHAR    MitreId[256];
    CHAR    Tags[512];
    CHAR    Source[64];
    ULONG64 AddedDate;         /* ThreatIntelMatch.addedDate */
    ULONG   Confidence;        /* 0-1000 */
} WKD_THREAT_INTEL_MATCH, *PWKD_THREAT_INTEL_MATCH;
