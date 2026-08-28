/**************************************************/
/*  WkDefender IOC 引擎 — 归档扫描                  */
/*  功能面全量迁移自 ShadowStrike ArchiveExtractor   */
/*  + ScanEngine::ScanArchive (扫描模式)            */
/*  按功能融合重实现，非源码复制。                  */
/*                                                  */
/*  ⚠ 死代码：本阶段功能面覆盖，未接入 ScanManager  */
/*  流水线 (接线点 ScanManager.c 留 TODO)。         */
/*                                                  */
/*  功能面覆盖 (对齐 SS ArchiveExtractor.cpp):      */
/*   - 格式魔数检测 13 种 + 复合 tar.* + 扩展名      */
/*   - ZIP 中央目录 (Zip64/重叠/隐藏/CRC/嵌套)       */
/*   - ZIP 条目提取 (STORED 直拷 + DEFLATE inflate)  */
/*   - TAR 解析 + 全数据读出 + 链路检测              */
/*   - GZIP 头解析 (FNAME/ISIZE/压缩比)              */
/*   - RAR4/RAR5 头级条目枚举 (不解压)               */
/*   - IsPathSafe 全规则 + SanitizePath              */
/*   - ZipBomb 5 检查 (总比/总量/单条目/Quine/重叠)  */
/*   - 内容分析 (香农熵/SHA256/哈希库/PE/脚本)       */
/*  依赖缺失:                                       */
/*   - 7z/BZ2/XZ/ZSTD/LZMA/CAB 内容级解析 (仅检测)   */
/*   - RAR 解压 (仅头枚举)                           */
/**************************************************/

#pragma once

#include <windows.h>

/**************************************************/
/*               归档格式枚举                       */
/*  对齐 SS ArchiveFormat L181-221 (仅魔数表+       */
/*  扩展名兜底覆盖的子集)                           */
/**************************************************/

typedef enum _WKD_ARCHIVE_FORMAT {
    WkdArcFormat_Unknown = 0,
    WkdArcFormat_Zip,
    WkdArcFormat_Rar4,
    WkdArcFormat_Rar5,
    WkdArcFormat_SevenZip,      /* 检测级, 无解析器 */
    WkdArcFormat_Tar,
    WkdArcFormat_Gzip,
    WkdArcFormat_Bzip2,         /* 检测级 */
    WkdArcFormat_Xz,            /* 检测级 */
    WkdArcFormat_Zstd,          /* 检测级 */
    WkdArcFormat_Cab,           /* 检测级 */
    WkdArcFormat_Lzma,          /* 检测级 */
    WkdArcFormat_Iso,           /* 检测级 (偏移 0x8001) */
    /* 复合 tar */
    WkdArcFormat_TarGz,
    WkdArcFormat_TarBz2,
    WkdArcFormat_TarXz,
    WkdArcFormat_TarZstd,
    /* 扩展名兜底 (无解析器) */
    WkdArcFormat_Msi,
    WkdArcFormat_Wim,
    WkdArcFormat_Vhd,
    WkdArcFormat_Vhdx,
    WkdArcFormat_Dmg,
    WkdArcFormat_Img,
    WkdArcFormat_Arj,
    WkdArcFormat_Lzh,
    WkdArcFormat_Ace,
    WkdArcFormat_Cpio,
    WkdArcFormat_Rpm,
    WkdArcFormat_Deb,
} WKD_ARCHIVE_FORMAT, *PWKD_ARCHIVE_FORMAT;

/**************************************************/
/*               安全标志                           */
/*  语义对齐 SS SecurityFlag L276-287, 数值保留     */
/*  wkd 既有位以兼容 (DeepNesting/Overlapping 数值   */
/*  与 SS 不同, 语义一致)                           */
/**************************************************/

typedef enum _WKD_ARCHIVE_SEC_FLAG {
    WkdArcFlag_None                 = 0x00000000,
    WkdArcFlag_ZipBombSuspected     = 0x00000001,
    WkdArcFlag_HighCompressionRatio = 0x00000002,
    WkdArcFlag_PathTraversalAttempt = 0x00000004,
    WkdArcFlag_EncryptedContent     = 0x00000008,
    WkdArcFlag_DeepNesting          = 0x00000010,
    WkdArcFlag_OverlappingEntries   = 0x00000020,
    /* SS 扩展 (对齐 SS L276-287) */
    WkdArcFlag_SymlinkAttack        = 0x00000040,
    WkdArcFlag_HiddenEntry          = 0x00000080,
    WkdArcFlag_SuspiciousEntry      = 0x00000100,
} WKD_ARCHIVE_SEC_FLAG;

/**************************************************/
/*               条目属性标志                       */
/**************************************************/

#define WKD_ARC_ENTRY_DIRECTORY    0x00000001
#define WKD_ARC_ENTRY_ENCRYPTED    0x00000002
#define WKD_ARC_ENTRY_HIDDEN       0x00000004
#define WKD_ARC_ENTRY_NESTED       0x00000008
#define WKD_ARC_ENTRY_SYMLINK      0x00000010
#define WKD_ARC_ENTRY_HARDLINK     0x00000020
#define WKD_ARC_ENTRY_PE           0x00000040
#define WKD_ARC_ENTRY_SCRIPT       0x00000080

/* 压缩方法 (对齐 SS compressionMethod 字符串语义) */
#define WKD_ARC_COMP_STORED        0
#define WKD_ARC_COMP_DEFLATE       8

/**************************************************/
/*               结构体声明                         */
/**************************************************/

#define WKD_ARCHIVE_MAX_ENTRIES   512

/* 注意: WKD_ARCHIVE_SCAN_RESULT 约 200KB,
   调用方必须堆分配, 禁止栈上声明 */

typedef struct _WKD_ARCHIVE_ENTRY {
    CHAR       Name[256];            /* 条目原始名 (ZIP/RAR UTF-8, TAR 原始字节) */
    ULONG64    CompressedSize;       /* Zip64 支持 */
    ULONG64    UncompressedSize;     /* Zip64 支持 */
    ULONG      Crc32;                /* 条目 CRC32 (ZIP/RAR/GZIP 提供) */
    double     SingleEntryRatio;     /* 单条目压缩比 (uncompressed/compressed) */
    double     Entropy;              /* 内容香农熵 0-8 (内容分析产出) */
    CHAR       Sha256Hex[65];        /* 条目内容 SHA256 hex (内容分析产出) */
    ULONG      SecurityFlags;        /* 逐条目标志 (WKD_ARCHIVE_SEC_FLAG) */
    ULONG      Flags;                /* WKD_ARC_ENTRY_* */
    ULONG      CompressionMethod;    /* WKD_ARC_COMP_* */
    ULONG64    LocalHeaderOffset;    /* ZIP LFH 偏移 (供提取/完整性) */
    ULONG64    DataOffset;           /* 条目数据起始偏移 (内部提取用) */
    ULONG64    DataSize;             /* 条目压缩数据大小 (ZIP 提取用) */
    WKD_ARCHIVE_FORMAT NestedFormat; /* 嵌套归档格式 (魔数检测产出) */
} WKD_ARCHIVE_ENTRY, *PWKD_ARCHIVE_ENTRY;

typedef struct _WKD_ARCHIVE_SCAN_RESULT {
    BOOLEAN            IsArchive;
    BOOLEAN            IsZipBomb;
    WKD_ARCHIVE_FORMAT ArchiveFormat;
    double             CompressionRatio;      /* 总未压缩 / 文件大小 */
    ULONG64            TotalUncompressed;     /* 溢出安全累加 (全量累计) */
    ULONG              TotalEntryCount;       /* EOCD 声明总条目数 */
    ULONG              EntryCount;            /* 实际填充 Entries[] 数量 (<=512) */
    ULONG              SecurityFlags;         /* 聚合安全标志 */
    ULONG              FlaggedCount;          /* 命中安全标志条目数 */
    ULONG              NestedCount;           /* 嵌套归档条目数 */
    ULONG              OverlappingCount;      /* 重叠条目数 */

    ULONG              Verdict;               /* 0 Clean / 1 Suspicious / 2 Infected */
    CHAR               ThreatName[64];
    WKD_ARCHIVE_ENTRY  Entries[WKD_ARCHIVE_MAX_ENTRIES];
} WKD_ARCHIVE_SCAN_RESULT, *PWKD_ARCHIVE_SCAN_RESULT;

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*++
Routine Description:
    判断文件是否为支持的归档格式 (魔数优先 + 扩展名兜底)。
    对齐 SS DetectFormat (L866-972)。

Arguments:
    FilePath  - 文件完整路径。
    IsArchive - 输出是否归档。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocArchive_IsArchive(
    _In_ PCWSTR     FilePath,
    _Out_ PBOOLEAN  IsArchive
    );

/*++
Routine Description:
    归档扫描主入口 (活代码, 接线点未接入 ScanManager)。
    ZIP 中央目录 → ZipBomb 预检 → 路径遍历 → 条目安全标志 →
    内容分析 (可提取条目) → 判定。
    对齐 SS ScanArchive (L2735-2824) + ScanEngine::ScanArchive。

Arguments:
    FilePath - 文件完整路径。
    Result   - 输出扫描结果 (调用方堆分配)。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocArchive_ScanFile(
    _In_ PCWSTR                 FilePath,
    _Out_ PWKD_ARCHIVE_SCAN_RESULT Result
    );

/*++
Routine Description:
    条目路径遍历检测 (对齐 SS IsPathSafe 子集)：
    ../ 相对逃逸 / 绝对路径 / 盘符。

Arguments:
    EntryName - 条目名。
    NameLen   - 长度。

Return Value:
    TRUE = 存在路径遍历。
--*/
BOOLEAN
IocArchive_IsPathTraversal(
    _In_ PCSTR EntryName,
    _In_ ULONG NameLen
    );

/**************************************************/
/*               格式检测                           */
/**************************************************/

/*++
Routine Description:
    从内存 buffer 检测归档格式 (魔数表优先)。
    对齐 SS DetectFormat(span) (L961-972)。

Arguments:
    Buffer - 头部字节。
    Size   - buffer 大小。
    Format - 输出格式。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
WkdArc_DetectFormatBuffer(
    _In_ const BYTE*         Buffer,
    _In_ ULONG               Size,
    _Out_ PWKD_ARCHIVE_FORMAT Format
    );

/*++
Routine Description:
    从文件路径检测归档格式 (魔数 + 复合 tar.* + 扩展名兜底)。
    对齐 SS DetectFormat(path) (L866-959)。

Arguments:
    FilePath - 文件路径。
    Format   - 输出格式。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
WkdArc_DetectFormatPath(
    _In_ PCWSTR                FilePath,
    _Out_ PWKD_ARCHIVE_FORMAT  Format
    );

/*++
Routine Description:
    格式化归档格式名 (对齐 SS GetFormatName L3737-3769)。

Arguments:
    Format - 格式。
    Buffer - 输出缓冲区。
    Size   - 缓冲区大小。

Return Value:
    VOID。
--*/
VOID
WkdArc_GetFormatName(
    _In_ WKD_ARCHIVE_FORMAT Format,
    _Out_ PCHAR             Buffer,
    _In_ ULONG              Size
    );

/**************************************************/
/*               路径安全                           */
/**************************************************/

/*++
Routine Description:
    条目路径安全全量检查 (对齐 SS IsPathSafe L528-591)：
    绝对路径/UNC/../尾部点空格/保留设备名/非法字符/
    Unicode 变体/RTL bidi/嵌入 NUL/C0 控制/ADS ::/超长 260。

Arguments:
    PathW - 宽字符路径 (NUL 终止)。

Return Value:
    TRUE = 安全。
--*/
BOOLEAN
WkdArc_IsPathSafeW(
    _In_ PCWSTR PathW
    );

/*++
Routine Description:
    路径净化 (对齐 SS SanitizePath L593-662)：剥离绝对前缀、
    跳过 ../ 和 ./、剥离尾部点空格、保留设备名加下划线前缀、
    非法字符替换为 '_'。

Arguments:
    PathW   - 原始宽字符路径。
    Out     - 净化输出缓冲区。
    OutSize - 输出缓冲区大小 (WCHAR 数)。

Return Value:
    TRUE = 成功。
--*/
BOOLEAN
WkdArc_SanitizePathW(
    _In_ PCWSTR PathW,
    _Out_ PWSTR Out,
    _In_ ULONG  OutSize
    );

/**************************************************/
/*               CRC32 / 解压                      */
/**************************************************/

/*++
Routine Description:
    CRC32 计算 (查表法, 对齐 SS ComputeCrc32 L500-506)。

Arguments:
    Buffer - 数据。
    Size   - 大小。

Return Value:
    CRC32 值。
--*/
ULONG
WkdArc_Crc32(
    _In_ const BYTE* Buffer,
    _In_ ULONG       Size
    );

/*++
Routine Description:
    RFC1951 inflate 解压 (自实现, 只解不解)。
    SS 因缺 codec 对 DEFLATE 显式拒绝 (L2702-2713),
    wkd 手写 inflate 补上该能力闭环 (用户决策增强)。

Arguments:
    In     - 压缩数据 (raw deflate)。
    InSize - 压缩数据大小。
    Out    - 输出缓冲区。
    OutCap - 输出缓冲区容量。
    OutLen - 输出实际大小。

Return Value:
    TRUE = 解压成功。
--*/
BOOLEAN
WkdArc_Inflate(
    _In_  const BYTE* In,
    _In_  ULONG       InSize,
    _Out_ BYTE*       Out,
    _In_  ULONG       OutCap,
    _Out_ PULONG      OutLen
    );

/**************************************************/
/*               条目提取                           */
/**************************************************/

/*++
Routine Description:
    提取 ZIP 条目内容 (STORED 直拷 / DEFLATE inflate)。
    对齐 SS ExtractZipEntry (L2647-2729), 加密拒绝。

Arguments:
    Buffer   - 整个归档 buffer。
    Size     - 归档大小。
    Entry    - 条目 (需 LocalHeaderOffset 有效)。
    Out      - 输出内容缓冲区。
    OutCap   - 容量。
    OutLen   - 输出大小。

Return Value:
    NTSTATUS (STATUS_SUCCESS / STATUS_ENCRYPTED / 其他失败)。
--*/
NTSTATUS
WkdArc_ExtractEntryContent(
    _In_  const BYTE*          Buffer,
    _In_  ULONG                Size,
    _In_  PWKD_ARCHIVE_ENTRY   Entry,
    _Out_ BYTE*                Out,
    _In_  ULONG                OutCap,
    _Out_ PULONG               OutLen
    );

/**************************************************/
/*               内容分析                           */
/**************************************************/

/*++
Routine Description:
    条目内容分析 (对齐 SS ScanZipArchive L3575-3618 / ScanTar
    L1592-1643)：香农熵 + SHA256 + PE(MZ) + 脚本检测。
    复用 wkd IocpCalculateShannonEntropy / IocScanner_ComputeBufferSha256。

Arguments:
    Content - 条目内容。
    Size    - 大小。
    Entry   - 条目 (就地更新 Entropy/Sha256Hex/Flags)。

Return Value:
    VOID。
--*/
VOID
WkdArc_AnalyzeEntryContent(
    _In_  const BYTE*        Content,
    _In_  ULONG              Size,
    _In_  PWKD_ARCHIVE_ENTRY Entry
    );

/**************************************************/
/*               ZipBomb 检测                      */
/**************************************************/

/*++
Routine Description:
    ZipBomb 判定 (5 检查, 对齐 SS IsZipBomb L3105-3210)：
    总压缩比 / 总量超限 / 单条目比×2 / Quine / 重叠条目。

Arguments:
    Result    - 已解析的归档结果。
    FileSize  - 归档文件大小 (字节)。

Return Value:
    TRUE = 判定为 ZipBomb。
--*/
BOOLEAN
WkdArc_IsZipBomb(
    _In_ PWKD_ARCHIVE_SCAN_RESULT Result,
    _In_ ULONG64                  FileSize
    );

/**************************************************/
/*               完整性 / 提取 (死代码)            */
/**************************************************/

/*++
Routine Description:
    判断净化路径是否安全落在输出根目录内 (canonical 根校验,
    对齐 SS ExtractAll L2860-2929)。活代码, 供未来隔离区/
    取证导出复用。

Arguments:
    OutPath      - 目标绝对路径。
    OutputRoot   - 输出根目录。
    AllowReparse - 是否允许目标为 reparse point。

Return Value:
    TRUE = 路径安全。
--*/
BOOLEAN
WkdArc_CheckPathInsideRoot(
    _In_ PCWSTR OutPath,
    _In_ PCWSTR OutputRoot,
    _In_ BOOLEAN AllowReparse
    );

/**************************************************/
/*               归档信息结构                       */
/*  对齐 SS ArchiveInfo L374-416 (精简, 死代码)    */
/**************************************************/

typedef struct _WKD_ARCHIVE_INFO {
    WKD_ARCHIVE_FORMAT ArchiveFormat;
    ULONG64            FileSize;
    ULONG              TotalEntries;
    ULONG              FileCount;
    ULONG              DirectoryCount;
    ULONG64            TotalCompressedSize;
    ULONG64            TotalUncompressedSize;
    double             OverallCompressionRatio;
    BOOLEAN            HasEncryptedEntries;
    ULONG              SecurityFlags;
} WKD_ARCHIVE_INFO, *PWKD_ARCHIVE_INFO;

/**************************************************/
/*               回调类型                           */
/**************************************************/

/* 逐条目扫描回调: 返回 TRUE=clean (对齐 SS EntryCallback) */
typedef BOOLEAN (*WKD_ARC_ENTRY_CALLBACK)(
    _In_ PWKD_ARCHIVE_ENTRY Entry,
    _In_ const BYTE*         Content,
    _In_ ULONG               ContentLen,
    _In_opt_ PVOID           Context
    );

/* 流式分块回调: 返回 TRUE=继续 (对齐 SS StreamCallback) */
typedef BOOLEAN (*WKD_ARC_STREAM_CALLBACK)(
    _In_ PWKD_ARCHIVE_ENTRY Entry,
    _In_ const BYTE*         Chunk,
    _In_ ULONG               ChunkLen,
    _In_ BOOLEAN             IsLast,
    _In_opt_ PVOID           Context
    );

/**************************************************/
/*   死代码 API 面 (对齐 SS ArchiveExtractor 公开  */
/*   接口, 未接入流水线, 功能面占位)               */
/**************************************************/

NTSTATUS
WkdArc_GetSupportedFormats(
    _Out_ PWKD_ARCHIVE_FORMAT Formats,
    _In_  ULONG               MaxCount,
    _Out_ PULONG              Count
    );

NTSTATUS
WkdArc_CheckEntrySecurity(
    _In_  PWKD_ARCHIVE_ENTRY Entry,
    _Out_ PULONG              SecurityFlags
    );

BOOLEAN
WkdArc_MatchesPattern(
    _In_ PCWSTR Path,
    _In_ PCWSTR Pattern
    );

NTSTATUS
WkdArc_ListContents(
    _In_ PCWSTR                FilePath,
    _Inout_ PWKD_ARCHIVE_SCAN_RESULT Result
    );

NTSTATUS
WkdArc_GetArchiveInfo(
    _In_ PCWSTR          FilePath,
    _Out_ PWKD_ARCHIVE_INFO Info
    );

NTSTATUS
WkdArc_VerifyIntegrity(
    _In_  PCWSTR   FilePath,
    _Out_ PBOOLEAN Valid
    );

NTSTATUS
WkdArc_ExtractEntry(
    _In_  PCWSTR FilePath,
    _In_  PCWSTR EntryPath,
    _Out_ BYTE*  Out,
    _In_  ULONG  OutCap,
    _Out_ PULONG OutLen
    );

NTSTATUS
WkdArc_ExtractMatching(
    _In_ PCWSTR                    FilePath,
    _In_ PCWSTR                    Pattern,
    _In_opt_ WKD_ARC_ENTRY_CALLBACK Callback,
    _In_opt_ PVOID                 Context
    );

NTSTATUS
WkdArc_ExtractStreaming(
    _In_ PCWSTR                     FilePath,
    _In_ ULONG                      ChunkSize,
    _In_opt_ WKD_ARC_STREAM_CALLBACK Callback,
    _In_opt_ PVOID                  Context
    );

NTSTATUS
WkdArc_QuickSecurityCheck(
    _In_  PCWSTR FilePath,
    _Out_ PULONG SecurityFlags
    );

NTSTATUS
WkdArc_HandleKernelScanRequest(
    _In_ PCWSTR                     FilePath,
    _In_ ULONG                      ProcessId,
    _In_opt_ WKD_ARC_ENTRY_CALLBACK ScanCallback,
    _In_opt_ PVOID                  Context,
    _Out_ PBOOLEAN                  AllClean
    );

NTSTATUS
WkdArc_AnalyzeSecurity(
    _In_ PCWSTR                 FilePath,
    _Inout_ PWKD_ARCHIVE_SCAN_RESULT Result
    );
