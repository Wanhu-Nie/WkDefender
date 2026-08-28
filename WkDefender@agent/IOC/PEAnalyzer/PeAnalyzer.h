/**************************************************/
/*  WkDefender PEAnalyzer — 唯一对外公共接口        */
/*  外部模块一律 include 本头。                     */
/*  本头 = 公共类型(PeTypes.h) + 门面业务类型       */
/*  (WPA_* / WKD_*) + 业务门面函数。                 */
/*  不再 include PeInternal.h → 编译期函数隔离:     */
/*  内部解析/惰性解析/解包函数声明不可见; 死代码     */
/*  内部调用文件须显式 include PeInternal.h 并标注。 */
/**************************************************/

#pragma once

#include "PeTypes.h"
#include "../../DefendTypes.h"
#include "../IocTypes.h"

//
// PE 签名常量
//
#define WPA_DOS_SIGNATURE                   0x5A4D
#define WPA_NT_SIGNATURE                    0x00004550
#define WPA_PE32_MAGIC                      0x10B
#define WPA_PE32PLUS_MAGIC                  0x20B

//
// 深度 PE 验证常量 (对齐 SS MAX_IMAGE=256MB)
//
#define WKD_PE_DEEP_MAX_IMAGE              (256UL * 1024 * 1024)

//
// 熵阈值 (0-1000 简化熵)
//
#define WPA_ENTROPY_THRESHOLD_PACKED        7000    /* CoEntropyBinary bits*1000 (7.0 bits, packed 节) */
#define WPA_ENTROPY_THRESHOLD_ENCRYPTED     7500    /* CoEntropyBinary bits*1000 (7.5 bits, 加密载荷) */

//
// 行为标志
//
#define WPA_BEHAVIOR_NONE                   0x00000000
#define WPA_BEHAVIOR_UNSIGNED               0x00000004
#define WPA_BEHAVIOR_PACKED                 0x00000008
#define WPA_BEHAVIOR_NO_DEP                 0x00000010
#define WPA_BEHAVIOR_NO_ASLR                0x00000020
#define WPA_BEHAVIOR_ELEVATED               0x00000040
#define WPA_BEHAVIOR_SCRIPT_HOST            0x00002000
#define WPA_BEHAVIOR_HIGH_ENTROPY           0x00080000
#define WPA_BEHAVIOR_SUSPICIOUS_PARENT      0x00100000
#define WPA_BEHAVIOR_SUSPICIOUS_CMDLINE     0x00001000

/**************************************************/
/*            PE 分析结果 (遗留类型)                 */
/**************************************************/
typedef struct _WPA_PE_INFO {
    BOOLEAN IsPE;
    BOOLEAN Amd64;
    BOOLEAN IsDotNet;
    BOOLEAN IsPacked;
    BOOLEAN IsSigned;
    ULONG   Entropy;
    ULONG   Characteristics;
    ULONG   Subsystem;
    ULONG   ImageSize;
    USHORT  DllCharacteristics;
    USHORT  Machine;
    ULONG   TimeDateStamp;
    ULONG   EntryPoint;
    ULONG_PTR ImageBase;

    /* 镂空/反射检测扩展字段 */
    USHORT  NumberOfSections;
    ULONG   Checksum;
    ULONG   SectionAlignment;
    ULONG   FileAlignment;
    ULONG   SizeOfHeaders;
    ULONG   NumberOfDataDirectories;
    ULONG   ImportTableRVA;
    ULONG   ImportTableSize;
    ULONG   ExportTableRVA;
    ULONG   ExportTableSize;
    ULONG   RelocationTableRVA;
    ULONG   RelocationTableSize;
    ULONG   DebugDirectoryRVA;
    ULONG   DebugDirectorySize;
    ULONG   TlsDirectoryRVA;
    ULONG   TlsDirectorySize;
} WPA_PE_INFO, *PWPA_PE_INFO;

/**************************************************/
/*            节表条目 (遗留类型)                    */
/**************************************************/
#define WKD_PE_MAX_SECTIONS         96

typedef struct _WKD_PE_SECTION {
    CHAR    Name[8];
    ULONG   VirtualSize;
    ULONG   VirtualAddress;
    ULONG   SizeOfRawData;
    ULONG   PointerToRawData;
    ULONG   Characteristics;
    BOOLEAN IsExecutable;
    BOOLEAN IsWritable;
    BOOLEAN IsReadable;
    BOOLEAN ContainsCode;
    BOOLEAN ContainsData;
    ULONG   Entropy;
    ULONG_PTR MemoryAddress;
} WKD_PE_SECTION, *PWKD_PE_SECTION;

/**************************************************/
/*        深度 PE 验证结果分级 (遗留类型)             */
/**************************************************/
typedef enum _WKD_PE_VALIDATION_RESULT {
    WkdPeValid = 0,
    WkdPeInvalidDosHeader,
    WkdPeInvalidPeSignature,
    WkdPeInvalidOptionalHeader,
    WkdPeInvalidSections,
    WkdPeTruncatedPE,
    WkdPeSuspiciousCharacteristics,
    WkdPePacked,
    WkdPeEncrypted
} WKD_PE_VALIDATION_RESULT, *PWKD_PE_VALIDATION_RESULT;

/**************************************************/
/*        深度 PE 验证结果 (遗留类型)                 */
/**************************************************/
typedef struct _WKD_PE_DEEP_INFO {
    BOOLEAN  IsValidPE;
    BOOLEAN  Amd64;
    USHORT   Machine;
    USHORT   NumberOfSections;
    ULONG    TimeDateStamp;
    ULONG    Characteristics;
    ULONG    SizeOfImage;
    ULONG    EntryPoint;
    ULONG_PTR ImageBase;

    BOOLEAN  HasExportTable;
    BOOLEAN  HasImportTable;
    BOOLEAN  HasRelocationTable;
    BOOLEAN  HasTLSDirectory;
    BOOLEAN  HasDebugDirectory;

    BOOLEAN  IsPacked;
    BOOLEAN  IsEncrypted;
    ULONG    OverallEntropy;
    ULONG    HighestSectionEntropy;

    WKD_PE_SECTION Sections[WKD_PE_MAX_SECTIONS];
    WKD_PE_VALIDATION_RESULT ValidationResult;
    DEF_SHA256_HASH Sha256;
} WKD_PE_DEEP_INFO, *PWKD_PE_DEEP_INFO;

/**************************************************/
/*        磁盘 vs 内存 PE 头比对 (遗留类型)           */
/**************************************************/
typedef struct _WKD_PE_HEADER_COMPARE {
    BOOLEAN HeadersMatch;
    BOOLEAN ImageBaseMatches;
    BOOLEAN EntryPointMatches;
    BOOLEAN SizeOfImageMatches;
    BOOLEAN ChecksumMatches;
    BOOLEAN TimestampMatches;
    BOOLEAN SectionCountMatches;
    BOOLEAN MachineMatches;
    ULONG   MismatchCount;
    ULONG   OverallSimilarity;
} WKD_PE_HEADER_COMPARE, *PWKD_PE_HEADER_COMPARE;

/**************************************************/
/*          安全分析结果 (遗留类型)                   */
/**************************************************/
typedef struct _WPA_SECURITY_INFO {
    BOOLEAN HasDEP;
    BOOLEAN HasASLR;
    BOOLEAN HasCFG;
    BOOLEAN HasHighEntropyASLR;
    BOOLEAN IsElevated;
} WPA_SECURITY_INFO, *PWPA_SECURITY_INFO;

/**************************************************/
/*          综合分析结果 (遗留类型)                   */
/**************************************************/
typedef struct _WPA_ANALYSIS_RESULT {
    HANDLE              ProcessId;
    WPA_PE_INFO         PE;
    WPA_SECURITY_INFO   Security;
    ULONG               SuspicionScore;
    ULONG               BehaviorFlags;
    BOOLEAN             IsSuspicious;
} WPA_ANALYSIS_RESULT, *PWPA_ANALYSIS_RESULT;

/**************************************************/
/*        进程级综合风险评分 (遗留类型)               */
/*  注: 与 IocTypes.h 的 WKD_RISK_LEVEL(文件风险)    */
/*  撞名, 此处为 WPA 业务自用, 已更名避免 C2011。     */
/**************************************************/
typedef enum _WPA_RISK_LEVEL {
    WkdRl_Trusted    = 0,
    WkdRl_Safe       = 1,
    WkdRl_Unknown    = 2,
    WkdRl_LowRisk    = 3,
    WkdRl_MediumRisk = 4,
    WkdRl_HighRisk   = 5,
    WkdRl_Suspicious = 6,
    WkdRl_Malicious  = 7,
    WkdRl_Critical   = 8,
} WPA_RISK_LEVEL, *PWPA_RISK_LEVEL;

typedef struct _WKD_RISK_INPUT {
    BOOLEAN         IsKnownMalicious;
    BOOLEAN         HashFoundMalicious;
    BOOLEAN         IsWhitelisted;

    DEF_CERT_STATUS CertStatus;

    ULONG           SuspiciousActiveModules;
    ULONG           UnsignedActiveModules;

    ULONG           RwxRegionCount;
    ULONG           UnbackedExecRegionCount;

    ULONG           UnbackedStartCount;

    BOOLEAN         ParentAnomaly;
    BOOLEAN         PpidSpoofed;

    BOOLEAN         HasProcessHollowing;
    BOOLEAN         HasDirectSyscalls;
    BOOLEAN         HasRemoteThreads;
} WKD_RISK_INPUT, *PWKD_RISK_INPUT;

/**************************************************/
/*        业务门面函数 (吸收原 Wpa*)                 */
/**************************************************/

/* 从进程内存读取并分析 PE 头 (无调用者, 保留) */
_Check_return_
HRESULT
WpeAnalyzePEHeaders(
    _In_  HANDLE      ProcessHandle,
    _In_  PVOID       ImageBaseAddress,
    _Out_ PWPA_PE_INFO PeInfo
    );

/* 从文件缓冲区分析 PE 头 (离线模式) */
_Check_return_
HRESULT
WpeAnalyzePEHeadersFromBuffer(
    _In_  PVOID       FileBuffer,
    _In_  ULONG       FileSize,
    _Out_ PWPA_PE_INFO PeInfo
    );

/* 从 PE 缓冲区解析节表 */
_Check_return_
HRESULT
WpeParseSectionHeaders(
    _In_  PVOID Buffer,
    _In_  ULONG Size,
    _Out_writes_to_(MaxSections, *Count) PWKD_PE_SECTION Sections,
    _In_  ULONG MaxSections,
    _Out_ PULONG Count
    );

/* 深度 PE 验证 (反射加载/隐藏模块确认) */
_Check_return_
HRESULT
WpeAnalyzePEDeep(
    _In_  HANDLE       ProcessHandle,
    _In_  ULONG_PTR    BaseAddress,
    _Out_ PWKD_PE_DEEP_INFO Deep
    );

/* 比对磁盘/内存 PE 头 (7 字段, ASLR/Checksum 零值豁免) */
_Check_return_
HRESULT
WpeComparePEHeaders(
    _In_  PWPA_PE_INFO Disk,
    _In_  PWPA_PE_INFO Mem,
    _Out_ PWKD_PE_HEADER_COMPARE Compare
    );



/* 计算怀疑评分 (0-100, 无调用者) */
ULONG
WpeCalculateSuspicionScore(
    _In_ PWPA_ANALYSIS_RESULT Analysis
    );

/* 检测行为标志 (无调用者) */
ULONG
WpeDetectBehaviorFlags(
    _In_ PWPA_ANALYSIS_RESULT Analysis
    );

/* 计算进程级综合风险分 (0-100) + 等级映射 */
ULONG
WpeCalculateOverallRisk(
    _In_  const WKD_RISK_INPUT* Input,
    _Out_ PWPA_RISK_LEVEL       Level
    );

/**************************************************/
/*        三处手写 PE 逻辑收敛                       */
/**************************************************/

/* 收敛 IocKnownDll 私有导出表解析: 地址→导出函数名。
 * 精确匹配 Rva == Address-ModuleBase, 跳过 forwarder。 */
NTSTATUS
WpeResolveModuleExportName(
    _In_  HANDLE    ProcessHandle,
    _In_  ULONG_PTR ModuleBase,
    _In_  ULONG_PTR Address,
    _Out_writes_(FuncLen) PWSTR FuncName,
    _In_  ULONG     FuncLen
    );

/* 收敛 MsReconstructPE: 从内存重建文件对齐 PE (死代码, 无调用者) */
NTSTATUS
WpeReconstructPeFromMemory(
    _In_  DWORD     ProcessId,
    _In_  ULONG_PTR BaseAddress,
    _Out_ PBYTE*    OutBuffer,
    _Out_ PULONG    OutSize
    );

/* 收敛 IpeValidateModuleIntegrity: 内存 vs 磁盘 PE 头完整性 (死代码, 无调用者) */
BOOLEAN
WpeValidateModuleIntegrity(
    _In_ ULONG     ProcessId,
    _In_ ULONG_PTR ModuleBase,
    _In_ PCWSTR    ModulePath
    );

/**************************************************/
/*        版本信息提取 (对齐 SS GetVersionInfoImpl)   */
/**************************************************/
typedef struct _PE_VERSION_INFO {
    BOOLEAN HasVersionInfo;
    USHORT  FileMajor;
    USHORT  FileMinor;
    USHORT  FileBuild;
    USHORT  FileRevision;
    USHORT  ProductMajor;
    USHORT  ProductMinor;
    USHORT  ProductBuild;
    USHORT  ProductRevision;
    WCHAR   CompanyName[256];
    WCHAR   FileDescription[256];
    WCHAR   FileVersion[128];
    WCHAR   InternalName[256];
    WCHAR   LegalCopyright[256];
    WCHAR   OriginalFilename[256];
    WCHAR   ProductName[256];
    WCHAR   ProductVersion[128];
} PE_VERSION_INFO, *PPE_VERSION_INFO;

/* 提取文件版本信息 (Win32 GetFileVersionInfoSizeW/GetFileVersionInfoW/VerQueryValueW,
 * 对齐 SS GetVersionInfoImpl L2508-2583)。无调用者不告警 (wkd 惯例)。 */
NTSTATUS
WpeGetVersionInfo(
    _In_  PCWSTR            FilePath,
    _Out_ PPE_VERSION_INFO Version
    );

/**************************************************/
/*        ML 特征向量 (死代码, 对齐 SS ExtractMLFeatures)  */
/**************************************************/
#define PE_ML_FEATURE_MAX      256

typedef struct _PE_ML_FEATURES {
    ULONG Count;
    FLOAT Values[PE_ML_FEATURE_MAX];
} PE_ML_FEATURES, *PPE_ML_FEATURES;

/* 提取静态 PE 特征向量 (EMBER 对齐布局骨架, 对齐 SS ExtractMLFeatures L2799-2921)。
 * 死代码: wkd 无 ONNX/PhantomCortex, 供未来 ML 融合预留。 */
NTSTATUS
WpeExtractMlFeatures(
    _In_  const PE_INFO* Info,
    _Out_ PPE_ML_FEATURES  Features
    );

/**************************************************/
/*        门面薄转发 (活代码直调点收口)              */
/*  外部禁止直接调用内部解析层函数; 此处提供 1:1     */
/*  跳转包装, 实现于 PeAnalyzer.c → PeParser/PeLazy */
/**************************************************/

/* 文件解析(路径): 替代 IocDefaultPeParseOptions + IocAnalyzePeFromFilePath */
NTSTATUS
IocAnalyzePe(
    _In_ PCWSTR ImagePath,
    _Out_ PPE_INFO Info
    );

/* 文件解析(句柄): 段式 ReadFile 按需加载, 不整文件映射; 适用于超大文件/不可映射句柄/有界内存 */
NTSTATUS
IocAnalyzeFileHandle(
    _In_ HANDLE FileHandle,
    _In_ SIZE_T Size,
    _Out_ PPE_INFO Info
    );

/* 缓冲上下文解析: 替代 IocDefaultPeParseOptions + IocpAnalyzeBufferEx (IocScanner) */
NTSTATUS
WpeParseBufferContext(
    _Inout_ PPE_PARSER_CONTEXT Ctx,
    _In_    const BYTE*        Data,
    _In_    SIZE_T             Size,
    _In_    BOOLEAN            ComputeSectionEntropy
    );

/* 重置解析上下文: 替代 WpeParseContextReset (IocScanner) */
VOID
WpeResetParseContext(
    _Inout_ PPE_PARSER_CONTEXT Ctx
    );

/* 导入表解析: 替代 IocpParseImports (IocScanner IAT 分析) */
NTSTATUS
WpeParseImportList(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_IMPORT_LIST         Out
    );

/* 导入表释放: 替代 WpeImportsFree (IocScanner) */
VOID
WpeFreeImportList(
    _Inout_ PPE_IMPORT_LIST List
    );

/* 按 RVA 读字节（static 仅 PeAnalyzer.c 内部，声明见实现处） */



/* 静态解包: 替代 WpeUnpackPackedBuffer (IocScanner 解包闭环) */
NTSTATUS
WpeUnpackBuffer(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  const BYTE*              FileData,
    _In_  SIZE_T                   FileSize,
    _Out_ PPE_UNPACK_RESULT       Result    /* 先 RtlZeroMemory; 用后 WpeFreeUnpackResult */
    );

/* 释放解包结果: 替代 WpeUnpackResultFree (IocScanner) */
VOID
WpeFreeUnpackResult(
    _Inout_ PPE_UNPACK_RESULT Result
    );

/* 按文件偏移读字节 (含范围校验): 替代 CopValidateReadingRange + IocpReaderRead
 * (IocScanner 节哈希), 内部拷贝 Reader 副本, 不污染 Ctx 页缓存 */
BOOLEAN
WpeReadBytesAtOffset(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  ULONGLONG                Offset,
    _Out_ void*                    Out,
    _In_  SIZE_T                   Size
    );

/* 延迟导入解析: 替代 WpeParseDelayImports (IocScanner 延迟导入分析) */
NTSTATUS
WpeParseDelayImportList(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_DELAY_IMPORT_LIST   Out
    );

/* 释放延迟导入结果: 替代 WpeDelayImportsFree (IocScanner) */
VOID
WpeFreeDelayImportList(
    _Inout_ PPE_DELAY_IMPORT_LIST List
    );

/**************************************************/
/*        PE 启发式静态分析 (迁移自 IocScanner.c)    */
/*  文件级静态启发式主入口, 强耦合 IOC_SCAN_RESULT   */
/*  (IocAnalyzePe 的结果直写变体), 由扫描编排调用。  */
/**************************************************/

/* 从已解析几何 (PE_INFO) + 文件字节缓冲重建惰性解析 Ctx。
 * 供深度分析复用构建期 IocAnalyzePe 产物，消除对同一文件
 * 的第二次完整 PE 结构解析 (2026-08-19 Ctx 基座)：
 *   - Ctx->Info / RawSections[] 从 Info 几何直拷
 *   - Ctx->Reader 由 View/Size 构造 (Buffer 模式)
 * View 可 NULL：此时仅填几何，Reader.Size 钳 0 (调用方自行填)。
 * 返回 STATUS_INVALID_IMAGE_FORMAT = Info 无效 (Ctx 未初始化)。 */
NTSTATUS
WpeBuildLazyContextFromInfo(
    _In_      const PE_INFO*        Info,
    _In_opt_  const BYTE*           View,
    _In_      SIZE_T                Size,
    _Out_     PPE_PARSER_CONTEXT    Ctx
    );

/* 文件级启发式静态分析: 一次内存映射 + 全量 PE 解析,
 * 加壳/导入/字符串/异常 4 维聚合为 HeuristicConfidence (0-1000)。
 * PeInfo 可选 (2026-08-19)：非 NULL 且 Valid 时据此重建惰性 Ctx，
 * 免第二次完整解析；NULL 则内部自解析兜底。 */
VOID
IocHeuristicPeAnalysis(
    _In_opt_ PCWSTR              FilePath,
    _In_opt_ const PE_INFO*      PeInfo,
    _Inout_  IOC_SCAN_RESULT*    Result
    );
