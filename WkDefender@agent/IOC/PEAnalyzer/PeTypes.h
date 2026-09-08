/**************************************************/
/*  WkDefender PEAnalyzer — 公共类型头              */
/*  对外可暴露; 仅含解析上下文链 / 惰性输出 / 解包   */
/*  门面所需类型 + 外部直接使用的常量。             */
/*  依赖仅 <windows.h>, 禁止 include 任何内部头。    */
/*  外部唯一入口 = PeAnalyzer.h (本头经其带出)。     */
/*  纯内部 pack 磁盘结构与函数声明见 PeInternal.h。  */
/**************************************************/

#pragma once

#include <windows.h>
/* PWKD_PROCESS（PE_PARSER_CONTEXT 内嵌字段 VerifyProcess, 2026-09-07）
 * 本头自足声明：PeInternal.h 等内部头直接含本头时也能安全解析 */
#include "../../Process/ProcessTypes.h"

/**************************************************/
/*              公共 Limits (数组维度/外部使用)      */
/**************************************************/
#define PE_MAX_SECTIONS                96
#define PE_MAX_SECTION_NAME            8
#define PE_MAX_DLL_NAME                64
#define PE_MAX_FUNCTION_NAME           256
#define PE_MAX_TLS_CALLBACKS           1000
#define PE_MAX_DEBUG_ENTRIES           100
#define PE_MAX_RICH_ENTRIES            1000
#define PE_MAX_PDB_PATH_LENGTH         1024
#define PE_MAX_DOTNET_FRAMEWORK        64
#define PE_MAX_ANOMALIES               256

/**************************************************/
/*        PE 签名/魔数/节特性/DllChar 常量           */
/*        (对齐 IMAGE_* 标准值)                     */
/**************************************************/
#define PE_PE64_MAGIC                   0x20B
#define PE_DD_MAX_ENTRIES               16

#define PE_SCH_CNT_CODE                 0x00000020
#define PE_SCH_CNT_INITIALIZED_DATA     0x00000040
#define PE_SCH_MEM_EXECUTE              0x20000000
#define PE_SCH_MEM_READ                 0x40000000
#define PE_SCH_MEM_WRITE                0x80000000

#define PE_DLLC_DYNAMIC_BASE            0x0040
#define PE_DLLC_FORCE_INTEGRITY         0x0080
#define PE_DLLC_NX_COMPAT               0x0100
#define PE_DLLC_NO_SEH                  0x0400
#define PE_DLLC_GUARD_CF                0x4000

/**************************************************/
/*           校验结果枚举 (ValidationResult)         */
/**************************************************/
typedef enum _PE_VALIDATION_RESULT {
    WpeVal_Valid = 0,

    /* 通用错误 (1-9) */
    WpeVal_UnknownError = 1,
    WpeVal_FileTooSmall = 2,
    WpeVal_FileTooLarge = 3,
    WpeVal_NullPointer = 4,
    WpeVal_IntegerOverflow = 5,
    WpeVal_PathTooLong = 6,
    WpeVal_InvalidParameters = 7,

    /* DOS 头失败 (10-29) */
    WpeVal_InvalidDosSignature = 10,
    WpeVal_InvalidLfanew = 11,
    WpeVal_LfanewOutOfBounds = 12,
    WpeVal_LfanewNegative = 13,
    WpeVal_LfanewUnaligned = 14,
    WpeVal_LfanewTooSmall = 15,
    WpeVal_LfanewTooLarge = 16,

    /* NT 头失败 (30-59) */
    WpeVal_InvalidNtSignature = 30,
    WpeVal_InvalidMachine = 31,
    WpeVal_InvalidOptionalMagic = 32,
    WpeVal_NumberOfSectionsZero = 33,
    WpeVal_NumberOfSectionsOverflow = 34,
    WpeVal_SizeOfOptionalHeaderInvalid = 35,
    WpeVal_SizeOfOptionalHeaderTooSmall = 36,
    WpeVal_SizeOfOptionalHeaderTooLarge = 37,
    WpeVal_NtHeadersOutOfBounds = 38,
    WpeVal_InvalidFileAlignment = 39,
    WpeVal_InvalidSectionAlignment = 40,
    WpeVal_FileAlignmentGreaterThanSection = 41,
    WpeVal_SizeOfImageZero = 42,
    WpeVal_SizeOfHeadersZero = 43,
    WpeVal_SizeOfHeadersTooLarge = 44,
    WpeVal_NumberOfRvaAndSizesInvalid = 45,
    WpeVal_InvalidAddressOfEntryPoint = 46,
    WpeVal_InvalidImageBase = 47,
    WpeVal_InvalidSubsystem = 48,
    WpeVal_SizeOfStackCommitExceedsReserve = 49,
    WpeVal_SizeOfHeapCommitExceedsReserve = 50,
    WpeVal_SizeOfImageNotAligned = 51,
    WpeVal_SizeOfHeadersNotAligned = 52,

    /* 节失败 (60-99) */
    WpeVal_SectionTableOutOfBounds = 60,
    WpeVal_SectionTableOverflow = 61,
    WpeVal_SectionCountMismatch = 62,
    WpeVal_SectionNameInvalid = 63,
    WpeVal_SectionVirtualAddressZero = 64,
    WpeVal_SectionVirtualSizeZero = 65,
    WpeVal_SectionRawAddressInvalid = 66,
    WpeVal_SectionRawSizeInvalid = 67,
    WpeVal_SectionBeyondFile = 68,
    WpeVal_SectionBeyondImage = 69,
    WpeVal_SectionOverlap = 70,
    WpeVal_SectionAlignmentViolation = 71,
    WpeVal_SectionCharacteristicsInvalid = 72,
    WpeVal_SectionWritableExecutable = 73,
    WpeVal_EntryPointOutsideSections = 74,
    WpeVal_EntryPointInNonExecutable = 75,

    /* 数据目录失败 (100-129) */
    WpeVal_DataDirectoryOutOfBounds = 100,
    WpeVal_DataDirectorySizeInvalid = 101,
    WpeVal_DataDirectoryRvaInvalid = 102,
    WpeVal_ImportDirectoryInvalid = 103,
    WpeVal_ExportDirectoryInvalid = 104,
    WpeVal_ResourceDirectoryInvalid = 105,
    WpeVal_TLSDirectoryInvalid = 106,
    WpeVal_RelocDirectoryInvalid = 107,
    WpeVal_DebugDirectoryInvalid = 108,
    WpeVal_SecurityDirectoryInvalid = 109,
    WpeVal_CLRDirectoryInvalid = 110,
    WpeVal_BoundImportInvalid = 111,
    WpeVal_DelayImportInvalid = 112,
    WpeVal_LoadConfigInvalid = 113,

    /* 导入表失败 (130-159) */
    WpeVal_ImportDescriptorOutOfBounds = 130,
    WpeVal_ImportDllNameOutOfBounds = 131,
    WpeVal_ImportDllNameTooLong = 132,
    WpeVal_ImportThunkOutOfBounds = 133,
    WpeVal_ImportByNameOutOfBounds = 134,
    WpeVal_ImportFunctionNameTooLong = 135,
    WpeVal_ImportOrdinalInvalid = 136,
    WpeVal_ImportCircularReference = 137,
    WpeVal_ImportCountExceeded = 138,

    /* 导出表失败 (160-179) */
    WpeVal_ExportDirectoryOutOfBounds = 160,
    WpeVal_ExportNameOutOfBounds = 161,
    WpeVal_ExportOrdinalOutOfBounds = 162,
    WpeVal_ExportAddressOutOfBounds = 163,
    WpeVal_ExportForwarderInvalid = 164,
    WpeVal_ExportCountExceeded = 165,

    /* TLS 失败 (180-199) */
    WpeVal_TLSDirectoryOutOfBounds = 180,
    WpeVal_TLSCallbacksOutOfBounds = 181,
    WpeVal_TLSCallbackCountExceeded = 182,
    WpeVal_TLSDataOutOfBounds = 183,
    WpeVal_TLSCallbackInNonExecutable = 184,

    /* 资源失败 (200-229) */
    WpeVal_ResourceDirectoryOutOfBounds = 200,
    WpeVal_ResourceDepthExceeded = 201,
    WpeVal_ResourceCircularReference = 202,
    WpeVal_ResourceEntryCountExceeded = 203,
    WpeVal_ResourceDataOutOfBounds = 204,
    WpeVal_ResourceNameOutOfBounds = 205,

    /* 重定位失败 (230-249) */
    WpeVal_RelocationBlockOutOfBounds = 230,
    WpeVal_RelocationBlockSizeInvalid = 231,
    WpeVal_RelocationEntryInvalid = 232,
    WpeVal_RelocationCountExceeded = 233,
    WpeVal_RelocationCircularReference = 234,

    /* Debug 目录失败 (250-269) */
    WpeVal_DebugEntryOutOfBounds = 250,
    WpeVal_DebugDataOutOfBounds = 251,
    WpeVal_DebugCountExceeded = 252,
    WpeVal_DebugTypeUnknown = 253,

    /* Rich 头失败 (270-289) */
    WpeVal_RichHeaderNotFound = 270,
    WpeVal_RichHeaderCorrupted = 271,
    WpeVal_RichHeaderChecksumMismatch = 272,
    WpeVal_RichEntryCountExceeded = 273,

    /* Authenticode 失败 (290-309) */
    WpeVal_SignatureDirectoryInvalid = 290,
    WpeVal_SignatureOutOfBounds = 291,
    WpeVal_SignatureFormatInvalid = 292,
} PE_VALIDATION_RESULT, *PPE_VALIDATION_RESULT;

/**************************************************/
/*             异常类型枚举 (AnomalyType)            */
/**************************************************/
typedef enum _PE_ANOMALY_TYPE {
    WpeAnom_None = 0,

    /* 头异常 */
    WpeAnom_DosStubMissing,
    WpeAnom_DosStubModified,
    WpeAnom_MultiplePeSignatures,
    WpeAnom_UnusualLfanew,
    WpeAnom_TimestampInFuture,
    WpeAnom_TimestampZero,
    WpeAnom_TimestampVeryOld,
    WpeAnom_ChecksumMismatch,
    WpeAnom_ChecksumZero,
    WpeAnom_SubsystemMismatch,

    /* 节异常 */
    WpeAnom_SectionNameEmpty,
    WpeAnom_SectionNameNonPrintable,
    WpeAnom_SectionNameSuspicious,
    WpeAnom_SectionWritableExecutable,
    WpeAnom_SectionZeroRawSize,
    WpeAnom_SectionHighEntropy,
    WpeAnom_SectionLowEntropy,
    WpeAnom_SectionSizeMismatch,
    WpeAnom_TooManySections,
    WpeAnom_UnusualSectionOrder,
    WpeAnom_OverlappingSections,     /* 节物理(raw)/虚拟(VA)重叠 — 对齐 SS DetectOverlappingSectionsImpl */
    WpeAnom_CodeOutsideCodeSection,
    WpeAnom_SectionAlignmentViolation,

    /* 入口点异常 */
    WpeAnom_EntryPointInHeader,
    WpeAnom_EntryPointInLastSection,
    WpeAnom_EntryPointInWritableSection,
    WpeAnom_EntryPointNearEnd,
    WpeAnom_EntryPointZero,
    WpeAnom_EntryPointOutsideFile,

    /* 导入异常 */
    WpeAnom_NoImports,
    WpeAnom_SuspiciousImports,
    WpeAnom_ApiHashing,
    WpeAnom_DelayLoadSuspicious,

    /* 导出异常 */
    WpeAnom_ExportsInExecutable,
    WpeAnom_SuspiciousExportNames,
    WpeAnom_ForwardedExports,

    /* TLS 异常 */
    WpeAnom_TLSCallbackPresent,
    WpeAnom_TLSCallbackInWritable,
    WpeAnom_MultipleTLSCallbacks,

    /* 资源异常 */
    WpeAnom_ResourcesContainPE,
    WpeAnom_ResourcesHighEntropy,
    WpeAnom_ResourceSizeAnomaly,

    /* 加壳/保护指示 */
    WpeAnom_PackerSignatureDetected,
    WpeAnom_OverlayPresent,
    WpeAnom_OverlayHighEntropy,
    WpeAnom_OverlayContainsPE,       /* overlay 数据起点含 MZ 头 (dropper) — 对齐 SS AnalyzeOverlayImpl */
    WpeAnom_LargeOverlay,            /* overlay >1MB — 对齐 SS DetectAnomaliesImpl */
    WpeAnom_SelfModifyingCode,

    /* .NET 异常 */
    WpeAnom_DotNetNativeCode,
    WpeAnom_DotNetObfuscated,

    /* 安全异常 */
    WpeAnom_NoASLR,
    WpeAnom_NoDEP,
    WpeAnom_NoSEH,
    WpeAnom_NoCFG,
    WpeAnom_WeakChecksum,
} PE_ANOMALY_TYPE, *PPE_ANOMALY_TYPE;

/**************************************************/
/*              异常记录 (Anomaly)                  */
/*  Description / Context 指向静态字符串字面量。     */
/**************************************************/
typedef struct _PE_ANOMALY {
    PE_ANOMALY_TYPE Type;
    PCWSTR Description;     /* 非拥有, 指向静态串 */
    ULONG64 Offset;
    PCWSTR Context;         /* 非拥有, 指向静态串 */
} PE_ANOMALY, *PPE_ANOMALY;

/**************************************************/
/*              错误结构 (PEError)                  */
/**************************************************/
typedef struct _PE_PARSER_ERROR {
    PE_VALIDATION_RESULT Code;
    PCWSTR Message;         /* 非拥有, 指向静态串 */
    ULONG64 Offset;
    PCWSTR Context;         /* 非拥有, 指向静态串 */
    ULONG Win32Error;
} PE_PARSER_ERROR, *PPE_PARSER_ERROR;

/**************************************************/
/*              读取器模式                          */
/**************************************************/
typedef enum _PE_READER_MODE {
    PeReader_Buffer = 0,    /* 外部整块缓冲（内存流/已 map view），段 Base 直接指向外部 */
    PeReader_Process = 1,   /* 进程内存：ReadProcessMemory 4KB 段 */
    PeReader_File   = 2,    /* 文件句柄：ReadFile 4KB 段（reader 不拥有句柄） */
} PE_READER_MODE, *PPE_READER_MODE;

/**************************************************/
/*              分段 LRU 缓存                       */
/*  每段 4KB 本地缓冲，按源偏移 4KB 对齐索引；       */
/*  LRU 淘汰最久未访问段（固定 16 段上限，内存可控）。 */
/*  Buffer 模式段 Base 直接指向外部缓冲（不拷贝）；  */
/*  File/Process 模式段 Base 指向本段 Data（RPM/ReadFile 填充）。 */
/**************************************************/
#define PE_SEGMENT_SIZE     4096
#define PE_SEGMENT_COUNT    16

typedef struct _PE_SEGMENT {
    BOOLEAN     Valid;
    PBYTE       Data;        /* 本地 4KB 缓冲（构造时一次性分配；Buffer 模式空闲不用） */
    SIZE_T      Offset;   /* 该段覆盖的源偏移（已 4KB 对齐） */
    ULONG64     LruSeq;      /* LRU 序号（越大越新） */
} PE_SEGMENT, *PPE_SEGMENT;

/**************************************************/
/*              安全读取器                          */
/*  统一分段 LRU：Buffer/File/Process 三模式对称，   */
/*  调用方只见到 IocpReaderRead（返回指针）或        */
/*  _IocpReaderCopy（拷贝到调用方缓冲），不感知模式。 */
/**************************************************/
typedef struct _PE_READER {
    PE_READER_MODE  Mode;
    const BYTE*     Data;          /* Buffer 模式：外部整块缓冲 */
    SIZE_T          Size;          /* 当前解析域大小 */
    HANDLE          FileHandle;    /* File 模式：文件句柄（不拥有，调用方关闭） */
    ULONG_PTR       BaseAddress;   /* Process 模式：映像基址 */
    HANDLE          ProcessHandle; /* Process 模式：RPM 句柄（不拥有） */
    PE_SEGMENT      Segments[PE_SEGMENT_COUNT];
    ULONG64         LruClock;      /* 全局递增 LRU 时钟 */
    BYTE*           Scratch;       /* 跨段拼接缓冲（懒分配，IocReaderDestroy 释放） */
    SIZE_T          ScratchCap;
} PE_READER, *PPE_READER;

/**************************************************/
/*    pack(1) 公共磁盘结构 (须保持文件布局)          */
/**************************************************/
#pragma pack(push, 1)

/* 数据目录条目 (增强版, 24 字节) */
typedef struct _IMAGE_DATA_DIRECTORY_EX {
    ULONG   Rva;
    ULONG   Size;
    BOOLEAN Present;
    BOOLEAN HasFileOffset;  /* SECURITY 目录此处存文件偏移(特例) */
    ULONG   FileOffset;     /* 0xFFFFFFFF = 未解析 */
} IMAGE_DATA_DIRECTORY_EX, *PIMAGE_DATA_DIRECTORY_EX;

#pragma pack(pop)

/**************************************************/
/*             节信息                              */
/**************************************************/
typedef struct _PE_SECTION {
    CHAR    Name[PE_MAX_SECTION_NAME + 1];
    ULONG   VirtualSize;
    ULONG   VirtualAddress;
    ULONG   SizeOfRawData;
    ULONG   PointerToRawData;
    ULONG   Characteristics;
    BOOLEAN IsExecutable;
    BOOLEAN IsWritable;
    BOOLEAN IsReadable;
    BOOLEAN HasCode;
    BOOLEAN HasInitializedData;
    BOOLEAN HasUninitializedData;
    DOUBLE  ShannonEntropy;     /* -1.0 = 未计算 */
    BOOLEAN IsPackedHeuristic;  /* 香农 >7.0 且可执行/含码 */
} PE_SECTION, *PPE_SECTION;

/**************************************************/
/*             完整 PE 信息                         */
/*  数据目录索引 (DataDirectories[] 下标)            */
/**************************************************/
#define PE_DD_EXPORT          0
#define PE_DD_RESOURCE        2
#define PE_DD_EXCEPTION       3
#define PE_DD_SECURITY        4
#define PE_DD_BASERELOC       5
#define PE_DD_DEBUG           6
#define PE_DD_ARCHITECTURE    7
#define PE_DD_GLOBALPTR       8
#define PE_DD_TLS             9
#define PE_DD_LOAD_CONFIG     10
#define PE_DD_BOUND_IMPORT    11
#define PE_DD_IAT             12
#define PE_DD_DELAY_IMPORT    13
#define PE_DD_COM_DESCRIPTOR  14

typedef struct _PE_INFO {
    BOOLEAN Valid;
    BOOLEAN Amd64;
    BOOLEAN IsDotNet;
    BOOLEAN IsSigned;
    BOOLEAN IsDll;
    BOOLEAN IsDriver;
    CHAR    DotNetTargetFramework[PE_MAX_DOTNET_FRAMEWORK];

    /* IMAGE_FILE_HEADER */
    USHORT  Machine;
    USHORT  NumberOfSections;
    USHORT  Characteristics;
    ULONG   TimeDateStamp;

    ULONG64 ImageBase;
    ULONG   AddressOfEntryPoint;
    ULONG   SizeOfImage;
    ULONG   SizeOfHeaders;
    ULONG   Checksum;
    USHORT  Subsystem;
    USHORT  DllCharacteristics;
    ULONG   FileAlignment;
    ULONG   SectionAlignment;
    
    UCHAR   MajorLinkerVersion;
    UCHAR   MinorLinkerVersion;
    USHORT  MajorOsVersion;
    USHORT  MinorOsVersion;
    BOOLEAN HasForceIntegrity;
    BOOLEAN IsAppContainer;

    PE_SECTION Sections[PE_MAX_SECTIONS];

    IMAGE_DATA_DIRECTORY_EX DataDirectories[16];

    BOOLEAN EntryPointInExecutableSection;
    ULONG   EntryPointSectionIndex;   /* 0xFFFFFFFF = 无归属 */

    SIZE_T  FileSize;                 /* 文件模式=文件字节数; 内存模式=解析域 */
    ULONG   OverlayOffset;            /* 0 = 无 overlay */
    SIZE_T  OverlaySize;
    BOOLEAN OverlayContainsPE;

    PE_ANOMALY Anomalies[PE_MAX_ANOMALIES];
    ULONG       AnomalyCount;

    ULONG64 ParseTimeNs;
} PE_INFO, *PPE_INFO;

/**************************************************/
/*             解析选项                            */
/**************************************************/
typedef struct _PE_PARSE_OPTIONS {
    BOOLEAN ComputeSectionEntropy;  /* 默认 FALSE; 深验/加壳判定置 TRUE */
    BOOLEAN CollectAnomalies;       /* 默认 TRUE */
    BOOLEAN DetectOverlay;          /* 仅文件模式, 默认 TRUE */
    BOOLEAN VerifyChecksum;         /* 仅文件模式, 默认 TRUE */
    BOOLEAN AnalyzeContentAnomalies;/* 内容级异常, 默认 FALSE */
} PE_PARSE_OPTIONS, *PPE_PARSE_OPTIONS;

/**************************************************/
/*       导入校验回调 (双 reader 模式, 2026-09-07)   */
/*                                                  */
/*  回调数组挂 PE_PARSER_CONTEXT::ImportVerify:      */
/*   [0]=常规导入表, [1]=延迟导入表。回调非 NULL 时   */
/*  PepParseImports/WpeParseDelayImports 截断到 DLL  */
/*  层（不再展开 Functions），逐 DLL 调回调；回调内  */
/*  for 循环处理该 DLL 全部函数，用主 reader(内存)    */
/*  读 IAT 槽实际值 + 校验 reader(文件)读 INT 槽权威  */
/*  函数名 + 目标 DLL 导出表(临时 ctx)计算期望。      */
/**************************************************/
#define PE_MAX_IMPORT_VERIFY_CALLBACKS  2

/* 回调签名：DllInfo 按槽位解释（[0]=PE_IMPORT_DLL*, [1]=PE_DELAY_IMPORT_DLL*）。
 * 回调返回 STATUS_SUCCESS 且 *Terminated=TRUE 表示命中/提前终止整表。
 * VerifyHit 为门面（PeVerifyFunctionAddressTable）经 ImportVerify[i].Context 注入的
 * PPE_IMPORT_VERIFY_HIT 命中输出；VerifyProcess/VerifyProcessHandle 取自
 * Ctx->VerifyProcess/Ctx->VerifyProcessHandle（2026-09-07 重构：调用方上下文
 * PE_IMPORT_VERIFY_CONTEXT 已废除，输入全部内聚于解析上下文，输出由门面托管）。 */
typedef NTSTATUS (*PE_IMPORT_VERIFY_CALLBACK)(
    _In_ const struct _PE_PARSER_CONTEXT* Ctx,   /* 主解析上下文（内存模式 Reader + VerifyReader） */
    _In_ const void* DllInfo,                    /* [0]=PE_IMPORT_DLL* / [1]=PE_DELAY_IMPORT_DLL* */
    _In_ PCWSTR DllName,                         /* 当前 DLL 宽名（NameBlob 解析，可 NULL） */
    _Inout_ void* VerifyHit,                     /* PPE_IMPORT_VERIFY_HIT（门面注入的命中输出） */
    _Out_ BOOLEAN* Terminated                    /* 置 TRUE 提前终止整表 */
    );

typedef struct _PE_IMPORT_VERIFY_CALLBACK_ENTRY {
    PE_IMPORT_VERIFY_CALLBACK Callback;
    PVOID  Context;                              /* 门面注入：PPE_IMPORT_VERIFY_HIT（槽位对应） */
} PE_IMPORT_VERIFY_CALLBACK_ENTRY, *PPE_IMPORT_VERIFY_CALLBACK_ENTRY;

/* 导入校验命中输出（2026-09-07 重构）：PE_IMPORT_VERIFY_CONTEXT 废除后，
 * 输出内聚为精简结构，由门面 PeVerifyFunctionAddressTable 以
 * PE_IMPORT_VERIFY_RESULT 聚合（Iat=[0] 常规 / Delay=[1] 延迟）经回调注入。 */
typedef struct _PE_IMPORT_VERIFY_HIT {
    BOOLEAN    Found;              /* TRUE=检测到导入槽被篡改（期望≠实际） */
    WCHAR      DllName[PE_MAX_DLL_NAME + 1];       /* 命中 DLL 宽名 */
    CHAR       FuncName[PE_MAX_FUNCTION_NAME + 1]; /* 命中函数 ANSI 名（Ordinal≠0 时为空） */
    USHORT     Ordinal;            /* 按序号导入时的序号（ByName 时为 0） */
    ULONG_PTR  ExpectedAddress;    /* 期望地址（文件 INT 权威 + 目标 DLL 导出目录推导） */
    ULONG_PTR  ActualAddress;      /* IAT 槽实际值（内存 reader 读取） */
} PE_IMPORT_VERIFY_HIT, *PPE_IMPORT_VERIFY_HIT;

/* 导入表校验聚合结果：一次门面调用覆盖常规 + 延迟导入表（复用同一
 * 进程句柄 / 主模块域 / 校验 reader）。AntiDebug 按 Found 映射两类技术。 */
typedef struct _PE_IMPORT_VERIFY_RESULT {
    PE_IMPORT_VERIFY_HIT Iat;      /* 常规导入表（ImportVerify[0] 回调回填） */
    PE_IMPORT_VERIFY_HIT Delay;    /* 延迟导入表（ImportVerify[1] 回调回填） */
} PE_IMPORT_VERIFY_RESULT, *PPE_IMPORT_VERIFY_RESULT;

/**************************************************/
/*             解析上下文                           */
/**************************************************/
typedef struct _PE_PARSER_CONTEXT {
    PE_READER       Reader;
    PE_INFO         Info;

    IMAGE_SECTION_HEADER RawSections[PE_MAX_SECTIONS];
    ULONG           RawSectionCount;

    ULONG           NtHeaderOffset;
    ULONG           OptionalHeaderOffset;
    ULONG           SectionTableOffset;

    PE_PARSER_ERROR Error;
    BOOLEAN         Parsed;
    BOOLEAN         IsMemoryMode;   /* 内存模式: RvaToOffset 恒等 */
    PE_PARSE_OPTIONS Options;

    /* 导入校验回调（2026-09-07）：非 NULL 时导入解析截断到 DLL 层逐回调校验。
     * [0]=常规导入表, [1]=延迟导入表。Context 由门面注入对应槽位的
     * PPE_IMPORT_VERIFY_HIT（命中回填）。 */
    PE_IMPORT_VERIFY_CALLBACK_ENTRY ImportVerify[PE_MAX_IMPORT_VERIFY_CALLBACKS];
    /* 校验 reader（文件模式，主模块磁盘副本）：回调内经节表换算读取磁盘 INT/IAT 槽，
     * 与主 reader（内存模式, Ctx->Reader）双 reader 比对。门面负责构造与销毁。 */
    PE_READER       VerifyReader;
    /* 校验载体（2026-09-07 重构, PE_IMPORT_VERIFY_CONTEXT 废除后内聚）：
     * VerifyProcess      = 目标 WKD_PROCESS（回调查目标 DLL 模块表基址用, 强转自 PVOID）；
     * VerifyProcessHandle = 目标进程句柄（回调做目标 DLL 导出目录解析临时 ctx 用），
     *                       句柄所有权归门面，解析结束后由门面关闭。 */
    PWKD_PROCESS    VerifyProcess;
    HANDLE          VerifyProcessHandle;
} PE_PARSER_CONTEXT, *PPE_PARSER_CONTEXT;

/**************************************************/
/*             导入 (惰性输出)                      */
/**************************************************/
typedef struct _PE_IMPORT_FUNC {
    ULONG   NameOffset;   /* NameBlob 内 WCHAR 偏移 (0 = 无名/按序号) */
    ULONG   NameLength;
    USHORT  Ordinal;
    USHORT  Hint;
    BOOLEAN ByOrdinal;
    ULONG64 IatRva;
} PE_IMPORT_FUNC, *PPE_IMPORT_FUNC;

typedef struct _PE_IMPORT_DLL {
    ULONG   NameOffset;
    ULONG   NameLength;
    ULONG   FunctionCount;
    PE_IMPORT_FUNC* Functions;
    BOOLEAN IsBoundImport;
    BOOLEAN IsDelayLoad;
    BOOLEAN IsKnownSystem;
    ULONG   OriginalFirstThunk; // 导入名称表(INT) Rva
    ULONG   FirstThunk;         // 导入地址表(IAT) Rva
} PE_IMPORT_DLL, *PPE_IMPORT_DLL;

typedef struct _PE_IMPORT_LIST {
    ULONG   DllCount;
    PPE_IMPORT_DLL Dlls;
    PWCHAR  NameBlob;
    ULONG   NameBlobChars;
} PE_IMPORT_LIST, *PPE_IMPORT_LIST;

/**************************************************/
/*             导出 (惰性输出)                      */
/**************************************************/
typedef struct _PE_EXPORT {
    ULONG   NameOffset;       /* 0 = 按序号导出 */
    ULONG   NameLength;
    ULONG   Ordinal;
    ULONG   Rva;
    BOOLEAN IsForwarder;
    BOOLEAN ByName;
    BOOLEAN IsSuspicious;
    ULONG   ForwarderOffset;
    ULONG   ForwarderLength;
} PE_EXPORT, *PPE_EXPORT;

typedef struct _PE_EXPORT_DIR {
    ULONG   DllNameOffset;
    ULONG   DllNameLength;
    ULONG   OrdinalBase;
    ULONG   NumberOfFunctions;
    ULONG   NumberOfNames;
    ULONG   ExportCount;
    PE_EXPORT* Exports;
    PWCHAR  NameBlob;
    ULONG   NameBlobChars;
} PE_EXPORT_DIR, *PPE_EXPORT_DIR;

/**************************************************/
/*             TLS (惰性输出)                       */
/**************************************************/
typedef struct _PE_TLS_INFO {
    ULONG64 StartAddressOfRawData;
    ULONG64 EndAddressOfRawData;
    ULONG64 AddressOfIndex;
    ULONG64 AddressOfCallbacks;
    ULONG   CallbackCount;
    ULONG64 Callbacks[PE_MAX_TLS_CALLBACKS];
    ULONG64 CallbacksRva[PE_MAX_TLS_CALLBACKS];
    ULONG   SizeOfZeroFill;
    ULONG   Characteristics;
} PE_TLS_INFO, *PPE_TLS_INFO;

/**************************************************/
/*            重定位 (惰性输出)                     */
/**************************************************/
typedef struct _PE_RELOCATION_ENTRY {
    ULONG   Rva;
    USHORT  Type;
} PE_RELOCATION_ENTRY, *PPE_RELOCATION_ENTRY;

typedef struct _PE_RELOCATION_BLOCK {
    ULONG   PageRva;
    ULONG   EntryCount;
    PE_RELOCATION_ENTRY* Entries;
} PE_RELOCATION_BLOCK, *PPE_RELOCATION_BLOCK;

typedef struct _PE_RELOCATION_LIST {
    ULONG   BlockCount;
    PE_RELOCATION_BLOCK* Blocks;
} PE_RELOCATION_LIST, *PPE_RELOCATION_LIST;

/**************************************************/
/*             Debug 目录 (惰性输出)                */
/**************************************************/
typedef struct _PE_DEBUG_INFO {
    ULONG   Type;
    ULONG   Timestamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   SizeOfData;
    ULONG   AddressOfRawData;
    ULONG   PointerToRawData;
    WCHAR   PdbPath[PE_MAX_PDB_PATH_LENGTH];
    BYTE    PdbGuid[16];
    ULONG   PdbAge;
} PE_DEBUG_INFO, *PPE_DEBUG_INFO;

typedef struct _PE_DEBUG_LIST {
    ULONG   EntryCount;
    PE_DEBUG_INFO Entries[PE_MAX_DEBUG_ENTRIES];
} PE_DEBUG_LIST, *PPE_DEBUG_LIST;

/**************************************************/
/*             Rich 头 (惰性输出)                   */
/**************************************************/
typedef struct _PE_RICH_ENTRY {
    USHORT  BuildId;
    USHORT  ProductId;
    ULONG   UseCount;
    CHAR    ProductName[16];
} PE_RICH_ENTRY, *PPE_RICH_ENTRY;

typedef struct _PE_RICH_HEADER_INFO {
    BOOLEAN Present;
    BOOLEAN Valid;
    BOOLEAN IsPossibleFake;
    ULONG   Checksum;
    SIZE_T  Offset;
    SIZE_T  Size;
    ULONG   EntryCount;
    PE_RICH_ENTRY Entries[PE_MAX_RICH_ENTRIES];
} PE_RICH_HEADER_INFO, *PPE_RICH_HEADER_INFO;

/**************************************************/
/*             延迟导入 (惰性输出)                  */
/**************************************************/
typedef struct _PE_DELAY_IMPORT_DLL {
    ULONG   NameOffset;
    ULONG   NameLength;
    ULONG   FunctionCount;
    PE_IMPORT_FUNC* Functions;
    ULONG   Attributes;
    ULONG   ModuleHandleRva;
    ULONG   IatRva;
    ULONG   IntRva;
    ULONG   BoundIatRva;
    ULONG   UnloadIatRva;
    ULONG   TimeDateStamp;
} PE_DELAY_IMPORT_DLL, *PPE_DELAY_IMPORT_DLL;

typedef struct _PE_DELAY_IMPORT_LIST {
    ULONG   DllCount;
    PE_DELAY_IMPORT_DLL* Dlls;
    PWCHAR  NameBlob;
    ULONG   NameBlobChars;
} PE_DELAY_IMPORT_LIST, *PPE_DELAY_IMPORT_LIST;

/**************************************************/
/*             加载配置目录 (惰性输出)               */
/**************************************************/
typedef struct _PE_LOAD_CONFIG_INFO {
    ULONG   Size;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   GlobalFlagsClear;
    ULONG   GlobalFlagsSet;
    ULONG64 SecurityCookie;
    ULONG64 SeHandlerTable;
    ULONG64 SeHandlerCount;
    BOOLEAN HasSeh;
    BOOLEAN HasSecurityCookie;
    ULONG64 GuardCFFunctionTable;
    ULONG64 GuardCFFunctionCount;
    ULONG   GuardFlags;
    BOOLEAN HasGuardCF;
    BOOLEAN HasCET;
} PE_LOAD_CONFIG_INFO, *PPE_LOAD_CONFIG_INFO;

/**************************************************/
/*             Exception 目录 (惰性输出, x64)       */
/**************************************************/
typedef struct _PE_EXCEPTION_ENTRY {
    ULONG   BeginAddress;
    ULONG   EndAddress;
    ULONG   UnwindInfoAddress;
} PE_EXCEPTION_ENTRY, *PPE_EXCEPTION_ENTRY;

typedef struct _PE_EXCEPTION_LIST {
    ULONG   EntryCount;
    PE_EXCEPTION_ENTRY* Entries;
} PE_EXCEPTION_LIST, *PPE_EXCEPTION_LIST;

/**************************************************/
/*             资源 (惰性输出)                      */
/**************************************************/
typedef struct _PE_RESOURCE_ENTRY {
    ULONG   Type;
    ULONG   Name;
    ULONG   Language;
    ULONG   Offset;
    ULONG   Size;
    ULONG   CodePage;
    BOOLEAN NameIsString;
    ULONG   NameStringOffset;
    ULONG   NameStringLength;
    BOOLEAN ContainsPE;
    BOOLEAN IsScript;
    BOOLEAN IsEncrypted;
    DOUBLE  Entropy;
    CHAR    TypeName[16];
} PE_RESOURCE_ENTRY, *PPE_RESOURCE_ENTRY;

typedef struct _PE_RESOURCE_LIST {
    ULONG   EntryCount;
    PE_RESOURCE_ENTRY* Entries;
    PWCHAR  NameBlob;
    ULONG   NameBlobChars;
} PE_RESOURCE_LIST, *PPE_RESOURCE_LIST;

/**************************************************/
/*             解包常量                            */
/**************************************************/
#define PE_UNPACK_MAX_LAYERS       4
#define PE_UNPACK_MAX_OUTPUT      (256ULL * 1024ULL * 1024ULL)  /* 256MB */
#define PE_UNPACK_MAX_INPUT       (512ULL * 1024ULL * 1024ULL)  /* 512MB */

/**************************************************/
/*             解包状态                            */
/**************************************************/
typedef enum _PE_UNPACK_STATE {
    WpeUnpack_NotAttempted = 0,
    WpeUnpack_NoPacker,
    WpeUnpack_Skipped,
    WpeUnpack_Success,
    WpeUnpack_Failed,
    WpeUnpack_BombGuard,
    WpeUnpack_Unsupported,
} PE_UNPACK_STATE, *PPE_UNPACK_STATE;

/**************************************************/
/*             加壳器类型                          */
/**************************************************/
typedef enum _PE_UNPACK_PACKER {
    WpePacker_None = 0,
    WpePacker_Upx,
    WpePacker_Aspack,
    WpePacker_Mpress,
    WpePacker_Fsg,
    WpePacker_PeCompact,
    WpePacker_Generic,
} PE_UNPACK_PACKER, *PPE_UNPACK_PACKER;

/**************************************************/
/*             解包层                              */
/**************************************************/
typedef struct _PE_UNPACK_LAYER {
    PE_UNPACK_PACKER Packer;
    PCSTR   PackerName;
    ULONG   LayerNumber;
    ULONG   OriginalEntryPointRva;
    ULONG   UnpackedEntryPointRva;
    ULONG   UnpackedSize;
    PBYTE   UnpackedData;
    BYTE    Sha256[32];
    DOUBLE  EntropyBefore;
    DOUBLE  EntropyAfter;
} PE_UNPACK_LAYER, *PPE_UNPACK_LAYER;

/**************************************************/
/*             解包结果                            */
/**************************************************/
typedef struct _PE_UNPACK_RESULT {
    PE_UNPACK_STATE State;
    BOOLEAN Reconstructed;
    ULONG   LayerCount;
    PE_UNPACK_LAYER Layers[PE_UNPACK_MAX_LAYERS];
} PE_UNPACK_RESULT, *PPE_UNPACK_RESULT;

/**************************************************/
/*          动态解包接口 (EMU 占位类型)             */
/**************************************************/
typedef enum _PE_EMU_STATE {
    WpeEmu_Uninitialized = 0, WpeEmu_Ready, WpeEmu_Running, WpeEmu_Paused,
    WpeEmu_Completed, WpeEmu_Timeout, WpeEmu_InstructionLimit, WpeEmu_MemoryLimit,
    WpeEmu_Error, WpeEmu_Detected, WpeEmu_Terminated,
} PE_EMU_STATE, *PPE_EMU_STATE;

typedef struct _PE_EMU_CONFIG {
    ULONG    TimeoutMs;
    ULONG64  MaxInstructions;
    BOOLEAN  EnableApiTracing;
    BOOLEAN  UnpackOnly;
} PE_EMU_CONFIG, *PPE_EMU_CONFIG;

typedef struct _PE_EMU_LAYER {
    ULONG   LayerNumber;
    PCSTR   PackerType;
    ULONG   OriginalEntryPoint;
    ULONG   UnpackedEntryPoint;
    ULONG   UnpackedSize;
    PBYTE   UnpackedData;
    BYTE    Sha256[32];
    DOUBLE  EntropyBefore;
    DOUBLE  EntropyAfter;
} PE_EMU_LAYER, *PPE_EMU_LAYER;

typedef struct _PE_EMU_RESULT {
    PE_EMU_STATE State;
    ULONG64 InstructionsExecuted;
    BOOLEAN WasPacked;
    BOOLEAN UnpackSuccessful;
    ULONG   LayerCount;
    PE_EMU_LAYER Layers[PE_UNPACK_MAX_LAYERS];
} PE_EMU_RESULT, *PPE_EMU_RESULT;
