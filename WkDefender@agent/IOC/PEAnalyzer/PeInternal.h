/**************************************************/
/*  WkDefender PEAnalyzer — 内部聚合头              */
/*  仅本目录内 .c (含 PeAnalyzer.c) 与经批准的       */
/*  死代码内部调用文件可 include。                   */
/*  对外唯一公共入口 = PeAnalyzer.h (不含本头)。     */
/*                                                   */
/*  边界界定: 本头 = 解析能力域 — 字节→PE_INFO /  */
/*  惰性解析产物 (无业务语义); 业务结论 (深验/比对/   */
/*  风险评分等) 由 PeAnalyzer.c 组合产出。            */
/**************************************************/

#pragma once

#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <stdio.h>
#include <ntstatus.h>
#include <wintrust.h>
#include "PeTypes.h"

/**************************************************/
/*              内部常量 (仅目录内使用)              */
/**************************************************/

/* 内部 Limits (DoS 防护上限, 不对外) */
#define PE_MIN_FILE_SIZE               1024
#define PE_MAX_FILE_SIZE               (2ULL * 1024ULL * 1024ULL * 1024ULL)  /* 2GB */
#define IMAGE_MAX_IMPORT_DESCRIPTORS      10000
#define IMAGE_MAX_IMPORTS_PER_DLL         100000
#define PE_MAX_EXPORTS                 100000
#define PE_MAX_RELOCATIONS             10000000
#define PE_MAX_RELOCATION_BLOCKS       100000
#define PE_MAX_RESOURCE_DEPTH          32
#define PE_MAX_RESOURCE_ENTRIES        10000
#define PE_MAX_TOTAL_RESOURCES         100000
#define PE_MAX_DELAY_IMPORT_DESC       10000
#define PE_MAX_EXCEPTION_ENTRIES       1000000
#define PE_MAX_LOAD_CONFIG_SIZE        1024
#define PE_MAX_STRING_LENGTH           65536
#define PE_MIN_FILE_ALIGNMENT          512
#define PE_MAX_FILE_ALIGNMENT          65536
#define PE_MIN_SECTION_ALIGNMENT       1
#define PE_MAX_SECTION_ALIGNMENT       0x10000000
#define PE_MIN_DOS_HEADER_SIZE         64
#define PE_MAX_OPTIONAL_HEADER_SIZE    1024

/* 安全目录 (WIN_CERTIFICATE 头) 最小尺寸 */
#define PE_MIN_WIN_CERTIFICATE         (sizeof(WIN_CERTIFICATE))

/* GuardFlags 位 (对齐 winnt GuardFlags 位) */
#define PE_GUARD_CF_INSTRUMENTED       0x00000100UL
#define PE_GUARD_CF_FUNCTION_TABLE     0x00000400UL
#define PE_GUARD_CF_CET_COMPATIBLE     0x00002000UL
#define PE_GUARD_CF_CET_SHADOW_STACK   0x00010000UL

/* 魔数与头常量 */
#define PE_MAX_LFANEW                   0x400000   /* 4MB, 防 Rich 头扫描 DoS */
#define PE_ROM_MAGIC                   0x107
#define IMAGE_MAX_DIRECTORY_ENTRIES    16

/* 机器类型 */
#define PE_MACHINE_UNKNOWN             0x0000
#define PE_MACHINE_TARGET_HOST         0x0001
#define PE_MACHINE_I386                0x014C
#define PE_MACHINE_R3000               0x0162
#define PE_MACHINE_R4000               0x0166
#define PE_MACHINE_R10000              0x0168
#define PE_MACHINE_WCEMIPSV2           0x0169
#define PE_MACHINE_ALPHA               0x0184
#define PE_MACHINE_SH3                 0x01A2
#define PE_MACHINE_SH3DSP              0x01A3
#define PE_MACHINE_SH3E                0x01A4
#define PE_MACHINE_SH4                 0x01A6
#define PE_MACHINE_SH5                 0x01A8
#define PE_MACHINE_ARM                 0x01C0
#define PE_MACHINE_THUMB               0x01C2
#define PE_MACHINE_ARMNT               0x01C4
#define PE_MACHINE_AM33                0x01D3
#define PE_MACHINE_POWERPC             0x01F0
#define PE_MACHINE_POWERPCFP           0x01F1
#define PE_MACHINE_IA64                0x0200
#define PE_MACHINE_MIPS16              0x0266
#define PE_MACHINE_ALPHA64             0x0284
#define PE_MACHINE_MIPSFPU             0x0366
#define PE_MACHINE_MIPSFPU16           0x0466
#define PE_MACHINE_TRICORE             0x0520
#define PE_MACHINE_CEF                 0x0CEF
#define PE_MACHINE_EBC                 0x0EBC
#define PE_MACHINE_AMD64               0x8664
#define PE_MACHINE_M32R                0x9041
#define PE_MACHINE_ARM64               0xAA64
#define PE_MACHINE_CEE                 0xC0EE

/* 文件头特性位 */
#define PE_FCH_RELOCS_STRIPPED         0x0001
#define PE_FCH_EXECUTABLE_IMAGE        0x0002
#define PE_FCH_LINE_NUMS_STRIPPED      0x0004
#define PE_FCH_LOCAL_SYMS_STRIPPED     0x0008
#define PE_FCH_AGGRESSIVE_WS_TRIM      0x0010
#define PE_FCH_LARGE_ADDRESS_AWARE     0x0020
#define PE_FCH_BYTES_REVERSED_LO       0x0080
#define PE_FCH_MACHINE_32BIT           0x0100
#define PE_FCH_DEBUG_STRIPPED          0x0200
#define PE_FCH_REMOVABLE_RUN_FROM_SWAP 0x0400
#define PE_FCH_NET_RUN_FROM_SWAP       0x0800
#define PE_FCH_SYSTEM_FILE             0x1000
#define PE_FCH_UP_SYSTEM_ONLY          0x4000
#define PE_FCH_BYTES_REVERSED_HI       0x8000

/* 重定位类型 */
#define PE_RELOC_ABSOLUTE              0
#define PE_RELOC_HIGH                  1
#define PE_RELOC_LOW                   2
#define PE_RELOC_HIGHLOW               3
#define PE_RELOC_HIGHADJ               4
#define PE_RELOC_MACHINE_SPECIFIC_5    5
#define PE_RELOC_RESERVED              6
#define PE_RELOC_MACHINE_SPECIFIC_7    7
#define PE_RELOC_MACHINE_SPECIFIC_8    8
#define PE_RELOC_MACHINE_SPECIFIC_9    9
#define PE_RELOC_DIR64                 10

/* 调试类型 */
#define PE_DBT_UNKNOWN                 0
#define PE_DBT_COFF                    1
#define PE_DBT_CODEVIEW                2
#define PE_DBT_FPO                     3
#define PE_DBT_MISC                    4
#define PE_DBT_EXCEPTION               5
#define PE_DBT_FIXUP                   6
#define PE_DBT_OMAP_TO_SRC             7
#define PE_DBT_OMAP_FROM_SRC           8
#define PE_DBT_BORLAND                 9
#define PE_DBT_RESERVED10              10
#define PE_DBT_CLSID                   11
#define PE_DBT_VC_FEATURE              12
#define PE_DBT_POGO                    13
#define PE_DBT_ILTCG                   14
#define PE_DBT_MPX                     15
#define PE_DBT_REPRO                   16
#define PE_DBT_EMBEDDEDPDB             17
#define PE_DBT_PDBCHECKSUM             19
#define PE_DBT_EX_DLLCHARACTERISTICS   20

/* IMAGE_OPTIONAL_HEADER64::Subsystem */
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS  8

/* Authenticode / Rich / .NET 常量 */
#define PE_RICH_DANS_SIGNATURE         0x536E6144   /* "DanS" XOR'd */
#define PE_RICH_RICH_SIGNATURE         0x68636952   /* "Rich" XOR'd */
#define PE_CLR_FLAGS_ILONLY            0x00000001
#define PE_CLR_FLAGS_32BITREQUIRED     0x00000002
#define PE_CLR_FLAGS_IL_LIBRARY        0x00000004
#define PE_CLR_FLAGS_STRONGNAMESIGNED  0x00000008
#define PE_CLR_FLAGS_NATIVE_ENTRYPOINT 0x00000010
#define PE_CLR_FLAGS_TRACKDEBUGDATA    0x00010000
#define PE_CLR_FLAGS_32BITPREFERRED    0x00020000

/**************************************************/
/*         pack(1) 磁盘结构 (内部, 文件布局)         */
/**************************************************/
#pragma pack(push, 1)

/* CLR/.NET 头 (72 字节); 目录字段为原始 IMAGE_DATA_DIRECTORY (8 字节) */
typedef struct _PE_CLR_HEADER {
    ULONG   Cb;
    USHORT  MajorRuntimeVersion;
    USHORT  MinorRuntimeVersion;
    IMAGE_DATA_DIRECTORY MetaData;
    ULONG   Flags;
    ULONG   EntryPointToken;    /* union EntryPointToken/EntryPointRVA */
    IMAGE_DATA_DIRECTORY Resources;
    IMAGE_DATA_DIRECTORY StrongNameSignature;
    IMAGE_DATA_DIRECTORY CodeManagerTable;
    IMAGE_DATA_DIRECTORY VTableFixups;
    IMAGE_DATA_DIRECTORY ExportAddressTableJumps;
    IMAGE_DATA_DIRECTORY ManagedNativeHeader;
} PE_CLR_HEADER, *PPE_CLR_HEADER;

#pragma pack(pop)

/**************************************************/
/*             节重叠记录 (校验内部类型)             */
/**************************************************/
typedef struct _PE_SECTION_OVERLAP {
    SIZE_T Left;    /* 节索引 i */
    SIZE_T Right;   /* 节索引 j (i<j) */
} PE_SECTION_OVERLAP, *PPE_SECTION_OVERLAP;

/**************************************************/
/*              SafeMath(安全算术)                  */
/**************************************************/

FORCEINLINE BOOLEAN WpeSafeSubSz(SIZE_T A, SIZE_T B, SIZE_T* Out)
{
    if (B > A) return FALSE;
    *Out = A - B;
    return TRUE;
}

FORCEINLINE BOOLEAN IocpAddU32Safe(ULONG A, ULONG B, PULONG Out)
{
    if (A > 0xFFFFFFFFUL - B) return FALSE;
    *Out = A + B;
    return TRUE;
}

FORCEINLINE BOOLEAN IocpMulU16Safe(USHORT A, USHORT B, PUSHORT Out)
{
    if (A != 0 && B > 0xFFFFUL / A) return FALSE;
    *Out = A * B;
    return TRUE;
}

FORCEINLINE BOOLEAN IocpMulU32Safe(ULONG A, ULONG B, PULONG Out)
{
    if (A != 0 && B > 0xFFFFFFFFUL / A) return FALSE;
    *Out = A * B;
    return TRUE;
}

FORCEINLINE BOOLEAN WpeSafeAddU64(ULONG64 A, ULONG64 B, PULONG64 Out)
{
    if (A > (ULONG64)-1 - B) return FALSE;
    *Out = A + B;
    return TRUE;
}

FORCEINLINE BOOLEAN WpeSafeSubU64(ULONG64 A, ULONG64 B, PULONG64 Out)
{
    if (B > A) return FALSE;
    *Out = A - B;
    return TRUE;
}

/* SafeCast 窄化版 (U64→U32 范围检查) */
FORCEINLINE BOOLEAN WpeSafeCastU64ToU32(ULONG64 V, PULONG Out)
{
    if (V > 0xFFFFFFFFULL) return FALSE;
    *Out = (ULONG)V;
    return TRUE;
}

/* SIZE_T 安全加/乘 (防溢出, 对齐 SS SafeMath 语义) */
FORCEINLINE BOOLEAN IocpAddSizeSafe(SIZE_T A, SIZE_T B, SIZE_T* Out)
{
    if (A > (SIZE_T)-1 - B) return FALSE;
    *Out = A + B;
    return TRUE;
}

FORCEINLINE BOOLEAN WpeSafeMulSz(SIZE_T A, SIZE_T B, SIZE_T* Out)
{
    if (A != 0 && B > (SIZE_T)-1 / A) return FALSE;
    *Out = A * B;
    return TRUE;
}

/**************************************************/
/*              读取层 (内部)                      */
/**************************************************/
NTSTATUS
IocInitializeBufferReader(
    _Out_ PPE_READER Reader,
    _In_ const BYTE* Buffer,
    _In_ SIZE_T BufferSize
    );

PE_READER WpeReaderFromProcess(
    _In_ HANDLE      ProcessHandle,
    _In_ ULONG_PTR   BaseAddress,
    _In_ SIZE_T      Size
    );

VOID IocpInitializeReader(
    _Out_ PPE_READER Reader,
    _In_ HANDLE FileHandle,
    _In_ SIZE_T Size
    );

VOID IocReaderDestroy(
    _Inout_ PPE_READER Reader
    );

VOID WpeReaderSetSize(
    _Inout_ PPE_READER R,
    _In_    SIZE_T      Size
    );

FORCEINLINE
SIZE_T
CopGetReaderSize(
    _In_ const PPE_READER Reader
    )
{
    return Reader ? Reader->Size : 0;
}

NTSTATUS
CopValidateReadingRange(
    _In_ const PPE_READER Reader,
    _In_ SIZE_T Offset,
    _In_ SIZE_T Size
    );

BOOLEAN IocpReaderReadBytes(
    _In_ PPE_READER Reader,
    _In_ SIZE_T Offset,
    _Out_ PVOID Out,
    _In_ SIZE_T Size
    );

BOOLEAN IocpReaderReadArray(
    _In_  PPE_READER R,
    _In_  ULONGLONG   Offset,
    _In_  SIZE_T      Count,
    _In_  SIZE_T      ElemSize,
    _Out_ void*       Out
    );

BOOLEAN IocpReaderReadString(
    _In_  PPE_READER R,
    _In_  ULONGLONG   Offset,
    _In_  ULONG       MaxLen,
    _Out_writes_(OutCap) PCHAR Out,
    _In_  ULONG       OutCap,
    _Out_opt_ PULONG  Len
    );

BOOLEAN WpeReaderCompareBytes(
    _In_  PPE_READER  R,
    _In_  ULONGLONG    Offset,
    _In_  const void*  Expected,
    _In_  SIZE_T       Length
    );

/**************************************************/
/*              校验层 (内部)                      */
/**************************************************/
PCWSTR WpeValidationResultToString(
    _In_ PE_VALIDATION_RESULT Result
    );

PE_VALIDATION_RESULT IocpValidateDosHeader(
    _In_ const PPE_READER Reader,
    _Out_ PLONG Lfanew,
    _Out_opt_ PPE_PARSER_ERROR Error
    );

PE_VALIDATION_RESULT IocpValidateNtHeaders(
    _In_ const PPE_READER Reader,
    _In_ SIZE_T NtHeaderOffset,
    _Out_ PBOOLEAN Amd64,
    _Out_ PIMAGE_FILE_HEADER FileHeader,
    _Out_opt_ PPE_PARSER_ERROR Error
    );

PE_VALIDATION_RESULT IocpValidateOptionalHeader32(
    _In_ const PPE_READER Reader,
    _In_ SIZE_T Offset,
    _Out_ PIMAGE_OPTIONAL_HEADER32 OptionalHeader32,
    _Out_opt_ PPE_PARSER_ERROR Error
    );

PE_VALIDATION_RESULT IocpValidateOptionalHeader64(
    _In_ const PPE_READER Reader,
    _In_ SIZE_T Offset,
    _Out_ PIMAGE_OPTIONAL_HEADER64 OptionalHeader64,
    _Out_opt_ PPE_PARSER_ERROR Error
    );

/* 设计共识: 异常可累积、硬错误才拦截。Anomalies/AnomalyCount 可 NULL。 */
PE_VALIDATION_RESULT IocpValidateSectionHeader(
    _In_ const PIMAGE_SECTION_HEADER SectionHeader,
    _In_opt_ SIZE_T FileSize,
    _In_ ULONG SizeOfImage,
    _In_ ULONG FileAlignment,
    _In_ USHORT SectionIndex,
    _Out_opt_ PPE_PARSER_ERROR Error,
    _Out_opt_ PPE_ANOMALY Anomalies,
    _Inout_opt_ PULONG AnomalyCount,
    _In_opt_ ULONG AnomalyCap
    );

/* 两轮重叠检测: 物理(文件 raw) + 虚拟地址(VA) */
BOOLEAN WpeCheckSectionOverlaps(
    _In_  const IMAGE_SECTION_HEADER* Sections,
    _In_  ULONG                     SectionCount,
    _Out_opt_ PPE_SECTION_OVERLAP  Overlaps,
    _Inout_opt_ PULONG              OverlapCount,
    _In_  ULONG                     OverlapCap
    );

/* 数据目录校验; SECURITY(索引4) 的 VA 实为文件偏移, 特例。※死代码, 待接线 */
PE_VALIDATION_RESULT WpeValidateDataDirectory(
    _In_  SIZE_T            Index,
    _In_  ULONG             Rva,
    _In_  ULONG             Size,
    _In_  ULONG             SizeOfImage,
    _In_  SIZE_T            FileSize,
    _Out_opt_ PPE_PARSER_ERROR Err
    );

/**************************************************/
/*              解析层 (内部)                      */
/**************************************************/
/* 取默认解析选项 */
PE_PARSE_OPTIONS IocDefaultPeParseOptions(
    VOID
    );

/* 便捷 API: 内部自建 context, 返回 Info 拷贝 */
NTSTATUS IocAnalyzePeBuffer(
    _In_ const PBYTE Buffer,
    _In_ SIZE_T BufferSize,
    _In_opt_ const PPE_PARSE_OPTIONS Options,
    _Out_ PPE_INFO Info,
    _Out_opt_ PPE_PARSER_ERROR Error
    );

/* 进程内存模式: offset 语义 = RVA, 实际地址 = BaseAddress + offset */
NTSTATUS IocAnalyzeFromProcess(
    _In_  HANDLE                 ProcessHandle,
    _In_  ULONG_PTR              BaseAddress,
    _In_  SIZE_T                 Size,
    _In_  const PE_PARSE_OPTIONS* Options,
    _Out_ PPE_INFO           Out,
    _Out_opt_ PPE_PARSER_ERROR      Err
    );

/* 文件模式(路径): 整文件内存映射读取 (>2GB 拒绝) */
NTSTATUS IocAnalyzePeFromFilePath(
    _In_ PCWSTR ImagePath,
    _In_ const PPE_PARSE_OPTIONS Options,
    _Out_ PPE_INFO Info,
    _Out_opt_ PPE_PARSER_ERROR Error
    );

/* 文件模式(句柄): 段式 ReadFile 按需加载, 不整文件映射; 适用于超大文件/不可映射句柄/有界内存。
 * 读取器不拥有 FileHandle, 调用方负责关闭。 */
NTSTATUS IocpAnalyzeFileHandle(
    _In_ HANDLE FileHandle,
    _In_ SIZE_T Size,
    _In_opt_ const PPE_PARSE_OPTIONS Options,
    _Out_ PPE_INFO Info,
    _Out_opt_ PPE_PARSER_ERROR Error
    );

/* 上下文 API: 调用者持有 context, 供地址转换/惰性解析复用 */
NTSTATUS IocpAnalyzeBufferEx(
    _Inout_ PPE_PARSER_CONTEXT   Ctx,
    _In_  const BYTE*            Data,
    _In_  SIZE_T                 Size,
    _In_  const PE_PARSE_OPTIONS* Options
    );

NTSTATUS WpeParseMemoryEx(
    _Inout_ PPE_PARSER_CONTEXT   Ctx,
    _In_  HANDLE                 ProcessHandle,
    _In_  ULONG_PTR              BaseAddress,
    _In_  SIZE_T                 Size,
    _In_  const PE_PARSE_OPTIONS* Options
    );

VOID WpeParseContextReset(
    _Inout_ PPE_PARSER_CONTEXT   Ctx
    );

BOOLEAN WpeIsParsed(
    _In_ const PE_PARSER_CONTEXT* Ctx
    );

/* 取已解析 PE 信息 (未解析返回 NULL) */
const PE_INFO* WpeGetInfo(
    _In_ const PE_PARSER_CONTEXT* Ctx
    );

/* 取底层读取器 (未解析返回 NULL, 慎用) */
const PE_READER* WpeGetReader(
    _In_ const PE_PARSER_CONTEXT* Ctx
    );

/* RVA→文件偏移 (内存模式返回 RVA 恒等) */
BOOLEAN IocpRvaToOffset(
    _In_ const PE_PARSER_CONTEXT* Context,
    _In_ ULONG  Rva,
    _Out_ PULONG Offset
    );

BOOLEAN WpeOffsetToRva(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  SIZE_T Offset,
    _Out_ ULONG*  OutRva
    );

BOOLEAN WpeIsValidRva(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  ULONG Rva
    );

BOOLEAN WpeGetSectionByRva(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  ULONG Rva,
    _Out_ SIZE_T* OutIndex
    );

BOOLEAN WpeGetSectionByName(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  PCSTR Name,
    _Out_ SIZE_T* OutIndex
    );

/* 收集节校验问题 ※死代码, 无调用者, 待接线 */
BOOLEAN WpeValidatePe(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_opt_ PPE_VALIDATION_RESULT Issues,
    _Inout_opt_ PULONG               IssueCount,
    _In_  ULONG                      IssueCap
    );

BOOLEAN WpeHasAnomaly(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  PE_ANOMALY_TYPE Type
    );



/* fold-and-add 校验和比对; 仅文件模式 */
BOOLEAN WpeVerifyChecksum(
    _In_ const PE_PARSER_CONTEXT* Ctx
    );

/* 计算 Microsoft fold-and-add PE 校验和 (等价 MapFileAndCheckSumW) */
ULONG WpeComputeFileChecksum(
    _In_ const BYTE* Data,
    _In_ SIZE_T      Size,
    _In_ ULONG       CheckSumOffset
    );

PCWSTR WpeMachineToString(
    _In_ USHORT Machine
    );

PCWSTR WpeSubsystemToString(
    _In_ USHORT Subsystem
    );

/**************************************************/
/*              惰性解析层 (内部)                  */
/**************************************************/
NTSTATUS IocpParseImports(
    _In_ const PE_PARSER_CONTEXT* Context,
    _Out_ PPE_IMPORT_LIST Imports
    );

VOID WpeImportsFree(
    _Inout_ PPE_IMPORT_LIST List
    );

NTSTATUS WpeParseExports(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_EXPORT_DIR          Out
    );

VOID WpeExportsFree(
    _Inout_ PPE_EXPORT_DIR Out
    );

NTSTATUS WpeParseTls(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_TLS_INFO            Out
    );

VOID WpeTlsFree(
    _Inout_ PPE_TLS_INFO Out
    );

NTSTATUS WpeParseRelocations(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_RELOCATION_LIST     Out
    );

VOID WpeRelocationsFree(
    _Inout_ PPE_RELOCATION_LIST Out
    );

NTSTATUS WpeParseDebugInfo(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_DEBUG_LIST          Out
    );

VOID WpeDebugInfoFree(
    _Inout_ PPE_DEBUG_LIST Out
    );

NTSTATUS WpeParseRichHeader(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_RICH_HEADER_INFO    Out
    );

VOID WpeRichHeaderFree(
    _Inout_ PPE_RICH_HEADER_INFO Out
    );

NTSTATUS WpeParseDelayImports(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_DELAY_IMPORT_LIST   Out
    );

VOID WpeDelayImportsFree(
    _Inout_ PPE_DELAY_IMPORT_LIST Out
    );

NTSTATUS WpeParseLoadConfig(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_LOAD_CONFIG_INFO    Out
    );

VOID WpeLoadConfigFree(
    _Inout_ PPE_LOAD_CONFIG_INFO Out
    );

NTSTATUS WpeParseExceptionDirectory(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_EXCEPTION_LIST      Out
    );

VOID WpeExceptionDirectoryFree(
    _Inout_ PPE_EXCEPTION_LIST Out
    );

NTSTATUS WpeParseResources(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  ULONG                    MaxDepth,
    _Out_ PPE_RESOURCE_LIST       Out
    );

VOID WpeResourcesFree(
    _Inout_ PPE_RESOURCE_LIST Out
    );

/* 资源内容级异常检测 (内嵌 PE / 高熵>=7.2 / 超大资源>16MB)。
 * 2026-08-19 由深度分析 (IocHeuristicPeAnalysis) 在重建 Ctx 上接线调用；
 * 构建期解析 AnalyzeContentAnomalies=FALSE 不执行本检测。发射异常到 Ctx->Info.Anomalies。 */
VOID WpeDetectResourceContentAnomalies(
    _Inout_ PPE_PARSER_CONTEXT Context
    );

/**************************************************/
/*              解包层 (内部)                      */
/**************************************************/
/* 对已解析的加壳文件执行静态解包 (仅 UPX 可靠接入) */
NTSTATUS WpeUnpackPackedBuffer(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  const BYTE*              FileData,
    _In_  SIZE_T                   FileSize,
    _Out_ PPE_UNPACK_RESULT       Result
    );

VOID WpeUnpackResultFree(
    _Inout_ PPE_UNPACK_RESULT Result
    );

/* NRV2B 解压 (公有领域 UCL, 含防炸弹加固) */
NTSTATUS WpeNrV2bDecompress(
    _In_  const BYTE* Src,
    _In_  SIZE_T      SrcSize,
    _Out_ BYTE*       Dst,
    _In_  SIZE_T      DstSize,
    _Out_ PSIZE_T     OutUsed
    );

/* SS EmulatePE → 本函数; 依赖独立 CPU 模拟器, 当前返回 STATUS_NOT_IMPLEMENTED */
NTSTATUS WpeEmulatePe(
    _In_  const BYTE*            FileData,
    _In_  SIZE_T                 FileSize,
    _In_  const PE_EMU_CONFIG*  Config,
    _Out_ PPE_EMU_RESULT        Result
    );
