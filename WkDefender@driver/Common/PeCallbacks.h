/**************************************************/
/*  WkDefender — PE 解析回调束（PeCallbacks）        */
/*                                                  */
/*  2026-08-08 新建：承载 PhantomSensor 各解析点的   */
/*  独有检测能力，以回调函数形式接入统一 PE 核心。    */
/*                                                  */
/*  能力清单：                                      */
/*    WkdPeCbMitigationsInit  — 安全缓解映射        */
/*                              (PS ProcessAnalyzer) */
/*    WkdPeCbFindSection*     — 节定位              */
/*                              (PS Ntdll/Hollowing) */
/*    WkdPeCbExecRangeInit    — 可执行节区间合并     */
/*                              (PS Callstack)      */
/*    WkdPeCbPsInfoInit       — PS 16 节信息        */
/*                              (PS ImageNotify)    */
/*  粗分类/导出解析/file→image 重排已内置核心        */
/*  （WkdPeClassify/ResolveExport/RemapFileToImage）。*/
/**************************************************/

#pragma once

#include "PeParser.h"

/**************************************************/
/*            安全缓解映射（ProcessAnalyzer）       */
/**************************************************/

typedef struct _WKD_PE_MITIGATIONS {
    BOOLEAN IsPe;               // DOS+NT 校验通过
    BOOLEAN HasDep;             // IMAGE_DLLCHARACTERISTICS_NX_COMPAT      (0x0100)
    BOOLEAN HasAslr;            // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE   (0x0040)
    BOOLEAN HasCfg;             // IMAGE_DLLCHARACTERISTICS_GUARD_CF       (0x4000)
    BOOLEAN HasHighEntropyAslr; // IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA(0x0020)
    BOOLEAN IsDotNet;           // COM_DIR VA!=0
    BOOLEAN HasSignature;       // SECURITY 目录 VA!=0 && Size>0（启发式）
    ULONG   TimeDateStamp;
    ULONG   ImageEntropy;       // 镜像首 min(SizeOfImage, 0x10000) 的 Shannon 熵
} WKD_PE_MITIGATIONS, *PWKD_PE_MITIGATIONS;

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdPeCbMitigationsInit(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _Out_   PWKD_PE_MITIGATIONS Out
    );

/**************************************************/
/*              节定位（Ntdll/Hollowing）           */
/**************************************************/

typedef struct _WKD_PE_SECTION_MATCH {
    BOOLEAN             Found;          // 命中
    ULONG               Index;          // 节索引
    PIMAGE_SECTION_HEADER Section;      // 节头指针（解析生命周期内有效）
    PVOID               ContentPtr;     // 节内容指针（布局感知，可为 NULL）
    SIZE_T              ContentSize;    // effective = min(VirtualSize, RawData)，0 回退 VS
    /* 匹配标准（由 WkdPeCbFindSectionByName/ByChars 填充） */
    BOOLEAN             ByName;         // TRUE=按名匹配，FALSE=按特性掩码
    PCSTR               SectionName;    // 节名（ByName 时有效）
    ULONG               RequiredChars;  // 节特性掩码（!ByName 时有效）
} WKD_PE_SECTION_MATCH, *PWKD_PE_SECTION_MATCH;

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdPeCbFindSectionByName(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_    PCSTR SectionName,
    _Out_   PWKD_PE_SECTION_MATCH Out
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdPeCbFindSectionByChars(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_    ULONG RequiredChars,
    _Out_   PWKD_PE_SECTION_MATCH Out
    );

/**************************************************/
/*          可执行节区间合并（Callstack）           */
/**************************************************/

typedef struct _WKD_PE_EXEC_RANGE {
    BOOLEAN HasExecutableSection;   // 存在 CNT_CODE && MEM_EXECUTE 节
    ULONG   MinRva;                 // 全部可执行节 min VirtualAddress
    ULONG   MaxRva;                 // max (VirtualAddress + VirtualSize)
    ULONG   Size;                   // MaxRva - MinRva
} WKD_PE_EXEC_RANGE, *PWKD_PE_EXEC_RANGE;

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdPeCbExecRangeInit(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _Out_   PWKD_PE_EXEC_RANGE Out
    );

/**************************************************/
/*            PS 16 节信息（ImageNotify）           */
/**************************************************/

#define WKD_PS_PE_MAX_SECTIONS     16
#define WKD_PS_PE_SECTION_NAME     9       /* 8 字符 + NUL */

typedef struct _WKD_PS_PE_SECTION_INFO {
    CHAR    Name[WKD_PS_PE_SECTION_NAME];
    ULONG   VirtualSize;
    ULONG   VirtualAddress;
    ULONG   Characteristics;
    ULONG   Entropy;            // Shannon 熵（采样 min(VirtualSize, 4096)）
    BOOLEAN IsExecutable;
    BOOLEAN IsWritable;
} WKD_PS_PE_SECTION_INFO, *PWKD_PS_PE_SECTION_INFO;

typedef struct _WKD_PS_IMG_PE_INFO {
    WKD_PS_PE_SECTION_INFO Sections[WKD_PS_PE_MAX_SECTIONS];
    ULONG   SectionCount;       // min(节数, 16)
    BOOLEAN HasSecurityDirectory;
    ULONG   SecurityDirectorySize;
    /* 纸面字段（对齐 PS IMG_PE_INFO，PS ImgpAnalyzePeHeader 亦未填充）：
     * ImportCount / ExportCount / HasDelayLoadImports / TlsCallbackCount
     * 依赖深度目录解析，本轮不实现。 */
} WKD_PS_IMG_PE_INFO, *PWKD_PS_IMG_PE_INFO;

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdPeCbPsInfoInit(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _Out_   PWKD_PS_IMG_PE_INFO Out
    );
