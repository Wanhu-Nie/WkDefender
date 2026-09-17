/**************************************************/
/*  WkDefender Agent — 文件类型判定 + 文档/宏分析公共 API  */
/*                                                  */
/*  2026-09-14 重构:                               */
/*  1. 文件类型判定 API 自 Common/FileUtils.h 迁入   */
/*  2. 路径欺骗检测器自 IOC/IocScanner.h 迁入       */
/*  3. 文档分析 API 自 FileSystem/IocDocumentScanner  */
/*     .h (已删除) 迁入                            */
/*  本头为 FileSystem 子模块对外公共头 (include 惯例  */
/*  根目录→子目录 "Include/FileSystem/FileAnalyzer.h") */
/**************************************************/

#pragma once

#include <windows.h>
#include "../../IOC/IocTypes.h"   /* WKD_FILE_FORMAT / WKD_FILE_TYPE_INFO / WKD_FILE_HASH_SET 等 */
#include "../../DefendTypes.h"    /* NTSTATUS / BOOLEAN 等基本类型 */

/**************************************************/
/*               文件类型识别                       */
/*  迁移自 Common/FileUtils.h (2026-09-14)        */
/**************************************************/

/* 粗分类判定（内部走魔数表） */
typedef enum _IOC_FILE_TYPE {
    IocFileType_Unknown = 0,
    IocFileType_Pe32,
    IocFileType_Pe64,
    IocFileType_Dll,
    IocFileType_Sys,
    IocFileType_Elf,
    IocFileType_Pdf,
    IocFileType_Archive,
    IocFileType_Office,
    IocFileType_Script,
} IOC_FILE_TYPE;

/* 缓冲版粗分类 */
IOC_FILE_TYPE CopDetermineFileTypeInternal(_In_ const BYTE* Data, _In_ ULONG Size);

/* 路径版粗分类 */
IOC_FILE_TYPE CoDetermineFileType(_In_ PCWSTR FilePath);

/* 缓冲版完整文件类型分析 — 魔数匹配 + Disambiguate 精化 +
 * 类别/风险/扩展名映射 + 扩展名欺骗检测。
 * Data 建议 ≥64KB 以覆盖 ISO@0x8001 等多偏移签名。 */
NTSTATUS
CoDetermineFileTypeFromBuffer(
    _In_  const BYTE*          Data,
    _In_  ULONG                Size,
    _In_opt_ PCWSTR            DiskExtension,
    _Out_ PWKD_FILE_TYPE_INFO  Info
    );

/* 路径版完整文件类型分析 — 读文件头 + 路径安全欺骗检测 +
 * 扩展名-内容不匹配判定。 */
NTSTATUS
IocScan_AnalyzeFileTypePath(
    _In_  PCWSTR               FilePath,
    _Out_ PWKD_FILE_TYPE_INFO  Info
    );

/* 文本内容判定（UTF-8 有效性 + 90% 可打印 + NUL 拒） */
BOOLEAN IocScan_IsTextContent(_In_ const BYTE* Data, _In_ ULONG Size);

/* 扩展名完整信息查询（format/category/risk/mime/isCommon） */
NTSTATUS IocScan_GetExtensionInfo(_In_ PCWSTR Extension, _Out_ PWKD_EXTENSION_INFO Info);

/* 可执行判定（Category in Executable/Driver/Library） */
BOOLEAN IocScan_IsExecutable(_In_ PCWSTR FilePath);

/* 缓冲版可执行判定 */
BOOLEAN IocScan_IsExecutableBuffer(_In_ const BYTE* Data, _In_ ULONG Size);

/* 脚本判定 */
BOOLEAN IocScan_IsScript(_In_ PCWSTR FilePath);

/* 归档判定 */
BOOLEAN IocScan_IsArchive(_In_ PCWSTR FilePath);

/* 可含宏判定 */
BOOLEAN IocScan_CanContainMacros(_In_ PCWSTR FilePath);

/* MIME 映射（Web/HTTP 消费语义） */
PCSTR IocScan_GetMimeForFormat(_In_ WKD_FILE_FORMAT Format);

/* 扩展名风险等级 (GetExtensionRisk L1840-1843) */
WKD_RISK_LEVEL IocScan_GetExtensionRisk(_In_ PCWSTR Extension);

/* 路径版类别查询 (GetCategory L1554-1557, 读头判定) */
WKD_FILE_CATEGORY IocScan_GetCategory(_In_ PCWSTR FilePath);

/* 路径版 MIME 查询 (GetMimeType L1559-1562, 返回静态字面量) */
PCSTR IocScan_GetMimeType(_In_ PCWSTR FilePath);

/* 聚合欺骗检测 (DetectSpoofing L1610-1638: RTLO → 双扩展名 → 内容不匹配) */
WKD_SPOOFING_TYPE IocScan_DetectSpoofing(_In_ PCWSTR FilePath);

/**************************************************/
/*          路径欺骗检测器                          */
/*  迁移自 IOC/IocScanner.h (2026-09-14)          */
/**************************************************/

/* RTLO 双向控制字符检测 (全 7 种) */
BOOLEAN IocScan_HasRtlOverride(_In_ PCWSTR Filename);

/* 双扩展名检测 (safe+dangerous 组合集合判定) */
BOOLEAN IocScan_HasDoubleExtension(_In_ PCWSTR Filename);

/* 扩展名-内容不匹配检测 (带合法替代扩展名白名单) */
BOOLEAN IocScan_CheckExtMismatch(_Inout_ PWKD_FILE_TYPE_INFO Info);

/* 路径级欺骗聚合 (嵌入 NUL 截断/ADS/RTLO/尾部空格点) */
VOID IocScan_DetectPathSpoofing(_In_ PCWSTR FilePath, _Inout_ PWKD_FILE_TYPE_INFO Info);

/* 脚本类型检测 (BOM/Shebang/关键词, DetectScriptType) */
WKD_FILE_FORMAT IocScan_DetectScriptType(_In_ const BYTE* Data, _In_ ULONG Size);

/* 脚本分析 (BOM/Shebang/关键词提取, AnalyzeScript) */
VOID IocScan_AnalyzeScript(
    _In_  const BYTE*          Data,
    _In_  ULONG                Size,
    _Inout_ PWKD_FILE_TYPE_INFO Info
    );

/**************************************************/
/*               文档/宏分析 API                    */
/*  迁移自 FileSystem/IocDocumentScanner.h          */
/*  (已删除, 2026-09-14)                           */
/*  ⚠ 死代码：本阶段功能面覆盖，未接入流水线。      */
/*  接线点: ScanManager.c ScanFileDirect 步骤5/6间  */
/*  (IocDocument_ScanFile + ResultToIocScan) 留     */
/*  TODO。                                         */
/**************************************************/

/**************************************************/
/*               文档类型                           */
/**************************************************/

typedef enum _WKD_DOC_TYPE {
    WkdDocType_Unknown = 0,
    WkdDocType_PDF,
    WkdDocType_OLE,         /* D0CF11E0 复合文档 (doc/xls/ppt) */
    WkdDocType_OOXML,       /* PK zip 容器 (docx/xlsx/pptx) */
    WkdDocType_RTF,
    WkdDocType_DOC,
    WkdDocType_DOCX,
    WkdDocType_DOCM,
    WkdDocType_DOT,
    WkdDocType_DOTM,
    WkdDocType_XLS,
    WkdDocType_XLSX,
    WkdDocType_XLSM,
    WkdDocType_XLSB,
    WkdDocType_XLT,
    WkdDocType_PPT,
    WkdDocType_PPTX,
    WkdDocType_PPTM,
    WkdDocType_ODF,
    WkdDocType_MSG,
    WkdDocType_EML,
    WkdDocType_ONE,
} WKD_DOC_TYPE, *PWKD_DOC_TYPE;

/**************************************************/
/*               威胁类型                           */
/**************************************************/

typedef enum _WKD_DOC_THREAT_TYPE {
    WkdDocThreat_None = 0,
    /* 宏威胁 */
    WkdDocThreat_VBAMacro,
    WkdDocThreat_AutoExecMacro,
    WkdDocThreat_ObfuscatedMacro,
    WkdDocThreat_MacroShellExec,
    WkdDocThreat_MacroPowerShell,
    WkdDocThreat_MacroDownload,
    /* OLE 威胁 */
    WkdDocThreat_OLEObject,
    WkdDocThreat_OLEExecutable,
    WkdDocThreat_EquationEditor,
    WkdDocThreat_OLEPackage,
    WkdDocThreat_OLEAutoOpen,
    /* DDE/链接 */
    WkdDocThreat_DDELink,
    WkdDocThreat_TemplateInjection,
    WkdDocThreat_ExternalLink,
    /* PDF 威胁 */
    WkdDocThreat_PDFJavaScript,
    WkdDocThreat_PDFOpenAction,
    WkdDocThreat_PDFLaunchAction,
    WkdDocThreat_PDFSubmitForm,
    WkdDocThreat_PDFEmbeddedFile,
    /* RTF 威胁 */
    WkdDocThreat_RTFOLEObject,
    WkdDocThreat_RTFEquationEditor,
    /* CVE */
    WkdDocThreat_CVEExploit,
    /* 通用 */
    WkdDocThreat_HighEntropy,
    WkdDocThreat_SuspiciousString,
    WkdDocThreat_EncodedPayload,
    WkdDocThreat_AntiAnalysis,
} WKD_DOC_THREAT_TYPE;

/**************************************************/
/*               结构体                             */
/**************************************************/

#define WKD_DOC_MAX_THREATS   32
#define WKD_DOC_MAX_IOC       8
#define WKD_DOC_MAX_MACROS    8
#define WKD_DOC_MAX_OLE       16
#define WKD_DOC_MAX_PDFOBJ    16
#define WKD_DOC_MAX_EMAIL     8

typedef struct _WKD_DOC_THREAT {
    WKD_DOC_THREAT_TYPE Type;
    ULONG               Severity;       /* 0-100 */
    CHAR                Description[128];
    CHAR                Location[64];
    CHAR                MitreId[24];
    CHAR                Evidence[256];
} WKD_DOC_THREAT, *PWKD_DOC_THREAT;

typedef struct _WKD_DOC_MACRO {
    CHAR       ModuleName[64];
    CHAR       ModuleType[16];
    ULONG      LineCount;
    ULONG      RiskLevel;
    DOUBLE     Entropy;
    BOOLEAN    IsAutoExec;
    BOOLEAN    IsObfuscated;
    BOOLEAN    HasShellExec;
    BOOLEAN    HasPowerShell;
    BOOLEAN    HasDownload;
    BOOLEAN    HasFileWrite;
    BOOLEAN    HasRegistryAccess;
    BOOLEAN    HasWMI;
    CHAR       SourceCode[2048];
} WKD_DOC_MACRO, *PWKD_DOC_MACRO;

typedef struct _WKD_DOC_OLE_OBJECT {
    CHAR       ProgId[64];
    CHAR       Clsid[40];
    CHAR       DisplayName[64];
    ULONG64    Size;
    BOOLEAN    IsExecutable;
    BOOLEAN    IsPackage;
    BOOLEAN    HasAutoStart;
    CHAR       EmbeddedPath[260];
    CHAR       Sha256Hex[65];
} WKD_DOC_OLE_OBJECT, *PWKD_DOC_OLE_OBJECT;

typedef struct _WKD_DOC_PDF_OBJECT {
    ULONG      ObjectId;
    CHAR       ObjectType[32];
    CHAR       ActionType[32];
    CHAR       EmbeddedFileName[64];
    BOOLEAN    HasJavaScript;
    BOOLEAN    HasAction;
    BOOLEAN    HasEmbeddedFile;
    CHAR       JsSnippet[1024];
} WKD_DOC_PDF_OBJECT, *PWKD_DOC_PDF_OBJECT;

/* 注意: WKD_DOC_SCAN_RESULT 约 40KB, 调用方必须堆分配, 禁止栈上声明 */
typedef struct _WKD_DOC_SCAN_RESULT {
    WKD_DOC_TYPE        DocumentType;
    ULONG               RiskScore;
    ULONG               Verdict;
    CHAR                VerdictReason[128];
    ULONG64             FileSize;
    BOOLEAN             IsSpoofed;
    /* 宏 */
    BOOLEAN             HasMacros;
    ULONG               MacroCount;
    BOOLEAN             IsObfuscated;
    ULONG               HighestMacroRisk;
    WKD_DOC_MACRO       Macros[WKD_DOC_MAX_MACROS];
    /* OLE */
    BOOLEAN             HasOLEObjects;
    WKD_DOC_OLE_OBJECT  OleObjects[WKD_DOC_MAX_OLE];
    ULONG               OleObjectCount;
    /* PDF */
    BOOLEAN             HasPdfJavaScript;
    BOOLEAN             HasPdfActions;
    WKD_DOC_PDF_OBJECT  PdfObjects[WKD_DOC_MAX_PDFOBJ];
    ULONG               PdfObjectCount;
    /* 链接/模板 */
    BOOLEAN             HasDdeLinks;
    BOOLEAN             HasExternalLinks;
    BOOLEAN             HasTemplateInjection;
    /* 威胁 */
    ULONG               ThreatCount;
    WKD_DOC_THREAT      Threats[WKD_DOC_MAX_THREATS];
    ULONG               CriticalThreats;
    ULONG               HighThreats;
    ULONG               MediumThreats;
    /* IOC */
    CHAR                Urls[WKD_DOC_MAX_IOC][256];
    ULONG               UrlCount;
    CHAR                Ips[WKD_DOC_MAX_IOC][64];
    ULONG               IpCount;
    CHAR                Emails[WKD_DOC_MAX_EMAIL][128];
    ULONG               EmailCount;
    /* 去混淆输出 (死代码填充) */
    CHAR                DeobfuscatedCode[4096];
    /* 元数据 */
    CHAR                Author[128];
    CHAR                Title[256];
    CHAR                Subject[256];
} WKD_DOC_SCAN_RESULT, *PWKD_DOC_SCAN_RESULT;

/**************************************************/
/*               文档分析 API 声明                   */
/**************************************************/

NTSTATUS
IocDocument_DetectType(
    _In_ PCWSTR         FilePath,
    _Out_ PWKD_DOC_TYPE Type
    );

NTSTATUS
IocDocument_ScanFile(
    _In_ PCWSTR             FilePath,
    _Out_ PWKD_DOC_SCAN_RESULT Result
    );

NTSTATUS
IocDocument_AnalyzeVBACode(
    _In_ PCSTR              VbaCode,
    _Out_ PWKD_DOC_SCAN_RESULT Result
    );

NTSTATUS
IocDocument_ResultToIocScan(
    _In_ PWKD_DOC_SCAN_RESULT Doc,
    _Inout_ PIOC_SCAN_RESULT  Ioc
    );

NTSTATUS
IocDocument_ScanBuffer(
    _In_ const BYTE*      Buf,
    _In_ ULONG            Size,
    _In_ WKD_DOC_TYPE     DocType,
    _Out_ PWKD_DOC_SCAN_RESULT Result
    );

NTSTATUS
IocDocument_HasMacros(
    _In_ PCWSTR   FilePath,
    _Out_ PBOOLEAN Has
    );

NTSTATUS
IocDocument_IsMalicious(
    _In_ PCWSTR   FilePath,
    _Out_ PBOOLEAN Malicious
    );

NTSTATUS
IocDocument_ExtractIocs(
    _In_ PCWSTR              FilePath,
    _Inout_ PWKD_DOC_SCAN_RESULT Result
    );

NTSTATUS
IocDocument_AnalyzePdf(
    _In_ PCWSTR              FilePath,
    _Inout_ PWKD_DOC_SCAN_RESULT Result
    );

NTSTATUS
IocDocument_ExtractPdfJavaScript(
    _In_ PCWSTR  FilePath,
    _Out_ PCHAR  JsSnippets,
    _In_ ULONG   JsSnippetsSize
    );

NTSTATUS
IocDocument_ExtractOleObjects(
    _In_ PCWSTR              FilePath,
    _Inout_ PWKD_DOC_SCAN_RESULT Result
    );

NTSTATUS
IocDocument_ListOleStreams(
    _In_ PCWSTR  FilePath,
    _Out_ PCHAR  Streams,
    _In_ ULONG   StreamsSize
    );

NTSTATUS
IocDocument_ExtractMacros(
    _In_ PCWSTR              FilePath,
    _Inout_ PWKD_DOC_SCAN_RESULT Result
    );
