/**************************************************/
/*  WkDefender IOC 引擎 — 文档/宏分析               */
/*  功能面全量迁移自 ShadowStrike DocumentScanner   */
/*  + MacroDetector (Stage 4.5)                    */
/*  按功能融合重实现，非源码复制。                  */
/*                                                  */
/*  ⚠ 死代码：本阶段功能面覆盖，未接入流水线。      */
/*  接线点: ScanManager.c ScanFileDirect 步骤5/6间  */
/*  (IocDocument_ScanFile + ResultToIocScan) 留     */
/*  TODO。                                         */
/*                                                  */
/*  依赖:                                          */
/*   - IOC/IocArchiveScanner.{c,h}  (OOXML         */
/*     vbaProject.bin 提取, WkdArc_ExtractEntry)   */
/*   - IocScanner_ComputeBufferSha256 (载荷哈希)    */
/*   - IocpCalculateShannonEntropy 等价实现          */
/*     (本文内 WkdDocEntropy 自含, 不复用)          */
/*   - PhantomCortex AI → 评分不含 AI 维度 (死)     */
/**************************************************/

#pragma once

#include <windows.h>
#include "IocTypes.h"

/**************************************************/
/*               文档类型                           */
/*  对齐 SS DocumentType L174-195 (0-3 保留 wkd    */
/*  既有值, 4 起追加)                              */
/**************************************************/

typedef enum _WKD_DOC_TYPE {
    WkdDocType_Unknown = 0,
    WkdDocType_PDF,         /* %PDF */
    WkdDocType_OLE,         /* D0CF11E0 复合文档 (doc/xls/ppt) */
    WkdDocType_OOXML,       /* PK zip 容器 (docx/xlsx/pptx) */
    WkdDocType_RTF,         /* {\rtf */
    WkdDocType_DOC,
    WkdDocType_DOCX,
    WkdDocType_DOCM,        /* 启用宏 */
    WkdDocType_DOT,
    WkdDocType_DOTM,        /* 宏模板 */
    WkdDocType_XLS,
    WkdDocType_XLSX,
    WkdDocType_XLSM,
    WkdDocType_XLSB,        /* 二进制 */
    WkdDocType_XLT,
    WkdDocType_PPT,
    WkdDocType_PPTX,
    WkdDocType_PPTM,
    WkdDocType_ODF,         /* OpenDocument */
    WkdDocType_MSG,         /* Outlook 消息 */
    WkdDocType_EML,         /* 邮件 */
    WkdDocType_ONE,         /* OneNote */
} WKD_DOC_TYPE, *PWKD_DOC_TYPE;

/**************************************************/
/*               威胁类型                           */
/*  对齐 SS ThreatType L201-247                     */
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
/*               结构体声明                         */
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
    CHAR                Location[64];   /* 文档内位置 */
    CHAR                MitreId[24];
    CHAR                Evidence[256];
} WKD_DOC_THREAT, *PWKD_DOC_THREAT;

/* 宏详情 (对齐 SS MacroInfo L281-309) */
typedef struct _WKD_DOC_MACRO {
    CHAR       ModuleName[64];
    CHAR       ModuleType[16];         /* Module/Class/Form */
    ULONG      LineCount;
    ULONG      RiskLevel;              /* 0 None / 1 Low / 2 Medium / 3 High / 4 Critical */
    DOUBLE     Entropy;
    BOOLEAN    IsAutoExec;
    BOOLEAN    IsObfuscated;
    BOOLEAN    HasShellExec;
    BOOLEAN    HasPowerShell;
    BOOLEAN    HasDownload;
    BOOLEAN    HasFileWrite;
    BOOLEAN    HasRegistryAccess;
    BOOLEAN    HasWMI;
    CHAR       SourceCode[2048];       /* 截断源码 */
} WKD_DOC_MACRO, *PWKD_DOC_MACRO;

/* OLE 嵌入对象 (对齐 SS OLEObjectInfo L315-330) */
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

/* PDF 对象 (对齐 SS PDFObjectInfo L335-346) */
typedef struct _WKD_DOC_PDF_OBJECT {
    ULONG      ObjectId;
    CHAR       ObjectType[32];
    CHAR       ActionType[32];
    CHAR       EmbeddedFileName[64];
    BOOLEAN    HasJavaScript;
    BOOLEAN    HasAction;
    BOOLEAN    HasEmbeddedFile;
    CHAR       JsSnippet[1024];        /* JS 代码片段 */
} WKD_DOC_PDF_OBJECT, *PWKD_DOC_PDF_OBJECT;

/* 注意: WKD_DOC_SCAN_RESULT 约 40KB,
   调用方必须堆分配, 禁止栈上声明 */

typedef struct _WKD_DOC_SCAN_RESULT {
    WKD_DOC_TYPE        DocumentType;
    ULONG               RiskScore;      /* 0-100 */
    ULONG               Verdict;        /* 0 Clean / 1 Suspicious / 2 Malicious / 3 HighlyMalicious */
    CHAR                VerdictReason[128];
    ULONG64             FileSize;
    BOOLEAN             IsSpoofed;

    /* 宏 */
    BOOLEAN             HasMacros;
    ULONG               MacroCount;
    BOOLEAN             IsObfuscated;
    ULONG               HighestMacroRisk;
    WKD_DOC_MACRO       Macros[WKD_DOC_MAX_MACROS];

    /* OLE 嵌入对象 */
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
/*               函数声明                           */
/**************************************************/

/*++
Routine Description:
    检测文档类型 (签名判断 + 扩展名细化)。
    对齐 SS DetectDocumentType (魔数 + 扩展名映射)。

Arguments:
    FilePath - 文件完整路径。
    Type     - 输出 WKD_DOC_TYPE (细类型)。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocDocument_DetectType(
    _In_ PCWSTR         FilePath,
    _Out_ PWKD_DOC_TYPE Type
    );

/*++
Routine Description:
    文档威胁扫描主入口 (死代码，未接入流水线)。
    ContainerOf 归约到 PDF/OLE/OOXML/RTF 四基类分派:
    PDF action/JS / RTF OLE·CVE / OLE CFB 宏+嵌入对象 /
    OOXML vbaProject.bin 宏 / DDE / IOC 提取 / 评分判定。

Arguments:
    FilePath - 文件完整路径。
    Result   - 输出扫描结果 (调用方堆分配)。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocDocument_ScanFile(
    _In_ PCWSTR             FilePath,
    _Out_ PWKD_DOC_SCAN_RESULT Result
    );

/*++
Routine Description:
    独立 VBA 宏源码分析 (对齐 SS AnalyzeMacroCode)。
    AutoOpen 检测 / 可疑 API / 混淆 / URL·IP·Email 提取 / 风险分级。

Arguments:
    VbaCode - VBA 源码 (单字节)。
    Result  - 输出扫描结果 (仅宏字段有效)。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocDocument_AnalyzeVBACode(
    _In_ PCSTR              VbaCode,
    _Out_ PWKD_DOC_SCAN_RESULT Result
    );

/*++
Routine Description:
    文档扫描结果映射到 IOC_SCAN_RESULT (死代码)。
    供 ScanManager.ScanFileDirect 文档分支合并使用。
    Verdict: 0→Clean / 1→Suspicious / 2·3→Malicious;
    RiskScore→FinalConfidence; ThreatName="Doc.Macro"/"Doc.OLE"/
    "Doc.PDF"/"Doc.RTF"。

Arguments:
    Doc - 文档扫描结果。
    Ioc - 输出 IOC 扫描结果。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocDocument_ResultToIocScan(
    _In_ PWKD_DOC_SCAN_RESULT Doc,
    _Inout_ PIOC_SCAN_RESULT  Ioc
    );

/**************************************************/
/*           公开 API 面 (对齐 SS 全 API)          */
/*  功能面全量迁移, 活代码实现, 无调用者亦不       */
/*  告警 (导出函数)。                             */
/**************************************************/

/*++
Routine Description:
    缓冲版文档扫描 (对齐 SS ScanBuffer L467-515)。
    支持 PDF/RTF (buffer 内分析); 其他类型需文件路径。

Arguments:
    Buf    - 文档内容。
    Size   - 内容大小。
    DocType - 文档类型 (PDF/RTF)。
    Result - 输出扫描结果 (调用方堆分配)。

Return Value:
    NTSTATUS (STATUS_NOT_SUPPORTED 非 PDF/RTF)。
--*/
NTSTATUS
IocDocument_ScanBuffer(
    _In_ const BYTE*      Buf,
    _In_ ULONG            Size,
    _In_ WKD_DOC_TYPE     DocType,
    _Out_ PWKD_DOC_SCAN_RESULT Result
    );

/*++
Routine Description:
    快速宏存在检查 (对齐 SS HasMacros L517-549)。
    OOXML 宏类型 (DOCM/DOTM/XLSM/PPTM) 按扩展名判定;
    legacy OLE 按 VBA 字节特征判定。

Arguments:
    FilePath - 文件路径。
    Has      - 输出是否含宏。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocDocument_HasMacros(
    _In_ PCWSTR   FilePath,
    _Out_ PBOOLEAN Has
    );

/*++
Routine Description:
    快速恶意判定 (对齐 SS IsMalicious L551-600)。
    哈希库命中 (ioc_hashes) / CVE 模式前 1MB 匹配。
    YARA (SS PatternStore) 由 IocYaraScanner 异步覆盖 (死代码标注)。

Arguments:
    FilePath  - 文件路径。
    Malicious - 输出是否恶意。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocDocument_IsMalicious(
    _In_ PCWSTR   FilePath,
    _Out_ PBOOLEAN Malicious
    );

/*++
Routine Description:
    独立 IOC 提取 (对齐 SS ExtractIOCs L1269-1302)。
    URL/IP/Email 提取填充 Result (不覆盖既有字段, 追加)。

Arguments:
    FilePath - 文件路径。
    Result   - 扫描结果 (IOC 字段追加)。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocDocument_ExtractIocs(
    _In_ PCWSTR              FilePath,
    _Inout_ PWKD_DOC_SCAN_RESULT Result
    );

/*++
Routine Description:
    独立 PDF 对象分析 (对齐 SS AnalyzePDF L1133-1244)。
    填充 Result->PdfObjects/HasPdfJavaScript/HasPdfActions。

Arguments:
    FilePath - PDF 文件路径。
    Result   - 扫描结果 (PDF 字段)。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocDocument_AnalyzePdf(
    _In_ PCWSTR              FilePath,
    _Inout_ PWKD_DOC_SCAN_RESULT Result
    );

/*++
Routine Description:
    PDF JavaScript 代码提取 (对齐 SS ExtractPDFJavaScript L1246-1263)。
    聚合所有 PDF 对象 JsSnippet 到连续缓冲。

Arguments:
    FilePath    - PDF 文件路径。
    JsSnippets  - 输出 JS 片段 (NUL 分隔)。
    JsSnippetsSize - 输出缓冲大小。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocDocument_ExtractPdfJavaScript(
    _In_ PCWSTR  FilePath,
    _Out_ PCHAR  JsSnippets,
    _In_ ULONG   JsSnippetsSize
    );

/*++
Routine Description:
    独立 OLE 嵌入对象提取 (对齐 SS ExtractOLEObjects L701-1122)。
    填充 Result->OleObjects (CLSID/CompObj/Package/可执行判定)。

Arguments:
    FilePath - OLE 文件路径。
    Result   - 扫描结果 (OLE 字段)。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocDocument_ExtractOleObjects(
    _In_ PCWSTR              FilePath,
    _Inout_ PWKD_DOC_SCAN_RESULT Result
    );

/*++
Routine Description:
    OLE 流枚举 (对齐 SS ListOLEStreams L1124-1127)。
    目录项名以分号分隔输出。

Arguments:
    FilePath    - OLE 文件路径。
    Streams     - 输出流名串。
    StreamsSize - 输出缓冲大小。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocDocument_ListOleStreams(
    _In_ PCWSTR  FilePath,
    _Out_ PCHAR  Streams,
    _In_ ULONG   StreamsSize
    );

/*++
Routine Description:
    独立宏提取 (对齐 SS ExtractMacros L606-631)。
    legacy OLE 字节扫 / OOXML vbaProject.bin 提取, 填充 Result->Macros。

Arguments:
    FilePath - 文档文件路径。
    Result   - 扫描结果 (宏字段)。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
IocDocument_ExtractMacros(
    _In_ PCWSTR              FilePath,
    _Inout_ PWKD_DOC_SCAN_RESULT Result
    );
