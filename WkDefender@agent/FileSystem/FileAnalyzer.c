/**************************************************/
/*  WkDefender Agent — 文件类型判定 + 文档/宏分析实现   */
/*                                                  */
/*  2026-09-14 重构合入:                            */
/*  1. 文件类型分析 (魔数/Disambiguate/扩展名兜底/   */
/*     欺骗检测) 自 Common/FileUtils.c 迁入         */
/*  2. 脚本/欺骗检测器 (6 个) 自 IOC/IocScanner.c 迁入 */
/*  3. 文档/宏分析保持原有结构                       */
/*                                                  */
/*  ⚠ 死代码：文档分析未接入流水线。               */
/*  接线点: ScanManager.c ScanFileDirect 步骤5/6间  */
/*  (IocDocument_ScanFile + ResultToIocScan) 留     */
/*  TODO。                                         */
/*                                                  */
/*  依赖复用:                                       */
/*   - IocArchiveScanner WkdArc_ExtractEntry        */
/*   - IocScanner_ComputeBufferSha256 (载荷哈希)     */
/*   - Common/FileUtils: CoEntropyBinary /           */
/*     CoReadFileHeader / IocScan_ContainsPe         */
/*  依赖缺失 (死代码标注):                          */
/*   - pugixml/XML 解析 → 模板注入/外部链接用        */
/*   - PhantomCortex AI → 评分不含 AI 维度           */
/*   - HashStore/PatternStore/YARA → 哈希/YARA 判定  */
/*  对齐注释: SS L<行号> 标注对应参考源码位置.      */
/**************************************************/

#include "FileSystemInternal.h"  /* 内部共享结构/限制宏 */
#include "../Include/FileSystem/FileAnalyzer.h"  /* 公共 API: IocDocument_* + 文件类型判定 */
#include "../IOC/IocArchiveScanner.h"
#include "../IOC/IocScanner.h"       /* IocScanner_ComputeBufferSha256/QueryHash */
#include "../Common/FileUtils.h" /* CoEntropyBinary / CoReadFileHeader / IocScan_ContainsPe */
#include "../Common/Utils.h"     /* CoCheckStringValidity */

#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <ntstatus.h>

/* 死代码 static 函数未引用警告 (项目惯例, 仿 IocArchiveScanner.c:25) */
#pragma warning(disable: 4505)

/**************************************************/
/*               限制常量                           */
/*  已提升至 FileSystemInternal.h, 此处不再重复    */
/**************************************************/

/* 可执行内容魔数 (L181-185) */
static const BYTE g_WkdDocPeMagic[]    = { 0x4D, 0x5A };
static const BYTE g_WkdDocElfMagic[]   = { 0x7F, 0x45, 0x4C, 0x46 };
static const BYTE g_WkdDocZipMagic[]   = { 0x50, 0x4B, 0x03, 0x04 };
static const BYTE g_WkdDocCabMagic[]   = { 0x4D, 0x53, 0x43, 0x46 };
static const BYTE g_WkdDocRarMagic[]   = { 0x52, 0x61, 0x72, 0x21 };

/**************************************************/
/*               检测常量表                         */
/*  DocumentScanner.cpp                    */
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
/*  L836-848 (CFBDirEntry)                 */
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

/* (WkdDocEntropy 删除, 统一至 Common/FileUtils CoEntropyBinary, 2026-09-14) */

/* UTF-16LE 目录项名 → ANSI (CFB 名称), ToNarrow */
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
/*  ExtractURLs L2798-2839 / ExtractIPs     */
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
/*  ExtractOLEObjects L701-1122            */
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

    /* 收集 FAT 扇区 ID: 头内 DIFAT 109 项 + 追链 (L750-804) */
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

/* 统一流读取: size<4096 走 MiniFAT, 否则 FAT 链 (L917-928) */
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

/* CLSID → GUID 字符串 (FormatCLSIDString L2074-2092) */
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

/* 匹配危险 CLSID 表 (MatchDangerousCLSID L2108-2116) */
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

/* 解析 \x01CompObj 流提取 ProgID (L2283-2313) */
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

/* 解析 Package 流: 嵌入路径 + 载荷 (ParsePackageStream L2321-2370) */
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

/* 嵌入内容可执行判定 (ContainsExecutableContent L2247-2276) */
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
/*  ExtractOLEObjects L701-1122            */
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

    /* 第一遍: 提取 CompObj ProgID (L942-960) */
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
            /* 未知 CLSID: CompObj ProgID 填充 (L999-1005) */
            strncpy_s(obj->ProgId, sizeof(obj->ProgId), progIds + (size_t)i * 64, _TRUNCATE);
        }
        if (isNamedPackage) {
            obj->IsPackage = TRUE;
            obj->IsExecutable = TRUE; /* Package 可嵌入任意可执行 */
        }

        /* 流数据提取 + 深度检查 (L1015-1064) */
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

        /* storage 子流扫描: Contents/Package/Ole10Native (L1066-1101) */
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

        /* CVE 关联: Equation 对象 (L1103-1109) */
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

/* OLE 流枚举 (死代码, ListOLEStreamsInternal L2372-2467) */
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
/*  AnalyzeMacroCode L1982-2064            */
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

    /* 熵 → 混淆 (复用主链 CoEntropyBinary) */
    Macro->Entropy = CoEntropyBinary((const BYTE*)Code, codeLen, 0);
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

    /* 风险评分 (L2046-2059) */
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

    /* 威胁 (L1542-1562 / L1624-1644) */
    if (Macro->RiskLevel >= 3) {
        WkdDocAddThreat(R,
            Macro->IsAutoExec ? WkdDocThreat_AutoExecMacro : WkdDocThreat_VBAMacro,
            (ULONG)Macro->RiskLevel * 25,
            Macro->IsAutoExec ? "Suspicious auto-exec macro" : "Suspicious VBA macro",
            "VBA", "T1059.005", Macro->ModuleName);
    }
}

/* 宏源码提取共用: 从二进制 buffer 扫 Attribute VB_Name (L1825-1886) */
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

    /* 判定 (CalculateVerdict 宏路径) */
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

/* (WkdDocDeobfuscateMacro 死代码已删, 2026-09-14 — 无任何调用者) */

/**************************************************/
/*               OOXML 宏提取                       */
/*  ExtractOOXMLMacros L1889-1980          */
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

        /* 有 VBA 项目但无 Attribute 指令 → 二进制占位 (L1959-1966) */
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
/*  CheckTemplateInjection L2541-2606      */
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

        /* 字节级特征: External 目标 + 模板/对象类型 (pugixml 判定) */
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
/*  CheckExternalLinks L2608-2672          */
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
/*  AnalyzePDF L1133-1244                  */
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

    /* 对象定位: "\d+ \d+ obj ... endobj" (L1157-1236) */
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

/* PDF 全文快扫 (兜底, AnalyzePDFBuffer L1731-1769) */
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
/*  AnalyzeRTFDocument L1664-1729          */
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
/*  CheckForDDE L2498-2539 (前 16MB)       */
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
/*  ExtractMetadata L2674-2761 (ScanFile 调用)     */
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
/*  CalculateVerdict L2939-3040            */
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

    /* 宏风险 (L2948-2951) */
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

/* IOC 去重 (ExtractAllIOCs L2773-2781 排序去重, 双重循环保序) */
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
/*  DetectDocumentType L1351-1414          */
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

/* OLE 复合文档扩展名细化 (主链已归 OLE, 此处补 WKD_DOC_TYPE 文档语义) */
static WKD_DOC_TYPE
IocDocument_RefineOleExtension(
    _In_ PCWSTR Extension
    )
{
    if (!Extension || !Extension[0]) return WkdDocType_OLE;
    if (_wcsicmp(Extension, L".xls") == 0) return WkdDocType_XLS;
    if (_wcsicmp(Extension, L".ppt") == 0) return WkdDocType_PPT;
    if (_wcsicmp(Extension, L".msg") == 0) return WkdDocType_MSG;
    if (_wcsicmp(Extension, L".dot") == 0) return WkdDocType_DOT;
    if (_wcsicmp(Extension, L".xlt") == 0) return WkdDocType_XLT;
    return WkdDocType_DOC;
}

/* OOXML zip 容器扩展名细化 (主链内容判定仅到 Docx/Xlsx/Pptx/Odf,
 * DOCM/XLSM/PPTM 宏语义依赖扩展名区分 — 内容不可判) */
static WKD_DOC_TYPE
IocDocument_RefineOoxmlExtension(
    _In_ PCWSTR Extension
    )
{
    if (!Extension || !Extension[0]) return WkdDocType_OOXML;
    if (_wcsicmp(Extension, L".docm") == 0) return WkdDocType_DOCM;
    if (_wcsicmp(Extension, L".dotm") == 0) return WkdDocType_DOTM;
    if (_wcsicmp(Extension, L".xlsx") == 0) return WkdDocType_XLSX;
    if (_wcsicmp(Extension, L".xlsm") == 0) return WkdDocType_XLSM;
    if (_wcsicmp(Extension, L".xlsb") == 0) return WkdDocType_XLSB;
    if (_wcsicmp(Extension, L".pptx") == 0) return WkdDocType_PPTX;
    if (_wcsicmp(Extension, L".pptm") == 0) return WkdDocType_PPTM;
    if (_wcsicmp(Extension, L".odt") == 0 || _wcsicmp(Extension, L".ods") == 0 ||
        _wcsicmp(Extension, L".odp") == 0) return WkdDocType_ODF;
    return WkdDocType_DOCX;
}

NTSTATUS
IocDocument_DetectType(
    _In_ PCWSTR         FilePath,
    _Out_ PWKD_DOC_TYPE Type
    )
{
    WKD_FILE_TYPE_INFO info;
    NTSTATUS status;

    if (!FilePath || !Type) return STATUS_INVALID_PARAMETER;
    *Type = WkdDocType_Unknown;

    /* 收敛: 复用主链完整类型分析 (读头 + 魔数表 + Disambiguate +
     * 扩展名兜底 + 路径欺骗检测), 本模块不再自持魔数判断。 */
    status = IocScan_AnalyzeFileTypePath(FilePath, &info);
    if (!NT_SUCCESS(status)) return STATUS_NOT_FOUND;  /* 保持原调用方语义 */
    if (!info.Detected) return STATUS_SUCCESS;

    /* 文档语义映射: WKD_FILE_FORMAT → WKD_DOC_TYPE (宏细分靠扩展名) */
    switch (info.Format) {
    case WkdFmt_Pdf:
        *Type = WkdDocType_PDF;
        break;
    case WkdFmt_Rtf:
        *Type = WkdDocType_RTF;
        break;
    case WkdFmt_Doc:
    case WkdFmt_Xls:
    case WkdFmt_Ppt:
    case WkdFmt_Msi:                    /* OLE 复合文档族 */
        *Type = IocDocument_RefineOleExtension(info.DiskExtension);
        break;
    case WkdFmt_Docx:
    case WkdFmt_Xlsx:
    case WkdFmt_Pptx:
    case WkdFmt_Odt:
    case WkdFmt_Ods:
    case WkdFmt_Odp:
    case WkdFmt_Zip:                    /* OOXML zip 容器族 */
        *Type = IocDocument_RefineOoxmlExtension(info.DiskExtension);
        break;
    default:
        break;                          /* 非文档格式 → Unknown */
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
        /* legacy OLE 宏源码提取 (ExtractOLEMacros L1795-1887) */
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
    if (readLen > 0) {
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

        /* IOC 去重 (ExtractAllIOCs) */
        WkdDocDedupeUrls(Result->Urls, &Result->UrlCount);
        WkdDocDedupeIps(Result->Ips, &Result->IpCount);
        WkdDocDedupeEmails(Result->Emails, &Result->EmailCount);
    }

    /* 高熵检测 (CalculateVerdict 分段熵) */
    if (readLen > 64 * 1024) {
        double ent = CoEntropyBinary(buf, readLen, 0);
        if (ent > 7.2) {
            WkdDocAddThreat(Result, WkdDocThreat_HighEntropy, 35,
                            "Document high entropy (packed/encrypted)", "whole", NULL, NULL);
        }
    }

    /* 元数据 (OOXML core.xml / PDF Info 字典) */
    WkdDocExtractMetadata(FilePath, type, Result);

    /* 评分判定 */
    WkdDocCalculateVerdict(Result);

    free(buf);
    return STATUS_SUCCESS;
}

/**************************************************/
/*               IOC 结果映射                      */
/*  ScanVerdict → wkd DefIocVerdict        */
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
/*           公开 API 面 (全 API)          */
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

/* CVE 模式存在性判定 (IsMalicious L587-592, 不添加威胁) */
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

    /* OOXML 宏类型按扩展名 (L524-527) */
    if (base == WkdDocType_OOXML) {
        if (type == WkdDocType_DOCM || type == WkdDocType_DOTM ||
            type == WkdDocType_XLSM || type == WkdDocType_PPTM) {
            *Has = TRUE;
        }
        return STATUS_SUCCESS;
    }

    /* legacy OLE: 字节扫 VBA 特征 (L529-540 流名判定) */
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

    /* 哈希库命中 (L556-563, wkd 用 ioc_hashes) */
    if (IocScanner_ComputeFileSha256(FilePath, &hash)) {
        if (NT_SUCCESS(IocScanner_QueryHash(&hash, &found)) && found) {
            *Malicious = TRUE;
            return STATUS_SUCCESS;
        }
    }

    /* YARA (SS PatternStore L565-577) → IocYaraScanner 异步覆盖 (死代码) */

    /* CVE 模式前 1MB (L578-592) */
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

/**************************************************
/*  FileTypeAnalyzer 迁移合入 (2026-09-14)            
/*  来源: Common/FileUtils.c (L219-L965 + L1017-L1658) 
/*         IOC/IocScanner.c (L518-L859)              
/*  公共函数声明移至 Include/FileSystem/FileAnalyzer.h  
**************************************************/

/* -------------------------------------------------- */
/* �ļ�����ʶ�� (SS FileTypeAnalyzer ȫ��Ǩ��, 2026-08-06) */
/* ħ���� + Disambiguate ���� + ���/����/��չ��ӳ�� +   */
/* �ű�����ʶ�� + ��չ����ƭ��� + ��������ڡ�          */
/* ���� API ���� (IocScanner.h), ��ˮ�߽��ߵ�           */
/* (FUTURE): ScanManager.ScanFileDirect ���� 5/6 ��     */
/* �� ��� IOC_SCAN_RESULT �ļ����ͳн��ֶ� ��            */
/* IocScan_Aggregate ��֧ + ��ƭ�澯 (T1036.007/008).    */
/* (IOC_FILE_TYPE ö�� + ���������� IocScanner.h,       */
/*  WKD_FILE_FORMAT/CATEGORY/RISK/SPOOFING �� IocTypes.h) */
/* -------------------------------------------------- */

/**************************************************/
/*  5.1 ħ��ǩ���� (SS g_signatures L740-883,       */
/*       WkdArc_MagicTable ���, mask ʵ��ȫ�ղü�) */
/**************************************************/

/* MIME ӳ�� helper ǰ������ (SS GetMimeForFormat L1108-1198, ������ ��8 ������
 * ������ά��; �� 5.6 ����� + 5.7 ��ѯ API ����, ��������) */
static PCSTR
IocScan_GetMimeForFormat(
    _In_ WKD_FILE_FORMAT Format
    );


static const BYTE WkdSig_Mz[]       = { 0x4D, 0x5A };                                     /* MZ */
static const BYTE WkdSig_Elf32[]    = { 0x7F, 0x45, 0x4C, 0x46, 0x01 };
static const BYTE WkdSig_Elf64[]    = { 0x7F, 0x45, 0x4C, 0x46, 0x02 };
static const BYTE WkdSig_MachO32[]  = { 0xFE, 0xED, 0xFA, 0xCE };
static const BYTE WkdSig_MachO64[]  = { 0xFE, 0xED, 0xFA, 0xCF };
static const BYTE WkdSig_CafeBabe[] = { 0xCA, 0xFE, 0xBA, 0xBE };
static const BYTE WkdSig_Wasm[]     = { 0x00, 0x61, 0x73, 0x6D };
static const BYTE WkdSig_Zip[]      = { 0x50, 0x4B, 0x03, 0x04 };
static const BYTE WkdSig_ZipEmpty[] = { 0x50, 0x4B, 0x05, 0x06 };
static const BYTE WkdSig_ZipSpan[]  = { 0x50, 0x4B, 0x07, 0x08 };
static const BYTE WkdSig_Rar[]      = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 };
static const BYTE WkdSig_Rar5[]     = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 };
static const BYTE WkdSig_7z[]       = { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C };
static const BYTE WkdSig_Gzip[]     = { 0x1F, 0x8B, 0x08 };
static const BYTE WkdSig_Bzip2[]    = { 0x42, 0x5A, 0x68 };
static const BYTE WkdSig_Xz[]       = { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 };
static const BYTE WkdSig_Cab[]      = { 0x4D, 0x53, 0x43, 0x46 };                        /* MSCF */
static const BYTE WkdSig_Iso[]      = { 0x43, 0x44, 0x30, 0x30, 0x31 };                  /* CD001 @0x8001 */
static const BYTE WkdSig_Tar[]      = { 0x75, 0x73, 0x74, 0x61, 0x72 };                  /* ustar @257 */
static const BYTE WkdSig_Vhd[]      = { 0x63, 0x6F, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x78 };
static const BYTE WkdSig_Vhdx[]     = { 0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6C, 0x65 };
static const BYTE WkdSig_Pdf[]      = { 0x25, 0x50, 0x44, 0x46, 0x2D };                  /* %PDF- */
static const BYTE WkdSig_Rtf[]      = { 0x7B, 0x5C, 0x72, 0x74, 0x66 };                  /* {\rtf */
static const BYTE WkdSig_Ole[]      = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
static const BYTE WkdSig_HtmlDoctype[] = { 0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x59, 0x50, 0x45 };
static const BYTE WkdSig_HtmlLow[]  = { 0x3C, 0x68, 0x74, 0x6D, 0x6C };                  /* <html */
static const BYTE WkdSig_HtmlUp[]   = { 0x3C, 0x48, 0x54, 0x4D, 0x4C };                  /* <HTML */
static const BYTE WkdSig_Xml[]      = { 0x3C, 0x3F, 0x78, 0x6D, 0x6C };                  /* <?xml */
static const BYTE WkdSig_Jpeg1[]    = { 0xFF, 0xD8, 0xFF, 0xE0 };
static const BYTE WkdSig_Jpeg2[]    = { 0xFF, 0xD8, 0xFF, 0xE1 };
static const BYTE WkdSig_Jpeg3[]    = { 0xFF, 0xD8, 0xFF, 0xE2 };
static const BYTE WkdSig_Jpeg4[]    = { 0xFF, 0xD8, 0xFF, 0xE8 };
static const BYTE WkdSig_Png[]      = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
static const BYTE WkdSig_Gif87[]    = { 0x47, 0x49, 0x46, 0x38, 0x37, 0x61 };
static const BYTE WkdSig_Gif89[]    = { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 };
static const BYTE WkdSig_Bmp[]      = { 0x42, 0x4D };                                    /* BM */
static const BYTE WkdSig_TiffLe[]   = { 0x49, 0x49, 0x2A, 0x00 };
static const BYTE WkdSig_TiffBe[]   = { 0x4D, 0x4D, 0x00, 0x2A };
static const BYTE WkdSig_Ico[]      = { 0x00, 0x00, 0x01, 0x00 };
static const BYTE WkdSig_Riff[]     = { 0x52, 0x49, 0x46, 0x46 };                        /* RIFF �� WAV/AVI/WEBP */
static const BYTE WkdSig_Psd[]      = { 0x38, 0x42, 0x50, 0x53 };                        /* 8BPS */
static const BYTE WkdSig_Mp31[]     = { 0xFF, 0xFB };
static const BYTE WkdSig_Mp32[]     = { 0xFF, 0xF3 };
static const BYTE WkdSig_Mp33[]     = { 0xFF, 0xF2 };
static const BYTE WkdSig_Id3[]      = { 0x49, 0x44, 0x33 };                              /* ID3 */
static const BYTE WkdSig_Flac[]     = { 0x66, 0x4C, 0x61, 0x43 };                        /* fLaC */
static const BYTE WkdSig_Ogg[]      = { 0x4F, 0x67, 0x67, 0x53 };                        /* OggS */
static const BYTE WkdSig_M4a[]      = { 0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, 0x4D, 0x34, 0x41 };
static const BYTE WkdSig_Mp4[]      = { 0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70 };
static const BYTE WkdSig_Ebml[]     = { 0x1A, 0x45, 0xDF, 0xA3 };                        /* EBML �� MKV/WEBM */
static const BYTE WkdSig_Mov[]      = { 0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70, 0x71, 0x74 };
static const BYTE WkdSig_Flv[]      = { 0x46, 0x4C, 0x56, 0x01 };
static const BYTE WkdSig_Ftyp[]     = { 0x66, 0x74, 0x79, 0x70 };                        /* ftyp @4 */
static const BYTE WkdSig_Sqlite[]   = { 0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33 };
static const BYTE WkdSig_Mdb[]      = { 0x00, 0x01, 0x00, 0x00, 0x53, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x20, 0x4A, 0x65, 0x74 };
static const BYTE WkdSig_Der[]      = { 0x30, 0x82 };                                    /* DER/ASN.1 */
static const BYTE WkdSig_Pem[]      = { 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E };
static const BYTE WkdSig_Ttf[]      = { 0x00, 0x01, 0x00, 0x00, 0x00 };
static const BYTE WkdSig_Otf[]      = { 0x4F, 0x54, 0x54, 0x4F, 0x00 };                   /* OTTO */
static const BYTE WkdSig_Woff[]     = { 0x77, 0x4F, 0x46, 0x46 };                        /* wOFF */
static const BYTE WkdSig_Woff2[]    = { 0x77, 0x4F, 0x46, 0x32 };                        /* wOF2 */
static const BYTE WkdSig_Lnk[]      = { 0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00 };
static const BYTE WkdSig_Evtx[]     = { 0x45, 0x6C, 0x66, 0x46, 0x69, 0x6C, 0x65 };       /* ElfFile */
static const BYTE WkdSig_Prefetch[] = { 0x53, 0x43, 0x43, 0x41 };                        /* SCCA */
static const BYTE WkdSig_Regf[]     = { 0x72, 0x65, 0x67, 0x66 };                        /* regf */

/* ħ��ǩ���� (SS L740-883, ȫ��; ý��/ƽ̨��ʽ����Ϊ��ƽ̨ȡ֤������,
 * Windows EDR �����ѷ�, ����������) */
static const WKD_MAGIC_SIGNATURE g_IocMagicTable[] = {
    { WkdSig_Mz,       sizeof(WkdSig_Mz),       0,      WkdFmt_Pe32 },          /* DisambiguatePE */
    { WkdSig_Elf32,    sizeof(WkdSig_Elf32),    0,      WkdFmt_Elf32 },
    { WkdSig_Elf64,    sizeof(WkdSig_Elf64),    0,      WkdFmt_Elf64 },
    { WkdSig_MachO32,  sizeof(WkdSig_MachO32),  0,      WkdFmt_MachO32 },
    { WkdSig_MachO64,  sizeof(WkdSig_MachO64),  0,      WkdFmt_MachO64 },
    { WkdSig_CafeBabe, sizeof(WkdSig_CafeBabe), 0,      WkdFmt_MachOUniversal }, /* DisambiguateCAFEBABE �� Java/MachO */
    { WkdSig_Wasm,     sizeof(WkdSig_Wasm),     0,      WkdFmt_WebAssembly },
    { WkdSig_Zip,      sizeof(WkdSig_Zip),      0,      WkdFmt_Zip },           /* DisambiguateZIP �� DOCX/XLSX/... */
    { WkdSig_ZipEmpty, sizeof(WkdSig_ZipEmpty), 0,      WkdFmt_Zip },
    { WkdSig_ZipSpan,  sizeof(WkdSig_ZipSpan),  0,      WkdFmt_Zip },
    { WkdSig_Rar,      sizeof(WkdSig_Rar),      0,      WkdFmt_Rar },
    { WkdSig_Rar5,     sizeof(WkdSig_Rar5),     0,      WkdFmt_Rar5 },
    { WkdSig_7z,       sizeof(WkdSig_7z),       0,      WkdFmt_SevenZip },
    { WkdSig_Gzip,     sizeof(WkdSig_Gzip),     0,      WkdFmt_Gzip },
    { WkdSig_Bzip2,    sizeof(WkdSig_Bzip2),    0,      WkdFmt_Bzip2 },
    { WkdSig_Xz,       sizeof(WkdSig_Xz),       0,      WkdFmt_Xz },
    { WkdSig_Cab,      sizeof(WkdSig_Cab),      0,      WkdFmt_Cab },
    { WkdSig_Iso,      sizeof(WkdSig_Iso),      0x8001, WkdFmt_Iso },
    { WkdSig_Tar,      sizeof(WkdSig_Tar),      257,    WkdFmt_Tar },
    { WkdSig_Vhd,      sizeof(WkdSig_Vhd),      0,      WkdFmt_Vhd },
    { WkdSig_Vhdx,     sizeof(WkdSig_Vhdx),     0,      WkdFmt_Vhdx },
    { WkdSig_Pdf,      sizeof(WkdSig_Pdf),      0,      WkdFmt_Pdf },
    { WkdSig_Rtf,      sizeof(WkdSig_Rtf),      0,      WkdFmt_Rtf },
    { WkdSig_Ole,      sizeof(WkdSig_Ole),      0,      WkdFmt_Doc },           /* DisambiguateOLE �� DOC/XLS/PPT/MSI */
    { WkdSig_HtmlDoctype, sizeof(WkdSig_HtmlDoctype), 0, WkdFmt_Html },
    { WkdSig_HtmlLow,  sizeof(WkdSig_HtmlLow),  0,      WkdFmt_Html },
    { WkdSig_HtmlUp,   sizeof(WkdSig_HtmlUp),   0,      WkdFmt_Html },
    { WkdSig_Xml,      sizeof(WkdSig_Xml),      0,      WkdFmt_Xml },
    { WkdSig_Jpeg1,    sizeof(WkdSig_Jpeg1),    0,      WkdFmt_Jpeg },
    { WkdSig_Jpeg2,    sizeof(WkdSig_Jpeg2),    0,      WkdFmt_Jpeg },
    { WkdSig_Jpeg3,    sizeof(WkdSig_Jpeg3),    0,      WkdFmt_Jpeg },
    { WkdSig_Jpeg4,    sizeof(WkdSig_Jpeg4),    0,      WkdFmt_Jpeg },
    { WkdSig_Png,      sizeof(WkdSig_Png),      0,      WkdFmt_Png },
    { WkdSig_Gif87,    sizeof(WkdSig_Gif87),    0,      WkdFmt_Gif },
    { WkdSig_Gif89,    sizeof(WkdSig_Gif89),    0,      WkdFmt_Gif },
    { WkdSig_Bmp,      sizeof(WkdSig_Bmp),      0,      WkdFmt_Bmp },
    { WkdSig_TiffLe,   sizeof(WkdSig_TiffLe),   0,      WkdFmt_Tiff },
    { WkdSig_TiffBe,   sizeof(WkdSig_TiffBe),   0,      WkdFmt_Tiff },
    { WkdSig_Ico,      sizeof(WkdSig_Ico),      0,      WkdFmt_Ico },
    { WkdSig_Riff,     sizeof(WkdSig_Riff),     0,      WkdFmt_Webp },          /* DisambiguateRIFF �� WAV/AVI/WEBP */
    { WkdSig_Psd,      sizeof(WkdSig_Psd),      0,      WkdFmt_Psd },
    { WkdSig_Mp31,     sizeof(WkdSig_Mp31),     0,      WkdFmt_Mp3 },
    { WkdSig_Mp32,     sizeof(WkdSig_Mp32),     0,      WkdFmt_Mp3 },
    { WkdSig_Mp33,     sizeof(WkdSig_Mp33),     0,      WkdFmt_Mp3 },
    { WkdSig_Id3,      sizeof(WkdSig_Id3),      0,      WkdFmt_Mp3 },
    { WkdSig_Flac,     sizeof(WkdSig_Flac),     0,      WkdFmt_Flac },
    { WkdSig_Ogg,      sizeof(WkdSig_Ogg),      0,      WkdFmt_Ogg },
    { WkdSig_M4a,      sizeof(WkdSig_M4a),      0,      WkdFmt_M4a },
    { WkdSig_Mp4,      sizeof(WkdSig_Mp4),      0,      WkdFmt_Mp4 },           /* DisambiguateFtyp */
    { WkdSig_Ebml,     sizeof(WkdSig_Ebml),     0,      WkdFmt_Mkv },           /* DisambiguateEBML �� MKV/WEBM */
    { WkdSig_Mov,      sizeof(WkdSig_Mov),      0,      WkdFmt_Mov },
    { WkdSig_Flv,      sizeof(WkdSig_Flv),      0,      WkdFmt_Flv },
    { WkdSig_Ftyp,     sizeof(WkdSig_Ftyp),     4,      WkdFmt_Mp4 },           /* ͨ�� ftyp@4 */
    { WkdSig_Sqlite,   sizeof(WkdSig_Sqlite),   0,      WkdFmt_Sqlite },
    { WkdSig_Mdb,      sizeof(WkdSig_Mdb),      0,      WkdFmt_Mdb },
    { WkdSig_Der,      sizeof(WkdSig_Der),      0,      WkdFmt_Der },           /* DisambiguateDERPFX */
    { WkdSig_Pem,      sizeof(WkdSig_Pem),      0,      WkdFmt_Pem },
    { WkdSig_Ttf,      sizeof(WkdSig_Ttf),      0,      WkdFmt_Ttf },
    { WkdSig_Otf,      sizeof(WkdSig_Otf),      0,      WkdFmt_Otf },
    { WkdSig_Woff,     sizeof(WkdSig_Woff),     0,      WkdFmt_Woff },
    { WkdSig_Woff2,    sizeof(WkdSig_Woff2),    0,      WkdFmt_Woff2 },
    { WkdSig_Lnk,      sizeof(WkdSig_Lnk),      0,      WkdFmt_Lnk },
    { WkdSig_Evtx,     sizeof(WkdSig_Evtx),     0,      WkdFmt_Evtx },
    { WkdSig_Prefetch, sizeof(WkdSig_Prefetch), 0,      WkdFmt_Prefetch },
    { WkdSig_Regf,     sizeof(WkdSig_Regf),     0,      WkdFmt_Registry },
};

/* ħ��ƥ�� (���� SS MatchesPattern L107-131, mask ȫ�ռ�) */
static BOOLEAN
CopMatchMagic(
    _In_ const PBYTE Data,
    _In_ SIZE_T DataSize,
    _In_ const PWKD_MAGIC_SIGNATURE Signature
    )
{
    if (!Data || DataSize == 0 || !Signature) return FALSE;
    if (Signature->Offset + Signature->Length > DataSize) return FALSE;
    return RtlEqualMemory(Data + Signature->Offset, Signature->Bytes, Signature->Length);
}

/* buffer �Ӵ����� (SS std::search �ȼ�, �� DisambiguateZIP/EBML) */
static BOOLEAN
IocScan_MemContains(
    _In_ const BYTE* Buffer,
    _In_ ULONG       Size,
    _In_ PCSTR       Needle
    )
{
    SIZE_T nlen;
    ULONG i;
    if (!Buffer || !Needle) return FALSE;
    nlen = strlen(Needle);
    if (Size < nlen) return FALSE;
    for (i = 0; i + nlen <= Size; i++) {
        if (memcmp(Buffer + i, Needle, nlen) == 0) return TRUE;
    }
    return FALSE;
}
/**************************************************/
/*  5.2 Disambiguate ��ʽ���� (SS L351-679)         */
/**************************************************/

/* PE ����: EXE/DLL/SYS/.NET + 32/64 (���� SS L351-429,
 * ͷ�ڽ��� e_lfanew��COFF��CLR Ŀ¼#14, ħ���������� IocpAnalyzeBufferEx) */
static WKD_FILE_FORMAT
CopDisambiguatePe(
    _In_ const PBYTE Data,
    _In_ SIZE_T DataSize
    )
{
    ULONG peOffset;
    BOOLEAN is64;
    BOOLEAN isDll;
    BOOLEAN isSys;

    if (!Data || DataSize < sizeof(IMAGE_DOS_HEADER)) return WkdFmt_Unknown;

    peOffset = (ULONG)((PIMAGE_DOS_HEADER)Data)->e_lfanew;
    if (peOffset < sizeof(IMAGE_DOS_HEADER) || peOffset > 1024 || peOffset + 24 > DataSize) return WkdFmt_Unknown;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(Data + peOffset);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return WkdFmt_Unknown;
        
    PIMAGE_FILE_HEADER fileHeader = &nt->FileHeader;
    if (fileHeader->SizeOfOptionalHeader +
        (PBYTE)&fileHeader->SizeOfOptionalHeader - Data > DataSize) return WkdFmt_Unknown;

    // is64 = (fileHeader->Machine == IMAGE_FILE_MACHINE_AMD64);
    is64 = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    isDll = (fileHeader->Characteristics & IMAGE_FILE_DLL) != 0;
    isSys = (fileHeader->Characteristics & IMAGE_FILE_SYSTEM) != 0;

    /* .NET: CLR Runtime Header (����Ŀ¼ #14) */
    //{
    //    USHORT optHeaderSize = (USHORT)((USHORT)Data[coff + 16] | ((USHORT)Data[coff + 17] << 8));
    //    ULONG optOffset = coff + 20;
    //    if (optHeaderSize > 0 && optOffset + 4 <= DataSize) {
    //        USHORT optMagic = (USHORT)((USHORT)Data[optOffset] | ((USHORT)Data[optOffset + 1] << 8));
    //        ULONG dataDirBase = 0;
    //        if (optMagic == 0x10B && optOffset + 96 <= DataSize) dataDirBase = optOffset + 96;   /* PE32 */
    //        else if (optMagic == 0x20B && optOffset + 112 <= DataSize) dataDirBase = optOffset + 112; /* PE32+ */
    //        if (dataDirBase > 0) {
    //            ULONG clrEntry = dataDirBase + (14 * 8);
    //            if (clrEntry + 8 <= DataSize) {
    //                ULONG clrRva = (ULONG)Data[clrEntry] | ((ULONG)Data[clrEntry + 1] << 8) |
    //                               ((ULONG)Data[clrEntry + 2] << 16) | ((ULONG)Data[clrEntry + 3] << 24);
    //                ULONG clrSize = (ULONG)Data[clrEntry + 4] | ((ULONG)Data[clrEntry + 5] << 8) |
    //                                ((ULONG)Data[clrEntry + 6] << 16) | ((ULONG)Data[clrEntry + 7] << 24);
    //                if (clrRva != 0 && clrSize != 0) return WkdFmt_DotNetAssembly;
    //            }
    //        }
    //    }
    //}

    if (isSys) return is64 ? WkdFmt_Sys64 : WkdFmt_Sys32;
    if (isDll) return is64 ? WkdFmt_Dll64 : WkdFmt_Dll32;
    return is64 ? WkdFmt_Pe64 : WkdFmt_Pe32;
}

/* ZIP ��������: DOCX/XLSX/PPTX/ODT/ODS/ODP/JAR (���� SS L450-489) */
static WKD_FILE_FORMAT
IocScan_DisambiguateZip(
    _In_ const BYTE* Buffer,
    _In_ ULONG       Size,
    _In_opt_ PCWSTR  DiskExtension
    )
{
    if (IocScan_MemContains(Buffer, Size, "[Content_Types].xml")) {
        if (IocScan_MemContains(Buffer, Size, "word/")) return WkdFmt_Docx;
        if (IocScan_MemContains(Buffer, Size, "xl/"))   return WkdFmt_Xlsx;
        if (IocScan_MemContains(Buffer, Size, "ppt/"))  return WkdFmt_Pptx;
    }
    if (IocScan_MemContains(Buffer, Size, "mimetype") &&
        IocScan_MemContains(Buffer, Size, "META-INF/")) {
        if (IocScan_MemContains(Buffer, Size, "application/vnd.oasis.opendocument.text")) return WkdFmt_Odt;
        if (IocScan_MemContains(Buffer, Size, "application/vnd.oasis.opendocument.spreadsheet")) return WkdFmt_Ods;
        if (IocScan_MemContains(Buffer, Size, "application/vnd.oasis.opendocument.presentation")) return WkdFmt_Odp;
    }
    if (IocScan_MemContains(Buffer, Size, "META-INF/MANIFEST.MF")) return WkdFmt_JavaJar;

    if (DiskExtension && DiskExtension[0]) {
        if (_wcsicmp(DiskExtension, L".docx") == 0 || _wcsicmp(DiskExtension, L".docm") == 0) return WkdFmt_Docx;
        if (_wcsicmp(DiskExtension, L".xlsx") == 0 || _wcsicmp(DiskExtension, L".xlsm") == 0 ||
            _wcsicmp(DiskExtension, L".xlsb") == 0) return WkdFmt_Xlsx;
        if (_wcsicmp(DiskExtension, L".pptx") == 0 || _wcsicmp(DiskExtension, L".pptm") == 0) return WkdFmt_Pptx;
        if (_wcsicmp(DiskExtension, L".odt") == 0) return WkdFmt_Odt;
        if (_wcsicmp(DiskExtension, L".ods") == 0) return WkdFmt_Ods;
        if (_wcsicmp(DiskExtension, L".odp") == 0) return WkdFmt_Odp;
        if (_wcsicmp(DiskExtension, L".jar") == 0) return WkdFmt_JavaJar;
    }
    return WkdFmt_Zip;
}

/* OLE �����ļ�����: DOC/XLS/PPT/MSI (���� SS L495-508, ����չ����ʾ) */
static WKD_FILE_FORMAT
IocScan_DisambiguateOle(
    _In_opt_ PCWSTR DiskExtension
    )
{
    if (DiskExtension && DiskExtension[0]) {
        if (_wcsicmp(DiskExtension, L".doc") == 0 || _wcsicmp(DiskExtension, L".dot") == 0 ||
            _wcsicmp(DiskExtension, L".wbk") == 0) return WkdFmt_Doc;
        if (_wcsicmp(DiskExtension, L".xls") == 0 || _wcsicmp(DiskExtension, L".xlt") == 0 ||
            _wcsicmp(DiskExtension, L".xla") == 0) return WkdFmt_Xls;
        if (_wcsicmp(DiskExtension, L".ppt") == 0 || _wcsicmp(DiskExtension, L".pot") == 0 ||
            _wcsicmp(DiskExtension, L".pps") == 0) return WkdFmt_Ppt;
        if (_wcsicmp(DiskExtension, L".msi") == 0 || _wcsicmp(DiskExtension, L".msp") == 0 ||
            _wcsicmp(DiskExtension, L".mst") == 0) return WkdFmt_Msi;
        if (_wcsicmp(DiskExtension, L".msg") == 0) return WkdFmt_Doc;
    }
    return WkdFmt_Doc;
}

/* RIFF ��������: WAV/AVI/WEBP (���� SS L434-445) */
static WKD_FILE_FORMAT
IocScan_DisambiguateRiff(
    _In_ const BYTE* Buffer,
    _In_ ULONG       Size
    )
{
    if (!Buffer || Size < 12) return WkdFmt_Unknown;
    if (Buffer[8] == 'W' && Buffer[9] == 'A' && Buffer[10] == 'V' && Buffer[11] == 'E') return WkdFmt_Wav;
    if (Buffer[8] == 'A' && Buffer[9] == 'V' && Buffer[10] == 'I' && Buffer[11] == ' ') return WkdFmt_Avi;
    if (Buffer[8] == 'W' && Buffer[9] == 'E' && Buffer[10] == 'B' && Buffer[11] == 'P') return WkdFmt_Webp;
    return WkdFmt_Unknown;
}

/* EBML ��������: MKV/WEBM (���� SS L513-523) */
static WKD_FILE_FORMAT
IocScan_DisambiguateEbml(
    _In_ const BYTE* Buffer,
    _In_ ULONG       Size
    )
{
    ULONG searchLen = (Size < 256) ? Size : 256;
    if (IocScan_MemContains(Buffer, searchLen, "webm")) return WkdFmt_Webm;
    if (IocScan_MemContains(Buffer, searchLen, "matroska")) return WkdFmt_Mkv;
    return WkdFmt_Mkv;
}

/* 0xCAFEBABE ����: Java Class vs Mach-O Universal (���� SS L528-539) */
static WKD_FILE_FORMAT
IocScan_DisambiguateCafebabe(
    _In_ const BYTE* Buffer,
    _In_ ULONG       Size
    )
{
    USHORT javaMajor;
    if (!Buffer || Size < 8) return WkdFmt_JavaClass;
    javaMajor = (USHORT)((USHORT)Buffer[6] << 8) | Buffer[7];
    if (javaMajor >= 45 && javaMajor <= 70) return WkdFmt_JavaClass;   /* JDK 1.1 ~ JDK 26 */
    return WkdFmt_MachOUniversal;
}

/* ftyp ý����������: MP4/MOV/M4A (���� SS L544-560) */
static WKD_FILE_FORMAT
IocScan_DisambiguateFtyp(
    _In_ const BYTE* Buffer,
    _In_ ULONG       Size
    )
{
    ULONG i;
    if (!Buffer || Size < 12) return WkdFmt_Mp4;
    for (i = 0; i + 12 <= Size && i < 32; i += 4) {
        if (Buffer[i + 4] == 'f' && Buffer[i + 5] == 't' &&
            Buffer[i + 6] == 'y' && Buffer[i + 7] == 'p') {
            CHAR b0 = (CHAR)Buffer[i + 8];
            CHAR b1 = (CHAR)Buffer[i + 9];
            CHAR b2 = (CHAR)Buffer[i + 10];
            if (b0 == 'M' && b1 == '4' && b2 == 'A') return WkdFmt_M4a;
            if (b0 == 'q' && b1 == 't') return WkdFmt_Mov;
            return WkdFmt_Mp4;
        }
    }
    return WkdFmt_Mp4;
}

/* DER/PFX ֤�龫�� (���� SS L565-572, ����չ��) */
static WKD_FILE_FORMAT
IocScan_DisambiguateDerpfx(
    _In_opt_ PCWSTR DiskExtension
    )
{
    if (DiskExtension && DiskExtension[0]) {
        if (_wcsicmp(DiskExtension, L".pfx") == 0 || _wcsicmp(DiskExtension, L".p12") == 0) return WkdFmt_Pfx;
    }
    return WkdFmt_Der;
}

/* ������: ��������ħ����ʽ (���� SS L626-679) */
static WKD_FILE_FORMAT
CopDisambiguateFormat(
    _In_ const PBYTE Data,
    _In_ SIZE_T DataSize,
    _In_ WKD_FILE_FORMAT InitialFormat,
    _In_opt_ PCWSTR DiskExtension
    )
{
    if (!Data || DataSize == 0 || InitialFormat == WkdFmt_Unknown) {
        return WkdFmt_Unknown;
    }

    switch (InitialFormat) {
    case WkdFmt_Pe32: case WkdFmt_Pe64:
    case WkdFmt_Dll32: case WkdFmt_Dll64:
    case WkdFmt_Sys32: case WkdFmt_Sys64:
        return CopDisambiguatePe(Data, DataSize);

    case WkdFmt_Zip: case WkdFmt_Docx: case WkdFmt_Xlsx: case WkdFmt_Pptx:
    case WkdFmt_Odt: case WkdFmt_Ods: case WkdFmt_Odp: case WkdFmt_JavaJar:
        return IocScan_DisambiguateZip(Data, DataSize, DiskExtension);

    case WkdFmt_Webp: case WkdFmt_Wav: case WkdFmt_Avi:
        return IocScan_DisambiguateRiff(Data, DataSize);

    case WkdFmt_Doc: case WkdFmt_Xls: case WkdFmt_Ppt: case WkdFmt_Msi:
        return IocScan_DisambiguateOle(DiskExtension);

    case WkdFmt_Mkv: case WkdFmt_Webm:
        return IocScan_DisambiguateEbml(Data, DataSize);

    case WkdFmt_MachOUniversal: case WkdFmt_JavaClass:
        return IocScan_DisambiguateCafebabe(Data, DataSize);

    case WkdFmt_Mp4: case WkdFmt_Mov: case WkdFmt_M4a:
        return IocScan_DisambiguateFtyp(Data, DataSize);

    case WkdFmt_Der: case WkdFmt_Pfx:
        return IocScan_DisambiguateDerpfx(DiskExtension);

    default:
        return InitialFormat;
    }
}

/**************************************************/
/*  5.3 ���/����/����/��չ��ӳ�� (SS L577-620,     */
/*       L887-1103, L1203-1330, L1813-1838)        */
/**************************************************/

/* ��ʽ������ (���� SS GetCategoryForFormat L887-1017) */
static WKD_FILE_CATEGORY
IocScan_FormatToCategory(
    _In_ WKD_FILE_FORMAT Format
    )
{
    switch (Format) {
    case WkdFmt_Pe32: case WkdFmt_Pe64:
    case WkdFmt_Elf32: case WkdFmt_Elf64:
    case WkdFmt_MachO32: case WkdFmt_MachO64: case WkdFmt_MachOUniversal:
    case WkdFmt_JavaClass: case WkdFmt_DotNetAssembly: case WkdFmt_WebAssembly:
        return WkdCat_Executable;
    case WkdFmt_Dll32: case WkdFmt_Dll64:
        return WkdCat_Library;
    case WkdFmt_Sys32: case WkdFmt_Sys64:
        return WkdCat_Driver;
    case WkdFmt_PowerShell: case WkdFmt_Batch: case WkdFmt_VBScript:
    case WkdFmt_JScript: case WkdFmt_JavaScript: case WkdFmt_Python:
    case WkdFmt_Ruby: case WkdFmt_Perl: case WkdFmt_ShellScript:
    case WkdFmt_Php: case WkdFmt_Lua: case WkdFmt_Hta:
        return WkdCat_Script;
    case WkdFmt_Pdf: case WkdFmt_Doc: case WkdFmt_Docx: case WkdFmt_Rtf:
    case WkdFmt_Odt: case WkdFmt_Html: case WkdFmt_Xml: case WkdFmt_Mhtml:
        return WkdCat_Document;
    case WkdFmt_Xls: case WkdFmt_Xlsx: case WkdFmt_Ods:
        return WkdCat_Spreadsheet;
    case WkdFmt_Ppt: case WkdFmt_Pptx: case WkdFmt_Odp:
        return WkdCat_Presentation;
    case WkdFmt_Zip: case WkdFmt_Rar: case WkdFmt_Rar5: case WkdFmt_SevenZip:
    case WkdFmt_Tar: case WkdFmt_Gzip: case WkdFmt_Bzip2: case WkdFmt_Xz:
    case WkdFmt_Cab: case WkdFmt_JavaJar:
        return WkdCat_Archive;
    case WkdFmt_Iso: case WkdFmt_Vhd: case WkdFmt_Vhdx:
        return WkdCat_DiskImage;
    case WkdFmt_Msi:
        return WkdCat_Installer;
    case WkdFmt_Jpeg: case WkdFmt_Png: case WkdFmt_Gif: case WkdFmt_Bmp:
    case WkdFmt_Tiff: case WkdFmt_Ico: case WkdFmt_Webp: case WkdFmt_Svg:
    case WkdFmt_Psd:
        return WkdCat_Image;
    case WkdFmt_Mp3: case WkdFmt_Wav: case WkdFmt_Flac: case WkdFmt_Ogg:
    case WkdFmt_Wma: case WkdFmt_Aac: case WkdFmt_M4a:
        return WkdCat_Audio;
    case WkdFmt_Mp4: case WkdFmt_Avi: case WkdFmt_Mkv: case WkdFmt_Mov:
    case WkdFmt_Wmv: case WkdFmt_Flv: case WkdFmt_Webm:
        return WkdCat_Video;
    case WkdFmt_Sqlite: case WkdFmt_Mdb:
        return WkdCat_Database;
    case WkdFmt_Json: case WkdFmt_Yaml: case WkdFmt_Ini: case WkdFmt_Reg:
        return WkdCat_Configuration;
    case WkdFmt_Der: case WkdFmt_Pem: case WkdFmt_Crt: case WkdFmt_Pfx:
        return WkdCat_Certificate;
    case WkdFmt_Ttf: case WkdFmt_Otf: case WkdFmt_Woff: case WkdFmt_Woff2:
        return WkdCat_Font;
    default:
        return WkdCat_Unknown;
    }
}

/* ��ʽ�����յȼ� (���� SS GetRiskForFormat L1022-1103) */
static WKD_RISK_LEVEL
IocScan_FormatToRisk(
    _In_ WKD_FILE_FORMAT Format
    )
{
    switch (Format) {
    case WkdFmt_Pe32: case WkdFmt_Pe64:
    case WkdFmt_Dll32: case WkdFmt_Dll64:
    case WkdFmt_Sys32: case WkdFmt_Sys64:
    case WkdFmt_Elf32: case WkdFmt_Elf64:
    case WkdFmt_MachO32: case WkdFmt_MachO64: case WkdFmt_MachOUniversal:
    case WkdFmt_DotNetAssembly: case WkdFmt_WebAssembly: case WkdFmt_Msi:
    case WkdFmt_Hta:
        return WkdRisk_Critical;
    case WkdFmt_PowerShell: case WkdFmt_Batch: case WkdFmt_VBScript:
    case WkdFmt_JScript: case WkdFmt_JavaScript: case WkdFmt_Python:
    case WkdFmt_Ruby: case WkdFmt_Perl: case WkdFmt_ShellScript:
    case WkdFmt_Php: case WkdFmt_Lua:
    case WkdFmt_Zip: case WkdFmt_Rar: case WkdFmt_Rar5: case WkdFmt_SevenZip:
    case WkdFmt_JavaJar: case WkdFmt_Cab:
    case WkdFmt_Iso: case WkdFmt_Vhd: case WkdFmt_Vhdx:
    case WkdFmt_Lnk:
        return WkdRisk_High;
    case WkdFmt_Pdf: case WkdFmt_Doc: case WkdFmt_Docx:
    case WkdFmt_Xls: case WkdFmt_Xlsx: case WkdFmt_Ppt: case WkdFmt_Pptx:
    case WkdFmt_Rtf: case WkdFmt_Odt: case WkdFmt_Ods: case WkdFmt_Odp:
    case WkdFmt_Html: case WkdFmt_Mhtml:
        return WkdRisk_Medium;
    case WkdFmt_Xml: case WkdFmt_Json: case WkdFmt_Yaml: case WkdFmt_Ini:
    case WkdFmt_Sqlite: case WkdFmt_Mdb:
        return WkdRisk_Low;
    default:
        return WkdRisk_Safe;
    }
}

/* ���� (���� SS GetDescriptionForFormat L577-620, ��Ҫ��ʽ) */
static const CHAR*
IocScan_GetDescriptionForFormat(
    _In_ WKD_FILE_FORMAT Format
    )
{
    switch (Format) {
    case WkdFmt_Pe32: return "PE32 Executable";
    case WkdFmt_Pe64: return "PE64 Executable";
    case WkdFmt_Dll32: return "PE32 DLL";
    case WkdFmt_Dll64: return "PE64 DLL";
    case WkdFmt_Sys32: return "PE32 Kernel Driver";
    case WkdFmt_Sys64: return "PE64 Kernel Driver";
    case WkdFmt_DotNetAssembly: return ".NET Managed Assembly";
    case WkdFmt_Elf32: return "ELF 32-bit";
    case WkdFmt_Elf64: return "ELF 64-bit";
    case WkdFmt_MachO32: return "Mach-O 32-bit";
    case WkdFmt_MachO64: return "Mach-O 64-bit";
    case WkdFmt_MachOUniversal: return "Mach-O Universal";
    case WkdFmt_JavaClass: return "Java Class File";
    case WkdFmt_JavaJar: return "Java JAR Archive";
    case WkdFmt_WebAssembly: return "WebAssembly Module";
    case WkdFmt_Zip: return "ZIP Archive";
    case WkdFmt_Docx: return "MS Word DOCX";
    case WkdFmt_Xlsx: return "MS Excel XLSX";
    case WkdFmt_Pptx: return "MS PowerPoint PPTX";
    case WkdFmt_Odt: return "OpenDocument Text";
    case WkdFmt_Ods: return "OpenDocument Spreadsheet";
    case WkdFmt_Odp: return "OpenDocument Presentation";
    case WkdFmt_Doc: return "MS Word Document (OLE)";
    case WkdFmt_Xls: return "MS Excel Spreadsheet (OLE)";
    case WkdFmt_Ppt: return "MS PowerPoint (OLE)";
    case WkdFmt_Msi: return "Windows Installer (OLE)";
    case WkdFmt_Pdf: return "PDF Document";
    case WkdFmt_Rtf: return "RTF Document";
    case WkdFmt_Wav: return "WAV Audio";
    case WkdFmt_Avi: return "AVI Video";
    case WkdFmt_Webp: return "WebP Image";
    case WkdFmt_Mkv: return "Matroska Video";
    case WkdFmt_Webm: return "WebM Video";
    case WkdFmt_Mp4: return "MP4 Video";
    case WkdFmt_Mov: return "QuickTime Movie";
    case WkdFmt_M4a: return "M4A Audio";
    case WkdFmt_Der: return "DER Certificate";
    case WkdFmt_Pfx: return "PFX/PKCS#12 Certificate";
    case WkdFmt_Lnk: return "Windows Shortcut (LNK)";
    default: return "Unknown format";
    }
}

/* ��չ������ʽӳ�� (���� SS g_extensionMap L1203-1330, ȫ��) */
static const struct {
    PCSTR          Ext;      /* Сд���� */
    WKD_FILE_FORMAT Format;
} g_IocExtensionMap[] = {
    { ".exe", WkdFmt_Pe32 }, { ".dll", WkdFmt_Dll32 }, { ".sys", WkdFmt_Sys32 },
    { ".scr", WkdFmt_Pe32 }, { ".cpl", WkdFmt_Dll32 }, { ".ocx", WkdFmt_Dll32 },
    { ".elf", WkdFmt_Elf64 }, { ".so", WkdFmt_Elf64 }, { ".dylib", WkdFmt_MachO64 },
    { ".class", WkdFmt_JavaClass }, { ".jar", WkdFmt_JavaJar },

    { ".ps1", WkdFmt_PowerShell }, { ".psm1", WkdFmt_PowerShell }, { ".psd1", WkdFmt_PowerShell },
    { ".bat", WkdFmt_Batch }, { ".cmd", WkdFmt_Batch },
    { ".vbs", WkdFmt_VBScript }, { ".vbe", WkdFmt_VBScript },
    { ".js", WkdFmt_JavaScript }, { ".jse", WkdFmt_JScript },
    { ".wsf", WkdFmt_JScript }, { ".wsh", WkdFmt_JScript },
    { ".py", WkdFmt_Python }, { ".pyw", WkdFmt_Python },
    { ".rb", WkdFmt_Ruby }, { ".pl", WkdFmt_Perl },
    { ".sh", WkdFmt_ShellScript }, { ".php", WkdFmt_Php },
    { ".lua", WkdFmt_Lua }, { ".hta", WkdFmt_Hta },

    { ".pdf", WkdFmt_Pdf }, { ".doc", WkdFmt_Doc }, { ".docx", WkdFmt_Docx },
    { ".xls", WkdFmt_Xls }, { ".xlsx", WkdFmt_Xlsx },
    { ".ppt", WkdFmt_Ppt }, { ".pptx", WkdFmt_Pptx },
    { ".rtf", WkdFmt_Rtf }, { ".odt", WkdFmt_Odt }, { ".ods", WkdFmt_Ods },
    { ".odp", WkdFmt_Odp }, { ".html", WkdFmt_Html }, { ".htm", WkdFmt_Html },
    { ".xml", WkdFmt_Xml }, { ".mhtml", WkdFmt_Mhtml }, { ".mht", WkdFmt_Mhtml },

    { ".zip", WkdFmt_Zip }, { ".rar", WkdFmt_Rar }, { ".7z", WkdFmt_SevenZip },
    { ".tar", WkdFmt_Tar }, { ".gz", WkdFmt_Gzip }, { ".bz2", WkdFmt_Bzip2 },
    { ".xz", WkdFmt_Xz }, { ".cab", WkdFmt_Cab }, { ".msi", WkdFmt_Msi },
    { ".iso", WkdFmt_Iso }, { ".vhd", WkdFmt_Vhd }, { ".vhdx", WkdFmt_Vhdx },

    { ".jpg", WkdFmt_Jpeg }, { ".jpeg", WkdFmt_Jpeg }, { ".png", WkdFmt_Png },
    { ".gif", WkdFmt_Gif }, { ".bmp", WkdFmt_Bmp }, { ".tif", WkdFmt_Tiff },
    { ".tiff", WkdFmt_Tiff }, { ".ico", WkdFmt_Ico }, { ".webp", WkdFmt_Webp },
    { ".svg", WkdFmt_Svg }, { ".psd", WkdFmt_Psd },

    { ".mp3", WkdFmt_Mp3 }, { ".wav", WkdFmt_Wav }, { ".flac", WkdFmt_Flac },
    { ".ogg", WkdFmt_Ogg }, { ".wma", WkdFmt_Wma }, { ".aac", WkdFmt_Aac },
    { ".m4a", WkdFmt_M4a },

    { ".mp4", WkdFmt_Mp4 }, { ".avi", WkdFmt_Avi }, { ".mkv", WkdFmt_Mkv },
    { ".mov", WkdFmt_Mov }, { ".wmv", WkdFmt_Wmv }, { ".flv", WkdFmt_Flv },
    { ".webm", WkdFmt_Webm },

    { ".db", WkdFmt_Sqlite }, { ".sqlite", WkdFmt_Sqlite }, { ".sqlite3", WkdFmt_Sqlite },
    { ".mdb", WkdFmt_Mdb }, { ".json", WkdFmt_Json },
    { ".yaml", WkdFmt_Yaml }, { ".yml", WkdFmt_Yaml },
    { ".ini", WkdFmt_Ini }, { ".cfg", WkdFmt_Ini }, { ".reg", WkdFmt_Reg },

    { ".crt", WkdFmt_Crt }, { ".cer", WkdFmt_Crt }, { ".pem", WkdFmt_Pem },
    { ".der", WkdFmt_Der }, { ".pfx", WkdFmt_Pfx }, { ".p12", WkdFmt_Pfx },

    { ".ttf", WkdFmt_Ttf }, { ".otf", WkdFmt_Otf },
    { ".woff", WkdFmt_Woff }, { ".woff2", WkdFmt_Woff2 },

    { ".lnk", WkdFmt_Lnk }, { ".url", WkdFmt_Url },
};

/* ��չ����ѯ (���� SS GetExtensionInfo L1797-1811, ���ظ�ʽ; δ���� Unknown) */
static WKD_FILE_FORMAT
IocScan_GetExtensionFormat(
    _In_ PCWSTR Extension   /* ����, �� L".exe" */
    )
{
    ULONG i;
    CHAR ext[24];

    if (!Extension || !Extension[0]) return WkdFmt_Unknown;
    ext[0] = '\0';
    WideCharToMultiByte(CP_ACP, 0, Extension, -1, ext, (int)sizeof(ext), NULL, NULL);
    ext[sizeof(ext) - 1] = '\0';
    if (ext[0] != '.') return WkdFmt_Unknown;

    for (i = 0; i < RTL_NUMBER_OF(g_IocExtensionMap); i++) {
        if (_stricmp(ext, g_IocExtensionMap[i].Ext) == 0) return g_IocExtensionMap[i].Format;
    }
    return WkdFmt_Unknown;
}

/* ��ʽ����ʵ��չ�� (���� SS GetExtensionForFormat L1813-1838) */
static VOID
CopGetFileSuffix(
    _In_ WKD_FILE_FORMAT FileFormat,
    _Out_ PWCHAR Suffix,
    _In_ SIZE_T SuffixSize
    )
{

    if (FileFormat == WkdFmt_Unknown || !Suffix || SuffixSize == 0) return;
    Suffix[0] = L'\0';

    switch (FileFormat) {
    case WkdFmt_Pe32: case WkdFmt_Pe64: case WkdFmt_DotNetAssembly:
        wcscpy_s(Suffix, SuffixSize, L".exe"); return;
    case WkdFmt_Dll32: case WkdFmt_Dll64:
        wcscpy_s(Suffix, SuffixSize, L".dll"); return;
    case WkdFmt_Sys32: case WkdFmt_Sys64:
        wcscpy_s(Suffix, SuffixSize, L".sys"); return;
    case WkdFmt_JavaJar:
        wcscpy_s(Suffix, SuffixSize, L".jar"); return;
    default:
        break;
    }

    for (ULONG i = 0; i < RTL_NUMBER_OF(g_IocExtensionMap); i++) {
        if (g_IocExtensionMap[i].Format == Suffix) {
            MultiByteToWideChar(CP_ACP, 0, g_IocExtensionMap[i].Ext, -1, Suffix, (int)SuffixSize);
            return;
        }
    }
}

/**************************************************/
/*  5.4 �ű�����ʶ�� (SS AnalyzeScript L1652-1756 + */
/*       DetectScriptType L1758-1791)               */
/**************************************************/

/* �ı������ж� (���� SS IsTextContent L136-197:
 * UTF-8 ���ֽ���Ч�� + NUL �� + ��90% �ɴ�ӡ) */

BOOLEAN
IocScan_IsTextContent(
    _In_ const BYTE* Data,
    _In_ ULONG       Size
    )
{
    ULONG checkSize;
    ULONG printableCount = 0;
    ULONG i;

    if (!Data || Size == 0) return FALSE;
    checkSize = (Size < 512) ? Size : 512;

    for (i = 0; i < checkSize; i++) {
        BYTE b = Data[i];

        if (b == 0x00) return FALSE;   /* NUL ���� */
        if (b == '\t' || b == '\n' || b == '\r') { printableCount++; continue; }
        if (b >= 0x20 && b <= 0x7E) { printableCount++; continue; }

        /* UTF-8 ���ֽ�����У�� */
        {
            ULONG seqLen = 0;
            ULONG cp = 0;
            ULONG j;

            if (b >= 0xC2 && b <= 0xDF) { seqLen = 2; cp = b & 0x1F; }
            else if (b >= 0xE0 && b <= 0xEF) { seqLen = 3; cp = b & 0x0F; }
            else if (b >= 0xF0 && b <= 0xF4) { seqLen = 4; cp = b & 0x07; }
            else return FALSE;

            if (i + seqLen > checkSize) return FALSE;
            for (j = 1; j < seqLen; j++) {
                BYTE cont = Data[i + j];
                if ((cont & 0xC0) != 0x80) return FALSE;
                cp = (cp << 6) | (cont & 0x3F);
            }
            if ((seqLen == 2 && cp < 0x80) || (seqLen == 3 && cp < 0x800) ||
                (seqLen == 4 && cp < 0x10000) ||
                (cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF) return FALSE;
            printableCount += seqLen;
            i += seqLen - 1;
        }
    }
    return (printableCount * 10 / checkSize) >= 9;   /* ��90% �ɴ�ӡ/�Ϸ��ı� */
}
/* ����������ļ����ͷ��� (���� SS AnalyzeBufferImpl L2015-2126:
 * ħ�� �� Disambiguate �� ���/����/��չ�� �� ��ƭ; �ű�ʶ��; ��չ������) */

NTSTATUS
CoDetermineFileTypeFromBuffer(
    _In_ const PBYTE Data,
    _In_ SIZE_T DataSize,
    _In_opt_ PCWSTR DiskExtension,
    _Out_ PWKD_FILE_TYPE_INFO Info
    )
{
    if (!Data || DataSize == 0 || !Info) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Info, sizeof(WKD_FILE_TYPE_INFO));

    Info->FileSize = DataSize;
    if (CoCheckStringValidity(DiskExtension)) {
        wcscpy_s(Info->DiskExtension, RTL_NUMBER_OF(Info->DiskExtension), DiskExtension);
    }

    /* ħ��ƥ�� + Disambiguate ���� (SS L2028-2069) */
    for (ULONG i = 0; i < RTL_NUMBER_OF(g_IocMagicTable); i++) {
        const PWKD_MAGIC_SIGNATURE sig = &g_IocMagicTable[i];
        if (CopMatchMagic(Data, DataSize, sig)) {
            Info->Detected = TRUE;
            Info->Format = CopDisambiguateFormat(Data, DataSize, sig->Format, DiskExtension);
            Info->Category = IocScan_FormatToCategory(Info->Format);
            Info->RiskLevel = IocScan_FormatToRisk(Info->Format);
            CopGetFileSuffix(Info->Format, Info->Extension, RTL_NUMBER_OF(Info->Extension));
            strncpy_s(Info->Description, sizeof(Info->Description),
                      IocScan_GetDescriptionForFormat(Info->Format), _TRUNCATE);
            strncpy_s(Info->MimeType, sizeof(Info->MimeType),
                      IocScan_GetMimeForFormat(Info->Format), _TRUNCATE);
            strncpy_s(Info->MatchedSignature, sizeof(Info->MatchedSignature),
                      IocScan_GetDescriptionForFormat(sig->Format), _TRUNCATE);
            Info->Confidence = 100;
            Info->MagicOffset = sig->Offset;
            Info->IsExecutable = (Info->Category == WkdCat_Executable ||
                                  Info->Category == WkdCat_Driver ||
                                  Info->Category == WkdCat_Library);
            Info->IsScript = (Info->Category == WkdCat_Script);
            Info->IsArchive = (Info->Category == WkdCat_Archive);
            Info->CanContainMacros = (Info->Format == WkdFmt_Doc || Info->Format == WkdFmt_Docx ||
                                      Info->Format == WkdFmt_Xls || Info->Format == WkdFmt_Xlsx ||
                                      Info->Format == WkdFmt_Ppt || Info->Format == WkdFmt_Pptx);
            Info->IsCompound = (Info->Format == WkdFmt_Doc || Info->Format == WkdFmt_Xls ||
                                Info->Format == WkdFmt_Ppt || Info->Format == WkdFmt_Msi);

            /* ��չ����ƭ��� (SS L2152-2234) */
            if (Info->DiskExtension[0]) {
                IocScan_CheckExtMismatch(Info);
            }
            return STATUS_SUCCESS;
        }
    }

    /* �ű�����ʶ�� (SS L2073-2098) */
    if (IocScan_IsTextContent(Data, DataSize)) {
        IocScan_AnalyzeScript(Data, DataSize, Info);
        if (Info->HasBOM || Info->HasShebang || Info->HasScriptKeywords) {
            Info->ScriptType = IocScan_DetectScriptType(Data, DataSize);
            if (Info->ScriptType != WkdFmt_Unknown) {
                Info->Detected = TRUE;
                Info->Format = Info->ScriptType;
                Info->Category = WkdCat_Script;
                Info->RiskLevel = IocScan_FormatToRisk(Info->ScriptType);
                CopGetFileSuffix(Info->ScriptType, Info->Extension, RTL_NUMBER_OF(Info->Extension));
                Info->IsScript = TRUE;
                Info->Confidence = 80;   /* SS 0.8 */
                strncpy_s(Info->Description, sizeof(Info->Description), "Script file", _TRUNCATE);
                strncpy_s(Info->MimeType, sizeof(Info->MimeType),
                          IocScan_GetMimeForFormat(Info->ScriptType), _TRUNCATE);
                return STATUS_SUCCESS;
            }
        }
        /* ���ı� (SS L2090-2097) */
        Info->Detected = TRUE;
        Info->Category = WkdCat_Text;
        Info->RiskLevel = WkdRisk_Safe;
        Info->Confidence = 70;   /* SS 0.7 */
        strncpy_s(Info->Description, sizeof(Info->Description), "Text file", _TRUNCATE);
        strncpy_s(Info->MimeType, sizeof(Info->MimeType), "text/plain", _TRUNCATE);
        return STATUS_SUCCESS;
    }

    /* ��չ������ (SS L2101-2116, ������ 0.3) */
    if (Info->DiskExtension[0]) {
        WKD_FILE_FORMAT extFmt = IocScan_GetExtensionFormat(Info->DiskExtension);
        if (extFmt != WkdFmt_Unknown) {
            Info->Detected = TRUE;
            Info->Format = extFmt;
            Info->Category = IocScan_FormatToCategory(extFmt);
            Info->RiskLevel = IocScan_FormatToRisk(extFmt);
            CopGetFileSuffix(extFmt, Info->Extension, RTL_NUMBER_OF(Info->Extension));
            Info->Confidence = 30;   /* SS 0.3 */
            strncpy_s(Info->Description, sizeof(Info->Description), "Detected by extension", _TRUNCATE);
            strncpy_s(Info->MimeType, sizeof(Info->MimeType),
                      IocScan_GetMimeForFormat(extFmt), _TRUNCATE);
            return STATUS_SUCCESS;
        }
    }

    /* δ֪ (SS L2118-2125) */
    Info->Detected = FALSE;
    Info->Category = WkdCat_Unknown;
    Info->RiskLevel = WkdRisk_Low;
    Info->Confidence = 0;
    return STATUS_SUCCESS;
}

/* ·���������ļ����ͷ��� (���� SS Analyze L1397-1519:
 * ·������ȫ + ������չ�� �� ��ͷ �� buffer ����) */

NTSTATUS
IocScan_AnalyzeFileTypePath(
    _In_  PCWSTR               FilePath,
    _Out_ PWKD_FILE_TYPE_INFO  Info
    )
{
    ULONG64 fileSize = 0;
    BYTE* header;
    ULONG headerLen;
    NTSTATUS status;

    if (!FilePath || !Info) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Info, sizeof(*Info));

    /* ·������ȫ��ƭ (SS L1408-1451), ���ȼ����� buffer ��� */
    IocScan_DetectPathSpoofing(FilePath, Info);

    /* ������չ�� */
    {
        PCWSTR dot = wcsrchr(FilePath, L'.');
        if (dot && dot != FilePath) {
            wcscpy_s(Info->DiskExtension, RTL_NUMBER_OF(Info->DiskExtension), dot);
        }
    }

    if (!NT_SUCCESS(CoReadFileHeader(FilePath, &fileSize, &header, &headerLen))) {
        Info->FileSize = fileSize;
        return STATUS_UNSUCCESSFUL;   /* 读头失败/路径欺骗判定 */
    }
    Info->FileSize = fileSize;

    status = CoDetermineFileTypeFromBuffer(header, headerLen,
                                           (Info->DiskExtension[0]) ? Info->DiskExtension : NULL,
                                           Info);
    if (header) free(header);
    return status;
}

/* �ַ���� (���� SS DetectFileType(span) L1764-1813, ���±����� IOC_FILE_TYPE ����) */
IOC_FILE_TYPE
CopDetermineFileTypeInternal(
    _In_ const PBYTE Data,
    _In_ ULONG DataSize
    )
{
    WKD_FILE_TYPE_INFO info;

    if (!Data || DataSize == 0) return IocFileType_Unknown;

    if (NT_SUCCESS(CoDetermineFileTypeFromBuffer(Data, DataSize, NULL, &info))) {
        switch (info.Category) {
        case WkdCat_Executable:
            if (info.Format == WkdFmt_Dll32 || info.Format == WkdFmt_Dll64) return IocFileType_Dll;
            if (info.Format == WkdFmt_Sys32 || info.Format == WkdFmt_Sys64) return IocFileType_Sys;
            if (info.Format == WkdFmt_Elf32 || info.Format == WkdFmt_Elf64) return IocFileType_Elf;
            if (info.Format == WkdFmt_Pe32) return IocFileType_Pe32;
            if (info.Format == WkdFmt_Pe64) return IocFileType_Pe64;
            return IocFileType_Unknown;
        case WkdCat_Script:
            return IocFileType_Script;
        case WkdCat_Document:
            if (info.Format == WkdFmt_Pdf) return IocFileType_Pdf;
            return IocFileType_Office;
        case WkdCat_Archive:
            return IocFileType_Archive;
        case WkdCat_Driver:
            return IocFileType_Sys;
        case WkdCat_Library:
            return IocFileType_Dll;
        default:
            break;
        }
    }
    return IocFileType_Unknown;
}

/* �ַ���� ·���� (���� SS DetectFileType(path) L1815-1849, ��ͷ�ж�) */
IOC_FILE_TYPE
CoDetermineFileType(
    _In_ PCWSTR FilePath
    )
{
    SIZE_T fileSize = 0;
    PBYTE header = NULL;
    SIZE_T headerSize = 0;
    IOC_FILE_TYPE result;

    if (!CoCheckStringValidity(FilePath)) return IocFileType_Unknown;

    if (!NT_SUCCESS(CoReadFileHeader(FilePath, &fileSize, &header, &headerSize))) {
        return IocFileType_Unknown;
    }

    result = CopDetermineFileTypeInternal(header, headerSize);

    free(header);
    return result;
}

/**************************************************/
/*  5.7 ��ѯ API ���� (SS ���� API �� L1554-1843:  */
/*       GetCategory/GetMimeType/IsExecutable/     */
/*       IsScript/IsArchive/CanContainMacros/      */
/*       DetectSpoofing/GetExtensionInfo/          */
/*       GetExtensionRisk; ����뵼������ˮ�ߵ�����) */
/**************************************************/

/* MIME ӳ�� helper ǰ�������� 5.1 �������� (������ ��8 ��������) */

/* ��չ���淶�� (Сд+����, ���� SS NormalizeExtension L202-215) */

static VOID
IocScan_NormalizeExtension(
    _In_  PCSTR Extension,   /* �ɴ���򲻴��� */
    _Out_ PCHAR Out,
    _In_  ULONG OutCch
    )
{
    ULONG i, o = 0;

    if (!Extension || !Out || OutCch == 0) return;
    if (Extension[0] != '.' && (o + 1) < OutCch) Out[o++] = '.';
    for (i = 0; Extension[i] && (o + 1) < OutCch; i++) {
        CHAR c = Extension[i];
        Out[o++] = (c >= 'A' && c <= 'Z') ? (CHAR)(c - 'A' + 'a') : c;
    }
    Out[o] = '\0';
}

/* ��չ��������Ϣ��ѯ (���� SS GetExtensionInfo L1797-1811:
 * format/category/risk/mime/isCommon; δ���� Format=Unknown) */

NTSTATUS
IocScan_GetExtensionInfo(
    _In_  PCWSTR              Extension,
    _Out_ PWKD_EXTENSION_INFO Info
    )
{
    CHAR ext[24];
    ULONG i;

    if (!Info) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Info, sizeof(*Info));
    if (!Extension || !Extension[0]) return STATUS_SUCCESS;

    ext[0] = '\0';
    WideCharToMultiByte(CP_ACP, 0, Extension, -1, ext, (int)sizeof(ext), NULL, NULL);
    ext[sizeof(ext) - 1] = '\0';
    IocScan_NormalizeExtension(ext, Info->Extension, sizeof(Info->Extension));

    for (i = 0; i < RTL_NUMBER_OF(g_IocExtensionMap); i++) {
        if (_stricmp(Info->Extension, g_IocExtensionMap[i].Ext) == 0) {
            Info->Format = g_IocExtensionMap[i].Format;
            Info->Category = IocScan_FormatToCategory(Info->Format);
            Info->RiskLevel = IocScan_FormatToRisk(Info->Format);
            strncpy_s(Info->MimeType, sizeof(Info->MimeType),
                      IocScan_GetMimeForFormat(Info->Format), _TRUNCATE);
            Info->IsCommon = TRUE;
            break;
        }
    }
    return STATUS_SUCCESS;
}

/* ��չ�����յȼ� (���� SS GetExtensionRisk L1840-1843) */
WKD_RISK_LEVEL
IocScan_GetExtensionRisk(
    _In_ PCWSTR Extension
    )
{
    WKD_EXTENSION_INFO info;

    if (!NT_SUCCESS(IocScan_GetExtensionInfo(Extension, &info))) return WkdRisk_Low;
    return info.RiskLevel;
}

/* ·��������ѯ (���� SS GetCategory L1554-1557, ��ͷ�ж�) */
WKD_FILE_CATEGORY
IocScan_GetCategory(
    _In_ PCWSTR FilePath
    )
{
    ULONG64 fileSize;
    BYTE* header;
    ULONG headerLen;
    WKD_FILE_TYPE_INFO info;
    WKD_FILE_CATEGORY cat = WkdCat_Unknown;

    if (!FilePath) return WkdCat_Unknown;
    if (!CoReadFileHeader(FilePath, &fileSize, &header, &headerLen)) return WkdCat_Unknown;
    if (header) {
        if (NT_SUCCESS(CoDetermineFileTypeFromBuffer(header, headerLen, NULL, &info))) {
            cat = info.Category;
        }
        free(header);
    }
    return cat;
}

/* ·���� MIME ��ѯ (����CoDetermineFileTypeFromBuffer��ؾ�̬������) */
PCSTR
IocScan_GetMimeType(
    _In_ PCWSTR FilePath
    )
{
    ULONG64 fileSize;
    BYTE* header;
    ULONG headerLen;
    WKD_FILE_TYPE_INFO info;
    PCSTR mime = "application/octet-stream";

    if (!FilePath) return mime;
    if (!CoReadFileHeader(FilePath, &fileSize, &header, &headerLen)) return mime;
    if (header) {
        if (NT_SUCCESS(CoDetermineFileTypeFromBuffer(header, headerLen, NULL, &info))) {
            mime = IocScan_GetMimeForFormat(info.Format);
        }
        free(header);
    }
    return mime;
}

/* ��ִ���ж� (���� SS IsCoDetermineFileTypeFromBufferry in Executable/Driver/Library) */
BOOLEAN
IocScan_IsExecutable(
    _In_ PCWSTR FilePath
    )
{
    WKD_FILE_CATEGORY cat = IocScan_GetCategory(FilePath);
    return (cat == WkdCat_Executable || cat == WkdCat_Driver || cat == WkdCat_Library);
}

/* ������ִ���ж� (���� SS IsExecutable(span) L1575-1581) */
BOOLEAN
IocScan_IsExecutableBuffer(
    _In_ const BYTE* Data,
    _In_ ULONG       Size
    )
{
    WKD_FILE_TYPE_INFO info;

    if (!Data || Size == 0) return FALSE;
    if (!NT_SUCCESS(CoDetermineFileTypeFromBuffer(Data, Size, NULL, &info))) return FALSE;
    return info.IsExecutable;
}

/* �ű��ж� (���� SS IsScript L1583-1586) */
BOOLEAN
IocScan_IsScript(
    _In_ PCWSTR FilePath
    )
{
    return (IocScan_GetCategory(FilePath) == WkdCat_Script);
}

/* �鵵�ж� (���� SS IsArchive L1588-1591) */
BOOLEAN
IocScan_IsArchive(
    _In_ PCWSTR FilePath
    )
{
    return (IocScan_GetCategory(FilePath) == WkdCat_Archive);
}

/* �ɺ����ж� (���� SS CanContainMacros L1593-1604: DOC/DOCX/XLS/XLSX/PPT/PPTX/ODT/ODS/ODP) */
BOOLEAN
IocScan_CanContainMacros(
    _In_ PCWSTR FilePath
    )
{
    WKD_FILE_TYPE_INFO info;

    if (NT_SUCCESS(IocScan_AnalyzeFileTypePath(FilePath, &info))) {
        return info.CanContainMacros;
    }
    return FALSE;
}

/* �ۺ���ƭ��� (���� SS DetectSpoofing L1610-1638:
 * RTLO �� ˫��չ�� �� ���ݲ�ƥ�����ȼ�) */
WKD_SPOOFING_TYPE
IocScan_DetectSpoofing(
    _In_ PCWSTR FilePath
    )
{
    WKD_FILE_TYPE_INFO info;
    PCWSTR filename;
    PCWSTR lastSlash;

    if (!FilePath) return WkdSpoof_None;

    lastSlash = wcsrchr(FilePath, L'\\');
    {
        PCWSTR s2 = wcsrchr(FilePath, L'/');
        if (s2 && (!lastSlash || s2 > lastSlash)) lastSlash = s2;
    }
    filename = (lastSlash) ? (lastSlash + 1) : FilePath;

    /* RTLO */
    if (IocScan_HasRtlOverride(filename)) return WkdSpoof_RtlOverride;

    /* ˫��չ�� */
    if (IocScan_HasDoubleExtension(filename)) return WkdSpoof_DoubleExtension;

    /* ���ݲ�ƥ�� (Analyze ·���� DetectPathSpoofing + CheckExtMismatch �Ѿۺ�) */
    if (NT_SUCCESS(IocScan_AnalyzeFileTypePath(FilePath, &info)) && info.IsSpoofed) {
        return info.SpoofingType;
    }
    return WkdSpoof_None;
}

/* Chi-square ͳ�� (���� SS CalculateChiSquare: expected=size/256,
 * chi=��(f-expected)^2/expected)�������/�����ж������� */

static PCSTR
IocScan_GetMimeForFormat(
    _In_ WKD_FILE_FORMAT Format
    )
{
    switch (Format) {
    case WkdFmt_Pe32: case WkdFmt_Pe64:
    case WkdFmt_Dll32: case WkdFmt_Dll64:
    case WkdFmt_Sys32: case WkdFmt_Sys64:
    case WkdFmt_DotNetAssembly:
        return "application/x-msdownload";
    case WkdFmt_Elf32: case WkdFmt_Elf64:
        return "application/x-executable";
    case WkdFmt_MachO32: case WkdFmt_MachO64: case WkdFmt_MachOUniversal:
        return "application/x-mach-binary";
    case WkdFmt_JavaClass:
        return "application/java-vm";
    case WkdFmt_JavaJar:
        return "application/java-archive";
    case WkdFmt_WebAssembly:
        return "application/wasm";
    case WkdFmt_PowerShell:
        return "application/x-powershell";
    case WkdFmt_Batch:
        return "application/x-bat";
    case WkdFmt_VBScript:
        return "text/vbscript";
    case WkdFmt_JScript: case WkdFmt_JavaScript:
        return "application/javascript";
    case WkdFmt_Python:
        return "text/x-python";
    case WkdFmt_Hta:
        return "application/hta";
    case WkdFmt_Pdf:
        return "application/pdf";
    case WkdFmt_Rtf:
        return "application/rtf";
    case WkdFmt_Doc:
        return "application/msword";
    case WkdFmt_Xls:
        return "application/vnd.ms-excel";
    case WkdFmt_Ppt:
        return "application/vnd.ms-powerpoint";
    case WkdFmt_Docx:
        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    case WkdFmt_Xlsx:
        return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    case WkdFmt_Pptx:
        return "application/vnd.openxmlformats-officedocument.presentationml.presentation";
    case WkdFmt_Odt:
        return "application/vnd.oasis.opendocument.text";
    case WkdFmt_Ods:
        return "application/vnd.oasis.opendocument.spreadsheet";
    case WkdFmt_Odp:
        return "application/vnd.oasis.opendocument.presentation";
    case WkdFmt_Html:
        return "text/html";
    case WkdFmt_Xml:
        return "text/xml";
    case WkdFmt_Mhtml:
        return "message/rfc822";
    case WkdFmt_Zip:
        return "application/zip";
    case WkdFmt_Rar: case WkdFmt_Rar5:
        return "application/x-rar-compressed";
    case WkdFmt_SevenZip:
        return "application/x-7z-compressed";
    case WkdFmt_Tar:
        return "application/x-tar";
    case WkdFmt_Gzip:
        return "application/gzip";
    case WkdFmt_Bzip2:
        return "application/x-bzip2";
    case WkdFmt_Xz:
        return "application/x-xz";
    case WkdFmt_Cab:
        return "application/vnd.ms-cab-compressed";
    case WkdFmt_Msi:
        return "application/x-msi";
    case WkdFmt_Iso:
        return "application/x-iso9660-image";
    case WkdFmt_Vhd:
        return "application/x-vhd";
    case WkdFmt_Vhdx:
        return "application/x-vhdx";
    case WkdFmt_Jpeg:
        return "image/jpeg";
    case WkdFmt_Png:
        return "image/png";
    case WkdFmt_Gif:
        return "image/gif";
    case WkdFmt_Bmp:
        return "image/bmp";
    case WkdFmt_Tiff:
        return "image/tiff";
    case WkdFmt_Ico:
        return "image/x-icon";
    case WkdFmt_Webp:
        return "image/webp";
    case WkdFmt_Svg:
        return "image/svg+xml";
    case WkdFmt_Psd:
        return "image/vnd.adobe.photoshop";
    case WkdFmt_Mp3:
        return "audio/mpeg";
    case WkdFmt_Wav:
        return "audio/wav";
    case WkdFmt_Flac:
        return "audio/flac";
    case WkdFmt_Ogg:
        return "audio/ogg";
    case WkdFmt_M4a:
        return "audio/mp4";
    case WkdFmt_Aac:
        return "audio/aac";
    case WkdFmt_Mp4:
        return "video/mp4";
    case WkdFmt_Avi:
        return "video/x-msvideo";
    case WkdFmt_Mkv:
        return "video/x-matroska";
    case WkdFmt_Mov:
        return "video/quicktime";
    case WkdFmt_Webm:
        return "video/webm";
    case WkdFmt_Flv:
        return "video/x-flv";
    case WkdFmt_Json:
        return "application/json";
    case WkdFmt_Yaml:
        return "text/yaml";
    case WkdFmt_Sqlite:
        return "application/x-sqlite3";
    case WkdFmt_Lnk:
        return "application/x-ms-shortcut";
    default:
        return "application/octet-stream";
    }
}

/* -- �Զ���ħ��ǩ��ע�� (SS AddSignature L1849-1888, ������) -----------------
 * ����: ����ʱע���Զ���ǩ�� (У��: ��/����/mask ʧ��/offset Խ��/
 *   MAX_SIGNATURES cap; Pattern/Mask ���������)��
 * ������ԭ��: �����ھ�̬�� g_IocMagicTable �Ѹ�������ǩ��; ����ʱ�·�
 *   �ɸ��ɲ�������/���������, ����Ϊ������ռλ�� */
#define IOC_MAGIC_MAX_SIGNATURES  1000

typedef struct _WKD_RUNTIME_MAGIC {
    WKD_MAGIC_SIGNATURE Sig;
    BYTE*               OwnedBytes;     /* Pattern+Mask ��� */
    BOOLEAN             HasMask;
    CHAR                Description[64];
    BOOLEAN             Valid;
} WKD_RUNTIME_MAGIC;

static WKD_RUNTIME_MAGIC g_IocRuntimeMagics[IOC_MAGIC_MAX_SIGNATURES];
static ULONG g_IocRuntimeMagicCount = 0;

static BOOLEAN
IocScan_AddMagicSignature(
    _In_ PCWSTR            Description,
    _In_ ULONG             Offset,
    _In_ WKD_FILE_FORMAT   Format,
    _In_ const BYTE*       Pattern,
    _In_ ULONG             PatternLen,
    _In_opt_ const BYTE*   Mask,
    _In_ ULONG             MaskLen
    )
{
    WKD_RUNTIME_MAGIC* slot;
    BYTE* owned;
    ULONG totalLen;
    ULONG idx;

    if (!Pattern || PatternLen == 0 || PatternLen > 256) return FALSE;
    if (Mask && MaskLen != PatternLen) return FALSE;
    if (Offset > FILE_HEADER_MAX_SIZE ||
        (ULONGLONG)Offset + PatternLen > FILE_HEADER_MAX_SIZE) return FALSE;
    if (g_IocRuntimeMagicCount >= IOC_MAGIC_MAX_SIGNATURES) return FALSE;

    totalLen = PatternLen + (Mask ? PatternLen : 0);
    owned = (BYTE*)malloc(totalLen);
    if (!owned) return FALSE;
    memcpy(owned, Pattern, PatternLen);
    if (Mask) memcpy(owned + PatternLen, Mask, PatternLen);

    idx = g_IocRuntimeMagicCount;
    slot = &g_IocRuntimeMagics[idx];
    slot->Sig.Bytes = owned;
    slot->Sig.Length = PatternLen;
    slot->Sig.Offset = Offset;
    slot->Sig.Format = Format;
    slot->OwnedBytes = owned;
    slot->HasMask = (Mask != NULL);
    if (Description) {
        strncpy_s(slot->Description, sizeof(slot->Description), Description, _TRUNCATE);
    }
    slot->Valid = TRUE;
    g_IocRuntimeMagicCount++;
    return TRUE;
}

/* -- JSON ǩ���ļ����� (SS LoadSignatures L1890-1996, ������) ----------------
 * ����: JSON ���� �� hex pattern ���� �� AddSignature (�� entry �� cap/
 *   offset У��/hex ����У��/��ʽö�� clamp)��
 * ������ԭ��: ����ȱʧ �� wkd �� JSON ������ (SS ���� Utils::JSON);
 *   hex ������������ AddMagicSignature ����, JSON �����л��������롣 */
static SIZE_T
IocScan_LoadSignatures(
    _In_ PCWSTR SignaturePath
    )
{
    UNREFERENCED_PARAMETER(SignaturePath);
    return 0;   /* δʵ��: �� JSON �� (����ȱʧ��ע) */
}


/**************************************************
/*  脚本/欺骗检测器迁移 (来源 IOC/IocScanner.c L518-859)
**************************************************/

/* �ļ������Ƿ� PE (���� SS ContainsPE L2492-2505: �� MZ, У�� e_lfanew
 * �� PE ǩ��)���ļ�����; �ڴ漶�� MsContainsPE (MemoryScan.c) ���ǡ� */
VOID
IocScan_AnalyzeScript(
    _In_  const BYTE*          Data,
    _In_  ULONG                Size,
    _Inout_ PWKD_FILE_TYPE_INFO Info
    )
{
    CHAR content[4096];
    SIZE_T cLen;
    ULONG i;

    if (!Data || !Info || Size < 2) return;

    /* BOM ��� (SS L1660-1669) */
    if (Size >= 3 && Data[0] == 0xEF && Data[1] == 0xBB && Data[2] == 0xBF) {
        Info->HasBOM = TRUE;
        strcpy_s(Info->BomType, sizeof(Info->BomType), "UTF-8");
    } else if (Size >= 2 && Data[0] == 0xFF && Data[1] == 0xFE) {
        Info->HasBOM = TRUE;
        strcpy_s(Info->BomType, sizeof(Info->BomType), "UTF-16 LE");
    } else if (Size >= 2 && Data[0] == 0xFE && Data[1] == 0xFF) {
        Info->HasBOM = TRUE;
        strcpy_s(Info->BomType, sizeof(Info->BomType), "UTF-16 BE");
    }

    /* Shebang ��ȡ (SS L1671-1692, cap 256 + �����ַ�����) */
    if (Data[0] == '#' && Data[1] == '!') {
        SIZE_T endPos = 2;
        SIZE_T kHardCap = (Size < (256 + 2)) ? Size : (256 + 2);
        Info->HasShebang = TRUE;
        while (endPos < kHardCap && Data[endPos] != '\n' && Data[endPos] != '\r') endPos++;
        if (endPos > 2) {
            SIZE_T len = (endPos - 2 < sizeof(Info->ShebangInterpreter) - 1)
                         ? (endPos - 2) : (sizeof(Info->ShebangInterpreter) - 1);
            memcpy(Info->ShebangInterpreter, Data + 2, len);
            Info->ShebangInterpreter[len] = '\0';
            for (i = 0; i < len; i++) {
                if ((UCHAR)Info->ShebangInterpreter[i] < 0x20 ||
                    (UCHAR)Info->ShebangInterpreter[i] == 0x7F) {
                    Info->ShebangInterpreter[i] = '?';   /* ���� SS SanitizeForLog CWE-117 */
                }
            }
        }
    }

    /* �ı����� + �ؼ��� (SS L1694-1752) */
    if (!IocScan_IsTextContent(Data, Size)) return;

    cLen = (Size < (SIZE_T)sizeof(content) - 1) ? Size : (SIZE_T)sizeof(content) - 1;
    for (i = 0; i < cLen; i++) {
        CHAR c = (CHAR)Data[i];
        content[i] = (c >= 'A' && c <= 'Z') ? (CHAR)(c - 'A' + 'a') : c;
    }
    content[cLen] = '\0';

    if (strstr(content, "param(") != NULL || strstr(content, "function ") != NULL ||
        strstr(content, "$_") != NULL || strstr(content, "write-host") != NULL) {
        Info->HasScriptKeywords = TRUE;
        if (Info->KeywordCount < 4) strcpy_s(Info->DetectedKeywords[Info->KeywordCount++], 32, "PowerShell");
    }
    if (strstr(content, "dim ") != NULL || strstr(content, "wscript.") != NULL ||
        strstr(content, "msgbox") != NULL) {
        Info->HasScriptKeywords = TRUE;
        if (Info->KeywordCount < 4) strcpy_s(Info->DetectedKeywords[Info->KeywordCount++], 32, "VBScript");
    }
    if (strstr(content, "import ") != NULL || strstr(content, "def ") != NULL ||
        strstr(content, "__name__") != NULL) {
        Info->HasScriptKeywords = TRUE;
        if (Info->KeywordCount < 4) strcpy_s(Info->DetectedKeywords[Info->KeywordCount++], 32, "Python");
    }
    if (strstr(content, "function(") != NULL || strstr(content, "var ") != NULL ||
        strstr(content, "const ") != NULL || strstr(content, "console.log") != NULL) {
        Info->HasScriptKeywords = TRUE;
        if (Info->KeywordCount < 4) strcpy_s(Info->DetectedKeywords[Info->KeywordCount++], 32, "JavaScript");
    }
    if (strstr(content, "@echo off") != NULL || strstr(content, "goto ") != NULL ||
        strstr(content, "setlocal") != NULL || strstr(content, "%~") != NULL) {
        Info->HasScriptKeywords = TRUE;
        if (Info->KeywordCount < 4) strcpy_s(Info->DetectedKeywords[Info->KeywordCount++], 32, "Batch");
    }
    if (strstr(content, "<hta:application") != NULL || strstr(content, "hta:application") != NULL) {
        Info->HasScriptKeywords = TRUE;
        if (Info->KeywordCount < 4) strcpy_s(Info->DetectedKeywords[Info->KeywordCount++], 32, "HTA");
    }
}

/* �ű������ж� (���� SS DetectScriptType L1758-1791:
 * �ı� �� Shebang ������ �� �ؼ���) */
WKD_FILE_FORMAT
IocScan_DetectScriptType(
    _In_ const BYTE* Data,
    _In_ ULONG       Size
    )
{
    WKD_FILE_TYPE_INFO info;
    ULONG i;

    if (!IocScan_IsTextContent(Data, Size)) return WkdFmt_Unknown;

    RtlZeroMemory(&info, sizeof(info));
    IocScan_AnalyzeScript(Data, Size, &info);

    if (info.HasShebang && info.ShebangInterpreter[0]) {
        CHAR interp[64];
        strncpy_s(interp, sizeof(interp), info.ShebangInterpreter, _TRUNCATE);
        _strlwr_s(interp, sizeof(interp));
        if (strstr(interp, "python") != NULL) return WkdFmt_Python;
        if (strstr(interp, "ruby") != NULL) return WkdFmt_Ruby;
        if (strstr(interp, "perl") != NULL) return WkdFmt_Perl;
        if (strstr(interp, "bash") != NULL) return WkdFmt_ShellScript;
        if (strstr(interp, "sh") != NULL) return WkdFmt_ShellScript;
        if (strstr(interp, "php") != NULL) return WkdFmt_Php;
    }

    if (info.HasScriptKeywords) {
        for (i = 0; i < info.KeywordCount; i++) {
            if (_stricmp(info.DetectedKeywords[i], "PowerShell") == 0) return WkdFmt_PowerShell;
            if (_stricmp(info.DetectedKeywords[i], "VBScript") == 0) return WkdFmt_VBScript;
            if (_stricmp(info.DetectedKeywords[i], "Python") == 0) return WkdFmt_Python;
            if (_stricmp(info.DetectedKeywords[i], "JavaScript") == 0) return WkdFmt_JavaScript;
            if (_stricmp(info.DetectedKeywords[i], "Batch") == 0) return WkdFmt_Batch;
            if (_stricmp(info.DetectedKeywords[i], "HTA") == 0) return WkdFmt_Hta;
        }
    }
    return WkdFmt_Unknown;
}

/**************************************************/
/*  5.5 ��չ����ƭ��� (SS HasRTLOverrideImpl       */
/*       L2236-2253 / HasDoubleExtensionImpl       */
/*       L2255-2298 / DetectSpoofingImpl           */
/*       L2152-2234 / Analyze path ��ȫ L1408-1451) */
/**************************************************/

/* RTLO ˫������ַ���� �� ȫ 7 �� (���� SS L2236-2253):
 * U+202A-202E (LRE/RLE/PDF/LRO/RLO) / U+2066-2069 (LRI/RLI/FSI/PDI) /
 * U+200E-200F (LRM/RLM) / U+061C (ALM) / U+200B-200D (ZWSP/ZWNJ/ZWJ) /
 * U+FEFF (BOM/ZWNNBSP) */
BOOLEAN
IocScan_HasRtlOverride(
    _In_ PCWSTR Filename
    )
{
    PCWSTR p;

    if (!Filename) return FALSE;
    for (p = Filename; *p; p++) {
        WCHAR ch = *p;
        if (ch >= 0x202A && ch <= 0x202E) return TRUE;
        if (ch >= 0x2066 && ch <= 0x2069) return TRUE;
        if (ch == 0x200E || ch == 0x200F) return TRUE;
        if (ch == 0x061C) return TRUE;
        if (ch >= 0x200B && ch <= 0x200D) return TRUE;
        if (ch == 0xFEFF) return TRUE;
    }
    return FALSE;
}

/* ˫��չ����� (���� SS HasDoubleExtensionImpl L2255-2298:
 * ������չ��Σ�� �� ǰһ����չ����ȫ �� file.txt.exe) */
BOOLEAN
IocScan_HasDoubleExtension(
    _In_ PCWSTR Filename
    )
{
    static const PCWSTR safeExtensions[] = {
        L".txt", L".pdf", L".doc", L".docx", L".xls", L".xlsx",
        L".ppt", L".pptx", L".jpg", L".jpeg", L".png", L".gif",
        L".bmp", L".tif", L".tiff", L".csv", L".rtf", L".odt",
        L".ods", L".odp", L".mp3", L".mp4", L".wav", L".avi",
        L".html", L".htm", L".xml", L".json", L".yaml", L".yml",
        L".log", L".cfg", L".ini", L".zip", L".rar", L".7z",
    };
    static const PCWSTR dangerousExtensions[] = {
        L".exe", L".scr", L".bat", L".cmd", L".com", L".pif",
        L".vbs", L".vbe", L".js", L".jse", L".wsf", L".wsh",
        L".ps1", L".psm1", L".hta", L".cpl", L".msi", L".msp",
        L".dll", L".sys", L".lnk",
    };
    WCHAR lower[260];
    PCWSTR lastDot;
    PCWSTR prevDot;
    PCWSTR scan;
    SIZE_T j;
    BOOLEAN finalIsDangerous = FALSE;
    BOOLEAN prevIsSafe = FALSE;
    SIZE_T i;

    if (!Filename || !Filename[0]) return FALSE;
    if (wcslen(Filename) >= RTL_NUMBER_OF(lower)) return FALSE;
    for (i = 0; Filename[i]; i++) lower[i] = (WCHAR)towlower(Filename[i]);
    lower[i] = L'\0';

    lastDot = wcsrchr(lower, L'.');
    if (!lastDot || lastDot == lower) return FALSE;

    for (j = 0; j < RTL_NUMBER_OF(dangerousExtensions); j++) {
        if (_wcsicmp(lastDot, dangerousExtensions[j]) == 0) { finalIsDangerous = TRUE; break; }
    }
    if (!finalIsDangerous) return FALSE;

    prevDot = NULL;
    for (scan = lower; scan < lastDot; scan++) {
        if (*scan == L'.') prevDot = scan;
    }
    if (!prevDot) return FALSE;
    for (j = 0; j < RTL_NUMBER_OF(safeExtensions); j++) {
        if (_wcsicmp(prevDot, safeExtensions[j]) == 0) { prevIsSafe = TRUE; break; }
    }
    return prevIsSafe;
}

/* ��չ��-���ݲ�ƥ���� (���� SS DetectSpoofingImpl L2152-2234,
 * ���Ϸ������չ��������: PE .exe/.scr/.com/.pif��DLL .dll/.ocx/.cpl/.drv��
 * SYS .sys��.NET .exe/.dll��ZIP docx/xlsx/...��OLE doc/dot/wbk/msg ��) */
BOOLEAN
IocScan_CheckExtMismatch(
    _Inout_ PWKD_FILE_TYPE_INFO Info
    )
{
    static const PCWSTR validZipExts[] = {
        L".docx", L".docm", L".xlsx", L".xlsm", L".xlsb",
        L".pptx", L".pptm", L".odt", L".ods", L".odp",
        L".jar", L".war", L".ear", L".apk", L".xpi",
        L".epub", L".cbz", L".nupkg", L".vsix",
    };
    PCWSTR disk;
    PCWSTR expected;
    SIZE_T j;

    if (!Info || Info->DiskExtension[0] == L'\0' || Info->Extension[0] == L'\0') return FALSE;

    disk = Info->DiskExtension;
    expected = Info->Extension;

    if (_wcsicmp(disk, expected) == 0) return FALSE;

    /* PE ��ִ�п��ж��ֺϷ���չ�� */
    if (Info->Format == WkdFmt_Pe32 || Info->Format == WkdFmt_Pe64) {
        if (_wcsicmp(disk, L".exe") == 0 || _wcsicmp(disk, L".scr") == 0 ||
            _wcsicmp(disk, L".com") == 0 || _wcsicmp(disk, L".pif") == 0) return FALSE;
    }
    if (Info->Format == WkdFmt_Dll32 || Info->Format == WkdFmt_Dll64) {
        if (_wcsicmp(disk, L".dll") == 0 || _wcsicmp(disk, L".ocx") == 0 ||
            _wcsicmp(disk, L".cpl") == 0 || _wcsicmp(disk, L".drv") == 0) return FALSE;
    }
    if (Info->Format == WkdFmt_Sys32 || Info->Format == WkdFmt_Sys64) {
        if (_wcsicmp(disk, L".sys") == 0) return FALSE;
    }
    if (Info->Format == WkdFmt_DotNetAssembly) {
        if (_wcsicmp(disk, L".exe") == 0 || _wcsicmp(disk, L".dll") == 0) return FALSE;
    }

    /* ZIP ������ʽ�Ϸ���չ������ */
    if (Info->Format == WkdFmt_Zip) {
        for (j = 0; j < RTL_NUMBER_OF(validZipExts); j++) {
            if (_wcsicmp(disk, validZipExts[j]) == 0) return FALSE;
        }
    }

    /* OLE �����ļ� */
    if (Info->Format == WkdFmt_Doc) {
        if (_wcsicmp(disk, L".doc") == 0 || _wcsicmp(disk, L".dot") == 0 ||
            _wcsicmp(disk, L".wbk") == 0 || _wcsicmp(disk, L".msg") == 0) return FALSE;
    }
    if (Info->Format == WkdFmt_Xls) {
        if (_wcsicmp(disk, L".xls") == 0 || _wcsicmp(disk, L".xlt") == 0 ||
            _wcsicmp(disk, L".xla") == 0) return FALSE;
    }
    if (Info->Format == WkdFmt_Ppt) {
        if (_wcsicmp(disk, L".ppt") == 0 || _wcsicmp(disk, L".pot") == 0 ||
            _wcsicmp(disk, L".pps") == 0) return FALSE;
    }
    if (Info->Format == WkdFmt_Msi) {
        if (_wcsicmp(disk, L".msi") == 0 || _wcsicmp(disk, L".msp") == 0 ||
            _wcsicmp(disk, L".mst") == 0) return FALSE;
    }

    /* ��չ����ƥ�� �� �����Ǹ����ص���ƭ (RTLO/ADS/β����) */
    if (!Info->IsSpoofed) {
        Info->IsSpoofed = TRUE;
        Info->SpoofingType = WkdSpoof_ExtensionMismatch;
    }
    wcscpy_s(Info->SuggestedExt, RTL_NUMBER_OF(Info->SuggestedExt), expected);
    return TRUE;
}

/* ·������ƭ�ۺ� (���� SS Analyze path ��ȫ��� L1408-1451:
 * Ƕ�� NUL �ض� / ADS ð�� / RTLO / β���ո��)��
 * ע: NUL �ضϹ��� (SS L1408-1414) ��� C++ wstring ��Ƕ NUL; wkd C PCWSTR
 * �ӿ��� wcslen �ض�, ��Ƕ NUL �����ܵ���˺��� �� ��Ȼ����, �߼���Ǩ�ơ� */
VOID
IocScan_DetectPathSpoofing(
    _In_ PCWSTR        FilePath,
    _Inout_ PWKD_FILE_TYPE_INFO Info
    )
{
    PCWSTR filename;
    PCWSTR lastSlash;
    const WCHAR* colonPos;
    BOOLEAN isDriveLetter;

    if (!FilePath || !Info) return;

    lastSlash = wcsrchr(FilePath, L'\\');
    {
        PCWSTR s2 = wcsrchr(FilePath, L'/');
        if (s2 && (!lastSlash || s2 > lastSlash)) lastSlash = s2;
    }
    filename = (lastSlash) ? (lastSlash + 1) : FilePath;

    /* NTFS ADS (�ļ�����ð��, �ų��̷� "C:") �� ���� SS L1423-1435 */
    colonPos = wcschr(filename, L':');
    if (colonPos != NULL) {
        isDriveLetter = (colonPos == filename + 1 &&
                         lastSlash == NULL &&
                         ((filename[0] >= L'A' && filename[0] <= L'Z') ||
                          (filename[0] >= L'a' && filename[0] <= L'z')));
        if (!isDriveLetter) {
            Info->IsSpoofed = TRUE;
            Info->SpoofingType = WkdSpoof_HiddenExtension;
            return;
        }
    }

    /* RTLO ˫������ַ� �� ���� SS L1437-1443 */
    if (IocScan_HasRtlOverride(filename)) {
        Info->IsSpoofed = TRUE;
        Info->SpoofingType = WkdSpoof_RtlOverride;
        return;
    }

    /* β���ո�/�� (NTFS �淶���ƹ�) �� ���� SS L1445-1450 */
    if (filename[0] != L'\0' &&
        (filename[wcslen(filename) - 1] == L' ' || filename[wcslen(filename) - 1] == L'.')) {
        Info->IsSpoofed = TRUE;
        Info->SpoofingType = WkdSpoof_HiddenExtension;
        return;
    }
}
