/**************************************************/
/*  WkDefender IOC 引擎 — 归档扫描实现              */
/*  功能面全量迁移自 ShadowStrike ArchiveExtractor   */
/*  + ScanEngine::ScanArchive (扫描模式)            */
/*  按功能融合重实现，非源码复制。                  */
/*                                                  */
/*  ⚠ 死代码：本阶段功能面覆盖，未接入流水线。      */
/*  接线点: ScanManager.c ScanFileDirect 步骤5/6间  */
/*  (IocArchive_ScanFile + 条目内容哈希) 留 TODO。  */
/**************************************************/

#include "IocArchiveScanner.h"
#include "../Common/FileUtils.h"

#include "PEAnalyzer/PeAnalyzer.h"        /* IocpCalculateShannonEntropy (SS 熵 L479-498 对齐) */
#include "IocScanner.h"                 /* ComputeBufferSha256 / QueryHash */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <wchar.h>
#include <wctype.h>
#include <ntstatus.h>

/* 兼容回退: STATUS_ENCRYPTED 为内核特有状态码, 用户态 ntstatus.h
 * 不含 (仅有 STATUS_ENCRYPTED_FILE_NOT_SUPPORTED 等)。此处按 SS
 * 语义补自定义值 (0xC0000070L 对应原内核 STATUS_ENCRYPTED)。 */
#ifndef STATUS_ENCRYPTED
#define STATUS_ENCRYPTED ((NTSTATUS)0xC0000070L)
#endif

#pragma warning(disable: 4505)   /* 死代码 static 函数未引用警告 (项目惯例) */

/**************************************************/
/*               常量定义                           */
/**************************************************/

#define WKD_ARC_MAX_FILE_SIZE   (200u * 1024u * 1024u)      /* 整读 cap, 保留 wkd 既有 */
#define WKD_ARC_MAX_RATIO       100.0                       /* SS DEFAULT_MAX_COMPRESSION_RATIO */
#define WKD_ARC_MAX_NESTING     5                           /* SS DEFAULT_MAX_NESTING_DEPTH */
#define WKD_ARC_MAX_ENTRY_SIZE   (2u * 1024u * 1024u * 1024u) /* SS DEFAULT_MAX_ENTRY_SIZE */
#define WKD_ARC_MAX_TOTAL_SIZE   (10u * 1024u * 1024u * 1024u) /* SS DEFAULT_MAX_TOTAL_SIZE */
#define WKD_ARC_MAX_INFLATE      (100u * 1024u * 1024u)     /* inflate 单条目输出上限 (MAX_MEMORY_EXTRACTION) */
#define WKD_ARC_MAGIC_READ_SIZE  0x8009                     /* ISO 需偏移 0x8001+8 */
#define WKD_ARC_MAX_CENTRAL_DIR  (256u * 1024u * 1024u)     /* ZIP 中央目录 256MB cap (SS L1088) */
#define WKD_ARC_EOCD_SEARCH      65558                      /* EOCD 尾部搜索窗口 */
#define WKD_ARC_PATH_MAX         260

/* ZIP 签名 */
#define WKD_ZIP_LOCAL_SIG        0x04034b50u
#define WKD_ZIP_CENTRAL_SIG      0x02014b50u
#define WKD_ZIP_EOCD_SIG         0x06054b50u
#define WKD_ZIP_ZIP64_LOC_SIG    0x07064b50u
#define WKD_ZIP_ZIP64_EOCD_SIG   0x06064b50u

#define WKD_ZIP_FLAG_ENCRYPTED        0x0001
#define WKD_ZIP_FLAG_DATA_DESCRIPTOR  0x0008
#define WKD_ZIP_FLAG_STRONG_ENCRYPT   0x0040
#define WKD_ZIP_FLAG_UTF8             0x0800
#define WKD_ZIP_ATTR_HIDDEN           0x00000002u  /* DOS 隐藏属性 */

/**************************************************/
/*               小端读取                           */
/**************************************************/

static ULONG
WkdArc_ReadLE16(
    _In_ const BYTE* P
    )
{
    return (ULONG)P[0] | ((ULONG)P[1] << 8);
}

static ULONG
WkdArc_ReadLE32(
    _In_ const BYTE* P
    )
{
    return (ULONG)P[0] | ((ULONG)P[1] << 8) |
           ((ULONG)P[2] << 16) | ((ULONG)P[3] << 24);
}

/* 溢出安全累加 (对齐 SS L2319-2323) */
static BOOLEAN
WkdArc_SafeAdd64(
    _In_  ULONG64  A,
    _In_  ULONG64  B,
    _Out_ PULONG64 Sum
    )
{
    if (A > (ULONG64)-1 - B) return FALSE;
    *Sum = A + B;
    return TRUE;
}

/**************************************************/
/*               UTF-8 → 宽字符                     */
/**************************************************/

static BOOLEAN
WkdArc_Utf8ToWide(
    _In_  PCSTR  Src,
    _Out_ PWSTR  Dst,
    _In_  ULONG  DstSize    /* WCHAR 数 */
    )
{
    if (!Src || !Dst || DstSize == 0) return FALSE;

    if (MultiByteToWideChar(CP_UTF8, 0, Src, -1, Dst, (int)DstSize) == 0) {
        /* 回退系统 ANSI (非 UTF-8 归档名) */
        if (MultiByteToWideChar(CP_ACP, 0, Src, -1, Dst, (int)DstSize) == 0) {
            Dst[0] = L'\0';
            return FALSE;
        }
    }
    return TRUE;
}

/**************************************************/
/*               CRC32 (查表法)                     */
/*  对齐 SS ComputeCrc32 L500-506 + CRC32_TABLE    */
/**************************************************/

static ULONG g_WkdArcCrc32Table[256];
static LONG g_WkdArcCrc32State = 0;   /* 0 未构建 / 1 构建中 / 2 就绪 */

static VOID
WkdArc_Crc32BuildTable(
    VOID
    )
{
    ULONG i, j;
    for (i = 0; i < 256; i++) {
        ULONG crc = i;
        for (j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320u : 0);
        }
        g_WkdArcCrc32Table[i] = crc;
    }
}

static VOID
WkdArc_Crc32EnsureTable(
    VOID
    )
{
    if (InterlockedCompareExchange(&g_WkdArcCrc32State, 1, 0) == 0) {
        WkdArc_Crc32BuildTable();
        InterlockedExchange(&g_WkdArcCrc32State, 2);
    } else {
        while (InterlockedCompareExchange(&g_WkdArcCrc32State, 2, 2) != 2) {
            Sleep(0);
        }
    }
}

ULONG
WkdArc_Crc32(
    _In_ const BYTE* Buffer,
    _In_ ULONG       Size
    )
{
    ULONG crc = 0xFFFFFFFFu;
    ULONG i;

    if (!Buffer) return 0;
    if (g_WkdArcCrc32State != 2) WkdArc_Crc32EnsureTable();

    for (i = 0; i < Size; i++) {
        crc = g_WkdArcCrc32Table[(crc ^ Buffer[i]) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

/**************************************************/
/*               归档格式检测                       */
/*  对齐 SS MAGIC_TABLE L199-213 + DetectFormat     */
/**************************************************/

typedef struct _WKD_ARC_MAGIC {
    const BYTE* Bytes;
    ULONG       Length;
    ULONG       Offset;
    WKD_ARCHIVE_FORMAT Format;
} WKD_ARC_MAGIC;

static const BYTE WkdArc_SigZip[]      = { 0x50, 0x4B, 0x03, 0x04 };
static const BYTE WkdArc_SigZipEmpty[] = { 0x50, 0x4B, 0x05, 0x06 };
static const BYTE WkdArc_SigRar5[]     = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 };
static const BYTE WkdArc_SigRar4[]     = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 };
static const BYTE WkdArc_Sig7z[]       = { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C };
static const BYTE WkdArc_SigGzip[]     = { 0x1F, 0x8B };
static const BYTE WkdArc_SigBzip2[]    = { 0x42, 0x5A, 0x68 };
static const BYTE WkdArc_SigXz[]       = { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 };
static const BYTE WkdArc_SigZstd[]     = { 0x28, 0xB5, 0x2F, 0xFD };
static const BYTE WkdArc_SigCab[]      = { 0x4D, 0x53, 0x43, 0x46 };
static const BYTE WkdArc_SigLzma[]     = { 0x5D, 0x00, 0x00 };
static const BYTE WkdArc_SigTar[]      = { 0x75, 0x73, 0x74, 0x61, 0x72 };  /* "ustar" @257 */
static const BYTE WkdArc_SigIso[]      = { 0x43, 0x44, 0x30, 0x30, 0x31 };  /* "CD001" @0x8001 */

static const WKD_ARC_MAGIC WkdArc_MagicTable[] = {
    { WkdArc_SigZip,      sizeof(WkdArc_SigZip),      0,       WkdArcFormat_Zip },
    { WkdArc_SigZipEmpty, sizeof(WkdArc_SigZipEmpty), 0,       WkdArcFormat_Zip },
    { WkdArc_SigRar5,     sizeof(WkdArc_SigRar5),     0,       WkdArcFormat_Rar5 },
    { WkdArc_SigRar4,     sizeof(WkdArc_SigRar4),     0,       WkdArcFormat_Rar4 },
    { WkdArc_Sig7z,       sizeof(WkdArc_Sig7z),       0,       WkdArcFormat_SevenZip },
    { WkdArc_SigGzip,     sizeof(WkdArc_SigGzip),     0,       WkdArcFormat_Gzip },
    { WkdArc_SigBzip2,    sizeof(WkdArc_SigBzip2),    0,       WkdArcFormat_Bzip2 },
    { WkdArc_SigXz,       sizeof(WkdArc_SigXz),       0,       WkdArcFormat_Xz },
    { WkdArc_SigZstd,     sizeof(WkdArc_SigZstd),     0,       WkdArcFormat_Zstd },
    { WkdArc_SigCab,      sizeof(WkdArc_SigCab),      0,       WkdArcFormat_Cab },
    { WkdArc_SigLzma,     sizeof(WkdArc_SigLzma),     0,       WkdArcFormat_Lzma },
    { WkdArc_SigTar,      sizeof(WkdArc_SigTar),      257,     WkdArcFormat_Tar },
    { WkdArc_SigIso,      sizeof(WkdArc_SigIso),      0x8001,  WkdArcFormat_Iso },
};

static const struct {
    PCWSTR Ext;
    WKD_ARCHIVE_FORMAT Fmt;
} WkdArc_ExtMap[] = {
    { L".zip",   WkdArcFormat_Zip },      { L".rar",   WkdArcFormat_Rar4 },
    { L".7z",    WkdArcFormat_SevenZip }, { L".tar",   WkdArcFormat_Tar },
    { L".gz",    WkdArcFormat_Gzip },     { L".gzip",  WkdArcFormat_Gzip },
    { L".bz2",   WkdArcFormat_Bzip2 },    { L".bzip2", WkdArcFormat_Bzip2 },
    { L".xz",    WkdArcFormat_Xz },       { L".lzma",  WkdArcFormat_Lzma },
    { L".zst",   WkdArcFormat_Zstd },     { L".zstd",  WkdArcFormat_Zstd },
    { L".cab",   WkdArcFormat_Cab },      { L".msi",   WkdArcFormat_Msi },
    { L".wim",   WkdArcFormat_Wim },      { L".iso",   WkdArcFormat_Iso },
    { L".vhd",   WkdArcFormat_Vhd },      { L".vhdx",  WkdArcFormat_Vhdx },
    { L".dmg",   WkdArcFormat_Dmg },      { L".img",   WkdArcFormat_Img },
    { L".arj",   WkdArcFormat_Arj },      { L".lzh",   WkdArcFormat_Lzh },
    { L".ace",   WkdArcFormat_Ace },      { L".cpio",  WkdArcFormat_Cpio },
    { L".rpm",   WkdArcFormat_Rpm },      { L".deb",   WkdArcFormat_Deb },
};

NTSTATUS
WkdArc_DetectFormatBuffer(
    _In_  const BYTE*          Buffer,
    _In_  ULONG                Size,
    _Out_ PWKD_ARCHIVE_FORMAT  Format
    )
/*++
Routine Description:
    从内存 buffer 检测归档格式 (魔数表优先)。
    对齐 SS DetectFormat(span) L961-972。

Arguments:
    Buffer - 头部字节。
    Size   - buffer 大小。
    Format - 输出格式。

Return Value:
    STATUS_SUCCESS。
--*/
{
    ULONG i;

    if (!Buffer || !Format) return STATUS_INVALID_PARAMETER;
    *Format = WkdArcFormat_Unknown;

    for (i = 0; i < sizeof(WkdArc_MagicTable) / sizeof(WkdArc_MagicTable[0]); i++) {
        const WKD_ARC_MAGIC* m = &WkdArc_MagicTable[i];
        if (Size < m->Offset + m->Length) continue;
        if (memcmp(Buffer + m->Offset, m->Bytes, m->Length) == 0) {
            *Format = m->Format;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_SUCCESS;
}

/* 提取文件名 (最后一个 \ / 之后) 转小写 */
static VOID
WkdArc_FileNameLower(
    _In_  PCWSTR FilePath,
    _Out_ WCHAR*  Out,
    _In_  ULONG   OutSize
    )
{
    PCWSTR slash;
    ULONG i;

    slash = wcsrchr(FilePath, L'\\');
    if (!slash) slash = wcsrchr(FilePath, L'/');
    if (slash) slash++;
    else slash = FilePath;

    for (i = 0; i + 1 < OutSize && slash[i] != L'\0'; i++) {
        Out[i] = (WCHAR)towlower(slash[i]);
    }
    Out[i] = L'\0';
}

NTSTATUS
WkdArc_DetectFormatPath(
    _In_  PCWSTR                FilePath,
    _Out_ PWKD_ARCHIVE_FORMAT   Format
    )
/*++
Routine Description:
    从文件路径检测归档格式 (魔数优先 + 复合 tar.* + 扩展名兜底)。
    对齐 SS DetectFormat(path) L866-959。

Arguments:
    FilePath - 文件路径。
    Format   - 输出格式。

Return Value:
    NTSTATUS。
--*/
{
    HANDLE h;
    BYTE head[WKD_ARC_MAGIC_READ_SIZE];
    DWORD rd = 0;
    WKD_ARCHIVE_FORMAT fmt;
    WCHAR nameLower[64];

    if (!FilePath || !Format) return STATUS_INVALID_PARAMETER;
    *Format = WkdArcFormat_Unknown;

    h = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return STATUS_NOT_FOUND;
    ReadFile(h, head, sizeof(head), &rd, NULL);
    CloseHandle(h);

    WkdArc_DetectFormatBuffer(head, rd, &fmt);
    if (fmt == WkdArcFormat_Unknown) {
        /* 扩展名兜底 (对齐 SS L931-952) */
        PCWSTR dot = wcsrchr(FilePath, L'.');
        if (dot) {
            ULONG i;
            for (i = 0; i < sizeof(WkdArc_ExtMap) / sizeof(WkdArc_ExtMap[0]); i++) {
                if (_wcsicmp(dot, WkdArc_ExtMap[i].Ext) == 0) {
                    *Format = WkdArc_ExtMap[i].Fmt;
                    break;
                }
            }
        }
        return STATUS_SUCCESS;
    }

    /* 复合格式: tar.gz/tgz, tar.bz2/tbz2, tar.xz/txz, tar.zst (对齐 SS L903-928) */
    WkdArc_FileNameLower(FilePath, nameLower, sizeof(nameLower) / sizeof(WCHAR));
    if (fmt == WkdArcFormat_Gzip &&
        (wcsstr(nameLower, L".tar.gz") || wcsstr(nameLower, L".tgz"))) {
        *Format = WkdArcFormat_TarGz;
    } else if (fmt == WkdArcFormat_Bzip2 &&
        (wcsstr(nameLower, L".tar.bz2") || wcsstr(nameLower, L".tbz2"))) {
        *Format = WkdArcFormat_TarBz2;
    } else if (fmt == WkdArcFormat_Xz &&
        (wcsstr(nameLower, L".tar.xz") || wcsstr(nameLower, L".txz"))) {
        *Format = WkdArcFormat_TarXz;
    } else if (fmt == WkdArcFormat_Zstd &&
        wcsstr(nameLower, L".tar.zst")) {
        *Format = WkdArcFormat_TarZstd;
    } else {
        *Format = fmt;
    }
    return STATUS_SUCCESS;
}

VOID
WkdArc_GetFormatName(
    _In_  WKD_ARCHIVE_FORMAT Format,
    _Out_ PCHAR             Buffer,
    _In_  ULONG              Size
    )
/*++
Routine Description:
    格式化归档格式名。对齐 SS GetFormatName L3737-3769。

Arguments:
    Format - 格式。
    Buffer - 输出缓冲区。
    Size   - 缓冲区大小。

Return Value:
    VOID。
--*/
{
    PCSTR name = "Unknown";
    switch (Format) {
    case WkdArcFormat_Zip:      name = "ZIP"; break;
    case WkdArcFormat_Rar4:     name = "RAR"; break;
    case WkdArcFormat_Rar5:     name = "RAR5"; break;
    case WkdArcFormat_SevenZip: name = "7-Zip"; break;
    case WkdArcFormat_Tar:      name = "TAR"; break;
    case WkdArcFormat_Gzip:     name = "GZIP"; break;
    case WkdArcFormat_Bzip2:    name = "BZIP2"; break;
    case WkdArcFormat_Xz:       name = "XZ"; break;
    case WkdArcFormat_Zstd:     name = "ZSTD"; break;
    case WkdArcFormat_Cab:      name = "CAB"; break;
    case WkdArcFormat_Lzma:     name = "LZMA"; break;
    case WkdArcFormat_Iso:      name = "ISO"; break;
    case WkdArcFormat_TarGz:    name = "TAR.GZ"; break;
    case WkdArcFormat_TarBz2:   name = "TAR.BZ2"; break;
    case WkdArcFormat_TarXz:    name = "TAR.XZ"; break;
    case WkdArcFormat_TarZstd:  name = "TAR.ZSTD"; break;
    case WkdArcFormat_Msi:      name = "MSI"; break;
    case WkdArcFormat_Wim:      name = "WIM"; break;
    case WkdArcFormat_Vhd:      name = "VHD"; break;
    case WkdArcFormat_Vhdx:     name = "VHDX"; break;
    case WkdArcFormat_Dmg:      name = "DMG"; break;
    case WkdArcFormat_Img:      name = "IMG"; break;
    case WkdArcFormat_Arj:      name = "ARJ"; break;
    case WkdArcFormat_Lzh:      name = "LZH"; break;
    case WkdArcFormat_Ace:      name = "ACE"; break;
    case WkdArcFormat_Cpio:     name = "CPIO"; break;
    case WkdArcFormat_Rpm:      name = "RPM"; break;
    case WkdArcFormat_Deb:      name = "DEB"; break;
    default:                    name = "Unknown"; break;
    }
    strncpy_s(Buffer, Size, name, _TRUNCATE);
}

/**************************************************/
/*               路径安全                           */
/*  对齐 SS IsPathSafe L528-591 + SanitizePath     */
/*  L593-662 + IsReservedDeviceName L508-526       */
/**************************************************/

/* 保留设备名 (对齐 SS RESERVED_NAMES L297-301, 先剥离扩展名 L509-512) */
static BOOLEAN
WkdArc_IsReservedDeviceName(
    _In_ PCWSTR Name    /* 组件, 内部剥离扩展名 */
    )
{
    static const WCHAR* Reserved[] = {
        L"CON", L"PRN", L"AUX", L"NUL",
        L"COM1", L"COM2", L"COM3", L"COM4", L"COM5", L"COM6", L"COM7", L"COM8", L"COM9",
        L"LPT1", L"LPT2", L"LPT3", L"LPT4", L"LPT5", L"LPT6", L"LPT7", L"LPT8", L"LPT9",
    };
    ULONG i;
    SIZE_T len = wcslen(Name);
    SIZE_T dot = 0;

    /* 剥离扩展名: baseName = [0, dot) */
    while (dot < len && Name[dot] != L'.') dot++;

    for (i = 0; i < sizeof(Reserved) / sizeof(Reserved[0]); i++) {
        SIZE_T rlen = wcslen(Reserved[i]);
        if (dot == rlen && _wcsnicmp(Name, Reserved[i], rlen) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
WkdArc_IsPathSafeW(
    _In_ PCWSTR PathW
    )
/*++
Routine Description:
    条目路径安全全量检查。对齐 SS IsPathSafe L528-591：
    绝对路径 / UNC / ../ / 尾部点空格 / 保留设备名 /
    非法字符 < > : " | ? * / Unicode 变体 / RTL bidi /
    嵌入 NUL / C0 控制 / ADS :: / 超长 260。

Arguments:
    PathW - 宽字符路径。

Return Value:
    TRUE = 安全。
--*/
{
    SIZE_T len;
    SIZE_T i;

    if (!PathW || PathW[0] == L'\0') return FALSE;
    len = wcslen(PathW);

    /* 绝对路径 / UNC 前缀 / 盘符 (对齐 SS L534-538) */
    if (PathW[0] == L'/' || PathW[0] == L'\\') return FALSE;
    if (len >= 2 && PathW[1] == L':') return FALSE;
    if (len >= 2 &&
        (PathW[0] == L'\\' || PathW[0] == L'/') &&
        (PathW[1] == L'\\' || PathW[1] == L'/')) return FALSE;

    /* 逐组件检查 (对齐 SS L540-561) */
    i = 0;
    while (i < len) {
        SIZE_T sep = i;
        SIZE_T clen;
        WCHAR comp[WKD_ARC_PATH_MAX + 1];
        SIZE_T k;

        while (sep < len && PathW[sep] != L'/' && PathW[sep] != L'\\') sep++;
        clen = sep - i;
        if (clen >= WKD_ARC_PATH_MAX) return FALSE;

        for (k = 0; k < clen; k++) comp[k] = PathW[i + k];
        comp[clen] = L'\0';

        /* ".." 组件 (任意大小写形式) */
        if (clen == 2 && comp[0] == L'.' && comp[1] == L'.') return FALSE;

        /* 尾部点/空格 — Windows 静默剥离 (对齐 SS L553-555) */
        if (clen > 0 && (comp[clen - 1] == L'.' || comp[clen - 1] == L' ')) return FALSE;

        /* 保留设备名 */
        if (clen > 0 && WkdArc_IsReservedDeviceName(comp)) return FALSE;

        if (sep >= len) break;
        i = sep + 1;
    }

    /* 全路径非法字符 (对齐 SS L563-580) */
    for (i = 0; i < len; i++) {
        WCHAR ch = PathW[i];
        if (ch == L'<' || ch == L'>' || ch == L':' || ch == L'"' ||
            ch == L'|' || ch == L'?' || ch == L'*') return FALSE;
        /* Unicode 规范化规避字符, 可折叠为 . / \ */
        if (ch == 0xFF0E /* 全角句点 */ || ch == 0xFF0F /* 全角斜杠 */ ||
            ch == 0x2215 /* division slash */ || ch == 0x29F8 /* big solidus */ ||
            ch == 0xFF3C /* 全角反斜杠 */) return FALSE;
        /* RTL 覆盖, 伪造扩展名 */
        if (ch == 0x202E || ch == 0x202D || ch == 0x202A ||
            ch == 0x202B || ch == 0x202C) return FALSE;
        if (ch == L'\0') return FALSE;
        if (ch < 0x20) return FALSE;   /* C0 控制 */
    }

    /* 备用数据流 (对齐 SS L582-583) */
    if (wcsstr(PathW, L"::") != NULL) return FALSE;

    /* 超长 (对齐 SS L586-588) */
    if (len > WKD_ARC_PATH_MAX) return FALSE;

    return TRUE;
}

BOOLEAN
WkdArc_SanitizePathW(
    _In_  PCWSTR PathW,
    _Out_ PWSTR  Out,
    _In_  ULONG  OutSize    /* WCHAR 数 */
    )
/*++
Routine Description:
    路径净化。对齐 SS SanitizePath L593-662：剥离绝对前缀、
    跳过 . 和 .. 组件、剥离尾部点空格、保留设备名加下划线、
    非法字符替换为 '_'。

Arguments:
    PathW   - 原始路径。
    Out     - 净化输出。
    OutSize - 输出容量。

Return Value:
    TRUE = 成功。
--*/
{
    SIZE_T len, i, pos = 0;
    WCHAR result[WKD_ARC_PATH_MAX + 1];

    if (!PathW || !Out || OutSize == 0) return FALSE;
    len = wcslen(PathW);
    if (len >= WKD_ARC_PATH_MAX) return FALSE;

    /* 剥离前导斜杠 (覆盖 UNC / \\?\ / \\.\) */
    i = 0;
    while (i < len && (PathW[i] == L'/' || PathW[i] == L'\\')) i++;
    /* 剥离 "?\" / ".\" */
    if (i + 1 < len && (PathW[i] == L'?' || PathW[i] == L'.') &&
        (PathW[i + 1] == L'\\' || PathW[i + 1] == L'/')) {
        i += 2;
    }
    /* 剥离盘符 */
    if (i + 1 < len && PathW[i + 1] == L':') i += 2;
    /* 剥离遗留前导斜杠 */
    while (i < len && (PathW[i] == L'/' || PathW[i] == L'\\')) i++;

    while (i < len) {
        SIZE_T sep = i;
        SIZE_T clen, k;
        WCHAR comp[WKD_ARC_PATH_MAX + 1];
        BOOLEAN isReserved;

        while (sep < len && PathW[sep] != L'/' && PathW[sep] != L'\\') sep++;
        clen = sep - i;
        if (clen >= WKD_ARC_PATH_MAX) { i = (sep < len) ? sep + 1 : len; continue; }
        for (k = 0; k < clen; k++) comp[k] = PathW[i + k];
        comp[clen] = L'\0';

        /* 跳过危险组件 */
        if ((clen == 1 && comp[0] == L'.') ||
            (clen == 2 && comp[0] == L'.' && comp[1] == L'.') ||
            clen == 0) {
            i = (sep < len) ? sep + 1 : len;
            continue;
        }

        /* 剥离尾部点/空格 */
        while (clen > 0 && (comp[clen - 1] == L'.' || comp[clen - 1] == L' ')) clen--;
        if (clen == 0) { i = (sep < len) ? sep + 1 : len; continue; }
        comp[clen] = L'\0';

        isReserved = WkdArc_IsReservedDeviceName(comp);

        if (pos != 0 && pos < WKD_ARC_PATH_MAX) result[pos++] = L'\\';
        if (isReserved) {
            if (pos < WKD_ARC_PATH_MAX) result[pos++] = L'_';
        }

        for (k = 0; k < clen && pos < WKD_ARC_PATH_MAX; k++) {
            WCHAR ch = comp[k];
            if (ch == L'<' || ch == L'>' || ch == L':' || ch == L'"' ||
                ch == L'|' || ch == L'?' || ch == L'*' ||
                ch == 0xFF0E || ch == 0xFF0F || ch == 0x2215 ||
                ch == 0x29F8 || ch == 0xFF3C ||
                ch == 0x202E || ch == 0x202D || ch == 0x202A ||
                ch == 0x202B || ch == 0x202C ||
                ch == L'\0' || ch < 0x20) {
                result[pos++] = L'_';
            } else {
                result[pos++] = ch;
            }
        }

        i = (sep < len) ? sep + 1 : len;
    }
    result[pos] = L'\0';

    if (pos + 1 > OutSize) return FALSE;
    wcscpy_s(Out, OutSize, result);
    return TRUE;
}

/* 兼容薄壳: ANSI 快速检测 (wkd 既有语义) */
BOOLEAN
IocArchive_IsPathTraversal(
    _In_ PCSTR EntryName,
    _In_ ULONG NameLen
    )
{
    ULONG i;

    if (!EntryName || NameLen == 0) return FALSE;

    if (EntryName[0] == '/' || EntryName[0] == '\\') return TRUE;
    if (NameLen >= 2 && EntryName[1] == ':') return TRUE;

    for (i = 0; i + 1 < NameLen; i++) {
        if (EntryName[i] == '.' && EntryName[i + 1] == '.') {
            BOOLEAN segStart = (i == 0) ||
                (EntryName[i - 1] == '/' || EntryName[i - 1] == '\\');
            if (segStart) return TRUE;
        }
    }
    return FALSE;
}

/**************************************************/
/*               ZIP 格式结构                      */
/*  对齐 SS L89-158 (pack(1))                      */
/**************************************************/

#pragma pack(push, 1)

typedef struct _WKD_ZIP_LFH {
    ULONG  Signature;
    USHORT VersionNeeded;
    USHORT Flags;
    USHORT CompressionMethod;
    USHORT LastModTime;
    USHORT LastModDate;
    ULONG  Crc32;
    ULONG  CompressedSize;
    ULONG  UncompressedSize;
    USHORT FileNameLength;
    USHORT ExtraFieldLength;
} WKD_ZIP_LFH;   /* 30 */

typedef struct _WKD_ZIP_CDE {
    ULONG  Signature;
    USHORT VersionMadeBy;
    USHORT VersionNeeded;
    USHORT Flags;
    USHORT CompressionMethod;
    USHORT LastModTime;
    USHORT LastModDate;
    ULONG  Crc32;
    ULONG  CompressedSize;
    ULONG  UncompressedSize;
    USHORT FileNameLength;
    USHORT ExtraFieldLength;
    USHORT CommentLength;
    USHORT DiskNumberStart;
    USHORT InternalAttributes;
    ULONG  ExternalAttributes;
    ULONG  LocalHeaderOffset;
} WKD_ZIP_CDE;   /* 46 */

typedef struct _WKD_ZIP_EOCD {
    ULONG  Signature;
    USHORT DiskNumber;
    USHORT DiskWithCentralDir;
    USHORT NumEntriesThisDisk;
    USHORT NumEntriesTotal;
    ULONG  CentralDirSize;
    ULONG  CentralDirOffset;
    USHORT CommentLength;
} WKD_ZIP_EOCD;  /* 22 */

typedef struct _WKD_ZIP64_LOCATOR {
    ULONG   Signature;
    ULONG   DiskWithZip64Eocd;
    ULONG64 Zip64EocdOffset;
    ULONG   TotalDisks;
} WKD_ZIP64_LOCATOR;   /* 20 */

typedef struct _WKD_ZIP64_EOCD {
    ULONG   Signature;
    ULONG64 SizeOfRecord;
    USHORT  VersionMadeBy;
    USHORT  VersionNeeded;
    ULONG   DiskNumber;
    ULONG   DiskWithCentralDir;
    ULONG64 NumEntriesThisDisk;
    ULONG64 NumEntriesTotal;
    ULONG64 CentralDirSize;
    ULONG64 CentralDirOffset;
} WKD_ZIP64_EOCD;   /* 56 */

#pragma pack(pop)

/* 嵌套归档扩展名 (对齐 SS ARCHIVE_EXTS L1228-1231) */
static const WCHAR* WkdArc_ArchiveExts[] = {
    L".zip", L".rar", L".7z", L".tar", L".gz", L".bz2",
    L".xz", L".cab", L".iso", L".msi",
};

/* 扩展名精确匹配 (对齐 SS fs::path::extension ends_with 语义) */
static BOOLEAN
WkdArc_HasExt(
    _In_ PCWSTR LowerName,
    _In_ PCWSTR Ext
    )
{
    PCWSTR dot = wcsrchr(LowerName, L'.');
    if (!dot) return FALSE;
    return wcscmp(dot, Ext) == 0;
}

static BOOLEAN
WkdArc_IsArchiveExt(
    _In_ PCWSTR LowerName
    )
{
    ULONG i;
    for (i = 0; i < sizeof(WkdArc_ArchiveExts) / sizeof(WkdArc_ArchiveExts[0]); i++) {
        if (WkdArc_HasExt(LowerName, WkdArc_ArchiveExts[i])) return TRUE;
    }
    return FALSE;
}

/**************************************************/
/*               ZIP 中央目录解析                   */
/*  对齐 SS ParseZipCentralDirectory L994-1241     */
/**************************************************/

static NTSTATUS
WkdArc_ParseZipCentralDirectory(
    _In_  const BYTE*          Buffer,
    _In_  ULONG                Size,
    _Inout_ PWKD_ARCHIVE_SCAN_RESULT Result
    )
{
    ULONG searchSize;
    ULONG eocdOff = 0;
    BOOLEAN found = FALSE;
    ULONG centralOff, centralSize, totalEntries;
    ULONG pos, entryId = 0;
    LONG i;

    if (Size < 22) return STATUS_SUCCESS;

    /* 1. EOCD 尾部搜索 (对齐 SS L999-1030) */
    searchSize = (Size < WKD_ARC_EOCD_SEARCH + 22) ? Size : WKD_ARC_EOCD_SEARCH + 22;
    {
        ULONG start = Size - searchSize;
        if (searchSize >= sizeof(WKD_ZIP_EOCD)) {
            for (i = (LONG)searchSize - (LONG)sizeof(WKD_ZIP_EOCD); i >= 0; i--) {
                ULONG sig;
                memcpy(&sig, Buffer + start + i, 4);
                if (sig == WKD_ZIP_EOCD_SIG) {
                    eocdOff = start + i;
                    found = TRUE;
                    break;
                }
            }
        }
    }
    if (!found) return STATUS_SUCCESS;

    {
        const WKD_ZIP_EOCD* eocd = (const WKD_ZIP_EOCD*)(Buffer + eocdOff);
        ULONG64 cdOffset = eocd->CentralDirOffset;
        ULONG64 cdSize = eocd->CentralDirSize;
        ULONG64 total = eocd->NumEntriesTotal;

        /* 2. Zip64 EOCD (对齐 SS L1039-1061) */
        if (cdOffset == 0xFFFFFFFF || total == 0xFFFF) {
            if (eocdOff >= sizeof(WKD_ZIP64_LOCATOR)) {
                const WKD_ZIP64_LOCATOR* loc =
                    (const WKD_ZIP64_LOCATOR*)(Buffer + eocdOff - sizeof(WKD_ZIP64_LOCATOR));
                if (loc->Signature == WKD_ZIP_ZIP64_LOC_SIG &&
                    loc->Zip64EocdOffset < Size &&
                    Size - loc->Zip64EocdOffset >= sizeof(WKD_ZIP64_EOCD)) {
                    const WKD_ZIP64_EOCD* z64 =
                        (const WKD_ZIP64_EOCD*)(Buffer + loc->Zip64EocdOffset);
                    if (z64->Signature == WKD_ZIP_ZIP64_EOCD_SIG) {
                        cdOffset = z64->CentralDirOffset;
                        cdSize = z64->CentralDirSize;
                        total = z64->NumEntriesTotal;
                    }
                }
            }
        }

        /* 3. 中央目录边界校验 (溢出安全, 对齐 SS L1063-1069) */
        if (cdOffset > Size || cdSize > (ULONG64)Size - cdOffset) return STATUS_SUCCESS;

        /* 4. 中央目录 256MB cap (对齐 SS L1085-1094) */
        if (cdSize > WKD_ARC_MAX_CENTRAL_DIR) return STATUS_SUCCESS;

        /* 5. 条目 cap (对齐 SS L1071-1077, 结构容量 512) */
        Result->TotalEntryCount = (total > 0xFFFFFFFFu) ? 0xFFFFFFFFu : (ULONG)total;
        /* SS 仅截断 warning 不判 bomb; 超限仅记录不置位
           (SuspiciousEntry 保留给内容哈希命中语义) */
        totalEntries = (ULONG)((total > WKD_ARCHIVE_MAX_ENTRIES) ? WKD_ARCHIVE_MAX_ENTRIES : total);
        centralOff = (ULONG)cdOffset;
        centralSize = (ULONG)cdSize;
    }

    /* 6. 遍历中央目录 (对齐 SS L1106-1238) */
    pos = centralOff;
    /* 以中央目录结束偏移为界 (对齐 SS 用 centralDirSize 限制, 防附加数据误解析) */
    while (pos + sizeof(WKD_ZIP_CDE) <= centralOff + centralSize && entryId < totalEntries) {
        const WKD_ZIP_CDE* cde;
        ULONG nameLen, extraLen, commentLen;
        ULONG flags = WkdArcFlag_None;
        PWKD_ARCHIVE_ENTRY e;
        CHAR rawName[256];
        ULONG rawNameLen = 0;
        WCHAR wideName[256];
        ULONG64 z64Uncomp, z64Comp, z64Local;
        ULONG64 entryStart, entryEnd, addend;
        ULONG overlapIdx;
        WCHAR lowerName[256];

        if (pos + sizeof(WKD_ZIP_CDE) > Size) break;
        cde = (const WKD_ZIP_CDE*)(Buffer + pos);
        if (cde->Signature != WKD_ZIP_CENTRAL_SIG) break;

        nameLen = cde->FileNameLength;
        extraLen = cde->ExtraFieldLength;
        commentLen = cde->CommentLength;

        /* 文件名 */
        if (pos + sizeof(WKD_ZIP_CDE) + nameLen > Size) break;
        rawNameLen = (nameLen < 255) ? nameLen : 255;
        memcpy(rawName, Buffer + pos + sizeof(WKD_ZIP_CDE), rawNameLen);
        rawName[rawNameLen] = '\0';

        /* Zip64 extra field 0x0001 (对齐 SS L1129-1163) */
        z64Uncomp = cde->UncompressedSize;
        z64Comp = cde->CompressedSize;
        z64Local = cde->LocalHeaderOffset;
        if (extraLen >= 4 && pos + sizeof(WKD_ZIP_CDE) + nameLen + extraLen <= Size) {
            const BYTE* extra = Buffer + pos + sizeof(WKD_ZIP_CDE) + nameLen;
            SIZE_T ePos = 0;
            SIZE_T extraSize = extraLen;
            while (ePos + 4 <= extraSize) {
                USHORT hdrId = (USHORT)WkdArc_ReadLE16(extra + ePos);
                USHORT dataSize = (USHORT)WkdArc_ReadLE16(extra + ePos + 2);
                ePos += 4;
                if (ePos + dataSize > extraSize) break;
                if (hdrId == 0x0001) {
                    SIZE_T fPos = 0;
                    if (cde->UncompressedSize == 0xFFFFFFFF && fPos + 8 <= dataSize) {
                        memcpy(&z64Uncomp, extra + ePos + fPos, 8); fPos += 8;
                    }
                    if (cde->CompressedSize == 0xFFFFFFFF && fPos + 8 <= dataSize) {
                        memcpy(&z64Comp, extra + ePos + fPos, 8); fPos += 8;
                    }
                    if (cde->LocalHeaderOffset == 0xFFFFFFFF && fPos + 8 <= dataSize) {
                        memcpy(&z64Local, extra + ePos + fPos, 8);
                    }
                    break;
                }
                ePos += dataSize;
            }
        }

        /* 构建条目 (对齐 SS L1167-1188) */
        e = &Result->Entries[Result->EntryCount];
        RtlZeroMemory(e, sizeof(*e));
        strncpy_s(e->Name, sizeof(e->Name), rawName, _TRUNCATE);
        e->CompressedSize = z64Comp;
        e->UncompressedSize = z64Uncomp;
        e->Crc32 = cde->Crc32;
        e->CompressionMethod = cde->CompressionMethod;
        e->LocalHeaderOffset = z64Local;
        e->DataSize = z64Comp;

        if (cde->Flags & WKD_ZIP_FLAG_ENCRYPTED) {
            e->Flags |= WKD_ARC_ENTRY_ENCRYPTED;
            flags |= WkdArcFlag_EncryptedContent;
        }
        if (rawNameLen > 0 && (rawName[rawNameLen - 1] == '/')) {
            e->Flags |= WKD_ARC_ENTRY_DIRECTORY;
        }
        /* DOS 隐藏属性 (对齐 SS L1205-1209) */
        if ((cde->ExternalAttributes & WKD_ZIP_ATTR_HIDDEN) != 0) {
            e->Flags |= WKD_ARC_ENTRY_HIDDEN;
            flags |= WkdArcFlag_HiddenEntry;
        }

        /* 压缩比 (对齐 SS L1182-1187) */
        if (e->CompressedSize > 0 && !(e->Flags & WKD_ARC_ENTRY_DIRECTORY)) {
            e->SingleEntryRatio = (double)e->UncompressedSize /
                                  (double)e->CompressedSize;
            if (e->SingleEntryRatio > WKD_ARC_MAX_RATIO) {
                flags |= WkdArcFlag_HighCompressionRatio;
            }
        }

        /* 路径安全 (对齐 SS L1189-1194) */
        WkdArc_Utf8ToWide(e->Name, wideName, sizeof(wideName) / sizeof(WCHAR));
        if (wideName[0] != L'\0' && !WkdArc_IsPathSafeW(wideName)) {
            flags |= WkdArcFlag_PathTraversalAttempt;
        }

        /* 嵌套归档 (对齐 SS L1226-1235) */
        WkdArc_FileNameLower(wideName, lowerName, sizeof(lowerName) / sizeof(WCHAR));
        if (lowerName[0] != L'\0' && WkdArc_IsArchiveExt(lowerName)) {
            e->Flags |= WKD_ARC_ENTRY_NESTED;
            Result->NestedCount++;
        }

        e->SecurityFlags = flags;
        if (flags != WkdArcFlag_None) Result->FlaggedCount++;
        Result->SecurityFlags |= flags;

        /* 重叠条目检测 (溢出安全, 对齐 SS L1211-1224) */
        addend = 30ull + nameLen + extraLen + z64Comp;
        entryStart = z64Local;
        entryEnd = (entryStart > (ULONG64)-1 - addend) ? (ULONG64)-1 : entryStart + addend;
        for (overlapIdx = 0; overlapIdx < Result->EntryCount; overlapIdx++) {
            PWKD_ARCHIVE_ENTRY prev = &Result->Entries[overlapIdx];
            ULONG64 prevStart = prev->LocalHeaderOffset;
            ULONG64 prevEnd = prev->DataOffset;   /* 已计算的条目结束偏移 */
            if (entryStart < prevEnd && entryEnd > prevStart) {
                e->SecurityFlags |= WkdArcFlag_OverlappingEntries;
                Result->SecurityFlags |= WkdArcFlag_OverlappingEntries;
                Result->OverlappingCount++;
                break;
            }
        }
        /* 记录本条目结束偏移供后续重叠检测 */
        e->DataOffset = entryEnd;

        /* 累计未压缩大小 (溢出安全, 对齐 SS L2319-2323) */
        if (!WkdArc_SafeAdd64(Result->TotalUncompressed, z64Uncomp,
                              &Result->TotalUncompressed)) {
            Result->SecurityFlags |= WkdArcFlag_ZipBombSuspected;
            Result->IsZipBomb = TRUE;
            return STATUS_SUCCESS;
        }

        Result->EntryCount++;
        entryId++;

        /* 推进到下一条 */
        if (pos + sizeof(WKD_ZIP_CDE) + nameLen + extraLen + commentLen > Size) break;
        pos += sizeof(WKD_ZIP_CDE) + nameLen + extraLen + commentLen;
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*               RFC1951 inflate                   */
/*  自实现 (SS 缺 codec 显式拒绝, L2702-2713),     */
/*  算法参考公共领域 puff 结构                     */
/**************************************************/

#define WKD_INF_MAXBITS 15

typedef struct _WKD_INFLATE_BS {
    const BYTE* In;
    ULONG       InLen;
    ULONG       InPos;
    ULONG       BitBuf;      /* 已加载未消费位, 低位为下一个 */
    ULONG       BitCnt;
} WKD_INFLATE_BS, *PWKD_INFLATE_BS;

typedef struct _WKD_INFLATE_HUFF {
    USHORT Counts[WKD_INF_MAXBITS + 1];
    USHORT Symbols[288 + 32];
    USHORT Offs[WKD_INF_MAXBITS + 1];
} WKD_INFLATE_HUFF, *PWKD_INFLATE_HUFF;

static BOOLEAN
WkdInf_ReadBits(
    _Inout_ PWKD_INFLATE_BS S,
    _In_ ULONG N,
    _Out_ PULONG Val
    )
{
    ULONG v = 0;
    while (N > 0) {
        if (S->BitCnt == 0) {
            if (S->InPos >= S->InLen) return FALSE;
            S->BitBuf = S->In[S->InPos++];
            S->BitCnt = 8;
        }
        {
            ULONG take = (N < S->BitCnt) ? N : S->BitCnt;
            ULONG bits = S->BitBuf & ((1u << take) - 1);
            S->BitBuf >>= take;
            S->BitCnt -= take;
            v = (v << take) | bits;    /* 先读的 bit 在 v 高位 */
            N -= take;
        }
    }
    *Val = v;
    return TRUE;
}

/* 构建 canonical Huffman 表 (对齐 puff construct) */
static BOOLEAN
WkdInf_BuildHuff(
    _In_  const USHORT* Lengths,
    _In_  ULONG         NumCodes,
    _Out_ PWKD_INFLATE_HUFF H
    )
{
    ULONG len, symbol;
    LONG left;
    USHORT offs[WKD_INF_MAXBITS + 1];

    RtlZeroMemory(H->Counts, sizeof(H->Counts));
    for (symbol = 0; symbol < NumCodes; symbol++) {
        if (Lengths[symbol] > WKD_INF_MAXBITS) return FALSE;
        H->Counts[Lengths[symbol]]++;
    }
    if (H->Counts[0] == NumCodes) return TRUE;   /* 空树, decode 必然失败 */

    left = 1;
    for (len = 1; len <= WKD_INF_MAXBITS; len++) {
        left <<= 1;
        left -= H->Counts[len];
        if (left < 0) return FALSE;   /* 超订阅 */
    }

    offs[1] = 0;
    for (len = 1; len < WKD_INF_MAXBITS; len++) {
        offs[len + 1] = (USHORT)(offs[len] + H->Counts[len]);
    }
    for (len = 1; len <= WKD_INF_MAXBITS; len++) {
        H->Offs[len] = offs[len];
    }
    for (symbol = 0; symbol < NumCodes; symbol++) {
        len = Lengths[symbol];
        if (len != 0) {
            H->Symbols[offs[len]++] = (USHORT)symbol;
        }
    }
    return TRUE;
}

/* 解码一个符号 (对齐 puff decode) */
static BOOLEAN
WkdInf_DecodeHuff(
    _Inout_ PWKD_INFLATE_BS S,
    _In_    PWKD_INFLATE_HUFF H,
    _Out_   PULONG Symbol
    )
{
    ULONG code = 0, first = 0;
    ULONG len;

    for (len = 1; len <= WKD_INF_MAXBITS; len++) {
        ULONG bit;
        if (!WkdInf_ReadBits(S, 1, &bit)) return FALSE;
        code |= bit;
        {
            ULONG count = H->Counts[len];
            if (code - count < first) {
                *Symbol = H->Symbols[H->Offs[len] + (code - first)];
                return TRUE;
            }
            first += count;
            first <<= 1;
            code <<= 1;
        }
    }
    return FALSE;   /* 无效码 */
}

static BOOLEAN
WkdInf_CopyMatch(
    _Out_ BYTE* Out,
    _In_  ULONG OutCap,
    _Inout_ PULONG OutPos,
    _In_  ULONG Length,
    _In_  ULONG Distance
    )
{
    ULONG i;
    if (Distance > *OutPos) return FALSE;
    if (*OutPos + Length > OutCap) return FALSE;
    for (i = 0; i < Length; i++) {
        Out[*OutPos] = Out[*OutPos - Distance];
        (*OutPos)++;
    }
    return TRUE;
}

BOOLEAN
WkdArc_Inflate(
    _In_  const BYTE* In,
    _In_  ULONG       InSize,
    _Out_ BYTE*       Out,
    _In_  ULONG       OutCap,
    _Out_ PULONG      OutLen
    )
/*++
Routine Description:
    RFC1951 inflate 解压 (只解不解)。SS 因缺 codec 对
    DEFLATE 显式拒绝 (L2702-2713); wkd 手写补上该能力。

Arguments:
    In     - raw deflate 数据。
    InSize - 压缩数据大小。
    Out    - 输出缓冲区。
    OutCap - 输出容量。
    OutLen - 实际输出大小。

Return Value:
    TRUE = 成功。
--*/
{
    static const USHORT LenBase[29] = {
        3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,
        35,43,51,59,67,83,99,115,131,163,195,227,258 };
    static const BYTE LenExtra[29] = {
        0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,
        3,3,3,3,4,4,4,4,5,5,5,5,0 };
    static const USHORT DistBase[30] = {
        1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,
        257,385,513,769,1025,1537,2049,3073,4097,6145,
        8193,12289,16385,24577 };
    static const BYTE DistExtra[30] = {
        0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,
        7,7,8,8,9,9,10,10,11,11,12,12,13,13 };
    static const BYTE Order[19] = { 16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15 };

    WKD_INFLATE_BS S;
    ULONG outPos = 0;
    BOOLEAN last;

    if (!In || !Out || !OutLen || OutCap == 0) return FALSE;
    S.In = In;
    S.InLen = InSize;
    S.InPos = 0;
    S.BitBuf = 0;
    S.BitCnt = 0;
    *OutLen = 0;
    last = FALSE;

    while (!last) {
        ULONG bfinal, btype;
        if (!WkdInf_ReadBits(&S, 1, &bfinal)) return FALSE;
        if (!WkdInf_ReadBits(&S, 2, &btype)) return FALSE;
        last = (bfinal == 1);

        if (btype == 0) {
            /* 存储块 */
            ULONG len, nlen;
            S.BitBuf = 0;
            S.BitCnt = 0;    /* 丢弃残余位, 对齐字节 */
            if (S.InPos + 4 > S.InLen) return FALSE;
            len = S.In[S.InPos] | ((ULONG)S.In[S.InPos + 1] << 8);
            nlen = S.In[S.InPos + 2] | ((ULONG)S.In[S.InPos + 3] << 8);
            S.InPos += 4;
            if ((len ^ 0xFFFF) != nlen) return FALSE;
            if (outPos + len > OutCap) return FALSE;
            if (S.InPos + len > S.InLen) return FALSE;
            memcpy(Out + outPos, S.In + S.InPos, len);
            S.InPos += len;
            outPos += len;
        } else if (btype == 1 || btype == 2) {
            USHORT litLengths[288];
            USHORT distLengths[32];
            WKD_INFLATE_HUFF lit, dist;
            ULONG hlit = 288, hdist = 30;
            ULONG i;

            if (btype == 2) {
                /* 动态 Huffman: 读表 */
                ULONG hclen, n;
                USHORT lenCode[19];
                WKD_INFLATE_HUFF lenHuff;

                if (!WkdInf_ReadBits(&S, 5, &hlit)) return FALSE;
                if (!WkdInf_ReadBits(&S, 5, &hdist)) return FALSE;
                if (!WkdInf_ReadBits(&S, 4, &hclen)) return FALSE;
                hlit += 257;
                hdist += 1;
                hclen += 4;
                if (hdist > 32) return FALSE;

                RtlZeroMemory(lenCode, sizeof(lenCode));
                for (i = 0; i < hclen; i++) {
                    ULONG v;
                    if (!WkdInf_ReadBits(&S, 3, &v)) return FALSE;
                    lenCode[Order[i]] = (USHORT)v;
                }
                if (!WkdInf_BuildHuff(lenCode, 19, &lenHuff)) return FALSE;

                n = 0;
                while (n < hlit + hdist) {
                    ULONG sym;
                    ULONG prev;
                    if (!WkdInf_DecodeHuff(&S, &lenHuff, &sym)) return FALSE;
                    if (sym < 16) {
                        if (n < hlit) litLengths[n] = (USHORT)sym;
                        else distLengths[n - hlit] = (USHORT)sym;
                        n++;
                    } else if (sym == 16) {
                        ULONG rep;
                        if (n == 0) return FALSE;
                        if (!WkdInf_ReadBits(&S, 2, &rep)) return FALSE;
                        rep += 3;
                        prev = (n <= hlit) ? litLengths[n - 1] : distLengths[n - 1 - hlit];
                        while (rep-- && n < hlit + hdist) {
                            if (n < hlit) litLengths[n] = (USHORT)prev;
                            else distLengths[n - hlit] = (USHORT)prev;
                            n++;
                        }
                    } else if (sym == 17) {
                        ULONG rep;
                        if (!WkdInf_ReadBits(&S, 3, &rep)) return FALSE;
                        rep += 3;
                        while (rep-- && n < hlit + hdist) {
                            if (n < hlit) litLengths[n] = 0;
                            else distLengths[n - hlit] = 0;
                            n++;
                        }
                    } else {
                        ULONG rep;
                        if (!WkdInf_ReadBits(&S, 7, &rep)) return FALSE;
                        rep += 11;
                        while (rep-- && n < hlit + hdist) {
                            if (n < hlit) litLengths[n] = 0;
                            else distLengths[n - hlit] = 0;
                            n++;
                        }
                    }
                }
                if (n != hlit + hdist) return FALSE;
                if (!WkdInf_BuildHuff(litLengths, hlit, &lit)) return FALSE;
                if (!WkdInf_BuildHuff(distLengths, hdist, &dist)) return FALSE;
            } else {
                /* 固定 Huffman */
                for (i = 0; i < 144; i++) litLengths[i] = 8;
                for (i = 144; i < 256; i++) litLengths[i] = 9;
                for (i = 256; i < 280; i++) litLengths[i] = 7;
                for (i = 280; i < 288; i++) litLengths[i] = 8;
                for (i = 0; i < 30; i++) distLengths[i] = 5;
                if (!WkdInf_BuildHuff(litLengths, 288, &lit)) return FALSE;
                if (!WkdInf_BuildHuff(distLengths, 30, &dist)) return FALSE;
            }

            /* 解码数据 */
            for (;;) {
                ULONG sym;
                if (!WkdInf_DecodeHuff(&S, &lit, &sym)) return FALSE;
                if (sym < 256) {
                    if (outPos + 1 > OutCap) return FALSE;
                    Out[outPos++] = (BYTE)sym;
                } else if (sym == 256) {
                    break;   /* 块结束 */
                } else {
                    ULONG idx = sym - 257;
                    ULONG length, distSym, off;
                    if (idx >= 29) return FALSE;
                    length = LenBase[idx];
                    if (LenExtra[idx]) {
                        ULONG extra;
                        if (!WkdInf_ReadBits(&S, LenExtra[idx], &extra)) return FALSE;
                        length += extra;
                    }
                    if (!WkdInf_DecodeHuff(&S, &dist, &distSym)) return FALSE;
                    if (distSym >= 30) return FALSE;
                    off = DistBase[distSym];
                    if (DistExtra[distSym]) {
                        ULONG extra;
                        if (!WkdInf_ReadBits(&S, DistExtra[distSym], &extra)) return FALSE;
                        off += extra;
                    }
                    if (!WkdInf_CopyMatch(Out, OutCap, &outPos, length, off)) return FALSE;
                }
            }
        } else {
            return FALSE;   /* 保留块类型 */
        }
    }

    *OutLen = outPos;
    return TRUE;
}

/**************************************************/
/*               ZIP 条目内容提取                   */
/*  对齐 SS ExtractZipEntry L2647-2729             */
/**************************************************/

NTSTATUS
WkdArc_ExtractEntryContent(
    _In_  const BYTE*          Buffer,
    _In_  ULONG                Size,
    _In_  PWKD_ARCHIVE_ENTRY   Entry,
    _Out_ BYTE*                Out,
    _In_  ULONG                OutCap,
    _Out_ PULONG               OutLen
    )
/*++
Routine Description:
    提取 ZIP 条目内容 (STORED 直拷 / DEFLATE inflate)。
    对齐 SS ExtractZipEntry L2647-2729, 加密拒绝。

Arguments:
    Buffer - 整个归档 buffer。
    Size   - 归档大小。
    Entry  - 条目 (LocalHeaderOffset/CompressionMethod/大小)。
    Out    - 内容输出缓冲区。
    OutCap - 容量。
    OutLen - 输出大小。

Return Value:
    STATUS_SUCCESS / STATUS_ENCRYPTED / STATUS_INVALID_PARAMETER。
--*/
{
    ULONG64 dataOffset;
    const WKD_ZIP_LFH* lfh;
    ULONG lfhFileLen, lfhExtraLen;
    ULONG csize, usize;

    if (!Buffer || !Entry || !Out || !OutLen) return STATUS_INVALID_PARAMETER;
    *OutLen = 0;

    if (Entry->Flags & WKD_ARC_ENTRY_ENCRYPTED) {
        return STATUS_ENCRYPTED;   /* 对齐 SS L2653-2660 */
    }
    if (Entry->LocalHeaderOffset + sizeof(WKD_ZIP_LFH) > Size) {
        return STATUS_INVALID_PARAMETER;
    }

    lfh = (const WKD_ZIP_LFH*)(Buffer + (ULONG)Entry->LocalHeaderOffset);
    if (lfh->Signature != WKD_ZIP_LOCAL_SIG) {
        return STATUS_INVALID_PARAMETER;
    }
    lfhFileLen = lfh->FileNameLength;
    lfhExtraLen = lfh->ExtraFieldLength;
    dataOffset = Entry->LocalHeaderOffset + sizeof(WKD_ZIP_LFH) + lfhFileLen + lfhExtraLen;

    csize = (ULONG)Entry->CompressedSize;
    usize = (ULONG)Entry->UncompressedSize;

    if (usize > OutCap) return STATUS_BUFFER_TOO_SMALL;
    if (Entry->CompressedSize > WKD_ARC_MAX_INFLATE) return STATUS_BUFFER_TOO_SMALL;

    if (dataOffset + csize > Size) return STATUS_INVALID_PARAMETER;

    if (Entry->CompressionMethod == WKD_ARC_COMP_STORED) {
        memcpy(Out, Buffer + (ULONG)dataOffset, csize);
        *OutLen = csize;
    } else if (Entry->CompressionMethod == WKD_ARC_COMP_DEFLATE) {
        if (!WkdArc_Inflate(Buffer + (ULONG)dataOffset, csize, Out, OutCap, OutLen)) {
            return STATUS_UNSUCCESSFUL;
        }
    } else {
        return STATUS_NOT_SUPPORTED;   /* 其他压缩方法不支持 */
    }

    /* CRC32 校验 (对齐 SS L2716-2726, 不丢弃) */
    if (*OutLen > 0 && Entry->Crc32 != 0) {
        ULONG computed = WkdArc_Crc32(Out, *OutLen);
        if (computed != Entry->Crc32) {
            /* 恶意样本常带坏 CRC, 仍返回内容供扫描 */
        }
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*               TAR 格式解析                       */
/*  对齐 SS L225-257 常量 + ParseTarContents       */
/*  L1247-1447 + ScanTarArchive L1453-1733         */
/**************************************************/

#define WKD_TAR_BLOCK_SIZE        512
#define WKD_TAR_NAME_OFFSET       0
#define WKD_TAR_NAME_LEN          100
#define WKD_TAR_SIZE_OFFSET       124
#define WKD_TAR_SIZE_LEN          12
#define WKD_TAR_MTIME_OFFSET      136
#define WKD_TAR_CHKSUM_OFFSET     148
#define WKD_TAR_CHKSUM_LEN        8
#define WKD_TAR_TYPEFLAG_OFFSET   156
#define WKD_TAR_LINKNAME_OFFSET   157
#define WKD_TAR_LINKNAME_LEN      100
#define WKD_TAR_PREFIX_OFFSET     345
#define WKD_TAR_PREFIX_LEN        155
#define WKD_TAR_MAX_ENTRIES       500000
#define WKD_TAR_MAX_ENTRY_SIZE    (4ull * 1024ull * 1024ull * 1024ull)

#define WKD_TAR_TYPE_REGULAR      '0'
#define WKD_TAR_TYPE_REGULAR_ALT  '\0'
#define WKD_TAR_TYPE_LINK         '1'
#define WKD_TAR_TYPE_SYMLINK      '2'
#define WKD_TAR_TYPE_DIRECTORY    '5'
#define WKD_TAR_TYPE_LONGNAME     'L'
#define WKD_TAR_TYPE_LONGLINK     'K'
#define WKD_TAR_TYPE_PAX_GLOBAL   'g'
#define WKD_TAR_TYPE_PAX_NEXT     'x'

/* GNU base-256 + POSIX 八进制 (对齐 SS L323-348) */
static ULONG64
WkdArc_TarParseOctal(
    _In_ const BYTE* Field,
    _In_ SIZE_T      Length
    )
{
    SIZE_T i;
    if (Length == 0) return 0;

    /* GNU base-256: 首字节高位标记位 */
    if ((Field[0] & 0x80) != 0) {
        ULONG64 value = Field[0] & 0x7F;
        for (i = 1; i < Length; i++) {
            value = (value << 8) | Field[i];
        }
        return value;
    }

    /* POSIX 八进制, 跳过空格/前导零 */
    {
        ULONG64 value = 0;
        for (i = 0; i < Length; i++) {
            if (Field[i] == ' ' || Field[i] == '\0') continue;
            if (Field[i] < '0' || Field[i] > '7') break;
            if (value > ((ULONG64)-1 >> 3)) return (ULONG64)-1;
            value = (value << 3) | (ULONG64)(Field[i] - '0');
        }
        return value;
    }
}

/* 双校验和: 无符号 + 有符号 (对齐 SS L353-379) */
static BOOLEAN
WkdArc_TarVerifyChecksum(
    _In_ const BYTE* Block
    )
{
    ULONG i;
    ULONG computed = 0;
    ULONG stored;
    LONG signedComputed = 0;

    for (i = 0; i < WKD_TAR_BLOCK_SIZE; i++) {
        if (i >= WKD_TAR_CHKSUM_OFFSET && i < WKD_TAR_CHKSUM_OFFSET + WKD_TAR_CHKSUM_LEN) {
            computed += ' ';
        } else {
            computed += Block[i];
        }
    }
    stored = (ULONG)WkdArc_TarParseOctal(Block + WKD_TAR_CHKSUM_OFFSET, WKD_TAR_CHKSUM_LEN);

    for (i = 0; i < WKD_TAR_BLOCK_SIZE; i++) {
        if (i >= WKD_TAR_CHKSUM_OFFSET && i < WKD_TAR_CHKSUM_OFFSET + WKD_TAR_CHKSUM_LEN) {
            signedComputed += ' ';
        } else {
            signedComputed += (signed char)Block[i];
        }
    }
    return (computed == stored) || ((ULONG)signedComputed == stored);
}

/* 全零块 = 归档结束 (对齐 SS L384-394) */
static BOOLEAN
WkdArc_TarIsZeroBlock(
    _In_ const BYTE* Block
    )
{
    ULONG i;
    for (i = 0; i < WKD_TAR_BLOCK_SIZE; i += sizeof(ULONG64)) {
        ULONG64 q = 0;
        memcpy(&q, Block + i, sizeof(q));
        if (q != 0) return FALSE;
    }
    return TRUE;
}

/* 定长字段取 NUL 终止串 (对齐 SS L399-407) */
static VOID
WkdArc_TarExtractString(
    _In_  const BYTE* Field,
    _In_  SIZE_T      MaxLen,
    _Out_ PSTR        Out,
    _In_  ULONG       OutSize
    )
{
    SIZE_T len = 0;
    while (len < MaxLen && Field[len] != '\0') len++;
    if (len >= OutSize) len = OutSize - 1;
    memcpy(Out, Field, len);
    Out[len] = '\0';
}

static NTSTATUS
WkdArc_ParseTarContents(
    _In_  const BYTE*          Buffer,
    _In_  ULONG                Size,
    _Inout_ PWKD_ARCHIVE_SCAN_RESULT Result
    )
/*++
Routine Description:
    TAR 头级条目解析 + 数据位置记录。
    对齐 SS ParseTarContents L1247-1447。

Arguments:
    Buffer - TAR 文件 buffer。
    Size   - 大小。
    Result - 输出结果。

Return Value:
    STATUS_SUCCESS。
--*/
{
    ULONG64 offset = 0;
    ULONG64 entryId = 0;
    ULONG consecutiveZero = 0;
    CHAR gnuLongName[300];
    BOOLEAN hasGnuLong = FALSE;

    while (offset + WKD_TAR_BLOCK_SIZE <= Size) {
        const BYTE* block;
        CHAR typeFlag;
        ULONG64 entrySize;
        CHAR prefix[WKD_TAR_PREFIX_LEN + 1];
        CHAR name[WKD_TAR_NAME_LEN + 1];
        CHAR fullName[512];
        PWKD_ARCHIVE_ENTRY e;
        WCHAR wideName[512];
        WCHAR lowerName[512];
        ULONG flags = WkdArcFlag_None;

        if (Result->EntryCount >= WKD_ARCHIVE_MAX_ENTRIES) break;
        if (entryId >= WKD_TAR_MAX_ENTRIES) break;

        block = Buffer + offset;

        if (WkdArc_TarIsZeroBlock(block)) {
            consecutiveZero++;
            if (consecutiveZero >= 2) break;   /* 两个连续零块结束 */
            offset += WKD_TAR_BLOCK_SIZE;
            continue;
        }
        consecutiveZero = 0;

        if (!WkdArc_TarVerifyChecksum(block)) break;

        typeFlag = (CHAR)block[WKD_TAR_TYPEFLAG_OFFSET];
        entrySize = WkdArc_TarParseOctal(block + WKD_TAR_SIZE_OFFSET, WKD_TAR_SIZE_LEN);

        WkdArc_TarExtractString(block + WKD_TAR_PREFIX_OFFSET, WKD_TAR_PREFIX_LEN,
                                prefix, sizeof(prefix));
        WkdArc_TarExtractString(block + WKD_TAR_NAME_OFFSET, WKD_TAR_NAME_LEN,
                                name, sizeof(name));
        if (prefix[0] != '\0') {
            strcpy_s(fullName, sizeof(fullName), prefix);
            strcat_s(fullName, sizeof(fullName), "/");
            strcat_s(fullName, sizeof(fullName), name);
        } else {
            strcpy_s(fullName, sizeof(fullName), name);
        }

        /* GNU longname (对齐 SS L1313-1336) */
        if (typeFlag == WKD_TAR_TYPE_LONGNAME) {
            ULONG64 nameDataBlocks = (entrySize + WKD_TAR_BLOCK_SIZE - 1) / WKD_TAR_BLOCK_SIZE;
            ULONG64 nameDataSize = nameDataBlocks * WKD_TAR_BLOCK_SIZE;
            if (nameDataSize > 65536 ||
                nameDataSize > (ULONG64)Size - (offset + WKD_TAR_BLOCK_SIZE)) {
                offset += WKD_TAR_BLOCK_SIZE + nameDataSize;
                continue;
            }
            {
                ULONG copyLen = (entrySize < 299) ? (ULONG)entrySize : 299;
                memcpy(gnuLongName, Buffer + offset + WKD_TAR_BLOCK_SIZE, copyLen);
                gnuLongName[copyLen] = '\0';
                hasGnuLong = TRUE;
            }
            offset += WKD_TAR_BLOCK_SIZE + nameDataSize;
            continue;
        }

        /* pax 扩展头跳过 (对齐 SS L1339-1344) */
        if (typeFlag == WKD_TAR_TYPE_PAX_NEXT || typeFlag == WKD_TAR_TYPE_PAX_GLOBAL) {
            ULONG64 dataBlocks = (entrySize + WKD_TAR_BLOCK_SIZE - 1) / WKD_TAR_BLOCK_SIZE;
            offset += WKD_TAR_BLOCK_SIZE + dataBlocks * WKD_TAR_BLOCK_SIZE;
            continue;
        }

        /* 应用 GNU longname */
        if (hasGnuLong) {
            strcpy_s(fullName, sizeof(fullName), gnuLongName);
            hasGnuLong = FALSE;
        }

        if (entrySize > WKD_TAR_MAX_ENTRY_SIZE) break;

        /* 构建条目 */
        e = &Result->Entries[Result->EntryCount];
        RtlZeroMemory(e, sizeof(*e));
        strncpy_s(e->Name, sizeof(e->Name), fullName, _TRUNCATE);
        e->UncompressedSize = entrySize;
        e->CompressedSize = entrySize;
        e->SingleEntryRatio = 1.0;
        e->CompressionMethod = WKD_ARC_COMP_STORED;

        if (typeFlag == WKD_TAR_TYPE_DIRECTORY) {
            e->Flags |= WKD_ARC_ENTRY_DIRECTORY;
        }

        WkdArc_Utf8ToWide(fullName, wideName, sizeof(wideName) / sizeof(WCHAR));

        /* 链路检测 → SymlinkAttack (对齐 SS L1391-1407) */
        if (typeFlag == WKD_TAR_TYPE_SYMLINK || typeFlag == WKD_TAR_TYPE_LINK) {
            CHAR linkTarget[WKD_TAR_LINKNAME_LEN + 1];
            WCHAR wideTarget[128];
            WkdArc_TarExtractString(block + WKD_TAR_LINKNAME_OFFSET,
                                    WKD_TAR_LINKNAME_LEN, linkTarget, sizeof(linkTarget));
            if (typeFlag == WKD_TAR_TYPE_SYMLINK) e->Flags |= WKD_ARC_ENTRY_SYMLINK;
            else e->Flags |= WKD_ARC_ENTRY_HARDLINK;
            flags |= WkdArcFlag_SymlinkAttack;
            if (linkTarget[0] != '\0') {
                WkdArc_Utf8ToWide(linkTarget, wideTarget, sizeof(wideTarget) / sizeof(WCHAR));
                if (!WkdArc_IsPathSafeW(wideTarget)) {
                    flags |= WkdArcFlag_PathTraversalAttempt;
                }
            }
        }

        /* 路径安全 */
        if (wideName[0] != L'\0' && !WkdArc_IsPathSafeW(wideName)) {
            flags |= WkdArcFlag_PathTraversalAttempt;
        }

        /* 类型识别 (对齐 SS L1415-1437) */
        if (!(e->Flags & WKD_ARC_ENTRY_DIRECTORY)) {
            WkdArc_FileNameLower(wideName, lowerName, sizeof(lowerName) / sizeof(WCHAR));
            if (WkdArc_IsArchiveExt(lowerName)) {
                e->Flags |= WKD_ARC_ENTRY_NESTED;
                Result->NestedCount++;
            } else if (WkdArc_HasExt(lowerName, L".exe") ||
                       WkdArc_HasExt(lowerName, L".dll") ||
                       WkdArc_HasExt(lowerName, L".sys") ||
                       WkdArc_HasExt(lowerName, L".scr") ||
                       WkdArc_HasExt(lowerName, L".ocx")) {
                e->Flags |= WKD_ARC_ENTRY_PE;
            }
        }

        e->SecurityFlags = flags;
        if (flags != WkdArcFlag_None) Result->FlaggedCount++;
        Result->SecurityFlags |= flags;

        /* 记录数据位置 (TAR 无压缩, 内容 = 头后 entrySize 字节) */
        e->DataOffset = offset + WKD_TAR_BLOCK_SIZE;
        e->DataSize = entrySize;

        if (!WkdArc_SafeAdd64(Result->TotalUncompressed, entrySize,
                              &Result->TotalUncompressed)) {
            Result->SecurityFlags |= WkdArcFlag_ZipBombSuspected;
            Result->IsZipBomb = TRUE;
            return STATUS_SUCCESS;
        }

        Result->EntryCount++;
        entryId++;

        {
            ULONG64 dataBlocks = (entrySize + WKD_TAR_BLOCK_SIZE - 1) / WKD_TAR_BLOCK_SIZE;
            offset += WKD_TAR_BLOCK_SIZE + dataBlocks * WKD_TAR_BLOCK_SIZE;
        }
    }
    Result->TotalEntryCount = Result->EntryCount;
    return STATUS_SUCCESS;
}

/**************************************************/
/*               GZIP 头解析                       */
/*  对齐 SS ParseGzipContents L1739-1883           */
/**************************************************/

#define WKD_GZIP_HEADER_MIN  10
#define WKD_GZIP_TRAILER     8
#define WKD_GZIP_FLAG_FTEXT     0x01
#define WKD_GZIP_FLAG_FHCRC     0x02
#define WKD_GZIP_FLAG_FEXTRA    0x04
#define WKD_GZIP_FLAG_FNAME     0x08
#define WKD_GZIP_FLAG_FCOMMENT  0x10

static NTSTATUS
WkdArc_ParseGzipContents(
    _In_  const BYTE*          Buffer,
    _In_  ULONG                Size,
    _Inout_ PWKD_ARCHIVE_SCAN_RESULT Result
    )
/*++
Routine Description:
    GZIP 头解析 (FEXTRA/FNAME/FCOMMENT/FHCRC) + 尾部 ISIZE。
    对齐 SS ParseGzipContents L1739-1883。

Arguments:
    Buffer - GZIP 文件 buffer。
    Size   - 大小。
    Result - 输出结果。

Return Value:
    STATUS_SUCCESS。
--*/
{
    PWKD_ARCHIVE_ENTRY e;
    ULONG pos = WKD_GZIP_HEADER_MIN;
    ULONG flags;
    ULONG isize;
    CHAR originalName[256];
    WCHAR wideName[300];
    WCHAR lowerName[300];
    originalName[0] = '\0';

    if (Size < WKD_GZIP_HEADER_MIN + WKD_GZIP_TRAILER) return STATUS_SUCCESS;
    if (Buffer[0] != 0x1F || Buffer[1] != 0x8B) return STATUS_SUCCESS;
    if (Buffer[2] != 8) return STATUS_SUCCESS;   /* 仅 deflate 方法 */

    flags = Buffer[3];

    /* FEXTRA */
    if ((flags & WKD_GZIP_FLAG_FEXTRA) != 0 && pos + 2 <= Size) {
        ULONG extraLen = WkdArc_ReadLE16(Buffer + pos);
        pos += 2 + extraLen;
    }
    /* FNAME */
    if ((flags & WKD_GZIP_FLAG_FNAME) != 0 && pos < Size) {
        ULONG start = pos;
        while (pos < Size && Buffer[pos] != '\0') pos++;
        if (pos < Size) {
            ULONG copyLen = (pos - start < 255) ? (pos - start) : 255;
            memcpy(originalName, Buffer + start, copyLen);
            originalName[copyLen] = '\0';
            pos++;
        }
    }
    /* FCOMMENT */
    if ((flags & WKD_GZIP_FLAG_FCOMMENT) != 0 && pos < Size) {
        while (pos < Size && Buffer[pos] != '\0') pos++;
        if (pos < Size) pos++;
    }
    /* FHCRC */
    if ((flags & WKD_GZIP_FLAG_FHCRC) != 0) pos += 2;

    e = &Result->Entries[Result->EntryCount];
    RtlZeroMemory(e, sizeof(*e));
    if (originalName[0] != '\0') {
        strncpy_s(e->Name, sizeof(e->Name), originalName, _TRUNCATE);
        WkdArc_Utf8ToWide(originalName, wideName, sizeof(wideName) / sizeof(WCHAR));
    } else {
        strcpy_s(e->Name, sizeof(e->Name), "[content]");
        wcscpy_s(wideName, sizeof(wideName) / sizeof(WCHAR), L"[content]");
    }

    /* 尾部 ISIZE (原始大小 mod 2^32) */
    isize = WkdArc_ReadLE32(Buffer + Size - 4);
    e->Crc32 = WkdArc_ReadLE32(Buffer + Size - 8);
    e->UncompressedSize = isize;
    e->CompressedSize = (Size > pos + WKD_GZIP_TRAILER)
        ? (Size - pos - WKD_GZIP_TRAILER) : 0;
    e->CompressionMethod = WKD_ARC_COMP_DEFLATE;

    if (e->CompressedSize > 0 && isize > 0) {
        e->SingleEntryRatio = (double)isize / (double)e->CompressedSize;
        if (e->SingleEntryRatio > WKD_ARC_MAX_RATIO) {
            e->SecurityFlags |= WkdArcFlag_HighCompressionRatio;
        }
    }

    /* 路径安全 (对齐 SS: 无原始名时 [content] 不检查) */
    if (originalName[0] != '\0' && !WkdArc_IsPathSafeW(wideName)) {
        e->SecurityFlags |= WkdArcFlag_PathTraversalAttempt;
    }

    /* tar 嵌套 (对齐 SS L1873-1879) */
    WkdArc_FileNameLower(wideName, lowerName, sizeof(lowerName) / sizeof(WCHAR));
    if (WkdArc_HasExt(lowerName, L".tar")) {
        e->Flags |= WKD_ARC_ENTRY_NESTED;
        e->NestedFormat = WkdArcFormat_Tar;
        Result->NestedCount++;
    }

    if (e->SecurityFlags != WkdArcFlag_None) Result->FlaggedCount++;
    Result->SecurityFlags |= e->SecurityFlags;
    Result->TotalUncompressed = e->UncompressedSize;
    Result->TotalEntryCount = 1;
    Result->EntryCount = 1;
    return STATUS_SUCCESS;
}

/**************************************************/
/*               RAR4 头解析                       */
/*  对齐 SS ParseRar4Contents L1889-2064           */
/**************************************************/

#define WKD_RAR4_MARKER_LEN       7
#define WKD_RAR4_FILE_HEADER      0x74
#define WKD_RAR4_END_HEADER       0x7B
#define WKD_RAR4_FLAG_LARGE       0x8000
#define WKD_RAR4_FLAG_ENCRYPTED   0x0004
#define WKD_RAR4_MAX_ENTRIES      500000

static NTSTATUS
WkdArc_ParseRar4Contents(
    _In_  const BYTE*          Buffer,
    _In_  ULONG                Size,
    _Inout_ PWKD_ARCHIVE_SCAN_RESULT Result
    )
/*++
Routine Description:
    RAR4 头级条目枚举 (不解压)。对齐 SS ParseRar4Contents L1889-2064。

Arguments:
    Buffer - RAR4 文件 buffer。
    Size   - 大小。
    Result - 输出结果。

Return Value:
    STATUS_SUCCESS。
--*/
{
    ULONG64 offset = WKD_RAR4_MARKER_LEN;
    ULONG64 entryId = 0;

    if (Size < WKD_RAR4_MARKER_LEN + 7) return STATUS_SUCCESS;

    while (offset + 7 < Size) {
        const BYTE* h = Buffer + offset;
        BYTE headType;
        USHORT flags, headSize;
        PWKD_ARCHIVE_ENTRY e;
        ULONG flags2 = WkdArcFlag_None;

        if (Result->EntryCount >= WKD_ARCHIVE_MAX_ENTRIES) break;
        if (entryId >= WKD_RAR4_MAX_ENTRIES) break;

        headType = h[2];
        flags = (USHORT)WkdArc_ReadLE16(h + 3);
        headSize = (USHORT)WkdArc_ReadLE16(h + 5);

        if (headSize < 7) break;
        if (headSize > 65535) break;

        if (headType == WKD_RAR4_END_HEADER) break;

        if (headType == WKD_RAR4_FILE_HEADER && headSize >= 32) {
            ULONG readLen = (headSize < 4096) ? headSize : 4096;
            ULONG packLow, unpLow, fileCrc, nameSize, fileAttr;
            ULONG64 packSize, unpSize;
            ULONG nameOffset = 32;
            CHAR fileName[256];
            ULONG flen = 0;
            WCHAR wideName[256];
            WCHAR lowerName[256];

            if (offset + readLen > Size) readLen = (ULONG)(Size - offset);
            if (readLen < 32) { offset += headSize; continue; }

            packLow = WkdArc_ReadLE32(h + 7);
            unpLow = WkdArc_ReadLE32(h + 11);
            fileCrc = WkdArc_ReadLE32(h + 16);
            nameSize = WkdArc_ReadLE16(h + 26);
            fileAttr = WkdArc_ReadLE32(h + 28);

            packSize = packLow;
            unpSize = unpLow;
            if ((flags & WKD_RAR4_FLAG_LARGE) != 0 && readLen >= 40) {
                ULONG packHigh = WkdArc_ReadLE32(h + 32);
                ULONG unpHigh = WkdArc_ReadLE32(h + 36);
                packSize |= (ULONG64)packHigh << 32;
                unpSize |= (ULONG64)unpHigh << 32;
                nameOffset = 40;
            }

            if (nameSize > 0 && nameSize < 4096 && nameOffset + nameSize <= readLen) {
                flen = (nameSize < 255) ? nameSize : 255;
                memcpy(fileName, h + nameOffset, flen);
                fileName[flen] = '\0';
            }

            e = &Result->Entries[Result->EntryCount];
            RtlZeroMemory(e, sizeof(*e));
            strncpy_s(e->Name, sizeof(e->Name), fileName, _TRUNCATE);
            e->CompressedSize = packSize;
            e->UncompressedSize = unpSize;
            e->Crc32 = fileCrc;
            e->CompressionMethod = 0xFF;   /* rar4 */

            if (flags & WKD_RAR4_FLAG_ENCRYPTED) {
                e->Flags |= WKD_ARC_ENTRY_ENCRYPTED;
                flags2 |= WkdArcFlag_EncryptedContent;
            }
            if ((fileAttr & 0x10) != 0 || ((flags & 0x00E0) == 0x00E0)) {
                e->Flags |= WKD_ARC_ENTRY_DIRECTORY;
            }

            if (unpSize > 0 && packSize > 0) {
                e->SingleEntryRatio = (double)unpSize / (double)packSize;
            }

            WkdArc_Utf8ToWide(fileName, wideName, sizeof(wideName) / sizeof(WCHAR));
            if (wideName[0] != L'\0' && !WkdArc_IsPathSafeW(wideName)) {
                flags2 |= WkdArcFlag_PathTraversalAttempt;
            }

            /* 类型识别 (对齐 SS L2027-2041) */
            if (!(e->Flags & WKD_ARC_ENTRY_DIRECTORY)) {
                WkdArc_FileNameLower(wideName, lowerName, sizeof(lowerName) / sizeof(WCHAR));
                if (lowerName[0] != L'\0' &&
                    (WkdArc_HasExt(lowerName, L".exe") ||
                     WkdArc_HasExt(lowerName, L".dll") ||
                     WkdArc_HasExt(lowerName, L".sys") ||
                     WkdArc_HasExt(lowerName, L".scr"))) {
                    e->Flags |= WKD_ARC_ENTRY_PE;
                } else if (WkdArc_HasExt(lowerName, L".zip") ||
                           WkdArc_HasExt(lowerName, L".rar") ||
                           WkdArc_HasExt(lowerName, L".7z") ||
                           WkdArc_HasExt(lowerName, L".tar")) {
                    e->Flags |= WKD_ARC_ENTRY_NESTED;
                    Result->NestedCount++;
                }
            }

            e->SecurityFlags = flags2;
            if (flags2 != WkdArcFlag_None) Result->FlaggedCount++;
            Result->SecurityFlags |= flags2;

            if (!WkdArc_SafeAdd64(Result->TotalUncompressed, unpSize,
                                  &Result->TotalUncompressed)) {
                Result->SecurityFlags |= WkdArcFlag_ZipBombSuspected;
                return STATUS_SUCCESS;
            }
            Result->EntryCount++;
            entryId++;

            offset += headSize + packSize;
        } else {
            /* 非文件头: ADD_SIZE flag 处理 (对齐 SS L2047-2059) */
            ULONG64 dataSize = 0;
            if ((flags & 0x8000) != 0 && headSize >= 11 && offset + headSize + 4 <= Size) {
                dataSize = WkdArc_ReadLE32(Buffer + offset + 7);
            }
            offset += headSize + dataSize;
        }
    }
    Result->TotalEntryCount = Result->EntryCount;
    return STATUS_SUCCESS;
}

/**************************************************/
/*               RAR5 头解析                       */
/*  对齐 SS ParseRar5Contents L2070-2257 +         */
/*  ReadRar5Vint L413-428                          */
/**************************************************/

#define WKD_RAR5_MARKER_LEN   8
#define WKD_RAR5_HDR_FILE     2
#define WKD_RAR5_HDR_END      5
#define WKD_RAR5_FILE_FLAG_DIRECTORY 0x0001
#define WKD_RAR5_FILE_FLAG_UNIX_MTIME 0x0002
#define WKD_RAR5_FILE_FLAG_CRC32      0x0004

static SIZE_T
WkdArc_ReadRar5Vint(
    _In_  const BYTE* Data,
    _In_  SIZE_T      Available,
    _Out_ PULONG64    OutValue
    )
{
    SIZE_T bytesRead = 0;
    ULONG shift = 0;
    *OutValue = 0;
    while (bytesRead < Available && bytesRead < 10) {
        BYTE b = Data[bytesRead++];
        *OutValue |= ((ULONG64)(b & 0x7F)) << shift;
        if ((b & 0x80) == 0) return bytesRead;
        shift += 7;
    }
    return 0;   /* 未终止 vint */
}

static NTSTATUS
WkdArc_ParseRar5Contents(
    _In_  const BYTE*          Buffer,
    _In_  ULONG                Size,
    _Inout_ PWKD_ARCHIVE_SCAN_RESULT Result
    )
/*++
Routine Description:
    RAR5 头级条目枚举 (不解压)。对齐 SS ParseRar5Contents L2070-2257。

Arguments:
    Buffer - RAR5 文件 buffer。
    Size   - 大小。
    Result - 输出结果。

Return Value:
    STATUS_SUCCESS。
--*/
{
    ULONG64 offset = WKD_RAR5_MARKER_LEN;
    ULONG64 entryId = 0;

    if (Size < WKD_RAR5_MARKER_LEN + 12) return STATUS_SUCCESS;

    while (offset + 6 < Size) {
        const BYTE* h = Buffer + offset;
        SIZE_T available = (SIZE_T)(Size - offset);
        SIZE_T pos = 4;   /* 跳过头 CRC32 */
        SIZE_T v;
        ULONG64 headerSize, headerType, headerFlags, extraSize = 0, dataAreaSize = 0;

        if (Result->EntryCount >= WKD_ARCHIVE_MAX_ENTRIES) break;
        if (entryId >= WKD_RAR4_MAX_ENTRIES) break;
        if (available < 4) break;

        v = WkdArc_ReadRar5Vint(h + pos, available - pos, &headerSize);
        if (v == 0 || headerSize < 1) break;
        pos += v;
        v = WkdArc_ReadRar5Vint(h + pos, available - pos, &headerType);
        if (v == 0) break;
        pos += v;
        v = WkdArc_ReadRar5Vint(h + pos, available - pos, &headerFlags);
        if (v == 0) break;
        pos += v;
        if ((headerFlags & 0x0001) != 0) {
            v = WkdArc_ReadRar5Vint(h + pos, available - pos, &extraSize);
            if (v == 0) break;
            pos += v;
        }
        if ((headerFlags & 0x0002) != 0) {
            v = WkdArc_ReadRar5Vint(h + pos, available - pos, &dataAreaSize);
            if (v == 0) break;
            pos += v;
        }

        if (headerType == WKD_RAR5_HDR_END) break;

        if (headerType == WKD_RAR5_HDR_FILE && pos + 4 < available) {
            ULONG64 fileFlags, unpSize, attributes, mtime = 0, dataCrc = 0;
            ULONG64 compInfo, hostOS, nameLen;
            CHAR fileName[256];
            ULONG flen = 0;
            WCHAR wideName[256];
            WCHAR lowerName[256];
            PWKD_ARCHIVE_ENTRY e;
            ULONG flags2 = WkdArcFlag_None;

            v = WkdArc_ReadRar5Vint(h + pos, available - pos, &fileFlags);
            if (v == 0) { offset += 4 + headerSize + dataAreaSize; continue; }
            pos += v;
            v = WkdArc_ReadRar5Vint(h + pos, available - pos, &unpSize);
            if (v == 0) { offset += 4 + headerSize + dataAreaSize; continue; }
            pos += v;
            v = WkdArc_ReadRar5Vint(h + pos, available - pos, &attributes);
            if (v == 0) { offset += 4 + headerSize + dataAreaSize; continue; }
            pos += v;
            if ((fileFlags & WKD_RAR5_FILE_FLAG_UNIX_MTIME) != 0 && pos + 4 <= available) {
                mtime = WkdArc_ReadLE32(h + pos);
                pos += 4;
            }
            if ((fileFlags & WKD_RAR5_FILE_FLAG_CRC32) != 0 && pos + 4 <= available) {
                dataCrc = WkdArc_ReadLE32(h + pos);
                pos += 4;
            }
            v = WkdArc_ReadRar5Vint(h + pos, available - pos, &compInfo);
            if (v == 0) { offset += 4 + headerSize + dataAreaSize; continue; }
            pos += v;
            v = WkdArc_ReadRar5Vint(h + pos, available - pos, &hostOS);
            if (v == 0) { offset += 4 + headerSize + dataAreaSize; continue; }
            pos += v;
            v = WkdArc_ReadRar5Vint(h + pos, available - pos, &nameLen);
            if (v == 0) { offset += 4 + headerSize + dataAreaSize; continue; }
            pos += v;

            if (nameLen > 0 && nameLen < 4096 && pos + nameLen <= available) {
                flen = (nameLen < 255) ? (ULONG)nameLen : 255;
                memcpy(fileName, h + pos, flen);
                fileName[flen] = '\0';
            }

            e = &Result->Entries[Result->EntryCount];
            RtlZeroMemory(e, sizeof(*e));
            strncpy_s(e->Name, sizeof(e->Name), fileName, _TRUNCATE);
            e->CompressedSize = dataAreaSize;
            e->UncompressedSize = unpSize;
            e->Crc32 = (ULONG)dataCrc;
            e->CompressionMethod = 0xFF;   /* rar5 */

            if (fileFlags & WKD_RAR5_FILE_FLAG_DIRECTORY) {
                e->Flags |= WKD_ARC_ENTRY_DIRECTORY;
            }

            if (unpSize > 0 && dataAreaSize > 0) {
                e->SingleEntryRatio = (double)unpSize / (double)dataAreaSize;
            }

            WkdArc_Utf8ToWide(fileName, wideName, sizeof(wideName) / sizeof(WCHAR));
            if (wideName[0] != L'\0' && !WkdArc_IsPathSafeW(wideName)) {
                flags2 |= WkdArcFlag_PathTraversalAttempt;
            }

            if (!(e->Flags & WKD_ARC_ENTRY_DIRECTORY)) {
                WkdArc_FileNameLower(wideName, lowerName, sizeof(lowerName) / sizeof(WCHAR));
                if (lowerName[0] != L'\0' &&
                    (WkdArc_HasExt(lowerName, L".exe") ||
                     WkdArc_HasExt(lowerName, L".dll") ||
                     WkdArc_HasExt(lowerName, L".sys") ||
                     WkdArc_HasExt(lowerName, L".scr"))) {
                    e->Flags |= WKD_ARC_ENTRY_PE;
                } else if (WkdArc_HasExt(lowerName, L".zip") ||
                           WkdArc_HasExt(lowerName, L".rar") ||
                           WkdArc_HasExt(lowerName, L".7z")) {
                    e->Flags |= WKD_ARC_ENTRY_NESTED;
                    Result->NestedCount++;
                }
            }

            e->SecurityFlags = flags2;
            if (flags2 != WkdArcFlag_None) Result->FlaggedCount++;
            Result->SecurityFlags |= flags2;

            if (!WkdArc_SafeAdd64(Result->TotalUncompressed, unpSize,
                                  &Result->TotalUncompressed)) {
                Result->SecurityFlags |= WkdArcFlag_ZipBombSuspected;
                return STATUS_SUCCESS;
            }
            Result->EntryCount++;
            entryId++;
        }

        offset += 4 + headerSize + dataAreaSize;
    }
    Result->TotalEntryCount = Result->EntryCount;
    return STATUS_SUCCESS;
}

/**************************************************/
/*               内容分析                           */
/*  对齐 SS ScanZipArchive L3575-3618 / ScanTar    */
/*  L1592-1643 (熵/SHA256/PE/脚本)                 */
/**************************************************/

VOID
WkdArc_AnalyzeEntryContent(
    _In_  const BYTE*        Content,
    _In_  ULONG              Size,
    _In_  PWKD_ARCHIVE_ENTRY Entry
    )
/*++
Routine Description:
    条目内容分析: 香农熵 + SHA256 + 哈希库命中 + PE/脚本检测。
    熵复用 wkd IocpCalculateShannonEntropy (真香农 0-8, 对齐 SS
    CalculateEntropy L479-498); 哈希复用 IocScanner_ComputeBufferSha256。

Arguments:
    Content - 条目内容。
    Size    - 大小。
    Entry   - 条目 (就地更新)。

Return Value:
    VOID。
--*/
{
    static const CHAR hexChars[] = "0123456789abcdef";
    DEF_SHA256_HASH hash;
    BOOLEAN malicious = FALSE;
    ULONG i;

    if (!Content || !Entry || Size == 0) return;

    /* 1. 香农熵 (SS L1597-1598) */
    Entry->Entropy = CoEntropyCalculate(Content, Size, CoEntropyAlphabet_Byte, 0);

    /* 2. SHA256 + 哈希库查询 (SS L1600-1606 + 内容级检测) */
    if (IocScanner_ComputeBufferSha256(Content, Size, &hash)) {
        for (i = 0; i < 32; i++) {
            Entry->Sha256Hex[i * 2]     = hexChars[(hash.Data[i] >> 4) & 0x0F];
            Entry->Sha256Hex[i * 2 + 1] = hexChars[hash.Data[i] & 0x0F];
        }
        Entry->Sha256Hex[64] = '\0';

        if (NT_SUCCESS(IocScanner_QueryHash(&hash, &malicious)) && malicious) {
            Entry->SecurityFlags |= WkdArcFlag_SuspiciousEntry;
        }
    }

    /* 3. PE 头 (SS L1608-1610) */
    if (Size >= 2 && Content[0] == 'M' && Content[1] == 'Z') {
        Entry->Flags |= WKD_ARC_ENTRY_PE;
    }

    /* 4. 脚本指示 (SS L1612-1622, 大小写折叠增强) */
    if (Size >= 10) {
        CHAR head[257];
        ULONG scanLen = (Size < 256) ? Size : 256;
        for (i = 0; i < scanLen; i++) head[i] = (CHAR)tolower((UCHAR)Content[i]);
        head[scanLen] = '\0';
        if (strstr(head, "#!/") != NULL ||
            strstr(head, "powershell") != NULL ||
            strstr(head, "wscript") != NULL ||
            strstr(head, "<script") != NULL) {
            Entry->Flags |= WKD_ARC_ENTRY_SCRIPT;
        }
    }

    /* 5. 内容级嵌套归档魔数检测 (对齐 SS L1624-1633):
       条目内容本身是归档 → 置 Nested + 记录 NestedFormat */
    if (Size >= 8) {
        WKD_ARCHIVE_FORMAT nestedFmt;
        ULONG scanLen = (Size < WKD_ARC_MAGIC_READ_SIZE) ? Size : WKD_ARC_MAGIC_READ_SIZE;
        if (WkdArc_DetectFormatBuffer(Content, scanLen, &nestedFmt) == STATUS_SUCCESS &&
            nestedFmt != WkdArcFormat_Unknown) {
            Entry->Flags |= WKD_ARC_ENTRY_NESTED;
            Entry->NestedFormat = nestedFmt;
        }
    }
}

/**************************************************/
/*               ZipBomb 检测                      */
/*  对齐 SS IsZipBomb L3105-3210 (5 检查)          */
/**************************************************/

BOOLEAN
WkdArc_IsZipBomb(
    _In_ PWKD_ARCHIVE_SCAN_RESULT Result,
    _In_ ULONG64                  FileSize
    )
/*++
Routine Description:
    ZipBomb 判定 5 检查: 总压缩比 / 总量超限 / 单条目比×2 /
    Quine (条目压缩尺寸=归档尺寸) / 重叠条目。

Arguments:
    Result   - 已解析结果。
    FileSize - 归档文件大小。

Return Value:
    TRUE = ZipBomb。
--*/
{
    ULONG i;

    if (!Result) return FALSE;

    /* 溢出 (解析期已标记) */
    if (Result->SecurityFlags & WkdArcFlag_ZipBombSuspected) return TRUE;

    /* 1. 总压缩比 (SS L3149-3164) */
    if (Result->TotalUncompressed > 0) {
        if (FileSize > 0) {
            if ((double)Result->TotalUncompressed / (double)FileSize > WKD_ARC_MAX_RATIO) {
                Result->SecurityFlags |= WkdArcFlag_ZipBombSuspected;
                return TRUE;
            }
        } else {
            Result->SecurityFlags |= WkdArcFlag_ZipBombSuspected;
            return TRUE;
        }
    }

    /* 2. 总量超限 (SS L3166-3172) */
    if (Result->TotalUncompressed > WKD_ARC_MAX_TOTAL_SIZE) {
        Result->SecurityFlags |= WkdArcFlag_ZipBombSuspected;
        return TRUE;
    }

    /* 3. 单条目比 ×2 (SS L3174-3183) */
    for (i = 0; i < Result->EntryCount; i++) {
        PWKD_ARCHIVE_ENTRY e = &Result->Entries[i];
        if (e->Flags & WKD_ARC_ENTRY_DIRECTORY) continue;
        if (e->CompressedSize == 0) continue;
        if (e->SingleEntryRatio > WKD_ARC_MAX_RATIO * 2.0) {
            Result->SecurityFlags |= WkdArcFlag_ZipBombSuspected;
            return TRUE;
        }
    }

    /* 4. Quine (SS L3185-3192) */
    for (i = 0; i < Result->EntryCount; i++) {
        PWKD_ARCHIVE_ENTRY e = &Result->Entries[i];
        if (e->Flags & WKD_ARC_ENTRY_DIRECTORY) continue;
        if (e->CompressedSize == FileSize) {
            Result->SecurityFlags |= WkdArcFlag_ZipBombSuspected;
            return TRUE;
        }
    }

    /* 5. 重叠条目 (SS L3194-3201) */
    if (Result->OverlappingCount > 0) {
        Result->SecurityFlags |= WkdArcFlag_ZipBombSuspected;
        return TRUE;
    }

    return FALSE;
}

/**************************************************/
/*               完整性校验                         */
/*  活: ZIP LFH 可达性 (对齐 SS VerifyIntegrity    */
/*  L2471-2641 的 LFH 检查部分)                    */
/**************************************************/

static BOOLEAN
WkdArc_VerifyIntegrityZip(
    _In_  const BYTE*          Buffer,
    _In_  ULONG                Size,
    _In_  PWKD_ARCHIVE_SCAN_RESULT Result
    )
{
    ULONG i;

    if (!Buffer || !Result) return FALSE;
    if (Result->ArchiveFormat != WkdArcFormat_Zip) return FALSE;

    for (i = 0; i < Result->EntryCount; i++) {
        PWKD_ARCHIVE_ENTRY e = &Result->Entries[i];
        const WKD_ZIP_LFH* lfh;
        if (e->LocalHeaderOffset + sizeof(WKD_ZIP_LFH) > Size) return FALSE;
        lfh = (const WKD_ZIP_LFH*)(Buffer + (ULONG)e->LocalHeaderOffset);
        if (lfh->Signature != WKD_ZIP_LOCAL_SIG) return FALSE;
    }
    return TRUE;
}

/* 死代码: 密码测试 (对齐 SS TestPassword L3235-3259, SS 亦恒 false) */
static BOOLEAN
WkdArc_TestPassword(
    _In_ PCWSTR FilePath,
    _In_ PCSTR  Password
    )
{
    /* 需完整解密支持, 与 SS 一致返回 FALSE (死代码, 未接入流水线) */
    UNREFERENCED_PARAMETER(FilePath);
    UNREFERENCED_PARAMETER(Password);
    return FALSE;
}

/**************************************************/
/*               路径落地校验                       */
/*  活: canonical 根校验 + reparse 拒绝 (对齐 SS   */
/*  ExtractAll L2860-2929)                          */
/**************************************************/

BOOLEAN
WkdArc_CheckPathInsideRoot(
    _In_ PCWSTR OutPath,
    _In_ PCWSTR OutputRoot,
    _In_ BOOLEAN AllowReparse
    )
/*++
Routine Description:
    判断净化路径是否安全落在输出根目录内。对齐 SS ExtractAll
    L2860-2929: canonical 根前缀校验 + reparse point 拒绝。
    活代码, 供未来隔离区/取证导出复用。

Arguments:
    OutPath      - 目标绝对路径。
    OutputRoot   - 输出根目录。
    AllowReparse - 是否允许目标为 reparse point。

Return Value:
    TRUE = 路径安全。
--*/
{
    WCHAR canonicalRoot[MAX_PATH];
    WCHAR canonicalOut[MAX_PATH];
    DWORD attrs;
    SIZE_T rlen, olen;

    if (!OutPath || !OutputRoot) return FALSE;

    if (GetFullPathNameW(OutputRoot, MAX_PATH, canonicalRoot, NULL) == 0) return FALSE;
    if (GetFullPathNameW(OutPath, MAX_PATH, canonicalOut, NULL) == 0) return FALSE;

    /* 尾部反斜杠归一化, 防 C:\out 与 C:\output 误判 (SS L2872-2878) */
    rlen = wcslen(canonicalRoot);
    if (rlen > 0 && canonicalRoot[rlen - 1] != L'\\' && canonicalRoot[rlen - 1] != L'/') {
        if (rlen + 1 < MAX_PATH) {
            canonicalRoot[rlen] = L'\\';
            canonicalRoot[rlen + 1] = L'\0';
        }
    }
    rlen = wcslen(canonicalRoot);
    olen = wcslen(canonicalOut);

    /* 前缀比较 (SS L2907-2914) */
    if (olen < rlen) return FALSE;
    if (_wcsnicmp(canonicalOut, canonicalRoot, rlen) != 0) return FALSE;

    /* reparse point 拒绝 (SS L2921-2929) */
    if (!AllowReparse) {
        attrs = GetFileAttributesW(canonicalOut);
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
            return FALSE;
        }
    }
    return TRUE;
}

/* 死代码: 落盘提取 (对齐 SS ExtractAll L2826-2953)。
   EDR 不落盘 (解压炸弹/临时污染), 功能面覆盖保留。
   canonical 校验复用 WkdArc_CheckPathInsideRoot。未接入流水线。 */
static NTSTATUS
WkdArc_ExtractAllToPath(
    _In_  const BYTE*          Buffer,
    _In_  ULONG                Size,
    _In_  PCWSTR               OutputDir,
    _In_  PWKD_ARCHIVE_SCAN_RESULT Result
    )
{
    WCHAR safePath[MAX_PATH];
    WCHAR fullPath[MAX_PATH];
    ULONG i;
    BYTE* content = NULL;

    if (!Buffer || !OutputDir || !Result) return STATUS_INVALID_PARAMETER;
    if (Result->ArchiveFormat != WkdArcFormat_Zip &&
        Result->ArchiveFormat != WkdArcFormat_Tar) {
        return STATUS_NOT_SUPPORTED;   /* 对齐 SS 仅 ZIP/TAR 全提取 */
    }

    content = (BYTE*)malloc(WKD_ARC_MAX_INFLATE);
    if (!content) return STATUS_NO_MEMORY;

    for (i = 0; i < Result->EntryCount; i++) {
        PWKD_ARCHIVE_ENTRY e = &Result->Entries[i];
        ULONG contentLen = 0;

        if (e->Flags & WKD_ARC_ENTRY_DIRECTORY) continue;
        if (e->UncompressedSize > WKD_ARC_MAX_INFLATE) continue;

        if (Result->ArchiveFormat == WkdArcFormat_Zip) {
            NTSTATUS st = WkdArc_ExtractEntryContent(
                Buffer, Size, e, content, WKD_ARC_MAX_INFLATE, &contentLen);
            if (!NT_SUCCESS(st)) continue;
        } else {
            if (e->DataOffset + e->DataSize > Size) continue;
            contentLen = (ULONG)e->DataSize;
            memcpy(content, Buffer + (ULONG)e->DataOffset, contentLen);
        }

        /* SanitizePath → 根目录内校验 */
        {
            WCHAR wideName[512];
            if (!WkdArc_Utf8ToWide(e->Name, wideName, sizeof(wideName) / sizeof(WCHAR))) continue;
            if (!WkdArc_SanitizePathW(wideName, safePath, MAX_PATH)) continue;
            if (safePath[0] == L'\0') continue;
        }
        if (swprintf_s(fullPath, MAX_PATH, L"%s\\%s", OutputDir, safePath) < 0) continue;
        if (!WkdArc_CheckPathInsideRoot(fullPath, OutputDir, FALSE)) continue;

        {
            HANDLE hOut = CreateFileW(fullPath, GENERIC_WRITE, 0, NULL,
                                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hOut != INVALID_HANDLE_VALUE) {
                DWORD written = 0;
                WriteFile(hOut, content, contentLen, &written, NULL);
                CloseHandle(hOut);
            }
        }
    }
    free(content);
    return STATUS_SUCCESS;
}

/**************************************************/
/*               判定                              */
/*  0 Clean / 1 Suspicious / 2 Infected            */
/**************************************************/

static VOID
WkdArc_DetermineVerdict(
    _Inout_ PWKD_ARCHIVE_SCAN_RESULT Result
    )
{
    ULONG i;

    /* Infected: ZipBomb */
    if (Result->IsZipBomb) {
        Result->Verdict = 2;
        strcpy_s(Result->ThreatName, sizeof(Result->ThreatName), "Archive.ZipBomb");
        return;
    }

    /* Infected: 条目内容哈希命中 ioc_hashes (内容分析闭环) */
    for (i = 0; i < Result->EntryCount; i++) {
        PWKD_ARCHIVE_ENTRY e = &Result->Entries[i];
        if ((e->SecurityFlags & WkdArcFlag_SuspiciousEntry) != 0 &&
            e->Sha256Hex[0] != '\0') {
            Result->Verdict = 2;
            strcpy_s(Result->ThreatName, sizeof(Result->ThreatName), "Archive.MaliciousEntry");
            return;
        }
    }

    /* Suspicious: 路径遍历优先细分 */
    if (Result->SecurityFlags & WkdArcFlag_PathTraversalAttempt) {
        Result->Verdict = 1;
        strcpy_s(Result->ThreatName, sizeof(Result->ThreatName), "Archive.PathTraversal");
        return;
    }

    /* Suspicious: 压缩比/加密/嵌套/重叠/链路/隐藏 */
    if (Result->SecurityFlags &
        (WkdArcFlag_HighCompressionRatio | WkdArcFlag_EncryptedContent |
         WkdArcFlag_DeepNesting | WkdArcFlag_OverlappingEntries |
         WkdArcFlag_SymlinkAttack | WkdArcFlag_HiddenEntry |
         WkdArcFlag_SuspiciousEntry)) {
        Result->Verdict = 1;
        strcpy_s(Result->ThreatName, sizeof(Result->ThreatName), "Archive.Suspicious");
        return;
    }

    Result->Verdict = 0;
    strcpy_s(Result->ThreatName, sizeof(Result->ThreatName), "Archive.Clean");
}

/**************************************************/
/*               归档格式判断                       */
/**************************************************/

NTSTATUS
IocArchive_IsArchive(
    _In_ PCWSTR     FilePath,
    _Out_ PBOOLEAN  IsArchive
    )
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
{
    WKD_ARCHIVE_FORMAT fmt;

    if (!FilePath || !IsArchive) return STATUS_INVALID_PARAMETER;
    *IsArchive = FALSE;

    if (WkdArc_DetectFormatPath(FilePath, &fmt) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }
    if (fmt != WkdArcFormat_Unknown) *IsArchive = TRUE;
    return STATUS_SUCCESS;
}

/**************************************************/
/*               主入口                            */
/*  对齐 SS ScanArchive L2735-2824 +               */
/*  ScanEngine::ScanArchive (扫描模式)             */
/**************************************************/

NTSTATUS
IocArchive_ScanFile(
    _In_ PCWSTR                 FilePath,
    _Out_ PWKD_ARCHIVE_SCAN_RESULT Result
    )
/*++
Routine Description:
    归档扫描主入口 (活代码, 接线点未接入 ScanManager):
    读入 → 格式检测 → 分派解析 → ZipBomb 5 检查 →
    逐条目内容分析 (ZIP STORED/DEFLATE + TAR) → 判定。

Arguments:
    FilePath - 文件完整路径。
    Result   - 输出扫描结果 (调用方堆分配)。

Return Value:
    NTSTATUS。
--*/
{
    HANDLE h;
    LARGE_INTEGER size;
    BYTE* buf = NULL;
    ULONG len = 0;
    DWORD rd = 0;
    WKD_ARCHIVE_FORMAT fmt;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;
    BYTE* contentBuf = NULL;
    ULONG contentCap = 0;

    if (!FilePath || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));

    h = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return STATUS_NOT_FOUND;

    GetFileSizeEx(h, &size);
    if (size.QuadPart <= 0) { CloseHandle(h); return STATUS_SUCCESS; }
    if (size.QuadPart > WKD_ARC_MAX_FILE_SIZE) { CloseHandle(h); return STATUS_SUCCESS; }
    len = (ULONG)size.QuadPart;

    buf = (BYTE*)malloc(len);
    if (!buf) { CloseHandle(h); return STATUS_NO_MEMORY; }
    if (!ReadFile(h, buf, len, &rd, NULL) || rd < len) {
        free(buf); CloseHandle(h); return STATUS_UNSUCCESSFUL;
    }
    CloseHandle(h);

    WkdArc_DetectFormatBuffer(buf, len, &fmt);
    Result->ArchiveFormat = fmt;

    /* 分派解析器 */
    switch (fmt) {
    case WkdArcFormat_Zip:
        status = WkdArc_ParseZipCentralDirectory(buf, len, Result);
        break;
    case WkdArcFormat_Tar:
        status = WkdArc_ParseTarContents(buf, len, Result);
        break;
    case WkdArcFormat_Gzip:
    case WkdArcFormat_TarGz:
        status = WkdArc_ParseGzipContents(buf, len, Result);
        break;
    case WkdArcFormat_Rar4:
        status = WkdArc_ParseRar4Contents(buf, len, Result);
        break;
    case WkdArcFormat_Rar5:
        status = WkdArc_ParseRar5Contents(buf, len, Result);
        break;
    default:
        /* 检测级格式 (7z/BZ2/XZ/ZSTD/CAB/LZMA/ISO 等):
           标记归档, 内容级依赖缺失 (死代码标注) */
        Result->IsArchive = TRUE;
        free(buf);
        if (NT_SUCCESS(status)) WkdArc_DetermineVerdict(Result);
        return status;
    }

    if (!NT_SUCCESS(status)) { free(buf); return status; }
    Result->IsArchive = TRUE;

    /* 总压缩比 */
    if (len > 0) {
        Result->CompressionRatio = (double)Result->TotalUncompressed / (double)len;
    }

    /* ZipBomb 判定 (5 检查) */
    Result->IsZipBomb = WkdArc_IsZipBomb(Result, len);

    /* 逐条目内容分析 (ZIP/TAR 可提取, DEFLATE 走 inflate)。
       按需分配: 容量 = 最大需分析条目大小 (cap 100MB) */
    for (i = 0; i < Result->EntryCount; i++) {
        PWKD_ARCHIVE_ENTRY e = &Result->Entries[i];
        if (e->Flags & WKD_ARC_ENTRY_DIRECTORY) continue;
        if (e->UncompressedSize > WKD_ARC_MAX_INFLATE) continue;
        if (e->UncompressedSize > contentCap) contentCap = (ULONG)e->UncompressedSize;
    }
    if (contentCap > 0) {
        contentBuf = (BYTE*)malloc(contentCap);
        if (contentBuf) {
            for (i = 0; i < Result->EntryCount; i++) {
                PWKD_ARCHIVE_ENTRY e = &Result->Entries[i];
                ULONG contentLen = 0;
                BOOLEAN got = FALSE;

                if (e->Flags & WKD_ARC_ENTRY_DIRECTORY) continue;
                if (e->UncompressedSize > WKD_ARC_MAX_INFLATE) continue;

                if (fmt == WkdArcFormat_Zip) {
                    if (WkdArc_ExtractEntryContent(buf, len, e, contentBuf,
                                                   contentCap, &contentLen) == STATUS_SUCCESS) {
                        got = TRUE;
                    }
                } else if (fmt == WkdArcFormat_Tar) {
                    if (e->DataOffset + e->DataSize <= len && e->DataSize <= WKD_ARC_MAX_INFLATE) {
                        contentLen = (ULONG)e->DataSize;
                        memcpy(contentBuf, buf + (ULONG)e->DataOffset, contentLen);
                        got = TRUE;
                    }
                }

                if (got && contentLen > 0) {
                    WkdArc_AnalyzeEntryContent(contentBuf, contentLen, e);
                }
            }
            free(contentBuf);
        }
    }

    /* DeepNesting (对齐 SS AnalyzeSecurity L3090-3095: 嵌套数 > 上限) */
    if (Result->NestedCount > WKD_ARC_MAX_NESTING) {
        Result->SecurityFlags |= WkdArcFlag_DeepNesting;
    }

    /* 判定 */
    WkdArc_DetermineVerdict(Result);

    free(buf);
    return status;
}

/**************************************************/
/*   死代码 API 面                                 */
/*  对齐 ShadowStrike ArchiveExtractor 公开接口    */
/*  (GetSupportedFormats/ListContents/GetArchiveInfo */
/*  VerifyIntegrity / Extract / QuickSecurityCheck  */
/*  HandleKernelScanRequest/AnalyzeSecurity/        */
/*  CheckEntrySecurity/MatchesPattern), 功能面占位  */
/*  ⚠ 死代码: 未接入流水线, 无调用方。             */
/**************************************************/

/* 读整个文件 (≤200MB cap), 调用方 free。主入口保留自身读逻辑。 */
static NTSTATUS
WkdArc_ReadWholeFile(
    _In_  PCWSTR FilePath,
    _Out_ BYTE**  Buf,
    _Out_ PULONG  Len
    )
{
    HANDLE h;
    LARGE_INTEGER size;
    BYTE* buf;
    DWORD rd = 0;

    *Buf = NULL;
    *Len = 0;

    h = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return STATUS_NOT_FOUND;

    GetFileSizeEx(h, &size);
    if (size.QuadPart <= 0) { CloseHandle(h); return STATUS_SUCCESS; }
    if (size.QuadPart > WKD_ARC_MAX_FILE_SIZE) { CloseHandle(h); return STATUS_SUCCESS; }
    *Len = (ULONG)size.QuadPart;

    buf = (BYTE*)malloc(*Len);
    if (!buf) { CloseHandle(h); return STATUS_NO_MEMORY; }
    if (!ReadFile(h, buf, *Len, &rd, NULL) || rd < *Len) {
        free(buf); CloseHandle(h); return STATUS_UNSUCCESSFUL;
    }
    CloseHandle(h);
    *Buf = buf;
    return STATUS_SUCCESS;
}

/* 检测格式 + 分派解析器 (纯 buffer, 无文件 I/O) */
static NTSTATUS
WkdArc_ParseBuffer(
    _In_  const BYTE*          Buffer,
    _In_  ULONG                Size,
    _Inout_ PWKD_ARCHIVE_SCAN_RESULT Result,
    _Out_ PWKD_ARCHIVE_FORMAT  Format
    )
{
    WkdArc_DetectFormatBuffer(Buffer, Size, Format);
    Result->ArchiveFormat = *Format;

    switch (*Format) {
    case WkdArcFormat_Zip:
        return WkdArc_ParseZipCentralDirectory(Buffer, Size, Result);
    case WkdArcFormat_Tar:
        return WkdArc_ParseTarContents(Buffer, Size, Result);
    case WkdArcFormat_Gzip:
    case WkdArcFormat_TarGz:
        return WkdArc_ParseGzipContents(Buffer, Size, Result);
    case WkdArcFormat_Rar4:
        return WkdArc_ParseRar4Contents(Buffer, Size, Result);
    case WkdArcFormat_Rar5:
        return WkdArc_ParseRar5Contents(Buffer, Size, Result);
    default:
        /* 检测级格式 (7z/BZ2/XZ/ZSTD/CAB/LZMA/ISO), 内容级依赖缺失 */
        Result->IsArchive = TRUE;
        return STATUS_SUCCESS;
    }
}

/* 支持格式列表 (对齐 SS GetSupportedFormats L978-988) */
NTSTATUS
WkdArc_GetSupportedFormats(
    _Out_ PWKD_ARCHIVE_FORMAT Formats,
    _In_  ULONG               MaxCount,
    _Out_ PULONG              Count
    )
/*++ 死代码: 无调用方。 --*/
{
    static const WKD_ARCHIVE_FORMAT All[] = {
        WkdArcFormat_Zip, WkdArcFormat_Rar4, WkdArcFormat_Rar5,
        WkdArcFormat_SevenZip, WkdArcFormat_Tar, WkdArcFormat_Gzip,
        WkdArcFormat_Bzip2, WkdArcFormat_Xz, WkdArcFormat_Zstd,
        WkdArcFormat_Cab, WkdArcFormat_Lzma, WkdArcFormat_Iso,
        WkdArcFormat_TarGz, WkdArcFormat_TarBz2, WkdArcFormat_TarXz,
        WkdArcFormat_TarZstd,
    };
    ULONG n = sizeof(All) / sizeof(All[0]);

    if (!Formats || !Count || MaxCount == 0) return STATUS_INVALID_PARAMETER;
    if (MaxCount < n) n = MaxCount;
    memcpy(Formats, All, n * sizeof(All[0]));
    *Count = n;
    return STATUS_SUCCESS;
}

/* 单条目安全判定 (对齐 SS CheckEntrySecurity L3212-3224) */
NTSTATUS
WkdArc_CheckEntrySecurity(
    _In_  PWKD_ARCHIVE_ENTRY Entry,
    _Out_ PULONG              SecurityFlags
    )
/*++ 死代码: 无调用方, 安全检查内联在解析器。 --*/
{
    WCHAR wideName[512];
    ULONG flags = WkdArcFlag_None;

    if (!Entry || !SecurityFlags) return STATUS_INVALID_PARAMETER;

    if (WkdArc_Utf8ToWide(Entry->Name, wideName, sizeof(wideName) / sizeof(WCHAR)) &&
        wideName[0] != L'\0' && !WkdArc_IsPathSafeW(wideName)) {
        flags |= WkdArcFlag_PathTraversalAttempt;
    }
    if (!(Entry->Flags & WKD_ARC_ENTRY_DIRECTORY) &&
        Entry->CompressedSize > 0 && Entry->SingleEntryRatio > WKD_ARC_MAX_RATIO) {
        flags |= WkdArcFlag_HighCompressionRatio;
    }
    if (Entry->Flags & (WKD_ARC_ENTRY_SYMLINK | WKD_ARC_ENTRY_HARDLINK)) {
        flags |= WkdArcFlag_SymlinkAttack;
    }
    if (Entry->Flags & WKD_ARC_ENTRY_ENCRYPTED) {
        flags |= WkdArcFlag_EncryptedContent;
    }
    if (Entry->Flags & WKD_ARC_ENTRY_HIDDEN) {
        flags |= WkdArcFlag_HiddenEntry;
    }

    *SecurityFlags = flags;
    return STATUS_SUCCESS;
}

/* 通配符匹配 (对齐 SS MatchesPattern L3771-3802) */
BOOLEAN
WkdArc_MatchesPattern(
    _In_ PCWSTR Path,
    _In_ PCWSTR Pattern
    )
/*++ 死代码: 供 ExtractMatching 用。 --*/
{
    SIZE_T plen = wcslen(Pattern);

    if (wcscmp(Pattern, L"*") == 0) return TRUE;
    if (wcschr(Pattern, L'*') == NULL) return wcscmp(Path, Pattern) == 0;

    /* 扩展名匹配: *.exe */
    if (plen >= 2 && Pattern[0] == L'*' && Pattern[1] == L'.') {
        return WkdArc_HasExt(Path, Pattern + 1);
    }

    /* 包含匹配: *foo* (在单端通配前检查) */
    if (plen > 2 && Pattern[0] == L'*' && Pattern[plen - 1] == L'*') {
        WCHAR mid[256];
        SIZE_T mlen = plen - 2;
        if (mlen >= 256) return FALSE;
        wcsncpy_s(mid, 256, Pattern + 1, mlen);
        mid[mlen] = L'\0';
        return wcsstr(Path, mid) != NULL;
    }

    /* 前缀匹配: dir/* */
    if (Pattern[plen - 1] == L'*') {
        return _wcsnicmp(Path, Pattern, plen - 1) == 0;
    }

    /* 后缀匹配: *filename */
    if (Pattern[0] == L'*') {
        SIZE_T slen = plen - 1;
        SIZE_T plen2 = wcslen(Path);
        if (plen2 < slen) return FALSE;
        return _wcsnicmp(Path + (plen2 - slen), Pattern + 1, slen) == 0;
    }

    return FALSE;
}

/* 纯条目枚举 (对齐 SS ListContents L2372-2469) */
NTSTATUS
WkdArc_ListContents(
    _In_ PCWSTR                FilePath,
    _Inout_ PWKD_ARCHIVE_SCAN_RESULT Result
    )
/*++ 死代码: 未接入流水线, 主入口 IocArchive_ScanFile 覆盖枚举+分析。 --*/
{
    BYTE* buf = NULL;
    ULONG len = 0;
    WKD_ARCHIVE_FORMAT fmt;
    NTSTATUS status;

    if (!FilePath || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));

    status = WkdArc_ReadWholeFile(FilePath, &buf, &len);
    if (!NT_SUCCESS(status) || !buf) return status;

    status = WkdArc_ParseBuffer(buf, len, Result, &fmt);
    if (NT_SUCCESS(status) && len > 0) {
        Result->CompressionRatio = (double)Result->TotalUncompressed / (double)len;
    }

    free(buf);
    return status;
}

/* 归档聚合信息 (对齐 SS GetArchiveInfo L2263-2370) */
NTSTATUS
WkdArc_GetArchiveInfo(
    _In_  PCWSTR          FilePath,
    _Out_ PWKD_ARCHIVE_INFO Info
    )
/*++ 死代码: 未接入流水线, 统计可由主入口结果推导。 --*/
{
    BYTE* buf = NULL;
    ULONG len = 0;
    WKD_ARCHIVE_FORMAT fmt;
    WKD_ARCHIVE_SCAN_RESULT result;
    NTSTATUS status;
    ULONG i;

    if (!FilePath || !Info) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Info, sizeof(*Info));
    RtlZeroMemory(&result, sizeof(result));

    status = WkdArc_ReadWholeFile(FilePath, &buf, &len);
    if (!NT_SUCCESS(status) || !buf) return status;

    status = WkdArc_ParseBuffer(buf, len, &result, &fmt);
    if (NT_SUCCESS(status)) {
        Info->ArchiveFormat = fmt;
        Info->FileSize = len;
        Info->TotalEntries = result.TotalEntryCount;
        Info->TotalUncompressedSize = result.TotalUncompressed;
        Info->SecurityFlags = result.SecurityFlags;

        for (i = 0; i < result.EntryCount; i++) {
            PWKD_ARCHIVE_ENTRY e = &result.Entries[i];
            if (e->Flags & WKD_ARC_ENTRY_DIRECTORY) Info->DirectoryCount++;
            else Info->FileCount++;
            if (e->Flags & WKD_ARC_ENTRY_ENCRYPTED) Info->HasEncryptedEntries = TRUE;
            if (!WkdArc_SafeAdd64(Info->TotalCompressedSize, e->CompressedSize,
                                  &Info->TotalCompressedSize)) {
                Info->TotalCompressedSize = (ULONG64)-1;
            }
        }
        if (Info->TotalCompressedSize > 0) {
            Info->OverallCompressionRatio =
                (double)Info->TotalUncompressedSize / (double)Info->TotalCompressedSize;
        }
    }

    free(buf);
    return status;
}

/* 完整性校验 (对齐 SS VerifyIntegrity L2471-2641) */
NTSTATUS
WkdArc_VerifyIntegrity(
    _In_  PCWSTR   FilePath,
    _Out_ PBOOLEAN Valid
    )
/*++ 死代码: 未接入流水线; ZIP LFH 可达性 + TAR 可解析。 --*/
{
    BYTE* buf = NULL;
    ULONG len = 0;
    WKD_ARCHIVE_FORMAT fmt;
    WKD_ARCHIVE_SCAN_RESULT result;
    NTSTATUS status;

    if (!FilePath || !Valid) return STATUS_INVALID_PARAMETER;
    *Valid = FALSE;
    RtlZeroMemory(&result, sizeof(result));

    status = WkdArc_ReadWholeFile(FilePath, &buf, &len);
    if (!NT_SUCCESS(status) || !buf) return status;

    status = WkdArc_ParseBuffer(buf, len, &result, &fmt);
    if (NT_SUCCESS(status)) {
        if (fmt == WkdArcFormat_Zip) {
            *Valid = WkdArc_VerifyIntegrityZip(buf, len, &result);
        } else if (fmt == WkdArcFormat_Tar) {
            *Valid = (result.EntryCount > 0);   /* TAR: 能解析出条目 (SS L2474-2486) */
        } else {
            *Valid = TRUE;   /* 非 ZIP/TAR: SS 仅 fs::exists (L2487-2492) */
        }
    }

    free(buf);
    return status;
}

/* 单条目内存提取 (对齐 SS ExtractEntry L2955-3003) */
NTSTATUS
WkdArc_ExtractEntry(
    _In_  PCWSTR FilePath,
    _In_  PCWSTR EntryPath,
    _Out_ BYTE*  Out,
    _In_  ULONG  OutCap,
    _Out_ PULONG OutLen
    )
/*++ 死代码: 未接入流水线。 --*/
{
    BYTE* buf = NULL;
    ULONG len = 0;
    WKD_ARCHIVE_FORMAT fmt;
    WKD_ARCHIVE_SCAN_RESULT result;
    NTSTATUS status = STATUS_NOT_FOUND;
    ULONG i;

    if (!FilePath || !EntryPath || !Out || !OutLen) return STATUS_INVALID_PARAMETER;
    *OutLen = 0;
    RtlZeroMemory(&result, sizeof(result));

    status = WkdArc_ReadWholeFile(FilePath, &buf, &len);
    if (!NT_SUCCESS(status) || !buf) return status;

    status = WkdArc_ParseBuffer(buf, len, &result, &fmt);
    if (!NT_SUCCESS(status)) { free(buf); return status; }

    for (i = 0; i < result.EntryCount; i++) {
        PWKD_ARCHIVE_ENTRY e = &result.Entries[i];
        WCHAR wideName[512];
        PCWSTR fname;

        if (!WkdArc_Utf8ToWide(e->Name, wideName, sizeof(wideName) / sizeof(WCHAR))) continue;
        fname = wcsrchr(wideName, L'\\');
        if (!fname) fname = wcsrchr(wideName, L'/');
        if (fname) fname++; else fname = wideName;

        /* 完整路径或文件名匹配 (SS L2977) */
        if (wcscmp(wideName, EntryPath) != 0 && wcscmp(fname, EntryPath) != 0) continue;

        if (fmt == WkdArcFormat_Tar) {
            if (e->DataOffset + e->DataSize <= len && e->DataSize <= OutCap) {
                *OutLen = (ULONG)e->DataSize;
                memcpy(Out, buf + (ULONG)e->DataOffset, *OutLen);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
        } else {
            status = WkdArc_ExtractEntryContent(buf, len, e, Out, OutCap, OutLen);
        }
        break;
    }

    free(buf);
    return status;
}

/* 模式匹配提取 (对齐 SS ExtractMatching L3005-3017) */
NTSTATUS
WkdArc_ExtractMatching(
    _In_ PCWSTR                     FilePath,
    _In_ PCWSTR                     Pattern,
    _In_opt_ WKD_ARC_ENTRY_CALLBACK Callback,
    _In_opt_ PVOID                  Context
    )
/*++ 死代码: 未接入流水线。 --*/
{
    BYTE* buf = NULL;
    ULONG len = 0;
    WKD_ARCHIVE_FORMAT fmt;
    WKD_ARCHIVE_SCAN_RESULT result;
    NTSTATUS status;
    ULONG i;
    ULONG contentCap = 0;
    BYTE* content = NULL;

    if (!FilePath || !Pattern) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(&result, sizeof(result));

    status = WkdArc_ReadWholeFile(FilePath, &buf, &len);
    if (!NT_SUCCESS(status) || !buf) return status;

    status = WkdArc_ParseBuffer(buf, len, &result, &fmt);
    if (!NT_SUCCESS(status)) { free(buf); return status; }

    for (i = 0; i < result.EntryCount; i++) {
        PWKD_ARCHIVE_ENTRY e = &result.Entries[i];
        if (e->UncompressedSize > contentCap && e->UncompressedSize <= WKD_ARC_MAX_INFLATE) {
            contentCap = (ULONG)e->UncompressedSize;
        }
    }
    if (contentCap > 0) content = (BYTE*)malloc(contentCap);

    if (content) {
        for (i = 0; i < result.EntryCount; i++) {
            PWKD_ARCHIVE_ENTRY e = &result.Entries[i];
            WCHAR wideName[512];
            ULONG contentLen = 0;

            if (e->Flags & WKD_ARC_ENTRY_DIRECTORY) continue;
            if (!WkdArc_Utf8ToWide(e->Name, wideName, sizeof(wideName) / sizeof(WCHAR))) continue;
            if (!WkdArc_MatchesPattern(wideName, Pattern)) continue;

            if (fmt == WkdArcFormat_Tar) {
                if (e->DataOffset + e->DataSize > len) continue;
                contentLen = (ULONG)e->DataSize;
                memcpy(content, buf + (ULONG)e->DataOffset, contentLen);
            } else {
                if (WkdArc_ExtractEntryContent(buf, len, e, content, contentCap,
                                               &contentLen) != STATUS_SUCCESS) {
                    continue;
                }
            }
            if (Callback) Callback(e, content, contentLen, Context);
        }
        free(content);
    }

    free(buf);
    return status;
}

/* 流式提取 (对齐 SS ExtractStreaming L3019-3045) */
NTSTATUS
WkdArc_ExtractStreaming(
    _In_ PCWSTR                      FilePath,
    _In_ ULONG                       ChunkSize,
    _In_opt_ WKD_ARC_STREAM_CALLBACK Callback,
    _In_opt_ PVOID                   Context
    )
/*++ 死代码: 未接入流水线。 --*/
{
    BYTE* buf = NULL;
    ULONG len = 0;
    WKD_ARCHIVE_FORMAT fmt;
    WKD_ARCHIVE_SCAN_RESULT result;
    NTSTATUS status;
    ULONG i;
    ULONG contentCap = 0;
    BYTE* content = NULL;

    if (!FilePath || ChunkSize == 0) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(&result, sizeof(result));

    status = WkdArc_ReadWholeFile(FilePath, &buf, &len);
    if (!NT_SUCCESS(status) || !buf) return status;

    status = WkdArc_ParseBuffer(buf, len, &result, &fmt);
    if (!NT_SUCCESS(status)) { free(buf); return status; }

    for (i = 0; i < result.EntryCount; i++) {
        PWKD_ARCHIVE_ENTRY e = &result.Entries[i];
        if (e->UncompressedSize > contentCap && e->UncompressedSize <= WKD_ARC_MAX_INFLATE) {
            contentCap = (ULONG)e->UncompressedSize;
        }
    }
    if (contentCap > 0) content = (BYTE*)malloc(contentCap);

    if (content) {
        for (i = 0; i < result.EntryCount; i++) {
            PWKD_ARCHIVE_ENTRY e = &result.Entries[i];
            ULONG contentLen = 0;

            if (e->Flags & WKD_ARC_ENTRY_DIRECTORY) continue;

            if (fmt == WkdArcFormat_Tar) {
                if (e->DataOffset + e->DataSize > len) continue;
                contentLen = (ULONG)e->DataSize;
                memcpy(content, buf + (ULONG)e->DataOffset, contentLen);
            } else {
                if (WkdArc_ExtractEntryContent(buf, len, e, content, contentCap,
                                               &contentLen) != STATUS_SUCCESS) {
                    continue;
                }
            }

            /* 分块投递 (SS L3029-3043) */
            if (Callback && contentLen > 0) {
                ULONG off = 0;
                while (off < contentLen) {
                    ULONG thisChunk = contentLen - off;
                    BOOLEAN isLast;
                    if (thisChunk > ChunkSize) thisChunk = ChunkSize;
                    isLast = (off + thisChunk >= contentLen);
                    if (!Callback(e, content + off, thisChunk, isLast, Context)) break;
                    off += thisChunk;
                }
            }
        }
        free(content);
    }

    free(buf);
    return status;
}

/* 快速预检 (对齐 SS QuickSecurityCheck L3344-3391) */
NTSTATUS
WkdArc_QuickSecurityCheck(
    _In_  PCWSTR FilePath,
    _Out_ PULONG SecurityFlags
    )
/*++ 死代码: 未接入流水线; 实时过滤热路径预检由 ScanManager 决策。 --*/
{
    BYTE* buf = NULL;
    ULONG len = 0;
    WKD_ARCHIVE_FORMAT fmt;
    WKD_ARCHIVE_SCAN_RESULT result;
    NTSTATUS status;

    if (!FilePath || !SecurityFlags) return STATUS_INVALID_PARAMETER;
    *SecurityFlags = WkdArcFlag_None;
    RtlZeroMemory(&result, sizeof(result));

    status = WkdArc_ReadWholeFile(FilePath, &buf, &len);
    if (!NT_SUCCESS(status) || !buf) return status;

    status = WkdArc_ParseBuffer(buf, len, &result, &fmt);
    if (NT_SUCCESS(status)) {
        if (WkdArc_IsZipBomb(&result, len)) {
            *SecurityFlags |= WkdArcFlag_ZipBombSuspected | WkdArcFlag_HighCompressionRatio;
        }
        *SecurityFlags |= result.SecurityFlags;
    }

    free(buf);
    return status;
}

/* 内核扫描请求 (对齐 SS HandleKernelScanRequest L3304-3342) */
NTSTATUS
WkdArc_HandleKernelScanRequest(
    _In_ PCWSTR                     FilePath,
    _In_ ULONG                      ProcessId,
    _In_opt_ WKD_ARC_ENTRY_CALLBACK ScanCallback,
    _In_opt_ PVOID                  Context,
    _Out_ PBOOLEAN                  AllClean
    )
/*++ 死代码: wkd 架构由 ScanManager 主动扫, 驱动不直发归档请求。 --*/
{
    BYTE* buf = NULL;
    ULONG len = 0;
    WKD_ARCHIVE_FORMAT fmt;
    WKD_ARCHIVE_SCAN_RESULT result;
    NTSTATUS status;
    ULONG i;
    ULONG contentCap = 0;
    BYTE* content = NULL;

    UNREFERENCED_PARAMETER(ProcessId);

    if (!FilePath || !AllClean) return STATUS_INVALID_PARAMETER;
    *AllClean = TRUE;
    RtlZeroMemory(&result, sizeof(result));

    status = WkdArc_ReadWholeFile(FilePath, &buf, &len);
    if (!NT_SUCCESS(status) || !buf) return status;

    status = WkdArc_ParseBuffer(buf, len, &result, &fmt);
    if (!NT_SUCCESS(status)) { free(buf); return status; }

    for (i = 0; i < result.EntryCount; i++) {
        PWKD_ARCHIVE_ENTRY e = &result.Entries[i];
        if (e->UncompressedSize > contentCap && e->UncompressedSize <= WKD_ARC_MAX_INFLATE) {
            contentCap = (ULONG)e->UncompressedSize;
        }
    }
    if (contentCap > 0) content = (BYTE*)malloc(contentCap);

    if (content) {
        for (i = 0; i < result.EntryCount; i++) {
            PWKD_ARCHIVE_ENTRY e = &result.Entries[i];
            ULONG contentLen = 0;

            if (e->Flags & WKD_ARC_ENTRY_DIRECTORY) continue;

            if (fmt == WkdArcFormat_Tar) {
                if (e->DataOffset + e->DataSize > len) continue;
                contentLen = (ULONG)e->DataSize;
                memcpy(content, buf + (ULONG)e->DataOffset, contentLen);
            } else {
                if (WkdArc_ExtractEntryContent(buf, len, e, content, contentCap,
                                               &contentLen) != STATUS_SUCCESS) {
                    continue;
                }
            }

            if (ScanCallback && !ScanCallback(e, content, contentLen, Context)) {
                *AllClean = FALSE;
            }
        }
        free(content);
    }

    /* ZipBomb 亦判不 clean (对齐 SS L3337-3339) */
    if (WkdArc_IsZipBomb(&result, len)) *AllClean = FALSE;

    free(buf);
    return status;
}

/* 聚合安全分析 (对齐 SS AnalyzeSecurity L3051-3103) */
NTSTATUS
WkdArc_AnalyzeSecurity(
    _In_ PCWSTR                 FilePath,
    _Inout_ PWKD_ARCHIVE_SCAN_RESULT Result
    )
/*++ 死代码: 未接入流水线; 主入口已含 ZipBomb/DeepNesting/判定。 --*/
{
    BYTE* buf = NULL;
    ULONG len = 0;
    WKD_ARCHIVE_FORMAT fmt;
    NTSTATUS status;

    if (!FilePath || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));

    status = WkdArc_ReadWholeFile(FilePath, &buf, &len);
    if (!NT_SUCCESS(status) || !buf) return status;

    status = WkdArc_ParseBuffer(buf, len, Result, &fmt);
    if (NT_SUCCESS(status)) {
        if (WkdArc_IsZipBomb(Result, len)) {
            Result->SecurityFlags |= WkdArcFlag_ZipBombSuspected | WkdArcFlag_HighCompressionRatio;
        }
        if (Result->NestedCount > WKD_ARC_MAX_NESTING) {
            Result->SecurityFlags |= WkdArcFlag_DeepNesting;
        }
        WkdArc_DetermineVerdict(Result);
    }

    free(buf);
    return status;
}

