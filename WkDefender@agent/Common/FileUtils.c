/**************************************************/
/*  WkDefender Agent - �ļ�/�ֽ�/����̬����         */
/*                                                  */
/*  2026-08-15 �ع�: �� IOC/IocScanner.c Ǩ��        */
/*  ��ɨ���ص��ļ� I/O������ʶ��(ħ��/����/����/��չ��) */
/*  ������(ͳһ��)���ܡ�                            */
/*                                                  */
/*  2026-09-08 �ع�: ���㷨��ϣ(SHA256/MD5/CTPH/    */
/*  TLSH)���������ʱ��� BCrypUtils.{c,h} ͳһ�ϲ���   */
/*  ���������� FileUtils.h ͨ BCrypUtils.h �������ġ� */
/**************************************************/

#include "FileUtils.h"
#include "../Common/Utils.h"     /* UtHexEncode/UtHexDecode/UtBase64Encode */
#include "../IOC/PEAnalyzer/PeAnalyzer.h"
#include "../IOC/IocScanner.h"   /* IocScan_AnalyzeScript/ReadFileHeader ���� */  /* CtphHashNormalized ������ת�� WpeParseBufferContext */
#include <windows.h>
#include <math.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
/**************************************************/
/*  Entropy (unified) - user-mode float, bits out  */
/**************************************************/

DOUBLE
CoEntropyCalculate(
    _In_ LPCVOID Buffer,
    _In_ SIZE_T  Size,
    _In_ CO_ENTROPY_ALPHABET Alphabet,
    _In_ SIZE_T  Sample
    )
{
    const BYTE* data = (const BYTE*)Buffer;
    SIZE_T n, i;
    DOUBLE freq[256];
    DOUBLE H = 0.0;

    if (data == NULL || Size == 0) return 0.0;
    n = (Sample == 0) ? Size : (Size > Sample ? Sample : Size);

    for (i = 0; i < (SIZE_T)Alphabet; i++) freq[i] = 0.0;
    for (i = 0; i < n; i++) {
        UINT idx = (UINT)data[i];
        if (idx < (UINT)Alphabet) freq[idx] += 1.0;
    }
    for (i = 0; i < (SIZE_T)Alphabet; i++) {
        if (freq[i] > 0.0) {
            DOUBLE p = freq[i] / (DOUBLE)n;
            H -= p * (log(p) / log(2.0));
        }
    }
    return H;
}

DOUBLE
CoEntropyBinary(
    _In_ LPCVOID Buffer,
    _In_ SIZE_T  Size,
    _In_ SIZE_T  Sample
    )
{
    return CoEntropyCalculate(Buffer, Size, CoEntropyAlphabet_Byte, Sample);
}

DOUBLE
CoEntropyStringW(
    _In_ LPCWSTR String,
    _In_ USHORT  LengthChars
    )
{
    ULONG freq[128];
    DOUBLE H = 0.0;
    SIZE_T i, n = 0;
    USHORT c;

    if (String == NULL || LengthChars < 2) return 0.0;
    for (i = 0; i < 128; i++) freq[i] = 0;
    for (i = 0; i < (SIZE_T)LengthChars; i++) {
        c = (USHORT)String[i];
        if (c < 128) { freq[c]++; n++; }
    }
    if (n == 0) return 0.0;
    for (i = 0; i < 128; i++) {
        if (freq[i] > 0) {
            DOUBLE p = (DOUBLE)freq[i] / (DOUBLE)n;
            H -= p * (log(p) / log(2.0));
        }
    }
    return H;
}

DOUBLE
CoEntropyStringA(
    _In_ LPCSTR String,
    _In_ USHORT  LengthChars
    )
{
    ULONG freq[128];
    DOUBLE H = 0.0;
    SIZE_T i, n = 0;
    UCHAR c;

    if (String == NULL || LengthChars < 2) return 0.0;
    for (i = 0; i < 128; i++) freq[i] = 0;
    for (i = 0; i < (SIZE_T)LengthChars; i++) {
        c = (UCHAR)String[i];
        if (c < 128) { freq[c]++; n++; }
    }
    if (n == 0) return 0.0;
    for (i = 0; i < 128; i++) {
        if (freq[i] > 0) {
            DOUBLE p = (DOUBLE)freq[i] / (DOUBLE)n;
            H -= p * (log(p) / log(2.0));
        }
    }
    return H;
}

ULONG
CoEntropyToFixed(
    _In_ DOUBLE Bits,
    _In_ ULONG  Scale
    )
{
    ULONG v = (ULONG)(Bits * (DOUBLE)Scale);
    return (v > Scale) ? Scale : v;
}

ULONG
CoEntropyToPercent(
    _In_ DOUBLE Bits,
    _In_ CO_ENTROPY_ALPHABET Alphabet
    )
{
    DOUBLE maxBits = (DOUBLE)(Alphabet == CoEntropyAlphabet_Byte ? 8.0 : 7.0);
    ULONG pct = (ULONG)(Bits / maxBits * 100.0);
    return (pct > 100) ? 100 : pct;
}
_Use_decl_annotations_
HANDLE
CoOpenFileForSequentialRead(
    _In_ PCWSTR FilePath,
    _Out_opt_ PSIZE_T FileSize
    )
/*++
Routine Description:
    ��˳���ģʽ���ļ���ִ�а�ȫ����: FILE_FLAG_OPEN_REPARSE_POINT ������
    �����ض���, �򿪺��þ��У��ܾ�Ŀ¼/reparse (TOCTOU-safe), 4GB ��СԤ�졣

Arguments:
    Path     - �ļ�·����
    TooLarge - ���: TRUE=�ļ��� 4GB ���ޡ�

Return Value:
    ��Ч���; ʧ�ܷ��� INVALID_HANDLE_VALUE��
--*/
{
    HANDLE hFile;
    BY_HANDLE_FILE_INFORMATION info;
    LARGE_INTEGER fileSize;

    if (!CoCheckStringValidity(FilePath)) return INVALID_HANDLE_VALUE;
    if (FileSize) *FileSize = 0;

    hFile = CreateFileW(FilePath, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING,
                        FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT,
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

    /* ���Ѵ򿪾��У�� (���� SS L1083-1101): �ܾ�Ŀ¼/reparse �� */
    if (!GetFileInformationByHandle(hFile, &info)) goto Cleanup;
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        goto Cleanup;
    }

    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart < 0) goto Cleanup;

    if (FileSize) *FileSize = (SIZE_T)fileSize.QuadPart;
    return hFile;

Cleanup:
    CloseHandle(hFile);
    return INVALID_HANDLE_VALUE;
}
/**************************************************/
/*   5.10 ���ߺ��� (���� SS HeuristicAnalyzer.cpp    */
/*        ��Ѻ�����)                               */
/**************************************************/

/* �������Ƿ���ɵ��� (�� 5.1 �����, ���� SS IsSuspiciousImport) */

BOOLEAN
IocScan_ContainsPe(
    _In_ const BYTE* Data,
    _In_ ULONG       Size
    )
{
    ULONG i;
    if (!Data || Size < 2) return FALSE;
    for (i = 0; i + sizeof(IMAGE_DOS_HEADER) <= Size; i++) {
        if (Data[i] == 'M' && Data[i + 1] == 'Z') {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)(Data + i);
            ULONG off = (ULONG)dos->e_lfanew;
            if (i + off + 4 <= Size) {
                DWORD sig = *(const DWORD*)(Data + i + off);
                if (sig == IMAGE_NT_SIGNATURE) return TRUE;
            }
        }
    }
    return FALSE;
}

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

/* �ű�ָʾ�����: BOM/Shebang/�ؼ��� (���� SS AnalyzeScript L1652-1756) */

#define FILE_HEADER_MAX_SIZE   (4 * 1024)

/* 读取文件头，最大支持4KB，Header缓冲区由调用者释放 */
NTSTATUS
CoReadFileHeader(
    _In_ PCWSTR FilePath,
    _Out_opt_ PSIZE_T FileSize,
    _Outptr_ PBYTE* Header,
    _Out_ PSIZE_T HeaderSize
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hFile;
    SIZE_T fileSize = 0;
    ULONG readSize;
    DWORD bytesRead = 0;
    PBYTE buf;
    
    if (!CoCheckStringValidity(FilePath) || !Header || !HeaderSize) {
        return STATUS_INVALID_PARAMETER;
    }
    if (FileSize) *FileSize = 0;
    *Header = NULL;
    *HeaderSize = 0;

    hFile = CoOpenFileForSequentialRead(FilePath, &fileSize);
    if (hFile == INVALID_HANDLE_VALUE) return STATUS_OBJECT_PATH_INVALID;
    if (fileSize == 0) { status = STATUS_FILE_INVALID; goto Cleanup; };
    
    readSize = min(FILE_HEADER_MAX_SIZE, fileSize);
    buf = (PBYTE)malloc(readSize);
    if (!buf) { status = STATUS_NO_MEMORY; goto Cleanup; }

    if (!ReadFile(hFile, buf, readSize, &bytesRead, NULL) || bytesRead == 0) {
        free(buf);
        status = STATUS_FILE_NOT_AVAILABLE;
        goto Cleanup;
    }

    *Header = buf;
    *HeaderSize = bytesRead;
    if (FileSize) *FileSize = fileSize;

Cleanup:
    CloseHandle(hFile);
    return status;
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

    if (!CoReadFileHeader(FilePath, &fileSize, &header, &headerLen)) {
        Info->FileSize = fileSize;
        return STATUS_UNSUCCESSFUL;   /* ����·������ƭ�ж� */
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
IocScan_DetectFileType(
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

    result = IocScan_DetectFileType(header, headerSize);

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

