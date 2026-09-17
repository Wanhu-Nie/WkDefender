/**************************************************/
/*  WkDefender Agent — 熵计算 / 文件 I/O 工具层      */
/*                                                  */
/*  本文件仅保留:                                   */
/*   - 熵计算 (CoEntropy*)                          */
/*   - 文件顺序读取 (CoOpenFileForSequentialRead)   */
/*   - CoReadFileHeader (文件头缓冲读取)            */
/*   - IocScan_ContainsPe (PE 签名探测)            */
/*                                                  */
/*  文件类型判定/魔数/Disambiguate 等已迁移至        */
/*  FileSystem/FileAnalyzer.c (2026-09-14)。        */
/*  多算法哈希已迁移至 BCrypUtils (2026-09-08)。    */
/**************************************************/

#include "FileUtils.h"
#include "Utils.h"     /* CoCheckStringValidity */
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

