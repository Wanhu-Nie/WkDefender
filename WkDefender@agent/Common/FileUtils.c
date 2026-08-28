/**************************************************/
/*  WkDefender Agent - �ļ�/�ֽ�/��ϣ���߲�ʵ��     */
/*                                                  */
/*  2026-08-15 �� IOC/IocScanner.c ��Ǩ:            */
/*  �ļ� I/O + ���㷨��ϣ (SHA256/MD5/CTPH/TLSH)     */
/*  + �ļ�����ʶ�� (ħ��/����/����/��չ��/MIME)��    */
/*  ������ FileUtils.h��                            */
/**************************************************/

#include "FileUtils.h"
#include "../Common/Utils.h"     /* UtHexEncode/UtHexDecode/UtBase64Encode */
#include "../IOC/PEAnalyzer/PeAnalyzer.h"
#include "../IOC/IocScanner.h"   /* IocScan_AnalyzeScript/ReadFileHeader ���� */  /* CtphHashNormalized ������ת�� WpeParseBufferContext */
#include <windows.h>
#include <math.h>
#include <bcrypt.h>
#include <intrin.h>      /* __cpuidex (Ӳ�����ټ��) */
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "bcrypt.lib")

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

/* ˳������� (4KB) */
#define WKD_HASH_BUFFER_SIZE     (1ULL << 12)

/* ����ϣ�ļ���С (4GB, ���� SS HashUtils MAX_HASH_FILE_SIZE) */
#define WKD_MAX_HASH_FILE_SIZE   (4ULL * 1024 * 1024 * 1024)

typedef struct _WKD_HASH_SLOT {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_HASH_HANDLE hHash;
    ULONG  AlgBit;     /* WKD_HASH_ALG λ */
    ULONG  HashLen;
} WKD_HASH_SLOT, * PWKD_HASH_SLOT;

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

/* �������㷨 BCrypt ��ϣ��� (HashLen �� provider Ȩ��Ϊ׼, ���� SS ensureProviderReady) */

static NTSTATUS
CopCreateAlgorithmSlot(
    _In_ ULONG AlgBit,
    _Out_ PWKD_HASH_SLOT Slot
    )
{
    NTSTATUS status;
    LPCWSTR algName = NULL;
    ULONG cb = 0;

    if (!Slot) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Slot, sizeof(WKD_HASH_SLOT));
    Slot->AlgBit = AlgBit;

    switch (AlgBit) {
    case WkdHash_MD5:       algName = BCRYPT_MD5_ALGORITHM;         break;
    case WkdHash_SHA1:      algName = BCRYPT_SHA1_ALGORITHM;        break;
    case WkdHash_SHA256:    algName = BCRYPT_SHA256_ALGORITHM;      break;
    case WkdHash_SHA512:    algName = BCRYPT_SHA512_ALGORITHM;      break;
    case WkdHash_SHA3_256:  algName = BCRYPT_SHA3_256_ALGORITHM;    break;
    case WkdHash_SHA3_512:  algName = BCRYPT_SHA3_512_ALGORITHM;    break;
    default: return STATUS_NOT_SUPPORTED;
    }

    status = BCryptOpenAlgorithmProvider(&Slot->hAlg, algName, NULL, 0);
    if (!NT_SUCCESS(status)) return status;   /* SHA3 �ھ�ϵͳʧ�� �� ��λ������, ������ */

    status = BCryptGetProperty(Slot->hAlg, BCRYPT_HASH_LENGTH,
                               (PUCHAR)&Slot->HashLen, sizeof(Slot->HashLen), &cb, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    status = BCryptCreateHash(Slot->hAlg, &Slot->hHash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    return STATUS_SUCCESS;

Cleanup:
    BCryptCloseAlgorithmProvider(Slot->hAlg, 0);
    Slot->hAlg = NULL;
    return status;
}

/* ����������������ϣ���, ���سɹ��� */
static ULONG
CopCreateMultipleAlgorithmSlots(
    _In_ ULONG HashMask,
    _Out_ PWKD_HASH_SLOT Slots,
    _In_ ULONG MaxSlots
    )
{
    ULONG count = 0;
    static const ULONG algBits[] = {
        WkdHash_MD5, WkdHash_SHA1, WkdHash_SHA256,
        WkdHash_SHA512, WkdHash_SHA3_256, WkdHash_SHA3_512
    };
    
    if (!Slots || MaxSlots == 0)  return 0;

    for (ULONG i = 0; i < RTL_NUMBER_OF(algBits) && count < MaxSlots; i++) {
        if (HashMask & algBits[i]) {
            if (NT_SUCCESS(CopCreateAlgorithmSlot(algBits[i], &Slots[count]))) {
                count++;
            }
        }
    }
    return count;
}

/* ���� FinishHash ������ WKD_FILE_HASH_SET ��Ӧ�ֶ� */
static VOID
CopFinishAlgorithmSlots(
    _In_ PWKD_HASH_SLOT Slots,
    _In_ ULONG Count,
    _Inout_ PWKD_FILE_HASH_SET FileHashes
    )
{
    BYTE digest[64];

    if (!Slots || Count == 0 || !FileHashes) return;

    for (ULONG i = 0; i < Count; i++) {
        NTSTATUS status = BCryptFinishHash(Slots[i].hHash, digest, Slots[i].HashLen, 0);
        if (!NT_SUCCESS(status)) continue;

        switch (Slots[i].AlgBit) {
        case WkdHash_MD5:
            RtlCopyMemory(FileHashes->Md5, digest, 16);        
            FileHashes->Md5Valid = TRUE; 
            break;
        case WkdHash_SHA1:      
            RtlCopyMemory(FileHashes->Sha1, digest, 20);       
            FileHashes->Sha1Valid = TRUE; 
            break;
        case WkdHash_SHA256:    
            RtlCopyMemory(FileHashes->Sha256, digest, 32);     
            FileHashes->Sha256Valid = TRUE; 
            break;                            
        case WkdHash_SHA512:    
            RtlCopyMemory(FileHashes->Sha512, digest, 64);     
            FileHashes->Sha512Valid = TRUE; 
            break;
        case WkdHash_SHA3_256:  
            RtlCopyMemory(FileHashes->Sha3_256, digest, 32);   
            FileHashes->Sha3_256Valid = TRUE; 
            break;
        case WkdHash_SHA3_512:  
            RtlCopyMemory(FileHashes->Sha3_512, digest, 64);   
            FileHashes->Sha3_512Valid = TRUE; 
            break;
        default: break;
        }
    }
}

/* ������ϣ��� */
static VOID
CopCleanupAlgorithmSlots(
    _In_ PWKD_HASH_SLOT Slots,
    _In_ ULONG Count
    )
{
    if (!Slots || Count == 0)  return;

    for (ULONG i = 0; i < Count; i++) {
        if (Slots[i].hHash) BCryptDestroyHash(Slots[i].hHash);
        if (Slots[i].hAlg) BCryptCloseAlgorithmProvider(Slots[i].hAlg, 0);
    }
}

/* �ļ����������ϣ: һ�ζ��ļ���ι N �� BCrypt ��� */

static
NTSTATUS
CopComputeMultipleFileHashes(
    _In_ PCWSTR FilePath,
    _In_ ULONG HashMask,
    _Out_ PWKD_FILE_HASH_SET FileHashSet
    )
/*++
Routine Description:
    ���ļ���������ָ���Ķ��㷨��ϣ���������: һ��˳���ѭ����ι����
    �����㷨�� BCrypt ��� (���� SS FileHasher single-pass), �� 4GB ˫������
    (Ԥ�� + ��ѭ���ۼ�, �� FILE_SHARE_WRITE ���ļ���д��)��

Arguments:
    Path - �ļ�·����
    HashMask - WKD_HASH_ALG λ���롣
    Out  - ������㷨��ϣ����

Return Value:
    TRUE = ����һ���㷨�ɹ�; ʧ�� FALSE (Out->HasErrors ��λ)��
--*/
{
    NTSTATUS status;
    WKD_HASH_SLOT slots[6];
    HANDLE hFile;
    PBYTE buffer = NULL;
    ULONG slotCount = 0;
    DWORD read = 0, totalRead = 0;

    if (!FilePath || !FileHashSet) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(FileHashSet, sizeof(WKD_FILE_HASH_SET));

    hFile = CoOpenFileForSequentialRead(FilePath, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        FileHashSet->HasErrors = TRUE;
        FileHashSet->ErrorCode = ERROR_FILE_INVALID;
        return STATUS_OPEN_FAILED;
    }

    slotCount = CopCreateMultipleAlgorithmSlots(HashMask, slots, RTL_NUMBER_OF(slots));
    if (slotCount == 0) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    buffer = (PBYTE)malloc(WKD_HASH_BUFFER_SIZE);
    if (!buffer) {
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }
    
    while (ReadFile(hFile, buffer, WKD_HASH_BUFFER_SIZE, &read, NULL) && read > 0) {
        totalRead += read;
        if (totalRead > WKD_MAX_HASH_FILE_SIZE) {       /* �������� */
            FileHashSet->HasErrors = TRUE;
            FileHashSet->ErrorCode = ERROR_FILE_TOO_LARGE;
            goto Cleanup;
        }
        for (ULONG i = 0; i < slotCount; i++) {
            if (!NT_SUCCESS(BCryptHashData(slots[i].hHash, buffer, read, 0))) {
                goto Cleanup;
            }
        }
    }

    CopFinishAlgorithmSlots(slots, slotCount, FileHashSet);
    status = STATUS_SUCCESS;

Cleanup:
    if (buffer) free(buffer);
    CopCleanupAlgorithmSlots(slots, slotCount);
    CloseHandle(hFile);
    return status;
}

/* ���������������ϣ */

BOOLEAN
IocScan_HashBufferMulti(
    _In_  const BYTE*      Buf,
    _In_  ULONG            Size,
    _In_  ULONG            Mask,
    _Out_ PWKD_FILE_HASH_SET Out
    )
{
    WKD_HASH_SLOT slots[6];
    ULONG slotCount = 0;
    BOOLEAN ok = FALSE;
    ULONG i;

    if (!Buf || !Out || Size == 0) return FALSE;
    RtlZeroMemory(Out, sizeof(*Out));

    slotCount = CopCreateMultipleAlgorithmSlots(Mask, slots, 6);
    if (slotCount == 0) return FALSE;

    for (i = 0; i < slotCount; i++) {
        if (BCryptHashData(slots[i].hHash, (PUCHAR)Buf, Size, 0) < 0) {
            goto cleanup;
        }
    }

    CopFinishAlgorithmSlots(slots, slotCount, Out);
    ok = TRUE;

cleanup:
    CopCleanupAlgorithmSlots(slots, slotCount);
    return ok;
}

/**************************************************/
/*               1. ��ϣ��ѯ                        */
/**************************************************/

/*++
 * CoComputeFileSha256
 *   �����ļ��� SHA256������ PS HashUtils::ComputeFile����
 *   ����װ: �� CopComputeMultipleFileHashes �����������, �Զ����
 *   4GB ���� / reparse �ܾ� / share READ|WRITE|DELETE / SEQUENTIAL_SCAN ������
 *--*/

NTSTATUS
CoComputeFileSha256(
    _In_ PCWSTR FilePath,
    _Out_ PDEF_SHA256_HASH Hash
    )
{
    WKD_FILE_HASH_SET hashes;

    if (!FilePath || !Hash) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Hash, sizeof(DEF_SHA256_HASH));

    if (!NT_SUCCESS(CopComputeMultipleFileHashes(FilePath, WkdHash_SHA256, &hashes))) return FALSE;
    if (!hashes.Sha256Valid) return FALSE;
    memcpy(Hash->Data, hashes.Sha256, DEF_SHA256_SIZE);
    return STATUS_SUCCESS;
}

/*++
 * IocScan_ComputeBufferSha256
 *   �����ڴ滺���� SHA256������ PS HashUtils::Compute����
 *   ����װ: �� IocScan_HashBufferMulti ����������ġ�
 *--*/

BOOLEAN
IocScan_ComputeBufferSha256(
    _In_  const BYTE*      Buffer,
    _In_  ULONG            Size,
    _Out_ PDEF_SHA256_HASH Hash
    )
{
    WKD_FILE_HASH_SET hashes;

    if (!Buffer || !Hash || Size == 0) return FALSE;

    if (!IocScan_HashBufferMulti(Buffer, Size, WkdHash_SHA256, &hashes)) return FALSE;
    if (!hashes.Sha256Valid) return FALSE;
    memcpy(Hash->Data, hashes.Sha256, DEF_SHA256_SIZE);
    return TRUE;
}


/*++ �ļ� SHA256 (Ǩ��������λ: ���÷�����ԭ IocScanner.c ����, 2026-08-16) --*/
BOOLEAN
IocScanner_ComputeFileSha256(
    _In_  PCWSTR           FilePath,
    _Out_ PDEF_SHA256_HASH Hash
    )
{
    return NT_SUCCESS(CoComputeFileSha256(FilePath, Hash));
}


BOOLEAN
IocScan_ComputeMd5Hex(
    _In_  const BYTE* Data,
    _In_  ULONG       Size,
    _Out_ CHAR*       HexOut
    )
/*++
Routine Description:
    ���� MD5 ʮ�����ƴ� (Сд, 33 �ֽں���β 0)��BCrypt ʵ��, ����
    IocScan_ComputeBufferSha256 ��񡣹� ImpHash ���㡣

Arguments:
    Data   - ���뻺�塣
    Size   - ���볤�ȡ�
    HexOut - ��� 33 �ֽڻ��塣

Return Value:
    TRUE = �ɹ���
--*/
{
    static const CHAR hexdig[] = "0123456789abcdef";
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BYTE digest[16];
    NTSTATUS status;
    BOOLEAN ok = FALSE;
    ULONG i;

    if (!Data || !HexOut || Size == 0) return FALSE;
    HexOut[0] = 0;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM, NULL, 0);
    if (status >= 0) {
        status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
        if (status >= 0) {
            status = BCryptHashData(hHash, Data, Size, 0);
            if (status >= 0) {
                status = BCryptFinishHash(hHash, digest, sizeof(digest), 0);
                if (status >= 0) {
                    for (i = 0; i < sizeof(digest); i++) {
                        HexOut[i * 2]     = hexdig[(digest[i] >> 4) & 0xF];
                        HexOut[i * 2 + 1] = hexdig[digest[i] & 0xF];
                    }
                    HexOut[32] = 0;
                    ok = TRUE;
                }
            }
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    return ok;
}

/**************************************************/
/*               �������                           */
/**************************************************/

/* -------------------------------------------------- */
/* 5.5 �ַ�������                                      */
/* -------------------------------------------------- */

/* �����ַ����������� (���� SS AnalyzeExtractedStringImpl, ��10 ת 0-1000) */

/* CTPH ���� (���� SS DigestGenerator.hpp/RollingHash.hpp; �� CTPH ������ IocScanner.c Ǩ��) */
#define WKD_CTPH_MIN_BLOCK        3
#define WKD_CTPH_SIG_MAX          64      /* kDigestComponentLength */
#define WKD_CTPH_SIG2_MAX         32      /* kHalfDigestLength */
#define WKD_CTPH_WINDOW           7       /* kRollingWindowSize */
#define WKD_CTPH_FNV_OFFSET       0x811c9dc5u
#define WKD_CTPH_FNV_PRIME        0x01000193u
#define WKD_CTPH_MAX_HASHABLE     (200ULL * 1024 * 1024)   /* kMaxHashableSize */
#define WKD_CTPH_MAX_DIGEST_LEN   200     /* kMaxDigestStringLength */

static const CHAR g_IocCtphBase64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

typedef struct _WKD_CTPH_ROLLER {
    BYTE  window[WKD_CTPH_WINDOW];
    ULONG h1, h2, h3;
    ULONG pos;
} WKD_CTPH_ROLLER, *PWKD_CTPH_ROLLER;

typedef struct _WKD_CTPH_CHUNK {
    ULONG state;
    ULONG initialState;
} WKD_CTPH_CHUNK, *PWKD_CTPH_CHUNK;

/* ������ϣ: ������ (h1 �ֽں� / h2 ��Ȩλ�ú� / h3 ��λ���), ���� 7
   (���� SS RollingHash::Update) */
static ULONG
IocScan_CtphRollerUpdate(
    _Inout_ PWKD_CTPH_ROLLER R,
    _In_    BYTE             Byte
    )
{
    R->h2 -= R->h1;
    R->h2 += WKD_CTPH_WINDOW * (ULONG)Byte;

    R->h1 += (ULONG)Byte;
    R->h1 -= (ULONG)R->window[R->pos];

    R->window[R->pos] = Byte;
    R->pos = (R->pos + 1) % WKD_CTPH_WINDOW;

    R->h3 = (R->h3 << 5) & 0xFFFFFFFF;
    R->h3 ^= (ULONG)Byte;

    return R->h1 + R->h2 + R->h3;
}

static VOID
IocScan_CtphRollerReset(
    _Out_ PWKD_CTPH_ROLLER R
    )
{
    RtlZeroMemory(R->window, sizeof(R->window));
    R->h1 = 0; R->h2 = 0; R->h3 = 0;
    R->pos = 0;
}

/* FNV-1a ���ϣ (���� SS ChunkHash) */
static VOID
IocScan_CtphChunkUpdate(
    _Inout_ PWKD_CTPH_CHUNK C,
    _In_    BYTE            Byte
    )
{
    C->state ^= (ULONG)Byte;
    C->state *= WKD_CTPH_FNV_PRIME;
}

static VOID
IocScan_CtphChunkReset(
    _Inout_ PWKD_CTPH_CHUNK C
    )
{
    C->state = C->initialState;
}

/* ѡ���С: 3��2^n, ʹ blockSize��64 �� ���볤 (���� SS SelectBlockSize) */
static ULONG
IocScan_CtphSelectBlockSize(
    _In_ ULONGLONG InputLength
    )
{
    ULONG blockSize = WKD_CTPH_MIN_BLOCK;

    while ((ULONGLONG)blockSize * WKD_CTPH_SIG_MAX < InputLength) {
        blockSize *= 2;
        if (blockSize >= 0x80000000u) break;    /* ������� */
    }
    return blockSize;
}

/* ����˫ǩ������ (���� SS GenerateSignatures, �����͸��� + �ֽڼ�����β) */
static VOID
IocScan_CtphGenerateSignatures(
    _In_  const BYTE* Data,
    _In_  SIZE_T      Size,
    _In_  ULONG       BlockSize,
    _Out_ PCHAR       Sig1,      /* ���� �� WKD_CTPH_SIG_MAX+1 */
    _Out_ PULONG      Sig1Len,
    _Out_ PCHAR       Sig2,      /* ���� �� WKD_CTPH_SIG2_MAX+1 */
    _Out_ PULONG      Sig2Len,
    _In_  ULONG       ChunkInitState
    )
{
    WKD_CTPH_ROLLER roller;
    WKD_CTPH_CHUNK chunk1, chunk2;
    ULONG c1 = 0, c2 = 0;
    ULONGLONG doubleBlockSize;
    SIZE_T i;

    IocScan_CtphRollerReset(&roller);
    chunk1.state = ChunkInitState; chunk1.initialState = ChunkInitState;
    chunk2.state = ChunkInitState; chunk2.initialState = ChunkInitState;

    *Sig1Len = 0;
    *Sig2Len = 0;
    doubleBlockSize = (ULONGLONG)BlockSize * 2;

    for (i = 0; i < Size; i++) {
        BYTE byte = Data[i];
        ULONG rollVal = IocScan_CtphRollerUpdate(&roller, byte);

        IocScan_CtphChunkUpdate(&chunk1, byte);
        c1++;
        IocScan_CtphChunkUpdate(&chunk2, byte);
        c2++;

        /* ��ǩ��: �����ڿ��С���� (���� SS L138-150) */
        if ((rollVal % BlockSize) == (BlockSize - 1)) {
            Sig1[*Sig1Len] = g_IocCtphBase64[chunk1.state % 64];
            if (*Sig1Len < WKD_CTPH_SIG_MAX - 1) {
                IocScan_CtphChunkReset(&chunk1);
                c1 = 0;
                (*Sig1Len)++;
            }
            /* ����: Sig1Len ͣ�� SIG_MAX-1, �۷�������, c1 ������ (��ȷ��β) */
        }

        /* ��ǩ��: ������ 2�� ���С (���� SS L153-161) */
        if (((ULONGLONG)rollVal % doubleBlockSize) == (doubleBlockSize - 1)) {
            Sig2[*Sig2Len] = g_IocCtphBase64[chunk2.state % 64];
            if (*Sig2Len < WKD_CTPH_SIG2_MAX - 1) {
                IocScan_CtphChunkReset(&chunk2);
                c2 = 0;
                (*Sig2Len)++;
            }
        }
    }

    /* ��ʽ��β: δ���ֽڼ��� > 0 �򲹷�β���� (���� SS L164-179, BUG-6 �޸�) */
    if (c1 > 0 && *Sig1Len < WKD_CTPH_SIG_MAX) {
        Sig1[*Sig1Len] = g_IocCtphBase64[chunk1.state % 64];
        (*Sig1Len)++;
    }
    if (c2 > 0 && *Sig2Len < WKD_CTPH_SIG2_MAX) {
        Sig2[*Sig2Len] = g_IocCtphBase64[chunk2.state % 64];
        (*Sig2Len)++;
    }

    Sig1[*Sig1Len] = '\0';
    Sig2[*Sig2Len] = '\0';
}

/* ժҪ����: ѡ�� �� ˫ǩ�� �� ϡ����ɨ(sig1<32 ����) �� ��ʽ�� (���� SS BuildDigest) */
static INT
IocScan_CtphBuildDigest(
    _In_  const BYTE* Data,
    _In_  SIZE_T      Size,
    _Out_ PCHAR       Out,
    _In_  ULONG       OutCch
    )
{
    ULONG blockSize;
    CHAR sig1[WKD_CTPH_SIG_MAX + 1];
    CHAR sig2[WKD_CTPH_SIG2_MAX + 1];
    ULONG sig1Len = 0, sig2Len = 0;
    INT written;

    if (!Data || !Out) return -1;
    if (Size == 0) return -1;                   /* ������ܾ� (���� SS BUG-5) */
    if (Size > WKD_CTPH_MAX_HASHABLE) return -1; /* DoS ���� */
    if (OutCch < 110) return -1;                /* 10+1+64+1+32+1 */

    blockSize = IocScan_CtphSelectBlockSize((ULONGLONG)Size);
    IocScan_CtphGenerateSignatures(Data, Size, blockSize,
        sig1, &sig1Len, sig2, &sig2Len, WKD_CTPH_FNV_OFFSET);

    while (blockSize > WKD_CTPH_MIN_BLOCK && sig1Len < WKD_CTPH_SIG_MAX / 2) {
        blockSize /= 2;
        memset(sig1, 0, sizeof(sig1));
        memset(sig2, 0, sizeof(sig2));
        sig1Len = 0;
        sig2Len = 0;
        IocScan_CtphGenerateSignatures(Data, Size, blockSize,
            sig1, &sig1Len, sig2, &sig2Len, WKD_CTPH_FNV_OFFSET);
    }

    written = _snprintf_s(Out, OutCch, _TRUNCATE, "%lu:%s:%s",
                          (unsigned long)blockSize, sig1, sig2);
    if (written < 0) return -1;
    return 0;
}

typedef struct _WKD_CTPH_PARSED {
    ULONG  blockSize;
    PCSTR  sig1;
    SIZE_T sig1Len;
    PCSTR  sig2;
    SIZE_T sig2Len;
} WKD_CTPH_PARSED, *PWKD_CTPH_PARSED;

/* ���� "blockSize:sig1:sig2" (�ϸ�ʮ����, �н�ɨ��, ���� SS ParseDigest L79-135) */
static BOOLEAN
IocScan_CtphParseDigest(
    _In_  PCSTR            Digest,
    _In_  SIZE_T           Len,
    _Out_ PWKD_CTPH_PARSED Out
    )
{
    SIZE_T colon1 = 0, colon2;
    SIZE_T i;
    ULONGLONG bs = 0;

    if (!Digest || !Out || Len == 0) return FALSE;

    while (colon1 < Len && Digest[colon1] != ':') colon1++;
    if (colon1 == 0 || colon1 >= Len) return FALSE;
    if (colon1 > 10) return FALSE;

    for (i = 0; i < colon1; i++) {
        if (Digest[i] < '0' || Digest[i] > '9') return FALSE;
        bs = bs * 10 + (ULONGLONG)(Digest[i] - '0');
    }
    if (bs == 0 || bs > 0xFFFFFFFFULL) return FALSE;
    Out->blockSize = (ULONG)bs;

    colon2 = colon1 + 1;
    while (colon2 < Len && Digest[colon2] != ':') colon2++;
    if (colon2 >= Len) return FALSE;

    Out->sig1 = Digest + colon1 + 1;
    Out->sig1Len = colon2 - colon1 - 1;
    Out->sig2 = Digest + colon2 + 1;
    Out->sig2Len = Len - colon2 - 1;

    if (Out->sig1Len == 0 || Out->sig2Len == 0 ||
        Out->sig1Len > WKD_CTPH_SIG_MAX || Out->sig2Len > WKD_CTPH_SIG_MAX) {
        return FALSE;
    }
    return TRUE;
}

/* ���� 4+ ��ͬ�ַ���Ϊ 3 (���� SS EliminateSequences L144-167) */
static VOID
IocScan_CtphEliminateSequences(
    _In_  PCSTR  Input,
    _In_  SIZE_T InLen,
    _Out_ PCHAR  Out,
    _In_  SIZE_T OutCap,
    _Out_ PSIZE_T OutLen
    )
{
    SIZE_T i, o = 0;

    if (!Out || OutCap == 0) { if (OutLen) *OutLen = 0; return; }

    if (InLen <= 3) {
        for (i = 0; i < InLen && o + 1 < OutCap; i++) Out[o++] = Input[i];
        Out[o] = 0;
        if (OutLen) *OutLen = o;
        return;
    }

    for (i = 0; i < 3 && i < InLen && o + 1 < OutCap; i++) {
        Out[o++] = Input[i];
    }
    for (i = 3; i < InLen && o + 1 < OutCap; i++) {
        if (Input[i] != Input[i - 1] ||
            Input[i] != Input[i - 2] ||
            Input[i] != Input[i - 3]) {
            Out[o++] = Input[i];
        }
    }
    Out[o] = 0;
    if (OutLen) *OutLen = o;
}

/* �����Ӵ� ��7 �ֽ�: ������ϣ���� + memcmp ȷ�� (���� SS HasCommonSubstring L185-236) */
static BOOLEAN
IocScan_CtphHasCommonSubstring(
    _In_  PCSTR  S1,
    _In_  SIZE_T S1Len,
    _In_  PCSTR  S2,
    _In_  SIZE_T S2Len
    )
{
    WKD_CTPH_ROLLER roller;
    ULONG hashes[WKD_CTPH_SIG_MAX];
    SIZE_T i, j;

    if (S1Len < WKD_CTPH_WINDOW || S2Len < WKD_CTPH_WINDOW) return FALSE;
    if (S1Len > WKD_CTPH_SIG_MAX || S2Len > WKD_CTPH_SIG_MAX) return FALSE;

    IocScan_CtphRollerReset(&roller);
    for (i = 0; i < S1Len; i++) {
        hashes[i] = IocScan_CtphRollerUpdate(&roller, (BYTE)S1[i]);
    }

    IocScan_CtphRollerReset(&roller);
    for (i = 0; i < S2Len; i++) {
        ULONG h = IocScan_CtphRollerUpdate(&roller, (BYTE)S2[i]);
        if (i < WKD_CTPH_WINDOW - 1) continue;

        for (j = WKD_CTPH_WINDOW - 1; j < S1Len; j++) {
            if (hashes[j] == h) {
                SIZE_T s2Start = i - (WKD_CTPH_WINDOW - 1);
                SIZE_T s1Start = j - (WKD_CTPH_WINDOW - 1);
                if (s2Start + WKD_CTPH_WINDOW <= S2Len &&
                    s1Start + WKD_CTPH_WINDOW <= S1Len &&
                    memcmp(S1 + s1Start, S2 + s2Start, WKD_CTPH_WINDOW) == 0) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

/* ��Ȩ�༭����: ����/ɾ��=1, �滻=3, ���� DP (���� SS WeightedEditDistance L74-119) */
static ULONG
IocScan_CtphWeightedEditDistance(
    _In_ PCSTR S1,
    _In_ ULONG Len1,
    _In_ PCSTR S2,
    _In_ ULONG Len2
    )
{
    ULONG prev[WKD_CTPH_SIG_MAX + 1];
    ULONG curr[WKD_CTPH_SIG_MAX + 1];
    ULONG i, j;

    if (Len1 > WKD_CTPH_SIG_MAX || Len2 > WKD_CTPH_SIG_MAX) return 0xFFFFFFFF;

    if (Len1 > Len2) {
        PCSTR ts = S1; S1 = S2; S2 = ts;
        ULONG tl = Len1; Len1 = Len2; Len2 = tl;
    }

    for (j = 0; j <= Len2; j++) prev[j] = j;
    for (i = 1; i <= Len1; i++) {
        curr[0] = i;
        for (j = 1; j <= Len2; j++) {
            if (S1[i - 1] == S2[j - 1]) {
                curr[j] = prev[j - 1];
            } else {
                ULONG ins = curr[j - 1] + 1;
                ULONG del = prev[j] + 1;
                ULONG sub = prev[j - 1] + 3;
                ULONG m = ins < del ? ins : del;
                curr[j] = m < sub ? m : sub;
            }
        }
        for (j = 0; j <= Len2; j++) prev[j] = curr[j];
    }
    return prev[Len2];
}

/* ǩ���� 0-100 �÷� (���� SS ScoreStrings L248-311) */
static ULONG
IocScan_CtphScoreStrings(
    _In_  PCSTR  S1,
    _In_  SIZE_T S1Len,
    _In_  PCSTR  S2,
    _In_  SIZE_T S2Len,
    _In_  ULONG  BlockSize
    )
{
    ULONG len1 = (ULONG)S1Len;
    ULONG len2 = (ULONG)S2Len;
    ULONG editDist;
    ULONG score, minLen;
    ULONGLONG capU64;
    ULONG cap;

    if (len1 > WKD_CTPH_SIG_MAX || len2 > WKD_CTPH_SIG_MAX) return 0;
    if (len1 == 0 || len2 == 0) return 0;

    if (!IocScan_CtphHasCommonSubstring(S1, S1Len, S2, S2Len)) return 0;

    editDist = IocScan_CtphWeightedEditDistance(S1, len1, S2, len2);
    if (editDist == 0xFFFFFFFF) return 0;

    score = (editDist * WKD_CTPH_SIG_MAX) / (len1 + len2);
    score = (100 * score) / WKD_CTPH_SIG_MAX;

    if (score >= 100) return 0;

    score = 100 - score;

    minLen = len1 < len2 ? len1 : len2;
    capU64 = ((ULONGLONG)BlockSize / WKD_CTPH_MIN_BLOCK) * (ULONGLONG)minLen;
    cap = (ULONG)(capU64 < 100 ? capU64 : 100);
    if (score > cap) score = cap;

    return score;
}

/* CTPH �Ƚ������: 0-100 ���ƶ�, -1=�Ƿ� (���� SS CompareDigests L315-382) */
static INT
IocScan_CtphCompare(
    _In_ PCSTR Digest1,
    _In_ PCSTR Digest2
    )
{
    WKD_CTPH_PARSED d1, d2;
    CHAR s1_1[WKD_CTPH_SIG_MAX + 1], s1_2[WKD_CTPH_SIG_MAX + 1];
    CHAR s2_1[WKD_CTPH_SIG_MAX + 1], s2_2[WKD_CTPH_SIG_MAX + 1];
    SIZE_T s1_1len, s1_2len, s2_1len, s2_2len;
    SIZE_T len1, len2;
    ULONGLONG b1, b2;
    ULONG score = 0;

    if (!Digest1 || !Digest2) return -1;

    len1 = strnlen(Digest1, WKD_CTPH_MAX_DIGEST_LEN + 1);
    len2 = strnlen(Digest2, WKD_CTPH_MAX_DIGEST_LEN + 1);
    if (len1 > WKD_CTPH_MAX_DIGEST_LEN || len2 > WKD_CTPH_MAX_DIGEST_LEN) return -1;

    if (!IocScan_CtphParseDigest(Digest1, len1, &d1) ||
        !IocScan_CtphParseDigest(Digest2, len2, &d2)) return -1;

    /* ��ߴ����: ��Ȼ�һ�� 2�� (uint64 �����, ���� SS L348-352) */
    b1 = d1.blockSize;
    b2 = d2.blockSize;
    if (b1 != b2 && b1 != b2 * 2 && b2 != b1 * 2) return 0;

    IocScan_CtphEliminateSequences(d1.sig1, d1.sig1Len, s1_1, sizeof(s1_1), &s1_1len);
    IocScan_CtphEliminateSequences(d1.sig2, d1.sig2Len, s1_2, sizeof(s1_2), &s1_2len);
    IocScan_CtphEliminateSequences(d2.sig1, d2.sig1Len, s2_1, sizeof(s2_1), &s2_1len);
    IocScan_CtphEliminateSequences(d2.sig2, d2.sig2Len, s2_2, sizeof(s2_2), &s2_2len);

    if (b1 == b2) {
        ULONG score1 = IocScan_CtphScoreStrings(s1_1, s1_1len, s2_1, s2_1len, d1.blockSize);
        ULONG score2 = IocScan_CtphScoreStrings(s1_2, s1_2len, s2_2, s2_2len, d1.blockSize);
        score = score1 > score2 ? score1 : score2;
    } else if (b1 == b2 * 2) {
        score = IocScan_CtphScoreStrings(s1_1, s1_1len, s2_2, s2_2len, d1.blockSize);
    } else {
        score = IocScan_CtphScoreStrings(s1_2, s1_2len, s2_1, s2_1len, d2.blockSize);
    }

    return (INT)score;
}

/* CTPH ģ����ϣ���� (SS FuzzyHasher::HashBufferRaw, ��ʵ���滻�տ�)��
   0=�ɹ�, -1=ʧ�� (������/�� 200MB/���岻��); ʧ�� Out[0]=0�� */
static INT
IocScan_CalculateFuzzyHash(
    _In_ const BYTE* Data,
    _In_ ULONG       Size,
    _Out_ CHAR*      Out,
    _In_ ULONG       OutCch
    )
{
    INT rc;
    if (!Out || OutCch == 0) return -1;
    rc = IocScan_CtphBuildDigest(Data, (SIZE_T)Size, Out, OutCch);
    if (rc != 0) Out[0] = 0;
    return rc;
}

static VOID
IocScan_CalculateTlsh(
    _In_ const BYTE* Data,
    _In_ ULONG       Size,
    _Out_ CHAR*      Out,
    _In_ ULONG       OutCch
    )
{
    /* TLSH: SS FileHasher δ���� libtlsh (ComputeTLSHImpl ���ؿ�), ���ֿտ� */
    (void)Data; (void)Size;
    if (Out && OutCch) Out[0] = 0;
}

/* CTPH ���ƶȱȽ� (SS FuzzyHasher::Compare, ��ʵ���滻�ɱ�׼ Levenshtein)��
   0-100 ���ƶ�, -1=�Ƿ����롣 */
static INT
IocScan_CompareFuzzyHash(
    _In_ PCSTR Hash1,
    _In_ PCSTR Hash2
    )
{
    return IocScan_CtphCompare(Hash1, Hash2);
}

/* TLSH �򻯾��� (SS CompareTLSH: �ַ����� �� 0-256) */
static INT
IocScan_CompareTlsh(
    _In_ PCSTR Hash1,
    _In_ PCSTR Hash2
    )
{
    SIZE_T diffs = 0;
    SIZE_T len, i;

    if (!Hash1 || !Hash2 || !Hash1[0] || !Hash2[0]) return 256;
    if (strcmp(Hash1, Hash2) == 0) return 0;
    len = strlen(Hash1);
    if (strlen(Hash2) != len) return 256;
    if (len < 70) return 256;   /* ��С TLSH ���� */

    for (i = 0; i < len; i++) {
        if (Hash1[i] != Hash2[i]) diffs++;
    }
    return (INT)(((double)diffs / (double)len) * 256.0);
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

BOOLEAN
IocScanner_ComputeBufferSha256(
    _In_  const BYTE*      Buffer,
    _In_  ULONG            Size,
    _Out_ PDEF_SHA256_HASH Hash
    )
/*++
Routine Description:
    �����ڴ滺���� SHA256��BCrypt����������װ�����غɹ�ϣ/�ڴ�ȡ֤���á�

Arguments:
    Buffer - �ڴ滺������
    Size   - ��������С��
    Hash   - ��� 32 �ֽڹ�ϣ��

Return Value:
    TRUE = �ɹ���
--*/
{
    if (!Buffer || !Hash || Size == 0) return FALSE;
    return IocScan_ComputeBufferSha256(Buffer, Size, Hash);
}

/**************************************************/
/*       ���㷨��ϣ / CTPH ���� API (SS FileHasher) */
/**************************************************/

BOOLEAN
IocScanner_ComputeFileHashMulti(
    _In_  PCWSTR           FilePath,
    _In_  ULONG            Mask,
    _Out_ PWKD_FILE_HASH_SET Hashes
    )
/*++
Routine Description:
    ���㷨�ļ���ϣ���������, ���� SS FileHasher::ComputeAll �� single-pass
    ���壩��һ��˳�����ι����ָ���ĸ� BCrypt ���, �� 4GB/reparse ������

Arguments:
    FilePath - �ļ�����·����
    Mask     - WKD_HASH_ALG λ���롣
    Hashes   - ������㷨��ϣ����

Return Value:
    TRUE = ����һ���㷨�ɹ���
--*/
{
    if (!FilePath || !Hashes) return FALSE;
    return CopComputeMultipleFileHashes(FilePath, Mask, Hashes);
}

BOOLEAN
IocScanner_ComputeBufferHashMulti(
    _In_  const BYTE*      Buffer,
    _In_  ULONG            Size,
    _In_  ULONG            Mask,
    _Out_ PWKD_FILE_HASH_SET Hashes
    )
/*++
Routine Description:
    ���㷨�����ϣ���������, ���� SS FileHasher::ComputeAll(span)����

Arguments:
    Buffer - �ڴ滺������
    Size   - ��������С��
    Mask   - WKD_HASH_ALG λ���롣
    Hashes - ������㷨��ϣ����

Return Value:
    TRUE = ����һ���㷨�ɹ���
--*/
{
    if (!Buffer || !Hashes || Size == 0) return FALSE;
    return IocScan_HashBufferMulti(Buffer, Size, Mask, Hashes);
}

INT
IocScanner_ComputeFuzzyHash(
    _In_  const BYTE* Data,
    _In_  SIZE_T      Size,
    _Out_ CHAR*       Out,
    _In_  ULONG       OutCch
    )
/*++
Routine Description:
    CTPH ģ����ϣ���ɣ����� SS FuzzyHasher::HashBufferRaw�������
    "blockSize:sig1:sig2" ��ʽ��Out �� ��128 �ֽڡ�

Arguments:
    Data  - ���뻺�塣
    Size  - ���볤�ȡ�
    Out   - ��� digest ����
    OutCch - ���������

Return Value:
    0 = �ɹ�; -1 = ʧ�ܣ������� / �� 200MB / ���岻�㣩��
--*/
{
    if (!Data || !Out || OutCch == 0 || Size == 0) return -1;
    if (Size > WKD_CTPH_MAX_HASHABLE) return -1;
    return IocScan_CtphBuildDigest(Data, Size, Out, OutCch);
}

INT
IocScanner_CompareFuzzyHash(
    _In_ PCSTR Digest1,
    _In_ PCSTR Digest2
    )
/*++
Routine Description:
    CTPH ���ƶȱȽϣ����� SS FuzzyHasher::Compare����

Arguments:
    Digest1 - ��һ�� digest ����
    Digest2 - �ڶ��� digest ����

Return Value:
    0-100 ���ƶ�; -1 = �Ƿ����롣
--*/
{
    return IocScan_CtphCompare(Digest1, Digest2);
}


static BOOLEAN
IocScan_DetectHardwareAccel(
    _Out_ PBOOLEAN HasAesNi,
    _Out_ PBOOLEAN HasShaNi
    )
{
    int cpuInfo[4] = { 0 };

    if (!HasAesNi || !HasShaNi) return FALSE;
    *HasAesNi = FALSE;
    *HasShaNi = FALSE;

    __cpuidex(cpuInfo, 1, 0);
    *HasAesNi = (cpuInfo[2] & (1 << 25)) != 0;   /* ECX bit 25 */
    __cpuidex(cpuInfo, 7, 0);
    *HasShaNi = (cpuInfo[1] & (1 << 29)) != 0;   /* EBX bit 29 */
    return TRUE;
}

/* -- �� N �ֽ�ͷ�� SHA256 (SS FileHasher.cpp ComputeHeaderHashImpl L1253-1296) --
 * ������: �ĵ�ɨ�� CVE ǰ 1MB �ȶԵĲ����ź�; ��ǰ�����ѷ��� */
static BOOLEAN
IocScan_ComputeHeaderSha256(
    _In_  PCWSTR FilePath,
    _In_  ULONG  HeaderSize,
    _Out_ PCHAR  HexOut,        /* ��65 */
    _In_  ULONG  HexCch
    )
{
    BYTE* buf;
    BOOLEAN tooLarge = FALSE;
    HANDLE hFile;
    WKD_FILE_HASH_SET hashes;
    DWORD read = 0;
    BOOLEAN ok = FALSE;

    if (!FilePath || !HexOut || HexCch < 65) return FALSE;
    if (HeaderSize == 0 || HeaderSize > 16 * 1024 * 1024) return FALSE;   /* MAX_HEADER_READ_SIZE */

    buf = (BYTE*)malloc(HeaderSize);
    if (!buf) return FALSE;

    hFile = CoOpenFileForSequentialRead(FilePath, &tooLarge);
    if (hFile == INVALID_HANDLE_VALUE) { free(buf); return FALSE; }

    if (ReadFile(hFile, buf, HeaderSize, &read, NULL) && read > 0) {
        if (IocScan_HashBufferMulti(buf, read, WkdHash_SHA256, &hashes) && hashes.Sha256Valid) {
            ok = UtHexEncode(hashes.Sha256, 32, HexOut, HexCch, FALSE);
        }
    }
    CloseHandle(hFile);
    free(buf);
    return ok;
}

/* -- ���ֹ�ϣ�ۺ� (SS FileHasher.cpp ComputePartialHashes L1933-1951) ---------
 * ������: header �� + section ���� IocScan_ComputeSectionHashes (�� PE ����������)�� */
static VOID
IocScan_ComputePartialHashes(
    _In_  PCWSTR FilePath,
    _Out_ PCHAR  HeaderSha256Hex,   /* ��65 */
    _In_  ULONG  HexCch
    )
{
    if (!FilePath || !HeaderSha256Hex) return;
    HeaderSha256Hex[0] = 0;
    IocScan_ComputeHeaderSha256(FilePath, 4096, HeaderSha256Hex, HexCch);
}

/* -- Authentihash (SS FileHasher.cpp ComputeAuthentihashImpl L1038-1043) -------
 * ������: SS ��δʵ�� (���� PEParser ǩ��Ŀ¼����); wkd ֤����֤�� IocVerifySignature�� */
static BOOLEAN
IocScan_ComputeAuthentihash(
    _In_  PCWSTR FilePath,
    _Out_ PCHAR  AuthHex,           /* ��129 */
    _In_  ULONG  HexCch
    )
{
    (void)FilePath;
    if (!AuthHex || HexCch == 0) return FALSE;
    AuthHex[0] = 0;
    return FALSE;   /* δʵ��: �� PE [Ŀ¼]Authenticode ��ϣ������ */
}

/* -- ���ϣ����ȷ�Ƚ� (SS FileHasher.cpp CompareImpl L1158-1199) --------------
 * ������: wkd ��ϣƥ���� IocMatcher ��ȷ��ϣ�⸲��, �������㷨���ϱȽϡ� */
static BOOLEAN
IocScan_CompareHashSets(
    _In_  PCWKD_FILE_HASH_SET A,
    _In_  PCWKD_FILE_HASH_SET B,
    _Out_ PBOOLEAN Md5Match,
    _Out_ PBOOLEAN Sha1Match,
    _Out_ PBOOLEAN Sha256Match,
    _Out_ PBOOLEAN Sha512Match
    )
{
    if (!A || !B) return FALSE;
    if (Md5Match)    *Md5Match    = A->Md5Valid    && B->Md5Valid    && memcmp(A->Md5, B->Md5, 16) == 0;
    if (Sha1Match)   *Sha1Match   = A->Sha1Valid   && B->Sha1Valid   && memcmp(A->Sha1, B->Sha1, 20) == 0;
    if (Sha256Match) *Sha256Match = A->Sha256Valid && B->Sha256Valid && memcmp(A->Sha256, B->Sha256, 32) == 0;
    if (Sha512Match) *Sha512Match = A->Sha512Valid && B->Sha512Valid && memcmp(A->Sha512, B->Sha512, 64) == 0;
    return TRUE;
}

/* -- MatchesAny (SS FileHasher.cpp MatchesAny L1655-1666) ---------------------
 * ������: ����ģ���Ƚ�; ��ȷ��ϣƥ���� IocMatcher ���ǡ� */
static BOOLEAN
IocScan_MatchesAny(
    _In_ PCSTR  FuzzyDigest,
    _In_ PCSTR* Candidates,
    _In_ ULONG  Count
    )
{
    ULONG i;

    if (!FuzzyDigest || !Candidates) return FALSE;
    for (i = 0; i < Count; i++) {
        if (IocScan_CtphCompare(FuzzyDigest, Candidates[i]) >= 50) return TRUE;   /* IsSimilar ��ֵ */
    }
    return FALSE;
}

/* -- FindBestMatch (SS FileHasher.cpp FindBestMatch L1668-1688) ---------------
 * ������: ����ģ���Ƚ�; ����������ѷ�ȱʧ�� */
static INT
IocScan_FindBestMatch(
    _In_  PCSTR   FuzzyDigest,
    _In_  PCSTR*  Candidates,
    _In_  ULONG   Count,
    _In_  DOUBLE  MinSimilarity,
    _Out_opt_ PULONG BestIndex
    )
{
    DOUBLE bestSim = 0.0;
    ULONG best = (ULONG)-1;
    ULONG i;

    if (!FuzzyDigest || !Candidates || Count == 0) return -1;

    for (i = 0; i < Count; i++) {
        INT score = IocScan_CtphCompare(FuzzyDigest, Candidates[i]);
        if (score > (INT)bestSim) {
            bestSim = (DOUBLE)score;
            if (bestSim >= MinSimilarity) best = i;
        }
    }
    if (BestIndex) *BestIndex = best;
    return (best != (ULONG)-1) ? 0 : -1;
}

/* -- ValidateHashFormat (SS FileHasher.cpp ValidateHashFormat L1906-1931) ------
 * ������: �ͼ�ֵ��Ϲ��ߡ� */
static BOOLEAN
IocScan_ValidateHashFormat(
    _In_ PCSTR Hash,
    _In_ ULONG ExpectedLen     /* �ֽ���: 16/20/32/64 */
    )
{
    ULONG i;

    if (!Hash || ExpectedLen == 0) return FALSE;
    if (strlen(Hash) != ExpectedLen * 2) return FALSE;
    for (i = 0; i < ExpectedLen * 2; i++) {
        CHAR c = Hash[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return FALSE;
        }
    }
    return TRUE;
}

/* -- ToHexString/FromHexString (SS FileHasher.cpp L1868-1904) -----------------
 * ������: ί�� UtHexEncode/UtBase64Encode/UtHexDecode; �����ѷ��� */
typedef enum _WKD_HASH_FORMAT {
    WkdHashFormat_Hex = 0,
    WkdHashFormat_HexUpper,
    WkdHashFormat_Base64,
    WkdHashFormat_Raw
} WKD_HASH_FORMAT;

static BOOLEAN
IocScan_ToHexString(
    _In_  const BYTE*     Hash,
    _In_  ULONG           HashLen,
    _In_  WKD_HASH_FORMAT Format,
    _Out_ PCHAR           Out,
    _In_  ULONG           OutCch
    )
{
    if (!Hash || !Out) return FALSE;
    switch (Format) {
    case WkdHashFormat_Hex:       return UtHexEncode(Hash, HashLen, Out, OutCch, FALSE);
    case WkdHashFormat_HexUpper:  return UtHexEncode(Hash, HashLen, Out, OutCch, TRUE);
    case WkdHashFormat_Base64:    return UtBase64Encode(Hash, HashLen, Out, OutCch);
    case WkdHashFormat_Raw:
        if (OutCch < HashLen + 1) return FALSE;
        memcpy(Out, Hash, HashLen);
        Out[HashLen] = 0;
        return TRUE;
    default: return FALSE;
    }
}

static BOOLEAN
IocScan_FromHexString(
    _In_  PCSTR  Hex,
    _Out_ PBYTE  Out,
    _In_  ULONG  OutLen,
    _Out_opt_ PULONG Written
    )
{
    return UtHexDecode(Hex, Out, OutLen, Written);
}

/* -- ͳ�� (SS FileHasher.cpp InternalStats L273-330) --------------------------
 * ������: �����;; wkd ɨ��ͳ���� g_ScanManager �������ǡ� */
typedef struct _IOC_HASH_STATS {
    volatile LONG64 FilesHashed;
    volatile LONG64 BytesProcessed;
    volatile LONG64 Md5Computed;
    volatile LONG64 Sha1Computed;
    volatile LONG64 Sha256Computed;
    volatile LONG64 Sha512Computed;
    volatile LONG64 FuzzyComputed;
} IOC_HASH_STATS, *PIOC_HASH_STATS;

static IOC_HASH_STATS g_IocHashStats;

static VOID
IocScan_HashStatsReset(
    VOID
    )
{
    RtlZeroMemory(&g_IocHashStats, sizeof(g_IocHashStats));
}

static VOID
IocScan_HashStatsGet(
    _Out_ PIOC_HASH_STATS Out
    )
{
    if (Out) *Out = g_IocHashStats;   /* 64 λ��ԭ�Ӷ�, �����������; */
}

/* -- SelfTest (SS FileHasher.cpp SelfTest L1779-1822) -------------------------
 * ������: ��֪���� + CTPH �����Բ⡣ */
static BOOLEAN
IocScan_HashSelfTest(
    VOID
    )
{
    static const BYTE abc[] = "abc";
    WKD_FILE_HASH_SET hashes;
    CHAR hex[65];
    CHAR fa[128], fb[128];
    static const BYTE dataA[] =
        "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";
    BYTE dataB[sizeof(dataA)];
    INT score;

    /* ��֪����: MD5("abc") / SHA256("abc") */
    if (!IocScan_HashBufferMulti(abc, 3,
        WkdHash_MD5 | WkdHash_SHA256 | WkdHash_SHA512 | WkdHash_SHA3_256 | WkdHash_SHA3_512,
        &hashes)) {
        return FALSE;
    }
    if (hashes.Md5Valid) {
        if (!UtHexEncode(hashes.Md5, 16, hex, sizeof(hex), FALSE)) return FALSE;
        if (_stricmp(hex, "900150983cd24fb0d6963f7d28e17f72") != 0) return FALSE;
    }
    if (hashes.Sha256Valid) {
        if (!UtHexEncode(hashes.Sha256, 32, hex, sizeof(hex), FALSE)) return FALSE;
        if (_stricmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") != 0) return FALSE;
    }

    /* CTPH ����: �� 1 �ֽ� �� �����ƶ�; �Ա� �� 100 */
    memcpy(dataB, dataA, sizeof(dataA));
    dataB[5] = 'X';
    if (IocScan_CtphBuildDigest(dataA, sizeof(dataA) - 1, fa, sizeof(fa)) != 0) return FALSE;
    if (IocScan_CtphBuildDigest(dataB, sizeof(dataB) - 1, fb, sizeof(fb)) != 0) return FALSE;
    score = IocScan_CtphCompare(fa, fb);
    if (score <= 0) return FALSE;
    if (IocScan_CtphCompare(fa, fa) != 100) return FALSE;

    return TRUE;
}

/* -- �ڴ�ӳ����ļ���ϣ��֧ (SS FileHasher.cpp ComputeAllImpl L720-726) --------
 * ������: ��ǰ 1MB ��ʽ + 4 �����ۿɽ���; mmap �� CreateFileMapping/MapViewOfFile,
 * �����Ż�����ȫ��ɨ��ƿ�������ټ�� */
static BOOLEAN
IocScan_HashFileMapped(
    _In_  PCWSTR           Path,
    _In_  ULONG            Mask,
    _Out_ PWKD_FILE_HASH_SET Out
    )
{
    HANDLE hFile;
    HANDLE hMap;
    LPVOID base;
    BOOLEAN tooLarge = FALSE;
    BOOLEAN ok = FALSE;

    if (!Path || !Out) return FALSE;
    RtlZeroMemory(Out, sizeof(*Out));

    hFile = CoOpenFileForSequentialRead(Path, &tooLarge);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMap) {
        base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if (base) {
            LARGE_INTEGER size;
            if (GetFileSizeEx(hFile, &size) &&
                size.QuadPart > 0 && size.QuadPart <= (LONGLONG)WKD_CTPH_MAX_HASHABLE) {
                ok = IocScan_HashBufferMulti((const BYTE*)base, (ULONG)size.QuadPart, Mask, Out);
            }
            UnmapViewOfFile(base);
        }
        CloseHandle(hMap);
    }
    CloseHandle(hFile);
    return ok;
}

/* -- HashUtils ���� (SS HashUtils.cpp Equal/Fnv1a32/Fnv1a64/DigestSize) -------
 * ������: ����ʱ��Ƚ�/�Ǽ��ܹ�ϣ/�㷨�ߴ�ӳ��; wkd ƥ���� IocMatcher, �����ѷ��� */
static BOOLEAN
IocScan_Equal(
    _In_  const BYTE* A,
    _In_  const BYTE* B,
    _In_  SIZE_T      Len
    )
{
    volatile UCHAR acc = 0;
    SIZE_T i;

    if (Len == 0) return TRUE;
    if (!A || !B) return FALSE;
    for (i = 0; i < Len; i++) acc |= (UCHAR)(A[i] ^ B[i]);
    return acc == 0;
}

static ULONG
IocScan_Fnv1a32(
    _In_  const BYTE* Data,
    _In_  SIZE_T      Len
    )
{
    ULONG h = 2166136261u;      /* FNV-1a 32 λ offset basis */
    SIZE_T i;

    if (!Data || Len == 0) return h;
    for (i = 0; i < Len; i++) { h ^= Data[i]; h *= 16777619u; }
    return h;
}

static ULONGLONG
IocScan_Fnv1a64(
    _In_  const BYTE* Data,
    _In_  SIZE_T      Len
    )
{
    ULONGLONG h = 14695981039346656037ull;  /* FNV-1a 64 λ offset basis */
    SIZE_T i;

    if (!Data || Len == 0) return h;
    for (i = 0; i < Len; i++) { h ^= Data[i]; h *= 1099511628211ull; }
    return h;
}

static ULONG
IocScan_DigestSize(
    _In_ ULONG AlgBit
    )
{
    switch (AlgBit) {
    case WkdHash_MD5:     return 16;
    case WkdHash_SHA1:    return 20;
    case WkdHash_SHA256:  return 32;
    case WkdHash_SHA512:  return 64;
    case WkdHash_SHA3_256: return 32;
    case WkdHash_SHA3_512: return 64;
    default:              return 32;
    }
}

/* -- FileHashes::IsValid �ȼ� (SS FileHasher.cpp L336-340) ---------------------
 * ������: WKD_FILE_HASH_SET ��Ч���ж��� */
static BOOLEAN
IocScan_HashSetIsValid(
    _In_ PCWKD_FILE_HASH_SET H
    )
{
    if (!H) return FALSE;
    return H->Md5Valid || H->Sha1Valid || H->Sha256Valid ||
           H->Sha512Valid || H->Sha3_256Valid || H->Sha3_512Valid || H->FuzzyValid;
}

/* -- ���㷨 file ���� (SS FileHasher.cpp ComputeMD5/SHA1/SHA512/SHA3 L1529-1577)
 * ������: �� Multi ���ĵ� hex �����װ; wkd ���� SHA256 ���㷨�������ǡ� */
static BOOLEAN
IocScan_ComputeFileHashSingleHex(
    _In_  PCWSTR FilePath,
    _In_  ULONG  AlgBit,          /* ���� WKD_HASH_ALG λ (�����) */
    _Out_ PCHAR  HexOut,
    _In_  ULONG  HexCch
    )
{
    WKD_FILE_HASH_SET hashes;
    const BYTE* digest = NULL;
    ULONG len = 0;

    if (!FilePath || !HexOut) return FALSE;
    if (AlgBit != WkdHash_MD5 && AlgBit != WkdHash_SHA1 &&
        AlgBit != WkdHash_SHA512 && AlgBit != WkdHash_SHA3_256 &&
        AlgBit != WkdHash_SHA3_512) return FALSE;

    if (!CopComputeMultipleFileHashes(FilePath, AlgBit, &hashes)) return FALSE;

    switch (AlgBit) {
    case WkdHash_MD5:      if (!hashes.Md5Valid) return FALSE; digest = hashes.Md5; len = 16; break;
    case WkdHash_SHA1:     if (!hashes.Sha1Valid) return FALSE; digest = hashes.Sha1; len = 20; break;
    case WkdHash_SHA512:   if (!hashes.Sha512Valid) return FALSE; digest = hashes.Sha512; len = 64; break;
    case WkdHash_SHA3_256: if (!hashes.Sha3_256Valid) return FALSE; digest = hashes.Sha3_256; len = 32; break;
    case WkdHash_SHA3_512: if (!hashes.Sha3_512Valid) return FALSE; digest = hashes.Sha3_512; len = 64; break;
    default: return FALSE;
    }
    return UtHexEncode(digest, len, HexOut, HexCch, FALSE);
}

/* -- buffer MD5 ���� (SS FileHasher.cpp ComputeMD5(span) L1583-1591) ------------
 * ������: ���� ComputeBufferSha256 ֮�ⲹ MD5 buffer �档 */
static BOOLEAN
IocScan_ComputeBufferMd5Hex(
    _In_  const BYTE* Buffer,
    _In_  ULONG       Size,
    _Out_ PCHAR       HexOut,     /* ��33 */
    _In_  ULONG       HexCch
    )
{
    WKD_FILE_HASH_SET hashes;

    if (!Buffer || !HexOut || HexCch < 33 || Size == 0) return FALSE;
    if (!IocScan_HashBufferMulti(Buffer, Size, WkdHash_MD5, &hashes)) return FALSE;
    if (!hashes.Md5Valid) return FALSE;
    return UtHexEncode(hashes.Md5, 16, HexOut, HexCch, FALSE);
}

/* -- �ļ��� CTPH (SS FileHasher.cpp ComputeFuzzyHash L1559-1562) ---------------
 * ������: �����ļ�(��200MB) �� buffer CTPH; wkd ��ǰ�� buffer �浼���� */
static INT
IocScan_ComputeFuzzyHashFile(
    _In_  PCWSTR FilePath,
    _Out_ PCHAR  Out,
    _In_  ULONG  OutCch
    )
{
    HANDLE hFile;
    LARGE_INTEGER size;
    BYTE* data = NULL;
    DWORD read;
    BOOLEAN tooLarge = FALSE;
    INT rc = -1;

    if (!FilePath || !Out || OutCch < 128) return -1;

    hFile = CoOpenFileForSequentialRead(FilePath, &tooLarge);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    if (!GetFileSizeEx(hFile, &size) || size.QuadPart < 0 ||
        (ULONGLONG)size.QuadPart == 0 ||
        (ULONGLONG)size.QuadPart > WKD_CTPH_MAX_HASHABLE) {
        CloseHandle(hFile);
        return -1;
    }

    data = (BYTE*)malloc((size_t)size.QuadPart);
    if (data) {
        if (ReadFile(hFile, data, (DWORD)size.QuadPart, &read, NULL) &&
            read == (DWORD)size.QuadPart) {
            rc = IocScan_CtphBuildDigest(data, read, Out, OutCch);
        }
        free(data);
    }
    CloseHandle(hFile);
    return rc;
}

/* -- TLSH ���� (SS FileHasher.cpp ComputeTLSHDistanceImpl L1234-1247) ----------
 * ������: TLSH δ����, �㷵�������� (���� SS ��Ϊ)�� */
static ULONG
IocScan_ComputeTlshDistance(
    _In_ PCSTR Tlsh1,
    _In_ PCSTR Tlsh2
    )
{
    (void)Tlsh1; (void)Tlsh2;
    return 0xFFFFFFFF;
}

/* -- �汾/Ӳ����� (SS FileHasher.cpp GetVersionInfo/GetHardwareInfo L1824-1846)
 * ������: �ͼ�ֵ���, �� UI/��־δ��չʾ�� */
typedef struct _WKD_HASH_VERSION_INFO {
    CHAR    HasherVersion[32];
    CHAR    FuzzyHasherVersion[32];
    CHAR    TlshVersion[32];
} WKD_HASH_VERSION_INFO, *PWKD_HASH_VERSION_INFO;

static VOID
IocScan_GetHashVersionInfo(
    _Out_ PWKD_HASH_VERSION_INFO Out
    )
{
    if (!Out) return;
    strncpy_s(Out->HasherVersion, sizeof(Out->HasherVersion), "3.1.0", _TRUNCATE);
    strncpy_s(Out->FuzzyHasherVersion, sizeof(Out->FuzzyHasherVersion), "1.0.0", _TRUNCATE);
    strncpy_s(Out->TlshVersion, sizeof(Out->TlshVersion), "not-integrated", _TRUNCATE);
}

typedef struct _WKD_HASH_HARDWARE_INFO {
    BOOLEAN HasAesNi;
    BOOLEAN HasShaNi;
    BOOLEAN UseHardwareAccel;
} WKD_HASH_HARDWARE_INFO, *PWKD_HASH_HARDWARE_INFO;

static VOID
IocScan_GetHashHardwareInfo(
    _Out_ PWKD_HASH_HARDWARE_INFO Out
    )
{
    BOOLEAN aes = FALSE, sha = FALSE;

    if (!Out) return;
    IocScan_DetectHardwareAccel(&aes, &sha);
    Out->HasAesNi = aes;
    Out->HasShaNi = sha;
    Out->UseHardwareAccel = (aes || sha);
}

/* -- ���� CTPH (SS FuzzyHasher.hpp HashWithSalt / GenerateDigestWithSalt L241-262)
 * ������: �Ự�λ��� FNV ��ʼ̬, ������Ԥ����; ��ǰ�޿�Ự�Ƚ����� */
static INT
IocScan_CtphBuildDigestWithSalt(
    _In_  const BYTE* Data,
    _In_  SIZE_T      Size,
    _In_  ULONGLONG   Salt,
    _Out_ PCHAR       Out,
    _In_  ULONG       OutCch
    )
{
    ULONG saltedState;
    ULONG blockSize;
    CHAR sig1[WKD_CTPH_SIG_MAX + 1];
    CHAR sig2[WKD_CTPH_SIG2_MAX + 1];
    ULONG sig1Len = 0, sig2Len = 0;
    INT written;

    if (!Data || !Out) return -1;
    if (Size == 0 || Size > WKD_CTPH_MAX_HASHABLE) return -1;
    if (OutCch < 110) return -1;

    saltedState = WKD_CTPH_FNV_OFFSET
                ^ (ULONG)(Salt & 0xFFFFFFFFULL)
                ^ (ULONG)(Salt >> 32);

    blockSize = IocScan_CtphSelectBlockSize((ULONGLONG)Size);
    IocScan_CtphGenerateSignatures(Data, Size, blockSize, sig1, &sig1Len, sig2, &sig2Len, saltedState);

    while (blockSize > WKD_CTPH_MIN_BLOCK && sig1Len < WKD_CTPH_SIG_MAX / 2) {
        blockSize /= 2;
        memset(sig1, 0, sizeof(sig1));
        memset(sig2, 0, sizeof(sig2));
        sig1Len = 0;
        sig2Len = 0;
        IocScan_CtphGenerateSignatures(Data, Size, blockSize, sig1, &sig1Len, sig2, &sig2Len, saltedState);
    }

    written = _snprintf_s(Out, OutCch, _TRUNCATE, "%lu:%s:%s",
                          (unsigned long)blockSize, sig1, sig2);
    if (written < 0) return -1;
    return 0;
}

/* -- ���� digest ��� (SS FuzzyHasher.hpp IsSuspiciousDigest L296-312) ---------
 * ������: �ܾ���������/�Ƚ��ƹ������ digest�� */
static BOOLEAN
IocScan_IsSuspiciousDigest(
    _In_ PCSTR Digest
    )
{
    WKD_CTPH_PARSED d;
    SIZE_T len;
    SIZE_T i;
    BOOLEAN allSame1, allSame2;
    ULONG bs;

    if (!Digest) return FALSE;
    len = strnlen(Digest, WKD_CTPH_MAX_DIGEST_LEN + 1);
    if (len > WKD_CTPH_MAX_DIGEST_LEN) return FALSE;
    if (!IocScan_CtphParseDigest(Digest, len, &d)) return FALSE;

    /* 1. ȫͬ�ַ�ǩ�� (�� "AAAAAA") �� �������ļ����������ƶ� */
    allSame1 = (d.sig1Len > 0);
    for (i = 1; i < d.sig1Len; i++) {
        if (d.sig1[i] != d.sig1[0]) { allSame1 = FALSE; break; }
    }
    allSame2 = (d.sig2Len > 0);
    for (i = 1; i < d.sig2Len; i++) {
        if (d.sig2[i] != d.sig2[0]) { allSame2 = FALSE; break; }
    }
    if (allSame1 || allSame2) return TRUE;

    /* 2. ���С�� 3��2^n (�Ϸ� CTPH blockSize = 3 * 2^n) */
    if (d.blockSize < WKD_CTPH_MIN_BLOCK) return TRUE;
    if (d.blockSize % WKD_CTPH_MIN_BLOCK != 0) return TRUE;
    bs = d.blockSize / WKD_CTPH_MIN_BLOCK;
    while (bs > 1) {
        if (bs & 1) return TRUE;
        bs >>= 1;
    }

    /* 3. ǩ����� < 7 (HasCommonSubstring ���Ҫ��, �޷��÷�) */
    if (d.sig1Len < WKD_CTPH_WINDOW || d.sig2Len < WKD_CTPH_WINDOW) return TRUE;

    return FALSE;
}

/* -- ����ģ���Ƚ� (SS FuzzyHasher.hpp BatchCompare L326-329) -------------------
 * ������: Ŀ�� digest �Ժ�ѡ�������Ƚ�ȡ����; ����������ѷ�ȱʧ�� */
static INT
IocScan_BatchCompareFuzzy(
    _In_  PCSTR   Target,
    _In_  PCSTR*  Candidates,
    _In_  ULONG   Count,
    _Out_ PULONG  BestIndex,
    _Out_ PULONG  BestScore
    )
{
    ULONG i;
    INT best = -1;
    ULONG bestIdx = (ULONG)-1;

    if (!Target || !Candidates || Count == 0) return -1;

    for (i = 0; i < Count; i++) {
        INT score = IocScan_CtphCompare(Target, Candidates[i]);
        if (score > best) {
            best = score;
            bestIdx = i;
        }
    }
    if (BestIndex) *BestIndex = bestIdx;
    if (BestScore) *BestScore = (best >= 0) ? (ULONG)best : 0;
    return (best >= 0) ? 0 : -1;
}

/* -- ģ��+����ȷ�� (SS FuzzyHasher.hpp CompareWithCryptoConfirmation L361-365)
 * ������: ģ���� �� ��ֵ���� SHA256 ����ͬ��������ȷȷ��, ����������ϣ������
 * ���ݵ��󱨡�Ĭ����ֵ 90�� */
static INT
IocScan_CompareFuzzyCryptoConfirm(
    _In_  const BYTE* Buf1,
    _In_  SIZE_T      Size1,
    _In_  const BYTE* Buf2,
    _In_  SIZE_T      Size2,
    _In_  INT         Threshold,          /* ��0 ��Ĭ�� 90 */
    _Out_ PBOOLEAN    ExactMatch
    )
{
    CHAR d1[128], d2[128];
    INT score;
    WKD_FILE_HASH_SET h1, h2;

    if (ExactMatch) *ExactMatch = FALSE;
    if (!Buf1 || !Buf2) return -1;
    if (Threshold <= 0) Threshold = 90;

    if (IocScan_CtphBuildDigest(Buf1, Size1, d1, sizeof(d1)) != 0) return -1;
    if (IocScan_CtphBuildDigest(Buf2, Size2, d2, sizeof(d2)) != 0) return -1;
    score = IocScan_CtphCompare(d1, d2);

    if (score >= Threshold && Size1 <= 0xFFFFFFFF && Size2 <= 0xFFFFFFFF) {
        if (IocScan_HashBufferMulti(Buf1, (ULONG)Size1, WkdHash_SHA256, &h1) && h1.Sha256Valid &&
            IocScan_HashBufferMulti(Buf2, (ULONG)Size2, WkdHash_SHA256, &h2) && h2.Sha256Valid) {
            if (memcmp(h1.Sha256, h2.Sha256, 32) == 0) {
                if (ExactMatch) *ExactMatch = TRUE;
            }
        }
    }
    return score;
}

/* -- ��һ�� CTPH (SS FuzzyHasher.hpp HashBufferNormalized L268-271) ------------
 * ������: ����Կ��� padding/PE overlay ������������� CTPH��
 *   �� PE: ��β�� ��512 �ֽ������;
 *   PE:    ��ȡ��ִ��/����� raw ƴ�� (IocpAnalyzeBufferEx), �޴���ڻ���ȫ���塣 */
static INT
IocScan_CtphHashNormalized(
    _In_  const BYTE* Data,
    _In_  SIZE_T      Size,
    _Out_ PCHAR       Out,
    _In_  ULONG       OutCch,
    _Out_opt_ PBOOLEAN WasNormalized,
    _Out_opt_ PBOOLEAN IsPe
    )
{
    if (WasNormalized) *WasNormalized = FALSE;
    if (IsPe) *IsPe = FALSE;

    if (!Data || !Out || OutCch < 128) return -1;
    if (Size == 0 || Size > WKD_CTPH_MAX_HASHABLE) return -1;

    /* �� PE: ����β������� */
    if (Size < 2 || !(Data[0] == 'M' && Data[1] == 'Z')) {
        SIZE_T n = Size;
        while (n >= 512) {
            SIZE_T k = n - 512;
            SIZE_T j;
            BOOLEAN allZero = TRUE;
            for (j = k; j < n; j++) {
                if (Data[j] != 0) { allZero = FALSE; break; }
            }
            if (!allZero) break;
            n = k;
        }
        if (WasNormalized) *WasNormalized = (n != Size);
        return IocScan_CtphBuildDigest(Data, n, Out, OutCch);
    }

    /* PE: ��ȡ��ִ��/����� */
    if (IsPe) *IsPe = TRUE;
    {
        PE_PARSER_CONTEXT ctx;
                BYTE* norm = NULL;
        SIZE_T need = 0, o = 0;
        ULONG i;
        INT rc = -1;
        BOOLEAN parsed = FALSE;
        RtlZeroMemory(&ctx, sizeof(ctx));
        if (NT_SUCCESS(WpeParseBufferContext(&ctx, Data, Size, FALSE))) {
            parsed = TRUE;
            for (i = 0; i < ctx.Info.NumberOfSections; i++) {
                const PE_SECTION* sec = &ctx.Info.Sections[i];
                if ((sec->IsExecutable || sec->HasCode) && sec->SizeOfRawData > 0) {
                    need += sec->SizeOfRawData;
                }
            }
        }

        if (!parsed) {
            rc = IocScan_CtphBuildDigest(Data, Size, Out, OutCch);
            WpeResetParseContext(&ctx);
            return rc;
        }

        if (need == 0) {
            /* �޴���� �� ����ȫ���� (���� SS fallback) */
            rc = IocScan_CtphBuildDigest(Data, Size, Out, OutCch);
            WpeResetParseContext(&ctx);
            return rc;
        }

        if (need <= WKD_CTPH_MAX_HASHABLE) {
            norm = (BYTE*)malloc(need);
            if (norm) {
                for (i = 0; i < ctx.Info.NumberOfSections; i++) {
                    const PE_SECTION* sec = &ctx.Info.Sections[i];
                    if ((sec->IsExecutable || sec->HasCode) && sec->SizeOfRawData > 0) {
                        if ((ULONGLONG)sec->PointerToRawData + sec->SizeOfRawData <= (ULONGLONG)Size) {
                            memcpy(norm + o, Data + sec->PointerToRawData, sec->SizeOfRawData);
                            o += sec->SizeOfRawData;
                        }
                    }
                }
                if (o > 0) {
                    if (WasNormalized) *WasNormalized = (o != Size);
                    rc = IocScan_CtphBuildDigest(norm, o, Out, OutCch);
                }
                free(norm);
            }
        }
        WpeResetParseContext(&ctx);
        return rc;
    }
}

/**************************************************/
/*      7. ���������������� (SS FileReputation)      */
/*  ThreatIntel / �ƶ� / ��Ϊ / JSON���� / ���ù���  */
/*  ������ȫ������, δ������ˮ��, ��ע������ԭ��    */
/**************************************************/


/* -- MIME ӳ�� (SS GetMimeForFormat L1108-1198) ------------------------------
 * ����: ��ʽ��MIME ���� (Web/HTTP ��������)��
 * ���ѷ�: 5.7 ��ѯ API IocScan_GetExtensionInfo/IocScan_GetMimeType (ǰ������
 *   ����), ��������; λ�ñ����������������ڼ���ά��, 4505 ���Ծ���ò������� */
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

