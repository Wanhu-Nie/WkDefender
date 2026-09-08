/**************************************************/
/*  WkDefender Agent — BCrypt/哈希工具层实现        */
/*                                                  */
/*  2026-09-08 重构: 自 Common/FileUtils.c 迁出     */
/*  全部加密算法函数（SHA-256/MD5 多算法哈希槽、     */
/*  CTPH/TLSH 模糊哈希、哈希高层封装与硬件加速），   */
/*  统一收敛 Agent 侧 BCrypt 使用。                 */
/**************************************************/

#include <windows.h>
#include "BCrypUtils.h"
#include "../Common/FileUtils.h"   /* CoOpenFileForSequentialRead（单遍文件哈希护栏） */
#include "../Common/Utils.h"       /* UtHexEncode（SelfTest 已知值校验） */
#include "../IOC/PEAnalyzer/PeAnalyzer.h"  /* WpeParseBufferContext（CtphHashNormalized 归一化输入） */
#include <bcrypt.h>
#include <intrin.h>      /* __cpuidex（AES-NI/SHA-NI 硬件加速检测） */
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "bcrypt.lib")

/**************************************************/
/*  哈希基础宏 / 槽结构（迁自 FileUtils.c）         */
/**************************************************/
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

/**************************************************/
/*  哈希核心（BCrypt 多算法槽 + SHA/MD5 封装）      */
/**************************************************/
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
/*  CTPH / TLSH 模糊哈希实现                       */
/**************************************************/
/**************************************************/
/*  哈希高层封装（SS FileHasher 族）               */
/**************************************************/
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
