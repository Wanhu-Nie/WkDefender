/**************************************************/
/*  WkDefender PEAnalyzer — 加壳解包实现            */
/*  移植 ShadowStrike PackerUnpacker                */
/*  (按功能融合, C 重实现非复制)                      */
/*  活代码: NRV2B / UPX 静态解包 / OEP / PE 重建     */
/*  死代码: ASPack/MPRESS/PECompact/FSG / IAT 重建   */
/*          / 动态解包 (EmulationEngine 接口留档)     */
/**************************************************/

#include "PeInternal.h"
#include "../../Common/FileUtils.h"

#include <ntstatus.h>
#include <bcrypt.h>
#include <math.h>
#include <stdio.h>   /* _snwprintf_s (死代码 ResolveApiByAddress) */
#include <string.h>
#include <stdlib.h>
#include <wchar.h>   /* wcschr/wcsncpy_s (死代码 WpeScanIatRange) */

/**************************************************/
/*              内部静态辅助                         */
/**************************************************/

static
BOOLEAN
WpeUnpackComputeSha256(
    _In_  const BYTE* Data,
    _In_  SIZE_T      Size,
    _Out_ BYTE        Digest[32]
    )
/*++
Routine Description:
    SHA-256 计算 (BCrypt, 对齐 SS UnpackLayer::sha256)。

Arguments:
    Data   - 输入缓冲。
    Size   - 输入长度。
    Digest - 输出 32 字节摘要。

Return Value:
    TRUE=成功。
--*/
{
    DEF_SHA256_HASH digest;

    if (Data == NULL || Digest == NULL) return FALSE;
    if (Size > 0xFFFFFFFFUL) return FALSE;

    /* 统一走 BCrypUtils（BCrypt SHA-256 buffer 哈希, 2026-09-08 收敛） */
    if (!IocScanner_ComputeBufferSha256(Data, (ULONG)Size, &digest)) {
        return FALSE;
    }
    memcpy(Digest, digest.Data, DEF_SHA256_SIZE);
    return TRUE;
}

static
NTSTATUS
WpeUnpackDetectOepInPayload(
    _In_  const BYTE* Payload,
    _In_  SIZE_T      PayloadSize,
    _In_  ULONG       PayloadRva,      /* payload 目标 RVA (UPX0->VirtualAddress) */
    _Out_ PULONG      OutOepRva
    )
/*++
Routine Description:
    在解压载荷内扫描 OEP 特征 (对齐 SS FindOEPInternal 的 .text 模式:
    PUSH EBP; MOV EBP,ESP / MOV EDI,EDI; PUSH EBP; MOV EBP,ESP / REX.W SUB RSP,imm8)。
    静态 UPX 路径无 .text 节, 直接对解压代码扫描, 命中返回 RVA。

Arguments:
    Payload     - 解压后的代码载荷。
    PayloadSize - 载荷长度。
    PayloadRva  - 载荷目标 RVA (用于换算命中地址)。
    OutOepRva   - 输出 OEP RVA。

Return Value:
    STATUS_SUCCESS / STATUS_NOT_FOUND。
--*/
{
    static const BYTE PATTERN1[] = { 0x55, 0x8B, 0xEC };            /* PUSH EBP; MOV EBP,ESP */
    static const BYTE PATTERN2[] = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC }; /* MOV EDI,EDI; PUSH EBP; MOV EBP,ESP */
    static const BYTE PATTERN3[] = { 0x48, 0x83 };                  /* x64: REX.W SUB RSP,imm8 */
    SIZE_T idx;

    if (Payload == NULL || OutOepRva == NULL) return STATUS_INVALID_PARAMETER;
    *OutOepRva = 0;

    for (idx = 0; idx + sizeof(PATTERN2) <= PayloadSize; idx++) {
        if (memcmp(Payload + idx, PATTERN2, sizeof(PATTERN2)) == 0) {
            *OutOepRva = PayloadRva + (ULONG)idx;
            return STATUS_SUCCESS;
        }
    }
    for (idx = 0; idx + sizeof(PATTERN1) <= PayloadSize; idx++) {
        if (memcmp(Payload + idx, PATTERN1, sizeof(PATTERN1)) == 0) {
            *OutOepRva = PayloadRva + (ULONG)idx;
            return STATUS_SUCCESS;
        }
    }
    for (idx = 0; idx + sizeof(PATTERN3) <= PayloadSize; idx++) {
        if (memcmp(Payload + idx, PATTERN3, sizeof(PATTERN3)) == 0) {
            *OutOepRva = PayloadRva + (ULONG)idx;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

/**************************************************/
/*              NRV2B 解压 (公有领域 UCL)           */
/**************************************************/

NTSTATUS
WpeNrV2bDecompress(
    _In_  const BYTE* Src,
    _In_  SIZE_T      SrcSize,
    _Out_ BYTE*       Dst,
    _In_  SIZE_T      DstSize,      /* 期望输出上限 */
    _Out_ PSIZE_T     OutUsed
    )
/*++
Routine Description:
    NRV2B 解压 (UCL 公有领域, 对齐 SS Nrv2bDecompress 的 C 重实现)。

    加固 (对齐 SS Hardening notes):
      - 迭代上限 kMaxLoopIters = min(DstSize*16, 2^28), 防畸形流 CPU 耗尽;
      - 位解码循环上限 kMaxBitDecodeIters = 33, 防无限零流;
      - mOff/mLen 中间值显式上限, 防 uint32 静默回绕;
      - 每次输出 push 受 DstSize 门控; 重叠匹配逐字节拷贝。

Arguments:
    Src    - 压缩输入。
    SrcSize- 输入长度。
    Dst    - 输出缓冲。
    DstSize- 输出缓冲上限。
    OutUsed- 实际解压字节数。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_BUFFER_SIZE (输入耗尽/越界) /
    STATUS_BUFFER_TOO_SMALL (触发防炸弹上限或输出超限) / STATUS_UNSUCCESSFUL。
--*/
{
    SIZE_T ip = 0;
    SIZE_T op = 0;
    ULONG  bb = 0;
    ULONG  ilen = 0;
    ULONG  lastMOff = 1;
    SIZE_T loopIters = 0;
    SIZE_T kMaxLoopIters;
    int bit;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN done = FALSE;

    if (Src == NULL || Dst == NULL || OutUsed == NULL || SrcSize == 0 || DstSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutUsed = 0;
    kMaxLoopIters = (DstSize * 16 < ((SIZE_T)1 << 28)) ? (DstSize * 16) : ((SIZE_T)1 << 28);

#define PE_NRV2B_GETBIT() do { \
        if (ilen == 0) { \
            if (ip >= SrcSize) { status = STATUS_INVALID_BUFFER_SIZE; goto done; } \
            bb = Src[ip++]; \
            ilen = 8; \
        } \
        bit = (int)((bb >> 7) & 1); \
        bb <<= 1; \
        ilen--; \
    } while (0)

    while (!done) {
        ULONG mOff, mLen;
        ULONG iter;

        if (++loopIters > kMaxLoopIters) { status = STATUS_BUFFER_TOO_SMALL; goto done; }

        /* 字面量: while bit==1 复制一个字节 */
        PE_NRV2B_GETBIT();
        while (bit == 1) {
            if (ip >= SrcSize || op >= DstSize) { status = STATUS_INVALID_BUFFER_SIZE; goto done; }
            Dst[op++] = Src[ip++];
            PE_NRV2B_GETBIT();
        }

        /* 解 offset (上限防 uint32 回绕) */
        mOff = 1;
        for (iter = 0; ; iter++) {
            if (iter > 33) { status = STATUS_BUFFER_TOO_SMALL; goto done; }
            PE_NRV2B_GETBIT();
            if (mOff > 0x7FFFFFFFu) { status = STATUS_BUFFER_TOO_SMALL; goto done; }
            mOff = mOff * 2u + (ULONG)bit;
            PE_NRV2B_GETBIT();
            if (bit) break;
        }

        if (mOff == 2) {
            mOff = lastMOff;
        } else {
            if (ip >= SrcSize) { status = STATUS_INVALID_BUFFER_SIZE; goto done; }
            if (mOff < 3 || mOff > 0x7FFFFFu) { status = STATUS_BUFFER_TOO_SMALL; goto done; }
            mOff = (mOff - 3u) * 256u + Src[ip++];
            if (mOff == 0xFFFFFFFFu) { done = TRUE; break; }   /* 流结束 */
            mOff++;
            lastMOff = mOff;
        }

        /* 解匹配长度 */
        PE_NRV2B_GETBIT();
        mLen = (ULONG)bit;
        PE_NRV2B_GETBIT();
        mLen = mLen * 2 + (ULONG)bit;

        if (mLen == 0) {
            mLen = 1;
            for (iter = 0; ; iter++) {
                if (iter > 33) { status = STATUS_BUFFER_TOO_SMALL; goto done; }
                PE_NRV2B_GETBIT();
                if (mLen > 0x7FFFFFFFu) { status = STATUS_BUFFER_TOO_SMALL; goto done; }
                mLen = mLen * 2u + (ULONG)bit;
                PE_NRV2B_GETBIT();
                if (bit) break;
            }
            if (mLen > 0xFFFFFFFEu) { status = STATUS_BUFFER_TOO_SMALL; goto done; }
            mLen += 2;
        }

        if (mOff > 0xD00) mLen++;

        /* 校验匹配 (防越界) */
        if (mOff > op) { status = STATUS_UNSUCCESSFUL; goto done; }
        if (op + mLen > DstSize) { status = STATUS_BUFFER_TOO_SMALL; goto done; }

        /* 重叠匹配: 逐字节拷贝 */
        {
            SIZE_T srcPos = op - mOff;
            ULONG i;
            for (i = 0; i < mLen; i++) {
                Dst[op + i] = Dst[srcPos + i];
            }
            op += mLen;
        }
    }

    status = STATUS_SUCCESS;

done:
#undef PE_NRV2B_GETBIT
    *OutUsed = op;
    return status;
}

/**************************************************/
/*              PE 重建 (写侧)                      */
/**************************************************/

static
NTSTATUS
WpeUnpackBuildImage(
    _In_  const BYTE* OrigData,
    _In_  SIZE_T      OrigSize,
    _In_  ULONG       OepRva,
    _In_  const BYTE* Payload,
    _In_  ULONG       PayloadSize,
    _In_  ULONG       PayloadRva,
    _Out_ PBYTE*      OutBuffer,
    _Out_ PULONG      OutSize
    )
/*++
Routine Description:
    将解压载荷重建为完整 PE 镜像 (对齐 SS FixPEHeadersInternal 语义:
    改入口点 + 删壳节 + 重对齐 + 重算 SizeOfImage/校验和)。借鉴
    WpeReconstructPeFromMemory 按节表摆位的思路, C 写侧重实现。

Arguments:
    OrigData    - 原始加壳文件缓冲。
    OrigSize    - 原始文件大小。
    OepRva      - 解压镜像 OEP RVA。
    Payload     - 解压出的代码载荷 (对应原 UPX0 内容)。
    PayloadSize - 载荷大小。
    PayloadRva  - 载荷目标 RVA (原 UPX0->VirtualAddress)。
    OutBuffer   - 输出重建镜像 (堆分配, 调用方 free)。
    OutSize     - 输出大小。

Return Value:
    STATUS_SUCCESS / 错误码。
--*/
{
    IMAGE_DOS_HEADER dos;
    IMAGE_FILE_HEADER fh;
    ULONG optOff, secOff;
    BOOLEAN is64;
    ULONG fileAlign, secAlign, sizeOfHeaders;
    ULONG optChecksumOff;
    IMAGE_SECTION_HEADER inSec[PE_MAX_SECTIONS];
    ULONG numIn;
    IMAGE_SECTION_HEADER outSec[PE_MAX_SECTIONS];
    ULONG numOut = 0;
    ULONG payloadIdx = (ULONG)-1;
    ULONG i;
    ULONG payloadRaw;
    ULONG bufSize;
    ULONG maxVaEnd = 0;
    PBYTE buf;
    USHORT magic;
    USHORT numSectionsOut;

    if (OrigData == NULL || OrigSize < sizeof(IMAGE_DOS_HEADER) ||
        Payload == NULL || PayloadSize == 0 ||
        OutBuffer == NULL || OutSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutBuffer = NULL; *OutSize = 0;

    memcpy(&dos, OrigData, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;
    if ((ULONG)dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + 2 > OrigSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    memcpy(&fh, OrigData + dos.e_lfanew + 4, sizeof(fh));
    optOff = (ULONG)dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER);
    memcpy(&magic, OrigData + optOff, sizeof(magic));
    is64 = (magic == PE_PE64_MAGIC);

    if (is64) {
        IMAGE_OPTIONAL_HEADER64 opt;
        if (optOff + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) > OrigSize) return STATUS_INVALID_IMAGE_FORMAT;
        memcpy(&opt, OrigData + optOff, offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory));
        fileAlign = opt.FileAlignment;
        secAlign  = opt.SectionAlignment;
        sizeOfHeaders = opt.SizeOfHeaders;
    } else {
        IMAGE_OPTIONAL_HEADER32 opt;
        if (optOff + offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) > OrigSize) return STATUS_INVALID_IMAGE_FORMAT;
        memcpy(&opt, OrigData + optOff, offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory));
        fileAlign = opt.FileAlignment;
        secAlign  = opt.SectionAlignment;
        sizeOfHeaders = opt.SizeOfHeaders;
    }
    if (sizeOfHeaders == 0 || sizeOfHeaders > OrigSize) return STATUS_INVALID_IMAGE_FORMAT;
    if (fileAlign < PE_MIN_FILE_ALIGNMENT || fileAlign > PE_MAX_FILE_ALIGNMENT ||
        (fileAlign & (fileAlign - 1)) != 0) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    if (secAlign < 0x1000 || (secAlign & (secAlign - 1)) != 0 || secAlign < fileAlign) {
        secAlign = 0x1000;   /* 异常对齐宽容降级到页对齐 */
    }
    optChecksumOff = optOff + 64;   /* CheckSum 字段固定偏移 64 (PE32/PE32+ 一致) */

    secOff = optOff + fh.SizeOfOptionalHeader;
    numIn = fh.NumberOfSections;
    if (numIn == 0 || numIn > PE_MAX_SECTIONS) return STATUS_INVALID_IMAGE_FORMAT;
    if (secOff + numIn * sizeof(IMAGE_SECTION_HEADER) > OrigSize) return STATUS_INVALID_IMAGE_FORMAT;
    for (i = 0; i < numIn; i++) {
        memcpy(&inSec[i], OrigData + secOff + i * sizeof(IMAGE_SECTION_HEADER), sizeof(inSec[i]));
    }

    /* 选节: payload 目标节保留为代码节; 壳节删除; 其余保留 */
    for (i = 0; i < numIn; i++) {
        CHAR name[PE_MAX_SECTION_NAME + 1];
        ULONG va = inSec[i].VirtualAddress;
        ULONG vsize = inSec[i].Misc.VirtualSize ? inSec[i].Misc.VirtualSize : inSec[i].SizeOfRawData;
        BOOLEAN isPackerSec;
        BOOLEAN containsPayload;

        memcpy(name, inSec[i].Name, 8); name[8] = 0;
        isPackerSec = (strcmp(name, "UPX0") == 0 || strcmp(name, "UPX1") == 0 ||
                       strcmp(name, "UPX2") == 0 || strcmp(name, ".UPX0") == 0 ||
                       strcmp(name, ".UPX1") == 0 || strcmp(name, ".UPX2") == 0 ||
                       strcmp(name, "UPX!") == 0 || strcmp(name, ".aspack") == 0 ||
                       strcmp(name, ".adata") == 0 || strcmp(name, ".nsp0") == 0 ||
                       strcmp(name, ".nsp1") == 0 || strcmp(name, ".nsp2") == 0);
        containsPayload = (PayloadRva >= va && PayloadRva < va + (vsize ? vsize : 1));

        if (containsPayload) {
            IMAGE_SECTION_HEADER* o = &outSec[numOut];
            memcpy(o, &inSec[i], sizeof(*o));
            o->Misc.VirtualSize = PayloadSize;
            o->SizeOfRawData = (PayloadSize + fileAlign - 1) & ~(fileAlign - 1);
            o->Characteristics = (o->Characteristics & ~PE_SCH_MEM_WRITE) |
                                 PE_SCH_CNT_CODE | PE_SCH_MEM_EXECUTE |
                                 PE_SCH_MEM_READ | PE_SCH_CNT_INITIALIZED_DATA;
            payloadIdx = numOut;
            numOut++;
            continue;
        }
        if (isPackerSec) continue;
        memcpy(&outSec[numOut], &inSec[i], sizeof(outSec[numOut]));
        numOut++;
    }
    if (payloadIdx == (ULONG)-1) {
        /* 未找到 payload 节: 追加 .text 代码节 */
        IMAGE_SECTION_HEADER* o = &outSec[numOut];
        RtlZeroMemory(o, sizeof(*o));
        memcpy(o->Name, ".text", 6);
        o->VirtualAddress = secAlign;
        o->Misc.VirtualSize = PayloadSize;
        o->SizeOfRawData = (PayloadSize + fileAlign - 1) & ~(fileAlign - 1);
        o->Characteristics = PE_SCH_CNT_CODE | PE_SCH_MEM_EXECUTE |
                             PE_SCH_MEM_READ | PE_SCH_CNT_INITIALIZED_DATA;
        payloadIdx = numOut;
        numOut++;
    }
    if (numOut == 0 || numOut > PE_MAX_SECTIONS) return STATUS_UNSUCCESSFUL;

    /* 摆位: payload 节 raw 追加到所有保留节 raw 末尾之后 (保留节 raw 原位不动,
     * 避免覆盖冲突; 数据目录对保留节的引用保持有效) */
    {
        ULONG maxRawEnd = (ULONG)OrigSize;
        ULONG i2;
        for (i2 = 0; i2 < numOut; i2++) {
            ULONG end;
            if (i2 == payloadIdx) continue;
            if (!IocpAddU32Safe(outSec[i2].PointerToRawData, outSec[i2].SizeOfRawData, &end)) {
                return STATUS_FILE_TOO_LARGE;
            }
            if (end > maxRawEnd) maxRawEnd = end;
        }
        payloadRaw = maxRawEnd + (fileAlign - 1);
        if (payloadRaw < maxRawEnd) return STATUS_FILE_TOO_LARGE;   /* 溢出 */
        payloadRaw &= ~(fileAlign - 1);
        if (!IocpAddU32Safe(payloadRaw, outSec[payloadIdx].SizeOfRawData, &bufSize)) {
            return STATUS_FILE_TOO_LARGE;
        }
        outSec[payloadIdx].PointerToRawData = payloadRaw;
    }
    if (bufSize > PE_UNPACK_MAX_OUTPUT) return STATUS_FILE_TOO_LARGE;

    buf = (PBYTE)malloc(bufSize);
    if (buf == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(buf, bufSize);
    memcpy(buf, OrigData, (OrigSize < bufSize) ? OrigSize : bufSize);

    /* 重写节表 + NumberOfSections */
    for (i = 0; i < numOut; i++) {
        memcpy(buf + secOff + i * sizeof(IMAGE_SECTION_HEADER), &outSec[i], sizeof(IMAGE_SECTION_HEADER));
    }
    for (i = numOut; i < numIn; i++) {
        RtlZeroMemory(buf + secOff + i * sizeof(IMAGE_SECTION_HEADER), sizeof(IMAGE_SECTION_HEADER));
    }
    numSectionsOut = (USHORT)numOut;
    memcpy(buf + dos.e_lfanew + 4 + 2, &numSectionsOut, sizeof(numSectionsOut));

    /* 写入解压载荷 */
    memcpy(buf + outSec[payloadIdx].PointerToRawData, Payload, PayloadSize);

    /* 修入口点 + SizeOfImage + 校验和 */
    for (i = 0; i < numOut; i++) {
        ULONG end = outSec[i].VirtualAddress +
                    (outSec[i].Misc.VirtualSize ? outSec[i].Misc.VirtualSize : outSec[i].SizeOfRawData);
        if (end > maxVaEnd) maxVaEnd = end;
    }
    maxVaEnd = (maxVaEnd + secAlign - 1) & ~(secAlign - 1);

    if (is64) {
        IMAGE_OPTIONAL_HEADER64 opt;
        memcpy(&opt, buf + optOff, offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory));
        opt.AddressOfEntryPoint = OepRva;
        opt.SizeOfImage = maxVaEnd;
        opt.CheckSum = WpeComputeFileChecksum(buf, bufSize, optChecksumOff);
        memcpy(buf + optOff, &opt, offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory));
    } else {
        IMAGE_OPTIONAL_HEADER32 opt;
        memcpy(&opt, buf + optOff, offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory));
        opt.AddressOfEntryPoint = OepRva;
        opt.SizeOfImage = maxVaEnd;
        opt.CheckSum = WpeComputeFileChecksum(buf, bufSize, optChecksumOff);
        memcpy(buf + optOff, &opt, offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory));
    }

    *OutBuffer = buf;
    *OutSize = bufSize;
    return STATUS_SUCCESS;
}

/**************************************************/
/*              UPX 静态解包                        */
/**************************************************/

static
NTSTATUS
WpeUnpackUpxInternal(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  const BYTE*              FileData,
    _In_  SIZE_T                   FileSize,
    _Out_ PPE_UNPACK_LAYER        Layer,
    _Out_ PBOOLEAN                 Reconstructed
    )
/*++
Routine Description:
    UPX 静态解包 (对齐 SS UnpackUPX): UPX0=目的 / UPX1=压缩载荷,
    NRV2B 解压 → 尝试完整重建 (WpeUnpackBuildImage), 失败回退
    "原始头区 + 解压数据" (对齐 SS rebuilt 语义)。

Arguments:
    Ctx           - 已 IocpAnalyzeBufferEx 解析的上下文。
    FileData      - 原始文件缓冲。
    FileSize      - 原始文件大小。
    Layer         - 输出解包层。
    Reconstructed - 输出是否完成完整重建。

Return Value:
    STATUS_SUCCESS / STATUS_NOT_FOUND (无 UPX 节) / 解压错误。
--*/
{
    SIZE_T upx0Idx = 0, upx1Idx = 0;
    const PE_SECTION* upx0;
    const PE_SECTION* upx1;
    SIZE_T compressedStart, compressedSize;
    SIZE_T decompressedSize;
    SIZE_T headerSize;
    BYTE*  out = NULL;
    SIZE_T outUsed = 0;
    ULONG  oepRva = 0;
    PBYTE  img = NULL;
    ULONG  imgSize = 0;
    NTSTATUS status;

    if (Ctx == NULL || !Ctx->Parsed || FileData == NULL || Layer == NULL || Reconstructed == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Layer, sizeof(*Layer));
    *Reconstructed = FALSE;

    if (!WpeGetSectionByName(Ctx, "UPX0", &upx0Idx)) {
        if (!WpeGetSectionByName(Ctx, ".UPX0", &upx0Idx)) return STATUS_NOT_FOUND;
    }
    if (!WpeGetSectionByName(Ctx, "UPX1", &upx1Idx)) {
        if (!WpeGetSectionByName(Ctx, ".UPX1", &upx1Idx)) return STATUS_NOT_FOUND;
    }
    upx0 = &Ctx->Info.Sections[upx0Idx];
    upx1 = &Ctx->Info.Sections[upx1Idx];

    /* UPX0 = 目的 (解压后), UPX1 = 压缩载荷 */
    compressedStart = upx1->PointerToRawData;
    compressedSize = upx1->SizeOfRawData;
    if (compressedSize == 0 || compressedStart + compressedSize > FileSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    decompressedSize = upx0->VirtualSize;
    if (decompressedSize == 0 || decompressedSize > PE_UNPACK_MAX_OUTPUT) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    out = (BYTE*)malloc(decompressedSize);
    if (out == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    status = WpeNrV2bDecompress(FileData + compressedStart, compressedSize,
                                out, decompressedSize, &outUsed);
    if (!NT_SUCCESS(status)) {
        free(out);
        return status;
    }

    Layer->Packer = WpePacker_Upx;
    Layer->PackerName = "UPX";
    Layer->LayerNumber = 1;
    Layer->OriginalEntryPointRva = Ctx->Info.AddressOfEntryPoint;
    Layer->EntropyBefore = CoEntropyCalculate(FileData + compressedStart, compressedSize, CoEntropyAlphabet_Byte, 0);
    Layer->EntropyAfter = CoEntropyCalculate(out, outUsed, CoEntropyAlphabet_Byte, 0);

    (void)WpeUnpackDetectOepInPayload(out, outUsed, upx0->VirtualAddress, &oepRva);
    Layer->UnpackedEntryPointRva = oepRva;

    /* 完整重建 (活代码): 产出可再解析的 PE 镜像; 失败回退 rebuilt */
    if (oepRva != 0 &&
        NT_SUCCESS(WpeUnpackBuildImage(FileData, FileSize, oepRva,
                                       out, (ULONG)outUsed, upx0->VirtualAddress,
                                       &img, &imgSize))) {
        Layer->UnpackedData = img;
        Layer->UnpackedSize = imgSize;
        *Reconstructed = TRUE;
    } else {
        PBYTE rebuilt;
        headerSize = Ctx->Info.SizeOfHeaders;
        if (headerSize > FileSize) {
            free(out);
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        rebuilt = (PBYTE)malloc(headerSize + outUsed);
        if (rebuilt == NULL) {
            free(out);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        memcpy(rebuilt, FileData, headerSize);
        memcpy(rebuilt + headerSize, out, outUsed);
        Layer->UnpackedData = rebuilt;
        Layer->UnpackedSize = (ULONG)(headerSize + outUsed);
    }
    free(out);

    WpeUnpackComputeSha256(Layer->UnpackedData, Layer->UnpackedSize, Layer->Sha256);
    return STATUS_SUCCESS;
}

static
PE_UNPACK_PACKER
WpeUnpackIdentifyPacker(
    _In_ const PE_PARSER_CONTEXT* Ctx
    )
/*++
Routine Description:
    按节名识别加壳器类型 (对齐 SS UnpackFileInternal 的分派判定)。

Return Value:
    识别到的类型; WpePacker_None = 未识别。
--*/
{
    ULONG i;

    if (Ctx == NULL || !Ctx->Parsed) return WpePacker_None;

    for (i = 0; i < Ctx->Info.NumberOfSections; i++) {
        CHAR name[PE_MAX_SECTION_NAME + 1];
        memcpy(name, Ctx->Info.Sections[i].Name, 8); name[8] = 0;

        if (strcmp(name, "UPX0") == 0 || strcmp(name, "UPX1") == 0 ||
            strcmp(name, "UPX2") == 0 || strcmp(name, ".UPX0") == 0 ||
            strcmp(name, ".UPX1") == 0 || strcmp(name, ".UPX2") == 0 ||
            strcmp(name, "UPX!") == 0) return WpePacker_Upx;
        if (strcmp(name, ".aspack") == 0 || strcmp(name, ".adata") == 0) return WpePacker_Aspack;
        if (strcmp(name, ".mpress1") == 0 || strcmp(name, ".MPRESS1") == 0 ||
            strcmp(name, ".mpress2") == 0 || strcmp(name, ".MPRESS2") == 0 ||
            strcmp(name, "MPRESS") == 0) return WpePacker_Mpress;
        if (strcmp(name, ".fsg") == 0 || strcmp(name, ".FSG") == 0 ||
            strcmp(name, "FSG!") == 0) return WpePacker_Fsg;
        if (strcmp(name, ".pecompact") == 0 || strcmp(name, "PECompact") == 0 ||
            strcmp(name, "pec1") == 0 || strcmp(name, "pec2") == 0 ||
            strcmp(name, "PEC2") == 0) return WpePacker_PeCompact;
    }
    return WpePacker_None;
}

/**************************************************/
/*              解包公开入口                        */
/**************************************************/

NTSTATUS
WpeUnpackPackedBuffer(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  const BYTE*              FileData,
    _In_  SIZE_T                   FileSize,
    _Out_ PPE_UNPACK_RESULT       Result
    )
/*++
Routine Description:
    对已解析的加壳文件执行静态解包 (仅 UPX 可靠接入, 对齐 SS
    UnpackFileInternal 的 Static 路径)。Ctx 须已解析且
    ComputeSectionEntropy=TRUE。

Arguments:
    Ctx      - 已解析上下文。
    FileData - 原始文件缓冲。
    FileSize - 原始文件大小。
    Result   - 输出解包结果 (先 RtlZeroMemory; 用后 WpeUnpackResultFree)。

Return Value:
    STATUS_SUCCESS (成功, 或检测未命中) / 错误码。
--*/
{
    PE_UNPACK_PACKER packer;
    BOOLEAN reconstructed = FALSE;
    NTSTATUS status;

    if (Ctx == NULL || !Ctx->Parsed || FileData == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Result, sizeof(*Result));
    Result->State = WpeUnpack_NoPacker;

    if (FileSize > PE_UNPACK_MAX_INPUT) {
        Result->State = WpeUnpack_Unsupported;
        return STATUS_FILE_TOO_LARGE;
    }

    packer = WpeUnpackIdentifyPacker(Ctx);
    if (packer == WpePacker_None) {
        Result->State = WpeUnpack_NoPacker;
        return STATUS_SUCCESS;
    }

    switch (packer) {
    case WpePacker_Upx:
        status = WpeUnpackUpxInternal(Ctx, FileData, FileSize, &Result->Layers[0], &reconstructed);
        if (NT_SUCCESS(status)) {
            Result->State = WpeUnpack_Success;
            Result->Reconstructed = reconstructed;
            Result->LayerCount = 1;
            return STATUS_SUCCESS;
        }
        Result->State = (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INVALID_BUFFER_SIZE)
                            ? WpeUnpack_BombGuard : WpeUnpack_Failed;
        return status;

    case WpePacker_Aspack:
    case WpePacker_Mpress:
    case WpePacker_Fsg:
    case WpePacker_PeCompact:
        /* 静态解包不可靠 (见死代码区 WpeUnpack*Internal), 标记 Skipped */
        Result->State = WpeUnpack_Skipped;
        return STATUS_NOT_SUPPORTED;

    default:
        Result->State = WpeUnpack_Unsupported;
        return STATUS_NOT_SUPPORTED;
    }
}

VOID
WpeUnpackResultFree(
    _Inout_ PPE_UNPACK_RESULT Result
    )
/*++
Routine Description:
    释放解包结果 (各层 UnpackedData)。

Arguments:
    Result - 解包结果。
--*/
{
    ULONG i;

    if (Result == NULL) return;
    for (i = 0; i < Result->LayerCount; i++) {
        if (Result->Layers[i].UnpackedData != NULL) {
            free(Result->Layers[i].UnpackedData);
            Result->Layers[i].UnpackedData = NULL;
        }
    }
    RtlZeroMemory(Result, sizeof(*Result));
}

/**************************************************/
/*  死代码迁移区 (不接入流水线)                      */
/*  功能完整实现, 静态编译保留, 注释说明不接入原因。  */
/**************************************************/

/* -- WpeUnpackFixImportDirectory (SS PackerUnpacker::FixImportDirectory, 死代码)
 * 功能: 把 PE 缓冲的 DataDirectory[IMPORT] 重定向到重建后的 IAT RVA。
 * 不接入原因: 静态 UPX 路径导入目录通常存活于保留节, BuildImage 无需重定向;
 *       完整 IAT 重建 (WpeReconstructImportsInternal) 接入时才需要。
 * 注: DataDirectory 在可选头固定部分之后 (PE32 +96 / PE32+ +112),
 *     用字节偏移写入, 避开 PeTypes/PeParser 同名 IMAGE_DATA_DIRECTORY_EX 双义。 */
static
NTSTATUS
WpeUnpackFixImportDirectory(
    _Inout_ PBYTE  PeData,
    _In_    SIZE_T PeSize,
    _In_    ULONG  IatRva,
    _In_    ULONG  DescriptorCount
    )
{
    IMAGE_DOS_HEADER dos;
    ULONG optOff;
    BOOLEAN is64;
    USHORT magic;
    SIZE_T ddImport;   /* DataDirectory[1] 字节偏移 */
    ULONG va, sz;

    if (PeData == NULL || PeSize < sizeof(IMAGE_DOS_HEADER)) return STATUS_INVALID_PARAMETER;
    memcpy(&dos, PeData, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return STATUS_INVALID_IMAGE_FORMAT;
    if ((ULONG)dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + 2 > PeSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    optOff = (ULONG)dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER);
    memcpy(&magic, PeData + optOff, sizeof(magic));
    is64 = (magic == PE_PE64_MAGIC);

    /* DataDirectory 起始: PE32=optOff+96, PE32+=optOff+112; IMPORT=索引1 */
    ddImport = optOff + (is64 ? 112 : 96) + 2 * sizeof(ULONG);
    if (ddImport + 8 > PeSize) return STATUS_INVALID_IMAGE_FORMAT;

    va = IatRva;
    sz = (DescriptorCount + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    memcpy(PeData + ddImport, &va, sizeof(va));
    memcpy(PeData + ddImport + sizeof(va), &sz, sizeof(sz));
    return STATUS_SUCCESS;
}

/* -- WpeRtlXpressDecompress (SS CompressionUtils Xpress, 死代码) -----------
 * 功能: RtlDecompressBuffer(COMPRESSION_FORMAT_XPRESS) 解压, 对齐 SS
 *       CompressionUtils::Algorithm::Xpress (=0x0003 = COMPRESSION_FORMAT_XPRESS,
 *       内部同为 ntdll RtlDecompressBuffer 链路)。
 * 不接入原因: Xpress 非常规 PE 壳压缩, 仅 ASPack/MPRESS/PECompact 启发式用;
 *       动态解析避免 ntdll.lib 链接依赖。 */

typedef NTSTATUS (NTAPI *PE_PFN_RTL_DECOMPRESS)(
    USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG);

static
NTSTATUS
WpeRtlXpressDecompress(
    _In_  const BYTE* Src,
    _In_  ULONG       SrcSize,
    _Out_ BYTE*       Dst,
    _In_  ULONG       DstCapacity,
    _Out_ PULONG      OutUsed
    )
/*++
Routine Description:
    Xpress 解压 (死代码辅助)。

Arguments:
    Src         - 压缩输入。
    SrcSize     - 输入长度。
    Dst         - 输出缓冲。
    DstCapacity - 输出容量。
    OutUsed     - 实际解压字节数。

Return Value:
    STATUS_SUCCESS / STATUS_NOT_IMPLEMENTED (RtlDecompressBuffer 不可用) / 错误码。
--*/
{
    PE_PFN_RTL_DECOMPRESS pfn;
    HMODULE ntdll;
    NTSTATUS status;
    ULONG written = 0;

    if (Src == NULL || Dst == NULL || OutUsed == NULL || SrcSize == 0 || DstCapacity == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutUsed = 0;

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) return STATUS_NOT_IMPLEMENTED;
    pfn = (PE_PFN_RTL_DECOMPRESS)GetProcAddress(ntdll, "RtlDecompressBuffer");
    if (pfn == NULL) return STATUS_NOT_IMPLEMENTED;

    status = pfn(COMPRESSION_FORMAT_XPRESS, Dst, DstCapacity,
                 (PUCHAR)Src, SrcSize, &written);
    if (!NT_SUCCESS(status)) return status;
    *OutUsed = written;
    return STATUS_SUCCESS;
}

/* -- WpeUnpackAspackInternal (SS PackerUnpacker::UnpackASPack, 死代码) -----
 * 功能: 定位 .aspack/.adata 节 → EP stub 前 30 字节扫 XOR 密钥
 *       (XOR AL,imm8=0x34 / XOR reg,imm8=0x80 0xF?) → 逐字节异或解密 →
 *       Xpress 解压 (SS 亦自标 "proprietary compression + simple XOR")。
 * 不接入原因: ① ASPack 是专有压缩+变体 XOR, 密钥提取是字节启发式, 命中/
 *       误解密不可靠; ② 静态产出未经验证, 误报风险 > 价值; ③ 若未来有
 *       真实 ASPack 样本池可复核再启用。 */
static
NTSTATUS
WpeUnpackAspackInternal(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  const BYTE*              FileData,
    _In_  SIZE_T                   FileSize,
    _Out_ PPE_UNPACK_LAYER        Layer
    )
{
    SIZE_T secIdx;
    SIZE_T secStart, secSize;
    ULONG  epRva;
    SIZE_T epOff = 0;
    BYTE   xorKey = 0;
    BOOLEAN keyFound = FALSE;
    BYTE*  decrypted = NULL;
    BYTE*  out = NULL;
    ULONG  outSize = 0;
    ULONG  i;
    NTSTATUS status;

    if (Ctx == NULL || !Ctx->Parsed || FileData == NULL || Layer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Layer, sizeof(*Layer));

    if (!WpeGetSectionByName(Ctx, ".aspack", &secIdx)) {
        if (!WpeGetSectionByName(Ctx, ".adata", &secIdx)) return STATUS_NOT_FOUND;
    }
    secStart = Ctx->Info.Sections[secIdx].PointerToRawData;
    secSize = Ctx->Info.Sections[secIdx].SizeOfRawData;
    if (secSize < 16 || secStart + secSize > FileSize) return STATUS_INVALID_IMAGE_FORMAT;

    epRva = Ctx->Info.AddressOfEntryPoint;
    if (IocpRvaToOffset(Ctx, epRva, &epOff)) {
        for (i = 0; i < 30 && epOff + i + 2 <= FileSize; i++) {
            if (FileData[epOff + i] == 0x34) {              /* XOR AL, imm8 */
                xorKey = FileData[epOff + i + 1];
                keyFound = TRUE;
                break;
            }
            if (FileData[epOff + i] == 0x80 &&
                (FileData[epOff + i + 1] & 0xF8) == 0xF0) { /* XOR reg, imm8 */
                xorKey = FileData[epOff + i + 2];
                keyFound = TRUE;
                break;
            }
        }
    }
    if (!keyFound || xorKey == 0) return STATUS_NOT_FOUND;   /* SS: defer to dynamic */

    decrypted = (BYTE*)malloc(secSize);
    if (decrypted == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    for (i = 0; i < secSize; i++) decrypted[i] = FileData[secStart + i] ^ xorKey;

    out = (BYTE*)malloc(PE_UNPACK_MAX_OUTPUT);
    if (out == NULL) { free(decrypted); return STATUS_INSUFFICIENT_RESOURCES; }
    status = WpeRtlXpressDecompress(decrypted, (ULONG)secSize,
                                    out, PE_UNPACK_MAX_OUTPUT, &outSize);
    free(decrypted);
    if (!NT_SUCCESS(status) || outSize == 0) {
        free(out);
        return status;
    }

    Layer->Packer = WpePacker_Aspack;
    Layer->PackerName = "ASPack";
    Layer->LayerNumber = 1;
    Layer->UnpackedData = out;
    Layer->UnpackedSize = outSize;
    Layer->EntropyBefore = CoEntropyCalculate(FileData + secStart, secSize, CoEntropyAlphabet_Byte, 0);
    Layer->EntropyAfter = CoEntropyCalculate(out, outSize, CoEntropyAlphabet_Byte, 0);
    WpeUnpackComputeSha256(out, outSize, Layer->Sha256);
    return STATUS_SUCCESS;
}

/* -- WpeUnpackMpressInternal (SS PackerUnpacker::UnpackMPRESS, 死代码) -----
 * 功能: 定位 .mpress1 节 → Xpress 解压 (SS 自标 "LZMA not available - XPRESS
 *       as heuristic"; MPRESS 实为 LZMA + 自定义 stub)。
 * 不接入原因: Xpress 对 MPRESS 只是启发式, 静态产出不可靠; 真实 LZMA 需
 *       引入 LZMA SDK。未来若接入 LZMA 解码可复核。 */
static
NTSTATUS
WpeUnpackMpressInternal(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  const BYTE*              FileData,
    _In_  SIZE_T                   FileSize,
    _Out_ PPE_UNPACK_LAYER        Layer
    )
{
    SIZE_T secIdx;
    SIZE_T secStart, secSize;
    BYTE*  out = NULL;
    ULONG  outSize = 0;
    NTSTATUS status;

    if (Ctx == NULL || !Ctx->Parsed || FileData == NULL || Layer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Layer, sizeof(*Layer));

    if (!WpeGetSectionByName(Ctx, ".mpress1", &secIdx)) {
        if (!WpeGetSectionByName(Ctx, ".MPRESS1", &secIdx)) return STATUS_NOT_FOUND;
    }
    secStart = Ctx->Info.Sections[secIdx].PointerToRawData;
    secSize = Ctx->Info.Sections[secIdx].SizeOfRawData;
    if (secSize == 0 || secStart + secSize > FileSize) return STATUS_INVALID_IMAGE_FORMAT;

    out = (BYTE*)malloc(PE_UNPACK_MAX_OUTPUT);
    if (out == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    status = WpeRtlXpressDecompress((const BYTE*)(FileData + secStart), (ULONG)secSize,
                                    out, PE_UNPACK_MAX_OUTPUT, &outSize);
    if (!NT_SUCCESS(status) || outSize == 0) {
        free(out);
        return status;
    }

    Layer->Packer = WpePacker_Mpress;
    Layer->PackerName = "MPRESS";
    Layer->LayerNumber = 1;
    Layer->UnpackedData = out;
    Layer->UnpackedSize = outSize;
    Layer->EntropyBefore = CoEntropyCalculate(FileData + secStart, secSize, CoEntropyAlphabet_Byte, 0);
    Layer->EntropyAfter = CoEntropyCalculate(out, outSize, CoEntropyAlphabet_Byte, 0);
    WpeUnpackComputeSha256(out, outSize, Layer->Sha256);
    return STATUS_SUCCESS;
}

/* -- WpeUnpackPeCompactInternal (SS PackerUnpacker::UnpackPECompact, 死代码)
 * 功能: 定位 .pecompact/.pec1 节 → Xpress 解压 (SS 自标 "XPRESS as heuristic",
 *       PECompact 实为 aPLib 压缩 + 自定义 stub)。
 * 不接入原因: 同 MPRESS — Xpress 启发式不可靠; 真实 aPLib 需引入解码器。 */
static
NTSTATUS
WpeUnpackPeCompactInternal(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  const BYTE*              FileData,
    _In_  SIZE_T                   FileSize,
    _Out_ PPE_UNPACK_LAYER        Layer
    )
{
    SIZE_T secIdx;
    SIZE_T secStart, secSize;
    BYTE*  out = NULL;
    ULONG  outSize = 0;
    NTSTATUS status;

    if (Ctx == NULL || !Ctx->Parsed || FileData == NULL || Layer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Layer, sizeof(*Layer));

    if (!WpeGetSectionByName(Ctx, ".pecompact", &secIdx)) {
        if (!WpeGetSectionByName(Ctx, ".pec1", &secIdx)) return STATUS_NOT_FOUND;
    }
    secStart = Ctx->Info.Sections[secIdx].PointerToRawData;
    secSize = Ctx->Info.Sections[secIdx].SizeOfRawData;
    if (secSize == 0 || secStart + secSize > FileSize) return STATUS_INVALID_IMAGE_FORMAT;

    out = (BYTE*)malloc(PE_UNPACK_MAX_OUTPUT);
    if (out == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    status = WpeRtlXpressDecompress((const BYTE*)(FileData + secStart), (ULONG)secSize,
                                    out, PE_UNPACK_MAX_OUTPUT, &outSize);
    if (!NT_SUCCESS(status) || outSize == 0) {
        free(out);
        return status;
    }

    Layer->Packer = WpePacker_PeCompact;
    Layer->PackerName = "PECompact";
    Layer->LayerNumber = 1;
    Layer->UnpackedData = out;
    Layer->UnpackedSize = outSize;
    Layer->EntropyBefore = CoEntropyCalculate(FileData + secStart, secSize, CoEntropyAlphabet_Byte, 0);
    Layer->EntropyAfter = CoEntropyCalculate(out, outSize, CoEntropyAlphabet_Byte, 0);
    WpeUnpackComputeSha256(out, outSize, Layer->Sha256);
    return STATUS_SUCCESS;
}

/* -- WpeUnpackFsgInternal (SS PackerUnpacker::UnpackFSG, 死代码) ------------
 * 功能: 定位 .fsg/FSG! 节。SS 实现即为空壳 — 只定位节后返回 nullopt,
 *       因为 FSG 使用多态解密循环 + aPLib, 静态不可靠, 一律 defer 到动态。
 * 不接入原因: 与 SS 一致 — 多态解密无法静态还原。 */
static
NTSTATUS
WpeUnpackFsgInternal(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_UNPACK_LAYER        Layer
    )
{
    SIZE_T secIdx;

    if (Ctx == NULL || !Ctx->Parsed || Layer == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Layer, sizeof(*Layer));

    if (!WpeGetSectionByName(Ctx, ".fsg", &secIdx)) {
        if (!WpeGetSectionByName(Ctx, "FSG!", &secIdx)) return STATUS_NOT_FOUND;
    }
    /* FSG 多态解密, 静态无法还原 (SS UnpackFSG 同样只定位节即返回) */
    return STATUS_NOT_SUPPORTED;
}

/* -- WpeFindIatStart (SS PackerUnpacker::FindIATStart, 死代码) -------------
 * 功能: 定位 IAT 起始 RVA — 优先 IAT 数据目录(12) → IMPORT 目录(1) →
 *       .rdata/.idata/.data 节首 (SS 同序)。
 * 不接入原因: 完整 IAT 重建仅对"内存 dump/运行期 IAT"场景有效; wkd 无该
 *       场景, 活代码侧 PepParseImports (PeLazy.c) 已覆盖文件导入表读取。 */
static
NTSTATUS
WpeFindIatStart(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PULONG                   IatRva,
    _Out_ PULONG                   IatSize
    )
{
    ULONG i;

    if (Ctx == NULL || !Ctx->Parsed || IatRva == NULL || IatSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *IatRva = 0; *IatSize = 0;

    if (Ctx->Info.DataDirectories[PE_DD_IAT].Present &&
        Ctx->Info.DataDirectories[PE_DD_IAT].Rva != 0) {
        *IatRva = Ctx->Info.DataDirectories[PE_DD_IAT].Rva;
        *IatSize = Ctx->Info.DataDirectories[PE_DD_IAT].Size;
        return STATUS_SUCCESS;
    }
    if (Ctx->Info.DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Present &&
        Ctx->Info.DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Rva != 0) {
        *IatRva = Ctx->Info.DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Rva;
        return STATUS_SUCCESS;
    }
    for (i = 0; i < Ctx->Info.NumberOfSections; i++) {
        CHAR name[PE_MAX_SECTION_NAME + 1];
        memcpy(name, Ctx->Info.Sections[i].Name, 8); name[8] = 0;
        if (strcmp(name, ".rdata") == 0 || strcmp(name, ".idata") == 0 ||
            strcmp(name, ".data") == 0) {
            *IatRva = Ctx->Info.Sections[i].VirtualAddress;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

/* -- WpeResolveApiByAddress (SS PackerUnpacker::ResolveAPIByAddress, 死代码)
 * 功能: 遍历当前进程已加载系统 DLL 导出表, 反查地址对应的 "dll!func" 名。
 * 不接入原因: 仅运行期 IAT 场景需要; wkd 活代码侧 WpeResolveModuleExportName
 *       (PeAnalyzer.c) 已覆盖地址→导出名反查, 本实现保留 SS 完整逻辑。 */
static
NTSTATUS
WpeResolveApiByAddress(
    _In_  ULONG_PTR Address,
    _Out_writes_(NameLen) PWSTR Name,
    _In_  ULONG      NameLen
    )
{
    static const PCWSTR kDlls[] = {
        L"kernel32.dll", L"ntdll.dll", L"user32.dll", L"advapi32.dll",
        L"ws2_32.dll", L"shell32.dll", L"ole32.dll", L"gdi32.dll",
        L"comctl32.dll", L"msvcrt.dll"
    };
    ULONG i;

    if (Name == NULL || NameLen == 0) return STATUS_INVALID_PARAMETER;
    Name[0] = 0;

    for (i = 0; i < ARRAYSIZE(kDlls); i++) {
        HMODULE h = GetModuleHandleW(kDlls[i]);
        const BYTE* base;
        const IMAGE_DOS_HEADER* dos;
        const IMAGE_NT_HEADERS* nt;
        const IMAGE_EXPORT_DIRECTORY* exp;
        const DWORD* funcs;
        const DWORD* names;
        const WORD* ords;
        DWORD j, k;

        if (h == NULL) continue;
        base = (const BYTE*)h;
        dos = (const IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        nt = (const IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
        if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0 ||
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
            continue;
        }
        exp = (const IMAGE_EXPORT_DIRECTORY*)(
            base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        funcs = (const DWORD*)(base + exp->AddressOfFunctions);
        names = (const DWORD*)(base + exp->AddressOfNames);
        ords  = (const WORD*)(base + exp->AddressOfNameOrdinals);

        for (j = 0; j < exp->NumberOfFunctions; j++) {
            if ((ULONG_PTR)(base + funcs[j]) == Address) {
                for (k = 0; k < exp->NumberOfNames; k++) {
                    if (ords[k] == j) {
                        _snwprintf_s(Name, NameLen, _TRUNCATE, L"%s!%S",
                                     kDlls[i], (const char*)(base + names[k]));
                        return STATUS_SUCCESS;
                    }
                }
                _snwprintf_s(Name, NameLen, _TRUNCATE, L"%s!Ordinal%lu",
                             kDlls[i], j + exp->Base);
                return STATUS_SUCCESS;
            }
        }
    }
    return STATUS_NOT_FOUND;
}

/* -- WpeResolveApiByOrdinal (SS PackerUnpacker::ResolveAPIByOrdinal, 死代码)
 * 功能: 按序号反查指定 DLL 导出表还原 "dll!func" 名; 找不到返回 "dll!OrdinalN"
 *       (对齐 SS fallback 语义)。
 * 不接入原因: 同 IAT 重建 — 仅运行期/内存 dump 场景; 随 IAT 三件套死代码。 */
static
NTSTATUS
WpeResolveApiByOrdinal(
    _In_  PCWSTR DllName,
    _In_  USHORT Ordinal,
    _Out_writes_(NameLen) PWSTR Name,
    _In_  ULONG  NameLen
    )
{
    HMODULE h;
    const BYTE* base;
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS* nt;
    const IMAGE_EXPORT_DIRECTORY* exp;
    const DWORD* names;
    const WORD* ords;
    DWORD funcIndex;
    DWORD j;

    if (DllName == NULL || Name == NULL || NameLen == 0) return STATUS_INVALID_PARAMETER;
    Name[0] = 0;

    h = GetModuleHandleW(DllName);
    if (h == NULL) {
        _snwprintf_s(Name, NameLen, _TRUNCATE, L"%s!Ordinal%hu", DllName, Ordinal);
        return STATUS_NOT_FOUND;
    }
    base = (const BYTE*)h;
    dos = (const IMAGE_DOS_HEADER*)base;
    nt = (const IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0 ||
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
        _snwprintf_s(Name, NameLen, _TRUNCATE, L"%s!Ordinal%hu", DllName, Ordinal);
        return STATUS_NOT_FOUND;
    }
    exp = (const IMAGE_EXPORT_DIRECTORY*)(
        base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    funcIndex = (DWORD)Ordinal - (WORD)exp->Base;
    if (funcIndex >= exp->NumberOfFunctions) {
        _snwprintf_s(Name, NameLen, _TRUNCATE, L"%s!Ordinal%hu", DllName, Ordinal);
        return STATUS_NOT_FOUND;
    }
    names = (const DWORD*)(base + exp->AddressOfNames);
    ords  = (const WORD*)(base + exp->AddressOfNameOrdinals);
    for (j = 0; j < exp->NumberOfNames; j++) {
        if (ords[j] == funcIndex) {
            _snwprintf_s(Name, NameLen, _TRUNCATE, L"%s!%S", DllName,
                         (const char*)(base + names[j]));
            return STATUS_SUCCESS;
        }
    }
    _snwprintf_s(Name, NameLen, _TRUNCATE, L"%s!Ordinal%hu", DllName, Ordinal);
    return STATUS_NOT_FOUND;
}

/* -- WpeScanIatRange (SS PackerUnpacker::ScanIATRange, 死代码) -------------
 * 功能: 从 IAT 起始 RVA 起 8 字节对齐扫描已解析 API 地址 (非零槽),
 *       WpeResolveApiByAddress/ByOrdinal 反查还原, 完整填充 PE_IMPORT_LIST
 *       (NameBlob 扁平存储, 对齐 PeLazy PepParseImports 的输出约定)。
 * 不接入原因: 同 IAT 重建 — 仅运行期/内存 dump 场景有效; wkd 无该流程。
 *       输出用 WpeImportsFree (PeLazy.h) 释放。 */
static
NTSTATUS
WpeScanIatRange(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  const BYTE*              Data,
    _In_  SIZE_T                   DataSize,
    _In_  ULONG                    IatRva,
    _Out_ PPE_IMPORT_LIST         Out
    )
{
    typedef struct _IAT_ENTRY {
        ULONG_PTR Addr;
        ULONG     IatRva;
        WCHAR     Dll[PE_MAX_DLL_NAME];
        WCHAR     Func[PE_MAX_FUNCTION_NAME];
    } IAT_ENTRY;

    IAT_ENTRY* entries = NULL;
    ULONG entryCount = 0;
    PCWSTR dllNames[64];
    ULONG dllCount = 0;
    ULONG i, d;
    SIZE_T fileOff;
    PPE_IMPORT_DLL dlls = NULL;
    PWCHAR blob = NULL;
    SIZE_T blobChars = 0;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (Ctx == NULL || Data == NULL || Out == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));
    if (!IocpRvaToOffset(Ctx, IatRva, &fileOff)) return STATUS_NOT_FOUND;

    /* entries 含 512×4KB 函数名缓冲, 必须堆分配 (防栈溢出) */
    entries = (IAT_ENTRY*)calloc(512, sizeof(IAT_ENTRY));
    if (entries == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    /* 第一趟: 扫描解析 (cap 512 槽, 对齐 SS kMaxSlots) */
    for (i = 0; i < 16384 && entryCount < 512; i++) {
        ULONG64 value = 0;
        SIZE_T off = fileOff + (SIZE_T)i * sizeof(ULONG64);
        WCHAR name[256];
        PWSTR bang;
        if (off + sizeof(value) > DataSize) break;
        memcpy(&value, Data + off, sizeof(value));
        if (value == 0) { if (entryCount > 0) break; continue; }

        if (NT_SUCCESS(WpeResolveApiByAddress((ULONG_PTR)value, name, 256))) {
            bang = wcschr(name, L'!');
            if (bang == NULL) continue;
            *bang = 0;
            wcsncpy_s(entries[entryCount].Dll, PE_MAX_DLL_NAME, name, _TRUNCATE);
            wcsncpy_s(entries[entryCount].Func, PE_MAX_FUNCTION_NAME, bang + 1, _TRUNCATE);
            entries[entryCount].Addr = (ULONG_PTR)value;
            entries[entryCount].IatRva = IatRva + i * (ULONG)sizeof(ULONG64);
            entryCount++;
        }
    }
    if (entryCount == 0) goto done;

    /* 建 DLL 唯一列表 (cap 64) */
    for (i = 0; i < entryCount; i++) {
        BOOLEAN found = FALSE;
        for (d = 0; d < dllCount; d++) {
            if (_wcsicmp(dllNames[d], entries[i].Dll) == 0) { found = TRUE; break; }
        }
        if (!found && dllCount < 64) dllNames[dllCount++] = entries[i].Dll;
    }
    if (dllCount == 0) goto done;

    dlls = (PPE_IMPORT_DLL)calloc(dllCount, sizeof(PE_IMPORT_DLL));
    {
        SIZE_T totalChars = 0;
        for (d = 0; d < dllCount; d++) totalChars += wcslen(dllNames[d]) + 1;
        for (i = 0; i < entryCount; i++) totalChars += wcslen(entries[i].Func) + 1;
        blob = (PWCHAR)malloc(totalChars * sizeof(WCHAR));
    }
    if (dlls == NULL || blob == NULL) goto done;

    /* 填充 DLL 名到 NameBlob, 统计每 DLL 函数数并分配 Functions */
    for (d = 0; d < dllCount; d++) {
        SIZE_T len = wcslen(dllNames[d]);
        ULONG fc = 0;
        memcpy(blob + blobChars, dllNames[d], (len + 1) * sizeof(WCHAR));
        dlls[d].NameOffset = (ULONG)blobChars;
        dlls[d].NameLength = (ULONG)len;
        blobChars += len + 1;
        for (i = 0; i < entryCount; i++) {
            if (_wcsicmp(dllNames[d], entries[i].Dll) == 0) fc++;
        }
        dlls[d].Functions = (PPE_IMPORT_FUNC)calloc(fc, sizeof(PE_IMPORT_FUNC));
        dlls[d].FunctionCount = fc;
    }

    /* 填充函数名到 NameBlob + Functions */
    {
        ULONG idx[64] = { 0 };
        for (i = 0; i < entryCount; i++) {
            ULONG d2;
            PE_IMPORT_FUNC* fn;
            SIZE_T len;
            for (d2 = 0; d2 < dllCount; d2++) {
                if (_wcsicmp(dllNames[d2], entries[i].Dll) == 0) break;
            }
            if (d2 == dllCount || idx[d2] >= dlls[d2].FunctionCount) continue;
            fn = &dlls[d2].Functions[idx[d2]++];
            len = wcslen(entries[i].Func);
            fn->NameOffset = (ULONG)blobChars;
            fn->NameLength = (ULONG)len;
            memcpy(blob + blobChars, entries[i].Func, (len + 1) * sizeof(WCHAR));
            blobChars += len + 1;
            fn->Ordinal = 0;
            fn->Hint = 0;
            fn->ByOrdinal = FALSE;
            fn->IatRva = entries[i].IatRva;
        }
    }

    Out->DllCount = dllCount;
    Out->Dlls = dlls;
    Out->NameBlob = blob;
    Out->NameBlobChars = (ULONG)blobChars;
    dlls = NULL;      /* 所有权移交 Out (调用方 WpeImportsFree) */
    blob = NULL;
    status = STATUS_SUCCESS;

done:
    free(entries);
    free(dlls);
    free(blob);
    return status;
}

/* -- WpeReconstructImportsInternal (SS PackerUnpacker::ReconstructImportsInternal,
 *    死代码) --------------------------------------------------------------
 * 功能: IAT 重建编排入口 — FindIATStart → ScanIATRange → 输出 PE_IMPORT_LIST。
 * 不接入原因: 同 IAT 三件套 — 仅运行期/内存 dump 场景; wkd 无该流程。
 *       活代码侧 PepParseImports (PeLazy.c) 已覆盖文件导入表读取。 */
static
NTSTATUS
WpeReconstructImportsInternal(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  const BYTE*              Data,
    _In_  SIZE_T                   DataSize,
    _Out_ PPE_IMPORT_LIST         Out
    )
{
    ULONG iatRva = 0, iatSize = 0;

    if (Ctx == NULL || Data == NULL || Out == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));

    if (!NT_SUCCESS(WpeFindIatStart(Ctx, &iatRva, &iatSize))) {
        return STATUS_NOT_FOUND;
    }
    return WpeScanIatRange(Ctx, Data, DataSize, iatRva, Out);
}

/**************************************************/
/*  OEP 死代码区 (SS PackerUnpacker 补遗)           */
/**************************************************/

/* -- WpeUnpackIsLikelyOep (SS PackerUnpacker::IsLikelyOEP, 死代码) ----------
 * 功能: OEP 宽松启发式判定 — 检查代码开头是否为常见函数序言
 *       (PUSH EBP;MOV EBP,ESP / MOV EDI,EDI;PUSH EBP / SUB RSP,imm /
 *        REX.W SUB RSP / REX.W MOV [RSP..],RBX / PUSH reg)。
 * 不接入原因: 活代码 WpeUnpackDetectOepInPayload 已用精确模式扫描覆盖;
 *       本函数为 SS 的"宽松判定"变体, 供未来 OEP 候选复核用。 */
static
BOOLEAN
WpeUnpackIsLikelyOep(
    _In_  const BYTE* Code,
    _In_  SIZE_T      CodeSize
    )
{
    if (Code == NULL || CodeSize < 10) return FALSE;
    if (Code[0] == 0x55 && Code[1] == 0x8B && Code[2] == 0xEC) return TRUE;  /* PUSH EBP; MOV EBP,ESP */
    if (Code[0] == 0x8B && Code[1] == 0xFF && Code[2] == 0x55) return TRUE;  /* MOV EDI,EDI; PUSH EBP */
    if (Code[0] == 0x83 && Code[1] == 0xEC) return TRUE;                     /* SUB RSP,imm8 */
    if (Code[0] == 0x81 && Code[1] == 0xEC) return TRUE;                     /* SUB RSP,imm32 */
    if (Code[0] == 0x48 && Code[1] == 0x83 && Code[2] == 0xEC) return TRUE;  /* x64 REX.W SUB RSP,imm8 */
    if (Code[0] == 0x48 && Code[1] == 0x89 && Code[2] == 0x5C) return TRUE;  /* x64 MOV [RSP+..],RBX */
    if (Code[0] >= 0x50 && Code[0] <= 0x57) return TRUE;                     /* PUSH reg */
    return FALSE;
}

/* -- WpeFindOepViaEmulation (SS PackerUnpacker::FindOEPViaEmulation, 死代码)
 * 功能: 经 EmulationEngine 模拟执行定位 OEP — 从模拟解包层末层取
 *       unpackedEntryPoint (对齐 SS FindOEPViaEmulation)。
 * 不接入原因: 依赖独立 CPU 模拟器 (SS PhantomEmulator) 立项, 同 WpeEmulatePe
 *       骨架仅留档接口; 模拟器接入后从此函数返回末层入口点。 */
static
NTSTATUS
WpeFindOepViaEmulation(
    _In_  const BYTE* FileData,
    _In_  SIZE_T      FileSize,
    _Out_ PULONG      OutOepRva,
    _Out_ PBOOLEAN    Found
    )
{
    if (OutOepRva != NULL) *OutOepRva = 0;
    if (Found != NULL) *Found = FALSE;
    (void)FileData; (void)FileSize;
    return STATUS_NOT_IMPLEMENTED;
}

/**************************************************/
/*  动态解包死代码区 (SS EmulationEngine 接口留档)  */
/**************************************************/

NTSTATUS
WpeEmulatePe(
    _In_  const BYTE*            FileData,
    _In_  SIZE_T                 FileSize,
    _In_  const PE_EMU_CONFIG*  Config,
    _Out_ PPE_EMU_RESULT        Result
    )
/*++
Routine Description:
    动态解包骨架 (SS EmulationEngine 接口留档)。wkd 无 CPU 模拟器基础设施,
    依赖独立立项 (对齐 SS PhantomEmulator/Unicorn 类后端)。

Arguments:
    FileData - 待解包 PE 缓冲 (SS EmulatePE 输入)。
    FileSize - 缓冲大小。
    Config   - 解包配置 (对齐 EmulationConfig::CreateUnpackOnly:
               TimeoutMs=30000, MaxInstructions=1e8, UnpackOnly=TRUE,
               EnableApiTracing=FALSE)。
    Result   - 输出 (对齐 EmulationResult; unpackLayers[] 承载每层解包结果)。

Return Value:
    当前恒返回 STATUS_NOT_IMPLEMENTED。
--*/
{
    if (Result != NULL) RtlZeroMemory(Result, sizeof(*Result));
    (void)FileData; (void)FileSize; (void)Config;
    return STATUS_NOT_IMPLEMENTED;
}
