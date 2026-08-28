/**************************************************/
/*  WkDefender PEAnalyzer — 主解析器实现            */
/**************************************************/

#include "PeInternal.h"
#include "../../Common/FileUtils.h"

#include <math.h>

/* 内部地址换算 (WpeFinalizeDataDirectoryFileOffsets 先于定义调用, 前置声明) */
static
BOOLEAN
IocpRvaToOffsetInternal(
    _In_ const PE_PARSER_CONTEXT* Context,
    _In_ ULONG Rva,
    _Out_ PULONG Offset
    );

/**************************************************/
/*             静态辅助函数                         */
/**************************************************/

/*
 * WpeAddAnomalyToInfo — 累积异常到 Info (数组满则丢弃)。
 */
static
VOID
WpeAddAnomalyToInfo(
    _Inout_ PPE_PARSER_CONTEXT Context,
    _In_    PE_ANOMALY_TYPE   Type,
    _In_    PCWSTR             Desc
    )
{
    PE_INFO* info = &Context->Info;

    if (info->AnomalyCount < PE_MAX_ANOMALIES) {
        info->Anomalies[info->AnomalyCount].Type = Type;
        info->Anomalies[info->AnomalyCount].Description = Desc;
        info->Anomalies[info->AnomalyCount].Offset = 0;
        info->Anomalies[info->AnomalyCount].Context = NULL;
        info->AnomalyCount++;
    }
}

/*
 * WpeNowEpochSeconds — 当前 Unix 时间戳 (秒)。
 */
static
ULONG64
WpeNowEpochSeconds(
    VOID
    )
{
    FILETIME ft;
    ULONG64 t;

    GetSystemTimeAsFileTime(&ft);
    t = ((ULONG64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    /* 1601-01-01 到 1970-01-01 的 100ns 间隔数 */
    return (t - 116444736000000000ULL) / 10000000ULL;
}

/**************************************************/
/*             数据目录解析                         */
/**************************************************/

static
VOID
IocpParseDataDirectories32(
    _Inout_ PPE_PARSER_CONTEXT Context,
    _In_ const IMAGE_OPTIONAL_HEADER32* OptionalHeader32
    )
{
    PPE_INFO info;
    USHORT ddOffset, ddCount;

    if (!Context || !OptionalHeader32) {
        return STATUS_INVALID_PARAMETER;
    }

    info = &Context->Info;
    ddOffset = Context->OptionalHeaderOffset + offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
    ddCount = OptionalHeader32->NumberOfRvaAndSizes;

    /* 检查可选头是否有空间放数据目录 */
    /* 注意: 文件中的数据目录条目为原始 IMAGE_DATA_DIRECTORY (8 字节),
     * 增强版 IMAGE_DATA_DIRECTORY_EX (24 字节) 仅用于内存表示, 此处按原始布局读取。 */
    {
        ULONG ddBytes;
        if (!IocpMulU16Safe(ddCount, sizeof(IMAGE_DATA_DIRECTORY), &ddBytes)) {
            ddCount = 0;
        } /*else if (offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) + ddBytes > OptionalHeaderSize) {
            if (OptionalHeaderSize < offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory)) ddCount = 0;
            else ddCount = (OptionalHeaderSize - offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory)) /
                            sizeof(IMAGE_DATA_DIRECTORY);
        }*/
    }

    ddCount = min(ddCount, IMAGE_MAX_DIRECTORY_ENTRIES);
    for (ULONG i = 0; i < ddCount; i++) {
        IMAGE_DATA_DIRECTORY entry;
        if (IocpReaderReadBytes(&Context->Reader, ddOffset + i * sizeof(IMAGE_DATA_DIRECTORY),
                          &entry, sizeof(IMAGE_DATA_DIRECTORY))) {
            info->DataDirectories[i].Rva = entry.VirtualAddress;
            info->DataDirectories[i].Size = entry.Size;
            info->DataDirectories[i].Present = (entry.VirtualAddress != 0 || entry.Size != 0);
        }
    }
}

static
NTSTATUS
IocpParseDataDirectories64(
    _Inout_ PPE_PARSER_CONTEXT Context,
    _In_ PIMAGE_OPTIONAL_HEADER64 OptionalHeader64
    )
{
    PPE_INFO info;
    USHORT ddOffset, ddCount;

    if (!Context || !OptionalHeader64) {
        return STATUS_INVALID_PARAMETER;
    }

    info = &Context->Info;
    ddOffset = Context->OptionalHeaderOffset + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
    ddCount = OptionalHeader64->NumberOfRvaAndSizes;
    
    /* 这里的逻辑似乎有问题??? */
    {
        USHORT ddBytes;
        if (!IocpMulU16Safe(ddCount, sizeof(IMAGE_DATA_DIRECTORY), &ddBytes)) {
            ddCount = 0;
        } /*else if (offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) + ddBytes > OptionalHeaderSize) {
            if (OptionalHeaderSize < offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory)) ddCount = 0;
            else ddCount = (OptionalHeaderSize - offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory)) / 
                            sizeof(IMAGE_DATA_DIRECTORY);
        }*/
    }

    ddCount = min(ddCount, IMAGE_MAX_DIRECTORY_ENTRIES);
    for (ULONG i = 0; i < ddCount; i++) {
        IMAGE_DATA_DIRECTORY entry;
        if (IocpReaderReadBytes(&Context->Reader, ddOffset + i * sizeof(IMAGE_DATA_DIRECTORY),
                          &entry, sizeof(IMAGE_DATA_DIRECTORY))) {
            info->DataDirectories[i].Rva = entry.VirtualAddress;
            info->DataDirectories[i].Size = entry.Size;
            info->DataDirectories[i].Present = (entry.VirtualAddress != 0 || entry.Size != 0);
        }
    }
}

/*
 * WpeFinalizeDataDirectoryFileOffsets — 数据目录 RVA→文件偏移定稿。
 * SECURITY 目录的 VA 实为文件偏移 (PE 规范例外)。
 */
static
VOID
WpeFinalizeDataDirectoryFileOffsets(
    _Inout_ PPE_PARSER_CONTEXT Context
    )
{
    if (!Context) return;

    for (ULONG i = 0; i < IMAGE_MAX_DIRECTORY_ENTRIES; i++) {
        PIMAGE_DATA_DIRECTORY_EX dir = &Context->Info.DataDirectories[i];
        SIZE_T off = 0;

        dir->HasFileOffset = FALSE;
        dir->FileOffset = MAXULONG32;
        if (!dir->Present || dir->Rva == 0) continue;

        if (i == IMAGE_DIRECTORY_ENTRY_SECURITY) {
            SIZE_T certEnd = 0;
            if (WpeSafeAddU64((ULONG64)dir->Rva, (ULONG64)dir->Size, &certEnd) &&
                certEnd <= (ULONG64)Context->Reader.Size) {
                dir->FileOffset = dir->Rva;
                dir->HasFileOffset = TRUE;
            }
            continue;
        }

        if (IocpRvaToOffsetInternal(Context, dir->Rva, &off)) {
            dir->FileOffset = (ULONG64)off;
            dir->HasFileOffset = TRUE;
        }
    }
}

/**************************************************/
/*             节表解析                             */
/**************************************************/

static
NTSTATUS
IocpParseSections(
    _Inout_ PPE_PARSER_CONTEXT Context
    )
{
    PPE_INFO info;
    USHORT numberOfSections;

    if (!Context) return STATUS_INVALID_PARAMETER;  
    info = &Context->Info;

    /* 节表大小溢出与越界 */
    {
        USHORT tableSize;

        if (!IocpMulU16Safe(info->NumberOfSections, (USHORT)sizeof(IMAGE_SECTION_HEADER), &tableSize)) {
            Context->Error.Code = WpeVal_SectionTableOverflow;
            Context->Error.Message = L"Section table size overflow";
            Context->Error.Offset = Context->SectionTableOffset;
            return STATUS_INTEGER_OVERFLOW;
        }

        if (!NT_SUCCESS(CopValidateReadingRange(&Context->Reader, Context->SectionTableOffset, tableSize))) {
            Context->Error.Code = WpeVal_SectionTableOutOfBounds;
            Context->Error.Message = L"Section table extends beyond file";
            Context->Error.Offset = Context->SectionTableOffset;
            return STATUS_BUFFER_OVERFLOW;
        }
    }

    numberOfSections = min(info->NumberOfSections, PE_MAX_SECTIONS);
    for (ULONG i = 0; i < numberOfSections; i++) {
        IMAGE_SECTION_HEADER section;
        PPE_SECTION out;
        SIZE_T offset = Context->SectionTableOffset + i * sizeof(IMAGE_SECTION_HEADER);
        PE_VALIDATION_RESULT result;

        if (!IocpReaderReadBytes(&Context->Reader, offset, &section, sizeof(IMAGE_SECTION_HEADER))) {
            Context->Error.Code = WpeVal_SectionTableOutOfBounds;
            Context->Error.Message = L"Cannot read section header";
            Context->Error.Offset = offset;
            return STATUS_ACCESS_VIOLATION;
        }

        if (Context->RawSectionCount < PE_MAX_SECTIONS) {
            Context->RawSections[Context->RawSectionCount++] = section;
        }

        out = &info->Sections[info->NumberOfSections];
        RtlZeroMemory(out, sizeof(PE_SECTION));

        /* 内存模式下 raw 文件边界校验无意义 (PointerToRawData 是文件偏移),
         * 传 SIZE_MAX 使 raw 越界检查恒通过; 虚拟边界检查仍用 SizeOfImage。 */
        result = IocpValidateSectionHeader(&section,
                                      (Context->IsMemoryMode) ? (SIZE_T)-1 : (SIZE_T)Context->Reader.Size,
                                      info->SizeOfImage,
                                      info->FileAlignment, i, &Context->Error,
                                      (Context->Options.CollectAnomalies) ? info->Anomalies : NULL,
                                      &info->AnomalyCount, PE_MAX_ANOMALIES);
        if (result != WpeVal_Valid) {
            return FALSE;
        }

        /* section.name */
        RtlCopyMemory(out->Name, section.Name, PE_MAX_SECTION_NAME);
        out->Name[PE_MAX_SECTION_NAME] = '\0';

        out->VirtualSize = section.Misc.VirtualSize;
        out->VirtualAddress = section.VirtualAddress;
        out->PointerToRawData = section.PointerToRawData;
        out->SizeOfRawData = section.SizeOfRawData;
        out->Characteristics = section.Characteristics;
        out->IsExecutable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        out->IsWritable = (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        out->IsReadable = (section.Characteristics & IMAGE_SCN_MEM_READ) != 0;
        out->HasCode = (section.Characteristics & IMAGE_SCN_CNT_CODE) != 0;
        out->HasInitializedData = (section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;
        out->HasUninitializedData = (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;

        /* W+X */
        if (out->IsExecutable && out->IsWritable) {
            WpeAddAnomalyToInfo(Context, WpeAnom_SectionWritableExecutable,
                                L"Section is both writable and executable");
        }

        info->NumberOfSections++;
    }

    /* 重叠检测 */
    {
        PE_SECTION_OVERLAP overlaps[64];
        ULONG overlapCount = 0;
        if (WpeCheckSectionOverlaps(Context->RawSections, Context->RawSectionCount,
                                    overlaps, &overlapCount, 64)) {
            ULONG k;
            for (k = 0; k < overlapCount; k++) {
                if (Context->Options.AnalyzeContentAnomalies) {
                    /* 独立重叠异常 (对齐 SS DetectOverlappingSectionsImpl, severity 75) */
                    WpeAddAnomalyToInfo(Context, WpeAnom_OverlappingSections,
                        L"Sections overlap in file — strong malware indicator");
                } else {
                    WpeAddAnomalyToInfo(Context, WpeAnom_UnusualSectionOrder, L"Sections overlap in file");
                }
            }
        }
    }

    /* 逐节熵 + 加壳启发 (门控) */
    if (Context->Options.ComputeSectionEntropy) {
        for (ULONG i = 0; i < info->NumberOfSections; i++) {
            PPE_SECTION section = &info->Sections[i];
            if (section->SizeOfRawData > 0 && section->PointerToRawData != 0) {
                ULONG offset = section->PointerToRawData;
                ULONG size = section->SizeOfRawData;
                BYTE* sbuf = (BYTE*)malloc(size);
                if (sbuf != NULL) {
                    if (CopValidateReadingRange(&Context->Reader, offset, size) &&
                        IocpReaderReadBytes((PPE_READER)&Context->Reader, offset, sbuf, size)) {
                        section->ShannonEntropy = CoEntropyCalculate(sbuf, size, CoEntropyAlphabet_Byte, 0);
                    } else {
                        section->ShannonEntropy = 0.0;
                    }
                    free(sbuf);
                } else {
                    section->ShannonEntropy = 0.0;
                }
                section->IsPackedHeuristic = (section->ShannonEntropy > 7.0 &&
                                          (section->IsExecutable || section->HasCode));
                if (section->ShannonEntropy > 7.2) {
                    WpeAddAnomalyToInfo(Context, WpeAnom_SectionHighEntropy,
                        L"Section has very high entropy (>7.2) — likely packed or encrypted");
                }
            }
        }
    }

    return TRUE;
}

/**************************************************/
/*             入口点分析                           */
/**************************************************/

static
VOID
IocpParseEntryPoint(
    _Inout_ PPE_PARSER_CONTEXT Context
    )
{
    PPE_INFO info;
    
    if (!Context) return;
    info = &Context->Info;

    if (info->AddressOfEntryPoint == 0) {
        /* 零入口点对 DLL 合法 */
        if (!info->IsDll) {
            WpeAddAnomalyToInfo(Context, WpeAnom_EntryPointZero, L"Entry point is zero");
        }
        return;
    }

    for (ULONG i = 0; i < info->NumberOfSections; i++) {
        PPE_SECTION sectoin = &info->Sections[i];
        ULONG sectionStart = sectoin->VirtualAddress;
        ULONG sectionSize = sectoin->VirtualSize > 0 ? 
                            sectoin->VirtualSize : sectoin->SizeOfRawData;
        ULONG secEnd = sectionStart + sectionSize;

        if (info->AddressOfEntryPoint >= sectionStart &&
            info->AddressOfEntryPoint < secEnd) {
            info->EntryPointSectionIndex = i;
            info->EntryPointInExecutableSection = sectoin->IsExecutable;

            if (i == info->NumberOfSections - 1) {
                WpeAddAnomalyToInfo(Context, WpeAnom_EntryPointInLastSection,
                                    L"Entry point in last section (packer indicator)");
            }
            if (sectoin->IsWritable) {
                WpeAddAnomalyToInfo(Context, WpeAnom_EntryPointInWritableSection,
                                    L"Entry point in writable section");
            }
            if (!sectoin->IsExecutable) {
                WpeAddAnomalyToInfo(Context, WpeAnom_CodeOutsideCodeSection,
                                    L"Entry point in non-executable section");
            }
            return;
        }
    }

    /* 入口点不在任何节 */
    if (info->AddressOfEntryPoint < info->SizeOfHeaders) {
        WpeAddAnomalyToInfo(Context, WpeAnom_EntryPointInHeader, L"Entry point in PE header");
    } else {
        WpeAddAnomalyToInfo(Context, WpeAnom_EntryPointOutsideFile, L"Entry point outside all sections");
    }
}

/**************************************************/
/*         Authenticode 结构级验证                  */
/**************************************************/

static
VOID
IocpVerifyPeAuthenticode(
    _Inout_ PPE_PARSER_CONTEXT Context
    )
{
    if (!Context) return;

    PPE_INFO info = &Context->Info;
    PIMAGE_DATA_DIRECTORY_EX securityDirectory = &info->DataDirectories[IMAGE_DIRECTORY_ENTRY_SECURITY];
    
    if (!securityDirectory->Present) return;

    /* SECURITY 目录用文件偏移 (非 RVA) — PE 规范例外 */
    {
        WIN_CERTIFICATE certificate;
        ULONG certFileOffset = securityDirectory->Rva;
        if (certFileOffset > 0 && securityDirectory->Size >= sizeof(WIN_CERTIFICATE) &&
            CopValidateReadingRange(&Context->Reader, certFileOffset, securityDirectory->Size)) {
            if (IocpReaderReadBytes(&Context->Reader, certFileOffset, &certificate, sizeof(WIN_CERTIFICATE))) {
            
            if (certificate.wRevision == WIN_CERT_REVISION_2_0 &&
                /* WIN_CERTIFICATE::bCertificate 指向一个完整的 PKCS#7 / CMS（加密消息语法） 签名结构。
                 * 它内部包含了对文件哈希值的签名、完整的证书链（含中间证书）、以及吊销列表（CRL）信息。
                 * 用于标准的 Authenticode（数字签名）验证。
                 * Windows 的资源管理器、WinVerifyTrust 函数都是针对这种格式设计的。*/
                // ❌ WIN_CERT_TYPE_X509 - 最早期（如 Windows CE 或非常古老的 NT 版本）的设计，仅包含一个原始的 X.509 裸证书，不具备防篡改验证能力，已淘汰。
                // ❌ WIN_CERT_TYPE_RESERVED_1 - 保留项
                // WIN_CERT_TYPE_PKCS1_SIGN - 内核引导专用精简签名
                certificate.wCertificateType == WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
                info->IsSigned = TRUE;
            }
            }
        }
    }
}

/**************************************************/
/*             Overlay 检测                         */
/**************************************************/

static
VOID
WpeDetectOverlay(
    _Inout_ PPE_PARSER_CONTEXT Context
    )
/*++
    检测最后一个节之后的多余数据（Overlay）
    攻击者常将恶意载荷（dropper、shellcode、加密 blob、第二个 PE）附加在合法签名文件末尾——因为签名只覆盖节区，
    不覆盖 overlay，白名单/哈希校验往往忽略它。本函数负责发现并分析这部分数据。
--*/
{
    PE_INFO* info = &Context->Info;
    SIZE_T lastSectionEnd = 0;
    SIZE_T overlayStart;
    ULONG i;

    if (info->NumberOfSections == 0) return;

    /* 末节文件尾 */
    for (i = 0; i < info->NumberOfSections; i++) {
        PE_SECTION* sec = &info->Sections[i];
        SIZE_T secEnd;
        if (IocpAddSizeSafe((SIZE_T)sec->SizeOfRawData, (SIZE_T)sec->SizeOfRawData, &secEnd) &&
            secEnd > lastSectionEnd) {
            lastSectionEnd = secEnd;
        }
    }
    overlayStart = lastSectionEnd;

    /* Authenticode 证书位于映像后, 紧邻末节时排除 (非 overlay) */
    {
        IMAGE_DATA_DIRECTORY_EX* secDir = &info->DataDirectories[PE_DD_SECURITY];
        if (secDir->Present && secDir->Rva != 0 && secDir->Size >= sizeof(WIN_CERTIFICATE)) {
            SIZE_T certEnd;
            SIZE_T certStart = (SIZE_T)secDir->Rva;
            if (certStart == overlayStart &&
                IocpAddSizeSafe(certStart, (SIZE_T)secDir->Size, &certEnd) &&
                certEnd <= (SIZE_T)info->FileSize) {
                overlayStart = certEnd;
            }
        }
    }

    if (overlayStart < (SIZE_T)info->FileSize) {
        info->OverlayOffset = overlayStart;
        info->OverlaySize = info->FileSize - overlayStart;

        if (info->OverlaySize > 0) {
            WpeAddAnomalyToInfo(Context, WpeAnom_OverlayPresent, L"File has overlay data");

            /* overlay 内嵌 PE (dropper) + 大 overlay (>1MB) — 对齐 SS AnalyzeOverlayImpl
             * L3398-3418 / DetectAnomaliesImpl L2341-2350, 门控 AnalyzeContentAnomalies */
            if (Context->Options.AnalyzeContentAnomalies) {
                USHORT mz;
                if (info->OverlaySize >= sizeof(IMAGE_DOS_HEADER) &&
                    IocpReaderReadBytes(&Context->Reader, (ULONGLONG)info->OverlayOffset, &mz, sizeof(USHORT)) &&
                    mz == IMAGE_DOS_SIGNATURE) {
                    info->OverlayContainsPE = TRUE;
                    WpeAddAnomalyToInfo(Context, WpeAnom_OverlayContainsPE,
                        L"Overlay contains embedded PE (dropper indicator)");
                }
                if (info->OverlaySize > 1024 * 1024) {
                    WpeAddAnomalyToInfo(Context, WpeAnom_LargeOverlay,
                        L"Large overlay detected (>1MB)");
                }
            }

            /* overlay 熵 (采样 1MB) — 高熵指示嵌入加密/压缩载荷 */
            {
                SIZE_T sampleSize = (SIZE_T)info->OverlaySize;
                BYTE* buf;
                if (sampleSize > 1024 * 1024) sampleSize = 1024 * 1024;
                if (CopValidateReadingRange(&Context->Reader, info->OverlayOffset, sampleSize)) {
                    buf = (BYTE*)malloc(sampleSize);
                    if (buf) {
                        if (IocpReaderReadBytes(&Context->Reader, info->OverlayOffset, buf, sampleSize)) {
                            DOUBLE entropy = CoEntropyCalculate(buf, sampleSize, CoEntropyAlphabet_Byte, 0);
                            if (entropy > 7.0) {
                                WpeAddAnomalyToInfo(Context, WpeAnom_OverlayHighEntropy,
                                    L"Overlay data has high entropy (>7.0) — encrypted/compressed payload");
                            }
                        }
                        free(buf);
                    }
                }
            }
        }
    }
}

/**************************************************/
/*             Anomaly 收集                         */
/**************************************************/

static
VOID
WpeDetectAnomalies(
    _Inout_ PPE_PARSER_CONTEXT Context
    )
{
    PE_INFO* info = &Context->Info;
    ULONG i;

    /* 时间戳 */
    if (info->TimeDateStamp == 0) {
        WpeAddAnomalyToInfo(Context, WpeAnom_TimestampZero, L"Timestamp is zero");
    } else {
        ULONG64 nowEpoch = WpeNowEpochSeconds();
        if (info->TimeDateStamp > nowEpoch + 86400) {
            WpeAddAnomalyToInfo(Context, WpeAnom_TimestampInFuture, L"Timestamp is in the future");
        }
        if (info->TimeDateStamp < 788918400) {   /* 1995-01-01 */
            WpeAddAnomalyToInfo(Context, WpeAnom_TimestampVeryOld, L"Timestamp is suspiciously old");
        }
    }

    /* 安全特性 */
    if ((info->DllCharacteristics & PE_DLLC_DYNAMIC_BASE) == 0) {
        WpeAddAnomalyToInfo(Context, WpeAnom_NoASLR, L"ASLR not enabled");
    }
    if ((info->DllCharacteristics & PE_DLLC_NX_COMPAT) == 0) {
        WpeAddAnomalyToInfo(Context, WpeAnom_NoDEP, L"DEP/NX not enabled");
    }
    /* NoCFG: 2014-01-01 后编译且非 .NET (CLR 自带控制流模型) */
    {
        static const ULONG kCfgEpoch = 1388534400u;   /* 2014-01-01 UTC */
        if (!info->IsDotNet && info->TimeDateStamp > kCfgEpoch &&
            (info->DllCharacteristics & PE_DLLC_GUARD_CF) == 0) {
            WpeAddAnomalyToInfo(Context, WpeAnom_NoCFG,
                L"Control Flow Guard (GUARD_CF) not enabled on modern binary (post-2014)");
        }
    }
    /* NoSEH: 非 DLL/驱动/.NET 且无 NO_SEH */
    if (!info->IsDll && !info->IsDriver && !info->IsDotNet &&
        (info->DllCharacteristics & PE_DLLC_NO_SEH) == 0) {
        WpeAddAnomalyToInfo(Context, WpeAnom_NoSEH,
            L"NO_SEH flag not set; executable may contain exploitable SEH handlers");
    }
    /* 驱动无校验和 */
    if (info->Checksum == 0 && info->IsDriver) {
        WpeAddAnomalyToInfo(Context, WpeAnom_WeakChecksum, L"Driver has no checksum");
    }

    /* 节名检查 */
    for (i = 0; i < info->NumberOfSections; i++) {
        PE_SECTION* sec = &info->Sections[i];
        if (sec->Name[0] == '\0') {
            WpeAddAnomalyToInfo(Context, WpeAnom_SectionNameEmpty, L"Section has empty name");
        } else {
            BOOLEAN hasNonPrintable = FALSE;
            ULONG k;
            for (k = 0; k < sizeof(sec->Name) && sec->Name[k] != '\0'; k++) {
                UCHAR c = (UCHAR)sec->Name[k];
                if (c < 0x20 || c > 0x7E) {
                    hasNonPrintable = TRUE;
                    break;
                }
            }
            if (hasNonPrintable) {
                WpeAddAnomalyToInfo(Context, WpeAnom_SectionNameNonPrintable,
                                    L"Section has non-printable characters in name");
            }

            /* 已知 packer/protector 节名签名 */
            {
                static const PCSTR kSuspiciousNames[] = {
                    "UPX0", "UPX1", "UPX2", "UPX!",
                    ".aspack", ".adata",
                    ".nsp0", ".nsp1", ".nsp2",
                    ".packed", ".RLPack",
                    ".petite",
                    ".yP", ".y0da",
                    "pebundle", "PEBundle",
                    ".Themida", ".Winlice",
                    ".vmp0", ".vmp1", ".vmp2",
                    ".enigma1", ".enigma2",
                    "MEW",
                    ".MPRESS1", ".MPRESS2",
                    ".perplex",
                    ".sforce",
                    "BitArts", ".boom",
                    ".ndata",
                    /* SS PackerUnpacker m_packerSectionNames 补漏 (2026-08) */
                    ".winlice",           /* SS 小写变体 */
                    ".pespin",
                    "FSG!",
                    "petite",             /* SS 无点变体 */
                    ".mpress1",           /* SS 小写变体 */
                };
                for (k = 0; k < ARRAYSIZE(kSuspiciousNames); k++) {
                    if (strcmp(sec->Name, kSuspiciousNames[k]) == 0) {
                        WpeAddAnomalyToInfo(Context, WpeAnom_SectionNameSuspicious,
                            L"Section name matches known packer/protector signature");
                        break;
                    }
                }
            }
        }
    }

    /* 无导入 (对多数可执行文件可疑) */
    if (!info->DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Present && !info->IsDll) {
        WpeAddAnomalyToInfo(Context, WpeAnom_NoImports, L"No import table");
    }

    /* 加壳启发聚合 */
    {
        SIZE_T packedSections = 0;
        SIZE_T execSections = 0;
        for (i = 0; i < info->NumberOfSections; i++) {
            PE_SECTION* sec = &info->Sections[i];
            if (sec->IsExecutable || sec->HasCode) {
                execSections++;
                if (sec->IsPackedHeuristic) packedSections++;
            }
        }
        if (execSections > 0 && packedSections > 0 &&
            packedSections >= (execSections + 1) / 2) {
            WpeAddAnomalyToInfo(Context, WpeAnom_PackerSignatureDetected,
                L"Majority of executable sections show high entropy — likely packed");
        }
    }

    /* API hashing / shellcode 指示: 无导入 + 高熵 — 对齐 SS DetectAnomaliesImpl L2391-2402
     * (avgEntropy >= 6.8 → APIHashing), 门控 AnalyzeContentAnomalies */
    if (Context->Options.AnalyzeContentAnomalies &&
        !info->DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Present && !info->IsDll) {
        DOUBLE avgEntropy = 0.0;
        ULONG entropyCount = 0;
        ULONG si;
        for (si = 0; si < info->NumberOfSections; si++) {
            if (info->Sections[si].ShannonEntropy >= 0.0) {
                avgEntropy += info->Sections[si].ShannonEntropy;
                entropyCount++;
            }
        }
        if (entropyCount > 0) avgEntropy /= entropyCount;
        if (avgEntropy >= 6.8) {
            WpeAddAnomalyToInfo(Context, WpeAnom_ApiHashing,
                L"No imports + high entropy — possible shellcode or API hashing");
        }
    }

    /* TLS 回调异常 (对齐 SS DetectAnomaliesImpl L2352-2363: hasTLSCallbacks → TLSCallbackPresent,
     * severity 55 anti-analysis), 门控 AnalyzeContentAnomalies 防改变既有扫描分 */
    if (Context->Options.AnalyzeContentAnomalies &&
        info->DataDirectories[PE_DD_TLS].Present) {
        WpeAddAnomalyToInfo(Context, WpeAnom_TLSCallbackPresent,
            L"TLS callbacks present — common anti-analysis / pre-main execution");
    }
}

/**************************************************/
/*             地址换算 (内部)                      */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
IocpRvaToOffsetInternal(
    _In_ const PE_PARSER_CONTEXT* Context,
    _In_ ULONG Rva,
    _Out_ PULONG Offset
    )
{
    if (!Context || !Offset || Rva == 0) return FALSE;
    *Offset = 0;

    if (Context->IsMemoryMode) {
        /* 内存模式: RVA 恒等 (offset 语义 = RVA, 由 reader 加基址) */
        *Offset = Rva;
        return TRUE;
    }

    /* 头区 */
    if (Rva < Context->Info.SizeOfHeaders) {
        *Offset = Rva;
        return TRUE;
    }

    /* 找含 RVA 的节 */
    for (ULONG i = 0; i < Context->RawSectionCount; i++) {
        const IMAGE_SECTION_HEADER* section = &Context->RawSections[i];
        ULONG secVa = section->VirtualAddress;
        ULONG secVSize = section->Misc.VirtualSize;

        if (secVSize == 0) secVSize = section->SizeOfRawData;

        if (Rva >= secVa && Rva < secVa + secVSize) {
            ULONG sectionOffset = Rva - secVa;
            if (sectionOffset < section->SizeOfRawData) {
                ULONG fileOffset;
                if (IocpAddU32Safe(section->PointerToRawData,
                                 sectionOffset, &fileOffset) &&
                    fileOffset < Context->Reader.Size) {
                    *Offset = fileOffset;
                    return TRUE;
                }
            }
            return FALSE;   /* RVA 在 virtual-only 部分 */
        }
    }

    return FALSE;
}

/**************************************************/
/*             主解析流程 (10 步)                   */
/**************************************************/

PE_PARSE_OPTIONS
IocDefaultPeParseOptions(
    VOID
    )
/*++
Routine Description:
    返回默认解析选项 (CollectAnomalies/DetectOverlay/VerifyChecksum=TRUE)。

Return Value:
    默认选项。
--*/
{
    PE_PARSE_OPTIONS opts;

    RtlZeroMemory(&opts, sizeof(PE_PARSE_OPTIONS));
    opts.CollectAnomalies = TRUE;
    opts.DetectOverlay = TRUE;
    opts.VerifyChecksum = TRUE;
    return opts;
}

/*
 * WpeParseDotNetFramework — 读 COR20 MetaData → BSJB 签名 → 目标框架版本串。
 * 对齐 SS ParseDotNetImpl L2044-2067 (corHeader->MetaData, BSJB @0, 版本串 @+16)。
 */
static
VOID
WpeParseDotNetFramework(
    _Inout_ PPE_PARSER_CONTEXT Context
    )
{
    PE_INFO* info = &Context->Info;
    IMAGE_DATA_DIRECTORY_EX* clrDir = &info->DataDirectories[PE_DD_COM_DESCRIPTOR];
    PE_CLR_HEADER cor;
    SIZE_T clrOffset;
    SIZE_T metaOffset;
    ULONG metaSig;
    ULONG versionLen;
    CHAR version[PE_MAX_DOTNET_FRAMEWORK];

    if (!clrDir->Present || clrDir->Rva == 0 || clrDir->Size < sizeof(PE_CLR_HEADER)) return;
    if (!IocpRvaToOffset(Context, clrDir->Rva, &clrOffset)) return;
    if (!IocpReaderReadBytes(&Context->Reader, clrOffset, &cor, sizeof(cor))) return;

    if (cor.MetaData.VirtualAddress == 0 || cor.MetaData.Size < 20) return;
    if (!IocpRvaToOffset(Context, cor.MetaData.VirtualAddress, &metaOffset)) return;
    if (metaOffset + 16 > Context->Reader.Size) return;

    /* BSJB 签名 */
    if (!IocpReaderReadBytes(&Context->Reader, metaOffset, &metaSig, sizeof(ULONG)) || metaSig != 0x424A5342) return;

    /* 版本串: @+12 length, @+16 string (含 NUL 终止需 <64) */
    if (!IocpReaderReadBytes(&Context->Reader, metaOffset + 12, &versionLen, sizeof(ULONG))) return;
    if (versionLen == 0 || versionLen >= PE_MAX_DOTNET_FRAMEWORK) return;
    if (metaOffset + 16 + versionLen > Context->Reader.Size) return;
        if (!IocpReaderReadBytes(&Context->Reader, metaOffset + 16, version, versionLen)) return;
    version[versionLen] = 0;

    /* 拷贝到 Info (剔控制字符, 防日志注入) */
    {
        ULONG outIdx = 0;
        ULONG k;
        for (k = 0; k < versionLen && outIdx < PE_MAX_DOTNET_FRAMEWORK - 1; k++) {
            UCHAR c = (UCHAR)version[k];
            if (c >= 0x20 && c != 0x7F) info->DotNetTargetFramework[outIdx++] = (CHAR)c;
        }
        info->DotNetTargetFramework[outIdx] = 0;
    }
}

/*
 * WpeDetectResourceContentAnomalies — 遍历资源做内容级异常发射。
 * 对齐 SS ParseResourcesImpl: 内嵌 PE → ResourcesContainPE / 熵>=7.2 → ResourcesHighEntropy /
 * 单资源>16MB → ResourceSizeAnomaly (枚举已有, 原零发射)。
 */
/* WpeDetectResourceContentAnomalies — 遍历资源做内容级异常发射。
 * 对齐 SS ParseResourcesImpl: 内嵌 PE → ResourcesContainPE / 熵>=7.2 → ResourcesHighEntropy /
 * 单资源>16MB → ResourceSizeAnomaly (枚举已有, 原零发射)。
 * 非 static (2026-08-19): 供深度分析 IocHeuristicPeAnalysis 接线 —
 * 构建期解析 (IocAnalyzePeFromFilePath, AnalyzeContentAnomalies=FALSE) 不执行本检测，
 * 深度分析在重建 Ctx 上补调用使资源内嵌 PE 强信号 (AnomalyScore +160) 生效。 */
VOID
WpeDetectResourceContentAnomalies(
    _Inout_ PPE_PARSER_CONTEXT Context
    )
{
    PE_RESOURCE_LIST list;
    ULONG i;
    NTSTATUS status;

    RtlZeroMemory(&list, sizeof(list));
    status = WpeParseResources(Context, 3, &list);
    if (!NT_SUCCESS(status)) return;

    for (i = 0; i < list.EntryCount; i++) {
        const PE_RESOURCE_ENTRY* re = &list.Entries[i];
        if (re->ContainsPE) {
            WpeAddAnomalyToInfo(Context, WpeAnom_ResourcesContainPE,
                L"Resource contains embedded PE (dropper indicator)");
        }
        if (re->Entropy >= 7.2) {
            WpeAddAnomalyToInfo(Context, WpeAnom_ResourcesHighEntropy,
                L"Resource has high entropy (>7.2) — likely encrypted payload");
        }
        if (re->Size > 0x1000000u) {
            WpeAddAnomalyToInfo(Context, WpeAnom_ResourceSizeAnomaly,
                L"Resource size exceeds 16MB");
        }
    }
    WpeResourcesFree(&list);
}

static
NTSTATUS
IocpParsePe(
    _Inout_ PPE_PARSER_CONTEXT Context
    )
{
    PPE_INFO info;
    INT32 lfanew = 0;
    IMAGE_FILE_HEADER fileHeader = { 0 };
    PE_VALIDATION_RESULT result;
    BOOLEAN is64Bit = FALSE;
    LARGE_INTEGER qpcStart, qpcEnd, qpcFreq;

    if (!Context) return STATUS_INVALID_PARAMETER;

    /* 解析耗时采样 (Step 8 后用于计算 ParseTimeNs) */
    QueryPerformanceFrequency(&qpcFreq);
    QueryPerformanceCounter(&qpcStart);

    /* 重置 */
    info = &Context->Info;
    RtlZeroMemory(info, sizeof(PE_INFO));
    info->FileSize = Context->Reader.Size;
    info->EntryPointSectionIndex = ULONG_MAX;
    Context->Parsed = FALSE;
    Context->RawSectionCount = 0;
    Context->NtHeaderOffset = 0;
    Context->OptionalHeaderOffset = 0;
    Context->SectionTableOffset = 0;

    /* Step 1: DOS 头 */
    result = IocpValidateDosHeader(&Context->Reader, &lfanew, &Context->Error);
    if (result != WpeVal_Valid) return STATUS_INVALID_IMAGE_FORMAT;
    Context->NtHeaderOffset = (ULONG)lfanew;

    /* Step 2: NT 头 */
    result = IocpValidateNtHeaders(&Context->Reader, 
                                Context->NtHeaderOffset, &is64Bit, &fileHeader, &Context->Error);
    if (result != WpeVal_Valid) return STATUS_INVALID_IMAGE_FORMAT;

    info->Amd64 = is64Bit;
    info->Machine = fileHeader.Machine;
    info->NumberOfSections = fileHeader.NumberOfSections;
    info->Characteristics = fileHeader.Characteristics;
    info->TimeDateStamp = fileHeader.TimeDateStamp;
    info->IsDll = (fileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

    /* Step 3: 可选头 + 数据目录 */
    Context->OptionalHeaderOffset = Context->NtHeaderOffset + offsetof(IMAGE_NT_HEADERS, OptionalHeader);

    if (is64Bit) {
        IMAGE_OPTIONAL_HEADER64 opt64 = { 0 };

        result = IocpValidateOptionalHeader64(&Context->Reader,
                                            Context->OptionalHeaderOffset,
                                            &opt64, &Context->Error);
        if (result != WpeVal_Valid) return STATUS_INVALID_IMAGE_FORMAT;

        info->ImageBase = opt64.ImageBase;
        info->AddressOfEntryPoint = opt64.AddressOfEntryPoint;
        info->SizeOfImage = opt64.SizeOfImage;
        info->SizeOfHeaders = opt64.SizeOfHeaders;
        info->Checksum = opt64.CheckSum;
        info->Subsystem = opt64.Subsystem;
        info->DllCharacteristics = opt64.DllCharacteristics;
        info->FileAlignment = opt64.FileAlignment;
        info->SectionAlignment = opt64.SectionAlignment;
        info->MajorLinkerVersion = opt64.MajorLinkerVersion;
        info->MinorLinkerVersion = opt64.MinorLinkerVersion;
        info->MajorOsVersion = opt64.MajorOperatingSystemVersion;
        info->MinorOsVersion = opt64.MinorOperatingSystemVersion;
        IocpParseDataDirectories64(Context, &opt64);
    } else {
        IMAGE_OPTIONAL_HEADER32 opt32 = { 0 };

        result = IocpValidateOptionalHeader32(&Context->Reader,
                                            fileHeader.SizeOfOptionalHeader,
                                            &opt32, &Context->Error);
        if (result != WpeVal_Valid) return STATUS_INVALID_IMAGE_FORMAT;

        info->ImageBase = opt32.ImageBase;
        info->AddressOfEntryPoint = opt32.AddressOfEntryPoint;
        info->SizeOfImage = opt32.SizeOfImage;
        info->SizeOfHeaders = opt32.SizeOfHeaders;
        info->Checksum = opt32.CheckSum;
        info->Subsystem = opt32.Subsystem;
        info->DllCharacteristics = opt32.DllCharacteristics;
        info->FileAlignment = opt32.FileAlignment;
        info->SectionAlignment = opt32.SectionAlignment;
        info->MajorLinkerVersion = opt32.MajorLinkerVersion;
        info->MinorLinkerVersion = opt32.MinorLinkerVersion;
        info->MajorOsVersion = opt32.MajorOperatingSystemVersion;
        info->MinorOsVersion = opt32.MinorOperatingSystemVersion;
        IocpParseDataDirectories32(Context, &opt32);
    }

    /* Step 3.1: 缓解标志派生 (对齐 SS ExtractSecurityMitigationsImpl) */
    {
        // 强制进行代码完整性检查
        info->HasForceIntegrity = (info->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) != 0;
        // 在 AppContainer 中执行
        info->IsAppContainer = (info->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER) != 0;
    }

    /* 驱动检测 */
    info->IsDriver = (info->Subsystem == IMAGE_SUBSYSTEM_NATIVE);

    /* 扩解析域: 内存模式学到 SizeOfImage 后扩展 reader 域 */
    if (Context->IsMemoryMode && info->SizeOfImage > 0) {
        WpeReaderSetSize(&Context->Reader, (SIZE_T)info->SizeOfImage);
    }

    /* Step 4: 节表 */
    Context->SectionTableOffset = Context->OptionalHeaderOffset + fileHeader.SizeOfOptionalHeader;
    if (!IocpParseSections(Context)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Step 5: 数据目录文件偏移转换 (文件模式) */
    if (!Context->IsMemoryMode) {
        WpeFinalizeDataDirectoryFileOffsets(Context);
    }

    /* Step 6: 入口点分析 */
    IocpParseEntryPoint(Context);

    /* Step 7: .NET 检测 (2026-08-19 启用: 原注释致 IsDotNet 恒 FALSE) */
    //if (info->DataDirectories[PE_DD_COM_DESCRIPTOR].Present) {
    //    info->IsDotNet = TRUE;
    //}

    /* Step 7.1: .NET 目标框架 (BSJB 元数据版本串) — 对齐 SS ParseDotNetImpl。
     * 2026-08-19 启用: 仅 .NET 时读取，供 DotNetAnalyzer 迁移与 Facts.HasDotNet 消费。 */
    //if (info->IsDotNet) {
    //    WpeParseDotNetFramework(Context);
    //}

    /* Step 8: 校验数字签名 - IMAGE_DIRECTORY_ENTRY_SECURITY */
    IocpVerifyPeAuthenticode(Context);

    /* Step 9: Overlay 检测 (仅文件模式) */
    //if (Context->Options.DetectOverlay && !Context->IsMemoryMode) {
    //    WpeDetectOverlay(Context);
    //}

    /* Step 10: Anomaly 收集 */
    //if (Context->Options.CollectAnomalies) {
    //    WpeDetectAnomalies(Context);
    //}

    /* Step 11: 资源内容级异常 (门控) — 对齐 SS ParseResourcesImpl, 需 Parsed */
    //if (Context->Options.AnalyzeContentAnomalies) {
    //    WpeDetectResourceContentAnomalies(Context);
    //}

    /* 校验和异常 (文件模式, 需 Parsed) */
    //if (Context->Options.VerifyChecksum && !Context->IsMemoryMode) {
    //    if (!WpeVerifyChecksum(Context)) {
    //        WpeAddAnomalyToInfo(Context, WpeAnom_ChecksumMismatch,
    //            L"PE checksum does not match computed value — possible tampering");
    //    }
    //}

    QueryPerformanceCounter(&qpcEnd);
    if (qpcFreq.QuadPart > 0) {
        info->ParseTimeNs = ((ULONG64)(qpcEnd.QuadPart - qpcStart.QuadPart) *
            1000000000ULL) / (ULONG64)qpcFreq.QuadPart;
    }

    info->Valid = TRUE;
    Context->Parsed = TRUE;

    return STATUS_SUCCESS;
}

/**************************************************/
/*             主解析入口                           */
/**************************************************/

NTSTATUS
IocAnalyzePeBuffer(
    _In_ const PBYTE Buffer,
    _In_ SIZE_T BufferSize,
    _In_opt_ const PPE_PARSE_OPTIONS Options,
    _Out_ PPE_INFO Info,
    _Out_opt_ PPE_PARSER_ERROR Error
    )
/*++
Routine Description:
    从内存缓冲解析 PE (含已映射文件视图)。offset 语义 = 文件偏移。

Arguments:
    Buffer  - 数据指针 (内存缓冲或已映射文件视图)。
    Size    - 数据大小。
    Options - 解析选项 (可 NULL = 默认)。
    Info    - 输出 PE 信息。
    Error   - [可选] 错误输出。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;
    PPE_PARSER_CONTEXT ctx;

    if (!Buffer || BufferSize == 0 || !Info) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Info, sizeof(PE_INFO));

    ctx = (PPE_PARSER_CONTEXT)malloc(sizeof(PE_PARSER_CONTEXT));
    if (ctx == NULL) return STATUS_NO_MEMORY;
    RtlZeroMemory(ctx, sizeof(PE_PARSER_CONTEXT));

    ctx->Options = (Options) ? *Options : IocDefaultPeParseOptions();
    ctx->IsMemoryMode = FALSE;
    IocInitializeBufferReader(&ctx->Reader, Buffer, BufferSize);

    status = IocpParsePe(ctx);
    if (NT_SUCCESS(status)) {
        *Info = ctx->Info;
    }
    if (Error) {
        *Error = ctx->Error;
    }

    IocReaderDestroy(&ctx->Reader);
    free(ctx);
    return status;
}

NTSTATUS
IocAnalyzeFromProcess(
    _In_  HANDLE                 ProcessHandle,
    _In_  ULONG_PTR              BaseAddress,
    _In_  SIZE_T                 Size,
    _In_  const PE_PARSE_OPTIONS* Options,
    _Out_ PPE_INFO           Out,
    _Out_opt_ PPE_PARSER_ERROR      Err
    )
/*++
Routine Description:
    从进程内存解析 PE (内存模式)。offset 语义 = RVA, 实际地址 = BaseAddress + offset。

Arguments:
    ProcessHandle - 目标进程句柄 (PROCESS_VM_READ)。
    BaseAddress   - 映像基址。
    Size          - 解析域大小 (通常 4096 头区或 SizeOfImage)。
    Options       - 解析选项。
    Out           - 输出 PE 信息。
    Err           - [可选] 错误输出。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;
    PPE_PARSER_CONTEXT ctx;
    PE_PARSE_OPTIONS opt;

    if (Out == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));

    ctx = (PPE_PARSER_CONTEXT)malloc(sizeof(PE_PARSER_CONTEXT));
    if (ctx == NULL) return STATUS_NO_MEMORY;
    RtlZeroMemory(ctx, sizeof(*ctx));

    opt = (Options) ? *Options : IocDefaultPeParseOptions();
    ctx->Options = opt;
    ctx->IsMemoryMode = TRUE;
    ctx->Reader = WpeReaderFromProcess(ProcessHandle, BaseAddress, Size);

    status = IocpParsePe(ctx);
    if (NT_SUCCESS(status)) {
        *Out = ctx->Info;
    }
    if (Err) {
        *Err = ctx->Error;
    }

    IocReaderDestroy(&ctx->Reader);
    free(ctx);
    return status;
}

NTSTATUS
IocpAnalyzeFileHandle(
    _In_ HANDLE FileHandle,
    _In_ SIZE_T Size,
    _In_opt_ const PPE_PARSE_OPTIONS Options,
    _Out_ PPE_INFO Info,
    _Out_opt_ PPE_PARSER_ERROR Error
    )
/*++
Routine Description:
    从已打开的文件句柄解析 PE (File 模式, 段式 ReadFile 按需加载, 不整文件映射)。
    适用于超大文件 / 不可映射句柄 / 需有界内存的场景。offset 语义 = 文件偏移。
    读取器不拥有 FileHandle, 调用方负责关闭。句柄须以 GENERIC_READ 打开且定位于文件头。

Arguments:
    FileHandle - 文件句柄 (GENERIC_READ)。
    Size       - 解析域大小 (文件大小)。
    Options    - 解析选项 (可 NULL = 默认)。
    Info       - 输出 PE 信息。
    Error      - [可选] 错误输出。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;
    PPE_PARSER_CONTEXT ctx;

    if (FileHandle == INVALID_HANDLE_VALUE || FileHandle == NULL || Size == 0 || !Info) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Info, sizeof(PE_INFO));

    ctx = (PPE_PARSER_CONTEXT)malloc(sizeof(PE_PARSER_CONTEXT));
    if (ctx == NULL) return STATUS_NO_MEMORY;
    RtlZeroMemory(ctx, sizeof(PE_PARSER_CONTEXT));

    ctx->Options = (Options) ? *Options : IocDefaultPeParseOptions();
    ctx->IsMemoryMode = FALSE;
    IocpInitializeReader(&ctx->Reader, FileHandle, Size);

    status = IocpParsePe(ctx);
    if (NT_SUCCESS(status)) {
        *Info = ctx->Info;
    }
    if (Error) {
        *Error = ctx->Error;
    }

    IocReaderDestroy(&ctx->Reader);
    free(ctx);
    return status;
}

NTSTATUS
IocAnalyzePeFromFilePath(
    _In_ PCWSTR ImagePath,
    _In_ const PPE_PARSE_OPTIONS Options,
    _Out_ PPE_INFO Info,
    _Out_opt_ PPE_PARSER_ERROR Error
    )
/*++
Routine Description:
    从磁盘文件解析 PE (File reader 段式 ReadFile, 不整文件内存映射, >2GB 拒绝)。
    读取器自行按需分段读取, 解析核心直接走 IocpParsePe, 不依赖 IocAnalyzePeBuffer。

Arguments:
    Path    - 文件路径。
    Options - 解析选项。
    Out     - 输出 PE 信息。
    Err     - [可选] 错误输出。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;
    HANDLE hFile;
    LARGE_INTEGER fileSize;
    PPE_PARSER_CONTEXT ctx;

    if (!CoCheckStringValidity(ImagePath) || !Options || !Info) {
        if (Error) {
            Error->Code = WpeVal_NullPointer;
            Error->Message = L"Invalid parameters provided";
        }
        return STATUS_INVALID_PARAMETER;
    }
    if (wcslen(ImagePath) > MAX_PATH) {
        if (Error) {
            Error->Code = WpeVal_PathTooLong;
            Error->Message = L"Path length exceeds MAX_PATH";
        }
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Info, sizeof(PE_INFO));

    hFile = CoOpenFileForSequentialRead(ImagePath, &fileSize);
    if (hFile == INVALID_HANDLE_VALUE) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    /* 建 File reader 直接走 IocpParsePe: 读取器自行段式 ReadFile,
       不整文件内存映射, 不依赖 IocAnalyzePeBuffer 缓冲范式 (对齐 IocAnalyzeFromProcess) */
    ctx = (PPE_PARSER_CONTEXT)malloc(sizeof(PE_PARSER_CONTEXT));
    if (ctx == NULL) {
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }
    RtlZeroMemory(ctx, sizeof(PE_PARSER_CONTEXT));

    ctx->Options = *Options;
    ctx->IsMemoryMode = FALSE;
    IocpInitializeReader(&ctx->Reader, hFile, (SIZE_T)fileSize.QuadPart);

    status = IocpParsePe(ctx);
    if (NT_SUCCESS(status)) {
        *Info = ctx->Info;
    }
    if (Error) {
        *Error = ctx->Error;
    }

    IocReaderDestroy(&ctx->Reader);
    free(ctx);
    CloseHandle(hFile);

    /* 继承既有怪癖: 文件已成功打开并尝试解析时统一返回 STATUS_SUCCESS
       (调用方 IocAnalyzePe 依赖此契约, 解析是否成功由 Info->IsPE 判定) */
    status = STATUS_SUCCESS;
    return status;

Cleanup:
    if (hFile) CloseHandle(hFile);
    return;
}

NTSTATUS
IocpAnalyzeBufferEx(
    _Inout_ PPE_PARSER_CONTEXT   Context,
    _In_  const BYTE*            Data,
    _In_  SIZE_T                 Size,
    _In_  const PE_PARSE_OPTIONS* Options
    )
/*++
Routine Description:
    上下文版解析 (缓冲模式), 调用者持有 context 供地址转换/惰性解析。

Return Value:
    NTSTATUS。
--*/
{
    if (Context == NULL) return STATUS_INVALID_PARAMETER;

    WpeParseContextReset(Context);
    Context->Options = (Options) ? *Options : IocDefaultPeParseOptions();
    Context->IsMemoryMode = FALSE;
    IocInitializeBufferReader(&Context->Reader, Data, Size);
    return IocpParsePe(Context);
}

NTSTATUS
WpeParseMemoryEx(
    _Inout_ PPE_PARSER_CONTEXT   Context,
    _In_  HANDLE                 ProcessHandle,
    _In_  ULONG_PTR              BaseAddress,
    _In_  SIZE_T                 Size,
    _In_  const PE_PARSE_OPTIONS* Options
    )
/*++
Routine Description:
    上下文版解析 (内存模式), 调用者持有 context 供地址转换/惰性解析。

Return Value:
    NTSTATUS。
--*/
{
    if (Context == NULL) return STATUS_INVALID_PARAMETER;

    WpeParseContextReset(Context);
    Context->Options = (Options) ? *Options : IocDefaultPeParseOptions();
    Context->IsMemoryMode = TRUE;
    Context->Reader = WpeReaderFromProcess(ProcessHandle, BaseAddress, Size);
    return IocpParsePe(Context);
}

VOID
WpeParseContextReset(
    _Inout_ PPE_PARSER_CONTEXT Context
    )
/*++
Routine Description:
    重置解析上下文。

Return Value:
    无。
--*/
{
    if (Context) {
        /* 先释放 Reader 持有的堆 (Scratch / File-Process 段缓冲),
         * 否则 RtlZeroMemory 会令其泄漏。 */
        IocReaderDestroy(&Context->Reader);
        RtlZeroMemory(Context, sizeof(*Context));
    }
}

BOOLEAN
WpeIsParsed(
    _In_ const PE_PARSER_CONTEXT* Context
    )
/*++
Routine Description:
    是否已成功解析。

Return Value:
    TRUE=已解析。
--*/
{
    return (Context != NULL && Context->Parsed);
}

const PE_INFO*
WpeGetInfo(
    _In_ const PE_PARSER_CONTEXT* Context
    )
/*++
Routine Description:
    取已解析 PE 信息 (对齐 SS GetInfo)。无调用者 (直接经 Context->Info 访问)。

Return Value:
    PE 信息指针; 未解析返回 NULL。
--*/
{
    return (Context != NULL && Context->Parsed) ? &Context->Info : NULL;
}

const PE_READER*
WpeGetReader(
    _In_ const PE_PARSER_CONTEXT* Context
    )
/*++
Routine Description:
    取底层读取器 (对齐 SS GetReader)。无调用者 (慎用, 页缓存为可变状态)。

Return Value:
    读取器指针; 未解析返回 NULL。
--*/
{
    return (Context != NULL && Context->Parsed) ? &Context->Reader : NULL;
}

/**************************************************/
/*             地址转换                             */
/**************************************************/

BOOLEAN
IocpRvaToOffset(
    _In_ const PE_PARSER_CONTEXT* Context,
    _In_ ULONG  Rva,
    _Out_ PULONG Offset
    )
/*++
Routine Description:
    RVA → 文件偏移 (内存模式返回 RVA 恒等)。

Return Value:
    TRUE=可换算。
--*/
{
    return IocpRvaToOffsetInternal(Context, Rva, Offset);
}

BOOLEAN
WpeOffsetToRva(
    _In_  const PE_PARSER_CONTEXT* Context,
    _In_  SIZE_T Offset,
    _Out_ ULONG*  OutRva
    )
/*++
Routine Description:
    文件偏移 → RVA。

Return Value:
    TRUE=可换算。
--*/
{
    ULONG i;

    if (Context == NULL || !Context->Parsed || OutRva == NULL) return FALSE;

    if (Context->IsMemoryMode) {
        *OutRva = (ULONG)Offset;
        return TRUE;
    }

    if (Offset < Context->Info.SizeOfHeaders) {
        *OutRva = (ULONG)Offset;
        return TRUE;
    }

    for (i = 0; i < Context->RawSectionCount; i++) {
        const IMAGE_SECTION_HEADER* sec = &Context->RawSections[i];
        SIZE_T secStart, secEnd;

        if (sec->SizeOfRawData == 0) continue;
        secStart = (SIZE_T)sec->PointerToRawData;
        if (!IocpAddSizeSafe(secStart, (SIZE_T)sec->SizeOfRawData, &secEnd)) continue;

        if (Offset >= secStart && Offset < secEnd) {
            SIZE_T secOffset = Offset - secStart;
            ULONG rva;
            if (!IocpAddU32Safe(sec->VirtualAddress, (ULONG)secOffset, &rva)) continue;
            *OutRva = rva;
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN
WpeIsValidRva(
    _In_  const PE_PARSER_CONTEXT* Context,
    _In_  ULONG Rva
    )
/*++
Routine Description:
    RVA 是否落在有效节/头区。

Return Value:
    TRUE=有效。
--*/
{
    SIZE_T off;
    return IocpRvaToOffsetInternal(Context, Rva, &off);
}

BOOLEAN
WpeGetSectionByRva(
    _In_  const PE_PARSER_CONTEXT* Context,
    _In_  ULONG Rva,
    _Out_ SIZE_T* OutIndex
    )
/*++
Routine Description:
    找包含 RVA 的节索引。

Return Value:
    TRUE=找到。
--*/
{
    SIZE_T i;

    if (Context == NULL || !Context->Parsed || OutIndex == NULL) return FALSE;

    for (i = 0; i < Context->Info.NumberOfSections; i++) {
        const PE_SECTION* sec = &Context->Info.Sections[i];
        ULONG secSize = sec->VirtualSize ? sec->VirtualSize : sec->SizeOfRawData;
        ULONG secEnd;
        if (!IocpAddU32Safe(sec->VirtualAddress, secSize, &secEnd)) continue;
        if (Rva >= sec->VirtualAddress && Rva < secEnd) {
            *OutIndex = i;
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
WpeGetSectionByName(
    _In_  const PE_PARSER_CONTEXT* Context,
    _In_  PCSTR Name,
    _Out_ SIZE_T* OutIndex
    )
/*++
Routine Description:
    按节名找节索引。

Return Value:
    TRUE=找到。
--*/
{
    SIZE_T i;

    if (Context == NULL || !Context->Parsed || OutIndex == NULL || Name == NULL) return FALSE;

    for (i = 0; i < Context->Info.NumberOfSections; i++) {
        if (strcmp(Context->Info.Sections[i].Name, Name) == 0) {
            *OutIndex = i;
            return TRUE;
        }
    }
    return FALSE;
}

/**************************************************/
/*             验证与工具                           */
/**************************************************/

BOOLEAN
WpeValidatePe(
    _In_  const PE_PARSER_CONTEXT* Context,
    _Out_opt_ PPE_VALIDATION_RESULT Issues,
    _Inout_opt_ PULONG               IssueCount,
    _In_  ULONG                      IssueCap
    )
/*++
Routine Description:
    深度验证: 收集节校验问题与重叠 (对齐 SS ValidatePE)。
    ※死代码: SS ValidatePE 为对外公共 API (PEParser.cpp:2408), 收集
      ValidateSectionHeader + CheckSectionOverlaps 的问题列表; WKD 已完整
      对齐但无调用者, 待接线 — 后续磁盘 vs 内存比对 WpeValidateModuleIntegrity
      及上层取证场景消费问题列表。

Arguments:
    Context        - 解析上下文。
    Issues     - [可选] 输出问题数组。
    IssueCount - [in,out] 问题计数。
    IssueCap   - 输出容量。

Return Value:
    TRUE=无关键问题。
--*/
{
    ULONG count = (IssueCount) ? *IssueCount : 0;
    ULONG i;

    if (Context == NULL || !Context->Parsed) {
        if (IssueCount) *IssueCount = 0;
        return FALSE;
    }

    for (i = 0; i < Context->RawSectionCount; i++) {
        PE_VALIDATION_RESULT r = IocpValidateSectionHeader(
            &Context->RawSections[i], (SIZE_T)Context->Reader.Size,
            Context->Info.SizeOfImage, Context->Info.FileAlignment, i, NULL, NULL, NULL, 0);
        if (r != WpeVal_Valid) {
            if (Issues && count < IssueCap) Issues[count] = r;
            if (count < IssueCap) count++;
        }
    }

    {
        PE_SECTION_OVERLAP overlaps[8];
        ULONG overlapCount = 0;
        if (WpeCheckSectionOverlaps(Context->RawSections, Context->RawSectionCount,
                                    overlaps, &overlapCount, 8)) {
            if (Issues && count < IssueCap) Issues[count] = WpeVal_SectionOverlap;
            if (count < IssueCap) count++;
        }
    }

    if (IssueCount) *IssueCount = count;
    return (count == 0);
}

BOOLEAN
WpeHasAnomaly(
    _In_  const PE_PARSER_CONTEXT* Context,
    _In_  PE_ANOMALY_TYPE Type
    )
/*++
Routine Description:
    是否已检测到指定异常类型。

Return Value:
    TRUE=存在。
--*/
{
    ULONG i;

    if (Context == NULL || !Context->Parsed) return FALSE;
    for (i = 0; i < Context->Info.AnomalyCount; i++) {
        if (Context->Info.Anomalies[i].Type == Type) return TRUE;
    }
    return FALSE;
}



BOOLEAN
WpeVerifyChecksum(
    _In_ const PE_PARSER_CONTEXT* Context
    )
/*++
Routine Description:
    Microsoft fold-and-add 校验和计算并比对 (等价 MapFileAndCheckSumW,
    跳过校验和两词、加文件大小、奇字节补 0)。校验和为 0 (未设置) 视为通过。

Return Value:
    TRUE=匹配或未设置。
--*/
{
    ULONG64 fileSize;
    ULONGLONG checksumByteOffset;
    ULONGLONG wordCount;
    ULONG skip0, skip1;
    ULONG64 acc = 0;
    USHORT block[131072];   /* 256KB 块 = 131072 words */

    if (Context == NULL || !Context->Parsed) return FALSE;
    if (Context->Info.Checksum == 0) return TRUE;

    fileSize = Context->Reader.Size;
    if (fileSize == 0) return FALSE;

    /* CheckSum 字段在可选头固定偏移 64 处 (PE32 与 PE32+ 均如此) */
    checksumByteOffset = (ULONGLONG)Context->OptionalHeaderOffset + 64;
    if ((checksumByteOffset & 1) != 0 || checksumByteOffset + 4 > fileSize) {
        return FALSE;
    }

    wordCount = fileSize / 2;
    skip0 = (ULONG)(checksumByteOffset / 2);
    skip1 = skip0 + 1;

    {
        ULONG64 base = 0;   /* 当前块起始 word 索引 */
        while (base < wordCount) {
            SIZE_T chunkWords = sizeof(block) / sizeof(USHORT);
            ULONG64 i;
            if ((ULONG64)chunkWords > wordCount - base) {
                chunkWords = (SIZE_T)(wordCount - base);
            }
            if (!IocpReaderReadBytes((PPE_READER)&Context->Reader, base * 2,
                               block, chunkWords * sizeof(USHORT))) {
                return FALSE;
            }
            for (i = 0; i < chunkWords; i++) {
                ULONG64 idx = base + i;
                if (idx == skip0 || idx == skip1) continue;
                acc += block[i];
                acc = (acc >> 16) + (acc & 0xFFFF);
            }
            base += chunkWords;
        }
    }

    /* 尾随奇字节补 0 */
    if (fileSize & 1) {
        BYTE lastByte = 0;
        if (IocpReaderReadBytes((PPE_READER)&Context->Reader, fileSize - 1, &lastByte, sizeof(BYTE))) {
            acc += lastByte;
            acc = (acc >> 16) + (acc & 0xFFFF);
        }
    }

    acc = (acc & 0xFFFF) + (acc >> 16);
    acc += fileSize;
    acc = (acc & 0xFFFF) + (acc >> 16);

    return ((ULONG)(acc & 0xFFFF)) == Context->Info.Checksum;
}

ULONG
WpeComputeFileChecksum(
    _In_ const BYTE* Data,
    _In_ SIZE_T      Size,
    _In_ ULONG       CheckSumOffset
    )
/*++
Routine Description:
    Microsoft fold-and-add PE 校验和计算 (等价 MapFileAndCheckSumW,
    与 WpeVerifyChecksum 同算法, 但为纯内存写侧版本: 输入为已重建的
    PE 缓冲, 返回计算值供调用方写回 OptionalHeader.CheckSum。
    跳过校验和两词、加文件大小、奇字节补 0。

Arguments:
    Data           - PE 缓冲。
    Size           - 缓冲大小。
    CheckSumOffset - CheckSum 字段相对缓冲偏移 (可选头+64, PE32 与 PE32+ 均如此)。

Return Value:
    计算出的校验和 (ULONG); 无效输入返回 0。
--*/
{
    ULONG64 acc = 0;
    ULONG64 wordCount;
    ULONG skip0, skip1;
    ULONG64 base = 0;
    USHORT block[131072];   /* 256KB 块 = 131072 words */

    if (Data == NULL || Size == 0) return 0;
    if ((CheckSumOffset & 1) != 0 || CheckSumOffset + 4 > Size) return 0;

    wordCount = Size / 2;
    skip0 = CheckSumOffset / 2;
    skip1 = skip0 + 1;

    while (base < wordCount) {
        SIZE_T chunkWords = sizeof(block) / sizeof(USHORT);
        ULONG64 i;
        if ((ULONG64)chunkWords > wordCount - base) {
            chunkWords = (SIZE_T)(wordCount - base);
        }
        for (i = 0; i < chunkWords; i++) {
            ULONG64 idx = base + i;
            USHORT w;
            if (idx == skip0 || idx == skip1) continue;
            memcpy(&w, Data + idx * 2, sizeof(w));   /* 防非对齐读取 */
            acc += w;
            acc = (acc >> 16) + (acc & 0xFFFF);
        }
        base += chunkWords;
    }

    /* 尾随奇字节补 0 */
    if (Size & 1) {
        acc += Data[Size - 1];
        acc = (acc >> 16) + (acc & 0xFFFF);
    }

    acc = (acc & 0xFFFF) + (acc >> 16);
    acc += Size;
    acc = (acc & 0xFFFF) + (acc >> 16);

    return (ULONG)(acc & 0xFFFF);
}

PCWSTR
WpeMachineToString(
    _In_ USHORT Machine
    )
/*++
Routine Description:
    机器类型 → 可读字符串。

Return Value:
    静态字符串。
--*/
{
    switch (Machine) {
    case PE_MACHINE_UNKNOWN:   return L"Unknown";
    case PE_MACHINE_I386:      return L"Intel 386";
    case PE_MACHINE_AMD64:     return L"AMD64 (x64)";
    case PE_MACHINE_ARM:       return L"ARM";
    case PE_MACHINE_ARMNT:     return L"ARM Thumb-2";
    case PE_MACHINE_ARM64:     return L"ARM64";
    case PE_MACHINE_IA64:      return L"Intel Itanium";
    case PE_MACHINE_THUMB:     return L"ARM Thumb";
    case PE_MACHINE_POWERPC:   return L"PowerPC";
    case PE_MACHINE_MIPS16:    return L"MIPS16";
    case PE_MACHINE_ALPHA:     return L"Alpha";
    case PE_MACHINE_ALPHA64:   return L"Alpha64";
    case PE_MACHINE_SH3:       return L"Hitachi SH3";
    case PE_MACHINE_SH4:       return L"Hitachi SH4";
    case PE_MACHINE_EBC:       return L"EFI Byte Code";
    default:                    return L"Unknown";
    }
}

PCWSTR
WpeSubsystemToString(
    _In_ USHORT Subsystem
    )
/*++
Routine Description:
    子系统类型 → 可读字符串。

Return Value:
    静态字符串。
--*/
{
    switch (Subsystem) {
    case IMAGE_SUBSYSTEM_UNKNOWN:                    return L"Unknown";
    case IMAGE_SUBSYSTEM_NATIVE:                     return L"Native (Driver)";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:                return L"Windows GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:                return L"Windows Console";
    case IMAGE_SUBSYSTEM_OS2_CUI:                    return L"OS/2 Console";
    case IMAGE_SUBSYSTEM_POSIX_CUI:                  return L"POSIX Console";
    case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:             return L"Native Windows";
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:             return L"Windows CE GUI";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:            return L"EFI Application";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:    return L"EFI Boot Driver";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:         return L"EFI Runtime Driver";
    case IMAGE_SUBSYSTEM_EFI_ROM:                    return L"EFI ROM";
    case IMAGE_SUBSYSTEM_XBOX:                       return L"Xbox";
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:   return L"Windows Boot Application";
    default:                                         return L"Unknown";
    }
}
