/**************************************************/
/*  WkDefender PEAnalyzer — 对外业务门面实现         */
/**************************************************/

#include "PeAnalyzer.h"
#include "../StringExtractor.h"  /* IocStrExtract (编码串提取, 2026-08-19) */
#include "../../Common/FileUtils.h"   /* CoOpenFileForSequentialRead（校验 reader 文件打开, 2026-09-07） */
#include "../../Common/Utils.h"       /* CoOpenProcessForQueryRead（跨进程最小句柄, 2026-09-07） */
#include "../../Process/ProcessModule.h" /* PsGetMainModuleInstance（门面主模块域/磁盘路径, 2026-09-07） */
#include "PeInternal.h"      /* 内部解析/惰性/解包 — 门面实现专用 */

#include <wchar.h>    /* swprintf_s (版本信息 StringFileInfo 子块拼接) */

/* 深度验证节熵读上限 (对齐旧 WpaAnalyzePEDeep 的 WKD_PE_DEEP_MAX_SECTION_READ) */
#define WKD_PE_DEEP_MAX_SECTION_READ  (1024 * 1024)

/**************************************************/
/*             静态辅助函数                         */
/**************************************************/

/*
 * WpeInfoToWpaPeInfo — PE_INFO → 遗留 WPA_PE_INFO。
 */
static
VOID
WpeInfoToWpaPeInfo(
    _In_  const PE_INFO* Info,
    _Out_ PWPA_PE_INFO       Out
    )
{
    RtlZeroMemory(Out, sizeof(*Out));
    if (Info == NULL || !Info->Valid) {
        Out->IsPE = FALSE;
        return;
    }

    Out->IsPE = TRUE;
    Out->Amd64 = Info->Amd64;
    Out->IsDotNet = Info->IsDotNet;
    Out->IsSigned = Info->IsSigned;
    Out->IsPacked = FALSE;          /* 需熵计算, 默认未判 */
    Out->Entropy = 0;
    Out->Characteristics = Info->Characteristics;
    Out->Subsystem = Info->Subsystem;
    Out->ImageSize = Info->SizeOfImage;
    Out->DllCharacteristics = Info->DllCharacteristics;
    Out->Machine = Info->Machine;
    Out->TimeDateStamp = Info->TimeDateStamp;
    Out->EntryPoint = Info->AddressOfEntryPoint;
    Out->ImageBase = (ULONG_PTR)Info->ImageBase;

    Out->NumberOfSections = (USHORT)Info->NumberOfSections;
    Out->Checksum = Info->Checksum;
    Out->SectionAlignment = Info->SectionAlignment;
    Out->FileAlignment = Info->FileAlignment;
    Out->SizeOfHeaders = Info->SizeOfHeaders;
    Out->NumberOfDataDirectories = PE_DD_MAX_ENTRIES;

    Out->ImportTableRVA = Info->DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Rva;
    Out->ImportTableSize = Info->DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    Out->ExportTableRVA = Info->DataDirectories[PE_DD_EXPORT].Rva;
    Out->ExportTableSize = Info->DataDirectories[PE_DD_EXPORT].Size;
    Out->RelocationTableRVA = Info->DataDirectories[PE_DD_BASERELOC].Rva;
    Out->RelocationTableSize = Info->DataDirectories[PE_DD_BASERELOC].Size;
    Out->DebugDirectoryRVA = Info->DataDirectories[PE_DD_DEBUG].Rva;
    Out->DebugDirectorySize = Info->DataDirectories[PE_DD_DEBUG].Size;
    Out->TlsDirectoryRVA = Info->DataDirectories[PE_DD_TLS].Rva;
    Out->TlsDirectorySize = Info->DataDirectories[PE_DD_TLS].Size;
}

/*
 * WpeSectionToWkd — PE_SECTION → 遗留 WKD_PE_SECTION。
 */
static
VOID
WpeSectionToWkd(
    _In_  const PE_SECTION* Src,
    _Out_ PWKD_PE_SECTION    Dst
    )
{
    RtlZeroMemory(Dst, sizeof(*Dst));
    memcpy(Dst->Name, Src->Name, 8);
    Dst->VirtualSize = Src->VirtualSize;
    Dst->VirtualAddress = Src->VirtualAddress;
    Dst->SizeOfRawData = Src->SizeOfRawData;
    Dst->PointerToRawData = Src->PointerToRawData;
    Dst->Characteristics = Src->Characteristics;
    Dst->IsExecutable = Src->IsExecutable;
    Dst->IsWritable = Src->IsWritable;
    Dst->IsReadable = Src->IsReadable;
    Dst->ContainsCode = Src->HasCode;
    Dst->ContainsData = Src->HasInitializedData;
    Dst->Entropy = 0;
    Dst->MemoryAddress = 0;
}

/*
 * WpeValidationToWkd — WPE 校验结果 → 遗留深度验证分级。
 */
static
WKD_PE_VALIDATION_RESULT
WpeValidationToWkd(
    _In_ PE_VALIDATION_RESULT Vr
    )
{
    switch (Vr) {
    case WpeVal_InvalidDosSignature:
    case WpeVal_LfanewNegative:
    case WpeVal_LfanewTooSmall:
    case WpeVal_LfanewTooLarge:
    case WpeVal_LfanewOutOfBounds:
    case WpeVal_InvalidLfanew:
        return WkdPeInvalidDosHeader;
    case WpeVal_InvalidNtSignature:
    case WpeVal_InvalidMachine:
        return WkdPeInvalidPeSignature;
    case WpeVal_InvalidOptionalMagic:
    case WpeVal_InvalidFileAlignment:
    case WpeVal_InvalidSectionAlignment:
    case WpeVal_FileAlignmentGreaterThanSection:
    case WpeVal_SizeOfImageZero:
    case WpeVal_SizeOfHeadersZero:
    case WpeVal_SizeOfHeadersTooLarge:
    case WpeVal_NumberOfRvaAndSizesInvalid:
    case WpeVal_InvalidSubsystem:
    case WpeVal_InvalidImageBase:
    case WpeVal_InvalidAddressOfEntryPoint:
        return WkdPeInvalidOptionalHeader;
    case WpeVal_NumberOfSectionsOverflow:
    case WpeVal_SectionTableOutOfBounds:
    case WpeVal_SectionTableOverflow:
    case WpeVal_SectionBeyondFile:
    case WpeVal_SectionBeyondImage:
        return WkdPeInvalidSections;
    case WpeVal_FileTooSmall:
    case WpeVal_NtHeadersOutOfBounds:
    case WpeVal_SizeOfOptionalHeaderTooSmall:
        return WkdPeTruncatedPE;
    case WpeVal_SizeOfImageNotAligned:
        return WkdPeSuspiciousCharacteristics;
    default:
        return WkdPeInvalidDosHeader;
    }
}

/*
 * WpeRpmAlloc — 读目标进程内存 (自含 OpenProcess+RPM)。
 */
static
NTSTATUS
WpeRpmAlloc(
    _In_  DWORD     ProcessId,
    _In_  ULONG_PTR Address,
    _In_  SIZE_T    Size,
    _Out_ PBYTE*    OutBuf,
    _Out_ PULONG    OutSize
    )
{
    HANDLE hProc;
    PBYTE buf;
    SIZE_T read = 0;

    if (OutBuf == NULL || OutSize == NULL) return STATUS_INVALID_PARAMETER;
    *OutBuf = NULL;
    *OutSize = 0;

    hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (hProc == NULL) return STATUS_ACCESS_DENIED;

    buf = (PBYTE)malloc(Size);
    if (buf == NULL) {
        CloseHandle(hProc);
        return STATUS_NO_MEMORY;
    }
    if (!ReadProcessMemory(hProc, (LPCVOID)Address, buf, Size, &read) || read == 0) {
        free(buf);
        CloseHandle(hProc);
        return STATUS_UNSUCCESSFUL;
    }

    *OutBuf = buf;
    *OutSize = (ULONG)read;
    CloseHandle(hProc);
    return STATUS_SUCCESS;
}

/*
 * WpeAnalyzePEHeadersFromFile — 内部: 磁盘文件 → WPA_PE_INFO。
 * (WpeValidateModuleIntegrity 用, 避免依赖文件映射细节)
 */
static
HRESULT
WpeAnalyzePEHeadersFromFile(
    _In_  PCWSTR       FilePath,
    _Out_ PWPA_PE_INFO PeInfo
    )
{
    HANDLE hFile;
    LARGE_INTEGER size;
    PBYTE buf = NULL;
    HRESULT hr = S_OK;

    if (FilePath == NULL || PeInfo == NULL) return E_INVALIDARG;
    RtlZeroMemory(PeInfo, sizeof(*PeInfo));

    hFile = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(GetLastError());
    if (!GetFileSizeEx(hFile, &size) || size.QuadPart <= 0 ||
        (ULONGLONG)size.QuadPart > 0x1000000ULL) {   /* 16MB 上限足够头区 */
        CloseHandle(hFile);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    buf = (PBYTE)malloc((SIZE_T)size.QuadPart);
    if (buf == NULL) {
        CloseHandle(hFile);
        return E_OUTOFMEMORY;
    }
    {
        DWORD read = 0;
        if (!ReadFile(hFile, buf, (DWORD)size.QuadPart, &read, NULL) || read == 0) {
            hr = HRESULT_FROM_WIN32(GetLastError());
        } else {
            hr = WpeAnalyzePEHeadersFromBuffer(buf, read, PeInfo);
        }
    }

    free(buf);
    CloseHandle(hFile);
    return hr;
}

/**************************************************/
/*         PE 头分析 (内存 / 缓冲)                   */
/**************************************************/

_Check_return_
HRESULT
WpeAnalyzePEHeaders(
    _In_  HANDLE      ProcessHandle,
    _In_  PVOID       ImageBaseAddress,
    _Out_ PWPA_PE_INFO PeInfo
    )
/*++
Routine Description:
    从进程内存读取并分析 PE 头 (进程模式)。

Arguments:
    ProcessHandle    - 目标进程句柄。
    ImageBaseAddress - 映像基址。
    PeInfo           - 输出 PE 信息。

Return Value:
    S_OK; 空参 E_INVALIDARG。非 PE 时 PeInfo->IsPE=FALSE。
--*/
{
    PE_INFO info;
    PE_PARSE_OPTIONS opt;
    NTSTATUS status;

    if (PeInfo == NULL) return E_INVALIDARG;
    RtlZeroMemory(PeInfo, sizeof(*PeInfo));
    if (ProcessHandle == NULL || ProcessHandle == INVALID_HANDLE_VALUE ||
        ImageBaseAddress == NULL) {
        return E_INVALIDARG;
    }

    opt = IocDefaultPeParseOptions();
    opt.CollectAnomalies = FALSE;
    opt.DetectOverlay = FALSE;
    opt.VerifyChecksum = FALSE;

    status = IocAnalyzeFromProcess(ProcessHandle, (ULONG_PTR)ImageBaseAddress, 4096, &opt, &info, NULL);
    if (!NT_SUCCESS(status)) {
        PeInfo->IsPE = FALSE;
        return S_OK;
    }
    WpeInfoToWpaPeInfo(&info, PeInfo);
    return S_OK;
}

_Check_return_
HRESULT
WpeAnalyzePEHeadersFromBuffer(
    _In_  PVOID       FileBuffer,
    _In_  ULONG       FileSize,
    _Out_ PWPA_PE_INFO PeInfo
    )
/*++
Routine Description:
    从文件缓冲区分析 PE 头 (离线模式)。

Arguments:
    FileBuffer - 数据指针。
    FileSize   - 数据大小。
    PeInfo     - 输出 PE 信息。

Return Value:
    S_OK; 空参 E_INVALIDARG。非 PE 时 PeInfo->IsPE=FALSE。
--*/
{
    PE_INFO info;
    PE_PARSE_OPTIONS opt;
    NTSTATUS status;

    if (PeInfo == NULL) return E_INVALIDARG;
    RtlZeroMemory(PeInfo, sizeof(*PeInfo));
    if (FileBuffer == NULL || FileSize < sizeof(IMAGE_DOS_HEADER)) {
        return E_INVALIDARG;
    }

    opt = IocDefaultPeParseOptions();
    opt.CollectAnomalies = FALSE;
    opt.DetectOverlay = FALSE;
    opt.VerifyChecksum = FALSE;

    status = IocAnalyzePeBuffer((const BYTE*)FileBuffer, FileSize, &opt, &info, NULL);
    if (!NT_SUCCESS(status)) {
        PeInfo->IsPE = FALSE;
        return S_OK;
    }
    WpeInfoToWpaPeInfo(&info, PeInfo);
    return S_OK;
}

_Check_return_
HRESULT
WpeParseSectionHeaders(
    _In_  PVOID Buffer,
    _In_  ULONG Size,
    _Out_writes_to_(MaxSections, *Count) PWKD_PE_SECTION Sections,
    _In_  ULONG MaxSections,
    _Out_ PULONG Count
    )
/*++
Routine Description:
    从完整 PE 缓冲区解析节表。

Arguments:
    Buffer      - 数据指针。
    Size        - 数据大小。
    Sections    - 输出节表。
    MaxSections - 输出容量。
    Count       - 输出节数量。

Return Value:
    S_OK; 空参 E_INVALIDARG。非 PE 时 *Count=0。
--*/
{
    PE_INFO info;
    PE_PARSE_OPTIONS opt;
    NTSTATUS status;
    ULONG i;

    if (Sections == NULL || Count == NULL || MaxSections == 0) return E_INVALIDARG;
    *Count = 0;
    if (Buffer == NULL || Size < sizeof(IMAGE_DOS_HEADER)) return E_INVALIDARG;

    opt = IocDefaultPeParseOptions();
    opt.CollectAnomalies = FALSE;
    opt.DetectOverlay = FALSE;
    opt.VerifyChecksum = FALSE;

    status = IocAnalyzePeBuffer((const BYTE*)Buffer, Size, &opt, &info, NULL);
    if (!NT_SUCCESS(status)) {
        return S_OK;
    }

    for (i = 0; i < info.NumberOfSections && i < MaxSections; i++) {
        WpeSectionToWkd(&info.Sections[i], &Sections[i]);
        *Count = i + 1;
    }
    return S_OK;
}

/**************************************************/
/*             深度 PE 验证                          */
/**************************************************/

_Check_return_
HRESULT
WpeAnalyzePEDeep(
    _In_  HANDLE       ProcessHandle,
    _In_  ULONG_PTR    BaseAddress,
    _Out_ PWKD_PE_DEEP_INFO Deep
    )
/*++
Routine Description:
    深度 PE 验证 (对齐 SS ValidatePEImpl): 读头区 → SHA256 →
    完整解析 → 节表 + 逐节熵 (0-1000) → packed/encrypted → 数据目录完备性。
    供定向无背衬 PE 确认 (反射加载/隐藏模块) 使用。

Arguments:
    ProcessHandle - 目标进程句柄。
    BaseAddress   - 映像基址。
    Deep          - 输出深度验证结果。

Return Value:
    S_OK。
--*/
{
    PE_INFO info;
    PE_PARSE_OPTIONS opt;
    PE_PARSER_ERROR err;
    NTSTATUS status;
    BYTE headerBuf[4096];
    SIZE_T bytesRead = 0;
    ULONG i;

    if (Deep == NULL) return E_INVALIDARG;
    RtlZeroMemory(Deep, sizeof(*Deep));
    if (ProcessHandle == NULL || ProcessHandle == INVALID_HANDLE_VALUE || BaseAddress == 0) {
        Deep->ValidationResult = WkdPeInvalidDosHeader;
        return E_INVALIDARG;
    }

    /* 读头区 (DOS + NT + 节表通常 4096 内) */
    if (!ReadProcessMemory(ProcessHandle, (LPCVOID)BaseAddress, headerBuf,
                           sizeof(headerBuf), &bytesRead) || bytesRead == 0) {
        Deep->ValidationResult = WkdPeInvalidDosHeader;
        return HRESULT_FROM_WIN32(GetLastError());
    }

    /* 头区 SHA256 + 整体熵 (0-1000) */
    IocScanner_ComputeBufferSha256(headerBuf, (ULONG)bytesRead, &Deep->Sha256);
    Deep->OverallEntropy = (ULONG)(CoEntropyBinary(headerBuf, (ULONG)bytesRead, 0) * 1000.0);

    /* 深度解析 (内存模式) */
    opt = IocDefaultPeParseOptions();
    opt.ComputeSectionEntropy = FALSE;   /* 节熵用 0-1000 单独算 */
    opt.CollectAnomalies = FALSE;
    opt.DetectOverlay = FALSE;
    opt.VerifyChecksum = FALSE;

    status = IocAnalyzeFromProcess(ProcessHandle, BaseAddress, sizeof(headerBuf), &opt, &info, &err);
    if (!NT_SUCCESS(status)) {
        Deep->ValidationResult = WpeValidationToWkd(err.Code);
        return S_OK;
    }

    /* SizeOfImage 上限 (对齐 WKD_PE_DEEP_MAX_IMAGE=256MB) */
    if (info.SizeOfImage == 0 || info.SizeOfImage > WKD_PE_DEEP_MAX_IMAGE) {
        Deep->ValidationResult = WkdPeSuspiciousCharacteristics;
        return S_OK;
    }

    Deep->IsValidPE = TRUE;
    Deep->Amd64 = info.Amd64;
    Deep->Machine = info.Machine;
    Deep->NumberOfSections = (USHORT)info.NumberOfSections;
    Deep->TimeDateStamp = info.TimeDateStamp;
    Deep->Characteristics = info.Characteristics;
    Deep->SizeOfImage = info.SizeOfImage;
    Deep->EntryPoint = info.AddressOfEntryPoint;
    Deep->ImageBase = (ULONG_PTR)info.ImageBase;

    Deep->HasExportTable = info.DataDirectories[PE_DD_EXPORT].Present;
    Deep->HasImportTable = info.DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Present;
    Deep->HasRelocationTable = info.DataDirectories[PE_DD_BASERELOC].Present;
    Deep->HasTLSDirectory = info.DataDirectories[PE_DD_TLS].Present;
    Deep->HasDebugDirectory = info.DataDirectories[PE_DD_DEBUG].Present;

    /* 节表 */
    for (i = 0; i < info.NumberOfSections && i < WKD_PE_MAX_SECTIONS; i++) {
        WpeSectionToWkd(&info.Sections[i], &Deep->Sections[i]);
    }

    /* 逐节 0-1000 熵 (内存模式读 VirtualAddress) */
    for (i = 0; i < info.NumberOfSections && i < WKD_PE_MAX_SECTIONS; i++) {
        WKD_PE_SECTION* sec = &Deep->Sections[i];
        if (sec->VirtualAddress > 0 && sec->VirtualSize > 0) {
            ULONG readSize = min(sec->VirtualSize, WKD_PE_DEEP_MAX_SECTION_READ);
            PBYTE secBuf = (PBYTE)malloc(readSize);
            SIZE_T secRead = 0;
            ULONG secEntropy = 0;
            if (secBuf != NULL) {
                if (ReadProcessMemory(ProcessHandle,
                        (LPCVOID)(BaseAddress + sec->VirtualAddress),
                        secBuf, readSize, &secRead) && secRead > 0) {
                    secEntropy = (ULONG)(CoEntropyBinary(secBuf, (ULONG)secRead, 0) * 1000.0);
                    sec->Entropy = secEntropy;
                    if (secEntropy > Deep->HighestSectionEntropy) {
                        Deep->HighestSectionEntropy = secEntropy;
                    }
                }
                free(secBuf);
            }
        }
    }

    /* packed/encrypted (对齐 700/750 阈值) */
    for (i = 0; i < info.NumberOfSections && i < WKD_PE_MAX_SECTIONS; i++) {
        if (Deep->Sections[i].Entropy >= WPA_ENTROPY_THRESHOLD_ENCRYPTED) {
            Deep->IsEncrypted = TRUE;
            Deep->IsPacked = TRUE;
        } else if (Deep->Sections[i].Entropy >= WPA_ENTROPY_THRESHOLD_PACKED) {
            Deep->IsPacked = TRUE;
        }
    }

    /* 分级 (packed/encrypted 亦为有效 PE) */
    if (Deep->IsEncrypted) {
        Deep->ValidationResult = WkdPeEncrypted;
    } else if (Deep->IsPacked) {
        Deep->ValidationResult = WkdPePacked;
    } else {
        Deep->ValidationResult = WkdPeValid;
    }

    return S_OK;
}

/**************************************************/
/*         磁盘 vs 内存 PE 头比对                    */
/**************************************************/

_Check_return_
HRESULT
WpeComparePEHeaders(
    _In_  PWPA_PE_INFO Disk,
    _In_  PWPA_PE_INFO Mem,
    _Out_ PWKD_PE_HEADER_COMPARE Compare
    )
/*++
Routine Description:
    比对磁盘/内存 PE 头 (7 字段, 含 ASLR 豁免与 Checksum 零值豁免)。

Arguments:
    Disk    - 磁盘 PE 信息。
    Mem     - 内存 PE 信息。
    Compare - 输出比对结果。

Return Value:
    S_OK; 空参 E_INVALIDARG。
--*/
{
    ULONG mismatchCount = 0;
    BOOLEAN diskHasASLR;

    if (Disk == NULL || Mem == NULL || Compare == NULL) return E_INVALIDARG;
    RtlZeroMemory(Compare, sizeof(*Compare));

    Compare->ImageBaseMatches = (Disk->ImageBase == Mem->ImageBase);
    Compare->EntryPointMatches = (Disk->EntryPoint == Mem->EntryPoint);
    Compare->SizeOfImageMatches = (Disk->ImageSize == Mem->ImageSize);

    /* 任一 Checksum 为 0 视为无法校验 → 匹配; 仅双非零且不等才算不匹配 */
    Compare->ChecksumMatches = (Disk->Checksum == 0) || (Mem->Checksum == 0) ||
                               (Disk->Checksum == Mem->Checksum);
    Compare->TimestampMatches = (Disk->TimeDateStamp == Mem->TimeDateStamp);
    Compare->SectionCountMatches = (Disk->NumberOfSections == Mem->NumberOfSections);
    Compare->MachineMatches = (Disk->Machine == Mem->Machine);

    diskHasASLR = (Disk->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    if (!Compare->ImageBaseMatches && !diskHasASLR) mismatchCount++;
    if (!Compare->EntryPointMatches) mismatchCount++;
    if (!Compare->SizeOfImageMatches) mismatchCount++;
    if (!Compare->ChecksumMatches) mismatchCount++;
    if (!Compare->TimestampMatches) mismatchCount++;
    if (!Compare->SectionCountMatches) mismatchCount++;
    if (!Compare->MachineMatches) mismatchCount++;

    Compare->MismatchCount = mismatchCount;
    Compare->HeadersMatch = (mismatchCount == 0);

    /* 7 个字段参与比对 */
    Compare->OverallSimilarity = Compare->HeadersMatch ? 1000 :
        (1000 - (mismatchCount * 1000) / 7);

    return S_OK;
}

/**************************************************/
/*             熵 (0-1000, 保算法)                  */
/**************************************************/



/**************************************************/
/*         怀疑评分 / 行为标志 (无调用者)             */
/**************************************************/

ULONG
WpeCalculateSuspicionScore(
    _In_ PWPA_ANALYSIS_RESULT Analysis
    )
/*++
Routine Description:
    计算怀疑评分 (0-100)。无调用者 (供主动分析)。

Return Value:
    评分。
--*/
{
    ULONG score = 0;

    if (Analysis == NULL) return 0;

    if (!Analysis->PE.IsPE) score += 10;
    if (Analysis->PE.IsPacked) score += 30;
    if (!Analysis->PE.IsSigned) score += 15;
    if (Analysis->PE.Entropy >= WPA_ENTROPY_THRESHOLD_ENCRYPTED) score += 25;

    if (!Analysis->Security.HasDEP) score += 15;
    if (!Analysis->Security.HasASLR) score += 10;
    if (!Analysis->Security.HasCFG) score += 5;
    if (Analysis->Security.IsElevated) score += 10;

    if (Analysis->BehaviorFlags & WPA_BEHAVIOR_HIGH_ENTROPY) score += 20;
    if (Analysis->BehaviorFlags & WPA_BEHAVIOR_SCRIPT_HOST) score += 15;
    if (Analysis->BehaviorFlags & WPA_BEHAVIOR_SUSPICIOUS_PARENT) score += 25;
    if (Analysis->BehaviorFlags & WPA_BEHAVIOR_SUSPICIOUS_CMDLINE) score += 25;

    if (score > 100) score = 100;
    return score;
}

ULONG
WpeDetectBehaviorFlags(
    _In_ PWPA_ANALYSIS_RESULT Analysis
    )
/*++
Routine Description:
    检测行为标志。无调用者。

Return Value:
    标志位组合。
--*/
{
    ULONG flags = WPA_BEHAVIOR_NONE;

    if (Analysis == NULL) return flags;

    if (!Analysis->PE.IsSigned) flags |= WPA_BEHAVIOR_UNSIGNED;
    if (Analysis->PE.IsPacked) flags |= WPA_BEHAVIOR_PACKED;
    if (!Analysis->Security.HasDEP) flags |= WPA_BEHAVIOR_NO_DEP;
    if (!Analysis->Security.HasASLR) flags |= WPA_BEHAVIOR_NO_ASLR;
    if (Analysis->Security.IsElevated) flags |= WPA_BEHAVIOR_ELEVATED;
    if (Analysis->PE.Entropy >= WPA_ENTROPY_THRESHOLD_PACKED) flags |= WPA_BEHAVIOR_HIGH_ENTROPY;

    return flags;
}

/**************************************************/
/*        进程级综合风险评分                         */
/**************************************************/

_Use_decl_annotations_
ULONG
WpeCalculateOverallRisk(
    const WKD_RISK_INPUT* Input,
    PWPA_RISK_LEVEL       Level
    )
/*++
Routine Description:
    依据多维度画像计算进程级综合风险分 (0-100), 并映射风险等级。

Arguments:
    Input - 各维度计数输入。
    Level - 输出风险等级。

Return Value:
    0-100 风险分。
--*/
{
    ULONG risk = 0;

    if (!Input) {
        if (Level) *Level = WkdRl_Unknown;
        return 0;
    }
    if (Level) *Level = WkdRl_Trusted;

    /* 快查硬结论 */
    if (Input->IsKnownMalicious) {
        if (Level) *Level = WkdRl_Malicious;
        return 100;
    }
    if (Input->HashFoundMalicious) {
        if (Level) *Level = WkdRl_Malicious;
        return 95;
    }
    if (Input->IsWhitelisted) {
        if (Level) *Level = WkdRl_Trusted;
        return 0;
    }

    /* 签名 */
    if (Input->CertStatus == DefCertStatus_Revoked) {
        risk += 50;
    } else if (Input->CertStatus == DefCertStatus_Unsigned) {
        risk += 15;
    }

    /* 模块 */
    risk += Input->SuspiciousActiveModules * 5;
    risk += Input->UnsignedActiveModules * 2;

    /* 内存画像 */
    risk += Input->RwxRegionCount * 20;
    risk += Input->UnbackedExecRegionCount * 35;

    /* 线程画像 */
    risk += Input->UnbackedStartCount * 25;

    /* 父-子异常 */
    if (Input->ParentAnomaly) risk += 25;
    if (Input->PpidSpoofed) risk += 40;

    /* 行为指标 */
    if (Input->HasProcessHollowing) risk += 40;
    if (Input->HasDirectSyscalls) risk += 30;
    if (Input->HasRemoteThreads) risk += 25;

    risk = min(risk, 100);

    /* 等级映射 */
    if (risk >= 90) {
        if (Level) *Level = WkdRl_Critical;
    } else if (risk >= 75) {
        if (Level) *Level = WkdRl_Suspicious;
    } else if (risk >= 60) {
        if (Level) *Level = WkdRl_HighRisk;
    } else if (risk >= 45) {
        if (Level) *Level = WkdRl_MediumRisk;
    } else if (risk >= 30) {
        if (Level) *Level = WkdRl_LowRisk;
    } else if (risk >= 15) {
        if (Level) *Level = WkdRl_Unknown;
    } else if (risk > 0) {
        if (Level) *Level = WkdRl_Safe;
    } else {
        if (Level) *Level = WkdRl_Trusted;
    }

    return risk;
}

/**************************************************/
/*        收敛①: 模块导出函数名解析                  */
/**************************************************/

NTSTATUS
WpeResolveModuleExportName(
    _In_  HANDLE    ProcessHandle,
    _In_  ULONG_PTR ModuleBase,
    _In_  ULONG_PTR Address,
    _Out_writes_(FuncLen) PWSTR FuncName,
    _In_  ULONG     FuncLen
    )
/*++
Routine Description:
    解析模块导出表中 Address 对应的导出函数名 (收敛 IocKnownDll 私有导出解析)。
    精确匹配 Rva == Address-ModuleBase, 跳过 forwarder。

Arguments:
    ProcessHandle - 目标进程句柄。
    ModuleBase    - 模块基址。
    Address       - 目标地址。
    FuncName      - 输出函数名。
    FuncLen       - 输出缓冲容量。

Return Value:
    STATUS_SUCCESS / STATUS_NOT_FOUND / STATUS_INVALID_PARAMETER。
--*/
{
    PE_PARSER_CONTEXT* ctx;
    PE_EXPORT_DIR ex;
    PE_PARSE_OPTIONS opt;
    NTSTATUS status = STATUS_NOT_FOUND;
    ULONG rva;
    ULONG i;

    if (FuncName == NULL || FuncLen == 0 || Address < ModuleBase) {
        return STATUS_INVALID_PARAMETER;
    }
    FuncName[0] = 0;
    rva = (ULONG)(Address - ModuleBase);

    ctx = (PE_PARSER_CONTEXT*)malloc(sizeof(PE_PARSER_CONTEXT));
    if (ctx == NULL) return STATUS_NO_MEMORY;

    opt = IocDefaultPeParseOptions();
    opt.ComputeSectionEntropy = FALSE;
    opt.CollectAnomalies = FALSE;
    opt.DetectOverlay = FALSE;
    opt.VerifyChecksum = FALSE;

    if (!NT_SUCCESS(PeParseMemoryEx(ctx, ProcessHandle, ModuleBase, 4096, &opt))) {
        free(ctx);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    RtlZeroMemory(&ex, sizeof(ex));
    if (NT_SUCCESS(WpeParseExports(ctx, &ex))) {
        for (i = 0; i < ex.ExportCount; i++) {
            if (ex.Exports[i].Rva == rva &&
                !ex.Exports[i].IsForwarder &&
                ex.Exports[i].NameLength > 0) {
                PWCHAR name = ex.NameBlob + ex.Exports[i].NameOffset;
                wcsncpy_s(FuncName, FuncLen, name, _TRUNCATE);
                status = STATUS_SUCCESS;
                break;
            }
        }
        WpeExportsFree(&ex);
    }

    free(ctx);
    return status;
}

/**************************************************/
/*        收敛②: 内存 PE 重建 (文件对齐)             */
/**************************************************/

NTSTATUS
WpeReconstructPeFromMemory(
    _In_  DWORD     ProcessId,
    _In_  ULONG_PTR BaseAddress,
    _Out_ PBYTE*    OutBuffer,
    _Out_ PULONG    OutSize
    )
/*++
Routine Description:
    从内存重建文件对齐 PE (收敛 MsReconstructPE, 对齐 SS ReconstructPE):
     读头 4096 → 校验 (DOS/NT/节数/SizeOfImage≤256MB) →
     读整个内存映像 → 按节表 PointerToRawData 重建文件布局。
    无 raw 数据指针时内存直出。死代码: 取证阶段接入。

Arguments:
    ProcessId   - 目标进程 PID。
    BaseAddress - 映像基址。
    OutBuffer   - 输出重建缓冲 (调用方 free)。
    OutSize     - 输出大小。

Return Value:
    NTSTATUS。
--*/
{
    PBYTE headerBuf = NULL;
    PBYTE memImage = NULL;
    PBYTE rebuilt = NULL;
    ULONG headerBytes = 0;
    ULONG imageBytes = 0;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    ULONG_PTR imageSize = 0;
    ULONG fileAlignment = 0;
    ULONG numSections = 0;
    ULONG maxFileOffset = 0;
    ULONG i;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (OutBuffer == NULL || OutSize == NULL) return STATUS_INVALID_PARAMETER;
    *OutBuffer = NULL;
    *OutSize = 0;

    /* 1. 读 PE 头 (对齐 SS MAX_PE_HEADER_SCAN=4096) */
    if (!NT_SUCCESS(WpeRpmAlloc(ProcessId, BaseAddress, 4096, &headerBuf, &headerBytes))) {
        return STATUS_UNSUCCESSFUL;
    }
    if (headerBytes < sizeof(IMAGE_DOS_HEADER)) goto done;

    dos = (PIMAGE_DOS_HEADER)headerBuf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto done;
    if ((ULONG)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > headerBytes) goto done;

    nt = (PIMAGE_NT_HEADERS)(headerBuf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) goto done;
    numSections = nt->FileHeader.NumberOfSections;
    if (numSections > WKD_PE_MAX_SECTIONS) goto done;

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        PIMAGE_OPTIONAL_HEADER64 opt = (PIMAGE_OPTIONAL_HEADER64)&nt->OptionalHeader;
        imageSize = opt->SizeOfImage;
        fileAlignment = opt->FileAlignment;
    } else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        PIMAGE_OPTIONAL_HEADER32 opt = (PIMAGE_OPTIONAL_HEADER32)&nt->OptionalHeader;
        imageSize = opt->SizeOfImage;
        fileAlignment = opt->FileAlignment;
    } else {
        goto done;
    }

    /* 2. SizeOfImage 校验 (非零且 ≤256MB) */
    if (imageSize == 0 || imageSize > WKD_PE_DEEP_MAX_IMAGE) goto done;
    if (fileAlignment == 0) fileAlignment = 0x200;

    /* 3. 读整个内存映像 */
    if (!NT_SUCCESS(WpeRpmAlloc(ProcessId, BaseAddress, (SIZE_T)imageSize,
                                &memImage, &imageBytes))) {
        goto done;
    }
    if (imageBytes < sizeof(IMAGE_DOS_HEADER)) goto done;

    /* 4. 重建文件对齐 PE */
    {
        PIMAGE_SECTION_HEADER firstSection = IMAGE_FIRST_SECTION(nt);
        ULONG sectionTableEnd = (ULONG)dos->e_lfanew + sizeof(ULONG) +
                                sizeof(IMAGE_FILE_HEADER) +
                                nt->FileHeader.SizeOfOptionalHeader +
                                numSections * sizeof(IMAGE_SECTION_HEADER);
        if (sectionTableEnd > headerBytes) goto done;

        /* 计算文件大小 (各节 raw 结束最大偏移) */
        for (i = 0; i < numSections; i++) {
            ULONG rawEnd = firstSection[i].PointerToRawData + firstSection[i].SizeOfRawData;
            if (rawEnd > maxFileOffset) maxFileOffset = rawEnd;
        }

        /* 无 raw 数据指针 → 内存直出 */
        if (maxFileOffset == 0) {
            *OutBuffer = memImage;
            *OutSize = (ULONG)imageSize;
            memImage = NULL;
            status = STATUS_SUCCESS;
            goto done;
        }

        rebuilt = (PBYTE)malloc(maxFileOffset);
        if (rebuilt == NULL) goto done;
        memset(rebuilt, 0, maxFileOffset);

        /* 复制头区到首节 raw 偏移 */
        {
            ULONG headerCopy = firstSection[0].PointerToRawData;
            if (headerCopy == 0) headerCopy = 0x200;
            headerCopy = min(headerCopy, (ULONG)imageBytes);
            memcpy(rebuilt, memImage, headerCopy);
        }

        /* 逐节从 VA 偏移复制到文件偏移 */
        for (i = 0; i < numSections; i++) {
            PIMAGE_SECTION_HEADER sec = &firstSection[i];
            ULONG copySize;
            if (sec->VirtualAddress >= imageBytes) continue;
            if (sec->PointerToRawData >= maxFileOffset) continue;
            copySize = min(min(sec->SizeOfRawData, imageBytes - sec->VirtualAddress),
                           maxFileOffset - sec->PointerToRawData);
            memcpy(rebuilt + sec->PointerToRawData,
                   memImage + sec->VirtualAddress, copySize);
        }

        *OutBuffer = rebuilt;
        *OutSize = maxFileOffset;
        rebuilt = NULL;
        status = STATUS_SUCCESS;
    }

done:
    if (headerBuf) free(headerBuf);
    if (memImage) free(memImage);
    if (rebuilt) free(rebuilt);
    return status;
}

/**************************************************/
/*        收敛③: 内存 vs 磁盘模块完整性              */
/**************************************************/

BOOLEAN
WpeValidateModuleIntegrity(
    _In_ ULONG     ProcessId,
    _In_ ULONG_PTR ModuleBase,
    _In_ PCWSTR    ModulePath
    )
/*++
Routine Description:
    比较内存 PE 头与磁盘文件 PE 头 (收敛 IpeValidateModuleIntegrity,
    增强为 7 字段 WpeComparePEHeaders)。死代码: 无调用者。

Arguments:
    ProcessId  - 目标进程 PID。
    ModuleBase - 模块基址。
    ModulePath - 磁盘模块路径。

Return Value:
    TRUE=一致。
--*/
{
    HANDLE hProcess;
    WPA_PE_INFO memInfo;
    WPA_PE_INFO diskInfo;
    WKD_PE_HEADER_COMPARE compare;
    BOOLEAN result = FALSE;

    if (ProcessId == 0 || ProcessId == 4 || ModuleBase == 0 ||
        ModulePath == NULL || ModulePath[0] == 0) {
        return FALSE;
    }

    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (hProcess == NULL) return FALSE;

    /* 内存头 */
    if (SUCCEEDED(WpeAnalyzePEHeaders(hProcess, (PVOID)ModuleBase, &memInfo)) &&
        memInfo.IsPE) {
        /* 磁盘头 (读文件) */
        if (SUCCEEDED(WpeAnalyzePEHeadersFromFile(ModulePath, &diskInfo)) &&
            diskInfo.IsPE) {
            if (SUCCEEDED(WpeComparePEHeaders(&diskInfo, &memInfo, &compare))) {
                result = compare.HeadersMatch;
            }
        }
    }

    CloseHandle(hProcess);
    return result;
}

/**************************************************/
/*        版本信息提取                               */
/**************************************************/

NTSTATUS
WpeGetVersionInfo(
    _In_  PCWSTR            FilePath,
    _Out_ PPE_VERSION_INFO Version
    )
/*++
Routine Description:
    提取文件版本信息 (GetFileVersionInfoSizeW/GetFileVersionInfoW/VerQueryValueW)。
    对齐 SS GetVersionInfoImpl L2508-2583: 文件/产品四段版本 +
    CompanyName/FileDescription/FileVersion/InternalName/LegalCopyright/
    OriginalFilename/ProductName/ProductVersion。

Arguments:
    FilePath - 文件路径。
    Version  - 输出版本信息 (未找到时 HasVersionInfo=FALSE, STATUS_NOT_FOUND)。

Return Value:
    NTSTATUS。
--*/
{
    DWORD handle = 0;
    DWORD size;
    BYTE* data;
    VS_FIXEDFILEINFO* fileInfo = NULL;
    UINT fileInfoSize = 0;

    if (FilePath == NULL || Version == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Version, sizeof(*Version));

    size = GetFileVersionInfoSizeW(FilePath, &handle);
    if (size == 0) return STATUS_NOT_FOUND;

    data = (BYTE*)malloc(size);
    if (data == NULL) return STATUS_NO_MEMORY;

    if (!GetFileVersionInfoW(FilePath, 0, size, data)) {
        free(data);
        return STATUS_UNSUCCESSFUL;
    }

    /* 固定版本号 (VS_FIXEDFILEINFO) */
    if (VerQueryValueW(data, L"\\", (LPVOID*)&fileInfo, &fileInfoSize) && fileInfo != NULL) {
        Version->HasVersionInfo = TRUE;
        Version->FileMajor = HIWORD(fileInfo->dwFileVersionMS);
        Version->FileMinor = LOWORD(fileInfo->dwFileVersionMS);
        Version->FileBuild = HIWORD(fileInfo->dwFileVersionLS);
        Version->FileRevision = LOWORD(fileInfo->dwFileVersionLS);
        Version->ProductMajor = HIWORD(fileInfo->dwProductVersionMS);
        Version->ProductMinor = LOWORD(fileInfo->dwProductVersionMS);
        Version->ProductBuild = HIWORD(fileInfo->dwProductVersionLS);
        Version->ProductRevision = LOWORD(fileInfo->dwProductVersionLS);
    }

    /* Translation → StringFileInfo 字符串查询 */
    {
        struct {
            WORD language;
            WORD codePage;
        } *translation = NULL;
        UINT translationSize = 0;

        if (VerQueryValueW(data, L"\\VarFileInfo\\Translation",
                          (LPVOID*)&translation, &translationSize) &&
            translation != NULL && translationSize >= sizeof(*translation)) {
            WCHAR subBlock[256];

            const struct {
                PCWSTR Name;
                PWCHAR Out;
                ULONG  Cch;
            } kStrings[] = {
                { L"CompanyName",      Version->CompanyName,      (ULONG)sizeof(Version->CompanyName) / sizeof(WCHAR) },
                { L"FileDescription",  Version->FileDescription,  (ULONG)sizeof(Version->FileDescription) / sizeof(WCHAR) },
                { L"FileVersion",      Version->FileVersion,      (ULONG)sizeof(Version->FileVersion) / sizeof(WCHAR) },
                { L"InternalName",     Version->InternalName,     (ULONG)sizeof(Version->InternalName) / sizeof(WCHAR) },
                { L"LegalCopyright",   Version->LegalCopyright,   (ULONG)sizeof(Version->LegalCopyright) / sizeof(WCHAR) },
                { L"OriginalFilename", Version->OriginalFilename, (ULONG)sizeof(Version->OriginalFilename) / sizeof(WCHAR) },
                { L"ProductName",      Version->ProductName,      (ULONG)sizeof(Version->ProductName) / sizeof(WCHAR) },
                { L"ProductVersion",   Version->ProductVersion,   (ULONG)sizeof(Version->ProductVersion) / sizeof(WCHAR) },
            };
            ULONG k;

            for (k = 0; k < sizeof(kStrings) / sizeof(kStrings[0]); k++) {
                WCHAR* value = NULL;
                UINT valueSize = 0;
                swprintf_s(subBlock, sizeof(subBlock) / sizeof(subBlock[0]),
                           L"\\StringFileInfo\\%04x%04x\\%s",
                           (UINT)translation->language, (UINT)translation->codePage,
                           kStrings[k].Name);
                if (VerQueryValueW(data, subBlock, (LPVOID*)&value, &valueSize) &&
                    value != NULL && value[0] != 0) {
                    wcsncpy_s(kStrings[k].Out, kStrings[k].Cch, value, _TRUNCATE);
                }
            }
        }
    }

    free(data);
    return STATUS_SUCCESS;
}

/**************************************************/
/*        ML 特征向量 (死代码, 对齐 SS ExtractMLFeatures)  */
/**************************************************/

#define PE_ML_SECTIONS_CAP     16
#define PE_ML_SECTION_FEATURES 8

static
VOID
WpeMlPush(
    _Inout_ PPE_ML_FEATURES F,
    _In_    FLOAT            V
    )
{
    if (F->Count < PE_ML_FEATURE_MAX) F->Values[F->Count++] = V;
}

static
BOOLEAN
WpeMlHasAnomaly(
    _In_ const PE_INFO* Info,
    _In_ PE_ANOMALY_TYPE   Type
    )
{
    ULONG i;

    for (i = 0; i < Info->AnomalyCount; i++) {
        if (Info->Anomalies[i].Type == Type) return TRUE;
    }
    return FALSE;
}

NTSTATUS
WpeExtractMlFeatures(
    _In_  const PE_INFO* Info,
    _Out_ PPE_ML_FEATURES  Features
    )
/*++
Routine Description:
    提取静态 PE 特征向量 (EMBER 对齐布局骨架, 对齐 SS ExtractMLFeatures L2799-2921)。
    死代码: wkd 无 ONNX/PhantomCortex, 供未来 ML 融合预留。
    注: 导入/导出/资源明细与 overallEntropy/riskScore 不内嵌 PE_INFO
        (PeLazy 惰性输出), 相关特征用目录 Present/0 近似 (注释标注)。

Arguments:
    Info     - PeParser 解析结果。
    Features - 输出特征向量 (Count + Values[])。

Return Value:
    NTSTATUS。
--*/
{
    ULONG i;
    DOUBLE avgEntropy = 0.0;
    ULONG entropyCount = 0;

    if (Info == NULL || Features == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Features, sizeof(*Features));

    for (i = 0; i < Info->NumberOfSections; i++) {
        if (Info->Sections[i].ShannonEntropy >= 0.0) {
            avgEntropy += Info->Sections[i].ShannonEntropy;
            entropyCount++;
        }
    }
    if (entropyCount > 0) avgEntropy /= entropyCount;

    /* --- 头特征 (16) --- */
    WpeMlPush(Features, Info->Amd64 ? 1.0f : 0.0f);
    WpeMlPush(Features, (FLOAT)Info->ImageBase);
    WpeMlPush(Features, (FLOAT)Info->AddressOfEntryPoint);
    WpeMlPush(Features, (FLOAT)Info->FileSize);
    WpeMlPush(Features, (FLOAT)Info->NumberOfSections);
    WpeMlPush(Features, Info->DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Present ? 1.0f : 0.0f);
    WpeMlPush(Features, Info->DataDirectories[PE_DD_EXPORT].Present ? 1.0f : 0.0f);
    WpeMlPush(Features, 0.0f);   /* overallEntropy (未计算) */
    WpeMlPush(Features, (FLOAT)avgEntropy);
    WpeMlPush(Features, Info->IsSigned ? 1.0f : 0.0f);
    WpeMlPush(Features, Info->IsDotNet ? 1.0f : 0.0f);
    WpeMlPush(Features, WpeMlHasAnomaly(Info, WpeAnom_PackerSignatureDetected) ? 1.0f : 0.0f);
    WpeMlPush(Features, 0.0f);   /* richHeader.present (惰性未内嵌) */
    WpeMlPush(Features, 0.0f);   /* richHeader.valid */
    WpeMlPush(Features, 0.0f);   /* richHeader.entries.size */
    WpeMlPush(Features, (FLOAT)Info->AnomalyCount);   /* riskScore 近似 */

    /* --- 节特征 (最多 16 节 × 8) --- */
    for (i = 0; i < PE_ML_SECTIONS_CAP; i++) {
        if (i < Info->NumberOfSections) {
            const PE_SECTION* s = &Info->Sections[i];
            WpeMlPush(Features, (FLOAT)s->VirtualSize);
            WpeMlPush(Features, (FLOAT)s->SizeOfRawData);
            WpeMlPush(Features, s->ShannonEntropy >= 0.0 ? (FLOAT)s->ShannonEntropy : 0.0f);
            WpeMlPush(Features, s->IsExecutable ? 1.0f : 0.0f);
            WpeMlPush(Features, s->IsWritable ? 1.0f : 0.0f);
            WpeMlPush(Features, s->IsPackedHeuristic ? 1.0f : 0.0f);
            WpeMlPush(Features, s->VirtualSize > 0 ? (FLOAT)s->SizeOfRawData / (FLOAT)s->VirtualSize : 0.0f);
            WpeMlPush(Features, (FLOAT)s->Characteristics);
        } else {
            ULONG j;
            for (j = 0; j < PE_ML_SECTION_FEATURES; j++) WpeMlPush(Features, 0.0f);
        }
    }

    /* --- 导入特征 (3) — 明细惰性未内嵌, 目录 Present + 0 近似 --- */
    WpeMlPush(Features, Info->DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Present ? 1.0f : 0.0f);
    WpeMlPush(Features, 0.0f);   /* riskyImportCount */
    WpeMlPush(Features, 0.0f);   /* ordinalImportCount */

    /* --- 导出特征 (3) --- */
    WpeMlPush(Features, Info->DataDirectories[PE_DD_EXPORT].Present ? 1.0f : 0.0f);
    WpeMlPush(Features, 0.0f);   /* forwardedExportCount */
    WpeMlPush(Features, 0.0f);   /* ordinalExportCount */

    /* --- 异常特征 (4) — wkd 无 Severity 字段, 总计数 + 强信号近似 --- */
    WpeMlPush(Features, (FLOAT)Info->AnomalyCount);
    WpeMlPush(Features, WpeMlHasAnomaly(Info, WpeAnom_OverlappingSections) ? 1.0f : 0.0f);
    WpeMlPush(Features, WpeMlHasAnomaly(Info, WpeAnom_ResourcesContainPE) ? 1.0f : 0.0f);
    WpeMlPush(Features, WpeMlHasAnomaly(Info, WpeAnom_ApiHashing) ? 1.0f : 0.0f);

    /* --- APT 指示特征 (13) --- */
    WpeMlPush(Features, WpeMlHasAnomaly(Info, WpeAnom_TLSCallbackPresent) ? 1.0f : 0.0f);
    WpeMlPush(Features, 0.0f);   /* tlsCallbackCount (惰性未内嵌) */
    WpeMlPush(Features, WpeMlHasAnomaly(Info, WpeAnom_DelayLoadSuspicious) ? 1.0f : 0.0f);
    WpeMlPush(Features, 0.0f);   /* delayLoadImports.size */
    WpeMlPush(Features, WpeMlHasAnomaly(Info, WpeAnom_OverlappingSections) ? 1.0f : 0.0f);
    WpeMlPush(Features, WpeMlHasAnomaly(Info, WpeAnom_EntryPointOutsideFile) ? 1.0f : 0.0f);
    WpeMlPush(Features, (Info->DllCharacteristics & PE_DLLC_GUARD_CF) ? 1.0f : 0.0f);
    WpeMlPush(Features, 0.0f);   /* hasCET (LoadConfig 惰性) */
    WpeMlPush(Features, (Info->DllCharacteristics & PE_DLLC_FORCE_INTEGRITY) ? 1.0f : 0.0f);
    WpeMlPush(Features, Info->OverlayContainsPE ? 1.0f : 0.0f);
    WpeMlPush(Features, 0.0f);   /* overlayEntropy (未计算) */
    WpeMlPush(Features, (FLOAT)Info->OverlaySize);
    WpeMlPush(Features, WpeMlHasAnomaly(Info, WpeAnom_SectionHighEntropy) ? 1.0f : 0.0f);   /* hasDebug 近似 */

    return STATUS_SUCCESS;
}

/**************************************************/
/*        门面薄转发 (活代码直调点收口)              */
/*  外部经 PeAnalyzer.h 调用; 内部 1:1 跳转至        */
/*  PeParser/PeLazy 解析层, 不新增语义。            */
/**************************************************/

/* 文件解析(路径) (替代 IocDefaultPeParseOptions + IocAnalyzePeFromFilePath)。
 * 注: 继承 IocAnalyzePeFromFilePath "解析失败仍返回 STATUS_SUCCESS" 的既有怪癖 (PeParser.c:1153)。 */
NTSTATUS
IocAnalyzePe(
    _In_ PCWSTR ImagePath,
    _Out_ PPE_INFO Info
    )
{
    PE_PARSE_OPTIONS opts;

    if (!CoCheckStringValidity(ImagePath) || !Info) {
        return STATUS_INVALID_PARAMETER;
    }

    opts = IocDefaultPeParseOptions();
    return IocAnalyzePeFromFilePath(ImagePath, &opts, Info, NULL);
}

NTSTATUS
IocAnalyzeFileHandle(
    _In_ HANDLE FileHandle,
    _In_ SIZE_T Size,
    _Out_ PPE_INFO Info
    )
{
    PE_PARSE_OPTIONS opts;

    if (FileHandle == INVALID_HANDLE_VALUE || FileHandle == NULL || Size == 0 || !Info) {
        return STATUS_INVALID_PARAMETER;
    }

    opts = IocDefaultPeParseOptions();
    return IocpAnalyzeFileHandle(FileHandle, Size, &opts, Info, NULL);
}

/* 缓冲上下文解析 (替代 IocDefaultPeParseOptions + IocpAnalyzeBufferEx) */
NTSTATUS
WpeParseBufferContext(
    _Inout_ PPE_PARSER_CONTEXT Ctx,
    _In_    const BYTE*        Data,
    _In_    SIZE_T             Size,
    _In_    BOOLEAN            ComputeSectionEntropy
    )
{
    PE_PARSE_OPTIONS opt;

    opt = IocDefaultPeParseOptions();
    opt.ComputeSectionEntropy = ComputeSectionEntropy;
    return IocpAnalyzeBufferEx(Ctx, Data, Size, &opt);
}

/* 重置解析上下文 (替代 WpeParseContextReset) */
VOID
WpeResetParseContext(
    _Inout_ PPE_PARSER_CONTEXT Ctx
    )
{
    WpeParseContextReset(Ctx);
}

/* 导入表释放 (替代 WpeImportsFree) */
VOID
WpeFreeImportList(
    _Inout_ PPE_IMPORT_LIST List
    )
{
    WpeImportsFree(List);
}

/* 统一导入表校验门面（双 reader, 2026-09-07 重构）：对目标进程主模块的
 * 常规导入表 + 延迟导入表一次性校验（延迟导入表复用同一装配, 不再独立门面）。
 * 内部装配：
 *   - CoOpenProcessForQueryRead 打开进程句柄（AccessControl 侧反调试检测块
 *     同源共用, 迁 Common/Utils 消除 IOC→AccessControl 循环依赖）；
 *   - PsGetMainModuleInstance 派生主模块基址/SizeOfImage 与磁盘路径；
 *   - CoOpenFileForSequentialRead（拒绝目录/reparse, TOCTOU-safe）打开磁盘
 *     副本为校验 reader（文件权威）;
 *   - 主 reader = PeParseMemoryEx 进程内存模式；ImportVerify[0]/[1] 分别挂
 *     常规/延迟双 reader 回调, Context 注入 Result->Iat / Result->Delay,
 *     PepParseImports + WpeParseDelayImportList 两次解析覆盖两表。
 * 命中语义见 Result：Iat.Found（常规）/ Delay.Found（延迟）。句柄/文件/
 * 解析上下文全部内部管理，调用方仅需持有稳定的 WKD_PROCESS 引用。 */
_Use_decl_annotations_
NTSTATUS
PeVerifyFunctionAddressTable(
    _In_ const PWKD_PROCESS WkdProcess,
    _Out_ PPE_IMPORT_VERIFY_RESULT Result
    )
{
    PPE_PARSER_CONTEXT ctx;
    PE_PARSE_OPTIONS opt;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    HANDLE hProcess = NULL;
    PWKD_MODULE_INSTANCE instance = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    SIZE_T fileSize = 0;
    PE_IMPORT_LIST importList = { 0 };     /* 校验模式截断到 DLL 层（命中经回调回填） */
    PE_DELAY_IMPORT_LIST delayList = { 0 };

    if (!WkdProcess || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(PE_IMPORT_VERIFY_RESULT));

    /* 1. 进程句柄（最小读取权限, 2026-09-07 经 CoOpenProcessForQueryRead） */
    if (!CoOpenProcessForQueryRead(HandleToULong(WkdProcess->ProcessId), &hProcess)) {
        return STATUS_ACCESS_DENIED;
    }
    
    /* 2. 主模块域（基址/SizeOfImage/磁盘路径）：主模块未挂或未映射 → 不值得校验 */
    if (!NT_SUCCESS(PsGetMainModuleInstance(WkdProcess, &instance))) {
        status = STATUS_NOT_FOUND;
        goto Cleanup;
    }

    /* 3. 磁盘副本（校验 reader 权威源）：直接复用 CoOpenFileForSequentialRead,
     * 替代 CreateFileW/GetFileSizeEx（拒绝目录/reparse, TOCTOU-safe）。 */
    hFile = CoOpenFileForSequentialRead(instance->Module->ImagePath->Buffer, &fileSize);
    if (hFile == INVALID_HANDLE_VALUE || fileSize == 0) {
        status = STATUS_NOT_FOUND;
        goto Cleanup;
    }

    ctx = (PPE_PARSER_CONTEXT)malloc(sizeof(PE_PARSER_CONTEXT));
    if (!ctx) { status = STATUS_NO_MEMORY; goto Cleanup; }
    RtlZeroMemory(ctx, sizeof(PE_PARSER_CONTEXT));

    opt = IocDefaultPeParseOptions();
    opt.ComputeSectionEntropy = FALSE;
    opt.CollectAnomalies = FALSE;
    opt.DetectOverlay = FALSE;
    opt.VerifyChecksum = FALSE;

    if (!NT_SUCCESS(PeParseMemoryEx(ctx, hProcess, instance->ImageBase,
                                    instance->Module->SizeOfImage, &opt))) {
        free(ctx);
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto Cleanup;
    }

    /* 4. 校验载体注入 + 双槽回调（2026-09-07 重构：输入内聚 Ctx, 输出门面托管） */
    ctx->VerifyProcess = WkdProcess;
    ctx->VerifyProcessHandle = hProcess;
    ctx->ImportVerify[0].Callback = PepVerifyImportDllByDualReader;
    ctx->ImportVerify[0].Context = &Result->Iat;
    ctx->ImportVerify[1].Callback = PepVerifyDelayImportDllByDualReader;
    ctx->ImportVerify[1].Context = &Result->Delay;
    PepCreateFileReader(&ctx->VerifyReader, hFile, fileSize);

    /* 5. 常规 + 延迟一次覆盖（命中经回调回填 Result, 列表仅作截断遍历载体） */
    PepParseImports(ctx, &importList);
    WpeParseDelayImportList(ctx, &delayList);
    status = STATUS_SUCCESS;

    /* 校验 reader（文件模式）独立于主 reader, 须显式销毁（WpeResetParseContext 不覆盖） */
    if (ctx->VerifyReader.Mode == PeReader_File) {
        IocReaderDestroy(&ctx->VerifyReader);
    }
    WpeResetParseContext(ctx);
    free(ctx);

Cleanup:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (hProcess != INVALID_HANDLE_VALUE) CloseHandle(hProcess);
    return status;
}

/* 按 RVA 读字节 (替代 WpeRvaToOffset + IocpReaderRead, 封装 EP stub 读取)。
 * 等价语义: Rva 无效/超出解析域 → FALSE; 读 min(域剩余, Capacity) 字节。 */
static NTSTATUS
IocpReadPeBytesAtRva(
    _In_ const PE_PARSER_CONTEXT* Context,
    _In_ ULONG Rva,
    _Out_ PVOID Out,
    _In_ SIZE_T Capacity,
    _Out_ PSIZE_T BytesRead
    )
{
    NTSTATUS status;
    PE_READER reader;
    ULONG offset, available;

    if (!Context || !Out || !BytesRead || Capacity == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Out, Capacity);
    *BytesRead = 0;

    if (!IocpRvaToOffset(Context, Rva, &offset)) {
        return STATUS_BUFFER_OVERFLOW;
    }

    reader = Context->Reader;
    if (offset >= reader.Size) {
        return STATUS_BUFFER_OVERFLOW;
    }

    available = max((ULONG)reader.Size - offset, Capacity);
    status = IocpReaderReadBytes(&reader, offset, Out, available) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    if (!NT_SUCCESS(status))  return status;
    *BytesRead = available;
    return STATUS_SUCCESS;
}



/* 静态解包 (1:1 转接 WpeUnpackPackedBuffer) */
NTSTATUS
WpeUnpackBuffer(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  const BYTE*              FileData,
    _In_  SIZE_T                   FileSize,
    _Out_ PPE_UNPACK_RESULT       Result
    )
{
    return WpeUnpackPackedBuffer(Ctx, FileData, FileSize, Result);
}

/* 释放解包结果 (1:1 转接 WpeUnpackResultFree) */
VOID
WpeFreeUnpackResult(
    _Inout_ PPE_UNPACK_RESULT Result
    )
{
    WpeUnpackResultFree(Result);
}

/* 按文件偏移读字节 (转接 CopValidateReadingRange + IocpReaderRead);
 * Reader 拷贝副本, 不污染 Ctx 页缓存。 */
BOOLEAN
WpeReadBytesAtOffset(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  ULONGLONG                Offset,
    _Out_ void*                    Out,
    _In_  SIZE_T                   Size
    )
{
    PE_READER reader;

    if (Ctx == NULL || Out == NULL || Size == 0) {
        return FALSE;
    }
    if (!CopValidateReadingRange(&Ctx->Reader, Offset, Size)) {
        return FALSE;
    }
    reader = Ctx->Reader;
    return IocpReaderReadBytes(&reader, Offset, Out, Size);
}

/* 延迟导入解析 (1:1 转接 WpeParseDelayImports) */
NTSTATUS
WpeParseDelayImportList(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_DELAY_IMPORT_LIST   Out
    )
{
    return WpeParseDelayImports(Ctx, Out);
}

/* 释放延迟导入结果 (1:1 转接 WpeDelayImportsFree) */
VOID
WpeFreeDelayImportList(
    _Inout_ PPE_DELAY_IMPORT_LIST List
    )
{
    WpeDelayImportsFree(List);
}

/**************************************************/
/*      PE 启发式静态分析 (迁移自 IocScanner.c)      */
/*  文件级静态启发式: 可疑 API / 加壳 / 字符串 /     */
/*  PE 结构异常 4 维聚合为 HeuristicConfidence。    */
/*  2026-08-19 自 IocScanner.c 迁入 (档案 #70),     */
/*  迁移时统一修复原 GBK 乱码注释。                */
/**************************************************/

/* -------------------------------------------------- */
/* 5.1 可疑 API 分类表                                 */
/* -------------------------------------------------- */

/* 可疑 API 表: 对齐 SS InitializeSuspiciousImports。
 * 剔除 GetDC (SS 归 ScreenCapture, 常见于正常 GUI 程序, 高误报);
 * 补齐网络/下载/凭据等高风险类别条目
 * (socket/connect/WinHttp/WinExec/CryptUnprotectData)。 */
static const IOC_API_CAT_ENTRY g_IocSuspiciousApis[] = {
    /* 进程操作 */
    { "CreateRemoteThread",         IocApiCat_ProcessManipulation },
    { "CreateRemoteThreadEx",       IocApiCat_ProcessManipulation },
    { "WriteProcessMemory",         IocApiCat_ProcessManipulation },
    { "ReadProcessMemory",          IocApiCat_ProcessManipulation },
    { "SetThreadContext",           IocApiCat_ProcessManipulation },
    /* 内存操作 */
    { "VirtualAllocEx",             IocApiCat_MemoryOperations },
    { "VirtualProtectEx",           IocApiCat_MemoryOperations },
    { "VirtualProtect",             IocApiCat_MemoryOperations },
    { "VirtualAlloc",               IocApiCat_MemoryOperations },
    /* 代码注入 */
    { "QueueUserAPC",               IocApiCat_CodeInjection },
    { "NtQueueApcThread",           IocApiCat_CodeInjection },
    { "NtCreateThreadEx",           IocApiCat_CodeInjection },
    { "RtlCreateUserThread",        IocApiCat_CodeInjection },
    /* 动态加载 */
    { "LoadLibraryA",               IocApiCat_DynamicCode },
    { "LoadLibraryW",               IocApiCat_DynamicCode },
    { "LoadLibraryExA",             IocApiCat_DynamicCode },
    { "LoadLibraryExW",             IocApiCat_DynamicCode },
    { "GetProcAddress",             IocApiCat_DynamicCode },
    /* 反调试 */
    { "IsDebuggerPresent",          IocApiCat_AntiDebug },
    { "CheckRemoteDebuggerPresent", IocApiCat_AntiDebug },
    { "NtQueryInformationProcess",  IocApiCat_AntiDebug },
    { "OutputDebugStringA",         IocApiCat_AntiDebug },
    { "OutputDebugStringW",         IocApiCat_AntiDebug },
    /* 注册表 */
    { "RegSetValueExA",             IocApiCat_RegistryOperations },
    { "RegSetValueExW",             IocApiCat_RegistryOperations },
    { "RegCreateKeyExA",            IocApiCat_RegistryOperations },
    { "RegCreateKeyExW",            IocApiCat_RegistryOperations },
    /* 服务 */
    { "CreateServiceA",             IocApiCat_ServiceOperations },
    { "CreateServiceW",             IocApiCat_ServiceOperations },
    { "ChangeServiceConfigA",       IocApiCat_ServiceOperations },
    { "ChangeServiceConfigW",       IocApiCat_ServiceOperations },
    /* 输入捕获 */
    { "SetWindowsHookExA",          IocApiCat_InputCapture },
    { "SetWindowsHookExW",          IocApiCat_InputCapture },
    { "GetAsyncKeyState",           IocApiCat_InputCapture },
    { "GetKeyState",                IocApiCat_InputCapture },
    /* 网络 */
    { "InternetOpenA",              IocApiCat_NetworkOperations },
    { "InternetOpenW",              IocApiCat_NetworkOperations },
    { "InternetConnectA",           IocApiCat_NetworkOperations },
    { "InternetConnectW",           IocApiCat_NetworkOperations },
    { "HttpSendRequestA",           IocApiCat_NetworkOperations },
    { "HttpSendRequestW",           IocApiCat_NetworkOperations },
    { "URLDownloadToFileA",         IocApiCat_NetworkOperations },
    { "URLDownloadToFileW",         IocApiCat_NetworkOperations },
    { "WinHttpOpen",                IocApiCat_NetworkOperations },
    { "WinHttpConnect",             IocApiCat_NetworkOperations },
    { "WSASocketA",                 IocApiCat_NetworkOperations },
    { "socket",                     IocApiCat_NetworkOperations },
    { "connect",                    IocApiCat_NetworkOperations },
    /* 加密 */
    { "CryptEncrypt",               IocApiCat_CryptoOperations },
    { "CryptDecrypt",               IocApiCat_CryptoOperations },
    { "CryptDeriveKey",             IocApiCat_CryptoOperations },
    { "CryptGenKey",                IocApiCat_CryptoOperations },
    /* 凭据 */
    { "CredReadA",                  IocApiCat_CredentialAccess },
    { "CredReadW",                  IocApiCat_CredentialAccess },
    { "CryptUnprotectData",         IocApiCat_CredentialAccess },
    /* 提权 */
    { "AdjustTokenPrivileges",      IocApiCat_PrivilegeEscalation },
    { "OpenProcessToken",           IocApiCat_PrivilegeEscalation },
    { "ImpersonateLoggedOnUser",    IocApiCat_PrivilegeEscalation },
    /* 屏幕捕获 (GetDC 已剔除: 误报) */
    { "BitBlt",                     IocApiCat_ScreenCapture },
    /* Shell */
    { "ShellExecuteA",              IocApiCat_Shell },
    { "ShellExecuteW",              IocApiCat_Shell },
    { "ShellExecuteExA",            IocApiCat_Shell },
    { "ShellExecuteExW",            IocApiCat_Shell },
    { "WinExec",                    IocApiCat_Shell },
    /* COM */
    { "CoCreateInstance",           IocApiCat_Com },
    /* 剪贴板访问 (T1115, 迁移自 SS ClipboardMonitor SuspiciousImports;
     * 因剪贴板 API 常见于正常 GUI 程序, 计分低档, 见 IocScan_ApiCategoryScore) */
    { "OpenClipboard",              IocApiCat_ClipboardAccess },
    { "GetClipboardData",           IocApiCat_ClipboardAccess },
    { "SetClipboardData",           IocApiCat_ClipboardAccess },
    { "OleGetClipboard",            IocApiCat_ClipboardAccess },
    { "RegisterClipboardFormat",    IocApiCat_ClipboardAccess },
    /* SS RiskyAPIDatabase 补漏 (2026-08): Nt/Zw 直接调用系 / 凭据 / 提权 / 反审计。
     * 对齐 SS InitializeSuspiciousImports 的底层 API 集, 映射到 wkd 既有分类 (重功能非复制)。
     * 注: Nt 直接调用常被静态分析器误报 (动态存在) 或由静态 IAT 呈现, 为有效信号。 */
    /* 内存/线程直接 (注入/引用) */
    { "NtAllocateVirtualMemory",     IocApiCat_CodeInjection },
    { "NtWriteVirtualMemory",        IocApiCat_CodeInjection },
    { "NtReadVirtualMemory",         IocApiCat_ProcessManipulation },
    { "NtProtectVirtualMemory",      IocApiCat_MemoryOperations },
    { "NtMapViewOfSection",          IocApiCat_CodeInjection },
    { "NtUnmapViewOfSection",        IocApiCat_CodeInjection },
    { "NtCreateSection",             IocApiCat_CodeInjection },
    { "NtSuspendThread",             IocApiCat_ProcessManipulation },
    { "NtResumeThread",              IocApiCat_ProcessManipulation },
    { "NtSetContextThread",          IocApiCat_ProcessManipulation },
    { "ZwSetContextThread",          IocApiCat_ProcessManipulation },
    /* 反审计直调 */
    { "NtSetInformationThread",      IocApiCat_AntiDebug },
    { "NtSetInformationProcess",     IocApiCat_AntiDebug },
    { "ZwQueryInformationProcess",   IocApiCat_AntiDebug },
    /* 凭据获取 */
    { "CredEnumerateA",              IocApiCat_CredentialAccess },
    { "CredEnumerateW",              IocApiCat_CredentialAccess },
    { "LsaEnumerateLogonSessions",   IocApiCat_CredentialAccess },
    { "SamConnect",                  IocApiCat_CredentialAccess },
    /* 提权 */
    { "DuplicateToken",              IocApiCat_PrivilegeEscalation },
    { "DuplicateTokenEx",            IocApiCat_PrivilegeEscalation },
    { "SetTokenInformation",         IocApiCat_PrivilegeEscalation },
    /* 反审计 (绕过防御/AMSI/ETW) */
    { "LdrLoadDll",                  IocApiCat_DynamicCode },
    { "AmsiScanBuffer",              IocApiCat_AntiDebug },
    { "EtwEventWrite",               IocApiCat_AntiDebug },
    /* 进程枚举 */
    { "CreateToolhelp32Snapshot",    IocApiCat_ProcessManipulation },
    { "Process32First",              IocApiCat_ProcessManipulation },
    { "Process32Next",               IocApiCat_ProcessManipulation },
    /* 加密上下文 (遗留) */
    { "CryptAcquireContext",         IocApiCat_CryptoOperations },
    /* 进程创建 */
    { "CreateProcessA",              IocApiCat_Shell },
    { "CreateProcessW",              IocApiCat_Shell },
};
#define IOC_API_CAT_COUNT \
    (sizeof(g_IocSuspiciousApis) / sizeof(g_IocSuspiciousApis[0]))

/* 分类 → 加分 (对齐 SS ClassifyImport: 注入/进程操作 5, 防审计/凭据/提权 4,
 * 加密/网络 3, 其它 2; ×10 转 0-1000 尺度) */
static ULONG
IocScan_ApiCategoryScore(
    _In_ IOC_SUSPICIOUS_API_CATEGORY Cat
    )
{
    switch (Cat) {
    case IocApiCat_CodeInjection:
    case IocApiCat_ProcessManipulation:
        return 150;
    case IocApiCat_AntiDebug:
    case IocApiCat_CredentialAccess:
    case IocApiCat_PrivilegeEscalation:
        return 120;
    case IocApiCat_NetworkOperations:
    case IocApiCat_CryptoOperations:
        return 80;
    case IocApiCat_ClipboardAccess:
        /* T1115 剪贴板; 但剪贴板 API 常见于正常 GUI 程序, 低分防误报 (对齐
         * HeuristicAnalyzer "剔除 GetDC 类似误报" 取舍) */
        return 60;
    default:
        return 50;
    }
}

/* -------------------------------------------------- */
/* 5.2 加壳检测节名/EP 签名表                          */
/* -------------------------------------------------- */

/* 加壳器 → 类型显示名 (顺序需与 PE_PACKER_TYPE 枚举一致) */
static const PCSTR g_IocPackerTypeNames[] = {
    "Unknown", "UPX", "ASPack", "FSG", "PECompact", "MPRESS", "MEW",
    "NsPack", "Petite", "RLPack", "WinUpack", "Themida", "VMProtect",
    "Obsidium", "Enigma", "Armadillo", "ASProtect", "NSIS", "InnoSetup",
    "AutoIt", "PyInstaller", "PESpin", "Generic",
};

/* 节名 → 加壳器 (对齐 SS InitializePackerSignatures 全量 32 条) */
static const PE_PACKER_ENTRY g_IocPackerSections[] = {
    /* 常见加壳节名 */
    { "UPX0",      IocPacker_Upx,        FALSE, FALSE },
    { "UPX1",      IocPacker_Upx,        FALSE, FALSE },
    { "UPX2",      IocPacker_Upx,        FALSE, FALSE },
    { "UPX!",      IocPacker_Upx,        FALSE, FALSE },
    { ".aspack",   IocPacker_Aspack,     FALSE, FALSE },
    { ".adata",    IocPacker_Aspack,     FALSE, FALSE },
    { ".ASPack",   IocPacker_Aspack,     FALSE, FALSE },
    { ".FSG",      IocPacker_Fsg,        FALSE, FALSE },
    { "PEC2",      IocPacker_PeCompact,  FALSE, FALSE },
    { "PECompact", IocPacker_PeCompact,  FALSE, FALSE },
    { "pec1",      IocPacker_PeCompact,  FALSE, FALSE },
    { "pec2",      IocPacker_PeCompact,  FALSE, FALSE },
    { "MPRESS",    IocPacker_Mpress,     FALSE, FALSE },
    { ".MPRESS1",  IocPacker_Mpress,     FALSE, FALSE },
    { ".MPRESS2",  IocPacker_Mpress,     FALSE, FALSE },
    { ".petite",   IocPacker_Petite,     FALSE, FALSE },
    { "MEW",       IocPacker_Mew,        FALSE, FALSE },
    { ".nsp0",     IocPacker_NsPack,     FALSE, FALSE },
    { ".nsp1",     IocPacker_NsPack,     FALSE, FALSE },
    { "nsp0",      IocPacker_NsPack,     FALSE, FALSE },
    { "RLPack",    IocPacker_RlPack,     FALSE, FALSE },
    { ".RLPack",   IocPacker_RlPack,     FALSE, FALSE },
    { ".Upack",    IocPacker_WinUpack,   FALSE, FALSE },
    /* 商业加密壳 */
    { ".armadill", IocPacker_Armadillo,  FALSE, TRUE },
    { ".themida",  IocPacker_Themida,    FALSE, TRUE },
    { ".vmp0",     IocPacker_VmProtect,  FALSE, TRUE },
    { ".vmp1",     IocPacker_VmProtect,  FALSE, TRUE },
    { ".vmp2",     IocPacker_VmProtect,  FALSE, TRUE },
    { ".enigma",   IocPacker_Enigma,     FALSE, TRUE },
    { ".enigma1",  IocPacker_Enigma,     FALSE, TRUE },
    { ".enigma2",  IocPacker_Enigma,     FALSE, TRUE },
    /* 安装包/SFX (SS 降权 5 分) */
    { ".nsis",     IocPacker_Nsis,       TRUE,  FALSE },
    { "nsis",      IocPacker_Nsis,       TRUE,  FALSE },
    { ".idata",    IocPacker_InnoSetup,  TRUE,  FALSE },
    /* SS PackerUnpacker m_packerSectionNames 补漏 (2026-08) */
    { ".winlice",  IocPacker_Themida,    FALSE, TRUE },
    { ".pespin",   IocPacker_PESpin,     FALSE, TRUE },
    { "FSG!",      IocPacker_Fsg,        FALSE, FALSE },
    { "petite",    IocPacker_Petite,     FALSE, FALSE },
    { ".mpress1",  IocPacker_Mpress,     FALSE, FALSE },
};
#define PE_PACKER_SECTIONS \
    (sizeof(g_IocPackerSections) / sizeof(g_IocPackerSections[0]))

/* -------------------------------------------------- */
/* EP 入口点字节签名 (SS PackerUnpacker::IdentifyBySignature) */
/* 强信号 → 通用 stub 加分偏低, 特异模式加分偏高, 避免中间型加壳器误判 */
/* -------------------------------------------------- */
typedef struct _IOC_EP_SIGNATURE {
    const BYTE*     Pattern;
    UCHAR           Length;
    BOOLEAN         IsSubstring;      /* TRUE=子串 search (如 UPX), FALSE=前缀 equal */
    PE_PACKER_TYPE Type;
    ULONG           BaseScore;        /* 特异模式 (FSG/Themida/PESpin) 110, 通用 stub 60 */
} IOC_EP_SIGNATURE;

static const BYTE IOC_EP_UPX[]       = { 0x60, 0xBE, 0x00, 0x00, 0x00, 0x00 };
static const BYTE IOC_EP_ASPACK[]    = { 0x60, 0xE8, 0x03, 0x00 };
static const BYTE IOC_EP_FSG[]       = { 0x87, 0x25, 0x00, 0x00, 0x00 };
static const BYTE IOC_EP_PECOMPACT[] = { 0xEB, 0x06, 0x68, 0x00 };
static const BYTE IOC_EP_MPRESS[]    = { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00 };
static const BYTE IOC_EP_THEMIDA[]   = { 0xEB, 0x10, 0x66, 0x62, 0x3A };
static const BYTE IOC_EP_VMPROTECT[] = { 0x68, 0x00, 0x00, 0x00, 0x00 };
static const BYTE IOC_EP_ENIGMA[]    = { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00 };
static const BYTE IOC_EP_MEW[]       = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
static const BYTE IOC_EP_PESPIN[]    = { 0xEB, 0x01, 0x68, 0x60 };
static const BYTE IOC_EP_PETITE[]    = { 0xB8, 0x00, 0x00, 0x00, 0x00 };

static const IOC_EP_SIGNATURE g_IocEpSignatures[] = {
    { IOC_EP_UPX,       6, TRUE,  IocPacker_Upx,       60 },
    { IOC_EP_ASPACK,    4, FALSE, IocPacker_Aspack,    60 },
    { IOC_EP_FSG,       5, FALSE, IocPacker_Fsg,      110 },
    { IOC_EP_PECOMPACT, 4, FALSE, IocPacker_PeCompact, 60 },
    { IOC_EP_MPRESS,    6, FALSE, IocPacker_Mpress,    60 },
    { IOC_EP_THEMIDA,   5, FALSE, IocPacker_Themida,  110 },
    { IOC_EP_VMPROTECT, 5, FALSE, IocPacker_VmProtect, 60 },
    { IOC_EP_ENIGMA,    6, FALSE, IocPacker_Enigma,    60 },  /* =MPRESS 同类, 冲突以节名为准 */
    { IOC_EP_MEW,       5, FALSE, IocPacker_Mew,       60 },
    { IOC_EP_PESPIN,    4, FALSE, IocPacker_PESpin,   110 },
    { IOC_EP_PETITE,    5, FALSE, IocPacker_Petite,    60 },
};
#define IOC_EP_SIGNATURE_COUNT \
    (sizeof(g_IocEpSignatures) / sizeof(g_IocEpSignatures[0]))

/* -------------------------------------------------- */
/* 字符串: MD5 (ImpHash 用)                            */
/* -------------------------------------------------- */

/* 单条字符串分类计分 (URL/IP/注册表路径/勒索关键词/可疑 API 名) */
static ULONG
IocScan_ClassifyString(
    _In_ const CHAR* Str,
    _In_ ULONG       Len
    )
{
    CHAR lower[2048];
    ULONG i;
    ULONG score = 0;

    if (Len >= sizeof(lower)) Len = sizeof(lower) - 1;
    for (i = 0; i < Len; i++) lower[i] = (CHAR)tolower((UCHAR)Str[i]);
    lower[Len] = 0;

    /* URL */
    if (strstr(lower, "http://") || strstr(lower, "https://") ||
        strstr(lower, "ftp://")) {
        score += 20;
    }

    /* IP 地址 (4 段纯数字点分) */
    if (score == 0) {
        ULONG dots = 0;
        BOOLEAN allDigitDot = TRUE;
        for (i = 0; i < Len; i++) {
            if (lower[i] == '.') dots++;
            else if (lower[i] < '0' || lower[i] > '9') { allDigitDot = FALSE; break; }
        }
        if (dots == 3 && allDigitDot && Len >= 7 && Len <= 15) score += 30;
    }

    /* 注册表路径 */
    if (strstr(lower, "hkey_") || strstr(lower, "\\software\\") ||
        strstr(lower, "\\currentversion\\run")) {
        score += 20;
    }

    /* 勒索信关键词 (对齐 SS AnalyzeExtractedStringImpl 静态表) */
    {
        static const PCSTR ransomKw[] = {
            "your files have been encrypted", "bitcoin", "btc wallet",
            "decrypt your files", "ransom", "pay to", ".onion"
        };
        ULONG k;
        for (k = 0; k < sizeof(ransomKw) / sizeof(ransomKw[0]); k++) {
            if (strstr(lower, ransomKw[k])) { score += 50; break; }
        }
    }

    /* 可疑 API 名 (精确匹配) */
    {
        static const PCSTR suspApis[] = {
            "createremotethread", "writeprocessmemory",
            "virtualallocex", "ntcreatethreadex", "setwindowshookex"
        };
        ULONG k;
        for (k = 0; k < sizeof(suspApis) / sizeof(suspApis[0]); k++) {
            if (strcmp(lower, suspApis[k]) == 0) { score += 20; break; }
        }
    }

    return score;
}

/* ASCII 字符串提取 + 计分 (对齐 SS AnalyzeStrings: 扫前 16MB, 长度 [6,2048], cap 180) */
static ULONG
IocScan_StringAnalysis(
    _In_  const BYTE*       Data,
    _In_  ULONG             Size,
    _Inout_ IOC_SCAN_RESULT* Result
    )
{
    const ULONG maxScan = (Size > (16 * 1024 * 1024)) ? (16 * 1024 * 1024) : Size;
    const ULONG minLen = 6;
    const ULONG maxLen = 2048;
    CHAR cur[2048];
    ULONG curLen = 0;
    ULONG found = 0;
    ULONG score = 0;
    ULONG i;

    Result->StringScore = 0;

    for (i = 0; i < maxScan; i++) {
        UCHAR c = (UCHAR)Data[i];
        if (c >= 0x20 && c <= 0x7E) {
            if (curLen < maxLen) cur[curLen++] = (CHAR)c;
        } else {
            if (curLen >= minLen && found < 10000) {
                score += IocScan_ClassifyString(cur, curLen);
                found++;
            }
            curLen = 0;
        }
    }
    if (curLen >= minLen && found < 10000) {
        score += IocScan_ClassifyString(cur, curLen);
    }

    if (score > 180) score = 180;   /* 对齐 SS MAX_STRING_SCORE(15)*STRING_WEIGHT(1.2) */
    Result->StringScore = score;
    return score;
}

/* -------------------------------------------------- */
/* 5.3 IAT 导入分析 + ImpHash                         */
/* -------------------------------------------------- */

typedef struct _IOC_IMP_ENTRY {
    CHAR Text[192];   /* 小写 "dll.func" (dll 去 .dll), 供 ImpHash 拼接 */
} IOC_IMP_ENTRY;

static int __cdecl
IocImpEntryCompare(
    _In_ const void* a,
    _In_ const void* b
    )
{
    return strcmp(((const IOC_IMP_ENTRY*)a)->Text,
                  ((const IOC_IMP_ENTRY*)b)->Text);
}

/* IAT 导入分析: 用真实导入表 (PepParseImports), 分类可疑 API, 计算 ImpHash。
 * 对比 SS 全文件字节扫描 memcmp 查找函数名 (O(N*M*F) 慢 + 子串误报, 如
 * "SafeCreateRemoteThreadShim"), 本实现更准。返回导入维度分 (0-625, 对齐
 * SS MAX_IMPORT*WEIGHT)。 */
static NTSTATUS
IocpPeImportAnalysis(
    _In_ const PE_PARSER_CONTEXT* Ctx,
    _Inout_ PIOC_SCAN_RESULT Result,
    _Out_ PULONG Score
    )
{
    PE_IMPORT_LIST imports;
    IOC_IMP_ENTRY* entries = NULL;
    ULONG cap = 512, count = 0;
    ULONG susScore = 0;
    BOOLEAN hasLoadLib = FALSE;
    BOOLEAN hasGetProc = FALSE;
    ULONG totalFuncCount = 0;      /* 导入函数总数 (SS 导入稀疏判定用) */
    ULONG dllCountSave = 0;
    NTSTATUS status;

    if (!Ctx || !Result || !Score) {
        return STATUS_INVALID_PARAMETER;
    }
    *Score = 0;

    Result->ImportSuspiciousCount = 0;
    Result->HasDynamicLoading = FALSE;
    Result->ImpHash[0] = 0;
    Result->ImpHashStandard[0] = 0;

    RtlZeroMemory(&imports, sizeof(PE_IMPORT_LIST));
    status = PepParseImports(Ctx, &imports);
    if (!NT_SUCCESS(status)) return 0;

    entries = (IOC_IMP_ENTRY*)malloc(sizeof(IOC_IMP_ENTRY) * cap);
    if (!entries) { WpeFreeImportList(&imports); return 0; }

    for (ULONG i = 0; i < imports.DllCount; i++) {
        const PPE_IMPORT_DLL dll = &imports.Dlls[i];
        PCWSTR dllName = NULL;
        ULONG dllNameLen = 0;
        CHAR dllNameAscii[PE_MAX_DLL_NAME];

        if (dll->NameLength > 0 && dll->NameOffset < imports.NameBlobChars) {
            dllName = imports.NameBlob + dll->NameOffset;
            dllNameLen = dll->NameLength;
        }
        WideCharToMultiByte(CP_ACP, 0, dllName ? dllName : L"",
                            (int)dllNameLen, dllNameAscii,
                            (int)sizeof(dllNameAscii), NULL, NULL);
        dllNameAscii[sizeof(dllNameAscii) - 1] = 0;

        totalFuncCount += dll->FunctionCount;

        for (ULONG j = 0; j < dll->FunctionCount; j++) {
            const PPE_IMPORT_FUNC fn = &dll->Functions[j];
            CHAR funcNameAscii[PE_MAX_FUNCTION_NAME];
            IOC_SUSPICIOUS_API_CATEGORY cat = IocApiCat_None;

            /* 序号导入: 无函数名, 不影响 ImpHash (对齐 SS 只计具名函数) */
            if (fn->ByOrdinal || fn->NameLength == 0 ||
                fn->NameOffset >= imports.NameBlobChars) {
                continue;
            }

            {
                PCWSTR funcName = imports.NameBlob + fn->NameOffset;
                WideCharToMultiByte(CP_ACP, 0, funcName, (int)fn->NameLength,
                    funcNameAscii, (int)sizeof(funcNameAscii), NULL, NULL);
                funcNameAscii[sizeof(funcNameAscii) - 1] = 0;
            }

            /* 可疑 API 分类 */
            for (ULONG k = 0; k < IOC_API_CAT_COUNT; k++) {
                if (strcmp(g_IocSuspiciousApis[k].Name, funcNameAscii) == 0) {
                    cat = g_IocSuspiciousApis[k].Category;
                    break;
                }
            }
            if (cat != IocApiCat_None) {
                susScore += IocScan_ApiCategoryScore(cat);
                Result->ImportSuspiciousCount++;
            }

            if (strncmp(funcNameAscii, "LoadLibrary", 11) == 0) hasLoadLib = TRUE;
            if (strcmp(funcNameAscii, "GetProcAddress") == 0) hasGetProc = TRUE;

            /* 收集 ImpHash 条目 - "dll.func" */
            if (count < cap) {
                IOC_IMP_ENTRY* entry = &entries[count];
                CHAR dllPart[PE_MAX_DLL_NAME];          // dll名截断
                CHAR funcPart[PE_MAX_FUNCTION_NAME];
                SIZE_T pos = 0;
                SIZE_T dl;

                strncpy_s(dllPart, sizeof(dllPart), dllNameAscii, _TRUNCATE);
                _strlwr_s(dllPart, sizeof(dllPart));    // 转小写
                dl = strlen(dllPart);
                if (dl > 4 && _stricmp(dllPart + dl - 4, ".dll") == 0) dllPart[dl - 4] = 0;

                strncpy_s(funcPart, sizeof(funcPart), funcNameAscii, _TRUNCATE);
                _strlwr_s(funcPart, sizeof(funcPart));

                if (dllPart[0]) {
                    strcpy_s(entry->Text, sizeof(entry->Text), dllPart);
                    pos = strlen(entry->Text);
                    if (pos + 1 < sizeof(entry->Text)) { entry->Text[pos] = '.'; entry->Text[pos + 1] = 0; pos++; }
                }
                strncat_s(entry->Text, sizeof(entry->Text), funcPart, _TRUNCATE);
                count++;
            }
        }
    }

    dllCountSave = imports.DllCount;
    WpeFreeImportList(&imports);

    /* 标准 Mandiant ImpHash (未排序, 保持原始导入顺序 对比 SS ComputeImpHashImpl
     * L2700-2749, 可匹配 VT/ThreatFox 等外部威胁情报) */
    if (count > 0) {
        PUCHAR blob = (PUCHAR)malloc((SIZE_T)count * 192 + 1);
        if (blob) {
            SIZE_T pos = 0;
            for (ULONG i = 0; i < count; i++) {
                SIZE_T need = strlen(entries[i].Text);
                if (pos + need + 1 < (SIZE_T)count * 192) {
                    if (pos > 0) blob[pos++] = ',';
                    memcpy(blob + pos, entries[i].Text, need);
                    pos += need;
                }
            }
            blob[pos] = 0;
            IocScan_ComputeMd5Hex((const BYTE*)blob, (ULONG)pos, Result->ImpHashStandard);
            free(blob);
        }
    }

    /* 排序后 ImpHash = MD5(排序后 "dll.func" 逗号拼接)  → 归一化行为 */
    if (count > 0) {
        qsort(entries, count, sizeof(IOC_IMP_ENTRY), IocImpEntryCompare);
        {
            PUCHAR blob = (PUCHAR)malloc((SIZE_T)count * 192 + 1);
            if (blob) {
                SIZE_T pos = 0;
                for (ULONG i = 0; i < count; i++) {
                    SIZE_T need = strlen(entries[i].Text);
                    if (pos + need + 1 < (SIZE_T)count * 192) {
                        if (pos > 0) blob[pos++] = ',';
                        memcpy(blob + pos, entries[i].Text, need);
                        pos += need;
                    }
                }
                blob[pos] = 0;
                IocScan_ComputeMd5Hex((const BYTE*)blob, (ULONG)pos, Result->ImpHash);
                free(blob);
            }
        }
    }

    free(entries);

    Result->HasDynamicLoading = (hasLoadLib && hasGetProc);

    /* 动态加载组合加分 (SS hasDynamicLoading) */
    if (Result->HasDynamicLoading) susScore += 100;
    /* 可疑函数过多 (SS suspiciousCount>5 达 MAX_IMPORT_SCORE) */
    if (Result->ImportSuspiciousCount > 5) susScore += 150;
    /* 导入稀疏 (SS PackerUnpacker::HasSuspiciousImports 方案4): <3 DLL 或 <5 函数
     * 提权 + 门控: .NET(mscoree 常为单导入)/驱动/已签名 不加分;
     * DllCount>=1 防与 WpeAnom_NoImports(+100) 双计 */
    if (dllCountSave > 0 &&
        (dllCountSave < 3 || totalFuncCount < 5) &&
        !Ctx->Info.IsDotNet && !Ctx->Info.IsDriver &&
        !Result->CertValid) {
        susScore += 40;
    }
    if (susScore > 625) susScore = 625;

    return susScore;
}

/* -------------------------------------------------- */
/* 5.3b 延迟导入风险分析 (2026-08-19 新增, 对齐 SS     */
/*      ExecutableAnalyzer::ParseDelayLoadImportsImpl + */
/*      HeuristicAnalyzer delay-load 风险分类)          */
/*                                                   */
/*  延迟导入 (DLL 首次调用才加载) 常被恶意软件用于      */
/*  隐藏敏感 API。统计其中落入危险分类 (凭据/注入/      */
/*  进程操纵/提权/网络) 的函数数，累计                   */
/*  ImportSuspiciousCount + HasDynamicLoading 入启发式。 */
/* -------------------------------------------------- */

static VOID
IocpPeDelayImportAnalysis(
    _In_    const PE_PARSER_CONTEXT* Ctx,
    _Inout_ IOC_SCAN_RESULT*         Result
    )
/*++
Routine Description:
    延迟导入表风险分析。遍历 PE_DELAY_IMPORT_LIST 的每个延迟导入 DLL 函数，
    以 g_IocSuspiciousApis 分类表判定危险 API，累计可疑计数与动态加载标志。

    简化迁移说明 (未全量)：SS 本体 (ParseDelayLoadImportsImpl L2954) 还做
    attrs bit0 RVA/VA 双模式 + 完整 PE_IMPORT 产出；wkd 仅做风险判定维度，
    不做 attrs/模式细粒度解析 (惰性解析器 WpeParseDelayImports 已覆盖读)。

Arguments:
    Ctx    - 惰性解析上下文 (已 Parsed)。
    Result - IOC 扫描结果 (ImportSuspiciousCount/HasDynamicLoading 累加)。

Return Value:
    无。
--*/
{
    PE_DELAY_IMPORT_LIST list;
    NTSTATUS status;
    ULONG before;

    if (Ctx == NULL || !Ctx->Parsed || Result == NULL) return;

    RtlZeroMemory(&list, sizeof(list));
    status = WpeParseDelayImports(Ctx, &list);
    if (!NT_SUCCESS(status)) return;
    if (list.DllCount == 0) {
        WpeDelayImportsFree(&list);
        return;
    }

    before = Result->ImportSuspiciousCount;

    for (ULONG i = 0; i < list.DllCount; i++) {
        const PE_DELAY_IMPORT_DLL* dll = &list.Dlls[i];
        for (ULONG j = 0; j < dll->FunctionCount; j++) {
            const PE_IMPORT_FUNC* fn = &dll->Functions[j];
            CHAR fnAscii[PE_MAX_FUNCTION_NAME];
            ULONG k;

            if (fn->ByOrdinal || fn->NameLength == 0 ||
                fn->NameOffset >= list.NameBlobChars) {
                continue;   /* 序号导入不计入 (同 ImportAnalysis) */
            }

            {
                PCWSTR funcName = list.NameBlob + fn->NameOffset;
                WideCharToMultiByte(CP_ACP, 0, funcName, (int)fn->NameLength,
                                    fnAscii, (int)sizeof(fnAscii), NULL, NULL);
                fnAscii[sizeof(fnAscii) - 1] = 0;
            }

            for (k = 0; k < IOC_API_CAT_COUNT; k++) {
                if (strcmp(g_IocSuspiciousApis[k].Name, fnAscii) == 0) {
                    IOC_SUSPICIOUS_API_CATEGORY category =
                        g_IocSuspiciousApis[k].Category;
                    if (category == IocApiCat_CredentialAccess ||
                        category == IocApiCat_CodeInjection ||
                        category == IocApiCat_ProcessManipulation ||
                        category == IocApiCat_PrivilegeEscalation ||
                        category == IocApiCat_NetworkOperations) {
                        Result->ImportSuspiciousCount++;
                    }
                    break;
                }
            }
        }
    }

    if (Result->ImportSuspiciousCount > before) {
        Result->HasDynamicLoading = TRUE;
    }

    WpeDelayImportsFree(&list);
}

/* -------------------------------------------------- */
/* 5.4 加壳检测                                       */
/* -------------------------------------------------- */

/* EP 入口点字节签名匹配 (SS PackerUnpacker::IdentifyBySignature)。
 * 只读 EP 前 64 字节; 门控 .NET / 非可执行节入口。 */
static NTSTATUS
IocpPeEntryPointSignatureMatch(
    _In_ const PE_PARSER_CONTEXT* Context,
    _Out_ PPE_PACKER_TYPE Type,
    _Out_ PULONG Score
    )
{
    NTSTATUS status;
    ULONG epRva;    // 入口点相对虚拟地址
    BYTE buf[64];
    SIZE_T available;

    if (!Context || !Context->Parsed || !Type || !Score) {
        return STATUS_INVALID_PARAMETER;
    }
    *Type = IocPacker_Unknown;
    *Score = 0;

    /* .NET EP 是 mscoree thunk, 非加壳 stub; 非可执行节入口同理 */
    if (Context->Info.IsDotNet) return STATUS_NOT_SUPPORTED;
    if (!Context->Info.EntryPointInExecutableSection) return STATUS_INTERNAL_ERROR;
    epRva = Context->Info.AddressOfEntryPoint;
    if (epRva == 0) return STATUS_INTERNAL_ERROR;
    status = IocpReadPeBytesAtRva(Context, epRva, buf, sizeof(buf), &available);
    if (!NT_SUCCESS(status)) return status;

    for (ULONG i = 0; i < IOC_EP_SIGNATURE_COUNT; i++) {
        const IOC_EP_SIGNATURE* sig = &g_IocEpSignatures[i];
        if (sig->Length > available) continue;
        if (sig->IsSubstring) {
            BOOLEAN hit = FALSE;
            for (ULONG k = 0; k + sig->Length <= available; k++) {
                if (memcmp(buf + k, sig->Pattern, sig->Length) == 0) { hit = TRUE; break; }
            }
            if (hit) { *Type = sig->Type; *Score = sig->BaseScore; return STATUS_SUCCESS; }
        } else {
            if (memcmp(buf, sig->Pattern, sig->Length) == 0) {
                *Type = sig->Type; *Score = sig->BaseScore; return STATUS_SUCCESS;
            }
        }
    }
    return STATUS_UNSUCCESSFUL;
}

/* 对齐 SS DetectPacker: 节名精确匹配 → EP 签名 → 熵回退, 多信号叠加。
 * 返回加壳分 (0-1000)。 */
NTSTATUS
IocpDetectPePacker(
    _In_ const PE_PARSER_CONTEXT* Context,
    _Inout_ PIOC_SCAN_RESULT Result
    )
{
    const PE_INFO* info;
    ULONG score = 0;
    BOOLEAN nameMatched = FALSE;
    PE_PACKER_TYPE nameType = IocPacker_Unknown;
    PE_PACKER_TYPE epType = IocPacker_Unknown;
    ULONG epScore = 0;
    BOOLEAN epMatched = FALSE;
    SIZE_T hiEntropy = 0;
    ULONG typeCount = RTL_NUMBER_OF(g_IocPackerTypeNames);
    
    if (!Context || !Context->Info.Valid || !Result) {
        return STATUS_INVALID_PARAMETER;
    }
    Result->IsPacked = FALSE;
    Result->PackerName[0] = 0;

    info = &Context->Info;
    /* 1. 节名精确匹配 (SS g_packerSignatures; 已知节名 → 类型/名称/加减权) */
    for (ULONG i = 0; i < info->NumberOfSections; i++) {
        PCSTR name = info->Sections[i].Name;
        for (ULONG k = 0; k < PE_PACKER_SECTIONS; k++) {
            if (strcmp(g_IocPackerSections[k].SectionName, name) == 0) {
                const PE_PACKER_ENTRY* entry = &g_IocPackerSections[k];
                if (!nameMatched) {
                    nameType = entry->Type;
                    Result->IsPacked = TRUE;
                    if (entry->Type < (PE_PACKER_TYPE)typeCount) {
                        strcpy_s(Result->PackerName, sizeof(Result->PackerName),
                                 g_IocPackerTypeNames[entry->Type]);
                    } else {
                        strcpy_s(Result->PackerName, sizeof(Result->PackerName), name);
                    }
                }
                /* 加减权 (SS 5/15 分), 取三档最高: 安装包/SFX 降权, 商业壳提权 */
                /*if (entry->IsInstaller) secScore = 50;
                else if (entry->IsProtector) secScore = 200;
                else secScore = 150;
                if (secScore > score) score = secScore;*/
                nameMatched = TRUE;
            }
        }
    }

    /* 2. EP 入口点字节签名 (叠加信号) */
    epMatched = IocpPeEntryPointSignatureMatch(Context, &epType, &epScore);
    if (epMatched) {
        if (nameMatched) {
            /* 同型 → 确认奖; 冲突 (MPRESS/Enigma 同型) → 以节名为准不加分 */
            if (epType == nameType) score += 30;
        } else {
            /* 无节名: 取 EP 分数, 命名类型 */
            if (epType < (PE_PACKER_TYPE)typeCount) {
                strcpy_s(Result->PackerName, sizeof(Result->PackerName),
                         g_IocPackerTypeNames[epType]);
            }
            if (epScore > score) score = epScore;
            Result->IsPacked = TRUE;
        }
    }

    /* 3. 熵回退 Generic (SS: fileEntropy>7.8 记为 Generic)。
     * PeParser IsPackedHeuristic = 节熵>7.0 且可执行/可写, 复用。 */
    if (!nameMatched) {
        for (ULONG i = 0; i < info->NumberOfSections; i++) {
            if (info->Sections[i].IsPackedHeuristic) {
                if (!Result->PackerName[0]) {
                    strcpy_s(Result->PackerName, sizeof(Result->PackerName),
                             "Generic (high entropy)");
                }
                if (100 > score) score = 100;
                Result->IsPacked = TRUE;
                break;
            }
        }
    }

    /* 4. ≥2 节熵>7.2 聚合 (SS HasSuspiciousEntropy 方案) */
    for (ULONG i = 0; i < info->NumberOfSections; i++) {
        if (info->Sections[i].ShannonEntropy > 7.2) hiEntropy++;
    }
    if (hiEntropy >= 2 && !nameMatched) {
        if (!Result->PackerName[0]) {
            strcpy_s(Result->PackerName, sizeof(Result->PackerName),
                     "Generic (multi-section high entropy)");
        }
        if (160 > score) score = 160;
        Result->IsPacked = TRUE;
    }

    return score;
}

/* -------------------------------------------------- */
/* 5.6 PE 结构异常评分 (对齐 SS AnalyzePE/DetectHeuristicAnomalies) */
/* -------------------------------------------------- */

static ULONG
IocScan_AnomalyScore(
    _In_ const PE_INFO* Info,
    _In_ IOC_SCAN_RESULT*   Result
    )
/*++
Routine Description:
    把 PeParser 采集的结构异常 + 挽救缺失映射为启发式分 (×10 对齐 SS 权重)。
    RWX ×15 / EP 异常 ×10 / 区段违规 ×5 / 时间戳异常 ×5 /
    无导入 ×10 / 无 ASLR+DEP+CFG+SEH 累计。cap 600 (MAX_PE_ANOMALY(30)*WEIGHT(2))。

    补漏映射 (SS HeuristicAnalyzer 实现, 2026-08):
      OverlayPresent/OverlayHighEntropy → 门控 !CertValid (签名程序以 overlay
        追加数据属正常, 避免误报);
      SectionHighEntropy → 去除 IsPacked (已由 PackerDetect 熵回退计分, 防双计);
      SectionName* / TimestampVeryOld / CodeOutsideCodeSection /
        EntryPointInLastSection / UnusualSectionOrder / Checksum* 单项加分;
      PackerSignatureDetected 不加分 (节名表已覆盖)。

Arguments:
    Info   - PeParser 解析结果 (由 IocpAnalyzeBufferEx 产出)。
    Result - 扫描结果 (用 CertValid/IsPacked 做门控/去重)。

Return Value:
    PE 异常维度分 0-600。
--*/
{
    ULONG score = 0;
    ULONG i;
    BOOLEAN isSigned;
    BOOLEAN alreadyPacked;

    if (!Info->Valid) return 0;

    isSigned = (Result != NULL && Result->CertValid);
    alreadyPacked = (Result != NULL && Result->IsPacked);

    for (i = 0; i < Info->AnomalyCount; i++) {
        switch (Info->Anomalies[i].Type) {
        case WpeAnom_SectionWritableExecutable:   score += 150; break;  /* RWX ×15 */
        case WpeAnom_EntryPointZero:
        case WpeAnom_EntryPointInHeader:
        case WpeAnom_EntryPointOutsideFile:
        case WpeAnom_EntryPointInWritableSection: score += 100; break;  /* EP ×10 */
        case WpeAnom_EntryPointInLastSection:     score += 30;  break;  /* ×3 */
        case WpeAnom_CodeOutsideCodeSection:      score += 50;  break;  /* ×5 */
        case WpeAnom_SectionAlignmentViolation:   score += 50;  break;  /* ×5 */
        case WpeAnom_SectionNameSuspicious:       score += 50;  break;  /* ×5 */
        case WpeAnom_SectionNameEmpty:
        case WpeAnom_SectionNameNonPrintable:     score += 20;  break;  /* ×2 */
        case WpeAnom_SectionHighEntropy:
            if (!alreadyPacked) score += 80;      break;  /* ×8, 去除 IsPacked */
        case WpeAnom_TimestampInFuture:
        case WpeAnom_TimestampZero:               score += 50;  break;  /* ×5 */
        case WpeAnom_TimestampVeryOld:            score += 30;  break;  /* ×3 */
        case WpeAnom_OverlayPresent:
            if (!isSigned) score += 20;           break;  /* ×2, 门控签名 */
        case WpeAnom_OverlayHighEntropy:
            if (!isSigned) score += 100;          break;  /* ×10, 门控签名 */
        case WpeAnom_OverlayContainsPE:
            if (!isSigned) score += 140;          break;  /* overlay 内嵌 PE (SS severity 70) */
        case WpeAnom_LargeOverlay:
            if (!isSigned) score += 60;           break;  /* 超大 overlay >1MB (SS severity 40) */
        case WpeAnom_UnusualSectionOrder:         score += 30;  break;  /* ×3 */
        case WpeAnom_OverlappingSections:         score += 150; break;  /* 重叠节 (SS severity 75) */
        case WpeAnom_ApiHashing:                  score += 170; break;  /* 无导入 + 疑似 shellcode (SS severity 85) */
        case WpeAnom_ResourcesContainPE:          score += 160; break;  /* 资源内嵌 PE (dropper 强信号) */
        case WpeAnom_ResourcesHighEntropy:        score += 80;  break;  /* 资源高熵压缩载荷 */
        case WpeAnom_ResourceSizeAnomaly:         score += 40;  break;  /* 资源 >16MB */
        case WpeAnom_TLSCallbackPresent:          score += 110; break;  /* TLS 回调 anti-analysis (SS severity 55) */
        case WpeAnom_ChecksumMismatch:            score += 20;  break;  /* ×2 */
        case WpeAnom_WeakChecksum:                score += 20;  break;  /* ×2 */
        case WpeAnom_NoImports:                   score += 100; break;  /* ×10 */
        case WpeAnom_NoASLR:                      score += 30;  break;  /* ×3 */
        case WpeAnom_NoDEP:                       score += 30;  break;  /* ×3 */
        case WpeAnom_NoCFG:                       score += 20;  break;  /* ×2 */
        case WpeAnom_NoSEH:                       score += 20;  break;  /* ×2 */
        /* WpeAnom_PackerSignatureDetected: 不加分 (IocpDetectPePacker 节名已覆盖) */
        default: break;
        }
    }

    /* DLL 无导出 (对齐 SS AnalyzePE: isDLL && !EXPORT 目录 → NoExportsForDLL) */
    if (Info->IsDll && PE_DD_EXPORT < PE_DD_MAX_ENTRIES &&
        !Info->DataDirectories[PE_DD_EXPORT].Present) {
        score += 20;
    }

    if (score > 600) score = 600;
    return score;
}

/**************************************************/
/*        文本: 脚本内容判定 (Heuristic 分支)        */
/**************************************************/

/* 前置声明: 脚本分析 (定义见本分区后; IocHeuristicPeAnalysis else 分支脚本扩展调用) */
static ULONG
IocScan_ScriptAnalysis(
    _In_ const BYTE* Data,
    _In_ ULONG       Size
    );

/* 路径扩展名是否脚本 (对齐 SS DetectFileType 路径版脚本分支 L1829-1832) */
static BOOLEAN
IocScan_IsScriptFile(
    _In_ PCWSTR FilePath
    )
{
    static const PCWSTR extTable[] = {
        L".ps1", L".psm1", L".psd1", L".js", L".jse",
        L".vbs", L".vbe", L".bat", L".cmd"
    };
    PCWSTR dot;
    ULONG i;

    if (!FilePath || !FilePath[0]) return FALSE;
    dot = wcsrchr(FilePath, L'.');
    if (!dot) return FALSE;
    for (i = 0; i < sizeof(extTable) / sizeof(extTable[0]); i++) {
        if (_wcsicmp(dot, extTable[i]) == 0) return TRUE;
    }
    return FALSE;
}

/* -- 5.8 脚本分析 (SS AnalyzeScript): PS/VBS/JS 静态检测 -------------
 * 计分: 混淆特征 (base64/frombase64/+>30/-replace/[char]+[int]/iex, ≥3 命中 +25)
 *   + 能力特征 (下载 15/执行 10/WMI 5/注册表 5/文件 5/网络 5/COM 3) +
 *   URL 提及 +5, cap 100。
 * 注: SS 为逐关键词子串匹配, 权重易偏; 运行时脚本执行维度由
 *   IocScanner_ScanCmdline 覆盖。 */
static ULONG
IocScan_ScriptAnalysis(
    _In_ const BYTE* Data,
    _In_ ULONG       Size
    )
{
    const ULONG maxAnalyze = (Size > (4 * 1024 * 1024)) ? (4 * 1024 * 1024) : Size;
    CHAR* content = NULL;
    CHAR* lower = NULL;
    ULONG obf = 0;
    ULONG capScore = 0;
    ULONG plusCount = 0;
    ULONG score = 0;
    ULONG i;

    if (!Data || Size == 0) return 0;

    content = (CHAR*)malloc(maxAnalyze + 1);
    lower = (CHAR*)malloc(maxAnalyze + 1);
    if (!content || !lower) { free(content); free(lower); return 0; }

    memcpy(content, Data, maxAnalyze);
    content[maxAnalyze] = 0;
    for (i = 0; i < maxAnalyze; i++) lower[i] = (CHAR)tolower((UCHAR)content[i]);
    lower[maxAnalyze] = 0;

    if (strstr(lower, "base64") || strstr(lower, "frombase64string") ||
        strstr(lower, "convert]::frombase64")) obf++;
    for (i = 0; i < maxAnalyze && plusCount <= 30; i++) if (lower[i] == '+') plusCount++;
    if (plusCount > 30) obf++;
    if (strstr(lower, "-replace") || strstr(lower, ".replace(")) obf++;
    if (strstr(lower, "char]") && strstr(lower, "[int]")) obf++;
    if (strstr(lower, "-join") && strstr(lower, "-split")) obf++;
    if (strstr(lower, "iex") || strstr(lower, "invoke-expression")) obf++;

    if (obf >= 3) score += 25;

    if (strstr(lower, "downloadstring") || strstr(lower, "downloadfile") ||
        strstr(lower, "invoke-webrequest")) capScore += 15;
    if (strstr(lower, "start-process") || strstr(lower, "createobject") ||
        strstr(lower, "wscript.shell")) capScore += 10;
    if (strstr(lower, "get-wmiobject") || strstr(lower, "gwmi") ||
        strstr(lower, "invoke-wmimethod")) capScore += 5;
    if (strstr(lower, "set-itemproperty") || strstr(lower, "new-itemproperty") ||
        strstr(lower, "hklm:") || strstr(lower, "hkcu:")) capScore += 5;
    if (strstr(lower, "remove-item") || strstr(lower, "copy-item") ||
        strstr(lower, "move-item")) capScore += 5;
    if (strstr(lower, "webclient") || strstr(lower, "net.sockets")) capScore += 5;
    if (strstr(lower, "new-object -com")) capScore += 3;

    score += capScore;

    if (strstr(lower, "http")) score += 5;
    if (score > 100) score = 100;

    free(content);
    free(lower);
    return score;
}

/* 前向声明: 解包闭环 (定义于本文件后部 "加壳解包闭环" 分区; 2026-08-19
 * 接入 IocHeuristicPeAnalysis 触发使用前置, C 语言需先声明后使用)。 */
static VOID
IocScan_UnpackClosure(
    _In_    const PE_PARSER_CONTEXT* Ctx,
    _In_    const BYTE*              Data,
    _In_    SIZE_T                   Size,
    _Inout_ IOC_SCAN_RESULT*         Result
    );

/**************************************************/
/*         5. 启发式静态分析主入口                  */
/**************************************************/

/* 文件级启发式静态分析 (SS HeuristicAnalyzer AnalyzeBufferInternal 的 PE 分支)。
 * 一次内存映射 + IocpAnalyzeBufferEx 全量解析, 再分 加壳/导入/字符串/异常 4 维,
 * 各维度分聚合为 HeuristicConfidence (0-1000), 供 IocScan_Aggregate 判定。 */
VOID
IocHeuristicPeAnalysis(
    _In_opt_ PCWSTR              FilePath,
    _In_opt_ const PE_INFO*      PeInfo,
    _Inout_  IOC_SCAN_RESULT*    Result
    )
{
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    HANDLE mapping = NULL;
    PVOID view = NULL;
    LARGE_INTEGER fileSize;
    PE_PARSER_CONTEXT* ctx = NULL;
    NTSTATUS status;
    ULONG total = 0;
    ULONG importScore = 0;      /* IocpPeImportAnalysis 导入维度分输出 */

    Result->HeuristicRan = FALSE;
    Result->HeuristicConfidence = 0;

    if (!FilePath || !FilePath[0]) return;

    fileHandle = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) return;
    if (!GetFileSizeEx(fileHandle, &fileSize) ||
        fileSize.QuadPart < sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(fileHandle);
        return;
    }

    mapping = CreateFileMappingW(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (mapping == NULL) { CloseHandle(fileHandle); return; }
    view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (view == NULL) { CloseHandle(mapping); CloseHandle(fileHandle); return; }

    ctx = (PE_PARSER_CONTEXT*)malloc(sizeof(PE_PARSER_CONTEXT));
    if (!ctx) {
        UnmapViewOfFile(view); CloseHandle(mapping); CloseHandle(fileHandle);
        return;
    }

    /* 惰性 Ctx 构造 (2026-08-19 Ctx 基座)：
     *   传入调用方已解析的 PE_INFO (构建期 IocAnalyzePe 产物) 时，
     *   复用其几何重建 Ctx，省去 WpeParseBufferContext 第二次完整
     *   结构解析；若 PeInfo 不可用则回退 IocpAnalyzeBufferEx 自解析。 */
    if (PeInfo != NULL && PeInfo->Valid) {
        status = WpeBuildLazyContextFromInfo(PeInfo, (const BYTE*)view,
                                             (SIZE_T)fileSize.QuadPart, ctx);
    } else {
        status = WpeParseBufferContext(ctx, (const BYTE*)view,
                                       (SIZE_T)fileSize.QuadPart, TRUE);
    }
    if (NT_SUCCESS(status) && ctx->Info.Valid) {
        /* PE 文件: 加壳/导入/字符串/异常 4 维聚合 */
        Result->HeuristicRan = TRUE;

        total  = IocpDetectPePacker(ctx, Result);
        if (NT_SUCCESS(IocpPeImportAnalysis(ctx, Result, &importScore))) {
            total += importScore;   /* 导入维度分 (0-625) */
        }
        IocpPeDelayImportAnalysis(ctx, Result);   /* 延迟导入风险 (新增, 2026-08-19) */
        //total += IocScan_StringAnalysis((const BYTE*)view,
        //                                (ULONG)fileSize.LowPart, Result);

        /* 编码字符串提取 (2026-08-19 迁移, SS StringExtractor)：检测 XOR/Base64/
         * ROT 混淆串并分类，StrExtScore 作为字符串编码维度并入启发式 total。
         * view 字节流直接复用 (不新建缓冲)。 */
        //IocStrExtract((const BYTE*)view, (SIZE_T)fileSize.QuadPart, Result, NULL);
        //total += Result->StrExtScore;

        /* 资源内容级异常 (2026-08-19 接线, SS ParseResourcesImpl)：
         * 内嵌 PE / 高熵 / 超大资源 → 发射异常，随后 AnomalyScore 计入
         * (ResourcesContainPE +160 = dropper 强信号)。仅深度分析路径生效，
         * 构建期解析 (IocAnalyzePe, AnalyzeContentAnomalies=FALSE) 不执行。 */
        // WpeDetectResourceContentAnomalies(ctx);

        total += IocScan_AnomalyScore(&ctx->Info, Result);

        /* 解包闭环接线 (2026-08-19, SS PackerUnpacker)：
         * 加壳 + 非签名 + ≤64MB 时静态解包 (UPX/NRV2B)，解包镜像二次
         * 分析 (ImpHash/可疑导入以解包结果为准，对齐 SS）。门控与二次
         * 分析在 IocScan_UnpackClosure 内部自持 (IsPacked/CertValid)。
         * 复用同一惰性 Ctx，不额外解析。 */
        //IocScan_UnpackClosure(ctx, (const BYTE*)view,
        //                      (SIZE_T)fileSize.QuadPart, Result);
    } else if (IocScan_IsScriptFile(FilePath)) {
        /* 脚本: 对齐 SS AnalyzeBufferInternal Script 分支 → AnalyzeScript
         * (混淆/能力/URL), 0-100 分 ×10 转 0-1000 */
        ULONG scriptScore;
        Result->HeuristicRan = TRUE;

        scriptScore = IocScan_ScriptAnalysis((const BYTE*)view,
                                             (ULONG)fileSize.LowPart);
        total = ((scriptScore > 100) ? 100 : scriptScore) * 10;
    } else {
        /* 非脚本非 PE (未知/文档/归档): 对齐 SS AnalyzeBufferInternal default 分支 →
         * 熵加值 + 字符串分析, cap 1000 */
        ULONG entropy = 0;
        Result->HeuristicRan = TRUE;

        total = IocScan_StringAnalysis((const BYTE*)view,
                                       (ULONG)fileSize.LowPart, Result);
        entropy = (ULONG)(CoEntropyBinary(view, (ULONG)fileSize.LowPart, 0) * 1000.0);
        if (entropy >= WPA_ENTROPY_THRESHOLD_PACKED) {
            total += 150;   /* 对齐 SS entropy>7.0 时 entropy*1.5 (高位) */
        }
    }

    if (total > 1000) total = 1000;
    Result->HeuristicConfidence = total;

    /* 启发式威胁命名 (对齐 SS GenerateThreatName: "Heuristic:Win/<category>",
     * 在给予高置信度时命名) */
    if (total >= 500) {
        PCSTR category;
        if (Result->IsPacked) {
            category = "Packed";
        } else if (Result->ImportSuspiciousCount >= 3) {
            category = "Import";
        } else if (Result->StringScore >= 100) {
            category = "Anomaly";
        } else {
            category = "Generic";
        }
        sprintf_s(Result->ThreatName, sizeof(Result->ThreatName),
                  "Heuristic:Win/%s", category);
    }

    WpeResetParseContext(ctx);
    free(ctx);
    UnmapViewOfFile(view);
    CloseHandle(mapping);
    CloseHandle(fileHandle);
}

/**************************************************/
/*     惰性解析 Ctx 重建 (2026-08-19 Ctx 基座)       */
/*                                                   */
/*  从已解析 PE_INFO 几何 + 文件字节缓冲重建           */
/*  PE_PARSER_CONTEXT，供深度子函数 (加壳/导入/惰性    */
/*  目录) 复用，消除对同一文件的第二次完整结构解析。   */
/*  依赖方向：本函数属 PEAnalyzer 能力域 (有           */
/*  PeInternal.h 访问权)，由模块域 PmBuildLazyContext  */
/*  薄封装 (ProcessModule.c) 或扫描编排传入待用。      */
/**************************************************/

NTSTATUS
WpeBuildLazyContextFromInfo(
    _In_      const PE_INFO*        Info,
    _In_opt_  const BYTE*           View,
    _In_      SIZE_T                Size,
    _Out_     PPE_PARSER_CONTEXT    Ctx
    )
/*++
Routine Description:
    从构建期 IocAnalyzePe 的 PE_INFO 几何 + 文件字节缓冲构造惰性解析
    上下文 (补齐 Info/RawSections/Reader)。与 IocpAnalyzeBufferEx 完整
    解析的区别：本函数只重放几何与节表，不做 10 步结构重解析，供
    WpeRvaToOffset → IocpReaderRead 惰性读取 Import/Export 等目录。

    简化迁移说明 (未全量)：
      - 仅重建惰性解析所需字段 (Info/RawSections/Parsed/IsMemoryMode/
        Reader)；NtHeaderOffset/OptionalHeaderOffset/SectionTableOffset
        未重放 (惰性解析器不消费，仅结构解析用)。
      - 异常表/Anomalies 不再累积 (深度子函数以 Result 为准)。

Arguments:
    Info - 构建期完整 PE_INFO (须 Valid)。
    View - 文件字节缓冲 (可为 NULL，NULL 时 Reader.Size 钳 0)。
    Size - 缓冲字节数。
    Ctx  - 输出惰性解析上下文。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_IMAGE_FORMAT (Info 无效)。
--*/
{
    ULONG i;

    if (Ctx == NULL || Info == NULL || !Info->Valid) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    RtlZeroMemory(Ctx, sizeof(*Ctx));

    /* Info 几何直拷 */
    Ctx->Info = *Info;

    /* 节表转换: PE_SECTION → IMAGE_SECTION_HEADER (RvaToOffset 消费) */
    Ctx->RawSectionCount = Info->NumberOfSections >
                           PE_MAX_SECTIONS ? PE_MAX_SECTIONS
                                           : Info->NumberOfSections;
    for (i = 0; i < Ctx->RawSectionCount; i++) {
        const PE_SECTION* ps = &Info->Sections[i];
        IMAGE_SECTION_HEADER* ih = &Ctx->RawSections[i];

        memset(ih, 0, sizeof(*ih));
        memcpy(ih->Name, ps->Name, PE_MAX_SECTION_NAME);
        ih->Misc.VirtualSize = ps->VirtualSize;
        ih->VirtualAddress = ps->VirtualAddress;
        ih->SizeOfRawData = ps->SizeOfRawData;
        ih->PointerToRawData = ps->PointerToRawData;
        ih->Characteristics = ps->Characteristics;
    }

    Ctx->Parsed = TRUE;
    Ctx->IsMemoryMode = FALSE;

    /* Reader (Buffer 模式): View 可 NULL (钳 0，调用方自填) */
    if (View != NULL && Size > 0) {
        (VOID)IocInitializeBufferReader(&Ctx->Reader, View, Size);
    } else {
        RtlZeroMemory(&Ctx->Reader, sizeof(Ctx->Reader));
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*      加壳解包闭环 (死代码, SS PackerUnpacker)     */
/*  功能面保留, 启动门控保持关闭, 避免污染扫描行为  */
/**************************************************/

/* IocScan_MergeUnpackAnalysis (SS PackerUnpacker 解包闭环, 死代码)
 * 把解包后二次分析 IOC_SCAN_RESULT 并入原始结果:
 *   ImpHash/可疑导入/动态加载 以解包结果为基准 (避免加壳 IAT 伪影),
 *   HeuristicConfidence 取较大, 非重复可疑导入 +50,
 *   解包熵 0-1000 换算写入。 */
static VOID
IocScan_MergeUnpackAnalysis(
    _Inout_ IOC_SCAN_RESULT*        Result,
    _In_    const IOC_SCAN_RESULT*  Sub,
    _In_    const PE_UNPACK_RESULT* Ur
    )
{
    if (Result == NULL || Sub == NULL || Ur == NULL) return;

    /* 保留原 IsPacked/PackerName (文件确实加壳的) */
    if (Sub->ImpHash[0]) {
        strcpy_s(Result->ImpHash, sizeof(Result->ImpHash), Sub->ImpHash);
        Result->ImportSuspiciousCount = Sub->ImportSuspiciousCount;
        Result->HasDynamicLoading = Sub->HasDynamicLoading;
    }
    if (Sub->HeuristicConfidence > Result->HeuristicConfidence) {
        Result->HeuristicConfidence = Sub->HeuristicConfidence;
    } else if (Sub->ImportSuspiciousCount > Result->ImportSuspiciousCount &&
               Result->HeuristicConfidence <= 1000 - 50) {
        Result->HeuristicConfidence += 50;
    }
    if (Ur->Reconstructed && Ur->Layers[0].UnpackedSize > 0) {
        /* 解包熵 0-1000 换算: 熵 (0-8) * 125 分档, 供运营展示 */
        Result->UnpackedEntropy = (ULONG)(Ur->Layers[0].EntropyAfter * 125.0);
        if (Result->UnpackedEntropy > 1000) Result->UnpackedEntropy = 1000;
    }
}

/* IocScan_UnpackClosure (SS PackerUnpacker 解包闭环)
 * 条件: IsPacked 且非签名且 ≤64MB 时对 WpeUnpackPackedBuffer 静态解包,
 *       解包镜像再 IocpAnalyzeBufferEx + 4 维聚合, 合并回 IOC_SCAN_RESULT。
 * 2026-08-19 接入: IocHeuristicPeAnalysis 四维聚合后调用 (见其 PE 分支),
 * 与原有 IocpDetectPePacker/ImportAnalysis 复用同一惰性 Ctx (Ctx 基座),
 * 解包镜像的二次 WpeParseBufferContext 为独立 Ctx (纯内存)。 */
static VOID
IocScan_UnpackClosure(
    _In_    const PE_PARSER_CONTEXT* Ctx,
    _In_    const BYTE*              Data,
    _In_    SIZE_T                   Size,
    _Inout_ IOC_SCAN_RESULT*         Result
    )
{
    PE_UNPACK_RESULT ur;
    NTSTATUS status;
    ULONG subImpScore = 0;      /* 解包二次导入分析分输出（IocpPeImportAnalysis） */

    if (Ctx == NULL || !Ctx->Parsed || Data == NULL || Result == NULL) return;

    /* 门控: 加壳 + 非签名 + 大小限制 */
    if (!Result->IsPacked || Result->CertValid || Size > 64ULL * 1024 * 1024) {
        return;
    }
    Result->UnpackAttempted = TRUE;

    RtlZeroMemory(&ur, sizeof(ur));
    status = WpeUnpackBuffer(Ctx, Data, Size, &ur);
    if (NT_SUCCESS(status) && ur.State == WpeUnpack_Success && ur.LayerCount > 0) {
        PE_PARSER_CONTEXT ctx2;
        IOC_SCAN_RESULT sub;

        Result->Unpacked = TRUE;
        Result->UnpackedSize = ur.Layers[0].UnpackedSize;
        memcpy(Result->UnpackedHash, ur.Layers[0].Sha256, 32);
        Result->UnpackedEntryPointRva = ur.Layers[0].UnpackedEntryPointRva;

        /* 解包后二次分析 (纯内存, 不落盘 → EDR 安全) */
        RtlZeroMemory(&ctx2, sizeof(ctx2));
        if (NT_SUCCESS(WpeParseBufferContext(&ctx2, ur.Layers[0].UnpackedData,
                                            ur.Layers[0].UnpackedSize, TRUE))) {
            RtlZeroMemory(&sub, sizeof(sub));
            IocpDetectPePacker(&ctx2, &sub);
            IocpPeImportAnalysis(&ctx2, &sub, &subImpScore);
            IocScan_StringAnalysis(ur.Layers[0].UnpackedData,
                                   ur.Layers[0].UnpackedSize, &sub);
            IocScan_AnomalyScore(&ctx2.Info, &sub);
            IocScan_MergeUnpackAnalysis(Result, &sub, &ur);
        }
        WpeResetParseContext(&ctx2);
    }
    WpeFreeUnpackResult(&ur);
}
