/**************************************************/
/*  WkDefender PEAnalyzer — PE 校验实现            */
/**************************************************/

#include "PeInternal.h"

#include <stddef.h>

/**************************************************/
/*             静态辅助函数                         */
/**************************************************/

/*
 * IocpRecordError — 设置错误 (Error 可 NULL)。
 */
static
NTSTATUS
IocpRecordError(
    _In_opt_ PPE_PARSER_ERROR Error,
    _In_ PE_VALIDATION_RESULT Code,
    _In_ PCWSTR Message,
    _In_ ULONG64 Offset
    )
{
    if (Error && Code && Message) {
        Error->Code = Code;
        Error->Message = Message;
        Error->Offset = Offset;
        Error->Context = NULL;
        Error->Win32Error = 0;
        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_PARAMETER;
}

/*
 * WpeLogAnomalyDropOnce — 异常数组容量耗尽时仅告警一次。
 * 对齐 SS LogValidationGrowthFailureOnce (static atomic_bool 一次性)。
 * C 移植: agent 为多线程, 用 InterlockedCompareExchange 保证线程安全;
 * 告警经 OutputDebugStringW 输出 (可替换为 agent 统一日志)。
 */
static
VOID
WpeLogAnomalyDropOnce(
    VOID
    )
{
    static LONG logged = 0;

    if (InterlockedCompareExchange(&logged, 1, 0) == 0) {
        OutputDebugStringW(L"WkDefender PEAnalyzer: anomaly buffer full, telemetry dropped\n");
    }
}

/*
 * WpeAddAnomaly — 累积异常记录 (数组满则丢弃, 不阻断)。
 * 容量耗尽时告警一次 (对齐 SS TryAddAnomaly 的 vector 增长失败日志)。
 */
static
BOOLEAN
WpeAddAnomaly(
    _Out_opt_ PPE_ANOMALY   Anomalies,
    _Inout_opt_ PULONG       Count,
    _In_     ULONG           Cap,
    _In_     PE_ANOMALY_TYPE Type,
    _In_     PCWSTR          Desc
    )
{
    if (Anomalies && Count && *Count < Cap) {
        Anomalies[*Count].Type = Type;
        Anomalies[*Count].Description = Desc;
        Anomalies[*Count].Offset = 0;
        Anomalies[*Count].Context = NULL;
        (*Count)++;
        return TRUE;
    }

    /* 容量耗尽丢弃 — 告警一次 (对齐 SS LogValidationGrowthFailureOnce) */
    if (Anomalies && Count && *Count >= Cap) {
        WpeLogAnomalyDropOnce();
    }
    return FALSE;
}

/*
 * IocpCheckFileHeaderMachineField — 机器类型白名单 (敌对 PE 用任意机器值探测解析器)。
 */
static
BOOLEAN
IocpCheckFileHeaderMachineField(
    _In_ USHORT Machine
    )
{
    switch (Machine) {
    case PE_MACHINE_UNKNOWN:
    case PE_MACHINE_TARGET_HOST:
    case PE_MACHINE_I386:
    case PE_MACHINE_R3000:
    case PE_MACHINE_R4000:
    case PE_MACHINE_R10000:
    case PE_MACHINE_WCEMIPSV2:
    case PE_MACHINE_ALPHA:
    case PE_MACHINE_SH3:
    case PE_MACHINE_SH3DSP:
    case PE_MACHINE_SH3E:
    case PE_MACHINE_SH4:
    case PE_MACHINE_SH5:
    case PE_MACHINE_ARM:
    case PE_MACHINE_THUMB:
    case PE_MACHINE_ARMNT:
    case PE_MACHINE_AM33:
    case PE_MACHINE_POWERPC:
    case PE_MACHINE_POWERPCFP:
    case PE_MACHINE_IA64:
    case PE_MACHINE_MIPS16:
    case PE_MACHINE_ALPHA64:
    case PE_MACHINE_MIPSFPU:
    case PE_MACHINE_MIPSFPU16:
    case PE_MACHINE_TRICORE:
    case PE_MACHINE_CEF:
    case PE_MACHINE_EBC:
    case PE_MACHINE_AMD64:
    case PE_MACHINE_M32R:
    case PE_MACHINE_ARM64:
    case PE_MACHINE_CEE:
        return TRUE;
    default:
        return FALSE;
    }
}

/*
 * IocpCheckOptionalHeaderSubsystem — 子系统白名单。
 */
static
BOOLEAN
IocpCheckOptionalHeaderSubsystem(
    _In_ USHORT Subsystem
    )
{
    switch (Subsystem) {
    case IMAGE_SUBSYSTEM_UNKNOWN:
    case IMAGE_SUBSYSTEM_NATIVE:
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
    case IMAGE_SUBSYSTEM_OS2_CUI:
    case IMAGE_SUBSYSTEM_POSIX_CUI:
    case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
    case IMAGE_SUBSYSTEM_EFI_ROM:
    case IMAGE_SUBSYSTEM_XBOX:
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
    case IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG:
        return TRUE;
    default:
        return FALSE;
    }
}

/**************************************************/
/*        校验结果 → 字符串                          */
/**************************************************/

PCWSTR
WpeValidationResultToString(
    _In_ PE_VALIDATION_RESULT Result
    )
/*++
Routine Description:
    校验结果码 → 可读描述 (静态字符串)。

Arguments:
    Result - 校验结果码。

Return Value:
    描述字符串。
--*/
{
    switch (Result) {
    case WpeVal_Valid: return L"Valid";
    case WpeVal_UnknownError: return L"Unknown error";
    case WpeVal_FileTooSmall: return L"File too small to be a valid PE";
    case WpeVal_FileTooLarge: return L"File exceeds maximum supported size";
    case WpeVal_NullPointer: return L"Null pointer provided";
    case WpeVal_IntegerOverflow: return L"Integer overflow detected";
    case WpeVal_InvalidDosSignature: return L"Invalid DOS signature (expected MZ)";
    case WpeVal_InvalidLfanew: return L"Invalid e_lfanew value";
    case WpeVal_LfanewOutOfBounds: return L"e_lfanew points outside file";
    case WpeVal_LfanewNegative: return L"e_lfanew is negative";
    case WpeVal_LfanewUnaligned: return L"e_lfanew is not properly aligned";
    case WpeVal_LfanewTooSmall: return L"e_lfanew is too small";
    case WpeVal_LfanewTooLarge: return L"e_lfanew exceeds maximum allowed";
    case WpeVal_InvalidNtSignature: return L"Invalid NT signature (expected PE\\0\\0)";
    case WpeVal_InvalidMachine: return L"Invalid or unsupported machine type";
    case WpeVal_InvalidOptionalMagic: return L"Invalid optional header magic";
    case WpeVal_NumberOfSectionsZero: return L"Number of sections is zero";
    case WpeVal_NumberOfSectionsOverflow: return L"Number of sections exceeds limit";
    case WpeVal_SizeOfOptionalHeaderInvalid: return L"Invalid optional header size";
    case WpeVal_SizeOfOptionalHeaderTooSmall: return L"Optional header too small";
    case WpeVal_SizeOfOptionalHeaderTooLarge: return L"Optional header too large";
    case WpeVal_NtHeadersOutOfBounds: return L"NT headers extend beyond file";
    case WpeVal_InvalidFileAlignment: return L"Invalid file alignment";
    case WpeVal_InvalidSectionAlignment: return L"Invalid section alignment";
    case WpeVal_FileAlignmentGreaterThanSection: return L"File alignment > section alignment";
    case WpeVal_SizeOfImageZero: return L"Size of image is zero";
    case WpeVal_SizeOfHeadersZero: return L"Size of headers is zero";
    case WpeVal_SizeOfHeadersTooLarge: return L"Size of headers exceeds file size";
    case WpeVal_NumberOfRvaAndSizesInvalid: return L"Invalid number of data directories";
    case WpeVal_InvalidAddressOfEntryPoint: return L"Invalid entry point address";
    case WpeVal_InvalidImageBase: return L"Invalid image base address";
    case WpeVal_InvalidSubsystem: return L"Invalid subsystem type";
    case WpeVal_SizeOfStackCommitExceedsReserve:
        return L"SizeOfStackCommit exceeds SizeOfStackReserve";
    case WpeVal_SizeOfHeapCommitExceedsReserve:
        return L"SizeOfHeapCommit exceeds SizeOfHeapReserve";
    case WpeVal_SizeOfImageNotAligned:
        return L"SizeOfImage is not a multiple of SectionAlignment";
    case WpeVal_SizeOfHeadersNotAligned:
        return L"SizeOfHeaders is not a multiple of FileAlignment";
    case WpeVal_SectionTableOutOfBounds: return L"Section table extends beyond file";
    case WpeVal_SectionTableOverflow: return L"Section table size overflow";
    case WpeVal_SectionCountMismatch: return L"Section count mismatch";
    case WpeVal_SectionNameInvalid: return L"Invalid section name";
    case WpeVal_SectionVirtualAddressZero: return L"Section virtual address is zero";
    case WpeVal_SectionVirtualSizeZero: return L"Section virtual size is zero";
    case WpeVal_SectionRawAddressInvalid: return L"Invalid section raw address";
    case WpeVal_SectionRawSizeInvalid: return L"Invalid section raw size";
    case WpeVal_SectionBeyondFile: return L"Section extends beyond file";
    case WpeVal_SectionBeyondImage: return L"Section extends beyond image";
    case WpeVal_SectionOverlap: return L"Sections overlap in file";
    case WpeVal_SectionAlignmentViolation: return L"Section alignment violation";
    case WpeVal_SectionCharacteristicsInvalid: return L"Invalid section characteristics";
    case WpeVal_SectionWritableExecutable: return L"Section is both writable and executable";
    case WpeVal_EntryPointOutsideSections: return L"Entry point outside all sections";
    case WpeVal_EntryPointInNonExecutable: return L"Entry point in non-executable section";
    case WpeVal_DataDirectoryOutOfBounds: return L"Data directory extends beyond file";
    case WpeVal_DataDirectorySizeInvalid: return L"Invalid data directory size";
    case WpeVal_DataDirectoryRvaInvalid: return L"Invalid data directory RVA";
    case WpeVal_ImportDirectoryInvalid: return L"Invalid import directory";
    case WpeVal_ExportDirectoryInvalid: return L"Invalid export directory";
    case WpeVal_ResourceDirectoryInvalid: return L"Invalid resource directory";
    case WpeVal_TLSDirectoryInvalid: return L"Invalid TLS directory";
    case WpeVal_RelocDirectoryInvalid: return L"Invalid relocation directory";
    case WpeVal_DebugDirectoryInvalid: return L"Invalid debug directory";
    case WpeVal_SecurityDirectoryInvalid: return L"Invalid security directory";
    case WpeVal_CLRDirectoryInvalid: return L"Invalid CLR directory";
    case WpeVal_BoundImportInvalid: return L"Invalid bound import directory";
    case WpeVal_DelayImportInvalid: return L"Invalid delay import directory";
    case WpeVal_LoadConfigInvalid: return L"Invalid load config directory";
    case WpeVal_ImportDescriptorOutOfBounds: return L"Import descriptor beyond file";
    case WpeVal_ImportDllNameOutOfBounds: return L"Import DLL name beyond file";
    case WpeVal_ImportDllNameTooLong: return L"Import DLL name too long";
    case WpeVal_ImportThunkOutOfBounds: return L"Import thunk beyond file";
    case WpeVal_ImportByNameOutOfBounds: return L"Import by name beyond file";
    case WpeVal_ImportFunctionNameTooLong: return L"Import function name too long";
    case WpeVal_ImportOrdinalInvalid: return L"Invalid import ordinal";
    case WpeVal_ImportCircularReference: return L"Circular import reference";
    case WpeVal_ImportCountExceeded: return L"Import count exceeded limit";
    case WpeVal_ExportDirectoryOutOfBounds: return L"Export directory beyond file";
    case WpeVal_ExportNameOutOfBounds: return L"Export name beyond file";
    case WpeVal_ExportOrdinalOutOfBounds: return L"Export ordinal out of bounds";
    case WpeVal_ExportAddressOutOfBounds: return L"Export address beyond file";
    case WpeVal_ExportForwarderInvalid: return L"Invalid export forwarder";
    case WpeVal_ExportCountExceeded: return L"Export count exceeded limit";
    case WpeVal_TLSDirectoryOutOfBounds: return L"TLS directory beyond file";
    case WpeVal_TLSCallbacksOutOfBounds: return L"TLS callbacks beyond file";
    case WpeVal_TLSCallbackCountExceeded: return L"TLS callback count exceeded";
    case WpeVal_TLSDataOutOfBounds: return L"TLS data beyond file";
    case WpeVal_TLSCallbackInNonExecutable: return L"TLS callback in non-executable memory";
    case WpeVal_ResourceDirectoryOutOfBounds: return L"Resource directory beyond file";
    case WpeVal_ResourceDepthExceeded: return L"Resource directory depth exceeded";
    case WpeVal_ResourceCircularReference: return L"Circular resource reference";
    case WpeVal_ResourceEntryCountExceeded: return L"Resource entry count exceeded";
    case WpeVal_ResourceDataOutOfBounds: return L"Resource data beyond file";
    case WpeVal_ResourceNameOutOfBounds: return L"Resource name beyond file";
    case WpeVal_RelocationBlockOutOfBounds: return L"Relocation block beyond file";
    case WpeVal_RelocationBlockSizeInvalid: return L"Invalid relocation block size";
    case WpeVal_RelocationEntryInvalid: return L"Invalid relocation entry";
    case WpeVal_RelocationCountExceeded: return L"Relocation count exceeded";
    case WpeVal_RelocationCircularReference: return L"Circular relocation reference";
    case WpeVal_DebugEntryOutOfBounds: return L"Debug entry beyond file";
    case WpeVal_DebugDataOutOfBounds: return L"Debug data beyond file";
    case WpeVal_DebugCountExceeded: return L"Debug entry count exceeded";
    case WpeVal_DebugTypeUnknown: return L"Unknown debug type";
    case WpeVal_RichHeaderNotFound: return L"Rich header not found";
    case WpeVal_RichHeaderCorrupted: return L"Rich header corrupted";
    case WpeVal_RichHeaderChecksumMismatch: return L"Rich header checksum mismatch";
    case WpeVal_RichEntryCountExceeded: return L"Rich header entry count exceeded";
    case WpeVal_SignatureDirectoryInvalid: return L"Invalid signature directory";
    case WpeVal_SignatureOutOfBounds: return L"Signature beyond file";
    case WpeVal_SignatureFormatInvalid: return L"Invalid signature format";
    default: return L"Unknown validation result";
    }
}

/**************************************************/
/*            DOS 头校验                            */
/**************************************************/

_Use_decl_annotations_
PE_VALIDATION_RESULT
IocpValidateDosHeader(
    _In_ const PPE_READER Reader,
    _Out_ PLONG Lfanew,
    _Out_opt_ PPE_PARSER_ERROR Error
    )
/*++
Routine Description:
    校验 DOS 头: 文件大小门禁 / e_magic / e_lfanew(有符号, 区间钳制, 越界检查)。

Arguments:
    Reader  - 读取器 (定位文件起始)。
    Lfanew  - 输出 e_lfanew。
    Error   - [可选] 错误输出。

Return Value:
    校验结果码。
--*/
{
    IMAGE_DOS_HEADER dos;
    LONG ntEnd;

    if (!Reader || !Lfanew) {
        IocpRecordError(Error, WpeVal_InvalidParameters, L"Parameters are invalid", 0);
        return WpeVal_InvalidParameters;
    }
    *Lfanew = 0;
    if (Error) RtlZeroMemory(Error, sizeof(PE_PARSER_ERROR));

    /* 文件大小门禁 */
    if (CopGetReaderSize(Reader) < PE_MIN_FILE_SIZE) {
        IocpRecordError(Error, WpeVal_FileTooSmall, L"File is smaller than minimum PE size", 0);
        return WpeVal_FileTooSmall;
    }
    if (CopGetReaderSize(Reader) > PE_MAX_FILE_SIZE) {
        IocpRecordError(Error, WpeVal_FileTooLarge, L"File exceeds maximum supported size", 0);
        return WpeVal_FileTooLarge;
    }

    /* 读 DOS 头 */
    if (!IocpReaderReadBytes(Reader, 0, &dos, sizeof(IMAGE_DOS_HEADER))) {
        IocpRecordError(Error, WpeVal_FileTooSmall, L"Cannot read DOS header", 0);
        return WpeVal_FileTooSmall;
    }

    /* DOS 签名 */
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        IocpRecordError(Error, WpeVal_InvalidDosSignature,
                  L"Invalid DOS signature (expected 0x5A4D 'MZ')", 0);
        return WpeVal_InvalidDosSignature;
    }

    /* e_lfanew 有符号 — 负数攻击向量 */
    if (dos.e_lfanew < 0) {
        IocpRecordError(Error, WpeVal_LfanewNegative,
                  L"e_lfanew is negative (potential attack)", offsetof(IMAGE_DOS_HEADER, e_lfanew));
        return WpeVal_LfanewNegative;
    }
    
    /* 最小 e_lfanew (必须越过 DOS 头) */
    if (dos.e_lfanew < sizeof(IMAGE_DOS_HEADER)) {
        IocpRecordError(Error, WpeVal_LfanewTooSmall,
                  L"e_lfanew is too small (overlaps DOS header)", offsetof(IMAGE_DOS_HEADER, e_lfanew));
        return WpeVal_LfanewTooSmall;
    }

    /* 最大 e_lfanew (防 Rich 头扫描 DoS) */
    if (dos.e_lfanew > PE_MAX_LFANEW) {
        IocpRecordError(Error, WpeVal_LfanewTooLarge,
                  L"e_lfanew exceeds maximum allowed offset", offsetof(IMAGE_DOS_HEADER, e_lfanew));
        return WpeVal_LfanewTooLarge;
    }
    
    /* e_lfanew 越界检查: 至少容纳 PE 签名 + 文件头 */
    ntEnd = dos.e_lfanew + (LONG)offsetof(IMAGE_NT_HEADERS, OptionalHeader);
    if (ntEnd < 0) {
        IocpRecordError(Error, WpeVal_IntegerOverflow,
                  L"Integer overflow checking NT headers bounds", offsetof(IMAGE_DOS_HEADER, e_lfanew));
        return WpeVal_IntegerOverflow;
    }
    if (ntEnd > CopGetReaderSize(Reader)) {
        IocpRecordError(Error, WpeVal_LfanewOutOfBounds,
                  L"e_lfanew points beyond file boundary", offsetof(IMAGE_DOS_HEADER, e_lfanew));
        return WpeVal_LfanewOutOfBounds;
    }

    if (Lfanew) *Lfanew = dos.e_lfanew;
    return WpeVal_Valid;
}

/**************************************************/
/*            NT 头校验                             */
/**************************************************/

_Use_decl_annotations_
PE_VALIDATION_RESULT
IocpValidateNtHeaders(
    _In_ const PPE_READER Reader,
    _In_ SIZE_T NtHeaderOffset,
    _Out_ PBOOLEAN Amd64,
    _Out_ PIMAGE_FILE_HEADER FileHeader,
    _Out_opt_ PPE_PARSER_ERROR Error
    )
/*++
Routine Description:
    校验 NT 签名 / 文件头 / 机器白名单 / 节数 / 可选头大小 / magic 架构判定。

Arguments:
    Reader        - 读取器。
    NtHeaderOffset      - NT 头偏移 (e_lfanew)。
    Amd64    - 输出架构 (PE32+/PE32)。
    OutFileHeader - 输出文件头。
    Error           - [可选] 错误输出。

Return Value:
    校验结果码。
--*/
{
    ULONG signature;
    ULONG fileHeaderOffset;
    IMAGE_FILE_HEADER fileHeader = { 0 };

    if (!Reader || NtHeaderOffset <= sizeof(IMAGE_DOS_HEADER) ||
        !Amd64 || !FileHeader) {
        IocpRecordError(Error, WpeVal_InvalidParameters, L"Parameters are invalid", 0);
        return WpeVal_InvalidParameters;
    }
    *Amd64 = FALSE;
    RtlZeroMemory(FileHeader, sizeof(IMAGE_FILE_HEADER));
    if (Error) RtlZeroMemory(Error, sizeof(PE_PARSER_ERROR));

    /* ---- 读取 IMAGE_NT_HEADERS::Signature ---- */
    if (!IocpReaderReadBytes(Reader, NtHeaderOffset, &signature, sizeof(ULONG))) {
        IocpRecordError(Error, WpeVal_NtHeadersOutOfBounds, L"Cannot read PE signature", NtHeaderOffset);
        return WpeVal_NtHeadersOutOfBounds;
    }
    if (signature != IMAGE_NT_SIGNATURE) {
        IocpRecordError(Error, WpeVal_InvalidNtSignature,
                  L"Invalid PE signature (expected 0x00004550)", NtHeaderOffset);
        return WpeVal_InvalidNtSignature;
    }

    /* ---- 读取 IMAGE_FILE_HEADER ---- */
    fileHeaderOffset = NtHeaderOffset + offsetof(IMAGE_NT_HEADERS, FileHeader);
    if (!IocpReaderReadBytes(Reader, fileHeaderOffset, &fileHeader, sizeof(IMAGE_FILE_HEADER))) {
        IocpRecordError(Error, WpeVal_NtHeadersOutOfBounds, L"Cannot read file header", fileHeaderOffset);
        return WpeVal_NtHeadersOutOfBounds;
    }

    /* 机器类型白名单 — 拒绝未定义机器值 (敌对 PE 探测解析器) */
    if (!IocpCheckFileHeaderMachineField(fileHeader.Machine)) {
        IocpRecordError(Error, WpeVal_InvalidMachine, L"Invalid or unsupported machine type",
                  fileHeaderOffset + offsetof(IMAGE_FILE_HEADER, Machine));
        return WpeVal_InvalidMachine;
    }

    /* NumberOfSections == 0 放行 (某些工具生成, 记异常在解析层) */

    if (fileHeader.NumberOfSections > PE_MAX_SECTIONS) {
        IocpRecordError(Error, WpeVal_NumberOfSectionsOverflow,
                  L"Number of sections exceeds safety limit",
                  fileHeaderOffset + offsetof(IMAGE_FILE_HEADER, NumberOfSections));
        return WpeVal_NumberOfSectionsOverflow;
    }

    /* 可选头大小 */
    if (fileHeader.SizeOfOptionalHeader == 0) {
        IocpRecordError(Error, WpeVal_SizeOfOptionalHeaderTooSmall, L"Optional header size is zero",
                  fileHeaderOffset + offsetof(IMAGE_FILE_HEADER, SizeOfOptionalHeader));
        return WpeVal_SizeOfOptionalHeaderTooSmall;
    }
    if (fileHeader.SizeOfOptionalHeader > PE_MAX_OPTIONAL_HEADER_SIZE) {
        IocpRecordError(Error, WpeVal_SizeOfOptionalHeaderTooLarge, L"Optional header size exceeds limit",
                  fileHeaderOffset + offsetof(IMAGE_FILE_HEADER, SizeOfOptionalHeader));
        return WpeVal_SizeOfOptionalHeaderTooLarge;
    }

    /* 可选头 magic → 架构判定 */
    {
        USHORT magic;
        ULONG optionalOffset;

        optionalOffset = NtHeaderOffset + offsetof(IMAGE_NT_HEADERS, OptionalHeader);
        if (!IocpReaderReadBytes(Reader, optionalOffset, &magic, sizeof(USHORT))) {
            IocpRecordError(Error, WpeVal_NtHeadersOutOfBounds, L"Cannot read optional header magic", optionalOffset);
            return WpeVal_NtHeadersOutOfBounds;
        }

        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            if (Amd64) *Amd64 = TRUE;
            if (fileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
                IocpRecordError(Error, WpeVal_SizeOfOptionalHeaderTooSmall, L"PE64 optional header too small",
                    fileHeaderOffset + offsetof(IMAGE_FILE_HEADER, SizeOfOptionalHeader));
                return WpeVal_SizeOfOptionalHeaderTooSmall;
            }
        }
        else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            if (Amd64) *Amd64 = FALSE;
            if (fileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) {
                IocpRecordError(Error, WpeVal_SizeOfOptionalHeaderTooSmall, L"PE32 optional header too small",
                    fileHeaderOffset + offsetof(IMAGE_FILE_HEADER, SizeOfOptionalHeader));
                return WpeVal_SizeOfOptionalHeaderTooSmall;
            }
        }
        else if (magic == IMAGE_ROM_OPTIONAL_HDR_MAGIC) {
            /* ROM 映像非标准 Windows PE — 拒绝并标记规避 */
            IocpRecordError(Error, WpeVal_InvalidOptionalMagic,
                L"ROM image magic (0x107) not supported — potential evasion", optionalOffset);
            return WpeVal_InvalidOptionalMagic;
        }
        else {
            IocpRecordError(Error, WpeVal_InvalidOptionalMagic, L"Invalid optional header magic", optionalOffset);
            return WpeVal_InvalidOptionalMagic;
        }
    }

    *FileHeader = fileHeader;
    return WpeVal_Valid;
}

/**************************************************/
/*        可选头校验 (PE32 / PE32+)                 */
/**************************************************/

_Use_decl_annotations_
PE_VALIDATION_RESULT
IocpValidateOptionalHeader32(
    _In_ const PPE_READER Reader,
    _In_ SIZE_T Offset,
    _Out_ PIMAGE_OPTIONAL_HEADER32 OptionalHeader32,
    _Out_opt_ PPE_PARSER_ERROR Error
    )
/*++
Routine Description:
    校验 PE32 可选头全部字段 (对齐 SS ValidateOptionalHeader32)。
    逻辑与 64 位版近乎一致, 仅字段宽度差异 (此处分列保证尺寸语义精确)。

Arguments:
    Reader              - 读取器。
    Offset              - 可选头偏移。
    SizeOfOptionalHeader - 文件头声明的大小。
    OptionalHeader64         - 输出可选头。
    Error                 - [可选] 错误输出。

Return Value:
    校验结果码。
--*/
{
    IMAGE_OPTIONAL_HEADER32 opt32 = { 0 };

    if (!Reader || !OptionalHeader32 ||
        Offset < sizeof(IMAGE_DOS_HEADER) + offsetof(IMAGE_NT_HEADERS32, OptionalHeader)) {
        IocpRecordError(Error, WpeVal_InvalidParameters, L"Parameters are invalid", 0);
        return WpeVal_InvalidParameters;
    }
    RtlZeroMemory(OptionalHeader32, sizeof(IMAGE_OPTIONAL_HEADER32));
    if (Error) RtlZeroMemory(Error, sizeof(PE_PARSER_ERROR));

    if (!IocpReaderReadBytes(Reader, Offset, &opt32, sizeof(IMAGE_OPTIONAL_HEADER32))) {
        IocpRecordError(Error, WpeVal_NtHeadersOutOfBounds, L"Cannot read PE32 optional header", Offset);
        return WpeVal_NtHeadersOutOfBounds;
    }

    if (opt32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IocpRecordError(Error, WpeVal_InvalidOptionalMagic, L"Invalid PE32 magic", Offset);
        return WpeVal_InvalidOptionalMagic;
    }

    if (opt32.FileAlignment < PE_MIN_FILE_ALIGNMENT ||
        opt32.FileAlignment > PE_MAX_FILE_ALIGNMENT) {
        IocpRecordError(Error, WpeVal_InvalidFileAlignment, L"File alignment out of valid range",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER32, FileAlignment));
        return WpeVal_InvalidFileAlignment;
    }
    if ((opt32.FileAlignment & (opt32.FileAlignment - 1)) != 0) {
        IocpRecordError(Error, WpeVal_InvalidFileAlignment, L"File alignment is not a power of 2",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER32, FileAlignment));
        return WpeVal_InvalidFileAlignment;
    }
    if (opt32.SectionAlignment < PE_MIN_SECTION_ALIGNMENT ||
        opt32.SectionAlignment > PE_MAX_SECTION_ALIGNMENT) {
        IocpRecordError(Error, WpeVal_InvalidSectionAlignment, L"Section alignment out of valid range",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER32, SectionAlignment));
        return WpeVal_InvalidSectionAlignment;
    }
    if ((opt32.SectionAlignment & (opt32.SectionAlignment - 1)) != 0) {
        IocpRecordError(Error, WpeVal_InvalidSectionAlignment, L"Section alignment is not a power of 2",
            Offset + offsetof(IMAGE_OPTIONAL_HEADER32, SectionAlignment));
        return WpeVal_InvalidSectionAlignment;
    }
    if (opt32.FileAlignment > opt32.SectionAlignment) {
        IocpRecordError(Error, WpeVal_FileAlignmentGreaterThanSection,
                  L"File alignment greater than section alignment",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER32, FileAlignment));
        return WpeVal_FileAlignmentGreaterThanSection;
    }
    if (opt32.SizeOfImage == 0) {
        IocpRecordError(Error, WpeVal_SizeOfImageZero, L"Size of image is zero",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfImage));
        return WpeVal_SizeOfImageZero;
    }
    if (opt32.SizeOfHeaders == 0) {
        IocpRecordError(Error, WpeVal_SizeOfHeadersZero, L"Size of headers is zero",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfHeaders));
        return WpeVal_SizeOfHeadersZero;
    }
    if (opt32.SizeOfHeaders > CopGetReaderSize(Reader)) {
        IocpRecordError(Error, WpeVal_SizeOfHeadersTooLarge, L"Size of headers exceeds file size",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfHeaders));
        return WpeVal_SizeOfHeadersTooLarge;
    }
    if (opt32.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
        IocpRecordError(Error, WpeVal_NumberOfRvaAndSizesInvalid,
                  L"Number of data directories exceeds maximum",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER32, NumberOfRvaAndSizes));
        return WpeVal_NumberOfRvaAndSizesInvalid;
    }
    if (opt32.SizeOfStackCommit > opt32.SizeOfStackReserve) {
        IocpRecordError(Error, WpeVal_SizeOfStackCommitExceedsReserve,
                  L"SizeOfStackCommit exceeds SizeOfStackReserve",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfStackCommit));
        return WpeVal_SizeOfStackCommitExceedsReserve;
    }
    if (opt32.SizeOfHeapCommit > opt32.SizeOfHeapReserve) {
        IocpRecordError(Error, WpeVal_SizeOfHeapCommitExceedsReserve,
                  L"SizeOfHeapCommit exceeds SizeOfHeapReserve",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfHeapCommit));
        return WpeVal_SizeOfHeapCommitExceedsReserve;
    }
    if (opt32.SectionAlignment > 0 &&
        (opt32.SizeOfImage % opt32.SectionAlignment) != 0) {
        IocpRecordError(Error, WpeVal_SizeOfImageNotAligned,
                  L"SizeOfImage is not a multiple of SectionAlignment",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfImage));
        return WpeVal_SizeOfImageNotAligned;
    }
    if (opt32.FileAlignment >= PE_MIN_FILE_ALIGNMENT &&
        (opt32.SizeOfHeaders % opt32.FileAlignment) != 0) {
        IocpRecordError(Error, WpeVal_SizeOfHeadersNotAligned,
                  L"SizeOfHeaders is not a multiple of FileAlignment",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfHeaders));
        return WpeVal_SizeOfHeadersNotAligned;
    }
    if (!IocpCheckOptionalHeaderSubsystem(opt32.Subsystem)) {
        IocpRecordError(Error, WpeVal_InvalidSubsystem, L"Invalid PE subsystem value",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER32, Subsystem));
        return WpeVal_InvalidSubsystem;
    }
    if (opt32.ImageBase % 0x10000 != 0) {
        IocpRecordError(Error, WpeVal_InvalidImageBase, L"ImageBase not aligned to 64KB boundary",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER32, ImageBase));
        return WpeVal_InvalidImageBase;
    }

    *OptionalHeader32 = opt32;
    return WpeVal_Valid;
}

_Use_decl_annotations_
PE_VALIDATION_RESULT
IocpValidateOptionalHeader64(
    _In_ const PPE_READER Reader,
    _In_ SIZE_T Offset,
    _Out_ PIMAGE_OPTIONAL_HEADER64 OptionalHeader64,
    _Out_opt_ PPE_PARSER_ERROR Error
    )
/*++
Routine Description:
    校验 PE32+ 可选头全部字段 (对齐 SS ValidateOptionalHeader64)。

Arguments:
    Reader              - 读取器。
    Offset              - 可选头偏移。
    OptionalHeader64         - 输出可选头。
    Error                 - [可选] 错误输出。

Return Value:
    校验结果码。
--*/
{
    IMAGE_OPTIONAL_HEADER64 opt64 = { 0 };

    if (!Reader || !OptionalHeader64 ||
        Offset < sizeof(IMAGE_DOS_HEADER) + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)) {
        IocpRecordError(Error, WpeVal_InvalidParameters, L"Parameters are invalid", 0);
        return WpeVal_InvalidParameters;
    }
    RtlZeroMemory(OptionalHeader64, sizeof(IMAGE_OPTIONAL_HEADER64));
    if (Error) RtlZeroMemory(Error, sizeof(PE_PARSER_ERROR));

    if (!IocpReaderReadBytes(Reader, Offset, &opt64, sizeof(IMAGE_OPTIONAL_HEADER64))) {
        IocpRecordError(Error, WpeVal_NtHeadersOutOfBounds, L"Cannot read PE64 optional header", Offset);
        return WpeVal_NtHeadersOutOfBounds;
    }

    if (opt64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IocpRecordError(Error, WpeVal_InvalidOptionalMagic, L"Invalid PE64 magic", Offset);
        return WpeVal_InvalidOptionalMagic;
    }

    if (opt64.FileAlignment < PE_MIN_FILE_ALIGNMENT ||
        opt64.FileAlignment > PE_MAX_FILE_ALIGNMENT) {
        IocpRecordError(Error, WpeVal_InvalidFileAlignment, L"File alignment out of valid range",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER64, FileAlignment));
        return WpeVal_InvalidFileAlignment;
    }
    if ((opt64.FileAlignment & (opt64.FileAlignment - 1)) != 0) {
        IocpRecordError(Error, WpeVal_InvalidFileAlignment, L"File alignment is not a power of 2",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER64, FileAlignment));
        return WpeVal_InvalidFileAlignment;
    }
    if (opt64.SectionAlignment < PE_MIN_SECTION_ALIGNMENT ||
        opt64.SectionAlignment > PE_MAX_SECTION_ALIGNMENT) {
        IocpRecordError(Error, WpeVal_InvalidSectionAlignment, L"Section alignment out of valid range",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER64, SectionAlignment));
        return WpeVal_InvalidSectionAlignment;
    }
    if ((opt64.SectionAlignment & (opt64.SectionAlignment - 1)) != 0) {
        IocpRecordError(Error, WpeVal_InvalidSectionAlignment, L"Section alignment is not a power of 2",
            Offset + offsetof(IMAGE_OPTIONAL_HEADER64, SectionAlignment));
        return WpeVal_InvalidSectionAlignment;
    }
    if (opt64.FileAlignment > opt64.SectionAlignment) {
        IocpRecordError(Error, WpeVal_FileAlignmentGreaterThanSection,
                  L"File alignment greater than section alignment",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER64, FileAlignment));
        return WpeVal_FileAlignmentGreaterThanSection;
    }
    if (opt64.SizeOfImage == 0) {
        IocpRecordError(Error, WpeVal_SizeOfImageZero, L"Size of image is zero",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage));
        return WpeVal_SizeOfImageZero;
    }
    if (opt64.SizeOfHeaders == 0) {
        IocpRecordError(Error, WpeVal_SizeOfHeadersZero, L"Size of headers is zero",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders));
        return WpeVal_SizeOfHeadersZero;
    }
    if (opt64.SizeOfHeaders > CopGetReaderSize(Reader)) {
        IocpRecordError(Error, WpeVal_SizeOfHeadersTooLarge, L"Size of headers exceeds file size",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders));
        return WpeVal_SizeOfHeadersTooLarge;
    }
    if (opt64.NumberOfRvaAndSizes > IMAGE_MAX_DIRECTORY_ENTRIES) {
        IocpRecordError(Error, WpeVal_NumberOfRvaAndSizesInvalid,
                  L"Number of data directories exceeds maximum",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER64, NumberOfRvaAndSizes));
        return WpeVal_NumberOfRvaAndSizesInvalid;
    }
    if (opt64.SizeOfStackCommit > opt64.SizeOfStackReserve) {
        IocpRecordError(Error, WpeVal_SizeOfStackCommitExceedsReserve,
                  L"SizeOfStackCommit exceeds SizeOfStackReserve",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfStackCommit));
        return WpeVal_SizeOfStackCommitExceedsReserve;
    }
    if (opt64.SizeOfHeapCommit > opt64.SizeOfHeapReserve) {
        IocpRecordError(Error, WpeVal_SizeOfHeapCommitExceedsReserve,
                  L"SizeOfHeapCommit exceeds SizeOfHeapReserve",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfHeapCommit));
        return WpeVal_SizeOfHeapCommitExceedsReserve;
    }
    if (opt64.SectionAlignment > 0 &&
        (opt64.SizeOfImage % opt64.SectionAlignment) != 0) {
        IocpRecordError(Error, WpeVal_SizeOfImageNotAligned,
                  L"SizeOfImage is not a multiple of SectionAlignment",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage));
        return WpeVal_SizeOfImageNotAligned;
    }
    if (opt64.FileAlignment >= PE_MIN_FILE_ALIGNMENT &&
        (opt64.SizeOfHeaders % opt64.FileAlignment) != 0) {
        IocpRecordError(Error, WpeVal_SizeOfHeadersNotAligned,
                  L"SizeOfHeaders is not a multiple of FileAlignment",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders));
        return WpeVal_SizeOfHeadersNotAligned;
    }
    if (!IocpCheckOptionalHeaderSubsystem(opt64.Subsystem)) {
        IocpRecordError(Error, WpeVal_InvalidSubsystem, L"Invalid PE subsystem value",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER64, Subsystem));
        return WpeVal_InvalidSubsystem;
    }
    if (opt64.ImageBase % 0x10000 != 0) {
        IocpRecordError(Error, WpeVal_InvalidImageBase, L"ImageBase not aligned to 64KB boundary",
                  Offset + offsetof(IMAGE_OPTIONAL_HEADER64, ImageBase));
        return WpeVal_InvalidImageBase;
    }

    *OptionalHeader64 = opt64;
    return WpeVal_Valid;
}

/**************************************************/
/*           节头校验                               */
/**************************************************/

PE_VALIDATION_RESULT
IocpValidateSectionHeader(
    _In_ const PIMAGE_SECTION_HEADER SectionHeader,
    _In_opt_ SIZE_T FileSize,
    _In_ ULONG SizeOfImage,
    _In_ ULONG FileAlignment,
    _In_ USHORT SectionIndex,
    _Out_opt_ PPE_PARSER_ERROR Error,
    _Out_opt_ PPE_ANOMALY Anomalies,
    _Inout_opt_ PULONG AnomalyCount,
    _In_opt_ ULONG AnomalyCap
    )
/*++
Routine Description:
    校验单个节头。设计共识: 异常可累积、硬错误才拦截 — 始终返回 Valid
    (除非硬错误), 可疑信号 (VA=0/空节/无内存标志/未对齐) 累积为异常。

Arguments:
    Header        - 节头。
    FileSize      - 文件大小。
    SizeOfImage   - 映像大小。
    FileAlignment - 文件对齐。
    SectionIndex  - 节索引 (错误定位用)。
    Error           - [可选] 错误输出。
    Anomalies     - [可选] 异常数组。
    AnomalyCount  - [in,out] 异常计数。
    AnomalyCap    - 异常数组容量。

Return Value:
    校验结果码 (硬错误或 Valid)。
--*/
{
    UNREFERENCED_PARAMETER(SectionIndex);
    if (!SectionHeader || SizeOfImage == 0 || FileAlignment == 0) {
        return WpeVal_InvalidParameters;
    }

    /* VA==0 且 VS>0 — 头覆盖规避技术 */
    if (SectionHeader->VirtualAddress == 0 && SectionHeader->Misc.VirtualSize > 0) {
        WpeAddAnomaly(Anomalies, AnomalyCount, AnomalyCap, WpeAnom_UnusualSectionOrder,
                      L"Section has VirtualAddress == 0 with non-zero VirtualSize (header overlay technique)");
    }

    /* 完全空节 (VS 与 RawSize 均 0) — 加壳标记 */
    if (SectionHeader->Misc.VirtualSize == 0 && SectionHeader->SizeOfRawData == 0) {
        WpeAddAnomaly(Anomalies, AnomalyCount, AnomalyCap, WpeAnom_SectionZeroRawSize,
                      L"Section has zero virtual and raw size");
    }

    /* 无任何内存访问标志 (MEM_READ|WRITE|EXECUTE 均无) — 混淆信号 */
    {
        const ULONG rwxMask = 0xE0000000LU;
        if ((SectionHeader->Characteristics & rwxMask) == 0 && SectionHeader->SizeOfRawData > 0) {
            WpeAddAnomaly(Anomalies, AnomalyCount, AnomalyCap, WpeAnom_SectionSizeMismatch,
                          L"Section has no memory access flags (not readable, writable, or executable)");
        }
    }

    /* raw 边界 (硬错误) */
    if (SectionHeader->SizeOfRawData > 0) {
        ULONG rawEnd;
        if (!IocpAddU32Safe(SectionHeader->PointerToRawData,
                          SectionHeader->SizeOfRawData, &rawEnd)) {
            IocpRecordError(Error, WpeVal_IntegerOverflow,
                      L"Integer overflow in section raw data bounds", 0);
            return WpeVal_IntegerOverflow;
        }
        if (rawEnd > FileSize) {
            IocpRecordError(Error, WpeVal_SectionBeyondFile,
                      L"Section raw data extends beyond file", SectionHeader->PointerToRawData);
            return WpeVal_SectionBeyondFile;
        }
    }

    /* virtual 边界 (硬错误); VirtualSize 为 0 时用 SizeOfRawData 代替 */
    if (SectionHeader->Misc.VirtualSize > 0 || SectionHeader->SizeOfRawData > 0) {
        ULONG virtualEnd = 0;
        ULONG virtualSize = SectionHeader->Misc.VirtualSize;
        if (virtualSize == 0) virtualSize = SectionHeader->SizeOfRawData;

        if (!IocpAddU32Safe(SectionHeader->VirtualAddress,
                          virtualSize, &virtualEnd)) {
            IocpRecordError(Error, WpeVal_IntegerOverflow,
                      L"Integer overflow in section virtual bounds", 0);
            return WpeVal_IntegerOverflow;
        }
        if (virtualEnd > SizeOfImage) {
            IocpRecordError(Error, WpeVal_SectionBeyondImage,
                      L"Section virtual data extends beyond image", SectionHeader->VirtualAddress);
            return WpeVal_SectionBeyondImage;
        }
    }

    /* 未对齐 (PointerToRawData % FileAlignment) — packer/恶意指示, 记异常 */
    if (SectionHeader->PointerToRawData != 0 && FileAlignment > 0) {
        if ((SectionHeader->PointerToRawData % FileAlignment) != 0) {
            WpeAddAnomaly(Anomalies, AnomalyCount, AnomalyCap, WpeAnom_SectionAlignmentViolation,
                          L"Section PointerToRawData is not aligned to FileAlignment");
        }
    }

    return WpeVal_Valid;
}

/**************************************************/
/*           节重叠检测                             */
/**************************************************/

BOOLEAN
WpeCheckSectionOverlaps(
    _In_  const IMAGE_SECTION_HEADER* Sections,
    _In_  ULONG                     SectionCount,
    _Out_opt_ PPE_SECTION_OVERLAP  Overlaps,
    _Inout_opt_ PULONG              OverlapCount,
    _In_  ULONG                     OverlapCap
    )
/*++
Routine Description:
    两轮重叠检测: Pass1 物理(raw 文件)重叠; Pass2 虚拟地址(VA)重叠。
    溢出时按延伸到最大处理 (正确与一切重叠)。VA 重叠破坏 RVA→offset
    映射, 可绕过基于节的异常检测 — 已知规避技术。

Arguments:
    Sections     - 节头数组。
    SectionCount - 节数量。
    Overlaps     - [可选] 输出重叠对。
    OverlapCount - [in,out] 重叠对数。
    OverlapCap   - 输出容量。

Return Value:
    TRUE=存在重叠。
--*/
{
    ULONG i;
    ULONG j;
    BOOLEAN found = FALSE;
    ULONG count = (OverlapCount) ? *OverlapCount : 0;

    /* count 仅反映"实际存储的对数": Overlaps==NULL 时恒 0,
     * 使 Pass2 的 alreadyRecorded 遍历(基于 count)不因无存储而失效,
     * 对齐 SS vector 语义(去重后的对集合)。 */
#define OVERLAP_ADD(l, r)                                                \
    do {                                                                 \
        if (Overlaps && count < OverlapCap) {                            \
            Overlaps[count].Left = (l);                                  \
            Overlaps[count].Right = (r);                                 \
            count++;                                                     \
        }                                                                \
        found = TRUE;                                                    \
    } while (0)

    /* Pass 1: 物理 raw 重叠 */
    for (i = 0; i < SectionCount; i++) {
        SIZE_T s1Start, s1End;
        if (Sections[i].SizeOfRawData == 0) continue;
        s1Start = (SIZE_T)Sections[i].PointerToRawData;
        if (!IocpAddSizeSafe(s1Start, (SIZE_T)Sections[i].SizeOfRawData, &s1End)) {
            s1End = (SIZE_T)-1;   /* 溢出 → 与一切重叠 */
        }
        for (j = i + 1; j < SectionCount; j++) {
            SIZE_T s2Start, s2End;
            if (Sections[j].SizeOfRawData == 0) continue;
            s2Start = (SIZE_T)Sections[j].PointerToRawData;
            if (!IocpAddSizeSafe(s2Start, (SIZE_T)Sections[j].SizeOfRawData, &s2End)) {
                s2End = (SIZE_T)-1;
            }
            if (s1Start < s2End && s2Start < s1End) {
                OVERLAP_ADD(i, j);
            }
        }
    }

    /* Pass 2: 虚拟地址重叠 (去重 Pass1 已记录的对) */
    for (i = 0; i < SectionCount; i++) {
        ULONG s1VSize;
        SIZE_T s1VStart, s1VEnd;
        s1VSize = (Sections[i].Misc.VirtualSize != 0) ? Sections[i].Misc.VirtualSize
                                                 : Sections[i].SizeOfRawData;
        if (s1VSize == 0 || Sections[i].VirtualAddress == 0) continue;
        s1VStart = (SIZE_T)Sections[i].VirtualAddress;
        if (!IocpAddSizeSafe(s1VStart, (SIZE_T)s1VSize, &s1VEnd)) {
            s1VEnd = (SIZE_T)-1;
        }
        for (j = i + 1; j < SectionCount; j++) {
            ULONG s2VSize;
            SIZE_T s2VStart, s2VEnd;
            ULONG k;
            BOOLEAN alreadyRecorded = FALSE;
            s2VSize = (Sections[j].Misc.VirtualSize != 0) ? Sections[j].Misc.VirtualSize
                                                     : Sections[j].SizeOfRawData;
            if (s2VSize == 0 || Sections[j].VirtualAddress == 0) continue;
            s2VStart = (SIZE_T)Sections[j].VirtualAddress;
            if (!IocpAddSizeSafe(s2VStart, (SIZE_T)s2VSize, &s2VEnd)) {
                s2VEnd = (SIZE_T)-1;
            }
            if (s1VStart < s2VEnd && s2VStart < s1VEnd) {
                for (k = 0; k < count; k++) {
                    if (Overlaps && Overlaps[k].Left == i && Overlaps[k].Right == j) {
                        alreadyRecorded = TRUE;
                        break;
                    }
                }
                if (!alreadyRecorded) {
                    OVERLAP_ADD(i, j);
                }
            }
        }
    }

#undef OVERLAP_ADD

    if (OverlapCount) *OverlapCount = count;
    return found;
}

/**************************************************/
/*           数据目录校验                           */
/**************************************************/

PE_VALIDATION_RESULT
WpeValidateDataDirectory(
    _In_  SIZE_T            Index,
    _In_  ULONG             Rva,
    _In_  ULONG             Size,
    _In_  ULONG             SizeOfImage,
    _In_  SIZE_T            FileSize,
    _Out_opt_ PPE_PARSER_ERROR Error
    )
/*++
Routine Description:
    校验数据目录条目。SECURITY(索引4) 的 VirtualAddress 实为文件偏移而非
    RVA — 特例按 FileSize 校验。其余目录按 SizeOfImage 校验。
    ※死代码: SS ValidateDataDirectory 亦无调用者 (其逻辑被 SS 各 Internal
      解析器内联替代, WKD 被 PeLazy.c 各惰性解析器的 IocpRvaToOffset +
      STATUS_INVALID_IMAGE_FORMAT 覆盖); 功能完整含 IMPORT/EXPORT/TLS
      最小尺寸检查, 待接线决策。

Arguments:
    Index      - 数据目录索引。
    Rva        - 目录 RVA (SECURITY 为文件偏移)。
    Size       - 目录大小。
    SizeOfImage - 映像大小 (可 0)。
    FileSize   - 文件大小。
    Error        - [可选] 错误输出。

Return Value:
    校验结果码。
--*/
{
    SIZE_T end;

    /* 空目录条目合法 (目录不存在) */
    if (Rva == 0 && Size == 0) {
        return WpeVal_Valid;
    }

    /* 非零 size + 零 RVA — 结构性畸形 */
    if (Rva == 0 && Size != 0) {
        IocpRecordError(Error, WpeVal_DataDirectoryRvaInvalid,
                  L"Data directory has non-zero size but zero RVA", 0);
        return WpeVal_DataDirectoryRvaInvalid;
    }

    /* SECURITY 目录: VA 存文件偏移, 按 FileSize 校验 */
    if (Index == PE_DD_SECURITY) {
        if (!IocpAddSizeSafe((SIZE_T)Rva, (SIZE_T)Size, &end)) {
            IocpRecordError(Error, WpeVal_IntegerOverflow,
                      L"Security certificate directory size overflow", 0);
            return WpeVal_IntegerOverflow;
        }
        if (end > FileSize) {
            IocpRecordError(Error, WpeVal_SecurityDirectoryInvalid,
                      L"Security certificate directory extends beyond file", Rva);
            return WpeVal_SecurityDirectoryInvalid;
        }
        if (Size < PE_MIN_WIN_CERTIFICATE) {
            IocpRecordError(Error, WpeVal_SecurityDirectoryInvalid,
                      L"Security directory too small for a valid WIN_CERTIFICATE header", Rva);
            return WpeVal_SecurityDirectoryInvalid;
        }
        return WpeVal_Valid;
    }

    /* 其余目录使用 RVA — 按 SizeOfImage 校验 */
    if (SizeOfImage > 0) {
        if (Rva >= SizeOfImage) {
            IocpRecordError(Error, WpeVal_DataDirectoryRvaInvalid,
                      L"Data directory RVA exceeds image size", Rva);
            return WpeVal_DataDirectoryRvaInvalid;
        }
        if (!IocpAddSizeSafe((SIZE_T)Rva, (SIZE_T)Size, &end)) {
            IocpRecordError(Error, WpeVal_IntegerOverflow,
                      L"Data directory RVA+size overflow", 0);
            return WpeVal_IntegerOverflow;
        }
        if (end > (SIZE_T)SizeOfImage) {
            IocpRecordError(Error, WpeVal_DataDirectoryOutOfBounds,
                      L"Data directory extends beyond image", Rva);
            return WpeVal_DataDirectoryOutOfBounds;
        }
    } else {
        /* 无 SizeOfImage — 至少防算术溢出 */
        if (!IocpAddSizeSafe((SIZE_T)Rva, (SIZE_T)Size, &end)) {
            IocpRecordError(Error, WpeVal_IntegerOverflow,
                      L"Data directory size overflow", 0);
            return WpeVal_IntegerOverflow;
        }
    }

    /* 已知关键目录最小尺寸检查 */
    switch (Index) {
    case IMAGE_DIRECTORY_ENTRY_IMPORT:
        if (Size < sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            IocpRecordError(Error, WpeVal_ImportDirectoryInvalid,
                      L"Import directory too small for an import descriptor", Rva);
            return WpeVal_ImportDirectoryInvalid;
        }
        break;
    case PE_DD_EXPORT:
        if (Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
            IocpRecordError(Error, WpeVal_ExportDirectoryInvalid,
                      L"Export directory too small for an export directory", Rva);
            return WpeVal_ExportDirectoryInvalid;
        }
        break;
    case PE_DD_TLS:
        if (Size < sizeof(IMAGE_TLS_DIRECTORY32)) {
            IocpRecordError(Error, WpeVal_TLSDirectoryInvalid,
                      L"TLS directory too small for a TLS descriptor", Rva);
            return WpeVal_TLSDirectoryInvalid;
        }
        break;
    default:
        break;
    }

    return WpeVal_Valid;
}
