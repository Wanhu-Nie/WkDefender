/**************************************************/
/*  WkDefender — 统一 PE 解析核心（PeParser）        */
/*                                                  */
/*  核心实现：融合边界校验 + 标准事实填充 +           */
/*  布局感知寻址 + 熵双变体 + 导出解析。             */
/*  零分配热路径，单 SEH 包整条流水线。              */
/**************************************************/

#include "PeParser.h"

/**************************************************/
/*                  熵双变体                       */
/**************************************************/

_Use_decl_annotations_
ULONG
WkdPeEntropyWkd(
    _In_reads_bytes_(Size) PUCHAR Data,
    _In_ ULONG Size
    )
/*++
    Routine Description（描述）:
        wkd 简化熵（uniqueFactor+distFactor，0-1000 尺度，无浮点）。
        必须与重构前 ImgpParsePeFacts 内联实现逐字节一致（对拍基准）。

    Arguments（参数）:
        Data - 节内容缓冲（调用方保证可读）。
        Size - 采样长度（建议 <= WKD_PE_MAX_ENTROPY_SCAN）。

    Return Value:
        熵值 [0, 1000]。
--*/
{
    ULONG freq[256] = { 0 };
    ULONG uniqueBytes = 0, maxCount = 0, totalBytes = 0;
    ULONG entScaled = 0;

    if (Data == NULL || Size == 0) {
        return 0;
    }

    for (ULONG b = 0; b < Size; b++) {
        freq[Data[b]]++;
        totalBytes++;
    }
    for (ULONG c = 0; c < 256; c++) {
        if (freq[c] > 0) {
            uniqueBytes++;
            if (freq[c] > maxCount) {
                maxCount = freq[c];
            }
        }
    }
    if (uniqueBytes > 0 && totalBytes > 0) {
        ULONG64 uniqueFactor = ((ULONG64)uniqueBytes * 500) / 256;
        ULONG64 distFactor = (maxCount > 0)
            ? 500 - (((ULONG64)maxCount * 500) / totalBytes) : 500;
        entScaled = (ULONG)(uniqueFactor + distFactor);
        if (entScaled > 1000) {
            entScaled = 1000;
        }
    }
    return entScaled;
}

_Use_decl_annotations_
ULONG
WkdPeEntropyShannon(
    _In_reads_bytes_(Size) PUCHAR Data,
    _In_ ULONG Size
    )
/*++
    Routine Description（描述）:
        PS 语义 Shannon 熵近似（prob*10000/Size + 右移 logApprox，clamp 800）。
        对齐 SS ImgpCalculateSectionEntropy，供 PhantomSensor 回调。

    Arguments（参数）:
        Data - 数据缓冲。
        Size - 采样长度。

    Return Value:
        熵值 [0, 800]。
--*/
{
    ULONG byteCount[256] = { 0 };
    ULONG entropy = 0;

    if (Data == NULL || Size == 0) {
        return 0;
    }
    for (ULONG i = 0; i < Size; i++) {
        byteCount[Data[i]]++;
    }
    for (ULONG i = 0; i < 256; i++) {
        if (byteCount[i] > 0) {
            ULONG prob = (byteCount[i] * 10000) / Size;
            if (prob > 0 && prob < 10000) {
                ULONG logApprox = 0;
                ULONG tmp = prob;
                while (tmp > 0) {
                    logApprox++;
                    tmp >>= 1;
                }
                entropy += (prob * logApprox) / 10000;
            }
        }
    }
    if (entropy > 800) {
        entropy = 800;
    }
    return entropy;
}

/**************************************************/
/*               布局感知寻址                      */
/**************************************************/

_Use_decl_annotations_
ULONG
WkdPeRvaToFileOffset(
    _In_ PWKD_PE_PARSE_CONTEXT Context,
    _In_ ULONG Rva
    )
/*++
    Routine Description（描述）:
        RVA → 文件偏移（仅 File 模式有意义）。遍历节表，
        防 va+raw / ptr+delta 的 ULONG 溢出（对齐 Amsi AbdpRvaToFileOffset 全防）。

    Arguments（参数）:
        Context - 已由 CoParsePe 填充节表的解析上下文。
        Rva - 相对虚拟地址。

    Return Value:
        文件偏移；0 兼作失败哨兵（RVA 未落入任何节或偏移溢出）。
--*/
{
    for (ULONG i = 0; i < Context->SectionCount; i++) {
        PIMAGE_SECTION_HEADER sec = &Context->Sections[i];
        ULONG va = sec->VirtualAddress;
        ULONG raw = sec->SizeOfRawData;
        ULONG end, delta;

        if (raw > MAXULONG - va) {
            continue;                       /* 防 va+raw 溢出 */
        }
        end = va + raw;
        if (Rva < va || Rva >= end) {
            continue;
        }
        delta = Rva - va;
        if (delta > MAXULONG - sec->PointerToRawData) {
            return 0;                       /* 防 ptr+delta 溢出 */
        }
        return delta + sec->PointerToRawData;
    }
    return 0;
}

_Use_decl_annotations_
NTSTATUS
WkdPeGetDataAtRva(
    _Inout_ PWKD_PE_PARSE_CONTEXT Context,
    _In_ ULONG Rva,
    _In_ SIZE_T Size,
    _Outptr_ PVOID* Ptr,
    _Out_opt_ PSIZE_T BoundedSize
    )
/*++
    Routine Description（描述）:
        布局感知寻址：把 RVA 解析为 Data 缓冲内的有效指针。
        Image 模式直接加基址；File 模式先经节表转文件偏移。
        BoundedSize 受 Size 与 DataSize 双夹。

    Arguments（参数）:
        Context - 解析上下文（CoParsePe 调用后）。
        Rva - 相对虚拟地址。
        Size - 期望读取长度（0 = 仅定位）。
        Ptr - 输出有效指针。
        BoundedSize - 输出实际可安全读取字节数（可为 NULL）。

    Return Value:
        STATUS_SUCCESS / STATUS_ACCESS_VIOLATION（越界或转换失败）。
--*/
{
    PVOID ptr = NULL;
    SIZE_T bounded = 0;

    if (Context == NULL || Context->Data == NULL || Ptr == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Context->Mode == WkdPeMode_Image) {
        if (Rva > Context->DataSize) {
            return STATUS_ACCESS_VIOLATION;
        }
        ptr = (PUCHAR)Context->Data + Rva;
        bounded = Context->DataSize - Rva;
    } else {
        ULONG offset = WkdPeRvaToFileOffset(Context, Rva);
        if (offset == 0 || offset > Context->DataSize) {
            return STATUS_ACCESS_VIOLATION;
        }
        ptr = (PUCHAR)Context->Data + offset;
        bounded = Context->DataSize - offset;
    }
    if (Size > 0 && bounded > Size) {
        bounded = Size;
    }
    *Ptr = ptr;
    if (BoundedSize != NULL) {
        *BoundedSize = bounded;
    }
    return STATUS_SUCCESS;
}

/**************************************************/
/*              导出解析（Amsi 能力）              */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
WkdPeResolveExport(
    _Inout_ PWKD_PE_PARSE_CONTEXT Context,
    _In_ PCSTR Name,
    _Out_ PWKD_PE_EXPORT_ENTRY Out
    )
/*++
    Routine Description（描述）:
        按名解析导出函数（对齐 Amsi AbdpFindExportRva 全防）：
        目录 VA/Size 整界校验、名字·函数数 1M 上限、SIZE_T 乘法逐表越界、
        strnlen 防越界、ordinal 界校验。

    Arguments（参数）:
        Context - 已解析上下文（需含导出目录）。
        Name - 导出函数名（ASCII）。
        Out - 输出 RVA / Ordinal / FileOffset。

    Return Value:
        STATUS_SUCCESS（命中）/ STATUS_NOT_FOUND（未命中或非导出）/ 其他错误。
--*/
{
    PIMAGE_EXPORT_DIRECTORY export;
    PVOID dirPtr = NULL, namesPtr = NULL, funcsPtr = NULL, ordsPtr = NULL;
    SIZE_T bounded = 0;
    NTSTATUS status;

    if (Context == NULL || Name == NULL || Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Out, sizeof(*Out));

    //if (Context->DirCount <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
    //    return STATUS_NOT_FOUND;
    //}
    {
        IMAGE_DATA_DIRECTORY exportDir = WKD_PE_OPT_DIR(Context, IMAGE_DIRECTORY_ENTRY_EXPORT);
        if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) {
            return STATUS_NOT_FOUND;
        }
        status = WkdPeGetDataAtRva(Context, exportDir.VirtualAddress, exportDir.Size, &dirPtr, &bounded);
        if (!NT_SUCCESS(status) || bounded < sizeof(IMAGE_EXPORT_DIRECTORY)) {
            return STATUS_NOT_FOUND;
        }
    }
    export = (PIMAGE_EXPORT_DIRECTORY)dirPtr;

    /* 名字·函数数上限 1M（对齐 SS/Amsi） */
    if (export->NumberOfNames == 0 || export->NumberOfNames > 0x100000 ||
        export->NumberOfFunctions == 0 || export->NumberOfFunctions > 0x100000) {
        return STATUS_NOT_FOUND;
    }

    /* 三表定位（SIZE_T 乘法越界由 GetDataAtRva 双夹保证） */
    status = WkdPeGetDataAtRva(Context, export->AddressOfNames,
        (SIZE_T)export->NumberOfNames * sizeof(ULONG), &namesPtr, &bounded);
    if (!NT_SUCCESS(status)) {
        return STATUS_NOT_FOUND;
    }
    status = WkdPeGetDataAtRva(Context, export->AddressOfFunctions,
        (SIZE_T)export->NumberOfFunctions * sizeof(ULONG), &funcsPtr, &bounded);
    if (!NT_SUCCESS(status)) {
        return STATUS_NOT_FOUND;
    }
    status = WkdPeGetDataAtRva(Context, export->AddressOfNameOrdinals,
        (SIZE_T)export->NumberOfNames * sizeof(USHORT), &ordsPtr, &bounded);
    if (!NT_SUCCESS(status)) {
        return STATUS_NOT_FOUND;
    }

    for (ULONG i = 0; i < export->NumberOfNames; i++) {
        ULONG nameRva = ((PULONG)namesPtr)[i];
        PCHAR nameStr;
        SIZE_T nameBounded = 0;
        ULONG ordinal;

        status = WkdPeGetDataAtRva(Context, nameRva, 0, (PVOID*)&nameStr, &nameBounded);
        if (!NT_SUCCESS(status)) {
            continue;
        }
        if (strnlen(nameStr, nameBounded) == strlen(Name) &&
            RtlCompareMemory(nameStr, Name, strlen(Name)) == strlen(Name)) {
            ordinal = ((PUSHORT)ordsPtr)[i];
            if (ordinal >= export->NumberOfFunctions) {
                return STATUS_NOT_FOUND;
            }
            Out->Ordinal = ordinal;
            Out->Rva = ((PULONG)funcsPtr)[ordinal];
            if (Context->Mode == WkdPeMode_File) {
                Out->FileOffset = WkdPeRvaToFileOffset(Context, Out->Rva);
            }
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

/**************************************************/
/*              file→image 重排（死代码预留）       */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
WkdPeRemapFileToImage(
    _In_ PVOID FileData,
    _In_ SIZE_T FileSize,
    _Out_ PVOID* ImageBuffer,
    _Out_ PSIZE_T ImageSize
    )
/*++
    Routine Description（描述）:
        file→image 布局重排（对齐 SS NipRemapFileToImage，死代码预留）：
        解析头后分配并清零 SizeOfImage 镜像缓冲，SizeOfHeaders 双夹拷贝头部，
        逐节 copySize 截断搬移到 VirtualAddress。之后可作 WkdPeMode_Image 再解析。

    Arguments（参数）:
        FileData - 文件缓冲。
        FileSize - 文件缓冲大小。
        ImageBuffer - 输出镜像缓冲（调用方用 WKD_PE_REMAP_TAG 释放）。
        ImageSize - 输出 SizeOfImage。

    Return Value:
        NTSTATUS。
--*/
{
    WKD_PE_PARSE_CONTEXT ctx;
    NTSTATUS status;
    ULONG sizeOfImage, sizeOfHeaders;
    PVOID img = NULL;
    SIZE_T headersSize;

    if (FileData == NULL || FileSize == 0 || ImageBuffer == NULL || ImageSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&ctx, sizeof(ctx));
    ctx.Data = FileData;
    ctx.DataSize = FileSize;
    ctx.Mode = WkdPeMode_File;
    ctx.MaxSections = WKD_PE_MAX_SECTIONS_DEFAULT;

    status = CoParsePe(&ctx);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    sizeOfImage = WKD_PE_OPT_OFFSET(&ctx, SizeOfImage);
    if (sizeOfImage == 0 || sizeOfImage > WKD_PE_MAX_REMAP_SIZE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    sizeOfHeaders = WKD_PE_OPT_OFFSET(&ctx, SizeOfHeaders);

    img = ExAllocatePool2(POOL_FLAG_PAGED, sizeOfImage, WKD_PE_REMAP_TAG);
    if (img == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(img, sizeOfImage);

    /* SizeOfHeaders 双夹（对齐 SS: min(FileSize, SizeOfImage)） */
    headersSize = sizeOfHeaders;
    if (headersSize > FileSize) {
        headersSize = FileSize;
    }
    if (headersSize > sizeOfImage) {
        headersSize = sizeOfImage;
    }
    RtlCopyMemory(img, FileData, headersSize);

    /* 逐节搬移：越界/重叠节跳过，copySize 截断到镜像边界（对齐 SS） */
    for (ULONG i = 0; i < ctx.SectionCount; i++) {
        PIMAGE_SECTION_HEADER sec = &ctx.Sections[i];
        ULONG va = sec->VirtualAddress;
        ULONG raw = sec->SizeOfRawData;
        ULONG ptr = sec->PointerToRawData;
        ULONG copySize;

        if (raw == 0 || ptr == 0) {
            continue;
        }
        if (ptr > FileSize || raw > FileSize - ptr) {
            continue;
        }
        if (va >= sizeOfImage || va < sizeOfHeaders) {
            continue;
        }
        copySize = raw;
        if (copySize > sizeOfImage - va) {
            copySize = sizeOfImage - va;
        }
        RtlCopyMemory((PUCHAR)img + va, (PUCHAR)FileData + ptr, copySize);
    }

    *ImageBuffer = img;
    *ImageSize = sizeOfImage;
    return STATUS_SUCCESS;
}

/**************************************************/
/*                粗分类（FileUtils）              */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
WkdPeClassify(
    _Inout_ PWKD_PE_PARSE_CONTEXT Context,
    _Out_ PWKD_PE_CLASSIFY Out
    )
/*++
    Routine Description（描述）:
        粗分类（对齐 SS ShadowpParsePEHeaders 语义）：
        非 PE 返回 STATUS_SUCCESS 且 IsPe=FALSE（不报错）。

    Arguments（参数）:
        Context - 待解析上下文（Data/DataSize/Mode 由调用方预置）。
        Out - 输出分类结果。

    Return Value:
        STATUS_SUCCESS。
--*/
{
    NTSTATUS status;

    if (Context == NULL || Out == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Out, sizeof(*Out));

    status = CoParsePe(Context);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS;              /* 非 PE 静默 */
    }
    Out->IsPe = TRUE;
    Out->Amd64 = Context->Facts.Amd64;
    Out->Subsystem = (USHORT)WKD_PE_OPT_OFFSET(Context, Subsystem);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
WkdPeIsUserExecutableRange(
    _In_ PVOID Address
    )
/*++
    Routine Description（描述）:
        用户可执行地址域判定（对齐 CSA 地址域 0x10000..0x7FFFFFFFFFFF）。

    Arguments（参数）:
        Address - 待判定地址。

    Return Value:
        TRUE = 落在用户可执行地址域。
--*/
{
    ULONG_PTR addr = (ULONG_PTR)Address;
    return (addr >= 0x10000 && addr <= 0x7FFFFFFFFFFFULL);
}

/**************************************************/
/*                统一解析核心                     */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
CoParsePe(
    _Inout_ PWKD_PE_PARSE_CONTEXT Context
    )
/*++
    Routine Description（描述）:
        统一 PE 解析核心（模板函数）。融合边界校验 + 标准事实填充 +
        阶段回调驱动。边界校验集 7 种 e_lfanew 写法之长（下界拒负 +
        双比较防下溢 + 4096 硬顶）、Magic 两步消除硬编码位宽、
        节表显式防回绕、目录硬夹 16。Facts 逐字段对齐重构前
        ImgpParsePeFacts（对拍基准，保 L1 IocImage 零变化）。

    Arguments（参数）:
        Context - 解析上下文。Data/DataSize/Mode/Flags/MaxSections/Callbacks/
              CallbackContext 由调用方预置；Size 须 = sizeof(*Context)。

    Return Value:
        STATUS_SUCCESS / STATUS_INVALID_IMAGE_FORMAT（PE 结构非法）/
        STATUS_INVALID_PARAMETER（参数错误）/ 异常码（SEH 触发，对齐旧语义）。
--*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (!Context || !Context->Data || Context->DataSize == 0 ||
        Context->Mode >= WkdPeMode_Max) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Context->MaxSections == 0) {
        Context->MaxSections = WKD_PE_MAX_SECTIONS_DEFAULT;
    }
    RtlZeroMemory(&Context->Facts, sizeof(Context->Facts));

     __try { 
         ULONG offset;

        /* === DOS 头 === */
        {
            PIMAGE_DOS_HEADER dos;

            if (Context->DataSize < sizeof(IMAGE_DOS_HEADER)) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }

            dos = (PIMAGE_DOS_HEADER)Context->Data;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }

            /* === e_lfanew 校验 === */
            offset = dos->e_lfanew;
            if (offset < sizeof(IMAGE_DOS_HEADER) ||
                offset + FIELD_OFFSET(IMAGE_NT_HEADERS, FileHeader) > Context->DataSize ) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
        }

        /* === NT 头 === */
        {
            PIMAGE_NT_HEADERS nt;
            USHORT optMagic;
            USHORT optSize; /* 可选PE头大小 */
            USHORT numberOfSections;
            PIMAGE_SECTION_HEADER sections;
            
            nt = (PIMAGE_NT_HEADERS)((PUCHAR)Context->Data + offset);
            if (nt->Signature != IMAGE_NT_SIGNATURE) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }

            /* === IMAGE_FILE_HEADER 校验 === */
            if (offset + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
                FIELD_OFFSET(IMAGE_OPTIONAL_HEADER, Magic) > Context->DataSize) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }

            /* ===  IMAGE_OPTIONAL_HEADER 校验 === */
            optMagic = nt->OptionalHeader.Magic;
            optSize = nt->FileHeader.SizeOfOptionalHeader;
            if (optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                if (optSize != sizeof(IMAGE_OPTIONAL_HEADER32) ||
                    offset + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + optSize > Context->DataSize) {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }
                Context->Opt32 = (PIMAGE_OPTIONAL_HEADER32)(&nt->OptionalHeader);
            }
            else if (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                if (optSize != sizeof(IMAGE_OPTIONAL_HEADER64) ||
                    offset + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + optSize > Context->DataSize) {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }
                Context->Opt64 = (PIMAGE_OPTIONAL_HEADER64)(&nt->OptionalHeader);
            }
            else {
                return STATUS_INVALID_IMAGE_FORMAT;
            }

            /* === 节数上限检验 === */
            numberOfSections = nt->FileHeader.NumberOfSections;
            if (numberOfSections > WKD_PE_MAX_SECTIONS_DEFAULT) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            numberOfSections = min(numberOfSections, Context->MaxSections);

            /* === 节表边界（显式防回绕，对齐 ROP/ImageNotify） === */
            sections = (PIMAGE_SECTION_HEADER)((PUCHAR)&nt->OptionalHeader + optSize);
            if ((SIZE_T)((PUCHAR)sections - (PUCHAR)Context->Data) +
                numberOfSections * sizeof(IMAGE_SECTION_HEADER) > Context->DataSize) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }

            Context->NtHeaders = nt;
            Context->Sections = sections;
            Context->SectionCount = numberOfSections;
            Context->DirectoryEntries = WKD_PE_OPT_OFFSET(Context, NumberOfRvaAndSizes);

            Context->Facts.Valid = TRUE;
            Context->Facts.Amd64 = (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) &&
                (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
            Context->Facts.IsDll = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
            /* IMAGE_FILE_SYSTEM 不是一个可靠的判断依据??? */
            Context->Facts.IsSystem = (nt->FileHeader.Characteristics & IMAGE_FILE_SYSTEM) != 0;    
            Context->Facts.IsDriver = (WKD_PE_OPT_OFFSET(Context, Subsystem) == IMAGE_SUBSYSTEM_NATIVE);
            Context->Facts.NumberOfSections = (USHORT)numberOfSections;
            Context->Facts.AddressOfEntryPoint = WKD_PE_OPT_OFFSET(Context, AddressOfEntryPoint);
            Context->Facts.ImageBase = WKD_PE_OPT_OFFSET(Context, ImageBase);
            Context->Facts.TimeDateStamp = nt->FileHeader.TimeDateStamp;
            Context->Facts.CheckSum = WKD_PE_OPT_OFFSET(Context, CheckSum);

            /* === OnNtHeader 回调（填 Facts 前，回调可经 Context->Opt 读字段） === */
            if (Context->Callbacks.OnNtHeader) {
                status = Context->Callbacks.OnNtHeader(Context, nt, Context->CallbackContext);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            /*
             * [NumberOfRvaAndSizes指明 DataDirectory 数组中实际有效的数据目录条目数量]
             * 0. IMAGE_DIRECTORY_ENTRY_EXPORT          导出表
             * 1. IMAGE_DIRECTORY_ENTRY_IMPORT          导入表
             * 2. IMAGE_DIRECTORY_ENTRY_RESOURCE        资源表
             * 3. IMAGE_DIRECTORY_ENTRY_EXCEPTION       异常表
             * 4. IMAGE_DIRECTORY_ENTRY_SECURITY        安全目录
             * 5. IMAGE_DIRECTORY_ENTRY_BASERELOC       基址重定位表
             * 6. IMAGE_DIRECTORY_ENTRY_DEBUG           调试目录
             * 7. IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    体系结构特定数据
             * 8. IMAGE_DIRECTORY_ENTRY_GLOBALPTR       全局指针
             * 9. IMAGE_DIRECTORY_ENTRY_TLS             TLS目录
             * 10.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG     加载配置目录
             * 11.IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT    绑定导入表
             * 12.IMAGE_DIRECTORY_ENTRY_IAT             导入地址表
             * 13.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT    延迟导入描述符
             * 14.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR  COM运行时描述符
             * 15.保留
             */

             /* COM运行时描述符 */
            if (Context->DirectoryEntries > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR &&
                WKD_PE_OPT_DIR(Context, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR).VirtualAddress != 0) {
                Context->Facts.HasDotNet = TRUE;
            }
            /* 安全目录 */
            if (Context->DirectoryEntries > IMAGE_DIRECTORY_ENTRY_SECURITY &&
                WKD_PE_OPT_DIR(Context, IMAGE_DIRECTORY_ENTRY_SECURITY).VirtualAddress != 0) {
                Context->Facts.HasSecurityDirectory = TRUE;
            }
            /* TLS目录 */
            if (Context->DirectoryEntries > IMAGE_DIRECTORY_ENTRY_TLS &&
                WKD_PE_OPT_DIR(Context, IMAGE_DIRECTORY_ENTRY_TLS).VirtualAddress != 0) {
                Context->Facts.HasTlsCallbacks = TRUE;
            }
            /* 导出表 */
            if (Context->DirectoryEntries > IMAGE_DIRECTORY_ENTRY_EXPORT) {
                IMAGE_DATA_DIRECTORY exportDir = WKD_PE_OPT_DIR(Context, IMAGE_DIRECTORY_ENTRY_EXPORT);
                if (exportDir.Size == 0) {
                    Context->Facts.HasNoExports = TRUE;
                }
            }

            /* === OnDirectory 回调（需置 WKD_PE_FLAG_DIRECTORIES） === */
            if ((Context->Flags & WKD_PE_FLAG_DIRECTORIES) != 0 && Context->Callbacks.OnDirectory != NULL) {
                for (ULONG i = 0; i < Context->DirectoryEntries; i++) {
                    IMAGE_DATA_DIRECTORY dir = WKD_PE_OPT_DIR(Context, i);
                    status = Context->Callbacks.OnDirectory(Context, i, &dir, Context->CallbackContext);
                    if (status == STATUS_NO_MORE_ENTRIES) {
                        break;
                    }
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
            }

            /* === 节循环（WX/EP/熵 + OnSection/OnSectionContent） === */
            for (USHORT i = 0; i < numberOfSections; i++) {
                ULONG secChars = sections[i].Characteristics;
                BOOLEAN isExec = (secChars & IMAGE_SCN_MEM_EXECUTE) != 0;

                /* WX 节（SelfModifying）— 仅记录事实，判定在 L1 */
                if (isExec && (secChars & IMAGE_SCN_MEM_WRITE)) {
                    Context->Facts.HasWxSection = TRUE;
                    Context->Facts.SectionMask[i >> 5] |= (1UL << (i & 31));
                }

                /* EP 落代码段（溢出安全：EP ∈ [VA, VA+VS) 用 (EP - VA) < VS 判定，
                 * 先减后比消除 VA+VS 的 ULONG 回绕；无溢出时与原式完全等价，
                 * 对拍基准不变——仅改算术形式，不加语义约束） */
                if (isExec && Context->Facts.AddressOfEntryPoint != 0 &&
                    Context->Facts.AddressOfEntryPoint >= sections[i].VirtualAddress &&
                    (Context->Facts.AddressOfEntryPoint - sections[i].VirtualAddress) <
                    sections[i].Misc.VirtualSize) {
                    Context->Facts.EntryPointInCode = TRUE;
                }

                /* OnSection 回调（Facts 增量更新后） */
                if (Context->Callbacks.OnSection) {
                    status = Context->Callbacks.OnSection(Context, &sections[i], i, Context->CallbackContext);
                    if (status == STATUS_NO_MORE_ENTRIES) {
                        break;
                    }
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }

                /* OnSectionContent 回调（需置 WKD_PE_FLAG_SECTION_CONTENT） */
                if ((Context->Flags & WKD_PE_FLAG_SECTION_CONTENT) != 0 &&
                    Context->Callbacks.OnSectionContent) {
                    ULONG vs = sections[i].Misc.VirtualSize;
                    ULONG raw = sections[i].SizeOfRawData;
                    ULONG effective = (vs < raw) ? vs : raw;    /* min */
                    PVOID ptr = NULL;
                    SIZE_T bounded = 0;

                    if (effective == 0) {
                        effective = vs;                         /* 0 回退 VirtualSize */
                    }
                    if (effective > 0 &&
                        NT_SUCCESS(WkdPeGetDataAtRva(Context, sections[i].VirtualAddress,
                            effective, &ptr, &bounded)) && ptr != NULL) {
                        status = Context->Callbacks.OnSectionContent(Context, ptr, bounded,
                            Context->CallbackContext);
                        if (status == STATUS_NO_MORE_ENTRIES) {
                            break;
                        }
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                    }
                }
            }
        }

        /* === OnComplete 回调（头部有效后必调） === */
        if (Context->Callbacks.OnComplete != NULL) {
            status = Context->Callbacks.OnComplete(Context, Context->CallbackContext);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        status = STATUS_SUCCESS;
     } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    } 
    return status;
}
