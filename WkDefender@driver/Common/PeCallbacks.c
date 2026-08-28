/**************************************************/
/*  WkDefender — PE 解析回调束（PeCallbacks）        */
/*                                                  */
/*  各能力回调以回调函数形式接入统一 PE 核心，        */
/*  WkdPeCbXxxInit 装填 Ctx->Callbacks +             */
/*  CallbackContext，调用方调 CoParsePe 触发。      */
/**************************************************/

#include "PeCallbacks.h"

/**************************************************/
/*            安全缓解映射（ProcessAnalyzer）       */
/**************************************************/

static
NTSTATUS
WkdPeCbMitigationsOnNtHeader(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_    PIMAGE_NT_HEADERS NtHeaders,
    _In_opt_ PVOID UserCtx
    )
/*++
    DllCharacteristics → HasDEP/ASLR/CFG/高熵ASLR 位映射
    （对齐 SS PapAnalyzePEHeaders）+ TimeDateStamp + .NET 判定。
--*/
{
    PWKD_PE_MITIGATIONS mit = (PWKD_PE_MITIGATIONS)UserCtx;
    ULONG dllChar;

    if (mit == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    dllChar = WKD_PE_OPT_OFFSET(Ctx, DllCharacteristics);

    mit->IsPe = TRUE;
    mit->HasDep = (dllChar & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    mit->HasAslr = (dllChar & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    mit->HasCfg = (dllChar & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
    mit->HasHighEntropyAslr = (dllChar & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;
    mit->TimeDateStamp = NtHeaders->FileHeader.TimeDateStamp;
    mit->IsDotNet = (Ctx->DirectoryEntries > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR &&
        WKD_PE_OPT_DIR(Ctx, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR).VirtualAddress != 0);
    return STATUS_SUCCESS;
}

static
NTSTATUS
WkdPeCbMitigationsOnDirectory(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_    ULONG Index,
    _In_    PIMAGE_DATA_DIRECTORY Directory,
    _In_opt_ PVOID UserCtx
    )
/*++
    签名启发式：SECURITY 目录 VA!=0 && Size>0（对齐 SS）。
--*/
{
    PWKD_PE_MITIGATIONS mit = (PWKD_PE_MITIGATIONS)UserCtx;

    UNREFERENCED_PARAMETER(Ctx);
    if (Index == IMAGE_DIRECTORY_ENTRY_SECURITY && mit != NULL) {
        mit->HasSignature = (Directory->VirtualAddress != 0 && Directory->Size != 0);
    }
    return STATUS_SUCCESS;
}

static
NTSTATUS
WkdPeCbMitigationsOnComplete(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_opt_ PVOID UserCtx
    )
/*++
    镜像级 Shannon 熵：采样首 min(SizeOfImage, 0x10000) 字节（对齐 SS PapCalculateEntropy）。
--*/
{
    PWKD_PE_MITIGATIONS mit = (PWKD_PE_MITIGATIONS)UserCtx;
    ULONG sizeOfImage, sample;
    PVOID ptr = NULL;
    SIZE_T bounded = 0;

    if (mit == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    sizeOfImage = WKD_PE_OPT_OFFSET(Ctx, SizeOfImage);
    sample = (sizeOfImage < 0x10000) ? sizeOfImage : 0x10000;
    if (sample > 0 && NT_SUCCESS(WkdPeGetDataAtRva(Ctx, 0, sample, &ptr, &bounded)) &&
        ptr != NULL) {
        mit->ImageEntropy = WkdPeEntropyShannon((PUCHAR)ptr, (ULONG)bounded);
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
WkdPeCbMitigationsInit(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _Out_   PWKD_PE_MITIGATIONS Out
    )
/*++
    装填缓解映射回调束。调用方须在调用 CoParsePe 前调用。
--*/
{
    if (Ctx == NULL || Out == NULL) {
        return;
    }
    RtlZeroMemory(Out, sizeof(*Out));
    Ctx->Callbacks.OnNtHeader = WkdPeCbMitigationsOnNtHeader;
    Ctx->Callbacks.OnDirectory = WkdPeCbMitigationsOnDirectory;
    Ctx->Callbacks.OnComplete = WkdPeCbMitigationsOnComplete;
    Ctx->CallbackContext = Out;
    Ctx->Flags |= WKD_PE_FLAG_DIRECTORIES;
}

/**************************************************/
/*              节定位（Ntdll/Hollowing）           */
/**************************************************/

static
NTSTATUS
WkdPeCbFindSectionOnSection(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_    PIMAGE_SECTION_HEADER Section,
    _In_    ULONG Index,
    _In_opt_ PVOID UserCtx
    )
/*++
    节匹配回调：按名/掩码命中 → 填结果并优雅停环。
    匹配标准存于 Out 结构 Init 私有段。
--*/
{
    PWKD_PE_SECTION_MATCH match = (PWKD_PE_SECTION_MATCH)UserCtx;
    BOOLEAN hit = FALSE;

    if (match == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (match->Found) {
        return STATUS_SUCCESS;
    }
    if (match->ByName) {
        SIZE_T len = strlen(match->SectionName);
        if (len > 0 && len <= IMAGE_SIZEOF_SHORT_NAME &&
            RtlCompareMemory(Section->Name, match->SectionName, len) == len) {
            hit = TRUE;
        }
    } else {
        if ((Section->Characteristics & match->RequiredChars) == match->RequiredChars &&
            match->RequiredChars != 0) {
            hit = TRUE;
        }
    }
    if (!hit) {
        return STATUS_SUCCESS;
    }

    match->Found = TRUE;
    match->Index = Index;
    match->Section = Section;

    {
        ULONG vs = Section->Misc.VirtualSize;
        ULONG raw = Section->SizeOfRawData;
        ULONG effective = (vs < raw) ? vs : raw;    /* min */
        PVOID ptr = NULL;
        SIZE_T bounded = 0;

        if (effective == 0) {
            effective = vs;                         /* 0 回退 VirtualSize */
        }
        if (effective > 0 &&
            NT_SUCCESS(WkdPeGetDataAtRva(Ctx, Section->VirtualAddress,
                effective, &ptr, &bounded))) {
            match->ContentPtr = ptr;
            match->ContentSize = bounded;
        }
    }
    return STATUS_NO_MORE_ENTRIES;                  /* 找到即停 */
}

_Use_decl_annotations_
VOID
WkdPeCbFindSectionByName(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_    PCSTR SectionName,
    _Out_   PWKD_PE_SECTION_MATCH Out
    )
/*++
    按节名前缀匹配定位（对齐 NtdllIntegrity NipGetTextSection / MmParsePeSection）。
--*/
{
    if (Ctx == NULL || SectionName == NULL || Out == NULL) {
        return;
    }
    RtlZeroMemory(Out, sizeof(*Out));
    Out->ByName = TRUE;
    Out->SectionName = SectionName;
    Ctx->Callbacks.OnSection = WkdPeCbFindSectionOnSection;
    Ctx->CallbackContext = Out;
}

_Use_decl_annotations_
VOID
WkdPeCbFindSectionByChars(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_    ULONG RequiredChars,
    _Out_   PWKD_PE_SECTION_MATCH Out
    )
/*++
    按节特性掩码匹配定位（对齐 Callstack CNT_CODE|MEM_EXECUTE）。
--*/
{
    if (Ctx == NULL || Out == NULL) {
        return;
    }
    RtlZeroMemory(Out, sizeof(*Out));
    Out->ByName = FALSE;
    Out->RequiredChars = RequiredChars;
    Ctx->Callbacks.OnSection = WkdPeCbFindSectionOnSection;
    Ctx->CallbackContext = Out;
}

/**************************************************/
/*          可执行节区间合并（Callstack）           */
/**************************************************/

static
NTSTATUS
WkdPeCbExecRangeOnSection(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_    PIMAGE_SECTION_HEADER Section,
    _In_    ULONG Index,
    _In_opt_ PVOID UserCtx
    )
/*++
    累计 CNT_CODE && MEM_EXECUTE 节的 min~max 区间
    （LTCG/延迟加载多 .text 节防伪帧漏报，对齐 SS CsapPopulateTextSectionInline）。
--*/
{
    PWKD_PE_EXEC_RANGE range = (PWKD_PE_EXEC_RANGE)UserCtx;
    ULONG64 end64;

    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Index);
    if (range == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((Section->Characteristics & IMAGE_SCN_CNT_CODE) != 0 &&
        (Section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
        ULONG start = Section->VirtualAddress;
        end64 = (ULONG64)start + Section->Misc.VirtualSize;
        if (end64 > MAXULONG) {
            end64 = MAXULONG;
        }
        if (!range->HasExecutableSection) {
            range->MinRva = start;
            range->MaxRva = (ULONG)end64;
            range->HasExecutableSection = TRUE;
        } else {
            if (start < range->MinRva) {
                range->MinRva = start;
            }
            if (end64 > range->MaxRva) {
                range->MaxRva = (ULONG)end64;
            }
        }
    }
    return STATUS_SUCCESS;
}

static
NTSTATUS
WkdPeCbExecRangeOnComplete(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_opt_ PVOID UserCtx
    )
/*++
    区间收尾。
--*/
{
    PWKD_PE_EXEC_RANGE range = (PWKD_PE_EXEC_RANGE)UserCtx;

    UNREFERENCED_PARAMETER(Ctx);
    if (range == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (range->HasExecutableSection) {
        range->Size = range->MaxRva - range->MinRva;
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
WkdPeCbExecRangeInit(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _Out_   PWKD_PE_EXEC_RANGE Out
    )
/*++
    装填可执行节区间合并回调束（死代码预留，供 Callstack 栈回溯校验接入）。
--*/
{
    if (Ctx == NULL || Out == NULL) {
        return;
    }
    RtlZeroMemory(Out, sizeof(*Out));
    Ctx->Callbacks.OnSection = WkdPeCbExecRangeOnSection;
    Ctx->Callbacks.OnComplete = WkdPeCbExecRangeOnComplete;
    Ctx->CallbackContext = Out;
}

/**************************************************/
/*            PS 16 节信息（ImageNotify）           */
/**************************************************/

static
NTSTATUS
WkdPeCbPsInfoOnSection(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_    PIMAGE_SECTION_HEADER Section,
    _In_    ULONG Index,
    _In_opt_ PVOID UserCtx
    )
/*++
    填 Sections[Index]（Name/VS/VA/Chars/Shannon 熵/IsExec/IsWritable），
    对齐 SS ImgpAnalyzePeHeader（节遍历上限 min(Number, 16)）。
--*/
{
    WKD_PS_IMG_PE_INFO* info = (WKD_PS_IMG_PE_INFO*)UserCtx;
    WKD_PS_PE_SECTION_INFO* si;
    ULONG vs, sample;
    PVOID ptr = NULL;
    SIZE_T bounded = 0;

    if (info == NULL || Index >= WKD_PS_PE_MAX_SECTIONS) {
        return STATUS_SUCCESS;
    }
    si = &info->Sections[Index];
    RtlCopyMemory(si->Name, Section->Name, IMAGE_SIZEOF_SHORT_NAME);
    si->Name[IMAGE_SIZEOF_SHORT_NAME] = '\0';
    si->VirtualSize = Section->Misc.VirtualSize;
    si->VirtualAddress = Section->VirtualAddress;
    si->Characteristics = Section->Characteristics;
    si->IsExecutable = (Section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    si->IsWritable = (Section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

    vs = Section->Misc.VirtualSize;
    sample = (vs < 4096) ? vs : 4096;
    if (sample > 0 &&
        NT_SUCCESS(WkdPeGetDataAtRva(Ctx, Section->VirtualAddress, sample, &ptr, &bounded)) &&
        ptr != NULL) {
        si->Entropy = WkdPeEntropyShannon((PUCHAR)ptr, (ULONG)bounded);
    }
    return STATUS_SUCCESS;
}

static
NTSTATUS
WkdPeCbPsInfoOnDirectory(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_    ULONG Index,
    _In_    PIMAGE_DATA_DIRECTORY Directory,
    _In_opt_ PVOID UserCtx
    )
/*++
    安全目录事实（对齐 SS ImgpAnalyzePeHeader：Security VA/Size）。
--*/
{
    WKD_PS_IMG_PE_INFO* info = (WKD_PS_IMG_PE_INFO*)UserCtx;

    UNREFERENCED_PARAMETER(Ctx);
    if (Index == IMAGE_DIRECTORY_ENTRY_SECURITY && info != NULL) {
        info->HasSecurityDirectory = (Directory->VirtualAddress != 0);
        info->SecurityDirectorySize = Directory->Size;
    }
    return STATUS_SUCCESS;
}

static
NTSTATUS
WkdPeCbPsInfoOnComplete(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _In_opt_ PVOID UserCtx
    )
/*++
    节数收尾（clamp 16）。
--*/
{
    WKD_PS_IMG_PE_INFO* info = (WKD_PS_IMG_PE_INFO*)UserCtx;

    if (info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    info->SectionCount = min(Ctx->SectionCount, WKD_PS_PE_MAX_SECTIONS);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
WkdPeCbPsInfoInit(
    _Inout_ PWKD_PE_PARSE_CONTEXT Ctx,
    _Out_   PWKD_PS_IMG_PE_INFO Out
    )
/*++
    装填 PS 16 节信息回调束（死代码预留，供 PhantomSensor 深度镜像分析接入）。
--*/
{
    if (Ctx == NULL || Out == NULL) {
        return;
    }
    RtlZeroMemory(Out, sizeof(*Out));
    Ctx->Callbacks.OnSection = WkdPeCbPsInfoOnSection;
    Ctx->Callbacks.OnDirectory = WkdPeCbPsInfoOnDirectory;
    Ctx->Callbacks.OnComplete = WkdPeCbPsInfoOnComplete;
    Ctx->CallbackContext = Out;
    Ctx->Flags |= WKD_PE_FLAG_DIRECTORIES;
}
