/**************************************************/
/*  WkDefender PEAnalyzer — 惰性解析器实现          */
/**************************************************/

#include "PeInternal.h"
#include "../../Common/FileUtils.h"
#include "../../Process/ProcessModule.h"   /* PsLookupModuleInstanceByName/PsGetMainModuleInstance（双 reader 回调目标 DLL 基址/主模块域, 2026-09-07） */

#include <stdio.h>    /* sprintf_s (Rich 编译器名映射) */
#include <stdlib.h>   /* _rotl (Rich 校验和, 对齐 SS) */
#include <ctype.h>    /* tolower (资源脚本预览) */
#include <string.h>   /* strncpy_s/strstr */

/* 资源目录防环 visited 容量 */
#define PE_RESOURCE_VISITED_MAX    512

/**************************************************/
/*             动态数组辅助                         */
/**************************************************/

/*
 * WpeVecPush — realloc 增长数组, 返回新元素指针 (可失败)。
 */
static
void*
WpeVecPush(
    _Inout_ void** Data,
    _Inout_ PULONG Count,
    _Inout_ PULONG Cap,
    _In_    SIZE_T ElemSize
    )
{
    void* p;

    if (*Count >= *Cap) {
        ULONG newCap = (*Cap == 0) ? 16 : (*Cap * 2);
        void* nd = realloc(*Data, (SIZE_T)newCap * ElemSize);
        if (nd == NULL) return NULL;
        *Data = nd;
        *Cap = newCap;
    }
    p = (BYTE*)*Data + (SIZE_T)(*Count) * ElemSize;
    (*Count)++;
    return p;
}

/*
 * WpeBlobGrow — 确保 NameBlob 容量足够。
 */
static
BOOLEAN
WpeBlobGrow(
    _Inout_ PWCHAR* Blob,
    _Inout_ PULONG  Cap,
    _In_    ULONG   Need
    )
{
    ULONG newCap;

    if (*Cap >= Need) return TRUE;
    newCap = (*Cap == 0) ? 256 : (*Cap * 2);
    while (newCap < Need) newCap *= 2;

    {
        PWCHAR nd = realloc(*Blob, (SIZE_T)newCap * sizeof(WCHAR));
        if (nd == NULL) return FALSE;
        *Blob = nd;
        *Cap = newCap;
    }
    return TRUE;
}

/*
 * WpeBlobAddA — 追加 ASCII 串 (转 WCHAR) 到 NameBlob。
 * Used 为已用 WCHAR 数 (即调用方的 BlobChars 计数器)。
 */
static
BOOLEAN
WpeBlobAddA(
    _Inout_ PWCHAR* Blob,
    _Inout_ PULONG  Used,
    _Inout_ PULONG  Cap,
    _In_    PCSTR   Str,
    _In_    ULONG   Len,
    _Out_opt_ PULONG OutOffset
    )
{
    ULONG need;
    ULONG i;

    if (Len == 0) {
        if (OutOffset) *OutOffset = 0;
        return TRUE;
    }
    need = *Used + Len + 1;
    if (!WpeBlobGrow(Blob, Cap, need)) return FALSE;
    for (i = 0; i < Len; i++) {
        (*Blob)[*Used + i] = (WCHAR)(BYTE)Str[i];
    }
    (*Blob)[*Used + Len] = 0;
    if (OutOffset) *OutOffset = *Used;
    *Used += Len + 1;
    return TRUE;
}

/*
 * WpeBlobAddW — 追加 WCHAR 串到 NameBlob。
 */
static
BOOLEAN
WpeBlobAddW(
    _Inout_ PWCHAR* Blob,
    _Inout_ PULONG  Used,
    _Inout_ PULONG  Cap,
    _In_    PCWSTR  Str,
    _In_    ULONG   Len,
    _Out_opt_ PULONG OutOffset
    )
{
    ULONG need;

    if (Len == 0) {
        if (OutOffset) *OutOffset = 0;
        return TRUE;
    }
    need = *Used + Len + 1;
    if (!WpeBlobGrow(Blob, Cap, need)) return FALSE;
    memcpy(*Blob + *Used, Str, (SIZE_T)Len * sizeof(WCHAR));
    (*Blob)[*Used + Len] = 0;
    if (OutOffset) *OutOffset = *Used;
    *Used += Len + 1;
    return TRUE;
}

/**************************************************/
/*             导入解析                             */
/**************************************************/

/*
 * WpepRvaToFileOffset — RVA → 文件偏移（节表换算，不依赖 IsMemoryMode）。
 * 校验 reader（文件模式）读取磁盘 IAT/INT 槽时使用：内存模式 IocpRvaToOffset
 * 恒等返回 RVA，而文件 reader 需要的 offset 语义 = 文件偏移，故独立换算。
 */
static
BOOLEAN
WpepRvaToFileOffset(
    _In_ const PE_PARSER_CONTEXT* Ctx,
    _In_ ULONG Rva,
    _Out_ PULONG Offset
    )
{
    ULONG i;
    ULONG64 rva = Rva;

    if (!Ctx || !Offset) return FALSE;
    for (i = 0; i < Ctx->RawSectionCount; i++) {
        const IMAGE_SECTION_HEADER* sec = &Ctx->RawSections[i];
        ULONG64 vaEnd = (ULONG64)sec->VirtualAddress +
                        (((ULONG64)sec->Misc.VirtualSize > sec->SizeOfRawData) ?
                          (ULONG64)sec->Misc.VirtualSize : (ULONG64)sec->SizeOfRawData);
        if (rva >= sec->VirtualAddress && rva < vaEnd) {
            ULONG delta = (ULONG)(rva - sec->VirtualAddress);
            if (delta >= sec->SizeOfRawData) return FALSE;   /* 超出文件 raw 区（BSS 等） */
            *Offset = sec->PointerToRawData + delta;
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * WpepExportNameMatches — 按名字匹配目标 DLL 导出项。
 * expDir.NameBlob 以 WCHAR 存储（WpeBlobAddA 逐字节扩宽），
 * 与从磁盘 INT 读出的 ANSI 函数名逐字节比较。
 */
static
BOOLEAN
WpepExportNameMatches(
    _In_ const PE_EXPORT_DIR* Exports,
    _In_ ULONG Index,
    _In_ PCSTR FnAnsi,
    _In_ ULONG FnLen
    )
{
    const PE_EXPORT* e;
    ULONG i;

    if (!Exports || Index >= Exports->ExportCount || !FnAnsi) return FALSE;
    e = &Exports->Exports[Index];
    if (!e->ByName || e->NameLength != FnLen) return FALSE;
    if (e->NameOffset >= Exports->NameBlobChars) return FALSE;
    for (i = 0; i < FnLen; i++) {
        if ((WCHAR)(BYTE)FnAnsi[i] != Exports->NameBlob[e->NameOffset + i]) return FALSE;
    }
    return TRUE;
}

/*
 * PepVerifyImportDllByDualReader — 常规导入表双 reader 校验回调（2026-09-07）。
 * PepParseImports 截断点（ImportVerify[0] 非 NULL）逐 DLL 调用，回调内
 * for 循环处理该 DLL 全部 INT/IAT 槽：
 *   - 函数名/序号 ← 校验 reader（文件模式）读磁盘 INT 槽（权威原始值，
 *     防内存 INT 被同时伪造）；
 *   - 期望地址 ← 目标 DLL 导出表 name/ordinal→RVA + 目标 DLL 远程基址
 *     （每 DLL 一次临时内存 ctx 解析导出目录，目标 DLL 基址经
 *     Ctx->VerifyProcess 进程模块表 PsLookupModuleInstanceByName 查找）；
 *   - 实际地址 ← 主 reader（内存模式）读内存 IAT 槽。
 * 不等即命中：填 VerifyHit（PPE_IMPORT_VERIFY_HIT）并置 *Terminated=TRUE。
 * 输入内聚于解析上下文（PE_IMPORT_VERIFY_CONTEXT 已废除）：wkd_process 取
 * Ctx->VerifyProcess，进程句柄取 Ctx->VerifyProcessHandle，均由门面注入。
 */
_Use_decl_annotations_
NTSTATUS
PepVerifyImportDllByDualReader(
    _In_ const PPE_PARSER_CONTEXT Ctx,
    _In_ const void* DllInfo,
    _In_ PCWSTR DllName,
    _Inout_ void* VerifyHit,
    _Out_ BOOLEAN* Terminated
    )
{
    const PE_IMPORT_DLL* imp = (const PE_IMPORT_DLL*)DllInfo;
    PPE_IMPORT_VERIFY_HIT hit = (PPE_IMPORT_VERIFY_HIT)VerifyHit;
    const PWKD_PROCESS proc = (const PWKD_PROCESS)Ctx->VerifyProcess;
    SIZE_T ptrSize;
    ULONG_PTR intRva, iatRva;
    ULONG_PTR dllBase = 0;
    ULONG dllSize = 0;
    PWKD_MODULE_INSTANCE inst = NULL;
    PE_PARSER_CONTEXT tmpCtx;
    PE_EXPORT_DIR expDir;
    PE_PARSE_OPTIONS opt;
    BOOLEAN hasExports = FALSE;
    ULONG i;

    if (!Ctx || !imp || !hit || !proc || !Terminated) return STATUS_INVALID_PARAMETER;
    *Terminated = FALSE;

    /* 校验 reader 缺位（门面未安装文件 reader）→ 整表跳过, 不构成命中 */
    if (Ctx->VerifyReader.Mode != PeReader_File) return STATUS_SUCCESS;

    intRva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
    iatRva = imp->FirstThunk;
    if (intRva == 0 || iatRva == 0) return STATUS_SUCCESS;
    ptrSize = Ctx->Info.Amd64 ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32);

    /* 目标 DLL 基址（期望地址基准源）：进程模块表按名定位, 未加载/磁盘视图
     * （无基址）→ 整 DLL 跳过（不构成命中）。 */
    if (!NT_SUCCESS(PsLookupModuleInstanceByName(proc, DllName, &inst)) ||
        inst->ImageBase == NULL || !inst->Module ||
        inst->Module->SizeOfImage == 0) {
        return STATUS_SUCCESS;
    }
    dllBase = (ULONG_PTR)inst->ImageBase;
    dllSize = (ULONG)inst->Module->SizeOfImage;

    /* 目标 DLL 导出目录解析（每 DLL 一次）：临时内存模式 ctx */
    RtlZeroMemory(&tmpCtx, sizeof(tmpCtx));
    opt = IocDefaultPeParseOptions();
    opt.ComputeSectionEntropy = FALSE;
    opt.CollectAnomalies = FALSE;
    opt.DetectOverlay = FALSE;
    opt.VerifyChecksum = FALSE;
    if (NT_SUCCESS(PeParseMemoryEx(&tmpCtx, Ctx->VerifyProcessHandle, dllBase,
                                   dllSize, &opt))) {
        RtlZeroMemory(&expDir, sizeof(expDir));
        if (NT_SUCCESS(WpeParseExports(&tmpCtx, &expDir))) {
            hasExports = TRUE;
        }
    }

    for (i = 0; i < IMAGE_MAX_IMPORTS_PER_DLL; i++) {
        ULONGLONG fileIntVal = 0;      /* 文件 INT 槽（权威原始值） */
        ULONGLONG memIatVal = 0;       /* 内存 IAT 槽（实际地址） */
        ULONG_PTR intSlotRva = intRva + (ULONG_PTR)i * ptrSize;
        ULONG_PTR iatSlotRva = iatRva + (ULONG_PTR)i * ptrSize;
        ULONG intOff;
        CHAR fnAnsi[PE_MAX_FUNCTION_NAME + 1];
        ULONG fnLen = 0;
        USHORT ordinal = 0;
        BOOLEAN byOrdinal = FALSE;
        ULONG_PTR expected = 0;
        BOOLEAN matched = FALSE;
        ULONG k;

        /* 文件 INT 槽（文件偏移换算后经校验 reader 读取） */
        if (!WpepRvaToFileOffset(Ctx, (ULONG)intSlotRva, &intOff)) break;
        if (!IocpReaderReadBytes((PPE_READER)&Ctx->VerifyReader, intOff,
                                 &fileIntVal, ptrSize)) break;
        if (fileIntVal == 0) break;    /* 终止符 */

        /* 判定 ordinal / name（对齐 WpepParseImportThunks 语义） */
        if (Ctx->Info.Amd64) {
            if (fileIntVal & IMAGE_ORDINAL_FLAG64) {
                byOrdinal = TRUE;
                ordinal = (USHORT)(fileIntVal & 0xFFFF);
            } else {
                ULONG nameFileOff;
                USHORT hint = 0;
                if (!WpepRvaToFileOffset(Ctx, (ULONG)fileIntVal, &nameFileOff)) continue;
                if (!IocpReaderReadBytes((PPE_READER)&Ctx->VerifyReader,
                                         nameFileOff, &hint, sizeof(hint))) continue;
                if (!IocpReaderReadString((PPE_READER)&Ctx->VerifyReader,
                                          nameFileOff + 2, PE_MAX_FUNCTION_NAME,
                                          fnAnsi, sizeof(fnAnsi), &fnLen)) continue;
            }
        } else {
            if (fileIntVal & IMAGE_ORDINAL_FLAG32) {
                byOrdinal = TRUE;
                ordinal = (USHORT)(fileIntVal & 0xFFFF);
            } else {
                ULONG nameFileOff;
                USHORT hint = 0;
                if (!WpepRvaToFileOffset(Ctx, (ULONG)fileIntVal, &nameFileOff)) continue;
                if (!IocpReaderReadBytes((PPE_READER)&Ctx->VerifyReader,
                                         nameFileOff, &hint, sizeof(hint))) continue;
                if (!IocpReaderReadString((PPE_READER)&Ctx->VerifyReader,
                                          nameFileOff + 2, PE_MAX_FUNCTION_NAME,
                                          fnAnsi, sizeof(fnAnsi), &fnLen)) continue;
            }
        }

        /* 期望地址 = 目标 DLL 导出表 name/ordinal→RVA + 远程基址 */
        if (hasExports) {
            for (k = 0; k < expDir.ExportCount; k++) {
                const PE_EXPORT* e = &expDir.Exports[k];
                if (byOrdinal) {
                    if (e->Ordinal == ordinal && e->Rva != 0) {
                        expected = dllBase + (ULONG_PTR)e->Rva;
                        matched = TRUE;
                        break;
                    }
                } else if (WpepExportNameMatches(&expDir, k, fnAnsi, fnLen)) {
                    expected = dllBase + (ULONG_PTR)e->Rva;
                    matched = TRUE;
                    break;
                }
            }
        }
        if (!matched) continue;   /* 目标导出未命中 → 跳过该槽（不构成命中） */

        /* 实际地址 = 主 reader（内存模式, RVA 恒等）读内存 IAT 槽 */
        if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, iatSlotRva,
                                 &memIatVal, ptrSize)) break;

        if (memIatVal != (ULONGLONG)expected) {
            /* 命中 */
            hit->Found = TRUE;
            hit->ExpectedAddress = expected;
            hit->ActualAddress = (ULONG_PTR)memIatVal;
            hit->Ordinal = byOrdinal ? ordinal : 0;
            if (DllName) {
                wcsncpy_s(hit->DllName, PE_MAX_DLL_NAME, DllName, _TRUNCATE);
            }
            if (!byOrdinal && fnLen > 0) {
                ULONG copyLen = min(fnLen, (ULONG)(PE_MAX_FUNCTION_NAME - 1));
                memcpy(hit->FuncName, fnAnsi, copyLen);
                hit->FuncName[copyLen] = 0;
            }
            *Terminated = TRUE;
            break;
        }
    }

    if (hasExports) {
        WpeExportsFree(&expDir);
        WpeResetParseContext(&tmpCtx);
    }
    return STATUS_SUCCESS;
}

/*
 * WpepParseImportThunks — INT/IAT thunk 解析 (32/64)。
 */
static
NTSTATUS
WpepParseImportThunks(
    _In_ const PE_PARSER_CONTEXT* Context,
    _In_ ULONG IntRva,
    _In_ ULONG IatRva,
    _Inout_ PPE_IMPORT_DLL Imp,
    _Inout_ PWCHAR*  Blob,
    _Inout_ PULONG Used,
    _Inout_ PULONG BlobCap
    )
{
    ULONG thunkOffset;
    SIZE_T funcCount = 0;
    ULONG iatOffset = IatRva;
    ULONG funcCap = 0;

    if (!Context || IntRva == 0 || IatRva == 0 ||
        !Imp || !Blob || !Used || !BlobCap) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!IocpRvaToOffset(Context, IntRva, &thunkOffset)) return STATUS_INVALID_IMAGE_FORMAT;   /* 无 INT 合法 */

    while (funcCount < IMAGE_MAX_IMPORTS_PER_DLL) {
        PPE_IMPORT_FUNC func = (PE_IMPORT_FUNC*)WpeVecPush(
            (void**)&Imp->Functions, &Imp->FunctionCount, &funcCap, sizeof(PE_IMPORT_FUNC));
        if (func == NULL) return FALSE;
        RtlZeroMemory(func, sizeof(PE_IMPORT_FUNC));
        func->IatRva = iatOffset;

        if (Context->Info.Amd64) {
            PIMAGE_THUNK_DATA64 thunk = NULL;
            if (!IocpReaderReadBytes(&Context->Reader, thunkOffset, &thunk, sizeof(ULONG64)) || 
                *(PULONG64)thunk == 0) {
                Imp->FunctionCount--;   /* 回退空槽 */
                break;
            }

            /* 判断 - 按序号/名称导入??? */
            if (*(PULONG64)thunk & IMAGE_ORDINAL_FLAG64) {
                func->ByOrdinal = TRUE;
                func->Ordinal = (USHORT)(thunk->u1.Ordinal & 0xFFFF);
            } else if ((*(PULONG64)thunk & 0xFFFFFFFF00000000ULL) != 0) {
                /* 非 ordinal 但高位非零 — 无效, 跳过 */
            } else {
                ULONG nameOffset;
                if (IocpRvaToOffset(Context, thunk->u1.AddressOfData, &nameOffset)) {
                    PIMAGE_IMPORT_BY_NAME importName;
                    if (IocpReaderReadBytes(&Context->Reader, nameOffset, &importName, sizeof(ULONG))) {
                        CHAR nameBuf[PE_MAX_FUNCTION_NAME + 1];
                        ULONG nameLen = 0;
                        func->Hint = importName->Hint;
                        if (IocpReaderReadString(&Context->Reader, importName->Name, PE_MAX_FUNCTION_NAME,
                                                nameBuf, sizeof(nameBuf), &nameLen)) {
                            if (WpeBlobAddA(Blob, Used, BlobCap, nameBuf, nameLen, &func->NameOffset)) {
                                func->NameLength = nameLen;
                            }
                        }
                    }
                }
            }
            thunkOffset += sizeof(IMAGE_THUNK_DATA64);
            iatOffset += sizeof(IMAGE_THUNK_DATA64);
        } else {
            PIMAGE_THUNK_DATA32 thunk = NULL;
            if (!IocpReaderReadBytes(&Context->Reader, thunkOffset, &thunk, sizeof(ULONG)) ||
                *(PULONG32)thunk == 0) {
                Imp->FunctionCount--;
                break;
            }
            
            if (*(PULONG32)thunk & IMAGE_ORDINAL_FLAG32) {
                func->ByOrdinal = TRUE;
                func->Ordinal = (USHORT)(thunk->u1.Ordinal & 0xFFFF);
            } else {
                ULONG nameOffset;
                if (IocpRvaToOffset(Context, thunk, &nameOffset)) {
                    PIMAGE_IMPORT_BY_NAME importName;
                    if (IocpReaderReadBytes(&Context->Reader, nameOffset, &importName, sizeof(USHORT))) {
                        CHAR nameBuf[PE_MAX_FUNCTION_NAME + 1];
                        ULONG nameLen = 0;
                        func->Hint = importName->Hint;
                        if (IocpReaderReadString(&Context->Reader, importName->Name, PE_MAX_FUNCTION_NAME,
                                                nameBuf, sizeof(nameBuf), &nameLen)) {
                            if (WpeBlobAddA(Blob, Used, BlobCap, nameBuf, nameLen, &func->NameOffset)) {
                                func->NameLength = nameLen;
                            }
                        }
                    }
                }
            }
            thunkOffset += sizeof(IMAGE_THUNK_DATA32);
            iatOffset += sizeof(IMAGE_THUNK_DATA32);
        }
        funcCount++;
    }
    return TRUE;
}

_Use_decl_annotations_
NTSTATUS
PepParseImports(
    _In_ const PPE_PARSER_CONTEXT Context,
    _Out_ PPE_IMPORT_LIST Imports
    )
/*++
Routine Description:
    解析导入表 (INT/IAT 双表, ordinal/hint/name)。防环用描述符计数封顶。

Arguments:
    Ctx - 解析上下文。
    Out - 输出导入列表。

Return Value:
    NTSTATUS。
--*/
{
    PIMAGE_DATA_DIRECTORY_EX importDir;
    ULONG importOffset;
    ULONG dllCap = 0;
    ULONG blobCap = 0;

    if (!Context || !Context->Parsed || !Imports) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Imports, sizeof(PE_IMPORT_LIST));

    importDir = &Context->Info.DataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir->Present || importDir->Rva == 0 ||
        !IocpRvaToOffset(Context, importDir->Rva, &importOffset)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    for (ULONG i = 0; i < IMAGE_MAX_IMPORT_DESCRIPTORS; i++) {
        NTSTATUS status;
        IMAGE_IMPORT_DESCRIPTOR desc;
        PE_IMPORT_DLL* imp;
        
        ULONG nameLen = 0;

        status = IocpReaderReadBytes(
                    &Context->Reader,
                    importOffset, &desc, 
                    sizeof(IMAGE_IMPORT_DESCRIPTOR)) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        if (!NT_SUCCESS(status)) return status;

        if (desc.OriginalFirstThunk == 0 && desc.FirstThunk == 0) break;   /* 终止符 */

        imp = (PE_IMPORT_DLL*)WpeVecPush((void**)&Imports->Dlls, &Imports->DllCount,
                                          &dllCap, sizeof(PE_IMPORT_DLL));
        if (imp == NULL) return STATUS_NO_MEMORY;
        RtlZeroMemory(imp, sizeof(PE_IMPORT_DLL));
        imp->OriginalFirstThunk = desc.OriginalFirstThunk;  // 导入名称表(INT) Rva
        imp->FirstThunk = desc.FirstThunk;                  // 导入地址表(IAT) Rva
        imp->IsBoundImport = (desc.TimeDateStamp != 0 && desc.TimeDateStamp != MAXULONG32);

        if (desc.Name != 0) {
            CHAR nameBuf[PE_MAX_DLL_NAME + 1];
            ULONG nameOffset;

            /* IMAGE_IMPORT_DESCRIPTOR::Name - Dll名 Rva */
            if (IocpRvaToOffset(Context, desc.Name, &nameOffset) &&
                IocpReaderReadString(&Context->Reader, nameOffset, PE_MAX_DLL_NAME,
                                    nameBuf, sizeof(nameBuf), &nameLen)) {
                if (WpeBlobAddA(&Imports->NameBlob, &Imports->NameBlobChars, &blobCap,
                                nameBuf, nameLen, &imp->NameOffset)) {
                    imp->NameLength = nameLen;
                }

                /* 已知系统 DLL 判定 (对齐 SS ParseImportsImpl L1369-1379:
                 * kernel32/user32/ntdll/advapi32 精确 + msvcr* 前缀) */
                {
                    static const char* sysDlls[] = {
                        "kernel32.dll", "user32.dll", "ntdll.dll", "advapi32.dll"
                    };

                    for (ULONG k = 0; k < RTL_NUMBER_OF(sysDlls); k++) {
                        if (_strnicmp(nameBuf, sysDlls[k], strlen(sysDlls[k])) == 0) {
                            imp->IsKnownSystem = TRUE;
                            break;
                        }
                    }

                    if (!imp->IsKnownSystem &&
                        _strnicmp(nameBuf, "msvcr", 5) == 0) {
                        imp->IsKnownSystem = TRUE;
                    }
                }
            }
        }

        {
            ULONG thunkRva = desc.OriginalFirstThunk;
            if (thunkRva == 0) thunkRva = desc.FirstThunk;
            if (thunkRva != 0) {
                if (!WpepParseImportThunks(Context, thunkRva, desc.FirstThunk, imp,
                                           &Imports->NameBlob, &Imports->NameBlobChars, &blobCap)) {
                    return STATUS_NO_MEMORY;
                }
            }
        }

        /* 导入校验回调（双 reader, 2026-09-07）：ImportVerify[0] 非 NULL 时进入校验模式。
         * 解析器在该 DLL 层截断（不展开 Functions[]，由回调内部逐函数处理），
         * 回调置 Terminated=TRUE（命中）则提前终止整个导入表。 */
        if (Context->ImportVerify[0].Callback != NULL) {
            NTSTATUS verifyStatus;
            BOOLEAN terminated = FALSE;
            PCWSTR dllWideName = NULL;
            WCHAR dllWideBuf[PE_MAX_DLL_NAME + 1];

            if (imp->NameLength > 0 && imp->NameOffset < Imports->NameBlobChars) {
                ULONG copyLen = min((ULONG)imp->NameLength, (ULONG)PE_MAX_DLL_NAME);
                for (ULONG c = 0; c < copyLen; c++) {
                    dllWideBuf[c] = (WCHAR)(BYTE)Imports->NameBlob[imp->NameOffset + c];
                }
                dllWideBuf[copyLen] = 0;
                dllWideName = dllWideBuf;
            }

            verifyStatus = Context->ImportVerify[0].Callback(
                                Context, imp, dllWideName,
                                Context->ImportVerify[0].Context, &terminated);
            if (terminated) return STATUS_SUCCESS;   /* 命中：提前终止 */
            if (!NT_SUCCESS(verifyStatus)) return verifyStatus;
        }

        importOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    return STATUS_SUCCESS;
}

VOID
WpeImportsFree(
    _Inout_ PPE_IMPORT_LIST List
    )
/*++
Routine Description:
    释放导入列表。

Return Value:
    无。
--*/
{
    ULONG i;

    if (List == NULL) return;
    for (i = 0; i < List->DllCount; i++) {
        free(List->Dlls[i].Functions);
    }
    free(List->Dlls);
    free(List->NameBlob);
    RtlZeroMemory(List, sizeof(*List));
}

/**************************************************/
/*             导出解析                             */
/**************************************************/

NTSTATUS
WpeParseExports(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_EXPORT_DIR          Out
    )
/*++
Routine Description:
    解析导出表 (EAT/NPT/Ordinal 三表, forwarder, 固定大小 EAT 索引)。
    对齐 SS: ordIndex 为 0-based 索引到完整 EAT, 非压缩向量。

Arguments:
    Ctx - 解析上下文。
    Out - 输出导出目录。

Return Value:
    NTSTATUS。
--*/
{
    IMAGE_DATA_DIRECTORY_EX exportDir;
    SIZE_T exportOffset;
    IMAGE_EXPORT_DIRECTORY dir;
    SIZE_T eatOffset = 0;
    SIZE_T nptOffset = 0;
    SIZE_T ordOffset = 0;
    PE_EXPORT* eat = NULL;
    ULONG exportCap = 0;
    ULONG blobCap = 0;
    ULONG i;

    if (Ctx == NULL || !Ctx->Parsed || Out == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));

    exportDir = Ctx->Info.DataDirectories[PE_DD_EXPORT];
    if (!exportDir.Present || exportDir.Rva == 0) return STATUS_SUCCESS;

    if (!IocpRvaToOffset(Ctx, exportDir.Rva, &exportOffset)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, exportOffset, &dir, sizeof(dir))) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    Out->OrdinalBase = dir.Base;
    Out->NumberOfFunctions = dir.NumberOfFunctions;
    Out->NumberOfNames = dir.NumberOfNames;

    if (dir.Name != 0) {
        SIZE_T nameOffset;
        if (IocpRvaToOffset(Ctx, dir.Name, &nameOffset)) {
            CHAR nameBuf[PE_MAX_DLL_NAME + 1];
            ULONG nameLen = 0;
            if (IocpReaderReadString(&Ctx->Reader, nameOffset, PE_MAX_DLL_NAME,
                                    nameBuf, sizeof(nameBuf), &nameLen)) {
                if (WpeBlobAddA(&Out->NameBlob, &Out->NameBlobChars, &blobCap,
                                nameBuf, nameLen, &Out->DllNameOffset)) {
                    Out->DllNameLength = nameLen;
                }
            }
        }
    }

    if (dir.NumberOfFunctions > PE_MAX_EXPORTS) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (!IocpRvaToOffset(Ctx, dir.AddressOfFunctions, &eatOffset)) {
        return STATUS_SUCCESS;   /* 无 EAT */
    }
    if (dir.AddressOfNames != 0) (void)IocpRvaToOffset(Ctx, dir.AddressOfNames, &nptOffset);
    if (dir.AddressOfNameOrdinals != 0) (void)IocpRvaToOffset(Ctx, dir.AddressOfNameOrdinals, &ordOffset);

    eat = (PE_EXPORT*)calloc(dir.NumberOfFunctions, sizeof(PE_EXPORT));
    if (dir.NumberOfFunctions > 0 && eat == NULL) return STATUS_NO_MEMORY;

    for (i = 0; i < dir.NumberOfFunctions; i++) {
        ULONG funcRva;

        eat[i].Ordinal = dir.Base + i;
        if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader,
                              eatOffset + (SIZE_T)i * 4, &funcRva, sizeof(ULONG))) continue;
        if (funcRva == 0) continue;   /* 空槽 */
        eat[i].Rva = funcRva;

        /* forwarder: RVA 落在导出目录范围内 */
        {
            ULONG64 exportDirEnd = (ULONG64)exportDir.Rva + (ULONG64)exportDir.Size;
            if ((ULONG64)funcRva >= exportDir.Rva && (ULONG64)funcRva < exportDirEnd) {
                SIZE_T fwdOffset;
                eat[i].IsForwarder = TRUE;
                if (IocpRvaToOffset(Ctx, funcRva, &fwdOffset)) {
                    CHAR fwdBuf[PE_MAX_DLL_NAME + 1];
                    ULONG fwdLen = 0;
                    if (IocpReaderReadString(&Ctx->Reader, fwdOffset, PE_MAX_DLL_NAME,
                                            fwdBuf, sizeof(fwdBuf), &fwdLen)) {
                        if (WpeBlobAddA(&Out->NameBlob, &Out->NameBlobChars, &blobCap,
                                        fwdBuf, fwdLen, &eat[i].ForwarderOffset)) {
                            eat[i].ForwarderLength = fwdLen;
                        }
                    }
                }
            }
        }
    }

    /* 用完整 EAT 索引匹配导出名 */
    if (nptOffset != 0 && ordOffset != 0 && dir.NumberOfNames > 0) {
        for (i = 0; i < dir.NumberOfNames && i < PE_MAX_EXPORTS; i++) {
            ULONG nameRva;
            USHORT ordIndex;
            SIZE_T nameOffset;

            if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader,
                                  nptOffset + (SIZE_T)i * 4, &nameRva, sizeof(ULONG))) continue;
            if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader,
                                  ordOffset + (SIZE_T)i * 2, &ordIndex, sizeof(USHORT))) continue;
            if ((ULONG)ordIndex >= dir.NumberOfFunctions) continue;

            if (!IocpRvaToOffset(Ctx, nameRva, &nameOffset)) continue;
            {
                CHAR nameBuf[PE_MAX_FUNCTION_NAME + 1];
                ULONG nameLen = 0;
                if (IocpReaderReadString(&Ctx->Reader, nameOffset, PE_MAX_FUNCTION_NAME,
                                        nameBuf, sizeof(nameBuf), &nameLen)) {
                    if (WpeBlobAddA(&Out->NameBlob, &Out->NameBlobChars, &blobCap,
                                    nameBuf, nameLen, &eat[ordIndex].NameOffset)) {
                        eat[ordIndex].NameLength = nameLen;
                        eat[ordIndex].ByName = TRUE;
                    }
                }
            }
        }
    }

    /* 剔空槽 → 输出 */
    for (i = 0; i < dir.NumberOfFunctions; i++) {
        if (eat[i].Rva != 0) {
            PE_EXPORT* dst = (PE_EXPORT*)WpeVecPush((void**)&Out->Exports, &Out->ExportCount,
                                                      &exportCap, sizeof(PE_EXPORT));
            if (dst == NULL) {
                free(eat);
                return STATUS_NO_MEMORY;
            }
            *dst = eat[i];
            /* 仅序号/空名导出 (非 forwarder) 可疑 — 对齐 SS ParseExportedFunction:
             * func.name.empty() && !func.isForwarded → isSuspicious */
            dst->IsSuspicious = (eat[i].NameLength == 0 && !eat[i].IsForwarder);
        }
    }

    free(eat);
    return STATUS_SUCCESS;
}

VOID
WpeExportsFree(
    _Inout_ PPE_EXPORT_DIR Out
    )
/*++
Routine Description:
    释放导出目录。

Return Value:
    无。
--*/
{
    if (Out == NULL) return;
    free(Out->Exports);
    free(Out->NameBlob);
    RtlZeroMemory(Out, sizeof(*Out));
}

/**************************************************/
/*             TLS 解析                             */
/**************************************************/

NTSTATUS
WpeParseTls(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_TLS_INFO            Out
    )
/*++
Routine Description:
    解析 TLS 目录 (64/32, callbacks)。AddressOfCallbacks 为 VA, 减 ImageBase 得 RVA。

Arguments:
    Ctx - 解析上下文。
    Out - 输出 TLS 信息。

Return Value:
    NTSTATUS。
--*/
{
    IMAGE_DATA_DIRECTORY_EX tlsDir;
    SIZE_T tlsOffset;
    ULONG64 vaBase;

    if (Ctx == NULL || !Ctx->Parsed || Out == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));

    tlsDir = Ctx->Info.DataDirectories[PE_DD_TLS];
    if (!tlsDir.Present || tlsDir.Rva == 0) return STATUS_SUCCESS;
    if (!IocpRvaToOffset(Ctx, tlsDir.Rva, &tlsOffset)) return STATUS_INVALID_IMAGE_FORMAT;

    /* VA 基准: 内存模式=实际模块基址 (ASLR 后 AddressOfCallbacks 是运行时 VA),
     * 文件模式=首选 ImageBase。 */
    vaBase = Ctx->IsMemoryMode ? (ULONG64)Ctx->Reader.BaseAddress : Ctx->Info.ImageBase;

    if (Ctx->Info.Amd64) {
        IMAGE_TLS_DIRECTORY64 tls;
        if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, tlsOffset, &tls, sizeof(tls))) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        Out->StartAddressOfRawData = tls.StartAddressOfRawData;
        Out->EndAddressOfRawData = tls.EndAddressOfRawData;
        Out->AddressOfIndex = tls.AddressOfIndex;
        Out->AddressOfCallbacks = tls.AddressOfCallBacks;
        Out->SizeOfZeroFill = tls.SizeOfZeroFill;
        Out->Characteristics = tls.Characteristics;

        if (tls.AddressOfCallBacks != 0 && tls.AddressOfCallBacks >= vaBase) {
            ULONG64 callbacksRva = tls.AddressOfCallBacks - vaBase;
            if (callbacksRva <= 0xFFFFFFFFULL) {
                SIZE_T cbOffset;
                SIZE_T offset;
                if (IocpRvaToOffset(Ctx, (ULONG)callbacksRva, &cbOffset)) {
                    offset = cbOffset;
                    while (Out->CallbackCount < PE_MAX_TLS_CALLBACKS) {
                        ULONG64 callback;
                        if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, offset, &callback, sizeof(ULONG64)) ||
                            callback == 0) break;
                        Out->Callbacks[Out->CallbackCount] = callback;
                        /* RVA 视图: VA - vaBase (异常值兜底保留原值), 对齐 SS ParseTLSCallbacksImpl */
                        Out->CallbacksRva[Out->CallbackCount] =
                            (callback >= vaBase) ? (callback - vaBase) : callback;
                        Out->CallbackCount++;
                        offset += 8;
                    }
                }
            }
        }
    } else {
        IMAGE_TLS_DIRECTORY32 tls;
        if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, tlsOffset, &tls, sizeof(tls))) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        Out->StartAddressOfRawData = tls.StartAddressOfRawData;
        Out->EndAddressOfRawData = tls.EndAddressOfRawData;
        Out->AddressOfIndex = tls.AddressOfIndex;
        Out->AddressOfCallbacks = tls.AddressOfCallBacks;
        Out->SizeOfZeroFill = tls.SizeOfZeroFill;
        Out->Characteristics = tls.Characteristics;

        if (tls.AddressOfCallBacks != 0 &&
            tls.AddressOfCallBacks >= (ULONG)vaBase) {
            ULONG callbacksRva = tls.AddressOfCallBacks - (ULONG)vaBase;
            SIZE_T cbOffset;
            SIZE_T offset;
            if (IocpRvaToOffset(Ctx, callbacksRva, &cbOffset)) {
                offset = cbOffset;
                while (Out->CallbackCount < PE_MAX_TLS_CALLBACKS) {
                    ULONG callback;
                    if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, offset, &callback, sizeof(ULONG)) ||
                        callback == 0) break;
                    Out->Callbacks[Out->CallbackCount] = callback;
                    Out->CallbacksRva[Out->CallbackCount] =
                        ((ULONG64)callback >= vaBase) ? ((ULONG64)callback - vaBase) : callback;
                    Out->CallbackCount++;
                    offset += 4;
                }
            }
        }
    }

    return STATUS_SUCCESS;
}

VOID
WpeTlsFree(
    _Inout_ PPE_TLS_INFO Out
    )
/*++
Routine Description:
    释放 TLS 信息 (定长, 仅清零)。

Return Value:
    无。
--*/
{
    if (Out) RtlZeroMemory(Out, sizeof(*Out));
}

/**************************************************/
/*             重定位解析                           */
/**************************************************/

NTSTATUS
WpeParseRelocations(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_RELOCATION_LIST     Out
    )
/*++
Routine Description:
    解析重定位表 (块循环 + visited 防环 + 计数封顶)。

Arguments:
    Ctx - 解析上下文。
    Out - 输出重定位列表。

Return Value:
    NTSTATUS。
--*/
{
    IMAGE_DATA_DIRECTORY_EX relocDir;
    SIZE_T relocOffset;
    SIZE_T offset;
    SIZE_T endOffset;
    ULONG blockCount = 0;
    ULONG totalEntries = 0;
    SIZE_T visited[4096];
    ULONG visitedCount = 0;
    ULONG blockCap = 0;

    if (Ctx == NULL || !Ctx->Parsed || Out == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));

    relocDir = Ctx->Info.DataDirectories[PE_DD_BASERELOC];
    if (!relocDir.Present || relocDir.Rva == 0 || relocDir.Size == 0) return STATUS_SUCCESS;
    if (!IocpRvaToOffset(Ctx, relocDir.Rva, &relocOffset)) return STATUS_INVALID_IMAGE_FORMAT;
    if (!IocpAddSizeSafe(relocOffset, relocDir.Size, &endOffset)) return STATUS_INVALID_IMAGE_FORMAT;

    offset = relocOffset;
    while (offset < endOffset && blockCount < PE_MAX_RELOCATION_BLOCKS) {
        IMAGE_BASE_RELOCATION block;
        PE_RELOCATION_BLOCK* rb;
        SIZE_T numEntries;
        SIZE_T entryOffset;
        SIZE_T i;
        ULONG k;
        BOOLEAN loop = FALSE;

        for (k = 0; k < visitedCount; k++) {
            if (visited[k] == offset) {
                loop = TRUE;
                break;
            }
        }
        if (loop) break;
        if (visitedCount < ARRAYSIZE(visited)) visited[visitedCount++] = offset;

        if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, offset, &block, sizeof(block))) break;
        if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
        if (block.SizeOfBlock > relocDir.Size) break;

        rb = (PE_RELOCATION_BLOCK*)WpeVecPush((void**)&Out->Blocks, &Out->BlockCount,
                                               &blockCap, sizeof(PE_RELOCATION_BLOCK));
        if (rb == NULL) return STATUS_NO_MEMORY;
        RtlZeroMemory(rb, sizeof(*rb));
        rb->PageRva = block.VirtualAddress;

        numEntries = (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        entryOffset = offset + sizeof(IMAGE_BASE_RELOCATION);

        {
            ULONG entryCap = 0;
            for (i = 0; i < numEntries && totalEntries < PE_MAX_RELOCATIONS; i++) {
                USHORT entry;
                USHORT type;
                USHORT off;
                PE_RELOCATION_ENTRY* re;

                if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader,
                                      entryOffset + i * 2, &entry, sizeof(USHORT))) break;
                type = entry >> 12;
                off = entry & 0x0FFF;
                if (type == PE_RELOC_ABSOLUTE) continue;   /* 填充 */

                re = (PE_RELOCATION_ENTRY*)WpeVecPush((void**)&rb->Entries, &rb->EntryCount,
                                                        &entryCap, sizeof(PE_RELOCATION_ENTRY));
                if (re == NULL) return STATUS_NO_MEMORY;
                /* SafeAdd: 攻击者可控 VirtualAddress + 12 位偏移防回绕 */
                if (!IocpAddU32Safe(block.VirtualAddress, (ULONG)off, &re->Rva)) {
                    rb->EntryCount--;
                    continue;
                }
                re->Type = type;
                totalEntries++;
            }
        }

        offset += block.SizeOfBlock;
        blockCount++;
    }
    return STATUS_SUCCESS;
}

VOID
WpeRelocationsFree(
    _Inout_ PPE_RELOCATION_LIST Out
    )
/*++
Routine Description:
    释放重定位列表。

Return Value:
    无。
--*/
{
    ULONG i;

    if (Out == NULL) return;
    for (i = 0; i < Out->BlockCount; i++) {
        free(Out->Blocks[i].Entries);
    }
    free(Out->Blocks);
    RtlZeroMemory(Out, sizeof(*Out));
}

/**************************************************/
/*             Debug 目录解析                       */
/**************************************************/

/*
 * WpepParseCodeViewInfo — CodeView RSDS 提取 + PDB 路径消毒。
 * 消毒: 拒 \ 或 / 开头 (UNC/SMB 认证触发), 限 1024, 剔控制字符。
 */
static
VOID
WpepParseCodeViewInfo(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  ULONG                    Offset,
    _In_  ULONG                    Size,
    _Inout_ PPE_DEBUG_INFO        Info
    )
{
    ULONG signature;

    if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, Offset, &signature, sizeof(ULONG))) return;

    if (signature == 0x53445352) {   /* "RSDS" */
        CHAR pathBuf[PE_MAX_PDB_PATH_LENGTH + 1];
        ULONG pathLen = 0;
        ULONG i;
        ULONG outIdx = 0;

        if (Size < 24) return;

        if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, Offset + 4, Info->PdbGuid, 16)) return;
        if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, Offset + 20, &Info->PdbAge, sizeof(ULONG))) return;

        if (!IocpReaderReadString(&Ctx->Reader, Offset + 24, Size - 24,
                                 pathBuf, sizeof(pathBuf), &pathLen)) {
            /* 无 NUL — 定长读 */
            ULONG copyLen = Size - 24;
            if (copyLen >= sizeof(pathBuf)) copyLen = sizeof(pathBuf) - 1;
            if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, Offset + 24, pathBuf, copyLen)) return;
            pathBuf[copyLen] = 0;
            pathLen = copyLen;
        }

        /* 拒绝对接 UNC/设备路径 */
        if (pathLen >= 1 && (pathBuf[0] == '\\' || pathBuf[0] == '/')) {
            return;
        }

        /* 剔控制字符, 限长 */
        for (i = 0; i < pathLen && outIdx < PE_MAX_PDB_PATH_LENGTH; i++) {
            UCHAR c = (UCHAR)pathBuf[i];
            if (c >= 0x20 && c != 0x7F) {
                Info->PdbPath[outIdx++] = (WCHAR)c;
            }
        }
        Info->PdbPath[outIdx] = 0;
    } else if (signature == 0x3031424E) {   /* "NB10" — 旧版 CodeView, 对齐 SS ParseDebugDirectoryImpl */
        CHAR pathBuf[PE_MAX_PDB_PATH_LENGTH + 1];
        ULONG pathLen = 0;
        ULONG i;
        ULONG outIdx = 0;

        /* NB10 布局: sig@0 + offset@4 + sig@8 + age@12 + path@16 */
        if (Size < 16) return;
        if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, Offset + 12, &Info->PdbAge, sizeof(ULONG))) return;

        if (!IocpReaderReadString(&Ctx->Reader, Offset + 16, Size - 16,
                                 pathBuf, sizeof(pathBuf), &pathLen)) {
            ULONG copyLen = Size - 16;
            if (copyLen >= sizeof(pathBuf)) copyLen = sizeof(pathBuf) - 1;
            if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, Offset + 16, pathBuf, copyLen)) return;
            pathBuf[copyLen] = 0;
            pathLen = copyLen;
        }

        /* 与 RSDS 相同的消毒: 拒 UNC/设备路径 + 剔控制字符 */
        if (pathLen >= 1 && (pathBuf[0] == '\\' || pathBuf[0] == '/')) {
            return;
        }
        for (i = 0; i < pathLen && outIdx < PE_MAX_PDB_PATH_LENGTH; i++) {
            UCHAR c = (UCHAR)pathBuf[i];
            if (c >= 0x20 && c != 0x7F) {
                Info->PdbPath[outIdx++] = (WCHAR)c;
            }
        }
        Info->PdbPath[outIdx] = 0;
    }
}

NTSTATUS
WpeParseDebugInfo(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_DEBUG_LIST          Out
    )
/*++
Routine Description:
    解析 Debug 目录 (CODEVIEW RSDS → PDB 路径 + 消毒)。

Arguments:
    Ctx - 解析上下文。
    Out - 输出 Debug 列表。

Return Value:
    NTSTATUS。
--*/
{
    IMAGE_DATA_DIRECTORY_EX debugDir;
    SIZE_T debugOffset;
    ULONG numEntries;
    ULONG i;

    if (Ctx == NULL || !Ctx->Parsed || Out == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));

    debugDir = Ctx->Info.DataDirectories[PE_DD_DEBUG];
    if (!debugDir.Present || debugDir.Rva == 0 || debugDir.Size == 0) return STATUS_SUCCESS;
    if (!IocpRvaToOffset(Ctx, debugDir.Rva, &debugOffset)) return STATUS_INVALID_IMAGE_FORMAT;

    numEntries = debugDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    if (numEntries > PE_MAX_DEBUG_ENTRIES) numEntries = PE_MAX_DEBUG_ENTRIES;

    for (i = 0; i < numEntries; i++) {
        IMAGE_DEBUG_DIRECTORY entry;
        PE_DEBUG_INFO* info;

        if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader,
                           debugOffset + (SIZE_T)i * sizeof(IMAGE_DEBUG_DIRECTORY),
                           &entry, sizeof(entry))) break;

        info = &Out->Entries[Out->EntryCount];
        RtlZeroMemory(info, sizeof(*info));
        info->Type = entry.Type;
        info->Timestamp = entry.TimeDateStamp;
        info->MajorVersion = entry.MajorVersion;
        info->MinorVersion = entry.MinorVersion;
        info->SizeOfData = entry.SizeOfData;
        info->AddressOfRawData = entry.AddressOfRawData;
        info->PointerToRawData = entry.PointerToRawData;

        if (entry.Type == PE_DBT_CODEVIEW && entry.PointerToRawData != 0) {
            WpepParseCodeViewInfo(Ctx, entry.PointerToRawData, entry.SizeOfData, info);
        }
        Out->EntryCount++;
    }
    return STATUS_SUCCESS;
}

VOID
WpeDebugInfoFree(
    _Inout_ PPE_DEBUG_LIST Out
    )
/*++
Routine Description:
    释放 Debug 列表 (定长, 仅清零)。

Return Value:
    无。
--*/
{
    if (Out) RtlZeroMemory(Out, sizeof(*Out));
}

/**************************************************/
/*             Rich 头解析                          */
/**************************************************/

/*
 * WpepRichProductName — 编译器 ProductId 名映射 (对齐 SS ParseRichHeaderImpl L1931-1950)。
 * 未知 ProductId → NULL (调用方回退 "ProdIdN")。
 */
static
const CHAR*
WpepRichProductName(
    _In_ USHORT ProductId
    )
{
    switch (ProductId) {
    case 1:   return "Import0";
    case 4:   return "Linker510";
    case 5:   return "Cvtomf510";
    case 6:   return "Linker600";
    case 10:  return "Linker622";
    case 19:  return "Linker700";
    case 40:  return "Linker710";
    case 45:  return "Linker800";
    case 83:  return "Linker900";
    case 93:  return "Linker1000";
    case 170: return "Linker1100";
    case 199: return "Linker1200";
    case 219: return "Linker1210";
    case 258: return "Linker1400";
    default:  return NULL;
    }
}

NTSTATUS
WpeParseRichHeader(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_RICH_HEADER_INFO    Out
    )
/*++
Routine Description:
    解析 Rich 头。4KB 反 DoS 搜索窗口 (e_lfanew 可被设 256MB 致 CPU 停顿)。
    反向找 "Rich" → XOR key → 反向找 "DanS" → XOR 解析条目。

Arguments:
    Ctx - 解析上下文。
    Out - 输出 Rich 头信息。

Return Value:
    NTSTATUS。
--*/
{
    SIZE_T searchEnd;
    SIZE_T searchStart;
    ULONG64 i;

    if (Ctx == NULL || !Ctx->Parsed || Out == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));

    if (Ctx->NtHeaderOffset < 8) return STATUS_SUCCESS;

    /* 搜索窗口: DOS 头之后 4KB 内 */
    searchEnd = Ctx->NtHeaderOffset;
    {
        SIZE_T cap = sizeof(IMAGE_DOS_HEADER) + 4096;
        if (searchEnd > cap) searchEnd = cap;
    }
    searchStart = sizeof(IMAGE_DOS_HEADER);

    {
        ULONG64 richOffset = 0;
        for (i = searchEnd; i >= searchStart + 4; i--) {
            ULONG val;
            if (IocpReaderReadBytes((PPE_READER)&Ctx->Reader, i - 4, &val, sizeof(ULONG)) &&
                val == PE_RICH_RICH_SIGNATURE) {
                richOffset = i - 4;
                break;
            }
        }
        if (richOffset == 0) return STATUS_SUCCESS;

        {
            ULONG xorKey;
            if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, richOffset + 4, &xorKey, sizeof(ULONG))) {
                return STATUS_SUCCESS;
            }
            Out->Present = TRUE;
            Out->Checksum = xorKey;

            /* 反向找 "DanS" (XOR'd) */
            {
                ULONG64 dansOffset = 0;
                for (i = richOffset; i >= searchStart + 4; i -= 4) {
                    ULONG val;
                    if (IocpReaderReadBytes((PPE_READER)&Ctx->Reader, i - 4, &val, sizeof(ULONG)) &&
                        (val ^ xorKey) == PE_RICH_DANS_SIGNATURE) {
                        dansOffset = i - 4;
                        break;
                    }
                }
                if (dansOffset == 0) {
                    Out->Present = FALSE;
                    return STATUS_SUCCESS;
                }
                Out->Offset = dansOffset;
                Out->Size = richOffset + 8 - dansOffset;

                /* 解析条目 */
                {
                    ULONG64 entryOffset = dansOffset + 16;   /* DanS + 3 填充 DWORD */
                    while (entryOffset < richOffset && Out->EntryCount < PE_MAX_RICH_ENTRIES) {
                        ULONG id, count;
                        PE_RICH_ENTRY* re;

                        if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, entryOffset, &id, sizeof(ULONG)) ||
                            !IocpReaderReadBytes((PPE_READER)&Ctx->Reader, entryOffset + 4, &count, sizeof(ULONG))) {
                            break;
                        }
                        id ^= xorKey;
                        count ^= xorKey;
                        if (id == 0 && count == 0) break;

                        re = &Out->Entries[Out->EntryCount];
                        re->BuildId = (USHORT)(id >> 16);
                        re->ProductId = (USHORT)(id & 0xFFFF);
                        re->UseCount = count;
                        /* 编译器名映射 (对齐 SS): 已知 → 名称, 未知 → "ProdIdN" */
                        {
                            const CHAR* pn = WpepRichProductName(re->ProductId);
                            if (pn != NULL) {
                                strncpy_s(re->ProductName, sizeof(re->ProductName), pn, _TRUNCATE);
                            } else {
                                sprintf_s(re->ProductName, sizeof(re->ProductName),
                                          "ProdId%u", (UINT)re->ProductId);
                            }
                        }
                        Out->EntryCount++;
                        entryOffset += 8;
                    }
                }

                /* XOR 校验和验证 (对齐 SS ParseRichHeaderImpl L1961-1981):
                 * computed = dansOffset(初始) + rotl(DOS 头字节,i)[跳过 e_lfanew 0x3C-0x40]
                 *          + rotl(compId, count&0x1F), compId = (ProductId<<16)|BuildId */
                {
                    ULONG computedChecksum = (ULONG)dansOffset;
                    BYTE dosBuf[4096];
                    SIZE_T dosLen = dansOffset;
                    SIZE_T k;
                    if (dosLen > sizeof(dosBuf)) dosLen = sizeof(dosBuf);
                    if (IocpReaderReadBytes((PPE_READER)&Ctx->Reader, 0, dosBuf, dosLen)) {
                        for (k = 0; k < dosLen; k++) {
                            if (k >= 0x3C && k < 0x40) continue;   /* 跳过 e_lfanew */
                            computedChecksum += _rotl((ULONG)dosBuf[k], (INT)k);
                        }
                    }
                    for (k = 0; k < Out->EntryCount; k++) {
                        ULONG compId = ((ULONG)Out->Entries[k].ProductId << 16) | Out->Entries[k].BuildId;
                        computedChecksum += _rotl(compId, (INT)(Out->Entries[k].UseCount & 0x1F));
                    }
                    Out->Valid = (computedChecksum == xorKey);
                    if (!Out->Valid) Out->IsPossibleFake = TRUE;
                }
            }
        }
    }
    return STATUS_SUCCESS;
}

VOID
WpeRichHeaderFree(
    _Inout_ PPE_RICH_HEADER_INFO Out
    )
/*++
Routine Description:
    释放 Rich 头信息 (定长, 仅清零)。

Return Value:
    无。
--*/
{
    if (Out) RtlZeroMemory(Out, sizeof(*Out));
}

/**************************************************/
/*             延迟导入解析                         */
/**************************************************/

/*
 * PepVerifyDelayImportDllByDualReader — 延迟导入表双 reader 校验回调（2026-09-07）。
 * WpeParseDelayImports 截断点（ImportVerify[1] 非 NULL）逐 DLL 调用。语义对齐
 * 常规导入校验，另含延迟槽三态判定（防误报关键区）：
 *   - 槽值 0 → 未绑定（零值）, 跳过；
 *   - 槽值落在主模块映像内 → 未绑定 thunk/helper 落点, 跳过；
 *   - 已绑定 → 期望地址（目标 DLL 导出表 + 远程基址）比对, 不等即命中。
 * 函数名/序号 ← 校验 reader（文件模式）读磁盘 INT 槽（权威原始值）；
 * 实际槽值 ← 主 reader（内存模式）读内存 IAT 槽（IatRva + index*ptrSize）。
 * 输入内聚于解析上下文：目标 DLL 基址经 Ctx->VerifyProcess 模块表查找，
 * 主模块映像域经 PsGetMainModuleInstance 派生；句柄取 Ctx->VerifyProcessHandle。
 */
_Use_decl_annotations_
NTSTATUS
PepVerifyDelayImportDllByDualReader(
    _In_ const PPE_PARSER_CONTEXT Ctx,
    _In_ const void* DllInfo,
    _In_ PCWSTR DllName,
    _Inout_ void* VerifyHit,
    _Out_ BOOLEAN* Terminated
    )
{
    const PE_DELAY_IMPORT_DLL* imp = (const PE_DELAY_IMPORT_DLL*)DllInfo;
    PPE_IMPORT_VERIFY_HIT hit = (PPE_IMPORT_VERIFY_HIT)VerifyHit;
    const PWKD_PROCESS proc = (const PWKD_PROCESS)Ctx->VerifyProcess;
    SIZE_T ptrSize;
    ULONG_PTR intRva, iatRva;
    ULONG_PTR dllBase = 0;
    ULONG dllSize = 0;
    ULONG_PTR remoteBase = 0;
    ULONG remoteSize = 0;
    ULONG_PTR imageEnd;
    PWKD_MODULE_INSTANCE inst = NULL;
    PWKD_MODULE_INSTANCE mainInst = NULL;
    PE_PARSER_CONTEXT tmpCtx;
    PE_EXPORT_DIR expDir;
    PE_PARSE_OPTIONS opt;
    BOOLEAN hasExports = FALSE;
    ULONG i;

    if (!Ctx || !imp || !hit || !proc || !Terminated) return STATUS_INVALID_PARAMETER;
    *Terminated = FALSE;

    if (Ctx->VerifyReader.Mode != PeReader_File) return STATUS_SUCCESS;

    intRva = imp->IntRva;
    iatRva = imp->IatRva;
    if (intRva == 0 || iatRva == 0 || imp->FunctionCount == 0) return STATUS_SUCCESS;
    ptrSize = Ctx->Info.Amd64 ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32);

    /* 目标 DLL 基址（期望地址基准源）：模块表按名定位, 未加载/无基址→跳过 */
    if (!DllName || !DllName[0]) return STATUS_SUCCESS;
    if (!NT_SUCCESS(PsLookupModuleInstanceByName(proc, DllName, &inst)) ||
        inst->ImageBase == NULL || !inst->Module ||
        inst->Module->SizeOfImage == 0) {
        return STATUS_SUCCESS;
    }
    dllBase = (ULONG_PTR)inst->ImageBase;
    dllSize = (ULONG)inst->Module->SizeOfImage;

    /* 主模块映像域（延迟 thunk/helper 落点判定） */
    if (NT_SUCCESS(PsGetMainModuleInstance(proc, &mainInst)) &&
        mainInst->ImageBase != NULL && mainInst->Module) {
        remoteBase = (ULONG_PTR)mainInst->ImageBase;
        remoteSize = (ULONG)mainInst->Module->SizeOfImage;
    }
    imageEnd = remoteBase + remoteSize;

    RtlZeroMemory(&tmpCtx, sizeof(tmpCtx));
    opt = IocDefaultPeParseOptions();
    opt.ComputeSectionEntropy = FALSE;
    opt.CollectAnomalies = FALSE;
    opt.DetectOverlay = FALSE;
    opt.VerifyChecksum = FALSE;
    if (NT_SUCCESS(PeParseMemoryEx(&tmpCtx, Ctx->VerifyProcessHandle, dllBase,
                                   dllSize, &opt))) {
        RtlZeroMemory(&expDir, sizeof(expDir));
        if (NT_SUCCESS(WpeParseExports(&tmpCtx, &expDir))) {
            hasExports = TRUE;
        }
    }

    for (i = 0; i < imp->FunctionCount; i++) {
        ULONGLONG fileIntVal = 0;      /* 文件 INT 槽（权威原始值） */
        ULONGLONG memIatVal = 0;       /* 内存 IAT 槽（实际地址） */
        ULONG_PTR intSlotRva = intRva + (ULONG_PTR)i * ptrSize;
        ULONG_PTR iatSlotRva = iatRva + (ULONG_PTR)i * ptrSize;
        ULONG intOff;
        CHAR fnAnsi[PE_MAX_FUNCTION_NAME + 1];
        ULONG fnLen = 0;
        USHORT ordinal = 0;
        BOOLEAN byOrdinal = FALSE;
        ULONG_PTR expected = 0;
        BOOLEAN matched = FALSE;
        ULONG k;

        /* 实际槽值先读（三态判定的首要依据） */
        if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, iatSlotRva,
                                 &memIatVal, ptrSize)) break;
        if (memIatVal == 0) continue;                                     /* 未绑定（零值） */
        if (remoteBase != 0 && memIatVal >= remoteBase && memIatVal < imageEnd) {
            continue;                                                     /* 未绑定 thunk/helper（指向主模块内） */
        }

        /* 文件 INT 槽（权威函数名/序号） */
        if (!WpepRvaToFileOffset(Ctx, (ULONG)intSlotRva, &intOff)) break;
        if (!IocpReaderReadBytes((PPE_READER)&Ctx->VerifyReader, intOff,
                                 &fileIntVal, ptrSize)) break;
        if (fileIntVal == 0) continue;

        if (Ctx->Info.Amd64) {
            if (fileIntVal & IMAGE_ORDINAL_FLAG64) {
                byOrdinal = TRUE;
                ordinal = (USHORT)(fileIntVal & 0xFFFF);
            } else {
                ULONG nameFileOff;
                USHORT hint = 0;
                if (!WpepRvaToFileOffset(Ctx, (ULONG)fileIntVal, &nameFileOff)) continue;
                if (!IocpReaderReadBytes((PPE_READER)&Ctx->VerifyReader,
                                         nameFileOff, &hint, sizeof(hint))) continue;
                if (!IocpReaderReadString((PPE_READER)&Ctx->VerifyReader,
                                          nameFileOff + 2, PE_MAX_FUNCTION_NAME,
                                          fnAnsi, sizeof(fnAnsi), &fnLen)) continue;
            }
        } else {
            if (fileIntVal & IMAGE_ORDINAL_FLAG32) {
                byOrdinal = TRUE;
                ordinal = (USHORT)(fileIntVal & 0xFFFF);
            } else {
                ULONG nameFileOff;
                USHORT hint = 0;
                if (!WpepRvaToFileOffset(Ctx, (ULONG)fileIntVal, &nameFileOff)) continue;
                if (!IocpReaderReadBytes((PPE_READER)&Ctx->VerifyReader,
                                         nameFileOff, &hint, sizeof(hint))) continue;
                if (!IocpReaderReadString((PPE_READER)&Ctx->VerifyReader,
                                          nameFileOff + 2, PE_MAX_FUNCTION_NAME,
                                          fnAnsi, sizeof(fnAnsi), &fnLen)) continue;
            }
        }

        /* 期望地址 = 目标 DLL 导出表 + 远程基址（已绑定槽位比对） */
        if (hasExports) {
            for (k = 0; k < expDir.ExportCount; k++) {
                const PE_EXPORT* e = &expDir.Exports[k];
                if (byOrdinal) {
                    if (e->Ordinal == ordinal && e->Rva != 0) {
                        expected = dllBase + (ULONG_PTR)e->Rva;
                        matched = TRUE;
                        break;
                    }
                } else if (WpepExportNameMatches(&expDir, k, fnAnsi, fnLen)) {
                    expected = dllBase + (ULONG_PTR)e->Rva;
                    matched = TRUE;
                    break;
                }
            }
        }
        if (!matched) continue;

        if (memIatVal != (ULONGLONG)expected) {
            hit->Found = TRUE;
            hit->ExpectedAddress = expected;
            hit->ActualAddress = (ULONG_PTR)memIatVal;
            hit->Ordinal = byOrdinal ? ordinal : 0;
            if (DllName) {
                wcsncpy_s(hit->DllName, PE_MAX_DLL_NAME, DllName, _TRUNCATE);
            }
            if (!byOrdinal && fnLen > 0) {
                ULONG copyLen = min(fnLen, (ULONG)(PE_MAX_FUNCTION_NAME - 1));
                memcpy(hit->FuncName, fnAnsi, copyLen);
                hit->FuncName[copyLen] = 0;
            }
            *Terminated = TRUE;
            break;
        }
    }

    if (hasExports) {
        WpeExportsFree(&expDir);
        WpeResetParseContext(&tmpCtx);
    }
    return STATUS_SUCCESS;
}

/*
 * WpepParseDelayImportThunks — 延迟导入 INT thunk 解析 (32/64)。
 */
static
BOOLEAN
WpepParseDelayImportThunks(
    _In_ const PPE_PARSER_CONTEXT Context,
    _In_ ULONG ThunkOffset,
    _Inout_ PPE_DELAY_IMPORT_DLL DelayImports,
    _Inout_ PWCHAR* Blob,
    _Inout_ PULONG Used,
    _Inout_ PULONG BlobCap
    )
{
    ULONG offset = ThunkOffset;
    ULONG funcCount = 0;
    ULONG funcCap = 0;

    while (funcCount < IMAGE_MAX_IMPORTS_PER_DLL) {
        PE_IMPORT_FUNC* func = (PE_IMPORT_FUNC*)WpeVecPush(
            (void**)&DelayImports->Functions, &DelayImports->FunctionCount, &funcCap, sizeof(PE_IMPORT_FUNC));
        if (func == NULL) return FALSE;
        RtlZeroMemory(func, sizeof(*func));

        if (Context->Info.Amd64) {
            PIMAGE_THUNK_DATA64 thunk = NULL;
            if (!IocpReaderReadBytes(&Context->Reader, offset, &thunk, sizeof(ULONG64)) ||
                *(PULONG64)thunk == 0) {
                DelayImports->FunctionCount--;
                break;
            }
            if (*(PULONG64)thunk & IMAGE_ORDINAL_FLAG64) {
                func->ByOrdinal = TRUE;
                func->Ordinal = (USHORT)(thunk->u1.Ordinal & 0xFFFF);
            } else if ((*(PULONG64)thunk & 0xFFFFFFFF00000000ULL) == 0) {
                SIZE_T hintOff;
                if (IocpRvaToOffset(Context, (ULONG)thunk, &hintOff)) {
                    USHORT hint;
                    if (!IocpReaderReadBytes(&Context->Reader, hintOff, &hint, sizeof(USHORT))) break;
                    func->Hint = hint;
                    {
                        CHAR nameBuf[PE_MAX_FUNCTION_NAME + 1];
                        ULONG nameLen = 0;
                        if (IocpReaderReadString(&Context->Reader, hintOff + 2, PE_MAX_FUNCTION_NAME,
                                                nameBuf, sizeof(nameBuf), &nameLen)) {
                            if (WpeBlobAddA(Blob, Used, BlobCap, nameBuf, nameLen, &func->NameOffset)) {
                                func->NameLength = nameLen;
                            }
                        }
                    }
                }
            }
            offset += sizeof(IMAGE_THUNK_DATA64);
        } else {
            PIMAGE_THUNK_DATA32 thunk = NULL;
            if (!IocpReaderReadBytes(&Context->Reader, offset, &thunk, sizeof(ULONG)) ||
                *(PULONG)thunk == 0) {
                DelayImports->FunctionCount--;
                break;
            }
            if (*(PULONG64)thunk & IMAGE_ORDINAL_FLAG32) {
                func->ByOrdinal = TRUE;
                func->Ordinal = (USHORT)(thunk->u1.Ordinal & 0xFFFF);
            } else {
                SIZE_T hintOff;
                if (IocpRvaToOffset(Context, thunk, &hintOff)) {
                    USHORT hint;
                    if (!IocpReaderReadBytes(&Context->Reader, hintOff, &hint, sizeof(USHORT))) break;
                    func->Hint = hint;
                    {
                        CHAR nameBuf[PE_MAX_FUNCTION_NAME + 1];
                        ULONG nameLen = 0;
                        if (IocpReaderReadString(&Context->Reader, hintOff + 2, PE_MAX_FUNCTION_NAME,
                                                nameBuf, sizeof(nameBuf), &nameLen)) {
                            if (WpeBlobAddA(Blob, Used, BlobCap, nameBuf, nameLen, &func->NameOffset)) {
                                func->NameLength = nameLen;
                            }
                        }
                    }
                }
            }
            offset += sizeof(IMAGE_THUNK_DATA32);
        }
        funcCount++;
    }
    return TRUE;
}

NTSTATUS
WpeParseDelayImports(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_DELAY_IMPORT_LIST   Out
    )
/*++
Routine Description:
    解析延迟导入表。

Arguments:
    Ctx - 解析上下文。
    Out - 输出延迟导入列表。

Return Value:
    NTSTATUS。
--*/
{
    IMAGE_DATA_DIRECTORY_EX delayDir;
    SIZE_T delayOffset;
    SIZE_T offset;
    ULONG descriptorCount = 0;
    ULONG dllCap = 0;
    ULONG blobCap = 0;

    if (Ctx == NULL || !Ctx->Parsed || Out == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));

    delayDir = Ctx->Info.DataDirectories[PE_DD_DELAY_IMPORT];
    if (!delayDir.Present || delayDir.Rva == 0 || delayDir.Size == 0) return STATUS_SUCCESS;
    if (!IocpRvaToOffset(Ctx, delayDir.Rva, &delayOffset)) return STATUS_INVALID_IMAGE_FORMAT;

    offset = delayOffset;
    while (descriptorCount < PE_MAX_DELAY_IMPORT_DESC) {
        IMAGE_DELAYLOAD_DESCRIPTOR desc;
        PE_DELAY_IMPORT_DLL* imp;

        if (!IocpReaderReadBytes(&Ctx->Reader, offset, &desc, sizeof(IMAGE_DELAYLOAD_DESCRIPTOR))) break;
        if (desc.DllNameRVA == 0 && desc.ImportAddressTableRVA == 0 &&
            desc.ImportNameTableRVA == 0) break;   /* 终止符 */

        imp = (PE_DELAY_IMPORT_DLL*)WpeVecPush((void**)&Out->Dlls, &Out->DllCount,
                                                &dllCap, sizeof(PE_DELAY_IMPORT_DLL));
        if (imp == NULL) return STATUS_NO_MEMORY;
        RtlZeroMemory(imp, sizeof(*imp));
        imp->Attributes = desc.Attributes.AllAttributes;
        imp->ModuleHandleRva = desc.ModuleHandleRVA;
        imp->IatRva = desc.ImportAddressTableRVA;
        imp->IntRva = desc.ImportNameTableRVA;
        imp->BoundIatRva = desc.BoundImportAddressTableRVA;
        imp->UnloadIatRva = desc.UnloadInformationTableRVA;
        imp->TimeDateStamp = desc.TimeDateStamp;

        /* attrs bit0: 1=RVA 模式(现代链接器恒置), 0=VA 模式(旧格式) — 对齐 SS rvaMode 判定;
         * VA 模式下表字段是 VA, 需 VA - ImageBase → RVA 再转文件偏移 */
        {
            ULONG dllNameRva = desc.DllNameRVA;
            ULONG intRva = desc.ImportNameTableRVA;
            ULONG64 imageBase = Ctx->Info.ImageBase;

            if ((imp->Attributes & 1) == 0) {
                if (dllNameRva != 0 && (ULONG64)dllNameRva >= imageBase)
                    dllNameRva = (ULONG)((ULONG64)dllNameRva - imageBase);
                if (intRva != 0 && (ULONG64)intRva >= imageBase)
                    intRva = (ULONG)((ULONG64)intRva - imageBase);
            }

            if (dllNameRva != 0) {
                SIZE_T nameOffset;
                if (IocpRvaToOffset(Ctx, dllNameRva, &nameOffset)) {
                    CHAR nameBuf[PE_MAX_DLL_NAME + 1];
                    ULONG nameLen = 0;
                    if (IocpReaderReadString(&Ctx->Reader, nameOffset, PE_MAX_DLL_NAME,
                                            nameBuf, sizeof(nameBuf), &nameLen)) {
                        if (WpeBlobAddA(&Out->NameBlob, &Out->NameBlobChars, &blobCap,
                                        nameBuf, nameLen, &imp->NameOffset)) {
                            imp->NameLength = nameLen;
                        }
                    }
                }
            }

            if (intRva != 0) {
                SIZE_T intOffset;
                if (IocpRvaToOffset(Ctx, intRva, &intOffset)) {
                    if (!WpepParseDelayImportThunks(Ctx, intOffset, imp,
                                                    &Out->NameBlob, &Out->NameBlobChars, &blobCap)) {
                        return STATUS_NO_MEMORY;
                    }
                }
            }

            /* 延迟导入校验回调（双 reader, 2026-09-07）：ImportVerify[1] 非 NULL 时校验模式。
             * 解析器在 DLL 层截断，回调内部按三态语义逐函数处理，
             * 回调置 Terminated=TRUE（命中）则提前终止整个延迟导入表。 */
            if (Ctx->ImportVerify[1].Callback != NULL) {
                NTSTATUS verifyStatus;
                BOOLEAN terminated = FALSE;
                PCWSTR dllWideName = NULL;
                WCHAR dllWideBuf[PE_MAX_DLL_NAME + 1];

                if (imp->NameLength > 0 && imp->NameOffset < Out->NameBlobChars) {
                    ULONG copyLen = min((ULONG)imp->NameLength, (ULONG)PE_MAX_DLL_NAME);
                    for (ULONG c = 0; c < copyLen; c++) {
                        dllWideBuf[c] = (WCHAR)(BYTE)Out->NameBlob[imp->NameOffset + c];
                    }
                    dllWideBuf[copyLen] = 0;
                    dllWideName = dllWideBuf;
                }

                verifyStatus = Ctx->ImportVerify[1].Callback(
                                    Ctx, imp, dllWideName,
                                    Ctx->ImportVerify[1].Context, &terminated);
                if (terminated) return STATUS_SUCCESS;   /* 命中：提前终止 */
                if (!NT_SUCCESS(verifyStatus)) return verifyStatus;
            }
        }

        offset += sizeof(IMAGE_DELAYLOAD_DESCRIPTOR);
        descriptorCount++;
    }
    return STATUS_SUCCESS;
}

VOID
WpeDelayImportsFree(
    _Inout_ PPE_DELAY_IMPORT_LIST Out
    )
/*++
Routine Description:
    释放延迟导入列表。

Return Value:
    无。
--*/
{
    ULONG i;

    if (Out == NULL) return;
    for (i = 0; i < Out->DllCount; i++) {
        free(Out->Dlls[i].Functions);
    }
    free(Out->Dlls);
    free(Out->NameBlob);
    RtlZeroMemory(Out, sizeof(*Out));
}

/**************************************************/
/*             加载配置目录解析                      */
/**************************************************/

NTSTATUS
WpeParseLoadConfig(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_LOAD_CONFIG_INFO    Out
    )
/*++
Routine Description:
    解析加载配置目录 (最小子集: SEH table / security cookie)。

Arguments:
    Ctx - 解析上下文。
    Out - 输出加载配置信息。

Return Value:
    NTSTATUS。
--*/
{
    IMAGE_DATA_DIRECTORY_EX lcDir;
    SIZE_T lcOffset;
    ULONG configSize;

    if (Ctx == NULL || !Ctx->Parsed || Out == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));

    lcDir = Ctx->Info.DataDirectories[PE_DD_LOAD_CONFIG];
    if (!lcDir.Present || lcDir.Rva == 0 || lcDir.Size == 0) return STATUS_SUCCESS;
    if (!IocpRvaToOffset(Ctx, lcDir.Rva, &lcOffset)) return STATUS_INVALID_IMAGE_FORMAT;

    /* 先读 Size 字段 */
    if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, lcOffset, &configSize, sizeof(ULONG))) {
        return STATUS_SUCCESS;
    }
    if (configSize == 0 || configSize > PE_MAX_LOAD_CONFIG_SIZE) {
        return STATUS_SUCCESS;   /* 异常但非错误 */
    }
    Out->Size = configSize;

    if (Ctx->Info.Amd64) {
        IMAGE_LOAD_CONFIG_DIRECTORY64 lc;
        SIZE_T readSize = configSize;
        if (readSize > sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64)) readSize = sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64);
        if (!CopValidateReadingRange(&Ctx->Reader, lcOffset, readSize)) return STATUS_SUCCESS;
        RtlZeroMemory(&lc, sizeof(lc));
        if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, lcOffset, &lc, readSize)) return STATUS_SUCCESS;

        Out->TimeDateStamp = lc.TimeDateStamp;
        Out->MajorVersion = lc.MajorVersion;
        Out->MinorVersion = lc.MinorVersion;
        Out->GlobalFlagsClear = lc.GlobalFlagsClear;
        Out->GlobalFlagsSet = lc.GlobalFlagsSet;
        Out->SecurityCookie = lc.SecurityCookie;
        Out->SeHandlerTable = lc.SEHandlerTable;
        Out->SeHandlerCount = lc.SEHandlerCount;
        Out->HasSeh = (lc.SEHandlerTable != 0);
        Out->HasSecurityCookie = (lc.SecurityCookie != 0);
        /* Guard 缓解 (configSize 不足时零填充保持安全) */
        Out->GuardCFFunctionTable = lc.GuardCFFunctionTable;
        Out->GuardCFFunctionCount = lc.GuardCFFunctionCount;
        Out->GuardFlags = lc.GuardFlags;
        Out->HasGuardCF = ((lc.GuardFlags & (PE_GUARD_CF_INSTRUMENTED | PE_GUARD_CF_FUNCTION_TABLE)) != 0);
        Out->HasCET = ((lc.GuardFlags & (PE_GUARD_CF_CET_COMPATIBLE | PE_GUARD_CF_CET_SHADOW_STACK)) != 0);
    } else {
        IMAGE_LOAD_CONFIG_DIRECTORY32 lc;
        SIZE_T readSize = configSize;
        if (readSize > sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32)) readSize = sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32);
        if (!CopValidateReadingRange(&Ctx->Reader, lcOffset, readSize)) return STATUS_SUCCESS;
        RtlZeroMemory(&lc, sizeof(lc));
        if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, lcOffset, &lc, readSize)) return STATUS_SUCCESS;

        Out->TimeDateStamp = lc.TimeDateStamp;
        Out->MajorVersion = lc.MajorVersion;
        Out->MinorVersion = lc.MinorVersion;
        Out->GlobalFlagsClear = lc.GlobalFlagsClear;
        Out->GlobalFlagsSet = lc.GlobalFlagsSet;
        Out->SecurityCookie = lc.SecurityCookie;
        Out->SeHandlerTable = lc.SEHandlerTable;
        Out->SeHandlerCount = lc.SEHandlerCount;
        Out->HasSeh = (lc.SEHandlerTable != 0);
        Out->HasSecurityCookie = (lc.SecurityCookie != 0);
        Out->GuardCFFunctionTable = lc.GuardCFFunctionTable;
        Out->GuardCFFunctionCount = lc.GuardCFFunctionCount;
        Out->GuardFlags = lc.GuardFlags;
        Out->HasGuardCF = ((lc.GuardFlags & (PE_GUARD_CF_INSTRUMENTED | PE_GUARD_CF_FUNCTION_TABLE)) != 0);
        Out->HasCET = ((lc.GuardFlags & (PE_GUARD_CF_CET_COMPATIBLE | PE_GUARD_CF_CET_SHADOW_STACK)) != 0);
    }

    return STATUS_SUCCESS;
}

VOID
WpeLoadConfigFree(
    _Inout_ PPE_LOAD_CONFIG_INFO Out
    )
/*++
Routine Description:
    释放加载配置信息 (定长, 仅清零)。

Return Value:
    无。
--*/
{
    if (Out) RtlZeroMemory(Out, sizeof(*Out));
}

/**************************************************/
/*             Exception 目录解析 (x64)              */
/**************************************************/

NTSTATUS
WpeParseExceptionDirectory(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Out_ PPE_EXCEPTION_LIST      Out
    )
/*++
Routine Description:
    解析异常目录 (x64 RUNTIME_FUNCTION, 3×ULONG)。

Arguments:
    Ctx - 解析上下文。
    Out - 输出异常条目列表。

Return Value:
    NTSTATUS。
--*/
{
    IMAGE_DATA_DIRECTORY_EX excDir;
    SIZE_T excOffset;
    SIZE_T numEntries;
    SIZE_T i;
    ULONG entryCap = 0;

    if (Ctx == NULL || !Ctx->Parsed || Out == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));

    excDir = Ctx->Info.DataDirectories[PE_DD_EXCEPTION];
    if (!excDir.Present || excDir.Rva == 0 || excDir.Size == 0) return STATUS_SUCCESS;

    /* 仅 x64/ARM64/IA64 有意义 */
    if (Ctx->Info.Machine != PE_MACHINE_AMD64 &&
        Ctx->Info.Machine != PE_MACHINE_ARM64 &&
        Ctx->Info.Machine != PE_MACHINE_IA64) {
        return STATUS_SUCCESS;
    }

    if (!IocpRvaToOffset(Ctx, excDir.Rva, &excOffset)) return STATUS_INVALID_IMAGE_FORMAT;

    numEntries = excDir.Size / 12;   /* RUNTIME_FUNCTION = 3×ULONG */
    if (numEntries > PE_MAX_EXCEPTION_ENTRIES) numEntries = PE_MAX_EXCEPTION_ENTRIES;

    for (i = 0; i < numEntries; i++) {
        ULONG beginAddr, endAddr, unwindInfo;
        PE_EXCEPTION_ENTRY* e;

        if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, excOffset + i * 12, &beginAddr, sizeof(ULONG)) ||
            !IocpReaderReadBytes((PPE_READER)&Ctx->Reader, excOffset + i * 12 + 4, &endAddr, sizeof(ULONG)) ||
            !IocpReaderReadBytes((PPE_READER)&Ctx->Reader, excOffset + i * 12 + 8, &unwindInfo, sizeof(ULONG))) {
            break;
        }
        if (beginAddr == 0 && endAddr == 0 && unwindInfo == 0) break;   /* 终止符 */

        e = (PE_EXCEPTION_ENTRY*)WpeVecPush((void**)&Out->Entries, &Out->EntryCount,
                                             &entryCap, sizeof(PE_EXCEPTION_ENTRY));
        if (e == NULL) return STATUS_NO_MEMORY;
        e->BeginAddress = beginAddr;
        e->EndAddress = endAddr;
        e->UnwindInfoAddress = unwindInfo;
    }
    return STATUS_SUCCESS;
}

VOID
WpeExceptionDirectoryFree(
    _Inout_ PPE_EXCEPTION_LIST Out
    )
/*++
Routine Description:
    释放异常条目列表。

Return Value:
    无。
--*/
{
    if (Out == NULL) return;
    free(Out->Entries);
    RtlZeroMemory(Out, sizeof(*Out));
}

/**************************************************/
/*             资源解析 (递归)                      */
/**************************************************/

/*
 * WpepResourceTypeName — RT_* 类型名映射 (对齐 SS ParseResourcesImpl L1771-1784)。
 */
static
VOID
WpepResourceTypeName(
    _In_  ULONG  TypeId,
    _Out_ CHAR*  Buf,
    _In_  SIZE_T BufSize
    )
{
    static const struct {
        ULONG Id;
        const CHAR* Name;
    } kNames[] = {
        { 1, "RT_CURSOR" }, { 2, "RT_BITMAP" }, { 3, "RT_ICON" },
        { 4, "RT_MENU" }, { 5, "RT_DIALOG" }, { 6, "RT_STRING" },
        { 9, "RT_ACCELERATOR" }, { 10, "RT_RCDATA" }, { 14, "RT_GROUP_ICON" },
        { 16, "RT_VERSION" }, { 24, "RT_MANIFEST" },
    };
    ULONG k;

    for (k = 0; k < sizeof(kNames) / sizeof(kNames[0]); k++) {
        if (kNames[k].Id == TypeId) {
            strncpy_s(Buf, BufSize, kNames[k].Name, _TRUNCATE);
            return;
        }
    }
    sprintf_s(Buf, BufSize, "RT_UNKNOWN(%lu)", TypeId);
}

/*
 * WpepParseResourceLevel — 递归解析资源目录一层。
 * visited: 已处理目录偏移 (防环); 超限依赖深度/条目封顶兜底。
 */
static
VOID
WpepParseResourceLevel(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _Inout_ PPE_RESOURCE_LIST     Out,
    _In_  SIZE_T                   RsrcBase,
    _In_  ULONG                    RsrcSize,
    _In_  ULONG                    DirOffsetFromBase,
    _In_  ULONG                    TypeId,
    _In_  ULONG                    NameId,
    _In_  ULONG                    LangId,
    _In_  BOOLEAN                  NameIsStringEntry,
    _In_  ULONG                    NameStringOffset,
    _In_  ULONG                    Depth,
    _In_  ULONG                    MaxDepth,
    _Inout_ PULONG                 Visited,
    _Inout_ PULONG                 VisitedCount,
    _Inout_ PULONG                 BlobCap,
    _Inout_ PULONG                 EntryCap
    )
{
    SIZE_T rsrcEnd;
    SIZE_T dirFileOffset;
    IMAGE_RESOURCE_DIRECTORY dir;
    ULONG numEntries;
    ULONG i;

    if (Depth >= MaxDepth) return;
    if (Out->EntryCount >= PE_MAX_TOTAL_RESOURCES) return;

    /* 防环 */
    {
        ULONG k;
        for (k = 0; k < *VisitedCount; k++) {
            if (Visited[k] == DirOffsetFromBase) return;
        }
        if (*VisitedCount < PE_RESOURCE_VISITED_MAX) Visited[(*VisitedCount)++] = DirOffsetFromBase;
    }

    if (!IocpAddSizeSafe(RsrcBase, (SIZE_T)RsrcSize, &rsrcEnd)) return;
    if (!IocpAddSizeSafe(RsrcBase, (SIZE_T)DirOffsetFromBase, &dirFileOffset)) return;
    if (dirFileOffset + sizeof(IMAGE_RESOURCE_DIRECTORY) > rsrcEnd) return;

    if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, dirFileOffset, &dir, sizeof(dir))) return;

    if (!IocpAddU32Safe((ULONG)dir.NumberOfNamedEntries, (ULONG)dir.NumberOfIdEntries,
                       &numEntries)) return;
    if (numEntries > PE_MAX_RESOURCE_ENTRIES) numEntries = PE_MAX_RESOURCE_ENTRIES;

    for (i = 0; i < numEntries && Out->EntryCount < PE_MAX_TOTAL_RESOURCES; i++) {
        SIZE_T stride;
        SIZE_T entryFileOffset;
        IMAGE_RESOURCE_DIRECTORY_ENTRY entry;
        BOOLEAN entryNameIsString;
        ULONG entryNameOffsetOrId;
        BOOLEAN entryDataIsDir;
        ULONG entryDirOrDataOffset;
        ULONG curType = TypeId;
        ULONG curName = NameId;
        ULONG curLang = LangId;
        BOOLEAN curNameIsString = NameIsStringEntry;
        ULONG curNameStrOffset = NameStringOffset;

        if (!WpeSafeMulSz((SIZE_T)i, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), &stride) ||
            !IocpAddSizeSafe(dirFileOffset + sizeof(IMAGE_RESOURCE_DIRECTORY), stride, &entryFileOffset)) break;
        if (entryFileOffset + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > rsrcEnd) break;

        if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, entryFileOffset, &entry, sizeof(entry))) break;

        /* 位掩码解码 (位域布局实现定义, 用显式掩码) */
        entryNameIsString = (entry.Name >> 31) != 0;
        entryNameOffsetOrId = entry.Name & 0x7FFFFFFFu;
        entryDataIsDir = (entry.OffsetToData >> 31) != 0;
        entryDirOrDataOffset = entry.OffsetToData & 0x7FFFFFFFu;

        if (Depth == 0) {
            curType = entryNameIsString ? 0u : (entryNameOffsetOrId & 0xFFFFu);
        } else if (Depth == 1) {
            curNameIsString = entryNameIsString;
            if (entryNameIsString) {
                curName = 0;
                curNameStrOffset = entryNameOffsetOrId;
            } else {
                curName = entryNameOffsetOrId & 0xFFFFu;
                curNameStrOffset = 0;
            }
        } else if (Depth == 2) {
            curLang = entryNameIsString ? 0u : (entryNameOffsetOrId & 0xFFFFu);
        }

        if (entryDataIsDir) {
            WpepParseResourceLevel(Ctx, Out, RsrcBase, RsrcSize, entryDirOrDataOffset,
                                   curType, curName, curLang, curNameIsString, curNameStrOffset,
                                   Depth + 1, MaxDepth, Visited, VisitedCount, BlobCap, EntryCap);
        } else {
            SIZE_T dataEntryFileOffset;
            IMAGE_RESOURCE_DATA_ENTRY dataEntry;
            PE_RESOURCE_ENTRY* resEntry;

            if (!IocpAddSizeSafe(RsrcBase, (SIZE_T)entryDirOrDataOffset, &dataEntryFileOffset)) continue;
            if (dataEntryFileOffset + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > rsrcEnd) continue;
            if (!IocpReaderReadBytes((PPE_READER)&Ctx->Reader, dataEntryFileOffset, &dataEntry, sizeof(dataEntry))) continue;

            /* 大小 >16MB 记异常 (裁剪, 不记录) */
            if (dataEntry.Size > 0x1000000u) {
                /* 可疑大资源, 仍收录 */
            }

            resEntry = (PE_RESOURCE_ENTRY*)WpeVecPush((void**)&Out->Entries, &Out->EntryCount,
                                                       EntryCap, sizeof(PE_RESOURCE_ENTRY));
            if (resEntry == NULL) return;
            RtlZeroMemory(resEntry, sizeof(*resEntry));
            resEntry->Type = curType;
            resEntry->Name = curName;
            resEntry->Language = curLang;
            resEntry->CodePage = dataEntry.CodePage;
            resEntry->Size = dataEntry.Size;
            resEntry->NameIsString = curNameIsString;
            resEntry->Entropy = -1.0;

            /* dataEntry.OffsetToData 是 RVA → 文件偏移 */
            if (dataEntry.OffsetToData != 0) {
                SIZE_T dataFileOpt;
                if (IocpRvaToOffset(Ctx, dataEntry.OffsetToData, &dataFileOpt)) {
                    resEntry->Offset = (ULONG)(dataFileOpt & 0xFFFFFFFFu);
                }
            }

            /* 内容级检测 (对齐 SS ParseResourcesImpl L1786-1822): 内嵌 PE/脚本/熵加密 */
            if (resEntry->Offset != 0 && resEntry->Size >= 2 &&
                resEntry->Offset < Ctx->Reader.Size) {
                SIZE_T dataStart = resEntry->Offset;
                SIZE_T dataLen = resEntry->Size;
                if (dataStart + dataLen > Ctx->Reader.Size || dataStart + dataLen < dataStart) {
                    dataLen = Ctx->Reader.Size - dataStart;
                }
                if (dataLen > 0) {
                    /* 内嵌 PE (MZ 头) */
                    USHORT mz;
                    if (dataLen >= sizeof(IMAGE_DOS_HEADER) &&
                        IocpReaderReadBytes((PPE_READER)&Ctx->Reader, dataStart, &mz, sizeof(USHORT)) &&
                        mz == IMAGE_DOS_SIGNATURE) {
                        resEntry->ContainsPE = TRUE;
                    }
                    /* 脚本预览 (前 64B, 小写化后 strstr) */
                    if (dataLen >= 10) {
                        CHAR preview[65];
                        SIZE_T plen = dataLen < 64 ? dataLen : 64;
                        if (IocpReaderReadBytes((PPE_READER)&Ctx->Reader, dataStart, preview, plen)) {
                            SIZE_T k;
                            for (k = 0; k < plen; k++) preview[k] = (CHAR)tolower((UCHAR)preview[k]);
                            preview[plen] = 0;
                            if (strstr(preview, "powershell") != NULL ||
                                strstr(preview, "wscript") != NULL ||
                                strstr(preview, "cscript") != NULL ||
                                strstr(preview, "cmd /c") != NULL) {
                                resEntry->IsScript = TRUE;
                            }
                        }
                    }
                    /* 熵 (>=7.2 加密判定, ≤10MB 门控防 DoS, 对齐 SS maxResourceSize=10MB) */
                    if (dataLen >= 64 && dataLen <= (10u * 1024u * 1024u)) {
                        BYTE* buf = (BYTE*)malloc(dataLen);
                        if (buf != NULL) {
                            if (IocpReaderReadBytes((PPE_READER)&Ctx->Reader, dataStart, buf, dataLen)) {
                                DOUBLE ent = CoEntropyCalculate(buf, dataLen, CoEntropyAlphabet_Byte, 0);
                                resEntry->Entropy = ent;
                                if (ent >= 7.2) resEntry->IsEncrypted = TRUE;
                            }
                            free(buf);
                        }
                    }
                }
            }
            WpepResourceTypeName(resEntry->Type, resEntry->TypeName, sizeof(resEntry->TypeName));

            /* UNICODE 字符串名: WORD 长度 + WORD 数组 */
            if (curNameIsString && curNameStrOffset != 0) {
                SIZE_T nameStrFileOffset;
                if (IocpAddSizeSafe(RsrcBase, (SIZE_T)curNameStrOffset, &nameStrFileOffset)) {
                    USHORT nameLen = 0;
                    if (IocpReaderReadBytes((PPE_READER)&Ctx->Reader, nameStrFileOffset, &nameLen, sizeof(USHORT)) &&
                        nameLen > 0 && nameLen <= 256) {
                        WCHAR nameBuf[256];
                        BOOLEAN ok = TRUE;
                        ULONG k;
                        for (k = 0; k < nameLen; k++) {
                            USHORT ch;
                            SIZE_T chOffset;
                            if (!IocpAddSizeSafe(nameStrFileOffset + 2, (SIZE_T)k * 2, &chOffset) ||
                                !IocpReaderReadBytes((PPE_READER)&Ctx->Reader, chOffset, &ch, sizeof(USHORT))) {
                                ok = FALSE;
                                break;
                            }
                            nameBuf[k] = (WCHAR)ch;
                        }
                        if (ok) {
                            if (WpeBlobAddW(&Out->NameBlob, &Out->NameBlobChars, BlobCap,
                                            nameBuf, nameLen, &resEntry->NameStringOffset)) {
                                resEntry->NameStringLength = nameLen;
                            }
                        }
                    }
                }
            }
        }
    }
}

NTSTATUS
WpeParseResources(
    _In_  const PE_PARSER_CONTEXT* Ctx,
    _In_  ULONG                    MaxDepth,
    _Out_ PPE_RESOURCE_LIST       Out
    )
/*++
Routine Description:
    解析资源目录树 (递归, 深度上限, 防环, 计数封顶)。

Arguments:
    Ctx      - 解析上下文。
    MaxDepth - 最大递归深度 (0=1, >32 钳 32)。
    Out      - 输出资源列表。

Return Value:
    NTSTATUS。
--*/
{
    IMAGE_DATA_DIRECTORY_EX rsrcDir;
    SIZE_T rsrcBase;
    SIZE_T rsrcEnd;
    ULONG visited[PE_RESOURCE_VISITED_MAX];
    ULONG visitedCount = 0;
    ULONG blobCap = 0;
    ULONG entryCap = 0;

    if (Ctx == NULL || !Ctx->Parsed || Out == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));

    rsrcDir = Ctx->Info.DataDirectories[PE_DD_RESOURCE];
    if (!rsrcDir.Present || rsrcDir.Rva == 0 || rsrcDir.Size == 0) return STATUS_SUCCESS;

    if (MaxDepth == 0) MaxDepth = 1;
    if (MaxDepth > PE_MAX_RESOURCE_DEPTH) MaxDepth = PE_MAX_RESOURCE_DEPTH;

    if (!IocpRvaToOffset(Ctx, rsrcDir.Rva, &rsrcBase)) return STATUS_INVALID_IMAGE_FORMAT;
    if (!IocpAddSizeSafe(rsrcBase, rsrcDir.Size, &rsrcEnd) || rsrcEnd > Ctx->Reader.Size) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* 根目录在节基址偏移 0 */
    WpepParseResourceLevel(Ctx, Out, rsrcBase, rsrcDir.Size,
                           0u, 0u, 0u, 0u, FALSE, 0u, 0u, MaxDepth,
                           visited, &visitedCount, &blobCap, &entryCap);
    return STATUS_SUCCESS;
}

VOID
WpeResourcesFree(
    _Inout_ PPE_RESOURCE_LIST Out
    )
/*++
Routine Description:
    释放资源列表。

Return Value:
    无。
--*/
{
    if (Out == NULL) return;
    free(Out->Entries);
    free(Out->NameBlob);
    RtlZeroMemory(Out, sizeof(*Out));
}
