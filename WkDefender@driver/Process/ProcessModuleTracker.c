/**************************************************/
/*  WkDefender — 进程模块追踪子系统实现              */
/*  参考 PhantomSensor: ImgpFindOrCreateProcessModules */
/*  ImgpAddModuleToTracking / ImageNotifyProcessTerminated */
/*                                                   */
/*  2026-08-11 全局镜像对象重构：                     */
/*    - g_WkdModuleTable 全局唯一镜像表（WKD_HASH_MAP）*/
/*    - WKD_MODULE 对象：内容固有数据只解析一次        */
/*    - 引用契约：RefCount = 表引用(1) + 视图引用 + pin*/
/*    - PsDereferenceWkdModule 归零(RefCount==1) → ShouldRemove*/
/*      double-check 摘表 → 锁外释放（无延迟释放）     */
/**************************************************/

#include "ProcessModuleTracker.h"
#include "ProcessMonitor.h"     /* WKD_PROCESS / Ps* API / ModuleContext */
#include "../Common/PeParser.h"
#include "../Common/Utils.h"
#include <ntstrsafe.h>

WKD_HASH_MAP g_WkdModuleTable;

/**************************************************/
/*              WKD_MODULE 内部辅助                 */
/**************************************************/

static
WKD_IMAGE_TYPE
PspDetermineImageType(
    _In_ PCUNICODE_STRING ImagePath,
    _In_opt_ PIMAGE_INFO ImageInfo
)
{
    WKD_IMAGE_TYPE type = WkdImageType_Unknown;

    if (ImageInfo && ImageInfo->SystemModeImage) {
        return WkdImageType_Sys;
    }

    if (!ImagePath || !ImagePath->Buffer || ImagePath->Length == 0) {
        return WkdImageType_Unknown;
    }

    /* 提取扩展名并匹配 */
    {
        ULONG length = ImagePath->Length / sizeof(WCHAR);
        PCWSTR buffer = ImagePath->Buffer;

        for (ULONG i = length; i > 0; i--) {
            if (buffer[i - 1] == L'.') {
                /* 扩展长度 */
                ULONG extLen = length - (i - 1);

                if (extLen == 4) {
                    WCHAR ext[5] = { 0 };
                    RtlCopyMemory(ext, &buffer[i - 1], 4 * sizeof(WCHAR));

                    if (wcscmp(ext, L".dll") == 0)      type = WkdImageType_Dll;
                    else if (wcscmp(ext, L".exe") == 0) type = WkdImageType_Exe;
                    else if (wcscmp(ext, L".sys") == 0) type = WkdImageType_Sys;
                    /* 旧版驱动：主要用于 Windows 9x / NT 4.0 时代的遗留驱动或特定设备驱动程序（如旧的打印机驱动、显示驱动） */
                    else if (wcscmp(ext, L".drv") == 0) type = WkdImageType_Drv;
                    /* OLE 控件：本质上是特殊的 .dll，属于 ActiveX/COM 组件，通常用于 UI 界面嵌入（如浏览器插件）或提供特定功能接口。*/
                    else if (wcscmp(ext, L".ocx") == 0) type = WkdImageType_Ocx;
                    /* 控制面板项：本质上是导出了特定函数（如 CPlApplet）的 .dll。双击它时，控制面板 (control.exe) 会加载该文件并调用对应函数，用于显示和配置系统设置（如鼠标、网络属性）。*/
                    else if (wcscmp(ext, L".cpl") == 0) type = WkdImageType_Cpl;
                    /* 屏幕保护程序：本质上是导出了特定函数（如 ScreenSaverProc）的 .exe。系统会根据其扩展名将其识别为屏保，在空闲时运行或执行预览。*/
                    else if (wcscmp(ext, L".scr") == 0) type = WkdImageType_Scr;
                    /* EFI应用程序：虽然它也基于 PE（可移植可执行文件）格式，但它不运行在 Windows 操作系统内核中，而是运行在主板固件启动阶段（操作系统加载之前）。它负责硬件初始化、引导管理（如 bootmgfw.efi），是 Windows 启动过程的第一道关卡。*/
                    else if (wcscmp(ext, L".efi") == 0) type = WkdImageType_Efi;
                }
                break;
            }
        }
    }

    return type;
}

//
// PspAnalyzeImageProperties：纯数据收集，输出直填 WKD_MODULE::ImageProperties 位域
// （2026-08-12：弃用 IMG_IMGFLAG_* 位图中转；文件级位域直写，每映射 Unbacked 走视图路径）。
//
static
NTSTATUS
PspAnalyzeImageProperties(
    _In_ const PIMAGE_INFO ImageInfo,
    _Out_ PWKD_IMAGE_PROPERTIES Properties   /* 直填 WKD_MODULE::ImageProperties */
)
{
    if (!ImageInfo || !Properties) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Properties, sizeof(WKD_IMAGE_PROPERTIES));

    if (ImageInfo->ImageAddressingMode != IMAGE_ADDRESSING_MODE_32BIT) {
        /* 违反微软文档定义，发生严重错误，直接返回 */
        return STATUS_INTERNAL_ERROR;
    }

    /* 内核模式镜像? */
    Properties->SystemModeImage = ImageInfo->SystemModeImage;

#if (NTDDI_VERSION >= NTDDI_WINBLUE)
    /*
     * 代码完整性标记映像的签名级别（保留值，SE_SIGNING_LEVEL_* 之一）。
     * 此值是 ntddk.h中的 #define SE_SIGNING_LEVEL_* 常量之一。
     */
    Properties->ImageSignatureLevel = ImageInfo->ImageSignatureLevel;

    /*
     * 代码完整性标记映像的签名类型（保留值，SE_IMAGE_SIGNATURE_TYPE 枚举）。
     * 此值是在 ntddk.h中定义的 SE_IMAGE_SIGNATURE_TYPE 枚举值。
     */
    Properties->ImageSignatureType = ImageInfo->ImageSignatureType;
#else
    // ImgpGetCachedSigningLevel(ImageInfo, &sigStatus, &sigEval);
#endif

    return STATUS_SUCCESS;
}

//
// 分配全局镜像对象（结构体 + 路径尾随缓冲一次分配，非分页池）
//
static
NTSTATUS
PspCreateModule(
    _In_ PCUNICODE_STRING ImagePath,
    _In_ const PIMAGE_INFO ImageInfo,
    _Out_ PWKD_MODULE* Module
    )
{
    NTSTATUS status;
    PWKD_MODULE module;
    PUNICODE_STRING copiedImagePath;

    if (!CoCheckUnicodeStringValidity(ImagePath) ||
        !ImageInfo || !Module) {
        return STATUS_INVALID_PARAMETER;
    }

    module = (PWKD_MODULE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(WKD_MODULE), WKD_MT_MODULE_TAG);
    if (module == NULL) return STATUS_NO_MEMORY;
    RtlZeroMemory(module, sizeof(WKD_MODULE));

    module->RefCount = 1;   /* 创建者引用 */
    module->ImageSize = ImageInfo->ImageSize;
    /* ImageProperties：全零（位域 0），由调用方首见直填（PspAnalyzeImageProperties 位域直写） */
    module->ImageType = PspDetermineImageType(ImagePath, ImageInfo);
    /* LastWriteTime：本轮 0（从 IMAGE_INFO_EX.FileObject 查询成本高，预留扩展） */
    DaInitialize(&module->Sections, sizeof(WKD_MODULE_SECTION),
                 POOL_FLAG_NON_PAGED, WKD_MT_MODULE_TAG);

    status = CoCopyUnicodeString(&copiedImagePath, ImagePath);
    if (!NT_SUCCESS(status)) DbgBreakPoint();   /* 发生严重错误 */
    module->ImagePath = copiedImagePath;

    PspAnalyzeImageProperties(ImageInfo, &module->ImageProperties);

#if (NTDDI_VERSION >= NTDDI_VISTA)
    /* 扩展信息存在（IMAGE_INFO_EX 可用），获取镜像文件句柄 */
    if (ImageInfo->ExtendedInfoPresent) {
        PIMAGE_INFO_EX imageInfoEx =
            CONTAINING_RECORD(ImageInfo, IMAGE_INFO_EX, ImageInfo);

        if (imageInfoEx->FileObject) {
            module->FileObject = imageInfoEx->FileObject;
            // 增加引用计数，避免 uaf
            ObfReferenceObject(imageInfoEx->FileObject);
        }
        else {
            // 非常规镜像加载??? 暂不支持
            DbgBreakPoint();
        }

    }
    else {
        // 非常规镜像加载??? 暂不支持
        DbgBreakPoint();
    }
#endif

    *Module = module;
    return STATUS_SUCCESS;
}

//
// 释放全局镜像对象（节集缓冲 + 对象本身；引用归零且摘表后调用）
//
// 此时没有任何线程持有模块对象索引，可安全无锁释放!!!
//
static
VOID
PspDestroyWkdModule(
    _In_ PWKD_MODULE WkdModule
    )
{
    if (!WkdModule) return;

    /* FileObject 引用配对（首见构造 ObfReferenceObject 持有；2026-08-13 修复泄漏）。
     * 注：PsDereferenceWkdModule 标注 max APC_LEVEL，ObDereferenceObject 在 APC_LEVEL 实际安全
     * （引用计数操作不涉分页/调度），严格 SAL 要求 PASSIVE 的话需重构摘表路径。 */
    if (WkdModule->FileObject) {
        ObfDereferenceObject(WkdModule->FileObject);
        WkdModule->FileObject = NULL;
    }
    
    if (WkdModule->ImagePath->Buffer)  ExFreePool(WkdModule->ImagePath->Buffer);
    if (WkdModule->ImagePath)          ExFreePool(WkdModule->ImagePath);
    DaDestroy(&WkdModule->Sections);
    ExFreePoolWithTag(WkdModule, WKD_MT_MODULE_TAG);
}

//
// OnNtHeader 回调：填充 SectionAlignment/FileAlignment/SizeOfImage + 一次性节容量
//
static
NTSTATUS
MmpOnNtHeader(
    _Inout_ PWKD_PE_PARSE_CONTEXT Context,
    _In_ const PIMAGE_NT_HEADERS NtHeaders,
    _In_opt_ PVOID UserCtx
    )
{
    PWKD_MODULE module = (PWKD_MODULE)UserCtx;
    ULONG secCount;

    if (!Context || !NtHeaders) {
        return STATUS_INVALID_PARAMETER;
    }

    module->SectionAlignment = WKD_PE_OPT_OFFSET(Context, SectionAlignment);
    module->FileAlignment = WKD_PE_OPT_OFFSET(Context, FileAlignment);
    module->SizeOfImage = WKD_PE_OPT_OFFSET(Context, SizeOfImage);

    //secCount = NtHeaders->FileHeader.NumberOfSections;
    //if (secCount > WKD_PE_MAX_SECTIONS_DEFAULT) secCount = WKD_PE_MAX_SECTIONS_DEFAULT;
    //if (secCount > 0) {
    //    DaEnsureCapacity(&module->Sections, secCount);   /* 失败忽略：节采集尽力 */
    //}
    return STATUS_SUCCESS;
}

//
// OnSection 回调：逐节采集（一次性容量已备，DaAppend 追加）
//
static
NTSTATUS
PspParserSection(
    _Inout_ PWKD_PE_PARSE_CONTEXT Context,
    _In_ PIMAGE_SECTION_HEADER Section,
    _In_ ULONG Index,
    _In_opt_ PVOID UserContext
    )
{
    PWKD_MODULE module;
    WKD_MODULE_SECTION section;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Index);

    if (!Section) return STATUS_INVALID_PARAMETER;
    module = (PWKD_MODULE)UserContext;

    RtlZeroMemory(&section, sizeof(WKD_MODULE_SECTION));

    for (ULONG i = 0; i < IMAGE_SIZEOF_SHORT_NAME; i++) {
        section.Name[i] = (WCHAR)Section->Name[i];   /* 节名 8 字节 ASCII → WCHAR */
    }
    section.Name[7] = L'\0';

    section.VirtualSize = Section->Misc.VirtualSize;
    section.VirtualAddress = Section->VirtualAddress;
    section.SizeOfRawData = Section->SizeOfRawData;
    section.Characteristics = Section->Characteristics;

    DaAppend(&module->Sections, &section);                /* 失败忽略：节采集尽力 */
    return STATUS_SUCCESS;
}

//
// 完整 PE 测量采集（仅首见路径执行一次；解析失败仍保留模块 Valid=FALSE）
//
static
NTSTATUS
PspParseModule(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _Inout_ PWKD_MODULE Module
    )
{
    NTSTATUS status;
    WKD_PE_PARSE_CONTEXT ctx;

    if (!ImageBase || ImageSize == 0 || !Module) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&ctx, sizeof(WKD_PE_PARSE_CONTEXT));
    ctx.Data = ImageBase;
    ctx.DataSize = ImageSize;
    ctx.Mode = WkdPeMode_Image;
    ctx.Flags = WKD_PE_FLAG_DIRECTORIES;
    ctx.MaxSections = WKD_PE_MAX_SECTIONS_DEFAULT;
    ctx.Callbacks.OnNtHeader = MmpOnNtHeader;
    ctx.Callbacks.OnSection = PspParserSection;
    ctx.CallbackContext = Module;

    status = CoParsePe(&ctx);
    if (NT_SUCCESS(status)) {
        Module->Facts = ctx.Facts;
    }
    return status;
}

//
// 移除裁决（桶独占锁内 double-check）：RefCount==1（仅剩表引用）才允许摘除
//
static
BOOLEAN
PspShouldRemoveWkdModule(
    _In_ PWKD_MODULE WkdModule
    )
{
    if (!WkdModule) return TRUE;
    return (InterlockedCompareExchange(&WkdModule->RefCount, 0, 0) == 1);
}

/**************************************************/
/*             全局表初始化 / 清理                  */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
MtInitialize(
    VOID
    )
{
    NTSTATUS status;

    RtlZeroMemory(&g_WkdModuleTable, sizeof(g_WkdModuleTable));
    status = CoInitializeHashMap(&g_WkdModuleTable, WKD_MODULE_TABLE_BUCKETS, TRUE,
                                 PsReferenceWkdModule,
                                 PspShouldRemoveWkdModule,
                                 PsDereferenceWkdModule);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
MtCleanup(
    VOID
    )
{
    ULONG remain;

    if (g_WkdModuleTable.Entries == NULL) return;

    remain = g_WkdModuleTable.ActiveEntries;
    if (remain == 0) {
        CoFreeHashMap(&g_WkdModuleTable);
    } else {
        /* 卸载路径进程视图引用未归零 → ShouldRemove 拒绝 → 残留。
         * 跳过 CoFreeHashMap（其 ASSERT(ActiveEntries==0) 会 bugcheck）；
         * 表/模块对象泄漏（卸载罕见路径，与现有卸载清理注释态策略对齐）。 */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] MtCleanup: %lu module entries remain (views not released), skip free.\n",
            remain);
    }
}

/**************************************************/
/*              查重或创建（两阶段）                */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
PsFindOrCreateModule(
    _In_ PCUNICODE_STRING ImagePath,
    _In_ const PIMAGE_INFO ImageInfo,
    _Out_ PWKD_MODULE* Module,
    _Out_opt_ PBOOLEAN Existing
    )
{
    NTSTATUS status;
    PWKD_MODULE module;
    
    if (!ImageInfo || !Module ||
        !CoCheckUnicodeStringValidity(ImagePath)) {
        return STATUS_INVALID_PARAMETER;
    }
    *Module = NULL;
    if (Existing) *Existing = FALSE;

    /* === Phase 1: 查重（锁内 pin） === */
    module = (PWKD_MODULE)CoLookupHashMapEntry(&g_WkdModuleTable, ImagePath->Buffer, ImagePath->Length);
    if (module) {
        if (module->ImageSize == ImageInfo->ImageSize) {
            /* Identity 匹配 → 复用 */
            *Module = module;
            return STATUS_SUCCESS;
        }
        /* 同路径文件被替换后重载 → 释放 pin，落新建 */
        PsDereferenceWkdModule(module);
        DbgBreakPoint();    /* 异常 */
    }
   
    /* === Phase 2: 锁外解析 + 回表 try-insert === */
    status = PspCreateModule(ImagePath, ImageInfo, &module);
    if (!NT_SUCCESS(status)) return status;
    PspParseModule(ImageInfo->ImageBase, ImageInfo->ImageSize, module);

Retry:
    {
        BOOLEAN exists = FALSE;

        status = CoInsertHashMap(&g_WkdModuleTable,
            ImagePath->Buffer, ImagePath->Length, (ULONG64)module, &exists);
        if (NT_SUCCESS(status)) {
            *Module = module;
            return STATUS_SUCCESS;
        } else if (status == STATUS_OBJECT_NAME_COLLISION && exists) {
            PWKD_MODULE exist_module;

            /* 并发创建者胜出：释放自建，取赢家 */
            exist_module = (PWKD_MODULE)CoLookupHashMapEntry(&g_WkdModuleTable,
                ImagePath->Buffer, ImagePath->Length);
            if (exist_module == NULL) {
                /* 极端竞态：赢家已被并发摘除 → 放弃 */
                goto Retry;
            }

            /* lookup成功，释放已创建的WKD_MODULE */
            *Module = exist_module;
            if (Existing) *Existing = TRUE;
            status = STATUS_SUCCESS;
            goto Cleanup;
        } else {
            /* 上限（WKD_MODULE_TABLE_MAX_ENTRIES）/ 内存不足 → 放弃追踪 */
            goto Cleanup;
        }
    }

Cleanup:
    PspDestroyWkdModule(module);
    return status;
}

_Use_decl_annotations_
LONG
PsDereferenceWkdModule(
    _Inout_ PWKD_MODULE Module
    )
{
    LONG ref;

    if (!Module) return MAXLONG;

    ref = InterlockedDecrement(&Module->RefCount);
    if (ref == 1) {
        /* 仅剩表引用 → 无视图无 pin → 尝试摘表（ShouldRemove 桶锁内 double-check） */
        CoRemoveHashMapEntry(&g_WkdModuleTable,
                             Module->ImagePath->Buffer,
                             Module->ImagePath->Length);
            /* 摘除成功：Dereference 已释放表引用（1→0）→ 锁外释放 */
    } else if (ref == 0) {
        PspDestroyWkdModule(Module);
    }
    
    return ref;
}

/**************************************************/
/*              per-process 视图挂接               */
/**************************************************/

/* 调用者必须持有 WkdProcess 的推锁（与 PsLookupModuleInstanceByImageBaseLocked 同约定；
 * 2026-08-13 修复：原实现内部加锁，调用方持锁场景下推锁不可重入 → 自死锁） */
_Use_decl_annotations_
NTSTATUS
PsModuleAttachProcessLocked(
    _Inout_ PWKD_PROCESS WkdProcess,
    _Inout_ PWKD_MODULE Module,
    _In_ PVOID ImageBase,
    _Out_opt_ PWKD_MODULE_INSTANCE* Instance
    )
{
    NTSTATUS status;
    PWKD_MODULE_INSTANCE instance;
    PWKD_MODULE_CONTEXT context;

    if (!WkdProcess || !WkdProcess->ModuleContext || 
        !ImageBase || !Module) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Instance) *Instance = NULL;

    context = WkdProcess->ModuleContext;
    if (context->ActiveModules >= MAX_MODULES_PER_PROCESS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    instance = (PWKD_MODULE_INSTANCE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(WKD_MODULE_INSTANCE), WKD_MT_POOL_ENTRY);
    if (!instance)  return STATUS_NO_MEMORY;
    RtlZeroMemory(instance, sizeof(WKD_MODULE_INSTANCE));

    instance->ImageBase = ImageBase;
    instance->Module = Module;
    KeQuerySystemTime(&instance->LoadTime);
    InsertTailList(&context->ModuleList, &instance->ListEntry);
    InterlockedIncrement(&context->ActiveModules);

    /* 视图引用（Module 由调用方传入时已 pin，此处再加视图引用） */
    PsReferenceWkdModule(Module);

    if (Instance) *Instance = instance;
    return STATUS_SUCCESS;
}

/**************************************************/
/*           上下文创建 / 销毁                     */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
PsAllocateModuleContext(
    _Inout_ PWKD_PROCESS WkdProcess
    )
{
    PWKD_MODULE_CONTEXT ctx;

    if (!WkdProcess) return STATUS_INVALID_PARAMETER;

    /* ---- 快路径: 已存在直接返回 ---- */
    if (WkdProcess->ModuleContext) return STATUS_SUCCESS;

    ctx = (PWKD_MODULE_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(WKD_MODULE_CONTEXT), WKD_MT_POOL_TAG);
    if (ctx == NULL) return STATUS_NO_MEMORY;
    RtlZeroMemory(ctx, sizeof(WKD_MODULE_CONTEXT));

    InitializeListHead(&ctx->ModuleList);
    ExInitializePushLock(&ctx->Lock);
    ctx->ProcessId = WkdProcess->Core.ProcessId;

    if (InterlockedCompareExchangePointer(
        &WkdProcess->ModuleContext, ctx, NULL)) {
        /* 并发输家: 赢家已发布, 释放本地副本 */
        PsDestroyWkdModuleContext(ctx);
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PsDestroyWkdModuleContext(
    _In_ PWKD_PROCESS WkdProcess
    )
/*++
    销毁模块追踪上下文：摘出全部视图 → 锁外逐个 PsDereferenceWkdModule（可能触发
    摘表+锁外释放）→ 释放视图/上下文。IRQL 注解 2026-08-11 降级 PASSIVE
    （PsDereferenceWkdModule 经 CoRemoveHashMapEntry，max APC_LEVEL）。
    无锁访问。
--*/
{
    PLIST_ENTRY entry, next;
    PWKD_MODULE_CONTEXT context;
    PWKD_MODULE_INSTANCE instance;

    if (!WkdProcess || !WkdProcess->ModuleContext) return;
    
    context = WkdProcess->ModuleContext;

    entry = context->ModuleList.Flink;
    while (entry != &context->ModuleList) {
        next = entry->Flink;
        instance = CONTAINING_RECORD(entry, WKD_MODULE_INSTANCE, ListEntry);
        RemoveEntryList(entry);
        PsDereferenceWkdModule(instance->Module);
        ExFreePoolWithTag(instance, WKD_MT_POOL_ENTRY);
        InterlockedDecrement(&context->ActiveModules);
        entry = next;
    }

    ExFreePoolWithTag(context, WKD_MT_POOL_TAG);
    WkdProcess->ModuleContext = NULL;
}

/* 调用者必须持有WkdProcess的推锁 */
_Use_decl_annotations_
PWKD_MODULE_INSTANCE
PsLookupModuleInstanceByImageBaseLocked(
    _Inout_ PWKD_PROCESS WkdProcess,
    _In_ PVOID ImageBase
    )
{
    PLIST_ENTRY entry;
    PWKD_MODULE_INSTANCE instance;
    PWKD_MODULE_CONTEXT context;

    if (!WkdProcess || !WkdProcess->ModuleContext || !ImageBase)
        return NULL;

    context = WkdProcess->ModuleContext;
    for (entry = context->ModuleList.Flink;
         entry != &context->ModuleList;
         entry = entry->Flink) {
        instance = CONTAINING_RECORD(entry, WKD_MODULE_INSTANCE, ListEntry);
        if (instance->ImageBase == ImageBase) {
            return instance;
        }
    }

    return NULL;
}

//
// 地址包含查询（新增，对齐 SS TnpFindModuleForAddress，改用 WKD_MODULE 全局表替代 PEB 遍历）。
// 遍历目标进程 ModuleContext->ModuleList，对每个 WKD_MODULE_INSTANCE 判定
//   Address ∈ [ImageBase, ImageBase + Module->ImageSize)
// 命中返回实例（Module 指针可回溯全局 WKD_MODULE 取 ImageSize/ImagePath），未命中返回 NULL。
// 全程内核数据结构（ModuleList/ImageBase/Module->ImageSize 均非分页），无 KeStackAttachProcess、
// 无 ProbeForRead、无用户态地址访问 → 无需 SEH 保护，本质优于 PEB 版遍历。
// 约定：调用方须已持有 ModuleContext 共享锁（EX_PUSH_LOCK，≤APC_LEVEL）。
//
_Use_decl_annotations_
NTSTATUS
PsLookupWkdModuleContainingAddress(
    _In_ PWKD_PROCESS WkdProcess,
    _In_ PVOID Address,
    _Outptr_ PWKD_MODULE_INSTANCE* Instance
    )
{
    PWKD_MODULE_CONTEXT context;
    PLIST_ENTRY entry;

    if (!WkdProcess || !WkdProcess->ModuleContext || !Address || !Instance)
        return STATUS_INVALID_PARAMETER;
    *Instance = NULL;

    context = WkdProcess->ModuleContext;
    for (entry = context->ModuleList.Flink;
         entry != &context->ModuleList;
         entry = entry->Flink) {
        PWKD_MODULE_INSTANCE inst = CONTAINING_RECORD(entry, WKD_MODULE_INSTANCE, ListEntry);
        PVOID imageBase = inst->ImageBase;
        SIZE_T size = inst->Module->ImageSize;

        if (size > 0 &&
            (ULONG_PTR)Address >= (ULONG_PTR)imageBase &&
            (ULONG_PTR)Address <  (ULONG_PTR)imageBase + size) {
            *Instance = inst;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

/**************************************************/
/*  2026-08-11 S5：旧 Mt API（MtAddModuleEx /      */
/*  MtAddModule / MtFindModuleByPath /             */
/*  MtpExtractFileName）已删除——全局镜像对象重构   */
/*  完成后无调用者，模块挂接统一走                 */
/*  PsFindOrCreateModule + PsModuleAttachProcessLocked。*/
/**************************************************/

