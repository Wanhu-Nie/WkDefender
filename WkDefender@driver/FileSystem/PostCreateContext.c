/*
 * WkDefender - PostCreate 上下文模块（迁移 ShadowStrike PostCreate.c）
 *
 * 迁移说明（重功能实现非复制）：
 *   - 主回调 FsPostCreateNotifyCallback：create 成功后挂 FLT_STREAM_CONTEXT（文件标识/属性
 *     分类/verdict 关联/变更基线）+ FLT_STREAMHANDLE_CONTEXT（per-open）
 *   - CompletionContext：能力模块 FsPreCreateNotifyCallback（FileSystem\PreCreate.c）同步扫描后
 *     分配（verdict/评分），经 FLT_PREOP_SUCCESS_WITH_CALLBACK 传递，本模块消费并释放（lookaside+防双释）
 *   - 修改闭环：薄层 FspPreWrite/FsPreSetInformationNotifyCallback 经 WkdPocMarkFileModified /
 *     WkdPocInvalidateFileVerdict 置 Dirty → verdict 失效 → 后续 create/cleanup
 *     经 WkdPocHasFreshVerdict 判定重扫
 *   - 卷实例 context / BeEngineSubmitEvent / RansomwareMonitored 等在 wkd 无对应，
 *     裁剪（勒索评分归 ProcessFileContext；ThreatScore 仅记录）
 *
 * IRQL 纪律（FSC-1）：Post-op 回调可运行至 DISPATCH（draining），
 * 主回调入口必须非分页；DRAINING/IRQL 守卫先于 PAGED_CODE()。
 */

#include "FileSystem.h"   /* 内部私有头（2026-09-13 重构）：include 公共头 + 内部结构 */

/* ========================================================================== */
/* 私有常量/结构                                                               */
/* ========================================================================== */

typedef struct _WKD_POC_EXTENSION_ENTRY {
    PCWSTR Extension;
    WKD_POC_FILE_CLASS Class;
} WKD_POC_EXTENSION_ENTRY;

/* ========================================================================== */
/* 全局状态                                                                    */
/* ========================================================================== */

static struct {
    volatile LONG Initialized;
    volatile LONG ShutdownRequested;

    /* lookaside（仅 completion context；stream/handle 经 FltAllocateContext） */
    NPAGED_LOOKASIDE_LIST CompletionLookaside;
    BOOLEAN LookasideInitialized;

    /* 限速（原子） */
    volatile LONG CurrentSecondLogs;
    volatile LONGLONG CurrentSecondStart;

    /* 配置（编译期默认，PocpInitializeDefaultConfig） */
    struct {
        BOOLEAN EnableContextCaching;   /* 名称缓存 */
        BOOLEAN EnableChangeTracking;   /* 变更跟踪（Dirty） */
        BOOLEAN EnableHandleContexts;   /* per-open handle context */
        BOOLEAN LogContextCreation;     /* 上下文创建日志（默认关） */
    } Config;

    /* 统计（全部原子） */
    struct {
        volatile LONG64 TotalPostCreates;
        volatile LONG64 ContextsCreated;
        volatile LONG64 ContextsReused;
        volatile LONG64 ContextsFailed;
        volatile LONG64 ContextsSkipped;
        volatile LONG64 DirectoriesSkipped;
        volatile LONG64 VolumeOpensSkipped;
        volatile LONG64 HandleContextsCreated;
        volatile LONG64 HandleContextsFailed;
        volatile LONG64 ScannedFiles;
        volatile LONG64 ErrorsHandled;
        volatile LONG64 SignatureMismatches;
        volatile LONG64 InvalidContexts;
        volatile LONG64 DoubleFreeAttempts;
        LARGE_INTEGER StartTime;
    } Stats;
} g_WkdPocState = { 0 };

/* ========================================================================== */
/* 扩展名分类表（迁移 SS g_ExtensionTable）                                    */
/* ========================================================================== */

static const WKD_POC_EXTENSION_ENTRY g_WkdPocExtensionTable[] = {
    /* 可执行 */
    { L"exe",   WkdPocFileClassExecutable },
    { L"dll",   WkdPocFileClassExecutable },
    { L"sys",   WkdPocFileClassExecutable },
    { L"drv",   WkdPocFileClassExecutable },
    { L"scr",   WkdPocFileClassExecutable },
    { L"com",   WkdPocFileClassExecutable },
    { L"msi",   WkdPocFileClassExecutable },
    { L"ocx",   WkdPocFileClassExecutable },
    { L"cpl",   WkdPocFileClassExecutable },

    /* 脚本 */
    { L"ps1",   WkdPocFileClassScript },
    { L"bat",   WkdPocFileClassScript },
    { L"cmd",   WkdPocFileClassScript },
    { L"vbs",   WkdPocFileClassScript },
    { L"js",    WkdPocFileClassScript },
    { L"hta",   WkdPocFileClassScript },
    { L"wsf",   WkdPocFileClassScript },

    /* 文档 */
    { L"doc",   WkdPocFileClassDocument },
    { L"docx",  WkdPocFileClassDocument },
    { L"docm",  WkdPocFileClassDocument },
    { L"xls",   WkdPocFileClassDocument },
    { L"xlsx",  WkdPocFileClassDocument },
    { L"xlsm",  WkdPocFileClassDocument },
    { L"ppt",   WkdPocFileClassDocument },
    { L"pptx",  WkdPocFileClassDocument },
    { L"pdf",   WkdPocFileClassDocument },
    { L"rtf",   WkdPocFileClassDocument },

    /* 归档 */
    { L"zip",   WkdPocFileClassArchive },
    { L"rar",   WkdPocFileClassArchive },
    { L"7z",    WkdPocFileClassArchive },
    { L"cab",   WkdPocFileClassArchive },
    { L"iso",   WkdPocFileClassArchive },
    { L"tar",   WkdPocFileClassArchive },
    { L"gz",    WkdPocFileClassArchive },

    /* 媒体 */
    { L"jpg",   WkdPocFileClassMedia },
    { L"jpeg",  WkdPocFileClassMedia },
    { L"png",   WkdPocFileClassMedia },
    { L"gif",   WkdPocFileClassMedia },
    { L"bmp",   WkdPocFileClassMedia },
    { L"mp3",   WkdPocFileClassMedia },
    { L"mp4",   WkdPocFileClassMedia },
    { L"avi",   WkdPocFileClassMedia },
    { L"mkv",   WkdPocFileClassMedia },

    /* 配置 */
    { L"ini",   WkdPocFileClassConfig },
    { L"cfg",   WkdPocFileClassConfig },
    { L"conf",  WkdPocFileClassConfig },
    { L"xml",   WkdPocFileClassConfig },
    { L"json",  WkdPocFileClassConfig },
    { L"yaml",  WkdPocFileClassConfig },

    /* 证书 */
    { L"pem",   WkdPocFileClassCertificate },
    { L"pfx",   WkdPocFileClassCertificate },
    { L"p12",   WkdPocFileClassCertificate },
    { L"cer",   WkdPocFileClassCertificate },
    { L"crt",   WkdPocFileClassCertificate },
    { L"key",   WkdPocFileClassCertificate },

    /* 数据库 */
    { L"mdb",   WkdPocFileClassDatabase },
    { L"accdb", WkdPocFileClassDatabase },
    { L"sqlite",WkdPocFileClassDatabase },
    { L"db",    WkdPocFileClassDatabase },
    { L"sql",   WkdPocFileClassDatabase },

    /* 备份 */
    { L"bak",   WkdPocFileClassBackup },
    { L"backup",WkdPocFileClassBackup },
    { L"old",   WkdPocFileClassBackup },

    /* 日志 */
    { L"log",   WkdPocFileClassLog },
    { L"evt",   WkdPocFileClassLog },
    { L"evtx",  WkdPocFileClassLog },

    /* 临时 */
    { L"tmp",   WkdPocFileClassTemporary },
    { L"temp",  WkdPocFileClassTemporary },
};

#define WKD_POC_EXTENSION_TABLE_COUNT \
    (sizeof(g_WkdPocExtensionTable) / sizeof(g_WkdPocExtensionTable[0]))

/* ========================================================================== */
/* 前向声明                                                                    */
/* ========================================================================== */

static BOOLEAN
WkdPocpShouldLogOperation(
    VOID
    );

static NTSTATUS
FspQueryFileInformation(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PLONGLONG OutFileId,
    _Out_ PLONGLONG OutFileSize,
    _Out_ PLARGE_INTEGER OutLastWriteTime,
    _Out_ PLARGE_INTEGER OutCreationTime
    );

static NTSTATUS
WkdPocpQueryVolumeSerial(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PULONG OutSerial
    );

static VOID
WkdPocpSetTrackingFlags(
    _Inout_ PWKD_POC_STREAM_CONTEXT Context,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PFLT_FILE_NAME_INFORMATION NameInfo
    );

static NTSTATUS
WkdPocpCreateHandleContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PWKD_POC_HANDLE_CONTEXT* OutContext
    );

static NTSTATUS
FspQueryFileAttributes(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PWKD_POC_STREAM_CONTEXT Context
    );

static VOID
WkdPocpCacheFileName(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _Inout_ PWKD_POC_STREAM_CONTEXT Context
    );

static WKD_POC_FILE_CLASS
WkdPocpClassifyFileExtension(
    _In_opt_ PCUNICODE_STRING Extension
    );

/* ASCII 大小写不敏感宽串比较（DISPATCH_LEVEL 安全，不触分页内存） */
FORCEINLINE
LONG
WkdPocpCompareExtensionSafe(
    _In_ PCWSTR Ext1,
    _In_ PCWSTR Ext2
    )
{
    while (*Ext1 && *Ext2) {
        WCHAR c1 = *Ext1;
        WCHAR c2 = *Ext2;

        if (c1 >= L'A' && c1 <= L'Z') {
            c1 = c1 + (L'a' - L'A');
        }
        if (c2 >= L'A' && c2 <= L'Z') {
            c2 = c2 + (L'a' - L'A');
        }
        if (c1 != c2) {
            return (LONG)(c1 - c2);
        }
        Ext1++;
        Ext2++;
    }
    return (LONG)(*Ext1 - *Ext2);
}

FORCEINLINE
LONG64
WkdPocAtomicRead64(
    _In_ volatile LONG64* Target
    )
{
    return InterlockedCompareExchange64(Target, 0, 0);
}

/* ========================================================================== */
/* 初始化 / 关闭                                                               */
/* ========================================================================== */

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdPocInitialize(
    VOID
    )
{
    LONG previousValue;
    LARGE_INTEGER currentTime;

    PAGED_CODE();

    previousValue = InterlockedCompareExchange(&g_WkdPocState.Initialized, 1, 0);
    if (previousValue != 0) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_WkdPocState.Stats, sizeof(g_WkdPocState.Stats));
    RtlZeroMemory(&g_WkdPocState.Config, sizeof(g_WkdPocState.Config));

    InterlockedExchange(&g_WkdPocState.ShutdownRequested, 0);
    g_WkdPocState.LookasideInitialized = FALSE;

    ExInitializeNPagedLookasideList(
        &g_WkdPocState.CompletionLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(WKD_POC_COMPLETION_CONTEXT),
        WKD_POC_POOL_TAG,
        WKD_POC_COMPLETION_LOOKASIDE_DEPTH
        );
    g_WkdPocState.LookasideInitialized = TRUE;

    /* 默认配置（PocpInitializeDefaultConfig） */
    g_WkdPocState.Config.EnableContextCaching = TRUE;
    g_WkdPocState.Config.EnableChangeTracking = TRUE;
    g_WkdPocState.Config.EnableHandleContexts = TRUE;
    g_WkdPocState.Config.LogContextCreation = FALSE;

    KeQuerySystemTime(&g_WkdPocState.Stats.StartTime);

    KeQuerySystemTime(&currentTime);
    InterlockedExchange64(&g_WkdPocState.CurrentSecondStart, currentTime.QuadPart);
    InterlockedExchange(&g_WkdPocState.CurrentSecondLogs, 0);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender/POC] PostCreate context subsystem initialized\n");
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdPocShutdown(
    VOID
    )
{
    LONG wasInitialized;

    PAGED_CODE();

    wasInitialized = InterlockedExchange(&g_WkdPocState.Initialized, 0);
    if (wasInitialized == 0) {
        return;
    }

    InterlockedExchange(&g_WkdPocState.ShutdownRequested, 1);

    /* 先置不可用再删除 lookaside（防 in-flight WkdPocFreeCompletionContext） */
    if (g_WkdPocState.LookasideInitialized) {
        g_WkdPocState.LookasideInitialized = FALSE;
        MemoryBarrier();
        ExDeleteNPagedLookasideList(&g_WkdPocState.CompletionLookaside);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender/POC] PostCreate shutdown. "
        "Total=%lld, Created=%lld, Reused=%lld, Failed=%lld\n",
        WkdPocAtomicRead64(&g_WkdPocState.Stats.TotalPostCreates),
        WkdPocAtomicRead64(&g_WkdPocState.Stats.ContextsCreated),
        WkdPocAtomicRead64(&g_WkdPocState.Stats.ContextsReused),
        WkdPocAtomicRead64(&g_WkdPocState.Stats.ContextsFailed));
}

/* ========================================================================== */
/* CompletionContext（lookaside + 所有权防双释）                               */
/* ========================================================================== */

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
WkdPocAllocateCompletionContext(
    _Out_ PWKD_POC_COMPLETION_CONTEXT* OutContext
    )
{
    PWKD_POC_COMPLETION_CONTEXT context;

    PAGED_CODE();

    if (OutContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutContext = NULL;

    if (*(volatile LONG*)&g_WkdPocState.Initialized != 1 ||
        !g_WkdPocState.LookasideInitialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    context = (PWKD_POC_COMPLETION_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_WkdPocState.CompletionLookaside);
    if (context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(context, sizeof(WKD_POC_COMPLETION_CONTEXT));
    context->Signature = WKD_POC_COMPLETION_SIGNATURE;
    context->SecurityCookie = WkdPocComputeSecurityCookie(context);
    context->OwnershipToken = 1;
    KeQuerySystemTime(&context->PreCreateTime);

    *OutContext = context;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdPocFreeCompletionContext(
    _Inout_ PWKD_POC_COMPLETION_CONTEXT* Context
    )
{
    PWKD_POC_COMPLETION_CONTEXT ctx;
    LONG previousOwner;

    if (Context == NULL || *Context == NULL) {
        return;
    }

    ctx = *Context;
    *Context = NULL;   /* 防调用方释放后用 */

    if (ctx->Signature != WKD_POC_COMPLETION_SIGNATURE) {
        InterlockedIncrement64(&g_WkdPocState.Stats.SignatureMismatches);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender/POC] Invalid completion context signature: 0x%08X\n",
            ctx->Signature);
        return;   /* 不释放未知内存 */
    }

    previousOwner = InterlockedCompareExchange(&ctx->OwnershipToken, 0, 1);
    if (previousOwner != 1) {
        InterlockedIncrement64(&g_WkdPocState.Stats.DoubleFreeAttempts);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender/POC] Double-free attempt on completion context\n");
        return;
    }

    ctx->Signature = 0;   /* 捕获 use-after-free */

    if (g_WkdPocState.LookasideInitialized) {
        ExFreeToNPagedLookasideList(&g_WkdPocState.CompletionLookaside, ctx);
    }
}

/* ========================================================================== */
/* 主回调：FsPostCreateNotifyCallback                                                   */
/* ========================================================================== */

_Use_decl_annotations_
FLT_POSTOP_CALLBACK_STATUS
FsPostCreateNotifyCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++
 * 主回调（ShadowStrikePostCreate Phase 1-11）：
 *   1. create 成功后挂 stream context（文件标识/属性/分类/verdict 关联/变更基线）
 *   2. 可选挂 handle context（per-open）
 *   3. 成功路径不阻断（恒 FLT_POSTOP_FINISHED_PROCESSING）
 *--*/
{
    NTSTATUS status;
    PWKD_POC_STREAM_CONTEXT streamContext = NULL;
    PWKD_POC_STREAM_CONTEXT existingContext = NULL;
    PWKD_POC_COMPLETION_CONTEXT completionCtx = NULL;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    LONGLONG fileId = 0;
    LONGLONG fileSize = 0;
    LARGE_INTEGER lastWriteTime = { 0 };
    LARGE_INTEGER creationTime = { 0 };
    WKD_POC_FILE_CLASS fileClass = WkdPocFileClassUnknown;
    ULONG volumeSerial = 0;

    /* FSC-1（关键）：draining/IRQL 守卫必须先于 PAGED_CODE()。
     * Post-op 回调在 draining 时可运行于 DISPATCH_LEVEL。 */
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PAGED_CODE();

    InterlockedIncrement64(&g_WkdPocState.Stats.TotalPostCreates);

    /* 模块就绪守卫（对齐 SS：Initialized/ShutdownRequested 原子读） */
    if (*(volatile LONG*)&g_WkdPocState.Initialized != 1) {
        goto Cleanup;
    }
    if (*(volatile LONG*)&g_WkdPocState.ShutdownRequested != 0) {
        goto Cleanup;
    }

    /* boot 期防御：PreCreate 在 boot 窗口内已跳过扫描（无 completion 分配），
     * 此处兜底跳过上下文挂载（防御性，保 boot 速度）。completion 若泄漏至此
     * 将在 Cleanup 释放。 */
    if (WkdFspIsBootPhase()) {
        goto Cleanup;
    }

    /* filter 句柄校验（FltAllocateContext 依赖） */
    if (WkdFsGetFilterHandle() == NULL) {
        InterlockedIncrement64(&g_WkdPocState.Stats.ErrorsHandled);
        goto Cleanup;
    }

    /* 仅处理 create 成功路径 */
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        goto Cleanup;
    }

    /* 对象校验 */
    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        InterlockedIncrement64(&g_WkdPocState.Stats.ContextsSkipped);
        goto Cleanup;
    }

    /* 目录跳过（仅跟踪文件） */
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        InterlockedIncrement64(&g_WkdPocState.Stats.DirectoriesSkipped);
        goto Cleanup;
    }

    /* 卷打开跳过 */
    if (FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {
        InterlockedIncrement64(&g_WkdPocState.Stats.VolumeOpensSkipped);
        goto Cleanup;
    }

    /* ===================================================================== */
    /* PHASE 2：校验 completion context（verdict 传递）                      */
    /* ===================================================================== */

    if (CompletionContext != NULL) {
        completionCtx = (PWKD_POC_COMPLETION_CONTEXT)CompletionContext;
        if (!WkdPocIsValidCompletionContext(completionCtx)) {
            InterlockedIncrement64(&g_WkdPocState.Stats.InvalidContexts);
            completionCtx = NULL;
        }
    }

    /* ===================================================================== */
    /* PHASE 3：复用已有 stream context                                      */
    /* ===================================================================== */

    status = FltGetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&existingContext);

    if (NT_SUCCESS(status)) {
        /* 已有上下文：应用 verdict（若本次已扫描）+ 更新访问计数 */
        InterlockedIncrement64(&g_WkdPocState.Stats.ContextsReused);

        if (completionCtx != NULL && completionCtx->WasScanned) {
            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&existingContext->Lock);

            existingContext->Scanned = TRUE;
            existingContext->ScanResult = completionCtx->ScanResult;
            existingContext->ThreatScore = completionCtx->ThreatScore;
            KeQuerySystemTime(&existingContext->ScanTime);
            existingContext->TrackingFlags |= WkdPocTrackingScanned;

            ExReleasePushLockExclusive(&existingContext->Lock);
            KeLeaveCriticalRegion();

            InterlockedIncrement64(&g_WkdPocState.Stats.ScannedFiles);
        }

        KeQuerySystemTime(&existingContext->LastAccessTime);
        InterlockedIncrement(&existingContext->OpenCount);

        FltReleaseContext((PFLT_CONTEXT)existingContext);
        existingContext = NULL;

        goto CreateHandleContext;
    }

    /* ===================================================================== */
    /* PHASE 4：分配新 stream context                                       */
    /* ===================================================================== */

    status = FltAllocateContext(
        WkdFsGetFilterHandle(),
        FLT_STREAM_CONTEXT,
        sizeof(WKD_POC_STREAM_CONTEXT),
        NonPagedPoolNx,
        (PFLT_CONTEXT*)&streamContext);

    if (!NT_SUCCESS(status)) {
        /* 非致命：分配失败只是不跟踪此文件 */
        InterlockedIncrement64(&g_WkdPocState.Stats.ContextsFailed);
        if (WkdPocpShouldLogOperation()) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[WkDefender/POC] Context allocation failed: 0x%08X\n", status);
        }
        goto Cleanup;
    }

    RtlZeroMemory(streamContext, sizeof(WKD_POC_STREAM_CONTEXT));
    streamContext->Signature = FLT_STREAM_CONTEXT_SIGNATURE;
    streamContext->SecurityCookie = WkdPocComputeSecurityCookie(streamContext);
    ExInitializePushLock(&streamContext->Lock);
    KeQuerySystemTime(&streamContext->ContextCreateTime);
    KeQuerySystemTime(&streamContext->LastAccessTime);
    streamContext->OpenCount = 1;

    /* ===================================================================== */
    /* PHASE 5：采集文件信息（FileId/大小/时间戳/卷序列号）                   */
    /* ===================================================================== */

    status = FspQueryFileInformation(
        FltObjects, &fileId, &fileSize, &lastWriteTime, &creationTime);
    if (NT_SUCCESS(status)) {
        streamContext->FileId = fileId;
        streamContext->ScanFileSize = fileSize;
        streamContext->LastWriteTime = lastWriteTime;
        streamContext->CreationTime = creationTime;
    }

    status = WkdPocpQueryVolumeSerial(FltObjects, &volumeSerial);
    if (NT_SUCCESS(status)) {
        streamContext->VolumeSerial = volumeSerial;
    }

    /* ===================================================================== */
    /* PHASE 6：名称获取/分类/tracking 标志                                  */
    /* ===================================================================== */

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(nameInfo);
        if (NT_SUCCESS(status)) {
            if (g_WkdPocState.Config.EnableContextCaching) {
                WkdPocpCacheFileName(nameInfo, streamContext);
            }

            fileClass = WkdPocpClassifyFileExtension(&nameInfo->Extension);
            streamContext->FileClass = fileClass;

            WkdPocpSetTrackingFlags(streamContext, FltObjects, nameInfo);
        }
    }

    /* ===================================================================== */
    /* PHASE 7：应用 verdict（completion context）                           */
    /* ===================================================================== */

    if (completionCtx != NULL && completionCtx->WasScanned) {
        streamContext->Scanned = TRUE;
        streamContext->ScanResult = completionCtx->ScanResult;
        streamContext->ThreatScore = completionCtx->ThreatScore;
        KeQuerySystemTime(&streamContext->ScanTime);
        streamContext->TrackingFlags |= WkdPocTrackingScanned;
        InterlockedIncrement64(&g_WkdPocState.Stats.ScannedFiles);

        /* 注：SS 此处上送 BeEngineSubmitEvent（ThreatScore>0）。wkd 无对应
         * 事件（SS 该分支属预留相位，completion 实际为 NULL），评分仅记录。 */

        if (g_WkdPocState.Config.LogContextCreation &&
            WkdPocpShouldLogOperation()) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WkDefender/POC] Context created with verdict: "
                "FileId=0x%llX, Score=%u, Class=%d\n",
                fileId, completionCtx->ThreatScore, fileClass);
        }
    }

    /* ===================================================================== */
    /* PHASE 8：属性缓存（非致命）                                            */
    /* ===================================================================== */

    status = FspQueryFileAttributes(FltObjects, streamContext);

    /* ===================================================================== */
    /* PHASE 9：挂载 stream context（KEEP_IF_EXISTS 处理并发竞争）            */
    /* ===================================================================== */

    status = FltSetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        (PFLT_CONTEXT)streamContext,
        (PFLT_CONTEXT*)&existingContext);

    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        /* 并发：其他线程已挂载，复用其上下文并回填 verdict */
        InterlockedIncrement64(&g_WkdPocState.Stats.ContextsReused);

        if (existingContext != NULL) {
            if (completionCtx != NULL && completionCtx->WasScanned) {
                KeEnterCriticalRegion();
                ExAcquirePushLockExclusive(&existingContext->Lock);

                existingContext->Scanned = TRUE;
                existingContext->ScanResult = completionCtx->ScanResult;
                existingContext->ThreatScore = completionCtx->ThreatScore;
                KeQuerySystemTime(&existingContext->ScanTime);

                ExReleasePushLockExclusive(&existingContext->Lock);
                KeLeaveCriticalRegion();
            }
            FltReleaseContext((PFLT_CONTEXT)existingContext);
            existingContext = NULL;
        }
    } else if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_WkdPocState.Stats.ContextsCreated);
    } else {
        /* 挂载失败：非致命 */
        InterlockedIncrement64(&g_WkdPocState.Stats.ContextsFailed);
        InterlockedIncrement64(&g_WkdPocState.Stats.ErrorsHandled);
        if (WkdPocpShouldLogOperation()) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[WkDefender/POC] FltSetStreamContext failed: 0x%08X\n", status);
        }
    }

    /* ===================================================================== */
    /* PHASE 10：handle context（per-open，可选）                             */
    /* ===================================================================== */

CreateHandleContext:
    if (g_WkdPocState.Config.EnableHandleContexts) {
        PWKD_POC_HANDLE_CONTEXT handleContext = NULL;

        status = WkdPocpCreateHandleContext(FltObjects, Data, &handleContext);
        if (NT_SUCCESS(status) && handleContext != NULL) {
            /* set 成功后 fltmgr 持有引用，释放我们的 */
            FltReleaseContext((PFLT_CONTEXT)handleContext);
            handleContext = NULL;
        }
    }

    /* ===================================================================== */
    /* CLEANUP                                                                 */
    /* ===================================================================== */

Cleanup:
    if (nameInfo != NULL) {
        FltReleaseFileNameInformation(nameInfo);
        nameInfo = NULL;
    }

    if (streamContext != NULL) {
        /* FltSetStreamContext 成功后 fltmgr 持有引用；此处释放本次引用 */
        FltReleaseContext((PFLT_CONTEXT)streamContext);
        streamContext = NULL;
    }

    if (completionCtx != NULL) {
        WkdPocFreeCompletionContext(&completionCtx);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ========================================================================== */
/* handle context（per-open；PocGetOrCreateHandleContext）            */
/* ========================================================================== */

static NTSTATUS
WkdPocpCreateHandleContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PWKD_POC_HANDLE_CONTEXT* OutContext
    )
{
    NTSTATUS status;
    PWKD_POC_HANDLE_CONTEXT context = NULL;
    PWKD_POC_HANDLE_CONTEXT existingContext = NULL;

    PAGED_CODE();

    if (FltObjects == NULL || Data == NULL || OutContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutContext = NULL;

    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (WkdFsGetFilterHandle() == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    /* 已有则直接复用 */
    status = FltGetStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&context);
    if (NT_SUCCESS(status)) {
        if (WkdPocIsValidHandleContext(context)) {
            *OutContext = context;
            return STATUS_SUCCESS;
        }
        InterlockedIncrement64(&g_WkdPocState.Stats.InvalidContexts);
        FltReleaseContext((PFLT_CONTEXT)context);
        context = NULL;
    }

    /* 分配（必须 FltAllocateContext：FltSetStreamHandleContext 要求
     * filter-managed context，不能用 lookaside 裸池） */
    status = FltAllocateContext(
        WkdFsGetFilterHandle(),
        FLT_STREAMHANDLE_CONTEXT,
        sizeof(WKD_POC_HANDLE_CONTEXT),
        NonPagedPoolNx,
        (PFLT_CONTEXT*)&context);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_WkdPocState.Stats.HandleContextsFailed);
        return status;
    }

    RtlZeroMemory(context, sizeof(WKD_POC_HANDLE_CONTEXT));
    context->Signature = WKD_POC_HANDLE_CONTEXT_SIGNATURE;
    context->SecurityCookie = WkdPocComputeSecurityCookie(context);
    ExInitializePushLock(&context->Lock);
    context->ProcessId = PsGetCurrentProcessId();
    context->ThreadId = PsGetCurrentThreadId();

    /* 安全：内核发起打开（IoCreateFileEx/NtCreateSection 图像映射路径）时
     * SecurityContext 可为 NULL——无 NULL 守卫会 BSOD。缺省补零。 */
    if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        context->DesiredAccess =
            Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    } else {
        context->DesiredAccess = 0;
    }
    context->CreateOptions =
        Data->Iopb->Parameters.Create.Options & FILE_VALID_OPTION_FLAGS;
    context->ShareAccess = Data->Iopb->Parameters.Create.ShareAccess;
    KeQuerySystemTime(&context->OpenTime);

    status = FltSetStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        (PFLT_CONTEXT)context,
        (PFLT_CONTEXT*)&existingContext);

    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        FltReleaseContext((PFLT_CONTEXT)context);
        context = NULL;
        if (existingContext != NULL && WkdPocIsValidHandleContext(existingContext)) {
            *OutContext = existingContext;
            return STATUS_SUCCESS;
        }
        if (existingContext != NULL) {
            InterlockedIncrement64(&g_WkdPocState.Stats.InvalidContexts);
            FltReleaseContext((PFLT_CONTEXT)existingContext);
        }
        return STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(status)) {
        FltReleaseContext((PFLT_CONTEXT)context);
        context = NULL;
        InterlockedIncrement64(&g_WkdPocState.Stats.HandleContextsFailed);
        return status;
    }

    InterlockedIncrement64(&g_WkdPocState.Stats.HandleContextsCreated);
    *OutContext = context;
    return STATUS_SUCCESS;
}

/* ========================================================================== */
/* 修改跟踪（薄层 PreWrite/PreSetInformation/Cleanup 消费）                   */
/* ========================================================================== */

_IRQL_requires_max_(APC_LEVEL)
VOID
WkdPocMarkFileModified(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    PWKD_POC_STREAM_CONTEXT ctx = NULL;
    NTSTATUS status;

    PAGED_CODE();

    if (FltObjects == NULL || FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL) {
        return;
    }
    if (*(volatile LONG*)&g_WkdPocState.Initialized != 1) {
        return;
    }

    status = FltGetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&ctx);
    if (!NT_SUCCESS(status) || ctx == NULL) {
        return;   /* 无上下文：未挂载（如非可扫扩展名），无需跟踪 */
    }

    if (!FsCheckStreamContextValidity(ctx)) {
        InterlockedIncrement64(&g_WkdPocState.Stats.InvalidContexts);
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&ctx->Lock);

    ctx->Dirty = TRUE;
    ctx->TrackingFlags |= WkdPocTrackingModified;
    if (ctx->FirstWriteTime.QuadPart == 0) {
        KeQuerySystemTime(&ctx->FirstWriteTime);
    }
    KeQuerySystemTime(&ctx->LastModifyTime);
    InterlockedIncrement(&ctx->WriteCount);

    ExReleasePushLockExclusive(&ctx->Lock);
    KeLeaveCriticalRegion();

    FltReleaseContext((PFLT_CONTEXT)ctx);
}

_IRQL_requires_max_(APC_LEVEL)
VOID
WkdPocInvalidateFileVerdict(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    PWKD_POC_STREAM_CONTEXT ctx = NULL;
    NTSTATUS status;

    PAGED_CODE();

    if (FltObjects == NULL || FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL) {
        return;
    }
    if (*(volatile LONG*)&g_WkdPocState.Initialized != 1) {
        return;
    }

    status = FltGetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&ctx);
    if (!NT_SUCCESS(status) || ctx == NULL) {
        return;
    }

    if (!FsCheckStreamContextValidity(ctx)) {
        InterlockedIncrement64(&g_WkdPocState.Stats.InvalidContexts);
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&ctx->Lock);

    ctx->Scanned = FALSE;
    ctx->Dirty = TRUE;
    ctx->TrackingFlags &= ~WkdPocTrackingScanned;
    ctx->TrackingFlags &= ~WkdPocTrackingCached;
    ctx->TrackingFlags |= WkdPocTrackingModified;

    ExReleasePushLockExclusive(&ctx->Lock);
    KeLeaveCriticalRegion();

    FltReleaseContext((PFLT_CONTEXT)ctx);
}

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WkdPocHasFreshVerdict(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    PWKD_POC_STREAM_CONTEXT ctx = NULL;
    NTSTATUS status;
    BOOLEAN fresh = FALSE;

    PAGED_CODE();

    if (FltObjects == NULL || FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL) {
        return FALSE;
    }
    if (*(volatile LONG*)&g_WkdPocState.Initialized != 1) {
        return FALSE;
    }

    status = FltGetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&ctx);
    if (!NT_SUCCESS(status) || ctx == NULL) {
        return FALSE;
    }

    if (FsCheckStreamContextValidity(ctx) && !WkdPocNeedsRescan(ctx)) {
        fresh = TRUE;
    }

    FltReleaseContext((PFLT_CONTEXT)ctx);
    return fresh;
}

/* ========================================================================== */
/* 统计                                                                        */
/* ========================================================================== */

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WkdPocGetStatistics(
    _Out_opt_ PULONG64 TotalPostCreates,
    _Out_opt_ PULONG64 ContextsCreated,
    _Out_opt_ PULONG64 ContextsReused,
    _Out_opt_ PULONG64 ContextsFailed
    )
{
    if (TotalPostCreates != NULL) {
        *TotalPostCreates = (ULONG64)WkdPocAtomicRead64(
            &g_WkdPocState.Stats.TotalPostCreates);
    }
    if (ContextsCreated != NULL) {
        *ContextsCreated = (ULONG64)WkdPocAtomicRead64(
            &g_WkdPocState.Stats.ContextsCreated);
    }
    if (ContextsReused != NULL) {
        *ContextsReused = (ULONG64)WkdPocAtomicRead64(
            &g_WkdPocState.Stats.ContextsReused);
    }
    if (ContextsFailed != NULL) {
        *ContextsFailed = (ULONG64)WkdPocAtomicRead64(
            &g_WkdPocState.Stats.ContextsFailed);
    }
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WkdPocGetErrorStatistics(
    _Out_opt_ PULONG64 SignatureMismatches,
    _Out_opt_ PULONG64 InvalidContexts,
    _Out_opt_ PULONG64 DoubleFreeAttempts
    )
{
    if (SignatureMismatches != NULL) {
        *SignatureMismatches = (ULONG64)WkdPocAtomicRead64(
            &g_WkdPocState.Stats.SignatureMismatches);
    }
    if (InvalidContexts != NULL) {
        *InvalidContexts = (ULONG64)WkdPocAtomicRead64(
            &g_WkdPocState.Stats.InvalidContexts);
    }
    if (DoubleFreeAttempts != NULL) {
        *DoubleFreeAttempts = (ULONG64)WkdPocAtomicRead64(
            &g_WkdPocState.Stats.DoubleFreeAttempts);
    }
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
VOID
WkdPocResetStatistics(
    VOID
    )
{
    PAGED_CODE();

    InterlockedExchange64(&g_WkdPocState.Stats.TotalPostCreates, 0);
    InterlockedExchange64(&g_WkdPocState.Stats.ContextsCreated, 0);
    InterlockedExchange64(&g_WkdPocState.Stats.ContextsReused, 0);
    InterlockedExchange64(&g_WkdPocState.Stats.ContextsFailed, 0);
    InterlockedExchange64(&g_WkdPocState.Stats.ContextsSkipped, 0);
    InterlockedExchange64(&g_WkdPocState.Stats.DirectoriesSkipped, 0);
    InterlockedExchange64(&g_WkdPocState.Stats.VolumeOpensSkipped, 0);
    InterlockedExchange64(&g_WkdPocState.Stats.HandleContextsCreated, 0);
    InterlockedExchange64(&g_WkdPocState.Stats.HandleContextsFailed, 0);
    InterlockedExchange64(&g_WkdPocState.Stats.ScannedFiles, 0);
    InterlockedExchange64(&g_WkdPocState.Stats.ErrorsHandled, 0);
    InterlockedExchange64(&g_WkdPocState.Stats.SignatureMismatches, 0);
    InterlockedExchange64(&g_WkdPocState.Stats.InvalidContexts, 0);
    InterlockedExchange64(&g_WkdPocState.Stats.DoubleFreeAttempts, 0);
    KeQuerySystemTime(&g_WkdPocState.Stats.StartTime);
}

/* ========================================================================== */
/* 私有工具                                                                    */
/* ========================================================================== */

/* 限速：每秒最多 WKD_POC_LOG_RATE_LIMIT_PER_SEC 条日志（对齐 SS） */
static BOOLEAN
WkdPocpShouldLogOperation(
    VOID
    )
{
    LARGE_INTEGER currentTime;
    LONGLONG secondStart;
    LONGLONG elapsed;

    KeQuerySystemTime(&currentTime);
    secondStart = WkdPocAtomicRead64(&g_WkdPocState.CurrentSecondStart);
    elapsed = currentTime.QuadPart - secondStart;

    if (elapsed >= WKD_POC_ONE_SECOND_100NS) {
        if (InterlockedCompareExchange64(
                &g_WkdPocState.CurrentSecondStart,
                currentTime.QuadPart,
                secondStart) == secondStart) {
            InterlockedExchange(&g_WkdPocState.CurrentSecondLogs, 0);
        }
    }

    if (g_WkdPocState.CurrentSecondLogs >= WKD_POC_LOG_RATE_LIMIT_PER_SEC) {
        return FALSE;
    }
    InterlockedIncrement(&g_WkdPocState.CurrentSecondLogs);
    return TRUE;
}

/* 采集 FileId/大小/最后写时间/创建时间（PocpQueryFileInformation） */
static NTSTATUS
FspQueryFileInformation(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PLONGLONG OutFileId,
    _Out_ PLONGLONG OutFileSize,
    _Out_ PLARGE_INTEGER OutLastWriteTime,
    _Out_ PLARGE_INTEGER OutCreationTime
    )
{
    NTSTATUS status;
    FILE_STANDARD_INFORMATION stdInfo;
    FILE_INTERNAL_INFORMATION internalInfo;
    FILE_BASIC_INFORMATION basicInfo;

    PAGED_CODE();

    *OutFileId = 0;
    *OutFileSize = 0;
    OutLastWriteTime->QuadPart = 0;
    OutCreationTime->QuadPart = 0;

    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &stdInfo,
        sizeof(stdInfo),
        FileStandardInformation,
        NULL);
    if (NT_SUCCESS(status)) {
        *OutFileSize = stdInfo.EndOfFile.QuadPart;
    }

    /* ---- 获取文件ID!!! ---- */
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &internalInfo,
        sizeof(internalInfo),
        FileInternalInformation,
        NULL);
    if (NT_SUCCESS(status)) {
        *OutFileId = internalInfo.IndexNumber.QuadPart;
    }

    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &basicInfo,
        sizeof(basicInfo),
        FileBasicInformation,
        NULL);
    if (NT_SUCCESS(status)) {
        *OutLastWriteTime = basicInfo.LastWriteTime;
        *OutCreationTime = basicInfo.CreationTime;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
WkdPocpQueryVolumeSerial(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PULONG OutSerial
    )
{
    NTSTATUS status;
    UCHAR buffer[sizeof(FILE_FS_VOLUME_INFORMATION) + 256 * sizeof(WCHAR)];
    PFILE_FS_VOLUME_INFORMATION volumeInfo;
    ULONG bytesReturned;

    PAGED_CODE();

    *OutSerial = 0;

    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    volumeInfo = (PFILE_FS_VOLUME_INFORMATION)buffer;
    status = FltQueryVolumeInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        volumeInfo,
        sizeof(buffer),
        FileFsVolumeInformation,
        &bytesReturned);
    if (NT_SUCCESS(status)) {
        *OutSerial = volumeInfo->VolumeSerialNumber;
    }
    return status;
}

/* 卷类型（网络/可移除）+ ADS 冒号检测（PocpSetTrackingFlags） */
static VOID
WkdPocpSetTrackingFlags(
    _Inout_ PWKD_POC_STREAM_CONTEXT Context,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PFLT_FILE_NAME_INFORMATION NameInfo
    )
{
    FLT_VOLUME_PROPERTIES volumeProps;
    ULONG bytesReturned;
    NTSTATUS status;

    PAGED_CODE();

    if (Context == NULL) {
        return;
    }

    if (FltObjects->Volume != NULL) {
        status = FltGetVolumeProperties(
            FltObjects->Volume,
            &volumeProps,
            sizeof(volumeProps),
            &bytesReturned);
        if (NT_SUCCESS(status)) {
            if (volumeProps.DeviceCharacteristics & FILE_REMOTE_DEVICE) {
                Context->TrackingFlags |= WkdPocTrackingNetwork;
            }
            if (volumeProps.DeviceCharacteristics & FILE_REMOVABLE_MEDIA) {
                Context->TrackingFlags |= WkdPocTrackingRemovable;
            }
        }
    }

    /* ADS 检测：排除盘符冒号后，路径中再出现 ':' 视为 ADS */
    if (NameInfo != NULL && NameInfo->Name.Buffer != NULL) {
        USHORT nameLen = NameInfo->Name.Length / sizeof(WCHAR);

        if (nameLen >= 5) {
            USHORT i;
            for (i = 3; i < nameLen; i++) {
                if (NameInfo->Name.Buffer[i] == L':') {
                    Context->TrackingFlags |= WkdPocTrackingAds;
                    break;
                }
            }
        }
    }
}

/* 属性缓存 + 属性类 tracking flags（PocQueryFileAttributes） */
static NTSTATUS
FspQueryFileAttributes(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PWKD_POC_STREAM_CONTEXT Context
    )
{
    NTSTATUS status;
    FILE_BASIC_INFORMATION basicInfo;

    PAGED_CODE();

    if (FltObjects == NULL || Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &basicInfo,
        sizeof(basicInfo),
        FileBasicInformation,
        NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Context->Lock);

    Context->FileAttributes = basicInfo.FileAttributes;

    // https://learn.microsoft.com/zh-cn/windows/win32/fileio/file-attribute-constants
    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_HIDDEN) {
        Context->TrackingFlags |= WkdPocTrackingHidden;
    }
    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_SYSTEM) {
        Context->TrackingFlags |= WkdPocTrackingSystem;
    }
    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_READONLY) {
        Context->TrackingFlags |= WkdPocTrackingReadOnly;
    }
    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_TEMPORARY) {
        Context->TrackingFlags |= WkdPocTrackingTemporary;
    }
    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_ENCRYPTED) {
        Context->TrackingFlags |= WkdPocTrackingEncrypted;
    }
    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_COMPRESSED) {
        Context->TrackingFlags |= WkdPocTrackingCompressed;
    }
    if (basicInfo.FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) {
        Context->TrackingFlags |= WkdPocTrackingSparse;
    }

    ExReleasePushLockExclusive(&Context->Lock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/* 名称缓存（FinalComponent + 扩展名，去前导点） */
static VOID
WkdPocpCacheFileName(
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _Inout_ PWKD_POC_STREAM_CONTEXT Context
    )
{
    USHORT copyLength;

    PAGED_CODE();

    if (NameInfo == NULL || Context == NULL) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Context->Lock);

    if (NameInfo->FinalComponent.Buffer != NULL &&
        NameInfo->FinalComponent.Length > 0) {
        copyLength = min(
            NameInfo->FinalComponent.Length,
            (WKD_POC_MAX_CACHED_NAME - 1) * sizeof(WCHAR));
        RtlCopyMemory(
            Context->CachedFileName,
            NameInfo->FinalComponent.Buffer,
            copyLength);
        Context->CachedFileName[copyLength / sizeof(WCHAR)] = L'\0';
        Context->CachedFileNameLength = copyLength / sizeof(WCHAR);
    }

    if (NameInfo->Extension.Buffer != NULL && NameInfo->Extension.Length > 0) {
        PCWSTR extStart = NameInfo->Extension.Buffer;
        USHORT extLen = NameInfo->Extension.Length;

        if (extLen >= sizeof(WCHAR) && *extStart == L'.') {
            extStart++;
            extLen -= sizeof(WCHAR);
        }

        copyLength = min(extLen, (WKD_POC_MAX_CACHED_EXTENSION - 1) * sizeof(WCHAR));
        RtlCopyMemory(Context->CachedExtension, extStart, copyLength);
        Context->CachedExtension[copyLength / sizeof(WCHAR)] = L'\0';
        Context->CachedExtensionLength = copyLength / sizeof(WCHAR);
    }

    ExReleasePushLockExclusive(&Context->Lock);
    KeLeaveCriticalRegion();
}

/* 扩展名分类（查表，DISPATCH_LEVEL 安全比较） */
static WKD_POC_FILE_CLASS
WkdPocpClassifyFileExtension(
    _In_opt_ PCUNICODE_STRING Extension
    )
{
    WCHAR extBuffer[32];
    USHORT extLen;
    ULONG i;
    PCWSTR extStart;

    PAGED_CODE();

    if (Extension == NULL || Extension->Buffer == NULL || Extension->Length == 0) {
        return WkdPocFileClassUnknown;
    }

    extStart = Extension->Buffer;
    extLen = Extension->Length;

    if (extLen >= sizeof(WCHAR) && *extStart == L'.') {
        extStart++;
        extLen -= sizeof(WCHAR);
    }

    if (extLen == 0 || extLen >= sizeof(extBuffer)) {
        return WkdPocFileClassUnknown;
    }

    RtlCopyMemory(extBuffer, extStart, extLen);
    extBuffer[extLen / sizeof(WCHAR)] = L'\0';

    for (i = 0; i < WKD_POC_EXTENSION_TABLE_COUNT; i++) {
        if (WkdPocpCompareExtensionSafe(
                extBuffer, g_WkdPocExtensionTable[i].Extension) == 0) {
            return g_WkdPocExtensionTable[i].Class;
        }
    }

    return WkdPocFileClassUnknown;
}