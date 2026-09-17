/*
 * WkDefender - PostWrite 模块（原 PostWriteContext.c，2026-10 更名）
 *
 * 迁移说明（重功能实现非复制）：
 *   - 主回调 FsPostWriteNotifyCallabck：post-write 勒索行为检测（熵/双扩展/勒索扩展/
 *     蜜罐/写模式）+ 进程级评分聚合 + 告警（B3：AeReportIndicatorPair）
 *   - 进程活动表 64 槽静态（A2 决策）；C1 决策：单写算分 → 进程聚合 →
 *     超阈值（150）单次告警（IsFlagged），可疑写（≥30）限速日志
 *   - 熵：D1 决策独立计算（MDL 采样 + Shannon 查表，FSC-4 安全语义）
 *   - Dirty 置位：E1 决策保持 PreWrite 的 WkdPocMarkFileModified 承担，
 *     主回调不重复置位（写尝试即失效，多扫无害；SS 为 post 成功才置位，
 *     语义偏差见主回调注释）
 *   - 蜜罐复用 FileScan WkdFsIsHoneypotFile（同源 g_HoneypotFileNames 12 条）
 *   - 裁剪：ETW 双通道 / KTM 事务 / ScanCache 失效 / CommPort 载荷 /
 *     TeLogFileEvent / SHADOWSTRIKE_IS_READY 全局门控
 *
 * IRQL 纪律（PWR-1）：post-op 回调可运行至 DISPATCH（非缓存 I/O），
 * 入口先 DRAINING/IRQL 守卫，PAGED_CODE() 置后。
 */

#include "FileSystem.h"   /* 内部私有头（2026-09-13 重构）：include 公共头 + 内部结构 */
#include "../AnalysisEngine/AnalysisEngine.h"
#include "../ThreatScoring/ThreatScoring.h"
#include "../Common/Exempts/Exempts.h"

/* ========================================================================== */
/* 私有结构                                                                    */
/* ========================================================================== */

/* 扩展名表条目（预计算长度，避免 wcslen——PW_EXTENSION_ENTRY） */
typedef struct _WKD_PWC_EXTENSION_ENTRY {
    PCWSTR Extension;
    USHORT LengthInBytes;
    USHORT Reserved;
} WKD_PWC_EXTENSION_ENTRY;

/* 全局状态（64 槽活动表 + 限速 + 统计） */
typedef struct _WKD_PWC_GLOBAL_STATE {
    volatile LONG Initialized;
    volatile LONG ShutdownRequested;

    WKD_PWC_PROCESS_ACTIVITY ProcessActivity[WKD_PWC_MAX_TRACKED_PROCESSES];
    volatile LONG ActiveTrackers;
    EX_PUSH_LOCK ActivityLock;

    volatile LONG CurrentSecondLogs;
    LARGE_INTEGER CurrentSecondStart;
    EX_PUSH_LOCK RateLimitLock;

    BOOLEAN ProcessNotifyRegistered;
    UINT8 Reserved[7];

    struct {
        volatile LONG64 TotalPostWrites;
        volatile LONG64 HighEntropyWrites;
        volatile LONG64 DoubleExtensionWrites;
        volatile LONG64 RapidWriteDetections;
        volatile LONG64 HoneypotAccesses;
        volatile LONG64 RansomwareAlerts;
        volatile LONG64 SuspiciousOperations;
        volatile LONG64 UniqueFileModifications;
        volatile LONG64 EntropyCalculations;
        volatile LONG64 InvalidContexts;
        volatile LONG64 MissingStreamContexts;
        volatile LONG64 AllocationFailures;
    } Stats;

    LARGE_INTEGER StartTime;
} WKD_PWC_GLOBAL_STATE;

static WKD_PWC_GLOBAL_STATE g_WkdPwcState = { 0 };

/* ========================================================================== */
/* 扩展名表（迁移 SS g_KnownRansomwareExtensions / g_DoubleExtensions）        */
/* ========================================================================== */

static WKD_PWC_EXTENSION_ENTRY g_WkdPwcRansomwareExtensions[] = {
    { L".encrypted",      20, 0 },
    { L".locked",        14, 0 },
    { L".crypto",        14, 0 },
    { L".crypt",         12, 0 },
    { L".enc",            8, 0 },
    { L".locky",         12, 0 },
    { L".cerber",        14, 0 },
    { L".zepto",         12, 0 },
    { L".thor",          10, 0 },
    { L".zzzzz",         12, 0 },
    { L".micro",         12, 0 },
    { L".crypted",       16, 0 },
    { L".cryptolocker",  26, 0 },
    { L".crypz",         12, 0 },
    { L".cryp1",         12, 0 },
    { L".ransom",        14, 0 },
    { L".wncry",         12, 0 },
    { L".wcry",          10, 0 },
    { L".wncryt",        14, 0 },
    { L".onion",         12, 0 },
    { L".wallet",        14, 0 },
    { L".petya",         12, 0 },
    { L".mira",          10, 0 },
    { L".globe",         12, 0 },
    { L".dharma",        14, 0 },
    { L".arena",         12, 0 },
    { L".java",          10, 0 },
    { L".adobe",         12, 0 },
    { L".dotmap",        14, 0 },
    { L".ETH",            8, 0 },
    { L".id",             6, 0 },
    { L".CONTI",         12, 0 },
    { L".LOCKBIT",       16, 0 },
    { L".BLACKCAT",      18, 0 },
    { L".hive",          10, 0 },
    { L".cuba",          10, 0 },
};

#define WKD_PWC_RANSOMWARE_EXT_COUNT \
    (sizeof(g_WkdPwcRansomwareExtensions) / sizeof(g_WkdPwcRansomwareExtensions[0]))

static WKD_PWC_EXTENSION_ENTRY g_WkdPwcDoubleExtensions[] = {
    { L".pdf.exe",   16, 0 },
    { L".doc.exe",   16, 0 },
    { L".docx.exe",  18, 0 },
    { L".xls.exe",   16, 0 },
    { L".xlsx.exe",  18, 0 },
    { L".jpg.exe",   16, 0 },
    { L".png.exe",   16, 0 },
    { L".txt.exe",   16, 0 },
    { L".zip.exe",   16, 0 },
    { L".mp3.exe",   16, 0 },
    { L".mp4.exe",   16, 0 },
    { L".avi.exe",   16, 0 },
    { L".pdf.scr",   16, 0 },
    { L".doc.scr",   16, 0 },
    { L".jpg.scr",   16, 0 },
    { L".pdf.js",    14, 0 },
    { L".doc.js",    14, 0 },
    { L".pdf.vbs",   16, 0 },
    { L".doc.vbs",   16, 0 },
};

#define WKD_PWC_DOUBLE_EXT_COUNT \
    (sizeof(g_WkdPwcDoubleExtensions) / sizeof(g_WkdPwcDoubleExtensions[0]))

/* ========================================================================== */
/* 熵查找表（迁移 SS g_EntropyTable：Shannon 熵 ×100 整数运算）                */
/* ========================================================================== */

static const USHORT g_WkdPwcEntropyTable[257] = {
    0, 800, 700, 642, 600, 568, 542, 519, 500, 483, 468, 454, 442, 430, 419, 409,
    400, 391, 383, 375, 368, 361, 354, 348, 342, 336, 330, 325, 319, 314, 309, 305,
    300, 296, 291, 287, 283, 279, 275, 271, 268, 264, 261, 257, 254, 251, 248, 245,
    242, 239, 236, 233, 230, 227, 225, 222, 219, 217, 214, 212, 209, 207, 205, 202,
    200, 198, 196, 193, 191, 189, 187, 185, 183, 181, 179, 177, 175, 173, 171, 170,
    168, 166, 164, 162, 161, 159, 157, 156, 154, 152, 151, 149, 148, 146, 145, 143,
    142, 140, 139, 137, 136, 134, 133, 131, 130, 129, 127, 126, 125, 123, 122, 121,
    119, 118, 117, 115, 114, 113, 112, 111, 109, 108, 107, 106, 105, 103, 102, 101,
    100, 99, 98, 97, 96, 94, 93, 92, 91, 90, 89, 88, 87, 86, 85, 84,
    83, 82, 81, 80, 79, 78, 77, 76, 75, 74, 73, 72, 71, 71, 70, 69,
    68, 67, 66, 65, 64, 63, 62, 62, 61, 60, 59, 58, 57, 57, 56, 55,
    54, 53, 52, 52, 51, 50, 49, 48, 48, 47, 46, 45, 45, 44, 43, 42,
    42, 41, 40, 39, 39, 38, 37, 36, 36, 35, 34, 33, 33, 32, 31, 31,
    30, 29, 29, 28, 27, 27, 26, 25, 25, 24, 23, 23, 22, 21, 21, 20,
    19, 19, 18, 17, 17, 16, 15, 15, 14, 14, 13, 12, 12, 11, 11, 10,
    9, 9, 8, 8, 7, 6, 6, 5, 5, 4, 3, 3, 2, 2, 1, 1,
    0
};

/* ========================================================================== */
/* 前向声明                                                                    */
/* ========================================================================== */

static VOID
WkdPwcpProcessNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

static BOOLEAN
WkdPwcpShouldRateLimit(
    VOID
    );

static PWKD_PWC_PROCESS_ACTIVITY
WkdPwcpGetOrCreateProcessActivity(
    _In_ HANDLE ProcessId
    );

static VOID
WkdPwcpCleanupProcessActivity(
    _In_ HANDLE ProcessId
    );

static VOID
WkdPwcpUpdateProcessActivity(
    _Inout_ PWKD_PWC_PROCESS_ACTIVITY Activity,
    _In_ PWKD_PWC_WRITE_CONTEXT WriteContext
    );

static VOID
WkdPwcpApplyScoreDecay(
    _Inout_ PWKD_PWC_PROCESS_ACTIVITY Activity,
    _In_ PLARGE_INTEGER CurrentTime
    );

static BOOLEAN
WkdPwcpTrackUniqueFile(
    _Inout_ PWKD_PWC_PROCESS_ACTIVITY Activity,
    _In_ UINT64 FileId,
    _In_ ULONG VolumeSerial
    );

static VOID
WkdPwcpAnalyzeWritePattern(
    _In_opt_ PWKD_POC_STREAM_CONTEXT StreamContext,
    _Inout_ PWKD_PWC_WRITE_CONTEXT WriteContext
    );

static ULONG
WkdPwcpCalculateEntropy(
    _In_reads_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length
    );

static BOOLEAN
WkdPwcpCheckDoubleExtension(
    _In_ PCUNICODE_STRING FileName
    );

static BOOLEAN
WkdPwcpCheckKnownRansomwareExtension(
    _In_ PCUNICODE_STRING FileName
    );

static VOID
WkdPwcpCalculateSuspicionScore(
    _Inout_ PWKD_PWC_WRITE_CONTEXT WriteContext
    );

static NTSTATUS
WkdPwcpGetFileName(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PUNICODE_STRING FileName
    );

static VOID
WkdPwcpFreeFileName(
    _Inout_ PUNICODE_STRING FileName
    );

static NTSTATUS
WkdPwcpQueryFileIdentity(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PUINT64 OutFileId,
    _Out_ PLONGLONG OutFileSize
    );

static BOOLEAN
WkdPwcpStringEndsWithInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Suffix,
    _In_ USHORT SuffixLengthBytes
    );

static BOOLEAN
WkdPwcpLogAllowed(
    VOID
    );

/* ========================================================================== */
/* 初始化 / 关闭                                                               */
/* ========================================================================== */

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdPwcInitialize(
    VOID
    )
{
    NTSTATUS status;
    LONG previousValue;
    LARGE_INTEGER currentTime;

    PAGED_CODE();

    previousValue = InterlockedCompareExchange(&g_WkdPwcState.Initialized, 1, 0);
    if (previousValue != 0) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_WkdPwcState.Stats, sizeof(g_WkdPwcState.Stats));
    InterlockedExchange(&g_WkdPwcState.ShutdownRequested, 0);

    RtlZeroMemory(g_WkdPwcState.ProcessActivity,
                  sizeof(g_WkdPwcState.ProcessActivity));
    g_WkdPwcState.ActiveTrackers = 0;
    ExInitializePushLock(&g_WkdPwcState.ActivityLock);
    ExInitializePushLock(&g_WkdPwcState.RateLimitLock);

    g_WkdPwcState.CurrentSecondLogs = 0;
    g_WkdPwcState.ProcessNotifyRegistered = FALSE;
    KeQuerySystemTime(&g_WkdPwcState.StartTime);
    KeQuerySystemTime(&currentTime);
    g_WkdPwcState.CurrentSecondStart = currentTime;

    /* 进程退出回调：清理活动槽防 PID 复用（失败非致命——stale 回收兜底） */
    status = PsSetCreateProcessNotifyRoutineEx(
        WkdPwcpProcessNotifyCallback,
        FALSE);
    if (NT_SUCCESS(status)) {
        g_WkdPwcState.ProcessNotifyRegistered = TRUE;
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender/PWC] Process notify registration failed "
            "(non-fatal): 0x%X\n", status);
        status = STATUS_SUCCESS;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender/PWC] PostWrite subsystem initialized\n");
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdPwcShutdown(
    VOID
    )
{
    LONG wasInitialized;

    PAGED_CODE();

    wasInitialized = InterlockedExchange(&g_WkdPwcState.Initialized, 0);
    if (wasInitialized == 0) {
        return;
    }

    InterlockedExchange(&g_WkdPwcState.ShutdownRequested, 1);

    if (g_WkdPwcState.ProcessNotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(WkdPwcpProcessNotifyCallback, TRUE);
        g_WkdPwcState.ProcessNotifyRegistered = FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_WkdPwcState.ActivityLock);
    RtlZeroMemory(g_WkdPwcState.ProcessActivity,
                  sizeof(g_WkdPwcState.ProcessActivity));
    g_WkdPwcState.ActiveTrackers = 0;
    ExReleasePushLockExclusive(&g_WkdPwcState.ActivityLock);
    KeLeaveCriticalRegion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender/PWC] PostWrite shutdown. Total=%lld Alerts=%lld\n",
        InterlockedCompareExchange64(&g_WkdPwcState.Stats.TotalPostWrites, 0, 0),
        InterlockedCompareExchange64(&g_WkdPwcState.Stats.RansomwareAlerts, 0, 0));
}

/* ========================================================================== */
/* 主回调：FsPostWriteNotifyCallabck                                                    */
/* ========================================================================== */

_Use_decl_annotations_
FLT_POSTOP_CALLBACK_STATUS
FsPostWriteNotifyCallabck(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++
 * 主回调（ShadowStrikePostWrite）：
 *   1. DRAINING/IRQL 守卫（PWR-1：post-write 可运行至 DISPATCH）
 *   2. 成功写（IoStatus.Information>0）且非分页 I/O 才处理
 *   3. 读 stream context（E1：不置位——PreWrite 的 WkdPocMarkFileModified
 *      已在写尝试时置 Dirty；SS 在 post 置 Dirty+Scanned=FALSE，wkd 的
 *      NeedsRescan = !Scanned || Dirty，Dirty 已触发重扫，语义等价）
 *   4. 熵（MDL 采样）+ 双扩展/勒索扩展/蜜罐 + 写模式 → 分数
 *   5. 进程聚合（C1）→ ≥150 单次告警（IsFlagged）+ ≥30 限速日志
 *--*/
{
    NTSTATUS status;
    PWKD_POC_STREAM_CONTEXT streamContext = NULL;
    WKD_PWC_WRITE_CONTEXT writeContext;
    PWKD_PWC_PROCESS_ACTIVITY processActivity = NULL;
    UNICODE_STRING fileName = { 0 };
    BOOLEAN contextAcquired = FALSE;
    BOOLEAN fileNameAcquired = FALSE;
    PVOID writeBuffer = NULL;
    ULONG bytesToAnalyze = 0;
    BOOLEAN shouldAlert = FALSE;
    ULONG alertScore = 0;

    UNREFERENCED_PARAMETER(CompletionContext);

    /* PWR-1（关键）：draining/IRQL 守卫必须先于 PAGED_CODE() */
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PAGED_CODE();

    /* 模块就绪守卫（对齐 SS：READY 门控 + lazy-init 的 wkd 静态版） */
    if (*(volatile LONG*)&g_WkdPwcState.Initialized != 1) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (*(volatile LONG*)&g_WkdPwcState.ShutdownRequested != 0) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* boot 期跳过（ShadowFsIsBootPhase） */
    if (WkdFspIsBootPhase()) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* 仅处理成功且实际写入的写操作 */
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (Data->IoStatus.Information == 0) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (FltObjects->FileObject == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* 分页 I/O / 可信进程排除（ShadowStrikeIsProcessExcluded；
     * KernelMode 在 post 无意义——IoStatus 已定，无需跳过） */
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (ExemptsIsProcessTrusted(PsGetCurrentProcessId())) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    InterlockedIncrement64(&g_WkdPwcState.Stats.TotalPostWrites);

    /* 构造写上下文 */
    RtlZeroMemory(&writeContext, sizeof(writeContext));
    writeContext.ProcessId = PsGetCurrentProcessId();
    writeContext.ThreadId = PsGetCurrentThreadId();
    writeContext.BytesWritten = Data->IoStatus.Information;
    KeQuerySystemTime(&writeContext.Timestamp);

    if (Data->Iopb->Parameters.Write.ByteOffset.QuadPart != -1) {
        writeContext.WriteOffset = Data->Iopb->Parameters.Write.ByteOffset;
    }

    /* 取 stream context（E1：只读用于文件身份/覆写/追加检测） */
    status = FltGetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&streamContext);

    if (NT_SUCCESS(status) && streamContext != NULL) {
        if (FsCheckStreamContextValidity(streamContext)) {
            contextAcquired = TRUE;

            writeContext.VolumeSerial = streamContext->VolumeSerial;
            writeContext.FileId = (UINT64)streamContext->FileId;
            writeContext.FileSize.QuadPart = streamContext->ScanFileSize;

            /* 整文件覆写 / 追加模式 */
            if (writeContext.WriteOffset.QuadPart == 0 &&
                (LONGLONG)writeContext.BytesWritten >= streamContext->ScanFileSize) {
                writeContext.IsFullOverwrite = TRUE;
            }
            if (writeContext.WriteOffset.QuadPart >=
                (LONGLONG)streamContext->ScanFileSize) {
                writeContext.IsAppend = TRUE;
            }
        } else {
            InterlockedIncrement64(&g_WkdPwcState.Stats.InvalidContexts);
        }
    } else {
        /* 无 stream context：尽力从文件对象取 FileId/大小（SS 用
         * CacheBuildKey 兜底，wkd 无 ScanCache → 直接查询等价字段） */
        InterlockedIncrement64(&g_WkdPwcState.Stats.MissingStreamContexts);
        status = WkdPwcpQueryFileIdentity(
            FltObjects,
            &writeContext.FileId,
            &writeContext.FileSize.QuadPart);
    }

    /* ================================================================== */
    /* 熵计算（D1）：MDL 采样 + Shannon 查表                                 */
    /* FSC-4：post-op 回调中用户态 WriteBuffer 不可信（已释放/换出/未映射）， */
    /* 仅 MDL 备份缓冲安全可访问——非 MDL 直接跳过而非 __try 兜底。          */
    /* ================================================================== */

    if (Data->Iopb->Parameters.Write.WriteBuffer != NULL &&
        !FlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE) &&
        writeContext.BytesWritten >= 64) {

        bytesToAnalyze = (ULONG)min(writeContext.BytesWritten,
                                    WKD_PWC_ENTROPY_SAMPLE_SIZE);

        if (Data->Iopb->Parameters.Write.MdlAddress != NULL) {
            writeBuffer = MmGetSystemAddressForMdlSafe(
                Data->Iopb->Parameters.Write.MdlAddress,
                NormalPagePriority | MdlMappingNoExecute);
        } else {
            writeBuffer = NULL;
        }

        if (writeBuffer != NULL) {
            __try {
                writeContext.EntropyX100 = WkdPwcpCalculateEntropy(
                    (PUCHAR)writeBuffer,
                    bytesToAnalyze);

                InterlockedIncrement64(&g_WkdPwcState.Stats.EntropyCalculations);

                if (writeContext.EntropyX100 >= WKD_PWC_ENTROPY_HIGH_X100) {
                    writeContext.IsHighEntropy = TRUE;
                    InterlockedIncrement64(&g_WkdPwcState.Stats.HighEntropyWrites);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                /* MDL 映射页异常——跳过熵检查 */
            }
        }
    }

    /* ================================================================== */
    /* 文件名 + 勒索扩展三查                                                 */
    /* ================================================================== */

    status = WkdPwcpGetFileName(Data, &fileName);
    if (NT_SUCCESS(status) && fileName.Buffer != NULL) {
        fileNameAcquired = TRUE;

        writeContext.IsDoubleExtension = WkdPwcpCheckDoubleExtension(&fileName);
        writeContext.IsKnownRansomwareExt =
            WkdPwcpCheckKnownRansomwareExtension(&fileName);
        writeContext.IsHoneypotFile = WkdFsIsHoneypotFile(&fileName);

        if (writeContext.IsDoubleExtension) {
            InterlockedIncrement64(&g_WkdPwcState.Stats.DoubleExtensionWrites);
        }
        if (writeContext.IsHoneypotFile) {
            InterlockedIncrement64(&g_WkdPwcState.Stats.HoneypotAccesses);
        }
    }

    /* ================================================================== */
    /* 写模式分析 + 分数累积（C1：单写算分 → 进程聚合）                     */
    /* ================================================================== */

    WkdPwcpAnalyzeWritePattern(streamContext, &writeContext);
    WkdPwcpCalculateSuspicionScore(&writeContext);

    /* ================================================================== */
    /* 进程活动表（C2 结构：GetOrCreate 后锁内 revalidate + 更新）          */
    /* 对齐 SS：activity 指针指向全局数组，修改段必须持 ActivityLock 排他，  */
    /* 防 PwpCleanupProcessActivity 并发清零与非原子字段撕裂。               */
    /* ================================================================== */

    processActivity = WkdPwcpGetOrCreateProcessActivity(writeContext.ProcessId);
    if (processActivity != NULL) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_WkdPwcState.ActivityLock);

        /* Re-validate：槽可能在 GetOrCreate 与加锁之间被进程退出清理 */
        if (processActivity->IsActive &&
            processActivity->ProcessId == writeContext.ProcessId) {

            if (writeContext.FileId != 0) {
                writeContext.IsNewUniqueFile = WkdPwcpTrackUniqueFile(
                    processActivity,
                    writeContext.FileId,
                    writeContext.VolumeSerial);
                if (writeContext.IsNewUniqueFile) {
                    InterlockedIncrement64(
                        &g_WkdPwcState.Stats.UniqueFileModifications);
                }
            }

            WkdPwcpUpdateProcessActivity(processActivity, &writeContext);

            /* 告警判据（≥150 且未标记）——锁内置位，锁外上报 */
            if (processActivity->SuspicionScore >= WKD_PWC_ALERT_THRESHOLD &&
                !processActivity->IsFlagged) {

                processActivity->IsFlagged = TRUE;
                alertScore = (ULONG)processActivity->SuspicionScore;
                shouldAlert = TRUE;
                InterlockedIncrement64(&g_WkdPwcState.Stats.RansomwareAlerts);
            }
        }

        ExReleasePushLockExclusive(&g_WkdPwcState.ActivityLock);
        KeLeaveCriticalRegion();

        /* 告警（锁外，B3：AeReportIndicatorPair 聚合——ThreatScoring 流水线，
         * 不在落锁期间调用） */
        if (shouldAlert) {
            AeReportIndicatorPair(
                writeContext.ProcessId,
                writeContext.ProcessId,
                TsSourceIOC,
                TsIndicator_File_MassModify,
                AeThreatSeverityCritical);

            if (WkdPwcpLogAllowed()) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[WkDefender/PWC] RANSOMWARE ALERT: PID=%lu Score=%u "
                    "File=%wZ\n",
                    HandleToULong(writeContext.ProcessId),
                    alertScore,
                    &fileName);
            }
        }
    }

    /* ================================================================== */
    /* 可疑写日志（≥30，限速）——SuspiciousOperations               */
    /* ================================================================== */

    if (writeContext.SuspicionScore >= WKD_PWC_SCORE_SEQUENTIAL_OVERWRITE &&
        !WkdPwcpShouldRateLimit()) {

        InterlockedIncrement64(&g_WkdPwcState.Stats.SuspiciousOperations);
    }

    /* ================================================================== */
    /* 清理                                                                 */
    /* ================================================================== */

    if (fileNameAcquired) {
        WkdPwcpFreeFileName(&fileName);
    }

    if (contextAcquired) {
        FltReleaseContext((PFLT_CONTEXT)streamContext);
        streamContext = NULL;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ========================================================================== */
/* 私有工具 - 进程退出清理                                                     */
/* ========================================================================== */

static VOID
WkdPwcpProcessNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        return;   /* 仅处理进程退出 */
    }

    WkdPwcpCleanupProcessActivity(ProcessId);
}

static VOID
WkdPwcpCleanupProcessActivity(
    _In_ HANDLE ProcessId
    )
{
    ULONG i;

    if (*(volatile LONG*)&g_WkdPwcState.Initialized != 1) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_WkdPwcState.ActivityLock);

    for (i = 0; i < WKD_PWC_MAX_TRACKED_PROCESSES; i++) {
        if (g_WkdPwcState.ProcessActivity[i].ProcessId == ProcessId &&
            g_WkdPwcState.ProcessActivity[i].IsActive) {

            RtlZeroMemory(&g_WkdPwcState.ProcessActivity[i],
                          sizeof(WKD_PWC_PROCESS_ACTIVITY));
            InterlockedDecrement(&g_WkdPwcState.ActiveTrackers);
            break;
        }
    }

    ExReleasePushLockExclusive(&g_WkdPwcState.ActivityLock);
    KeLeaveCriticalRegion();
}

/* ========================================================================== */
/* 私有工具 - 限速                                                             */
/* ========================================================================== */

static BOOLEAN
WkdPwcpShouldRateLimit(
    VOID
    )
{
    LARGE_INTEGER currentTime;
    LONGLONG secondsDiff;
    LONG currentCount;

    KeQuerySystemTime(&currentTime);

    secondsDiff = (currentTime.QuadPart -
                   g_WkdPwcState.CurrentSecondStart.QuadPart) / 10000000LL;

    if (secondsDiff >= 1) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_WkdPwcState.RateLimitLock);

        if ((currentTime.QuadPart -
             g_WkdPwcState.CurrentSecondStart.QuadPart) / 10000000LL >= 1) {
            g_WkdPwcState.CurrentSecondStart = currentTime;
            g_WkdPwcState.CurrentSecondLogs = 0;
        }

        ExReleasePushLockExclusive(&g_WkdPwcState.RateLimitLock);
        KeLeaveCriticalRegion();
    }

    currentCount = InterlockedIncrement(&g_WkdPwcState.CurrentSecondLogs);
    return (currentCount > WKD_PWC_MAX_LOGS_PER_SECOND);
}

/* 告警日志专用限速（独立于可疑写日志，防告警洪泛刷屏） */
static BOOLEAN
WkdPwcpLogAllowed(
    VOID
    )
{
    return !WkdPwcpShouldRateLimit();
}

/* ========================================================================== */
/* 私有工具 - 进程活动表                                                       */
/* ========================================================================== */

static PWKD_PWC_PROCESS_ACTIVITY
WkdPwcpGetOrCreateProcessActivity(
    _In_ HANDLE ProcessId
    )
{
    PWKD_PWC_PROCESS_ACTIVITY activity = NULL;
    ULONG i;
    ULONG freeSlotIndex = (ULONG)-1;
    ULONG staleSlotIndex = (ULONG)-1;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER age;

    if (*(volatile LONG*)&g_WkdPwcState.Initialized != 1) {
        return NULL;
    }

    KeQuerySystemTime(&currentTime);

    /* 共享锁查找既有槽 */
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_WkdPwcState.ActivityLock);

    for (i = 0; i < WKD_PWC_MAX_TRACKED_PROCESSES; i++) {
        if (g_WkdPwcState.ProcessActivity[i].ProcessId == ProcessId &&
            g_WkdPwcState.ProcessActivity[i].IsActive) {
            activity = &g_WkdPwcState.ProcessActivity[i];
            break;
        }
    }

    ExReleasePushLockShared(&g_WkdPwcState.ActivityLock);
    KeLeaveCriticalRegion();

    if (activity != NULL) {
        return activity;
    }

    /* 排他锁：完整搜索 + 分配（free 槽优先，其次 stale 槽，防 TOCTOU） */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_WkdPwcState.ActivityLock);

    for (i = 0; i < WKD_PWC_MAX_TRACKED_PROCESSES; i++) {
        if (g_WkdPwcState.ProcessActivity[i].ProcessId == ProcessId &&
            g_WkdPwcState.ProcessActivity[i].IsActive) {
            activity = &g_WkdPwcState.ProcessActivity[i];
            goto Exit;
        }

        if (!g_WkdPwcState.ProcessActivity[i].IsActive) {
            if (freeSlotIndex == (ULONG)-1) {
                freeSlotIndex = i;
            }
        } else if (staleSlotIndex == (ULONG)-1) {
            age.QuadPart = currentTime.QuadPart -
                g_WkdPwcState.ProcessActivity[i].LastWriteTime.QuadPart;
            if (age.QuadPart > WKD_PWC_STALE_ENTRY_TIMEOUT_100NS) {
                staleSlotIndex = i;
            }
        }
    }

    if (freeSlotIndex != (ULONG)-1) {
        i = freeSlotIndex;
    } else if (staleSlotIndex != (ULONG)-1) {
        i = staleSlotIndex;
    } else {
        activity = NULL;   /* 槽满且无 stale：放弃跟踪（stat 不计数） */
        goto Exit;
    }

    RtlZeroMemory(&g_WkdPwcState.ProcessActivity[i],
                  sizeof(WKD_PWC_PROCESS_ACTIVITY));
    g_WkdPwcState.ProcessActivity[i].ProcessId = ProcessId;
    g_WkdPwcState.ProcessActivity[i].IsActive = TRUE;
    g_WkdPwcState.ProcessActivity[i].FirstWriteTime = currentTime;
    g_WkdPwcState.ProcessActivity[i].LastWriteTime = currentTime;
    g_WkdPwcState.ProcessActivity[i].WindowStart = currentTime;
    g_WkdPwcState.ProcessActivity[i].LastScoreUpdate = currentTime;

    activity = &g_WkdPwcState.ProcessActivity[i];
    InterlockedIncrement(&g_WkdPwcState.ActiveTrackers);

Exit:
    ExReleasePushLockExclusive(&g_WkdPwcState.ActivityLock);
    KeLeaveCriticalRegion();

    return activity;
}

static VOID
WkdPwcpApplyScoreDecay(
    _Inout_ PWKD_PWC_PROCESS_ACTIVITY Activity,
    _In_ PLARGE_INTEGER CurrentTime
    )
{
    LONGLONG elapsedSeconds;
    LONG decay;
    LONG currentScore;
    LONG newScore;

    elapsedSeconds = (CurrentTime->QuadPart -
                      Activity->LastScoreUpdate.QuadPart) / 10000000LL;

    if (elapsedSeconds > 0) {
        decay = (LONG)(elapsedSeconds * WKD_PWC_SCORE_DECAY_PER_SECOND);

        do {
            currentScore = Activity->SuspicionScore;
            newScore = currentScore - decay;
            if (newScore < 0) {
                newScore = 0;
            }
        } while (InterlockedCompareExchange(&Activity->SuspicionScore,
                                            newScore,
                                            currentScore) != currentScore);

        /* 调用方（UpdateProcessActivity）在 ActivityLock 排他锁内：
         * LastScoreUpdate 写入无撕裂风险 */
        Activity->LastScoreUpdate = *CurrentTime;
    }
}

static BOOLEAN
WkdPwcpTrackUniqueFile(
    _Inout_ PWKD_PWC_PROCESS_ACTIVITY Activity,
    _In_ UINT64 FileId,
    _In_ ULONG VolumeSerial
    )
{
    ULONG i;

    for (i = 0; i < Activity->TrackedFileCount; i++) {
        if (Activity->TrackedFiles[i].FileId == FileId &&
            Activity->TrackedFiles[i].VolumeSerial == VolumeSerial) {
            return FALSE;   /* 已跟踪 */
        }
    }

    if (Activity->TrackedFileCount < WKD_PWC_MAX_TRACKED_FILES_PER_PROCESS) {
        Activity->TrackedFiles[Activity->TrackedFileCount].FileId = FileId;
        Activity->TrackedFiles[Activity->TrackedFileCount].VolumeSerial =
            VolumeSerial;
        Activity->TrackedFileCount++;
        InterlockedIncrement(&Activity->UniqueFileCount);
        return TRUE;
    }

    /* 跟踪表满：按新文件计（检测不放过） */
    InterlockedIncrement(&Activity->UniqueFileCount);
    return TRUE;
}

static VOID
WkdPwcpUpdateProcessActivity(
    _Inout_ PWKD_PWC_PROCESS_ACTIVITY Activity,
    _In_ PWKD_PWC_WRITE_CONTEXT WriteContext
    )
{
    LARGE_INTEGER windowAge;
    LONG oldScore;
    LONG desired;

    if (Activity == NULL || WriteContext == NULL) {
        return;
    }

    /* 先衰减再加分 */
    WkdPwcpApplyScoreDecay(Activity, &WriteContext->Timestamp);

    Activity->LastWriteTime = WriteContext->Timestamp;

    /* 1s 窗口滚动重置 */
    windowAge.QuadPart = WriteContext->Timestamp.QuadPart -
                         Activity->WindowStart.QuadPart;
    if (windowAge.QuadPart > WKD_PWC_RAPID_WRITE_WINDOW_100NS) {
        Activity->WindowStart = WriteContext->Timestamp;
        InterlockedExchange(&Activity->WriteCount, 0);
        InterlockedExchange(&Activity->UniqueFileCount, 0);
        Activity->TrackedFileCount = 0;
    }

    InterlockedIncrement(&Activity->WriteCount);

    if (WriteContext->IsHighEntropy) {
        InterlockedIncrement(&Activity->HighEntropyWrites);
    }

    /* RawScore 累积（上限 500） */
    if (InterlockedAdd(&Activity->RawScore,
                       WriteContext->SuspicionScore) > WKD_PWC_SCORE_MAX_ACCUMULATION) {
        InterlockedExchange(&Activity->RawScore, WKD_PWC_SCORE_MAX_ACCUMULATION);
    }

    /* SuspicionScore 衰减后分数 CAS 累积（上限 500） */
    do {
        oldScore = Activity->SuspicionScore;
        desired = oldScore + (LONG)WriteContext->SuspicionScore;
        if (desired > WKD_PWC_SCORE_MAX_ACCUMULATION) {
            desired = WKD_PWC_SCORE_MAX_ACCUMULATION;
        }
    } while (InterlockedCompareExchange(&Activity->SuspicionScore,
                                        desired,
                                        oldScore) != oldScore);

    /* 快速写模式（勒索指标） */
    if (Activity->WriteCount > WKD_PWC_RANSOMWARE_WRITE_THRESHOLD) {
        InterlockedIncrement64(&g_WkdPwcState.Stats.RapidWriteDetections);
        Activity->IsRateLimited = TRUE;
    }

    /* 快速大量文件修改（勒索指标，+70 CAS） */
    if (Activity->UniqueFileCount > WKD_PWC_RANSOMWARE_FILE_THRESHOLD) {
        do {
            oldScore = Activity->SuspicionScore;
            desired = oldScore + WKD_PWC_SCORE_RAPID_FILE_MODIFICATIONS;
            if (desired > WKD_PWC_SCORE_MAX_ACCUMULATION) {
                desired = WKD_PWC_SCORE_MAX_ACCUMULATION;
            }
        } while (InterlockedCompareExchange(&Activity->SuspicionScore,
                                            desired,
                                            oldScore) != oldScore);
    }
}

/* ========================================================================== */
/* 私有工具 - 熵计算                                                           */
/* ========================================================================== */

static ULONG
WkdPwcpCalculateEntropy(
    _In_reads_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length
    )
{
    ULONG byteCounts[256] = { 0 };
    ULONG i;
    ULONG entropy = 0;
    ULONG count;

    if (Buffer == NULL || Length == 0) {
        return 0;
    }

    for (i = 0; i < Length; i++) {
        byteCounts[Buffer[i]]++;
    }

    for (i = 0; i < 256; i++) {
        count = byteCounts[i];
        if (count > 0) {
            ULONG scaledCount = (count * 256) / Length;
            ULONG contribution;

            if (scaledCount > 256) {
                scaledCount = 256;
            }

            contribution = (g_WkdPwcEntropyTable[scaledCount] * count) / Length;
            entropy += contribution;
        }
    }

    /* 结果 = 熵 ×100（0~800） */
    return entropy;
}

/* ========================================================================== */
/* 私有工具 - 扩展名检查                                                       */
/* ========================================================================== */

static BOOLEAN
WkdPwcpCheckDoubleExtension(
    _In_ PCUNICODE_STRING FileName
    )
{
    ULONG i;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }

    for (i = 0; i < WKD_PWC_DOUBLE_EXT_COUNT; i++) {
        if (WkdPwcpStringEndsWithInsensitive(
                FileName,
                g_WkdPwcDoubleExtensions[i].Extension,
                g_WkdPwcDoubleExtensions[i].LengthInBytes)) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
WkdPwcpCheckKnownRansomwareExtension(
    _In_ PCUNICODE_STRING FileName
    )
{
    ULONG i;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }

    for (i = 0; i < WKD_PWC_RANSOMWARE_EXT_COUNT; i++) {
        if (WkdPwcpStringEndsWithInsensitive(
                FileName,
                g_WkdPwcRansomwareExtensions[i].Extension,
                g_WkdPwcRansomwareExtensions[i].LengthInBytes)) {
            return TRUE;
        }
    }

    return FALSE;
}

/* ========================================================================== */
/* 私有工具 - 写模式与评分                                                     */
/* ========================================================================== */

static VOID
WkdPwcpAnalyzeWritePattern(
    _In_opt_ PWKD_POC_STREAM_CONTEXT StreamContext,
    _Inout_ PWKD_PWC_WRITE_CONTEXT WriteContext
    )
{
    if (WriteContext == NULL) {
        return;
    }

    /* 整文件覆写（勒索常见） */
    if (WriteContext->IsFullOverwrite) {
        WriteContext->SuspicionScore += WKD_PWC_SCORE_FULL_FILE_OVERWRITE;
    }

    /* 从头顺序覆写（加密模式） */
    if (WriteContext->WriteOffset.QuadPart == 0 &&
        !WriteContext->IsAppend &&
        WriteContext->BytesWritten > WKD_PWC_SMALL_WRITE_THRESHOLD) {

        WriteContext->IsSequential = TRUE;
        WriteContext->SuspicionScore += WKD_PWC_SCORE_SEQUENTIAL_OVERWRITE;
    }

    /* 大写入覆写已有文件（批量加密） */
    if (WriteContext->BytesWritten >= WKD_PWC_LARGE_WRITE_THRESHOLD &&
        !WriteContext->IsAppend &&
        StreamContext != NULL) {

        WriteContext->SuspicionScore += WKD_PWC_SCORE_LARGE_WRITE_OVERWRITE;
    }
}

static VOID
WkdPwcpCalculateSuspicionScore(
    _Inout_ PWKD_PWC_WRITE_CONTEXT WriteContext
    )
{
    if (WriteContext == NULL) {
        return;
    }

    if (WriteContext->IsDoubleExtension) {
        WriteContext->SuspicionScore += WKD_PWC_SCORE_DOUBLE_EXTENSION;
    }
    if (WriteContext->IsKnownRansomwareExt) {
        WriteContext->SuspicionScore += WKD_PWC_SCORE_KNOWN_RANSOM_EXT;
    }
    if (WriteContext->IsHoneypotFile) {
        WriteContext->SuspicionScore += WKD_PWC_SCORE_HONEYPOT_ACCESS;
    }
    if (WriteContext->IsHighEntropy) {
        WriteContext->SuspicionScore += WKD_PWC_SCORE_HIGH_ENTROPY;
    }
}

/* ========================================================================== */
/* 私有工具 - 文件名（PagedPool）                                              */
/* ========================================================================== */

static NTSTATUS
WkdPwcpGetFileName(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PUNICODE_STRING FileName
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    RtlZeroMemory(FileName, sizeof(UNICODE_STRING));

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return status;
    }

    FileName->MaximumLength = nameInfo->Name.Length + sizeof(WCHAR);
    FileName->Buffer = (PWCH)ExAllocatePool2(
        POOL_FLAG_PAGED,
        FileName->MaximumLength,
        WKD_PWC_POOL_TAG);
    if (FileName->Buffer == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        InterlockedIncrement64(&g_WkdPwcState.Stats.AllocationFailures);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(FileName->Buffer, nameInfo->Name.Buffer, nameInfo->Name.Length);
    FileName->Length = nameInfo->Name.Length;
    FileName->Buffer[FileName->Length / sizeof(WCHAR)] = L'\0';

    FltReleaseFileNameInformation(nameInfo);
    return STATUS_SUCCESS;
}

static VOID
WkdPwcpFreeFileName(
    _Inout_ PUNICODE_STRING FileName
    )
{
    if (FileName->Buffer != NULL) {
        ExFreePoolWithTag(FileName->Buffer, WKD_PWC_POOL_TAG);
        FileName->Buffer = NULL;
        FileName->Length = 0;
        FileName->MaximumLength = 0;
    }
}

/* 无 stream context 时的文件身份兜底查询（SS CacheBuildKey 等价） */
static NTSTATUS
WkdPwcpQueryFileIdentity(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PUINT64 OutFileId,
    _Out_ PLONGLONG OutFileSize
    )
{
    NTSTATUS status;
    FILE_STANDARD_INFORMATION stdInfo;
    FILE_INTERNAL_INFORMATION internalInfo;

    *OutFileId = 0;
    *OutFileSize = 0;

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
    if (!NT_SUCCESS(status)) {
        status = FltQueryInformationFile(
            FltObjects->Instance,
            FltObjects->FileObject,
            &internalInfo,
            sizeof(internalInfo),
            FileInternalInformation,
            NULL);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        *OutFileId = internalInfo.IndexNumber.QuadPart;
        return STATUS_SUCCESS;
    }

    *OutFileSize = stdInfo.EndOfFile.QuadPart;

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

    return STATUS_SUCCESS;
}

/* ========================================================================== */
/* 私有工具 - 字符串匹配（预计算长度，避免 wcslen）                            */
/* ========================================================================== */

static BOOLEAN
WkdPwcpStringEndsWithInsensitive(
    _In_ PCUNICODE_STRING String,
    _In_ PCWSTR Suffix,
    _In_ USHORT SuffixLengthBytes
    )
{
    USHORT stringLen;
    PWCHAR stringEnd;
    UNICODE_STRING suffixString;
    UNICODE_STRING endString;

    if (String == NULL || String->Buffer == NULL || Suffix == NULL) {
        return FALSE;
    }
    if (SuffixLengthBytes > String->Length) {
        return FALSE;
    }

    stringLen = String->Length;
    stringEnd = String->Buffer + ((stringLen - SuffixLengthBytes) / sizeof(WCHAR));

    suffixString.Buffer = (PWCH)Suffix;
    suffixString.Length = SuffixLengthBytes;
    suffixString.MaximumLength = SuffixLengthBytes;

    endString.Buffer = stringEnd;
    endString.Length = SuffixLengthBytes;
    endString.MaximumLength = SuffixLengthBytes;

    return RtlEqualUnicodeString(&endString, &suffixString, TRUE);
}

/* ========================================================================== */
/* 统计                                                                        */
/* ========================================================================== */

FORCEINLINE
LONG64
WkdPwcAtomicRead64(
    _In_ volatile LONG64* Target
    )
{
    return InterlockedCompareExchange64(Target, 0, 0);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WkdPwcGetStatistics(
    _Out_opt_ PULONG64 TotalPostWrites,
    _Out_opt_ PULONG64 HighEntropyWrites,
    _Out_opt_ PULONG64 RansomwareAlerts,
    _Out_opt_ PULONG32 ActiveTrackers
    )
{
    if (TotalPostWrites != NULL) {
        *TotalPostWrites = (ULONG64)WkdPwcAtomicRead64(
            &g_WkdPwcState.Stats.TotalPostWrites);
    }
    if (HighEntropyWrites != NULL) {
        *HighEntropyWrites = (ULONG64)WkdPwcAtomicRead64(
            &g_WkdPwcState.Stats.HighEntropyWrites);
    }
    if (RansomwareAlerts != NULL) {
        *RansomwareAlerts = (ULONG64)WkdPwcAtomicRead64(
            &g_WkdPwcState.Stats.RansomwareAlerts);
    }
    if (ActiveTrackers != NULL) {
        *ActiveTrackers = (ULONG32)g_WkdPwcState.ActiveTrackers;
    }
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WkdPwcGetErrorStatistics(
    _Out_opt_ PULONG64 InvalidContexts,
    _Out_opt_ PULONG64 MissingStreamContexts,
    _Out_opt_ PULONG64 AllocationFailures
    )
{
    if (InvalidContexts != NULL) {
        *InvalidContexts = (ULONG64)WkdPwcAtomicRead64(
            &g_WkdPwcState.Stats.InvalidContexts);
    }
    if (MissingStreamContexts != NULL) {
        *MissingStreamContexts = (ULONG64)WkdPwcAtomicRead64(
            &g_WkdPwcState.Stats.MissingStreamContexts);
    }
    if (AllocationFailures != NULL) {
        *AllocationFailures = (ULONG64)WkdPwcAtomicRead64(
            &g_WkdPwcState.Stats.AllocationFailures);
    }
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
VOID
WkdPwcResetStatistics(
    VOID
    )
{
    PAGED_CODE();

    InterlockedExchange64(&g_WkdPwcState.Stats.TotalPostWrites, 0);
    InterlockedExchange64(&g_WkdPwcState.Stats.HighEntropyWrites, 0);
    InterlockedExchange64(&g_WkdPwcState.Stats.DoubleExtensionWrites, 0);
    InterlockedExchange64(&g_WkdPwcState.Stats.RapidWriteDetections, 0);
    InterlockedExchange64(&g_WkdPwcState.Stats.HoneypotAccesses, 0);
    InterlockedExchange64(&g_WkdPwcState.Stats.RansomwareAlerts, 0);
    InterlockedExchange64(&g_WkdPwcState.Stats.SuspiciousOperations, 0);
    InterlockedExchange64(&g_WkdPwcState.Stats.UniqueFileModifications, 0);
    InterlockedExchange64(&g_WkdPwcState.Stats.EntropyCalculations, 0);
    InterlockedExchange64(&g_WkdPwcState.Stats.InvalidContexts, 0);
    InterlockedExchange64(&g_WkdPwcState.Stats.MissingStreamContexts, 0);
    InterlockedExchange64(&g_WkdPwcState.Stats.AllocationFailures, 0);
    KeQuerySystemTime(&g_WkdPwcState.StartTime);
}