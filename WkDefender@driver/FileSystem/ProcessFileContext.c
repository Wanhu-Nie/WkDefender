/**************************************************/
/*  WkDefender 进程文件上下文（勒索评分）             */
/**************************************************/

#include "FileSystem.h"   /* 内部私有头（2026-09-13 重构）：include 公共头 + 内部结构 */
#include "../Common/PeriodicTimer.h"               /* 定时清理（系统线程模式） */
#include "../AnalysisEngine/AnalysisEngine.h"      /* AeReportIndicatorPair 弱信号上报 */
#include "../ThreatScoring/ThreatScoring.h"        /* TsIndicator_File_MassModify/DataDestruction */

/*++
 * 实现说明（迁移 DEC-03 裁剪原则）：
 *   本模块对应 SS FileSystemCallbacks.c 的 Fsc*ProcessFileContext* 体系，
 *   按 wkd 架构拆分为独立评分模块（原勒索评分分区 C 死代码 + SS Fscp* 的
 *   wkd 收敛实现）。行为要点：
 *     - 评分评估不产出阻断决策（决策归属后续威胁落地层），仅弱信号上报；
 *     - 槽内计数均原子访问，但整体更新在 EX_PUSH_LOCK 内完成（调用点
 *       PASSIVE_LEVEL，无锁内阻塞调用）；
 *     - 定时器清理与 Notify 并发：锁内互斥，槽生命周期安全。
 *--*/

/* 滚动窗口计数器（PSI_FILE_METRICS 的 wkd 收敛版） */
typedef struct _WKD_PFCP_METRICS {
    volatile LONG  RecentModifies;
    volatile LONG  RecentDeletes;
    volatile LONG  RecentRenames;
    volatile LONG  RecentTruncates;
    volatile LONG  RecentExtensionChanges;
    volatile LONG64 TotalModifies;
    volatile LONG64 TotalDeletes;
    volatile LONG64 TotalRenames;
    volatile LONG64 TotalTruncates;
    volatile LONG64 TotalExtensionChanges;
} WKD_PFCP_METRICS, *PWKD_PFCP_METRICS;

/* 进程上下文槽 */
typedef struct _WKD_PFCP_CONTEXT {
    HANDLE        ProcessId;
    LARGE_INTEGER WindowStart;         /* 1s 滚动窗口起点 */
    LARGE_INTEGER LastActivityTime;    /* 最近一次文件操作（TTL 判定） */
    volatile LONG IsActive;            /* 槽占用标志（仅原子写，锁内切换） */
    WKD_PFCP_METRICS Metrics;
} WKD_PFCP_CONTEXT, *PWKD_PFCP_CONTEXT;

static WKD_PFCP_CONTEXT g_PfcpContexts[WKD_PFCP_MAX_CONTEXTS];
static EX_PUSH_LOCK     g_PfcpLock;
static EX_RUNDOWN_REF   g_PfcpRundown;
static volatile LONG    g_PfcpReady;
static WKD_PERIODIC_TIMER g_PfcpTimer;

/* DbgPrint 退避计数（得分对齐日志按 64 次 1 条降噪） */
static volatile LONG    g_PfcpLogDrain;

/* ============================================================================
 * 扩展名变更判定（T1486）：提取两侧最后 '.' 后扩展名（无点/空 → 非扩展），
 * 大小写不敏感比较不同 → TRUE。长度上限 16 字符防栈溢出。
 * ========================================================================== */
_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WkdPfcpCompareExtensionSafe(
    _In_ PCUNICODE_STRING OldName,
    _In_ PCUNICODE_STRING NewName
    )
{
    WCHAR oldExt[17];
    WCHAR newExt[17];
    ULONG oldChars;
    ULONG newChars;
    ULONG oldExtLen = 0;
    ULONG newExtLen = 0;
    LONG i;

    if (OldName == NULL || OldName->Buffer == NULL || OldName->Length == 0 ||
        NewName == NULL || NewName->Buffer == NULL || NewName->Length == 0) {
        return FALSE;
    }

    oldChars = OldName->Length / sizeof(WCHAR);
    newChars = NewName->Length / sizeof(WCHAR);

    /* 定位最后 '.' */
    for (i = (LONG)oldChars - 1; i >= 0; i--) {
        if (OldName->Buffer[i] == L'.') {
            oldExtLen = (ULONG)(oldChars - i - 1);
            break;
        }
        if (OldName->Buffer[i] == L'\\') {
            break;   /* 越过目录分隔符即止（文件名无点） */
        }
    }
    for (i = (LONG)newChars - 1; i >= 0; i--) {
        if (NewName->Buffer[i] == L'.') {
            newExtLen = (ULONG)(newChars - i - 1);
            break;
        }
        if (NewName->Buffer[i] == L'\\') {
            break;
        }
    }

    /* 任一侧无扩展名 → 不构成勒索扩展名变更信号 */
    if (oldExtLen == 0 || newExtLen == 0 || oldExtLen > 16 || newExtLen > 16) {
        return FALSE;
    }

    RtlCopyMemory(oldExt, OldName->Buffer + (oldChars - oldExtLen), oldExtLen * sizeof(WCHAR));
    oldExt[oldExtLen] = L'\0';
    RtlCopyMemory(newExt, NewName->Buffer + (newChars - newExtLen), newExtLen * sizeof(WCHAR));
    newExt[newExtLen] = L'\0';

    return (_wcsicmp(oldExt, newExt) != 0);
}

/* ============================================================================
 * 勒索行为评分（FscpDetectRansomwareBehavior 分值布局）：
 *   40 重命名风暴 / 35 扩展名变更风暴 / 30 删除风暴 / 20 总量重命名 /
 *   15 总量扩展名变更 / 25 重命名+扩展名组合 / 20 大量改写。
 * ========================================================================== */
_IRQL_requires_max_(DISPATCH_LEVEL)
static LONG
WkdPfcpDetectRansomwareBehavior(
    _In_ PWKD_PFCP_METRICS Metrics
    )
{
    LONG score = 0;
    BOOLEAN renameStorm;
    BOOLEAN extChangeStorm;

    if (Metrics == NULL) {
        return 0;
    }

    renameStorm = (Metrics->RecentRenames > WKD_PFCP_RENAME_THRESHOLD);
    extChangeStorm = (Metrics->RecentExtensionChanges > WKD_PFCP_EXT_CHANGE_THRESHOLD);

    if (renameStorm) {
        score += WKD_PFCP_SCORE_MASS_RENAME;
    }
    if (extChangeStorm) {
        score += WKD_PFCP_SCORE_EXT_CHANGE;
    }
    if (Metrics->RecentDeletes > WKD_PFCP_DELETE_THRESHOLD) {
        score += WKD_PFCP_SCORE_MASS_DELETE;
    }
    if (Metrics->TotalRenames > WKD_PFCP_TOTAL_RENAME_THRESHOLD) {
        score += WKD_PFCP_SCORE_TOTAL_RENAME;
    }
    if (Metrics->TotalExtensionChanges > WKD_PFCP_TOTAL_EXT_CHANGE_THRESHOLD) {
        score += WKD_PFCP_SCORE_TOTAL_EXT_CHANGE;
    }
    if (renameStorm && extChangeStorm) {
        score += WKD_PFCP_SCORE_COMBO_RENAME_EXT;
    }
    if (Metrics->RecentModifies > WKD_PFCP_MODIFY_THRESHOLD) {
        score += WKD_PFCP_SCORE_MASS_MODIFY;
    }

    return score;
}

/* ============================================================================
 * 定时清理（PeriodicTimer 线程，PASSIVE_LEVEL）：
 *   重置超 1s 窗口的滚动计数 + 回收超 5min 无活动的槽（防 PID 复用）。
 *   全程锁内，与 Notify 互斥；经 g_PfcpRundown 保证 Shutdown 同步。
 * ========================================================================== */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
WkdPfcpCleanupTimerCallback(
    _In_opt_ PVOID Context
    )
{
    ULONG i;
    LARGE_INTEGER now;

    UNREFERENCED_PARAMETER(Context);

    if (!ExAcquireRundownProtection(&g_PfcpRundown)) {
        return;   /* 关闭中 */
    }

    KeQuerySystemTime(&now);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PfcpLock);

    for (i = 0; i < WKD_PFCP_MAX_CONTEXTS; i++) {
        PWKD_PFCP_CONTEXT slot = &g_PfcpContexts[i];

        if (!slot->IsActive) {
            continue;
        }

        /* 1s 窗口滚动重置 */
        if (now.QuadPart - slot->WindowStart.QuadPart > WKD_PFCP_WINDOW_100NS) {
            slot->WindowStart = now;
            InterlockedExchange(&slot->Metrics.RecentModifies, 0);
            InterlockedExchange(&slot->Metrics.RecentDeletes, 0);
            InterlockedExchange(&slot->Metrics.RecentRenames, 0);
            InterlockedExchange(&slot->Metrics.RecentTruncates, 0);
            InterlockedExchange(&slot->Metrics.RecentExtensionChanges, 0);
        }

        /* 5min 无活动 → 回收槽 */
        if (now.QuadPart - slot->LastActivityTime.QuadPart > WKD_PFCP_CONTEXT_TTL_100NS) {
            RtlZeroMemory(slot, sizeof(WKD_PFCP_CONTEXT));
        }
    }

    ExReleasePushLockExclusive(&g_PfcpLock);
    KeLeaveCriticalRegion();

    ExReleaseRundownProtection(&g_PfcpRundown);
}

/* ============================================================================
 * 文件操作通知（薄层 FspPreWrite / FsPreSetInformationNotifyCallback 调用）
 * ========================================================================== */
_Use_decl_annotations_
VOID
WkdPfcpNotifyFileOperation(
    HANDLE ProcessId,
    WKD_PFCP_OP OpType,
    PCUNICODE_STRING FileName,
    PCUNICODE_STRING NewFileName
    )
{
    ULONG i;
    PWKD_PFCP_CONTEXT slot = NULL;
    LARGE_INTEGER now;
    LONG score;
    TS_INDICATOR_TYPE indicator;
    BOOLEAN extChanged = FALSE;
    BOOLEAN deleteStorm = FALSE;
    LONG recentModifies = 0, recentDeletes = 0;
    LONG recentRenames = 0, recentExtensionChanges = 0;
    LONG64 totalModifies = 0, totalDeletes = 0;
    LONG64 totalRenames = 0, totalExtensionChanges = 0;

    if (!g_PfcpReady) {
        return;
    }
    if (ProcessId == NULL || FileName == NULL || FileName->Buffer == NULL) {
        return;
    }

    KeQuerySystemTime(&now);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PfcpLock);

    /* 找槽，未命中则复用空闲槽 */
    for (i = 0; i < WKD_PFCP_MAX_CONTEXTS; i++) {
        if (g_PfcpContexts[i].IsActive && g_PfcpContexts[i].ProcessId == ProcessId) {
            slot = &g_PfcpContexts[i];
            break;
        }
    }
    if (slot == NULL) {
        for (i = 0; i < WKD_PFCP_MAX_CONTEXTS; i++) {
            if (!g_PfcpContexts[i].IsActive) {
                slot = &g_PfcpContexts[i];
                RtlZeroMemory(slot, sizeof(WKD_PFCP_CONTEXT));
                slot->ProcessId = ProcessId;
                slot->WindowStart = now;
                slot->LastActivityTime = now;
                InterlockedExchange(&slot->IsActive, 1);
                break;
            }
        }
    }
    if (slot == NULL) {
        /* 槽满：仅记录窗口重置（防死锁呼叫链）；释放即回。 */
        ExReleasePushLockExclusive(&g_PfcpLock);
        KeLeaveCriticalRegion();
        return;
    }

    slot->LastActivityTime = now;

    /* 1s 窗口滚动重置 */
    if (now.QuadPart - slot->WindowStart.QuadPart > WKD_PFCP_WINDOW_100NS) {
        slot->WindowStart = now;
        InterlockedExchange(&slot->Metrics.RecentModifies, 0);
        InterlockedExchange(&slot->Metrics.RecentDeletes, 0);
        InterlockedExchange(&slot->Metrics.RecentRenames, 0);
        InterlockedExchange(&slot->Metrics.RecentTruncates, 0);
        InterlockedExchange(&slot->Metrics.RecentExtensionChanges, 0);
    }

    /* 计数 */
    switch (OpType) {
    case WkdPfcpOp_Rename:
        InterlockedIncrement64(&slot->Metrics.TotalRenames);
        InterlockedIncrement(&slot->Metrics.RecentRenames);
        if (WkdPfcpCompareExtensionSafe(FileName, NewFileName)) {
            InterlockedIncrement64(&slot->Metrics.TotalExtensionChanges);
            InterlockedIncrement(&slot->Metrics.RecentExtensionChanges);
            extChanged = TRUE;
        }
        break;
    case WkdPfcpOp_Delete:
        InterlockedIncrement64(&slot->Metrics.TotalDeletes);
        InterlockedIncrement(&slot->Metrics.RecentDeletes);
        break;
    case WkdPfcpOp_Truncate:
        InterlockedIncrement64(&slot->Metrics.TotalTruncates);
        InterlockedIncrement(&slot->Metrics.RecentTruncates);
        break;
    case WkdPfcpOp_Write:
    default:
        InterlockedIncrement64(&slot->Metrics.TotalModifies);
        InterlockedIncrement(&slot->Metrics.RecentModifies);
        break;
    }

    score = WkdPfcpDetectRansomwareBehavior(&slot->Metrics);

    /* 上报决策所需指标在锁内取值（解锁后槽可能被定时清理回收） */
    deleteStorm = (slot->Metrics.RecentDeletes > WKD_PFCP_DELETE_THRESHOLD);
    recentModifies = slot->Metrics.RecentModifies;
    recentDeletes = slot->Metrics.RecentDeletes;
    recentRenames = slot->Metrics.RecentRenames;
    recentExtensionChanges = slot->Metrics.RecentExtensionChanges;
    totalModifies = slot->Metrics.TotalModifies;
    totalDeletes = slot->Metrics.TotalDeletes;
    totalRenames = slot->Metrics.TotalRenames;
    totalExtensionChanges = slot->Metrics.TotalExtensionChanges;

    ExReleasePushLockExclusive(&g_PfcpLock);
    KeLeaveCriticalRegion();

    /* 弱信号上报（Audit，不阻断）。锁外执行（WKD_UDC-1 同理由：Ae 上报链
     * 不得在 PushLock 内调用）。 */
    if (score >= WKD_PFCP_RANSOMWARE_THRESHOLD) {
        /* 删除主导 → 数据销毁（T1485/T1490 语义接近），否则大量修改/重命名 */
        indicator = deleteStorm
            ? TsIndicator_File_DataDestruction
            : TsIndicator_File_MassModify;

        AeReportIndicatorPair(ProcessId, ProcessId, TsSourceBehavioral, indicator, 0);

        if ((InterlockedIncrement(&g_PfcpLogDrain) % 64) == 1) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WkDefender/PFCP] Ransomware behavior score=%ld (PID=%lu, "
                "Mod=%ld/%I64u Del=%ld/%I64u Ren=%ld/%I64u Ext=%ld/%I64u%s)\n",
                score,
                HandleToULong(ProcessId),
                recentModifies, totalModifies,
                recentDeletes, totalDeletes,
                recentRenames, totalRenames,
                recentExtensionChanges, totalExtensionChanges,
                extChanged ? " [ext-change]" : "");
        }
    }
}

/* ============================================================================
 * 生命周期
 * ========================================================================== */
_Use_decl_annotations_
NTSTATUS
WkdPfcpInitialize(
    VOID
    )
{
    NTSTATUS status;

    ExInitializeRundownProtection(&g_PfcpRundown);
    ExInitializePushLock(&g_PfcpLock);
    RtlZeroMemory(g_PfcpContexts, sizeof(g_PfcpContexts));
    InterlockedExchange(&g_PfcpLogDrain, 0);

    status = CoCreatePeriodicTimer(
        &g_PfcpTimer,
        WKD_PFCP_CLEANUP_INTERVAL_MS,
        WkdPfcpCleanupTimerCallback,
        NULL,
        TRUE,                     /* RunAtPassive：清理需 PushLock */
        &g_PfcpRundown
        );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    CoStartPeriodicTimer(&g_PfcpTimer);

    InterlockedExchange(&g_PfcpReady, 1);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender/PFCP] Process file context initialized "
        "(slots=%d, cleanup=%ums, threshold=%d)\n",
        WKD_PFCP_MAX_CONTEXTS, WKD_PFCP_CLEANUP_INTERVAL_MS,
        WKD_PFCP_RANSOMWARE_THRESHOLD);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
WkdPfcpShutdown(
    VOID
    )
{
    InterlockedExchange(&g_PfcpReady, 0);

    /* 先停定时器（等待执行中回调退出，其持有 Rundown 引用随之释放），
     * 再 RundownCompleted + Wait 确保清理线程完全离线，最后销毁。 */
    WkdTimerStop(&g_PfcpTimer, TRUE);
    ExRundownCompleted(&g_PfcpRundown);
    ExWaitForRundownProtectionRelease(&g_PfcpRundown);
    WkdTimerDestroy(&g_PfcpTimer);

    /* 无并发（Notify 已由 Ready=0 拒绝进入，定时器已离场）→ 直接清零 */
    RtlZeroMemory(g_PfcpContexts, sizeof(g_PfcpContexts));
}