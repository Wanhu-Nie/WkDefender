/*++
    Memory/MemoryRegionVerify.c - 定时器一致性校验器实现

    Purpose:
        见 MemoryRegionVerify.h 头部注释。三阶段覆盖的第三阶段：
        "基线快照 → 事件增量 → 定时一致性校验"。

        每 30s 回调（Thread 模式，PASSIVE_LEVEL）：
          MvpPeriodicVerify
            └─ 锁内遍历 ActiveProcessHead 收集引用（PsReferenceWkdProcess +1）
               └─ MvpVerifyProcess（锁外，每进程）
                    ├─ MvpReconcileWithVad：Phase1 清 ScanHit + Phase2 枚举 VAD 对账
                    │    ├─ 命中：ScanHit=TRUE；保护漂移 → 修正 + 可疑操作
                    │    └─ 盲区：MmpAddMemoryRegionToVirtualAddressSpace 补录
                    │         （RWX → GapHighRisk + 可疑操作）
                    └─ MvpRemoveStaleRegions：Phase3 收集 ScanHit==FALSE 候选 →
                         锁外 ZwQueryVirtualMemory 单点确认 State!=MEM_COMMIT →
                         锁内复查后 MmpRemoveMemoryRegionFromVirtualAddressSpace

        事件轨当前为预埋（SmInitialize 未启用），校验器是区域表事实来源的
        主力维护者；告警统计经 MvpGetStats 暴露，上报通道随事件轨接入。

    Copyright (c) WkDefender Team
--*/

#include <ntifs.h>
#include "../Common/PeriodicTimer.h"
#include "../Common/Utils.h"
#include "../Memory/MemoryRegion.h"
#include "../Memory/MemoryRegionVerify.h"
#include "../Process/ProcessMonitor.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, MvpInitialize)
#pragma alloc_text(PAGE, MvpShutdown)
#pragma alloc_text(PAGE, MvpPeriodicVerify)
#pragma alloc_text(PAGE, MvpVerifyProcess)
#pragma alloc_text(PAGE, MvpReconcileWithVad)
#pragma alloc_text(PAGE, MvpRemoveStaleRegions)
#endif

/**************************************************/
/*              校验引擎全局状态                    */
/**************************************************/

typedef struct _WKD_MEM_VERIFY_STATE {
    EX_RUNDOWN_REF       Rundown;       /* 定时器线程存活判据（Shutdown 时 Begin 阻止新激活） */
    WKD_PERIODIC_TIMER   Timer;         /* 周期定时器（Thread 模式） */
    BOOLEAN              Initialized;   /* 幂等保护（MvpShutdown 可安全重复） */
    WKD_MEM_VERIFY_STATS Stats;         /* 校验统计 */
} WKD_MEM_VERIFY_STATE, *PWKD_MEM_VERIFY_STATE;

static WKD_MEM_VERIFY_STATE g_MemVerify;

/**************************************************/
/*        Phase3：已释放区域清理（RegionList 残留） */
/**************************************************/

//
// 收集 ScanHit==FALSE 的候选地址（独占锁）；锁外逐点 ZwQueryVirtualMemory
// 单点确认 State!=MEM_COMMIT（兜底"VAD 枚举与事件写入交错"竞争窗口；
// 大区域相邻或子区域重映射时保留），确认后锁内复查并摘除。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
MvpRemoveStaleRegions(
    _Inout_ PWKD_PROCESS WkdProcess,
    _Inout_ PWKD_MEMORY_REGION_CONTEXT Ctx
    )
{
    ULONG64 candidates[WKD_MEM_VERIFY_MAX_CANDIDATES];
    ULONG candidateCount = 0;
    PLIST_ENTRY entry;
    NTSTATUS status;
    PEPROCESS process;
    HANDLE hProcess = NULL;
    SIZE_T returnLength = 0;
    ULONG i;

    if (Ctx == NULL || WkdProcess == NULL) {
        return;
    }

    /* 独占锁收集 stale 候选（防御性：ScanHit 在本次校验 Phase1 清零后
     * 未被 Phase2 命中 → 事件轨认为存在但 VAD 已无该区域） */
    WkdAcquirePushLockExclusive(&Ctx->RegionLock);

    entry = Ctx->RegionList.Flink;
    while (entry != &Ctx->RegionList && candidateCount < WKD_MEM_VERIFY_MAX_CANDIDATES) {
        PWKD_MEMORY_REGION region;

        region = CONTAINING_RECORD(entry, WKD_MEMORY_REGION, ListEntry);
        entry = entry->Flink;

        if (!region->ScanHit) {
            candidates[candidateCount] = region->BaseAddress;
            candidateCount++;
        }
    }

    WkdReleasePushLockExclusive(&Ctx->RegionLock);

    if (candidateCount == 0) {
        return;
    }

    process = WkdProcess->Core.EProcess;
    if (process == NULL) {
        return;
    }

    status = ObOpenObjectByPointer(
        process, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_QUERY_LIMITED_INFORMATION,
        *PsProcessType, KernelMode, &hProcess);
    if (!NT_SUCCESS(status)) {
        return;
    }

    for (i = 0; i < candidateCount; i++) {
        MEMORY_BASIC_INFORMATION mbi;

        RtlZeroMemory(&mbi, sizeof(mbi));
        status = ZwQueryVirtualMemory(
            hProcess, (PVOID)(ULONG_PTR)candidates[i],
            MemoryBasicInformation, &mbi, sizeof(mbi), &returnLength);
        if (NT_SUCCESS(status) && mbi.State == MEM_COMMIT) {
            /* 单点确认仍为提交态：可能是 VAD 枚举窗口内的事件写入/重映射，
             * 保留节点（下轮校验自然对账） */
            continue;
        }

        /* 已释放（MEM_RESERVE/MEM_FREE/查询失败）：锁内复查后摘除。
         * 复查防 TOCTOU：地址可能已被新区域重用（新节点 ScanHit 由同周期
         * Phase2 置位，或事件轨写入后本周期已命中） */
        WkdAcquirePushLockExclusive(&Ctx->RegionLock);

        {
            PWKD_MEMORY_REGION region;
            BOOLEAN isHighRisk;

            region = MmpFindMemoryRegion(Ctx, candidates[i]);
            if (region != NULL && !region->ScanHit) {
                isHighRisk = region->IsHighRisk;
                MmpRemoveMemoryRegionFromVirtualAddressSpace(Ctx, region);

                InterlockedIncrement((volatile LONG *)&g_MemVerify.Stats.FreedRegions);
                if (isHighRisk) {
                    InterlockedIncrement((volatile LONG *)&g_MemVerify.Stats.FreedHighRisk);
                }
            }
        }

        WkdReleasePushLockExclusive(&Ctx->RegionLock);
    }

    ZwClose(hProcess);

    /* 本周期可能摘除了若干节点，风险聚合跟随刷新 */
    WkdMemRegionUpdateProcessRisk(Ctx);
}

/**************************************************/
/*        Phase1+2：VAD 枚举与区域表对账           */
/**************************************************/

//
// Phase1：共享锁清 ScanHit（单验证器写，无并发；与 Phase3 独占锁互斥）；
// Phase2：枚举当前 VAD（仅 COMMIT），命中 → 置 ScanHit + 保护漂移修正；
//         盲区 → MmpAddMemoryRegionToVirtualAddressSpace 补录。
// VAD 枚举骨架对齐 MmBuildMemoryRegionBaseline（对象打开方式/回绕防护）。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
MvpReconcileWithVad(
    _Inout_ PWKD_PROCESS WkdProcess,
    _Inout_ PWKD_MEMORY_REGION_CONTEXT Ctx
    )
{
    NTSTATUS status;
    PEPROCESS process;
    HANDLE hProcess = NULL;
    PVOID currentAddress = NULL;
    SIZE_T returnLength = 0;
    LARGE_INTEGER now;
    PLIST_ENTRY entry;
    ULONG vadScanned = 0;

    if (Ctx == NULL || WkdProcess == NULL) {
        return;
    }

    process = WkdProcess->Core.EProcess;
    if (process == NULL) {
        return;
    }

    /* Phase 1：清空本轮命中标记 */
    WkdAcquirePushLockShared(&Ctx->RegionLock);

    entry = Ctx->RegionList.Flink;
    while (entry != &Ctx->RegionList) {
        PWKD_MEMORY_REGION region;

        region = CONTAINING_RECORD(entry, WKD_MEMORY_REGION, ListEntry);
        region->ScanHit = FALSE;
        entry = entry->Flink;
    }

    WkdReleasePushLockShared(&Ctx->RegionLock);

    status = ObOpenObjectByPointer(
        process, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_QUERY_LIMITED_INFORMATION,
        *PsProcessType, KernelMode, &hProcess);
    if (!NT_SUCCESS(status)) {
        return;
    }

    KeQuerySystemTimePrecise(&now);

    while (vadScanned < WKD_MEM_VERIFY_MAX_VAD_SCAN) {
        MEMORY_BASIC_INFORMATION mbi;
        PVOID nextAddress;
        PWKD_MEMORY_REGION region = NULL;
        ULONG64 base;

        RtlZeroMemory(&mbi, sizeof(mbi));
        status = ZwQueryVirtualMemory(
            hProcess, currentAddress, MemoryBasicInformation,
            &mbi, sizeof(mbi), &returnLength);
        if (!NT_SUCCESS(status)) {
            break;
        }

        if (mbi.State == MEM_COMMIT) {
            base = (ULONG64)(ULONG_PTR)mbi.BaseAddress;

            /* 命中检测（共享锁；MmpFindMemoryRegion 要求持有锁） */
            WkdAcquirePushLockShared(&Ctx->RegionLock);

            region = MmpFindMemoryRegion(Ctx, base);
            if (region != NULL) {
                region->ScanHit = TRUE;

                /* 保护漂移修正：RegionList 记录 ≠ 当前 VAD 实际保护 */
                if (region->Protection != mbi.Protect) {
                    ULONG suspicion;
                    ULONG oldProtection;

                    oldProtection = region->Protection;
                    suspicion = WkdMemRegionGetProtectionChangeSuspicion(
                        oldProtection, mbi.Protect, region->RegionType);

                    region->Protection = mbi.Protect;
                    region->ProtectionChangeCount++;
                    region->LastProtectionChangeTime = now;
                    region->NowExecutable = MmpIsExecutableProtection(mbi.Protect);
                    if (MmpIsRwxProtection(mbi.Protect)) {
                        region->IsHighRisk = TRUE;
                    }

                    InterlockedIncrement((volatile LONG *)&g_MemVerify.Stats.ProtectionDrifts);

                    /* W→X / →RWX 等（susp≥60）：计可疑操作（对齐
                     * WkdMemRegionGetProtectionChangeSuspicion 语义） */
                    if (suspicion >= 60) {
                        InterlockedIncrement64(&Ctx->SuspiciousOperations);
                        InterlockedIncrement((volatile LONG *)&g_MemVerify.Stats.DriftSuspicious);
                    }
                }
            }

            WkdReleasePushLockShared(&Ctx->RegionLock);

            /* 盲区：VAD 有而 RegionList 无 → 补录（内部独占锁，勿持共享锁进入） */
            if (region == NULL) {
                status = MmpAddMemoryRegionToVirtualAddressSpace(
                    Ctx, base, (ULONG64)mbi.RegionSize, mbi.Protect, mbi.Type);
                if (NT_SUCCESS(status)) {
                    InterlockedIncrement((volatile LONG *)&g_MemVerify.Stats.GapRegions);

                    /* 盲区初始即 RWX：事件轨从未记录的高危区域（分配/保护变化
                     * 均未捕获）→ 计可疑操作（AddRegion 已置 IsHighRisk） */
                    if (MmpIsRwxProtection(mbi.Protect)) {
                        InterlockedIncrement((volatile LONG *)&g_MemVerify.Stats.GapHighRisk);
                        InterlockedIncrement64(&Ctx->SuspiciousOperations);
                    }
                }
                /* 表满/分配失败：失败非致命，区域下轮再试（事件轨补上时自然入表） */
            }
        }

        /* 回绕/非前进防护（对齐 MmBuildMemoryRegionBaseline） */
        if (mbi.RegionSize == 0) {
            break;
        }
        nextAddress = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
        if (nextAddress < mbi.BaseAddress || nextAddress <= currentAddress) {
            break;
        }
        currentAddress = nextAddress;

        vadScanned++;
    }

    if (hProcess != NULL) {
        ZwClose(hProcess);
    }

    /* 风险聚合（RegionLock 外；Phase3 清理后亦会刷新一次） */
    WkdMemRegionUpdateProcessRisk(Ctx);
}

/**************************************************/
/*              单进程三阶段校验                    */
/**************************************************/

//
// 单进程校验编排：Phase1+2 对账（盲区补录 + 漂移修正）→ Phase3 已释放清理。
// 调用前提：调用方已持有 WkdProcess 引用（RefCount≥3，context 不可能被销毁）。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
MvpVerifyProcess(
    _Inout_ PWKD_PROCESS WkdProcess
    )
{
    PWKD_MEMORY_REGION_CONTEXT ctx;

    if (WkdProcess == NULL) {
        return;
    }

    /* 收集后可能已摘链（终止）：跳过，避免对终止进程做无谓枚举 */
    if (WkdProcess->Core.ExitTime.QuadPart != 0) {
        return;
    }

    ctx = WkdProcess->MemoryRegionContext;
    if (ctx == NULL) {
        return;   /* 惰性挂载尚未发生（构建失败）；下次周期再试 */
    }

    MvpReconcileWithVad(WkdProcess, ctx);
    MvpRemoveStaleRegions(WkdProcess, ctx);
}

/**************************************************/
/*              定时回调（Thread 模式）            */
/**************************************************/

//
// 周期回调：锁内遍历 ActiveProcessHead 收集引用（PsReferenceWkdProcess +1，
// 收集窗口内进程不会被销毁/摘除安全），锁外逐个校验后释放引用。
// 上限 WKD_MEM_VERIFY_MAX_PROCS：一轮查不满全部进程时，下轮自然延续。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
MvpPeriodicVerify(
    _Inout_opt_ PVOID Context
    )
{
    PWKD_PROCESS collected[WKD_MEM_VERIFY_MAX_PROCS];
    ULONG count = 0;
    PLIST_ENTRY entry;
    KIRQL oldIrql;
    ULONG i;

    UNREFERENCED_PARAMETER(Context);

    /* 锁内收集（引用防销毁；链摘除需同一把锁，故收集窗口内进程必在链上） */
    KeAcquireSpinLock(&g_WkdProcessMonitor.Lock, &oldIrql);

    entry = g_WkdProcessMonitor.ActiveProcessHead.Flink;
    while (entry != &g_WkdProcessMonitor.ActiveProcessHead) {
        PWKD_PROCESS process;

        if (count >= WKD_MEM_VERIFY_MAX_PROCS) {
            break;   /* 本轮配额满，下轮补查 */
        }

        process = CONTAINING_RECORD(entry, WKD_PROCESS, Links);
        entry = entry->Flink;

        if (process->Core.ExitTime.QuadPart != 0) {
            continue;   /* 已终止（链引用已摘除），跳过 */
        }
        if (process->MemoryRegionContext == NULL) {
            continue;   /* 无内存上下文（构建失败），跳过 */
        }

        PsReferenceWkdProcess(process);   /* +1，校验期间防销毁 */
        collected[count] = process;
        count++;
    }

    KeReleaseSpinLock(&g_WkdProcessMonitor.Lock, oldIrql);

    InterlockedIncrement((volatile LONG *)&g_MemVerify.Stats.TotalRuns);

    for (i = 0; i < count; i++) {
        MvpVerifyProcess(collected[i]);
        PsDereferenceWkdProcess(collected[i]);   /* -1；若归零则销毁（校验已完成，安全） */
        InterlockedIncrement((volatile LONG *)&g_MemVerify.Stats.ProcessesChecked);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "[WkDefender] MemVerify run: procs=%u gap=%u gapHR=%u drift=%u driftSus=%u freed=%u freedHR=%u\n",
        count,
        g_MemVerify.Stats.GapRegions,
        g_MemVerify.Stats.GapHighRisk,
        g_MemVerify.Stats.ProtectionDrifts,
        g_MemVerify.Stats.DriftSuspicious,
        g_MemVerify.Stats.FreedRegions,
        g_MemVerify.Stats.FreedHighRisk);
}

/**************************************************/
/*              生命周期与统计查询                 */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
MvpInitialize(
    VOID
    )
{
    NTSTATUS status;
    WKD_TIMER_OPTIONS opts;

    PAGED_CODE();

    RtlZeroMemory(&g_MemVerify, sizeof(g_MemVerify));
    ExInitializeRundownProtection(&g_MemVerify.Rundown);

    opts.Mode = WkdTimerModeThread;      /* PASSIVE_LEVEL 回调（ZwQueryVirtualMemory 要求） */
    opts.ThreadPriority = 0;             /* 正常优先级：后台兜底，不与事件热路径争抢 */

    status = CoCreatePeriodicTimerEx(
        &g_MemVerify.Timer,
        WKD_MEM_VERIFY_INTERVAL_MS,
        MvpPeriodicVerify,
        NULL,
        &opts,
        &g_MemVerify.Rundown);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    CoStartPeriodicTimer(&g_MemVerify.Timer);

    g_MemVerify.Initialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[WkDefender] MemoryRegionVerify initialized (interval=%u ms)\n",
        WKD_MEM_VERIFY_INTERVAL_MS);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
MvpShutdown(
    VOID
    )
{
    if (!g_MemVerify.Initialized) {
        return;
    }

    /* 阻止新回调获取激活 → 排空定时器线程（WkdTimerStop(TRUE) 等待进行中
     * 回调完成）→ 结束 rundown。回调已全部退出，运行期无并发访问 g_MemVerify */
    ExBeginRundownProtection(&g_MemVerify.Rundown);
    WkdTimerDestroy(&g_MemVerify.Timer);
    ExEndRundownProtection(&g_MemVerify.Rundown);

    g_MemVerify.Initialized = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[WkDefender] MemoryRegionVerify shutdown (runs=%u procs=%u\n",
        g_MemVerify.Stats.TotalRuns,
        g_MemVerify.Stats.ProcessesChecked);
}

_Use_decl_annotations_
VOID
MvpGetStats(
    _Out_ PWKD_MEM_VERIFY_STATS Stats
    )
{
    if (Stats == NULL) {
        return;
    }

    RtlCopyMemory(Stats, (PVOID)&g_MemVerify.Stats, sizeof(WKD_MEM_VERIFY_STATS));
}