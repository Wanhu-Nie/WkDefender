/**************************************************/
/*  WkDefender — AnalysisEngine 容器 + 维护线程     */
/*                                                   */
/*  职责: 协调子引擎初始化/清理 + 定时维护            */
/**************************************************/

#include "AnalysisEngine.h"
#include "IoaEngine.h"
#include "IocEngine.h"
#include "IocSyscall.h"
#include "IocThread.h"
#include "IocHandle.h"
#include "IocImage.h"
#include "IocProcess.h"
#include "../Process/ProcessMonitor.h"
#include "../Process/ProcessPairContext.h"
#include "../ThreatScoring/ThreatScoring.h"
#include "../Syscall/SyscallMonitor.h"
#include "../Common/Utils.h"
#include "../Callbacks/ThreadNotify.h"
#include "../Callbacks/ImageNotify.h"

/**************************************************/
/*           维护线程状态                           */
/**************************************************/

#define AE_MAINTENANCE_INTERVAL_SEC     60          /* 每 60 秒执行一次 */

typedef struct _AE_MAINTENANCE_STATE {
    HANDLE ThreadHandle;
    PVOID ThreadObject;
    volatile BOOLEAN Running;
    KEVENT StopEvent;
} AE_MAINTENANCE_STATE;

static AE_MAINTENANCE_STATE g_AeMaintenance = { 0 };

/**************************************************/
/*       多目标注入源检测 (对齐 SS 进程关系图)        */
/*                                                  */
/*  迁移自 ShadowStrike ProcessRelationship.c       */
/*  PrpCalculateRelationshipScore 的                */
/*  PR_SCORE_MULTIPLE_TARGETS(+120) 修正项:         */
/*  源节点关系数 >5 时注入关系分叠加。                */
/**************************************************/

/*
 * [死代码] 多目标源检测门控（默认关）。
 * 原因: 当前 AE_PROCESS_PAIR 无 SourceLink/OutboundPairs 双向引用
 *   （2026-07 重构移除）, 无法在行为提交路径即时判定多目标, 退化为
 *   维护线程周期聚合; 提交评分会改变活代码行为, 接入需单独决策。
 * 活代码等价物: agent IOA_PROCESS_NODE.OutPairCount (>5) +
 *   IoaInjectionClassifier 多目标修正。
 */
static BOOLEAN g_AeMultiTargetEnabled = FALSE;

typedef struct _AE_SOURCE_OUTDEGREE {
    HANDLE SourceProcessId;
    ULONG  OutboundCount;
} AE_SOURCE_OUTDEGREE;

#define AE_MAX_SOURCE_OUTDEGREE     512
#define AE_MULTI_TARGET_THRESHOLD   5       /* 对齐 SS: 源关系数 >5 */

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
AepDetectMultiTargetSources(
    _In_ PWKD_HASH_MAP_SNAPSHOT Snapshot,
    _In_ ULONG Capacity
    )
/*++
Routine Description:
    按 SourceProcessId 聚合进程对出边数（出度）, 检测多目标注入源。
    进程对表键为 <源,目标>, 每对不同目标一个条目,
    故源出现次数 = 出度（不同目标数）。

    [死代码] 门控 g_AeMultiTargetEnabled=FALSE 默认关（原因见上）。

Arguments:
    Snapshot — 进程对哈希表快照。
    Capacity — 快照有效条目数。

Return Value:
    VOID。
--*/
{
    AE_SOURCE_OUTDEGREE entries[AE_MAX_SOURCE_OUTDEGREE];
    ULONG entryCount = 0;
    ULONG i, j;

    if (!Snapshot || Capacity == 0) {
        return;
    }

    /* 第一趟: 统计每个源的出边数（固定数组, 超限截断） */
    for (i = 0; i < Capacity; i++) {
        PAE_PROCESS_PAIR_KEY key = (PAE_PROCESS_PAIR_KEY)Snapshot[i].KeyData;
        BOOLEAN found = FALSE;

        for (j = 0; j < entryCount; j++) {
            if (entries[j].SourceProcessId == key->SourceProcessId) {
                entries[j].OutboundCount++;
                found = TRUE;
                break;
            }
        }

        if (!found && entryCount < AE_MAX_SOURCE_OUTDEGREE) {
            entries[entryCount].SourceProcessId = key->SourceProcessId;
            entries[entryCount].OutboundCount = 1;
            entryCount++;
        }
    }

    /* 第二趟: 出度 >5 的源 → 多目标注入源 */
    for (i = 0; i < entryCount; i++) {
        if (entries[i].OutboundCount > AE_MULTI_TARGET_THRESHOLD) {
            /* 对齐 SS PR_SCORE_MULTIPLE_TARGETS=120。
             * 接入提示: 对源进程相关 pair 提交
             * AeReportIndicatorEx(..., TsIndicator_Injection_RemoteThread, 2);
             * 当前仅记录, 不改变活代码评分行为。 */
            DbgPrint("[WkD] MultiTargetSource pid=%lu targets=%lu (SS +120)\n",
                     HandleToULong(entries[i].SourceProcessId),
                     entries[i].OutboundCount);
        }
    }
}

/**************************************************/
/*           维护线程函数                           */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
AepPerformMaintenance(
    VOID
    )
/*++
Routine Description:
    两阶段维护进程对哈希表。
    Phase 1: CoCaptureHashMapSnapshot 获取 key-only 快照（逐桶共享锁）。
    Phase 2: 对快照中的每个 key 执行 AeLookupProcessPair + IoaRefreshProcessPair，
             再 double-check ActiveBehaviors 后回收空 pair。

    与旧实现的区别：
      - 不持桶锁时调用 IoaRefreshProcessPair（零锁反转风险）
      - key-only 快照，无 refcount 管理负担
      - TOCTOU 安全：条目在被 Lookup 前已被清理 → 跳过
--*/
{
    NTSTATUS status;
    LARGE_INTEGER now;
    PWKD_HASH_MAP_SNAPSHOT snapshot = NULL;
    SIZE_T snapshotSize = 0;
    ULONG capacity = 0;
    ULONG retryCount = 0;

    KeQuerySystemTime(&now);

    /* ============ Phase 1: 估算 + 分配 ============ */

    {
        /* 第一轮，获取快照所需容量 */
        status = CoCaptureHashMapSnapshot(&WkdProcessPairMap, NULL, &snapshotSize, NULL);
        if (snapshotSize == 0) return;
        else snapshotSize = ALIGN_UP_BY(snapshotSize, PAGE_SIZE);
        
        snapshot = (PWKD_HASH_MAP_SNAPSHOT)ExAllocatePool2(
            POOL_FLAG_PAGED,
            snapshotSize,
            'pSnp');
        if (!snapshot) return;
    }

    /* ============ Phase 2: 获取快照 ============ */

    status = CoCaptureHashMapSnapshot(&WkdProcessPairMap, snapshot, &snapshotSize, &capacity);
    if (!(NT_SUCCESS(status) ||
    /* 所提供缓冲区容量不足，存在 hashmap 项被遗漏，非致命 */
        status == STATUS_INFO_LENGTH_MISMATCH)) {
        goto Cleanup;
    }

    /*
     * ★ 快照截断说明（已知，属设计允许，暂不修复）：
     *   快照期间并发插入导致条目数超过缓冲容量时，CoCaptureHashMapSnapshot
     *   返回 STATUS_INFO_LENGTH_MISMATCH，capacity = 实际写入数。
     *   被截断的条目（仅剩在哈希表中的部分）不在本轮回合处理，延迟到
     *   下一轮（60s 后）——仅推迟老化回收，无数据丢失，可接受。
     *   故此处不检查返回值、不做重试。
     */

    /* ============ Phase 3: 遍历快照，刷新 + 回收 ============ */

    for (ULONG i = 0; i < capacity; i++) {
        PAE_PROCESS_PAIR pair;
        PAE_PROCESS_PAIR_KEY key = (PAE_PROCESS_PAIR_KEY)snapshot[i].KeyData;

        /* 快照外安全查找（已不持桶锁） */
        pair = AeLookupProcessPair(key->SourceProcessId, key->TargetProcessId);
        if (!pair) continue;   /* 已被其他路径安全清理，TOCTOU 正常 */
        IoaRefreshProcessPair(pair, now);
        PsDereferenceWkdProcessPair(pair);

        /* 尝试回收空 pair */
        if (InterlockedCompareExchange(
            &pair->IoaContext->ActiveBehaviors, 0, 0) == 0) {
            /* CoRemoveHashMapEntry调用者必须持有Ref */
            AE_PROCESS_PAIR_KEY removeKey = { pair->SourceProcessId, pair->TargetProcessId };
            if (CoRemoveHashMapEntry(&WkdProcessPairMap, &removeKey, sizeof(removeKey))) {
                /* 全局 pair 计数递减 */
                InterlockedDecrement(&WkdPairCount);
            }
        }
    }

    /* ============ Phase 3.5: 多目标源检测（死代码, 对齐 SS 多目标修正 +120） ============ */

    //if (g_AeMultiTargetEnabled) {
    //    AepDetectMultiTargetSources(snapshot, capacity);
    //}


Cleanup:
    if (snapshot) ExFreePoolWithTag(snapshot, 'pSnp');
}

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
AepMaintenanceThread(
    _In_ PVOID Context
    )
{
    LARGE_INTEGER timeout;
    UNREFERENCED_PARAMETER(Context);

    /* 指定线程的优先级，通常为 LOW_REALTIME_PRIORITY */
    KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

    while (g_AeMaintenance.Running) {
        /* 延时 60 秒 */
        timeout.QuadPart = -10000LL * AE_MAINTENANCE_INTERVAL_SEC * 1000;
        KeWaitForSingleObject(&g_AeMaintenance.StopEvent,
            Executive, KernelMode, FALSE, &timeout);

        if (!g_AeMaintenance.Running) break;

        AepPerformMaintenance();
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/**************************************************/
/*       AeOrchestratorDispatch — 分析引擎统一编排入口            */
/*                                                  */
/*  回调通过此入口进入分析引擎，不直接调用 IOA/IOC。 */
/*  内部按 Source 类型编排流水线顺序。               */
/*                                                  */
/*  参数:                                           */
/*    SourceProcess — 事件源进程（发起者）           */
/*    TargetProcess — 事件目标进程                  */
/*    Data          — 事件特定数据指针，按 Source    */
/*                    转型                           */
/*    Source        — 来源标识                       */
/*      WkdMessage_SourceSyscall → PWKD_SYSCALL_CONTEXT */
/*      WkdMessage_SourceProcessCallback → PPS_CREATE_NOTIFY_INFO / NULL */
/*      WkdMessage_SourceThreadCallback → PWKD_THREAD */
/*      WkdMessage_SourceObjectCallback → POB_PRE_OPERATION_INFORMATION */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
AeOrchestratorDispatch(
    _In_ const PWKD_PROCESS SourceProcess,
    _Inout_ PWKD_PROCESS TargetProcess,
    _In_ WKD_ASSEMBLY_SOURCE Source,
    _In_ WKD_ASSEMBLY_TYPE Type,
    _In_opt_ const PVOID Context
    )
/*++
Routine Description:
    分析引擎统一编排入口（2026-07 迁移，进程对为核心挂载单元）:
      Phase 1: 创建/查找进程对并 pin
      Phase 2: IOC 检测（全部传 pair）
      Phase 3: IOA 行为记录（收 pair）
      Phase 4: 评分统一结算（pair 维度）
      Phase 5: 解 pair pin

Arguments:
    SourceProcess - 事件源进程（发起者）。
    TargetProcess - 事件目标进程。
    Source        - 来源标识（WkdMessage_Source*）。
    Type          - 事件类型。
    Context       - 事件特定数据指针。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;
    PAE_PROCESS_PAIR pair = NULL;

    if (!SourceProcess || !TargetProcess ||
        Source == WkdMessage_SourceUnknow ||
        Type == WkdMessage_Unknow) {
        return STATUS_INVALID_PARAMETER;
    }

    /* ---- Phase 1: 建 pair + pin ---- */
    status = AeFindOrCreateProcessPair(
        SourceProcess->Core.ProcessId,
        TargetProcess->Core.ProcessId, &pair);
    if (!NT_SUCCESS(status)) {
        /* 配额/内存失败：丢弃本事件 */
        return status;
    }

    /* ---- Phase 2: IOC 检测（全部传 pair） ---- */
    switch (Source) {

    case WkdMessage_SourceSyscall:
        IocDetectSyscall(pair, (PWKD_SYSCALL_CONTEXT)Context);
        break;

    case WkdMessage_SourceProcessCallback:
    {
        if (!Context) goto Cleanup;

        /* WkdMessage_ProcessCreated（退出已短路） */
        IocAnalysisProcess(pair, (PPS_CREATE_NOTIFY_INFO)Context);
        break;
    }

    case WkdMessage_SourceThreadCallback:
        IocObserveThread(pair, (PWKD_THREAD)Context);
        break;

    case WkdMessage_SourceObjectCallback:
        if (Context) {
            IocDetectHandle(pair, (POB_PRE_OPERATION_INFORMATION)Context);
        }
        break;

    case WkdMessage_SourceImageCallback:
        if (Context) {
            /* L0 回调传 PIMAGE_INFO（(X,X) 自对）；IocImage 从源进程
             * ModuleContext 读 L0 采集的 PE 事实（2026-08-08 L0/L1 边界重构） */
            IocDetectImage(pair, (PIMAGE_INFO)Context);
        }
        status = STATUS_SUCCESS;
        goto Cleanup;

    default:
        status = STATUS_NOT_SUPPORTED;
        goto Cleanup;
    }

    /* ---- Phase 3: IOA 行为记录 ---- */
    status = IoaAnalysisBehavior(pair, Type, Context, NULL);

    /* ---- Phase 4: 评分统一结算（pair 维度） ---- */
    TsSettleScores(WkdTsEngine, pair);

    /* ---- Phase 4.5: 评分裁决消费（迁移自 SS BepDetermineResponse）
     * Blocked → 终止源进程（豁免校验）+ 上报；Malicious → 上报 ---- */
    AeEvaluateVerdict(pair);

Cleanup:
    /* ---- Phase 5: 解 pair pin ---- */
    if (pair) {
        PsDereferenceWkdProcessPair(pair);
    }

    return status;
}

/**************************************************/
/*       阻断豁免 — AepIsCriticalProcess            */
/*                                                  */
/*  迁移自 SS BepIsCriticalProcess                  */
/*  (BehaviorEngine.c L1874-1948)。                 */
/*  实现用 wkd 尾部匹配模式（对齐 CbpIsCriticalBootProcess），  */
/*  名单 = SS 14 项 + wkd 既有项。                  */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
AepIsCriticalProcess(
    _In_ HANDLE ProcessId,
    _In_opt_ PCUNICODE_STRING ImagePath
    )
{
    UNICODE_STRING needle;
    UNICODE_STRING tail;
    NTSTATUS status;
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    PEPROCESS process = NULL;
    PUNICODE_STRING procName = NULL;
    BOOLEAN isCritical = FALSE;

    /* 关键进程名单（SS L1918-1933 + wkd CbpIsCriticalBootProcess 既有项） */
    static const PCWSTR criticalNames[] = {
        L"System",                    /* System 进程 */
        L"\\csrss.exe",               /* Client/Server Runtime — BSOD if killed */
        L"\\smss.exe",                /* Session Manager */
        L"\\wininit.exe",             /* Windows Initialization */
        L"\\winlogon.exe",            /* Windows Logon */
        L"\\services.exe",            /* Service Control Manager */
        L"\\lsass.exe",               /* Local Security Authority */
        L"\\lsaiso.exe",              /* LSA Isolated */
        L"\\svchost.exe",             /* Service Host */
        L"\\Registry",                /* Registry 进程 */
        L"\\Memory Compression",      /* 内存压缩（SS L1931） */
        L"\\MemCompression",          /* 内存压缩（wkd CbpIsCriticalBootProcess 既有） */
        L"\\dwm.exe",                 /* Desktop Window Manager */
        L"\\conhost.exe",             /* Console host */
        L"\\ntoskrnl.exe",            /* Kernel（兜底） */
        NULL
    };

    /* System(PID 4) / Idle(PID 0) 直接豁免 */
    if (pid == 4 || pid == 0) {
        return TRUE;
    }

    /* 无现成路径 → 解析进程对象镜像路径（SS L1900-1913） */
    if (!ImagePath || !ImagePath->Buffer || ImagePath->Length == 0) {
        status = PsLookupProcessByProcessId(ProcessId, &process);
        if (!NT_SUCCESS(status)) {
            return FALSE;   /* 进程可能已退出，保守不豁免 */
        }
        status = SeLocateProcessImageName(process, &procName);
        ObDereferenceObject(process);
        if (!NT_SUCCESS(status) || !procName || !procName->Buffer) {
            if (procName) ExFreePool(procName);
            return FALSE;
        }
        ImagePath = procName;
    }

    /* 尾部匹配（非子串，避免 \System 误匹配 System32） */
    for (ULONG i = 0; criticalNames[i] != NULL; i++) {
        RtlInitUnicodeString(&needle, criticalNames[i]);

        if (ImagePath->Length < needle.Length) {
            continue;
        }

        tail.Buffer = (PWCH)((PUCHAR)ImagePath->Buffer +
                             (ImagePath->Length - needle.Length));
        tail.Length = needle.Length;
        tail.MaximumLength = needle.MaximumLength;

        if (RtlEqualUnicodeString(&tail, &needle, TRUE)) {
            isCritical = TRUE;
            break;
        }
    }

    if (procName) {
        ExFreePool(procName);
    }

    return isCritical;
}

/**************************************************/
/*       评分裁决消费 — AeEvaluateVerdict           */
/*                                                  */
/*  迁移自 SS BepDetermineResponse                  */
/*  (BehaviorEngine.c L4481-4497):                  */
/*    Critical → Block / High → Alert。             */
/*  映射到 wkd TsVerdict：                          */
/*    Blocked   → 终止源进程（豁免校验）+ ALPC 上报   */
/*    Malicious → ALPC 上报                          */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
VOID
AeEvaluateVerdict(
    _In_ PAE_PROCESS_PAIR Pair
    )
{
    TS_VERDICT verdict = TsVerdict_Unknown;
    NTSTATUS status;
    PWKD_MESSAGE message;
    ULONG severity = 0;

    if (!Pair || !Pair->TsContext) {
        return;
    }

    status = TsGetVerdict(WkdTsEngine, Pair, &verdict);
    if (!NT_SUCCESS(status) || verdict == TsVerdict_Unknown) {
        return;
    }

    /* 仅高置信恶意（Blocked，阈值 95）触发处置 */
    if (verdict == TsVerdict_Blocked) {
        /* 源进程豁免校验：关键进程不终止（对齐 SS BepIsCriticalProcess） */
        if (!AepIsCriticalProcess(Pair->SourceProcessId, NULL)) {
            PEPROCESS process = NULL;

            status = PsLookupProcessByProcessId(Pair->SourceProcessId, &process);
            if (NT_SUCCESS(status) && process) {
                /* 26100 内核已移除 PsTerminateProcess 导出，改用
                 * ObOpenObjectByPointer + ZwTerminateProcess 等价处置
                 * （两 API 均为 26100 导出，对齐 wdm.h 声明）。 */
                HANDLE processHandle = NULL;

                status = ObOpenObjectByPointer(
                    process,
                    0,
                    NULL,
                    PROCESS_TERMINATE,
                    *PsProcessType,
                    KernelMode,
                    &processHandle);
                if (NT_SUCCESS(status) && processHandle != NULL) {
                    ZwTerminateProcess(processHandle, STATUS_UNSUCCESSFUL);
                    ZwClose(processHandle);
                }
                ObDereferenceObject(process);
            }
        }
        severity = 4;   /* Critical（对齐 SS ThreatSeverity_Critical → Block） */
    } else if (verdict == TsVerdict_Malicious) {
        severity = 3;   /* High（对齐 SS ThreatSeverity_High → Alert） */
    } else {
        return;
    }

    /* ALPC 上报 ThreatLevelChanged（NtfSendMessageAsync 接管消息所有权） */
    message = NtfCreateMessage(WkdMessage_ThreatLevelChanged,
        WkdMessage_SourceThreatScoring, WkdMessage_PriorityCritical, 0);
    if (!message) {
        return;
    }
    message->Header.SourceProcessId = Pair->SourceProcessId;
    message->Header.TargetProcessId = Pair->TargetProcessId;
    message->Header.AtomicRisk = severity;
    NtfSendMessageAsync(message);
}

/**************************************************/
/*           初始化 / 清理                         */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
AeInitialize(
    VOID
    )
{
    NTSTATUS status;
    UNICODE_STRING usFunctionName;

    RtlInitUnicodeString(&usFunctionName, L"PsGetProcessSignatureLevel");
    pfnPsGetProcessSignatureLevel =
        (PFN_PsGetProcessSignatureLevel)MmGetSystemRoutineAddress(&usFunctionName);

    if (!pfnPsGetProcessSignatureLevel) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to get PsGetProcessSignatureLevel address\n");
        return STATUS_NOT_FOUND;
    }

    status = IocInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[Ae] IocInitialize failed: 0x%X\n", status);
        return status;
    }

    status = IoaInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[Ae] IoaInitialize failed: 0x%X\n", status);
        IocCleanup();
        return status;
    }

    /* 启动维护线程 */
    {
        KeInitializeEvent(&g_AeMaintenance.StopEvent,
            SynchronizationEvent, FALSE);

        g_AeMaintenance.Running = TRUE;

        status = PsCreateSystemThread(&g_AeMaintenance.ThreadHandle,
            THREAD_ALL_ACCESS, NULL, NULL, NULL,
            AepMaintenanceThread, NULL);

        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[Ae] PsCreateSystemThread failed: 0x%X (0x%X)\n",
                status, status & 0x0FFFFFFF);
            g_AeMaintenance.Running = FALSE;
            IoaCleanup();
            IocCleanup();
            return status;
        }

        /* 获取线程对象以便后续终止 */
        ObReferenceObjectByHandle(g_AeMaintenance.ThreadHandle,
            THREAD_ALL_ACCESS, *PsThreadType, KernelMode,
            &g_AeMaintenance.ThreadObject, NULL);
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
AeCleanup(
    VOID
    )
{
    /* 停止维护线程 */
    if (g_AeMaintenance.Running) {
        g_AeMaintenance.Running = FALSE;
        KeSetEvent(&g_AeMaintenance.StopEvent, 0, FALSE);

        if (g_AeMaintenance.ThreadObject) {
            KeWaitForSingleObject(g_AeMaintenance.ThreadObject,
                Executive, KernelMode, FALSE, NULL);
            ObDereferenceObject(g_AeMaintenance.ThreadObject);
        }

        if (g_AeMaintenance.ThreadHandle) {
            ZwClose(g_AeMaintenance.ThreadHandle);
        }
    }

    IoaCleanup();
    IocCleanup();
}

/**************************************************/
/*   AeReportIndicator — 指示记录统一提交入口        */
/*                                                   */
/*  分析引擎所有来源（IOC/IOA）均通过本系列提交。     */
/*  提交只插入记录，零计算；得分由 AeOrchestratorDispatch */
/*  尾部 Phase 3 统一结算。                          */
/*                                                   */
/*  IOC 分支: 先写 pair->iocContext 证据链（去重），  */
/*  重复命中不再上报评分系统；新事实才上报。          */
/*  IOA 分支: 写 pair->ioaContext 摘要链（FIFO），    */
/*  同步上报评分系统（双份：证据 + 评分工作集）。     */
/*                                                   */
/*  调用方须持有 pair pin（pin 契约）。               */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
AeReportIndicator(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ TS_SOURCE Source,
    _In_ TS_INDICATOR_TYPE Indicator
    )
/*++
Routine Description:
    IOC 默认入口 — 查分析引擎威胁程度映射表获取默认等级。
    等级为 0（无威胁贡献）时不落记录。

Arguments:
    Pair      - 目标进程对。
    Source    - 来源类型（TsSourceIOC / TsSourceBehavioral）。
    Indicator - 指标类型。

Return Value:
    NTSTATUS。
--*/
{
    AE_THREAT_SEVERITY severity;

    if (!Pair ||
        Source >= TsSourceMaxValue ||
        Indicator >= TsIndicator_MaxValue) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 查默认威胁程度（分析引擎映射表，0 = 无威胁贡献） */
    severity = IocGetIndicatorSeverity(Indicator);
    if (!VALID_SEVERITY(severity)) {
        return STATUS_NOT_SUPPORTED;
    }

    return AeReportIndicatorEx(Pair, Source, Indicator, severity);
}

_Use_decl_annotations_
NTSTATUS
AeReportIndicatorEx(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ TS_SOURCE Source,
    _In_ TS_INDICATOR_TYPE Indicator,
    _In_ AE_THREAT_SEVERITY Severity
    )
/*++
Routine Description:
    统一自定义入口 — 支持所有来源（IOC/IOA）与自定义威胁程度。
    Severity 须为 AE_THREAT_SEVERITY 1-4。
    IOC 分支先经 pair->iocContext 去重（重复命中不再上报）；
    IOA 分支写 pair->ioaContext 摘要链后上报。

Arguments:
    Pair      - 目标进程对。
    Source    - 来源类型（TsSourceIOC / TsSourceBehavioral）。
    Indicator - 指标类型（IOC 0x01xx-0x0Bxx / IOA 0x0Dxx）。
    Severity  - 威胁程度（1-4，0 拒绝）。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;
    LARGE_INTEGER now;
    BOOLEAN isIoa;
    PAE_IOC_CONTEXT iocContext;   /* IOC 分支上下文（Cleanup 路径使用） */

    if (!Pair ||
        Source >= TsSourceMaxValue ||
        Indicator >= TsIndicator_MaxValue ||
        !VALID_SEVERITY(Severity)) {
        return STATUS_INVALID_PARAMETER;
    }

    /* ---- 相关子引擎的Rundown由调用者获取 ---- */

    /* 获取Pair写锁 */
    WkdAcquirePushLockExclusive(&Pair->Lock);

    isIoa = (Source == TsSourceBehavioral);
    if (Source != TsSourceIOC && !isIoa) {
        status = STATUS_NOT_SUPPORTED;
        goto Cleanup;
    }

    KeQuerySystemTime(&now);

    if (isIoa) {
        /* ---- IOA 分支：pair->ioaContext 摘要链（不去重，FIFO 上限） ---- */
        PAE_IOA_RECORD record;
        PAE_IOA_CONTEXT ioaContext = Pair->IoaContext;
        if (!ioaContext) {
            status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }

        record = ExAllocatePool2(POOL_FLAG_NON_PAGED,
            sizeof(AE_IOA_RECORD), 'ioaS');
        if (!record) {
            status = STATUS_NO_MEMORY;
            goto Cleanup;
        }
        
        record->Indicator = Indicator;
        record->Severity = Severity;
        record->Timestamp = now;

        /* 遵循FIFO，但并未判断是否过期 */
        while (InterlockedCompareExchange(
            &ioaContext->IoaChainCount, 0, 0) >= WKD_MAX_IOA_CHAIN_RECORDS &&
            !IsListEmpty(&ioaContext->IoaChain)) {
            PLIST_ENTRY oldest = RemoveHeadList(&ioaContext->IoaChain);
            ExFreePoolWithTag(
                CONTAINING_RECORD(oldest, AE_IOA_RECORD, Link), 'ioaS');
            ioaContext->IoaChainCount--;
        }

        InsertTailList(&ioaContext->IoaChain, &record->Link);
        ioaContext->IoaChainCount++;
    } else {
        /* ---- IOC 分支：pair->iocContext 证据链去重 ---- */
        PAE_IOC_RECORD record;

        iocContext = Pair->IocContext;
        if (!iocContext) {
            status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }

        if (IocIndicatorDedupLocked(
                iocContext, Indicator, Severity, now)) {
            /* 重复命中：更新证据链，不再上报评分系统 */
            status = STATUS_SUCCESS;
            goto Cleanup;
        }
        
        record = ExAllocatePool2(POOL_FLAG_NON_PAGED,
            sizeof(AE_IOC_RECORD), 'iocN');
        if (!record) {
            status = STATUS_NO_MEMORY;
            goto Cleanup;
        }
        record->Indicator = Indicator;
        record->Severity = (AE_THREAT_SEVERITY)Severity;
        record->Timestamp = now;

        InsertTailList(&iocContext->IocChain, &record->Link);
        iocContext->ActiveRecords++;
        iocContext->TotalRecords++;
    }

    /* 上报评分系统（IOC 仅新事实；IOA 每次提交） */
    status = TsReportIndicatorLocked(
        WkdTsEngine, Pair, Source, Indicator, Severity);

Cleanup:
    WkdReleasePushLockExclusive(&Pair->Lock);
    return status;
}

/**************************************************/
/*   AeReportIndicatorPair — PID 对便捷入口         */
/*                                                   */
/*  流水线外调用点（如 SyscallHijack 栈篡改上报）     */
/*  内部: 建 pair → 提交 → 解引用。                 */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
AeReportIndicatorPair(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ TS_SOURCE Source,
    _In_ TS_INDICATOR_TYPE Indicator,
    _In_ UCHAR Severity
    )
/*++
Routine Description:
    PID 对便捷入口 — 内部 AeFindOrCreateProcessPair → AeReportIndicatorEx
    → PsDereferenceWkdProcessPair。Severity = 0 时查分析引擎默认威胁程度表。

Arguments:
    SourceProcessId - 源进程 PID。
    TargetProcessId - 目标进程 PID。
    Source          - 来源类型（TsSourceIOC / TsSourceBehavioral）。
    Indicator       - 指标类型。
    Severity        - 威胁程度（0 = 查默认等级表）。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;
    PAE_PROCESS_PAIR pair;
    UCHAR effectiveSeverity = Severity;

    if (!SourceProcessId || !TargetProcessId ||
        Source >= TsSourceMaxValue ||
        Indicator >= TsIndicator_MaxValue) {
        return STATUS_INVALID_PARAMETER;
    }

    status = AeFindOrCreateProcessPair(SourceProcessId, TargetProcessId, &pair);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (effectiveSeverity == 0) {
        effectiveSeverity = IocGetIndicatorSeverity(Indicator);
        if (!VALID_SEVERITY(effectiveSeverity)) {
            PsDereferenceWkdProcessPair(pair);
            return STATUS_SUCCESS;
        }
    }

    status = AeReportIndicatorEx(
        pair, Source, Indicator, effectiveSeverity);

    PsDereferenceWkdProcessPair(pair);

    return status;
}

