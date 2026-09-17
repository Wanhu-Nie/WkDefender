
#include "HollowingDetector.h"
// 【WkD 迁移说明】
// 源文件（SS HollowingDetector.c）此处原为 5 行 SS 工具/框架 include：
//   #include "../Utilities/MemoryUtils.h"
//   #include "../Utilities/HashUtils.h"
//   #include "../Utilities/ProcessUtils.h"
//   #include "../ETW/TelemetryEvents.h"
//   #include "../Core/Globals.h"
// WkD 项目中均不存在，本文件所需 API 已按 WkD 规范处理：
//   内存分配/释放：ShadowStrikeAllocatePoolWithTag -> ExAllocatePool2、
//                  ShadowStrikeFreePoolWithTag -> ExFreePoolWithTag；
//   哈希：ShadowStrikeComputeSha256 -> CoComputeSha256
//         （Common/BCryptUtils.h，SHA-256 子系统已由 SelfProtectionEngine 初始化）；
//   ShadowStrikeIsUserAddress 为本文件内自带宏（下方定义），不依赖 MemoryUtils.h；
//   进程路径获取使用 SeLocateProcessImageName（WDK API），无需 ProcessUtils.h；
//   本文件不使用 TelemetryEvents.h / Globals.h 的任何符号。
// 故 5 行 include 迁移时删除，新增 BCryptUtils.h 替代哈希设施。
// 【WkD 迁移说明】（2026-09-13，Memory → Process 域迁移）
// 本文件自 Memory/ 目录迁入 Process/ 进程域，并适配 WKD_PROCESS 权威副本：
//   新增公共入口 PhAnalyzeWkdProcess —— 直接消费 WKD_PROCESS（Core.ProcessId /
//   Core.EProcess / Core.ImagePath），免去 PsLookupProcessByProcessId 与
//   SeLocateProcessImageName 重复采集；原 PsAnalyzeProcessHollowing（按 PID）API 保持
//   兼容，两入口共用私有分析主体 PspAnalyzeProcessHollowingInternal。
//   ProcessMonitor.h 提供 WKD_PROCESS 完整定义（头文件保留前向声明）。
#include "ProcessMonitor.h"
#include "../Include/Process/WkdProcess.h"  /* PsGetMainModuleImageBase / PsLookupModuleInstanceByImageBase（非锁版模块链查询，2026-09-13） */
#include "../Common/BCryptUtils.h"
#include "../Common/Utils.h"   /* CoCopyUnicodeString 等字符串工具（锁原语已下沉 ProcessModuleTracker，2026-09-13） */
#include "../Memory/MemoryIntegrity.h"  /* Mi* 跨模块辅助（跨进程读取/主模块定位/镜像比对，2026-09-13 迁入 Memory 域） */
#include <ntimage.h>

// ============================================================================
// 内核态类型定义
// ============================================================================
//
// 进程访问权限 — 定义于 winnt.h（用户态），但 WDK 内核头文件中不一定
// 可用。若未定义则在此定义。
//
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ             0x0010
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION   0x0400
#endif

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

//
// PROCESS_BASIC_INFORMATION 已在 ntddk.h 中定义 — 无需重复定义。
//

//
// PEB 与 RTL_USER_PROCESS_PARAMETERS 直接使用 ntddk.h 的官方完整结构
// （2026-09-13 去自定义子集：官方结构跨架构自动适配，避免自定义头漂移）。
// 读取量为 sizeof(PEB)，PEB 在进程地址空间完整映射，无越界风险。
//

//
// 用户态地址校验辅助函数。
//
#ifndef SHADOWSTRIKE_IS_USER_ADDRESS_DECLARED
#define ShadowStrikeIsUserAddress(addr) \
    ((ULONG_PTR)(addr) >= 0x10000 && (ULONG_PTR)(addr) < (ULONG_PTR)MM_HIGHEST_USER_ADDRESS)
#define SHADOWSTRIKE_IS_USER_ADDRESS_DECLARED
#endif

#define PH_VERSION                      1
#define PH_MAX_CALLBACKS                8
#define PH_SHUTDOWN_TIMEOUT_100NS       (-(LONGLONG)10 * 1000 * 10000)  // 10 秒

//
// 基于 CAS 的生命周期状态（C-1、H-1、H-5 修复）
//
#define PH_STATE_UNINITIALIZED          0
#define PH_STATE_INITIALIZING           1
#define PH_STATE_READY                  2
#define PH_STATE_SHUTTING_DOWN          3

//
// 置信度评分权重
//
#define PH_SCORE_IMAGE_MISMATCH         25
#define PH_SCORE_SECTION_MISMATCH       20
#define PH_SCORE_ENTRY_MODIFIED         30
#define PH_SCORE_HEADER_MODIFIED        25
#define PH_SCORE_UNMAPPED_MODULE        35
#define PH_SCORE_TRANSACTED             40
#define PH_SCORE_DELETED_FILE           45
#define PH_SCORE_SUSPENDED_THREAD       15
#define PH_SCORE_PEB_MODIFIED           30
#define PH_SCORE_NO_PHYSICAL_FILE       35
#define PH_SCORE_HASH_MISMATCH          40
#define PH_SCORE_TIMESTAMP_ANOMALY      10

//
// 严重度权重
//
#define PH_SEVERITY_BASE                20
#define PH_SEVERITY_CRITICAL_INDICATOR  30
#define PH_SEVERITY_HIGH_INDICATOR      20
#define PH_SEVERITY_MEDIUM_INDICATOR    10

// ============================================================================
// 私有结构
// ============================================================================

/**
 * @brief 回调注册条目。
 */
typedef struct _PH_CALLBACK_ENTRY {
    PH_DETECTION_CALLBACK Callback;
    PVOID Context;
    BOOLEAN InUse;
} PH_CALLBACK_ENTRY, *PPH_CALLBACK_ENTRY;

/**
 * @brief 扩展的内部检测器结构。
 *
 * 使用基于 CAS 的状态机进行生命周期管理。
 * 公共的 PH_DETECTOR 作为第一个成员嵌入，
 * 方便调用方通过 CONTAINING_RECORD 访问。
 */
typedef struct _PH_DETECTOR_INTERNAL {
    //
    // 基础公共结构
    //
    PH_DETECTOR Public;

    //
    // 生命周期状态（基于 CAS：PH_STATE_*）
    //
    volatile LONG State;

    //
    // 回调管理
    //
    PH_CALLBACK_ENTRY Callbacks[PH_MAX_CALLBACKS];
    EX_PUSH_LOCK CallbackLock;

    //
    // 关闭同步
    //
    volatile LONG ActiveOperations;
    KEVENT ShutdownEvent;

} PH_DETECTOR_INTERNAL, *PPH_DETECTOR_INTERNAL;

//
// 分析上下文（PH_ANALYSIS_CONTEXT）已于 2026-09-13 删除：
// 阶段函数直接消费 WKD_PROCESS 权威副本（可选，NULL = 链外进程）+ PEPROCESS，
// 主模块定位经模块链（PsGetMainModuleImageBase 查 MainModule==TRUE
// 实例，闭锁由阶段函数自持 ModuleContext.Lock 共享锁），取代 PEB attach 探测。
// 映像比对 / 入口点分析对无模块链进程返回 STATUS_NOT_FOUND（跳过，
// 模块链是映像事实的唯一来源）。
//

// ============================================================================
// 前向声明
// ============================================================================

//
// PsGetProcessPeb：由 ntoskrnl.exe 导出；不在任何 WDK 公共头文件中。
// 返回给定 EPROCESS 的用户态 PEB 地址。
// 返回的指针位于目标进程的地址空间中 —
// 调用方在解引用之前必须附加（KeStackAttachProcess）。
//
#ifndef SHADOWSTRIKE_PS_GET_PROCESS_PEB_DECLARED
NTKERNELAPI
PPEB
NTAPI
PsGetProcessPeb(
    _In_ PEPROCESS Process
    );
#define SHADOWSTRIKE_PS_GET_PROCESS_PEB_DECLARED
#endif

static PPH_ANALYSIS_RESULT
PhpAllocateResult(
    VOID
    );

static VOID
PhpFreeResultInternal(
    _In_ PPH_ANALYSIS_RESULT Result
    );

static NTSTATUS
PhpAnalyzeImageComparison(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_opt_ PWKD_PROCESS WkdProcess,
    _In_ PEPROCESS Process,
    _Inout_ PPH_ANALYSIS_RESULT Result
    );

static NTSTATUS
PhpAnalyzeEntryPoint(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_opt_ PWKD_PROCESS WkdProcess,
    _In_ PEPROCESS Process,
    _Inout_ PPH_ANALYSIS_RESULT Result
    );

static NTSTATUS
PhpAnalyzePEB(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_opt_ PWKD_PROCESS WkdProcess,
    _In_ PEPROCESS Process,
    _Inout_ PPH_ANALYSIS_RESULT Result
    );

static NTSTATUS
PhpAnalyzeSectionBacking(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_opt_ PWKD_PROCESS WkdProcess,
    _In_ PEPROCESS Process,
    _Inout_ PPH_ANALYSIS_RESULT Result
    );

/*（原 PhpCheckFileTransacted / PhpCheckFileDeleted 前向声明已于 2026-09-13
 * 删除——文件级 TxF / DeletePending 检测内联至 PhCheckForDoppelganging /
 * PhCheckForGhosting，不再作为独立私有辅助函数）*/

static VOID
PhpCalculateScores(
    _Inout_ PPH_ANALYSIS_RESULT Result
    );

static PH_HOLLOWING_TYPE
PhpDetermineHollowingType(
    _In_ PPH_ANALYSIS_RESULT Result
    );

static VOID
PhpInvokeCallbacks(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_ PPH_ANALYSIS_RESULT Result
    );

/**
 * @brief 以原子方式获取引用。若正在关闭则返回 FALSE。
 * （C-1、H-1 修复：先递增后检查模式可防止释放后使用）
 */
static BOOLEAN
PhpAcquireReference(
    _In_ PPH_DETECTOR_INTERNAL Detector
    );

static VOID
PhpReleaseReference(
    _In_ PPH_DETECTOR_INTERNAL Detector
    );

static NTSTATUS
PspAnalyzeProcessHollowingInternal(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_opt_ PWKD_PROCESS WkdProcess,
    _In_ PEPROCESS Process,
    _In_opt_ PUNICODE_STRING ImagePath,
    _In_ LARGE_INTEGER CreateTime,
    _Inout_ PPH_ANALYSIS_RESULT Result
    );

static NTSTATUS
PhpOpenProcessForAnalysis(
    _In_ HANDLE ProcessId,
    _Out_ PHANDLE ProcessHandle,
    _Out_ PEPROCESS* Process
    );

/**
 * @brief 就绪状态的内联状态检查。
 */
static FORCEINLINE BOOLEAN
PhpIsReady(
    _In_ PPH_DETECTOR_INTERNAL Detector
    )
{
    return (ReadAcquire(&Detector->State) == PH_STATE_READY);
}

// ============================================================================
// 初始化与关闭
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PhInitialize(
    _Out_ PPH_DETECTOR* Detector
    )
{
    PPH_DETECTOR_INTERNAL internal = NULL;
    LONG previousState;

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    //
    // 分配检测器结构
    //
    internal = (PPH_DETECTOR_INTERNAL)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(PH_DETECTOR_INTERNAL),
        PH_POOL_TAG_CONTEXT
    );

    if (internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(internal, sizeof(PH_DETECTOR_INTERNAL));

    //
    // CAS 状态：UNINITIALIZED -> INITIALIZING（C-1 修复）
    //
    previousState = InterlockedCompareExchange(
        &internal->State,
        PH_STATE_INITIALIZING,
        PH_STATE_UNINITIALIZED
    );

    if (previousState != PH_STATE_UNINITIALIZED) {
        ExFreePoolWithTag(internal, PH_POOL_TAG_CONTEXT);
        return STATUS_UNSUCCESSFUL;
    }

    //
    // 初始化同步原语
    //
    ExInitializePushLock(&internal->CallbackLock);

    //
    // 初始化关闭同步
    //
    KeInitializeEvent(&internal->ShutdownEvent, NotificationEvent, FALSE);
    internal->ActiveOperations = 1;  // 初始化引用 — 由 PhShutdown 释放

    //
    // 设置默认配置
    //
    internal->Public.Config.CompareWithFile = TRUE;
    internal->Public.Config.AnalyzePEB = TRUE;
    internal->Public.Config.AnalyzeEntryPoint = TRUE;
    internal->Public.Config.AnalyzeMemoryRegions = TRUE;  // 已弃用（2026-09-13）：保留置位仅为公共 API 兼容，
                                                          // Hollowing 不再执行 VAD 枚举（见 DefensiveEvasion.h）
    internal->Public.Config.CompareWritableSections = FALSE;
    internal->Public.Config.TimeoutMs = PH_SCAN_TIMEOUT_MS;
    internal->Public.Config.MinConfidenceToReport = 50;

    //
    // 初始化统计信息
    //
    KeQuerySystemTime(&internal->Public.Stats.StartTime);

    //
    // 状态转换：INITIALIZING -> READY
    //
    MemoryBarrier();
    InterlockedExchange(&internal->State, PH_STATE_READY);

    *Detector = &internal->Public;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PhShutdown(
    _Inout_ PPH_DETECTOR Detector
    )
{
    PPH_DETECTOR_INTERNAL internal;
    LARGE_INTEGER timeout;
    LONG previousState;

    if (Detector == NULL) {
        return;
    }

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    //
    // CAS 状态：READY -> SHUTTING_DOWN（C-1 修复）
    //
    previousState = InterlockedCompareExchange(
        &internal->State,
        PH_STATE_SHUTTING_DOWN,
        PH_STATE_READY
    );

    if (previousState != PH_STATE_READY) {
        return;
    }

    //
    // 释放初始化引用并等待活动操作全部完成。
    // 有界超时防止无限挂起。
    //
    PhpReleaseReference(internal);
    timeout.QuadPart = PH_SHUTDOWN_TIMEOUT_100NS;
    KeWaitForSingleObject(
        &internal->ShutdownEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );

    //
    // 最终状态转换与释放
    //
    InterlockedExchange(&internal->State, PH_STATE_UNINITIALIZED);

    ExFreePoolWithTag(internal, PH_POOL_TAG_CONTEXT);
}

// ============================================================================
// 进程分析
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PhAnalyzeWkdProcess(
    _In_ PPH_DETECTOR Detector,
    _In_ PWKD_PROCESS WkdProcess,
    _Out_ PPH_ANALYSIS_RESULT* Result
    )
/*++
Routine Description:
    基于 WKD_PROCESS 权威副本的进程镂空/幽灵全量分析入口。

    与 PsAnalyzeProcessHollowing 的区别：
      - 进程标识直接取自 WkdProcess->Core（ProcessId / EProcess），
        免去 PsLookupProcessByProcessId 二次查找；
      - 镜像路径复用 WkdProcess->Core.ImagePath（权威副本内维护，
        随进程生命周期有效），免去 SeLocateProcessImageName 重复采集；
      - EProcess 引用保护（M-5 模式）：分析窗口内经 ObReferenceObjectSafe
        额外持引用，防"分析中出现进程退出"竞态；
      - 不回写 WkdProcess->SecurityContext->IsGhostingDetected —— 该字段
        由 AnalysisEngine/IocProcess.c §5 IocpDetectGhosting 独占维护，
        本模块检测结果经 Result 返回 + PhRegisterCallback 回调上送。

Arguments:
    Detector    - 检测器实例（PhInitialize 输出）。
    WkdProcess  - WKD_PROCESS 权威副本（调用方持有引用，分析期间不得释放）。
    Result      - 输出：全量分析结果（调用方以 PhFreeResult 释放）。

Return Value:
    STATUS_SUCCESS / NTSTATUS 错误码。成功时 *Result 非 NULL。
--*/
{
    NTSTATUS status;
    PPH_DETECTOR_INTERNAL internal;
    PPH_ANALYSIS_RESULT result = NULL;
    LARGE_INTEGER startTime;

    if (Detector == NULL || WkdProcess == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (!PhpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeQuerySystemTime(&startTime);

    //
    // M-5 fix: 调用方持 WKD_PROCESS 引用，Core.EProcess 在进程存活期内通常
    // 有效；分析窗口内再持一次引用防进程退出竞态（对齐 PsAnalyzeProcessHollowingAtCreation
    // 的 ObReferenceObjectSafe 模式）。
    //
    if (!ObReferenceObjectSafe(WkdProcess->Core.EProcess)) {
        PhpReleaseReference(internal);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    //
    // 阶段函数直接消费 WKD_PROCESS 权威副本（2026-09-13 去 PH_ANALYSIS_CONTEXT）：
    // ProcessId / EProcess / ImagePath / CreateTime 均取自 Core；主模块定位
    // 下沉到各阶段函数自身——经 PsGetMainModuleImageBase 查模块链
    // （MainModule==TRUE 实例），免 PEB attach 探测与重复 PE 解析。
    //
    //
    // C-4 fix: 结果恒走池分配（public API 返回值，PhFreeResult 以池释放）。
    //
    result = PhpAllocateResult();
    if (result == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(result, sizeof(PH_ANALYSIS_RESULT));
    result->ProcessId = WkdProcess->Core.ProcessId;
    result->AnalysisTime = startTime;
    result->ProcessCreateTime.QuadPart = WkdProcess->Core.CreateTime.QuadPart;

    //
    // 复用权威副本镜像路径（深拷贝入 Result，之后由 PhFreeResult 释放）。
    // 无路径本身即幽灵/无实体文件可疑信号（对齐 IocpDetectGhosting Phase 1）。
    //
    if (WkdProcess->Core.ImagePath != NULL &&
        WkdProcess->Core.ImagePath->Buffer != NULL &&
        WkdProcess->Core.ImagePath->Length > 0) {

        CoCopyUnicodeString(
            &result->ActualImagePath,
            WkdProcess->Core.ImagePath
        );

        if (result->ActualImagePath == NULL) {
            result->Indicators |= PhIndicator_NoPhysicalFile;
        }
    } else {
        result->Indicators |= PhIndicator_NoPhysicalFile;
    }

    //
    // 全量分析（与 PsAnalyzeProcessHollowing / PsAnalyzeProcessHollowingAtCreation 共用主体）
    //
    status = PspAnalyzeProcessHollowingInternal(
        internal,
        WkdProcess,
        WkdProcess->Core.EProcess,
        (WkdProcess->Core.ImagePath != NULL) ? WkdProcess->Core.ImagePath : NULL,
        WkdProcess->Core.CreateTime,
        result
    );

    *Result = result;
    result = NULL;
    status = STATUS_SUCCESS;

Cleanup:
    if (result != NULL) {
        PhpFreeResultInternal(result);
    }

    ObDereferenceObject(WkdProcess->Core.EProcess);

    PhpReleaseReference(internal);

    return status;
}

_Use_decl_annotations_
NTSTATUS
PsAnalyzeProcessHollowing(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PPH_ANALYSIS_RESULT* Result
    )
/*++
Routine Description:
    按 PID 的进程镂空/幽灵全量分析入口（兼容原 SS API）。

    内部 PsLookupProcessByProcessId → ObOpenObjectByPointer → PspAnalyzeProcessHollowingInternal。
    WKD_PROCESS 权威副本持有方应优先使用 PhAnalyzeWkdProcess。

Arguments:
    Detector    - 检测器实例。
    ProcessId   - 目标进程 PID。
    Result      - 输出：全量分析结果（PhFreeResult 释放）。

Return Value:
    STATUS_SUCCESS / NTSTATUS 错误码。成功时 *Result 非 NULL。
--*/
{
    NTSTATUS status;
    PPH_DETECTOR_INTERNAL internal;
    PPH_ANALYSIS_RESULT result = NULL;
    HANDLE processHandle = NULL;
    PEPROCESS process = NULL;
    LARGE_INTEGER startTime;

    if (Detector == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (!PhpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeQuerySystemTime(&startTime);

    //
    // 打开目标进程（保留旧复合入口 PsLookup + ObOpen；核心阶段已全部
    // Context 化/内部自开句柄，此句柄仅随旧流程持有释放，2026-09-13）
    //
    status = PhpOpenProcessForAnalysis(ProcessId, &processHandle, &process);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // 分配结果结构（C-4 修复：通过公共 API 返回给调用方的结果
    // 一律使用池分配，绝不用后备列表（lookaside），
    // 以便 PhFreeResult 可以安全地使用池释放）
    //
    result = PhpAllocateResult();
    if (result == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(result, sizeof(PH_ANALYSIS_RESULT));
    result->ProcessId = ProcessId;
    result->AnalysisTime = startTime;

    //
    // 2026-09-13：优先查 WKD_PROCESS 权威副本（PsLookupWkdProcessByProcessId
    // 返回 +1 引用，配对 PsDereferenceWkdProcess）——命中则 ImagePath /
    // CreateTime 取权威值、阶段函数可查模块链定位主模块；未命中（链外进程）
    // 则 ImagePath=NULL（SeLocate 兜底）/ CreateTime 由 EPROCESS 采集。
    //
    {
        PWKD_PROCESS wkd = NULL;
        PUNICODE_STRING imagePath = NULL;
        LARGE_INTEGER createTime;

        wkd = PsLookupWkdProcessByProcessId(ProcessId);
        if (wkd != NULL) {
            imagePath = (wkd->Core.ImagePath != NULL) ? wkd->Core.ImagePath : NULL;
            createTime = wkd->Core.CreateTime;
        } else {
            createTime.QuadPart = PsGetProcessCreateTimeQuadPart(process);
        }

        //
        // 全量分析（与 PhAnalyzeWkdProcess 共用主体）
        //
        status = PspAnalyzeProcessHollowingInternal(
            internal,
            wkd,
            process,
            imagePath,
            createTime,
            result
        );

        if (wkd != NULL) {
            PsDereferenceWkdProcess(wkd);
        }
    }

    *Result = result;
    result = NULL;
    status = STATUS_SUCCESS;

Cleanup:
    if (result != NULL) {
        PhpFreeResultInternal(result);
    }

    if (processHandle != NULL) {
        ZwClose(processHandle);
    }

    if (process != NULL) {
        ObDereferenceObject(process);
    }

    PhpReleaseReference(internal);

    return status;
}

/**************************************************/
/*  私有：共用分析主体                               */
/*  （PsAnalyzeProcessHollowing / PhAnalyzeWkdProcess 共用）  */
/**************************************************/

//
// PspAnalyzeProcessHollowingInternal
//
// 全量镂空检测流水线（主体自原 PsAnalyzeProcessHollowing 抽取，2026-09-13 重构）：
//   1. 镜像路径采集（WKD_PROCESS 入口已预填 ActualImagePath 时跳过）；
//   2. Section 实体/事务/删除检查（doppelganging / ghosting 信号）；
//   3. 内存镜像 vs 磁盘文件比对；
//   4. 入口点校验；
//   5. PEB 篡改分析；
//   6. 内存区域枚举（RWX / 无实体可执行）；
//   7. 评分 + 镂空类型判定 + 统计 + 回调上送。
//
// 各分析阶段独立容错：单阶段失败不影响整体结果（保持原语义）。
//
static NTSTATUS
PspAnalyzeProcessHollowingInternal(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_opt_ PWKD_PROCESS WkdProcess,
    _In_ PEPROCESS Process,
    _In_opt_ PUNICODE_STRING ImagePath,
    _In_ LARGE_INTEGER CreateTime,
    _Inout_ PPH_ANALYSIS_RESULT Result
    )
{
    NTSTATUS status;
    LARGE_INTEGER startTime;
    LARGE_INTEGER endTime;

    KeQuerySystemTime(&startTime);

    //
    // 进程创建时间：WKD_PROCESS / 查链入口由入口处预填；此处兜底补齐
    //
    if (Result->ProcessCreateTime.QuadPart == 0) {
        Result->ProcessCreateTime.QuadPart = CreateTime.QuadPart;
    }

    //
    // 获取进程镜像路径（WKD_PROCESS 入口已预填 ActualImagePath 时跳过；
    // 否则优先提交的权威副本指针，最后回退 SeLocateProcessImageName，
    // 避免重复采集）
    //
    if (Result->ActualImagePath == NULL) {
        if (ImagePath != NULL) {
            status = CoCopyUnicodeString(&Result->ActualImagePath, ImagePath);
            if (!NT_SUCCESS(status) || Result->ActualImagePath == NULL) {
                //
                // 拷贝失败也继续分析 - 这本身就是可疑的
                //
                Result->Indicators |= PhIndicator_NoPhysicalFile;
            }
        } else {
            PUNICODE_STRING processImageName = NULL;

            status = SeLocateProcessImageName(Process, &processImageName);
            if (NT_SUCCESS(status) && processImageName != NULL) {
                status = CoCopyUnicodeString(&Result->ActualImagePath, processImageName);
                ExFreePool(processImageName);
            }

            if (!NT_SUCCESS(status) || Result->ActualImagePath == NULL) {
                //
                // 即使没有路径也继续分析 - 这本身就是可疑的
                //
                Result->Indicators |= PhIndicator_NoPhysicalFile;
            }
        }
    }

    //
    // 执行 Section/文件后备（backing）分析
    //
    status = PhpAnalyzeSectionBacking(Detector, WkdProcess, Process, Result);
    if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND) {
        //
        // 非关键 - 继续
        //
    }

    //
    // 将内存中的镜像与文件比对
    //
    if (Detector->Public.Config.CompareWithFile) {
        status = PhpAnalyzeImageComparison(Detector, WkdProcess, Process, Result);
        if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND) {
            //
            // 非关键 - 继续
            //
        }
    }

    //
    // 校验入口点
    //
    if (Detector->Public.Config.AnalyzeEntryPoint) {
        status = PhpAnalyzeEntryPoint(Detector, WkdProcess, Process, Result);
        if (!NT_SUCCESS(status)) {
            //
            // 非关键 - 继续
            //
        }
    }

    //
    // 分析 PEB 是否被篡改
    //
    if (Detector->Public.Config.AnalyzePEB) {
        status = PhpAnalyzePEB(Detector, WkdProcess, Process, Result);
        if (!NT_SUCCESS(status)) {
            //
            // 非关键 - 继续
            //
        }
    }

    //
    // 计算置信度与严重度评分
    //
    PhpCalculateScores(Result);

    //
    // 确定镂空（hollowing）类型
    //
    Result->Type = PhpDetermineHollowingType(Result);
    Result->HollowingDetected = (Result->Type != PhHollowing_None);

    //
    // 计算分析耗时。对时钟回拨/偏移进行钳制，防止时间倒退时
    // 通过无符号溢出合成出约 4.29e9 毫秒的耗时。
    //
    KeQuerySystemTime(&endTime);
    if (endTime.QuadPart > startTime.QuadPart) {
        Result->AnalysisDurationMs =
            (ULONG)min((ULONGLONG)((endTime.QuadPart - startTime.QuadPart) / 10000),
                       (ULONGLONG)MAXULONG);
    } else {
        Result->AnalysisDurationMs = 0;
    }

    //
    // 更新统计信息
    //
    InterlockedIncrement64(&Detector->Public.Stats.ProcessesAnalyzed);

    if (Result->HollowingDetected) {
        InterlockedIncrement64(&Detector->Public.Stats.HollowingDetected);

        if (Result->Type == PhHollowing_Doppelganging) {
            InterlockedIncrement64(&Detector->Public.Stats.DoppelgangingDetected);
        } else if (Result->Type == PhHollowing_Ghosting) {
            InterlockedIncrement64(&Detector->Public.Stats.GhostingDetected);
        }

        //
        // 调用回调以通知检测结果
        //
        if (Result->ConfidenceScore >= Detector->Public.Config.MinConfidenceToReport) {
            PhpInvokeCallbacks(Detector, Result);
        }
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PsAnalyzeProcessHollowingAtCreation(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentId,
    _In_ PEPROCESS Process,
    _Out_ PPH_ANALYSIS_RESULT* Result
    )
{
    NTSTATUS status;
    PPH_DETECTOR_INTERNAL internal;
    PPH_ANALYSIS_RESULT result = NULL;
    PWKD_PROCESS wkd = NULL;
    PUNICODE_STRING imagePath = NULL;
    LARGE_INTEGER createTime;
    LARGE_INTEGER startTime;

    UNREFERENCED_PARAMETER(ParentId);

    if (Detector == NULL || Process == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Result = NULL;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (!PhpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeQuerySystemTime(&startTime);

    //
    // M-5 修复：使用 ObReferenceObjectSafe 处理正在终止的进程对象
    //
    if (!ObReferenceObjectSafe(Process)) {
        PhpReleaseReference(internal);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    //
    // 2026-09-13：优先查 WKD_PROCESS 权威副本（PsLookupWkdProcessByProcessId
    // 返回 +1 引用）——创建回调内权威副本通常已登记，命中则 ImagePath /
    // CreateTime 取权威值、阶段函数可查模块链；未命中（限流丢弃等）则
    // ImagePath=NULL（SeLocate 兜底）/ CreateTime 由 EPROCESS 采集。
    //
    wkd = PsLookupWkdProcessByProcessId(ProcessId);
    if (wkd != NULL) {
        imagePath = (wkd->Core.ImagePath != NULL) ? wkd->Core.ImagePath : NULL;
        createTime = wkd->Core.CreateTime;
    } else {
        createTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);
    }

    //
    // 分配结果结构（C-4 修复：使用池分配，而非后备链表 lookaside）
    //
    result = PhpAllocateResult();
    if (result == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(result, sizeof(PH_ANALYSIS_RESULT));
    result->ProcessId = ProcessId;
    result->AnalysisTime = startTime;

    //
    // 创建时刻主线程通常处于挂起状态——共用核心会先检查节（Section）后备，
    // 再执行镜像比对/入口点/PEB/内存区域分析（与 PhAnalyzeWkdProcess /
    // PsAnalyzeProcessHollowing 共用主体，2026-09-13 收敛去重复实现）
    //
    status = PspAnalyzeProcessHollowingInternal(
        internal,
        wkd,
        Process,
        imagePath,
        createTime,
        result
    );

    if (wkd != NULL) {
        PsDereferenceWkdProcess(wkd);
    }

    *Result = result;
    result = NULL;
    status = STATUS_SUCCESS;

Cleanup:
    if (result != NULL) {
        PhpFreeResultInternal(result);
    }

    ObDereferenceObject(Process);

    PhpReleaseReference(internal);

    return status;
}

_Use_decl_annotations_
NTSTATUS
PhQuickCheck(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsHollowed,
    _Out_opt_ PPH_HOLLOWING_TYPE Type,
    _Out_opt_ PULONG Score
    )
{
    NTSTATUS status;
    PPH_ANALYSIS_RESULT result = NULL;

    if (Detector == NULL || IsHollowed == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsHollowed = FALSE;
    if (Type != NULL) *Type = PhHollowing_None;
    if (Score != NULL) *Score = 0;

    //
    // 执行完整分析
    //
    status = PsAnalyzeProcessHollowing(Detector, ProcessId, &result);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // 提取快速结果
    //
    *IsHollowed = result->HollowingDetected;

    if (Type != NULL) {
        *Type = result->Type;
    }

    if (Score != NULL) {
        *Score = result->ConfidenceScore;
    }

    PhFreeResult(result);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PhValidateEntryPoint(
    _In_ PPH_DETECTOR Detector,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN Valid
    )
{
    NTSTATUS status;
    PPH_DETECTOR_INTERNAL internal;
    HANDLE processHandle = NULL;
    PEPROCESS process = NULL;
    PPH_ANALYSIS_RESULT result = NULL;

    if (Detector == NULL || Valid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Valid = FALSE;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (!PhpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // 打开进程
    //
    status = PhpOpenProcessForAnalysis(ProcessId, &processHandle, &process);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // 分配临时结果结构
    //
    result = PhpAllocateResult();
    if (result == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(result, sizeof(PH_ANALYSIS_RESULT));

    //
    // 2026-09-13：入口点专项分析直接以 PID 查权威副本并传链（阶段函数
    // 内部查模块链定位主模块；未命中则返回 STATUS_NOT_FOUND，Valid 保持
    // FALSE——模块链是映像事实的唯一来源，不再做 attach 探测）
    //
    {
        PWKD_PROCESS wkd = NULL;

        wkd = PsLookupWkdProcessByProcessId(ProcessId);

        status = PhpAnalyzeEntryPoint(internal, wkd, process, result);

        if (wkd != NULL) {
            PsDereferenceWkdProcess(wkd);
        }
    }

    if (NT_SUCCESS(status)) {
        *Valid = result->EntryPoint.EntryPointValid &&
                 result->EntryPoint.EntryPointExecutable &&
                 result->EntryPoint.EntryPointInImage;
    }

Cleanup:
    if (result != NULL) {
        PhpFreeResultInternal(result);
    }

    if (processHandle != NULL) {
        ZwClose(processHandle);
    }

    if (process != NULL) {
        ObDereferenceObject(process);
    }

    PhpReleaseReference(internal);

    return status;
}

_Use_decl_annotations_
NTSTATUS
PhCheckForDoppelganging(
    _In_ PPH_DETECTOR Detector,
    _In_ PWKD_PROCESS WkdProcess,
    _Out_ PBOOLEAN IsDoppelganging
    )
/* ++
 * 进程伪装 (T1055.013)
 * TxF（Transactional NTFS）是 Windows Vista 引入的用于安全文件操作的机制，允许应用程序将一组文件操作作为一个原子事务来执行。TxF 保证：在事务提交之前，**所有其他进程只能读取该文件的“已提交版本”**，而看不到事务内的修改。
 * 1. **Transact（事务）**：创建一个 TxF 事务，用合法可执行文件（通常是签名过的微软二进制文件）打开一个事务句柄，然后**在事务上下文中将恶意代码写入该文件**。由于事务的隔离性，磁盘上的原始文件保持不变，其他进程（包括杀软）扫描时看到的仍是合法的原始文件。
 * 2. **Load（加载）**：从被“污染”的事务文件中**创建一个内存节区（Section）**，将恶意映像加载到内存中。这个节区在内存中是完整的恶意 PE 映像。
 * 3. **Rollback（回滚）**：**回滚 TxF 事务**。磁盘上的文件恢复到原始合法状态，恶意代码在文件系统中**完全消失**，实现了“无文件”。
 * 4. **Animate（激活）**：利用之前创建的**内存节区**创建进程并启动执行。由于节区在回滚之前已经创建，它仍然引用着恶意映像的内存内容，不受事务回滚的影响。
 * 2026-09-13 改进：改用 WKD_PROCESS 权威副本（Core.ImagePath），删除
 * 打开进程 / SeLocateProcessImageName 冗余采集；原 PhpCheckFileTransacted
 * 文件级 TxF 检测内联。
--*/
{
    NTSTATUS status;
    PPH_DETECTOR_INTERNAL internal;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    PTXN_PARAMETER_BLOCK txnParams = NULL;

    if (Detector == NULL || WkdProcess == NULL || IsDoppelganging == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsDoppelganging = FALSE;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (!PhpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // 权威 WKD_PROCESS 副本（2026-09-13）：Core.ImagePath 为登记时权威映像路径。
    // 无映像路径——可能为已回滚的事务性（transacted）文件 → 直接判 Doppelganging。
    //
    if (WkdProcess->Core.ImagePath == NULL) {
        *IsDoppelganging = TRUE;
        status = STATUS_SUCCESS;
        goto Cleanup;
    }

    //
    // 文件级 TxF 检测（原 PhpCheckFileTransacted 内联，2026-09-13）：
    //   1) 打开失败（目标不存在）——已回滚的 TxF 事务文件，强烈指示；
    //   2) 文件存在但属于活动事务（IoGetTransactionParameterBlock）。
    //
    InitializeObjectAttributes(
        &objAttr,
        WkdProcess->Core.ImagePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    status = ZwOpenFile(
        &fileHandle,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status)) {
        if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_OBJECT_PATH_NOT_FOUND) {
            //
            // 文件不存在 — 可能是已回滚的 TxF 事务
            //
            *IsDoppelganging = TRUE;
            status = STATUS_SUCCESS;
        }
        goto Cleanup;
    }

    //
    // 获取 FILE_OBJECT，通过 IoGetTransactionParameterBlock 检查活动事务。
    //
    status = ObReferenceObjectByHandle(
        fileHandle,
        0,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&fileObject,
        NULL
    );

    if (NT_SUCCESS(status)) {
        txnParams = IoGetTransactionParameterBlock(fileObject);
        if (txnParams != NULL) {
            //
            // 文件属于某个活动事务 — 强烈的 Doppelganging 攻击指示
            //
            *IsDoppelganging = TRUE;
        }
        ObDereferenceObject(fileObject);
    }

    ZwClose(fileHandle);

    status = STATUS_SUCCESS;

Cleanup:
    PhpReleaseReference(internal);

    return status;
}

_Use_decl_annotations_
NTSTATUS
PhCheckForGhosting(
    _In_ PPH_DETECTOR Detector,
    _In_ PWKD_PROCESS WkdProcess,
    _Out_ PBOOLEAN IsGhosting
    )
/*++
 * 👻 Process Ghosting (进程幽灵)
 * 创建一个临时文件，写入恶意Payload，**将其标记为删除（delete-pending状态）**，
 * 然后关闭句柄——文件从磁盘消失，但内容仍被映射在内存节区中。之后从该内存节区创建进程并执行。
 * 2026-09-13 改进：改用 WKD_PROCESS 权威副本（Core.ImagePath），删除
 * 打开进程 / SeLocateProcessImageName 冗余采集；原 PhpCheckFileDeleted
 * 文件级检测内联。
--*/
{
    NTSTATUS status;
    PPH_DETECTOR_INTERNAL internal;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    FILE_STANDARD_INFORMATION fileInfo = { 0 };

    if (Detector == NULL || WkdProcess == NULL || IsGhosting == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsGhosting = FALSE;

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (!PhpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // 权威 WKD_PROCESS 副本（2026-09-13）：Core.ImagePath 为登记时权威映像路径。
    // 无映像路径——可能为已删除的文件 → 直接判 Ghosting。
    //
    if (WkdProcess->Core.ImagePath == NULL) {
        *IsGhosting = TRUE;
        status = STATUS_SUCCESS;
        goto Cleanup;
    }

    //
    // 文件级检测（原 PhpCheckFileDeleted 内联，2026-09-13）：
    //   1) 打开失败（不存在 / 删除待定）——文件已删除；
    //   2) 打开成功但 DeletePending（FileStandardInformation）。
    //
    InitializeObjectAttributes(
        &objAttr,
        WkdProcess->Core.ImagePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    status = ZwOpenFile(
        &fileHandle,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );

    if (!NT_SUCCESS(status)) {
        if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_OBJECT_PATH_NOT_FOUND ||
            status == STATUS_DELETE_PENDING) {
            //
            // 文件已确认被删除或处于删除待定状态。
            // 返回 STATUS_SUCCESS，调用方通过 NT_SUCCESS(status) && IsGhosting
            // 看到该检测结果——否则后备文件被完全删除时 Ghosting 无法被检测到。
            //
            *IsGhosting = TRUE;
            status = STATUS_SUCCESS;
        }
        goto Cleanup;
    }

    //
    // 检查删除是否处于待定状态
    //
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatus,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation
    );

    if (NT_SUCCESS(status)) {
        *IsGhosting = fileInfo.DeletePending;
    }

    ZwClose(fileHandle);

    status = STATUS_SUCCESS;

Cleanup:
    PhpReleaseReference(internal);

    return status;
}

// ============================================================================
// 回调机制
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PhRegisterCallback(
    _In_ PPH_DETECTOR Detector,
    _In_ PH_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PPH_DETECTOR_INTERNAL internal;
    ULONG i;
    NTSTATUS status = STATUS_QUOTA_EXCEEDED;

    if (Detector == NULL || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (!PhpIsReady(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&internal->CallbackLock);

    for (i = 0; i < PH_MAX_CALLBACKS; i++) {
        if (!internal->Callbacks[i].InUse) {
            internal->Callbacks[i].Callback = Callback;
            internal->Callbacks[i].Context = Context;
            internal->Callbacks[i].InUse = TRUE;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockExclusive(&internal->CallbackLock);
    KeLeaveCriticalRegion();

    return status;
}

_Use_decl_annotations_
VOID
PhUnregisterCallback(
    _In_ PPH_DETECTOR Detector,
    _In_ PH_DETECTION_CALLBACK Callback
    )
{
    PPH_DETECTOR_INTERNAL internal;
    ULONG i;

    if (Detector == NULL || Callback == NULL) {
        return;
    }

    internal = CONTAINING_RECORD(Detector, PH_DETECTOR_INTERNAL, Public);

    if (!PhpIsReady(internal)) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&internal->CallbackLock);

    for (i = 0; i < PH_MAX_CALLBACKS; i++) {
        if (internal->Callbacks[i].InUse &&
            internal->Callbacks[i].Callback == Callback) {
            internal->Callbacks[i].InUse = FALSE;
            internal->Callbacks[i].Callback = NULL;
            internal->Callbacks[i].Context = NULL;
            break;
        }
    }

    ExReleasePushLockExclusive(&internal->CallbackLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// 结果结构
// ============================================================================

_Use_decl_annotations_
VOID
PhFreeResult(
    _In_ PPH_ANALYSIS_RESULT Result
    )
{
    if (Result == NULL) {
        return;
    }

    //
    // 释放已分配的字符串（CoCopyUnicodeString 分配，CoFreeUnicodeStringSafe 释放）
    //
    CoFreeUnicodeStringSafe(Result->ClaimedImagePath);
    Result->ClaimedImagePath = NULL;
    CoFreeUnicodeStringSafe(Result->ActualImagePath);
    Result->ActualImagePath = NULL;
    CoFreeUnicodeStringSafe(Result->ProcessName);
    Result->ProcessName = NULL;
    CoFreeUnicodeStringSafe(Result->Section.BackingFileName);
    Result->Section.BackingFileName = NULL;

    //
    // 释放结果结构本身
    //
    ExFreePoolWithTag(Result, PH_POOL_TAG_RESULT);
}

// ============================================================================
// 统计信息
// ============================================================================

_Use_decl_annotations_
NTSTATUS
PhGetStatistics(
    _In_ PPH_DETECTOR Detector,
    _Out_ PPH_STATISTICS Stats
    )
{
    LARGE_INTEGER currentTime;

    if (Detector == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // L-3：统计信息的读取有意采用非原子方式（近似值）。
    // 写入使用 InterlockedIncrement64；普通读取可能看到
    // 略微过期的值，对诊断计数而言这是可接受的。
    //
    RtlZeroMemory(Stats, sizeof(PH_STATISTICS));

    Stats->ProcessesAnalyzed = Detector->Stats.ProcessesAnalyzed;
    Stats->HollowingDetected = Detector->Stats.HollowingDetected;
    Stats->DoppelgangingDetected = Detector->Stats.DoppelgangingDetected;
    Stats->GhostingDetected = Detector->Stats.GhostingDetected;

    //
    // 计算运行时长（uptime）
    //
    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Detector->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

// ============================================================================
// 私有辅助函数 - 分配
// ============================================================================

//
// C-4 修复：返回给调用方的结果始终使用池分配（绝不用后备链表 lookaside）。
// 这消除了 PhFreeResult（池释放）与 PhpFreeResultInternal
// （原先按条件使用 lookaside）之间的释放不匹配问题。
//
static PPH_ANALYSIS_RESULT
PhpAllocateResult(
    VOID
    )
{
    return (PPH_ANALYSIS_RESULT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(PH_ANALYSIS_RESULT),
        PH_POOL_TAG_RESULT
    );
}

static VOID
PhpFreeResultInternal(
    _In_ PPH_ANALYSIS_RESULT Result
    )
{
    //
    // 先释放字符串（CoCopyUnicodeString 分配，CoFreeUnicodeStringSafe 释放）
    //
    CoFreeUnicodeStringSafe(Result->ClaimedImagePath);
    Result->ClaimedImagePath = NULL;
    CoFreeUnicodeStringSafe(Result->ActualImagePath);
    Result->ActualImagePath = NULL;
    CoFreeUnicodeStringSafe(Result->ProcessName);
    Result->ProcessName = NULL;
    CoFreeUnicodeStringSafe(Result->Section.BackingFileName);
    Result->Section.BackingFileName = NULL;

    ExFreePoolWithTag(Result, PH_POOL_TAG_RESULT);
}

// ============================================================================
// 私有辅助函数 - 进程访问
// ============================================================================

static NTSTATUS
PhpOpenProcessForAnalysis(
    _In_ HANDLE ProcessId,
    _Out_ PHANDLE ProcessHandle,
    _Out_ PEPROCESS* Process
    )
{
    NTSTATUS status;

    *ProcessHandle = NULL;
    *Process = NULL;

    //
    // 获取进程对象
    //
    status = PsLookupProcessByProcessId(ProcessId, Process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // 打开进程句柄
    //
    status = ObOpenObjectByPointer(
        *Process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        ProcessHandle
    );

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(*Process);
        *Process = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// 私有辅助函数 - 映像分析
// ============================================================================

static NTSTATUS
PhpAnalyzeImageComparison(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_opt_ PWKD_PROCESS WkdProcess,
    _In_ PEPROCESS Process,
    _Inout_ PPH_ANALYSIS_RESULT Result
    )
{
    NTSTATUS status;
    PVOID imageBase = NULL;
    SIZE_T imageSize = 0;
    PWKD_MODULE_SECTION sections = NULL;
    ULONG sectionCount = 0;
    BOOLEAN match = FALSE;
    ULONG mismatchOffset = 0;
    PWKD_MODULE_INSTANCE instance = NULL;

    UNREFERENCED_PARAMETER(Detector);

    //
    // 主模块定位：经模块链查 MainModule==TRUE 实例（2026-09-13 取代
    // PhpGetProcessImageBase attach 探测）——
    //   - 命中：直接消费 WKD_MODULE_INSTANCE.ImageBase（实际映射基址）与
    //     WKD_MODULE.SizeOfImage（PE 头 SizeOfImage，L0 镜像回调采集），
    //     并取已解析节表（WKD_MODULE.Sections）供逐节比对——免 attach /
    //     免重复 PE 解析；
    //   - 未命中（无模块链 / 链外进程）：跳过映像比对（STATUS_NOT_FOUND，
    //     模块链是映像事实的唯一来源）。
    //
    if (WkdProcess != NULL && WkdProcess->ModuleContext != NULL) {
        //
        // 非锁版查询（2026-09-13 封装下沉）：PsGetMainModuleImageBase /
        // PsLookupModuleInstanceByImageBase 内部自持 ModuleContext 共享锁，
        // 此处不再手动持锁；imageBase 用函数级变量（锁内复制，值语义安全）
        //
        if (NT_SUCCESS(PsGetMainModuleImageBase(WkdProcess, &imageBase))) {
            instance = PsLookupModuleInstanceByImageBase(WkdProcess, imageBase);
        }
    }

    if (instance != NULL) {
        imageBase = instance->ImageBase;
        imageSize = instance->Module->SizeOfImage;
        sections = (PWKD_MODULE_SECTION)
            DaGetElement(&instance->Module->Sections, 0);
        sectionCount = (ULONG)min(instance->Module->Sections.Count,
                                  WKD_MT_PE_SECTION_MASK_BITS);
    } else {
        return STATUS_NOT_FOUND;
    }

    Result->ImageComparison.MemoryBase = imageBase;
    Result->ImageComparison.MemorySize = imageSize;

    //
    // 若已获取实际映像路径，则与文件比较
    //
    if (Result->ActualImagePath != NULL) {
        status = MiCompareMemoryWithFile(
            Process,
            imageBase,
            imageSize,
            sections,
            sectionCount,
            Detector->Public.Config.CompareWritableSections,
            Result->ActualImagePath,
            &match,
            &mismatchOffset,
            &Result->ImageComparison.ComparedSectionCount,
            &Result->ImageComparison.SkippedSectionCount,
            Result->ImageComparison.MemoryHash,
            Result->ImageComparison.FileHash
        );

        if (NT_SUCCESS(status)) {
            Result->ImageComparison.HashMatch = match;
            Result->ImageComparison.MismatchOffset = mismatchOffset;

            if (!match) {
                Result->Indicators |= PhIndicator_HashMismatch;
                Result->Indicators |= PhIndicator_SectionMismatch;
            }
        }
    } else {
        //
        // 没有可供比较的文件——可疑
        //
        Result->Indicators |= PhIndicator_NoPhysicalFile;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
PhpAnalyzeEntryPoint(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_opt_ PWKD_PROCESS WkdProcess,
    _In_ PEPROCESS Process,
    _Inout_ PPH_ANALYSIS_RESULT Result
    )
{
    PVOID imageBase = NULL;
    SIZE_T imageSize = 0;
    PWKD_MODULE_INSTANCE instance = NULL;

    UNREFERENCED_PARAMETER(Detector);
    UNREFERENCED_PARAMETER(Process);

    //
    // 主模块定位：经模块链查 MainModule==TRUE 实例（2026-09-13 取代
    // PhpGetProcessImageBase attach 探测路径）——
    //   - 命中：直接消费 L0 PeParser 已解析事实，免去重复的内存 PE 解析
    //     （原 attach 路径自读 PE 头/自解析为冗余实现）：
    //     Facts.AddressOfEntryPoint（EP RVA）/ Facts.EntryPointInCode
    //     （EP 落在可执行节）/ ImageBase（实际映射基址）/
    //     Module->SizeOfImage（PE 头 SizeOfImage）。
    //     运行期"EP 页当前仍可执行"页保护查询在此路径省略——EntryPointInCode
    //     为 PE 固有事实，映像比对（ImageComparison）已覆盖运行期篡改。
    //   - 未命中（无模块链 / 链外进程）：跳过入口点分析，返回
    //     STATUS_NOT_FOUND——PhValidateEntryPoint 对链外进程恒 Valid=FALSE。
    //
    if (WkdProcess != NULL && WkdProcess->ModuleContext != NULL) {
        //
        // 非锁版查询（2026-09-13 封装下沉）：PsGetMainModuleImageBase /
        // PsLookupModuleInstanceByImageBase 内部自持 ModuleContext 共享锁，
        // 此处不再手动持锁；imageBase 用函数级变量（锁内复制，值语义安全）
        //
        if (NT_SUCCESS(PsGetMainModuleImageBase(WkdProcess, &imageBase))) {
            instance = PsLookupModuleInstanceByImageBase(WkdProcess, imageBase);
        }
    }

    if (instance == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // 模块链路径（链上主模块）：消费 PeParser 已解析事实。
    //
    {
        ULONG entryRva = instance->Module->Facts.AddressOfEntryPoint;

        imageBase = instance->ImageBase;
        imageSize = instance->Module->SizeOfImage;

        Result->EntryPoint.DeclaredEntryPoint =
            (PVOID)((ULONG_PTR)imageBase + entryRva);
        Result->EntryPoint.ActualEntryPoint = Result->EntryPoint.DeclaredEntryPoint;

        //
        // 入口点在镜像边界内 && PE 解析时已确认落在可执行节。
        // （AddressOfEntryPoint 为 ULONG RVA 恒非负，无需负值/回绕防护；
        //   EP=0 即无入口，保持原行为）
        //
        Result->EntryPoint.EntryPointInImage =
            (entryRva < imageSize) &&
            ((ULONG_PTR)imageBase + entryRva >= (ULONG_PTR)imageBase);
        Result->EntryPoint.EntryPointExecutable =
            instance->Module->Facts.EntryPointInCode;

        if (entryRva == 0 || !Result->EntryPoint.EntryPointInImage ||
            !Result->EntryPoint.EntryPointExecutable) {
            Result->Indicators |= PhIndicator_EntryPointModified;
        }

        Result->EntryPoint.EntryPointValid =
            Result->EntryPoint.EntryPointInImage &&
            Result->EntryPoint.EntryPointExecutable;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
PhpAnalyzePEB(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_opt_ PWKD_PROCESS WkdProcess,
    _In_ PEPROCESS Process,
    _Inout_ PPH_ANALYSIS_RESULT Result
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PPEB pebAddress = NULL;
    PPEB peb = NULL;
    SIZE_T bytesRead = 0;
    UNICODE_STRING pebImagePath = { 0 };

    UNREFERENCED_PARAMETER(Detector);
    UNREFERENCED_PARAMETER(WkdProcess);

    //
    // 获取 PEB 地址：PsGetProcessPeb 直接取自 EPROCESS，
    // 免句柄 / 免 ZwQueryInformationProcess（2026-09-13 去句柄化）
    //
    pebAddress = PsGetProcessPeb(Process);
    if (pebAddress == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // PPEB 类型化（2026-09-13）：PsGetProcessPeb 返回 PPEB，直接以指针
    // 类型承接；读取目标为临时池内存（避免 PEB 大结构栈上拷贝），
    // 读取完成后统一在 Cleanup 释放。
    // 跨进程读取经 Memory\MemoryIntegrity（MiReadProcessMemory）封装，无需 attach。
    //
    peb = (PPEB)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(PEB),
        PH_POOL_TAG_BUFFER
    );
    if (peb == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = MiReadProcessMemory(
        Process,
        pebAddress,
        peb,
        sizeof(PEB),
        &bytesRead
    );

    if (!NT_SUCCESS(status) || bytesRead < sizeof(PEB)) {
        goto Cleanup;
    }

    //
    // 从 PEB 获取映像路径并与实际路径比较
    //
    //
    // H-6 修复：验证 peb->ProcessParameters 是否为用户态地址。
    // 恶意进程可能将其指向内核空间。
    //
    if (peb->ProcessParameters != NULL && ShadowStrikeIsUserAddress(peb->ProcessParameters)) {
        RTL_USER_PROCESS_PARAMETERS params = { 0 };

        status = MiReadProcessMemory(
            Process,
            peb->ProcessParameters,
            &params,
            sizeof(RTL_USER_PROCESS_PARAMETERS),
            &bytesRead
        );

        if (NT_SUCCESS(status) && bytesRead >= sizeof(RTL_USER_PROCESS_PARAMETERS)) {
            //
            // 从进程内存读取映像路径名
            // H-6 修复：同时验证 params.ImagePathName.Buffer 是否为用户态地址
            //
            if (params.ImagePathName.Length > 0 &&
                params.ImagePathName.Length < MAX_PATH * sizeof(WCHAR) &&
                params.ImagePathName.Buffer != NULL &&
                ShadowStrikeIsUserAddress(params.ImagePathName.Buffer)) {

                pebImagePath.Length = params.ImagePathName.Length;
                pebImagePath.MaximumLength = params.ImagePathName.Length + sizeof(WCHAR);
                pebImagePath.Buffer = (PWCH)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED,
                    pebImagePath.MaximumLength,
                    PH_POOL_TAG_BUFFER
                );

                if (pebImagePath.Buffer != NULL) {
                    status = MiReadProcessMemory(
                        Process,
                        params.ImagePathName.Buffer,
                        pebImagePath.Buffer,
                        pebImagePath.Length,
                        &bytesRead
                    );

                    if (NT_SUCCESS(status) && bytesRead == pebImagePath.Length) {
                        pebImagePath.Buffer[pebImagePath.Length / sizeof(WCHAR)] = L'\0';

                        //
                        // 复制到结果
                        //
                        CoCopyUnicodeString(&Result->ClaimedImagePath, &pebImagePath);

                        //
                        // 与实际路径比较
                        //
                        if (Result->ActualImagePath != NULL) {
                            if (!RtlEqualUnicodeString(&pebImagePath, Result->ActualImagePath, TRUE)) {
                                Result->Indicators |= PhIndicator_ImagePathMismatch;
                                Result->PEB.PebModified = TRUE;
                            }
                        }
                    }

                    ExFreePoolWithTag(pebImagePath.Buffer, PH_POOL_TAG_BUFFER);
                }
            }
        }
    }

    //
    // 检查映像基址是否匹配
    //
    if (Result->ImageComparison.MemoryBase != NULL) {
        if (peb->ImageBaseAddress != Result->ImageComparison.MemoryBase) {
            Result->Indicators |= PhIndicator_ModifiedPEB;
            Result->PEB.ImageBaseModified = TRUE;
        }
    }

    status = STATUS_SUCCESS;

Cleanup:
    if (peb != NULL) {
        ExFreePoolWithTag(peb, PH_POOL_TAG_BUFFER);
    }

    return status;
}

static NTSTATUS
PhpAnalyzeSectionBacking(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_opt_ PWKD_PROCESS WkdProcess,
    _In_ PEPROCESS Process,
    _Inout_ PPH_ANALYSIS_RESULT Result
    )
{
    UNREFERENCED_PARAMETER(Detector);
    UNREFERENCED_PARAMETER(WkdProcess);
    UNREFERENCED_PARAMETER(Process);

    if (Result->ActualImagePath == NULL) {
        Result->Section.HasBackingFile = FALSE;
        Result->Indicators |= PhIndicator_NoPhysicalFile;
        return STATUS_NOT_FOUND;
    }

    Result->Section.HasBackingFile = TRUE;
    CoCopyUnicodeString(&Result->Section.BackingFileName, Result->ActualImagePath);

    //
    // TxF / DeletePending 文件级检测已于 2026-09-13 内联至
    // PhCheckForDoppelganging / PhCheckForGhosting（专项检测 API）——
    // 阶段分析不再重复执行；Section.FileIsTransacted / FileIsDeleted
    // 保持默认 FALSE（无繁琐阶段的字段填充）。
    //
    return STATUS_SUCCESS;
}

// ============================================================================
// 私有辅助函数 - 评分
// ============================================================================

static VOID
PhpCalculateScores(
    _Inout_ PPH_ANALYSIS_RESULT Result
    )
{
    ULONG confidence = 0;
    ULONG severity = PH_SEVERITY_BASE;
    PH_INDICATORS indicators = Result->Indicators;

    //
    // 根据指示标志（Indicators）计算置信度评分
    //
    if (indicators & PhIndicator_ImagePathMismatch) {
        confidence += PH_SCORE_IMAGE_MISMATCH;
        severity += PH_SEVERITY_HIGH_INDICATOR;
    }

    if (indicators & PhIndicator_SectionMismatch) {
        confidence += PH_SCORE_SECTION_MISMATCH;
        severity += PH_SEVERITY_HIGH_INDICATOR;
    }

    if (indicators & PhIndicator_EntryPointModified) {
        confidence += PH_SCORE_ENTRY_MODIFIED;
        severity += PH_SEVERITY_CRITICAL_INDICATOR;
    }

    if (indicators & PhIndicator_HeaderModified) {
        confidence += PH_SCORE_HEADER_MODIFIED;
        severity += PH_SEVERITY_HIGH_INDICATOR;
    }

    if (indicators & PhIndicator_UnmappedMainModule) {
        confidence += PH_SCORE_UNMAPPED_MODULE;
        severity += PH_SEVERITY_CRITICAL_INDICATOR;
    }

    if (indicators & PhIndicator_TransactedFile) {
        confidence += PH_SCORE_TRANSACTED;
        severity += PH_SEVERITY_CRITICAL_INDICATOR;
    }

    if (indicators & PhIndicator_DeletedFile) {
        confidence += PH_SCORE_DELETED_FILE;
        severity += PH_SEVERITY_CRITICAL_INDICATOR;
    }

    if (indicators & PhIndicator_SuspiciousThread) {
        confidence += PH_SCORE_SUSPENDED_THREAD;
        severity += PH_SEVERITY_MEDIUM_INDICATOR;
    }

    if (indicators & PhIndicator_ModifiedPEB) {
        confidence += PH_SCORE_PEB_MODIFIED;
        severity += PH_SEVERITY_HIGH_INDICATOR;
    }

    if (indicators & PhIndicator_NoPhysicalFile) {
        confidence += PH_SCORE_NO_PHYSICAL_FILE;
        severity += PH_SEVERITY_CRITICAL_INDICATOR;
    }

    if (indicators & PhIndicator_HashMismatch) {
        confidence += PH_SCORE_HASH_MISMATCH;
        severity += PH_SEVERITY_CRITICAL_INDICATOR;
    }

    if (indicators & PhIndicator_TimestampAnomaly) {
        confidence += PH_SCORE_TIMESTAMP_ANOMALY;
        severity += PH_SEVERITY_MEDIUM_INDICATOR;
    }

    //
    // 将分数上限设为 100
    //
    Result->ConfidenceScore = min(confidence, 100);
    Result->SeverityScore = min(severity, 100);
}

static PH_HOLLOWING_TYPE
PhpDetermineHollowingType(
    _In_ PPH_ANALYSIS_RESULT Result
    )
{
    PH_INDICATORS indicators = Result->Indicators;

    //
    // 根据指示标志组合检查特定的进程镂空类型。
    // 顺序很重要：先判断最具针对性的类型，再落入更宽泛的启发式规则。
    //

    //
    // 进程 Doppelganging：事务文件 + 节不匹配。
    // 基于 TxF 的攻击通过事务性文件创建节，
    // 然后回滚事务，在磁盘上不留任何痕迹。
    //
    if ((indicators & PhIndicator_TransactedFile) ||
        ((indicators & PhIndicator_NoPhysicalFile) &&
         (indicators & PhIndicator_SectionMismatch))) {
        return PhHollowing_Doppelganging;
    }

    //
    // 进程 Ghosting：后备文件已删除。
    // 攻击者在创建节之前标记删除文件，
    // 使进程运行时没有磁盘映像。
    //
    if (indicators & PhIndicator_DeletedFile) {
        return PhHollowing_Ghosting;
    }

    //
    // 进程 Herpaderping：节创建之后文件被修改。
    // 哈希不匹配，但文件仍然存在且未处于事务中。
    // 磁盘文件在 NtCreateSection 之后、杀毒软件（AV）来得及
    // 扫描原始内容之前被覆盖。
    //
    if ((indicators & PhIndicator_HashMismatch) &&
        !(indicators & PhIndicator_TransactedFile) &&
        !(indicators & PhIndicator_DeletedFile) &&
        Result->Section.HasBackingFile) {
        return PhHollowing_Herpaderping;
    }

    //
    // 进程覆写（RunPE）：头部 + 节不匹配，但
    // 入口点仍然有效（指向被覆写的代码）。
    // 攻击者解除原始映像的映射，并在同一基址上
    // 映射带有有效入口点的新映像。
    //
    if ((indicators & PhIndicator_HeaderModified) &&
        (indicators & PhIndicator_SectionMismatch) &&
        !(indicators & PhIndicator_EntryPointModified)) {
        return PhHollowing_Overwriting;
    }

    //
    // 经典进程镂空：入口点被修改，节不匹配。
    // 原始代码节被替换为恶意代码，
    // 入口点被重定向到载荷（payload）。
    //
    if ((indicators & PhIndicator_EntryPointModified) &&
        (indicators & PhIndicator_SectionMismatch)) {
        return PhHollowing_Classic;
    }

    //
    // 经典进程镂空变体：仅入口点被修改。
    // 某些镂空实现只修改入口点，
    // 而不完全替换代码节（部分镂空）。
    //
    if ((indicators & PhIndicator_EntryPointModified) &&
        (indicators & PhIndicator_HashMismatch)) {
        return PhHollowing_Classic;
    }

    //
    // 模块践踏（Module Stomping）：映像路径不匹配并伴随 PEB 修改。
    // 攻击者加载合法 DLL，随后在修复 PEB 的同时
    // 用恶意代码覆写其代码节。
    //
    if ((indicators & PhIndicator_ImagePathMismatch) &&
        (indicators & PhIndicator_ModifiedPEB)) {
        return PhHollowing_ModuleStomping;
    }

    /*（幻影 DLL 镂空分支已于 2026-09-13 删除：原判定依赖
     * PhIndicator_HiddenMemory（私有 VAD 枚举派生），内存区域枚举
     * 统一迁移至 Memory\MemoryRegion 侧后指示位不再产生，
     * Phantom 类型不再被命中，保留枚举值供公共 API 兼容）*/

    //
    // 若存在强指示标志，则归为通用型进程镂空
    //
    if (Result->ConfidenceScore >= 50) {
        if (indicators & (PhIndicator_SectionMismatch | PhIndicator_EntryPointModified |
                          PhIndicator_HeaderModified | PhIndicator_UnmappedMainModule)) {
            return PhHollowing_Classic;
        }
    }

    return PhHollowing_None;
}

// ============================================================================
// 私有辅助函数 - 回调
// ============================================================================

static VOID
PhpInvokeCallbacks(
    _In_ PPH_DETECTOR_INTERNAL Detector,
    _In_ PPH_ANALYSIS_RESULT Result
    )
{
    ULONG i;
    ULONG count = 0;

    //
    // H-4 修复：在持锁状态下复制回调，然后在锁外调用。
    // 这防止了回调内调用 PhUnregisterCallback 时发生死锁
    // （该函数会对同一推锁（push lock）获取独占锁）。
    //
    struct {
        PH_DETECTION_CALLBACK Callback;
        PVOID Context;
    } snapshot[PH_MAX_CALLBACKS];

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->CallbackLock);

    for (i = 0; i < PH_MAX_CALLBACKS; i++) {
        if (Detector->Callbacks[i].InUse && Detector->Callbacks[i].Callback != NULL) {
            snapshot[count].Callback = Detector->Callbacks[i].Callback;
            snapshot[count].Context = Detector->Callbacks[i].Context;
            count++;
        }
    }

    ExReleasePushLockShared(&Detector->CallbackLock);
    KeLeaveCriticalRegion();

    //
    // 在锁外调用 — 避免死锁
    //
    for (i = 0; i < count; i++) {
        snapshot[i].Callback(Result, snapshot[i].Context);
    }
}

// ============================================================================
// 私有辅助函数 - 引用计数
// ============================================================================

//
// H-1 修复：PhpAcquireReference 返回 BOOLEAN。先递增计数，
// 再检查状态是否为 READY。若不是，则递减并发出事件信号。
// 这消除了状态检查与递增之间的 TOCTOU（检查使用间竞争）问题。
//
static BOOLEAN
PhpAcquireReference(
    _In_ PPH_DETECTOR_INTERNAL Detector
    )
{
    InterlockedIncrement(&Detector->ActiveOperations);

    if (ReadAcquire(&Detector->State) == PH_STATE_READY) {
        return TRUE;
    }

    //
    // 未就绪（正在关闭或尚未初始化）— 回滚
    //
    if (InterlockedDecrement(&Detector->ActiveOperations) == 0) {
        KeSetEvent(&Detector->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
    return FALSE;
}

static VOID
PhpReleaseReference(
    _In_ PPH_DETECTOR_INTERNAL Detector
    )
{
    if (InterlockedDecrement(&Detector->ActiveOperations) == 0) {
        //
        // 仅在关闭过程中发出信号 — 避免虚假唤醒
        //
        if (ReadAcquire(&Detector->State) == PH_STATE_SHUTTING_DOWN) {
            KeSetEvent(&Detector->ShutdownEvent, IO_NO_INCREMENT, FALSE);
        }
    }
}

// ============================================================================
// 私有辅助函数 - 字符串工具
// ============================================================================
// 2026-09-13：PhpCopyUnicodeString / PhpFreeUnicodeString 已移除，
// 统一改用 Common\Utils 的 CoCopyUnicodeString / CoFreeUnicodeStringSafe
//（后者整体分配/释放 UNICODE_STRING 结构，所有权模型见 PH_ANALYSIS_RESULT
//  的 PUNICODE_STRING 字段注释）。
//
