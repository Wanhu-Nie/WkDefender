#pragma once

#include "IocEngine.h"
#include "IoaEngine.h"
#include "../Notification/NotificationManager.h"

//
// Forward declaration for undocumented but supported API (Win8.1+)
// PsGetProcessSignatureLevel returns VOID and populates output params
//
#if (NTDDI_VERSION >= NTDDI_WINBLUE)
typedef
NTKERNELAPI
UCHAR
(*PFN_PsGetProcessSignatureLevel)(
    _In_ PEPROCESS Process,
    _Out_ PUCHAR SectionSignatureLevel
    );
PFN_PsGetProcessSignatureLevel pfnPsGetProcessSignatureLevel;
#endif

//
// AnalysisEngine — IOC/IOA 统一容器
//
// 职责: 协调子引擎的初始化/清理, 不包含检测逻辑
//

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AeInitialize(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
AeCleanup(
    VOID
    );

//
// AeReportIndicator — 指示记录统一提交入口（进程对维度）
// 所有来源（IOC/IOA）均通过本系列提交，只插入记录、零计算；
// 得分由 AeOrchestratorDispatch 尾部 Phase 3 统一结算。
// 调用方须持有 pair pin（pin 契约）。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AeReportIndicator(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ TS_SOURCE Source,
    _In_ TS_INDICATOR_TYPE Indicator
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AeReportIndicatorEx(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ TS_SOURCE Source,
    _In_ TS_INDICATOR_TYPE Indicator,
    _In_ AE_THREAT_SEVERITY Severity
    );

//
// AeReportIndicatorPair — PID 对便捷入口（流水线外调用点用，如 SyscallHijack）。
// 内部 AeFindOrCreateProcessPair → AeReportIndicatorEx → PsDereferenceWkdProcessPair。
// Severity = 0 时查分析引擎默认威胁程度表。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AeReportIndicatorPair(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ TS_SOURCE Source,
    _In_ TS_INDICATOR_TYPE Indicator,
    _In_ UCHAR Severity
    );

//
// AeOrchestratorDispatch — 分析引擎统一编排入口
//
// 回调通过此入口进入分析引擎，不直接调用 IOA/IOC。
// Source 标识事件来源类型（WkdMessage_SourceSyscall / _ProcessCallback / 等），
// Data 指针根据 Source 转型：
//   WkdMessage_SourceSyscall       → PWKD_SYSCALL_CONTEXT
//   WkdMessage_SourceProcessCallback → PPS_CREATE_NOTIFY_INFO（NULL 表示进程退出）
//   WkdMessage_SourceThreadCallback  → PWKD_THREAD
//   WkdMessage_SourceObjectCallback  → POB_PRE_OPERATION_INFORMATION
//   WkdMessage_SourceImageCallback   → PIMAGE_INFO（L1 IocImage 从源进程
//     ModuleContext 读 L0 采集的 PE 事实；WKD_IMG_EVENT_DATA 已删除，
//     2026-08-08 L0/L1 边界重构）
//

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AeOrchestratorDispatch(
    _In_ PWKD_PROCESS SourceProcess,
    _In_ PWKD_PROCESS TargetProcess,
    _In_ WKD_ASSEMBLY_SOURCE Source,
    _In_ WKD_ASSEMBLY_TYPE Type,
    _In_opt_ PVOID Context
    );

//
// AepIsCriticalProcess — 阻断豁免判定（迁移自 SS BepIsCriticalProcess）
// PID 0/4 直接豁免；ImagePath 为空时经 SeLocateProcessImageName 解析；
// 名单对齐 SS 14 项 + wkd CbpIsCriticalBootProcess 既有项，尾部匹配。
// 与 Exempts（跳过评分语义）独立：本函数是"阻断豁免"（不允许终止）。
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
AepIsCriticalProcess(
    _In_ HANDLE ProcessId,
    _In_opt_ PCUNICODE_STRING ImagePath
    );

//
// AeEvaluateVerdict — 评分裁决消费（迁移自 SS BepDetermineResponse）
// 在评分结算（AeOrchestratorDispatch Phase 4）后调用：
//   TsVerdict_Blocked  → 经 AepIsCriticalProcess 豁免校验后终止源进程 + ALPC 上报
//   TsVerdict_Malicious → ALPC 上报 ThreatLevelChanged
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
AeEvaluateVerdict(
    _In_ PAE_PROCESS_PAIR Pair
    );