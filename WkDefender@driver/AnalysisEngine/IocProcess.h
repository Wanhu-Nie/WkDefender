#pragma once

#include "../Process/ProcessMonitor.h"
#include "../Process/ProcessPairContext.h"     /* PAE_PROCESS_PAIR */

//
// IocAnalysisProcess — 进程创建 IOC 检测流水线
//
// 全面采集进程安全上下文 + 静态特征 IOC 检测。
// 涵盖特权/PPID 欺骗/命令行/Ghosting/签名/谱系/脚本宿主。
//
// 由 AeOrchestratorDispatch 在 WkdMessage_SourceProcessCallback
// 中调用（Data != NULL 时）。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocAnalysisProcess(
    _Inout_ PAE_PROCESS_PAIR Pair,
    _In_ const PPS_CREATE_NOTIFY_INFO CreateInfo
    );

//
// 父进程校验规则初始化（WkdEntry 初始化时调用）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IocInitializeParentChildRules(
    VOID
    );

//
// 系统进程判定（内部+外部共用）
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdIsSystemProcess(
    _In_ HANDLE Pid
    );

//
// 剪贴板追踪表（T1115，IocProcess.c §8；2026-10 激活接线）
// 生命周期：IocInitializeParentChildRules 内 IocpClipboardInitialize 初始化；
// §3.2 IocpDetectClipboardAbuse 命中后 IocpClipboardTrackProcess 入表；
// 进程终止回调 IocpClipboardRemoveProcess 清理；minifilter IRP_MJ_WRITE
// 前置回调（FsPreWriteNotifyCallback）经 IocpClipboardCheckFileWrite 查询
// temp 快速写入模式。前向声明（定义在调用点之后，防 C4013）。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocpClipboardTrackProcess(
    _In_ HANDLE ProcessId,
    _In_ ULONG Indicators
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
IocpClipboardCheckFileWrite(
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING FileName
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IocpClipboardRemoveProcess(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocpClipboardInitialize(
    VOID
    );
