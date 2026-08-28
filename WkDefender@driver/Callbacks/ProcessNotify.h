#pragma once
#include "../Common/Constants.h"

//
// 关键启动进程检测（被 ProcessMonitor.c 的 PPID 检测调用）
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
CbpIsCriticalBootProcess(
    _In_opt_ PCUNICODE_STRING ImageFileName
    );

//
// 初始化与清理函数
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CbProcessNotifyInitialize(
    VOID
);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
CbProcessNotifyCleanup(
    VOID
);

//
// ETW 事件发射函数（DbgPrintEx 回退阶段）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
CbEtwEmitProcessCreate(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _In_opt_ PUNICODE_STRING ImagePath
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
CbEtwEmitProcessExit(
    _In_ HANDLE ProcessId,
    _In_ NTSTATUS ExitStatus
    );

//
// 线程 ETW 事件发射（死代码——高频线程事件需 EtwWrite + 远程线程门控，见 ProcessNotify.c 标注）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
CbEtwEmitThreadCreate(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ HANDLE CreatorProcessId,
    _In_ BOOLEAN IsRemote,
    _In_opt_ PVOID StartAddress,
    _In_ ULONG InjectionScore
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
CbEtwEmitThreadExit(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId
    );