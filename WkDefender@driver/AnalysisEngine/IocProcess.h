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
