#pragma once

#include <ntifs.h>
#include "../Syscall/SyscallMonitor.h"
#include "../Process/ProcessPairContext.h"     /* PAE_PROCESS_PAIR */

/* ============================================================================
 * 未文档化 API：进程保护级别。
 *   Windows 8.1+ 的 PsGetProcessProtection 为未文档化导出，WinSDK 无声明。
 *   PS_PROTECTED_TYPE / PS_PROTECTED_SIGNER / PS_PROTECTION 类型定义统一
 *   在 Process/ProcessMonitor.h（经 ProcessPairContext.h 间接引入），
 *   本头不再自声明，避免 C2011 枚举/结构重定义。
 * ========================================================================== */

NTKERNELAPI
PS_PROTECTED_TYPE
NTAPI
PsGetProcessProtection(
    _In_ PEPROCESS Process
    );

//
// IocDetectSyscall — Syscall IOC 检测流水线
//
// 检测范围：
//   1. 跨进程空洞相关 syscall（WriteVM/ProtectVM/ReadVM）
//   2. 跨进程 OpenProcess 目标为保护进程
//   3. 跨进程 AllocateVirtualMemory
//   4. 线程操作 syscall（CreateRemoteThread/QueueApc/SetContext/Suspend/Resume）——死代码标注见 IocSyscall.c
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocDetectSyscall(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ PWKD_SYSCALL_CONTEXT Ctx
    );

//
// IocspIsProtectedProcess — 受保护进程判定（提升为导出，供 ThreadNotify 复用，
// 对齐 PS TnpIsProtectedProcess）。硬编码 PID + PPL 签名级别双重判定。
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocspIsProtectedProcess(
    _In_ HANDLE ProcessId
    );
