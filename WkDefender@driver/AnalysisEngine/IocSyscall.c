/**************************************************/
/*  WkDefender — Syscall IOC 检测流水线             */
/*                                                   */
/*  检测: 进程空洞跨进程 syscall + 保护进程访问       */
/**************************************************/

#include "IocSyscall.h"
#include "AnalysisEngine.h"
#include "../Process/ProcessMonitor.h"

//
// 未文档化 API 声明 — PsGetProcessImageFileName
// 返回 EPROCESS 内部 15 字节 ANSI 缓冲区
//
NTKERNELAPI PUCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

//
// 保护进程 PID 列表（常见系统保护进程）
//
//
// 受保护进程判定（提升为导出，供 ThreadNotify 复用，对齐 PS TnpIsProtectedProcess）
//
// 双重判定：
//   1. 硬编码已知系统保护进程 PID（lsass 等常驻 PID）
//   2. PPL 签名级别（PsGetProcessProtection，Win8.1+ 导出）——覆盖 Win11
//      上受保护进程（含 PPL 保护的 lsass/wininit 等，PID 随启动变化）
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocspIsProtectedProcess(
    _In_ HANDLE ProcessId
    )
{
    ULONG pid = HandleToULong(ProcessId);

    switch (pid) {
    case 0x4:   /* System (Idle → System 转换后可能) */
    case 0x2E0: /* LSASS 常见 PID */
    case 0x3E0:
    case 0x4E0:
        return TRUE;
    default:
        break;
    }

    /* PPL 签名级别判定（对齐 PS TnpIsProtectedProcess 遍历 ProtectedProcessList 的语义替代） */
    {
        PEPROCESS process = NULL;
        PS_PROTECTED_TYPE protection = PsProtectedTypeNone;

        if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
            protection = PsGetProcessProtection(process);
            ObDereferenceObject(process);
        }

        return (protection != PsProtectedTypeNone);
    }

    return FALSE;
}

static
BOOLEAN
IocspIsLsass(
    _In_ HANDLE ProcessId
    )
{
    PEPROCESS targetProcess = NULL;
    PCHAR imageName;
    BOOLEAN isLsass = FALSE;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &targetProcess))) {
        return FALSE;
    }

    imageName = PsGetProcessImageFileName(targetProcess);
    if (imageName != NULL) {
        ANSI_STRING imgA, lsassA;
        RtlInitAnsiString(&lsassA, "lsass.exe");
        RtlInitAnsiString(&imgA, imageName);
        isLsass = (RtlCompareString(&imgA, &lsassA, TRUE) == 0);
    }

    ObDereferenceObject(targetProcess);
    return isLsass;
}

_Use_decl_annotations_
NTSTATUS
IocDetectSyscall(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ PWKD_SYSCALL_CONTEXT Ctx
    )
{
    if (!Pair || !Ctx) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 仅关注跨进程操作（self-pair 无跨进程语义） */
    if (Pair->SourceProcessId == Ctx->TargetProcessId) {
        return STATUS_SUCCESS;
    }

    switch (Ctx->SyscallNumber) {

    /*
     * === 进程空洞 / 内存篡改（写/保护/读跨进程内存） ===
     * 来源: AeOrchestratorDispatch 内联（原 SyscallHijack）
     */
    case WkdSyscall_NtWriteVirtualMemory:
    case WkdSyscall_NtProtectVirtualMemory:
    case WkdSyscall_NtReadVirtualMemory:
        AeReportIndicator(Pair, TsSourceBehavioral,
            TsIndicator_Injection_ProcessHollowing);

        /* 若目标为保护进程则升级严重程度 */
        if (IocspIsProtectedProcess(Ctx->TargetProcessId)) {
            AeReportIndicatorEx(Pair, TsSourceBehavioral,
                TsIndicator_Injection_ProcessHollowing, 3);
        }
        break;

    /*
     * === 跨进程内存分配（注入前兆） ===
     * 新增检测（原缺失）
     */
    case WkdSyscall_NtAllocateVirtualMemory:
        AeReportIndicator(Pair, TsSourceBehavioral,
            TsIndicator_Injection_ProcessHollowing);
        break;

    /*
     * === 打开 LSASS 进程（凭据窃取前兆） ===
     * 新增检测（原缺失）
     */
    case WkdSyscall_NtOpenProcess:
        if (IocspIsLsass(Ctx->TargetProcessId)) {
            AeReportIndicator(Pair, TsSourceBehavioral,
                TsIndicator_Handle_LsassAccess);
        }
        break;

    /*
     * === 线程操作 syscall（远程线程/APC/上下文/挂起恢复） ===
     * [死代码] 对齐 PS ThreadNotify 远程线程注入检测信号（T1055.001/.004/.003）。
     * 不接入原因：当前 syscall IOC 管线未接入驱动评分（SyscallHijack dispatch
     *   注释态，IocDetectSyscall 无调用者）；线程事件已由 Callbacks/ThreadNotify.c
     *   采集（WKD_THREAD.InjectIndicators）+ agent IoaInjectionClassifier
     *   深度分类覆盖。此分支为功能面保留，待 syscall IOC 管线恢复后接入。
     */
    case WkdSyscall_NtCreateThreadEx:
        AeReportIndicator(Pair, TsSourceBehavioral,
            TsIndicator_Injection_RemoteThread);
        break;

    case WkdSyscall_NtQueueApcThread:
        AeReportIndicator(Pair, TsSourceBehavioral,
            TsIndicator_Injection_RemoteThread);
        break;

    case WkdSyscall_NtSetContextThread:
    case WkdSyscall_NtSuspendThread:
    case WkdSyscall_NtResumeThread:
        AeReportIndicator(Pair, TsSourceBehavioral,
            TsIndicator_Injection_RemoteThread);
        break;

    default:
        break;
    }

    return STATUS_SUCCESS;
}
