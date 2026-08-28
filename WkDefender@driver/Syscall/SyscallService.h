#pragma once

#include "../Common/Constants.h"
//
// 函数声明
//

//
// 判断内核栈是否扩展
// 某些系统调用会导致内核栈扩展，需要额外的空间计算
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
SsIsKernelStackExpanded(
    _In_ ULONG SyscallNumber
    );


_IRQL_requires_(PASSIVE_LEVEL)
PVOID SsGetSsdtBase(
    VOID
    );


/**************************************************/
/*                   系统服务号映射                */
/**************************************************/
typedef enum _WKD_SYSCALL_TYPE {
    // 进程相关
    WkdSyscall_NtOpenProcess          = 0x26,   // Windows 10 2004+
    WkdSyscall_NtCreateProcess        = 0xba,
    WkdSyscall_NtCreateProcessEx      = 0x4b,
    
    // 内存操作相关
    WkdSyscall_NtAllocateVirtualMemory = 0x18,
    WkdSyscall_NtReadVirtualMemory    = 0x3f,
    WkdSyscall_NtWriteVirtualMemory   = 0x3a,
    WkdSyscall_NtProtectVirtualMemory = 0x50,
    WkdSyscall_NtMapViewOfSection     = 0x28,
    WkdSyscall_NtUnmapViewOfSection   = 0x29,   /* 进程镂空 T1055.012（PreAcquireSection 迁移 2026-08，对齐 Win10 2004+） */
    WkdSyscall_NtCreateSection        = 0x2e,   /* SectionTracker 迁移 2026-08：匿名可执行/大匿名/无背衬/TxF 检测捕获点（Win10 全系稳定） */
    
    // 线程相关
    WkdSyscall_NtCreateThread         = 0xb9,
    WkdSyscall_NtCreateThreadEx       = 0xc2,
    WkdSyscall_NtQueueApcThread       = 0x45,
    WkdSyscall_NtSetContextThread     = 0x16e,
    WkdSyscall_NtGetContextThread     = 0x16d,
    
    // 其他
    WkdSyscall_NtResumeThread         = 0x52,
    WkdSyscall_NtSuspendThread        = 0x17a,

    // Token 操作（PrivilegeMonitor 迁移 2026-08-06，驱动事件源→agent WpaCheckForEscalation）
    WkdSyscall_NtAdjustPrivilegesToken = 0x1a,   // 运行时启用/禁用令牌特权（唯一运行时提权途径，T1134）
    WkdSyscall_NtImpersonateThread     = 0x1b,   // 线程模拟令牌（T1134.003）
    WkdSyscall_NtDuplicateToken        = 0x1c,   // 复制令牌句柄（T1134.001）
    WkdSyscall_NtSetInformationToken   = 0x22,   // 修改令牌属性（T1134）
} WKD_SYSCALL_TYPE;
