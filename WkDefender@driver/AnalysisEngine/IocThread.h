#pragma once

#include <ntifs.h>
#include "../Callbacks/ThreadNotify.h"
#include "../Process/ProcessPairContext.h"     /* PAE_PROCESS_PAIR */

//
// IocDetectThread — 线程创建 IOC 检测流水线
//
// 检测范围：
//   1. 远程线程创建（TsIndicator_Injection_RemoteThread）
//   2. 跨会话线程注入（TsIndicator_Injection_CrossProcessThread）
//   3. 系统目标远程线程（Severity 3）
//   4. 入口点 shellcode 特征
//   5. 入口点 RWX 内存属性（新增）
//   6. 挂起创建线程（新增）
//   7. 受保护进程目标（新增）
//   8. 创建者提权源（新增）
//   9. 远程线程快速创建（新增, 死代码填充）
//   10. 孤儿注入器 — 源进程父已退出（新增, 对齐 SS PR_SCORE_ORPHANED_INJECTOR）
//
// TargetProcess: 线程所属进程（远程线程时为目标进程）
// Entry: 线程信息条目
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocDetectThread(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ PWKD_THREAD Entry
    );
