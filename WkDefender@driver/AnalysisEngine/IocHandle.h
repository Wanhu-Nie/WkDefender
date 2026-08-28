#pragma once

#include <ntifs.h>
#include "../Process/ProcessMonitor.h"
#include "../Process/ProcessPairContext.h"     /* PAE_PROCESS_PAIR */

//
// IocDetectHandle — 句柄访问 IOC 检测流水线
//
// 检测范围：
//   1. LSASS 敏感访问（VM_READ/VM_WRITE/VM_OPERATION）
//   2. 进程终止请求（PROCESS_TERMINATE）
//   3. 线程劫持（SET_CONTEXT/SUSPEND_RESUME/SET_THREAD_TOKEN）
//   4. 远程线程创建的句柄前兆 — PROCESS_CREATE_THREAD（新增）
//   5. VirtualProtectEx 前兆 — VM_OPERATION（新增）
//   6. 独立 SET_CONTEXT 判定（新增）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocDetectHandle(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ POB_PRE_OPERATION_INFORMATION OpInfo
    );
