/**************************************************/
/*  WkDefender IOC — YARA 扫描器 (机制 A 封装)       */
/**************************************************/

/*
 * 职责：
 *   封装 libyara（用户态机制 A），仅负责扫描。
 *   规则管理（导入/编译/热重载）由 Storage/YaraRule.h 提供。
 *   规则通过 YaraRule_GetRules() / YaraRule_GetLock() 获取。
 *
 * 锁层次（与 YaraRule.h 一致）：
 *   Level 1: g_YaraLock     — 保护 rules 指针（扫描持 Shared）
 *   Level 2: g_YaraScanLock — 串行化 yr_rules_scan_mem（扫描持 Exclusive）
 *   Level 3: SQLite 内部锁  — sqlite3_mutex 自动管理
 *
 * 扫描入口：
 *     1) 同步文件扫描 IocYara_ScanFile —— 供 YaraScanPort 调用
 *     2) 通用内存扫描 IocYara_ScanBuffer —— 供 PackerDetector 等模块调用
 *     3) 异步队列扫描 IocYara_Enqueue —— 进程创建事件驱动
 */

#pragma once

#include "IocTypes.h"
#include "../IOA/IoaTypes.h"
#include "../Notification/msg_queue.h"
#include "../Common/TitaniumLimits.h"

/* libyara 头文件（由 External/yara/include 提供） */
#include <yara.h>

typedef struct _IOC_YARA_SCANNER {
    BOOLEAN Initialized; WKD_MSG_QUEUE Queue; HANDLE WorkerThread;
    volatile BOOLEAN Running; volatile LONG64 Enqueued; volatile LONG64 Completed;
} IOC_YARA_SCANNER, *PIOC_YARA_SCANNER;

NTSTATUS IocYara_Initialize(PIOC_YARA_SCANNER Scaner);
VOID     IocYara_Cleanup(PIOC_YARA_SCANNER S);
NTSTATUS IocYara_Enqueue(PIOC_YARA_SCANNER S, PWKD_PROCESS Node);

/*++
 * IocYara_ScanFile
 *   同步文件扫描 — 内存映射 → yr_rules_scan_mem → 回调聚合最高威胁。
 *--*/
NTSTATUS IocYara_ScanFile(
    _In_ PCWSTR FilePath,
    _Out_ PBOOLEAN Detected,
    _Out_ PULONG Score,
    _Out_writes_opt_(RuleNameCch) PWCHAR RuleName,
    _In_ ULONG RuleNameCch
    );

/*++
 * IocYara_ScanBuffer
 *   通用内存缓冲扫描入口。
 *--*/
NTSTATUS IocYara_ScanBuffer(
    _In_ const BYTE* Buffer,
    _In_ ULONG BufferSize,
    _Out_ PBOOLEAN Detected,
    _Out_ PULONG Score,
    _Out_writes_opt_(RuleNameCch) PWCHAR RuleName,
    _In_ ULONG RuleNameCch
    );
