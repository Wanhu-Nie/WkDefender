/*++
    SelfProtection/AntiDebug.h - 防调试检测与告警（AntiDebug, AD）子组件

    Purpose:
        检测内核/用户态调试器、虚拟化（Hypervisor）、驱动验证器（Driver Verifier）、
        完整内存转储配置等"规避/调试"行为，记录为事件并上报（经
        WkdReportSelfProtectionEvent -> ALPC 到 Agent）。

        Detect-and-alert 模型：本组件只做【检测与上报】，不能也不试图阻止
        内核调试器附加（驱动无法做到）。

    架构（对齐自防护引擎铁律）:
        - 本组件【不持有】也不获取 EX_RUNDOWN_REF / 生命周期标志；
          生命周期由自防护引擎（SelfProtectionEngine）统一编排。
        - 周期检测采用 Common/PeriodicTimer.h 的 Thread 模式（PASSIVE_LEVEL 回调），
          不在本组件内自建系统线程。
        - 不对外暴露用户态回调注册；检测结果统一经上报事件通道发送。
        - 事件以值类型 ADB_EVENT_INFO 快照返回给调用方（不暴露内部指针）。

    对外 API 生命周期：
        SpInitializeAntiDebugProtection  -> SpStartPeriodicAntiDebugProtection -> ...(周期检测/查询 API)... -> AdbShutdown

    上报（IRQL 约束）:
        WkdReportSelfProtectionEvent 要求 PASSIVE_LEVEL，周期回调运行于
        PASSIVE_LEVEL（Thread 模式）可直接调用；潜在高 IRQL 路径需先做
        KeGetCurrentIrql() > PASSIVE_LEVEL 门控（当前 AD 检测均在 PASSIVE 执行）。

    Copyright (c) WkDefender Team
--*/

#pragma once

#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 常量
 * ============================================================================ */

#define ADB_POOL_TAG_CTX    'cBDA'   /* WKD_ANTIDEBUG_PROTECTION context */
#define ADB_POOL_TAG_EVENT  'eBDA'   /* 内部 ADB_EVENT 节点 */

#define ADB_MAX_PROCESS_NAME    260     /* 进程名宽字符上限 */
#define ADB_MAX_DETAIL_LENGTH   256     /* 详情窄字符上限 */
#define ADB_MAX_EVENTS          1024    /* 内部事件链表上限硬顶 */
#define ADB_CHECK_INTERVAL_MS   30000   /* 周期检测间隔（毫秒，Thread 模式） */

//
// 上报事件子类型（编排到 WkdReportSelfProtectionEvent 的 EventSubType）。
// 0x5010 段预留给 AD；各检测类型一个固定子类型 + 独立严重度。
//
#define ADB_EVENT_SUBTYPE_KERNEL_DEBUGGER   0x5010   /* 内核调试器 */
#define ADB_EVENT_SUBTYPE_USER_DEBUGGER     0x5011   /* 用户态调试器 */
#define ADB_EVENT_SUBTYPE_HYPERVISOR        0x5012   /* 虚拟化/Hypervisor */
#define ADB_EVENT_SUBTYPE_DRIVER_VERIFIER   0x5013   /* 驱动验证器 */
#define ADB_EVENT_SUBTYPE_MEMORY_DUMP       0x5014   /* 完整内存转储 */

/* ============================================================================
 * 检测类型
 * ============================================================================ */

typedef enum _ADB_DEBUG_ATTEMPT {
    AdbAttemptNone = 0,
    AdbAttemptKernelDebugger,       /* KD_DEBUGGER_ENABLED 检测 */
    AdbAttemptUserDebugger,         /* DebugPort 检测 */
    AdbAttemptDriverVerifier,       /* 驱动验证器启用 */
    AdbAttemptHypervisor,           /* Hypervisor/VM 检测 */
    AdbAttemptMemoryDump,           /* 完整内存转储配置 */
    AdbAttemptMax
} ADB_DEBUG_ATTEMPT, *PADB_DEBUG_ATTEMPT;

/* ============================================================================
 * 事件快照（返回给调用方，自包含值类型）
 * ============================================================================ */

typedef struct _ADB_EVENT_INFO {
    ADB_DEBUG_ATTEMPT   Type;
    HANDLE              ProcessId;
    WCHAR               ProcessName[ADB_MAX_PROCESS_NAME];
    USHORT              ProcessNameLength;      /* 字符数，非字节 */
    CHAR                Details[ADB_MAX_DETAIL_LENGTH];
    LARGE_INTEGER       Timestamp;
} ADB_EVENT_INFO, *PADB_EVENT_INFO;

/* ============================================================================
 * 统计
 * ============================================================================ */

typedef struct _ADB_STATISTICS {
    volatile LONG64     TotalDetections;
    volatile LONG64     ReportInvocations;
    LONG                CurrentEventCount;
    BOOLEAN             KernelDebuggerPresent;
    BOOLEAN             UserDebuggerPresent;
    BOOLEAN             HypervisorPresent;
    BOOLEAN             VerifierEnabled;
    BOOLEAN             CrashDumpEnabled;
    LARGE_INTEGER       LastCheckTime;
    LARGE_INTEGER       StartTime;
} ADB_STATISTICS, *PADB_STATISTICS;

/* ============================================================================
 * 保护器上下文（不透明句柄，结构定义在 AntiDebug.c）
 * ============================================================================ */

typedef struct _WKD_ANTIDEBUG_PROTECTION WKD_ANTIDEBUG_PROTECTION, *PWKD_ANTIDEBUG_PROTECTION;

/* ============================================================================
 * 公共 API
 * ============================================================================ */

//
// 初始化 AD 子组件（创建上下文、记录初始检测状态，尚未启动周期检测）。
// EngineRundown: 注入的自防护引擎 EX_RUNDOWN_REF（必传，周期线程据此判活）
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SpInitializeAntiDebugProtection(
    _Out_ PWKD_ANTIDEBUG_PROTECTION* Protector
    );

//
// 启动周期检测（创建并启动 Thread 模式周期定时器）。
// 须在 SpInitializeAntiDebugProtection 之后调用。运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SpStartPeriodicAntiDebugProtection(
    _Inout_ PWKD_ANTIDEBUG_PROTECTION Protection,
    _In_ const PEX_RUNDOWN_REF RundownRef,
    _In_ ULONG IntervalMs
    );

//
// 关闭 AD 子组件（停止周期定时器、清空并释放事件、释放上下文）。NULL 安全。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
AdbShutdown(
    _In_ _Post_invalid_ PWKD_ANTIDEBUG_PROTECTION Protector
    );

//
// 主动查询：内核调试器 + 用户态调试器是否附加。
// 需 ZwQueryInformationProcess，故限 PASSIVE_LEVEL。
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AdbCheckForDebugger(
    _In_ PWKD_ANTIDEBUG_PROTECTION Protector,
    _Out_ PBOOLEAN DebuggerPresent
    );

//
// 主动查询：Hypervisor 是否存在。运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AdbCheckForHypervisor(
    _In_ PWKD_ANTIDEBUG_PROTECTION Protector,
    _Out_ PBOOLEAN HypervisorPresent
    );

//
// 取事件数组的值类型快照（最多 MaxEvents 条）。运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AdbGetEvents(
    _In_ PWKD_ANTIDEBUG_PROTECTION Protector,
    _Out_writes_to_(MaxEvents, *ReturnedCount) PADB_EVENT_INFO EventArray,
    _In_ ULONG MaxEvents,
    _Out_ PULONG ReturnedCount
    );

//
// 取检测统计快照。运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AdbGetStatistics(
    _In_ PWKD_ANTIDEBUG_PROTECTION Protector,
    _Out_ PADB_STATISTICS Stats
    );

//
// 清空并释放全部事件。运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AdbClearEvents(
    _In_ PWKD_ANTIDEBUG_PROTECTION Protector
    );

#ifdef __cplusplus
}
#endif
