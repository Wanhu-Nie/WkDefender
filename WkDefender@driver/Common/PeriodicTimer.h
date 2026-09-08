/*++
    Common/PeriodicTimer.h - 通用周期性定时任务执行器

    Purpose:
        提供统一的周期性任务调度接口，支持两种运行模式：
        - Thread 模式：系统线程 + KEVENT，回调运行于 PASSIVE_LEVEL
        - DPC 模式：KeSetTimerEx + KDPC，回调运行于 DISPATCH_LEVEL

        所有需要周期性轮询/检查的模块均通过此层调度，
        避免每个模块重复编写线程创建/Timer 初始化样板代码。

    Thread 模式设计:
        - 创建时生成专用系统线程，等待 KEVENT 信号
        - 每次信号触发后执行回调，完成后回到等待
        - 停止时设置 TerminateThread 标志并信号事件，线程自行退出
        - 通过 CallbackRunning 计数器保护回调不与销毁并发

    DPC 模式设计:
        - KeSetTimerEx 周期性触发 DPC
        - DPC 回调设置 WorkItem，由工作项在 PASSIVE_LEVEL 执行用户回调
        - 若不使用 WorkItem，用户回调直接在 DISPATCH_LEVEL 执行
          （CallbackProtection 需要 PASSIVE_LEVEL，必须用 Thread 模式）

    Usage:
        WKD_PERIODIC_TIMER timer;

        // 创建（Thread 模式），Rundown 为宿主生命周期 EX_RUNDOWN_REF（必传）
        CoCreatePeriodicTimer(&timer, 5000, MyCallback, myCtx, TRUE, &engineRundown);

        // 启动
        CoStartPeriodicTimer(&timer);

        // 停止（置 TerminateThread + 信号；线程在 next 次激活因 rundown
        // 获取失败或 TerminateThread 而退出，不做重启设计）
        WkdTimerStop(&timer, TRUE);

        // 销毁
        WkdTimerDestroy(&timer);

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

#define WKD_TIMER_DEFAULT_THREAD_TIMEOUT_SEC  10
#define WKD_TIMER_MIN_INTERVAL_MS          1000
#define WKD_TIMER_MAX_INTERVAL_MS          60000

/* ============================================================================
 * 类型定义
 * ============================================================================ */

//
// 定时器回调函数指针类型
//
// Thread 模式：回调运行于 PASSIVE_LEVEL
// DPC 模式：回调运行于 DISPATCH_LEVEL（除非使用 WorkItem 桥接）
//
typedef
VOID
(*WKD_TIMER_CALLBACK)(
    _Inout_opt_ PVOID Context
    );

//
// 定时器运行模式
//
typedef enum _WKD_TIMER_MODE {
    WkdTimerModeThread = 0,     // 系统线程 + KEVENT（PASSIVE_LEVEL 回调）
    WkdTimerModeDpc = 1,        // KeSetTimerEx + KDPC（DISPATCH_LEVEL 回调）
} WKD_TIMER_MODE;

//
// 定时器选项（可选扩展）
//
typedef struct _WKD_TIMER_OPTIONS {
    WKD_TIMER_MODE Mode;            // 运行模式（默认 Thread）
    LONG ThreadPriority;            // 线程优先级（仅 Thread 模式，默认 0 = 正常）
} WKD_TIMER_OPTIONS, *PWKD_TIMER_OPTIONS;

//
// 定时器状态
//
typedef enum _WKD_TIMER_STATE {
    WkdTimerStateUninitialized = 0,
    WkdTimerStateStopped,
    WkdTimerStateRunning,
    WkdTimerStateStopping,
} WKD_TIMER_STATE;

/* ============================================================================
 * 周期性定时器上下文（不透明布局，调用者不应直接访问字段）
 * ============================================================================ */

typedef struct _WKD_PERIODIC_TIMER {
    //
    // 配置（创建时设定，生命周期内不可变）
    //
    WKD_TIMER_CALLBACK Callback;
    PVOID CallbackContext;
    ULONG IntervalMs;
    WKD_TIMER_MODE Mode;

    //
    // 状态（被动记录，仅供诊断/查询；作为循环判据的是 Rundown，不是 State）
    //
    volatile WKD_TIMER_STATE State;

    //
    // 存活判据：注入的 EX_RUNDOWN_REF（由调用方持有，通常为父子系统/引擎 rundown）。
    // 线程/DPC 每次激活先 ExAcquireRundownProtection，成功才执行回调本轮结束后释放；
    // 获取失败表示宿主子系统进入关闭阶段，线程立即退出。
    // 必传；rundown 块须位于非分页池（可在 DISPATCH_LEVEL 调用）。
    //
    PEX_RUNDOWN_REF RundownRef;

    //
    // ---- Thread 模式内部状态 ----
    //
    HANDLE ThreadHandle;             // 线程句柄（ZwClose 用）
    PETHREAD ThreadObject;           // 线程对象（KeWaitForSingleObject 用）
    KEVENT WakeEvent;                // 信号事件（SynchronizationEvent）
    volatile LONG TerminateThread;   // 终止信号

    //
    // ---- DPC 模式内部状态 ----
    //
    KTIMER DpcTimer;                 // 内核定时器
    KDPC PeriodicDpc;                // 周期性 DPC
    volatile LONG DpcFired;          // DPC 已触发标志（防重入）

    //
    // ---- 同步 ----
    //
    volatile LONG CallbackRunning;   // 当前正在执行的回调数量
    KEVENT AllDoneEvent;             // 所有回调完成信号（Stop 等待用）
} WKD_PERIODIC_TIMER, *PWKD_PERIODIC_TIMER;

/* ============================================================================
 * 公共 API
 * ============================================================================ */

//
// 创建定时器（PASSIVE_LEVEL）
//
// IntervalMs:    触发间隔（毫秒），最小 WKD_TIMER_MIN_INTERVAL_MS
// Callback:      回调函数
// Context:       传递给回调的上下文指针
// RunAtPassive:  TRUE = Thread 模式，FALSE = DPC 模式
// Rundown:       存活判据（必传），见 WKD_PERIODIC_TIMER::Rundown
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CoCreatePeriodicTimer(
    _Out_ PWKD_PERIODIC_TIMER Timer,
    _In_ ULONG IntervalMs,
    _In_ const WKD_TIMER_CALLBACK Callback,
    _In_opt_ const PVOID Context,
    _In_ BOOLEAN RunAtPassive,
    _In_ const PEX_RUNDOWN_REF RundownRef
    );

//
// 带选项创建（PASSIVE_LEVEL）
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CoCreatePeriodicTimerEx(
    _Out_ PWKD_PERIODIC_TIMER Timer,
    _In_ ULONG IntervalMs,
    _In_ WKD_TIMER_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _In_opt_ PWKD_TIMER_OPTIONS Options,
    _In_ const PEX_RUNDOWN_REF RundownRef
    );

//
// 启动定时器（PASSIVE_LEVEL）
// 已运行时调用无效果。
// 启动后立即触发第一次回调（Thread 模式通过信号事件，DPC 模式通过立即触发 Timer）。
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
CoStartPeriodicTimer(
    _Inout_ PWKD_PERIODIC_TIMER Timer
    );

//
// 停止定时器（PASSIVE_LEVEL）
//
// WaitForDrain:
//   TRUE  — 阻塞等待当前正在执行的回调完成（超时 5 秒）
//   FALSE — 仅设置停止标志，不等待
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdTimerStop(
    _Inout_ PWKD_PERIODIC_TIMER Timer,
    _In_ BOOLEAN WaitForDrain
    );

//
// 销毁定时器（PASSIVE_LEVEL）
// 内部调用 WkdTimerStop(TRUE)，然后释放线程/DPC 资源。
// 调用后 Timer 结构体内容不确定，不应再使用。
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdTimerDestroy(
    _Inout_ PWKD_PERIODIC_TIMER Timer
    );

//
// 查询定时器状态（无锁读取）
//
_IRQL_requires_max_(APC_LEVEL)
WKD_TIMER_STATE
WkdTimerGetState(
    _In_ const PWKD_PERIODIC_TIMER Timer
    );

//
// 动态更新间隔（下次触发生效，当前周期不受影响）
// 仅 Thread 模式：更新后重新信号事件以应用新间隔（通过重置等待超时实现）。
// DPC 模式：需取消+重建定时器。
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdTimerSetInterval(
    _Inout_ PWKD_PERIODIC_TIMER Timer,
    _In_ ULONG NewIntervalMs
    );

#ifdef __cplusplus
}
#endif
