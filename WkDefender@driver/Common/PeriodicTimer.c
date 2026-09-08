/*++
    Common/PeriodicTimer.c - 通用周期性定时任务执行器实现

    Copyright (c) WkDefender Team
--*/

#include "PeriodicTimer.h"

/* ============================================================================
 * 内部前向声明
 * ============================================================================ */

static
_Function_class_(KSTART_ROUTINE)
VOID
CopThreadBasedTimerRoutine(
    _In_ PVOID Context
    );

static
_Function_class_(PKDEFERRED_ROUTINE)
VOID
WkdTimerDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

/* ============================================================================
 * 创建
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
CoCreatePeriodicTimer(
    _Out_ PWKD_PERIODIC_TIMER Timer,
    _In_ ULONG IntervalMs,
    _In_ const WKD_TIMER_CALLBACK Callback,
    _In_opt_ const PVOID Context,
    _In_ BOOLEAN RunAtPassive,
    _In_ const PEX_RUNDOWN_REF RundownRef
    )
{
    WKD_TIMER_OPTIONS opts;
    opts.Mode = RunAtPassive ? WkdTimerModeThread : WkdTimerModeDpc;
    opts.ThreadPriority = 0;
    return CoCreatePeriodicTimerEx(Timer, IntervalMs, Callback, Context, &opts, RundownRef);
}

_Use_decl_annotations_
NTSTATUS
CoCreatePeriodicTimerEx(
    _Out_ PWKD_PERIODIC_TIMER Timer,
    _In_ ULONG IntervalMs,
    _In_ const WKD_TIMER_CALLBACK Callback,
    _In_opt_ const PVOID Context,
    _In_opt_ PWKD_TIMER_OPTIONS Options,
    _In_ const PEX_RUNDOWN_REF RundownRef
    )
{
    NTSTATUS status;

    if (!Timer || !Callback || !RundownRef ||
        IntervalMs < WKD_TIMER_MIN_INTERVAL_MS || IntervalMs > WKD_TIMER_MAX_INTERVAL_MS) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Timer, sizeof(WKD_PERIODIC_TIMER));

    Timer->Callback = Callback;
    Timer->CallbackContext = Context;
    Timer->IntervalMs = IntervalMs;
    Timer->State = WkdTimerStateStopped;
    Timer->RundownRef = RundownRef;
    Timer->Mode = Options ? Options->Mode : WkdTimerModeThread;

    //
    // 根据模式初始化
    //
    if (Timer->Mode == WkdTimerModeThread) {
        HANDLE threadHandle = NULL;
        OBJECT_ATTRIBUTES objAttr;

        KeInitializeEvent(&Timer->WakeEvent, SynchronizationEvent, FALSE);
        KeInitializeEvent(&Timer->AllDoneEvent, SynchronizationEvent, FALSE);
        InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

        status = PsCreateSystemThread(
            &threadHandle,
            THREAD_ALL_ACCESS,
            &objAttr,
            NULL,
            NULL,
            CopThreadBasedTimerRoutine,
            Timer
        );
        if (!NT_SUCCESS(status)) return status;

        //
        // 获取线程对象引用（用于 KeWaitForSingleObject）
        //
        status = ObReferenceObjectByHandle(
            threadHandle,
            THREAD_ALL_ACCESS,
            *PsThreadType,
            KernelMode,
            (PVOID*)&Timer->ThreadObject,
            NULL
        );
        ZwClose(threadHandle);

        if (!NT_SUCCESS(status)) {
            //
            // 线程已启动但无法获取对象引用，通知其退出
            //
            InterlockedExchange(&Timer->TerminateThread, TRUE);
            KeSetEvent(&Timer->WakeEvent, IO_NO_INCREMENT, FALSE);
            return status;
        }

    } else {
        //
        // DPC 模式
        //
        KeInitializeTimer(&Timer->DpcTimer);
        KeInitializeDpc(&Timer->PeriodicDpc, WkdTimerDpcRoutine, Timer);
    }

    return STATUS_SUCCESS;
}

/* ============================================================================
 * 启动 / 停止
 * ============================================================================ */

_Use_decl_annotations_
VOID
CoStartPeriodicTimer(
    _Inout_ PWKD_PERIODIC_TIMER Timer
    )
{
    if (!Timer) return;

    //
    // 不做重启设计：Stop 后线程已退出（TerminateThread 置位），
    // 此处若已置位则直接返回。
    //
    if (InterlockedCompareExchange(&Timer->TerminateThread, 0, 0)) return;

    if (Timer->Mode == WkdTimerModeThread) {
        //
        // Thread 模式：信号唤醒线程，唤醒后以 rundown 为判据执行回调
        //
        KeSetEvent(&Timer->WakeEvent, IO_NO_INCREMENT, FALSE);
    } else {
        //
        // DPC 模式：启动周期性定时器
        //
        LARGE_INTEGER dueTime;
        InterlockedExchange(&Timer->DpcFired, FALSE);

        //
        // dueTime 为负数表示相对时间（100ns 单位）
        //
        dueTime.QuadPart = -(LONGLONG)Timer->IntervalMs * 10000LL;
        KeSetTimerEx(&Timer->DpcTimer, dueTime, Timer->IntervalMs, &Timer->PeriodicDpc);
    }
    InterlockedExchange(&Timer->State, WkdTimerStateRunning);
}

_Use_decl_annotations_
VOID
WkdTimerStop(
    PWKD_PERIODIC_TIMER Timer,
    BOOLEAN WaitForDrain
    )
{
    LARGE_INTEGER timeout;
    NT_ASSERT(Timer != NULL);

    if (Timer->TerminateThread && Timer->CallbackRunning == 0) {
        return;      // 已停止且回调已排空
    }

    //
    // 置停止信号（被动状态记录）
    //
    InterlockedExchange(&Timer->State, WkdTimerStateStopping);

    //
    // 停止底层调度器
    //
    if (Timer->Mode == WkdTimerModeDpc) {
        KeCancelTimer(&Timer->DpcTimer);
        InterlockedExchange(&Timer->DpcFired, FALSE);
    } else {
        //
        // Thread 模式：置 TerminateThread 并信号事件，
        // 线程唤醒后优先检查 TerminateThread 直接退出；
        // 即便正阻塞，也会因随后 rundown 排空/terminate 而退出。
        //
        InterlockedExchange(&Timer->TerminateThread, TRUE);
        KeSetEvent(&Timer->WakeEvent, IO_NO_INCREMENT, FALSE);
    }

    //
    // 等待回调排空（已获取 rundown 的回调完成）
    //
    if (WaitForDrain) {
        //
        // 超时 5 秒，防御死锁
        //
        timeout.QuadPart = -50000000LL;

        while (Timer->CallbackRunning > 0) {
            NTSTATUS waitStatus = KeWaitForSingleObject(
                &Timer->AllDoneEvent,
                Executive,
                KernelMode,
                FALSE,
                &timeout
            );

            if (waitStatus == STATUS_TIMEOUT) {
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID,
                    DPFLTR_ERROR_LEVEL,
                    "[WkDefender] PeriodicTimer: drain timeout, CallbackRunning=%ld\n",
                    Timer->CallbackRunning
                );
                break;
            }
        }
    }

    InterlockedExchange(&Timer->State, WkdTimerStateStopped);
}

/* ============================================================================
 * 销毁
 * ============================================================================ */

_Use_decl_annotations_
VOID
WkdTimerDestroy(
    PWKD_PERIODIC_TIMER Timer
    )
{
    NT_ASSERT(Timer != NULL);

    if (Timer->State == WkdTimerStateUninitialized) {
        return;
    }

    WkdTimerStop(Timer, TRUE);

    if (Timer->Mode == WkdTimerModeThread) {
        //
        // 通知线程退出并等待
        //
        if (Timer->ThreadObject != NULL) {
            InterlockedExchange(&Timer->TerminateThread, TRUE);
            KeSetEvent(&Timer->WakeEvent, IO_NO_INCREMENT, FALSE);

            KeWaitForSingleObject(
                Timer->ThreadObject,
                Executive,
                KernelMode,
                FALSE,
                NULL
            );

            ObDereferenceObject(Timer->ThreadObject);
            Timer->ThreadObject = NULL;
        }
    } else {
        //
        // DPC 模式：取消定时器和 DPC
        //
        KeCancelTimer(&Timer->DpcTimer);
        KeFlushQueuedDpcs();    // 确保 DPC 不再执行
    }

    InterlockedExchange(&Timer->State, WkdTimerStateUninitialized);
}

/* ============================================================================
 * 查询 / 修改
 * ============================================================================ */

_Use_decl_annotations_
WKD_TIMER_STATE
WkdTimerGetState(
    const PWKD_PERIODIC_TIMER Timer
    )
{
    NT_ASSERT(Timer != NULL);
    return Timer->State;
}

_Use_decl_annotations_
VOID
WkdTimerSetInterval(
    PWKD_PERIODIC_TIMER Timer,
    ULONG NewIntervalMs
    )
{
    NT_ASSERT(Timer != NULL);

    if (NewIntervalMs < WKD_TIMER_MIN_INTERVAL_MS) {
        return;
    }

    Timer->IntervalMs = NewIntervalMs;

    //
    // Thread 模式：间隔在下次等待超时中自然生效
    // DPC 模式：需重建定时器
    //
    if (Timer->Mode == WkdTimerModeDpc && Timer->State == WkdTimerStateRunning) {
        LARGE_INTEGER dueTime;
        KeCancelTimer(&Timer->DpcTimer);
        dueTime.QuadPart = -(LONGLONG)NewIntervalMs * 10000LL;
        KeSetTimerEx(&Timer->DpcTimer, dueTime, NewIntervalMs, &Timer->PeriodicDpc);
    }
}

/* ============================================================================
 * Thread 模式工作线程
 * ============================================================================ */

static
_Function_class_(KSTART_ROUTINE)
VOID
CopThreadBasedTimerRoutine(
    _In_ PVOID Context
    )
{
    LARGE_INTEGER timeout;
    PWKD_PERIODIC_TIMER timer = (PWKD_PERIODIC_TIMER)Context;

    //
    // 超时 10 秒，防御性地检查 TerminateThread
    //
    timeout.QuadPart = - (LONGLONG)WKD_TIMER_DEFAULT_THREAD_TIMEOUT_SEC * 10000000LL;

    for (;;) {
        KeWaitForSingleObject(
            &timer->WakeEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );

        //
        // 优先检查终止信号
        //
        if (timer->TerminateThread) break;

        //
        // 核心判据：以注入的 rundown 为存活依据。
        // 获取成功 = 宿主子系统存活，执行本轮回调并获得生命周期保护；
        // 获取失败 = 子系统已进入关闭阶段，线程退出。
        //
        if (!ExAcquireRundownProtection(timer->RundownRef)) {
            InterlockedExchange(&timer->State, WkdTimerStateStopping); // 被动记录
            break;
        }

        InterlockedExchange(&timer->State, WkdTimerStateRunning);       // 被动记录
        InterlockedIncrement(&timer->CallbackRunning);
        timer->Callback(timer->CallbackContext);

        if (InterlockedDecrement(&timer->CallbackRunning) == 0) {
            //
            // 最后一个回调完成，通知等待 Drain 的 Stop 调用者
            //
            KeSetEvent(&timer->AllDoneEvent, IO_NO_INCREMENT, FALSE);
        }

        ExReleaseRundownProtection(timer->RundownRef);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* ============================================================================
 * DPC 模式回调
 *
 * DPC 运行在 DISPATCH_LEVEL。如果回调本身需要 PASSIVE_LEVEL，
 * 调用者应使用 Thread 模式。此处直接调用回调（DISPATCH_LEVEL）。
 * ============================================================================ */

static
_Function_class_(PKDEFERRED_ROUTINE)
VOID
WkdTimerDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PWKD_PERIODIC_TIMER timer = (PWKD_PERIODIC_TIMER)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (timer == NULL) {
        return;
    }

    //
    // 防重入（同一次 DPC 尚未处理完毕时新 DPC 到达）
    //
    if (InterlockedCompareExchange(&timer->DpcFired, TRUE, FALSE) != FALSE) {
        return;
    }

    //
    // 核心判据：以注入的 rundown 为存活依据。获取成功才执行回调
    // （DPC 运行于 DISPATCH_LEVEL，rundown 块非分页，可在此调用）；
    // 获取失败表示宿主子系统进入关闭阶段，本轮跳过。
    //
    if (ExAcquireRundownProtection(timer->RundownRef)) {
        InterlockedExchange(&timer->State, WkdTimerStateRunning);  // 被动记录
        InterlockedIncrement(&timer->CallbackRunning);
        timer->Callback(timer->CallbackContext);

        if (InterlockedDecrement(&timer->CallbackRunning) == 0) {
            KeSetEvent(&timer->AllDoneEvent, IO_NO_INCREMENT, FALSE);
        }

        ExReleaseRundownProtection(timer->RundownRef);
    }

    InterlockedExchange(&timer->DpcFired, FALSE);
}
