/**************************************************/
/*  WkDefender Agent — 进程域线程挂载实现           */
/*                                                  */
/*  2026-08-15 新增。线程挂载 WKD_PROCESS::           */
/*  ThreadContext（并发安全重构 2026-08-23，独立       */
/*  Lock），数据源 = EVENT_PAYLOAD_THREAD_*。           */
/**************************************************/

#include "ProcessThread.h"
#include "ProcessTree.h"
#include "../tools.h"

/**************************************************/
/*               线程挂载 API                       */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
PsThreadAttachProcess(
    _Inout_ PWKD_PROCESS WkdProcess,
    _In_ const PEVENT_PAYLOAD_THREAD_CREATE Payload,
    _Out_ PWKD_THREAD* WkdThread
    )
/*++
Routine Description:
    将线程事件挂载到目标进程的线程表（2026-08-15 进程域）。
    由 IoaObserve 线程分支或分发层调用（注入评分计算之后）。

Arguments:
    Process — 目标进程节点（线程所属进程）。
    Payload — 线程创建事件载荷（WKD_MESSAGE_BODY_THREAD_CREATE 对齐）。

Return Value:
    成功返回新挂载的 WKD_THREAD 节点; 失败返回 NULL。
--*/
{
    PWKD_THREAD thread;
    PWKD_THREAD_CONTEXT ctx;

    if (!WkdProcess || !Payload || !WkdThread) {
        return STATUS_INVALID_PARAMETER;
    }
    *WkdThread = NULL;

    /* ---- Step 1: 惰性申请线程上下文 ---- */
    ctx = InterlockedCompareExchangePointer(&WkdProcess->ThreadContext, NULL, NULL);
    if (!ctx) {
        PWKD_THREAD_CONTEXT newContext;

        /* 创建线程上下文后需要二次检查通过后才能替换指针 */
        newContext = malloc(sizeof(WKD_THREAD_CONTEXT));
        if (!newContext) return STATUS_NO_MEMORY;
        RtlZeroMemory(newContext, sizeof(WKD_THREAD_CONTEXT));
        
        InitializeListHead(&newContext->ThreadList);
        newContext->ProcessId = WkdProcess->ProcessId;
        InitializeSRWLock(&newContext->Lock);

        ctx = InterlockedCompareExchangePointer(
            &WkdProcess->ThreadContext, newContext, NULL);
        /* 发生竞态创建，输家释放本地副本 */
        if (ctx) free(newContext);
        else ctx = newContext;
    }
    
    /* ---- Step 2: 申请线程对象并插入 ---- */
    thread = malloc(sizeof(WKD_THREAD));
    if (!thread) return STATUS_NO_MEMORY;
    
    thread->ProcessId           = WkdProcess->ProcessId;
    thread->ThreadId            = Payload->ThreadId;
    thread->CreatorProcessId    = Payload->CreatorProcessId;
    thread->CreatorThreadId     = Payload->CreatorThreadId;
    thread->StartRoutine        = Payload->StartRoutine;
    thread->Argument            = Payload->Argument;
    thread->DesiredAccess       = Payload->DesiredAccess;
    thread->CreateFlags         = Payload->CreateFlags;
    thread->MemoryProtection    = Payload->MemoryProtection;
    thread->CreatorSessionId    = Payload->CreatorSessionId;
    thread->TargetSessionId     = Payload->TargetSessionId;
    thread->InjectIndicators    = Payload->InjectIndicators;
    thread->InjectionScore      = Payload->InjectionScore;
    thread->RiskLevel           = Payload->RiskLevel;
    //if (Payload->StartBytesSize && Payload->StartBytesSize <= sizeof(thread->StartBytes)) {
    //    memcpy(thread->StartBytes, Payload->StartBytes, Payload->StartBytesSize);
    //    t->StartBytesSize = Payload->StartBytesSize;
    //}
    thread->CreateTime          = Payload->CreateTime;
    thread->Flags               = Payload->Flags;
    /* IOC 区域: 单写者 IocObserveThread 后续写回; 此处初始化防垃圾值 */
    thread->IoacUnbackedStart       = FALSE;
    thread->IoacUnusualEntry        = FALSE;
    thread->IoacShellcodeSuspected  = FALSE;

    AcquireSRWLockExclusive(&ctx->Lock);
    InsertTailList(&ctx->ThreadList, &thread->ListEntry);
    ReleaseSRWLockExclusive(&ctx->Lock);
    InterlockedIncrement(&ctx->ActiveThreads);
    InterlockedIncrement(&ctx->TotalThreads);
    PsReferenceWkdProcess(WkdProcess);

    *WkdThread = thread;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PsThreadDetachProcess(
    _Inout_ PWKD_PROCESS WkdProcess,
    _In_ HANDLE ThreadId
    )
/*++
Routine Description:
    按 ThreadId 从目标进程线程表移除线程节点。

Arguments:
    Process  — 目标进程节点。
    ThreadId — 线程 ID。

Return Value:
    VOID。
--*/
{
    PLIST_ENTRY entry, next;
    PWKD_THREAD_CONTEXT ctx;
    PWKD_THREAD thread;

    if (!WkdProcess || !WkdProcess->ThreadContext || !ThreadId) {
        return STATUS_INVALID_PARAMETER;
    }

    ctx = WkdProcess->ThreadContext;

    AcquireSRWLockExclusive(&ctx->Lock);
    entry = ctx->ThreadList.Flink;
    while (entry != &ctx->ThreadList) {
        next = entry->Flink;
        thread = CONTAINING_RECORD(entry, WKD_THREAD, ListEntry);
        if (thread->ThreadId == ThreadId) {
            RemoveEntryList(entry);
            free(thread);
            InterlockedDecrement(&ctx->ActiveThreads);
            ReleaseSRWLockExclusive(&ctx->Lock);
            PsDereferenceWkdProcess(WkdProcess);
            return STATUS_SUCCESS;
        }
        entry = next;
    }
    ReleaseSRWLockExclusive(&ctx->Lock);
    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
VOID
PsDestroyThreadContext(
    _Inout_ PWKD_PROCESS WkdProcess
    )
/*++
Routine Description:
    释放进程全部线程节点（进程退出/清理时调用）。

Arguments:
    Process — 进程节点。

Return Value:
    VOID。
--*/
{
    PLIST_ENTRY entry, next;
    PWKD_THREAD_CONTEXT context;
    PWKD_THREAD thread;

    if (!WkdProcess || !WkdProcess->ThreadContext) return;

    context = WkdProcess->ThreadContext;

    /* 理论上进程终止时，线程上下文中不存在任何线程!!! */
    entry = context->ThreadList.Flink;
    while (entry != &context->ThreadList) {
        next = entry->Flink;
        thread = CONTAINING_RECORD(entry, WKD_THREAD, ListEntry);
        RemoveEntryList(entry);
        free(thread);
        entry = next;
    }
   
    free(context);
    WkdProcess->ThreadContext = NULL;
}
