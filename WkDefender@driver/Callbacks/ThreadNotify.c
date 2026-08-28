#include "ThreadNotify.h"
#include "../Notification/NotificationManager.h"
#include "../Syscall/SyscallMonitor.h"
#include "../Syscall/SyscallContextCache.h"
#include "../Common/Utils.h"
#include "../AnalysisEngine/IoaEngine.h"
#include "../Notification/AlpcService.h"
#include "../Process/ProcessPairContext.h"
#include "../Notification/MessageSync.h"
#include "../AnalysisEngine/IocEngine.h"
#include "../AnalysisEngine/AnalysisEngine.h"
#include "../Common/Exempts/Exempts.h"
#include "../AnalysisEngine/IocSyscall.h"

/**************************************************/
/*                   内部状态                      */
/**************************************************/

typedef struct _WKD_THREAD_CALLBACK_STATE {
    BOOLEAN Initialized;
    BOOLEAN CallbackRegistered;
    BOOLEAN ShutdownRequested;
    EX_RUNDOWN_REF RundownRef;
} WKD_THREAD_CALLBACK_STATE;

static WKD_THREAD_CALLBACK_STATE g_TdState = { 0 };

/**************************************************/
/*                函数前向声明                     */
/**************************************************/

//
// 确保必要的常量定义（WDK 跨版本兼容）
//
#ifndef THREAD_CREATE_FLAGS_CREATE_SUSPENDED
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED    0x00000001
#endif
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION       0x1000
#endif


typedef NTSTATUS(NTAPI* PFN_ZwOpenThread)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
    );
static PFN_ZwOpenThread pfn_ZwOpenThread = NULL;

typedef NTSTATUS(NTAPI* PFN_ZwQueryInformationThread)(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
    );
static PFN_ZwQueryInformationThread pfn_ZwQueryInformationThread = NULL;

//
// 内存查询 & 进程属性 API（对齐 PS ThreadNotify）
//
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
    );

__declspec(dllimport) ULONG    NTAPI PsGetProcessSessionId(_In_ PEPROCESS Process);

//
// 注：线程退出信息 API PsGetThreadExitTime / KeQueryThreadTime 为未文档化导出，
// 已于 26100 内核移除（ntoskrnl.lib 无符号），相关采集逻辑在回调内降级为
// KeQuerySystemTime 近似（见 CbpThreadNotifyCallback 退出分支注释）。
//

//
// 线程创建/终止回调
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
CbpThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    );

//_IRQL_requires_(PASSIVE_LEVEL)
//static
//NTSTATUS
//CbpRegistryThread(
//    _In_ PWKD_PROCESS Process,
//    _In_ HANDLE ThreadId
//    );
//
//_IRQL_requires_(PASSIVE_LEVEL)
//static
//NTSTATUS
//CbpUnregistryThread(
//    _In_ PWKD_PROCESS Process,
//    _In_ HANDLE ThreadId
//    );
//
//_IRQL_requires_(PASSIVE_LEVEL)
//static
//VOID
//CbpNotifyIoaRemoteThread(
//    _In_ HANDLE TargetProcessId,
//    _In_ HANDLE ThreadId
//    );
//
//_IRQL_requires_(PASSIVE_LEVEL)
//static
//VOID
//CbpNotifyThreadCreate(
//    _In_ HANDLE ProcessId,
//    _In_ HANDLE ThreadId,
//    _In_ BOOLEAN Create
//    );

/**************************************************/
/*              初始化 / 清理                      */
/**************************************************/

//
// 初始化线程回调模块
//
_Use_decl_annotations_
NTSTATUS
CbThreadNotifyInitialize(
    VOID
    )
/*++
Routine Description:
    初始化线程回调模块。
    注册 PsSetCreateThreadNotifyRoutine 回调，
    用于检测跨进程线程创建（DLL注入核心行为）。

Returns:
    STATUS_SUCCESS  — 注册成功
    其他 NTSTATUS   — 注册失败
--*/
{
    NTSTATUS status;
    UNICODE_STRING uniStr;

    RtlZeroMemory(&g_TdState, sizeof(WKD_THREAD_CALLBACK_STATE));
    ExInitializeRundownProtection(&g_TdState.RundownRef);

    /* 初始化相关函数 */
    RtlInitUnicodeString(&uniStr, L"ZwOpenThread");
    pfn_ZwOpenThread =
        (PFN_ZwOpenThread)MmGetSystemRoutineAddress(&uniStr);

    RtlInitUnicodeString(&uniStr, L"ZwQueryInformationThread");
    pfn_ZwQueryInformationThread =
        (PFN_ZwQueryInformationThread)MmGetSystemRoutineAddress(&uniStr);

    //
    // 注册线程创建/终止回调
    //
    status = PsSetCreateThreadNotifyRoutine(CbpThreadNotifyCallback);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] CbThreadNotifyInitialize: PsSetCreateThreadNotifyRoutine failed: 0x%08X\n",
            status);
        return status;
    }

    g_TdState.CallbackRegistered = TRUE;
    g_TdState.Initialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] ThreadNotify module initialized.\n");

    return STATUS_SUCCESS;
}

//
// 清理线程回调模块
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
CbThreadNotifyCleanup(
    VOID
    )
/*++
Routine Description:
    清理线程回调模块，注销回调并等待所有正在进行的回调完成。
--*/
{
    g_TdState.ShutdownRequested = TRUE;

    //
    // 等待所有正在进行的回调完成
    //
    ExWaitForRundownProtectionRelease(&g_TdState.RundownRef);

    //
    // 注销线程回调
    //
    if (g_TdState.CallbackRegistered) {
        NTSTATUS status = PsRemoveCreateThreadNotifyRoutine(CbpThreadNotifyCallback);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[WkDefender] CbThreadNotifyCleanup: PsRemoveCreateThreadNotifyRoutine failed: 0x%08X\n",
                status);
        }
        g_TdState.CallbackRegistered = FALSE;
    }

    g_TdState.Initialized = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] ThreadNotify module cleaned up.\n");
}

/**************************************************/
/*           线程上下文管理                        */
/**************************************************/

//
// 为进程注册线程上下文
//
_Use_decl_annotations_
NTSTATUS
CbAllocateThreadContext(
    _Inout_ PWKD_PROCESS WkdProcess
    )
/*++
Routine Description:
    为指定进程分配并初始化 WKD_THREAD_CONTEXT。
    在进程创建时调用，挂载到 WKD_PROCESS.ThreadContext。

    2026-08-25 锁下沉: 进程级推锁已删除，挂载点改用
    InterlockedCompareExchangePointer 发布 (赢家/输家模型) —
    输家释放本地副本复用赢家；上下文内嵌 Lock 由本函数初始化。

Arguments:
    Process — 目标 WKD_PROCESS。

Returns:
    STATUS_SUCCESS       — 成功
    STATUS_NO_MEMORY     — 内存分配失败
    STATUS_INVALID_PARAMETER — 无效参数
--*/
{
    PWKD_THREAD_CONTEXT context;

    if (!WkdProcess) return STATUS_INVALID_PARAMETER;

    /* ---- 快路径: 已存在直接返回 ---- */
    if (WkdProcess->ThreadContext) return STATUS_SUCCESS;

    context = ExAllocatePool2(POOL_FLAG_NON_PAGED,
        sizeof(WKD_THREAD_CONTEXT), 'tdCx');
    if (!context) return STATUS_NO_MEMORY;
    RtlZeroMemory(context, sizeof(WKD_THREAD_CONTEXT));

    InitializeListHead(&context->ThreadHead);
    InitializeListHead(&context->RecentEvents);
    ExInitializePushLock(&context->Lock);

    if (InterlockedCompareExchangePointer(
        &WkdProcess->ThreadContext, context, NULL)) {
        /* 并发输家: 赢家已发布, 释放本地副本 */
        ExFreePoolWithTag(context, 'tdCx');
    }

    return STATUS_SUCCESS;
}

//
// 注销线程上下文
//
_Use_decl_annotations_
VOID
CbDistroyThreadContext(
    _Inout_ PWKD_PROCESS WkdProcess
    )
/*++
Routine Description:
    清理指定进程的线程上下文。
    遍历并释放所有线程条目，最后释放 WKD_THREAD_CONTEXT。
    在进程销毁时调用。

Arguments:
    Process — 目标 WKD_PROCESS。
--*/
{
    PWKD_THREAD_CONTEXT context;
    PLIST_ENTRY entry, next;
    PWKD_THREAD wkdThread;
    KIRQL oldIrql;

    if (!WkdProcess || !WkdProcess->ThreadContext) {
        return;
    }

    context = WkdProcess->ThreadContext;

    /* 无锁锁遍历并释放所有线程条目（理论上不会发生!!!） */
    entry = context->ThreadHead.Flink;
    while (entry != &context->ThreadHead) {
        next = entry->Flink;
        wkdThread = CONTAINING_RECORD(entry, WKD_THREAD, Links);
        RemoveEntryList(entry);
        PsDereferenceWkdThread(wkdThread);
        InterlockedDecrement(&context->Statistics.ActiveThreads);
        InterlockedIncrement(&context->Statistics.TotalTerminated);
    }

    //
    // 释放上下文本身
    //
    ExFreePoolWithTag(context, 'tdCx');
    WkdProcess->ThreadContext = NULL;
}

//
// 查找线程条目
//
_IRQL_requires_(PASSIVE_LEVEL)
PWKD_THREAD
CbLookupWkdThread(
    _In_ PWKD_PROCESS Process,
    _In_ HANDLE ThreadId
    )
/*++
Routine Description:
    在进程的线程上下文中查找指定 ThreadId 的线程条目。

Arguments:
    Process  — 目标 WKD_PROCESS。
    ThreadId — 要查找的线程 ID。

Returns:
    找到则返回 WKD_THREAD 指针，否则 NULL。
--*/
{
    PWKD_THREAD_CONTEXT context;
    PLIST_ENTRY entry;
    PWKD_THREAD wkdThread;
    KIRQL oldIrql;

    if (!Process || !Process->ThreadContext || !ThreadId) {
        return NULL;
    }

    context = Process->ThreadContext;


    entry = context->ThreadHead.Flink;
    while (entry != &context->ThreadHead) {
        wkdThread = CONTAINING_RECORD(entry, WKD_THREAD, Links);

        if (wkdThread->ThreadId == ThreadId) {
            return wkdThread;
        }

        entry = entry->Flink;
    }

    return NULL;
}

//
// 获取线程数量
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
CbGetThreadCount(
    _In_ PWKD_PROCESS Process
    )
{
    if (!Process || !Process->ThreadContext) {
        return 0;
    }

    return Process->ThreadContext->Statistics.ActiveThreads;
}

/**************************************************/
/*           内部辅助函数                          */
/**************************************************/


//
// 线程条目解引用 - 归零自动销毁 (2026-08-25 强制对称契约)。
// 引用模型: 创建=1 (临时引用, 出参转移) / 插入链表 +1 (表引用,
// CbpUnregistryThread 摘链时归还) / 借出方持 pin 用完归还。
//
_Use_decl_annotations_
VOID
PsDereferenceWkdThread(
    _Inout_ PWKD_THREAD WkdThread
    )
{
    if (!WkdThread) return;
    if (InterlockedDecrement(&WkdThread->RefCount) == 0) {
        if (WkdThread->EThread) {
            ObDereferenceObject(WkdThread->EThread);
            WkdThread->EThread = NULL;
        }
        ExFreePoolWithTag(WkdThread, 'tdEn');
    }
}
//
// 添加线程条目
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
CbpRegistryThread(
    _Inout_ PWKD_PROCESS WkdProcess,
    _In_ HANDLE ThreadId,
    _In_ HANDLE CreatorProcessId,
    _In_ HANDLE CreatorThreadId,
    _Out_opt_ PWKD_THREAD* WkdThread
    )
/*++
Routine Description:
    在线程创建时向进程的线程上下文添加一个新的线程条目。
    获取 ETHREAD 对象引用，采集线程入口地址、模拟状态等关键信息，
    用于支撑 IOA 行为分析中的线程注入检测和攻击链构建。

Arguments:
    Process           — 目标 WKD_PROCESS（线程所属进程）。
    ThreadId          — 新线程的 ID。
    CreatorProcessId  — 创建者进程 ID (sPid)，本地创建时与 Process->ProcessId 相同。
    CreatorThreadId   — 创建者线程 ID (sTid)。

Returns:
    STATUS_SUCCESS — 成功添加
    其他状态码     — 失败
--*/
{
    HANDLE hThread;
    PETHREAD ethread = NULL;
    PWKD_THREAD_CONTEXT context;
    PWKD_THREAD thread;
    
    NTSTATUS status;
    KIRQL oldIrql;

    if (!ThreadId || !CreatorThreadId || !CreatorProcessId || !WkdProcess) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!WkdProcess->ThreadContext) {
        status = CbAllocateThreadContext(WkdProcess);
        if (!NT_SUCCESS(status)) return status;
    }
    if (WkdThread) *WkdThread = NULL;

    context = WkdProcess->ThreadContext;

    //
    // 通过 ThreadId 获取 ETHREAD 对象（避免uaf）
    //
    status = PsLookupThreadByThreadId(ThreadId, &ethread);
    if (!NT_SUCCESS(status)) {
        /* 新创建线程获取失败??? 这是严重错误!!! 当前线程并未返回!!! */
        return status;
    }

    //
    // 分配线程条目（使用非分页池）
    //
    thread = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(WKD_THREAD), 'tdEn');
    if (!thread) {
        ObDereferenceObject(ethread);
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(thread, sizeof(WKD_THREAD));

    thread->ProcessId = WkdProcess->Core.ProcessId;
    thread->ThreadId = ThreadId;
    thread->EThread = ethread;
    thread->CreateTime.QuadPart = PsGetThreadCreateTime(ethread);
    thread->CreatorProcessId = CreatorProcessId;
    thread->CreatorThreadId = CreatorThreadId;
    thread->IsRemote = CreatorProcessId != WkdProcess->Core.ProcessId;

    /* 2026-08-25 引用契约: 创建临时引用 (经出参转移给调用方),
     * 插链成功后再 +1 表引用; 失败路径统一 Deref 自动销毁。 */
    thread->RefCount = 1;

    /*
     * === 填充线程属性（入口地址 + syscall 上下文匹配） ===
     */
    {
        PVOID startAddress;
        CLIENT_ID cid = { thread->ProcessId, ThreadId };
        OBJECT_ATTRIBUTES objAttr = { 0 };

        status = pfn_ZwOpenThread(&hThread, THREAD_QUERY_LIMITED_INFORMATION, &objAttr, &cid);
        if (!NT_SUCCESS(status)) goto Cleanup;
        
        status = pfn_ZwQueryInformationThread(hThread,
            ThreadQuerySetWin32StartAddress, &startAddress, sizeof(PVOID), NULL);
        if (!NT_SUCCESS(status)) goto Cleanup;

        thread->StartRoutine = startAddress;
        thread->HasStartRoutine = TRUE;
        ZwClose(hThread);

        /*
         * 从 ETW 缓存中匹配 NtCreateThreadEx 的 syscall 上下文。
         * 匹配键: <CreatorThreadId, WkdSyscall_NtCreateThreadEx>
         * 缓存中的项在 ETW 回调侧由 CtxCacheInsertEx 写入，此处消费。
         */
        {
            PCTX_CACHE_ENTRY cachedEntry =
                CtxCacheConsumeByTid(CreatorThreadId, WkdSyscall_NtCreateThreadEx);
            if (cachedEntry) {
                thread->DesiredAccess = cachedEntry->Params.CreateRemoteThread.DesiredAccess;
                thread->Argument      = cachedEntry->Params.CreateRemoteThread.Argument;
                thread->CreateFlags   = cachedEntry->Params.CreateRemoteThread.CreateFlags;
                thread->HasSyscallCtx = TRUE;
                ExFreePool(cachedEntry);
            }
        }
    }

    /* 链头插入: 持 ThreadContext::Lock 独占 + 表引用 (+1) */
    WkdAcquirePushLockExclusive(&context->Lock);
    InsertTailList(&context->ThreadHead, &thread->Links);
    PsReferenceWkdThread(thread);
    WkdReleasePushLockExclusive(&context->Lock);
    InterlockedIncrement(&context->Statistics.ActiveThreads);
    InterlockedIncrement(&context->Statistics.TotalCreated);

    if (WkdThread) *WkdThread = thread;   /* 创建临时引用转移给调用方 */
    return STATUS_SUCCESS;

Cleanup:
    if (hThread) ZwClose(hThread);
    PsDereferenceWkdThread(thread);   /* 归零自动销毁 (含 ETHREAD 解引) */
    return status;
}

//
// 移除线程条目
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
CbpUnregistryThread(
    _Inout_ PWKD_PROCESS WkdProcess,
    _In_ HANDLE ThreadId,
    _Out_opt_ PWKD_THREAD* WkdThread
    )
/*++
Routine Description:
    在线程终止时从进程的线程上下文移除对应的线程条目。

    2026-08-25 引用契约重构 — 本函数只做"摘链"，不销毁对象:
      1. 独占锁内定位并 pin (+1, 防摘除-交出间隙归零);
      2. RemoveEntryList — 阻断新的查找/引用获取路径;
      3. 锁外 PsDereferenceWkdThread 归还表引用 (2→1)。
    存活保障由调用方出参持有的 pin 提供; 调用方完成 ALPC
    消息构建后必须 PsDereferenceWkdThread 归还 (1→0 自动销毁)。
    原实现摘链后立即 ExFreePoolWithTag 再把悬空指针交出参,
    导致退出事件构建 UAF + 回调尾部二次释放双重堆损坏。

Arguments:
    Process  — 目标 WKD_PROCESS。
    ThreadId — 要移除的线程 ID。
    RemovedEntry — [可选] 接收被移除的线程条目（持引用 pin）。

Returns:
    STATUS_SUCCESS      — 成功移除
    STATUS_NOT_FOUND    — 未找到对应条目
--*/
{
    PWKD_THREAD_CONTEXT context;
    PLIST_ENTRY entry;
    PWKD_THREAD wkdThread = NULL;
    BOOLEAN found = FALSE;

    if (!WkdProcess || !WkdProcess->ThreadContext || !ThreadId) {
        return STATUS_INVALID_PARAMETER;
    }
    if (WkdThread) *WkdThread = NULL;

    context = WkdProcess->ThreadContext;

    /* ---- Step 1: 共享锁扫描定位并 pin ---- */
    WkdAcquirePushLockShared(&context->Lock);
    entry = context->ThreadHead.Flink;
    while (entry != &context->ThreadHead) {
        wkdThread = CONTAINING_RECORD(entry, WKD_THREAD, Links);
        if (wkdThread->ThreadId == ThreadId) {
            PsReferenceWkdThread(wkdThread);   /* pin: 防并发摘除销毁 */
            found = TRUE;
            break;
        }
        entry = entry->Flink;
    }
    WkdReleasePushLockShared(&context->Lock);
    if (!found) return STATUS_NOT_FOUND;

    /* ---- Step 2: 独占锁内摘链 (阻断新引用获取路径) ---- */
    WkdAcquirePushLockExclusive(&context->Lock);
    RemoveEntryList(&wkdThread->Links);
    WkdReleasePushLockExclusive(&context->Lock);
    InterlockedDecrement(&context->Statistics.ActiveThreads);
    InterlockedIncrement(&context->Statistics.TotalTerminated);

    /* ---- Step 3: 归还表引用 (pin 仍在手, 对象存活) ---- */
    PsDereferenceWkdThread(wkdThread);

    if (WkdThread) *WkdThread = wkdThread;   /* pin 转移给调用方 */
    return STATUS_SUCCESS;
}

//
// 通知 IOA 引擎：统一线程事件（创建/终止，本地/远程通过 Flags 区分）
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
CbpNotifyThreadCreate(
    _In_ const PWKD_THREAD WkdThread,
    _In_ BOOLEAN Create
    )
/*++
Routine Description:
    构造并发送线程创建/终止事件到 IOA 分析引擎。
    统一使用 WkdMessage_ThreadCreated / WkdMessage_ThreadExited 消息类型，
    通过 PWKD_MESSAGE_BODY_THREAD_CREATE.Flags 的 IsRemote 位区分本地/远程线程。

Arguments:
    SourceProcessId — 源进程 ID（创建者进程）。
    TargetProcessId — 目标进程 ID（线程所属进程）。
    ThreadId        — 线程 ID。
    Create          — TRUE 为创建，FALSE 为终止。
--*/
{
    PWKD_MESSAGE wkdMsg;
    PWKD_MESSAGE_BODY_THREAD_CREATE body;

    if (!WkdThread) return STATUS_INVALID_PARAMETER;

    wkdMsg = NtfCreateMessage(
        Create ? WkdMessage_ThreadCreated : WkdMessage_ThreadExited,
        WkdMessage_SourceThreadCallback,
        WkdThread->IsRemote ? WkdMessage_PriorityHigh : WkdMessage_PriorityNormal,
        sizeof(WKD_MESSAGE_BODY_THREAD_CREATE));
    if (!wkdMsg) return STATUS_NO_MEMORY;

    wkdMsg->Header.ThreadId = WkdThread->CreatorThreadId;
    wkdMsg->Header.SourceProcessId = WkdThread->CreatorProcessId;
    wkdMsg->Header.TargetProcessId = WkdThread->ProcessId;

    /*
     * 填充线程事件消息体
     */
    body = WKD_MESSAGE_BODY(wkdMsg, WKD_MESSAGE_BODY_THREAD_CREATE);
    body->ThreadId = WkdThread->ThreadId;
    body->CreatorThreadId = WkdThread->CreatorThreadId;
    body->CreateTime = WkdThread->CreateTime;
    body->StartRoutine = WkdThread->StartRoutine;
    body->DesiredAccess = WkdThread->DesiredAccess;
    body->Argument      = WkdThread->Argument;
    body->CreateFlags   = WkdThread->CreateFlags;
    body->Flags = (WkdThread->IsRemote ? 0x00000001 : 0) |
                       (Create ? 0x00000002 : 0);
    body->ImageBase             = WkdThread->ModuleBase;
    body->MemoryProtection      = WkdThread->MemoryProtection;
    body->CreatorSessionId      = WkdThread->CreatorSessionId;
    body->TargetSessionId       = WkdThread->TargetSessionId;
    //body->InjectIndicators     = WkdThread->InjectIndicators;
    //body->InjectionScore       = WkdThread->InjectionScore;
    //body->RiskLevel            = (ULONG)WkdThread->RiskLevel;

    /*
     * 入口点内存原始字节（供 agent shellcode 模式匹配，对齐 PS TnpCheckShellcodePatterns）
     */
    //body->StartBytesSize = WkdThread->StartBytesSize;
    //if (WkdThread->HasStartBytes && WkdThread->StartBytesSize > 0) {
    //    RtlCopyMemory(body->StartBytes, WkdThread->StartBytes,
    //                  min(WkdThread->StartBytesSize, sizeof(body->StartBytes)));
    //} else {
    //    RtlZeroMemory(body->StartBytes, sizeof(body->StartBytes));
    //}

    /*
     * 起始地址归属结论（IocDetectThread 计算，供 agent IOC 消费）：
     *   IsUnusualEntry  — 入口点未落在已知模块区间
     *   IsStartAddrBacked — 入口地址为 MEM_IMAGE 文件映射
     * agent 侧 IocObserveThread 直接读取，无需重做归属检查。
     */
    body->IsUnusualEntry    = WkdThread->IsUnusualEntry;
    body->IsStartAddrBacked = WkdThread->IsStartAddrBacked;

    AlpcSendWkdMessage(wkdMsg);
    return STATUS_SUCCESS;

    /*
     * 同步/异步双路径:
     *   - 远程线程创建 (IsRemote + Create) 默认检测进程对位图
     *   - 本地线程操作直接异步
     */
    if (WkdThread->IsRemote && Create &&
        PsPairNeedsSync(
            wkdMsg->Header.SourceProcessId,
            wkdMsg->Header.TargetProcessId,
            WkdOp_CreateThread)) {

        /* === 同步路径 === */
        NTSTATUS status;
        WKD_SYNC_REPLY_DATA verdict;
        PWKD_SYNC_REQUEST req;

        status = NtfAcquireSyncRequest(&g_SyncMgr,
            &verdict, sizeof(verdict), &req);
        if (!NT_SUCCESS(status)) {
            NmFreeMessage(wkdMsg);
            // return STATUS_INSUFFICIENT_RESOURCES;
            return;
        }

        wkdMsg->Header.SyncRequestId = req->RequestId;

        /*
         * === 同步 = 异步队列 + 事件等待 === 
         * WKD_MESSAGE 的生命周期由异步队列接管
         */
        NtfSendMessageAsync(wkdMsg);

        /* 阻塞当前线程 (PASSIVE_LEVEL) */
        {
            //LARGE_INTEGER timeout;
            //timeout.QuadPart = -50000000LL;
            status = NtfSyncWait(&g_SyncMgr, req, NULL);
        
            if (status != STATUS_SUCCESS) {
                NtfReleaseSyncRequest(&g_SyncMgr, req);
                // return STATUS_TIMEOUT;
                return;
            }
        }

        NtfReleaseSyncRequest(&g_SyncMgr, req);

        if (verdict.Verdict != WkdSyncVerdict_Allow) {
            // return STATUS_ACCESS_DENIED;
            return;
        }
    } else {
        /* === 异步路径 === */
        NtfSendMessageAsync(wkdMsg);
    }
}

/**************************************************/
/*           线程回调处理函数                      */
/**************************************************/
_Use_decl_annotations_
VOID
CbpThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    )
/*++
Routine Description:
    全局线程创建/终止回调。
    注册方式：PsSetCreateThreadNotifyRoutine。

    负责：
    1. 维护每个 WKD_PROCESS 的线程上下文（添加/移除线程条目）
    2. 检测跨进程线程创建（远程线程注入）
    3. 将相关事件通过 WKD_MESSAGE 发送给 IOA 分析引擎

Arguments:
    ProcessId — 拥有该线程的进程 ID。
    ThreadId  — 线程 ID。
    Create    — TRUE 表示线程创建，FALSE 表示终止。
--*/
{
    NTSTATUS status;
    HANDLE sourceProcessId;
    PWKD_PROCESS sourceWkdProcess = NULL;
    PWKD_PROCESS targetWkdProcess = NULL;
    PWKD_PROCESS registryProcess = NULL;
    BOOLEAN isRemote;
    PWKD_THREAD wkdThread = NULL;

    NT_ASSERT(g_TdState.Initialized);

    //
    // 获取 Rundown 保护，防止模块在回调执行期间被清理
    //
    if (!ExAcquireRundownProtection(&g_TdState.RundownRef)) {
        return;
    }

    //
    // 获取源进程&目标进程 WKD_PROCESS（通常是严重错误!!!）
    //
    sourceProcessId = PsGetCurrentProcessId();
    sourceWkdProcess = PsLookupWkdProcessByProcessId(sourceProcessId);
    if (!sourceWkdProcess) goto Cleanup;
    targetWkdProcess = PsLookupWkdProcessByProcessId(ProcessId);
    if (!sourceWkdProcess) goto Cleanup;

    /* 2026-08-10 恢复：Common\Exempts 重新引入，受信跳过逻辑复原 */
    //
    // 白名单检查：跳过系统进程和 EDR 自身
    //
    if (CoEvaluateProcessExemption(targetWkdProcess, NULL) == ExemptVerdict_Trusted) {
        goto Cleanup;
    }

    isRemote = (ProcessId != sourceProcessId);

    //
    // 确定线程注册的目标进程
    //   - 远程线程：线程属于 ProcessId（目标进程）
    //   - 本地线程：线程属于 sourceProcessId（创建者进程）
    //
    if (isRemote) {
        registryProcess = targetWkdProcess;
    } else {
        registryProcess = sourceWkdProcess;
    }

    if (Create) {
        //
        // === 线程创建 ===
        //
        
        /* 暂定的过滤策略 - 自操作直接放过 */
        if (sourceProcessId == ProcessId) goto Cleanup;

        //
        // 1. 首先：采集线程信息，注册到目标进程的线程上下文
        //
        status = CbpRegistryThread(registryProcess, ThreadId, sourceProcessId,
                                    PsGetCurrentThreadId(), &wkdThread);
        if (!NT_SUCCESS(status)) DbgBreakPoint();

        //
        // 1.5 调用编排器：IOC 检测 + IOA 记录
        //
        /*status = AeOrchestratorDispatch(sourceWkdProcess, targetWkdProcess,
                                        WkdMessage_SourceThreadCallback,
                                        WkdMessage_ThreadCreated,
                                        wkdThread);*/

        //
        // 2. 其次：发送 IOA 线程创建事件
        //    （此时线程信息已在上下文中可用）
        //
        CbpNotifyThreadCreate(wkdThread, TRUE);

        //
        // 2.5 归还创建临时引用 (2026-08-25 引用契约: 出参 pin 用完即还;
        //     表引用仍持有 — 对象随链表存活至线程终止摘除)
        //
        PsDereferenceWkdThread(wkdThread);
        wkdThread = NULL;

        //
        // 3. 远程线程统计计数
        //
        if (isRemote) {
            InterlockedIncrement(
                &registryProcess->ThreadContext->Statistics.RemoteCreated);
        }
    }
    else {
        //
        // === 线程终止 ===
        //
        
        //
        // 1. 首先：移除线程条目（摘链阻断新引用, 出参持 pin 供退出事件采集）
        //
        status = CbpUnregistryThread(registryProcess, ThreadId, &wkdThread);
        if (!NT_SUCCESS(status)) goto Cleanup;   /* 2026-08-25 修复原条件反转 */

        //
        // 2. 采集退出信息（ObDereference ETHREAD 前）
        //
        //if (wkdThread->EThread) {
        //    /* 26100 内核已移除未文档化导出 PsGetThreadExitTime/KeQueryThreadTime
        //        * （ntoskrnl.lib 无对应符号）。退出时间以降级为当前系统时间近似
        //        * （回调于线程退出时执行，误差为毫秒级）；CPU 时间无法获取置 0。
        //        * 注：WKD_MESSAGE_BODY_THREAD_CREATE 仅上送 CreateTime，无消费方。 */
        //    ULONG64 userTime = 0;
        //    ULONG64 kernelTime = 0;

        //    KeQuerySystemTime(&wkdThread->ExitTime);
        //    wkdThread->UserTime.QuadPart = (LONGLONG)userTime;
        //    wkdThread->KernelTime.QuadPart = (LONGLONG)kernelTime;
        //}

        //
        // 3. 发送线程退出事件（CbpNotifyThreadCreate 内 Flags bit0=IsRemote/bit1=Create=0
        //    自动正确；退出事件走异步路径——退出回调不可同步阻塞）
        //
        CbpNotifyThreadCreate(wkdThread, FALSE);

        //
        // 4. 归还借出引用 (2026-08-25 引用契约: 替代原手动
        //    ObDereferenceObject + ExFreePoolWithTag 双重释放 —
        //    Unregistry 已不销毁对象, 销毁统一由 Deref 归零触发)
        //
        PsDereferenceWkdThread(wkdThread);
        wkdThread = NULL;
    }

Cleanup:
    if (targetWkdProcess) {
        PsDereferenceWkdProcess(targetWkdProcess);
    }
    if (sourceWkdProcess) {
        PsDereferenceWkdProcess(sourceWkdProcess);
    }
    ExReleaseRundownProtection(&g_TdState.RundownRef);
}

/**************************************************/
/*          死代码区 — 功能面覆盖                   */
/*                                                  */
/*  对齐 SS Callbacks/Process/ThreadNotify.c        */
/*  以下全部为 static + 不接入活代码链路，仅功能面   */
/*  保留（重功能实现而非源码复制）。                 */
/**************************************************/

#pragma warning(push)
#pragma warning(disable:4505)

//
// 死代码常量（对齐 SS ThreadNotify.h L86-93）
//
#define TN_RAPID_THREAD_WINDOW_100NS    (1000LL * 10000LL)  // 1 秒窗口（100ns 单位）
#define TN_RAPID_THREAD_THRESHOLD       10                  // 窗口内远程线程阈值


//
// 快速线程创建检测（对齐 SS TnpCheckRapidCreation L2766-2811）
// [死代码] 窗口计数：1 秒内 >=10 个远程线程判定为快速创建。
// 不接入原因：agent RA_METRIC_THREAD 频率分析（IoaRateAnalyzer）已覆盖
//   频率维度且更稳健（Z-Score/MAD 统计基线）；本函数为内核硬实时信号
//   保留，供未来同步阻断加分使用。
//
_IRQL_requires_max_(DISPATCH_LEVEL)
static
BOOLEAN
CbpCheckRapidCreation(
    _Inout_ PWKD_THREAD_CONTEXT Context,
    _In_ PLARGE_INTEGER CurrentTime
    )
{
    LARGE_INTEGER windowStart;
    LONG threadsInWindow;

    windowStart.QuadPart = CurrentTime->QuadPart - TN_RAPID_THREAD_WINDOW_100NS;

    if (Context->WindowStart.QuadPart < windowStart.QuadPart ||
        Context->WindowStart.QuadPart == 0) {
        Context->WindowStart = *CurrentTime;
        InterlockedExchange(&Context->RemoteThreadsInWindow, 1);
        return FALSE;
    }

    threadsInWindow = InterlockedIncrement(&Context->RemoteThreadsInWindow);
    return (threadsInWindow >= TN_RAPID_THREAD_THRESHOLD);
}

//
// 线程远程性按需分析（对齐 SS TnIsRemoteThread L3176-3225）
// [死代码] 查线程条目返回 IsRemote/指示器/评分。
// 不接入原因：无消费方；供未来第2层同步阻塞查询（NtCreateRemoteThread 时
//   按需分析目标线程）复用。接入时移除 static。
//
static
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TnIsRemoteThread(
    _In_ HANDLE TargetProcessId,
    _In_ HANDLE ThreadId,
    _Out_ PBOOLEAN IsRemote,
    _Out_opt_ PULONG Indicators,
    _Out_opt_ PULONG Score
    )
{
    PWKD_PROCESS process;
    PWKD_THREAD entry;

    if (!IsRemote) {
        return STATUS_INVALID_PARAMETER;
    }
    *IsRemote = FALSE;
    if (Indicators) *Indicators = 0;
    if (Score) *Score = 0;

    process = PsLookupWkdProcessByProcessId(TargetProcessId);
    if (!process) {
        return STATUS_NOT_FOUND;
    }

    entry = CbLookupWkdThread(process, ThreadId);
    if (!entry) {
        PsDereferenceWkdProcess(process);
        return STATUS_NOT_FOUND;
    }

    *IsRemote = entry->IsRemote;
    /*if (Indicators) *Indicators = entry->InjectIndicators;
    if (Score) *Score = entry->InjectionScore;*/

    PsDereferenceWkdProcess(process);
    return STATUS_SUCCESS;
}

#pragma warning(pop)
