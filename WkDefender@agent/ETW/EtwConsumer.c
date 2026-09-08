/*
 * WkDefender - Enterprise NGAV/EDR Agent Kernel Driver
 *
 * EtwConsumer.c - ETW (Event Tracing for Windows) 消费器（用户态）。
 * ============================================================================
 * 迁移源：ShadowStrike/PhantomCore/Utils/ProcessUtils.cpp
 *         EnableETWProcessTracing / DisableETWProcessTracing / 消费者线程。
 * 迁移日期：2026-09-07
 *
 * 会话生命周期（对齐 SS 框架，C 化）：
 *   Start   : StartTraceW → EnableTraceEx2 → OpenTraceW → CreateThread(ProcessTrace)
 *   Shutdown: CloseTrace（解阻塞）→ 等待线程 → ControlTraceW(STOP)
 *
 * 载荷解析：
 *   UserData = [WKD_MESSAGE_HEADER + WKD_MESSAGE_BODY_*]（单 blob）。
 *   EventId  = WKD_MESSAGE_TYPE 值（Driver ETWProvider 渲染 / 本消费器直解，
 *   与 ALPC 通道同源同构）。Magic/BodySize 双重边界校验后按 Type 分派。
 *
 * 同步设计：
 *   - 状态转换（Start/Shutdown）由主线程串行调用，回调线程不回写状态；
 *     故无需互斥锁（SS std::mutex 对应场景为服务多线程管理，本项目无）。
 *   - Active 用 volatile LONG + Interlocked 访问（轻量、可跨线程观察）；
 *   - Dispatch 钩子指针：主线程单写、ETW 服务线程单读（x64 指针原子读）。
 *
 * 安全注意：
 *   - 回调在 ETW 服务线程同步执行，快进快出；
 *   - BodySize 越界（防变长尾部误用/恶意载荷）一律丢弃；
 *   - 不接编排层（本期），仅内建打印 + 可选分派钩子。
 *
 * Copyright (c) WkDefender Team
 * ============================================================================
 */

#include "EtwConsumer.h"

#include <stdio.h>
#include <stdlib.h>

// ============================================================================
// Provider GUID（本 TU 唯一实例；与 Driver 侧同值）
// ============================================================================

GUID WKD_ETW_PROVIDER_GUID = {
    0x9f2c4d1a, 0x3b6e, 0x4c70,
    {0x9a, 0x8b, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b, 0x6c}
};

// ============================================================================
// 内部常量
// ============================================================================

#define ETW_CONSUMER_STOP_WAIT_MS       5000    /* 消费线程退出最大等待 */
#define ETW_CONSUMER_MAX_PRINT_CHARS    160     /* 诊断消息打印截断 */

// ============================================================================
// 消费器全局状态
// ============================================================================

typedef struct _ETW_CONSUMER_STATE {
    volatile LONG           Active;         /* 0=停止 1=运行（Interlocked） */
    TRACEHANDLE             SessionHandle;  /* StartTraceW 会话句柄 */
    TRACEHANDLE             ConsumerHandle; /* OpenTraceW 消费句柄 */
    HANDLE                  ConsumerThread; /* ProcessTrace 阻塞线程 */
    ETW_DISPATCH_CALLBACK   Dispatch;       /* 分派钩子（NULL=内建打印） */
} ETW_CONSUMER_STATE;

static ETW_CONSUMER_STATE g_EtwConsumer;

// ============================================================================
// 内部函数 — 消费线程 / 事件回调
// ============================================================================

/*++

Routine Description:

    ETW 事件记录回调。在 ETW 服务线程内同步执行。

    载荷结构校验：
      Driver ETWProvider 渲染载荷 = [WKD_MESSAGE_HEADER + Body] 单 blob
      （EtwWriteWkdMessage 统一 blit）。此处反序列化同构校验：
        - UserData 长度 >= sizeof(WKD_MESSAGE_HEADER)
        - Header.Magic == WKD_NOTIFICATION_MAGIC
        - Header.BodySize <= UserData 剩余（防越界/变长尾部误用）

    校验通过后按 Type 分派：内建打印诊断事件（0x41xx 段），其余类型
    打印概要；若已注册 Dispatch 钩子则交钩子处理（不接编排层，扩展点）。

--*/
static VOID WINAPI
EtwpEventRecordCallback(
    _In_ PEVENT_RECORD EventRecord
    )
{
    PWKD_MESSAGE_HEADER header;
    PUCHAR body;
    ULONG headerSize;
    ETW_DISPATCH_CALLBACK dispatch;

    if (EventRecord == NULL) {
        return;
    }

    /* 1. 最小长度校验 */
    headerSize = (ULONG)sizeof(WKD_MESSAGE_HEADER);
    if ((ULONG)EventRecord->UserDataLength < headerSize ||
        EventRecord->UserData == NULL) {
        return;
    }

    header = (PWKD_MESSAGE_HEADER)EventRecord->UserData;

    /* 2. Magic 校验（协议层） */
    if (header->Magic != WKD_NOTIFICATION_MAGIC) {
        return;
    }

    /* 3. BodySize 边界校验（防变长尾部越界/恶意载荷） */
    if ((ULONG)header->BodySize > (ULONG)EventRecord->UserDataLength - headerSize) {
        return;
    }

    body = (PUCHAR)header + headerSize;

    /* 4. 分派：优先扩展钩子，否则内建打印消费者 */
    dispatch = g_EtwConsumer.Dispatch;
    if (dispatch != NULL) {
        dispatch(header, body, (ULONG)header->BodySize);
        return;
    }

    /* 5. 内建打印消费者：概要 + 诊断事件详情（定长 Body 视图） */
    printf("[ETW] Type=0x%04X BodySize=%lu SrcPid=%p TgtPid=%p Time=%lld\n",
        (ULONG)header->Type,
        (ULONG)header->BodySize,
        header->SourceProcessId,
        header->TargetProcessId,
        header->Timestamp.QuadPart);

    /* 诊断段（0x41xx）：打印组件名与消息 */
    if (header->Type >= WkdMessage_DriverStarted &&
        header->Type <= WkdMessage_DriverError &&
        (ULONG)header->BodySize >= sizeof(WKD_MESSAGE_BODY_DIAGNOSTIC_EVENT)) {
        PWKD_MESSAGE_BODY_DIAGNOSTIC_EVENT diag =
            (PWKD_MESSAGE_BODY_DIAGNOSTIC_EVENT)body;

        /* 有界宽字符打印（截断防超长） */
        printf("[ETW]   Component=%ls Msg=%.*ls (Sev=%lu Err=0x%lX)\n",
            diag->ComponentName,
            ETW_CONSUMER_MAX_PRINT_CHARS,
            diag->Message,
            diag->Severity,
            diag->ErrorCode);
    }
}

/*++

Routine Description:

    ETW 消费者线程。阻塞于 ProcessTrace，由 CloseTrace 解阻塞退出。

--*/
static DWORD WINAPI
EtwpConsumerThreadProc(
    _In_ LPVOID Parameter
    )
{
    TRACEHANDLE consumerHandle;
    ULONG status;

    UNREFERENCED_PARAMETER(Parameter);

    consumerHandle = g_EtwConsumer.ConsumerHandle;
    if (consumerHandle == 0) {
        return 0;
    }

    /* 阻塞处理实时事件；CloseTrace 后返回 ERROR_CTX_CLOSE_PENDING 或成功。 */
    status = ProcessTrace(&consumerHandle, 1, NULL, NULL);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED &&
        status != ERROR_CTX_CLOSE_PENDING) {
        printf("[ETW] ProcessTrace exited: 0x%lX\n", status);
    }

    return 0;
}

// ============================================================================
// 内部函数 — 会话构建辅助
// ============================================================================

/*++

Routine Description:

    构造 EVENT_TRACE_PROPERTIES 缓冲（会话名内嵌，供 StartTraceW /
    ControlTraceW 复用）。

--*/
static ULONG
EtwpBuildTraceProperties(
    _Out_ PEVENT_TRACE_PROPERTIES *OutProperties,
    _Out_ PVOID *OutBuffer
    )
{
    /* 会话名容纳（宽字符，含终止符） */
    SIZE_T nameChars = (wcslen(WKD_ETW_SESSION_NAME) + 1);
    ULONG bufferSize = (ULONG)(sizeof(EVENT_TRACE_PROPERTIES) +
                               nameChars * sizeof(wchar_t));
    PEVENT_TRACE_PROPERTIES properties;
    PVOID buffer;

    buffer = calloc(1, bufferSize);
    if (buffer == NULL) {
        *OutProperties = NULL;
        *OutBuffer = NULL;
        return ERROR_OUTOFMEMORY;
    }

    properties = (PEVENT_TRACE_PROPERTIES)buffer;
    properties->Wnode.BufferSize = bufferSize;
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 1;            /* QPC 时间戳 */
    properties->Wnode.Guid = WKD_ETW_PROVIDER_GUID;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->MaximumFileSize = 0;                /* 无文件日志 */
    properties->FlushTimer = WKD_ETW_FLUSH_TIMER_SEC;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    wcscpy_s(
        (wchar_t*)((PUCHAR)buffer + properties->LoggerNameOffset),
        nameChars,                                   /* 目标缓冲元素数 */
        WKD_ETW_SESSION_NAME);

    *OutProperties = properties;
    *OutBuffer = buffer;
    return ERROR_SUCCESS;
}

// ============================================================================
// 公共 API
// ============================================================================

/*++

Routine Description:

    初始化消费器（幂等）。复位内部状态（含已注册分派回调）。
    可安全重复调用。

--*/
_Use_decl_annotations_
NTSTATUS
EtwConsumer_Initialize(
    VOID
    )
{
    g_EtwConsumer.Active = 0;
    g_EtwConsumer.SessionHandle = 0;
    g_EtwConsumer.ConsumerHandle = 0;
    g_EtwConsumer.ConsumerThread = NULL;
    g_EtwConsumer.Dispatch = NULL;

    return STATUS_SUCCESS;
}

/*++

Routine Description:

    启动 WkDefender ETW 实时消费会话。

    流程（对齐 SS EnableETWProcessTracing，C 化）：
      1. StartTraceW（ERROR_ALREADY_EXISTS 时先停旧会话再重建）
      2. EnableTraceEx2（全关键字 + TRACE_LEVEL_VERBOSE）
      3. OpenTraceW（REAL_TIME | EVENT_RECORD，EventRecordCallback）
      4. CreateThread → ProcessTrace 阻塞消费

    任一步失败：逐级清理已获取资源（不残留会话/句柄），返回对应错误。

    Return Value:

        STATUS_SUCCESS              成功。
        STATUS_ACCESS_DENIED        权限不足（需以管理员运行 Agent）。
        STATUS_INSUFFICIENT_RESOURCES 内存/线程资源不足。
        其他 NTSTATUS               底层组件失败码。

--*/
_Use_decl_annotations_
NTSTATUS
EtwConsumer_Start(
    VOID
    )
{
    NTSTATUS status;
    ULONG winStatus;
    PEVENT_TRACE_PROPERTIES properties;
    PVOID buffer;
    TRACEHANDLE sessionHandle;
    EVENT_TRACE_LOGFILEW logFile;
    TRACEHANDLE consumerHandle;
    HANDLE thread;

    if (InterlockedCompareExchange(&g_EtwConsumer.Active, 1, 0) != 0) {
        return STATUS_SUCCESS;      /* 已启动，幂等 */
    }

    /* 1. 构造会话属性 */
    winStatus = EtwpBuildTraceProperties(&properties, &buffer);
    if (winStatus != ERROR_SUCCESS) {
        InterlockedExchange(&g_EtwConsumer.Active, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* 2. 启动实时会话 */
    sessionHandle = 0;
    winStatus = StartTraceW(&sessionHandle, WKD_ETW_SESSION_NAME, properties);

    if (winStatus == ERROR_ALREADY_EXISTS) {
        /* 停掉旧会话（残留会话），短暂等待后重建 */
        (VOID)ControlTraceW(0, WKD_ETW_SESSION_NAME, properties,
            EVENT_TRACE_CONTROL_STOP);
        Sleep(500);
        sessionHandle = 0;
        winStatus = StartTraceW(&sessionHandle, WKD_ETW_SESSION_NAME, properties);
    }

    if (winStatus != ERROR_SUCCESS) {
        printf("[ETW] StartTraceW failed: 0x%lX (需管理员权限)\n", winStatus);
        free(buffer);
        InterlockedExchange(&g_EtwConsumer.Active, 0);
        return (winStatus == ERROR_ACCESS_DENIED)
                   ? STATUS_ACCESS_DENIED
                   : STATUS_UNSUCCESSFUL;
    }

    g_EtwConsumer.SessionHandle = sessionHandle;

    /* 3. 使能 Provider（全关键字 + VERBOSE，对齐 Level/Keywords 过滤） */
    winStatus = EnableTraceEx2(
        sessionHandle,
        &WKD_ETW_PROVIDER_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        (ULONGLONG)-1,          /* MatchAnyKeyword：全开 */
        (ULONGLONG)-1,          /* MatchAllKeyword */
        0,                      /* Timeout：立即 */
        NULL                    /* EnableTraceParameters */
        );

    if (winStatus != ERROR_SUCCESS) {
        printf("[ETW] EnableTraceEx2 failed: 0x%lX\n", winStatus);
        (VOID)ControlTraceW(sessionHandle, NULL, properties,
            EVENT_TRACE_CONTROL_STOP);
        g_EtwConsumer.SessionHandle = 0;
        free(buffer);
        InterlockedExchange(&g_EtwConsumer.Active, 0);
        return STATUS_UNSUCCESSFUL;
    }

    /* 4. 打开实时消费通道 */
    ZeroMemory(&logFile, sizeof(logFile));
    logFile.LoggerName = (LPWSTR)WKD_ETW_SESSION_NAME;
    logFile.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EtwpEventRecordCallback;

    consumerHandle = OpenTraceW(&logFile);
    if (consumerHandle == INVALID_PROCESSTRACE_HANDLE) {
        winStatus = GetLastError();
        printf("[ETW] OpenTraceW failed: 0x%lX\n", winStatus);
        (VOID)ControlTraceW(sessionHandle, NULL, properties,
            EVENT_TRACE_CONTROL_STOP);
        g_EtwConsumer.SessionHandle = 0;
        free(buffer);
        InterlockedExchange(&g_EtwConsumer.Active, 0);
        return STATUS_UNSUCCESSFUL;
    }

    g_EtwConsumer.ConsumerHandle = consumerHandle;

    /* 5. 创建消费者线程（ProcessTrace 阻塞） */
    thread = CreateThread(NULL, 0, EtwpConsumerThreadProc, NULL, 0, NULL);
    if (thread == NULL) {
        printf("[ETW] CreateThread failed: %lu\n", GetLastError());
        (VOID)CloseTrace(consumerHandle);
        (VOID)ControlTraceW(sessionHandle, NULL, properties,
            EVENT_TRACE_CONTROL_STOP);
        g_EtwConsumer.SessionHandle = 0;
        g_EtwConsumer.ConsumerHandle = 0;
        free(buffer);
        InterlockedExchange(&g_EtwConsumer.Active, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_EtwConsumer.ConsumerThread = thread;

    free(buffer);

    printf("[ETW] Consumer started (session %ls, provider %08lX-%04lX)\n",
        WKD_ETW_SESSION_NAME,
        WKD_ETW_PROVIDER_GUID.Data1,
        WKD_ETW_PROVIDER_GUID.Data2);

    return STATUS_SUCCESS;
}

/*++

Routine Description:

    停止 ETW 实时消费会话。

    停止序列（对齐 SS DisableETWProcessTracing）：
      1. CloseTrace(consumerHandle) → 解阻塞 ProcessTrace
      2. 等待消费者线程退出（有界等待）
      3. ControlTraceW(EVENT_TRACE_CONTROL_STOP)

    幂等；未启动时直接返回。

--*/
_Use_decl_annotations_
VOID
EtwConsumer_Shutdown(
    VOID
    )
{
    TRACEHANDLE sessionHandle;
    TRACEHANDLE consumerHandle;
    HANDLE thread;
    PEVENT_TRACE_PROPERTIES properties;
    PVOID buffer;

    if (InterlockedExchange(&g_EtwConsumer.Active, 0) == 0) {
        return;                 /* 未启动，幂等 */
    }

    consumerHandle = g_EtwConsumer.ConsumerHandle;
    sessionHandle = g_EtwConsumer.SessionHandle;
    thread = g_EtwConsumer.ConsumerThread;

    /* 1. 解阻塞 ProcessTrace */
    if (consumerHandle != 0) {
        (VOID)CloseTrace(consumerHandle);
        g_EtwConsumer.ConsumerHandle = 0;
    }

    /* 2. 等待消费者线程退出 */
    if (thread != NULL) {
        WaitForSingleObject(thread, ETW_CONSUMER_STOP_WAIT_MS);
        CloseHandle(thread);
        g_EtwConsumer.ConsumerThread = NULL;
    }

    /* 3. 停止会话 */
    if (sessionHandle != 0 &&
        EtwpBuildTraceProperties(&properties, &buffer) == ERROR_SUCCESS) {
        (VOID)ControlTraceW(sessionHandle, WKD_ETW_SESSION_NAME, properties,
            EVENT_TRACE_CONTROL_STOP);
        free(buffer);
        g_EtwConsumer.SessionHandle = 0;
    }

    printf("[ETW] Consumer stopped\n");

    /* 复位分派钩子（下次 Start 回到内建打印基线） */
    g_EtwConsumer.Dispatch = NULL;
}

/*++

Routine Description:

    查询消费器是否活跃（Interlocked 读）。

--*/
_Use_decl_annotations_
BOOLEAN
EtwConsumer_IsActive(
    VOID
    )
{
    return (g_EtwConsumer.Active != 0) ? TRUE : FALSE;
}

/*++

Routine Description:

    注册 WKD_MESSAGE 分派回调（下一阶段接编排层的扩展点）。
    传 NULL 恢复内建打印消费者。

--*/
_Use_decl_annotations_
VOID
EtwConsumer_SetDispatchCallback(
    _In_opt_ ETW_DISPATCH_CALLBACK Callback
    )
{
    g_EtwConsumer.Dispatch = Callback;
}