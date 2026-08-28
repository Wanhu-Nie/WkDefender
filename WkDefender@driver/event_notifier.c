#include "event_notifier.h"
#include "notification_manager.h"

// 确保ALPC函数指针在EventNotifier.c中可用
extern pfnNtAlpcConnectPort WkAlpcConnectPort;
extern pfnNtAlpcSendWaitReceivePort WkAlpcSendWaitReceivePort;

// 外部全局ALPC服务器实例
extern ALPC_SERVER g_AlpcServer;

// 声明ZwQueryInformationProcess函数
NTSTATUS ZwQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

/*
 * 事件通知模块实现
 * 功能：实现Driver向Agent发送进程/线程事件通知
 * 作者：WkDefender Team
 * 日期：2026-04-09
 */

// 全局事件通知管理器
static EVENT_NOTIFIER g_EventNotifier = { 0 };

// Agent端口名称
static UNICODE_STRING g_AgentPortName = RTL_CONSTANT_STRING(L"\\RPC Control\\WkDefender@Agent");

// 初始化事件通知管理器
NTSTATUS InitializeEventNotifier()
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> Initializing event notifier...\n", __FUNCTION__);

    // 初始化同步锁
    ExInitializeFastMutex(&g_EventNotifier.Lock);

    // 初始化统计信息
    g_EventNotifier.TotalEventsSent = 0;
    g_EventNotifier.FailedEvents = 0;
    g_EventNotifier.IsConnected = FALSE;
    g_EventNotifier.AgentPort = NULL;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> Event notifier initialized\n", __FUNCTION__);
    return STATUS_SUCCESS;
}

// 清理事件通知管理器
VOID CleanupEventNotifier()
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> Cleaning up event notifier...\n", __FUNCTION__);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> Event notifier cleanup completed. Total events: %u, Failed: %u\n",
        __FUNCTION__, g_EventNotifier.TotalEventsSent, g_EventNotifier.FailedEvents);
}



// EventNotifier 通用接口
NTSTATUS EventNotifier_SendNotification(
    _In_ WKDEFENDER_EVENT_TYPE EventType,
    _In_ PVOID Event,
    _In_ ULONG EventSize
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    // 参数检查
    if (Event == NULL || EventSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 发送事件通知
    status = AlpcServer_SendNotification(
        Event,
        EventSize,
        EVENT_TYPE_TO_MESSAGE_TYPE(EventType),
        0,
        0,
        1
    );

    if (NT_SUCCESS(status)) {
        InterlockedIncrement((PLONG)&g_EventNotifier.TotalEventsSent);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> Event sent successfully (Type: %u)\n", __FUNCTION__, EventType);
    } else {
        InterlockedIncrement((PLONG)&g_EventNotifier.FailedEvents);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> Failed to send event: 0x%X\n", __FUNCTION__, status);
    }

    return status;
}

// 发送进程创建事件通知
NTSTATUS NotifyProcessCreate(
    _In_ PEPROCESS Process, 
    _In_ HANDLE ProcessId, 
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    NTSTATUS status;
    ULONG image_file_name_length, command_line_length, event_size;     // 需要动态申请的包大小
    PPROCESS_CREATE_EVENT event = NULL;
    PUCHAR data_ptr;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> Notifying process create (PID: %u)\n", __FUNCTION__, HandleToUlong(ProcessId));

    // 计算动态数据大小
    image_file_name_length = 0;
    command_line_length = 0;
    
    if (CreateInfo->ImageFileName != NULL) {
        image_file_name_length = CreateInfo->ImageFileName->Length + sizeof(WCHAR); // 包含终止符
    }
    if (CreateInfo->CommandLine != NULL) {
        command_line_length = CreateInfo->CommandLine->Length + sizeof(WCHAR); // 包含终止符
    }

    // 更新package大小
    event_size = sizeof(PROCESS_CREATE_EVENT) + image_file_name_length + command_line_length;
    if (event_size < sizeof(PROCESS_CREATE_EVENT))
        event_size = sizeof(PROCESS_CREATE_EVENT);

    // 分配内存
    event = (PPROCESS_CREATE_EVENT)ExAllocatePoolWithTag(NonPagedPool, event_size, 'even');
    if (!event) {
        return STATUS_NO_MEMORY;
    }

    // 初始化事件数据结构
    memset(event, 0, event_size);
    event->ProcessId = ProcessId;
    event->ParentProcessId = CreateInfo->ParentProcessId;
    data_ptr = (PUCHAR)(event + 1);

    // 复制映像文件名
    if (CreateInfo->ImageFileName != NULL) {
        event->ImageFileName.Length = image_file_name_length;
        event->ImageFileName.Offset = (ULONG)(data_ptr - (PUCHAR)event);
        memcpy(data_ptr, CreateInfo->ImageFileName->Buffer, image_file_name_length);
        data_ptr += image_file_name_length;
    }

    // 复制命令行
    if (CreateInfo->CommandLine != NULL) {
        event->CommandLine.Length = command_line_length;
        event->CommandLine.Offset = (ULONG)(data_ptr - (PUCHAR)event);
        memcpy(data_ptr, CreateInfo->CommandLine->Buffer, command_line_length);
        data_ptr += command_line_length;
    }

    // 发送事件
    status = EventNotifier_SendNotification(EVENT_TYPE_PROCESS_CREATE, event, event_size);

    // 释放内存
    if (event) {
        ExFreePoolWithTag(event, 'even');
    }

    return status;
}

// 发送进程退出事件通知
NTSTATUS NotifyProcessExit(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId
)
{
    PROCESS_EXIT_EVENT event;
    NTSTATUS status;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> Notifying process exit (PID: %u)\n", __FUNCTION__, HandleToUlong(ProcessId));

    // 初始化事件数据结构
    memset(&event, 0, sizeof(PROCESS_EXIT_EVENT));
    event.ProcessId = HandleToUlong(ProcessId);
    event.ExitCode = 0; // 需要从进程结构获取
    KeQuerySystemTime(&event.ExitTime);

    // 发送事件
    status = EventNotifier_SendNotification(EVENT_TYPE_PROCESS_EXIT, &event, sizeof(PROCESS_EXIT_EVENT));

    return status;
}

// 发送线程创建事件通知（预留接口）
NTSTATUS NotifyThreadCreate(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ PVOID StartAddress
)
{
    THREAD_CREATE_EVENT event;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> Notifying thread create (PID: %u, TID: %u)\n",
        __FUNCTION__, HandleToUlong(ProcessId), HandleToUlong(ThreadId));

    memset(&event, 0, sizeof(THREAD_CREATE_EVENT));
    event.ProcessId = HandleToUlong(ProcessId);
    event.ThreadId = HandleToUlong(ThreadId);
    event.StartAddress = (ULONG)(ULONG64)StartAddress;
    KeQuerySystemTime(&event.CreateTime);

    return EventNotifier_SendNotification(EVENT_TYPE_THREAD_CREATE, &event, sizeof(THREAD_CREATE_EVENT));
}

// 发送线程退出事件通知（预留接口）
NTSTATUS NotifyThreadExit(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ NTSTATUS ExitStatus
)
{
    THREAD_EXIT_EVENT event;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> Notifying thread exit (PID: %u, TID: %u)\n",
        __FUNCTION__, HandleToUlong(ProcessId), HandleToUlong(ThreadId));

    memset(&event, 0, sizeof(THREAD_EXIT_EVENT));
    event.ProcessId = HandleToUlong(ProcessId);
    event.ThreadId = HandleToUlong(ThreadId);
    event.ExitCode = (ULONG)ExitStatus;
    KeQuerySystemTime(&event.ExitTime);

    return EventNotifier_SendNotification(EVENT_TYPE_THREAD_EXIT, &event, sizeof(THREAD_EXIT_EVENT));
}

// 发送API调用事件通知（预留接口）
NTSTATUS NotifyApiCall(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ ULONG ApiId,
    _In_ PCHAR ApiName,
    _In_ PVOID Parameters,
    _In_ ULONG ParameterSize
)
{
    API_CALL_EVENT event;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] %s ==> Notifying API call (PID: %u, API: %s)\n",
        __FUNCTION__, HandleToUlong(ProcessId), ApiName ? ApiName : "Unknown");

    memset(&event, 0, sizeof(API_CALL_EVENT));
    event.ProcessId = HandleToUlong(ProcessId);
    event.ThreadId = HandleToUlong(ThreadId);
    event.ApiId = ApiId;
    event.ParameterCount = 0; // 根据实际参数设置
    KeQuerySystemTime(&event.CallTime);

    if (ApiName != NULL) {
        ANSI_STRING ansiApiName;
        RtlInitAnsiString(&ansiApiName, ApiName);
        RtlAnsiStringToUnicodeString(
            &(UNICODE_STRING){0, sizeof(event.ApiName), event.ApiName},
            &ansiApiName,
            FALSE
        );
    }

    if (Parameters != NULL && ParameterSize > 0) {
        ULONG copySize = min(ParameterSize, sizeof(event.Parameters));
        memcpy(event.Parameters, Parameters, copySize);
    }

    return EventNotifier_SendNotification(EVENT_TYPE_API_CALL, &event, sizeof(API_CALL_EVENT));
}

// 获取事件通知统计信息
VOID GetEventNotifierStats(
    _Out_ PULONG TotalEvents,
    _Out_ PULONG FailedEvents
)
{
    if (TotalEvents != NULL) {
        *TotalEvents = g_EventNotifier.TotalEventsSent;
    }
    if (FailedEvents != NULL) {
        *FailedEvents = g_EventNotifier.FailedEvents;
    }
}

// 检查是否已连接到Agent
BOOLEAN IsAgentConnected()
{
    return g_EventNotifier.IsConnected && g_EventNotifier.AgentPort != NULL;
}

// 发送事件通知到Agent（通用接口）
NTSTATUS SendEventToAgent(
    _In_ ULONG EventType,
    _In_ PVOID EventData,
    _In_ ULONG EventDataSize
)
{
    return EventNotifier_SendNotification(EventType, EventData, EventDataSize);
}
