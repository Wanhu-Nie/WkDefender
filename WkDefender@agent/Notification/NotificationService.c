#include "NotificationService.h"
#include <wtsapi32.h>
#include <securitybaseapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>
#include "msg_queue.h"
#include "../process_manager.h"
#include "../log_manager.h"
#include "../system_manager.h"

// 声明全局Agent上下文
extern WKDEFENDER_AGENT WkDefenderAgent;

// 声明全局管理器实例
extern PROCESS_MANAGER g_ProcessManager;
extern LOG_MANAGER g_LogManager;
extern SYSTEM_MANAGER g_SystemManager;
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "advapi32.lib")

// 固定管道名称
#define FIXED_PIPE_NAME "WkDefender_Notification_Service"
#define WKD_DEFAULT_AlpcServer     L"\\RPC Control\\WkDefender@Agent"

NOTIFICATION_SERVICE WkdNotificationService;

// 初始化通知服务
NTSTATUS 
NtfInitializeService(
    VOID
    )
{
    NTSTATUS status;

    printf("[NotificationService] Initializing service...\n");

    /* 1. 创建默认 ALPC 服务器 */
    status = AlpcCreateServer(&WkdDefaultAlpcServer, WKD_DEFAULT_AlpcServer);
    if (!NT_SUCCESS(status)) {
        printf("[NotificationService] Default ALPC server init failed: 0x%X\n", status);
        return status;
    }

    /* 2. 引用 ALPC 服务器 */
    WkdNotificationService.AlpcServer = &WkdDefaultAlpcServer;

    /* 3. 初始化临界区 */
    InitializeCriticalSection(&WkdNotificationService.Lock);

    /* 4. 创建管道服务器 */
    //WkdNotificationService.PipeServer = PipeCreateServer(FIXED_PIPE_NAME);
    //if (!WkdNotificationService.PipeServer) {
    //    DeleteCriticalSection(&WkdNotificationService.Lock);
    //    WkdAlpcCleanup(&WkdDefaultAlpcServer);
    //    return STATUS_NO_MEMORY;
    //}

    /* 5. 初始化消息队列（不启动线程，StartAllModules 阶段统一启动） */
    status = NtfInitializeMessageQueueMessageQueue(&WkdNotificationService.MessageQueue, WKD_MSG_QUEUE_MAX_SIZE, NULL, WkdNotificationService.AlpcServer);
    if (!NT_SUCCESS(status)) {
        printf("[NotificationService] Failed to initialize message queue: 0x%X\n", status);
        PipeServer_Close(WkdNotificationService.PipeServer);
        DeleteCriticalSection(&WkdNotificationService.Lock);
        WkdAlpcCleanup(&WkdDefaultAlpcServer);
        return status;
    }

    WkdNotificationService.helper_process = NULL;
    WkdNotificationService.Initialized = TRUE;

    printf("[NotificationService] Service Initialized successfully\n");
    return STATUS_SUCCESS;
}

// 清理通知管理器资源
VOID NotificationManager_Cleanup(
    PNOTIFICATION_SERVICE Manager
)
{
    if (!Manager || !Manager->Initialized) {
        return;
    }

    // 停止通知管理器 (内部已做同步：停止 Pipe + ALPC Worker)
    NotificationManager_Stop(Manager);

    // 清理消息队列
    WkdMsgQueueStopProcessing(&Manager->MessageQueue);
    WkdMsgQueueCleanup(&Manager->MessageQueue);

    // 清理管道服务器
    if (Manager->PipeServer) {
        PipeServer_Close(Manager->PipeServer);
        Manager->PipeServer = NULL;
    }

    // 清理 ALPC 服务器（AlpcService 是 NotificationService 的子组件）
    if (Manager->AlpcServer) {
        WkdAlpcCleanup(Manager->AlpcServer);
        Manager->AlpcServer = NULL;
    }

    // 清理Helper进程
    if (Manager->helper_process) {
        CloseHandle(Manager->helper_process);
        Manager->helper_process = NULL;
    }

    // 清理临界区
    DeleteCriticalSection(&Manager->Lock);

    Manager->Initialized = FALSE;

    printf("[NotificationService] Cleanup completed\n");
}

// 启动通知管理器
NTSTATUS 
NtfStartService(
    PNOTIFICATION_SERVICE Service
    )
{
    NTSTATUS status;

    if (!Service || !Service->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    EnterCriticalSection(&Service->Lock);

    /* 1. 启动 ALPC Worker（接收消息并路由到各模块消息队列） */
    status = AlpcStartServer(Service->AlpcServer);
    if (!NT_SUCCESS(status)) {
        LeaveCriticalSection(&Service->Lock);
        printf("[NotificationService] ALPC server start failed: 0x%X\n", status);
        return status;
    }

    /* 2. 启动管道服务器 */
    //if (!PipeServer_Start(Service->PipeServer)) {
    //    WkdAlpcStopServer(Service->AlpcServer);
    //    LeaveCriticalSection(&Service->Lock);
    //    return STATUS_UNSUCCESSFUL;
    //}

    LeaveCriticalSection(&Service->Lock);

    printf("[NotificationService] Started successfully (ALPC + Pipe)\n");
    return STATUS_SUCCESS;
}

// 停止通知管理器
NTSTATUS 
NotificationManager_Stop(
    PNOTIFICATION_SERVICE Service
    )
{
    if (!Service || !Service->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    EnterCriticalSection(&Service->Lock);

    /* 1. 停止管道服务器 */
    if (Service->PipeServer) {
        PipeServer_Stop(Service->PipeServer);
    }

    /* 2. 停止 ALPC Worker（如果未启动，WkdAlpcStopServer 会返回错误，忽略） */
    if (Service->AlpcServer) {
        WkdAlpcStopServer(Service->AlpcServer);
    }

    /* 3. 清理Helper进程 */
    if (Service->helper_process) {
        CloseHandle(Service->helper_process);
        Service->helper_process = NULL;
    }

    LeaveCriticalSection(&Service->Lock);

    printf("[NotificationService] Stopped\n");
    return STATUS_SUCCESS;
}

// 检查UI状态
BOOL NotificationManager_CheckUIStatus(
    PNOTIFICATION_SERVICE Manager
)
{
    if (!Manager || !Manager->Initialized || !Manager->AlpcServer) {
        return FALSE;
    }
    
    return WkdAlpcIsUiConnected(Manager->AlpcServer);
}

// 通过ALPC向UI发送通知
NTSTATUS NotificationManager_SendNotificationToUI(
    PNOTIFICATION_SERVICE Manager,
    WKDEFENDER_NOTIFICATION_DATA* pNotification
)
{
    if (!Manager || !Manager->Initialized || !Manager->AlpcServer || !pNotification) {
        return STATUS_INVALID_PARAMETER;
    }
    
    return WkdAlpcSendToUi(
        Manager->AlpcServer,
        WkdAlpcMsg_SecurityNotification,
        pNotification,
        sizeof(WKDEFENDER_NOTIFICATION_DATA)
    );
}

// 通过Helper发送Toast通知
NTSTATUS NotificationManager_SendNotificationWithHelper(
    PNOTIFICATION_SERVICE Manager,
    WKDEFENDER_NOTIFICATION_DATA* pNotification
)
{
    if (!Manager || !Manager->Initialized || !Manager->PipeServer || !pNotification) {
        return STATUS_INVALID_PARAMETER;
    }
    
    EnterCriticalSection(&Manager->Lock);
    
    // 1. 检查Helper是否运行，如未运行则启动
    //if (!PipeServer_IsHelperRunning(Manager->helper_process)) {
    //    wchar_t helper_path[MAX_PATH] = L"E:\Downloads\code\WkDefender\WkDefender@NotifierHelper\bin\Release\net8.0-windows10.0.26100.0\publish\WkDefender@NotifierHelper.exe";
    //    if (!PipeServer_StartResidentHelper(helper_path, &Manager->helper_process)) {
    //        LeaveCriticalSection(&Manager->Lock);
    //        return STATUS_UNSUCCESSFUL;
    //    }
    //}
    
    // 2. 构建JSON格式的通知请求
    // 转换宽字符为多字节字符
    char title[256] = {0};
    char message[512] = {0};
    WideCharToMultiByte(CP_UTF8, 0, pNotification->title, -1, title, sizeof(title), NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, pNotification->message, -1, message, sizeof(message), NULL, NULL);
    
    // 构建JSON字符串
    char json[2048] = {0};
    int json_pos = 0;
    
    // 开始JSON对象
    json_pos += snprintf(json + json_pos, sizeof(json) - json_pos, "{\"Type\":1,\"Data\":{\"Title\":\"%s\",\"Body\":\"%s\",\"Buttons\":[", title, message);
    
    // 添加按钮
    if (wcslen(pNotification->actionButton) > 0 && wcslen(pNotification->actionCommand) > 0) {
        char button_text[64] = {0};
        char button_action[64] = {0};
        char button_args[256] = {0};
        
        WideCharToMultiByte(CP_UTF8, 0, pNotification->actionButton, -1, button_text, sizeof(button_text), NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, pNotification->actionCommand, -1, button_args, sizeof(button_args), NULL, NULL);
        
        // 提取 action
        char* action_start = strstr(button_args, "action:");
        if (action_start) {
            action_start += 7; // 跳过 "action:"
            char* action_end = strchr(action_start, '&');
            if (action_end) {
                strncpy_s(button_action, sizeof(button_action), action_start, action_end - action_start);
            } else {
                strcpy_s(button_action, sizeof(button_action), action_start);
            }
        } else {
            strcpy_s(button_action, sizeof(button_action), "default");
        }
        
        // 添加按钮到JSON
        json_pos += snprintf(json + json_pos, sizeof(json) - json_pos, "{\"Text\":\"%s\",\"Action\":\"%s\",\"Arguments\":\"%s\"}", button_text, button_action, button_args);
    }
    
    // 结束JSON对象
    json_pos += snprintf(json + json_pos, sizeof(json) - json_pos, "]}}");
    
    // 3. 发送JSON格式的通知请求
    NOTIFY_MESSAGE notify_message;
    notify_message.type = NOTIFY_MSG_REQUEST;
    notify_message.length = (size_t)json_pos;
    memcpy(notify_message.data, json, json_pos);
    
    BOOL result = PipeServer_SendMessage(Manager->PipeServer, &notify_message);
    
    LeaveCriticalSection(&Manager->Lock);
    
    return result ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

// 发送通知（根据UI状态选择通知方式）
NTSTATUS NotificationManager_SendNotification(
    PNOTIFICATION_SERVICE Manager,
    WKDEFENDER_NOTIFICATION_TYPE type,
    const wchar_t* title,
    const wchar_t* message,
    const wchar_t* actionButton,
    const wchar_t* actionCommand
)
{
    if (!Manager || !Manager->Initialized || !title || !message) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 构造通知数据
    WKDEFENDER_NOTIFICATION_DATA notification = {0};
    notification.type = type;
    wcscpy_s(notification.title, sizeof(notification.title) / sizeof(wchar_t), title);
    wcscpy_s(notification.message, sizeof(notification.message) / sizeof(wchar_t), message);
    if (actionButton) {
        wcscpy_s(notification.actionButton, sizeof(notification.actionButton) / sizeof(wchar_t), actionButton);
    }
    if (actionCommand) {
        wcscpy_s(notification.actionCommand, sizeof(notification.actionCommand) / sizeof(wchar_t), actionCommand);
    }

    // 检查UI状态
    if (NotificationManager_CheckUIStatus(Manager)) {
        // UI可用，通过ALPC发送通知
        return NotificationManager_SendNotificationToUI(Manager, &notification);
    } else {
        // UI不可用，通过Helper发送通知
        return NotificationManager_SendNotificationWithHelper(Manager, &notification);
    }
}

// 发送威胁检测通知
NTSTATUS NotificationManager_SendThreatNotification(
    PNOTIFICATION_SERVICE Manager,
    const wchar_t* threatName
)
{
    if (!Manager || !Manager->Initialized || !threatName) {
        return STATUS_INVALID_PARAMETER;
    }
    
    wchar_t message[1024];
    swprintf_s(message, 1024, L"检测到威胁: %s", threatName);
    
    return NotificationManager_SendNotification(
        Manager,
        WKDEFENDER_NOTIFICATION_TYPE_ERROR,
        L"安全威胁检测",
        message,
        L"隔离威胁",
        L"action:isolate"
    );
}

// 发送进程终止通知
NTSTATUS NotificationManager_SendProcessTerminatedNotification(
    PNOTIFICATION_SERVICE Manager,
    int pid,
    const wchar_t* processName
)
{
    if (!Manager || !Manager->Initialized || !processName) {
        return STATUS_INVALID_PARAMETER;
    }
    
    wchar_t message[1024];
    swprintf_s(message, 1024, L"进程 %s (PID: %d) 已成功终止", processName, pid);
    
    return NotificationManager_SendNotification(
        Manager,
        WKDEFENDER_NOTIFICATION_TYPE_SUCCESS,
        L"进程操作",
        message,
        NULL,
        NULL
    );
}

// 发送扫描完成通知
NTSTATUS NotificationManager_SendScanCompletedNotification(
    PNOTIFICATION_SERVICE Manager,
    int threatCount
)
{
    if (!Manager || !Manager->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }
    
    wchar_t message[1024];
    if (threatCount > 0) {
        swprintf_s(message, 1024, L"扫描完成，发现 %d 个威胁", threatCount);
        return NotificationManager_SendNotification(
            Manager,
            WKDEFENDER_NOTIFICATION_TYPE_WARNING,
            L"扫描完成",
            message,
            L"查看威胁",
            L"action:view_threats"
        );
    } else {
        swprintf_s(message, 1024, L"扫描完成，未发现威胁");
        return NotificationManager_SendNotification(
            Manager,
            WKDEFENDER_NOTIFICATION_TYPE_SUCCESS,
            L"扫描完成",
            message,
            NULL,
            NULL
        );
    }
}

// 发送消息到Driver（模拟实现）
NTSTATUS NotificationManager_SendToDriver(
    PNOTIFICATION_SERVICE Manager,
    WKD_ALPC_MESSAGE_TYPE MessageType,
    PVOID pData,
    ULONG DataLength
)
{
    if (!Manager || !Manager->Initialized || !Manager->AlpcServer) {
        return STATUS_INVALID_PARAMETER;
    }
    
    return WkdAlpcSendToDriver(
        Manager->AlpcServer,
        MessageType,
        pData,
        DataLength
    );
}

// 获取ALPC服务器状态
WKD_ALPC_SERVER_STATE NotificationManager_GetAlpcState(
    PNOTIFICATION_SERVICE Manager
)
{
    if (!Manager || !Manager->Initialized || !Manager->AlpcServer) {
        return WkdAlpcStateError;
    }
    
    return WkdAlpcGetState(Manager->AlpcServer);
}

// 检查Driver连接状态（模拟实现）
BOOL NotificationManager_IsDriverConnected(
    PNOTIFICATION_SERVICE Manager
)
{
    if (!Manager || !Manager->Initialized || !Manager->AlpcServer) {
        return FALSE;
    }
    
    return WkdAlpcIsDriverConnected(Manager->AlpcServer);
}

/*
 * RouteMessageHandler 已迁移至 Common/AlpcServer.c 的 AlpcpRouteMessage。
 * 新架构使用路由表注册机制，不再需要此函数。
 */