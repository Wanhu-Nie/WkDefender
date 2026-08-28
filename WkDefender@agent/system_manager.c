// 系统状态模块实现
// 
// 功能说明：
// 本模块提供系统状态管理的基础功能，主要是消息队列支持
//
// 作者：WkDefender Team
// 版本：1.0.0
// 日期：2026-04-04

#include "system_manager.h"
#include "WkDefenderHeader.h"
#include "Notification/AlpcService.h"
#include "Notification/NotificationService.h"

// 全局系统管理器实例
SYSTEM_MANAGER g_SystemManager = {0};

// 声明全局Agent上下文
extern WKDEFENDER_AGENT WkDefenderAgent;

// 初始化系统状态模块（自注册模式）
NTSTATUS SystemManager_InitializeService(
    _In_opt_ PWKD_ALPC_SERVER AlpcServer
    )
{
    NTSTATUS status;
    PWKD_ALPC_SERVER targetServer;

    printf("[SystemManager] Initializing service...\n");

    targetServer = AlpcServer ? AlpcServer : &WkdDefaultAlpcServer;

    // 初始化临界区
    InitializeCriticalSection(&g_SystemManager.Lock);

    // 初始化消息队列（不启动线程，StartAllModules 阶段统一启动）
    status = NtfInitializeMessageQueueMessageQueue(&g_SystemManager.MessageQueue, WKD_MSG_QUEUE_MAX_SIZE, SystemManager_MessageHandler, &g_SystemManager);
    if (!NT_SUCCESS(status)) {
        printf("[SystemManager] Failed to initialize message queue: 0x%X\n", status);
        DeleteCriticalSection(&g_SystemManager.Lock);
        return status;
    }

    // 注册消息路由
    // UI → Agent: 系统状态请求
    AlpcRegisterRoute(targetServer,
        WkdAlpcMsg_GetSystemStatusReq, WkdAlpcMsg_GetSystemStatusReq,
        WkdMsgQueueAlpcHandler, &g_SystemManager.MessageQueue);

    g_SystemManager.Initialized = TRUE;
    printf("[SystemManager] Service initialized successfully\n");
    return STATUS_SUCCESS;
}

// 清理系统状态模块资源
VOID SystemManager_Cleanup()
{
    printf("[SystemManager] Cleaning up...\n");
    
    // 清理消息队列
    WkdMsgQueueStopProcessing(&g_SystemManager.MessageQueue);
    WkdMsgQueueCleanup(&g_SystemManager.MessageQueue);
    
    // 清理临界区
    DeleteCriticalSection(&g_SystemManager.Lock);
    
    g_SystemManager.Initialized = FALSE;
    printf("[SystemManager] Cleanup completed\n");
}

// 系统管理器消息处理函数
PVOID SystemManager_MessageHandler(
    PVOID Context,
    ULONG MessageType,
    PVOID Data
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PWKD_MESSAGE msg = (PWKD_MESSAGE)Data;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(MessageType);

    printf("[SystemManager] Processing message: Type=0x%X\n", msg->Header.Type);

    switch (msg->Header.Type) {
    case WkdAlpcMsg_GetSystemStatusReq:
        printf("[SystemManager] Processing get system status request\n");
        /* 通过 ALPC 发送响应 */
        if (WkDefenderAgent.NotificationManager != NULL &&
            WkDefenderAgent.NotificationManager->AlpcServer != NULL) {
            /* 简单返回状态数据: uint[4] = {安全, CPU, 内存, 威胁} */
            ULONG statusData[4] = { 1, 15, 30, 0 };
            //WkdAlpcSendToUi(
            //    WkDefenderAgent.NotificationManager->AlpcServer,
            //    WkdAlpcMsg_GetSystemStatusResp,
            //    statusData,
            //    sizeof(statusData)
            //);
        } else {
            printf("[SystemManager] ALPC server not initialized\n");
            status = STATUS_INVALID_DEVICE_STATE;
        }
        break;
    default:
        printf("[SystemManager] Unknown message type: 0x%X\n", MessageType);
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    
    return (PVOID)(ULONG_PTR)status;
}
