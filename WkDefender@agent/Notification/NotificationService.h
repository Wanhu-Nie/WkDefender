// WkDefender Agent - 通知管理模块头文件
//
// 功能说明：
// 本模块负责管理Agent的通知功能，根据UI状态选择合适的通知方式
// 并管理ALPC服务器和管道服务器的生命周期
//
// 作者：WkDefender Team
// 版本：3.0.0
// 日期：2026-04-09

#pragma once
#include "../WkDefenderHeader.h"
#include "AlpcService.h"
#include "pipe_server.h"
#include "msg_queue.h"

// 通知类型定义
typedef enum _WKDEFENDER_NOTIFICATION_TYPE {
    WKDEFENDER_NOTIFICATION_TYPE_INFO,
    WKDEFENDER_NOTIFICATION_TYPE_WARNING,
    WKDEFENDER_NOTIFICATION_TYPE_ERROR,
    WKDEFENDER_NOTIFICATION_TYPE_SUCCESS
} WKDEFENDER_NOTIFICATION_TYPE;

// 通知数据结构
typedef struct _WKDEFENDER_NOTIFICATION_DATA {
    WKDEFENDER_NOTIFICATION_TYPE type;
    wchar_t title[256];
    wchar_t message[1024];
    wchar_t actionButton[128];
    wchar_t actionCommand[256];
} WKDEFENDER_NOTIFICATION_DATA;

// 通知管理器结构体
typedef struct _NOTIFICATION_SERVICE {
    PWKD_ALPC_SERVER AlpcServer;
    PPIPE_SERVER PipeServer;
    HANDLE helper_process;
    CRITICAL_SECTION Lock;
    BOOLEAN Initialized;
    WKD_MSG_QUEUE MessageQueue;  // 独立的消息队列
    HANDLE WorkerThread;         // 独立的处理线程
} NOTIFICATION_SERVICE, * PNOTIFICATION_SERVICE;

// 初始化通知管理器
NTSTATUS 
NtfInitializeService(
    VOID
    );

// 清理通知管理器资源
VOID 
NotificationManager_Cleanup(
    PNOTIFICATION_SERVICE Manager
    );  

// 启动通知管理器
NTSTATUS 
NtfStartService(
    PNOTIFICATION_SERVICE Service
    );

// 停止通知管理器
NTSTATUS 
NotificationManager_Stop(
    PNOTIFICATION_SERVICE Service
    );

// 检查UI状态
BOOL 
NotificationManager_CheckUIStatus(
    PNOTIFICATION_SERVICE Manager
    );

// 通过ALPC向UI发送通知
NTSTATUS NotificationManager_SendNotificationToUI(
    PNOTIFICATION_SERVICE Manager,
    WKDEFENDER_NOTIFICATION_DATA* pNotification
);

// 通过Helper发送Toast通知
NTSTATUS NotificationManager_SendNotificationWithHelper(
    PNOTIFICATION_SERVICE Manager,
    WKDEFENDER_NOTIFICATION_DATA* pNotification
);

// 发送通知（根据UI状态选择通知方式）
NTSTATUS NotificationManager_SendNotification(
    PNOTIFICATION_SERVICE Manager,
    WKDEFENDER_NOTIFICATION_TYPE type,
    const wchar_t* title,
    const wchar_t* message,
    const wchar_t* actionButton,
    const wchar_t* actionCommand
);

// 发送威胁检测通知
NTSTATUS NotificationManager_SendThreatNotification(
    PNOTIFICATION_SERVICE Manager,
    const wchar_t* threatName
);

// 发送进程终止通知
NTSTATUS NotificationManager_SendProcessTerminatedNotification(
    PNOTIFICATION_SERVICE Manager,
    int pid,
    const wchar_t* processName
);

// 发送扫描完成通知
NTSTATUS NotificationManager_SendScanCompletedNotification(
    PNOTIFICATION_SERVICE Manager,
    int threatCount
);

// 发送消息到Driver（模拟实现）
NTSTATUS NotificationManager_SendToDriver(
    PNOTIFICATION_SERVICE Manager,
    WKD_ALPC_MESSAGE_TYPE MessageType,
    PVOID pData,
    ULONG DataLength
);

// 获取ALPC服务器状态
WKD_ALPC_SERVER_STATE NotificationManager_GetAlpcState(
    PNOTIFICATION_SERVICE Manager
);

// 检查Driver连接状态（模拟实现）
BOOL NotificationManager_IsDriverConnected(
    PNOTIFICATION_SERVICE Manager
);

// 路由消息处理已迁移至 Common/alpc_server.c 的 AlpcpRouteMessage。
// 各模块通过 AlpcRegisterRoute 注册自己的处理路由。

// 全局通知管理器实例（由 NtfInitializeService 初始化）
extern NOTIFICATION_SERVICE WkdNotificationService;