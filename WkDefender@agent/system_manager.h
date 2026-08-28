// 系统状态模块头文件
// 
// 功能说明：
// 本模块提供系统状态管理的基础功能，主要是消息队列支持
//
// 使用说明：
// 1. 调用SystemManager_Initialize()初始化模块
// 2. 系统会自动处理消息队列中的消息
// 3. 调用SystemManager_Cleanup()清理资源
//
// 作者：WkDefender Team
// 版本：1.0.0
// 日期：2026-04-04

#pragma once

#include "WkDefenderHeader.h"
#include "Notification/msg_queue.h"
#include "Notification/AlpcService.h"

// 系统管理器结构体
typedef struct _SYSTEM_MANAGER {
    BOOLEAN Initialized;
    CRITICAL_SECTION Lock;
    WKD_MSG_QUEUE MessageQueue;         // 独立的消息队列
    HANDLE WorkerThread;                // 独立的处理线程
} SYSTEM_MANAGER, *PSYSTEM_MANAGER;

// 全局系统管理器实例
extern SYSTEM_MANAGER g_SystemManager;

// 系统状态模块接口

// 初始化系统状态模块（自注册模式）
// 参数：AlpcServer — ALPC 服务器实例（NULL = 使用全局默认 WkdDefaultAlpcServer）
NTSTATUS SystemManager_InitializeService(
    _In_opt_ PWKD_ALPC_SERVER AlpcServer
    );

// 清理系统状态模块资源
VOID SystemManager_Cleanup();

// 系统管理器消息处理函数
PVOID SystemManager_MessageHandler(
    PVOID Context,
    ULONG MessageType,
    PVOID Data
);
