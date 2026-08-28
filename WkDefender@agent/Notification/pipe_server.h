// 命名管道服务器模块头文件
//
// 功能说明：
// 本模块负责管理Agent与Helper之间的命名管道通信
//
// 作者：WkDefender Team
// 版本：2.0.0
// 日期：2026-04-09

#pragma once
#include "../WkDefenderHeader.h"

// 消息类型枚举
typedef enum _NOTIFY_MESSAGE_TYPE {
    NOTIFY_MSG_REQUEST = 1,      // 通知请求
    NOTIFY_MSG_RESPONSE = 2,     // 通知响应
    NOTIFY_MSG_BUTTON_CLICK = 3, // 按钮点击
    NOTIFY_MSG_DISMISSED = 4,    // 通知被关闭
    NOTIFY_MSG_FAILED = 5        // 通知失败
} NOTIFY_MESSAGE_TYPE;

// 按钮信息
typedef struct _BUTTON_INFO {
    char text[64];
    char action[64];
    char arguments[256];
} BUTTON_INFO;

// 通知请求消息
typedef struct _NOTIFY_REQUEST {
    char app_id[256];
    char title[256];
    char subtitle[256];
    char body[512];
    char image_path[512];
    int button_count;
    BUTTON_INFO buttons[3];
} NOTIFY_REQUEST;

// 通知响应消息
typedef struct _NOTIFY_RESPONSE {
    BOOLEAN success;
    char error_message[256];
} NOTIFY_RESPONSE;

// 按钮点击消息
typedef struct _BUTTON_CLICK {
    char action[64];
    char arguments[256];
} BUTTON_CLICK;

// 通用消息结构
typedef struct _NOTIFY_MESSAGE {
    NOTIFY_MESSAGE_TYPE type;
    size_t length;
    //union {
    //    NOTIFY_REQUEST request;
    //    NOTIFY_RESPONSE response;
    //    BUTTON_CLICK button_click;
    //    char data[1]; // 可变长度数据
    //} data;
    BYTE data[256];
} NOTIFY_MESSAGE;

// 命名管道服务器上下文
typedef struct _PIPE_SERVER {
    HANDLE pipe_handle;
    char pipe_name[256];
    BOOLEAN is_connected;
    OVERLAPPED overlapped;
    HANDLE thread_handle;
    BOOLEAN running;
} PIPE_SERVER, * PPIPE_SERVER;

// 生成唯一的管道名称
BOOLEAN PipeServer_GeneratePipeName(char* buffer, size_t buffer_size);

// 创建命名管道服务器
PPIPE_SERVER PipeCreateServer(const char* pipe_name);

// 启动管道服务器
BOOLEAN PipeServer_Start(PPIPE_SERVER server);

// 停止管道服务器
VOID PipeServer_Stop(PPIPE_SERVER server);

// 关闭管道服务器
VOID PipeServer_Close(PPIPE_SERVER server);

// 等待客户端连接
BOOLEAN PipeServer_WaitForConnection(PPIPE_SERVER server, DWORD timeout_ms);

// 读取消息
BOOLEAN PipeServer_ReadMessage(PPIPE_SERVER server, NOTIFY_MESSAGE* message, DWORD timeout_ms);

// 发送消息
BOOLEAN PipeServer_SendMessage(PPIPE_SERVER server, const NOTIFY_MESSAGE* message);

// 启动Helper进程
BOOLEAN PipeServer_StartHelper(
    const wchar_t* helper_path,
    const char* pipe_name,
    const NOTIFY_REQUEST* request,
    HANDLE* process_handle
);

// 检查Helper进程是否运行
BOOLEAN PipeServer_IsHelperRunning(HANDLE helper_process);

// 启动常驻Helper进程
BOOLEAN PipeServer_StartResidentHelper(
    const wchar_t* helper_path,
    HANDLE* process_handle
);
