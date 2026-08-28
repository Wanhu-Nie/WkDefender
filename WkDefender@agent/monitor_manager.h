// 进程监控模块头文件
// 
// 功能说明：
// 本模块提供进程监控相关的功能，包括：
// 1. 启动进程监控
// 2. 停止进程监控
// 3. 添加监控进程
// 4. 移除监控进程
// 5. 进程事件通知回调
//
// 使用说明：
// 1. 调用MonitorManager_Initialize()初始化模块
// 2. 设置事件通知回调函数
// 3. 使用相应的函数管理监控进程
// 4. 调用MonitorManager_Cleanup()清理资源
//
// 作者：WkDefender Team
// 版本：1.0.0
// 日期：2026-04-04

#pragma once
/*
#include "WkDefenderHeader.h"

// 监控事件类型枚举
typedef enum _MONITOR_EVENT_TYPE {
    MONITOR_EVENT_PROCESS_CREATED = 0,
    MONITOR_EVENT_PROCESS_TERMINATED = 1,
    MONITOR_EVENT_PROCESS_SUSPENDED = 2,
    MONITOR_EVENT_PROCESS_RESUMED = 3,
    MONITOR_EVENT_PROCESS_ACCESS_DENIED = 4
} MONITOR_EVENT_TYPE;

// 监控事件结构体
typedef struct _MONITOR_EVENT {
    MONITOR_EVENT_TYPE EventType;
    DWORD Pid;
    CHAR ProcessName[256];
    CHAR FilePath[MAX_PATH];
    FILETIME EventTime;
} MONITOR_EVENT, * PMONITOR_EVENT;

// 监控进程信息结构体
typedef struct _MONITORED_PROCESS {
    DWORD Pid;
    CHAR ProcessName[256];
    CHAR FilePath[MAX_PATH];
    HANDLE hProcess;
    HANDLE hWaitThread;
    BOOL bMonitoring;
} MONITORED_PROCESS, * PMONITORED_PROCESS;

// 进程事件通知回调函数类型
// 参数：
//   pEvent - 监控事件
//   pContext - 用户自定义上下文
typedef VOID (*MONITOR_EVENT_CALLBACK)(
    PMONITOR_EVENT pEvent,
    PVOID pContext
);

// 进程监控模块接口

// 初始化进程监控模块
NTSTATUS MonitorManager_Initialize();

// 清理进程监控模块资源
VOID MonitorManager_Cleanup();

// 启动进程监控
// 参数：
//   EventCallback - 事件通知回调函数
//   pCallbackContext - 回调函数上下文
// 返回：NTSTATUS状态码
NTSTATUS MonitorManager_StartMonitoring(
    MONITOR_EVENT_CALLBACK EventCallback,
    PVOID pCallbackContext
);

// 停止进程监控
// 返回：NTSTATUS状态码
NTSTATUS MonitorManager_StopMonitoring();

// 添加监控进程
// 参数：
//   Pid - 进程ID
//   pProcessName - 进程名称
//   pFilePath - 进程路径
// 返回：NTSTATUS状态码
NTSTATUS MonitorManager_AddProcess(
    DWORD Pid,
    LPCSTR pProcessName,
    LPCSTR pFilePath
);

// 移除监控进程
// 参数：
//   Pid - 进程ID
// 返回：NTSTATUS状态码
NTSTATUS MonitorManager_RemoveProcess(
    DWORD Pid
);

// 获取监控进程列表
// 参数：
//   pProcessList - 输出参数，监控进程列表数组
//   pCount - 输出参数，监控进程数量
// 返回：NTSTATUS状态码
NTSTATUS MonitorManager_GetMonitoredProcesses(
    PMONITORED_PROCESS* pProcessList,
    PULONG pCount
);

// 释放监控进程列表内存
VOID MonitorManager_FreeProcessList(
    PMONITORED_PROCESS pProcessList
);

// 清理所有监控的进程
VOID MonitorManager_CleanupAllProcesses();

*/