// 进程监控模块实现
// 
// 功能说明：
// 本模块实现进程监控的核心功能，包括：
// 1. 启动进程监控
// 2. 停止进程监控
// 3. 添加监控进程
// 4. 移除监控进程
// 5. 进程事件通知回调
//
// 作者：WkDefender Team
// 版本：1.0.0
// 日期：2026-04-04

#include "monitor_manager.h"

/*
// 最大监控进程数
#define MAX_MONITORED_PROCESSES 100

// 全局变量
static MONITORED_PROCESS g_MonitoredProcesses[MAX_MONITORED_PROCESSES];
static ULONG g_MonitoredProcessCount = 0;
static CRITICAL_SECTION g_MonitorLock;
static BOOL g_Monitoring = FALSE;
static MONITOR_EVENT_CALLBACK g_EventCallback = NULL;
static PVOID g_CallbackContext = NULL;

// 进程等待线程函数
DWORD WINAPI ProcessWaitThread(LPVOID lpParam)
{
    PMONITORED_PROCESS pMonitoredProcess = (PMONITORED_PROCESS)lpParam;
    MONITOR_EVENT event;
    NTSTATUS status = STATUS_SUCCESS;
    
    printf("[MonitorManager] Wait thread started for PID %d\n", pMonitoredProcess->ProcessId);
    
    // TODO: 实现真实的进程等待逻辑
    // 当前使用模拟等待，实际应该：
    // 1. 使用 WaitForSingleObject() 等待进程退出
    // 2. 检查进程状态变化
    // 3. 触发相应的事件通知
    // 4. 清理进程句柄
    
    // 模拟等待进程退出
    WaitForSingleObject(pMonitoredProcess->hProcess, INFINITE);
    
    printf("[MonitorManager] Process %d terminated\n", pMonitoredProcess->ProcessId);
    
    // 触发进程终止事件
    if (g_EventCallback != NULL && pMonitoredProcess->bMonitoring)
    {
        RtlSecureZeroMemory(&event, sizeof(MONITOR_EVENT));
        event.EventType = MONITOR_EVENT_PROCESS_TERMINATED;
        event.ProcessId = pMonitoredProcess->ProcessId;
        strcpy_s(event.ProcessName, pMonitoredProcess->ProcessName);
        strcpy_s(event.FilePath, pMonitoredProcess->FilePath);
        GetSystemTimeAsFileTime(&event.EventTime);
        
        printf("[MonitorManager] Calling event callback for PID %d\n", pMonitoredProcess->ProcessId);
        g_EventCallback(&event, g_CallbackContext);
    }
    
    // 标记为不再监控
    pMonitoredProcess->bMonitoring = FALSE;
    
    printf("[MonitorManager] Wait thread exiting for PID %d\n", pMonitoredProcess->ProcessId);
    return 0;
}

// 初始化进程监控模块
NTSTATUS MonitorManager_Initialize()
{
    printf("[MonitorManager] Initializing...\n");
    
    RtlSecureZeroMemory(g_MonitoredProcesses, sizeof(g_MonitoredProcesses));
    g_MonitoredProcessCount = 0;
    g_Monitoring = FALSE;
    g_EventCallback = NULL;
    g_CallbackContext = NULL;
    
    InitializeCriticalSection(&g_MonitorLock);
    
    printf("[MonitorManager] Initialized successfully\n");
    return STATUS_SUCCESS;
}

// 清理进程监控模块资源
VOID MonitorManager_Cleanup()
{
    printf("[MonitorManager] Cleaning up...\n");
    
    // 停止监控
    if (g_Monitoring)
    {
        MonitorManager_StopMonitoring();
    }
    
    // 清理所有监控的进程
    MonitorManager_CleanupAllProcesses();
    
    DeleteCriticalSection(&g_MonitorLock);
    
    printf("[MonitorManager] Cleanup completed\n");
}

// 启动进程监控
NTSTATUS MonitorManager_StartMonitoring(
    MONITOR_EVENT_CALLBACK EventCallback,
    PVOID pCallbackContext)
{
    printf("[MonitorManager] Starting monitoring...\n");
    
    EnterCriticalSection(&g_MonitorLock);
    
    if (g_Monitoring)
    {
        printf("[MonitorManager] Error: Already monitoring\n");
        LeaveCriticalSection(&g_MonitorLock);
        return STATUS_DEVICE_BUSY;
    }
    
    g_EventCallback = EventCallback;
    g_CallbackContext = pCallbackContext;
    g_Monitoring = TRUE;
    
    LeaveCriticalSection(&g_MonitorLock);
    
    printf("[MonitorManager] Monitoring started\n");
    return STATUS_SUCCESS;
}

// 停止进程监控
NTSTATUS MonitorManager_StopMonitoring()
{
    printf("[MonitorManager] Stopping monitoring...\n");
    
    EnterCriticalSection(&g_MonitorLock);
    
    if (!g_Monitoring)
    {
        printf("[MonitorManager] Error: Not monitoring\n");
        LeaveCriticalSection(&g_MonitorLock);
        return STATUS_INVALID_DEVICE_STATE;
    }
    
    g_Monitoring = FALSE;
    g_EventCallback = NULL;
    g_CallbackContext = NULL;
    
    LeaveCriticalSection(&g_MonitorLock);
    
    printf("[MonitorManager] Monitoring stopped\n");
    return STATUS_SUCCESS;
}

// 添加监控进程
NTSTATUS MonitorManager_AddProcess(
    DWORD Pid,
    LPCSTR pProcessName,
    LPCSTR pFilePath)
{
    NTSTATUS status = STATUS_SUCCESS;
    PMONITORED_PROCESS pMonitoredProcess = NULL;
    
    printf("[MonitorManager] Adding process to monitor: PID %d\n", Pid);
    
    if (pProcessName == NULL || pFilePath == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    EnterCriticalSection(&g_MonitorLock);
    
    // 检查是否已达到最大监控数
    if (g_MonitoredProcessCount >= MAX_MONITORED_PROCESSES)
    {
        printf("[MonitorManager] Error: Maximum monitored processes reached\n");
        LeaveCriticalSection(&g_MonitorLock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // 检查进程是否已在监控列表中
    for (ULONG i = 0; i < g_MonitoredProcessCount; i++)
    {
        if (g_MonitoredProcesses[i].ProcessId == Pid)
        {
            printf("[MonitorManager] Error: Process %d already monitored\n", Pid);
            LeaveCriticalSection(&g_MonitorLock);
            return STATUS_OBJECT_NAME_COLLISION;
        }
    }
    
    // TODO: 实现真实的进程监控添加逻辑
    // 当前使用模拟，实际应该：
    // 1. 使用 OpenProcess() 打开进程
    // 2. 检查进程句柄是否有效
    // 3. 创建等待线程监控进程状态
    // 4. 设置进程访问权限
    // 5. 记录进程信息
    
    // 模拟添加监控进程
    pMonitoredProcess = &g_MonitoredProcesses[g_MonitoredProcessCount];
    pMonitoredProcess->ProcessId = Pid;
    strcpy_s(pMonitoredProcess->ProcessName, pProcessName);
    strcpy_s(pMonitoredProcess->FilePath, pFilePath);
    pMonitoredProcess->hProcess = OpenProcess(SYNCHRONIZE, FALSE, Pid);
    pMonitoredProcess->bMonitoring = TRUE;
    
    if (pMonitoredProcess->hProcess == NULL)
    {
        printf("[MonitorManager] Failed to open process %d\n", Pid);
        pMonitoredProcess->bMonitoring = FALSE;
        LeaveCriticalSection(&g_MonitorLock);
        return STATUS_UNSUCCESSFUL;
    }
    
    // 创建等待线程
    pMonitoredProcess->hWaitThread = CreateThread(
        NULL,
        0,
        ProcessWaitThread,
        pMonitoredProcess,
        0,
        NULL
    );
    
    if (pMonitoredProcess->hWaitThread == NULL)
    {
        printf("[MonitorManager] Failed to create wait thread for PID %d\n", Pid);
        CloseHandle(pMonitoredProcess->hProcess);
        pMonitoredProcess->bMonitoring = FALSE;
        LeaveCriticalSection(&g_MonitorLock);
        return STATUS_UNSUCCESSFUL;
    }
    
    g_MonitoredProcessCount++;
    
    LeaveCriticalSection(&g_MonitorLock);
    
    printf("[MonitorManager] Process %d added to monitoring\n", Pid);
    return STATUS_SUCCESS;
}

// 移除监控进程
NTSTATUS MonitorManager_RemoveProcess(
    DWORD Pid)
{
    NTSTATUS status = STATUS_SUCCESS;
    PMONITORED_PROCESS pMonitoredProcess = NULL;
    
    printf("[MonitorManager] Removing process from monitor: PID %d\n", Pid);
    
    EnterCriticalSection(&g_MonitorLock);
    
    // 查找进程
    for (ULONG i = 0; i < g_MonitoredProcessCount; i++)
    {
        if (g_MonitoredProcesses[i].ProcessId == Pid)
        {
            pMonitoredProcess = &g_MonitoredProcesses[i];
            break;
        }
    }
    
    if (pMonitoredProcess == NULL)
    {
        printf("[MonitorManager] Error: Process %d not found in monitoring list\n", Pid);
        LeaveCriticalSection(&g_MonitorLock);
        return STATUS_NOT_FOUND;
    }
    
    // TODO: 实现真实的进程监控移除逻辑
    // 当前使用模拟，实际应该：
    // 1. 标记进程为不再监控
    // 2. 终止等待线程
    // 3. 关闭进程句柄
    // 4. 从监控列表中移除
    
    // 模拟移除监控进程
    pMonitoredProcess->bMonitoring = FALSE;
    
    if (pMonitoredProcess->hWaitThread != NULL)
    {
        TerminateThread(pMonitoredProcess->hWaitThread, 0);
        CloseHandle(pMonitoredProcess->hWaitThread);
        pMonitoredProcess->hWaitThread = NULL;
    }
    
    if (pMonitoredProcess->hProcess != NULL)
    {
        CloseHandle(pMonitoredProcess->hProcess);
        pMonitoredProcess->hProcess = NULL;
    }
    
    // 从列表中移除（移动最后一个元素到当前位置）
    ULONG index = (ULONG)(pMonitoredProcess - g_MonitoredProcesses);
    if (index < g_MonitoredProcessCount - 1)
    {
        g_MonitoredProcesses[index] = g_MonitoredProcesses[g_MonitoredProcessCount - 1];
    }
    
    g_MonitoredProcessCount--;
    
    LeaveCriticalSection(&g_MonitorLock);
    
    printf("[MonitorManager] Process %d removed from monitoring\n", Pid);
    return STATUS_SUCCESS;
}

// 获取监控进程列表
NTSTATUS MonitorManager_GetMonitoredProcesses(
    PMONITORED_PROCESS* pProcessList,
    PULONG pCount)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    if (pProcessList == NULL || pCount == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    
    EnterCriticalSection(&g_MonitorLock);
    
    *pCount = g_MonitoredProcessCount;
    
    if (g_MonitoredProcessCount > 0)
    {
        *pProcessList = (PMONITORED_PROCESS)UtHeapAlloc(
            sizeof(MONITORED_PROCESS) * g_MonitoredProcessCount
        );
        
        if (*pProcessList == NULL)
        {
            LeaveCriticalSection(&g_MonitorLock);
            return STATUS_NO_MEMORY;
        }
        
        memcpy(*pProcessList, g_MonitoredProcesses, 
               sizeof(MONITORED_PROCESS) * g_MonitoredProcessCount);
    }
    else
    {
        *pProcessList = NULL;
    }
    
    LeaveCriticalSection(&g_MonitorLock);
    
    printf("[MonitorManager] Got %u monitored processes\n", *pCount);
    return STATUS_SUCCESS;
}

// 释放监控进程列表内存
VOID MonitorManager_FreeProcessList(
    PMONITORED_PROCESS pProcessList)
{
    if (pProcessList != NULL)
    {
        UtHeapFree(pProcessList);
    }
}

// 清理所有监控的进程
VOID MonitorManager_CleanupAllProcesses()
{
    printf("[MonitorManager] Cleaning up all monitored processes...\n");
    
    EnterCriticalSection(&g_MonitorLock);
    
    for (ULONG i = 0; i < g_MonitoredProcessCount; i++)
    {
        PMONITORED_PROCESS pMonitoredProcess = &g_MonitoredProcesses[i];
        
        pMonitoredProcess->bMonitoring = FALSE;
        
        if (pMonitoredProcess->hWaitThread != NULL)
        {
            TerminateThread(pMonitoredProcess->hWaitThread, 0);
            CloseHandle(pMonitoredProcess->hWaitThread);
            pMonitoredProcess->hWaitThread = NULL;
        }
        
        if (pMonitoredProcess->hProcess != NULL)
        {
            CloseHandle(pMonitoredProcess->hProcess);
            pMonitoredProcess->hProcess = NULL;
        }
    }
    
    g_MonitoredProcessCount = 0;
    
    LeaveCriticalSection(&g_MonitorLock);
    
    printf("[MonitorManager] All monitored processes cleaned up\n");
}
*/