#include "pipe_server.h"
#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 内部缓冲区大小
#define PIPE_BUFFER_SIZE 65536
#define PIPE_TIMEOUT 5000

// 处理Helper反馈消息
static VOID ProcessHelperResponse(NOTIFY_MESSAGE* message);

// 处理管道消息的线程函数
static DWORD WINAPI PipeMessageThread(LPVOID lpParam);

// 生成唯一的管道名称
BOOLEAN PipeServer_GeneratePipeName(char* buffer, size_t buffer_size)
{
    if (!buffer || buffer_size == 0) return FALSE;
    
    DWORD pid = GetCurrentProcessId();
    DWORD tick = GetTickCount();
    
    snprintf(buffer, buffer_size, "WkDefender_Notify_%lu_%lu", pid, tick);
    
    return TRUE;
}

// 创建命名管道服务器
PPIPE_SERVER PipeCreateServer(const char* pipe_name)
{
    if (!pipe_name) return NULL;
    
    PPIPE_SERVER server = (PPIPE_SERVER)malloc(sizeof(PIPE_SERVER));
    if (!server) return NULL;
    
    // 构建完整的管道路径
    char full_pipe_name[512];
    snprintf(full_pipe_name, sizeof(full_pipe_name), "\\\\.\\pipe\\%s", pipe_name);
    
    // 创建命名管道
    server->pipe_handle = CreateNamedPipeA(
        full_pipe_name,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, PIPE_TIMEOUT, NULL
    );
    
    if (server->pipe_handle == INVALID_HANDLE_VALUE) {
        free(server);
        return NULL;
    }
    
    // 初始化服务器结构
    strcpy_s(server->pipe_name, sizeof(server->pipe_name), pipe_name);
    server->is_connected = FALSE;
    ZeroMemory(&server->overlapped, sizeof(server->overlapped));
    server->thread_handle = NULL;
    server->running = FALSE;
    
    return server;
}

// 启动管道服务器
BOOLEAN PipeServer_Start(PPIPE_SERVER server)
{
    if (!server || server->pipe_handle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    server->running = TRUE;
    server->thread_handle = CreateThread(
        NULL,
        0,
        PipeMessageThread,
        server,
        0,
        NULL
    );
    
    if (!server->thread_handle) {
        server->running = FALSE;
        return FALSE;
    }
    
    return TRUE;
}

// 停止管道服务器
VOID PipeServer_Stop(PPIPE_SERVER server)
{
    if (!server) return;
    
    server->running = FALSE;
    
    if (server->thread_handle) {
        WaitForSingleObject(server->thread_handle, 5000);
        CloseHandle(server->thread_handle);
        server->thread_handle = NULL;
    }
}

// 关闭管道服务器
VOID PipeServer_Close(PPIPE_SERVER server)
{
    if (!server) return;
    
    PipeServer_Stop(server);
    
    if (server->pipe_handle != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(server->pipe_handle);
        CloseHandle(server->pipe_handle);
    }
    
    free(server);
}

// 等待客户端连接
BOOLEAN PipeServer_WaitForConnection(PPIPE_SERVER server, DWORD timeout_ms)
{
    if (!server || server->pipe_handle == INVALID_HANDLE_VALUE) return FALSE;
    
    // 创建事件对象
    server->overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!server->overlapped.hEvent) return FALSE;
    
    // 开始连接
    BOOL result = ConnectNamedPipe(server->pipe_handle, &server->overlapped);
    
    if (result) {
        // 连接成功
        server->is_connected = TRUE;
        CloseHandle(server->overlapped.hEvent);
        return TRUE;
    } else {
        // 检查错误码
        DWORD error = GetLastError();
        if (error == ERROR_IO_PENDING) {
            // 等待连接完成
            if (WaitForSingleObject(server->overlapped.hEvent, timeout_ms) == WAIT_OBJECT_0) {
                server->is_connected = TRUE;
                CloseHandle(server->overlapped.hEvent);
                return TRUE;
            }
        }
    }
    
    CloseHandle(server->overlapped.hEvent);
    return FALSE;
}

// 读取消息
BOOLEAN PipeServer_ReadMessage(PPIPE_SERVER server, NOTIFY_MESSAGE* message, DWORD timeout_ms)
{
    if (!server || !server->is_connected || !message) return FALSE;
    
    // 读取消息长度
    DWORD bytes_read = 0;
    DWORD message_length = 0;
    
    if (!ReadFile(server->pipe_handle, &message_length, sizeof(message_length), &bytes_read, NULL)) {
        return FALSE;
    }
    
    if (bytes_read != sizeof(message_length)) return FALSE;
    
    // 读取消息内容
    if (!ReadFile(server->pipe_handle, message, message_length, &bytes_read, NULL)) {
        return FALSE;
    }
    
    return bytes_read == message_length;
}

// 发送消息
BOOLEAN PipeServer_SendMessage(PPIPE_SERVER server, const NOTIFY_MESSAGE* message)
{
    if (!server || !server->is_connected || !message) return FALSE;
    
    // 计算消息大小
    DWORD message_size = sizeof(NOTIFY_MESSAGE);
    
    // 发送消息长度
    DWORD bytes_written = 0;
    if (!WriteFile(server->pipe_handle, &message_size, sizeof(message_size), &bytes_written, NULL)) {
        return FALSE;
    }
    
    if (bytes_written != sizeof(message_size)) return FALSE;
    
    // 发送消息内容
    if (!WriteFile(server->pipe_handle, message, message_size, &bytes_written, NULL)) {
        return FALSE;
    }
    
    return bytes_written == message_size;
}

// 启动Helper进程
BOOLEAN PipeServer_StartHelper(
    const wchar_t* helper_path,
    const char* pipe_name,
    const NOTIFY_REQUEST* request,
    HANDLE* process_handle
)
{
    if (!helper_path || !pipe_name || !request) return FALSE;
    
    // 构建命令行参数
    wchar_t cmd_line[4096];
    int pos = 0;
    
    pos += swprintf_s(cmd_line + pos, sizeof(cmd_line) / sizeof(wchar_t) - pos, L"\"%s\"", helper_path);
    pos += swprintf_s(cmd_line + pos, sizeof(cmd_line) / sizeof(wchar_t) - pos, L" --pipe %hs", pipe_name);
    
    if (strlen(request->title) > 0) {
        pos += swprintf_s(cmd_line + pos, sizeof(cmd_line) / sizeof(wchar_t) - pos, L" --title \"%hs\"", request->title);
    }
    
    if (strlen(request->subtitle) > 0) {
        pos += swprintf_s(cmd_line + pos, sizeof(cmd_line) / sizeof(wchar_t) - pos, L" --subtitle \"%hs\"", request->subtitle);
    }
    
    if (strlen(request->body) > 0) {
        pos += swprintf_s(cmd_line + pos, sizeof(cmd_line) / sizeof(wchar_t) - pos, L" --body \"%hs\"", request->body);
    }
    
    if (strlen(request->image_path) > 0) {
        pos += swprintf_s(cmd_line + pos, sizeof(cmd_line) / sizeof(wchar_t) - pos, L" --image \"%hs\"", request->image_path);
    }
    
    // 添加按钮参数
    for (int i = 0; i < request->button_count && i < 3; i++) {
        pos += swprintf_s(cmd_line + pos, sizeof(cmd_line) / sizeof(wchar_t) - pos, 
            L" --button \"%hs|%hs|%hs\"", 
            request->buttons[i].text,
            request->buttons[i].action,
            request->buttons[i].arguments);
    }
    
    // 启动进程
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION process_info = { 0 };
    
    BOOL result = CreateProcessW(
        NULL,
        cmd_line,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
        NULL,
        NULL,
        &si,
        &process_info
    );
    
    if (!result) {
        return FALSE;
    }
    
    // 关闭线程句柄
    CloseHandle(process_info.hThread);
    
    if (process_handle) {
        *process_handle = process_info.hProcess;
    } else {
        CloseHandle(process_info.hProcess);
    }
    
    return TRUE;
}

// 检查Helper进程是否运行
BOOLEAN PipeServer_IsHelperRunning(HANDLE helper_process)
{
    if (helper_process) {
        DWORD exit_code;
        if (GetExitCodeProcess(helper_process, &exit_code)) {
            if (exit_code == STILL_ACTIVE) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

// 启动常驻Helper进程
BOOLEAN PipeServer_StartResidentHelper(
    const wchar_t* helper_path,
    HANDLE* process_handle
)
{
    if (!helper_path) return FALSE;
    
    // 启动进程
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION process_info = { 0 };
    
    BOOL result = CreateProcessW(
        helper_path,
        NULL,  // 无需命令行参数，Helper会自动连接管道
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE,  // 后台运行
        NULL,
        NULL,
        &si,
        &process_info
    );
    
    if (!result) {
        return FALSE;
    }
    
    // 关闭线程句柄
    CloseHandle(process_info.hThread);
    
    if (process_handle) {
        *process_handle = process_info.hProcess;
    } else {
        CloseHandle(process_info.hProcess);
    }
    
    return TRUE;
}

// 处理Helper反馈消息
static VOID ProcessHelperResponse(NOTIFY_MESSAGE* message)
{
    switch (message->type) {
    case NOTIFY_MSG_RESPONSE:
        // 处理通知响应
        break;
    case NOTIFY_MSG_BUTTON_CLICK:
        // 处理按钮点击
        break;
    case NOTIFY_MSG_DISMISSED:
        // 处理通知被关闭
        break;
    case NOTIFY_MSG_FAILED:
        // 处理通知失败
        break;
    default:
        break;
    }
}

// 处理管道消息的线程函数
static DWORD WINAPI PipeMessageThread(LPVOID lpParam)
{
    PPIPE_SERVER server = (PPIPE_SERVER)lpParam;
    if (!server) return 0;

    while (server->running) {
        // 等待客户端连接
        if (PipeServer_WaitForConnection(server, 5000)) {
            // 连接成功，处理消息
            while (server->is_connected && server->running) {
                NOTIFY_MESSAGE message;
                if (PipeServer_ReadMessage(server, &message, 1000)) {
                    ProcessHelperResponse(&message);
                } else {
                    // 读取失败，可能连接已断开
                    break;
                }
            }

            // 断开连接，准备接受下一个连接
            DisconnectNamedPipe(server->pipe_handle);
            server->is_connected = FALSE;
        }
    }

    return 0;
}
