#include "notification_manager.h"

// 定义端口名称
#define ALPC_MSGFLG_SYNC_REQUEST 0x20000
#define ALPC_MSGFLG_RELEASE_MESSAGE 0x10000



// 全局ALPC服务器实例
ALPC_SERVER g_AlpcServer = {
    .Running = FALSE,
    .State = ALPC_SERVER_STATE_STOPPED
};

pfnNtAlpcConnectPort WkAlpcConnectPort = NULL;
pfnNtAlpcSendWaitReceivePort WkAlpcSendWaitReceivePort = NULL, ZwAlpcSendWaitReceivePort = NULL;
pfnNtAlpcCreatePort WkAlpcCreatePort = NULL;
pfnNtAlpcAcceptConnectPort WkAlpcAcceptConnectPort = NULL;
pfnNtAlpcDisconnectPort WkAlpcDisconnectPort = NULL;

// 初始化ALPC函数指针
NTSTATUS InitializeAlpcFunctions()
{
    PVOID pfnPsSetProcessWin32Process = NULL;
    UNICODE_STRING ucs_PsSetProcessWin32Process, ucs_ZwAlpcSendWaitReceivePort;

    RtlInitUnicodeString(&ucs_PsSetProcessWin32Process, L"PsSetProcessWin32Process");
    pfnPsSetProcessWin32Process = MmGetSystemRoutineAddress(&ucs_PsSetProcessWin32Process);
    
    if (!pfnPsSetProcessWin32Process) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Failed to get PsSetProcessWin32Process address\n");
        return STATUS_NOT_FOUND;
    }

    // 根据偏移量获取ALPC函数地址
    // PsSetProcessWin32Process@0000000140710780 -NtAlpcSendWaitReceivePort@0000000140605AF0 
    WkAlpcSendWaitReceivePort = (pfnNtAlpcSendWaitReceivePort)((ULONG64)pfnPsSetProcessWin32Process - 0x10ac90);
    // NtAlpcConnectPort@000000014067AB70
    WkAlpcConnectPort = (pfnNtAlpcConnectPort)((ULONG64)pfnPsSetProcessWin32Process - 0x95c10);
    // NtAlpcCreatePort@0000000140711230
    WkAlpcCreatePort = (pfnNtAlpcCreatePort)((ULONG64)pfnPsSetProcessWin32Process + 0xab0);
    // NtAlpcAcceptConnectPort@000000014067C8E0
    WkAlpcAcceptConnectPort = (pfnNtAlpcAcceptConnectPort)((ULONG64)pfnPsSetProcessWin32Process - 0x93ea0);
    // NtAlpcDisconnectPort@0000000140679DD0
    WkAlpcDisconnectPort = (pfnNtAlpcDisconnectPort)((ULONG64)pfnPsSetProcessWin32Process - 0x969b0);

    RtlInitUnicodeString(&ucs_ZwAlpcSendWaitReceivePort, L"ZwAlpcSendWaitReceivePort");
    ZwAlpcSendWaitReceivePort = 
        (pfnNtAlpcSendWaitReceivePort)(MmGetSystemRoutineAddress(&ucs_ZwAlpcSendWaitReceivePort));

    if (!WkAlpcSendWaitReceivePort || !WkAlpcConnectPort || !WkAlpcCreatePort || 
        !WkAlpcAcceptConnectPort || !WkAlpcDisconnectPort || !ZwAlpcSendWaitReceivePort) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Failed to get ALPC function addresses\n");
        return STATUS_NOT_FOUND;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WkDefender] ALPC functions initialized successfully\n");
    return STATUS_SUCCESS;
}

// 连接到Agent
NTSTATUS AlpcServer_ConnectToAgent(
    PALPC_SERVER AlpcServer
)
{
    NTSTATUS status;
    SIZE_T size;
    UNICODE_STRING port_name;
    WKDEFENDER_ALPC_MESSAGE msg = { 0 };
    
    if (!AlpcServer) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 连接到Agent端口
    RtlInitUnicodeString(&port_name, L"\\RPC Control\\WkDefender@Agent");
    
    size = sizeof(WKDEFENDER_ALPC_MESSAGE);
    msg.ConnectionType = ALPC_CONNECTION_TYPE_DRIVER;
    msg.Header.u1.s1.TotalLength = sizeof(WKDEFENDER_ALPC_MESSAGE);
    msg.Header.u1.s1.DataLength = sizeof(WKDEFENDER_ALPC_MESSAGE) - sizeof(PORT_MESSAGE);
    status = WkAlpcConnectPort(
        &AlpcServer->AgentPort,
        &port_name,
        NULL,
        NULL,
        0,
        NULL,
        (PPORT_MESSAGE)&msg,
        &size,
        NULL,
        NULL,
        NULL
    );
    
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Failed to connect to Agent communication port: 0x%X\n", status);
        return status;
    }
    
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Connected to Agent communication port successfully 0x%p\n", AlpcServer->AgentPort);
    return STATUS_SUCCESS;
}

// 消息处理线程函数
VOID AlpcServer_WorkerThread(PVOID Context)
{
    PALPC_SERVER AlpcServer = (PALPC_SERVER)Context;
    NTSTATUS status;
    SIZE_T bufferSize = sizeof(WKDEFENDER_ALPC_MESSAGE) + 1024; // 1024字节的消息数据
    PWKDEFENDER_ALPC_MESSAGE recv_msg = NULL;

    if (!AlpcServer) {
        return;
    }

    // 分配接收缓冲区
    recv_msg = (PWKDEFENDER_ALPC_MESSAGE)ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'ALPC');
    if (!recv_msg) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Failed to allocate buffer for message thread\n");
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WkDefender] ALPC message thread started\n");

    while (AlpcServer->Running) {
        RtlZeroMemory(recv_msg, bufferSize);
        
        // 等待接收消息
        status = WkAlpcSendWaitReceivePort(
            AlpcServer->ServerPort,
            0,
            NULL,
            NULL,
            (PPORT_MESSAGE)recv_msg,
            &bufferSize,
            NULL,
            NULL
        );

        if (!NT_SUCCESS(status)) {
            // 如果端口已断开，退出循环
            if (status == STATUS_PORT_DISCONNECTED) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Agent port disconnected\n");
                break;
            }
            
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Failed to receive message: 0x%X\n", status);
            // 短暂延迟后继续
            KeDelayExecutionThread(KernelMode, FALSE, &(LARGE_INTEGER){-10000000}); // 1秒
            continue;
        }

        // 处理接收到的消息
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Received message: Type=%d, DataLength=%d\n",
            recv_msg->Header.u2.s2.Type, recv_msg->Header.u1.s1.DataLength);

        // 处理来自agent的反向连接请求
        if ((UCHAR)recv_msg->Header.u2.s2.Type == 0xa) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Received connection request from agent\n");
            
            // 批准连接请求
            status = WkAlpcAcceptConnectPort(
                &AlpcServer->AgentBoundPort,
                AlpcServer->ServerPort,
                0,
                NULL,
                NULL,
                NULL,
                (PPORT_MESSAGE)recv_msg,
                NULL,
                TRUE
            );
            
            if (NT_SUCCESS(status)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Connection accepted from agent\n");
                
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Failed to accept connection: 0x%X\n", status);
            }
        } else {
            // 处理其他类型的消息
            // 例如处理来自agent的命令等
        }
    }

    // 释放缓冲区
    if (recv_msg) {
        ExFreePoolWithTag(recv_msg, 'ALPC');
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WkDefender] ALPC message thread stopped\n");
}

// 初始化ALPC服务器
NTSTATUS AlpcServer_Initialize(
    PALPC_SERVER AlpcServer,
    LPCWSTR PortName
)
{
    if (!AlpcServer || !PortName) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WkDefender] Initializing ALPC server...\n");

    // 初始化ALPC函数指针
    NTSTATUS status = InitializeAlpcFunctions();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 初始化服务器结构体
    RtlZeroMemory(AlpcServer, sizeof(ALPC_SERVER));
    wcscpy_s(AlpcServer->PortName, 1024, PortName);
    AlpcServer->Running = FALSE;
    AlpcServer->State = ALPC_SERVER_STATE_STOPPED;

    // 初始化端口和线程
    AlpcServer->AgentPort = NULL;
    AlpcServer->MessageThread = NULL;

    // 创建服务器端口
    UNICODE_STRING port_name;
    OBJECT_ATTRIBUTES obj_attr;
    ALPC_PORT_ATTRIBUTES port_attr;

    RtlInitUnicodeString(&port_name, AlpcServer->PortName);
    InitializeObjectAttributes(&obj_attr, &port_name, 0, NULL, NULL);
    RtlZeroMemory(&port_attr, sizeof(ALPC_PORT_ATTRIBUTES));
    port_attr.MaxMessageLength = 4096; // 与agent项目保持一致

    status = WkAlpcCreatePort(
        &AlpcServer->ServerPort,
        &obj_attr,
        &port_attr
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Failed to create server port: 0x%X\n", status);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WkDefender] ALPC server initialized successfully\n");
    return STATUS_SUCCESS;
}

// 启动ALPC服务器
NTSTATUS AlpcServer_Start(
    PALPC_SERVER AlpcServer
)
{
    if (!AlpcServer) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WkDefender] Starting ALPC server...\n");

    // 连接到Agent（反向连接）
    NTSTATUS status = AlpcServer_ConnectToAgent(AlpcServer);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Failed to connect to Agent: 0x%X\n", status);
        AlpcServer->State = ALPC_SERVER_STATE_ERROR;
        return status;
    }

    AlpcServer->Running = TRUE;
    AlpcServer->State = ALPC_SERVER_STATE_RUNNING;

    // 创建消息处理线程
    NTSTATUS threadStatus = PsCreateSystemThread(
        &AlpcServer->MessageThread,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        AlpcServer_WorkerThread,
        AlpcServer
    );

    if (!NT_SUCCESS(threadStatus)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Failed to create message thread: 0x%X\n", threadStatus);
        AlpcServer->Running = FALSE;
        AlpcServer->State = ALPC_SERVER_STATE_ERROR;
        WkAlpcDisconnectPort(AlpcServer->AgentPort, 0);
        AlpcServer->AgentPort = NULL;
        return threadStatus;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WkDefender] ALPC server started successfully\n");
    return STATUS_SUCCESS;
}

// 停止ALPC服务器
NTSTATUS AlpcServer_Stop(
    PALPC_SERVER AlpcServer
)
{
    if (!AlpcServer) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WkDefender] Stopping ALPC server...\n");

    // 设置运行状态为FALSE，让线程退出
    AlpcServer->Running = FALSE;

    // 等待消息线程退出
    if (AlpcServer->MessageThread) {
        KeWaitForSingleObject(AlpcServer->MessageThread, Executive, KernelMode, FALSE, NULL);
        ZwClose(AlpcServer->MessageThread);
        AlpcServer->MessageThread = NULL;
    }

    // 断开与Agent的连接
    if (AlpcServer->AgentPort) {
        WkAlpcDisconnectPort(AlpcServer->AgentPort, 0);
        AlpcServer->AgentPort = NULL;
    }

    // 关闭服务器端口
    if (AlpcServer->ServerPort) {
        WkAlpcDisconnectPort(AlpcServer->ServerPort, 0);
        AlpcServer->ServerPort = NULL;
    }

    AlpcServer->State = ALPC_SERVER_STATE_STOPPED;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WkDefender] ALPC server stopped successfully\n");
    return STATUS_SUCCESS;
}

// 清理ALPC服务器资源
VOID AlpcServer_Cleanup(
    PALPC_SERVER AlpcServer
)
{
    if (!AlpcServer) {
        return;
    }

    // 停止服务器
    AlpcServer_Stop(AlpcServer);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WkDefender] ALPC server cleaned up successfully\n");
}

// 发送ALPC消息
NTSTATUS AlpcServer_SendMessage(
    _In_ HANDLE PortHandle,
    _In_ PWKDEFENDER_ALPC_MESSAGE Message
)
{
    NTSTATUS status;
    ULONG retryCount = 0;
    const ULONG MAX_RETRIES = 3;
    pfnNtAlpcSendWaitReceivePort func;

    if (!PortHandle || !Message) {
        return STATUS_INVALID_PARAMETER;
    }

    func = ExGetPreviousMode() == UserMode ? ZwAlpcSendWaitReceivePort : WkAlpcSendWaitReceivePort;
    // 尝试发送消息，最多重试MAX_RETRIES次
    while (retryCount < MAX_RETRIES) {
        // 发送复制的消息
        status = func(
            PortHandle,
            0,
            (PPORT_MESSAGE)Message,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
        );

        if (NT_SUCCESS(status)) {
            break; // 发送成功，退出重试循环
        }

        // 发送失败，记录错误
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ALPC Server] Failed to send ALPC message (attempt %d): 0x%X\n", retryCount + 1, status);

        // 如果是端口断开或无效句柄，尝试重新连接
        if (status == STATUS_PORT_DISCONNECTED || status == STATUS_INVALID_HANDLE) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ALPC Server] Port disconnected, attempting to reconnect...\n");
            status = AlpcServer_ConnectToAgent(&g_AlpcServer);
            if (NT_SUCCESS(status)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ALPC Server] Reconnected to Agent successfully\n");
                // 更新PortHandle为新的连接端口
                PortHandle = g_AlpcServer.AgentPort;
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ALPC Server] Failed to reconnect to Agent: 0x%X\n", status);
            }
        }

        // 短暂延迟后重试
        KeDelayExecutionThread(KernelMode, FALSE, &(LARGE_INTEGER){-5000000}); // 500ms
        retryCount++;
    }

    return status;
}

// 发送通知消息到Agent
NTSTATUS AlpcServer_SendNotification(
    _In_ PVOID Package,
    _In_ ULONG PackageSize,
    _In_ WKDEFENDER_MESSAGE_TYPE MessageType,
    _In_ UCHAR Status,
    _In_ UCHAR Response,
    _In_ USHORT ItemCount
)
{
    NTSTATUS status;
    PWKDEFENDER_ALPC_MESSAGE message;

    if (!Package || !PackageSize) {
        return STATUS_INVALID_PARAMETER;
    }

    // 检查Agent是否连接
    if (!g_AlpcServer.AgentPort) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Agent not connected, attempting to connect...\n");
        // 尝试连接Agent
        status = AlpcServer_ConnectToAgent(&g_AlpcServer);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Failed to connect to Agent: 0x%X\n", status);
            return status;
        }
    }

    // 初始化消息
    message = (PWKDEFENDER_ALPC_MESSAGE)Package;
    RtlZeroMemory(message, sizeof(WKDEFENDER_ALPC_MESSAGE));
    message->Header.u1.s1.TotalLength = PackageSize;
    message->Header.u1.s1.DataLength = PackageSize - sizeof(PORT_MESSAGE);
    message->Status = Status;
    message->Response = Response;
    message->ItemCount = ItemCount;
    message->MessageType = MessageType;

    // 发送消息
    return AlpcServer_SendMessage(g_AlpcServer.AgentPort, message);
}

// 获取ALPC服务器状态
ALPC_SERVER_STATE AlpcServer_GetState(
    PALPC_SERVER AlpcServer
)
{
    if (!AlpcServer) {
        return ALPC_SERVER_STATE_ERROR;
    }
    return AlpcServer->State;
}

// 检查Agent是否连接
BOOLEAN AlpcServer_IsAgentConnected(
    PALPC_SERVER AlpcServer
)
{
    if (!AlpcServer) {
        return FALSE;
    }
    return AlpcServer->AgentPort != NULL;
}


NTSTATUS NotificationManager_Initialize()
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Initializing connection manager...\n");

    // 初始化ALPC服务器
    NTSTATUS status = AlpcServer_Initialize(&g_AlpcServer, L"\\RPC Control\\WkDefender@Driver");
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Failed to initialize ALPC server: 0x%X\n", status);
        return status;
    }

    // 启动ALPC服务器
    status = AlpcServer_Start(&g_AlpcServer);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Failed to start ALPC server: 0x%X\n", status);
        AlpcServer_Cleanup(&g_AlpcServer);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Connection manager initialized successfully\n");
    return STATUS_SUCCESS;
}

// 清理连接管理器
VOID CleanupConnectionManager()
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WkDefender] Cleaning up connection manager...\n");
    AlpcServer_Cleanup(&g_AlpcServer);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[WkDefender] Connection manager cleaned up successfully\n");
}

// 通知管理器清理
VOID NotificationManager_Cleanup()
{
    CleanupConnectionManager();
}