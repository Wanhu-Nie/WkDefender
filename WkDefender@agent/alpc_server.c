#include "alpc_server.h"
#include "notification_manager.h"
#include "process_manager.h"

//#include "EventNotifier.h" // 共享事件结构定义

#define MAX_MSG_LEN 0x1000


#pragma comment(lib, "ntdll.lib")   // 获取ALPC相关未导出函数名地址获取



/* ALPC消息请求类型 */
typedef enum _ALPC_MESSAGE_TYPE
{
    LPC_REQUEST=1,
    LPC_REPLY,
    LPC_DATAGRAM,
    LPC_LOST_REPLY,
    LPC_PORT_CLOSED,
    LPC_CLIENT_DIED,
    LPC_EXCEPTION,
    LPC_DEBUG_EVENT,
    LPC_ERROR_EVENT,
    LPC_CONNECTION_REQUEST,
    LPC_CONNECTION_REPLY,
    LPC_CANCELED,
    LPC_UNREGISTER_PROCESS
} ALPC_MESSAGE_TYPE;

typedef struct _ALPC_PORT_ATTRIBUTES
{
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalSectionSize;
    ULONG DupObjectTypes;
    ULONG Reserved;
} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcCreatePort(
    _Out_ PHANDLE PortHandle,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcAcceptConnectPort(
    _Out_ PHANDLE PortHandle,
    _In_ HANDLE ConnectionPortHandle,
    _In_ ULONG Flags,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
    _In_opt_ PVOID PortContext,
    _In_reads_bytes_(ConnectionRequest->u1.s1.TotalLength) PPORT_MESSAGE ConnectionRequest,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes,
    _In_ BOOLEAN AcceptConnection
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcSendWaitReceivePort(
    _In_ HANDLE PortHandle,
    _In_ ULONG Flags,
    _In_reads_bytes_opt_(SendMessage->u1.s1.TotalLength) PPORT_MESSAGE SendMessage,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
    _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ReceiveMessage,
    _Inout_opt_ PSIZE_T BufferLength,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcDisconnectPort(
    _In_ HANDLE PortHandle,
    _In_ ULONG Flags
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcConnectPort(
    _Out_ PHANDLE PortHandle,
    _In_ PCUNICODE_STRING PortName,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
    _In_ ULONG Flags,
    _In_opt_ PSID RequiredServerSid,
    _Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ConnectionMessage,
    _Inout_opt_ PSIZE_T BufferLength,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcCreateSectionView(
    _In_ HANDLE PortHandle,
    _Reserved_ ULONG Flags,
    _Inout_ PALPC_DATA_VIEW_ATTR ViewAttributes
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAlpcCreatePortSection(
    _In_ HANDLE PortHandle,
    _In_ ULONG Flags,
    _In_opt_ HANDLE SectionHandle,
    _In_ SIZE_T SectionSize,
    _Out_ PALPC_HANDLE AlpcSectionHandle,
    _Out_ PSIZE_T ActualSectionSize
);

NTSYSAPI
NTSTATUS
NTAPI
AlpcInitializeMessageAttribute(
    _In_ ULONG AttributeFlags,
    _Out_opt_ PALPC_MESSAGE_ATTRIBUTES Buffer,
    _In_ SIZE_T BufferSize,
    _Out_ PSIZE_T RequiredBufferSize
);

NTSYSAPI
PVOID
NTAPI
AlpcGetMessageAttribute(
    _In_ PALPC_MESSAGE_ATTRIBUTES Buffer,
    _In_ ULONG AttributeFlag
);

/* ALPC同步标识符: Flags */
#define ALPC_MSGFLG_RELEASE_MESSAGE 0x10000     // 不期望对方回复
#define ALPC_MSGFLG_SYNC_REQUEST 0x20000        // 阻塞, 等待对方回复

// 内存分配辅助函数（使用 UtHeapAlloc）
LPVOID AllocHeapMemory(SIZE_T Size)
{
    return UtHeapAlloc(Size);
}

void FreeHeapMemory(LPVOID lpMem)
{
    UtHeapFree(lpMem);
}

// 端口名称配置表
static const WCHAR* g_AlpcPortNames[ALPC_CONNECTION_TYPE_MAX] = {
    L"\\RPC Control\\WkDefender@UI",       // UI端口
    L"\\RPC Control\\WkDefender@Driver",  // Driver端口（模拟）
    L"\\RPC Control\\WkDefender@Helper"   // Helper端口（预留）
};

// 统一的反向连接函数
NTSTATUS AlpcServer_ConnectToPort(
    PALPC_SERVER AlpcServer,
    ALPC_CONNECTION_TYPE ConnectionType,
    BOOLEAN IsSimulation
)
{
    NTSTATUS status;
    UNICODE_STRING port_name;
    
    if (!AlpcServer || ConnectionType >= ALPC_CONNECTION_TYPE_MAX) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 如果已经是模拟模式，直接设置模拟句柄
    if (IsSimulation) {
        printf("[ALPC Server] Simulating connection to %s communication port\n",
               ConnectionType == ALPC_CONNECTION_TYPE_UI ? "UI" :
               ConnectionType == ALPC_CONNECTION_TYPE_DRIVER ? "Driver" : "Helper");
        
        AlpcServer->OutboundPorts[ConnectionType] = (HANDLE)(0x12345678 + ConnectionType);
        
        printf("[ALPC Server] Connected to %s communication port successfully (simulated)\n",
               ConnectionType == ALPC_CONNECTION_TYPE_UI ? "UI" :
               ConnectionType == ALPC_CONNECTION_TYPE_DRIVER ? "Driver" : "Helper");
        return STATUS_SUCCESS;
    }
    
    // 实际连接
    RtlInitUnicodeString(&port_name, g_AlpcPortNames[ConnectionType]);
    
    status = NtAlpcConnectPort(
        &AlpcServer->OutboundPorts[ConnectionType],
        &port_name,
        NULL,
        NULL,
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );
    
    if (!NT_SUCCESS(status))
    {
        printf("[ALPC Server] Failed to connect to %s communication port: 0x%X\n",
               ConnectionType == ALPC_CONNECTION_TYPE_UI ? "UI" :
               ConnectionType == ALPC_CONNECTION_TYPE_DRIVER ? "Driver" : "Helper",
               status);
        return status;
    }
    
    printf("[ALPC Server] Connected to %s communication port successfully\n",
           ConnectionType == ALPC_CONNECTION_TYPE_UI ? "UI" :
           ConnectionType == ALPC_CONNECTION_TYPE_DRIVER ? "Driver" : "Helper");
    return STATUS_SUCCESS;
}



// 处理进程列表请求
NTSTATUS HandleGetProcessListRequest(
    PALPC_SERVER AlpcServer,
    PWKDEFENDER_ALPC_MESSAGE recv_msg
);

// 处理结束进程请求
NTSTATUS HandleKillProcessRequest(
    PALPC_SERVER AlpcServer,
    PWKDEFENDER_ALPC_MESSAGE recv_msg
);

// 处理Driver事件
NTSTATUS HandleDriverEvent(
    PALPC_SERVER AlpcServer,
    PWKDEFENDER_ALPC_MESSAGE recv_msg
);

// 处理Driver事件
NTSTATUS HandleDriverEvent(
    PALPC_SERVER AlpcServer,
    PWKDEFENDER_ALPC_MESSAGE recv_msg
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    // 检查是否是Driver事件消息
    //if (recv_msg->Header.u1.s1.DataLength >= sizeof(EVENT_PACKET_HEADER)) {
    //    PEVENT_PACKET eventPacket = (PEVENT_PACKET)recv_msg->Data;
    //    if (eventPacket->Header.Magic == EVENT_PACKET_MAGIC) {
    //        // 处理Driver事件
    //        printf("[ALPC Server] Received Driver event: Type=%u, Size=%u\n", 
    //               eventPacket->Header.EventType, eventPacket->Header.EventSize);
    //        
    //        // 调用ProcessManager处理Driver事件
    //        status = ProcessManager_ProcessDriverEvent(
    //            eventPacket->Header.EventType,
    //            eventPacket->EventData.RawData,
    //            eventPacket->Header.EventSize
    //        );
    //        
    //        if (!NT_SUCCESS(status)) {
    //            printf("[ALPC Server] Failed to process Driver event: 0x%X\n", status);
    //        }
    //    }
    //}
    
    return status;
}

// 消息处理函数 - 由消息队列线程调用
// 默认消息处理器 - 处理ALPC相关的消息
PVOID AlpcServer_MessageHandler(
    PVOID Context,
    ULONG MessageType,
    PVOID Data
)
{
    PALPC_SERVER alpc_server = (PALPC_SERVER)Context;
    PWKDEFENDER_ALPC_MESSAGE recv_msg = (PWKDEFENDER_ALPC_MESSAGE)Data;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(alpc_server);

    printf("[ALPC Server] Processing message in default handler: Type=0x%X\n", MessageType);

    switch (MessageType) {
    case WKDEFENDER_MSG_GET_SYSTEM_STATUS_REQUEST:
        printf("[ALPC Server] Handling system status request\n");
        status = HandleGetSystemStatusRequest(alpc_server, recv_msg);
        break;

    case WKDEFENDER_MSG_GET_PROCESS_LIST_REQUEST:
        printf("[ALPC Server] Handling process list request\n");
        status = HandleGetProcessListRequest(alpc_server, recv_msg);
        break;

    case WKDEFENDER_MSG_RUN_SCAN_REQUEST:
        printf("[ALPC Server] Handling scan request\n");
        break;

    case WKDEFENDER_MSG_KILL_PROCESS_REQUEST:
        printf("[ALPC Server] Handling kill process request\n");
        status = HandleKillProcessRequest(alpc_server, recv_msg);
        break;

    //case WKDEFENDER_MSG_DRIVER_EVENT:
    //    printf("[ALPC Server] Handling Driver event\n");
    //    status = HandleDriverEvent(alpc_server, recv_msg);
    //    break;

    default:
        printf("[ALPC Server] Unknown message type: 0x%X\n", MessageType);
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    if (recv_msg != NULL) {
        FreeHeapMemory(recv_msg);
    }

    return (PVOID)(ULONG_PTR)status;
}





// ALPC服务器工作线程函数
DWORD WINAPI AlpcServer_WorkerThread(LPVOID lpParam)
{
    SIZE_T size;
    NTSTATUS status;
    PALPC_SERVER alpc_server = (PALPC_SERVER)lpParam;
    PWKDEFENDER_ALPC_MESSAGE recv_msg;

    recv_msg = (PWKDEFENDER_ALPC_MESSAGE)AllocHeapMemory(MAX_MSG_LEN);
    if (!recv_msg) {
        printf("[ALPC Server] Failed to allocate memory for receive message\n");
        return 1;
    }

    printf("[ALPC Server] Worker thread started.\n");
    while (alpc_server->Running) {
        printf("[ALPC Server] Waiting for messages...\n");

        // 接收客户端请求消息
        status = NtAlpcSendWaitReceivePort(
            alpc_server->ServerPort,
            0,
            NULL,
            NULL,
            (PPORT_MESSAGE)recv_msg,
            &size,
            NULL,
            NULL
        );

        if (!NT_SUCCESS(status)) {
            printf("[ALPC Server] Failed to receive message: 0x%X\n", status);
            FreeHeapMemory(recv_msg);
            continue;
        }

        printf("[ALPC Server] Received message\n");
        switch (recv_msg->Header.u2.s2.Type & 0xff) {
        case LPC_REQUEST:
            // 直接通过MessageType进行区分，统一由RouteMessageHandler处理
            printf("[ALPC Server] Handling request message, type: 0x%X\n", recv_msg->MessageType);

            // 路由消息处理
            status = RouteMessageHandler(recv_msg);
            if (!NT_SUCCESS(status)) {
                printf("[ALPC Server] Message handling failed: 0x%X\n", status);
            }
            break;
            
        case LPC_CONNECTION_REQUEST:
            printf("[ALPC Server] Connection request received\n");
           
            // 临时句柄用于接受连接
            HANDLE tempPort;
            status = NtAlpcAcceptConnectPort(
                &tempPort,
                alpc_server->ServerPort,
                0,
                NULL,
                NULL,
                NULL,
                (PPORT_MESSAGE)recv_msg,
                NULL,
                TRUE
            );

            if (!NT_SUCCESS(status)) {
                printf("[ALPC Server] Failed to accept connection: 0x%X\n", status);
                continue;   // 继续监听
            }
            

            // alpc反向链接
            alpc_server->AcceptedPorts[recv_msg->ConnectionType] = tempPort;
            printf("[ALPC Server] Connection accepted and stored as UI connection\n");
            
            status = AlpcServer_ConnectToPort(alpc_server, recv_msg->ConnectionType, FALSE);
            if (!NT_SUCCESS(status)) {
                printf("[ALPC Server] Warning: Failed to connect to Driver communication port, but continuing\n");
            }

            if (recv_msg->ConnectionType == ALPC_CONNECTION_TYPE_DRIVER)
            {
                SIZE_T msg_attr_size;
                PORT_MESSAGE send_msg = { 0 };
                PALPC_MESSAGE_ATTRIBUTES msg_attr;
                PALPC_DATA_VIEW_ATTR sectionViewAttr;

                // 初始化msg_attr/data_view_attr
                AlpcInitializeMessageAttribute(ALPC_MESSAGE_VIEW_ATTRIBUTE, NULL, 0, &msg_attr_size);
                msg_attr = AllocHeapMemory(msg_attr_size);
                AlpcInitializeMessageAttribute(ALPC_MESSAGE_VIEW_ATTRIBUTE, msg_attr, msg_attr_size, &msg_attr_size);
                sectionViewAttr = AlpcGetMessageAttribute(msg_attr, ALPC_MESSAGE_VIEW_ATTRIBUTE);
                alpc_server->SectionViewAttr = sectionViewAttr;

                // 创建Section
                status = NtAlpcCreatePortSection(
                    alpc_server->OutboundPorts[recv_msg->ConnectionType],
                    0, NULL, 1024 * 16,                     
                    &sectionViewAttr->SectionHandle,
                    &sectionViewAttr->ViewSize
                );
                if (!NT_SUCCESS(status)) {
                    printf("[WkDefender] Failed to create server section: 0x%X\n", status);
                    return status;
                }

                // 创建共享视图
                status = NtAlpcCreateSectionView(
                    alpc_server->OutboundPorts[recv_msg->ConnectionType],
                    0, 
                    sectionViewAttr
                );
                if (!NT_SUCCESS(status)) {
                    printf("[WkDefender] Failed to create server section view: 0x%X\n", status);
                    return status;
                }
                printf("[WkDefender@Agent] Section View: 0x%llx\n", sectionViewAttr->ViewBase);

                send_msg.u1.s1.TotalLength = sizeof(PORT_MESSAGE);
                send_msg.u1.s1.DataLength = 0;
                msg_attr->ValidAttributes = ALPC_MESSAGE_VIEW_ATTRIBUTE;

                Sleep(1);
                status = NtAlpcSendWaitReceivePort(
                    alpc_server->OutboundPorts[recv_msg->ConnectionType],
                    0,
                    (PPORT_MESSAGE)&send_msg,
                    msg_attr,
                    NULL,
                    NULL,
                    NULL,
                    NULL
                );

                if (!NT_SUCCESS(status)) {
                    printf("[ALPC Server] Failed to send message: 0x%X\n", status);
                    FreeHeapMemory(msg_attr);
                    return status;
                }

                FreeHeapMemory(msg_attr);
            }
            
            break;

        default:
            printf("[ALPC Server] Unhandled message type: 0x%X\n", recv_msg->Header.u2.s2.Type & 0xff);
        }
        
    }

    printf("[ALPC Server] Worker thread exited\n");
    return 0;
}

// 初始化ALPC服务器
NTSTATUS AlpcServer_Initialize(
    PALPC_SERVER AlpcServer,
    LPCWSTR PortName
)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES obj_attr;
    UNICODE_STRING port_name;
    ALPC_PORT_ATTRIBUTES port_attr;

    if (!AlpcServer || !PortName) {
        return STATUS_INVALID_PARAMETER;
    }

    g_AlpcServer = AlpcServer;

    // 初始化上下文
    ZeroMemory(AlpcServer, sizeof(ALPC_SERVER));
    wcscpy_s(AlpcServer->PortName, MAX_PATH, PortName);
    AlpcServer->State = ALPC_SERVER_STATE_STOPPED;
    AlpcServer->Running = FALSE;
    
    // 初始化接受的连接端口数组
    for (int i = 0; i < ALPC_CONNECTION_TYPE_MAX; i++) {
        AlpcServer->AcceptedPorts[i] = NULL;
    }
    
    // 初始化主动连接的端口数组（反向连接）
    for (int i = 0; i < ALPC_CONNECTION_TYPE_MAX; i++) {
        AlpcServer->OutboundPorts[i] = NULL;
    }

    /* 创建ALPC端口 */
    RtlInitUnicodeString(&port_name, AlpcServer->PortName);
    InitializeObjectAttributes(&obj_attr, &port_name, 0, NULL, NULL);
    ZeroMemory(&port_attr, sizeof(ALPC_PORT_ATTRIBUTES));
    port_attr.MaxMessageLength = MAX_MSG_LEN;

    status = NtAlpcCreatePort(
        &AlpcServer->ServerPort,
        &obj_attr,
        &port_attr
    );

    if (!NT_SUCCESS(status)) {
        printf("[ALPC Server] Failed to create port: 0x%X\n", status);
    } else {
        printf("[ALPC Server] Port created successfully\n");
    }

    printf("[WkDefender] ALPC server initialized successfully\n");
    return STATUS_SUCCESS;

    return status;
}

// 启动ALPC服务器
NTSTATUS AlpcServer_Start(
    PALPC_SERVER AlpcServer
)
{
    NTSTATUS status;

    if (!AlpcServer || AlpcServer->State != ALPC_SERVER_STATE_STOPPED) {
        return STATUS_INVALID_PARAMETER;
    }

    // 启动工作线程: 端口监听
    AlpcServer->Running = TRUE;
    AlpcServer->WorkerItem = CreateThread(
        NULL,
        0,
        AlpcServer_WorkerThread,
        AlpcServer,
        0,
        NULL
    );

    if (!AlpcServer->WorkerItem) {
        printf("[ALPC Server] Failed to create worker thread\n");
        AlpcServer->Running = FALSE;
        MsgQueue_StopProcessing(&g_MessageQueue);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    AlpcServer->State = ALPC_SERVER_STATE_RUNNING;
    printf("[ALPC Server] Started successfully\n");

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

    if (AlpcServer->State != ALPC_SERVER_STATE_RUNNING) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // 停止工作线程
    AlpcServer->Running = FALSE;
    
    if (AlpcServer->WorkerItem) {
        WaitForSingleObject(AlpcServer->WorkerItem, 5000);
        CloseHandle(AlpcServer->WorkerItem);
        AlpcServer->WorkerItem = NULL;
    }

    // 停止消息处理线程
    MsgQueue_StopProcessing(&g_MessageQueue);
    printf("[ALPC Server] Message processing thread stopped\n");

    // 断开所有接受的连接端口（反向连接）
    for (int i = 0; i < ALPC_CONNECTION_TYPE_MAX; i++) {
        if (AlpcServer->AcceptedPorts[i]) {
            NtAlpcDisconnectPort(AlpcServer->AcceptedPorts[i], 0);
            AlpcServer->AcceptedPorts[i] = NULL;
        }
    }
    
    // 断开所有主动连接的端口（反向连接）
    for (int i = 0; i < ALPC_CONNECTION_TYPE_MAX; i++) {
        if (AlpcServer->OutboundPorts[i]) {
            if (i == ALPC_CONNECTION_TYPE_DRIVER) {
                // 模拟断开Driver连接
                printf("[ALPC Server] Disconnecting from Driver communication port (simulated)\n");
            } else {
                // 实际断开其他连接
                NtAlpcDisconnectPort(AlpcServer->OutboundPorts[i], 0);
            }
            AlpcServer->OutboundPorts[i] = NULL;
        }
    }

    if (AlpcServer->ServerPort) {
        NtAlpcDisconnectPort(AlpcServer->ServerPort, 0);
        AlpcServer->ServerPort = NULL;
    }

    AlpcServer->State = ALPC_SERVER_STATE_STOPPED;
    printf("[ALPC Server] Stopped\n");
    return STATUS_SUCCESS;
}

// 清理ALPC服务器资源
VOID AlpcServer_Cleanup(
    PALPC_SERVER AlpcServer
)
{
    if (AlpcServer) {
        if (AlpcServer->State == ALPC_SERVER_STATE_RUNNING) {
            AlpcServer_Stop(AlpcServer);
        }
    }
}

// 发送通知消息到UI
NTSTATUS AlpcServer_SendNotification(
    PALPC_SERVER AlpcServer,
    WKDEFENDER_MESSAGE_TYPE MessageType,
    PVOID pData,
    ULONG DataLength
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    if (!AlpcServer || AlpcServer->State != ALPC_SERVER_STATE_RUNNING || !AlpcServer->OutboundPorts[ALPC_CONNECTION_TYPE_UI]) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // 分配消息内存
    size_t messageSize = sizeof(WKDEFENDER_ALPC_MESSAGE) + DataLength;
    PWKDEFENDER_ALPC_MESSAGE send_msg = (PWKDEFENDER_ALPC_MESSAGE)AllocHeapMemory(messageSize);
    if (!send_msg) {
        return STATUS_NO_MEMORY;
    }

    // 填充消息
    RtlZeroMemory(send_msg, messageSize);
    send_msg->Header.u1.s1.DataLength = (USHORT)(messageSize - sizeof(PORT_MESSAGE));
    send_msg->Header.u1.s1.TotalLength = (USHORT)messageSize;
    send_msg->MessageType = MessageType;
    send_msg->Flags.Bits.Response = FALSE;
    send_msg->ItemCount = 0;
    
    if (pData && DataLength > 0) {
        memcpy(send_msg + 1, pData, DataLength);
    }

    // 发送消息
    status = NtAlpcSendWaitReceivePort(
        AlpcServer->OutboundPorts[ALPC_CONNECTION_TYPE_UI],
        ALPC_MSGFLG_RELEASE_MESSAGE,
        (PPORT_MESSAGE)send_msg,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );

    FreeHeapMemory(send_msg);
    return status;
}

// 发送消息到Driver（模拟实现）
NTSTATUS AlpcServer_SendToDriver(
    PALPC_SERVER AlpcServer,
    WKDEFENDER_MESSAGE_TYPE MessageType,
    PVOID pData,
    ULONG DataLength
)
{
    // 模拟实现：由于Driver暂时不参与调试，直接返回成功
    printf("[ALPC Server] Sending message to Driver: Type=0x%X (simulated)\n", MessageType);
    return STATUS_SUCCESS;
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

// 检查UI是否连接
BOOL AlpcServer_IsUIConnected(
    PALPC_SERVER AlpcServer
)
{
    if (!AlpcServer) {
        return FALSE;
    }
    
    // 检查UI主动连接的端口是否有效
    return (AlpcServer->OutboundPorts[ALPC_CONNECTION_TYPE_UI] != NULL);
}

// 检查Driver是否连接（模拟实现）
BOOL AlpcServer_IsDriverConnected(
    PALPC_SERVER AlpcServer
)
{
    if (!AlpcServer) {
        return FALSE;
    }
    
    // 模拟实现：检查Driver主动连接的端口
    return (AlpcServer->OutboundPorts[ALPC_CONNECTION_TYPE_DRIVER] != NULL);
}

// 处理系统状态请求
NTSTATUS HandleGetSystemStatusRequest(
    PALPC_SERVER AlpcServer,
    PWKDEFENDER_ALPC_MESSAGE recv_msg
)
{
    NTSTATUS status;
    PULONG ptrData;
    
    // 分配响应消息内存（包括数据部分）
    size_t messageSize = sizeof(WKDEFENDER_ALPC_MESSAGE) + 16;
    PWKDEFENDER_ALPC_MESSAGE send_msg = (PWKDEFENDER_ALPC_MESSAGE)AllocHeapMemory(messageSize);
    if (!send_msg) {
        return STATUS_NO_MEMORY;
    }
    
    // 填充响应消息
    RtlZeroMemory(send_msg, messageSize);
    send_msg->Header.u1.s1.DataLength = (USHORT)(messageSize - sizeof(PORT_MESSAGE));
    send_msg->Header.u1.s1.TotalLength = (USHORT)messageSize;
    send_msg->MessageType = WKDEFENDER_MSG_GET_SYSTEM_STATUS_RESPONSE;
    send_msg->Flags.Bits.Response = 0; // 不需要回复
    send_msg->ItemCount = 1;
    
    // 填充系统状态数据
    // 数据格式：uint[4] = {安全状态(0=安全,1=不安全), CPU使用率, 内存使用率, 威胁数量}
    ptrData = send_msg + 1;
    ptrData[0] = 1; // 安全状态：0=安全
    ptrData[1] = 15; // CPU使用率：15%
    ptrData[2] = 30; // 内存使用率：30%
    ptrData[3] = 0;  // 威胁数量：0
    
    // 发送响应消息到接受的UI连接端口
    status = NtAlpcSendWaitReceivePort(
        AlpcServer->OutboundPorts[ALPC_CONNECTION_TYPE_UI],
        0,
        (PPORT_MESSAGE)send_msg,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );
    
    FreeHeapMemory(send_msg);
    return status;
}

// 发送ALPC消息
NTSTATUS AlpcServer_SendMessage(
    _In_ PALPC_SERVER AlpcServer,
    _In_ HANDLE PortHandle,
    _In_ PWKDEFENDER_ALPC_MESSAGE Message
)
{
    NTSTATUS status;

    if (!AlpcServer || !PortHandle || !Message) {
        return STATUS_INVALID_PARAMETER;
    }

    // 发送消息
    status = NtAlpcSendWaitReceivePort(
        PortHandle,
        0,
        (PPORT_MESSAGE)Message,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        printf("[ALPC Server] Failed to send message: 0x%X\n", status);
        return status;
    }

    printf("[ALPC Server] Message sent successfully\n");
    return STATUS_SUCCESS;
}

// 处理进程列表请求
NTSTATUS HandleGetProcessListRequest(
    PALPC_SERVER AlpcServer,
    PWKDEFENDER_ALPC_MESSAGE recv_msg
)
{
    NTSTATUS status;
    PPROCESS_INFO processList = NULL;
    ULONG processCount = 0;
    size_t messageSize = 0;
    PWKDEFENDER_ALPC_MESSAGE send_msg = NULL;
    size_t processDataSize = 0;
    char* processData = NULL;
    size_t processDataOffset = 0;

    // 调用ProcessManager_GetProcessList获取进程信息
    status = ProcessManager_GetProcessList(&processList, &processCount);
    if (!NT_SUCCESS(status)) {
        printf("[ALPC Server] Failed to get process list: 0x%X\n", status);
        return status;
    }

    // 计算进程数据大小
    for (ULONG i = 0; i < processCount; i++) {
        // 构建进程信息字符串：进程名|PID|CPU使用率|内存使用率|文件路径|信任级别|数字签名
        char processInfo[2048];
        sprintf_s(processInfo, sizeof(processInfo), "%s|%d|%.2f|%.2f|%s|%s|%s",
            processList[i].Name,
            processList[i].ProcessId,
            processList[i].CpuUsage,
            processList[i].MemoryUsageMB,
            processList[i].FilePath,
            processList[i].TrustLevel,
            processList[i].DigitalSignature);
        processDataSize += strlen(processInfo) + 1; // 包括null终止符
    }

    // 分配进程数据内存
    if (processDataSize > 0) {
        processData = (char*)AllocHeapMemory(processDataSize);
        if (!processData) {
            if (processList) {
                UtHeapFree(processList);
            }
            return STATUS_NO_MEMORY;
        }

        // 填充进程数据
        for (ULONG i = 0; i < processCount; i++) {
            char processInfo[2048];
            sprintf_s(processInfo, sizeof(processInfo), "%s|%d|%.2f|%.2f|%s|%s|%s",
                processList[i].Name,
                processList[i].ProcessId,
                processList[i].CpuUsage,
                processList[i].MemoryUsageMB,
                processList[i].FilePath,
                processList[i].TrustLevel,
                processList[i].DigitalSignature);
            size_t infoLength = strlen(processInfo) + 1;
            memcpy(processData + processDataOffset, processInfo, infoLength);
            processDataOffset += infoLength;
        }
    }

    // 分配响应消息内存
    messageSize = sizeof(WKDEFENDER_ALPC_MESSAGE) + processDataSize;
    send_msg = (PWKDEFENDER_ALPC_MESSAGE)AllocHeapMemory(messageSize);
    if (!send_msg) {
        if (processData) {
            FreeHeapMemory(processData);
        }
        if (processList) {
            UtHeapFree(processList);
        }
        return STATUS_NO_MEMORY;
    }

    // 填充响应消息
    RtlZeroMemory(send_msg, messageSize);
    send_msg->Header.u1.s1.DataLength = (USHORT)(messageSize - sizeof(PORT_MESSAGE));
    send_msg->Header.u1.s1.TotalLength = (USHORT)messageSize;
    send_msg->MessageType = WKDEFENDER_MSG_GET_PROCESS_LIST_RESPONSE;
    send_msg->Flags.Bits.Response = 0; // 不需要回复
    send_msg->ItemCount = processCount;

    // 复制进程数据到响应消息
    if (processDataSize > 0) {
        memcpy(send_msg + 1, processData, processDataSize);
    }

    // 发送响应消息到接受的UI连接端口
    status = AlpcServer_SendMessage(
        AlpcServer,
        AlpcServer->OutboundPorts[ALPC_CONNECTION_TYPE_UI],
        send_msg
    );

    // 清理内存
    if (processData) {
        FreeHeapMemory(processData);
    }
    if (processList) {
        UtHeapFree(processList);
    }
    if (send_msg) {
        FreeHeapMemory(send_msg);
    }

    return status;
}

// 处理结束进程请求
NTSTATUS HandleKillProcessRequest(
    PALPC_SERVER AlpcServer,
    PWKDEFENDER_ALPC_MESSAGE recv_msg
)
{
    NTSTATUS status;
    
    // 结束进程的具体逻辑由用户负责实现
    // 这里仅发送响应消息
    
    // 分配响应消息内存
    size_t messageSize = sizeof(WKDEFENDER_ALPC_MESSAGE);
    PWKDEFENDER_ALPC_MESSAGE send_msg = (PWKDEFENDER_ALPC_MESSAGE)AllocHeapMemory(messageSize);
    if (!send_msg) {
        return STATUS_NO_MEMORY;
    }
    
    // 填充响应消息
    RtlZeroMemory(send_msg, messageSize);
    send_msg->Header.u1.s1.DataLength = (USHORT)(messageSize - sizeof(PORT_MESSAGE));
    send_msg->Header.u1.s1.TotalLength = (USHORT)messageSize;
    send_msg->Status = 0; // 0: 成功
    send_msg->Flags.Bits.Response = 0; // 不需要回复
    send_msg->MessageType = WKDEFENDER_MSG_KILL_PROCESS_RESPONSE;
    send_msg->ItemCount = 0;
    
    // 发送响应消息到接受的UI连接端口
    status = NtAlpcSendWaitReceivePort(
        AlpcServer->AcceptedPorts[ALPC_CONNECTION_TYPE_UI],
        0,
        (PPORT_MESSAGE)send_msg,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );
    
    // 清理内存
    FreeHeapMemory(send_msg);
    
    return status;
}

// 消息队列测试函数
void MsgQueue_Test()
{
    NTSTATUS status;
    
    printf("[MsgQueue] Starting test...\n");
    ULONG64 memory_dump[] = {
        // ffff9d8f`c4702ef0  
        0x0000000000500028, 0x0000000000000000,
        // ffff9d8f`c4702f00  
        0x0000000000000000, 0x0000000000000000,
        // ffff9d8f`c4702f10  
        0x0000000000000000, 0x0000300300010000,
        // ffff9d8f`c4702f20  
        0x00000000000001a0, 0x0000000000000990,
        // ffff9d8f`c4702f30  
        0x0000000000000000, 0x0000000000000000
    };

    // 直接调用RouteMessageHandler处理模拟的driver消息
    printf("[MsgQueue] Calling RouteMessageHandler for driver event...\n");
    status = RouteMessageHandler(&memory_dump);
    if (NT_SUCCESS(status)) {
        printf("[MsgQueue] RouteMessageHandler succeeded for driver event\n");
    } else {
        printf("[MsgQueue] RouteMessageHandler failed: 0x%X\n", status);
    }
    
    printf("[MsgQueue] Test completed.\n");
}



NTSTATUS AlpcServer_GetMessageAttribute(
    _In_ PALPC_MESSAGE_ATTRIBUTES MessageAttr,
    _In_ ULONG AttributeFlag,
    _Out_ PVOID *Attr
)
{
    if (!MessageAttr || !AttributeFlag || !Attr) {
        return STATUS_INVALID_PARAMETER;
    }

    *Attr = AlpcGetMessageAttribute(MessageAttr, AttributeFlag);
    return STATUS_SUCCESS;
}