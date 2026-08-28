#pragma once
#include "framework.h"

typedef struct _ALPC_PORT_ATTRIBUTES {
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    ULONG MaxMessageLength;
    ULONG MemoryBandwidth;
    ULONG MaxPoolUsage;
    ULONG MaxSectionSize;
    ULONG MaxViewSize;
    ULONG MaxTotalSectionSize;
    ULONG DupObjectTypes;
    ULONG Reserved;
} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

typedef struct _PORT_MESSAGE {
    union {
        struct {
            CSHORT DataLength;      // 数据部分的长度 (不包括头部)
            CSHORT TotalLength;     // 整个消息的总长度 (包括头部)
        } s1;
        ULONG Length;               // 总长度 (s1 的另一种访问方式)
    } u1;

    union {
        struct {
            CSHORT Type;            // 消息类型 (如连接请求、数据消息等)
            CSHORT DataInfoOffset;  // 数据信息偏移量 (用于视图)
        } s2;
        ULONG ZeroInit;             // 保留，必须为 0
    } u2;

    union {
        CLIENT_ID ClientId;         // 发送方的进程/线程 ID
        double DoNotUseThisField;   // 强制 8 字节对齐
    };

    ULONG MessageId;                // 消息 ID (用于匹配请求和回复)
    union {
        ULONG CallbackId;           // 回调 ID (如果启用了回调)
        ULONG Reserved;             // 保留
    };

    ULONG64 Reserved2;               // 宽度对齐差异
} PORT_MESSAGE, * PPORT_MESSAGE;

// ALPC消息属性
typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
    ULONG AllocatedAttributes;
    ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

// ALPC函数指针类型
typedef NTSTATUS (NTAPI* pfnNtAlpcConnectPort)(
    PHANDLE PortHandle,
    PCUNICODE_STRING PortName,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PALPC_PORT_ATTRIBUTES PortAttributes,
    ULONG Flags,
    PSID RequiredServerSid,
    PPORT_MESSAGE ConnectionMessage,
    PSIZE_T BufferLength,
    PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
    PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
    PLARGE_INTEGER Timeout
);

typedef NTSTATUS (NTAPI* pfnNtAlpcSendWaitReceivePort)(
    HANDLE PortHandle,
    ULONG Flags,
    PPORT_MESSAGE SendMessage,
    PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
    PPORT_MESSAGE ReceiveMessage,
    PSIZE_T BufferLength,
    PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
    PLARGE_INTEGER Timeout
);

typedef NTSTATUS (NTAPI* pfnNtAlpcCreatePort)(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PALPC_PORT_ATTRIBUTES PortAttributes
);

typedef NTSTATUS (NTAPI* pfnNtAlpcAcceptConnectPort)(
    PHANDLE PortHandle,
    HANDLE ConnectionPortHandle,
    ULONG Flags,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PALPC_PORT_ATTRIBUTES PortAttributes,
    PVOID PortContext,
    PPORT_MESSAGE ConnectionRequest,
    PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes,
    BOOLEAN AcceptConnection
);

typedef NTSTATUS (NTAPI* pfnNtAlpcDisconnectPort)(
    HANDLE PortHandle,
    ULONG Flags
);

// 外部ALPC函数指针
extern pfnNtAlpcConnectPort NtAlpcConnectPort;
extern pfnNtAlpcSendWaitReceivePort NtAlpcSendWaitReceivePort;
extern pfnNtAlpcCreatePort NtAlpcCreatePort;
extern pfnNtAlpcAcceptConnectPort NtAlpcAcceptConnectPort;
extern pfnNtAlpcDisconnectPort NtAlpcDisconnectPort;

// ALPC服务器状态
typedef enum _ALPC_SERVER_STATE {
    ALPC_SERVER_STATE_STOPPED,
    ALPC_SERVER_STATE_RUNNING,
    ALPC_SERVER_STATE_ERROR
} ALPC_SERVER_STATE;

// ALPC连接类型
typedef enum _ALPC_CONNECTION_TYPE {
    ALPC_CONNECTION_TYPE_UI = 0,
    ALPC_CONNECTION_TYPE_DRIVER = 1,
    ALPC_CONNECTION_TYPE_HELPER = 2,
    ALPC_CONNECTION_TYPE_MAX = 3
} ALPC_CONNECTION_TYPE;

// 消息类型枚举（统一所有通信的消息类型）
typedef enum _WKDEFENDER_MESSAGE_TYPE {
    // 通用消息
    WKDEFENDER_MSG_UNKNOWN = 0,
    
    // UI -> Agent 消息
    WKDEFENDER_MSG_GET_SYSTEM_STATUS_REQUEST = 0x1001,
    WKDEFENDER_MSG_GET_PROCESS_LIST_REQUEST = 0x1002,
    WKDEFENDER_MSG_RUN_SCAN_REQUEST = 0x1003,
    WKDEFENDER_MSG_KILL_PROCESS_REQUEST = 0x1004,
    
    // Agent -> UI 消息
    WKDEFENDER_MSG_GET_SYSTEM_STATUS_RESPONSE = 0x2001,
    WKDEFENDER_MSG_GET_PROCESS_LIST_RESPONSE = 0x2002,
    WKDEFENDER_MSG_KILL_PROCESS_RESPONSE = 0x2004,
    WKDEFENDER_MSG_SECURITY_ACTION_NOTIFICATION = 0x6004,
    
    // Driver -> Agent 消息
    WKDEFENDER_MSG_DRIVER_PROCESS_CREATE = 0x3001,
    
    // Agent -> Driver 消息
    WKDEFENDER_MSG_DRIVER_COMMAND = 0x4001,
    
    // 进程和线程相关消息
    WKDEFENDER_ALPC_MSG_PROCESS_CREATE = 0x1005,
    WKDEFENDER_ALPC_MSG_PROCESS_EXIT = 0x1006,
    WKDEFENDER_ALPC_MSG_THREAD_CREATE = 0x1007,
    WKDEFENDER_ALPC_MSG_THREAD_EXIT = 0x1008,
    
    // 日志相关消息
    WKDEFENDER_ALPC_MSG_LOG_EVENT = 0x3002
} WKDEFENDER_MESSAGE_TYPE;

// 通用ALPC消息结构 <核心结构体, 请勿更改>
typedef struct _WKDEFENDER_ALPC_MESSAGE {
    PORT_MESSAGE Header;
    UCHAR Status;
    UCHAR Response;
    USHORT ItemCount;
    union {
        ALPC_CONNECTION_TYPE ConnectionType;    // 连接请求时使用
        WKDEFENDER_MESSAGE_TYPE MessageType;    // 普通消息时使用
    };
} WKDEFENDER_ALPC_MESSAGE, * PWKDEFENDER_ALPC_MESSAGE;

// ALPC服务器结构体
typedef struct _ALPC_SERVER {
    WCHAR PortName[256];
    HANDLE ServerPort;                              // 服务器监听端口（主动授权）
    HANDLE AgentBoundPort;                         // 与Agent绑定的Port
    HANDLE AgentPort;                               // 与Agent的连接端口
    HANDLE WorkerItem;
    HANDLE MessageThread;                           // 消息处理线程
    BOOLEAN Running;
    ALPC_SERVER_STATE State;
} ALPC_SERVER, * PALPC_SERVER;

// 初始化ALPC服务器
NTSTATUS AlpcServer_Initialize(
    PALPC_SERVER AlpcServer,
    LPCWSTR PortName
);

// 启动ALPC服务器
NTSTATUS AlpcServer_Start(
    PALPC_SERVER AlpcServer
);

// 停止ALPC服务器
NTSTATUS AlpcServer_Stop(
    PALPC_SERVER AlpcServer
);

// 清理ALPC服务器资源
VOID AlpcServer_Cleanup(
    PALPC_SERVER AlpcServer
);

// 发送通知消息到Agent
NTSTATUS AlpcServer_SendNotification(
    _In_ PVOID Package,
    _In_ ULONG PackageSize,
    _In_ WKDEFENDER_MESSAGE_TYPE MessageType,
    _In_ UCHAR Status,
    _In_ UCHAR Response,
    _In_ USHORT ItemCount
);

// 获取ALPC服务器状态
ALPC_SERVER_STATE AlpcServer_GetState(
    PALPC_SERVER AlpcServer
);

// 检查Agent是否连接
BOOLEAN AlpcServer_IsAgentConnected(
    PALPC_SERVER AlpcServer
);

// 发送ALPC消息
NTSTATUS AlpcServer_SendMessage(
    _In_ HANDLE PortHandle,
    _In_ PWKDEFENDER_ALPC_MESSAGE Message
);

// 统一的反向连接函数
NTSTATUS AlpcServer_ConnectToPort(
    PALPC_SERVER AlpcServer,
    WKDEFENDER_MESSAGE_TYPE ConnectionType
);

// 初始化通知管理器
NTSTATUS NotificationManager_Initialize();

// 清理通知管理器
VOID NotificationManager_Cleanup();


// 发送进程创建事件通知
NTSTATUS NotifyProcessCreate(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
);