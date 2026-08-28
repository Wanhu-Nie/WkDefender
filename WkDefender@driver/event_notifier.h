#pragma once
#include "framework.h"
#include "process_manager.h"
#include "notification_manager.h"

/*
 * 事件通知模块头文件
 * 功能：定义Driver向Agent发送进程/线程事件通知的数据结构和接口
 * 作者：WkDefender Team
 * 日期：2026-04-09
 */

// 事件类型定义
typedef enum _WKDEFENDER_EVENT_TYPE {
    EVENT_TYPE_PROCESS_CREATE = 1,
    EVENT_TYPE_PROCESS_EXIT,
    EVENT_TYPE_THREAD_CREATE,
    EVENT_TYPE_THREAD_EXIT,
    EVENT_TYPE_API_CALL,
    EVENT_TYPE_MODULE_LOAD,
    EVENT_TYPE_REGISTRY_ACCESS,
    EVENT_TYPE_FILE_ACCESS,
} WKDEFENDER_EVENT_TYPE;

// EVENT_TYPE 到 WKDEFENDER_MESSAGE_TYPE 的映射宏
#define EVENT_TYPE_TO_MESSAGE_TYPE(event_type) ((WKDEFENDER_MESSAGE_TYPE)(0x3000 + (event_type)))

// 威胁等级定义
#define THREAT_LEVEL_NORMAL             0
#define THREAT_LEVEL_LOW                1
#define THREAT_LEVEL_MEDIUM             2
#define THREAT_LEVEL_HIGH               3

// 进程创建事件信息
typedef struct _PROCESS_CREATE_EVENT {
    WKDEFENDER_ALPC_MESSAGE Header;
    HANDLE ProcessId;                    // 进程ID
    HANDLE ParentProcessId;              // 父进程ID
    // ULONG SessionId;                    // 会话ID
    // ULONG ThreatLevel;                  // 威胁等级
    // LARGE_INTEGER CreateTime;           // 创建时间
    struct {
        ULONG Length;
        ULONG Offset;
    } ImageFileName;             // 进程映像名称
    struct {
        ULONG Length;
        ULONG Offset;
    } CommandLine;              // 命令行参数
    // WCHAR ImagePath[256];               // 映像文件路径
    // WCHAR ParentImageName[260];         // 父进程映像名称
} PROCESS_CREATE_EVENT, *PPROCESS_CREATE_EVENT;

// 进程退出事件信息
typedef struct _PROCESS_EXIT_EVENT {
    WKDEFENDER_ALPC_MESSAGE Header;
    ULONG ProcessId;                    // 进程ID
    ULONG ExitCode;                     // 退出代码
    LARGE_INTEGER ExitTime;             // 退出时间
    LARGE_INTEGER UserTime;             // 用户态CPU时间
    LARGE_INTEGER KernelTime;           // 内核态CPU时间
} PROCESS_EXIT_EVENT, *PPROCESS_EXIT_EVENT;

// 线程创建事件信息
typedef struct _THREAD_CREATE_EVENT {
    WKDEFENDER_ALPC_MESSAGE Header;
    ULONG ProcessId;                    // 所属进程ID
    ULONG ThreadId;                     // 线程ID
    ULONG StartAddress;                 // 起始地址
    LARGE_INTEGER CreateTime;           // 创建时间
} THREAD_CREATE_EVENT, *PTHREAD_CREATE_EVENT;

// 线程退出事件信息
typedef struct _THREAD_EXIT_EVENT {
    WKDEFENDER_ALPC_MESSAGE Header;
    ULONG ProcessId;                    // 所属进程ID
    ULONG ThreadId;                     // 线程ID
    ULONG ExitCode;                     // 退出代码
    LARGE_INTEGER ExitTime;             // 退出时间
} THREAD_EXIT_EVENT, *PTHREAD_EXIT_EVENT;

// API调用事件信息
typedef struct _API_CALL_EVENT {
    WKDEFENDER_ALPC_MESSAGE Header;
    ULONG ProcessId;                    // 进程ID
    ULONG ThreadId;                     // 线程ID
    ULONG ApiId;                        // API标识符
    ULONG ParameterCount;               // 参数数量
    LARGE_INTEGER CallTime;             // 调用时间
    WCHAR ApiName[64];                  // API名称
    UCHAR Parameters[256];              // 参数数据（序列化）
} API_CALL_EVENT, *PAPI_CALL_EVENT;

// 通用事件包头
typedef struct _EVENT_PACKET_HEADER {
    ULONG Magic;                        // 魔数：'WKED' (0x574B4544)
    ULONG Version;                      // 版本号
    ULONG EventType;                    // 事件类型
    ULONG EventSize;                    // 事件数据大小
    LARGE_INTEGER Timestamp;            // 时间戳
    GUID EventId;                       // 事件唯一标识
} EVENT_PACKET_HEADER, *PEVENT_PACKET_HEADER;

// 完整事件包
typedef struct _EVENT_PACKET {
    EVENT_PACKET_HEADER Header;         // 包头
    union {
        PROCESS_CREATE_EVENT ProcessCreate;
        PROCESS_EXIT_EVENT ProcessExit;
        THREAD_CREATE_EVENT ThreadCreate;
        THREAD_EXIT_EVENT ThreadExit;
        API_CALL_EVENT ApiCall;
        UCHAR RawData[1];
    } EventData;
} EVENT_PACKET, *PEVENT_PACKET;
#pragma pack(pop)

#define EVENT_PACKET_MAGIC      0x574B4544  // 'WKED'
#define EVENT_PACKET_VERSION    1

// 事件通知管理器上下文
typedef struct _EVENT_NOTIFIER {
    HANDLE AgentPort;                   // 与Agent通信的ALPC端口
    BOOLEAN IsConnected;                // 是否已连接
    FAST_MUTEX Lock;                    // 同步锁
    ULONG TotalEventsSent;              // 发送的事件总数
    ULONG FailedEvents;                 // 发送失败的事件数
} EVENT_NOTIFIER, *PEVENT_NOTIFIER;

// 函数声明

// 初始化事件通知管理器
NTSTATUS InitializeEventNotifier();

// 清理事件通知管理器
VOID CleanupEventNotifier();

// 连接到Agent的ALPC端口
NTSTATUS ConnectToAgentPort();

// 断开与Agent的连接
VOID DisconnectFromAgent();

// 发送事件通知到Agent（通用接口）
NTSTATUS SendEventToAgent(
    _In_ ULONG EventType,
    _In_ PVOID EventData,
    _In_ ULONG EventDataSize
);

// 发送进程创建事件通知
NTSTATUS NotifyProcessCreate(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

// 发送进程退出事件通知
NTSTATUS NotifyProcessExit(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId
);

// 发送线程创建事件通知（预留接口）
NTSTATUS NotifyThreadCreate(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ PVOID StartAddress
);

// 发送线程退出事件通知（预留接口）
NTSTATUS NotifyThreadExit(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ NTSTATUS ExitStatus
);

// 发送API调用事件通知（预留接口）
NTSTATUS NotifyApiCall(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ ULONG ApiId,
    _In_ PCHAR ApiName,
    _In_ PVOID Parameters,
    _In_ ULONG ParameterSize
);

// 获取事件通知统计信息
VOID GetEventNotifierStats(
    _Out_ PULONG TotalEvents,
    _Out_ PULONG FailedEvents
);

// 检查是否已连接到Agent
BOOLEAN IsAgentConnected();
