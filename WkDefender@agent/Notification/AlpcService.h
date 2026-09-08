/**************************************************/
/*  WkDefender Agent — 统一 ALPC 通信模块头文件       */
/*  融合新旧两代架构，提供：                          */
/*   - 基于路由表的消息分发 (RouteMessageHandler)      */
/*   - 共享节池（LRU淘汰 + TTL过期）                  */
/*   - Reactor 模式 Worker 线程                       */
/*  与驱动侧 AlpcService 协议完全兼容                  */
/*  作者: WkDefender Team                           */
/*  版本: 5.0.0                                     */
/**************************************************/

#pragma once

#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <stdio.h>
#include <ntstatus.h>

/**************************************************/
/*               基础类型                           */
/**************************************************/

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(p) ((void)(p))
#endif

#ifndef MAX_PATH
#define MAX_PATH                        256
#endif

#pragma comment(lib, "ntdll.lib")

/**************************************************/
/*               ALPC 消息协议层（LPC层）            */
/**************************************************/

typedef enum _ALPC_PORT_MSG_TYPE {
    LPC_REQUEST                 = 1,
    LPC_REPLY                   = 2,
    LPC_DATAGRAM                = 3,
    LPC_LOST_REPLY              = 4,
    LPC_PORT_CLOSED             = 5,
    LPC_CLIENT_DIED             = 6,
    LPC_EXCEPTION               = 7,
    LPC_DEBUG_EVENT             = 8,
    LPC_ERROR_EVENT             = 9,
    LPC_CONNECTION_REQUEST      = 10,
    LPC_CONNECTION_REPLY        = 11,
    LPC_CANCELED                = 12,
    LPC_UNREGISTER_PROCESS      = 13
} ALPC_PORT_MSG_TYPE;

/**************************************************/
/*               ALPC 同步标识符                    */
/**************************************************/

typedef enum _ALPC_MESSAGE_FLAGS
{
    // Low 2 bits are historical/public ALPC message bits
    ALPC_MSGFLG_REPLY_MESSAGE = 0x00000001,
    ALPC_MSGFLG_LPC_MODE = 0x00000002,

    // High-word message/connect flags
    ALPC_MSGFLG_RELEASE_MESSAGE = 0x00010000, // SendWaitReceive: synchronous-request path rejects this bit when a send message is present; debug/internal-style release semantic.
    ALPC_MSGFLG_SYNC_REQUEST = 0x00020000, // SendWaitReceive: selects AlpcpProcessSynchronousRequest instead of normal send/receive flow.
    ALPC_MSGFLG_TRACK_PORT_REFERENCES = 0x00040000, // SendWaitReceive: increments per-port reference tracking and may signal the tracking event.
    ALPC_MSGFLG_WAIT_USER_MODE = 0x00100000,
    ALPC_MSGFLG_WAIT_ALERTABLE = 0x00200000,
    ALPC_MSGFLG_SIGNAL_ALERTABLE = 0x00400000, // NtAlpcSendWaitReceivePort: passed as the alertable boolean to AlpcpSignal after shifting flags by 0x16.
    ALPC_MSGFLG_INTERNAL_REJECT = 0x01000000, // NtAlpcSendWaitReceivePort: explicit invalid-parameter reject in both sync and send paths.
    ALPC_MSGFLG_WOW64_CALL = 0x80000000,
} ALPC_MESSAGE_FLAGS;

/**************************************************/
/*               ALPC 消息视图属性常量              */
/**************************************************/

#define WKD_ALPC_MESSAGE_HANDLE_ATTR           0x10000000
#define WKD_ALPC_MESSAGE_CONTEXT_ATTR          0x20000000
#define WKD_ALPC_MESSAGE_VIEW_ATTR             0x40000000
#define WKD_ALPC_MESSAGE_SECURITY_ATTR         0x80000000

/**************************************************/
/*               ALPC 最大消息尺寸                  */
/**************************************************/

#define WKD_ALPC_MAX_MESSAGE_SUPPORTED     256

/**************************************************/
/*               ALPC 端口属性                     */
/**************************************************/

typedef struct _ALPC_PORT_ATTRIBUTES {
    ULONG                           Flags;
    SECURITY_QUALITY_OF_SERVICE     SecurityQos;
    SIZE_T                          MaxMessageLength;
    SIZE_T                          MemoryBandwidth;
    SIZE_T                          MaxPoolUsage;
    SIZE_T                          MaxSectionSize;
    SIZE_T                          MaxViewSize;
    SIZE_T                          MaxTotalSectionSize;
    ULONG                           DupObjectTypes;
    ULONG                           Reserved;
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

/**************************************************/
/*               ALPC 消息属性结构                  */
/**************************************************/

typedef struct _ALPC_MSG_ATTRIBUTES {
    ULONG                           AllocatedAttributes;
    ULONG                           ValidAttributes;
} ALPC_MSG_ATTRIBUTES, *PALPC_MSG_ATTRIBUTES;

typedef struct _ALPC_DATA_VIEW_ATTR {
    ULONG                           Flags;
    HANDLE                          SectionHandle;
    PVOID                           ViewBase;           /* 输入时必须为 0 */
    SIZE_T                          ViewSize;
} ALPC_DATA_VIEW_ATTR, *PALPC_DATA_VIEW_ATTR;

/**************************************************/
/*               PORT_MESSAGE (NT 内核定义)         */
/**************************************************/

typedef struct _PORT_MESSAGE {
    union {
        struct {
            USHORT                  DataLength;
            USHORT                  TotalLength;
        } s1;
        ULONG                       Length;
    } u1;
    union {
        struct {
            USHORT                  Type;
            USHORT                  DataInfoOffset;
        } s2;
        ULONG                       ZeroInit;
    } u2;
    union {
        CLIENT_ID                   ClientId;
        double                      DoNotUseThisField;
    };
    ULONG                           MessageId;
    union {
        SIZE_T                      ClientViewSize;
        ULONG                       CallbackId;
    };
} PORT_MESSAGE, *PPORT_MESSAGE;

/**************************************************/
/*              ALPC 连接类型                       */
/*  消息源：标注消息的发送方                        */
/**************************************************/

typedef enum _WKD_ALPC_CONNECTION_TYPE {
    WkdAlpcConnectionUi = 0,
    WkdAlpcConnectionDriver,
    WkdAlpcConnectionHelper,
    WkdAlpcConnectionMax,

    WkdAlpcConnectionUnknow,
    WkdAlpcConnectionAgent,
} WKD_ALPC_CONNECTION_TYPE;

/**************************************************/
/*           业务层消息类型枚举                      */
/*  MessageType 标记消息的操作类型                   */
/**************************************************/

typedef enum _WKD_ALPC_MESSAGE_TYPE {
    WkdAlpcMsg_Unknown                      = 0,

    /* Alpc 管理 */
    WkdAlpcMessage_PortConnect              = 0x0001,

    /* UI ↔ Agent */
    WkdAlpcMsg_GetSystemStatusReq           = 0x1001,
    WkdAlpcMsg_GetProcessListReq            = 0x1002,
    WkdAlpcMsg_RunScanReq                   = 0x1010,   /* 扫描启动 (改号自 0x1003: 与驱动 WkdMessage_SyscallWriteMemory=0x1003 冲突) */
    WkdAlpcMsg_KillProcessReq               = 0x1004,
    WkdAlpcMsg_GetActiveThreatsReq          = 0x1005,   /* VerdictEngine: 活跃威胁列表 */
    WkdAlpcMsg_GetVerdictReq                = 0x1006,   /* VerdictEngine: 按 NodeId 查 Verdict */
    WkdAlpcMsg_RollbackProcessReq           = 0x1007,   /* 回滚进程文件（FBE 迁移 2026-08，UI→Agent） */

    /* Agent → UI */
    WkdAlpcMsg_GetSystemStatusResp          = 0x2001,
    WkdAlpcMsg_GetProcessListResp           = 0x2002,
    WkdAlpcMsg_KillProcessResp              = 0x2004,
    WkdAlpcMsg_GetActiveThreatsResp         = 0x2005,   /* 载荷 = WKD_VERDICT 数组 */
    WkdAlpcMsg_GetVerdictResp               = 0x2006,   /* 载荷 = WKD_VERDICT */
    WkdAlpcMsg_RunScanResponse              = 0x4002,   /* 扫描启动确认 */
    WkdAlpcMsg_ScanProgressNotification     = 0x4003,   /* 扫描进度 (载荷=ULONG 0-100) */
    WkdAlpcMsg_ThreatDetectedNotification   = 0x6002,   /* 单威胁 (载荷=威胁串) */
    WkdAlpcMsg_ScanCompletedNotification    = 0x6003,   /* 扫描完成 (载荷=威胁数 ULONG) */
    WkdAlpcMsg_ProcessTerminatedNotification = 0x6001,   /* 进程已终止通知（裸 PID 载荷） */
    WkdAlpcMsg_SecurityNotification         = 0x6004,
    WkdAlpcMsg_ThreatVerdictNotification    = 0x6005,   /* VerdictEngine: 融合判定通知 (载荷=WKD_VERDICT) */

    /* Driver → Agent */
    WkdAlpcMessage_ProcessCreate          = 0x3001,
    WkdAlpcMessage_ProcessExit            = 0x3002,
    WkdAlpcMessage_ThreadCreate           = 0x3003,
    WkdAlpcMessage_ThreadExit             = 0x3004,
    WkdAlpcMessage_ImageLoad              = 0x3005,
    WkdAlpcMessage_RegistryEvent          = 0x3006,
    WkdAlpcMessage_SyscallEvent           = 0x3007,
    WkdAlpcMessage_ProcessSnapshot        = 0x3008,  /* 进程枚举快照（批量）*/
    WkdAlpcMessage_AmsiBypass             = 0x3009,  /* AMSI绕过检测（Driver→Agent）*/
    WkdAlpcMessage_FileEvent              = 0x300A,  /* 文件操作事件（FBE 迁移 2026-08，Driver→Agent）*/
    WkdAlpcMessage_FileRollbackResult     = 0x300B,  /* 回滚结果（FBE 迁移 2026-08，Driver→Agent，死代码：agent 暂不解析，待 UI 消费接线） */
    WkdAlpcMessage_NamedPipeEvent         = 0x300C,  /* 命名管道创建（NamedPipeMonitor 迁移 2026-08，Driver→Agent）*/
    WkdAlpcMessage_SecurityEvent          = 0x300D,  /* 自保护/安全事件（Driver→Agent，与驱动端 AlpcService 对齐。
                                                     * 2026-09-01 自保护桥接接线：驱动自防护模块（AntiDebug/AntiUnload/
                                                     * IntegrityMonitor/RegistryProtection/CallbackProtection）经
                                                     * WkdReportSelfProtectionEvent → WkdMessage_SecurityEvent(0x4001)
                                                     * 上报，驱动转换层映射到 0x300D 送达。载荷=整包 WKD_MESSAGE
                                                     * （Header+Body，Body=WKD_MESSAGE_BODY_SECURITY_EVENT）。*/

    WkdAlpcMessage_ThreadOpen               = 0x3101,
    WkdAlpcMessage_MemoryRead               = 0x3102,
    WkdAlpcMessage_MemoryWrite              = 0x3103,
    WkdAlpcMessage_RollbackProcessReq       = 0x3104,   /* 回滚进程文件（FBE 迁移 2026-08，Agent→Driver，载荷=ULONG PID） */
    WkdAlpcMessage_ExemptsUpdate            = 0x3105,   /* 排除规则推送（Agent→Driver，载荷=WKD_ALPC_EXEMPT_UPDATE，同步回执 0x3106） */
    WkdAlpcMessage_ExemptsAck               = 0x3106,   /* 排除规则回执（Driver→Agent，载荷=WKD_ALPC_EXEMPT_ACK） */

    /* Agent → Driver */
    WkdAlpcMessage_Command                = 0x4001,

    /* section view 控制 */
    WkdAlpcMessage_SectionViewRequest       = 0x5001,
    WkdAlpcMessage_SectionViewReady         = 0x5002,
    WkdAlpcMessage_SectionDataReady         = 0x5003,   /* 数据已写入共享节通知 */
    WkdAlpcMessage_SyncReply                = 0x5004,   /* Agent→Driver: 统一同步回复 */
    WkdAlpcMessage_PairBitmapUpdate         = 0x5005,   /* Agent→Driver: 进程对位图更新 */
} WKD_ALPC_MESSAGE_TYPE;

/**************************************************/
/*           ALPC 业务消息结构体（线格式，勿改！）   */
/*                                                 */
/*   ConnectionType — 消息源（谁发的）              */
/*   MessageType    — 操作类型（做什么）            */
/*   两者均为独立字段，不再共用 union               */
/**************************************************/

typedef struct _WKD_ALPC_MESSAGE {
    PORT_MESSAGE Header;

    WKD_ALPC_CONNECTION_TYPE ConnectionType;    // 消息源
    WKD_ALPC_MESSAGE_TYPE    MessageType;       // 消息类型

    ULONG Status;
    ULONG ItemCount;

    /* flags 域 */
    struct {
        ULONG Response : 1;
        ULONG UseSectionView : 1;
    } Flags;

} WKD_ALPC_MESSAGE, *PWKD_ALPC_MESSAGE;

/**************************************************/
/*               共享节池参数                       */
/**************************************************/

#define WKD_ALPC_MAX_POOL_SIZE              8       /* 每连接类型最大共享节数 */
#define WKD_ALPC_SECTION_TTL_MS             5000    /* 5 秒空闲超时 */

/**************************************************/
/*               共享节缓存条目                     */
/**************************************************/

typedef struct _WKD_ALPC_SECTION_VIEW {
    BOOLEAN                         Active;             /* 节已分配 */
    BOOLEAN                         Busy;               /* 当前已借出给 Driver */
    LARGE_INTEGER                   LastUsedTime;       /* 最后使用时间 (FileTime) */
    ALPC_DATA_VIEW_ATTR             ViewAttr;           /* ALPC 视图属性（ViewSize 即实际分配大小） */
    ULONG                           AllocCount;         /* 累计分配次数（调试统计） */
} WKD_ALPC_SECTION_VIEW, *PWKD_ALPC_SECTION_VIEW;

/**************************************************/
/*               DataReady 消息数据载荷（线格式）     */
/*   载荷 = SlotIndex(ULONG) + WKD_ALPC_SECTION_VIEW_PAYLOAD */
/**************************************************/

#define WKD_DATA_READY_SLOT_SIZE        sizeof(ULONG)

typedef struct _WKD_ALPC_SECTION_VIEW_PAYLOAD {
    ULONG                       RequestId;          /* 统一同步请求 ID（Driver 端 Manager 定位用） */
    ULONG                       SlotIndex;          /* Agent 端共享节槽位索引 */
    ULONG                       DataSize;           /* 有效业务数据大小 */
    ULONG                       Reserved;
} WKD_ALPC_SECTION_VIEW_PAYLOAD, *PWKD_ALPC_SECTION_VIEW_PAYLOAD;

/**************************************************/
/*           统一同步回复消息载荷                    */
/*  WorkerThread 只做 memcpy，不关心 Data 格式      */
/**************************************************/

typedef struct _WKD_ALPC_SYNC_REPLY {
    ULONG   RequestId;           /* Driver 端 Manager 据此定位等待节点 */
    UCHAR   Data[ANYSIZE_ARRAY]; /* 场景特定的回复数据 */
} WKD_ALPC_SYNC_REPLY, *PWKD_ALPC_SYNC_REPLY;

/**************************************************/
/*         进程对位图更新消息载荷                    */
/**************************************************/

typedef struct _WKD_ALPC_PAIR_BITMAP_UPDATE {
    HANDLE  SourceProcessId;
    HANDLE  TargetProcessId;
    ULONG64 NewBitmap;              /* 0 = 删除此进程对条目 */
} WKD_ALPC_PAIR_BITMAP_UPDATE, *PWKD_ALPC_PAIR_BITMAP_UPDATE;

/**************************************************/
/*        排除规则推送消息载荷（与 Driver 端对齐）    */
/*  每消息 1 条规则，Value 上限 88 WCHAR。           */
/*  BatchOp: 0=Clear+Replace 1=Add 2=Remove 3=Clear  */
/*  RuleType: 0=Path 1=Extension 2=ProcessName       */
/*            3=ProcessId 4=TrustedHash               */
/**************************************************/

typedef struct _WKD_ALPC_EXEMPT_UPDATE {
    ULONG  Version;        /* 规则版本（单调递增） */
    UINT8  BatchOp;        /* 0=Clear+Replace 1=Add 2=Remove 3=Clear */
    UINT8  RuleType;       /* 0=Path 1=Extension 2=ProcessName 3=ProcessId 4=TrustedHash */
    UINT8  Flags;          /* EXEMPT_FLAG_* */
    UINT8  ItemOp;         /* 保留 */
    ULONG  TTLSeconds;     /* 临时排除有效期（0=永久） */
    WCHAR  Value[88];      /* 路径/进程名/扩展名；哈希类型=64 hex 字符；PID 类型=十进制字符串 */
} WKD_ALPC_EXEMPT_UPDATE, *PWKD_ALPC_EXEMPT_UPDATE;

typedef struct _WKD_ALPC_EXEMPT_ACK {
    ULONG   Version;        /* 原样带回 */
    ULONG   AppliedCount;   /* 已应用条目数（Clear+Replace=清除数） */
    NTSTATUS Status;        /* 处理结果 */
} WKD_ALPC_EXEMPT_ACK, *PWKD_ALPC_EXEMPT_ACK;

/**************************************************/
/*               消息路由表                         */
/**************************************************/

/* ALPC 服务器前向声明 */
typedef struct _WKD_ALPC_SERVER WKD_ALPC_SERVER, *PWKD_ALPC_SERVER;

#include "msg_queue.h"

#include "../WkDefenderHeader.h"

typedef NTSTATUS (*PWKD_MESSAGE_HANDLER)(
    _In_ PWKD_ALPC_SERVER        Server,
    _In_ PWKD_MESSAGE            Message,
    _In_opt_ PVOID               Context
    );

/* 入队处理器：将消息复制后入队到指定模块的队列 */
typedef NTSTATUS (*PWKD_ALPC_ENQUEUE_HANDLER)(
    _In_ PWKD_ALPC_SERVER        Server,
    _In_ PWKD_MESSAGE            Message
    );

#define WKD_ALPC_MAX_ROUTES             16

typedef struct _WKD_ALPC_MESSAGE_ROUTE {
    ULONG                       MsgTypeStart;       /* 匹配范围起始（WKD_ALPC_MESSAGE_TYPE 数值） */
    ULONG                       MsgTypeEnd;         /* 匹配范围结束 */
    PWKD_MESSAGE_HANDLER        Handler;            /* 消息处理回调（接收 PWKD_MESSAGE） */
    PVOID                       Context;            /* 回调上下文 */
} WKD_ALPC_MESSAGE_ROUTE, *PWKD_ALPC_MESSAGE_ROUTE;

/**************************************************/
/*               ALPC 服务器状态                    */
/**************************************************/

typedef enum _WKD_ALPC_SERVER_STATE {
    WkdAlpcStateStopped     = 0,
    WkdAlpcStateRunning     = 1,
    WkdAlpcStateError       = 2
} WKD_ALPC_SERVER_STATE;

/**************************************************/
/*               ALPC 服务器结构体                  */
/**************************************************/

typedef struct _WKD_ALPC_SERVER {
    WCHAR                           PortName[MAX_PATH];
    HANDLE                          ServerPort;         /* 监听端口 */
    HANDLE                          AcceptedPorts[WkdAlpcConnectionMax];
    HANDLE                          OutboundPorts[WkdAlpcConnectionMax];

    HANDLE                          WorkerThread;
    volatile BOOLEAN                Running;
    WKD_ALPC_SERVER_STATE            State;
    CRITICAL_SECTION                Lock;

    /* 共享节池 — 每连接类型独立池 */
    WKD_ALPC_SECTION_VIEW           SectionPool[WkdAlpcConnectionMax][WKD_ALPC_MAX_POOL_SIZE];

    /* 消息路由表 */
    WKD_ALPC_MESSAGE_ROUTE          RouteTable[WKD_ALPC_MAX_ROUTES];
    ULONG                           RouteCount;

    /* 统计 */
    volatile LONG64                 TotalRecv;
    volatile LONG64                 TotalRouted;
    volatile LONG64                 TotalDropped;
} WKD_ALPC_SERVER;

/**************************************************/
/*               NtAlpc* 未导出函数声明             */
/**************************************************/

NTSYSAPI
NTSTATUS
NTAPI
NtAlpcCreatePort(
    _Out_ PHANDLE                   PortHandle,
    _In_opt_ POBJECT_ATTRIBUTES     ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES  PortAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
NtAlpcAcceptConnectPort(
    _Out_ PHANDLE                   PortHandle,
    _In_ HANDLE                     ConnectionPortHandle,
    _In_ ULONG                      Flags,
    _In_opt_ POBJECT_ATTRIBUTES     ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES  PortAttributes,
    _In_opt_ PVOID                  PortContext,
    _In_reads_bytes_(ConnectionRequest->u1.s1.TotalLength) PPORT_MESSAGE ConnectionRequest,
    _Inout_opt_ PALPC_MSG_ATTRIBUTES ConnectionMessageAttributes,
    _In_ BOOLEAN                    AcceptConnection
    );

NTSYSAPI
NTSTATUS
NTAPI
NtAlpcSendWaitReceivePort(
    _In_ HANDLE                     PortHandle,
    _In_ ULONG                      Flags,
    _In_reads_bytes_opt_(SendMessage->u1.s1.TotalLength) PPORT_MESSAGE SendMessage,
    _Inout_opt_ PALPC_MSG_ATTRIBUTES SendMessageAttributes,
    _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ReceiveMessage,
    _Inout_opt_ PSIZE_T             BufferLength,
    _Inout_opt_ PALPC_MSG_ATTRIBUTES ReceiveMessageAttributes,
    _In_opt_ PLARGE_INTEGER         Timeout
    );

NTSYSAPI
NTSTATUS
NTAPI
NtAlpcDisconnectPort(
    _In_ HANDLE                     PortHandle,
    _In_ ULONG                      Flags
    );

NTSYSAPI
NTSTATUS
NTAPI
NtAlpcConnectPort(
    _Out_ PHANDLE                   PortHandle,
    _In_ PCUNICODE_STRING           PortName,
    _In_opt_ POBJECT_ATTRIBUTES     ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES  PortAttributes,
    _In_ ULONG                      Flags,
    _In_opt_ PSID                   RequiredServerSid,
    _Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ConnectionMessage,
    _Inout_opt_ PSIZE_T             BufferLength,
    _Inout_opt_ PALPC_MSG_ATTRIBUTES OutMessageAttributes,
    _Inout_opt_ PALPC_MSG_ATTRIBUTES InMessageAttributes,
    _In_opt_ PLARGE_INTEGER         Timeout
    );

NTSYSAPI
NTSTATUS
NTAPI
NtAlpcCreateSectionView(
    _In_ HANDLE                     PortHandle,
    _Reserved_ ULONG                Flags,
    _Inout_ PALPC_DATA_VIEW_ATTR    ViewAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
NtAlpcDeleteSectionView(
    _In_ HANDLE PortHandle,
    _Reserved_ ULONG Flags,
    _In_ PVOID ViewBase
    );

NTSYSAPI
NTSTATUS
NTAPI
NtAlpcCreatePortSection(
    _In_ HANDLE                     PortHandle,
    _In_ ULONG                      Flags,
    _In_opt_ HANDLE                 SectionHandle,
    _In_ SIZE_T                     SectionSize,
    _Out_ PHANDLE                   AlpcSectionHandle,
    _Out_ PSIZE_T                   ActualSectionSize
    );

typedef HANDLE ALPC_HANDLE, * PALPC_HANDLE;
NTSYSAPI
NTSTATUS
NTAPI
NtAlpcDeletePortSection(
    _In_ HANDLE PortHandle,
    _Reserved_ ULONG Flags,
    _In_ ALPC_HANDLE SectionHandle
    );

NTSYSAPI
NTSTATUS
NTAPI
AlpcInitializeMessageAttribute(
    _In_ ULONG                      AttributeFlags,
    _Out_opt_ PALPC_MSG_ATTRIBUTES  Buffer,
    _In_ SIZE_T                     BufferSize,
    _Out_ PSIZE_T                   RequiredBufferSize
    );

NTSYSAPI
PVOID
NTAPI
AlpcGetMessageAttribute(
    _In_ PALPC_MSG_ATTRIBUTES       Buffer,
    _In_ ULONG                      AttributeFlag
    );

/**************************************************/
/*                   函数声明                       */
/**************************************************/

/*
 * AlpcpSectionPoolCleanup
 *   清理指定连接类型的整个池（停止/断连时调用）。
 */
VOID
AlpcpSectionPoolCleanup(
    _Inout_ PWKD_ALPC_SERVER        Server,
    _In_    WKD_ALPC_CONNECTION_TYPE ConnType
    );

NTSTATUS
AlpcCreateServer(
    _In_ PWKD_ALPC_SERVER   Server,
    _In_ LPCWSTR            PortName
    );

NTSTATUS
AlpcStartServer(
    _In_ PWKD_ALPC_SERVER   Server
    );

NTSTATUS
WkdAlpcStopServer(
    _In_ PWKD_ALPC_SERVER   Server
    );

VOID
WkdAlpcCleanup(
    _In_ PWKD_ALPC_SERVER   Server
    );

NTSTATUS
AlpcRegisterRoute(
    _In_ PWKD_ALPC_SERVER           Server,
    _In_ ULONG                      MsgTypeStart,
    _In_ ULONG                      MsgTypeEnd,
    _In_ PWKD_MESSAGE_HANDLER       Handler,
    _In_opt_ PVOID                  Context
    );

NTSTATUS
AlpcSendMessageAsync(
    _In_ PWKD_ALPC_SERVER           Server,
    _In_ WKD_ALPC_CONNECTION_TYPE   ConnType,
    _In_ PWKD_ALPC_MESSAGE          Message,
    _In_opt_ ULONG                  Flags,
    _In_opt_ PALPC_MSG_ATTRIBUTES   MessageAttributes
    );

NTSTATUS
WkdAlpcSendToUi(
    _In_ PWKD_ALPC_SERVER           Server,
    _In_ WKD_ALPC_MESSAGE_TYPE           MsgType,
    _In_opt_ PVOID                  Data,
    _In_ ULONG                      DataLength
    );

NTSTATUS
WkdAlpcSendToUiEx(
    _In_ PWKD_ALPC_SERVER           Server,
    _In_ WKD_ALPC_MESSAGE_TYPE           MsgType,
    _In_opt_ PVOID                  Data,
    _In_ ULONG                      DataLength,
    _In_ BYTE                      StatusByte
    );

NTSTATUS
WkdAlpcSendToDriver(
    _In_ PWKD_ALPC_SERVER           Server,
    _In_ WKD_ALPC_MESSAGE_TYPE           MsgType,
    _In_opt_ PVOID                  Data,
    _In_ ULONG                      DataLength
    );

NTSTATUS
WkdAlpcSendPairBitmapUpdate(
    _In_ PWKD_ALPC_SERVER           Server,
    _In_ HANDLE                     SourceProcessId,
    _In_ HANDLE                     TargetProcessId,
    _In_ ULONG64                    NewBitmap
    );

NTSTATUS
WkdAlpcSendExemptsUpdate(
    _In_ PWKD_ALPC_SERVER              Server,
    _In_ PWKD_ALPC_EXEMPT_UPDATE      Update,
    _Out_opt_ PWKD_ALPC_EXEMPT_ACK    Ack
    );

WKD_ALPC_SERVER_STATE
WkdAlpcGetState(
    _In_ PWKD_ALPC_SERVER           Server
    );

BOOLEAN
WkdAlpcIsDriverConnected(
    _In_ PWKD_ALPC_SERVER           Server
    );

BOOLEAN
WkdAlpcIsUiConnected(
    _In_ PWKD_ALPC_SERVER           Server
    );

/**************************************************/
/*               全局 ALPC 服务器实例               */
/**************************************************/

extern WKD_ALPC_SERVER WkdDefaultAlpcServer;

/**************************************************/
/*          ALPC 路由通用入队助手                    */
/**************************************************/

/*
 * WkdMsgQueueAlpcHandler
 *   通用消息路由处理器：将已解包的 WKD_MESSAGE 入队到模块的 WKD_MSG_QUEUE。
 *   可直接作为 PWKD_MESSAGE_HANDLER 传给 AlpcRegisterRoute。
 *   Context 参数必须指向 PWKD_MSG_QUEUE 实例。
 */
NTSTATUS
WkdMsgQueueAlpcHandler(
    _In_ PWKD_ALPC_SERVER       Server,
    _In_ PWKD_MESSAGE           Message,
    _In_opt_ PVOID              Context
    );
