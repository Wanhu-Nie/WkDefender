#pragma once

#include "../Common/Constants.h"
#include "NotificationManager.h"
#include "MessageQueue.h"
#include "MessageSync.h"

/**************************************************/
/*                ALPC 端口属性                    */
/**************************************************/

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
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

/**************************************************/
/*                PORT_MESSAGE                     */
/**************************************************/

typedef struct _PORT_MESSAGE {
    union {
        struct {
            CSHORT DataLength;
            CSHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;

    union {
        struct {
            CSHORT Type;
            CSHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union {
        CLIENT_ID ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union
    {
        /* 对于超大Alpc包，Length域存在超长截断溢出问题。
         * 此时，Length域置空，暂时启用ClientViewSize域，AlpcSendMessage函数内部负责识别和修复。*/
        SIZE_T ClientViewSize;
        ULONG CallbackId;
    };
} PORT_MESSAGE, *PPORT_MESSAGE;

/**************************************************/
/*              ALPC 消息属性                      */
/**************************************************/

typedef struct _ALPC_MESSAGE_ATTRIBUTES {
    ULONG AllocatedAttributes;
    ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_DATA_VIEW_ATTR {
    ULONG Flags;
    HANDLE SectionHandle;
    PVOID ViewBase;
    SIZE_T ViewSize;
} ALPC_DATA_VIEW_ATTR, *PALPC_DATA_VIEW_ATTR;

/**************************************************/
/*              ALPC 函数指针类型                  */
/**************************************************/

typedef enum _ALPC_DISCONNECT_PORT_FLAGS
{
    ALPC_DISCONNECT_PORT_FLG_DEFAULT = 0x00000000,
    ALPC_DISCONNECT_PORT_FLG_SKIP_PENDING_FLUSH = 0x00000001
} ALPC_DISCONNECT_PORT_FLAGS;

typedef enum _ALPC_PORT_FLAGS
{
    ALPC_PORTFLG_NONE = 0x00000000,
    ALPC_PORTFLG_WOW64_STYLE_HEADER = 0x80000000,
    ALPC_PORTFLG_TOP_MASK = 0xC0000000,
} ALPC_PORT_FLAGS;

typedef enum _ALPC_MESSAGE_FLAGS
{
    ALPC_MSGFLG_REPLY_MESSAGE = 0x00000001,
    ALPC_MSGFLG_LPC_MODE = 0x00000002,
    ALPC_MSGFLG_RELEASE_MESSAGE = 0x00010000,
    ALPC_MSGFLG_SYNC_REQUEST = 0x00020000,
    ALPC_MSGFLG_TRACK_PORT_REFERENCES = 0x00040000,
    ALPC_MSGFLG_WAIT_USER_MODE = 0x00100000,
    ALPC_MSGFLG_WAIT_ALERTABLE = 0x00200000,
    ALPC_MSGFLG_SIGNAL_ALERTABLE = 0x00400000,
    ALPC_MSGFLG_INTERNAL_REJECT = 0x01000000,
    ALPC_MSGFLG_WOW64_CALL = 0x80000000,
} ALPC_MESSAGE_FLAGS;

typedef NTSTATUS(NTAPI* pfnZwAlpcCreatePort)(
    _Out_ PHANDLE PortHandle,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes
    );

typedef NTSTATUS(NTAPI* pfnZwAlpcConnectPort)(
    _Out_ PHANDLE PortHandle,
    _In_ PCUNICODE_STRING PortName,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
    _In_ ALPC_MESSAGE_FLAGS Flags,
    _In_opt_ PSID RequiredServerSid,
    _Inout_updates_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ConnectionMessage,
    _Inout_opt_ PSIZE_T BufferLength,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef NTSTATUS(NTAPI* pfnZwAlpcDisconnectPort)(
    _In_ HANDLE PortHandle,
    _In_ ALPC_DISCONNECT_PORT_FLAGS Flags
    );

typedef NTSTATUS (NTAPI *pfnZwAlpcAcceptConnectPort)(
    _Out_ PHANDLE PortHandle,
    _In_ HANDLE ConnectionPortHandle,
    _In_ ALPC_PORT_FLAGS Flags,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
    _In_opt_ PVOID PortContext,
    _In_reads_bytes_(ConnectionRequest->u1.s1.TotalLength) PPORT_MESSAGE ConnectionRequest,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes,
    _In_ BOOLEAN AcceptConnection
);

typedef NTSTATUS(NTAPI* pfnZwAlpcSendWaitReceivePort)(
    _In_ HANDLE PortHandle,
    _In_ ALPC_MESSAGE_FLAGS Flags,
    _In_reads_bytes_opt_(SendMessage->u1.s1.TotalLength) PPORT_MESSAGE SendMessage,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
    _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ReceiveMessage,
    _Inout_opt_ PSIZE_T BufferLength,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef NTSTATUS(NTAPI* pfnZwAlpcCreatePortSection)(
    _In_ HANDLE PortHandle,
    _In_ ULONG Flags,
    _In_opt_ HANDLE SectionHandle,
    _In_ SIZE_T SectionSize,
    _Out_ HANDLE* AlpcSectionHandle,
    _Out_ PSIZE_T ActualSectionSize
    );

typedef NTSTATUS (NTAPI *pfnZwAlpcCreateSectionView)(
    _In_ HANDLE PortHandle,
    _Reserved_ ULONG Flags,
    _Inout_ PALPC_DATA_VIEW_ATTR ViewAttributes
);

typedef PVOID(NTAPI* pfnAlpcGetMessageAttribute)(
    _In_ PALPC_MESSAGE_ATTRIBUTES Buffer,
    _In_ ULONG AttributeFlag
    );

typedef NTSTATUS(NTAPI* pfnAlpcInitializeMessageAttribute)(
    _In_ ULONG AttributeFlags,
    _Out_opt_ PALPC_MESSAGE_ATTRIBUTES Buffer,
    _In_ SIZE_T BufferSize,
    _Out_ PSIZE_T RequiredBufferSize
    );

/**************************************************/
/*              ALPC 连接类型                      */
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
/*              ALPC 消息类型                      */
/**************************************************/

typedef enum _WKD_ALPC_MESSAGE_TYPE {
    WkdAlpcMsgUnknown = 0,

    /* Alpc 管理 */
    WkdAlpcMessage_PortConnect          = 0x0001,

    WkdAlpcMessage_ProcessCreate        = 0x3001,
    WkdAlpcMessage_ProcessExit          = 0x3002,
    WkdAlpcMessage_ThreadCreate         = 0x3003,
    WkdAlpcMessage_ThreadExit           = 0x3004,
    WkdAlpcMessage_ImageLoad            = 0x3005,
    WkdAlpcMessage_RegistryEvent        = 0x3006,
    WkdAlpcMessage_Syscall              = 0x3007,
    WkdAlpcMessage_ProcessSnapshot      = 0x3008,  /* 进程枚举快照（批量） */
    WkdAlpcMessage_AmsiBypass           = 0x3009,  /* AMSI绕过检测（Driver→Agent） */
    WkdAlpcMessage_FileEvent            = 0x300A,  /* 文件操作事件（FBE 迁移 2026-08，Driver→Agent） */
    WkdAlpcMessage_FileRollbackResult   = 0x300B,  /* 回滚结果（FBE 迁移 2026-08，Driver→Agent） */
    WkdAlpcMessage_NamedPipeEvent       = 0x300C,  /* 命名管道创建（NamedPipeMonitor 迁移 2026-08，Driver→Agent） */
    WkdAlpcMessage_SecurityEvent        = 0x300D,  /* 自保护/安全事件（Driver→Agent，载荷=WKD_MESSAGE_BODY_SECURITY_EVENT。
                                                   * 2026-09-01 自保护桥接接线：此前 WkdMessage_SecurityEvent(0x4001)
                                                   * 在 AlpcSendWkdMessage 无映射落入 Unknown(0)，Agent 收不到；新增映射到
                                                   * 0x300D 并对齐 Agent 端枚举/路由。载荷=整包 WKD_MESSAGE（Header+Body）。 */

    /* 系统调用 */
    WkdAlpcMessage_ThreadOpen           = 0x3101,
    WkdAlpcMessage_MemoryRead           = 0x3102,
    WkdAlpcMessage_MemoryWrite          = 0x3103,

    /* Agent → Driver */
    WkdAlpcMessage_AgentWkdMessageForward   = 0x3100,
    WkdAlpcMessage_RollbackProcessReq   = 0x3104,  /* 回滚进程文件（FBE 迁移 2026-08，Agent→Driver，载荷=ULONG PID） */
    WkdAlpcMessage_ExemptsUpdate        = 0x3105,  /* 排除规则推送（Agent→Driver，载荷=WKD_ALPC_EXEMPT_UPDATE，同步回执 0x3106） */
    WkdAlpcMessage_ExemptsAck           = 0x3106,  /* 排除规则回执（Driver→Agent，载荷=WKD_ALPC_EXEMPT_ACK） */
    WkdAlpcMessage_UnloadPrepareReq     = 0x3107,  /* 受控卸载-准备/恢复（Agent→Driver，载荷=WKD_ALPC_UNLOAD_UPD，同步回执 0x3108） */
    WkdAlpcMessage_UnloadPrepareAck     = 0x3108,  /* 受控卸载回执（Driver→Agent，载荷=WKD_ALPC_UNLOAD_ACK） */

    /* Driver ↔ Agent 共享节控制（与 Agent 端统一） */
    WkdAlpcMessage_SectionViewRequest   = 0x5001,  /* Driver→Agent: 请求创建/扩展共享节 */
    WkdAlpcMessage_SectionViewReady     = 0x5002,  /* Agent→Driver: 共享节就绪通知（携带 ViewAttr） */
    WkdAlpcMessage_SectionDataReady     = 0x5003,  /* Driver→Agent: 数据已写入共享节（携带 ViewBase） */
    WkdAlpcMessage_SyncReply            = 0x5004,  /* Agent→Driver: 统一同步回复（所有同步场景通用） */
    WkdAlpcMessage_PairBitmapUpdate     = 0x5005,  /* Agent→Driver: 进程对位图更新（异步配置通道） */

    /* HandleScanner（ALPC 通信处 TODO）
     * ⚠ 消息号冲突（2026-08 标注）：0x6001/0x6002 与 agent 侧已占用——
     *   agent Notification/AlpcService.h WkdAlpcMsg_ProcessTerminatedNotification=0x6001、
     *   WkdAlpcMsg_ThreatDetectedNotification=0x6002。驱动侧 HandleScan 若需接线
     *   Agent 客户端，必须重分配（建议 0x6201/0x6202 或 0x6006/0x6007），
     *   同时同步两端；当前无 Agent 客户端，暂不激活。 */
    WkdAlpcMessage_HandleScan           = 0x6001,  /* Agent→Driver: 请求句柄扫描 */
    WkdAlpcMessage_HandleScanResult     = 0x6002,  /* Driver→Agent: 句柄扫描结果 */
} WKD_ALPC_MESSAGE_TYPE;

/**************************************************/
/*              ALPC 消息结构体                    */
/**************************************************/

typedef struct _WKD_ALPC_MESSAGE {
    PORT_MESSAGE Header;

    WKD_ALPC_CONNECTION_TYPE ConnectionType;    // 消息源
    WKD_ALPC_MESSAGE_TYPE MessageType;          // 消息类型

    ULONG Status;
    ULONG ItemCount;

    /* flags 域 */
    struct {
        ULONG Response : 1;
        ULONG UseSectionView : 1;
    } Flags;

} WKD_ALPC_MESSAGE, *PWKD_ALPC_MESSAGE;

/**************************************************/
/*              ALPC 服务器状态                    */
/**************************************************/

typedef enum _WKD_ALPC_SERVER_STATE {
    WkdAlpcStateStopped = 0,
    WkdAlpcStateRunning,
    WkdAlpcStateError,
    WkdAlpcStateNotFound
} WKD_ALPC_SERVER_STATE;

/**************************************************/
/*              SectionView 消息数据载荷           */
/**************************************************/

typedef struct _WKD_ALPC_SECTION_VIEW_PAYLOAD {
    ULONG RequestId;          /* 统一同步请求 ID（Agent 回复时原样带回） */
    ULONG SlotIndex;          /* Agent 端共享节槽位索引（DataReady 时归还用） */
    ULONG DataSize;           /* 有效业务数据大小 */
    ULONG Reserved;
} WKD_ALPC_SECTION_VIEW_PAYLOAD, * PWKD_ALPC_SECTION_VIEW_PAYLOAD;

/**************************************************/
/*           统一同步回复消息载荷                    */
/*  WorkerThread 只做 memcpy，不关心 Data 格式      */
/**************************************************/

typedef struct _WKD_ALPC_SYNC_REPLY {
    ULONG   RequestId;           /* 原样带回，Manager 据此定位等待节点 */
    UCHAR   Data[ANYSIZE_ARRAY]; /* 场景特定的回复数据（格式调用方知道） */
} WKD_ALPC_SYNC_REPLY, *PWKD_ALPC_SYNC_REPLY;

/**************************************************/
/*         进程对位图更新消息载荷                    */
/*  Agent→Driver 异步配置通道                       */
/**************************************************/

typedef struct _WKD_ALPC_PAIR_BITMAP_UPDATE {
    HANDLE  SourceProcessId;        /* 源进程 PID */
    HANDLE  TargetProcessId;        /* 目标进程 PID */
    ULONG64 NewBitmap;              /* 0 = 删除此进程对条目 */
} WKD_ALPC_PAIR_BITMAP_UPDATE, *PWKD_ALPC_PAIR_BITMAP_UPDATE;

/**************************************************/
/*        排除规则推送消息载荷                       */
/*  Agent→Driver 热更新通道（排除子系统 Exempts）    */
/*  受 WKD_ALPC_MAX_MESSAGE_SUPPORTED 限制：         */
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
/*        受控卸载消息载荷                          */
/*  Agent→Driver 受控卸载前置命令                    */
/*  BatchOp: 0=Resume(恢复DriverUnload以允许sc stop) */
/*           1=Force(忽略，预留)                     */
/*  该命令触发 AuShutdown，恢复 DriverUnload 后      */
/*  Agent 再执行 sc stop 完成正常清理。              */
/**************************************************/

typedef struct _WKD_ALPC_UNLOAD_UPD {
    ULONG   Version;        /* 命令版本（单调递增） */
    UINT8   BatchOp;        /* 0=Resume(恢复DriverUnload) 1=Force(预留) */
    UINT8   Flags;          /* 保留 */
    ULONG   Reason;         /* 卸载原因码 */
    WCHAR   AuthToken[64];  /* 可选授权令牌（预留） */
} WKD_ALPC_UNLOAD_UPD, *PWKD_ALPC_UNLOAD_UPD;

typedef struct _WKD_ALPC_UNLOAD_ACK {
    ULONG   Version;        /* 原样带回 */
    NTSTATUS Status;        /* 处理结果 */
} WKD_ALPC_UNLOAD_ACK, *PWKD_ALPC_UNLOAD_ACK;

/**************************************************/
/*              ALPC 服务器结构体                  */
/**************************************************/

typedef struct _WKD_ALPC_SERVER {
    WCHAR PortName[MAX_PATH];
    HANDLE ServerPort;
    HANDLE AgentBoundPort;
    HANDLE AgentPort;

    // === 接收线程（接收来自 Agent 的 ALPC 消息） ===
    HANDLE MessageThread;

    volatile BOOLEAN Running;
    WKD_ALPC_SERVER_STATE State;
} WKD_ALPC_SERVER, *PWKD_ALPC_SERVER;

/**************************************************/
/*              全局 ALPC 服务器实例               */
/**************************************************/

extern WKD_ALPC_SERVER WkdDefaultAlpcServer;

/**************************************************/
/*                  函数声明                       */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AlpcCreateServer(
    VOID
);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
AlpcCleanupService(
    VOID
);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AlpcSendMessage(
    _In_opt_ PWKD_ALPC_SERVER AlpcServer,
    _In_ PWKD_ALPC_MESSAGE Message
    );

_IRQL_requires_(PASSIVE_LEVEL)
WKD_ALPC_SERVER_STATE
AlpcGetState(
    _In_ PWKD_ALPC_SERVER Server
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
AlpcIsAgentConnected(
    _In_ PWKD_ALPC_SERVER Server
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AlpcSendWkdMessage(
    _In_ PWKD_MESSAGE Message
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AlpcSendWkdMessageBatch(
    _In_ WKD_ALPC_MESSAGE_TYPE  AlpcMsgType,
    _In_ PWKD_MESSAGE* Messages,
    _In_ ULONG                  MessageCount
    );
