#pragma once
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <stdio.h>
// #include <locale.h>
#include <ntstatus.h>

/**************************************************/
/*               兼容回退宏                          */
/**************************************************/
/* SE_*_NAME 字符串宏仅定义于内核头 (wdm.h), 用户态
 * 包含链 (winnt.h) 不提供, 按 wdm.h 取值补全。 */
#ifndef SE_DEBUG_PRIVILEGE_NAME
#define SE_DEBUG_PRIVILEGE_NAME         TEXT("SeDebugPrivilege")
#endif

/**************************************************/
/*               ͳһ�Ѻ����ӿ�                      */
/**************************************************/
#include "Common/Utils.h"

// Agent上下文结构体
typedef struct _WKDEFENDER_AGENT
{
    struct _NOTIFICATION_SERVICE* NotificationManager;   // 通知管理器指针
} WKDEFENDER_AGENT, * PWKDEFENDER_AGENT;

/**************************************************/
/*    与驱动侧 NotificationManager.h 同步的线格式    */
/*    WARNING: 驱动侧修改时此处必须同步更新！         */
/**************************************************/

#define WKD_NOTIFICATION_MAGIC            0x576B4E64  // 'WkNd'
#define WKD_NOTIFICATION_VERSION          3
#define WKD_SYSCALL_MAX_PARAMETERS        8

/* ---- 消息类型枚举（驱动侧 WKD_MESSAGE_TYPE 子集）---- */
/*
 * 内部消息类型枚举 — 与驱动端 WKD_MESSAGE_TYPE 完全对齐
 * Layer 1A: 原始事件层 | Layer 1B: 行为分析层 | Layer 2: 系统级事件 | Layer 3: 通用消息
 */
typedef enum _WKD_MESSAGE_TYPE {
    /* Layer 1A: 原始事件层 */
    WkdMessage_SyscallDetected       = 0x1000,
    WkdMessage_SyscallOpenProcess    = 0x1001,
    WkdMessage_SyscallAllocateMemory = 0x1002,
    WkdMessage_SyscallWriteMemory    = 0x1003,
    WkdMessage_SyscallReadMemory     = 0x1004,
    WkdMessage_SyscallCreateThread   = 0x1005,
    WkdMessage_SyscallMapSection     = 0x1006,
    WkdMessage_SyscallQueueApc       = 0x1007,
    WkdMessage_SyscallSetContextThread = 0x1008,
    WkdMessage_SyscallProtectMemory  = 0x1009,
    WkdMessage_SyscallSuspendThread  = 0x100A,   // NtSuspendThread（线程劫持前置）
    WkdMessage_SyscallResumeThread   = 0x100B,   // NtResumeThread（线程劫持恢复）
    WkdMessage_SyscallAdjustPrivileges = 0x100C, // NtAdjustPrivilegesToken（令牌特权调整，T1134）
    WkdMessage_SyscallDuplicateToken   = 0x100D, // NtDuplicateToken（令牌复制，T1134.001）
    WkdMessage_SyscallSetInformationToken = 0x100E, // NtSetInformationToken（令牌属性修改）
    WkdMessage_SyscallImpersonateThread  = 0x100F, // NtImpersonateThread（线程模拟，T1134.003）
    WkdMessage_SyscallUnmapSection = 0x1010, // NtUnmapViewOfSection（进程镂空 T1055.012，PreAcquireSection 迁移 2026-08）
    WkdMessage_SyscallCreateSection = 0x1011, // NtCreateSection（SectionTracker 迁移 2026-08：匿名可执行/大匿名/无背衬/TxF 检测）

    WkdMessage_MemoryAllocate        = 0x1101,
    WkdMessage_MemoryFree            = 0x1102,
    WkdMessage_MemoryProtect         = 0x1103,

    WkdMessage_RegistrySetValue      = 0x1201,
    WkdMessage_RegistryDeleteValue   = 0x1202,

    WkdMessage_FileCreate            = 0x1301,
    WkdMessage_FileWrite             = 0x1302,
    WkdMessage_FileRename            = 0x1303,  // 文件重命名（FBE 迁移 2026-08）
    WkdMessage_FileDelete            = 0x1304,  // 文件删除（FBE 迁移 2026-08）
    WkdMessage_FileRollbackResult    = 0x1305,  // 回滚结果（FBE 迁移 2026-08）
    WkdMessage_FileShadowCopyDelete  = 0x1306,  // 卷影副本删除（T1490，勒索检测）
    WkdMessage_NamedPipeCreate       = 0x1307,  // 命名管道创建（NamedPipeMonitor 迁移 2026-08）
    WkdMessage_SectionMap            = 0x1308,  // 可执行区段映射（PreAcquireSection 迁移 2026-08）

    WkdMessage_ProcessObjectAccess   = 0x1401,
    WkdMessage_ThreadObjectAccess    = 0x1402,

    /* Layer 1B: 行为分析结果层 */
    WkdMessage_CrossProcessMemoryAccess = 0x2001,
    WkdMessage_CodeInjectionPattern     = 0x2002,
    WkdMessage_ProcessHollowingPattern  = 0x2003,
    WkdMessage_ApcInjectionPattern      = 0x2004,
    WkdMessage_AmsiBypassDetected       = 0x2005,   // AMSI绕过检测（T1562.001）

    WkdMessage_ThreatScoreUpdated    = 0x2201,
    WkdMessage_ThreatLevelChanged    = 0x2202,

    /* Layer 2: 系统级事件 */
    WkdMessage_ProcessCreated        = 0x3001,
    WkdMessage_ProcessExited         = 0x3002,
    WkdMessage_ThreadCreated         = 0x3003,  // 线程创建（本地/远程统一，通过 Flags 区分）
    WkdMessage_ThreadExited          = 0x3004,  // 线程退出
    WkdMessage_ImageLoaded           = 0x3005,
    WkdMessage_RemoteThreadCreated   = 0x3003,  // [已弃用] 使用 WkdMessage_ThreadCreated
    WkdMessage_RemoteThreadExited    = 0x3004,  // [已弃用] 使用 WkdMessage_ThreadExited
    WkdMessage_ProcessSnapshot       = 0x3008,

    /* Layer 3: 通用消息 */
    WkdMessage_SecurityEvent         = 0x4001,
    WkdMessage_SystemStatus          = 0x4002,
    WkdMessage_Error                 = 0x4003,
} WKD_MESSAGE_TYPE;

/* ---- 进程退出事件体（驱动→Agent，线格式，2026-08-25 镜像驱动布局）----
 *  固定大小，不含变长字符串；与 driver NotificationManager.h
 *  WKD_MESSAGE_BODY_PROCESS_EXIT 逐字段一致。 */
typedef struct _WKD_MESSAGE_BODY_PROCESS_EXIT {
    /* === 标识（前置字段） === */
    HANDLE          ProcessId;              // 退出进程 ID
    ULONG           ExitCode;               // 退出码

    /* === 扩展上下文 === */
    HANDLE          ParentProcessId;        // 父进程 ID
    LARGE_INTEGER   CreateTime;             // 创建时间 (代际锚)
    LARGE_INTEGER   ExitTime;               // 退出时间
    ULONG           SessionId;              // 会话 ID
    ULONG           ExitFlags;              // 保留标志位
} WKD_MESSAGE_BODY_PROCESS_EXIT, *PWKD_MESSAGE_BODY_PROCESS_EXIT;

/* ---- 消息头（与驱动侧 WKD_MESSAGE_HEADER 完全一致）---- */
typedef struct _WKD_MESSAGE_HEADER {
    ULONG               Magic;
    ULONG               Version;
    WKD_MESSAGE_TYPE    Type;
    ULONG               Source;
    ULONG               Priority;
    LARGE_INTEGER       Timestamp;
    HANDLE              SourceProcessId;
    HANDLE              TargetProcessId;
    HANDLE              ThreadId;
    ULONG               BodySize;
    ULONG               Flags;
    ULONG               AtomicRisk;         // 当前事件更新后的Ioa得分，用于alpc通知agent
    ULONG               SyncRequestId;      // 0=异步事件, >0=同步阻塞请求(Agent处理完后需回复)
} WKD_MESSAGE_HEADER, *PWKD_MESSAGE_HEADER;

/* ---- 完整消息结构（Header + Body 连续内存）---- */
typedef struct _WKD_MESSAGE {
    WKD_MESSAGE_HEADER  Header;
    UCHAR               Body[ANYSIZE_ARRAY];   /* 实际大小 = Header.BodySize */
} WKD_MESSAGE, *PWKD_MESSAGE;

/* ---- 消息体类型（与驱动侧一致）---- */
typedef struct _WKD_MSG_BODY_SYSCALL {
    ULONG   SyscallNumber;
    ULONG   SyscallCount;
    ULONG   TimeWindowMs;
    ULONG   ParameterNumber;
    ULONG64 ParameterBase[WKD_SYSCALL_MAX_PARAMETERS];
} WKD_MSG_BODY_SYSCALL, *PWKD_MSG_BODY_SYSCALL;

/* ---- AMSI绕过检测消息体（与驱动侧 WKD_MESSAGE_BODY_AMSI_BYPASS 一致）---- */
typedef struct _WKD_MSG_BODY_AMSI_BYPASS {
    HANDLE  ProcessId;
    ULONG   BypassType;                 /* ABD_BYPASS_TYPE */
    PVOID   TargetAddress;
    CHAR    FunctionName[64];
    UCHAR   OriginalBytes[16];
    UCHAR   CurrentBytes[16];
    ULONG   OldProtection;              /* 保护变更: 旧保护 */
    ULONG   NewProtection;              /* 保护变更: 新保护 */
} WKD_MSG_BODY_AMSI_BYPASS, *PWKD_MSG_BODY_AMSI_BYPASS;

typedef struct _WKD_MSG_BODY_OBJECT_ACCESS {
    ACCESS_MASK DesiredAccess;
    ACCESS_MASK SensitiveMask;
} WKD_MSG_BODY_OBJECT_ACCESS, *PWKD_MSG_BODY_OBJECT_ACCESS;

/*
 * 线程事件消息体（驱动→Agent，与驱动侧一致）
 * 通过 Flags bit0=IsRemote, bit1=Create 区分本地/远程和创建/退出
 *
 * 注意: StartRoutine/DesiredAccess/Argument/CreateFlags 在未匹配到
 *       syscall 上下文时全为 0（Agent 侧通过 Argument!=0 判断有效性）
 */
typedef struct _WKD_MESSAGE_BODY_THREAD_CREATE {
    HANDLE ThreadId;                    // 目标线程 ID（tTid）
    HANDLE CreatorThreadId;             // 创建者线程 ID (sTid)

    /* 线程入口 */
    PVOID  StartRoutine;                // 线程入口地址（统一名称，替代原 StartAddress）

    /* syscall 侧关键参数 */
    ULONG  DesiredAccess;               // NtCreateThreadEx 的 DesiredAccess（未匹配=0）
    PVOID  Argument;                    // NtCreateThreadEx 的 Argument（未匹配=0）
    ULONG  CreateFlags;                 // NtCreateThreadEx 的 CreateFlags（未匹配=0）

    /* 内存分析（对齐 PS TnpGetMemoryProtection） */
    ULONG  MemoryProtection;             // 入口点内存保护属性 (PAGE_*)
    ULONG  MemoryProtectionFlags;        // 保留（后续扩展）

    /* 注入分析上下文（对齐 PS TnpAnalyzeThreadCreation） */
    ULONG  CreatorSessionId;            // 创建者会话 ID
    ULONG  TargetSessionId;             // 目标进程会话 ID
    ULONG  InjectIndicators;            // WKD_MSG_INJECT_* 位图
    ULONG  InjectionScore;              // 注入评分 0-1000（agent 回填，内核发送时=0）
    ULONG  RiskLevel;                   // 风险等级（agent 回填，内核发送时=0）

    /* 入口点内存原始字节（供 agent shellcode 模式匹配） */
    UCHAR  StartBytes[128];             // 线程入口点前 128 字节
    ULONG  StartBytesSize;              // 有效字节数（0=未采集）

    /* 时间与标志 */
    LARGE_INTEGER CreateTime;           // 线程创建时间
    ULONG Flags;                        // bit0=IsRemote, bit1=Create
} WKD_MESSAGE_BODY_THREAD_CREATE, *PWKD_MESSAGE_BODY_THREAD_CREATE;

/**************************************************/
/*    进程创建事件体（驱动→Agent，与驱动侧一致）    */
/*                                                  */
/*  单条记录内存布局:                                */
/*    [固定头][ImagePath WCHAR][CommandLine WCHAR]   */
/*    UNICODE_STRING.Buffer 紧随固定头之后           */
/**************************************************/

typedef struct _WKD_MESSAGE_BODY_PROCESS_CREATE {
    HANDLE          ProcessId;
    HANDLE          ParentProcessId;
    LARGE_INTEGER   CreateTime;
    ULONG           SessionId;
    ULONG           IntegrityLevel;
    ULONG           Elevated;
    ULONG           SecurityFlags;
    UNICODE_STRING  ImagePath;          /* Buffer→紧随固定头之后 */
    UNICODE_STRING  CommandLine;        /* Buffer→紧随ImagePath之后 */
} WKD_MESSAGE_BODY_PROCESS_CREATE, *PWKD_MESSAGE_BODY_PROCESS_CREATE;

/**************************************************/
/*    镜像加载事件体（驱动→Agent，与驱动侧一致）    */
/*    单条记录内存布局:                            */
/*    [固定头][ImagePath WCHAR]                     */
/*    UNICODE_STRING.Buffer 紧随固定头之后          */
/**************************************************/

//
// 镜像指示器位（对齐 driver Callbacks/ImageNotify.h IMG_INDICATOR_*）
//
#define WKD_IMG_IND_SUSPICIOUS_PATH   0x00000001
#define WKD_IMG_IND_MASQUERADING_DLL  0x00000002
#define WKD_IMG_IND_LOW_ENTROPY       0x00000004
#define WKD_IMG_IND_HIGH_ENTROPY      0x00000008
#define WKD_IMG_IND_WX_CODE_SECTION   0x00000010
#define WKD_IMG_IND_NO_EXPORTS        0x00000020
#define WKD_IMG_IND_BOOT_IMAGE        0x00000040
#define WKD_IMG_IND_NETWORK_PATH      0x00000080
#define WKD_IMG_IND_DOUBLE_EXTENSION  0x00000100
#define WKD_IMG_IND_TYPOSQUATTING     0x00000200
#define WKD_IMG_IND_UNBACKED          0x00000400
#define WKD_IMG_IND_ENTRYPOINT_OUTSIDE 0x00000800
#define WKD_IMG_IND_SYSTEM_MODULE     0x00001000
#define WKD_IMG_IND_MACHINE_MISMATCH  0x00002000
#define WKD_IMG_IND_DOTNET            0x00004000
#define WKD_IMG_IND_SECURITY_DIR      0x00008000
#define WKD_IMG_IND_TLS_CALLBACK      0x00010000

//
// 镜像签名状态（对齐 driver ImageNotify.h IMG_SIGNATURE_*）
//
#define IMG_SIGNATURE_UNEVALUATED   0   // FileObject 不可用，跳过签名判定（不视为未签名）
#define IMG_SIGNATURE_VALID         1   // CI 签名等级 > SE_SIGNING_LEVEL_UNSIGNED
#define IMG_SIGNATURE_UNSIGNED      2   // 无 CI 缓存或未签名

//
// 镜像加载消息体（驱动→Agent，线格式 v2）
// 2026-08-15 对齐 driver Callbacks/ImageNotify.h（修复布局错位）：
//   - 删除 ProcessId（Pid 在 WKD_MESSAGE_HEADER.SourceProcessId，驱动侧一直填充）
//   - 删除 PeInfo（WKD_IMG_PE_BASIC，驱动 v2 已移除，PE 事实由 agent 自解析）
//
typedef struct _WKD_MESSAGE_BODY_IMAGE_LOAD {
    PVOID           ImageBase;
    SIZE_T          ImageSize;
    UNICODE_STRING  ImagePath;          /* Buffer→紧随固定头之后 */

    /* === 深度分析字段 === */
    ULONG           ImageType;          /* 0=user, 1=kernel */
    ULONG           ImageIndicators;    /* IMG_INDICATOR_* 位图 */
    UCHAR           SignatureStatus;    /* IMG_SIGNATURE_* */
    UCHAR           Reserved[3];

} WKD_MESSAGE_BODY_IMAGE_LOAD, *PWKD_MESSAGE_BODY_IMAGE_LOAD;

/**************************************************/
/*    文件操作事件体（驱动→Agent，与驱动侧一致）     */
/*    用于 WkdMessage_FileWrite/Rename/Delete。     */
/*    [固定头][FilePath WCHAR]                      */
/*    UNICODE_STRING.Buffer 紧随固定头之后          */
/*    OperationType 对齐 WKD_FILE_OP_*              */
/**************************************************/

#define WKD_FILE_OP_WRITE       0
#define WKD_FILE_OP_RENAME      1
#define WKD_FILE_OP_DELETE      2
#define WKD_FILE_OP_TRUNCATE    3
#define WKD_FILE_OP_HARDLINK    4   /* 硬链接创建（FileLinkInformation，PreSetInfo 迁移 2026-08） */
#define WKD_FILE_OP_ATTRIBUTE   5   /* 属性/时间戳/短名变更（FileBasicInformation/ShortName，PreSetInfo 迁移 2026-08） */

typedef struct _WKD_MESSAGE_BODY_FILE_EVENT {
    HANDLE          ProcessId;          /* 操作进程 */
    HANDLE          ThreadId;           /* 操作线程 */
    ULONG           OperationType;      /* WKD_FILE_OP_* */
    ULONG           FileSize;           /* 文件大小（低 32 位） */
    LONGLONG        WriteOffset;        /* 写偏移（-1=未知/非写操作）。对齐 SS PostWrite PW_WRITE_CONTEXT.WriteOffset */
    ULONG           BytesWritten;       /* 写字节数（0=非写操作）。对齐 SS PostWrite BytesWritten */
    ULONG64         FileId;             /* 文件对象 ID（0=未知）。对齐 SS stream context FileId，FileInternalInformation */
    ULONG           FileEntropy;        /* 写缓冲区熵（Q16 定点，0=未知/未采样）。对齐 agent WKD_RANSOM_ENTROPY_Q16 */
    ULONG           Flags;              /* bit0=IsCanary（蜜罐命中）；后续扩展位见 DEF_FILE_FLAG_* */
    LARGE_INTEGER   Timestamp;          /* 操作时间 */
    UNICODE_STRING  FilePath;           /* Buffer→紧随固定头之后 */
} WKD_MESSAGE_BODY_FILE_EVENT, *PWKD_MESSAGE_BODY_FILE_EVENT;

/**************************************************/
/*    回滚结果事件体（驱动→Agent，与驱动侧一致）     */
/*    用于 WkdMessage_FileRollbackResult。          */
/*    Result 值对齐 FBE_ROLLBACK_RESULT            */
/**************************************************/

typedef struct _WKD_MESSAGE_BODY_FILE_ROLLBACK {
    HANDLE          ProcessId;          /* 被回滚进程 */
    ULONG           Result;             /* FBE_ROLLBACK_RESULT */
    ULONG           FilesRestored;      /* 成功恢复文件数 */
} WKD_MESSAGE_BODY_FILE_ROLLBACK, *PWKD_MESSAGE_BODY_FILE_ROLLBACK;

/**************************************************/
/*    命名管道创建事件体（驱动→Agent，与驱动侧一致） */
/*                                                  */
/*  [固定头][PipeName WCHAR]                         */
/*  UNICODE_STRING.Buffer 紧随固定头之后             */
/*  分类/威胁等级/威胁分对齐驱动 NamedPipeMonitor.h   */
/**************************************************/

typedef struct _WKD_MESSAGE_BODY_NAMED_PIPE {
    HANDLE          ProcessId;          /* 创建者进程 */
    HANDLE          ThreadId;           /* 创建线程 */
    ULONG           Classification;     /* 对齐驱动 WKD_NPM_PIPE_CLASS */
    ULONG           ThreatLevel;        /* 对齐驱动 WKD_NPM_THREAT_LEVEL */
    ULONG           ThreatScore;        /* 0-100 */
    ULONG           Flags;              /* bit0=Blocked */
    CHAR            CreatorImageName[16]; /* 创建者镜像名（ANSI 15 字符 + NUL） */
    UNICODE_STRING  PipeName;           /* Buffer→紧随固定头之后 */
} WKD_MESSAGE_BODY_NAMED_PIPE, *PWKD_MESSAGE_BODY_NAMED_PIPE;

/**************************************************/
/*    区段映射事件体（驱动→Agent，与驱动侧一致）     */
/*                                                  */
/*  用于 WkdMessage_SectionMap(0x1308)/             */
/*      WkdMessage_SyscallMapSection(0x1006)/       */
/*      WkdMessage_SyscallUnmapSection(0x1010)。    */
/*  Origin=0 文件轨 / 1 syscall Map / 2 Unmap。     */
/*  [固定头][FilePath WCHAR]（syscall 侧可空）      */
/**************************************************/

typedef struct _WKD_MESSAGE_BODY_SECTION_MAP {
    HANDLE          ProcessId;          /* 目标进程（被映射进程）；Header.Source/Target 为准 */
    HANDLE          ThreadId;           /* 映射线程 */
    ULONG           PageProtection;     /* 请求保护（含 SEC_IMAGE；syscall 侧=Win32Protect） */
    ULONG           SectionType;        /* 0=数据节 1=SEC_IMAGE */
    ULONG           MappingFlags;       /* PAS_MAP_FLAG_* 位图 */
    ULONG           SuspicionScore;     /* 0-100 */
    ULONG           Origin;             /* 0=minifilter 1=syscall Map 2=syscall Unmap */
    ULONG           Flags;              /* bit0=Blocked */
    ULONG64         SectionObject;      /* 内核 Section 对象指针（syscall 轨解析，agent 聚合键/RemoteMap 判定；SectionTracker 迁移 2026-08） */
    ULONG64         SectionHandle;      /* syscall 侧才有 */
    ULONG64         BaseAddress;        /* 映射基址 */
    ULONG64         RegionSize;         /* 视图大小 */
    LARGE_INTEGER   Timestamp;
    UNICODE_STRING  FilePath;           /* Buffer→紧随固定头之后（syscall 侧可空） */
} WKD_MESSAGE_BODY_SECTION_MAP, *PWKD_MESSAGE_BODY_SECTION_MAP;

/**************************************************/
/*    区段创建事件体（驱动→Agent，与驱动侧一致）      */
/*                                                  */
/*  用于 WkdMessage_SyscallCreateSection(0x1011)。  */
/*  SectionTracker 迁移 2026-08（对齐 SS SectionTracker.c）：
/*  5 类怀疑信号判定 + 评分随消息上送，agent 以       */
/*  SectionObject 为键聚合跨进程映射/RemoteMap。     */
/*  ※ 死代码: 依赖驱动 SmInitialize 启用。           */
/**************************************************/

/* 区段怀疑标志位（与驱动侧 WKD_SEC_SUSPICION_* 一致） */
#define WKD_SEC_SUSPICION_NONE              0x00000000
#define WKD_SEC_SUSPICION_TRANSACTED        0x00000001  /* TxF 事务（Doppelganging T1055.013，权重 300） */
#define WKD_SEC_SUSPICION_DELETED           0x00000002  /* DeletePending（Doppelganging 变体，权重 250） */
#define WKD_SEC_SUSPICION_LARGE_ANONYMOUS   0x00000004  /* 匿名 >100MB（权重 80） */
#define WKD_SEC_SUSPICION_EXECUTE_ANONYMOUS 0x00000008  /* 匿名可执行（权重 200） */
#define WKD_SEC_SUSPICION_NO_BACKING_FILE   0x00000010  /* SEC_IMAGE 无文件（权重 180） */

typedef struct _WKD_MESSAGE_BODY_SECTION_CREATE {
    HANDLE          ProcessId;          /* 创建进程（Header.Source 为准） */
    HANDLE          ThreadId;           /* 创建线程 */
    ULONG64         SectionObject;      /* 输出 SectionObject（内核对象指针，agent 聚合键） */
    ULONG64         MaximumSize;        /* 实际值（大匿名判定） */
    ULONG           SectionPageProtection;  /* SectionPageProtection（可执行判定） */
    ULONG           AllocationAttributes;   /* 原始 AllocationAttributes（SEC_IMAGE 位） */
    ULONG           SectionType;        /* 0=数据节 1=SEC_IMAGE */
    ULONG           IsAnonymous;        /* FileHandle==NULL && ObjectAttributes==NULL */
    ULONG           SuspicionFlags;     /* WKD_SEC_SUSPICION_* 位图 */
    ULONG           SuspicionScore;     /* SS 权重和（0-1000） */
    LARGE_INTEGER   Timestamp;
} WKD_MESSAGE_BODY_SECTION_CREATE, *PWKD_MESSAGE_BODY_SECTION_CREATE;

