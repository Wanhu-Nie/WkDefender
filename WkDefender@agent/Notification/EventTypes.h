/**************************************************/
/*  WkDefender 事件系统 — 事件类型定义               */
/*  WKD_EVENT_HEADER + 所有载荷类型                 */
/**************************************************/

#pragma once

#include "../DefendTypes.h"

/**************************************************/
/*               事件类型枚举                       */
/**************************************************/

typedef enum _WKD_EVENT_TYPE {
    WkdEvent_Unknown            = 0,

    /* 进程生命周期 */
    WkdEvent_ProcessCreate      = 0x1001,
    WkdEvent_ProcessExit        = 0x1002,
    WkdEvent_ProcessOpen        = 0x1003,

    /* 线程 */
    WkdEvent_ThreadCreate       = 0x2001,
    WkdEvent_ThreadExit         = 0x2002,
    WkdEvent_RemoteThreadCreate = 0x2003,
    WkdEvent_QueueApc           = 0x2004,  /* APC 注入: 需驱动补 NtQueueApcThread case */
    WkdEvent_ThreadSuspend      = 0x2005,  /* 线程劫持: 需驱动补 NtSuspendThread case */
    WkdEvent_ThreadResume       = 0x2006,  /* 线程劫持: 需驱动补 NtResumeThread case */
    WkdEvent_SetThreadContext   = 0x2007,  /* 镂空/劫持: 需驱动补 NtSetContextThread case */
    WkdEvent_TokenAdjustPrivileges = 0x2008, /* 令牌特权调整（T1134，PrivilegeMonitor 迁移） */
    WkdEvent_TokenDuplicate       = 0x2009, /* 令牌复制（T1134.001） */
    WkdEvent_TokenSetInformation  = 0x200A, /* 令牌属性修改（T1134） */
    WkdEvent_TokenImpersonate     = 0x200B, /* 线程模拟（T1134.003） */

    /* 文件 */
    WkdEvent_FileCreate         = 0x3001,
    WkdEvent_FileWrite          = 0x3002,
    WkdEvent_FileDelete         = 0x3003,
    WkdEvent_FileRename         = 0x3004,  /* 文件重命名（FBE 迁移 2026-08） */
    WkdEvent_FileShadowCopyDelete = 0x3007, /* 卷影副本删除（T1490，勒索检测）。
                                             * 原 0x3005 与 WkdEvent_ImageLoad 冲突
                                             * （后者有消费方：IoaCarsalGraph/IoaFsmEngine），
                                             * 改号 0x3007 避让（PreSetInfo 迁移 2026-08）。 */
    WkdEvent_ImageLoad          = 0x3005,
    WkdEvent_NamedPipeCreate    = 0x3006,  /* 命名管道创建（NamedPipeMonitor 迁移 2026-08） */

    /* 注册表 */
    WkdEvent_RegSetValue        = 0x4001,
    WkdEvent_RegDeleteValue     = 0x4002,
    WkdEvent_RegCreateKey       = 0x4003,

    /* 网络 */
    WkdEvent_NetworkConnect     = 0x5001,
    WkdEvent_NetworkListen      = 0x5002,

    /* 内存 */
    WkdEvent_MemoryAllocate     = 0x6001,
    WkdEvent_MemoryProtect      = 0x6002,
    WkdEvent_MemoryWrite        = 0x6003,
    WkdEvent_MemoryRead         = 0x6004,
    WkdEvent_MapViewOfSection   = 0x6005,  /* 区段映射注入: 需驱动补 NtMapViewOfSection case */
    WkdEvent_UnmapViewOfSection = 0x6006,  /* 进程镂空: 需驱动补 NtUnmapViewOfSection case */
    WkdEvent_SectionCreate      = 0x6007,  /* Section 创建（SectionTracker 迁移 2026-08: 匿名可执行/大匿名/无背衬/TxF，需驱动补 NtCreateSection case） */

    /* Syscall */
    WkdEvent_SyscallAggregated  = 0x7001,

    /* IOC */
    WkdEvent_IocHashMatch       = 0x8001,
    WkdEvent_IocYaraMatch       = 0x8002,
    WkdEvent_IocCertMatch       = 0x8003,
    WkdEvent_AmsiBypass         = 0x8004,  /* AMSI 绕过检测（T1562.001，驱动 AmsiBypassDetector） */

    /* 系统 */
    WkdEvent_SystemHeartbeat    = 0x9001,
} WKD_EVENT_TYPE, *PWKD_EVENT_TYPE;

/**************************************************/
/*               事件头                             */
/**************************************************/

typedef struct _WKD_EVENT_HEADER {
    GUID                EventId;
    DEF_EVENT_CLASS     Class;
    WKD_EVENT_TYPE      Type;
    ULONG               SchemaVersion;
    LARGE_INTEGER       Timestamp;
    LARGE_INTEGER       IngestTime;
    GUID                SourceProcessId;    /* IOA 回填: 父进程 NodeId */
    GUID                TargetProcessId;    /* IOA 回填: 子进程 NodeId */
    ULONG               Confidence;
    DEF_IOC_SOURCE      IocSource;
    ULONG               BehaviorFlags;
    DEF_THREAT_SEVERITY Severity;
    ULONG               PayloadSize;
} WKD_EVENT_HEADER, *PWKD_EVENT_HEADER;

/**************************************************/
/*               进程创建载荷                       */
/**************************************************/

typedef struct _EVENT_PAYLOAD_PROCESS_CREATE {
    HANDLE              ProcessId;
    LARGE_INTEGER       CreateTime;
    HANDLE              ParentProcessId;
    LARGE_INTEGER       ParentCreateTime;
    ULONG               SessionId;
    ULONG               IntegrityLevel;
    BOOLEAN             IsElevated;
    BOOLEAN             Amd64;
    BOOLEAN             IsProtectedProcess;
    UCHAR               Reserved;
    /* 嵌入式扁平布局 (2026-08-25, 与 WKD_MESSAGE_BODY_* 同构):
     * UNICODE_STRING.Buffer → 紧随本载荷之后的 WCHAR 数据区,
     * 排布序 = 字段声明序 (ImagePath → CommandLine → ImageFileName),
     * Length=0 表示缺失; PayloadSize 含数据区总长 (整块归档依赖)。 */
    UNICODE_STRING      ImagePath;
    UNICODE_STRING      CommandLine;
    UNICODE_STRING      ImageFileName;
    DEF_SHA256_HASH     ImageHash;
} EVENT_PAYLOAD_PROCESS_CREATE, *PEVENT_PAYLOAD_PROCESS_CREATE;

/**************************************************/
/*               进程退出载荷                       */
/**************************************************/

typedef struct _EVENT_PAYLOAD_PROCESS_EXIT {
    /* 2026-08-25 与 WKD_MESSAGE_BODY_PROCESS_EXIT 线格式同构
     * (原 UserTime/KernelTime 无消费方, 移除) */
    HANDLE              ProcessId;          /* 退出进程 ID */
    ULONG               ExitCode;           /* 退出码 (NTSTATUS 口径) */
    HANDLE              ParentProcessId;    /* 父进程 (PID 复用关联) */
    LARGE_INTEGER       CreateTime;         /* 创建时间 (代际锚) */
    LARGE_INTEGER       ExitTime;           /* 退出时间 */
    ULONG               SessionId;          /* 会话 ID */
    ULONG               ExitFlags;          /* 驱动保留标志位 */
} EVENT_PAYLOAD_PROCESS_EXIT, *PEVENT_PAYLOAD_PROCESS_EXIT;

/**************************************************/
/*               文件操作事件载荷                   */
/**************************************************/

/*
 * 文件写/重命名/删除事件（WkdMessage_FileWrite/Rename/Delete → WkdEvent_FileWrite
 * /FileRename/FileDelete）。来源为驱动 FBE（FileBackupEngine 迁移 2026-08），
 * 载荷前两字段 (SourceProcessId/TargetProcessId) 与 EVENT_PAYLOAD_SYSCALL 布局一致，
 * 使 IoaObserve 阶段1 可经文件事件专用 case 解析节点（文件事件为单进程，Target=同源）。
 * FilePath 指向紧随固定头之后的 UNICODE_STRING（复用 WKD_MESSAGE_BODY_FILE_EVENT
 * 扁平布局，驱动已按此线格式上送）。
 */
/*
 * 文件事件 Flags 位定义（驱动上送 WKD_MESSAGE_BODY_FILE_EVENT.Flags → 载荷 Flags）
 */
#define DEF_FILE_FLAG_CANARY        0x00000001  /* 蜜罐（canary）文件命中 */

typedef struct _EVENT_PAYLOAD_FILE_EVENT {
    HANDLE              SourceProcessId;    /* 操作进程 (sPid) */
    HANDLE              TargetProcessId;    /* 同源（单进程事件） */
    ULONG               OperationType;      /* WKD_FILE_OP_WRITE/RENAME/DELETE/TRUNCATE */
    ULONG               FileSize;           /* 文件大小（低 32 位） */
    LONGLONG            WriteOffset;        /* 写偏移（-1=未知/非写操作）。对齐 SS PostWrite PW_WRITE_CONTEXT.WriteOffset */
    ULONG               BytesWritten;       /* 写字节数（0=非写操作）。对齐 SS PostWrite BytesWritten */
    ULONG64             FileId;             /* 文件对象 ID（0=未知）。对齐 SS stream context FileId */
    ULONG               FileEntropy;        /* 写缓冲区熵（Q16 定点，0=未知）。对齐 WKD_RANSOM_ENTROPY_Q16 */
    ULONG               Flags;              /* DEF_FILE_FLAG_* 位图（bit0=Canary） */
    LARGE_INTEGER       Timestamp;          /* 操作时间 */
    UNICODE_STRING      FilePath;           /* 嵌入式: Buffer→载荷后路径数据 */
} EVENT_PAYLOAD_FILE_EVENT, *PEVENT_PAYLOAD_FILE_EVENT;

/**************************************************/
/*              命名管道创建事件载荷                 */
/**************************************************/

/*
 * 命名管道创建（WkdMessage_NamedPipeCreate → WkdEvent_NamedPipeCreate）。
 * 来源为驱动 NamedPipeMonitor（minifilter IRP_MJ_CREATE_NAMED_PIPE，2026-08 迁移）。
 * 载荷前两字段 (SourceProcessId/TargetProcessId) 与 EVENT_PAYLOAD_SYSCALL 布局一致，
 * 使 IoaObserve 阶段1 可经单进程事件 case 解析节点（Target=同源）。
 * PipeName 指向紧随固定头之后的 UNICODE_STRING（复用 WKD_MESSAGE_BODY_NAMED_PIPE
 * 扁平布局，驱动已按此线格式上送）。
 * 分类常量对齐驱动 WKD_NPM_PIPE_CLASS（IoaObserve 阶段4.10 消费）。
 */
#define DEF_NPM_CLASS_UNKNOWN          0
#define DEF_NPM_CLASS_SYSTEM           1
#define DEF_NPM_CLASS_KNOWN_APP        2
#define DEF_NPM_CLASS_C2_COBALT        3
#define DEF_NPM_CLASS_C2_METERPRETER   4
#define DEF_NPM_CLASS_C2_PSEXEC        5
#define DEF_NPM_CLASS_C2_IMPACKET      6
#define DEF_NPM_CLASS_C2_GENERIC       7
#define DEF_NPM_CLASS_HIGH_ENTROPY     8
#define DEF_NPM_CLASS_SUSPICIOUS       9
#define DEF_NPM_CLASS_SPOOFED_SYSTEM   10

/**************************************************/
/*              镜像加载事件载荷                     */
/**************************************************/

/*
 * 镜像加载（WkdMessage_ImageLoaded(0x3005) → WkdEvent_ImageLoad(0x3005)）。
 * 2026-08-09 镜像职责收敛：驱动 L0 采集 PE 头+节事实、CI 签名状态、ImageInfo 标志，
 * 无签名或非白名单镜像无条件上送；agent 侧复用 ScanManager.ScanFileDirect 全量校验
 * （签名/哈希/熵/YARA 全在扫描链内，熵由 agent 重新解析文件计算）。
 * 载荷前两字段 (SourceProcessId/TargetProcessId) 与 EVENT_PAYLOAD_SYSCALL 布局一致，
 * 使 IoaObserve 阶段1 可经 default 分支解析节点（单进程事件，Target=同源）。
 * ImagePath 指向载荷后路径数据（内联 UNICODE_STRING，Buffer 紧随载荷固定头）。
 */
typedef struct _EVENT_PAYLOAD_IMAGE_LOAD {
    HANDLE              SourceProcessId;    /* 加载进程 (sPid) */
    HANDLE              TargetProcessId;    /* 同源（单进程事件） */
    PVOID               ImageBase;          /* 镜像基址 */
    SIZE_T              ImageSize;          /* 镜像大小 */
    ULONG               ImageType;          /* 0=user, 1=kernel */
    ULONG               ImageIndicators;    /* IMG_INDICATOR_* 位图 */
    UCHAR               SignatureStatus;    /* IMG_SIGNATURE_*（CI 缓存签名判定） */
    UCHAR               Reserved[3];
    BOOLEAN             Valid;          /* 驱动解析 DOS+NT 签名校验通过 */
    BOOLEAN             IsDll;              /* IMAGE_FILE_DLL */
    USHORT              NumberOfSections;   /* 节数（agent 解析参考） */
    ULONG               SectionAlignment;   /* 节对齐 */
    ULONG               FileAlignment;      /* 文件对齐 */
    UNICODE_STRING      ImagePath;          /* 嵌入式: Buffer→载荷后路径数据 */
} EVENT_PAYLOAD_IMAGE_LOAD, *PEVENT_PAYLOAD_IMAGE_LOAD;

typedef struct _EVENT_PAYLOAD_NAMED_PIPE {
    HANDLE              SourceProcessId;    /* 创建者进程 (sPid) */
    HANDLE              TargetProcessId;    /* 同源（单进程事件） */
    ULONG               Classification;     /* DEF_NPM_CLASS_* */
    ULONG               ThreatLevel;        /* 对齐驱动 WKD_NPM_THREAT_LEVEL */
    ULONG               ThreatScore;        /* 0-100 */
    ULONG               Flags;              /* bit0=Blocked */
    WCHAR               CreatorImageName[16]; /* 创建者镜像名（ANSI→WCHAR） */
    UNICODE_STRING      PipeName;           /* 嵌入式: Buffer→载荷后管道名数据 */
} EVENT_PAYLOAD_NAMED_PIPE, *PEVENT_PAYLOAD_NAMED_PIPE;

/**************************************************/
/*               Syscall 聚合载荷                   */
/**************************************************/

typedef struct _EVENT_PAYLOAD_SYSCALL {
    HANDLE              SourceProcessId;    // 创建者进程 ID (sPid)
    HANDLE              TargetProcessId;    // 创建者线程 ID (tPid)
    ULONG               SyscallNumber;
    ULONG               RepeatCount;
    ULONG               TimeWindowMs;
    ULONG               OverallScore;
    ULONG               ParameterNumber;
    ULONG64             ParameterBase[8];
} EVENT_PAYLOAD_SYSCALL, *PEVENT_PAYLOAD_SYSCALL;

/**************************************************/
/*              区段映射事件载荷                     */
/**************************************************/

/*
 * 代码执行映射（WkdMessage_SectionMap(0x1308)/SyscallMapSection(0x1006)/
 * SyscallUnmapSection(0x1010) → WkdEvent_MapViewOfSection(0x6005)/
 * UnmapViewOfSection(0x6006)）。PreAcquireSection 迁移 2026-08。
 * 来源为驱动 minifilter AcquireSection（文件轨，Origin=0）或 SyscallHijack
 * （跨进程注入轨，Origin=1/2）。
 * 载荷前两字段 (SourceProcessId/TargetProcessId) 与 EVENT_PAYLOAD_SYSCALL 布局一致，
 * 使 IoaObserve 阶段1 可经 default 分支解析节点（文件轨 Target=同源，syscall 轨
 * 跨进程 Source≠Target → 建进程对）。FilePath 指向载荷后路径数据（syscall 侧可空）。
 */
typedef struct _EVENT_PAYLOAD_SECTION_MAP {
    HANDLE              SourceProcessId;    /* 源进程（映射发起者） */
    HANDLE              TargetProcessId;    /* 目标进程（被映射进程） */
    HANDLE              ThreadId;           /* 映射线程 */
    ULONG               PageProtection;     /* 请求保护（含 SEC_IMAGE；syscall 侧=Win32Protect） */
    ULONG               SectionType;        /* 0=数据节 1=SEC_IMAGE */
    ULONG               MappingFlags;       /* PAS_MAP_FLAG_* 位图 */
    ULONG               SuspicionScore;     /* 0-100 */
    ULONG               Origin;             /* 0=minifilter 1=syscall Map 2=syscall Unmap */
    ULONG               Flags;              /* bit0=Blocked */
    ULONG64             SectionHandle;      /* syscall 侧才有 */
    ULONG64             BaseAddress;        /* 映射基址 */
    ULONG64             RegionSize;         /* 视图大小 */
    LARGE_INTEGER       Timestamp;
    UNICODE_STRING      FilePath;           /* 嵌入式: Buffer→载荷后路径（syscall 侧可空） */
} EVENT_PAYLOAD_SECTION_MAP, *PEVENT_PAYLOAD_SECTION_MAP;

/**************************************************/
/*              区段创建事件载荷                     */
/**************************************************/

/*
 * Section 创建（WkdMessage_SyscallCreateSection(0x1011) → WkdEvent_SectionCreate(0x6007)）。
 * SectionTracker 迁移 2026-08（对齐 SS SectionTracker.c SecTrackSectionCreate）。
 * 驱动在 NtCreateSection Exit 时 deref 输出 SectionHandle 得 SectionObject（内核对象指针），
 * 解析输入参数做 5 类怀疑信号判定（匿名可执行 200/大匿名 80/无背衬 180/TxF 事务 300/
 * DeletePending 250），评分对齐 SS SecpUpdateSuspicionScore 权重和 + ≥3 标志组合加成。
 * 载荷前两字段 (SourceProcessId/TargetProcessId) 与 EVENT_PAYLOAD_SYSCALL 布局一致，
 * 使 IoaObserve 阶段1 可经 default 分支解析节点（创建为单进程事件，Target=同源）。
 * SectionObject 为聚合键：IoaInjectionClassifier 共享 Section 聚合表按它关联
 * WkdEvent_MapViewOfSection 的跨进程映射（RemoteMap 三方判定）。
 * ※ 死代码: 依赖驱动 SmInitialize 启用。
 */
typedef struct _EVENT_PAYLOAD_SECTION_CREATE {
    HANDLE              SourceProcessId;    /* 创建进程 (sPid) */
    HANDLE              TargetProcessId;    /* 同源（单进程事件） */
    HANDLE              ThreadId;           /* 创建线程 */
    ULONG64             SectionObject;      /* 输出 SectionObject（内核对象指针，聚合键） */
    ULONG64             MaximumSize;        /* 实际值（大匿名判定） */
    ULONG               SectionPageProtection;  /* SectionPageProtection（可执行判定） */
    ULONG               AllocationAttributes;   /* 原始 AllocationAttributes（SEC_IMAGE 位） */
    ULONG               SectionType;        /* 0=数据节 1=SEC_IMAGE */
    ULONG               IsAnonymous;        /* FileHandle==NULL && ObjectAttributes==NULL */
    ULONG               SuspicionFlags;     /* WKD_SEC_SUSPICION_* 位图 */
    ULONG               SuspicionScore;     /* SS 权重和（0-1000） */
    LARGE_INTEGER       Timestamp;
} EVENT_PAYLOAD_SECTION_CREATE, *PEVENT_PAYLOAD_SECTION_CREATE;

/**************************************************/
/*               AMSI 绕过检测载荷                   */
/*  注意: 前两字段 SourceProcessId/TargetProcessId  */
/*       布局约定 — IoaObserve 阶段1 default 分支   */
/*       按此读取 pid，不得调整顺序。               */
/**************************************************/

typedef struct _EVENT_PAYLOAD_AMSI_BYPASS {
    HANDLE              SourceProcessId;    // 被检测进程 PID
    HANDLE              TargetProcessId;    // 同源（AMSI bypass 为单进程事件）
    ULONG               BypassType;         // ABD_BYPASS_TYPE
    ULONG64             TargetAddress;      // 被补丁函数地址/保护变更区域基址
    WCHAR               FunctionName[64];   // AmsiScanBuffer 等 / "(protection-change)"
    UCHAR               CurrentBytes[16];   // 当前序言字节
    ULONG               OldProtection;      // 保护变更: 旧保护
    ULONG               NewProtection;      // 保护变更: 新保护
} EVENT_PAYLOAD_AMSI_BYPASS, *PEVENT_PAYLOAD_AMSI_BYPASS;

/**************************************************/
/*               线程事件载荷                       */
/**************************************************/

typedef struct _EVENT_PAYLOAD_THREAD_CREATE {
    HANDLE              ProcessId;          // 目标进程 ID
    HANDLE              ThreadId;           // 线程 ID
    HANDLE              CreatorProcessId;   // 创建者进程 ID (sPid)
    HANDLE              CreatorThreadId;    // 创建者线程 ID (sTid)
    PVOID               StartRoutine;       // 线程入口地址（统一名称，替代原 StartAddress）
    PVOID               Argument;           // NtCreateThreadEx 的 Argument（未匹配=NULL）
    ULONG               DesiredAccess;      // NtCreateThreadEx 的 DesiredAccess（未匹配=0）
    ULONG               CreateFlags;        // NtCreateThreadEx 的 CreateFlags（未匹配=0）
    LARGE_INTEGER       CreateTime;         // 创建时间
    ULONG               Flags;              // bit0=IsRemote, bit1=Create

    /* === 注入分析（对齐 PS TnpAnalyzeThreadCreation） === */
    ULONG               MemoryProtection;    // 入口点内存保护属性 (PAGE_*)
    ULONG               CreatorSessionId;   // 创建者会话 ID
    ULONG               TargetSessionId;    // 目标进程会话 ID
    ULONG               InjectIndicators;   // WKD_MSG_INJECT_* 位图
    ULONG               InjectionScore;     // 注入评分 0-1000
    ULONG               RiskLevel;          // 风险等级

    /* === 入口点内存原始字节（供 shellcode 模式匹配，对齐 PS TnpCheckShellcodePatterns） === */
    UCHAR               StartBytes[128];    // 线程入口点前 128 字节
    ULONG               StartBytesSize;     // 有效字节数

    /* === 起始地址归属结论（driver IocDetectThread 计算，经 ALPC 上送） === */
    BOOLEAN             IsUnusualEntry;     // 起始地址未落在已知模块内
    BOOLEAN             IsStartAddrBacked;  // 起始地址为 MEM_IMAGE 文件映射
} EVENT_PAYLOAD_THREAD_CREATE, *PEVENT_PAYLOAD_THREAD_CREATE;

/**************************************************/
/*              线程退出事件载荷                     */
/**************************************************/

/*
 * 线程退出事件（WkdMessage_ThreadExited → WkdEvent_ThreadExit=0x2002）。
 * 载荷来源为 WKD_MESSAGE_BODY_THREAD_CREATE（Flags bit1=Create=0）。
 * 前两字段 (SourceProcessId/TargetProcessId) 与 EVENT_PAYLOAD_SYSCALL 布局一致，
 * 使 IoaObserve default 分支（IoaEngine.c L984-998）无需修改即完成节点解析
 * （srcNode=创建者，tgtNode=线程所属进程）。
 * ExitTime/UserTime/KernelTime 驱动消息体未含（线格式零变更约束），不在此暴露。
 */
typedef struct _EVENT_PAYLOAD_THREAD_EXIT {
    HANDLE              SourceProcessId;    /* 创建者进程 ID (sPid) */
    HANDLE              TargetProcessId;    /* 线程所属进程 ID (tPid) */
    HANDLE              ThreadId;           /* 线程 ID */
    HANDLE              CreatorThreadId;    /* 创建者线程 ID (sTid) */
    LARGE_INTEGER       CreateTime;         /* 线程创建时间 */
    ULONG               Flags;              /* bit0=IsRemote（bit1=Create 恒 0） */
} EVENT_PAYLOAD_THREAD_EXIT, *PEVENT_PAYLOAD_THREAD_EXIT;

/**************************************************/
/*               APC 队列事件载荷                   */
/**************************************************/

/*
 * NtQueueApcThread 载荷 (T1055.004 / T1055.009 AtomBombing)。
 *
 * 前两字段 (SourceProcessId/TargetProcessId) 与 EVENT_PAYLOAD_SYSCALL 布局一致,
 * 使 IoaObserve default 分支 (IoaEngine.c L835-839) 无需修改即完成节点解析。
 * ApcRoutine 为 AtomBombing 精准判定的核心信号 (命中 GlobalGetAtomName 等)。
 * 数据源状态: 需驱动补 NtQueueApcThread syscall 参数解析 (ParameterBase
 *   [0]=ThreadHandle, [1]=ApcRoutine, [2..4]=ApcArgument1/2/3), 当前未发送,
 *   ApcRoutine==0 时分类器原子判定自然不触发, 不引入误报。
 */
typedef struct _EVENT_PAYLOAD_QUEUE_APC {
    HANDLE              SourceProcessId;    /* APC 队列发起进程 (sPid) */
    HANDLE              TargetProcessId;    /* APC 目标进程 (tPid) */
    HANDLE              ThreadId;           /* APC 目标线程 */
    ULONG_PTR           ApcRoutine;         /* APC 例程地址 (AtomBombing 命中原子检索 API) */
    ULONG_PTR           ApcArgument1;       /* 参数1 (AtomBombing: 原子句柄) */
    ULONG_PTR           ApcArgument2;       /* 参数2 */
    ULONG_PTR           ApcArgument3;       /* 参数3 */
} EVENT_PAYLOAD_QUEUE_APC, *PEVENT_PAYLOAD_QUEUE_APC;

/**************************************************/
/*               线程操作事件载荷                    */
/**************************************************/

/*
 * NtSetContextThread / NtSuspendThread / NtResumeThread 统一载荷
 * （线程劫持时序 T1055.003: Suspend→SetContext→Resume）。
 *
 * 前两字段 (SourceProcessId/TargetProcessId) 与 EVENT_PAYLOAD_SYSCALL 布局一致,
 * 使 IoaObserve default 分支 (IoaEngine.c L835-839) 无需修改即完成节点解析。
 * ThreadId 来自 WKD_MESSAGE_HEADER.ThreadId（驱动 ShpResolveThreadTarget 回填），
 * 时序状态按 (SourceProcessId, TargetProcessId, ThreadId) 三元组关联。
 * ThreadHandle 供 W4 线程上下文验证工具重开句柄读取寄存器。
 * 数据源状态: 需驱动补 NtSetContextThread/NtSuspendThread/NtResumeThread
 *   syscall case + 参数解析 (ParameterBase[0]=ThreadHandle)。
 */
typedef struct _EVENT_PAYLOAD_THREAD_OP {
    HANDLE              SourceProcessId;    /* 发起进程 (sPid) */
    HANDLE              TargetProcessId;    /* 目标进程 (tPid) */
    HANDLE              ThreadId;           /* 目标线程 TID */
    ULONG_PTR           ThreadHandle;       /* 目标线程句柄值（W4 重开句柄读取上下文用） */
} EVENT_PAYLOAD_THREAD_OP, *PEVENT_PAYLOAD_THREAD_OP;

/**************************************************/
/*               令牌操作事件载荷                    */
/**************************************************/

/*
 * NtAdjustPrivilegesToken / NtDuplicateToken / NtSetInformationToken /
 * NtImpersonateThread 统一载荷（令牌操纵 T1134 / 提权 T1548，
 * PrivilegeMonitor 迁移 2026-08-06）。
 *
 * 前两字段 (SourceProcessId/TargetProcessId) 与 EVENT_PAYLOAD_SYSCALL 布局一致,
 * 使 IoaObserve default 分支无需修改即完成节点解析。
 * 驱动侧令牌句柄无进程反查 → 非模拟类 OpType 的 TargetProcessId 回退源进程;
 * Impersonate 为被模拟线程 (ClientThreadHandle) 所属进程 (真实目标)。
 * 事件到达 agent 后触发 WpaCheckForEscalation (TokenAnalyzer.c) 重采当前
 * 令牌对比基线, 判定 9 类提权 + UAC 绕过; 本载荷的 OpType/TokenType/AccessMask
 * /InfoClass 供事件分类与后续深化 (死代码字段, WpaCheckForEscalation 当前不消费)。
 * 数据源状态: 已由驱动 SyscallHijack.c 4 个 case 上送 (消息 0x100C-0x100F)。
 */
typedef struct _EVENT_PAYLOAD_TOKEN_OP {
    HANDLE              SourceProcessId;    /* 发起进程 (sPid) */
    HANDLE              TargetProcessId;    /* 目标进程 (tPid); 非模拟类=源进程 */
    HANDLE              TokenHandle;        /* 目标令牌句柄值 */
    ULONG               OpType;             /* 0=AdjustPrivileges 1=Duplicate 2=SetInformation 3=Impersonate */
    ULONG               TokenType;          /* Duplicate 的 TOKEN_TYPE (1=Primary 2=Impersonation) */
    ULONG               AccessMask;         /* Duplicate 的 DesiredAccess */
    ULONG               InfoClass;          /* SetInformationToken 的 TokenInformationClass */
} EVENT_PAYLOAD_TOKEN_OP, *PEVENT_PAYLOAD_TOKEN_OP;
