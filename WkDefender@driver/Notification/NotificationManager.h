#pragma once

#include "../Common/Constants.h"
#include "../Common/DynamicArray.h"
#include "MessageQueue.h"

//
// 消息通知系统架构说明
//
// 本模块提供统一的消息通知接口，所有驱动内部组件间的通信都通过此系统完成。
// 采用生产者-消费者模式，支持异步提交和批量处理。
//
// 消息结构：
// [消息头 WKD_MESSAGE_HEADER] + [消息体 WKD_MESSAGE_BODY_*]
//
// 特性：
// - 优先级消息队列（High/Normal/Low 三级）
// - 异步提交（工作项机制）
// - 自动内存管理
// - 线程安全

//
// 消息优先级枚举（映射到 MessageQueue 的三级链表）
//
typedef enum _WKD_MESSAGE_PRIORITY {
    WkdMessage_PriorityLow = 0,      // 低优先级（日志、统计）     → Queue Low
    WkdMessage_PriorityNormal = 1,   // 普通优先级（一般事件）     → Queue Normal
    WkdMessage_PriorityHigh = 2,     // 高优先级（安全事件）       → Queue High
    WkdMessage_PriorityCritical = 3  // 紧急优先级（立即响应）      → Queue High
} WKD_MESSAGE_PRIORITY, *PWKD_MESSAGE_PRIORITY;

//
// 消息来源组件枚举
//
typedef enum _WKD_MESSAGE_SOURCE {
    WkdMessage_SourceUnknow = 0,
    WkdMessage_SourceSyscall,           // SyscallHijack模块
    WkdMessage_SourceProcessCallback,   // ProcessNotify 进程回调模块
    WkdMessage_SourceThreadCallback,    // ThreadNotify 线程回调模块
    WkdMessage_SourceObjectCallback,    // ObjectNotify 对象回调模块
    WkdMessage_SourceImageCallback,     // ImageNotify 镜像加载回调模块
    WkdMessage_SourceBehaviorEngine,    // BehaviorEngine模块
    WkdMessage_SourceThreatScoring,     // ThreatScoring模块
    WkdMessage_SourceMemoryScan,        // MemoryScan模块
    WkdMessage_SourceRegistry,          // Registry监控模块
    WkdMessage_SourceFile,              // 文件系统监控模块
    WkdMessage_SourceNetwork,           // 网络监控模块（预留）
    WkdMessage_SourceHandleScanner,     // HandleScanner 句柄扫描模块
    WkdMessage_SourceAmsiBypass,        // AmsiBypassDetector 模块
    WkdMessage_SourceEtw,               // ETW Provider（ETW 迁移 2026-09-07）
} WKD_MESSAGE_SOURCE, *PWKD_MESSAGE_SOURCE;

//
// 消息类型枚举（三层语义结构：L1原始事件层、L2行为模式层、L3攻击链层）
//
typedef enum _WKD_MESSAGE_TYPE {
    // ========================================
    // Layer 1A: 原始事件层（SyscallHijack等监控模块发送）
    // ========================================
    WkdMessage_Unknow = 0,
    // Syscall原始事件
    WkdMessage_SyscallDetected = 0x1000,           // ⭐ 通用syscall检测（兼容旧代码）
    WkdMessage_SyscallOpenProcess = 0x1001,        // NtOpenProcess
    WkdMessage_SyscallAllocateMemory = 0x1002,     // NtAllocateVirtualMemory
    WkdMessage_SyscallWriteMemory = 0x1003,        // NtWriteVirtualMemory
    WkdMessage_SyscallReadMemory = 0x1004,         // NtReadVirtualMemory
    WkdMessage_SyscallCreateThread = 0x1005,       // NtCreateRemoteThread
    WkdMessage_SyscallMapSection = 0x1006,         // NtMapViewOfSection
    WkdMessage_SyscallQueueApc = 0x1007,           // NtQueueApcThread
    WkdMessage_SyscallSetContextThread = 0x1008,   // NtSetContextThread
    WkdMessage_SyscallProtectMemory = 0x1009,      // NtProtectVirtualMemory
    WkdMessage_SyscallSuspendThread = 0x100A,      // NtSuspendThread（线程劫持前置：挂起）
    WkdMessage_SyscallResumeThread = 0x100B,       // NtResumeThread（线程劫持恢复：执行权转移）
    WkdMessage_SyscallAdjustPrivileges = 0x100C,   // NtAdjustPrivilegesToken（令牌特权调整，T1134）
    WkdMessage_SyscallDuplicateToken   = 0x100D,   // NtDuplicateToken（令牌复制，T1134.001）
    WkdMessage_SyscallSetInformationToken = 0x100E, // NtSetInformationToken（令牌属性修改）
    WkdMessage_SyscallImpersonateThread  = 0x100F, // NtImpersonateThread（线程模拟，T1134.003）
    WkdMessage_SyscallUnmapSection = 0x1010,       // NtUnmapViewOfSection（进程镂空 T1055.012，PreAcquireSection 迁移 2026-08）
    WkdMessage_SyscallCreateSection = 0x1011,      // NtCreateSection（SectionTracker 迁移 2026-08：匿名可执行/大匿名/无背衬/TxF 检测）

    // 内存操作原始事件
    WkdMessage_MemoryAllocate = 0x1101,            // 内存分配
    WkdMessage_MemoryFree = 0x1102,                // 内存释放
    WkdMessage_MemoryProtect = 0x1103,             // 内存保护修改
    WkdMessage_MemoryAlert = 0x1104,               // 内存告警（Shellcode/注入/Hollowing，ETW 全覆盖映射）

    // 注册表原始事件
    WkdMessage_RegistrySetValue = 0x1201,          // 注册表写入
    WkdMessage_RegistryDeleteValue = 0x1202,       // 注册表删除
    WkdMessage_RegistrySuspicious = 0x1203,        // 注册表可疑操作（ETW 全覆盖映射）
    WkdMessage_RegistryBlocked = 0x1204,           // 注册表阻断（ETW 全覆盖映射）

    // 文件原始事件
    WkdMessage_FileCreate = 0x1301,                // 文件创建
    WkdMessage_FileWrite = 0x1302,                 // 文件写入
    WkdMessage_FileRename = 0x1303,                // 文件重命名（FBE 迁移 2026-08）
    WkdMessage_FileDelete = 0x1304,                // 文件删除（FBE 迁移 2026-08）
    WkdMessage_FileRollbackResult = 0x1305,        // 回滚结果（FBE 迁移 2026-08）
    WkdMessage_FileShadowCopyDelete = 0x1306,      // 卷影副本删除（T1490，勒索检测）
    WkdMessage_NamedPipeCreate = 0x1307,           // 命名管道创建（NamedPipeMonitor 迁移 2026-08）
    WkdMessage_SectionMap = 0x1308,                // 可执行区段映射（代码执行映射检测，PreAcquireSection 迁移 2026-08）
    WkdMessage_FileScanResult = 0x1309,            // 文件扫描结果（ETW 全覆盖映射，SS EtwEventId_FileScanResult 对齐）
    WkdMessage_FileBlocked = 0x130A,               // 文件阻断（ETW 全覆盖映射，SS EtwEventId_FileBlocked 对齐）
    WkdMessage_FileQuarantined = 0x130B,           // 文件隔离（ETW 全覆盖映射，SS EtwEventId_FileQuarantined 对齐）

    // 对象访问原始事件（ObjectNotify 发送）
    WkdMessage_ProcessObjectAccess = 0x1401,        // 敏感对象访问（进程）
    WkdMessage_ThreadObjectAccess = 0x1402,         // 敏感对象访问（线程）
    WkdMessage_HandleDuplicate = 0x1403,            // 句柄复制事件（HandleTracker 迁移 2026-08，死代码：依赖 Ob 回调激活）

    // 网络原始事件（ETW 全覆盖映射，对标 SS EtwEventId_Network 600-605）
    WkdMessage_NetworkConnect = 0x1601,             // 网络连接
    WkdMessage_NetworkListen = 0x1602,              // 网络监听
    WkdMessage_DnsQuery = 0x1603,                   // DNS 查询
    WkdMessage_C2Detected = 0x1604,                 // C2 通信检测
    WkdMessage_ExfiltrationDetected = 0x1605,       // 数据泄露检测
    WkdMessage_NetworkBlocked = 0x1606,             // 网络阻断

    // ========================================
    // Layer 1B: 行为分析结果层（BehaviorEngine发送）
    // ========================================

    // 跨进程操作模式
    WkdMessage_CrossProcessMemoryAccess = 0x2001,  // 跨进程内存访问模式
    WkdMessage_CodeInjectionPattern = 0x2002,      // 代码注入模式
    WkdMessage_ProcessHollowingPattern = 0x2003,   // 进程hollowing模式
    WkdMessage_ApcInjectionPattern = 0x2004,       // APC注入模式
    WkdMessage_AmsiBypassDetected = 0x2005,        // AMSI绕过检测（T1562.001，AmsiBypassDetector发送）

    // 威胁评分
    WkdMessage_ThreatScoreUpdated = 0x2201,        // 威胁评分更新
    WkdMessage_ThreatLevelChanged = 0x2202,        // 威胁等级变化

    // 行为分析结果层（ETW 全覆盖映射，对标 SS EtwEventId_Behavior 700-704）
    WkdMessage_BehaviorAlert = 0x2401,              // 行为告警
    WkdMessage_AttackChainStarted = 0x2402,         // 攻击链启动
    WkdMessage_AttackChainUpdated = 0x2403,         // 攻击链更新
    WkdMessage_AttackChainCompleted = 0x2404,       // 攻击链完成
    WkdMessage_MitreDetection = 0x2405,             // MITRE ATT&CK 检测映射

    // ========================================
    // Layer 2: 系统级事件（ProcessMonitor等基础模块发送）
    // ========================================

    WkdMessage_ProcessCreated = 0x3001,            // 进程创建
    WkdMessage_ProcessExited = 0x3002,             // 进程退出
    WkdMessage_ThreadCreated = 0x3003,             // 线程创建（本地/远程统一，通过 Flags 区分）
    WkdMessage_ThreadExited = 0x3004,              // 线程退出
    WkdMessage_ImageLoaded = 0x3005,               // 镜像加载
    WkdMessage_RemoteThreadCreated = 0x3003,       // [已弃用] 远程线程创建，使用 WkdMessage_ThreadCreated + Flags
    WkdMessage_RemoteThreadExited = 0x3004,        // [已弃用] 远程线程退出，使用 WkdMessage_ThreadExited + Flags
    WkdMessage_ProcessSnapshot = 0x3008,            // 进程枚举快照（批量）
    WkdMessage_HandleScan = 0x3009,                  // 句柄扫描结果

    // 系统级事件（ETW 全覆盖映射，Suspicious/Blocked 变体）
    WkdMessage_ProcessCreatedSuspicious = 0x300A,   // 进程创建-可疑（SS EtwEventId_ProcessSuspicious 对齐）
    WkdMessage_ProcessCreatedBlocked = 0x300B,      // 进程创建-阻断（SS EtwEventId_ProcessBlocked 对齐）
    WkdMessage_ThreadCreatedSuspicious = 0x300C,    // 线程创建-可疑（SS EtwEventId_ThreadSuspicious 对齐）
    WkdMessage_ImageLoadedSuspicious = 0x300D,      // 镜像加载-可疑（SS EtwEventId_ImageSuspicious 对齐）
    WkdMessage_ImageLoadedBlocked = 0x300E,         // 镜像加载-阻断（SS EtwEventId_ImageBlocked 对齐）

    // ========================================
    // Layer 3: 通用消息
    // ========================================

    WkdMessage_SecurityEvent = 0x4001,             // 安全事件
    WkdMessage_SystemStatus = 0x4002,              // 系统状态
    WkdMessage_Error = 0x4003,                      // 错误报告

    // Layer 3 诊断消息（ETW 全覆盖映射，对标 SS EtwEventId_Diagnostic 900-905，不进编排链，仅审计）
    WkdMessage_DriverStarted = 0x4101,              // 驱动启动
    WkdMessage_DriverStopping = 0x4102,             // 驱动停止
    WkdMessage_Heartbeat = 0x4103,                  // 心跳
    WkdMessage_PerformanceStats = 0x4104,           // 性能统计
    WkdMessage_ComponentHealth = 0x4105,            // 组件健康
    WkdMessage_DriverError = 0x4106,                // 驱动错误
} WKD_MESSAGE_TYPE, WKD_EVENT_TYPE;

//
// 消息头结构体（所有消息的统一模板）
//
typedef struct _WKD_MESSAGE_HEADER {
    ULONG Magic;                          // 魔数标识 'WkNd' (0x576B4E64)
    ULONG Version;                        // 版本号

    WKD_MESSAGE_TYPE Type;                // 消息类型
    WKD_MESSAGE_SOURCE Source;            // 消息来源组件
    WKD_MESSAGE_PRIORITY Priority;        // 消息优先级

    LARGE_INTEGER Timestamp;              // 消息生成时间戳

    // === 进程上下文 ===
    HANDLE SourceProcessId;               // 源进程ID
    HANDLE TargetProcessId;               // 目标进程ID
    HANDLE ThreadId;                      // 线程ID（可选）

    // === 元数据 ===
    ULONG BodySize;                       // 消息体大小

    // === 标志位 ===
    struct {
        ULONG RequiresResponse : 1;   // 需要响应
        ULONG IsAsync : 1;            // 异步提交
        ULONG IsBatched : 1;          // 批量消息
        ULONG FromHighIrql : 1;       // 来自高IRQL级别
        ULONG CriticalPath : 1;       // 关键路径（不可丢弃）
        ULONG Reserved : 27;
    } Flags;                          // 仅在driver侧有效

    ULONG AtomicRisk;                 // 当前事件更新后的原子威胁得分，用于alpc通知agent

    ULONG SyncRequestId;              // 同步请求ID：0=异步事件，非0=同步阻塞请求
} WKD_MESSAGE_HEADER, *PWKD_MESSAGE_HEADER;

#define WKD_NOTIFICATION_MAGIC            0x576B4E64  // 'WkNd'
#define WKD_NOTIFICATION_VERSION          3

//
// Syscall检测消息体
//
#define WKD_SYSCALL_MAX_PARAMETERS 8
typedef struct _WKD_MESSAGE_BODY_SYSCALL {
    ULONG SyscallNumber;                                // 系统调用号
    ULONG SyscallCount;                                 // syscall数量（序列检测时）
    ULONG TimeWindowMs;                                 // 时间窗口（毫秒）
    ULONG ParameterNumber;                              // 参数个数
    ULONG64 ParameterBase[WKD_SYSCALL_MAX_PARAMETERS];  // 参数块
} WKD_MESSAGE_BODY_SYSCALL, *PWKD_MESSAGE_BODY_SYSCALL;

//
// AMSI绕过检测消息体（驱动→Agent，线格式）
// 用于 WkdMessage_AmsiBypassDetected。
// 注: 16 对齐 AmsiBypassDetector.h ABD_PROLOGUE_SIZE；agent 侧
//     WkDefenderHeader.h WKD_MSG_BODY_AMSI_BYPASS 必须布局一致！
//
typedef struct _WKD_MESSAGE_BODY_AMSI_BYPASS {
    HANDLE  ProcessId;                 // 被检测进程 PID
    ULONG   BypassType;                // ABD_BYPASS_TYPE
    PVOID   TargetAddress;             // 被补丁的函数地址/保护变更区域基址
    CHAR    FunctionName[64];          // 函数名（AmsiScanBuffer 等；保护变更="protection-change"）
    UCHAR   OriginalBytes[16];         // 基线字节（无基线/保护变更时全 0）
    UCHAR   CurrentBytes[16];          // 当前序言字节（保护变更时全 0）
    ULONG   OldProtection;             // 保护变更: 旧保护（补丁检测时 0）
    ULONG   NewProtection;             // 保护变更: 新保护（补丁检测时 0）
} WKD_MESSAGE_BODY_AMSI_BYPASS, *PWKD_MESSAGE_BODY_AMSI_BYPASS;

//
// DLL注入检测消息体
//
typedef struct _WKD_MESSAGE_BODY_DLL_INJECTION {
    HANDLE InjectorPid;                   // 注入者进程ID
    HANDLE TargetProcessId;               // 被注入进程ID
    ULONG InjectionMethod;                // 注入方法（1=CreateRemoteThread, 2=APC, etc）
    PVOID InjectedAddress;                // 注入地址
    SIZE_T InjectedSize;                  // 注入大小
    ULONG ThreatScore;                    // 威胁评分
    ULONG AttackChainId;                  // 关联的攻击链ID
    WCHAR InjectorPath[512];              // 注入者路径
    WCHAR TargetPath[512];                // 目标进程路径
} WKD_MESSAGE_BODY_DLL_INJECTION, *PWKD_MESSAGE_BODY_DLL_INJECTION;

//
// 通用安全事件消息体
//
typedef struct _WKD_MESSAGE_BODY_SECURITY_EVENT {
    ULONG EventId;                        // 事件ID
    ULONG Severity;                       // 严重程度（1-10）
    ULONG Category;                       // 事件类别
    HANDLE RelatedProcessId;              // 相关进程ID
    WCHAR EventName[128];                 // 事件名称
    WCHAR Description[512];               // 详细描述
    UCHAR Evidence[1024];                 // 证据数据（可选）
    ULONG EvidenceSize;                   // 证据大小
} WKD_MESSAGE_BODY_SECURITY_EVENT, *PWKD_MESSAGE_BODY_SECURITY_EVENT;

//
// 对象访问消息体（ObjectNotify 回调专用）
//
typedef struct _WKD_MESSAGE_BODY_OBJECT_ACCESS {
    ACCESS_MASK DesiredAccess;              // 请求的完整访问掩码
    ACCESS_MASK SensitiveMask;              // 命中的敏感权限位
} WKD_MESSAGE_BODY_OBJECT_ACCESS, *PWKD_MESSAGE_BODY_OBJECT_ACCESS;

//
// 句柄复制事件消息体（对齐 SS HtRecordDuplication 参数语义，HandleTracker 迁移 2026-08）
// 死代码：事件源=Ob 回调 OB_OPERATION_HANDLE_DUPLICATE，CbInitializeObjectNotify 未激活；
// Agent 侧由因果图消费（跨进程边，对齐 SS PrAddRelationship(PrRelation_HandleDuplication)）。
//
typedef struct _WKD_MESSAGE_BODY_HANDLE_DUPLICATE {
    HANDLE      SourceProcessId;            // 复制源进程 PID
    HANDLE      TargetProcessId;            // 复制目标进程 PID
    UCHAR       ObjectType;                 // 0=Process 1=Thread
    UCHAR       Padding[3];
    ACCESS_MASK DesiredAccess;              // 原始请求访问掩码（Ob 回调 PreOperation 句柄值不可用）
} WKD_MESSAGE_BODY_HANDLE_DUPLICATE, *PWKD_MESSAGE_BODY_HANDLE_DUPLICATE;

//
// 注入检测指示器位（跟随 PS TnIndicator_*，对齐 WKD_INJECT_*）
//
#define WKD_MSG_INJECT_REMOTE_THREAD        0x00000001
#define WKD_MSG_INJECT_SUSPENDED_START      0x00000002
#define WKD_MSG_INJECT_UNBACKED_START       0x00000004
#define WKD_MSG_INJECT_RWX_START            0x00000008
#define WKD_MSG_INJECT_CROSS_SESSION        0x00000010
#define WKD_MSG_INJECT_SYSTEM_TARGET        0x00000020
#define WKD_MSG_INJECT_ELEVATED_SOURCE      0x00000040
#define WKD_MSG_INJECT_SHELLCODE_PATTERN    0x00000080

//
// 线程事件消息体（驱动→Agent，线格式）
// 用于 WkdMessage_ThreadCreated / WkdMessage_ThreadExited
// 通过 Flags 的 bit0 (IsRemote) 和 bit1 (Create) 统一区分本地/远程、创建/退出
//
// 注意: StartRoutine/DesiredAccess/Argument/CreateFlags 在未匹配到
//       syscall 上下文时全为 0（Agent 侧通过 Argument!=0 判断有效性）
//
// 注入分析字段（MemoryProtection/InjectIndicators/InjectionScore/RiskLevel）
// 对齐 PhantomSensor ThreadNotify.c TnpAnalyzeThreadCreation / TnpCalculateInjectionScore
//
typedef struct _WKD_MESSAGE_BODY_THREAD_CREATE {
    /* === 线程标识（来自线程回调） === */
    HANDLE ThreadId;                    // 目标线程 ID（tTid）
    HANDLE CreatorThreadId;             // 创建者线程 ID (sTid)

    /* === 线程入口（统一名称，来自 ETW 侧 NtCreateThreadEx.StartRoutine） === */
    PVOID StartRoutine;                 // 线程入口地址

    /* === syscall 侧关键参数（来自 ETW 缓存，未匹配时全为 0） === */
    ULONG DesiredAccess;                // NtCreateThreadEx 的 DesiredAccess
    PVOID Argument;                     // NtCreateThreadEx 的 Argument（DLL路径地址等）
    ULONG CreateFlags;                  // NtCreateThreadEx 的 CreateFlags

    /* === 内存分析（对齐 PS TnpGetMemoryProtection） === */
    PVOID ImageBase;                    // 所属模块的基址
    ULONG MemoryProtection;              // 入口点内存保护属性 (PAGE_*)
    ULONG MemoryProtectionFlags;         // 保留（后续扩展）

    /* === 注入分析上下文（对齐 PS TnpAnalyzeThreadCreation） === */
    ULONG CreatorSessionId;             // 创建者会话 ID
    ULONG TargetSessionId;              // 目标进程会话 ID
    ULONG InjectIndicators;             // WKD_MSG_INJECT_* 位图
    ULONG InjectionScore;               // 注入评分 0-1000（agent 回填，内核发送时=0）
    ULONG RiskLevel;                    // 风险等级（agent 回填，内核发送时=0）

    /* === 入口点内存原始字节（供 agent shellcode 模式匹配，对齐 PS TnpCheckShellcodePatterns） === */
    UCHAR  StartBytes[128];             // 线程入口点前 128 字节
    ULONG  StartBytesSize;              // 有效字节数（0=未采集）

    /* === 时间与标志 === */
    LARGE_INTEGER CreateTime;           // 线程创建时间
    ULONG Flags;                        // bit0=IsRemote, bit1=Create

    /* === 起始地址归属结论（IocObserveThread 计算，供 agent IOC 消费） === */
    BOOLEAN IsUnusualEntry;             // 起始地址未落在已知模块内 (PsLookupWkdModuleContainingAddress 未命中)
    BOOLEAN IsStartAddrBacked;          // 起始地址为 MEM_IMAGE (ZwQueryVirtualMemory.Type)
} WKD_MESSAGE_BODY_THREAD_CREATE, *PWKD_MESSAGE_BODY_THREAD_CREATE;

/* 结构体大小约 96 字节，128 字节以内 */


/**************************************************/
/*       进程创建事件体（驱动→Agent，线格式）       */
/*                                                 */
/*  单条记录内存布局:                              */
/*    [固定头 WKD_MESSAGE_BODY_PROCESS_CREATE]      */
/*    [ImagePath 字符串数据]  ← Buffer 指向此处     */
/*    [CommandLine 字符串数据] ← Buffer 指向此处    */
/**************************************************/

typedef struct _WKD_MESSAGE_BODY_PROCESS_CREATE {
    /* === 标识 === */
    HANDLE          ProcessId;
    HANDLE          ParentProcessId;
    LARGE_INTEGER   CreateTime;

    /* === 安全上下文（无法获取的字段置0） === */
    ULONG           SessionId;
    ULONG           IntegrityLevel;
    ULONG           Elevated;
    ULONG           SecurityFlags;

    /* === 字符串（Buffer 指向紧随固定头之后的实际数据） === */
    UNICODE_STRING  ImagePath;
    UNICODE_STRING  CommandLine;
} WKD_MESSAGE_BODY_PROCESS_CREATE, *PWKD_MESSAGE_BODY_PROCESS_CREATE;

/**************************************************/
/*       进程退出事件体（驱动→Agent，线格式）       */
/*                                                  */
/*  固定大小，不含变长字符串                         */
/*  ProcessId+ExitCode 前置，兼容 agent 直接读取    */
/**************************************************/

typedef struct _WKD_MESSAGE_BODY_PROCESS_EXIT {
    /* === 标识（前置字段，agent 直接读取） === */
    HANDLE          ProcessId;              // 退出进程 ID
    NTSTATUS        ExitCode;               // 退出码

    /* === 扩展上下文 === */
    HANDLE          TerminatorProcessId;
    LARGE_INTEGER   CreateTime;             // 创建时间
    LARGE_INTEGER   ExitTime;               // 退出时间
    ULONG           SessionId;              // 会话 ID
    ULONG           ExitFlags;              // 保留标志位
} WKD_MESSAGE_BODY_PROCESS_EXIT, *PWKD_MESSAGE_BODY_PROCESS_EXIT;

/**************************************************/
/*       文件操作事件体（驱动→Agent，线格式）       */
/*                                                  */
/*  用于 WkdMessage_FileWrite/FileRename/           */
/*      FileDelete 消息（FBE 迁移 2026-08）。        */
/*  Body = [固定头 WKD_MESSAGE_BODY_FILE_EVENT]      */
/*         [FilePath 字符串数据] ← Buffer 指向此处  */
/*                                                  */
/*  对齐 FBE_OPERATION_TYPE 数值：                  */
/*    Write=0 / Rename=1 / Delete=2 / Truncate=3    */
/*   HardLink/Attribute 为 PreSetInfo 迁移新增       */
/*   （T1003.003 硬链接 / T1070.006·T1564.001 属性）。 */
/**************************************************/

#define WKD_FILE_OP_WRITE       0
#define WKD_FILE_OP_RENAME      1
#define WKD_FILE_OP_DELETE      2
#define WKD_FILE_OP_TRUNCATE    3
#define WKD_FILE_OP_HARDLINK    4   /* 硬链接创建（FileLinkInformation，PreSetInfo 迁移 2026-08） */
#define WKD_FILE_OP_ATTRIBUTE   5   /* 属性/时间戳/短名变更（FileBasicInformation/ShortName，PreSetInfo 迁移 2026-08） */

typedef struct _WKD_MESSAGE_BODY_FILE_EVENT {
    /* === 标识 === */
    HANDLE          ProcessId;          /* 操作进程 */
    HANDLE          ThreadId;           /* 操作线程 */

    /* === 操作 === */
    ULONG           OperationType;      /* WKD_FILE_OP_* */
    ULONG           FileSize;           /* 文件大小（低 32 位） */
    LONGLONG        WriteOffset;        /* 写偏移（-1=未知/非写操作）。对齐 SS PostWrite PW_WRITE_CONTEXT.WriteOffset */
    ULONG           BytesWritten;       /* 写字节数（0=非写操作）。对齐 SS PostWrite BytesWritten */
    ULONG64         FileId;             /* 文件对象 ID（0=未知）。对齐 SS stream context FileId，FileInternalInformation */
    ULONG           FileEntropy;        /* 写缓冲区熵（Q16 定点，0=未知/未采样）。对齐 agent WKD_RANSOM_ENTROPY_Q16 */
    ULONG           Flags;              /* bit0=IsCanary（蜜罐命中）；后续扩展位见 DEF_FILE_FLAG_* */
    LARGE_INTEGER   Timestamp;          /* 操作时间 */

    /* === 路径（Buffer 指向紧随固定头之后的数据） === */
    UNICODE_STRING  FilePath;
} WKD_MESSAGE_BODY_FILE_EVENT, *PWKD_MESSAGE_BODY_FILE_EVENT;

/**************************************************/
/*       回滚结果事件体（驱动→Agent，线格式）       */
/*                                                  */
/*  用于 WkdMessage_FileRollbackResult 消息。       */
/*  Result 值对齐 FBE_ROLLBACK_RESULT（0=Success    */
/*  1=Partial 2=NoBackups 3=IOError 4=ShuttingDown  */
/*  5=InvalidProcess）。                             */
/**************************************************/

typedef struct _WKD_MESSAGE_BODY_FILE_ROLLBACK {
    HANDLE          ProcessId;          /* 被回滚进程 */
    ULONG           Result;             /* FBE_ROLLBACK_RESULT */
    ULONG           FilesRestored;      /* 成功恢复文件数 */
} WKD_MESSAGE_BODY_FILE_ROLLBACK, *PWKD_MESSAGE_BODY_FILE_ROLLBACK;

/**************************************************/
/*       命名管道创建事件体（驱动→Agent，线格式）     */
/*                                                   */
/*  用于 WkdMessage_NamedPipeCreate 消息。           */
/*  Body = [固定头 WKD_MESSAGE_BODY_NAMED_PIPE]      */
/*         [PipeName 字符串数据] ← Buffer 指向此处  */
/*                                                   */
/*  分类/威胁等级/威胁分对齐 NamedPipeMonitor.h       */
/*  WKD_NPM_PIPE_CLASS / WKD_NPM_THREAT_LEVEL。      */
/**************************************************/

typedef struct _WKD_MESSAGE_BODY_NAMED_PIPE {
    /* === 标识 === */
    HANDLE          ProcessId;          /* 创建者进程 */
    HANDLE          ThreadId;           /* 创建线程 */

    /* === 检测 === */
    ULONG           Classification;     /* WKD_NPM_PIPE_CLASS */
    ULONG           ThreatLevel;        /* WKD_NPM_THREAT_LEVEL */
    ULONG           ThreatScore;        /* 0-100 */
    ULONG           Flags;              /* bit0=Blocked */

    /* === 创建者镜像名（PsGetProcessImageFileName，ANSI 15 字符 + NUL） === */
    CHAR            CreatorImageName[16];

    /* === 管道名（Buffer 指向紧随固定头之后的数据） === */
    UNICODE_STRING  PipeName;
} WKD_MESSAGE_BODY_NAMED_PIPE, *PWKD_MESSAGE_BODY_NAMED_PIPE;

/**************************************************/
/*       区段映射事件体（驱动→Agent，线格式）        */
/*                                                  */
/*  用于 WkdMessage_SectionMap(0x1308)/             */
/*      WkdMessage_SyscallMapSection(0x1006)/       */
/*      WkdMessage_SyscallUnmapSection(0x1010)。    */
/*                                                  */
/*  文件轨（minifilter AcquireSection）与 syscall 轨 */
/*  （NtMapViewOfSection/Unmap）共用同一消息体：      */
/*    - Origin=0 文件轨 / 1 syscall Map / 2 Unmap    */
/*    - syscall 侧 ParameterBase 槽位有限(8)，       */
/*      10 参直接拷贝会越界，故走本专用体。           */
/*  Body = [固定头 WKD_MESSAGE_BODY_SECTION_MAP]     */
/*         [FilePath 字符串数据] ← Buffer 指向此处   */
/*          （syscall 侧 FilePath 长度=0 可空）       */
/**************************************************/

typedef struct _WKD_MESSAGE_BODY_SECTION_MAP {
    /* === 标识 === */
    HANDLE          ProcessId;          /* 目标进程（被映射进程）；Header.Source/Target 为准 */
    HANDLE          ThreadId;           /* 映射线程 */

    /* === 映射 === */
    ULONG           PageProtection;     /* 请求保护（含 SEC_IMAGE 位；syscall 侧=Win32Protect） */
    ULONG           SectionType;        /* 0=数据节 1=SEC_IMAGE */
    ULONG           MappingFlags;       /* PAS_MAP_FLAG_* 位图 */
    ULONG           SuspicionScore;     /* 0-100 */

    /* === 来源/处置 === */
    ULONG           Origin;             /* 0=minifilter(文件轨) 1=syscall Map 2=syscall Unmap */
    ULONG           Flags;              /* bit0=Blocked */

    /* === syscall 侧参数（文件轨为 0） === */
    ULONG64         SectionObject;      /* 内核 Section 对象指针（syscall 轨 ObReferenceObjectByHandle 解析，
                                         * agent 以它为键聚合跨进程映射/RemoteMap 判定；SectionTracker 迁移 2026-08） */
    ULONG64         SectionHandle;
    ULONG64         BaseAddress;        /* 映射基址 */
    ULONG64         RegionSize;         /* 视图大小 */

    LARGE_INTEGER   Timestamp;

    /* === 路径（Buffer 指向紧随固定头之后的数据；syscall 侧可空） === */
    UNICODE_STRING  FilePath;
} WKD_MESSAGE_BODY_SECTION_MAP, *PWKD_MESSAGE_BODY_SECTION_MAP;

/**************************************************/
/*       区段创建事件体（驱动→Agent，线格式）        */
/*                                                  */
/*  用于 WkdMessage_SyscallCreateSection(0x1011)。  */
/*  SectionTracker 迁移 2026-08（对齐 SS SectionTracker.c）：
/*  NtCreateSection 在 Exit 时 deref 输出 SectionHandle 得 SectionObject，
/*  解析输入参数做 5 类怀疑信号判定（匿名可执行 200/大匿名 80/无背衬 180/
/*  TxF 事务 300/DeletePending 250），评分对齐 SS SecpUpdateSuspicionScore
/*  权重和 + ≥3 标志组合加成，随消息上送。
/*  Body = [固定头 WKD_MESSAGE_BODY_SECTION_CREATE]（固定大小，无变长数据）。
/*  ※ 死代码: 依赖 SmInitialize 启用（WkdEntry.c:261 注释态）。
/**************************************************/

/* 区段怀疑标志位（对齐 SS SecSuspicion_* 裁剪，wkd 由 NtCreateSection 轨产生） */
#define WKD_SEC_SUSPICION_NONE              0x00000000
#define WKD_SEC_SUSPICION_TRANSACTED        0x00000001  /* TxF 事务（Doppelganging T1055.013，权重 300） */
#define WKD_SEC_SUSPICION_DELETED           0x00000002  /* DeletePending（Doppelganging 变体，权重 250） */
#define WKD_SEC_SUSPICION_LARGE_ANONYMOUS   0x00000004  /* 匿名 >100MB（权重 80） */
#define WKD_SEC_SUSPICION_EXECUTE_ANONYMOUS 0x00000008  /* 匿名可执行（权重 200） */
#define WKD_SEC_SUSPICION_NO_BACKING_FILE   0x00000010  /* SEC_IMAGE 无文件（权重 180） */

typedef struct _WKD_MESSAGE_BODY_SECTION_CREATE {
    /* === 标识 === */
    HANDLE          ProcessId;          /* 创建进程（Header.Source 为准） */
    HANDLE          ThreadId;           /* 创建线程 */

    /* === 创建参数（解析后实际值） === */
    ULONG64         SectionObject;      /* 输出 SectionObject（内核对象指针，agent 聚合键） */
    ULONG64         MaximumSize;        /* 实际值（大匿名判定） */
    ULONG           SectionPageProtection;  /* SectionPageProtection（可执行判定） */
    ULONG           AllocationAttributes;   /* 原始 AllocationAttributes（SEC_IMAGE 位） */
    ULONG           SectionType;        /* 0=数据节 1=SEC_IMAGE */
    ULONG           IsAnonymous;        /* FileHandle==NULL && ObjectAttributes==NULL */

    /* === 检测结果 === */
    ULONG           SuspicionFlags;     /* WKD_SEC_SUSPICION_* 位图 */
    ULONG           SuspicionScore;     /* SS 权重和（0-1000） */

    LARGE_INTEGER   Timestamp;
} WKD_MESSAGE_BODY_SECTION_CREATE, *PWKD_MESSAGE_BODY_SECTION_CREATE;

/**************************************************/
/*       网络事件消息体（驱动→Agent，线格式）       */
/*                                                  */
/*  用于 WkdMessage_Network*（ETW 全覆盖映射，对标  */
/*  SS ETW_NETWORK_EVENT）。定长，无变长数据。       */
/*  IP 字段：V4 存 LocalIpV4/RemoteIpV4，V6 存       */
/*  LocalIpV6/RemoteIpV6（V4 时清零）。              */
/**************************************************/

#define WKD_NETWORK_IPV4_ADDR_LEN         4
#define WKD_NETWORK_IPV6_ADDR_LEN         16

typedef struct _WKD_MESSAGE_BODY_NETWORK_EVENT {
    /* === 共同上下文 === */
    HANDLE          ProcessId;          /* 源进程 ID */
    HANDLE          ThreadId;           /* 源线程 ID */
    ULONG           SessionId;          /* 会话 ID */

    /* === 连接描述 === */
    ULONG           Protocol;           /* IPPROTO_*（6=TCP 17=UDP） */
    ULONG           Direction;          /* 0=出站 1=入站 */
    USHORT          LocalPort;
    USHORT          RemotePort;
    UINT32          LocalIpV4;          /* 网络序或主机序（约定主机序） */
    UINT32          RemoteIpV4;
    UINT8           LocalIpV6[WKD_NETWORK_IPV6_ADDR_LEN];
    UINT8           RemoteIpV6[WKD_NETWORK_IPV6_ADDR_LEN];
    UINT64          BytesSent;
    UINT64          BytesReceived;

    /* === 检测 === */
    UINT32          ThreatScore;        /* 0-100 */
    UINT32          ThreatType;         /* 0=正常 1=C2 2=Exfil 3=Malware */

    /* === 字符串 === */
    WCHAR           RemoteHostname[128]; /* 远端主机名 */
    WCHAR           ProcessPath[512];   /* 源进程路径 */
    LARGE_INTEGER   Timestamp;
} WKD_MESSAGE_BODY_NETWORK_EVENT, *PWKD_MESSAGE_BODY_NETWORK_EVENT;

/**************************************************/
/*       行为分析事件消息体（驱动→Agent，线格式）   */
/*                                                  */
/*  用于 WkdMessage 行为/攻击链/Mitre 系列事件       */
/*  （ETW 全覆盖映射，对标 SS ETW_BEHAVIOR_EVENT /  */
/*  ETW_SECURITY_ALERT）。定长，无变长数据。         */
/**************************************************/

typedef struct _WKD_MESSAGE_BODY_BEHAVIOR_EVENT {
    /* === 共同上下文 === */
    HANDLE          ProcessId;          /* 关联进程 ID */
    HANDLE          ThreadId;           /* 关联线程 ID */
    ULONG           SessionId;          /* 会话 ID */

    /* === 行为描述 === */
    ULONG           BehaviorType;       /* 行为类型（对齐 BehaviorTypes） */
    ULONG           Category;           /* 行为类别 */
    LONG64          ChainId;            /* 攻击链 ID（0=无） */
    ULONG           MitreTechnique;     /* MITRE ATT&CK Technique ID */
    ULONG           MitreTactic;        /* MITRE ATT&CK Tactic ID */
    ULONG           ThreatScore;        /* 0-100 */
    ULONG           Confidence;         /* 置信度 0-1000 */

    /* === 字符串 === */
    WCHAR           ProcessPath[512];   /* 进程路径 */
    WCHAR           Description[256];   /* 描述 */
    LARGE_INTEGER   Timestamp;
} WKD_MESSAGE_BODY_BEHAVIOR_EVENT, *PWKD_MESSAGE_BODY_BEHAVIOR_EVENT;

/**************************************************/
/*       诊断事件消息体（驱动→Agent，线格式）       */
/*                                                  */
/*  用于 WkdMessage_DriverStarted/Heartbeat/Error   */
/*  等诊断消息（ETW 全覆盖映射，对标 SS 9xx 事件）。*/
/*  仅审计用途，不进编排链。定长，无变长数据。       */
/**************************************************/

typedef struct _WKD_MESSAGE_BODY_DIAGNOSTIC_EVENT {
    ULONG           ComponentId;        /* 组件 ID */
    ULONG           Severity;           /* 1-10（对齐 DebugLevel/威胁等级） */
    ULONG           ErrorCode;          /* NTSTATUS 或自定义错误码 */
    HANDLE          RelatedProcessId;   /* 相关进程 ID */
    WCHAR           ComponentName[128]; /* 组件名 */
    WCHAR           Message[512];       /* 诊断消息 */
    LARGE_INTEGER   Timestamp;
} WKD_MESSAGE_BODY_DIAGNOSTIC_EVENT, *PWKD_MESSAGE_BODY_DIAGNOSTIC_EVENT;

/**************************************************/
/*       内存/注入告警事件体（驱动→Agent，线格式）  */
/*                                                  */
/*  用于 WkdMessage_MemoryAlert（ETW 全覆盖映射，   */
/*  对标 SS ETW_MEMORY_EVENT）。定长，无变长数据。  */
/*  已有 WKD_MESSAGE_BODY_SECTION_MAP/SECTION_CREATE */
/*  覆盖映射/区段轨，本结构覆盖注入/Shellcode/Hollow*/
/*  ing 内存告警。                                  */
/**************************************************/

typedef struct _WKD_MESSAGE_BODY_MEMORY_ALERT {
    /* === 上下文 === */
    HANDLE          SourceProcessId;    /* 源进程（发起者） */
    HANDLE          TargetProcessId;    /* 目标进程 */
    HANDLE          ThreadId;           /* 相关线程 */

    /* === 告警描述 === */
    ULONG           AlertType;          /* 0=Shellcode 1=Injection 2=Hollowing 3=Allocation 4=ProtectionChange */
    UINT64          BaseAddress;        /* 内存基址 */
    UINT64          RegionSize;         /* 区域大小 */
    ULONG           Protection;         /* 内存保护（PAGE_* 或请求保护） */
    ULONG           OldProtection;      /* 旧保护（ProtectionChange 时） */
    ULONG           ThreatScore;        /* 0-100 */
    ULONG           Flags;              /* 保留 */

    /* === 字符串 === */
    WCHAR           ProcessPath[512];   /* 源进程路径 */
    LARGE_INTEGER   Timestamp;
} WKD_MESSAGE_BODY_MEMORY_ALERT, *PWKD_MESSAGE_BODY_MEMORY_ALERT;

/**************************************************/
/*       句柄扫描结果事件体（驱动→Agent，线格式）   */
/*                                                   */
/*  用于 WkdMessage_HandleScan 消息。                 */
/*  Body = [固定头 WKD_MESSAGE_BODY_HANDLE_SCAN]      */
/*         [WKD_MESSAGE_BODY_HANDLE_ENTRY × Count]   */
/*                                                   */
/*  ALPC 通信 TODO: 通过共享节或内联发送              */
/**************************************************/

//
// 句柄怀疑标志（与 HandleScanner.h HS_SUSPICION 对齐）
//
#define HANDLE_SCAN_FLAG_NONE               0x00000000
#define HANDLE_SCAN_FLAG_CROSS_PROCESS      0x00000001
#define HANDLE_SCAN_FLAG_HIGH_PRIVILEGE     0x00000002
#define HANDLE_SCAN_FLAG_SENSITIVE_TARGET   0x00000004
#define HANDLE_SCAN_FLAG_MANY_HANDLES       0x00000008
#define HANDLE_SCAN_FLAG_INJECTION_CAPABLE  0x00000010
#define HANDLE_SCAN_FLAG_TOKEN_STEAL        0x00000020
#define HANDLE_SCAN_FLAG_CREDENTIAL_ACCESS  0x00000040
#define HANDLE_SCAN_FLAG_SYSTEM_PROCESS     0x00000080

//
// 句柄类型（与 HandleScanner.h HS_HANDLE_TYPE 对齐）
//
#define HANDLE_SCAN_TYPE_UNKNOWN    0
#define HANDLE_SCAN_TYPE_PROCESS    1
#define HANDLE_SCAN_TYPE_THREAD     2
#define HANDLE_SCAN_TYPE_FILE       3
#define HANDLE_SCAN_TYPE_KEY        4
#define HANDLE_SCAN_TYPE_SECTION    5
#define HANDLE_SCAN_TYPE_TOKEN      6
#define HANDLE_SCAN_TYPE_EVENT      7
#define HANDLE_SCAN_TYPE_SEMAPHORE  8
#define HANDLE_SCAN_TYPE_MUTEX      9
#define HANDLE_SCAN_TYPE_TIMER      10
#define HANDLE_SCAN_TYPE_PORT       11
#define HANDLE_SCAN_TYPE_DEVICE     12
#define HANDLE_SCAN_TYPE_DRIVER     13

//
// 单条句柄条目（固定大小，便于数组遍历）
//
typedef struct _WKD_MESSAGE_BODY_HANDLE_ENTRY {
    HANDLE      HandleValue;            // 句柄值
    UCHAR       Type;                   // HANDLE_SCAN_TYPE_*
    UCHAR       Padding[3];
    ULONG       GrantedAccess;          // 访问掩码
    HANDLE      OwnerProcessId;         // 持有者 PID
    HANDLE      TargetProcessId;        // 目标 PID（仅 Process/Thread）
    ULONG       SuspicionFlags;         // HANDLE_SCAN_FLAG_* 组合
    ULONG       SuspicionScore;         // 0-100
} WKD_MESSAGE_BODY_HANDLE_ENTRY, *PWKD_MESSAGE_BODY_HANDLE_ENTRY;

//
// 句柄扫描结果固定头（后接变长数组 HandleEntries[Count]）
//
typedef struct _WKD_MESSAGE_BODY_HANDLE_SCAN {
    HANDLE      TargetProcessId;        // 被扫描的进程 PID
    ULONG       TotalHandleCount;       // 该进程总句柄数
    ULONG       CrossProcessCount;      // 跨进程句柄数
    ULONG       InjectionCapableCount;  // 注入能力句柄数
    ULONG       TokenStealCount;        // 令牌窃取句柄数
    ULONG       CredentialAccessCount;  // 凭证访问句柄数
    ULONG       HighPrivilegeCount;     // 高权限句柄数
    ULONG       AggregatedFlags;        // 聚合怀疑标志
    ULONG       AggregatedScore;        // 聚合评分 0-100
    ULONG       Count;                  // 后接条目数
    /* WKD_MESSAGE_BODY_HANDLE_ENTRY Entries[Count]; */
} WKD_MESSAGE_BODY_HANDLE_SCAN, *PWKD_MESSAGE_BODY_HANDLE_SCAN;

//
// 完整消息结构 — 头 + 体连续内存布局（线格式）
//
// 内存布局:
//   [WKD_MESSAGE_HEADER][BodyData...]
//                        ^ 从 Header.BodySize 得知尾部长度
//
// 此结构直接用于：
//   - 驱动内部队列节点
//   - ALPC 消息载荷（完整发送到 Agent）
//   - Agent 端直接解析
//
typedef struct _WKD_MESSAGE {
    WKD_MESSAGE_HEADER Header;              // 消息头
    _Field_size_bytes_(Header.BodySize)
    UCHAR Body[ANYSIZE_ARRAY];              // 变长尾部 — 实际大小 = Header.BodySize
} WKD_MESSAGE, *PWKD_MESSAGE;

// 辅助宏：从 WKD_MESSAGE 取出类型化 body 指针
#define WKD_MESSAGE_BODY(msg, T)  ((T*)((msg)->Body))

//
// 消息队列节点（包装 WKD_MESSAGE，附加元数据）
//
typedef struct _WKD_MESSAGE_QUEUE_NODE {
    LIST_ENTRY Links;                     // 链表节点（必须为第一个字段）
    PWKD_MESSAGE Message;                 // 消息指针
    LARGE_INTEGER EnqueueTime;            // 入队时间
    BOOLEAN Processed;                    // 是否已处理
} WKD_MESSAGE_QUEUE_NODE, *PWKD_MESSAGE_QUEUE_NODE;

//
// 消息通知回调函数类型
//
typedef VOID (*PFN_NOTIFICATION_CALLBACK)(
    _In_ PWKD_MESSAGE Message,
    _In_opt_ PVOID Context
    );

//
// 通知管理器全局状态
//
typedef struct _WKD_NOTIFICATION_SERVICE {
    BOOLEAN Initialized;                  // 是否已初始化
    volatile BOOLEAN ShutdownRequested;   // 关闭请求标志

    WKD_MESSAGE_QUEUE MsgQueue;           // 优先级消息队列

    HANDLE ConsumerThread;                // 消费线程句柄
    KEVENT ProcessEvent;                  // 处理事件

    PFN_NOTIFICATION_CALLBACK Callback;   // 通知回调函数
    PVOID CallbackContext;                // 回调上下文
} WKD_NOTIFICATION_SERVICE, *PWKD_NOTIFICATION_SERVICE;

//
// 全局通知管理器实例
//
extern WKD_NOTIFICATION_SERVICE WkdNotificationService;

/****************************************************
**              核心API函数声明                    **
*****************************************************/

//
// 初始化通知管理器
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NtfInitializeService(
    VOID
    );

//
// 初始化通知管理器并注册消息转发回调（B1 修复）：
// 把 NotificationManager 总线上的异步消息经 ALPC 转发到 Agent。
// 见 NotificationHandler.c NmpAlpcForwardCallback。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NtfInitializeServiceWithCallback(
    VOID
    );

//
// 清理通知管理器
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
NmCleanup(
    VOID
    );

//
// 同步提交消息
//
// 对于紧急/阻断类消息，应直接调用目标阻断函数（TODO）。
// 当前实现为直接调用注册的回调函数。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NmSendMessageSync(
    _In_ PWKD_MESSAGE Message
    );

//
// 异步提交消息（加入优先级队列，由消费线程处理）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NtfSendMessageAsync(
    _In_ PWKD_MESSAGE Message
    );

//
// 消息入队（封装节点分配 + 优先级映射 + 入队 + 唤醒消费线程）
// 由 NtfSendMessageAsync 和 ALPC 消息转换层调用。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NtfpQueueInsert(
    _In_ PWKD_MESSAGE Message
    );

//
// 创建消息（辅助函数）
//
_IRQL_requires_(PASSIVE_LEVEL)
PWKD_MESSAGE
NtfCreateMessage(
    _In_ WKD_MESSAGE_TYPE Type,
    _In_ WKD_MESSAGE_SOURCE Source,
    _In_ WKD_MESSAGE_PRIORITY Priority,
    _In_ ULONG BodySize
    );

//
// 释放消息
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
NmFreeMessage(
    _In_ PWKD_MESSAGE Message
    );

//
// 注册通知回调
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NmRegisterCallback(
    _In_ PFN_NOTIFICATION_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

//
// 刷新消息队列（立即处理所有待处理消息）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NmFlushQueue(
    VOID
    );

//
// 获取队列统计信息
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
NmGetStatistics(
    _Out_ PLONG64 TotalEnqueued,
    _Out_ PLONG64 TotalProcessed,
    _Out_ PLONG64 TotalDropped,
    _Out_ PLONG64 CurrentQueueSize
    );

//
// 从动态数组导出 WKD_MESSAGE（批量发送场景）
//
_IRQL_requires_(PASSIVE_LEVEL)
PWKD_MESSAGE
NmExportFromDynamicArray(
    _In_ PWKD_MESSAGE_HEADER Template,
    _In_ PWKD_DYNAMIC_ARRAY *Array
    );
