// 进程管理模块头文件
// 
// 功能说明：
// 本模块提供进程管理相关的功能，包括：
// 1. 获取进程列表
// 2. 获取进程详细信息
// 3. 获取进程模块列表
// 4. 终止进程
// 5. 隔离进程
// 6. 信任进程
// 7. 处理Driver事件
//
// 使用说明：
// 1. 调用ProcessManager_Initialize()初始化模块
// 2. 使用相应的函数获取进程信息或执行操作
// 3. 调用ProcessManager_Cleanup()清理资源
//
// 作者：WkDefender Team
// 版本：1.0.0
// 日期：2026-04-04

#pragma once

#include "WkDefenderHeader.h"
#include "tools.h"
#include "Notification/msg_queue.h"
#include "Notification/AlpcService.h"

// 状态码定义
#define STATUS_NOT_INITIALIZED 0xC0000001

#define MAX_PROCESS_NAME_LENGTH     260
#define MAX_COMMAND_LINE_LENGTH     512
#define MAX_IMAGE_PATH_LENGTH       260

// 威胁等级定义
#define THREAT_LEVEL_NONE           0
#define THREAT_LEVEL_LOW            1
#define THREAT_LEVEL_MEDIUM         2
#define THREAT_LEVEL_HIGH           3
#define THREAT_LEVEL_CRITICAL       4
#define THREAT_LEVEL_NORMAL         THREAT_LEVEL_NONE


// 进程管理器结构体
typedef struct _PROCESS_MANAGER {
    BOOLEAN Initialized;
    CRITICAL_SECTION Lock;
    ULONG TotalEvents;
    ULONG ProcessCreateEvents;
    ULONG ProcessExitEvents;
    ULONG ThreadCreateEvents;
    ULONG ThreadExitEvents;
    ULONG ApiCallEvents;
    WKD_MSG_QUEUE MessageQueue;  // 独立的消息队列
    HANDLE WorkerThread;         // 独立的处理线程
} PROCESS_MANAGER, * PPROCESS_MANAGER;

// 全局进程管理器定义
extern PROCESS_MANAGER g_ProcessManager;

// 进程信息结构体
typedef struct _PROCESS_INFO {
    DWORD ProcessId;
    CHAR Name[256];
    CHAR Description[256];
    DOUBLE CpuUsage;
    DOUBLE MemoryUsageMB;
    CHAR FilePath[MAX_PATH];
    CHAR TrustLevel[32];
    CHAR DigitalSignature[256];
    CHAR CommandLine[1024];
} PROCESS_INFO, * PPROCESS_INFO;

// 进程模块信息结构体
typedef struct _PROCESS_MODULE_INFO {
    CHAR ModuleName[256];
    CHAR BaseAddress[32];
    CHAR FilePath[MAX_PATH];
    UINT32 Size;
} PROCESS_MODULE_INFO, * PPROCESS_MODULE_INFO;

// 进程管理模块接口

// 初始化进程管理模块（自注册模式）
// 参数：
//   AlpcServer - ALPC 服务器实例（NULL = 使用全局默认 WkdDefaultAlpcServer）
// 返回：NTSTATUS状态码
// 说明：内部完成结构体初始化、消息队列初始化和路由注册
NTSTATUS ProcessManager_InitializeService(
    _In_opt_ PWKD_ALPC_SERVER AlpcServer
    );

// 清理进程管理模块资源
VOID ProcessManager_Cleanup();

// 获取进程列表
// 参数：
//   pProcessList - 输出参数，进程列表数组
//   pCount - 输出参数，进程数量
// 返回：NTSTATUS状态码
NTSTATUS ProcessManager_GetProcessList(
    PPROCESS_INFO* pProcessList,
    PULONG pCount
);

// 获取进程详细信息
// 参数：
//   Pid - 进程ID
//   pProcessInfo - 输出参数，进程详细信息
// 返回：NTSTATUS状态码
NTSTATUS ProcessManager_GetProcessDetail(
    DWORD Pid,
    PPROCESS_INFO pProcessInfo
);


// 获取进程模块列表
// 参数：
//   Pid - 进程ID
//   pModuleList - 输出参数，模块列表数组
//   pCount - 输出参数，模块数量
// 返回：NTSTATUS状态码
NTSTATUS ProcessManager_GetProcessModules(
    DWORD Pid,
    PPROCESS_MODULE_INFO* pModuleList,
    PULONG pCount
);

// 终止进程
// 参数：
//   Pid - 进程ID
// 返回：NTSTATUS状态码
NTSTATUS ProcessManager_KillProcess(
    DWORD Pid
);

// 隔离进程
// 参数：
//   Pid - 进程ID
// 返回：NTSTATUS状态码
NTSTATUS ProcessManager_IsolateProcess(
    DWORD Pid
);

// 信任进程
// 参数：
//   Pid - 进程ID
// 返回：NTSTATUS状态码
NTSTATUS ProcessManager_TrustProcess(
    DWORD Pid
);

// 释放进程列表内存
VOID ProcessManager_FreeProcessList(
    PPROCESS_INFO pProcessList
);

// 释放进程模块列表内存
VOID ProcessManager_FreeModuleList(
    PPROCESS_MODULE_INFO pModuleList
);

// 处理Driver事件
NTSTATUS ProcessManager_ProcessDriverEvent(
    _In_ ULONG EventType,
    _In_ PVOID EventData,
    _In_ ULONG EventDataSize
);

// 获取事件统计信息
VOID ProcessManager_GetEventStats(
    _Out_ PULONG TotalEvents,
    _Out_ PULONG ProcessCreateEvents,
    _Out_ PULONG ProcessExitEvents,
    _Out_ PULONG ThreadCreateEvents,
    _Out_ PULONG ThreadExitEvents,
    _Out_ PULONG ApiCallEvents
);


// 进程消息处理函数 - 由消息队列调用
PVOID ProcessManager_MessageHandler(
    PVOID Context,
    ULONG MessageType,
    PVOID Data
);

/**************************************************/
/*   处置引擎:进程终止/挂起/隔离/防护              */
/*   迁移自 ShadowStrike ProcessKiller (按功能融合) */
/**************************************************/

/* 处置枚举(数值对齐 ShadowStrike ProcessKiller;MSVC C 枚举为 int,序列化时按 UINT8) */
typedef enum _WKD_KILL_METHOD {
    WkKillMethod_Auto = 0,
    WkKillMethod_Standard = 1,
    WkKillMethod_Privileged = 2,
    WkKillMethod_Freeze = 3,
    WkKillMethod_JobObject = 4,
    WkKillMethod_TokenManipulation = 5,
    WkKillMethod_Kernel = 6,
    WkKillMethod_ForceKernel = 7,
    WkKillMethod_Nuclear = 8
} WKD_KILL_METHOD, *PWKD_KILL_METHOD;

typedef enum _WKD_KILL_RESULT {
    WkKillResult_Success = 0,
    WkKillResult_AlreadyDead = 1,
    WkKillResult_AccessDenied = 2,
    WkKillResult_Protected = 3,
    WkKillResult_Critical = 4,
    WkKillResult_NotFound = 5,
    WkKillResult_Timeout = 6,
    WkKillResult_PartialSuccess = 7,
    WkKillResult_Failed = 8,
    WkKillResult_Blocked = 9,
    WkKillResult_Resurrected = 10,
    WkKillResult_InsufficientPriv = 11
} WKD_KILL_RESULT, *PWKD_KILL_RESULT;

typedef enum _WKD_SUSPEND_RESULT {
    WkSuspendResult_Success = 0,
    WkSuspendResult_PartialSuccess = 1,
    WkSuspendResult_AccessDenied = 2,
    WkSuspendResult_NotFound = 3,
    WkSuspendResult_Failed = 4,
    WkSuspendResult_AlreadySuspended = 5
} WKD_SUSPEND_RESULT, *PWKD_SUSPEND_RESULT;

typedef enum _WKD_PROTECTION_LEVEL {
    WkProtection_None = 0,
    WkProtection_Light = 1,     /* PPL */
    WkProtection_Full = 2,      /* PP */
    WkProtection_Unknown = 3
} WKD_PROTECTION_LEVEL, *PWKD_PROTECTION_LEVEL;

typedef enum _WKD_PROCESS_CRITICALITY {
    WkCriticality_Normal = 0,
    WkCriticality_SystemService = 1,
    WkCriticality_SecuritySoftware = 2,
    WkCriticality_Critical = 3,      /* BreakOnTermination: 终止致 BSOD */
    WkCriticality_Forbidden = 4,     /* csrss/smss 等核心系统进程 */
    WkCriticality_Unknown = 5
} WKD_PROCESS_CRITICALITY, *PWKD_PROCESS_CRITICALITY;

typedef enum _WKD_TREE_KILL_STRATEGY {
    WkTreeStrategy_BottomUp = 0,     /* 先子后父 */
    WkTreeStrategy_TopDown = 1,      /* 先父后子 */
    WkTreeStrategy_Simultaneous = 2, /* 全部冻结后并行杀, 防 watchdog 复活 */
    WkTreeStrategy_Selective = 3     /* 仅杀非关键进程 */
} WKD_TREE_KILL_STRATEGY, *PWKD_TREE_KILL_STRATEGY;

typedef enum _WKD_WATCHDOG_TYPE {
    WkWatchdog_None = 0,
    WkWatchdog_MutualProcess = 1,
    WkWatchdog_ParentChild = 2,
    WkWatchdog_ServiceMonitor = 3,
    WkWatchdog_ScheduledTask = 4,
    WkWatchdog_RegistryRun = 5,
    WkWatchdog_WMISubscription = 6
} WKD_WATCHDOG_TYPE, *PWKD_WATCHDOG_TYPE;

/* 处置常量(对齐 ShadowStrike KillerConstants) */
#define WK_KILL_TIMEOUT_MS_DEFAULT      5000UL
#define WK_SUSPEND_TIMEOUT_MS           3000UL
#define WK_TREE_KILL_TIMEOUT_MS         30000UL
#define WK_VERIFY_INTERVAL_MS           100UL
#define WK_MAX_RETRY_ATTEMPTS           3UL
#define WK_RETRY_DELAY_MS               500UL
#define WK_MAX_TREE_DEPTH               64UL
#define WK_MAX_TREE_SIZE                1024UL
#define WK_MAX_WATCHDOG_GROUPS          256UL
#define WK_MAX_THREADS_PER_PROCESS      10000UL
#define WK_EXIT_CODE_KILLED             0xDEADUL
#define WK_EXIT_CODE_SECURITY           0x0BADUL
#define WK_EXIT_CODE_FORCE              0xF0CEUL
#define WK_CRITICAL_PROCESS_COUNT       7
#define WK_SYSTEM_PROCESS_COUNT         8

/* 保护签名者类型（对齐 SS PROTECTION_*，用于 ProtectionInfo.SignerType；※死代码） */
#define WK_PROTECTION_NONE              0
#define WK_PROTECTION_PPL_AUTHENTICODE  1
#define WK_PROTECTION_PPL_CODEGEN       2
#define WK_PROTECTION_PPL_ANTIMALWARE   3
#define WK_PROTECTION_PPL_LSA           4
#define WK_PROTECTION_PPL_WINDOWS       5
#define WK_PROTECTION_PP_WINTCB         6

/* 进程保护信息(GetProtectionInfo) */
typedef struct _WKD_PROCESS_PROTECTION_INFO {
    WKD_PROTECTION_LEVEL Level;
    UINT8 SignerType;
    UINT8 ProtectionType;
    BOOLEAN IsCritical;
    BOOLEAN IsBreakOnTermination;
    BOOLEAN IsSecure;
    BOOLEAN CanTerminate;
    WCHAR ProtectionDescription[128];
} WKD_PROCESS_PROTECTION_INFO, *PWKD_PROCESS_PROTECTION_INFO;

/* 终止选项(对齐 SS KillOptions;4 个工厂见 WkKillOptions_*) */
typedef struct _WKD_KILL_OPTIONS {
    WKD_KILL_METHOD PreferredMethod;         /* 默认 Auto */
    ULONG TimeoutMs;                         /* 默认 WK_KILL_TIMEOUT_MS_DEFAULT */
    ULONG MaxRetries;                        /* 默认 WK_MAX_RETRY_ATTEMPTS */
    BOOLEAN EscalateOnFailure;               /* 失败升级更强手段 */
    BOOLEAN KillTree;
    WKD_TREE_KILL_STRATEGY TreeStrategy;     /* 默认 BottomUp */
    BOOLEAN DefeatWatchdogs;
    BOOLEAN CleanPersistence;
    BOOLEAN VerifyTermination;
    BOOLEAN PreserveEvidence;
    BOOLEAN AllowCritical;
    ULONG ExitCode;                          /* 默认 WK_EXIT_CODE_KILLED */
} WKD_KILL_OPTIONS, *PWKD_KILL_OPTIONS;

/* 挂起选项（对齐 SS SuspendOptions；当前 SuspendProcess 为简化签名，※死代码类型） */
typedef struct _WKD_SUSPEND_OPTIONS {
    ULONG TimeoutMs;                 /* 默认 WK_SUSPEND_TIMEOUT_MS */
    BOOLEAN SuspendAllThreads;       /* 默认 TRUE */
    BOOLEAN IncludeFrozenThreads;    /* 默认 FALSE */
    BOOLEAN VerifyFreeze;            /* 默认 TRUE */
} WKD_SUSPEND_OPTIONS, *PWKD_SUSPEND_OPTIONS;

/* 进程终止信息(KillProcessEx 输出) */
typedef struct _WKD_PROCESS_KILL_INFO {
    ULONG ProcessId;
    ULONG ParentProcessId;
    WCHAR ProcessName[260];
    WCHAR ProcessPath[260];
    WCHAR CommandLine[1024];
    WCHAR UserName[64];
    LARGE_INTEGER StartTime;
    LARGE_INTEGER KillTime;
    WKD_KILL_METHOD MethodUsed;
    WKD_KILL_RESULT Result;
    ULONG ExitCode;
    ULONG AttemptCount;
    WKD_PROCESS_PROTECTION_INFO ProtectionInfo;
    WCHAR ErrorMessage[256];
} WKD_PROCESS_KILL_INFO, *PWKD_PROCESS_KILL_INFO;

/* 线程级终止信息（对齐 SS ThreadKillInfo；SS 未实际填充该列表，※死代码类型） */
typedef struct _WKD_THREAD_KILL_INFO {
    ULONG ThreadId;
    BOOLEAN WasSuspended;
    BOOLEAN WasTerminated;
    ULONG SuspendCount;
    WCHAR Status[64];
} WKD_THREAD_KILL_INFO, *PWKD_THREAD_KILL_INFO;

/* 进程树终止信息 */
typedef struct _WKD_TREE_KILL_NODE {
    ULONG Pid;
    WKD_KILL_RESULT Result;
    WKD_KILL_METHOD MethodUsed;
} WKD_TREE_KILL_NODE, *PWKD_TREE_KILL_NODE;

typedef struct _WKD_TREE_KILL_INFO {
    ULONG RootPid;
    WCHAR RootName[260];
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;
    WKD_TREE_KILL_STRATEGY Strategy;
    ULONG TotalProcesses;
    ULONG KilledProcesses;
    ULONG FailedProcesses;
    ULONG SkippedProcesses;
    WKD_KILL_RESULT OverallResult;
    PWKD_TREE_KILL_NODE Results;   /* UtHeapAlloc 分配,容量 TotalProcesses;调用方 ProcessManager_FreeTreeKillInfo */
    WCHAR LastError[256];
} WKD_TREE_KILL_INFO, *PWKD_TREE_KILL_INFO;

/* Watchdog 信息与组 */
typedef struct _WKD_WATCHDOG_INFO {
    WKD_WATCHDOG_TYPE Type;
    ULONG WatcherPid;
    ULONG WatchedPid;
    WCHAR WatcherName[260];
    WCHAR WatchedName[260];
    WCHAR Mechanism[128];
    WCHAR PersistenceLocation[260];
    BOOLEAN CanDisable;
} WKD_WATCHDOG_INFO, *PWKD_WATCHDOG_INFO;

typedef struct _WKD_WATCHDOG_GROUP {
    ULONG ProcessIds[WK_MAX_TREE_SIZE];
    ULONG ProcessCount;
    WKD_WATCHDOG_INFO Relationships[16];
    ULONG RelationshipCount;
    WCHAR PersistenceLocations[4][260];
    ULONG PersistenceLocationCount;
    BOOLEAN RequiresSimultaneousKill;
} WKD_WATCHDOG_GROUP, *PWKD_WATCHDOG_GROUP;

/* 终止统计(21 计数器, 内核用 Interlocked 递增) */
typedef struct _WKD_KILLER_STATISTICS {
    volatile LONG64 TotalKillAttempts;
    volatile LONG64 SuccessfulKills;
    volatile LONG64 FailedKills;
    volatile LONG64 EscalatedKills;
    volatile LONG64 StandardKills;
    volatile LONG64 PrivilegedKills;
    volatile LONG64 FreezeKills;
    volatile LONG64 JobObjectKills;
    volatile LONG64 KernelKills;
    volatile LONG64 TreeKillAttempts;
    volatile LONG64 ProcessesInTreesKilled;
    volatile LONG64 SuspendAttempts;
    volatile LONG64 SuccessfulSuspends;
    volatile LONG64 ResumeAttempts;
    volatile LONG64 WatchdogsDetected;
    volatile LONG64 WatchdogsDefeated;
    volatile LONG64 ProtectedProcessesEncountered;
    volatile LONG64 CriticalProcessesBlocked;
    volatile LONG64 AccessDeniedErrors;
    volatile LONG64 TimeoutErrors;
    volatile LONG64 ResurrectionsDetected;
} WKD_KILLER_STATISTICS, *PWKD_KILLER_STATISTICS;

/* const 指针别名（回调与公共 API 的只读入参） */
typedef const WKD_KILL_OPTIONS* PCWKD_KILL_OPTIONS;
typedef const WKD_PROCESS_KILL_INFO* PCWKD_PROCESS_KILL_INFO;
typedef const WKD_WATCHDOG_INFO* PCWKD_WATCHDOG_INFO;

/* 处置回调(※死代码: 当前无消费者, 保留 API 面) */
typedef BOOLEAN (*WKD_PRE_KILL_CALLBACK)(ULONG Pid, _In_ PCWKD_KILL_OPTIONS Options);
typedef VOID    (*WKD_POST_KILL_CALLBACK)(_In_ PCWKD_PROCESS_KILL_INFO Info);
typedef VOID    (*WKD_TREE_PROGRESS_CALLBACK)(ULONG Current, ULONG Total, _In_ PCWKD_PROCESS_KILL_INFO Info);
typedef VOID    (*WKD_WATCHDOG_CALLBACK)(_In_ PCWKD_WATCHDOG_INFO Watchdog);

/* KillOptions 工厂(镜像 SS CreateStandard/Aggressive/MalwareKill/Forensic) */
VOID WkKillOptions_Standard(_Out_ PWKD_KILL_OPTIONS Options);
VOID WkKillOptions_Aggressive(_Out_ PWKD_KILL_OPTIONS Options);
VOID WkKillOptions_MalwareKill(_Out_ PWKD_KILL_OPTIONS Options);
VOID WkKillOptions_Forensic(_Out_ PWKD_KILL_OPTIONS Options);

/* ── 终止(改写自原空壳, 语义升级为真实终止) ── */
NTSTATUS ProcessManager_KillProcess(DWORD Pid);
NTSTATUS ProcessManager_KillProcessEx(DWORD Pid, _In_opt_ PCWKD_KILL_OPTIONS Options, _Out_opt_ PWKD_PROCESS_KILL_INFO OutInfo);
/* fire-and-forget 异步终止(消息接线用, 不阻塞队列消费线程) */
NTSTATUS ProcessManager_KillProcessAsync(DWORD Pid);

/* ── 隔离/信任 ── */
NTSTATUS ProcessManager_IsolateProcess(DWORD Pid);
NTSTATUS ProcessManager_TrustProcess(DWORD Pid);

/* ── 挂起/恢复/冻结 ── */
WKD_SUSPEND_RESULT ProcessManager_SuspendProcess(DWORD Pid);
BOOLEAN ProcessManager_ResumeProcess(DWORD Pid);
WKD_SUSPEND_RESULT ProcessManager_FreezeProcess(DWORD Pid);
BOOLEAN ProcessManager_ThawProcess(DWORD Pid);
BOOLEAN ProcessManager_IsProcessSuspended(DWORD Pid);

/* ── 进程树 ── */
NTSTATUS ProcessManager_GetProcessTree(DWORD RootPid, ULONG MaxDepth, _Out_ PULONG* Pids, _Out_ PULONG Count);
NTSTATUS ProcessManager_GetChildren(DWORD Pid, BOOLEAN Recursive, _Out_ PULONG* Pids, _Out_ PULONG Count);
NTSTATUS ProcessManager_TerminateProcessTree(DWORD RootPid, _In_opt_ PCWKD_KILL_OPTIONS Options, _Out_ PWKD_TREE_KILL_INFO OutInfo);
VOID ProcessManager_FreeTreeKillInfo(PWKD_TREE_KILL_INFO Info);

/* ── 保护/关键性 ── */
NTSTATUS ProcessManager_GetProtectionInfo(DWORD Pid, _Out_ PWKD_PROCESS_PROTECTION_INFO OutInfo);
BOOLEAN ProcessManager_IsProtectedProcess(DWORD Pid);
WKD_PROCESS_CRITICALITY ProcessManager_GetCriticality(DWORD Pid);
BOOLEAN ProcessManager_IsCriticalProcess(DWORD Pid);
BOOLEAN ProcessManager_CanTerminate(DWORD Pid);
BOOLEAN ProcessManager_RemoveProtection(DWORD Pid);   /* ※死代码: PPL 剥离需驱动 */
/* 驱动 PPL 剥离请求（对齐 SS RequestKernelProtectionRemoval，※死代码: 依赖驱动 IPC） */
BOOLEAN WkRequestKernelProtectionRemoval(DWORD Pid);

/* ── Watchdog ── */
NTSTATUS ProcessManager_DetectWatchdogs(DWORD Pid, _Out_ PWKD_WATCHDOG_INFO* OutList, _Out_ PULONG OutCount);
NTSTATUS ProcessManager_DetectWatchdogGroups(_In_ const ULONG* Pids, ULONG PidCount, _Out_ PWKD_WATCHDOG_GROUP* OutList, _Out_ PULONG OutCount);
BOOLEAN ProcessManager_DefeatWatchdogGroup(_In_ PWKD_WATCHDOG_GROUP Group);
NTSTATUS ProcessManager_KillWithWatchdogs(DWORD Pid, _In_opt_ PCWKD_KILL_OPTIONS Options, _Out_ PWKD_TREE_KILL_INFO OutInfo);

/* ── 持久化清理(※死代码: 未接入隔离/终止流程) ── */
BOOLEAN ProcessManager_CleanPersistence(DWORD Pid);
BOOLEAN ProcessManager_RemoveService(DWORD Pid);
BOOLEAN ProcessManager_RemoveScheduledTasks(DWORD Pid);
BOOLEAN ProcessManager_RemoveRegistryPersistence(DWORD Pid);

/* ── 验证/复活 ── */
BOOLEAN ProcessManager_VerifyTermination(DWORD Pid, ULONG TimeoutMs);
ULONG ProcessManager_CheckResurrection(PCWSTR Name, PCWSTR Path, LARGE_INTEGER SinceFileTime);

/* ── 统计(※死代码: 当前无消费方) ── */
NTSTATUS ProcessManager_GetKillStatistics(_Out_ PWKD_KILLER_STATISTICS Out);
VOID ProcessManager_ResetKillStatistics(VOID);
/* 成功率（对齐 SS KillerStatistics::GetSuccessRate，※死代码） */
double WkKillStatistics_GetSuccessRate(VOID);

/* ── 回调注册(※死代码) ── */
UINT64 ProcessManager_RegisterPreKillCallback(WKD_PRE_KILL_CALLBACK Cb);
UINT64 ProcessManager_RegisterPostKillCallback(WKD_POST_KILL_CALLBACK Cb);
UINT64 ProcessManager_RegisterTreeProgressCallback(WKD_TREE_PROGRESS_CALLBACK Cb);
UINT64 ProcessManager_RegisterWatchdogCallback(WKD_WATCHDOG_CALLBACK Cb);
VOID ProcessManager_UnregisterCallback(UINT64 CallbackId);

/* 结果/方法 → 字符串（展示/日志用，※死代码：对齐 SS ResultToString/MethodToString） */
PCWSTR WkKillResultToString(WKD_KILL_RESULT Result);
PCWSTR WkKillMethodToString(WKD_KILL_METHOD Method);

/* ── 批量/按名/按路径终止（※死代码：对齐 SS TerminateMultiple/ByName/ByPath） ── */
NTSTATUS ProcessManager_TerminateMultiple(_In_ const ULONG* Pids, ULONG PidCount,
                                          _In_opt_ PCWKD_KILL_OPTIONS Options);
NTSTATUS ProcessManager_TerminateByName(_In_ PCWSTR ProcessName,
                                        _In_opt_ PCWKD_KILL_OPTIONS Options);
NTSTATUS ProcessManager_TerminateByPath(_In_ PCWSTR ProcessPath,
                                        _In_opt_ PCWKD_KILL_OPTIONS Options);

/* ── 树挂起/恢复（※死代码：对齐 SS SuspendTree/ResumeTree） ── */
BOOLEAN ProcessManager_SuspendTree(_In_ DWORD RootPid);
BOOLEAN ProcessManager_ResumeTree(_In_ DWORD RootPid);

/* ── 内核模式可用性（对齐 SS IsKernelModeAvailable；WkD 当前无驱动通道，恒 FALSE） ── */
BOOLEAN ProcessManager_IsKernelModeAvailable(VOID);

/* ── 处置引擎版本（对齐 SS GetVersion） ── */
PCWSTR WkKillGetVersion(VOID);
