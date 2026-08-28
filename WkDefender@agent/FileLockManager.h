/**************************************************/
/*  WkDefender 文件锁管理（锁检测 + 解锁链 + 威胁关联） */
/*                                                  */
/*  迁移自 ShadowStrike FileLockManager.{hpp,cpp}   */
/*  (The Keymaster), 功能重实现非源码复制。          */
/*                                                  */
/*  模块职责 (对齐 SS FileLockManager.hpp):          */
/*    1. 锁检测   - 轻量探测 + RM/句柄枚举双路        */
/*    2. 解锁链   - RM→HandleClose→Kernel→Terminate   */
/*                 →DeleteOnReboot 五级升级          */
/*    3. 重启调度 - MoveFileExW 延迟删除/移动         */
/*    4. 威胁关联 - 锁模式 APT 关联 + 评分            */
/*                                                  */
/*  融合决策 (2026-08, 用户确认):                    */
/*    - 独立模块 (对齐 ScanManager/DirectoryMonitor   */
/*      功能域惯例), 服务 ScanManager/quarantine/    */
/*      FBE 回滚/UI 多消费方                        */
/*    - 签名验证复用 IocVerifySignature      */
/*    - 进程终止委托 ProcessManager_KillProcess      */
/*      (SS TerminateProcessOp 不重复实现)           */
/*    - KernelUnlock 死代码 (SS 驱动端未实现, 协议   */
/*      纯用户态预留, 用户态句柄关闭兜底)            */
/*                                                  */
/*  全部新代码 UTF-8 BOM。                          */
/**************************************************/

#pragma once

#include <windows.h>

/* 兼容回退: SE_*_NAME 字符串宏仅定义于内核头 (wdm.h),
 * 用户态包含链不提供, 此处按需补全。 */
#ifndef SE_DEBUG_PRIVILEGE_NAME
#define SE_DEBUG_PRIVILEGE_NAME         TEXT("SeDebugPrivilege")
#endif

/**************************************************/
/*                   常量定义                       */
/**************************************************/

#define WKD_FLM_MAX_PATH           520     /* 完整路径缓冲 */
#define WKD_FLM_MAX_PROC_NAME      64      /* 进程名缓冲 */
#define WKD_FLM_MAX_PROC_PATH      260     /* 进程路径缓冲 (对齐 SS 内核协议 filePath[260]) */
#define WKD_FLM_MAX_CMDLINE        260     /* 命令行缓冲 (类型预留) */
#define WKD_FLM_MAX_SIGNER         128     /* 签名者名缓冲 (类型预留) */
#define WKD_FLM_MAX_SESSION_NAME   64      /* 会话名缓冲 (类型预留) */
#define WKD_FLM_MAX_USER_NAME      64      /* 用户名缓冲 (类型预留) */
#define WKD_FLM_MAX_INDICATORS     16      /* ThreatAssessment 指标条数 */
#define WKD_FLM_MAX_ERRORS         8       /* UnlockOperation 错误条数 */
#define WKD_FLM_MAX_WARNINGS       4       /* UnlockOperation 警告条数 */
#define WKD_FLM_MAX_ACTION_LEN     128     /* 建议动作/挂起操作描述缓冲 */
#define WKD_FLM_MAX_OWNERS         64      /* 锁 owner 枚举上限 (SS MAX_LOCK_OWNERS=1000 为 vector 堆分配;
                                              纯 C 定长控栈, 64 覆盖典型锁场景) */
#define WKD_FLM_MAX_PENDING        64      /* 挂起重启操作队列上限 */
#define WKD_FLM_MAX_APP_NAME       260     /* RM 应用名缓冲 */
#define WKD_FLM_MAX_APPS           64      /* RM 应用列表上限 */
#define WKD_FLM_MAX_INDICATOR_LEN  64      /* 单条指标字符串缓冲 */

#define WKD_FLM_HANDLE_ENUM_INIT_MB 4      /* 句柄枚举初始缓冲 (SS HANDLE_ENUM_INITIAL_BUFFER_MB) */
#define WKD_FLM_HANDLE_ENUM_MAX_MB  256    /* 句柄枚举最大缓冲 (SS MAX_HANDLE_BUFFER_BYTES) */
#define WKD_FLM_KERNEL_RETRY        3      /* 内核端口连接重试 (SS KERNEL_CONNECT_RETRY_COUNT) */
#define WKD_FLM_KERNEL_RETRY_DELAY_MS 1000 /* 内核端口重连延迟 */
#define WKD_FLM_SYSTEM_PID          4      /* 系统进程 PID */
#define WKD_FLM_IDLE_PID            0      /* Idle PID */

/**************************************************/
/*                   枚举类型                       */
/**************************************************/

/* 锁类型 (对齐 SS LockType, 9 值) */
typedef enum _WKD_LOCK_TYPE {
    WkdLock_Unknown = 0,        /* 未判定 */
    WkdLock_Read,               /* 共享读 */
    WkdLock_Write,              /* 独占写 */
    WkdLock_ReadWrite,          /* 读写 */
    WkdLock_Delete,             /* 删除共享冲突 */
    WkdLock_Exclusive,          /* 无共享 */
    WkdLock_Mapping,            /* 内存映射文件 (类型预留) */
    WkdLock_Section,            /* Section 对象 (类型预留) */
    WkdLock_Module              /* 作为 DLL/EXE 加载 (类型预留) */
} WKD_LOCK_TYPE;

/* 锁行为模式 (对齐 SS LockPattern, 8 值) */
typedef enum _WKD_LOCK_PATTERN {
    WkdLockPattern_Normal = 0,
    WkdLockPattern_Ransomware,          /* 批量锁文件 + 加密指示 */
    WkdLockPattern_LateralMovement,     /* 远程进程锁系统文件 */
    WkdLockPattern_Persistence,         /* 锁启动/服务二进制 */
    WkdLockPattern_DataExfiltration,    /* 锁后读取 (外渗) */
    WkdLockPattern_DefenseEvasion,      /* 锁 AV/EDR 文件 */
    WkdLockPattern_PrivilegeEscalation, /* 锁特权服务二进制 */
    WkdLockPattern_ProcessInjection     /* 被镂空/注入进程持锁 */
} WKD_LOCK_PATTERN;

/* 解锁方法 (对齐 SS UnlockMethod, 6 值) */
typedef enum _WKD_UNLOCK_METHOD {
    WkdUnlock_None = 0,
    WkdUnlock_HandleClose,      /* 关闭复制句柄 */
    WkdUnlock_ProcessTerminate, /* 终止进程 */
    WkdUnlock_RestartManager,   /* Restart Manager */
    WkdUnlock_KernelDriver,     /* 内核驱动 (死代码) */
    WkdUnlock_DeleteOnReboot    /* 重启后删除 */
} WKD_UNLOCK_METHOD;

/* 解锁结果 (对齐 SS UnlockResult, 8 值) */
typedef enum _WKD_UNLOCK_RESULT {
    WkdUnlockResult_Success = 0,
    WkdUnlockResult_PartialSuccess,     /* 部分句柄已关闭 */
    WkdUnlockResult_Failed,
    WkdUnlockResult_AccessDenied,
    WkdUnlockResult_ProcessCritical,    /* 关键进程不可终止 */
    WkdUnlockResult_RequiresReboot,
    WkdUnlockResult_InUseBySystem,
    WkdUnlockResult_NotLocked
} WKD_UNLOCK_RESULT;

/* 进程角色 (对齐 SS ProcessRole, 7 值, 类型预留) */
typedef enum _WKD_PROCESS_ROLE {
    WkdRole_Unknown = 0,
    WkdRole_Application,
    WkdRole_Service,
    WkdRole_System,
    WkdRole_Antivirus,
    WkdRole_Explorer,
    WkdRole_Malware
} WKD_PROCESS_ROLE;

/**************************************************/
/*                   结构体声明                     */
/**************************************************/

/* 文件锁 owner (对齐 SS LockOwner, 纯 C 定长)。
 * 实填字段: Pid/ProcessName/ProcessPath/LockType/HandleValue/AccessMask/
 *           IsSystemProcess/IsCriticalProcess/IsSigned/IsSuspicious/
 *           IsUntrustedSigner/IsInjectedProcess。
 * 其余字段类型预留 (对齐 SS 现状: cpp 亦只填上述, 其余零值)。 */
typedef struct _WKD_LOCK_OWNER {
    ULONG               Pid;
    ULONG               ParentProcessId;              /* 类型预留 */
    WCHAR               ProcessName[WKD_FLM_MAX_PROC_NAME];
    WCHAR               ProcessPath[WKD_FLM_MAX_PROC_PATH];
    WCHAR               CommandLine[WKD_FLM_MAX_CMDLINE];   /* 类型预留 */
    WKD_LOCK_TYPE       LockType;
    ULONG64             HandleValue;            /* 0 = 未知 (RM 来源) */
    ULONG               AccessMask;
    ULONG               ShareMode;              /* 类型预留 */
    WKD_PROCESS_ROLE    Role;                   /* 类型预留 */
    BOOLEAN             IsSystemProcess;
    BOOLEAN             IsCriticalProcess;
    BOOLEAN             IsElevated;             /* 类型预留 */
    BOOLEAN             IsSigned;
    WCHAR               SignerName[WKD_FLM_MAX_SIGNER];      /* 类型预留 */
    ULONG               SessionId;              /* 类型预留 */
    WCHAR               SessionName[WKD_FLM_MAX_SESSION_NAME];/* 类型预留 */
    WCHAR               UserName[WKD_FLM_MAX_USER_NAME];     /* 类型预留 */
    LARGE_INTEGER       ProcessStart;           /* 类型预留 */
    LARGE_INTEGER       HandleCreated;          /* 类型预留 */
    DOUBLE              ThreatScore;            /* 类型预留 */
    BOOLEAN             IsSuspicious;
    BOOLEAN             IsUntrustedSigner;
    BOOLEAN             IsInjectedProcess;
    BOOLEAN             IsRemoteProcess;        /* 类型预留 */
    WKD_LOCK_PATTERN    LockPattern;            /* 类型预留 */
    CHAR                ModuleHash[65];         /* 类型预留 */
} WKD_LOCK_OWNER, * PWKD_LOCK_OWNER;

/* 威胁评估 (对齐 SS ThreatAssessment) */
typedef struct _WKD_THREAT_ASSESSMENT {
    DOUBLE              OverallThreatScore;
    WKD_LOCK_PATTERN    DominantPattern;
    BOOLEAN             RequiresImmediateAction;
    BOOLEAN             IsSuspiciousActivity;
    ULONG               UntrustedLockCount;
    ULONG               InjectedProcessCount;
    ULONG               RemoteLockCount;
    ULONG               UnsignedProcessCount;
    CHAR                Indicators[WKD_FLM_MAX_INDICATORS][WKD_FLM_MAX_INDICATOR_LEN];
    ULONG               IndicatorCount;
    WCHAR               RecommendedAction[WKD_FLM_MAX_ACTION_LEN];
} WKD_THREAT_ASSESSMENT, * PWKD_THREAT_ASSESSMENT;

/* 文件锁信息汇总 (对齐 SS FileLockInfo)。
 * Owners 为动态数组 (FileLockManager_GetLockInfo 内部分配),
 * 调用方须以 FileLockManager_FreeLockInfo 释放。 */
typedef struct _WKD_FILE_LOCK_INFO {
    WCHAR               FilePath[WKD_FLM_MAX_PATH];
    BOOLEAN             IsLocked;
    ULONG               LockCount;              /* owner 数 */
    PWKD_LOCK_OWNER     Owners;                 /* 动态数组, 可空 */
    BOOLEAN             HasSystemLock;
    BOOLEAN             HasCriticalLock;
    BOOLEAN             CanForceUnlock;         /* 有 critical 锁时为 FALSE */
    ULONG64             FileSize;
    BOOLEAN             FileExists;
    BOOLEAN             IsDirectory;
    WKD_THREAT_ASSESSMENT ThreatAssessment;
    ULONG64             DetectionDurationUs;    /* 检测耗时 (微秒) */
} WKD_FILE_LOCK_INFO, * PWKD_FILE_LOCK_INFO;

/* 解锁操作结果 (对齐 SS UnlockOperation) */
typedef struct _WKD_UNLOCK_OPERATION {
    WCHAR               FilePath[WKD_FLM_MAX_PATH];
    WKD_UNLOCK_RESULT   Result;
    WKD_UNLOCK_METHOD   Method;
    ULONG               HandlesClosed;
    ULONG               ProcessesTerminated;
    CHAR                Errors[WKD_FLM_MAX_ERRORS][256];
    ULONG               ErrorCount;
    CHAR                Warnings[WKD_FLM_MAX_WARNINGS][256];
    ULONG               WarningCount;
    BOOLEAN             RequiresReboot;
    WCHAR               PendingOperation[WKD_FLM_MAX_ACTION_LEN];
    ULONG               DurationMs;
} WKD_UNLOCK_OPERATION, * PWKD_UNLOCK_OPERATION;

/* 挂起重启操作 (对齐 SS PendingOperation) */
typedef struct _WKD_PENDING_OPERATION {
    WCHAR               SourcePath[WKD_FLM_MAX_PATH];
    WCHAR               DestinationPath[WKD_FLM_MAX_PATH];   /* 删除时为空 */
    BOOLEAN             IsDelete;
    BOOLEAN             IsMove;
    LARGE_INTEGER       ScheduledTime;
    CHAR                Reason[256];
} WKD_PENDING_OPERATION, * PWKD_PENDING_OPERATION;

/* RM 应用信息 (GetApplicationsUsingFile 输出项) */
typedef struct _WKD_LOCK_APP {
    WCHAR               AppName[WKD_FLM_MAX_APP_NAME];
    ULONG               Pid;
} WKD_LOCK_APP, * PWKD_LOCK_APP;

/* 运行配置 (对齐 SS FileLockManagerConfig) */
typedef struct _WKD_FILE_LOCK_CONFIG {
    BOOLEAN             AllowProcessTermination;
    BOOLEAN             AllowKernelUnlock;
    BOOLEAN             AllowRestartManager;
    ULONG               UnlockTimeoutMs;
    ULONG               RetryCount;
    ULONG               RetryDelayMs;
    BOOLEAN             ProtectSystemProcesses;
    BOOLEAN             ProtectCriticalProcesses;
    BOOLEAN             ProtectServices;
} WKD_FILE_LOCK_CONFIG, * PWKD_FILE_LOCK_CONFIG;

/* 运行时统计 (对齐 SS FileLockManagerStatistics, 9 计数器) */
typedef struct _WKD_FILE_LOCK_STATS {
    volatile LONG64     LocksDetected;
    volatile LONG64     SuccessfulUnlocks;
    volatile LONG64     FailedUnlocks;
    volatile LONG64     ProcessesTerminated;
    volatile LONG64     HandlesClosed;
    volatile LONG64     RebootScheduled;
    volatile LONG64     KernelUnlocks;
    volatile LONG64     HandleEnumerations;
    volatile LONG64     ThreatsDetected;
} WKD_FILE_LOCK_STATS, * PWKD_FILE_LOCK_STATS;

/**************************************************/
/*              回调类型 (死代码: ALPC 覆盖)         */
/**************************************************/

/* 终止前确认回调 (对齐 SS TerminateCallback, L420): 返回 FALSE 否决终止该 owner。
 * ※死代码: wkd 处置引擎已有 pre-callback, 本回调保留 SS API 面对齐。 */
typedef BOOLEAN (*WKD_FLM_TERMINATE_CALLBACK)(const WKD_LOCK_OWNER* Owner);

/* 解锁进度回调 (对齐 SS UnlockProgressCallback, L425) */
typedef VOID (*WKD_FLM_PROGRESS_CALLBACK)(PCWSTR Status, ULONG Percent);

/* 内核实时锁事件回调 (对齐 SS LockEventCallback, L430; SS 亦仅存储未调用) */
typedef VOID (*WKD_FLM_LOCK_EVENT_CALLBACK)(const WKD_FILE_LOCK_INFO* LockInfo);

/**************************************************/
/*                   函数声明                       */
/**************************************************/

/* 生命周期 (对齐 SS Initialize/Shutdown) */
_Check_return_
NTSTATUS
FileLockManager_Initialize(
    _In_opt_ PWKD_FILE_LOCK_CONFIG Config   /* NULL = 默认配置 */
    );

VOID
FileLockManager_Shutdown(
    VOID
    );

/**************************************************/
/*                 配置工厂 (对齐 SS 三工厂)         */
/**************************************************/

VOID
FileLockManager_ConfigDefault(
    _Out_ PWKD_FILE_LOCK_CONFIG Config
    );

VOID
FileLockManager_ConfigAggressive(
    _Out_ PWKD_FILE_LOCK_CONFIG Config
    );

VOID
FileLockManager_ConfigSafe(
    _Out_ PWKD_FILE_LOCK_CONFIG Config
    );

/**************************************************/
/*                   锁检测                        */
/**************************************************/

/* IsFileLocked — CreateFileW 低影响探测。
 * 成功打开(共享读+全共享位) → 未锁;
 * 失败区分 ERROR_SHARING_VIOLATION/LOCK_VIOLATION (真锁)
 * 与 ERROR_ACCESS_DENIED (只读系统文件误报, 非锁)。
 * AccessDeniedMisreport 输出: 因权限被拒而非锁时为 TRUE。 */
BOOLEAN
FileLockManager_IsFileLocked(
    _In_  PCWSTR FilePath,
    _Out_opt_ PBOOLEAN AccessDeniedMisreport
    );

/* GetLockType — 读/写双 open 探测分类 (对齐 SS GetLockType)。 */
WKD_LOCK_TYPE
FileLockManager_GetLockType(
    _In_ PCWSTR FilePath
    );

/* CanDeleteFile — DELETE 访问探测 (对齐 SS CanDeleteFile)。 */
BOOLEAN
FileLockManager_CanDeleteFile(
    _In_ PCWSTR FilePath
    );

/* GetLockingProcesses — RM + 句柄枚举双路合并去重。
 * Owners 动态分配 (UtHeapAlloc), 调用方以 FileLockManager_FreeLockOwners 释放。 */
_Check_return_
NTSTATUS
FileLockManager_GetLockingProcesses(
    _In_  PCWSTR FilePath,
    _Out_ PWKD_LOCK_OWNER* Owners,
    _Out_ PULONG Count
    );

/* EnumerateHandles — 仅句柄枚举级深层枚举 (对齐 SS EnumerateHandles L1108-1110,
 * 不含 RM 合并)。用于取证/调试。动态分配, 以 FileLockManager_FreeLockOwners 释放。 */
_Check_return_
NTSTATUS
FileLockManager_EnumerateHandles(
    _In_  PCWSTR FilePath,
    _Out_ PWKD_LOCK_OWNER* Owners,
    _Out_ PULONG Count
    );

VOID
FileLockManager_FreeLockOwners(
    _In_opt_ PWKD_LOCK_OWNER Owners
    );

/* GetLockInfo — 汇总文件元数据 + 锁 owner + 威胁评估。
 * Info->Owners 动态分配, 调用方以 FileLockManager_FreeLockInfo 释放。 */
_Check_return_
NTSTATUS
FileLockManager_GetLockInfo(
    _In_  PCWSTR FilePath,
    _Out_ PWKD_FILE_LOCK_INFO Info
    );

VOID
FileLockManager_FreeLockInfo(
    _Inout_ PWKD_FILE_LOCK_INFO Info
    );

/* GetApplicationsUsingFile — RM 应用名枚举。
 * Apps 动态分配, 调用方以 FileLockManager_FreeApps 释放。 */
_Check_return_
NTSTATUS
FileLockManager_GetApplicationsUsingFile(
    _In_  PCWSTR FilePath,
    _Out_ PWKD_LOCK_APP** Apps,
    _Out_ PULONG Count
    );

VOID
FileLockManager_FreeApps(
    _In_opt_ PWKD_LOCK_APP Apps
    );

/**************************************************/
/*                   解锁操作                       */
/**************************************************/

/* UnlockFile — 五级升级链 (对齐 SS UnlockFile):
 *   检测锁 → RM → HandleClose → KernelUnlock → ProcessTerminate → DeleteOnReboot。
 * 关键进程保护先检查 (ProcessCritical)。 */
_Check_return_
NTSTATUS
FileLockManager_UnlockFile(
    _In_  PCWSTR FilePath,
    _Out_ PWKD_UNLOCK_OPERATION Op
    );

/* UnlockFileWithMethod — 指定方法解锁 (对齐 SS UnlockFile(method))。 */
_Check_return_
NTSTATUS
FileLockManager_UnlockFileWithMethod(
    _In_  PCWSTR FilePath,
    _In_  WKD_UNLOCK_METHOD Method,
    _Out_ PWKD_UNLOCK_OPERATION Op
    );

/* ForceUnlockFile — 全部方法强制解锁 (对齐 SS ForceUnlockFile)。 */
_Check_return_
NTSTATUS
FileLockManager_ForceUnlockFile(
    _In_  PCWSTR FilePath,
    _Out_ PWKD_UNLOCK_OPERATION Op
    );

/* CloseHandle — 复制句柄关闭 (DuplicateHandle+DUPLICATE_CLOSE_SOURCE,
 * PID 复用复核 + 进程退出复核, 对齐 SS CloseHandleOp)。 */
BOOLEAN
FileLockManager_CloseHandle(
    _In_ const PWKD_LOCK_OWNER Owner
    );

/* TerminateProcess — 终止持锁进程 (对齐 SS TerminateProcessOp)。
 * 委托 ProcessManager_KillProcess (8 级升级链 + TOCTOU + 关键进程豁免)。 */
BOOLEAN
FileLockManager_TerminateProcess(
    _In_ const PWKD_LOCK_OWNER Owner,
    _In_ BOOLEAN Force
    );

/* UseRestartManager — RM 强关会话 (RmShutdown RmForceShutdown, 对齐 SS)。 */
BOOLEAN
FileLockManager_UseRestartManager(
    _In_ PCWSTR FilePath
    );

/**************************************************/
/*                 重启调度操作                     */
/**************************************************/

BOOLEAN
FileLockManager_ScheduleDeleteOnReboot(
    _In_ PCWSTR FilePath
    );

BOOLEAN
FileLockManager_ScheduleMoveOnReboot(
    _In_ PCWSTR SourcePath,
    _In_ PCWSTR DestinationPath
    );

/* GetPendingOperations — 返回挂起队列副本 (动态分配, FreePendingOperations 释放)。
 * 接口活代码, 当前无 UI/驱动消费方 (死代码标注)。 */
ULONG
FileLockManager_GetPendingOperations(
    _Out_ PWKD_PENDING_OPERATION* Operations
    );

VOID
FileLockManager_FreePendingOperations(
    _In_opt_ PWKD_PENDING_OPERATION Operations
    );

BOOLEAN
FileLockManager_CancelPendingOperation(
    _In_ PCWSTR SourcePath
    );

/**************************************************/
/*               威胁关联 (对齐 SS AnalyzeThreat)    */
/**************************************************/

/* AnalyzeThreat — 锁上下文 APT 威胁评估。
 * 评分公式对齐 SS AnalyzeThreatInternal (未签名+15/注入+40/系统独占+30/
 * 多锁>3 每+5/模式加成 Ransomware+80 等, suspicious≥30/action≥70)。
 * 接线: 死代码, 建议经 VerdictEngine E6 槽位融合 (防与 E5 双计)。 */
_Check_return_
NTSTATUS
FileLockManager_AnalyzeThreat(
    _In_  PWKD_FILE_LOCK_INFO Info,
    _Out_ PWKD_THREAT_ASSESSMENT Threat
    );

/**************************************************/
/*               内核集成 (死代码)                  */
/**************************************************/

/* KernelUnlockFile — 经 FLT 通信端口请求驱动强制关句柄。
 * ※死代码: SS 驱动端未实现该命令 (KernelProtocol 纯用户态预留,
 * PhantomSensor CommPort.c 分派 switch 无 ForceCloseHandle);
 * wkd 驱动 FspMessageNotify(Filter.c:349) 空壳为预留扩展点。
 * 实际兜底为 FileLockManager_CloseHandle 用户态句柄关闭。 */
BOOLEAN
FileLockManager_KernelUnlockFile(
    _In_ PCWSTR FilePath
    );

BOOLEAN
FileLockManager_IsKernelDriverAvailable(
    VOID
    );

BOOLEAN
FileLockManager_ConnectKernelDriver(
    VOID
    );

VOID
FileLockManager_DisconnectKernelDriver(
    VOID
    );

/**************************************************/
/*               配置与统计                         */
/**************************************************/

VOID
FileLockManager_SetAllowProcessTermination(
    _In_ BOOLEAN Allow
    );

/* 回调注册 (死代码: ALPC 覆盖告警分发, 保留 SS 公共 API 面对齐, 供后续接线) */
VOID
FileLockManager_SetTerminateCallback(
    _In_opt_ WKD_FLM_TERMINATE_CALLBACK Callback
    );

VOID
FileLockManager_SetProgressCallback(
    _In_opt_ WKD_FLM_PROGRESS_CALLBACK Callback
    );

VOID
FileLockManager_SetLockEventCallback(
    _In_opt_ WKD_FLM_LOCK_EVENT_CALLBACK Callback
    );

VOID
FileLockManager_SetProtectSystemProcesses(
    _In_ BOOLEAN Protect
    );

VOID
FileLockManager_GetStatistics(
    _Out_ PWKD_FILE_LOCK_STATS Stats
    );

VOID
FileLockManager_ResetStatistics(
    VOID
    );

/**************************************************/
/*                   自测                           */
/**************************************************/

_Check_return_
NTSTATUS
FileLockManager_SelfTest(
    VOID
    );
