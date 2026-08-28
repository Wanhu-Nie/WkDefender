/**************************************************/
/*  WkDefender Agent — 扫描编排层 ScanManager       */
/*  迁移自 ShadowStrike ScanEngine (编排层, 非检测) */
/*  按功能融合重实现，非源码复制。                  */
/*                                                  */
/*  功能面覆盖:                                     */
/*   - ScanFile 流水线 (排除→哈希→缓存→白名单→扫描) */
/*   - ScanDirectory 递归遍历 + 过滤                */
/*   - ScanJob 状态机 (排队/运行/完成/取消/失败)     */
/*   - 排除规则 (路径前缀/扩展名/进程名)            */
/*   - 结果缓存 (LRU + TTL)                         */
/*   - 进度/完成回调 (供 ALPC 通知挂接)             */
/*   - 统计计数器                                   */
/**************************************************/

#pragma once

#include "IOC/IocTypes.h"

/**************************************************/
/*               常量                               */
/**************************************************/

#define WKD_SCAN_MAX_JOBS          4       /* 并发任务上限 */
#define WKD_SCAN_MAX_THREATS       256     /* 单任务威胁上限 */
#define WKD_SCAN_MAX_EXCLUSIONS    64      /* 排除规则上限 */
#define WKD_SCAN_CACHE_ENTRIES     512     /* 结果缓存容量 (LRU) */
#define WKD_SCAN_CACHE_TTL_MS      900000  /* 结果缓存 TTL: 15min */

/**************************************************/
/*               枚举                               */
/**************************************************/

typedef enum _WKD_SCAN_TYPE {
    WkdScanType_Quick = 0,      /* 关键目录 */
    WkdScanType_Full,           /* 全盘 */
    WkdScanType_Custom,         /* 指定路径 */
} WKD_SCAN_TYPE;

typedef enum _WKD_SCAN_STATE {
    WkdScanState_Idle = 0,
    WkdScanState_Queued,
    WkdScanState_Running,
    WkdScanState_Paused,        /* 暂停 (ScanManager_PauseScan) */
    WkdScanState_Completed,
    WkdScanState_Cancelled,
    WkdScanState_Failed,
} WKD_SCAN_STATE;

typedef enum _AE_THREAT_SEVERITY {
    WkdThreatSev_Low = 0,
    WkdThreatSev_Medium,
    WkdThreatSev_High,
} AE_THREAT_SEVERITY;

/**************************************************/
/*               结构体声明                         */
/**************************************************/

/* 单个威胁结果（对齐 UI ScanResultItem） */
typedef struct _WKD_SCAN_THREAT {
    WCHAR               FilePath[MAX_PATH];
    WCHAR               ThreatName[64];
    AE_THREAT_SEVERITY Severity;
    BOOLEAN             IsCleaned;
} WKD_SCAN_THREAT, *PWKD_SCAN_THREAT;

/* 扫描任务（Job 状态机） */
typedef struct _WKD_SCAN_JOB {
    ULONG               JobId;
    WKD_SCAN_TYPE       Type;
    WCHAR               RootPath[MAX_PATH];
    BOOLEAN             Recursive;

    volatile LONG       State;          /* WKD_SCAN_STATE */
    volatile LONG       Progress;       /* 0-100 */
    volatile LONG       FilesScanned;
    volatile LONG       TotalFiles;
    volatile LONG       ThreatsFound;

    HANDLE              Thread;         /* 扫描线程 */
    HANDLE              CancelEvent;
    volatile LONG       Paused;         /* 暂停标志 (PauseScan/ResumeScan) */

    CRITICAL_SECTION    Lock;
    WKD_SCAN_THREAT     Threats[WKD_SCAN_MAX_THREATS];
    volatile LONG       ThreatCount;

    FILETIME            StartTime;
    FILETIME            EndTime;
} WKD_SCAN_JOB, *PWKD_SCAN_JOB;

/* 排除规则 */
typedef enum _WKD_EXCLUSION_TYPE {
    WkdExclType_PathPrefix = 0,     /* 路径前缀 */
    WkdExclType_Extension,          /* 扩展名 */
    WkdExclType_ProcessName,        /* 文件名 */
} WKD_EXCLUSION_TYPE;

typedef struct _WKD_EXCLUSION_RULE {
    WKD_EXCLUSION_TYPE  Type;
    WCHAR               Pattern[MAX_PATH];
    BOOLEAN             Enabled;
} WKD_EXCLUSION_RULE, *PWKD_EXCLUSION_RULE;

/* 回调（ALPC 通知挂接） */
typedef VOID (*WKD_SCAN_PROGRESS_CB)(
    _In_ ULONG JobId,
    _In_ ULONG Progress,
    _In_ ULONG Files,
    _In_ ULONG Threats
    );

typedef VOID (*WKD_SCAN_COMPLETE_CB)(
    _In_ ULONG JobId,
    _In_ ULONG Threats
    );

/* 单个威胁发现回调（ALPC 0x6002 通知挂接，逐条上报） */
typedef VOID (*WKD_SCAN_THREAT_CB)(
    _In_ ULONG JobId,
    _In_ PWKD_SCAN_THREAT Threat
    );

/* 结果缓存条目（内部置于 .c） */

/**************************************************/
/*               信誉评分统计                       */
/*  (SS FileReputation 迁移, 2026-08-06)           */
/**************************************************/

typedef struct _WKD_REPUTATION_STATS {
    volatile LONG64 ReputationChecks;      /* 信誉评分执行次数 (对齐 SS totalQueries) */
    volatile LONG64 LocalHits;             /* 本地库命中 (对齐 SS localHits, 待接线) */
    volatile LONG64 CloudQueries;          /* 云查询 (对齐 SS cloudQueries, 死代码无云后端) */
    volatile LONG64 MaliciousDetected;     /* 恶意判定数 (对齐 SS maliciousDetected) */
    volatile LONG64 SuspiciousDetected;    /* 可疑判定数 (对齐 SS suspiciousDetected) */
    volatile LONG64 UnknownFiles;          /* Unknown 等级计数 (对齐 SS unknownFiles) */
    volatile LONG64 TrustedFiles;          /* 可信等级计数 (对齐 SS trustedFiles) */
    volatile LONG64 BlacklistHits;         /* 哈希黑名单命中 (对齐 SS localHits 黑名单侧) */
    volatile LONG64 CertReputationHits;    /* 证书信誉判定次数 */
    volatile LONG64 CacheEvictions;        /* 缓存淘汰 (对齐 SS EvictOldestCacheEntry) */
    volatile LONG64 PersistenceLoads;      /* file_reputation 读取次数 */
    volatile LONG64 PersistenceSaves;      /* file_reputation 写入次数 */
    volatile LONG64 AverageLatencyUs;      /* 平均耗时 EMA (对齐 SS averageLatencyUs) */
    volatile LONG64 MaxLatencyUs;          /* 最大耗时 (对齐 SS maxLatencyUs) */
    volatile LONG64 CloudFailures;         /* 云失败 (对齐 SS cloudFailures, 死代码) */
} WKD_REPUTATION_STATS, *PWKD_REPUTATION_STATS;

/**************************************************/
/*               全局实例                           */
/**************************************************/

typedef struct _WKD_SCAN_MANAGER {
    BOOLEAN             Initialized;
    CRITICAL_SECTION    Lock;
    WKD_SCAN_JOB        Jobs[WKD_SCAN_MAX_JOBS];
    WKD_EXCLUSION_RULE  Exclusions[WKD_SCAN_MAX_EXCLUSIONS];
    volatile LONG       ExclusionCount;
    WKD_SCAN_PROGRESS_CB ProgressCb;
    WKD_SCAN_COMPLETE_CB CompleteCb;
    WKD_SCAN_THREAT_CB   ThreatCb;
    volatile LONG64     TotalScans;         /* 统计 */
    volatile LONG64     FilesScanned;       /* 已扫描文件计数 */
    volatile LONG64     TotalThreats;
    volatile LONG64     CacheHits;
    volatile LONG64     CacheMisses;       /* 缓存未命中计数 (SS FileHasher cacheMisses) */
    volatile LONG64     WhitelistHits;
    volatile LONG64     LockedFiles;      /* 被锁文件跳过扫描计数 (FileLockManager 迁移 2026-08) */
    WKD_REPUTATION_STATS RepStats;         /* 信誉评分统计 (SS FileReputation 迁移 2026-08) */
    HANDLE              CacheCleanupThread; /* 缓存 TTL 清扫线程 */
    HANDLE              CacheCleanupEvent;
} WKD_SCAN_MANAGER, *PWKD_SCAN_MANAGER;

extern WKD_SCAN_MANAGER g_ScanManager;

/**************************************************/
/*               函数声明                           */
/**************************************************/

NTSTATUS
ScanManager_Initialize(
    VOID
    );

VOID
ScanManager_Cleanup(
    VOID
    );

/*++
Routine Description:
    启动一个扫描任务（异步，立即返回 JobId）。

Arguments:
    Type  - 扫描类型 (Quick/Full/Custom)。
    Path  - 自定义扫描根路径 (Custom 必填，其余可 NULL)。
    JobId - 输出任务 ID。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
ScanManager_StartScan(
    _In_ WKD_SCAN_TYPE          Type,
    _In_opt_ PCWSTR             Path,
    _Out_ PULONG                JobId
    );

/*++
Routine Description:
    取消指定扫描任务。

Arguments:
    JobId - 任务 ID。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
ScanManager_CancelScan(
    _In_ ULONG                  JobId
    );

/*++
Routine Description:
    查询任务状态。

Arguments:
    JobId - 任务 ID。
    State - 输出 WKD_SCAN_STATE。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
ScanManager_GetScanState(
    _In_ ULONG                  JobId,
    _Out_ PULONG                State
    );

/*++
Routine Description:
    查询任务进度。

Arguments:
    JobId    - 任务 ID。
    Progress - 输出 0-100。
    Files    - 输出已扫描文件数。
    Threats  - 输出已发现威胁数。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
ScanManager_GetScanProgress(
    _In_ ULONG                  JobId,
    _Out_opt_ PULONG            Progress,
    _Out_opt_ PULONG            Files,
    _Out_opt_ PULONG            Threats
    );

/*++
Routine Description:
    获取任务已收集的威胁列表（内部加锁快照）。

Arguments:
    JobId   - 任务 ID。
    Threats - 输出威胁数组指针（指向任务内部存储，调用方不得释放）。
    Count   - 输出威胁数量。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
ScanManager_GetScanThreats(
    _In_ ULONG                  JobId,
    _Out_ PWKD_SCAN_THREAT*     Threats,
    _Out_ PULONG                Count
    );

/*++
Routine Description:
    单文件快速扫描（独立于任务，供事件驱动/单文件请求复用）。
    流程: 排除 → SHA256 → 缓存 → 白名单 → IocEngine_ScanFile → 缓存。

Arguments:
    FilePath - 文件完整路径。
    Result   - 输出 IOC 扫描结果。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
ScanManager_ScanFileDirect(
    _In_ PCWSTR                 FilePath,
    _Out_ PIOC_SCAN_RESULT      Result
    );

/*++
Routine Description:
    判断路径是否命中排除规则。

Arguments:
    Path - 文件完整路径。

Return Value:
    TRUE = 排除。
--*/
BOOLEAN
ScanManager_IsExcluded(
    _In_ PCWSTR                 Path
    );

/*++
Routine Description:
    添加排除规则。

Arguments:
    Rule - 排除规则（拷贝）。
--*/
VOID
ScanManager_AddExclusion(
    _In_ PWKD_EXCLUSION_RULE    Rule
    );

/*++
Routine Description:
    设置进度/完成回调（ALPC 通知挂接点）。

Arguments:
    ProgressCb - 进度回调。
    CompleteCb - 完成回调。
--*/
VOID
ScanManager_SetCallbacks(
    _In_opt_ WKD_SCAN_PROGRESS_CB ProgressCb,
    _In_opt_ WKD_SCAN_COMPLETE_CB CompleteCb
    );

/*++
Routine Description:
    设置单个威胁发现回调（逐条上报，供 ALPC 0x6002 通知挂接）。

Arguments:
    ThreatCb - 威胁回调。
--*/
VOID
ScanManager_SetThreatCallback(
    _In_opt_ WKD_SCAN_THREAT_CB ThreatCb
    );

/*++
Routine Description:
    文件数组批处理扫描 (对齐 SS ScanBatch)。
    顺序扫描每个文件，命中威胁收集到输出数组。

Arguments:
    FilePaths - 文件路径数组。
    Count     - 数组长度。
    Threats   - 输出威胁数组 (容量 WKD_SCAN_MAX_THREATS)。
    ThreatCount - 输出威胁数量。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
ScanManager_ScanBatch(
    _In_ PCWSTR*            FilePaths,
    _In_ ULONG              Count,
    _Out_ PWKD_SCAN_THREAT  Threats,
    _Out_ PULONG            ThreatCount
    );

/*++
Routine Description:
    暂停扫描任务。

Arguments:
    JobId - 任务 ID。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
ScanManager_PauseScan(
    _In_ ULONG              JobId
    );

/*++
Routine Description:
    恢复已暂停的扫描任务。

Arguments:
    JobId - 任务 ID。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
ScanManager_ResumeScan(
    _In_ ULONG              JobId
    );

/*++
Routine Description:
    内存缓冲快速扫描 (对齐 SS ScanMemory)。
    缓冲 SHA256 → 缓存 → 恶意库预检 → 判定。

Arguments:
    Buf    - 内存缓冲。
    Len    - 长度。
    Result - 输出 IOC 结果。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
ScanManager_ScanMemoryBuffer(
    _In_ const BYTE*        Buf,
    _In_ ULONG              Len,
    _Out_ PIOC_SCAN_RESULT  Result
    );

/*++
Routine Description:
    按 PID 扫描进程 (对齐 SS ScanProcess)。
    解析进程可执行文件路径 → ScanFileDirect。

Arguments:
    Pid    - 进程 ID。
    Result - 输出 IOC 结果。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
ScanManager_ScanProcess(
    _In_ ULONG              Pid,
    _Out_ PIOC_SCAN_RESULT  Result
    );

/*++
Routine Description:
    枚举全部进程扫描 (对齐 SS ScanAllProcesses)。
    Toolhelp 快照遍历，忽略系统进程 PID{0,4}。

Arguments:
    Pids - 输出扫描到的进程 ID 数组 (容量 1024)。
    Count - 输出数量。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
ScanManager_ScanAllProcesses(
    _Out_ ULONG*            Pids,
    _In_ ULONG              MaxCount,
    _Out_ PULONG            Count
    );

/*++
Routine Description:
    缓存预热 (对齐 SS WarmCache)：预扫描常见路径填充结果缓存。

Arguments:
    Paths - 路径数组。
    Count - 数量。
--*/
VOID
ScanManager_WarmCache(
    _In_ PCWSTR*            Paths,
    _In_ ULONG              Count
    );

/*++
Routine Description:
    引擎自测 (对齐 SS SelfTest)：缓存存取/排除规则/单文件扫描。

Return Value:
    TRUE = 全部通过。
--*/
BOOLEAN
ScanManager_SelfTest(
    VOID
    );

/*++
Routine Description:
    显式清空结果缓存 (对齐 SS FileHasher::ClearCache)。
--*/
VOID
ScanManager_ClearCache(
    VOID
    );

/*++
Routine Description:
    当前缓存条目数 (对齐 SS FileHasher::GetCacheSize)。

Return Value:
    活跃缓存条目数。
--*/
ULONG
ScanManager_GetCacheSize(
    VOID
    );
