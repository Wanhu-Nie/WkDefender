/**************************************************/
/*  WkDefender Agent — 目录监控编排层 DirectoryMonitor */
/*                                                  */
/*  迁移自 ShadowStrike DirectoryMonitor.cpp        */
/*  (PhantomCore/Core/FileSystem, 1604 行),          */
/*  按功能融合重实现, 非源码复制。                    */
/*                                                  */
/*  职责: 目录级状态监控事件源 (L2 独立信号源)。     */
/*    - 关键路径自动发现 (System/User/Startup/       */
/*      Downloads/Temp)                             */
/*    - 每目录 worker 线程 + OVERLAPPED 异步 RDCW    */
/*    - reparse point 拒绝 + 句柄最终路径验证        */
/*      (FILE_FLAG_OPEN_REPARSE_POINT, 防 TOCTOU)    */
/*    - 智能过滤 + 限流 + 统计 + 生命周期            */
/*                                                  */
/*  不承载检测逻辑 — 检测融合进:                     */
/*    IoaPersistenceDetect (目录投放) /              */
/*    IoaRansomwareDetect (目录批量变化) /           */
/*    ScanManager (Quick 扫描路径库 + 新增文件触发)  */
/*    VerdictEngine (NULL-NodeId 目录级告警)          */
/*                                                  */
/*  与驱动 minifilter 关系: 驱动提供操作级+进程      */
/*  上下文事件 (Filter.c → WkdEvent_File*), 本模块   */
/*  提供目录级聚合视图 (RDCW 无 PID, 不可阻断)。     */
/*  二者分层消费, 不强行去重。                       */
/*                                                  */
/*  死代码标注: 消费链默认 g_IoaDirectoryMonitorEnabled */
/*  =FALSE (main.c 回调门控), 编排器本体可独立运行/  */
/*  SelfTest。 长路径 (>DEF_MAX_PATH) 目录暂不支持   */
/*  (搁置项)。                                      */
/**************************************************/

#pragma once

#include "DefendTypes.h"

/**************************************************/
/*               常量                               */
/**************************************************/

#define WKD_DIR_MAX_MONITORS        64      /* SS MAX_CONCURRENT_MONITORS=1000 缩至 64, 内存可控 */
#define WKD_DIR_NOTIFY_BUFFER       65536   /* RDCW 通知缓冲: MS 远程共享硬上限 (SS kNotifyBufferBytes) */
#define WKD_DIR_MAX_FILENAME        512     /* 单文件名存储上限 (防御性截断) */
#define WKD_DIR_MAX_RECORD_FILENAME 32767u  /* FILE_NOTIFY_INFORMATION 文件名字节上限 (SS kMaxFileNameBytes/2) */
#define WKD_DIR_MAX_RATELIMIT_TICKS 4096    /* 每 monitor 限流时间戳滑动窗容量 (SS kMaxRateLimitBuckets) */
#define WKD_DIR_CONSECUTIVE_ERRORS  16      /* RDCW 连续错误放弃阈值 (SS kMaxConsecutiveErrors) */
#define WKD_DIR_STOP_TIMEOUT_MS     10000   /* worker 线程退出等待 (SS StopMonitor) */
#define WKD_DIR_MAX_CONFIG_PATHS    8       /* 配置附加路径上限 */
#define WKD_DIR_MAX_EXCLUDED_PATHS  16      /* 配置排除路径上限 */
#define WKD_DIR_MAX_QUICK_ROOTS     12      /* GetQuickScanRoots 输出容量 */

/**************************************************/
/*               枚举                               */
/**************************************************/

/* 监控路径分类 (对齐 SS PathCategory, 全量枚举) */
typedef enum _WKD_DIR_CATEGORY {
    WkdDirCat_Unknown        = 0,
    WkdDirCat_SystemCritical = 1,   /* System32/Windows/drivers/Program Files */
    WkdDirCat_UserProfile    = 2,   /* AppData/Documents/Desktop */
    WkdDirCat_Startup        = 3,   /* 启动文件夹 */
    WkdDirCat_Downloads      = 4,   /* 下载目录 */
    WkdDirCat_Temporary      = 5,   /* Temp */
    WkdDirCat_RemovableMedia = 6,   /* ※死代码: SS 纸面功能, 发现逻辑未实现 (cpp 仅枚举预留) */
    WkdDirCat_NetworkShare   = 7,   /* ※死代码: 同上, config.monitorNetworkShares 无消费方 */
    WkdDirCat_CloudSync      = 8,   /* ※死代码: 同上, autoDiscoverNewPaths 无实现 */
    WkdDirCat_Custom         = 9,   /* 用户自定义 */
} WKD_DIR_CATEGORY, *PWKD_DIR_CATEGORY;

/* 监控器状态机 (对齐 SS DirectoryMonitorStatus) */
typedef enum _WKD_DIR_STATUS {
    WkdDirStatus_Uninitialized = 0,
    WkdDirStatus_Initializing  = 1,
    WkdDirStatus_Running       = 2,
    WkdDirStatus_Paused        = 3,
    WkdDirStatus_Error         = 4,
    WkdDirStatus_Stopping      = 5,
    WkdDirStatus_Stopped       = 6,
} WKD_DIR_STATUS, *PWKD_DIR_STATUS;

/* 目录变化动作 (对齐 SS FileSystemAction) */
typedef enum _WKD_DIR_ACTION {
    WkdDirAct_Unknown       = 0,
    WkdDirAct_FileAdded     = 1,
    WkdDirAct_FileRemoved   = 2,
    WkdDirAct_FileModified  = 3,
    WkdDirAct_FileRenamed   = 4,    /* RENAMED_OLD+NEW 配对后 */
    WkdDirAct_DirAdded      = 5,
    WkdDirAct_DirRemoved    = 6,
    WkdDirAct_DirRenamed    = 7,
} WKD_DIR_ACTION, *PWKD_DIR_ACTION;

/**************************************************/
/*               结构体声明                         */
/**************************************************/

/* 监控配置 (对齐 SS DirectoryMonitorConfig, 裁剪 autoDiscover/媒体/网络项) */
typedef struct _WKD_DIR_MONITOR_CONFIG {
    BOOLEAN     Enabled;
    BOOLEAN     MonitorSystemPaths;
    BOOLEAN     MonitorUserPaths;
    BOOLEAN     MonitorStartupLocations;
    BOOLEAN     MonitorTempDirectories;
    BOOLEAN     EnableRateLimiting;
    BOOLEAN     EnableIntelligentFiltering;
    ULONG       MaxConcurrentMonitors;      /* 0 → 默认 WKD_DIR_MAX_MONITORS */
    ULONG       RateLimitWindowSec;         /* 限流窗口 (秒), 默认 60 */
    ULONG       MaxEventsPerWindow;         /* 每窗口事件上限, 默认 1000 */
    WCHAR       AdditionalPaths[WKD_DIR_MAX_CONFIG_PATHS][DEF_MAX_PATH];
    ULONG       AdditionalPathCount;
    WCHAR       ExcludedPaths[WKD_DIR_MAX_EXCLUDED_PATHS][DEF_MAX_PATH];
    ULONG       ExcludedPathCount;
} WKD_DIR_MONITOR_CONFIG, *PWKD_DIR_MONITOR_CONFIG;

/* 目录监控事件 (对齐 SS DirectoryEvent, 定长 C 结构) */
typedef struct _WKD_DIR_EVENT {
    ULONG           EventId;
    ULONG           MonitorId;
    WCHAR           Path[DEF_MAX_PATH];                 /* 监控目录 */
    WCHAR           FileName[WKD_DIR_MAX_FILENAME];     /* 变化的文件/目录名 */
    WCHAR           OldFileName[WKD_DIR_MAX_FILENAME];  /* rename 旧名 (非 rename 空) */
    WKD_DIR_ACTION  Action;
    WKD_DIR_CATEGORY Category;
    LARGE_INTEGER   Timestamp;
} WKD_DIR_EVENT, *PWKD_DIR_EVENT;

/* 已监控路径快照 (对齐 SS MonitoredPath) */
typedef struct _WKD_DIR_MONITORED_PATH {
    ULONG           MonitorId;
    WCHAR           Path[DEF_MAX_PATH];
    WKD_DIR_CATEGORY Category;
    BOOLEAN         Recursive;
    BOOLEAN         IsActive;
    LONG64          EventsReceived;
    LARGE_INTEGER   LastEventNs;        /* 上次事件时间 (FILETIME 100ns, 0 = 无) */
    LARGE_INTEGER   CreatedTime;        /* 监控创建时间 (对齐 SS createdTime) */
} WKD_DIR_MONITORED_PATH, *PWKD_DIR_MONITORED_PATH;

/* 运行统计 (对齐 SS DirectoryMonitorStatistics, C 原子) */
typedef struct _WKD_DIR_STATS {
    volatile LONG   ActiveMonitors;
    volatile LONG64 TotalEvents;
    volatile LONG64 FilteredEvents;
    volatile LONG64 RateLimitedEvents;
    volatile LONG64 Errors;
    volatile LONG64 PathsDiscovered;
    volatile LONG64 CallbackInvocations;
    volatile LONG64 TotalProcessingTimeUs;   /* 累计事件处理耗时 (us, 对齐 SS totalProcessingTimeUs) */
    LONG64          ByCategory[10];          /* WKD_DIR_CATEGORY 索引 */
    LONG64          ByAction[8];             /* WKD_DIR_ACTION 索引 */
} WKD_DIR_STATS, *PWKD_DIR_STATS;

/* 回调类型 (对齐 SS DirectoryEventCallback 等) */
typedef VOID (*WKD_DIR_EVENT_CB)(_In_ const WKD_DIR_EVENT* Evt);
typedef VOID (*WKD_DIR_STATUS_CB)(_In_ ULONG MonitorId, _In_ BOOLEAN Active);
typedef VOID (*WKD_DIR_ERROR_CB)(_In_ PCWSTR Path, _In_ PCWSTR Error);

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*++
Routine Description:
    初始化目录监控。配置非法返回 STATUS_INVALID_PARAMETER;
    !Enabled 视为停用, 返回 STATUS_SUCCESS。

Arguments:
    Config - 配置 (可 NULL, 用默认)。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
DirectoryMonitor_Initialize(
    _In_opt_ const WKD_DIR_MONITOR_CONFIG* Config
    );

VOID
DirectoryMonitor_Cleanup(
    VOID
    );

/*++
Routine Description:
    按配置监控所有关键路径 (系统/用户/启动/下载/临时)。
    单个失败仅记统计, 不中止扫描。
--*/
VOID
DirectoryMonitor_MonitorCriticalPaths(
    VOID
    );

/*++
Routine Description:
    添加目录监控。规范化 → reparse 拒绝 → 排除 → 去重 →
    上限 → CreateFile(OPEN_REPARSE_POINT) → 句柄最终路径验证 → 建 worker。

Arguments:
    Path      - 目录完整路径。
    Category  - 路径分类。
    Recursive - 是否递归监控子目录。

Return Value:
    MonitorId (0 = 失败)。
--*/
ULONG
DirectoryMonitor_AddMonitor(
    _In_ PCWSTR            Path,
    _In_ WKD_DIR_CATEGORY  Category,
    _In_ BOOLEAN           Recursive
    );

VOID
DirectoryMonitor_RemoveMonitor(
    _In_ ULONG             MonitorId
    );

VOID
DirectoryMonitor_RemoveAll(
    VOID
    );

BOOLEAN
DirectoryMonitor_IsMonitored(
    _In_ PCWSTR            Path
    );

ULONG
DirectoryMonitor_GetActiveCount(
    VOID
    );

VOID
DirectoryMonitor_PauseAll(
    VOID
    );

VOID
DirectoryMonitor_ResumeAll(
    VOID
    );

VOID
DirectoryMonitor_PauseMonitor(
    _In_ ULONG             MonitorId
    );

VOID
DirectoryMonitor_ResumeMonitor(
    _In_ ULONG             MonitorId
    );

VOID
DirectoryMonitor_SetEventCallback(
    _In_opt_ WKD_DIR_EVENT_CB Callback
    );

VOID
DirectoryMonitor_SetStatusCallback(
    _In_opt_ WKD_DIR_STATUS_CB Callback
    );

VOID
DirectoryMonitor_SetErrorCallback(
    _In_opt_ WKD_DIR_ERROR_CB Callback
    );

NTSTATUS
DirectoryMonitor_GetStatistics(
    _Out_ PWKD_DIR_STATS    Stats
    );

/*++
Routine Description:
    引擎自测: Temp 目录 Add → IsMonitored → Pause → Resume → Remove 生命周期。

Return Value:
    TRUE = 全部通过。
--*/
BOOLEAN
DirectoryMonitor_SelfTest(
    VOID
    );

/*++
Routine Description:
    关键路径发现 (融合供 ScanManager Quick 扫描复用)。
    聚合 SystemCritical/UserProfile/Startup/Downloads/Temp 五类路径,
    填充 Roots 数组 (调用方提供容量)。供 ScanManager_ScanThread
    Quick 分支多根扫描。

Arguments:
    Roots    - 输出路径数组 (每项 DEF_MAX_PATH WCHAR)。
    MaxCount - Roots 容量。
    Count    - 输出路径数。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
DirectoryMonitor_GetQuickScanRoots(
    _Out_writes_(MaxCount) WCHAR (*Roots)[DEF_MAX_PATH],
    _In_ ULONG             MaxCount,
    _Out_ PULONG           Count
    );

/*++
Routine Description:
    快照全部已监控路径 (对齐 SS GetMonitoredPaths)。

Arguments:
    Paths    - 输出数组。
    MaxCount - 数组容量。
    Count    - 输出数量。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
DirectoryMonitor_GetMonitoredPaths(
    _Out_writes_(MaxCount) PWKD_DIR_MONITORED_PATH Paths,
    _In_ ULONG             MaxCount,
    _Out_ PULONG           Count
    );

/*++
Routine Description:
    按 MonitorId 查询监控路径快照 (对齐 SS GetMonitorById)。

Arguments:
    MonitorId - 监控 ID。
    Path      - 输出快照。

Return Value:
    TRUE 找到。
--*/
BOOLEAN
DirectoryMonitor_GetMonitorById(
    _In_ ULONG                  MonitorId,
    _Out_ PWKD_DIR_MONITORED_PATH Path
    );

/*++
Routine Description:
    热更新配置 (对齐 SS SetConfiguration)。worker 每批快照读取,
    即时生效; 非法配置拒绝。

Arguments:
    Config - 新配置。

Return Value:
    NTSTATUS。
--*/
NTSTATUS
DirectoryMonitor_SetConfiguration(
    _In_ const WKD_DIR_MONITOR_CONFIG* Config
    );

/*++
Routine Description:
    读取当前配置 (对齐 SS GetConfiguration)。

Arguments:
    Config - 输出配置。

Return Value:
    无。
--*/
VOID
DirectoryMonitor_GetConfiguration(
    _Out_ PWKD_DIR_MONITOR_CONFIG Config
    );

/*++
Routine Description:
    清零运行统计 (对齐 SS ResetStatistics)。

Return Value:
    无。
--*/
VOID
DirectoryMonitor_ResetStatistics(
    VOID
    );

/*++
Routine Description:
    注销全部回调 (对齐 SS UnregisterCallbacks)。

Return Value:
    无。
--*/
VOID
DirectoryMonitor_UnregisterCallbacks(
    VOID
    );

/*++
Routine Description:
    是否已初始化 (对齐 SS IsInitialized)。

Return Value:
    TRUE 已初始化。
--*/
BOOLEAN
DirectoryMonitor_IsInitialized(
    VOID
    );

/*++
Routine Description:
    当前状态机状态 (对齐 SS GetStatus)。

Return Value:
    WKD_DIR_STATUS。
--*/
WKD_DIR_STATUS
DirectoryMonitor_GetStatus(
    VOID
    );

/*++
Routine Description:
    平均事件处理时间 (ms, 对齐 SS GetAverageProcessingTimeMs)。

Return Value:
    平均处理时间; 无事件时 0。
--*/
double
DirectoryMonitor_GetAverageProcessingTimeMs(
    VOID
    );

/*++
Routine Description:
    版本字符串 (对齐 SS GetVersionString, 静态常量)。

Return Value:
    L"3.0.0"。
--*/
PCWSTR
DirectoryMonitor_GetVersionString(
    VOID
    );

/*++
Routine Description:
    枚举转字符串 (对齐 SS GetPathCategoryName / GetFileSystemActionName /
    GetMonitorStatusName, 死代码调试工具, 无消费方)。

Arguments:
    Category/Action/Status — 枚举值。

Return Value:
    静态字符串常量。
--*/
PCWSTR
DirectoryMonitor_GetCategoryName(
    _In_ WKD_DIR_CATEGORY Category
    );

PCWSTR
DirectoryMonitor_GetActionName(
    _In_ WKD_DIR_ACTION Action
    );

PCWSTR
DirectoryMonitor_GetStatusName(
    _In_ WKD_DIR_STATUS Status
    );

/*++
Routine Description:
    ToJson 序列化 (对齐 SS 各 ToJson, 死代码工具, 无消费方)。
    Out 始终 NUL 结尾, 超长截断。

Arguments:
    Evt/Path/Config/Stats — 待序列化对象。
    Out                  - 输出缓冲。
    MaxLen               - 输出容量 (WCHAR 数)。

Return Value:
    STATUS_SUCCESS。
--*/
NTSTATUS
DirectoryMonitor_EventToJson(
    _In_ const WKD_DIR_EVENT* Evt,
    _Out_writes_(MaxLen) WCHAR* Out,
    _In_ ULONG MaxLen
    );

NTSTATUS
DirectoryMonitor_PathToJson(
    _In_ const WKD_DIR_MONITORED_PATH* Path,
    _Out_writes_(MaxLen) WCHAR* Out,
    _In_ ULONG MaxLen
    );

NTSTATUS
DirectoryMonitor_ConfigToJson(
    _In_ const WKD_DIR_MONITOR_CONFIG* Config,
    _Out_writes_(MaxLen) WCHAR* Out,
    _In_ ULONG MaxLen
    );

NTSTATUS
DirectoryMonitor_StatsToJson(
    _In_ const WKD_DIR_STATS* Stats,
    _Out_writes_(MaxLen) WCHAR* Out,
    _In_ ULONG MaxLen
    );
