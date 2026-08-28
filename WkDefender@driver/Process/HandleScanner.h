/**************************************************/
/*  WkDefender — 句柄扫描引擎（内核态）              */
/*  参考 PhantomSensor HandleTracker.c               */
/*                                                   */
/*  功能：                                           */
/*    - 通过 ZwQuerySystemInformation 安全枚举句柄    */
/*    - 安全复制句柄 (ZwDuplicateObject) 后查询类型   */
/*    - 跨进程句柄检测 (T1055)                        */
/*    - 令牌窃取句柄检测 (T1134)                      */
/*    - 凭证访问句柄检测 (T1003)                      */
/*    - 敏感进程句柄访问检测                           */
/*                                                   */
/*  通信：ALPC 层调用本模块的扫描函数获取结果后发送    */
/**************************************************/

#pragma once

#include "../Common/Constants.h"
//
// 池标记
//
#define HS_POOL_TAG         'HShW'
#define HS_POOL_TAG_BUFFER  'hbsW'
#define HS_POOL_TAG_ENTRY   'eHSW'   /* 缓存句柄条目（对齐 SS HT_POOL_TAG_ENTRY） */
#define HS_POOL_TAG_PROCESS 'pHSW'   /* 缓存快照（对齐 SS HT_POOL_TAG_PROCESS） */

//
// 限制
//
#define HS_MAX_HANDLES_PER_PROCESS  65536
#define HS_MAX_PATH_LENGTH          520
#define HS_MAX_SENSITIVE_PROCESSES  32
#define HS_MAX_OBJECT_NAME_LENGTH   520     // 对象名最大长度（字节，对齐 SS HT_MAX_OBJECT_NAME_LENGTH）
#define HS_MAX_DUPLICATIONS         4096    // 复制记录上限（对齐 SS HT_MAX_DUPLICATIONS）
#define HS_MAX_TRACKED_PROCESSES    4096    // 缓存进程上限（对齐 SS HT_MAX_TRACKED_PROCESSES）

//
// 缓存层常量（对齐 SS HT_HASH_BUCKET_COUNT / HT_SIGNATURE / HT_DEFAULT_*）
//
#define HS_HASH_BUCKET_COUNT            256
#define HS_HASH_BUCKET_MASK             (HS_HASH_BUCKET_COUNT - 1)
#define HS_SIGNATURE                    'HsHw'   /* 快照/tracker 签名 */
#define HS_DEFAULT_CLEANUP_INTERVAL_MS  60000
#define HS_DEFAULT_CACHE_TIMEOUT_MS     30000

//
// 句柄类型枚举
//
typedef enum _HS_HANDLE_TYPE {
    HsTypeUnknown = 0,
    HsTypeProcess,
    HsTypeThread,
    HsTypeFile,
    HsTypeKey,
    HsTypeSection,
    HsTypeToken,
    HsTypeEvent,
    HsTypeSemaphore,
    HsTypeMutex,
    HsTypeTimer,
    HsTypePort,
    HsTypeDevice,
    HsTypeDriver,
    HsTypeMax
} HS_HANDLE_TYPE;

//
// 怀疑标志位
//
typedef enum _HS_SUSPICION {
    HsSuspicion_None             = 0x00000000,
    HsSuspicion_CrossProcess     = 0x00000001,  // 持有其他进程句柄
    HsSuspicion_HighPrivilege    = 0x00000002,  // 高权限访问
    HsSuspicion_SensitiveTarget  = 0x00000004,  // 目标为敏感进程
    HsSuspicion_ManyHandles      = 0x00000008,  // 句柄数过多
    HsSuspicion_InjectionCapable = 0x00000010,  // 具备注入能力
    HsSuspicion_TokenSteal       = 0x00000020,  // 令牌窃取
    HsSuspicion_CredentialAccess = 0x00000040,  // 凭证访问 (LSASS dump)
    HsSuspicion_SystemProcess    = 0x00000080,  // System 进程 (PID=4)
    HsSuspicion_DuplicatedIn     = 0x00000100,  // 复制流入句柄（对齐 SS HtSuspicion_DuplicatedIn；SS 枚举路径未置位 IsDuplicated，此维度在 SS 未激活，标注保留）
} HS_SUSPICION;

//
// 单条句柄条目（扫描结果）
//
typedef struct _HS_HANDLE_ENTRY {
    HANDLE          HandleValue;
    HS_HANDLE_TYPE  Type;
    ACCESS_MASK     GrantedAccess;
    HANDLE          OwnerProcessId;     // 持有者 PID
    HANDLE          TargetProcessId;    // 指向的目标 PID（仅 Process/Thread）
    HS_SUSPICION    SuspicionFlags;
    ULONG           SuspicionScore;     // 0-100
    /* ---- 补充字段（对齐 SS HT_HANDLE_ENTRY，HandleTracker 迁移 2026-08）---- */
    BOOLEAN         IsDuplicated;       // 是否复制流入（SS 枚举路径未置位，死逻辑标注）
    BOOLEAN         Reserved0;
    HANDLE          DuplicatedFromProcess;  // 复制来源进程（SS 未激活，恒 NULL）
    WCHAR           ObjectName[HS_MAX_OBJECT_NAME_LENGTH / sizeof(WCHAR)];  // 对象名（枚举时补查）
    USHORT          ObjectNameLength;   // 对象名长度（字节）
    USHORT          Reserved1;
} HS_HANDLE_ENTRY, *PHS_HANDLE_ENTRY;

//
// 进程句柄聚合结果
//
typedef struct _HS_PROCESS_HANDLE_RESULT {
    HANDLE          ProcessId;          // 目标进程 PID
    ULONG           HandleCount;        // 总句柄数
    ULONG           CrossProcessCount;  // 跨进程句柄数
    ULONG           InjectionCapableCount;  // 具备注入能力的句柄数
    ULONG           TokenStealCount;    // 令牌窃取句柄数
    ULONG           CredentialAccessCount;  // 凭证访问句柄数
    ULONG           HighPrivilegeCount; // 高权限句柄数
    HS_SUSPICION    AggregatedFlags;    // 聚合怀疑标志
    ULONG           SuspicionScore;     // 聚合怀疑评分 (0-100)
    PHS_HANDLE_ENTRY Handles;           // 句柄数组（调用方分配缓冲区）
    ULONG           MaxHandles;         // 缓冲区大小（条目数）
} HS_PROCESS_HANDLE_RESULT, *PHS_PROCESS_HANDLE_RESULT;

//
// 系统范围跨进程句柄结果（用于 T1055 溯源）
//
typedef struct _HS_CROSS_PROCESS_RESULT {
    HANDLE          SourceProcessId;    // 持有句柄的进程 PID
    HANDLE          HandleValue;        // 句柄值
    HS_HANDLE_TYPE  Type;               // 句柄类型
    ACCESS_MASK     GrantedAccess;      // 访问掩码
    HS_SUSPICION    SuspicionFlags;     // 怀疑标志
    ULONG           SuspicionScore;     // 怀疑评分
} HS_CROSS_PROCESS_RESULT, *PHS_CROSS_PROCESS_RESULT;

//
// 扫描配置
//
typedef struct _HS_CONFIG {
    ULONG MaxHandlesPerProcess;
    ULONG MaxCrossProcessResults;
    BOOLEAN EnableCrossProcessDetection;
    BOOLEAN EnableTokenStealDetection;
    BOOLEAN EnableSensitiveProcessDetection;
    /* ---- 补充字段（对齐 SS HT_CONFIG，HandleTracker 迁移 2026-08，供复制追踪/缓存死代码使用）---- */
    BOOLEAN EnableDuplicationTracking;      // 复制追踪开关（对齐 SS HT_CONFIG.EnableDuplicationTracking）
    ULONG   SuspicionThreshold;             // 聚合怀疑阈值（对齐 SS HT_CONFIG.SuspicionThreshold，默认 50）
    ULONG MaxDuplications;              // 复制记录上限（默认 HS_MAX_DUPLICATIONS）
    ULONG CleanupIntervalMs;            // 周期清理间隔（默认 60000）
    ULONG CacheTimeoutMs;               // 复制记录/缓存 TTL（默认 30000）
} HS_CONFIG, *PHS_CONFIG;

//
// 默认配置
//
#define HS_DEFAULT_MAX_HANDLES          4096
#define HS_DEFAULT_MAX_CROSS_PROCESS    1024

//
// ======================================================================
// 公共 API
// ======================================================================
//

/*++
Routine Description:
    枚举指定进程的全部句柄并进行安全分析。
    调用方提供 HS_PROCESS_HANDLE_RESULT 并预分配 Handles 缓冲区。

IRQL: PASSIVE_LEVEL

Arguments:
    Config      — 扫描配置（NULL = 默认值）
    ProcessId   — 目标进程 PID
    Result      — [in] 预分配的结果结构（Handles/HandleCount 由调用方填充）

Return Value:
    STATUS_SUCCESS           — 扫描完成
    STATUS_INVALID_PARAMETER — 参数无效
    STATUS_NOT_FOUND         — 进程不存在
    STATUS_INSUFFICIENT_RESOURCES — 内存不足
    STATUS_BUFFER_TOO_SMALL  — Handles 缓冲区不够大（Result->HandleCount 返回实际数量）
--*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
HsScanProcessHandles(
    _In_opt_ PHS_CONFIG            Config,
    _In_      HANDLE               ProcessId,
    _Inout_   PHS_PROCESS_HANDLE_RESULT Result
    );

/*++
Routine Description:
    查找全系统中所有持有目标进程句柄的跨进程句柄。
    用于 T1055 溯源和 LSASS 凭证访问检测。

IRQL: PASSIVE_LEVEL

Arguments:
    Config          — 扫描配置（NULL = 默认值）
    TargetProcessId — 目标进程 PID（如 LSASS）
    Results         — 调用方预分配的 HS_CROSS_PROCESS_RESULT 数组
    MaxResults      — Results 数组大小
    ResultCount     — 返回实际找到的数量

Return Value:
    STATUS_SUCCESS           — 正常返回
    STATUS_BUFFER_TOO_SMALL  — Results 不够大，ResultCount 返回实际值
    STATUS_INVALID_PARAMETER — 参数无效
--*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
HsFindCrossProcessHandles(
    _In_opt_ PHS_CONFIG              Config,
    _In_      HANDLE                 TargetProcessId,
    _Out_writes_to_(MaxResults, *ResultCount) PHS_CROSS_PROCESS_RESULT Results,
    _In_      ULONG                  MaxResults,
    _Out_     PULONG                 ResultCount
    );

/*++
Routine Description:
    快速检测一个进程是否为敏感进程（LSASS、CSRSS 等）。

IRQL: PASSIVE_LEVEL

Arguments:
    ProcessId   — 进程 PID
    IsSensitive — [out] TRUE=敏感进程

Return Value:
    STATUS_SUCCESS — 正常返回
--*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
HsIsSensitiveProcess(
    _In_  HANDLE   ProcessId,
    _Out_ PBOOLEAN IsSensitive
    );

/**************************************************/
/*  死代码：复制追踪 / 缓存层 / 统计 / 查询 API      */
/*                                                   */
/*  对齐 SS HandleTracker.{c,h}，迁移 2026-08。      */
/*  功能面覆盖但未接入流水线——复制追踪事件源是       */
/*  Ob 回调 OB_OPERATION_HANDLE_DUPLICATE（ObjectNotify */
/*  CbObjectNotifyInitialize 被 WkdEntry 注释），     */
/*  缓存层服务于"创建时全量快照"（与 wkd 分层模型    */
/*  Agent 按需扫描冲突）。接入前均保持死代码。        */
/**************************************************/

//
// 查询 API 输出（对齐 SS HT_HANDLE_INFO / HT_PROCESS_HANDLES_INFO）
//
typedef struct _HS_HANDLE_INFO {
    HANDLE          HandleValue;
    HS_HANDLE_TYPE  Type;
    ACCESS_MASK     GrantedAccess;
    HANDLE          TargetProcessId;
    BOOLEAN         IsDuplicated;
    HANDLE          DuplicatedFromProcess;
    HS_SUSPICION    SuspicionFlags;
    ULONG           SuspicionScore;
    WCHAR           ObjectName[HS_MAX_OBJECT_NAME_LENGTH / sizeof(WCHAR)];
    USHORT          ObjectNameLength;
} HS_HANDLE_INFO, *PHS_HANDLE_INFO;

typedef struct _HS_PROCESS_HANDLES_INFO {
    HANDLE          ProcessId;
    LONG            HandleCount;
    HS_SUSPICION    AggregatedSuspicion;
    ULONG           SuspicionScore;
    ULONG           ProcessHandleCount;
    ULONG           ThreadHandleCount;
    ULONG           FileHandleCount;
    ULONG           TokenHandleCount;
    ULONG           SectionHandleCount;
    ULONG           OtherHandleCount;
    ULONG           CrossProcessHandleCount;
    ULONG           HighPrivilegeHandleCount;
    LARGE_INTEGER   SnapshotTime;
} HS_PROCESS_HANDLES_INFO, *PHS_PROCESS_HANDLES_INFO;

//
// 复制追踪记录（对齐 SS HT_DUPLICATION_RECORD）
// 不接入：跨进程复制关联应归 Agent 因果图（IOA_TIER3 跨进程边），内核不维护复制列表。
//
typedef struct _HS_DUPLICATION_RECORD {
    LIST_ENTRY      ListEntry;
    HANDLE          SourceProcessId;
    HANDLE          TargetProcessId;
    HANDLE          SourceHandle;           /* Ob 回调 PreOperation 不可用，恒 NULL */
    HANDLE          TargetHandle;           /* Ob 回调 PreOperation 不可用，恒 NULL */
    ACCESS_MASK     GrantedAccess;
    HS_HANDLE_TYPE  HandleType;
    LARGE_INTEGER   Timestamp;
    HS_SUSPICION    SuspicionFlags;
} HS_DUPLICATION_RECORD, *PHS_DUPLICATION_RECORD;

//
// 句柄快照缓存（对齐 SS HT_PROCESS_HANDLES）
// 不接入：wkd 分层模型句柄快照由 Agent 按需触发（ScanManager 模式），内核无快照缓存需求。
//
typedef struct _HS_PROCESS_HANDLES {
    ULONG           Signature;
    volatile LONG   RefCount;
    HANDLE          ProcessId;
    PEPROCESS       ProcessObject;
    LIST_ENTRY      HandleList;
    EX_PUSH_LOCK    Lock;
    volatile LONG   HandleCount;

    /* 聚合结果 */
    HS_SUSPICION    AggregatedSuspicion;
    ULONG           SuspicionScore;

    /* 类型统计 */
    ULONG           ProcessHandleCount;
    ULONG           ThreadHandleCount;
    ULONG           FileHandleCount;
    ULONG           TokenHandleCount;
    ULONG           SectionHandleCount;
    ULONG           OtherHandleCount;
    ULONG           CrossProcessHandleCount;
    ULONG           HighPrivilegeHandleCount;
    ULONG           DuplicatedHandleCount;

    LARGE_INTEGER   SnapshotTime;

    /* hash 表 + 全局链表 */
    LIST_ENTRY      HashEntry;
    ULONG           HashBucket;
    BOOLEAN         InHashTable;
    LIST_ENTRY      GlobalEntry;
} HS_PROCESS_HANDLES, *PHS_PROCESS_HANDLES;

//
// hash 桶（对齐 SS HT_HASH_BUCKET）
//
typedef struct _HS_HASH_BUCKET {
    LIST_ENTRY      ProcessList;
    EX_PUSH_LOCK    Lock;
    volatile LONG   Count;
} HS_HASH_BUCKET, *PHS_HASH_BUCKET;

//
// 统计（对齐 SS HT_STATISTICS）
//
typedef struct _HS_STATISTICS {
    volatile LONG64 HandlesTracked;
    volatile LONG64 SuspiciousHandles;
    volatile LONG64 CrossProcessHandles;
    volatile LONG64 TotalEnumerations;
    volatile LONG64 DuplicationsRecorded;
    volatile LONG64 SensitiveAccessDetected;
    volatile LONG64 HighPrivilegeHandles;
    volatile LONG64 TokenHandlesTracked;
    volatile LONG64 InjectionHandlesDetected;
    LARGE_INTEGER   StartTime;
} HS_STATISTICS, *PHS_STATISTICS;

//
// 主 tracker（对齐 SS HT_TRACKER）
// 裁剪：SS 的 SensitiveProcesses[32] 哈希名单由 wkd HspIsSensitiveProcessName
// 运行时数组遍历替代（重功能实现），不搬；timer 由 SS TimerManager 改用
// worker 线程周期性等待（通用 KEVENT/线程机制，见 HsInitialize 死代码实现）。
//
typedef struct _HS_TRACKER {
    ULONG               Signature;
    volatile LONG       Initialized;

    /* rundown 保护（安全卸载同步） */
    EX_RUNDOWN_REF      RundownRef;

    /* 全局进程列表 */
    LIST_ENTRY          ProcessList;
    EX_PUSH_LOCK        ProcessListLock;
    volatile LONG       ProcessCount;

    /* hash 表 */
    PHS_HASH_BUCKET     HashBuckets;
    ULONG               HashBucketCount;

    /* lookaside */
    NPAGED_LOOKASIDE_LIST HandleEntryLookaside;
    NPAGED_LOOKASIDE_LIST ProcessHandlesLookaside;
    NPAGED_LOOKASIDE_LIST DuplicationLookaside;
    BOOLEAN             LookasideInitialized;

    /* 复制追踪 */
    LIST_ENTRY          DuplicationList;
    EX_PUSH_LOCK        DuplicationLock;
    volatile LONG       DuplicationCount;

    /* 配置 / 统计 */
    HS_CONFIG           Config;
    HS_STATISTICS       Stats;

    /* worker 线程 + 事件（周期清理 + 关闭同步） */
    PETHREAD            WorkerThreadObject;
    KEVENT              ShutdownEvent;
    KEVENT              WorkAvailableEvent;
    volatile LONG       ShutdownRequested;
} HS_TRACKER, *PHS_TRACKER;

//
// ======================================================================
// 死代码 API 声明（对齐 SS HtInitialize/HtShutdown/HtRecordDuplication/
// HtGetStatistics/HtGetHandlesInfo/HtGetHandleByIndex）
// ======================================================================
//

/*++
Routine Description:
    初始化句柄追踪器（缓存层）。死代码：缓存层未接入，服务于创建时全量快照，
    wkd 由 Agent 按需扫描替代。

IRQL: PASSIVE_LEVEL
--*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
HsInitialize(
    _Out_ PHS_TRACKER* OutTracker,
    _In_opt_ PHS_CONFIG Config
    );

/*++
Routine Description:
    安全关闭句柄追踪器。死代码（随 HsInitialize）。

IRQL: PASSIVE_LEVEL
--*/
_IRQL_requires_(PASSIVE_LEVEL)
VOID
HsShutdown(
    _Inout_ PHS_TRACKER* TrackerPtr
    );

/*++
Routine Description:
    记录一条句柄复制事件。死代码：事件源=Ob 回调 OB_OPERATION_HANDLE_DUPLICATE，
    wkd Ob 回调（CbObjectNotifyInitialize）未激活；跨进程关联应由 Agent 因果图承接。

IRQL: PASSIVE_LEVEL / APC_LEVEL
--*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
HsRecordDuplication(
    _In_ PHS_TRACKER Tracker,
    _In_ HANDLE SourceProcess,
    _In_ HANDLE TargetProcess,
    _In_ HANDLE SourceHandle,
    _In_ HANDLE TargetHandle,
    _In_ ACCESS_MASK GrantedAccess,
    _In_ HS_HANDLE_TYPE HandleType
    );

/*++
Routine Description:
    获取追踪器统计。死代码：无消费方（对齐 SS HtGetStatistics 在 SS 内亦无调用方）。

IRQL: DISPATCH_LEVEL 及以下
--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
HsGetStatistics(
    _In_ PHS_TRACKER Tracker,
    _Out_ PHS_STATISTICS Stats
    );

/*++
Routine Description:
    读取快照摘要。死代码：依赖缓存层（HS_PROCESS_HANDLES），未接入。

IRQL: PASSIVE_LEVEL / APC_LEVEL
--*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
HsGetHandlesInfo(
    _In_ PHS_PROCESS_HANDLES Handles,
    _Out_ PHS_PROCESS_HANDLES_INFO Info
    );

/*++
Routine Description:
    按索引读取单条句柄。死代码：依赖缓存层，未接入。

IRQL: PASSIVE_LEVEL / APC_LEVEL
--*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
HsGetHandleByIndex(
    _In_ PHS_PROCESS_HANDLES Handles,
    _In_ ULONG Index,
    _Out_ PHS_HANDLE_INFO Info
    );

/*++
Routine Description:
    新进程句柄快照分析（对齐 SS PnpAnalyzeProcess 的 HandleTracker 段，
    ProcessNotify.c:3398-3465：HtSnapshotHandles+HtAnalyzeHandles →
    PN_BEHAVIOR_HANDLE_* 映射 → SuspicionScore 累加）。实时枚举新进程
    句柄→聚合分析→映射句柄行为标志→输出聚合摘要。

    死代码：进程创建热路径全系统枚举成本高，wkd 以 Ob 回调实时检测
    （IocDetectHandle，操作时）为主路径；接入需门控开关（如
    g_IoaCmdLineAnalyzerEnabled 模式），默认关。

IRQL: PASSIVE_LEVEL

Arguments:
    Process       — 新创建进程（读取 ProcessId）
    BehaviorFlags — [in/out] WKD_SECURITY_CONTEXT.BehaviorFlags 地址，命中注入/凭证/令牌位时置位
    Info          — [out] 聚合摘要（含 AggregatedSuspicion/SuspicionScore）

Return Value:
    STATUS_SUCCESS — 分析完成
--*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
HspAnalyzeNewProcessHandles(
    _In_ struct _WKD_PROCESS* Process,
    _Inout_ PULONG BehaviorFlags,
    _Out_ PHS_PROCESS_HANDLES_INFO Info
    );

/*++
Routine Description:
    快照并缓存指定进程的全部句柄（对齐 SS HtSnapshotHandles L1084-1152）。
    组合 API：分配 → 枚举 → 缓存（hash 表 + 全局列表）。返回的快照须
    HspReleaseHandles 释放。HspEnumerateProcessHandles 内部已更新统计。
    死代码：缓存层未接入（wkd 创建时快照走 HspAnalyzeNewProcessHandles 实时枚举）。

IRQL: PASSIVE_LEVEL
--*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
HspSnapshotHandles(
    _In_ PHS_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_ PHS_PROCESS_HANDLES* OutHandles
    );

/*++
Routine Description:
    对快照做聚合分析（对齐 SS HtAnalyzeHandles L1367-1438）。
    遍历聚合 SuspicionFlags + ManyHandles 阈值 + 更新缓存聚合字段（独占锁发布一致对）。
    死代码：缓存层未接入。

IRQL: PASSIVE_LEVEL / APC_LEVEL
--*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
HspAnalyzeHandles(
    _In_ PHS_TRACKER Tracker,
    _In_ PHS_PROCESS_HANDLES Handles,
    _Out_ HS_SUSPICION* Flags,
    _Out_opt_ PULONG Score
    );

/*++
Routine Description:
    释放快照（对齐 SS HtReleaseHandles L1551-1571）：移除缓存 + 引用递减。
    死代码：缓存层未接入。

IRQL: PASSIVE_LEVEL / APC_LEVEL
--*/
_IRQL_requires_max_(APC_LEVEL)
VOID
HspReleaseHandles(
    _In_ PHS_TRACKER Tracker,
    _In_ PHS_PROCESS_HANDLES Handles
    );

/*++
    句柄聚合怀疑 → 告警位图（对齐 SS PnpAnalyzeProcess 的 BeEngineSubmitEvent
    三类告警，ProcessNotify.c:3427-3449：CredentialDumping/RemoteThreadCreate/LSASSAccess）
    权重：CredentialAccess=40 / InjectionCapable=25 / TokenSteal=30（对齐 SS 权重，
    cap 100，即 SS 的 SuspicionScore 累加语义）。
*/
#define HS_ALERT_CREDENTIAL_DUMP   0x00000001   /* 对齐 SS BehaviorEvent_CredentialDumping */
#define HS_ALERT_INJECTION         0x00000002   /* 对齐 SS BehaviorEvent_RemoteThreadCreate */
#define HS_ALERT_TOKEN_STEAL       0x00000004   /* 对齐 SS BehaviorEvent_LSASSAccess */

/*++
Routine Description:
    句柄聚合怀疑 → 告警位图 + 建议累计分（对齐 SS PnpAnalyzeProcess 的
    BeEngineSubmitEvent + SuspicionScore += HtScore 累加，ProcessNotify.c:3427-3449）。
    死代码：接入点在进程创建路径（AeOrchestratorDispatch ProcessCreated 分支，
    门控默认关）；wkd 以 Ob 回调实时检测为主路径。返回告警位图，AccumulatedScore
    输出建议写入进程评分的累计分。

IRQL: PASSIVE_LEVEL
--*/
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
HspSubmitHandleAlerts(
    _In_ HS_SUSPICION AggregatedSuspicion,
    _Out_opt_ PULONG AccumulatedScore
    );
