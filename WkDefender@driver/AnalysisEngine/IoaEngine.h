#pragma once

#include <ntifs.h>
#include "../ThreatScoring/ThreatScoring.h"   /* TS_INDICATOR_TYPE, AE_THREAT_SEVERITY */
#include "../Process/ProcessPairContext.h"
#include "../Process/ProcessMonitor.h"
#include "../Notification/NotificationManager.h"
#include "../Common/DynamicArray.h"
#include "../Common/HashMap.h"

//
// 行为节点哈希表 Key — <进程对, 行为类型>
//
typedef struct _WKD_BEHAVIOR_KEY {
    HANDLE SourceProcessId;
    HANDLE TargetProcessId;
    WKD_ASSEMBLY_TYPE Type;
    ULONG Reserved;
} WKD_BEHAVIOR_KEY;

//
// 进程对管理（IoaEngine 内部函数，AnalysisEngine 维护线程调用）
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
IoaRefreshProcessPair(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ LARGE_INTEGER CurrentTime
    );

//
// 分配进程对的 IoaContext — 由 AeFindOrCreateProcessPair 创建时调用。
// 分配 + 初始化链头 + 锁。失败返回 NULL。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IoaAllocateProcessPairContext(
    _Inout_ PAE_PROCESS_PAIR Pair
    );

//
// 销毁进程对的 IoaContext — 由 PsDereferenceWkdProcessPair refcount==0 分支调用。
// 遍历 IoaChain 释放全部摘要节点 + 释放 context + 置 NULL。
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IoaFreeProcessPairContext(
    _Inout_ PAE_PROCESS_PAIR Pair
    );
    
/**************************************************/
/*          EWMA 风险评分（已迁移）                  */
/*                                                   */
/*  EWMA 平滑已移入威胁评分系统 TsContext            */
/*  （IoaScore 缓存，ThreatScoring.c）。             */
/*  IOA 侧仅负责行为记录 + 提交评分指示记录。        */
/**************************************************/
#define WKD_BLOCK_SCORE         60      /* 综合评分 (MAX聚合, cap100) 越过此线 → 同步阻断 */
#define WKD_ESCALATE_SCORE      50      /* 综合评分 (MAX聚合, cap100) 越过此线 → 异步提升上报 */

//
// 阻断原因 (传给 IoaBlockAndWait)
//
typedef enum _WKD_BLOCK_REASON {
    WkdBlockReason_None             = 0,
    WkdBlockReason_HighScoreRapid   = 1,    /* 高评分 + 高单步增量 */
    WkdBlockReason_IocHit           = 2,    /* IOC 已知恶意命中 (预留) */
    WkdBlockReason_ProcessOverflow  = 3,    /* 进程对溢出 (预留) */
} WKD_BLOCK_REASON, *PWKD_BLOCK_REASON;

/**************************************************/
/*               IOA 事件参数条目                   */
/**************************************************/

//
// 通用条目头部 — 所有 IOA_BEHAVIOR_RECORD_ENTRY_* 共用首部布局，
// 通过 Header.BehaviorType 区分具体类型。
//
typedef struct _IOA_BEHAVIOR_RECORD_ENTRY_HEADER {
    LARGE_INTEGER TimeStamp;
    WKD_ASSEMBLY_TYPE BehaviorType;     // 行为类型
    BOOLEAN Valid;                      // TRUE=有效, FALSE=已过期可覆写
    AE_THREAT_SEVERITY Severity;
    ULONG Reserved;                     // 对齐到 24 字节
} IOA_BEHAVIOR_RECORD_ENTRY_HEADER, *PIOA_BEHAVIOR_RECORD_ENTRY_HEADER;

//
// 对象访问参数条目（ProcessObjectAccess / ThreadObjectAccess）
//
typedef struct _IOA_BEHAVIOR_RECORD_ENTRY_OBJECT_ACCESS {
    IOA_BEHAVIOR_RECORD_ENTRY_HEADER Header;
    ACCESS_MASK DesiredAccess;
    ACCESS_MASK SensitiveMask;
} IOA_BEHAVIOR_RECORD_ENTRY_OBJECT_ACCESS, *PIOA_BEHAVIOR_RECORD_ENTRY_OBJECT_ACCESS;

//
// NtOpenProcess 参数条目
//
typedef struct _IOA_BEHAVIOR_RECORD_ENTRY_OPEN_PROCESS {
    IOA_BEHAVIOR_RECORD_ENTRY_HEADER Header;
    _Out_ PHANDLE ProcessHandle;
    _In_ ACCESS_MASK DesiredAccess;
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes;
    _In_opt_ PCLIENT_ID ClientId;
} IOA_BEHAVIOR_RECORD_ENTRY_OPEN_PROCESS, *PIOA_BEHAVIOR_RECORD_ENTRY_OPEN_PROCESS;

//
// NtAllocateVirtualMemory 参数条目
// 注意：BaseAddress / RegionSize 在 Exit 路径中已被替换为实际输出值，
//       不再是 In/Out 指针，而是实际分配地址和大小。
//
typedef struct _IOA_BEHAVIOR_RECORD_ENTRY_ALLOCATE_MEMORY {
    IOA_BEHAVIOR_RECORD_ENTRY_HEADER Header;
    HANDLE ProcessHandle;
    PVOID BaseAddress;                  // 实际分配基址（Exit 后从 *BaseAddress 读取）
    ULONG_PTR ZeroBits;
    SIZE_T RegionSize;                  // 实际分配大小（Exit 后从 *RegionSize 读取）
    ULONG AllocationType;
    ULONG PageProtection;
} IOA_BEHAVIOR_RECORD_ENTRY_ALLOCATE_MEMORY, *PIOA_BEHAVIOR_RECORD_ENTRY_ALLOCATE_MEMORY;

//
// NtProtectVirtualMemory 参数条目
// 注意：OldProtection 在 Exit 路径中已被替换为实际输出值，
//       不再是输出指针，而是实际旧保护值。
//
typedef struct _IOA_BEHAVIOR_RECORD_ENTRY_PROTECT_MEMORY {
    IOA_BEHAVIOR_RECORD_ENTRY_HEADER Header;
    HANDLE ProcessHandle;
    PVOID* BaseAddress;
    PSIZE_T RegionSize;
    ULONG NewProtection;
    ULONG OldProtection;                // 实际旧保护值（Exit 后从 *OldProtection 读取）
} IOA_BEHAVIOR_RECORD_ENTRY_PROTECT_MEMORY, *PIOA_BEHAVIOR_RECORD_ENTRY_PROTECT_MEMORY;

//
// NtWriteVirtualMemory 参数条目
// 注意：NumberOfBytesWritten 在 Exit 路径中已被替换为实际输出值。
//
typedef struct _IOA_BEHAVIOR_RECORD_ENTRY_WRITE_MEMORY {
    IOA_BEHAVIOR_RECORD_ENTRY_HEADER Header;
    HANDLE ProcessHandle;
    PVOID BaseAddress;
    PVOID Buffer;
    SIZE_T NumberOfBytesToWrite;
    SIZE_T NumberOfBytesWritten;            // 实际写入字节数（Exit 后从 *NumberOfBytesWritten 读取）
} IOA_BEHAVIOR_RECORD_ENTRY_WRITE_MEMORY, *PIOA_BEHAVIOR_RECORD_ENTRY_WRITE_MEMORY;

//
// NtCreateRemoteThread / NtCreateThreadEx 参数条目
//
typedef struct _IOA_BEHAVIOR_RECORD_ENTRY_CREATE_THREAD {
    IOA_BEHAVIOR_RECORD_ENTRY_HEADER Header;
    PVOID StartAddress;
    PVOID Parameter;
} IOA_BEHAVIOR_RECORD_ENTRY_CREATE_THREAD, *PIOA_BEHAVIOR_RECORD_ENTRY_CREATE_THREAD;

//
// NtReadVirtualMemory 参数条目
// 注意：NumberOfBytesRead 在 Exit 路径中已被替换为实际输出值。
//
typedef struct _IOA_BEHAVIOR_RECORD_ENTRY_READ_MEMORY {
    IOA_BEHAVIOR_RECORD_ENTRY_HEADER Header;
    HANDLE ProcessHandle;
    PVOID BaseAddress;
    PVOID Buffer;
    SIZE_T NumberOfBytesToRead;
    SIZE_T NumberOfBytesRead;               // 实际读取字节数（Exit 后从 *NumberOfBytesRead 读取）
} IOA_BEHAVIOR_RECORD_ENTRY_READ_MEMORY, *PIOA_BEHAVIOR_RECORD_ENTRY_READ_MEMORY;

//
// NtMapViewOfSection 参数条目
//
typedef struct _IOA_BEHAVIOR_RECORD_ENTRY_MAP_SECTION {
    IOA_BEHAVIOR_RECORD_ENTRY_HEADER Header;
    PVOID BaseAddress;
    SIZE_T ViewSize;
} IOA_BEHAVIOR_RECORD_ENTRY_MAP_SECTION, *PIOA_BEHAVIOR_RECORD_ENTRY_MAP_SECTION;

//
// NtQueueApcThread 参数条目
//
typedef struct _IOA_BEHAVIOR_RECORD_ENTRY_QUEUE_APC {
    IOA_BEHAVIOR_RECORD_ENTRY_HEADER Header;
    PVOID ApcRoutine;
} IOA_BEHAVIOR_RECORD_ENTRY_QUEUE_APC, *PIOA_BEHAVIOR_RECORD_ENTRY_QUEUE_APC;

//
// NtSetContextThread 参数条目
//
typedef struct _IOA_BEHAVIOR_RECORD_ENTRY_SET_CONTEXT {
    IOA_BEHAVIOR_RECORD_ENTRY_HEADER Header;
    ULONG ContextFlags;
} IOA_BEHAVIOR_RECORD_ENTRY_SET_CONTEXT, *PIOA_BEHAVIOR_RECORD_ENTRY_SET_CONTEXT;

//
// 统一线程事件条目 — 合并原 REMOTE_THREAD 和 THREAD_EVENT
// 用于线程创建/终止（本地和远程），通过 IsRemote 标志区分
//
typedef struct _IOA_BEHAVIOR_RECORD_ENTRY_THREAD {
    IOA_BEHAVIOR_RECORD_ENTRY_HEADER Header;
    HANDLE ThreadId;                    // 线程 ID (tTid)
    HANDLE CreatorProcessId;            // 创建者进程 ID (sPid)
    HANDLE CreatorThreadId;             // 创建者线程 ID (sTid)
    PVOID StartRoutine;                 // 线程入口地址
    PVOID Argument;                     // NtCreateThreadEx 的 Argument（未匹配=NULL）
    ULONG DesiredAccess;                // NtCreateThreadEx 的 DesiredAccess
    ULONG CreateFlags;                  // NtCreateThreadEx 的 CreateFlags
    LARGE_INTEGER CreateTime;           // 创建时间
    BOOLEAN Create;                     // TRUE=创建, FALSE=退出
    BOOLEAN IsRemote;                   // TRUE=远程线程创建（跨进程）
} IOA_BEHAVIOR_RECORD_ENTRY_THREAD, *PIOA_BEHAVIOR_RECORD_ENTRY_THREAD;

//
// 进程创建参数条目（WkdMessage_ProcessCreated）
// 父进程创建子进程这一行为的事实记录。
//
typedef struct _IOA_BEHAVIOR_RECORD_ENTRY_PROCESS_CREATE {
    IOA_BEHAVIOR_RECORD_ENTRY_HEADER Header;
    HANDLE ChildProcessId;              // 被创建的子进程 PID
    ULONG CreateFlags;                  // 创建标志（来自 CreateInfo）
} IOA_BEHAVIOR_RECORD_ENTRY_PROCESS_CREATE, *PIOA_BEHAVIOR_RECORD_ENTRY_PROCESS_CREATE;

/**************************************************/
/*           行为节点 + 进程对上下文                */
/**************************************************/

//
// 事件窗口配置
//
#define WKD_IOA_EVENT_WINDOW_MS             1000 * 60  // 1小时

//
// 计算 EarliestExpiryTime：从时间戳推算过期时间点。
// 参数 ts 为 LARGE_INTEGER，返回值可直接赋值给 EarliestExpiryTime。
// 比较：EarliestExpiryTime.QuadPart < now.QuadPart 表示已过期。
//
#define WKD_IOA_RECORD_EXPIRY(ts) \
    ((ts).QuadPart + (LONGLONG)WKD_IOA_EVENT_WINDOW_MS * 10000)

//
// IOA 摘要记录 — 行为摘要（证据，生命周期 = pair = IoaContext）。
// 与评分系统记录同构（不含 Source：本链恒为 IOA 来源）。
//
#define WKD_MAX_IOA_CHAIN_RECORDS   1024

typedef struct _AE_IOA_RECORD {
    LIST_ENTRY          Link;           // → IoaContext.IoaChain
    TS_INDICATOR_TYPE   Indicator;      // 评分指标类型（0x0Dxx IOA 段）
    AE_THREAT_SEVERITY Severity;       // 威胁程度 1-4
    LARGE_INTEGER       Timestamp;      // 提交时间
} AE_IOA_RECORD, *PAE_IOA_RECORD;

//
// IoaContext — 动态行为分析上下文（进程对维度）
// 行为链（2026-08 下沉自 pair 本体）+ 摘要记录链。
// 行为链仍由 Pair->Lock 保护；IoaContext->Lock 只保护 IoaChain。
//
typedef struct _AE_IOA_CONTEXT {
    /* ---- 行为链（下沉自 pair 本体） ---- */
    LIST_ENTRY      BehaviorHead;       // 行为节点链表（WKD_BEHAVIOR）
    volatile ULONG  ActiveBehaviors;    // 当前行为节点数
    volatile ULONG  TotalBehaviors;     // 累计行为节点数（只增不减）

    /* ---- 行为记录统计（迁移自 pair->TotalRecords/ActiveRecords） ---- */
    volatile ULONG  TotalRecords;       // 累计行为记录数（只增不减）
    volatile ULONG  ActiveRecords;      // 当前IOA所有有效行为记录数

    /* ---- 摘要记录链 ---- */
    LIST_ENTRY      IoaChain;           // 摘要记录链（FIFO 上限 WKD_MAX_IOA_CHAIN_RECORDS）
    volatile ULONG  IoaChainCount;      // 当前摘要记录数（FIFO 判断）
    LARGE_INTEGER   LastRecordTime;
} AE_IOA_CONTEXT, *PAE_IOA_CONTEXT;

/**************************************************/
/*                   函数声明                      */
/**************************************************/

//
// 初始化与清理
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IoaInitialize(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IoaCleanup(
    VOID
    );


// ============================================================================
// MITRE ATT&CK 技术权重表（2026-08 激活，迁移自 SS g_EventMitreMap）
//
// 每行对应一个槽位, 在语义权重基础上叠加 MITRE 技术
// 的基础分。使评测分在 L1 阶段就区分高危技术（注入 T1055 = 65）和低危技术
// （系统发现 T1057 = 15）, 无需等到 L2 异步分析。
//
// 实现在 IoaEngine.c 中（IoapGetMitreBaseScore / IoapEventTypeToSlot），
// 提交侧 severity band 上调：基础分 ≥65→+2、≥40→+1、<40→+0（clamp 1-4）。
// ============================================================================


//
// IoaAnalysisBehavior — 行为记录统一入口（进程对维度）
// 调用方须持有 pair pin（AeOrchestratorDispatch Phase 0 获得）。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IoaAnalysisBehavior(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ WKD_ASSEMBLY_TYPE Type,
    _In_opt_ PVOID Context,
    _Out_opt_ PAE_THREAT_SEVERITY Severity
    );

/**************************************************/
/*               全局实例                           */
/**************************************************/

extern WKD_HASH_MAP WkdBehaviorMap;