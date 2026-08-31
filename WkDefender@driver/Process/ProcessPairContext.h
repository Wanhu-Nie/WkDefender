#pragma once

#include <ntifs.h>
#include "../Process/ProcessMonitor.h"      /* PAE_IOA_CONTEXT 前向声明 */
#include "../Common/DynamicArray.h"         /* WKD_DYNAMIC_ARRAY */
#include "../Common/HashMap.h"              /* WKD_HASH_MAP */
#include "../Common//Utils.h"
#include "../Notification/NotificationManager.h"  /* WKD_MESSAGE_TYPE, WKD_MESSAGE_SOURCE */

/* WKD_ASSEMBLY_TYPE / WKD_ASSEMBLY_SOURCE — 从 IoaEngine.h 迁移至此
 * 避免 ProcessPairContext.h ↔ IoaEngine.h 循环包含。 */
typedef WKD_MESSAGE_TYPE WKD_ASSEMBLY_TYPE;
typedef WKD_MESSAGE_SOURCE WKD_ASSEMBLY_SOURCE;

/**************************************************/
/*         进程对同步位图表                          */
/*                                                  */
/*  控制哪些 <源进程, 目标进程> 上的哪些操作需同步。   */
/*  粒度: 进程对 — 不影响进程对自身的操作。          */
/*  公共位图: 进程对不存在时的默认策略。              */
/*  动态位图: 通过 SyncBitmap（进程对内嵌）控制。     */
/*                                                  */
/*  查询流程:                                        */
/*    查 PairTable[(sPid,tPid)]                     */
/*    → 未命中: 用 PublicBitmap[opType] 判断         */
/*    → 命中:   用 pair->SyncBitmap[opType] 判断     */
/**************************************************/

#define WKD_OP_MAX              64

/**************************************************/
/*                   操作类型枚举                    */
/**************************************************/

typedef enum _WKD_OP_TYPE {
    WkdOp_OpenProcess = 0,
    WkdOp_AllocateVirtualMemory = 1,
    WkdOp_WriteVirtualMemory = 2,
    WkdOp_ReadVirtualMemory = 3,
    WkdOp_ProtectVirtualMemory = 4,
    WkdOp_CreateRemoteThread = 5,
    WkdOp_MapViewOfSection = 6,
    WkdOp_QueueApcThread = 7,
    WkdOp_SetContextThread = 8,
    WkdOp_ResumeThread = 9,
    WkdOp_CreateProcess = 10,
    WkdOp_CreateThread = 11,
    WkdOp_ObjectAccess = 12,
    WkdOp_RegistryEvent = 13,
    WkdOp_SuspendThread = 14,
    // ... 保留扩展到 64
} WKD_OP_TYPE;

//
// Pair 哈希表 Key — <源进程 PID, 目标进程 PID>
//
typedef struct _AE_PROCESS_PAIR_KEY {
    HANDLE SourceProcessId;
    HANDLE TargetProcessId;
} AE_PROCESS_PAIR_KEY, * PAE_PROCESS_PAIR_KEY;

//
// 上限配置
//
#define IOA_MAX_BEHAVIORS_PER_PAIR          256
#define IOA_MAX_RECORDS_PER_BEHAVIOR        1024
#define WKD_BEHAVIOR_INIT_CAPACITY     4

/**************************************************/
/*                   进程对定义                     */
/*                                                  */
/*  承担职责:                                       */
/*    1) 同步位图裁决 —— 通过 HashLink 挂入         */
/*       WkdProcessPairMap，按 AE_PROCESS_PAIR_KEY <sPid,tPid> 索引        */
/*    2) 分析 + 评分上下文挂载（Ioc/Ioa/Ts）         */
/**************************************************/

//
// 行为上下文（2026-08 迁移自 ShadowStrike BehaviorEngine BE_PROC_CONTEXT）
// 内嵌纯标量（无链表/无分配），RtlZeroMemory 归零 + 创建时显式初始化乘数。
// 写入一律 Interlocked 或在 Pair->Lock 下（ScoreMultiplierPercent/StageFlags/
// CumulativeThreatScore 在结算线程持 Pair 引用时读）。
//
typedef struct _AE_PAIR_BEHAVIOR_CONTEXT {
    volatile ULONG SuspiciousEventCount;    /* 惯犯计数 — 对齐 SS BepUpdateProcessContext 可疑事件数 */
    ULONG BehaviorFlags;                    /* 行为标志位（WKD_BEHAVIOR_*，合并自源进程 WKD_SECURITY_CONTEXT） */
    volatile ULONG ScoreMultiplierPercent;  /* 评分乘数百分比 — 默认 100（SS BepCalculateEventThreatScore 连乘缓存，结算侧应用） */
    ULONG StageFlags;                       /* 链种子：攻击阶段位图（SS BE_ATTACK_CHAIN.StageFlags，预留） */
    ULONG CumulativeThreatScore;            /* 链种子：累积威胁分（SS BE_ATTACK_CHAIN.CumulativeThreatScore，结算时累加） */
} AE_PAIR_BEHAVIOR_CONTEXT, * PAE_PAIR_BEHAVIOR_CONTEXT;

typedef struct _AE_PROCESS_PAIR {
    LONG            RefCount;
    EX_PUSH_LOCK    Lock;

    HANDLE          SourceProcessId;    // 源进程 PID（哈希表键值）
    HANDLE          TargetProcessId;    // 目标进程 PID（哈希表键值）

    LARGE_INTEGER   CreateTime;         // 进程对创建时间
    volatile LARGE_INTEGER   LastAccessTime;     // 最后访问时间（行为记录路径 IoaRecordBehavior 原子更新）

    ULONG64         SyncBitmap;         // 同步位图：控制哪些操作类型需要同步阻塞

    /* ---- 行为上下文（进程对级行为状态，迁移自 SS BehaviorEngine） ---- */
    AE_PAIR_BEHAVIOR_CONTEXT BehaviorContext;

    /* ---- 分析 + 评分上下文（2026-07 迁移自 WKD_PROCESS） ---- */
    PAE_IOC_CONTEXT IocContext;         /* IOC 证据链（按 Indicator 去重）   */
    PAE_IOA_CONTEXT IoaContext;         /* IOA 摘要链 + 行为分析            */
    PTS_CONTEXT     TsContext;          /* 评分上下文（双链 + 得分缓存）     */
} AE_PROCESS_PAIR, * PAE_PROCESS_PAIR;

//
// 行为节点 — 同一 (EventType) 的记录存储在动态数组中。
// ValidBitmap 标记有效槽位，替代循环缓冲的 Head/Tail 包裹。
//

#define WKD_BEHAVIOR_BITMAP_SIZE    IOA_MAX_RECORDS_PER_BEHAVIOR   // 1024 位
#define WKD_BEHAVIOR_BITMAP_WORDS   ((WKD_BEHAVIOR_BITMAP_SIZE + 63) / 64)  // 16 × ULONG64

typedef struct _WKD_BEHAVIOR {
    LONG RefCount;                         // 引用计数
    EX_PUSH_LOCK Lock;                      // 节点级推锁

    LIST_ENTRY Links;                       // 挂入 AE_IOA_CONTEXT::BehaviorHead
    WKD_ASSEMBLY_TYPE Type;                 // 行为类型
    LARGE_INTEGER CreateTime;               // 节点首次追加记录的时刻

    /* 位图标记数组 */
    WKD_DYNAMIC_ARRAY Records;              // 底层存储，元素大小为记录结构体
    ULONG64 ValidBitmap[WKD_BEHAVIOR_BITMAP_WORDS];  // 有效槽位位图

    /* 缓存式威胁评估 */
    LONG AccumulatedThreat;       // 累积威胁贡献值

    /* 快速路径 */
    LARGE_INTEGER EarliestExpiryTime;       // 最早有效记录的过期时间点
} WKD_BEHAVIOR, * PWKD_BEHAVIOR;

/**************************************************/
/*                   进程对 hash 表                  */
/*  已迁移至 WKD_HASH_MAP（HashMap.c）管理。         */
/*  公共位图分离为独立变量。                         */
/**************************************************/

extern ULONG64 g_PairPublicBitmap;      // 进程对不存在时的默认同步策略

/**************************************************/
/*                   函数声明                       */
/**************************************************/

/*
 * WkdPairTableInitialize
 *   初始化进程对 hash 表（已迁移至 WKD_HASH_MAP）。
 *   g_PairPublicBitmap 初始化: 执行权转移类 + 进程/线程创建 位默认置 1。
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdPairTableInitialize(
    VOID
);

/*
 * AeLookupProcessPair
 *   在 WkdProcessPairMap 中查找 <SourceProcessId, TargetProcessId>。
 *   返回 pair 指针（Reference 已 +1），调用者需配对 PsDereferenceWkdProcessPair。
 *   未找到返回 NULL。
 */
_IRQL_requires_max_(APC_LEVEL)
PAE_PROCESS_PAIR
AeLookupProcessPair(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId
);

/*
 * PsPairNeedsSync
 *   查询 <SourceProcessId, TargetProcessId> 进程对上指定操作是否需要同步阻塞。
 *   WkdProcessPairMap 命中 → 查 pair->SyncBitmap[OpType]
 *   未命中          → 查 g_PairPublicBitmap[OpType]
 */
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
PsPairNeedsSync(
    _In_ HANDLE      SourceProcessId,
    _In_ HANDLE      TargetProcessId,
    _In_ WKD_OP_TYPE OpType
);

/*
 * PsUpdatePairBitmap
 *   Agent 下发: 更新指定进程对的 SyncBitmap。
 *   进程对必须已存在于 WkdProcessPairMap（由 IOA 引擎保证），
 *   本函数只更新位图，不创建/删除条目。
 *   NewBitmap == 0 → 位图清零（不删除条目）
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PsUpdatePairBitmap(
    _In_ HANDLE  SourceProcessId,
    _In_ HANDLE  TargetProcessId,
    _In_ ULONG64 NewBitmap
);

/*
 * AeFindOrCreateProcessPair
 *   在 WkdProcessPairMap 中查找 <sid,tid> 进程对，未命中时创建新条目。
 *   使用 HashMap 桶级锁管理并发（fast path: 共享锁查找，
 *   slow path: 独占锁 double-check 插入）。
 *   创建时全部分配 IocContext/IoaContext/TsContext 三个上下文
 *   （2026-07 迁移：进程对成为分析+评分核心挂载单元，无进程侧挂链）。
 *
 *   返回值:
 *     STATUS_SUCCESS              — Pair 输出有效指针
 *     STATUS_QUOTA_EXCEEDED       — 超过全局 AE_MAX_PROCESS_PAIRS 上限
 *     STATUS_INSUFFICIENT_RESOURCES — 内存分配失败
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
AeFindOrCreateProcessPair(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _Out_ PAE_PROCESS_PAIR* Pair
    );

_IRQL_requires_(PASSIVE_LEVEL)
LONG
PsReferenceWkdProcessPair(
    _Inout_ PAE_PROCESS_PAIR Pair
    );

_IRQL_requires_(PASSIVE_LEVEL)
LONG
PsDereferenceWkdProcessPair(
    _Inout_ PAE_PROCESS_PAIR Pair
    );

LONG
PsReferenceWkdBehavior(
    _Inout_ PWKD_BEHAVIOR Behavior
    );

ULONG
PsDereferenceWkdBehavior(
    _Inout_ PWKD_BEHAVIOR Behavior
    );

/**************************************************/
/*               全局实例                           */
/**************************************************/

extern WKD_HASH_MAP WkdProcessPairMap;          // 进程对哈希表（HashMap.c）
extern ULONG64 g_PairPublicBitmap;      // 公共位图: 进程对不存在时的默认策略
extern volatile LONG WkdPairCount;      // 全局 pair 数量（上限 AE_MAX_PROCESS_PAIRS，维护线程摘除后递减）
