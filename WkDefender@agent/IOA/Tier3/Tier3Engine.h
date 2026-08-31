/**************************************************/
/*  WkDefender IOA — Tier3 深度取证引擎              */
/*                                                  */
/*  重构 (2026-07):                                  */
/*    1. 同步架构 — T2直接调用，无异步队列            */
/*    2. 攻击链主动合并 (进程重叠+时序+战术连贯性)     */
/*    3. 因果倒推 + 步骤间动态窗口 (替代固定±5s)       */
/*    4. MITRE 螺旋推进 (FSM粗分类→参数细化→         */
/*       图拓扑补全→收敛循环)                         */
/*    5. 战术标注附着在 PairContext (T1/T2/T3共享)    */
/*    6. 同步阻塞快速路径 (T3HandleBlockingQuery)      */
/*       — 默认 DENY，低威胁才 ALLOW                  */
/*    7. 概率化输出 (基于内存证据, 置信度上限98%)      */
/*                                                  */
/*  触发源:                                          */
/*    - T2 FSM 全接受/部分接受 → T3DeepForensics 同步│
/*    - Driver 同步阻塞查询 → T3HandleBlockingQuery  │
/**************************************************/

#pragma once

#include "../IoaTypes.h"
#include "../../Process/ProcessTree.h"
#include "../IoaCarsalGraph.h"
#include "IoaGraphWalker.h"
#include "IoaGraphMatcher.h"
#include "../../Storage/StorageEngine.h"
#include "../../DefendTypes.h"

/**************************************************/
/*           前向声明                               */
/**************************************************/

typedef struct _IOA_TIER3_ENGINE IOA_TIER3_ENGINE, *PIOA_TIER3_ENGINE;
typedef struct _TIRE3_ATTACK_CHAIN TIRE3_ATTACK_CHAIN, *PTIRE3_ATTACK_CHAIN;

/**************************************************/
/*           常量                                   */
/**************************************************/

#define TIRE3_MAX_EVIDENCE_ITEMS  32
#define T3_CHAIN_MAX_PROCESSES    16
#define T3_CHAIN_MAX_STEPS        32
#define T3_CHAIN_MAX_BRANCHES     4
#define TIRE3_ATTACK_CHAIN_POOL_MAX         64
#define T3_CHAIN_TTL_MS           1800000     /* 30 分钟无活动淘汰 */
#define T3_MAX_GRAPH_WALK_ITERATIONS 3        /* MITRE 螺旋最大迭代次数 */

/**************************************************/
/*           事件参数载荷 (按边类型)                  */
/**************************************************/

typedef union _T3_EVENT_PARAMS {
    struct { ACCESS_MASK DesiredAccess; ULONG TargetIntegrityLevel; } ProcessOpen;
    struct { ULONG64 BaseAddress; ULONG64 RegionSize; ULONG Protect; } MemoryAlloc;
    struct { ULONG64 BaseAddress; ULONG64 NumberOfBytesWritten; UCHAR BufferHead[64]; BOOLEAN HasMZ; BOOLEAN HasDllPath; } MemoryWrite;
    struct { ULONG64 BaseAddress; ULONG64 RegionSize; ULONG NewProtect; ULONG OldProtect; } MemoryProtect;
    struct { ULONG64 StartRoutine; ULONG64 Parameter; ULONG CreationFlags; ULONG SyscallCreateFlags; ULONG DesiredAccess; BOOLEAN IsLoadLibrary; BOOLEAN IsApc; } ThreadCreate;
    struct { WCHAR ImagePath[256]; WCHAR CommandLine[1024]; ULONG ParentProcessId; ULONG CreationFlags; } ProcessCreate;
    struct { ULONG64 DestIP; USHORT DestPort; BOOLEAN IsKnownC2; } NetworkConnect;
} T3_EVENT_PARAMS;

/**************************************************/
/*           候选信息结构 (ScoreCand 输入/输出载体)    */
/**************************************************/

typedef struct _T3_CANDIDATE_INFO {
    GUID                EdgeId;
    GUID                SourceNodeId;          /* 源进程节点 GUID */
    GUID                TargetNodeId;          /* 目标进程节点 GUID (用于内容深化) */
    IOA_GRAPH_EDGE_TYPE EdgeType;
    LARGE_INTEGER       Timestamp;

    /* 提取后的参数 (由 ScoreCand 内部填充) */
    T3_EVENT_PARAMS     Params;

    /* 深化后的内容标记 */
    UINT8               ContentConfidence;      /* 0=未深化, 100=深化成功 */
    BOOLEAN             HasMZ;
    BOOLEAN             HasDllPath;
    UCHAR               BufferHead[64];
} T3_CANDIDATE_INFO, *PT3_CANDIDATE_INFO;

/**************************************************/
/*           Tier3 证据项                            */
/**************************************************/

typedef struct _TIRE3_EVIDENCE_ITEM {
    BOOLEAN             IsExtraEdge;
    UINT8               ContentConfidence;     /* 0=未深化, 100=内容深化成功 */
    GUID                EdgeId;
    IOA_GRAPH_EDGE_TYPE EdgeType;
    LARGE_INTEGER       Timestamp;
    WKD_EVENT_TYPE      EventType;
    ULONG               EventClass;
    ULONG               BehaviorFlags;
    T3_EVENT_PARAMS     Params;
    PWCHAR              Description;
} TIRE3_EVIDENCE_ITEM, *PTIRE3_EVIDENCE_ITEM;

/**************************************************/
/*           因果倒推 — 前置条件                     */
/**************************************************/

typedef struct _TIRE3_CAUSAL_NEEDS {
    ULONG64               RequiredWriteAddr;
    ULONG64               RequiredAllocMin;
    ULONG64               RequiredAllocMax;
    ULONG64               RequiredAccessMask;
    ULONG64               RequiredProtectAddr;
    ULONG                 RequiredNewProtectBits;
    BOOLEAN               ExactMatch;           /* TRUE=精确匹配, FALSE=降级模糊匹配 */
    UINT8                 ConfidencePenalty;    /* 模糊匹配扣分 [0,100] */
    BOOLEAN               HasMissingEdge;
    IOA_GRAPH_EDGE_TYPE   MissingEdgeType;
} TIRE3_CAUSAL_NEEDS, *PTIRE3_CAUSAL_NEEDS;

/**************************************************/
/*           心愿清单 (Wishlist) — 替代单一 Needs    */
/*                                                  */
/*  每个分析器步骤产生独立条目，不做去重/合并。       */
/*  匹配时遍历所有 Active 条目，部分满足隐式支持。     */
/*  条目通过 FromStepIndex 可追溯来源步骤。          */
/**************************************************/

typedef struct _TIRE3_WISH_ENTRY {
    BOOLEAN             Active;                 /* TRUE=待满足, FALSE=已满足 */
    UINT8               FromStepIndex;          /* 产生此需求的步骤索引 (调试用) */
    ULONG               ConfidencePenalty;      /* 匹配质量衰减, 默认 0 */

    /* 类别 — 由布尔位域区分, 一条可同时含多种需求 */
    BOOLEAN             NeedAccessMask;
    ULONG               RequiredAccessMask;

    BOOLEAN             NeedWriteAt;
    ULONG64             RequiredWriteAddr;      /* 需要在此地址写入 */
    ULONG               RequiredWriteSize;

    BOOLEAN             NeedAllocCover;
    ULONG64             RequiredAllocMin;
    ULONG64             RequiredAllocMax;

    BOOLEAN             NeedExeMemory;

    BOOLEAN             NeedDllPath;
    BOOLEAN             NeedPeImage;
} TIRE3_WISH_ENTRY, *PTIRE3_WISH_ENTRY;

#define TIRE3_WISHLIST_MAX  48          /* FSM_STATE_MAX(12) × 4条/步 */

typedef struct _TIRE3_NEEDS_WISHLIST {
    TIRE3_WISH_ENTRY    Entries[TIRE3_WISHLIST_MAX];
    ULONG               Count;
    ULONG               CurrentStep;    /* 当前步骤索引 (由倒推循环设置) */
} TIRE3_NEEDS_WISHLIST, *PTIRE3_NEEDS_WISHLIST;

/**************************************************/
/*           图展开提示                             */
/**************************************************/

typedef struct _T3_GRAPH_WALK_HINT {
    BOOLEAN               Backward;
    GUID                  SeedNodeId;
    IOA_GRAPH_EDGE_TYPE   EdgeFilter;
    ULONG                 MaxHops;
    BOOLEAN               Recursive;
    PCWSTR                Question;
} T3_GRAPH_WALK_HINT, *PT3_GRAPH_WALK_HINT;

/**************************************************/
/*           同步阻塞查询回复 — 状态更新             */
/**************************************************/

typedef struct _T3_STATE_UPDATE {
    ULONG               SrcRiskScoreDelta;
    ULONG               TgtMarkFlags;
    BOOLEAN             SrcBlacklist;
    GUID                IocExtractId;
} T3_STATE_UPDATE, *PT3_STATE_UPDATE;

/**************************************************/
/*           MITRE 概率组                          */
/*                                                  */
/*  由分析器 UpdateMitreProbs 回调逐步骤累积。       */
/*  倒推结束后写入 PairContext.T3Tactic。            */
/**************************************************/

#define T3_MITRE_PROB_MAX   6

typedef struct _T3_MITRE_PROB_DIST {
    struct {
        PCWSTR  TechniqueId;        /* "T1055.001" 等, 指向静态字符串 */
        DOUBLE  Probability;        /* [0.0, 1.0] */
        PCWSTR  Rationale;          /* 简要推理依据 */
    } Entries[T3_MITRE_PROB_MAX];
    ULONG   Count;
    BOOLEAN IsClosed;               /* TRUE=已收敛, FALSE=仍在累积中 */
} T3_MITRE_PROB_DIST, *PT3_MITRE_PROB_DIST;

/**************************************************/
/*           攻击链                                 */
/**************************************************/

#define T3_CHAIN_STATUS_COMPLETE    0
#define T3_CHAIN_STATUS_TIMED_OUT   1

typedef struct _T3_CHAIN_STEP_REF {
    PAE_PROCESS_PAIR   PairCtx;
    TIRE3_EVIDENCE_ITEM         Evidence;
} T3_CHAIN_STEP_REF, *PT3_CHAIN_STEP_REF;

typedef struct _TIRE3_ATTACK_CHAIN {
    GUID                ChainId;
    LIST_ENTRY          Link;
    GUID                ProcessSet[T3_CHAIN_MAX_PROCESSES];
    ULONG               ProcessCount;
    T3_CHAIN_STEP_REF   StepRefs[T3_CHAIN_MAX_STEPS];
    ULONG               StepCount;
    ULONG               ThreatScore;
    FLOAT               Completeness;
    ULONG               TerminationStatus;
    PCWSTR              Disposition;
    LARGE_INTEGER       CreateTime;
    LARGE_INTEGER       LastActivity;
    LARGE_INTEGER       LastMergeTime;
    GUID                MergedFromChains[T3_CHAIN_MAX_BRANCHES];
    ULONG               MergeCount;
    ULONG               WalkIteration;      // 循环迭代次数

    /* ── ShadowStrike AttackChainTracker 迁移字段 (2026-08-05, 死代码预留) ──
     * 现有活代码不读这些字段; 创建时 RtlZeroMemory 保证初值 0, 零行为变化.
     * 消费方 = T3Chain_IngestTechnique / T3Chain_EvaluateTacticCoverage /
     *          T3Chain_ConfirmAttack (T3AttackChain.c 死代码分区).
     * TechniqueSet 仅存 IoaMitreMapper.h 静态表指针, 无 UAF. */
    PCWSTR              TechniqueSet[T3_CHAIN_MAX_STEPS];  /* 已确认基技术, 静态指针去重 */
    ULONG               TechniqueCount;
    ULONG               TacticMask;         /* 覆盖战术位图 (bit = IOA_TACTIC_ID) */
    ULONG               TacticCount;
    ULONG               AppliedComboMask;   /* bit = ComboIndex, 已计分组合 */
    ULONG               ComputedScore;      /* Σ基分 + Σcombo (饱和), 确认判据专用, 不动 ThreatScore */
    ULONG               ComboBonusTotal;
    BOOLEAN             IsConfirmedAttack;
} TIRE3_ATTACK_CHAIN, *PTIRE3_ATTACK_CHAIN;

/**************************************************/
/*           攻击链池                               */
/**************************************************/

typedef struct _TIRE3_ATTACK_CHAIN_POOL {
    BOOLEAN             Initialized;
    LIST_ENTRY          ChainHead;
    ULONG               ChainCount;
    CRITICAL_SECTION    Lock;
} TIRE3_ATTACK_CHAIN_POOL, *PTIRE3_ATTACK_CHAIN_POOL;

/**************************************************/
/*           Tier3 引擎 (纯同步)                     */
/**************************************************/

struct _IOA_TIER3_ENGINE {
    BOOLEAN             Initialized;
    CRITICAL_SECTION    Lock;

    /* 攻击链池 */
    TIRE3_ATTACK_CHAIN_POOL       ChainPool;

    /* 统计 */
    volatile LONG64     TotalForensicsCalls;
    volatile LONG64     TotalChainsCreated;
    volatile LONG64     TotalChainMerges;
    volatile LONG64     TotalChainTimeouts;
    volatile LONG64     TotalBlockingQueries;
    volatile LONG64     TotalBlockingDenies;

    /* ── ShadowStrike AttackChainTracker Stats.AttacksConfirmed 迁移
     * (2026-08-05, 死代码预留; 初值由 T3Initialize RtlZeroMemory 保证 0).
     * 接入点: T3Chain_ConfirmAttack 确认时 InterlockedIncrement64. ── */
    volatile LONG64     TotalAttacksConfirmed;
};

/**************************************************/
/*               函数声明                           */
/**************************************************/

NTSTATUS T3Initialize(
    _Out_ PIOA_TIER3_ENGINE* Out
    );

VOID T3Cleanup(
    _In_ PIOA_TIER3_ENGINE Engine
    );

/*
 * ── T3DeepForensics 入口 (同步) ──
 *
 * 被 T2 同步调用。极低频（每天个位数），执行完整螺旋流水线。
 * 返回的链已加入链池，攻击链缓存已就绪。
 *
 * 螺旋流水线:
 *   阶段0: 攻击链合并
 *   循环 (最多 3 轮):
 *     因果倒推 + 参数提取 + Write阶段 ReadProcessMemory +
 *     纳新边 + 战术决策 + 缺口评估 + 条件图展开
 */
NTSTATUS T3DeepForensics(
    _In_    PIOA_TIER3_ENGINE       Engine,
    _In_    PIOA_FSM_EVIDENCE       Evidence,
    _Out_   PTIRE3_ATTACK_CHAIN* OutChain
    );

/*
 * ── 同步阻塞查询快速路径 ──
 *
 * 默认 DENY。只有 ThreatScore < 15 且操作非关键时才 ALLOW。
 * 进入 Tier3 本身已是"威胁确认"的强信号。
 */
NTSTATUS T3HandleBlockingQuery(
    _In_    PIOA_TIER3_ENGINE   Engine,
    _In_    GUID                SourceNodeId,
    _In_    GUID                TargetNodeId,
    _In_    IOA_GRAPH_EDGE_TYPE OperationType,
    _Out_   BOOLEAN*            OutAllow,
    _Out_   PT3_STATE_UPDATE    OutState
    );

/*
 * 攻击链池操作。
 */
PTIRE3_ATTACK_CHAIN T3ChainPool_Create(
    _In_ PTIRE3_ATTACK_CHAIN_POOL      Pool,
    _In_ PIOA_FSM_EVIDENCE   Evidence
    );

PTIRE3_ATTACK_CHAIN T3MergeOrCreateAttackChain(
    _In_ PTIRE3_ATTACK_CHAIN_POOL   Pool,
    _In_ PIOA_FSM_EVIDENCE          Evidence
    );

VOID T3ChainPool_EvictExpired(
    _In_ PTIRE3_ATTACK_CHAIN_POOL Pool
    );

/*
 * 周期性维护 (由 Orchestrator 维护线程调用)。
 */
VOID T3PeriodicMaintenance(
    _In_ PIOA_TIER3_ENGINE Engine
    );

/*
 * 统计查询。
 */
VOID T3GetStats(
    _In_  PIOA_TIER3_ENGINE Engine,
    _Out_ ULONG64*            ForensicsCalls,
    _Out_ ULONG64*            BlockingQueries,
    _Out_ ULONG64*            BlockingDenies
    );
