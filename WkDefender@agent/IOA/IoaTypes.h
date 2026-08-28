/**************************************************/
/*  WkDefender IOA 引擎 — 核心类型                  */
/*  进程节点 / 图节点 / 图边 / 攻击链 / 引擎配置    */
/*                                                  */
/*  重构: PairContext 中心化 + FSM 稀疏化            */
/*  - 进程节点新增进程对双向关联 + 信号缓存          */
/*  - IOA_FSM_TRACKER 按需分配，嵌入 PairContext         */
/*  - 全局稀疏状态表 <spn, tpn, pattern>            */
/**************************************************/

#pragma once

#include "../DefendTypes.h"
#include "../Process/ProcessTypes.h"
#include "../Storage/StorageEngine.h"
#include "../Common/HashMap.h"

/**************************************************/
/*               前向声明                           */
/**************************************************/

typedef struct _IOA_CARSAL_GRAPH_NODE     IOA_CARSAL_GRAPH_NODE, *PIOA_CARSAL_GRAPH_NODE;
typedef struct _IOA_GRAPH_EDGE            IOA_GRAPH_EDGE, *PIOA_GRAPH_EDGE;
typedef struct _IOA_FSM_TRACKER           IOA_FSM_TRACKER, *PIOA_FSM_TRACKER;
typedef struct _FSM_PATTERN           FSM_PATTERN, *PFSM_PATTERN;

/* ── _IOA_ENGINE 结构体需要的附加前向声明 ── */
typedef struct _IOA_CARSAL_GRAPH          IOA_CARSAL_GRAPH, *PIOA_CARSAL_GRAPH;
typedef struct _IOA_PERSIST_QUEUE         IOA_PERSIST_QUEUE, *PIOA_PERSIST_QUEUE;
typedef struct _IOA_TIER1_ENGINE          IOA_TIER1_ENGINE, *PIOA_TIER1_ENGINE;
typedef struct _IOA_TIER2_BACKTRACK       IOA_TIER2_BACKTRACK, *PIOA_TIER2_BACKTRACK;
typedef struct _IOA_FSM_ENGINE            IOA_FSM_ENGINE, *PIOA_FSM_ENGINE;
typedef struct _IOA_GRAPH_RING_BUFFER     IOA_GRAPH_RING_BUFFER, *PIOA_GRAPH_RING_BUFFER;
typedef struct _IOA_TIER3_ENGINE          IOA_TIER3_ENGINE, *PIOA_TIER3_ENGINE;
typedef struct _IOA_GRAPH_MATCHER         IOA_GRAPH_MATCHER, *PIOA_GRAPH_MATCHER;
typedef struct _IOA_GRAPH_WALKER          IOA_GRAPH_WALKER, *PIOA_GRAPH_WALKER;
typedef struct _IOA_RATE_ANALYZER         IOA_RATE_ANALYZER, *PIOA_RATE_ANALYZER;
typedef struct _IOA_SCORER               IOA_SCORER, *PIOA_SCORER;
typedef struct _IOA_AGGREGATE_EDGE_TABLE  IOA_AGGREGATE_EDGE_TABLE, *PIOA_AGGREGATE_EDGE_TABLE;
typedef struct _IOA_PROCESS_PAIR_MANAGER  IOA_PROCESS_PAIR_MANAGER, *PIOA_PROCESS_PAIR_MANAGER;

/* ── 进程对三分析上下文 (对齐 driver AE_PROCESS_PAIR 内嵌
 *    IocContext/IoaContext/TsContext, 2026-08-23) ── */
typedef struct _AE_PROCESS_PAIR_IOC_CONTEXT      AE_PROCESS_PAIR_IOC_CONTEXT, *PAE_PROCESS_PAIR_IOC_CONTEXT;
typedef struct _AE_PROCESS_PAIR_IOA_CONTEXT      AE_PROCESS_PAIR_IOA_CONTEXT, *PAE_PROCESS_PAIR_IOA_CONTEXT;
typedef struct _AE_PROCESS_PAIR_TS_CONTEXT       AE_PROCESS_PAIR_TS_CONTEXT, *PAE_PROCESS_PAIR_TS_CONTEXT;

/**************************************************/
/*               IOA 引擎配置                       */
/**************************************************/

typedef struct _IOA_ENGINE_CONFIG {
    ULONG       HotCacheMaxEntries;
    ULONG       HotCacheTtlMs;
    ULONG       PruneIntervalMs;
    ULONG       EdgeRetentionWindowMs;
    WCHAR       WarmDbPath[DEF_MAX_PATH];
    WCHAR       ColdDbPath[DEF_MAX_PATH];
    ULONG       ColdRetentionDays;
    ULONG       AttackChainMaxDepth;
    ULONG       AttackChainMinScore;
    BOOLEAN     VerboseLogging;
    BOOLEAN     StatsCollection;
    BOOLEAN     AnalysisEnabled;
    UCHAR       Reserved;
    ULONG       TemporalWindowMs;
    ULONG       AlertThrottleSeconds;
    ULONG       ScoreDecayIntervalMs;
} IOA_ENGINE_CONFIG, *PIOA_ENGINE_CONFIG;

#define IOA_DEFAULT_CONFIG                              \
    {                                                   \
        DEF_HOT_CACHE_MAX_ENTRIES,                      \
        DEF_HOT_CACHE_TTL_MS,                           \
        60000, 3600000,                                 \
        L"cg_warm.db", L"cg_cold.db",                   \
        90, DEF_PATH_MAX_DEPTH, 50,                     \
        TRUE, TRUE, TRUE, 0,                            \
        60000, 300, 60000,                              \
    }

/**************************************************/
/*               IOA 引擎统计                       */
/**************************************************/

typedef struct _IOA_ENGINE_STATS {
    volatile LONG64     EventsIngested;
    volatile LONG64     ProcessNodesCreated;
    volatile LONG       ProcessNodesTerminated;
    volatile LONG64     ThreadNodesTerminated;   /* 线程退出释放的 wkd_thread 计数 (2026-08-27) */
    volatile LONG64     GraphNodesCreated;
    volatile LONG64     EdgesCreated;
    volatile LONG64     EdgesCompacted;
    volatile LONG64     T1Evaluations;
    volatile LONG64     T1RuleHits;
    volatile LONG64     T2Calls;
    volatile LONG64     T2Hits;
    volatile LONG64     PersistEnqueued;
    volatile LONG64     PersistWritten;
    volatile LONG64     ScoreUpdates;
    volatile LONG64     MitreMappings;
    volatile LONG64     CurrentProcessCount;
    /* FSM 统计 */
    volatile LONG64     FsmEventsProcessed;
    volatile LONG64     FsmAcceptHits;
    /* 环形缓冲区写入 / 丢弃统计 (在同步路径上更新) */
    volatile LONG64     RingBufferWrites;
    volatile LONG64     RingBufferDrops;
    /* 注: RingBufferConsumed/FsmActiveTrackers/FsmTimeouts
       已迁移至 GrbGetStats / FsmGetStats 实时读取 */
    /* 进程对缺失计数 (2026-08-23 改造点三上提后, IoaObserve 阶段2 应只查
     * 分发层已建的 pair; 此处缺失属异常, 计数以观测量级) */
    volatile LONG64     MissingPairCount;
} IOA_ENGINE_STATS, * PIOA_ENGINE_STATS;

/**************************************************/
/*               IOA 引擎                           */
/**************************************************/

typedef struct _IOA_ENGINE {
    BOOLEAN             Initialized;
    BOOLEAN             Running;
    IOA_ENGINE_CONFIG   Config;

    /* 核心存储 */
    PIOA_CARSAL_GRAPH       Graph;              /* 因果图 (唯一数据源) */

    /* 持久化 */
    PIOA_PERSIST_QUEUE      PersistQueue;       /* 异步持久化队列 */

    /* 三层检测 */
    PIOA_TIER1_ENGINE       Tier1;              /* Tier 1: 单事件规则引擎 */
    PIOA_TIER2_BACKTRACK    Tier2;              /* Tier 2: 异步有界回溯 */

    /* 时序追踪与异步图写入 */
    PIOA_FSM_ENGINE         FsmEngine;          /* DFA+FSM 时序攻击链追踪 */
    PIOA_GRAPH_RING_BUFFER  RingBuffer;         /* 无锁环形缓冲区 */

    /* 分析组件 (Tier 3 异步使用) */
    PIOA_TIER3_ENGINE       Tier3;              /* Tier3 深度取证引擎 */
    PIOA_GRAPH_MATCHER      GraphMatcher;       /* 攻击链模板匹配 */
    PIOA_GRAPH_WALKER       GraphWalker;        /* 图游走调查 */
    PIOA_RATE_ANALYZER      RateAnalyzer;       /* 速率分析 */
    PIOA_SCORER             Scorer;             /* 威胁评分 */

    /* 进程对上下文 + 边聚合 */
    PIOA_AGGREGATE_EDGE_TABLE EdgeAggTable;     /* 全局边聚合表 */
    PIOA_PROCESS_PAIR_MANAGER PairManager;       /* 进程对管理器 */

    IOA_ENGINE_STATS    Stats;
    CRITICAL_SECTION    Lock;
} IOA_ENGINE, * PIOA_ENGINE;

/**************************************************/
/*               全局实例                          */
/**************************************************/

extern IOA_ENGINE WkdIoaEngine;


/**************************************************/
/*               因果图节点                         */
/**************************************************/

struct _IOA_CARSAL_GRAPH_NODE {
    GUID                    NodeId;
    DEF_NODE_TYPE           NodeType;
    LARGE_INTEGER           FirstSeen;
    LARGE_INTEGER           LastSeen;
    LIST_ENTRY              OutEdgesHead;
    LIST_ENTRY              InEdgesHead;
    ULONG                   OutDegree;
    ULONG                   InDegree;
    PWKD_PROCESS           ProcessNode;
    WCHAR                   EntityPath[DEF_MAX_PATH];
    DEF_IOC_VERDICT         IocVerdict;
    LIST_ENTRY              HashLink;
    LIST_ENTRY              GlobalLink;
    LONG                    RefCount;
};

/**************************************************/
/*               因果图边                           */
/**************************************************/

struct _IOA_GRAPH_EDGE {
    GUID                    EdgeId;
    IOA_GRAPH_EDGE_TYPE           Type;
    DEF_EVENT_CLASS         EventClass;
    GUID                    SrcNodeId;
    GUID                    TgtNodeId;
    PIOA_CARSAL_GRAPH_NODE  SrcNode;
    PIOA_CARSAL_GRAPH_NODE  TgtNode;
    LARGE_INTEGER           FirstSeen;
    LARGE_INTEGER           LastSeen;
    ULONG                   OccurrenceCount;
    ULONG                   Confidence;
    ULONG                   Weight;
    ULONG                   BehaviorFlags;
    ULONG                   EventIdCount;
    GUID                    EventIds[DEF_EDGE_MAX_EVENT_IDS];
    LIST_ENTRY              SrcOutLink;
    LIST_ENTRY              TgtInLink;
    LIST_ENTRY              GlobalLink;
};

/**************************************************/
/*           FSM 常量 + 基本类型                    */
/**************************************************/

#define FSM_HASH_BUCKETS            512         /* 旧常量，已废弃 (保留用于编译兼容) */
#define IOA_FSM_TRACKER_MAX             2048        /* 旧常量，已废弃 */
#define IOA_FSM_TRACKER_TTL_MS          120000      /* 旧常量，已废弃 */
#define FSM_CLEANUP_INTERVAL_MS     30000       /* 后台清理间隔 */
#define FSM_STATE_HASH_BUCKETS      4096        /* 全局稀疏状态哈希桶数 */

/* FSM_PATTERN_STATE — 定义见 DefendTypes.h，作为聚合边的上层包装 */

/**************************************************/
/*           全局稀疏状态条目                       */
/*           Key: <spn, tpn, PatternIndex>         */
/*           按需懒分配，只存储活跃模式的状态       */
/**************************************************/

struct _FSM_PATTERN {
    /* ── 键 (Hash 输入: DJB(SrcNodeId || TgtNodeId || PatternIndex)) ── */
    GUID                    SrcNodeId;
    GUID                    TgtNodeId;
    ULONG                   PatternIndex;       /* 攻击模式索引 (0=ClassicDllInjection, ...) */

    /* ── 模式级状态 ── */
    ULONG                   ThreatScore;        /* 当前累积威胁得分 (已含衰减) */
    LARGE_INTEGER           CreationTime;
    LARGE_INTEGER           LastStepTime;       /* 最后步进时间 (用于步骤间隔计算) */
    ULONG                   CurrentStep;        /* 已完成步数 = States[] 有效条目数 */

    /* ── States[k] 包装 Steps[k] 对应的聚合边 ── */
    FSM_PATTERN_STATE       States[FSM_STATE_MAX];  /* 按步索引，永不覆写 */

    /* ── 链表 ── */
    LIST_ENTRY              HashLink;           /* 全局稀疏哈希桶 (IOA_FSM_ENGINE::PatternHashBuckets[]) */
    LIST_ENTRY              TrackerLink;        /* 链入所属 IOA_FSM_TRACKER::ActivePatternHead */

    /* ── 所属 Tracker (反向引用，用于超时清理时同步清除 ActivePatternMask) ── */
    PIOA_FSM_TRACKER        OwnerTracker;

    volatile LONG           RefCount;
};

/**************************************************/
/*           FSM 追踪器 (重构 — 稀疏版本)           */
/*           Key: <spn, tpn>                       */
/*           按需分配，通过 PairCtx->FsmTracker 访问 */
/*           无独立哈希表/LRU，生命周期绑定 PairCtx  */
/**************************************************/

struct _IOA_FSM_TRACKER {
    GUID                    SourceProcessNodeId;
    GUID                    TargetProcessNodeId;

    /* ── 稀疏活跃状态链表 ── */
    LIST_ENTRY              ActivePatternHead;  /* FSM_PATTERN::TrackerLink */
    ULONG                   ActivePatternMask;  /* 位图: bit[i]=1 表示 Pattern[i] 当前 S>=1 */

    /* ── 接受态证据 (已迁移至 FSM_PATTERN_RESULT::Evidence, 此处不再冗余存储) ── */

    LARGE_INTEGER           CreationTime;
    LARGE_INTEGER           LastActivity;
    volatile LONG           RefCount;
};

/**************************************************/
/*           FSM 引擎全局状态 (重构)                */
/*           稀疏哈希表替代 Tracker 哈希表          */
/**************************************************/

typedef struct _IOA_FSM_ENGINE {
    BOOLEAN             Initialized;

    /* ── 全局稀疏模式哈希表 <spn, tpn, pattern> ── */
    LIST_ENTRY          PatternHashBuckets[FSM_STATE_HASH_BUCKETS];
    volatile LONG       PatternCount;

    /* ── 预定义攻击模式 (只读，初始化后不变) ── */
    FSM_PATTERN_TEMPLATE     Patterns[FSM_PATTERN_COUNT];

    /* ── 同步锁 — 保护哈希表、状态条目 ── */
    CRITICAL_SECTION    Lock;

    /* ── 过期状态检查线程 ── */
    HANDLE              CleanupThread;
    volatile BOOLEAN    CleanupRunning;

    /* ── 统计 ── */
    volatile LONG64     TotalEventsProcessed;
    volatile LONG64     TotalAcceptHits;
    volatile LONG64     TotalPatternAdvances;
    volatile LONG64     TotalTimeouts;
    volatile LONG64     TotalPartialsReported;
    volatile LONG64     TotalStateEntriesCreated;
    volatile LONG64     TotalStateEntriesFreed;
} IOA_FSM_ENGINE, *PIOA_FSM_ENGINE;

/*
 * FSM_MAX_SCORE_INFO — 查询最高威胁得分的返回值。
 */
typedef struct _FSM_MAX_SCORE_INFO {
    ULONG   MaxThreatScore;      /* 最高威胁得分 */
    ULONG   AcceptThreshold;     /* 对应模式的接受阈值 */
    ULONG   PatternIndex;        /* 最高分对应的模式索引 */
} FSM_MAX_SCORE_INFO;

/**************************************************/
/*           无锁环形缓冲区类型                      */
/**************************************************/

#define GRB_CONSUME_INTERVAL_MS     5       /* 消费线程轮询间隔 */
#define GRB_CONSUME_BATCH_SIZE      256     /* 批量消费阈值 */
#define GRB_BACKPRESSURE_THRESHOLD  (GRAPH_RING_BUFFER_SIZE * 3 / 4)

typedef struct _IOA_GRAPH_RING_BUFFER {
    /* 无锁 SPMC 环形缓冲区 */
    volatile LONG64     WriteIndex;         /* 生产者写入位置 (单调递增) */
    volatile LONG64     ReadIndex;          /* 消费者读取位置 (单调递增) */
    GRAPH_EDGE_DESCRIPTOR Buffer[GRAPH_RING_BUFFER_SIZE];

    /* 消费线程 */
    HANDLE              ConsumerThread;
    volatile BOOLEAN    ConsumerRunning;
    HANDLE              WakeEvent;          /* 自动重置事件，唤醒消费线程 */

    /* 背压降级控制 */
    volatile BOOLEAN    Backpressure;       /* TRUE=当前处于背压状态 */

    /* 统计 */
    volatile LONG64     TotalWritten;
    volatile LONG64     TotalConsumed;
    volatile LONG64     TotalDropped;       /* 背压丢弃 */
    volatile LONG64     TotalLayerDecisions[4];  /* 各层累计 */
} IOA_GRAPH_RING_BUFFER, *PIOA_GRAPH_RING_BUFFER;

/**************************************************/
/*           全局边聚合表 (P0 新增)                  */
/*           Key: <SrcNodeId, TgtNodeId, EdgeType>  */
/*           内存常驻，仅统计 + EventId 指针         */
/**************************************************/

/*
 * IOA_AGGREGATE_EDGE — <spn, tpn, type> 的聚合统计。
 *
 * 设计约束: 不存储具体事件参数。证据通过 RecentEventIds[]
 * 从 Causal Graph / SQLite 按需回查。
 */
typedef struct _IOA_AGGREGATE_EDGE {
    /* ── 键（隐式，由哈希表维护）── */
    GUID                    SrcNodeId;
    GUID                    TgtNodeId;
    IOA_GRAPH_EDGE_TYPE     EdgeType;

    /* ── 基础统计 (Tier1 语义进化用) ── */
    ULONG                   OccurrenceCount;      /* 总发生次数 (单调递增) */
    ULONG                   ActiveCount;          /* 滑动窗口内次数 */
    LARGE_INTEGER           FirstSeen;            /* 首条边的时间戳0 */
    LARGE_INTEGER           LastSeen;             /* 最近刷新时间——新入边或定期刷新 */
    ULONG                   Confidence;           /* 滚动平均置信度 [0,100] */

    /* ── 时间窗口 ── */
    LARGE_INTEGER           WindowStart;
    ULONG                   TimeWindowMs;         /* 默认 5000ms */

    /* ── 脏标记 ── */
    volatile LONG64         SequenceNumber;       /* 该类型边每次更新递增 */

    /* ── 具体边链表 (FSM 多路归并数据源) ──
     * 每条 IOA_CONCRETE_EDGE 记录一次 syscall 的 EdgeId + Timestamp。
     * 尾插保证基本有序。
     * Active=TRUE 的节点参与 FSM 归并, Active=FALSE 被跳过。
     */
    LIST_ENTRY              EdgesHead;            /* IOA_CONCRETE_EDGE::Link */
    volatile LONG           TotalEdgeCount;       /* 总节点数 (含 inactive) */
    volatile LONG           ActiveEdgeCount;      /* 活跃节点数 (Active=TRUE) */

    /* ── 链表操作锁 (保护 EdgesHead 所有操作) ── */
    SRWLOCK                 EdgeLock;

    /* ── 链表 ── */
    LIST_ENTRY              HashLink;             /* 哈希桶 */
    LIST_ENTRY              PairLink;             /* 挂入 AE_PROCESS_PAIR::EdgeListHead */
    PVOID                   OwnerPair;            /* 反向指针 → 挂靠的 AE_PROCESS_PAIR (双向摘链用, 2026-08-25) */
    LONG                    RefCount;
} IOA_AGGREGATE_EDGE, *PIOA_AGGREGATE_EDGE;

/*
 * IOA_AGGREGATE_EDGE_TABLE — 全局边聚合表。
 * 按 (SrcNodeId, TgtNodeId, EdgeType) 三元组索引。
 */
typedef struct _IOA_AGGREGATE_EDGE_TABLE {
    BOOLEAN             Initialized;
    LIST_ENTRY          HashBuckets[8192];
    volatile LONG       EntryCount;
    CRITICAL_SECTION    Lock;
} IOA_AGGREGATE_EDGE_TABLE, *PIOA_AGGREGATE_EDGE_TABLE;

/**************************************************/
/*           Tier1 谱系特征标志                       */
/*  由 T1CollectGenealogyFlags 从进程节点提取          */
/**************************************************/

#define T1_GFLAG_PPID_SPOOF      0x00000001  /* PPID 欺骗 */
#define T1_GFLAG_CROSS_SESSION   0x00000002  /* 跨会话 */
#define T1_GFLAG_ELEVATED        0x00000004  /* 提权执行 */
#define T1_GFLAG_ORPHAN          0x00000008  /* 孤儿进程 (无父) */
#define T1_GFLAG_DEEP_TREE       0x00000010  /* 谱系深度 > 3 */
#define T1_GFLAG_SYSTEM_PARENT   0x00000020  /* 系统父进程 → 非系统子进程 */

/**************************************************/
/*           Tier1 特征记录 (嵌入 PairContext)        */
/*                                                  */
/*  设计原则:                                        */
/*    1. 只记录不可从位图推导的特征 (速率/谱系/时序)    */
/*    2. 数据层+语义层由 InteractionBitmap 统一承载    */
/*    3. 供 Policy/Scorer 读取                       */
/*    4. 进程对为核心 — 特征反映"这对进程之间发生什么"   */
/**************************************************/

typedef struct _T1_PAIR_FEATURE {
    /* ── 两端进程谱系标志 (从进程节点提取) ── */
    ULONG   SrcGenealogyFlags;     /* 源进程: T1_GFLAG_* */
    ULONG   TgtGenealogyFlags;     /* 目标进程: T1_GFLAG_* */
    BOOLEAN TgtIsSystemProcess;    /* 目标=lsass/csrss/winlogon/smss */
    BOOLEAN SrcIsSystemProcess;
    ULONG   SrcIntegrityLevel;
    ULONG   TgtIntegrityLevel;

    /* ── 速率统计 (纯数据, 不评分) ── */
    ULONG   ActiveOutTargets;      /* 源进程活跃出向目标数 (广度) */
    ULONG   ActiveInSources;       /* 目标进程活跃入向源数 (受害广度) */
    ULONG   ActiveOutEdges;
    ULONG   ActiveInEdges;
    LONG64  PairEventCount;        /* 当前进程对活跃事件总数 */

    /* ── 语义进化统计 (辅助调试) ── */
    ULONG   RuleHitCount;          /* 本次 T1Evaluate 命中规则数 */
    ULONG   SemanticPopcount;      /* 语义层当前置位数 (快照) */

    /* ── 时序位图 (纯数据维护, 仅窗口衰减清理, 不做模式命名) ──
     *
     * RecentEdgeMask:  滑动窗口内的边类型位图 (bit[EdgeType]=1)。
     *                  每事件到达时原子 OR 更新, IoaCollectFeatures 中做窗口衰减。
     * EdgeLastSeen[]:  每种边类型最近触发时间, 窗口衰减时做时效性判断。
     */
    volatile ULONG64    RecentEdgeMask;
    LARGE_INTEGER       EdgeLastSeen[64];

    /* ── Tier2 反馈抑制 (由 Tier2 反写) ── */
    volatile ULONG      T2SuppressFactor;       /* 当前抑制系数 (Q8定点: 100=1.0, 5=0.05) */
    volatile LONG       LastT2Verdict;          /* 最近 Tier2 判定 (T2_VERDICT_*) */

    /* ── 累积风险评分 (由 Scorer EWMA 平滑后写入) ── */
    volatile ULONG      CumulativeRiskScore;    /* 当前进程对的累积威胁评分 */

    /* 并发安全重构 2026-08-23：EWMA 读-改-写依赖旧值，无法纯原子，
     * 用独立 SRWLOCK 保护（局部锁最后原则，粒度精准到进程对特征）。 */
    SRWLOCK             EwmaLock;               /* 保护 CumulativeRiskScore EWMA 更新 */

    /* ── 版本控制 ── */
    ULONG               Version;
    LARGE_INTEGER       LastUpdate;
} T1_PAIR_FEATURE, *PT1_PAIR_FEATURE;

/**************************************************/
/*           进程对上下文 (重构)                     */
/*           Key: <SrcNodeId, TgtNodeId>            */
/*           轻量聚合入口 + FSM Tracker 指针         */
/**************************************************/

/*
 * T3_TACTICAL_ANNOTATION — Tier3 战术标注，附着在进程对上下文上。
 *
 * 设计原则:
 *   - 进程对之间的战术标注，附着在最自然的载体（PairContext）上
 *   - T1/T2/T3 三层共享，通过 DirtyFlags 机制做增量更新
 *   - 攻击链不副本存储标注，只引用 PairContext
 *   - ConfirmedTechnique/Candidates[].TechniqueId 指向静态常量字符串
 *   - Confidence 上限 98%（永不 100%，保留不确定性空间）
 *   - PairContext TTL 过期时，如有活跃攻击链引用则晋升标注到攻击链持久化存储
 */
typedef struct _T3_TACTICAL_ANNOTATION {
    FSM_ATTACK_CLASS    ConfirmedClass;         /* Tier3 确认的 FsmClass */
    PCWSTR              ConfirmedTechnique;     /* 如 "T1055.001" (静态字符串指针, NULL=未确认) */
    ULONG               Confidence;             /* 置信度 [0, 98], 上限 98% */

    /* 概率分布 (IsClosed=FALSE 时有效) */
    struct {
        PCWSTR          TechniqueId;            /* 静态字符串指针 */
        ULONG           Probability;            /* [0, 100] */
        PCWSTR          Rationale;              /* 依据简述 (静态字符串) */
    } Candidates[4];
    ULONG               CandidateCount;

    BOOLEAN             IsClosed;               /* 攻击链在此进程对上是否已闭合 */
    ULONG               TerminationStatus;      /* COMPLETE(0) / TIMED_OUT(1) */
    LARGE_INTEGER       LastAnalysisTime;
} T3_TACTICAL_ANNOTATION, *PT3_TACTICAL_ANNOTATION;

/*
 * THREAD_HIJACK_TRACKER — 线程劫持时序追踪器，附着在进程对上下文上。
 *
 * 追踪 Suspend→SetContext→Resume 线程劫持序列 (T1055.003)，挂载范式
 * 对齐 T3_TACTICAL_ANNOTATION: 附着在 PairContext 上、跨层可见、随
 * PairContext TTL 自动清理。
 *
 * 时序语义 (对齐 ShadowStrike ThreadStateTracking + 关联窗口):
 *   - Suspend  事件: 记录 TrackedThreadId + SuspendTime, SuspendSeen=TRUE
 *   - SetContext事件: 若同一线程且距 SuspendTime ≤ THREAD_HIJACK_WINDOW_MS
 *                     → SetContextSeen=TRUE
 *   - Resume   事件: 同一线程且距 SetContextTime ≤ 窗口 → 序列闭合 → Confirmed
 * 消费点: IoaEngine 阶段4.5b 更新, IoaInjectionClassifier ThreadHijacking 分支消费。
 */
typedef struct _THREAD_HIJACK_TRACKER {
    /* 时序状态 (当前追踪的线程) */
    HANDLE          TrackedThreadId;        /* 当前追踪线程 ID (0=无) */
    LARGE_INTEGER   SuspendTime;            /* 最近 Suspend 时间戳 */
    LARGE_INTEGER   SetContextTime;         /* 最近 SetContext 时间戳 */
    LARGE_INTEGER   ResumeTime;             /* 最近 Resume 时间戳 */
    BOOLEAN         SuspendSeen;            /* 窗口内已见 Suspend */
    BOOLEAN         SetContextSeen;         /* 窗口内已见 SetContext (同线程) */

    /* 确认状态 (阶段4.5b 闭合后设置) */
    BOOLEAN         Confirmed;              /* Suspend→SetContext→Resume 已闭合 */
    ULONG           Confidence;             /* 置信度 [0,100] (对齐 IoaComputeInjectionConfidence) */
    LARGE_INTEGER   ConfirmedTime;          /* 确认时间 */
} THREAD_HIJACK_TRACKER, *PTHREAD_HIJACK_TRACKER;

/* 线程劫持时序窗口 (对齐 ShadowStrike CONTEXT_CHANGE_CORRELATION_MS / SUSPEND_DURATION_THRESHOLD_MS) */
#define THREAD_HIJACK_WINDOW_MS         1000    /* Suspend→SetContext→Resume 关联窗口 */
#define THREAD_HIJACK_SUSPEND_MIN_MS    100     /* 挂起时长下限 (低于此不构成劫持序列)

/**************************************************/
/*     WKD_BEHAVIOR_EVENT — 进程级行为检测事件视图  */
/*                                                  */
/*  死代码: 检测引擎 (Ioa*Detect) 的统一输入契约,    */
/*  对应 SS BehaviorEvent 的关键字段子集。           */
/*  接入阶段由 IoaObserve 从 WKD_EVENT_HEADER +      */
/*  各 EVENT_PAYLOAD_* 填充后分发。                    */
/*                                                  */
/*  TargetPath/RemoteHost 为借用指针 (指向接入层      */
/*  缓冲), 死代码阶段无填充者, 检测函数须判空。      */
/**************************************************/

typedef struct _WKD_BEHAVIOR_EVENT {
    /* 事件标识 */
    ULONG           Type;               /* 语义事件 (SS BehaviorEventType) */
    ULONG           TargetProcessId;    /* 目标进程 ID */

    /* 文件 */
    PCWSTR          TargetPath;         /* 文件/注册表路径 (借用指针, 可空) */
    WCHAR           FileExtension[16];  /* 文件扩展名 (含前导点) */
    ULONG           FileEntropy;        /* 熵 Q16 定点 (0=未知, 需 minifilter) */
    ULONG64         FileSize;

    /* 注册表 */
    ULONG           RegValueType;       /* REG_* (SS valueType) */

    /* 网络 */
    ULONG           RemotePort;
    ULONG64         BytesSent;
    PCWSTR          RemoteHost;         /* 域名/IP (借用指针, 可空) */

    /* 访问 */
    ULONG           AccessMask;         /* 目标对象访问权限 */

    /* 标志 */
    BOOLEAN         IsCanary;           /* 命中 Canary 蜜罐清单 */
} WKD_BEHAVIOR_EVENT, *PWKD_BEHAVIOR_EVENT;

/**************************************************/
/*      进程级 MaliceScore 时间衰减 (死代码)         */
/*                                                  */
/*  迁移自 ShadowStrike BehaviorAnalyzer             */
/*  ApplyScoreDecay (BehaviorAnalyzer.cpp L1513-     */
/*  1536, 由 ProcessEvent 每次事件前调用)。           */
/*  按距 LastUpdateTime 的分钟数线性衰减, 不低于 0。  */
/*  死代码: 供接入层/测试在事件间隔调用。             */
/**************************************************/

static
inline
VOID
IoaBehavior_ApplyScoreDecay(
    _Inout_ PWKD_PROCESS_BEHAVIOR_STATE State,
    _In_    ULONG                       DecayPerMinute   /* 每分钟衰减分 (SS SCORE_DECAY_PER_MINUTE=2) */
    )
/*++
Routine Description:
    进程级 MaliceScore 时间衰减。首次调用仅记录 LastUpdateTime,
    后续按间隔分钟数衰减。

Arguments:
    State          — 进程级行为状态 (读写 MaliceScore/LastUpdateTime)。
    DecayPerMinute — 每分钟衰减分数。

Return Value:
    无。
--*/
{
    LARGE_INTEGER now;
    LONGLONG elapsedMin;

    if (!State) return;

    GetSystemTimeAsFileTime((PFILETIME)&now);

    if (State->LastUpdateTime.QuadPart == 0) {
        State->LastUpdateTime = now;
        return;
    }

    elapsedMin = (now.QuadPart - State->LastUpdateTime.QuadPart) /
                 (10000LL * 60000LL);
    State->LastUpdateTime = now;

    if (elapsedMin > 0 && State->MaliceScore > 0) {
        /* MaliceScore 为有符号 LONG, 衰减量钳位后转有符号口径比较
         * (消除 C4018, 且防 elapsedMin 巨大时乘积截断溢出) */
        ULONG decay = DecayPerMinute * (ULONG)elapsedMin;
        LONG dec = (LONG)((decay > 0x7FFFFFFFUL) ? 0x7FFFFFFFUL : decay);
        State->MaliceScore = (State->MaliceScore > dec)
                             ? (State->MaliceScore - dec)
                             : 0;
    }
}

typedef struct _AE_PROCESS_PAIR_KEY {
    HANDLE SourceProcessId;
    HANDLE TargetProcessId;
} AE_PROCESS_PAIR_KEY, *PAE_PROCESS_PAIR_KEY;

/*
 * AE_PROCESS_PAIR — 进程对级上下文。
 *
 * 重构要点 (InteractionBitmap 统一):
 *   - InteractionBitmap 替代 ActiveEdgeTypeMask / ActiveEdgeTypeCount / PairBehaviorFlags
 *     · 低64位 = 数据层 (边类型存在性, 事件到达无条件设置)
 *     · 高64位 = 语义层 (由 T1Evaluate 多轮进化推导)
 *   - T1Feature 嵌入: Tier1 纯特征记录, 不评分不决策
 *   - FsmTracker 按需分配 (Tier2)
 *   - 速率/谱系等不可从位图推导的特征仍保留在 T1Feature
 */
typedef struct _AE_PROCESS_PAIR {
    /* ── 键 ── */
    HANDLE                  SourceProcessId;        /* 源进程 PID */
    HANDLE                  TargetProcessId;        /* 目标进程 PID */

    /* ── 统一位图 (数据层 + 语义层, 128位) ── */
    INTERACTION_BITMAP      InteractionBitmap;    /* 低64=数据层, 高64=语义层 */

    /* ── FSM 追踪器 (Tier2) ── */
    PIOA_FSM_TRACKER        FsmTracker;

    /* ── 进程节点反向关联 (2026-08-24 重构) ──
     * 承载真实节点指针 (对齐 driver AeFindOrCreateProcessPair 收
     * PWKD_PROCESS)。与 PID 键并存: PID 用于跨进程/同步查询匹配,
     * 指针用于 O(1) 访问节点、避免 PsLookupWkdProcessByStrictProcessId 反查与 UAF。 */
    PWKD_PROCESS            SrcNode;             /* 源进程节点指针 */
    PWKD_PROCESS            TgtNode;             /* 目标进程节点指针 */
    LIST_ENTRY              SourceProcessLinks;              /* 链入 SrcNode->OutPairListHead */
    LIST_ENTRY              TargetProcessLinks;              /* 链入 TgtNode->InPairListHead */

    /* ── 边聚合入口 (指向 EdgeAggregateTable 中的条目) ──
     * 链头锁原则 (2026-08-25): EdgeListHead 的全部读写一律持
     * 本锁 — 挂链查重/遍历用共享, InsertTailList 用独占。 */
    SRWLOCK                 EdgeListLock;         /* 保护 EdgeListHead */
    LIST_ENTRY              EdgeListHead;         /* IOA_AGGREGATE_EDGE::PairLink */

    /* ── <spn, tpn> 级别总计数 (供进程级速率计算) ── */
    volatile ULONG          TotalEventCount;      /* Σ OccurrenceCount，历史累计 */
    volatile ULONG          ActiveEventCount;     /* Σ ActiveCount，活跃窗口内 */

    /* ── 时间戳 ── */
    LARGE_INTEGER           FirstSeen;
    LARGE_INTEGER           LastSeen;
    LARGE_INTEGER           CreationTime;

    /* ── 脏标记 ── */
    volatile LONG64         SequenceNumber;       /* 任意边更新时递增 */
    volatile ULONG          DirtyFlags;           /* IOA_PAIR_DIRTY_TIER1|T2|T3 */

    /* ── Tier1 特征记录 (不可从位图推导的特征: 速率/谱系/时序/评分) ── */
    T1_PAIR_FEATURE         T1Feature;            /* IoaCollectFeatures 填充, Scorer 读取 */

    /* ── 生命周期 ──
     * 2026-08-23 HashMap 化: 自定义桶/LRU 已删除, 索引由 PairManager.PairMap
     * 承接 (key=AE_PROCESS_PAIR_KEY 字节块)。配额由 MaxEntries 承接,
     * 淘汰策略由维护清扫按 LastSeen 摘除 (对齐 driver 范式)。 */
    volatile LONG           RefCount;

    /* ── Tier2 良性抑制元数据 (由 Tier2 反写) ──
     *
     * Tier2 判定良性后反写抑制因子, Policy 读取降权以避免频繁误触发。
     * 抑制强度随连续良性判定次数递增: 100→80→60→40→20→5(floor)
     */
    LARGE_INTEGER           LastT2VerdictTime;       /* 判定时间戳 */
    volatile LONG           T2SuppressCount;         /* 连续良性判定的累计次数 */
    LARGE_INTEGER           T2SuppressResetTime;     /* 抑制因子下次衰减检查时间 */
    ULONG                   T2VerdictEdgeMask;       /* 判定时的数据层位图快照 (用于检测变化) */

    /* ── Tier3 战术标注 (2026-07 新增) ── */
    T3_TACTICAL_ANNOTATION  T3Tactic;               /* 三层共享，攻击链通过 PairRefs[] 引用 */

    /* ── 线程劫持时序追踪 (2026-08 新增, T1055.003) ── */
    THREAD_HIJACK_TRACKER   ThreadHijack;           /* Suspend→SetContext→Resume 时序追踪 */

    /* ── 序列规则引擎状态宿主 (ShadowStrike PatternMatcher 迁移, 2026-08) ──
     * 内嵌列表头 + 计数。状态实体在 PolicyEngine g_SeqEngine.StateHashBuckets 中
     * (键 = <SrcNodeId,TgtNodeId,RuleIndex>), 经 PairLink 链回本列表。
     * PairCtx 被 LRU/TTL 淘汰时据此回收全部序列状态
     * (PolicyEngine_RemovePairSequenceStates)。
     * 默认 EnableSequenceRules=FALSE, 不创建任何状态。 */
    LIST_ENTRY              SeqMatchHead;           /* WKD_SEQ_MATCH_STATE::PairLink */
    ULONG                   SeqMatchCount;

    /* ── 三分析上下文 (对齐 driver AE_PROCESS_PAIR 内嵌
     *      IocContext/IoaContext/TsContext, 2026-08-23) ──
     *    IOC 证据链挂互动产生的 IOC 痕迹 (如 shellcode 注入);
     *    IOA 行为摘要链 + 评分上下文 (60s 结算委托 VerdictEngine)。
     *    生命周期 = pair; 创建时 AeCreateProcessPairContexts 分配,
     *    释放时 AeDestroyProcessPairContexts 释放。 */
    PAE_PROCESS_PAIR_IOC_CONTEXT  IocContext;   /* IOC 证据链 (按 Indicator 去重) */
    PAE_PROCESS_PAIR_IOA_CONTEXT  IoaContext;   /* IOA 行为摘要链 */
    PAE_PROCESS_PAIR_TS_CONTEXT   TsContext;    /* 评分上下文 (双链 + 得分缓存) */
} AE_PROCESS_PAIR, *PAE_PROCESS_PAIR;

/*
 * IOA_PROCESS_PAIR_MANAGER — 进程对管理器。
 * 2026-08-23 HashMap 化: 自定义 HashBuckets[4096]+LruHead 删除,
 * 改持通用 WKD_HASH_MAP (key=AE_PROCESS_PAIR_KEY 字节块, value=pair 指针)。
 */
typedef struct _IOA_PROCESS_PAIR_MANAGER {
    BOOLEAN                 Initialized;
    WKD_HASH_MAP            PairMap;              /* <SrcPid,TgtPid> → pair 索引 */
    volatile LONG          ActivePairs;
    volatile LONG          PeakPairs;
    volatile LONG          TotalPairs;
    CRITICAL_SECTION        Lock;                 /* 保护创建慢路径与统计 */
    ULONG                   MaxPairs;             /* 默认 4096 (同步至 PairMap.MaxEntries) */
    ULONG                   PairTtlMs;            /* 默认 300000 (5分钟) */
    HANDLE                  CleanupThread;
    volatile BOOLEAN        CleanupRunning;
} IOA_PROCESS_PAIR_MANAGER, *PIOA_PROCESS_PAIR_MANAGER;

/* DirtyFlags 位定义 */
#define IOA_PAIR_DIRTY_TIER1    0x01
#define IOA_PAIR_DIRTY_TIER2    0x02
#define IOA_PAIR_DIRTY_TIER3    0x04
#define IOA_PAIR_DIRTY_THREAD_HIJACK 0x08   /* ThreadHijack 时序状态已更新 */
#define IOA_PAIR_DIRTY_TIER3_TACTIC 0x08   /* T3TacticalAnnotation 已更新 */
#define IOA_PAIR_DIRTY_T2_SUSPICIOUS 0x08   /* Tier2 判定可疑 → 降低后续触发阈值 */
