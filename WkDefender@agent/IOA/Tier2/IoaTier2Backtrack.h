/**************************************************/
/*  WkDefender — Tier 2 异步有界回溯                 */
/*  触发源: FSM 接受态 / Tier 1 规则命中              */
/*  异步消费告警描述符队列, 对每项执行读图验证         */
/*  支持 FSM 证据包交叉验证 (图中缺失边时补充)         */
/**************************************************/

#pragma once

#include "../IoaCarsalGraph.h"
#include "../IoaPersistQueue.h"

/**************************************************/
/*     T1 触发描述符构造函数（简化入队）              */
/*     不再使用 IOA_TIER2_TRIGGER（已弃用冗余结构）  */
/*     直接在 IoapDispatchTier2/消费端间传递必要参数  */
/**************************************************/
/*               Tier 2 告警描述符 (异步队列条目)    */
/**************************************************/

typedef struct _IOA_TIER2_ALERT_DESCRIPTOR {
    LIST_ENTRY          Link;               /* 队列链表 */

    BOOLEAN             FromFsm;            /* TRUE=来自 FSM 引擎 */

    /* ── 进程对标识 (T1/FSM 共享, 供异步消费端重建 FSM 推进上下文) ── */
    GUID                SourceNodeId;
    GUID                TargetNodeId;
    IOA_GRAPH_EDGE_TYPE EdgeType;           /* 触发边类型 */
    ULONG               BehaviorFlags;      /* Event->BehaviorFlags */

    union {
        struct {
            WCHAR           RuleName[64];
            WCHAR           MitreId[16];
        } T1;
        struct {
            PIOA_FSM_EVIDENCE Evidence;  /* 堆分配, 消费后释放 */
        } Fsm;
    } Source;

    DEF_THREAT_SEVERITY TriggerSeverity;
    LONG64              TriggerSeqNum;      /* P2: 触发时的进程对序列号 */
    LARGE_INTEGER       Timestamp;
} IOA_TIER2_ALERT_DESCRIPTOR, *PIOA_TIER2_ALERT_DESCRIPTOR;

/**************************************************/
/*               Tier 2 回溯结果                    */
/*  注意: T2_PATH_NODE 和 T2_MAX_PATH_NODES 已移除  */
/*  （IoapBfsBackward 已弃用，不再需要限边类型回溯） */
/**************************************************/
/*           Tier2 子图与特征类型 (P2)               */
/**************************************************/

#define T2_SUBGRAPH_MAX_NODES   64
#define T2_SUBGRAPH_MAX_EDGES   128
#define T2_BACKTRACK_MAX_DEPTH   3

/* 子图中的边（压缩表示） */
typedef struct _T2_SUBGRAPH_EDGE {
    GUID                SourceNodeId;
    GUID                TargetNodeId;
    IOA_GRAPH_EDGE_TYPE EdgeType;
    ULONG               OccurrenceCount;
    ULONG               Confidence;
    ULONG               BehaviorFlags;
} T2_SUBGRAPH_EDGE, *PT2_SUBGRAPH_EDGE;

/* 局部因果子图 */
typedef struct _T2_SUBGRAPH {
    ULONG               NodeCount;
    GUID                NodeIds[T2_SUBGRAPH_MAX_NODES];
    ULONG               EdgeCount;
    T2_SUBGRAPH_EDGE    Edges[T2_SUBGRAPH_MAX_EDGES];

    /* 汇总（避免重复遍历） */
    ULONG               InEdgeCount;
    ULONG               OutEdgeCount;
    ULONG               InjectionEdgeCount;     /* InjectsInto / Hollows */
    ULONG               MemoryOpEdgeCount;      /* Allocates/WritesTo/Protects/ReadsFrom */
    ULONG               CreatesEdgeCount;
    BOOLEAN             ContainsSystemProcess;
    BOOLEAN             ContainsLsass;
    GUID                SeedNodeId;
} T2_SUBGRAPH, *PT2_SUBGRAPH;

/* 子图特征向量 */
typedef struct _T2_FEATURE_VECTOR {
    /* 拓扑特征 */
    FLOAT   NonCreateEdgeRatio;     /* 非 Creates 边占比 */
    ULONG   DistinctEdgeTypes;      /* 不同边类型数量 */
    ULONG   MaxInDegree;            /* 子图中最大入度 */
    ULONG   MultiHopInjectionDepth; /* 连续非创建边的最大跳数 */
    BOOLEAN HasInjectionEdge;       /* 存在 InjectsInto/Hollows 边 */
    BOOLEAN HasWriteEdge;           /* 存在 WritesTo 边 */
    BOOLEAN HasAllocateEdge;        /* 存在 Allocates 边 */
    ULONG   MemoryOpEdgeCount;      /* 内存操作边数 (Allocates/WritesTo/Protects/ReadsFrom) */

    /* 节点属性特征 */
    ULONG   ElevatedProcessCount;   /* IsElevated 或 IntegrityLevel≥High */
    ULONG   SystemProcessAbused;    /* 系统进程被非创建边连接 (InDegree>1) */
    ULONG   ExternalNodeCount;      /* 不在同一进程树分支的节点 */

    /* 时序特征 */
    LONGLONG TotalDurationMs;       /* 子图时间跨度 (ms) */
    FLOAT    EventDensity;           /* 边数 / 时间跨度(s) — 越高越密集 */
    BOOLEAN HasBurstPattern;        /* 短时间窗口内密集操作 (≥3边/100ms) */

    /* 输出标记 */
    BOOLEAN HasSensitiveTarget;     /* ContainsLsass || ContainsSystemProcess abused */
} T2_FEATURE_VECTOR, *PT2_FEATURE_VECTOR;

/* Tier2 判决 */
typedef enum _T2_VERDICT {
    T2_VERDICT_BENIGN     = 0,
    T2_VERDICT_SUSPICIOUS = 1,
    T2_VERDICT_ATTACK     = 2
} T2_VERDICT;

/* Tier2 分析结果 */
typedef struct _T2_ANALYSIS_RESULT {
    T2_VERDICT  Verdict;
    ULONG       ThreatScore;            /* 融合后威胁得分 [0,100] */
    WCHAR       Reason[128];            /* 可读原因 */
    T2_SUBGRAPH Subgraph;               /* 提取的子图 */
    T2_FEATURE_VECTOR Features;         /* 测量的特征 */

    /* ── FSM 阶段输出 (调用者无需了解 FSM 实现) ── */
    BOOLEAN     FsmAccepted;            /* FSM 是否到达最终接受态 */
    BOOLEAN     FsmPartialAccept;       /* FSM 是否到达部分接受态 */
    WCHAR       FsmPatternName[64];     /* FSM 识别的模式名 */
    ULONG       FsmMaxScore;            /* FSM 最高威胁得分 */
} T2_ANALYSIS_RESULT, *PT2_ANALYSIS_RESULT;

/**************************************************/
/*               Tier 2 分析器                      */
/**************************************************/

typedef struct _IOA_TIER2_BACKTRACK {
    BOOLEAN             Initialized;
    CRITICAL_SECTION    Lock;
    PIOA_PERSIST_QUEUE  PersistQueue;

    /* 告警描述符队列 (SPSC, 生产者=FSM回调/T1, 消费者=T2异步线程) */
    LIST_ENTRY          AlertDescHead;
    volatile LONG       AlertDescCount;
    HANDLE              AlertWakeEvent;     /* 自动重置, 唤醒消费线程 */

    volatile LONG64     TotalCalls;
    volatile LONG64     VerificationHits;
    volatile LONG64     TotalProcessed;
    volatile LONG64     CrossValidations;
} IOA_TIER2_BACKTRACK, *PIOA_TIER2_BACKTRACK;

/**************************************************/
/*               函数声明                           */
/**************************************************/

NTSTATUS T2Initialize(
    _Out_ PIOA_TIER2_BACKTRACK* Out,
    _In_  PIOA_PERSIST_QUEUE    PersistQueue
    );

VOID T2Cleanup(_In_ PIOA_TIER2_BACKTRACK Engine);

/*
 * 简化入队：T1 触发 → 告警描述符入队。
 *
 * 不再使用 IOA_TIER2_TRIGGER 结构体，直接传递必要参数。
 * SuspectNodeId/VictimNodeId 在消费端作为种子节点用于子图提取，
 * T2ExtractSubgraph 不做边类型过滤（全量回溯），因此无需 BacktrackEdges。
 */
NTSTATUS IoaTire2Trackback(
    _In_ PIOA_TIER2_BACKTRACK Engine,
    _In_ GUID                 SuspectNodeId,
    _In_ GUID                 VictimNodeId,
    _In_opt_ PCWSTR           RuleName,
    _In_ DEF_THREAT_SEVERITY  Severity,
    _In_ LONG64               SeqNum
    );

/*
 * 异步处理: 消费告警描述符队列。
 * 对每个描述符:
 *   - FromFsm: IoapEvidenceCrossValidate 证据包 vs Warm 图
 *   - From T1:  T2ExtractSubgraph 子图提取 + 特征测量 + 判定
 *              （不再使用限边类型的 BFS 回溯，IoapBfsBackward 已移除）
 *
 * 由后台线程周期性调用。
 */
VOID T2ProcessAlertQueue(
    _In_ PIOA_TIER2_BACKTRACK Engine
    );

/*
 * FSM 证据包直接入队到 Tier 2 告警处理队列。
 * 由 IoaEngine 的 FSM 接受态回调调用 (FSM 锁内或外部均可)。
 *
 * 此函数分配 IOA_TIER2_ALERT_DESCRIPTOR + 深拷贝证据包，
 * 插入 AlertDescHead 并唤醒 T2 异步消费线程。
 *
 * 注意: Evidence 的内存所有权转移给 Tier 2 (消费后释放)。
 */
VOID T2EnqueueFsmAlert(
    _In_ PIOA_TIER2_BACKTRACK  Engine,
    _In_ PIOA_FSM_EVIDENCE   Evidence,
    _In_ DEF_THREAT_SEVERITY    Severity
    );

/*
 * ── Tier2 同步评估入口 ──
 *
 * T2AnalyzeInternal 的统一同步入口。
 * 执行: FSM多路归并 → 谱系上下文 → 子图分析 → 威胁得分融合。
 */
NTSTATUS T2EvaluateSync(
    _In_  PIOA_TIER2_BACKTRACK  Engine,
    _In_  PAE_PROCESS_PAIR PairCtx,
    _Out_ PT2_ANALYSIS_RESULT   Result
    );

/*
 * ── Tier2 异步入队 ──
 *
 * 打包含 SourceNodeId/TargetNodeId 的描述符入队。
 * 消费端 T2ProcessAlertQueue 取出后重建 PairCtx 调用 T2AnalyzeInternal。
 */
NTSTATUS T2EnqueueAsync(
    _In_ PIOA_TIER2_BACKTRACK   Engine,
    _In_ PAE_PROCESS_PAIR PairCtx,
    _In_ DEF_THREAT_SEVERITY    Severity
    );

/*
 * ── Tier2 统一分析流水线 ──
 *
 * 供同步和异步路径共享。
 * SrcNode/TgtNode 从 Genealogy + PairCtx 反查。
 * FSM 从 PairCtx->EdgeListHead 多路归并。
 *
 * 流水线:
 *   1. FSM 多路归并推进 (步骤间隔衰减内建)
 *   2. 谱系上下文权重
 *   3. 两级决策 (良性/部分接受/继续)
 *   4. 子图提取 + 特征测量 + 规则树判定
 *   5. 威胁得分融合 (FSM×0.7 + 子图×0.3)
 *   6. 判决 + 良性抑制反写
 */
NTSTATUS T2AnalyzeInternal(
    _In_  PIOA_TIER2_BACKTRACK  Engine,
    _In_  PAE_PROCESS_PAIR PairCtx,
    _Out_ PT2_ANALYSIS_RESULT   Result
    );

/*
 * 提取局部因果子图（双向 BFS，深度 ≤ T2_BACKTRACK_MAX_DEPTH）。
 * 供 T2EvaluateSync 和异步路径共享。
 */
NTSTATUS T2ExtractSubgraph(
    _In_  PIOA_CARSAL_GRAPH  Graph,
    _In_  GUID               SeedNodeId,
    _In_  ULONG              MaxDepth,
    _Out_ PT2_SUBGRAPH       Subgraph
    );

/*
 * 测量子图结构特征向量。
 */
VOID T2MeasureFeatures(
    _In_  PT2_SUBGRAPH        Subgraph,
    _In_  PIOA_CARSAL_GRAPH   Graph,
    _Out_ PT2_FEATURE_VECTOR  Features
    );

/*
 * 规则树判定: ATTACK / SUSPICIOUS / BENIGN。
 * 基于子图特征向量做二分类。
 */
VOID T2ClassifySubgraph(
    _In_  PT2_FEATURE_VECTOR   Features,
    _In_  BOOLEAN              HasFsmGuidance,
    _Out_ PT2_ANALYSIS_RESULT  Result
    );
