/**************************************************/
/*  WkDefender VerdictEngine — 中央判定层            */
/*  多引擎加权融合 + 活跃威胁管理 + 响应分发          */
/*                                                  */
/*  ShadowStrike ThreatDetector 迁移 (2026-08-04):   */
/*    - AggregateEngineDetections  → VerdictEngine_Fuse
/*    - GetActiveThreats 系列       → 活跃威胁表 + ALPC 查询
/*    - ExecuteAction              → VerdictEngine_DispatchResponse (monitor-only)
/*    - OnProcessTerminate         → VerdictEngine_OnProcessTerminate
/*                                                  */
/*  数据来源 (融合信号):                              */
/*    E1 IOC     procNode.SecCtx.IocVerdict/IocConfidence
/*    E2 IOA-T1  PairCtx.T1Feature.CumulativeRiskScore
/*    E3 IOA-T2  PairCtx.T1Feature.LastT2Verdict
/*    E4 IOA-T3  PairCtx.T3Tactic.Confidence
/*    E5 行为     Event.Confidence (注入分类器回填, 尺度 0-1000)
/*    E6 行为     WKD_PROCESS_BEHAVIOR_STATE.MaliceScore (※死代码)
/**************************************************/

#pragma once

#include "../DefendTypes.h"
#include "../Notification/EventTypes.h"
#include "../Notification/AlpcService.h"
#include "../IOA/IoaTypes.h"
#include "../IOA/IoaPersistQueue.h"

/**************************************************/
/*               Verdict 结构                       */
/**************************************************/

/* 单引擎检测 (融合输入) */
typedef struct _WKD_ENGINE_DETECTION {
    DEF_DETECTION_SOURCE    Source;
    ULONG                   Score;          /* [0,100] */
    ULONG                   Confidence;     /* [0,100] */
    PCWSTR                  MitreId;        /* 静态字符串或 NULL (T3 ConfirmedTechnique) */
} WKD_ENGINE_DETECTION, *PWKD_ENGINE_DETECTION;

#define WKD_VERDICT_MAX_MITRE       4
#define WKD_VERDICT_MAX_DETECTIONS  8
#define WKD_VERDICT_NAME_LEN        64
#define WKD_VERDICT_DESC_LEN        256

/* 本地白名单容量 (SS WhitelistProcess/WhitelistHash 迁移, 防误报) */
#define VERDICT_WHITELIST_MAX_PIDS    128
#define VERDICT_WHITELIST_MAX_HASHES  64

/* 统一威胁判定 (平坦结构, 可直接 ALPC 传输 / 持久化投影) */
typedef struct _WKD_VERDICT {
    GUID                    VerdictId;
    LARGE_INTEGER           Timestamp;
    GUID                    SuspectNodeId;      /* 嫌疑进程 NodeId */
    GUID                    VictimNodeId;       /* 受害进程/实体 NodeId */
    ULONG                   ThreatScore;        /* 融合后威胁评分 [0,100] */
    DEF_THREAT_SEVERITY     Severity;
    ULONG                   Confidence;         /* 引擎一致率 [0,100] */
    DEF_CONFIDENCE_LEVEL    ConfidenceLevel;
    DEF_THREAT_CATEGORY     Category;
    DEF_RESPONSE_ACTION     RecommendedAction;
    DEF_DETECTION_SOURCE    PrimarySource;
    ULONG                   EngineCount;        /* 参与融合的引擎数 */
    ULONG                   EngineAgreement;    /* 一致率 [0,100] */
    ULONG                   BestEngineScore;
    ULONG                   DetectionFlags;     /* DEF_BEHAVIOR_FLAG_* */
    ULONG                   MitreCount;
    WCHAR                   MitreIds[WKD_VERDICT_MAX_MITRE][16];
    WCHAR                   ProcessName[WKD_VERDICT_NAME_LEN];
    WCHAR                   Description[WKD_VERDICT_DESC_LEN];
} WKD_VERDICT, *PWKD_VERDICT;

/* 活跃威胁条目 (NodeId → Verdict, LRU 淘汰) */
typedef struct _WKD_ACTIVE_THREAT {
    WKD_VERDICT             Verdict;
    LARGE_INTEGER           LastUpdate;
    LIST_ENTRY              LruLink;        /* 全局 LRU 链 */
    LIST_ENTRY              HashLink;       /* 桶内链 */
} WKD_ACTIVE_THREAT, *PWKD_ACTIVE_THREAT;

/**************************************************/
/*               VerdictEngine 配置                 */
/**************************************************/

typedef struct _VERDICT_ENGINE_CONFIG {
    BOOLEAN             Enabled;
    ULONG               DetectionThreshold;     /* 默认 50 */
    ULONG               CriticalThreshold;      /* 默认 90 */
    ULONG               HighThreshold;          /* 默认 70 */
    ULONG               MediumThreshold;        /* 默认 50 */
    DEF_THREAT_SEVERITY MinNotifySeverity;      /* 默认 High */
    ULONG               MaxActiveThreats;       /* 默认 10000 */
    BOOLEAN             AutoTerminate;          /* monitor-only 默认 FALSE */
    BOOLEAN             AutoQuarantine;
    BOOLEAN             AutoIsolate;
    /* 引擎权重 (Q8 定点: 100=1.00, 总和 100) */
    ULONG               WeightIoc;              /* 30 */
    ULONG               WeightT1;               /* 25 */
    ULONG               WeightT2;               /* 20 */
    ULONG               WeightT3;               /* 15 */
    ULONG               WeightClassifier;       /* 5 (E5 事件级行为信号) */
    ULONG               WeightBehavior;         /* 5 (E6 死代码) */
    BOOLEAN             EnableRuntimeRules;     /* FALSE (死代码) */
} VERDICT_ENGINE_CONFIG, *PVERDICT_ENGINE_CONFIG;

#define VERDICT_DEFAULT_CONFIG  \
    { TRUE, 50, 90, 70, 50, DefThreatSeverity_High, 10000, \
      FALSE, FALSE, FALSE, 30, 25, 20, 15, 5, 5, FALSE }

typedef struct _VERDICT_ENGINE {
    BOOLEAN             Initialized;
    VERDICT_ENGINE_CONFIG Config;
    LIST_ENTRY          HashBuckets[1024];
    LIST_ENTRY          LruHead;
    ULONG               Count;
    CRITICAL_SECTION    Lock;
    volatile LONG64     VerdictsProduced;
    volatile LONG64     ResponsesDispatched;

    /* ── 本地白名单 (对齐 SS WhitelistProcess/WhitelistHash, 防误报) ── */
    CRITICAL_SECTION    WhitelistLock;
    ULONG               WhitelistedPidCount;
    ULONG               WhitelistedPids[VERDICT_WHITELIST_MAX_PIDS];
    ULONG               WhitelistedHashCount;
    CHAR                WhitelistedHashes[VERDICT_WHITELIST_MAX_HASHES][65];  /* 小写 hex */

    /* ── Verdict 统计细分 (对齐 SS ThreatDetectorStats) ── */
    volatile LONG64     ThreatsBySeverity[5];       /* DEF_THREAT_SEVERITY 索引 */
    volatile LONG64     ThreatsByCategory[DefThreatCat_Max];
    volatile LONG64     FalsePositives;             /* 用户反馈误报计数 */
} VERDICT_ENGINE, *PVERDICT_ENGINE;

extern VERDICT_ENGINE g_VerdictEngine;

/**************************************************/
/*               函数声明                           */
/**************************************************/

NTSTATUS VerdictEngine_Initialize(_In_opt_ PVERDICT_ENGINE_CONFIG Config);
VOID     VerdictEngine_Cleanup(VOID);

/* 多引擎融合判定: 有检测产出返回 TRUE, Verdict 填充。
 * 对齐 SS AggregateEngineDetections (ThreatDetector.cpp L410-527):
 *   加权平均评分 → 严重度分级 → 引擎一致率置信度 → 类别推断 → 推荐动作 */
BOOLEAN  VerdictEngine_Fuse(
    _In_ PWKD_EVENT_HEADER   Event,
    _In_opt_ PWKD_PROCESS Node,
    _Out_ PWKD_VERDICT       Verdict
    );

/* 引擎检测收集 (供单测): 返回检测数量 */
ULONG    VerdictEngine_CollectEngineDetections(
    _In_ PWKD_EVENT_HEADER   Event,
    _In_opt_ PWKD_PROCESS Node,
    _Out_ PWKD_ENGINE_DETECTION Detections,
    _In_ ULONG               MaxCount
    );

/* ── 活跃威胁管理 ── */
VOID     VerdictEngine_UpsertActiveThreat(_In_ PWKD_VERDICT Verdict);
ULONG    VerdictEngine_GetActiveThreatCount(VOID);
ULONG    VerdictEngine_GetActiveThreats(_Out_ PWKD_VERDICT Out, _In_ ULONG MaxCount);
BOOLEAN  VerdictEngine_GetVerdict(_In_ GUID NodeId, _Out_ PWKD_VERDICT Verdict);
ULONG    VerdictEngine_GetProcessThreatScore(_In_ ULONG Pid);
VOID     VerdictEngine_OnProcessTerminate(_In_ ULONG Pid);   /* 进程退出清理 */

/* ── 响应分发 (monitor-only 默认, 对齐 SS ExecuteAction) ── */
VOID     VerdictEngine_DispatchResponse(_In_ PWKD_VERDICT Verdict);

/* ── Verdict → IOA_ALERT 投影 ── */
VOID     VerdictEngine_VerdictToAlert(_In_ PWKD_VERDICT Verdict, _Inout_ PIOA_ALERT Alert);

/* 分配持久化 IOA_ALERT (单块堆内存, 含字符串缓冲)。
 * 满足持久化队列 UtHeapFree(Data) 整体释放语义; 调用方转移所有权。 */
PIOA_ALERT VerdictEngine_AllocPersistAlert(_In_ PWKD_VERDICT Verdict);

/* ── 运行时规则 (※死代码: EnableRuntimeRules=FALSE, 评估逻辑预留) ── */
NTSTATUS VerdictEngine_ApplyRuntimeRules(
    _In_ PWKD_EVENT_HEADER   Event,
    _In_opt_ PWKD_PROCESS Node,
    _Inout_ PULONG           Score
    );

/* ── ALPC 查询 handler (0x1005/0x1006, 由 main.c 注册路由) ── */
NTSTATUS VerdictEngine_GetActiveThreatsHandler(
    _In_ PWKD_ALPC_SERVER Server,
    _In_ PWKD_MESSAGE     Message,
    _In_opt_ PVOID        Context
    );

NTSTATUS VerdictEngine_GetVerdictHandler(
    _In_ PWKD_ALPC_SERVER Server,
    _In_ PWKD_MESSAGE     Message,
    _In_opt_ PVOID        Context
    );

/* ── 本地白名单 (SS WhitelistProcess/WhitelistHash 迁移, 防误报) ── */
VOID     VerdictEngine_WhitelistProcess(_In_ ULONG Pid);
VOID     VerdictEngine_WhitelistHash(_In_ PCSTR Sha256Hex);     /* 小写归一化 */
BOOLEAN  VerdictEngine_IsWhitelisted(_In_ ULONG Pid, _In_opt_ PCSTR Sha256Hex);

/* ── 误报反馈 (SS ReportFalsePositive 迁移: 移除威胁 + 计数) ── */
VOID     VerdictEngine_ReportFalsePositive(_In_ GUID VerdictId);

/* ── 查询 API 补全 (SS GetThreatsByProcess/BySeverity/ByCategory/HasActiveThreat) ── */
ULONG    VerdictEngine_GetThreatsByProcess(_In_ ULONG Pid, _Out_ PWKD_VERDICT Out, _In_ ULONG MaxCount);
ULONG    VerdictEngine_GetThreatsBySeverity(_In_ DEF_THREAT_SEVERITY MinSeverity, _Out_ PWKD_VERDICT Out, _In_ ULONG MaxCount);
ULONG    VerdictEngine_GetThreatsByCategory(_In_ DEF_THREAT_CATEGORY Category, _Out_ PWKD_VERDICT Out, _In_ ULONG MaxCount);
BOOLEAN  VerdictEngine_HasActiveThreat(_In_ ULONG Pid);

/* ── 统计快照/重置 (SS GetStats/ResetStats 迁移) ── */
VOID     VerdictEngine_GetStats(_Out_opt_ PULONG64 ThreatsBySeverity, _Out_opt_ PULONG64 ThreatsByCategory, _Out_opt_ PULONG64 FalsePositives);
VOID     VerdictEngine_ResetStats(VOID);
