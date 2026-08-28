/**************************************************/
/*  WkDefender IOA — 进程行为速率分析器              */
/*                                                  */
/*  真正的"时序分析"——不是攻击链检测:                */
/*  - 每个进程维护操作计数和速率统计                 */
/*  - 检测异常频率（如每秒 N 次远程线程创建）         */
/*  - 第一阶段：提供计数底座，检测逻辑后续迭代        */
/*                                                  */
/*  增强: RaGetRateScore — Tier1 同步查询             */
/*  返回归一化速率异常分 [0,100]，供多源聚合          */
/**************************************************/

#pragma once

#include "../IoaTypes.h"
#include "../../Notification/EventTypes.h"
#include "../IoaPersistQueue.h"     /* IOA_ALERT (统计异常告警) */

#define RA_MAX_PROCESS_COUNT     4096
#define RA_WINDOW_MS             10000       /* 滑动窗口 10 秒 */

/*
 * ─────────────────────────────────────────────────────────
 * 统计基线异常检测 (ShadowStrike AnomalyDetector 迁移, 2026-08-05)
 *
 * Z-Score + Modified Z-Score(MAD) 统计基线, 对齐 SS AnomalyDetector.c:
 *   - 每进程按 RA_METRIC_TYPE 维度维护滑动窗口基线
 *     (均值/标准差/Min/Max, 256 样本环形缓冲, 每10样本重算)
 *   - 经典 Z-Score 与 MAD 修正 Z 取保守值; z>4σ 回退纯 Z-Score
 *   - 进程级基线优先, 样本<10 回退全局基线
 *   - 判定异常(≥2σ)的样本不写入基线 (防攻击流量驯化基线, SS 缺失补强)
 * ─────────────────────────────────────────────────────────
 */
#define RA_BASELINE_SAMPLES         256     /* SS 1000 → 256 (内存可控滑动窗口) */
#define RA_MIN_SAMPLES_FOR_DETECTION 10    /* 基线可用最小样本数 */
#define RA_STALE_BASELINE_AGE_MS    3600000 /* 进程基线 TTL: 1 小时 */
#define RA_MAINTENANCE_INTERVAL_MS  60000   /* 维护线程周期: 1 分钟 */
#define RA_MAX_ANOMALIES            10000   /* 异常环上限 (LRU 驱逐) */
#define RA_HASH_BUCKET_COUNT        1024    /* 进程基线哈希桶 */
#define RA_MAX_PROCESS_BASELINES    1024    /* 进程基线上限 (惰性分配) */
#define RA_MAX_PROCESS_NAME_CCH     260

/* sigma 阈值 (SS AD_DEFAULT_SIGMA_THRESHOLD 等) */
#define RA_DEFAULT_SIGMA_THRESHOLD  3.0
#define RA_HIGH_CONFIDENCE_SIGMA    4.0
#define RA_CRITICAL_SIGMA           5.0
#define RA_MAD_CONSTANT             0.6745

/* 严重度 sigma 映射 (SS AD_SEVERITY_*_SIGMA) */
#define RA_SEVERITY_LOW_SIGMA       2.0
#define RA_SEVERITY_MEDIUM_SIGMA    3.0
#define RA_SEVERITY_HIGH_SIGMA      4.0
#define RA_SEVERITY_CRITICAL_SIGMA  5.0

/**************************************************/
/*               速率记录                           */
/**************************************************/

typedef struct _RA_PROC_RATE_RECORD {
    GUID                ProcessNodeId;      /* 进程节点 GUID */
    volatile LONG64     WindowStart;        /* 当前窗口起始时间 */
    volatile LONG       Counts[12];         /* 各操作类型的计数 */
                                            /* [0..6] 索引 = RA_METRIC_TYPE (统一维度, 2026-08-05) */
                                            /*   [0] 进程创建 (RA_METRIC_PROC_CREATE) */
                                            /*   [1] 线程操作 (RA_METRIC_THREAD) */
                                            /*   [2] 文件操作 (RA_METRIC_FILE) */
                                            /*   [3] 注册表操作 (RA_METRIC_REG) */
                                            /*   [4] 网络操作 (RA_METRIC_NET) */
                                            /*   [5] 内存操作 (RA_METRIC_MEM) */
                                            /*   [6] 其他 (RA_METRIC_CUSTOM) */
                                            /* [7..11] 预留 */
} RA_PROC_RATE_RECORD, *PRA_PROC_RATE_RECORD;

/**************************************************/
/*               速率异常阈值配置                    */
/**************************************************/

#define RA_SLOT_RMT_THREAD      0
#define RA_SLOT_PROC_OPEN       1
#define RA_SLOT_MEM_ALLOC       2
#define RA_SLOT_MEM_WRITE       3
#define RA_SLOT_MEM_PROTECT     4
#define RA_SLOT_MEM_READ        5
#define RA_SLOT_COUNT           6       /* 历史槽位数 (已废弃, 统一到 RA_METRIC_TYPE) */

/*
 * 两级阈值:
 *   WarningCount  — 超过此值 → 50 分
 *   CriticalCount — 超过此值 → 90 分
 * 介于两者之间 → 线性插值
 */
typedef struct _RA_RATE_THRESHOLD {
    ULONG   WarningCount;       /* 10s 窗口内正常上限 */
    ULONG   CriticalCount;      /* 明显异常上限 */
} RA_RATE_THRESHOLD;

/**************************************************/
/*               统计基线指标类型                    */
/*   对齐 SS AD_METRIC_TYPE (11 → wkd 事件分类)     */
/**************************************************/

typedef enum _RA_METRIC_TYPE {
    RA_METRIC_PROC_CREATE   = 0,    /* 0x10 进程段: Create/Open   */
    RA_METRIC_THREAD,               /* 0x20 线程段: Create/RemoteThread/QueueApc/Suspend/Resume/SetContext */
    RA_METRIC_FILE,                 /* 0x30 文件段: Create/Write/Delete/ImageLoad(DLL) */
    RA_METRIC_REG,                  /* 0x40 注册表段: SetValue/DeleteValue/CreateKey */
    RA_METRIC_NET,                  /* 0x50 网络段: Connect/Listen */
    RA_METRIC_MEM,                  /* 0x60 内存段: Allocate/Protect/Write/Read/Map/Unmap */
    RA_METRIC_CUSTOM,               /* 其他 (0x70 syscall / 0x90 heartbeat) */

    /* ── 无事件源槽位 (SS 11 metric 保留, 标注死码: wkd 无对应事件) ── */
    RA_METRIC_CPU_USAGE,            /* ※ 死码: agent 无 CPU 采样路径 */
    RA_METRIC_HANDLE_COUNT,         /* ※ 死码: 无句柄事件 */
    RA_METRIC_PRIVILEGE_USE,        /* ※ 死码: 无特权事件 */

    RA_METRIC_MaxValue = RA_METRIC_PRIVILEGE_USE
} RA_METRIC_TYPE;

#define RA_METRIC_COUNT     (RA_METRIC_MaxValue + 1)      /* 10 槽 (含 3 死码) */
#define RA_METRIC_VALID     7                             /* 前 7 个有事件源 */

/**************************************************/
/*               统计基线 (滑动窗口)                 */
/*   对齐 SS AD_BASELINE_INTERNAL                  */
/**************************************************/

typedef struct _RA_BASELINE {
    RA_METRIC_TYPE  Type;
    DOUBLE          Mean;
    DOUBLE          StandardDeviation;
    DOUBLE          Min;
    DOUBLE          Max;
    ULONG           SampleCount;
    DOUBLE          Samples[RA_BASELINE_SAMPLES];  /* 环形缓冲 */
    ULONG           CurrentIndex;
    BOOLEAN         IsFull;
    LARGE_INTEGER   LastUpdated;
} RA_BASELINE, *PRA_BASELINE;

/* 基线统计快照 (对齐 SS AD_BASELINE_INFO, 供 RaGetBaseline 查询) */
typedef struct _RA_BASELINE_INFO {
    RA_METRIC_TYPE  Type;
    DOUBLE          Mean;
    DOUBLE          StandardDeviation;
    DOUBLE          Min;
    DOUBLE          Max;
    ULONG           SampleCount;
    BOOLEAN         IsFull;
    LARGE_INTEGER   LastUpdated;
} RA_BASELINE_INFO, *PRA_BASELINE_INFO;

/**************************************************/
/*               进程基线记录                       */
/*   对齐 SS AD_PROCESS_BASELINE (GUID 替代 PID)   */
/**************************************************/

typedef struct _RA_PROCESS_BASELINE {
    GUID                ProcessNodeId;
    WCHAR               ProcessName[RA_MAX_PROCESS_NAME_CCH]; /* ※保留字段: 进程名由 WKD_PROCESS.ImageFileName 提供, 统计模块经 NodeId 解析不填充 */
    LARGE_INTEGER       CreateTime;
    LARGE_INTEGER       LastActivityTime;

    RA_BASELINE         Baselines[RA_METRIC_COUNT];

    /* 双 EMA (※死代码: SS 原实现只更新未消费) */
    DOUBLE              EMA[RA_METRIC_COUNT];
    DOUBLE              EMAFast[RA_METRIC_COUNT];
    BOOLEAN             EMAInitialized[RA_METRIC_COUNT];

    volatile LONG       RefCount;           /* 1 = 列表引用; >1 = 有活动使用 */
    LIST_ENTRY          ListEntry;          /* 全局基线链表 (TTL 遍历) */
    LIST_ENTRY          HashEntry;          /* 哈希桶链 */
} RA_PROCESS_BASELINE, *PRA_PROCESS_BASELINE;

/**************************************************/
/*               异常记录                          */
/*   对齐 SS AD_ANOMALY_INFO                       */
/**************************************************/

typedef struct _RA_ANOMALY_INFO {
    GUID            ProcessNodeId;
    RA_METRIC_TYPE  Metric;
    DOUBLE          ObservedValue;
    DOUBLE          ExpectedValue;
    DOUBLE          DeviationSigmas;
    ULONG           SeverityScore;          /* [0,100] */
    BOOLEAN         IsHighConfidence;
    LARGE_INTEGER   DetectionTime;
} RA_ANOMALY_INFO, *PRA_ANOMALY_INFO;

/* 异常环节点 (LRU 上限 RA_MAX_ANOMALIES) */
typedef struct _RA_ANOMALY {
    RA_ANOMALY_INFO Info;
    LIST_ENTRY      ListEntry;
} RA_ANOMALY, *PRA_ANOMALY;

/**************************************************/
/*               速率分析器                         */
/**************************************************/

typedef struct _IOA_RATE_ANALYZER {
    BOOLEAN             Initialized;
    CRITICAL_SECTION    Lock;
    ULONG               RecordCount;
    RA_PROC_RATE_RECORD Records[RA_MAX_PROCESS_COUNT];
    volatile LONG64     TotalFeedbacks;
    /*
     * 新增: 速率异常阈值表 (可通过 RaSetRateThresholds 运行时调整)
     * 默认值在 RaInitialize 中设置
     */
    RA_RATE_THRESHOLD   Thresholds[RA_METRIC_VALID];

    /* ── 统计基线 (Z-Score/MAD, SS AnomalyDetector 迁移 2026-08-05) ── */
    DOUBLE              SigmaThreshold;         /* 默认 3.0σ */
    ULONG               MinimumSamples;         /* 默认 10 */
    RA_BASELINE         GlobalBaselines[RA_METRIC_COUNT];  /* 每 metric 单份全局基线 */
    LIST_ENTRY          BaselineBuckets[RA_HASH_BUCKET_COUNT]; /* GUID 哈希桶 */
    LIST_ENTRY          BaselineList;           /* 进程基线全局链表 (TTL 遍历) */
    volatile LONG       BaselineCount;          /* 活跃进程基线数 */
    ULONG               BaselineMaxProcesses;   /* 上限 (默认 RA_MAX_PROCESS_BASELINES) */

    LIST_ENTRY          AnomalyList;            /* 异常环 (LRU) */
    volatile LONG       AnomalyCount;           /* 当前异常数 (上限 RA_MAX_ANOMALIES) */

    /* 统计 (对齐 SS AD_STATISTICS) */
    volatile LONG64     SamplesProcessed;
    volatile LONG64     AnomaliesDetected;
    LARGE_INTEGER       StartTime;

    /* 维护线程 (TTL 淘汰, 对齐 SS AdpCleanupWorkerThread) */
    HANDLE              MaintenanceThread;
    HANDLE              MaintenanceWakeEvent;   /* 自动重置事件, 唤醒维护线程 */
    volatile BOOLEAN    MaintenanceRunning;
    volatile BOOLEAN    CleanupTerminate;
} IOA_RATE_ANALYZER, *PIOA_RATE_ANALYZER;

/**************************************************/
/*               函数声明                           */
/**************************************************/

NTSTATUS RaInitialize(_Out_ PIOA_RATE_ANALYZER* Out);
VOID     RaCleanup(_In_ PIOA_RATE_ANALYZER Analyzer);

/* 每收到一个事件时调用，累加对应操作计数 */
VOID     RaFeedEvent(_In_ PIOA_RATE_ANALYZER Analyzer, _In_ PWKD_EVENT_HEADER Event);

/*
 * 查询指定进程的速率异常评分，返回归一化值 [0,100]。
 * 0  = 正常或未找到记录
 * 100= 超过高危阈值
 *
 * 同步路径安全: 仅读内部记录 + 持锁，不触发任何 I/O。
 * 供 Tier1 信号采集器 (IoaCollectSignals) 调用。
 */
ULONG    RaGetRateScore(_In_ PIOA_RATE_ANALYZER Analyzer, _In_ GUID ProcessNodeId);

/*
 * 运行时调整阈值 (可选)。
 * 传入 NULL 恢复默认值。
 */
VOID     RaSetRateThresholds(_In_ PIOA_RATE_ANALYZER Analyzer,
                             _In_opt_ const RA_RATE_THRESHOLD* Thresholds);

/* 检查进程是否触发速率告警（当前返回 FALSE，留作后续实现） */
BOOLEAN  RaIsRateAlert(_In_ PIOA_RATE_ANALYZER Analyzer, _In_ GUID ProcessNodeId);

/*
 * ─────────────────────────────────────────────────────────
 * 统计基线异常检测 API (SS AnomalyDetector 迁移)
 * ─────────────────────────────────────────────────────────
 */

/* 事件类型 → 统计基线指标 (对齐 SS BepProcessSingleEvent 步骤⑦ metric 映射) */
RA_METRIC_TYPE RaMapEventTypeToMetric(_In_ WKD_EVENT_TYPE EventType);

/*
 * RaCheckForAnomaly — 检测+记录 (对齐 SS AdCheckForAnomaly)。
 * 观测值 = 当前 10s 窗口内该指标的事件计数 (RA_PROC_RATE_RECORD::Counts)。
 * 判定异常(≥2σ)的样本不写入基线 (防驯化)。
 * IRQL: PASSIVE (用户态)
 */
NTSTATUS RaCheckForAnomaly(
    _In_  PIOA_RATE_ANALYZER Analyzer,
    _In_  GUID               ProcessNodeId,
    _In_  RA_METRIC_TYPE     Metric,
    _Out_ PBOOLEAN           IsAnomaly,
    _Out_opt_ PRA_ANOMALY_INFO AnomalyInfo
    );

/* 查询进程当前统计异常分 [0,100] (供阶段6 max 提升 / PolicyAnalyze) */
ULONG    RaGetAnomalyScore(_In_ PIOA_RATE_ANALYZER Analyzer, _In_ GUID ProcessNodeId);

/* 周期维护: 进程基线 TTL 淘汰 + 异常环清理 (对齐 SS AdpCleanupWorkerThread) */
VOID     RaMaintenance(_In_ PIOA_RATE_ANALYZER Analyzer);

/* 运行时调整 sigma 阈值 (对齐 SS AdSetThreshold, [1.5, 6.0]) */
VOID     RaSetSigmaThreshold(_In_ PIOA_RATE_ANALYZER Analyzer, _In_ DOUBLE Sigma);

/* 统计快照 (对齐 SS AdGetStatistics, 供调试 printf) */
VOID     RaGetAnomalyStats(
    _In_  PIOA_RATE_ANALYZER Analyzer,
    _Out_opt_ PLONG64        SamplesProcessed,
    _Out_opt_ PLONG64        AnomaliesDetected,
    _Out_opt_ PLONG          BaselineCount,
    _Out_opt_ PLONG          AnomalyCount
    );

/* ── 对齐 SS 公开 API 面补充 (无消费方, 死代码; 供未来调试/画像/UI 查询) ── */

/*
 * RaRecordSample — 仅记录样本 (对齐 SS AdRecordSample)。
 * ※死代码: 检测+记录已由 RaCheckForAnomaly 合并 (全局+进程基线双写),
 *   本函数供未来"纯学习模式" (新进程静默学习不告警) 接入。
 */
NTSTATUS RaRecordSample(
    _In_ PIOA_RATE_ANALYZER Analyzer,
    _In_ GUID               ProcessNodeId,
    _In_ RA_METRIC_TYPE     Metric,
    _In_ DOUBLE             Value
    );

/*
 * RaGetRecentAnomalies — 时间窗口查询异常环 (对齐 SS AdGetRecentAnomalies)。
 * ※死代码: 无消费方 (VerdictEngine 活跃威胁表已覆盖告警查询),
 *   供未来 UI/调试按时间回溯统计异常历史。
 */
NTSTATUS RaGetRecentAnomalies(
    _In_  PIOA_RATE_ANALYZER Analyzer,
    _In_  ULONG              MaxAgeSeconds,
    _Out_writes_to_(MaxCount, *ActualCount) PRA_ANOMALY_INFO AnomalyArray,
    _In_  ULONG              MaxCount,
    _Out_ PULONG             ActualCount
    );

/*
 * RaGetBaseline — 查询基线统计快照 (对齐 SS AdGetBaseline)。
 * ※死代码: 无消费方 (SS AdGetBaseline 仅调试 UI 消费), 供未来进程行为画像。
 */
NTSTATUS RaGetBaseline(
    _In_  PIOA_RATE_ANALYZER Analyzer,
    _In_  GUID               ProcessNodeId,
    _In_  RA_METRIC_TYPE     Metric,
    _Out_ PRA_BASELINE_INFO  BaselineInfo
    );

/*
 * RaAllocStatAlert — 统计异常告警构造 (单块堆分配, 含字符串缓冲)。
 * 对齐 VerdictEngine_AllocPersistAlert 分配语义, 满足持久化队列
 * UtHeapFree(Data) 整体释放; 调用方转移所有权。
 * 由 IoaObserve 阶段6 在严重度 ≥ Medium 时调用, 经 PersistType_Alert 入队。
 */
PIOA_ALERT RaAllocStatAlert(
    _In_ GUID             SuspectNodeId,
    _In_ PRA_ANOMALY_INFO Info
    );
