/**************************************************/
/*  WkDefender Agent — 时序逃逸检测引擎             */
/*  AntiEvasio / TimeBasedEvasionDetector          */
/*                                                  */
/*  迁移自 ShadowStrike TimeBasedEvasionDetector    */
/*  (.hpp 1778行 + .cpp 2676行)。纯 C 实现。        */
/*                                                  */
/*  检测类别（MITRE ATT&CK T1497.003 时序逃逸）：   */
/*    1. RDTSC/RDTSCP 滥用                          */
/*       - 高频 RDTSC（VM/沙箱探测）                */
/*       - RDTSC delta 校验（hypervisor 开销）      */
/*       - RDTSCP 串行时序                          */
/*       - RDTSC+CPUID 组合（序列化探测）           */
/*    2. 睡眠逃避                                   */
/*       - Sleep bombing（超时沙箱分析窗口）        */
/*       - 睡眠加速检测（沙箱快进）                 */
/*       - 睡眠碎片化（规避加速检测）               */
/*    3. API 时序交叉校验（GetTickCount/QPC/时间）  */
/*    4. NTP/网络时间校验（外部时间源验证）         */
/*    5. 硬件定时器操作（NtSetTimerResolution 等）  */
/*    6. 多技术关联（Multi-Technique）与威胁评分    */
/*                                                  */
/*  与源架构差异（纯 C 化决策）：                   */
/*    - PhantomDisassembler → 字节模式扫描          */
/*    - PEParser           → 内联 PE 导入解析      */
/*    - asm 时序函数       → 全部省略（零调用）     */
/*    - ThreadPool/异步    → 省略（仅同步分析）     */
/*    - std::thread/CV     → CreateThread + 事件    */
/*    - std::function 回调 → 函数指针槽位数组       */
/*    - std::vector/map    → 固定上限数组           */
/*    - std::chrono        → GetTickCount64 毫秒    */
/*                                                  */
/*  编码：UTF-8 with BOM（铁律）                    */
/**************************************************/

#pragma once

#ifndef _WIN32
#error "此模块仅支持 Windows 平台"
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

/**************************************************/
/*          常量                                   */
/**************************************************/

/* --- 结构与数组上限（压缩自源 vector/无上限容器） --- */

/* 最大同时监控进程数（源 10000，压缩以控制内存） */
#define TED_MAX_MONITORED_PROCESSES      128

/* 每进程最大事件缓冲数（源 50000，压缩；事件记录 64B） */
#define TED_MAX_EVENTS_PER_PROCESS       512

/* 单结果最大发现数（源 vector 无上限；Check* 链条实际上限 12，
   16 为下限裁剪：TED_RESULT 体积大，缓存放大效应需控制） */
#define TED_MAX_RESULT_FINDINGS          16

/* 单结果最大摘要消息数 */
#define TED_MAX_DETAILS                  16

/* 最大 MITRE 技术 ID 数 */
#define TED_MAX_MITRE_IDS                4

/* 结果缓存最大条目数（源 1000，压缩） */
#define TED_MAX_CACHE_ENTRIES            128

/* 缓存淘汰批量（满时一次性移除的最旧条目数） */
#define TED_CACHE_EVICT_COUNT            16

/* 回调槽位数 */
#define TED_MAX_CALLBACKS                16
#define TED_MAX_EVENT_CALLBACKS          16

/* 睡眠 API / NTP 服务器 / HTTP 主机表上限 */
#define TED_MAX_SLEEP_APIS               8
#define TED_MAX_NTP_SERVERS              8
#define TED_MAX_HTTP_HOSTS               8

/* 事件类型总数（DetectedTypes 位图）/统计桶 */
#define TED_TYPE_COUNT                   256

/* --- 字符串长度上限 --- */

#define TED_MAX_PROCESS_NAME             256
#define TED_MAX_PATH                     512
#define TED_MAX_COMMAND_LINE             1024    /* 源无上限，压缩 */
#define TED_MAX_DESC                     256
#define TED_MAX_TECH_DETAILS             512
#define TED_MAX_ERROR                    256
#define TED_MAX_MITRE_STR                16
#define TED_MAX_IMPORT_NAME              128
#define TED_MAX_DLL_NAME                 128
#define TED_MAX_HOSTNAME                 64

/* --- 代码扫描限制 --- */

/* 最大代码扫描字节数（主模块 1MB 以内） */
#define TED_MAX_CODE_SCAN_SIZE           (1024 * 1024)

/* 最大指令扫描数（模式扫描仍保留计数上限） */
#define TED_MAX_INSTRUCTIONS_PER_SCAN    10000

/* RDTSC+CPUID 组合的最大字节距离 */
#define TED_RDTSC_CPUID_MAX_DISTANCE     20

/* RDTSC 高频判定最小计数（源 100；降低误报后定值） */
#define TED_MIN_RDTSC_FOR_SUSPICION      100

/* --- 阈值常量（对齐源 TimingConstants） --- */

#define TED_DEFAULT_SAMPLE_INTERVAL_MS   100
#define TED_MIN_SAMPLE_INTERVAL_MS       10
#define TED_MAX_SAMPLE_INTERVAL_MS       60000

#define TED_RDTSC_HIGH_FREQUENCY_THRESHOLD   10000ULL
#define TED_RDTSC_DELTA_VM_THRESHOLD_NS      1000ULL
#define TED_SLEEP_EVASION_THRESHOLD_MS       60000ULL  /* 1 分钟 */
#define TED_SLEEP_ACCELERATION_RATIO         0.5
#define TED_MIN_SLEEP_FRAGMENTS              10
#define TED_TIME_DRIFT_THRESHOLD_SECONDS     60
#define TED_TICKCOUNT_ANOMALY_PERCENT        10.0
#define TED_QPC_ANOMALY_PERCENT              5.0

#define TED_MAX_CONFIDENCE_SCORE             100.0f
#define TED_MIN_REPORTABLE_CONFIDENCE        10.0f
#define TED_RESULT_CACHE_TTL_MS              (5 * 60 * 1000)     /* 5 分钟 */
#define TED_HISTORY_RETENTION_MS             (24 * 60 * 60 * 1000)

/* --- 内部判定阈值（源 cpp 内部常量/修复值） --- */

/* 回调 ID 起始值 */
#define TED_CALLBACK_ID_START                1000

/* Sleep bombing：睡眠 API 数 + 运行时调用数组合 */
#define TED_SLEEP_BOMBING_CALL_THRESHOLD     50
#define TED_SLEEP_BOMBING_DURATION_MS        30000

/* QuickScan：时序 API 导入数阈值（源 Issue#8 从 4 提至 8） */
#define TED_QUICKSCAN_TIMING_API_THRESHOLD   8

/* 高 GetTickCount / 高 QPC 导入阈值（源 Issue#8 防误报提阈值） */
#define TED_HIGH_TICKCOUNT_IMPORT_THRESHOLD  15
#define TED_HIGH_QPC_IMPORT_THRESHOLD        10

/* 反调试：QPC 调用数 + 交叉校验组合阈值 */
#define TED_ANTIDEBUG_QPC_CALL_THRESHOLD     5

/* 威胁评分归一化除数（严重度权重上限） */
#define TED_THREAT_SCORE_DIVISOR             4.0f
#define TED_THREAT_EVASIVE_MIN_SCORE         20.0f

/* 缓存 TTL 默认值（毫秒） */
#define TED_DEFAULT_CACHE_TTL_MS             TED_RESULT_CACHE_TTL_MS

/**************************************************/
/*          枚举                                   */
/*  对齐源 TimingEvasionType（T1497.003 组）       */
/*  分组：RDTSC(1-19) Sleep(20-39) API(40-59)     */
/*        NTP(60-79) 硬件(80-99) 侧信道(100-119)  */
/*        组合/高级(120-139)                       */
/**************************************************/

typedef enum _TED_EVASION_TYPE {
    TED_TYPE_NONE = 0,

    /* RDTSC 技术 (1-19) */
    TED_TYPE_RDTSC_HIGH_FREQUENCY       = 1,
    TED_TYPE_RDTSC_DELTA_CHECK          = 2,
    TED_TYPE_RDTSCP_USAGE               = 3,
    TED_TYPE_RDTSC_CPUID_COMBO          = 4,
    TED_TYPE_TSC_FREQUENCY_MEASUREMENT  = 5,

    /* 睡眠技术 (20-39) */
    TED_TYPE_SLEEP_BOMBING              = 20,
    TED_TYPE_SLEEP_ACCELERATION         = 21,
    TED_TYPE_SLEEP_FRAGMENTATION        = 22,
    TED_TYPE_NT_DELAY_EXECUTION_ABUSE   = 23,
    TED_TYPE_SLEEPEX_ALERTABLE          = 24,
    TED_TYPE_WAITFOR_SINGLE_OBJECT_DELAY = 25,
    TED_TYPE_MSGWAIT_DELAY              = 26,
    TED_TYPE_WAITABLE_TIMER_DELAY       = 27,

    /* API 时序技术 (40-59) */
    TED_TYPE_GETTICKCOUNT_DELTA         = 40,
    TED_TYPE_QPC_ANOMALY                = 41,
    TED_TYPE_SYSTEM_TIME_CHECK          = 42,
    TED_TYPE_TIMEGETTIME_CHECK          = 43,
    TED_TYPE_TIMING_API_CROSS_CHECK     = 44,
    TED_TYPE_PRECISE_TIME_CHECK         = 45,

    /* NTP/网络时间 (60-79) */
    TED_TYPE_NTP_QUERY                  = 60,
    TED_TYPE_EXTERNAL_TIME_VALIDATION   = 61,
    TED_TYPE_HTTP_DATE_CHECK            = 62,
    TED_TYPE_TIMEZONE_ANOMALY           = 63,

    /* 硬件定时器 (80-99) */
    TED_TYPE_HPET_ACCESS                = 80,
    TED_TYPE_ACPI_PM_TIMER              = 81,
    TED_TYPE_HARDWARE_TIMER_DIRECT      = 82,
    TED_TYPE_INTERRUPT_TIMING           = 83,

    /* 侧信道时序 (100-119) */
    TED_TYPE_INSTRUCTION_TIMING         = 100,
    TED_TYPE_CACHE_TIMING               = 101,
    TED_TYPE_BRANCH_PREDICTION_TIMING   = 102,
    TED_TYPE_MEMORY_ACCESS_TIMING       = 103,

    /* 组合/高级 (120-139) */
    TED_TYPE_MULTI_TECHNIQUE            = 120,
    TED_TYPE_ADAPTIVE_TIMING            = 121,
    TED_TYPE_TIME_LOCKED_PAYLOAD        = 122,
    TED_TYPE_TIMING_ANTI_DEBUG          = 123,

    /* 保留/未知 */
    TED_TYPE_RESERVED                   = 254,
    TED_TYPE_UNKNOWN                    = 255
} TED_EVASION_TYPE;

/* 严重度（对齐源 TimingEvasionSeverity） */
typedef enum _TED_SEVERITY {
    TED_SEVERITY_INFO      = 0,
    TED_SEVERITY_LOW       = 25,
    TED_SEVERITY_MEDIUM    = 50,
    TED_SEVERITY_HIGH      = 75,
    TED_SEVERITY_CRITICAL  = 100
} TED_SEVERITY;

/* 检测方法（对齐源 TimingDetectionMethod） */
typedef enum _TED_DETECTION_METHOD {
    TED_METHOD_UNKNOWN                = 0,
    TED_METHOD_STATIC_ANALYSIS        = 1,   /* 静态代码/导入分析 */
    TED_METHOD_DYNAMIC_MONITORING     = 2,   /* 动态运行时监控 */
    TED_METHOD_API_HOOKING            = 3,   /* API 挂钩/拦截 */
    TED_METHOD_HARDWARE_COUNTERS      = 4,   /* 硬件性能计数器 */
    TED_METHOD_KERNEL_INSTRUMENTATION = 5,   /* 内核驱动插桩 */
    TED_METHOD_HYPERVISOR_MONITORING  = 6,   /* 虚拟化监控 */
    TED_METHOD_ETW_TRACING            = 7,   /* ETW 事件追踪 */
    TED_METHOD_BEHAVIORAL_HEURISTICS  = 8,   /* 行为启发式 */
    TED_METHOD_ML_CLASSIFICATION      = 9    /* 机器学习分类 */
} TED_DETECTION_METHOD;

/* 监控状态（对齐源 MonitoringState） */
typedef enum _TED_MONITORING_STATE {
    TED_MON_STATE_INACTIVE   = 0,   /* 未监控 */
    TED_MON_STATE_ACTIVE     = 1,   /* 监控中 */
    TED_MON_STATE_PAUSED     = 2,   /* 已暂停 */
    TED_MON_STATE_COMPLETED  = 3,   /* 已完成（进程退出） */
    TED_MON_STATE_FAILED     = 4    /* 失败（拒绝访问等） */
} TED_MONITORING_STATE;

/**************************************************/
/*          数据结构                               */
/**************************************************/

/*
 * 单一时序事件记录（对齐源 TimingEventRecord，64 字节缓存行对齐）。
 * 时间戳统一使用 GetTickCount64() 毫秒值（跨重启语义无需日历时间）。
 */
typedef struct _TED_EVENT_RECORD {
    ULONGLONG TimestampMs;          /* 事件发生时间（毫秒） */
    ULONG     ProcessId;            /* 进程 ID */
    ULONG     ThreadId;             /* 线程 ID */
    UINT8     EventType;            /* TED_EVASION_TYPE */
    UINT8     DetectionMethod;      /* TED_DETECTION_METHOD */
    UINT8     Reserved[6];          /* 对齐填充 */
    ULONGLONG TimingValue;          /* 原始时序值（语义取决于 EventType） */
    ULONGLONG ExpectedValue;        /* 期望时序值（比较用） */
    LONGLONG  Deviation;            /* 偏离差值 */
    ULONG     CallCount;            /* 调用计数（频率分析） */
    UINT8     Padding[12];          /* 补齐到 64 字节 */
} TED_EVENT_RECORD;                 /* sizeof == 64 */

/*
 * 单一发现（对齐源 TimingEvasionFinding；省略源从未填充的
 * relatedEvents/evidence/involvedThreads/observedAPICalls）。
 */
typedef struct _TED_FINDING {
    UINT8       Type;               /* TED_EVASION_TYPE */
    UINT8       Severity;           /* TED_SEVERITY */
    UINT8       DetectionMethod;    /* TED_DETECTION_METHOD */
    UINT8       Reserved0;
    FLOAT       Confidence;         /* 置信度 0-100 */
    ULONGLONG   DetectionTimeMs;    /* 检测时间（毫秒） */
    CHAR        MitreId[TED_MAX_MITRE_STR];         /* MITRE 技术 ID */
    WCHAR       Description[TED_MAX_DESC];          /* 人读描述 */
    WCHAR       TechnicalDetails[TED_MAX_TECH_DETAILS]; /* 分析详情 */
} TED_FINDING;

/*
 * 时序逃逸分析综合结果（对齐源 TimingEvasionResult）。
 * ProcessName/Path/CommandLine 为宽字符，DetectedTypes 为 256 位图。
 */
typedef struct _TED_RESULT {
    BOOLEAN     IsEvasive;
    UINT8       Reserved0[3];
    FLOAT       Confidence;                          /* 综合置信度 0-100 */
    UINT8       Severity;                            /* 最高严重度 */
    UINT8       Reserved1[3];
    FLOAT       ThreatScore;                         /* 复合威胁评分 0-100 */
    ULONG       ProcessId;
    WCHAR       ProcessName[TED_MAX_PROCESS_NAME];
    WCHAR       ProcessPath[TED_MAX_PATH];
    WCHAR       CommandLine[TED_MAX_COMMAND_LINE];
    ULONG       ParentProcessId;
    WCHAR       ParentProcessName[TED_MAX_PROCESS_NAME];

    TED_FINDING Findings[TED_MAX_RESULT_FINDINGS];
    ULONG       FindingCount;
    WCHAR       Details[TED_MAX_DETAILS][TED_MAX_DESC];
    ULONG       DetailCount;
    UINT8       PrimaryEvasionType;                  /* TED_EVASION_TYPE */
    UINT8       DetectedTypes[TED_TYPE_COUNT / 8];   /* 256 位位图 */
    CHAR        MitreIds[TED_MAX_MITRE_IDS][TED_MAX_MITRE_STR];
    ULONG       MitreIdCount;
    CHAR        MitreTactic[TED_MAX_MITRE_STR];      /* 默认 TA0005 */

    ULONGLONG   RdtscCallCount;
    ULONGLONG   AvgRdtscDeltaNs;
    ULONGLONG   MaxRdtscDeltaNs;
    ULONGLONG   TotalSleepDurationMs;
    ULONGLONG   ActualSleepDurationMs;
    ULONG       SleepCallCount;
    ULONG       GetTickCountCalls;
    ULONG       QpcCallCount;
    ULONG       NtpQueryCount;

    ULONGLONG   AnalysisStartTimeMs;
    ULONGLONG   AnalysisEndTimeMs;
    ULONGLONG   AnalysisDurationMs;
    ULONGLONG   EventsAnalyzed;
    WCHAR       ErrorMessage[TED_MAX_ERROR];
    BOOLEAN     AnalysisComplete;
    UINT8       Reserved2[3];
} TED_RESULT;

/*
 * 检测配置（对齐源 TimingDetectorConfig）。
 * 时间字段统一毫秒；时间戳比较用 GetTickCount64 单调语义。
 */
typedef struct _TED_CONFIG {
    /* 常规 */
    BOOLEAN     Enabled;                    /* 总开关 */
    BOOLEAN     ContinuousMonitoring;       /* 持续监控模式 */
    UINT8       Reserved0[2];
    ULONG       SampleIntervalMs;           /* 采样间隔（毫秒） */
    ULONG       MaxMonitoredProcesses;      /* 最大监控进程数 */
    ULONG       MaxEventsPerProcess;        /* 每进程最大事件数 */

    /* 灵敏度 */
    ULONGLONG   RdtscFrequencyThreshold;    /* RDTSC 高频阈值（次/秒） */
    ULONGLONG   RdtscDeltaThresholdNs;      /* RDTSC delta 阈值（纳秒） */
    ULONGLONG   SleepEvasionThresholdMs;    /* 睡眠逃避时长阈值（毫秒） */
    DOUBLE      SleepAccelerationThreshold; /* 睡眠加速比阈值 */
    ULONG       MinSleepFragments;          /* 碎片化检测最小片段数 */
    LONGLONG    TimeDriftThresholdSeconds;  /* 时间漂移阈值（秒） */
    DOUBLE      TickCountAnomalyPercent;    /* GetTickCount 异常百分比 */
    DOUBLE      QpcAnomalyPercent;          /* QPC 异常百分比 */

    /* 检测特性 */
    BOOLEAN     DetectRDTSC;
    BOOLEAN     DetectSleepEvasion;
    BOOLEAN     DetectAPITiming;
    BOOLEAN     DetectNTPEvasion;
    BOOLEAN     DetectHardwareTimers;
    BOOLEAN     DetectSideChannels;         /* 代价高，默认关闭 */
    BOOLEAN     EnableCorrelation;

    /* 报告 */
    FLOAT       MinReportableConfidence;    /* 最低报告置信度 */
    BOOLEAN     IncludeEventDetails;
    BOOLEAN     IncludeEvidence;            /* 可能很大 */
    BOOLEAN     EnableMitreMapping;

    /* 缓存 */
    BOOLEAN     EnableResultCache;
    UINT8       Reserved1[3];
    ULONG       ResultCacheTTLMs;           /* 结果缓存 TTL（毫秒） */
} TED_CONFIG;

/* 检测统计（对齐源 TimingDetectorStats；Interlocked 访问） */
typedef struct _TED_STATS {
    volatile LONGLONG TotalProcessesAnalyzed;
    volatile LONGLONG TotalEventsProcessed;
    volatile LONGLONG TotalEvasionsDetected;
    volatile LONGLONG DetectionsByType[TED_TYPE_COUNT];
    volatile LONGLONG CurrentlyMonitoring;
    volatile LONGLONG CacheHits;
    volatile LONGLONG CacheMisses;
    volatile LONGLONG AnalysisErrors;
    volatile LONGLONG AvgAnalysisDurationUs;    /* EMA 平滑值 */
    volatile LONGLONG LastAnalysisTimestamp;    /* 秒级 Unix 时间戳 */
} TED_STATS;

/* 睡眠行为详细分析（对齐源 SleepAnalysis；sleepDurations[] 源未填充已省略） */
typedef struct _TED_SLEEP_ANALYSIS {
    ULONG       ProcessId;
    ULONG       ThreadId;
    ULONG       SleepCallCount;
    ULONGLONG   TotalRequestedDurationMs;
    ULONGLONG   TotalActualDurationMs;
    ULONGLONG   AvgRequestedDurationMs;
    ULONGLONG   AvgActualDurationMs;
    ULONGLONG   MaxRequestedDurationMs;
    DOUBLE      AccelerationRatio;          /* 实际/请求 比值 */
    ULONG       FragmentedSleepCount;
    ULONGLONG   AvgFragmentDurationMs;
    BOOLEAN     SleepBombingDetected;
    BOOLEAN     AccelerationDetected;
    BOOLEAN     FragmentationDetected;
    UINT8       Reserved0;
    FLOAT       Confidence;
    WCHAR       SleepAPIsUsed[TED_MAX_SLEEP_APIS][TED_MAX_IMPORT_NAME];
    ULONG       SleepAPICount;
} TED_SLEEP_ANALYSIS;

/* RDTSC 分析结果（对齐源 RDTSCAnalysis） */
typedef struct _TED_RDTSC_ANALYSIS {
    ULONG       ProcessId;
    ULONGLONG   RdtscCount;
    ULONGLONG   RdtscpCount;
    ULONGLONG   RdtscCpuidComboCount;
    ULONGLONG   AvgDeltaNs;
    ULONGLONG   MinDeltaNs;
    ULONGLONG   MaxDeltaNs;
    DOUBLE      DeltaStdDev;
    DOUBLE      CallsPerSecond;
    BOOLEAN     HighFrequencyDetected;
    BOOLEAN     DeltaCheckDetected;
    BOOLEAN     FrequencyMeasurementDetected;
    UINT8       Reserved0;
    FLOAT       Confidence;
    ULONGLONG   ObservationDurationMs;
} TED_RDTSC_ANALYSIS;

/* API 时序分析结果（对齐源 APITimingAnalysis） */
typedef struct _TED_API_TIMING_ANALYSIS {
    ULONG       ProcessId;
    ULONG       GetTickCountCalls;
    ULONG       QpcCalls;
    ULONG       SystemTimeCalls;
    ULONG       TimeGetTimeCalls;
    ULONG       PreciseTimeCalls;
    ULONG       CrossCheckCount;
    ULONGLONG   MaxTickCountDeltaMs;
    ULONGLONG   QpcFrequencyHz;
    ULONGLONG   ExpectedQpcFrequencyHz;
    DOUBLE      QpcFrequencyDeviation;
    BOOLEAN     TickCountAnomalyDetected;
    BOOLEAN     QpcAnomalyDetected;
    BOOLEAN     CrossCheckDetected;
    UINT8       Reserved0;
    FLOAT       Confidence;
} TED_API_TIMING_ANALYSIS;

/* NTP/网络时间分析结果（对齐源 NTPAnalysis） */
typedef struct _TED_NTP_ANALYSIS {
    ULONG       ProcessId;
    ULONG       NtpQueryCount;
    ULONG       HttpTimeCheckCount;
    ULONG       ExternalTimeAPICalls;
    WCHAR       NtpServers[TED_MAX_NTP_SERVERS][TED_MAX_HOSTNAME];
    ULONG       NtpServerCount;
    WCHAR       HttpTimeHosts[TED_MAX_HTTP_HOSTS][TED_MAX_HOSTNAME];
    ULONG       HttpHostCount;
    LONGLONG    DetectedDriftSeconds;
    BOOLEAN     NtpEvasionDetected;
    BOOLEAN     ExternalValidationDetected;
    UINT8       Reserved0[2];
    FLOAT       Confidence;
} TED_NTP_ANALYSIS;

/**************************************************/
/*          回调类型                               */
/**************************************************/

/* 逃避检测结果回调（实时监控通知） */
typedef VOID (*TED_EVASION_CALLBACK)(_In_ const TED_RESULT* Result);

/* 单条时序事件回调（高级监控，事件量大需慎用） */
typedef VOID (*TED_EVENT_CALLBACK)(_In_ const TED_EVENT_RECORD* Event);

/**************************************************/
/*          公共 API                               */
/**************************************************/

/* --- 生命周期与配置 --- */

/*
 * 初始化检测器（默认配置）。可重复调用（后续调用为无操作）。
 * 首次调用前必须初始化；返回 FALSE 表示内部状态异常。
 */
BOOLEAN
TedInitialize(
    _In_opt_ const TED_CONFIG* Config
    );

/* 关闭检测器：停止全部监控、清空缓存与回调、等待监控线程退出。可重复调用。 */
VOID
TedShutdown(
    VOID
    );

BOOLEAN
TedIsInitialized(
    VOID
    );

/* 运行时更新配置（建议先停止监控再更新，部分设置需重启监控生效） */
VOID
TedUpdateConfig(
    _In_ const TED_CONFIG* Config
    );

BOOLEAN
TedGetConfig(
    _Out_ PTED_CONFIG OutConfig
    );

/* --- 配置工厂（对齐源 CreateDefault/HighSensitivity/PerformanceOptimized） --- */

VOID
TedCreateDefaultConfig(
    _Out_ PTED_CONFIG OutConfig
    );

VOID
TedCreateHighSensitivityConfig(
    _Out_ PTED_CONFIG OutConfig
    );

VOID
TedCreatePerformanceOptimizedConfig(
    _Out_ PTED_CONFIG OutConfig
    );

/* --- 单进程分析（同步） --- */

/*
 * 分析目标进程的时序逃避行为。
 * 需要 PROCESS_QUERY_INFORMATION | PROCESS_VM_READ 权限；
 * 为同步操作，完整分析可能耗时数秒。
 * 返回 TRUE 表示分析完成（Result->AnalysisComplete 区分成败）。
 */
BOOLEAN
TedAnalyzeProcess(
    _In_ ULONG ProcessId,
    _Out_ PTED_RESULT Result
    );

/* 快速扫描：主模块时序 API 导入数 > 阈值（8）即判定明显逃避 */
BOOLEAN
TedQuickScanProcess(
    _In_ ULONG ProcessId,
    _Out_ PBOOLEAN Evasive
    );

/* --- 专项分析 --- */

BOOLEAN
TedAnalyzeRDTSC(
    _In_ ULONG ProcessId,
    _Out_ PTED_RDTSC_ANALYSIS Out
    );

BOOLEAN
TedAnalyzeSleep(
    _In_ ULONG ProcessId,
    _Out_ PTED_SLEEP_ANALYSIS Out
    );

BOOLEAN
TedAnalyzeAPITiming(
    _In_ ULONG ProcessId,
    _Out_ PTED_API_TIMING_ANALYSIS Out
    );

BOOLEAN
TedAnalyzeNTP(
    _In_ ULONG ProcessId,
    _Out_ PTED_NTP_ANALYSIS Out
    );

/* 检测睡眠加速（当前为静态模式检测：睡眠加速 + 监控上下文证据） */
BOOLEAN
TedDetectSleepAcceleration(
    _In_ ULONG ProcessId,
    _Out_ PBOOLEAN Detected
    );

/* 检测时序反调试（RDTSC delta 校验 / RDTSC+CPUID / 高 QPC + 交叉校验） */
BOOLEAN
TedDetectTimingAntiDebug(
    _In_ ULONG ProcessId,
    _Out_ PBOOLEAN Detected
    );

/* --- 持续监控 --- */

/* 开始监控一个进程（需先注册回调以获得通知；超限返回 FALSE） */
BOOLEAN
TedStartMonitoring(
    _In_ ULONG ProcessId
    );

VOID
TedStopMonitoring(
    _In_ ULONG ProcessId
    );

VOID
TedStopAllMonitoring(
    VOID
    );

BOOLEAN
TedIsMonitoring(
    _In_ ULONG ProcessId,
    _Out_ PBOOLEAN IsActive
    );

TED_MONITORING_STATE
TedGetMonitoringState(
    _In_ ULONG ProcessId
    );

VOID
TedPauseMonitoring(
    _In_ ULONG ProcessId
    );

VOID
TedResumeMonitoring(
    _In_ ULONG ProcessId
    );

/* 获取当前有监控记录的进程 ID 列表（含 Active/Paused） */
BOOLEAN
TedGetMonitoredProcesses(
    _Out_writes_(Count) PULONG Pids,
    _In_ ULONG Count,
    _Out_ PULONG OutCount
    );

/* --- 回调 --- */

/* 注册逃避检测回调，返回注册 ID（供注销） */
BOOLEAN
TedRegisterCallback(
    _In_ TED_EVASION_CALLBACK Callback,
    _Out_ PULONGLONG OutId
    );

BOOLEAN
TedUnregisterCallback(
    _In_ ULONGLONG CallbackId
    );

BOOLEAN
TedRegisterEventCallback(
    _In_ TED_EVENT_CALLBACK Callback,
    _Out_ PULONGLONG OutId
    );

BOOLEAN
TedUnregisterEventCallback(
    _In_ ULONGLONG CallbackId
    );

/* --- 统计与缓存 --- */

BOOLEAN
TedGetStats(
    _Out_ PTED_STATS OutStats
    );

VOID
TedResetStats(
    VOID
    );

/* 缓存命中率（CacheHits / (CacheHits+CacheMisses)），无样本返回 0.0 */
DOUBLE
TedGetCacheHitRatio(
    _In_ const TED_STATS* Stats
    );

/* 获取缓存结果（校验 TTL，过期视为未命中） */
BOOLEAN
TedGetCachedResult(
    _In_ ULONG ProcessId,
    _Out_ PTED_RESULT OutResult
    );

VOID
TedClearCache(
    VOID
    );

VOID
TedClearCacheForProcess(
    _In_ ULONG ProcessId
    );

/* 获取进程事件历史（MaxEvents=0 表示全部；返回实际条数） */
BOOLEAN
TedGetEventHistory(
    _In_ ULONG ProcessId,
    _In_ ULONG MaxEvents,
    _Out_writes_opt_(MaxEvents) PTED_EVENT_RECORD Out,
    _Out_ PULONG OutCount
    );

/* --- 工具函数（对齐源 inline 工具） --- */

/* 睡眠加速比 = 实际 / 请求（<1.0 表示加速）；请求为 0 返回 1.0 */
DOUBLE
TedCalculateSleepAccelerationRatio(
    _In_ ULONGLONG RequestedMs,
    _In_ ULONGLONG ActualMs
    );

/* 多因子加权置信度合成（0-100）；Weights 可少于 Factors（缺省权重 1.0） */
FLOAT
TedCalculateCombinedConfidence(
    _In_reads_(FactorCount) const FLOAT* Factors,
    _In_ ULONG FactorCount,
    _In_reads_opt_(WeightCount) const FLOAT* Weights,
    _In_ ULONG WeightCount
    );

/* 置信度 → 严重度：>=90 Critical, >=70 High, >=40 Medium, >=15 Low */
UINT8
TedConfidenceToSeverity(
    _In_ FLOAT Confidence
    );

/* 枚举 → 字符串映射 */
PCSTR
TedTypeToString(
    _In_ UINT8 Type
    );

/* 枚举 → MITRE 技术 ID（None→空串；TimingAntiDebug→T1622；其余→T1497.003） */
PCSTR
TedTypeToMitre(
    _In_ UINT8 Type
    );

PCSTR
TedSeverityToString(
    _In_ UINT8 Severity
    );

/**************************************************/
/*          文件尾                                */
/**************************************************/