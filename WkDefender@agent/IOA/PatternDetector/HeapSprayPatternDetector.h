/**************************************************/
/*  WkDefender IOA — 堆喷攻击模式检测器             */
/*                                                  */
/*  迁移自 ShadowStrike HeapSprayDetector           */
/*  (HeapSprayDetector.cpp/.hpp, v3.0.0)            */
/*  功能重实现 (C 重写), 非源码复制。                */
/*                                                  */
/*  能力面 (六大检测能力):                   */
/*    ├─ 经典堆喷检测 (NOP sled / 大块均匀分配 /    */
/*    │    重复模式 / 可预测靶址)                   */
/*    ├─ 香农熵分析 (低熵 NOP 特征 / 高熵加密壳)     */
/*    ├─ shellcode 检测 (12 模式表 + 8 API hash +   */
/*    │    XOR 解码循环, ≥3 指标判壳)               */
/*    ├─ 进程堆扫描 (VirtualQueryEx 提交区遍历,     */
/*    │    单扫描可疑块上限 256, ≥3 块触发事件,     */
/*    │    评分 = 块数×10 + MB + 壳码(+30))         */
/*    ├─ Toolhelp 堆枚举 (异常堆数 ≥4096 再加分)    */
/*    └─ 内核内存告警接入 (OnMemoryAllocation /     */
/*         OnProtectionChange 的 W→X 转换 /         */
/*         ProcessKernelMemoryAlert 统一分发)       */
/*                                                  */
/*  与 SS 源码的对齐/裁剪 (注释就地标注):            */
/*    - 去 JSON 序列化 → 事件结构体直接输出          */
/*    - 去 Meyers 单例/PIMPL → 静态全局 + SRWLOCK    */
/*    - 去监控线程/Start/Stop/Pause/Resume 状态机   */
/*      (Initialize/Shutdown 两态 + GetStatus)      */
/*    - 去 CorrelateWithJITSpray (依赖 JITSpray      */
/*      Detector 跨模块, WkDefender 死代码无配对)    */
/*    - 去 IPCManager/AlertSystem/PatternStore/      */
/*      SignatureStore → 单一事件回调上报            */
/*    - 3 类回调合一为 HSD_DETECTED_CALLBACK         */
/*    - 监控表 unordered_map → 定长数组收敛 (256),  */
/*      每进程分配历史 deque(8192) → 环形 512        */
/*    - SS ExtractSprayPattern 定义但主流程未接线    */
/*      (sprayPattern 恒为 nullopt), 保留实现不接线  */
/*                                                  */
/*  与 DefendTypes.h WKD_HEAP_SPRAY 类型的关系:      */
/*    DefendTypes.h 的 WKD_HEAP_SPRAY_TYPE (9 项)    */
/*    迁移自早期 SS HeapSpray.h 类型层 (2026-08-07), */
/*    消费方为 IoaHeapSprayDetect 聚合; 本模块按     */
/*    HeapSprayDetector.hpp 实际 13 项 SprayTechnique */
/*    自带 HSD 前缀完整枚举, 两者互不干扰。           */
/*                                                  */
/*  接入状态: 独立模块 (死代码), 未挂接 IoaObserve   */
/*  事件流水线。调用方按需调用 HsdScanProcessHeap /   */
/*  HsdAnalyzeMemoryRegion 等分析入口, 或经          */
/*  HsdProcessKernelMemoryAlert 接收内核告警后触发。  */
/**************************************************/

#pragma once

#include "../../DefendTypes.h"

/**************************************************/
/*               容量常量                           */
/*  HeapSprayConstants (同类项中文化注释)。 */
/**************************************************/

#define HSD_VERSION_MAJOR              3
#define HSD_VERSION_MINOR              0
#define HSD_VERSION_PATCH              0

/* 最小/最大喷射块规模 (SS MIN/MAX_SPRAY_BLOCK_SIZE) */
#define HSD_MIN_SPRAY_BLOCK_SIZE       (1024ULL * 1024ULL)                 /* 1MB  */
#define HSD_MAX_SPRAY_BLOCK_SIZE       (64ULL * 1024ULL * 1024ULL)         /* 64MB */

/* 熵阈值 (SS ENTROPY_THRESHOLD_*) */
#define HSD_ENTROPY_THRESHOLD_LOW      1.0                                 /* 低熵 (NOP sled)      */
#define HSD_ENTROPY_THRESHOLD_VERY_LOW 0.5                                 /* 极低熵 (均匀数据)    */
#define HSD_ENTROPY_THRESHOLD_HIGH     7.5                                 /* 高熵 (加密壳)        */

/* 每进程跟踪分配上限. SS MAX_TRACKED_ALLOCATIONS=8192 且 deque 无界增长;
 * C 静态化收敛为 512 环形, 语义 (最近窗口内的分配计数) 不变。 */
#define HSD_TRACKED_ALLOCATIONS_PER_PROCESS  512
/* 监控进程表上限. SS 为 unordered_map 无固定上限 (受 MAX_TRACKED_ALLOCATIONS
 * =8192 保护); C 静态化收敛 256。 */
#define HSD_MAX_MONITORED_PROCESSES    256

/* 熵采样规模 (SS ENTROPY_SAMPLE_SIZE) */
#define HSD_ENTROPY_SAMPLE_SIZE        4096
/* 单次扫描可疑块收集上限 (SS ScanProcessHeap 内 constexpr MAX_SUSPICIOUS_PER_SCAN) */
#define HSD_MAX_SUSPICIOUS_PER_SCAN    256
/* 事件结构内嵌可疑块上限 (SS suspiciousBlocks 为未限 vector, 事件定长化收敛 16) */
#define HSD_MAX_SUSPICIOUS_BLOCKS      16
/* 触发喷射事件的阈值块数 (SS ≥3 块) */
#define HSD_SUSPICIOUS_TRIGGER_COUNT   3
/* 检测历史环形容量 (SS MAX_HISTORY_SIZE) */
#define HSD_MAX_RECENT_DETECTIONS      1000
/* Toolhelp 异常堆数阈值 (SS ScanAllHeaps kAbnormalToolhelpHeapCount) */
#define HSD_ABNORMAL_TOOLHELP_HEAP_COUNT 4096

/* NOP sled 检测最小长度: 通用默认 (SS DetectNopSled 默认 64) 与
 * 技术分类用 (SS IdentifySprayTechnique 用 32) */
#define HSD_MIN_NOP_SLED_LENGTH        64
#define HSD_NOP_SLED_CLASSIFY_MIN      32
/* shellcode 检测最小数据规模 (SS DetectShellcode <16 直接否定) */
#define HSD_MIN_SHELLCODE_SIZE         16
/* 模式提取基础单元 (SS ExtractSprayPattern 取前 64 字节) */
#define HSD_PATTERN_UNIT_SIZE          64
/* 事件内嵌 shellcode 样本上限 */
#define HSD_SHELLCODE_SAMPLE_SIZE      64
/* 事件详情缓冲 */
#define HSD_DETAILS_SIZE               512

/* 配置默认值 (SS HeapSprayDetectorConfiguration 默认构造) */
#define HSD_CONFIG_DEFAULT_SCAN_INTERVAL_MS      500
#define HSD_CONFIG_DEFAULT_MEMORY_PRESSURE       (512ULL * 1024ULL * 1024ULL) /* 512MB */

/**************************************************/
/*               模块状态枚举                       */
/*  ModuleStatus (SPD SpdStatus 同构)。     */
/**************************************************/

typedef enum _HSD_STATUS {
    HsdStatus_Uninitialized = 0,
    HsdStatus_Initializing  = 1,
    HsdStatus_Running       = 2,
    HsdStatus_Paused        = 3,
    HsdStatus_Stopping      = 4,
    HsdStatus_Stopped       = 5,
    HsdStatus_Error         = 6
} HSD_STATUS;

/**************************************************/
/*               Spray 技术枚举                    */
/*  SprayTechnique (0-13)。                 */
/**************************************************/

typedef enum _HSD_SPRAY_TECHNIQUE {
    HsdSpray_Unknown         = 0,    /* 无法判定              */
    HsdSpray_ClassicNopSled  = 1,    /* 传统 NOP sled 喷       */
    HsdSpray_JitSpray        = 2,    /* JIT 编译器滥用         */
    HsdSpray_ArrayBuffer     = 3,    /* HTML5 ArrayBuffer      */
    HsdSpray_TypedArray      = 4,    /* JavaScript TypedArray  */
    HsdSpray_Bstr            = 5,    /* COM BSTR 字符串        */
    HsdSpray_Variant         = 6,    /* COM VARIANT            */
    HsdSpray_DomElement      = 7,    /* DOM 元素喷             */
    HsdSpray_StringSpray     = 8,    /* JS 字符串喷            */
    HsdSpray_FengShui        = 9,    /* 堆风水                 */
    HsdSpray_Plunger         = 10,   /* Plunger 喷             */
    HsdSpray_LookAsideList   = 11,   /* LAL 定向               */
    HsdSpray_SegmentHeap     = 12,   /* 段堆滥用               */
    HsdSpray_LfhBucket       = 13    /* LFH 桶喷               */
} HSD_SPRAY_TECHNIQUE;

/**************************************************/
/*               内存区域类型枚举                   */
/*  MemoryRegionType (0-7)。                */
/**************************************************/

typedef enum _HSD_MEMORY_REGION_TYPE {
    HsdRegion_Unknown       = 0,
    HsdRegion_Heap          = 1,
    HsdRegion_Stack         = 2,
    HsdRegion_Image         = 3,
    HsdRegion_Mapped        = 4,
    HsdRegion_Private       = 5,
    HsdRegion_JitCode       = 6,
    HsdRegion_SharedMemory  = 7
} HSD_MEMORY_REGION_TYPE;

/**************************************************/
/*               分配标志 (位标志)                  */
/*  AllocationFlags (位序一致)。             */
/**************************************************/

#define HSD_ALLOC_FLAG_NONE            0x00000000
#define HSD_ALLOC_FLAG_EXECUTABLE      0x00000001   /* 可执行            */
#define HSD_ALLOC_FLAG_WRITABLE        0x00000002   /* 可写              */
#define HSD_ALLOC_FLAG_READABLE        0x00000004   /* 可读              */
#define HSD_ALLOC_FLAG_LARGE_PAGES     0x00000008   /* 大页              */
#define HSD_ALLOC_FLAG_GUARD           0x00000010   /* guard page        */
#define HSD_ALLOC_FLAG_NO_CACHE        0x00000020   /* 非缓存            */
#define HSD_ALLOC_FLAG_SHARED          0x00000040   /* 共享              */
#define HSD_ALLOC_FLAG_LOW_ENTROPY     0x00000080   /* 低熵              */
#define HSD_ALLOC_FLAG_HIGH_ENTROPY    0x00000100   /* 高熵              */
#define HSD_ALLOC_FLAG_SUSPICIOUS      0x00000200   /* 多指标可疑        */
#define HSD_ALLOC_FLAG_CONFIRMED_SPRAY 0x00000400   /* 确认喷射          */

/* 测试位掩码 (HasFlag) */
#define HSD_HAS_ALLOC_FLAG(Flags, Mask) \
    (((Flags) & (Mask)) != 0)

/**************************************************/
/*               置信度枚举                         */
/*  ConfidenceLevel (SPD SpdConf 同构)。     */
/**************************************************/

typedef enum _HSD_CONFIDENCE {
    HsdConf_Unknown   = 0,
    HsdConf_Low       = 1,
    HsdConf_Medium    = 2,
    HsdConf_High      = 3,
    HsdConf_VeryHigh  = 4,
    HsdConf_Confirmed = 5
} HSD_CONFIDENCE;

/**************************************************/
/*               堆分配信息结构                     */
/*  HeapAllocationInfo。                    */
/*  裁剪: SS heapHandle 字段从未被实现赋值;         */
/*  timestamp 移到事件级 (LARGE_INTEGER)。          */
/**************************************************/

typedef struct _HSD_ALLOCATION_INFO {
    UINT64                  Address;                /* 分配地址              */
    SIZE_T                  Size;                   /* 分配大小 (提交区规模) */
    ULONG                   Protection;             /* 内存保护 (PAGE_*)     */
    HSD_MEMORY_REGION_TYPE  RegionType;             /* 区域类型              */
    ULONG                   Flags;                  /* 分配标志 (HSD_ALLOC_FLAG_*) */
    BOOLEAN                 IsExecutable;           /* 可执行                */
    BOOLEAN                 IsWritable;             /* 可写                  */
    DOUBLE                  Entropy;                /* 香农熵                */
    UCHAR                   DominantByte;           /* 主导字节              */
    DOUBLE                  DominantBytePercent;    /* 主导字节占比 (%)      */
    BOOLEAN                 ContainsShellcode;      /* 含疑似 shellcode      */
    BOOLEAN                 ContainsNopSled;        /* 含疑似 NOP sled       */
} HSD_ALLOCATION_INFO, *PHSD_ALLOCATION_INFO;

/**************************************************/
/*               Spray 模式结构                     */
/*  SprayPatternInfo, 定长化。              */
/*  注意: SS ExtractSprayPattern 定义但从未被主流程 */
/*  接线 (CreateSprayEvent 恒不设置 sprayPattern),   */
/*  本字段/函数保留实现, 默认无效 (HasSprayPattern=  */
/*  FALSE)。                                        */
/**************************************************/

typedef struct _HSD_SPRAY_PATTERN {
    UINT64                  PatternId;              /* 模式 ID (序列)        */
    HSD_SPRAY_TECHNIQUE     Technique;              /* 喷射技术 (未赋值, 恒 Unknown) */
    UCHAR                   PatternBytes[HSD_PATTERN_UNIT_SIZE]; /* 基础模式单元 (前 64B) */
    UINT32                  PatternLength;          /* 模式长度              */
    UINT32                  RepeatCount;            /* 重复次数              */
    UINT64                  TargetAddress;          /* 靶地址 (如有)         */
} HSD_SPRAY_PATTERN, *PHSD_SPRAY_PATTERN;

/**************************************************/
/*               喷射检测事件结构                   */
/*  SprayEvent, 定长化 (vector→定长数组)。   */
/**************************************************/

typedef struct _HSD_DETECTION_EVENT {
    ULONG                   EventId;                /* 自增事件 ID           */
    ULONG                   ProcessId;              /* 进程 ID               */
    WCHAR                   ProcessName[DEF_MAX_IMAGE_NAME];  /* 进程名  */
    WCHAR                   ProcessPath[DEF_MAX_PATH * 2];    /* 进程路径 */
    HSD_SPRAY_TECHNIQUE     Technique;              /* 检测到的喷射技术      */
    UINT64                  TotalSprayedBytes;      /* 喷射总字节            */
    UINT32                  BlockCount;             /* 可疑块总计数 (≤256)   */
    UINT32                  StoredBlockCount;       /* 内嵌块计数 (≤16)      */
    HSD_ALLOCATION_INFO     SuspiciousBlocks[HSD_MAX_SUSPICIOUS_BLOCKS]; /* 内嵌可疑块 */
    HSD_SPRAY_PATTERN       SprayPattern;           /* 喷射模式 (未接线, 恒无效) */
    BOOLEAN                 HasSprayPattern;        /* 模式有效标志          */
    UINT64                  TargetAddress;          /* 靶地址 (如有)         */
    BOOLEAN                 ShellcodeDetected;      /* 检测到 shellcode      */
    UCHAR                   ShellcodeSample[HSD_SHELLCODE_SAMPLE_SIZE]; /* 壳码样本 */
    UINT32                  ShellcodeSampleSize;    /* 壳码样本实际大小      */
    HSD_CONFIDENCE          Confidence;             /* 置信度级别            */
    DOUBLE                  ConfidenceScore;        /* 置信度分数 [0,100]    */
    BOOLEAN                 WasBlocked;             /* 是否已阻断 (调用方处置) */
    BOOLEAN                 ProcessTerminated;      /* 是否已终止 (调用方处置) */
    WCHAR                   Details[HSD_DETAILS_SIZE];    /* 补充详情    */
    LARGE_INTEGER           Timestamp;              /* 检测时间戳            */
} HSD_DETECTION_EVENT, *PHSD_DETECTION_EVENT;

/**************************************************/
/*               进程堆状态结构                     */
/*  ProcessHeapState。                      */
/*  裁剪: SS allocationRate/freeRate/              */
/*  lowEntropyRegionCount 字段从未被实现赋值 (恒 0), */
/*  此处省略。                                      */
/**************************************************/

typedef struct _HSD_HEAP_STATE {
    ULONG                   ProcessId;              /* 进程 ID               */
    UINT32                  HeapCount;              /* SS: MEM_PRIVATE 提交区计数 */
    UINT64                  TotalCommitted;         /* 总已提交              */
    UINT64                  TotalReserved;          /* 总保留                */
    UINT64                  WorkingSetSize;         /* 工作集                */
    UINT64                  PrivateBytes;           /* 私有字节              */
    UINT32                  LargeAllocationCount;   /* 大分配 (≥阈值) 计数   */
    BOOLEAN                 IsUnderPressure;        /* 内存压力              */
    BOOLEAN                 SpraySuspected;         /* 喷射可疑              */
    LARGE_INTEGER           SnapshotTime;           /* 快照时间戳            */
} HSD_HEAP_STATE, *PHSD_HEAP_STATE;

/**************************************************/
/*               配置结构                           */
/*  HeapSprayDetectorConfiguration。         */
/*  注意: SS 中 monitorScriptEngines /             */
/*  blockOnDetection / terminateOnHighConfidence /  */
/*  verboseLogging 仅为配置字段, 实现未消费 (注释   */
/*  就地标注); scanIntervalMs 由已裁剪的监控线程     */
/*  消费, 保留字段以对齐配置面。                    */
/**************************************************/

typedef struct _HSD_CONFIG {
    BOOLEAN                 Enabled;                /* 总开关 (SS enabled)              */
    SIZE_T                  MinAllocationThreshold; /* 最小分析阈值 (默认 1MB)           */
    BOOLEAN                 EnableEntropyAnalysis;  /* 熵分析开关                        */
    DOUBLE                  LowEntropyThreshold;    /* 低熵阈值 (默认 1.0)               */
    BOOLEAN                 MonitorScriptEngines;   /* 脚本引擎监控 (SS 实现未消费)      */
    BOOLEAN                 EnableShellcodeDetection; /* shellcode 检测开关            */
    BOOLEAN                 BlockOnDetection;       /* 阻断喷射 (SS 实现未消费, 由回调方处置) */
    BOOLEAN                 TerminateOnHighConfidence; /* 高置信终止 (SS 实现未消费)    */
    UINT32                  ScanIntervalMs;         /* 扫描间隔 (SS 监控线程消费, 线程已裁剪) */
    UINT64                  MemoryPressureThreshold;/* 内存压力阈值 (默认 512MB)          */
    BOOLEAN                 VerboseLogging;         /* 详细日志 (SS 实现未消费)          */
} HSD_CONFIG, *PHSD_CONFIG;

/**************************************************/
/*               统计快照结构                       */
/*  HeapSprayStatisticsSnapshot             */
/*  (FromLive 语义 → HsdGetStatistics 快照拷贝).    */
/**************************************************/

typedef struct _HSD_STATS_SNAPSHOT {
    UINT64                  ScansPerformed;         /* 扫描次数              */
    UINT64                  BlocksAnalyzed;         /* 分析块数              */
    UINT64                  SpraysDetected;         /* 喷射检出数            */
    UINT64                  NopSledsDetected;       /* NOP sled 检出数       */
    UINT64                  ShellcodesDetected;     /* shellcode 检出数      */
    UINT64                  LowEntropyBlocks;       /* 低熵块数              */
    UINT64                  HighEntropyBlocks;      /* 高熵块数              */
    UINT64                  AttacksBlocked;         /* 阻断攻击数 (未接线, 恒 0) */
    UINT64                  ByTechnique[16];        /* 按技术计数 (HsdSpray_* 索引) */
    LARGE_INTEGER           StartTime;              /* 初始化时刻 (FILETIME) */
    UINT64                  UptimeSeconds;          /* 运行秒数              */
} HSD_STATS_SNAPSHOT, *PHSD_STATS_SNAPSHOT;

/**************************************************/
/*               默认配置宏                         */
/*  HeapSprayDetectorConfiguration 默认值。  */
/**************************************************/

#define HSD_DEFAULT_CONFIG \
    { \
        TRUE,                                               /* Enabled               */ \
        HSD_MIN_SPRAY_BLOCK_SIZE,                           /* MinAllocationThreshold*/ \
        TRUE,                                               /* EnableEntropyAnalysis */ \
        HSD_ENTROPY_THRESHOLD_LOW,                          /* LowEntropyThreshold   */ \
        TRUE,                                               /* MonitorScriptEngines  */ \
        TRUE,                                               /* EnableShellcodeDetection */ \
        TRUE,                                               /* BlockOnDetection      */ \
        FALSE,                                              /* TerminateOnHighConfidence */ \
        HSD_CONFIG_DEFAULT_SCAN_INTERVAL_MS,                /* ScanIntervalMs        */ \
        HSD_CONFIG_DEFAULT_MEMORY_PRESSURE,                 /* MemoryPressureThreshold */ \
        FALSE                                               /* VerboseLogging        */ \
    }

/**************************************************/
/*               检测回调类型                       */
/*  SS 三回调 (Spray/HeapState/Error) 合一。         */
/**************************************************/

typedef VOID (CALLBACK *HSD_DETECTED_CALLBACK)(const HSD_DETECTION_EVENT* Event);

/**************************************************/
/*               模块公共 API                       */
/*  全部 _IRQL_requires_max_(PASSIVE_LEVEL)。       */
/**************************************************/

/*++
生命周期/配置 (Initialize/Shutdown/Start/Stop/Pause/Resume →
    两态 + GetStatus; Start/Stop 状态机及其监控线程已裁剪)

HsdInitialize   — 初始化模块并装载配置 (NULL → HSD_DEFAULT_CONFIG);
                  校验失败返回 STATUS_INVALID_PARAMETER 并置 Error 态。
HsdShutdown     — 清理 (清空监控表/历史/回调; 无监控线程, 无 join 死锁面)。
HsdIsInitialized— 是否已初始化。
HsdGetStatus    — 状态查询。
HsdUpdateConfiguration — 运行时更新配置 (等价 SS UpdateConfiguration)。
HsdGetConfiguration — 配置快照拷贝。
HsdGetVersionString — 版本字符串 "3.0.0" (静态宽字符串)。
--*/

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
HsdInitialize(
    _In_opt_ const HSD_CONFIG* Config);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
HsdShutdown(
    VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
HsdIsInitialized(
    VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
HSD_STATUS
HsdGetStatus(
    VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
HsdUpdateConfiguration(
    _In_ const HSD_CONFIG* Config);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
HsdGetConfiguration(
    _Out_ HSD_CONFIG* Config);

_IRQL_requires_max_(PASSIVE_LEVEL)
const WCHAR*
HsdGetVersionString(
    VOID);

/*++
堆扫描/内存分析 (扫描与分析族)。

HsdScanProcessHeap   — 遍历进程提交区 (VirtualQueryEx), 熵/NOP/shellcode
                       判定标记可疑块 (单扫描上限 256), ≥3 块产出事件。
HsdScanAllHeaps      — Toolhelp 堆枚举 + 单扫描; 堆数异常高 (≥4096) 加分;
                       Toolhelp 失败回退单扫描。
HsdAnalyzeMemoryRegion — 读取区域样本 (≤4096B) 并做块级分析 + 保护/类型。
HsdAnalyzeMemoryBlock  — 纯数据块分析 (熵/主导字节/NOP/shellcode)。
HsdCalculateEntropy   — 香农熵 (256 桶)。
HsdDetectNopSled      — NOP sled 检测 (统一字节连续性 ≥ MinLength)。
HsdDetectShellcode    — 壳码检测 (12 模式表 + API hash + XOR 循环, ≥3 指标)。
HsdIdentifySprayTechnique — 技术分类 (空数据按熵, 有数据按熵+sled+靶址)。
--*/

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
HsdScanProcessHeap(
    _In_ ULONG ProcessId,
    _Out_ PHSD_DETECTION_EVENT Event);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
HsdScanAllHeaps(
    _In_ ULONG ProcessId,
    _Out_ PHSD_DETECTION_EVENT Event);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
HsdAnalyzeMemoryRegion(
    _In_ ULONG ProcessId,
    _In_ UINT64 Address,
    _In_ SIZE_T Size,
    _Out_ PHSD_ALLOCATION_INFO Info);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
HsdAnalyzeMemoryBlock(
    _In_reads_opt_(DataSize) const UCHAR* Data,
    _In_ SIZE_T DataSize,
    _In_ UINT64 BaseAddress,
    _Out_ PHSD_ALLOCATION_INFO Info);

_IRQL_requires_max_(PASSIVE_LEVEL)
DOUBLE
HsdCalculateEntropy(
    _In_reads_opt_(DataSize) const UCHAR* Data,
    _In_ SIZE_T DataSize);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
HsdDetectNopSled(
    _In_reads_opt_(DataSize) const UCHAR* Data,
    _In_ SIZE_T DataSize,
    _In_ SIZE_T MinLength);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
HsdDetectShellcode(
    _In_reads_opt_(DataSize) const UCHAR* Data,
    _In_ SIZE_T DataSize);

_IRQL_requires_max_(PASSIVE_LEVEL)
HSD_SPRAY_TECHNIQUE
HsdIdentifySprayTechnique(
    _In_reads_opt_(DataSize) const UCHAR* Data,
    _In_ SIZE_T DataSize,
    _In_ DOUBLE Entropy);

/*++
进程堆状态 (GetProcessHeapState / HasSprayIndicators)。

HsdGetProcessHeapState — 工作集/私有字节 (GetProcessMemoryInfo) + 提交/保留/
                         大分配计数 (VirtualQueryEx 遍历)。
HsdHasSprayIndicators  — 轻量喷射判定 (spraySuspected 或大分配 >5)。
--*/

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
HsdGetProcessHeapState(
    _In_ ULONG ProcessId,
    _Out_ PHSD_HEAP_STATE State);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
HsdHasSprayIndicators(
    _In_ ULONG ProcessId);

/*++
进程监控 (MonitorProcess 族)。

HsdMonitorProcess      — 登记监控进程 (表满返回 STATUS_TOO_MANY_OPENED)。
HsdStopMonitoring      — 注销监控。
HsdIsMonitoring        — 是否在监控表内。
HsdGetMonitoredProcesses — 枚举监控进程 PID 列表。
--*/

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
HsdMonitorProcess(
    _In_ ULONG ProcessId);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
HsdStopMonitoring(
    _In_ ULONG ProcessId);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
HsdIsMonitoring(
    _In_ ULONG ProcessId);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
HsdGetMonitoredProcesses(
    _Out_writes_to_opt_(MaxProcesses, *ProcessCount) ULONG* ProcessIds,
    _In_ ULONG MaxProcesses,
    _Out_ ULONG* ProcessCount);

/*++
内核内存告警接入 (内核集成族)。

HsdOnMemoryAllocation   — 记录监控进程分配 (环形窗口), 大分配累计 ≥3 触发
                          扫描; RWX 分配高优先级。
HsdOnProtectionChange   — 检测 W→X 转换 (可写且不可执行 → 可执行) 且规模
                          ≥ 阈值 → 触发扫描。
HsdProcessKernelMemoryAlert — 统一入口, 委托 OnMemoryAllocation (与
                          JITSprayDetector::ProcessKernelMemoryAlert 同签名,
                          供上层统一分发; WkDefender 无内核 IPC 通道, 保留
                          公共入口供直接调用)。
--*/

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
HsdOnMemoryAllocation(
    _In_ ULONG ProcessId,
    _In_ UINT64 Address,
    _In_ SIZE_T Size,
    _In_ ULONG Protection);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
HsdOnProtectionChange(
    _In_ ULONG ProcessId,
    _In_ UINT64 Address,
    _In_ SIZE_T Size,
    _In_ ULONG OldProtection,
    _In_ ULONG NewProtection);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
HsdProcessKernelMemoryAlert(
    _In_ ULONG ProcessId,
    _In_ UINT64 Address,
    _In_ SIZE_T Size,
    _In_ ULONG Protection);

/*++
回调/统计/历史 (回调与统计族)。

HsdRegisterCallback   — 登记单一检测回调 (NULL 注销)。
HsdGetStatistics      — 统计快照 (FromLive 语义)。
HsdResetStatistics    — 清零统计。
HsdGetRecentDetections— 最近检测事件 (最新在前, 逆序返回)。
HsdSelfTest           — 4 项自检 (熵/NOP sled/shellcode/块分析)。
--*/

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
HsdRegisterCallback(
    _In_opt_ HSD_DETECTED_CALLBACK Callback);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
HsdGetStatistics(
    _Out_ PHSD_STATS_SNAPSHOT Snapshot);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
HsdResetStatistics(
    VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
HsdGetRecentDetections(
    _Out_writes_to_opt_(MaxCount, *EventCount) PHSD_DETECTION_EVENT Events,
    _In_ ULONG MaxCount,
    _Out_ ULONG* EventCount);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
HsdSelfTest(
    VOID);

/*++
工具函数 (Get*Name / IsCommon* 族)。

HsdGetSprayTechniqueName — 技术 → 名称 (静态宽字符串, 恒非空)。
HsdGetMemoryRegionTypeName — 区域类型 → 名称。
HsdGetConfidenceLevelName  — 置信度 → 名称。
HsdIsCommonNopByte         — 是否常见 NOP 字节 (9 值表)。
HsdIsCommonSprayAddress    — 是否常见喷射靶址 (8 值表)。
--*/

_IRQL_requires_max_(PASSIVE_LEVEL)
const WCHAR*
HsdGetSprayTechniqueName(
    _In_ HSD_SPRAY_TECHNIQUE Technique);

_IRQL_requires_max_(PASSIVE_LEVEL)
const WCHAR*
HsdGetMemoryRegionTypeName(
    _In_ HSD_MEMORY_REGION_TYPE RegionType);

_IRQL_requires_max_(PASSIVE_LEVEL)
const WCHAR*
HsdGetConfidenceLevelName(
    _In_ HSD_CONFIDENCE Level);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
HsdIsCommonNopByte(
    _In_ UCHAR Byte);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
HsdIsCommonSprayAddress(
    _In_ ULONG Address);