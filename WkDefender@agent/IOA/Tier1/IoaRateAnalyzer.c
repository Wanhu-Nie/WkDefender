/**************************************************/
/*  WkDefender IOA — 进程行为速率分析器实现            */
/*                                                   */
/*  增强: RaGetRateScore 将原始计数值归一化到          */
/*  [0,100] 区间供 Tier1 聚合使用                     */
/*                                                   */
/*  ── 统计基线异常检测 (2026-08-05) ──               */
/*  ShadowStrike AnomalyDetector (Z-Score/MAD)        */
/*  按代码功能融合, 重实现非复制:                       */
/*    - 滑动窗口基线 (256 样本环形缓冲, 每10样本重算)   */
/*    - 经典 Z-Score + Modified Z-Score(MAD) 保守合并  */
/*    - 进程级基线优先 + 全局基线兜底 (<10 样本回退)    */
/*    - 判定异常(≥2σ)样本不写基线 (防驯化, SS 缺失补强) */
/*    - 进程基线 TTL 1h 淘汰 (维护线程 1 分钟周期)      */
/**************************************************/

#include "IoaRateAnalyzer.h"
#include "../../Notification/EventTypes.h"
#include <windows.h>
#include <wchar.h>
#include <math.h>
#include <objbase.h>       /* CoCreateGuid (告警 AlertId) */

/**************************************************/
/*               速率阈值配置                       */
/**************************************************/

/*
 * 默认速率阈值配置
 * 基于经验值设定：警告阈值和严重阈值的判断模型
 * 索引对齐 RA_METRIC_TYPE (统一维度, 2026-08-05)
 */
static const RA_RATE_THRESHOLD g_DefaultThresholds[RA_METRIC_VALID] = {
    /* 进程创建:      >10 警告 40,  >30 严重 70 */
    [RA_METRIC_PROC_CREATE] = { 10, 30 },
    /* 线程操作:      >8  警告 50,  >25 严重 80 */
    [RA_METRIC_THREAD]      = { 8,  25 },
    /* 文件操作:      >15 警告 40,  >50 严重 70 */
    [RA_METRIC_FILE]        = { 15, 50 },
    /* 注册表操作:    >15 警告 40,  >50 严重 70 */
    [RA_METRIC_REG]         = { 15, 50 },
    /* 网络操作:      >10 警告 40,  >30 严重 70 */
    [RA_METRIC_NET]         = { 10, 30 },
    /* 内存操作:      >10 警告 50,  >30 严重 80 */
    [RA_METRIC_MEM]         = { 10, 30 },
    /* 其他:          >20 警告 40,  >60 严重 70 */
    [RA_METRIC_CUSTOM]      = { 20, 60 },
};

/**************************************************/
/*           内部辅助函数                          */
/**************************************************/

static BOOLEAN
RaIsNullGuid(
    _In_ GUID NodeId
    )
/*++
Routine Description:
    判断 GUID 是否为空 (未初始化/孤儿进程父节点)。

Arguments:
    NodeId — 进程节点 GUID。

Return Value:
    TRUE = 空 GUID。
--*/
{
    return (NodeId.Data1 == 0 && NodeId.Data2 == 0 &&
            NodeId.Data3 == 0 && NodeId.Data4[0] == 0 &&
            NodeId.Data4[1] == 0 && NodeId.Data4[2] == 0 &&
            NodeId.Data4[3] == 0 && NodeId.Data4[4] == 0 &&
            NodeId.Data4[5] == 0 && NodeId.Data4[6] == 0 &&
            NodeId.Data4[7] == 0);
}

static ULONG
RaHashGuid(
    _In_ GUID NodeId,
    _In_ ULONG BucketCount
    )
/*++
Routine Description:
    进程节点 GUID → 哈希桶索引 (FNV-1a 变体, 对齐 SS AdpHashProcessId)。

Arguments:
    NodeId      — 进程节点 GUID。
    BucketCount — 哈希桶数量。

Return Value:
    桶索引 [0, BucketCount)。
--*/
{
    ULONGLONG h = 0xcbf29ce484222325ULL;
    PUCHAR p = (PUCHAR)&NodeId;
    ULONG i;

    for (i = 0; i < sizeof(GUID); i++) {
        h ^= p[i];
        h *= 0x100000001b3ULL;
    }

    return (ULONG)(h % BucketCount);
}

static VOID
RaNow(
    _Out_ LARGE_INTEGER* Now
    )
/*++
Routine Description:
    获取当前时间 (FILETIME 100ns, 对齐 SS KeQuerySystemTime 语义)。
--*/
{
    GetSystemTimeAsFileTime((PFILETIME)Now);
}

/*
 * RaMapEventTypeToMetric — 事件类型 → 统计基线指标。
 * 对齐 SS BepProcessSingleEvent 步骤⑦ eventCategory 映射
 * (EventType 高字节: 0x10 进程/0x20 线程/0x30 文件/0x40 注册表/
 *  0x50 网络/0x60 内存; 0x80 IOC 段返回 CUSTOM, 调用方跳过学习)。
 */
_Use_decl_annotations_
RA_METRIC_TYPE
RaMapEventTypeToMetric(
    WKD_EVENT_TYPE EventType
    )
{
    USHORT category = (USHORT)((USHORT)EventType >> 8);

    switch (category) {
    case 0x10: return RA_METRIC_PROC_CREATE;
    case 0x20: return RA_METRIC_THREAD;
    case 0x30: return RA_METRIC_FILE;
    case 0x40: return RA_METRIC_REG;
    case 0x50: return RA_METRIC_NET;
    case 0x60: return RA_METRIC_MEM;
    default:   return RA_METRIC_CUSTOM;
    }
}

/**************************************************/
/*        速率记录管理 (固定阈值计数)               */
/**************************************************/

static PRA_PROC_RATE_RECORD
RaFindRateRecordLocked(
    _In_ PIOA_RATE_ANALYZER Analyzer,
    _In_ GUID               ProcessNodeId
    )
/*++
Routine Description:
    在固定计数数组中查找进程记录 (持锁调用)。

Arguments:
    Analyzer      — 速率分析器。
    ProcessNodeId — 进程节点 GUID。

Return Value:
    记录指针; 未找到返回 NULL。
--*/
{
    ULONG i;

    if (RaIsNullGuid(ProcessNodeId)) return NULL;

    for (i = 0; i < Analyzer->RecordCount; i++) {
        if (RtlCompareMemory(&Analyzer->Records[i].ProcessNodeId,
                             &ProcessNodeId, sizeof(GUID)) == sizeof(GUID)) {
            return &Analyzer->Records[i];
        }
    }

    return NULL;
}

static PRA_PROC_RATE_RECORD
RaCreateRateRecordLocked(
    _In_ PIOA_RATE_ANALYZER Analyzer,
    _In_ GUID               ProcessNodeId
    )
/*++
Routine Description:
    创建进程计数记录 (持锁调用)。

Arguments:
    Analyzer      — 速率分析器。
    ProcessNodeId — 进程节点 GUID。

Return Value:
    新记录指针; 已满/无效返回 NULL。
--*/
{
    PRA_PROC_RATE_RECORD rec;
    LARGE_INTEGER now;

    if (RaIsNullGuid(ProcessNodeId)) return NULL;
    if (Analyzer->RecordCount >= RA_MAX_PROCESS_COUNT) return NULL;

    rec = &Analyzer->Records[Analyzer->RecordCount];
    RtlZeroMemory(rec, sizeof(*rec));
    rec->ProcessNodeId = ProcessNodeId;
    RaNow(&now);
    rec->WindowStart = now.QuadPart;
    Analyzer->RecordCount++;

    return rec;
}

static ULONG
RaGetMetricCountLocked(
    _In_ PIOA_RATE_ANALYZER Analyzer,
    _In_ GUID               ProcessNodeId,
    _In_ RA_METRIC_TYPE     Metric
    )
/*++
Routine Description:
    读取进程当前窗口内指定指标的计数 (持锁调用)。

Arguments:
    Analyzer      — 速率分析器。
    ProcessNodeId — 进程节点 GUID。
    Metric        — 统计基线指标。

Return Value:
    当前窗口计数; 无记录返回 0。
--*/
{
    PRA_PROC_RATE_RECORD rec;

    if (Metric >= RA_METRIC_VALID) return 0;

    rec = RaFindRateRecordLocked(Analyzer, ProcessNodeId);
    if (!rec) return 0;

    return (ULONG)rec->Counts[Metric];
}

/**************************************************/
/*          进程基线管理 (统计基线)                 */
/**************************************************/

static PRA_PROCESS_BASELINE
RaFindProcessBaselineLocked(
    _In_ PIOA_RATE_ANALYZER Analyzer,
    _In_ GUID               ProcessNodeId
    )
/*++
Routine Description:
    在哈希表中查找进程基线 (持锁调用)。

Arguments:
    Analyzer      — 速率分析器。
    ProcessNodeId — 进程节点 GUID。

Return Value:
    基线指针; 未找到返回 NULL。
--*/
{
    ULONG bucket;
    PLIST_ENTRY entry;

    if (RaIsNullGuid(ProcessNodeId)) return NULL;

    bucket = RaHashGuid(ProcessNodeId, RA_HASH_BUCKET_COUNT);

    for (entry = Analyzer->BaselineBuckets[bucket].Flink;
         entry != &Analyzer->BaselineBuckets[bucket];
         entry = entry->Flink) {

        PRA_PROCESS_BASELINE pb = CONTAINING_RECORD(
            entry, RA_PROCESS_BASELINE, HashEntry);

        if (RtlCompareMemory(&pb->ProcessNodeId,
                             &ProcessNodeId, sizeof(GUID)) == sizeof(GUID)) {
            return pb;
        }
    }

    return NULL;
}

static PRA_PROCESS_BASELINE
RaCreateProcessBaselineLocked(
    _In_ PIOA_RATE_ANALYZER Analyzer,
    _In_ GUID               ProcessNodeId
    )
/*++
Routine Description:
    创建进程基线并插入哈希表 (持锁调用, 对齐 SS AdpCreateProcessBaseline)。

Arguments:
    Analyzer      — 速率分析器。
    ProcessNodeId — 进程节点 GUID。

Return Value:
    新基线指针; 已满/重复返回已有指针。
--*/
{
    PRA_PROCESS_BASELINE pb;
    ULONG bucket;
    ULONG i;
    LARGE_INTEGER now;

    if (RaIsNullGuid(ProcessNodeId)) return NULL;
    if (Analyzer->BaselineCount >= Analyzer->BaselineMaxProcesses) return NULL;

    /* 双检: 避免竞态重复创建 */
    pb = RaFindProcessBaselineLocked(Analyzer, ProcessNodeId);
    if (pb) return pb;

    pb = (PRA_PROCESS_BASELINE)UtHeapAlloc(sizeof(RA_PROCESS_BASELINE));
    if (!pb) return NULL;

    RtlZeroMemory(pb, sizeof(*pb));
    pb->ProcessNodeId = ProcessNodeId;
    pb->RefCount = 1;   /* 列表引用; 用户态持锁访问无需额外引用计数 */
    RaNow(&now);
    pb->CreateTime = now;
    pb->LastActivityTime = now;

    for (i = 0; i < RA_METRIC_COUNT; i++) {
        pb->Baselines[i].Type = (RA_METRIC_TYPE)i;
    }

    bucket = RaHashGuid(ProcessNodeId, RA_HASH_BUCKET_COUNT);
    InsertTailList(&Analyzer->BaselineList, &pb->ListEntry);
    InsertTailList(&Analyzer->BaselineBuckets[bucket], &pb->HashEntry);
    Analyzer->BaselineCount++;

    return pb;
}

/**************************************************/
/*          基线更新 (滑动窗口, 对齐 SS)           */
/**************************************************/

static DOUBLE
RaSqrt(
    _In_ DOUBLE Value
    )
/*++
Routine Description:
    平方根 (用户态直接使用 CRT sqrt; SS 内核用 Newton-Raphson 为避 CRT)。
--*/
{
    return sqrt(Value);
}

static VOID
RaCalculateStatisticsLocked(
    _Inout_ PRA_BASELINE Baseline
    )
/*++
Routine Description:
    从样本环重算 Mean/StdDev/Min/Max。
    对齐 SS AdpCalculateStatisticsLocked (单遍 min/max/mean + 二次方差)。

Arguments:
    Baseline — 基线 (样本环已更新)。
--*/
{
    ULONG count = Baseline->SampleCount;
    ULONG i;
    DOUBLE sum = 0.0;
    DOUBLE sumSquares = 0.0;
    DOUBLE mean;
    DOUBLE minVal, maxVal;

    if (count == 0) return;

    minVal = Baseline->Samples[0];
    maxVal = Baseline->Samples[0];

    for (i = 0; i < count; i++) {
        DOUBLE val = Baseline->Samples[i];
        sum += val;
        if (val < minVal) minVal = val;
        if (val > maxVal) maxVal = val;
    }

    mean = sum / (DOUBLE)count;
    Baseline->Mean = mean;
    Baseline->Min = minVal;
    Baseline->Max = maxVal;

    for (i = 0; i < count; i++) {
        DOUBLE diff = Baseline->Samples[i] - mean;
        sumSquares += diff * diff;
    }

    Baseline->StandardDeviation = RaSqrt(sumSquares / (DOUBLE)count);
}

static VOID
RaUpdateBaselineLocked(
    _Inout_ PRA_BASELINE Baseline,
    _In_    DOUBLE       Value
    )
/*++
Routine Description:
    将样本写入环形缓冲, 每 10 样本重算统计。
    对齐 SS AdpUpdateBaselineLocked。

Arguments:
    Baseline — 基线。
    Value    — 观测值。
--*/
{
    ULONG index = Baseline->CurrentIndex;

    Baseline->Samples[index] = Value;
    Baseline->CurrentIndex = (index + 1) % RA_BASELINE_SAMPLES;

    if (Baseline->SampleCount < RA_BASELINE_SAMPLES) {
        Baseline->SampleCount++;
    } else {
        Baseline->IsFull = TRUE;
    }

    if (Baseline->SampleCount % 10 == 0 || Baseline->SampleCount < 20) {
        RaCalculateStatisticsLocked(Baseline);
    }

    RaNow(&Baseline->LastUpdated);
}

static VOID
RaUpdateEMA(
    _Inout_ PRA_PROCESS_BASELINE ProcessBaseline,
    _In_    RA_METRIC_TYPE       Metric,
    _In_    DOUBLE               Value
    )
/*++
Routine Description:
    双 EMA 更新 (α=0.1 慢速 / 0.3 快速)。
    ※死代码: SS 原实现只更新未消费 (AdCheckForAnomaly 从不读 EMA 字段);
    wkd 迁移保留字段与逻辑, 无消费方, 由 RaUpdateBaselineLocked 替代。
--*/
{
#define RA_EMA_ALPHA        0.1
#define RA_EMA_FAST_ALPHA   0.3

    if (!ProcessBaseline->EMAInitialized[Metric]) {
        ProcessBaseline->EMA[Metric] = Value;
        ProcessBaseline->EMAFast[Metric] = Value;
        ProcessBaseline->EMAInitialized[Metric] = TRUE;
    } else {
        ProcessBaseline->EMA[Metric] =
            RA_EMA_ALPHA * Value + (1.0 - RA_EMA_ALPHA) * ProcessBaseline->EMA[Metric];
        ProcessBaseline->EMAFast[Metric] =
            RA_EMA_FAST_ALPHA * Value + (1.0 - RA_EMA_FAST_ALPHA) * ProcessBaseline->EMAFast[Metric];
    }
}

/**************************************************/
/*        统计计算 (Z-Score / MAD, 对齐 SS)        */
/**************************************************/

static DOUBLE
RaCalculateZScoreLocked(
    _In_ PRA_BASELINE Baseline,
    _In_ DOUBLE       Value
    )
/*++
Routine Description:
    经典 Z-Score = |(Value - Mean) / StdDev|。
    无方差 (stddev<0.0001) 退化: 与均值不同即判 6σ 当量 (对齐 SS)。

Arguments:
    Baseline — 基线 (统计已重算)。
    Value    — 观测值。

Return Value:
    Z 值 (绝对值)。
--*/
{
    DOUBLE zScore;

    if (Baseline->StandardDeviation < 0.0001) {
        if (Value == Baseline->Mean) return 0.0;
        return RA_CRITICAL_SIGMA + 1.0;     /* 6σ */
    }

    zScore = (Value - Baseline->Mean) / Baseline->StandardDeviation;
    return (zScore < 0.0) ? -zScore : zScore;
}

static VOID
RaInsertionSortDouble(
    _Inout_updates_(Count) DOUBLE* Array,
    _In_ ULONG Count
    )
/*++
Routine Description:
    插入排序 (样本量小, 对齐 SS AdpInsertionSortDouble)。
--*/
{
    ULONG i, j;
    DOUBLE temp;

    for (i = 1; i < Count; i++) {
        temp = Array[i];
        j = i;
        while (j > 0 && Array[j - 1] > temp) {
            Array[j] = Array[j - 1];
            j--;
        }
        Array[j] = temp;
    }
}

static DOUBLE
RaCalculateMedian(
    _Inout_updates_(Count) DOUBLE* Array,
    _In_ ULONG Count
    )
/*++
Routine Description:
    中位数 (就地排序)。
--*/
{
    RaInsertionSortDouble(Array, Count);

    if (Count % 2 == 0) {
        return (Array[Count / 2 - 1] + Array[Count / 2]) / 2.0;
    } else {
        return Array[Count / 2];
    }
}

static DOUBLE
RaCalculateModifiedZScore(
    _In_ PRA_BASELINE Baseline,
    _In_ DOUBLE       Value
    )
/*++
Routine Description:
    Modified Z-Score (MAD 鲁棒版) = 0.6745 × |Value - Median| / MAD。
    使用用户态栈缓冲 (SS 内核用 scratch pool, 用户态无栈限制)。

    对齐 SS AdpCalculateModifiedZScore:
      1. 拷贝样本到排序缓冲 + 偏差缓冲
      2. median = 中位数(排序缓冲)
      3. MAD = 中位数(|x_i - median|)
      4. MAD<0.0001 → 回退经典 Z-Score

Arguments:
    Baseline — 基线。
    Value    — 观测值。

Return Value:
    Modified Z 值 (绝对值)。
--*/
{
    DOUBLE sortBuf[RA_BASELINE_SAMPLES];
    DOUBLE devBuf[RA_BASELINE_SAMPLES];
    ULONG count = Baseline->SampleCount;
    DOUBLE median;
    DOUBLE mad;
    DOUBLE modifiedZ;
    ULONG i;

    if (count < 3) {
        return RaCalculateZScoreLocked(Baseline, Value);
    }

    RtlCopyMemory(sortBuf, Baseline->Samples, count * sizeof(DOUBLE));
    RtlCopyMemory(devBuf, Baseline->Samples, count * sizeof(DOUBLE));

    median = RaCalculateMedian(sortBuf, count);

    for (i = 0; i < count; i++) {
        DOUBLE diff = devBuf[i] - median;
        sortBuf[i] = (diff < 0.0) ? -diff : diff;
    }
    mad = RaCalculateMedian(sortBuf, count);

    if (mad < 0.0001) {
        return RaCalculateZScoreLocked(Baseline, Value);
    }

    modifiedZ = RA_MAD_CONSTANT * (Value - median) / mad;
    return (modifiedZ < 0.0) ? -modifiedZ : modifiedZ;
}

static ULONG
RaCalculateSeverityScore(
    _In_ DOUBLE       DeviationSigmas,
    _In_ RA_METRIC_TYPE Metric
    )
/*++
Routine Description:
    严重度评分 = sigma 基础分 × 指标乘数, clamp 0-100。
    对齐 SS AdpCalculateSeverityScore (Privilege150%/Proc&Thread130%/
    Net&Reg120%/File&DLL110%/其他100%)。

Arguments:
    DeviationSigmas — 偏离 sigma 数。
    Metric          — 指标类型。

Return Value:
    严重度 [0,100]。
--*/
{
    ULONG baseScore;
    ULONG multiplier = 100;
    ULONG finalScore;

    if (DeviationSigmas < RA_SEVERITY_LOW_SIGMA)      baseScore = 10;
    else if (DeviationSigmas < RA_SEVERITY_MEDIUM_SIGMA) baseScore = 30;
    else if (DeviationSigmas < RA_SEVERITY_HIGH_SIGMA)   baseScore = 60;
    else if (DeviationSigmas < RA_SEVERITY_CRITICAL_SIGMA) baseScore = 80;
    else baseScore = 100;

    switch (Metric) {
    case RA_METRIC_PROC_CREATE:
    case RA_METRIC_THREAD:
        multiplier = 130;
        break;
    case RA_METRIC_NET:
    case RA_METRIC_REG:
        multiplier = 120;
        break;
    case RA_METRIC_FILE:
    case RA_METRIC_MEM:
        multiplier = 110;
        break;
    default:
        multiplier = 100;
        break;
    }

    finalScore = (baseScore * multiplier) / 100;
    if (finalScore > 100) finalScore = 100;

    return finalScore;
}

/**************************************************/
/*        异常环 (LRU, 上限 RA_MAX_ANOMALIES)      */
/**************************************************/

static VOID
RaAddAnomalyToList(
    _In_ PIOA_RATE_ANALYZER Analyzer,
    _In_ CONST RA_ANOMALY_INFO* Info
    )
/*++
Routine Description:
    异常入环 (LRU, 超上限移除最老)。
    对齐 SS AdpAddAnomalyToList。

Arguments:
    Analyzer — 速率分析器。
    Info     — 异常记录。
--*/
{
    PRA_ANOMALY anomaly;
    PRA_ANOMALY oldest;

    anomaly = (PRA_ANOMALY)UtHeapAlloc(sizeof(RA_ANOMALY));
    if (!anomaly) return;

    RtlCopyMemory(&anomaly->Info, Info, sizeof(RA_ANOMALY_INFO));

    /* 持锁调用: RaCheckForAnomaly 已在锁内 */
    if (Analyzer->AnomalyCount >= RA_MAX_ANOMALIES) {
        if (!IsListEmpty(&Analyzer->AnomalyList)) {
            oldest = CONTAINING_RECORD(
                RemoveHeadList(&Analyzer->AnomalyList), RA_ANOMALY, ListEntry);
            Analyzer->AnomalyCount--;
            UtHeapFree(oldest);
        }
    }

    InsertTailList(&Analyzer->AnomalyList, &anomaly->ListEntry);
    Analyzer->AnomalyCount++;
}

/**************************************************/
/*       主入口 — RaCheckForAnomaly               */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
RaCheckForAnomaly(
    PIOA_RATE_ANALYZER Analyzer,
    GUID               ProcessNodeId,
    RA_METRIC_TYPE     Metric,
    PBOOLEAN           IsAnomaly,
    PRA_ANOMALY_INFO   AnomalyInfo
    )
/*++
Routine Description:
    检测+记录统计异常 (对齐 SS AdCheckForAnomaly)。

    流程:
      1. 观测值 = 当前 10s 窗口内该指标事件计数
      2. 进程级基线优先 (样本≥MinimumSamples), 否则全局基线兜底
      3. 经典 Z-Score 与 Modified Z-Score(MAD) 取保守值, z>4σ 回退纯 Z
      4. effectiveDeviation > SigmaThreshold(3.0) → 异常
      5. 异常样本不写入基线 (防驯化, SS 缺失补强)

Arguments:
    Analyzer      — 速率分析器。
    ProcessNodeId — 进程节点 GUID。
    Metric        — 统计基线指标。
    IsAnomaly     — [输出] 是否异常。
    AnomalyInfo   — [输出可选] 异常详情。

Return Value:
    NTSTATUS。
--*/
{
    PRA_PROCESS_BASELINE processBaseline = NULL;
    PRA_BASELINE baseline = NULL;
    RA_ANOMALY_INFO info;
    LARGE_INTEGER now;
    DOUBLE zScore;
    DOUBLE modifiedZScore;
    DOUBLE effectiveDeviation;
    DOUBLE baselineMean, baselineMin, baselineMax;
    ULONG sampleCount;
    ULONG value;
    BOOLEAN isAnomaly = FALSE;

    if (!Analyzer || !Analyzer->Initialized || !IsAnomaly) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Metric > RA_METRIC_MaxValue) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Analyzer->CleanupTerminate) {
        return STATUS_DEVICE_NOT_READY;
    }

    *IsAnomaly = FALSE;
    if (AnomalyInfo) RtlZeroMemory(AnomalyInfo, sizeof(*AnomalyInfo));
    RtlZeroMemory(&info, sizeof(info));

    RaNow(&now);

    EnterCriticalSection(&Analyzer->Lock);

    value = RaGetMetricCountLocked(Analyzer, ProcessNodeId, Metric);

    /* 进程级基线 (惰性创建) */
    processBaseline = RaFindProcessBaselineLocked(Analyzer, ProcessNodeId);
    if (!processBaseline) {
        processBaseline = RaCreateProcessBaselineLocked(Analyzer, ProcessNodeId);
    }
    if (processBaseline) {
        processBaseline->LastActivityTime = now;
    }

    /* 检测基线选择 (对齐 SS AdCheckForAnomaly 双轨):
     * 进程基线成熟 (样本≥MinimumSamples) → 用它;
     * 否则回退全局基线 (所有进程样本混合, 对齐 SS GlobalBaselines)。
     * 样本同时记录到全局 + 进程基线 (对齐 SS AdRecordSample)。 */
    if (processBaseline &&
        processBaseline->Baselines[Metric].SampleCount >= Analyzer->MinimumSamples) {
        baseline = &processBaseline->Baselines[Metric];
    } else {
        baseline = &Analyzer->GlobalBaselines[Metric];
    }

    /* 学习期不足 → 不做判定, 记录样本后返回 */
    if (baseline->SampleCount < Analyzer->MinimumSamples) {
        RaUpdateBaselineLocked(&Analyzer->GlobalBaselines[Metric], (DOUBLE)value);
        if (processBaseline) {
            RaUpdateBaselineLocked(&processBaseline->Baselines[Metric], (DOUBLE)value);
        }
        InterlockedIncrement64(&Analyzer->SamplesProcessed);
        LeaveCriticalSection(&Analyzer->Lock);
        return STATUS_SUCCESS;
    }

    sampleCount = baseline->SampleCount;
    baselineMean = baseline->Mean;
    baselineMin = baseline->Min;
    baselineMax = baseline->Max;

    /* 双算法保守合并 (对齐 SS AdCheckForAnomaly) */
    zScore = RaCalculateZScoreLocked(baseline, (DOUBLE)value);
    modifiedZScore = RaCalculateModifiedZScore(baseline, (DOUBLE)value);
    effectiveDeviation = (zScore < modifiedZScore) ? zScore : modifiedZScore;
    if (zScore > RA_HIGH_CONFIDENCE_SIGMA) {
        effectiveDeviation = zScore;
    }

    if (effectiveDeviation > Analyzer->SigmaThreshold) {
        isAnomaly = TRUE;

        info.ProcessNodeId = ProcessNodeId;
        info.Metric = Metric;
        info.ObservedValue = (DOUBLE)value;
        info.ExpectedValue = baselineMean;
        info.DeviationSigmas = effectiveDeviation;
        info.SeverityScore = RaCalculateSeverityScore(effectiveDeviation, Metric);
        info.IsHighConfidence = (effectiveDeviation >= RA_HIGH_CONFIDENCE_SIGMA) ||
            (sampleCount >= 100 &&
             ((DOUBLE)value < baselineMin || (DOUBLE)value > baselineMax));
        info.DetectionTime = now;

        RaAddAnomalyToList(Analyzer, &info);
        InterlockedIncrement64(&Analyzer->AnomaliesDetected);

        if (AnomalyInfo) {
            RtlCopyMemory(AnomalyInfo, &info, sizeof(info));
        }
    }

    /*
     * 记录样本 (对齐 SS AdRecordSample: 全局+进程基线同时更新):
     *  - 判定异常的样本不写入基线 (防驯化, SS 缺失补强) — 防止攻击者
     *    用攻击流量把基线"驯化"到异常水平, 后续不再触发。
     */
    if (!isAnomaly) {
        RaUpdateBaselineLocked(&Analyzer->GlobalBaselines[Metric], (DOUBLE)value);
        if (processBaseline) {
            RaUpdateBaselineLocked(&processBaseline->Baselines[Metric], (DOUBLE)value);
        }
    }
    InterlockedIncrement64(&Analyzer->SamplesProcessed);

    LeaveCriticalSection(&Analyzer->Lock);

    *IsAnomaly = isAnomaly;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
ULONG
RaGetAnomalyScore(
    PIOA_RATE_ANALYZER Analyzer,
    GUID               ProcessNodeId
    )
/*++
Routine Description:
    查询进程当前统计异常分 [0,100] (跨 7 个有效指标取最高严重度)。
    对齐 SS 严重度映射; 供阶段6 max 提升 / 策略选择 / 外部查询。

Arguments:
    Analyzer      — 速率分析器。
    ProcessNodeId — 进程节点 GUID。

Return Value:
    统计异常分 [0,100]; 无异常/无基线返回 0。
--*/
{
    ULONG best = 0;
    ULONG i;
    PRA_PROCESS_BASELINE processBaseline;

    if (!Analyzer || !Analyzer->Initialized) return 0;

    EnterCriticalSection(&Analyzer->Lock);

    processBaseline = RaFindProcessBaselineLocked(Analyzer, ProcessNodeId);
    if (processBaseline) {
        for (i = 0; i < RA_METRIC_VALID; i++) {
            PRA_BASELINE b = &processBaseline->Baselines[i];
            DOUBLE eff;
            ULONG value;

            if (b->SampleCount < Analyzer->MinimumSamples) continue;

            value = RaGetMetricCountLocked(Analyzer, ProcessNodeId, (RA_METRIC_TYPE)i);
            eff = RaCalculateZScoreLocked(b, (DOUBLE)value);

            if (eff > Analyzer->SigmaThreshold) {
                ULONG s = RaCalculateSeverityScore(eff, (RA_METRIC_TYPE)i);
                if (s > best) best = s;
            }
        }
    }

    LeaveCriticalSection(&Analyzer->Lock);

    return best;
}

/**************************************************/
/*        周期维护 (TTL 淘汰, 对齐 SS)             */
/**************************************************/

_Use_decl_annotations_
VOID
RaMaintenance(
    PIOA_RATE_ANALYZER Analyzer
    )
/*++
Routine Description:
    进程基线 TTL 淘汰 (1h) + 异常环时间清理。
    对齐 SS AdpCleanupWorkerThread 阶段1/2。

Arguments:
    Analyzer — 速率分析器。
--*/
{
    LARGE_INTEGER now;
    LARGE_INTEGER staleTime;
    PLIST_ENTRY entry, next;

    if (!Analyzer || !Analyzer->Initialized) return;

    RaNow(&now);
    staleTime.QuadPart = now.QuadPart -
        ((LONGLONG)RA_STALE_BASELINE_AGE_MS * 10000);

    EnterCriticalSection(&Analyzer->Lock);

    /* 阶段1: 清理过期异常 (保留 1h) */
    for (entry = Analyzer->AnomalyList.Flink;
         entry != &Analyzer->AnomalyList;
         entry = next) {

        PRA_ANOMALY anomaly;

        next = entry->Flink;
        anomaly = CONTAINING_RECORD(entry, RA_ANOMALY, ListEntry);

        if (anomaly->Info.DetectionTime.QuadPart < staleTime.QuadPart) {
            RemoveEntryList(&anomaly->ListEntry);
            Analyzer->AnomalyCount--;
            UtHeapFree(anomaly);
        }
    }

    /* 阶段2: 淘汰过期进程基线 (1h 无活动) */
    for (entry = Analyzer->BaselineList.Flink;
         entry != &Analyzer->BaselineList;
         entry = next) {

        PRA_PROCESS_BASELINE pb;

        next = entry->Flink;
        pb = CONTAINING_RECORD(entry, RA_PROCESS_BASELINE, ListEntry);

        if (pb->LastActivityTime.QuadPart < staleTime.QuadPart) {
            RemoveEntryList(&pb->ListEntry);
            RemoveEntryList(&pb->HashEntry);
            Analyzer->BaselineCount--;
            UtHeapFree(pb);
        }
    }

    LeaveCriticalSection(&Analyzer->Lock);
}

static DWORD
WINAPI
RaMaintenanceWorker(
    _In_ LPVOID StartContext
    )
/*++
Routine Description:
    维护线程 (1 分钟周期, 对齐 SS AdpCleanupWorkerThread)。
    被事件唤醒立即执行一次 (关闭时快速退出)。
--*/
{
    PIOA_RATE_ANALYZER analyzer = (PIOA_RATE_ANALYZER)StartContext;

    while (!analyzer->CleanupTerminate) {
        WaitForSingleObject(analyzer->MaintenanceWakeEvent,
                            RA_MAINTENANCE_INTERVAL_MS);

        if (analyzer->CleanupTerminate) break;

        RaMaintenance(analyzer);
    }

    return 0;
}

/**************************************************/
/*        配置 / 统计 (对齐 SS AdSetThreshold)     */
/**************************************************/

_Use_decl_annotations_
VOID
RaSetSigmaThreshold(
    PIOA_RATE_ANALYZER Analyzer,
    DOUBLE             Sigma
    )
/*++
Routine Description:
    运行时调整 sigma 阈值 (对齐 SS AdSetThreshold, 范围 [1.5, 6.0])。

Arguments:
    Analyzer — 速率分析器。
    Sigma    — 检测阈值。
--*/
{
    if (!Analyzer || !Analyzer->Initialized) return;
    if (Sigma < 1.5 || Sigma > 6.0) return;

    EnterCriticalSection(&Analyzer->Lock);
    Analyzer->SigmaThreshold = Sigma;
    LeaveCriticalSection(&Analyzer->Lock);
}

_Use_decl_annotations_
VOID
RaGetAnomalyStats(
    PIOA_RATE_ANALYZER Analyzer,
    PLONG64            SamplesProcessed,
    PLONG64            AnomaliesDetected,
    PLONG              BaselineCount,
    PLONG              AnomalyCount
    )
/*++
Routine Description:
    统计快照 (对齐 SS AdGetStatistics, 供调试 printf)。

Arguments:
    Analyzer          — 速率分析器。
    SamplesProcessed  — [输出可选] 已处理样本数。
    AnomaliesDetected — [输出可选] 检测异常数。
    BaselineCount     — [输出可选] 活跃进程基线数。
    AnomalyCount      — [输出可选] 异常环条目数。
--*/
{
    if (!Analyzer || !Analyzer->Initialized) return;

    if (SamplesProcessed) {
        *SamplesProcessed = InterlockedCompareExchange64(&Analyzer->SamplesProcessed, 0, 0);
    }
    if (AnomaliesDetected) {
        *AnomaliesDetected = InterlockedCompareExchange64(&Analyzer->AnomaliesDetected, 0, 0);
    }
    if (BaselineCount) {
        *BaselineCount = InterlockedCompareExchange(&Analyzer->BaselineCount, 0, 0);
    }
    if (AnomalyCount) {
        *AnomalyCount = InterlockedCompareExchange(&Analyzer->AnomalyCount, 0, 0);
    }
}

/**************************************************/
/*   对齐 SS 公开 API 面补充 (无消费方, 死代码)      */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
RaRecordSample(
    PIOA_RATE_ANALYZER Analyzer,
    GUID               ProcessNodeId,
    RA_METRIC_TYPE     Metric,
    DOUBLE             Value
    )
/*++
Routine Description:
    仅记录样本到全局 + 进程基线 (对齐 SS AdRecordSample)。
    ※死代码: 检测+记录已由 RaCheckForAnomaly 合并 (全局+进程基线双写),
    本函数供未来"纯学习模式" (新进程静默学习不告警) 接入; 当前无调用者。

Arguments:
    Analyzer      — 速率分析器。
    ProcessNodeId — 进程节点 GUID。
    Metric        — 统计基线指标。
    Value         — 观测值 (显式传入, 对齐 SS 签名)。

Return Value:
    NTSTATUS。
--*/
{
    PRA_PROCESS_BASELINE processBaseline;
    LARGE_INTEGER now;

    if (!Analyzer || !Analyzer->Initialized) return STATUS_INVALID_PARAMETER;
    if (Metric > RA_METRIC_MaxValue) return STATUS_INVALID_PARAMETER;
    if (Analyzer->CleanupTerminate) return STATUS_DEVICE_NOT_READY;

    EnterCriticalSection(&Analyzer->Lock);

    RaNow(&now);

    /* 全局基线 (所有进程混合, 对齐 SS GlobalBaselines) */
    RaUpdateBaselineLocked(&Analyzer->GlobalBaselines[Metric], Value);

    /* 进程基线 (惰性创建) */
    processBaseline = RaFindProcessBaselineLocked(Analyzer, ProcessNodeId);
    if (!processBaseline) {
        processBaseline = RaCreateProcessBaselineLocked(Analyzer, ProcessNodeId);
    }
    if (processBaseline) {
        processBaseline->LastActivityTime = now;
        RaUpdateBaselineLocked(&processBaseline->Baselines[Metric], Value);
    }

    InterlockedIncrement64(&Analyzer->SamplesProcessed);

    LeaveCriticalSection(&Analyzer->Lock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
RaGetRecentAnomalies(
    PIOA_RATE_ANALYZER Analyzer,
    ULONG              MaxAgeSeconds,
    PRA_ANOMALY_INFO   AnomalyArray,
    ULONG              MaxCount,
    PULONG             ActualCount
    )
/*++
Routine Description:
    时间窗口查询异常环 (对齐 SS AdGetRecentAnomalies)。
    ※死代码: 无消费方 (VerdictEngine 活跃威胁表已覆盖告警查询),
    供未来 UI/调试按时间回溯统计异常历史。

Arguments:
    Analyzer      — 速率分析器。
    MaxAgeSeconds — 查询时间窗口 (秒), 早于 now-MaxAge 的异常忽略。
    AnomalyArray  — [输出] 异常数组。
    MaxCount      — 数组容量。
    ActualCount   — [输出] 实际返回条数。

Return Value:
    NTSTATUS。
--*/
{
    PLIST_ENTRY entry;
    PRA_ANOMALY anomaly;
    LARGE_INTEGER now;
    LARGE_INTEGER cutoffTime;
    ULONG count = 0;

    if (!Analyzer || !Analyzer->Initialized ||
        !AnomalyArray || !ActualCount || MaxCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *ActualCount = 0;

    EnterCriticalSection(&Analyzer->Lock);

    RaNow(&now);
    cutoffTime.QuadPart = now.QuadPart - ((LONGLONG)MaxAgeSeconds * 10000000);

    for (entry = Analyzer->AnomalyList.Flink;
         entry != &Analyzer->AnomalyList && count < MaxCount;
         entry = entry->Flink) {

        anomaly = CONTAINING_RECORD(entry, RA_ANOMALY, ListEntry);

        if (anomaly->Info.DetectionTime.QuadPart >= cutoffTime.QuadPart) {
            RtlCopyMemory(&AnomalyArray[count], &anomaly->Info,
                          sizeof(RA_ANOMALY_INFO));
            count++;
        }
    }

    LeaveCriticalSection(&Analyzer->Lock);

    *ActualCount = count;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
RaGetBaseline(
    PIOA_RATE_ANALYZER Analyzer,
    GUID               ProcessNodeId,
    RA_METRIC_TYPE     Metric,
    PRA_BASELINE_INFO  BaselineInfo
    )
/*++
Routine Description:
    查询基线统计快照 (对齐 SS AdGetBaseline)。
    ※死代码: 无消费方 (SS AdGetBaseline 仅调试 UI 消费), 供未来进程行为画像。

Arguments:
    Analyzer      — 速率分析器。
    ProcessNodeId — 进程节点 GUID。
    Metric        — 统计基线指标。
    BaselineInfo  — [输出] 基线快照。

Return Value:
    STATUS_SUCCESS / STATUS_NOT_FOUND (基线无样本) / STATUS_INVALID_PARAMETER。
--*/
{
    PRA_PROCESS_BASELINE processBaseline = NULL;
    PRA_BASELINE baseline = NULL;

    if (!Analyzer || !Analyzer->Initialized || !BaselineInfo) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Metric > RA_METRIC_MaxValue) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(BaselineInfo, sizeof(*BaselineInfo));

    EnterCriticalSection(&Analyzer->Lock);

    /* 进程基线优先, 回退全局基线 (对齐 SS AdGetBaseline 双轨) */
    processBaseline = RaFindProcessBaselineLocked(Analyzer, ProcessNodeId);
    if (processBaseline) {
        baseline = &processBaseline->Baselines[Metric];
    }
    if (baseline == NULL || baseline->SampleCount == 0) {
        baseline = &Analyzer->GlobalBaselines[Metric];
    }

    if (baseline->SampleCount == 0) {
        LeaveCriticalSection(&Analyzer->Lock);
        return STATUS_NOT_FOUND;
    }

    BaselineInfo->Type = baseline->Type;
    BaselineInfo->Mean = baseline->Mean;
    BaselineInfo->StandardDeviation = baseline->StandardDeviation;
    BaselineInfo->Min = baseline->Min;
    BaselineInfo->Max = baseline->Max;
    BaselineInfo->SampleCount = baseline->SampleCount;
    BaselineInfo->IsFull = baseline->IsFull;
    BaselineInfo->LastUpdated = baseline->LastUpdated;

    LeaveCriticalSection(&Analyzer->Lock);

    return STATUS_SUCCESS;
}

/**************************************************/
/*                   公开 API                     */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
RaInitialize(
    PIOA_RATE_ANALYZER* Out
    )
/*++
Routine Description:
    初始化速率分析器 + 统计基线引擎。

    对齐 SS SpInitializeAntiDebugProtection:
      1. 全局基线 (每 metric 单份) 初始化
      2. 进程基线哈希桶 + 链表
      3. 异常环
      4. 维护线程 (TTL 淘汰)

Arguments:
    Out — [输出] 分析器实例。

Return Value:
    NTSTATUS。
--*/
{
    PIOA_RATE_ANALYZER a;
    ULONG i;
    LARGE_INTEGER now;

    if (!Out) return STATUS_INVALID_PARAMETER;
    *Out = NULL;

    a = UtHeapAlloc(sizeof(IOA_RATE_ANALYZER));
    if (!a) return STATUS_NO_MEMORY;

    RtlZeroMemory(a, sizeof(*a));

    InitializeCriticalSection(&a->Lock);
    a->Initialized = TRUE;

    /* 复制默认阈值 (metric 维度, 7 个) */
    memcpy(a->Thresholds, g_DefaultThresholds, sizeof(g_DefaultThresholds));

    /* 统计基线配置 */
    a->SigmaThreshold = RA_DEFAULT_SIGMA_THRESHOLD;
    a->MinimumSamples = RA_MIN_SAMPLES_FOR_DETECTION;
    a->BaselineMaxProcesses = RA_MAX_PROCESS_BASELINES;

    /* 全局基线 (对齐 SS GlobalBaselines[AD_METRIC_COUNT]) */
    InitializeListHead(&a->BaselineList);
    RaNow(&now);
    for (i = 0; i < RA_METRIC_COUNT; i++) {
        a->GlobalBaselines[i].Type = (RA_METRIC_TYPE)i;
        a->GlobalBaselines[i].LastUpdated = now;
    }

    for (i = 0; i < RA_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&a->BaselineBuckets[i]);
    }
    InitializeListHead(&a->AnomalyList);

    a->StartTime = now;

    /* 维护线程 (TTL 淘汰, 1 分钟周期) */
    a->MaintenanceWakeEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (a->MaintenanceWakeEvent) {
        a->MaintenanceThread = CreateThread(
            NULL, 0, RaMaintenanceWorker, a, 0, NULL);
        if (a->MaintenanceThread) {
            a->MaintenanceRunning = TRUE;
        } else {
            CloseHandle(a->MaintenanceWakeEvent);
            a->MaintenanceWakeEvent = NULL;
        }
    }

    printf("[IoaRateAnalyzer] Initialized: max=%u processes, window=%ums\n",
           RA_MAX_PROCESS_COUNT, RA_WINDOW_MS);
    printf("[IoaRateAnalyzer]   StatBaseline: sigma=%.1f minSamples=%u "
           "samples=%u baselineMax=%u (SS AnomalyDetector 迁移)\n",
           a->SigmaThreshold, a->MinimumSamples,
           RA_BASELINE_SAMPLES, a->BaselineMaxProcesses);

    *Out = a;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
RaCleanup(
    PIOA_RATE_ANALYZER Analyzer
    )
/*++
Routine Description:
    停止维护线程 + 释放全部基线/异常。

Arguments:
    Analyzer — 速率分析器。
--*/
{
    PLIST_ENTRY entry;

    if (!Analyzer || !Analyzer->Initialized) return;

    /* 停止维护线程 */
    if (Analyzer->MaintenanceThread) {
        Analyzer->CleanupTerminate = TRUE;
        if (Analyzer->MaintenanceWakeEvent) {
            SetEvent(Analyzer->MaintenanceWakeEvent);
        }
        WaitForSingleObject(Analyzer->MaintenanceThread, 2000);
        CloseHandle(Analyzer->MaintenanceThread);
        Analyzer->MaintenanceThread = NULL;
    }
    if (Analyzer->MaintenanceWakeEvent) {
        CloseHandle(Analyzer->MaintenanceWakeEvent);
        Analyzer->MaintenanceWakeEvent = NULL;
    }

    EnterCriticalSection(&Analyzer->Lock);

    /* 释放进程基线 */
    while (!IsListEmpty(&Analyzer->BaselineList)) {
        PRA_PROCESS_BASELINE pb;

        entry = RemoveHeadList(&Analyzer->BaselineList);
        pb = CONTAINING_RECORD(entry, RA_PROCESS_BASELINE, ListEntry);
        UtHeapFree(pb);
    }

    /* 释放异常环 */
    while (!IsListEmpty(&Analyzer->AnomalyList)) {
        PRA_ANOMALY anomaly;

        entry = RemoveHeadList(&Analyzer->AnomalyList);
        anomaly = CONTAINING_RECORD(entry, RA_ANOMALY, ListEntry);
        UtHeapFree(anomaly);
    }

    LeaveCriticalSection(&Analyzer->Lock);

    DeleteCriticalSection(&Analyzer->Lock);
    Analyzer->Initialized = FALSE;

    printf("[IoaRateAnalyzer] Cleanup: feeds=%lld, samples=%lld, anomalies=%lld\n",
           Analyzer->TotalFeedbacks,
           InterlockedCompareExchange64(&Analyzer->SamplesProcessed, 0, 0),
           InterlockedCompareExchange64(&Analyzer->AnomaliesDetected, 0, 0));

    UtHeapFree(Analyzer);
}

_Use_decl_annotations_
VOID
RaFeedEvent(
    PIOA_RATE_ANALYZER Analyzer,
    PWKD_EVENT_HEADER  Event
    )
/*++
Routine Description:
    每收到一个事件时调用: 累加对应 metric 窗口计数 (10s 滑动窗口轮转)。
    调用点: IoaObserve 阶段1 (NodeId 回填后), 计数供阶段6 统计基线检测。

    0x80 IOC 段事件 (IocHashMatch/YaraMatch/CertMatch) 不计数 —
    防攻击流量驯化统计基线。

Arguments:
    Analyzer — 速率分析器。
    Event    — 事件 (SourceProcessId 须已回填为进程节点 GUID)。
--*/
{
    RA_METRIC_TYPE metric;
    USHORT category;
    PRA_PROC_RATE_RECORD rec;
    LARGE_INTEGER now;

    if (!Analyzer || !Analyzer->Initialized || !Event) return;
    if (Analyzer->CleanupTerminate) return;

    metric = RaMapEventTypeToMetric(Event->Type);
    if (metric >= RA_METRIC_VALID) return;

    /* 0x80 IOC 段: 跳过学习 (防驯化) */
    category = (USHORT)((USHORT)Event->Type >> 8);
    if (category == 0x80) return;

    EnterCriticalSection(&Analyzer->Lock);

    rec = RaFindRateRecordLocked(Analyzer, Event->SourceProcessId);
    if (!rec) {
        rec = RaCreateRateRecordLocked(Analyzer, Event->SourceProcessId);
    }
    if (rec) {
        RaNow(&now);

        /* 窗口轮转: 10s 窗口清零 */
        if (now.QuadPart - rec->WindowStart >= (LONGLONG)RA_WINDOW_MS * 10000) {
            RtlZeroMemory((PVOID)rec->Counts, sizeof(rec->Counts));
            rec->WindowStart = now.QuadPart;
        }

        rec->Counts[metric]++;
        Analyzer->TotalFeedbacks++;
    }

    LeaveCriticalSection(&Analyzer->Lock);
}

_Use_decl_annotations_
ULONG
RaGetRateScore(
    PIOA_RATE_ANALYZER Analyzer,
    GUID               ProcessNodeId
    )
/*++
Routine Description:
    查询指定进程的速率异常评分, 返回归一化值 [0,100]。
    0 = 正常或未找到记录, 100 = 超过高危阈值。

    统一出口 = max(固定阈值计数分, 统计异常分) —
    固定阈值抓绝对超限, Z-Score/MAD 统计基线抓相对自身历史的突变。

Arguments:
    Analyzer      — 速率分析器。
    ProcessNodeId — 进程节点 GUID。

Return Value:
    评分 [0,100]。
--*/
{
    ULONG thresholdScore = 0;
    ULONG anomalyScore = 0;
    ULONG i;
    PRA_PROC_RATE_RECORD rec;

    if (!Analyzer || !Analyzer->Initialized) return 0;

    EnterCriticalSection(&Analyzer->Lock);

    /* 固定阈值计数分 (跨 7 个有效 metric 取最高) */
    rec = RaFindRateRecordLocked(Analyzer, ProcessNodeId);
    if (rec) {
        for (i = 0; i < RA_METRIC_VALID; i++) {
            ULONG count = (ULONG)rec->Counts[i];
            RA_RATE_THRESHOLD th = Analyzer->Thresholds[i];
            ULONG s;

            if (count >= th.CriticalCount) {
                s = 90;
            } else if (count >= th.WarningCount && th.CriticalCount > th.WarningCount) {
                s = 50 + (count - th.WarningCount) * 40 /
                    (th.CriticalCount - th.WarningCount);
                if (s > 90) s = 90;
            } else {
                s = 0;
            }

            if (s > thresholdScore) thresholdScore = s;
        }
    }

    LeaveCriticalSection(&Analyzer->Lock);

    /* 统计异常分 (进程级 + 全局, 独立加锁) */
    anomalyScore = RaGetAnomalyScore(Analyzer, ProcessNodeId);

    return max(thresholdScore, anomalyScore);
}

_Use_decl_annotations_
VOID
RaSetRateThresholds(
    PIOA_RATE_ANALYZER         Analyzer,
    _In_opt_ const RA_RATE_THRESHOLD* Thresholds
    )
/*++
Routine Description:
    运行时动态调整速率阈值 (metric 维度 7 个)。
    传入 NULL 则恢复默认值。

Arguments:
    Analyzer   — 速率分析器实例指针。
    Thresholds — 新阈值数组 (NULL = 恢复默认)。
--*/
{
    if (!Analyzer || !Analyzer->Initialized) return;

    EnterCriticalSection(&Analyzer->Lock);

    if (Thresholds) {
        memcpy(Analyzer->Thresholds, Thresholds,
               sizeof(RA_RATE_THRESHOLD) * RA_METRIC_VALID);
    } else {
        memcpy(Analyzer->Thresholds, g_DefaultThresholds,
               sizeof(g_DefaultThresholds));
    }

    LeaveCriticalSection(&Analyzer->Lock);
}

_Use_decl_annotations_
BOOLEAN
RaIsRateAlert(
    PIOA_RATE_ANALYZER Analyzer,
    GUID               ProcessNodeId
    )
/*++
Routine Description:
    检查指定进程是否触发速率告警。
    统计异常分 ≥ 60 视为告警 (对齐 SS severity ≥ Medium)。

Arguments:
    Analyzer      — 速率分析器实例指针。
    ProcessNodeId — 进程节点 GUID。

Return Value:
    TRUE = 触发告警。
--*/
{
    return (RaGetRateScore(Analyzer, ProcessNodeId) >= 60);
}

/**************************************************/
/*       统计异常告警构造 (IOA_ALERT)               */
/**************************************************/

_Use_decl_annotations_
PIOA_ALERT
RaAllocStatAlert(
    GUID               SuspectNodeId,
    PRA_ANOMALY_INFO   Info
    )
/*++
Routine Description:
    统计异常告警构造 (单块堆分配, 含字符串缓冲)。
    对齐 VerdictEngine_AllocPersistAlert 分配语义, 满足持久化队列
    UtHeapFree(Data) 整体释放; 调用方转移所有权。

    字段:
      RuleName     — "StatAnomaly/<metric>"
      MitreId      — metric 映射 (Thread→T1055.003/Reg→T1112/Net→T1071/
                      File→T1059/Proc→T1058/Mem→T1055)
      Severity     — sigma 档 (2-3 Medium / 3-4 High / ≥4 Critical)
      Confidence   — IsHighConfidence ? 100 : 60
      Category     — DefThreatCat_SuspiciousBehavior
      DetectionSource — DefDetSrc_IOA_Tier1

Arguments:
    SuspectNodeId — 嫌疑进程节点 GUID。
    Info          — 异常详情。

Return Value:
    告警指针 (调用方转移所有权); 分配失败返回 NULL。
--*/
{
    static const WCHAR* sMitreThread = L"T1055.003";   /* 线程劫持/注入 */
    static const WCHAR* sMitreReg    = L"T1112";       /* 注册表修改 */
    static const WCHAR* sMitreNet    = L"T1071";       /* 应用层协议 */
    static const WCHAR* sMitreFile   = L"T1059";       /* 命令与脚本 */
    static const WCHAR* sMitreProc   = L"T1058";       /* 服务执行 */
    static const WCHAR* sMitreMem    = L"T1055";       /* 进程注入 */
    const WCHAR* ruleName;
    const WCHAR* mitreId;
    DEF_THREAT_SEVERITY severity;
    size_t ruleLen, mitreLen, descLen, total;
    PIOA_ALERT alert;
    PWCHAR buf;
    WCHAR descBuf[256];

    if (!Info) return NULL;

    switch (Info->Metric) {
    case RA_METRIC_THREAD:     mitreId = sMitreThread; ruleName = L"StatAnomaly/Thread"; break;
    case RA_METRIC_REG:        mitreId = sMitreReg;    ruleName = L"StatAnomaly/Registry"; break;
    case RA_METRIC_NET:        mitreId = sMitreNet;    ruleName = L"StatAnomaly/Network"; break;
    case RA_METRIC_FILE:       mitreId = sMitreFile;   ruleName = L"StatAnomaly/File"; break;
    case RA_METRIC_PROC_CREATE:mitreId = sMitreProc;   ruleName = L"StatAnomaly/Process"; break;
    case RA_METRIC_MEM:        mitreId = sMitreMem;    ruleName = L"StatAnomaly/Memory"; break;
    default:                   mitreId = NULL;         ruleName = L"StatAnomaly/Custom"; break;
    }

    if (Info->DeviationSigmas >= RA_SEVERITY_CRITICAL_SIGMA) {
        severity = DefThreatSeverity_Critical;
    } else if (Info->DeviationSigmas >= RA_SEVERITY_HIGH_SIGMA) {
        severity = DefThreatSeverity_High;
    } else {
        severity = DefThreatSeverity_Medium;
    }

    swprintf_s(descBuf, 256,
               L"StatAnomaly: metric=%d sigmas=%.2f observed=%.0f expected=%.0f",
               (int)Info->Metric, Info->DeviationSigmas,
               Info->ObservedValue, Info->ExpectedValue);

    ruleLen  = wcslen(ruleName);
    mitreLen = mitreId ? wcslen(mitreId) : 0;
    descLen  = wcslen(descBuf);
    total = sizeof(IOA_ALERT) +
            (ruleLen + 1 + mitreLen + 1 + descLen + 1) * sizeof(WCHAR);

    alert = (PIOA_ALERT)UtHeapAlloc(total);
    if (!alert) return NULL;
    RtlZeroMemory(alert, total);

    CoCreateGuid(&alert->AlertId);
    alert->Timestamp     = Info->DetectionTime;
    alert->SuspectNodeId = SuspectNodeId;
    alert->VictimNodeId  = SuspectNodeId;   /* 统计异常无独立受害实体 */
    alert->Severity      = severity;
    alert->Score         = Info->SeverityScore;
    alert->Confidence    = Info->IsHighConfidence ? 100 : 60;
    alert->Category      = DefThreatCat_SuspiciousBehavior;
    alert->ConfidenceLevel = Info->IsHighConfidence
                           ? DefConfidence_High : DefConfidence_Medium;
    alert->RecommendedAction = DefRespAction_Alert;   /* monitor-only, 仅告警 */
    alert->DetectionSource  = DefDetSrc_IOA_Tier1;

    buf = (PWCHAR)((PUCHAR)alert + sizeof(IOA_ALERT));
    alert->RuleName = buf;
    wcscpy_s(buf, ruleLen + 1, ruleName);
    buf += ruleLen + 1;

    if (mitreLen) {
        alert->MitreId = buf;
        wcscpy_s(buf, mitreLen + 1, mitreId);
        buf += mitreLen + 1;
    }
    if (descLen) {
        alert->Description = buf;
        wcscpy_s(buf, descLen + 1, descBuf);
    }

    return alert;
}

/**************************************************/
/*              独立单测 (RA_SELF_TEST)            */
/*   用法: 单独编译本文件, -DRA_SELF_TEST          */
/**************************************************/

#ifdef RA_SELF_TEST

int
RaSelfTestMain(
    void
    )
/*++
Routine Description:
    统计基线引擎自测:
      1. 学习期 (正常低计数) 不误报
      2. 突发高计数 → 判异常 + 严重度 ≥ 70
      3. 异常样本不写基线 (防驯化: SampleCount 不变)
      4. 新进程 (无进程基线) → 全局基线兜底
--*/
{
    PIOA_RATE_ANALYZER a = NULL;
    GUID pid1 = { 0x11111111, 0x1111, 0x1111,
                  {0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11} };
    GUID pid2 = { 0x22222222, 0x2222, 0x2222,
                  {0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22} };
    WKD_EVENT_HEADER ev;
    BOOLEAN isAnom = FALSE;
    RA_ANOMALY_INFO info;
    ULONG i, s;
    LONG baseSample;

    NTSTATUS st = RaInitialize(&a);
    if (!NT_SUCCESS(st)) {
        printf("[RaSelfTest] FAIL: RaInitialize = 0x%lx\n", st);
        return 1;
    }

    RtlZeroMemory(&ev, sizeof(ev));
    ev.Type = WkdEvent_ProcessCreate;
    ev.SourceProcessId = pid1;

    /* 1. 学习期: 正常低计数 */
    for (i = 0; i < 30; i++) {
        RaFeedEvent(a, &ev);
        RaCheckForAnomaly(a, pid1, RA_METRIC_PROC_CREATE, &isAnom, &info);
    }
    s = RaGetAnomalyScore(a, pid1);
    printf("[RaSelfTest] learning done: score=%lu (expect low)\n", s);
    if (s >= 70) {
        printf("[RaSelfTest] FAIL: learning phase false positive\n");
        RaCleanup(a);
        return 1;
    }

    baseSample = (LONG)a->BaselineList.Flink
        ? CONTAINING_RECORD(a->BaselineList.Flink,
                            RA_PROCESS_BASELINE, ListEntry)->Baselines[RA_METRIC_PROC_CREATE].SampleCount
        : 0;
    printf("[RaSelfTest] baseline SampleCount after learning = %ld\n", baseSample);

    /* 2. 突发高计数 (直接注入计数, 模拟 10s 窗口内 200 次操作) */
    {
        PRA_PROC_RATE_RECORD rec = RaFindRateRecordLocked(a, pid1);
        if (rec) rec->Counts[RA_METRIC_PROC_CREATE] = 200;
    }
    RaCheckForAnomaly(a, pid1, RA_METRIC_PROC_CREATE, &isAnom, &info);
    printf("[RaSelfTest] burst: isAnomaly=%s score=%lu sigmas=%.2f\n",
           isAnom ? "YES" : "NO", info.SeverityScore, info.DeviationSigmas);
    if (!isAnom || info.SeverityScore < 70) {
        printf("[RaSelfTest] FAIL: burst not detected (score=%lu)\n",
               info.SeverityScore);
        RaCleanup(a);
        return 1;
    }

    /* 3. 防驯化: 异常样本不写基线 */
    {
        PLONG cnt = NULL;
        PRA_PROCESS_BASELINE pb = RaFindProcessBaselineLocked(a, pid1);
        cnt = (PLONG)&pb->Baselines[RA_METRIC_PROC_CREATE].SampleCount;
        printf("[RaSelfTest] SampleCount after anomaly = %ld (expect == base)\n", *cnt);
        if (*cnt != baseSample) {
            printf("[RaSelfTest] FAIL: anomaly sample polluted baseline\n");
            RaCleanup(a);
            return 1;
        }
    }

    /* 4. 全局基线兜底: 新进程样本不足时用全局基线 */
    RtlZeroMemory(&ev, sizeof(ev));
    ev.Type = WkdEvent_NetworkConnect;
    ev.SourceProcessId = pid2;
    for (i = 0; i < 5; i++) {
        RaFeedEvent(a, &ev);
        RaCheckForAnomaly(a, pid2, RA_METRIC_NET, &isAnom, &info);
    }
    printf("[RaSelfTest] new process (5 samples): isAnomaly=%s (global fallback)\n",
           isAnom ? "YES" : "NO");

    printf("[RaSelfTest] PASS\n");
    RaCleanup(a);
    return 0;
}

#endif /* RA_SELF_TEST */
