/**************************************************/
/*  WkDefender IOA — MITRE 技术检测记录器 (死代码)    */
/*                                                   */
/*  ShadowStrike MITREMapper 检测记录功能迁移         */
/*  (MmRecordDetection L1583-1696 /                  */
/*   MmGetRecentDetections L1810-1895), 按功能融合     */
/*  进 IoaMitreMapper 模块, 重功能实现非源码复制.      */
/*                                                   */
/*  死代码原因:                                     */
/*    wkd 告警链路 IOA_ALERT→StPersistAlert→cg_alerts */
/*    已覆盖"检测→单 MITRE 技术落库"持久化; 本记录器   */
/*    补内存态逐技术记录 + 时间窗查询 + 技术维度统计    */
/*    缺口 (SS MITRE 仪表板对应物), 接入前不消费.      */
/*    ProcessName 定长拷贝替代 SS 堆 UNICODE_STRING    */
/*    (防泄漏); GetRecentDetections 拷贝出替代 SS      */
/*    借引用 (无锁防悬垂).                            */
/*                                                   */
/*  用户态重实现要点:                               */
/*    - 静态环形缓冲 4096, 满员覆盖最旧 (对齐 SS       */
/*      头删尾插 LRU L1664)                          */
/*    - 无锁, 单线程/未接入假设 (SS 内核 SpinLock      */
/*      在用户态静态数据场景无并发竞争, 舍弃)          */
/*    - ConfidenceScore clamp 0-100 (对齐 SS L1616)   */
/*    - 技术必须已知 (对齐 SS L1629 内部 Lookup)      */
/**************************************************/

#include "IoaMitreMapper.h"

static IOA_MITRE_DETECTION g_IoaMitreDetections[IOA_MITRE_DETECTION_MAX];
static ULONG g_IoaMitreHead = 0;                 /* 最旧记录槽 */
static ULONG g_IoaMitreCount = 0;                /* 有效记录数 */
static ULONG g_IoaMitreTotalRecorded = 0;        /* 历史累计 */
static ULONG g_IoaMitrePerTactic[IoATactic_Max] = { 0 };

/**
 * 记录一次 MITRE 技术检测.
 *
 * 对齐 SS MmRecordDetection (L1583-1696):
 *   - 技术必须已加载 (IoaMitreLookupById 命中), 未知名返回 NOT_FOUND
 *     (SS L1629-1634 内部 Lookup, 失败仅忽略; wkd 返回错误更明确).
 *   - ConfidenceScore clamp 0-100 (SS L1616-1618).
 *   - 满员覆盖最旧 (SS L1664-1670 头删尾插).
 *   - 时间戳 GetSystemTimeAsFileTime (SS KeQuerySystemTime).
 *
 * 死代码: 接入时由事件分析/告警侧调用.
 */
NTSTATUS
IoaMitreRecordDetection(
    _In_      PCWSTR    StringId,
    _In_opt_  HANDLE    ProcessId,
    _In_opt_  PCWSTR    ProcessName,
    _In_      ULONG     ConfidenceScore
    )
{
    const IOA_TECHNIQUE_ENTRY* entry;
    PIOA_MITRE_DETECTION rec;
    ULONG slot;

    if (StringId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    entry = IoaMitreLookupById(StringId);
    if (entry == NULL) {
        return STATUS_NOT_FOUND;
    }

    if (ConfidenceScore > 100) {
        ConfidenceScore = 100;
    }

    /* 环形槽: 满员覆盖最旧 (对齐 SS 4096 LRU 头删尾插) */
    if (g_IoaMitreCount < IOA_MITRE_DETECTION_MAX) {
        slot = (g_IoaMitreHead + g_IoaMitreCount) % IOA_MITRE_DETECTION_MAX;
        g_IoaMitreCount++;
    } else {
        slot = g_IoaMitreHead;
        g_IoaMitreHead = (g_IoaMitreHead + 1) % IOA_MITRE_DETECTION_MAX;
    }

    rec = &g_IoaMitreDetections[slot];
    rec->StringId = entry->StringId;    /* 指向静态表串, 无拷贝 */
    rec->ProcessId = ProcessId;
    rec->ConfidenceScore = ConfidenceScore;
    GetSystemTimeAsFileTime(&rec->DetectionTime);
    rec->Valid = TRUE;

    if (ProcessName != NULL) {
        wcsncpy_s(rec->ProcessName, IOA_MITRE_PROCESS_NAME_LEN, ProcessName, _TRUNCATE);
    } else {
        rec->ProcessName[0] = 0;
    }

    g_IoaMitreTotalRecorded++;
    if (entry->TacticBit < IoATactic_Max) {
        g_IoaMitrePerTactic[entry->TacticBit]++;
    }

    return STATUS_SUCCESS;
}

/**
 * 查询时间窗口内的检测记录 (最新→最旧, 拷贝出).
 *
 * 对齐 SS MmGetRecentDetections (L1810-1895):
 *   - MaxAgeSeconds=0 表示全部 (SS L1850-1858).
 *   - 超窗口即停止 (环形内时间从新到旧, SS L1875-1880).
 *   - 拷贝出而非借引用 (SS 引用计数场景, wkd 无锁防悬垂).
 *
 * 死代码: 供未来 MITRE 仪表板/报告查询.
 */
ULONG
IoaMitreGetRecentDetections(
    _In_  ULONG                  MaxAgeSeconds,
    _Out_ PIOA_MITRE_DETECTION   Detections,
    _In_  ULONG                  Max,
    _Out_ ULONG*                 Count
    )
{
    ULONG count = 0;
    FILETIME now;
    ULONGLONG cutoff;
    ULONGLONG recTime;

    if (Detections == NULL || Max == 0) {
        if (Count != NULL) {
            *Count = 0;
        }
        return 0;
    }
    if (Count != NULL) {
        *Count = 0;
    }

    GetSystemTimeAsFileTime(&now);
    cutoff = ((ULONGLONG)now.dwHighDateTime << 32) | now.dwLowDateTime;
    if (MaxAgeSeconds > 0) {
        ULONGLONG age = (ULONGLONG)MaxAgeSeconds * 10000000ULL;
        cutoff = (cutoff > age) ? (cutoff - age) : 0;
    } else {
        cutoff = 0;
    }

    /* 从最新 (head+count-1) 到最旧 (head) 遍历 */
    for (ULONG i = 0; i < g_IoaMitreCount && count < Max; i++) {
        ULONG idx = (g_IoaMitreHead + g_IoaMitreCount - 1 - i) % IOA_MITRE_DETECTION_MAX;
        PIOA_MITRE_DETECTION rec = &g_IoaMitreDetections[idx];

        if (!rec->Valid) {
            continue;
        }
        recTime = ((ULONGLONG)rec->DetectionTime.dwHighDateTime << 32)
                  | rec->DetectionTime.dwLowDateTime;
        if (recTime < cutoff) {
            break;   /* 更旧的记录必然超窗, 停止 (对齐 SS L1875-1880) */
        }
        Detections[count++] = *rec;    /* 拷贝出 */
    }

    if (Count != NULL) {
        *Count = count;
    }
    return count;
}

/**
 * 技术维度统计 (历史累计 + 逐战术直方图).
 *
 * 对齐 SS MM_MAPPER.Stats 思想 (L293-300), 补 wkd
 * IoaTypes.h:94 MitreMappings 从未递增的统计缺口.
 * Lookups/Hits 等计数器无消费方, 舍弃.
 *
 * 死代码: 供 MITRE 仪表板/报告.
 */
VOID
IoaMitreGetStats(
    _Out_opt_ ULONG* TotalCount,
    _Out_opt_ ULONG* PerTacticHistogram
    )
{
    if (TotalCount != NULL) {
        *TotalCount = g_IoaMitreTotalRecorded;
    }
    if (PerTacticHistogram != NULL) {
        for (ULONG i = 0; i < IoATactic_Max; i++) {
            PerTacticHistogram[i] = g_IoaMitrePerTactic[i];
        }
    }
}
