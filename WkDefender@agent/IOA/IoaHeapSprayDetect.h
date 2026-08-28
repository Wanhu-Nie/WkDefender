/**************************************************/
/*  WkDefender IOA 引擎 — 堆喷检测 feature 模块      */
/*                                                  */
/*  迁移自 ShadowStrike HeapSpray.c (2026-08-07),   */
/*  按功能融合重实现非复制。                          */
/*                                                  */
/*  职责 (agent L2 深度分析):                       */
/*   - 每进程分配窗口聚合 (对齐 SS HS_PROCESS_      */
/*     CONTEXT 聚合计数 + HspPruneOldAllocations)    */
/*   - 门控内容采样 (对齐 SS HsRecordAllocation 的   */
/*     PatternSample, 采样移至 agent ReadProcess     */
/*     Memory, 见 Memory/MemoryScan.c MsReadMemory)  */
/*   - 评分 (对齐 SS HspCalculateSprayScore, 0-1000) */
/*   - 告警构造 (对齐 SS HsInvokeCallbacks →         */
/*     IOA_ALERT + PersistQueue, ALPC 覆盖回调)      */
/*                                                  */
/*  死代码: 消费方 IoaEngine 阶段4.11 门控           */
/*  g_IoaHeapSprayEnabled=FALSE, 且驱动 SmInitialize */
/*  注释态 (内存事件不可达)。流水线未接入。           */
/**************************************************/

#pragma once

#include <windows.h>
#include "../DefendTypes.h"
#include "IoaTypes.h"
#include "IoaPersistQueue.h"      /* IOA_ALERT */

/**************************************************/
/*               配置常量                           */
/*  对齐 SS HeapSpray.h                             */
/**************************************************/

#define WKD_HS_MIN_SPRAY_SIZE           (1024 * 1024)            /* 1 MB (SS HS_MIN_SPRAY_SIZE) */
#define WKD_HS_ALLOCATION_WINDOW_MS     5000                     /* 5s 窗口 (SS HS_ALLOCATION_WINDOW_MS) */
#define WKD_HS_MIN_SIMILAR_ALLOCATIONS  100                      /* 触发阈值 (SS HS_MIN_SIMILAR_ALLOCATIONS) */
#define WKD_HS_MIN_SCORE_FOR_SPRAY      500                      /* 判定阈值 (SS HS_MIN_SCORE_FOR_SPRAY) */
#define WKD_HS_HIGH_ALLOC_RATE_THRESHOLD 50                      /* 分配率 /s (SS HS_HIGH_ALLOC_RATE_THRESHOLD) */
#define WKD_HS_MAX_SINGLE_SIZE          ((SIZE_T)0x80000000ULL)  /* 单分配大小护栏 (SS 拒绝 >2GB) */
#define WKD_HS_REPETITION_THRESHOLD     80                       /* 重复度阈值 (SS HS_REPETITION_THRESHOLD, 置 RepeatedPattern 标志) */
#define WKD_HS_LARGE_CONTIGUOUS_SIZE     (10 * 1024 * 1024)      /* 大块连续阈值 (SS HsAnalyzeProcess L1367, 置 LargeContiguous 标志) */

/* 门控采样阈值 (agent 读内存成本控制) */
#define WKD_HS_SAMPLE_RATE_THRESHOLD    25                       /* 分配率 ≥25/s 才采样 */
#define WKD_HS_SAMPLE_ALIGN_THRESHOLD   20                       /* 对齐分配 ≥20 才采样 */

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*++
Routine Description:
    分配事件处理 — 窗口聚合 + 门控内容采样 + 评分 + 判定。
    对齐 SS HsRecordAllocation + HspPruneOldAllocations +
    HspCalculateSprayScore。滑窗采用 IoaRateAnalyzer 轮转
    (到期全清, agent 无 65536 记录池只存聚合计数)。

Arguments:
    State  - 进程堆喷窗口状态 (挂 WKD_PROCESS_BEHAVIOR_STATE.HeapSpray)。
    Pid    - 分配进程 PID。
    Addr   - 实际分配基址 (驱动 Exit 上送, ParameterBase[1])。
    Size   - 实际分配大小 (驱动 Exit 上送, ParameterBase[3])。
    Protect- 分配保护属性 (ParameterBase[5])。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER (Size 护栏拒收)。
--*/
NTSTATUS
IoaHeapSpray_OnAllocate(
    _Inout_ PWKD_HEAP_SPRAY_STATE State,
    _In_ ULONG Pid,
    _In_ ULONG_PTR Addr,
    _In_ SIZE_T Size,
    _In_ ULONG Protect
    );

/*++
Routine Description:
    堆喷评分 (0-1000)。对齐 SS HspCalculateSprayScore:
    rep×3 + count 100~300 + size 100~200 + rate 150 + known 200
    + nopsled 250 + shellcode 300 + exec 100 + aligned 50。

Arguments:
    State - 进程堆喷窗口状态。

Return Value:
    评分 [0,1000]。
--*/
ULONG
IoaHeapSpray_CalculateSprayScore(
    _In_ PWKD_HEAP_SPRAY_STATE State
    );

/*++
Routine Description:
    堆喷告警构造 (单块堆分配, 含字符串缓冲)。
    对齐 RaAllocStatAlert / VerdictEngine_AllocPersistAlert 分配
    语义, 满足持久化队列 UtHeapFree(Data) 整体释放。
    告警字段: RuleName="HeapSpray/Detected", MitreId=T1203
    (高分配率标志命中改 T1499), Severity 按评分分级,
    Category=DefThreatCat_Exploit, DetectionSource=Behavior。
    入队由调用方 (IoaEngine 阶段6) 执行。

Arguments:
    SuspectNodeId - 嫌疑进程节点 GUID (堆喷为进程内自分配)。
    State         - 进程堆喷窗口状态。

Return Value:
    告警指针 (调用方转移所有权); 分配失败返回 NULL。
--*/
PIOA_ALERT
IoaHeapSpray_AllocAlert(
    _In_ GUID SuspectNodeId,
    _In_ PWKD_HEAP_SPRAY_STATE State
    );

/*++
Routine Description:
    堆喷完整分析 (查询 API)。对齐 SS HsAnalyzeProcess。
    ※ 死代码: 供 UI/进程详情查询, 当前无调用者。

Arguments:
    State  - 进程堆喷窗口状态。
    Result - 输出分析结果 (值语义, 无需释放)。

Return Value:
    STATUS_SUCCESS。
--*/
NTSTATUS
IoaHeapSpray_AnalyzeProcess(
    _In_ ULONG Pid,
    _In_ PWKD_HEAP_SPRAY_STATE State,
    _Out_ PWKD_HEAP_SPRAY_RESULT Result
    );

/*++
Routine Description:
    堆喷快速检查 (查询 API)。对齐 SS HsCheckForSpray。
    ※ 死代码: 供快速体检, 当前无调用者。

Arguments:
    State         - 进程堆喷窗口状态。
    SprayDetected - 接收是否判定堆喷。
    Type          - 可选; 接收堆喷类型。
    Score         - 可选; 接收评分。

Return Value:
    STATUS_SUCCESS。
--*/
NTSTATUS
IoaHeapSpray_CheckForSpray(
    _In_ PWKD_HEAP_SPRAY_STATE State,
    _Out_ PBOOLEAN SprayDetected,
    _Out_opt_ PWKD_HEAP_SPRAY_TYPE Type,
    _Out_opt_ PULONG Score
    );
