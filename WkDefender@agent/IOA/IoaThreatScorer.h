/**************************************************/
/*  WkDefender IOA — 威胁评分器 (Scorer)              */
/*                                                    */
/*  职责: 纯评分执行者                                  */
/*    - 提供一组回调函数, 按 Policy 选择的策略计算评分   */
/*    - 不做策略选择 (那是 Policy 的职责)               */
/*    - 不直接读事件 (只有 T1Feature)                   */
/*    - 不做分级决策 (那是 Policy/编排器的职责)         */
/*                                                    */
/*  输入: T1_PAIR_FEATURE + 策略上下文                  */
/*  输出: 威胁评分 [0,100]                              */
/**************************************************/

#pragma once

#include "IoaTypes.h"
#include "Tier1/Tier1Engine.h"      /* SCORE_STRATEGY */

/**************************************************/
/*               评分器状态                         */
/**************************************************/

typedef struct _IOA_SCORER {
    BOOLEAN             Initialized;
    ULONG               DecayIntervalMs;        /* EWMA 衰减间隔 */
    volatile LONG64     TotalScoresProduced;    /* 总评分次数 */
} IOA_SCORER, *PIOA_SCORER;

/**************************************************/
/*               Scorer 回调类型                    */
/**************************************************/

/*
 * SCORER_FN — 评分回调函数原型。
 * Feature: T1 特征记录 (只读)。
 * Context: 策略附加上下文 (如基线统计数据、模板表等)。
 * 返回: 威胁评分 [0,100]。
 */
typedef ULONG (*SCORER_FN)(
    _In_ PT1_PAIR_FEATURE Feature,
    _In_opt_ PVOID        Context
    );

/**************************************************/
/*               函数声明                           */
/**************************************************/

NTSTATUS
IoaScorer_Initialize(
    _Out_ PIOA_SCORER* Scorer,
    _In_  ULONG        DecayMs
    );

VOID
IoaScorer_Cleanup(
    _In_ PIOA_SCORER Scorer
    );

/*
 * IoaScorer_Evaluate — Scorer 主入口。
 *
 * 根据 Strategy 选择对应的评分回调, 调用其计算评分。
 *
 * 参数:
 *   Strategy — 评分策略 (由 Policy 选择)。
 *   Feature  — T1 特征记录 (只读)。
 *   Context  — 策略附加上下文 (可 NULL)。
 *
 * 返回值: 威胁评分 [0,100]。
 */
ULONG
IoaScorer_Evaluate(
    _In_ SCORE_STRATEGY     Strategy,
    _In_ PT1_PAIR_FEATURE   Feature,
    _In_opt_ PVOID          Context
    );

/*
 * Scorer_ApplyEwmaDecay — EWMA 平滑 + 时间衰减。
 *
 * 将本次 rawScore 与 T1Feature.CumulativeRiskScore 做 EWMA 混合，
 * 然后根据 LastUpdate 时间差做衰减。
 *
 * 结果写入 T1Feature.CumulativeRiskScore。
 *
 * 参数:
 *   Feature   — T1 特征记录 (读写 CumulativeRiskScore)。
 *   RawScore  — 本次评分器回调产出的原始分 [0,100]。
 *
 * 返回值: 平滑后的最终评分 [0,100]。
 */
ULONG
Scorer_ApplyEwmaDecay(
    _Inout_ PT1_PAIR_FEATURE Feature,
    _In_    ULONG            RawScore
    );

/* ── 各策略回调 (Policy 不直接调用, 由 IoaScorer_Evaluate 分发) ── */

ULONG Scorer_EvalBaseline(
    _In_ PT1_PAIR_FEATURE f,
    _In_opt_ PVOID ctx
    );

ULONG Scorer_EvalTemplate(
    _In_ PT1_PAIR_FEATURE f,
    _In_opt_ PVOID ctx
    );

ULONG Scorer_EvalAccumulate(
    _In_ PT1_PAIR_FEATURE f,
    _In_opt_ PVOID ctx
    );

ULONG Scorer_EvalAnomaly(
    _In_ PT1_PAIR_FEATURE f,
    _In_opt_ PVOID ctx
    );

ULONG Scorer_EvalContext(
    _In_ PT1_PAIR_FEATURE f,
    _In_opt_ PVOID ctx
    );

ULONG Scorer_EvalT2Feedback(
    _In_ PT1_PAIR_FEATURE f,
    _In_opt_ PVOID ctx
    );
