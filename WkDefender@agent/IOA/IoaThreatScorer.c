/**************************************************/
/*  WkDefender IOA — 威胁评分器实现                   */
/*                                                    */
/*  重构:                                              */
/*    - ATTACK_TEMPLATE 精简为位图模式匹配               */
/*    - Scorer_MatchTemplates 改用覆盖率匹配            */
/*    - 上下文调节因子迁移至 Policy 层                   */
/*    - 移除 MITRE ID (归 Tier3 IoaMitreMapper)         */
/**************************************************/

#include "IoaThreatScorer.h"
#include "IoaEngine.h"
#include "Tier1/Tier1Engine.h"

/**************************************************/
/*               攻击模板定义                        */
/*   供 SCORE_BY_TEMPLATE 策略使用                  */
/*   纯位图模式: RequiredDataMask + RequiredSemMask */
/**************************************************/

static const ATTACK_TEMPLATE g_AttackTemplates[] = {

    /* ── DLL 注入 (Opens+WritesTo+InjectsInto → DLL_INJECTION) ── */
    {
        L"DllInjection",
        (1ULL << DefEdge_Opens) | (1ULL << DefEdge_WritesTo) | (1ULL << DefEdge_InjectsInto),
        (1ULL << BM_SEM_DLL_INJECTION),
        50,     /* 数据层至少50%覆盖 */
        75,     /* BaseScore */
    },

    /* ── APC 注入 (Opens+Allocates+WritesTo+InjectsInto → APC_INJECTION) ── */
    {
        L"ApcInjection",
        (1ULL << DefEdge_Opens) | (1ULL << DefEdge_Allocates) |
            (1ULL << DefEdge_WritesTo) | (1ULL << DefEdge_InjectsInto),
        (1ULL << BM_SEM_APC_INJECTION),
        40,
        80,
    },

    /* ── 进程镂空 (Allocates+WritesTo+Protects+Hollows → PROCESS_HOLLOWING) ── */
    {
        L"ProcessHollowing",
        (1ULL << DefEdge_Allocates) | (1ULL << DefEdge_WritesTo) |
            (1ULL << DefEdge_Protects) | (1ULL << DefEdge_Hollows),
        (1ULL << BM_SEM_PROCESS_HOLLOWING),
        50,
        90,
    },

    /* ── 凭证窃取 (Opens+ReadsFrom → CREDENTIAL_DUMPING) ── */
    {
        L"CredentialDumping",
        (1ULL << DefEdge_Opens) | (1ULL << DefEdge_ReadsFrom),
        (1ULL << BM_SEM_CREDENTIAL_DUMPING),
        40,
        85,
    },

    /* ── Token 操纵 (Impersonates → TOKEN_MANIPULATE) ── */
    {
        L"TokenManipulation",
        (1ULL << DefEdge_Impersonates),
        (1ULL << BM_SEM_TOKEN_MANIPULATE),
        30,
        70,
    },

    /* ── DLL 侧加载 (Sideloads → DLL_SIDE_LOADING) ── */
    {
        L"DllSideLoading",
        (1ULL << DefEdge_Sideloads),
        (1ULL << BM_SEM_DLL_SIDE_LOADING),
        30,
        55,
    },

    /* ── 线程劫持 (Opens+Allocates+AssociatedWith → THREAD_HIJACK) ── */
    {
        L"ThreadHijack",
        (1ULL << DefEdge_Opens) | (1ULL << DefEdge_Allocates) |
            (1ULL << DefEdge_AssociatedWith),
        (1ULL << BM_SEM_THREAD_HIJACK),
        40,
        65,
    },

    /* ── 反射加载 (ReflectiveLoad → REFLECTIVE_LOAD) ── */
    {
        L"ReflectiveLoad",
        (1ULL << DefEdge_ReflectiveLoad),
        (1ULL << BM_SEM_REFLECTIVE_LOAD),
        30,
        60,
    },

    /* ── 原子炸弹 (InjectsInto(QueueApc)+Opens → ATOM_BOMBING) ── */
    {
        L"AtomBombing",
        (1ULL << DefEdge_InjectsInto) | (1ULL << DefEdge_Opens),
        (1ULL << BM_SEM_ATOM_BOMBING),
        40,
        85,
    },

    /* 哨兵 */
    { NULL, 0, 0, 0, 0 }
};

#define TPL_COUNT (sizeof(g_AttackTemplates) / sizeof(g_AttackTemplates[0]) - 1)

/**************************************************/
/*         内部: 攻击模板匹配 (覆盖率)               */
/**************************************************/

static
ULONG
Scorer_MatchTemplates(
    _In_ PINTERACTION_BITMAP Bitmap,
    _In_ PT1_PAIR_FEATURE    f
    )
/*++
Routine Description:
    基于覆盖率匹配攻击模板。

    对每个模板:
      1. 数据层覆盖率 = popcount(DataMask ∩ dataDword) / popcount(DataMask)
      2. 语义层覆盖率 = RequiredSemMask ∩ semDword 是否 != 0 (二值)
      3. 数据层覆盖率 >= MinCoveragePct → 匹配
      4. 语义层命中 → 完整匹配 (×1.0); 未命中但数据层达标 → 部分匹配 (×0.7)
      5. 上下文微调: 系统进程目标放大, 低完整性放大

    Arguments:
        Bitmap — 进程对的 InteractionBitmap。
        f      — T1 特征记录 (用于上下文调节)。

    Return Value:
        最佳匹配模板的评分 [0,100]。无匹配返回 0。
--*/
{
    ULONG64 dataDword = BM_DATA_U64(Bitmap);
    ULONG64 semDword  = BM_SEM_U64(Bitmap);
    ULONG bestScore = 0;

    for (ULONG i = 0; i < TPL_COUNT; i++) {
        const ATTACK_TEMPLATE* tpl = &g_AttackTemplates[i];
        ULONG dataRequiredPop, dataMatchPop, dataCoverage;
        BOOLEAN semHit;
        ULONG score;

        if (!tpl->Name) continue;

        /* 数据层覆盖率 */
        dataRequiredPop = (ULONG)__popcnt64(tpl->RequiredDataMask);
        if (dataRequiredPop == 0) continue;

        dataMatchPop = (ULONG)__popcnt64(dataDword & tpl->RequiredDataMask);
        dataCoverage = dataMatchPop * 100 / dataRequiredPop;

        if (dataCoverage < tpl->MinCoveragePct) continue;

        /* 语义层检查: 至少一位命中 */
        semHit = (tpl->RequiredSemMask != 0 &&
                  (semDword & tpl->RequiredSemMask) != 0);

        /* 基础分 = BaseScore × 覆盖率 */
        score = tpl->BaseScore * dataCoverage / 100;

        /* 语义层未命中 → 部分匹配降权 */
        if (!semHit && tpl->RequiredSemMask != 0) {
            score = score * 70 / 100;   /* ×0.7 */
        }

        /* 上下文微调 (简化版, 复杂调节交给 Policy 层) */
        if (f->TgtIsSystemProcess) {
            score = min(score * 120 / 100, 100);  /* +20% */
        }
        if (f->SrcIntegrityLevel > 0 &&
            f->SrcIntegrityLevel <= SECURITY_MANDATORY_LOW_RID) {
            score = min(score * 130 / 100, 100);  /* +30% 低完整性源 */
        }

        if (score > bestScore) bestScore = score;
    }

    return min(bestScore, 100);
}

/**************************************************/
/*         各策略回调实现                           */
/**************************************************/

ULONG
Scorer_EvalBaseline(
    _In_ PT1_PAIR_FEATURE f,
    _In_opt_ PVOID ctx
    )
/*++
Routine Description:
    轻量基线 — 几乎无异常时最便宜的评分。
--*/
{
    UNREFERENCED_PARAMETER(ctx);

    if (!f) return 0;

    if (f->PairEventCount > 0) return min((ULONG)(f->PairEventCount / 10), 5);
    return 0;
}

ULONG
Scorer_EvalTemplate(
    _In_ PT1_PAIR_FEATURE f,
    _In_opt_ PVOID ctx
    )
/*++
Routine Description:
    攻击模板匹配 — 基于位图覆盖率匹配预定义攻击模式。

    Context 参数传递 PINTERACTION_BITMAP (从 PairCtx->InteractionBitmap)。
--*/
{
    PINTERACTION_BITMAP bm;

    if (!f) return 0;

    bm = (PINTERACTION_BITMAP)ctx;
    if (!bm) return 0;

    return Scorer_MatchTemplates(bm, f);
}

ULONG
Scorer_EvalAccumulate(
    _In_ PT1_PAIR_FEATURE f,
    _In_opt_ PVOID ctx
    )
/*++
Routine Description:
    模式累积 — 多个弱信号共现时的策略。

    信号计数来源:
      - 语义层 popcount (从 T1Feature.SemanticPopcount 快照)
      - 谱系异常标志
      - 速率广度
--*/
{
    ULONG signalCount;
    ULONG score;
    PINTERACTION_BITMAP bm;

    UNREFERENCED_PARAMETER(ctx);

    if (!f) return 0;

    /* 独立信号计数 */
    signalCount  = f->SemanticPopcount;                    /* 语义层命中数 */
    signalCount += (f->SrcGenealogyFlags ? 1 : 0);         /* 源谱系异常 */
    signalCount += (f->TgtGenealogyFlags ? 1 : 0);         /* 目标谱系异常 */
    signalCount += f->RuleHitCount;                        /* 规则命中 */

    /* 非线性阶梯映射 */
    if (signalCount <= 2)       score = 10;
    else if (signalCount <= 4)  score = 30;
    else if (signalCount <= 6)  score = 50;
    else                         score = 70;

    /* 速率放大 */
    if (f->ActiveOutTargets >= 5 && score >= 30) {
        score = min(score + 15, 100);
    }
    if (f->ActiveInSources >= 3 && score >= 30) {
        score = min(score + 10, 100);
    }

    /* 语义层命中时额外放大 — 弱信号但有已确认的攻击模型 */
    bm = (PINTERACTION_BITMAP)ctx;
    if (bm) {
        ULONG64 semDword = BM_SEM_U64(bm);
        if (semDword & BM_MASK_L2_SEMANTIC) {
            score = min(score + 20, 100);  /* L2 高级语义命中 → 大幅提升信度 */
        }
    }

    return score;
}

ULONG
Scorer_EvalAnomaly(
    _In_ PT1_PAIR_FEATURE f,
    _In_opt_ PVOID ctx
    )
/*++
Routine Description:
    异常偏离 — 无恶意标志、无组合信号、仅统计异常时的兜底策略。
--*/
{
    ULONG score = 0;
    ULONG rarityScore = 0;
    ULONG densityScore = 0;

    UNREFERENCED_PARAMETER(ctx);

    if (!f) return 0;

    if (f->ActiveOutTargets >= 10)       rarityScore = 70;
    else if (f->ActiveOutTargets >= 7)   rarityScore = 50;
    else if (f->ActiveOutTargets >= 5)   rarityScore = 30;
    else if (f->ActiveOutTargets >= 3)   rarityScore = 15;

    if (f->ActiveInSources >= 5)         rarityScore = max(rarityScore, 60);
    else if (f->ActiveInSources >= 3)    rarityScore = max(rarityScore, 35);

    if (f->SemanticPopcount >= 4 && f->PairEventCount > 20)  densityScore = 60;
    else if (f->SemanticPopcount >= 3 && f->PairEventCount > 10) densityScore = 40;
    else if (f->SemanticPopcount >= 2)                             densityScore = 20;

    score = max(rarityScore, densityScore);

    if (f->TgtIsSystemProcess && score > 0) {
        score = min(score * 150 / 100, 100);
    }

    return score;
}

ULONG
Scorer_EvalContext(
    _In_ PT1_PAIR_FEATURE f,
    _In_opt_ PVOID ctx
    )
/*++
Routine Description:
    上下文敏感 — 目标为系统进程时的策略。
--*/
{
    ULONG score = 0;
    PINTERACTION_BITMAP bm;

    UNREFERENCED_PARAMETER(ctx);

    if (!f) return 0;

    if (f->TgtIsSystemProcess) {
        bm = (PINTERACTION_BITMAP)ctx;
        if (bm) {
            ULONG64 dataDword = BM_DATA_U64(bm);
            ULONG dataPop = (ULONG)__popcnt64(dataDword);
            if (dataPop >= 1) {
                score = 30;
                if (dataPop >= 2) score += 20;
                if (dataPop >= 3) score += 15;
                if (!f->SrcIsSystemProcess) score += 10;
                if (f->SrcIntegrityLevel <= SECURITY_MANDATORY_LOW_RID) score += 20;
            }
        }
    }

    return min(score, 100);
}

ULONG
Scorer_EvalT2Feedback(
    _In_ PT1_PAIR_FEATURE f,
    _In_opt_ PVOID ctx
    )
/*++
Routine Description:
    Tier2 反馈 — T2 已有分析结论时的策略。
--*/
{
    UNREFERENCED_PARAMETER(ctx);

    if (!f) return 0;

    if (f->T2SuppressFactor <= 20) {
        return 1;
    }
    if (f->T2SuppressFactor < 60) {
        return 5;
    }
    if (f->LastT2Verdict >= 4) {
        return 95;
    }
    if (f->LastT2Verdict >= 2) {
        return 60;
    }
    return 20;
}

/**************************************************/
/*         主入口 — IoaScorer_Evaluate              */
/**************************************************/

ULONG
IoaScorer_Evaluate(
    _In_ SCORE_STRATEGY     Strategy,
    _In_ PT1_PAIR_FEATURE   Feature,
    _In_opt_ PVOID          Context
    )
/*++
Routine Description:
    Scorer 主入口。根据策略分发到对应的评分回调。

    Context 约定:
      SCORE_BY_TEMPLATE    → PINTERACTION_BITMAP (PairCtx->InteractionBitmap)
      SCORE_BY_ACCUMULATE  → PINTERACTION_BITMAP (可选, 用于语义层检查)
      SCORE_BY_CONTEXT     → PINTERACTION_BITMAP (可选)
      其他                  → NULL
--*/
{
    const static SCORER_FN callbacks[] = {
        Scorer_EvalBaseline,
        Scorer_EvalTemplate,
        Scorer_EvalAccumulate,
        Scorer_EvalAnomaly,
        Scorer_EvalContext,
        Scorer_EvalT2Feedback,
    };

    if (!Feature) return 0;
    if (Strategy > SCORE_BY_T2_FEEDBACK) return 0;

    return callbacks[Strategy](Feature, Context);
}

/**************************************************/
/*         EWMA 平滑 + 时间衰减                     */
/**************************************************/

ULONG
Scorer_ApplyEwmaDecay(
    _Inout_ PT1_PAIR_FEATURE Feature,
    _In_    ULONG            RawScore
    )
/*++
Routine Description:
    将本次评分与历史累积分做 EWMA 平滑 (α=0.3)，
    然后根据距上次更新的时间差做衰减。
--*/
{
    ULONG final;
    ULONG prev;

    if (!Feature) return RawScore;

    /* 并发安全重构 2026-08-23：EWMA 读-改-写依赖旧值，整段持 EwmaLock，
     * 防止与 Tier1Engine 的 LastUpdate 写者交错导致 prev/lastUpdate 不一致。 */
    AcquireSRWLockExclusive(&Feature->EwmaLock);

    prev = Feature->CumulativeRiskScore;

    final = (ULONG)(0.3 * RawScore + 0.7 * prev);

    if (Feature->LastUpdate.QuadPart > 0) {
        LARGE_INTEGER now;
        GetSystemTimeAsFileTime((PFILETIME)&now);
        LONGLONG elapsed = (now.QuadPart - Feature->LastUpdate.QuadPart) / 10000;

        if (elapsed > 60000) {
            ULONG periods = (ULONG)(elapsed / 60000);
            for (ULONG d = 0; d < min(periods, (ULONG)5); d++) {
                final = final * 9 / 10;
            }
        }
    }

    Feature->CumulativeRiskScore = final;
    GetSystemTimeAsFileTime((PFILETIME)&Feature->LastUpdate);

    ReleaseSRWLockExclusive(&Feature->EwmaLock);

    return final;
}

/**************************************************/
/*         初始化 / 清理                            */
/**************************************************/

NTSTATUS
IoaScorer_Initialize(
    _Out_ PIOA_SCORER* Out,
    _In_  ULONG        DecayMs
    )
{
    PIOA_SCORER s = UtHeapAlloc(sizeof(IOA_SCORER));
    if (!s) return STATUS_NO_MEMORY;

    RtlZeroMemory(s, sizeof(IOA_SCORER));
    s->DecayIntervalMs = DecayMs;
    s->Initialized = TRUE;

    printf("[IoaScorer] Initialized: %u attack templates, 6 strategies, decay=%lums\n",
           TPL_COUNT, DecayMs);
    *Out = s;
    return STATUS_SUCCESS;
}

VOID
IoaScorer_Cleanup(
    _In_ PIOA_SCORER S
    )
{
    if (!S || !S->Initialized) return;

    printf("[IoaScorer] Cleanup: %lld scores produced\n", S->TotalScoresProduced);
    UtHeapFree(S);
}
