/**************************************************/
/*  WkDefender — Tier3 深度取证螺旋流水线 (2026-07 重构) */
/*                                                   */
/*  T3DeepForensics 整体流程:                        */
/*   阶段0: 攻击链合并 (进程重叠+时序+战术连贯性)      */
/*   循环 (最多 T3_MAX_GRAPH_WALK_ITERATIONS 轮):     */
/*     阶段1: 因果倒推 (分析器Confirm完成参数提取+     */
/*             内容深化, DeriveNeeds推导前置条件)      */
/*     阶段2: 步骤入链 + 纳新边纳入                   */
/*     阶段3: 战术决策 (更新 PairContext.T3Tactic)    */
/*     阶段4: 缺口评估 + 条件图展开                   */
/*     阶段5: 展开结果反哺链 → 继续循环 或 退出       */
/*   阶段6: 叙事生成                                  */
/*                                                   */
/*   注意: 参数提取+内容深化已由阶段1的因果倒推循环     */
/*         中的分析器 Confirm 完成, 不再需要单独的     */
/*         StLoadEventByGuid + 分析器循环。           */
/**************************************************/

#include "Tier3Engine.h"
#include "T3AttackChain.h"
#include "CausalInference.h"
#include "../IoaEngine.h"
#include "../IoaCarsalGraph.h"
#include "../IoaEdgeAggregate.h"
#include "../IoaProcessPair.h"
#include "../../Common/Utils.h"
#include <string.h>

/**************************************************/
/*           内部辅助: 战术决策                       */
/**************************************************/

static
VOID
T3pDecideTechnique(
    _Inout_ PTIRE3_ATTACK_CHAIN          Chain,
    _In_    PAE_PROCESS_PAIR PairCtx,
    _In_    PTIRE3_CAUSAL_INFERENCE         CausalResult
    )
/*++
Routine Description:
    从倒推累积的 MitreProbs 决定精确的 MITRE Technique。
    优先使用 CausalResult->MitreProbs (分析器 UpdateMitreProbs 累积)，
    回退到特征矩阵 (向后兼容)。

    结果直接写入 PairCtx->T3Tactic。
    置信度上限 98%。
--*/
{
    PT3_TACTICAL_ANNOTATION t = &PairCtx->T3Tactic;
    DOUBLE bestProb = 0.0;
    PT3_MITRE_PROB_DIST probs;

    if (!Chain || !PairCtx || !CausalResult) return;

    probs = &CausalResult->MitreProbs;

    /* 确认攻击类 */
    t->ConfirmedClass = PairCtx->T3Tactic.ConfirmedClass;
    if (t->ConfirmedClass == FsmClass_None) {
        t->ConfirmedClass = (CausalResult->ConfirmedCount > 0)
            ? FsmClass_ProcessInjection : FsmClass_None;
    }

    /*
     * 优先路径: 从 MitreProbs 累积概率中选取最高概率的技术。
     * 这是倒推循环中各分析器 UpdateMitreProbs 回调逐步累积的结果。
     */
    if (probs && probs->Count > 0 && probs->Entries[0].TechniqueId != NULL) {
        t->CandidateCount = 0;
        t->ConfirmedTechnique = NULL;
        t->Confidence = 0;

        for (ULONG i = 0; i < probs->Count && t->CandidateCount < 4; i++) {
            if (probs->Entries[i].TechniqueId == NULL) break;

            /* 填充 T3Tactic Candidates 槽位 */
            t->Candidates[t->CandidateCount].TechniqueId  = probs->Entries[i].TechniqueId;
            t->Candidates[t->CandidateCount].Probability  = (ULONG)(probs->Entries[i].Probability * 100);
            t->Candidates[t->CandidateCount].Rationale    = probs->Entries[i].Rationale;
            t->CandidateCount++;

            if (probs->Entries[i].Probability > bestProb) {
                bestProb = probs->Entries[i].Probability;
                t->ConfirmedTechnique = probs->Entries[i].TechniqueId;
                t->Confidence = (ULONG)(bestProb * 98);  /* 上限 98% */
            }
        }

        t->IsClosed = (t->Confidence >= 80);   /* 置信度 ≥80% 闭合 */
        t->Confidence = min(t->Confidence, 98);

        printf("[T3Forensics] Technique from MitreProbs: %S (Conf=%lu%%)\n",
               t->ConfirmedTechnique ? t->ConfirmedTechnique : L"NULL",
               t->Confidence);
        return;
    }

    /*
     * 回退路径: 特征矩阵 (向后兼容，当 MitreProbs 未填充时使用)
     */
    {
        BOOLEAN hasMZ = FALSE, hasDllPath = FALSE, hasShellcode = FALSE;
        BOOLEAN hasUnmap = FALSE, hasProtect = FALSE, isLoadLibrary = FALSE;

        for (ULONG i = 0; i < CausalResult->ConfirmedCount; i++) {
            PTIRE3_EVIDENCE_ITEM item = &CausalResult->ConfirmedSteps[i];
            switch (item->EdgeType) {
            case DefEdge_WritesTo:
                hasMZ        |= item->Params.MemoryWrite.HasMZ;
                hasDllPath   |= item->Params.MemoryWrite.HasDllPath;
                if (!hasMZ && !hasDllPath) hasShellcode = TRUE;
                break;
            case DefEdge_InjectsInto:
                isLoadLibrary = item->Params.ThreadCreate.IsLoadLibrary;
                break;
            case DefEdge_Hollows:
                hasUnmap = TRUE;
                break;
            case DefEdge_Protects:
                if (item->Params.MemoryProtect.NewProtect &
                    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
                    hasProtect = TRUE;
                }
                break;
            default: break;
            }
        }

        if (hasMZ && hasUnmap) {
            t->ConfirmedTechnique = L"T1055.012";
            t->Confidence = 92;
        } else if (hasMZ) {
            t->ConfirmedTechnique = L"T1055.002";
            t->Confidence = 85;
        } else if (hasDllPath) {
            t->ConfirmedTechnique = L"T1055.001";
            t->Confidence = isLoadLibrary ? 98 : 88;
            if (hasProtect) t->Confidence = 88;
        } else if (hasShellcode) {
            t->ConfirmedTechnique = L"T1620";
            t->Confidence = 80;
        } else {
            t->ConfirmedTechnique = NULL;
            t->Candidates[0].TechniqueId = L"T1055.001";
            t->Candidates[0].Probability = 70;
            t->Candidates[0].Rationale  = L"RW分配 + 跨进程写入 (最可能为DLL注入)";
            t->Candidates[1].TechniqueId = L"T1055.004";
            t->Candidates[1].Probability = 15;
            t->Candidates[1].Rationale  = L"同样序列但可能走APC";
            t->Candidates[2].TechniqueId = L"T1055.002";
            t->Candidates[2].Probability = 10;
            t->Candidates[2].Rationale  = L"备选: PE注入 (需进一步证据)";
            t->CandidateCount = 3;
            t->Confidence = 0;
            t->IsClosed = FALSE;
            return;
        }

        t->IsClosed = TRUE;
        t->Confidence = min(t->Confidence, 98);
        printf("[T3Forensics] Technique from feature matrix: %S (Conf=%lu%%) "
               "hasMZ=%d hasDllPath=%d hasUnmap=%d hasProtect=%d\n",
               t->ConfirmedTechnique, t->Confidence,
               hasMZ, hasDllPath, hasUnmap, hasProtect);
    }
}

/**************************************************/
/*           T3DeepForensics 入口                   */
/**************************************************/

NTSTATUS
T3DeepForensics(
    _In_    PIOA_TIER3_ENGINE       Engine,
    _In_    PIOA_FSM_EVIDENCE       Evidence,
    _Out_   PTIRE3_ATTACK_CHAIN*    OutChain
    )
/*++
Routine Description:
    Tier3 螺旋式取证流水线入口（同步 — 被 T2 直接调用）。

    输入: FSM 精简证据包 (FsmClass + PatternIndex + CurrentStep + ThreatScore)
    输出: 更新的攻击链 (PairContext.T3Tactic 已标注, 链已加入链池)

    循环 (最多 T3_MAX_GRAPH_WALK_ITERATIONS 轮):
      - 因果倒推 + 参数提取
      - Write阶段内容分析 (ReadProcessMemory)
      - 纳新边
      - 战术决策
      - 缺口评估 + 条件图展开
      - 展开结果反哺链 → 收敛检查
--*/
{
    PTIRE3_ATTACK_CHAIN chain;
    PTIRE3_CAUSAL_INFERENCE causalInference;    // 因果推断
    PAE_PROCESS_PAIR pairCtx = NULL;
    NTSTATUS status;

    if (!Engine || !Evidence || !OutChain) return STATUS_INVALID_PARAMETER;
    *OutChain = NULL;

    /* === 阶段0: 攻击链合并 === */
    chain = T3MergeOrCreateAttackChain(&Engine->ChainPool, Evidence);
    if (!chain) return STATUS_NO_MEMORY;

    /* 获取/创建进程对上下文 (用于挂载战术标注)
     * 2026-08-23 pair 键 PID 化: NodeId → 节点 → PID 后查找 */
    {
        PWKD_PROCESS srcNode = PtTreeLookupByNodeId(
            &WkdProcessTree, Evidence->SrcProcessNodeId);
        PWKD_PROCESS tgtNode = PtTreeLookupByNodeId(
            &WkdProcessTree, Evidence->TgtProcessNodeId);
        if (srcNode && tgtNode &&
            !srcNode->SecCtx.Placeholder && !tgtNode->SecCtx.Placeholder) {
            status = AeFindOrCreateProcessPair(
                srcNode, tgtNode, &pairCtx);
            if (!NT_SUCCESS(status)) pairCtx = NULL;
        }
        if (!pairCtx) {
            printf("[T3Forensics] WARNING: Cannot create or get PairContext\n");
        }
    }

    /* 分配因果倒推结果 */
    causalInference = UtHeapAlloc(sizeof(TIRE3_CAUSAL_INFERENCE));
    if (!causalInference) return STATUS_NO_MEMORY;

    /* === 螺旋循环 === */
    for (chain->WalkIteration = 1;
         chain->WalkIteration <= T3_MAX_GRAPH_WALK_ITERATIONS;
         chain->WalkIteration++) {

        printf("[T3Forensics] === Iteration %lu ===\n",
               chain->WalkIteration);

        /* ── 阶段1: 因果倒推 + 参数提取 ── */
        status = T3CausalBackwardInference(Evidence, causalInference);
        if (!NT_SUCCESS(status)) {
            printf("[T3Forensics] Causal inference failed: 0x%X\n", status);
            break;
        }

        /* ── 阶段2: 步骤入链 + 纳新边纳入 ── */
        /*    (参数提取 + 内容深化已在阶段1因果倒推中由分析器Confirm完成) */
        for (ULONG i = 0; i < causalInference->ConfirmedCount; i++) {
            PTIRE3_EVIDENCE_ITEM item = &causalInference->ConfirmedSteps[i];

            /* 添加到攻击链步骤 (Params 已填充, ContentConfidence 已设置) */
            if (pairCtx) {
                T3Chain_AddStep(chain, pairCtx, item);
            }
        }

        /* 纳新边入链 */
        for (ULONG e = 0; e < causalInference->ExtraCount; e++) {
            if (pairCtx) {
                T3Chain_AddStep(chain, pairCtx, &causalInference->ExtraEdges[e]);
            }
        }

        /* ── 阶段3: 战术决策 ── */
        if (pairCtx) {
            T3pDecideTechnique(chain, pairCtx, causalInference);
            pairCtx->DirtyFlags |= IOA_PAIR_DIRTY_TIER3_TACTIC;
        }

        /* ── 阶段4: 缺口评估 ── */
        FLOAT completeness;
        ULONG missingGaps;
        T3Chain_AssessCompleteness(chain, &completeness, &missingGaps);
        chain->Completeness = completeness;

        printf("[T3Forensics] Completeness=%.2f, gaps=0x%lx\n",
               completeness, missingGaps);

        /* ── 阶段5: 条件图展开 ── */
        if (missingGaps != 0 &&
            chain->ThreatScore >= 50) {  /* 威胁足够高才展开 */

            T3_GRAPH_WALK_HINT hints[4];
            ULONG hintCount = T3Chain_GenerateGraphWalkHints(
                chain, missingGaps, hints, 4);

            BOOLEAN foundNewNodes = FALSE;
            for (ULONG h = 0; h < hintCount; h++) {
                GW_PATH_NODE pathNodes[GW_CHAIN_MAX_NODES];
                ULONG pathCount = GW_CHAIN_MAX_NODES;

                printf("[T3Forensics] Graph walk: %ls (%ls, maxHops=%lu)\n",
                       hints[h].Backward ? L"Backward" : L"Forward",
                       hints[h].Question, hints[h].MaxHops);

                if (hints[h].Backward) {
                    GwWalkBackward(WkdIoaEngine.GraphWalker,
                                   hints[h].SeedNodeId,
                                   hints[h].EdgeFilter,
                                   hints[h].MaxHops,
                                   pathNodes, &pathCount);
                } else {
                    GwWalkForward(WkdIoaEngine.GraphWalker,
                                  hints[h].SeedNodeId,
                                  hints[h].EdgeFilter,
                                  hints[h].MaxHops,
                                  pathNodes, &pathCount);
                }

                /* 展开结果纳入链 */
                for (ULONG n = 0; n < pathCount; n++) {
                    if (!DefIsNullNodeId(pathNodes[n].NodeId) &&
                        !T3QueryAttackChainIncludedProcess(chain, pathNodes[n].NodeId)) {
                        T3AttackChainAttachProcess(chain, pathNodes[n].NodeId);
                        foundNewNodes = TRUE;
                    }
                }
            }

            /* ── 阶段6: 收敛检查 ── */
            if (!foundNewNodes) {
                printf("[T3Forensics] Convergence reached: "
                       "no new nodes in iteration %lu\n",
                       chain->WalkIteration);
                break;
            }
        } else {
            /* 无缺口 或 威胁不够 → 不展开 */
            printf("[T3Forensics] Skipping graph walk: "
                   "gaps=0x%lx threatScore=%lu\n",
                   missingGaps, chain->ThreatScore);
            break;
        }
    }

    /* === 阶段7: 叙事生成 === */
    printf("[T3Forensics] Chain %08X complete: "
           "threatScore=%lu, completeness=%.2f, "
           "processes=%lu, steps=%lu, iterations=%lu\n",
           chain->ChainId.Data1, chain->ThreatScore,
           chain->Completeness, chain->ProcessCount,
           chain->StepCount, chain->WalkIteration);

    if (pairCtx && pairCtx->T3Tactic.ConfirmedTechnique) {
        printf("[T3Forensics] Final technique: %S (Conf=%lu%%)\n",
               pairCtx->T3Tactic.ConfirmedTechnique,
               pairCtx->T3Tactic.Confidence);
    }

    /* 归还 pair pin (2026-08-25 HashMap ref/deref 契约: 战术标注已挂
     * pairCtx, 攻击链经 PairContext 引用读取, 本函数不再持有) */
    if (pairCtx) AeDereferenceProcessPair(pairCtx);

    UtHeapFree(causalInference);
    *OutChain = chain;
    return STATUS_SUCCESS;
}
