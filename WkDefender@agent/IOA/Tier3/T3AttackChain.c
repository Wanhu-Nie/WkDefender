/**************************************************/
/*  WkDefender IOA — Tier3 攻击链池实现               */
/**************************************************/

#include "T3AttackChain.h"
#include "../IoaEngine.h"
#include "../IoaEdgeAggregate.h"
#include "../IoaMitreMapper.h"
#include "../../Common/Utils.h"
#include <string.h>

/**************************************************/
/*           死代码迁移说明 (2026-08-05)             */
/*                                                   */
/*  ShadowStrike AttackChainTracker 功能迁移, 按功能  */
/*  融合进现有实现, 死代码完整实现 (不接入活跃流水线): */
/*    - 技术→战术+基础分映射 / 危险组合表:            */
/*      IoaMitreMapper.h (g_IoaTechniqueTable /        */
/*      g_IoaDangerousCombos / IoaMitreLookupTactic)  */
/*    - 链字段扩展: Tier3Engine.h TIRE3_ATTACK_CHAIN   */
/*    - 检测函数: 本文件末尾死代码分区                  */
/*  待接入点 (后续接线):                              */
/*    1. T3Chain_IngestTechnique → T3Chain_AddStep 尾部 */
/*       (守卫: PairCtx->T3Tactic.ConfirmedTechnique   */
/*       非 NULL) + Tier3Forensics.c 阶段3             */
/*       T3pDecideTechnique 返回后 (阶段2 加步先于阶段3)*/
/*    2. T3Chain_EvaluateTacticCoverage → 替换/增强    */
/*       T3Chain_AssessCompleteness (TODO: 战术覆盖度) */
/*    3. T3Chain_ConfirmAttack → 阶段4 缺口评估后/阶段7 */
/*  死代码函数对应 SS 源: AttackChainTracker.c Lxxx.   */
/**************************************************/

/**************************************************/
/*           内部辅助                               */
/**************************************************/

static
ULONG
T3pHashNodeId(
    _In_ GUID NodeId
    )
{
    return (ULONG)(NodeId.Data1 ^ NodeId.Data2 ^ NodeId.Data3);
}

/**************************************************/
/*           链池生命周期                           */
/**************************************************/

NTSTATUS
T3ChainPool_Init(
    _Out_ PTIRE3_ATTACK_CHAIN_POOL Pool
    )
{
    if (!Pool) return STATUS_INVALID_PARAMETER;

    InitializeListHead(&Pool->ChainHead);
    Pool->ChainCount = 0;
    InitializeCriticalSection(&Pool->Lock);
    Pool->Initialized = TRUE;

    printf("[T3ChainPool] Initialized (max=%lu chains, TTL=%lu ms)\n",
           (ULONG)TIRE3_ATTACK_CHAIN_POOL_MAX, T3_CHAIN_TTL_MS);
    return STATUS_SUCCESS;
}

VOID
T3ChainPool_Cleanup(
    _In_ PTIRE3_ATTACK_CHAIN_POOL Pool
    )
{
    if (!Pool || !Pool->Initialized) return;

    EnterCriticalSection(&Pool->Lock);

    while (!IsListEmpty(&Pool->ChainHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&Pool->ChainHead);
        PTIRE3_ATTACK_CHAIN chain = CONTAINING_RECORD(entry, TIRE3_ATTACK_CHAIN, Link);
        UtHeapFree(chain);
        Pool->ChainCount--;
    }

    LeaveCriticalSection(&Pool->Lock);
    DeleteCriticalSection(&Pool->Lock);
    Pool->Initialized = FALSE;

    printf("[T3ChainPool] Cleanup: %lu chains freed\n", Pool->ChainCount);
}

/**************************************************/
/*           链创建                                 */
/**************************************************/

static
NTSTATUS
T3pCreateAttackChain(
    _In_    PTIRE3_ATTACK_CHAIN_POOL    Pool,
    _In_    PIOA_FSM_EVIDENCE           Evidence,
    _Out_   PTIRE3_ATTACK_CHAIN*        AttackChine
    )
/*
 * 从 FSM 证据创建新攻击链。
 * 返回新链（已加入链池），失败返回 NULL。
 */
{
    NTSTATUS status;
    PTIRE3_ATTACK_CHAIN chain;

    if (!Pool || !Pool->Initialized || !Evidence || !AttackChine)
        return STATUS_INVALID_PARAMETER;

    chain = UtHeapAlloc(sizeof(TIRE3_ATTACK_CHAIN));
    if (!chain) return STATUS_NO_MEMORY;
    RtlZeroMemory(chain, sizeof(TIRE3_ATTACK_CHAIN));

    WkdCreateGuid(&chain->ChainId);
    chain->ThreatScore = Evidence->ThreatScore;
    chain->Completeness = 0.0f;
    chain->TerminationStatus = T3_CHAIN_STATUS_COMPLETE;
    chain->Disposition = NULL;
    chain->WalkIteration = 0;

    /* 初始进程组 */
    T3AttackChainAttachProcess(chain, Evidence->SrcProcessNodeId);
    T3AttackChainAttachProcess(chain, Evidence->TgtProcessNodeId);

    GetSystemTimeAsFileTime((LPFILETIME)&chain->CreateTime);
    chain->LastActivity = chain->CreateTime;
    chain->LastMergeTime = chain->CreateTime;

    EnterCriticalSection(&Pool->Lock);
    InsertTailList(&Pool->ChainHead, &chain->Link);
    Pool->ChainCount++;
    LeaveCriticalSection(&Pool->Lock);

    printf("[T3ChainPool] New chain created: %08X (FsmClass=%d, "
           "threatScore=%lu, step=%lu/%lu)\n",
           chain->ChainId.Data1, (int)Evidence->FsmClass,
           Evidence->ThreatScore, Evidence->CurrentStep,
           (Evidence->PatternIndex < FSM_PATTERN_COUNT
            ? WkdIoaEngine.FsmEngine->Patterns[Evidence->PatternIndex].StateCount - 1
            : 0UL));

    *AttackChine = chain;
    return STATUS_SUCCESS;
}

/**************************************************/
/*           合并评分                               */
/**************************************************/

static
ULONG
T3pComputeMergeScore(
    _In_ PTIRE3_ATTACK_CHAIN    Chain,
    _In_ PIOA_FSM_EVIDENCE      Evidence
    )
/*
 * 计算两链合并评分 [0, 100]。
 * 维度: 进程重叠(40) + 时序连续性(30) + 战术连贯性(20) + 边连通性(10)
 */
{
    ULONG score = 0;

    if (!Chain || !Evidence) return 0;

    /* ── 进程重叠度 (Max 40) ── */
    {
        ULONG overlapCount = 0;     // 重叠计数
        if (T3QueryAttackChainIncludedProcess(Chain, Evidence->SrcProcessNodeId))
            overlapCount++;
        if (T3QueryAttackChainIncludedProcess(Chain, Evidence->TgtProcessNodeId))
            overlapCount++;

        switch (overlapCount) {
        case 2: score += 40; break;    /* 两端都在链中 */
        case 1: score += 25; break;    /* 一端在链中 */
        default: break;                /* 无重叠 → 不合并 */
        }
    }

    /* ── 时序连续性 (Max 30) ── */
    {
        LONGLONG gapMs = (Evidence->StartTime.QuadPart -
                         Chain->LastActivity.QuadPart) / 10000LL;

        if (gapMs >= 0) {
            if (gapMs <= 5000)       score += 30;    /* 5s内: 紧密衔接 */
            else if (gapMs <= 30000) score += 20;    /* 30s内: 合理衔接 */
            else if (gapMs <= 60000) score += 10;    /* 1min内: 可能有关 */
        }
        /* 负间隔: 新证据时间早于链的最后活动 → 不加分 */
    }

    /* ── 战术连贯性 (Max 20) ── */
    {
        /* 检查 FsmClass 转移是否合理:
           注入→凭据访问, 注入→C2, 凭据访问→C2 都是合理转移 */
        if (Chain->StepCount > 0) {
            /* 简单检查: 只要 FsmClass 不同, 就有一定连贯性 */
            /* 完整实现将在 Phase 2 中添加转移概率矩阵 */
            score += 10;
        }
    }

    /* ── 因果图边连通性 (Max 10) ── */
    {
        /* 检查链中某节点是否与新证据的 SrcNode 有直接边 */
        for (ULONG i = 0; i < Chain->ProcessCount; i++) {
            PIOA_AGGREGATE_EDGE agg = IoaLookupAggregateEdge(
                WkdIoaEngine.EdgeAggTable,
                Chain->ProcessSet[i],
                Evidence->SrcProcessNodeId,
                DefEdge_Unknown);  /* 任意边类型 */
            if (agg) {
                if (agg->ActiveEdges > 0) {
                    score += 10;
                    IoaDereferenceAggregateEdge(agg);
                    break;
                }
                IoaDereferenceAggregateEdge(agg);
            }
        }
    }

    return score;
}

/**************************************************/
/*           合并或创建                            */
/**************************************************/

PTIRE3_ATTACK_CHAIN
T3MergeOrCreateAttackChain(
    _In_ PTIRE3_ATTACK_CHAIN_POOL   Pool,
    _In_ PIOA_FSM_EVIDENCE          Evidence
    )
{
    PTIRE3_ATTACK_CHAIN bestMatch = NULL;
    ULONG bestScore = 0;

    if (!Pool || !Pool->Initialized || !Evidence) return NULL;

    EnterCriticalSection(&Pool->Lock);

    /* 遍历链池，找最佳合并候选 */
    {
        PLIST_ENTRY entry = Pool->ChainHead.Flink;
        while (entry != &Pool->ChainHead) {
            PTIRE3_ATTACK_CHAIN candidate = CONTAINING_RECORD(
                entry, TIRE3_ATTACK_CHAIN, Link);

            ULONG score = T3pComputeMergeScore(candidate, Evidence);
            if (score > bestScore && score >= T3_MERGE_THRESHOLD) {
                bestScore = score;
                bestMatch = candidate;
            }
            entry = entry->Flink;
        }
    }

    if (bestMatch) {
        /* 合并: 将新证据的节点加入现有链 */
        T3AttackChainAttachProcess(bestMatch, Evidence->SrcProcessNodeId);
        T3AttackChainAttachProcess(bestMatch, Evidence->TgtProcessNodeId);
        bestMatch->ThreatScore = max(bestMatch->ThreatScore,
                                     Evidence->ThreatScore);
        bestMatch->LastActivity = bestMatch->LastActivity;
        GetSystemTimeAsFileTime((LPFILETIME)&bestMatch->LastMergeTime);

        /* 记录合并历史 */
        if (bestMatch->MergeCount < T3_CHAIN_MAX_BRANCHES) {
            WkdCopyGuid(&bestMatch->MergedFromChains[bestMatch->MergeCount],
                        &bestMatch->ChainId);
            bestMatch->MergeCount++;
        }

        printf("[T3ChainPool] Chain merged: %08X <- evidence "
               "(overlapScore=%lu, processes=%lu)\n",
               bestMatch->ChainId.Data1, bestScore,
               bestMatch->ProcessCount);
    } else {
        /* 创建新链 */
        T3pCreateAttackChain(Pool, Evidence, &bestMatch);
    }

    LeaveCriticalSection(&Pool->Lock);
    return bestMatch;
}

/**************************************************/
/*           完整度评估                             */
/**************************************************/

VOID
T3Chain_AssessCompleteness(
    _In_  PTIRE3_ATTACK_CHAIN    Chain,
    _Out_ FLOAT*              Completeness,
    _Out_ ULONG*              MissingGaps
    )
{
    FLOAT complete = 0.0f;
    ULONG gaps = 0;

    if (!Chain || !Completeness || !MissingGaps) return;

    /*
     * 简化评估: 基于步骤计数和 FSM 模式信息。
     * 完整实现: 基于 MITRE ATT&CK 战术阶段覆盖度
     * (TA0001~TA0011 中哪些已确认、哪些缺失)。
     */
    {
        ULONG confirmed = 0;
        ULONG total = 0;

        /* 遍历链中的所有步骤引用，统计已确认的 PairContext */
        for (ULONG i = 0; i < Chain->StepCount; i++) {
            if (Chain->StepRefs[i].PairCtx) {
                total++;
                if (Chain->StepRefs[i].PairCtx->T3Tactic.ConfirmedTechnique != NULL) {
                    confirmed++;
                }
            }
        }

        if (total > 0) {
            complete = (FLOAT)confirmed / (FLOAT)total;
        }
    }

    /* 默认缺口: 假设完整的攻击链至少覆盖 3 个战术阶段 */
    /* 如果已确认 < 3，标记缺失 */
    if (complete < 0.5f) {
        gaps |= 0x01;    /* 前置阶段缺失 */
        gaps |= 0x02;    /* 后置阶段缺失 */
    } else if (complete < 0.8f) {
        gaps |= 0x02;    /* 仅后置阶段可能缺失 */
    }

    *Completeness = complete;
    *MissingGaps = gaps;
}

/**************************************************/
/*           危险等级评估                           */
/**************************************************/

T3_DANGER_LEVEL
T3AssessDangerLevel(
    _In_ IOA_GRAPH_EDGE_TYPE EdgeType
    )
{
    switch (EdgeType) {
    /* 执行权转移 → CRITICAL (Driver 无条件同步阻塞) */
    case DefEdge_InjectsInto:     /* CreateRemoteThread / QueueUserApc */
        return T3Danger_Critical;

    /* 线程/进程控制 → HIGH */
    case DefEdge_Creates:         /* CreateProcess */
    case DefEdge_Executes:        /* 执行/加载镜像 */
        return T3Danger_High;

    /* 内存保护修改 → MEDIUM (可能使代码变为可执行) */
    case DefEdge_Protects:        /* VirtualProtectEx */
    case DefEdge_ReflectiveLoad:
        return T3Danger_Medium;

    /* 信息收集/非破坏性操作 → LOW */
    case DefEdge_Opens:           /* OpenProcess */
    case DefEdge_ReadsFrom:       /* ReadProcessMemory */
    case DefEdge_Allocates:       /* VirtualAllocEx */
    case DefEdge_WritesTo:        /* WriteProcessMemory */
    case DefEdge_Modifies:        /* 注册表修改 */
    case DefEdge_ConnectsTo:      /* 网络连接 */
    case DefEdge_DnsQueries:      /* DNS查询 */
    default:
        return T3Danger_Low;
    }
}

/**************************************************/
/*           图展开提示生成                         */
/**************************************************/

ULONG
T3Chain_GenerateGraphWalkHints(
    _In_  PTIRE3_ATTACK_CHAIN    Chain,
    _In_  ULONG               MissingGaps,
    _Out_ PT3_GRAPH_WALK_HINT Hints,
    _In_  ULONG               MaxHints
    )
{
    ULONG count = 0;

    if (!Chain || !Hints || MaxHints == 0) return 0;

    /* 前置缺失 → 反向图展开 (追溯攻击来源) */
    if (MissingGaps & 0x01 && count < MaxHints) {
        Hints[count].Backward   = TRUE;
        Hints[count].SeedNodeId = Chain->ProcessSet[0];  /* 链中的第一个进程 */
        Hints[count].EdgeFilter = DefEdge_Creates;        /* 关注创建边 */
        Hints[count].MaxHops    = 3;
        Hints[count].Recursive  = TRUE;
        Hints[count].Question   = L"追溯攻击入口: 谁创建了攻击进程?";
        count++;
    }

    /* 后置缺失 → 前向图展开 (追踪影响范围) */
    if (MissingGaps & 0x02 && count < MaxHints) {
        Hints[count].Backward   = FALSE;
        Hints[count].SeedNodeId = Chain->ProcessSet[Chain->ProcessCount - 1];
        Hints[count].EdgeFilter = DefEdge_Unknown;        /* 不限边类型 */
        Hints[count].MaxHops    = 2;
        Hints[count].Recursive  = FALSE;
        Hints[count].Question   = L"追踪攻击影响: 目标进程被攻击后做了什么?";
        count++;
    }

    return count;
}

/**************************************************/
/*           过期淘汰                               */
/**************************************************/

VOID
T3ChainPool_EvictExpired(
    _In_ PTIRE3_ATTACK_CHAIN_POOL Pool
    )
{
    LARGE_INTEGER now;
    LONGLONG nowMs;
    ULONG evicted = 0;

    if (!Pool || !Pool->Initialized) return;

    GetSystemTimeAsFileTime((LPFILETIME)&now);
    nowMs = now.QuadPart / 10000LL;

    EnterCriticalSection(&Pool->Lock);

    {
        PLIST_ENTRY entry = Pool->ChainHead.Flink;
        while (entry != &Pool->ChainHead) {
            PTIRE3_ATTACK_CHAIN chain = CONTAINING_RECORD(
                entry, TIRE3_ATTACK_CHAIN, Link);
            PLIST_ENTRY next = entry->Flink;

            LONGLONG ageMs = nowMs - (chain->LastActivity.QuadPart / 10000LL);
            if (ageMs > (LONGLONG)T3_CHAIN_TTL_MS) {
                RemoveEntryList(&chain->Link);
                Pool->ChainCount--;
                UtHeapFree(chain);
                evicted++;
            }
            entry = next;
        }
    }

    LeaveCriticalSection(&Pool->Lock);

    if (evicted > 0) {
        printf("[T3ChainPool] Evicted %lu expired chains\n", evicted);
    }
}

/**************************************************/
/*           步骤/进程管理                          */
/**************************************************/

VOID
T3Chain_AddStep(
    _Inout_ PTIRE3_ATTACK_CHAIN          Chain,
    _In_    PAE_PROCESS_PAIR PairCtx,
    _In_    PTIRE3_EVIDENCE_ITEM      Evidence
    )
{
    if (!Chain || !PairCtx || !Evidence) return;
    if (Chain->StepCount >= T3_CHAIN_MAX_STEPS) return;

    Chain->StepRefs[Chain->StepCount].PairCtx  = PairCtx;
    Chain->StepRefs[Chain->StepCount].Evidence = *Evidence;
    Chain->StepCount++;

    GetSystemTimeAsFileTime((LPFILETIME)&Chain->LastActivity);
}

VOID
T3AttackChainAttachProcess(
    _Inout_ PTIRE3_ATTACK_CHAIN Chain,
    _In_    GUID                ProcessNodeId
    )
/*
 * 将节点添加到链的进程组（去重）。
 */
{
    if (!Chain || DefIsNullNodeId(ProcessNodeId)) return;

    /* 去重 */
    for (ULONG i = 0; i < Chain->ProcessCount; i++) {
        if (DefGuidEqual(&Chain->ProcessSet[i], &ProcessNodeId)) return;
    }

    if (Chain->ProcessCount < T3_CHAIN_MAX_PROCESSES) {
        WkdCopyGuid(&Chain->ProcessSet[Chain->ProcessCount], &ProcessNodeId);
        Chain->ProcessCount++;
    }
}

BOOLEAN
T3QueryAttackChainIncludedProcess(
    _In_ PTIRE3_ATTACK_CHAIN    Chain,
    _In_ GUID                   ProcessNodeId
    )
/*
 * 检查节点是否在链的进程组中。
 */
{
    if (!Chain || DefIsNullNodeId(ProcessNodeId)) return FALSE;

    for (ULONG i = 0; i < Chain->ProcessCount; i++) {
        if (DefGuidEqual(&Chain->ProcessSet[i], &ProcessNodeId)) return TRUE;
    }
    return FALSE;
}

/**************************************************/
/*           死代码分区 — ShadowStrike              */
/*           AttackChainTracker 迁移检测函数         */
/*                                                   */
/*  本分区为完整实现但不接入活跃流水线.               */
/*  接入时按文件头"死代码迁移说明"的三步接线.         */
/**************************************************/

/**
 * 饱和加法 (对齐 SS ActpSaturatingAdd L448-457).
 * 防止 ULONG 溢出, 用于 ComputedScore 累加.
 */
static
ULONG
T3pSaturatingAdd(
    _In_ ULONG Value,
    _In_ ULONG Addend
    )
{
    if (Value > 0xFFFFFFFFUL - Addend) {
        return 0xFFFFFFFFUL;
    }
    return Value + Addend;
}

/**
 * 宽字符串相等比较 (无库依赖).
 */
static
BOOLEAN
T3pWStrEq(
    _In_ PCWSTR A,
    _In_ PCWSTR B
    )
{
    if (A == NULL || B == NULL) {
        return FALSE;
    }
    while (*A != 0 && *B != 0 && *A == *B) {
        A++;
        B++;
    }
    return (*A == 0 && *B == 0);
}

/**
 * 将基技术串与 g_IoaTechniqueTable 匹配 (对齐 SS ActpGetPhaseForTechnique L1534-1554).
 * 命中返回表项指针 (StringId 为静态串), 未命中返回 NULL.
 */
static
const IOA_TECHNIQUE_ENTRY*
T3pLookupTacticEntry(
    _In_ PCWSTR TechniqueBase
    )
{
    ULONG i;
    for (i = 0; g_IoaTechniqueTable[i].StringId != NULL; i++) {
        if (T3pWStrEq(TechniqueBase, g_IoaTechniqueTable[i].StringId)) {
            return &g_IoaTechniqueTable[i];
        }
    }
    return NULL;
}

/**
 * 摄入已确认技术: 技术集合去重 + 置战术位 + 累计基础分 + 增量组合检测.
 *
 * 对齐 SS ActSubmitEvent (L947-1230) 内 AddEvent → CheckDangerousCombos →
 * UpdateScore 顺序; 组合检测对齐 ActpCheckDangerousCombosLocked (L2096-2152),
 * AppliedComboMask 位图防重复计分.
 *
 * 设计差异 (与 SS 对照):
 *   - 技术集合去重: 同一基技术重复摄入不重复计分 (SS 事件不查重, 靠位图防
 *     combo 重复; wkd 去重更简洁, 攻击链看重技术多样性而非重复次数).
 *   - 未映射技术 (g_IoaTechniqueTable 未命中): 累计默认分 10 (SS 默认 base=10),
 *     不入 TechniqueSet (无静态基技术串可安全引用), 不置战术位, 不参与组合.
 *
 * 死代码: 待接入点 = T3Chain_AddStep 尾部 (守卫 ConfirmedTechnique 非 NULL)
 *         + Tier3Forensics.c 阶段3 T3pDecideTechnique 返回后 (阶段2 加步先于阶段3).
 */
VOID
T3Chain_IngestTechnique(
    _Inout_ PTIRE3_ATTACK_CHAIN Chain,
    _In_    PCWSTR              Technique
    )
{
    WCHAR base[16];
    ULONG len = 0;
    ULONG i;
    ULONG j;
    const IOA_TECHNIQUE_ENTRY* entry;
    ULONG bit;
    BOOLEAN already;

    if (Chain == NULL || Technique == NULL) {
        return;
    }

    /* 截断子技术: "T1055.001" → "T1055" */
    while (Technique[len] != 0 && Technique[len] != L'.' && len < 15) {
        base[len] = Technique[len];
        len++;
    }
    base[len] = 0;

    entry = T3pLookupTacticEntry(base);
    if (entry == NULL) {
        /* 未映射技术 → fallback 到 Discovery 阶段 + 默认分 10
         * (对齐 SS ActSubmitEvent L1019-1025: 未知技术 phase=Discovery, baseScore=10).
         * 技术串不入 TechniqueSet (无静态基技术串可安全引用), 不参与组合;
         * 战术位置 Discovery 对齐 SS phaseCount 语义 (同阶段仅计数一次). */
        Chain->ComputedScore = T3pSaturatingAdd(Chain->ComputedScore, 10);
        if ((Chain->TacticMask & (1UL << IoATactic_Discovery)) == 0) {
            Chain->TacticMask |= (1UL << IoATactic_Discovery);
            Chain->TacticCount++;
        }
        return;
    }

    /* 技术去重: 已摄入则幂等返回 (不重复计分) */
    already = FALSE;
    for (i = 0; i < Chain->TechniqueCount; i++) {
        if (T3pWStrEq(Chain->TechniqueSet[i], entry->StringId)) {
            already = TRUE;
            break;
        }
    }
    if (already) {
        return;
    }

    /* 追加技术 + 置战术位 */
    if (Chain->TechniqueCount < T3_CHAIN_MAX_STEPS) {
        Chain->TechniqueSet[Chain->TechniqueCount++] = entry->StringId;
    }

    bit = entry->TacticBit;
    if (bit < IoATactic_Max) {
        if ((Chain->TacticMask & (1UL << bit)) == 0) {
            Chain->TacticMask |= (1UL << bit);
            Chain->TacticCount++;
        }
    }

    Chain->ComputedScore = T3pSaturatingAdd(Chain->ComputedScore, entry->BaseScore);

    /* 增量组合检测: 新技术 vs 既有技术集合 */
    for (i = 0; g_IoaDangerousCombos[i].Technique1 != NULL; i++) {
        ULONG comboBit = 1UL << g_IoaDangerousCombos[i].ComboIndex;
        if (Chain->AppliedComboMask & comboBit) {
            continue;   /* 已应用, 防重复计分 */
        }
        for (j = 0; j < Chain->TechniqueCount; j++) {
            PCWSTR existing = Chain->TechniqueSet[j];
            if ((T3pWStrEq(g_IoaDangerousCombos[i].Technique1, entry->StringId) &&
                 T3pWStrEq(g_IoaDangerousCombos[i].Technique2, existing)) ||
                (T3pWStrEq(g_IoaDangerousCombos[i].Technique2, entry->StringId) &&
                 T3pWStrEq(g_IoaDangerousCombos[i].Technique1, existing))) {
                Chain->AppliedComboMask |= comboBit;
                Chain->ComputedScore = T3pSaturatingAdd(
                    Chain->ComputedScore, g_IoaDangerousCombos[i].BonusScore);
                Chain->ComboBonusTotal = T3pSaturatingAdd(
                    Chain->ComboBonusTotal, g_IoaDangerousCombos[i].BonusScore);
                printf("[T3Chain] Dangerous combo: %ws (+%lu, chain=%08X)\n",
                       g_IoaDangerousCombos[i].Description,
                       g_IoaDangerousCombos[i].BonusScore,
                       Chain->ChainId.Data1);
                break;
            }
        }
    }
}

/**
 * 战术覆盖评估: 链覆盖的战术阶段数 → Completeness + MissingGaps.
 *
 * 对齐 SS ActpCountPhasesLocked (L2056-2086) + 攻击链阶段覆盖思想.
 * 读链上 TacticMask/TacticCount (由 T3Chain_IngestTechnique 维护),
 * 不遍历 StepRefs (规避 PairContext 被 TTL 淘汰的悬垂).
 *
 * 死代码: 待接入点 = 替换/增强 T3Chain_AssessCompleteness (L269-316),
 * 保留其 0x01(前置缺失)/0x02(后置缺失) 缺口语义.
 */
VOID
T3Chain_EvaluateTacticCoverage(
    _In_  PTIRE3_ATTACK_CHAIN Chain,
    _Out_ FLOAT*               Completeness,
    _Out_ ULONG*               MissingGaps
    )
{
    if (Chain == NULL || Completeness == NULL || MissingGaps == NULL) {
        return;
    }

    *Completeness = (FLOAT)Chain->TacticCount / (FLOAT)IoATactic_Max;
    *MissingGaps  = (~Chain->TacticMask) & ((1UL << IoATactic_Max) - 1);
}

/**
 * 确认攻击判定 (对齐 SS ActSubmitEvent 确认分支 L1137-1189).
 *
 * 确认公式 (阈值 /5 换算到 wkd 0-100 尺度):
 *   TacticCount >= 3 且 ComputedScore >= 60 → IsConfirmedAttack = TRUE
 * (SS: ThreatScore >= 300 且 phaseCount >= 3; 300/5=60, 与 VerdictEngine
 *  High=70/Detection=50 档次对齐).
 *
 * Engine 非空时对 TotalAttacksConfirmed 计数 (对齐 SS L1145
 * InterlockedIncrement64(&Tracker->Stats.AttacksConfirmed)).
 *
 * 确认后链不被 T3ChainPool_EvictExpired 淘汰 (对齐 SS ActpIsChainExpiredLocked
 * L1989: 已确认攻击不过期; 但 wkd 池上限 64, 接入时需加确认链保留上限约束).
 *
 * 死代码: 待接入点 = 阶段4 缺口评估后 / 阶段7 叙事.
 */
VOID
T3Chain_ConfirmAttack(
    _Inout_ PTIRE3_ATTACK_CHAIN Chain,
    _In_opt_ PIOA_TIER3_ENGINE   Engine
    )
{
    if (Chain == NULL || Chain->IsConfirmedAttack) {
        return;
    }

    if (Chain->TacticCount >= 3 && Chain->ComputedScore >= 60) {
        Chain->IsConfirmedAttack = TRUE;
        if (Engine != NULL) {
            InterlockedIncrement64(&Engine->TotalAttacksConfirmed);
        }
        printf("[T3Chain] ATTACK CONFIRMED: chain=%08X tactics=%lu "
               "score=%lu comboBonus=%lu\n",
               Chain->ChainId.Data1,
               Chain->TacticCount,
               Chain->ComputedScore,
               Chain->ComboBonusTotal);
    }
}

/**
 * 链置信度启发式 (对齐 SS ActpUpdateChainScoreLocked L1968-1971):
 *   confidence = min(100, 技术数*10 + 战术覆盖数*15)
 * 死代码: 供接入时写入告警/叙事. wkd 链完整度由
 * T3Chain_EvaluateTacticCoverage (战术覆盖比例) 近似覆盖, 二者语义不同
 * (覆盖度 vs 置信度), 故单独保留此启发式.
 */
ULONG
T3Chain_ComputeConfidence(
    _In_ PTIRE3_ATTACK_CHAIN Chain
    )
{
    ULONG confidence;

    if (Chain == NULL) {
        return 0;
    }

    confidence = T3pSaturatingAdd(Chain->TechniqueCount * 10,
                                  Chain->TacticCount * 15);
    return (confidence > 100) ? 100 : confidence;
}
