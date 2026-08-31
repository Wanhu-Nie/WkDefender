/**************************************************/
/*  WkDefender IOA — Tier3 因果倒推引擎              */
/*                                                  */
/*  统一倒推循环 + 心愿清单 + 评分制候选决策。        */
/*                                                  */
/*  重构核心变更:                                    */
/*    1. T3pProcessCore 骨架替代旧 T3pConfirmCore    */
/*    2. TIRE3_NEEDS_WISHLIST 替代 TIRE3_CAUSAL_NEEDS */
/*    3. 评分制候选选择替代"选时间最近"               */
/*    4. TryFuse 替代固定分段合并                     */
/*    5. 分析器回调集替代 Confirm+DeriveNeeds 两段式  */
/**************************************************/

#include "CausalInference.h"
#include "../IoaEngine.h"
#include "../IoaEdgeAggregate.h"
#include <string.h>

/**************************************************/
/*           Wishlist 辅助函数                      */
/**************************************************/

VOID
WishAppend(
    _Inout_ PTIRE3_NEEDS_WISHLIST Wish,
    _In_    PTIRE3_WISH_ENTRY     Entry
    )
/*++
Routine Description:
    纯追加心愿条目到 Wishlist，不做去重/合并。
    由分析器 DeriveNeeds 调用，每个独立需求调用一次。

    FromStepIndex 自动取自 Wish->CurrentStep（由倒推循环设置）。

Arguments:
    Wish          - 目标心愿清单（in/out）。
    Entry         - 新心愿条目（拷贝到数组）。
--*/
{
    if (!Wish || Wish->Count >= TIRE3_WISHLIST_MAX) return;

    Wish->Entries[Wish->Count] = *Entry;
    Wish->Entries[Wish->Count].Active = TRUE;
    Wish->Entries[Wish->Count].FromStepIndex = Wish->CurrentStep;
    Wish->Count++;
}

VOID
WishCompact(
    _Inout_ PTIRE3_NEEDS_WISHLIST Wish
    )
/*++
Routine Description:
    压缩 Wishlist: 移除所有 Active=FALSE 的条目，保持顺序。
--*/
{
    ULONG writeIdx = 0;
    ULONG i;

    if (!Wish) return;

    for (i = 0; i < Wish->Count; i++) {
        if (Wish->Entries[i].Active) {
            if (writeIdx != i) {
                Wish->Entries[writeIdx] = Wish->Entries[i];
            }
            writeIdx++;
        }
    }
    Wish->Count = writeIdx;
}

BOOLEAN
WishIsEmpty(
    _In_ PTIRE3_NEEDS_WISHLIST Wish
    )
/*++
Routine Description:
    检查 Wishlist 是否全部满足 (Count==0 或所有条目 Active=FALSE)。
--*/
{
    ULONG i;
    if (!Wish) return TRUE;
    for (i = 0; i < Wish->Count; i++) {
        if (Wish->Entries[i].Active) return FALSE;
    }
    return TRUE;
}

BOOLEAN
WishFulfillWriteAt(
    _Inout_ PTIRE3_WISH_ENTRY Wish,
    _In_    ULONG64           BaseAddr,
    _In_    ULONG64           Size
    )
/*++
Routine Description:
    检查单条心愿的写地址是否被 BaseAddr+Size 覆盖。
    若覆盖则设置 Active=FALSE 并返回 TRUE。
--*/
{
    if (!Wish || !Wish->Active || !Wish->NeedWriteAt) return FALSE;

    if (BaseAddr <= Wish->RequiredWriteAddr &&
        BaseAddr + Size > Wish->RequiredWriteAddr) {
        Wish->Active = FALSE;
        return TRUE;
    }
    return FALSE;
}

BOOLEAN
WishFulfillAllocCover(
    _Inout_ PTIRE3_WISH_ENTRY Wish,
    _In_    ULONG64           BaseAddr,
    _In_    ULONG64           Size
    )
/*++
Routine Description:
    检查单条心愿的分配范围是否被 BaseAddr+Size 覆盖。
    若覆盖则设置 Active=FALSE 并返回 TRUE。
--*/
{
    if (!Wish || !Wish->Active || !Wish->NeedAllocCover) return FALSE;

    if (BaseAddr <= Wish->RequiredAllocMin &&
        BaseAddr + Size >= Wish->RequiredAllocMax) {
        Wish->Active = FALSE;
        return TRUE;
    }
    return FALSE;
}

BOOLEAN
WishFulfillAccessMask(
    _Inout_ PTIRE3_WISH_ENTRY Wish,
    _In_    ULONG             GrantedAccess
    )
/*++
Routine Description:
    检查单条心愿的访问权限是否被 GrantedAccess 覆盖。
    若覆盖则设置 Active=FALSE 并返回 TRUE。
--*/
{
    if (!Wish || !Wish->Active || !Wish->NeedAccessMask) return FALSE;

    if ((GrantedAccess & Wish->RequiredAccessMask) == Wish->RequiredAccessMask) {
        Wish->Active = FALSE;
        return TRUE;
    }
    return FALSE;
}

/**************************************************/
/*           评分辅助函数                           */
/**************************************************/

ULONG
Score_WriteAddressCoverage(
    _In_ ULONG64 BaseAddr,
    _In_ ULONG64 Size,
    _In_ ULONG64 RequiredAddr
    )
/*++
Routine Description:
    计算写地址覆盖度评分 [0, 100]。
    RequiredAddr 在 [BaseAddr, BaseAddr+Size) 内 → 100。
    在外部 → 距离越远分越低，最小 0。
--*/
{
    if (BaseAddr <= RequiredAddr && BaseAddr + Size > RequiredAddr) {
        return 100;
    }

    /* 距离衰减 */
    ULONG64 dist;
    if (RequiredAddr < BaseAddr) {
        dist = BaseAddr - RequiredAddr;
    } else {
        dist = RequiredAddr - (BaseAddr + Size);
    }

    if (dist >= 0x100000) return 0;     /* > 1MB → 无关 */
    return (ULONG)(100 - (dist * 100 / 0x100000));
}

ULONG
Score_AccessMaskCoverage(
    _In_ ULONG GrantedAccess,
    _In_ ULONG RequiredAccess
    )
/*++
Routine Description:
    计算访问权限覆盖度评分 [0, 100]。
    popcount(Granted & Required) / popcount(Required) × 100。
    若 RequiredAccess==0 则返回 50（无具体需求时的默认值）。
--*/
{
    ULONG requiredBits, grantedBits;
    if (RequiredAccess == 0) return 50;

    requiredBits = __popcnt(RequiredAccess);
    if (requiredBits == 0) return 50;

    grantedBits = __popcnt(GrantedAccess & RequiredAccess);
    return (ULONG)((ULONG64)grantedBits * 100 / requiredBits);
}

ULONG
Score_ContentMatch(
    _In_ BOOLEAN HasFeature,
    _In_ BOOLEAN NeedFeature
    )
/*++
Routine Description:
    内容匹配评分 [0, 100]。
    HasFeature == NeedFeature → 100
    !NeedFeature (无内容需求) → 50
    HasFeature=FALSE && NeedFeature=TRUE → 0
--*/
{
    if (!NeedFeature) return 50;        /* 无内容约束 → 默认分 */
    return HasFeature ? 100 : 0;
}

/**************************************************/
/*           默认满足检查 (按边类型)                 */
/**************************************************/

static
VOID
DefaultFulfillCheck(
    _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
    _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist
    )
/*++
Routine Description:
    默认满足检查: 按 OutItem 的边类型匹配 Wishlist 中的同类需求。
    被分析器特定的 FulfillCheck 覆盖调用。
--*/
{
    ULONG i;

    if (!OutItem || !Wishlist) return;

    for (i = 0; i < Wishlist->Count; i++) {
        PTIRE3_WISH_ENTRY w = &Wishlist->Entries[i];
        if (!w->Active) continue;

        switch (OutItem->EdgeType) {
        case DefEdge_WritesTo:
            if (w->NeedWriteAt) {
                WishFulfillWriteAt(w,
                    OutItem->Params.MemoryWrite.BaseAddress,
                    OutItem->Params.MemoryWrite.NumberOfBytesWritten);
            }
            break;

        case DefEdge_Allocates:
            if (w->NeedAllocCover) {
                WishFulfillAllocCover(w,
                    OutItem->Params.MemoryAlloc.BaseAddress,
                    OutItem->Params.MemoryAlloc.RegionSize);
            }
            break;

        case DefEdge_Opens:
        case DefEdge_Creates:
            if (w->NeedAccessMask) {
                WishFulfillAccessMask(w,
                    OutItem->Params.ProcessOpen.DesiredAccess);
            }
            break;

        default:
            break;
        }
    }
}

/**************************************************/
/*           公共骨架 T3pProcessCore                */
/**************************************************/

static
BOOLEAN
T3pProcessCore(
    _In_    GUID                    SourceNodeId,
    _In_    GUID                    TargetNodeId,
    _In_    IOA_GRAPH_EDGE_TYPE     EdgeType,
    _In_    LARGE_INTEGER           WinStart,
    _In_    LARGE_INTEGER           WinEnd,
    _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist,
    _Inout_ PT3_MITRE_PROB_DIST     Probs,
    _Out_   PTIRE3_EVIDENCE_ITEM    OutItem,
    _In_    PT3_ANALYZER_CALLBACKS  Callbacks
    )
/*++
Routine Description:
    统一 Process 骨架 — 所有分析器共享的处理流水线。

    内部顺序:
      阶段1: CollectCandidates — 查聚合边表 + 时间窗口过滤
      阶段2: Score each candidate — 提取参数+深化内容+评分
      阶段3: Decision — TryFuse or ArgMax
      阶段4: FulfillCheck — 检查当前边满足 Wishlist 中的哪些需求
      阶段5: DeriveNeeds — 推导对更前步骤的需求
      阶段6: UpdateMitreProbs — 更新概率分布

Arguments:
    SourceNodeId, TargetNodeId - 进程节点 GUID。
    EdgeType             - 边类型。
    WinStart, WinEnd     - 时间窗口。
    Wishlist             - [in/out] 心愿清单 (传入待满足需求，传出更新后清单)。
    Probs                - [in/out] MITRE 概率分布 (累积更新)。
    OutItem              - [输出] 确认的边。
    Callbacks            - 分析器回调集。

Returns:
    TRUE  = 找到并确认了边，OutItem 有效。
    FALSE = 无匹配边 (链断裂或超时)。
--*/
{
    T3_CANDIDATE_INFO candidates[8];
    PTIRE3_EVIDENCE_ITEM filledCands[8];
    TIRE3_EVIDENCE_ITEM filledStorage[8];
    ULONG scores[8];
    ULONG candidateCount = 0;
    ULONG i;
    BOOLEAN fused = FALSE;

    if (!OutItem || !Callbacks) return FALSE;
    RtlZeroMemory(OutItem, sizeof(TIRE3_EVIDENCE_ITEM));

    /* ── 阶段1: 候选收集 ── */
    RtlZeroMemory(candidates, sizeof(candidates));
    if (Callbacks->Collect) {
        candidateCount = Callbacks->Collect(
            SourceNodeId, TargetNodeId, EdgeType,
            WinStart, WinEnd,
            candidates, 8);
    } else {
        /* 默认: 查聚合边表 + 时间窗口过滤 */
        PIOA_AGGREGATE_EDGE agg;
        PLIST_ENTRY entry;

        agg = IoaLookupAggregateEdge(WkdIoaEngine.EdgeAggTable,
                                      SourceNodeId, TargetNodeId, EdgeType);
        if (agg) {
            AcquireSRWLockShared(&agg->EdgeLock);
            for (entry = agg->EdgesHead.Flink;
                 entry != &agg->EdgesHead && candidateCount < 8;
                 entry = entry->Flink) {

                PIOA_CONCRETE_EDGE edge = CONTAINING_RECORD(
                    entry, IOA_CONCRETE_EDGE, Link);

                if (edge->Timestamp.QuadPart < WinStart.QuadPart ||
                    edge->Timestamp.QuadPart >= WinEnd.QuadPart) continue;
                if (!edge->Active) continue;

                candidates[candidateCount].EdgeId     = edge->EdgeId;
                candidates[candidateCount].SourceNodeId  = SourceNodeId;
                candidates[candidateCount].TargetNodeId  = TargetNodeId;
                // candidates[candidateCount].EdgeType   = edge->EdgeType;
                candidates[candidateCount].Timestamp   = edge->Timestamp;
                candidateCount++;
            }
            ReleaseSRWLockShared(&agg->EdgeLock);
            /* Lookup 返回已 pin 的边, 遍历用毕归还引用 */
            IoaDereferenceAggregateEdge(agg);
        }
    }

    if (candidateCount == 0) {
        return FALSE;
    }

    /* ── 阶段2: 评分每条候选 (内含 Extract+Deepen) ── */
    RtlZeroMemory(filledStorage, sizeof(filledStorage));
    for (i = 0; i < candidateCount; i++) {
        filledCands[i] = &filledStorage[i];
        RtlZeroMemory(filledCands[i], sizeof(TIRE3_EVIDENCE_ITEM));

        /* 拷贝候选基本信息 */
        WkdCopyGuid(&filledCands[i]->EdgeId, &candidates[i].EdgeId);
        filledCands[i]->EdgeType   = candidates[i].EdgeType;
        filledCands[i]->Timestamp  = candidates[i].Timestamp;

        /* 调用分析器评分函数 (内含 ExtractParams + DeepenContent) */
        if (Callbacks->ScoreCand) {
            scores[i] = Callbacks->ScoreCand(
                &candidates[i], Wishlist, filledCands[i]);
        } else {
            scores[i] = 50;     /* 默认分 */
        }
    }

    /* ── 阶段3: 决策 — TryFuse or ArgMax ── */
    if (Callbacks->TryFuse && candidateCount >= 2) {
        /* 检查是否有必要融合: 最高分的候选是否完全满足 Wishlist */
        ULONG bestScore = 0;
        for (i = 0; i < candidateCount; i++) {
            if (scores[i] > bestScore) bestScore = scores[i];
        }

        if (bestScore < 100 || !WishIsEmpty(Wishlist)) {
            /* 最高分未达满分 或 Wishlist 仍有未满足需求 → 尝试融合 */
            fused = Callbacks->TryFuse(
                candidates, candidateCount,
                Wishlist, OutItem);
        }
    }

    if (!fused) {
        /* ArgMax: 选评分最高的 */
        ULONG bestIdx = 0;
        for (i = 1; i < candidateCount; i++) {
            if (scores[i] > scores[bestIdx]) bestIdx = i;
        }
        *OutItem = *filledCands[bestIdx];
    }

    /* ── 阶段4: 满足检查 ── */
    if (Callbacks->FulfillCheck) {
        Callbacks->FulfillCheck(OutItem, Wishlist);
    } else {
        DefaultFulfillCheck(OutItem, Wishlist);
    }

    /* ── 阶段5: 需求推导 ── */
    if (Callbacks->DeriveNeeds) {
        Callbacks->DeriveNeeds(OutItem, Wishlist);
    }

    /* ── 阶段6: MITRE 概率更新 ── */
    if (Callbacks->UpdateMitreProbs) {
        Callbacks->UpdateMitreProbs(OutItem, Probs);
    }

    return TRUE;
}

/**************************************************/
/*           完整因果倒推流水线                      */
/**************************************************/

NTSTATUS
T3CausalBackwardInference(
    _In_  PIOA_FSM_EVIDENCE         Evidence,
    _Out_ PTIRE3_CAUSAL_INFERENCE   Result
    )
/*++
Routine Description:
    统一倒推循环 — 从最后一步开始，每步调用 T3pProcessCore。
    通过 Wishlist 在步骤间传递需求，通过 MitreProbs 累积概率。

    Wishlist 流转:
      初始: 空
      每步: 骨架内部 FulfillCheck 标记已满足需求 + DeriveNeeds 加入新需求
      结束: 写回 Result.FinalWishlist (未满足的需求用于报告)

    Probs 流转:
      初始: 空
      每步: UpdateMitreProbs 更新概率
      结束: 写回 Result.MitreProbs

Arguments:
    Evidence — FSM 精简证据包。
    Result   — [输出] 因果推断结果 (ConfirmedSteps + MitreProbs + FinalWishlist)。
--*/
{
    const FSM_PATTERN_TEMPLATE* tmpl;
    NTSTATUS status = STATUS_SUCCESS;

    /* 运行时 Wishlist 和 Probs */
    TIRE3_NEEDS_WISHLIST wishlist;
    T3_MITRE_PROB_DIST probs;

    if (!Evidence || !Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(TIRE3_CAUSAL_INFERENCE));

    if (Evidence->PatternIndex >= FSM_PATTERN_COUNT)
        return STATUS_INVALID_PARAMETER;

    tmpl = &WkdIoaEngine.FsmEngine->Patterns[Evidence->PatternIndex];

    if (Evidence->CurrentStep == 0)
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(&wishlist, sizeof(wishlist));
    RtlZeroMemory(&probs, sizeof(probs));
    probs.Count = T3_MITRE_PROB_MAX;

    printf("[T3Causal] Backward inference: FsmClass=%d, step=%lu/%lu\n",
           (int)Evidence->FsmClass, Evidence->CurrentStep, tmpl->StateCount - 1);

    for (LONG i = (LONG)Evidence->CurrentStep - 1; i >= 0; i--) {
        LARGE_INTEGER winStart, winEnd;     // 时间窗口
        IOA_GRAPH_EDGE_TYPE edgeType = tmpl->Steps[i].TriggerEdge;
        PTIRE3_EVIDENCE_ITEM confirmedStep = &Result->ConfirmedSteps[i];
        PT3_ANALYZER_CALLBACKS callbacks;
        BOOLEAN found;

        /* 路由: 获取步骤 i 的分析器 */
        callbacks = T3CausalAnalyzerRoute(Evidence->FsmClass, edgeType);
        if (!callbacks) {
            /* 回退: 尝试通用分析器 */
            callbacks = T3CausalAnalyzerRoute(FsmClass_None, edgeType);
        }
        if (!callbacks) {
            printf("[T3Causal] WARNING: No analyzer for EdgeType=%d "
                   "FsmClass=%d at step %ld\n",
                   (int)edgeType, (int)Evidence->FsmClass, i);
            Result->HasDiscrepancy = TRUE;
            break;
        }

        /* 时间窗口: WinStart=聚合边 FirstSeen, WinEnd=上一步确认时间 */
        T3GetAggregateEdgeTimeWindow(
            Evidence->SrcProcessNodeId,
            Evidence->TgtProcessNodeId,
            tmpl->Steps[i].TriggerEdge,
            &winStart, &winEnd);

        if (i != (LONG)Evidence->CurrentStep - 1) {
            winEnd = Result->ConfirmedSteps[i + 1].Timestamp;
        }

        /* 设置 Wishlist 当前步骤 (供 WishAppend 自动打 FromStepIndex) */
        wishlist.CurrentStep = i;

        /* ★ 统一 Process — 传入/传出 Wishlist 和 Probs */
        found = T3pProcessCore(
            Evidence->SrcProcessNodeId,
            Evidence->TgtProcessNodeId,
            edgeType,
            winStart, winEnd,
            &wishlist,      /* [in/out] */
            &probs,          /* [in/out] */
            confirmedStep,
            callbacks);

        if (!found) {
            printf("[T3Causal] Missing edge: type=%d step=%ld "
                   "— needs extra edge query\n",
                   (int)edgeType, i);

            Result->HasDiscrepancy = TRUE;

            /* 纳新边查询 */
            {
                TIRE3_EVIDENCE_ITEM extras[8];
                ULONG extraCount = T3QueryExtraEdge(
                    Evidence->SrcProcessNodeId,
                    Evidence->TgtProcessNodeId,
                    winStart, winEnd,
                    extras, 8);
                for (ULONG e = 0; e < extraCount && Result->ExtraCount < 8; e++) {
                    extras[e].IsExtraEdge = TRUE;
                    Result->ExtraEdges[Result->ExtraCount++] = extras[e];
                }
            }
            break;
        }

        if (Result->ConfirmedCount < TIRE3_MAX_EVIDENCE_ITEMS)
            Result->ConfirmedCount++;

        printf("[T3Causal] Step %ld confirmed: EdgeType=%d "
               "ContentConfidence=%u, WishlistActive=%lu\n",
               i, (int)edgeType, confirmedStep->ContentConfidence,
               wishlist.Count);
    }

    /* 写回 Result */
    Result->FinalWishlist = wishlist;
    Result->MitreProbs = probs;

    /*
     * 事后: 分段写入合并
     * (保留旧 T3MergeSegmentedWrites 作为补充,
     *  但 TryFuse 已在骨架中覆盖主要场景)
     */
    {
        TIRE3_EVIDENCE_ITEM writeItems[8];
        ULONG writeCount = 0;

        for (ULONG i = 0; i < Result->ConfirmedCount; i++) {
            if (Result->ConfirmedSteps[i].EdgeType == DefEdge_WritesTo) {
                if (writeCount < 8) {
                    writeItems[writeCount++] = Result->ConfirmedSteps[i];
                }
            }
        }

        if (writeCount >= 2) {
            TIRE3_EVIDENCE_ITEM merged;
            ULONG mergedCount = T3MergeSegmentedWrites(
                writeItems, writeCount, &merged);
            if (mergedCount >= 2) {
                printf("[T3Causal] Segmented writes merged: %lu -> 1 "
                       "(totalSize=%llu)\n",
                       mergedCount,
                       merged.Params.MemoryWrite.NumberOfBytesWritten);
                Result->MergedWriteCount = mergedCount;
            }
        }
    }

    printf("[T3Causal] Backward inference complete: %lu confirmed, "
           "%lu extra, %lu mergedWrites, discrepancy=%d, "
           "probsCount=%lu\n",
           Result->ConfirmedCount, Result->ExtraCount,
           Result->MergedWriteCount, Result->HasDiscrepancy,
           probs.Count);

    return status;
}

/**************************************************/
/*           分段写入合并                           */
/**************************************************/

ULONG
T3MergeSegmentedWrites(
    _Inout_ PTIRE3_EVIDENCE_ITEM WriteItems,
    _In_    ULONG                WriteCount,
    _Out_   PTIRE3_EVIDENCE_ITEM MergedItem
    )
{
    ULONG merged = 0;
    ULONG64 totalSize = 0;

    if (!WriteItems || WriteCount < 2 || !MergedItem) return 0;

    /* 排序: 按时间戳升序 */
    for (ULONG i = 1; i < WriteCount; i++) {
        TIRE3_EVIDENCE_ITEM temp = WriteItems[i];
        LONG j = (LONG)i - 1;
        while (j >= 0 && WriteItems[j].Timestamp.QuadPart > temp.Timestamp.QuadPart) {
            WriteItems[j + 1] = WriteItems[j];
            j--;
        }
        WriteItems[j + 1] = temp;
    }

    *MergedItem = WriteItems[0];
    merged = 1;
    totalSize = WriteItems[0].Params.MemoryWrite.NumberOfBytesWritten;

    for (ULONG i = 1; i < WriteCount; i++) {
        ULONG64 expectedNext = MergedItem->Params.MemoryWrite.BaseAddress + totalSize;
        ULONG64 gap = WriteItems[i].Params.MemoryWrite.BaseAddress - expectedNext;

        if (gap <= 4096) {
            totalSize += WriteItems[i].Params.MemoryWrite.NumberOfBytesWritten + (ULONG64)((LONG64)gap);
            merged++;
            if (WriteItems[i].Timestamp.QuadPart > MergedItem->Timestamp.QuadPart) {
                MergedItem->Timestamp = WriteItems[i].Timestamp;
            }
        } else {
            break;
        }
    }

    MergedItem->Params.MemoryWrite.NumberOfBytesWritten = totalSize;
    return merged;
}

/**************************************************/
/*           纳新边查询                             */
/**************************************************/

ULONG
T3QueryExtraEdge(
    _In_    GUID                  SourceNodeId,
    _In_    GUID                  TargetNodeId,
    _In_    LARGE_INTEGER         WindowStart,
    _In_    LARGE_INTEGER         WindowEnd,
    _Out_   PTIRE3_EVIDENCE_ITEM  ExtraItems,
    _In_    ULONG                 MaxExtra
    )
/*
 * 在因果图/聚合边表中搜索时间窗口内所有非模板类型边。
 * 返回找到的边数量。
 *
 * 简化实现: 遍历所有边类型, 查找窗口内存在且不在 ConfirmedSteps 中的边。
 */
{
    ULONG found = 0;

    if (!ExtraItems || MaxExtra == 0) return 0;

    /* 关注的纳新边类型: Hollows/ReflectiveLoad/Sideloads/AssociatedWith */
    static const IOA_GRAPH_EDGE_TYPE extraTypes[] = {
        DefEdge_Hollows,
        DefEdge_ReflectiveLoad,
        DefEdge_Sideloads,
        DefEdge_AssociatedWith,
        DefEdge_Executes,
        DefEdge_Impersonates,
    };
    static const ULONG extraTypeCount =
        sizeof(extraTypes) / sizeof(extraTypes[0]);

    for (ULONG t = 0; t < extraTypeCount && found < MaxExtra; t++) {
        PIOA_AGGREGATE_EDGE agg;
        PLIST_ENTRY entry;

        agg = IoaLookupAggregateEdge(WkdIoaEngine.EdgeAggTable,
                                      SourceNodeId, TargetNodeId, extraTypes[t]);
        if (!agg) continue;

        AcquireSRWLockShared(&agg->EdgeLock);
        for (entry = agg->EdgesHead.Flink;
             entry != &agg->EdgesHead && found < MaxExtra;
             entry = entry->Flink) {

            PIOA_CONCRETE_EDGE edge = CONTAINING_RECORD(
                entry, IOA_CONCRETE_EDGE, Link);

            if (edge->Timestamp.QuadPart < WindowStart.QuadPart ||
                edge->Timestamp.QuadPart >= WindowEnd.QuadPart) continue;
            if (!edge->Active) continue;

            RtlZeroMemory(&ExtraItems[found], sizeof(TIRE3_EVIDENCE_ITEM));
            ExtraItems[found].IsExtraEdge = TRUE;
            WkdCopyGuid(&ExtraItems[found].EdgeId, &edge->EdgeId);
            // ExtraItems[found].EdgeType  = edge->EdgeType;
            ExtraItems[found].Timestamp = edge->Timestamp;

            //printf("[T3Causal] Extra edge found: type=%d "
            //       "(timestamp=%lld)\n",
            //       (int)edge->EdgeType, edge->Timestamp.QuadPart);

            found++;
        }
        ReleaseSRWLockShared(&agg->EdgeLock);
        /* Lookup 返回已 pin 的边, 本类型遍历用毕归还引用 */
        IoaDereferenceAggregateEdge(agg);
    }

    return found;
}

/**************************************************/
/*           主动读取 Write 内容                    */
/**************************************************/

NTSTATUS
T3AnalyzeWriteContent(
    _Inout_ PTIRE3_EVIDENCE_ITEM WriteItem,
    _In_    HANDLE              TargetProcessHandle
    )
{
    UCHAR buffer[64];
    SIZE_T bytesRead = 0;
    BOOLEAN hasMZ = FALSE;
    BOOLEAN hasDllPath = FALSE;

    if (!WriteItem) return STATUS_INVALID_PARAMETER;

    if (TargetProcessHandle && TargetProcessHandle != INVALID_HANDLE_VALUE) {
        RtlZeroMemory(buffer, sizeof(buffer));
        if (ReadProcessMemory(TargetProcessHandle,
                              (LPCVOID)(ULONG_PTR)WriteItem->Params.MemoryWrite.BaseAddress,
                              buffer, sizeof(buffer), &bytesRead) &&
            bytesRead > 0) {

            memcpy(WriteItem->Params.MemoryWrite.BufferHead, buffer,
                   min(bytesRead, sizeof(WriteItem->Params.MemoryWrite.BufferHead)));

            if (bytesRead >= 2 && buffer[0] == 0x4D && buffer[1] == 0x5A) {
                hasMZ = TRUE;
            }

            if (bytesRead >= 4) {
                BOOLEAN allPrintable = TRUE;
                ULONG strLen = 0;
                for (ULONG i = 0; i < min(bytesRead, 64); i++) {
                    if (buffer[i] == 0) { strLen = i; break; }
                    if (buffer[i] < 0x20 || buffer[i] > 0x7E) {
                        if (buffer[i] != '\\' && buffer[i] != ':') {
                            allPrintable = FALSE;
                            break;
                        }
                    }
                }
                if (allPrintable && strLen > 4) {
                    if (strLen >= 4 &&
                        (buffer[strLen-4] == '.' || buffer[strLen-4] == 'd') &&
                        (buffer[strLen-3] == 'd' || buffer[strLen-3] == 'l') &&
                        (buffer[strLen-2] == 'l' || buffer[strLen-2] == 'l')) {
                        hasDllPath = TRUE;
                    }
                    if (buffer[0] >= 'A' && buffer[0] <= 'Z' && buffer[1] == ':') {
                        hasDllPath = TRUE;
                    }
                }
            }
        }
    }

    WriteItem->Params.MemoryWrite.HasMZ     = hasMZ;
    WriteItem->Params.MemoryWrite.HasDllPath = hasDllPath;

    printf("[T3Causal] WriteContent analysis: hasMZ=%d hasDllPath=%d "
           "(addr=0x%llX, size=%llu)\n",
           hasMZ, hasDllPath,
           WriteItem->Params.MemoryWrite.BaseAddress,
           WriteItem->Params.MemoryWrite.NumberOfBytesWritten);

    return STATUS_SUCCESS;
}
