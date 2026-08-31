/**************************************************/
/*  WkDefender IOA — Tier3 因果倒推引擎              */
/*                                                  */
/*  统一倒推循环 + 心愿清单 + 评分制候选决策。        */
/*                                                  */
/*  倒推循环从最后一步开始逐步骤回溯:                 */
/*    调用 T3pProcessCore 骨架 -> 公共骨架自动编排:   */
/*    Collect → ScoreCand → TryFuse/ArgMax →         */
/*    FulfillCheck → DeriveNeeds → UpdateMitreProbs  */
/*                                                  */
/*  步骤间通过 Wishlist (TIRE3_NEEDS_WISHLIST) 传递   */
/*  前置需求，通过 MitreProbs (T3_MITRE_PROB_DIST)   */
/*  累积概率分布。                                   */
/*                                                  */
/*  纳新边在倒推循环外执行，由内容深化结果触发。       */
/**************************************************/

#pragma once

#include "Tier3Engine.h"
#include "CausalAnalyzer.h"

/**************************************************/
/*           因果推断结果                           */
/**************************************************/

typedef struct _TIRE3_CAUSAL_INFERENCE {
    TIRE3_EVIDENCE_ITEM     ConfirmedSteps[TIRE3_MAX_EVIDENCE_ITEMS];
    ULONG                   ConfirmedCount;
    TIRE3_EVIDENCE_ITEM     ExtraEdges[8];          /* 纳新边 */
    ULONG                   ExtraCount;
    ULONG                   MergedWriteCount;       /* 被合并的写入数目 */
    BOOLEAN                 HasDiscrepancy;         /* 因果倒推结果与FSM归并不一致? */

    /* 倒推结束时的 Wishlist 快照 (用于报告未满足的需求) */
    TIRE3_NEEDS_WISHLIST    FinalWishlist;

    /* MITRE 概率组 (由分析器 UpdateMitreProbs 逐步骤累积) */
    T3_MITRE_PROB_DIST      MitreProbs;
} TIRE3_CAUSAL_INFERENCE, *PTIRE3_CAUSAL_INFERENCE;

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * 完整的因果倒推流水线 — 统一倒推循环 + 心愿清单。
 *
 * 从最后一步开始，每步调用 T3pProcessCore 骨架:
 *   骨架内部自动编排 Collect → ScoreCand → TryFuse/ArgMax →
 *   FulfillCheck → DeriveNeeds → UpdateMitreProbs
 *
 * 步骤间传递:
 *   Wishlist — [in/out] 待满足的前置需求（每步填充和消耗）
 *   MitreProbs — [in/out] 概率分布（每步累积更新）
 *
 * Evidence: FSM 精简证据包 (LastStepTime 用于定位最后一步)
 * Result:   因果一致性确认的边序列 + 纳新边 + 概率组
 */
NTSTATUS T3CausalBackwardInference(
    _In_  PIOA_FSM_EVIDENCE         Evidence,
    _Out_ PTIRE3_CAUSAL_INFERENCE   Result
    );

/*
 * 分段写入合并: 识别地址连续的多次 WriteProcessMemory。
 * 合并后的 TotalSize = Σ Size_i，覆盖地址范围 [MinBase, MaxBase+MaxSize)。
 */
ULONG T3MergeSegmentedWrites(
    _Inout_ PTIRE3_EVIDENCE_ITEM WriteItems,
    _In_    ULONG                WriteCount,
    _Out_   PTIRE3_EVIDENCE_ITEM MergedItem
    );

/*
 * 纳新边查询: 在因果图中搜索非模板边类型。
 * 由内容深化结果 (HasMZ/HasDllPath) 触发, 补全 FSM 模板缺口。
 */
ULONG T3QueryExtraEdge(
    _In_    GUID                  SourceNodeId,
    _In_    GUID                  TargetNodeId,
    _In_    LARGE_INTEGER         WindowStart,
    _In_    LARGE_INTEGER         WindowEnd,
    _Out_   PTIRE3_EVIDENCE_ITEM  ExtraItems,
    _In_    ULONG                 MaxExtra
    );

/*
 * 主动读取目标进程内存 (Write 阶段内容分析)。
 *
 * 读取 WriteProcessMemory 写入的内容，分析:
 *   - ASCII DLL 路径 → 标准DLL注入
 *   - MZ 魔数 → PE文件 (Hollowing/ReflectiveLoad)
 *   - 高熵/Shellcode特征 → 直接代码执行
 *
 * 结果写入 EvidenceItem.Params.MemoryWrite.BufferHead/HasMZ/HasDllPath。
 * 注意: 此函数由分析器的 DeepenContent 内部调用，也可独立使用。
 */
NTSTATUS T3AnalyzeWriteContent(
    _Inout_ PTIRE3_EVIDENCE_ITEM WriteItem,
    _In_    HANDLE              TargetProcessHandle
    );

/**************************************************/
/*           Wishlist 操作函数                      */
/*                                                  */
/*  方案B: 每条需求是独立条目，不做去重/合并。        */
/*  从 DeriveNeeds 调用 WishAppend 追加即可。        */
/**************************************************/

/*
 * 追加心愿条目到 Wishlist（纯 append，不做去重）。
 * FromStepIndex=0 时自动取自 Wish->CurrentStep。
 */
VOID
WishAppend(
    _Inout_ PTIRE3_NEEDS_WISHLIST Wish,
    _In_    PTIRE3_WISH_ENTRY     NewEntry
    );

/*
 * 压缩 Wishlist: 将所有 Active=FALSE 的条目移除。
 */
VOID
WishCompact(
    _Inout_ PTIRE3_NEEDS_WISHLIST Wish
    );

/*
 * 检查 Wishlist 是否全部满足。
 */
BOOLEAN
WishIsEmpty(
    _In_ PTIRE3_NEEDS_WISHLIST Wish
    );

/*
 * 单条目满足检查 — 写地址被 [BaseAddr, BaseAddr+Size) 覆盖 → Active=FALSE。
 */
BOOLEAN
WishFulfillWriteAt(
    _Inout_ PTIRE3_WISH_ENTRY Wish,
    _In_    ULONG64           BaseAddr,
    _In_    ULONG64           Size
    );

/*
 * 单条目满足检查 — 分配范围被 [BaseAddr, BaseAddr+Size] 覆盖 → Active=FALSE。
 */
BOOLEAN
WishFulfillAllocCover(
    _Inout_ PTIRE3_WISH_ENTRY Wish,
    _In_    ULONG64           BaseAddr,
    _In_    ULONG64           Size
    );

/*
 * 单条目满足检查 — 权限位全覆盖 → Active=FALSE。
 */
BOOLEAN
WishFulfillAccessMask(
    _Inout_ PTIRE3_WISH_ENTRY Wish,
    _In_    ULONG             GrantedAccess
    );

/**************************************************/
/*           评分辅助函数                           */
/**************************************************/

/*
 * 计算写地址覆盖度评分 [0, 100]:
 *   RequiredAddr 在 [BaseAddr, BaseAddr+Size) 内 → 100
 *   否则基于距离衰减
 */
ULONG
Score_WriteAddressCoverage(
    _In_ ULONG64 BaseAddr,
    _In_ ULONG64 Size,
    _In_ ULONG64 RequiredAddr
    );

/*
 * 计算访问权限覆盖度评分 [0, 100]:
 *   popcount(Granted & Required) / popcount(Required) * 100
 */
ULONG
Score_AccessMaskCoverage(
    _In_ ULONG GrantedAccess,
    _In_ ULONG RequiredAccess
    );

/*
 * 计算内容匹配评分 [0, 100]:
 *   HasFeature == NeedFeature → 100 (或 NeedFeature=FALSE → 50)
 *   HasFeature=FALSE && NeedFeature=TRUE → 0
 */
ULONG
Score_ContentMatch(
    _In_ BOOLEAN HasFeature,
    _In_ BOOLEAN NeedFeature
    );
