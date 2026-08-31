/**************************************************/
/*  WkDefender IOA — Tier3 分析器回调注册表           */
/*                                                  */
/*  重构: 统一 Process 骨架 + 心愿清单 + 评分制决策   */
/*                                                  */
/*  每个边类型注册一组回调 (T3_ANALYZER_CALLBACKS):   */
/*    Collect    — 候选收集 (可选, 默认单类型)        */
/*    ScoreCand  — 提取+深化+评分 (必选)              */
/*    TryFuse    — 融合尝试 (可选)                    */
/*    FulfillCheck — 满足检查 (可选, 标记 Active=FALSE)*/
/*    DeriveNeeds — 需求推导 (必选, 链首可 NULL)      */
/*    UpdateMitreProbs — 概率更新 (必选)              */
/*                                                  */
/*  骨架 T3pProcessCore 自动编排上述回调顺序。        */
/**************************************************/

#pragma once

#include "Tier3Engine.h"

/**************************************************/
/*           分析器回调集                           */
/**************************************************/

typedef struct _T3_ANALYZER_CALLBACKS {
    PCWSTR Name;

    /*
     * Collect — 候选收集 (可选)
     *
     * 默认行为: 查单类型聚合边 + 时间窗口过滤。
     * 覆盖场景: 跨类型收集 (如 Hollowing 同时收集 Unmap+Allocates)。
     *
     * 返回收集到的候选数量，0=无候选。
     */
    ULONG (*Collect)(
        _In_    GUID                SourceNodeId,
        _In_    GUID                TargetNodeId,
        _In_    IOA_GRAPH_EDGE_TYPE TargetType,
        _In_    LARGE_INTEGER       WinStart,
        _In_    LARGE_INTEGER       WinEnd,
        _Out_   PT3_CANDIDATE_INFO  Candidates,
        _In_    ULONG               MaxCand
        );

    /*
     * ScoreCand — 评分函数 (必选)
     *
     * 对单条候选边执行:
     *   1. 从事件存储提取参数 → 填充 OutItem.Params
     *   2. 需要时 ReadProcessMemory 深化 → OutItem.HasMZ/..
     *   3. 参照 Wishlist 计算匹配分 [0, 100]
     *
     * 返回评分，0=完全无关。
     */
    ULONG (*ScoreCand)(
        _In_    PT3_CANDIDATE_INFO      Candidate,
        _In_    PTIRE3_NEEDS_WISHLIST   Wishlist,
        _Out_   PTIRE3_EVIDENCE_ITEM    OutItem
        );

    /*
     * TryFuse — 融合尝试 (可选)
     *
     * 在有≥2条候选且评分最高者不能完全满足 Wishlist 时触发。
     * 成功时填充 FusedItem 并返回 TRUE。
     *
     * 典型场景:
     *   - 分段 WritesTo: gap ≤ 4KB 的多段写入合并
     *   - 分阶段 Opens: DesiredAccess 按位或合并
     */
    BOOLEAN (*TryFuse)(
        _In_    PT3_CANDIDATE_INFO      Candidates,
        _In_    ULONG                   Count,
        _In_    PTIRE3_NEEDS_WISHLIST   Wishlist,
        _Out_   PTIRE3_EVIDENCE_ITEM    FusedItem
        );

    /*
     * FulfillCheck — 满足检查 (可选)
     *
     * 检查 OutItem 满足 Wishlist 中的哪些条目，标记为 Active=FALSE。
     * 默认: 按边类型匹配移除同类需求。
     * 定制: WritesTo 检查地址覆盖+内容，Open 检查权限位。
     */
    VOID (*FulfillCheck)(
        _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
        _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist
        );

    /*
     * DeriveNeeds — 需求推导 (必选, 链首可 NULL)
     *
     * 从 OutItem 推导对更前步骤的需求。
     * 新需求通过 WishAppend 加入 Wishlist (纯追加，不做去重)。
     */
    VOID (*DeriveNeeds)(
        _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
        _Inout_ PTIRE3_NEEDS_WISHLIST   Wishlist
        );

    /*
     * UpdateMitreProbs — 概率更新 (必选)
     *
     * 基于当前步骤的证据调整 MITRE 概率分布。
     * 如 ThreadCreate 确认 IsLoadLibrary → T1055.001 提升。
     */
    VOID (*UpdateMitreProbs)(
        _In_    PTIRE3_EVIDENCE_ITEM    OutItem,
        _Inout_ PT3_MITRE_PROB_DIST     Probs
        );

} T3_ANALYZER_CALLBACKS, *PT3_ANALYZER_CALLBACKS;

/**************************************************/
/*           注册条目                               */
/**************************************************/

typedef struct _T3_ANALYZER_REG {
    FSM_ATTACK_CLASS    FsmClass;           /* FsmClass_None = 通用 */
    IOA_GRAPH_EDGE_TYPE EdgeType;
    T3_ANALYZER_CALLBACKS Callbacks;         /* 值拷贝 (静态分配) */
} T3_ANALYZER_REG, *PT3_ANALYZER_REG;

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * 初始化回调注册表，注册所有内置分析器。
 */
VOID T3Registry_Initialize(VOID);

/*
 * 路由: 根据 FsmClass + EdgeType 查找对应的分析器回调。
 * 返回指向静态回调集的指针，或 NULL (未注册)。
 */
PT3_ANALYZER_CALLBACKS T3CausalAnalyzerRoute(
    _In_ FSM_ATTACK_CLASS    FsmClass,
    _In_ IOA_GRAPH_EDGE_TYPE EdgeType
    );

/*
 * 注册新的分析器回调。
 */
VOID T3Registry_Register(
    _In_ FSM_ATTACK_CLASS        FsmClass,
    _In_ IOA_GRAPH_EDGE_TYPE     EdgeType,
    _In_ PT3_ANALYZER_CALLBACKS  Callbacks,
    _In_ PCWSTR                  Name
    );

/* ── 内置分析器声明 ── */

extern T3_ANALYZER_CALLBACKS g_T3A_ProcessOpen;
extern T3_ANALYZER_CALLBACKS g_T3A_MemoryAlloc;
extern T3_ANALYZER_CALLBACKS g_T3A_MemoryWrite;
extern T3_ANALYZER_CALLBACKS g_T3A_MemoryProtect;
extern T3_ANALYZER_CALLBACKS g_T3A_ThreadCreate;
extern T3_ANALYZER_CALLBACKS g_T3A_ProcessCreate;
extern T3_ANALYZER_CALLBACKS g_T3A_NetworkConnect;
