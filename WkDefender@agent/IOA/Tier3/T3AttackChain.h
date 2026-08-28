/**************************************************/
/*  WkDefender IOA — Tier3 攻击链池                 */
/*                                                  */
/*  管理活跃攻击链的生命周期:                        */
/*    1. 创建新链 (从 FSM 证据初始化)                */
/*    2. 主动合并 (进程重叠+时序+战术连贯性)          */
/*    3. 被动扩展 (威胁评分+完整度缺口驱动)           */
/*    4. 过期淘汰 (TTL 30分钟无活动)                 */
/*    5. 持久化 (PairContext 淘汰时晋升标注)          */
/**************************************************/

#pragma once

#include "Tier3Engine.h"

/**************************************************/
/*           合并评分权重                            */
/**************************************************/

#define T3_MERGE_WEIGHT_OVERLAP      40    /* 进程重叠度 */
#define T3_MERGE_WEIGHT_TEMPORAL     30    /* 时序连续性 */
#define T3_MERGE_WEIGHT_TACTICAL     20    /* 战术连贯性 */
#define T3_MERGE_WEIGHT_EDGE         10    /* 因果图边连通性 */
#define T3_MERGE_THRESHOLD           55    /* 合并评分阈值 [0,100] */

/**************************************************/
/*           危险等级                               */
/**************************************************/

typedef enum _T3_DANGER_LEVEL {
    T3Danger_Low        = 0,
    T3Danger_Medium     = 1,
    T3Danger_High       = 2,
    T3Danger_Critical   = 3,
} T3_DANGER_LEVEL;

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * 初始化/清理攻击链池。
 */
NTSTATUS T3ChainPool_Init(
    _Out_ PTIRE3_ATTACK_CHAIN_POOL Pool
    );

VOID T3ChainPool_Cleanup(
    _In_ PTIRE3_ATTACK_CHAIN_POOL Pool
    );

/*
 * 评估链的完整度 + 缺口列表。
 * Completeness 返回 [0.0, 1.0]。
 */
VOID T3Chain_AssessCompleteness(
    _In_  PTIRE3_ATTACK_CHAIN    Chain,
    _Out_ FLOAT*              Completeness,
    _Out_ ULONG*              MissingGaps       /* 位掩码 */
    );

/*
 * 评估当前操作的危险等级。
 */
T3_DANGER_LEVEL T3AssessDangerLevel(
    _In_ IOA_GRAPH_EDGE_TYPE  EdgeType
    );

/*
 * 从缺口列表生成图展开提示。
 * 返回生成的提示数量。
 */
ULONG T3Chain_GenerateGraphWalkHints(
    _In_  PTIRE3_ATTACK_CHAIN    Chain,
    _In_  ULONG               MissingGaps,
    _Out_ PT3_GRAPH_WALK_HINT Hints,
    _In_  ULONG               MaxHints
    );

/*
 * 将步骤添加到攻击链。
 * 引用 PairContext（含战术标注），存储参数证据。
 */
VOID T3Chain_AddStep(
    _Inout_ PTIRE3_ATTACK_CHAIN          Chain,
    _In_    PAE_PROCESS_PAIR PairCtx,
    _In_    PTIRE3_EVIDENCE_ITEM      Evidence
    );

BOOLEAN
T3QueryAttackChainIncludedProcess(
    _In_ PTIRE3_ATTACK_CHAIN    Chain,
    _In_ GUID                   ProcessNodeId
    );

VOID
T3AttackChainAttachProcess(
    _Inout_ PTIRE3_ATTACK_CHAIN Chain,
    _In_    GUID                ProcessNodeId
    );

/**************************************************/
/*        死代码函数声明 (AttackChainTracker 迁移)   */
/*        完整实现于 T3AttackChain.c 死代码分区,      */
/*        未接入活跃流水线.                         */
/**************************************************/

VOID T3Chain_IngestTechnique(
    _Inout_ PTIRE3_ATTACK_CHAIN Chain,
    _In_    PCWSTR              Technique
    );

VOID T3Chain_EvaluateTacticCoverage(
    _In_  PTIRE3_ATTACK_CHAIN Chain,
    _Out_ FLOAT*               Completeness,
    _Out_ ULONG*               MissingGaps
    );

VOID T3Chain_ConfirmAttack(
    _Inout_ PTIRE3_ATTACK_CHAIN Chain,
    _In_opt_ PIOA_TIER3_ENGINE   Engine
    );

ULONG T3Chain_ComputeConfidence(
    _In_ PTIRE3_ATTACK_CHAIN Chain
    );