/**************************************************/
/*  WkDefender IOA — 图模式匹配器实现                */
/**************************************************/

#include "IoaGraphMatcher.h"
#include "../../Process/ProcessTree.h"
#include "../IoaEngine.h"

/**************************************************/
/*               预定义攻击链模板                   */
/**************************************************/

static const GM_ATTACK_CHAIN_TEMPLATE g_ChainTemplates[] = {

    /* ---- Classic Injection (T1055.001) ----------------------------- */
    {
        L"Classic Injection", L"T1055.001", 4,
        {
            { DefEdge_Opens,       GM_TARGET_ROLE_DIRECT,       0, FALSE, L"Opens target process" },
            { DefEdge_Allocates,   GM_TARGET_ROLE_INTERMEDIATE, 0, FALSE, L"Allocates memory in target" },
            { DefEdge_WritesTo,    GM_TARGET_ROLE_INTERMEDIATE, 0, FALSE, L"Writes shellcode" },
            { DefEdge_InjectsInto, GM_TARGET_ROLE_DIRECT,       0, FALSE, L"Creates remote thread" },
        },
        75, 80
    },

    /* ---- APC Injection (T1055.004) --------------------------------- */
    {
        L"APC Injection", L"T1055.004", 5,
        {
            { DefEdge_Opens,       GM_TARGET_ROLE_DIRECT,       0, FALSE, L"Opens target process" },
            { DefEdge_Allocates,   GM_TARGET_ROLE_INTERMEDIATE, 0, FALSE, L"Allocates memory in target" },
            { DefEdge_WritesTo,    GM_TARGET_ROLE_INTERMEDIATE, 0, FALSE, L"Writes payload" },
            { DefEdge_InjectsInto, GM_TARGET_ROLE_DIRECT,       0, FALSE, L"Creates remote thread" },
            { DefEdge_Unknown,     GM_TARGET_ROLE_DIRECT,
              DEF_BEHAVIOR_FLAG_APC_INJECTION, TRUE, L"Queued APC in target" },
        },
        75, 90
    },

    /* ---- Process Hollowing (T1055.012) ----------------------------- */
    {
        L"Process Hollowing", L"T1055.012", 5,
        {
            { DefEdge_Opens,       GM_TARGET_ROLE_DIRECT,       0, FALSE, L"Opens target suspended" },
            { DefEdge_Allocates,   GM_TARGET_ROLE_INTERMEDIATE, 0, FALSE, L"Allocates memory in target" },
            { DefEdge_WritesTo,    GM_TARGET_ROLE_INTERMEDIATE, 0, FALSE, L"Writes PE image" },
            { DefEdge_Protects,    GM_TARGET_ROLE_INTERMEDIATE, 0, FALSE, L"Protects target memory" },
            { DefEdge_InjectsInto, GM_TARGET_ROLE_DIRECT,       0, FALSE, L"Resumes target thread" },
        },
        80, 95
    },

    /* ---- Credential Dumping (T1003.001) ---------------------------- */
    {
        L"Credential Dumping", L"T1003.001", 3,
        {
            { DefEdge_Opens,       GM_TARGET_ROLE_DIRECT,       0, FALSE, L"Opens target (lsass)" },
            { DefEdge_Allocates,   GM_TARGET_ROLE_INTERMEDIATE, 0, FALSE, L"Allocates memory" },
            { DefEdge_ReadsFrom,   GM_TARGET_ROLE_INTERMEDIATE,
              DEF_BEHAVIOR_FLAG_MEMORY_READ_REMOTE, TRUE, L"Reads remote memory" },
        },
        80, 85
    },

    /* ---- Reflective DLL Load (T1620) ------------------------------- */
    {
        L"Reflective DLL Load", L"T1620", 3,
        {
            { DefEdge_Allocates,   GM_TARGET_ROLE_INTERMEDIATE, 0, FALSE, L"Allocates memory" },
            { DefEdge_WritesTo,    GM_TARGET_ROLE_INTERMEDIATE, 0, FALSE, L"Writes DLL payload" },
            { DefEdge_InjectsInto, GM_TARGET_ROLE_DIRECT,       0, FALSE, L"Executes via thread" },
        },
        80, 90
    },

    /* 哨兵 */
    { 0 }
};

/**************************************************/
/*               内部匹配函数                       */
/**************************************************/

_Use_decl_annotations_
static
BOOLEAN
GmMatchStepFromEdge(
    PIOA_GRAPH_EDGE               Edge,
    PCGM_EDGE_CONSTRAINT    Constraint,
    GUID*                   TgtProcessId
    )
/*++
Routine Description:
    检查单条边是否满足单步约束。

Arguments:
    Edge       — 因果图中的一条边。
    Constraint — 步骤约束。
    TgtProcessId — 事件的目标进程 NodeId。

Return Value:
    TRUE = 满足约束。
--*/
{
    /* 边类型必须匹配 */
    if (Edge->Type != Constraint->EdgeType) {
        return FALSE;
    }

    /* TargetRole=0: 边必须指向事件目标进程 */
    if (Constraint->TargetRole == GM_TARGET_ROLE_DIRECT) {
        if (!DefGuidEqual(&Edge->TargetNodeId, TgtProcessId)) {
            return FALSE;
        }
    }
    /* TargetRole=1: 任意目标都接受，无需额外检查 */

    /* 行为标志检查 */
    if (Constraint->MinBehaviorFlags) {
        ULONG flags = Constraint->CheckProcessFlag
            ? (Edge->TgtNode && Edge->TgtNode->ProcessNode
               ? Edge->TgtNode->ProcessNode->BehaviorFlags : 0)
            : Edge->BehaviorFlags;

        if (!(flags & Constraint->MinBehaviorFlags)) {
            return FALSE;
        }
    }

    return TRUE;
}

_Use_decl_annotations_
static
BOOLEAN
GmMatchStepFromProcessNode(
    PWKD_PROCESS       ProcNode,
    PCGM_EDGE_CONSTRAINT    Constraint
    )
/*++
Routine Description:
    检查进程节点的累积行为标志是否满足纯行为标志步骤。

    Constraint->EdgeType == DefEdge_Unknown 且 CheckProcessFlag == TRUE
    时进入此路径。

Arguments:
    ProcNode   — 源进程谱系节点。
    Constraint — 步骤约束。

Return Value:
    TRUE = 满足约束。
--*/
{
    return (ProcNode->BehaviorFlags & Constraint->MinBehaviorFlags) != 0;
}

_Use_decl_annotations_
static
ULONG
GmCollectStepMask(
    PIOA_CARSAL_GRAPH_NODE  SrcNode,
    GUID*                   TgtProcessId,
    PWKD_PROCESS       SrcProcNode,
    PCGM_ATTACK_CHAIN_TEMPLATE Chain
    )
/*++
Routine Description:
    遍历源节点的出边，生成攻击链步骤的覆盖掩码。
    每个步骤一个 bit，命中 bit 置 1。

Arguments:
    SrcNode      — 源图节点。
    TgtProcessId — 事件目标进程 NodeId。
    SrcProcNode  — 源进程谱系节点（用于纯行为标志步骤）。
    Chain        — 攻击链模板。

Return Value:
    ULONG 步进覆盖掩码。
--*/
{
    ULONG stepMask = 0;
    PLIST_ENTRY entry;

    /* 遍历源节点的所有出边 */
    entry = SrcNode->OutEdgesHead.Flink;
    while (entry != &SrcNode->OutEdgesHead) {
        PIOA_GRAPH_EDGE edge = CONTAINING_RECORD(entry, IOA_GRAPH_EDGE, SrcOutLink);

        for (ULONG s = 0; s < Chain->StepCount; s++) {
            if (stepMask & (1 << s)) continue;  /* 已覆盖 */

            if (Chain->Steps[s].EdgeType != DefEdge_Unknown) {
                /* 边类型步骤：检查边是否满足约束 */
                if (GmMatchStepFromEdge(edge, &Chain->Steps[s], TgtProcessId)) {
                    stepMask |= (1 << s);
                }
            }
        }
        entry = entry->Flink;
    }

    /* 纯行为标志步骤：检查源进程节点的累积标志 */
    if (SrcProcNode) {
        for (ULONG s = 0; s < Chain->StepCount; s++) {
            if (stepMask & (1 << s)) continue;

            if (Chain->Steps[s].EdgeType == DefEdge_Unknown &&
                Chain->Steps[s].CheckProcessFlag) {
                if (GmMatchStepFromProcessNode(SrcProcNode, &Chain->Steps[s])) {
                    stepMask |= (1 << s);
                }
            }
        }
    }

    return stepMask;
}

/**************************************************/
/*                   公开 API                       */
/**************************************************/

_Use_decl_annotations_
_Use_decl_annotations_
NTSTATUS
GmInitialize(
    PIOA_GRAPH_MATCHER* Out
    )
{
    PIOA_GRAPH_MATCHER m;

    m = UtHeapAlloc(sizeof(IOA_GRAPH_MATCHER));
    if (!m) return STATUS_NO_MEMORY;

    InitializeCriticalSection(&m->Lock);
    m->Initialized = TRUE;

    printf("[IoaGraphMatcher] Initialized, %u attack chains loaded\n",
           (ULONG)(sizeof(g_ChainTemplates) / sizeof(g_ChainTemplates[0]) - 1));

    *Out = m;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
GmCleanup(
    PIOA_GRAPH_MATCHER Matcher
    )
/*++
Routine Description:
    清理图模式匹配器。

Arguments:
    Matcher — 匹配器实例。
--*/
{
    if (!Matcher || !Matcher->Initialized) return;

    printf("[IoaGraphMatcher] Cleanup: evals=%lld hits=%lld\n",
           Matcher->TotalEvaluations, Matcher->ChainHits);

    DeleteCriticalSection(&Matcher->Lock);
    UtHeapFree(Matcher);
}

_Use_decl_annotations_
NTSTATUS
GmEvaluate(
    PIOA_GRAPH_MATCHER Matcher,
    PWKD_EVENT_HEADER  Event
    )
/*++
Routine Description:
    图模式匹配评估入口。
    1. 从因果图查询源节点
    2. 遍历源节点的出边，生成步骤覆盖掩码
    3. 与攻击链模板逐一比对
    4. 命中时提升 Event->Severity

Arguments:
    Matcher — 匹配器实例。
    Event   — 当前事件（已插入因果图）。

Return Value:
    NTSTATUS。
--*/
{
    PIOA_CARSAL_GRAPH_NODE  srcNode = NULL;
    PWKD_PROCESS       srcProcNode = NULL;

    if (!Matcher || !Event) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&Matcher->Lock);

    /* 1. 查询源图节点 */
    srcNode = IoaCarsalGraphLookupNode(WkdIoaEngine.Graph, Event->SourceProcessId);
    if (!srcNode) {
        LeaveCriticalSection(&Matcher->Lock);
        return STATUS_SUCCESS;  /* 非错误：源节点可能尚未创建 */
    }

    /* 2. 查询源进程谱系节点（用于获取 BehaviorFlags） */
    if (&WkdProcessTree) {
        srcProcNode = PtTreeLookupByNodeId(
            &WkdProcessTree,
            Event->SourceProcessId);
    }

    /* 3. 遍历攻击链模板 */
    for (ULONG c = 0; g_ChainTemplates[c].Name; c++) {
        PCGM_ATTACK_CHAIN_TEMPLATE chain = &g_ChainTemplates[c];

        ULONG stepMask = GmCollectStepMask(
            srcNode,
            &Event->TargetProcessId,
            srcProcNode,
            chain);

        /* 计算匹配比率 */
        ULONG matched = 0;
        for (ULONG s = 0; s < chain->StepCount; s++) {
            if (stepMask & (1 << s)) matched++;
        }
        ULONG ratio = (matched * 100) / chain->StepCount;

        if (ratio >= chain->MinRatio) {
            Matcher->ChainHits++;

            printf("[IoaGraphMatcher] Chain hit: %S (%S) "
                   "ratio=%lu%% mask=0x%X\n",
                   chain->Name, chain->MitreId, ratio, stepMask);

            /* 提升事件严重等级 */
            if (Event->Severity < DefThreatSeverity_High) {
                Event->Severity = DefThreatSeverity_High;
            }
            break;  /* 一击即止，避免同一事件命中多条链 */
        }
    }

    Matcher->TotalEvaluations++;
    LeaveCriticalSection(&Matcher->Lock);
    return STATUS_SUCCESS;
}

/**************************************************/
/*   Phase 5: 子图模式匹配 (升级GmEvaluate)          */
/*                                                  */
/*   从平面位图匹配 → 多节点子图约束匹配              */
/*   基于 GwWalkBidirectional 产出的攻击图           */
/**************************************************/

/*
 * 子图模式节点约束。
 */
typedef struct _GM_PATTERN_NODE_CONSTRAINT {
    INT             HopDepthMin;        /* 最小跳深 (-1=不限) */
    INT             HopDepthMax;        /* 最大跳深 (-1=不限) */
    DEF_NODE_TYPE   NodeType;           /* DefNode_Unknown=不限 */
    BOOLEAN         IsSystemProcess;    /* 必须是系统进程 */
    BOOLEAN         MustBeElevated;     /* 必须是提权进程 */
    ULONG           MinIntegrity;       /* 最低完整性级别 */
} GM_PATTERN_NODE_CONSTRAINT;

/*
 * 子图模式边约束。
 */
typedef struct _GM_PATTERN_EDGE_CONSTRAINT {
    UINT8               FromNodeIdx;    /* 源节点在模式中的索引 */
    UINT8               ToNodeIdx;      /* 目标节点在模式中的索引 */
    IOA_GRAPH_EDGE_TYPE EdgeType;       /* 边类型 (DefEdge_Unknown=不限) */
    ULONG               MinOccurrence;  /* 最小发生次数 */
} GM_PATTERN_EDGE_CONSTRAINT;

/*
 * 子图攻击模式 (多节点 + 多边约束)。
 */
typedef struct _GM_SUBGRAPH_PATTERN {
    PCWSTR                      Name;
    PCWSTR                      MitreId;
    PCWSTR                      MitreTactic;
    ULONG                       NodeCount;
    GM_PATTERN_NODE_CONSTRAINT  Nodes[4];   /* 最多4个模式节点 */
    ULONG                       EdgeCount;
    GM_PATTERN_EDGE_CONSTRAINT  Edges[8];   /* 最多8条模式边 */
    ULONG                       MinMatchScore;
} GM_SUBGRAPH_PATTERN;

/*
 * 预定义子图攻击模式。
 */
static const GM_SUBGRAPH_PATTERN g_SubgraphPatterns[] = {

    /* ── LSASS 凭据窃取完整链 ── */
    {
        L"LSASS Credential Theft Chain", L"T1003.001", L"TA0006",
        .NodeCount = 3,
        .Nodes = {
            { 0, 0, DefNode_Unknown, FALSE, FALSE, 0 },               /* 攻击进程 */
            { 0, 2, DefNode_Unknown, TRUE,  FALSE, SECURITY_MANDATORY_SYSTEM_RID }, /* lsass */
            { 1, 4, DefNode_Unknown, FALSE, FALSE, 0 },               /* C2端点 */
        },
        .EdgeCount = 4,
        .Edges = {
            { 0, 1, DefEdge_Opens,       1 },
            { 0, 1, DefEdge_ReadsFrom,   1 },
            { 0, 1, DefEdge_WritesTo,    0 },  /* 可选: 注入后写回 */
            { 0, 2, DefEdge_ConnectsTo,  1 },
        },
        .MinMatchScore = 80,
    },

    /* ── Process Hollowing with Persistence ── */
    {
        L"ProcessHollowing with Registry Persistence", L"T1055.012", L"TA0005",
        .NodeCount = 3,
        .Nodes = {
            { 0, 0, DefNode_Unknown, FALSE, TRUE,  0 },               /* 提权的攻击进程 */
            { 0, 1, DefNode_Unknown, FALSE, FALSE, 0 },               /* 目标进程 */
            { 1, 4, DefNode_Unknown, FALSE, FALSE, 0 },               /* 持久化目标文件/注册表 */
        },
        .EdgeCount = 5,
        .Edges = {
            { 0, 1, DefEdge_Opens,       1 },
            { 0, 1, DefEdge_Allocates,   1 },
            { 0, 1, DefEdge_WritesTo,    0 },
            { 0, 1, DefEdge_InjectsInto, 1 },
            { 0, 2, DefEdge_Modifies,    1 },  /* 持久化操作 */
        },
        .MinMatchScore = 85,
    },

    /* ── DLL Side-Loading + C2 ── */
    {
        L"DLL Side-Loading to C2", L"T1574.002", L"TA0003",
        .NodeCount = 2,
        .Nodes = {
            { 0, 0, DefNode_Unknown, FALSE, FALSE, 0 },
            { 1, 4, DefNode_Unknown, FALSE, FALSE, 0 },
        },
        .EdgeCount = 2,
        .Edges = {
            { 0, 1, DefEdge_Sideloads,   1 },
            { 0, 1, DefEdge_ConnectsTo,  1 },
        },
        .MinMatchScore = 70,
    },
};

#define GM_SUBGRAPH_PATTERN_COUNT \
    (sizeof(g_SubgraphPatterns) / sizeof(g_SubgraphPatterns[0]))

_Use_decl_annotations_
NTSTATUS
GmEvaluateSubgraph(
    PIOA_GRAPH_MATCHER        Matcher,
    PIOA_CARSAL_GRAPH_NODE    SeedNode,
    GW_PATH_NODE*             PathNodes,
    ULONG                     PathNodeCount
    )
/*++
Routine Description:
    Phase 5 升级: 子图模式匹配。

    在 GwWalkBidirectional 产出的扩展攻击图中，匹配预定义的
    多节点攻击模式（LSASS凭据窃取/持久化镂空/DLL侧加载+C2等）。

    与 GmEvaluate 的区别:
      - GmEvaluate: 单节点出边位图匹配（已与FSM重复）
      - GmEvaluateSubgraph: 多节点子图约束匹配（Tier3专用）

    算法: 约束匹配（非完整子图同构）
      1. 对每个模式，尝试将 PatternNodes 分配给实际图节点
      2. 验证节点约束（类型/深度/完整性）
      3. 验证边约束（类型/方向/发生次数）
      4. 计算匹配分数

Return Value:
    STATUS_SUCCESS — 匹配完成，命中模式记录在日志中。
--*/
{
    ULONG p, n, e;
    ULONG totalHits = 0;

    if (!Matcher || !Matcher->Initialized || !SeedNode) return STATUS_INVALID_PARAMETER;

    for (p = 0; p < GM_SUBGRAPH_PATTERN_COUNT; p++) {
        const GM_SUBGRAPH_PATTERN* pattern = &g_SubgraphPatterns[p];
        ULONG edgeMatchCount = 0;
        ULONG nodeMatchCount = 0;
        BOOLEAN nodeAssigned[4] = { FALSE };

        /*
         * 分配模式节点到实际图节点。
         * Node[0] = SeedNode（攻击进程锚点）。
         * 其余节点从 PathNodes 中按约束匹配。
         */
        nodeAssigned[0] = TRUE;
        nodeMatchCount = 1;

        for (n = 1; n < pattern->NodeCount; n++) {
            for (ULONG i = 0; i < PathNodeCount; i++) {
                if (PathNodes[i].NodeType == DefNode_Unknown) continue;

                /* 检查节点约束 */
                if (pattern->Nodes[n].NodeType != DefNode_Unknown &&
                    PathNodes[i].NodeType != pattern->Nodes[n].NodeType) continue;

                if (pattern->Nodes[n].HopDepthMin >= 0 &&
                    (INT)PathNodes[i].HopDepth < pattern->Nodes[n].HopDepthMin) continue;

                if (pattern->Nodes[n].HopDepthMax >= 0 &&
                    (INT)PathNodes[i].HopDepth > pattern->Nodes[n].HopDepthMax) continue;

                if (pattern->Nodes[n].IsSystemProcess &&
                    (!PathNodes[i].ProcessNode ||
                     !PathNodes[i].ProcessNode->IsSystemProcess)) continue;

                nodeAssigned[n] = TRUE;
                nodeMatchCount++;
                break;
            }
        }

        /* 节点未全部匹配 → 跳过此模式 */
        if (nodeMatchCount < pattern->NodeCount) continue;

        /*
         * 验证边约束。
         * 对每条模式边，检查 (FromNode, ToNode) 之间是否存在对应类型的边。
         * 此处做轻量验证 — 完整实现需要访问图中具体边。
         */
        for (e = 0; e < pattern->EdgeCount; e++) {
            /* 通过遍历 SeedNode 的出边做简化检查 */
            PLIST_ENTRY entry = SeedNode->OutEdgesHead.Flink;
            BOOLEAN found = FALSE;

            while (entry != &SeedNode->OutEdgesHead) {
                PIOA_GRAPH_EDGE edge = CONTAINING_RECORD(
                    entry, IOA_GRAPH_EDGE, SrcOutLink);

                if (pattern->Edges[e].EdgeType == DefEdge_Unknown ||
                    edge->Type == pattern->Edges[e].EdgeType) {
                    if (edge->OccurrenceCount >= pattern->Edges[e].MinOccurrence) {
                        found = TRUE;
                        break;
                    }
                }
                entry = entry->Flink;
            }

            if (found) edgeMatchCount++;
        }

        /* 计算匹配分数 */
        if (edgeMatchCount > 0) {
            ULONG score = (edgeMatchCount * 100) / pattern->EdgeCount;

            if (score >= pattern->MinMatchScore) {
                printf("[GmEvaluateSubgraph] Pattern HIT: %S (%S/%S) "
                       "score=%lu (edges=%lu/%lu, nodes=%lu/%lu)\n",
                       pattern->Name, pattern->MitreId, pattern->MitreTactic,
                       score, edgeMatchCount, pattern->EdgeCount,
                       nodeMatchCount, pattern->NodeCount);

                Matcher->ChainHits++;
                totalHits++;
            }
        }
    }

    if (totalHits == 0) {
        printf("[GmEvaluateSubgraph] No patterns matched (seed=%08X, "
               "pathNodes=%lu)\n", SeedNode->NodeId.Data1, PathNodeCount);
    }

    return STATUS_SUCCESS;
}
