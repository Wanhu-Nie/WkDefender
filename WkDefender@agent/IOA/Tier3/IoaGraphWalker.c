/**************************************************/
/*  WkDefender IOA — 图游走器实现                    */
/**************************************************/

#include "IoaGraphWalker.h"
#include "../IoaEngine.h"

/**************************************************/
/*               内部辅助                           */
/**************************************************/

static
VOID
GwFillPathNode(
    _Out_ PGW_PATH_NODE            Out,
    _In_  PIOA_CARSAL_GRAPH_NODE  GraphNode,
    _In_  IOA_GRAPH_EDGE_TYPE           IncomingEdge,
    _In_  ULONG                   Hop
    )
/*++
Routine Description:
    将因果图节点转换为对外游走路径节点。
--*/
{
    Out->NodeId   = GraphNode->NodeId;
    Out->NodeType = GraphNode->NodeType;
    Out->IncomingEdgeType = IncomingEdge;
    Out->HopDepth = Hop;
    Out->ProcessNode = GraphNode->ProcessNode;
    Out->EntityPath = GraphNode->EntityPath;
}

/**************************************************/
/*                   公开 API                       */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
GwInitialize(
    PIOA_GRAPH_WALKER* Out
    )
{
    PIOA_GRAPH_WALKER w;

    w = UtHeapAlloc(sizeof(IOA_GRAPH_WALKER));
    if (!w) return STATUS_NO_MEMORY;

    w->Initialized = TRUE;

    printf("[IoaGraphWalker] Initialized\n");
    *Out = w;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
GwCleanup(
    PIOA_GRAPH_WALKER Walker
    )
{
    if (!Walker || !Walker->Initialized) return;

    printf("[IoaGraphWalker] Cleanup\n");
    UtHeapFree(Walker);
}

_Use_decl_annotations_
NTSTATUS
GwWalkForward(
    PIOA_GRAPH_WALKER Walker,
    GUID              StartNodeId,
    IOA_GRAPH_EDGE_TYPE     EdgeTypeFilter,
    ULONG             MaxHops,
    GW_PATH_NODE      OutNodes[],
    PULONG            OutCount
    )
/*++
Routine Description:
    从 StartNodeId 沿出边追踪影响范围。
    采用 BFS 遍历，每步可选按 EdgeTypeFilter 过滤。

Arguments:
    Walker         — 游走器实例。
    StartNodeId    — 起始节点 GUID。
    EdgeTypeFilter — 边类型过滤器（DefEdge_Unknown=不限）。
    MaxHops        — 最大步数。
    OutNodes       — 输出节点列表。
    OutCount       — [IN]最大节点数 [OUT]实际节点数。

Return Value:
    NTSTATUS。
--*/
{
    PIOA_CARSAL_GRAPH_NODE start;
    ULONG count = 0;

    if (!Walker || !OutNodes || !OutCount || MaxHops == 0) return STATUS_INVALID_PARAMETER;

    start = IoaCarsalGraphLookupNode(WkdIoaEngine.Graph, StartNodeId);
    if (!start) {
        *OutCount = 0;
        return STATUS_SUCCESS;
    }

    /* BFS: 遍历出边 */
    PLIST_ENTRY e = start->OutEdgesHead.Flink;
    while (e != &start->OutEdgesHead && count < MaxHops) {
        PIOA_GRAPH_EDGE edge = CONTAINING_RECORD(e, IOA_GRAPH_EDGE, SrcOutLink);

        if (EdgeTypeFilter == DefEdge_Unknown || edge->Type == EdgeTypeFilter) {
            if (edge->TgtNode) {
                GwFillPathNode(&OutNodes[count], edge->TgtNode, edge->Type, count + 1);
                count++;
            }
        }
        e = e->Flink;
    }

    *OutCount = count;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
GwWalkBackward(
    PIOA_GRAPH_WALKER Walker,
    GUID              StartNodeId,
    IOA_GRAPH_EDGE_TYPE     EdgeTypeFilter,
    ULONG             MaxHops,
    GW_PATH_NODE      OutNodes[],
    PULONG            OutCount
    )
/*++
Routine Description:
    从 StartNodeId 沿入边回溯根因。

Arguments:
    Walker         — 游走器实例。
    StartNodeId    — 起始节点 GUID。
    EdgeTypeFilter — 边类型过滤器。
    MaxHops        — 最大步数。
    OutNodes       — 输出节点列表。
    OutCount       — [IN]最大节点数 [OUT]实际节点数。

Return Value:
    NTSTATUS。
--*/
{
    PIOA_CARSAL_GRAPH_NODE start;
    ULONG count = 0;

    if (!Walker || !OutNodes || !OutCount || MaxHops == 0) return STATUS_INVALID_PARAMETER;

    start = IoaCarsalGraphLookupNode(WkdIoaEngine.Graph, StartNodeId);
    if (!start) {
        *OutCount = 0;
        return STATUS_SUCCESS;
    }

    /* BFS: 遍历入边 */
    PLIST_ENTRY e = start->InEdgesHead.Flink;
    while (e != &start->InEdgesHead && count < MaxHops) {
        PIOA_GRAPH_EDGE edge = CONTAINING_RECORD(e, IOA_GRAPH_EDGE, TgtInLink);

        if (EdgeTypeFilter == DefEdge_Unknown || edge->Type == EdgeTypeFilter) {
            if (edge->SrcNode) {
                GwFillPathNode(&OutNodes[count], edge->SrcNode, edge->Type, count + 1);
                count++;
            }
        }
        e = e->Flink;
    }

    *OutCount = count;
    return STATUS_SUCCESS;
}

/**************************************************/
/*         P3: 双向图游走                           */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
GwWalkBidirectional(
    PIOA_GRAPH_WALKER  Walker,
    GUID               SeedNodeId,
    ULONG              MaxHops,
    GW_PATH_NODE       BackwardPath[],
    PULONG             BackwardCount,
    GW_PATH_NODE       ForwardPath[],
    PULONG             ForwardCount
    )
/*++
Routine Description:
    从种子节点做双向图游走，重建攻击链。
    回溯方向: 沿入边追溯攻击根因。
    前向方向: 沿出边追踪攻击影响范围。
    使用分层 BFS，确保每层所有节点都被处理。

Arguments:
    Walker         — 游走器实例
    SeedNodeId     — 种子节点
    MaxHops        — 最大跳数 (≤ GW_CHAIN_MAX_HOPS)
    BackwardPath   — 输出: 回溯路径（从最近到最远祖先）
    BackwardCount  — [IN] 最大节点数 / [OUT] 实际节点数
    ForwardPath    — 输出: 前向路径（从最近到最远影响）
    ForwardCount   — [IN] 最大节点数 / [OUT] 实际节点数

Return Value:
    NTSTATUS
--*/
{
    PIOA_CARSAL_GRAPH_NODE start;
    GUID queue[GW_CHAIN_MAX_NODES];
    GUID visited[GW_CHAIN_MAX_NODES];
    ULONG maxNodes;

    if (!Walker || !BackwardPath || !BackwardCount || !ForwardPath || !ForwardCount)
        return STATUS_INVALID_PARAMETER;
    if (MaxHops > GW_CHAIN_MAX_HOPS) MaxHops = GW_CHAIN_MAX_HOPS;

    maxNodes = (*BackwardCount < *ForwardCount) ? *BackwardCount : *ForwardCount;

    start = IoaCarsalGraphLookupNode(WkdIoaEngine.Graph, SeedNodeId);
    if (!start) {
        *BackwardCount = 0;
        *ForwardCount  = 0;
        return STATUS_SUCCESS;
    }

    /* ── 回溯方向 (入边): 找攻击根因 ── */
    {
        ULONG qHead = 0, qTail = 0, vCount = 0, outIdx = 0;
        ULONG i;

        WkdCopyGuid(&queue[qTail], &SeedNodeId); qTail++;
        WkdCopyGuid(&visited[vCount], &SeedNodeId); vCount++;
        GwFillPathNode(&BackwardPath[outIdx], start, DefEdge_Unknown, 0);
        outIdx++;

        ULONG layerStart = 0;
        for (ULONG depth = 1; depth <= MaxHops && outIdx < maxNodes; depth++) {
            ULONG layerEnd = qTail;
            BOOLEAN found = FALSE;
            for (i = layerStart; i < layerEnd && outIdx < maxNodes; i++) {
                PIOA_CARSAL_GRAPH_NODE cur = IoaCarsalGraphLookupNode(WkdIoaEngine.Graph, queue[i]);
                if (!cur) continue;
                PLIST_ENTRY e = cur->InEdgesHead.Flink;
                while (e != &cur->InEdgesHead && outIdx < maxNodes) {
                    PIOA_GRAPH_EDGE edge = CONTAINING_RECORD(e, IOA_GRAPH_EDGE, TgtInLink);
                    if (edge->SrcNode) {
                        BOOLEAN dup = FALSE;
                        ULONG v;
                        for (v = 0; v < vCount; v++) {
                            if (DefGuidEqual(&visited[v], &edge->SourceNodeId)) { dup = TRUE; break; }
                        }
                        if (!dup && vCount < GW_CHAIN_MAX_NODES) {
                            WkdCopyGuid(&visited[vCount], &edge->SourceNodeId); vCount++;
                            WkdCopyGuid(&queue[qTail], &edge->SourceNodeId); qTail++;
                            GwFillPathNode(&BackwardPath[outIdx], edge->SrcNode, edge->Type, depth);
                            outIdx++;
                            found = TRUE;
                        }
                    }
                    e = e->Flink;
                }
            }
            layerStart = layerEnd;
            if (!found) break;
        }
        *BackwardCount = outIdx;
    }

    /* ── 前向方向 (出边): 找攻击影响范围 ── */
    {
        ULONG qHead = 0, qTail = 0, vCount = 0, outIdx = 0;
        ULONG i;

        WkdCopyGuid(&queue[qTail], &SeedNodeId); qTail++;
        WkdCopyGuid(&visited[vCount], &SeedNodeId); vCount++;
        GwFillPathNode(&ForwardPath[outIdx], start, DefEdge_Unknown, 0);
        outIdx++;

        ULONG layerStart = 0;
        for (ULONG depth = 1; depth <= MaxHops && outIdx < maxNodes; depth++) {
            ULONG layerEnd = qTail;
            BOOLEAN found = FALSE;
            for (i = layerStart; i < layerEnd && outIdx < maxNodes; i++) {
                PIOA_CARSAL_GRAPH_NODE cur = IoaCarsalGraphLookupNode(WkdIoaEngine.Graph, queue[i]);
                if (!cur) continue;
                PLIST_ENTRY e = cur->OutEdgesHead.Flink;
                while (e != &cur->OutEdgesHead && outIdx < maxNodes) {
                    PIOA_GRAPH_EDGE edge = CONTAINING_RECORD(e, IOA_GRAPH_EDGE, SrcOutLink);
                    if (edge->TgtNode) {
                        BOOLEAN dup = FALSE;
                        ULONG v;
                        for (v = 0; v < vCount; v++) {
                            if (DefGuidEqual(&visited[v], &edge->TargetNodeId)) { dup = TRUE; break; }
                        }
                        if (!dup && vCount < GW_CHAIN_MAX_NODES) {
                            WkdCopyGuid(&visited[vCount], &edge->TargetNodeId); vCount++;
                            WkdCopyGuid(&queue[qTail], &edge->TargetNodeId); qTail++;
                            GwFillPathNode(&ForwardPath[outIdx], edge->TgtNode, edge->Type, depth);
                            outIdx++;
                            found = TRUE;
                        }
                    }
                    e = e->Flink;
                }
            }
            layerStart = layerEnd;
            if (!found) break;
        }
        *ForwardCount = outIdx;
    }

    return STATUS_SUCCESS;
}
