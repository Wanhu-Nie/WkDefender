/**************************************************/
/*  WkDefender IOA — 因果图引擎实现                 */
/**************************************************/

#include "IoaCarsalGraph.h"
#include "../Process/ProcessTree.h"
#include "IoaEngine.h"

/**************************************************/
/*               内部辅助函数                       */
/**************************************************/

static
ULONG
IoaCarsalGraphNodeHash(
    _In_ GUID* id
    )
{
    ULONG h = 5381;
    PUCHAR p = (PUCHAR)id;
    for (int i = 0; i < 16; i++) {
        h = ((h << 5) + h) + p[i];
    }
    return h % IOA_CARSAL_GRAPH_NODE_HASH_BUCKETS;
}

static
PIOA_CARSAL_GRAPH_NODE
IoaCarsalGraphAllocNode(
    VOID
    )
/*++
Routine Description:
    分配并初始化一个新的因果图节点。

Return Value:
    图节点指针，失败返回 NULL。
--*/
{
    PIOA_CARSAL_GRAPH_NODE n = UtHeapAlloc(sizeof(IOA_CARSAL_GRAPH_NODE));
    if (n) {
        InitializeListHead(&n->OutEdgesHead);
        InitializeListHead(&n->InEdgesHead);
        InitializeListHead(&n->HashLink);
        InitializeListHead(&n->GlobalLink);
        n->RefCount = 1;
    }
    return n;
}

static
PIOA_GRAPH_EDGE
IoaCarsalGraphAllocEdge(
    VOID
    )
/*++
Routine Description:
    分配并初始化一个新的因果图边。

Return Value:
    图边指针，失败返回 NULL。
--*/
{
    PIOA_GRAPH_EDGE e = UtHeapAlloc(sizeof(IOA_GRAPH_EDGE));
    if (e) {
        InitializeListHead(&e->SrcOutLink);
        InitializeListHead(&e->TgtInLink);
        InitializeListHead(&e->GlobalLink);
    }
    return e;
}

static
IOA_GRAPH_EDGE_TYPE
IoaCarsalGraphDeriveEdgeType(
    _In_ WKD_EVENT_TYPE t
    )
/*++
Routine Description:
    根据事件类型推导对应的因果图边类型。

Arguments:
    t — 事件类型。

Return Value:
    边类型枚举值，未匹配返回 DefEdge_Unknown。
--*/
{
    switch (t) {
    case WkdEvent_ProcessCreate:        return DefEdge_Creates;
    case WkdEvent_ProcessOpen:          return DefEdge_Opens;
    case WkdEvent_ThreadCreate:         return DefEdge_AssociatedWith;
    case WkdEvent_RemoteThreadCreate:   return DefEdge_InjectsInto;
    case WkdEvent_MemoryAllocate:       return DefEdge_Allocates;
    case WkdEvent_MemoryProtect:        return DefEdge_Protects;
    case WkdEvent_MemoryWrite:          return DefEdge_WritesTo;
    case WkdEvent_MemoryRead:           return DefEdge_ReadsFrom;
    case WkdEvent_ImageLoad:            return DefEdge_Executes;
    case WkdEvent_FileWrite:
    case WkdEvent_FileCreate:           return DefEdge_WritesTo;
    case WkdEvent_NamedPipeCreate:      return DefEdge_ListensOn;  /* 命名管道服务端监听（NamedPipeMonitor 迁移 2026-08） */
    case WkdEvent_NetworkConnect:       return DefEdge_ConnectsTo;
    case WkdEvent_RegSetValue:
    case WkdEvent_RegCreateKey:         return DefEdge_Modifies;

    /* ── 注入相关新事件映射 (PreAcquireSection 迁移 2026-08: 区段映射文件轨
     * AcquireSection 已激活; 线程/区段 syscall 轨 case 已落位, 依赖 SmInitialize 启用) ── */
    case WkdEvent_QueueApc:             return DefEdge_InjectsInto;  /* APC 注入 */
    case WkdEvent_SetThreadContext:     return DefEdge_InjectsInto;  /* 执行流劫持 */
    case WkdEvent_ThreadSuspend:
    case WkdEvent_ThreadResume:         return DefEdge_AssociatedWith; /* 线程操作 */
    case WkdEvent_MapViewOfSection:     return DefEdge_Allocates;   /* 远程映射 */
    case WkdEvent_UnmapViewOfSection:   return DefEdge_Hollows;     /* 镂空标志动作 */

    /* ── Token 操作事件 (PrivilegeMonitor 迁移 2026-08-06) ──
     * 令牌操纵家族统一映射 DefEdge_Impersonates，对齐 IoaFsmEngine.c 同款映射。 */
    case WkdEvent_TokenAdjustPrivileges:
    case WkdEvent_TokenDuplicate:
    case WkdEvent_TokenSetInformation:
    case WkdEvent_TokenImpersonate:     return DefEdge_Impersonates;

    default:                            return DefEdge_Unknown;
    }
}

/* 内部无锁查找: 仅供已持 Mgr->Lock 的路径复用 */
static
PIOA_CARSAL_GRAPH_NODE
IoaCarsalGraphpLookupUnlocked(
    _In_ PIOA_CARSAL_GRAPH  Mgr,
    _In_ GUID               NodeId
    )
{
    ULONG hi = IoaCarsalGraphNodeHash(&NodeId);
    PLIST_ENTRY e = Mgr->NodeHashBuckets[hi].Flink;

    while (e != &Mgr->NodeHashBuckets[hi]) {
        PIOA_CARSAL_GRAPH_NODE n = CONTAINING_RECORD(e, IOA_CARSAL_GRAPH_NODE, HashLink);
        if (DefGuidEqual(&n->NodeId, &NodeId)) return n;
        e = e->Flink;
    }
    return NULL;
}

PIOA_CARSAL_GRAPH_NODE
IoaCarsalGraphLookupNode(
    _In_ PIOA_CARSAL_GRAPH  Mgr,
    _In_ GUID               NodeId
    )
/*++
Routine Description:
    通过 NodeId 在哈希表中查找图节点。
    链头锁原则 (2026-08-25): 桶链读持 Mgr->Lock。
    CRITICAL_SECTION 为递归锁 — 已持 Mgr->Lock 的调用方
    (如 IoaGqGetProcessChildren) 重入安全; 返回裸指针借用,
    调用方须立即消费。

Arguments:
    Mgr    — 因果图实例。
    NodeId — 目标节点 GUID。

Return Value:
    图节点指针，未找到返回 NULL。
--*/
{
    PIOA_CARSAL_GRAPH_NODE found;

    EnterCriticalSection(&Mgr->Lock);
    found = IoaCarsalGraphpLookupUnlocked(Mgr, NodeId);
    LeaveCriticalSection(&Mgr->Lock);
    return found;
}

static
NTSTATUS
IoaCarsalGraphEnsureNode(
    _In_ PIOA_CARSAL_GRAPH     Mgr,
    _In_ GUID                  NodeId,
    _In_ DEF_NODE_TYPE         NodeType,
    _Out_ PIOA_CARSAL_GRAPH_NODE* Out
    )
/*++
Routine Description:
    确保指定 NodeId 的图节点存在。
    若已存在则直接返回，否则创建新节点并关联谱系节点。

Arguments:
    Mgr      — 因果图实例。
    NodeId   — 节点 GUID。
    NodeType — 节点类型。
    Out      — 接收节点指针。

Return Value:
    NTSTATUS。
--*/
{
    PIOA_CARSAL_GRAPH_NODE n = IoaCarsalGraphLookupNode(Mgr, NodeId);
    if (n) {
        *Out = n;
        return STATUS_SUCCESS;
    }

    n = IoaCarsalGraphAllocNode();
    if (!n) return STATUS_NO_MEMORY;

    WkdCopyGuid(&n->NodeId, &NodeId);
    n->NodeType = NodeType;
    GetSystemTimeAsFileTime((PFILETIME)&n->FirstSeen);
    n->LastSeen = n->FirstSeen;

    if (NodeType == DefNode_Process) {
        n->ProcessNode = PtTreeLookupByNodeId(
            &WkdProcessTree, NodeId);
    }

    ULONG hi = IoaCarsalGraphNodeHash(&NodeId);
    InsertTailList(&Mgr->NodeHashBuckets[hi], &n->HashLink);
    InsertTailList(&Mgr->NodeGlobalList, &n->GlobalLink);
    Mgr->NodeCount++;
    Mgr->TotalNodesCreated++;

    *Out = n;
    return STATUS_SUCCESS;
}

static
NTSTATUS
IoapCarsalGraphInsertEdge(
    _In_ PIOA_CARSAL_GRAPH      Mgr,
    _In_ PIOA_CARSAL_GRAPH_NODE Src,
    _In_ PIOA_CARSAL_GRAPH_NODE Tgt,
    _In_ IOA_GRAPH_EDGE_TYPE          EdgeType,
    _In_ DEF_EVENT_CLASS        EventClass,
    _In_ LARGE_INTEGER          Timestamp,
    _In_ ULONG                  Confidence,
    _In_ ULONG                  BehaviorFlags,
    _In_ GUID*                  EventId
    )
/*++
Routine Description:
    在源节点和目标节点之间插入一条因果边。
    若同类型边已存在（相同源→目标），则执行聚合更新：
    更新 LastSeen、累加 OccurrenceCount、平均 Confidence、按位或 BehaviorFlags。

Arguments:
    Mgr           — 因果图实例。
    Src           — 源节点。
    Tgt           — 目标节点。
    EdgeType      — 边类型。
    EventClass    — 事件分类。
    Timestamp     — 时间戳。
    Confidence    — 置信度。
    BehaviorFlags — 行为标志。
    EventId       — 事件 GUID（用于边关联）。

Return Value:
    NTSTATUS。
--*/
{
    /* 检查是否已存在同类型边到同一目标 */
    PLIST_ENTRY e = Src->OutEdgesHead.Flink;
    while (e != &Src->OutEdgesHead) {
        PIOA_GRAPH_EDGE edge = CONTAINING_RECORD(e, IOA_GRAPH_EDGE, SrcOutLink);
        if (edge->Type == EdgeType && DefGuidEqual(&edge->TargetNodeId, &Tgt->NodeId)) {
            edge->LastSeen = Timestamp;
            edge->OccurrenceCount++;
            edge->Confidence = (edge->Confidence + Confidence) / 2;
            edge->BehaviorFlags |= BehaviorFlags;
            Mgr->TotalEdgesCompacted++;
            return STATUS_SUCCESS;
        }
        e = e->Flink;
    }

    /* 创建新边 */
    PIOA_GRAPH_EDGE edge = IoaCarsalGraphAllocEdge();
    if (!edge) return STATUS_NO_MEMORY;

    CoCreateGuid(&edge->EdgeId);
    edge->Type       = EdgeType;
    edge->EventClass = EventClass;
    WkdCopyGuid(&edge->SourceNodeId, &Src->NodeId);
    WkdCopyGuid(&edge->TargetNodeId, &Tgt->NodeId);
    edge->SrcNode = Src;
    edge->TgtNode = Tgt;
    edge->FirstSeen = Timestamp;
    edge->LastSeen  = Timestamp;
    edge->OccurrenceCount = 1;
    edge->Confidence = Confidence;
    edge->Weight     = Confidence / 10;
    edge->BehaviorFlags = BehaviorFlags;

    if (EventId && !DefIsNullNodeId(*EventId)) {
        WkdCopyGuid(&edge->EventIds[0], EventId);
        edge->EventIdCount = 1;
    }

    InsertTailList(&Src->OutEdgesHead, &edge->SrcOutLink);
    InsertTailList(&Tgt->InEdgesHead, &edge->TgtInLink);
    InsertTailList(&Mgr->EdgeGlobalList, &edge->GlobalLink);
    Src->OutDegree++;
    Tgt->InDegree++;
    Mgr->EdgeCount++;
    Mgr->TotalEdgesCreated++;

    return STATUS_SUCCESS;
}

/**************************************************/
/*                   公开 API                       */
/**************************************************/

NTSTATUS
IoaCarsalGraphInitialize(
    _Out_ PIOA_CARSAL_GRAPH* OutMgr
    )
/*++
Routine Description:
    初始化因果图引擎。

Arguments:
    OutMgr — 接收因果图实例指针。

Return Value:
    NTSTATUS。
--*/
{
    PIOA_CARSAL_GRAPH mgr = UtHeapAlloc(sizeof(IOA_CARSAL_GRAPH));
    if (!mgr) return STATUS_NO_MEMORY;

    for (ULONG i = 0; i < IOA_CARSAL_GRAPH_NODE_HASH_BUCKETS; i++) {
        InitializeListHead(&mgr->NodeHashBuckets[i]);
    }
    InitializeListHead(&mgr->NodeGlobalList);
    InitializeListHead(&mgr->EdgeGlobalList);
    InitializeCriticalSection(&mgr->Lock);
    mgr->Initialized = TRUE;

    printf("[IoaCarsalGraph] Initialized: %u buckets\n", IOA_CARSAL_GRAPH_NODE_HASH_BUCKETS);
    *OutMgr = mgr;
    return STATUS_SUCCESS;
}

VOID
IoaCarsalGraphCleanup(
    _In_ PIOA_CARSAL_GRAPH Mgr
    )
/*++
Routine Description:
    清理因果图引擎，释放所有节点和边。

Arguments:
    Mgr — 因果图实例。

Return Value:
    VOID。
--*/
{
    if (!Mgr || !Mgr->Initialized) return;

    EnterCriticalSection(&Mgr->Lock);

    while (!IsListEmpty(&Mgr->EdgeGlobalList)) {
        PIOA_GRAPH_EDGE e = CONTAINING_RECORD(Mgr->EdgeGlobalList.Flink, IOA_GRAPH_EDGE, GlobalLink);
        RemoveEntryList(&e->GlobalLink);
        UtHeapFree(e);
    }
    while (!IsListEmpty(&Mgr->NodeGlobalList)) {
        PIOA_CARSAL_GRAPH_NODE n = CONTAINING_RECORD(Mgr->NodeGlobalList.Flink,
                                                     IOA_CARSAL_GRAPH_NODE, GlobalLink);
        RemoveEntryList(&n->GlobalLink);
        UtHeapFree(n);
    }

    LeaveCriticalSection(&Mgr->Lock);
    DeleteCriticalSection(&Mgr->Lock);

    printf("[IoaCarsalGraph] Cleanup: %lld nodes / %lld edges\n",
           Mgr->TotalNodesCreated, Mgr->TotalEdgesCreated);
    UtHeapFree(Mgr);
}

NTSTATUS
IoaCarsalGraphInsertEvent(
    _In_ PIOA_CARSAL_GRAPH   Mgr,
    _In_ PWKD_EVENT_HEADER   Event
    )
/*++
Routine Description:
    将安全事件插入因果图。
    根据事件类型推导边类型，确定源和目标节点类型，
    确保节点存在后插入边，并更新节点的 LastSeen。

Arguments:
    Mgr   — 因果图实例。
    Event — 安全事件。

Return Value:
    NTSTATUS。
--*/
{
    IOA_GRAPH_EDGE_TYPE       et;
    PIOA_CARSAL_GRAPH_NODE src = NULL, tgt = NULL;
    DEF_NODE_TYPE       tgtType;

    if (!Mgr || !Event) return STATUS_INVALID_PARAMETER;

    /* 推导边类型 */
    et = IoaCarsalGraphDeriveEdgeType(Event->Type);
    if (et == DefEdge_Unknown) return STATUS_SUCCESS;

    EnterCriticalSection(&Mgr->Lock);

    /* 源节点固定为进程类型 */
    if (NT_SUCCESS(IoaCarsalGraphEnsureNode(Mgr, Event->SourceProcessId,
                                            DefNode_Process, &src))) {
        src->LastSeen = Event->Timestamp;
    }

    /* 确定目标节点类型 */
    switch (Event->Type) {
    case WkdEvent_ProcessCreate:
    case WkdEvent_ProcessOpen:
    case WkdEvent_ThreadCreate:
    case WkdEvent_RemoteThreadCreate:
        tgtType = DefNode_Process;
        break;

    case WkdEvent_FileCreate:
    case WkdEvent_FileWrite:
        tgtType = DefNode_File;
        break;

    case WkdEvent_RegSetValue:
    case WkdEvent_RegCreateKey:
        tgtType = DefNode_Registry;
        break;

    case WkdEvent_NetworkConnect:
        tgtType = DefNode_Network;
        break;

    case WkdEvent_MemoryAllocate:
    case WkdEvent_MemoryProtect:
    case WkdEvent_MemoryWrite:
    case WkdEvent_MemoryRead:
        tgtType = DefNode_MemoryRegion;
        break;

    default:
        tgtType = DefNode_Unknown;
        break;
    }

    /* 插入边 */
    if (!DefIsNullNodeId(Event->TargetProcessId)) {
        if (NT_SUCCESS(IoaCarsalGraphEnsureNode(Mgr, Event->TargetProcessId,
                                                tgtType, &tgt))) {
            tgt->LastSeen = Event->Timestamp;

            IoapCarsalGraphInsertEdge(Mgr, src, tgt, et,
                                     Event->Class, Event->Timestamp,
                                     Event->Confidence, Event->BehaviorFlags,
                                     &Event->EventId);
        }
    }

    LeaveCriticalSection(&Mgr->Lock);
    return STATUS_SUCCESS;
}

VOID
IoaCarsalGraphPrune(
    _In_ PIOA_CARSAL_GRAPH  Mgr,
    _In_ LARGE_INTEGER      WindowStart
    )
/*++
Routine Description:
    修剪因果图，移除所有 LastSeen 早于 WindowStart 的边。

Arguments:
    Mgr         — 因果图实例。
    WindowStart — 时间窗口起点（文件时间）。

Return Value:
    VOID。
--*/
{
    if (!Mgr) return;

    ULONG pruned = 0;
    EnterCriticalSection(&Mgr->Lock);

    PLIST_ENTRY e = Mgr->EdgeGlobalList.Flink;
    while (e != &Mgr->EdgeGlobalList) {
        PLIST_ENTRY next = e->Flink;
        PIOA_GRAPH_EDGE edge = CONTAINING_RECORD(e, IOA_GRAPH_EDGE, GlobalLink);

        if (edge->LastSeen.QuadPart < WindowStart.QuadPart) {
            RemoveEntryList(&edge->SrcOutLink);
            RemoveEntryList(&edge->TgtInLink);
            RemoveEntryList(&edge->GlobalLink);

            if (edge->SrcNode) edge->SrcNode->OutDegree--;
            if (edge->TgtNode) edge->TgtNode->InDegree--;

            UtHeapFree(edge);
            Mgr->EdgeCount--;
            pruned++;
        }
        e = next;
    }

    LeaveCriticalSection(&Mgr->Lock);

    if (pruned) {
        printf("[IoaCarsalGraph] Pruned %lu edges\n", pruned);
    }
}

NTSTATUS
IoaCarsalGraphInsertEdge(
    _In_ PIOA_CARSAL_GRAPH   Mgr,
    _In_ PGRAPH_EDGE_DESCRIPTOR Desc
    )
/*++
Routine Description:
    从 GRAPH_EDGE_DESCRIPTOR (环形缓冲区条目) 插入因果图边。
    供后台消费线程调用。

    流程:
      1. 确保源节点存在 (DefNode_Process)
      2. 确保目标节点存在 (DefNode_Process / DefNode_MemoryRegion 等)
      3. 调用 IoaCarsalGraphInsertEdge 执行聚合插入

Arguments:
    Mgr  — 因果图实例。
    Desc — 边描述符。

Return Value:
    NTSTATUS。
--*/
{
    PIOA_CARSAL_GRAPH_NODE srcNode, tgtNode;
    DEF_NODE_TYPE tgtNodeType;
    NTSTATUS status;

    if (!Mgr || !Desc) return STATUS_INVALID_PARAMETER;
    if (DefIsNullNodeId(Desc->SourceNodeId)) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&Mgr->Lock);

    /* 确保源进程节点存在 */
    status = IoaCarsalGraphEnsureNode(Mgr, Desc->SourceNodeId, DefNode_Process, &srcNode);
    if (!NT_SUCCESS(status)) {
        LeaveCriticalSection(&Mgr->Lock);
        return status;
    }

    /* 确定目标节点类型 */
    if (!DefIsNullNodeId(Desc->TargetNodeId)) {
        switch (Desc->EdgeType) {
        case DefEdge_Creates:
        case DefEdge_Terminates:
        case DefEdge_Opens:
        case DefEdge_InjectsInto:
        case DefEdge_Hollows:
        case DefEdge_AssociatedWith:
            tgtNodeType = DefNode_Process;
            break;
        case DefEdge_Allocates:
        case DefEdge_Protects:
        case DefEdge_WritesTo:
        case DefEdge_ReadsFrom:
            tgtNodeType = DefNode_MemoryRegion;
            break;
        case DefEdge_Modifies:
            tgtNodeType = DefNode_File;
            break;
        case DefEdge_ConnectsTo:
        case DefEdge_ListensOn:
        case DefEdge_DnsQueries:
            tgtNodeType = DefNode_Network;
            break;
        case DefEdge_Executes:
            tgtNodeType = DefNode_Process;
            break;
        default:
            tgtNodeType = DefNode_Process;
            break;
        }
    } else {
        tgtNodeType = DefNode_Process;
    }

    /* 确保目标节点存在 */
    status = IoaCarsalGraphEnsureNode(Mgr, Desc->TargetNodeId, tgtNodeType, &tgtNode);
    if (!NT_SUCCESS(status)) {
        LeaveCriticalSection(&Mgr->Lock);
        return status;
    }

    /* 插入边 */
    status = IoapCarsalGraphInsertEdge(Mgr, srcNode, tgtNode,
                                      Desc->EdgeType, Desc->EventClass,
                                      Desc->Timestamp, Desc->Confidence,
                                      Desc->BehaviorFlags, &Desc->EdgeId);

    /* 更新源节点活动时间 */
    srcNode->LastSeen = Desc->Timestamp;
    tgtNode->LastSeen = Desc->Timestamp;

    LeaveCriticalSection(&Mgr->Lock);
    return status;
}

PIOA_GRAPH_EDGE
IoaCarsalGraphLookupEdge(
    _In_ PIOA_CARSAL_GRAPH   Mgr,
    _In_ GUID                 SourceNodeId,
    _In_ GUID                 TargetNodeId,
    _In_ IOA_GRAPH_EDGE_TYPE        EdgeType
    )
/*++
Routine Description:
    按 (Src, Tgt, EdgeType) 精确查找因果图中的边。
    供 Tier 2 FSM 证据包交叉验证使用。

    遍历源节点的出边链表，匹配目标节点和边类型。

Arguments:
    Mgr      — 因果图实例。
    SourceNodeId — 源节点 GUID。
    TargetNodeId — 目标节点 GUID。
    EdgeType  — 边类型。

Return Value:
    找到的边指针 (不增加引用计数)，未找到返回 NULL。
--*/
{
    PIOA_CARSAL_GRAPH_NODE srcNode;
    PLIST_ENTRY e;

    if (!Mgr) return NULL;
    if (DefIsNullNodeId(SourceNodeId) || DefIsNullNodeId(TargetNodeId)) return NULL;

    EnterCriticalSection(&Mgr->Lock);

    srcNode = IoaCarsalGraphLookupNode(Mgr, SourceNodeId);
    if (!srcNode) {
        LeaveCriticalSection(&Mgr->Lock);
        return NULL;
    }

    /* 遍历源节点的出边链表 */
    e = srcNode->OutEdgesHead.Flink;
    while (e != &srcNode->OutEdgesHead) {
        PIOA_GRAPH_EDGE edge = CONTAINING_RECORD(e, IOA_GRAPH_EDGE, SrcOutLink);
        if (edge->Type == EdgeType &&
            DefGuidEqual(&edge->TargetNodeId, &TargetNodeId)) {
            LeaveCriticalSection(&Mgr->Lock);
            return edge;
        }
        e = e->Flink;
    }

    LeaveCriticalSection(&Mgr->Lock);
    return NULL;
}

/**************************************************/
/*       关系查询 API (对齐 SS 进程关系图)            */
/*                                                  */
/*  迁移自 ShadowStrike ProcessRelationship.c       */
/*  PrGetNodeInfo / PrGetRelationships /            */
/*  PrGetChildren / PrGetStatistics。               */
/*  结构定义与函数声明见 IoaCarsalGraph.h。          */
/*                                                  */
/*  [死代码] SS 侧这些查询 API 全项目零消费           */
/*  (PrGetNodeInfo/PrGetRelationships/PrGetChildren/ */
/*  PrGetStatistics 无调用者), wkd 提供等价物         */
/*  供 UI/主动查询/紧急分析接线。                    */
/*  返回拷贝 + 计数, 不返回裸指针。                  */
/**************************************************/

NTSTATUS
IoaGqGetNodeInfo(
    _In_  PIOA_CARSAL_GRAPH Mgr,
    _In_  GUID              NodeId,
    _Out_ PIOA_NODE_INFO    Out
    )
/*++
Routine Description:
    进程节点信息查询 (对齐 SS PrGetNodeInfo)。

Arguments:
    Mgr    — 因果图实例。
    NodeId — 进程节点 GUID。
    Out    — 输出节点信息。

Return Value:
    STATUS_SUCCESS / STATUS_NOT_FOUND / STATUS_INVALID_PARAMETER。
--*/
{
    PIOA_CARSAL_GRAPH_NODE node;

    if (!Mgr || !Out) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Out, sizeof(*Out));

    EnterCriticalSection(&Mgr->Lock);
    node = IoaCarsalGraphLookupNode(Mgr, NodeId);
    if (!node) {
        LeaveCriticalSection(&Mgr->Lock);
        return STATUS_NOT_FOUND;
    }

    Out->NodeId = NodeId;
    Out->OutDegree = node->OutDegree;
    Out->InDegree = node->InDegree;
    Out->RelationshipCount = node->OutDegree + node->InDegree;

    if (node->ProcessNode) {
        Out->OutPairCount = (ULONG)node->ProcessNode->OutPairCount;
        Out->InPairCount = (ULONG)node->ProcessNode->InPairCount;
        Out->IsOrphan = (node->ProcessNode->Parent == NULL &&
                         !node->ProcessNode->IsSystemProcess);
        Out->TreeDepth = node->ProcessNode->TreeDepth;
    }

    LeaveCriticalSection(&Mgr->Lock);
    return STATUS_SUCCESS;
}

NTSTATUS
IoaGqGetRelationships(
    _In_  PIOA_CARSAL_GRAPH Mgr,
    _In_  GUID              NodeId,
    _In_  IOA_GRAPH_EDGE_TYPE EdgeFilter,   /* DefEdge_Unknown=不过滤 */
    _Out_writes_to_(MaxCount, *Count) PIOA_RELATIONSHIP_INFO Out,
    _In_  ULONG             MaxCount,
    _Out_ ULONG*            Count
    )
/*++
Routine Description:
    进程关系列表查询 (对齐 SS PrGetRelationships)。
    返回该节点全部出边 + 入边 (可过滤边类型), 拷贝语义。

Arguments:
    Mgr        — 因果图实例。
    NodeId     — 进程节点 GUID。
    EdgeFilter — 边类型过滤 (DefEdge_Unknown=不过滤)。
    Out        — 输出关系数组。
    MaxCount   — 输出数组容量。
    Count      — 实际写入数。

Return Value:
    STATUS_SUCCESS / STATUS_NOT_FOUND / STATUS_INVALID_PARAMETER。
--*/
{
    PIOA_CARSAL_GRAPH_NODE node;
    PLIST_ENTRY entry;
    ULONG count = 0;

    if (!Mgr || !Out || !Count || MaxCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    *Count = 0;

    EnterCriticalSection(&Mgr->Lock);
    node = IoaCarsalGraphLookupNode(Mgr, NodeId);
    if (!node) {
        LeaveCriticalSection(&Mgr->Lock);
        return STATUS_NOT_FOUND;
    }

    /* 出边 */
    for (entry = node->OutEdgesHead.Flink;
         entry != &node->OutEdgesHead && count < MaxCount;
         entry = entry->Flink) {
        PIOA_GRAPH_EDGE edge =
            CONTAINING_RECORD(entry, IOA_GRAPH_EDGE, SrcOutLink);
        if (EdgeFilter != DefEdge_Unknown && edge->Type != EdgeFilter) {
            continue;
        }
        Out[count].Type = edge->Type;
        Out[count].SourceNodeId = edge->SourceNodeId;
        Out[count].TargetNodeId = edge->TargetNodeId;
        Out[count].Timestamp = edge->LastSeen;
        Out[count].Score = edge->Weight;
        count++;
    }

    /* 入边 */
    for (entry = node->InEdgesHead.Flink;
         entry != &node->InEdgesHead && count < MaxCount;
         entry = entry->Flink) {
        PIOA_GRAPH_EDGE edge =
            CONTAINING_RECORD(entry, IOA_GRAPH_EDGE, TgtInLink);
        if (EdgeFilter != DefEdge_Unknown && edge->Type != EdgeFilter) {
            continue;
        }
        Out[count].Type = edge->Type;
        Out[count].SourceNodeId = edge->SourceNodeId;
        Out[count].TargetNodeId = edge->TargetNodeId;
        Out[count].Timestamp = edge->LastSeen;
        Out[count].Score = edge->Weight;
        count++;
    }

    LeaveCriticalSection(&Mgr->Lock);
    *Count = count;
    return STATUS_SUCCESS;
}

NTSTATUS
IoaGqGetProcessChildren(
    _In_  PIOA_CARSAL_GRAPH Mgr,
    _In_  GUID              NodeId,
    _Out_writes_to_(MaxCount, *Count) GUID* Children,
    _In_  ULONG             MaxCount,
    _Out_ ULONG*            Count
    )
/*++
Routine Description:
    进程子节点查询 (对齐 SS PrGetChildren)。
    通过谱系节点 ChildrenHead 遍历直接子进程。

Arguments:
    Mgr      — 因果图实例。
    NodeId   — 父进程节点 GUID。
    Children — 输出子节点 GUID 数组。
    MaxCount — 输出数组容量。
    Count    — 实际写入数。

Return Value:
    STATUS_SUCCESS / STATUS_NOT_FOUND / STATUS_INVALID_PARAMETER。
--*/
{
    PIOA_CARSAL_GRAPH_NODE node;
    PLIST_ENTRY entry;
    ULONG count = 0;

    if (!Mgr || !Children || !Count || MaxCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    *Count = 0;

    EnterCriticalSection(&Mgr->Lock);
    node = IoaCarsalGraphpLookupUnlocked(Mgr, NodeId);
    if (!node || !node->ProcessNode) {
        LeaveCriticalSection(&Mgr->Lock);
        return STATUS_NOT_FOUND;
    }

    /* 链头锁原则 (2026-08-25): ChildrenHead 归谱系节点 GenealogyLock
     * 管辖 — 跨域遍历改为锁外持 GenealogyLock 共享完成。先在图锁内
     * 取 ProcessNode 指针快照, 放图锁后再进谱系锁 (两锁不嵌套)。 */
    {
        PWKD_PROCESS processNode = node->ProcessNode;
        LeaveCriticalSection(&Mgr->Lock);

        AcquireSRWLockShared(&processNode->GenealogyLock);
        for (entry = processNode->ChildrenHead.Flink;
             entry != &processNode->ChildrenHead && count < MaxCount;
             entry = entry->Flink) {
            PWKD_PROCESS child =
                CONTAINING_RECORD(entry, WKD_PROCESS, ChildrenLink);
            Children[count++] = child->NodeId;
        }
        ReleaseSRWLockShared(&processNode->GenealogyLock);
    }

    *Count = count;
    return STATUS_SUCCESS;
}

NTSTATUS
IoaGqGetStatistics(
    _In_  PIOA_CARSAL_GRAPH Mgr,
    _Out_ PIOA_GRAPH_STATS_INFO Out
    )
/*++
Routine Description:
    因果图统计查询 (对齐 SS PrGetStatistics)。

Arguments:
    Mgr — 因果图实例。
    Out — 输出统计。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER。
--*/
{
    if (!Mgr || !Out) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Out, sizeof(*Out));

    EnterCriticalSection(&Mgr->Lock);
    Out->NodeCount = Mgr->NodeCount;
    Out->EdgeCount = Mgr->EdgeCount;
    Out->TotalNodesCreated = Mgr->TotalNodesCreated;
    Out->TotalEdgesCreated = Mgr->TotalEdgesCreated;
    Out->TotalEdgesCompacted = Mgr->TotalEdgesCompacted;
    Out->StartTime.QuadPart = 0;   /* 图无显式 StartTime, 置 0 */
    LeaveCriticalSection(&Mgr->Lock);

    return STATUS_SUCCESS;
}

/**************************************************/
/*         P3: LookupEdgeByEventId                  */
/**************************************************/

PIOA_GRAPH_EDGE
IoaCarsalGraphLookupEdgeByEventId(
    _In_ PIOA_CARSAL_GRAPH   Mgr,
    _In_ GUID                 EventId
    )
{
    PLIST_ENTRY entry;

    if (!Mgr || DefIsNullNodeId(EventId)) return NULL;

    EnterCriticalSection(&Mgr->Lock);

    /* 线性扫描全局边链表 */
    entry = Mgr->EdgeGlobalList.Flink;
    while (entry != &Mgr->EdgeGlobalList) {
        PIOA_GRAPH_EDGE edge = CONTAINING_RECORD(entry, IOA_GRAPH_EDGE, GlobalLink);

        for (ULONG i = 0; i < edge->EventIdCount && i < DEF_EDGE_MAX_EVENT_IDS; i++) {
            if (DefGuidEqual(&edge->EventIds[i], &EventId)) {
                LeaveCriticalSection(&Mgr->Lock);
                return edge;
            }
        }

        entry = entry->Flink;
    }

    LeaveCriticalSection(&Mgr->Lock);
    return NULL;
}
