/**************************************************/
/*  WkDefender IOA — 全局边聚合表实现                */
/*  Key: <SourceNodeId, TargetNodeId, EdgeType>           */
/*                                                  */
/*  重构: 具体边链表替代 RecentEdgeIds 环形缓冲        */
/*  FSM 多路归并从 EdgesHead 消费具体边       */
/**************************************************/

#include "IoaEdgeAggregate.h"
#include "../Common/HashMap.h"  /* 复用通用哈希表 (WKD_HASH_MAP) */
#include "../Notification/EventTypes.h"
#include "IoaProcessPair.h"     /* PAE_PROCESS_PAIR (CleanupExpired 双向摘链) */
#include <string.h>


/**************************************************/
/*  哈希已迁移至 WKD_HASH_MAP                        */
/*  (IOA_AGGREGATE_EDGE_KEY 定长二进制 key,           */
/*   见 IoaEdgeAggregate.h), 无需自制哈希函数。       */
/**************************************************/

static
ULONG
EdgeAggRecalcWindow(
    _Inout_ PIOA_AGGREGATE_EDGE Entry,
    _In_    LARGE_INTEGER       Now
    )
{
    LONGLONG windowEndMs;

    if (Entry->WindowStart.QuadPart == 0) {
        Entry->WindowStart = Now;
        return Entry->ActiveEdges;
    }

    windowEndMs = Entry->WindowStart.QuadPart / 10000 + Entry->TimeWindowMs;
    if (Now.QuadPart / 10000 > windowEndMs) {
        Entry->ActiveEdges = 0;
        Entry->WindowStart = Now;
    }

    return Entry->ActiveEdges;
}

/**************************************************/
/*                   公开 API                       */
/**************************************************/

/**************************************************/
/*          HashMap ref/deref/shouldremove 回调       */
/*  对齐 driver 侧 (PairManager) 引用契约:             */
/*   - Insert/Lookup 命中 → Reference (RefCount+1, 表引用/外部 pin) */
/*   - Remove → ShouldRemove(RefCount<=1) 裁决 → Dereference(-1); */
/*     归零即释放本体 (free-on-zero)。                 */
/*  边本体与具体边均走 malloc, 释放统一 free 配对。       */
/**************************************************/

_Use_decl_annotations_
LONG
IoaReferenceAggregateEdge(
    _In_ PIOA_AGGREGATE_EDGE AggEdge
    )
{
    if (!AggEdge) return MAXLONG;
    else return InterlockedIncrement(&AggEdge->RefCount);
}

static
BOOLEAN
IoapShouldRemoveAggregateEdge(
    _In_ const PIOA_AGGREGATE_EDGE AggEdge,
    _In_ BOOLEAN HoldLock
    )
{
    /* 仅当无外部 pin (RefCount<=1, 仅剩表引用) 方可摘除,
     * 闭合"枚举→复查→Remove 窗口内并发 pin"的 UAF。 */
    return (AggEdge->RefCount == (HoldLock ? 2 : 1));
}

/*
 * 摘除回调 (HashMap 桶独占锁内调用): RefCount -1; 归零即无并发可达者,
 * 释放具体边链表 + Edge 本体。锁序: 桶锁(外) → EdgeLock(内), 与读写路径
 * 单向一致。释放统一用 free (malloc 配对)。
 */
VOID
IoaDereferenceAggregateEdge(
    _In_ PIOA_AGGREGATE_EDGE AggEdge
    )
{
    LONG ref;

    if (!AggEdge) return MAXLONG;

    ref = InterlockedDecrement(&AggEdge->RefCount);
    if (ref == 0) {
        /* 无任何持有者，可安全无锁访问 */
        IoapDestroyAggregateEdge(AggEdge);
    }

    return ref;
}

_Use_decl_annotations_
NTSTATUS
IoaInitializeAggregateEdgeTable(
    _Out_ PIOA_AGGREGATE_EDGE_TABLE* Table
    )
{
    PIOA_AGGREGATE_EDGE_TABLE table;
    NTSTATUS status;

    if (!Table) return STATUS_INVALID_PARAMETER;

    table = malloc(sizeof(IOA_AGGREGATE_EDGE_TABLE));
    if (!table) return STATUS_NO_MEMORY;
    RtlZeroMemory(table, sizeof(IOA_AGGREGATE_EDGE_TABLE));

    /* 复用通用哈希表: 定长二进制 key (IOA_AGGREGATE_EDGE_KEY),
     * value = PIOA_AGGREGATE_EDGE 指针。
     * PerBucketLock=TRUE: 桶级 SRWLOCK, 细粒度并发 (替换原全局锁)。
     * UseRefCallbacks=TRUE: 启用 ref/deref/shouldremove 强制对称契约 —
     *   Insert/Lookup 命中 Reference(+1), Remove 经 ShouldRemove 裁决后
     *   Dereference(-1), 归零释放本体。HashMap 仅管索引与回调, 不触碰 Edge
     *   生命周期细节。 */
    status = CoInitializeHashMap(
        &table->HashMap,
        EDGE_AGGREGATE_HASH_BUCKETS,
        EDGE_AGGREGATE_MAX_ENTRIES,
        TRUE,
        TRUE,
        IoaReferenceAggregateEdge, IoapShouldRemoveAggregateEdge,
        (PFN_HASH_MAP_DEREFERENCE)IoaDereferenceAggregateEdge);
    if (!NT_SUCCESS(status)) { free(table); return status; }

    table->Initialized = TRUE;
    printf("[EdgeAggTable] Initialized: %u hash buckets (WKD_HASH_MAP, PerBucketLock+RefCallbacks)\n",
           EDGE_AGGREGATE_HASH_BUCKETS);

    *Table = table;
    return STATUS_SUCCESS;
}

/*
 * 整体清理 (进程退出/卸载路径)。
 *   CoHashMapClear 依 HashMap 语义不调用 Dereference (不清引用, 对齐驱动
 *   teardown 语义) —— 故须先枚举收集所有 Edge 指针, 再 CoHashMapClear 释放
 *   索引桶数组, 最后逐条 IoaDereferenceAggregateEdge 扣表引用 → 归零由回调释放
 *   具体边链表 + Edge 本体 (free-on-zero)。
 *   表本体由 malloc 分配, 此处以 free 配对释放。
 */
typedef struct _EDGE_FREE_NODE {
    struct _EDGE_FREE_NODE* Next;
    PIOA_AGGREGATE_EDGE     Edge;
} EDGE_FREE_NODE, *PEDGE_FREE_NODE;

static
BOOLEAN
EdgeAggpCleanupCollect(
    _In_ PVOID  Key,
    _In_ SIZE_T KeySize,
    _In_ PVOID  Value,
    _In_ PVOID  Context
    )
{
    PEDGE_FREE_NODE* head = (PEDGE_FREE_NODE*)Context;
    PEDGE_FREE_NODE node = (PEDGE_FREE_NODE)UtHeapAlloc(sizeof(EDGE_FREE_NODE));
    if (!node) return TRUE; /* teardown 路径, 极少数分配失败忽略 */
    node->Edge = (PIOA_AGGREGATE_EDGE)Value;
    node->Next = *head;
    *head = node;
    return TRUE;
}

_Use_decl_annotations_
VOID
IoaCleanupAggregateEdgeTable(
    _Inout_ PIOA_AGGREGATE_EDGE_TABLE Table
    )
{
    PEDGE_FREE_NODE collected = NULL;
    PEDGE_FREE_NODE node;

    if (!Table || !Table->Initialized) return;

    /* 清理线程不会并发竞争, 无需 cas */
    InterlockedExchange8(&Table->Initialized, FALSE);

    /* 阶段1: 枚举收集所有 Edge 指针 (teardown 单线程, 不 pin), 再清空索引桶数组 */
    CoEnumerateHashMap(&Table->HashMap, (PFN_HASH_MAP_ENUM)EdgeAggpCleanupCollect, &collected);
    CoHashMapClear(&Table->HashMap);

    /* 阶段2: 逐条 IoaDereferenceAggregateEdge 扣表引用 → 归零释放具体边链表 + Edge 本体 */
    node = collected;
    while (node) {
        PEDGE_FREE_NODE next = node->Next;
        IoaDereferenceAggregateEdge(node->Edge);
        UtHeapFree(node);
        node = next;
    }

    printf("[EdgeAggTable] Cleanup: aggregate edge table destroyed\n");
    free(Table);
}

_Use_decl_annotations_
PIOA_AGGREGATE_EDGE
IoaLookupAggregateEdge(
    _In_ PIOA_AGGREGATE_EDGE_TABLE Table,
    _In_ GUID SourceNodeId,
    _In_ GUID TargetNodeId,
    _In_ IOA_GRAPH_EDGE_TYPE EdgeType
    )
/*++
 * 按 (源/目标/类型) 精确查找聚合边。UseRefCallbacks=TRUE 下命中即 pin
 * (RefCount+1), 返回的边已被 pin, 调用方用毕须调 IoaDereferenceAggregateEdge。
 * 对应 driver 侧 PairManager_FindProcessPair 的取值语义: 返回的边在表引用
 * 存续期间受引用计数保护, 不会凭空释放。
 * --*/
{
    IOA_AGGREGATE_EDGE_KEY key = { 0 };

    if (!Table || !Table->Initialized) return NULL;
    if (DefIsNullNodeId(SourceNodeId) || DefIsNullNodeId(TargetNodeId)) return NULL;
    if (EdgeType == DefEdge_Unknown) return NULL;

    WkdCopyGuid(&key.SourceNodeId, &SourceNodeId);
    WkdCopyGuid(&key.TargetNodeId, &TargetNodeId);
    key.EdgeType = EdgeType;

    return (PIOA_AGGREGATE_EDGE)CoLookupHashMapEntry(&Table->HashMap, &key, sizeof(key));
}

_Use_decl_annotations_
PIOA_AGGREGATE_EDGE
IoaFindOrCreateAggregateEdge(
    _Inout_opt_ PIOA_AGGREGATE_EDGE_TABLE Table,
    _In_ GUID SourceNodeId,
    _In_ GUID TargetNodeId,
    _In_ IOA_GRAPH_EDGE_TYPE EdgeType,
    _In_opt_ LARGE_INTEGER Timestamp
    )
{
    NTSTATUS status;
    PIOA_AGGREGATE_EDGE aggEdge = NULL;

    if (!Table) Table = WkdIoaEngine.EdgeAggTable;
    if (!Table || !Table->Initialized ||
        DefIsNullNodeId(SourceNodeId) ||
        DefIsNullNodeId(TargetNodeId) ||
        EdgeType == DefEdge_Unknown) return NULL;

    /* 阶段1: 查找 (WKD_HASH_MAP 内部桶锁); 命中直接返回 */
    status = IoaLookupAggregateEdgeByNodeId(
        SourceNodeId, TargetNodeId, EdgeType, &aggEdge);
    if (NT_SUCCESS(status)) return aggEdge;
    
    /* 阶段2: 未命中 → 创建新 Edge */
    {
        LARGE_INTEGER now;

        aggEdge = malloc(sizeof(IOA_AGGREGATE_EDGE));
        if (!aggEdge) return NULL;
        RtlZeroMemory(aggEdge, sizeof(IOA_AGGREGATE_EDGE));

        aggEdge->RefCount = 1;
        aggEdge->SourceNodeId = SourceNodeId;
        aggEdge->TargetNodeId = TargetNodeId;
        aggEdge->EdgeType = EdgeType;
        aggEdge->TimeWindowMs = 5000;
        aggEdge->FirstSeen = Timestamp;
        aggEdge->LastSeen = Timestamp;
        GetSystemTimeAsFileTime((LPFILETIME)&now);
        aggEdge->WindowStart = now;
        InitializeListHead(&aggEdge->EdgesHead);
        InitializeSRWLock(&aggEdge->EdgeLock);
    }

        /* 阶段3: 尝试插入索引表。
         * 并发下若另一线程已插入相同 key, CoInsertHashMapEntry 返回
         * STATUS_OBJECT_NAME_COLLISION: double-check 回收已存在 Edge,
         * 释放本线程多余创建的新 Edge (无泄漏/无双插入)。
         * 无表锁: HashMap 桶锁串行同 key 操作; 新边 Insert 即 Reference(+1)
         * 落地表引用; 即便此后 CleanupExpired 立刻枚举到该边, 因 RefCount=1
         * (仅表引用) 会经 ShouldRemove 摘除并释放, 不存在"重插入旧边"的竞态
         * (old 指针已失效, Retry 重新 CoLookupHashMapEntry 取当前存活边),
         * 故不再需要全局表锁来杜绝 double-free。 */
    {   
        ULONG attempts = 3;
        IOA_AGGREGATE_EDGE_KEY key = { SourceNodeId, TargetNodeId, EdgeType };
Retry:
        if (0 == attempts--) { free(aggEdge); return NULL; };
        status = CoInsertHashMapEntry(&Table->HashMap, &key, sizeof(key), aggEdge);
        if (NT_SUCCESS(status)) {
            InterlockedIncrement(&Table->ActiveAggEdges);
            InterlockedIncrement(&Table->TotalAggEdges);
            return aggEdge;
        }
        else if (status == STATUS_OBJECT_NAME_COLLISION) {
            PIOA_AGGREGATE_EDGE existing =
                (PIOA_AGGREGATE_EDGE)CoLookupHashMapEntry(&Table->HashMap, &key, sizeof(key));
            /* 释放多余 Edge (具体边链表为空, 无需额外清理) */
            free(aggEdge);
            return existing;
        } else goto Retry;
    }
}

_Use_decl_annotations_
VOID 
IoapDestroyAggregateEdge(
    _In_  PIOA_AGGREGATE_EDGE AggEdge
    )
{
    if (!AggEdge) return;
    while (!IsListEmpty(&AggEdge->EdgesHead)) {
        PLIST_ENTRY ce = RemoveHeadList(&AggEdge->EdgesHead);
        free(CONTAINING_RECORD(ce, IOA_CONCRETE_EDGE, Link));
    }
    free(AggEdge);
}

/**************************************************/
/*           具体边链表操作                          */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
IoapInsertConcreteEdge(
    _Inout_ PIOA_AGGREGATE_EDGE AggEdge,
    _In_ GUID EventId,
    _In_ LARGE_INTEGER Timestamp,
    _In_ LARGE_INTEGER Now
    )
/*++
Routine Description:
    尾插具体边记录到聚合边的 EdgesHead。

    O(1) 快速路径: Timestamp >= 尾节点 → 直接追加。
    慢速路径: 从尾部 Blink 向前遍历找到插入点 (罕见，线程池乱序写入)。

    持有 EdgeLock 写锁保护链表操作。
    若链表长度超过 MAX_CONCRETES_PER_AGGREGATE_EDGE，淘汰最旧节点。
--*/
{
    PIOA_CONCRETE_EDGE entry;
    PLIST_ENTRY tail;
    PLIST_ENTRY pos;

    if (!AggEdge || DefIsNullNodeId(EventId) ||
        Timestamp.QuadPart == 0 || Now.QuadPart == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 分配新节点 (锁外分配，减少锁持有时间) */
    entry = malloc(sizeof(IOA_CONCRETE_EDGE));
    if (!entry) return;
    RtlZeroMemory(entry, sizeof(entry));

    entry->EdgeId = EventId;
    entry->Timestamp = Timestamp;
    entry->Active = TRUE;

    AcquireSRWLockExclusive(&AggEdge->EdgeLock);

    /* 快速路径: 链表空 或 Timestamp >= 尾节点 → 直接追加到尾部 */
    tail = AggEdge->EdgesHead.Blink;
    if (IsListEmpty(&AggEdge->EdgesHead) ||
        Timestamp.QuadPart >= CONTAINING_RECORD(tail, IOA_CONCRETE_EDGE, Link)->Timestamp.QuadPart) {
        InsertTailList(&AggEdge->EdgesHead, &entry->Link);
    } else {
        /*
         * 慢速路径: 从尾部向前遍历 (Blink 方向)。
         *
         * 进入这里的条件是 Timestamp < tail->Timestamp，
         * 即新节点比尾节点"早"，所以从尾部向前找第一个 <= 新节点的位置，
         * 将新节点插入到该位置之后 (保持升序)。
         */
        pos = tail;
        while (pos != &AggEdge->EdgesHead) {
            PIOA_CONCRETE_EDGE cur = CONTAINING_RECORD(pos, IOA_CONCRETE_EDGE, Link);
            if (Timestamp.QuadPart >= cur->Timestamp.QuadPart) {
                /* 插入到 cur 之后 */
                entry->Link.Flink = cur->Link.Flink;
                entry->Link.Blink = &cur->Link;
                cur->Link.Flink->Blink = &entry->Link;
                cur->Link.Flink = &entry->Link;
                break;
            }
            pos = pos->Blink;
        }
        if (pos == &AggEdge->EdgesHead) {
            /* 新节点比所有节点都早 → 插入到头部 */
            entry->Link.Flink = AggEdge->EdgesHead.Flink;
            entry->Link.Blink = &AggEdge->EdgesHead;
            AggEdge->EdgesHead.Flink->Blink = &entry->Link;
            AggEdge->EdgesHead.Flink = &entry->Link;
        }
    }

    InterlockedIncrement(&AggEdge->ActiveEdges);
    InterlockedIncrement(&AggEdge->TotalEdges);

    /* 维护最早过期时间 (min): 插入即更新; 回收/图淘汰不抬高 (保持下估计, 快速路径安全) */
    {
        LONGLONG newExpiry = Timestamp.QuadPart + (LONGLONG)EDGE_AGGREGATE_TTL_MS * 10000;
        if (AggEdge->EarliestExpireTime.QuadPart == 0 ||
            newExpiry < AggEdge->EarliestExpireTime.QuadPart) {
            AggEdge->EarliestExpireTime.QuadPart = newExpiry;
        }
    }

    /* 超过上限 → 淘汰最旧节点 (链表头部) */
    if (InterlockedCompareExchange(&AggEdge->ActiveEdges, 0, 0) >
        MAX_CONCRETES_PER_AGGREGATE_EDGE) {
        PIOA_CONCRETE_EDGE oldNode;
        
        /* 尝试惰性刷新聚合边以释放空间 */
        IoaRefreshAggregateEdgeLocked(AggEdge, Now);

        /* 聚合边中的活跃项仍超出上限，直接淘汰早期记录并更新最早过期时间 */
        if (InterlockedCompareExchange(&AggEdge->ActiveEdges, 0, 0) >
            MAX_CONCRETES_PER_AGGREGATE_EDGE) {
            oldNode = CONTAINING_RECORD(
                RemoveHeadList(&AggEdge->EdgesHead),
                IOA_CONCRETE_EDGE,
                Link);
            
            InterlockedDecrement(&AggEdge->ActiveEdges);
            free(oldNode);
            AggEdge->EarliestExpireTime.QuadPart =
                CONTAINING_RECORD(&AggEdge->EdgesHead, IOA_CONCRETE_EDGE, Link)->Timestamp.QuadPart;
        }
    }
    ReleaseSRWLockExclusive(&AggEdge->EdgeLock);
    return STATUS_SUCCESS;
}

VOID
EdgeAgg_EvictInactive(
    _Inout_ PIOA_AGGREGATE_EDGE AggEdge,
    _In_    LONGLONG            WindowMs
    )
/*++
Routine Description:
    Tier1 窗口过期清理: 遍历具体边链表，
    将 Timestamp < (Now - WindowMs) 的节点标记为 Active=FALSE。

    持有 EdgeLock 写锁防止与 InsertConcrete 的淘汰逻辑竞争。
    不删除节点 — 因果图淘汰时才删除 — 但 FSM 归并时跳过 Active=FALSE 的节点。
--*/
{
    LARGE_INTEGER now;
    LONGLONG nowMs;
    LONG deactivated = 0;
    PLIST_ENTRY entry;

    if (!AggEdge || WindowMs <= 0) return;

    GetSystemTimeAsFileTime((LPFILETIME)&now);
    nowMs = now.QuadPart / 10000LL;
    if (nowMs < 0) return;

    AcquireSRWLockExclusive(&AggEdge->EdgeLock);

    entry = AggEdge->EdgesHead.Flink;
    while (entry != &AggEdge->EdgesHead) {
        PIOA_CONCRETE_EDGE node = CONTAINING_RECORD(entry, IOA_CONCRETE_EDGE, Link);
        entry = entry->Flink;

        if (node->Active &&
            (nowMs - node->Timestamp.QuadPart / 10000LL) > WindowMs) {
            node->Active = FALSE;
            deactivated++;
        }
    }

    if (deactivated > 0) {
        AggEdge->ActiveEdges -= deactivated;
    }

    ReleaseSRWLockExclusive(&AggEdge->EdgeLock);
}

VOID
EdgeAgg_OnGraphEdgeEvicted(
    _Inout_ PIOA_AGGREGATE_EDGE AggEdge,
    _In_    GUID                EdgeId
    )
/*++
Routine Description:
    因果图边淘汰回调: 按 EdgeId 精确匹配并释放具体边节点。
    持有 EdgeLock 写锁保护链表操作。

    与因果图边生命周期严格同步 — 因果图忘记一条边，聚合边同步删除。
--*/
{
    PLIST_ENTRY entry;

    if (!AggEdge) return;

    AcquireSRWLockExclusive(&AggEdge->EdgeLock);

    entry = AggEdge->EdgesHead.Flink;
    while (entry != &AggEdge->EdgesHead) {
        PIOA_CONCRETE_EDGE node = CONTAINING_RECORD(entry, IOA_CONCRETE_EDGE, Link);
        PLIST_ENTRY next = entry->Flink;

        if (DefGuidEqual(&node->EdgeId, &EdgeId)) {
            RemoveEntryList(entry);
            AggEdge->TotalEdges--;
            InterlockedDecrement(&AggEdge->ActiveEdges);
            if (node->Active) {
                AggEdge->ActiveEdges--;
            }
            UtHeapFree(node);
            /* 不 break — 同一 EdgeId 理论只有一条, 但安全遍历到底 */
        }
        entry = next;
    }

    ReleaseSRWLockExclusive(&AggEdge->EdgeLock);
}

_Use_decl_annotations_
VOID
IoaUpdateAggregateEdge(
    _Inout_ PIOA_AGGREGATE_EDGE AggEdge,
    _In_ const PWKD_EVENT_HEADER Event
    )
/*++
Routine Description:
    更新边聚合条目。
    由 IoaObserve 阶段2 调用。
--*/
{
    LARGE_INTEGER now;

    if (!AggEdge || !Event) return;

    GetSystemTimeAsFileTime((LPFILETIME)&now);

    //if (AggEdge->OccurrenceCount == 1) {
    //    AggEdge->Confidence = Event->Confidence;
    //} else {
    //    AggEdge->Confidence = (AggEdge->Confidence * 7 + Event->Confidence * 3) / 10;
    //}

    // EdgeAggRecalcWindow(AggEdge, now);
    AggEdge->LastSeen = now;

    /* 尾插具体边记录 (传递原始事件GUID供Tier3反查) */
    IoapInsertConcreteEdge(AggEdge, Event->EventId, Event->Timestamp, now);
    if (InterlockedCompareExchangePointer(&AggEdge->OwnerPair, NULL, NULL)) {
        InterlockedIncrement(&AggEdge->OwnerPair->ActiveEdges);
        InterlockedIncrement(&AggEdge->OwnerPair->TotalEdges);
    }

    InterlockedIncrement64(&AggEdge->SequenceNumber);

    if (AggEdge->FirstSeen.QuadPart == 0) {
        AggEdge->FirstSeen = now;
    }
}

/*
 * 刷新聚合边 (对齐 driver 侧 IoaRefreshProcessPair 对行为节点/记录的回收语义):
 *   回收 EdgesHead 中超过 EDGE_AGGREGATE_TTL_MS 的具体边节点 (释放), 返回是否仍含
 *   有效 (未过期) 具体边。聚合边是否存活取决于子对象 (具体边) 是否有效 —— 该判定被
 *   IocCleanupExpiredProcessPair 经 AepRefreshProcessPair 统一回收聚合边时共用,
 *   消除此前"是否含有效聚合边"判定的割裂。
 */
ULONG
IoaRefreshAggregateEdgeLocked(
    _Inout_ PIOA_AGGREGATE_EDGE AggEdge,
    _In_ LARGE_INTEGER Now
    )
{
    PLIST_ENTRY entry;
    LONG reclaimed = 0;
    LONGLONG earliestExpiry = 0;

    if (!AggEdge || Now.QuadPart == 0) return ULONG_MAX;

    /* 快速路径 (对齐 driver IoapReclaimExpiredRecordsLocked):
     *   - 无任何具体边 → 直接判失效;
     *   - 最早过期时间尚未到达 → 全部有效, 直接返回, 跳过整条链表遍历。 */
    
    if (InterlockedCompareExchange(&AggEdge->ActiveEdges, 0, 0) == 0) {
        AggEdge->EarliestExpireTime.QuadPart = 0;
        return ULONG_MAX;            /* 无有效具体边 → 聚合边应释放 */
    }
    if (AggEdge->EarliestExpireTime.QuadPart > Now.QuadPart) {
        return ULONG_MAX;             /* 全部未过期, 无需遍历 */
    }

    /* 慢速路径: 回收过期具体边, 并重算最早过期时间 */
    entry = AggEdge->EdgesHead.Flink;
    while (entry != &AggEdge->EdgesHead) {
        PIOA_CONCRETE_EDGE ce = CONTAINING_RECORD(entry, IOA_CONCRETE_EDGE, Link);
        PLIST_ENTRY next = entry->Flink;
        LONGLONG expiry = ce->Timestamp.QuadPart + (LONGLONG)EDGE_AGGREGATE_TTL_MS * 10000;

        if (expiry < Now.QuadPart) {
            /* 过期具体边 → 摘除并释放 */
            RemoveEntryList(entry);
            reclaimed++;
            free(ce);
        } else {
            /* 未过期 → 参与最早过期时间重算 (保持缓存下估计, 快速路径可靠) */
            expiry = ce->Timestamp.QuadPart + (LONGLONG)EDGE_AGGREGATE_TTL_MS * 10000;
            if (earliestExpiry == 0 || expiry < earliestExpiry) {
                earliestExpiry = expiry;
            }
        }

        entry = next;
    }

    InterlockedAdd(&AggEdge->ActiveEdges, - reclaimed);
    InterlockedAdd(&AggEdge->OwnerPair->ActiveEdges, -reclaimed);
    AggEdge->EarliestExpireTime.QuadPart = earliestExpiry;
    return reclaimed;
}


ULONG
EdgeAggTable_GetCount(
    _In_ PIOA_AGGREGATE_EDGE_TABLE Table
    )
{
    if (!Table) return 0;
    return (ULONG)Table->ActiveAggEdges;
}

NTSTATUS
T3GetAggregateEdgeTimeWindow(
    _In_        GUID                SourceNodeId,
    _In_        GUID                TargetNodeId,
    _In_        IOA_GRAPH_EDGE_TYPE EdgeType,
    _Out_opt_   PLARGE_INTEGER      Start,
    _Out_opt_   PLARGE_INTEGER      End
    )
/*
 * 获取指定三元组聚合边的 FirstSeen 时间戳。
 * 若聚合边不存在, 返回 {0}。
 */
{
    if (DefIsNullNodeId(SourceNodeId) || DefIsNullNodeId(TargetNodeId) || !EdgeType)
        return STATUS_INVALID_PARAMETER;

    if (Start)  Start->QuadPart = 0;
    if (End)    End->QuadPart   = 0;

    PIOA_AGGREGATE_EDGE agg = 
        IoaLookupAggregateEdge(WkdIoaEngine.EdgeAggTable, SourceNodeId, TargetNodeId, EdgeType);
    if (!agg) return STATUS_UNSUCCESSFUL;

    if (Start)
        *Start = agg->FirstSeen;

    if (End)
        *End = agg->LastSeen;

    /* Lookup 返回已 pin 的边, 读取时间戳后归还引用 */
    IoaDereferenceAggregateEdge(agg);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
IoaLookupAggregateEdgeByNodeId(
    _In_ GUID SourceNodeId,
    _In_ GUID TargetNodeId,
    _In_ IOA_GRAPH_EDGE_TYPE EdgeType,
    _Out_ PIOA_AGGREGATE_EDGE* Aggrate
    )
{
    IOA_AGGREGATE_EDGE_KEY key;
    PIOA_AGGREGATE_EDGE aggEdge;
    PIOA_AGGREGATE_EDGE_TABLE Table = WkdIoaEngine.EdgeAggTable;

    if (DefIsNullNodeId(SourceNodeId) ||
        DefIsNullNodeId(TargetNodeId) ||
        EdgeType == DefEdge_Unknown ||
        !Aggrate || !Table) {
        return STATUS_INVALID_PARAMETER;
    }
    *Aggrate = NULL;
    
    key.SourceNodeId = SourceNodeId;
    key.TargetNodeId = TargetNodeId;
    key.EdgeType = EdgeType;

    aggEdge = (PIOA_AGGREGATE_EDGE)CoLookupHashMapEntry(
        &Table->HashMap, &key, sizeof(key));
    if (aggEdge) {
        *Aggrate = aggEdge;
        return STATUS_SUCCESS;
    } else return STATUS_NOT_FOUND;
}