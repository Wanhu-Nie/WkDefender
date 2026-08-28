/**************************************************/
/*  WkDefender IOA — 全局边聚合表实现                */
/*  Key: <SrcNodeId, TgtNodeId, EdgeType>           */
/*                                                  */
/*  重构: 具体边链表替代 RecentEdgeIds 环形缓冲        */
/*  FSM 多路归并从 EdgesHead 消费具体边       */
/**************************************************/

#include "IoaEdgeAggregate.h"
#include "../Notification/EventTypes.h"
#include "IoaProcessPair.h"     /* PAE_PROCESS_PAIR (CleanupExpired 双向摘链) */
#include <string.h>

/**************************************************/
/*               内部辅助: 哈希函数                 */
/**************************************************/

static
ULONG
EdgeAggHash(
    _In_ GUID                SrcNodeId,
    _In_ GUID                TgtNodeId,
    _In_ IOA_GRAPH_EDGE_TYPE EdgeType
    )
{
    ULONG hash = 5381;
    UCHAR* p;
    ULONG i;

    p = (UCHAR*)&SrcNodeId;
    for (i = 0; i < sizeof(GUID); i++) {
        hash = ((hash << 5) + hash) ^ p[i];
    }
    p = (UCHAR*)&TgtNodeId;
    for (i = 0; i < sizeof(GUID); i++) {
        hash = ((hash << 5) + hash) ^ p[i];
    }
    {
        UCHAR* et = (UCHAR*)&EdgeType;
        for (i = 0; i < sizeof(IOA_GRAPH_EDGE_TYPE); i++) {
            hash = ((hash << 5) + hash) ^ et[i];
        }
    }
    return hash % EDGE_AGGREGATE_HASH_BUCKETS;
}

/**************************************************/
/*               内部辅助: 窗口重算                 */
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
        return Entry->ActiveCount;
    }

    windowEndMs = Entry->WindowStart.QuadPart / 10000 + Entry->TimeWindowMs;
    if (Now.QuadPart / 10000 > windowEndMs) {
        Entry->ActiveCount = 0;
        Entry->WindowStart = Now;
    }

    return Entry->ActiveCount;
}

/**************************************************/
/*                   公开 API                       */
/**************************************************/

NTSTATUS
EdgeAggTable_Initialize(
    PIOA_AGGREGATE_EDGE_TABLE* Out
    )
{
    PIOA_AGGREGATE_EDGE_TABLE table;
    ULONG i;

    table = UtHeapAlloc(sizeof(IOA_AGGREGATE_EDGE_TABLE));
    if (!table) return STATUS_NO_MEMORY;

    for (i = 0; i < EDGE_AGGREGATE_HASH_BUCKETS; i++) {
        InitializeListHead(&table->HashBuckets[i]);
    }

    InitializeCriticalSection(&table->Lock);
    table->Initialized = TRUE;

    printf("[EdgeAggTable] Initialized: %u hash buckets\n",
           EDGE_AGGREGATE_HASH_BUCKETS);

    *Out = table;
    return STATUS_SUCCESS;
}

VOID
EdgeAggTable_Cleanup(
    PIOA_AGGREGATE_EDGE_TABLE Table
    )
{
    ULONG b;
    LONG totalFreed = 0;

    if (!Table || !Table->Initialized) return;

    EnterCriticalSection(&Table->Lock);

    for (b = 0; b < EDGE_AGGREGATE_HASH_BUCKETS; b++) {
        while (!IsListEmpty(&Table->HashBuckets[b])) {
            PLIST_ENTRY entry = RemoveHeadList(&Table->HashBuckets[b]);
            PIOA_AGGREGATE_EDGE ea = CONTAINING_RECORD(entry,
                IOA_AGGREGATE_EDGE, HashLink);

            /* 获取 ea 的写锁后释放具体边链表 */
            AcquireSRWLockExclusive(&ea->EdgeLock);

            while (!IsListEmpty(&ea->EdgesHead)) {
                PLIST_ENTRY ce = RemoveHeadList(&ea->EdgesHead);
                UtHeapFree(CONTAINING_RECORD(ce, IOA_CONCRETE_EDGE, Link));
            }

            ReleaseSRWLockExclusive(&ea->EdgeLock);
            UtHeapFree(ea);
            totalFreed++;
        }
    }

    Table->Initialized = FALSE;
    LeaveCriticalSection(&Table->Lock);
    DeleteCriticalSection(&Table->Lock);

    printf("[EdgeAggTable] Cleanup: %ld entries freed\n", totalFreed);
    UtHeapFree(Table);
}

/* 内部无锁查找: 仅供已持 Table->Lock 的路径 (GetOrCreate 的
 * double-check) 复用; 外部一律走 IoaLookupAggregateEdge 持锁版本。 */
static
PIOA_AGGREGATE_EDGE
EdgeAggpLookupUnlocked(
    _In_ PIOA_AGGREGATE_EDGE_TABLE Table,
    _In_ GUID                      SrcNodeId,
    _In_ GUID                      TgtNodeId,
    _In_ IOA_GRAPH_EDGE_TYPE       EdgeType
    )
{
    ULONG bucket;
    PLIST_ENTRY head, entry;

    bucket = EdgeAggHash(SrcNodeId, TgtNodeId, EdgeType);
    head = &Table->HashBuckets[bucket];

    for (entry = head->Flink; entry != head; entry = entry->Flink) {
        PIOA_AGGREGATE_EDGE ea = CONTAINING_RECORD(entry,
            IOA_AGGREGATE_EDGE, HashLink);
        if (DefGuidEqual(&ea->SrcNodeId, &SrcNodeId) &&
            DefGuidEqual(&ea->TgtNodeId, &TgtNodeId) &&
            ea->EdgeType == EdgeType) {
            return ea;
        }
    }
    return NULL;
}

PIOA_AGGREGATE_EDGE
IoaLookupAggregateEdge(
    _In_ PIOA_AGGREGATE_EDGE_TABLE Table,
    _In_ GUID                      SrcNodeId,
    _In_ GUID                      TgtNodeId,
    _In_ IOA_GRAPH_EDGE_TYPE       EdgeType
    )
{
    ULONG bucket;
    PLIST_ENTRY head, entry;
    PIOA_AGGREGATE_EDGE found = NULL;

    if (!Table || !Table->Initialized) return NULL;

    bucket = EdgeAggHash(SrcNodeId, TgtNodeId, EdgeType);
    head = &Table->HashBuckets[bucket];

    /* 链头锁原则 (2026-08-25): 哈希桶链读须持表锁 */
    EnterCriticalSection(&Table->Lock);

    for (entry = head->Flink; entry != head; entry = entry->Flink) {
        PIOA_AGGREGATE_EDGE ea = CONTAINING_RECORD(entry,
            IOA_AGGREGATE_EDGE, HashLink);
        if (DefGuidEqual(&ea->SrcNodeId, &SrcNodeId) &&
            DefGuidEqual(&ea->TgtNodeId, &TgtNodeId) &&
            ea->EdgeType == EdgeType) {
            found = ea;
            break;
        }
    }

    LeaveCriticalSection(&Table->Lock);
    return found;
}

PIOA_AGGREGATE_EDGE
IoaGetOrCreateAggregateEdge(
    _In_ PIOA_AGGREGATE_EDGE_TABLE Table,
    _In_ GUID                      SrcNodeId,
    _In_ GUID                      TgtNodeId,
    _In_ IOA_GRAPH_EDGE_TYPE       EdgeType,
    _In_ LARGE_INTEGER             Timestamp
    )
{
    PIOA_AGGREGATE_EDGE aggEdge;
    ULONG bucket;

    aggEdge = IoaLookupAggregateEdge(Table, SrcNodeId, TgtNodeId, EdgeType);
    if (aggEdge) return aggEdge;

    EnterCriticalSection(&Table->Lock);

    aggEdge = EdgeAggpLookupUnlocked(Table, SrcNodeId, TgtNodeId, EdgeType);
    if (aggEdge) {
        LeaveCriticalSection(&Table->Lock);
        return aggEdge;
    }

    aggEdge = UtHeapAlloc(sizeof(IOA_AGGREGATE_EDGE));
    if (!aggEdge) {
        LeaveCriticalSection(&Table->Lock);
        return NULL;
    }

    WkdCopyGuid(&aggEdge->SrcNodeId, &SrcNodeId);
    WkdCopyGuid(&aggEdge->TgtNodeId, &TgtNodeId);
    aggEdge->EdgeType        = EdgeType;
    aggEdge->TimeWindowMs    = 5000;
    aggEdge->RefCount        = 1;
    
    aggEdge->FirstSeen       = Timestamp;
    aggEdge->LastSeen        = Timestamp;
    {
        LARGE_INTEGER now;
        GetSystemTimeAsFileTime((LPFILETIME)&now);
        aggEdge->WindowStart = now;
    }

    /* 初始化具体边链表 + 锁 */
    InitializeListHead(&aggEdge->EdgesHead);
    InitializeSRWLock(&aggEdge->EdgeLock);
    aggEdge->TotalEdgeCount       = 0;
    aggEdge->ActiveEdgeCount = 0;
    aggEdge->OwnerPair = NULL;

    bucket = EdgeAggHash(SrcNodeId, TgtNodeId, EdgeType);
    InsertTailList(&Table->HashBuckets[bucket], &aggEdge->HashLink);
    InterlockedIncrement(&Table->EntryCount);

    LeaveCriticalSection(&Table->Lock);
    return aggEdge;
}

/**************************************************/
/*           具体边链表操作                          */
/**************************************************/

VOID
EdgeAgg_InsertConcrete(
    _Inout_ PIOA_AGGREGATE_EDGE AggEdge,
    _In_    GUID                EdgeId,
    _In_    GUID                EventId,
    _In_    LARGE_INTEGER       Timestamp
    )
/*++
Routine Description:
    尾插具体边记录到聚合边的 EdgesHead。

    O(1) 快速路径: Timestamp >= 尾节点 → 直接追加。
    慢速路径: 从尾部 Blink 向前遍历找到插入点 (罕见，线程池乱序写入)。

    持有 EdgeLock 写锁保护链表操作。
    若链表长度超过 CONCRETE_EDGE_MAX_NODES，淘汰最旧节点。
--*/
{
    PIOA_CONCRETE_EDGE entry;
    PLIST_ENTRY tail;
    PLIST_ENTRY pos;

    if (!AggEdge) return;

    /* 分配新节点 (锁外分配，减少锁持有时间) */
    entry = UtHeapAlloc(sizeof(IOA_CONCRETE_EDGE));
    if (!entry) return;

    WkdCopyGuid(&entry->EdgeId, &EdgeId);
    entry->EdgeType = AggEdge->EdgeType;
    entry->Timestamp = Timestamp;
    entry->Active    = TRUE;

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

    AggEdge->TotalEdgeCount++;
    AggEdge->ActiveEdgeCount++;

    /* 超过上限 → 淘汰最旧节点 (链表头部) */
    if (AggEdge->TotalEdgeCount > CONCRETE_EDGE_MAX_NODES) {
        //PLIST_ENTRY oldEntry = RemoveHeadList(&AggEdge->EdgesHead);
        //PIOA_CONCRETE_EDGE oldNode = CONTAINING_RECORD(oldEntry, IOA_CONCRETE_EDGE, Link);
        //AggEdge->TotalEdgeCount--;

        ReleaseSRWLockExclusive(&AggEdge->EdgeLock);
        // UtHeapFree(oldNode);
    } else {
        ReleaseSRWLockExclusive(&AggEdge->EdgeLock);
    }
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
        AggEdge->ActiveEdgeCount -= deactivated;
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
            AggEdge->TotalEdgeCount--;
            if (node->Active) {
                AggEdge->ActiveEdgeCount--;
            }
            UtHeapFree(node);
            /* 不 break — 同一 EdgeId 理论只有一条, 但安全遍历到底 */
        }
        entry = next;
    }

    ReleaseSRWLockExclusive(&AggEdge->EdgeLock);
}

VOID
IoaUpdateProcessPairEdgeAggregate(
    _Inout_ PIOA_AGGREGATE_EDGE Edge,
    _In_    PWKD_EVENT_HEADER   Event,
    _In_    GUID                EdgeId
    )
/*++
Routine Description:
    更新边聚合条目。
    由 IoaObserve 阶段2 调用。
--*/
{
    LARGE_INTEGER now;

    if (!Edge || !Event) return;

    GetSystemTimeAsFileTime((LPFILETIME)&now);

    Edge->OccurrenceCount++;

    if (Edge->OccurrenceCount == 1) {
        Edge->Confidence = Event->Confidence;
    } else {
        Edge->Confidence = (Edge->Confidence * 7 + Event->Confidence * 3) / 10;
    }

    EdgeAggRecalcWindow(Edge, now);
    Edge->ActiveCount++;
    Edge->LastSeen = now;

    /* 尾插具体边记录 (传递原始事件GUID供Tier3反查) */
    EdgeAgg_InsertConcrete(Edge, EdgeId, Event->EventId, Event->Timestamp);

    InterlockedIncrement64(&Edge->SequenceNumber);

    if (Edge->FirstSeen.QuadPart == 0) {
        Edge->FirstSeen = now;
    }
}

VOID
EdgeAggTable_CleanupExpired(
    _In_ PIOA_AGGREGATE_EDGE_TABLE Table
    )
{
    LARGE_INTEGER now;
    LONGLONG nowMs;
    ULONG b;
    LONG cleaned = 0;

    if (!Table || !Table->Initialized) return;

    GetSystemTimeAsFileTime((LPFILETIME)&now);
    nowMs = now.QuadPart / 10000;

    EnterCriticalSection(&Table->Lock);

    for (b = 0; b < EDGE_AGGREGATE_HASH_BUCKETS; b++) {
        PLIST_ENTRY head = &Table->HashBuckets[b];
        PLIST_ENTRY entry = head->Flink;

        while (entry != head) {
            PIOA_AGGREGATE_EDGE ea = CONTAINING_RECORD(entry,
                IOA_AGGREGATE_EDGE, HashLink);
            PLIST_ENTRY next = entry->Flink;

            LONGLONG age = nowMs - (ea->LastSeen.QuadPart / 10000);
            if (age > EDGE_AGGREGATE_TTL_MS && ea->RefCount <= 1) {
                /* 双向摘链闭环 (2026-08-25): 先从挂靠 pair 的 EdgeListHead
                 * 摘除 PairLink — 持该 pair 的 EdgeListLock 独占, 与
                 * PairContext_AttachEdge/RefreshScore 同锁域, 防 FSM/T1
                 * 遍历踩已释放内存。锁序: Table->Lock(外) →
                 * EdgeListLock(内), 与 AttachEdge 路径单向一致。 */
                PAE_PROCESS_PAIR owner = (PAE_PROCESS_PAIR)ea->OwnerPair;
                if (owner && !IsListEmpty(&ea->PairLink)) {
                    AcquireSRWLockExclusive(&owner->EdgeListLock);
                    if (!IsListEmpty(&ea->PairLink)) {
                        RemoveEntryList(&ea->PairLink);
                    }
                    ReleaseSRWLockExclusive(&owner->EdgeListLock);
                }

                /* 获取 ea 的写锁后释放具体边链表 */
                AcquireSRWLockExclusive(&ea->EdgeLock);

                while (!IsListEmpty(&ea->EdgesHead)) {
                    PLIST_ENTRY ce = RemoveHeadList(&ea->EdgesHead);
                    UtHeapFree(CONTAINING_RECORD(ce, IOA_CONCRETE_EDGE, Link));
                }

                ReleaseSRWLockExclusive(&ea->EdgeLock);
                RemoveEntryList(entry);
                UtHeapFree(ea);
                InterlockedDecrement(&Table->EntryCount);
                cleaned++;
            }
            entry = next;
        }
    }

    LeaveCriticalSection(&Table->Lock);

    if (cleaned > 0) {
        printf("[EdgeAggTable] Cleanup: %ld expired entries removed\n", cleaned);
    }
}

ULONG
EdgeAggTable_GetCount(
    _In_ PIOA_AGGREGATE_EDGE_TABLE Table
    )
{
    if (!Table) return 0;
    return (ULONG)Table->EntryCount;
}

NTSTATUS
T3GetAggregateEdgeTimeWindow(
    _In_        GUID                SrcNodeId,
    _In_        GUID                TgtNodeId,
    _In_        IOA_GRAPH_EDGE_TYPE EdgeType,
    _Out_opt_   PLARGE_INTEGER      Start,
    _Out_opt_   PLARGE_INTEGER      End
    )
/*
 * 获取指定三元组聚合边的 FirstSeen 时间戳。
 * 若聚合边不存在, 返回 {0}。
 */
{
    if (DefIsNullNodeId(SrcNodeId) || DefIsNullNodeId(TgtNodeId) || !EdgeType)
        return STATUS_INVALID_PARAMETER;

    if (Start)  Start->QuadPart = 0;
    if (End)    End->QuadPart   = 0;

    PIOA_AGGREGATE_EDGE agg = 
        IoaLookupAggregateEdge(WkdIoaEngine.EdgeAggTable, SrcNodeId, TgtNodeId, EdgeType);
    if (!agg) return STATUS_UNSUCCESSFUL;

    if (Start)
        *Start = agg->FirstSeen;

    if (End)
        *End = agg->LastSeen;

    return STATUS_SUCCESS;
}