/**************************************************/
/*  WkDefender Agent — 通用哈希表实现               */
/*                                                   */
/*  2026-08-25 重构：对齐驱动 CoHashMap 双模式锁      */
/*  （PerBucketLock）与 ref/deref 强制对称契约。      */
/*  任意 key 抽象：SRWLOCK 桶级锁数组（PerBucket-    */
/*  Lock=TRUE）或单把全局锁（FALSE）；引用回调契约   */
/*  保留。                                           */
/**************************************************/

#include "HashMap.h"
#include "../DefendTypes.h"   /* 用户态 LIST_ENTRY 宏实现 (InitializeListHead/InsertTailList 等) */
#include <string.h>
#include <ntstatus.h>

/**************************************************/
/*          内部：任意 key 处理三件套                */
/*                                                   */
/*  移植自 driver Common/HashMap.c CopHashKey/       */
/*  CopKeyEqual/CopCopyKey（用户态 Heap 版）。        */
/**************************************************/

/* 任意 key 哈希：≤8 字节小端整数 + >8 字节 FNV-1a，
 * 混入长度信息 + fmix64 三段雪崩（分布增强）。 */
static
ULONG64
CopHashKey(
    _In_ const PVOID Key,
    _In_ SIZE_T KeySize
    )
{
    ULONG64 hash = 0;
    const PUCHAR p = (const PUCHAR)Key;

    if (KeySize <= sizeof(ULONG64)) {
        /* 小键：前 KeySize 字节小端序填充为 64 位整数 */
        for (ULONG i = 0; i < KeySize; i++) {
            hash |= ((ULONG64)p[i]) << (i * 8);
        }
    } else {
        /* 大键：FNV-1a 64 位迭代 */
        hash = 0xcbf29ce484222325ULL;
        for (ULONG i = 0; i < KeySize; i++) {
            hash ^= p[i];
            hash *= 0x100000001b3ULL;
        }
    }
    /* 混入长度，防止长度不同但内容相同（如 "\x00" vs "\x00\x00"）碰撞 */
    hash ^= (ULONG64)KeySize << 56;

    /* 最终雪崩（fmix64） */
    hash ^= hash >> 33;
    hash *= 0xff51afd7ed558ccdULL;
    hash ^= hash >> 33;
    hash *= 0xc4ceb9fe1a85ec53ULL;
    hash ^= hash >> 33;

    return hash;
}

/* key 字节等值：长度不等即 FALSE；小键逐字节拼装比较
 * （无对齐读假设，用户态 key 来源可能非 8 字节对齐）；
 * 大键 memcmp。 */
static
BOOLEAN
CopKeyEqual(
    _In_ const PVOID StoredKey,
    _In_ SIZE_T StoredKeySize,
    _In_ const PVOID QueryKey,
    _In_ SIZE_T QueryKeySize
    )
{
    if (StoredKeySize != QueryKeySize) return FALSE;
    if (StoredKeySize <= sizeof(ULONG64)) {
        return *(PULONG64)StoredKey == *(PULONG64)QueryKey;
    }
    
    return RtlCompareMemory(StoredKey, QueryKey, StoredKeySize) == StoredKeySize;
}

/* key 副本：8 字节对齐清零分配 + 原样拷贝
 * （RtlZeroMemory 保证小键拼装读取时对齐填零）。 */
static
PVOID
CopCopyKey(
    _In_ const PVOID Key,
    _In_ SIZE_T KeySize
    )
{
    PVOID keyCopy = malloc(((ULONG64)KeySize + 7ULL) & ~7UL);
    if (!keyCopy) return NULL;
    RtlCopyMemory(keyCopy, Key, KeySize);
    return keyCopy;
}

/**************************************************/
/*          内部：双模式加锁辅助函数                 */
/*                                                   */
/*  封装 PerBucketLock 差异：TRUE 锁单桶 Buckets[i]. */
/*  Lock，FALSE 锁全局 GlobalLock。作用范围由调用点   */
/*  决定（单桶遍历或整表遍历）。                      */
/**************************************************/

static
VOID
CopAcquireHashMapLockExclusive(
    _Inout_ PWKD_HASH_MAP HashMap,
    _In_opt_ ULONG BucketIndex
    )
{
    if (HashMap->PerBucketLock) {
        if (BucketIndex) {
            AcquireSRWLockExclusive(&HashMap->Buckets[BucketIndex].Lock);
        }
    } else {
        AcquireSRWLockExclusive(&HashMap->GlobalLock);
    }
}

static
VOID
CopReleaseHashMapLockExclusive(
    _Inout_ PWKD_HASH_MAP HashMap,
    _In_opt_ ULONG BucketIndex
    )
{
    if (HashMap->PerBucketLock) {
        if (BucketIndex) {
            ReleaseSRWLockExclusive(&HashMap->Buckets[BucketIndex].Lock);
        }
    } else {
        ReleaseSRWLockExclusive(&HashMap->GlobalLock);
    }
}

static
VOID
CopAcquireHashMapLockShared(
    _Inout_ PWKD_HASH_MAP HashMap,
    _In_opt_ ULONG BucketIndex
    )
{
    if (HashMap->PerBucketLock) {
        if (BucketIndex) {
            AcquireSRWLockShared(&HashMap->Buckets[BucketIndex].Lock);
        }
    } else {
        AcquireSRWLockShared(&HashMap->GlobalLock);
    }
}

static
VOID
CopReleaseHashMapLockShared(
    _Inout_ PWKD_HASH_MAP HashMap,
    _In_opt_ ULONG BucketIndex
    )
{
    if (HashMap->PerBucketLock) {
        if (BucketIndex) {
            ReleaseSRWLockShared(&HashMap->Buckets[BucketIndex].Lock);
        }
    } else {
        ReleaseSRWLockShared(&HashMap->GlobalLock);
    }
}

/**************************************************/
/*              初始化与清理                        */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
CoInitializeHashMap(
    _Out_ PWKD_HASH_MAP             Map,
    _In_  ULONG                     BucketCount,
    _In_  ULONG                     MaxEntries,
    _In_  BOOLEAN                   PerBucketLock,
    _In_  BOOLEAN                   UseRefCallbacks,
    _In_  PFN_HASH_MAP_REFERENCE    Reference,
    _In_opt_ PFN_HASH_MAP_SHOULD_REMOVE ShouldRemove,
    _In_  PFN_HASH_MAP_DEREFERENCE  Dereference
    )
/*++
Routine Description:
    初始化哈希表。分配桶数组（含每桶 SRWLOCK），登记回调契约。

    强制对称校验（与驱动 CoHashMap 一致）：
    - UseRefCallbacks=TRUE 要求 Reference 与 Dereference 均
      非 NULL；任一为 NULL → STATUS_INVALID_PARAMETER。
    - UseRefCallbacks=FALSE 时任一回调非 NULL 亦拒绝（禁止半注册
      非对称态，避免插入 +1 / 摘除不 -1 的泄漏）。
    - ShouldRemove 始终可选，不参与校验。

Arguments:
    Map            - 输出表结构（调用方栈上）。
    BucketCount    - 桶数量（PerBucketLock=TRUE 即锁数量）。
    MaxEntries     - 容量配额（插入超限返回 QUOTA_EXCEEDED）。
    PerBucketLock  - TRUE=桶级锁，FALSE=全局锁。
    UseRefCallbacks - TRUE=启用 ref/deref 契约并强制成对。
    Reference    - 查找/插入命中 pin（UseRefCallbacks 下必填）。
    ShouldRemove - 移除裁决（可选）。
    Dereference  - 摘除解引（仅 -1，UseRefCallbacks 下必填）。

Return Value:
    NTSTATUS。
--*/
{
    SIZE_T allocSize;
    ULONG i;

    if (!Map || BucketCount == 0 || BucketCount > MaxEntries) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 对称校验：ref/deref 必须成对非 NULL；半注册态一律拒绝。 */
    if (UseRefCallbacks) {
        if (!Reference || !Dereference) {
            return STATUS_INVALID_PARAMETER;   /* ref/deref 强制成对 */
        }
    } else {
        if (Reference || Dereference || ShouldRemove) {
            return STATUS_INVALID_PARAMETER;   /* 非回调态不应挂回调 */
        }
    }

    RtlZeroMemory(Map, sizeof(WKD_HASH_MAP));

    allocSize = BucketCount * sizeof(WKD_HASH_MAP_BUCKET);
    Map->Buckets = (PWKD_HASH_MAP_BUCKET)malloc(allocSize);
    if (!Map->Buckets) {
        return STATUS_NO_MEMORY;
    }

    for (i = 0; i < BucketCount; i++) {
        InitializeSRWLock(&Map->Buckets[i].Lock);
        InitializeListHead(&Map->Buckets[i].ListHead);
    }

    InitializeSRWLock(&Map->GlobalLock);

    Map->BucketCount     = BucketCount;
    Map->MaxEntries      = MaxEntries;
    Map->ActiveEntries   = 0;
    Map->PerBucketLock   = PerBucketLock;
    Map->UseRefCallbacks = UseRefCallbacks;
    Map->Reference     = Reference;
    Map->ShouldRemove  = ShouldRemove;
    Map->Dereference   = Dereference;
    Map->Initialized     = TRUE;
    return STATUS_SUCCESS;
}

/* 仅释放 entry 包装与 key 副本，不触碰 Value（Dereference
 * 不在清空路径调用，对齐驱动 CoFreeHashMap 语义：teardown
 * 由调用方保证 rundown 后手动释放对象，避免双释放）。 */
static
VOID
CopDestroyHashMapEntry(
    _In_ PWKD_HASH_MAP_ENTRY Entry
    )
{
    if (!Entry) return;
    if (Entry->Key) free(Entry->Key);
    free(Entry);
}

VOID
CoHashMapClear(
    _Inout_ PWKD_HASH_MAP HashMap
    )
/*++
Routine Description:
    清理全部条目（释放表内 key 副本与 entry 包装）。
    不调用 Dereference（不清引用，对齐驱动 teardown 语义），
    对象本体由调用方在 Clear 前手动释放（如两阶段收集→释放范式）。

Return Value:
    无。
--*/
{
    ULONG i;

    if (!HashMap || !HashMap->Initialized || !HashMap->Buckets) return;

    for (i = 0; i < HashMap->BucketCount; i++) {
        CopAcquireHashMapLockExclusive(HashMap, i);
        while (!IsListEmpty(&HashMap->Buckets[i].ListHead)) {
            PLIST_ENTRY e = HashMap->Buckets[i].ListHead.Flink;
            PWKD_HASH_MAP_ENTRY entry =
                CONTAINING_RECORD(e, WKD_HASH_MAP_ENTRY, ListEntry);
            RemoveEntryList(e);
            HashMap->ActiveEntries--;
            CopDestroyHashMapEntry(entry);
        }
        CopReleaseHashMapLockExclusive(HashMap, i);
    }

    free(HashMap->Buckets);
    HashMap->Buckets = NULL;
    HashMap->Initialized = FALSE;
}

/**************************************************/
/*               查找                               */
/**************************************************/

PVOID
CoLookupHashMapEntry(
    _In_ const PWKD_HASH_MAP HashMap,
    _In_ const PVOID Key,
    _In_ SIZE_T KeySize
    )
/*++
Routine Description:
    按 key 字节等值查找首个匹配条目。命中时持共享锁内调用
    Reference pin 后返回 Value（UseRefCallbacks 下）；未命中
    返回 NULL。调用方负责释放 pin 后解引。

Return Value:
    命中的 Value，或 NULL。
--*/
{
    ULONG bucket;
    PLIST_ENTRY le;
    PVOID value = NULL;

    if (!HashMap || !HashMap->Initialized || !Key || KeySize == 0) return NULL;

    bucket = (ULONG)(CopHashKey(Key, KeySize) % HashMap->BucketCount);

    CopAcquireHashMapLockShared(HashMap, bucket);
    le = HashMap->Buckets[bucket].ListHead.Flink;
    while (le != &HashMap->Buckets[bucket].ListHead) {
        PWKD_HASH_MAP_ENTRY entry =
            CONTAINING_RECORD(le, WKD_HASH_MAP_ENTRY, ListEntry);

        if (CopKeyEqual(entry->Key, entry->KeySize, Key, KeySize)) {
            if (HashMap->UseRefCallbacks && HashMap->Reference) {
                HashMap->Reference(entry->Value);   /* pin：锁内仅原子 */
            }
            value = entry->Value;
            break;
        }
        le = le->Flink;
    }
    CopReleaseHashMapLockShared(HashMap, bucket);

    return value;
}

/**************************************************/
/*               插入                               */
/**************************************************/

NTSTATUS
CoInsertHashMapEntry(
    _Inout_ PWKD_HASH_MAP HashMap,
    _In_ const PVOID Key,
    _In_ SIZE_T KeySize,
    _In_ const PVOID Value
    )
/*++
Routine Description:
    插入。key 字节等值已存在 → COLLISION 不重复插入；否则表内拷贝
    key 副本入桶并 SUCCESS。

    UseRefCallbacks 下：表获得一份引用，插入成功（新条目）时于独占
    锁内调 Reference(+1)；命中已存在键不 +1（不调回调）。

Return Value:
    STATUS_SUCCESS / STATUS_OBJECT_NAME_COLLISION / STATUS_QUOTA_EXCEEDED。
--*/
{
    NTSTATUS status;
    ULONG bucket;
    PLIST_ENTRY le;
    PWKD_HASH_MAP_ENTRY entry = NULL;
    PVOID keyCopy;

    if (!HashMap || !HashMap->Initialized || !Key || KeySize == 0 || !Value) {
        return STATUS_INVALID_PARAMETER;
    }

    bucket = (ULONG)(CopHashKey(Key, KeySize) % HashMap->BucketCount);

    CopAcquireHashMapLockExclusive(HashMap, bucket);

    /* 容量配额 */
    if (HashMap->ActiveEntries > HashMap->MaxEntries) {
        status = STATUS_QUOTA_EXCEEDED;
        goto Cleanup;
    }

    /* 冲突检测：key 字节等值已存在 → COLLISION */
    le = HashMap->Buckets[bucket].ListHead.Flink;
    while (le != &HashMap->Buckets[bucket].ListHead) {
        PWKD_HASH_MAP_ENTRY __entry =
            CONTAINING_RECORD(le, WKD_HASH_MAP_ENTRY, ListEntry);
        if (CopKeyEqual(__entry->Key, __entry->KeySize, Key, KeySize)) {
            status = STATUS_OBJECT_NAME_COLLISION;
            goto Cleanup;
        }
        le = le->Flink;
    }

    /* key 副本（锁内分配） */
    keyCopy = CopCopyKey(Key, KeySize);
    if (!keyCopy) { status = STATUS_NO_MEMORY; goto Cleanup; }

    entry = (PWKD_HASH_MAP_ENTRY)malloc(sizeof(WKD_HASH_MAP_ENTRY));
    if (!entry) { status = STATUS_NO_MEMORY; goto Cleanup; }

    entry->Key = keyCopy;
    entry->KeySize = KeySize;
    entry->Value = Value;
    InsertTailList(&HashMap->Buckets[bucket].ListHead, &entry->ListEntry);
    HashMap->ActiveEntries++;
    HashMap->TotalEntries++;

    if (HashMap->UseRefCallbacks && HashMap->Reference) {
        HashMap->Reference(Value);   /* 新条目：表获得一份引用 */
    }

    status = STATUS_SUCCESS;
    entry = NULL;   /* 所有权已移交桶链表, 禁止 Cleanup 再 free */

Cleanup:
    if (entry) CopDestroyHashMapEntry(entry);
    CopReleaseHashMapLockExclusive(HashMap, bucket);
    return status;
}

/**************************************************/
/*               移除                               */
/**************************************************/

BOOLEAN
CoRemoveHashMapEntry(
    _Inout_ PWKD_HASH_MAP HashMap,
    _In_ const PVOID Key,
    _In_ SIZE_T KeySize
    )
/*++
Routine Description:
    按 key 字节等值移除首个匹配条目。摘除前经 ShouldRemove
    裁决（若注册且返回 FALSE 则取消移除）。摘除成功后于独占锁内
    调 Dereference 释放表引用（-1，与 Reference 配对语义）。

    对象本体释放由调用方负责（UseRefCallbacks 下 Dereference
    仅做原子 -1），不在本函数内 free。

Return Value:
    TRUE=已移除；FALSE=未找到或裁决取消。
--*/
{
    ULONG bucket;
    PLIST_ENTRY le;

    if (!HashMap || !HashMap->Initialized || !Key || KeySize == 0) return FALSE;
    bucket = (ULONG)(CopHashKey(Key, KeySize) % HashMap->BucketCount);

    CopAcquireHashMapLockExclusive(HashMap, bucket);
    le = HashMap->Buckets[bucket].ListHead.Flink;
    while (le != &HashMap->Buckets[bucket].ListHead) {
        PWKD_HASH_MAP_ENTRY entry =
            CONTAINING_RECORD(le, WKD_HASH_MAP_ENTRY, ListEntry);

        if (CopKeyEqual(entry->Key, entry->KeySize, Key, KeySize)) {
            if (HashMap->ShouldRemove &&
                !HashMap->ShouldRemove(entry->Value)) {
                goto Cleanup;
            }
            if (HashMap->UseRefCallbacks && HashMap->Dereference) {
                HashMap->Dereference(entry->Value);   /* 表引用 -1 */
            }
            RemoveEntryList(le);
            HashMap->ActiveEntries--;
            CopDestroyHashMapEntry(entry);
            CopReleaseHashMapLockExclusive(HashMap, bucket);
            return TRUE;
        }
        le = le->Flink;
    }

Cleanup:
    CopReleaseHashMapLockExclusive(HashMap, bucket);
    return FALSE;
}

/**************************************************/
/*               枚举                               */
/**************************************************/

VOID
CoHashMapEnumerate(
    _In_ PWKD_HASH_MAP HashMap,
    _In_ PFN_HASH_MAP_ENUM Callback,
    _Inout_opt_ PVOID Context
    )
/*++
Routine Description:
    全表逐桶共享锁遍历。回调在锁内调用（仅原子/拷贝），返回 FALSE
    提前终止。回调内不得释放 Value（Dereference 不在枚举路径调用）。

Return Value:
    无。
--*/
{
    ULONG i;

    if (!HashMap || !HashMap->Initialized || !Callback) return;

    for (i = 0; i < HashMap->BucketCount; i++) {
        CopAcquireHashMapLockShared(HashMap, i);
        {
            PLIST_ENTRY e = HashMap->Buckets[i].ListHead.Flink;
            while (e != &HashMap->Buckets[i].ListHead) {
                PWKD_HASH_MAP_ENTRY entry =
                    CONTAINING_RECORD(e, WKD_HASH_MAP_ENTRY, ListEntry);
                PLIST_ENTRY next = e->Flink;
                if (!Callback(entry->Key, entry->KeySize, entry->Value, Context)) {
                    CopReleaseHashMapLockShared(HashMap, i);
                    return;
                }
                e = next;
            }
        }
        CopReleaseHashMapLockShared(HashMap, i);
    }
}
