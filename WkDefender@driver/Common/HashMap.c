#include "HashMap.h"
#include "Utils.h"

//
// 计算哈希索引
//
#define GET_BUCKET_INDEX(HashValue, BucketCount) ((HashValue) % (BucketCount))

//
// 哈希映射条目池标签
//
#define HASH_MAP_ENTRY_TAG 'hmap'

/************************************************
**                  内部锁操作
************************************************/

//
// 获取桶锁（推锁独占模式）
//
_IRQL_requires_max_(APC_LEVEL)
static
VOID
CopAcquireHashMapLockExclusive(
    _Inout_ PWKD_HASH_MAP HashMap,
    _In_opt_ ULONG BucketIndex
    )
{
    if (HashMap->PerBucketLock) {
        WkdAcquirePushLockExclusive(&HashMap->Entries[BucketIndex].Lock);
    }
    else {
        WkdAcquirePushLockExclusive(&HashMap->GlobalLock);
    }
}

_IRQL_requires_max_(APC_LEVEL)
static
VOID
CopAcquireHashMapLockShared(
    _Inout_ PWKD_HASH_MAP HashMap,
    _In_opt_ ULONG BucketIndex
)
{
    if (HashMap->PerBucketLock) {
        WkdAcquirePushLockShared(&HashMap->Entries[BucketIndex].Lock);
    }
    else {
        WkdAcquirePushLockShared(&HashMap->GlobalLock);
    }
}

//
// 释放桶锁
//
_IRQL_requires_max_(APC_LEVEL)
static
VOID
CopReleaseHashMapLockExclusive(
    _In_ PWKD_HASH_MAP HashMap,
    _In_ ULONG BucketIndex
    )
{
    if (HashMap->PerBucketLock) {
        WkdReleasePushLockExclusive(&HashMap->Entries[BucketIndex].Lock);
    }
    else {
        WkdReleasePushLockExclusive(&HashMap->GlobalLock);
    }
}

_IRQL_requires_max_(APC_LEVEL)
static
VOID
CopReleaseHashMapLockShared(
    _In_ PWKD_HASH_MAP HashMap,
    _In_ ULONG BucketIndex
)
{
    if (HashMap->PerBucketLock) {
        WkdReleasePushLockShared(&HashMap->Entries[BucketIndex].Lock);
    }
    else {
        WkdReleasePushLockShared(&HashMap->GlobalLock);
    }
}

/************************************************
**                  内部哈希与比较函数
************************************************/

static
ULONG64
CopHashKey(
    _In_ const PVOID Key,
    _In_ ULONG KeySize
    )
{
    ULONG64 hash = 0;
    const PUCHAR p = (const PUCHAR)Key;

    // 对于 <= 8 字节的键，直接视为一个 64 位整数，做一次完美雪崩
    if (KeySize <= sizeof(ULONG64)) {
        // 只取前 8 字节，小端序填充
        for (ULONG i = 0; i < KeySize; i++) {
            hash |= ((ULONG64)p[i]) << (i * 8);
        }
    } else {
        // 对于 > 8 字节的变长键，使用 FNV-1a 64 位，最后再做强雪崩
        hash = 0xcbf29ce484222325ULL;
        for (ULONG i = 0; i < KeySize; i++) {
            hash ^= p[i];
            hash *= 0x100000001b3ULL;
        }
    }
    // 混入长度信息，防止长度不同但内容相同（如 "\x00" 和 "\x00\x00"）碰撞
    hash ^= (ULONG64)KeySize << 56;

    /* 最终雪崩函数，分布增强 */
    hash ^= hash >> 33;
    hash *= 0xff51afd7ed558ccdULL;
    hash ^= hash >> 33;
    hash *= 0xc4ceb9fe1a85ec53ULL;
    hash ^= hash >> 33;

    return hash;
}

static
BOOLEAN
CopKeyEqual(
    _In_ PVOID StoredKey,
    _In_ ULONG StoredKeySize,
    _In_ PVOID QueryKey,
    _In_ ULONG QueryKeySize
    )
{
    if (StoredKeySize != QueryKeySize) {
        return FALSE;
    }

    if (StoredKeySize <= sizeof(ULONG64)) {
        //
        // 小键内联：读出查询值，与存储值比对
        //
        return (*(PULONG64)StoredKey == *(PULONG64)QueryKey);
    }

    //
    // 大键堆拷贝：逐字节内存比对
    //
    return RtlCompareMemory(StoredKey, QueryKey, StoredKeySize) == StoredKeySize;
}

static
PVOID
CopCopyKey(
    _In_ PVOID Key,
    _In_ ULONG KeySize
)
{
    PVOID keyCopy = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, ALIGN_8(KeySize), HASH_MAP_ENTRY_TAG);
    if (!keyCopy) {
        return NULL;
    }
    RtlZeroMemory(keyCopy, ALIGN_8(KeySize));
    RtlCopyMemory(keyCopy, Key, KeySize);
    return keyCopy;
}

/************************************************
**                  初始化与清理
************************************************/

_Use_decl_annotations_
NTSTATUS
CoInitializeHashMap(
    _Out_ PWKD_HASH_MAP HashMap,
    _In_ ULONG BucketCount,
    _In_ BOOLEAN PerBucketLock,
    _In_ PFN_HASH_MAP_REFERENCE_CALLBACK Reference,
    _In_opt_ PFN_HASH_MAP_REMOVE_CALLBACK ShouldRemove,
    _In_ PFN_HASH_MAP_DEREFERENCE_CALLBACK Dereference
    )
{
    PWKD_HASH_MAP_ENTRY entries;
    SIZE_T allocSize;

    //
    // 2026-08-25 强制对称契约: Reference/Dereference 必选成对,
    // 缺一拒绝初始化 (条目引用计数管理的最小完备集);
    // ShouldRemove 可选 (NULL = 移除无存活裁决)。
    //
    if (!HashMap || BucketCount == 0 || !Reference || !Dereference) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(HashMap, sizeof(WKD_HASH_MAP));

    //
    // 分配哈希槽数组
    //
    allocSize = BucketCount * sizeof(WKD_HASH_MAP_ENTRY);
    entries = (PWKD_HASH_MAP_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        allocSize,
        HASH_MAP_ENTRY_TAG
        );

    if (!entries) {
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(entries, allocSize);
    HashMap->Entries = entries;
    HashMap->BucketCount = BucketCount;
    HashMap->PerBucketLock = PerBucketLock;

    /* 回调注册 (ShouldRemove 允许 NULL) */
    HashMap->Reference   = Reference;
    HashMap->ShouldRemove = ShouldRemove;
    HashMap->Dereference = Dereference;

    /* 初始化推锁 */
    ExInitializePushLock(&HashMap->GlobalLock);
    for (ULONG i = 0; i < BucketCount; i++) {
        ExInitializePushLock(&(HashMap->Entries[i].Lock));
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
CoFreeHashMap(
    _Inout_ PWKD_HASH_MAP HashMap
    )
{
    PWKD_HASH_MAP_ENTRY entry;
    PWKD_HASH_MAP_ENTRY nextEntry;

    if (!HashMap || !HashMap->Entries) {
        return;
    }

    /* PerBucketLock直接在循环外持有锁；否则在循环内逐桶获取锁 */
    if (!HashMap->PerBucketLock) {
        WkdAcquirePushLockExclusive(&HashMap->GlobalLock);
    }

    for (ULONG i = 0; i < HashMap->BucketCount; i++) {
        if (HashMap->PerBucketLock)
            WkdAcquirePushLockExclusive(&HashMap->Entries[i].Lock);

        entry = HashMap->Entries[i].Next;
        while (entry) {
            nextEntry = entry->Next;
            ExFreePoolWithTag(entry->Key, HASH_MAP_ENTRY_TAG);
            ExFreePoolWithTag(entry, HASH_MAP_ENTRY_TAG);
            HashMap->ActiveEntries--;
            entry = nextEntry;
        }

        entry = &HashMap->Entries[i];
        if (entry->Occupied) {
            ExFreePoolWithTag(entry->Key, HASH_MAP_ENTRY_TAG);
            HashMap->ActiveEntries--;
        }

        if (HashMap->PerBucketLock)
            WkdReleasePushLockExclusive(&HashMap->Entries[i].Lock);
    }

    if (!HashMap->PerBucketLock) {
        WkdReleasePushLockExclusive(&HashMap->GlobalLock);
    }

    /*
     * 桶内条目均已释放完毕。
     * 并发读取结构字段（Entries/BucketCount）的操作者须由调用方
     * 统一确保已退出（如 IoaCleanup 经 ExWaitForRundownProtectionRelease
     * 等待全部拥有者释放），此处无活跃持有者，可无锁清理结构。
     */
    ASSERT(HashMap->ActiveEntries == 0);
    ExFreePoolWithTag(HashMap->Entries, HASH_MAP_ENTRY_TAG);
    HashMap->Entries = NULL;
    HashMap->BucketCount = 0;
    HashMap->PerBucketLock = FALSE;

    return;
}

/************************************************
**                  简单接口实现
**
**  简单模式：Key 即身份标识值（PVOID），KeySize 内部为 0。
**  不拷贝 Key，比较时直接比对指针值。
**  自动增加引用计数
************************************************/

_Use_decl_annotations_
NTSTATUS
CoInsertHashMap(
    _Inout_ PWKD_HASH_MAP HashMap,
    _In_ PVOID Key,
    _In_ ULONG KeySize,
    _In_ ULONG64 Value,
    _Out_opt_ PBOOLEAN AlreadyExists
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;;
    PVOID cachedKey;
    ULONG bucketIndex;
    PWKD_HASH_MAP_ENTRY entry;

    if (!HashMap || !HashMap->Entries || !Key || !KeySize) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * 2026-08-25 强制对称契约: Reference/Dereference 由 CoInitializeHashMap
     * 强制校验成对注册, 此处保留防御性复查 (杜绝"动态生命周期但未注册
     * ref"导致的 UAF/泄漏)。
     */
    if (!HashMap->Reference || !HashMap->Dereference) {
        return STATUS_INVALID_PARAMETER;
    }

    if (AlreadyExists) {
        *AlreadyExists = FALSE;
    }

    bucketIndex = GET_BUCKET_INDEX(
        CopHashKey(Key, KeySize), HashMap->BucketCount);

    CopAcquireHashMapLockExclusive(HashMap, bucketIndex);

    //
    // 检查是否已存在
    //
    entry = &HashMap->Entries[bucketIndex];
    while (entry->Occupied) {
        if (CopKeyEqual(entry->Key, entry->KeySize, Key, KeySize)) {
            //
            // 键已存在，直接返回
            //
            if (AlreadyExists) {
                *AlreadyExists = TRUE;
            }
            status = STATUS_OBJECT_NAME_COLLISION;
            goto Success;
        }

        if (entry->Next == NULL) {
            break;
        }
        entry = entry->Next;
    }

    /* 申请Key副本用于存储 */
    {
        cachedKey = CopCopyKey(Key, KeySize);
        if (!cachedKey) {
            CopReleaseHashMapLockExclusive(HashMap, bucketIndex);
            return STATUS_NO_MEMORY;
        }
    }

    //
    // 如果槽位已被占用，创建冲突链节点
    //
    if (entry->Occupied) {
        PWKD_HASH_MAP_ENTRY newEntry =
            (PWKD_HASH_MAP_ENTRY)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(WKD_HASH_MAP_ENTRY),
            HASH_MAP_ENTRY_TAG
            );
        if (!newEntry) {
            status = STATUS_NO_MEMORY;
            goto Cleanup;
        }

        RtlZeroMemory(newEntry, sizeof(WKD_HASH_MAP_ENTRY));
        newEntry->Key = cachedKey;      // 简单模式：直接存标识值
        newEntry->KeySize = KeySize;    // 标记简单模式
        newEntry->Value = Value;
        newEntry->Occupied = TRUE;
        newEntry->Next = NULL;

        entry->Next = newEntry;
        entry = newEntry;           // entry指针统一后用于增加引用计数
    } else {
        //
        // 直接使用空槽位
        //
        entry->Key = cachedKey;     // 简单模式：直接存标识值
        entry->KeySize = KeySize;   // 标记简单模式
        entry->Value = Value;
        entry->Occupied = TRUE;
        entry->Next = NULL;
    }

    /* 引用计数（Reference =FALSE 且未注册回调时跳过） */
    if (HashMap->Reference) {
        HashMap->Reference(entry->Value);
    }

    HashMap->TotalEntries++;
    HashMap->ActiveEntries++;
    status = STATUS_SUCCESS;

Success:
    CopReleaseHashMapLockExclusive(HashMap, bucketIndex);
    return status;

Cleanup:
    CopReleaseHashMapLockExclusive(HashMap, bucketIndex);
    if (cachedKey) 
        ExFreePoolWithTag(cachedKey, HASH_MAP_ENTRY_TAG);

    return STATUS_NO_MEMORY;
}

/* 调用者负责解引用 */
_Use_decl_annotations_
PVOID
CoLookupHashMapEntry(
    _In_ PWKD_HASH_MAP HashMap,
    _In_ PVOID Key,
    _In_ ULONG KeySize
    )
{
    ULONG bucketIndex;
    PWKD_HASH_MAP_ENTRY entry;
    PVOID value;

    if (!HashMap || !HashMap->Entries || !Key || !KeySize) {
        return NULL;
    }

    bucketIndex = GET_BUCKET_INDEX(
        CopHashKey(Key, KeySize), HashMap->BucketCount);

    CopAcquireHashMapLockShared(HashMap, bucketIndex);

    entry = &HashMap->Entries[bucketIndex];
    while (entry && entry->Occupied) {
        if (CopKeyEqual(entry->Key, entry->KeySize, Key, KeySize)) {
            value = (PVOID)(ULONG_PTR)entry->Value;

            //
            // 锁内调用 Reference pin 住 Value，防止并发移除后 UAF
            //
            if (HashMap->Reference) {
                HashMap->Reference(value);
            }

            CopReleaseHashMapLockShared(HashMap, bucketIndex);
            return value;
        }

        entry = entry->Next;
    }

    CopReleaseHashMapLockShared(HashMap, bucketIndex);
    return NULL;
}

/* 调用者需自身持有对象的Ref */
_Use_decl_annotations_
BOOLEAN
CoRemoveHashMapEntry(
    _Inout_ PWKD_HASH_MAP HashMap,
    _In_ const PVOID Key,
    _In_ SIZE_T KeySize
    )
{
    ULONG bucketIndex;
    PWKD_HASH_MAP_ENTRY entry, previous = NULL;

    if (!HashMap || !HashMap->Entries || !Key || KeySize == 0) {
        return FALSE;
    }

    bucketIndex = GET_BUCKET_INDEX(
        CopHashKey(Key, KeySize), HashMap->BucketCount);

    CopAcquireHashMapLockExclusive(HashMap, bucketIndex);

    entry = &HashMap->Entries[bucketIndex];
    while (entry && entry->Occupied) {
        if (CopKeyEqual(entry->Key, entry->KeySize, Key, KeySize)) {

            /* 移除前裁决：如果 ShouldRemove 回调返回 FALSE，取消移除 */
            if (HashMap->ShouldRemove &&
                !HashMap->ShouldRemove(entry->Value)) {
                CopReleaseHashMapLockExclusive(HashMap, bucketIndex);
                return FALSE;
            }

            /* 摘除前保存 Value，供摘除后 Dereference 配对释放（与插入时 Reference 成对） */
            PVOID removedValue = (PVOID)entry->Value;

            //
            // 找到目标，释放旧 Key（如有堆分配）
            //
            ExFreePoolWithTag(entry->Key, HASH_MAP_ENTRY_TAG);

            if (previous) {
                previous->Next = entry->Next;
                ExFreePoolWithTag(entry, HASH_MAP_ENTRY_TAG);
            } 
            else if (entry->Next) {
                //
                // 有后继节点：将后继数据折叠到当前节点，释放后继
                //
                PWKD_HASH_MAP_ENTRY next = entry->Next;
                entry->Key = next->Key;
                entry->KeySize = next->KeySize;
                entry->Value = next->Value;
                entry->Next = next->Next;
                entry->Occupied = TRUE;
                ExFreePoolWithTag(next, HASH_MAP_ENTRY_TAG);
            } else {
                //
                // 槽头唯一节点：清空槽位
                //
                entry->Key = NULL;
                entry->KeySize = 0;
                entry->Value = NULL;
                entry->Occupied = FALSE;
            }

            HashMap->ActiveEntries--;

            /*
             * 释放 HashMap 持有的 Value 引用（桶独占锁内调用，回调须无锁）。
             * 对 IoapBehaviorDeref / IoapPairDeref 而言即 InterlockedDecrement
             * + 可能的对象释放（ExFreePoolWithTag / DaDestroy），均无锁安全。
             * Reference =FALSE 且未注册回调时跳过（Value 由调用方自管）。
             */
            if (HashMap->Dereference) {
                HashMap->Dereference(removedValue);
            }

            CopReleaseHashMapLockExclusive(HashMap, bucketIndex);
            return TRUE;
        }

        previous = entry;
        entry = entry->Next;
    }

    CopReleaseHashMapLockExclusive(HashMap, bucketIndex);
    return FALSE;
}

/************************************************
**              快照枚举 API
**
**  CoCaptureHashMapSnapshot — 两阶段 key-only 快照。
**
**  Buffer == NULL：
**      返回 ActiveEntries 的近似值（无锁，快速估算）。
**      调用者可据此分配缓冲区，建议加余量避免重试。
**
**  Buffer != NULL：
**      逐桶加共享锁，拷贝 key 缓冲区。
**      返回实际写入的条目数。
**      若返回值等于 BufferCapacity，可能因并发插入被截断，
**      调用者应分配更大缓冲区重试（指数增长）。
************************************************/

_Use_decl_annotations_
NTSTATUS
CoCaptureHashMapSnapshot(
    _In_ const PWKD_HASH_MAP HashMap,
    _In_opt_ PWKD_HASH_MAP_SNAPSHOT Buffer,
    _Inout_ PSIZE_T BufferSize,
    _Out_opt_ PULONG Capacity
    )
{
    BOOLEAN queryMode;
    BOOLEAN full = FALSE;
    SIZE_T requiredSize = 0;
    ULONG outCapacity = 0;  // 枚举到的实际项数

    if (!HashMap || !HashMap->Entries || !BufferSize) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Buffer) queryMode = TRUE;  // 查询容量模式
    else {
        /* 枚举模式 - 初始化缓冲区 */
        queryMode = FALSE;
        RtlZeroMemory(Buffer, *BufferSize);
    }

    if (!HashMap->PerBucketLock) CopAcquireHashMapLockShared(HashMap, 0);
    for (ULONG i = 0; i < HashMap->BucketCount; i++) {
        if (HashMap->PerBucketLock) CopAcquireHashMapLockShared(HashMap, i);

        PWKD_HASH_MAP_ENTRY entry = &HashMap->Entries[i];
        while (entry && entry->Occupied) {
            SIZE_T seSize = entry->KeySize + sizeof(SIZE_T);
            
            if (queryMode) {
                requiredSize += entry->KeySize;
                outCapacity++;
            }
            else if (requiredSize + seSize < *BufferSizee) {
                /*
                 * 必须用 min 截断：KeyData 数组固定为 WKD_HASH_MAP_MAX_KEY_SIZE。
                 * 历史版本误用 max，当 KeySize 小于 MAX 时越界读 entry->Key
                 * 之后的内存；当 KeySize 超过 MAX 时越界写缓冲区（堆破坏）。
                 */
                PWKD_HASH_MAP_SNAPSHOT se =
                    (PWKD_HASH_MAP_SNAPSHOT)((PUCHAR)Buffer + requiredSize);
                se->KeySize = entry->KeySize;
                RtlCopyMemory(se->KeyData, entry->Key, entry->KeySize);
                requiredSize += seSize;
                outCapacity++;
            } else { full = TRUE;  goto Return; }   // 容量不足，提前结束枚举
            entry = entry->Next;
        }

        if (HashMap->PerBucketLock) CopReleaseHashMapLockShared(HashMap, i);
    }
    if (!HashMap->PerBucketLock) CopReleaseHashMapLockShared(HashMap, 0);

Return:
    if (Capacity) *Capacity = outCapacity;
    if (queryMode) { 
        *BufferSize = requiredSize;
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    else if (full) return STATUS_INFO_LENGTH_MISMATCH;
    else return STATUS_SUCCESS;
}

/************************************************
**              枚举回调 API 实现
** 逐桶共享锁遍历，回调返回 FALSE 提前终止。
************************************************/

_Use_decl_annotations_
VOID
CoEnumerateHashMap(
    _In_ PWKD_HASH_MAP HashMap,
    _In_ PFN_HASH_MAP_ENUM_CALLBACK Callback,
    _Inout_opt_ PVOID Context
    )
{
    if (!HashMap || !HashMap->Entries || !Callback) {
        return;
    }

    for (ULONG i = 0; i < HashMap->BucketCount; i++) {
        CopAcquireHashMapLockShared(HashMap, i);

        PWKD_HASH_MAP_ENTRY entry = &HashMap->Entries[i];
        while (entry && entry->Occupied) {
            if (!Callback(entry->Key, entry->KeySize, entry->Value, Context)) {
                CopReleaseHashMapLockShared(HashMap, i);
                return;
            }
            entry = entry->Next;
        }

        CopReleaseHashMapLockShared(HashMap, i);
    }
}

