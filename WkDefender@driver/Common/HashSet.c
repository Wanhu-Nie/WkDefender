#include "HashSet.h"

//
// 计算桶索引（要求 BucketCount 为 2 的幂）
//
#define HASH_SET_BUCKET_INDEX(HashValue, BucketCount) ((HashValue) & ((BucketCount) - 1))
#define ULONG_MAX (ULONG)-1
//
// 初始化 hash set
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdHashSetInitialize(
    _Out_ PWKD_HASH_SET HashSet,
    _In_ ULONG BucketCount
    )
{
    if (!HashSet || BucketCount == 0 || (BucketCount & (BucketCount - 1)) != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(HashSet, sizeof(WKD_HASH_SET));

    
    HashSet->Entries = (PWKD_HASH_SET_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        BucketCount * sizeof(WKD_HASH_SET_ENTRY),
        'hset'
        );
    if (!HashSet->Entries) {
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(HashSet->Entries, BucketCount * sizeof(WKD_HASH_SET_ENTRY));

    HashSet->BucketCount = BucketCount;
    HashSet->Count = 0;
    KeInitializeSpinLock(&HashSet->Lock);
    HashSet->Initialized = TRUE;

    return STATUS_SUCCESS;
}

//
// 清理 hash set（仅释放槽数组，不处理 Element 指向的外部数据）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdHashSetCleanup(
    _Inout_ WKD_HASH_SET * HashSet
    )
{
    if (!HashSet || !HashSet->Entries) {
        return;
    }

    ExFreePoolWithTag(HashSet->Entries, 'hset');
    RtlZeroMemory(HashSet, sizeof(WKD_HASH_SET));
}

//
// 插入元素（线性探测开放寻址）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdHashSetInsert(
    _Inout_ PWKD_HASH_SET Set,
    _In_ ULONG64 Element,
    _In_ PFN_HASHSET_HASH_FUNC HashFunc,
    _In_ PFN_HASHSET_EQUAL_FUNC EqualFunc,
    _Out_opt_ PBOOLEAN AlreadyExists
    )
{
    ULONG hashValue;
    ULONG index;
    ULONG i;
    KIRQL oldIrql;
    ULONG firstDeleted = ULONG_MAX;

    if (!Set || !Set->Entries || !HashFunc || !EqualFunc) {
        return STATUS_INVALID_PARAMETER;
    }

    if (AlreadyExists) {
        *AlreadyExists = FALSE;
    }

    hashValue = HashFunc((PVOID)Element);
    KeAcquireSpinLock(&Set->Lock, &oldIrql);

    for (i = 0; i < Set->BucketCount; i++) {
        index = HASH_SET_BUCKET_INDEX(hashValue + i, Set->BucketCount);

        /* 空槽位，插入 */
        if (!Set->Entries[index].Occupied && !Set->Entries[index].Deleted) {
            // 槽位复用：如果在之前的探测中遇到过“已删除”的槽位（firstDeleted != ULONG_MAX），则优先把新元素插入到那个 firstDeleted 位置（而不是当前的空槽位），这样可以保持哈希表的紧凑性。
            if (firstDeleted != ULONG_MAX) {
                index = firstDeleted;
            }
            Set->Entries[index].Element = Element;
            Set->Entries[index].Occupied = TRUE;
            Set->Entries[index].Deleted = FALSE;
            InterlockedIncrement(&Set->Count);
            KeReleaseSpinLock(&Set->Lock, oldIrql);
            return STATUS_SUCCESS;
        }

        /* 遇到“已删除的槽位” */
        if (Set->Entries[index].Deleted && firstDeleted == ULONG_MAX) {
            firstDeleted = index;
            continue;
        }

        /* 遇到“已存在的元素” */
        if (!Set->Entries[index].Deleted &&
            EqualFunc((PVOID)Set->Entries[index].Element, (PVOID)Element, TRUE) == 0) {
            /* 已存在 */
            if (AlreadyExists) {
                *AlreadyExists = TRUE;
            }
            KeReleaseSpinLock(&Set->Lock, oldIrql);
            return STATUS_SUCCESS;
        }
    }

    /* 表满 */
    KeReleaseSpinLock(&Set->Lock, oldIrql);
    return STATUS_INSUFFICIENT_RESOURCES;
}

//
// 删除元素
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdHashSetRemove(
    _Inout_ WKD_HASH_SET *Set,
    _In_ ULONG64 Element,
    _In_ PFN_HASHSET_HASH_FUNC HashFunc,
    _In_ PFN_HASHSET_EQUAL_FUNC EqualFunc
    )
{
    ULONG hashValue;
    ULONG index;
    ULONG i;
    KIRQL oldIrql;

    if (!Set || !Set->Entries || !HashFunc || !EqualFunc) {
        return FALSE;
    }

    hashValue = HashFunc((PVOID)Element);
    KeAcquireSpinLock(&Set->Lock, &oldIrql);

    for (i = 0; i < Set->BucketCount; i++) {
        index = HASH_SET_BUCKET_INDEX(hashValue + i, Set->BucketCount);

        if (!Set->Entries[index].Occupied && !Set->Entries[index].Deleted) {
            break;
        }

        if (Set->Entries[index].Occupied &&
            !Set->Entries[index].Deleted &&
            EqualFunc((PVOID)Set->Entries[index].Element, (PVOID)Element, TRUE) == 0) {

            Set->Entries[index].Occupied = FALSE;
            Set->Entries[index].Deleted = TRUE; /* 墓碑 */
            InterlockedDecrement(&Set->Count);
            KeReleaseSpinLock(&Set->Lock, oldIrql);
            return TRUE;
        }
    }

    KeReleaseSpinLock(&Set->Lock, oldIrql);
    return FALSE;
}

//
// 查询元素是否存在
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdHashSetContains(
    _In_ WKD_HASH_SET *Set,
    _In_ ULONG64 Element,
    _In_ PFN_HASHSET_HASH_FUNC HashFunc,
    _In_ PFN_HASHSET_EQUAL_FUNC EqualFunc
    )
{
    ULONG hashValue;
    ULONG index;
    ULONG i;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    if (!Set || !Set->Entries || !HashFunc || !EqualFunc) {
        return FALSE;
    }

    hashValue = HashFunc((PVOID)Element);
    KeAcquireSpinLock(&Set->Lock, &oldIrql);

    for (i = 0; i < Set->BucketCount; i++) {
        index = HASH_SET_BUCKET_INDEX(hashValue + i, Set->BucketCount);

        if (!Set->Entries[index].Occupied && !Set->Entries[index].Deleted) {
            break;
        }

        if (Set->Entries[index].Occupied &&
            !Set->Entries[index].Deleted &&
            EqualFunc((PVOID)Set->Entries[index].Element, (PVOID)Element, TRUE) == 0) {
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&Set->Lock, oldIrql);
    return found;
}

//
// 遍历 hash set
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdHashSetEnumerate(
    _In_ WKD_HASH_SET *Set,
    _In_ PFN_HASHSET_ENUM EnumFunc,
    _In_opt_ PVOID Context
    )
{
    ULONG i;
    KIRQL oldIrql;

    if (!Set || !Set->Entries || !EnumFunc) {
        return;
    }

    KeAcquireSpinLock(&Set->Lock, &oldIrql);

    for (i = 0; i < Set->BucketCount; i++) {
        if (Set->Entries[i].Occupied && !Set->Entries[i].Deleted) {
            BOOLEAN cont = EnumFunc(Set->Entries[i].Element, Context);
            if (!cont) {
                break;
            }
        }
    }

    KeReleaseSpinLock(&Set->Lock, oldIrql);
}

//
// 返回当前元素数量
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
WkdHashSetCount(
    _In_ WKD_HASH_SET *Set
    )
{
    if (!Set || !Set->Entries) {
        return 0;
    }
    return (ULONG)Set->Count;
}
