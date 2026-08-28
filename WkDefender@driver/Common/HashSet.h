#pragma once

#include <ntifs.h>

/**************************************************/
/*             通用 Hash Set 类型定义              */
/**************************************************/

//
// 哈希函数类型
//
typedef ULONG(*PFN_HASHSET_HASH_FUNC)(
    _In_ PVOID Element
    );

//
// 元素比较函数类型
//
typedef BOOLEAN(*PFN_HASHSET_EQUAL_FUNC)(
    _In_ PVOID Element1,
    _In_ PVOID Element2,
    _In_ BOOLEAN CaseInSensitive
    );

//
// 遍历回调函数类型
//
typedef
_Function_class_(PFN_HASHSET_ENUM)
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
(*PFN_HASHSET_ENUM)(
    _In_ ULONG64 Element,
    _In_opt_ PVOID Context
    );

typedef struct _WKD_HASH_SET_ENTRY {
    ULONG64 Element;                    // 通用元素（可存储值或指针）
    BOOLEAN Occupied;                   // 槽位是否占用
    BOOLEAN Deleted;                    // 墓碑标记（开放寻址删除用）
} WKD_HASH_SET_ENTRY, * PWKD_HASH_SET_ENTRY;

typedef struct _WKD_HASH_SET {
    PWKD_HASH_SET_ENTRY Entries;        // 哈希槽数组
    ULONG BucketCount;                  // 桶数量（2 的幂）
    volatile LONG Count;                // 当前元素数
    KSPIN_LOCK Lock;                    // 全局自旋锁
    BOOLEAN Initialized;
} WKD_HASH_SET, * PWKD_HASH_SET;

/**************************************************/
/*               API 声明                         */
/**************************************************/

//
// 初始化 hash set（分配槽数组，2 的幂性能更优）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdHashSetInitialize(
    _Out_ PWKD_HASH_SET Set,
    _In_ ULONG BucketCount
    );

//
// 清理 hash set（仅释放槽数组，不处理 Element 指向的外部数据）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdHashSetCleanup(
    _Inout_ WKD_HASH_SET *Set
    );

//
// 插入元素
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdHashSetInsert(
    _Inout_ PWKD_HASH_SET Set,
    _In_ ULONG64 Element,
    _In_ PFN_HASHSET_HASH_FUNC HashFunc,
    _In_ PFN_HASHSET_EQUAL_FUNC EqualFunc,
    _Out_opt_ PBOOLEAN AlreadyExists
    );

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
    );

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
    );

//
// 遍历 hash set
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdHashSetEnumerate(
    _In_ WKD_HASH_SET *Set,
    _In_ PFN_HASHSET_ENUM EnumFunc,
    _In_opt_ PVOID Context
    );

//
// 返回当前元素数量
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
WkdHashSetCount(
    _In_ WKD_HASH_SET *Set
    );
