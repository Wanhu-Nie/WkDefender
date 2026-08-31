#pragma once

#include <ntifs.h>
#include "Constants.h"

/************************************************
**                  类型定义
************************************************/

//
// Value 引用递增回调（查找命中时在共享锁内调用）
//
typedef
LONG
(*PFN_HASH_MAP_REFERENCE_CALLBACK)(
    _Inout_ PVOID Object
    );

//
// Value 移除裁决回调（CoRemoveHashMapEntry 在桶独占锁内调用）
// 返回 TRUE = 允许移除，FALSE = 取消移除（CoRemoveHashMapEntry 返回 FALSE）
//
typedef
BOOLEAN
(*PFN_HASH_MAP_REMOVE_CALLBACK)(
    _In_ PVOID Object
    );

//
// Value 解引用回调（CoRemoveHashMapEntry 摘除条目成功时在桶独占锁内调用）
// 与 Reference 成对：插入时 +1，摘除时 -1。
// 调用方注册的回调中不得再获取本哈希表的桶锁（锁内回调，仅允许无锁/原子操作）。
//
typedef
LONG
(*PFN_HASH_MAP_DEREFERENCE_CALLBACK)(
    _Inout_ PVOID Object
    );

/************************************************
**                  结构体定义
************************************************/

//
// 哈希映射条目（内部冲突链节点）
//
typedef struct _WKD_HASH_MAP_ENTRY {
    struct _WKD_HASH_MAP_ENTRY *Next;   // 冲突链下一项
    BOOLEAN Occupied;                   // 槽位是否被占用
    EX_PUSH_LOCK Lock;                  // 桶级推锁（PerBucketLock 模式使用）
    PVOID Key;                          // 键存储（见 KeySize 语义）
    SIZE_T KeySize;                      // 键大小
    ULONG64 Value;                      // 值
} WKD_HASH_MAP_ENTRY, * PWKD_HASH_MAP_ENTRY;

//
// 哈希映射表
//
typedef struct _WKD_HASH_MAP {
    PWKD_HASH_MAP_ENTRY Entries;        // 哈希槽数组（锁已嵌入每个条目）
    ULONG BucketCount;                  // 桶数量

    EX_PUSH_LOCK GlobalLock;            // 全局推锁（PerBucketLock=FALSE 时使用）
    BOOLEAN PerBucketLock;              // 是否使用桶级锁（Entries[i].Lock）

    volatile ULONG TotalEntries;
    volatile ULONG ActiveEntries;

    /* 回调函数 (2026-08-25 强制对称契约):
     * Reference/Dereference 必选 — CoInitializeHashMap 强制校验成对提供;
     * ShouldRemove 可选 (NULL = 移除无裁决)。
     *   插入 CoInsertHashMap      → Reference +1 (表引用)
     *   查找 CoLookupHashMapEntry → 共享锁内 Reference +1 (pin)
     *   摘除 CoRemoveHashMapEntry → 桶独占锁内 Dereference -1 */
    PFN_HASH_MAP_REFERENCE_CALLBACK Reference;
    PFN_HASH_MAP_REMOVE_CALLBACK    ShouldRemove;
    PFN_HASH_MAP_DEREFERENCE_CALLBACK Dereference;
} WKD_HASH_MAP, * PWKD_HASH_MAP;

/************************************************
**              快照枚举条目定义
************************************************/

#define WKD_HASH_MAP_MAX_KEY_SIZE  32

//
// CoCaptureHashMapSnapshot 输出的快照条目（key-only）。
// KeyData 固定大小，容纳所有当前 key 类型：
//   AE_PROCESS_PAIR_KEY     = 16 字节 (2*HANDLE)
//   WKD_BEHAVIOR_KEY = 24 字节 (2*HANDLE + WKD_ASSEMBLY_TYPE + ULONG)
//
typedef struct _WKD_HASH_MAP_SNAPSHOT {
    SIZE_T KeySize;                             // 实际 key 大小（≤ WKD_HASH_MAP_MAX_KEY_SIZE）
    UCHAR KeyData[WKD_HASH_MAP_MAX_KEY_SIZE];
} WKD_HASH_MAP_SNAPSHOT, * PWKD_HASH_MAP_SNAPSHOT;

/************************************************
**              哈希映射初始化
**
**  2026-08-25 强制对称契约:
**    Reference/Dereference 必选 — 缺一即 STATUS_INVALID_PARAMETER
*     (条目值具备独立生命周期的引用计数管理基础);
**    ShouldRemove 可选 — NULL 表示移除不做存活裁决。
************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CoInitializeHashMap(
    _Out_ PWKD_HASH_MAP HashMap,
    _In_ ULONG BucketCount,
    _In_ BOOLEAN PerBucketLock,
    _In_ PFN_HASH_MAP_REFERENCE_CALLBACK Reference,
    _In_opt_ PFN_HASH_MAP_REMOVE_CALLBACK ShouldRemove,
    _In_ PFN_HASH_MAP_DEREFERENCE_CALLBACK Dereference
    );

/************************************************
**                  哈希映射清理
************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
VOID
CoFreeHashMap(
    _Inout_ PWKD_HASH_MAP HashMap
    );

/************************************************
**                  简单接口（Key 即身份标识）
**
**  适用场景：键值为 HANDLE、PID、指针等 ≤8 字节
**  的身份标识。Key 作为 PVOID 直接存入，不做拷贝。
**  KeySize 内部记为 0，比较时直接比对指针值。
************************************************/

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
CoInsertHashMap(
    _Inout_ PWKD_HASH_MAP HashMap,
    _In_ PVOID Key,
    _In_ ULONG KeySize,
    _In_ ULONG64 Value,
    _Out_opt_ PBOOLEAN AlreadyExists
    );

_IRQL_requires_max_(APC_LEVEL)
PVOID
CoLookupHashMapEntry(
    _In_ PWKD_HASH_MAP HashMap,
    _In_ PVOID Key,
    _In_ ULONG KeySize
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
CoRemoveHashMapEntry(
    _Inout_ PWKD_HASH_MAP HashMap,
    _In_ const PVOID Key,
    _In_ SIZE_T KeySize
    );

/************************************************
**              快照枚举 API
**
**  key-only 两阶段快照，逐桶共享锁遍历。
**  Buffer == NULL → 返回 ActiveEntries（无锁估算）。
**  Buffer != NULL → 逐桶加共享锁拷贝 key，返回实际写入数。
**  若返回值等于 BufferCapacity，可能因并发插入而被截断，
**  调用者应分配更大缓冲区重试。
************************************************/

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
CoCaptureHashMapSnapshot(
    _In_ const PWKD_HASH_MAP HashMap,
    _In_opt_ PWKD_HASH_MAP_SNAPSHOT Buffer,
    _Inout_ PSIZE_T BufferSize,
    _Out_opt_ PULONG Capacity
    );

/************************************************
**              枚举回调 API
**
**  逐桶共享锁遍历。回调在桶锁内调用（仅允许
**  原子操作/拷贝 key 到调用方上下文），返回
**  TRUE 继续枚举 / FALSE 提前终止。
**  用于 Clear/Shutdown 前收集 key，锁外再执行
**  删除，避免在锁内释放池内存。
************************************************/

typedef
BOOLEAN
(*PFN_HASH_MAP_ENUM_CALLBACK)(
    _In_ PVOID Key,
    _In_ ULONG KeySize,
    _In_ ULONG64 Value,
    _Inout_ PVOID Context
    );

_IRQL_requires_max_(APC_LEVEL)
VOID
CoEnumerateHashMap(
    _In_ PWKD_HASH_MAP HashMap,
    _In_ PFN_HASH_MAP_ENUM_CALLBACK Callback,
    _Inout_opt_ PVOID Context
    );
