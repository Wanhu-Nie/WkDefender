/**************************************************/
/*  WkDefender Agent — 通用哈希表                   */
/*                                                   */
/*  2026-08-25 重构：对齐驱动 CoHashMap 双模式锁     */
/*  （PerBucketLock）与 ref/deref 强制对称契约。      */
/*    - key = PVOID + KeySize（任意字节内存）         */
/*    - 哈希/拷贝/比较统一表内完成，无 HashFn/       */
/*      MatchFn 注入                                 */
/*    - 通用哈希：≤8 字节整数 / FNV-1a + 长度混入     */
/*      + fmix64 雪崩（移植驱动 CopHashKey）          */
/*    - SRWLOCK 桶级锁数组（PerBucketLock=TRUE）或    */
/*      单把全局锁（PerBucketLock=FALSE）             */
/*    - Reference/Dereference 强制成对（Use-     */
/*      RefCallbacks=TRUE 时非 NULL 校验）；Should-   */
/*      RemoveFn 始终可选                            */
/*                                                   */
/*  本表只管理 Value 指针与回调契约。Dereference    */
/*  仅做引用计数 -1（原子），对象本体的真正释放由     */
/*  调用方在 teardown 路径手动完成（对齐驱动          */
/*  CoFreeHashMap 不清引用语义），避免双释放。        */
/**************************************************/

#pragma once

#include <windows.h>

/**************************************************/
/*               回调类型                           */
/**************************************************/

/* 查找命中 / 插入新条目回调（共享/独占锁内调用）：
 * pin Value，防并发摘除 UAF。本项目模块表/PidMap/
 * PairMap 语义：命中或入表时 RefCount++（pin），
 * 调用方随后释放。锁内仅允许原子操作（如
 * InterlockedIncrement）。 */
typedef
VOID
(*PFN_HASH_MAP_REFERENCE)(
    _In_ PVOID Value
    );

/* 移除裁决回调（独占锁内调用）：返回 TRUE=允许移除。
 * 只允许原子/纯读操作。可选（ShouldRemove）。 */
typedef
BOOLEAN
(*PFN_HASH_MAP_SHOULD_REMOVE)(
    _In_ PVOID Value
    );

/* 摘除回调（独占锁内调用）：释放 Value 引用（-1），
 * 与 Reference 配对。本项目约定：回调仅做原子
 * RefCount--，不释放对象本体；真正 free() 由调用方
 * 在 teardown 路径（如 PairManager_Cleanup /
 * PtTreeCleanup / PsDereferenceWkdModule）手动完成。
 * 锁内仅允许原子操作。 */
typedef
VOID
(*PFN_HASH_MAP_DEREFERENCE)(
    _In_ PVOID Value
    );

/**************************************************/
/*               结构体定义                         */
/**************************************************/

typedef struct _WKD_HASH_MAP_ENTRY {
    LIST_ENTRY ListEntry;     /* 桶内冲突链 */
    PVOID      Key;           /* 表内 key 副本（HeapAlloc，插入拷贝/摘除释放） */
    SIZE_T     KeySize;       /* key 字节数 */
    PVOID      Value;         /* 调用方对象（定长指针） */
} WKD_HASH_MAP_ENTRY, *PWKD_HASH_MAP_ENTRY;

/* 桶头：PerBucketLock=TRUE 时每桶一把独立 SRWLOCK，
 * 并发粒度细化到单桶；FALSE 时仅用 GlobalLock。 */
typedef struct _WKD_HASH_MAP_BUCKET {
    SRWLOCK    Lock;          /* 桶级读写锁（PerBucketLock=TRUE 使用） */
    LIST_ENTRY ListHead;      /* 桶内冲突链头 */
} WKD_HASH_MAP_BUCKET, *PWKD_HASH_MAP_BUCKET;

typedef struct _WKD_HASH_MAP {
    PWKD_HASH_MAP_BUCKET Buckets;   /* 桶数组（HeapAlloc，含锁+链头） */
    ULONG               BucketCount;
    ULONG               MaxEntries; /* 容量配额（插入超限 QUOTA_EXCEEDED） */
    volatile ULONG      ActiveEntries;
    volatile ULONG      TotalEntries;
    BOOLEAN             Initialized;
    BOOLEAN             PerBucketLock;   /* TRUE=桶级锁, FALSE=全局锁 */
    BOOLEAN             UseRefCallbacks; /* TRUE=强制 Reference+Deref 成对 */
    SRWLOCK             GlobalLock;      /* 全局单锁（PerBucketLock=FALSE 时使用） */

    /* 回调契约：Reference/Dereference 在 UseRefCallbacks
     * 下强制成对非 NULL；ShouldRemove 始终可选。 */
    PFN_HASH_MAP_REFERENCE     Reference;     /* 查找/插入命中 pin */
    PFN_HASH_MAP_SHOULD_REMOVE ShouldRemove;  /* 移除裁决（可选） */
    PFN_HASH_MAP_DEREFERENCE   Dereference;   /* 摘除解引（仅 -1） */
} WKD_HASH_MAP, *PWKD_HASH_MAP;

/**************************************************/
/*               函数声明                           */
/**************************************************/

/**************************************************/
/*                      初始化                       */
/**************************************************/
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
    );

VOID
CoHashMapClear(
    _Inout_ PWKD_HASH_MAP Map
    );

/* 查找：key 字节等值（表内统一比较），命中时调用
 * Reference pin 后返回（UseRefCallbacks 下）。
 * 未命中返回 NULL。调用方负责释放 pin 后解引。 */
PVOID
CoLookupHashMapEntry(
    _In_ PWKD_HASH_MAP HashMap,
    _In_ const PVOID Key,
    _In_ SIZE_T KeySize
    );

/* 插入：key 字节等值已存在返回 COLLISION（不重复插入），
 * 否则入桶并返回 SUCCESS（UseRefCallbacks 下 +1）。
 * 配额取则返回 QUOTA_EXCEEDED。 */
NTSTATUS
CoInsertHashMapEntry(
    _Inout_ PWKD_HASH_MAP HashMap,
    _In_ const PVOID Key,
    _In_ SIZE_T KeySize,
    _In_ const PVOID Value
    );

/* 移除：key 字节等值命中 → ShouldRemove 裁决 →
 * 摘除并调 Dereference（UseRefCallbacks 下 -1）。
 * 返回 TRUE=移除，FALSE=未找到或被裁决取消。 */
BOOLEAN
CoRemoveHashMapEntry(
    _Inout_ PWKD_HASH_MAP HashMap,
    _In_ const PVOID Key,
    _In_ SIZE_T KeySize
    );

/* 全表枚举（供清理/统计）。回调在锁内（逐桶共享锁），
 * 仅原子/拷贝操作。返回 FALSE 提前终止。 */
typedef
BOOLEAN
(*PFN_HASH_MAP_ENUM)(
    _In_     PVOID Key,
    _In_     SIZE_T KeySize,
    _In_     PVOID Value,
    _Inout_  PVOID Context
    );

VOID
CoHashMapEnumerate(
    _In_ PWKD_HASH_MAP Map,
    _In_ PFN_HASH_MAP_ENUM Callback,
    _Inout_opt_ PVOID Context
    );
