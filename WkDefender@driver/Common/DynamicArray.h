#pragma once

#include <ntifs.h>

/**************************************************/
/*              动态数组容器                       */
/**************************************************/

//
// 通用动态数组容器，支持固定长度元素的追加和随机访问。
// 扩容策略: 首次分配4个元素，之后每次倍增。
// 所有操作均在 PASSIVE_LEVEL 下进行，非线程安全（由调用者持锁保护）。
//

typedef struct _WKD_DYNAMIC_ARRAY {
    PVOID Data;                   // 数据缓冲区
    SIZE_T ElementSize;            // 单个元素大小（字节）
    ULONG Count;                  // 当前元素数量
    ULONG Capacity;               // 当前容量（元素数）
    POOL_TYPE PoolType;           // 内存池类型
    ULONG PoolTag;                // 内存池标签
} WKD_DYNAMIC_ARRAY, *PWKD_DYNAMIC_ARRAY;

//
// 默认配置
//
#define WKD_DA_DEFAULT_CAPACITY    16       // 初始容量
#define WKD_DA_GROWTH_FACTOR       2       // 扩容倍增因子
#define WKD_DA_MAX_CAPACITY        256     // 容量上限

/**************************************************/
/*                   函数声明                      */
/**************************************************/

//
// 初始化动态数组
//
FORCEINLINE
VOID
DaInitialize(
    _Out_ PWKD_DYNAMIC_ARRAY Array,
    _In_ SIZE_T ElementSize,
    _In_ POOL_TYPE PoolType,
    _In_ ULONG PoolTag
    )
/*++
Routine Description:
    初始化动态数组结构体，不分配数据缓冲区（首次 Append 时懒分配）。

Arguments:
    Array       — 数组指针。
    ElementSize — 每个元素的字节大小。
    PoolType    — 内存池类型（通常 POOL_FLAG_NON_PAGED）。
    PoolTag     — 内存分配标签。
--*/
{
    RtlZeroMemory(Array, sizeof(WKD_DYNAMIC_ARRAY));
    Array->ElementSize = ElementSize;
    Array->PoolType = PoolType;
    Array->PoolTag = PoolTag;
}

//
// 确保容量
//
FORCEINLINE
NTSTATUS
DaEnsureCapacity(
    _Inout_ PWKD_DYNAMIC_ARRAY Array,
    _In_ ULONG RequiredCapacity
    )
/*++
Routine Description:
    确保数组至少有 RequiredCapacity 个元素的容量。
    如果需要扩容，按倍增策略分配新缓冲区并拷贝旧数据。

Arguments:
    Array            — 数组指针。
    RequiredCapacity — 需要的最小元素容量。

Returns:
    STATUS_SUCCESS       — 成功。
    STATUS_NO_MEMORY     — 内存分配失败。
--*/
{
    ULONG newCapacity;
    PVOID newData;
    SIZE_T newSize;
    SIZE_T oldSize;

    if (Array->Capacity >= RequiredCapacity) {
        return STATUS_SUCCESS;
    }

    //
    // 计算新容量：不小于 RequiredCapacity，按倍增策略
    //
    newCapacity = (Array->Capacity == 0)
        ? WKD_DA_DEFAULT_CAPACITY
        : Array->Capacity;

    while (newCapacity < RequiredCapacity) {
        if (newCapacity > WKD_DA_MAX_CAPACITY / WKD_DA_GROWTH_FACTOR) {
            newCapacity = WKD_DA_MAX_CAPACITY;
            break;
        }
        newCapacity *= WKD_DA_GROWTH_FACTOR;
    }

    if (newCapacity > WKD_DA_MAX_CAPACITY) {
        newCapacity = WKD_DA_MAX_CAPACITY;
    }

    newSize = (SIZE_T)newCapacity * Array->ElementSize;
    oldSize = (SIZE_T)Array->Count * Array->ElementSize;

    newData = ExAllocatePool2(Array->PoolType, newSize, Array->PoolTag);
    if (!newData) {
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(newData, newSize);

    //
    // 拷贝旧数据
    //
    if (Array->Data && oldSize > 0) {
        RtlCopyMemory(newData, Array->Data, oldSize);
        ExFreePoolWithTag(Array->Data, Array->PoolTag);
    }

    Array->Data = newData;
    Array->Capacity = newCapacity;
    return STATUS_SUCCESS;
}

//
// 追加元素
//
FORCEINLINE
NTSTATUS
DaAppend(
    _Inout_ PWKD_DYNAMIC_ARRAY Array,
    _In_ PVOID Element
    )
/*++
Routine Description:
    在数组末尾追加一个元素。元素数据通过指针传入，内部拷贝。
    如果容量不足，自动扩容。

Arguments:
    Array   — 数组指针。
    Element — 要追加的元素数据指针。

Returns:
    STATUS_SUCCESS       — 成功。
    STATUS_NO_MEMORY     — 扩容失败。
    STATUS_BUFFER_TOO_SMALL — 已达容量上限。
--*/
{
    NTSTATUS status;
    PUCHAR dest;

    if (!Array || !Element || !Array->ElementSize) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Array->Count >= WKD_DA_MAX_CAPACITY) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = DaEnsureCapacity(Array, Array->Count + 1);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    dest = (PUCHAR)Array->Data + ((SIZE_T)Array->Count * Array->ElementSize);
    RtlCopyMemory(dest, Element, Array->ElementSize);
    Array->Count++;

    return STATUS_SUCCESS;
}

//
// 获取元素指针
//
FORCEINLINE
PVOID
DaGetElement(
    _In_ PWKD_DYNAMIC_ARRAY Array,
    _In_ ULONG Index
    )
/*++
Routine Description:
    返回指定索引处元素的指针。调用者不应持有此指针跨锁使用。

Arguments:
    Array — 数组指针。
    Index — 0-based 索引。

Returns:
    元素指针，或 NULL（索引越界）。
--*/
{
    if (!Array || !Array->Data || Index >= Array->Count) {
        return NULL;
    }

    return (PUCHAR)Array->Data + ((SIZE_T)Index * Array->ElementSize);
}

//
// 清空数组（保留容量）
//
FORCEINLINE
VOID
DaClear(
    _Inout_ PWKD_DYNAMIC_ARRAY Array
    )
/*++
Routine Description:
    重置 Count 为 0，不释放缓冲区（保留已分配的容量）。
--*/
{
    if (Array) {
        Array->Count = 0;
    }
}

//
// 销毁数组（释放缓冲区）
//
FORCEINLINE
VOID
DaDestroy(
    _Inout_ PWKD_DYNAMIC_ARRAY Array
    )
/*++
Routine Description:
    释放数据缓冲区并重置所有字段。
--*/
{
    if (Array) {
        if (Array->Data) {
            ExFreePoolWithTag(Array->Data, Array->PoolTag);
        }
        RtlZeroMemory(Array, sizeof(WKD_DYNAMIC_ARRAY));
    }
}
