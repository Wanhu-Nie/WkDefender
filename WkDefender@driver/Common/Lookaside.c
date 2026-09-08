/*++
    Common/Lookaside.c - 通用类型安全 Lookaside 池实现（分页 / 非分页）

    Copyright (c) WkDefender Team
--*/

#include "Lookaside.h"
#include "ExportParser.h"   /* pfnExFreeToPagedLookasideList / pfnExFreeToNPagedLookasideList */

/* ============================================================================
 * Lookaside 初始化
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
CoInitializeLookaside(
    _Out_ PWKD_LOOKASIDE Lookaside,
    _In_ SIZE_T ElementSize,
    _In_ ULONG PoolTag,
    _In_ WKD_LOOKASIDE_TYPE Type
    )
{
    if (!Lookaside || ElementSize == 0 || Type >= WkdLookasideUnknown) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Lookaside, sizeof(WKD_LOOKASIDE));

    Lookaside->Type = Type;
    Lookaside->ElementSize = ElementSize;
    Lookaside->PoolTag = PoolTag;

    switch (Type) {
    case WkdLookasidePaged:
        /*
         * 分页池：分配标志 = POOL_RAISE_IF_ALLOCATION_FAILURE（分配失败时 Raise）。
         * depth 固定为 0 = 系统默认。
         * 分页 lookaside 只能在 PASSIVE/APC_LEVEL 使用。
         */
        ExInitializePagedLookasideList(
            &Lookaside->List.PagedList,
            NULL,       // Allocate 使用默认（ExAllocatePoolWithTag）
            NULL,       // Free 使用默认（ExFreePoolWithTag）
            POOL_RAISE_IF_ALLOCATION_FAILURE,
            ElementSize,
            PoolTag,
            0
        );
        break;

    case WkdLookasideNonPaged:
    default:
        /*
         * 非分页池：分配标志 = POOL_RAISE_IF_ALLOCATION_FAILURE | POOL_NX_ALLOCATION
         * （分配失败时 Raise + 要求不可执行内存）。
         * depth 固定为 0 = 系统默认。
         * 非分页 lookaside 可 <= DISPATCH_LEVEL 使用。
         */
        ExInitializeNPagedLookasideList(
            &Lookaside->List.NPagedList,
            NULL,       // Allocate 使用默认（ExAllocatePoolWithTag）
            NULL,       // Free 使用默认（ExFreePoolWithTag）
            POOL_RAISE_IF_ALLOCATION_FAILURE | POOL_NX_ALLOCATION,
            ElementSize,
            PoolTag,
            0
        );
        break;
    }

    return STATUS_SUCCESS;
}

/* ============================================================================
 * Lookaside 销毁
 * ============================================================================ */

_Use_decl_annotations_
VOID
CoDeleteLookaside(
    _Inout_ PWKD_LOOKASIDE Lookaside
    )
{
    LONG leaked;

    if (!Lookaside) return;

    leaked = Lookaside->ActiveAllocated;
    if (leaked > 0) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[WkDefender] LookasideDelete: %ld elements still allocated "
            "(tag=0x%08X, size=%zu) — potential pool leak\n",
            leaked,
            Lookaside->PoolTag,
            Lookaside->ElementSize
        );
    }

    switch (Lookaside->Type) {
    case WkdLookasidePaged:
        ExDeletePagedLookasideList(&Lookaside->List.PagedList);
        break;
    case WkdLookasideNonPaged:
    default:
        ExDeleteNPagedLookasideList(&Lookaside->List.NPagedList);
        break;
    }
}

/* ============================================================================
 * 分配 / 释放
 * ============================================================================ */

_Use_decl_annotations_
PVOID
CoAllocateLookaside(
    _Inout_ PWKD_LOOKASIDE Lookaside
    )
{
    PVOID lookaside = NULL;
    LONG active;
    LONG peak;

    if (!Lookaside) return NULL;

    switch (Lookaside->Type) {
    case WkdLookasidePaged:
        /*
         * Win10 中不存在 ExAllocateFromPagedLookasideList 导出；分页 / 非分页
         * 统一经 ExAllocateFromNPagedLookasideList 分配（其内部按 Lookaside
         * 指针中的 AllocateEx 区分）。未解析成功时回退 ExAllocatePoolWithTag
         *（lookaside 初始化即用该分配器，等价，仅无缓存复用）。
         */
        if (pfnExAllocateFromNPagedLookasideList) {
            lookaside = pfnExAllocateFromNPagedLookasideList(
                            (PVOID)&Lookaside->List.PagedList);
        } else {
            lookaside = ExAllocatePoolWithTag(
                            PagedPool, Lookaside->ElementSize, Lookaside->PoolTag);
        }
        break;
    case WkdLookasideNonPaged:
    default:
        if (pfnExAllocateFromNPagedLookasideList) {
            lookaside = pfnExAllocateFromNPagedLookasideList(
                            (PVOID)&Lookaside->List.NPagedList);
        } else {
            lookaside = ExAllocatePoolWithTag(
                            NonPagedPoolNx, Lookaside->ElementSize, Lookaside->PoolTag);
        }
        break;
    }
    if (!lookaside) return NULL;
    
    //
    // 更新统计：已分配 +1，累计 +1，更新峰值
    //
    InterlockedIncrement(&Lookaside->ActiveAllocated);
    InterlockedIncrement(&Lookaside->TotalAllocated);

    do {
        active = InterlockedCompareExchange(&Lookaside->ActiveAllocated, 0, 0);
        peak = InterlockedCompareExchange(&Lookaside->PeakAllocated, 0, 0);
    } while (InterlockedCompareExchange(
                &Lookaside->PeakAllocated, active, peak) != peak);

    return lookaside;
}

_Use_decl_annotations_
VOID
WkdLookasideFree(
    _Inout_ PWKD_LOOKASIDE Lookaside,
    _In_ _Post_invalid_ PVOID Element
    )
{
    if (!Lookaside || !Element) return;

    //
    // ExFreeTo* 在当前目标 Windows 版本未导出，无法链入 IAT。
    // 经 ExportParser 特征码扫描解析所得的函数指针（pfnExFreeTo*）
    // 释放回 lookaside；未解析成功时回退为 ExFreePoolWithTag
    //（lookaside 分配的块本质即带标签池块，等价释放，仅无缓存复用）。
    //
    switch (Lookaside->Type) {
    case WkdLookasidePaged:
        if (pfnExFreeToPagedLookasideList) {
            pfnExFreeToPagedLookasideList(
                (PVOID)&Lookaside->List.PagedList, Element);
        } else {
            ExFreePoolWithTag(Element, Lookaside->PoolTag);
        }
        break;
    case WkdLookasideNonPaged:
    default:
        if (pfnExFreeToNPagedLookasideList) {
            pfnExFreeToNPagedLookasideList(
                (PVOID)&Lookaside->List.NPagedList, Element);
        } else {
            ExFreePoolWithTag(Element, Lookaside->PoolTag);
        }
        break;
    }

    InterlockedDecrement(&Lookaside->ActiveAllocated);
}

/* ============================================================================
 * 诊断统计
 * ============================================================================ */

_Use_decl_annotations_
LONG
WkdLookasideGetActiveAllocated(
    const PWKD_LOOKASIDE Lookaside
    )
{
    NT_ASSERT(Lookaside != NULL);
    return Lookaside->ActiveAllocated;
}

_Use_decl_annotations_
VOID
WkdLookasideResetStats(
    PWKD_LOOKASIDE Lookaside
    )
{
    NT_ASSERT(Lookaside != NULL);
    InterlockedExchange(&Lookaside->TotalAllocated, 0);
    InterlockedExchange(&Lookaside->PeakAllocated, 0);
}
