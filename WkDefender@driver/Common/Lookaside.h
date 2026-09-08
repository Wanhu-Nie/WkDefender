/*++
    Common/Lookaside.h - 通用类型安全 Lookaside 池封装（分页 / 非分页）

    Purpose:
        消除 NPAGED_LOOKASIDE_LIST / PAGED_LOOKASIDE_LIST
        初始化/分配/释放的样板代码，提供编译期类型安全和统一的生命周期管理。
        所有 SelfProtection 及其它模块的固定大小对象池化均通过此层完成。

    Design:
        WKD_LOOKASIDE 是薄封装层，持有 NPAGED_LOOKASIDE_LIST 或
        PAGED_LOOKASIDE_LIST（union）+ 类型/元数据。
        WKD_LOOKASIDE_DECLARE 宏为指定类型生成类型安全的分配/释放函数。

        内存类型由 CoInitializeLookaside 的 Type 参数决定（depth 固定为 0 =
        系统默认），分配标志自动推导：
          - WkdLookasideNonPaged：非分页，分配标志 = POOL_RAISE_IF_ALLOCATION_FAILURE | POOL_NX_ALLOCATION
          - WkdLookasidePaged   ：分页，   分配标志 = POOL_RAISE_IF_ALLOCATION_FAILURE

        注意 IRQL 约束：
          - 分页 lookaside 的分配/释放只能在 PASSIVE_LEVEL / APC_LEVEL；
          - 非分页 lookaside 的分配/释放可在 <= DISPATCH_LEVEL 使用。

    Usage:
        // 1. 声明（在模块头文件中）
        WKD_LOOKASIDE_DECLARE(MyEntryLookaside, MY_ENTRY);

        // 2. 初始化（PASSIVE_LEVEL）— 指定内存类型
        CoInitializeLookaside(&g_MyEntryLookaside, sizeof(MY_ENTRY), PoolTag_MyE, WkdLookasideNonPaged);

        // 3. 分配（非分页：<= DISPATCH_LEVEL；分页：<= APC_LEVEL）
        PMY_ENTRY p = MyEntryLookasideAllocate(&g_MyEntryLookaside);

        // 4. 释放（IRQL 约束同分配）
        MyEntryLookasideFree(&g_MyEntryLookaside, p);

        // 5. 销毁（PASSIVE_LEVEL）
        CoDeleteLookaside(&g_MyEntryLookaside);

    Copyright (c) WkDefender Team
--*/

#pragma once

#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 类型定义
 * ============================================================================ */

//
// Lookaside 内存类型
//
typedef enum _WKD_LOOKASIDE_TYPE {
    WkdLookasideNonPaged = 0,   // 非分页（NonPagedPoolNx + POOL_NX_ALLOCATION），可 <= DISPATCH_LEVEL 使用
    WkdLookasidePaged ,         // 分页（PagedPool），仅 PASSIVE/APC_LEVEL 使用
    WkdLookasideUnknown
} WKD_LOOKASIDE_TYPE, *PWKD_LOOKASIDE_TYPE;

//
// Lookaside 池描述符
//
// 注意：union List 必须位于结构体开头。内部 NPAGED_LOOKASIDE_LIST 的
// SLIST_HEADER（16 字节对齐要求）需从结构起点对齐，故置其于 offset 0。
// 结构整体按 16 字节对齐，保证嵌入其它结构（WKD_CALLBACK_PROTECTION）
// 时，只要宿主基址 16 对齐（NonPagedPoolNx 池分配即满足），NPagedList 即正确对齐。
//
typedef struct DECLSPEC_ALIGN(16) _WKD_LOOKASIDE {
    //
    // 底层 Lookaside 句柄（置于开头以保证对齐）
    //
    union {
        NPAGED_LOOKASIDE_LIST NPagedList;   // 非分页 Lookaside 句柄（别名）
        PAGED_LOOKASIDE_LIST  PagedList;    // 分页 Lookaside 句柄（别名）
    } List;

    WKD_LOOKASIDE_TYPE Type;            // 内存类型（分页 / 非分页）

    SIZE_T ElementSize;                 // 单个元素大小（字节）
    ULONG PoolTag;                      // 四字符池标签

    //
    // 诊断统计（原子操作，无锁读取）
    //
    volatile LONG ActiveAllocated;      // 当前已分配数量
    volatile LONG TotalAllocated;       // 累计分配次数
    volatile LONG PeakAllocated;        // 峰值已分配数量
} WKD_LOOKASIDE, *PWKD_LOOKASIDE;

/* ============================================================================
 * 基础 API
 * ============================================================================ */

//
// 初始化 Lookaside 池（PASSIVE_LEVEL）
//
// ElementSize: 单个元素的大小（字节），必须 > 0
// PoolTag:     四字符池标签
// Type:        内存类型（分页 / 非分页），决定底层池类型与分配标志
//
// 内部将 depth 固定为 0（系统默认），不再暴露缓存深度参数。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CoInitializeLookaside(
    _Out_ PWKD_LOOKASIDE Lookaside,
    _In_ SIZE_T ElementSize,
    _In_ ULONG PoolTag,
    _In_ WKD_LOOKASIDE_TYPE Type
    );

//
// 销毁 Lookaside 池（PASSIVE_LEVEL）
// 调用前须确保所有已分配元素已释放。
// 仍有残留元素时打印 DbgPrint 警告（Debug 构建）。
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
CoDeleteLookaside(
    _Inout_ PWKD_LOOKASIDE Lookaside
    );

//
// 分配元素
// 非分页: <= DISPATCH_LEVEL；分页: <= APC_LEVEL。
// 返回 NULL 表示分配失败（池耗尽或 Lookaside 深度已满）。
// 返回的指针内容已清零（ExAllocatePoolZero 行为）。
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
_Ret_maybenull_
PVOID
CoAllocateLookaside(
    _Inout_ PWKD_LOOKASIDE Lookaside
    );

//
// 释放元素
// 非分页: <= DISPATCH_LEVEL；分页: <= APC_LEVEL。
// Element 必须是由 CoAllocateLookaside 返回的非 NULL 指针。
// 释放后指针内容不确定，调用者不应再访问。
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdLookasideFree(
    _Inout_ PWKD_LOOKASIDE Lookaside,
    _In_ _Post_invalid_ PVOID Element
    );

//
// 获取当前已分配计数（无锁快照，诊断/统计用）
//
_IRQL_requires_max_(APC_LEVEL)
LONG
WkdLookasideGetActiveAllocated(
    _In_ const PWKD_LOOKASIDE Lookaside
    );

//
// 重置统计计数器（仅重置 TotalAllocated/PeakAllocated，不重置 ActiveAllocated）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdLookasideResetStats(
    _Inout_ PWKD_LOOKASIDE Lookaside
    );

/* ============================================================================
 * 类型安全宏封装
 *
 * 用法示例（在 .h 中声明，在 .c 中使用）：
 *
 *   // 头文件中声明
 *   WKD_LOOKASIDE_DECLARE(WkdCpEntryLookaside, WKD_CALLBACK_ENTRY);
 *
 *   // 源文件中分配
 *   PWKD_CALLBACK_ENTRY entry = WkdCpEntryLookasideAllocate(&g_EntryLookaside);
 *
 *   // 源文件中释放
 *   WkdCpEntryLookasideFree(&g_EntryLookaside, entry);
 * ============================================================================ */

#define WKD_LOOKASIDE_DECLARE(LookasideName, ElementType)                     \
                                                                                \
    static __forceinline                                                      \
    _Must_inspect_result_                                                     \
    _Ret_maybenull_                                                           \
    ElementType*                                                              \
    LookasideName##Allocate(                                                  \
        _Inout_ PWKD_LOOKASIDE L                                              \
        )                                                                     \
    {                                                                         \
        return (ElementType*)CoAllocateLookaside(L);                         \
    }                                                                         \
                                                                                \
    static __forceinline                                                      \
    VOID                                                                      \
    LookasideName##Free(                                                      \
        _Inout_ PWKD_LOOKASIDE L,                                             \
        _In_ _Post_invalid_ ElementType* E                                     \
        )                                                                     \
    {                                                                         \
        WkdLookasideFree(L, (PVOID)(E));                                      \
    }

#ifdef __cplusplus
}
#endif
