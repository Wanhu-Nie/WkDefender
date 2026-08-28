#pragma once

#include "../Common/Constants.h"

//
// 函数声明
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ShRegisterEtwCallback(
    _In_opt_ ULONG LoggerId
    );

//
// 高性能计数器挂钩（PASSIVE_LEVEL 安全）
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONGLONG
ShHalPerfCounterHook(
    _In_opt_ PVOID Context
    );

//
// 初始化高性能计数器挂钩
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShInitializePerfCounterHook(
    VOID
    );

//
// 清理高性能计数器挂钩
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShCleanupPerfCounterHook(
    VOID
    );

//
// 获取 KeSetTracepoint 中 KiDynamicTraceMask 的偏移量
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG64
ShGetDynamicTraceMask(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
PVOID
ScTrampolineCallback(
    VOID
    );