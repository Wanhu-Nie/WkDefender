#pragma once

#include "Constants.h"
#include "HashSet.h"

//
// 全局变量：缓存 DriverObject 用于模块遍历
// 定义（extern 声明 + Utils.c 中的唯一定义）——避免多个 TU include 造成
// 多重定义链接错误。
//
extern PDRIVER_OBJECT WkdDriverObject;

//
// 字符串操作函数
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdStringContains(
    _In_ PUNICODE_STRING Source,
    _In_ PUNICODE_STRING Pattern
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdStringStartsWith(
    _In_ PUNICODE_STRING Source,
    _In_ PUNICODE_STRING Prefix
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdStringEndsWith(
    _In_ PUNICODE_STRING Source,
    _In_ PUNICODE_STRING Suffix
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdStringToLower(
    _Inout_ PUNICODE_STRING Str
    );



//
// 进程判断函数
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdIsSystemProcess(
    _In_ HANDLE ProcessId
);

//
// 路径归一化函数
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CoNormalizeDosPath(
    _In_     PCUNICODE_STRING  RawPath,
    _Outptr_ PUNICODE_STRING* NormalizedPath
    );

//
// UNICODE_STRING 工具（适配通用 hash set）
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
UtHashUnicodeString(
    _In_ PVOID Element
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
CoFreeUnicodeStringElement(
    _In_ ULONG64 Element,
    _In_opt_ PVOID Context
    );

//
// 安全验证函数
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdValidateSignature(
    _In_ PUNICODE_STRING FilePath
    );

_IRQL_requires_(PASSIVE_LEVEL)
ULONG
WkdCalculateEntropy(
    _In_ PVOID Buffer,
    _In_ ULONG Size
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdBase64Decode(
    _In_ PUNICODE_STRING Encoded,
    _Out_ PVOID* Decoded,
    _Out_ PULONG DecodedSize
    );

//
// 内存操作函数
//
_IRQL_requires_(PASSIVE_LEVEL)
PVOID
WkdAllocatePoolWithTag(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T Size,
    _In_ ULONG Tag
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdFreePoolWithTag(
    _In_ PVOID Buffer,
    _In_ ULONG Tag
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdReadProcessMemory(
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CoCopyUnicodeString(
    _Out_ PUNICODE_STRING* Dst,
    _In_ PCUNICODE_STRING Src
    );

//
// 内核模块相关函数
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CoRecordWkdDriverObject(
    _In_ const PDRIVER_OBJECT DriverObject
    );

_IRQL_requires_(PASSIVE_LEVEL)
PVOID
UtGetNtoskrnlBase(
    VOID
    );

//
// Windows 版本检测函数
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
UtGetWindowsBuildNumber(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdIsWindows11OrLater(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
WkdIsWindows10Version2004OrLater(
    VOID
    );


//
// 获取内核模块基地址函数
//
_IRQL_requires_(PASSIVE_LEVEL)
PVOID
UtGetKernelModuleBase(
    _In_ PCWSTR ModuleName
    );


//
// 获取当前线程的系统调用号
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
UtGetCurrentThreadSyscallNumber(
    VOID
    );

//
// 获取当前线程的系统调用号
//
_IRQL_requires_(PASSIVE_LEVEL)
PKTRAP_FRAME
UtGetCurrentThreadTrapFrame(
    VOID
    );

//
// EX_PUSH_LOCK 安全包装
//
// ExAcquirePushLockExclusive/Shared 必须在 APC_LEVEL 下调用，
// 否则如果持有锁期间发生 APC 中断导致死锁。
// KeEnterCriticalRegion 将 IRQL 提升到 APC_LEVEL，禁止普通 APC 传递。
//
_IRQL_requires_(PASSIVE_LEVEL)
FORCEINLINE
VOID
WkdAcquirePushLockExclusive(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(Lock);
}

_IRQL_requires_(APC_LEVEL)
FORCEINLINE
VOID
WkdReleasePushLockExclusive(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    ExReleasePushLockExclusive(Lock);
    KeLeaveCriticalRegion();
}

_IRQL_requires_(PASSIVE_LEVEL)
FORCEINLINE
VOID
WkdAcquirePushLockShared(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(Lock);
}

_IRQL_requires_(APC_LEVEL)
FORCEINLINE
VOID
WkdReleasePushLockShared(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    ExReleasePushLockShared(Lock);
    KeLeaveCriticalRegion();
}

//
// 推锁升级：释放共享 → 获取排他。
// 调用者在获取排他锁后必须 double-check 原条件，
// 窗口期内其他线程可能已修改状态。
//
_IRQL_requires_(PASSIVE_LEVEL)
FORCEINLINE
VOID
WkdSharedToExclusive(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    WkdReleasePushLockShared(Lock);
    WkdAcquirePushLockExclusive(Lock);
}

//
// 推锁降级：释放排他 → 获取共享。
//
_IRQL_requires_(PASSIVE_LEVEL)
FORCEINLINE
VOID
WkdExclusiveToShared(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    WkdReleasePushLockExclusive(Lock);
    WkdAcquirePushLockShared(Lock);
}

// 从路径中提取 basename（最后一个分隔符之后，零拷贝）
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
CoGetBasenameFromPath(
    _In_ PCUNICODE_STRING Path,
    _Out_ PUNICODE_STRING FileName
    );

FORCEINLINE
BOOLEAN
CoCheckStringValidity(_In_ PCWSTR String) {
    if (!String || String[0] == L'\0') return FALSE;
    else return TRUE;
};

FORCEINLINE
BOOLEAN
CoCheckUnicodeStringValidity(_In_ PCUNICODE_STRING String) {
    if (!String || !String->Buffer || String->Length == 0) return FALSE;
    else return TRUE;
    };

/* ============================================================================
 * 内核代码安全读取
 * ============================================================================ */

 //
 // 安全读取内核代码到本地缓冲区
 // 运行环境: PASSIVE_LEVEL 或 APC_LEVEL
 // 拒绝用户态地址（< MmUserProbeAddress），使用 __try/__except 保护。
 //
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
CoReadKernelRegionSafe(
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ const PVOID Address,
    _In_ SIZE_T Size
    );