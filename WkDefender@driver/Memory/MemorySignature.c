#include "MemorySignature.h"
#include "../Common/Utils.h"

#define WKD_MEMORY_SIGNATURE_POOL 'MsPo'
#define WKD_SIGNATURE_NAME_POOL 'wksn'

//
// 模块说明：内存签名生命周期管理
// 主要功能：
//   1. 统一管理所有内存签名的注册和注销
//   2. 自动处理签名的预编译和资源分配
//   3. 支持一次性签名和持久化签名的分类管理
//   4. 提供签名查询和批量清理功能
//
// 注意：本模块与 MemoryScan 模块解耦，专注于签名管理
//       MemoryScan 模块负责实际的扫描逻辑
//

//
// 全局签名管理器实例
//

static WKD_SIGNATURE_MANAGER g_SignatureManager = { 0 };
static BOOLEAN g_ManagerInitialized = FALSE;

#define WKD_MEMORY_MATCH_PATTERN_POOL 'mmpp'

//
// 内部辅助函数：释放预编译的特征码资源
// 仅由签名管理器内部调用，不对外暴露
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
MspFreePrecompiledPattern(
    _Inout_ PWKD_MEMORY_SIGNATURE Signature
    );

//
// 预编译特征码模式
// 将Pattern中的精确匹配字节提取出来，构建高效匹配结构
// 应在初始化时调用一次，后续扫描可重复使用
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsPrecompileSignature(
    _Inout_ PWKD_MEMORY_SIGNATURE Signature
    )
{
    ULONG exactCount = 0;
    PUCHAR exactPattern = NULL;
    PUCHAR exactPositions = NULL;

    if (!Signature || Signature->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // 如果已经预编译过，先清理旧资源
    if (Signature->IsPrecompiled) {
        MspFreePrecompiledPattern(Signature);
    }

    // 第一次遍历：统计精确匹配字节数量
    for (ULONG i = 0; i < Signature->Length; i++) {
        if (Signature->Mask[i] == 0xFF) {
            exactCount++;
        }
    }

    // 如果没有精确匹配字节，无法优化
    if (exactCount == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Pattern has no exact bytes, cannot optimize\n");
        Signature->IsPrecompiled = FALSE;
        return STATUS_SUCCESS;
    }

    /* __try { */
        // 分配精确匹配字节数组
        exactPattern = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            exactCount,
            WKD_MEMORY_MATCH_PATTERN_POOL
        );
        if (!exactPattern) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // 分配位置索引数组
        exactPositions = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            exactCount,
            WKD_MEMORY_MATCH_PATTERN_POOL
        );
        if (!exactPositions) {
            ExFreePoolWithTag(exactPattern, WKD_MEMORY_MATCH_PATTERN_POOL);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // 第二次遍历：提取精确匹配字节及其位置
        ULONG idx = 0;
        BOOLEAN firstByteFound = FALSE;
        UCHAR firstByteValue = 0;
        
        for (ULONG i = 0; i < Signature->Length; i++) {
            if (Signature->Mask[i] == 0xFF) {
                exactPattern[idx] = Signature->Pattern[i];
                exactPositions[idx] = (UCHAR)i;
                
                // 记录第一个精确字节（用于快速过滤）
                if (!firstByteFound) {
                    firstByteValue = Signature->Pattern[i];
                    firstByteFound = TRUE;
                }
                
                idx++;
            }
        }

        // 更新Signature结构
        Signature->ExactPattern = exactPattern;
        Signature->ExactPositions = exactPositions;
        Signature->ExactCount = exactCount;
        Signature->IsPrecompiled = TRUE;
        
        // 设置快速过滤字段
        Signature->FirstExactByte = firstByteValue;
        Signature->HasFirstByte = firstByteFound;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WkDefender] Pattern precompiled: %lu exact bytes out of %lu total, first byte=0x%02X\n",
            exactCount, Signature->Length, firstByteValue);

        return STATUS_SUCCESS;
    /* }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (exactPattern) {
            ExFreePoolWithTag(exactPattern, WKD_MEMORY_MATCH_PATTERN_POOL);
        }
        if (exactPositions) {
            ExFreePoolWithTag(exactPositions, WKD_MEMORY_MATCH_PATTERN_POOL);
        }
        return STATUS_UNSUCCESSFUL;
    } */
}

//
// 清理预编译的特征码资源（内部辅助函数）
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
MspFreePrecompiledPattern(
    _Inout_ PWKD_MEMORY_SIGNATURE Signature
    )
{
    if (!Signature || !Signature->IsPrecompiled) {
        return;
    }

    if (Signature->ExactPattern) {
        ExFreePoolWithTag(Signature->ExactPattern, WKD_MEMORY_MATCH_PATTERN_POOL);
        Signature->ExactPattern = NULL;
    }

    if (Signature->ExactPositions) {
        ExFreePoolWithTag(Signature->ExactPositions, WKD_MEMORY_MATCH_PATTERN_POOL);
        Signature->ExactPositions = NULL;
    }

    Signature->ExactCount = 0;
    Signature->IsPrecompiled = FALSE;
}

//
// 初始化签名管理器
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsInitialize(
    VOID
    )
{
    if (g_ManagerInitialized) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Signature manager already initialized\n");
        return STATUS_SUCCESS;
    }

    // 初始化链表
    InitializeListHead(&g_SignatureManager.SignatureList);

    // 初始化自旋锁
    KeInitializeSpinLock(&g_SignatureManager.Lock);

    // 初始化计数器
    g_SignatureManager.NextSignatureId = 1;
    g_SignatureManager.TotalSignatures = 0;
    g_SignatureManager.PersistentCount = 0;
    g_SignatureManager.TemporaryCount = 0;

    g_ManagerInitialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Signature manager initialized successfully\n");

    return STATUS_SUCCESS;
}

//
// 清理签名管理器（内部辅助函数）
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
MspCleanupManagerInternal(
    VOID
    )
{
    PLIST_ENTRY currentEntry;
    PWKD_MEMORY_SIGNATURE_EX signatureInfo;

    if (!g_ManagerInitialized) {
        return;
    }

    // 遍历并清理所有签名
    while (!IsListEmpty(&g_SignatureManager.SignatureList)) {
        currentEntry = RemoveHeadList(&g_SignatureManager.SignatureList);
        signatureInfo = CONTAINING_RECORD(currentEntry, WKD_MEMORY_SIGNATURE_EX, ListEntry);

        // 释放预编译资源（通过统一的内部函数）
        MspFreePrecompiledPattern(&signatureInfo->Core);

        // 释放签名信息结构（Pattern 和 Mask 已内联到 Core 中，无需单独释放）
        ExFreePoolWithTag(signatureInfo, WKD_MEMORY_SIGNATURE_POOL);
    }

    // 重置管理器状态
    g_SignatureManager.NextSignatureId = 1;
    g_SignatureManager.TotalSignatures = 0;
    g_SignatureManager.PersistentCount = 0;
    g_SignatureManager.TemporaryCount = 0;
    g_ManagerInitialized = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Signature manager cleaned up\n");
}

//
// 清理签名管理器
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MsCleanup(
    VOID
    )
{
    KIRQL oldIrql;

    // 获取锁保护
    KeAcquireSpinLock(&g_SignatureManager.Lock, &oldIrql);

    MspCleanupManagerInternal();

    KeReleaseSpinLock(&g_SignatureManager.Lock, oldIrql);
}

//
// 注册新的内存签名
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsRegisterSignature(
    _In_ PWKD_MEMORY_SIGNATURE_DEFINE SignatureDefine,
    _In_ WKD_SIGNATURE_TYPE Type,
    _Out_ PWKD_MEMORY_SIGNATURE* Signature
    )
{
    PWKD_MEMORY_SIGNATURE_EX signatureInfo = NULL;
    SIZE_T nameLen;
    NTSTATUS status;
    KIRQL oldIrql;

    // 参数验证
    if (!(SignatureDefine && SignatureDefine->Name && SignatureDefine->Pattern && SignatureDefine->Mask &&
        SignatureDefine->Length && Signature)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_ManagerInitialized) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Signature manager not initialized\n");
        return STATUS_UNSUCCESSFUL;
    }

    /* __try { */
        // 分配签名信息结构
        signatureInfo = (PWKD_MEMORY_SIGNATURE_EX)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(WKD_MEMORY_SIGNATURE_EX),
            WKD_MEMORY_SIGNATURE_POOL
        );
        if (!signatureInfo) {
            return STATUS_NO_MEMORY;
        }

        RtlZeroMemory(signatureInfo, sizeof(WKD_MEMORY_SIGNATURE_EX));

        // 复制签名名称到 Core.Name
        nameLen = strlen(SignatureDefine->Name);
        if (nameLen >= sizeof(signatureInfo->Core.Name)) {
            nameLen = sizeof(signatureInfo->Core.Name) - 1;
        }
        RtlCopyMemory(signatureInfo->Core.Name, SignatureDefine->Name, nameLen);
        signatureInfo->Core.Name[nameLen] = '\0';

        // 初始化签名核心数据
        RtlCopyMemory(signatureInfo->Core.Pattern, SignatureDefine->Pattern, SignatureDefine->Length);
        RtlCopyMemory(signatureInfo->Core.Mask, SignatureDefine->Mask, SignatureDefine->Length);
        signatureInfo->Core.Length = SignatureDefine->Length;

        // 设置签名类型和管理信息
        signatureInfo->Type = Type;
        signatureInfo->ReferenceCount = 1;  // 初始引用计数为 1（注册者持有）
        signatureInfo->UsageCount = 0;      // 初始使用次数为 0
        KeQuerySystemTime(&signatureInfo->RegisterTime);

        // 预编译能显著提升扫描性能，即使是一次性签名也能受益
        status = MsPrecompileSignature(&signatureInfo->Core);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[WkDefender] Failed to precompile signature '%s': 0x%08X (will use fallback matching)\n",
                signatureInfo->Core.Name, status);
            // 预编译失败不影响注册，回退到原始匹配算法
        }

        // 获取锁保护链表操作
        KeAcquireSpinLock(&g_SignatureManager.Lock, &oldIrql);

        // 分配签名ID
        signatureInfo->SignatureId = g_SignatureManager.NextSignatureId++;

        // 插入链表
        InsertTailList(&g_SignatureManager.SignatureList, &signatureInfo->ListEntry);

        // 更新计数器
        g_SignatureManager.TotalSignatures++;
        if (Type == WkdMemorySignaturePersistent) {
            g_SignatureManager.PersistentCount++;
        } else {
            g_SignatureManager.TemporaryCount++;
        }

        KeReleaseSpinLock(&g_SignatureManager.Lock, oldIrql);

        // 返回签名指针
        *Signature = &signatureInfo->Core;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WkDefender] Registered signature '%s' (ID: %lu, Type: %s, Precompiled: %s)\n",
            signatureInfo->Core.Name,
            signatureInfo->SignatureId,
            Type == WkdMemorySignaturePersistent ? "Persistent" : "Temporary",
            signatureInfo->Core.IsPrecompiled ? "Yes" : "No");

        return STATUS_SUCCESS;
    /* }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Exception registering signature: 0x%08X\n",
            GetExceptionCode());

        if (signatureInfo) {
            ExFreePoolWithTag(signatureInfo, WKD_MEMORY_SIGNATURE_POOL);
        }

        return STATUS_UNSUCCESSFUL;
    } */
}

//
// 注销指定的内存签名
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsUnregisterSignature(
    _In_ PWKD_MEMORY_SIGNATURE Signature
    )
{
    PLIST_ENTRY currentEntry;
    PWKD_MEMORY_SIGNATURE_EX signatureInfo = NULL;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    if (!Signature || !g_ManagerInitialized) {
        return STATUS_INVALID_PARAMETER;
    }

    // 获取锁保护
    KeAcquireSpinLock(&g_SignatureManager.Lock, &oldIrql);

    // 遍历链表查找签名
    currentEntry = g_SignatureManager.SignatureList.Flink;
    while (currentEntry != &g_SignatureManager.SignatureList) {
        signatureInfo = CONTAINING_RECORD(currentEntry, WKD_MEMORY_SIGNATURE_EX, ListEntry);

        if (&signatureInfo->Core == Signature) {
            found = TRUE;
            break;
        }

        currentEntry = currentEntry->Flink;
    }

    if (!found) {
        KeReleaseSpinLock(&g_SignatureManager.Lock, oldIrql);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Signature not found for unregister\n");
        return STATUS_NOT_FOUND;
    }

    // 从链表中移除
    RemoveEntryList(&signatureInfo->ListEntry);

    // 更新计数器
    g_SignatureManager.TotalSignatures--;
    if (signatureInfo->Type == WkdMemorySignaturePersistent) {
        g_SignatureManager.PersistentCount--;
    } else {
        g_SignatureManager.TemporaryCount--;
    }

    KeReleaseSpinLock(&g_SignatureManager.Lock, oldIrql);

    // 释放预编译资源（MspFreePrecompiledPattern 内部已处理所有检查和清理）
    MspFreePrecompiledPattern(&signatureInfo->Core);

    // 释放签名信息结构（Pattern 和 Mask 已内联到 Core 中，无需单独释放）
    ExFreePoolWithTag(signatureInfo, WKD_MEMORY_SIGNATURE_POOL);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Unregistered signature '%s' (ID: %lu)\n",
        signatureInfo->Core.Name, signatureInfo->SignatureId);

    return STATUS_SUCCESS;
}

//
// 根据名称查找已注册的签名
//
_IRQL_requires_(PASSIVE_LEVEL)
PWKD_MEMORY_SIGNATURE
MsFindSignatureByName(
    _In_ PCHAR Name
    )
{
    PLIST_ENTRY currentEntry;
    PWKD_MEMORY_SIGNATURE_EX signatureInfo;
    KIRQL oldIrql;
    PWKD_MEMORY_SIGNATURE result = NULL;

    if (!Name || !g_ManagerInitialized) {
        return NULL;
    }

    // 获取锁保护
    KeAcquireSpinLock(&g_SignatureManager.Lock, &oldIrql);

    // 遍历链表查找签名
    currentEntry = g_SignatureManager.SignatureList.Flink;
    while (currentEntry != &g_SignatureManager.SignatureList) {
        signatureInfo = CONTAINING_RECORD(currentEntry, WKD_MEMORY_SIGNATURE_EX, ListEntry);

        if (_stricmp(signatureInfo->Core.Name, Name) == 0) {
            result = &signatureInfo->Core;
            break;
        }

        currentEntry = currentEntry->Flink;
    }

    KeReleaseSpinLock(&g_SignatureManager.Lock, oldIrql);

    return result;
}

//
// 根据ID查找已注册的签名
//
_IRQL_requires_(PASSIVE_LEVEL)
PWKD_MEMORY_SIGNATURE
MsFindSignatureById(
    _In_ ULONG SignatureId
    )
{
    PLIST_ENTRY currentEntry;
    PWKD_MEMORY_SIGNATURE_EX signatureInfo;
    KIRQL oldIrql;
    PWKD_MEMORY_SIGNATURE result = NULL;

    if (SignatureId == 0 || !g_ManagerInitialized) {
        return NULL;
    }

    // 获取锁保护
    KeAcquireSpinLock(&g_SignatureManager.Lock, &oldIrql);

    // 遍历链表查找签名
    currentEntry = g_SignatureManager.SignatureList.Flink;
    while (currentEntry != &g_SignatureManager.SignatureList) {
        signatureInfo = CONTAINING_RECORD(currentEntry, WKD_MEMORY_SIGNATURE_EX, ListEntry);

        if (signatureInfo->SignatureId == SignatureId) {
            result = &signatureInfo->Core;
            break;
        }

        currentEntry = currentEntry->Flink;
    }

    KeReleaseSpinLock(&g_SignatureManager.Lock, oldIrql);

    return result;
}

//
// 清理所有已注册的签名
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MsCleanupAllSignatures(
    VOID
    )
{
    MsCleanup();
}

//
// 获取签名统计信息
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MsGetStatistics(
    _Out_ PULONG TotalCount,
    _Out_ PULONG PersistentCount,
    _Out_ PULONG TemporaryCount
    )
{
    KIRQL oldIrql;

    if (!TotalCount || !PersistentCount || !TemporaryCount || !g_ManagerInitialized) {
        return;
    }

    // 获取锁保护
    KeAcquireSpinLock(&g_SignatureManager.Lock, &oldIrql);

    *TotalCount = g_SignatureManager.TotalSignatures;
    *PersistentCount = g_SignatureManager.PersistentCount;
    *TemporaryCount = g_SignatureManager.TemporaryCount;

    KeReleaseSpinLock(&g_SignatureManager.Lock, oldIrql);
}

//
// === 引用计数管理内部函数实现 ===
//

//
// 增加签名引用计数（原子操作，可在 PASSIVE_LEVEL 调用）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MspIncrementReferenceCount(
    _In_ PWKD_MEMORY_SIGNATURE Signature
    )
{
    PWKD_MEMORY_SIGNATURE_EX signatureInfo;

    if (!Signature) {
        return;
    }

    // 通过 Core 指针反推 EX 结构
    signatureInfo = CONTAINING_RECORD(Signature, WKD_MEMORY_SIGNATURE_EX, Core);

    // 原子增加引用计数
    InterlockedIncrement(&signatureInfo->ReferenceCount);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "[WkDefender] Incremented refcount for '%s': %ld\n",
        signatureInfo->Core.Name, signatureInfo->ReferenceCount);
}

//
// 减少签名引用计数（原子操作，可能在引用归零时触发清理）
// Returns:
//   TRUE  - 签名已被释放，调用者不应再访问该指针
//   FALSE - 签名仍然有效
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
MspDecrementReferenceCount(
    _In_ PWKD_MEMORY_SIGNATURE Signature
    )
{
    PWKD_MEMORY_SIGNATURE_EX signatureInfo;
    LONG newRefCount;
    BOOLEAN shouldCleanup = FALSE;

    if (!Signature || !g_ManagerInitialized) {
        return FALSE;
    }

    // 通过 Core 指针反推 EX 结构
    signatureInfo = CONTAINING_RECORD(Signature, WKD_MEMORY_SIGNATURE_EX, Core);

    // 原子减少引用计数
    newRefCount = InterlockedDecrement(&signatureInfo->ReferenceCount);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "[WkDefender] Decremented refcount for '%s': %ld\n",
        signatureInfo->Core.Name, newRefCount);

    // 如果引用计数归零且是临时签名，标记为需要清理
    if (newRefCount == 0 && signatureInfo->Type == WkdMemorySignatureTemporary) {
        shouldCleanup = TRUE;
    }

    // 如果需要清理，不能在 PASSIVE_LEVEL 执行（需要 PASSIVE_LEVEL）
    // 这里只返回状态，由调用者决定如何处理
    return shouldCleanup;
}

//
// 记录签名使用（更新使用统计）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MspRecordUsage(
    _In_ PWKD_MEMORY_SIGNATURE Signature
    )
{
    PWKD_MEMORY_SIGNATURE_EX signatureInfo;

    if (!Signature) {
        return;
    }

    // 通过 Core 指针反推 EX 结构
    signatureInfo = CONTAINING_RECORD(Signature, WKD_MEMORY_SIGNATURE_EX, Core);

    // 原子增加使用次数
    InterlockedIncrement(&signatureInfo->UsageCount);

    // 更新最后使用时间
    KeQuerySystemTime(&signatureInfo->LastUsedTime);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "[WkDefender] Recorded usage for '%s': UsageCount=%ld\n",
        signatureInfo->Core.Name, signatureInfo->UsageCount);
}

//
// 内部辅助函数：实际执行签名清理（必须在 PASSIVE_LEVEL 调用）
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
MspPerformCleanup(
    _In_ PWKD_MEMORY_SIGNATURE_EX SignatureInfo
    )
{
    if (!SignatureInfo) {
        return;
    }

    // 从链表中移除（需要锁保护）
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_SignatureManager.Lock, &oldIrql);
    RemoveEntryList(&SignatureInfo->ListEntry);

    // 更新计数器
    g_SignatureManager.TotalSignatures--;
    if (SignatureInfo->Type == WkdMemorySignaturePersistent) {
        g_SignatureManager.PersistentCount--;
    } else {
        g_SignatureManager.TemporaryCount--;
    }
    KeReleaseSpinLock(&g_SignatureManager.Lock, oldIrql);

    // 释放预编译资源
    MspFreePrecompiledPattern(&SignatureInfo->Core);

    // 释放签名信息结构
    ExFreePoolWithTag(SignatureInfo, WKD_MEMORY_SIGNATURE_POOL);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Cleaned up signature (RefCount=0)\n");
}

//
// 标记签名为"已使用"（公开 API）
// 对于临时签名，首次调用此函数后将自动释放该签名
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MsMarkSignatureAsUsed(
    _In_ PWKD_MEMORY_SIGNATURE Signature
    )
{
    PWKD_MEMORY_SIGNATURE_EX signatureInfo;
    BOOLEAN needCleanup;

    if (!Signature || !g_ManagerInitialized) {
        return STATUS_INVALID_PARAMETER;
    }

    // 通过 Core 指针反推 EX 结构
    signatureInfo = CONTAINING_RECORD(Signature, WKD_MEMORY_SIGNATURE_EX, Core);

    // 记录使用
    MspRecordUsage(Signature);

    // 减少引用计数（注册时初始为1，使用后减为0）
    needCleanup = MspDecrementReferenceCount(Signature);

    // 如果需要清理且是临时签名，执行清理
    if (needCleanup && signatureInfo->Type == WkdMemorySignatureTemporary) {
        MspPerformCleanup(signatureInfo);
        
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WkDefender] Auto-cleaned temporary signature '%s' after first use\n",
            signatureInfo->Core.Name);
    }

    return STATUS_SUCCESS;
}

