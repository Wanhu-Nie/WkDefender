/*++
    Protection/CallbackProtection.c - 回调代码完整性保护引擎实现

    Purpose:
        保护内核回调注册的代码不被篡改。
        核心流程：
        1. 注册时计算回调代码前 256 字节的 SHA-256 哈希作为基线
        2. 备份原始代码（供 MDL 恢复使用）
        3. 定期重新计算哈希并与基线比对
        4. 发现篡改时通过 MDL 映射写入备份代码进行恢复
        5. 通知注册的篡改回调和上报事件

    Synchronization Strategy:
        - CallbackListLock（EX_PUSH_LOCK）保护回调链表的插入/移除
        - 异步校验（定时器线程/回调）执行前获取注入的引擎 EX_RUNDOWN_REF
          （EngineRundown），保证访问条目期间宿主子系统存活；
          线程退出、CpShutdown 排空均以引擎 rundown 为纲
        - 条目无独立引用计数：生命周期由引擎 rundown 排空保证
        - MDL 恢复运行于 PASSIVE_LEVEL，需注意 IRQL 和分页约束

    Copyright (c) WkDefender Team
--*/

#include "CallbackProtection.h"
#include "../Common/Utils.h"   /* CoReadKernelRegionSafe */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SpInitializeCallbackProtection)
#pragma alloc_text(PAGE, SpRegisterCallbackProtection)
#pragma alloc_text(PAGE, SpStartPeriodicCallbackProtection)
#endif


/* ============================================================================
 * 内部结构体定义
 * ============================================================================ */

//
// 回调条目内部结构（扩展公开视图，附加内部管理字段）
//
typedef struct _WKD_CALLBACK_PROTECTION_ENTRY {
    LIST_ENTRY ListEntry;               // 回调链表节点（按 Type 线性索引）
    WKD_CALLBACK_TYPE Type;
    PVOID Callback;
    UCHAR CodeHash[BCRYPT_SHA256_SIZE];
    BOOLEAN IsProtected;
    BOOLEAN WasTampered;
    LARGE_INTEGER LastVerifyTime;
    ULONG VerifyCount;
    ULONG TamperCount;

    //
    // 原始代码备份（用于 MDL 恢复）
    //
    UCHAR OriginalBytes[WKD_CP_HASH_BYTES];
    SIZE_T OriginalBytesSize;
    BOOLEAN HasBackup;
} WKD_CALLBACK_PROTECTION_ENTRY, *PWKD_CALLBACK_PROTECTION_ENTRY;

//
// 保护器全局上下文（单例）
//
struct _WKD_CALLBACK_PROTECTION {
    //
    // 回调链表（LIST_ENTRY）与推锁。
    // 回调数目有限（WKD_CP_MAX_CALLBACKS），线性查找即可，无需哈希表；
    // 条目生命周期由引擎级 rundown（EngineRundown）排空保证，
    // 校验线程执行前获取 rundown，故无需条目级引用计数。
    //
    LIST_ENTRY     CallbackListHead;    // 条目链表头
    EX_PUSH_LOCK   CallbackListLock;    // 保护回调链表的推锁

    //
    // Lookaside 分配器（条目内存池）
    //
    WKD_LOOKASIDE Lookaside;

    //
    // 篡改通知回调
    //
    WKD_CP_TAMPER_CALLBACK TamperCallback;
    PVOID TamperCallbackProtection;

    //
    // 恢复回调（预留，供后续接通自动恢复流水线）
    //
    WKD_CP_RESTORE_CALLBACK RestoreCallback;
    PVOID RestoreCallbackProtection;

    //
    // 周期性验证定时器（创建迁移至 SpStartPeriodicCallbackProtection，对齐 AD/IM）
    //
    WKD_PERIODIC_TIMER PeriodicTimer;

    //
    // 自动恢复开关
    //
    BOOLEAN EnableRestoration;

    //
    // 统计
    //
    volatile LONG CallbacksProtected;
    volatile LONG TamperAttempts;
    volatile LONG CallbacksRestored;
    volatile LONG VerificationsRun;
    LARGE_INTEGER StartTime;
};

//
// Lookaside 收归各 Protection 上下文持有；回调条目统一以
// LIST_ENTRY 链接于 Protection->CallbackListHead，无条目级引用计数，
// 生命周期由引擎级 rundown 排空保证。见 SpInitializeCallbackProtection。
//

/* ============================================================================
 * 内部前向声明
 * ============================================================================ */

_IRQL_requires_max_(APC_LEVEL)
static
VOID
SppPeriodicCallbackCheck(
    _Inout_opt_ PVOID Context
    );

static
BOOLEAN
SppVerifyCallback(
    _In_ PWKD_CALLBACK_PROTECTION_ENTRY Entry
    );

static
BOOLEAN
SppRestoreCallbackViaMdl(
    _In_ PWKD_CALLBACK_PROTECTION_ENTRY Entry
    );

static
VOID
CpNotifyTamper(
    _In_ PWKD_CALLBACK_PROTECTION Protection,
    _In_ PWKD_CALLBACK_PROTECTION_ENTRY Entry,
    _In_ BOOLEAN Restored
    );

/* ============================================================================
 * 初始化 / 关闭
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
SpInitializeCallbackProtection(
    _Out_ PWKD_CALLBACK_PROTECTION* Protection
    )
{
    NTSTATUS status;
    PWKD_CALLBACK_PROTECTION protection = NULL;

    PAGED_CODE();

    if (!Protection) return STATUS_INVALID_PARAMETER;
    *Protection = NULL;

    //
    // 分配全局上下文
    //
    protection = (PWKD_CALLBACK_PROTECTION)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(WKD_CALLBACK_PROTECTION),
        WKD_CP_POOL_TAG
    );
    if (!protection) {
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }

    //
    // 初始化回调链表与推锁
    //
    InitializeListHead(&protection->CallbackListHead);
    ExInitializePushLock(&protection->CallbackListLock);

    //
    // 初始化 Lookaside（条目内存池）
    //
    status = CoInitializeLookaside(
        &protection->Lookaside,
        sizeof(WKD_CALLBACK_PROTECTION_ENTRY),
        WKD_CP_POOL_TAG_ENTRY,
        WkdLookasideNonPaged      // 回调条目需可 <= DISPATCH_LEVEL 分配/释放，使用非分页
    );
    if (!NT_SUCCESS(status)) goto Cleanup;

    //
    // 默认配置
    //
    protection->EnableRestoration = TRUE;
    KeQuerySystemTime(&protection->StartTime);

    *Protection = protection;
    return STATUS_SUCCESS;

Cleanup:
    if (protection) {
        CoDeleteLookaside(&protection->Lookaside);
        ExFreePoolWithTag(protection, WKD_CP_POOL_TAG);
    }

    return status;
}

_Use_decl_annotations_
VOID
CpShutdown(
    PWKD_CALLBACK_PROTECTION Protection
    )
{
    PAGED_CODE();

    if (Protection == NULL) {
        return;
    }

    //
    // 停止验证定时器
    //
    WkdTimerStop(&Protection->PeriodicTimer, TRUE);

    //
    // 停止验证定时器（Thread 模式，置 TerminateThread + 排空）；线程随后退出
    //
    WkdTimerStop(&Protection->PeriodicTimer, TRUE);

    //
    // 释放所有回调条目。此时引擎级 rundown 已被引擎 Shutdown 置为关闭，
    // 校验线程已退出，且引擎关闭编排在后续阶段等待排空后才调用本函数，
    // 故此处可在推锁保护下线性摘除并归还 Lookaside。
    //
    {
        PLIST_ENTRY cursor;
        while (!IsListEmpty(&Protection->CallbackListHead)) {
            cursor = RemoveHeadList(&Protection->CallbackListHead);
            WkdLookasideFree(&Protection->Lookaside, CONTAINING_RECORD(cursor, WKD_CALLBACK_PROTECTION_ENTRY, ListEntry));
        }
    }

    //
    // 销毁定时器
    //
    WkdTimerDestroy(&Protection->PeriodicTimer);

    //
    // 销毁 Lookaside
    //
    CoDeleteLookaside(&Protection->Lookaside);

    //
    // 释放上下文
    //
    ExFreePoolWithTag(Protection, WKD_CP_POOL_TAG);

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[WkDefender] CallbackProtection shut down\n"
    );
}

/* ============================================================================
 * 保护 / 取消保护
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
SpRegisterCallbackProtection(
    _Inout_ PWKD_CALLBACK_PROTECTION Protection,
    _In_ WKD_CALLBACK_TYPE Type,
    _In_ const PVOID Callback
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PWKD_CALLBACK_PROTECTION_ENTRY entry;

    PAGED_CODE();

    if (!Protection || !Callback || Type >= WkdCallback_MaxType) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 从 Lookaside 预分配条目
    //
    entry = CoAllocateLookaside(&Protection->Lookaside);
    if (!entry) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(entry, sizeof(WKD_CALLBACK_PROTECTION_ENTRY));

    //
    // 预填充条目（插入时由查重比对）
    //
    entry->Type = Type;
    entry->Callback = Callback;
    entry->IsProtected = TRUE;
    KeQuerySystemTime(&entry->LastVerifyTime);

    //
    // 计算回调代码的 SHA-256 哈希
    //
    status = CoComputeSha256(
        Callback,
        WKD_CP_HASH_BYTES,
        entry->CodeHash
    );
    if (!NT_SUCCESS(status)) goto Cleanup;

    //
    // 备份原始代码（用于 MDL 恢复）
    //
    status = CoReadKernelRegionSafe(
        entry->OriginalBytes,
        Callback,
        WKD_CP_HASH_BYTES
    );

    if (NT_SUCCESS(status)) {
        entry->OriginalBytesSize = WKD_CP_HASH_BYTES;
        entry->HasBackup = TRUE;
    } else {
        entry->HasBackup = FALSE;
        goto Cleanup;
    }

    //
    // 在推锁保护下：先查重（同 Type + 同 Callback 指针），再插入链表。
    // 回调数目有限（WKD_CP_MAX_CALLBACKS），线性查找即可。
    //
    WkdAcquirePushLockExclusive(&Protection->CallbackListLock);

    for (PLIST_ENTRY cursor = Protection->CallbackListHead.Flink;
         cursor != &Protection->CallbackListHead;
         cursor = cursor->Flink) {
        PWKD_CALLBACK_PROTECTION_ENTRY existing =
            CONTAINING_RECORD(cursor, WKD_CALLBACK_PROTECTION_ENTRY, ListEntry);

        if (existing->Type == Type && existing->Callback == (PVOID)Callback) {
            //
            // 已存在同 Type + 同 Callback 的条目，拒绝重复注册
            //
            WkdReleasePushLockExclusive(&Protection->CallbackListLock);
            WkdLookasideFree(&Protection->Lookaside, entry);
            return STATUS_OBJECT_NAME_EXISTS;
        }
    }
    InsertTailList(&Protection->CallbackListHead, &entry->ListEntry);
    WkdReleasePushLockExclusive(&Protection->CallbackListLock);

    InterlockedIncrement(&Protection->CallbacksProtected);
    return STATUS_SUCCESS;

Cleanup:
    WkdLookasideFree(&Protection->Lookaside, entry);
    return status;
}

_Use_decl_annotations_
_Must_inspect_result_
NTSTATUS
CpUnprotectCallback(
    PWKD_CALLBACK_PROTECTION Protection,
    WKD_CALLBACK_TYPE Type
    )
{
    PAGED_CODE();

    if (Protection == NULL || Type >= WkdCallback_MaxType) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockExclusive(&Protection->CallbackListLock);
    {
        PLIST_ENTRY cursor;
        for (cursor = Protection->CallbackListHead.Flink;
             cursor != &Protection->CallbackListHead;
             cursor = cursor->Flink) {

            PWKD_CALLBACK_PROTECTION_ENTRY entry =
                CONTAINING_RECORD(cursor, WKD_CALLBACK_PROTECTION_ENTRY, ListEntry);

            if (entry->Type == Type) {
                RemoveEntryList(cursor);
                ExReleasePushLockExclusive(&Protection->CallbackListLock);

                WkdLookasideFree(&Protection->Lookaside, entry);
                InterlockedDecrement(&Protection->CallbacksProtected);
                return STATUS_SUCCESS;
            }
        }
    }
    ExReleasePushLockExclusive(&Protection->CallbackListLock);

    return STATUS_NOT_FOUND;
}

/* ============================================================================
 * 篡改通知回调注册
 * ============================================================================ */

_Use_decl_annotations_
_Must_inspect_result_
NTSTATUS
CpRegisterTamperCallback(
    PWKD_CALLBACK_PROTECTION Protection,
    WKD_CP_TAMPER_CALLBACK Callback,
    PVOID CallbackProtection
    )
{
    PAGED_CODE();

    if (Protection == NULL || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Protection->TamperCallback = Callback;
    Protection->TamperCallbackProtection = CallbackProtection;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
CpUnregisterTamperCallback(
    PWKD_CALLBACK_PROTECTION Protection
    )
{
    PAGED_CODE();

    if (Protection == NULL) return;

    Protection->TamperCallback = NULL;
    Protection->TamperCallbackProtection = NULL;
}

/* ============================================================================
 * 恢复回调注册（预留）
 * ============================================================================ */

_Use_decl_annotations_
_Must_inspect_result_
NTSTATUS
CpRegisterRestoreCallback(
    PWKD_CALLBACK_PROTECTION Protection,
    WKD_CP_RESTORE_CALLBACK Callback,
    PVOID RestoreProtection
    )
{
    PAGED_CODE();

    if (Protection == NULL || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Protection->RestoreCallback = Callback;
    Protection->RestoreCallbackProtection = RestoreProtection;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
CpUnregisterRestoreCallback(
    PWKD_CALLBACK_PROTECTION Protection
    )
{
    PAGED_CODE();

    if (Protection == NULL) return;

    Protection->RestoreCallback = NULL;
    Protection->RestoreCallbackProtection = NULL;
}

/* ============================================================================
 * 周期性验证控制
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
SpStartPeriodicCallbackProtection(
    _Inout_ PWKD_CALLBACK_PROTECTION Protection,
    _In_ const PEX_RUNDOWN_REF RundownRef,
    _In_ ULONG IntervalMs
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (!Protection || !RundownRef ||
        IntervalMs < WKD_TIMER_MIN_INTERVAL_MS || IntervalMs > WKD_TIMER_MAX_INTERVAL_MS) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 对齐 AD/IM：定时器在 Start 阶段创建（而非 Init），
    // 此时引擎 rundown 已注入（EngineRundown），作为线程存活判据。
    //
    status = CoCreatePeriodicTimer(
        &Protection->PeriodicTimer,
        IntervalMs,
        SppPeriodicCallbackCheck,
        (PVOID)Protection,
        TRUE,                          // Thread 模式（PASSIVE_LEVEL）
        RundownRef
    );
    if (!NT_SUCCESS(status)) return status;

    //
    // 更新间隔并启动定时器
    //
    CoStartPeriodicTimer(&Protection->PeriodicTimer);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
_Must_inspect_result_
NTSTATUS
CpDisablePeriodicVerify(
    PWKD_CALLBACK_PROTECTION Protection
    )
{
    PAGED_CODE();

    if (Protection == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    WkdTimerStop(&Protection->PeriodicTimer, TRUE);

    return STATUS_SUCCESS;
}

/* ============================================================================
 * 定时器回调 → 触发验证
 * ============================================================================ */

_Use_decl_annotations_
static
VOID
SppPeriodicCallbackCheck(
    _Inout_opt_ PVOID Context
    )
{
    PWKD_CALLBACK_PROTECTION protection = (PWKD_CALLBACK_PROTECTION)Context;
    ULONG tampered = 0;     // 被篡改回调数量
    LARGE_INTEGER now;

    if (!protection) return;

    KeQuerySystemTime(&now);

    //
    // 遍历回调链表执行全量验证。
    // 回调数目有限（WKD_CP_MAX_CALLBACKS），持推锁全程遍历+校验即可，
    // 既保证条目在校验期间不被并发移除/释放，也无需条目级引用计数。
    // 校验线程由定时器 Thread 模式驱动，运行于 PASSIVE_LEVEL，可安全持推锁。
    //
    WkdAcquirePushLockShared(&protection->CallbackListLock);
    for (PLIST_ENTRY cursor = protection->CallbackListHead.Flink;
        cursor != &protection->CallbackListHead;
        cursor = cursor->Flink) {

        PWKD_CALLBACK_PROTECTION_ENTRY entry =
            CONTAINING_RECORD(cursor, WKD_CALLBACK_PROTECTION_ENTRY, ListEntry);

        //
        // 验证单个条目
        //
        if (!SppVerifyCallback(entry)) {
            BOOLEAN restored = FALSE;

            entry->WasTampered = TRUE;
            entry->TamperCount++;
            tampered++;

            InterlockedIncrement(&protection->TamperAttempts);

            //
            // 尝试 MDL 恢复
            //
            if (protection->EnableRestoration && entry->HasBackup) {
                if (SppRestoreCallbackViaMdl(entry)) {
                    InterlockedIncrement(&protection->CallbacksRestored);
                    restored = TRUE;
                }
                else if (protection->RestoreCallback != NULL) {
                    //
                    // MDL 恢复失败，调用预留的恢复回调
                    //
                    restored = protection->RestoreCallback(
                        entry->Type,
                        entry->Callback,
                        entry->OriginalBytes,
                        entry->OriginalBytesSize,
                        protection->RestoreCallbackProtection
                    );

                    if (restored) {
                        InterlockedIncrement(&protection->CallbacksRestored);
                    }
                }
            }

            //
            // 上报篡改事件
            //
            //WkdReportTamperAlert(
            //    (ULONG)entry->Type,
            //    entry->Callback,
            //    restored,
            //    restored ? L"Code restored from backup" : L"Code restoration failed"
            //);

            //
            // 通知注册的篡改回调
            //
            // CpNotifyTamper(protection, entry, restored);
        }

        entry->LastVerifyTime = now;
        entry->VerifyCount++;
    }
    WkdReleasePushLockShared(&protection->CallbackListLock);

    InterlockedIncrement(&protection->VerificationsRun);

    return STATUS_SUCCESS;
}

/* ============================================================================
 * 单条目验证
 * ============================================================================ */

static
BOOLEAN
SppVerifyCallback(
    _In_ PWKD_CALLBACK_PROTECTION_ENTRY Entry
    )
{
    NTSTATUS status;
    UCHAR hash[BCRYPT_SHA256_SIZE];

    if (!Entry || !Entry->Callback) return FALSE;

    status = CoComputeSha256(
        Entry->Callback,
        WKD_CP_HASH_BYTES,
        hash
    );
    if (!NT_SUCCESS(status)) return FALSE;

    return (RtlCompareMemory(hash, Entry->CodeHash, BCRYPT_SHA256_SIZE) == BCRYPT_SHA256_SIZE);
}

/* ============================================================================
 * MDL 代码恢复
 *
 * 通过 MDL 映射机制将备份的原始代码写入被篡改的回调地址。
 * 需要处理完整的 MDL 生命周期（分配→锁定→映射→写入→解映射→解锁→释放）。
 * SppRestoreCallbackViaMd 函数并没有解决多核同步问题。
 * (1) KeIpiGenericCall 函数能够实现多核同步，但是无法排除触发点位于恢复代码区域
 * (2) 如果出现代码被 patch，EDR 所维护的数据可能出现异常!!!
 * ============================================================================ */

static
BOOLEAN
SppRestoreCallbackViaMdl(
    _In_ PWKD_CALLBACK_PROTECTION_ENTRY Entry
    )
{
    PMDL mdl = NULL;
    BOOLEAN locked = FALSE;
    PVOID mapped = NULL;
    BOOLEAN success = FALSE;

    if (!Entry || !Entry->HasBackup || Entry->OriginalBytesSize == 0) {
        return FALSE;
    }
    
    //
    // 验证回调地址在内核空间
    //
    if ((ULONG_PTR)Entry->Callback < (ULONG_PTR)MmUserProbeAddress) {
        return FALSE;
    }

    __try {
        //
        // 分配 MDL
        //
        mdl = IoAllocateMdl(
            Entry->Callback,
            (ULONG)Entry->OriginalBytesSize,
            FALSE,      // 不加入系统 Mdl 链
            FALSE,      // 不分配扩展
            NULL        // 不关联 IRP
        );
        if (!mdl) return FALSE;

        //
        // 锁定物理页面（驻留内存）
        //
        __try {
            MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
            locked = TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            IoFreeMdl(mdl);
            return FALSE;
        }

        //
        // 映射到系统地址空间（可写）
        //
        mapped = MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmCached,
            NULL,           // 使用系统虚拟地址
            FALSE,          // 不加锁到 Mdl 页表项
            NormalPagePriority
        );

        if (mapped) {
            //
            // 写入备份的原始代码
            //
            RtlCopyMemory(mapped, Entry->OriginalBytes, Entry->OriginalBytesSize);
            MmUnmapLockedPages(mapped, mdl);
            mapped = NULL;

            //
            // 重新计算恢复后的哈希，更新基线
            //
            CoComputeSha256(
                Entry->Callback,
                WKD_CP_HASH_BYTES,
                Entry->CodeHash
            );

            Entry->WasTampered = FALSE;
            success = TRUE;
        }

        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        //
        // 异常清理：确保 MDL 状态一致
        //
        if (mapped && mdl) MmUnmapLockedPages(mapped, mdl);
        if (locked && mdl) MmUnlockPages(mdl);
        if (mdl) IoFreeMdl(mdl);
        success = FALSE;
    }

    return success;
}

/* ============================================================================
 * 篡改通知
 * ============================================================================ */

static
VOID
CpNotifyTamper(
    PWKD_CALLBACK_PROTECTION Protection,
    PWKD_CALLBACK_PROTECTION_ENTRY Entry,
    BOOLEAN Restored
    )
{
    UNREFERENCED_PARAMETER(Restored);

    //
    // 读取回调指针（共享锁保护一致性）
    //
    WKD_CP_TAMPER_CALLBACK callback = Protection->TamperCallback;
    PVOID callbackProtection = Protection->TamperCallbackProtection;

    if (callback != NULL) {
        callback(
            Entry->Type,
            Entry->Callback,
            callbackProtection
        );
    }
}

/* ============================================================================
 * 统计信息
 * ============================================================================ */

_Use_decl_annotations_
_Must_inspect_result_
NTSTATUS
CpGetStatistics(
    PWKD_CALLBACK_PROTECTION Protection,
    PWKD_CP_STATISTICS Stats
    )
{
    LARGE_INTEGER now;

    PAGED_CODE();

    if (Protection == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(WKD_CP_STATISTICS));

    Stats->CallbacksProtected = Protection->CallbacksProtected;
    Stats->TamperAttempts = Protection->TamperAttempts;
    Stats->CallbacksRestored = Protection->CallbacksRestored;
    Stats->VerificationsRun = Protection->VerificationsRun;

    //
    // 遍历回调链表统计当前条目数（持推锁保证一致快照）
    //
    {
        PLIST_ENTRY cursor;
        ULONG count = 0;
        ExAcquirePushLockShared(&Protection->CallbackListLock);
        for (cursor = Protection->CallbackListHead.Flink;
             cursor != &Protection->CallbackListHead;
             cursor = cursor->Flink) {
            count++;
        }
        ExReleasePushLockShared(&Protection->CallbackListLock);
        Stats->CallbackCount = count;
    }

    KeQuerySystemTime(&now);
    Stats->UpTime.QuadPart = now.QuadPart - Protection->StartTime.QuadPart;

    return STATUS_SUCCESS;
}
