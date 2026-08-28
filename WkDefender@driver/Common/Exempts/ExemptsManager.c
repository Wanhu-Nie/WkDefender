/**************************************************/
/*  WkDefender — 四表排除管理器（纯存储仓库）        */
/*                                                   */
/*  按 wkd 架构重写自 SS ExclusionManager.c（对齐     */
/*  SS 行号: IsPathExcluded L553 / IsProcessExcluded  */
/*  L768 / AddPathExclusion L881 / Clear L1196 /      */
/*  LoadDefaultExclusions L1278 / CleanupExpired      */
/*  L1762）                                          */
/*                                                   */
/*  职责：四表规则数据（路径/扩展名/进程名/PID）的    */
/*  存储、维护（Add/Remove/Clear/统计/过期清理）与    */
/*  查询支持。不再持有 rundown / 状态机 / 清理线程     */
/*  （这些归 EXEMPT_ENGINE，由门面 Exempts.c 持有）。 */
/*                                                   */
/*  路径规则存储于 PathHashMap（复用 Common\HashMap   */
/*  .c，全局推锁读共享/写独占）：key = 归一化小写路径， */
/*  value = PEXEMPT_PATH 指针。精确路径与目录规则     */
/*  （RECURSIVE）同表；查询走"逐级截断哈希"——对       */
/*  FilePath 每级 '\' 边界截断做 key 查找，等价于      */
/*  原 ExemptpMatchPathPattern 的精确/递归前缀语义。  */
/*  匹配 O(1) 哈希（扩展名/进程名）+ O(路径深度) 哈希。 */
/*  通配规则（WILDCARD）当前不使用：保留匹配函数能力， */
/*  CopAddExemptedPath 对 WILDCARD 标志返回              */
/*  STATUS_NOT_SUPPORTED（agent 不推送通配规则）。     */
/**************************************************/

#include "ExemptsInternal.h"
#include "../../Common/HashMap.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CopInitializeExemptMgr)
#pragma alloc_text(PAGE, CopAddExemptedPath)
#pragma alloc_text(PAGE, CoLoadDefaultExempts)

#endif

/**************************************************/
/*                  内部辅助函数                    */
/**************************************************/

/* 路径规则哈希桶数（白名单规模小，128 桶足够） */
#define EXEMPT_PATH_HASH_BUCKETS       128

/*
 * 路径条目引用 +1（HashMap Reference，桶锁内调用，仅原子操作）。
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ExemptpPathReference(
    _In_ PVOID Value
    )
{
    PEXEMPT_PATH entry = (PEXEMPT_PATH)Value;

    InterlockedIncrement(&entry->RefCount);
}

/*
 * 路径条目引用 -1，归零释放（HashMap Dereference，桶锁内调用；
 * InterlockedDecrement 为原子操作，ExFreePoolWithTag 归零分支锁内安全，
 * 因为归零意味着无任何在途引用，桶锁内无并发持有者）。
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ExemptpPathDereference(
    _In_ PVOID Value
    )
{
    PEXEMPT_PATH entry = (PEXEMPT_PATH)Value;

    if (InterlockedDecrement(&entry->RefCount) == 0) {
        /*
         * 归零释放：同时释放条目持有的 Path 所有权
         * （CoNormalizeDosPath 分配：'usTs' 结构体 + 'usTs' Buffer，均为 NonPaged，DISPATCH_LEVEL 安全）。
         */
        if (entry->Path != NULL) {
            if (entry->Path->Buffer != NULL) {
                ExFreePoolWithTag(entry->Path->Buffer, 'usTs');
            }
            ExFreePoolWithTag(entry->Path, 'usTs');
        }
        ExFreePoolWithTag(entry, EXEMPT_POOL_TAG_ENTRY);
    }
}

/*
 * 路径哈希表枚举回调：收集 key 到调用方上下文数组
 * （Clear/FreeAll 前收集，锁外再逐个删除）。
 * Context = PEXEMPT_PATH_ENUM_CONTEXT。
 */
typedef struct _EXEMPT_PATH_ENUM_CONTEXT {
    PVOID* Keys;            /* 收集到的 key 指针（指向哈希表内部拷贝，仅锁外删除前有效） */
    ULONG* KeySizes;        /* 对应 key 大小 */
    ULONG Count;            /* 已收集数 */
    ULONG Capacity;         /* 数组容量 */
    BOOLEAN FreeAll;        /* TRUE=收集全部；FALSE=仅非 SYSTEM（Clear 语义） */
} EXEMPT_PATH_ENUM_CONTEXT, *PEXEMPT_PATH_ENUM_CONTEXT;

_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN
ExemptpPathEnumCollect(
    _In_ PVOID Key,
    _In_ ULONG KeySize,
    _In_ ULONG64 Value,
    _Inout_ PVOID Context
    )
{
    PEXEMPT_PATH_ENUM_CONTEXT enumCtx = (PEXEMPT_PATH_ENUM_CONTEXT)Context;
    PEXEMPT_PATH entry = (PEXEMPT_PATH)(ULONG_PTR)Value;

    if (!enumCtx->FreeAll && (entry->Flags & EXEMPT_FLAG_SYSTEM)) {
        return TRUE;    /* Clear 语义跳过 SYSTEM 条目 */
    }

    if (enumCtx->Count >= enumCtx->Capacity) {
        return FALSE;   /* 容量不足提前终止（调用方按 ActiveEntries 预分配，正常不会触发） */
    }

    enumCtx->Keys[enumCtx->Count] = Key;
    enumCtx->KeySizes[enumCtx->Count] = KeySize;
    enumCtx->Count++;

    return TRUE;
}

/*
 * 扩展名条目引用 +1/-1（HashMap 回调，桶锁内调用，仅原子操作；归零锁内释放安全）。
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ExemptpExtensionReference(
    _In_ PVOID Value
    )
{
    InterlockedIncrement(&((PEXEMPT_EXTENSION_EXCLUSION)Value)->RefCount);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ExemptpExtensionDereference(
    _In_ PVOID Value
    )
{
    PEXEMPT_EXTENSION_EXCLUSION entry = (PEXEMPT_EXTENSION_EXCLUSION)Value;

    if (InterlockedDecrement(&entry->RefCount) == 0) {
        ExFreePoolWithTag(entry, EXEMPT_POOL_TAG_ENTRY);
    }
}

/*
 * 进程名条目引用 +1/-1。
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ExemptpProcessReference(
    _In_ PVOID Value
    )
{
    InterlockedIncrement(&((PEXEMPT_PROCESS_EXCLUSION)Value)->RefCount);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ExemptpProcessDereference(
    _In_ PVOID Value
    )
{
    PEXEMPT_PROCESS_EXCLUSION entry = (PEXEMPT_PROCESS_EXCLUSION)Value;

    if (InterlockedDecrement(&entry->RefCount) == 0) {
        ExFreePoolWithTag(entry, EXEMPT_POOL_TAG_ENTRY);
    }
}

/*
 * PID 条目引用 +1/-1。
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ExemptpPidReference(
    _In_ PVOID Value
    )
{
    InterlockedIncrement(&((PEXEMPT_PID_EXCLUSION)Value)->RefCount);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
ExemptpPidDereference(
    _In_ PVOID Value
    )
{
    PEXEMPT_PID_EXCLUSION entry = (PEXEMPT_PID_EXCLUSION)Value;

    if (InterlockedDecrement(&entry->RefCount) == 0) {
        ExFreePoolWithTag(entry, EXEMPT_POOL_TAG_ENTRY);
    }
}

/*
 * 扩展名排除匹配（调用方持有全局 rundown）。
 * 供 IsPathExcluded 查询扩展名排除（唯一实现，O(1) 哈希精确查找）。
 */
_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN
ExemptpMgrMatchExtension(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PCUNICODE_STRING Extension
    )
{
    PEXEMPT_MANAGER Mgr = &Engine->Manager;
    WCHAR lowerBuf[EXEMPT_MAX_EXTENSION_LENGTH];
    UNICODE_STRING lowerKey = { 0 };
    PEXEMPT_EXTENSION_EXCLUSION entry;
    BOOLEAN found = FALSE;

    entry = (PEXEMPT_EXTENSION_EXCLUSION)CoLookupHashMapEntry(
        &Mgr->ExtensionHashMap, lowerKey.Buffer, lowerKey.Length);
    if (entry != NULL) {
        found = TRUE;
        InterlockedIncrement(&entry->HitCount);
        ExemptpExtensionDereference(entry);   /* 归还查询引用 */
    }

    return found;
}

/**************************************************/
/*             关闭辅助 — 无状态门控释放            */
/**************************************************/

/*
 * 通用哈希表清空辅助：枚举收集全部 key → 锁外逐个 CoRemoveHashMapEntry
 * （Dereference -1 归零释放条目）→ CoFreeHashMap。
 * 供四表 Shutdown 复用。
 */
static VOID
ExemptpMgrFreeAllHashMapEntries(
    _In_ PWKD_HASH_MAP HashMap
    )
{
    EXEMPT_PATH_ENUM_CONTEXT enumCtx;
    ULONG count;
    ULONG i;
    PVOID* keys = NULL;
    ULONG* keySizes = NULL;

    count = (ULONG)ReadAcquire(&HashMap->ActiveEntries);
    if (count == 0) {
        return;
    }

    keys = (PVOID*)ExAllocatePoolZero(
        NonPagedPoolNx, count * sizeof(PVOID), EXEMPT_POOL_TAG_ENTRY);
    keySizes = (ULONG*)ExAllocatePoolZero(
        NonPagedPoolNx, count * sizeof(ULONG), EXEMPT_POOL_TAG_ENTRY);
    if (keys == NULL || keySizes == NULL) {
        if (keys != NULL) ExFreePoolWithTag(keys, EXEMPT_POOL_TAG_ENTRY);
        if (keySizes != NULL) ExFreePoolWithTag(keySizes, EXEMPT_POOL_TAG_ENTRY);
        return;
    }

    enumCtx.Keys = keys;
    enumCtx.KeySizes = keySizes;
    enumCtx.Count = 0;
    enumCtx.Capacity = count;
    enumCtx.FreeAll = TRUE;

    CoEnumerateHashMap(HashMap, ExemptpPathEnumCollect, &enumCtx);

    for (i = 0; i < enumCtx.Count; i++) {
        CoRemoveHashMapEntry(HashMap, keys[i], keySizes[i]);
    }

    ExFreePoolWithTag(keys, EXEMPT_POOL_TAG_ENTRY);
    ExFreePoolWithTag(keySizes, EXEMPT_POOL_TAG_ENTRY);

    CoFreeHashMap(HashMap);
}

static VOID
ExemptpMgrFreeAllPathEntries(
    _In_ PEXEMPT_MANAGER Mgr
    )
{
    ExemptpMgrFreeAllHashMapEntries(&Mgr->PathHashMap);
}

static VOID
ExemptpMgrFreeAllExtensionEntries(
    _In_ PEXEMPT_MANAGER Mgr
    )
{
    ExemptpMgrFreeAllHashMapEntries(&Mgr->ExtensionHashMap);
}

static VOID
ExemptpMgrFreeAllProcessEntries(
    _In_ PEXEMPT_MANAGER Mgr
    )
{
    ExemptpMgrFreeAllHashMapEntries(&Mgr->ProcessHashMap);
}

static VOID
ExemptpMgrFreeAllPidEntries(
    _In_ PEXEMPT_MANAGER Mgr
    )
{
    ExemptpMgrFreeAllHashMapEntries(&Mgr->PidHashMap);
}

/**************************************************/
/*                  生命周期                        */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
CopInitializeExemptMgr(
    _Inout_ PEXEMPT_ENGINE Engine
    )
/*++
Routine Description:
    初始化四表排除管理器：锁、链表、哈希桶。
    状态机/rundown/清理线程由门面 Exempts 统一管理（此处不涉及）。

Arguments:
    Engine - 子系统全局结构体（Manager 上下文位于 Engine->Manager）。

Return Value:
    STATUS_SUCCESS。
--*/
{
    PEXEMPT_MANAGER Mgr = &Engine->Manager;
    NTSTATUS status;

    PAGED_CODE();

    /*
     * 四表统一使用 WKD_HASH_MAP（全局推锁，读共享/写独占），
     * Reference =TRUE + 注册引用回调：条目动态分配、可被并发
     * 增删（ALPC/清理线程），查询锁外读条目字段依赖 ref pin 保护。
     */
    status = CoInitializeHashMap(
        &Mgr->PathHashMap,
        EXEMPT_PATH_HASH_BUCKETS,
        FALSE,
        ExemptpPathReference,
        NULL,
        ExemptpPathDereference);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = CoInitializeHashMap(
        &Mgr->ExtensionHashMap,
        EXEMPT_EXTENSION_HASH_BUCKETS,
        FALSE,
        ExemptpExtensionReference,
        NULL,
        ExemptpExtensionDereference);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = CoInitializeHashMap(
        &Mgr->ProcessHashMap,
        EXEMPT_PROCESS_HASH_BUCKETS,
        FALSE,
        ExemptpProcessReference,
        NULL,
        ExemptpProcessDereference);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = CoInitializeHashMap(
        &Mgr->PidHashMap,
        EXEMPT_PID_HASH_BUCKETS,
        FALSE,
        ExemptpPidReference,
        NULL,
        ExemptpPidDereference);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptsMgrShutdown(
    _Inout_ PEXEMPT_ENGINE Engine
    )
/*++
Routine Description:
    关闭四表排除管理器：释放全部条目。
    调用前门面已停清理线程并排空 rundown（无在途查询/清理并发）。

Arguments:
    Engine - 子系统全局结构体。

Return Value:
    无。
--*/
{
    PEXEMPT_MANAGER Mgr = &Engine->Manager;

    PAGED_CODE();

    ExemptpMgrFreeAllPathEntries(Mgr);
    ExemptpMgrFreeAllExtensionEntries(Mgr);
    ExemptpMgrFreeAllProcessEntries(Mgr);
    ExemptpMgrFreeAllPidEntries(Mgr);
}

/**************************************************/
/*                  匹配查询                        */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
CopCheckPathExempted(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PCUNICODE_STRING FilePath,
    _In_opt_ PCUNICODE_STRING Extension
    )
/*++
Routine Description:
    查询存储仓库：路径是否命中扩展名或路径排除。

Arguments:
    Engine    - 子系统全局结构体。
    FilePath  - 文件路径，必须经过标准化为Dos风格且小写。
    Extension - 可选扩展名（先查 O(1) 扩展名哈希）。

Return Value:
    TRUE 排除命中。
--*/
{
    PEXEMPT_MANAGER mgr;

    if (!Engine || !FilePath ||
        !FilePath->Buffer || FilePath->Length == 0) {
        return FALSE;
    }
    mgr = &Engine->Manager;

    /*
     * 先查扩展名（O(1) 哈希），命中即返回。
     */
    if (Extension != NULL && Extension->Buffer && Extension->Length > 0) {
        // 暂时未定义
        DbgBreakPoint();
        if (ExemptpMgrMatchExtension(Engine, Extension)) {
            return TRUE;
        }
    }

    /*
     * 查路径规则哈希表（逐级截断哈希查找）。
     * 语义等价于原 ExemptpMatchPathPattern 的精确/递归前缀匹配：
     *   - 精确规则（非 RECURSIVE）：FilePath 完整 key 命中
     *   - 目录规则（RECURSIVE）：FilePath 每级 '\' 边界截断的 key 命中
     * key 为归一化小写路径（CopAddExemptedPath 入库时 CoNormalizeDosPath + 去尾斜杠）。
     * 命中后检查过期：过期条目视为未命中，继续向父级截断。
     */
    {
        USHORT len = FilePath->Length / sizeof(WCHAR);
        LARGE_INTEGER scanTime;

        KeQuerySystemTime(&scanTime);

        for (;;) {
            UNICODE_STRING prefix;  /* 路径被截断的前缀 */
            PEXEMPT_PATH hit;

            prefix.Buffer = FilePath->Buffer;
            prefix.Length = (USHORT)(len * sizeof(WCHAR));
            prefix.MaximumLength = prefix.Length;

            hit = (PEXEMPT_PATH)CoLookupHashMapEntry(
                &mgr->PathHashMap, prefix.Buffer, prefix.Length);
            if (hit != NULL) {
                if (hit->ExpireTime.QuadPart == 0 ||
                    scanTime.QuadPart <= hit->ExpireTime.QuadPart) {
                    InterlockedIncrement(&hit->HitCount);
                    ExemptpPathDereference(hit);   /* 归还查询引用 */
                    return TRUE;
                }
                ExemptpPathDereference(hit);
            }

            if (len <= 2) {
                break;   /* 盘符根（如 "C:"）为最后一级 */
            }

            /* 截断到上一个 '\' 边界（不含分隔符） */
            {
                USHORT prev = len - 1;
                while (prev > 0 && FilePath->Buffer[prev] != L'\\') {
                    prev--;
                }
                if (prev == 0) {
                    break;   /* 无更上层分隔符 */
                }
                len = prev;
            }
        }
    }

    return FALSE;
}

_Use_decl_annotations_
BOOLEAN
CopCheckProcessExemptedByIdOrName(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _In_opt_ PCUNICODE_STRING ProcessName
    )
/*++
Routine Description:
    查询存储仓库：进程是否命中 PID 或进程名排除。

Arguments:
    Engine      - 子系统全局结构体。
    ProcessId   - 进程 ID（先查 PID 数组）。
    ProcessName - 可选进程名（再查进程名哈希），必须确保小写。

Return Value:
    TRUE 排除命中。
--*/
{
    PEXEMPT_MANAGER Mgr = &Engine->Manager;
    PEXEMPT_PID_EXCLUSION pidEntry;
    PEXEMPT_PROCESS_EXCLUSION procEntry;
    BOOLEAN excluded = FALSE;

    if (!Engine || !ProcessId) {
        return FALSE;
    }
    
    /*
     * 先查 PID 哈希表（key=8 字节 HANDLE，O(1) 精确查找）。
     */
    pidEntry = (PEXEMPT_PID_EXCLUSION)CoLookupHashMapEntry(
        &Mgr->PidHashMap, &ProcessId, sizeof(HANDLE));
    if (pidEntry != NULL) {
        LARGE_INTEGER currentTime;
        KeQuerySystemTime(&currentTime);

        if (pidEntry->ExpireTime.QuadPart == 0 ||
            currentTime.QuadPart < pidEntry->ExpireTime.QuadPart) {
            excluded = TRUE;
            InterlockedIncrement(&pidEntry->HitCount);
        }
        ExemptpPidDereference(pidEntry);   /* 归还查询引用 */

        if (excluded) return TRUE;
    }

    /*
     * 再查进程名哈希表（key=归一化小写进程名）。
     */
    if (ProcessName == NULL || ProcessName->Buffer == NULL ||
        ProcessName->Length == 0) {
        return FALSE;
    }

    procEntry = (PEXEMPT_PROCESS_EXCLUSION)CoLookupHashMapEntry(
        &Mgr->ProcessHashMap, ProcessName->Buffer, ProcessName->Length);
    if (procEntry != NULL) {
        excluded = TRUE;
        InterlockedIncrement(&procEntry->HitCount);
        ExemptpProcessDereference(procEntry);   /* 归还查询引用 */
    }

    return excluded;
}

/**************************************************/
/*                  规则管理                        */
/**************************************************/

_Use_decl_annotations_
CopAddExemptedPath(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PCUNICODE_STRING Path,
    _In_ UINT8 Flags,
    _In_ ULONG TTLSeconds
    )
/*++
Routine Description:
    添加路径排除。

Arguments:
    Engine     - 子系统全局结构体。
    Path       - 排除路径。
    Flags      - EXEMPT_FLAG_*。
    TTLSeconds - 临时排除有效期（0=永不过期）。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER / STATUS_NAME_TOO_LONG /
    STATUS_INSUFFICIENT_RESOURCES / STATUS_OBJECT_NAME_COLLISION。
--*/
{
    PEXEMPT_PATH entry;
    PUNICODE_STRING normalized = NULL;
    BOOLEAN alreadyExists = FALSE;
    NTSTATUS status;

    PAGED_CODE();
    
    if (!Engine || !Path || !Path->Buffer || Path->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * 通配规则：保留 ExemptpMatchPathPattern 的 WILDCARD 能力，但当前
     * agent 不推送通配规则，哈希表无法表达模式匹配——明确拒绝而非
     * 静默失效（未来若启用需独立存储结构）。
     */
    if (Flags & EXEMPT_FLAG_WILDCARD) {
        return STATUS_NOT_SUPPORTED;
    }

    /* 路径标准化并转小写 */
    status = CoNormalizeDosPath(Path, &normalized);
    if (!NT_SUCCESS(status)) return status;

    entry = (PEXEMPT_PATH)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(EXEMPT_PATH),
        EXEMPT_POOL_TAG_ENTRY);
    if (entry == NULL) {
        status = STATUS_NO_MEMORY;
        goto Cleanup;
    }

    entry->Flags = Flags;
    entry->RefCount = 0;    /* 插入时 Reference +1 成为表内引用 */
    entry->Path = normalized;
    KeQuerySystemTime(&entry->CreateTime);

    if ((Flags & EXEMPT_FLAG_TEMPORARY) && TTLSeconds > 0) {
        entry->ExpireTime.QuadPart =
            entry->CreateTime.QuadPart + ((LONGLONG)TTLSeconds * 10000000LL);
    }

    /*
     * 哈希插入：已存在 key → AlreadyExists=TRUE（返回碰撞状态）；
     * 插入成功 → Reference +1（RefCount 1→2，删除时 -1 归零释放）。
     */
    status = CoInsertHashMap(
        &Engine->Manager.PathHashMap,
        entry->Path->Buffer,
        entry->Path->Length,
        (ULONG64)entry,
        &alreadyExists);
    if (!NT_SUCCESS(status) || alreadyExists) goto Failed;

    /* 插入成功：表内引用 1 已由 Reference 加上，此处无需再操作 */
    return STATUS_SUCCESS;

Failed:
    if (entry) ExFreePoolWithTag(entry, EXEMPT_POOL_TAG_ENTRY);
Cleanup:
    /* 失败路径：normalized 所有权未转移，'usTs' 与 CoNormalizeDosPath 分配标签一致 */
    ExFreePoolWithTag(normalized->Buffer, 'usTs');
    ExFreePoolWithTag(normalized, 'usTs');
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ExemptsMgrAddExtensionExclusion(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PCUNICODE_STRING Extension,
    _In_ UINT8 Flags
    )
/*++
Routine Description:
    添加扩展名排除（大写归一化 + O(1) 哈希桶）。

Arguments:
    Engine    - 子系统全局结构体。
    Extension - 扩展名（不含点）。
    Flags     - EXEMPT_FLAG_*。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER / STATUS_NAME_TOO_LONG /
    STATUS_INSUFFICIENT_RESOURCES / STATUS_OBJECT_NAME_COLLISION。
--*/
{
    PEXEMPT_MANAGER Mgr = &Engine->Manager;
    PEXEMPT_EXTENSION_EXCLUSION entry;
    WCHAR lowerBuf[EXEMPT_MAX_EXTENSION_LENGTH];
    UNICODE_STRING lowerKey = { 0 };
    BOOLEAN alreadyExists = FALSE;
    NTSTATUS status;
    USHORT extChars;

    PAGED_CODE();

    if (Extension == NULL || Extension->Buffer == NULL || Extension->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    extChars = Extension->Length / sizeof(WCHAR);
    if (extChars >= EXEMPT_MAX_EXTENSION_LENGTH) {
        return STATUS_NAME_TOO_LONG;
    }

    /* 上限检查（agent 全量重推覆盖，防止表无限增长） */
    if ((ULONG)ReadAcquire(&Mgr->ExtensionHashMap.ActiveEntries) >=
        EXEMPT_MAX_EXTENSION_EXCLUSIONS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry = (PEXEMPT_EXTENSION_EXCLUSION)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(EXEMPT_EXTENSION_EXCLUSION),
        EXEMPT_POOL_TAG_ENTRY);

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->Flags = Flags;
    entry->RefCount = 0;    /* 插入时 Reference +1 成为表内引用 */
    RtlCopyMemory(entry->Extension, lowerKey.Buffer, lowerKey.Length);
    entry->ExtensionLength = extChars;
    entry->Extension[extChars] = L'\0';

    status = CoInsertHashMap(
        &Mgr->ExtensionHashMap,
        entry->Extension,
        entry->ExtensionLength * sizeof(WCHAR),
        (ULONG64)(ULONG_PTR)entry,
        &alreadyExists);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(entry, EXEMPT_POOL_TAG_ENTRY);
        return status;
    }

    if (alreadyExists) {
        ExFreePoolWithTag(entry, EXEMPT_POOL_TAG_ENTRY);
        return STATUS_OBJECT_NAME_COLLISION;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ExemptsMgrAddProcessExclusion(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PCUNICODE_STRING ProcessName,
    _In_ UINT8 Flags
    )
/*++
Routine Description:
    添加进程名排除（大写归一化 + O(1) 哈希桶）。

Arguments:
    Engine      - 子系统全局结构体。
    ProcessName - 进程名。
    Flags       - EXEMPT_FLAG_*。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER / STATUS_NAME_TOO_LONG /
    STATUS_INSUFFICIENT_RESOURCES / STATUS_OBJECT_NAME_COLLISION。
--*/
{
    PEXEMPT_MANAGER Mgr = &Engine->Manager;
    PEXEMPT_PROCESS_EXCLUSION entry;
    WCHAR lowerBuf[EXEMPT_MAX_PROCESS_NAME_LENGTH];
    UNICODE_STRING lowerKey = { 0 };
    BOOLEAN alreadyExists = FALSE;
    NTSTATUS status;
    USHORT nameChars;

    PAGED_CODE();

    if (ProcessName == NULL || ProcessName->Buffer == NULL || ProcessName->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    nameChars = ProcessName->Length / sizeof(WCHAR);
    if (nameChars >= EXEMPT_MAX_PROCESS_NAME_LENGTH) {
        return STATUS_NAME_TOO_LONG;
    }

    /* 上限检查 */
    if ((ULONG)ReadAcquire(&Mgr->ProcessHashMap.ActiveEntries) >=
        EXEMPT_MAX_PROCESS_EXCLUSIONS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry = (PEXEMPT_PROCESS_EXCLUSION)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(EXEMPT_PROCESS_EXCLUSION),
        EXEMPT_POOL_TAG_ENTRY);

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->Flags = Flags;
    entry->RefCount = 0;    /* 插入时 Reference +1 成为表内引用 */
    RtlCopyMemory(entry->ProcessName, lowerKey.Buffer, lowerKey.Length);
    entry->NameLength = nameChars;
    entry->ProcessName[nameChars] = L'\0';

    status = CoInsertHashMap(
        &Mgr->ProcessHashMap,
        entry->ProcessName,
        entry->NameLength * sizeof(WCHAR),
        (ULONG64)(ULONG_PTR)entry,
        &alreadyExists);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(entry, EXEMPT_POOL_TAG_ENTRY);
        return status;
    }

    if (alreadyExists) {
        ExFreePoolWithTag(entry, EXEMPT_POOL_TAG_ENTRY);
        return STATUS_OBJECT_NAME_COLLISION;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ExemptsMgrAddPidExclusion(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ HANDLE ProcessId,
    _In_opt_ ULONG TTLSeconds
    )
/*++
Routine Description:
    添加 PID 排除（固定数组，复用过期槽位）。

Arguments:
    Engine      - 子系统全局结构体。
    ProcessId   - 进程 ID。
    TTLSeconds  - 有效期（0=进程退出前有效）。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER / STATUS_INSUFFICIENT_RESOURCES。
--*/
{
    PEXEMPT_MANAGER Mgr = &Engine->Manager;
    PEXEMPT_PID_EXCLUSION entry;
    PEXEMPT_PID_EXCLUSION existing;
    LARGE_INTEGER currentTime;
    NTSTATUS status;
    PEPROCESS process = NULL;

    PAGED_CODE();

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * 校验 PID 指向真实进程，防 PID 预排除攻击。
     */
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return STATUS_INVALID_PARAMETER;
    }
    ObDereferenceObject(process);

    KeQuerySystemTime(&currentTime);

    /*
     * 已存在：更新 TTL（0=进程退出前有效），保持表内引用不变。
     */
    existing = (PEXEMPT_PID_EXCLUSION)CoLookupHashMapEntry(
        &Mgr->PidHashMap, &ProcessId, sizeof(ProcessId));
    if (existing != NULL) {
        if (TTLSeconds > 0) {
            existing->ExpireTime.QuadPart =
                currentTime.QuadPart + ((LONGLONG)TTLSeconds * 10000000LL);
        } else {
            existing->ExpireTime.QuadPart = 0;
        }
        ExemptpPidDereference(existing);   /* 归还查询引用 */
        return STATUS_SUCCESS;
    }

    /* 上限检查 */
    if ((ULONG)ReadAcquire(&Mgr->PidHashMap.ActiveEntries) >=
        EXEMPT_MAX_PID_EXCLUSIONS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry = (PEXEMPT_PID_EXCLUSION)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(EXEMPT_PID_EXCLUSION),
        EXEMPT_POOL_TAG_ENTRY);

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->ProcessId = ProcessId;
    entry->RefCount = 0;    /* 插入时 Reference +1 成为表内引用 */
    if (TTLSeconds > 0) {
        entry->ExpireTime.QuadPart =
            currentTime.QuadPart + ((LONGLONG)TTLSeconds * 10000000LL);
    } else {
        entry->ExpireTime.QuadPart = 0;
    }

    status = CoInsertHashMap(
        &Mgr->PidHashMap,
        &entry->ProcessId,
        sizeof(entry->ProcessId),
        (ULONG64)(ULONG_PTR)entry,
        NULL);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(entry, EXEMPT_POOL_TAG_ENTRY);
        return status;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExemptsMgrRemovePathExclusion(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PCUNICODE_STRING Path
    )
/*++
Routine Description:
    移除路径排除（Engine 标志条目不可移除）。

Arguments:
    Engine - 子系统全局结构体。
    Path   - 排除路径。

Return Value:
    TRUE 已移除。
--*/
{
    PEXEMPT_MANAGER Mgr = &Engine->Manager;
    PUNICODE_STRING normalized = NULL;
    PEXEMPT_PATH entry;
    USHORT pathChars;
    BOOLEAN removed = FALSE;
    NTSTATUS status;

    PAGED_CODE();

    /* 与插入同一归一化路径（小写 + 去尾斜杠），保证 key 一致 */
    status = CoNormalizeDosPath(Path, &normalized);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    pathChars = normalized->Length / sizeof(WCHAR);
    while (pathChars > 2 &&
           normalized->Buffer[pathChars - 1] == L'\\') {
        normalized->Length -= sizeof(WCHAR);
        pathChars--;
    }
    normalized->Buffer[pathChars] = L'\0';

    /*
     * 先查表拿条目（+1 临时引用），检查 SYSTEM 标志（不可移除）。
     * 非 SYSTEM：CoRemoveHashMapEntry 摘链（Dereference -1 表内引用），
     * 再归还临时引用 → 归零释放。
     */
    entry = (PEXEMPT_PATH)CoLookupHashMapEntry(
        &Mgr->PathHashMap,
        normalized->Buffer,
        normalized->Length);
    if (entry != NULL) {
        if (entry->Flags & EXEMPT_FLAG_SYSTEM) {
            ExemptpPathDereference(entry);   /* 归还临时引用 */
        } else {
            removed = CoRemoveHashMapEntry(
                &Mgr->PathHashMap,
                normalized->Buffer,
                normalized->Length);
            ExemptpPathDereference(entry);   /* 归还临时引用（若表内已删，归零释放） */
        }
    }

    /* 本地归一化临时量：'usTs' 与 CoNormalizeDosPath 分配标签一致 */
    ExFreePoolWithTag(normalized->Buffer, 'usTs');
    ExFreePoolWithTag(normalized, 'usTs');

    return removed;
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExemptsMgrRemoveExtensionExclusion(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PCUNICODE_STRING Extension
    )
/*++
Routine Description:
    移除扩展名排除（Engine 标志条目不可移除）。

Arguments:
    Engine    - 子系统全局结构体。
    Extension - 扩展名。

Return Value:
    TRUE 已移除。
--*/
{
    PEXEMPT_MANAGER Mgr = &Engine->Manager;
    PEXEMPT_EXTENSION_EXCLUSION entry;
    WCHAR lowerBuf[EXEMPT_MAX_EXTENSION_LENGTH];
    UNICODE_STRING lowerKey = { 0 };
    BOOLEAN removed = FALSE;

    PAGED_CODE();

    if (Extension == NULL || Extension->Buffer == NULL || Extension->Length == 0) {
        return FALSE;
    }

    /*
     * 先查表拿条目（+1 临时引用），检查 SYSTEM 标志（不可移除）。
     */
    entry = (PEXEMPT_EXTENSION_EXCLUSION)CoLookupHashMapEntry(
        &Mgr->ExtensionHashMap, lowerKey.Buffer, lowerKey.Length);
    if (entry != NULL) {
        if (entry->Flags & EXEMPT_FLAG_SYSTEM) {
            ExemptpExtensionDereference(entry);
        } else {
            removed = CoRemoveHashMapEntry(
                &Mgr->ExtensionHashMap, lowerKey.Buffer, lowerKey.Length);
            ExemptpExtensionDereference(entry);
        }
    }

    return removed;
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExemptsMgrRemoveProcessExclusion(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ PCUNICODE_STRING ProcessName
    )
/*++
Routine Description:
    移除进程名排除（Engine 标志条目不可移除）。

Arguments:
    Engine      - 子系统全局结构体。
    ProcessName - 进程名。

Return Value:
    TRUE 已移除。
--*/
{
    PEXEMPT_MANAGER Mgr = &Engine->Manager;
    PEXEMPT_PROCESS_EXCLUSION entry;
    WCHAR lowerBuf[EXEMPT_MAX_PROCESS_NAME_LENGTH];
    UNICODE_STRING lowerKey = { 0 };
    BOOLEAN removed = FALSE;

    PAGED_CODE();

    if (ProcessName == NULL || ProcessName->Buffer == NULL || ProcessName->Length == 0) {
        return FALSE;
    }

    /*
     * 先查表拿条目（+1 临时引用），检查 SYSTEM 标志（不可移除）。
     */
    entry = (PEXEMPT_PROCESS_EXCLUSION)CoLookupHashMapEntry(
        &Mgr->ProcessHashMap, lowerKey.Buffer, lowerKey.Length);
    if (entry != NULL) {
        if (entry->Flags & EXEMPT_FLAG_SYSTEM) {
            ExemptpProcessDereference(entry);
        } else {
            removed = CoRemoveHashMapEntry(
                &Mgr->ProcessHashMap, lowerKey.Buffer, lowerKey.Length);
            ExemptpProcessDereference(entry);
        }
    }

    return removed;
}

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExemptsMgrRemovePidExclusion(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    移除 PID 排除。

Arguments:
    Engine    - 子系统全局结构体。
    ProcessId - 进程 ID。

Return Value:
    TRUE 已移除。
--*/
{
    PEXEMPT_MANAGER Mgr = &Engine->Manager;
    PEXEMPT_PID_EXCLUSION entry;
    BOOLEAN removed = FALSE;

    PAGED_CODE();

    /*
     * 先查表拿条目（+1 临时引用），检查 SYSTEM 标志（不可移除）。
     */
    entry = (PEXEMPT_PID_EXCLUSION)CoLookupHashMapEntry(
        &Mgr->PidHashMap, &ProcessId, sizeof(ProcessId));
    if (entry != NULL) {
        if (entry->Flags & EXEMPT_FLAG_SYSTEM) {
            ExemptpPidDereference(entry);
        } else {
            removed = CoRemoveHashMapEntry(
                &Mgr->PidHashMap, &ProcessId, sizeof(ProcessId));
            ExemptpPidDereference(entry);
        }
    }

    return removed;
}

/*
 * 清空哈希表中非 SYSTEM 条目（Clear 语义）：枚举收集 key（回调内
 * 判定 SYSTEM 跳过）→ 锁外逐个 CoRemoveHashMapEntry。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
ExemptpMgrClearNonSystemHashMap(
    _In_ PWKD_HASH_MAP HashMap
    )
{
    EXEMPT_PATH_ENUM_CONTEXT enumCtx;
    ULONG count;
    ULONG i;
    PVOID* keys = NULL;
    ULONG* keySizes = NULL;

    count = (ULONG)ReadAcquire(&HashMap->ActiveEntries);
    if (count > 0) {
        keys = (PVOID*)ExAllocatePoolZero(
            NonPagedPoolNx, count * sizeof(PVOID), EXEMPT_POOL_TAG_ENTRY);
        keySizes = (ULONG*)ExAllocatePoolZero(
            NonPagedPoolNx, count * sizeof(ULONG), EXEMPT_POOL_TAG_ENTRY);
    }

    if (keys != NULL && keySizes != NULL && count > 0) {
        enumCtx.Keys = keys;
        enumCtx.KeySizes = keySizes;
        enumCtx.Count = 0;
        enumCtx.Capacity = count;
        enumCtx.FreeAll = FALSE;   /* Clear 语义：跳过 SYSTEM */

        CoEnumerateHashMap(HashMap, ExemptpPathEnumCollect, &enumCtx);

        for (i = 0; i < enumCtx.Count; i++) {
            CoRemoveHashMapEntry(HashMap, keys[i], keySizes[i]);
        }
    }

    if (keys != NULL) ExFreePoolWithTag(keys, EXEMPT_POOL_TAG_ENTRY);
    if (keySizes != NULL) ExFreePoolWithTag(keySizes, EXEMPT_POOL_TAG_ENTRY);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptsMgrClearExclusions(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ EXEMPT_RULE_TYPE Type
    )
/*++
Routine Description:
    按类型清空排除规则（保留 Engine 标志条目）。

Arguments:
    Engine - 子系统全局结构体。
    Type   - EXEMPT_RULE_TYPE。

Return Value:
    无。
--*/
{
    PEXEMPT_MANAGER Mgr = &Engine->Manager;

    PAGED_CODE();

    if (Type == ExemptRule_Path) {
        ExemptpMgrClearNonSystemHashMap(&Mgr->PathHashMap);
    }
    else if (Type == ExemptRule_Extension) {
        ExemptpMgrClearNonSystemHashMap(&Mgr->ExtensionHashMap);
    }
    else if (Type == ExemptRule_ProcessName) {
        ExemptpMgrClearNonSystemHashMap(&Mgr->ProcessHashMap);
    }
    else if (Type == ExemptRule_ProcessId) {
        ExemptpMgrClearNonSystemHashMap(&Mgr->PidHashMap);
    }
}

/**************************************************/
/*                  默认排除加载                    */
/**************************************************/

/*
 * 内建 NTFS 元文件排除（对齐 SS LoadDefaultExclusions L1278-1335）：
 * 这些元文件产生巨大 I/O 且不含用户态可执行代码，Engine|Recursive
 * 保证跨卷以组件后缀匹配。
 */
static const WCHAR* ExemptsDefaultNtfsPaths[] = {
    L"\\$LogFile",
    L"\\$Mft",
    L"\\$MftMirr",
    L"\\$Bitmap",
    L"\\pagefile.sys",
    L"\\swapfile.sys",
    L"\\hiberfil.sys",
};

/*
 * 内建白名单目录（兜底能力，不依赖 agent 推送）：
 * System32 / SysWOW64 为系统组件标准目录，RECURSIVE 前缀匹配其下
 * 任意可执行文件。插入为 SYSTEM|RECURSIVE 标志（不可被 Remove/Clear）。
 */
static const WCHAR* ExemptsDefaultSystemDirs[] = {
    L"C:\\Windows\\System32",
    L"C:\\Windows\\SysWOW64",
};

/*
 * 内建系统服务精确路径（迁移自 ProcessMonitor.c WkdTrustedEngineSerivcePaths）：
 * 核心系统进程 + 系统服务 + 现代 UI 组件 + 安全中心 + Windows 更新 +
 * Defender 组件。插入为 Engine 标志精确路径排除（非递归前缀=精确匹配）。
 */
static const WCHAR* ExemptsDefaultEnginePaths[] = {
    /* 核心系统进程 */
    L"System",
    L"Registry",
    L"Memory Compression",
    L"C:\\Windows\\System32\\svchost.exe",
    L"C:\\Windows\\System32\\services.exe",
    L"C:\\Windows\\System32\\lsass.exe",
    L"C:\\Windows\\System32\\wininit.exe",
    L"C:\\Windows\\System32\\csrss.exe",
    L"C:\\Windows\\System32\\smss.exe",
    L"C:\\Windows\\System32\\winlogon.exe",
    L"C:\\Windows\\System32\\dwm.exe",
    L"C:\\Windows\\explorer.exe",
    L"C:\\Windows\\System32\\fontdrvhost.exe",

    /* 系统服务与后台任务 */
    L"C:\\Windows\\System32\\spoolsv.exe",
    L"C:\\Windows\\System32\\SearchIndexer.exe",
    L"C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
    L"C:\\Windows\\System32\\sihost.exe",
    L"C:\\Windows\\System32\\taskhostw.exe",
    L"C:\\Windows\\System32\\RuntimeBroker.exe",
    L"C:\\Windows\\System32\\ctfmon.exe",
    L"C:\\Windows\\System32\\smartscreen.exe",
    L"C:\\Windows\\System32\\audiodg.exe",
    L"C:\\Windows\\System32\\WUDFHost.exe",
    L"C:\\Windows\\System32\\LogonUI.exe",
    L"C:\\Windows\\System32\\userinit.exe",
    L"C:\\Windows\\System32\\Conhost.exe",
    L"C:\\Windows\\System32\\taskmgr.exe",
    L"C:\\Windows\\System32\\DllHost.exe",
    L"C:\\Windows\\System32\\consent.exe",
    L"C:\\Windows\\System32\\rundll32.exe",
    L"C:\\Windows\\System32\\sihclient.exe",

    /* Windows 10/11 现代 UI 组件 */
    L"C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost.exe",
    L"C:\\Windows\\SystemApps\\Microsoft.Windows.Search_cw5n1h2txyewy\\SearchApp.exe",
    L"C:\\Windows\\SystemApps\\ShellExperienceHost_cw5n1h2txyewy\\ShellExperienceHost.exe",
    L"C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\TextInputHost.exe",

    /* Windows 安全中心 */
    L"C:\\Windows\\System32\\SecurityHealthHost.exe",
    L"C:\\Windows\\System32\\SecurityHealthService.exe",
    L"C:\\Windows\\System32\\SecurityHealthSystray.exe",
    L"C:\\Windows\\SystemApps\\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy\\SecHealthUI.exe",

    /* Windows 模块安装/更新 */
    L"C:\\Windows\\servicing\\TrustedInstaller.exe",
    L"C:\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.19041.5425_none_7e0bb22e7c8f7e0e\\TiWorker.exe",
    L"C:\\Windows\\System32\\UsoClient.exe",
    L"C:\\Windows\\System32\\MoUsoCoreWorker.exe",
    L"C:\\Windows\\System32\\WaaSMedicAgent.exe",
    L"C:\\Windows\\System32\\MusNotification.exe",
    L"C:\\Windows\\System32\\MusNotificationUx.exe",

    /* 软件保护 */
    L"C:\\Windows\\System32\\sppsvc.exe",
    L"C:\\Windows\\System32\\SppExtComObj.exe",
    L"C:\\Windows\\System32\\SLUI.exe",

    /* 遥测 */
    L"C:\\Windows\\System32\\CompatTelRunner.exe",
    L"C:\\Windows\\System32\\DeviceCensus.exe",

    /* Office 更新 */
    L"C:\\Windows\\System32\\upfc.exe",

    /* Windows Defender */
    L"C:\\Program Files\\Windows Defender\\MsMpEng.exe",
    L"C:\\Program Files\\Windows Defender\\NisSrv.exe",
    L"C:\\Program Files\\Windows Defender\\MpCmdRun.exe",

    /* 搜索服务 */
    L"C:\\Windows\\System32\\SearchFilterHost.exe",
    L"C:\\Windows\\System32\\SearchProtocolHost.exe",

    /* UWP 后台任务 */
    L"C:\\Windows\\System32\\BackgroundTaskHost.exe",

    /* 设置应用 */
    L"C:\\Windows\\ImmersiveControlPanel\\EngineSettings.exe",

    /* Edge 更新 */
    L"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",

    /* VM Ware */
    L"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",
};

_Use_decl_annotations_
VOID
CoLoadDefaultExempts(
    _In_ PEXEMPT_ENGINE Engine
    )
/*++
Routine Description:
    加载内建默认排除：NTFS 元文件（递归）+ 系统服务精确路径（Engine 标志）。

Arguments:
    Engine - 子系统全局结构体。

Return Value:
    无。
--*/
{
    ULONG i;
    UNICODE_STRING str;

    PAGED_CODE();

    if (!ExAcquireRundownProtection(&Engine->RundownRef)) {
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(ExemptsDefaultNtfsPaths); i++) {
        RtlInitUnicodeString(&str, ExemptsDefaultNtfsPaths[i]);
        CopAddExemptedPath(Engine, &str,
            EXEMPT_FLAG_SYSTEM | EXEMPT_FLAG_RECURSIVE, 0);
    }

    for (i = 0; i < RTL_NUMBER_OF(ExemptsDefaultEnginePaths); i++) {
        RtlInitUnicodeString(&str, ExemptsDefaultEnginePaths[i]);
        CopAddExemptedPath(Engine, &str, EXEMPT_FLAG_SYSTEM, 0);
    }

    /* 内置白名单目录（System32/SysWOW64，递归前缀兜底） */
    for (i = 0; i < RTL_NUMBER_OF(ExemptsDefaultSystemDirs); i++) {
        RtlInitUnicodeString(&str, ExemptsDefaultSystemDirs[i]);
        CopAddExemptedPath(Engine, &str,
            EXEMPT_FLAG_SYSTEM | EXEMPT_FLAG_RECURSIVE, 0);
    }

    ExReleaseRundownProtection(&Engine->RundownRef);
}

/**************************************************/
/*                  过期清理                        */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptsMgrCleanupExpired(
    _In_ PEXEMPT_ENGINE Engine
    )
/*++
Routine Description:
    清理过期路径/PID 排除条目（由门面自建 60s 清理线程周期调用）。

Arguments:
    Engine - 子系统全局结构体。

Return Value:
    无。
--*/
{
    PEXEMPT_MANAGER Mgr = &Engine->Manager;
    LARGE_INTEGER currentTime;
    ULONG i;

    PAGED_CODE();

    KeQuerySystemTime(&currentTime);

    /*
     * 路径过期清理：枚举收集过期条目 key（枚举持共享锁，回调内只读
     * ExpireTime 并拷贝 key 指针），锁外逐个 CoRemoveHashMapEntry。
     */
    {
        EXEMPT_PATH_ENUM_CONTEXT enumCtx;
        ULONG count;
        PVOID* keys = NULL;
        ULONG* keySizes = NULL;

        count = (ULONG)ReadAcquire(&Mgr->PathHashMap.ActiveEntries);
        if (count > 0) {
            keys = (PVOID*)ExAllocatePoolZero(
                NonPagedPoolNx, count * sizeof(PVOID), EXEMPT_POOL_TAG_ENTRY);
            keySizes = (ULONG*)ExAllocatePoolZero(
                NonPagedPoolNx, count * sizeof(ULONG), EXEMPT_POOL_TAG_ENTRY);
        }

        if (keys != NULL && keySizes != NULL && count > 0) {
            /* 复用枚举上下文，但这里需要"只收集过期条目"——
             * 直接遍历两次：先收集全部（FreeAll=TRUE），再锁外判定过期删除。 */
            enumCtx.Keys = keys;
            enumCtx.KeySizes = keySizes;
            enumCtx.Count = 0;
            enumCtx.Capacity = count;
            enumCtx.FreeAll = TRUE;

            CoEnumerateHashMap(&Mgr->PathHashMap, ExemptpPathEnumCollect, &enumCtx);

            for (i = 0; i < enumCtx.Count; i++) {
                PEXEMPT_PATH entry;

                /* 锁外查条目引用（+1），判定过期后删除 */
                entry = (PEXEMPT_PATH)CoLookupHashMapEntry(
                    &Mgr->PathHashMap, keys[i], keySizes[i]);
                if (entry != NULL) {
                    if (entry->ExpireTime.QuadPart != 0 &&
                        currentTime.QuadPart > entry->ExpireTime.QuadPart) {
                        CoRemoveHashMapEntry(&Mgr->PathHashMap, keys[i], keySizes[i]);
                    }
                    ExemptpPathDereference(entry);
                }
            }
        }

        if (keys != NULL) ExFreePoolWithTag(keys, EXEMPT_POOL_TAG_ENTRY);
        if (keySizes != NULL) ExFreePoolWithTag(keySizes, EXEMPT_POOL_TAG_ENTRY);
    }

    /*
     * PID 过期清理：枚举 PidHashMap 收集全部 key，锁外判定过期后删除。
     */
    {
        EXEMPT_PATH_ENUM_CONTEXT enumCtx;
        ULONG count;
        PVOID* keys = NULL;
        ULONG* keySizes = NULL;

        count = (ULONG)ReadAcquire(&Mgr->PidHashMap.ActiveEntries);
        if (count > 0) {
            keys = (PVOID*)ExAllocatePoolZero(
                NonPagedPoolNx, count * sizeof(PVOID), EXEMPT_POOL_TAG_ENTRY);
            keySizes = (ULONG*)ExAllocatePoolZero(
                NonPagedPoolNx, count * sizeof(ULONG), EXEMPT_POOL_TAG_ENTRY);
        }

        if (keys != NULL && keySizes != NULL && count > 0) {
            enumCtx.Keys = keys;
            enumCtx.KeySizes = keySizes;
            enumCtx.Count = 0;
            enumCtx.Capacity = count;
            enumCtx.FreeAll = TRUE;

            CoEnumerateHashMap(&Mgr->PidHashMap, ExemptpPathEnumCollect, &enumCtx);

            for (i = 0; i < enumCtx.Count; i++) {
                PEXEMPT_PID_EXCLUSION pidEntry;

                pidEntry = (PEXEMPT_PID_EXCLUSION)CoLookupHashMapEntry(
                    &Mgr->PidHashMap, keys[i], keySizes[i]);
                if (pidEntry != NULL) {
                    if (pidEntry->ExpireTime.QuadPart != 0 &&
                        currentTime.QuadPart > pidEntry->ExpireTime.QuadPart) {
                        CoRemoveHashMapEntry(&Mgr->PidHashMap, keys[i], keySizes[i]);
                    }
                    ExemptpPidDereference(pidEntry);
                }
            }
        }

        if (keys != NULL) ExFreePoolWithTag(keys, EXEMPT_POOL_TAG_ENTRY);
        if (keySizes != NULL) ExFreePoolWithTag(keySizes, EXEMPT_POOL_TAG_ENTRY);
    }
}

/**************************************************/
/*                  进程退出回收                    */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptsMgrReapPidOnExit(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    进程退出回收：移除 PID 规则表中 ExpireTime==0（TTL=0，"进程退出前有效"）
    的条目。TTL>0 条目仍由清理线程（CleanupExpired）按过期时间回收。

Arguments:
    Engine    - 子系统全局结构体。
    ProcessId - 已退出进程 ID。

Return Value:
    无。
--*/
{
    PEXEMPT_MANAGER Mgr = &Engine->Manager;
    PEXEMPT_PID_EXCLUSION pidEntry;

    PAGED_CODE();

    /*
     * 查 PID 哈希表（key=HANDLE，O(1)），命中且 ExpireTime==0
     * （"进程退出前有效"）→ 摘链删除（Dereference -1）。
     */
    pidEntry = (PEXEMPT_PID_EXCLUSION)CoLookupHashMapEntry(
        &Mgr->PidHashMap, &ProcessId, sizeof(ProcessId));
    if (pidEntry != NULL) {
        if (pidEntry->ExpireTime.QuadPart == 0) {
            CoRemoveHashMapEntry(&Mgr->PidHashMap, &ProcessId, sizeof(ProcessId));
        }
        ExemptpPidDereference(pidEntry);   /* 归还查询引用 */
    }
}
