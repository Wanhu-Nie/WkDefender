/*++
    SelfProtection/RegistryProtection.c - 注册表自保护实现

    Purpose:
        作为独立 CM 回调节点（Callbacks/RegistryCallback.c）的消费者，
        提供注册表自保护的判定能力。维护受保护键列表（静态数组 + 前缀
        匹配），结合引擎注入的豁免回调（受保护进程自改自键放行）对危险
        操作判定 BLOCK 并上报。

        对齐 ShadowStrike SelfProtect.c 的：
        - SHADOWSTRIKE_PROTECTED_REGKEY 键列表 + EX_SPIN_LOCK
        - SspPrefixMatch 前缀匹配
        - ShadowStrikeShouldBlockRegistryAccess 判定链

    Synchronization:
        - EX_SPIN_LOCK 保护键列表；判定路径取共享读、管理路径取排他。

    Copyright (c) WkDefender Team
--*/

#include "RegistryProtection.h"
#include <ntstrsafe.h>

/* ============================================================================
 * 常量定义
 * ============================================================================ */

#define WKD_RG_POOL_TAG                 'tRgW'      /* 保护器池标签 */

/* ============================================================================
 * 注册表保护器结构（不透明句柄的定义）
 * ============================================================================ */

typedef struct _WKD_REGISTRY_PROTECTION {
    EX_SPIN_LOCK               KeyLock;                     /* 键列表保护（共享读/排他写） */
    WKD_RG_PROTECTED_KEY      Keys[WKD_RG_MAX_PROTECTED_KEYS];
    BOOLEAN                   Initialized;

    /* 引擎注入的豁免回调（查 AU：受保护进程自改自键放行） */
    WKD_RG_EXEMPT_CALLBACK    ExemptCallback;
    PVOID                     ExemptContext;
} WKD_REGISTRY_PROTECTION;

/* ============================================================================
 * ALLOC_PRAGMA
 * ============================================================================ */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SpInitializeRegistryProtection)
#pragma alloc_text(PAGE, RgpShutdown)
#pragma alloc_text(PAGE, RgpProtectKey)
#pragma alloc_text(PAGE, RgpUnprotectKey)
#endif

/* ============================================================================
 * 私有: 前缀匹配
 * ============================================================================ */

/*++
    Routine Description:
        判断 KeyPath 是否以存储的键前缀（KeyPath[]）开头（大小写不敏感）。

        对齐 ShadowStrike SspPrefixMatch：纯前缀匹配，不要求完全相等。

    Arguments:
        TestPath    — 待判定的完整键路径。
        Prefix      — 存储的键前缀（WCHAR[]）。
        PrefixCch   — 键前缀字符数。

    Returns:
        TRUE — TestPath 以 Prefix 开头；FALSE — 不匹配。
--*/
static
BOOLEAN
RgpPrefixMatch(
    _In_ PCUNICODE_STRING TestPath,
    _In_ PCWCH Prefix,
    _In_ USHORT PrefixCch
    )
{
    UNICODE_STRING prefixStr;
    UNICODE_STRING testPrefix;

    if (PrefixCch == 0) {
        return FALSE;
    }

    prefixStr.Buffer = (PWCH)Prefix;
    prefixStr.Length = PrefixCch * sizeof(WCHAR);
    prefixStr.MaximumLength = prefixStr.Length;

    if (TestPath->Length < prefixStr.Length) {
        return FALSE;
    }

    testPrefix.Buffer = TestPath->Buffer;
    testPrefix.Length = prefixStr.Length;
    testPrefix.MaximumLength = prefixStr.Length;

    return (RtlCompareUnicodeString(&testPrefix, &prefixStr, TRUE) == 0);
}

/* ============================================================================
 * 私有: 键前缀匹配判定
 * ============================================================================ */

/*++
    Routine Description:
        判断 KeyPath 是否命中受保护键列表（前缀匹配）。

    Arguments:
        KeyPath — 待判定的完整键路径。

    Returns:
        TRUE — 命中受保护键前缀；FALSE — 未命中。
--*/
_IRQL_requires_(PASSIVE_LEVEL)
static
BOOLEAN
RgpIsKeyProtected(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCUNICODE_STRING KeyPath
    )
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN isProtected = FALSE;

    if (Protector == NULL || !Protector->Initialized ||
        KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0) {
        return FALSE;
    }

    oldIrql = ExAcquireSpinLockShared(&Protector->KeyLock);

    for (i = 0; i < WKD_RG_MAX_PROTECTED_KEYS; i++) {
        if (Protector->Keys[i].InUse) {
            if (RgpPrefixMatch(KeyPath,
                               Protector->Keys[i].KeyPath,
                               Protector->Keys[i].KeyPathLength)) {
                isProtected = TRUE;
                break;
            }
        }
    }

    ExReleaseSpinLockShared(&Protector->KeyLock, oldIrql);

    return isProtected;
}

/* ============================================================================
 * 私有: 事件子类型映射与上报
 * ============================================================================ */

/*++
    Routine Description:
        将 REG_NOTIFY_CLASS 映射到 0x5030 段事件子类型。

    Arguments:
        Operation — REG_NOTIFY_CLASS。

    Returns:
        对应事件子类型；未知操作返回 0。
--*/
static
ULONG
RgpOperationToEventSubtype(
    _In_ REG_NOTIFY_CLASS Operation
    )
{
    switch (Operation) {
        case RegNtPreDeleteKey:      return RG_EVENT_SUBTYPE_DELETE_KEY;
        case RegNtPreSetValueKey:    return RG_EVENT_SUBTYPE_SET_VALUE;
        case RegNtPreDeleteValueKey: return RG_EVENT_SUBTYPE_DELETE_VALUE;
        case RegNtPreRenameKey:      return RG_EVENT_SUBTYPE_RENAME_KEY;
        case RegNtPreSetKeySecurity: return RG_EVENT_SUBTYPE_SET_SECURITY;
        default:                     return 0;
    }
}

/* ============================================================================
 * 公共 API
 * ============================================================================ */

/*++
    Routine Description:
        分配并初始化注册表保护器，注入豁免回调。

        豁免回调由引擎提供（Context = Engine），2026-09-05 起受保护判定
        收敛为 Pap 画像（PapProfile 非零），使受保护进程自改自键放行。

    Arguments:
        Protector      — 输出保护器句柄。
        ExemptCallback — 豁免判定回调（引擎注入）。
        Context        — 豁免回调上下文（Engine）。

    Returns:
        STATUS_SUCCESS / STATUS_NO_MEMORY / STATUS_INVALID_PARAMETER。
--*/
_Use_decl_annotations_
NTSTATUS
SpInitializeRegistryProtection(
    _Out_ PWKD_REGISTRY_PROTECTION* Protection,
    _In_ const WKD_RG_EXEMPT_CALLBACK ExemptCallback,
    _In_opt_ const PVOID Context
    )
{
    PWKD_REGISTRY_PROTECTION protection;

    PAGED_CODE();

    if (!Protection || !ExemptCallback) {
        return STATUS_INVALID_PARAMETER;
    }
    *Protection = NULL;

    protection = (PWKD_REGISTRY_PROTECTION)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(WKD_REGISTRY_PROTECTION),
        WKD_RG_POOL_TAG
    );
    if (!protection) return STATUS_NO_MEMORY;

    KeInitializeSpinLock(&protection->KeyLock);
    protection->ExemptCallback = ExemptCallback;
    protection->ExemptContext = Context;
    protection->Initialized = TRUE;

    *Protection = protection;
    return STATUS_SUCCESS;
}

/*++
    Routine Description:
        释放注册表保护器。

        调用前提：CM 回调节点已注销（Callbacks/RegistryCallback.c 的
        CbRegistryCleanup 已执行），无并发 RgpShouldBlockRegistryAccess 进入。

    Arguments:
        Protector — 保护器句柄（NULL 安全）。

    Returns:
        无。
--*/
_Use_decl_annotations_
VOID
RgpShutdown(
    _Inout_ PWKD_REGISTRY_PROTECTION Protector
    )
{
    if (Protector == NULL) {
        return;
    }

    Protector->Initialized = FALSE;

    ExFreePoolWithTag(Protector, WKD_RG_POOL_TAG);
}

/*++
    Routine Description:
        保护一个注册表键/键前缀（前缀匹配生效）。

        在静态数组中找到第一个空闲槽位填充。重复保护同一前缀返回
        STATUS_OBJECT_NAME_EXISTS。

    Arguments:
        Protector — 保护器句柄。
        KeyPath   — 待保护键路径（宽字符串，最大 511 字符）。

    Returns:
        STATUS_SUCCESS / STATUS_OBJECT_NAME_EXISTS / STATUS_INSUFFICIENT_RESOURCES
        / STATUS_INVALID_PARAMETER / STATUS_NO_MEMORY。
--*/
_Use_decl_annotations_
NTSTATUS
RgpProtectKey(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCWSTR KeyPath
    )
{
    SIZE_T pathLen = 0;
    KIRQL oldIrql;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    ULONG i;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized || KeyPath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 安全测量长度（含 NUL），上限 WKD_RG_MAX_KEY_PATH_LEN */
    status = RtlStringCchLengthW(KeyPath, WKD_RG_MAX_KEY_PATH_LEN, (size_t*)&pathLen);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* pathLen 为字符数（不含 NUL） */

    oldIrql = ExAcquireSpinLockExclusive(&Protector->KeyLock);

    /* 判重：相同前缀已保护 */
    for (i = 0; i < WKD_RG_MAX_PROTECTED_KEYS; i++) {
        if (Protector->Keys[i].InUse &&
            Protector->Keys[i].KeyPathLength == (USHORT)pathLen &&
            RtlCompareMemory(Protector->Keys[i].KeyPath, KeyPath,
                             pathLen * sizeof(WCHAR)) == pathLen * sizeof(WCHAR)) {
            ExReleaseSpinLockExclusive(&Protector->KeyLock, oldIrql);
            return STATUS_OBJECT_NAME_EXISTS;
        }
    }

    /* 找空闲槽位 */
    for (i = 0; i < WKD_RG_MAX_PROTECTED_KEYS; i++) {
        if (!Protector->Keys[i].InUse) {
            Protector->Keys[i].KeyPathLength = (USHORT)pathLen;
            RtlCopyMemory(Protector->Keys[i].KeyPath, KeyPath, pathLen * sizeof(WCHAR));
            Protector->Keys[i].KeyPath[pathLen] = L'\0';
            Protector->Keys[i].InUse = TRUE;
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleaseSpinLockExclusive(&Protector->KeyLock, oldIrql);

    return status;
}

/*++
    Routine Description:
        注销对一个注册表键/键前缀的保护。

    Arguments:
        Protector — 保护器句柄。
        KeyPath   — 注销保护的键路径。

    Returns:
        无。
--*/
_Use_decl_annotations_
VOID
RgpUnprotectKey(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCWSTR KeyPath
    )
{
    SIZE_T pathLen = 0;
    KIRQL oldIrql;
    NTSTATUS status;
    ULONG i;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized || KeyPath == NULL) {
        return;
    }

    status = RtlStringCchLengthW(KeyPath, WKD_RG_MAX_KEY_PATH_LEN, (size_t*)&pathLen);
    if (!NT_SUCCESS(status)) {
        return;
    }

    oldIrql = ExAcquireSpinLockExclusive(&Protector->KeyLock);

    for (i = 0; i < WKD_RG_MAX_PROTECTED_KEYS; i++) {
        if (Protector->Keys[i].InUse &&
            Protector->Keys[i].KeyPathLength == (USHORT)pathLen &&
            RtlCompareMemory(Protector->Keys[i].KeyPath, KeyPath,
                             pathLen * sizeof(WCHAR)) == pathLen * sizeof(WCHAR)) {
            RtlZeroMemory(&Protector->Keys[i], sizeof(Protector->Keys[i]));
            break;
        }
    }

    ExReleaseSpinLockExclusive(&Protector->KeyLock, oldIrql);
}

/*++
    Routine Description:
        判定是否应 BLOCK 对路径的注册表操作。

        由 CM 回调节点（RegistryCallback.c）经引擎公共入口
        SpEngineShouldBlockRegistryAccess 转调。决策链：
          1. 豁免回调（引擎注入，查 AU：受保护进程自改自键放行）
          2. 键前缀匹配（RgpIsKeyProtected）
          3. 危险操作过滤（DeleteKey/SetValue/DeleteValue/Rename/SetSecurity；
             注：CreateKeyEx 不拦截——新键创建后可被后续操作拦截）
          4. 命中则计数 + 按操作上报 0x5030 段，返回 TRUE

    Arguments:
        Protector        — 保护器句柄。
        KeyPath          — 受操作键完整路径。
        Operation        — REG_NOTIFY_CLASS 操作类型。
        RequestorProcessId — 发起请求的进程 PID。

    Returns:
        TRUE — 应 BLOCK（调用方返回 STATUS_ACCESS_DENIED）；
        FALSE — 放行。
--*/
_Use_decl_annotations_
BOOLEAN
RgpShouldBlockRegistryAccess(
    _In_ PWKD_REGISTRY_PROTECTION Protector,
    _In_ PCUNICODE_STRING KeyPath,
    _In_ REG_NOTIFY_CLASS Operation,
    _In_ HANDLE RequestorProcessId
    )
{
    ULONG eventSubtype;

    if (Protector == NULL || !Protector->Initialized ||
        KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0) {
        return FALSE;
    }

    /* 1. 豁免：受保护进程自改自键放行 */
    if (Protector->ExemptCallback != NULL &&
        Protector->ExemptCallback(RequestorProcessId, Protector->ExemptContext)) {
        return FALSE;
    }

    /* 2. 键前缀匹配 */
    if (!RgpIsKeyProtected(Protector, KeyPath)) {
        return FALSE;
    }

    /* 3. 危险操作过滤 */
    switch (Operation) {
        case RegNtPreDeleteKey:
        case RegNtPreSetValueKey:
        case RegNtPreDeleteValueKey:
        case RegNtPreRenameKey:
        case RegNtPreSetKeySecurity:
            break;
        default:
            /* RegNtPreCreateKeyEx 等不拦截 */
            return FALSE;
    }

    /* 4. 命中：上报 0x5030 段事件 */
    eventSubtype = RgpOperationToEventSubtype(Operation);
    if (eventSubtype != 0) {
        (VOID)WkdReportSelfProtectionEvent(
            eventSubtype,
            7,   /* Severity */
            L"Blocked registry change to protected key"
            );
    }

#if DBG
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "[WkDefender] BLOCKED registry change (PID=%p, Op=%d, Path=%wZ)\n",
        RequestorProcessId, (int)Operation, KeyPath);
#endif

    return TRUE;
}