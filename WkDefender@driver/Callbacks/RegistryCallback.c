/*++
    Callbacks/RegistryCallback.c - 注册表回调节点实现

    Purpose:
        注册表配置变更的综合 CM 回调节点（独立于自防护）。
        机制（从 ShadowStrike RegistryCallback.c 迁移，适配 WkDefender）：
        1. 注册 CmRegisterCallbackEx（altitude L"380050"），拦截如下 Pre 操作：
           - RegNtPreDeleteKey      删除键
           - RegNtPreSetValueKey    设置键值
           - RegNtPreDeleteValueKey 删除键值
           - RegNtPreRenameKey      重命名键
           - RegNtPreCreateKeyEx    创建子键
           - RegNtPreSetKeySecurity 修改键安全描述符
        2. 对每类操作提取受操作键对象（CreateKeyEx 取 RootObject 父键对象）。
        3. ObQueryNameString 解析键完整路径（含 CreateKeyEx 时按
           RootObject + "\\" + CompleteName 拼接）。
        4. 调用自防护引擎判定入口 SpEngineShouldBlockRegistryAccess
           （路径, 操作, 请求者 PID）。返回 TRUE 则本节点向上返回
           STATUS_ACCESS_DENIED 阻断本次注册表变更。

        本节点【不】内嵌判定/豁免/键表/上报——全部由自防护子系统消费。

    Synchronization:
        - g_RegistryInitialized / g_RegistryLock (FAST_MUTEX) 串行化初始
          化与清理；CbRegistryCallbackRoutine 由 CM 在 PASSIVE_LEVEL 调用，
          卸载钩子后不再有并发进入。

    Copyright (c) WkDefender Team
--*/

#include "RegistryCallback.h"
#include "../Common/Utils.h"     /* WkdDriverObject 全局（驱动对象句柄） */
#include "../SelfProtection/SelfProtectionEngine.h"  /* 自防护引擎公共入口（BLOCK 判定消费） */
#include <ntstrsafe.h>

/* ============================================================================
 * 常量定义
 * ============================================================================ */

#define WKD_REG_POOL_TAG                'tRgW'      /* 路径缓冲区池标签 */

#define WKD_REG_MAX_PATH_STR_LEN        512         /* 键路径最大字符数（含 NUL） */
#define WKD_REG_MAX_PATH_ALLOCATION     (WKD_REG_MAX_PATH_STR_LEN * sizeof(WCHAR))

/* 注册表回调 Altitude（与 ShadowStrike 对齐，WHQL 提交前须在微软注册） */
#define WKD_REG_ALTITUDE                L"380050"

/* ============================================================================
 * 全局状态
 * ============================================================================ */

static BOOLEAN       g_RegistryInitialized;
static FAST_MUTEX    g_RegistryLock;
static LARGE_INTEGER g_RegistryCallbackCookie;       /* CmRegisterCallbackEx 返回的钩子 cookie */

/* 统计 */
static struct {
    volatile LONG64 PathBuildTruncates;  /* CreateKeyEx 完整路径拼接溢出降级次数 */
    volatile LONG64 BlockedOperations;   /* 经引擎判定被 BLOCK 的注册表操作次数 */
} g_RegistryStats;

/* ============================================================================
 * 私有: 键路径解析
 * ============================================================================ */

/*++
    Routine Description:
        解析键对象完整路径（ObQueryNameString）。

        两次调用：第一次查询所需缓冲区大小，第二次实际填充。
        溢出保护：路径长度超上限或整数溢出时返回错误（由调用方降级跳过）。

    Arguments:
        KeyObject — 键对象（PREG_KEY）。
        KeyPath   — 输出 UNICODE_STRING（Buffer 为 PagedPool 分配，调用方负责释放）。

    Returns:
        STATUS_SUCCESS                   — 路径解析成功
        STATUS_OBJECT_NAME_NOT_FOUND     — 对象无名称（忽略）
        STATUS_NAME_TOO_LONG             — 路径超上限（忽略）
        其他 NTSTATUS                    — 失败（忽略）
--*/
_Use_decl_annotations_
static
NTSTATUS
RegGetKeyObjectPath(
    _In_ PVOID KeyObject,
    _Out_ PUNICODE_STRING KeyPath
    )
{
    NTSTATUS status;
    ULONG returnLength = 0;
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    ULONG allocationSize;

    PAGED_CODE();

    RtlZeroMemory(KeyPath, sizeof(UNICODE_STRING));

    if (KeyObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 第一次查询所需大小 */
    status = ObQueryNameString(KeyObject, NULL, 0, &returnLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        if (status == STATUS_SUCCESS) {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        return status;
    }

    /* 溢出保护：长度上限 */
    if (returnLength > WKD_REG_MAX_PATH_ALLOCATION) {
        return STATUS_NAME_TOO_LONG;
    }

    /* 溢出保护：integer overflow */
    allocationSize = returnLength + sizeof(WCHAR);
    if (allocationSize < returnLength) {
        return STATUS_INTEGER_OVERFLOW;
    }

    nameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolZero(
        PagedPool,
        allocationSize,
        WKD_REG_POOL_TAG
    );
    if (nameInfo == NULL) {
        return STATUS_NO_MEMORY;
    }

    /* 第二次实际填充 */
    status = ObQueryNameString(KeyObject, nameInfo, returnLength, &returnLength);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(nameInfo, WKD_REG_POOL_TAG);
        return status;
    }

    /* 深拷贝到调用方缓冲区 */
    KeyPath->MaximumLength = nameInfo->Name.Length + sizeof(WCHAR);
    KeyPath->Buffer = (PWCH)ExAllocatePoolZero(
        PagedPool,
        KeyPath->MaximumLength,
        WKD_REG_POOL_TAG
    );
    if (KeyPath->Buffer == NULL) {
        ExFreePoolWithTag(nameInfo, WKD_REG_POOL_TAG);
        return STATUS_NO_MEMORY;
    }

    KeyPath->Length = nameInfo->Name.Length;
    RtlCopyMemory(KeyPath->Buffer, nameInfo->Name.Buffer, nameInfo->Name.Length);
    KeyPath->Buffer[KeyPath->Length / sizeof(WCHAR)] = L'\0';

    ExFreePoolWithTag(nameInfo, WKD_REG_POOL_TAG);

    return STATUS_SUCCESS;
}

/* ============================================================================
 * CM 回调例行函数
 * ============================================================================ */

/*++
    Routine Description:
        CM（Config Manager）pre-operation 回调例行函数。

        1. allow-list 只处理 6 类 Pre 操作（Argument1 携带 REG_NOTIFY_CLASS，
           非指针），其余直接放行。
        2. 提取受操作键对象：CreateKeyEx 取 RootObject（父键），其余取
           Argument2 中的键对象。
        3. 解析键完整路径（CreateKeyEx 时拼接 RootObject + "\\" + CompleteName）。
        4. 调用引擎判定入口 SpEngineShouldBlockRegistryAccess。
        5. BLOCK（返回 TRUE）则返回 STATUS_ACCESS_DENIED。

    注意:
        - Argument1 是 REG_NOTIFY_CLASS 值（ULONG），RegNtPreDeleteKey 定义
          为 0；`if (Argument1 == NULL)` 守卫会静默丢弃每个 delete-key 通知。
        - 路径解析失败时不阻断（降级放行）：自我保护是尽力而为，避免
          破坏系统正常注册表写操作。

    Arguments:
        CallbackContext — 注册时传入（本驱动未使用，NULL）。
        Argument1       — REG_NOTIFY_CLASS（ULONG，非指针）。
        Argument2       — 操作上下文（不同操作类型结构不同）。

    Returns:
        返回 STATUS_ACCESS_DENIED 表示 BLOCK；否则返回 STATUS_SUCCESS
        放行（或让引擎判定维持默认状态）。
--*/
_Use_decl_annotations_
NTSTATUS
CbRegistryCallbackRoutine(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    REG_NOTIFY_CLASS notifyClass;
    PVOID keyObject = NULL;
    PREG_CREATE_KEY_INFORMATION createInfo;
    UNICODE_STRING keyPath;
    HANDLE processId;
    BOOLEAN shouldBlock = FALSE;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CallbackContext);

    /* Argument1 携带 REG_NOTIFY_CLASS 值（非指针） */
    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    /* allow-list：只处理本节点关注的 6 类 Pre 操作 */
    switch (notifyClass) {
        case RegNtPreDeleteKey:
        case RegNtPreSetValueKey:
        case RegNtPreDeleteValueKey:
        case RegNtPreRenameKey:
        case RegNtPreCreateKeyEx:
        case RegNtPreSetKeySecurity:
            break;
        default:
            return STATUS_SUCCESS;
    }

    processId = PsGetCurrentProcessId();

    /* 提取受操作键对象（各 Pre 结构字段均为 PVOID） */
    switch (notifyClass) {
        case RegNtPreCreateKeyEx:
            /* CreateKeyEx：父键对象 = RootObject；CompleteName 为相对子键名 */
            createInfo = (PREG_CREATE_KEY_INFORMATION)Argument2;
            keyObject = createInfo->RootObject;
            break;

        case RegNtPreDeleteKey:
            keyObject = ((PREG_DELETE_KEY_INFORMATION)Argument2)->Object;
            break;

        case RegNtPreSetValueKey:
            keyObject = ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Object;
            break;

        case RegNtPreDeleteValueKey:
            keyObject = ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->Object;
            break;

        case RegNtPreRenameKey:
            keyObject = ((PREG_RENAME_KEY_INFORMATION)Argument2)->Object;
            break;

        case RegNtPreSetKeySecurity:
            keyObject = ((PREG_SET_KEY_SECURITY_INFORMATION)Argument2)->Object;
            break;

        default:
            keyObject = NULL;
            break;
    }

    if (keyObject == NULL) {
        return STATUS_SUCCESS;
    }

    /* 解析父键路径 */
    status = RegGetKeyObjectPath(keyObject, &keyPath);
    if (!NT_SUCCESS(status)) {
        /* 路径解析失败：尽力而为，降级放行（不阻断系统注册表写） */
        return STATUS_SUCCESS;
    }

    /* CreateKeyEx：拼接完整路径 = RootObject + "\\" + CompleteName */
    if (notifyClass == RegNtPreCreateKeyEx) {
        createInfo = (PREG_CREATE_KEY_INFORMATION)Argument2;
        if (createInfo->CompleteName != NULL &&
            createInfo->CompleteName->Buffer != NULL &&
            createInfo->CompleteName->Length > 0) {
            USHORT separatorLen = sizeof(WCHAR);
            ULONG totalLen = (ULONG)keyPath.Length + (ULONG)separatorLen +
                             (ULONG)createInfo->CompleteName->Length;
            PWCH fullBuffer;

            if (totalLen > WKD_REG_MAX_PATH_ALLOCATION || totalLen > MAXUSHORT) {
                /* 溢出：继续用父键路径判定 */
                InterlockedIncrement64(&g_RegistryStats.PathBuildTruncates);
                goto BlockAdvise;
            }

            fullBuffer = (PWCH)ExAllocatePoolZero(
                PagedPool,
                (SIZE_T)totalLen + sizeof(WCHAR),
                WKD_REG_POOL_TAG
            );
            if (fullBuffer != NULL) {
                RtlCopyMemory(fullBuffer, keyPath.Buffer, keyPath.Length);
                fullBuffer[keyPath.Length / sizeof(WCHAR)] = L'\\';
                RtlCopyMemory(
                    (PUCHAR)fullBuffer + keyPath.Length + separatorLen,
                    createInfo->CompleteName->Buffer,
                    createInfo->CompleteName->Length
                );
                fullBuffer[totalLen / sizeof(WCHAR)] = L'\0';

                ExFreePoolWithTag(keyPath.Buffer, WKD_REG_POOL_TAG);
                keyPath.Buffer = fullBuffer;
                keyPath.Length = (USHORT)totalLen;
                keyPath.MaximumLength = (USHORT)totalLen + sizeof(WCHAR);
            }
        }
    }

BlockAdvise:
    /* 交给自防护引擎判定（引擎内部复用 rundown，外部异步入口语义一致） */
    shouldBlock = SpEngineShouldBlockRegistryAccess(&keyPath, notifyClass, processId);

    /* 释放路径缓冲区 */
    if (keyPath.Buffer != NULL) {
        ExFreePoolWithTag(keyPath.Buffer, WKD_REG_POOL_TAG);
    }

    if (shouldBlock) {
        InterlockedIncrement64(&g_RegistryStats.BlockedOperations);
#if DBG
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] BLOCKED registry operation (PID=%p, Op=%d, Path=%wZ)\n",
            processId, (int)notifyClass, &keyPath);
#endif
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

/* ============================================================================
 * 注册 / 注销
 * ============================================================================ */

/*++
    Routine Description:
        注册 CmRegisterCallbackEx（altitude L"380050"）。

        使用互斥锁串行化，防止并发重复注册覆盖 cookie。
        失败时返回错误（由 WkdEntry 以非致命方式处理）。

    Arguments:
        DriverObject — 驱动对象（回调上下文归属）。

    Returns:
        STATUS_SUCCESS                                   — 注册成功
        STATUS_ALREADY_REGISTERED                        — 已注册
        CmRegisterCallbackEx 返回的其他 NTSTATUS        — 注册失败
--*/
_Use_decl_annotations_
NTSTATUS
CbRegistryInitialize(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;
    UNICODE_STRING altitude;

    PAGED_CODE();

    ExAcquireFastMutex(&g_RegistryLock);

    if (g_RegistryInitialized) {
        ExReleaseFastMutex(&g_RegistryLock);
        return STATUS_ALREADY_REGISTERED;
    }

    RtlInitUnicodeString(&altitude, WKD_REG_ALTITUDE);

    status = CmRegisterCallbackEx(
        CbRegistryCallbackRoutine,
        &altitude,
        DriverObject,
        NULL,   /* Context */
        &g_RegistryCallbackCookie,
        NULL    /* Reserved */
    );

    if (!NT_SUCCESS(status)) {
        g_RegistryCallbackCookie.QuadPart = 0;
        ExReleaseFastMutex(&g_RegistryLock);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] CbRegistryInitialize: CmRegisterCallbackEx failed: 0x%08X\n",
            status);
        return status;
    }

    g_RegistryInitialized = TRUE;

    ExReleaseFastMutex(&g_RegistryLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] RegistryCallback module initialized\n");

    return STATUS_SUCCESS;
}

/*++
    Routine Description:
        注销 CmUnRegisterCallback。

        使用互斥锁串行化；原子快照并清零 cookie，防止重复注销。
        调用方（WkdEntry）须在驱动卸载的 callbacks 清整阶段调用，
        先于自防护引擎 Shutdown，保证不再有回调进入引擎判定。

    Arguments:
        无。

    Returns:
        无。
--*/
_Use_decl_annotations_
VOID
CbRegistryCleanup(
    VOID
    )
{
    LARGE_INTEGER cookie;
    NTSTATUS status;

    PAGED_CODE();

    ExAcquireFastMutex(&g_RegistryLock);

    if (!g_RegistryInitialized) {
        ExReleaseFastMutex(&g_RegistryLock);
        return;
    }

    /* 原子快照 cookie 并清零，防重复注销 */
    cookie.QuadPart = InterlockedExchange64(
        (volatile LONG64*)&g_RegistryCallbackCookie.QuadPart,
        0);
    g_RegistryInitialized = FALSE;

    ExReleaseFastMutex(&g_RegistryLock);

    if (cookie.QuadPart == 0) {
        return;
    }

    status = CmUnRegisterCallback(cookie);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] CbRegistryCleanup: CmUnRegisterCallback failed: 0x%08X (cookie=0x%I64X)\n",
            status, cookie.QuadPart);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] RegistryCallback module cleaned up "
        "(blocked=%lld)\n",
        g_RegistryStats.BlockedOperations);
}