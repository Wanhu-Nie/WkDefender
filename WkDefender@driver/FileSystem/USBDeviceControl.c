/**************************************************/
/*  USBDeviceControl 可移除设备控制（死代码）       */
/*  迁移自 SS USBDeviceControl（全量功能面对齐）    */
/**************************************************/

#include <fltKernel.h>
#include <ntifs.h>
#include <ntddstor.h>
#include <ntstrsafe.h>
#include "USBDeviceControl.h"

/*++
 * 模块职责（死代码，未接入流水线）：
 *   可移除存储设备访问控制（防数据外泄 T1052.001 / BadUSB T1200 /
 *   autorun 感染 T1091 / T1204.002）：
 *     - 可移动卷识别（FltGetVolumeProperties FILE_REMOVABLE_MEDIA）
 *     - 设备身份提取：STORAGE_DEVICE_DESCRIPTOR（总线类型+序列号）+
 *       PDO 硬件 ID（VID_xxxx/PID_xxxx）
 *     - 策略解析：黑名单 → 白名单 → 默认策略（Allow/ReadOnly/Block/Audit）
 *     - 写阻断（ReadOnly 卷）：WkdUdcIsWriteBlocked / WkdUdcIsSetInfoBlocked
 *     - autorun.inf 阻断：WkdUdcCheckAutorun
 *     - 卷追踪：WkdUdcNotifyVolumeMount / WkdUdcNotifyVolumeDismount
 *     - 规则管理：WkdUdcAddRule / RemoveRule / ClearRules / UpdateConfig
 *     - 统计：WkdUdcGetStatistics
 *
 * 迁移来源：ShadowStrike Callbacks/FileSystem/USBDeviceControl.c（2026-08
 *           全量功能面对齐，重功能实现非复制）
 *
 * 接入前提（未接入原因）：
 *   1. 需 InstanceSetup 钩子（NotifyVolumeMount/Dismount 由 Filter.c 的
 *      InstanceSetup/Teardown 回调调用，当前 wkd 用默认 InstanceSetup）；
 *   2. 阻断上报需接入 wkd 通知链路（SS BeEngineSubmitEvent 在 wkd 无对应，
 *      TODO 标注接入点）。
 *
 * 未迁移项说明（对齐 SS 实际功能面，非遗漏）：
 *   1. BadUSB/Rubber Ducky 键盘注入检测（T1200）—— SS 头文件声明，.c 无实现，不迁；
 *   2. UDC_EVENT_POOL_TAG —— SS 定义未使用，不迁；
 *   3. 设备类细分（CDROM/HID/Network/Printer）—— SS 枚举有定义但 UdcpQueryDeviceInfo
 *      仅映射 MassStorage/Other，行为对齐；
 *   4. WKD_UDC_TRACKED_VOLUME.VolumeSerial —— SS 定义未填充，字段保留不赋值；
 *   5. WKD_UDC_MAX_AUTORUN_SIZE(64K) 大小限制逻辑 —— SS 仅定义常量未实现，常量保留。
 *
 *   本文件与 EDR 核心链路解耦，独立立项，当前整体为死代码。
 *--*/

#pragma warning(push)
#pragma warning(disable: 4505)  /* unreferenced local function（死代码分区） */
#pragma warning(disable: 4100)  /* unreferenced formal parameter */

/**************************************************/
/*                      私有类型                   */
/**************************************************/

typedef struct _WKD_UDC_STATE {

    /* 生命周期 */
    volatile LONG       State;          /* 0=uninit, 1=init, 2=ready, 3=shutdown */
    EX_RUNDOWN_REF      RundownRef;

    /* 设备规则 */
    LIST_ENTRY          WhitelistHead;
    LIST_ENTRY          BlacklistHead;
    EX_PUSH_LOCK        RulesLock;
    volatile LONG       WhitelistCount;
    volatile LONG       BlacklistCount;
    volatile LONG       NextRuleId;

    /* 已追踪卷 */
    LIST_ENTRY          VolumeListHead;
    EX_PUSH_LOCK        VolumeLock;
    volatile LONG       VolumeCount;

    /* 配置与统计 */
    WKD_UDC_CONFIG      Config;
    WKD_UDC_STATISTICS  Stats;

    /* 卷分配器 */
    NPAGED_LOOKASIDE_LIST VolumeLookaside;

} WKD_UDC_STATE, *PWKD_UDC_STATE;

/**************************************************/
/*                      全局状态                   */
/**************************************************/

static WKD_UDC_STATE g_WkdUdcState;

/**************************************************/
/*                      常量定义                   */
/**************************************************/

static const UNICODE_STRING g_WkdAutorunFileName =
    RTL_CONSTANT_STRING(L"autorun.inf");

/**************************************************/
/*                      函数声明                   */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdUdcIsRemovableVolume(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

_IRQL_requires_(PASSIVE_LEVEL)
static PWKD_UDC_TRACKED_VOLUME
WkdUdcFindVolumeUnlocked(
    _In_ PFLT_INSTANCE Instance
    );

_IRQL_requires_(PASSIVE_LEVEL)
static WKD_UDC_DEVICE_POLICY
WkdUdcResolvePolicy(
    _In_ USHORT VendorId,
    _In_ USHORT ProductId,
    _In_opt_ PCWSTR SerialNumber,
    _In_ WKD_UDC_DEVICE_CLASS DeviceClass
    );

static BOOLEAN
WkdUdcEnterOperation(
    VOID
    );

static VOID
WkdUdcLeaveOperation(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdUdcQueryDeviceInfo(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PUSHORT VendorId,
    _Out_ PUSHORT ProductId,
    _Out_writes_(WKD_UDC_SERIAL_MAX_LENGTH) PWCHAR SerialNumber,
    _Out_ PUSHORT SerialLength,
    _Out_ PWKD_UDC_DEVICE_CLASS DeviceClass
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdUdcSendStorageQuery(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PSTORAGE_DEVICE_DESCRIPTOR *Descriptor
    );

_IRQL_requires_(PASSIVE_LEVEL)
static PDEVICE_OBJECT
WkdUdcGetPhysicalDeviceObject(
    _In_ PDEVICE_OBJECT DeviceObject
    );

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdUdcParseHardwareIdForVidPid(
    _In_reads_bytes_(LengthInBytes) PCWSTR HardwareId,
    _In_ ULONG LengthInBytes,
    _Out_ PUSHORT VendorId,
    _Out_ PUSHORT ProductId
    );

_IRQL_requires_(PASSIVE_LEVEL)
static USHORT
WkdUdcParseHex4(
    _In_reads_(AvailableChars) PCWSTR Str,
    _In_ ULONG AvailableChars
    );

/**************************************************/
/*                    分页段映射                   */
/**************************************************/

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, WkdUdcInitialize)
#pragma alloc_text(PAGE, WkdUdcShutdown)
#pragma alloc_text(PAGE, WkdUdcCheckVolumePolicy)
#pragma alloc_text(PAGE, WkdUdcNotifyVolumeMount)
#pragma alloc_text(PAGE, WkdUdcNotifyVolumeDismount)
#pragma alloc_text(PAGE, WkdUdcAddRule)
#pragma alloc_text(PAGE, WkdUdcRemoveRule)
#pragma alloc_text(PAGE, WkdUdcClearRules)
#pragma alloc_text(PAGE, WkdUdcUpdateConfig)
#pragma alloc_text(PAGE, WkdUdcIsRemovableVolume)
#pragma alloc_text(PAGE, WkdUdcQueryDeviceInfo)
#pragma alloc_text(PAGE, WkdUdcSendStorageQuery)
#pragma alloc_text(PAGE, WkdUdcGetPhysicalDeviceObject)
#endif

/**************************************************/
/*                    生命周期                     */
/**************************************************/

/*
 * WkdUdcInitialize
 *   初始化 USB 设备控制模块（状态机 0→1→2 + rundown 防护 + lookaside）。
 *   默认配置：Audit 模式（记录不阻断）+ autorun 阻断开 + 写保护开。
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
WkdUdcInitialize(
    VOID
    )
{
    LONG previousState;

    PAGED_CODE();

    previousState = InterlockedCompareExchange(&g_WkdUdcState.State, 1, 0);
    if (previousState != 0) {
        return (previousState == 2) ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
    }

    ExInitializeRundownProtection(&g_WkdUdcState.RundownRef);

    InitializeListHead(&g_WkdUdcState.WhitelistHead);
    InitializeListHead(&g_WkdUdcState.BlacklistHead);
    ExInitializePushLock(&g_WkdUdcState.RulesLock);
    g_WkdUdcState.WhitelistCount = 0;
    g_WkdUdcState.BlacklistCount = 0;
    g_WkdUdcState.NextRuleId = 1;

    InitializeListHead(&g_WkdUdcState.VolumeListHead);
    ExInitializePushLock(&g_WkdUdcState.VolumeLock);
    g_WkdUdcState.VolumeCount = 0;

    /* WKD_UDC-5：NPagedPool 自 Win8+ 已不可执行，lookaside Flags 用 0 */
    ExInitializeNPagedLookasideList(
        &g_WkdUdcState.VolumeLookaside,
        NULL,
        NULL,
        0,
        sizeof(WKD_UDC_TRACKED_VOLUME),
        WKD_UDC_DEVICE_POOL_TAG,
        0
        );

    /* 默认配置：Audit 模式 */
    g_WkdUdcState.Config.DefaultPolicy = WkdUdcPolicy_Audit;
    g_WkdUdcState.Config.EnableAutorunBlocking = TRUE;
    g_WkdUdcState.Config.EnableWriteProtection = TRUE;
    g_WkdUdcState.Config.EnableAuditLogging = TRUE;
    g_WkdUdcState.Config.Enabled = TRUE;

    RtlZeroMemory(&g_WkdUdcState.Stats, sizeof(WKD_UDC_STATISTICS));

    InterlockedExchange(&g_WkdUdcState.State, 2);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WkDefender/UDC] USB Device Control initialized "
               "(DefaultPolicy=%d, AutorunBlock=%d)\n",
               g_WkdUdcState.Config.DefaultPolicy,
               g_WkdUdcState.Config.EnableAutorunBlocking);

    return STATUS_SUCCESS;
}

/*
 * WkdUdcShutdown
 *   逆序清理：等 rundown 释放 → 清卷表(lookaside 归还) → 清两规则表 → 删锁。
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdUdcShutdown(
    VOID
    )
{
    PLIST_ENTRY listEntry;

    PAGED_CODE();

    if (InterlockedCompareExchange(&g_WkdUdcState.State, 3, 2) != 2) {
        return;
    }

    ExWaitForRundownProtectionRelease(&g_WkdUdcState.RundownRef);

    /* 释放已追踪卷 */
    FltAcquirePushLockExclusive(&g_WkdUdcState.VolumeLock);
    while (!IsListEmpty(&g_WkdUdcState.VolumeListHead)) {
        listEntry = RemoveHeadList(&g_WkdUdcState.VolumeListHead);
        PWKD_UDC_TRACKED_VOLUME volume = CONTAINING_RECORD(
            listEntry, WKD_UDC_TRACKED_VOLUME, Link);
        ExFreeToNPagedLookasideList(&g_WkdUdcState.VolumeLookaside, volume);
    }
    FltReleasePushLock(&g_WkdUdcState.VolumeLock);

    /* 释放全部规则 */
    FltAcquirePushLockExclusive(&g_WkdUdcState.RulesLock);
    while (!IsListEmpty(&g_WkdUdcState.WhitelistHead)) {
        listEntry = RemoveHeadList(&g_WkdUdcState.WhitelistHead);
        PWKD_UDC_DEVICE_RULE rule = CONTAINING_RECORD(
            listEntry, WKD_UDC_DEVICE_RULE, Link);
        ExFreePoolWithTag(rule, WKD_UDC_DEVICE_POOL_TAG);
    }
    while (!IsListEmpty(&g_WkdUdcState.BlacklistHead)) {
        listEntry = RemoveHeadList(&g_WkdUdcState.BlacklistHead);
        PWKD_UDC_DEVICE_RULE rule = CONTAINING_RECORD(
            listEntry, WKD_UDC_DEVICE_RULE, Link);
        ExFreePoolWithTag(rule, WKD_UDC_DEVICE_POOL_TAG);
    }
    FltReleasePushLock(&g_WkdUdcState.RulesLock);

    ExDeleteNPagedLookasideList(&g_WkdUdcState.VolumeLookaside);
    /* ExDeletePushLock 并非有效内核 API（wdm.h 无此声明）。EX_PUSH_LOCK
     * 是内存内原语，无需清理——置零即可（对齐其余 EX_PUSH_LOCK 使用点）。
     * 原：ExDeletePushLock(&g_WkdUdcState.RulesLock);
     *     ExDeletePushLock(&g_WkdUdcState.VolumeLock); */
    RtlZeroMemory(&g_WkdUdcState.RulesLock, sizeof(EX_PUSH_LOCK));
    RtlZeroMemory(&g_WkdUdcState.VolumeLock, sizeof(EX_PUSH_LOCK));

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WkDefender/UDC] Shutdown complete. "
               "Mounts=%lld, WritesBlocked=%lld, AutorunBlocked=%lld\n",
               g_WkdUdcState.Stats.VolumeMounts,
               g_WkdUdcState.Stats.WritesBlocked,
               g_WkdUdcState.Stats.AutorunBlocked);
}

/**************************************************/
/*                    策略检查                     */
/**************************************************/

/*
 * WkdUdcCheckVolumePolicy
 *   InstanceSetup 回调调用。判断是否可移除卷 → 提取设备信息 → 解析策略。
 *   Block 策略 → 返回 FALSE（拒绝附加）；ReadOnly/Audit/Allow → 返回 TRUE。
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
BOOLEAN
WkdUdcCheckVolumePolicy(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PWKD_UDC_DEVICE_POLICY Policy
    )
{
    USHORT vendorId = 0;
    USHORT productId = 0;
    WCHAR serialNumber[WKD_UDC_SERIAL_MAX_LENGTH];
    USHORT serialLength = 0;
    WKD_UDC_DEVICE_CLASS deviceClass = WkdUdcClass_Unknown;

    PAGED_CODE();

    *Policy = WkdUdcPolicy_Allow;

    if (!g_WkdUdcState.Config.Enabled) {
        return TRUE;
    }
    if (!WkdUdcEnterOperation()) {
        return TRUE;
    }

    InterlockedIncrement64(&g_WkdUdcState.Stats.PolicyChecks);

    /* 仅可移除卷才进入策略判定 */
    if (!WkdUdcIsRemovableVolume(FltObjects)) {
        WkdUdcLeaveOperation();
        return TRUE;    /* 非可移除 — 总是放行 */
    }

    RtlZeroMemory(serialNumber, sizeof(serialNumber));

    NTSTATUS infoStatus = WkdUdcQueryDeviceInfo(
        FltObjects,
        &vendorId,
        &productId,
        serialNumber,
        &serialLength,
        &deviceClass
        );

    if (!NT_SUCCESS(infoStatus)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[WkDefender/UDC] Device info query returned 0x%08X, "
                   "applying default policy\n", infoStatus);
    }

    /* 解析策略：黑名单 → 白名单 → 默认 */
    *Policy = WkdUdcResolvePolicy(
        vendorId,
        productId,
        (serialLength > 0) ? serialNumber : NULL,
        deviceClass
        );

    if (*Policy == WkdUdcPolicy_Block) {
        InterlockedIncrement64(&g_WkdUdcState.Stats.VolumeAttachRejected);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[WkDefender/UDC] BLOCKED removable volume attachment "
                   "(VID=0x%04X, PID=0x%04X, Policy=Block)\n",
                   vendorId, productId);

        WkdUdcLeaveOperation();
        return FALSE;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WkDefender/UDC] Removable volume detected "
               "(VID=0x%04X, PID=0x%04X, Policy=%d)\n",
               vendorId, productId, *Policy);

    WkdUdcLeaveOperation();
    return TRUE;
}

/*
 * WkdUdcIsWriteBlocked
 *   PreWrite 回调调用。已追踪卷 EffectivePolicy==ReadOnly → 写阻断。
 *   统计 WriteAttempts/WriteBlocked/WritesBlocked/WritesAllowed。
 *   上报在卷锁外（WKD_UDC-1：锁内不得调用上报路径）。
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WkdUdcIsWriteBlocked(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    PWKD_UDC_TRACKED_VOLUME volume;
    BOOLEAN blocked = FALSE;
    BOOLEAN submitWriteBlockedEvent = FALSE;

    if (!g_WkdUdcState.Config.Enabled || !g_WkdUdcState.Config.EnableWriteProtection) {
        return FALSE;
    }
    if (!WkdUdcEnterOperation()) {
        return FALSE;
    }

    FltAcquirePushLockShared(&g_WkdUdcState.VolumeLock);

    volume = WkdUdcFindVolumeUnlocked(FltObjects->Instance);
    if (volume != NULL) {
        InterlockedIncrement(&volume->WriteAttempts);

        if (volume->EffectivePolicy == WkdUdcPolicy_ReadOnly) {
            InterlockedIncrement(&volume->WriteBlocked);
            InterlockedIncrement64(&g_WkdUdcState.Stats.WritesBlocked);
            blocked = TRUE;
            submitWriteBlockedEvent = TRUE;
        } else if (volume->EffectivePolicy == WkdUdcPolicy_Audit) {
            InterlockedIncrement64(&g_WkdUdcState.Stats.WritesAllowed);
        }
    }

    FltReleasePushLock(&g_WkdUdcState.VolumeLock);

    if (submitWriteBlockedEvent) {
        /* TODO(接入): 经 wkd 通知链路上报（SS BeEngineSubmitEvent
         * BehaviorEvent_USBWriteBlocked/Exfiltration 50 分）——建议消息
         * WkdMessage_UsbWriteBlocked，可选用 AeReportIndicatorPair 评分。 */
    }

    WkdUdcLeaveOperation();
    return blocked;
}

/*
 * WkdUdcIsSetInfoBlocked
 *   PreSetInformation 回调调用。只读卷上的重命名/删除同样阻断（委托写判断）。
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WkdUdcIsSetInfoBlocked(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    return WkdUdcIsWriteBlocked(FltObjects);
}

/*
 * WkdUdcCheckAutorun
 *   PreCreate 回调调用。仅对已追踪可移除卷上的 autorun.inf 访问阻断。
 *   WKD_UDC-7：锁内完成全部检查防 use-after-free；WKD_UDC-9：rundown 防护。
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WkdUdcCheckAutorun(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING FileName
    )
{
    USHORT length;
    USHORT nameStart;
    PWKD_UDC_TRACKED_VOLUME volume;
    BOOLEAN result = FALSE;

    if (!g_WkdUdcState.Config.Enabled || !g_WkdUdcState.Config.EnableAutorunBlocking) {
        return FALSE;
    }
    if (FileName == NULL || FileName->Length == 0 || FileName->Buffer == NULL) {
        return FALSE;
    }

    if (!WkdUdcEnterOperation()) {
        return FALSE;
    }

    /* WKD_UDC-7：仅阻断已追踪可移除卷上的 autorun.inf */
    FltAcquirePushLockShared(&g_WkdUdcState.VolumeLock);

    volume = WkdUdcFindVolumeUnlocked(FltObjects->Instance);
    if (volume == NULL) {
        FltReleasePushLock(&g_WkdUdcState.VolumeLock);
        WkdUdcLeaveOperation();
        return FALSE;   /* 非已追踪可移除卷 */
    }

    /* 提取文件名组件（最后一个反斜杠之后） */
    length = FileName->Length / sizeof(WCHAR);
    nameStart = length;

    for (USHORT i = length; i > 0; i--) {
        if (FileName->Buffer[i - 1] == L'\\') {
            nameStart = i;
            break;
        }
    }

    if (nameStart < length) {
        UNICODE_STRING fileNameOnly;
        fileNameOnly.Buffer = &FileName->Buffer[nameStart];
        fileNameOnly.Length = (length - nameStart) * sizeof(WCHAR);
        fileNameOnly.MaximumLength = fileNameOnly.Length;

        if (RtlEqualUnicodeString(&fileNameOnly, &g_WkdAutorunFileName, TRUE)) {
            InterlockedIncrement64(&g_WkdUdcState.Stats.AutorunDetected);
            InterlockedIncrement64(&g_WkdUdcState.Stats.AutorunBlocked);
            InterlockedIncrement(&volume->FilesAccessed);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[WkDefender/UDC] BLOCKED autorun.inf access: %wZ\n",
                       FileName);

            result = TRUE;
        }
    }

    FltReleasePushLock(&g_WkdUdcState.VolumeLock);

    /* WKD_UDC-AR1：上报在释放卷锁之后，避免热路径阻塞与锁序冲突 */
    if (result) {
        /* TODO(接入): 经 wkd 通知链路上报（SS BeEngineSubmitEvent
         * BehaviorEvent_USBAutorunBlocked/Exfiltration 80 分）——建议消息
         * WkdMessage_UsbAutorunBlocked，可选用 AeReportIndicatorPair 评分。 */
    }

    WkdUdcLeaveOperation();
    return result;
}

/**************************************************/
/*                    卷追踪                       */
/**************************************************/

/*
 * WkdUdcNotifyVolumeMount
 *   InstanceSetup 回调调用。登记已追踪卷（lookaside 分配 + 锁内 cap/去重复查）。
 *   WKD_UDC-MNT-TOCTOU：锁外快检 + 锁内复查防 hotplug-flood 超限与非分页池放大。
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdUdcNotifyVolumeMount(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ WKD_UDC_DEVICE_POLICY Policy
    )
{
    PWKD_UDC_TRACKED_VOLUME volume;

    PAGED_CODE();

    if (!WkdUdcEnterOperation()) {
        return;
    }

    /* WKD_UDC-VAL：拒绝非法策略值（防未来 IOCTL 边界注入静默禁用） */
    if (!WKD_UDC_IS_VALID_POLICY(Policy)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[WkDefender/UDC] WkdUdcNotifyVolumeMount rejected invalid "
                   "policy=%d\n", Policy);
        WkdUdcLeaveOperation();
        return;
    }

    /* WKD_UDC-MNT-TOCTOU：预检 cap 避免明确超限时无谓分配 */
    if (g_WkdUdcState.VolumeCount >= WKD_UDC_MAX_TRACKED_VOLUMES) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[WkDefender/UDC] Maximum tracked volumes reached (%d)\n",
                   WKD_UDC_MAX_TRACKED_VOLUMES);
        WkdUdcLeaveOperation();
        return;
    }

    volume = (PWKD_UDC_TRACKED_VOLUME)ExAllocateFromNPagedLookasideList(
        &g_WkdUdcState.VolumeLookaside);

    if (volume == NULL) {
        WkdUdcLeaveOperation();
        return;
    }

    RtlZeroMemory(volume, sizeof(WKD_UDC_TRACKED_VOLUME));
    InitializeListHead(&volume->Link);

    volume->Instance = FltObjects->Instance;
    volume->EffectivePolicy = Policy;
    KeQuerySystemTime(&volume->MountTime);

    /* 获取卷名（两段式：先取所需大小，再填充） */
    {
        NTSTATUS status;
        ULONG nameLength = 0;

        status = FltGetVolumeName(FltObjects->Volume, NULL, &nameLength);
        if (status == STATUS_BUFFER_TOO_SMALL &&
            nameLength > 0 &&
            nameLength <= sizeof(volume->VolumeNameBuffer)) {

            volume->VolumeName.Buffer = volume->VolumeNameBuffer;
            volume->VolumeName.MaximumLength = sizeof(volume->VolumeNameBuffer);

            status = FltGetVolumeName(FltObjects->Volume, &volume->VolumeName, NULL);

            if (!NT_SUCCESS(status)) {
                volume->VolumeName.Length = 0;
            }
        }
    }

    /* 提取设备 VID/PID/序列号/类写入追踪记录 */
    {
        USHORT serialLength = 0;
        WKD_UDC_DEVICE_CLASS deviceClass = WkdUdcClass_Unknown;

        WkdUdcQueryDeviceInfo(
            FltObjects,
            &volume->VendorId,
            &volume->ProductId,
            volume->SerialNumber,
            &serialLength,
            &deviceClass
            );

        volume->DeviceClass = deviceClass;
        if (serialLength > 0 && serialLength < WKD_UDC_SERIAL_MAX_LENGTH) {
            volume->SerialNumber[serialLength] = L'\0'; /* 补 NUL 终止 */
        }
    }

    FltAcquirePushLockExclusive(&g_WkdUdcState.VolumeLock);

    /* WKD_UDC-MNT-TOCTOU：锁内复查 cap + 按 Instance 去重 */
    if (g_WkdUdcState.VolumeCount >= WKD_UDC_MAX_TRACKED_VOLUMES ||
        WkdUdcFindVolumeUnlocked(FltObjects->Instance) != NULL) {

        FltReleasePushLock(&g_WkdUdcState.VolumeLock);
        ExFreeToNPagedLookasideList(&g_WkdUdcState.VolumeLookaside, volume);
        WkdUdcLeaveOperation();
        return;
    }

    InsertTailList(&g_WkdUdcState.VolumeListHead, &volume->Link);
    InterlockedIncrement(&g_WkdUdcState.VolumeCount);
    FltReleasePushLock(&g_WkdUdcState.VolumeLock);

    InterlockedIncrement64(&g_WkdUdcState.Stats.VolumeMounts);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WkDefender/UDC] Removable volume mounted: %wZ "
               "(VID=0x%04X, PID=0x%04X, Policy=%d)\n",
               &volume->VolumeName,
               volume->VendorId, volume->ProductId, Policy);

    WkdUdcLeaveOperation();
}

/*
 * WkdUdcNotifyVolumeDismount
 *   InstanceTeardown 回调调用。按 Instance 移除卷记录并归还 lookaside。
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdUdcNotifyVolumeDismount(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    PLIST_ENTRY listEntry;

    PAGED_CODE();

    if (!WkdUdcEnterOperation()) {
        return;
    }

    FltAcquirePushLockExclusive(&g_WkdUdcState.VolumeLock);

    for (listEntry = g_WkdUdcState.VolumeListHead.Flink;
         listEntry != &g_WkdUdcState.VolumeListHead;
         listEntry = listEntry->Flink) {

        PWKD_UDC_TRACKED_VOLUME volume = CONTAINING_RECORD(
            listEntry, WKD_UDC_TRACKED_VOLUME, Link);

        if (volume->Instance == FltObjects->Instance) {
            RemoveEntryList(&volume->Link);
            InterlockedDecrement(&g_WkdUdcState.VolumeCount);
            FltReleasePushLock(&g_WkdUdcState.VolumeLock);

            InterlockedIncrement64(&g_WkdUdcState.Stats.VolumeDismounts);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[WkDefender/UDC] Removable volume dismounted: %wZ "
                       "(Writes=%ld, Blocked=%ld)\n",
                       &volume->VolumeName,
                       volume->WriteAttempts,
                       volume->WriteBlocked);

            ExFreeToNPagedLookasideList(&g_WkdUdcState.VolumeLookaside, volume);
            WkdUdcLeaveOperation();
            return;
        }
    }

    FltReleasePushLock(&g_WkdUdcState.VolumeLock);
    WkdUdcLeaveOperation();
}

/**************************************************/
/*                    规则管理                     */
/**************************************************/

/*
 * WkdUdcAddRule
 *   添加白/黑名单规则（黑名单优先于白名单）。
 *   WKD_UDC-VAL：枚举校验；WKD_UDC-ADD-TOCTOU：cap 锁外快检 + 锁内复查。
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
WkdUdcAddRule(
    _In_ BOOLEAN IsBlacklist,
    _In_ USHORT VendorId,
    _In_ USHORT ProductId,
    _In_opt_ PCWSTR SerialNumber,
    _In_ WKD_UDC_DEVICE_CLASS DeviceClass,
    _In_ WKD_UDC_DEVICE_POLICY Policy,
    _Out_ PULONG RuleId
    )
{
    PWKD_UDC_DEVICE_RULE rule;
    PLIST_ENTRY targetList;
    volatile LONG *targetCount;
    LONG maxEntries;

    PAGED_CODE();

    if (RuleId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *RuleId = 0;

    /* WKD_UDC-VAL：非法枚举不得入规则表（否则静默禁用执行） */
    if (!WKD_UDC_IS_VALID_POLICY(Policy) || !WKD_UDC_IS_VALID_CLASS(DeviceClass)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!WkdUdcEnterOperation()) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (IsBlacklist) {
        targetList = &g_WkdUdcState.BlacklistHead;
        targetCount = &g_WkdUdcState.BlacklistCount;
        maxEntries = WKD_UDC_MAX_BLACKLIST_ENTRIES;
    } else {
        targetList = &g_WkdUdcState.WhitelistHead;
        targetCount = &g_WkdUdcState.WhitelistCount;
        maxEntries = WKD_UDC_MAX_WHITELIST_ENTRIES;
    }

    /* WKD_UDC-ADD-TOCTOU：锁外快检（权威判定在锁内复查） */
    if (*targetCount >= maxEntries) {
        WkdUdcLeaveOperation();
        return STATUS_QUOTA_EXCEEDED;
    }

    rule = (PWKD_UDC_DEVICE_RULE)ExAllocatePool2(
        POOL_FLAG_PAGED, sizeof(WKD_UDC_DEVICE_RULE), WKD_UDC_DEVICE_POOL_TAG);

    if (rule == NULL) {
        WkdUdcLeaveOperation();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(rule, sizeof(WKD_UDC_DEVICE_RULE));
    InitializeListHead(&rule->Link);

    rule->VendorId = VendorId;
    rule->ProductId = ProductId;
    rule->DeviceClass = DeviceClass;
    rule->Policy = Policy;
    rule->RuleId = (ULONG)InterlockedIncrement(&g_WkdUdcState.NextRuleId);
    KeQuerySystemTime(&rule->CreatedTime);

    if (SerialNumber != NULL) {
        size_t serialLen = 0;

        NTSTATUS copyStatus = RtlStringCchLengthW(
            SerialNumber,
            WKD_UDC_SERIAL_MAX_LENGTH - 1,
            &serialLen
            );

        if (NT_SUCCESS(copyStatus) && serialLen > 0) {
            RtlCopyMemory(rule->SerialNumber, SerialNumber,
                         serialLen * sizeof(WCHAR));
            rule->SerialNumber[serialLen] = L'\0';
            rule->SerialNumberLength = (USHORT)serialLen;
        }
    }

    FltAcquirePushLockExclusive(&g_WkdUdcState.RulesLock);

    /* WKD_UDC-ADD-TOCTOU：锁内复查 cap，防并发插入超限 */
    if (*targetCount >= maxEntries) {
        FltReleasePushLock(&g_WkdUdcState.RulesLock);
        ExFreePoolWithTag(rule, WKD_UDC_DEVICE_POOL_TAG);
        WkdUdcLeaveOperation();
        return STATUS_QUOTA_EXCEEDED;
    }

    InsertTailList(targetList, &rule->Link);
    InterlockedIncrement(targetCount);
    FltReleasePushLock(&g_WkdUdcState.RulesLock);

    *RuleId = rule->RuleId;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WkDefender/UDC] Rule added: ID=%lu, %s, VID=0x%04X, "
               "PID=0x%04X, Policy=%d\n",
               rule->RuleId,
               IsBlacklist ? "BLACKLIST" : "WHITELIST",
               VendorId, ProductId, Policy);

    WkdUdcLeaveOperation();
    return STATUS_SUCCESS;
}

/*
 * WkdUdcRemoveRule
 *   按 RuleId 遍历黑名单+白名单删除（先黑后白）。
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdUdcRemoveRule(
    _In_ ULONG RuleId
    )
{
    PLIST_ENTRY listEntry;
    BOOLEAN found = FALSE;

    PAGED_CODE();

    if (RuleId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!WkdUdcEnterOperation()) {
        return STATUS_DEVICE_NOT_READY;
    }

    FltAcquirePushLockExclusive(&g_WkdUdcState.RulesLock);

    /* 先查黑名单 */
    for (listEntry = g_WkdUdcState.BlacklistHead.Flink;
         listEntry != &g_WkdUdcState.BlacklistHead;
         listEntry = listEntry->Flink) {

        PWKD_UDC_DEVICE_RULE rule = CONTAINING_RECORD(
            listEntry, WKD_UDC_DEVICE_RULE, Link);

        if (rule->RuleId == RuleId) {
            RemoveEntryList(&rule->Link);
            InterlockedDecrement(&g_WkdUdcState.BlacklistCount);
            FltReleasePushLock(&g_WkdUdcState.RulesLock);
            ExFreePoolWithTag(rule, WKD_UDC_DEVICE_POOL_TAG);
            found = TRUE;
            goto Done;
        }
    }

    /* 再查白名单 */
    for (listEntry = g_WkdUdcState.WhitelistHead.Flink;
         listEntry != &g_WkdUdcState.WhitelistHead;
         listEntry = listEntry->Flink) {

        PWKD_UDC_DEVICE_RULE rule = CONTAINING_RECORD(
            listEntry, WKD_UDC_DEVICE_RULE, Link);

        if (rule->RuleId == RuleId) {
            RemoveEntryList(&rule->Link);
            InterlockedDecrement(&g_WkdUdcState.WhitelistCount);
            FltReleasePushLock(&g_WkdUdcState.RulesLock);
            ExFreePoolWithTag(rule, WKD_UDC_DEVICE_POOL_TAG);
            found = TRUE;
            goto Done;
        }
    }

    FltReleasePushLock(&g_WkdUdcState.RulesLock);

Done:
    WkdUdcLeaveOperation();
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/*
 * WkdUdcClearRules
 *   清空全部白名单+黑名单规则并归零计数。
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdUdcClearRules(
    VOID
    )
{
    PLIST_ENTRY listEntry;

    PAGED_CODE();

    if (!WkdUdcEnterOperation()) {
        return;
    }

    FltAcquirePushLockExclusive(&g_WkdUdcState.RulesLock);

    while (!IsListEmpty(&g_WkdUdcState.WhitelistHead)) {
        listEntry = RemoveHeadList(&g_WkdUdcState.WhitelistHead);
        PWKD_UDC_DEVICE_RULE rule = CONTAINING_RECORD(
            listEntry, WKD_UDC_DEVICE_RULE, Link);
        ExFreePoolWithTag(rule, WKD_UDC_DEVICE_POOL_TAG);
    }
    g_WkdUdcState.WhitelistCount = 0;

    while (!IsListEmpty(&g_WkdUdcState.BlacklistHead)) {
        listEntry = RemoveHeadList(&g_WkdUdcState.BlacklistHead);
        PWKD_UDC_DEVICE_RULE rule = CONTAINING_RECORD(
            listEntry, WKD_UDC_DEVICE_RULE, Link);
        ExFreePoolWithTag(rule, WKD_UDC_DEVICE_POOL_TAG);
    }
    g_WkdUdcState.BlacklistCount = 0;

    FltReleasePushLock(&g_WkdUdcState.RulesLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WkDefender/UDC] All rules cleared\n");

    WkdUdcLeaveOperation();
}

/*
 * WkdUdcUpdateConfig
 *   更新配置。WKD_UDC-VAL：快照后校验枚举 + BOOLEAN 规范化再发布。
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdUdcUpdateConfig(
    _In_ PWKD_UDC_CONFIG NewConfig
    )
{
    WKD_UDC_CONFIG sanitized;

    PAGED_CODE();

    if (NewConfig == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    sanitized = *NewConfig;

    /* 非法 DefaultPolicy 不得发布（防静默禁用执行） */
    if (!WKD_UDC_IS_VALID_POLICY(sanitized.DefaultPolicy)) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 非规范 BOOLEAN(UCHAR 0..255) 规范化为 TRUE/FALSE */
    sanitized.EnableAutorunBlocking = sanitized.EnableAutorunBlocking ? TRUE : FALSE;
    sanitized.EnableWriteProtection = sanitized.EnableWriteProtection ? TRUE : FALSE;
    sanitized.EnableAuditLogging    = sanitized.EnableAuditLogging    ? TRUE : FALSE;
    sanitized.Enabled               = sanitized.Enabled               ? TRUE : FALSE;

    if (!WkdUdcEnterOperation()) {
        return STATUS_DEVICE_NOT_READY;
    }

    FltAcquirePushLockExclusive(&g_WkdUdcState.RulesLock);
    RtlCopyMemory(&g_WkdUdcState.Config, &sanitized, sizeof(WKD_UDC_CONFIG));
    FltReleasePushLock(&g_WkdUdcState.RulesLock);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WkDefender/UDC] Config updated: Enabled=%d, "
               "DefaultPolicy=%d, WriteProtect=%d, AutorunBlock=%d\n",
               sanitized.Enabled,
               sanitized.DefaultPolicy,
               sanitized.EnableWriteProtection,
               sanitized.EnableAutorunBlocking);

    WkdUdcLeaveOperation();
    return STATUS_SUCCESS;
}

/**************************************************/
/*                    统计查询                     */
/**************************************************/

/*
 * WkdUdcGetStatistics
 *   统计快照。WKD_UDC-STAT：InterlockedCompareExchange64 无撕裂读
 *   （x64 对齐读原子性不保证 + 编译器重排）；非 ready 态清零。
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdUdcGetStatistics(
    _Out_ PWKD_UDC_STATISTICS Statistics
    )
{
    if (Statistics == NULL) {
        return;
    }

    if (g_WkdUdcState.State != 2) {
        RtlZeroMemory(Statistics, sizeof(WKD_UDC_STATISTICS));
        return;
    }

    Statistics->VolumeMounts =
        InterlockedCompareExchange64(&g_WkdUdcState.Stats.VolumeMounts, 0, 0);
    Statistics->VolumeDismounts =
        InterlockedCompareExchange64(&g_WkdUdcState.Stats.VolumeDismounts, 0, 0);
    Statistics->WritesBlocked =
        InterlockedCompareExchange64(&g_WkdUdcState.Stats.WritesBlocked, 0, 0);
    Statistics->WritesAllowed =
        InterlockedCompareExchange64(&g_WkdUdcState.Stats.WritesAllowed, 0, 0);
    Statistics->VolumeAttachRejected =
        InterlockedCompareExchange64(&g_WkdUdcState.Stats.VolumeAttachRejected, 0, 0);
    Statistics->AutorunDetected =
        InterlockedCompareExchange64(&g_WkdUdcState.Stats.AutorunDetected, 0, 0);
    Statistics->AutorunBlocked =
        InterlockedCompareExchange64(&g_WkdUdcState.Stats.AutorunBlocked, 0, 0);
    Statistics->PolicyChecks =
        InterlockedCompareExchange64(&g_WkdUdcState.Stats.PolicyChecks, 0, 0);
}

/**************************************************/
/*              设备信息提取流水线                 */
/**************************************************/

/*
 * WkdUdcQueryDeviceInfo
 *   提取设备身份：①FltGetDiskDeviceObject → 磁盘设备；
 *   ②STORAGE_DEVICE_DESCRIPTOR → 总线类型+序列号(ASCII→Unicode)；
 *   ③PDO 硬件 ID → VID_xxxx/PID_xxxx。全部 best-effort，失败留零值。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdUdcQueryDeviceInfo(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PUSHORT VendorId,
    _Out_ PUSHORT ProductId,
    _Out_writes_(WKD_UDC_SERIAL_MAX_LENGTH) PWCHAR SerialNumber,
    _Out_ PUSHORT SerialLength,
    _Out_ PWKD_UDC_DEVICE_CLASS DeviceClass
    )
{
    NTSTATUS status;
    PDEVICE_OBJECT diskDevice = NULL;
    PSTORAGE_DEVICE_DESCRIPTOR descriptor = NULL;
    PDEVICE_OBJECT physicalDevice = NULL;

    PAGED_CODE();

    *VendorId = 0;
    *ProductId = 0;
    *SerialLength = 0;
    *DeviceClass = WkdUdcClass_MassStorage;    /* 可移除默认大容量存储 */

    status = FltGetDiskDeviceObject(FltObjects->Volume, &diskDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* ① STORAGE_DEVICE_DESCRIPTOR：总线类型 + 序列号 */
    status = WkdUdcSendStorageQuery(diskDevice, &descriptor);
    if (NT_SUCCESS(status) && descriptor != NULL) {

        /* 总线类型 → 设备类 */
        switch (descriptor->BusType) {
            case BusTypeUsb:
            case BusTypeScsi:
            case BusTypeAta:
            case BusTypeSata:
                *DeviceClass = WkdUdcClass_MassStorage;
                break;

            default:
                *DeviceClass = descriptor->RemovableMedia ?
                    WkdUdcClass_MassStorage : WkdUdcClass_Other;
                break;
        }

        /* 序列号提取（ASCII→Unicode，去首尾空格；固件常以空格填充） */
        if (descriptor->SerialNumberOffset != 0 &&
            descriptor->SerialNumberOffset < descriptor->Size) {

            PCSTR asciiSerial = (PCSTR)((PUCHAR)descriptor +
                                        descriptor->SerialNumberOffset);

            /* 校验 ASCII 串在描述符边界内 */
            ULONG maxLen = descriptor->Size - descriptor->SerialNumberOffset;
            ULONG asciiLen = 0;

            while (asciiLen < maxLen && asciiSerial[asciiLen] != '\0') {
                asciiLen++;
            }

            /* 去首尾空格 */
            ULONG start = 0;
            while (start < asciiLen && asciiSerial[start] == ' ') {
                start++;
            }

            ULONG end = asciiLen;
            while (end > start && asciiSerial[end - 1] == ' ') {
                end--;
            }

            ULONG trimmedLen = end - start;
            if (trimmedLen > WKD_UDC_SERIAL_MAX_LENGTH - 1) {
                trimmedLen = WKD_UDC_SERIAL_MAX_LENGTH - 1;
            }

            for (ULONG i = 0; i < trimmedLen; i++) {
                SerialNumber[i] = (WCHAR)(UCHAR)asciiSerial[start + i];
            }

            *SerialLength = (USHORT)trimmedLen;
            SerialNumber[*SerialLength] = L'\0';
        }

        ExFreePoolWithTag(descriptor, WKD_UDC_POOL_TAG);
        descriptor = NULL;
    }

    /* ② 设备栈下钻到 PDO，查询硬件 ID 解析 VID/PID */
    physicalDevice = WkdUdcGetPhysicalDeviceObject(diskDevice);
    if (physicalDevice != NULL) {

        /* WKD_UDC-ALIGN：IoGetDeviceProperty 返回 REG_MULTI_SZ 宽字符数据，
         * 缓冲区必须 WCHAR 对齐后才能按 PCWSTR 解读 */
        WCHAR hardwareIdBuffer[WKD_UDC_HARDWARE_ID_BUFFER_SIZE / sizeof(WCHAR)];
        ULONG resultLength = 0;

        status = IoGetDeviceProperty(
            physicalDevice,
            DevicePropertyHardwareID,
            sizeof(hardwareIdBuffer),
            hardwareIdBuffer,
            &resultLength
            );

        if (NT_SUCCESS(status) && resultLength > sizeof(WCHAR)) {
            WkdUdcParseHardwareIdForVidPid(
                hardwareIdBuffer,
                resultLength,
                VendorId,
                ProductId
                );
        }

        ObDereferenceObject(physicalDevice);
    }

    ObDereferenceObject(diskDevice);
    return STATUS_SUCCESS;
}

/*
 * WkdUdcSendStorageQuery
 *   同步 IOCTL_STORAGE_QUERY_PROPERTY 取 STORAGE_DEVICE_DESCRIPTOR。
 *   WKD_UDC-DESC：描述符完整性校验（Size 三界 + Information + Version），
 *   防 (Size - SerialNumberOffset) 下溢为巨大 ULONG 与越界字段读。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
WkdUdcSendStorageQuery(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PSTORAGE_DEVICE_DESCRIPTOR *Descriptor
    )
{
    NTSTATUS status;
    STORAGE_PROPERTY_QUERY query;
    IO_STATUS_BLOCK ioStatus;
    KEVENT event;
    PIRP irp;
    PSTORAGE_DEVICE_DESCRIPTOR desc;

    PAGED_CODE();

    *Descriptor = NULL;

    desc = (PSTORAGE_DEVICE_DESCRIPTOR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        WKD_UDC_STORAGE_QUERY_BUFFER_SIZE,
        WKD_UDC_POOL_TAG
        );

    if (desc == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&query, sizeof(query));
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    irp = IoBuildDeviceIoControlRequest(
        IOCTL_STORAGE_QUERY_PROPERTY,
        DeviceObject,
        &query,
        sizeof(query),
        desc,
        WKD_UDC_STORAGE_QUERY_BUFFER_SIZE,
        FALSE,
        &event,
        &ioStatus
        );

    if (irp == NULL) {
        ExFreePoolWithTag(desc, WKD_UDC_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoCallDriver(DeviceObject, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(
            &event,
            Executive,
            KernelMode,
            FALSE,
            NULL
            );
        status = ioStatus.Status;
    }

    if (NT_SUCCESS(status)) {
        /* WKD_UDC-DESC：拒绝超大/超小描述符 + 未初始化 Version */
        if (ioStatus.Information < sizeof(STORAGE_DEVICE_DESCRIPTOR) ||
            desc->Size > WKD_UDC_STORAGE_QUERY_BUFFER_SIZE ||
            desc->Size < sizeof(STORAGE_DEVICE_DESCRIPTOR) ||
            desc->Size > ioStatus.Information ||
            desc->Version == 0) {
            ExFreePoolWithTag(desc, WKD_UDC_POOL_TAG);
            return STATUS_DATA_ERROR;
        }
        *Descriptor = desc;
    } else {
        ExFreePoolWithTag(desc, WKD_UDC_POOL_TAG);
    }

    return status;
}

/*
 * WkdUdcGetPhysicalDeviceObject
 *   从给定设备对象沿 IoGetLowerDeviceObject 下钻到栈底 PDO（深度 cap 64）。
 *   返回已引用的 PDO，调用方必须 ObDereferenceObject。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static PDEVICE_OBJECT
WkdUdcGetPhysicalDeviceObject(
    _In_ PDEVICE_OBJECT DeviceObject
    )
{
    PDEVICE_OBJECT current;
    PDEVICE_OBJECT lower;
    ULONG depth = 0;

    PAGED_CODE();

    current = DeviceObject;
    ObReferenceObject(current);

    while (depth < WKD_UDC_MAX_PDO_DEPTH) {
        lower = IoGetLowerDeviceObject(current);
        if (lower == NULL) {
            break;
        }
        ObDereferenceObject(current);
        current = lower;
        depth++;
    }

    /* current 即 PDO（栈底），已引用一次 */
    return current;
}

/*
 * WkdUdcParseHardwareIdForVidPid
 *   遍历 REG_MULTI_SZ 硬件 ID 各串内所有位置，找 VID_xxxx/PID_xxxx 模式
 *   （USB\VID_1234&PID_5678\serial），大小写不敏感，双命中提前返回。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdUdcParseHardwareIdForVidPid(
    _In_reads_bytes_(LengthInBytes) PCWSTR HardwareId,
    _In_ ULONG LengthInBytes,
    _Out_ PUSHORT VendorId,
    _Out_ PUSHORT ProductId
    )
{
    ULONG totalChars = LengthInBytes / sizeof(WCHAR);
    PCWSTR current = HardwareId;

    *VendorId = 0;
    *ProductId = 0;

    /* REG_MULTI_SZ：多个 NUL 终止串 + 双 NUL 结束，逐串迭代 */
    while (current < HardwareId + totalChars && *current != L'\0') {

        ULONG strLen = 0;
        while (current + strLen < HardwareId + totalChars &&
               current[strLen] != L'\0') {
            strLen++;
        }

        /* 串内全位置扫描 VID_ / PID_ */
        for (ULONG i = 0; i + 4 <= strLen; i++) {
            if ((current[i] == L'V' || current[i] == L'v') &&
                (current[i + 1] == L'I' || current[i + 1] == L'i') &&
                (current[i + 2] == L'D' || current[i + 2] == L'd') &&
                current[i + 3] == L'_') {

                if (i + 8 <= strLen) {
                    *VendorId = WkdUdcParseHex4(
                        &current[i + 4], strLen - i - 4);
                }
            }

            if ((current[i] == L'P' || current[i] == L'p') &&
                (current[i + 1] == L'I' || current[i + 1] == L'i') &&
                (current[i + 2] == L'D' || current[i + 2] == L'd') &&
                current[i + 3] == L'_') {

                if (i + 8 <= strLen) {
                    *ProductId = WkdUdcParseHex4(
                        &current[i + 4], strLen - i - 4);
                }
            }
        }

        /* 双命中提前返回 */
        if (*VendorId != 0 && *ProductId != 0) {
            return;
        }

        /* 跳过 NUL 进入下一串 */
        current += strLen + 1;
    }
}

/*
 * WkdUdcParseHex4
 *   解析最多 4 位十六进制（大小写不敏感），AvailableChars 约束防越界，
 *   非 hex 字符提前 break（对齐 SS UdcpParseHex4）。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static USHORT
WkdUdcParseHex4(
    _In_reads_(AvailableChars) PCWSTR Str,
    _In_ ULONG AvailableChars
    )
{
    USHORT result = 0;
    ULONG count = (AvailableChars < 4) ? AvailableChars : 4;

    for (ULONG i = 0; i < count; i++) {
        WCHAR ch = Str[i];
        if (ch >= L'0' && ch <= L'9') {
            result = (USHORT)((result << 4) | (USHORT)(ch - L'0'));
        } else if (ch >= L'A' && ch <= L'F') {
            result = (USHORT)((result << 4) | (USHORT)(ch - L'A' + 10));
        } else if (ch >= L'a' && ch <= L'f') {
            result = (USHORT)((result << 4) | (USHORT)(ch - L'a' + 10));
        } else {
            break;
        }
    }

    return result;
}

/**************************************************/
/*              私有 — 策略解析                    */
/**************************************************/

/*
 * WkdUdcResolvePolicy
 *   策略解析：黑名单 → 白名单 → 默认策略。
 *   WKD_UDC-6：规则指定序列号要求时设备必须提供匹配序列号（无序列号不匹配）。
 *   FSC-7：默认策略在锁内读取保证与规则检查一致。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static WKD_UDC_DEVICE_POLICY
WkdUdcResolvePolicy(
    _In_ USHORT VendorId,
    _In_ USHORT ProductId,
    _In_opt_ PCWSTR SerialNumber,
    _In_ WKD_UDC_DEVICE_CLASS DeviceClass
    )
{
    PLIST_ENTRY listEntry;

    FltAcquirePushLockShared(&g_WkdUdcState.RulesLock);

    /* 黑名单（最高优先） */
    for (listEntry = g_WkdUdcState.BlacklistHead.Flink;
         listEntry != &g_WkdUdcState.BlacklistHead;
         listEntry = listEntry->Flink) {

        PWKD_UDC_DEVICE_RULE rule = CONTAINING_RECORD(
            listEntry, WKD_UDC_DEVICE_RULE, Link);

        BOOLEAN vidMatch = (rule->VendorId == 0 || rule->VendorId == VendorId);
        BOOLEAN pidMatch = (rule->ProductId == 0 || rule->ProductId == ProductId);
        BOOLEAN classMatch = (rule->DeviceClass == WkdUdcClass_Unknown ||
                              rule->DeviceClass == DeviceClass);
        BOOLEAN serialMatch;

        /* WKD_UDC-6：规则要求序列号时设备必须提供匹配序列号 */
        if (rule->SerialNumberLength > 0) {
            if (SerialNumber == NULL) {
                serialMatch = FALSE;
            } else {
                UNICODE_STRING ruleSerial;
                ruleSerial.Buffer = rule->SerialNumber;
                ruleSerial.Length = rule->SerialNumberLength * sizeof(WCHAR);
                ruleSerial.MaximumLength = sizeof(rule->SerialNumber);

                UNICODE_STRING deviceSerial;
                RtlInitUnicodeString(&deviceSerial, SerialNumber);

                serialMatch = RtlEqualUnicodeString(
                    &ruleSerial, &deviceSerial, TRUE);
            }
        } else {
            serialMatch = TRUE;     /* 规则不关心序列号 */
        }

        if (vidMatch && pidMatch && classMatch && serialMatch) {
            WKD_UDC_DEVICE_POLICY policy = rule->Policy;
            FltReleasePushLock(&g_WkdUdcState.RulesLock);
            return policy;
        }
    }

    /* 白名单（次优先） */
    for (listEntry = g_WkdUdcState.WhitelistHead.Flink;
         listEntry != &g_WkdUdcState.WhitelistHead;
         listEntry = listEntry->Flink) {

        PWKD_UDC_DEVICE_RULE rule = CONTAINING_RECORD(
            listEntry, WKD_UDC_DEVICE_RULE, Link);

        BOOLEAN vidMatch = (rule->VendorId == 0 || rule->VendorId == VendorId);
        BOOLEAN pidMatch = (rule->ProductId == 0 || rule->ProductId == ProductId);
        BOOLEAN classMatch = (rule->DeviceClass == WkdUdcClass_Unknown ||
                              rule->DeviceClass == DeviceClass);
        BOOLEAN serialMatch;

        if (rule->SerialNumberLength > 0) {
            if (SerialNumber == NULL) {
                serialMatch = FALSE;
            } else {
                UNICODE_STRING ruleSerial;
                ruleSerial.Buffer = rule->SerialNumber;
                ruleSerial.Length = rule->SerialNumberLength * sizeof(WCHAR);
                ruleSerial.MaximumLength = sizeof(rule->SerialNumber);

                UNICODE_STRING deviceSerial;
                RtlInitUnicodeString(&deviceSerial, SerialNumber);

                serialMatch = RtlEqualUnicodeString(
                    &ruleSerial, &deviceSerial, TRUE);
            }
        } else {
            serialMatch = TRUE;
        }

        if (vidMatch && pidMatch && classMatch && serialMatch) {
            WKD_UDC_DEVICE_POLICY policy = rule->Policy;
            FltReleasePushLock(&g_WkdUdcState.RulesLock);
            return policy;
        }
    }

    /* FSC-7：无匹配规则 — 锁内读默认策略 */
    WKD_UDC_DEVICE_POLICY defaultPolicy = g_WkdUdcState.Config.DefaultPolicy;
    FltReleasePushLock(&g_WkdUdcState.RulesLock);

    return defaultPolicy;
}

/**************************************************/
/*              私有 — 卷检测/查找                 */
/**************************************************/

/*
 * WkdUdcIsRemovableVolume
 *   查询卷属性判断是否可移除介质（FILE_REMOVABLE_MEDIA / FLOPPY_DISKETTE）。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
WkdUdcIsRemovableVolume(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    NTSTATUS status;
    ULONG bufferSize;
    PFLT_VOLUME_PROPERTIES volumeProps = NULL;
    BOOLEAN isRemovable = FALSE;

    PAGED_CODE();

    bufferSize = sizeof(FLT_VOLUME_PROPERTIES) + 512;
    volumeProps = (PFLT_VOLUME_PROPERTIES)ExAllocatePool2(
        POOL_FLAG_PAGED, bufferSize, WKD_UDC_POOL_TAG);

    if (volumeProps == NULL) {
        return FALSE;
    }

    status = FltGetVolumeProperties(
        FltObjects->Volume,
        volumeProps,
        bufferSize,
        &bufferSize
        );

    if (NT_SUCCESS(status)) {
        if (FlagOn(volumeProps->DeviceCharacteristics, FILE_REMOVABLE_MEDIA) ||
            FlagOn(volumeProps->DeviceCharacteristics, FILE_FLOPPY_DISKETTE)) {
            isRemovable = TRUE;
        }
    }

    ExFreePoolWithTag(volumeProps, WKD_UDC_POOL_TAG);
    return isRemovable;
}

/*
 * WkdUdcFindVolumeUnlocked
 *   按 minifilter 实例查找已追踪卷（调用方必须持有 VolumeLock）。
 */
_IRQL_requires_(PASSIVE_LEVEL)
static PWKD_UDC_TRACKED_VOLUME
WkdUdcFindVolumeUnlocked(
    _In_ PFLT_INSTANCE Instance
    )
{
    PLIST_ENTRY listEntry;

    PAGED_CODE();

    for (listEntry = g_WkdUdcState.VolumeListHead.Flink;
         listEntry != &g_WkdUdcState.VolumeListHead;
         listEntry = listEntry->Flink) {

        PWKD_UDC_TRACKED_VOLUME volume = CONTAINING_RECORD(
            listEntry, WKD_UDC_TRACKED_VOLUME, Link);

        if (volume->Instance == Instance) {
            return volume;
        }
    }

    return NULL;
}

/**************************************************/
/*              私有 — 生命周期辅助                */
/**************************************************/

/*
 * WkdUdcEnterOperation / WkdUdcLeaveOperation
 *   rundown protection 配对（WKD_UDC-9：防止 shutdown 期间访问已释放状态）。
 */
static BOOLEAN
WkdUdcEnterOperation(
    VOID
    )
{
    if (g_WkdUdcState.State != 2) {
        return FALSE;
    }
    return ExAcquireRundownProtection(&g_WkdUdcState.RundownRef);
}

static VOID
WkdUdcLeaveOperation(
    VOID
    )
{
    ExReleaseRundownProtection(&g_WkdUdcState.RundownRef);
}

#pragma warning(pop)
