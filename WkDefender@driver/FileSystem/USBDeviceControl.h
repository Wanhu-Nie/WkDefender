/**************************************************/
/*  USBDeviceControl 可移除设备控制                */
/*  迁移自 SS USBDeviceControl（全量功能面对齐）    */
/**************************************************/

#pragma once

#include <fltKernel.h>

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
 * 迁移来源：ShadowStrike Callbacks/FileSystem/USBDeviceControl.{c,h}
 *           （2026-08 全量功能面对齐，重功能实现非复制）
 *
 * 接入前提（未接入原因）：
 *   1. 需 InstanceSetup 钩子（NotifyVolumeMount/Dismount 由 Filter.c 的
 *      InstanceSetup/Teardown 回调调用，当前 wkd 用默认 InstanceSetup）；
 *   2. 阻断上报需接入 wkd 通知链路（SS BeEngineSubmitEvent 在 wkd 无对应，
 *      TODO 标注接入点）。
 *   本文件与 EDR 核心链路解耦，独立立项，当前整体为死代码。
 *--*/

/**************************************************/
/*                      池标签                     */
/**************************************************/

#define WKD_UDC_POOL_TAG            'cDUW'  /* WUDc - USB Device Control */
#define WKD_UDC_DEVICE_POOL_TAG     'dDUW'  /* WUDd - Device Entry */

/**************************************************/
/*                    配置常量                     */
/**************************************************/

#define WKD_UDC_MAX_WHITELIST_ENTRIES   256
#define WKD_UDC_MAX_BLACKLIST_ENTRIES   256
#define WKD_UDC_MAX_TRACKED_VOLUMES     64
#define WKD_UDC_SERIAL_MAX_LENGTH       128
#define WKD_UDC_MAX_AUTORUN_SIZE        (64 * 1024)     /* 64 KB max autorun.inf */
#define WKD_UDC_STORAGE_QUERY_BUFFER_SIZE 1024
#define WKD_UDC_HARDWARE_ID_BUFFER_SIZE 512
#define WKD_UDC_MAX_PDO_DEPTH           64

/**************************************************/
/*                    策略校验宏                   */
/**************************************************/

/* WKD_UDC-VAL：公开 API/未来 IOCTL 边界校验，防止非法枚举值静默禁用执行 */
#define WKD_UDC_IS_VALID_POLICY(p) \
    ((p) == WkdUdcPolicy_Allow    || (p) == WkdUdcPolicy_ReadOnly || \
     (p) == WkdUdcPolicy_Block    || (p) == WkdUdcPolicy_Audit)

#define WKD_UDC_IS_VALID_CLASS(c) \
    ((ULONG)(c) <= (ULONG)WkdUdcClass_Other)

/**************************************************/
/*                    枚举类型                     */
/**************************************************/

/* 设备访问策略（对齐 SS UDC_DEVICE_POLICY） */
typedef enum _WKD_UDC_DEVICE_POLICY {
    WkdUdcPolicy_Allow = 0,     /* 完全访问 */
    WkdUdcPolicy_ReadOnly,      /* 只读，写操作阻断 */
    WkdUdcPolicy_Block,         /* 卷附加整体拒绝 */
    WkdUdcPolicy_Audit          /* 仅记录，不阻断 */
} WKD_UDC_DEVICE_POLICY, *PWKD_UDC_DEVICE_POLICY;

/* 设备类型（对齐 SS UDC_DEVICE_CLASS） */
typedef enum _WKD_UDC_DEVICE_CLASS {
    WkdUdcClass_Unknown = 0,
    WkdUdcClass_MassStorage,    /* USB 大容量存储（U 盘/移动硬盘） */
    WkdUdcClass_CDROM,          /* USB CD/DVD */
    WkdUdcClass_HID,            /* 人机接口设备（键盘/鼠标） */
    WkdUdcClass_Network,        /* USB 网卡 */
    WkdUdcClass_Printer,        /* USB 打印机 */
    WkdUdcClass_Other           /* 未分类 */
} WKD_UDC_DEVICE_CLASS, *PWKD_UDC_DEVICE_CLASS;

/**************************************************/
/*                    结构体声明                   */
/**************************************************/

/* 设备规则条目（对齐 SS UDC_DEVICE_RULE） */
typedef struct _WKD_UDC_DEVICE_RULE {

    LIST_ENTRY          Link;

    /* 匹配条件（0 = 通配） */
    USHORT              VendorId;
    USHORT              ProductId;
    WCHAR               SerialNumber[WKD_UDC_SERIAL_MAX_LENGTH];
    USHORT              SerialNumberLength;     /* 0 = 匹配任意序列号 */

    /* 设备类过滤（Unknown = 匹配任意类） */
    WKD_UDC_DEVICE_CLASS DeviceClass;

    /* 应用策略 */
    WKD_UDC_DEVICE_POLICY Policy;

    /* 规则元数据 */
    LARGE_INTEGER       CreatedTime;
    ULONG               RuleId;

} WKD_UDC_DEVICE_RULE, *PWKD_UDC_DEVICE_RULE;

/* 已追踪卷（对齐 SS UDC_TRACKED_VOLUME） */
typedef struct _WKD_UDC_TRACKED_VOLUME {

    LIST_ENTRY          Link;

    /* 卷标识 */
    UNICODE_STRING      VolumeName;
    WCHAR               VolumeNameBuffer[260];
    ULONG               VolumeSerial;

    /* 设备信息 */
    USHORT              VendorId;
    USHORT              ProductId;
    WCHAR               SerialNumber[WKD_UDC_SERIAL_MAX_LENGTH];
    WKD_UDC_DEVICE_CLASS DeviceClass;

    /* 有效策略 */
    WKD_UDC_DEVICE_POLICY EffectivePolicy;

    /* 追踪 */
    LARGE_INTEGER       MountTime;
    PFLT_INSTANCE       Instance;       /* 该卷上的 minifilter 实例 */
    volatile LONG       WriteAttempts;
    volatile LONG       WriteBlocked;
    volatile LONG       FilesAccessed;

} WKD_UDC_TRACKED_VOLUME, *PWKD_UDC_TRACKED_VOLUME;

/* 配置（对齐 SS UDC_CONFIG） */
typedef struct _WKD_UDC_CONFIG {

    WKD_UDC_DEVICE_POLICY DefaultPolicy;    /* 未列入设备的默认策略 */
    BOOLEAN             EnableAutorunBlocking;
    BOOLEAN             EnableWriteProtection;
    BOOLEAN             EnableAuditLogging;
    BOOLEAN             Enabled;            /* 总开关 */

} WKD_UDC_CONFIG, *PWKD_UDC_CONFIG;

/* 统计（对齐 SS UDC_STATISTICS，8 计数） */
typedef struct _WKD_UDC_STATISTICS {

    volatile LONG64     VolumeMounts;
    volatile LONG64     VolumeDismounts;
    volatile LONG64     WritesBlocked;
    volatile LONG64     WritesAllowed;
    volatile LONG64     VolumeAttachRejected;
    volatile LONG64     AutorunDetected;
    volatile LONG64     AutorunBlocked;
    volatile LONG64     PolicyChecks;

} WKD_UDC_STATISTICS, *PWKD_UDC_STATISTICS;

/**************************************************/
/*                    函数声明                     */
/**************************************************/

/*
 * 生命周期（对齐 SS UdcInitialize/UdcShutdown）
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
WkdUdcInitialize(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdUdcShutdown(
    VOID
    );

/*
 * 策略检查（minifilter 回调调用，对齐 SS UdcCheckVolumePolicy 等）
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
BOOLEAN
WkdUdcCheckVolumePolicy(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PWKD_UDC_DEVICE_POLICY Policy
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WkdUdcIsWriteBlocked(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WkdUdcIsSetInfoBlocked(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WkdUdcCheckAutorun(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING FileName
    );

/*
 * 卷追踪（InstanceSetup/Teardown 回调调用，对齐 SS UdcNotifyVolumeMount 等）
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdUdcNotifyVolumeMount(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ WKD_UDC_DEVICE_POLICY Policy
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdUdcNotifyVolumeDismount(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

/*
 * 统计查询（对齐 SS UdcGetStatistics）
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WkdUdcGetStatistics(
    _Out_ PWKD_UDC_STATISTICS Statistics
    );

/*
 * 规则管理（对齐 SS UdcAddRule/UdcRemoveRule/UdcClearRules/UdcUpdateConfig）
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
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdUdcRemoveRule(
    _In_ ULONG RuleId
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WkdUdcClearRules(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WkdUdcUpdateConfig(
    _In_ PWKD_UDC_CONFIG NewConfig
    );
