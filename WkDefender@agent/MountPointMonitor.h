/**************************************************/
/*  WkDefender Agent — 挂载点监控 MountPointMonitor */
/*                                                  */
/*  迁移自 ShadowStrike MountPointMonitor           */
/*  (PhantomCore/Core/FileSystem, ~2400 行 C++),    */
/*  按功能融合重实现, 非源码复制。                    */
/*                                                  */
/*  职责: 卷/可移除介质挂载事件源 (L2 独立信号源)。  */
/*    - 消息窗口线程 + RegisterDeviceNotification     */
/*      (WM_DEVICECHANGE 卷事件 + USB 接口),         */
/*      1s 轮询 RefreshDriveList 兜底               */
/*    - 卷信息采集: GetVolumeInformationW /          */
/*      GetDriveTypeW / 容量 / 只读 /               */
/*      ClassifyVirtualDisk (VHD/VHDX/ISO 检测)     */
/*    - USB 设备信息: SetupAPI 提 VID/PID/序列号/    */
/*      友好名 (GUID_DEVINTERFACE_USB_DEVICE)        */
/*    - 设备威胁检测: Unauthorized / Masquerading /  */
/*      RubberDucky / 恶意 VID-PID 表 /             */
/*      快速挂载循环 (30s 窗 3 次)                   */
/*    - 序列号白名单 + 设备连接历史 (cap 10000)       */
/*    - 处置 API: BlockDrive / SetReadOnly /         */
/*      EjectDrive / autorun.inf 阻断                */
/*                                                  */
/*  不承载执行控制 — 执行层归驱动:                    */
/*    WkDefender@driver/FileSystem/USBDeviceControl  */
/*    (档案 #44, 死代码独立线, 本次不接线), 本模块    */
/*    处置 API 为 SS 功能面对齐, monitor-only 门控    */
/*    下无调用者 (死代码标注)。                       */
/*                                                  */
/*  与驱动 minifilter 关系: 本模块 WM_DEVICECHANGE    */
/*    自足事件源, 不依赖驱动事件。DefEvent 0xA001/    */
/*    ALPC 0x300D 为未来驱动 USB 事件预留 (注释标注,  */
/*    本次不占用)。                                  */
/*                                                  */
/*  死代码标注: 消费链默认 g_IoaMountPointMonitorEnabled */
/*  =FALSE (main.c 回调门控), 编排器本体可独立运行/   */
/*  SelfTest。处置 API / 历史查询 / Get*Name /       */
/*  ToJson / USBKill / RequireApproval 均标注。      */
/*  白名单与设备历史主体在内存, StorageEngine 表      */
/*  (device_history/device_whitelist) 预留死代码。    */
/**************************************************/

#pragma once

#include <windows.h>
#include "DefendTypes.h"

/**************************************************/
/*               常量                               */
/**************************************************/

#define WKD_MPM_VERSION_MAJOR       3       /* 对齐 SS MountPointMonitorConstants::VERSION_MAJOR */
#define WKD_MPM_VERSION_MINOR       0
#define WKD_MPM_VERSION_PATCH       0

#define WKD_MPM_MAX_DEVICE_HISTORY  10000   /* 设备历史 cap (对齐 SS MAX_DEVICE_HISTORY) */
#define WKD_MPM_EVENT_QUEUE_CAPACITY 1000   /* ※死代码: SS 头文件定义未使用 (.cpp 无事件队列) */
#define WKD_MPM_POLLING_INTERVAL_MS 1000    /* 轮询兜底间隔 (对齐 SS POLLING_INTERVAL_MS) */

#define WKD_MPM_RAPID_CYCLE_THRESHOLD  3    /* 快速挂载循环阈值: 30s 窗内 3 次 (对齐 SS RAPID_CYCLE_THRESHOLD) */
#define WKD_MPM_RAPID_CYCLE_WINDOW_SEC 30   /* 对齐 SS RAPID_CYCLE_WINDOW_SEC */

#define WKD_MPM_MAX_DRIVE_LETTERS   26      /* A-Z 盘符固定映射数组 */
#define WKD_MPM_SERIAL_MAX          128     /* 设备序列号定长 (SetupAPI instance ID 尾部, 对齐 SS 无上限→防御性) */
#define WKD_MPM_VID_MAX             16      /* VID/PID 4 hex + NUL */
#define WKD_MPM_FRIENDLY_NAME_MAX   256     /* 友好名 (对齐 SS friendlyName[256]) */
#define WKD_MPM_CYCLE_SLOTS         8       /* 每盘符挂载循环时间戳槽 (阈值 3, 8 槽冗余) */
#define WKD_MPM_WIN_CLASS           L"WkDefenderMountPointMonitor" /* 消息窗口类名 */

/**************************************************/
/*               枚举                               */
/**************************************************/

/* 监控状态机 (对齐 SS MountPointMonitorStatus, 全量) */
typedef enum _WKD_MPM_STATUS {
    WkdMpmStatus_Uninitialized = 0,
    WkdMpmStatus_Initializing  = 1,
    WkdMpmStatus_Running       = 2,
    WkdMpmStatus_Paused        = 3,
    WkdMpmStatus_Error         = 4,
    WkdMpmStatus_Stopping      = 5,
    WkdMpmStatus_Stopped       = 6,
    WkdMpmStatus_Initialized   = 7,      /* 已初始化待 Start */
} WKD_MPM_STATUS, *PWKD_MPM_STATUS;

/* 驱动器类型 (对齐 SS DriveType, 全量) */
typedef enum _WKD_MPM_DRIVE {
    WkdMpmDrive_Unknown         = 0,
    WkdMpmDrive_Fixed           = 1,     /* HDD/SSD */
    WkdMpmDrive_Removable       = 2,     /* USB */
    WkdMpmDrive_Network         = 3,     /* 网络共享 */
    WkdMpmDrive_CDRom           = 4,
    WkdMpmDrive_RAMDisk         = 5,
    WkdMpmDrive_VirtualHardDisk = 6,     /* VHD/VHDX */
    WkdMpmDrive_ISOImage        = 7,     /* 挂载 ISO */
} WKD_MPM_DRIVE, *PWKD_MPM_DRIVE;

/* 挂载事件类型 (对齐 SS MountEvent, 全量; Media / Network / Virtual 为 SS 预留未触发) */
typedef enum _WKD_MPM_EVENT {
    WkdMpmEvent_DriveArrival       = 1,
    WkdMpmEvent_DriveRemoval       = 2,
    WkdMpmEvent_MediaInserted      = 3,   /* ※死代码: SS 未触发 */
    WkdMpmEvent_MediaRemoved       = 4,   /* ※死代码: SS 未触发 */
    WkdMpmEvent_NetworkConnected   = 5,   /* ※死代码: SS 未触发 */
    WkdMpmEvent_NetworkDisconnected= 6,   /* ※死代码: SS 未触发 */
    WkdMpmEvent_VirtualMounted     = 7,   /* ※死代码: SS 未触发 */
    WkdMpmEvent_VirtualUnmounted   = 8,   /* ※死代码: SS 未触发 */
} WKD_MPM_EVENT, *PWKD_MPM_EVENT;

/* 设备威胁分类 (对齐 SS DeviceThreatType, 全量) */
typedef enum _WKD_MPM_THREAT {
    WkdMpmThreat_None           = 0,
    WkdMpmThreat_BadUSB         = 1,     /* HID 伪装 (恶意 VID-PID 表) */
    WkdMpmThreat_RubberDucky    = 2,     /* 键盘注入设备 */
    WkdMpmThreat_USBKill        = 3,     /* ※死代码: SS 仅枚举未实现检测 */
    WkdMpmThreat_Masquerading   = 4,     /* 类型伪装 (USB 伪 CD-ROM 无介质) */
    WkdMpmThreat_Unauthorized   = 5,     /* 非白名单 (enforceWhitelist) */
    WkdMpmThreat_PolicyViolation= 6,     /* 策略违反 (快速挂载循环) */
} WKD_MPM_THREAT, *PWKD_MPM_THREAT;

/* 设备策略 (对齐 SS DevicePolicy, 全量) */
typedef enum _WKD_MPM_POLICY {
    WkdMpmPolicy_Allow          = 0,
    WkdMpmPolicy_AllowReadOnly  = 1,
    WkdMpmPolicy_Block          = 2,
    WkdMpmPolicy_BlockAndAlert  = 3,
    WkdMpmPolicy_RequireApproval= 4,     /* ※死代码: SS 未实现映射 (无批准通道) */
} WKD_MPM_POLICY, *PWKD_MPM_POLICY;

/**************************************************/
/*               结构体声明                         */
/**************************************************/

/* 已挂载驱动器信息 (对齐 SS DriveInfo, std::wstring → 定长 WCHAR 数组) */
typedef struct _WKD_MPM_DRIVE_INFO {

    WCHAR           DriveLetter;                        /* 盘符 (A-Z, 大写) */
    WCHAR           DevicePath[DEF_MAX_PATH];           /* 设备路径 */
    WCHAR           VolumeName[DEF_MAX_PATH];
    WCHAR           FileSystem[DEF_MAX_PATH];

    /* USB 设备信息 (仅 Removable 填充) */
    WCHAR           VendorId[WKD_MPM_VID_MAX];
    WCHAR           ProductId[WKD_MPM_VID_MAX];
    WCHAR           SerialNumber[WKD_MPM_SERIAL_MAX];
    WCHAR           FriendlyName[WKD_MPM_FRIENDLY_NAME_MAX];

    WKD_MPM_DRIVE   DriveType;
    ULONGLONG       TotalBytes;
    ULONGLONG       FreeBytes;

    BOOLEAN         IsReadOnly;
    BOOLEAN         IsWhitelisted;
    WKD_MPM_THREAT  ThreatType;

    LARGE_INTEGER   MountTime;                          /* FILETIME 100ns */
    LARGE_INTEGER   FirstSeen;
    ULONG           ConnectionCount;

} WKD_MPM_DRIVE_INFO, *PWKD_MPM_DRIVE_INFO;

/* 挂载事件 (对齐 SS MountEventInfo) */
typedef struct _WKD_MPM_MOUNT_EVENT {

    WKD_MPM_EVENT       Event;
    WCHAR               Path[DEF_MAX_PATH];
    WKD_MPM_DRIVE_INFO  DriveInfo;
    LARGE_INTEGER       Timestamp;
    WKD_MPM_POLICY      AppliedPolicy;

} WKD_MPM_MOUNT_EVENT, *PWKD_MPM_MOUNT_EVENT;

/* 设备历史条目 (对齐 SS DeviceHistoryEntry) */
typedef struct _WKD_MPM_DEVICE_HISTORY_ENTRY {

    WCHAR           SerialNumber[WKD_MPM_SERIAL_MAX];
    WCHAR           VendorId[WKD_MPM_VID_MAX];
    WCHAR           ProductId[WKD_MPM_VID_MAX];
    WCHAR           FriendlyName[WKD_MPM_FRIENDLY_NAME_MAX];
    LARGE_INTEGER   FirstSeen;
    LARGE_INTEGER   LastSeen;
    ULONG           ConnectionCount;
    BOOLEAN         IsWhitelisted;

} WKD_MPM_DEVICE_HISTORY_ENTRY, *PWKD_MPM_DEVICE_HISTORY_ENTRY;

/* 监控配置 (对齐 SS MountPointMonitorConfig, 无工厂字段, 工厂独立函数) */
typedef struct _WKD_MPM_CONFIG {

    BOOLEAN         MonitorUsb;
    BOOLEAN         MonitorNetwork;
    BOOLEAN         MonitorVirtual;
    BOOLEAN         EnforceWhitelist;
    BOOLEAN         BlockAutorun;
    BOOLEAN         DetectBadUsb;

    WKD_MPM_POLICY  DefaultRemovablePolicy;
    WKD_MPM_POLICY  DefaultNetworkPolicy;

} WKD_MPM_CONFIG, *PWKD_MPM_CONFIG;

/* 运行统计 (对齐 SS MountPointMonitorStatistics, C 原子) */
typedef struct _WKD_MPM_STATS {

    volatile LONG64 TotalEvents;
    volatile LONG64 DevicesBlocked;
    volatile LONG64 ThreatsDetected;
    volatile LONG64 UsbConnections;
    volatile LONG64 NetworkMounts;
    volatile LONG64 VirtualMounts;
    volatile LONG64 AutorunBlocked;
    volatile LONG64 Errors;
    volatile LONG64 TotalProcessingTimeUs;
    volatile LONG   ActiveMounts;
    LONG64          ByDriveType[8];                     /* WKD_MPM_DRIVE 索引 */
    LONG64          ByEventType[8];                     /* WKD_MPM_EVENT 索引 */
    LARGE_INTEGER   StartTime;

} WKD_MPM_STATS, *PWKD_MPM_STATS;

/* 恶意设备表条目 (数据驱动, 对齐 SS DetectThreats 硬编码两条, 仿 g_IocLolbinDb 可扩展) */
typedef struct _WKD_MPM_KNOWN_THREAT_DEVICE {

    USHORT          VendorId;
    USHORT          ProductId;
    WKD_MPM_THREAT  ThreatType;

} WKD_MPM_KNOWN_THREAT_DEVICE, *PWKD_MPM_KNOWN_THREAT_DEVICE;

/**************************************************/
/*               回调类型                           */
/**************************************************/

typedef VOID (*WKD_MPM_MOUNT_EVENT_CB)(_In_ const WKD_MPM_MOUNT_EVENT* Evt);
typedef WKD_MPM_POLICY (*WKD_MPM_POLICY_CB)(_In_ const WKD_MPM_DRIVE_INFO* Device);

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * 配置工厂 (对齐 SS MountPointMonitorConfig::CreateDefault/CreateHighSecurity)
 */
VOID
WkdMpmConfigDefault(
    _Out_ PWKD_MPM_CONFIG Config
    );

VOID
WkdMpmConfigHighSecurity(
    _Out_ PWKD_MPM_CONFIG Config
    );

/*
 * 生命周期 (对齐 SS Initialize/Shutdown/Start/Stop/Is*)
 */
_Must_inspect_result_
NTSTATUS
WkdMpm_Initialize(
    _In_opt_ const WKD_MPM_CONFIG* Config
    );

VOID
WkdMpm_Cleanup(
    VOID
    );

BOOLEAN
WkdMpm_IsInitialized(
    VOID
    );

WKD_MPM_STATUS
WkdMpm_GetStatus(
    VOID
    );

_Must_inspect_result_
NTSTATUS
WkdMpm_Start(
    VOID
    );

VOID
WkdMpm_Stop(
    VOID
    );

BOOLEAN
WkdMpm_IsRunning(
    VOID
    );

/*
 * 驱动器枚举 (对齐 SS GetMountedDrives 等; GetRemovableDrives/GetNetworkDrives 死代码无消费者)
 */
ULONG
WkdMpm_GetMountedDrives(
    _Out_writes_(Capacity) PWKD_MPM_DRIVE_INFO Drives,
    _In_ ULONG Capacity
    );

BOOLEAN
WkdMpm_GetDriveInfo(
    _In_ WCHAR DriveLetter,
    _Out_ PWKD_MPM_DRIVE_INFO Out
    );

ULONG
WkdMpm_GetRemovableDrives(
    _Out_writes_(Capacity) PWKD_MPM_DRIVE_INFO Drives,
    _In_ ULONG Capacity
    );      /* ※死代码: 无消费者, 保 SS 功能面 */

ULONG
WkdMpm_GetNetworkDrives(
    _Out_writes_(Capacity) PWKD_MPM_DRIVE_INFO Drives,
    _In_ ULONG Capacity
    );      /* ※死代码: 无消费者, 保 SS 功能面 */

VOID
WkdMpm_RefreshDriveList(
    VOID
    );

/*
 * 设备历史 (GetDeviceHistory 族死代码: UI 查询未接线; 内部 UpdateDeviceHistory 活)
 */
ULONG
WkdMpm_GetDeviceHistory(
    _Out_writes_(Capacity) PWKD_MPM_DEVICE_HISTORY_ENTRY History,
    _In_ ULONG Capacity
    );      /* 按 LastSeen 新→旧排序, 返回条数 */

BOOLEAN
WkdMpm_GetDeviceHistoryBySerial(
    _In_ PCWSTR SerialNumber,
    _Out_ PWKD_MPM_DEVICE_HISTORY_ENTRY Out
    );

VOID
WkdMpm_ClearDeviceHistory(
    VOID
    );

/*
 * 白名单 (序列号字符串层, 内存; SQLite 表预留死代码)
 */
VOID
WkdMpm_WhitelistDevice(
    _In_ PCWSTR SerialNumber
    );

VOID
WkdMpm_RemoveFromWhitelist(
    _In_ PCWSTR SerialNumber
    );

BOOLEAN
WkdMpm_IsWhitelisted(
    _In_ PCWSTR SerialNumber
    );

ULONG
WkdMpm_GetWhitelistedDevices(
    _Out_writes_(OutBufferChars) PWCHAR OutBuffer,
    _In_ ULONG OutBufferChars
    );      /* 每条目 NUL 终止连续存放, 返回条目数 */

/*
 * 处置 (死代码: monitor-only 门控下无调用者, SS 用户态功能面对齐; 执行层归驱动 USBDeviceControl)
 */
_Must_inspect_result_
NTSTATUS
WkdMpm_BlockDrive(
    _In_ WCHAR DriveLetter
    );      /* FSCTL_LOCK_VOLUME + FSCTL_DISMOUNT_VOLUME */

_Must_inspect_result_
NTSTATUS
WkdMpm_SetReadOnly(
    _In_ WCHAR DriveLetter,
    _In_ BOOLEAN ReadOnly
    );      /* IOCTL_DISK_SET_DISK_ATTRIBUTES */

_Must_inspect_result_
NTSTATUS
WkdMpm_EjectDrive(
    _In_ WCHAR DriveLetter
    );      /* IOCTL_STORAGE_EJECT_MEDIA */

/*
 * 回调 (对齐 SS SetMountEventCallback/SetPolicyCallback/UnregisterCallbacks)
 */
VOID
WkdMpm_SetMountEventCallback(
    _In_opt_ WKD_MPM_MOUNT_EVENT_CB Callback
    );

VOID
WkdMpm_SetPolicyCallback(
    _In_opt_ WKD_MPM_POLICY_CB Callback
    );

VOID
WkdMpm_UnregisterCallbacks(
    VOID
    );

/*
 * 配置与统计
 */
VOID
WkdMpm_GetConfiguration(
    _Out_ PWKD_MPM_CONFIG Config
    );

_Must_inspect_result_
NTSTATUS
WkdMpm_SetConfiguration(
    _In_ const WKD_MPM_CONFIG* Config
    );

VOID
WkdMpm_GetStatistics(
    _Out_ PWKD_MPM_STATS Stats
    );

VOID
WkdMpm_ResetStatistics(
    VOID
    );

DOUBLE
WkdMpm_GetAverageProcessingTimeMs(
    VOID
    );

/*
 * 诊断 (SelfTest/GetVersionString 活; Get*Name 死代码调试工具)
 */
BOOLEAN
WkdMpm_SelfTest(
    VOID
    );

VOID
WkdMpm_GetVersionString(
    _Out_writes_(Cch) PWCHAR Out,
    _In_ ULONG Cch
    );

PCWSTR
WkdMpm_GetDriveTypeName(
    _In_ WKD_MPM_DRIVE Type
    );      /* ※死代码: 调试工具 */

PCWSTR
WkdMpm_GetMountEventName(
    _In_ WKD_MPM_EVENT Event
    );      /* ※死代码: 调试工具 */

PCWSTR
WkdMpm_GetDeviceThreatTypeName(
    _In_ WKD_MPM_THREAT Threat
    );      /* 活: main.c OnMountEvent 告警描述消费 (门控 FALSE 时无实际调用) */

PCWSTR
WkdMpm_GetDevicePolicyName(
    _In_ WKD_MPM_POLICY Policy
    );      /* ※死代码: 调试工具 */

PCWSTR
WkdMpm_GetMonitorStatusName(
    _In_ WKD_MPM_STATUS Status
    );      /* ※死代码: 调试工具 */
