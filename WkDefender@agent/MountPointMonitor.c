/**************************************************/
/*  WkDefender Agent — 挂载点监控 MountPointMonitor */
/*  迁移自 ShadowStrike MountPointMonitor.cpp       */
/*  (PhantomCore/Core/FileSystem, 1883 行 C++),    */
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
/*  死代码标注: 消费链默认 g_IoaMountPointMonitorEnabled */
/*  =FALSE (main.c 回调门控), 编排器本体可独立运行/   */
/*  SelfTest。处置 API / 历史查询 / Get*Name /       */
/*  ToJson / EnumerateVolumes / USBKill /           */
/*  RequireApproval 均标注。                         */
/*  白名单与设备历史主体在内存, StorageEngine 表      */
/*  (device_history/device_whitelist) 预留死代码。    */
/*                                                  */
/*  与驱动 minifilter 关系: 本模块 WM_DEVICECHANGE    */
/*    自足事件源, 不依赖驱动事件。执行层归驱动         */
/*    USBDeviceControl (档案 #44 死代码, 不接线)。    */
/*  DefEvent 0xA001 / ALPC 0x300D 为未来驱动 USB     */
/*    事件预留 (注释标注, 本次不占用)。               */
/**************************************************/

#include "MountPointMonitor.h"

#include <windows.h>
#include <initguid.h>       /* GUID_DEVINTERFACE_USB_DEVICE 实例化 (须在 usbiodef.h 前) */
#include <winioctl.h>
#include <dbt.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <usbiodef.h>
#include <wchar.h>
#include <stdio.h>

#include "Common/TextSanitize.h"

#pragma warning(push)
#pragma warning(disable: 4505)  /* unreferenced local function（死代码分区） */
#pragma warning(disable: 4100)  /* unreferenced formal parameter */

/**************************************************/
/*                      池标签                     */
/**************************************************/

/**************************************************/
/*                      私有类型                   */
/**************************************************/

typedef struct _WKD_MPM_STATE {

    /* 生命周期 */
    volatile BOOLEAN    Initialized;
    volatile BOOLEAN    Running;
    volatile LONG       Status;                 /* WKD_MPM_STATUS */

    /* 配置 */
    WKD_MPM_CONFIG      Config;

    /* 锁组 (对齐 SS m_mutex/m_drivesMutex/m_historyMutex/
     * m_whitelistMutex/m_callbacksMutex/m_cyclesMutex) */
    CRITICAL_SECTION    StateLock;
    CRITICAL_SECTION    DrivesLock;
    CRITICAL_SECTION    HistoryLock;
    CRITICAL_SECTION    WhitelistLock;
    CRITICAL_SECTION    CallbacksLock;
    CRITICAL_SECTION    CyclesLock;

    /* 当前盘表 (盘符 A-Z 固定映射, 对齐 SS m_mountedDrives) */
    WKD_MPM_DRIVE_INFO  MountedDrives[WKD_MPM_MAX_DRIVE_LETTERS];
    BOOLEAN             DrivePresent[WKD_MPM_MAX_DRIVE_LETTERS];

    /* 设备历史 (动态数组 cap WKD_MPM_MAX_DEVICE_HISTORY,
     * 对齐 SS m_deviceHistory unordered_map) */
    PWKD_MPM_DEVICE_HISTORY_ENTRY History;
    ULONG               HistoryCount;
    ULONG               HistoryCapacity;

    /* 白名单 (动态数组, 每条目 WKD_MPM_SERIAL_MAX WCHAR,
     * 对齐 SS m_whitelistedDevices unordered_set) */
    PWCHAR              Whitelist;
    ULONG               WhitelistCount;
    ULONG               WhitelistCapacity;

    /* 快速挂载循环 (每盘符时间戳槽, GetTickCount64 毫秒,
     * 对齐 SS m_mountCycles) */
    ULONGLONG           CycleTicks[WKD_MPM_MAX_DRIVE_LETTERS][WKD_MPM_CYCLE_SLOTS];
    ULONG               CycleCount[WKD_MPM_MAX_DRIVE_LETTERS];

    /* 回调 */
    WKD_MPM_MOUNT_EVENT_CB  EventCallback;
    WKD_MPM_POLICY_CB       PolicyCallback;

    /* 统计 */
    WKD_MPM_STATS       Stats;

    /* 监控线程 */
    HANDLE              MonitorThread;
    HANDLE              StopEvent;
    HWND                MessageWindow;
    HDEVNOTIFY          DeviceNotify;

} WKD_MPM_STATE, *PWKD_MPM_STATE;

/**************************************************/
/*                      全局状态                   */
/**************************************************/

static WKD_MPM_STATE g_WkdMpm;

/* QPC 频率缓存 (对齐 wkd QueryPerformanceCounter 裸用惯例) */
static LARGE_INTEGER g_WkdMpmQpcFreq;

/**************************************************/
/*                      常量定义                   */
/**************************************************/

/* 恶意设备表 (对齐 SS DetectThreats 硬编码两条:
 *   VID 03EB:PID 2401 → RubberDucky
 *   VID 1FC9:PID 0083 → BadUSB
 * 数据驱动可扩展, 仿 g_IocLolbinDb) */
static const WKD_MPM_KNOWN_THREAT_DEVICE g_WkdMpmKnownThreatDevices[] = {
    { 0x03EB, 0x2401, WkdMpmThreat_RubberDucky },
    { 0x1FC9, 0x0083, WkdMpmThreat_BadUSB },
};
#define WKD_MPM_KNOWN_THREAT_DEVICE_COUNT \
    (sizeof(g_WkdMpmKnownThreatDevices) / sizeof(g_WkdMpmKnownThreatDevices[0]))

/**************************************************/
/*                      函数声明                   */
/**************************************************/

static BOOLEAN
WkdMpmIsValidDriveLetter(
    _In_ WCHAR c
    );

static WCHAR
WkdMpmNormalizeDriveLetter(
    _In_ WCHAR c
    );

static BOOLEAN
WkdMpmIsHexChar(
    _In_ WCHAR c
    );

static VOID
WkdMpmSanitizeDeviceString(
    _In_ PCWSTR In,
    _Out_writes_(MaxLen) PWCHAR Out,
    _In_ ULONG MaxLen
    );

static WKD_MPM_DRIVE
WkdMpmClassifyVirtualDisk(
    _In_ WCHAR DriveLetter
    );

static WKD_MPM_DRIVE
WkdMpmGetDriveTypeFromLetter(
    _In_ WCHAR DriveLetter
    );

static BOOLEAN
WkdMpmGetVolumeInformation(
    _In_ WCHAR DriveLetter,
    _Out_ PWKD_MPM_DRIVE_INFO Info
    );

static BOOLEAN
WkdMpmGetUsbDeviceInfo(
    _In_ WCHAR DriveLetter,
    _Inout_ PWKD_MPM_DRIVE_INFO Info
    );

static WKD_MPM_THREAT
WkdMpmDetectThreats(
    _In_ const WKD_MPM_DRIVE_INFO* Info
    );

static WKD_MPM_POLICY
WkdMpmDeterminePolicy(
    _In_ const WKD_MPM_DRIVE_INFO* Info
    );

static VOID
WkdMpmBlockAutorun(
    _In_ WCHAR DriveLetter
    );

static BOOLEAN
WkdMpmDetectRapidMountCycle(
    _In_ WCHAR DriveLetter
    );

static VOID
WkdMpmUpdateDeviceHistory(
    _In_ const WKD_MPM_DRIVE_INFO* Info
    );

static VOID
WkdMpmProcessDriveArrival(
    _In_ WCHAR DriveLetter
    );

static VOID
WkdMpmProcessDriveRemoval(
    _In_ WCHAR DriveLetter
    );

static VOID
WkdMpmRefreshDriveListLocked(
    VOID
    );

static VOID
WkdMpmFireMountCallback(
    _In_ WKD_MPM_EVENT Event,
    _In_ const WKD_MPM_DRIVE_INFO* Info,
    _In_ WKD_MPM_POLICY Policy,
    _In_ BOOLEAN IsArrival
    );

static BOOLEAN
WkdMpmIsWhitelistedLocked(
    _In_ PCWSTR SerialNumber
    );

static BOOLEAN
WkdMpmWhitelistGrow(
    VOID
    );

static BOOLEAN
WkdMpmHistoryGrow(
    VOID
    );

static VOID
WkdMpmHistoryEntryInit(
    _Out_ PWKD_MPM_DEVICE_HISTORY_ENTRY Entry,
    _In_ const WKD_MPM_DRIVE_INFO* Info,
    _In_ LARGE_INTEGER Now
    );

static VOID
WkdMpmStopLocked(
    VOID
    );

static LRESULT CALLBACK
WkdMpmDeviceNotifyWndProc(
    _In_ HWND hwnd,
    _In_ UINT msg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
    );

static DWORD WINAPI
WkdMpmMonitorThreadProc(
    _In_ LPVOID lpParameter
    );

static USHORT
WkdMpmParseHex16(
    _In_ PCWSTR Str
    );

/**************************************************/
/*                      配置工厂                   */
/**************************************************/

/*
 * WkdMpmConfigDefault
 *   默认配置 (对齐 SS MountPointMonitorConfig::CreateDefault):
 *   全部监控开, 白名单不强制, autorun 阻断开, BadUSB 检测开,
 *   可移除/网络默认 Allow。
 */
VOID
WkdMpmConfigDefault(
    _Out_ PWKD_MPM_CONFIG Config
    )
{
    if (Config == NULL) {
        return;
    }

    RtlZeroMemory(Config, sizeof(*Config));
    Config->MonitorUsb = TRUE;
    Config->MonitorNetwork = TRUE;
    Config->MonitorVirtual = TRUE;
    Config->EnforceWhitelist = FALSE;
    Config->BlockAutorun = TRUE;
    Config->DetectBadUsb = TRUE;
    Config->DefaultRemovablePolicy = WkdMpmPolicy_Allow;
    Config->DefaultNetworkPolicy = WkdMpmPolicy_Allow;
}

/*
 * WkdMpmConfigHighSecurity
 *   高安全配置 (对齐 SS MountPointMonitorConfig::CreateHighSecurity):
 *   强制白名单 + 可移除默认 BlockAndAlert + 网络只读。
 */
VOID
WkdMpmConfigHighSecurity(
    _Out_ PWKD_MPM_CONFIG Config
    )
{
    if (Config == NULL) {
        return;
    }

    WkdMpmConfigDefault(Config);
    Config->EnforceWhitelist = TRUE;
    Config->DefaultRemovablePolicy = WkdMpmPolicy_BlockAndAlert;
    Config->DefaultNetworkPolicy = WkdMpmPolicy_AllowReadOnly;
}

/**************************************************/
/*                    生命周期                     */
/**************************************************/

/*
 * WkdMpm_Initialize
 *   幂等初始化: 锁组 + 初始盘枚举 (GetLogicalDrives)。
 *   Config 为空 → 默认配置。对齐 SS MountPointMonitor::Initialize。
 */
NTSTATUS
WkdMpm_Initialize(
    _In_opt_ const WKD_MPM_CONFIG* Config
    )
{
    DWORD drives;
    WCHAR drive;
    ULONG i;

    if (g_WkdMpm.Initialized) {
        printf("[MountPointMonitor] Already initialized\n");
        return STATUS_SUCCESS;
    }

    WkdMpmConfigDefault(&g_WkdMpm.Config);
    if (Config != NULL) {
        g_WkdMpm.Config = *Config;
    }

    InitializeCriticalSection(&g_WkdMpm.StateLock);
    InitializeCriticalSection(&g_WkdMpm.DrivesLock);
    InitializeCriticalSection(&g_WkdMpm.HistoryLock);
    InitializeCriticalSection(&g_WkdMpm.WhitelistLock);
    InitializeCriticalSection(&g_WkdMpm.CallbacksLock);
    InitializeCriticalSection(&g_WkdMpm.CyclesLock);

    g_WkdMpm.Running = FALSE;
    g_WkdMpm.Status = WkdMpmStatus_Initialized;

    QueryPerformanceFrequency(&g_WkdMpmQpcFreq);

    /* 初始枚举 (对齐 SS Initialize: GetLogicalDrives 填充 m_mountedDrives) */
    drives = GetLogicalDrives();
    for (drive = L'A', i = 0; drive <= L'Z'; drive++, i++) {
        if (drives & (1 << i)) {
            WKD_MPM_DRIVE_INFO info;

            if (WkdMpmGetVolumeInformation(drive, &info)) {
                EnterCriticalSection(&g_WkdMpm.DrivesLock);
                g_WkdMpm.DrivePresent[i] = TRUE;
                g_WkdMpm.MountedDrives[i] = info;
                LeaveCriticalSection(&g_WkdMpm.DrivesLock);
                InterlockedIncrement(&g_WkdMpm.Stats.ActiveMounts);
            }
        }
    }

    GetSystemTimeAsFileTime((PFILETIME)&g_WkdMpm.Stats.StartTime);
    g_WkdMpm.Initialized = TRUE;

    printf("[MountPointMonitor] Initialized - %lu drives detected\n",
           (ULONG)g_WkdMpm.Stats.ActiveMounts);
    return STATUS_SUCCESS;
}

/*
 * WkdMpm_Cleanup
 *   逆序清理: 停线程 → 清盘表/历史/白名单/回调 → 删锁。
 *   对齐 SS MountPointMonitor::Shutdown。
 */
VOID
WkdMpm_Cleanup(
    VOID
    )
{
    if (!g_WkdMpm.Initialized) {
        return;
    }

    EnterCriticalSection(&g_WkdMpm.StateLock);
    WkdMpmStopLocked();
    LeaveCriticalSection(&g_WkdMpm.StateLock);

    /* 清盘表 */
    EnterCriticalSection(&g_WkdMpm.DrivesLock);
    RtlZeroMemory(g_WkdMpm.MountedDrives, sizeof(g_WkdMpm.MountedDrives));
    RtlZeroMemory(g_WkdMpm.DrivePresent, sizeof(g_WkdMpm.DrivePresent));
    LeaveCriticalSection(&g_WkdMpm.DrivesLock);

    /* 清历史 */
    EnterCriticalSection(&g_WkdMpm.HistoryLock);
    if (g_WkdMpm.History != NULL) {
        HeapFree(GetProcessHeap(), 0, g_WkdMpm.History);
        g_WkdMpm.History = NULL;
    }
    g_WkdMpm.HistoryCount = 0;
    g_WkdMpm.HistoryCapacity = 0;
    LeaveCriticalSection(&g_WkdMpm.HistoryLock);

    /* 清白名单 */
    EnterCriticalSection(&g_WkdMpm.WhitelistLock);
    if (g_WkdMpm.Whitelist != NULL) {
        HeapFree(GetProcessHeap(), 0, g_WkdMpm.Whitelist);
        g_WkdMpm.Whitelist = NULL;
    }
    g_WkdMpm.WhitelistCount = 0;
    g_WkdMpm.WhitelistCapacity = 0;
    LeaveCriticalSection(&g_WkdMpm.WhitelistLock);

    /* 清回调 */
    EnterCriticalSection(&g_WkdMpm.CallbacksLock);
    g_WkdMpm.EventCallback = NULL;
    g_WkdMpm.PolicyCallback = NULL;
    LeaveCriticalSection(&g_WkdMpm.CallbacksLock);

    g_WkdMpm.Status = WkdMpmStatus_Stopped;
    g_WkdMpm.Initialized = FALSE;

    DeleteCriticalSection(&g_WkdMpm.StateLock);
    DeleteCriticalSection(&g_WkdMpm.DrivesLock);
    DeleteCriticalSection(&g_WkdMpm.HistoryLock);
    DeleteCriticalSection(&g_WkdMpm.WhitelistLock);
    DeleteCriticalSection(&g_WkdMpm.CallbacksLock);
    DeleteCriticalSection(&g_WkdMpm.CyclesLock);

    printf("[MountPointMonitor] Shutdown complete\n");
}

/*
 * WkdMpm_IsInitialized
 *   查询初始化状态。
 */
BOOLEAN
WkdMpm_IsInitialized(
    VOID
    )
{
    return g_WkdMpm.Initialized;
}

/*
 * WkdMpm_GetStatus
 *   查询状态机。
 */
WKD_MPM_STATUS
WkdMpm_GetStatus(
    VOID
    )
{
    return (WKD_MPM_STATUS)g_WkdMpm.Status;
}

/*
 * WkdMpm_Start
 *   启动监控线程 (创建 stop event + 消息窗口线程)。
 *   对齐 SS MountPointMonitor::Start。
 */
NTSTATUS
WkdMpm_Start(
    VOID
    )
{
    if (!g_WkdMpm.Initialized) {
        printf("[MountPointMonitor] Cannot start - not initialized\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (g_WkdMpm.Running) {
        printf("[MountPointMonitor] Already running\n");
        return STATUS_SUCCESS;
    }

    g_WkdMpm.StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_WkdMpm.StopEvent == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_WkdMpm.Running = TRUE;

    g_WkdMpm.MonitorThread = CreateThread(NULL, 0, WkdMpmMonitorThreadProc,
                                          &g_WkdMpm, 0, NULL);
    if (g_WkdMpm.MonitorThread == NULL) {
        g_WkdMpm.Running = FALSE;
        CloseHandle(g_WkdMpm.StopEvent);
        g_WkdMpm.StopEvent = NULL;
        printf("[MountPointMonitor] Failed to create monitor thread\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_WkdMpm.Status = WkdMpmStatus_Running;
    printf("[MountPointMonitor] Started\n");
    return STATUS_SUCCESS;
}

/*
 * WkdMpm_Stop
 *   停止监控 (对齐 SS MountPointMonitor::Stop)。
 */
VOID
WkdMpm_Stop(
    VOID
    )
{
    EnterCriticalSection(&g_WkdMpm.StateLock);
    WkdMpmStopLocked();
    LeaveCriticalSection(&g_WkdMpm.StateLock);
}

/*
 * WkdMpm_IsRunning
 *   查询运行状态。
 */
BOOLEAN
WkdMpm_IsRunning(
    VOID
    )
{
    return g_WkdMpm.Running;
}

/*
 * WkdMpmStopLocked
 *   Stop 主逻辑: 置 running=FALSE → SetEvent → 等线程退出 (5s) →
 *   注销设备通知 → 关事件句柄。MessageWindow 由监控线程自销毁
 *   (DestroyWindow 必须运行在创建线程, 对齐 SS 注释)。
 */
static VOID
WkdMpmStopLocked(
    VOID
    )
{
    if (!g_WkdMpm.Running) {
        return;
    }

    g_WkdMpm.Running = FALSE;
    g_WkdMpm.Status = WkdMpmStatus_Stopping;

    if (g_WkdMpm.StopEvent != NULL) {
        SetEvent(g_WkdMpm.StopEvent);
    }

    if (g_WkdMpm.MonitorThread != NULL) {
        WaitForSingleObject(g_WkdMpm.MonitorThread, 5000);
        CloseHandle(g_WkdMpm.MonitorThread);
        g_WkdMpm.MonitorThread = NULL;
    }

    if (g_WkdMpm.DeviceNotify != NULL) {
        UnregisterDeviceNotification(g_WkdMpm.DeviceNotify);
        g_WkdMpm.DeviceNotify = NULL;
    }

    /* 防御性 fallback (对齐 SS StopMonitoring): 线程异常退出时消息窗口仍存活
     * 则 best-effort 销毁 + 注销窗口类; 正常退出时线程已自销毁置 NULL。 */
    if (g_WkdMpm.MessageWindow != NULL) {
        DestroyWindow(g_WkdMpm.MessageWindow);
        g_WkdMpm.MessageWindow = NULL;
        UnregisterClassW(WKD_MPM_WIN_CLASS, GetModuleHandleW(NULL));
    }

    if (g_WkdMpm.StopEvent != NULL) {
        CloseHandle(g_WkdMpm.StopEvent);
        g_WkdMpm.StopEvent = NULL;
    }

    g_WkdMpm.Status = WkdMpmStatus_Stopped;
}

/**************************************************/
/*                  卷信息采集                     */
/**************************************************/

/*
 * WkdMpmIsValidDriveLetter
 *   校验合法盘符 (A-Z/a-z)。
 */
static BOOLEAN
WkdMpmIsValidDriveLetter(
    _In_ WCHAR c
    )
{
    return (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z');
}

/*
 * WkdMpmNormalizeDriveLetter
 *   盘符转大写。
 */
static WCHAR
WkdMpmNormalizeDriveLetter(
    _In_ WCHAR c
    )
{
    return (c >= L'a' && c <= L'z') ? (WCHAR)(c - L'a' + L'A') : c;
}

/*
 * WkdMpmIsHexChar
 *   校验 0-9/A-F/a-f。
 */
static BOOLEAN
WkdMpmIsHexChar(
    _In_ WCHAR c
    )
{
    return (c >= L'0' && c <= L'9') ||
           (c >= L'A' && c <= L'F') ||
           (c >= L'a' && c <= L'f');
}

/*
 * WkdMpmSanitizeDeviceString
 *   设备可控字符串清洗 (防日志/verdict 注入, 复用 TxtSanitizeForDisplay)。
 *   serial/VID/PID 不清洗 (白名单/检测精确匹配依赖原始值)。
 */
static VOID
WkdMpmSanitizeDeviceString(
    _In_ PCWSTR In,
    _Out_writes_(MaxLen) PWCHAR Out,
    _In_ ULONG MaxLen
    )
{
    if (In == NULL || Out == NULL || MaxLen == 0) {
        return;
    }

    TxtSanitizeForDisplay(In, Out, MaxLen);
}

/*
 * WkdMpmClassifyVirtualDisk
 *   检测卷是否由虚拟盘支撑 (VHD/VHDX/ISO)。
 *   IOCTL_STORAGE_QUERY_PROPERTY → STORAGE_DEVICE_DESCRIPTOR:
 *     BusTypeVirtual(0x0E)/BusTypeFileBackedVirtual(0x11) → VHD/VHDX;
 *     BusTypeScsi + RemovableMedia + DRIVE_CDROM → ISO。
 *   对齐 SS ClassifyVirtualDisk。
 */
static WKD_MPM_DRIVE
WkdMpmClassifyVirtualDisk(
    _In_ WCHAR DriveLetter
    )
{
    WCHAR devicePath[8];
    HANDLE hDevice;
    STORAGE_PROPERTY_QUERY query;
    BYTE buffer[1024];
    DWORD bytesReturned = 0;
    PSTORAGE_DEVICE_DESCRIPTOR desc;
    WCHAR rootPath[4];

    devicePath[0] = L'\\';
    devicePath[1] = L'\\';
    devicePath[2] = L'.';
    devicePath[3] = L'\\';
    devicePath[4] = DriveLetter;
    devicePath[5] = L':';
    devicePath[6] = L'\0';

    hDevice = CreateFileW(devicePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        return WkdMpmDrive_Unknown;
    }

    RtlZeroMemory(&query, sizeof(query));
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    if (!DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY,
            &query, sizeof(query), buffer, sizeof(buffer),
            &bytesReturned, NULL)) {
        CloseHandle(hDevice);
        return WkdMpmDrive_Unknown;
    }
    CloseHandle(hDevice);

    if (bytesReturned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        return WkdMpmDrive_Unknown;
    }

    desc = (PSTORAGE_DEVICE_DESCRIPTOR)buffer;

    if (desc->BusType == BusTypeVirtual ||
        desc->BusType == BusTypeFileBackedVirtual) {
        return WkdMpmDrive_VirtualHardDisk;
    }

    if (desc->BusType == BusTypeScsi && desc->RemovableMedia) {
        /* Windows ISO mounter 通常呈现为虚拟 CD-ROM */
        rootPath[0] = DriveLetter;
        rootPath[1] = L':';
        rootPath[2] = L'\\';
        rootPath[3] = L'\0';
        if (GetDriveTypeW(rootPath) == DRIVE_CDROM) {
            return WkdMpmDrive_ISOImage;
        }
    }

    return WkdMpmDrive_Unknown;
}

/*
 * WkdMpmGetDriveTypeFromLetter
 *   GetDriveTypeW 结果映射到 WKD_MPM_DRIVE。
 *   对齐 SS GetDriveTypeFromLetter。
 */
static WKD_MPM_DRIVE
WkdMpmGetDriveTypeFromLetter(
    _In_ WCHAR DriveLetter
    )
{
    WCHAR rootPath[4];
    UINT type;

    rootPath[0] = DriveLetter;
    rootPath[1] = L':';
    rootPath[2] = L'\\';
    rootPath[3] = L'\0';

    type = GetDriveTypeW(rootPath);

    switch (type) {
        case DRIVE_FIXED:    return WkdMpmDrive_Fixed;
        case DRIVE_REMOVABLE: return WkdMpmDrive_Removable;
        case DRIVE_REMOTE:   return WkdMpmDrive_Network;
        case DRIVE_CDROM:    return WkdMpmDrive_CDRom;
        case DRIVE_RAMDISK:  return WkdMpmDrive_RAMDisk;
        default:             return WkdMpmDrive_Unknown;
    }
}

/*
 * WkdMpmGetVolumeInformation
 *   采集卷信息: 卷标/文件系统/类型/容量/只读, 虚拟盘细化分类。
 *   对齐 SS Impl::GetVolumeInformation。
 */
static BOOLEAN
WkdMpmGetVolumeInformation(
    _In_ WCHAR DriveLetter,
    _Out_ PWKD_MPM_DRIVE_INFO Info
    )
{
    WCHAR rootPath[4];
    WCHAR volumeName[DEF_MAX_PATH + 1];
    WCHAR fileSystemName[DEF_MAX_PATH + 1];
    DWORD serialNumber = 0;
    DWORD maxComponentLen = 0;
    DWORD fileSystemFlags = 0;
    ULARGE_INTEGER freeBytesAvailable;
    ULARGE_INTEGER totalBytes;
    ULARGE_INTEGER totalFreeBytes;

    if (!WkdMpmIsValidDriveLetter(DriveLetter)) {
        return FALSE;
    }

    rootPath[0] = WkdMpmNormalizeDriveLetter(DriveLetter);
    rootPath[1] = L':';
    rootPath[2] = L'\\';
    rootPath[3] = L'\0';

    if (!GetVolumeInformationW(rootPath, volumeName, DEF_MAX_PATH + 1,
            &serialNumber, &maxComponentLen, &fileSystemFlags,
            fileSystemName, DEF_MAX_PATH + 1)) {
        return FALSE;
    }

    RtlZeroMemory(Info, sizeof(*Info));
    Info->DriveLetter = WkdMpmNormalizeDriveLetter(DriveLetter);
    WkdMpmSanitizeDeviceString(volumeName, Info->VolumeName, DEF_MAX_PATH);
    WkdMpmSanitizeDeviceString(fileSystemName, Info->FileSystem, DEF_MAX_PATH);
    Info->DriveType = WkdMpmGetDriveTypeFromLetter(Info->DriveLetter);

    /* 虚拟盘细化分类 (Fixed/CDRom 才查询) */
    if (Info->DriveType == WkdMpmDrive_Fixed ||
        Info->DriveType == WkdMpmDrive_CDRom) {
        WKD_MPM_DRIVE vType = WkdMpmClassifyVirtualDisk(Info->DriveLetter);
        if (vType == WkdMpmDrive_VirtualHardDisk ||
            vType == WkdMpmDrive_ISOImage) {
            Info->DriveType = vType;
        }
    }

    if (GetDiskFreeSpaceExW(rootPath, &freeBytesAvailable,
            &totalBytes, &totalFreeBytes)) {
        Info->TotalBytes = totalBytes.QuadPart;
        Info->FreeBytes = totalFreeBytes.QuadPart;
    }

    Info->IsReadOnly = (fileSystemFlags & FILE_READ_ONLY_VOLUME) != 0;

    return TRUE;
}

/*
 * WkdMpmGetUsbDeviceInfo
 *   通过 SetupAPI 提取真实 VID/PID/序列号/友好名:
 *     IOCTL_STORAGE_GET_DEVICE_NUMBER → 设备号兜底;
 *     SetupDiGetClassDevsW(GUID_DEVINTERFACE_USB_DEVICE) →
 *     SetupDiEnumDeviceInfo + SetupDiGetDeviceInstanceIdW →
 *     instance ID "USB\VID_xxxx&PID_xxxx\serial" 解析;
 *     SPDRP_FRIENDLYNAME 友好名。
 *   对齐 SS Impl::GetUSBDeviceInfo。
 */
static BOOLEAN
WkdMpmGetUsbDeviceInfo(
    _In_ WCHAR DriveLetter,
    _Inout_ PWKD_MPM_DRIVE_INFO Info
    )
{
    WCHAR devicePath[8];
    HANDLE hDevice;
    DWORD bytesReturned = 0;
    STORAGE_DEVICE_NUMBER deviceNumber;
    HDEVINFO devInfoSet;
    SP_DEVINFO_DATA devInfoData;
    BOOLEAN found = FALSE;
    WCHAR friendlyName[WKD_MPM_FRIENDLY_NAME_MAX];

    if (!WkdMpmIsValidDriveLetter(DriveLetter)) {
        return FALSE;
    }

    devicePath[0] = L'\\';
    devicePath[1] = L'\\';
    devicePath[2] = L'.';
    devicePath[3] = L'\\';
    devicePath[4] = WkdMpmNormalizeDriveLetter(DriveLetter);
    devicePath[5] = L':';
    devicePath[6] = L'\0';

    hDevice = CreateFileW(devicePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    RtlZeroMemory(&deviceNumber, sizeof(deviceNumber));
    if (!DeviceIoControl(hDevice, IOCTL_STORAGE_GET_DEVICE_NUMBER,
            NULL, 0, &deviceNumber, sizeof(deviceNumber),
            &bytesReturned, NULL)) {
        CloseHandle(hDevice);
        return FALSE;
    }
    CloseHandle(hDevice);

    devInfoSet = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_USB_DEVICE,
                                      NULL, NULL,
                                      DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (devInfoSet == INVALID_HANDLE_VALUE) {
        wcscpy_s(Info->VendorId, WKD_MPM_VID_MAX, L"Unknown");
        wcscpy_s(Info->ProductId, WKD_MPM_VID_MAX, L"Unknown");
        _snwprintf_s(Info->SerialNumber, WKD_MPM_SERIAL_MAX, _TRUNCATE,
                     L"%u", deviceNumber.DeviceNumber);
        wcscpy_s(Info->FriendlyName, WKD_MPM_FRIENDLY_NAME_MAX, Info->VolumeName);
        return TRUE;
    }

    RtlZeroMemory(&devInfoData, sizeof(devInfoData));
    devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    for (DWORD idx = 0; SetupDiEnumDeviceInfo(devInfoSet, idx, &devInfoData); ++idx) {
        WCHAR instanceId[DEF_MAX_PATH];
        PCWSTR idStr;
        PCWSTR vidPos;
        PCWSTR pidPos;
        PCWSTR lastSlash;
        size_t idLen;

        if (!SetupDiGetDeviceInstanceIdW(devInfoSet, &devInfoData,
                instanceId, DEF_MAX_PATH, NULL)) {
            continue;
        }
        idStr = instanceId;

        /* 解析 VID_/PID_ (USB\VID_xxxx&PID_xxxx\serial) */
        vidPos = wcsstr(idStr, L"VID_");
        pidPos = wcsstr(idStr, L"PID_");
        if (vidPos == NULL || pidPos == NULL) {
            continue;
        }

        /* 校验 VID/PID 格式: 4 hex 且不越界 */
        idLen = wcslen(idStr);
        if (vidPos - idStr + 8 > (ptrdiff_t)idLen ||
            pidPos - idStr + 8 > (ptrdiff_t)idLen) {
            continue;
        }
        if (!WkdMpmIsHexChar(vidPos[4]) || !WkdMpmIsHexChar(vidPos[5]) ||
            !WkdMpmIsHexChar(vidPos[6]) || !WkdMpmIsHexChar(vidPos[7]) ||
            !WkdMpmIsHexChar(pidPos[4]) || !WkdMpmIsHexChar(pidPos[5]) ||
            !WkdMpmIsHexChar(pidPos[6]) || !WkdMpmIsHexChar(pidPos[7])) {
            continue;
        }

        wcsncpy_s(Info->VendorId, WKD_MPM_VID_MAX, vidPos + 4, 4);
        wcsncpy_s(Info->ProductId, WKD_MPM_VID_MAX, pidPos + 4, 4);

        /* 序列号 = 最后一个反斜杠之后 */
        lastSlash = wcsrchr(idStr, L'\\');
        if (lastSlash != NULL && lastSlash[1] != L'\0') {
            wcscpy_s(Info->SerialNumber, WKD_MPM_SERIAL_MAX, lastSlash + 1);
        } else {
            _snwprintf_s(Info->SerialNumber, WKD_MPM_SERIAL_MAX, _TRUNCATE,
                         L"%u", deviceNumber.DeviceNumber);
        }

        /* 友好名 (失败回退卷标, 一律清洗防日志/verdict 注入) */
        if (SetupDiGetDeviceRegistryPropertyW(devInfoSet, &devInfoData,
                SPDRP_FRIENDLYNAME, NULL, (PBYTE)friendlyName,
                sizeof(friendlyName), NULL)) {
            WkdMpmSanitizeDeviceString(friendlyName, Info->FriendlyName,
                                       WKD_MPM_FRIENDLY_NAME_MAX);
        } else {
            WkdMpmSanitizeDeviceString(Info->VolumeName, Info->FriendlyName,
                                       WKD_MPM_FRIENDLY_NAME_MAX);
        }

        found = TRUE;
        break;
    }

    SetupDiDestroyDeviceInfoList(devInfoSet);

    if (!found) {
        wcscpy_s(Info->VendorId, WKD_MPM_VID_MAX, L"Unknown");
        wcscpy_s(Info->ProductId, WKD_MPM_VID_MAX, L"Unknown");
        _snwprintf_s(Info->SerialNumber, WKD_MPM_SERIAL_MAX, _TRUNCATE,
                     L"%u", deviceNumber.DeviceNumber);
        wcscpy_s(Info->FriendlyName, WKD_MPM_FRIENDLY_NAME_MAX, Info->VolumeName);
    }

    return TRUE;
}

/**************************************************/
/*                  威胁检测/策略                   */
/**************************************************/

/*
 * WkdMpmDetectThreats
 *   设备威胁分类 (对齐 SS Impl::DetectThreats):
 *     ① enforceWhitelist 且序列号不在白名单 → Unauthorized
 *     ② USB 伪装 CD-ROM (已知 VID + 0 容量 + 无 FS) → Masquerading
 *     ③ 可移除但 0 容量 + 无 FS → RubberDucky
 *     ④ 恶意 VID/PID 数据表命中 → RubberDucky/BadUSB
 */
static WKD_MPM_THREAT
WkdMpmDetectThreats(
    _In_ const WKD_MPM_DRIVE_INFO* Info
    )
{
    USHORT vid;
    USHORT pid;
    ULONG i;

    /* ① 非白名单 (enforceWhitelist 使能时) */
    if (g_WkdMpm.Config.EnforceWhitelist) {
        BOOLEAN whitelisted;

        EnterCriticalSection(&g_WkdMpm.WhitelistLock);
        whitelisted = WkdMpmIsWhitelistedLocked(Info->SerialNumber);
        LeaveCriticalSection(&g_WkdMpm.WhitelistLock);

        if (!whitelisted) {
            return WkdMpmThreat_Unauthorized;
        }
    }

    /* ② USB 设备伪装 CD-ROM 且无实际介质 */
    if (Info->DriveType == WkdMpmDrive_CDRom &&
        _wcsicmp(Info->VendorId, L"Unknown") != 0 &&
        Info->VendorId[0] != L'\0' &&
        Info->TotalBytes == 0 &&
        Info->FileSystem[0] == L'\0') {
        return WkdMpmThreat_Masquerading;
    }

    /* ③ 可移除设备 0 容量且无文件系统 (Rubber Ducky 载荷形态) */
    if (Info->DriveType == WkdMpmDrive_Removable &&
        Info->TotalBytes == 0 &&
        Info->FileSystem[0] == L'\0') {
        return WkdMpmThreat_RubberDucky;
    }

    /* ④ 已知恶意 VID/PID (数据表) */
    vid = WkdMpmParseHex16(Info->VendorId);
    pid = WkdMpmParseHex16(Info->ProductId);
    for (i = 0; i < WKD_MPM_KNOWN_THREAT_DEVICE_COUNT; i++) {
        if (vid == g_WkdMpmKnownThreatDevices[i].VendorId &&
            pid == g_WkdMpmKnownThreatDevices[i].ProductId) {
            return g_WkdMpmKnownThreatDevices[i].ThreatType;
        }
    }

    return WkdMpmThreat_None;
}

/*
 * WkdMpmParseHex16
 *   解析宽字符串 hex (最多 4 位) → USHORT; 非 hex 返回 0。
 */
static USHORT
WkdMpmParseHex16(
    _In_ PCWSTR Str
    )
{
    USHORT result = 0;
    ULONG count = 0;

    while (Str[count] != L'\0' && count < 4) {
        WCHAR ch = Str[count];
        if (ch >= L'0' && ch <= L'9') {
            result = (USHORT)((result << 4) | (USHORT)(ch - L'0'));
        } else if (ch >= L'A' && ch <= L'F') {
            result = (USHORT)((result << 4) | (USHORT)(ch - L'A' + 10));
        } else if (ch >= L'a' && ch <= L'f') {
            result = (USHORT)((result << 4) | (USHORT)(ch - L'a' + 10));
        } else {
            return 0;
        }
        count++;
    }

    return result;
}

/*
 * WkdMpmDeterminePolicy
 *   策略判定 (对齐 SS Impl::DeterminePolicy):
 *     回调优先 → 威胁 → BlockAndAlert → 类型默认策略 → Allow。
 *   回调在锁外调用 (防回调内再进锁死锁; SS 锁内调用, 语义等价)。
 */
static WKD_MPM_POLICY
WkdMpmDeterminePolicy(
    _In_ const WKD_MPM_DRIVE_INFO* Info
    )
{
    WKD_MPM_POLICY_CB cb;
    WKD_MPM_POLICY policy;

    EnterCriticalSection(&g_WkdMpm.CallbacksLock);
    cb = g_WkdMpm.PolicyCallback;
    LeaveCriticalSection(&g_WkdMpm.CallbacksLock);

    if (cb != NULL) {
        policy = cb(Info);
        if (policy >= WkdMpmPolicy_Allow &&
            policy <= WkdMpmPolicy_RequireApproval) {
            return policy;
        }
        /* 非法策略值回退默认逻辑 */
    }

    if (Info->ThreatType != WkdMpmThreat_None) {
        return WkdMpmPolicy_BlockAndAlert;
    }

    switch (Info->DriveType) {
        case WkdMpmDrive_Removable:
            return g_WkdMpm.Config.DefaultRemovablePolicy;
        case WkdMpmDrive_Network:
            return g_WkdMpm.Config.DefaultNetworkPolicy;
        default:
            return WkdMpmPolicy_Allow;
    }
}

/*
 * WkdMpmBlockAutorun
 *   阻断可移除盘上 autorun.inf (SS fs::remove 等价: 去只读 + DeleteFileW)。
 *   对齐 SS Impl::BlockAutorun。
 */
static VOID
WkdMpmBlockAutorun(
    _In_ WCHAR DriveLetter
    )
{
    WCHAR autorunPath[DEF_MAX_PATH];
    DWORD attrs;

    if (!g_WkdMpm.Config.BlockAutorun) {
        return;
    }

    _snwprintf_s(autorunPath, DEF_MAX_PATH, _TRUNCATE, L"%c:\\autorun.inf",
                 WkdMpmNormalizeDriveLetter(DriveLetter));

    attrs = GetFileAttributesW(autorunPath);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return;
    }

    if (attrs & FILE_ATTRIBUTE_READONLY) {
        SetFileAttributesW(autorunPath, attrs & ~FILE_ATTRIBUTE_READONLY);
    }

    if (DeleteFileW(autorunPath)) {
        InterlockedIncrement64(&g_WkdMpm.Stats.AutorunBlocked);
        printf("[MountPointMonitor] Blocked autorun.inf on drive %c\n",
               WkdMpmNormalizeDriveLetter(DriveLetter));
    }
}

/*
 * WkdMpmDetectRapidMountCycle
 *   快速挂载/卸载循环检测 (30s 窗内 >=3 次 → 规避/磨损攻击)。
 *   对齐 SS Impl::DetectRapidMountCycle (steady_clock → GetTickCount64)。
 */
static BOOLEAN
WkdMpmDetectRapidMountCycle(
    _In_ WCHAR DriveLetter
    )
{
    ULONG idx = (ULONG)(WkdMpmNormalizeDriveLetter(DriveLetter) - L'A');
    ULONGLONG now;
    ULONG write = 0;
    ULONG i;
    BOOLEAN detected;

    now = GetTickCount64();

    EnterCriticalSection(&g_WkdMpm.CyclesLock);

    /* 剔除窗口外时间戳 */
    for (i = 0; i < g_WkdMpm.CycleCount[idx]; i++) {
        if (g_WkdMpm.CycleTicks[idx][i] +
            (ULONGLONG)WKD_MPM_RAPID_CYCLE_WINDOW_SEC * 1000ull >= now) {
            g_WkdMpm.CycleTicks[idx][write++] = g_WkdMpm.CycleTicks[idx][i];
        }
    }

    /* 追加当前时间戳 (槽满则滚动覆盖最旧) */
    if (write >= WKD_MPM_CYCLE_SLOTS) {
        for (i = 1; i < write; i++) {
            g_WkdMpm.CycleTicks[idx][i - 1] = g_WkdMpm.CycleTicks[idx][i];
        }
        g_WkdMpm.CycleTicks[idx][write - 1] = now;
    } else {
        g_WkdMpm.CycleTicks[idx][write] = now;
        write++;
    }
    g_WkdMpm.CycleCount[idx] = write;

    detected = (write >= WKD_MPM_RAPID_CYCLE_THRESHOLD);

    LeaveCriticalSection(&g_WkdMpm.CyclesLock);

    if (detected) {
        printf("[MountPointMonitor] Rapid mount/unmount cycle detected on drive %c "
               "(%lu events in %u sec window)\n",
               DriveLetter, write, WKD_MPM_RAPID_CYCLE_WINDOW_SEC);
    }

    return detected;
}

/**************************************************/
/*                  事件处理                       */
/**************************************************/

/*
 * WkdMpmProcessDriveArrival
 *   盘符到达全流程 (对齐 SS Impl::ProcessDriveArrival):
 *     卷信息 → USB 信息 (仅可移除) → 白名单标记 → 威胁检测 →
 *     快速挂载循环 → 策略 → autorun 阻断 → 历史 → 盘表 → 回调。
 */
static VOID
WkdMpmProcessDriveArrival(
    _In_ WCHAR DriveLetter
    )
{
    WKD_MPM_DRIVE_INFO info;
    WKD_MPM_POLICY policy;
    ULONG idx;
    BOOLEAN blocked = FALSE;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    LONGLONG durationUs;

    DriveLetter = WkdMpmNormalizeDriveLetter(DriveLetter);
    if (!WkdMpmIsValidDriveLetter(DriveLetter)) {
        return;
    }

    QueryPerformanceCounter(&start);

    if (!WkdMpmGetVolumeInformation(DriveLetter, &info)) {
        return;
    }

    /* USB 设备信息 (仅可移除) + 分类统计 */
    if (info.DriveType == WkdMpmDrive_Removable) {
        WkdMpmGetUsbDeviceInfo(DriveLetter, &info);
        InterlockedIncrement64(&g_WkdMpm.Stats.UsbConnections);
    } else if (info.DriveType == WkdMpmDrive_Network) {
        InterlockedIncrement64(&g_WkdMpm.Stats.NetworkMounts);
    } else if (info.DriveType == WkdMpmDrive_VirtualHardDisk ||
               info.DriveType == WkdMpmDrive_ISOImage) {
        InterlockedIncrement64(&g_WkdMpm.Stats.VirtualMounts);
        printf("[MountPointMonitor] Virtual disk mounted on %c (type=%d) "
               "- potential MotW bypass vector\n",
               DriveLetter, (int)info.DriveType);
    }

    GetSystemTimeAsFileTime((PFILETIME)&info.MountTime);

    /* 白名单标记 */
    EnterCriticalSection(&g_WkdMpm.WhitelistLock);
    info.IsWhitelisted = WkdMpmIsWhitelistedLocked(info.SerialNumber);
    LeaveCriticalSection(&g_WkdMpm.WhitelistLock);

    /* 威胁检测 */
    if (g_WkdMpm.Config.DetectBadUsb) {
        info.ThreatType = WkdMpmDetectThreats(&info);
        if (info.ThreatType != WkdMpmThreat_None) {
            InterlockedIncrement64(&g_WkdMpm.Stats.ThreatsDetected);
            printf("[MountPointMonitor] Threat detected on drive %c - Type: %d\n",
                   DriveLetter, (int)info.ThreatType);
        }
    }

    /* 快速挂载循环 (仅无其他威胁时升级) */
    if (WkdMpmDetectRapidMountCycle(DriveLetter) &&
        info.ThreatType == WkdMpmThreat_None) {
        info.ThreatType = WkdMpmThreat_PolicyViolation;
        InterlockedIncrement64(&g_WkdMpm.Stats.ThreatsDetected);
    }

    /* 策略判定与阻断标记 */
    policy = WkdMpmDeterminePolicy(&info);
    if (policy == WkdMpmPolicy_Block ||
        policy == WkdMpmPolicy_BlockAndAlert) {
        blocked = TRUE;
        InterlockedIncrement64(&g_WkdMpm.Stats.DevicesBlocked);
        printf("[MountPointMonitor] Drive %c blocked by policy\n", DriveLetter);
    }

    /* autorun 阻断 (仅未阻断的可移除盘) */
    if (!blocked && info.DriveType == WkdMpmDrive_Removable) {
        WkdMpmBlockAutorun(DriveLetter);
    }

    /* 设备历史 */
    WkdMpmUpdateDeviceHistory(&info);

    /* 盘表登记 (仅新挂载递增 activeMounts) */
    idx = (ULONG)(DriveLetter - L'A');
    EnterCriticalSection(&g_WkdMpm.DrivesLock);
    if (!g_WkdMpm.DrivePresent[idx]) {
        g_WkdMpm.DrivePresent[idx] = TRUE;
        InterlockedIncrement(&g_WkdMpm.Stats.ActiveMounts);
    }
    g_WkdMpm.MountedDrives[idx] = info;
    LeaveCriticalSection(&g_WkdMpm.DrivesLock);

    /* 分类型统计 */
    if ((ULONG)info.DriveType < 8) {
        InterlockedIncrement64(&g_WkdMpm.Stats.ByDriveType[(ULONG)info.DriveType]);
    }

    /* 回调 (锁外) */
    WkdMpmFireMountCallback(WkdMpmEvent_DriveArrival, &info, policy, TRUE);

    InterlockedIncrement64(&g_WkdMpm.Stats.TotalEvents);
    if ((ULONG)WkdMpmEvent_DriveArrival < 8) {
        InterlockedIncrement64(&g_WkdMpm.Stats.ByEventType[(ULONG)WkdMpmEvent_DriveArrival]);
    }

    QueryPerformanceCounter(&end);
    if (g_WkdMpmQpcFreq.QuadPart != 0) {
        durationUs = (end.QuadPart - start.QuadPart) * 1000000 / g_WkdMpmQpcFreq.QuadPart;
        InterlockedAdd64(&g_WkdMpm.Stats.TotalProcessingTimeUs, durationUs);
    }

    printf("[MountPointMonitor] Drive %c arrived - Type: %d, Volume: %ls, FS: %ls, Policy: %d\n",
           DriveLetter, (int)info.DriveType,
           info.VolumeName, info.FileSystem, (int)policy);
}

/*
 * WkdMpmProcessDriveRemoval
 *   盘符移除 (对齐 SS Impl::ProcessDriveRemoval):
 *     盘表摘除 → activeMounts-- → 回调 → 统计。
 */
static VOID
WkdMpmProcessDriveRemoval(
    _In_ WCHAR DriveLetter
    )
{
    WKD_MPM_DRIVE_INFO info;
    ULONG idx;
    BOOLEAN found = FALSE;

    DriveLetter = WkdMpmNormalizeDriveLetter(DriveLetter);

    idx = (ULONG)(DriveLetter - L'A');
    EnterCriticalSection(&g_WkdMpm.DrivesLock);
    if (g_WkdMpm.DrivePresent[idx]) {
        info = g_WkdMpm.MountedDrives[idx];
        g_WkdMpm.DrivePresent[idx] = FALSE;
        found = TRUE;
        InterlockedDecrement(&g_WkdMpm.Stats.ActiveMounts);
    }
    LeaveCriticalSection(&g_WkdMpm.DrivesLock);

    if (found) {
        WkdMpmFireMountCallback(WkdMpmEvent_DriveRemoval, &info,
                                WkdMpmPolicy_Allow, FALSE);

        InterlockedIncrement64(&g_WkdMpm.Stats.TotalEvents);
        if ((ULONG)WkdMpmEvent_DriveRemoval < 8) {
            InterlockedIncrement64(&g_WkdMpm.Stats.ByEventType[(ULONG)WkdMpmEvent_DriveRemoval]);
        }

        printf("[MountPointMonitor] Drive %c removed\n", DriveLetter);
    }
}

/*
 * WkdMpmFireMountCallback
 *   锁外分发挂载事件回调 (锁内取副本, 对齐 SS 复制回调锁外调用)。
 */
static VOID
WkdMpmFireMountCallback(
    _In_ WKD_MPM_EVENT Event,
    _In_ const WKD_MPM_DRIVE_INFO* Info,
    _In_ WKD_MPM_POLICY Policy,
    _In_ BOOLEAN IsArrival
    )
{
    WKD_MPM_MOUNT_EVENT_CB cb;
    WKD_MPM_MOUNT_EVENT evt;
    LARGE_INTEGER now;

    EnterCriticalSection(&g_WkdMpm.CallbacksLock);
    cb = g_WkdMpm.EventCallback;
    LeaveCriticalSection(&g_WkdMpm.CallbacksLock);

    if (cb == NULL) {
        return;
    }

    GetSystemTimeAsFileTime((PFILETIME)&now);

    RtlZeroMemory(&evt, sizeof(evt));
    evt.Event = Event;
    evt.DriveInfo = *Info;
    evt.Timestamp = now;
    evt.AppliedPolicy = Policy;
    _snwprintf_s(evt.Path, DEF_MAX_PATH, _TRUNCATE, L"%c:", Info->DriveLetter);

    (void)IsArrival;

    cb(&evt);
}

/**************************************************/
/*              消息窗口监控线程                   */
/**************************************************/

/*
 * WkdMpmDeviceNotifyWndProc
 *   设备通知窗口过程 (对齐 SS Impl::DeviceNotifyWndProc):
 *     WM_DEVICECHANGE + DBT_DEVICEARRIVAL/DBT_DEVICEREMOVECOMPLETE +
 *     DBT_DEVTYP_VOLUME → 校验 dbch_size → 单位掩码逐位 A..Z 解析。
 */
static LRESULT CALLBACK
WkdMpmDeviceNotifyWndProc(
    _In_ HWND hwnd,
    _In_ UINT msg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
    )
{
    if (msg == WM_DEVICECHANGE) {
        PWKD_MPM_STATE pThis =
            (PWKD_MPM_STATE)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

        if (pThis != NULL) {
            if (wParam == DBT_DEVICEARRIVAL ||
                wParam == DBT_DEVICEREMOVECOMPLETE) {
                PDEV_BROADCAST_HDR pHdr = (PDEV_BROADCAST_HDR)lParam;

                /* 结构校验后再 cast (防坏指针) */
                if (pHdr != NULL &&
                    pHdr->dbch_size >= sizeof(DEV_BROADCAST_HDR)) {

                    if (pHdr->dbch_devicetype == DBT_DEVTYP_VOLUME) {
                        if (pHdr->dbch_size >= sizeof(DEV_BROADCAST_VOLUME)) {
                            PDEV_BROADCAST_VOLUME pVolume =
                                (PDEV_BROADCAST_VOLUME)pHdr;
                            DWORD unitMask = pVolume->dbcv_unitmask;

                            for (WCHAR drive = L'A';
                                 drive <= L'Z' && unitMask != 0; drive++) {
                                if (unitMask & 1) {
                                    if (wParam == DBT_DEVICEARRIVAL) {
                                        WkdMpmProcessDriveArrival(drive);
                                    } else {
                                        WkdMpmProcessDriveRemoval(drive);
                                    }
                                }
                                unitMask >>= 1;
                            }
                        }
                    }
                }
            }
        }
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/*
 * WkdMpmMonitorThreadProc
 *   监控线程主循环 (对齐 SS Impl::MonitorThreadProc):
 *     注册窗口类 → 创建 HWND_MESSAGE 消息窗口 → GWLP_USERDATA →
 *     RegisterDeviceNotification (USB 接口) → 消息循环
 *     (PeekMessage + MsgWaitForMultipleObjects(stopEvent, 1s))。
 *   超时分支轮询兜底 RefreshDriveList。
 *   退出时自销毁窗口 (DestroyWindow 必须在创建线程) + 注销窗口类。
 */
static DWORD WINAPI
WkdMpmMonitorThreadProc(
    _In_ LPVOID lpParameter
    )
{
    PWKD_MPM_STATE pThis = (PWKD_MPM_STATE)lpParameter;
    WNDCLASSEXW wc;
    ATOM atom;
    DEV_BROADCAST_DEVICEINTERFACE filter;
    MSG msg;

    if (pThis == NULL) {
        return 1;
    }

    RtlZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = WkdMpmDeviceNotifyWndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = WKD_MPM_WIN_CLASS;

    atom = RegisterClassExW(&wc);
    if (atom == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        printf("[MountPointMonitor] RegisterClassExW failed\n");
        return 1;
    }

    pThis->MessageWindow = CreateWindowExW(0, WKD_MPM_WIN_CLASS,
        L"MountPointMonitor", 0, 0, 0, 0, 0,
        HWND_MESSAGE, NULL, GetModuleHandleW(NULL), NULL);
    if (pThis->MessageWindow == NULL) {
        printf("[MountPointMonitor] Failed to create message window\n");
        return 1;
    }

    SetWindowLongPtrW(pThis->MessageWindow, GWLP_USERDATA,
                      (LONG_PTR)pThis);

    /* 注册设备通知 — 卷事件 + USB 接口 */
    RtlZeroMemory(&filter, sizeof(filter));
    filter.dbcc_size = sizeof(filter);
    filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    filter.dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE;

    pThis->DeviceNotify = RegisterDeviceNotificationW(
        pThis->MessageWindow, &filter,
        DEVICE_NOTIFY_WINDOW_HANDLE | DEVICE_NOTIFY_ALL_INTERFACE_CLASSES);
    if (pThis->DeviceNotify == NULL) {
        printf("[MountPointMonitor] RegisterDeviceNotificationW failed - "
               "polling via RefreshDriveList still works\n");
    }

    printf("[MountPointMonitor] Monitor thread started\n");

    /* 消息循环 + stop event 等待 (1s 轮询兜底) */
    while (pThis->Running) {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        DWORD result = MsgWaitForMultipleObjects(
            1, &pThis->StopEvent, FALSE,
            WKD_MPM_POLLING_INTERVAL_MS, QS_ALLINPUT);

        if (result == WAIT_OBJECT_0) {
            break;  /* stop event */
        }
        if (result == WAIT_TIMEOUT) {
            /* 轮询兜底 (设备事件可能未被 RegisterDeviceNotification 捕获) */
            WkdMpmRefreshDriveListLocked();
        }
    }

    /* 线程自销毁消息窗口 (创建线程) + 注销窗口类 */
    if (pThis->MessageWindow != NULL) {
        DestroyWindow(pThis->MessageWindow);
        pThis->MessageWindow = NULL;
    }
    UnregisterClassW(WKD_MPM_WIN_CLASS, GetModuleHandleW(NULL));

    return 0;
}

/**************************************************/
/*                  驱动器枚举                     */
/**************************************************/

/*
 * WkdMpm_GetMountedDrives
 *   获取全部已挂载驱动器 (对齐 SS GetMountedDrives)。
 *   返回写入条数 (受 Capacity 限制)。
 */
ULONG
WkdMpm_GetMountedDrives(
    _Out_writes_(Capacity) PWKD_MPM_DRIVE_INFO Drives,
    _In_ ULONG Capacity
    )
{
    ULONG count = 0;
    ULONG i;

    if (Drives == NULL || Capacity == 0) {
        return 0;
    }

    EnterCriticalSection(&g_WkdMpm.DrivesLock);
    for (i = 0; i < WKD_MPM_MAX_DRIVE_LETTERS && count < Capacity; i++) {
        if (g_WkdMpm.DrivePresent[i]) {
            Drives[count++] = g_WkdMpm.MountedDrives[i];
        }
    }
    LeaveCriticalSection(&g_WkdMpm.DrivesLock);

    return count;
}

/*
 * WkdMpm_GetDriveInfo
 *   按盘符查询驱动器信息 (对齐 SS GetDriveInfo)。
 */
BOOLEAN
WkdMpm_GetDriveInfo(
    _In_ WCHAR DriveLetter,
    _Out_ PWKD_MPM_DRIVE_INFO Out
    )
{
    ULONG idx;
    BOOLEAN present;

    DriveLetter = WkdMpmNormalizeDriveLetter(DriveLetter);
    if (!WkdMpmIsValidDriveLetter(DriveLetter) || Out == NULL) {
        return FALSE;
    }

    idx = (ULONG)(DriveLetter - L'A');

    EnterCriticalSection(&g_WkdMpm.DrivesLock);
    present = g_WkdMpm.DrivePresent[idx];
    if (present) {
        *Out = g_WkdMpm.MountedDrives[idx];
    }
    LeaveCriticalSection(&g_WkdMpm.DrivesLock);

    return present;
}

/*
 * WkdMpm_GetRemovableDrives
 *   获取可移除驱动器列表。※死代码: 无消费者, 保 SS 功能面。
 */
ULONG
WkdMpm_GetRemovableDrives(
    _Out_writes_(Capacity) PWKD_MPM_DRIVE_INFO Drives,
    _In_ ULONG Capacity
    )
{
    ULONG count = 0;
    ULONG i;

    if (Drives == NULL || Capacity == 0) {
        return 0;
    }

    EnterCriticalSection(&g_WkdMpm.DrivesLock);
    for (i = 0; i < WKD_MPM_MAX_DRIVE_LETTERS && count < Capacity; i++) {
        if (g_WkdMpm.DrivePresent[i] &&
            g_WkdMpm.MountedDrives[i].DriveType == WkdMpmDrive_Removable) {
            Drives[count++] = g_WkdMpm.MountedDrives[i];
        }
    }
    LeaveCriticalSection(&g_WkdMpm.DrivesLock);

    return count;
}

/*
 * WkdMpm_GetNetworkDrives
 *   获取网络驱动器列表。※死代码: 无消费者, 保 SS 功能面。
 */
ULONG
WkdMpm_GetNetworkDrives(
    _Out_writes_(Capacity) PWKD_MPM_DRIVE_INFO Drives,
    _In_ ULONG Capacity
    )
{
    ULONG count = 0;
    ULONG i;

    if (Drives == NULL || Capacity == 0) {
        return 0;
    }

    EnterCriticalSection(&g_WkdMpm.DrivesLock);
    for (i = 0; i < WKD_MPM_MAX_DRIVE_LETTERS && count < Capacity; i++) {
        if (g_WkdMpm.DrivePresent[i] &&
            g_WkdMpm.MountedDrives[i].DriveType == WkdMpmDrive_Network) {
            Drives[count++] = g_WkdMpm.MountedDrives[i];
        }
    }
    LeaveCriticalSection(&g_WkdMpm.DrivesLock);

    return count;
}

/*
 * WkdMpm_RefreshDriveList
 *   快照差量刷新 (新盘 → arrival, 消失 → removal)。
 *   对齐 SS RefreshDriveList; 监控线程 1s 轮询兜底调用锁内版。
 */
VOID
WkdMpm_RefreshDriveList(
    VOID
    )
{
    if (!g_WkdMpm.Initialized) {
        return;
    }

    WkdMpmRefreshDriveListLocked();
}

/*
 * WkdMpmRefreshDriveListLocked
 *   RefreshDriveList 内部实现: GetLogicalDrives 快照与盘表差量。
 */
static VOID
WkdMpmRefreshDriveListLocked(
    VOID
    )
{
    DWORD drives;
    BOOLEAN present[WKD_MPM_MAX_DRIVE_LETTERS];
    ULONG i;

    if (!g_WkdMpm.Initialized) {
        return;
    }

    drives = GetLogicalDrives();

    for (i = 0; i < WKD_MPM_MAX_DRIVE_LETTERS; i++) {
        present[i] = (drives & (1 << i)) != 0;
    }

    /* 差量处理 (检查 tracked 状态用短锁, 处理在锁外) */
    for (i = 0; i < WKD_MPM_MAX_DRIVE_LETTERS; i++) {
        BOOLEAN tracked;

        EnterCriticalSection(&g_WkdMpm.DrivesLock);
        tracked = g_WkdMpm.DrivePresent[i];
        LeaveCriticalSection(&g_WkdMpm.DrivesLock);

        if (present[i] && !tracked) {
            WkdMpmProcessDriveArrival((WCHAR)(L'A' + i));
        } else if (!present[i] && tracked) {
            WkdMpmProcessDriveRemoval((WCHAR)(L'A' + i));
        }
    }
}

/**************************************************/
/*                  设备历史                       */
/**************************************************/

/*
 * WkdMpm_GetDeviceHistory
 *   获取设备连接历史 (按 LastSeen 新→旧排序)。
 *   ※死代码: UI 查询未接线, 保 SS 功能面。
 */
ULONG
WkdMpm_GetDeviceHistory(
    _Out_writes_(Capacity) PWKD_MPM_DEVICE_HISTORY_ENTRY History,
    _In_ ULONG Capacity
    )
{
    ULONG count;
    ULONG i;
    ULONG j;

    if (History == NULL || Capacity == 0) {
        return 0;
    }

    EnterCriticalSection(&g_WkdMpm.HistoryLock);

    count = (g_WkdMpm.HistoryCount < Capacity)
                ? g_WkdMpm.HistoryCount : Capacity;
    for (i = 0; i < count; i++) {
        History[i] = g_WkdMpm.History[i];
    }

    LeaveCriticalSection(&g_WkdMpm.HistoryLock);

    /* 选择排序 (LastSeen 新→旧, 对齐 SS std::sort desc) */
    for (i = 0; i + 1 < count; i++) {
        ULONG best = i;
        for (j = i + 1; j < count; j++) {
            if (History[j].LastSeen.QuadPart >
                History[best].LastSeen.QuadPart) {
                best = j;
            }
        }
        if (best != i) {
            WKD_MPM_DEVICE_HISTORY_ENTRY tmp = History[i];
            History[i] = History[best];
            History[best] = tmp;
        }
    }

    return count;
}

/*
 * WkdMpm_GetDeviceHistoryBySerial
 *   按序列号查询设备历史。※死代码: UI 查询未接线。
 */
BOOLEAN
WkdMpm_GetDeviceHistoryBySerial(
    _In_ PCWSTR SerialNumber,
    _Out_ PWKD_MPM_DEVICE_HISTORY_ENTRY Out
    )
{
    ULONG i;
    BOOLEAN found = FALSE;

    if (SerialNumber == NULL || Out == NULL) {
        return FALSE;
    }

    EnterCriticalSection(&g_WkdMpm.HistoryLock);

    for (i = 0; i < g_WkdMpm.HistoryCount; i++) {
        if (_wcsicmp(g_WkdMpm.History[i].SerialNumber, SerialNumber) == 0) {
            *Out = g_WkdMpm.History[i];
            found = TRUE;
            break;
        }
    }

    LeaveCriticalSection(&g_WkdMpm.HistoryLock);

    return found;
}

/*
 * WkdMpm_ClearDeviceHistory
 *   清空设备历史。※死代码: UI 查询未接线。
 */
VOID
WkdMpm_ClearDeviceHistory(
    VOID
    )
{
    EnterCriticalSection(&g_WkdMpm.HistoryLock);
    g_WkdMpm.HistoryCount = 0;
    LeaveCriticalSection(&g_WkdMpm.HistoryLock);
}

/*
 * WkdMpmUpdateDeviceHistory
 *   设备历史更新 (对齐 SS Impl::UpdateDeviceHistory):
 *     已有 → lastSeen + connectionCount++;
 *     新设备 → cap 淘汰 lastSeen 最旧 → 插入。
 *   序列号空/Unknown 跳过。
 */
static VOID
WkdMpmUpdateDeviceHistory(
    _In_ const WKD_MPM_DRIVE_INFO* Info
    )
{
    LARGE_INTEGER now;
    ULONG i;

    if (Info->SerialNumber[0] == L'\0' ||
        _wcsicmp(Info->SerialNumber, L"Unknown") == 0) {
        return;
    }

    GetSystemTimeAsFileTime((PFILETIME)&now);

    EnterCriticalSection(&g_WkdMpm.HistoryLock);

    for (i = 0; i < g_WkdMpm.HistoryCount; i++) {
        if (_wcsicmp(g_WkdMpm.History[i].SerialNumber,
                     Info->SerialNumber) == 0) {
            g_WkdMpm.History[i].LastSeen = now;
            g_WkdMpm.History[i].ConnectionCount++;
            LeaveCriticalSection(&g_WkdMpm.HistoryLock);
            return;
        }
    }

    /* 新设备: cap 淘汰 lastSeen 最旧条目 */
    if (g_WkdMpm.HistoryCount >= WKD_MPM_MAX_DEVICE_HISTORY) {
        ULONG oldest = 0;

        for (i = 1; i < g_WkdMpm.HistoryCount; i++) {
            if (g_WkdMpm.History[i].LastSeen.QuadPart <
                g_WkdMpm.History[oldest].LastSeen.QuadPart) {
                oldest = i;
            }
        }

        WkdMpmHistoryEntryInit(&g_WkdMpm.History[oldest], Info, now);
        LeaveCriticalSection(&g_WkdMpm.HistoryLock);
        return;
    }

    if (g_WkdMpm.HistoryCount >= g_WkdMpm.HistoryCapacity) {
        if (!WkdMpmHistoryGrow()) {
            LeaveCriticalSection(&g_WkdMpm.HistoryLock);
            return;
        }
    }

    WkdMpmHistoryEntryInit(&g_WkdMpm.History[g_WkdMpm.HistoryCount], Info, now);
    g_WkdMpm.HistoryCount++;

    LeaveCriticalSection(&g_WkdMpm.HistoryLock);
}

/*
 * WkdMpmHistoryEntryInit
 *   历史条目初始化 (对齐 SS UpdateDeviceHistory 新条目字段)。
 */
static VOID
WkdMpmHistoryEntryInit(
    _Out_ PWKD_MPM_DEVICE_HISTORY_ENTRY Entry,
    _In_ const WKD_MPM_DRIVE_INFO* Info,
    _In_ LARGE_INTEGER Now
    )
{
    RtlZeroMemory(Entry, sizeof(*Entry));

    wcscpy_s(Entry->SerialNumber, WKD_MPM_SERIAL_MAX, Info->SerialNumber);
    wcscpy_s(Entry->VendorId, WKD_MPM_VID_MAX, Info->VendorId);
    wcscpy_s(Entry->ProductId, WKD_MPM_VID_MAX, Info->ProductId);
    wcscpy_s(Entry->FriendlyName, WKD_MPM_FRIENDLY_NAME_MAX, Info->FriendlyName);

    Entry->FirstSeen = Now;
    Entry->LastSeen = Now;
    Entry->ConnectionCount = 1;
    Entry->IsWhitelisted = Info->IsWhitelisted;
}

/*
 * WkdMpmHistoryGrow
 *   历史动态数组扩容 (初始 32, 倍增, cap 由 MAX_DEVICE_HISTORY 外部约束)。
 */
static BOOLEAN
WkdMpmHistoryGrow(
    VOID
    )
{
    ULONG newCap = g_WkdMpm.HistoryCapacity ?
                   g_WkdMpm.HistoryCapacity * 2 : 32;
    SIZE_T bytes = (SIZE_T)newCap * sizeof(WKD_MPM_DEVICE_HISTORY_ENTRY);
    PWKD_MPM_DEVICE_HISTORY_ENTRY nb;

    if (g_WkdMpm.History == NULL) {
        nb = (PWKD_MPM_DEVICE_HISTORY_ENTRY)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
    } else {
        nb = (PWKD_MPM_DEVICE_HISTORY_ENTRY)HeapReAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, g_WkdMpm.History, bytes);
    }

    if (nb == NULL) {
        return FALSE;
    }

    g_WkdMpm.History = nb;
    g_WkdMpm.HistoryCapacity = newCap;
    return TRUE;
}

/**************************************************/
/*                    白名单                       */
/**************************************************/

/*
 * WkdMpm_WhitelistDevice
 *   白名单添加设备序列号 (对齐 SS WhitelistDevice)。
 */
VOID
WkdMpm_WhitelistDevice(
    _In_ PCWSTR SerialNumber
    )
{
    if (SerialNumber == NULL || SerialNumber[0] == L'\0') {
        return;
    }

    EnterCriticalSection(&g_WkdMpm.WhitelistLock);

    if (!WkdMpmIsWhitelistedLocked(SerialNumber)) {
        if (g_WkdMpm.WhitelistCount >= g_WkdMpm.WhitelistCapacity) {
            if (!WkdMpmWhitelistGrow()) {
                LeaveCriticalSection(&g_WkdMpm.WhitelistLock);
                return;
            }
        }
        wcscpy_s(&g_WkdMpm.Whitelist[g_WkdMpm.WhitelistCount * WKD_MPM_SERIAL_MAX],
                 WKD_MPM_SERIAL_MAX, SerialNumber);
        g_WkdMpm.WhitelistCount++;
        printf("[MountPointMonitor] Device whitelisted - %ls\n", SerialNumber);
    }

    LeaveCriticalSection(&g_WkdMpm.WhitelistLock);
}

/*
 * WkdMpm_RemoveFromWhitelist
 *   白名单移除设备序列号 (对齐 SS RemoveFromWhitelist)。
 */
VOID
WkdMpm_RemoveFromWhitelist(
    _In_ PCWSTR SerialNumber
    )
{
    ULONG i;

    if (SerialNumber == NULL || SerialNumber[0] == L'\0') {
        return;
    }

    EnterCriticalSection(&g_WkdMpm.WhitelistLock);

    for (i = 0; i < g_WkdMpm.WhitelistCount; i++) {
        if (_wcsicmp(&g_WkdMpm.Whitelist[i * WKD_MPM_SERIAL_MAX],
                     SerialNumber) == 0) {
            g_WkdMpm.WhitelistCount--;
            if (i < g_WkdMpm.WhitelistCount) {
                wcscpy_s(&g_WkdMpm.Whitelist[i * WKD_MPM_SERIAL_MAX],
                         WKD_MPM_SERIAL_MAX,
                         &g_WkdMpm.Whitelist[g_WkdMpm.WhitelistCount *
                                             WKD_MPM_SERIAL_MAX]);
            }
            printf("[MountPointMonitor] Device removed from whitelist - %ls\n",
                   SerialNumber);
            break;
        }
    }

    LeaveCriticalSection(&g_WkdMpm.WhitelistLock);
}

/*
 * WkdMpm_IsWhitelisted
 *   查询设备是否在白名单 (对齐 SS IsWhitelisted)。
 */
BOOLEAN
WkdMpm_IsWhitelisted(
    _In_ PCWSTR SerialNumber
    )
{
    BOOLEAN result;

    if (SerialNumber == NULL) {
        return FALSE;
    }

    EnterCriticalSection(&g_WkdMpm.WhitelistLock);
    result = WkdMpmIsWhitelistedLocked(SerialNumber);
    LeaveCriticalSection(&g_WkdMpm.WhitelistLock);

    return result;
}

/*
 * WkdMpm_GetWhitelistedDevices
 *   获取白名单列表 (对齐 SS GetWhitelistedDevices):
 *   每条目 NUL 终止连续写入 OutBuffer, 返回条目数。
 */
ULONG
WkdMpm_GetWhitelistedDevices(
    _Out_writes_(OutBufferChars) PWCHAR OutBuffer,
    _In_ ULONG OutBufferChars
    )
{
    ULONG count = 0;
    ULONG i;

    if (OutBuffer == NULL || OutBufferChars == 0) {
        return 0;
    }

    EnterCriticalSection(&g_WkdMpm.WhitelistLock);

    for (i = 0; i < g_WkdMpm.WhitelistCount; i++) {
        PCWSTR entry = &g_WkdMpm.Whitelist[i * WKD_MPM_SERIAL_MAX];
        SIZE_T len = wcslen(entry) + 1;

        if (count + len > OutBufferChars) {
            break;
        }
        wcscpy_s(&OutBuffer[count], OutBufferChars - count, entry);
        count += (ULONG)len;
    }

    LeaveCriticalSection(&g_WkdMpm.WhitelistLock);

    /* 返回条目数 (遍历统计) */
    {
        ULONG entries = 0;
        ULONG pos = 0;
        while (pos < count) {
            pos += (ULONG)wcslen(&OutBuffer[pos]) + 1;
            entries++;
        }
        return entries;
    }
}

/*
 * WkdMpmIsWhitelistedLocked
 *   锁内白名单查询 (调用方必须持有 WhitelistLock)。
 */
static BOOLEAN
WkdMpmIsWhitelistedLocked(
    _In_ PCWSTR SerialNumber
    )
{
    ULONG i;

    if (SerialNumber == NULL || SerialNumber[0] == L'\0') {
        return FALSE;
    }

    for (i = 0; i < g_WkdMpm.WhitelistCount; i++) {
        if (_wcsicmp(&g_WkdMpm.Whitelist[i * WKD_MPM_SERIAL_MAX],
                     SerialNumber) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

/*
 * WkdMpmWhitelistGrow
 *   白名单动态数组扩容 (初始 16, 倍增)。
 */
static BOOLEAN
WkdMpmWhitelistGrow(
    VOID
    )
{
    ULONG newCap = g_WkdMpm.WhitelistCapacity ?
                   g_WkdMpm.WhitelistCapacity * 2 : 16;
    SIZE_T bytes = (SIZE_T)newCap * WKD_MPM_SERIAL_MAX * sizeof(WCHAR);
    PWCHAR nb;

    if (g_WkdMpm.Whitelist == NULL) {
        nb = (PWCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
    } else {
        nb = (PWCHAR)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                 g_WkdMpm.Whitelist, bytes);
    }

    if (nb == NULL) {
        return FALSE;
    }

    g_WkdMpm.Whitelist = nb;
    g_WkdMpm.WhitelistCapacity = newCap;
    return TRUE;
}

/**************************************************/
/*                    处置                         */
/**************************************************/

/*
 * WkdMpm_BlockDrive
 *   阻断盘符: FSCTL_LOCK_VOLUME + FSCTL_DISMOUNT_VOLUME。
 *   ※死代码: monitor-only 门控下无调用者, 保 SS 用户态功能面;
 *   执行层归驱动 USBDeviceControl。
 */
NTSTATUS
WkdMpm_BlockDrive(
    _In_ WCHAR DriveLetter
    )
{
    WCHAR devicePath[8];
    HANDLE hVolume;
    DWORD bytesReturned = 0;

    DriveLetter = WkdMpmNormalizeDriveLetter(DriveLetter);
    if (!WkdMpmIsValidDriveLetter(DriveLetter)) {
        return STATUS_INVALID_PARAMETER;
    }

    devicePath[0] = L'\\';
    devicePath[1] = L'\\';
    devicePath[2] = L'.';
    devicePath[3] = L'\\';
    devicePath[4] = DriveLetter;
    devicePath[5] = L':';
    devicePath[6] = L'\0';

    hVolume = CreateFileW(devicePath, GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL, OPEN_EXISTING, 0, NULL);
    if (hVolume == INVALID_HANDLE_VALUE) {
        printf("[MountPointMonitor] Failed to open volume for block - %c\n",
               DriveLetter);
        return STATUS_ACCESS_DENIED;
    }

    /* 锁定卷阻止进一步 I/O */
    if (!DeviceIoControl(hVolume, FSCTL_LOCK_VOLUME,
            NULL, 0, NULL, 0, &bytesReturned, NULL)) {
        CloseHandle(hVolume);
        printf("[MountPointMonitor] FSCTL_LOCK_VOLUME failed for drive %c\n",
               DriveLetter);
        return STATUS_UNSUCCESSFUL;
    }

    /* 卸载卷 (失败为部分成功 — 卷已锁定) */
    DeviceIoControl(hVolume, FSCTL_DISMOUNT_VOLUME,
                    NULL, 0, NULL, 0, &bytesReturned, NULL);
    CloseHandle(hVolume);

    InterlockedIncrement64(&g_WkdMpm.Stats.DevicesBlocked);
    printf("[MountPointMonitor] Drive %c blocked (locked and dismounted)\n",
           DriveLetter);

    return STATUS_SUCCESS;
}

/*
 * WkdMpm_SetReadOnly
 *   设置盘只读: IOCTL_DISK_SET_DISK_ATTRIBUTES。
 *   ※死代码: 同 BlockDrive, 保 SS 功能面。
 */
NTSTATUS
WkdMpm_SetReadOnly(
    _In_ WCHAR DriveLetter,
    _In_ BOOLEAN ReadOnly
    )
{
    WCHAR devicePath[8];
    HANDLE hVolume;
    DWORD bytesReturned = 0;
    SET_DISK_ATTRIBUTES attrs;
    ULONG idx;

    DriveLetter = WkdMpmNormalizeDriveLetter(DriveLetter);
    if (!WkdMpmIsValidDriveLetter(DriveLetter)) {
        return STATUS_INVALID_PARAMETER;
    }

    devicePath[0] = L'\\';
    devicePath[1] = L'\\';
    devicePath[2] = L'.';
    devicePath[3] = L'\\';
    devicePath[4] = DriveLetter;
    devicePath[5] = L':';
    devicePath[6] = L'\0';

    hVolume = CreateFileW(devicePath, GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL, OPEN_EXISTING, 0, NULL);
    if (hVolume == INVALID_HANDLE_VALUE) {
        printf("[MountPointMonitor] Failed to open volume for SetReadOnly - %c\n",
               DriveLetter);
        return STATUS_ACCESS_DENIED;
    }

    RtlZeroMemory(&attrs, sizeof(attrs));
    attrs.Version = sizeof(SET_DISK_ATTRIBUTES);
    attrs.AttributesMask = DISK_ATTRIBUTE_READ_ONLY;
    attrs.Attributes = ReadOnly ? DISK_ATTRIBUTE_READ_ONLY : 0;

    if (!DeviceIoControl(hVolume, IOCTL_DISK_SET_DISK_ATTRIBUTES,
            &attrs, sizeof(attrs), NULL, 0, &bytesReturned, NULL)) {
        CloseHandle(hVolume);
        printf("[MountPointMonitor] IOCTL_DISK_SET_DISK_ATTRIBUTES failed "
               "for drive %c\n", DriveLetter);
        return STATUS_UNSUCCESSFUL;
    }
    CloseHandle(hVolume);

    /* 更新缓存盘表 */
    idx = (ULONG)(DriveLetter - L'A');
    EnterCriticalSection(&g_WkdMpm.DrivesLock);
    if (g_WkdMpm.DrivePresent[idx]) {
        g_WkdMpm.MountedDrives[idx].IsReadOnly = ReadOnly;
    }
    LeaveCriticalSection(&g_WkdMpm.DrivesLock);

    printf("[MountPointMonitor] Drive %c set to %ls\n",
           DriveLetter, ReadOnly ? L"read-only" : L"read-write");

    return STATUS_SUCCESS;
}

/*
 * WkdMpm_EjectDrive
 *   安全弹出盘: IOCTL_STORAGE_EJECT_MEDIA。
 *   ※死代码: 同 BlockDrive, 保 SS 功能面 (UI 主动弹出盘预留)。
 */
NTSTATUS
WkdMpm_EjectDrive(
    _In_ WCHAR DriveLetter
    )
{
    WCHAR devicePath[8];
    HANDLE hDevice;
    DWORD bytesReturned = 0;

    DriveLetter = WkdMpmNormalizeDriveLetter(DriveLetter);
    if (!WkdMpmIsValidDriveLetter(DriveLetter)) {
        return STATUS_INVALID_PARAMETER;
    }

    devicePath[0] = L'\\';
    devicePath[1] = L'\\';
    devicePath[2] = L'.';
    devicePath[3] = L'\\';
    devicePath[4] = DriveLetter;
    devicePath[5] = L':';
    devicePath[6] = L'\0';

    hDevice = CreateFileW(devicePath, GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[MountPointMonitor] Failed to open device for eject - %c\n",
               DriveLetter);
        return STATUS_ACCESS_DENIED;
    }

    if (!DeviceIoControl(hDevice, IOCTL_STORAGE_EJECT_MEDIA,
            NULL, 0, NULL, 0, &bytesReturned, NULL)) {
        CloseHandle(hDevice);
        printf("[MountPointMonitor] Failed to eject drive %c\n", DriveLetter);
        return STATUS_UNSUCCESSFUL;
    }
    CloseHandle(hDevice);

    printf("[MountPointMonitor] Drive %c ejected successfully\n", DriveLetter);
    return STATUS_SUCCESS;
}

/**************************************************/
/*                    回调                         */
/**************************************************/

/*
 * WkdMpm_SetMountEventCallback
 *   注册挂载事件回调 (对齐 SS SetMountEventCallback)。
 */
VOID
WkdMpm_SetMountEventCallback(
    _In_opt_ WKD_MPM_MOUNT_EVENT_CB Callback
    )
{
    EnterCriticalSection(&g_WkdMpm.CallbacksLock);
    g_WkdMpm.EventCallback = Callback;
    LeaveCriticalSection(&g_WkdMpm.CallbacksLock);
}

/*
 * WkdMpm_SetPolicyCallback
 *   注册策略回调 (对齐 SS SetPolicyCallback)。
 */
VOID
WkdMpm_SetPolicyCallback(
    _In_opt_ WKD_MPM_POLICY_CB Callback
    )
{
    EnterCriticalSection(&g_WkdMpm.CallbacksLock);
    g_WkdMpm.PolicyCallback = Callback;
    LeaveCriticalSection(&g_WkdMpm.CallbacksLock);
}

/*
 * WkdMpm_UnregisterCallbacks
 *   注销全部回调 (对齐 SS UnregisterCallbacks)。
 */
VOID
WkdMpm_UnregisterCallbacks(
    VOID
    )
{
    EnterCriticalSection(&g_WkdMpm.CallbacksLock);
    g_WkdMpm.EventCallback = NULL;
    g_WkdMpm.PolicyCallback = NULL;
    LeaveCriticalSection(&g_WkdMpm.CallbacksLock);
}

/**************************************************/
/*                配置与统计                       */
/**************************************************/

/*
 * WkdMpm_GetConfiguration
 *   获取当前配置 (对齐 SS GetConfiguration)。
 */
VOID
WkdMpm_GetConfiguration(
    _Out_ PWKD_MPM_CONFIG Config
    )
{
    if (Config == NULL) {
        return;
    }

    *Config = g_WkdMpm.Config;
}

/*
 * WkdMpm_SetConfiguration
 *   更新配置 (对齐 SS SetConfiguration)。策略枚举校验防非法值静默禁用。
 */
NTSTATUS
WkdMpm_SetConfiguration(
    _In_ const WKD_MPM_CONFIG* Config
    )
{
    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((ULONG)Config->DefaultRemovablePolicy > WkdMpmPolicy_RequireApproval ||
        (ULONG)Config->DefaultNetworkPolicy > WkdMpmPolicy_RequireApproval) {
        return STATUS_INVALID_PARAMETER;
    }

    g_WkdMpm.Config = *Config;

    printf("[MountPointMonitor] Configuration updated\n");
    return STATUS_SUCCESS;
}

/*
 * WkdMpm_GetStatistics
 *   统计快照 (对齐 SS GetStatistics)。
 */
VOID
WkdMpm_GetStatistics(
    _Out_ PWKD_MPM_STATS Stats
    )
{
    if (Stats == NULL) {
        return;
    }

    if (!g_WkdMpm.Initialized) {
        RtlZeroMemory(Stats, sizeof(*Stats));
        return;
    }

    /* 显式 cast 消除 volatile 结构 → void* 的限定丢失告警 */
    RtlCopyMemory(Stats, (const void*)&g_WkdMpm.Stats, sizeof(WKD_MPM_STATS));
}

/*
 * WkdMpm_ResetStatistics
 *   统计清零 (对齐 SS ResetStatistics)。
 */
VOID
WkdMpm_ResetStatistics(
    VOID
    )
{
    RtlZeroMemory(&g_WkdMpm.Stats, sizeof(g_WkdMpm.Stats));
    GetSystemTimeAsFileTime((PFILETIME)&g_WkdMpm.Stats.StartTime);
    printf("[MountPointMonitor] Statistics reset\n");
}

/*
 * WkdMpm_GetAverageProcessingTimeMs
 *   平均事件处理耗时 (us → ms, 对齐 SS GetAverageProcessingTimeMs)。
 */
DOUBLE
WkdMpm_GetAverageProcessingTimeMs(
    VOID
    )
{
    LONG64 total;
    LONG64 totalUs;

    total = InterlockedCompareExchange64(&g_WkdMpm.Stats.TotalEvents, 0, 0);

    if (total == 0) {
        return 0.0;
    }

    totalUs = InterlockedCompareExchange64(
        &g_WkdMpm.Stats.TotalProcessingTimeUs, 0, 0);

    return ((DOUBLE)totalUs / (DOUBLE)total) / 1000.0;
}

/**************************************************/
/*                  诊断                           */
/**************************************************/

/*
 * WkdMpm_SelfTest
 *   自检 (对齐 SS SelfTest): 驱动器枚举 + C: 信息 + 白名单加减。
 */
BOOLEAN
WkdMpm_SelfTest(
    VOID
    )
{
    DWORD drives;
    WKD_MPM_DRIVE_INFO info;

    printf("[MountPointMonitor] Starting self-test\n");

    drives = GetLogicalDrives();
    if (drives == 0) {
        printf("[MountPointMonitor] Self-test failed - no drives detected\n");
        return FALSE;
    }

    if (!WkdMpm_GetDriveInfo(L'C', &info)) {
        printf("[MountPointMonitor] Self-test failed - cannot get C: drive info\n");
        return FALSE;
    }

    WkdMpm_WhitelistDevice(L"TEST_SERIAL_12345");
    if (!WkdMpm_IsWhitelisted(L"TEST_SERIAL_12345")) {
        printf("[MountPointMonitor] Self-test failed - whitelist op failed\n");
        return FALSE;
    }
    WkdMpm_RemoveFromWhitelist(L"TEST_SERIAL_12345");

    printf("[MountPointMonitor] Self-test passed\n");
    return TRUE;
}

/*
 * WkdMpm_GetVersionString
 *   版本串 "3.0.0" (对齐 SS GetVersionString)。
 */
VOID
WkdMpm_GetVersionString(
    _Out_writes_(Cch) PWCHAR Out,
    _In_ ULONG Cch
    )
{
    if (Out == NULL || Cch == 0) {
        return;
    }

    _snwprintf_s(Out, Cch, _TRUNCATE, L"%u.%u.%u",
                 WKD_MPM_VERSION_MAJOR, WKD_MPM_VERSION_MINOR,
                 WKD_MPM_VERSION_PATCH);
}

/**************************************************/
/*              工具 Get*Name                      */
/**************************************************/

/*
 * Get*Name 系列 ※死代码: 调试/诊断工具, 无消费方, 保 SS 功能面。
 */

PCWSTR
WkdMpm_GetDriveTypeName(
    _In_ WKD_MPM_DRIVE Type
    )
{
    switch (Type) {
        case WkdMpmDrive_Unknown:         return L"Unknown";
        case WkdMpmDrive_Fixed:           return L"Fixed";
        case WkdMpmDrive_Removable:       return L"Removable";
        case WkdMpmDrive_Network:         return L"Network";
        case WkdMpmDrive_CDRom:           return L"CDRom";
        case WkdMpmDrive_RAMDisk:         return L"RAMDisk";
        case WkdMpmDrive_VirtualHardDisk: return L"VirtualHardDisk";
        case WkdMpmDrive_ISOImage:        return L"ISOImage";
        default:                          return L"Unknown";
    }
}

PCWSTR
WkdMpm_GetMountEventName(
    _In_ WKD_MPM_EVENT Event
    )
{
    switch (Event) {
        case WkdMpmEvent_DriveArrival:        return L"DriveArrival";
        case WkdMpmEvent_DriveRemoval:        return L"DriveRemoval";
        case WkdMpmEvent_MediaInserted:       return L"MediaInserted";
        case WkdMpmEvent_MediaRemoved:        return L"MediaRemoved";
        case WkdMpmEvent_NetworkConnected:    return L"NetworkConnected";
        case WkdMpmEvent_NetworkDisconnected: return L"NetworkDisconnected";
        case WkdMpmEvent_VirtualMounted:      return L"VirtualMounted";
        case WkdMpmEvent_VirtualUnmounted:    return L"VirtualUnmounted";
        default:                              return L"Unknown";
    }
}

PCWSTR
WkdMpm_GetDeviceThreatTypeName(
    _In_ WKD_MPM_THREAT Threat
    )
{
    switch (Threat) {
        case WkdMpmThreat_None:           return L"None";
        case WkdMpmThreat_BadUSB:         return L"BadUSB";
        case WkdMpmThreat_RubberDucky:    return L"RubberDucky";
        case WkdMpmThreat_USBKill:        return L"USBKill";
        case WkdMpmThreat_Masquerading:   return L"Masquerading";
        case WkdMpmThreat_Unauthorized:   return L"Unauthorized";
        case WkdMpmThreat_PolicyViolation:return L"PolicyViolation";
        default:                          return L"Unknown";
    }
}

PCWSTR
WkdMpm_GetDevicePolicyName(
    _In_ WKD_MPM_POLICY Policy
    )
{
    switch (Policy) {
        case WkdMpmPolicy_Allow:           return L"Allow";
        case WkdMpmPolicy_AllowReadOnly:   return L"AllowReadOnly";
        case WkdMpmPolicy_Block:           return L"Block";
        case WkdMpmPolicy_BlockAndAlert:   return L"BlockAndAlert";
        case WkdMpmPolicy_RequireApproval: return L"RequireApproval";
        default:                           return L"Unknown";
    }
}

PCWSTR
WkdMpm_GetMonitorStatusName(
    _In_ WKD_MPM_STATUS Status
    )
{
    switch (Status) {
        case WkdMpmStatus_Uninitialized: return L"Uninitialized";
        case WkdMpmStatus_Initializing:  return L"Initializing";
        case WkdMpmStatus_Running:       return L"Running";
        case WkdMpmStatus_Paused:        return L"Paused";
        case WkdMpmStatus_Error:         return L"Error";
        case WkdMpmStatus_Stopping:      return L"Stopping";
        case WkdMpmStatus_Stopped:       return L"Stopped";
        case WkdMpmStatus_Initialized:   return L"Initialized";
        default:                         return L"Unknown";
    }
}

/**************************************************/
/*                  死代码区                       */
/**************************************************/

/*
 * 以下为死代码: 保 SS 功能面, 无消费方/未接线, 标注不接入原因。
 */

/*
 * WkdMpmEnumerateVolumes
 *   FindFirstVolumeW/FindNextVolumeW 卷名枚举。
 *   ※死代码: SS 定义未使用 (Initial 枚举走 GetLogicalDrives),
 *   保 SS 功能面。
 */
static ULONG
WkdMpmEnumerateVolumes(
    _Out_writes_(Capacity * DEF_MAX_PATH) PWCHAR Volumes,
    _In_ ULONG Capacity
    )
{
    ULONG count = 0;
    WCHAR volumeName[DEF_MAX_PATH];
    HANDLE hFind;

    hFind = FindFirstVolumeW(volumeName, DEF_MAX_PATH);
    if (hFind == INVALID_HANDLE_VALUE) {
        return 0;
    }

    do {
        if (count < Capacity) {
            wcscpy_s(&Volumes[count * DEF_MAX_PATH], DEF_MAX_PATH, volumeName);
            count++;
        } else {
            break;
        }
    } while (FindNextVolumeW(hFind, volumeName, DEF_MAX_PATH));

    FindVolumeClose(hFind);
    return count;
}

/*
 * WkdMpmStatsToJson
 *   统计 JSON 序列化。※死代码: 调试工具, 无消费方, 对齐 SS
 *   MountPointMonitorStatistics::ToJson。
 */
static VOID
WkdMpmStatsToJson(
    _In_ const WKD_MPM_STATS* Stats,
    _Out_writes_(Cch) PWCHAR Out,
    _In_ ULONG Cch
    )
{
    if (Stats == NULL || Out == NULL || Cch == 0) {
        return;
    }

    _snwprintf_s(Out, Cch, _TRUNCATE,
        L"{\"totalEvents\":%lld,\"devicesBlocked\":%lld,"
        L"\"threatsDetected\":%lld,\"activeMounts\":%ld,"
        L"\"usbConnections\":%lld,\"networkMounts\":%lld,"
        L"\"virtualMounts\":%lld,\"autorunBlocked\":%lld,"
        L"\"errors\":%lld,\"avgProcessingTimeMs\":%f}",
        Stats->TotalEvents, Stats->DevicesBlocked,
        Stats->ThreatsDetected, Stats->ActiveMounts,
        Stats->UsbConnections, Stats->NetworkMounts,
        Stats->VirtualMounts, Stats->AutorunBlocked,
        Stats->Errors,
        WkdMpm_GetAverageProcessingTimeMs());
}

#pragma warning(pop)
