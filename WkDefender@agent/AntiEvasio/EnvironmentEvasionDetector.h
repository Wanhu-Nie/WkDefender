/**************************************************/
/*  WkDefender Agent — 环境逃逸检测引擎              */
/*  AntiEvasio                                      */
/*                                                  */
/*  迁移自 ShadowStrike EnvironmentEvasionDetector   */
/*  (.cpp 6286行 + .hpp 3193行)。                    */
/*  功能：检测目标进程的环境探测行为（VM/沙箱逃逸）    */
/*   以及系统环境特征采集（TYPE A + TYPE B 分析）。    */
/*                                                  */
/*  TYPE A = 分析系统环境本身（是否为 VM/沙箱）       */
/*  TYPE B = 分析目标进程行为（是否在探测环境）       */
/*                                                  */
/*  asm 文件不迁移：x64 无 __asm；CPUID/RDTSC 等     */
/*   用 <intrin.h> 等价替代。                        */
/*                                                  */
/*  编码：UTF-8 with BOM（铁律）                     */
/**************************************************/

#pragma once

#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <stdint.h>
#include <iphlpapi.h>

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************/
/*               常量定义                          */
/**************************************************/

/* 最大检测数（每次分析的检测条目上限） */
#define EED_MAX_DETECTIONS                  256

/* 描述/详情字符串缓冲区长度 */
#define EED_MAX_DESCRIPTION                 128
#define EED_MAX_DETAILS                     256
#define EED_MAX_VALUE                       256
#define EED_MAX_EXPECTED_VALUE              128
#define EED_MAX_SOURCE                      64
#define EED_MAX_MITRE_ID                    16

/* 进程名/路径缓冲区 */
#define EED_MAX_PROCESS_NAME                64
#define EED_MAX_PROCESS_PATH                260

/* 硬件信息缓冲区 */
#define EED_MAX_MANUFACTURER                128
#define EED_MAX_PRODUCT_NAME                128
#define EED_MAX_BIOS_VERSION                128
#define EED_MAX_CPU_BRAND                   128
#define EED_MAX_CPU_VENDOR                  16

/* 网络信息缓冲区 */
#define EED_MAX_ADAPTER_NAME                256
#define EED_MAX_ADAPTER_DESCRIPTION         256
#define EED_MAX_MAC_STRING                  32
#define EED_MAX_IP_STRING                   46
#define EED_MAX_DNS_STRING                  64
#define EED_MAX_NETWORK_ADAPTERS            16

/* 用户名/计算机名缓冲区 */
#define EED_MAX_USERNAME                    256
#define EED_MAX_COMPUTER_NAME               256
#define EED_MAX_DOMAIN_NAME                 256

/* 环境变量缓冲区 */
#define EED_MAX_ENV_VAR_NAME                256
#define EED_MAX_ENV_VAR_VALUE               1024
#define EED_MAX_ENV_VARS                    128

/* 注册表路径缓冲区 */
#define EED_MAX_REG_PATH                    512
#define EED_MAX_REG_VALUE                   512

/* 文件路径缓冲区 */
#define EED_MAX_FILE_PATH                   260
#define EED_MAX_FILE_NAME                   256

/* 枚举上限 */
#define EED_MAX_PROCESSES_TO_ENUMERATE      4096
#define EED_MAX_FILES_PER_DIRECTORY         10000
#define EED_MAX_REGISTRY_KEYS               5000
#define EED_MAX_DISPLAY_DEVICES             16

/* 黑名单表大小 */
#define EED_MAX_BLACKLISTED_USERNAMES       45
#define EED_MAX_BLACKLISTED_COMPUTER_NAMES  40
#define EED_MAX_SANDBOX_MAC_PREFIXES        16
#define EED_MAX_ANALYSIS_TOOL_PROCESSES     64
#define EED_MAX_SANDBOX_REGISTRY_KEYS       32
#define EED_MAX_SANDBOX_ENV_VARIABLES       24
#define EED_MAX_ANALYSIS_VAR_KEYWORDS       7
#define EED_MAX_VM_PATH_PATTERNS            6
#define EED_MAX_VM_ADAPTER_PATTERNS         9
#define EED_MAX_VM_BIOS_STRINGS             6
#define EED_MAX_VM_DISK_PATTERNS            5
#define EED_MAX_VM_SCSI_PATTERNS            4
#define EED_MAX_VM_DISPLAY_PATTERNS         10
#define EED_MAX_VM_TOOL_DIRS                40
#define EED_MAX_SANDBOX_PATHS               8
#define EED_MAX_SUSPICIOUS_DLLS             8
#define EED_MAX_PRODUCTIVITY_APPS           10
#define EED_MAX_SUSPICIOUS_IMPORTS          22
#define EED_MAX_SUSPICIOUS_SECTIONS         6
#define EED_MAX_CRITICAL_APIS               17
#define EED_MAX_PROBING_PATTERNS            40

/* 评分阈值 */
#define EED_HIGH_EVASION_THRESHOLD          70.0
#define EED_CRITICAL_EVASION_THRESHOLD      90.0

/* 评分权重（按类别，Constants 权重） */
#define EED_WEIGHT_NAME_CHECKS              2.5
#define EED_WEIGHT_HARDWARE_CHECKS          2.0
#define EED_WEIGHT_FILESYSTEM_CHECKS        1.5
#define EED_WEIGHT_REGISTRY_CHECKS          1.5
#define EED_WEIGHT_USER_ACTIVITY_CHECKS     2.0
#define EED_WEIGHT_NETWORK_CHECKS           1.8
#define EED_WEIGHT_PROCESS_CHECKS           1.5
#define EED_WEIGHT_TIMING_CHECKS            2.2
#define EED_WEIGHT_ENVIRONMENT_CHECKS       1.5
#define EED_WEIGHT_DISPLAY_CHECKS           1.2
#define EED_WEIGHT_BROWSER_CHECKS           1.3
#define EED_WEIGHT_PERIPHERAL_CHECKS        1.0
#define EED_WEIGHT_FILE_NAMING_CHECKS       1.5
#define EED_WEIGHT_ADVANCED_CHECKS          3.0
#define EED_WEIGHT_COMBINED                 3.0

/* 硬件阈值（保守策略——避免云 VM 误报） */
#define EED_MIN_NORMAL_PROCESSOR_COUNT      1
#define EED_MIN_NORMAL_RAM_BYTES            (512ULL * 1024 * 1024)
#define EED_MIN_NORMAL_DISK_BYTES           (8ULL * 1024 * 1024 * 1024)
#define EED_MAX_FRESH_BOOT_UPTIME_MS        (30ULL * 60 * 1000)

/* 进程/文件枚举上限 */
#define EED_MAX_RECENT_DOCUMENTS            5
#define EED_MAX_INSTALLED_PROGRAMS          30
#define EED_MAX_SCHEDULED_TASKS             50
#define EED_MAX_EVENT_LOG_RECORDS           200
#define EED_MAX_SYSTEM_EVENT_LOG_RECORDS    1000

/* 默认扫描超时（毫秒） */
#define EED_DEFAULT_TIMEOUT_MS              30000

/* 缓存条目上限 */
#define EED_MAX_CACHE_ENTRIES               64

/**************************************************/
/*          检测技术枚举（EnvironmentEvasionTechnique） */
/**************************************************/

typedef enum _EED_TECHNIQUE {
    /* --- 无/未知 --- */
    EeTechniqueNone                              = 0,

    /* --- 名称检查类 (1-6) --- */
    EeTechniqueName_BlacklistedUsername           = 1,
    EeTechniqueName_BlacklistedComputerName       = 2,
    EeTechniqueName_BlacklistedDomain             = 3,
    EeTechniqueName_DefaultUsername               = 4,
    EeTechniqueName_VMNamingPattern               = 5,
    EeTechniqueName_SuspiciousLength              = 6,

    /* --- 硬件指纹类 (21-34) --- */
    EeTechniqueHW_LowProcessorCount              = 21,
    EeTechniqueHW_LowRAM                         = 22,
    EeTechniqueHW_SmallDisk                      = 23,
    EeTechniqueHW_SingleDisk                     = 24,
    EeTechniqueHW_VMDiskVendor                   = 25,
    EeTechniqueHW_VMBIOSVendor                   = 26,
    EeTechniqueHW_VMManufacturer                 = 27,
    EeTechniqueHW_VMProductName                  = 28,
    EeTechniqueHW_VMCPUBrand                     = 29,
    EeTechniqueHW_HypervisorBit                  = 30,
    EeTechniqueHW_VMMotherboard                  = 31,
    EeTechniqueHW_VMDisplayAdapter               = 32,
    EeTechniqueHW_SMBIOSVMIndicators             = 33,
    EeTechniqueHW_ACPIVMIndicators               = 34,

    /* --- 文件系统工件类 (51-63) --- */
    EeTechniqueFS_VMToolsDirectory               = 51,
    EeTechniqueFS_VMDrivers                      = 52,
    EeTechniqueFS_SandboxAgentFiles              = 53,
    EeTechniqueFS_AnalysisToolsInstalled         = 54,
    EeTechniqueFS_EmptyDocuments                 = 55,
    EeTechniqueFS_EmptyDownloads                 = 56,
    EeTechniqueFS_EmptyDesktop                   = 57,
    EeTechniqueFS_NoRecentFiles                  = 58,
    EeTechniqueFS_MissingUserArtifacts           = 59,
    EeTechniqueFS_SuspiciousTempDir              = 60,
    EeTechniqueFS_AnalysisFiles                  = 61,
    EeTechniqueFS_VMSharedFolders                = 62,
    EeTechniqueFS_CleanSystemDirs                = 63,

    /* --- 注册表工件类 (81-93) --- */
    EeTechniqueReg_VMwareKeys                    = 81,
    EeTechniqueReg_VirtualBoxKeys                = 82,
    EeTechniqueReg_HyperVKeys                    = 83,
    EeTechniqueReg_ParallelsKeys                 = 84,
    EeTechniqueReg_QEMUKeys                      = 85,
    EeTechniqueReg_SandboxieKeys                 = 86,
    EeTechniqueReg_WineKeys                      = 87,
    EeTechniqueReg_EmptyMRULists                 = 88,
    EeTechniqueReg_NoTypedURLs                   = 89,
    EeTechniqueReg_NoRecentPrograms              = 90,
    EeTechniqueReg_SuspiciousInstallDate         = 91,
    EeTechniqueReg_MissingSoftwareKeys           = 92,
    EeTechniqueReg_VMServices                    = 93,

    /* --- 用户活动类 (111-123) --- */
    EeTechniqueAct_NoMouseMovement               = 111,
    EeTechniqueAct_NoKeyboardActivity            = 112,
    EeTechniqueAct_NoWindowFocus                 = 113,
    EeTechniqueAct_NoClipboardHistory            = 114,
    EeTechniqueAct_NoScreenshots                 = 115,
    EeTechniqueAct_EmptyRecycleBin               = 116,
    EeTechniqueAct_NoPrinterHistory              = 117,
    EeTechniqueAct_NoNetworkDrives               = 118,
    EeTechniqueAct_NoRecentSearches              = 119,
    EeTechniqueAct_EmptyJumpLists                = 120,
    EeTechniqueAct_NoNotifications               = 121,
    EeTechniqueAct_UserIdleDetection             = 122,
    EeTechniqueAct_SimulationCheck               = 123,

    /* --- 网络配置类 (141-150) --- */
    EeTechniqueNet_VMMACPrefix                   = 141,
    EeTechniqueNet_OnlyLoopback                  = 142,
    EeTechniqueNet_VMAdapterName                 = 143,
    EeTechniqueNet_NoWiFiHistory                 = 144,
    EeTechniqueNet_SuspiciousDNS                 = 145,
    EeTechniqueNet_NoNetworkShares               = 146,
    EeTechniqueNet_SandboxGateway                = 147,
    EeTechniqueNet_NATOnlyNetwork                = 148,
    EeTechniqueNet_NoMountedDrives               = 149,
    EeTechniqueNet_SuspiciousIPRange             = 150,

    /* --- 进程枚举类 (171-179) --- */
    EeTechniqueProc_AnalysisToolRunning          = 171,
    EeTechniqueProc_DebuggerRunning              = 172,
    EeTechniqueProc_VMToolsRunning               = 173,
    EeTechniqueProc_SandboxAgentRunning          = 174,
    EeTechniqueProc_SuspiciousService            = 175,
    EeTechniqueProc_LowProcessCount              = 176,
    EeTechniqueProc_MissingSystemProcesses       = 177,
    EeTechniqueProc_AnalysisWindowTitles         = 178,
    EeTechniqueProc_HookingDLLs                  = 179,

    /* --- 时序检查类 (201-208) --- */
    EeTechniqueTime_ShortUptime                  = 201,
    EeTechniqueTime_RecentInstall                = 202,
    EeTechniqueTime_NoScheduledTasks             = 203,
    EeTechniqueTime_EventLogCleared              = 204,
    EeTechniqueTime_AcceleratedTime              = 205,
    EeTechniqueTime_SleepSkipping                = 206,
    EeTechniqueTime_BootTimeAnomaly              = 207,
    EeTechniqueTime_TimestampClustering          = 208,

    /* --- 环境变量类 (221-226) --- */
    EeTechniqueEnv_SandboxVariable               = 221,
    EeTechniqueEnv_VMVariable                    = 222,
    EeTechniqueEnv_AnalysisVariable              = 223,
    EeTechniqueEnv_MissingVariables              = 224,
    EeTechniqueEnv_SuspiciousPath                = 225,
    EeTechniqueEnv_UnusualTempPath               = 226,

    /* --- 显示配置类 (241-246) --- */
    EeTechniqueDisp_LowResolution                = 241,
    EeTechniqueDisp_SingleMonitor                = 242,
    EeTechniqueDisp_VMDriver                     = 243,
    EeTechniqueDisp_MissingGPU                   = 244,
    EeTechniqueDisp_UnusualColorDepth             = 245,
    EeTechniqueDisp_VMGraphicsAdapter            = 246,

    /* --- 区域/语言类 (261-265) --- */
    EeTechniqueLocale_DefaultLocale              = 261,
    EeTechniqueLocale_MismatchedTimezone         = 262,
    EeTechniqueLocale_SingleKeyboard             = 263,
    EeTechniqueLocale_DefaultLanguage            = 264,
    EeTechniqueLocale_SuspiciousRegion           = 265,

    /* --- 浏览器工件类 (281-288) --- */
    EeTechniqueBrowser_NoHistory                 = 281,
    EeTechniqueBrowser_NoBookmarks               = 282,
    EeTechniqueBrowser_NoCookies                 = 283,
    EeTechniqueBrowser_NoPasswords               = 284,
    EeTechniqueBrowser_NoExtensions              = 285,
    EeTechniqueBrowser_NoDownloads               = 286,
    EeTechniqueBrowser_NoAutofill                = 287,
    EeTechniqueBrowser_OnlyDefault               = 288,

    /* --- 外设历史类 (301-306) --- */
    EeTechniquePeriph_NoUSBHistory               = 301,
    EeTechniquePeriph_NoBluetoothPairings        = 302,
    EeTechniquePeriph_NoPrinters                 = 303,
    EeTechniquePeriph_NoAudioDevices             = 304,
    EeTechniquePeriph_NoWebcam                   = 305,
    EeTechniquePeriph_MissingDevices             = 306,

    /* --- 文件命名模式类 (321-328) --- */
    EeTechniqueFile_MD5Hash                      = 321,
    EeTechniqueFile_SHA1Hash                     = 322,
    EeTechniqueFile_SHA256Hash                   = 323,
    EeTechniqueFile_GenericName                  = 324,
    EeTechniqueFile_SuspiciousLocation           = 325,
    EeTechniqueFile_AnalysisKeywords             = 326,
    EeTechniqueFile_MultipleExtensions           = 327,
    EeTechniqueFile_RandomPattern                = 328,

    /* --- 高级/组合类 (341-347) --- */
    EeTechniqueAdv_MultiCategoryEvasion          = 341,
    EeTechniqueAdv_SophisticatedFingerprinting   = 342,
    EeTechniqueAdv_PolymorphicCheck              = 343,
    EeTechniqueAdv_EncryptedCheck                = 344,
    EeTechniqueAdv_DelayedCheck                  = 345,
    EeTechniqueAdv_AntiForensics                 = 346,
    EeTechniqueAdv_APIHookDetection              = 347,

    EeTechniqueMax                               = 400
} EED_TECHNIQUE;

/**************************************************/
/*          检测类别枚举（EnvironmentEvasionCategory） */
/**************************************************/

typedef enum _EED_CATEGORY {
    EeCategoryNameChecks                = 0,
    EeCategoryHardwareFingerprinting    = 1,
    EeCategoryFileSystemArtifacts       = 2,
    EeCategoryRegistryArtifacts         = 3,
    EeCategoryUserActivityIndicators    = 4,
    EeCategoryNetworkConfiguration      = 5,
    EeCategoryProcessEnumeration        = 6,
    EeCategoryTimingChecks              = 7,
    EeCategoryEnvironmentVariables      = 8,
    EeCategoryDisplayConfiguration      = 9,
    EeCategoryLocaleSettings            = 10,
    EeCategoryBrowserArtifacts          = 11,
    EeCategoryPeripheralHistory         = 12,
    EeCategoryFileNamingPatterns        = 13,
    EeCategoryCombined                  = 14,
    EeCategoryUnknown                   = 255
} EED_CATEGORY;

/**************************************************/
/*          严重度枚举（EvasionSeverity）   */
/**************************************************/

typedef enum _EED_SEVERITY {
    EeSeverityLow      = 0,
    EeSeverityMedium   = 1,
    EeSeverityHigh     = 2,
    EeSeverityCritical = 3
} EED_SEVERITY;

/**************************************************/
/*          分析深度                                */
/**************************************************/

typedef enum _EED_DEPTH {
    EeDepthQuick         = 0,  /* 仅名称 + 基础硬件 */
    EeDepthStandard      = 1,  /* + 文件系统 + 注册表 + 进程 + 环境变量 */
    EeDepthDeep          = 2,  /* + 用户活动 + 网络 + 显示 + 浏览器 */
    EeDepthComprehensive = 3   /* 全部（含外设 + 高级 + PE 分析） */
} EED_DEPTH;

/**************************************************/
/*          分析标志位图（位域门控各检测子项）        */
/**************************************************/

#define EED_FLAG_NONE                       0x00000000
#define EED_FLAG_SCAN_NAME_CHECKS           0x00000001  /* bit0: 名称检查 */
#define EED_FLAG_SCAN_HARDWARE_FP           0x00000002  /* bit1: 硬件指纹 */
#define EED_FLAG_SCAN_FILESYSTEM            0x00000004  /* bit2: 文件系统 */
#define EED_FLAG_SCAN_REGISTRY              0x00000008  /* bit3: 注册表 */
#define EED_FLAG_SCAN_USER_ACTIVITY         0x00000010  /* bit4: 用户活动 */
#define EED_FLAG_SCAN_NETWORK               0x00000020  /* bit5: 网络配置 */
#define EED_FLAG_SCAN_PROCESS_ENUM          0x00000040  /* bit6: 进程枚举 */
#define EED_FLAG_SCAN_TIMING                0x00000080  /* bit7: 时序检查 */
#define EED_FLAG_SCAN_ENV_VARS              0x00000100  /* bit8: 环境变量 */
#define EED_FLAG_SCAN_DISPLAY               0x00000200  /* bit9: 显示配置 */
#define EED_FLAG_SCAN_LOCALE                0x00000400  /* bit10: 区域设置 */
#define EED_FLAG_SCAN_BROWSER               0x00000800  /* bit11: 浏览器 */
#define EED_FLAG_SCAN_PERIPHERAL            0x00001000  /* bit12: 外设历史 */
#define EED_FLAG_SCAN_FILE_NAMING           0x00002000  /* bit13: 文件命名 */
#define EED_FLAG_SCAN_ADVANCED              0x00004000  /* bit14: 高级/PE 分析 */
#define EED_FLAG_SCAN_CPUID                 0x00008000  /* bit15: CPUID 高级检测 */

/* 行为标志 */
#define EED_FLAG_ENABLE_CACHING             0x00010000  /* bit16: 结果缓存 */
#define EED_FLAG_STOP_ON_FIRST_DETECTION    0x00020000  /* bit17: 首命中即停 */
#define EED_FLAG_TYPE_B_BEHAVIORAL          0x00040000  /* bit18: TYPE B 行为分析 */
#define EED_FLAG_TYPE_A_SYSTEM_ENV          0x00080000  /* bit19: TYPE A 系统环境 */

/* 预设扫描档位 */
#define EED_PRESET_QUICK          \
    (EED_FLAG_SCAN_NAME_CHECKS | EED_FLAG_SCAN_HARDWARE_FP | EED_FLAG_SCAN_TIMING | \
     EED_FLAG_ENABLE_CACHING)

#define EED_PRESET_STANDARD       \
    (EED_PRESET_QUICK | EED_FLAG_SCAN_FILESYSTEM | EED_FLAG_SCAN_REGISTRY | \
     EED_FLAG_SCAN_PROCESS_ENUM | EED_FLAG_SCAN_ENV_VARS)

#define EED_PRESET_DEEP           \
    (EED_PRESET_STANDARD | EED_FLAG_SCAN_USER_ACTIVITY | EED_FLAG_SCAN_NETWORK | \
     EED_FLAG_SCAN_DISPLAY | EED_FLAG_SCAN_BROWSER)

#define EED_PRESET_COMPREHENSIVE  \
    (0x0000FFFF | EED_FLAG_ENABLE_CACHING | EED_FLAG_TYPE_A_SYSTEM_ENV | \
     EED_FLAG_TYPE_B_BEHAVIORAL)

#define EED_PRESET_DEFAULT        EED_PRESET_STANDARD

/**************************************************/
/*          检测类别位码（用于 detectedCategories） */
/**************************************************/

#define EED_CAT_BIT(cat)  (1u << (cat))

/**************************************************/
/*     硬件指纹信息                                */
/**************************************************/

typedef struct _EED_HARDWARE_INFO {
    BOOLEAN     Valid;

    /* 处理器 */
    ULONG       ProcessorCount;             /* GetSystemInfo().dwNumberOfProcessors */
    ULONG       ProcessorCoreCount;         /* CPUID 报告的核心数 */
    WCHAR       CpuVendor[EED_MAX_CPU_VENDOR];
    WCHAR       CpuBrand[EED_MAX_CPU_BRAND];

    /* 内存 */
    UINT64      TotalRAM;                   /* 字节 */

    /* 磁盘 */
    UINT64      DiskSize;                   /* 字节（C: 盘总容量） */
    ULONG       DiskCount;                  /* 物理磁盘数 */

    /* 虚拟化指示 */
    BOOLEAN     HypervisorDetected;         /* CPUID 叶 1, ECX 位 31 */
    WCHAR       HypervisorVendor[32];       /* CPUID 叶 0x40000000 厂商字符串 */
    WCHAR       Manufacturer[EED_MAX_MANUFACTURER];
    WCHAR       ProductName[EED_MAX_PRODUCT_NAME];
    WCHAR       BiosVersion[EED_MAX_BIOS_VERSION];
    WCHAR       Motherboard[EED_MAX_MANUFACTURER];

    /* VM 厂商字符串列表（分号分隔） */
    WCHAR       VmIndicators[512];
} EED_HARDWARE_INFO, *PEED_HARDWARE_INFO;

/**************************************************/
/*     系统身份信息                                */
/**************************************************/

typedef struct _EED_IDENTITY_INFO {
    BOOLEAN     Valid;

    WCHAR       Username[EED_MAX_USERNAME];
    WCHAR       ComputerName[EED_MAX_COMPUTER_NAME];
    WCHAR       DomainName[EED_MAX_DOMAIN_NAME];

    UINT64      UptimeMs;                   /* GetTickCount64 */
    UINT64      LastBootTime;               /* FILETIME 启动时间 */
    UINT64      InstallTime;                /* 安装日期（Unix 时间戳秒） */
} EED_IDENTITY_INFO, *PEED_IDENTITY_INFO;

/**************************************************/
/*     网络配置信息                                */
/**************************************************/

typedef struct _EED_NETWORK_ADAPTER {
    WCHAR       Name[EED_MAX_ADAPTER_NAME];
    WCHAR       Description[EED_MAX_ADAPTER_DESCRIPTION];
    WCHAR       MacAddress[EED_MAX_MAC_STRING];
    WCHAR       IpAddress[EED_MAX_IP_STRING];
    UINT8       MacBytes[6];
    BOOLEAN     IsVMAdapter;
    BOOLEAN     IsLoopback;
} EED_NETWORK_ADAPTER, *PEED_NETWORK_ADAPTER;

typedef struct _EED_NETWORK_INFO {
    BOOLEAN     Valid;

    ULONG       AdapterCount;
    ULONG       VmAdapterCount;
    BOOLEAN     HasWiFi;

    WCHAR       DnsServer[EED_MAX_DNS_STRING];

    EED_NETWORK_ADAPTER Adapters[EED_MAX_NETWORK_ADAPTERS];
} EED_NETWORK_INFO, *PEED_NETWORK_INFO;

/**************************************************/
/*     用户活动信息                                */
/**************************************************/

typedef struct _EED_USER_ACTIVITY_INFO {
    BOOLEAN     Valid;
    BOOLEAN     IsLivedInSystem;

    SIZE_T      DesktopItemsCount;
    SIZE_T      DocumentsCount;
    SIZE_T      DownloadsCount;
    SIZE_T      RecentDocumentsCount;

    /* 鼠标/输入 */
    ULONG       LastInputIdleMs;            /* 最后输入距今（毫秒） */

    /* 窗口 */
    ULONG       VisibleWindowCount;

    /* 剪贴板 */
    UINT        ClipboardFormatCount;

    /* 事件日志 */
    ULONG       ApplicationEventCount;
} EED_USER_ACTIVITY_INFO, *PEED_USER_ACTIVITY_INFO;

/**************************************************/
/*     进程环境信息                                */
/**************************************************/

typedef struct _EED_ENV_VAR_ENTRY {
    WCHAR       Name[EED_MAX_ENV_VAR_NAME];
    WCHAR       Value[EED_MAX_ENV_VAR_VALUE];
} EED_ENV_VAR_ENTRY, *PEED_ENV_VAR_ENTRY;

typedef struct _EED_PROCESS_ENV_INFO {
    BOOLEAN     Valid;

    WCHAR       ExecutablePath[EED_MAX_FILE_PATH];

    /* 可疑环境变量（沙箱相关）索引数组 */
    ULONG       SuspiciousVarIndices[EED_MAX_ENV_VARS];
    ULONG       SuspiciousVarCount;

    /* 环境变量表 */
    EED_ENV_VAR_ENTRY Vars[EED_MAX_ENV_VARS];
    ULONG       VarCount;
} EED_PROCESS_ENV_INFO, *PEED_PROCESS_ENV_INFO;

/**************************************************/
/*     文件命名分析信息                             */
/**************************************************/

typedef struct _EED_FILE_NAMING_INFO {
    BOOLEAN     Valid;

    WCHAR       FileName[EED_MAX_FILE_NAME];    /* 不含路径 */
    WCHAR       BaseName[EED_MAX_FILE_NAME];    /* 不含扩展名 */
    WCHAR       DirectoryPath[EED_MAX_FILE_PATH];
    WCHAR       ExecutablePath[EED_MAX_FILE_PATH];

    BOOLEAN     IsMD5;
    BOOLEAN     IsSHA1;
    BOOLEAN     IsSHA256;
    BOOLEAN     IsGeneric;                      /* sample / malware / test 等 */
    BOOLEAN     InSuspiciousLocation;
    BOOLEAN     ContainsAnalysisKeywords;
    BOOLEAN     HasMultipleExtensions;
    BOOLEAN     IsRandomPattern;
} EED_FILE_NAMING_INFO, *PEED_FILE_NAMING_INFO;

/**************************************************/
/*          检测结果条目                            */
/**************************************************/

typedef struct _EED_DETECTION {
    EED_TECHNIQUE   Technique;
    EED_CATEGORY    Category;
    EED_SEVERITY    Severity;
    DOUBLE          Confidence;             /* 0.0 - 1.0 */
    WCHAR           DetectedValue[EED_MAX_VALUE];
    WCHAR           ExpectedValue[EED_MAX_EXPECTED_VALUE];
    WCHAR           Description[EED_MAX_DESCRIPTION];
    WCHAR           Details[EED_MAX_DETAILS];
    WCHAR           Source[EED_MAX_SOURCE];
    WCHAR           MitreId[EED_MAX_MITRE_ID];
} EED_DETECTION, *PEED_DETECTION;

/**************************************************/
/*          分析配置                                */
/**************************************************/

typedef struct _EED_CONFIG {
    EED_DEPTH       Depth;                  /* 分析深度 */
    ULONG           Flags;                  /* EED_FLAG_* 位图 */
    ULONG           TimeoutMs;              /* 扫描超时（毫秒，0=默认） */
    DOUBLE          MinConfidence;          /* 最低置信度阈值（0.0=全部上报） */
    ULONG           TargetPid;              /* TYPE B 分析目标 PID（0=仅 TYPE A） */
} EED_CONFIG, *PEED_CONFIG;

/**************************************************/
/*          分析结果                                */
/**************************************************/

typedef struct _EED_RESULT {
    /* --- 标识 --- */
    ULONG           TargetPid;
    WCHAR           ProcessName[EED_MAX_PROCESS_NAME];
    WCHAR           ProcessPath[EED_MAX_PROCESS_PATH];

    /* --- 评分摘要 --- */
    BOOLEAN         IsEvasive;
    DOUBLE          EvasionScore;           /* 0.0 - 100.0 */
    EED_SEVERITY    MaxSeverity;
    ULONG           TotalDetections;
    ULONG           DetectedCategories;     /* 位码：EED_CAT_BIT(cat) 组合 */

    /* --- 检测详情 --- */
    EED_DETECTION   Detections[EED_MAX_DETECTIONS];
    ULONG           TechniquesChecked;

    /* --- 上下文信息 --- */
    EED_HARDWARE_INFO       HardwareInfo;
    EED_IDENTITY_INFO       IdentityInfo;
    EED_NETWORK_INFO        NetworkInfo;
    EED_USER_ACTIVITY_INFO  ActivityInfo;
    EED_PROCESS_ENV_INFO    ProcessEnvInfo;
    EED_FILE_NAMING_INFO    FileNamingInfo;

    /* --- 指示器列表（分号分隔） --- */
    WCHAR           VmIndicators[1024];
    WCHAR           SandboxIndicators[1024];
    WCHAR           AnalysisToolIndicators[512];

    /* --- 统计 --- */
    ULONG           CategoriesChecked;
    ULONG           RegistryKeysChecked;
    ULONG           FilesChecked;
    ULONG           ProcessesChecked;

    /* --- 时间戳 --- */
    LARGE_INTEGER   AnalysisStartTime;
    LARGE_INTEGER   AnalysisEndTime;
    UINT64          AnalysisDurationMs;

    /* --- 内核上下文（可选填充） --- */
    BOOLEAN         HasKernelContext;
} EED_RESULT, *PEED_RESULT;

/**************************************************/
/*          内核上下文（由驱动侧提供）               */
/**************************************************/

typedef struct _EED_KERNEL_CONTEXT {
    WCHAR           ImagePath[260];
    WCHAR           CommandLine[1024];
    ULONG           ParentProcessId;
    ULONG           CreatingProcessId;
    ULONG           CreatingThreadId;
    BOOLEAN         IsCreation;
} EED_KERNEL_CONTEXT, *PEED_KERNEL_CONTEXT;

/**************************************************/
/*          统计快照                                */
/**************************************************/

typedef struct _EED_STATS {
    volatile LONG64  TotalAnalyses;
    volatile LONG64  EvasiveProcesses;
    volatile LONG64  TotalDetections;
    volatile LONG64  CacheHits;
    volatile LONG64  CacheMisses;
    volatile LONG64  AnalysisErrors;
    volatile LONG64  TotalAnalysisTimeUs;
    /* 分类检测计数（15 个类别） */
    volatile LONG64  CategoryDetections[16];
} EED_STATS, *PEED_STATS;

/**************************************************/
/*          回调类型                                */
/**************************************************/

/* 检测回调：每命中一条检测触发。 */
typedef VOID (CALLBACK *PEED_DETECTION_CALLBACK)(
    _In_ ULONG TargetPid,
    _In_ const EED_DETECTION* Detection,
    _In_opt_ PVOID Context
    );

/**************************************************/
/*          公共 API                               */
/**************************************************/

/* ------------------------------------------------------------------ */
/* 主入口（TYPE A）：分析当前系统环境（是否为 VM/沙箱）。               */
/*  Config 为扫描配置（NULL=默认 Comprehensive）。                      */
/*  Result 接收分析结果（调用方分配，不可为 NULL）。                     */
/*  返回 NTSTATUS。                                                    */
/* ------------------------------------------------------------------ */
_Must_inspect_result_
NTSTATUS
EedAnalyzeSystemEnvironment(
    _In_opt_ const EED_CONFIG* Config,
    _Out_ PEED_RESULT          Result
    );

/* ------------------------------------------------------------------ */
/* 主入口（TYPE B）：对指定进程执行环境逃逸行为分析。                    */
/*  ProcessId 为目标分析进程 PID。                                      */
/*  Config 为扫描配置（NULL=默认 Standard）。                           */
/*  Result 接收分析结果（调用方分配，不可为 NULL）。                     */
/*  返回 NTSTATUS。                                                    */
/* ------------------------------------------------------------------ */
_Must_inspect_result_
NTSTATUS
EedAnalyzeProcess(
    _In_  ULONG              ProcessId,
    _In_opt_ const EED_CONFIG* Config,
    _Out_ PEED_RESULT         Result
    );

/* ------------------------------------------------------------------ */
/* 主入口（TYPE B 增强版）：额外接收内核上下文。                         */
/*  KernelContext 为驱动侧传来的可信进程创建数据（可为 NULL）。         */
/* ------------------------------------------------------------------ */
_Must_inspect_result_
NTSTATUS
EedAnalyzeProcessWithContext(
    _In_  ULONG              ProcessId,
    _In_opt_ const EED_CONFIG* Config,
    _In_opt_ const EED_KERNEL_CONTEXT* KernelContext,
    _Out_ PEED_RESULT         Result
    );

/* ------------------------------------------------------------------ */
/* 初始化/清理（全局统计与缓存）。                                      */
/* ------------------------------------------------------------------ */
_Must_inspect_result_
NTSTATUS
EedInitialize(
    _Outptr_ PEED_STATS* GlobalStats
    );

VOID
EedShutdown(
    _In_opt_ _Post_invalid_ PEED_STATS GlobalStats
    );

/* ------------------------------------------------------------------ */
/* 回调注册（可选，每条检测命中时同步触发）。                            */
/* ------------------------------------------------------------------ */
VOID
EedSetDetectionCallback(
    _In_opt_ PEED_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

/* ------------------------------------------------------------------ */
/* 类别/技术可读名称。                                                  */
/* ------------------------------------------------------------------ */
PCWSTR
EeTechniqueName(
    _In_ EED_TECHNIQUE Technique
    );

PCWSTR
EeCategoryName(
    _In_ EED_CATEGORY Category
    );

PCWSTR
EeSeverityName(
    _In_ EED_SEVERITY Severity
    );

#ifdef __cplusplus
}
#endif
