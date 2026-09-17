/**************************************************/
/*  WkDefender Agent — 沙箱逃逸检测引擎                */
/*  AntiEvasio                                      */
/*                                                  */
/*  迁移自 ShadowStrike SandboxEvasionDetector      */
/*  (.hpp 2672行 + .cpp 4043行)。                   */
/*                                                  */
/*  检测类别：                                       */
/*    类型A（系统上下文，用于行为评分校准）：          */
/*      1. 硬件指纹 (RAM/CPU/磁盘/BIOS/网卡)         */
/*      2. 系统磨损 (文档/桌面/程序/字体/临时文件)     */
/*      3. 环境探测 (分辨率/色深/时区/用户名)         */
/*      4. 沙箱工件 (DLL/进程/服务/互斥体/注册表/文件) */
/*      5. API 钩子检测（内联/Debug 钩子）           */
/*      6. 人机交互监测（鼠标轨迹/按键/窗口焦点）      */
/*    类型B（目标进程行为分析，主要检测）：            */
/*      7. PE 导入分类（沙箱探测 API 簇） T1497.001  */
/*      8. 内存字符串扫描（沙箱标识符）               */
/*      9. 代码模式扫描（RDTSC/CPUID 时序逃避）       */
/*                                                  */
/*  与源架构差异（纯 C 化决策）：                     */
/*    - PhantomDisassembler  → 字节模式扫描          */
/*    - PEParser             → 内联 PE 导入解析      */
/*    - asm 时序函数          → 全部省略（未被调用）  */
/*    - ThreadPool/异步       → 省略（无依赖）        */
/*    - WMI/COM              → 省略（实际未使用）     */
/*    - std::vector          → 固定上限数组           */
/*                                                  */
/*  编码：UTF-8 with BOM（铁律）                     */
/**************************************************/

#pragma once

#ifndef _WIN32
#error "此模块仅支持 Windows 平台"
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

/**************************************************/
/*          常量                                   */
/**************************************************/

/* 最大指示器数量（源 500，压缩以控制结构尺寸） */
#define SED_MAX_INDICATORS          256

/* 最大工件追踪数 */
#define SED_MAX_ARTIFACTS           128

/* 最大长度限制 */
#define SED_MAX_PATH                512
#define SED_MAX_NAME                128
#define SED_MAX_DESC                192
#define SED_MAX_ISSUES              16
#define SED_MAX_SUMMARY             8
#define SED_MAX_MITRE               8

/* 字符串表上限（与源数据表对齐） */
#define SED_MAX_HW_IMPORTS          10
#define SED_MAX_TIM_IMPORTS         6
#define SED_MAX_ENV_IMPORTS         11
#define SED_MAX_ART_IMPORTS         12
#define SED_MAX_HUM_IMPORTS         8
#define SED_MAX_STR_DLLS            12
#define SED_MAX_STR_PROC            20
#define SED_MAX_STR_MUTEX           7
#define SED_MAX_STR_VM              11
#define SED_MAX_STR_REG             8
#define SED_MAX_STR_PROD            8

/* 类型A 工件表上限 */
#define SED_MAX_DLLS                15
#define SED_MAX_PROCESSES           33   /* 源 35 项，去除 joebox 重复笔误 */
#define SED_MAX_ANALYSIS_TOOLS      9
#define SED_MAX_SERVICES            4
#define SED_MAX_MUTEXES             6
#define SED_MAX_PIPES               4
#define SED_MAX_EVENTS              4
#define SED_MAX_REGKEYS             14
#define SED_MAX_FILES               14
#define SED_MAX_DIRS                8
#define SED_MAX_SA_DLLS             8
#define SED_MAX_HOOKED_APIS         17
#define SED_MAX_IDENTIFIED          16

/* 进程内部分析表上限 */
#define SED_MAX_PROC_MITRE          8

/* 阈值常量（对齐源 SandboxConstants） */
#define SED_MIN_RAM_BYTES           (1ULL * 1024 * 1024 * 1024)     /* 1GB */
#define SED_SUSPICIOUS_RAM_BYTES    (512ULL * 1024 * 1024)          /* 512MB */
#define SED_MIN_CPU_CORES           1
#define SED_SUSPICIOUS_CPU_CORES    0
#define SED_MIN_DISK_BYTES          (20ULL * 1024 * 1024 * 1024)    /* 20GB */
#define SED_SUSPICIOUS_DISK_BYTES   (8ULL * 1024 * 1024 * 1024)     /* 8GB */
#define SED_MIN_UPTIME_MS           (10 * 60 * 1000)                /* 10分钟 */
#define SED_SUSPICIOUS_UPTIME_MS    (5 * 60 * 1000)                 /* 5分钟 */
#define SED_VERY_SUSPICIOUS_UPTIME_MS (2 * 60 * 1000)               /* 2分钟 */
#define SED_MIN_INSTALL_AGE_DAYS    7
#define SED_MIN_RECENT_DOCUMENTS    10
#define SED_MIN_DESKTOP_FILES       5
#define SED_MIN_INSTALLED_PROGRAMS  20
#define SED_MIN_BROWSER_HISTORY     50
#define SED_MIN_TEMP_FILES          100
#define SED_MIN_EVENT_LOG_ENTRIES   1000
#define SED_SUSPICIOUS_SCREEN_WIDTH 1024
#define SED_VERY_SUSPICIOUS_SCREEN_WIDTH 800
#define SED_SUSPICIOUS_SCREEN_HEIGHT 768
#define SED_VERY_SUSPICIOUS_SCREEN_HEIGHT 600
#define SED_MIN_COLOR_DEPTH         24
#define SED_DEFAULT_INTERACTION_MS  5000
#define SED_MIN_INTERACTION_MS      1000
#define SED_MAX_INTERACTION_MS      60000
#define SED_MIN_MOUSE_MOVEMENTS     5
#define SED_MIN_MOUSE_DISTANCE      100
#define SED_MAX_STRAIGHT_LINE_RATIO 0.9
#define SED_CACHE_TTL_MINUTES       10
#define SED_PROBABILITY_THRESHOLD   60.0f
#define SED_HIGH_CONFIDENCE_THRESHOLD 80.0f

/* TYPE B 默认扫描预算 */
#define SED_DEFAULT_MAX_MEM_SCAN    (64ULL * 1024 * 1024)   /* 64MB */
#define SED_DEFAULT_MAX_CODE_SCAN   (4ULL * 1024 * 1024)    /* 4MB */
#define SED_SYSTEM_MAX_MEM_SCAN     (4ULL * 1024 * 1024)    /* 系统扫描 4MB */
#define SED_SYSTEM_MAX_CODE_SCAN    (1ULL * 1024 * 1024)    /* 系统扫描 1MB */

/* 时序字节模式扫描窗口（降级实现） */
#define SED_RDTSC_SANDWICH_WINDOW   64    /* ≈ 20 条指令 */
#define SED_VMEXIT_PROBE_WINDOW     40    /* ≈ 10 条指令 */
#define SED_RDTSC_RESET_WINDOW      200   /* ≈ 50 条指令 */

/* 评分公式常量 */
#define SED_IMPORT_WEIGHT           0.30f
#define SED_STRING_WEIGHT           0.40f
#define SED_CODE_WEIGHT             0.30f
#define SED_EVASION_THRESHOLD       25.0f

/**************************************************/
/*          枚举：沙箱产品                         */
/*  SandboxProduct 枚举值                  */
/**************************************************/

typedef enum _SED_PRODUCT {
    SED_PRODUCT_Unknown = 0,

    /* 开源沙箱 (1-49) */
    SED_PRODUCT_Cuckoo            = 1,
    SED_PRODUCT_CAPE              = 2,
    SED_PRODUCT_Drakvuf           = 3,
    SED_PRODUCT_LiSa              = 4,

    /* 商业沙箱 (50-99) */
    SED_PRODUCT_JoeSandbox        = 50,
    SED_PRODUCT_AnyRun            = 51,
    SED_PRODUCT_HybridAnalysis    = 52,
    SED_PRODUCT_VirusTotal        = 53,
    SED_PRODUCT_VMRay             = 54,
    SED_PRODUCT_FireEyeAX         = 55,
    SED_PRODUCT_WildFire          = 56,
    SED_PRODUCT_ThreatGrid        = 57,
    SED_PRODUCT_Triage            = 58,
    SED_PRODUCT_Intezer           = 59,
    SED_PRODUCT_Lastline          = 60,
    SED_PRODUCT_RecordedFuture    = 61,

    /* 桌面沙箱 (100-149) */
    SED_PRODUCT_Sandboxie         = 100,
    SED_PRODUCT_WindowsSandbox    = 101,
    SED_PRODUCT_ComodoSandbox     = 102,
    SED_PRODUCT_AvastDeepScreen   = 103,
    SED_PRODUCT_BitdefenderATC    = 104,
    SED_PRODUCT_KasperskySafeRun  = 105,
    SED_PRODUCT_NortonSandbox     = 106,
    SED_PRODUCT_ESETLiveGuard     = 107,

    /* 企业沙箱 (150-199) */
    SED_PRODUCT_FalconSandbox     = 150,
    SED_PRODUCT_DefenderATP       = 151,
    SED_PRODUCT_CarbonBlack       = 152,
    SED_PRODUCT_SentinelOne       = 153,
    SED_PRODUCT_Cybereason        = 154,
    SED_PRODUCT_SophosInterceptX  = 155,
    SED_PRODUCT_TrendMicroDD      = 156,
    SED_PRODUCT_McAfeeATD         = 157,

    /* 研究/自定义 (200-254) */
    SED_PRODUCT_GenericAnalysis   = 200,
    SED_PRODUCT_CustomSandbox     = 201,
    SED_PRODUCT_Reserved          = 254,

    /* 多个沙箱 */
    SED_PRODUCT_Multiple          = 255
} SED_PRODUCT;

/**************************************************/
/*          枚举：指示器类别                       */
/**************************************************/

typedef enum _SED_INDICATOR_CATEGORY {
    SED_CATEGORY_Unknown          = 0,
    SED_CATEGORY_HumanInteraction = 1,
    SED_CATEGORY_Hardware         = 2,
    SED_CATEGORY_WearAndTear      = 3,
    SED_CATEGORY_Timing           = 4,
    SED_CATEGORY_Artifact         = 5,
    SED_CATEGORY_Environment      = 6,
    SED_CATEGORY_Network          = 7,
    SED_CATEGORY_FileSystem       = 8,
    SED_CATEGORY_Process          = 9,
    SED_CATEGORY_Registry         = 10,
    SED_CATEGORY_Kernel           = 11
} SED_INDICATOR_CATEGORY;

/**************************************************/
/*          枚举：严重度                           */
/**************************************************/

typedef enum _SED_SEVERITY {
    SED_SEVERITY_Info      = 0,
    SED_SEVERITY_Low       = 25,
    SED_SEVERITY_Medium    = 50,
    SED_SEVERITY_High      = 75,
    SED_SEVERITY_Critical  = 100
} SED_SEVERITY;

/**************************************************/
/*          枚举：检测类型                         */
/*  SandboxCheckType 枚举值                */
/**************************************************/

typedef enum _SED_CHECK_TYPE {
    SED_CHECK_Unknown = 0,

    /* 硬件 (1-29) */
    SED_CHECK_RAMSize            = 1,
    SED_CHECK_CPUCores           = 2,
    SED_CHECK_DiskSize           = 3,
    SED_CHECK_GPUPresence        = 4,
    SED_CHECK_NetworkAdapters    = 5,
    SED_CHECK_USBHistory         = 6,
    SED_CHECK_BIOSInfo           = 7,
    SED_CHECK_MotherboardInfo    = 8,
    SED_CHECK_CPUModel           = 9,
    SED_CHECK_StorageType        = 10,

    /* 人机交互 (30-49) */
    SED_CHECK_MouseMovement      = 30,
    SED_CHECK_MouseClicks        = 31,
    SED_CHECK_KeyboardInput      = 32,
    SED_CHECK_WindowFocus        = 33,
    SED_CHECK_ClipboardActivity  = 34,
    SED_CHECK_UserIdleTime       = 35,
    SED_CHECK_ScrollWheel        = 36,

    /* 时序 (50-69) */
    SED_CHECK_SystemUptime       = 50,
    SED_CHECK_InstallDate        = 51,
    SED_CHECK_LastBootTime       = 52,
    SED_CHECK_ProcessTimes       = 53,
    SED_CHECK_TimeConsistency    = 54,

    /* 磨损 (70-99) */
    SED_CHECK_RecentDocuments    = 70,
    SED_CHECK_DesktopFiles       = 71,
    SED_CHECK_DownloadsFolder    = 72,
    SED_CHECK_BrowserHistory     = 73,
    SED_CHECK_InstalledPrograms  = 74,
    SED_CHECK_TempFiles          = 75,
    SED_CHECK_EventLogDepth      = 76,
    SED_CHECK_RestorePoints      = 77,
    SED_CHECK_UserProfiles       = 78,
    SED_CHECK_BrowserCache       = 79,
    SED_CHECK_EmailData          = 80,
    SED_CHECK_MediaFiles         = 81,

    /* 环境 (100-129) */
    SED_CHECK_ScreenResolution   = 100,
    SED_CHECK_ColorDepth         = 101,
    SED_CHECK_MonitorCount       = 102,
    SED_CHECK_AudioDevices       = 103,
    SED_CHECK_Printers           = 104,
    SED_CHECK_Timezone           = 105,
    SED_CHECK_Locale             = 106,
    SED_CHECK_FontCount          = 107,
    SED_CHECK_Wallpaper          = 108,
    SED_CHECK_VisualSettings     = 109,

    /* 工件 (130-169) */
    SED_CHECK_SandboxDLLs        = 130,
    SED_CHECK_SandboxProcesses   = 131,
    SED_CHECK_SandboxServices    = 132,
    SED_CHECK_SandboxMutexes     = 133,
    SED_CHECK_SandboxNamedPipes  = 134,
    SED_CHECK_SandboxRegistry    = 135,
    SED_CHECK_SandboxFiles       = 136,
    SED_CHECK_HookDetection      = 137,
    SED_CHECK_AgentDetection     = 138,
    SED_CHECK_AnalysisTools      = 139,

    /* 网络 (170-199) */
    SED_CHECK_DNSResolver        = 170,
    SED_CHECK_GatewayFingerprint = 171,
    SED_CHECK_ExternalIP         = 172,
    SED_CHECK_NetworkLatency     = 173,
    SED_CHECK_BlockedPorts       = 174,
    SED_CHECK_InternetConnectivity = 175,
    SED_CHECK_MACAddress         = 176,

    /* 文件系统 (200-229) */
    SED_CHECK_System32Analysis   = 200,
    SED_CHECK_ProgramFilesDiversity = 201,
    SED_CHECK_ProfileCompleteness = 202,
    SED_CHECK_DocumentMetadata   = 203,
    SED_CHECK_FileTimestamps     = 204,
    SED_CHECK_HiddenFiles        = 205
} SED_CHECK_TYPE;

/**************************************************/
/*          枚举：人机交互结果                     */
/**************************************************/

typedef enum _SED_INTERACTION_RESULT {
    SED_INTERACTION_NotAnalyzed         = 0,
    SED_INTERACTION_HumanDetected       = 1,
    SED_INTERACTION_NoInteraction       = 2,
    SED_INTERACTION_BotPatterns         = 3,
    SED_INTERACTION_SimulatedInteraction = 4,
    SED_INTERACTION_Timeout             = 5,
    SED_INTERACTION_Error               = 6
} SED_INTERACTION_RESULT;

/**************************************************/
/*          结构体：单条指示器                     */
/**************************************************/

typedef struct _SED_INDICATOR {
    SED_CHECK_TYPE           CheckType;
    SED_INDICATOR_CATEGORY   Category;
    SED_SEVERITY             Severity;
    FLOAT                    Weight;        /* 0.0 - 10.0 */
    FLOAT                    Confidence;    /* 0.0 - 100.0 */
    SED_PRODUCT              SuspectedProduct;
    WCHAR                    Description[SED_MAX_DESC];
    WCHAR                    TechnicalDetails[SED_MAX_DESC];
    WCHAR                    ObservedValue[SED_MAX_NAME];
    WCHAR                    ExpectedValue[SED_MAX_NAME];
    CHAR                     MitreId[16];
    ULONGLONG                DetectionTime; /* FILETIME */
    BOOLEAN                  IsConclusive;
} SED_INDICATOR, *PSED_INDICATOR;

/**************************************************/
/*          结构体：硬件画像                       */
/**************************************************/

typedef struct _SED_HARDWARE_PROFILE {
    /* 内存 */
    ULONGLONG  TotalRam;
    ULONGLONG  AvailableRam;
    ULONGLONG  VirtualMemoryLimit;

    /* CPU */
    ULONG      LogicalProcessors;
    ULONG      PhysicalCores;
    WCHAR      CpuModel[SED_MAX_NAME];
    WCHAR      CpuVendor[64];
    ULONG      CpuFrequencyMHz;
    ULONGLONG  CpuFeatures;

    /* 存储 */
    ULONGLONG  TotalDiskSpace;
    ULONGLONG  FreeDiskSpace;
    ULONG      DiskCount;
    WCHAR      PrimaryDiskType[64];
    WCHAR      DiskSerial[64];

    /* 显卡 */
    BOOLEAN    GpuPresent;
    WCHAR      GpuModel[SED_MAX_NAME];
    WCHAR      GpuVendor[64];
    ULONGLONG  VideoRam;

    /* 网络 */
    ULONG      NetworkAdapterCount;
    BOOLEAN    PhysicalNicPresent;
    BOOLEAN    WifiPresent;
    BOOLEAN    BluetoothPresent;

    /* 外设 */
    ULONG      UsbDeviceCount;
    ULONG      UsbHistoryCount;
    BOOLEAN    AudioDevicePresent;
    BOOLEAN    WebcamPresent;
    ULONG      PrinterCount;

    /* BIOS/固件 */
    WCHAR      BiosVendor[64];
    WCHAR      BiosVersion[64];
    WCHAR      BiosDate[64];
    WCHAR      SystemManufacturer[SED_MAX_NAME];
    WCHAR      SystemModel[SED_MAX_NAME];
    WCHAR      SystemSerial[64];

    /* 分析结果 */
    FLOAT      SuspicionScore;    /* 0.0 - 100.0 */
    BOOLEAN    IsSandboxLike;
    WCHAR      Issues[SED_MAX_ISSUES][SED_MAX_DESC];
    ULONG      IssueCount;
} SED_HARDWARE_PROFILE, *PSED_HARDWARE_PROFILE;

/**************************************************/
/*          结构体：系统磨损分析                   */
/**************************************************/

typedef struct _SED_WEAR_TEAR {
    /* 文档计数 */
    SIZE_T     RecentDocumentsCount;
    SIZE_T     DesktopFileCount;
    SIZE_T     DownloadsFileCount;
    SIZE_T     DocumentsFileCount;
    SIZE_T     PicturesFileCount;

    /* 浏览器数据 */
    SIZE_T     BrowserHistoryCount;
    SIZE_T     BrowserCookieCount;
    SIZE_T     SavedPasswordCount;
    SIZE_T     BookmarkCount;
    SIZE_T     BrowserExtensionCount;

    /* 系统指标 */
    SIZE_T     InstalledProgramCount;
    SIZE_T     WindowsUpdateCount;
    SIZE_T     EventLogEntryCount;
    SIZE_T     PrefetchFileCount;
    SIZE_T     TempFileCount;
    SIZE_T     RecycleBinCount;
    SIZE_T     RestorePointCount;
    SIZE_T     UserProfileCount;

    /* 字体/主题 */
    SIZE_T     FontCount;
    BOOLEAN    CustomThemesPresent;
    BOOLEAN    CustomWallpaper;

    /* 通信数据 */
    BOOLEAN    EmailConfigured;
    SIZE_T     ImAppsCount;

    /* 分析结果 */
    FLOAT      UsageScore;        /* 0.0 - 100.0 */
    BOOLEAN    AppearsFresh;
    WCHAR      Issues[SED_MAX_ISSUES][SED_MAX_DESC];
    ULONG      IssueCount;
} SED_WEAR_TEAR, *PSED_WEAR_TEAR;

/**************************************************/
/*          结构体：人机交互分析                   */
/**************************************************/

typedef struct _SED_HUMAN_INTERACTION {
    /* 监控参数 */
    ULONG      MonitoringDurationMs;

    /* 鼠标分析 */
    ULONG      MouseMovementCount;
    ULONGLONG  MouseDistanceTraveled;
    ULONG      MouseClickCount;
    ULONG      LeftClickCount;
    ULONG      RightClickCount;
    ULONG      DoubleClickCount;
    ULONG      ScrollWheelEvents;
    DOUBLE     AvgMouseVelocity;    /* 像素/秒 */
    DOUBLE     MaxMouseVelocity;
    DOUBLE     StraightLineRatio;   /* 0.0-1.0 */
    DOUBLE     PathEntropy;         /* 0.0-1.0 */

    /* 键盘分析 */
    ULONG      KeyPressCount;
    ULONG      UniqueKeysPressed;
    DOUBLE     AvgTypingSpeed;
    DOUBLE     KeyTimingVariance;

    /* 窗口/焦点 */
    ULONG      WindowFocusChanges;
    ULONG      ApplicationsInteracted;
    ULONG      ClipboardOperations;

    /* 结果 */
    SED_INTERACTION_RESULT Result;
    FLOAT      HumanConfidence;     /* 0.0 - 100.0 */
    FLOAT      BotConfidence;
    FLOAT      SimulatedConfidence;
    BOOLEAN    AnalysisComplete;
    WCHAR      ErrorMessage[256];
    WCHAR      Findings[8][SED_MAX_DESC];
    ULONG      FindingCount;
} SED_HUMAN_INTERACTION, *PSED_HUMAN_INTERACTION;

/**************************************************/
/*          结构体：环境分析                       */
/**************************************************/

typedef struct _SED_ENV_ANALYSIS {
    /* 显示 */
    ULONG      ScreenWidth;
    ULONG      ScreenHeight;
    ULONG      ColorDepth;
    ULONG      MonitorCount;
    ULONG      Dpi;
    BOOLEAN    IsVmResolution;

    /* 区域/时间 */
    WCHAR      Timezone[SED_MAX_NAME];
    WCHAR      Locale[64];
    WCHAR      KeyboardLayout[64];
    WCHAR      DateFormat[64];
    WCHAR      TimeFormat[64];
    BOOLEAN    TimezoneConsistent;

    /* 系统信息 */
    WCHAR      ComputerName[64];
    WCHAR      Domain[64];
    WCHAR      UserName[SED_MAX_NAME];
    WCHAR      WindowsVersion[SED_MAX_NAME];
    ULONG      WindowsBuild;
    BOOLEAN    WindowsActivated;

    /* 分析结果 */
    FLOAT      SuspicionScore;
    WCHAR      Issues[SED_MAX_ISSUES][SED_MAX_DESC];
    ULONG      IssueCount;
} SED_ENV_ANALYSIS, *PSED_ENV_ANALYSIS;

/**************************************************/
/*          结构体：工件分析                       */
/**************************************************/

typedef struct _SED_ARTIFACT_ANALYSIS {
    /* DLL */
    WCHAR      SandboxDlls[SED_MAX_DLLS][SED_MAX_NAME];
    ULONG      SandboxDllCount;
    WCHAR      HookDlls[SED_MAX_SA_DLLS][SED_MAX_NAME];
    ULONG      HookDllCount;
    SIZE_T     SuspiciousDllCount;

    /* 进程 */
    WCHAR      SandboxProcesses[SED_MAX_PROCESSES][SED_MAX_NAME];
    ULONG      SandboxProcessCount;
    WCHAR      AnalysisToolProcesses[SED_MAX_ANALYSIS_TOOLS][SED_MAX_NAME];
    ULONG      AnalysisToolProcessCount;
    SIZE_T     SuspiciousProcessCount;

    /* 服务 */
    WCHAR      SandboxServices[SED_MAX_SERVICES][SED_MAX_NAME];
    ULONG      SandboxServiceCount;
    SIZE_T     SuspiciousServiceCount;

    /* 命名对象 */
    WCHAR      SandboxMutexes[SED_MAX_MUTEXES][SED_MAX_NAME];
    ULONG      SandboxMutexCount;
    WCHAR      SandboxNamedPipes[SED_MAX_PIPES][SED_MAX_NAME];
    ULONG      SandboxNamedPipeCount;
    WCHAR      SandboxEvents[SED_MAX_EVENTS][SED_MAX_NAME];
    ULONG      SandboxEventCount;

    /* 注册表 */
    WCHAR      SandboxRegistryKeys[SED_MAX_REGKEYS][SED_MAX_PATH];
    ULONG      SandboxRegistryKeyCount;
    SIZE_T     SuspiciousRegistryCount;

    /* 文件 */
    WCHAR      SandboxFiles[SED_MAX_FILES][SED_MAX_PATH];
    ULONG      SandboxFileCount;
    WCHAR      SandboxDirectories[SED_MAX_DIRS][SED_MAX_PATH];
    ULONG      SandboxDirectoryCount;

    /* 钩子检测 */
    BOOLEAN    ApiHooksDetected;
    ULONG      HookedApiCount;
    WCHAR      HookedApis[SED_MAX_HOOKED_APIS][SED_MAX_NAME];

    /* 结果 */
    SED_PRODUCT IdentifiedProducts[SED_MAX_IDENTIFIED];
    ULONG      IdentifiedProductCount;
    SED_PRODUCT PrimarySuspect;
    FLOAT      SuspicionScore;
    SIZE_T     TotalArtifactsFound;
    BOOLEAN    DefinitiveDetection;
} SED_ARTIFACT_ANALYSIS, *PSED_ARTIFACT_ANALYSIS;

/**************************************************/
/*          结构体：综合结果                       */
/**************************************************/

typedef struct _SED_RESULT {
    /* 核心判定 */
    BOOLEAN    IsSandboxLikely;
    FLOAT      Probability;         /* 0.0 - 100.0 */
    FLOAT      Confidence;
    BOOLEAN    IsDefinitive;

    /* 识别产品 */
    SED_PRODUCT IdentifiedSandbox;
    SED_PRODUCT SuspectedProducts[SED_MAX_IDENTIFIED];
    ULONG      SuspectedProductCount;
    WCHAR      SandboxName[SED_MAX_NAME];

    /* 各分析子结构 */
    SED_HARDWARE_PROFILE Hardware;
    SED_WEAR_TEAR        WearAndTear;
    BOOLEAN              HasHumanInteraction;
    SED_HUMAN_INTERACTION HumanInteraction;
    SED_ENV_ANALYSIS     Environment;
    SED_ARTIFACT_ANALYSIS Artifacts;

    /* 指示器 */
    SED_INDICATOR Indicators[SED_MAX_INDICATORS];
    ULONG         IndicatorCount;
    WCHAR         SummaryMessages[SED_MAX_SUMMARY][SED_MAX_DESC];
    ULONG         SummaryMessageCount;

    /* 检查计数 */
    ULONG        FailedChecks;
    ULONG        PassedChecks;
    ULONG        TotalChecks;

    /* 分类分数 */
    FLOAT        HardwareScore;
    FLOAT        WearAndTearScore;
    FLOAT        HumanInteractionScore;
    FLOAT        EnvironmentScore;
    FLOAT        ArtifactScore;
    FLOAT        TimingScore;
    FLOAT        NetworkScore;

    /* MITRE */
    CHAR         MitreIds[SED_MAX_MITRE][16];
    ULONG        MitreIdCount;
    CHAR         MitreTactic[16];

    /* 元数据 */
    ULONGLONG    AnalysisStartTime; /* FILETIME */
    ULONGLONG    AnalysisEndTime;
    ULONGLONG    AnalysisDurationMs;
    BOOLEAN      AnalysisComplete;
    WCHAR        ErrorMessage[256];
} SED_RESULT, *PSED_RESULT;

/**************************************************/
/*          结构体：检测配置                       */
/**************************************************/

typedef struct _SED_CONFIG {
    /* 常规 */
    BOOLEAN    Enabled;
    FLOAT      ProbabilityThreshold;         /* 默认 60.0f */
    BOOLEAN    EnableCache;
    ULONG      CacheTtlMinutes;              /* 默认 10 */

    /* 检查类别开关 */
    BOOLEAN    CheckHardware;
    BOOLEAN    CheckWearAndTear;
    BOOLEAN    CheckHumanInteraction;
    BOOLEAN    CheckEnvironment;
    BOOLEAN    CheckArtifacts;
    BOOLEAN    CheckTiming;
    BOOLEAN    CheckNetwork;
    BOOLEAN    CheckFileSystem;

    /* 硬件阈值 */
    ULONGLONG  MinRam;               /* 1GB */
    ULONG      MinCpuCores;          /* 1 */
    ULONGLONG  MinDiskSize;          /* 20GB */

    /* 时序阈值 */
    ULONGLONG  MinUptime;            /* 10分钟 */
    ULONG      MinInstallAgeDays;    /* 7 */

    /* 磨损阈值 */
    SIZE_T     MinRecentDocuments;   /* 10 */
    SIZE_T     MinInstalledPrograms; /* 20 */
    SIZE_T     MinBrowserHistory;    /* 50 */

    /* 人机交互 */
    ULONG      HumanInteractionMonitorMs;  /* 5000 */
    ULONG      MinMouseMovements;          /* 5 */
    ULONG      MinMouseDistance;           /* 100 */

    /* 屏幕阈值 */
    ULONG      SuspiciousScreenWidth;      /* 1024 */
    ULONG      SuspiciousScreenHeight;     /* 768 */

    /* 分类权重 */
    FLOAT      HardwareWeight;             /* 1.5f */
    FLOAT      WearAndTearWeight;          /* 1.0f */
    FLOAT      HumanInteractionWeight;     /* 2.0f */
    FLOAT      EnvironmentWeight;          /* 1.0f */
    FLOAT      ArtifactWeight;             /* 3.0f */
    FLOAT      TimingWeight;               /* 1.2f */
    FLOAT      NetworkWeight;              /* 0.8f */
} SED_CONFIG, *PSED_CONFIG;

/* 默认配置初始值（供参考；运行时请使用 SedApplyDefaultConfig） */
#define SED_CONFIG_DEFAULT_VALUES { \
    TRUE, SED_PROBABILITY_THRESHOLD, TRUE, SED_CACHE_TTL_MINUTES, \
    TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, \
    SED_MIN_RAM_BYTES, SED_MIN_CPU_CORES, SED_MIN_DISK_BYTES, \
    SED_MIN_UPTIME_MS, SED_MIN_INSTALL_AGE_DAYS, \
    SED_MIN_RECENT_DOCUMENTS, SED_MIN_INSTALLED_PROGRAMS, SED_MIN_BROWSER_HISTORY, \
    SED_DEFAULT_INTERACTION_MS, SED_MIN_MOUSE_MOVEMENTS, SED_MIN_MOUSE_DISTANCE, \
    SED_SUSPICIOUS_SCREEN_WIDTH, SED_SUSPICIOUS_SCREEN_HEIGHT, \
    1.5f, 1.0f, 2.0f, 1.0f, 3.0f, 1.2f, 0.8f \
}

/**************************************************/
/*          结构体：全局统计                       */
/**************************************************/

typedef struct _SED_STATS {
    volatile LONG64 TotalScans;
    volatile LONG64 SandboxesDetected;
    volatile LONG64 DefinitiveDetections;
    volatile LONG64 HumanInteractionChecks;
    volatile LONG64 CacheHits;
    volatile LONG64 CacheMisses;
    volatile LONG64 AvgAnalysisDurationUs;
    volatile LONG64 DetectionsByProduct[256];
} SED_STATS, *PSED_STATS;

/**************************************************/
/*          结构体：内核上下文                     */
/**************************************************/

typedef struct _SED_KERNEL_CONTEXT {
    WCHAR    ImagePath[SED_MAX_PATH];
    WCHAR    CommandLine[SED_MAX_PATH];
    ULONG    ParentProcessId;
    ULONG    CreatingProcessId;
    BOOLEAN  HasKernelData;   /* 由调用者设置 */
} SED_KERNEL_CONTEXT, *PSED_KERNEL_CONTEXT;

/**************************************************/
/*          结构体：进程分析配置 (类型B)           */
/**************************************************/

typedef struct _SED_PROCESS_CONFIG {
    BOOLEAN    CheckImports;          /* 默认 TRUE */
    BOOLEAN    CheckMemoryStrings;    /* 默认 TRUE */
    BOOLEAN    CheckCodePatterns;     /* 默认 TRUE */
    SIZE_T     MaxMemoryScanBytes;    /* 默认 64MB */
    SIZE_T     MaxCodeScanBytes;      /* 默认 4MB */
    SED_KERNEL_CONTEXT KernelContext;
    BOOLEAN    HasKernelCtx;
} SED_PROCESS_CONFIG, *PSED_PROCESS_CONFIG;

/**************************************************/
/*          结构体：进程分析结果 (类型B)           */
/**************************************************/

typedef struct _SED_PROCESS_RESULT {
    BOOLEAN    HasEvasionCapability;
    FLOAT      EvasionScore;          /* 0.0 - 100.0 */
    ULONG      ProcessId;

    /* 导入分析 */
    struct {
        WCHAR  HardwareFingerprinting[SED_MAX_HW_IMPORTS][SED_MAX_NAME];
        ULONG  HardwareFingerprintingCount;
        WCHAR  TimingApis[SED_MAX_TIM_IMPORTS][SED_MAX_NAME];
        ULONG  TimingApiCount;
        WCHAR  EnvironmentQueries[SED_MAX_ENV_IMPORTS][SED_MAX_NAME];
        ULONG  EnvironmentQueryCount;
        WCHAR  ArtifactChecks[SED_MAX_ART_IMPORTS][SED_MAX_NAME];
        ULONG  ArtifactCheckCount;
        WCHAR  HumanInteractionChecks[SED_MAX_HUM_IMPORTS][SED_MAX_NAME];
        ULONG  HumanInteractionCheckCount;
        FLOAT  Score;
    } Imports;

    /* 字符串分析 */
    struct {
        WCHAR  SandboxProductNames[SED_MAX_STR_PROD][SED_MAX_NAME];   /* 恒空（与源一致） */
        ULONG  SandboxProductNameCount;
        WCHAR  SandboxDllNames[SED_MAX_STR_DLLS][SED_MAX_NAME];
        ULONG  SandboxDllNameCount;
        WCHAR  SandboxProcessNames[SED_MAX_STR_PROC][SED_MAX_NAME];
        ULONG  SandboxProcessNameCount;
        WCHAR  SandboxMutexNames[SED_MAX_STR_MUTEX][SED_MAX_NAME];
        ULONG  SandboxMutexNameCount;
        WCHAR  VmVendorStrings[SED_MAX_STR_VM][SED_MAX_NAME];
        ULONG  VmVendorStringCount;
        WCHAR  SandboxRegistryPaths[SED_MAX_STR_REG][SED_MAX_NAME];
        ULONG  SandboxRegistryPathCount;
        FLOAT  Score;
    } Strings;

    /* 代码模式分析 */
    struct {
        ULONG  RdtscInstructions;
        ULONG  CpuidInstructions;
        ULONG  TimingSandwiches;
        ULONG  VmExitProbes;
        ULONG  PortProbes;
        FLOAT  Score;
    } CodePatterns;

    /* MITRE */
    CHAR         MitreIds[SED_MAX_PROC_MITRE][16];
    ULONG        MitreIdCount;

    ULONGLONG    AnalysisDurationUs;
} SED_PROCESS_RESULT, *PSED_PROCESS_RESULT;

/**************************************************/
/*          回调函数类型                           */
/**************************************************/

/* 系统扫描完成回调（快照后锁外调用） */
typedef VOID (CALLBACK *SED_DETECTION_CALLBACK)(
    _In_ const SED_RESULT* Result,
    _In_opt_ PVOID         Context
    );

/* 进程分析回调（configMutex 共享锁内调用） */
typedef VOID (CALLBACK *SED_PROCESS_CALLBACK)(
    _In_ const SED_PROCESS_RESULT* Result,
    _In_opt_ PVOID                 Context
    );

/**************************************************/
/*          编译器注解                             */
/**************************************************/

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4201)  /* 非名称的结构/联合 */
#endif

/**************************************************/
/*          公共 API — 初始化/关闭                 */
/**************************************************/

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SedInitialize(
    _In_opt_ PSED_CONFIG Config
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SedShutdown(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SedIsInitialized(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SedUpdateConfig(
    _In_ PSED_CONFIG Config
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SedGetConfig(
    _Out_ PSED_CONFIG Config
    );

/* 将默认值写入配置结构（运行时赋值，避免 C 初始化器局限） */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SedApplyDefaultConfig(
    _Out_ PSED_CONFIG Config
    );

/**************************************************/
/*          公共 API — 系统扫描                    */
/**************************************************/

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SedScanSystem(
    _Out_ PSED_RESULT Result
    );

/* 快速检查：工件/资源/运行时间，短路返回 */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SedQuickScan(
    VOID
    );

/**************************************************/
/*          公共 API — 主机上下文收集              */
/**************************************************/

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SedAnalyzeHardware(
    _Out_ PSED_HARDWARE_PROFILE Profile
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SedAnalyzeWearAndTear(
    _Out_ PSED_WEAR_TEAR Analysis
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SedAnalyzeEnvironment(
    _Out_ PSED_ENV_ANALYSIS Analysis
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SedScanArtifacts(
    _Out_ PSED_ARTIFACT_ANALYSIS Analysis
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SedVerifyHumanInteraction(
    _In_ ULONG MonitoringDurationMs
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SedAnalyzeHumanInteraction(
    _In_ ULONG MonitoringDurationMs,
    _Out_ PSED_HUMAN_INTERACTION Analysis
    );

/**************************************************/
/*          公共 API — 专项查询                    */
/**************************************************/

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SedIsSandboxProductDetected(
    _In_ SED_PRODUCT Product
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
ULONGLONG
SedGetSystemUptime(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SedGetScreenResolution(
    _Out_ PULONG Width,
    _Out_ PULONG Height
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SedIsSandboxDllLoaded(
    _In_ PCWSTR DllName
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SedIsSandboxProcessRunning(
    _In_ PCWSTR ProcessName
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SedDoesMutexExist(
    _In_ PCWSTR MutexName
    );

/**************************************************/
/*          公共 API — 类型B 进程分析              */
/**************************************************/

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SedAnalyzeProcess(
    _In_  HANDLE                ProcessHandle,
    _In_  ULONG                 ProcessId,
    _In_opt_ PSED_PROCESS_CONFIG Config,
    _Out_ PSED_PROCESS_RESULT   Result
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SedAnalyzeProcessById(
    _In_  ULONG                 ProcessId,
    _In_opt_ PSED_PROCESS_CONFIG Config,
    _Out_ PSED_PROCESS_RESULT   Result
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SedSetProcessDetectionCallback(
    _In_opt_ SED_PROCESS_CALLBACK Callback,
    _In_opt_ PVOID                Context
    );

/**************************************************/
/*          公共 API — 回调/统计/缓存              */
/**************************************************/

_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG64
SedRegisterCallback(
    _In_ SED_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID              Context
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SedUnregisterCallback(
    _In_ ULONG64 CallbackId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
SedGetStatistics(
    _Out_ PSED_STATS Stats
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SedResetStatistics(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SedGetCachedResult(
    _Out_ PSED_RESULT Result
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SedClearCache(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SedGetHardwareProfile(
    _Out_ PSED_HARDWARE_PROFILE Profile
    );

/**************************************************/
/*          公共 API — 名称/工具                   */
/**************************************************/

_Must_inspect_result_
PCWSTR
SedSandboxProductName(
    _In_ SED_PRODUCT Product
    );

_Must_inspect_result_
PCWSTR
SedCategoryName(
    _In_ SED_INDICATOR_CATEGORY Category
    );

_Must_inspect_result_
PCSTR
SedCheckTypeMitreId(
    _In_ SED_CHECK_TYPE CheckType
    );

/* 加权概率：Scores[i]*Weights[i] 求和 / 权重求和 */
_IRQL_requires_max_(PASSIVE_LEVEL)
FLOAT
SedCalculateWeightedProbability(
    _In_reads_(Count) const FLOAT* Scores,
    _In_reads_(Count) const FLOAT* Weights,
    _In_ ULONG Count
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
SED_SEVERITY
SedScoreToSeverity(
    _In_ FLOAT Score
    );

/* 鼠标路径熵（Shannon 熵，8 方向桶，归一化 0-1） */
_IRQL_requires_max_(PASSIVE_LEVEL)
DOUBLE
SedCalculateMousePathEntropy(
    _In_reads_(Count) const POINT* Movements,
    _In_ ULONG Count
    );

/* 直线率：直线距离 / 实际路径长度（0-1） */
_IRQL_requires_max_(PASSIVE_LEVEL)
DOUBLE
SedCalculateStraightLineRatio(
    _In_reads_(Count) const POINT* Movements,
    _In_ ULONG Count
    );

/**************************************************/
/*          结果初始化宏                           */
/**************************************************/

#define SED_INIT_RESULT(pResult) do { \
    RtlZeroMemory((pResult), sizeof(SED_RESULT)); \
} while(0)

#define SED_INIT_PROCESS_RESULT(pResult) do { \
    RtlZeroMemory((pResult), sizeof(SED_PROCESS_RESULT)); \
} while(0)

#define SED_INIT_ARTIFACT(pAnalysis) do { \
    RtlZeroMemory((pAnalysis), sizeof(SED_ARTIFACT_ANALYSIS)); \
} while(0)

#if defined(_MSC_VER)
#pragma warning(pop)
#endif