/**************************************************/
/*  WkDefender Agent — Registry 子系统【唯一】头     */
/*                                                  */
/*  内容（2026-09-15 起公共头 Registry.h 并入）：    */
/*    - 子系统公共门面接口（文件末尾公共段）：        */
/*      WkdRegistry_* 门面 + WKD_REG_NOTIFY 等       */
/*      公共类型，允许 main.c/Orchestrator 等外部    */
/*      模块引用（仅限公共段）                       */
/*    - 子系统共享类型/常量（原 RegistryCommon.h）   */
/*    - 各引擎私有结构与函数原型（PD/RA/RM/SSM/SA）  */
/*    - 引擎间互连声明（StartupAnalyzer ↔           */
/*      PersistenceDetector/RegistryMonitor 等）    */
/*                                                  */
/*  ⚠️  引擎私有段仅供 Registry\ 目录内 .c 实现      */
/*  ⚠️  文件引用，禁止被子系统外部（main.c/          */
/*  ⚠️  Orchestrator/其他模块）引用！外部一律使用    */
/*  ⚠️  文件末尾的公共门面段。                      */
/*                                                  */
/*  迁移来源：ShadowStrike PhantomCore/Core/Registry */
/*  （2026-09-08 全量迁移，纯 C 转写）              */
/**************************************************/

#pragma once

#include <windows.h>
#include <ntstatus.h>

/* 对齐项目惯例 (process_manager.h): C 移植不引入 status 供应商宏时使用 */
#ifndef STATUS_NOT_INITIALIZED
#define STATUS_NOT_INITIALIZED  0xC0000001L
#endif

/* ==================================================
 * 版本常量
 * ================================================== */
#define WKD_REG_VERSION_MAJOR  3
#define WKD_REG_VERSION_MINOR  0
#define WKD_REG_VERSION_PATCH  0

/* ==================================================
 * 输入边界常量（PersistenceDetectorConstants
 * 与各引擎硬化边界；转写时保留原上限语义）
 * ================================================== */

/* 扫描规模（SS 头声明 120，实测位置表约 60，按实测保留） */
#define WKD_REG_TOTAL_ASEP_LOCATIONS      120
#define WKD_REG_CRITICAL_ASEP_LOCATIONS   25
#define WKD_REG_MAX_SCAN_THREADS          8
#define WKD_REG_SCAN_TIMEOUT_MS           300000

/* 分析与解析边界 */
#define WKD_REG_MAX_COMMAND_LINE_LENGTH   32767
#define WKD_REG_MAX_RECURSION_DEPTH       10
#define WKD_REG_SUSPICIOUS_ENTROPY        6.5     /* 熵阈值（double 语义） */

/* 缓存规模 */
#define WKD_REG_SIGNATURE_CACHE_SIZE      10000
#define WKD_REG_HASH_CACHE_SIZE           50000
#define WKD_REG_CACHE_TTL_SECONDS         3600

/* 硬化输入边界（转写自 SS 匿名空间常量） */
#define WKD_REG_MAX_RAW_COMMAND_CHARS     32768
#define WKD_REG_MAX_MULTISTRING_ENTRIES   1024
#define WKD_REG_MAX_BASE64_INPUT_CHARS    (1024 * 1024)
#define WKD_REG_MAX_BASE64_DECODED_BYTES  (2 * 1024 * 1024)
#define WKD_REG_MAX_EXPANDED_PATH_CHARS   32767
#define WKD_REG_MAX_TASK_RECURSION_DEPTH  16
#define WKD_REG_MAX_ARGUMENT_CHARS        32768
#define WKD_REG_MAX_LOG_FIELD_CHARS       1024

/* 通用路径/名称上限（agent 侧宽字符缓冲） */
#define WKD_REG_MAX_PATH_CHARS            512
#define WKD_REG_MAX_NAME_CHARS            256
#define WKD_REG_MAX_DESC_CHARS            256
#define WKD_REG_MAX_USER_SID_CHARS        128
#define WKD_REG_MAX_HASH_HEX_CHARS        65      /* SHA256 小写十六进制 + NUL */

/* ==================================================
 * PersistenceType — 持久化入口类型（uint16 编码段）
 *   PD（ASEP 扫描）与 SA（启动项审计）共用。
 * ================================================== */
typedef enum _WKD_REG_PERSISTENCE_TYPE {
    WkdRegPersist_Unknown = 0,

    /* Registry Run Keys (100-105) */
    WkdRegPersist_RunKey = 100,
    WkdRegPersist_RunKeyOnce = 101,
    WkdRegPersist_RunServices = 102,
    WkdRegPersist_RunServicesOnce = 103,
    WkdRegPersist_PoliciesRun = 104,
    WkdRegPersist_ExplorerRun = 105,

    /* Services (200-204) */
    WkdRegPersist_Service = 200,
    WkdRegPersist_KernelDriver = 201,
    WkdRegPersist_FileSystemDriver = 202,
    WkdRegPersist_ServiceDLL = 203,
    WkdRegPersist_ServiceFailure = 204,

    /* Scheduled Tasks (300-302) */
    WkdRegPersist_ScheduledTask = 300,
    WkdRegPersist_ScheduledTaskXML = 301,
    WkdRegPersist_AtJob = 302,

    /* Startup Folders (400-402) */
    WkdRegPersist_StartupFolderUser = 400,
    WkdRegPersist_StartupFolderAllUsers = 401,
    WkdRegPersist_StartupFolderCommon = 402,

    /* Winlogon (500-505) */
    WkdRegPersist_WinlogonShell = 500,
    WkdRegPersist_WinlogonUserinit = 501,
    WkdRegPersist_WinlogonNotify = 502,
    WkdRegPersist_WinlogonTaskman = 503,
    WkdRegPersist_WinlogonSystem = 504,
    WkdRegPersist_WinlogonVMApplet = 505,

    /* Image File Execution Options (600-602) */
    WkdRegPersist_IFeoDebugger = 600,
    WkdRegPersist_IFeoGlobalFlag = 601,
    WkdRegPersist_SilentProcessExit = 602,

    /* DLL Injection (700-706) */
    WkdRegPersist_AppInitDlls = 700,
    WkdRegPersist_AppCertDlls = 701,
    WkdRegPersist_LoadAppInit = 702,
    WkdRegPersist_PrintMonitors = 703,
    WkdRegPersist_LsaAuthentication = 704,
    WkdRegPersist_LsaNotification = 705,
    WkdRegPersist_LsaSecurity = 706,

    /* Boot/Session (800-803) */
    WkdRegPersist_BootExecute = 800,
    WkdRegPersist_SetupExecute = 801,
    WkdRegPersist_KnownDlls = 802,
    WkdRegPersist_SessionManager = 803,

    /* Explorer/Shell (900-908) */
    WkdRegPersist_ShellServiceObjects = 900,
    WkdRegPersist_ShellServiceObjectDelayLoad = 901,
    WkdRegPersist_ShellIconOverlay = 902,
    WkdRegPersist_ShellExtensions = 903,
    WkdRegPersist_ContextMenuHandlers = 904,
    WkdRegPersist_PropertySheetHandlers = 905,
    WkdRegPersist_ColumnHandlers = 906,
    WkdRegPersist_CopyHookHandlers = 907,
    WkdRegPersist_DragDropHandlers = 908,

    /* COM Hijacking (1000-1004) */
    WkdRegPersist_ClsidInprocServer = 1000,
    WkdRegPersist_ClsidLocalServer = 1001,
    WkdRegPersist_ClsidTreatAs = 1002,
    WkdRegPersist_TypelibHijack = 1003,
    WkdRegPersist_ProgIdHijack = 1004,

    /* Browser (1100-1102) */
    WkdRegPersist_BrowserHelperObject = 1100,
    WkdRegPersist_BrowserExtensions = 1101,
    WkdRegPersist_UrlSearchHook = 1102,

    /* Office (1200-1202) */
    WkdRegPersist_OfficeAddins = 1200,
    WkdRegPersist_OfficeStartup = 1201,
    WkdRegPersist_OfficeVba = 1202,

    /* WMI (1300-1302) */
    WkdRegPersist_WmiEventFilter = 1300,
    WkdRegPersist_WmiEventConsumer = 1301,
    WkdRegPersist_WmiFilterToConsumer = 1302,

    /* Active Setup (1400) */
    WkdRegPersist_ActiveSetup = 1400,

    /* Other (1500-1514) */
    WkdRegPersist_LogonScript = 1500,
    WkdRegPersist_LogoffScript = 1501,
    WkdRegPersist_StartupScript = 1502,
    WkdRegPersist_ShutdownScript = 1503,
    WkdRegPersist_TerminalServices = 1504,
    WkdRegPersist_NetshHelper = 1505,
    WkdRegPersist_ProtocolHandler = 1506,
    WkdRegPersist_FontDriver = 1507,
    WkdRegPersist_Screensaver = 1508,
    WkdRegPersist_SecurityProviders = 1509,
    WkdRegPersist_WinsockProviders = 1510,
    WkdRegPersist_SidHijack = 1511,
    WkdRegPersist_PowerShellProfile = 1512,
    WkdRegPersist_AmsiProvider = 1513,
    WkdRegPersist_TimeProvider = 1514
} WKD_REG_PERSISTENCE_TYPE;

/* ==================================================
 * PersistenceRiskLevel — 持久化风险等级
 * ================================================== */
typedef enum _WKD_REG_RISK_LEVEL {
    WkdRegRisk_Safe = 0,
    WkdRegRisk_Low = 1,
    WkdRegRisk_Unknown = 2,
    WkdRegRisk_Suspicious = 3,
    WkdRegRisk_Malicious = 4
} WKD_REG_RISK_LEVEL;

/* ==================================================
 * EntryStatus — 持久化条目状态
 * ================================================== */
typedef enum _WKD_REG_ENTRY_STATUS {
    WkdRegEntry_Active = 0,
    WkdRegEntry_Disabled = 1,
    WkdRegEntry_Orphaned = 2,       /* 目标文件缺失 */
    WkdRegEntry_Corrupted = 3,      /* 数据无效 */
    WkdRegEntry_Hidden = 4          /* 使用隐藏技术 */
} WKD_REG_ENTRY_STATUS;

/* ==================================================
 * SignatureStatus — 二进制签名状态
 * ================================================== */
typedef enum _WKD_REG_SIGNATURE_STATUS {
    WkdRegSig_Unknown = 0,
    WkdRegSig_NotSigned = 1,
    WkdRegSig_SignedValid = 2,
    WkdRegSig_SignedExpired = 3,
    WkdRegSig_SignedRevoked = 4,
    WkdRegSig_SignedUntrusted = 5,
    WkdRegSig_SignedInvalid = 6,
    WkdRegSig_SignedCatalog = 7     /* 目录签名 */
} WKD_REG_SIGNATURE_STATUS;

/* ==================================================
 * ScanScope — 持久化扫描范围
 * ================================================== */
typedef enum _WKD_REG_SCAN_SCOPE {
    WkdRegScope_Critical = 0,       /* 关键位置（约 25） */
    WkdRegScope_Standard = 1,       /* 常见位置（约 50） */
    WkdRegScope_Extended = 2,       /* 全部已知位置（约 100） */
    WkdRegScope_Full = 3,           /* 含罕见/非常规位置 */
    WkdRegScope_Custom = 4          /* 自定义 */
} WKD_REG_SCAN_SCOPE;

/* ==================================================
 * 通用时间语义（迁移 std::chrono → FILETIME 语义）
 * 各结构统一使用 ULONGLONG（100ns 间隔，1601-01-01 纪元），
 * 与 Windows FILETIME 兼容，避免引入 chrono 设施。
 * ================================================== */
typedef ULONGLONG WKD_REG_TIMESTAMP;

/* ==================================================
 * 通用统计快照基元（各引擎在尾部追加自己的计数段，
 * 头部字段保持一致，便于统一导出/清零）
 * ================================================== */
typedef struct _WKD_REG_STATS_COMMON {
    volatile LONG  TotalScans;          /* 扫描/周期运行次数 */
    volatile LONG  TotalEntries;        /* 处理条目数（注明各自含义） */
    volatile LONG  Suspicious;          /* 可疑计数 */
    volatile LONG  Malicious;           /* 恶意计数 */
    volatile LONG  AlertsGenerated;     /* 告警总数 */
    volatile LONG  CallbackErrors;      /* 回调异常计数 */
} WKD_REG_STATS_COMMON, * PWKD_REG_STATS_COMMON;

/* ==================================================
 * ═══ PersistenceDetector (The Watchman) ═══
 * ASEP 持久化检测引擎
 *
 * 虚标剔除（审计文档）：
 *  - HashStore/ThreatIntel 未接线 → 不迁移
 *  - WhiteListStore → WkD Common\Exempts 门面
 *  - 并行扫描（实为串行）→ 保留串行语义
 *
 * 依赖（WkD 底座）：
 *  - Common\BCrypUtils（SHA256）    - Common\FileUtils（文件类型/熵）
 *  - IOC\Signature\SignatureVerifier（PE 签名）
 * ================================================== */

/* --- 引擎私有常量 --- */
#define WKD_PD_MAX_CMD_BUFFER          2048    /* rawCommand/命令缓冲 */
#define WKD_PD_MAX_SIGNER_CHARS        128     /* 签名者/颁发者 */
#define WKD_PD_MAX_FILE_TYPE_CHARS     32      /* 文件类型描述 */
#define WKD_PD_MAX_PUBLISHER_CHARS     128
#define WKD_PD_MAX_MALWARE_FAMILY_CHARS 64

#define WKD_PD_MAX_ADDITIONAL_TARGETS  4       /* 复杂命令拆解出的目标数量 */
#define WKD_PD_MAX_RISK_FACTORS        8       /* 风险因素文本 */
#define WKD_PD_MAX_DETECTION_NAMES     4       /* 检测名 */
#define WKD_PD_MAX_INDICATORS          8       /* 实时分析指示 */
#define WKD_PD_MAX_TASK_ACTIONS        4       /* 计划任务动作 */
#define WKD_PD_MAX_TASK_TRIGGERS       4       /* 计划任务触发器 */
#define WKD_PD_MAX_CALLBACKS           16      /* 每类回调注册上限 */
#define WKD_PD_MAX_SCAN_ENTRIES        8192    /* 单次扫描条目上限（动态缓冲） */

/* --- TargetBinary — 解析后的目标二进制信息 --- */
typedef struct _WKD_PERSISTENCE_TARGET {
    WCHAR  Path[WKD_REG_MAX_PATH_CHARS];        /* 解析后完整路径 */
    WCHAR  OriginalPath[WKD_REG_MAX_PATH_CHARS];/* 解析前的原始命令段 */
    WCHAR  Arguments[WKD_PD_MAX_CMD_BUFFER];    /* 提取的参数 */
    WCHAR  WorkingDirectory[WKD_REG_MAX_PATH_CHARS];

    /* 文件信息 */
    BOOLEAN            Exists;
    ULONGLONG          FileSize;
    WKD_REG_TIMESTAMP  CreatedTime;
    WKD_REG_TIMESTAMP  ModifiedTime;

    /* 哈希 */
    UCHAR              Sha256[32];
    CHAR               Sha256Hex[WKD_REG_MAX_HASH_HEX_CHARS];

    /* 签名 */
    WKD_REG_SIGNATURE_STATUS SignatureStatus;
    WCHAR              SignerName[WKD_PD_MAX_SIGNER_CHARS];
    WCHAR              IssuerName[WKD_PD_MAX_SIGNER_CHARS];
    WKD_REG_TIMESTAMP  SignatureTime;
    BOOLEAN            IsMicrosoftSigned;
    BOOLEAN            IsTrusted;

    /* 类型 */
    BOOLEAN            IsExecutable;
    BOOLEAN            IsDll;
    BOOLEAN            IsScript;
    CHAR               FileType[WKD_PD_MAX_FILE_TYPE_CHARS];

    /* 分析 */
    BOOLEAN            IsHidden;               /* 隐藏属性 */
    BOOLEAN            HasAds;                 /* 备用数据流 */
    BOOLEAN            InSystemPath;
    BOOLEAN            InTempPath;
    BOOLEAN            IsPacked;               /* 高熵判定 */
    DOUBLE             Entropy;
    WCHAR              Description[WKD_REG_MAX_DESC_CHARS];  /* 语境描述（如 LOLBin 解析结果） */
} WKD_PERSISTENCE_TARGET, * PWKD_PERSISTENCE_TARGET, * PCWKD_PERSISTENCE_TARGET;

/* --- PersistenceEntry — 完整持久化条目 --- */
typedef struct _WKD_PERSISTENCE_ENTRY {
    /* 标识 */
    ULONGLONG              EntryId;
    WKD_REG_PERSISTENCE_TYPE Type;
    WKD_REG_ENTRY_STATUS   Status;

    /* 位置 */
    WCHAR                  Location[WKD_REG_MAX_PATH_CHARS];  /* 注册表键或文件夹路径 */
    WCHAR                  EntryName[WKD_REG_MAX_NAME_CHARS]; /* 值名或文件名 */
    WCHAR                  RawCommand[WKD_PD_MAX_CMD_BUFFER]; /* 原始数据 */

    /* 解析目标 */
    WKD_PERSISTENCE_TARGET Target;
    WKD_PERSISTENCE_TARGET AdditionalTargets[WKD_PD_MAX_ADDITIONAL_TARGETS];
    ULONG                  AdditionalTargetCount;

    /* 上下文 */
    WCHAR                  Description[WKD_REG_MAX_DESC_CHARS];
    WCHAR                  Publisher[WKD_PD_MAX_PUBLISHER_CHARS];
    BOOLEAN                IsUserEntry;        /* HKCU vs HKLM */
    WCHAR                  UserSid[WKD_REG_MAX_USER_SID_CHARS];
    WCHAR                  UserName[WKD_REG_MAX_NAME_CHARS];

    /* 风险评估 */
    WKD_REG_RISK_LEVEL     Risk;
    UCHAR                  RiskScore;          /* 0-100 */
    CHAR                   RiskFactors[WKD_PD_MAX_RISK_FACTORS][64];
    ULONG                  RiskFactorCount;

    /* 元数据 */
    WKD_REG_TIMESTAMP      CreatedTime;
    WKD_REG_TIMESTAMP      ModifiedTime;
    WKD_REG_TIMESTAMP      LastScanned;

    /* 声誉 */
    BOOLEAN                IsKnownGood;
    BOOLEAN                IsKnownBad;
    CHAR                   MalwareFamily[WKD_PD_MAX_MALWARE_FAMILY_CHARS];
    CHAR                   DetectionNames[WKD_PD_MAX_DETECTION_NAMES][64];
    ULONG                  DetectionNameCount;

    /* MITRE 映射 */
    CHAR                   MitreTechnique[32];
    CHAR                   MitreSubTechnique[32];
} WKD_PERSISTENCE_ENTRY, * PWKD_PERSISTENCE_ENTRY, * PCWKD_PERSISTENCE_ENTRY;

/* --- ServiceEntry — Windows 服务持久化 --- */
typedef struct _WKD_SERVICE_ENTRY {
    WCHAR  ServiceName[64];
    WCHAR  DisplayName[WKD_REG_MAX_NAME_CHARS];
    WCHAR  Description[WKD_REG_MAX_DESC_CHARS];
    WCHAR  ImagePath[WKD_REG_MAX_PATH_CHARS];
    WCHAR  ObjectName[WKD_REG_MAX_NAME_CHARS];  /* 运行账户 */

    /* 服务配置 */
    ULONG  StartType;                           /* SERVICE_* 原值 */
    ULONG  ServiceType;
    ULONG  ErrorControl;

    /* 状态 */
    ULONG  CurrentState;
    ULONG  ProcessId;

    /* 安全描述符（文本形式，供审计） */
    WCHAR  SecurityDescriptor[WKD_REG_MAX_PATH_CHARS];
} WKD_SERVICE_ENTRY, * PWKD_SERVICE_ENTRY, * PCWKD_SERVICE_ENTRY;

/* --- 计划任务动作/触发器 --- */
typedef struct _WKD_TASK_ACTION {
    WCHAR  Type[32];                            /* Exec/ComHandler/... */
    WCHAR  Path[WKD_REG_MAX_PATH_CHARS];
    WCHAR  Arguments[WKD_PD_MAX_CMD_BUFFER];
    WCHAR  WorkingDirectory[WKD_REG_MAX_PATH_CHARS];
} WKD_TASK_ACTION, * PWKD_TASK_ACTION, * PCWKD_TASK_ACTION;

typedef struct _WKD_TASK_TRIGGER {
    WCHAR  Type[32];                            /* Boot/Logon/Time/Event/... */
    WCHAR  Details[WKD_REG_MAX_PATH_CHARS];
    BOOLEAN Enabled;
} WKD_TASK_TRIGGER, * PWKD_TASK_TRIGGER, * PCWKD_TASK_TRIGGER;

typedef struct _WKD_SCHEDULED_TASK_ENTRY {
    WCHAR  TaskName[WKD_REG_MAX_NAME_CHARS];
    WCHAR  TaskPath[WKD_REG_MAX_PATH_CHARS];
    WCHAR  Description[WKD_REG_MAX_DESC_CHARS];

    WKD_TASK_ACTION   Actions[WKD_PD_MAX_TASK_ACTIONS];
    ULONG             ActionCount;
    WKD_TASK_TRIGGER  Triggers[WKD_PD_MAX_TASK_TRIGGERS];
    ULONG             TriggerCount;

    /* 安全 */
    WCHAR  UserId[WKD_REG_MAX_NAME_CHARS];
    WCHAR  SecurityDescriptor[WKD_REG_MAX_PATH_CHARS];
    BOOLEAN RunAsHighest;
    BOOLEAN RunOnlyIfLoggedOn;

    /* 状态 */
    BOOLEAN           Enabled;
    WKD_REG_TIMESTAMP LastRunTime;
    WKD_REG_TIMESTAMP NextRunTime;
    ULONG             LastResult;
} WKD_SCHEDULED_TASK_ENTRY, * PWKD_SCHEDULED_TASK_ENTRY, * PCWKD_SCHEDULED_TASK_ENTRY;

/* --- WMISubscription — WMI 事件订阅 --- */
typedef struct _WKD_WMI_SUBSCRIPTION {
    WCHAR  FilterName[WKD_REG_MAX_NAME_CHARS];
    WCHAR  FilterQuery[WKD_REG_MAX_PATH_CHARS];
    WCHAR  FilterLanguage[32];

    WCHAR  ConsumerName[WKD_REG_MAX_NAME_CHARS];
    WCHAR  ConsumerType[32];                    /* CommandLine/Script/ActiveScript */
    WCHAR  ConsumerCommand[WKD_PD_MAX_CMD_BUFFER];

    WCHAR  BindingName[WKD_REG_MAX_NAME_CHARS];
} WKD_WMI_SUBSCRIPTION, * PWKD_WMI_SUBSCRIPTION, * PCWKD_WMI_SUBSCRIPTION;

/* --- ScanResult — 扫描结果（条目缓冲由引擎内部管理，下次扫描前有效） --- */
typedef struct _WKD_SCAN_RESULT {
    /* 计时 */
    WKD_REG_TIMESTAMP StartTime;
    WKD_REG_TIMESTAMP EndTime;
    ULONG             DurationMs;

    /* 范围 */
    WKD_REG_SCAN_SCOPE Scope;
    ULONG             LocationsScanned;
    ULONG             ErrorsEncountered;

    /* 条目（内部缓冲，下次扫描前有效） */
    PWKD_PERSISTENCE_ENTRY Entries;
    ULONG             EntryCount;

    /* 汇总 */
    ULONG             TotalEntries;
    ULONG             SafeEntries;
    ULONG             SuspiciousEntries;
    ULONG             MaliciousEntries;
    ULONG             UnknownEntries;
    ULONG             OrphanedEntries;
} WKD_SCAN_RESULT, * PWKD_SCAN_RESULT, * PCWKD_SCAN_RESULT;

/* --- RealTimeAnalysis — 实时分析结果 --- */
typedef struct _WKD_REALTIME_ANALYSIS {
    WKD_REG_RISK_LEVEL       Risk;
    UCHAR                    RiskScore;
    WKD_REG_PERSISTENCE_TYPE DetectedType;
    WCHAR                    ResolvedTarget[WKD_REG_MAX_PATH_CHARS];

    /* 标志 */
    BOOLEAN                  IsPersistenceAttempt;
    BOOLEAN                  IsKnownBad;
    BOOLEAN                  IsSuspiciousLocation;
    BOOLEAN                  IsSuspiciousTarget;
    BOOLEAN                  IsUnsigned;

    /* 证据 */
    CHAR                     Indicators[WKD_PD_MAX_INDICATORS][WKD_REG_MAX_DESC_CHARS];
    ULONG                    IndicatorCount;
    CHAR                     Recommendation[WKD_REG_MAX_DESC_CHARS];
} WKD_REALTIME_ANALYSIS, * PWKD_REALTIME_ANALYSIS, * PCWKD_REALTIME_ANALYSIS;

/* --- PersistenceAlert — 持久化告警 --- */
typedef struct _WKD_PERSISTENCE_ALERT {
    /* 标识 */
    ULONGLONG          AlertId;
    WKD_REG_TIMESTAMP  Timestamp;

    /* 检测 */
    WKD_REG_PERSISTENCE_TYPE Type;
    WKD_REG_RISK_LEVEL       Risk;
    CHAR                     Description[WKD_REG_MAX_DESC_CHARS];

    /* 条目 */
    WCHAR              Location[WKD_REG_MAX_PATH_CHARS];
    WCHAR              EntryName[WKD_REG_MAX_NAME_CHARS];
    WCHAR              Command[WKD_PD_MAX_CMD_BUFFER];
    WCHAR              TargetPath[WKD_REG_MAX_PATH_CHARS];

    /* 进程（实时分析来源） */
    ULONG              ProcessId;
    WCHAR              ProcessPath[WKD_REG_MAX_PATH_CHARS];
    CHAR               UserName[WKD_REG_MAX_NAME_CHARS];

    /* MITRE */
    CHAR               MitreTechnique[32];
    CHAR               MitreSubTechnique[32];

    /* 分析详情快照 */
    WKD_REALTIME_ANALYSIS Analysis;
} WKD_PERSISTENCE_ALERT, * PWKD_PERSISTENCE_ALERT, * PCWKD_PERSISTENCE_ALERT;

/* --- Config — 配置 --- */
typedef struct _WKD_PERSISTENCE_CONFIG {
    /* 扫描 */
    WKD_REG_SCAN_SCOPE  DefaultScope;
    ULONG               MaxScanThreads;         /* 保留字段（实现为串行） */
    ULONG               ScanTimeoutMs;

    /* 分析 */
    BOOLEAN             ResolveTargets;
    BOOLEAN             VerifySignatures;
    BOOLEAN             CheckHashes;
    BOOLEAN             CheckReputation;
    BOOLEAN             DetectHidden;

    /* 实时 */
    BOOLEAN             EnableRealTimeAnalysis;
    BOOLEAN             AlertOnSuspicious;
    BOOLEAN             AlertOnUnknown;

    /* 白名单（配置级白名单，WkD Exempts 可注入） */
    WCHAR               WhitelistedPaths[8][WKD_REG_MAX_PATH_CHARS];
    ULONG               WhitelistedPathCount;
    CHAR                WhitelistedHashes[8][WKD_REG_MAX_HASH_HEX_CHARS];
    ULONG               WhitelistedHashCount;
    WCHAR               WhitelistedSigners[8][WKD_PD_MAX_SIGNER_CHARS];
    ULONG               WhitelistedSignerCount;

    /* 性能 */
    BOOLEAN             UseCache;
    ULONG               CacheTtlSeconds;

    /* 日志 */
    BOOLEAN             LogAllEntries;
    BOOLEAN             LogSuspiciousOnly;
} WKD_PERSISTENCE_CONFIG, * PWKD_PERSISTENCE_CONFIG, * PCWKD_PERSISTENCE_CONFIG;

/* --- Statistics — 运行时统计（原子计数） --- */
typedef struct _WKD_PERSISTENCE_STATS {
    volatile LONG64  TotalScans;
    volatile LONG64  EntriesScanned;
    volatile LONG64  LocationsScanned;

    volatile LONG64  SafeEntriesFound;
    volatile LONG64  SuspiciousEntriesFound;
    volatile LONG64  MaliciousEntriesFound;

    volatile LONG64  RealTimeAnalyses;
    volatile LONG64  PersistenceAttempts;
    volatile LONG64  BlockedAttempts;

    volatile LONG64  SignaturesVerified;
    volatile LONG64  HashesChecked;
    volatile LONG64  CacheHits;

    volatile LONG64  AlertsGenerated;

    volatile LONG64  AvgScanTimeMs;
    volatile LONG64  AvgAnalysisTimeUs;
} WKD_PERSISTENCE_STATS, * PWKD_PERSISTENCE_STATS;

/* --- 回调类型 --- */
typedef
VOID
(*PFN_PD_PROGRESS_CALLBACK)(
    _In_ ULONG CurrentLocation,
    _In_ ULONG TotalLocations,
    _In_ PCWSTR CurrentPath,
    _In_opt_ PVOID Context
    );

typedef
VOID
(*PFN_PD_ENTRY_CALLBACK)(
    _In_ const WKD_PERSISTENCE_ENTRY* Entry,
    _In_opt_ PVOID Context
    );

typedef
VOID
(*PFN_PD_ALERT_CALLBACK)(
    _In_ const WKD_PERSISTENCE_ALERT* Alert,
    _In_opt_ PVOID Context
    );

/* --- PD 生命周期与工厂 --- */
NTSTATUS
PdInitialize(
    _In_opt_ const WKD_PERSISTENCE_CONFIG* Config   /* NULL = CreateDefault */
    );

VOID
PdShutdown(
    VOID
    );

BOOLEAN
PdIsInitialized(
    VOID
    );

VOID
PdCreateDefaultConfig(
    _Out_ PWKD_PERSISTENCE_CONFIG Config
    );

VOID
PdCreateQuickConfig(
    _Out_ PWKD_PERSISTENCE_CONFIG Config
    );

VOID
PdCreateThoroughConfig(
    _Out_ PWKD_PERSISTENCE_CONFIG Config
    );

VOID
PdCreateForensicConfig(
    _Out_ PWKD_PERSISTENCE_CONFIG Config
    );

/* --- PD 扫描（结果条目缓冲由引擎内部管理，下次扫描前有效） --- */
NTSTATUS
PdScanAll(
    _Out_ PWKD_SCAN_RESULT Result
    );

NTSTATUS
PdScanCritical(
    _Out_ PWKD_SCAN_RESULT Result
    );

NTSTATUS
PdScan(
    _In_ WKD_REG_SCAN_SCOPE Scope,
    _Out_ PWKD_SCAN_RESULT Result
    );

/* 释放 PdScan/PdScanAll/PdScanCritical 返回的条目缓冲（Entries 字段）。
 * 仅由调用方持有 Result 时调用；Result->Entries 置 NULL 以防二次释放。 */
VOID
PdFreeScanResult(
    _Inout_ PWKD_SCAN_RESULT Result
    );

/* 按目标路径过滤扫描（ScanPathImpl：全量 Extended 后按
 * 主目标/附加目标/原始命令包含匹配）。返回缓冲亦由 PdFreeScanResult 释放。 */
NTSTATUS
PdScanPath(
    _In_ PCWSTR TargetPath,
    _Out_ PWKD_SCAN_RESULT Result
    );

/* 按持久化类型过滤扫描（ScanType）。返回缓冲由 PdFreeScanResult 释放。 */
NTSTATUS
PdScanType(
    _In_ WKD_REG_PERSISTENCE_TYPE Type,
    _Out_ PWKD_SCAN_RESULT Result
    );

VOID
PdCancelScan(
    VOID
    );

/* --- PD 实时分析 --- */
WKD_REG_RISK_LEVEL
PdAnalyzeRealTime(
    _In_ PCWSTR KeyPath,
    _In_ PCWSTR ValueName,
    _In_opt_ const BYTE* Data,
    _In_ ULONG DataSize
    );

NTSTATUS
PdAnalyzeRealTimeFull(
    _In_ PCWSTR KeyPath,
    _In_ PCWSTR ValueName,
    _In_opt_ const BYTE* Data,
    _In_ ULONG DataSize,
    _Out_ PWKD_REALTIME_ANALYSIS Analysis
    );

WKD_REG_PERSISTENCE_TYPE
PdIsPersistenceLocation(
    _In_ PCWSTR KeyPath
    );

/* --- PD 目标解析 --- */
NTSTATUS
PdResolveTarget(
    _In_ PCWSTR Command,
    _Out_ PWKD_PERSISTENCE_TARGET Target
    );

NTSTATUS
PdResolveComplexCommand(
    _In_ PCWSTR Command,
    _In_ ULONG MaxTargets,
    _Out_ PWKD_PERSISTENCE_TARGET Targets,
    _Out_ PULONG TargetCount
    );

/* --- PD 专项枚举（服务/计划任务/WMI） --- */
NTSTATUS
PdScanServices(
    _In_ ULONG MaxEntries,
    _Out_ PWKD_SERVICE_ENTRY Entries,
    _Out_ PULONG EntryCount
    );

NTSTATUS
PdGetService(
    _In_ PCWSTR ServiceName,
    _Out_ PWKD_SERVICE_ENTRY Entry
    );

NTSTATUS
PdScanScheduledTasks(
    _In_ ULONG MaxEntries,
    _Out_ PWKD_SCHEDULED_TASK_ENTRY Entries,
    _Out_ PULONG EntryCount
    );

NTSTATUS
PdScanWmiSubscriptions(
    _In_ ULONG MaxEntries,
    _Out_ PWKD_WMI_SUBSCRIPTION Entries,
    _Out_ PULONG EntryCount
    );

/* --- PD 回调注册 --- */
ULONG
PdRegisterProgressCallback(
    _In_ PFN_PD_PROGRESS_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

ULONG
PdRegisterEntryCallback(
    _In_ PFN_PD_ENTRY_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

ULONG
PdRegisterAlertCallback(
    _In_ PFN_PD_ALERT_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

BOOLEAN
PdUnregisterCallback(
    _In_ ULONG CallbackId
    );

/* --- PD 统计与诊断 --- */
VOID
PdGetStatistics(
    _Out_ PWKD_PERSISTENCE_STATS Statistics
    );

VOID
PdResetStatistics(
    VOID
    );

BOOLEAN
PdPerformDiagnostics(
    VOID
    );

NTSTATUS
PdExportDiagnostics(
    _In_ PCWSTR OutputPath
    );

NTSTATUS
PdExportScanReport(
    _In_ const WKD_SCAN_RESULT* Result,
    _In_ PCWSTR OutputPath
    );

/* ==================================================
 * ═══ RegistryAnalyzer (The Deep Inspector) ═══
 * 深层注册表取证分析引擎
 *
 * 迁移来源：SS PhantomCore/Core/Registry/RegistryAnalyzer
 * (.cpp 3281 行 + .hpp 977 行, 2026-09-08 全量转写)
 *
 * 职责：
 *  - 五种分析模式：Quick/Standard/Deep/Forensic/RootkitHunting
 *  - 隐藏键检测（NULL 字节/控制字符注入，NtOpenKey 原生视图）
 *  - 交叉视图（Win32 vs NTAPI）Rootkit 差异检测
 *  - Hive 离线解析（regf 头校验 / 删除条目 hbin 空白区恢复）
 *  - 威胁指标加载与 IOC 匹配（通配符语义替代 std::wregex）
 *  - 自动运行项启发式（IFEO/AppInit/Winlogon/LSA/PendingFileRename/
 *    Run/RunOnce/ServiceDll 7 类，MITRE 映射）
 *  - 时间线构建 / 报告导出 / 熵分析
 *
 * 虚标剔除（对齐迁移审计）：
 *  - ThreatIntelManager → stub（哈希已计算，黑名单判定恒无）
 *  - RegistryMonitor/ProcessMonitor（DKOM 联动）→ stub 返回 FALSE
 *  - PatternStore(YARA) 被引用未使用 → 不迁移
 *  - std::wregex → 自实现 * / ? 通配符匹配（isRegex 语义降级）
 *  - RegistryUtils 封装 → 内联 Win32/NT API + 私有辅助
 *  - 线程池（threadCount，实为串行）→ 保留串行语义
 *
 * 依赖（WkD 底座）：
 *  - Common\BCrypUtils（IocScanner_ComputeBufferSha256）
 *  - ntdll（NtOpenKey/NtEnumerateKey/RtlInitUnicodeString）
 * ================================================== */

/* --- RA 常量 --- */
#define WKD_RA_VERSION_MAJOR                   3
#define WKD_RA_VERSION_MINOR                   0
#define WKD_RA_VERSION_PATCH                   0

#define WKD_RA_MAX_ANOMALIES                  100000
#define WKD_RA_MAX_KEY_NAME_LENGTH            255     /* 注册表键名上限 */
#define WKD_RA_MAX_VALUE_SIZE                 (1024 * 1024)   /* 值数据 1 MB */
#define WKD_RA_MAX_SCAN_DEPTH                 50
#define WKD_RA_MIN_BLOB_SIZE_FOR_ANALYSIS     256
#define WKD_RA_MAX_NTAPI_BUFFER_SIZE          (64 * 1024)     /* NtEnumerateKey 缓冲上限 */
#define WKD_RA_MAX_KEY_PATH_LENGTH            4096    /* 调用方路径防御上限 */
#define WKD_RA_MAX_INDICATOR_FILE_SIZE        (64 * 1024 * 1024)
#define WKD_RA_MAX_ANOMALY_RAW_DATA_BYTES     4096    /* 内存内原始数据保留上限 */

#define WKD_RA_HIGH_ENTROPY_THRESHOLD         7.0
#define WKD_RA_SUSPICIOUS_ENTROPY_THRESHOLD   6.0

#define WKD_RA_HIVE_SIGNATURE                 0x66676572u     /* "regf" */
#define WKD_RA_HBIN_SIGNATURE                 0x6E696268u     /* "hbin" */

#define WKD_RA_MAX_CALLBACKS                  16      /* 每类回调注册上限 */
#define WKD_RA_MAX_SCOPE_PATHS                16      /* AnalysisScope 指定路径上限 */
#define WKD_RA_MAX_LISTED_ENTRIES             64      /* 交叉视图/隐藏值清单上限 */
#define WKD_RA_MAX_ERRORS                     8       /* AnalysisResult 错误文本上限 */
#define WKD_RA_MAX_INDICATOR_LINE             4096    /* 指标行宽上限 */
#define WKD_RA_MAX_INDICATORS                 50000   /* 指标总数上限 */
#define WKD_RA_MAX_DECOMPONENTS               4096    /* REG_MULTI_SZ 组件上限 */
#define WKD_RA_MAX_HBINS                      65536   /* hive hbin 段上限 */
#define WKD_RA_MAX_RECOVERED_ENTRIES          100000  /* 单 hive 恢复上限 */
#define WKD_RA_MAX_INDICATOR_CHARS            256     /* 指标模式字段宽 */
#define WKD_RA_MAX_ENTRY_NAME_CHARS           1024    /* 恢复键名上限 */

/* --- RA 枚举 --- */
typedef enum _WKD_RA_ANALYSIS_MODE {
    WkdRaMode_Quick = 0,        /* 快速 API 扫描 */
    WkdRaMode_Standard = 1,     /* API + 基础隐藏检测 */
    WkdRaMode_Deep = 2,         /* 全量取证分析 */
    WkdRaMode_Forensic = 3,     /* 离线 hive 分析 */
    WkdRaMode_RootkitHunting = 4/* 交叉视图 Rootkit 检测 */
} WKD_RA_ANALYSIS_MODE;

typedef enum _WKD_RA_HIVE_TYPE {
    WkdRaHive_Unknown = 0,
    WkdRaHive_Sam = 1,
    WkdRaHive_Security = 2,
    WkdRaHive_Software = 3,
    WkdRaHive_System = 4,
    WkdRaHive_Default = 5,
    WkdRaHive_Ntuser = 6,
    WkdRaHive_Usrclass = 7,
    WkdRaHive_Amcache = 8,
    WkdRaHive_Bcd = 9,
    WkdRaHive_Components = 10
} WKD_RA_HIVE_TYPE;

typedef enum _WKD_RA_SEVERITY {
    WkdRaSev_Info = 0,
    WkdRaSev_Low = 1,
    WkdRaSev_Medium = 2,
    WkdRaSev_High = 3,
    WkdRaSev_Critical = 4
} WKD_RA_SEVERITY;

typedef enum _WKD_RA_ANOMALY_TYPE {
    WkdRaAnomaly_None = 0,

    /* 隐藏键技术 */
    WkdRaAnomaly_NullByteInjection = 1,
    WkdRaAnomaly_UnicodeControlChar = 2,
    WkdRaAnomaly_ExtendedAscii = 3,
    WkdRaAnomaly_OverlongName = 4,
    WkdRaAnomaly_ZeroLengthName = 5,

    /* 结构异常 */
    WkdRaAnomaly_InvalidStructure = 10,
    WkdRaAnomaly_CorruptedHeader = 11,
    WkdRaAnomaly_InvalidOffset = 12,
    WkdRaAnomaly_OrphanedCell = 13,
    WkdRaAnomaly_DeletedNotCleared = 14,

    /* 值异常 */
    WkdRaAnomaly_UnusualValueType = 20,
    WkdRaAnomaly_OversizedValue = 21,
    WkdRaAnomaly_EmbeddedExecutable = 22,
    WkdRaAnomaly_EncodedData = 23,
    WkdRaAnomaly_HighEntropy = 24,
    WkdRaAnomaly_SuspiciousPath = 25,

    /* API 差异 */
    WkdRaAnomaly_ApiHiddenKey = 30,
    WkdRaAnomaly_ApiHiddenValue = 31,
    WkdRaAnomaly_CallbackFiltered = 32,

    /* Rootkit 痕迹 */
    WkdRaAnomaly_DkomEvidence = 40,
    WkdRaAnomaly_HookedFunction = 41,
    WkdRaAnomaly_ModifiedCallback = 42,

    /* 威胁指标 */
    WkdRaAnomaly_KnownMalwareKey = 50,
    WkdRaAnomaly_KnownMalwareValue = 51,
    WkdRaAnomaly_SuspiciousAutorun = 52,
    WkdRaAnomaly_DataExfiltration = 53,

    /* 时间戳异常 */
    WkdRaAnomaly_FutureTimestamp = 60,
    WkdRaAnomaly_AncientTimestamp = 61,
    WkdRaAnomaly_TimestampMismatch = 62
} WKD_RA_ANOMALY_TYPE;

/* --- RA 核心结构 --- */

/* RegistryAnomaly — 检测到的注册表异常记录 */
typedef struct _WKD_RA_ANOMALY {
    /* 标识 */
    ULONGLONG          AnomalyId;
    WKD_REG_TIMESTAMP  DetectedTime;

    /* 位置 */
    WKD_RA_HIVE_TYPE   Hive;
    WCHAR              HivePath[WKD_REG_MAX_PATH_CHARS];
    WCHAR              KeyPath[WKD_REG_MAX_PATH_CHARS];
    WCHAR              ValueName[WKD_REG_MAX_NAME_CHARS];

    /* 详情 */
    WKD_RA_ANOMALY_TYPE Type;
    WKD_RA_SEVERITY     Severity;
    CHAR                Description[WKD_REG_MAX_DESC_CHARS];
    CHAR                Technique[16];              /* MITRE 技术编号 */

    /* 证据（截断保留） */
    BYTE                RawData[WKD_RA_MAX_ANOMALY_RAW_DATA_BYTES];
    ULONG               RawDataSize;
    BOOLEAN             RawDataTruncated;
    ULONG               OriginalSize;               /* 截断时记录原始长度 */

    /* 分析 */
    DOUBLE              Entropy;
    BOOLEAN             IsHidden;
    BOOLEAN             IsDeleted;
    BOOLEAN             IsMalicious;

    /* 威胁信息 */
    CHAR                MalwareFamily[WKD_PD_MAX_MALWARE_FAMILY_CHARS];
    CHAR                MatchedIocs[4][64];
    ULONG               MatchedIocCount;

    /* 哈希 */
    UCHAR               Sha256[32];
    CHAR                Sha256Hex[WKD_REG_MAX_HASH_HEX_CHARS];

    /* 取证偏移 */
    ULONG               KeyCellOffset;
    ULONG               ValueCellOffset;
} WKD_RA_ANOMALY, * PWKD_RA_ANOMALY, * PCWKD_RA_ANOMALY;

/* CrossViewResult — 交叉视图检测结果 */
typedef struct _WKD_RA_CROSS_VIEW_RESULT {
    WCHAR  KeyPath[WKD_REG_MAX_PATH_CHARS];

    /* API 枚举视图 */
    BOOLEAN FoundViaApi;
    WCHAR   ApiSubKeys[WKD_RA_MAX_LISTED_ENTRIES][WKD_REG_MAX_NAME_CHARS];
    ULONG   ApiSubKeyCount;
    WCHAR   ApiValues[WKD_RA_MAX_LISTED_ENTRIES][WKD_REG_MAX_NAME_CHARS];
    ULONG   ApiValueCount;

    /* 原生枚举视图 */
    BOOLEAN FoundViaRaw;
    WCHAR   RawSubKeys[WKD_RA_MAX_LISTED_ENTRIES][WKD_REG_MAX_NAME_CHARS];
    ULONG   RawSubKeyCount;
    WCHAR   RawValues[WKD_RA_MAX_LISTED_ENTRIES][WKD_REG_MAX_NAME_CHARS];
    ULONG   RawValueCount;

    /* 差异 */
    WCHAR   HiddenSubKeys[WKD_RA_MAX_LISTED_ENTRIES][WKD_REG_MAX_NAME_CHARS];
    ULONG   HiddenSubKeyCount;
    WCHAR   HiddenValues[WKD_RA_MAX_LISTED_ENTRIES][WKD_REG_MAX_NAME_CHARS];
    ULONG   HiddenValueCount;
    BOOLEAN HasDiscrepancy;
} WKD_RA_CROSS_VIEW_RESULT, * PWKD_RA_CROSS_VIEW_RESULT;

/* HiveHeader — 解析后的 hive 文件头 */
typedef struct _WKD_RA_HIVE_HEADER {
    ULONG              Signature;
    ULONG              Sequence1;
    ULONG              Sequence2;
    WKD_REG_TIMESTAMP  LastWritten;
    ULONG              MajorVersion;
    ULONG              MinorVersion;
    ULONG              HiveType;
    ULONG              Format;
    ULONG              RootCellOffset;
    ULONG              DataLength;
    WCHAR              HiveName[WKD_REG_MAX_NAME_CHARS];

    BOOLEAN            IsValid;
    BOOLEAN            IsCorrupted;
    BOOLEAN            IsDirty;
} WKD_RA_HIVE_HEADER, * PWKD_RA_HIVE_HEADER;

/* KeyCell — hive 内键单元信息 */
typedef struct _WKD_RA_KEY_CELL {
    ULONG  Offset;
    LONG   CellSize;
    BOOLEAN IsAllocated;
    BOOLEAN IsDeleted;

    WCHAR  KeyName[WKD_REG_MAX_PATH_CHARS];
    WCHAR  KeyNameRaw[WKD_REG_MAX_PATH_CHARS];      /* 含控制字符原样 */
    ULONG  SubKeyCount;
    ULONG  ValueCount;

    WKD_REG_TIMESTAMP LastWritten;

    ULONG  ParentOffset;
    ULONG  ClassNameOffset;
    ULONG  SecurityOffset;
    WCHAR  ClassName[WKD_REG_MAX_NAME_CHARS];

    BOOLEAN HasHiddenChars;
    BOOLEAN HasNullByte;
    BOOLEAN IsOrphaned;
} WKD_RA_KEY_CELL, * PWKD_RA_KEY_CELL;

/* DeletedEntry — 恢复的已删除条目 */
typedef struct _WKD_RA_DELETED_ENTRY {
    BOOLEAN   IsKey;
    WCHAR     Path[WKD_REG_MAX_PATH_CHARS];
    WCHAR     Name[WKD_REG_MAX_NAME_CHARS];

    ULONG     ValueType;
    BYTE*     Data;               /* 动态分配，由引擎管理 */
    ULONG     DataSize;

    WKD_REG_TIMESTAMP DeletedTime;
    ULONG     CellOffset;
    BOOLEAN   IsRecoverable;
    BOOLEAN   IsPartial;
} WKD_RA_DELETED_ENTRY, * PWKD_RA_DELETED_ENTRY;

/* AnalysisScope — 分析范围 */
typedef struct _WKD_RA_SCOPE {
    BOOLEAN  AnalyzeSam;
    BOOLEAN  AnalyzeSecurity;
    BOOLEAN  AnalyzeSoftware;
    BOOLEAN  AnalyzeSystem;
    BOOLEAN  AnalyzeNtuser;
    BOOLEAN  AnalyzeUsrclass;

    WCHAR    SpecificPaths[WKD_RA_MAX_SCOPE_PATHS][WKD_REG_MAX_PATH_CHARS];
    ULONG    SpecificPathCount;

    ULONG    MaxDepth;           /* 默认 WKD_RA_MAX_SCAN_DEPTH */

    BOOLEAN  IncludeDeleted;
    BOOLEAN  IncludeSlackSpace;
    WKD_REG_TIMESTAMP ModifiedAfter;
    WKD_REG_TIMESTAMP ModifiedBefore;
} WKD_RA_SCOPE, * PWKD_RA_SCOPE, * PCWKD_RA_SCOPE;

/* AnalysisResult — 分析结果 */
typedef struct _WKD_RA_RESULT {
    WKD_RA_ANALYSIS_MODE Mode;
    WKD_REG_TIMESTAMP    StartTime;
    WKD_REG_TIMESTAMP    EndTime;
    ULONG                DurationMs;

    /* 计数 */
    ULONGLONG KeysAnalyzed;
    ULONGLONG ValuesAnalyzed;
    ULONGLONG HivesAnalyzed;
    ULONGLONG BytesAnalyzed;

    /* 发现 */
    ULONGLONG AnomaliesFound;
    ULONGLONG HiddenKeysFound;
    ULONGLONG HiddenValuesFound;
    ULONGLONG DeletedRecovered;
    ULONGLONG MaliciousEntries;

    /* 严重度分布 */
    ULONG     CriticalAnomalies;
    ULONG     HighAnomalies;
    ULONG     MediumAnomalies;
    ULONG     LowAnomalies;

    /* 状态 */
    BOOLEAN   Completed;
    BOOLEAN   HadErrors;
    CHAR      Errors[WKD_RA_MAX_ERRORS][256];
    ULONG     ErrorCount;
} WKD_RA_RESULT, * PWKD_RA_RESULT, * PCWKD_RA_RESULT;

/* ThreatIndicator — 注册表威胁指标 */
typedef struct _WKD_RA_THREAT_INDICATOR {
    WCHAR  KeyPattern[WKD_RA_MAX_INDICATOR_CHARS];
    WCHAR  ValuePattern[WKD_RA_MAX_INDICATOR_CHARS];
    BYTE   DataPattern[256];
    ULONG  DataPatternSize;

    CHAR   ThreatName[WKD_REG_MAX_NAME_CHARS];
    CHAR   MalwareFamily[WKD_PD_MAX_MALWARE_FAMILY_CHARS];
    CHAR   MitreId[32];

    BOOLEAN IsRegex;            /* 原 regex 语义降级为通配符匹配 */
} WKD_RA_THREAT_INDICATOR, * PWKD_RA_THREAT_INDICATOR, * PCWKD_RA_THREAT_INDICATOR;

/* ForensicTimeline — 取证时间线条目 */
typedef struct _WKD_RA_TIMELINE {
    WKD_REG_TIMESTAMP Timestamp;
    CHAR              Action[32];       /* Created/Modified/Deleted */
    WKD_RA_HIVE_TYPE  Hive;
    WCHAR             KeyPath[WKD_REG_MAX_PATH_CHARS];
    WCHAR             ValueName[WKD_REG_MAX_NAME_CHARS];

    CHAR              Description[WKD_REG_MAX_DESC_CHARS];
    BOOLEAN           IsAnomaly;
} WKD_RA_TIMELINE, * PWKD_RA_TIMELINE, * PCWKD_RA_TIMELINE;

/* Config — 引擎配置 */
typedef struct _WKD_RA_CONFIG {
    WKD_RA_ANALYSIS_MODE DefaultMode;

    /* 分析选项 */
    BOOLEAN  DetectHiddenKeys;
    BOOLEAN  DetectHiddenValues;
    BOOLEAN  AnalyzeEntropy;
    BOOLEAN  DetectEmbeddedExecutables;

    /* Rootkit 检测 */
    BOOLEAN  EnableCrossView;
    BOOLEAN  DetectDkom;

    /* 取证 */
    BOOLEAN  RecoverDeleted;
    BOOLEAN  AnalyzeSlackSpace;
    BOOLEAN  BuildTimeline;

    /* 威胁狩猎 */
    BOOLEAN  MatchPatterns;
    BOOLEAN  MatchIocs;
    WCHAR    PatternDatabasePath[WKD_REG_MAX_PATH_CHARS];
    WCHAR    IocDatabasePath[WKD_REG_MAX_PATH_CHARS];

    /* 性能 */
    ULONG    MaxAnomalies;       /* 默认 WKD_RA_MAX_ANOMALIES */
    ULONG    ThreadCount;        /* 保留（实现为串行） */
} WKD_RA_CONFIG, * PWKD_RA_CONFIG, * PCWKD_RA_CONFIG;

/* Statistics — 运行时统计（原子计数） */
typedef struct _WKD_RA_STATS {
    volatile LONG64  TotalScans;
    volatile LONG64  KeysAnalyzed;
    volatile LONG64  ValuesAnalyzed;
    volatile LONG64  BytesAnalyzed;

    volatile LONG64  AnomaliesDetected;
    volatile LONG64  HiddenKeysFound;
    volatile LONG64  HiddenValuesFound;
    volatile LONG64  RootkitIndicators;
    volatile LONG64  MaliciousEntries;

    volatile LONG64  DeletedRecovered;
    volatile LONG64  PatternsMatched;
    volatile LONG64  IocsMatched;
} WKD_RA_STATS, * PWKD_RA_STATS;

/* --- RA 回调类型 --- */
typedef
VOID
(*PFN_RA_ANOMALY_CALLBACK)(
    _In_ const WKD_RA_ANOMALY* Anomaly,
    _In_opt_ PVOID Context
    );

typedef
VOID
(*PFN_RA_PROGRESS_CALLBACK)(
    _In_ PCWSTR CurrentPath,
    _In_ ULONG ProgressPercent,
    _In_opt_ PVOID Context
    );

typedef
VOID
(*PFN_RA_HIDDEN_CALLBACK)(
    _In_ PCWSTR Path,
    _In_ BOOLEAN IsKey,
    _In_opt_ PVOID Context
    );

/* --- RA 生命周期与工厂 --- */
NTSTATUS
RaInitialize(
    _In_opt_ const WKD_RA_CONFIG* Config    /* NULL = CreateDefault */
    );

VOID
RaShutdown(
    VOID
    );

BOOLEAN
RaIsInitialized(
    VOID
    );

VOID
RaCreateDefaultConfig(
    _Out_ PWKD_RA_CONFIG Config
    );

VOID
RaCreateForensicConfig(
    _Out_ PWKD_RA_CONFIG Config
    );

VOID
RaCreateRootkitHuntingConfig(
    _Out_ PWKD_RA_CONFIG Config
    );

VOID
RaCreateQuickConfig(
    _Out_ PWKD_RA_CONFIG Config
    );

/* --- RA 分析操作 --- */
NTSTATUS
RaAnalyze(
    _In_ PCWKD_RA_SCOPE Scope,
    _In_ WKD_RA_ANALYSIS_MODE Mode,
    _Out_ PWKD_RA_RESULT Result
    );

/* 单键分析。Anomalies 为调用方缓冲；容量不足返回 STATUS_BUFFER_TOO_SMALL
 * 且 AnomalyCount 返回所需数量（此时未填充）。 */
NTSTATUS
RegAnalyzeKey(
    _In_ PCWSTR KeyPath,
    _In_ BOOLEAN Recursive,
    _Out_opt_ PWKD_RA_ANOMALY Anomalies,
    _In_ ULONG MaxCount,
    _Out_ PULONG AnomalyCount
    );

NTSTATUS
RaAnalyzeHiveFile(
    _In_ PCWSTR HivePath,
    _Out_ PWKD_RA_RESULT Result
    );

NTSTATUS
RaAbortAnalysis(
    VOID
    );

BOOLEAN
RaIsAnalysisRunning(
    VOID
    );

/* --- RA 隐藏条目检测 --- */
NTSTATUS
RaDetectNullByteKeys(
    _In_ PCWSTR RootKey,
    _Out_opt_ PWCHAR* HiddenKeys,        /* 调用方缓冲（WCHAR[WKD_REG_MAX_PATH_CHARS]） */
    _In_ ULONG MaxCount,
    _Out_ PULONG KeyCount
    );

NTSTATUS
RaPerformCrossViewDetection(
    _In_ PCWSTR KeyPath,
    _Out_ PWKD_RA_CROSS_VIEW_RESULT Result
    );

NTSTATUS
RaGetHiddenKeys(
    _Out_opt_ PWCHAR* HiddenKeys,        /* 调用方缓冲 */
    _In_ ULONG MaxCount,
    _Out_ PULONG KeyCount
    );

/* --- RA 异常访问 --- */
NTSTATUS
RaGetAnomalies(
    _Out_opt_ PWKD_RA_ANOMALY Anomalies, /* 调用方缓冲 */
    _In_ ULONG MaxCount,
    _Out_ PULONG AnomalyCount
    );

NTSTATUS
RaGetAnomaliesByType(
    _In_ WKD_RA_ANOMALY_TYPE Type,
    _Out_opt_ PWKD_RA_ANOMALY Anomalies,
    _In_ ULONG MaxCount,
    _Out_ PULONG AnomalyCount
    );

NTSTATUS
RaGetAnomaliesBySeverity(
    _In_ WKD_RA_SEVERITY MinSeverity,
    _Out_opt_ PWKD_RA_ANOMALY Anomalies,
    _In_ ULONG MaxCount,
    _Out_ PULONG AnomalyCount
    );

NTSTATUS
RaGetAnomalyById(
    _In_ ULONGLONG AnomalyId,
    _Out_ PWKD_RA_ANOMALY Anomaly
    );

VOID
RaClearAnomalies(
    VOID
    );

/* --- RA 删除条目恢复 --- */
NTSTATUS
RaRecoverDeletedEntries(
    _In_ WKD_RA_HIVE_TYPE Hive,
    _Out_opt_ PWKD_RA_DELETED_ENTRY Entries,  /* 调用方缓冲 */
    _In_ ULONG MaxCount,
    _Out_ PULONG EntryCount
    );

NTSTATUS
RaRecoverFromHiveFile(
    _In_ PCWSTR HivePath,
    _Out_opt_ PWKD_RA_DELETED_ENTRY Entries,
    _In_ ULONG MaxCount,
    _Out_ PULONG EntryCount
    );

/* 释放 RaRecoverDeletedEntries/RaRecoverFromHiveFile 填充的条目动态 Data */
VOID
RaFreeRecoveredEntries(
    _In_ PWKD_RA_DELETED_ENTRY Entries,
    _In_ ULONG EntryCount
    );

/* --- RA Hive 解析 --- */
NTSTATUS
RaParseHiveHeader(
    _In_ PCWSTR HivePath,
    _Out_ PWKD_RA_HIVE_HEADER Header
    );

NTSTATUS
RaValidateHiveStructure(
    _In_ PCWSTR HivePath,
    _Out_ PBOOLEAN IsValid
    );

NTSTATUS
RaGetKeyCell(
    _In_ PCWSTR HivePath,
    _In_ ULONG Offset,
    _Out_ PWKD_RA_KEY_CELL Cell
    );

/* --- RA 威胁狩猎 --- */
NTSTATUS
RaLoadThreatIndicators(
    _In_ PCWSTR IndicatorsPath,
    _Out_ PULONG LoadedCount
    );

NTSTATUS
RaAddThreatIndicator(
    _In_ PCWKD_RA_THREAT_INDICATOR Indicator
    );

NTSTATUS
RaSearchIocs(
    _In_opt_ PCWSTR* Iocs,               /* 按需传多个 IOC 字面量 */
    _In_ ULONG IocCount,
    _Out_opt_ PWKD_RA_ANOMALY Matches,   /* 调用方缓冲 */
    _In_ ULONG MaxCount,
    _Out_ PULONG MatchCount
    );

/* --- RA 取证时间线 --- */
NTSTATUS
RaGetTimeline(
    _In_ WKD_REG_TIMESTAMP StartTime,
    _In_ WKD_REG_TIMESTAMP EndTime,
    _Out_opt_ PWKD_RA_TIMELINE Entries,  /* 调用方缓冲 */
    _In_ ULONG MaxCount,
    _Out_ PULONG EntryCount
    );

NTSTATUS
RaExportTimeline(
    _In_ PCWSTR OutputPath
    );

/* --- RA 熵分析 --- */
DOUBLE
RaCalculateEntropy(
    _In_ const BYTE* Data,
    _In_ SIZE_T Size
    );

NTSTATUS
RaGetHighEntropyValues(
    _In_ DOUBLE MinEntropy,
    _Out_opt_ PWKD_RA_ANOMALY Anomalies, /* 调用方缓冲 */
    _In_ ULONG MaxCount,
    _Out_ PULONG AnomalyCount
    );

/* --- RA 回调注册 --- */
ULONG
RaRegisterAnomalyCallback(
    _In_ PFN_RA_ANOMALY_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

ULONG
RaRegisterProgressCallback(
    _In_ PFN_RA_PROGRESS_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

ULONG
RaRegisterHiddenEntryCallback(
    _In_ PFN_RA_HIDDEN_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

BOOLEAN
RaUnregisterCallback(
    _In_ ULONG CallbackId
    );

/* --- RA 统计与导出 --- */
VOID
RaGetStatistics(
    _Out_ PWKD_RA_STATS Statistics
    );

VOID
RaResetStatistics(
    VOID
    );

NTSTATUS
RaExportReport(
    _In_ PCWSTR OutputPath
    );

NTSTATUS
RaExportAnomalies(
    _In_ PCWSTR OutputPath
    );

NTSTATUS
RaExportHiddenEntries(
    _In_ PCWSTR OutputPath
    );

/* ==================================================
 * ═══ RegistryMonitor（RM）═══
 * 迁移来源: ShadowStrike RegistryMonitor.cpp (2731 行)
 *
 * 虚标剔除 (对齐迁移审计):
 *  - 内核过滤端口 (FilterConnection/MessageDispatcher) → stub,
 *    RmIsKernelConnected 恒 FALSE, 无 worker 线程/消息泵;
 *    事件唯一入口为 RmProcessEvent (调用方手动喂）
 *  - WhiteListStore / ThreatIntelLookup / ProcessUtils(enrich) → 剔除
 *  - useUserModeHooks → 保留字段但恒不生效 (WkD 无挂钩设施)
 * ================================================== */

/* --- RM 常量 --- */
#define WKD_RM_VERSION_MAJOR                  3
#define WKD_RM_VERSION_MINOR                  0
#define WKD_RM_VERSION_PATCH                  0

/* 注册表边界 (SS: 16384/16383/1MB; WkD 工程缓冲收紧, 超限事件按
 * "路径超限"策略处理并计数 droppedEvents, 语义见 RmProcessEvent) */
#define WKD_RM_MAX_KEY_PATH_CHARS             1024
#define WKD_RM_MAX_VALUE_NAME_CHARS           256
#define WKD_RM_MAX_VALUE_DATA_SIZE            (1024 * 1024)   /* 分析输入上限 1 MB */
#define WKD_RM_LARGE_VALUE_THRESHOLD          (64 * 1024)     /* 大值阈值 64 KB */
#define WKD_RM_MAX_EVENT_DATA_BYTES           4096            /* 事件内联数据缓冲 */

/* 检测阈值 */
#define WKD_RM_ENTROPY_THRESHOLD              7.0
#define WKD_RM_MIN_BLOB_SIZE                  256
#define WKD_RM_MAX_SCRIPT_LENGTH              32768

/* 性能/容量 */
#define WKD_RM_EVENT_QUEUE_SIZE               10000           /* 保留 (无队列实现) */
#define WKD_RM_CALLBACK_TIMEOUT_MS            5000
#define WKD_RM_MAX_WORKER_THREADS             32
#define WKD_RM_MAX_PROTECTED_KEYS             1000
#define WKD_RM_MAX_RULES                      10000
#define WKD_RM_MAX_HONEYPOT_KEYS              1024
#define WKD_RM_MAX_RECENT_EVENTS              1000
#define WKD_RM_MAX_CALLBACKS                  32
#define WKD_RM_MAX_RULE_PROCESS_IDS           32
#define WKD_RM_MAX_EXTRACTED_PATHS            16
#define WKD_RM_MAX_EXTRACTED_URLS             64
#define WKD_RM_MAX_RISK_FACTORS               16

/* 告警去重环 */
#define WKD_RM_DEDUP_RING_SIZE                256
#define WKD_RM_DEDUP_WINDOW_MS                2000

/* --- RM 枚举 --- */

/* RegistryOp — 注册表操作类型 */
typedef enum _WKD_RM_OP {
    WkdRmOp_Unknown = 0,
    WkdRmOp_CreateKey = 1,
    WkdRmOp_OpenKey = 2,
    WkdRmOp_DeleteKey = 3,
    WkdRmOp_RenameKey = 4,
    WkdRmOp_CloseKey = 5,
    WkdRmOp_SetValue = 10,
    WkdRmOp_DeleteValue = 11,
    WkdRmOp_QueryValue = 12,
    WkdRmOp_EnumerateValue = 13,
    WkdRmOp_LoadKey = 20,
    WkdRmOp_UnloadKey = 21,
    WkdRmOp_SaveKey = 22,
    WkdRmOp_RestoreKey = 23,
    WkdRmOp_ReplaceKey = 24,
    WkdRmOp_SetKeySecurity = 30,
    WkdRmOp_QueryKeySecurity = 31,
    WkdRmOp_CreateTransaction = 40,
    WkdRmOp_CommitTransaction = 41,
    WkdRmOp_RollbackTransaction = 42
} WKD_RM_OP;

/* RegistryValueType — 值类型 (对齐 REG_* 数值) */
typedef enum _WKD_RM_VALUE_TYPE {
    WkdRmVal_None = 0,
    WkdRmVal_Sz = 1,
    WkdRmVal_ExpandSz = 2,
    WkdRmVal_Binary = 3,
    WkdRmVal_Dword = 4,
    WkdRmVal_DwordBigEndian = 5,
    WkdRmVal_Link = 6,
    WkdRmVal_MultiSz = 7,
    WkdRmVal_ResourceList = 8,
    WkdRmVal_FullResourceDescriptor = 9,
    WkdRmVal_ResourceRequirementsList = 10,
    WkdRmVal_Qword = 11
} WKD_RM_VALUE_TYPE;

/* RegistryVerdict — 操作裁决 */
typedef enum _WKD_RM_VERDICT {
    WkdRmVerdict_Allow = 0,
    WkdRmVerdict_Block = 1,
    WkdRmVerdict_SilentDrop = 2,
    WkdRmVerdict_Redirect = 3,
    WkdRmVerdict_Delay = 4,
    WkdRmVerdict_Alert = 5
} WKD_RM_VERDICT;

/* KeyCategory — 键分类 */
typedef enum _WKD_RM_KEY_CATEGORY {
    WkdRmCategory_Unknown = 0,
    WkdRmCategory_Persistence = 1,
    WkdRmCategory_Security = 2,
    WkdRmCategory_Network = 3,
    WkdRmCategory_Shell = 4,
    WkdRmCategory_Com = 5,
    WkdRmCategory_System = 6,
    WkdRmCategory_Driver = 7,
    WkdRmCategory_Application = 8,
    WkdRmCategory_UserPreference = 9
} WKD_RM_KEY_CATEGORY;

/* RegistryThreatType — 威胁类型 (保持 SS 数值分段) */
typedef enum _WKD_RM_THREAT_TYPE {
    WkdRmThreat_None = 0,

    /* 持久化 (100s) */
    WkdRmThreat_PersistenceRunKey = 100,
    WkdRmThreat_PersistenceService = 101,
    WkdRmThreat_PersistenceWinlogon = 102,
    WkdRmThreat_PersistenceScheduledTask = 103,
    WkdRmThreat_PersistenceIfeo = 104,
    WkdRmThreat_PersistenceAppInit = 105,
    WkdRmThreat_PersistenceBootExecute = 106,

    /* 劫持 (200s) */
    WkdRmThreat_ComHijack = 200,
    WkdRmThreat_DllSearchOrder = 201,
    WkdRmThreat_ShellExtension = 202,
    WkdRmThreat_FileAssociation = 203,
    WkdRmThreat_ContextMenu = 204,

    /* 安全绕过 (300s) */
    WkdRmThreat_UacBypass = 300,
    WkdRmThreat_FirewallDisable = 301,
    WkdRmThreat_DefenderDisable = 302,
    WkdRmThreat_AmsiBypass = 303,
    WkdRmThreat_EtwBypass = 304,

    /* 无文件 (400s) */
    WkdRmThreat_FilelessPayload = 400,
    WkdRmThreat_EncodedScript = 401,
    WkdRmThreat_PowershellCommand = 402,

    /* 篡改 (500s) */
    WkdRmThreat_SelfDefenseTamper = 500,
    WkdRmThreat_LogTampering = 501,
    WkdRmThreat_AuditDisable = 502,

    /* 网络 (600s) */
    WkdRmThreat_ProxyModification = 600,
    WkdRmThreat_DnsModification = 601,
    WkdRmThreat_HostsRedirect = 602
} WKD_RM_THREAT_TYPE;

/* RiskLevel — 风险等级 */
typedef enum _WKD_RM_RISK {
    WkdRmRisk_Safe = 0,
    WkdRmRisk_Low = 1,
    WkdRmRisk_Medium = 2,
    WkdRmRisk_High = 3,
    WkdRmRisk_Critical = 4
} WKD_RM_RISK;

/* RuleAction — 规则动作 (裁决实际走 Verdict; Action 保留兼容) */
typedef enum _WKD_RM_RULE_ACTION {
    WkdRmAction_Allow = 0,
    WkdRmAction_Block = 1,
    WkdRmAction_Alert = 2,
    WkdRmAction_Log = 3,
    WkdRmAction_Redirect = 4
} WKD_RM_RULE_ACTION;

/* --- RM 结构 --- */

/* RegistryEvent — 注册表操作事件 */
typedef struct _WKD_RM_EVENT {
    ULONGLONG         EventId;
    WKD_REG_TIMESTAMP Timestamp;

    ULONG             Operation;          /* WKD_RM_OP */
    BOOLEAN           IsPreOperation;

    ULONG             ProcessId;
    ULONG             ThreadId;
    WCHAR             ProcessPath[WKD_REG_MAX_PATH_CHARS];
    CHAR              ProcessName[WKD_REG_MAX_NAME_CHARS];
    WCHAR             UserSid[WKD_REG_MAX_USER_SID_CHARS];
    CHAR              UserName[WKD_REG_MAX_NAME_CHARS];
    ULONG             SessionId;
    BOOLEAN           IsElevated;

    WCHAR             KeyPath[WKD_RM_MAX_KEY_PATH_CHARS];
    ULONG             KeyPathCharCount;       /* 键名实际字符数 (不含终止 NUL); 0 = 未知, 回退 wcslen */
    WCHAR             ValueName[WKD_RM_MAX_VALUE_NAME_CHARS];
    ULONG             ValueNameCharCount;     /* 值名实际字符数 (不含终止 NUL); 0 = 未知, 回退 wcslen */
    ULONG             ValueType;          /* WKD_RM_VALUE_TYPE */

    BYTE              ValueData[WKD_RM_MAX_EVENT_DATA_BYTES];
    ULONG             ValueDataSize;
    ULONG             ValueDataOriginalSize;  /* 截断前完整长度 */

    ULONGLONG         KeyHandle;
    ULONG             DesiredAccess;
    ULONG             CreateOptions;

    BOOLEAN           IsTransacted;
    ULONGLONG         TransactionId;
} WKD_RM_EVENT, * PWKD_RM_EVENT, * PCWKD_RM_EVENT;

/* ValueAnalysis — 值分析结果 */
typedef struct _WKD_RM_VALUE_ANALYSIS {
    SIZE_T            DataSize;
    ULONG             Type;               /* WKD_RM_VALUE_TYPE */

    DOUBLE            Entropy;
    BOOLEAN           IsHighEntropy;
    BOOLEAN           IsBinaryBlob;
    BOOLEAN           IsLargeValue;

    BOOLEAN           ContainsExecutable;
    BOOLEAN           ContainsScript;
    BOOLEAN           ContainsEncodedData;    /* 保留 (SS 未填充) */
    BOOLEAN           ContainsPath;
    BOOLEAN           ContainsUrl;

    WCHAR             ExtractedPaths[WKD_RM_MAX_EXTRACTED_PATHS][WKD_REG_MAX_PATH_CHARS];
    ULONG             ExtractedPathCount;
    CHAR              ExtractedUrls[WKD_RM_MAX_EXTRACTED_URLS][128];
    ULONG             ExtractedUrlCount;
    CHAR              DetectedEncoding[32];

    ULONG             Risk;               /* WKD_RM_RISK */
    CHAR              RiskFactors[WKD_RM_MAX_RISK_FACTORS][WKD_REG_MAX_DESC_CHARS];
    ULONG             RiskFactorCount;
} WKD_RM_VALUE_ANALYSIS, * PWKD_RM_VALUE_ANALYSIS, * PCWKD_RM_VALUE_ANALYSIS;

/* RegistryRule — 策略规则 */
typedef struct _WKD_RM_RULE {
    ULONGLONG         RuleId;
    CHAR              Name[256];
    CHAR              Description[1024];

    WCHAR             KeyPathPattern[WKD_RM_MAX_KEY_PATH_CHARS];
    WCHAR             ValueNamePattern[WKD_RM_MAX_VALUE_NAME_CHARS]; /* 保留 (SS 未参与匹配) */
    BOOLEAN           HasOperation;
    ULONG             Operation;          /* WKD_RM_OP */
    BOOLEAN           HasValueType;
    ULONG             ValueType;          /* WKD_RM_VALUE_TYPE */

    WCHAR             ProcessPathPattern[WKD_RM_MAX_KEY_PATH_CHARS];
    ULONG             ProcessIds[WKD_RM_MAX_RULE_PROCESS_IDS];
    ULONG             ProcessIdCount;
    WCHAR             UserSidPattern[WKD_REG_MAX_USER_SID_CHARS];

    ULONG             Action;             /* WKD_RM_RULE_ACTION */
    ULONG             Verdict;            /* WKD_RM_VERDICT */
    ULONG             Priority;

    BOOLEAN           Enabled;
    WKD_REG_TIMESTAMP CreatedAt;
    WKD_REG_TIMESTAMP ExpiresAt;
    BOOLEAN           IsPermanent;

    ULONGLONG         MatchCount;         /* 快照匹配计数 (不写回存储, 对齐 SS) */
} WKD_RM_RULE, * PWKD_RM_RULE, * PCWKD_RM_RULE;

/* ProtectedKey — 受保护键配置 */
typedef struct _WKD_RM_PROTECTED_KEY {
    WCHAR             KeyPath[WKD_RM_MAX_KEY_PATH_CHARS];
    BOOLEAN           IncludeSubkeys;
    BOOLEAN           ProtectValues;
    BOOLEAN           ProtectDelete;
    BOOLEAN           ProtectRename;
    BOOLEAN           ProtectSecurity;

    WCHAR             AllowedProcesses[8][WKD_REG_MAX_PATH_CHARS]; /* 保留 (不参与判定, 对齐 SS) */
    ULONG             AllowedProcessCount;
    WCHAR             AllowedUsers[8][WKD_REG_MAX_USER_SID_CHARS];
    ULONG             AllowedUserCount;

    BOOLEAN           IsSelfDefense;
} WKD_RM_PROTECTED_KEY, * PWKD_RM_PROTECTED_KEY, * PCWKD_RM_PROTECTED_KEY;

/* RegistryAlert — 威胁告警 */
typedef struct _WKD_RM_ALERT {
    ULONGLONG         AlertId;
    ULONGLONG         EventId;
    WKD_REG_TIMESTAMP Timestamp;

    ULONG             ThreatType;         /* WKD_RM_THREAT_TYPE */
    ULONG             Risk;               /* WKD_RM_RISK */
    CHAR              Description[WKD_REG_MAX_DESC_CHARS];

    ULONG             Operation;
    WCHAR             KeyPath[WKD_RM_MAX_KEY_PATH_CHARS];
    WCHAR             ValueName[WKD_RM_MAX_VALUE_NAME_CHARS];

    ULONG             ProcessId;
    WCHAR             ProcessPath[WKD_REG_MAX_PATH_CHARS];
    CHAR              UserName[WKD_REG_MAX_NAME_CHARS];

    ULONG             Verdict;            /* WKD_RM_VERDICT */
    BOOLEAN           WasBlocked;

    BYTE              DataSnapshot[WKD_RM_MAX_EVENT_DATA_BYTES];   /* 保留 (SS 未填充) */
    ULONG             DataSnapshotSize;
    WKD_RM_VALUE_ANALYSIS Analysis;                                /* 保留 (SS 未填充) */
    CHAR              Indicators[8][128];                          /* 保留 (SS 未填充) */
    ULONG             IndicatorCount;

    CHAR              MitreTechnique[32];
    CHAR              MitreSubTechnique[32];
} WKD_RM_ALERT, * PWKD_RM_ALERT, * PCWKD_RM_ALERT;

/* DeceptionConfig — 欺骗模式配置 (honeypotKeys 由 RmAddHoneypotKey
 * 独立维护, WkD 版不内嵌列表) */
typedef struct _WKD_RM_DECEPTION_CONFIG {
    BOOLEAN           Enabled;
    BOOLEAN           SilentDropEnabled;
    BOOLEAN           HoneypotEnabled;
    BOOLEAN           FakeSuccessEnabled;
} WKD_RM_DECEPTION_CONFIG, * PWKD_RM_DECEPTION_CONFIG, * PCWKD_RM_DECEPTION_CONFIG;

/* RegistryMonitorConfig — 引擎配置 */
typedef struct _WKD_RM_CONFIG {
    BOOLEAN           Enabled;
    BOOLEAN           UseKernelCallback;
    BOOLEAN           UseUserModeHooks;   /* 保留: WkD 无挂钩设施, 恒不生效 */

    BOOLEAN           MonitorCreateKey;
    BOOLEAN           MonitorSetValue;
    BOOLEAN           MonitorDeleteKey;
    BOOLEAN           MonitorDeleteValue;
    BOOLEAN           MonitorRename;
    BOOLEAN           MonitorLoadHive;
    BOOLEAN           MonitorSecurity;
    BOOLEAN           MonitorTransactions;

    BOOLEAN           AnalyzeValues;
    BOOLEAN           DetectFileless;
    BOOLEAN           DetectPersistence;
    BOOLEAN           DetectSecurityChanges;
    ULONG             LargeValueThreshold;

    BOOLEAN           SelfDefenseEnabled;
    BOOLEAN           ProtectWkDefenderKeys;

    WKD_RM_DECEPTION_CONFIG Deception;

    ULONG             EventQueueSize;     /* 保留 (无队列实现) */
    ULONG             WorkerThreads;      /* 记录用 (无内核消息泵, 不建线程) */
    ULONG             CallbackTimeoutMs;

    BOOLEAN           LogAllOperations;
    BOOLEAN           LogBlockedOnly;
    BOOLEAN           LogPersistenceKeys;
} WKD_RM_CONFIG, * PWKD_RM_CONFIG, * PCWKD_RM_CONFIG;

/* RegistryMonitorStatistics — 运行时统计 (原子计数) */
typedef struct _WKD_RM_STATS {
    volatile LONG64   TotalEvents;
    volatile LONG64   CreateKeyEvents;
    volatile LONG64   SetValueEvents;
    volatile LONG64   DeleteKeyEvents;
    volatile LONG64   DeleteValueEvents;
    volatile LONG64   RenameEvents;
    volatile LONG64   AllowedOperations;
    volatile LONG64   BlockedOperations;
    volatile LONG64   SilentDropped;
    volatile LONG64   PersistenceAttempts;
    volatile LONG64   FilelessPayloads;
    volatile LONG64   SecurityChanges;
    volatile LONG64   SelfDefenseBlocks;
    volatile LONG64   AlertsGenerated;
    volatile LONG64   CriticalAlerts;
    volatile LONG64   AvgCallbackTimeUs;
    volatile LONG64   MaxCallbackTimeUs;
    volatile LONG64   DroppedEvents;
} WKD_RM_STATS, * PWKD_RM_STATS;

/* --- RM 回调类型 (函数指针 + 上下文, 对齐 WkD 回调槽惯例) --- */
typedef
WKD_RM_VERDICT
(*PFN_RM_POLICY_CALLBACK)(
    _In_ PCWKD_RM_EVENT Event,
    _In_opt_ PVOID Context
    );

typedef
VOID
(*PFN_RM_ALERT_CALLBACK)(
    _In_ PCWKD_RM_ALERT Alert,
    _In_opt_ PVOID Context
    );

typedef
VOID
(*PFN_RM_EVENT_CALLBACK)(
    _In_ PCWKD_RM_EVENT Event,
    _In_ WKD_RM_VERDICT Verdict,
    _In_opt_ PVOID Context
    );

typedef
VOID
(*PFN_RM_VALUE_CALLBACK)(
    _In_ PCWKD_RM_EVENT Event,
    _In_ PCWKD_RM_VALUE_ANALYSIS Analysis,
    _In_opt_ PVOID Context
    );

/* --- RM 函数原型 --- */

/* RM 配置工厂 */
VOID
RmCreateDefaultConfig(
    _Out_ PWKD_RM_CONFIG Config
    );

VOID
RmCreateHighSecurityConfig(
    _Out_ PWKD_RM_CONFIG Config
    );

VOID
RmCreatePerformanceConfig(
    _Out_ PWKD_RM_CONFIG Config
    );

VOID
RmCreateForensicConfig(
    _Out_ PWKD_RM_CONFIG Config
    );

/* RM 生命周期 */
BOOLEAN
RmInitialize(
    _In_opt_ PCWKD_RM_CONFIG Config      /* NULL = 默认配置 */
    );

BOOLEAN
RmStart(
    VOID
    );

VOID
RmStop(
    VOID
    );

VOID
RmShutdown(
    VOID
    );

BOOLEAN
RmIsRunning(
    VOID
    );

BOOLEAN
RmIsKernelConnected(
    VOID
    );

/* RM 策略管理 */
VOID
RmSetPolicyCallback(
    _In_opt_ PFN_RM_POLICY_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

ULONGLONG
RmAddRule(
    _In_ PCWKD_RM_RULE Rule
    );

BOOLEAN
RmRemoveRule(
    _In_ ULONGLONG RuleId
    );

ULONG
RmGetRules(
    _Out_opt_ PWKD_RM_RULE Rules,        /* 调用方缓冲 */
    _In_ ULONG MaxCount
    );

BOOLEAN
RmSetRuleEnabled(
    _In_ ULONGLONG RuleId,
    _In_ BOOLEAN Enabled
    );

/* RM 键保护 */
VOID
RegpAddProtectedKeyConfig(
    _In_ PCWKD_RM_PROTECTED_KEY Config
    );

VOID
RmRemoveProtectedKey(
    _In_ PCWSTR KeyPath
    );

BOOLEAN
RmIsProtectedKey(
    _In_ PCWSTR KeyPath
    );

ULONG
RmGetProtectedKeys(
    _Out_opt_ PWKD_RM_PROTECTED_KEY Keys, /* 调用方缓冲 */
    _In_ ULONG MaxCount
    );

/* RM 键分析 */
BOOLEAN
RmIsCriticalKey(
    _In_ PCWSTR KeyPath
    );

ULONG
RmGetKeyCategory(
    _In_ PCWSTR KeyPath
    );

VOID
RmAnalyzeValue(
    _In_ const BYTE* Data,
    _In_ ULONG DataSize,
    _In_ ULONG Type,                     /* WKD_RM_VALUE_TYPE */
    _Out_ PWKD_RM_VALUE_ANALYSIS Analysis
    );

/* RM 事件处理 */
WKD_RM_VERDICT
RmProcessEvent(
    _Inout_ PCWKD_RM_EVENT Event
    );

ULONG
RmGetRecentEvents(
    _Out_opt_ PWKD_RM_EVENT Events,      /* 调用方缓冲 (倒序, 最新优先) */
    _In_ ULONG MaxCount
    );

/* RM 欺骗模式 */
VOID
RmConfigureDeception(
    _In_ PCWKD_RM_DECEPTION_CONFIG Config
    );

VOID
RmAddHoneypotKey(
    _In_ PCWSTR KeyPath
    );

/* RM 回调注册 */
ULONG
RmRegisterAlertCallback(
    _In_ PFN_RM_ALERT_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

ULONG
RmRegisterEventCallback(
    _In_ PFN_RM_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

ULONG
RmRegisterValueCallback(
    _In_ PFN_RM_VALUE_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

BOOLEAN
RmUnregisterCallback(
    _In_ ULONG CallbackId
    );

/* RM 事件辅助 (原 RegistryEvent 方法) */
BOOLEAN
RmEventIsPersistenceKey(
    _In_ PCWKD_RM_EVENT Event
    );

BOOLEAN
RmEventIsServiceKey(
    _In_ PCWKD_RM_EVENT Event
    );

BOOLEAN
RmEventIsSecurityKey(
    _In_ PCWKD_RM_EVENT Event
    );

BOOLEAN
RmEventIsComKey(
    _In_ PCWKD_RM_EVENT Event
    );

BOOLEAN
RmEventIsNetworkKey(
    _In_ PCWKD_RM_EVENT Event
    );

ULONG
RmEventGetCategory(
    _In_ PCWKD_RM_EVENT Event
    );

VOID
RmEventGetHive(
    _In_ PCWKD_RM_EVENT Event,
    _Out_writes_(MaxCch) PWSTR Hive,
    _In_ ULONG MaxCch
    );

/* RM 统计 */
VOID
RmGetStatistics(
    _Out_ PWKD_RM_STATS Statistics
    );

VOID
RmResetStatistics(
    VOID
    );

/* RM 诊断 */
BOOLEAN
RmPerformDiagnostics(
    VOID
    );

BOOLEAN
RmExportDiagnostics(
    _In_ PCWSTR OutputPath
    );

/* ==================================================
 * ═══ RegistryAnalyzer 区结束 · StartupAnalyzer 区 ═══
 * ================================================== */

/* ==================================================
 * ═══ SA (StartupAnalyzer / The Boot Guard) ═══
 * 启动项审计与优化引擎
 *
 * 迁移自 ShadowStrike StartupAnalyzer.cpp (v3.0.0)，
 * 面向启动项枚举（40+ 自启动位置）、安全评估、
 * 管理回写与变更历史回滚。
 *
 * 工程收敛（相对 SS 的裁剪与替代）：
 *  - 哈希:  IocScanner_ComputeFileSha256 (IOC)
 *  - 签名:  IocVerifySignature / IocScan_IsMicrosoftSigned (IOC/Signature)
 *  - 信誉:  PdAnalyzeRealTime (委托本子系统 PD 引擎)
 *  - 计划任务/服务枚举: PdScanScheduledTasks / PdScanServices (委托)
 *  - 路径规范化: WkdNormalizePath (Common/PathUtil)
 *  - 路径 %ENV% 展开: ExpandEnvironmentStringsW + GetLongPathNameW
 *  - BootImpact/DelayItem: 保留 API 面与字段, 无系统机制, 恒 0
 *    （SS 侧为假测量, 不迁移）
 *  - WirePersistenceDetector: 空壳, 不迁移
 *  - HashStore/ThreatIntel/WhiteListStore/IPCManager: 死依赖, 剔除
 * ================================================== */

/* --- SA 常量 --- */
#define WKD_SA_VERSION_MAJOR              3
#define WKD_SA_VERSION_MINOR              0
#define WKD_SA_VERSION_PATCH              0

#define WKD_SA_MAX_ITEMS                 10000   /* 启动条目上限 (DoS 防护) */
#define WKD_SA_MAX_HISTORY               1000    /* 历史记录上限 */
#define WKD_SA_BOOT_TIMEOUT_MS           60000   /* 引导分析超时 (保留) */
#define WKD_SA_SLOW_STARTUP_THRESHOLD_MS 5000    /* 慢启动阈值 (保留) */

#define WKD_SA_DEFAULT_DELAY_SECONDS     30      /* 默认延迟秒数 */
#define WKD_SA_MAX_DELAY_SECONDS         300     /* 延迟秒数上限 */

#define WKD_SA_HKU_SID_CAP               512     /* HKEY_USERS SID 枚举上限 */

#define WKD_SA_MAX_DETECTIONS            8       /* 检测名列表上限 */
#define WKD_SA_MAX_RISK_FACTORS          16      /* 风险因子上限 */
#define WKD_SA_MAX_OPT_ITEMS             128     /* 优化计划每类 ID 上限 */
#define WKD_SA_MAX_PLAN_WARNINGS         8       /* 优化计划警告上限 */
#define WKD_SA_MAX_ALERTS                10000   /* 告警队列上限 */
#define WKD_SA_ALERT_TRIM_TO             5000    /* 告警裁剪保留量 */
#define WKD_SA_MAX_CALLBACKS             64      /* 每类回调注册上限 */

#define WKD_SA_MAX_LOG_FIELD_CHARS       1024    /* 日志字段清洗上限 */
#define WKD_SA_MAX_REG_PAYLOAD           (64u*1024u)  /* 注册表载荷读取上限 */
#define WKD_SA_CANONICALIZE_CEIL         (32u*1024u)  /* %ENV% 展开上限 (WCHAR) */
#define WKD_SA_SHA256_HEX_CHARS          65      /* SHA256 hex 串 (含 NUL) */

#define WKD_SA_SAFE_DISABLE_SUBKEY       L"AutorunsDisabled"  /* 禁用备份子键 */
#define WKD_SA_DIAG_MAX_LINES            16      /* 诊断输出行数上限 */
#define WKD_SA_DIAG_LINE_CHARS           256     /* 诊断单行宽度 */

/* --- SA 源枚举 (对应 SS StartupSource, 46 值) ---
 * 说明: 部分枚举值 SS 侧无实现（仅名称映射），WkD 保留以对齐 API 面；
 *       实际枚举覆盖范围见 StartupAnalyzer.c 的 SaEnumerate* 系列。
 * 审计标注: ShellExtension/GroupPolicy/AppX/KnownDLLs/Winsock/COM_Hijack/
 *           BrowserHelper/UserShellFolders/SessionManager/TerminalServer/
 *           NetworkProvider/ProtocolHandler/WMI/BITS/OfficeAddin/
 *           DomainPolicy 为无实现保留值。 */
typedef enum _WKD_SA_SOURCE {
    WkdSaSrc_Unknown = 0,
    WkdSaSrc_RegistryRun_HKLM = 1,
    WkdSaSrc_RegistryRun_HKCU = 2,
    WkdSaSrc_RegistryRunOnce_HKLM = 3,
    WkdSaSrc_RegistryRunOnce_HKCU = 4,
    WkdSaSrc_StartupFolder_User = 5,
    WkdSaSrc_StartupFolder_AllUsers = 6,
    WkdSaSrc_ScheduledTask = 7,
    WkdSaSrc_Service = 8,
    WkdSaSrc_ShellExtension = 9,        /* 无实现 */
    WkdSaSrc_GroupPolicy = 10,          /* 无实现 */
    WkdSaSrc_AppXPackage = 11,          /* 无实现 */
    WkdSaSrc_RegistryRun_Wow64_HKLM = 12,
    WkdSaSrc_RegistryRun_Wow64_HKCU = 13,
    WkdSaSrc_RegistryRunOnce_Wow64_HKLM = 14,
    WkdSaSrc_RegistryRunOnce_Wow64_HKCU = 15,
    WkdSaSrc_RegistryRunServices_HKLM = 16,
    WkdSaSrc_RegistryRunServices_HKCU = 17,
    WkdSaSrc_Winlogon_Shell = 18,
    WkdSaSrc_Winlogon_Userinit = 19,
    WkdSaSrc_Winlogon_Notify = 20,      /* 无实现 */
    WkdSaSrc_IFEO = 21,
    WkdSaSrc_AppInit_DLLs = 22,
    WkdSaSrc_LSA_AuthenticationPackages = 23,
    WkdSaSrc_LSA_SecurityPackages = 24,
    WkdSaSrc_PrintMonitor = 25,
    WkdSaSrc_BootExecute = 26,
    WkdSaSrc_KnownDLLs = 27,            /* 无实现 */
    WkdSaSrc_Winsock_Provider = 28,     /* 无实现 */
    WkdSaSrc_ComHijack = 29,            /* 无实现 */
    WkdSaSrc_ShellServiceObjectDelay = 30,
    WkdSaSrc_BrowserHelper = 31,        /* 无实现 */
    WkdSaSrc_ExplorerRun = 32,
    WkdSaSrc_ActiveSetup = 33,
    WkdSaSrc_UserShellFolders = 34,     /* 无实现 */
    WkdSaSrc_SessionManager_Execute = 35, /* 无实现 */
    WkdSaSrc_TerminalServer_Startup = 36, /* 无实现 */
    WkdSaSrc_NaturalLanguage_DLL = 37,
    WkdSaSrc_NetworkProvider = 38,      /* 无实现 */
    WkdSaSrc_ProtocolHandler = 39,      /* 无实现 */
    WkdSaSrc_ScreenSaver = 40,
    WkdSaSrc_WmiSubscription = 41,      /* 无实现 */
    WkdSaSrc_BitsJob = 42,              /* 无实现 */
    WkdSaSrc_OfficeAddin = 43,          /* 无实现 */
    WkdSaSrc_DomainPolicy = 44,         /* 无实现 */
    WkdSaSrc_DriverService = 45,
    WkdSaSrc_Max = 45
} WKD_SA_SOURCE;

/* --- SA 条目状态 (对应 SS StartupStatus) --- */
typedef enum _WKD_SA_STATUS {
    WkdSaStatus_Enabled = 0,
    WkdSaStatus_Disabled = 1,
    WkdSaStatus_Delayed = 2,
    WkdSaStatus_Quarantined = 3,
    WkdSaStatus_Removed = 4,
    WkdSaStatus_Orphaned = 5,           /* 目标文件不存在 */
    WkdSaStatus_Error = 6
} WKD_SA_STATUS;

/* --- SA 条目分类 (对应 SS ItemCategory) --- */
typedef enum _WKD_SA_CATEGORY {
    WkdSaCat_Unknown = 0,
    WkdSaCat_System = 1,                /* OS 组件 */
    WkdSaCat_Security = 2,              /* 安全软件 */
    WkdSaCat_Hardware = 3,              /* 驱动/工具 */
    WkdSaCat_Application = 4,           /* 应用程序 */
    WkdSaCat_Utility = 5,               /* 系统工具 */
    WkdSaCat_Bloatware = 6,             /* 冗余软件 */
    WkdSaCat_Malicious = 7              /* 恶意软件 */
} WKD_SA_CATEGORY;

/* --- SA 引导影响等级 (对应 SS ImpactLevel) --- */
typedef enum _WKD_SA_IMPACT_LEVEL {
    WkdSaImpact_None = 0,
    WkdSaImpact_Low = 1,                /* < 1 秒 */
    WkdSaImpact_Medium = 2,             /* 1-3 秒 */
    WkdSaImpact_High = 3,               /* 3-5 秒 */
    WkdSaImpact_Critical = 4            /* > 5 秒 */
} WKD_SA_IMPACT_LEVEL;

/* --- SA 管理动作结果 (对应 SS ActionResult) --- */
typedef enum _WKD_SA_ACTION_RESULT {
    WkdSaAction_Success = 0,
    WkdSaAction_Failed = 1,
    WkdSaAction_AccessDenied = 2,
    WkdSaAction_NotFound = 3,
    WkdSaAction_AlreadyInState = 4,
    WkdSaAction_RequiresReboot = 5,
    WkdSaAction_PartialSuccess = 6
} WKD_SA_ACTION_RESULT;

/* --- SA 优化建议 (对应 SS OptimizationRecommendation) --- */
typedef enum _WKD_SA_RECOMMENDATION {
    WkdSaRec_Keep = 0,
    WkdSaRec_Delay = 1,
    WkdSaRec_Disable = 2,
    WkdSaRec_Remove = 3,
    WkdSaRec_Investigate = 4
} WKD_SA_RECOMMENDATION;

/* --- SA 签名信息 (对应 SS SignatureInfo, 时间用 FILETIME 语义) --- */
typedef struct _WKD_SA_SIGNATURE {
    BOOLEAN  IsSigned;
    BOOLEAN  IsValid;
    BOOLEAN  IsTrusted;
    BOOLEAN  IsMicrosoftSigned;
    WCHAR    SignerName[WKD_REG_MAX_NAME_CHARS];
    WCHAR    IssuerName[WKD_REG_MAX_NAME_CHARS];
    CHAR     Thumbprint[64];            /* SHA1 指纹 hex 小写 */
    BOOLEAN  IsExpired;
    BOOLEAN  IsRevoked;
    ULONGLONG SignatureTime;            /* FILETIME 语义 (0=未知) */
} WKD_SA_SIGNATURE, * PWKD_SA_SIGNATURE, * PCWKD_SA_SIGNATURE;

/* --- SA 信誉信息 (对应 SS ReputationInfo) --- */
typedef struct _WKD_SA_REPUTATION {
    BOOLEAN  IsKnownGood;
    BOOLEAN  IsKnownBad;
    UCHAR    TrustScore;                /* 0-100 */
    CHAR     Reputation[32];            /* Good/Suspicious/Malicious/Unknown */
    CHAR     MalwareFamily[64];
    CHAR     DetectionNames[WKD_SA_MAX_DETECTIONS][64];
    ULONG    DetectionCount;
} WKD_SA_REPUTATION, * PWKD_SA_REPUTATION, * PCWKD_SA_REPUTATION;

/* --- SA 引导影响 (对应 SS BootImpact; 字段恒 0, 无系统机制) --- */
typedef struct _WKD_SA_BOOT_IMPACT {
    ULONG    Level;                     /* WKD_SA_IMPACT_LEVEL */
    ULONG    EstimatedMs;
    DOUBLE   CpuUsagePercent;
    ULONGLONG MemoryUsageMB;
    ULONG    DiskReadsMB;
    BOOLEAN  BlocksOthers;
} WKD_SA_BOOT_IMPACT, * PWKD_SA_BOOT_IMPACT, * PCWKD_SA_BOOT_IMPACT;

/* --- SA 启动条目 (对应 SS StartupItem, 单一自含结构) --- */
typedef struct _WKD_SA_ITEM {
    /* 标识 */
    ULONGLONG  ItemId;
    WCHAR      Name[WKD_REG_MAX_NAME_CHARS];
    WCHAR      DisplayName[WKD_REG_MAX_NAME_CHARS];
    WCHAR      Description[WKD_REG_MAX_DESC_CHARS];
    WCHAR      Publisher[WKD_REG_MAX_NAME_CHARS];

    /* 来源 */
    ULONG      Source;                  /* WKD_SA_SOURCE */
    WCHAR      Location[WKD_REG_MAX_PATH_CHARS];   /* 注册表键或文件夹 */
    WCHAR      EntryName[WKD_REG_MAX_NAME_CHARS];  /* 值名或文件名 */

    /* 目标 */
    WCHAR      Command[WKD_PD_MAX_CMD_BUFFER];     /* 完整命令行 */
    WCHAR      TargetPath[WKD_REG_MAX_PATH_CHARS]; /* 解析后可执行路径 */
    WCHAR      Arguments[WKD_PD_MAX_CMD_BUFFER];
    WCHAR      WorkingDirectory[WKD_REG_MAX_PATH_CHARS];
    BOOLEAN    TargetExists;

    /* 状态 */
    ULONG      Status;                  /* WKD_SA_STATUS */
    BOOLEAN    IsEnabled;
    BOOLEAN    IsDelayed;
    ULONG      DelaySeconds;

    /* 分类 */
    ULONG      Category;                /* WKD_SA_CATEGORY */
    BOOLEAN    IsCritical;
    BOOLEAN    IsUserCreated;
    BOOLEAN    IsHidden;

    /* 安全 */
    WKD_SA_SIGNATURE   Signature;
    WKD_SA_REPUTATION  Reputation;
    BOOLEAN    IsMalicious;
    UCHAR      RiskScore;               /* 0-100 */
    CHAR       RiskFactors[WKD_SA_MAX_RISK_FACTORS][WKD_REG_MAX_DESC_CHARS];
    ULONG      RiskFactorCount;

    /* 引导影响 (恒 0) */
    WKD_SA_BOOT_IMPACT BootImpact;

    /* 哈希 */
    BYTE       Sha256[32];
    CHAR       Sha256Hex[WKD_SA_SHA256_HEX_CHARS];

    /* 时间戳 (FILETIME 语义) */
    ULONGLONG  CreatedTime;
    ULONGLONG  ModifiedTime;
    ULONGLONG  LastRun;

    /* 优化 */
    ULONG      Recommendation;          /* WKD_SA_RECOMMENDATION */
    CHAR       RecommendationReason[WKD_REG_MAX_DESC_CHARS];

    /* 用户备注 */
    WCHAR      UserNotes[WKD_REG_MAX_NAME_CHARS];
} WKD_SA_ITEM, * PWKD_SA_ITEM, * PCWKD_SA_ITEM;

/* --- SA 引导分析 (对应 SS BootAnalysis) --- */
typedef struct _WKD_SA_BOOT_ANALYSIS {
    ULONGLONG  BootTime;                /* FILETIME 语义 */
    ULONG      TotalBootTimeMs;
    ULONG      PreLogonTimeMs;
    ULONG      PostLogonTimeMs;
    ULONG      DesktopReadyTimeMs;

    ULONG      TotalStartupItems;
    ULONG      EnabledItems;
    ULONG      DelayedItems;
    ULONG      CriticalItems;

    ULONG      HighImpactItems;
    ULONG      TotalStartupImpactMs;

    DOUBLE     PeakCpuPercent;
    ULONGLONG  PeakMemoryMB;
    ULONGLONG  DiskReadMB;

    LONG       ChangeFromBaselineMs;
    DOUBLE     ChangePercent;
} WKD_SA_BOOT_ANALYSIS, * PWKD_SA_BOOT_ANALYSIS, * PCWKD_SA_BOOT_ANALYSIS;

/* --- SA 变更记录 (对应 SS StartupChange) --- */
typedef struct _WKD_SA_CHANGE {
    ULONGLONG  ChangeId;
    ULONGLONG  Timestamp;               /* FILETIME 语义 */

    ULONGLONG  ItemId;
    WCHAR      ItemName[WKD_REG_MAX_NAME_CHARS];
    ULONG      Source;                  /* WKD_SA_SOURCE */

    CHAR       ChangeType[16];          /* Enable/Disable/Remove/Add/Modify/Restore/Rollback/Delay */
    ULONG      PreviousStatus;          /* WKD_SA_STATUS */
    ULONG      NewStatus;               /* WKD_SA_STATUS */

    CHAR       ChangedBy[32];           /* User/System/ShadowStrike */
    ULONG      ProcessId;
    WCHAR      ProcessPath[WKD_REG_MAX_PATH_CHARS];

    BOOLEAN    HasBackup;
    WCHAR      BackupData[WKD_PD_MAX_CMD_BUFFER];

    BOOLEAN    CanRollback;
} WKD_SA_CHANGE, * PWKD_SA_CHANGE, * PCWKD_SA_CHANGE;

/* --- SA 优化计划 (对应 SS OptimizationPlan) --- */
typedef struct _WKD_SA_OPT_PLAN {
    ULONG      ItemsToDelay;
    ULONG      ItemsToDisable;
    ULONG      ItemsToRemove;
    ULONG      EstimatedTimeSavedMs;

    ULONGLONG  DelayItems[WKD_SA_MAX_OPT_ITEMS];
    ULONG      DelayItemCount;
    ULONGLONG  DisableItems[WKD_SA_MAX_OPT_ITEMS];
    ULONG      DisableItemCount;
    ULONGLONG  RemoveItems[WKD_SA_MAX_OPT_ITEMS];
    ULONG      RemoveItemCount;

    BOOLEAN    IsSafe;
    CHAR       Warnings[WKD_SA_MAX_PLAN_WARNINGS][WKD_REG_MAX_DESC_CHARS];
    ULONG      WarningCount;
} WKD_SA_OPT_PLAN, * PWKD_SA_OPT_PLAN, * PCWKD_SA_OPT_PLAN;

/* --- SA 告警 (对应 SS StartupAlert) --- */
typedef struct _WKD_SA_ALERT {
    ULONGLONG  AlertId;
    ULONGLONG  Timestamp;               /* FILETIME 语义 */

    CHAR       AlertType[16];           /* NewItem/Malicious/Suspicious/Removed */
    UCHAR      Severity;                /* 0-4 */

    ULONGLONG  ItemId;
    WCHAR      ItemName[WKD_REG_MAX_NAME_CHARS];
    WCHAR      TargetPath[WKD_REG_MAX_PATH_CHARS];

    UCHAR      RiskScore;
    CHAR       RiskFactors[WKD_SA_MAX_RISK_FACTORS][WKD_REG_MAX_DESC_CHARS];
    ULONG      RiskFactorCount;

    ULONG      Recommendation;          /* WKD_SA_RECOMMENDATION */
    CHAR       Description[WKD_REG_MAX_DESC_CHARS];
} WKD_SA_ALERT, * PWKD_SA_ALERT, * PCWKD_SA_ALERT;

/* --- SA 配置 (对应 SS StartupAnalyzerConfig) --- */
typedef struct _WKD_SA_CONFIG {
    /* 分析选项 */
    BOOLEAN  AnalyzeSignatures;
    BOOLEAN  CheckReputation;
    BOOLEAN  MeasureBootImpact;
    BOOLEAN  DetectHidden;

    /* 自动动作 */
    BOOLEAN  AutoDisableMalicious;
    BOOLEAN  AutoQuarantineMalicious;
    BOOLEAN  AlertOnNewItems;
    BOOLEAN  AlertOnSuspicious;

    /* 优化 */
    BOOLEAN  EnableOptimization;
    BOOLEAN  AutoDelayNonCritical;
    ULONG    DefaultDelaySeconds;

    /* 历史 */
    BOOLEAN  TrackHistory;
    ULONG    MaxHistoryEntries;

    /* 备份 */
    BOOLEAN  CreateBackups;
    WCHAR    BackupPath[WKD_REG_MAX_PATH_CHARS];
} WKD_SA_CONFIG, * PWKD_SA_CONFIG, * PCWKD_SA_CONFIG;

/* --- SA 统计 (对齐 WKD_REG_STATS_COMMON 头部语义) --- */
typedef struct _WKD_SA_STATS {
    /* 条目统计 */
    volatile LONG  TotalItemsAnalyzed;
    volatile LONG  EnabledItems;
    volatile LONG  DisabledItems;
    volatile LONG  MaliciousItems;

    /* 动作统计 */
    volatile LONG  ItemsEnabled;
    volatile LONG  ItemsDisabled;
    volatile LONG  ItemsRemoved;
    volatile LONG  ItemsQuarantined;

    /* 告警统计 */
    volatile LONG  AlertsGenerated;

    /* 引导分析 */
    volatile LONG  LastBootTimeMs;
    volatile LONG  BaselineBootTimeMs;
} WKD_SA_STATS, * PWKD_SA_STATS, * PCWKD_SA_STATS;

/* --- SA 回调类型 --- */
typedef
VOID
(*PFN_SA_NEW_ITEM_CALLBACK)(
    _In_ PCWKD_SA_ITEM Item,
    _In_opt_ PVOID Context
    );

typedef
VOID
(*PFN_SA_ALERT_CALLBACK)(
    _In_ PCWKD_SA_ALERT Alert,
    _In_opt_ PVOID Context
    );

typedef
VOID
(*PFN_SA_CHANGE_CALLBACK)(
    _In_ PCWKD_SA_CHANGE Change,
    _In_opt_ PVOID Context
    );

/* --- SA 生命周期与配置 --- */
NTSTATUS
SaInitialize(
    _In_opt_ PCWKD_SA_CONFIG Config    /* NULL = CreateDefault */
    );

VOID
SaShutdown(
    VOID
    );

BOOLEAN
SaIsInitialized(
    VOID
    );

VOID
SaCreateDefaultConfig(
    _Out_ PWKD_SA_CONFIG Config
    );

VOID
SaCreateSecurityConfig(
    _Out_ PWKD_SA_CONFIG Config
    );

VOID
SaCreatePerformanceConfig(
    _Out_ PWKD_SA_CONFIG Config
    );

NTSTATUS
SaUpdateConfig(
    _In_ PCWKD_SA_CONFIG Config
    );

VOID
SaGetConfig(
    _Out_ PWKD_SA_CONFIG Config
    );

/* --- SA 枚举与查询 ---
 * SaGetStartupItems/SaGetItemsBySource/SaGetItemsByCategory:
 *   Items 可为 NULL (仅查询 Count)；Count 输入时含容量，输出实需
 *   条目数。容量不足返回 STATUS_BUFFER_TOO_SMALL 且 Count=所需数。
 * 条目标识: Name 大小写不敏感 (索引键去内嵌 NUL) */
NTSTATUS
SaRefreshItems(
    VOID
    );

NTSTATUS
SaGetStartupItems(
    _Out_opt_ PWKD_SA_ITEM Items,
    _In_ ULONG Capacity,
    _Inout_ PULONG Count
    );

NTSTATUS
SaGetItemByName(
    _In_ PCWSTR Name,
    _Out_ PWKD_SA_ITEM Item
    );

NTSTATUS
SaGetItemById(
    _In_ ULONGLONG ItemId,
    _Out_ PWKD_SA_ITEM Item
    );

NTSTATUS
SaGetItemsBySource(
    _In_ ULONG Source,                   /* WKD_SA_SOURCE */
    _Out_opt_ PWKD_SA_ITEM Items,
    _In_ ULONG Capacity,
    _Inout_ PULONG Count
    );

NTSTATUS
SaGetItemsByCategory(
    _In_ ULONG Category,                 /* WKD_SA_CATEGORY */
    _Out_opt_ PWKD_SA_ITEM Items,
    _In_ ULONG Capacity,
    _Inout_ PULONG Count
    );

/* --- SA 管理写回 (真实落盘/落注册表) --- */
WKD_SA_ACTION_RESULT
SaDisableItem(
    _In_ PCWSTR Name
    );

WKD_SA_ACTION_RESULT
SaEnableItem(
    _In_ PCWSTR Name
    );

WKD_SA_ACTION_RESULT
SaRemoveItem(
    _In_ PCWSTR Name,
    _In_ BOOLEAN Quarantine            /* 仅影响状态标记, 语义*/
    );

WKD_SA_ACTION_RESULT
SaDelayItem(
    _In_ PCWSTR Name,
    _In_ ULONG DelaySeconds            /* > MAX 时钳位; 内存状态, 无系统机制 */
    );

WKD_SA_ACTION_RESULT
SaRestoreItem(
    _In_ PCWSTR Name
    );

/* --- SA 实时接线 (RegistryMonitor 集成) --- */
ULONG
SaWireRegistryMonitor(
    VOID
    );

VOID
SaOnRegistryChange(
    _In_ PCWSTR KeyPath,
    _In_ PCWSTR ValueName,
    _In_opt_ const BYTE* Data,
    _In_ ULONG DataSize,
    _In_ ULONG ProcessId,
    _In_opt_ PCWSTR ProcessPath
    );

VOID
SaHandleKernelNotification(
    _In_ PCWSTR KeyPath,
    _In_ PCWSTR ValueName,
    _In_ ULONG ProcessId
    );

/* --- SA 引导分析 --- */
NTSTATUS
SaGetBootAnalysis(
    _Out_ PWKD_SA_BOOT_ANALYSIS Analysis
    );

VOID
SaSetBootBaseline(
    VOID
    );

ULONG
SaGetBootBaseline(
    VOID
    );

/* --- SA 优化 --- */
NTSTATUS
SaGetOptimizationPlan(
    _Out_ PWKD_SA_OPT_PLAN Plan
    );

BOOLEAN
SaApplyOptimizationPlan(
    _In_ PCWKD_SA_OPT_PLAN Plan
    );

NTSTATUS
SaGetDelayRecommendations(
    _Out_opt_ PULONGLONG Ids,
    _In_ ULONG Capacity,
    _Inout_ PULONG Count
    );

NTSTATUS
SaGetDisableRecommendations(
    _Out_opt_ PULONGLONG Ids,
    _In_ ULONG Capacity,
    _Inout_ PULONG Count
    );

/* --- SA 安全查询 --- */
NTSTATUS
SaGetMaliciousItems(
    _Out_opt_ PWKD_SA_ITEM Items,
    _In_ ULONG Capacity,
    _Inout_ PULONG Count
    );

NTSTATUS
SaGetSuspiciousItems(
    _In_ UCHAR MinRiskScore,
    _Out_opt_ PWKD_SA_ITEM Items,
    _In_ ULONG Capacity,
    _Inout_ PULONG Count
    );

NTSTATUS
SaScanItemByName(
    _In_ PCWSTR Name,
    _Out_ PWKD_SA_ITEM Item
    );

/* --- SA 历史与回滚 --- */
NTSTATUS
SaGetHistory(
    _In_ ULONG MaxCount,
    _Out_opt_ PWKD_SA_CHANGE Changes,
    _In_ ULONG Capacity,
    _Inout_ PULONG Count
    );

BOOLEAN
SaRollbackChange(
    _In_ ULONGLONG ChangeId
    );

/* --- SA 回调注册 --- */
ULONG
SaRegisterNewItemCallback(
    _In_ PFN_SA_NEW_ITEM_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

ULONG
SaRegisterAlertCallback(
    _In_ PFN_SA_ALERT_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

ULONG
SaRegisterChangeCallback(
    _In_ PFN_SA_CHANGE_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

BOOLEAN
SaUnregisterCallback(
    _In_ ULONG CallbackId
    );

/* --- SA 统计与诊断 --- */
VOID
SaGetStatistics(
    _Out_ PWKD_SA_STATS Statistics
    );

VOID
SaResetStatistics(
    VOID
    );

PCSTR
SaGetVersionString(
    VOID
    );

BOOLEAN
SaSelfTest(
    VOID
    );

BOOLEAN
SaRunDiagnostics(
    _Out_opt_ PWSTR Lines,             /* WCHAR[Capacity][WKD_SA_DIAG_LINE_CHARS] */
    _In_ ULONG Capacity,
    _Inout_ PULONG Count
    );

BOOLEAN
SaExportReport(
    _In_ PCWSTR OutputPath
    );

BOOLEAN
SaExportItems(
    _In_ PCWSTR OutputPath
    );

/* --- SA 名称映射 (返回静态窄字符串, 对应 SS Get*Name) --- */
PCSTR
SaLookupSourceName(
    _In_ ULONG Source                   /* WKD_SA_SOURCE */
    );

PCSTR
SaLookupStatusName(
    _In_ ULONG Status                   /* WKD_SA_STATUS */
    );

PCSTR
SaLookupCategoryName(
    _In_ ULONG Category                 /* WKD_SA_CATEGORY */
    );

PCSTR
SaLookupImpactName(
    _In_ ULONG Level                    /* WKD_SA_IMPACT_LEVEL */
    );

PCSTR
SaLookupActionResultName(
    _In_ ULONG Result                   /* WKD_SA_ACTION_RESULT */
    );

PCSTR
SaLookupRecommendationName(
    _In_ ULONG Recommendation           /* WKD_SA_RECOMMENDATION */
    );

/* ==================================================
 * ═══ SSM 区 (SystemSettingsMonitor, The Config
 *     Guardian) — 2026-09-09 迁移自 ShadowStrike
 *     SystemSettingsMonitor.hpp (1116 行) ═══
 * ================================================== */

/* --- SSM 常量 --- */
#define WKD_SSM_VERSION_MAJOR            3
#define WKD_SSM_VERSION_MINOR            0
#define WKD_SSM_VERSION_PATCH            0

/* 容量上限 (MAX_ALERTS=10000·MAX_HISTORY=5000;
 * 告警: 动态指针池 (堆分配, 上限 10000, 对齐 SA Alerts 模式);
 * 历史: 静态环形数组 WKD_SSM_MAX_HISTORY=2000 (SS=5000, WkD
 *   收敛控制静态内存 ~7.5MB; MaxHistoryEntries 可再下调);
 * 基线: 静态 32 槽 (~0.4MB)) */
#define WKD_SSM_MAX_ALERTS               10000
#define WKD_SSM_MAX_HISTORY              2000
#define WKD_SSM_MAX_BASELINES            32      /* SS 无上限, WkD 收敛 (快照含全量状态) */
#define WKD_SSM_MAX_CALLBACKS            64      /* 每类回调注册上限 (对齐 SA) */
#define WKD_SSM_HISTORY_RETURN_CAP       1000    /* Remediate/ExportHistory 历史回取上限 (使用处) */
#define WKD_SSM_DNS_MAX_SERVERS          32      /* DNS 服务器列表上限 */
#define WKD_SSM_DNS_MAX_IP_CHARS         64      /* DNS 项最大字符 (IPv6 压缩形态) */
#define WKD_SSM_MAX_EXCLUSIONS           4       /* Defender 排除项槽数 (SS 实现恒空, 仅保留字段面) */
#define WKD_SSM_MAX_COMPLIANCE_FAILURES  8       /* 合规失败条目上限 (实测 ≤4) */
#define WKD_SSM_MAX_COMPLIANCE_WARNINGS  8       /* 合规警告条目上限 (实测 ≤2) */

/* 轮询间隔钳位 (kMinPollIntervalMs/kMaxPollIntervalMs) */
#define WKD_SSM_MIN_POLL_INTERVAL_MS     250
#define WKD_SSM_MAX_POLL_INTERVAL_MS     60000
#define WKD_SSM_DEFAULT_POLL_INTERVAL_MS 1000

#define WKD_SSM_REMEDIATION_DELAY_MS     100     /* 自动补救延迟 (对齐 SS; 保留语义) */
#define WKD_SSM_MAX_LOG_FIELD_CHARS      1024    /* 日志字段清洗上限 */

/* UAC 级别常量 (SystemSettingsMonitorConstants) */
#define WKD_SSM_UAC_DISABLED             0
#define WKD_SSM_UAC_NOTIFY_CHANGES       1
#define WKD_SSM_UAC_NOTIFY_CHANGES_NO_DIM 2
#define WKD_SSM_UAC_NOTIFY_ALL           3
#define WKD_SSM_UAC_ALWAYS_NOTIFY        4

/* --- SSM 枚举 (数值对齐 SS, 递增序保持一致) --- */
typedef enum _WKD_SSM_CATEGORY {
    WkdSsmCat_Unknown = 0,
    WkdSsmCat_Security = 1,          /* UAC, Defender, Firewall */
    WkdSsmCat_Network = 2,           /* Proxy, DNS, TCP/IP */
    WkdSsmCat_Shell = 3,             /* 关联/右键菜单 (SS 未实现) */
    WkdSsmCat_Policy = 4,            /* 组策略/AppLocker (SS 未实现) */
    WkdSsmCat_Authentication = 5,    /* LSA, 凭据提供程序 */
    WkdSsmCat_Update = 6,            /* Windows Update (SS 未实现) */
    WkdSsmCat_Privacy = 7,           /* 遥测 (SS 未实现) */
    WkdSsmCat_Performance = 8        /* 电源/内存 (SS 未实现) */
} WKD_SSM_CATEGORY;

typedef enum _WKD_SSM_SETTING_TYPE {
    WkdSsmSt_Unknown = 0,

    /* UAC */
    WkdSsmSt_UacEnabled = 1,
    WkdSsmSt_UacConsentPromptAdmin = 2,
    WkdSsmSt_UacConsentPromptUser = 3,
    WkdSsmSt_UacPromptOnSecureDesktop = 4,
    WkdSsmSt_UacDetectInstallations = 5,
    WkdSsmSt_UacRunAllAdminsInAam = 6,   /* 规范化 #95: 字段已删, 枚举值占位保留 (无消费方) */
    WkdSsmSt_UacValidateAdminCodeSignatures = 7,

    /* Defender */
    WkdSsmSt_DefenderEnabled = 10,
    WkdSsmSt_DefenderRealtimeProtection = 11,
    WkdSsmSt_DefenderBehaviorMonitoring = 12,
    WkdSsmSt_DefenderIoav = 13,
    WkdSsmSt_DefenderCloudProtection = 14,
    WkdSsmSt_DefenderControlledFolderAccess = 15,
    WkdSsmSt_DefenderTamperProtection = 16,
    WkdSsmSt_DefenderExclusionPaths = 17,
    WkdSsmSt_DefenderExclusionExtensions = 18,
    WkdSsmSt_DefenderExclusionProcesses = 19,

    /* 防火墙 */
    WkdSsmSt_FirewallDomainEnabled = 20,
    WkdSsmSt_FirewallPrivateEnabled = 21,
    WkdSsmSt_FirewallPublicEnabled = 22,
    WkdSsmSt_FirewallDefaultInbound = 23,
    WkdSsmSt_FirewallDefaultOutbound = 24,

    /* 利用缓解 */
    WkdSsmSt_ExploitAslr = 30,
    WkdSsmSt_ExploitDep = 31,
    WkdSsmSt_ExploitCfg = 32,
    WkdSsmSt_ExploitSehop = 33,
    WkdSsmSt_ExploitHeapTermination = 34,

    /* LSA */
    WkdSsmSt_LsaRunAsPpl = 40,
    WkdSsmSt_LsaRestrictAnonymous = 41,
    WkdSsmSt_LsaLimitBlankPasswords = 42,
    WkdSsmSt_LsaNoLmHash = 43,
    WkdSsmSt_LsaAuditPolicy = 44,

    /* Credential Guard */
    WkdSsmSt_CredGuardEnabled = 50,
    WkdSsmSt_CredGuardUefi = 51,

    /* 网络 */
    WkdSsmSt_NetworkProxyEnabled = 60,
    WkdSsmSt_NetworkProxyServer = 61,
    WkdSsmSt_NetworkProxyOverride = 62,
    WkdSsmSt_NetworkAutoDetect = 63,
    WkdSsmSt_NetworkAutoConfigUrl = 64,
    WkdSsmSt_NetworkDnsServers = 65,
    WkdSsmSt_NetworkDnsSuffix = 66,

    /* Shell (SS 未实现) */
    WkdSsmSt_ShellFileAssociation = 70,
    WkdSsmSt_ShellContextMenuHandler = 71,
    WkdSsmSt_ShellShellExtension = 72,
    WkdSsmSt_ShellDefaultBrowser = 73,
    WkdSsmSt_ShellDefaultProgram = 74,

    /* 策略 (SS 未实现) */
    WkdSsmSt_PolicyAppLocker = 80,
    WkdSsmSt_PolicySrp = 81,
    WkdSsmSt_PolicyWdac = 82,
    WkdSsmSt_PolicyScriptExecution = 83,

    /* 更新 (SS 未实现) */
    WkdSsmSt_UpdateAutoUpdate = 90,
    WkdSsmSt_UpdateNotifyLevel = 91,
    WkdSsmSt_UpdateDeferUpdates = 92
} WKD_SSM_SETTING_TYPE;

typedef enum _WKD_SSM_CHANGE_TYPE {
    WkdSsmCht_Created = 0,
    WkdSsmCht_Modified = 1,
    WkdSsmCht_Deleted = 2,
    WkdSsmCht_Reset = 3
} WKD_SSM_CHANGE_TYPE;

typedef enum _WKD_SSM_SEVERITY {
    WkdSsmSev_Info = 0,
    WkdSsmSev_Low = 1,
    WkdSsmSev_Medium = 2,
    WkdSsmSev_High = 3,
    WkdSsmSev_Critical = 4
} WKD_SSM_SEVERITY;

typedef enum _WKD_SSM_REMEDIATION {
    WkdSsmRem_None = 0,
    WkdSsmRem_Restore = 1,           /* 恢复到安全默认 */
    WkdSsmRem_Block = 2,             /* 阻止变更 */
    WkdSsmRem_Alert = 3,             /* 仅告警 */
    WkdSsmRem_Quarantine = 4         /* 隔离责任进程 */
} WKD_SSM_REMEDIATION;

typedef enum _WKD_SSM_UAC_LEVEL {
    WkdSsmUac_Disabled = 0,
    WkdSsmUac_NotifyChanges = 1,
    WkdSsmUac_NotifyChangesNoDim = 2,
    WkdSsmUac_NotifyAll = 3,
    WkdSsmUac_AlwaysNotify = 4
} WKD_SSM_UAC_LEVEL;

typedef enum _WKD_SSM_FIREWALL_PROFILE {
    WkdSsmFw_Domain = 0,
    WkdSsmFw_Private = 1,
    WkdSsmFw_Public = 2,
    WkdSsmFw_All = 3
} WKD_SSM_FIREWALL_PROFILE;

/* --- SSM 数据结构 --- */

/* UAC 配置 (UACSettings) */
typedef struct _WKD_SSM_UAC_SETTINGS {
    BOOLEAN           Enabled;                 /* EnableLUA != 0 */
    ULONG             Level;                   /* WKD_SSM_UAC_LEVEL */
    ULONG             ConsentPromptAdmin;      /* 默认 5 (非 Win 二进制提示同意) */
    ULONG             ConsentPromptUser;       /* 默认 3 (提示凭据) */
    BOOLEAN           PromptOnSecureDesktop;
    BOOLEAN           DetectInstallations;   /* EnableInstallerDetection != 0 (规范化 #95: 原错位存入 RunAllAdminsInAAM) */
    BOOLEAN           ValidateAdminCodeSignatures;
    BOOLEAN           FilterAdministratorToken;
    WKD_REG_TIMESTAMP LastChecked;
} WKD_SSM_UAC_SETTINGS, * PWKD_SSM_UAC_SETTINGS, * PCWKD_SSM_UAC_SETTINGS;

/* Defender 配置 (DefenderSettings; 排除项/签名版本 SS 实现恒空) */
typedef struct _WKD_SSM_DEFENDER_SETTINGS {
    BOOLEAN           Enabled;
    BOOLEAN           RealTimeProtection;
    BOOLEAN           BehaviorMonitoring;
    BOOLEAN           IoavProtection;
    BOOLEAN           CloudProtection;
    BOOLEAN           ControlledFolderAccess;
    BOOLEAN           TamperProtection;        /* 值==5 视为开启 (对齐 SS) */
    BOOLEAN           NetworkProtection;       /* 值 1/2 视为开启 (对齐 SS) */
    BOOLEAN           PotentiallyUnwantedApps;
    WCHAR             ExcludedPaths[WKD_SSM_MAX_EXCLUSIONS][WKD_REG_MAX_PATH_CHARS];
    ULONG             ExcludedPathCount;
    WCHAR             ExcludedExtensions[WKD_SSM_MAX_EXCLUSIONS][WKD_REG_MAX_NAME_CHARS];
    ULONG             ExcludedExtensionCount;
    WCHAR             ExcludedProcesses[WKD_SSM_MAX_EXCLUSIONS][WKD_REG_MAX_PATH_CHARS];
    ULONG             ExcludedProcessCount;
    WCHAR             SignatureVersion[WKD_REG_MAX_NAME_CHARS];
    WKD_REG_TIMESTAMP LastSignatureUpdate;
    WKD_REG_TIMESTAMP LastFullScan;
    WKD_REG_TIMESTAMP LastChecked;
} WKD_SSM_DEFENDER_SETTINGS, * PWKD_SSM_DEFENDER_SETTINGS, * PCWKD_SSM_DEFENDER_SETTINGS;

/* 防火墙配置 (FirewallSettings) */
typedef struct _WKD_SSM_FIREWALL_SETTINGS {
    BOOLEAN           DomainEnabled;
    BOOLEAN           PrivateEnabled;
    BOOLEAN           PublicEnabled;
    ULONG             DomainDefaultInbound;    /* 1 = 阻止 */
    ULONG             DomainDefaultOutbound;   /* 0 = 放行 */
    ULONG             PrivateDefaultInbound;
    ULONG             PrivateDefaultOutbound;
    ULONG             PublicDefaultInbound;
    ULONG             PublicDefaultOutbound;
    BOOLEAN           NotifyOnBlocked;
    BOOLEAN           AllowLocalPolicyMerge;
    WKD_REG_TIMESTAMP LastChecked;
} WKD_SSM_FIREWALL_SETTINGS, * PWKD_SSM_FIREWALL_SETTINGS, * PCWKD_SSM_FIREWALL_SETTINGS;

/* 利用缓解 (ExploitProtection) */
typedef struct _WKD_SSM_EXPLOIT_SETTINGS {
    BOOLEAN           AslrEnabled;             /* MoveImages != 0xFFFFFFFF */
    BOOLEAN           DepEnabled;              /* 64 位 Win10+ 恒真 (SS 语义) */
    BOOLEAN           CfgEnabled;
    BOOLEAN           SehopEnabled;            /* DisableExceptionChainValidation==0 */
    BOOLEAN           HeapTerminationEnabled;
    WKD_REG_TIMESTAMP LastChecked;
} WKD_SSM_EXPLOIT_SETTINGS, * PWKD_SSM_EXPLOIT_SETTINGS, * PCWKD_SSM_EXPLOIT_SETTINGS;

/* LSA 配置 (LSASettings) */
typedef struct _WKD_SSM_LSA_SETTINGS {
    BOOLEAN           RunAsPpl;
    ULONG             RestrictAnonymous;
    BOOLEAN           LimitBlankPasswordUse;
    BOOLEAN           NoLmHash;
    ULONG             LmCompatibilityLevel;
    WKD_REG_TIMESTAMP LastChecked;
} WKD_SSM_LSA_SETTINGS, * PWKD_SSM_LSA_SETTINGS, * PCWKD_SSM_LSA_SETTINGS;

/* 代理配置 (ProxySettings) */
typedef struct _WKD_SSM_PROXY_SETTINGS {
    BOOLEAN           ProxyEnabled;
    WCHAR             ProxyServer[WKD_REG_MAX_PATH_CHARS];
    WCHAR             ProxyOverride[WKD_REG_MAX_PATH_CHARS];
    BOOLEAN           AutoDetect;
    WCHAR             AutoConfigUrl[WKD_REG_MAX_PATH_CHARS];
    BOOLEAN           IsSystemWide;
    WKD_REG_TIMESTAMP LastChecked;
} WKD_SSM_PROXY_SETTINGS, * PWKD_SSM_PROXY_SETTINGS, * PCWKD_SSM_PROXY_SETTINGS;

/* DNS 配置 (DNSSettings) */
typedef struct _WKD_SSM_DNS_SETTINGS {
    WCHAR             DnsServers[WKD_SSM_DNS_MAX_SERVERS][WKD_SSM_DNS_MAX_IP_CHARS];
    ULONG             DnsServerCount;
    WCHAR             DnsSuffix[WKD_REG_MAX_NAME_CHARS];
    WCHAR             SearchList[WKD_REG_MAX_PATH_CHARS];
    BOOLEAN           UseDhcp;
    BOOLEAN           RegisterAdapterName;
    BOOLEAN           DohEnabled;
    WCHAR             DohServer[WKD_REG_MAX_PATH_CHARS];
    WKD_REG_TIMESTAMP LastChecked;
} WKD_SSM_DNS_SETTINGS, * PWKD_SSM_DNS_SETTINGS, * PCWKD_SSM_DNS_SETTINGS;

/* 基线快照 (BaselineSnapshot) */
typedef struct _WKD_SSM_SNAPSHOT {
    ULONGLONG                SnapshotId;
    WKD_REG_TIMESTAMP        Created;
    CHAR                     Description[WKD_REG_MAX_DESC_CHARS];
    WKD_SSM_UAC_SETTINGS     Uac;
    WKD_SSM_DEFENDER_SETTINGS Defender;
    WKD_SSM_FIREWALL_SETTINGS Firewall;
    WKD_SSM_EXPLOIT_SETTINGS  Exploit;
    WKD_SSM_LSA_SETTINGS      Lsa;
    WKD_SSM_PROXY_SETTINGS    Proxy;
    WKD_SSM_DNS_SETTINGS      Dns;
    BOOLEAN                  IsDefault;
} WKD_SSM_SNAPSHOT, * PWKD_SSM_SNAPSHOT, * PCWKD_SSM_SNAPSHOT;

/* 设置变更记录 (SettingChange; Process* 域 SS 轮询引擎未填充) */
typedef struct _WKD_SSM_CHANGE {
    ULONGLONG           ChangeId;
    WKD_REG_TIMESTAMP   Timestamp;
    ULONG               Category;              /* WKD_SSM_CATEGORY */
    ULONG               SettingType;           /* WKD_SSM_SETTING_TYPE */
    WCHAR               SettingPath[WKD_REG_MAX_PATH_CHARS];
    WCHAR               SettingName[WKD_REG_MAX_NAME_CHARS];
    ULONG               ChangeType;            /* WKD_SSM_CHANGE_TYPE */
    WCHAR               PreviousValue[WKD_REG_MAX_PATH_CHARS];
    WCHAR               NewValue[WKD_REG_MAX_PATH_CHARS];
    ULONG               ProcessId;             /* 0 (SS 轮询无归属) */
    WCHAR               ProcessPath[WKD_REG_MAX_PATH_CHARS];
    WCHAR               ProcessUser[WKD_REG_MAX_USER_SID_CHARS];
    ULONG               Severity;              /* WKD_SSM_SEVERITY */
    BOOLEAN             IsSecurityDegrade;
    BOOLEAN             IsMalwareIndicator;
    CHAR                RiskDescription[WKD_REG_MAX_DESC_CHARS];
    ULONG               ActionTaken;           /* WKD_SSM_REMEDIATION */
    BOOLEAN             WasRemediated;
} WKD_SSM_CHANGE, * PWKD_SSM_CHANGE, * PCWKD_SSM_CHANGE;

/* 安全告警 (SecurityAlert; Acknowledge 取证保留语义) */
typedef struct _WKD_SSM_ALERT {
    ULONGLONG           AlertId;
    WKD_REG_TIMESTAMP   Timestamp;
    ULONG               Severity;              /* WKD_SSM_SEVERITY */
    CHAR                AlertType[32];
    CHAR                Title[WKD_REG_MAX_NAME_CHARS];
    CHAR                Description[WKD_REG_MAX_DESC_CHARS];
    ULONG               Category;              /* WKD_SSM_CATEGORY */
    ULONG               SettingType;           /* WKD_SSM_SETTING_TYPE */
    WCHAR               SettingPath[WKD_REG_MAX_PATH_CHARS];
    WCHAR               PreviousValue[WKD_REG_MAX_PATH_CHARS];
    WCHAR               CurrentValue[WKD_REG_MAX_PATH_CHARS];
    ULONG               ResponsiblePid;        /* 0 (SS 轮询无归属) */
    WCHAR               ResponsibleProcess[WKD_REG_MAX_PATH_CHARS];
    WCHAR               ResponsibleUser[WKD_REG_MAX_USER_SID_CHARS];
    BOOLEAN             CanRemediate;
    ULONG               RecommendedAction;     /* WKD_SSM_REMEDIATION */
    BOOLEAN             WasRemediated;
    BOOLEAN             Acknowledged;          /* AcknowledgeAlert 置位; 记录为取证保留 */
    CHAR                MitreId[32];
    CHAR                MitreTactic[64];
} WKD_SSM_ALERT, * PWKD_SSM_ALERT, * PCWKD_SSM_ALERT;

/* 合规状态 (ComplianceStatus) */
typedef struct _WKD_SSM_COMPLIANCE {
    BOOLEAN             IsCompliant;           /* failedChecks == 0 */
    ULONG               TotalChecks;
    ULONG               PassedChecks;
    ULONG               FailedChecks;
    ULONG               Warnings;
    CHAR                Failures[WKD_SSM_MAX_COMPLIANCE_FAILURES][WKD_REG_MAX_DESC_CHARS];
    ULONG               FailureCount;
    CHAR                WarningList[WKD_SSM_MAX_COMPLIANCE_WARNINGS][WKD_REG_MAX_DESC_CHARS];
    ULONG               WarningCount;
    WKD_REG_TIMESTAMP   LastChecked;
} WKD_SSM_COMPLIANCE, * PWKD_SSM_COMPLIANCE, * PCWKD_SSM_COMPLIANCE;

/* 配置 (SystemSettingsMonitorConfig; MonitorShell/MonitorPolicy
 * 承袭 SS 未实现, 仅保留字段面) */
typedef struct _WKD_SSM_CONFIG {
    /* 监控开关 */
    BOOLEAN         MonitorUAC;
    BOOLEAN         MonitorDefender;
    BOOLEAN         MonitorFirewall;
    BOOLEAN         MonitorExploitProtection;
    BOOLEAN         MonitorLSA;
    BOOLEAN         MonitorProxy;
    BOOLEAN         MonitorDNS;
    BOOLEAN         MonitorShell;          /* SS 未实现 (保留) */
    BOOLEAN         MonitorPolicy;         /* SS 未实现 (保留) */
    BOOLEAN         SuspiciousDnsCheckEnabled;  /* 增强 #95: DNS 可疑(错拼暗桩)判定开关, 默认 TRUE */
    /* 自动补救 */
    BOOLEAN         EnableAutoRemediation;
    BOOLEAN         RemediateUAC;
    BOOLEAN         RemediateDefender;
    BOOLEAN         RemediateFirewall;
    /* 告警 */
    ULONG           MinimumAlertSeverity;  /* WKD_SSM_SEVERITY, 默认 Medium */
    BOOLEAN         AlertOnAnyChange;
    BOOLEAN         AlertOnSecurityDegrade;
    /* 基线 */
    BOOLEAN         UseBaseline;
    BOOLEAN         AutoCreateBaseline;
    /* 历史 */
    ULONG           MaxHistoryEntries;     /* 默认 WKD_SSM_MAX_HISTORY */
    /* 轮询 */
    ULONG           MonitorPollIntervalMs; /* 默认 1000, 使用处钳位 [250,60000] */
} WKD_SSM_CONFIG, * PWKD_SSM_CONFIG, * PCWKD_SSM_CONFIG;

/* 统计 (对齐 WKD_SA_STATS 的 volatile LONG 语义) */
typedef struct _WKD_SSM_STATS {
    volatile LONGLONG  ChangesDetected;
    volatile LONGLONG  SecurityDegrades;
    volatile LONGLONG  AlertsGenerated;
    volatile LONGLONG  RemediationsPerformed;
    volatile LONGLONG  RemediationsFailed;
    volatile LONGLONG  UacChanges;
    volatile LONGLONG  DefenderChanges;
    volatile LONGLONG  FirewallChanges;
    volatile LONGLONG  NetworkChanges;
    volatile LONGLONG  ShellChanges;
} WKD_SSM_STATS, * PWKD_SSM_STATS, * PCWKD_SSM_STATS;

/* --- SSM 回调类型 (对齐 PFN_SA_* 的 Context 模式) --- */
typedef
VOID
(*PFN_SSM_CHANGE_CALLBACK)(
    _In_ PCWKD_SSM_CHANGE Change,
    _In_opt_ PVOID Context
    );

typedef
VOID
(*PFN_SSM_ALERT_CALLBACK)(
    _In_ PCWKD_SSM_ALERT Alert,
    _In_opt_ PVOID Context
    );

typedef
VOID
(*PFN_SSM_COMPLIANCE_CALLBACK)(
    _In_ PCWKD_SSM_COMPLIANCE Status,
    _In_opt_ PVOID Context
    );

/* --- SSM 生命周期与配置 --- */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
SsmInitialize(
    _In_opt_ PCWKD_SSM_CONFIG Config    /* NULL = CreateDefault */
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmShutdown(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmIsInitialized(
    VOID
    );

/* --- SSM 监控控制 --- */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmStart(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmStop(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmIsMonitoring(
    VOID
    );

/* --- SSM 配置工厂 (CreateDefault/HighSecurity/MonitorOnly) --- */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmCreateDefaultConfig(
    _Out_ PWKD_SSM_CONFIG Config
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmCreateHighSecurityConfig(
    _Out_ PWKD_SSM_CONFIG Config
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmCreateMonitorOnlyConfig(
    _Out_ PWKD_SSM_CONFIG Config
    );

/* --- SSM 设置查询 (UAC) --- */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmGetUacSettings(
    _Out_ PWKD_SSM_UAC_SETTINGS Settings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmIsUacDisabled(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG
SsmGetUacLevel(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmRestoreUacDefaults(
    VOID
    );

/* --- SSM 设置查询 (Defender) --- */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmGetDefenderSettings(
    _Out_ PWKD_SSM_DEFENDER_SETTINGS Settings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmIsDefenderDisabled(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmIsRealtimeProtectionDisabled(
    VOID
    );

/* Paths: WCHAR[Capacity][WKD_REG_MAX_PATH_CHARS]; Paths 可为 NULL (仅取 Count) */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
SsmGetDefenderExclusions(
    _Out_opt_ PWCHAR Paths,
    _In_ ULONG Capacity,
    _Inout_ PULONG Count
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmRestoreDefenderDefaults(
    VOID
    );

/* --- SSM 设置查询 (Firewall) --- */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmGetFirewallSettings(
    _Out_ PWKD_SSM_FIREWALL_SETTINGS Settings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmIsFirewallDisabled(
    _In_ ULONG Profile              /* WKD_SSM_FIREWALL_PROFILE */
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmIsAnyFirewallDisabled(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmRestoreFirewallDefaults(
    VOID
    );

/* --- SSM 设置查询 (Exploit Protection) --- */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmGetExploitSettings(
    _Out_ PWKD_SSM_EXPLOIT_SETTINGS Settings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmIsAslrDisabled(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmIsDepDisabled(
    VOID
    );

/* --- SSM 设置查询 (LSA) --- */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmGetLsaSettings(
    _Out_ PWKD_SSM_LSA_SETTINGS Settings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmIsLsaPplEnabled(
    VOID
    );

/* --- SSM 设置查询 (Proxy / DNS) --- */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmGetProxySettings(
    _Out_ PWKD_SSM_PROXY_SETTINGS Settings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmIsProxyEnabled(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmGetDnsSettings(
    _Out_ PWKD_SSM_DNS_SETTINGS Settings
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmIsDnsSuspicious(
    VOID
    );

/* --- SSM 基线管理 ---
 * SsmGetBaseline/SsmGetActiveBaseline: 未找到返回 STATUS_NOT_FOUND
 * SsmCompareToBaseline: Changes 可为 NULL (仅取 Count); 无差异返回 STATUS_SUCCESS 且 Count=0 */
_IRQL_requires_max_(PASSIVE_LEVEL)
ULONGLONG
SsmCreateBaseline(
    _In_ PCSTR Description
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
SsmGetBaseline(
    _In_ ULONGLONG BaselineId,
    _Out_ PWKD_SSM_SNAPSHOT Snapshot
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
SsmGetActiveBaseline(
    _Out_ PWKD_SSM_SNAPSHOT Snapshot
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmSetActiveBaseline(
    _In_ ULONGLONG BaselineId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmRestoreToBaseline(
    _In_ ULONGLONG BaselineId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
SsmCompareToBaseline(
    _In_ ULONGLONG BaselineId,
    _Out_opt_ PWKD_SSM_CHANGE Changes,
    _In_ ULONG Capacity,
    _Inout_ PULONG Count
    );

/* --- SSM 合规 --- */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmCheckCompliance(
    _Out_ PWKD_SSM_COMPLIANCE Status
    );

/* PolicyPath 存在性校验后委托 SsmCheckCompliance (承袭 SS 偏弱语义) */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmCheckPolicyCompliance(
    _In_ PCWSTR PolicyPath,
    _Out_ PWKD_SSM_COMPLIANCE Status
    );

/* --- SSM 历史 ---
 * Changes: WKD_SSM_CHANGE[Capacity]; 最新优先; 可为 NULL (仅取 Count) */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
SsmGetHistory(
    _In_ ULONG MaxCount,
    _Out_opt_ PWKD_SSM_CHANGE Changes,
    _In_ ULONG Capacity,
    _Inout_ PULONG Count
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
SsmGetHistoryByCategory(
    _In_ ULONG Category,                /* WKD_SSM_CATEGORY */
    _In_ ULONG MaxCount,
    _Out_opt_ PWKD_SSM_CHANGE Changes,
    _In_ ULONG Capacity,
    _Inout_ PULONG Count
    );

/* --- SSM 告警 --- */
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
SsmGetActiveAlerts(
    _Out_opt_ PWKD_SSM_ALERT Alerts,
    _In_ ULONG Capacity,
    _Inout_ PULONG Count
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmAcknowledgeAlert(
    _In_ ULONGLONG AlertId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmClearAlerts(
    VOID
    );

/* --- SSM 补救 --- */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmRemediate(
    _In_ ULONGLONG ChangeId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmSetAutoRemediation(
    _In_ BOOLEAN Enable
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmIsAutoRemediationEnabled(
    VOID
    );

/* --- SSM 回调注册 (id 槽精确注销, 对齐 SA 修正) --- */
_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG
SsmRegisterChangeCallback(
    _In_ PFN_SSM_CHANGE_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG
SsmRegisterAlertCallback(
    _In_ PFN_SSM_ALERT_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG
SsmRegisterComplianceCallback(
    _In_ PFN_SSM_COMPLIANCE_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmUnregisterCallback(
    _In_ ULONG CallbackId
    );

/* --- SSM 统计 --- */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmGetStatistics(
    _Out_ PWKD_SSM_STATS Statistics
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmResetStatistics(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
PCSTR
SsmGetVersionString(
    VOID
    );

/* --- SSM 刷新 --- */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmRefreshAll(
    VOID
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
SsmRefreshCategory(
    _In_ ULONG Category                /* WKD_SSM_CATEGORY */
    );

/* --- SSM 导出 (UTF-8; 路径规范化 + JSON/日志注入防护) --- */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmExportReport(
    _In_ PCWSTR OutputPath
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmExportSettings(
    _In_ PCWSTR OutputPath
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
SsmExportHistory(
    _In_ PCWSTR OutputPath
    );

/* ==================================================
 * ═══ 公共门面接口（原 Registry\Registry.h 并入，
 *  2026-09-15 合并） ═══
 *
 *  以下为 Registry 子系统对外暴露的唯一接口面：
 *  - 公共类型（不透明句柄/配置/状态/Notify 载荷）
 *  - WkdRegistry_* 门面函数原型
 *
 *  main.c / Orchestrator / 其他模块仅允许引用本段；
 *  上半部分各引擎私有 API（PdXxx/RaXxx/RmXxx/SsmXxx/
 *  SaXxx）仅供 Registry\ 目录内 .c 实现文件引用，
 *  禁止外部使用。
 *
 *  设计原则：
 *  - 子系统状态封装为不透明句柄 PWKD_REG_SUBSYSTEM
 *  - 配置与输出载荷全部使用本段自含的公共类型
 *  - 输出统一通过 Notify 回调（序列化友好文本行），
 *    不暴露任何引擎私有结构
 *  - 更细粒度引擎 API 仅存在于本头引擎私有段，由
 *    子系统编排逻辑（RegistrySubsystem.c）使用
 * ================================================== */

/* --- 子系统不透明句柄 --- */
typedef struct _WKD_REG_SUBSYSTEM *PWKD_REG_SUBSYSTEM;

/* --- 公共常量 --- */
#define WKD_REG_PUBLIC_MAX_TITLE_CHARS        64
#define WKD_REG_PUBLIC_MAX_DESC_CHARS         160
#define WKD_REG_PUBLIC_MAX_FIELDS             8
#define WKD_REG_PUBLIC_MAX_FIELD_CHARS        128

/* --- 引擎标识（对上层暴露的面） --- */
typedef enum _WKD_REG_ENGINE_ID {
    WkdRegEngine_None = 0,
    WkdRegEngine_PersistenceDetector = 1,     /* 持久化检测     */
    WkdRegEngine_SystemSettingsMonitor = 2,   /* 系统设置监控   */
    WkdRegEngine_RegistryAnalyzer = 3,        /* 注册表取证分析 */
    WkdRegEngine_RegistryMonitor = 4,         /* 注册表实时裁决 */
    WkdRegEngine_StartupAnalyzer = 5,         /* 启动项审计     */
    WkdRegEngine_Max = 5
} WKD_REG_ENGINE_ID;

/* --- 事件类型（Notify 载荷中的事件分类） --- */
typedef enum _WKD_REG_EVENT_KIND {
    WkdRegEvent_Info = 0,          /* 信息（扫描开始/结束/统计） */
    WkdRegEvent_Entry = 1,         /* 条目（持久化/启动项条目） */
    WkdRegEvent_Suspicious = 2,    /* 可疑告警 */
    WkdRegEvent_Malicious = 3,     /* 恶意告警 */
    WkdRegEvent_Blocked = 4,       /* 已阻断（由裁决链决定是否输出） */
    WkdRegEvent_Error = 5          /* 子系统错误 */
} WKD_REG_EVENT_KIND;

/* --- Notify 载荷 — 子系统向外部输出的统一事件结构
 * 字段按可序列化（文本/日志/ALPC）友好设计，
 * 文本行格式为 "Key=Value"。 --- */
typedef struct _WKD_REG_NOTIFY {
    ULONG              Engine;          /* WKD_REG_ENGINE_ID */
    ULONG              EventKind;       /* WKD_REG_EVENT_KIND */
    ULONG              Severity;        /* 0-4（对齐私有风险等级语义） */
    ULONG              EntryType;       /* WKD_REG_PERSISTENCE_TYPE（私有扩展，0=不适用） */

    WCHAR              Title[WKD_REG_PUBLIC_MAX_TITLE_CHARS];
    WCHAR              Description[WKD_REG_PUBLIC_MAX_DESC_CHARS];

    CHAR               MitreTechnique[32];   /* e.g. "T1547.001" */
    CHAR               MitreSubTechnique[32];

    ULONG              FieldCount;           /* 0-WKD_REG_PUBLIC_MAX_FIELDS */
    WCHAR              Fields[WKD_REG_PUBLIC_MAX_FIELDS][WKD_REG_PUBLIC_MAX_FIELD_CHARS];

    /* 时间戳（100ns 间隔，1601-01-01 纪元，FILETIME 语义） */
    ULONGLONG          Timestamp;
} WKD_REG_NOTIFY, * PWKD_REG_NOTIFY;

/* --- Notify 回调类型
 * 子系统在扫描/分析/告警/阻断/错误时同步调用；
 * 回调内禁止阻塞（子系统内部为串行执行路径）。 --- */
typedef
VOID
(*PFN_WKD_REG_NOTIFY_CALLBACK)(
    _In_ const PWKD_REG_NOTIFY Notify,
    _In_opt_ PVOID Context
    );

/* --- 初始化参数（全基元配置，不依赖私有类型） --- */
typedef struct _WKD_REG_INIT_PARAMS {
    /* 引擎启停 */
    BOOLEAN EnablePersistenceDetector;      /* 持久化检测     */
    BOOLEAN EnableSystemSettingsMonitor;    /* 系统设置监控   */
    BOOLEAN EnableRegistryAnalyzer;         /* 注册表取证分析 */
    BOOLEAN EnableRegistryMonitor;          /* 注册表实时裁决 */
    BOOLEAN EnableStartupAnalyzer;          /* 启动项审计     */

    /* 全局行为 */
    BOOLEAN BlockHighRiskOperations;        /* 是否允许内核侧阻断高危操作 */
    BOOLEAN ScanOnStartup;                  /* 初始化后是否立即异步全量扫描 */

    /* 持久化检测默认扫描范围（私有 WKD_REG_SCAN_SCOPE 数值，保持枚举序） */
    ULONG   PersistenceDefaultScope;        /* 0=Critical 1=Standard 2=Extended 3=Full 4=Custom */

    /* 性能 */
    BOOLEAN UseCaching;                     /* 启用签名/哈希缓存 */
    ULONG   CacheTtlSeconds;                /* 缓存有效期（秒） */
} WKD_REG_INIT_PARAMS, * PWKD_REG_INIT_PARAMS;

/* --- 子系统状态快照 --- */
typedef struct _WKD_REG_STATUS {
    BOOLEAN  Initialized;
    BOOLEAN  Started;                       /* 已进入运行态（回调管线已挂载） */

    BOOLEAN  PersistenceDetectorActive;
    BOOLEAN  SystemSettingsMonitorActive;
    BOOLEAN  RegistryAnalyzerActive;
    BOOLEAN  RegistryMonitorActive;
    BOOLEAN  StartupAnalyzerActive;

    BOOLEAN  Busy;                          /* 有扫描/分析在途 */
    ULONG    LastError;                     /* 最近一次 NTSTATUS 码 */
    ULONGLONG LastActivityTime;             /* FILETIME 语义时间戳 */
} WKD_REG_STATUS, * PWKD_REG_STATUS;

/* ==================================================
 * ═══ 点亮外部接口（子系统门面） ═══
 * 全部返回 NTSTATUS；失败时通过 Notify 回调(Error)
 * 携带补充信息。
 * ================================================== */

/* --- 生命周期 --- */
NTSTATUS
WkdRegistry_Initialize(
    _In_opt_ const WKD_REG_INIT_PARAMS* Params   /* NULL = 全默认 */
    );

VOID
WkdRegistry_Shutdown(
    VOID
    );

/* --- 运行态控制 --- */
NTSTATUS
WkdRegistry_Start(
    VOID
    );

VOID
WkdRegistry_Stop(
    VOID
    );

/* --- 输出面：Notify 回调注册（单槽位，重复注册覆盖） --- */
VOID
WkdRegistry_SetNotifyCallback(
    _In_opt_ PFN_WKD_REG_NOTIFY_CALLBACK Callback,  /* NULL = 清除 */
    _In_opt_ PVOID Context
    );

/* --- 控制命令（异步：调用立即返回，结果经 Notify 回调输出；
 *      在途扫描占用期间排队等待执行（BusyReleased 事件），
 *      关闭中返回 STATUS_INVALID_DEVICE_STATE） --- */
NTSTATUS
WkdRegistry_TriggerPersistenceScan(
    _In_ ULONG Scope          /* WKD_REG_SCAN_SCOPE 数值 */
    );

NTSTATUS
WkdRegistry_TriggerStartupAudit(
    VOID
    );

VOID
WkdRegistry_CancelActiveScan(
    VOID
    );

/* --- 状态与诊断 --- */
NTSTATUS
WkdRegistry_GetStatus(
    _Out_ PWKD_REG_STATUS Status
    );

NTSTATUS
WkdRegistry_GetStatistics(
    _Out_ PWKD_REG_NOTIFY Notify           /* 以 Info 事件输出各引擎统计摘要 */
    );

/* ==================================================
 * 备注：
 *  - 引擎级完整 API（PdXxx / RmXxx 等）仅由子系统
 *    编排逻辑使用，声明于本头上半部分私有段。
 *  - 内核侧交互（ALPC 事件注入/阻断决策）由驱动
 *    回调链（SpEngineAnalyzeRegistryAccess 等）驱动，
 *    上层无需感知，事件最终以 Notify 呈现。
 * ================================================== */