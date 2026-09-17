/**************************************************/
/*  WkDefender IOA — 内核利用 (KED) 模式检测器      */
/*                                                  */
/*  迁移自 ShadowStrike KernelExploitDetector       */
/*  (KernelExploitDetector.cpp/.hpp, v3.0.1)        */
/*  功能重实现 (C 重写), 非源码复制。                */
/*                                                  */
/*  独立模块: 纯用户态按需分析引擎 (SS 同定位,        */
/*  Exploits.md: "无内核接入接口, 按需调用").        */
/*  聚焦六大"模式"级检测:                            */
/*    ├─ 易受攻击驱动检测 (BYOVD)                   */
/*    │   内置 LOLDrivers 库 + MS 阻止列表 +          */
/*    │   自定义黑名单, 驱动文件哈希判定             */
/*    ├─ 驱动加载监控 (签名验证/未签名检测)          */
/*    ├─ 隐藏驱动扫描 (DKOM 三方交叉比对)            */
/*    ├─ IOCTL 滥用 (已知漏洞 IOCTL 表 +             */
/*    │   METHOD_NEITHER&FILE_ANY_ACCESS 启发式 +    */
/*    │   每进程速率限制)                            */
/*    ├─ KASLR 泄漏 (进程虚拟地址空间内核指针扫描)   */
/*    └─ BSOD 分析 (DUMP_HEADER64 解析,              */
/*        崩溃码分类 + 利用指示)                    */
/*                                                  */
/*  与 SS 源码的已知对齐缺口 (同样保留, 注释标注):   */
/*    - MDMP 结构化解析未实现 (仅遥测, 不伪造数据)   */
/*    - SiPolicy 结构化解析未实现 (仅探测 + 内置回退) */
/*    - BSOD 参数 2/3 模块提示为占位启发式           */
/*                                                  */
/*  裁剪声明 (C 版不做, 原因见各注释):               */
/*    - 在线 LOLDrivers 数据库拉取 (无网络依赖,      */
/*      使用内置 15 条基线库, 见 KedScanDriver)      */
/*    - 回调 5 类合并为统一 KED_DETECTED_CALLBACK    */
/*      (事件含 Kind 判别, 对齐同目录 LPE 风格)      */
/*    - Start/Stop/Pause/Resume/GetRecent* 查询      */
/*      (事件即时走回调, 统计聚合, 独立模块死代码)   */
/*                                                  */
/*  接入状态: 独立模块 (死代码), 未挂接 IoaObserve   */
/*  事件流水线。                                     */
/**************************************************/

#pragma once

#include "../../DefendTypes.h"

/**************************************************/
/*               容量常量                           */
/**************************************************/

#define KED_VERSION_STRING           "3.0.1"     /* VERSION 3.0.1 */

#define KED_MAX_DRIVER_SIZE          (20 * 1024 * 1024)  /* 驱动文件扫描上限 20MB (SS MAX_DRIVER_SIZE) */
#define KED_MAX_IOCTL_SAMPLE_SIZE    256         /* IOCTL 输入缓冲采样上限 (SS MAX_IOCTL_SAMPLE_SIZE) */
#define KED_IOCTL_RATE_LIMIT_PER_SEC 500         /* 每进程 IOCTL 速率上限 (SS IOCTL_RATE_LIMIT_PER_SEC) */
#define KED_IOCTL_RATE_WINDOW_MS     1000        /* 速率限制统计窗口 (SS IOCTL_RATE_WINDOW=1s) */
#define KED_MAX_RATE_SLOTS           1024        /* 速率限制 PID 槽位 (SS map 上限 4096, C 定长简化) */
#define KED_MAX_CALLBACKS            64          /* 回调上限 (SS MAX_CALLBACKS, C 版单槽, 保留常量对齐) */
#define KED_KASLR_LEAK_THRESHOLD     3           /* KASLR 泄漏判定阈值: 进程内存内核指针数 (SS) */
#define KED_MAX_DRIVER_COUNT         65536       /* EnumDeviceDrivers 扩容上限 (SS MAX_DRIVER_COUNT=64K) */
#define KED_MAX_DRIVER_ADDRS_INIT    1024        /* EnumDeviceDrivers 初始条目数 (SS INITIAL_DRIVER_COUNT) */
#define KED_SYSTEM_MODULE_CAP        (16 * 1024 * 1024)  /* NtQuerySystemInformation 缓冲上限 16MB (SS) */
#define KED_MIN_DUMP_HEADER_SIZE     4096        /* 崩溃转储最小头尺寸 (SS MIN_DUMP_HEADER_SIZE) */
#define KED_MAX_WHITELISTED_SIGNERS  8           /* 白名单签名者定长上限 (SS vector 无上限, C 定长) */
#define KED_MAX_BLACKLIST_ENTRIES    256         /* 自定义黑名单定长上限 (SS map, C 定长) */

/* 内核地址范围 (SS KERNEL_ADDRESS_MIN/MAX, 典型 x64) */
#define KED_KERNEL_ADDRESS_MIN       0xFFFF800000000000ULL
#define KED_KERNEL_ADDRESS_MAX       0xFFFFFFFFFFFFFFFFULL

/* SS 已知易受攻击驱动 IOCTL (KernelExploitConstants::VULNERABLE_IOCTLS) */
#define KED_VULNERABLE_IOCTLS_COUNT  6

/**************************************************/
/*               状态枚举 (对齐 SS)                 */
/**************************************************/

typedef enum _KED_STATUS {
    KedStatus_Uninitialized = 0,
    KedStatus_Initializing  = 1,
    KedStatus_Running       = 2,
    KedStatus_Paused        = 3,
    KedStatus_Stopping      = 4,
    KedStatus_Stopped       = 5,
    KedStatus_Error         = 6
} KED_STATUS, *PKED_STATUS;

/**************************************************/
/*               威胁类型枚举 (位标志)              */
/*  KernelThreatType 19 种位标志。          */
/**************************************************/

typedef enum _KED_THREAT_TYPE {
    KedThreat_Unknown                = 0,
    KedThreat_VulnerableDriverLoad   = 1 << 0,   /* BYOVD 攻击 */
    KedThreat_MaliciousDriverLoad    = 1 << 1,   /* 已知恶意驱动 */
    KedThreat_UnsignedDriverLoad     = 1 << 2,   /* 未签名驱动加载企图 */
    KedThreat_TokenStealing          = 1 << 3,   /* Token 窃取载荷 */
    KedThreat_NullPointerDeref       = 1 << 4,   /* 空指针解引用 */
    KedThreat_PoolCorruption         = 1 << 5,   /* 内核池损坏 */
    KedThreat_TypeConfusion          = 1 << 6,   /* 内核类型混淆 */
    KedThreat_IntegerOverflow        = 1 << 7,   /* 内核整数溢出 */
    KedThreat_UseAfterFree           = 1 << 8,   /* 内核 UAF */
    KedThreat_HiddenDriver           = 1 << 9,   /* Rootkit 隐藏驱动 */
    KedThreat_Ssdthooking            = 1 << 10,  /* SSDT 挂钩企图 */
    KedThreat_KaslrLeak              = 1 << 11,  /* KASLR 绕过企图 */
    KedThreat_CallbackTampering      = 1 << 12,  /* 回调篡改 */
    KedThreat_DkomAttack             = 1 << 13,  /* 直接内核对象操控 */
    KedThreat_PrivilegeEscalation    = 1 << 14,  /* 内核级提权 */
    KedThreat_ArbitraryRead          = 1 << 15,  /* 任意内核读 */
    KedThreat_ArbitraryWrite         = 1 << 16,  /* 任意内核写 */
    KedThreat_IoctlAbuse             = 1 << 17,  /* 可疑 IOCTL 使用 */
    KedThreat_DriverBlocklistViolation = 1 << 18 /* MS 阻止列表驱动 */
} KED_THREAT_TYPE, *PKED_THREAT_TYPE;

/**************************************************/
/*               驱动签名状态枚举                   */
/*  DriverSignatureStatus 10 种。           */
/**************************************************/

typedef enum _KED_SIGNATURE_STATUS {
    KedSig_Unknown           = 0,
    KedSig_ValidSigned       = 1,   /* 签名有效 */
    KedSig_InvalidSignature  = 2,   /* 签名无效 */
    KedSig_Unsigned          = 3,   /* 无签名 */
    KedSig_RevokedCertificate = 4,  /* 签名证书已吊销 */
    KedSig_ExpiredCertificate = 5,  /* 签名证书已过期 */
    KedSig_TestSigned        = 6,   /* 测试签名 */
    KedSig_WhqlSigned        = 7,   /* WHQL 签名 */
    KedSig_AttestationSigned = 8,   /* 证明签名 */
    KedSig_SelfSigned        = 9    /* 自签名证书 */
} KED_SIGNATURE_STATUS, *PKED_SIGNATURE_STATUS;

/**************************************************/
/*               驱动漏洞类别枚举                   */
/*  VulnerabilityClass。                    */
/**************************************************/

typedef enum _KED_VULN_CLASS {
    KedVuln_Unknown               = 0,
    KedVuln_ArbitraryMemoryRead   = 1,   /* 任意内核内存读 */
    KedVuln_ArbitraryMemoryWrite  = 2,   /* 任意内核内存写 */
    KedVuln_ArbitraryMsrAccess    = 3,   /* MSR 读写 */
    KedVuln_ArbitraryPortAccess   = 4,   /* IO 端口访问 */
    KedVuln_ArbitraryPhysAccess   = 5,   /* 物理内存访问 */
    KedVuln_PrivilegeEscalation   = 6,   /* 通用提权 */
    KedVuln_CodeExecution         = 7,   /* 内核代码执行 */
    KedVuln_InformationDisclosure = 8,   /* 信息泄露 */
    KedVuln_DenialOfService       = 9,   /* 系统崩溃 */
    KedVuln_Multiple              = 255  /* 多漏洞组合 */
} KED_VULN_CLASS, *PKED_VULN_CLASS;

/**************************************************/
/*               响应动作枚举 (对齐 SS)             */
/**************************************************/

typedef enum _KED_DETECTION_ACTION {
    KedAction_None      = 0,
    KedAction_Alert     = 1,
    KedAction_Block     = 2,
    KedAction_Terminate = 3,
    KedAction_Quarantine = 4
} KED_DETECTION_ACTION, *PKED_DETECTION_ACTION;

/**************************************************/
/*               崩溃 (BSOD) 类别枚举              */
/*  BugCheckCategory 7 种。                 */
/**************************************************/

typedef enum _KED_BUGCHECK_CATEGORY {
    KedBcc_Unknown          = 0,
    KedBcc_MemoryCorruption = 1,
    KedBcc_NullDereference  = 2,
    KedBcc_PoolCorruption   = 3,
    KedBcc_StackOverflow    = 4,
    KedBcc_InvalidAccess    = 5,
    KedBcc_DriverFault      = 6,
    KedBcc_ExploitIndicator = 7
} KED_BUGCHECK_CATEGORY, *PKED_BUGCHECK_CATEGORY;

/**************************************************/
/*               事件类别 (C 版扩展, Kind 判别)     */
/**************************************************/

typedef enum _KED_EVENT_KIND {
    KedEvent_DriverScan   = 0,   /* 驱动扫描 (附 DriverInfo) */
    KedEvent_HiddenDriver = 1,   /* 隐藏驱动 (附 DriverInfo) */
    KedEvent_Ioctl        = 2,   /* IOCTL 滥用 (附 IoctlInfo) */
    KedEvent_KaslrLeak    = 3,   /* KASLR 泄漏 */
    KedEvent_BugCheck     = 4,   /* BSOD 分析 (附 BugCheckInfo) */
    KedEvent_Error        = 5    /* 模块错误 */
} KED_EVENT_KIND, *PKED_EVENT_KIND;

/**************************************************/
/*               驱动信息结构                       */
/*  DriverInfo 核心字段 (去 JSON/optional/  */
/*  向量, 定长缓冲)。                              */
/**************************************************/

typedef struct _KED_DRIVER_INFO {
    WCHAR               FileName[DEF_MAX_IMAGE_NAME];  /* 驱动文件名 */
    WCHAR               FilePath[DEF_MAX_PATH * 2];    /* 完整文件路径 */
    WCHAR               ServiceName[256];              /* 服务名 (枚举时可为空) */
    ULONG64             BaseAddress;                   /* 内核基址 (枚举时填充) */
    ULONG               Size;                          /* 文件大小 */
    CHAR                Sha256Hex[64 + 1];             /* SHA256 大写 hex */
    CHAR                Sha1Hex[40 + 1];               /* SHA1 大写 hex */
    CHAR                Md5Hex[32 + 1];                /* MD5 大写 hex */
    KED_SIGNATURE_STATUS SignatureStatus;               /* 签名验证状态 */
    WCHAR               SignerName[256];               /* 签名者名称 */
    WCHAR               FileVersion[64];               /* 文件版本 */
    WCHAR               ProductName[128];              /* 产品名 */
    WCHAR               CompanyName[128];              /* 公司名 */
    WCHAR               Description[256];              /* 文件描述 */
    BOOLEAN             IsMicrosoftBlocked;            /* MS 阻止列表命中 */
    BOOLEAN             IsLolDriver;                   /* LOLDrivers 库命中 */
    BOOLEAN             IsVulnerable;                  /* 任一库判定易受攻击 */
    KED_VULN_CLASS      VulnerabilityClass;            /* 漏洞类别 */
    CHAR                CveIds[256];                   /* 逗号分隔 CVE 列表 */
    CHAR                ThreatIntelSource[64];         /* 情报来源 (LOLDrivers/MS Blocklist/...) */
    ULONG               LoaderProcessId;               /* 加载者 PID */
} KED_DRIVER_INFO, *PKED_DRIVER_INFO;

/**************************************************/
/*               IOCTL 事件结构                     */
/*  IOCTLEventInfo 核心字段。               */
/**************************************************/

typedef struct _KED_IOCTL_INFO {
    ULONG               ProcessId;
    WCHAR               ProcessName[DEF_MAX_IMAGE_NAME];
    WCHAR               ProcessPath[DEF_MAX_PATH * 2];
    WCHAR               DevicePath[DEF_MAX_PATH];      /* 目标设备路径 */
    WCHAR               DriverName[DEF_MAX_IMAGE_NAME];/* 目标驱动 (设备路径尾部) */
    ULONG               IoctlCode;                     /* IOCTL 码 */
    ULONG               InputBufferSize;               /* 输入缓冲大小 */
    ULONG               OutputBufferSize;              /* 输出缓冲大小 */
    UCHAR               InputSample[KED_MAX_IOCTL_SAMPLE_SIZE]; /* 输入样本 (前 256B) */
    ULONG               InputSampleSize;               /* 实际样本长度 */
    BOOLEAN             IsSuspicious;                  /* 是否判定可疑 */
    CHAR                SuspicionReason[128];          /* 可疑原因 */
    KED_THREAT_TYPE     ThreatType;                    /* 关联威胁类型 */
    BOOLEAN             WasBlocked;                    /* 是否拦截 */
} KED_IOCTL_INFO, *PKED_IOCTL_INFO;

/**************************************************/
/*               BSOD 分析结果结构                  */
/*  BugCheckAnalysis 核心字段。             */
/**************************************************/

typedef struct _KED_BUGCHECK_INFO {
    ULONG               BugCheckCode;                  /* 崩溃码 */
    CHAR                BugCheckName[64];              /* 崩溃码名称 */
    KED_BUGCHECK_CATEGORY Category;                    /* 崩溃类别 */
    ULONG64             Parameters[4];                 /* 崩溃参数 1..4 */
    ULONG64             FaultingAddress;               /* 故障地址 (参数 1) */
    WCHAR               FaultingModule[DEF_MAX_IMAGE_NAME]; /* 故障模块 */
    BOOLEAN             IsExploitIndicator;            /* 是否利用指示 */
    CHAR                Summary[256];                  /* 分析摘要 */
    WCHAR               DumpFilePath[DEF_MAX_PATH * 2];/* 转储文件路径 */
} KED_BUGCHECK_INFO, *PKED_BUGCHECK_INFO;

/**************************************************/
/*               统一检测事件结构                   */
/*  KernelExploitEvent 核心字段, 以 Kind   */
/*  判别附带的子信息 (union), 去 JSON/optional/     */
/*  向量, 定长缓冲。                               */
/**************************************************/

typedef struct _KED_EVENT {
    ULONG               EventId;                       /* 全局自增 ID (替代 SS 字符串 ID) */
    KED_EVENT_KIND      Kind;                          /* 事件类别 */
    KED_THREAT_TYPE     ThreatType;                    /* 威胁类型 */
    ULONG               SourceProcessId;               /* 源进程 PID (0=系统级) */
    WCHAR               SourceProcessName[DEF_MAX_IMAGE_NAME];
    WCHAR               SourceProcessPath[DEF_MAX_PATH * 2];
    ULONG               ConfidenceScore;               /* [0,100] */
    KED_DETECTION_ACTION Action;                       /* 响应动作 */
    BOOLEAN             WasBlocked;                    /* 是否拦截 */
    CHAR                TargetAddressHex[24];          /* 目标内核地址 (人读化) */
    WCHAR               Details[512];                  /* 人类可读细节 */
    LARGE_INTEGER       Timestamp;

    union {
        KED_DRIVER_INFO Driver;                        /* Kind=DriverScan/HiddenDriver */
        KED_IOCTL_INFO  Ioctl;                         /* Kind=Ioctl */
        KED_BUGCHECK_INFO BugCheck;                    /* Kind=BugCheck */
    } Info;
} KED_EVENT, *PKED_EVENT;

/**************************************************/
/*               配置结构                           */
/*  KernelExploitDetectorConfiguration      */
/*  (去 vector<wstring>, 定长数组)。               */
/**************************************************/

typedef struct _KED_CONFIG {
    BOOLEAN         EnableDriverMonitoring;     /* 驱动监控总开关 */
    BOOLEAN         BlockVulnerableDrivers;     /* 拦截易受攻击驱动 */
    BOOLEAN         BlockUnsignedDrivers;       /* 拦截未签名驱动 (仅标记) */
    BOOLEAN         EnableLolDriversDatabase;   /* 启用内置 LOLDrivers 库 */
    BOOLEAN         EnableMicrosoftBlocklist;   /* 启用 MS 阻止列表 */
    BOOLEAN         MonitorIoctl;               /* IOCTL 监控开关 */
    BOOLEAN         BlockSuspiciousIoctl;       /* 拦截可疑 IOCTL */
    BOOLEAN         DetectKaslrLeaks;           /* KASLR 泄漏检测开关 */
    BOOLEAN         AnalyzeBsodDumps;           /* BSOD 分析开关 */
    BOOLEAN         VerboseLogging;             /* 详细日志 */

    WCHAR           WhitelistedSigners[KED_MAX_WHITELISTED_SIGNERS][256];
    ULONG           WhitelistedSignerCount;     /* 有效白名单签名者数 */
} KED_CONFIG, *PKED_CONFIG;

#define KED_DEFAULT_CONFIG                                              \
    { TRUE, TRUE, FALSE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, FALSE,    \
      { { 0 } }, 0 }

/**************************************************/
/*               统计结构                           */
/*  KernelExploitStatistics 12 个计数器。  */
/**************************************************/

typedef struct _KED_STATISTICS {
    volatile LONG   DriversScanned;             /* 已扫描驱动数 */
    volatile LONG   DriversBlocked;             /* 已拦截驱动数 */
    volatile LONG   VulnerableDriversDetected;  /* 易受攻击驱动命中 */
    volatile LONG   LolDriversDetected;         /* LOLDrivers 命中 */
    volatile LONG   UnsignedDriversDetected;    /* 未签名驱动命中 */
    volatile LONG   IoctlEventsAnalyzed;        /* 已分析 IOCTL 数 */
    volatile LONG   SuspiciousIoctlsDetected;   /* 可疑 IOCTL 命中 */
    volatile LONG   KaslrLeaksDetected;         /* KASLR 泄漏命中 */
    volatile LONG   ExploitAttemptsBlocked;     /* 已拦截利用企图 */
    volatile LONG   BugChecksAnalyzed;          /* 已分析 BSOD 数 */
    volatile LONG   HiddenDriversDetected;      /* 隐藏驱动命中 */
    volatile LONG   EventsReported;             /* 上报事件总数 */
} KED_STATISTICS, *PKED_STATISTICS;

/**************************************************/
/*               检测回调                           */
/*  统一回调 (5 类回调语义, 事件含 Kind):  */
/*  DriverScan/HiddenDriver → DriverInfo           */
/*  Ioctl → IoctlInfo / BugCheck → BugCheckInfo    */
/*  KaslrLeak → 通用字段 / Error → Details         */
/**************************************************/

typedef VOID (*KED_DETECTED_CALLBACK)(
    _In_    const KED_EVENT* Event,
    _In_opt_ PVOID          Context
    );

/**************************************************/
/*               生命周期                           */
/**************************************************/

NTSTATUS
KedInitialize(
    _In_opt_ const KED_CONFIG* Config          /* NULL = KED_DEFAULT_CONFIG */
    );

VOID
KedShutdown(VOID);

BOOLEAN
KedIsInitialized(VOID);

KED_STATUS
KedGetStatus(VOID);

PCSTR
KedGetVersionString(VOID);

/**************************************************/
/*               驱动分析                           */
/**************************************************/

/*
 * KedScanDriver — 单驱动文件漏洞扫描 (ScanDriver)。
 *
 * 计算 SHA256/SHA1/MD5, 验证签名 (WinVerifyTrust), 提取版本信息,
 * 查 LOLDrivers/MS 阻止列表/自定义黑名单三库, 填充 Info。
 * 大小超 KED_MAX_DRIVER_SIZE (20MB) 返回 STATUS_FILE_TOO_LARGE。
 */
NTSTATUS
KedScanDriver(
    _In_  PCWSTR          DriverPath,
    _Out_ PKED_DRIVER_INFO Info
    );

BOOLEAN
KedIsVulnerableDriver(
    _In_ PCSTR Sha256Hex
    );

BOOLEAN
KedIsMicrosoftBlocked(
    _In_ PCSTR Sha256Hex
    );

BOOLEAN
KedIsLolDriver(
    _In_ PCSTR Sha256Hex
    );

/*
 * KedGetDriverCves — 查询驱动 SHA256 对应的 CVE 列表 (逗号分隔)。
 * 返回写入 CveBuffer 的字符数 (含尾 0), 0 表示无匹配。
 */
ULONG
KedGetDriverCves(
    _In_  PCSTR  Sha256Hex,
    _Out_writes_to_opt_(CveBufferCch, return) PCHAR CveBuffer,
    _In_  ULONG  CveBufferCch
    );

/*
 * KedEnumerateLoadedDrivers — 枚举已加载内核驱动 (对齐 SS
 * EnumerateLoadedDrivers): EnumDeviceDrivers 两遍扩容 (cap 64K) +
 * GetDeviceDriverFileNameW + 逐驱动 KedScanDriver。
 * 返回成功填写的驱动数 (写入 Drivers 缓冲)。
 */
ULONG
KedEnumerateLoadedDrivers(
    _Out_writes_to_opt_(MaxDrivers, *pReturned) PKED_DRIVER_INFO Drivers,
    _In_                               ULONG            MaxDrivers,
    _Out_opt_                          PULONG           pReturned
    );

/*
 * KedFindHiddenDrivers — 隐藏驱动 (Rootkit/DKOM) 检测 (对齐 SS
 * FindHiddenDrivers): 三方交叉比对 = EnumDeviceDrivers vs SCM 服务
 * 注册表 vs NtQuerySystemInformation(SystemModuleInformation=11)。
 * 内核模块对 EnumDeviceDrivers 不可见即疑似隐藏。
 */
ULONG
KedFindHiddenDrivers(
    _Out_writes_to_opt_(MaxDrivers, *pReturned) PKED_DRIVER_INFO Drivers,
    _In_                               ULONG            MaxDrivers,
    _Out_opt_                          PULONG           pReturned
    );

/**************************************************/
/*               黑名单管理                         */
/**************************************************/

VOID
KedAddToBlacklist(
    _In_ PCWSTR Sha256Hex,               /* 64 位 hex */
    _In_opt_ PCWSTR Reason
    );

VOID
KedRemoveFromBlacklist(
    _In_ PCWSTR Sha256Hex
    );

VOID
KedWhitelistSigner(
    _In_ PCWSTR SignerName
    );

BOOLEAN
KedIsSignerWhitelisted(
    _In_ PCWSTR SignerName
    );

/**************************************************/
/*               IOCTL 监控                        */
/**************************************************/

/*
 * KedAnalyzeIoctl — 分析一次 DeviceIoControl 调用 (对齐 SS
 * AnalyzeIOCTL): 每进程速率限制 (500/s, 1s 窗口) + 已知漏洞
 * IOCTL 表 + METHOD_NEITHER&FILE_ANY_ACCESS 启发式。可疑且
 * 配置拦截时上报 Block 事件。
 */
NTSTATUS
KedAnalyzeIoctl(
    _In_      ULONG       ProcessId,
    _In_      PCWSTR      DevicePath,
    _In_      ULONG       IoctlCode,
    _In_reads_bytes_opt_(InputSize) const UCHAR* InputBuffer,
    _In_      ULONG       InputSize,
    _Out_opt_ PKED_IOCTL_INFO Event
    );

BOOLEAN
KedIsSuspiciousIoctl(
    _In_ ULONG IoctlCode
    );

/**************************************************/
/*               KASLR 分析                        */
/**************************************************/

/*
 * KedDetectKaslrLeak — 检测进程虚拟地址空间中的内核地址泄露
 * (DetectKASLRLeak): VirtualQueryEx 遍历 + ReadProcessMemory
 * 每区采样 4KB, 逐 8 字节比对内核地址范围, 命中 >= 3 判定可疑。
 */
BOOLEAN
KedDetectKaslrLeak(
    _In_ ULONG ProcessId
    );

BOOLEAN
KedIsKernelAddress(
    _In_ ULONG64 Address
    );

/**************************************************/
/*               BSOD 分析                         */
/**************************************************/

/*
 * KedAnalyzeBsodDump — 分析崩溃转储 (AnalyzeBSODDump):
 * 区分 MDMP (仅遥测, 不伪造) 与 DUMP_HEADER64 (PAGE+DUMP/DU64),
 * 0x38 取 BugCheckCode, 0x40 起 4 参数, 已知崩溃码分类。
 */
NTSTATUS
KedAnalyzeBsodDump(
    _In_  PCWSTR             DumpPath,
    _Out_ PKED_BUGCHECK_INFO Analysis
    );

/**************************************************/
/*               回调 / 统计                        */
/**************************************************/

VOID
KedRegisterCallback(
    _In_opt_ KED_DETECTED_CALLBACK Callback,
    _In_opt_ PVOID                 Context
    );

VOID
KedGetStatistics(
    _Out_ PKED_STATISTICS Stats
    );

VOID
KedResetStatistics(VOID);

/**************************************************/
/*               诊断                              */
/**************************************************/

BOOLEAN
KedSelfTest(VOID);

/**************************************************/
/*               工具函数                           */
/*  Get*Name 名称解析函数族。               */
/**************************************************/

PCSTR
KedGetThreatTypeName(
    _In_ KED_THREAT_TYPE Type
    );

PCSTR
KedGetSignatureStatusName(
    _In_ KED_SIGNATURE_STATUS Status
    );

PCSTR
KedGetVulnerabilityClassName(
    _In_ KED_VULN_CLASS Class
    );

PCSTR
KedGetBugCheckCategoryName(
    _In_ KED_BUGCHECK_CATEGORY Category
    );

PCSTR
KedGetBugCheckCodeName(
    _In_ ULONG BugCheckCode
    );