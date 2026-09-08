/**************************************************/
/*  WkDefender Agent — 内存保护决策引擎              */
/*  (MemoryProtection)                              */
/*                                                   */
/*  纯 C 实现 ShadowStrike MemoryProtection.cpp/hpp  */
/*  迁移。职责：对 Agent 进程内存提供企业级保护：     */
/*   - 进程加固（ASLR/DEP/CFG 校验 + 缓解策略）       */
/*   - 安全内存分配（Secure/Encrypted/Locked/Guarded）*/
/*   - 内存区域保护与完整性监控（CRC32 + SHA-256）    */
/*   - 内联 hook 特征检测（E9/EB/FF25 等）            */
/*   - 反转储（PE 头混淆）                           */
/*   - 堆保护（终止于损坏 + 完整性校验 + 堆信息）     */
/*   - 栈保护（金丝雀校验 + 栈信息）                 */
/*   - 内存查询（VirtualQuery + W^X 强制）           */
/*   - 事件 / 统计 / 历史 / 报告 / 自检              */
/*                                                   */
/*  架构取舍（对齐 Pp 与 Ad 既有先例）：              */
/*   - 单例 → 引擎句柄显式传参（AC_MEMORY_INTEGRITY_ENGINE）。         */
/*   - SS 授权令牌 → Agent 内部 API 免鉴权。          */
/*   - std::vector/map/string → 定长数组 + 计数。     */
/*   - std::function 回调 → 函数指针 + Context。      */
/*   - SecureAllocator 模板 / RAII → C 语义替代       */
/*     （MpSecureZero / MpAllocateSecure）。          */
/*   - "Encrypted" 语义与 SS 一致：实际为             */
/*     Locked + 标志（诚实表达，不做真加密）。        */
/*   - W^X 强制保留：SetPageProtection 拒绝 RWX。     */
/*                                                   */
/*  生命周期：MpInitialize -> [AcStartMemoryIntegralityProtection 启监视线程] -> */
/*   (运行) -> [MpStop] -> MpShutdown -> MpCleanup。  */
/*  全部函数 PASSIVE_LEVEL。                          */
/*  编码：UTF-8 with BOM（铁律）                     */
/**************************************************/

#pragma once

#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <stdint.h>

/* 进程域模块视图（WKD_MODULE_INSTANCE：进程内映射视图 = ImageBase + 全局模块本体）。
 * 2026-09-06 代码完整性保护策略 Y：AcEnableCodeIntegrityProtection 以实例为对象保护代码。 */
#include "../Process/ProcessModule.h"

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************/
/*               版本标识                           */
/**************************************************/

#define MP_VERSION_MAJOR   3
#define MP_VERSION_MINOR   0
#define MP_VERSION_PATCH   0

/**************************************************/
/*               常量定义                           */
/*  对齐 ShadowStrike MemoryProtectionConstants。   */
/**************************************************/

#define MP_MAX_SECURE_ALLOCATIONS       10000   /* 安全分配追踪上限 */
#define MP_MAX_PROTECTED_REGIONS        500     /* 受保护区域上限 */
#define MP_MAX_INTEGRITY_REGIONS        100     /* 完整性校验区域上限 */
#define MP_DEFAULT_SECURE_POOL_SIZE     (1 * 1024 * 1024)     /* 默认安全池 1MB */
#define MP_MAX_SECURE_POOL_SIZE         (100 * 1024 * 1024)   /* 最大安全池 100MB */
#define MP_MIN_SECURE_ALLOCATION        16      /* 最小安全分配 16B */
#define MP_MAX_SECURE_ALLOCATION        (16 * 1024 * 1024)    /* 最大安全分配 16MB */
#define MP_SECURE_ALLOCATION_ALIGNMENT  16      /* 安全分配对齐 */

#define MP_HEAP_CANARY_MAGIC            0xFEEDFACE12345678ULL /* 堆金丝雀魔数 */
#define MP_GUARD_PAGE_FILL              0xCD                  /* 守卫页填充 */
#define MP_FREE_MEMORY_FILL             0xDD                  /* 释放填充 */
#define MP_UNINIT_MEMORY_FILL           0xCC                  /* 未初始化填充 */

#define MP_INTEGRITY_CHECK_INTERVAL_MS  30000   /* 完整性校验间隔 */
#define MP_HEAP_VALIDATION_INTERVAL_MS  60000   /* 堆校验间隔 */

#define MP_CRC32_SIZE                   4       /* CRC32 摘要长度 */
#define MP_SHA256_SIZE                  32      /* SHA-256 摘要长度 */

#define MP_ENCRYPTION_KEY_SIZE          32      /* AES-256 密钥 */
#define MP_ENCRYPTION_IV_SIZE           16      /* AES IV */
#define MP_ENCRYPTION_BLOCK_SIZE        16      /* AES 块 */

#define MP_PAGE_SIZE                    4096    /* 标准页 */
#define MP_LARGE_PAGE_SIZE              (2 * 1024 * 1024)  /* 大页 2MB */

/* ID / 描述长度（C 化 string/wstring 定长缓冲） */
#define MP_MAX_ID_LENGTH                64      /* 区域 ID 最大字符数 */
#define MP_MAX_DESCRIPTION              256     /* 描述最大字符数 */
#define MP_MAX_MODULE_NAME              260     /* 模块名最大字符数（MAX_PATH） */
#define MP_MAX_EVENT_CONTEXT_ENTRIES    8       /* 事件附加上下文键值对上限 */

/* 回调与历史容量 */
#define MP_MAX_CALLBACKS                32      /* 每类回调注册上限 */
#define MP_MAX_EVENT_HISTORY            10000   /* 事件历史上限（对齐 SS） */
#define MP_EVENT_HISTORY_TRIM           5000    /* 超限时一次删除条数（对齐 SS） */
#define MP_MAX_HEAPS                    256     /* 堆枚举上限（对齐 SS） */

/**************************************************/
/*               本地状态码别名                     */
/*  参照 AccessControlEngine.h 惯例，统一映射到确定存在  */
/*  的 NTSTATUS 值，避免跨 SDK 编译差异。          */
/**************************************************/

#ifndef MP_STATUS_ALREADY_EXISTS
#define MP_STATUS_ALREADY_EXISTS   STATUS_UNSUCCESSFUL   /* 语义：区域/分配已存在 */
#endif

/**************************************************/
/*               保护级别枚举                       */
/*  对齐 SS MemoryProtectionLevel。                 */
/**************************************************/

typedef enum _MP_PROTECTION_LEVEL {
    MpLevelDisabled  = 0,   /* 无保护（仅测试） */
    MpLevelMinimal   = 1,   /* 基础保护 */
    MpLevelStandard  = 2,   /* 标准保护（默认） */
    MpLevelEnhanced  = 3,   /* 增强保护 */
    MpLevelMaximum   = 4    /* 最大保护 */
} MP_PROTECTION_LEVEL, *PMP_PROTECTION_LEVEL;

/**************************************************/
/*               内存区域类型枚举                   */
/*  对齐 SS MemoryRegionType。                     */
/**************************************************/

typedef enum _MP_REGION_TYPE {
    MpRegionUnknown    = 0,   /* 未知 */
    MpRegionCode       = 1,   /* 可执行代码 */
    MpRegionReadOnly   = 2,   /* 只读数据 */
    MpRegionReadWrite  = 3,   /* 读写数据 */
    MpRegionStack      = 4,   /* 线程栈 */
    MpRegionHeap       = 5,   /* 堆内存 */
    MpRegionMapped     = 6,   /* 内存映射文件 */
    MpRegionReserved   = 7,   /* 保留内存 */
    MpRegionGuard      = 8    /* 守卫页 */
} MP_REGION_TYPE, *PMP_REGION_TYPE;

/**************************************************/
/*               页保护位标志                       */
/*  对齐 SS PageProtection（值即 Windows PAGE_*，   */
/*  除 TargetsNoUpdate 对齐 SS 原文 0x40000000，    */
/*  Agent 侧不消费该位）。                         */
/**************************************************/

typedef enum _MP_PAGE_PROTECTION {
    MpPageNoAccess         = 0x00000001,
    MpPageReadOnly         = 0x00000002,
    MpPageReadWrite        = 0x00000004,
    MpPageWriteCopy        = 0x00000008,
    MpPageExecute          = 0x00000010,
    MpPageExecuteRead      = 0x00000020,
    MpPageExecuteReadWrite = 0x00000040,
    MpPageExecuteWriteCopy = 0x00000080,
    MpPageGuard            = 0x00000100,
    MpPageNoCache          = 0x00000200,
    MpPageWriteCombine     = 0x00000400,
    MpPageTargetsInvalid   = 0x40000000,
    MpPageTargetsNoUpdate  = 0x40000000   /* 对齐 SS 原文；Windows 规范值 0x80000000 */
} MP_PAGE_PROTECTION, *PMP_PAGE_PROTECTION;

/**************************************************/
/*               分配类型枚举                       */
/*  对齐 SS AllocationType。                       */
/**************************************************/

typedef enum _MP_ALLOCATION_TYPE {
    MpAllocStandard   = 0,   /* 标准分配 */
    MpAllocSecure     = 1,   /* 安全（释放清零） */
    MpAllocEncrypted  = 2,   /* 静止加密（实现=加锁+标志） */
    MpAllocLocked     = 3,   /* 不可换页 */
    MpAllocGuarded    = 4    /* 带守卫页 */
} MP_ALLOCATION_TYPE, *PMP_ALLOCATION_TYPE;

/**************************************************/
/*               完整性状态枚举                     */
/*  对齐 SS MemoryIntegrityStatus。                */
/**************************************************/

typedef enum _MP_INTEGRITY_STATUS {
    MpIntegrityUnknown   = 0,
    MpIntegrityValid     = 1,
    MpIntegrityModified  = 2,
    MpIntegrityCorrupted = 3,
    MpIntegrityHooked    = 4
} MP_INTEGRITY_STATUS, *PMP_INTEGRITY_STATUS;

/**************************************************/
/*               保护事件类型位标志                 */
/*  对齐 SS MemoryProtectionEventType。            */
/**************************************************/

typedef enum _MP_EVENT_TYPE {
    MpEventNone              = 0x00000000,
    MpEventMemoryWrite       = 0x00000001,
    MpEventMemoryRead        = 0x00000002,
    MpEventPermissionChange  = 0x00000004,
    MpEventAllocationAttempt = 0x00000008,
    MpEventFreeAttempt       = 0x00000010,
    MpEventIntegrityViolation= 0x00000020,
    MpEventCanaryCorruption  = 0x00000040,
    MpEventHeapCorruption    = 0x00000080,
    MpEventHookDetected      = 0x00000200,
    MpEventDumpAttempt       = 0x00000400,
    MpEventScanDetected      = 0x00000800,
    MpEventAll               = 0xFFFFFFFF
} MP_EVENT_TYPE, *PMP_EVENT_TYPE;

/**************************************************/
/*               保护响应位标志                     */
/*  对齐 SS MemoryProtectionResponse。             */
/**************************************************/

typedef enum _MP_RESPONSE {
    MpResponseNone       = 0x00000000,
    MpResponseLog        = 0x00000001,
    MpResponseAlert      = 0x00000002,
    MpResponseBlock      = 0x00000004,
    MpResponseRepair     = 0x00000008,
    MpResponseTerminate  = 0x00000010,
    MpResponseEscalate   = 0x00000020,
    MpResponsePassive    = (MpResponseLog | MpResponseAlert),
    MpResponseActive     = (MpResponseLog | MpResponseAlert | MpResponseBlock | MpResponseRepair),
    MpResponseAggressive = (MpResponseLog | MpResponseAlert | MpResponseBlock | MpResponseRepair | MpResponseTerminate)
} MP_RESPONSE, *PMP_RESPONSE;

/**************************************************/
/*               模块状态枚举                       */
/*  对齐 SS ModuleStatus（SecurityEnums 规范）。    */
/**************************************************/

typedef enum _MP_MODULE_STATUS {
    MpModuleUninitialized = 0,
    MpModuleInitializing,
    MpModuleRunning,
    MpModuleStopping,
    MpModuleStopped,
    MpModuleError
} MP_MODULE_STATUS, *PMP_MODULE_STATUS;

/**************************************************/
/*               配置结构                           */
/*  对齐 SS MemoryProtectionConfiguration。        */
/**************************************************/

typedef struct _MP_CONFIGURATION {
    /* 保护级别 */
    MP_PROTECTION_LEVEL Level;

    /* 进程加固开关（EnableASLR/EnableDEP/EnableCFG）已于 2026-09-08 迁出至
     * ProcessProtection 配置（PPP_CONFIGURATION），本配置不再持有。 */

    /* 安全分配 */
    BOOLEAN EnableSecureAllocator;
    SIZE_T  SecurePoolSize;

    /* 反转储 / 代码完整性 */
    BOOLEAN EnableAntiDump;
    BOOLEAN EnableCodeIntegrity;
    ULONG   IntegrityCheckIntervalMs;    /* 完整性校验间隔（毫秒） */

    /* 堆 / 守卫页 */
    BOOLEAN EnableHeapProtection;
    BOOLEAN EnableGuardPages;

    /* 敏感数据 / 反扫描 */
    BOOLEAN EnableMemoryEncryption;
    BOOLEAN EnableAntiScan;

    /* 响应与遥测 */
    MP_RESPONSE DefaultResponse;
    BOOLEAN     VerboseLogging;
    BOOLEAN     SendTelemetry;
} MP_CONFIGURATION, *PMP_CONFIGURATION;

/**************************************************/
/*               受保护区域信息                     */
/*  对齐 SS ProtectedRegion（string→定长缓冲）。   */
/**************************************************/

typedef struct _MP_PROTECTED_REGION {
    CHAR                Id[MP_MAX_ID_LENGTH];   /* 区域 ID */
    ULONG_PTR           BaseAddress;            /* 基址 */
    SIZE_T              Size;                   /* 大小 */
    MP_REGION_TYPE      Type;                   /* 区域类型 */
    ULONG               Protection;             /* 页保护（Windows PAGE_*） */
    ULONG               ExpectedCrc32;          /* 期望 CRC32 */
    UCHAR               ExpectedSha256[MP_SHA256_SIZE]; /* 期望 SHA-256 */
    ULONG               CurrentCrc32;           /* 当前 CRC32 */
    MP_INTEGRITY_STATUS Status;                 /* 完整性状态 */
    BOOLEAN             IsCritical;             /* 是否关键区域 */
    LARGE_INTEGER       ProtectedSince;         /* 保护起始时间 */
    LARGE_INTEGER       LastVerified;           /* 最近校验时间 */
    ULONG_PTR           ProcessId;              /* 所属进程（0=本进程/EDR 自身，2026-09-08
                                                 * 受保护进程链消费：跨进程区域哈希/校验依据） */
    ULONG               ViolationCount;         /* 违规计数 */
    WCHAR               ModuleName[MP_MAX_MODULE_NAME]; /* 模块名（如适用） */
    CHAR                SectionName[8 + 1];     /* 节名（self_ 前缀除外） */
} MP_PROTECTED_REGION, *PMP_PROTECTED_REGION;

/**************************************************/
/*               安全分配信息                       */
/*  对齐 SS SecureAllocation。                     */
/**************************************************/

typedef struct _MP_SECURE_ALLOCATION {
    PVOID               Address;        /* 分配地址（用户指针） */
    SIZE_T              Size;           /* 请求大小 */
    SIZE_T              AllocatedSize;  /* 实际分配大小（含守卫页） */
    MP_ALLOCATION_TYPE  Type;           /* 分配类型 */
    BOOLEAN             IsLocked;       /* 是否已锁定（不可换页） */
    BOOLEAN             IsEncrypted;    /* 是否"加密"标志（SS 语义=加锁） */
    BOOLEAN             HasGuardPages;  /* 是否带守卫页 */
    LARGE_INTEGER       AllocatedAt;    /* 分配时间 */
    ULONG_PTR           CallSite;       /* 分配调用点（调试用） */
    ULONG               AllocatorThreadId;  /* 分配线程 ID */
} MP_SECURE_ALLOCATION, *PMP_SECURE_ALLOCATION;

/**************************************************/
/*               保护事件                           */
/*  对齐 SS ProtectionEvent（context→定长键值对）。*/
/**************************************************/

typedef struct _MP_EVENT_CONTEXT_ENTRY {
    CHAR    Key[32];        /* 键 */
    CHAR    Value[96];      /* 值 */
} MP_EVENT_CONTEXT_ENTRY, *PMP_EVENT_CONTEXT_ENTRY;

typedef struct _MP_PROTECTION_EVENT {
    ULONG64                 EventId;            /* 事件 ID */
    MP_EVENT_TYPE           Type;               /* 事件类型 */
    LARGE_INTEGER           Timestamp;          /* 时间戳 */
    ULONG_PTR               Address;            /* 关联地址 */
    SIZE_T                  Size;               /* 关联大小 */
    CHAR                    RegionId[MP_MAX_ID_LENGTH]; /* 关联区域 ID */
    ULONG                   SourceProcessId;    /* 源进程 ID */
    ULONG                   SourceThreadId;     /* 源线程 ID */
    WCHAR                   SourceProcessName[64];  /* 源进程名 */
    MP_RESPONSE             ResponseTaken;      /* 已采取响应 */
    BOOLEAN                 WasBlocked;         /* 是否已阻断 */
    BOOLEAN                 WasRepaired;        /* 是否已修复 */
    CHAR                    Description[MP_MAX_DESCRIPTION]; /* 描述 */
    MP_EVENT_CONTEXT_ENTRY  Context[MP_MAX_EVENT_CONTEXT_ENTRIES]; /* 附加上下文 */
} MP_PROTECTION_EVENT, *PMP_PROTECTION_EVENT;

/**************************************************/
/*               内存区域信息                       */
/*  对齐 SS MemoryRegionInfo。                     */
/**************************************************/

typedef struct _MP_REGION_INFO {
    ULONG_PTR       BaseAddress;    /* 区域基址 */
    SIZE_T          RegionSize;     /* 区域大小 */
    ULONG_PTR       AllocationBase; /* 分配基址 */
    SIZE_T          AllocationSize; /* 分配大小 */
    ULONG           Protection;     /* 页保护 */
    ULONG           State;          /* 状态（MEM_*） */
    ULONG           Type;           /* 类型（MEM_*） */
    MP_REGION_TYPE  RegionType;     /* 分类 */
    WCHAR           ModuleName[MP_MAX_MODULE_NAME]; /* 模块名（若映射） */
} MP_REGION_INFO, *PMP_REGION_INFO;

/**************************************************/
/*               堆信息                             */
/*  对齐 SS HeapInfo。                             */
/**************************************************/

typedef struct _MP_HEAP_INFO {
    PVOID       HeapHandle;     /* 堆句柄 */
    SIZE_T      TotalSize;      /* 总大小 */
    SIZE_T      CommittedSize;  /* 已提交大小 */
    SIZE_T      UncommittedSize;/* 未提交大小 */
    SIZE_T      BlockCount;     /* 块计数 */
    BOOLEAN     IsDefaultHeap;  /* 是否默认堆 */
    BOOLEAN     IsSecureHeap;   /* 是否安全堆 */
    ULONG       Flags;          /* 堆标志 */
} MP_HEAP_INFO, *PMP_HEAP_INFO;

/**************************************************/
/*               统计                               */
/*  对齐 SS MemoryProtectionStatistics。           */
/**************************************************/

typedef struct _MP_STATISTICS {
    volatile LONG64 TotalProtectedRegions;      /* 受保护区域总数（累计） */
    volatile LONG64 TotalSecureAllocations;     /* 安全分配总数（累计） */
    volatile LONG64 TotalSecureBytes;           /* 安全内存字节数（当前） */
    volatile LONG64 TotalIntegrityChecks;       /* 完整性校验总数 */
    volatile LONG64 IntegrityViolations;        /* 完整性违规数 */
    volatile LONG64 MemoryWritesBlocked;        /* 内存写阻断数 */
    volatile LONG64 HeapCorruptionsDetected;    /* 堆损坏检测数 */
    volatile LONG64 HooksDetected;              /* hook 检测数 */
    volatile LONG64 DumpAttemptsBlocked;        /* 反转储拦截数 */
    volatile LONG64 ScanAttemptsDetected;       /* 扫描尝试检测数 */
    LARGE_INTEGER   StartTime;                  /* 引擎启动时间 */
    LARGE_INTEGER   LastEventTime;              /* 最近事件时间 */
} MP_STATISTICS, *PMP_STATISTICS;

/**************************************************/
/*               回调类型                           */
/*  对齐 SS 4 类回调（std::function→函数指针）。   */
/**************************************************/

/* 保护事件回调（对齐 ProtectionEventCallback）。返回 STATUS_SUCCESS 表示已消费。 */
typedef NTSTATUS (*MP_EVENT_CALLBACK)(
    _In_ PMP_PROTECTION_EVENT Event,
    _In_opt_ PVOID            Context
    );

/* 完整性违规回调（对齐 MemoryIntegrityCallback）。 */
typedef NTSTATUS (*MP_INTEGRITY_CALLBACK)(
    _In_ PMP_PROTECTED_REGION Region,
    _In_opt_ PVOID            Context
    );

/* 堆损坏回调（对齐 HeapCorruptionCallback）。 */
typedef NTSTATUS (*MP_HEAP_CORRUPTION_CALLBACK)(
    _In_ PMP_HEAP_INFO Heap,
    _In_opt_ PVOID     Context
    );

/**************************************************/
/*               事件回调集合（初始化静态注入）      */
/**************************************************/

typedef struct _MP_CALLBACKS {
    /* 检测到保护事件时触发（对齐 fireEvent）。 */
    MP_EVENT_CALLBACK   OnEvent;
    /* 完整性违规时触发（对齐 VerifyRegionIntegrity 回调链）。 */
    MP_INTEGRITY_CALLBACK OnIntegrityViolation;
    /* 堆损坏时触发（对齐 ValidateHeapIntegrity）。 */
    MP_HEAP_CORRUPTION_CALLBACK OnHeapCorruption;
    _In_opt_ PVOID      Context; /* 透传给所有回调 */
} MP_CALLBACKS, *PMP_CALLBACKS;

/**************************************************/
/*               引擎上下文（不透明句柄）          */
/**************************************************/

typedef struct _AC_MEMORY_INTEGRITY_ENGINE AC_MEMORY_INTEGRITY_ENGINE, *PAC_MEMORY_INTEGRITY_ENGINE;

/**************************************************/
/*               公共 API                          */
/**************************************************/

/* ------------------------------------------------ */
/* 生命周期（对齐 SS Initialize/Shutdown 系列）      */
/* ------------------------------------------------ */

/* 初始化内存保护引擎（默认配置=Standard）。PASSIVE_LEVEL */
NTSTATUS
MpInitialize(
    _Out_ PAC_MEMORY_INTEGRITY_ENGINE* Engine,
    _In_opt_ PMP_CALLBACKS Callbacks,
    _In_opt_ PMP_CONFIGURATION Config       /* NULL=使用默认配置 */
    );

/* 停止引擎并释放内部资源（对齐 SS Shutdown，免鉴权）。PASSIVE_LEVEL */
NTSTATUS
MpShutdown(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* 释放引擎资源。NULL 安全。PASSIVE_LEVEL */
VOID
MpCleanup(
    _In_opt_ _Post_invalid_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* 启动完整性巡检线程（周期完整性校验 + EnableHeapProtection 时追加堆校验；
 * 对齐 SS startIntegrityMonitoring，Agent 侧由编排层显式启停）。PASSIVE_LEVEL */
NTSTATUS
AcStartMemoryIntegralityProtection(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* 停止完整性监视线程（对齐 SS stopIntegrityMonitoring）。PASSIVE_LEVEL */
NTSTATUS
MpStop(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* 查询引擎是否已初始化。PASSIVE_LEVEL */
BOOLEAN
MpIsInitialized(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* 查询引擎状态（对齐 SS GetStatus）。PASSIVE_LEVEL */
MP_MODULE_STATUS
MpGetStatus(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* ------------------------------------------------ */
/* 配置（对齐 SS SetConfiguration/GetConfiguration/  */
/*        SetProtectionLevel/GetProtectionLevel）    */
/* ------------------------------------------------ */

/* 取默认配置（对齐 SS 默认值：Standard、全功能开启、 */
/* 安全池 1MB、完整性间隔 30s、DefaultResponse=Active）。PASSIVE_LEVEL */
VOID
MpGetDefaultConfiguration(
    _Out_ PMP_CONFIGURATION Config
    );

/* 取保护级别对应的配置模板（对齐 SS FromLevel）。PASSIVE_LEVEL */
VOID
MpGetConfigurationForLevel(
    _In_ MP_PROTECTION_LEVEL Level,
    _Out_ PMP_CONFIGURATION Config
    );

/* 校验配置有效性（对齐 SS IsValid）。PASSIVE_LEVEL */
BOOLEAN
MpIsConfigurationValid(
    _In_ PMP_CONFIGURATION Config
    );

/* 更新配置（对齐 SS SetConfiguration；DefaultResponse 等实时生效）。PASSIVE_LEVEL */
NTSTATUS
MpSetConfiguration(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PMP_CONFIGURATION Config
    );

/* 获取当前配置快照。PASSIVE_LEVEL */
NTSTATUS
MpGetConfiguration(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _Out_ PMP_CONFIGURATION Config
    );

/* 设置保护级别（校验并应用 FromLevel 模板；对齐 SS SetProtectionLevel）。PASSIVE_LEVEL */
NTSTATUS
MpSetProtectionLevel(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ MP_PROTECTION_LEVEL Level
    );

/* 查询当前保护级别。PASSIVE_LEVEL */
MP_PROTECTION_LEVEL
MpGetProtectionLevel(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* ------------------------------------------------ */
/* 安全内存分配（对齐 SS AllocateSecure 系列）       */
/* ------------------------------------------------ */

/* 进程加固（ApplyProcessHardening/EnableASLR/EnableDEP/EnableCFG 及其 Is* 查询）
 * 已于 2026-09-08 迁移至 ProcessProtection（AcApplyProcessHardening 系列，
 * 粒度=受保护进程访问控制上下文 HardeningMask 位域）。 */

/* 分配安全内存（默认类型=Secure）。失败返回 NULL。PASSIVE_LEVEL */
PVOID
MpAllocateSecure(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ SIZE_T Size
    );

/* 分配指定类型的安全内存。失败返回 NULL。PASSIVE_LEVEL */
PVOID
MpAllocateSecureEx(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ SIZE_T Size,
    _In_ MP_ALLOCATION_TYPE Type
    );

/* 释放安全内存（零化→0xDD 填充→解锁→释放）。PASSIVE_LEVEL */
VOID
MpFreeSecure(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PVOID Ptr,
    _In_ SIZE_T Size
    );

/* 重分配安全内存（拷贝 min(old,new) 字节；对齐 SS ReallocateSecure）。PASSIVE_LEVEL */
PVOID
MpReallocateSecure(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PVOID Ptr,
    _In_ SIZE_T OldSize,
    _In_ SIZE_T NewSize
    );

/* 分配"加密"内存（对齐 SS；实际=加锁+标志）。PASSIVE_LEVEL */
PVOID
MpAllocateEncrypted(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ SIZE_T Size
    );

VOID
MpFreeEncrypted(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PVOID Ptr,
    _In_ SIZE_T Size
    );

/* 分配不可换页内存。PASSIVE_LEVEL */
PVOID
MpAllocateLocked(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ SIZE_T Size
    );

VOID
MpFreeLocked(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PVOID Ptr,
    _In_ SIZE_T Size
    );

/* 分配带守卫页的内存（前后各 1 页 PAGE_NOACCESS）。PASSIVE_LEVEL */
PVOID
MpAllocateGuarded(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ SIZE_T Size
    );

VOID
MpFreeGuarded(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PVOID Ptr,
    _In_ SIZE_T Size
    );

/* 获取安全分配信息。返回是否找到。PASSIVE_LEVEL */
BOOLEAN
MpGetSecureAllocationInfo(
    _In_  PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_  PVOID Ptr,
    _Out_ PMP_SECURE_ALLOCATION Info
    );

/* 获取全部安全分配。Buffer=NULL 时返回所需条目数（*Count）。PASSIVE_LEVEL */
NTSTATUS
MpGetAllSecureAllocations(
    _In_      PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _Out_writes_opt_(*Count) PMP_SECURE_ALLOCATION Buffer,
    _Inout_   PULONG Count
    );

/* 获取当前安全内存使用量（字节）。PASSIVE_LEVEL */
SIZE_T
MpGetSecureMemoryUsage(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* ------------------------------------------------ */
/* 内存区域保护（对齐 SS ProtectRegion 系列）        */
/* ------------------------------------------------ */

/* 保护内存区域（按类型设页保护 + 建立 CRC32+SHA-256 基线）。
 * Id 不得为空；重复 ID 返回 FALSE。PASSIVE_LEVEL */
BOOLEAN
AcEnableMemoryIntegrityProtection(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PCSTR Id,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T Size,
    _In_ MP_REGION_TYPE Type
    );

/* 解除区域保护（恢复 READWRITE 并移除基线。SS 需令牌，Agent 免鉴权）。PASSIVE_LEVEL */
BOOLEAN
MpUnprotectRegion(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PCSTR Id
    );

/* 保护模块实例全部代码节（进程内映射视图，含 ImageBase + 全局模块本体）。
 * 模块按 PeInfo.Sections（未就绪则回退自解析镜像）枚举 IMAGE_SCN_CNT_CODE 节并注册区域，
 * ID 形如 self_<基址低位>_<节名>。模块登记进 MP 模块保护链表（按 Module+ImageBase 判重，重复返回 TRUE），
 * 建链时 PsReferenceWkdModule 保活本体。返回是否成功。PASSIVE_LEVEL */
BOOLEAN
AcEnableCodeIntegrityProtection(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PWKD_MODULE_INSTANCE Instance
    );

/* 查询地址是否落在某个受保护区域内。PASSIVE_LEVEL */
BOOLEAN
MpIsRegionProtected(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ ULONG_PTR Address
    );

/* 获取指定 ID 的受保护区域。返回是否找到。PASSIVE_LEVEL */
BOOLEAN
MpGetProtectedRegion(
    _In_  PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_  PCSTR Id,
    _Out_ PMP_PROTECTED_REGION Region
    );

/* 获取全部受保护区域。Buffer=NULL 时返回所需条目数（*Count）。PASSIVE_LEVEL */
NTSTATUS
MpGetAllProtectedRegions(
    _In_      PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _Out_writes_opt_(*Count) PMP_PROTECTED_REGION Buffer,
    _Inout_   PULONG Count
    );

/* ------------------------------------------------ */
/* 完整性校验（对齐 SS VerifyRegionIntegrity 系列）  */
/* ------------------------------------------------ */

/* 校验区域完整性（CRC32+SHA-256 对比 + hook 特征检测）。PASSIVE_LEVEL */
MP_INTEGRITY_STATUS
AcpVerifyMemoryRegionIntegrity(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PCSTR Id
    );

/* 校验全部受保护区域，结果写回 Results（每项=ID+状态）。
 * Results=NULL 时返回所需条目数（*Count）。PASSIVE_LEVEL */
NTSTATUS
AcpVerifyMemoryIntegrity(
    _In_      PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _Out_writes_opt_(*Count) PMP_PROTECTED_REGION Results,
    _Inout_   PULONG Count
    );

/* 强制触发一次完整性校验（对齐 SS ForceIntegrityCheck）。PASSIVE_LEVEL */
VOID
MpForceIntegrityCheck(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* 更新区域基线（SS 需令牌，Agent 免鉴权）。PASSIVE_LEVEL */
BOOLEAN
MpUpdateRegionBaseline(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PCSTR Id
    );

/* ------------------------------------------------ */
/* 反转储保护（对齐 SS EnableAntiDump 系列）         */
/* ------------------------------------------------ */

/* 启用反转储（混淆自身 PE 头）。PASSIVE_LEVEL */
BOOLEAN
MpEnableAntiDump(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* 禁用反转储（恢复 PE 头。SS 需令牌，Agent 免鉴权）。PASSIVE_LEVEL */
VOID
MpDisableAntiDump(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* 查询反转储是否启用。PASSIVE_LEVEL */
BOOLEAN
MpIsAntiDumpEnabled(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* 混淆自身 PE 头（保存原始头→擦 DOS stub→清零 CheckSum/LoaderFlags）。PASSIVE_LEVEL */
BOOLEAN
MpObfuscatePEHeaders(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* 恢复原始 PE 头（SS 需令牌，Agent 免鉴权）。PASSIVE_LEVEL */
BOOLEAN
MpRestorePEHeaders(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* ------------------------------------------------ */
/* 堆保护（对齐 SS EnableHeapProtection 系列）       */
/* ------------------------------------------------ */

/* 启用堆保护（HeapSetInformation 终止于损坏）。PASSIVE_LEVEL */
BOOLEAN
MpEnableHeapProtection(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* 校验全部堆完整性（GetProcessHeaps + HeapValidate）。
 * 检测到损坏时触发事件并返回 FALSE。PASSIVE_LEVEL */
BOOLEAN
MpValidateHeapIntegrity(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* 获取全部堆信息。Buffer=NULL 时返回所需条目数（*Count）。PASSIVE_LEVEL */
NTSTATUS
MpGetHeapInfo(
    _In_      PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _Out_writes_opt_(*Count) PMP_HEAP_INFO Buffer,
    _Inout_   PULONG Count
    );

/* 创建安全堆（终止于损坏）。PASSIVE_LEVEL */
PVOID
MpCreateSecureHeap(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ SIZE_T InitialSize
    );

/* 销毁安全堆。PASSIVE_LEVEL */
VOID
MpDestroySecureHeap(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ PVOID HeapHandle
    );

/* ------------------------------------------------ */
/* 内存查询（对齐 SS QueryMemoryRegion 系列）        */
/* ------------------------------------------------ */

/* 查询地址所在内存区域信息。返回是否成功。PASSIVE_LEVEL */
BOOLEAN
MpQueryMemoryRegion(
    _In_  PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_  ULONG_PTR Address,
    _Out_ PMP_REGION_INFO Info
    );

/* 枚举全部内存区域（渐进式防死循环）。Buffer=NULL 时返回所需条目数（*Count）。PASSIVE_LEVEL */
NTSTATUS
MpEnumerateMemoryRegions(
    _In_      PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _Out_writes_opt_(*Count) PMP_REGION_INFO Buffer,
    _Inout_   PULONG Count
    );

/* 获取地址页保护。PASSIVE_LEVEL */
ULONG
MpGetPageProtection(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ ULONG_PTR Address
    );

/* 设置范围页保护（W^X 强制：拒绝 EXECUTE_READWRITE/WRITECOPY）。PASSIVE_LEVEL */
BOOLEAN
MpSetPageProtection(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T Size,
    _In_ MP_PAGE_PROTECTION Protection
    );

/* ------------------------------------------------ */
/* 回调管理（对齐 SS Register/Unregister 系列）      */
/* ------------------------------------------------ */

/* 注册保护事件回调，返回回调 ID。PASSIVE_LEVEL */
NTSTATUS
MpRegisterEventCallback(
    _In_  PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_  MP_EVENT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PULONG64 CallbackId
    );

VOID
MpUnregisterEventCallback(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ ULONG64 CallbackId
    );

/* 注册完整性违规回调。PASSIVE_LEVEL */
NTSTATUS
MpRegisterIntegrityCallback(
    _In_  PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_  MP_INTEGRITY_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PULONG64 CallbackId
    );

VOID
MpUnregisterIntegrityCallback(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ ULONG64 CallbackId
    );

/* 注册堆损坏回调。PASSIVE_LEVEL */
NTSTATUS
MpRegisterHeapCorruptionCallback(
    _In_  PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_  MP_HEAP_CORRUPTION_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PULONG64 CallbackId
    );

VOID
MpUnregisterHeapCorruptionCallback(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_ ULONG64 CallbackId
    );

/* ------------------------------------------------ */
/* 统计 / 历史 / 报告 / 自检                         */
/* ------------------------------------------------ */

/* 取统计快照（对齐 SS GetStatistics）。PASSIVE_LEVEL */
NTSTATUS
MpGetStatistics(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _Out_ PMP_STATISTICS Stats
    );

/* 重置统计（SS 需令牌，Agent 免鉴权）。PASSIVE_LEVEL */
VOID
MpResetStatistics(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* 取事件历史（最多 maxEntries 条；对齐 SS GetEventHistory）。PASSIVE_LEVEL */
NTSTATUS
MpGetEventHistory(
    _In_      PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _In_      ULONG MaxEntries,
    _Out_writes_opt_(*Count) PMP_PROTECTION_EVENT Buffer,
    _Inout_   PULONG Count
    );

/* 清空事件历史（SS 需令牌，Agent 免鉴权）。PASSIVE_LEVEL */
VOID
MpClearEventHistory(
    _In_ PAC_MEMORY_INTEGRITY_ENGINE Engine
    );

/* 导出 JSON 报告。Buffer=NULL 时返回所需字符数（*Length，含 null）。PASSIVE_LEVEL */
NTSTATUS
MpExportReport(
    _In_      PAC_MEMORY_INTEGRITY_ENGINE Engine,
    _Out_writes_opt_(*Length) PWSTR Buffer,
    _Inout_   PULONG Length
    );

/* 版本字符串（对齐 SS GetVersionString）。返回静态串。PASSIVE_LEVEL */
PCWSTR
MpGetVersionString(
    VOID
    );

/* ------------------------------------------------ */
/* 静态工具（对齐 SS SecureZero/ConstantTimeCompare）*/
/* ------------------------------------------------ */

/* 安全清零（volatile 写入 + 内存栅栏，防编译器优化）。PASSIVE_LEVEL */
VOID
MpSecureZero(
    _In_ PVOID Ptr,
    _In_ SIZE_T Size
    );

/* 常量时间比较（防时序侧信道）。PASSIVE_LEVEL */
BOOLEAN
MpConstantTimeCompare(
    _In_ const VOID* A,
    _In_ const VOID* B,
    _In_ SIZE_T Size
    );

/* ------------------------------------------------ */
/* 名称工具（对齐 SS Get*Name 系列）                 */
/* ------------------------------------------------ */

/* 保护级别 → 可读名。PASSIVE_LEVEL */
PCWSTR
MpProtectionLevelName(
    _In_ MP_PROTECTION_LEVEL Level
    );

/* 区域类型 → 可读名。PASSIVE_LEVEL */
PCWSTR
MpRegionTypeName(
    _In_ MP_REGION_TYPE Type
    );

/* 完整性状态 → 可读名。PASSIVE_LEVEL */
PCWSTR
MpIntegrityStatusName(
    _In_ MP_INTEGRITY_STATUS Status
    );

/* 分配类型 → 可读名。PASSIVE_LEVEL */
PCWSTR
MpAllocationTypeName(
    _In_ MP_ALLOCATION_TYPE Type
    );

/* 页保护格式化为可读串（对齐 SS FormatPageProtection）。PASSIVE_LEVEL */
VOID
MpFormatPageProtection(
    _In_ ULONG Protection,
    _Out_writes_(BufferChars) PWSTR Buffer,
    _In_ ULONG BufferChars
    );

/* 事件类型 → 可读名。PASSIVE_LEVEL */
PCWSTR
MpEventTypeName(
    _In_ MP_EVENT_TYPE Type
    );

#ifdef __cplusplus
}
#endif