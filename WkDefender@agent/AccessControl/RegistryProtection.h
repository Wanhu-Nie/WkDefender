/**************************************************/
/*  WkDefender Agent — 注册表保护引擎               */
/*  (RegistryProtection, RG)                       */
/*                                                 */
/*  纯 C 实现 ShadowStrike RegistryProtection.cpp/ */
/*  hpp（3137+1252 行）迁移。职责：用户态注册表     */
/*  键/值保护、操作过滤决策、完整性监控与快照回滚、 */
/*  白名单验签、事件记账与回调上报。                */
/*                                                 */
/*  与驱动端自防御（内核注册表回调）互补：本引擎为   */
/*  用户态决策/监控/回滚层。SS 内核桥（SHADOWSTRIKE  */
/*  UpdatePolicy/RegistryNotify 协议）在           */
/*  WkDefender 无对应通道——本轮裁剪留桩            */
/*  （RpSyncProtectedKeysToKernel 返回             */
/*  STATUS_NOT_SUPPORTED），后续接驱动桥接时启用。   */
/*                                                 */
/*  架构约定：                                     */
/*  - 引擎头不反向包含 AccessControlEngine.h；     */
/*    事件上行仅经本头注册的 RG_EVENT_CALLBACK，    */
/*    由编排层/main 注册桥接（→ SdfNotifyAlert）。  */
/*  - 授权令牌（SS GenerateAuthorizationToken /    */
/*    HMAC 会话密钥）归属编排层 SdfVerifyAuthToken  */
/*    职责：引擎敏感操作不设令牌参数，由门面把关。  */
/*  - RAII Guard（C++）随 C 化删除。               */
/*                                                 */
/*  生命周期：RpInitialize -> (运行) -> RpShutdown。*/
/*  决策核心：RpFilterOperation。                   */
/*  全部函数 PASSIVE_LEVEL。                       */
/*  编码：UTF-8 with BOM（铁律）                  */
/**************************************************/

#pragma once

#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    /**************************************************/
    /*               常量定义                           */
    /*  对齐 ShadowStrike RegistryProtectionConstants。 */
    /**************************************************/

    /* 版本（WkD 首版；v3.1.0 功能面） */
#define RG_VERSION_MAJOR        1
#define RG_VERSION_MINOR        0
#define RG_VERSION_PATCH        0

    /* 上限（对齐 SS） */
#define RG_MAX_PROTECTED_KEYS           200     /* 受保护键上限（SS MAX_PROTECTED_KEYS） */
#define RG_MAX_PROTECTED_VALUES         1000    /* 受保护值上限（SS MAX_PROTECTED_VALUES） */
#define RG_MAX_KEY_PATH_LENGTH          512     /* 键路径最大长度（含尾 0，SS MAX_KEY_PATH_LENGTH） */
#define RG_MAX_VALUE_NAME_LENGTH        256     /* 值名最大长度（含尾 0，SS MAX_VALUE_NAME_LENGTH） */
#define RG_MAX_VALUE_DATA_SIZE          (1u << 20)  /* 单值数据安全上限 1MB（SS MAX_VALUE_DATA_SIZE） */
#define RG_MAX_SNAPSHOTS_PER_KEY        10      /* 每键快照版本上限（SS MAX_SNAPSHOTS_PER_KEY） */
#define RG_MAX_BLOCKED_OPERATIONS_LOG   1000    /* 事件历史环形上限（SS MAX_BLOCKED_OPERATIONS_LOG） */
#define RG_SHA256_SIZE                  32      /* SHA-256 摘要长度（SS SHA256_SIZE） */

    /* 监测间隔（毫秒，对齐 SS） */
#define RG_INTEGRITY_CHECK_INTERVAL_MS  30000   /* 完整性检查间隔（SS INTEGRITY_CHECK_INTERVAL_MS） */
#define RG_POLLING_INTERVAL_MS          5000    /* 用户态轮询间隔（SS POLLING_INTERVAL_MS） */
#define RG_ROLLBACK_DELAY_MS            100     /* 回滚延迟（SS ROLLBACK_DELAY_MS） */

    /* 迁移补充护栏（SS 无上限或上限缺失，C 化必须显式上限） */
#define RG_MAX_SNAPSHOT_SUBKEYS         64      /* 单快照子键记录上限（防恶意海量子键 DoS） */
#define RG_MAX_SNAPSHOT_VALUES          256     /* 单快照值记录上限 */
#define RG_MAX_CONFIG_KEYS              32      /* 配置内联保护键上限 */
#define RG_MAX_CONFIG_WHITELIST         32      /* 配置内联白名单上限 */
#define RG_MAX_WHITELIST                256     /* 白名单进程总数上限 */
#define RG_MAX_CALLBACKS                32      /* 每组回调注册上限（对齐 PP_MAX_CALLBACKS 惯例） */
#define RG_SELF_TEST_CHECKS             4       /* 自检项数 */

/* 默认保护键 13 条（DEFAULT_PROTECTED_KEYS 原文；
 * 注：内容为 ShadowStrike 自身资产，WkDefender 自身键由编排层另行注册） */
#define RG_DEFAULT_PROTECTED_KEY_COUNT  13

/* 状态码语义自映射 (对齐现役 MemoryProtection.h MP_STATUS_ALREADY_EXISTS /
 * ProcessProtection.h PP_STATUS_ALREADY_EXISTS 惯例; 本 SDK 的 ntstatus.h
 * 不提供下述两个符号, 统一映射为 STATUS_UNSUCCESSFUL 承载语义) */
#define RG_STATUS_NOT_INITIALIZED       STATUS_UNSUCCESSFUL   /* 语义：引擎未初始化 */
#define RG_STATUS_ALREADY_EXISTS        STATUS_UNSUCCESSFUL   /* 语义：目标已存在 */

    /**************************************************/
    /*  事件子类型（与 AccessControlEngine.h           */
    /*  SP_EVENT_SUBTYPE_REG_* 值对齐，0x5030 段内）   */
    /**************************************************/

#define RG_EVENT_SUBTYPE_OPERATION_BLOCKED      0x5031  /* 操作被阻断 */
#define RG_EVENT_SUBTYPE_INTEGRITY_VIOLATION    0x5032  /* 完整性违规 */
#define RG_EVENT_SUBTYPE_VALUE_CHANGED          0x5033  /* 受保护值变更 */
#define RG_EVENT_SUBTYPE_KERNEL_BLOCK           0x5034  /* 内核回调阻断（预留给驱动桥接） */

    /**************************************************/
    /*               枚举定义                           */
    /*  对齐 ShadowStrike Security/RegistryProtection  */
    /**************************************************/

    /* 注册表保护模式（SS RegistryProtectionMode） */
    typedef enum _RG_PROTECTION_MODE {
        RgModeDisabled = 0,   /* 无保护 */
        RgModeMonitor = 1,   /* 仅监控记录 */
        RgModeProtect = 2,   /* 监控并阻断 */
        RgModeRollback = 3,   /* 监控、阻断并回滚 */
        RgModeStrict = 4    /* 严格强制 */
    } RG_PROTECTION_MODE, * PRG_PROTECTION_MODE;

    /* 注册表操作位域（SS RegistryOperation）。读写组合定义：AllWrite 为写操作掩码 */
    typedef enum _RG_OPERATION {
        RgOpNone = 0x00000000,
        RgOpQueryKey = 0x00000001,
        RgOpSetValue = 0x00000002,
        RgOpDeleteValue = 0x00000004,
        RgOpCreateKey = 0x00000008,
        RgOpDeleteKey = 0x00000010,
        RgOpRenameKey = 0x00000020,
        RgOpEnumerateKey = 0x00000040,
        RgOpEnumerateValue = 0x00000080,
        RgOpQueryValue = 0x00000100,
        RgOpSetKeySecurity = 0x00000200,
        RgOpQueryKeySecurity = 0x00000400,
        RgOpFlushKey = 0x00000800,
        RgOpLoadKey = 0x00001000,
        RgOpUnloadKey = 0x00002000,
        RgOpSaveKey = 0x00004000,
        RgOpRestoreKey = 0x00008000,

        RgOpAllWrite = RgOpSetValue | RgOpDeleteValue | RgOpCreateKey | RgOpDeleteKey | RgOpRenameKey | RgOpSetKeySecurity,
        RgOpAllRead = RgOpQueryKey | RgOpEnumerateKey | RgOpEnumerateValue | RgOpQueryValue | RgOpQueryKeySecurity,
        RgOpAll = 0xFFFFFFFF
    } RG_OPERATION, * PRG_OPERATION;

    /* 注册表值类型（SS RegistryValueType，值对齐 REG_*） */
    typedef enum _RG_REGISTRY_VALUE_TYPE {
        RgValueNone = REG_NONE,
        RgValueString = REG_SZ,
        RgValueExpandString = REG_EXPAND_SZ,
        RgValueBinary = REG_BINARY,
        RgValueDWord = REG_DWORD,
        RgValueDWordBigEndian = REG_DWORD_BIG_ENDIAN,
        RgValueLink = REG_LINK,
        RgValueMultiString = REG_MULTI_SZ,
        RgValueResourceList = REG_RESOURCE_LIST,
        RgValueFullResourceDesc = REG_FULL_RESOURCE_DESCRIPTOR,
        RgValueResourceReqList = REG_RESOURCE_REQUIREMENTS_LIST,
        RgValueQWord = REG_QWORD
    } RG_REGISTRY_VALUE_TYPE, * PRG_REGISTRY_VALUE_TYPE;

    /* 键保护类型（SS KeyProtectionType） */
    typedef enum _RG_KEY_PROTECTION_TYPE {
        RgKeyTypeNone = 0,      /* 无保护 */
        RgKeyTypeReadOnly = 1,  /* 允许读，阻断写 */
        RgKeyTypeNoDelete = 2,  /* 允许写，阻断删除 */
        RgKeyTypeNoModify = 3,  /* 阻断全部修改 */
        RgKeyTypeFull = 4,      /* 完全保护 */
        RgKeyTypeValuesOnly = 5, /* 仅保护值，允许键操作 */
        RgKeyTypeCustom = 6     /* 定制操作掩码 */
    } RG_KEY_PROTECTION_TYPE, * PRG_KEY_PROTECTION_TYPE;

    /* 完整性状态（SS RegistryIntegrityStatus） */
    typedef enum _RG_INTEGRITY_STATUS {
        RgIntegrityUnknown = 0,
        RgIntegrityValid = 1,
        RgIntegrityModified = 2,
        RgIntegrityMissing = 3,
        RgIntegrityCorrupted = 4,
        RgIntegrityNew = 5,
        RgIntegrityRestored = 6
    } RG_INTEGRITY_STATUS, * PRG_INTEGRITY_STATUS;

    /* 操作决策（SS RegistryOperationDecision） */
    typedef enum _RG_OPERATION_DECISION {
        RgDecisionAllow = 0,      /* 允许 */
        RgDecisionBlock = 1,      /* 阻断 */
        RgDecisionAllowLogged = 2, /* 允许并记录 */
        RgDecisionRollback = 3,   /* 回滚 */
        RgDecisionDefer = 4       /* 延后判定 */
    } RG_OPERATION_DECISION, * PRG_OPERATION_DECISION;

    /* 保护事件类型位域（SS RegistryProtectionEventType） */
    typedef enum _RG_PROTECTION_EVENT_TYPE {
        RgEventNone = 0x00000000,
        RgEventOperationBlocked = 0x00000001,
        RgEventOperationAllowed = 0x00000002,
        RgEventIntegrityViolation = 0x00000004,
        RgEventUnauthorizedAccess = 0x00000008,
        RgEventKeyCreated = 0x00000010,
        RgEventKeyDeleted = 0x00000020,
        RgEventValueModified = 0x00000040,
        RgEventValueDeleted = 0x00000080,
        RgEventRollbackPerformed = 0x00000100,
        RgEventSnapshotCreated = 0x00000200,
        RgEventSnapshotRestored = 0x00000400,
        RgEventAll = 0xFFFFFFFF
    } RG_PROTECTION_EVENT_TYPE, * PRG_PROTECTION_EVENT_TYPE;

    /* 保护响应位域（SS RegistryProtectionResponse） */
    typedef enum _RG_PROTECTION_RESPONSE {
        RgResponseNone = 0x00000000,
        RgResponseLog = 0x00000001,
        RgResponseAlert = 0x00000002,
        RgResponseBlock = 0x00000004,
        RgResponseRollback = 0x00000008,
        RgResponseSnapshot = 0x00000010,
        RgResponseTerminateSource = 0x00000020,
        RgResponseEscalate = 0x00000040,

        RgResponsePassive = RgResponseLog | RgResponseAlert,
        RgResponseActive = RgResponseLog | RgResponseAlert | RgResponseBlock,
        RgResponseAggressive = RgResponseLog | RgResponseAlert | RgResponseBlock | RgResponseRollback | RgResponseTerminateSource
    } RG_PROTECTION_RESPONSE, * PRG_PROTECTION_RESPONSE;

    /**************************************************/
    /*               结构定义                           */
    /**************************************************/

    /* 注册表保护配置（SS RegistryProtectionConfiguration） */
    typedef struct _RG_CONFIGURATION {
        RG_PROTECTION_MODE  Mode;                    /* 保护模式 */
        BOOLEAN             EnableKernelCallbacks;   /* 启用内核回调（SS；WkD 无通道，当前仅记账） */
        BOOLEAN             EnableUserModePolling;   /* 启用用户态轮询 */
        ULONG               PollingIntervalMs;       /* 轮询间隔（毫秒） */
        BOOLEAN             EnableIntegrityMonitoring; /* 启用完整性监控 */
        ULONG               IntegrityCheckIntervalMs; /* 完整性检查间隔（预留节流） */
        BOOLEAN             EnableAutoRollback;      /* 启用自动回滚（Rollback/Strict 模式生效） */
        BOOLEAN             EnableSnapshots;         /* 保护时创建快照 */
        ULONG               MaxSnapshotsPerKey;      /* 每键快照版本上限（1-100） */
        ULONG               DefaultResponse;         /* 默认保护响应位图（RG_PROTECTION_RESPONSE） */
        WCHAR               ProtectedKeys[RG_MAX_CONFIG_KEYS][RG_MAX_KEY_PATH_LENGTH];  /* 初始保护键 */
        ULONG               ProtectedKeyCount;
        WCHAR               WhitelistedProcesses[RG_MAX_CONFIG_WHITELIST][MAX_PATH];    /* 初始白名单 */
        ULONG               WhitelistedProcessCount;
        BOOLEAN             VerboseLogging;          /* 冗余日志 */
        BOOLEAN             SendTelemetry;           /* 发送遥测（WkD 经事件回调上行） */
    } RG_CONFIGURATION, * PRG_CONFIGURATION;

    /* 受保护键信息（SS ProtectedKey） */
    typedef struct _RG_PROTECTED_KEY {
        ULONGLONG               Id;
        WCHAR                   KeyPath[RG_MAX_KEY_PATH_LENGTH];          /* 原始路径 */
        WCHAR                   NormalizedPath[RG_MAX_KEY_PATH_LENGTH];   /* 规范化路径（HKLM\\ 前缀，子键小写） */
        HKEY                    RootKey;                                  /* 根键句柄常量 */
        RG_KEY_PROTECTION_TYPE  Type;
        ULONG                   BlockedOperations;                        /* RG_OPERATION 位图 */
        BOOLEAN                 IncludeSubkeys;                           /* 是否覆盖子键（祖先链匹配） */
        RG_INTEGRITY_STATUS     Integrity;
        LARGE_INTEGER           ProtectedSince;                           /* QPC 单调时间 */
        LARGE_INTEGER           LastVerified;
        ULONGLONG               BlockedOperationCount;
        BOOLEAN                 HasSnapshot;
        LARGE_INTEGER           LastSnapshotTime;
    } RG_PROTECTED_KEY, * PRG_PROTECTED_KEY;

    /* 受保护值信息（SS ProtectedValue）。
     * 注：期望数据（expectedData）不对外导出——回滚经引擎 API 完成，
     * 哈希已含基线语义，故出参 DataSize/ExpectedHash 足够。 */
    typedef struct _RG_PROTECTED_VALUE {
        ULONGLONG               Id;
        WCHAR                   KeyPath[RG_MAX_KEY_PATH_LENGTH];
        WCHAR                   ValueName[RG_MAX_VALUE_NAME_LENGTH];
        RG_REGISTRY_VALUE_TYPE  ValueType;
        UCHAR                   ExpectedHash[RG_SHA256_SIZE];
        UCHAR                   CurrentHash[RG_SHA256_SIZE];
        ULONG                   DataSize;                 /* 当前值数据大小 */
        RG_INTEGRITY_STATUS     Integrity;
        LARGE_INTEGER           ProtectedSince;
        LARGE_INTEGER           LastVerified;
        ULONG                   ModificationCount;
    } RG_PROTECTED_VALUE, * PRG_PROTECTED_VALUE;

    /* 快照值条目（SS KeySnapshot.values/valueTypes 合并元素） */
    typedef struct _RG_SNAPSHOT_ENTRY {
        WCHAR                   Name[RG_MAX_VALUE_NAME_LENGTH];
        PVOID                   Data;                     /* 动态缓冲，随快照生命周期 */
        ULONG                   DataSize;
        RG_REGISTRY_VALUE_TYPE  Type;
    } RG_SNAPSHOT_ENTRY, * PRG_SNAPSHOT_ENTRY;

    /* 键快照（SS KeySnapshot）。Values 为动态数组（需 RpFreeSnapshot 释放） */
    typedef struct _RG_KEY_SNAPSHOT {
        ULONGLONG               Id;
        WCHAR                   KeyPath[RG_MAX_KEY_PATH_LENGTH];
        LARGE_INTEGER           Timestamp;
        PRG_SNAPSHOT_ENTRY      Values;                   /* 动态数组，呼叫方经 RpFreeSnapshot 释放 */
        ULONG                   ValueCount;
        WCHAR                   Subkeys[RG_MAX_SNAPSHOT_SUBKEYS][RG_MAX_KEY_PATH_LENGTH];
        ULONG                   SubkeyCount;
        WCHAR                   SecurityDescriptor[1024]; /* SDDL（当前留空，预留） */
        ULONG                   Version;
        CHAR                    Reason[128];
    } RG_KEY_SNAPSHOT, * PRG_KEY_SNAPSHOT;

    /* 注册表操作请求（SS RegistryOperationRequest） */
    typedef struct _RG_OPERATION_REQUEST {
        ULONG                   Operation;                /* RG_OPERATION */
        WCHAR                   KeyPath[RG_MAX_KEY_PATH_LENGTH];
        WCHAR                   ValueName[RG_MAX_VALUE_NAME_LENGTH];
        const UCHAR*            NewData;                  /* 可选，写值操作时提供 */
        ULONG                   NewDataSize;
        RG_REGISTRY_VALUE_TYPE  ValueType;
        ULONG                   ProcessId;
        ULONG                   ThreadId;
        WCHAR                   ProcessName[MAX_PATH];
        WCHAR                   ProcessPath[MAX_PATH];
        ULONG                   DesiredAccess;
        LARGE_INTEGER           Timestamp;
        BOOLEAN                 IsElevated;
        BOOLEAN                 IsSystem;
        BOOLEAN                 IsWhitelisted;
    } RG_OPERATION_REQUEST, * PRG_OPERATION_REQUEST;

    /* 操作决策结果（SS RegistryOperationDecisionResult） */
    typedef struct _RG_DECISION_RESULT {
        RG_OPERATION_DECISION   Decision;
        CHAR                    Reason[256];
        BOOLEAN                 ShouldLog;
        BOOLEAN                 ShouldAlert;
        BOOLEAN                 ShouldSnapshot;
        BOOLEAN                 ShouldRollback;
    } RG_DECISION_RESULT, * PRG_DECISION_RESULT;

    /* 保护事件（SS RegistryProtectionEvent；context 字段 SS 无消费，裁剪） */
    typedef struct _RG_PROTECTION_EVENT {
        ULONGLONG               EventId;
        ULONG                   Type;                     /* RG_PROTECTION_EVENT_TYPE 位图 */
        LARGE_INTEGER           Timestamp;
        WCHAR                   KeyPath[RG_MAX_KEY_PATH_LENGTH];
        WCHAR                   ValueName[RG_MAX_VALUE_NAME_LENGTH];
        ULONG                   Operation;                /* RG_OPERATION */
        RG_OPERATION_DECISION   Decision;
        ULONG                   SourceProcessId;
        WCHAR                   SourceProcessName[64];
        WCHAR                   SourceProcessPath[MAX_PATH];
        ULONG                   ResponseTaken;            /* RG_PROTECTION_RESPONSE 位图 */
        BOOLEAN                 WasBlocked;
        BOOLEAN                 WasRolledBack;
        CHAR                    Description[512];
        UCHAR                   PreviousHash[RG_SHA256_SIZE];
        UCHAR                   NewHash[RG_SHA256_SIZE];
    } RG_PROTECTION_EVENT, * PRG_PROTECTION_EVENT;

    /* 统计快照（SS RegistryProtectionStatistics） */
    typedef struct _RG_PROTECTION_STATISTICS {
        ULONGLONG               TotalProtectedKeys;
        ULONGLONG               TotalProtectedValues;
        ULONGLONG               TotalOperations;
        ULONGLONG               TotalBlocked;
        ULONGLONG               TotalRollbacks;
        ULONGLONG               TotalIntegrityChecks;
        ULONGLONG               IntegrityViolations;
        ULONGLONG               SnapshotsCreated;
        ULONGLONG               SnapshotsRestored;
        LARGE_INTEGER           StartTime;
        LARGE_INTEGER           LastEventTime;
    } RG_PROTECTION_STATISTICS, * PRG_PROTECTION_STATISTICS;

    /* 完整性校验结果项（SS VerifyAllIntegrity 返回对） */
    typedef struct _RG_KEY_INTEGRITY_RESULT {
        WCHAR                   KeyPath[RG_MAX_KEY_PATH_LENGTH];
        RG_INTEGRITY_STATUS     Integrity;
    } RG_KEY_INTEGRITY_RESULT, * PRG_KEY_INTEGRITY_RESULT;

    /**************************************************/
    /*               回调类型                           */
    /*  RegistryEventCallback 等。             */
    /**************************************************/

    /* 操作决策回调：返回 TRUE 表示采用本回调产出的决策（覆盖默认判定）。 */
    typedef BOOLEAN(*RG_OPERATION_DECISION_CALLBACK)(
        _In_ const RG_OPERATION_REQUEST* Request,
        _Out_ PRG_DECISION_RESULT Result,
        _In_opt_ PVOID Context
    );

    /* 保护事件回调（阻断/完整性/值变更经此上行；编排层注册桥接 → SdfNotifyAlert）。 */
    typedef VOID(*RG_EVENT_CALLBACK)(
        _In_ const RG_PROTECTION_EVENT* Event,
        _In_opt_ PVOID Context
    );

    /* 完整性违规回调（SS RegistryIntegrityCallback）。 */
    typedef VOID(*RG_INTEGRITY_CALLBACK)(
        _In_ const RG_PROTECTED_KEY* Key,
        _In_opt_ PVOID Context
    );

    /* 值变更回调（SS ValueChangeCallback）。 */
    typedef VOID(*RG_VALUE_CHANGE_CALLBACK)(
        _In_ PCWSTR KeyPath,
        _In_ PCWSTR ValueName,
        _In_reads_bytes_opt_(OldDataSize) const UCHAR* OldData,
        _In_ ULONG OldDataSize,
        _In_reads_bytes_opt_(NewDataSize) const UCHAR* NewData,
        _In_ ULONG NewDataSize,
        _In_opt_ PVOID Context
    );

    /**************************************************/
    /*               引擎句柄                           */
    /*  不透明类型；单例经 RpGetEngine 获取。          */
    /**************************************************/

    typedef struct _RG_PROTECTION RG_PROTECTION, * PRG_PROTECTION;

    /**************************************************/
    /*               公共 API                          */
    /**************************************************/

    /* 全局引擎获取（单例，生命周期即 agent 进程生命周期；
     * 未 Initialize 时返回有效指针但 RpIsInitialized=FALSE）。PASSIVE_LEVEL */
    PRG_PROTECTION
    RpGetEngine(
        VOID
    );

    /* 初始化（Config=NULL 时用 FromMode(Protect) 默认配置；对齐 SS
     * RegistryProtection::Initialize）。已初始化返回成功（幂等）。
     * 失败返回 NTSTATUS 错误码。PASSIVE_LEVEL */
    NTSTATUS
    RpInitialize(
        _In_opt_ const RG_CONFIGURATION* Config
    );

    /* 以保护模式初始化（Initialize(mode)）。PASSIVE_LEVEL */
    NTSTATUS
    RpInitializeMode(
        _In_ RG_PROTECTION_MODE Mode
    );

    /* 关闭（停止监控线程、清空全部状态与回调；Shutdown，令牌把关归门面）。PASSIVE_LEVEL */
    VOID
    RpShutdown(
        VOID
    );

    /* 是否已初始化（状态==Running）。PASSIVE_LEVEL */
    BOOLEAN
    RpIsInitialized(
        VOID
    );

    /* 更新配置（轮询间隔变更时自动重启监控线程；SetConfiguration）。PASSIVE_LEVEL */
    NTSTATUS
    RpSetConfiguration(
        _In_ const RG_CONFIGURATION* Config
    );

    /* 取当前配置快照。PASSIVE_LEVEL */
    NTSTATUS
    RpGetConfiguration(
        _Out_ PRG_CONFIGURATION Config
    );

    /* 设置保护模式（同步修正配置内 Mode 字段）。PASSIVE_LEVEL */
    VOID
    RpSetProtectionMode(
        _In_ RG_PROTECTION_MODE Mode
    );

    /* 取保护模式。PASSIVE_LEVEL */
    RG_PROTECTION_MODE
    RpGetProtectionMode(
        VOID
    );

    /**************************************************/
    /*               键保护                             */
    /**************************************************/

    /* 以 Full(含子键) 注册键保护（ProtectKey 默认重载）。PASSIVE_LEVEL */
    NTSTATUS
    RpProtectKey(
        _In_ PCWSTR KeyPath
    );

    /* 以指定类型注册键保护（ProtectKey(keyPath,type,includeSubkeys)）。PASSIVE_LEVEL */
    NTSTATUS
    RpProtectKeyEx(
        _In_ PCWSTR KeyPath,
        _In_ RG_KEY_PROTECTION_TYPE Type,
        _In_ BOOLEAN IncludeSubkeys
    );

    /* 注销键保护（UnprotectKey，令牌把关归门面）。PASSIVE_LEVEL */
    NTSTATUS
    RpUnprotectKey(
        _In_ PCWSTR KeyPath
    );

    /* 键是否受保护（直接匹配 + 父键 includeSubkeys 祖先链）。PASSIVE_LEVEL */
    BOOLEAN
    RpIsKeyProtected(
        _In_ PCWSTR KeyPath
    );

    /* 取受保护键信息副本。PASSIVE_LEVEL */
    NTSTATUS
    RpGetProtectedKey(
        _In_ PCWSTR KeyPath,
        _Out_ PRG_PROTECTED_KEY Key
    );

    /* 枚举全部受保护键（Buffer=NULL 时返回所需条目数；
     * 超容返回 STATUS_BUFFER_TOO_SMALL，*Count 恒为所需数）。PASSIVE_LEVEL */
    NTSTATUS
    RpGetAllProtectedKeys(
        _Out_writes_opt_(Capacity) PRG_PROTECTED_KEY Buffer,
        _In_ ULONG Capacity,
        _Out_ PULONG Count
    );

    /* 保护本机服务键（ProtectServiceKeys，6 键 Full(含子键)）。PASSIVE_LEVEL */
    NTSTATUS
    RpProtectServiceKeys(
        VOID
    );

    /* 保护启动项键（ProtectStartupEntries，4 键 ValuesOnly）。PASSIVE_LEVEL */
    NTSTATUS
    RpProtectStartupEntries(
        VOID
    );

    /* 保护 IFEO 键（ProtectIFEOKeys，3 个目标 exe Full）。PASSIVE_LEVEL */
    NTSTATUS
    RpProtectIFEOKeys(
        VOID
    );

    /* 加固键 DACL（SS HardenKeyDACL：限制性 SDDL —— SYSTEM/管理员全控、
     * 认证用户只读、Everyone 拒绝写/删/改权）。PASSIVE_LEVEL */
    NTSTATUS
    RpHardenKeyDACL(
        _In_ PCWSTR KeyPath
    );

    /**************************************************/
    /*               值保护                             */
    /**************************************************/

    /* 注册值保护（读取当前值建立基线哈希；ProtectValue。
     * 上限 RG_MAX_PROTECTED_VALUES（SS 未检查，迁移补护栏）。PASSIVE_LEVEL */
    NTSTATUS
    RpProtectValue(
        _In_ PCWSTR KeyPath,
        _In_ PCWSTR ValueName
    );

    /* 注销值保护（UnprotectValue，令牌把关归门面）。PASSIVE_LEVEL */
    NTSTATUS
    RpUnprotectValue(
        _In_ PCWSTR KeyPath,
        _In_ PCWSTR ValueName
    );

    /* 值是否受保护（复合键 keyPath\\valueName）。PASSIVE_LEVEL */
    BOOLEAN
    RpIsValueProtected(
        _In_ PCWSTR KeyPath,
        _In_ PCWSTR ValueName
    );

    /* 取受保护值信息副本（不含期望数据，仅哈希/类型/大小）。PASSIVE_LEVEL */
    NTSTATUS
    RpGetProtectedValue(
        _In_ PCWSTR KeyPath,
        _In_ PCWSTR ValueName,
        _Out_ PRG_PROTECTED_VALUE Value
    );

    /* 枚举键下全部受保护值（前缀匹配 keyPath\\）。PASSIVE_LEVEL */
    NTSTATUS
    RpGetProtectedValues(
        _In_ PCWSTR KeyPath,
        _Out_writes_opt_(Capacity) PRG_PROTECTED_VALUE Buffer,
        _In_ ULONG Capacity,
        _Out_ PULONG Count
    );

    /**************************************************/
    /*               操作过滤                           */
    /**************************************************/

    /* 操作是否允许（IsOperationAllowed：内部构造当前进程请求并过滤）。PASSIVE_LEVEL */
    BOOLEAN
    RpIsOperationAllowed(
        _In_ PCWSTR KeyPath,
        _In_ ULONG OpType
    );

    /* 操作过滤决策（FilterOperation：白名单优先 → 决策回调 →
     * 键保护位域判定；Block 时记账、写历史、经事件回调上行）。PASSIVE_LEVEL */
    NTSTATUS
    RpFilterOperation(
        _In_ const RG_OPERATION_REQUEST* Request,
        _Out_ PRG_DECISION_RESULT Result
    );

    /* 设置决策回调（锁内调用，覆盖默认判定；回调须快速返回不得重入引擎）。PASSIVE_LEVEL */
    NTSTATUS
    RpSetDecisionCallback(
        _In_opt_ RG_OPERATION_DECISION_CALLBACK Callback,
        _In_opt_ PVOID Context
    );

    /* 清除决策回调。PASSIVE_LEVEL */
    NTSTATUS
    RpClearDecisionCallback(
        VOID
    );

    /**************************************************/
    /*               完整性管理                         */
    /**************************************************/

    /* 校验键完整性（VerifyKeyIntegrity：防御性键缺失不误报——
     * 仅先前 Valid 的键消失判 Missing，其余缺失保持 Unknown）。PASSIVE_LEVEL */
    RG_INTEGRITY_STATUS
    RpVerifyKeyIntegrity(
        _In_ PCWSTR KeyPath
    );

    /* 校验值完整性（基线哈希比对；Missing/Modified 触发变更回调并记账）。PASSIVE_LEVEL */
    RG_INTEGRITY_STATUS
    RpVerifyValueIntegrity(
        _In_ PCWSTR KeyPath,
        _In_ PCWSTR ValueName
    );

    /* 校验全部受保护键（逐个 VerifyKeyIntegrity，结果数组）。PASSIVE_LEVEL */
    NTSTATUS
    RpVerifyAllIntegrity(
        _Out_writes_opt_(Capacity) PRG_KEY_INTEGRITY_RESULT Buffer,
        _In_ ULONG Capacity,
        _Out_ PULONG Count
    );

    /* 更新键基线（先建快照再置 Valid；Phase 锁外 I/O）。PASSIVE_LEVEL */
    NTSTATUS
    RpUpdateKeyBaseline(
        _In_ PCWSTR KeyPath
    );

    /* 更新值基线（读当前值 → 替换 expectedHash/Data）。PASSIVE_LEVEL */
    NTSTATUS
    RpUpdateValueBaseline(
        _In_ PCWSTR KeyPath,
        _In_ PCWSTR ValueName
    );

    /* 强制完整性检查（遍历全部受保护键，统计违规数并日志）。PASSIVE_LEVEL */
    VOID
    RpForceIntegrityCheck(
        VOID
    );

    /**************************************************/
    /*               快照 / 回滚                        */
    /**************************************************/

    /* 创建键快照（枚举值+子键，版本号单调递增；CreateSnapshot）。PASSIVE_LEVEL */
    NTSTATUS
    RpCreateSnapshot(
        _In_ PCWSTR KeyPath
    );

    /* 从快照恢复（Version=0 取最新；RestoreFromSnapshot）。PASSIVE_LEVEL */
    NTSTATUS
    RpRestoreFromSnapshot(
        _In_ PCWSTR KeyPath,
        _In_ ULONG Version
    );

    /* 枚举可用快照（返回深拷贝，呼叫方须逐个 RpFreeSnapshot 释放）。PASSIVE_LEVEL */
    NTSTATUS
    RpGetAvailableSnapshots(
        _In_ PCWSTR KeyPath,
        _Out_writes_opt_(Capacity) PRG_KEY_SNAPSHOT Buffer,
        _In_ ULONG Capacity,
        _Out_ PULONG Count
    );

    /* 释放 RpGetAvailableSnapshots 产出的快照动态缓冲。PASSIVE_LEVEL */
    VOID
    RpFreeSnapshot(
        _In_ PRG_KEY_SNAPSHOT Snapshot
    );

    /* 回滚键到最新快照（RollbackKey）。PASSIVE_LEVEL */
    NTSTATUS
    RpRollbackKey(
        _In_ PCWSTR KeyPath
    );

    /* 回滚值为基线数据（RollbackValue，Phase 锁外 I/O）。PASSIVE_LEVEL */
    NTSTATUS
    RpRollbackValue(
        _In_ PCWSTR KeyPath,
        _In_ PCWSTR ValueName
    );

    /* 清理超限旧快照（CleanupOldSnapshots）。PASSIVE_LEVEL */
    VOID
    RpCleanupOldSnapshots(
        VOID
    );

    /**************************************************/
    /*               白名单                             */
    /**************************************************/

    /* 加入白名单（名称大小写不敏感；上限 RG_MAX_WHITELIST）。PASSIVE_LEVEL */
    NTSTATUS
    RpAddToWhitelist(
        _In_ PCWSTR ProcessName
    );

    /* 移出白名单。PASSIVE_LEVEL */
    NTSTATUS
    RpRemoveFromWhitelist(
        _In_ PCWSTR ProcessName
    );

    /* 进程名是否在白名单（名称匹配，不含验签）。PASSIVE_LEVEL */
    BOOLEAN
    RpIsWhitelisted(
        _In_ PCWSTR ProcessName
    );

    /* 进程 ID 是否白名单（名称匹配 + 数字签名校验防改名绕过；
     * IsProcessWhitelisted：验签失败一律拒绝白名单）。PASSIVE_LEVEL */
    BOOLEAN
    RpIsWhitelistedProcessId(
        _In_ ULONG ProcessId
    );

    /* 枚举白名单（容量=项数×MAX_PATH 字符）。PASSIVE_LEVEL */
    NTSTATUS
    RpGetWhitelistedProcesses(
        _Out_writes_opt_(Capacity) PWSTR Buffer,
        _In_ ULONG Capacity,
        _Out_ PULONG Count
    );

    /**************************************************/
    /*               事件回调                           */
    /**************************************************/

    /* 注册事件回调（返回回调 ID；满 RG_MAX_CALLBACKS 返回资源不足）。PASSIVE_LEVEL */
    NTSTATUS
    RpRegisterEventCallback(
        _In_ RG_EVENT_CALLBACK Callback,
        _In_opt_ PVOID Context,
        _Out_ PULONG64 CallbackId
    );

    /* 注销事件回调。PASSIVE_LEVEL */
    VOID
    RpUnregisterEventCallback(
        _In_ ULONG64 CallbackId
    );

    /* 注册完整性违规回调。PASSIVE_LEVEL */
    NTSTATUS
    RpRegisterIntegrityCallback(
        _In_ RG_INTEGRITY_CALLBACK Callback,
        _In_opt_ PVOID Context,
        _Out_ PULONG64 CallbackId
    );

    /* 注销完整性违规回调。PASSIVE_LEVEL */
    VOID
    RpUnregisterIntegrityCallback(
        _In_ ULONG64 CallbackId
    );

    /* 注册值变更回调。PASSIVE_LEVEL */
    NTSTATUS
    RpRegisterValueChangeCallback(
        _In_ RG_VALUE_CHANGE_CALLBACK Callback,
        _In_opt_ PVOID Context,
        _Out_ PULONG64 CallbackId
    );

    /* 注销值变更回调。PASSIVE_LEVEL */
    VOID
    RpUnregisterValueChangeCallback(
        _In_ ULONG64 CallbackId
    );

    /**************************************************/
    /*               统计 / 历史                        */
    /**************************************************/

    /* 取统计快照（原子读 + 锁内时间字段）。PASSIVE_LEVEL */
    NTSTATUS
    RpGetStatistics(
        _Out_ PRG_PROTECTION_STATISTICS Stats
    );

    /* 重置统计（ResetStatistics，令牌把关归门面）。PASSIVE_LEVEL */
    VOID
    RpResetStatistics(
        VOID
    );

    /* 取事件历史（逆序：最新在前；GetEventHistory）。PASSIVE_LEVEL */
    NTSTATUS
    RpGetEventHistory(
        _Out_writes_opt_(Capacity) PRG_PROTECTION_EVENT Buffer,
        _In_ ULONG Capacity,
        _Out_ PULONG Count
    );

    /* 清空事件历史。PASSIVE_LEVEL */
    VOID
    RpClearEventHistory(
        VOID
    );

    /* 导出 JSON 报告（模块/版本/状态/模式/统计/计数；ExportReport）。PASSIVE_LEVEL */
    NTSTATUS
    RpExportReport(
        _Out_writes_(Size) PSTR Buffer,
        _In_ ULONG Size
    );

    /**************************************************/
    /*               自检 / 工具                        */
    /**************************************************/

    /* 引擎自检（规范化/根解析/子键提取/原子统计 4 项；SelfTest）。PASSIVE_LEVEL */
    BOOLEAN
    RpSelfTest(
        VOID
    );

    /* 键路径规范化（根键归一 + 子键小写折叠 + 去尾斜杠；返回 Out 或 NULL）。PASSIVE_LEVEL */
    PCWSTR
    RpNormalizeKeyPath(
        _In_ PCWSTR KeyPath,
        _Out_writes_(RG_MAX_KEY_PATH_LENGTH) PWSTR Out
    );

    /* 解析根键句柄（HKLM/HKCU/HKCR/HKU/HKCC；无效返回 NULL）。PASSIVE_LEVEL */
    HKEY
    RpParseRootKey(
        _In_ PCWSTR KeyPath
    );

    /* 提取子键路径（去根键前缀；无效返回 STATUS_INVALID_PARAMETER）。PASSIVE_LEVEL */
    NTSTATUS
    RpGetSubkeyPath(
        _In_ PCWSTR FullPath,
        _Out_writes_(RG_MAX_KEY_PATH_LENGTH) PWSTR Out
    );

    /* 取版本串（如 "1.0.0"）。PASSIVE_LEVEL */
    VOID
    RpGetVersionString(
        _Out_writes_(32) PSTR Out,
        _In_ ULONG OutCch
    );

    /**************************************************/
    /*               名称工具                           */
    /**************************************************/

    PCWSTR RpGetProtectionModeName(_In_ RG_PROTECTION_MODE Mode);          /* 固定字符串 */
    PCWSTR RpGetRegistryOperationName(_In_ ULONG Operation);
    PCWSTR RpGetProtectionTypeName(_In_ RG_KEY_PROTECTION_TYPE Type);
    PCWSTR RpGetIntegrityStatusName(_In_ RG_INTEGRITY_STATUS Status);
    PCWSTR RpGetValueTypeName(_In_ RG_REGISTRY_VALUE_TYPE Type);

    /* 操作位域 → "SetValue|DeleteValue"（SS FormatRegistryOperation）。PASSIVE_LEVEL */
    NTSTATUS
    RpFormatRegistryOperation(
        _In_ ULONG Operation,
        _Out_writes_(Size) PSTR Out,
        _In_ ULONG Size
    );

    /**************************************************/
    /*               内核桥（留桩）                     */
    /**************************************************/

    /* SyncProtectedKeysToKernel。WkD 无 SS Protocol 内核通道：
     * 留桩返回 STATUS_NOT_SUPPORTED，后续驱动桥接时启用。PASSIVE_LEVEL */
    NTSTATUS
    RpSyncProtectedKeysToKernel(
        VOID
    );

#ifdef __cplusplus
}
#endif