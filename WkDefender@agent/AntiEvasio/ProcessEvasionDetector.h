/**************************************************/
/*  WkDefender Agent — 进程逃逸检测引擎                */
/*  AntiEvasio                                      */
/*                                                  */
/*  迁移自 ShadowStrike ProcessEvasionDetector       */
/*  (.hpp 752行 + .cpp 3364行)。                     */
/*                                                  */
/*  检测类别：                                       */
/*    1. 注入检测 (DLL/Hollowing/APC/反射/线程劫持)   */
/*    2. 代码注入 (RWX/远程线程/Hook/IAT)             */
/*    3. 伪装检测 (路径/父进程/签名/命令行)           */
/*    4. 反调试   (调试端口/硬件断点/时序/TLS)        */
/*    5. 权限提升 (SeDebug/Token/UAC)                */
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

/* 最大检测数 */
#define PES_MAX_DETECTIONS          128

/* 最大内存区域数 */
#define PES_MAX_MEMORY_REGIONS      4096

/* 最大线程数（单次检测上限） */
#define PES_MAX_THREADS             1024

/* 最大模块数 */
#define PES_MAX_MODULES             2048

/* 最大路径长度 */
#define PES_MAX_PATH                512

/* 最大描述/详情字符串长度 */
#define PES_MAX_DESCRIPTION         256
#define PES_MAX_DETAILS             512

/* 最大注入 DLL 数量 */
#define PES_MAX_INJECTED_DLLS       32

/* 最大 RWX 地址数量 */
#define PES_MAX_RWX_ADDRESSES       256

/* 最大检测技术字符串数 */
#define PES_MAX_TECHNIQUE_STRINGS   32

/* 最大导入函数名称长度 */
#define PES_MAX_IMPORT_NAME         128

/* 最大导入 DLL 名称长度 */
#define PES_MAX_DLL_NAME            128

/* 评分阈值 */
#define PES_MIN_EVASION_SCORE       50.0f
#define PES_HIGH_CONFIDENCE_SCORE   80.0f

/* 内存扫描限制 */
#define PES_MAX_SCAN_ITERATIONS     500000
#define PES_MAX_SCAN_SIZE_BYTES     (16ULL * 1024 * 1024 * 1024)  /* 16 GB */
#define PES_MAX_SUSPICIOUS_REGIONS  10000
#define PES_MEMORY_SCAN_BUFFER      4096
#define PES_MAX_HOOK_SCAN_BYTES     64

/* 缓存 */
#define PES_CACHE_TTL_SECONDS       300
#define PES_MAX_TRACKED_PROCESSES   10000

/* 已知合法进程路径表大小 */
#define PES_KNOWN_PROCESSES         15
/* 期望父进程映射表大小 */
#define PES_EXPECTED_PARENT_ENTRIES 12
/* 每个进程最大合法父进程数 */
#define PES_MAX_PARENTS_PER_PROC    6

/**************************************************/
/*          枚举：检测技术                         */
/*  ProcessEvasionTechnique                */
/*  分组：注入(1-50) 代码(51-100) 伪装(101-150)   */
/*        反调试(151-200) 权限(201-250) 枚举(251-300) */
/**************************************************/

typedef enum _PES_TECHNIQUE {
    PES_TECHNIQUE_UNKNOWN = 0,

    /* 注入 (1-50) */
    PES_TECHNIQUE_INJ_ClassicDLL          = 1,
    PES_TECHNIQUE_INJ_ReflectiveDLL       = 2,
    PES_TECHNIQUE_INJ_ProcessHollowing    = 3,
    PES_TECHNIQUE_INJ_ThreadHijacking     = 4,
    PES_TECHNIQUE_INJ_APCInjection        = 5,
    PES_TECHNIQUE_INJ_AtomBombing         = 6,
    PES_TECHNIQUE_INJ_Doppelganging       = 7,
    PES_TECHNIQUE_INJ_Herpaderping        = 8,
    PES_TECHNIQUE_INJ_EarlyBird           = 9,
    PES_TECHNIQUE_INJ_ExtraWindowMemory   = 10,

    /* 代码注入检测 (51-100) */
    PES_TECHNIQUE_CODE_SuspiciousRWX      = 51,
    PES_TECHNIQUE_CODE_CrossProcessWrite  = 52,
    PES_TECHNIQUE_CODE_RemoteThread       = 53,
    PES_TECHNIQUE_CODE_ShellcodePattern   = 54,
    PES_TECHNIQUE_CODE_IATHooking         = 55,
    PES_TECHNIQUE_CODE_InlineHooking      = 56,
    PES_TECHNIQUE_CODE_VEHHooking         = 57,
    PES_TECHNIQUE_CODE_TrampolineHook     = 58,

    /* 伪装 (101-150) */
    PES_TECHNIQUE_MASK_NameAbuse          = 101,
    PES_TECHNIQUE_MASK_ParentSpoofing     = 102,
    PES_TECHNIQUE_MASK_PathAnomaly        = 103,
    PES_TECHNIQUE_MASK_CmdLineInconsist   = 104,
    PES_TECHNIQUE_MASK_SignatureFailure   = 105,
    PES_TECHNIQUE_MASK_DoubleExtension    = 106,
    PES_TECHNIQUE_MASK_IconMismatch       = 107,

    /* 反调试 (151-200) */
    PES_TECHNIQUE_ANTI_DebuggerPresent    = 151,
    PES_TECHNIQUE_ANTI_CheckRemoteDbg     = 152,
    PES_TECHNIQUE_ANTI_NtQueryDebugPort   = 153,
    PES_TECHNIQUE_ANTI_DebugObject        = 154,
    PES_TECHNIQUE_ANTI_HWBreakpoint       = 155,
    PES_TECHNIQUE_ANTI_SWBreakpoint       = 156,
    PES_TECHNIQUE_ANTI_TimingDetection    = 157,
    PES_TECHNIQUE_ANTI_ParentDebugger     = 158,
    PES_TECHNIQUE_ANTI_SEH                = 159,
    PES_TECHNIQUE_ANTI_OutputDebugString  = 160,
    PES_TECHNIQUE_ANTI_TLSCallback        = 161,

    /* 权限提升 (201-250) */
    PES_TECHNIQUE_PRIV_SeDebug            = 201,
    PES_TECHNIQUE_PRIV_TokenManip         = 202,
    PES_TECHNIQUE_PRIV_UACBypass          = 203,
    PES_TECHNIQUE_PRIV_IntegrityAnomaly   = 204,
    PES_TECHNIQUE_PRIV_ImpersonationToken = 205,

    /* 枚举规避 (251-300) */
    PES_TECHNIQUE_ENUM_HiddenProcess      = 251,
    PES_TECHNIQUE_ENUM_DKOM               = 252,
    PES_TECHNIQUE_ENUM_PEBManipulation    = 253,
    PES_TECHNIQUE_ENUM_NameRandomization  = 254,
    PES_TECHNIQUE_ENUM_TempProcess        = 255,
} PES_TECHNIQUE;

/**************************************************/
/*          枚举：注入方法                         */
/**************************************************/

typedef enum _PES_METHOD {
    PES_METHOD_Unknown       = 0,
    PES_METHOD_ClassicDLL    = 1,
    PES_METHOD_ReflectiveDLL = 2,
    PES_METHOD_Hollowing     = 3,
    PES_METHOD_ThreadHijack  = 4,
    PES_METHOD_APC           = 5,
    PES_METHOD_AtomBombing   = 6,
    PES_METHOD_Doppelganging = 7,
    PES_METHOD_Herpaderping  = 8,
} PES_METHOD;

/**************************************************/
/*          枚举：严重度                           */
/**************************************************/

typedef enum _PES_SEVERITY {
    PES_SEVERITY_Low      = 0,
    PES_SEVERITY_Medium   = 1,
    PES_SEVERITY_High     = 2,
    PES_SEVERITY_Critical = 3,
} PES_SEVERITY;

/**************************************************/
/*          枚举：分析标志 (位码)                   */
/**************************************************/

#define PES_FLAG_CheckInjection        0x00000001u
#define PES_FLAG_CheckMasquerading     0x00000002u
#define PES_FLAG_CheckAntiDebug        0x00000004u
#define PES_FLAG_CheckPrivilege        0x00000008u
#define PES_FLAG_CheckEnumeration      0x00000010u
#define PES_FLAG_CheckMemory           0x00000020u
#define PES_FLAG_CheckThreads          0x00000040u
#define PES_FLAG_CheckModules          0x00000080u
#define PES_FLAG_EnableCaching         0x00000100u
#define PES_FLAG_DeepAnalysis          0x00000200u
#define PES_FLAG_All                   0xFFFFFFFFu
#define PES_FLAG_Default               (PES_FLAG_CheckInjection | PES_FLAG_CheckMasquerading | PES_FLAG_CheckAntiDebug | PES_FLAG_EnableCaching)

/**************************************************/
/*          结构体：错误信息                       */
/**************************************************/

typedef struct _PES_ERROR {
    DWORD   Win32Code;
    WCHAR   Message[256];
    WCHAR   Context[256];
} PES_ERROR, *PPES_ERROR;

/**************************************************/
/*          结构体：检测到的技术                   */
/**************************************************/

typedef struct _PES_DETECTED_TECHNIQUE {
    PES_TECHNIQUE  Technique;
    PES_SEVERITY   Severity;
    DOUBLE         Confidence;
    WCHAR          Description[PES_MAX_DESCRIPTION];
    WCHAR          Details[PES_MAX_DETAILS];
    ULONGLONG      Timestamp;     /* FILETIME */
} PES_DETECTED_TECHNIQUE, *PPES_DETECTED_TECHNIQUE;

/**************************************************/
/*          结构体：注入检测信息                   */
/**************************************************/

typedef struct _PES_INJECTION_INFO {
    BOOLEAN   HasInjection;
    PES_METHOD Method;
    ULONG     InjectedThreadCount;
    ULONG     SuspiciousMemoryRegions;
    ULONG64   RwxAddresses[PES_MAX_RWX_ADDRESSES];
    ULONG     RwxAddressCount;
    WCHAR     InjectedDLLs[PES_MAX_INJECTED_DLLS][PES_MAX_PATH];
    ULONG     InjectedDLLCount;
    BOOLEAN   HasRemoteThreads;
    BOOLEAN   HasHollowedImage;
    BOOLEAN   Valid;
} PES_INJECTION_INFO, *PPES_INJECTION_INFO;

/**************************************************/
/*          结构体：伪装检测信息                   */
/**************************************************/

typedef struct _PES_MASQUERADE_INFO {
    BOOLEAN IsMasquerading;
    WCHAR   ExpectedPath[PES_MAX_PATH];
    WCHAR   ActualPath[PES_MAX_PATH];
    WCHAR   ExpectedParent[PES_MAX_PATH];
    WCHAR   ActualParent[PES_MAX_PATH];
    BOOLEAN HasPathAnomaly;
    BOOLEAN HasParentSpoof;
    BOOLEAN HasSignatureFailure;
    BOOLEAN Valid;
} PES_MASQUERADE_INFO, *PPES_MASQUERADE_INFO;

/**************************************************/
/*          结构体：反调试信息                     */
/**************************************************/

typedef struct _PES_ANTIDEBUG_INFO {
    BOOLEAN HasAntiDebug;
    BOOLEAN IsDebuggerPresent;
    BOOLEAN HasDebugPrivilege;
    BOOLEAN HasHWBreakpoints;
    BOOLEAN HasSWBreakpoints;
    WCHAR   TechniqueStrings[PES_MAX_TECHNIQUE_STRINGS][PES_MAX_DESCRIPTION];
    ULONG   TechniqueCount;
    BOOLEAN Valid;
} PES_ANTIDEBUG_INFO, *PPES_ANTIDEBUG_INFO;

/**************************************************/
/*          结构体：内存区域信息                   */
/**************************************************/

typedef struct _PES_MEMORY_REGION {
    ULONG64 BaseAddress;
    ULONG64 Size;
    ULONG   Protection;
    ULONG   Type;
    BOOLEAN IsExecutable;
    BOOLEAN IsWritable;
    BOOLEAN IsReadable;
    BOOLEAN IsSuspicious;
    WCHAR   Description[PES_MAX_DESCRIPTION];
} PES_MEMORY_REGION, *PPES_MEMORY_REGION;

/**************************************************/
/*          结构体：内核上下文（防篡改数据）        */
/*  来源于内核 PsSetCreateProcessNotifyRoutineEx   */
/**************************************************/

typedef struct _PES_KERNEL_CONTEXT {
    WCHAR   ImagePath[PES_MAX_PATH];
    WCHAR   CommandLine[PES_MAX_PATH];
    ULONG   ParentProcessId;
    ULONG   CreatingProcessId;
    ULONG   CreatingThreadId;
    BOOLEAN HasKernelData;   /* 由调用者设置 */
} PES_KERNEL_CONTEXT, *PPES_KERNEL_CONTEXT;

/**************************************************/
/*          结构体：分析配置                       */
/**************************************************/

typedef struct _PES_CONFIG {
    ULONG              Flags;          /* PES_FLAG_* */
    ULONG              CacheTtlSec;
    BOOLEAN            EnableDeepScan;
    BOOLEAN            CheckAllThreads;
    BOOLEAN            CheckAllModules;
    PES_KERNEL_CONTEXT KernelContext;
    BOOLEAN            HasKernelCtx;
} PES_CONFIG, *PPES_CONFIG;

/* 初始化默认配置 */
#define PES_CONFIG_DEFAULT { \
    .Flags          = PES_FLAG_Default, \
    .CacheTtlSec    = PES_CACHE_TTL_SECONDS, \
    .EnableDeepScan = FALSE, \
    .CheckAllThreads= TRUE, \
    .CheckAllModules= TRUE, \
    .HasKernelCtx   = FALSE, \
}

/**************************************************/
/*          结构体：单条检测结果                   */
/**************************************************/

/* 注意：PES_DETECTED_TECHNIQUE 定义在上面 */

/**************************************************/
/*          结构体：分析结果                       */
/**************************************************/

typedef struct _PES_RESULT {
    /* 进程信息 */
    ULONG     ProcessId;
    WCHAR     ProcessName[MAX_PATH];
    WCHAR     ProcessPath[PES_MAX_PATH];
    ULONG     ParentProcessId;
    WCHAR     ParentProcessName[MAX_PATH];

    /* 综合判定 */
    BOOLEAN   IsEvasive;
    FLOAT     EvasionScore;
    PES_SEVERITY MaxSeverity;
    WCHAR     ConfidenceLevel[32];

    /* 子结构信息 */
    PES_INJECTION_INFO   InjectionInfo;
    PES_MASQUERADE_INFO  MasqueradeInfo;
    PES_ANTIDEBUG_INFO   AntiDebugInfo;

    /* 内存区域 */
    PES_MEMORY_REGION   MemoryRegions[PES_MAX_MEMORY_REGIONS];
    ULONG               MemoryRegionCount;

    /* 检测到的技术列表 */
    PES_DETECTED_TECHNIQUE Techniques[PES_MAX_DETECTIONS];
    ULONG               TotalDetections;
    ULONG               DetectedCategories;   /* 位码 */

    /* 分析元数据 */
    PES_CONFIG  Config;
    ULONGLONG   AnalysisStartMs;
    ULONGLONG   AnalysisEndMs;
    ULONGLONG   AnalysisDurationMs;
    BOOLEAN     AnalysisComplete;
    BOOLEAN     FromCache;
} PES_RESULT, *PPES_RESULT;

/**************************************************/
/*          结构体：全局统计                       */
/**************************************************/

typedef struct _PES_STATS {
    volatile LONG64 TotalAnalyses;
    volatile LONG64 EvasiveProcesses;
    volatile LONG64 InjectionsDetected;
    volatile LONG64 MasqueradingDetected;
    volatile LONG64 AntiDebugDetected;
    volatile LONG64 TotalDetections;
    volatile LONG64 CacheHits;
    volatile LONG64 CacheMisses;
    volatile LONG64 AnalysisErrors;
    volatile LONG64 TotalAnalysisTimeUs;
    volatile LONG64 CategoryDetections[8];
} PES_STATS, *PPES_STATS;

/**************************************************/
/*          回调函数类型                           */
/**************************************************/

typedef VOID (CALLBACK *PES_DETECTION_CALLBACK)(
    _In_ ULONG                     ProcessId,
    _In_ const PES_DETECTED_TECHNIQUE* Technique,
    _In_opt_ PVOID                 Context
    );

/**************************************************/
/*          内核上下文辅助宏                       */
/**************************************************/

/* 初始化内核上下文结构 */
#define PES_INIT_KERNEL_CONTEXT(pCtx) do { \
    RtlZeroMemory((pCtx), sizeof(PES_KERNEL_CONTEXT)); \
} while(0)

/* 标记内核上下文有效 */
#define PES_SET_KERNEL_DATA_VALID(pCtx) do { \
    (pCtx)->HasKernelData = TRUE; \
} while(0)

/**************************************************/
/*          编译器 / SAL 注解                      */
/**************************************************/

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4201)  /* 非名称的结构/联合 */
#endif

/**************************************************/
/*          前向声明                               */
/**************************************************/

/* NT 函数类型（内部使用） */
typedef NTSTATUS (NTAPI *PfnNtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef NTSTATUS (NTAPI *PfnNtQueryInformationThread)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

/**************************************************/
/*          公共 API — 初始化/关闭                 */
/**************************************************/

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PesInitialize(
    _In_opt_ PPES_CONFIG Config
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
PesShutdown(
    VOID
    );

/**************************************************/
/*          公共 API — 进程分析                   */
/**************************************************/

/* TYPE B：分析目标进程（完整） */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PesAnalyzeProcess(
    _In_  HANDLE     ProcessHandle,
    _In_  PPES_CONFIG Config,
    _Out_ PPES_RESULT Result
    );

/* TYPE B：按 PID 分析 */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PesAnalyzeProcessById(
    _In_  ULONG      ProcessId,
    _In_  PPES_CONFIG Config,
    _Out_ PPES_RESULT Result
    );

/**************************************************/
/*          公共 API — 专项检测                    */
/**************************************************/

/* 注入检测 */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PesDetectInjection(
    _In_  HANDLE               ProcessHandle,
    _Out_ PPES_INJECTION_INFO  Info
    );

/* 伪装检测 */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PesDetectMasquerading(
    _In_  ULONG                ProcessId,
    _Out_ PPES_MASQUERADE_INFO Info
    );

/* 反调试检测 */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PesDetectAntiDebug(
    _In_  HANDLE               ProcessHandle,
    _In_  ULONG                ProcessId,
    _Out_ PPES_ANTIDEBUG_INFO  Info
    );

/* 内存扫描 */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PesScanMemory(
    _In_  HANDLE               ProcessHandle,
    _Out_ PPES_MEMORY_REGION   Regions,
    _In_  ULONG                MaxRegions,
    _Out_ PULONG               ActualCount
    );

/**************************************************/
/*          公共 API — 回调/统计/工具              */
/**************************************************/

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
PesSetDetectionCallback(
    _In_opt_ PES_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID                  Context
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
PesGetStatistics(
    _Out_ PPES_STATS Stats
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
PesResetStatistics(
    VOID
    );

/**************************************************/
/*          公共 API — 名称查询                   */
/**************************************************/

_Must_inspect_result_
PCWSTR
PesTechniqueName(
    _In_ PES_TECHNIQUE Technique
    );

_Must_inspect_result_
PCWSTR
PesSeverityName(
    _In_ PES_SEVERITY Severity
    );

_Must_inspect_result_
PCWSTR
PesMethodName(
    _In_ PES_METHOD Method
    );

_Must_inspect_result_
PCSTR
PesTechniqueMitreId(
    _In_ PES_TECHNIQUE Technique
    );

/* 标记结果结构体已初始化 */
#define PES_INIT_RESULT(pResult) do { \
    RtlZeroMemory((pResult), sizeof(PES_RESULT)); \
    (pResult)->MaxSeverity = PES_SEVERITY_Low; \
} while(0)

#if defined(_MSC_VER)
#pragma warning(pop)
#endif
