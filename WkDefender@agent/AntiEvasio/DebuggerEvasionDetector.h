/**************************************************/
/*  WkDefender Agent — 反调试检测引擎（分析目标样本视角）*/
/*  AntiEvasio                                      */
/*                                                  */
/*  迁移自 ShadowStrike DebuggerEvasionDetector       */
/*  (.cpp 5581行 + .hpp 2408行)。                    */
/*  功能：被动扫描分析目标进程的反调试技术，          */
/*   输出逃逸评分与技术清单。                        */
/*                                                  */
/*  与 AccessControl\AntiDebug.c 互补：              */
/*   AntiDebug.c = 受保护进程自防护视角；            */
/*   本模块 = 分析目标样本被动扫描视角。             */
/*                                                  */
/*  asm 文件不迁移：x64 无 __asm；RDTSC/CPUID 等    */
/*   用 <intrin.h> 等价替代；单步时序死检测丢弃。    */
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

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************/
/*               常量定义                          */
/**************************************************/

/* 最大检测数（每次分析的检测条目上限） */
#define EDE_MAX_DETECTIONS              128

/* 描述/详情字符串缓冲区长度 */
#define EDE_MAX_DESCRIPTION             128
#define EDE_MAX_DETAILS                 256

/* 进程名/路径缓冲区 */
#define EDE_MAX_PROCESS_NAME            64
#define EDE_MAX_PROCESS_PATH            260

/* 线程枚举上限（扫描多少线程的上下文） */
#define EDE_MAX_THREADS                 512

/* 内存区域枚举上限（VirtualQueryEx 扫描多少区域） */
#define EDE_MAX_MEMORY_REGIONS          2048

/* 句柄枚举上限 */
#define EDE_MAX_HANDLES                 65536

/* 时序采样次数 */
#define EDE_TIMING_SAMPLE_COUNT         10

/* 反调试字节模式：INT3 断点告警阈值（>= N 个 0xCC 则告警） */
#define EDE_BREAKPOINT_THRESHOLD        3

/* KUSER_SHARED_DATA 地址 (0x7FFE0000) */
#define EDE_KUSER_SHARED_DATA           ((PVOID)0x7FFE0000)

/* KUSER_SHARED_DATA.SystemCall 偏移 (0x0308) */
#define EDE_KUSER_SYSCALL_OFFSET        0x308

/* 评分阈值 */
#define EDE_HIGH_EVASION_THRESHOLD      70.0
#define EDE_CRITICAL_EVASION_THRESHOLD  90.0

/* 评分权重（按类别，Constants 权重） */
#define EDE_WEIGHT_PEB                  1.5
#define EDE_WEIGHT_HARDWARE_BP          2.5
#define EDE_WEIGHT_API                  1.2
#define EDE_WEIGHT_TIMING               2.0
#define EDE_WEIGHT_EXCEPTION            1.8
#define EDE_WEIGHT_OBJECT_HANDLE        1.6
#define EDE_WEIGHT_PROCESS_RELATIONSHIP 1.0
#define EDE_WEIGHT_MEMORY_ARTIFACTS     1.3
#define EDE_WEIGHT_SELF_DEBUGGING       1.5
#define EDE_WEIGHT_THREAD_BASED         1.4
#define EDE_WEIGHT_KERNEL_QUERIES       2.0
#define EDE_WEIGHT_CODE_INTEGRITY       1.8
#define EDE_WEIGHT_COMBINED             3.0

/* 默认扫描超时（毫秒） */
#define EDE_DEFAULT_TIMEOUT_MS          30000

/* 默认最大扫描区域大小（字节） */
#define EDE_MAX_SCAN_REGION_SIZE        (4 * 1024 * 1024)

/**************************************************/
/*               检测技术枚举                       */
/*  EvasionTechnique 数值，便于追溯。       */
/**************************************************/

typedef enum _EDE_TECHNIQUE {
    /* --- 无/未知 --- */
    EdeTechniqueNone                           = 0,

    /* --- PEB 类 (1-20) --- */
    EdeTechniquePEB_BeingDebugged              = 1,
    EdeTechniquePEB_NtGlobalFlag               = 2,
    EdeTechniquePEB_HeapFlags                  = 3,
    EdeTechniquePEB_HeapFlagsForceFlags        = 4,
    EdeTechniquePEB_HeapTailChecking           = 5,
    EdeTechniquePEB_LdrModuleList              = 6,
    EdeTechniquePEB_ProcessParameters          = 7,
    EdeTechniquePEB_OSVersionCheck             = 8,

    /* --- 硬件调试寄存器类 (21-26) --- */
    EdeTechniqueHW_BreakpointRegisters         = 21,
    EdeTechniqueHW_DebugStatusRegister         = 22,
    EdeTechniqueHW_DebugControlRegister        = 23,
    EdeTechniqueHW_GetThreadContext            = 24,
    EdeTechniqueHW_SetThreadContext            = 25,
    EdeTechniqueHW_ContextDebugEnum            = 26,

    /* --- API 类 (41-61) --- */
    EdeTechniqueAPI_IsDebuggerPresent          = 41,
    EdeTechniqueAPI_CheckRemoteDebuggerPresent = 42,
    EdeTechniqueAPI_NtQueryInfo_DebugPort      = 43,
    EdeTechniqueAPI_NtQueryInfo_DebugFlags     = 44,
    EdeTechniqueAPI_NtQueryInfo_DebugObject    = 45,
    EdeTechniqueAPI_NtQuerySysInfo_DebugObject = 46,
    EdeTechniqueAPI_NtSetThread_HideFromDbg    = 47,
    EdeTechniqueAPI_NtCreateThreadEx_Hide      = 48,
    EdeTechniqueAPI_NtClose_InvalidHandle      = 49,
    EdeTechniqueAPI_OutputDebugString          = 50,
    EdeTechniqueAPI_FindWindow_DebuggerClass   = 51,
    EdeTechniqueAPI_EnumWindows_AnalysisTools  = 52,
    EdeTechniqueAPI_GetModuleHandle_DebugDLL   = 53,
    EdeTechniqueAPI_BlockInput                 = 54,
    EdeTechniqueAPI_SuspendThread_Debugger     = 55,
    EdeTechniqueAPI_TerminateThread_Debugger   = 56,
    EdeTechniqueAPI_ZwSetInfoProc_Detach       = 57,
    EdeTechniqueAPI_NtQueryObject_DebugObject  = 58,
    EdeTechniqueAPI_RtlQueryHeapInfo           = 59,
    EdeTechniqueAPI_DbgBreakPoint              = 60,
    EdeTechniqueAPI_DbgUiRemoteBreakin         = 61,

    /* --- 时序类 (81-91) --- */
    EdeTechniqueTiming_RDTSC                   = 81,
    EdeTechniqueTiming_RDTSCP                  = 82,
    EdeTechniqueTiming_QueryPerformanceCounter  = 83,
    EdeTechniqueTiming_GetTickCount            = 84,
    EdeTechniqueTiming_GetTickCount64          = 85,
    EdeTechniqueTiming_GetSystemTime           = 86,
    EdeTechniqueTiming_timeGetTime             = 87,
    EdeTechniqueTiming_NtQueryPerfCounter      = 88,
    EdeTechniqueTiming_KUSER_SHARED_DATA       = 89,
    EdeTechniqueTiming_SleepValidation         = 90,
    EdeTechniqueTiming_WaitValidation          = 91,

    /* --- 异常类 (101-115) --- */
    EdeTechniqueException_INT2D                = 101,
    EdeTechniqueException_INT3                 = 102,
    EdeTechniqueException_INT1                 = 103,
    EdeTechniqueException_BreakpointHandler    = 104,
    EdeTechniqueException_SingleStepHandler    = 105,
    EdeTechniqueException_UnhandledException   = 106,
    EdeTechniqueException_VectoredHandler      = 107,
    EdeTechniqueException_SEHChainWalk         = 108,
    EdeTechniqueException_GuardPage            = 109,
    EdeTechniqueException_InvalidHandle        = 110,
    EdeTechniqueException_UD2                  = 111,
    EdeTechniqueException_PrefetchNTA          = 112,
    EdeTechniqueException_RaiseExceptionDbgCC  = 113,
    EdeTechniqueException_RaiseExceptionRip    = 114,
    EdeTechniqueException_ICEBP                = 115,

    /* --- 句柄对象类 (131-136) --- */
    EdeTechniqueObject_DebugObjectHandle       = 131,
    EdeTechniqueObject_KernelObjectEnum        = 132,
    EdeTechniqueObject_ProcessHandleEnum       = 133,
    EdeTechniqueObject_FileHandleDebugLog      = 134,
    EdeTechniqueObject_NamedPipeDebugger       = 135,
    EdeTechniqueObject_MailslotDebugger        = 136,

    /* --- 进程关系类 (151-157) --- */
    EdeTechniqueProcess_ParentNotExplorer      = 151,
    EdeTechniqueProcess_ParentIsDebugger       = 152,
    EdeTechniqueProcess_TreeDepthAnalysis      = 153,
    EdeTechniqueProcess_SiblingAnalysisTools   = 154,
    EdeTechniqueProcess_ChildDebugSpawning     = 155,
    EdeTechniqueProcess_CSRSSParent            = 156,
    EdeTechniqueProcess_SubsystemValidation    = 157,

    /* --- 内存制品类 (171-182) --- */
    EdeTechniqueMemory_SoftwareBreakpoints     = 171,
    EdeTechniqueMemory_HardwareBPTraps         = 172,
    EdeTechniqueMemory_DebugHeapSignatures     = 173,
    EdeTechniqueMemory_PageProtectionAnomaly   = 174,
    EdeTechniqueMemory_InjectedDebuggerDLL     = 175,
    EdeTechniqueMemory_CodeCaveAnalysis        = 176,
    EdeTechniqueMemory_APIHookDetection        = 177,
    EdeTechniqueMemory_TrampolineDetection     = 178,
    EdeTechniqueMemory_MappedDebugFiles        = 179,
    EdeTechniqueMemory_ExceptionHandlerCorrupt = 180,
    EdeTechniqueMemory_NtDllIntegrity          = 181,
    EdeTechniqueMemory_Kernel32Integrity       = 182,

    /* --- 自调试类 (201-205) --- */
    EdeTechniqueSelf_DebugActiveProcess        = 201,
    EdeTechniqueSelf_CreateProcessDebug        = 202,
    EdeTechniqueSelf_AntiAttach                = 203,
    EdeTechniqueSelf_DebugLoop                 = 204,
    EdeTechniqueSelf_WaitForDebugEvent         = 205,

    /* --- 线程类 (221-226) --- */
    EdeTechniqueThread_TLSCallback             = 221,
    EdeTechniqueThread_TLSDebugData            = 222,
    EdeTechniqueThread_HiddenThread            = 223,
    EdeTechniqueThread_ContextManipulation     = 224,
    EdeTechniqueThread_EnumerationDebugger     = 225,
    EdeTechniqueThread_PriorityBoost           = 226,

    /* --- 内核查询类 (241-245) --- */
    EdeTechniqueKernel_SystemKernelDebugger    = 241,
    EdeTechniqueKernel_SystemDebugControl      = 242,
    EdeTechniqueKernel_KUserSharedData         = 243,
    EdeTechniqueKernel_BootConfigDebug         = 244,
    EdeTechniqueKernel_DriverSigningDebug      = 245,

    /* --- 代码完整性类 (261-266) --- */
    EdeTechniqueCode_SectionChecksum           = 261,
    EdeTechniqueCode_EntryPointIntegrity       = 262,
    EdeTechniqueCode_ImportTableHooks          = 263,
    EdeTechniqueCode_ExportTableHooks          = 264,
    EdeTechniqueCode_InlineHooks               = 265,
    EdeTechniqueCode_DebugStringObfuscation    = 266,

    /* --- 高级/组合类 (281-286) --- */
    EdeTechniqueAdvanced_MultiTechniqueCheck   = 281,
    EdeTechniqueAdvanced_PolymorphicAntiDebug  = 282,
    EdeTechniqueAdvanced_EncryptedAntiDebug    = 283,
    EdeTechniqueAdvanced_VMExitDetection       = 284,
    EdeTechniqueAdvanced_HypervisorDebug       = 285,
    EdeTechniqueAdvanced_SideChannelDetection  = 286,

    /* --- 命令行/内核上下文类 (301-310) --- */
    EdeTechniqueKernelCtx_CmdLineDebuggerKeyword = 301,
    EdeTechniqueKernelCtx_SuspiciousLaunchDir    = 302,
    EdeTechniqueKernelCtx_ParentPidSpoofed       = 303,
    EdeTechniqueKernelCtx_AbnormalCmdLineLength  = 304,

    EdeTechniqueMax                           = 400
} EDE_TECHNIQUE;

/**************************************************/
/*          检测类别枚举（EvasionCategory） */
/**************************************************/

typedef enum _EDE_CATEGORY {
    EdeCategoryPEBBased              = 0,
    EdeCategoryHardwareDebugRegisters = 1,
    EdeCategoryAPIBased              = 2,
    EdeCategoryTimingBased           = 3,
    EdeCategoryExceptionBased        = 4,
    EdeCategoryObjectHandleBased     = 5,
    EdeCategoryProcessRelationship   = 6,
    EdeCategoryMemoryArtifacts       = 7,
    EdeCategorySelfDebugging         = 8,
    EdeCategoryThreadBased           = 9,
    EdeCategoryKernelQueries         = 10,
    EdeCategoryCodeIntegrity         = 11,
    EdeCategoryCombined              = 12,
    EdeCategoryKernelContext          = 13,
    EdeCategoryUnknown               = 255
} EDE_CATEGORY;

/**************************************************/
/*          严重度枚举（EvasionSeverity）   */
/**************************************************/

typedef enum _EDE_SEVERITY {
    EdeSeverityLow      = 0,
    EdeSeverityMedium   = 1,
    EdeSeverityHigh     = 2,
    EdeSeverityCritical = 3
} EDE_SEVERITY;

/**************************************************/
/*          分析深度                                */
/**************************************************/

typedef enum _EDE_DEPTH {
    EdeDepthQuick         = 0,  /* 仅 PEB + 基础 API */
    EdeDepthStandard      = 1,  /* + 时序 + 异常 + 进程关系 */
    EdeDepthDeep          = 2,  /* + 内存制品 + 线程 + 句柄 */
    EdeDepthComprehensive = 3   /* 全部（含内核查询 + 代码完整性） */
} EDE_DEPTH;

/**************************************************/
/*          分析标志位图（位域门控各检测子项）        */
/**************************************************/

#define EDE_FLAG_NONE                       0x00000000
#define EDE_FLAG_SCAN_PEB                   0x00000001  /* bit0: PEB 分析 */
#define EDE_FLAG_SCAN_HARDWARE_BP           0x00000002  /* bit1: 硬件断点 */
#define EDE_FLAG_SCAN_API                   0x00000004  /* bit2: API/DebugObject */
#define EDE_FLAG_SCAN_TIMING                0x00000008  /* bit3: 时序分析 */
#define EDE_FLAG_SCAN_EXCEPTION             0x00000010  /* bit4: 异常处理 */
#define EDE_FLAG_SCAN_OBJECT_HANDLES        0x00000020  /* bit5: 句柄枚举 */
#define EDE_FLAG_SCAN_PROCESS_RELATIONSHIPS 0x00000040  /* bit6: 进程关系 */
#define EDE_FLAG_SCAN_MEMORY_ARTIFACTS      0x00000080  /* bit7: 内存制品 */
#define EDE_FLAG_SCAN_SELF_DEBUGGING         0x00000100  /* bit8: 自调试 */
#define EDE_FLAG_SCAN_THREAD_TECHNIQUES     0x00000200  /* bit9: 线程（TLS/隐藏线程） */
#define EDE_FLAG_SCAN_KERNEL_QUERIES        0x00000400  /* bit10: 内核查询 */
#define EDE_FLAG_SCAN_CODE_INTEGRITY        0x00000800  /* bit11: 代码完整性 */
#define EDE_FLAG_SCAN_KERNEL_CONTEXT        0x00001000  /* bit12: 内核上下文（命令行） */

/* 行为标志 */
#define EDE_FLAG_ENABLE_CACHING             0x00010000  /* bit16: 结果缓存 */
#define EDE_FLAG_STOP_ON_FIRST_DETECTION    0x00020000  /* bit17: 首命中即停 */

/* 预设扫描档位 */
#define EDE_PRESET_QUICK          \
    (EDE_FLAG_SCAN_PEB | EDE_FLAG_SCAN_API | EDE_FLAG_ENABLE_CACHING)

#define EDE_PRESET_STANDARD       \
    (EDE_PRESET_QUICK | EDE_FLAG_SCAN_HARDWARE_BP | EDE_FLAG_SCAN_TIMING | \
     EDE_FLAG_SCAN_EXCEPTION | EDE_FLAG_SCAN_PROCESS_RELATIONSHIPS)

#define EDE_PRESET_DEEP           \
    (EDE_PRESET_STANDARD | EDE_FLAG_SCAN_MEMORY_ARTIFACTS | \
     EDE_FLAG_SCAN_THREAD_TECHNIQUES | EDE_FLAG_SCAN_OBJECT_HANDLES)

#define EDE_PRESET_COMPREHENSIVE  \
    (0x00001FFF | EDE_FLAG_ENABLE_CACHING)

#define EDE_PRESET_DEFAULT        EDE_PRESET_STANDARD

/**************************************************/
/*          检测类别位码（用于 detectedCategories） */
/**************************************************/

#define EDE_CAT_BIT(cat)  (1u << (cat))

/**************************************************/
/*          检测结果条目                            */
/**************************************************/

typedef struct _EDE_DETECTION {
    EDE_TECHNIQUE   Technique;
    EDE_CATEGORY    Category;
    EDE_SEVERITY    Severity;
    DOUBLE          Confidence;         /* 0.0 - 1.0 */
    ULONG_PTR       Address;            /* 相关内存地址（0=无） */
    ULONG           ThreadId;           /* 关联线程（0=无） */
    WCHAR           Description[EDE_MAX_DESCRIPTION];
    WCHAR           Details[EDE_MAX_DETAILS];
} EDE_DETECTION, *PEDE_DETECTION;

/**************************************************/
/*          分析配置                                */
/**************************************************/

typedef struct _EDE_CONFIG {
    EDE_DEPTH       Depth;              /* 分析深度（Quick/Standard/Deep/Comprehensive） */
    ULONG           Flags;              /* EDE_FLAG_* 位图（与 Depth 联合生效） */
    ULONG           TimeoutMs;          /* 扫描超时（毫秒，0=默认 30000） */
    ULONG           MaxThreads;         /* 最大扫描线程数（0=默认 512） */
    ULONG           MaxMemoryRegions;   /* 最大扫描内存区域数（0=默认 2048） */
    ULONG           MaxHandles;         /* 最大句柄枚举数（0=默认 65536） */
    DOUBLE          MinConfidence;      /* 最低置信度阈值（0.0=默认 0.0，全部上报） */
} EDE_CONFIG, *PEDE_CONFIG;

/**************************************************/
/*          分析结果                                */
/**************************************************/

typedef struct _EDE_RESULT {
    /* --- 标识 --- */
    ULONG           TargetPid;
    WCHAR           ProcessName[EDE_MAX_PROCESS_NAME];
    WCHAR           ProcessPath[EDE_MAX_PROCESS_PATH];
    BOOLEAN         Is64Bit;

    /* --- 评分摘要 --- */
    BOOLEAN         IsEvasive;
    DOUBLE          EvasionScore;       /* 0.0 - 100.0 */
    EDE_SEVERITY    MaxSeverity;
    ULONG           TotalDetections;
    ULONG           DetectedCategories; /* 位码：EDE_CAT_BIT(cat) 组合 */

    /* --- 检测详情 --- */
    EDE_DETECTION   Detections[EDE_MAX_DETECTIONS];
    ULONG           TechniquesChecked;

    /* --- 统计 --- */
    ULONG           ThreadsScanned;
    ULONG           MemoryRegionsScanned;
    ULONG           HandlesEnumerated;
    UINT64          BytesScanned;

    /* --- 时间戳 --- */
    LARGE_INTEGER   AnalysisStartTime;
    LARGE_INTEGER   AnalysisEndTime;

    /* --- 内核上下文（可选填充） --- */
    BOOLEAN         HasKernelContext;
} EDE_RESULT, *PEDE_RESULT;

/**************************************************/
/*          内核上下文（由驱动侧提供）               */
/*  携带进程创建时内核可信数据，                      */
/*  防止目标进程篡改用户态查询结果。                  */
/**************************************************/

typedef struct _EDE_KERNEL_CONTEXT {
    WCHAR           ImagePath[260];
    WCHAR           CommandLine[1024];
    ULONG           ParentProcessId;
    ULONG           CreatingProcessId;
    ULONG           CreatingThreadId;
    BOOLEAN         IsCreation;         /* TRUE=进程创建中，FALSE=进程终止 */
} EDE_KERNEL_CONTEXT, *PEDE_KERNEL_CONTEXT;

/**************************************************/
/*          统计快照                                */
/**************************************************/

typedef struct _EDE_STATS {
    volatile LONG64  TotalAnalyses;
    volatile LONG64  EvasiveProcesses;
    volatile LONG64  TotalDetections;
    volatile LONG64  AnalysisErrors;
    /* 分类检测计数（categoryDetections） */
    volatile LONG64  CategoryDetections[16];
} EDE_STATS, *PEDE_STATS;

/**************************************************/
/*          回调类型                                */
/**************************************************/

/* 检测回调：每命中一条检测触发。 */
typedef VOID (CALLBACK *PDEDE_DETECTION_CALLBACK)(
    _In_ ULONG TargetPid,
    _In_ const EDE_DETECTION* Detection,
    _In_opt_ PVOID Context
    );

/**************************************************/
/*          公共 API                               */
/**************************************************/

/* ------------------------------------------------------------------ */
/* 主入口：对指定进程执行全量反调试检测分析。                            */
/*  ProcessId 为目标分析进程 PID。                                      */
/*  Config 为扫描配置（NULL=默认 Comprehensive）。                      */
/*  Result 接收分析结果（调用方分配，不可为 NULL）。                     */
/*  返回 NTSTATUS（STATUS_SUCCESS 表示分析完成，不代表未发现逃逸）。    */
/*  分析结果在 Result->IsEvasive / EvasionScore / Detections[] 中。    */
/* ------------------------------------------------------------------ */
_Must_inspect_result_
NTSTATUS
EdeAnalyzeProcess(
    _In_  ULONG              ProcessId,
    _In_opt_ const EDE_CONFIG* Config,
    _Out_ PEDE_RESULT         Result
    );

/* ------------------------------------------------------------------ */
/* 主入口（增强版）：额外接收内核上下文。                                */
/*  KernelContext 为驱动侧传来的可信进程创建数据（可为 NULL）。         */
/*  若非 NULL，则使用内核可信数据替代用户态查询（命令行/父进程/路径）。  */
/* ------------------------------------------------------------------ */
_Must_inspect_result_
NTSTATUS
EdeAnalyzeProcessWithContext(
    _In_  ULONG              ProcessId,
    _In_opt_ const EDE_CONFIG* Config,
    _In_opt_ const EDE_KERNEL_CONTEXT* KernelContext,
    _Out_ PEDE_RESULT         Result
    );

/* ------------------------------------------------------------------ */
/* 初始化/清理（全局统计与缓存）。                                      */
/*  EdeInitialize 须在首次调用 EdeAnalyzeProcess 前调用。              */
/*  EdeShutdown 释放所有资源。                                          */
/* ------------------------------------------------------------------ */
_Must_inspect_result_
NTSTATUS
EdeInitialize(
    _Outptr_ PEDE_STATS* GlobalStats
    );

VOID
EdeShutdown(
    _In_opt_ _Post_invalid_ PEDE_STATS GlobalStats
    );

/* ------------------------------------------------------------------ */
/* 回调注册（可选，每条检测命中时同步触发）。                            */
/* ------------------------------------------------------------------ */
VOID
EdeSetDetectionCallback(
    _In_opt_ PDEDE_DETECTION_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

/* ------------------------------------------------------------------ */
/* 类别/技术可读名称。                                                  */
/* ------------------------------------------------------------------ */
PCWSTR
EdeTechniqueName(
    _In_ EDE_TECHNIQUE Technique
    );

PCWSTR
EdeCategoryName(
    _In_ EDE_CATEGORY Category
    );

PCWSTR
EdeSeverityName(
    _In_ EDE_SEVERITY Severity
    );

#ifdef __cplusplus
}
#endif
