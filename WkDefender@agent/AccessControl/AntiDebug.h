/**************************************************/
/*  WkDefender Agent — 反调试检测引擎 (AntiDebug)     */
/*                                                     */
/*  纯 C 实现 ShadowStrike AntiDebug.cpp/hpp 迁移。     */
/*  功能：检测进程被调试/被逆向（PEB/TEB、API、时序、  */
/*   硬件断点、异常、内存钩子、调试器/插桩框架），      */
/*   并执行防护（线程隐藏、调试寄存器清除、CRC32 基线）、*/
/*   分级处置并回调上报。                              */
/*                                                     */
/*  与驱动端 AntiDebug（内核级 5 类检测）互补：本引擎   */
/*   为用户态主动防御层。                              */
/*                                                     */
/*  生命周期：SpInitializeAntiDebugProtection -> AdApplyProtection ->      */
/*   AcpVerifySignalProtectedProcessAntiDebug(自身+受保护进程链)/AcStartAntiDebugProtection -> */
/*   AdStopMonitoring -> AdCleanup。                   */
/*                                                     */
/*  全部函数 PASSIVE_LEVEL。                            */
/*  编码：UTF-8 with BOM（铁律）                       */
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
/**************************************************/

#define AD_MAX_PROCESSES            100         /* 调试器进程快照上限 */
#define AD_MAX_WINDOWS              50          /* 调试器窗口上限 */
#define AD_MAX_HISTORY              1000        /* 检测历史环形缓冲上限 */
#define AD_MAX_MEMORY_REGIONS       1000        /* 受保护内存区域上限 */
#define AD_TIMING_SAMPLE_COUNT      10          /* 时序采样次数（对齐 SS TIMING_SAMPLE_COUNT=10） */

/* 检测权重（0-100，对齐 SS AntiDebugConstants 每类权重） */
#define AD_WEIGHT_PEB_DETECTION     25
#define AD_WEIGHT_API_DETECTION     30
#define AD_WEIGHT_TIMING_DETECTION  20
#define AD_WEIGHT_HW_BP_DETECTION   35
#define AD_WEIGHT_SOFTWARE_BP_DETECTION 40
#define AD_WEIGHT_EXCEPTION_DETECTION 15
#define AD_WEIGHT_PROCESS_DETECTION 20
#define AD_WEIGHT_HOOK_DETECTION    45
#define AD_WEIGHT_INSTRUMENTATION_DETECTION 50

/* 时序阈值（对齐 SS AntiDebugConstants） */
#define AD_RDTSC_SINGLE_THRESHOLD   500         /* RDTSC 单指令阈值（周期） */
#define AD_RDTSC_BLOCK_THRESHOLD    10000       /* RDTSC 指令块阈值 */
#define AD_TIMING_ANOMALY_NS        1000000     /* QPC 时序异常阈值（纳秒） */
#define AD_TICKCOUNT_THRESHOLD_MS   100         /* GetTickCount 增量阈值（毫秒） */

/* 内存扫描上限（对齐 SS） */
#define AD_MAX_HOOKS_PER_MODULE     500         /* 每模块钩子上限 */
#define AD_MAX_BREAKPOINTS_THRESHOLD 3           /* 0xCC 断点告警阈值（对齐 SS=3） */

/* NtGlobalFlag 调试位掩码（FLG_HEAP_ENABLE_TAIL_CHECK|FREE_CHECK|VALIDATE_PARAMETERS） */
#define AD_NT_GLOBAL_FLAG_DEBUGGED  0x70UL

/* 默认监测间隔（毫秒） */
#define AD_DEFAULT_MONITOR_INTERVAL_MS  5000
#define AD_MIN_DETECTION_SCORE          40

/**************************************************/
/*               检测技术枚举                       */
/*  对齐 ShadowStrike DetectionTechnique。         */
/*  2026-09-08：移除 AdTechniqueMemoryCrc32（代码节  */
/*  完整性校验移交 MemoryProtection 模块），其后续位  */
/*  码整体前移一位（MemoryIatHook 起）。            */
/**************************************************/

typedef enum _AC_ANTIDEBUG_TECHNIQUE {
    AdTechniqueNone = 0,
    AdTechniquePebBeingDebugged,      /* PEB.BeingDebugged */
    AdTechniquePebHeapFlags,          /* PEB.Heap->Flags/ForceFlags */
    AdTechniquePebNtGlobalFlag,       /* PEB.NtGlobalFlag 调试节 */
    AdTechniquePebProcessHeap,        /* PEB.ProcessHeap (HeapQueryInformation) */
    AdTechniqueTebThreadInfo,         /* TEB / NtCurrentTeb() 类 */
    AdTechniqueIsDebuggerPresent,     /* IsDebuggerPresent API */
    AdTechniqueCheckRemoteDebugger,   /* CheckRemoteDebuggerPresent */
    AdTechniqueNtQueryDebugPort,      /* NtQueryInformationProcess DebugPort */
    AdTechniqueNtQueryDebugFlags,     /* NtQueryInformationProcess DebugFlags */
    AdTechniqueNtQueryDebugObject,    /* DebugObjectHandle/调试对象 */
    AdTechniqueNtQueryProcessBasic,   /* PROCESS_BASIC_INFORMATION 类 */
    AdTechniqueOutputDebugString,     /* OutputDebugString 行为 */
    AdTechniqueCloseHandle,           /* CloseHandle 无效句柄异常 */
    AdTechniqueTimingRdtsc,           /* RDTSC 时序差 */
    AdTechniqueTimingQueryPerf,       /* QueryPerformanceCounter 时序差 */
    AdTechniqueTimingGetTickCount,    /* GetTickCount 时序差 */
    AdTechniqueTimingInstruction,     /* 指令块执行时序 */
    AdTechniqueHardwareBreakpoint,    /* Dr0-Dr3/Dr7 */
    AdTechniqueHardwareContext,       /* 逐线程 RegisterDr */
    AdTechniqueExceptionInt3,         /* INT3 异常被吞 */
    AdTechniqueExceptionGuardPage,    /* GuardPage 异常被吞 */
    AdTechniqueExceptionVeh,          /* VEH 链被截 */
    AdTechniqueExceptionTrap,         /* 单步/陷阱异常 */
    AdTechniqueMemoryInt3,            /* 0xCC 断点序言 */
    AdTechniqueMemoryIatHook,         /* IAT 钩子 */
    AdTechniqueMemoryInlineHook,      /* 内联钩子（序言跳转） */
    AdTechniqueProcessDebugger,       /* 调试器进程快照 */
    AdTechniqueWindowDebugger,        /* 调试器窗口类枚举 */
    AdTechniqueKernelDebugger,        /* 内核调试器（驱动端补充） */
    AdTechniqueDebuggerDriver,        /* 调试器驱动设备探测 */
    AdTechniqueParentProcess,         /* 父进程可疑 */
    AdTechniqueInstrumentationFrida,  /* Frida */
    AdTechniqueInstrumentationDynamo, /* DynamoRIO */
    AdTechniqueInstrumentationPin,    /* Intel PIN */
    AdTechniqueInstrumentationDetours,/* MS Detours */
    AdTechniqueInstrumentationApiMonitor, /* API Monitor */
    AdTechniqueInstrumentationGeneric,    /* 其它插桩框架 */
    AdTechniqueMemoryDelayImport,         /* 延迟导入表钩子（2026-09-07 末尾追加，位码稳定） */
    AdTechniqueMax
} AC_ANTIDEBUG_TECHNIQUE;

/* 检测项使能位图（policy 使能开关，2026-09-06）。按 AC_ANTIDEBUG_TECHNIQUE 下标位。
 *  - AD_MASK_ALL：显式全激活（全部位置 1），EDR 自身/系统服务级守护默认。
 *  - AD_MASK_NONE（0）：显式全关闭；不再有任何哨兵语义（2026-09-07）。
 *  - 位图即最终使能：需要哪些能力就置哪些位，无需"0=全激活"类特判。 */
#define AD_MASK_ALL              (~0ULL)
#define AD_MASK_NONE             0ULL
#define AC_ANTIDEBUG_TECHNIQUE_MASK_ALL(Mask)   ((Mask) == AD_MASK_ALL)
#define AC_ANTIDEBUG_TECHNIQUE_MASK_BIT(Tech)           (1ULL << (Tech))

/* 仅自省可执行的技术位集合（检测语义仅对 EDR 自身成立：时序基线/RDTSC、
 * OutputDebugString 行为）。在掩码层裁剪（2026-09-07）：
 * AdGetDefaultMask 对普通/系统服务档产生位图时即剔除，运行时无适用性
 * 二次门控，检测表亦无 AppliesTo 列。 */
#define AD_MASK_SELF_ONLY_BITS \
    (AC_ANTIDEBUG_TECHNIQUE_MASK_BIT(AdTechniqueTimingRdtsc)         | \
     AC_ANTIDEBUG_TECHNIQUE_MASK_BIT(AdTechniqueTimingQueryPerf)     | \
     AC_ANTIDEBUG_TECHNIQUE_MASK_BIT(AdTechniqueTimingGetTickCount)  | \
     AC_ANTIDEBUG_TECHNIQUE_MASK_BIT(AdTechniqueTimingInstruction)   | \
     AC_ANTIDEBUG_TECHNIQUE_MASK_BIT(AdTechniqueOutputDebugString))

/* 受保护进程 policy 类型（2026-09-06）：默认按进程类型取位图
 * （AdGetDefaultMask：EDR 自身=全激活、系统服务=同 EDR 级、普通进程=
 * 去自省位子集）；注册时传 AD_MASK_ALL（全位）即按 Profile 取默认，
 * 其它值（含 0=全关闭）为显式最终位图（2026-09-07 废除 0 哨兵）。 */
typedef enum _AD_POLICY_PROFILE {
    AdPolicyProfileEdr = 0,         /* EDR 自身（AD_MASK_ALL 全激活） */
    AdPolicyProfileSystemService,   /* 系统服务（全激活，同 EDR 级守护） */
    AdPolicyProfileNormal,          /* 普通进程（基础子集：去基线依赖/侵入性项） */
    AdPolicyProfileCustom           /* 自定义位图（显式传值直接采用） */
} AD_POLICY_PROFILE, *PAD_POLICY_PROFILE;

/* 按进程类型取默认检测位图（2026-09-07 废除 0=全激活哨兵：显式全位=全激活）。
 * 普通进程默认：全位去掉 AD_MASK_SELF_ONLY_BITS（Timing/ODS 仅自身可执行），
 * 显式位图返回；后续按需调整。
 * PASSIVE_LEVEL */
ULONG64
AdGetDefaultMask(
    _In_ AD_POLICY_PROFILE Profile
    );

/* 已知调试器进程名清单 */
extern const WCHAR* const AdDebuggerProcessNames[];

/* 已知调试器窗口类清单 */
extern const WCHAR* const AdDebuggerWindowClasses[];

/* 已知调试器驱动名清单 */
extern const WCHAR* const AdDebuggerDrivers[];

/* 已知插桩框架签名清单 */
extern const WCHAR* const AdInstrumentationSignatures[];

/**************************************************/
/*               置信度 / 响应                     */
/**************************************************/

typedef enum _AD_CONFIDENCE {
    AdConfidenceLow = 0,      /* 低置信度 */
    AdConfidenceMedium,       /* 中置信度 */
    AdConfidenceHigh,         /* 高置信度 */
    AdConfidenceCritical      /* 极高置信度 */
} AD_CONFIDENCE, *PAD_CONFIDENCE;

typedef enum _AD_RESPONSE_ACTION {
    AdResponseIgnore = 0,     /* 忽略 */
    AdResponseAlert,          /* 告警上报 */
    AdResponseBlock,          /* 阻断（拒绝调用） */
    AdResponseAggressive      /* 激进处置（清除调试寄存器等） */
} AD_RESPONSE_ACTION, *PAD_RESPONSE_ACTION;

/**************************************************/
/*               检测结果                          */
/**************************************************/

typedef struct _AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT {
    AC_ANTIDEBUG_TECHNIQUE  Technique;      /* 命中的检测技术 */
    AD_CONFIDENCE           Confidence;     /* 置信度 */
    ULONG                   Score;          /* 0-100 */
    ULONG                   Severity;       /* 1-10 */
    AD_RESPONSE_ACTION      RecommendedAction; /* 建议处置 */
    ULONG_PTR               Address;        /* 相关地址（0=无） */
    WCHAR                   Description[256];
} AC_ANTIDEBUG_PROTECTION_DETECTION_RESULT, *PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT;

/**************************************************/
/*               检测事件快照                      */
/**************************************************/

typedef struct _AD_EVENT {
    AC_ANTIDEBUG_TECHNIQUE  Technique;
    AD_CONFIDENCE           Confidence;
    ULONG                   Score;
    ULONG                   Severity;
    HANDLE                  ProcessId;
    WCHAR                   ProcessName[64];
    LARGE_INTEGER           Timestamp;
    WCHAR                   Description[256];
} AD_EVENT, *PAD_EVENT;

/**************************************************/
/*               统计                              */
/**************************************************/

typedef struct _AD_STATISTICS {
    volatile LONG64         TotalScans;         /* 扫描次数 */
    volatile LONG64         TotalDetections;    /* 检测总数 */
    volatile LONG64         TotalResponses;     /* 处置次数 */
    ULONG                   HistoryCount;       /* 历史事件数 */
    BOOLEAN                 DebuggerPresent;    /* 当前是否检测到调试器 */
    BOOLEAN                 HardwareBreakpointsFound; /* 硬件断点 */
    BOOLEAN                 KernelDebuggerPresent;
    LARGE_INTEGER           LastScanTime;
    LARGE_INTEGER           StartTime;

    /* 分类检测计数（SS AntiDebugStatistics 对齐，2026-09-02 扩充） */
    volatile LONG64         PebDetections;      /* PEB 类 */
    volatile LONG64         ApiDetections;      /* API 类 */
    volatile LONG64         TimingDetections;   /* 时序类 */
    volatile LONG64         HardwareDetections; /* 硬件断点类 */
    volatile LONG64         ExceptionDetections;/* 异常类 */
    volatile LONG64         MemoryDetections;   /* 内存/钩子类 */
    volatile LONG64         ProcessDetections;  /* 进程类 */
    volatile LONG64         InstrumentationDetections; /* 插桩框架类 */
    volatile LONG64         HooksDetected;      /* 钩子总数 */
} AD_STATISTICS, *PAD_STATISTICS;

/**************************************************/
/*               回调集合                          */
/**************************************************/

typedef struct _AD_CALLBACKS {
    /* 检测到威胁时触发（返回是否已处理） */
    NTSTATUS (*OnDetection)(_In_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result, _In_opt_ PVOID Context);
    /* 处置动作执行时触发 */
    NTSTATUS (*OnResponse)(_In_ AD_RESPONSE_ACTION Action, _In_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT Result, _In_opt_ PVOID Context);
    /* 完整性校验（CRC32 基线）失败时触发 */
    NTSTATUS (*OnIntegrity)(_In_ PVOID Address, _In_ SIZE_T Size, _In_ ULONG ExpectedCrc, _In_ ULONG ActualCrc, _In_opt_ PVOID Context);
    /* 状态变化（启停/保护级别）时触发 */
    NTSTATUS (*OnStatus)(_In_ BOOLEAN Active, _In_opt_ PVOID Context);
    _In_opt_ PVOID          Context;    /* 透传给所有回调 */
} AD_CALLBACKS, *PAD_CALLBACKS;

/**************************************************/
/*               引擎上下文（不透明句柄）          */
/**************************************************/

typedef struct _AC_ANTIDEBUG_PROTECTION AC_ANTIDEBUG_PROTECTION, *PAC_ANTIDEBUG_PROTECTION;

/**************************************************/
/*               公共 API                          */
/**************************************************/

/* 初始化反调试引擎（创建上下文，不启动监测）。PASSIVE_LEVEL */
NTSTATUS
SpInitializeAntiDebugProtection(
    _Out_ PAC_ANTIDEBUG_PROTECTION* Engine,
    _In_opt_ PAD_CALLBACKS Callbacks
    );

/* 释放反调试引擎资源。NULL 安全。PASSIVE_LEVEL */
VOID
AdCleanup(
    _In_opt_ _Post_invalid_ PAC_ANTIDEBUG_PROTECTION Engine
    );

/* 对当前线程执行防护：线程隐藏 + 清除调试寄存器（可选）。PASSIVE_LEVEL */
NTSTATUS
AdApplyThreadProtection(
    _In_ PAC_ANTIDEBUG_PROTECTION Engine,
    _In_ BOOLEAN HideFromDebugger,
    _In_ BOOLEAN ClearDebugRegisters
    );

/* 对指定线程隐藏调试器（NtSetInformationThread ThreadHideFromDebugger；
 * threadId=0 表示当前线程）。线程防调试动作归位反调试模块（2026-09-06）。PASSIVE_LEVEL */
NTSTATUS
AdHideThreadFromDebuggerById(
    _In_ PAC_ANTIDEBUG_PROTECTION Engine,
    _In_ ULONG ThreadId
    );

/* 对指定受保护进程执行单次反调试扫描（统一目标表驱动，按 AntidebugMask 裁剪）。
 *  目标统一为谱系树 WKD_PROCESS：调用内经 PsLookupWkdProcessByProcessId
 *  持引用防 UAF，扫描结束 PsDereferenceWkdProcess 归还；检测块直接以
 *  WKD_PROCESS 为参数，读取原语（OpenProcess|VM_READ 句柄 + Toolhelp 模块表）
 *  由块内按需派生，检测块集合一致。
 *  ProcessId==0 或当前 PID → 自身目标（IsSelf=TRUE，全部检测项可执行）；
 *  仅自身可执行项（Timing/ODS）由 policy 位图生成时
 *  AD_MASK_SELF_ONLY_BITS 裁剪（2026-09-07 废除表内 AppliesTo/isSelf 门控）。
 *  AntidebugMask：AD_MASK_ALL=显式全激活、AD_MASK_NONE(0)=显式全关闭、
 *  部分位=显式裁剪（位图即最终使能）。
 *  命中即分发（AdDispatchDetection）并返回 STATUS_SUCCESS。PASSIVE_LEVEL */
NTSTATUS
AcpVerifySignalProtectedProcessAntiDebug(
    _In_ PAC_ANTIDEBUG_PROTECTION Engine,
    _In_ HANDLE ProcessId,
    _In_ ULONG64 AntidebugMask,
    _Out_opt_ PAC_ANTIDEBUG_PROTECTION_DETECTION_RESULT FirstHit
    );

/* 设置检测项使能位图（policy 使能开关，2026-09-06）。AD_MASK_ALL=显式全激活、
 * AD_MASK_NONE(0)=显式全关闭；其余按 AC_ANTIDEBUG_TECHNIQUE 位过滤（位图即
 * 最终使能，2026-09-07 废除 0=全激活哨兵）。PASSIVE_LEVEL */
NTSTATUS
AdSetDetectionMask(
    _Inout_ PAC_ANTIDEBUG_PROTECTION Engine,
    _In_ ULONG64 Mask
    );

/* 周期扫描受保护进程链（2026-09-06）：对链上每个受保护进程按其 policy
 * （WKD_ACCESS_CONTROL_CONTEXT::AntidebugMask，位图即最终使能）执行
 * AcpVerifySignalProtectedProcessAntiDebug 反调试检测；并对该进程全体线程实施
 * HideFromDebugger 防护（Toolhelp 枚举，重复设置幂等）。
 *  枚举编排层受保护进程链（AcEnumerateProtectedProcessPtrs）；
 *  EDR 自身跳过（自身由周期线程第一步 AcpVerifySignalProtectedProcessAntiDebug(0) 处理）。
 *  PASSIVE_LEVEL */
NTSTATUS
AcpVerifyProtectedProcessAntiDebug(
    _In_ PAC_ANTIDEBUG_PROTECTION Engine
    );

/* 映射检测技术到可读名称。PASSIVE_LEVEL */
PCWSTR
AdTechniqueName(
    _In_ AC_ANTIDEBUG_TECHNIQUE Technique
    );

/* 启动周期监测（创建监测线程，周期性 AcpVerifySignalProtectedProcessAntiDebug(自身) +
 * AcpVerifyProtectedProcessAntiDebug(受保护进程链，按各进程 policy)）。PASSIVE_LEVEL */
NTSTATUS
AcStartAntiDebugProtection(
    _Inout_ PAC_ANTIDEBUG_PROTECTION Engine,
    _In_ ULONG IntervalMs
    );

/* 停止周期监测。PASSIVE_LEVEL */
NTSTATUS
AdStopMonitoring(
    _In_ PAC_ANTIDEBUG_PROTECTION Engine
    );

/* 取检测历史快照（环形缓冲，最多 MaxEvents 条）。PASSIVE_LEVEL */
NTSTATUS
AdGetEvents(
    _In_ PAC_ANTIDEBUG_PROTECTION Engine,
    _Out_writes_to_(MaxEvents, *ReturnedCount) PAD_EVENT EventArray,
    _In_ ULONG MaxEvents,
    _Out_ PULONG ReturnedCount
    );

/* 取统计快照。PASSIVE_LEVEL */
NTSTATUS
AdGetStatistics(
    _In_ PAC_ANTIDEBUG_PROTECTION Engine,
    _Out_ PAD_STATISTICS Stats
    );

/* 清空检测历史。PASSIVE_LEVEL */
NTSTATUS
AdClearEvents(
    _In_ PAC_ANTIDEBUG_PROTECTION Engine
    );

/**************************************************/
/*               底层工具（可被编排层复用）         */
/**************************************************/

/* 读取指定地址的内存（SEH 保护，失败返回 FALSE 并置 LastError）。PASSIVE_LEVEL */
BOOLEAN
AdSafeReadMemory(
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    );

/* 检测当前进程是否被用户态调试器附加（DebugPort）。PASSIVE_LEVEL */
NTSTATUS
AdIsDebuggerAttached(
    _In_ PAC_ANTIDEBUG_PROTECTION Engine,
    _Out_ PBOOLEAN DebuggerPresent
    );

#ifdef __cplusplus
}
#endif
