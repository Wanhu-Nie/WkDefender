/**************************************************/
/*  WkDefender IOA — 缓冲区溢出攻击防护检测器 (接口) */
/*                                                  */
/*  迁移自 ShadowStrike BufferOverflowProtection.hpp*/
/*  (v3.0.0, 936 行), 功能重实现非源码复制。        */
/*                                                  */
/*  定位: 进程缓解策略加固/查询、异常分类、堆校验、  */
/*  栈 canary 校验、调用栈回溯、崩溃转储分析、内存   */
/*  模式扫描、硬件(CET/影子栈)能力检测。            */
/*                                                  */
/*  与 SS 的关键差异 (注释就地标注):                */
/*    - 去 PIMPL/单例/Start-Stop 状态机(两态)       */
/*    - 去 ThreatIntel/SignatureStore/IPCManager/   */
/*      ThreatDetector/json 依赖                    */
/*    - 进程缓解策略裁剪为 UINT64 位掩码 (BOF_POLICY)*/
/*    - 4 类回调合一为 BOF_DETECTED_CALLBACK        */
/*    - 事件 ID 用序列号替代 "BOF-xxxx" 字符串      */
/*  接入状态: 独立模块, 未挂接流水线。              */
/**************************************************/

#ifndef WKDEFENDER_IOA_BUFFER_OVERFLOW_PATTERN_DETECTOR_H
#define WKDEFENDER_IOA_BUFFER_OVERFLOW_PATTERN_DETECTOR_H

/**************************************************/
/*  Windows SDK 类型                              */
/**************************************************/
#ifndef _WIN32
#error "仅支持 Windows 平台"
#endif
#pragma once

#include <windows.h>

/**************************************************/
/*  工程基础头 (NTSTATUS/BOOLEAN/DEF_MAX_PATH 等)  */
/**************************************************/
#include "../../DefendTypes.h"

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************/
/*  版本与容量常量                                */
/**************************************************/
#define BOF_VERSION_MAJOR   3
#define BOF_VERSION_MINOR   0
#define BOF_VERSION_PATCH   0

/* 监控进程上限: SS 为 2048, 裁剪为 1024 定长数组 */
#define BOF_MAX_MONITORED_PROCESSES     1024
/* 调用栈回溯最大帧数 */
#define BOF_MAX_STACK_FRAMES            256
/* GS cookie 检查间隔 (ms): SS 中仅配置字段, 无线程消费, 保留标注 */
#define BOF_CANARY_CHECK_INTERVAL_MS    100
/* 近期事件环形缓冲上限 (SS MAX_RECENT_EVENTS) */
#define BOF_MAX_RECENT_EVENTS           1000
/* SS MAX_EXCEPTION_CACHE 定义了但从未使用, 不迁移 */
/* 栈 cookie 魔数: SS 定义但从未参与校验逻辑, 保留标注 */
#define BOF_STACK_COOKIE_MAGIC_64       0x2B992DDFA232ULL
#define BOF_STACK_COOKIE_MAGIC_32       0x0BB40E64UL
/* 堆头部魔数: SS 定义但远程堆校验仅检查可读性, 未比对魔数, 保留标注 */
#define BOF_HEAP_HEADER_MAGIC           0xFEEDFACECAFEBEEFULL
/* 内存区域扫描上限 (SS AnalyzeMemoryRegion MAX_SCAN_SIZE) */
#define BOF_MAX_SCAN_SIZE               (64 * 1024)
/* NOP sled 判定阈值 */
#define BOF_NOP_SLED_MIN                32
/* 事件内嵌损坏字节样本上限 */
#define BOF_CORRUPTED_DATA_MAX          256
/* 空指针判定的低地址阈值 (faultAddr < 0x10000) */
#define BOF_SUSPECT_ADDR_MIN            0x10000

/* 定长文本缓冲 (宽字符, 含末尾 L'\0') */
#define BOF_MAX_DETAILS                 512
#define BOF_MAX_FUNCTION_NAME           64
#define BOF_MAX_SOURCE_FILE             64
#define BOF_MAX_CORRUPTION_TYPE         64
#define BOF_MAX_RECOMMENDATIONS         8
#define BOF_MAX_RECOMMENDATION_LEN      96
#define BOF_MAX_SUCCESSFUL_POLICIES     16
#define BOF_MAX_FAILED_POLICIES         4
#define BOF_MAX_FAILED_MSG_LEN          96
#define BOF_MAX_EXCLUDED_PROCESSES      16

/* BOF_POLICY 往返位集合 (ToBitmask/FromBitmask 覆盖的 20 位)
 * 其余 BOF_PROTECT_* 位仅供名称查询/加固成功清单, 不参与策略掩码往返 */
#define BOF_PROTECT_STACK_CANARY        (1ULL << 0)
#define BOF_PROTECT_SAFE_SEH            (1ULL << 1)
#define BOF_PROTECT_SEHOP               (1ULL << 2)
#define BOF_PROTECT_DEP                 (1ULL << 3)
#define BOF_PROTECT_PERMANENT_DEP       (1ULL << 4)
#define BOF_PROTECT_ASLR                (1ULL << 5)
#define BOF_PROTECT_HIGH_ENTROPY_ASLR   (1ULL << 6)
#define BOF_PROTECT_BOTTOM_UP_ASLR      (1ULL << 7)
#define BOF_PROTECT_FORCE_RELOCATE      (1ULL << 8)
#define BOF_PROTECT_HEAP_TERMINATE      (1ULL << 9)
#define BOF_PROTECT_CFG                 (1ULL << 10)
#define BOF_PROTECT_STRICT_CFG          (1ULL << 11)
#define BOF_PROTECT_SHADOW_STACK        (1ULL << 12)
#define BOF_PROTECT_HARDWARE_CET        (1ULL << 13)
#define BOF_PROTECT_RETURN_ADDR_VERIFY  (1ULL << 14)
#define BOF_PROTECT_IMPORT_ADDR_FILTER  (1ULL << 15)
#define BOF_PROTECT_EXPORT_ADDR_FILTER  (1ULL << 16)
#define BOF_PROTECT_STRICT_HANDLE       (1ULL << 17)
#define BOF_PROTECT_DISABLE_DYN_CODE    (1ULL << 18)
#define BOF_PROTECT_DISALLOW_WIN32K     (1ULL << 19)
#define BOF_PROTECT_DISABLE_EXT_PTS     (1ULL << 20)
#define BOF_PROTECT_BLOCK_REMOTE_IMG    (1ULL << 21)
#define BOF_PROTECT_BLOCK_LOW_LABEL     (1ULL << 22)
#define BOF_PROTECT_PREFER_SYSTEM32     (1ULL << 23)
#define BOF_PROTECT_PROHIBIT_DYN_CODE   (1ULL << 24)
#define BOF_PROTECT_ALLOW_THREAD_OPTOUT (1ULL << 25)
#define BOF_PROTECT_AUDIT_ONLY          (1ULL << 26)

/* 进程缓解策略掩码类型 (SS ProcessMitigationPolicy::ToBitmask 语义) */
typedef UINT64 BOF_POLICY;

/* 安全默认策略 (GetSecureDefault: 保守兼容性, 禁用动态代码/CET/Win32k) */
#define BOF_POLICY_SECURE_DEFAULT                                                     \
    (BOF_PROTECT_STACK_CANARY | BOF_PROTECT_SEHOP | BOF_PROTECT_DEP |                 \
     BOF_PROTECT_PERMANENT_DEP | BOF_PROTECT_ASLR | BOF_PROTECT_HIGH_ENTROPY_ASLR |   \
     BOF_PROTECT_BOTTOM_UP_ASLR | BOF_PROTECT_FORCE_RELOCATE |                        \
     BOF_PROTECT_HEAP_TERMINATE | BOF_PROTECT_CFG | BOF_PROTECT_STRICT_HANDLE |       \
     BOF_PROTECT_DISABLE_EXT_PTS | BOF_PROTECT_BLOCK_REMOTE_IMG)

/* 最大安全策略 (GetMaximumSecurity: 除 DisallowWin32k 外全开,
 * 不含仅声明不往返的位: SafeSEH/ShadowStack/ReturnAddrVerify/Import/Export/
 * Prohibit/AllowThreadOptOut/AuditOnly) */
#define BOF_POLICY_MAXIMUM_SECURITY                                                   \
    (BOF_PROTECT_STACK_CANARY | BOF_PROTECT_SEHOP | BOF_PROTECT_DEP |                 \
     BOF_PROTECT_PERMANENT_DEP | BOF_PROTECT_ASLR | BOF_PROTECT_HIGH_ENTROPY_ASLR |   \
     BOF_PROTECT_BOTTOM_UP_ASLR | BOF_PROTECT_FORCE_RELOCATE |                        \
     BOF_PROTECT_HEAP_TERMINATE | BOF_PROTECT_CFG | BOF_PROTECT_STRICT_CFG |          \
     BOF_PROTECT_STRICT_HANDLE | BOF_PROTECT_DISABLE_DYN_CODE |                       \
     BOF_PROTECT_DISABLE_EXT_PTS | BOF_PROTECT_BLOCK_REMOTE_IMG |                     \
     BOF_PROTECT_BLOCK_LOW_LABEL | BOF_PROTECT_PREFER_SYSTEM32 |                      \
     BOF_PROTECT_HARDWARE_CET)

/**************************************************/
/*  枚举类型                                      */
/**************************************************/

/* 模块生命周期 (SS BufferOverflowProtectionStatus 7 态裁剪为 5 态:
 * Paused/Stopping 随 Start/Stop/Pause/Resume 状态机一并裁剪, 不再产生) */
typedef enum _BOF_MODULE_STATUS {
    BofStatus_Uninitialized = 0,
    BofStatus_Initializing  = 1,
    BofStatus_Running       = 2,
    BofStatus_Stopped       = 3,
    BofStatus_Error         = 4
} BOF_MODULE_STATUS;

/* 内存破坏类型 (SS OverflowType, 18 项) */
typedef enum _BOF_OVERFLOW_TYPE {
    BofOverflow_Unknown             = 0,
    BofOverflow_StackSmashing       = 1,
    BofOverflow_StackCanaryCorrupt  = 2,
    BofOverflow_SEHOverwrite        = 3,
    BofOverflow_HeapOverflow        = 4,
    BofOverflow_HeapMetaCorrupt     = 5,
    BofOverflow_FormatString        = 6,
    BofOverflow_IntegerOverflow     = 7,
    BofOverflow_IntegerUnderflow    = 8,
    BofOverflow_UseAfterFree        = 9,
    BofOverflow_DoubleFree          = 10,
    BofOverflow_HeapUseAfterRealloc = 11,
    BofOverflow_NullPointerDeref    = 12,
    BofOverflow_TypeConfusion       = 13,
    BofOverflow_OutOfBoundsRead     = 14,
    BofOverflow_OutOfBoundsWrite    = 15,
    BofOverflow_UninitializedMemory = 16,
    BofOverflow_OffByOne            = 17
} BOF_OVERFLOW_TYPE;

/* 利用事件状态 (SS ExploitStatus) */
typedef enum _BOF_EXPLOIT_STATUS {
    BofExploit_Unknown          = 0,
    BofExploit_Safe             = 1,
    BofExploit_Suspicious       = 2,
    BofExploit_LikelyExploit    = 3,
    BofExploit_ConfirmedExploit = 4,
    BofExploit_Blocked          = 5,
    BofExploit_Terminated       = 6
} BOF_EXPLOIT_STATUS;

/* 严重度 (SS ExploitSeverity) */
typedef enum _BOF_SEVERITY {
    BofSeverity_Information = 0,
    BofSeverity_Low         = 1,
    BofSeverity_Medium      = 2,
    BofSeverity_High        = 3,
    BofSeverity_Critical    = 4
} BOF_SEVERITY;

/* 检测方法 (SS DetectionMethod) */
typedef enum _BOF_DETECTION_METHOD {
    BofDetect_Unknown          = 0,
    BofDetect_ExceptionHandler = 1,
    BofDetect_CanaryCheck      = 2,
    BofDetect_ShadowStackMis   = 3,
    BofDetect_HeapValidation   = 4,
    BofDetect_HookDetection    = 5,
    BofDetect_PatternMatch     = 6,
    BofDetect_Heuristic        = 7,
    BofDetect_HardwareTrap     = 8,
    BofDetect_ApiMonitoring    = 9
} BOF_DETECTION_METHOD;

/* CPU 厂商 (SS CpuVendor) */
typedef enum _BOF_CPU_VENDOR {
    BofCpu_Unknown = 0,
    BofCpu_Intel   = 1,
    BofCpu_AMD     = 2
} BOF_CPU_VENDOR;

/* 加固失败条目 (SS failedPolicies 的 map<ProtectionTechnique,string> 简化) */
typedef struct _BOF_HARDENING_FAILED_ENTRY {
    UINT64 technique;                 /* BOF_PROTECT_* 位 */
    WCHAR  message[BOF_MAX_FAILED_MSG_LEN];  /* 失败原因 */
} BOF_HARDENING_FAILED_ENTRY;

/* 加固报告 (SS HardeningReport) */
typedef struct _BOF_HARDENING_REPORT {
    UINT32          processId;
    WCHAR           processName[DEF_MAX_IMAGE_NAME];
    BOF_POLICY      currentPolicy;    /* 应用前查询到的现网策略 */
    BOF_POLICY      appliedPolicy;    /* 本次请求的策略掩码 */
    UINT64          successfulPolicies[BOF_MAX_SUCCESSFUL_POLICIES];
    UINT32          successCount;
    BOF_HARDENING_FAILED_ENTRY failedPolicies[BOF_MAX_FAILED_POLICIES];
    UINT32          failureCount;
    double          hardeningScore;   /* 0-100 */
    WCHAR           recommendations[BOF_MAX_RECOMMENDATIONS][BOF_MAX_RECOMMENDATION_LEN];
    UINT32          recommendationCount;
    FILETIME        timestamp;
} BOF_HARDENING_REPORT;

/* 栈帧信息 (SS StackFrameInfo) */
typedef struct _BOF_STACK_FRAME_INFO {
    UINT32  frameIndex;
    UINT64  returnAddress;
    UINT64  stackPointer;
    UINT64  basePointer;
    WCHAR   moduleName[DEF_MAX_IMAGE_NAME];
    UINT64  moduleBase;
    UINT64  moduleOffset;
    WCHAR   functionName[BOF_MAX_FUNCTION_NAME];
    UINT32  functionOffset;
    WCHAR   sourceFile[BOF_MAX_SOURCE_FILE];
    UINT32  sourceLine;
    BOOLEAN isValid;
    BOOLEAN returnInExecutable;
} BOF_STACK_FRAME_INFO;

/* 异常上下文 (SS ExceptionContext, x64 寄存器 15 参数) */
typedef struct _BOF_EXCEPTION_CONTEXT {
    UINT32  exceptionCode;
    UINT32  exceptionFlags;
    UINT64  exceptionAddress;
    UINT32  numParameters;
    UINT64  parameters[15];
    BOOLEAN isContinuable;
    BOOLEAN isFirstChance;
    struct {
        UINT64 rax, rbx, rcx, rdx;
        UINT64 rsi, rdi, rbp, rsp;
        UINT64 r8, r9, r10, r11;
        UINT64 r12, r13, r14, r15;
        UINT64 rip, rflags;
        UINT16 cs, ss, ds, es, fs, gs;
    } registers;
} BOF_EXCEPTION_CONTEXT;

/* 内存破坏事件 (SS ExploitEvent; 裁剪: eventId→eventSequence,
 * signatureId 随 SignatureStore 裁剪, callStack 不内嵌——调用方
 * 按需 BofGetCallStack) */
typedef struct _BOF_EVENT {
    UINT64              eventSequence;
    BOF_OVERFLOW_TYPE   type;
    BOF_DETECTION_METHOD detectionMethod;
    BOF_EXPLOIT_STATUS  status;
    BOF_SEVERITY        severity;
    UINT32              processId;
    UINT32              threadId;
    WCHAR               processName[DEF_MAX_IMAGE_NAME];
    WCHAR               processPath[DEF_MAX_PATH];
    UINT64              instructionPointer;
    UINT64              stackPointer;
    UINT64              targetAddress;
    UINT64              expectedValue;
    UINT64              actualValue;
    WCHAR               moduleName[DEF_MAX_IMAGE_NAME];
    UINT64              moduleBase;
    WCHAR               functionName[BOF_MAX_FUNCTION_NAME];
    BOOLEAN             hasExceptionContext;
    BOF_EXCEPTION_CONTEXT exceptionContext;
    UINT8               corruptedData[BOF_CORRUPTED_DATA_MAX];
    UINT32              corruptedDataSize;
    BOOLEAN             prevented;
    BOOLEAN             processTerminated;
    WCHAR               details[BOF_MAX_DETAILS];
    FILETIME            timestamp;
} BOF_EVENT;

/* 堆分析结果 (SS HeapAnalysisResult) */
typedef struct _BOF_HEAP_ANALYSIS_RESULT {
    UINT64  heapHandle;
    UINT64  totalSize;
    UINT64  committedSize;
    UINT64  freeSize;
    UINT64  allocationCount;
    BOOLEAN isCorrupted;
    WCHAR   corruptionType[BOF_MAX_CORRUPTION_TYPE];
    UINT64  corruptionAddress;
    BOOLEAN isLFH;
    BOOLEAN isSegmentHeap;
    UINT32  heapFlags;
} BOF_HEAP_ANALYSIS_RESULT;

/* 统计快照 (SS BufferOverflowStatistics::Snapshot, 12 计数器) */
typedef struct _BOF_STATS_SNAPSHOT {
    UINT64 processesMonitored;
    UINT64 processesHardened;
    UINT64 exceptionsHandled;
    UINT64 stackOverflowsDetected;
    UINT64 heapCorruptionsDetected;
    UINT64 formatStringsDetected;
    UINT64 integerOverflowsDetected;
    UINT64 useAfterFreeDetected;
    UINT64 exploitsBlocked;
    UINT64 processesTerminated;
    UINT64 canaryChecks;
    UINT64 canaryFailures;
    FILETIME startTime;
    UINT64   uptimeSeconds;   /* 自 Initialize 起运行秒数 (GetTickCount64) */
} BOF_STATS_SNAPSHOT;

/* 配置 (SS BufferOverflowProtectionConfiguration;
 * 未消费字段就地标注: enableShadowStack / enableFormatStringProtection /
 * enableIntegerOverflowDetection 在 SS 实现中无消费点, 保留字段)
 * excludedProcesses 由 vector<wstring> 裁剪为定长数组 */
typedef struct _BOF_CONFIG {
    BOOLEAN      enabled;
    BOF_POLICY   defaultPolicy;
    BOOLEAN      enableExceptionMonitoring;
    BOOLEAN      enableHeapValidation;
    BOOLEAN      enableCanaryChecks;
    UINT32       canaryCheckIntervalMs;   /* BOF_CANARY_CHECK_INTERVAL_MS, 无线程消费 */
    BOOLEAN      terminateOnExploit;
    BOOLEAN      autoHardenProcesses;
    BOOLEAN      enableShadowStack;       /* 见头注释: SS 未消费 */
    WCHAR        excludedProcesses[BOF_MAX_EXCLUDED_PROCESSES][DEF_MAX_IMAGE_NAME];
    UINT32       excludedProcessCount;
    BOOLEAN      verboseLogging;
    BOOLEAN      enableFormatStringProtection;   /* SS 未消费 */
    BOOLEAN      enableIntegerOverflowDetection; /* SS 未消费 */
} BOF_CONFIG;

/* 默认配置 (模块静态初始值, 记账默认值) */
#define BOF_DEFAULT_INITIALIZED          FALSE
#define BOF_DEFAULT_ENABLED              TRUE
#define BOF_DEFAULT_POLICY               BOF_POLICY_SECURE_DEFAULT

/* 检测回调 (SS 4 类回调合 1: 利用事件回调; 加固/异常/错误回调裁剪,
 * 异常事件已含在 BOF_EVENT, 加固经返回报告 + 统计体现) */
typedef VOID (*BOF_DETECTED_CALLBACK)(const BOF_EVENT* event);

/**************************************************/
/*  公共 API (全部 PASSIVE_LEVEL)                 */
/**************************************************/

/* 生命周期 */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofInitialize(const BOF_CONFIG* config);   /* 传 NULL 用默认配置 */

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID BofShutdown(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofIsInitialized(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOF_MODULE_STATUS BofGetStatus(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofUpdateConfiguration(const BOF_CONFIG* config);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofGetConfiguration(BOF_CONFIG* config);  /* 返回 FALSE 表示未初始化 */

/* 进程加固 */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofHardenProcess(UINT32 processId, BOF_POLICY policyMask,
                         BOF_HARDENING_REPORT* report);
/* policyMask 传 0 时使用默认策略 */

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofGetProcessPolicy(UINT32 processId, BOF_POLICY* policyMask);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofHasProtection(UINT32 processId, UINT64 technique);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofGetHardeningScore(UINT32 processId, double* score);

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32 BofGetRecommendations(UINT32 processId,
                             WCHAR* buffer, UINT32 bufferLen);  /* 行数=UINT32 返回值 */

/* 监控 */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofMonitorProcess(UINT32 processId);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofStopMonitoring(UINT32 processId);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofIsMonitoring(UINT32 processId);

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32 BofGetMonitoredProcesses(UINT32* buffer, UINT32 bufferLen);

/* 分析 */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofAnalyzeException(UINT32 processId, const BOF_EXCEPTION_CONTEXT* context,
                            BOF_EVENT* event);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofAnalyzeCrashDump(const WCHAR* dumpPath, BOF_EVENT* event);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofAnalyzeMemoryRegion(UINT32 processId, UINT64 address, SIZE_T size,
                               BOF_EVENT* event);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofValidateHeap(UINT32 processId, UINT64 heapHandle,
                        BOF_HEAP_ANALYSIS_RESULT* result);

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32 BofValidateAllHeaps(UINT32 processId,
                           BOF_HEAP_ANALYSIS_RESULT* results, UINT32 maxResults);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofValidateStackCanary(UINT32 processId, UINT32 threadId);

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32 BofGetCallStack(UINT32 processId, UINT32 threadId, UINT32 maxFrames,
                       BOF_STACK_FRAME_INFO* frames);

/* 硬件能力 */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofIsCETAvailable(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofIsHardwareShadowStackAvailable(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOF_CPU_VENDOR BofGetCpuVendor(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT64 BofGetHardwareFeatures(VOID);

/* 回调 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID BofRegisterDetectionCallback(BOF_DETECTED_CALLBACK callback);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID BofUnregisterCallbacks(VOID);

/* 统计与诊断 */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofGetStatistics(BOF_STATS_SNAPSHOT* snapshot);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID BofResetStatistics(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32 BofGetRecentEvents(BOF_EVENT* events, UINT32 maxCount);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofSelfTest(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
PCWSTR BofGetVersionString(VOID);

/* 内核告警入口 (按 HSD 先例保留: 由调用方接线内核告警分发;
 * 载荷 [UINT32 pid][UINT32 excCode][UINT64 excAddr](内核报文) ) */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID BofProcessKernelMemoryAlert(UINT32 msgType, const void* data, SIZE_T dataSize);

/**************************************************/
/*  名称工具函数                                  */
/**************************************************/
_IRQL_requires_max_(PASSIVE_LEVEL)
PCWSTR BofGetOverflowTypeName(BOF_OVERFLOW_TYPE type);

_IRQL_requires_max_(PASSIVE_LEVEL)
PCWSTR BofGetProtectionTechniqueName(UINT64 technique);

_IRQL_requires_max_(PASSIVE_LEVEL)
PCWSTR BofGetExploitStatusName(BOF_EXPLOIT_STATUS status);

_IRQL_requires_max_(PASSIVE_LEVEL)
PCWSTR BofGetExploitSeverityName(BOF_SEVERITY severity);

_IRQL_requires_max_(PASSIVE_LEVEL)
PCWSTR BofGetDetectionMethodName(BOF_DETECTION_METHOD method);

/* 异常码名称; buffer 用于 "EXCEPTION_0x%08X" 兜底, 返回指向静态名或 buffer */
_IRQL_requires_max_(PASSIVE_LEVEL)
PCWSTR BofGetExceptionCodeName(UINT32 code, WCHAR* buffer, UINT32 bufferLen);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofIsExploitException(UINT32 exceptionCode);

/**************************************************/
/*  配置有效性 (内部也供公共 API 校验)            */
/**************************************************/
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN BofConfigIsValid(const BOF_CONFIG* config);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* WKDEFENDER_IOA_BUFFER_OVERFLOW_PATTERN_DETECTOR_H */