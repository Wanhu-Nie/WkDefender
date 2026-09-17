/**************************************************/
/*  WkDefender IOA — JIT 喷射攻击防护检测器 (接口) */
/*                                                  */
/*  迁移自 ShadowStrike JITSprayDetector.hpp        */
/*  (v3.0.0, 734 行), 功能重实现非源码复制。        */
/*                                                  */
/*  定位: JIT 引擎识别、JIT 页枚举/缓存、常量嵌入   */
/*  (XOR/浮点/整型) 检测、熵分析、shellcode/NOP     */
/*  识别、W^X 合规检查(独有能力)、内核告警接入。    */
/*                                                  */
/*  与 SS 的关键差异 (注释就地标注):                */
/*    - 去 PIMPL/单例/Start-Stop-Pause-Resume       */
/*      (两态)                                      */
/*    - 3 类回调合一为 JSP_DETECTED_CALLBACK        */
/*    - 去 CorrelateWithHeapSpray (HSD 侧已对应     */
/*      裁剪 CorrelateWithJITSpray, 双向关联不迁移) */
/*    - 事件 ID 用序列号替代 "JITSPRAY-xxxx"        */
/*    - 页缓存向量/监控集合/近期检测裁剪为定长      */
/*  接入状态: 独立模块, 未挂接流水线。              */
/**************************************************/

#ifndef WKDEFENDER_IOA_JIT_SPRAY_PATTERN_DETECTOR_H
#define WKDEFENDER_IOA_JIT_SPRAY_PATTERN_DETECTOR_H

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
#define JSP_VERSION_MAJOR   3
#define JSP_VERSION_MINOR   0
#define JSP_VERSION_PATCH   0

/* 最小 JIT 页扫描尺寸 (SS MIN_JIT_PAGE_SIZE) */
#define JSP_MIN_JIT_PAGE_SIZE       4096
/* 单区域最大扫描字节 (SS MAX_SCAN_SIZE = 1MB) */
#define JSP_MAX_SCAN_SIZE           (1024 * 1024)
/* 重复常量最小判定次数 (SS MIN_CONSTANT_REPEAT) */
#define JSP_MIN_CONSTANT_REPEAT     8
/* 单进程最大跟踪 JIT 页数 (SS MAX_JIT_PAGES) */
#define JSP_MAX_JIT_PAGES           4096
/* W^X 违规阈值 (SS WX_VIOLATION_THRESHOLD, 定义未参与逻辑, 保留标注) */
#define JSP_WX_VIOLATION_THRESHOLD  10
/* NOP sled 判定: 长度 <32 不判 (SS IsNopSled) */
#define JSP_NOP_SLED_MIN            32
/* 低熵喷射判据上限 (SS MAX_SPRAY_ENTROPY, 参与 isSuspicious 判定) */
#define JSP_ENTROPY_SPRAY_MAX       2.0
/* SS 定义了但从未参与逻辑的常量: MIN_EXECUTABLE_ENTROPY=3.0 /
 * MAX_CONSTANT_REPEAT_ANALYSIS=1024, 不迁移 */

/* 配置校验区间 (SS IsValid: maxScanBytes∈(0,100MB], scanIntervalMs∈[100,3600000]) */
#define JSP_MAX_SCAN_BYTES_LIMIT    (100 * 1024 * 1024)
#define JSP_SCAN_INTERVAL_MIN_MS    100
#define JSP_SCAN_INTERVAL_MAX_MS    3600000

/* 监控进程上限 (SS unordered_set 无上限, 裁剪为定长 1024, 对齐 BOF) */
#define JSP_MAX_MONITORED_PROCESSES 1024
/* 近期检测环形上限 (SS MAX_RECENT_DETECTIONS = 1000) */
#define JSP_MAX_RECENT_DETECTIONS   1000
/* JIT 页缓存生命周期/条目上限 (SS CACHE_LIFETIME=60s, 条目上限按定长裁剪) */
#define JSP_CACHE_LIFETIME_MS       60000
#define JSP_MAX_CACHED_PROCESSES    16
/* 模块枚举数组上限 (SS 1024 个 HMODULE) */
#define JSP_MAX_MODULES             1024
/* 引擎白名单/引擎集合上限 (SS vector, 裁剪为定长) */
#define JSP_MAX_ENGINES             16
/* 统计 byEngine 数组 (SS array<...,16>, 按 JitEngine 值索引) */
#define JSP_BY_ENGINE_COUNT         16
/* 统计 byTechnique 数组 (SS array<...,8>, 按 JitSprayTechnique 值索引) */
#define JSP_BY_TECHNIQUE_COUNT      8

/* 定长文本缓冲 (宽字符, 含末尾 L'\0') */
#define JSP_ENGINE_NAME_LEN         32    /* 进程名/模块名 */
#define JSP_MAX_DETAILS             512
#define JSP_MAX_SOURCE_SCRIPT       512
#define JSP_MAX_BYTECODE            256
#define JSP_MAX_CONSTANT_VALUE      16    /* 最大重复模式尺寸 (SS patternSize ≤16) */
#define JSP_MAX_NONCOMPLIANT_PAGES  32    /* W^X 报告内嵌违规页截断上限 */

/**************************************************/
/*  枚举类型                                      */
/**************************************************/

/* 模块生命周期 (SS ModuleStatus 7 态裁剪为 5 态:
 * Paused/Stopping 随 Start/Stop/Pause/Resume 状态机一并裁剪) */
typedef enum _JSP_MODULE_STATUS {
    JspStatus_Uninitialized = 0,
    JspStatus_Initializing  = 1,
    JspStatus_Running       = 2,
    JspStatus_Stopped       = 3,
    JspStatus_Error         = 4
} JSP_MODULE_STATUS;

/* JIT 引擎 (SS JitEngine, 13 项; DotNetNGen 无模块映射, 仅在名称工具可达) */
typedef enum _JSP_JIT_ENGINE {
    JspEngine_Unknown        = 0,
    JspEngine_V8             = 1,   /* Chrome/Node.js/Electron */
    JspEngine_SpiderMonkey   = 2,   /* Firefox */
    JspEngine_Chakra         = 3,   /* Legacy Edge (ChakraCore) */
    JspEngine_JavaScriptCore = 4,   /* Safari/WebKit */
    JspEngine_DotNetJIT      = 5,   /* .NET CLR JIT (RyuJIT) */
    JspEngine_DotNetNGen     = 6,   /* .NET Native image */
    JspEngine_JavaHotSpot    = 7,   /* Java HotSpot */
    JspEngine_OpenJ9         = 8,   /* Eclipse OpenJ9 */
    JspEngine_LuaJIT         = 9,   /* LuaJIT */
    JspEngine_WASM           = 10,  /* WebAssembly engine */
    JspEngine_ActionScript   = 11,  /* Flash (legacy) */
    JspEngine_PyPy           = 12   /* Python PyPy JIT */
} JSP_JIT_ENGINE;

/* JIT 页类型 (SS JitPageType; 运行时 GetJitPages 仅产出 CodePage,
 * 其余类型保留供名称工具与后续扩展) */
typedef enum _JSP_JIT_PAGE_TYPE {
    JspPageType_Unknown        = 0,
    JspPageType_Code           = 1,  /* JIT 编译代码 */
    JspPageType_Stub           = 2,  /* JIT stubs */
    JspPageType_ConstantPool   = 3,  /* 常量池 */
    JspPageType_Data           = 4,  /* JIT 数据 */
    JspPageType_Trampoline     = 5   /* Trampoline 代码 */
} JSP_JIT_PAGE_TYPE;

/* 喷射技术 (SS JitSprayTechnique, 8 项, 对齐 byTechnique[8]) */
typedef enum _JSP_SPRAY_TECHNIQUE {
    JspTechnique_Unknown        = 0,
    JspTechnique_XorConstant    = 1,  /* XOR 指令常量 */
    JspTechnique_FloatConstant  = 2,  /* 浮点常量滥用 */
    JspTechnique_IntegerConstant = 3, /* 整型常量嵌入 */
    JspTechnique_StringConstant = 4,  /* 字符串常量 shellcode */
    JspTechnique_ArrayConstant  = 5,  /* 数组初始化 */
    JspTechnique_ImmediateValue = 6,  /* 立即数值 */
    JspTechnique_AddressLeak    = 7   /* 常量地址泄露 */
} JSP_SPRAY_TECHNIQUE;

/* W^X 违规类型 (SS WXViolationType; 运行时仅探测 SimultaneousRWX,
 * 其余供名称工具与内核过渡分析) */
typedef enum _JSP_WX_VIOLATION_TYPE {
    JspWx_None                = 0,
    JspWx_SimultaneousRWX     = 1,  /* 页同时可写可执行 */
    JspWx_WriteToExecutable   = 2,  /* 写入可执行页 */
    JspWx_ExecuteWritable     = 3,  /* 执行可写页 */
    JspWx_TransitionViolation = 4   /* 非法保护转换 */
} JSP_WX_VIOLATION_TYPE;

/* 检测置信度 (SS DetectionConfidence, 6 级) */
typedef enum _JSP_CONFIDENCE {
    JspConfidence_Unknown   = 0,
    JspConfidence_Low       = 1,
    JspConfidence_Medium    = 2,
    JspConfidence_High      = 3,
    JspConfidence_VeryHigh  = 4,
    JspConfidence_Confirmed = 5
} JSP_CONFIDENCE;

/**************************************************/
/*  结构体                                        */
/**************************************************/

/* JIT 页信息 (SS JitPageInfo; moduleName 在 SS 中未被填充, 保留字段标注;
 * firstSeen/lastScanned 采用 FILETIME 替代 time_point) */
typedef struct _JSP_JIT_PAGE_INFO {
    UINT64              baseAddress;
    UINT64              size;
    JSP_JIT_ENGINE      engine;
    JSP_JIT_PAGE_TYPE   pageType;
    UINT32              protection;
    BOOLEAN             isExecutable;
    BOOLEAN             isWritable;
    JSP_WX_VIOLATION_TYPE wxViolation;
    UINT64              allocationBase;
    WCHAR               moduleName[JSP_ENGINE_NAME_LEN];   /* SS 未填充此字段 */
    double              entropy;
    BOOLEAN             suspiciousConstants;
    UINT32              constantRepeatCount;
    FILETIME            firstSeen;
    FILETIME            lastScanned;
} JSP_JIT_PAGE_INFO;

/* 常量嵌入信息 (SS ConstantEmbedding; decodedInstructions 矢量裁剪,
 * constantValue 上限为最大模式尺寸 16) */
typedef struct _JSP_CONSTANT_EMBEDDING {
    UINT64              offset;
    UINT8               constantValue[JSP_MAX_CONSTANT_VALUE];
    UINT32              constantValueSize;
    UINT32              repeatCount;
    UINT64              totalLength;
    UINT8               validInstructionDecode;  /* 解码分析占位 (SS vector<string>) */
    BOOLEAN             isValidShellcode;
    JSP_SPRAY_TECHNIQUE technique;
} JSP_CONSTANT_EMBEDDING;

/* JIT 喷射事件 (SS JitSprayEvent; eventId→eventSequence,
 * suspiciousBytecode/sourceScript 裁剪为定长, constantInfo 内嵌) */
typedef struct _JSP_JIT_SPRAY_EVENT {
    UINT64                   eventSequence;
    UINT32                   processId;
    WCHAR                    processName[JSP_ENGINE_NAME_LEN];
    JSP_JIT_ENGINE           engine;
    JSP_SPRAY_TECHNIQUE      technique;
    JSP_JIT_PAGE_INFO        suspiciousPage;
    UINT64                   address;
    BOOLEAN                  hasConstantInfo;
    JSP_CONSTANT_EMBEDDING   constantInfo;
    UINT8                    suspiciousBytecode[JSP_MAX_BYTECODE];
    UINT32                   suspiciousBytecodeSize;
    WCHAR                    sourceScript[JSP_MAX_SOURCE_SCRIPT];
    BOOLEAN                  shellcodeDetected;
    JSP_WX_VIOLATION_TYPE    wxViolation;
    JSP_CONFIDENCE           confidence;
    double                   confidenceScore;
    BOOLEAN                  wasBlocked;
    WCHAR                    details[JSP_MAX_DETAILS];
    FILETIME                 timestamp;
} JSP_JIT_SPRAY_EVENT;

/* W^X 合规报告 (SS WXComplianceReport; violationsByType map→[5] 数组,
 * nonCompliantPages 上限截断, 完整列表经 JspGetWXViolatingPages 获取) */
typedef struct _JSP_WX_COMPLIANCE_REPORT {
    UINT32              processId;
    WCHAR               processName[JSP_ENGINE_NAME_LEN];
    UINT32              totalJitPages;
    UINT32              compliantPages;
    UINT32              violationCount;
    UINT32              violationsByType[5];     /* 按 JspWx_* 值索引 */
    JSP_JIT_PAGE_INFO   nonCompliantPages[JSP_MAX_NONCOMPLIANT_PAGES];
    UINT32              nonCompliantCount;
    BOOLEAN             isFullyCompliant;
    double              complianceScore;         /* 0-100 */
    FILETIME            timestamp;
} JSP_WX_COMPLIANCE_REPORT;

/* 统计快照 (SS JITSprayStatistics, 6 主计数 + byEngine[16] + byTechnique[8]) */
typedef struct _JSP_STATS_SNAPSHOT {
    UINT64 pagesScanned;
    UINT64 constantsAnalyzed;
    UINT64 spraysDetected;
    UINT64 wxViolationsDetected;
    UINT64 shellcodesDetected;
    UINT64 attacksBlocked;
    UINT64 byEngine[JSP_BY_ENGINE_COUNT];
    UINT64 byTechnique[JSP_BY_TECHNIQUE_COUNT];
    FILETIME startTime;
    UINT64   uptimeSeconds;    /* 自 Initialize 起运行秒数 (GetTickCount64) */
} JSP_STATS_SNAPSHOT;

/* 配置 (SS JITSprayDetectorConfiguration; enforceWX/monitoredEngines
 * 在 SS 实现中无消费点, 保留字段就地标注) */
typedef struct _JSP_CONFIG {
    BOOLEAN      enabled;
    BOOLEAN      enforceWX;              /* SS 未消费 */
    BOOLEAN      scanJitPages;
    UINT64       maxScanBytes;           /* 默认 JSP_MAX_SCAN_SIZE */
    BOOLEAN      enableConstantAnalysis;
    BOOLEAN      blockOnWXViolation;
    BOOLEAN      blockOnSprayDetection;
    JSP_JIT_ENGINE monitoredEngines[JSP_MAX_ENGINES];  /* SS 未消费, 保留 */
    UINT32       monitoredEngineCount;
    UINT32       scanIntervalMs;         /* SS 默认 1000, 无线程消费 */
    BOOLEAN      verboseLogging;
} JSP_CONFIG;

/* 检测回调 (SS 3 类 vector 合 1; W^X 违规经事件 wxViolation +
 * suspiciousPage 承载, 错误回调裁剪由注释记录) */
typedef VOID (*JSP_DETECTED_CALLBACK)(const JSP_JIT_SPRAY_EVENT* event);

/**************************************************/
/*  公共 API (全部 PASSIVE_LEVEL)                 */
/**************************************************/

/* 生命周期 */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN JspInitialize(const JSP_CONFIG* config);   /* 传 NULL 用默认配置 */

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID JspShutdown(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN JspIsInitialized(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
JSP_MODULE_STATUS JspGetStatus(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN JspUpdateConfiguration(const JSP_CONFIG* config);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN JspGetConfiguration(JSP_CONFIG* config);  /* 返回 FALSE 表示未初始化 */

/* 扫描 */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN JspScanJitPages(UINT32 processId, JSP_JIT_SPRAY_EVENT* event);

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32 JspScanAllProcesses(JSP_JIT_SPRAY_EVENT* events, UINT32 maxCount);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN JspAnalyzeJitPage(UINT32 processId, UINT64 address, UINT64 size,
                          JSP_JIT_PAGE_INFO* pageInfo);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN JspDetectConstantEmbedding(const UINT8* data, UINT64 dataSize,
                                   UINT64 baseAddress,
                                   JSP_CONSTANT_EMBEDDING* embedding);

/* W^X 合规 (本模块独有能力) */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN JspCheckWXCompliance(UINT32 processId, JSP_WX_COMPLIANCE_REPORT* report);

_IRQL_requires_max_(PASSIVE_LEVEL)
JSP_WX_VIOLATION_TYPE JspCheckPageWXViolation(UINT32 processId, UINT64 address);

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32 JspGetWXViolatingPages(UINT32 processId,
                              JSP_JIT_PAGE_INFO* pages, UINT32 maxCount);

/* JIT 引擎 */
_IRQL_requires_max_(PASSIVE_LEVEL)
JSP_JIT_ENGINE JspDetectJitEngine(UINT32 processId);

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32 JspGetAllJitEngines(UINT32 processId,
                           JSP_JIT_ENGINE* engines, UINT32 maxCount);

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32 JspGetJitPages(UINT32 processId,
                      JSP_JIT_PAGE_INFO* pages, UINT32 maxCount);

/* 监控 */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN JspMonitorProcess(UINT32 processId);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN JspStopMonitoring(UINT32 processId);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN JspIsMonitoring(UINT32 processId);

/* 内核接入: 可执行内存分配/保护变更告警 (SS 同签名,
 * 由调用方接线 RealTimeProtection 分发) */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID JspProcessKernelMemoryAlert(UINT32 processId, UINT64 address,
                                 UINT64 size, UINT32 protection);

/* 回调 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID JspRegisterDetectionCallback(JSP_DETECTED_CALLBACK callback);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID JspUnregisterCallbacks(VOID);

/* 统计与诊断 */
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN JspGetStatistics(JSP_STATS_SNAPSHOT* snapshot);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID JspResetStatistics(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32 JspGetRecentDetections(JSP_JIT_SPRAY_EVENT* events, UINT32 maxCount);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN JspSelfTest(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
PCWSTR JspGetVersionString(VOID);

/**************************************************/
/*  名称工具函数                                  */
/**************************************************/
_IRQL_requires_max_(PASSIVE_LEVEL)
PCWSTR JspGetJitEngineName(JSP_JIT_ENGINE engine);

_IRQL_requires_max_(PASSIVE_LEVEL)
PCWSTR JspGetJitPageTypeName(JSP_JIT_PAGE_TYPE type);

_IRQL_requires_max_(PASSIVE_LEVEL)
PCWSTR JspGetJitSprayTechniqueName(JSP_SPRAY_TECHNIQUE technique);

_IRQL_requires_max_(PASSIVE_LEVEL)
PCWSTR JspGetWXViolationTypeName(JSP_WX_VIOLATION_TYPE type);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN JspIsJitEngineModule(const WCHAR* moduleName);

/* 模块名(小写比较, 子串匹配) → 引擎识别 */
_IRQL_requires_max_(PASSIVE_LEVEL)
JSP_JIT_ENGINE JspDetectJitEngineFromModule(const WCHAR* moduleName);

/**************************************************/
/*  配置有效性 (内部也供公共 API 校验)            */
/**************************************************/
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN JspConfigIsValid(const JSP_CONFIG* config);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* WKDEFENDER_IOA_JIT_SPRAY_PATTERN_DETECTOR_H */