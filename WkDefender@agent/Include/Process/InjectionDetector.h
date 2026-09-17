/**************************************************/
/*  WkDefender Agent — DLL 注入检测器公共 API      */
/*                                                  */
/*  2026-09-15 重构: 自 IOA/IoaInjectionClassifier  */
/*  迁出"模块窗口确认"能力 (对齐 ShadowStrike        */
/*  DLLInjectionDetector::DetectRemoteThread-       */
/*  InjectionImpl, T1055.001)。                     */
/*  本头为 Process 子模块对外公共头 (include 惯例    */
/*  根目录→子目录 "Include/Process/InjectionDetector.h") */
/**************************************************/

#pragma once

#include <windows.h>
#include "../../DefendTypes.h"    /* NTSTATUS / BOOLEAN 等基本类型 */

/*
 * IoaRecordModuleLoad — 记录一次模块加载, 供 DLL 注入模块窗口确认使用。
 * 数据源状态: 当前驱动 ImageLoad 事件未接入 IOA 流水线
 * (见 process_manager.c WkdMessage_ImageLoaded / EventParser),
 * 本函数尚无调用者。接入后缓存即被填充, IoaConfirmDllInjectionByModule
 * 自动生效。
 */
NTSTATUS
IoaRecordModuleLoad(
    _In_ ULONG ProcessId,
    _In_ PCWSTR ModulePath,
    _In_ LARGE_INTEGER LoadTime
    );

/*
 * IoaConfirmDllInjectionByModule — 远程线程 DLL 注入的模块窗口确认。
 * 移植自 ShadowStrike DetectRemoteThreadInjectionImpl (T1055.001)。
 * 当目标进程在关联时间窗 (1s) 内加载了未信任 (非系统目录) 模块时,
 * 将 DLL 注入置信度提升至确认级 (≥90), 风险分提升至 ≥85。
 * 模块缓存为空时返回 STATUS_NOT_FOUND, 不改变判定, 不引入误报。
 */
NTSTATUS
IoaConfirmDllInjectionByModule(
    _In_ ULONG TargetProcessId,
    _Inout_ PULONG Confidence,
    _Inout_ PULONG RiskScore
    );

/**************************************************/
/*  反射注入检测 (ReflectiveInjectionDetector)      */
/*  2026-09-15 新增: ShadowStrike                 */
/*  ReflectiveDLLDetector 决策层迁移 (Rid*)        */
/*  实现于 Process\ReflectiveInjectionDetector.c   */
/*  已合并原 IoaConfirmReflectiveLoading            */
/*  (IoaInjectionClassifier.c L907-975)。          */
/**************************************************/

#include "../../Memory/MemoryScan.h"   /* WKD_MEM_SCAN_MODE (RidScanProcess) */

/*
 * 反射加载器类型分类 (对齐 SS ReflectiveLoadType, 压缩为 8 类:
 * 合并 PackedReflective→由 WKD_MEM_THREAT 二进制类型表达,
 * 合并 PELoader/DotNetAssembly→CustomLoader)。
 */
typedef enum _RID_LOAD_TYPE {
    RidLoad_Unknown = 0,          /* 未分类 */
    RidLoad_ClassicReflective,    /* Stephen Fewer 经典反射加载 */
    RidLoad_Srdi,                 /* Shellcode Reflective DLL Injection */
    RidLoad_ManualMapping,        /* 手工映射加载器 */
    RidLoad_MemoryModule,         /* MemoryModule 类加载器 */
    RidLoad_CobaltStrikeBeacon,   /* CS Beacon (签名命中) */
    RidLoad_MeterpreterStage,     /* Meterpreter stage (签名命中) */
    RidLoad_ModuleOverloading,    /* 模块覆盖加载 */
    RidLoad_CustomLoader          /* 自定义加载器 */
} RID_LOAD_TYPE, *PRID_LOAD_TYPE;

/*
 * 置信度分级 (对齐 SS DetectionConfidence)。
 * 各分级触发规则 (对齐 AnalyzeCandidate L2335-2418):
 *   Low       — 无背衬内存中的 PE
 *   Medium    — RWX / 高熵 (加壳/加密)
 *   High      — 有效 PE 隐藏于 PEB 模块表 / 无背衬 PE 含 TLS 目录
 *   Confirmed — 线程起始落入隐藏 PE / 已知加载器签名 / 威胁情报命中
 */
typedef enum _RID_CONFIDENCE {
    RidConf_None = 0,
    RidConf_Low,
    RidConf_Medium,
    RidConf_High,
    RidConf_Confirmed
} RID_CONFIDENCE, *PRID_CONFIDENCE;

/* 单条反射加载检测结果 (输出结构) */
typedef struct _RID_REFLECTIVE_DETECTION {
    ULONG_PTR       BaseAddress;      /* 隐藏 PE 基址 */
    SIZE_T          RegionSize;       /* 所在区域大小 */
    ULONG           Protection;       /* 当前保护 PAGE_* */
    RID_LOAD_TYPE   LoadType;         /* 加载器分类 */
    RID_CONFIDENCE  Confidence;       /* 置信度分级 */
    ULONG           RiskScore;        /* 0-100 综合风险分 */
    BOOLEAN         IsUnbacked;       /* 无背衬内存 */
    BOOLEAN         IsRwx;            /* RWX 保护 */
    BOOLEAN         IsHiddenFromPeb;  /* 不在已加载模块表 */
    BOOLEAN         HasThreadStartingHere; /* 线程起始落入本 PE (活动注入) */
    ULONG           ThreadCount;      /* 关联线程数 */
    BOOLEAN         CorrelatedWithKnownThreat; /* 签名/威胁情报命中 */
    CHAR            ThreatName[64];   /* 命中加载器/威胁名称 */
    CHAR            MitreTechnique[16]; /* T1620 / T1055.001 / ... */
    DEF_SHA256_HASH Sha256;           /* PE 头区 SHA256 (威胁情报关联键) */
} RID_REFLECTIVE_DETECTION, *PRID_REFLECTIVE_DETECTION;

/*
 * PspDetermineReflectiveLoading — 反射 DLL 精确确认 (事件驱动定向验证)。
 * 合并原 IoaConfirmReflectiveLoading (迁移自 IoaInjectionClassifier.c):
 *   分类器以 UNBACKED_START 近似判定 ReflectiveDLL; 本函数用线程入口地址定向确认:
 *     MmGetMemoryRegionInformation 定位入口区域 → 私有可执行 → MsScanRegionAt 定向扫描 →
 *     隐藏无背衬 PE (PEInjection 且 !PeInPeb) → WpeAnalyzePEDeep 深度验证 →
 *     加载器分类 + 风险评分。
 *   对齐 ShadowStrike AnalyzeCandidate 的内存扫描确认阶段
 *   (ReflectiveDLLDetector.cpp L2403-2418, hasThreadStartingHere → Confirmed)。
 * 不可验证 (无入口地址/区域不可读/无 PE 命中/深度验证失败) 时返回 FALSE,
 * 不改变原近似判定, 不引入误报。
 * 确认成功时 Confidence/RiskScore 输出确认级 (≥90)。
 */
BOOLEAN
PspDetermineReflectiveLoading(
    _In_  ULONG             TargetProcessId,
    _In_  ULONG_PTR         StartRoutine,
    _Out_opt_ PRID_LOAD_TYPE  LoadType,   /* [可选] 加载器分类 */
    _Out_opt_ PULONG        Confidence,   /* [可选] 确认后置信度 (≥90) */
    _Out_opt_ PULONG        RiskScore     /* [可选] 确认后风险分 (≥90) */
    );

/*
 * RidScanProcess — 进程反射加载全量扫描 (主动扫描决策层)。
 * 对齐 ShadowStrike Scan (ReflectiveDLLDetector.cpp L981-1100):
 *   MsScanProcessMemoryFull 全量扫描 → 逐候选 (PEInjection && !PeInPeb)
 *   深度决策 (特征组合 + 线程起始分析 + 签名匹配 + 风险评分)。
 * 仅输出置信度 ≥ RidConf_Medium 的检测; 无命中时返回 STATUS_SUCCESS 且
 * DetectionCount = 0。
 */
NTSTATUS
RidScanProcess(
    _In_  DWORD  ProcessId,
    _In_  WKD_MEM_SCAN_MODE Mode,
    _Out_writes_to_(MaxDetections, *DetectionCount) PRID_REFLECTIVE_DETECTION Detections,
    _In_  ULONG  MaxDetections,
    _Out_ PULONG DetectionCount
    );

/**************************************************/
/*  进程镂空检测 (ProcessHollowingDetector)          */
/*  2026-09-15 新增: ShadowStrike                 */
/*  ProcessHollowingDetector 决策层迁移 (Ipe*)     */
/*  实现于 Process\ProcessHollowingDetector.c      */
/*  对齐清单: ScanProcess(8步)/ScanAllProcesses/   */
/*  ScanProcesses/ScanByName/ScanByPath/           */
/*  GetHollowedProcesses/IsHollowed(挂起创建)/     */
/*  ValidatePEHeader/ValidateImageBase/            */
/*  ExtractPayload/GetHollowingTypeName/           */
/*  GetDetectionMethodName。                       */
/*  类型/方法/风险评分对齐 PS 枚举语义。             */
/**************************************************/

#include "../../IOC/PEAnalyzer/PeAnalyzer.h"   /* PWPA_PE_INFO (IpeValidatePeHeader) */

/* 镂空类型（对齐 PS HollowingType） */
typedef enum _WKD_HOLLOWING_TYPE {
    WkdHt_None                = 0,
    WkdHt_ClassicHollowing    = 1,   // 经典 RunPE
    WkdHt_SectionHollowing    = 2,   // 单节替换
    WkdHt_ModuleStomping      = 3,   // 合法 DLL 覆写
    WkdHt_ProcessGhosting     = 4,   // 删除待决文件执行
    WkdHt_ProcessHerpaderping = 5,   // 映射后改文件
    WkdHt_EarlyBird           = 6,   // APC 注入 (依赖驱动事件源, 死代码)
    WkdHt_ThreadHijack        = 7,   // 线程上下文修改 (依赖驱动事件源, 死代码)
    WkdHt_ProcessDoppelganging= 8,   // TxF (依赖 FS 监控, 死代码)
    WkdHt_Overwriting          = 9,   // RunPE 覆写: 头+节不匹配但 EP 有效 (对齐 C 版 Overwriting)
    WkdHt_Phantom              = 10,  // 无物理文件 + 隐藏可执行内存 (对齐 C 版 Phantom)
} WKD_HOLLOWING_TYPE, *PWKD_HOLLOWING_TYPE;

/* 检测方法（对齐 PS DetectionMethod） */
typedef enum _WKD_HOLLOWING_METHOD {
    WkdHm_PEHeaderMismatch       = 1,
    WkdHm_EntryPointAnomaly      = 2,
    WkdHm_SectionMismatch        = 3,
    WkdHm_SectionCharacteristics = 4,
    WkdHm_ImageBaseAnomaly       = 5,
    WkdHm_ChecksumMismatch       = 6,
    WkdHm_TimestampMismatch      = 7,
    WkdHm_SizeOfImageMismatch    = 8,
    WkdHm_PebImageBaseMismatch   = 9,   // PEB.ImageBaseAddress 与主模块基址不一致 (对齐 C 版 ModifiedPEB)
    WkdHm_UnbackedExecMemory     = 10,
    WkdHm_ThreadContextAnomaly   = 11,
    WkdHm_CreationPatternAnomaly = 12,  // 依赖驱动事件源, 死代码
    WkdHm_PebImagePathMismatch   = 13,  // PEB.ImagePathName 与实际路径不一致 (对齐 C 版 ImagePathMismatch)
    WkdHm_DeletePendingFile      = 14,
    WkdHm_EntropyAnomaly         = 15,
} WKD_HOLLOWING_METHOD, *PWKD_HOLLOWING_METHOD;

#define WKD_HOLLOWING_MAX_METHODS 16

/* 镂空检测结果（对齐 PS HollowingDetectionResult） */
typedef struct _WKD_HOLLOWING_RESULT {
    BOOLEAN             IsHollowed;
    WKD_HOLLOWING_TYPE  Type;
    ULONG               Confidence;           // 0-100 (30/50/70/90)
    ULONG               RiskScore;            // 0-100
    ULONG               DetectionMethodCount;
    ULONG               DetectionMethods[WKD_HOLLOWING_MAX_METHODS];
    ULONG               MismatchCount;        // 头比对不匹配字段数
    ULONG               OverallSimilarity;    // 头比对千分比 0-1000
    BOOLEAN             HasUnbackedExec;      // 无文件支撑可执行内存
    BOOLEAN             HasRwx;               // RWX 区域
    BOOLEAN             HasShellcodeAtEntryPoint; // 入口点壳码 (对齐 PS entryPointAnalysis.hasShellcodePattern)
    BOOLEAN             ModuleStompingDetected;
    BOOLEAN             FileDeletePending;    // Ghosting 指标
    BOOLEAN             FileModifiedAfterMap; // Herpaderping 指标
    BOOLEAN             PebImageBaseModified; // PEB.ImageBaseAddress 被篡改 (对齐 C 版 ModifiedPEB)
    BOOLEAN             PebImagePathMismatch; // PEB.ImagePathName 与实际路径不一致 (对齐 C 版 ImagePathMismatch)
    BOOLEAN             CorrelatedWithKnownThreat;
    DEF_SHA256_HASH     PayloadHash;          // PayloadHashValid=TRUE 时有效
    BOOLEAN             PayloadHashValid;
    WCHAR               ScanError[128];
} WKD_HOLLOWING_RESULT, *PWKD_HOLLOWING_RESULT;

/*
 * IpeDetectProcessHollowing — 进程镂空检测 (对齐 PS ScanProcess)。
 * ScanMode 复用 WKD_MEM_SCAN_MODE: Quick=仅头比对 / Normal=+节采样+EP / Deep=全量。
 * 返回 TRUE = 检测执行; FALSE = 无法检测（进程不存在/无权限）。
 */
BOOL
IpeDetectProcessHollowing(
    _In_  ULONG                  ProcessId,
    _In_  WKD_MEM_SCAN_MODE      ScanMode,
    _Out_ PWKD_HOLLOWING_RESULT  Result
    );

/* 挂起创建模式判定 (对齐 PS AnalyzeCreationPattern 挂起时长部分)。
 * ★ 死代码: 激活需驱动补源 (创建挂起标志 + NtResumeThread 事件), 当前无调用者。 */
BOOLEAN
IpeIsSuspiciousSuspendedCreation(
    _In_ BOOLEAN CreatedSuspended,
    _In_ BOOLEAN HasResumed,
    _In_ LONGLONG CreatedTick,
    _In_ LONGLONG ResumedTick,
    _In_ LONGLONG CurrentTick
    );

/* 镂空类型 → 名称 (对齐 PS GetHollowingTypeName) */
PCWSTR
IpeHollowingTypeToString(
    _In_ WKD_HOLLOWING_TYPE Type
    );

/* 检测方法 → 名称 (对齐 PS GetDetectionMethodName) */
PCWSTR
IpeHollowingMethodToString(
    _In_ WKD_HOLLOWING_METHOD Method
    );

/* 校验 PE 头有效性 (对齐 PS ValidatePEHeader): 返回 TRUE = IsPE + 节数合理 */
BOOLEAN
IpeValidatePeHeader(
    _In_ PWPA_PE_INFO PeInfo
    );

/* 校验映像基址 (对齐 PS ValidateImageBase): 非 ASLR 非预期基址 / EP 不一致 → FALSE */
BOOLEAN
IpeValidateImageBase(
    _In_ ULONG      ProcessId,
    _In_ ULONG_PTR  ModuleBase,
    _In_ PCWSTR     ProcessPath
    );

/* 提取进程主模块载荷 (对齐 PS ExtractPayload, 上限 1MB), OutBuffer 由调用方 free() */
BOOLEAN
IpeExtractPayload(
    _In_  ULONG   ProcessId,
    _Outptr_ PBYTE* OutBuffer,
    _Out_ PULONG  OutSize
    );

/* 批量镂空扫描 (对齐 PS ScanAllProcesses, 仅返回 IsHollowed 命中)
 * ★ 死代码: 供 UI 主动全盘扫描, 当前无调用者。 */
ULONG
IpeScanAllProcessesForHollowing(
    _Out_writes_to_(MaxResults, *ResultCount) PWKD_HOLLOWING_RESULT Results,
    _In_  ULONG                  MaxResults,
    _Out_ PULONG                 ResultCount,
    _In_  WKD_MEM_SCAN_MODE      ScanMode
    );

/* 按 PID 数组批量镂空扫描 (对齐 PS ScanProcesses, 仅返回 IsHollowed 命中) */
ULONG
IpeScanProcesses(
    _In_  const ULONG* Pids,
    _In_  ULONG        PidCount,
    _Out_writes_to_(MaxResults, *ResultCount) PWKD_HOLLOWING_RESULT Results,
    _In_  ULONG        MaxResults,
    _Out_ PULONG       ResultCount,
    _In_  WKD_MEM_SCAN_MODE ScanMode
    );

/* 按进程名批量镂空扫描 (对齐 PS ScanByName, 仅返回 IsHollowed 命中)
 * ★ 死代码: 供 UI 定向扫描, 当前无调用者。 */
ULONG
IpeScanProcessesByName(
    _In_  PCWSTR ProcessName,
    _Out_writes_to_(MaxResults, *ResultCount) PWKD_HOLLOWING_RESULT Results,
    _In_  ULONG  MaxResults,
    _Out_ PULONG ResultCount,
    _In_  WKD_MEM_SCAN_MODE ScanMode
    );

/* 按进程路径批量镂空扫描 (对齐 PS ScanByPath, 仅返回 IsHollowed 命中)
 * ★ 死代码: 供 UI 定向扫描, 当前无调用者。 */
ULONG
IpeScanProcessesByPath(
    _In_  PCWSTR ProcessPath,
    _Out_writes_to_(MaxResults, *ResultCount) PWKD_HOLLOWING_RESULT Results,
    _In_  ULONG  MaxResults,
    _Out_ PULONG ResultCount,
    _In_  WKD_MEM_SCAN_MODE ScanMode
    );

/* 收集疑似镂空进程 PID 列表 (对齐 PS GetHollowedProcesses)
 * ★ 死代码: 供 UI 主动全盘扫描, 当前无调用者。 */
ULONG
IpeGetHollowedProcesses(
    _Out_writes_(MaxPids) ULONG* Pids,
    _In_  ULONG   MaxPids,
    _Out_ PULONG  Count,
    _In_  WKD_MEM_SCAN_MODE ScanMode
    );