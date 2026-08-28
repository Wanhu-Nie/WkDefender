/**************************************************/
/*  WkDefender 内存扫描 — 机制 B 进程内存入口            */
/**************************************************/

/*
 * 职责：
 *   把机制 B 的 AC 自动机（MemorySignature）应用到进程内存：打开目标进程、
 *   读取内存区域到本地缓冲、调用 MsPatternIndexSearch 做多模式匹配。
 *   完全用户态，无需内核驱动参与（与回路 A 的 FLT 文件扫描并列）。
 *
 * 参考 PhantomSensor：
 *   src/PhantomCore/Core/Process/MemoryScanner.cpp
 *     - ScanWithYARA / ScanProcessMemory（行 1466-2510）：开进程、读内存、调 PatternIndex::Search
 *   纯 C 重写：OpenProcess + ReadProcessMemory + VirtualQueryEx 枚举区域。
 *
 * 触发（回路 B，D8 决策）：agent 收到 WkdMessage_ImageLoaded（内核 ImageNotify
 *   经 ALPC 上送的镜像加载事件）→ 取 ProcessId/ImageBase/ImageSize → 调 MsScanWithYARA。
 *
 * ShadowStrike MemoryScanner.c（内核版扫描框架, 3893 行）对比（2026-08-07）：
 *   框架功能面（模式匹配/区域扫描/熵/统计）已由本文件 + MemorySignature 覆盖，
 *   本次补迁项：
 *     - 分块读取 overlap 跨边界（SS MspScanSingleRegion MED-1 fix L3362-3365）
 *       → MsScanProcessMemory 已补（读 chunk+overlap 推进 chunk，跨边界不漏检）。
 *     - MsFindHighEntropyRegions 全进程高熵区域发现（SS L2135-2265）→ 死代码补迁。
 *     - MsGetStatistics 统计读取（SS L2273-2321）→ 死代码补迁（g_MsStats 埋点）。
 *     - 结果/统计字段补全（SS MS_SCAN_RESULT.DurationMs·MaxSeverity,
 *       MsGetStatistics.Timeouts·CumulativeScanTimeMs·AverageScanTimeMs）→ 已补。
 *   明确不迁（理由见各注释）：BMH 单模式搜索（性能优化, AC 覆盖）/ 内核生命周期
 *   机制（引用计数·lookaside·IoWorkItem·电池降级）/ SS 纸面枚举（Regex·
 *   Signature·Entropy·API 模式类型, WholeWord·AtStart·AtEnd·Negated·Critical
 *   flags）/ MsScanAsync 异步编排（wkd ScanManager 并发槽覆盖）。
 */

#pragma once

#include <windows.h>
#include <stdint.h>
#include "MemorySignature.h"

/**************************************************/
/*               内存区域画像                       */
/*  对齐 PS ProcessAnalyzer AnalyzeMemoryInternal  */
/**************************************************/

typedef struct _WKD_MEMORY_PROFILE {
    ULONG   RegionCount;            /* 提交区域总数 */
    ULONG   ExecutableRegionCount;  /* 可执行区域数 */
    ULONG   RwxRegionCount;         /* RWX 区域数 */
    ULONG   UnbackedExecRegionCount;/* 无文件支撑可执行区域数 (MEM_PRIVATE) */
    ULONG64 TotalVirtualSize;       /* 虚拟地址总大小 */
    ULONG64 TotalCommittedSize;     /* 已提交总大小 */
    ULONG64 TotalExecutableSize;    /* 可执行区域总大小 */
} WKD_MEMORY_PROFILE, *PWKD_MEMORY_PROFILE;

/**************************************************/
/*               区域类型                           */
/*  对齐 PS MemoryType (MemoryScanner)             */
/**************************************************/

typedef enum _WKD_MEM_REGION_TYPE {
    WkdMemType_Unknown = 0,    /* 未知 */
    WkdMemType_Image   = 1,    /* MEM_IMAGE — 已加载模块映像 */
    WkdMemType_Mapped  = 2,    /* MEM_MAPPED — 文件映射 */
    WkdMemType_Private = 3,    /* MEM_PRIVATE — 私有/无文件支撑 */
} WKD_MEM_REGION_TYPE, *PWKD_MEM_REGION_TYPE;

/**************************************************/
/*               区域状态                           */
/**************************************************/

typedef enum _WKD_MEM_REGION_STATE {
    WkdMemState_Free      = 0,    /* MEM_FREE */
    WkdMemState_Reserved  = 1,    /* MEM_RESERVE */
    WkdMemState_Committed = 2,    /* MEM_COMMIT */
} WKD_MEM_REGION_STATE, *PWKD_MEM_REGION_STATE;

/**************************************************/
/*               扫描模式                           */
/*  对齐 PS ScanMode (MemoryScanner)               */
/**************************************************/

typedef enum _WKD_MEM_SCAN_MODE {
    WkdMemScan_Quick  = 0,    /* 仅可执行区域 */
    WkdMemScan_Normal = 1,    /* 可执行 + 私有 */
    WkdMemScan_Deep   = 2,    /* 全部提交内存 */
} WKD_MEM_SCAN_MODE, *PWKD_MEM_SCAN_MODE;

/*++
 * MsScanMemoryProfile
 *   枚举目标进程内存区域，统计可执行/RWX/无文件支撑可执行区域画像。
 *   参考 PS AnalyzeMemoryInternal（仅计数，不做内容匹配）。
 *   OpenProcess 由内部创建并在返回前关闭。
 *--*/
BOOL MsScanMemoryProfile(
    _In_ DWORD ProcessId,
    _Out_ PWKD_MEMORY_PROFILE Profile);

//
// 单条内存区域明细 (对齐 PS MemoryRegion, 含类型/状态/保护建模)
//
typedef struct _WKD_MEMORY_REGION {
    ULONG_PTR BaseAddress;
    SIZE_T    RegionSize;
    ULONG     Protection;          /* 当前保护 PAGE_* (含 modifier) */
    ULONG     AllocationProtect;   /* 分配时保护 (对齐 PS initialProtection) */
    WKD_MEM_REGION_TYPE Type;
    WKD_MEM_REGION_STATE State;
    BOOLEAN   IsRwx;               /* RWX 区域 */
    BOOLEAN   IsUnbackedExec;      /* 无文件支撑可执行区域 (MEM_PRIVATE) */
    BOOLEAN   IsExecutable;
    BOOLEAN   IsWritable;
    BOOLEAN   IsPrivate;
    BOOLEAN   ContainsPE;          /* 区域是否含 MZ/PE 头 (扫描时填充) */
    ULONG     Entropy;             /* 熵 0-1000 (扫描时填充) */
    BOOLEAN   IsSuspicious;
    CHAR      SuspicionReason[64];
} WKD_MEMORY_REGION, *PWKD_MEMORY_REGION;

/*++
 * MsScanMemoryRegions
 *   收集 RWX / 无文件支撑可执行区域的明细列表（对齐 PS rwxRegions /
 *   unbackedExecutable，供取证展示）。
 *--*/
BOOL MsScanMemoryRegions(
    _In_  DWORD             ProcessId,
    _Out_writes_to_(MaxRegions, *Count) PWKD_MEMORY_REGION Regions,
    _In_  ULONG             MaxRegions,
    _Out_ PULONG            Count);

/*++
 * MsScanProcessMemory
 *   扫描目标进程 [Base, Base+Size) 内存区域。本地缓冲后调 MsPatternIndexSearch。
 *   返回 TRUE 表示扫描执行（无论命中与否）；FALSE 表示无法读取该区域（跳过）。
 *--*/
BOOL MsScanProcessMemory(
    _In_ HANDLE hProcess,
    _In_ LPCVOID Base,
    _In_ SIZE_T Size,
    _In_ PMS_PATTERN_INDEX Index,
    _In_ MS_MATCH_CALLBACK Callback);

/*++
 * MsScanWithYARA
 *   高层接口：按 ProcessId 扫描其内存。
 *   ImageBase/ImageSize 为非 NULL 时仅扫该映像区域；否则枚举全部可读提交页。
 *   hProcess 由内部 OpenProcess 创建并在返回前关闭（调用方无需管理）。
 *--*/
BOOL MsScanWithYARA(
    _In_ DWORD ProcessId,
    _In_opt_ LPCVOID ImageBase,
    _In_opt_ SIZE_T ImageSize,
    _In_ PMS_PATTERN_INDEX Index,
    _In_ MS_MATCH_CALLBACK Callback);

/**************************************************/
/*               内存威胁类型                       */
/*  对齐 PS MemoryThreatType (MemoryScanner)       */
/**************************************************/

typedef enum _WKD_MEM_THREAT_TYPE {
    WkdMemThreat_None             = 0,
    WkdMemThreat_Malware          = 1,   /* 通用恶意 (YARA/规则命中) */
    WkdMemThreat_Shellcode        = 2,   /* 壳码模式 */
    WkdMemThreat_APIHashing       = 3,   /* API 哈希壳码 */
    WkdMemThreat_SyscallStub      = 4,   /* 直接 syscall */
    WkdMemThreat_ROPChain         = 5,   /* ROP 链 */
    WkdMemThreat_PEInjection      = 6,   /* 非映像内存 PE (反射加载) */
    WkdMemThreat_CobaltStrike     = 7,   /* CS Beacon */
    WkdMemThreat_Meterpreter      = 8,   /* Meterpreter stage */
    WkdMemThreat_EncryptedPayload = 9,   /* 高熵可执行 (加壳/加密) */
    WkdMemThreat_SuspiciousCode   = 10,  /* Guard 页等规避指标 */
} WKD_MEM_THREAT_TYPE, *PWKD_MEM_THREAT_TYPE;

/**************************************************/
/*               单条内存威胁                       */
/*  对齐 PS MemoryThreat (MemoryScanner)           */
/**************************************************/

#define WKD_MEM_EVIDENCE_SIZE  256

typedef struct _WKD_MEM_THREAT {
    WKD_MEM_THREAT_TYPE Type;
    ULONG_PTR           RegionBase;
    SIZE_T              RegionSize;
    SIZE_T              DetectionOffset;
    ULONG               Protection;
    WKD_MEM_REGION_TYPE MemType;
    CHAR                MatchedRule[64];       /* 命中规则/特征名 */
    CHAR                RuleCategory[32];      /* YARA/Pattern/Kernel/... */
    ULONG               Confidence;            /* 0-100 */
    ULONG               RiskScore;             /* 0-100 */
    CHAR                MitreTechnique[16];    /* T1055/T1620/... */
    /* PE 解析信息 (Type==PEInjection 时有效) */
    BOOLEAN             PeValid;
    ULONG_PTR           PeImageBase;
    ULONG               PeImageSize;
    ULONG               PeEntryPoint;
    USHORT              PeMachine;
    USHORT              PeCharacteristics;
    /* 模块表对照 (对齐 SS isInPEB / isFileBacked, PECandidate) */
    BOOLEAN             PeInPeb;          /* PE 基址在已加载模块表内 (EnumProcessModules) */
    BOOLEAN             PeFileBacked;     /* 是否有文件支撑 (模块表内 ≈ 文件支撑) */
    /* 证据预览 (前 N 字节) */
    UCHAR               EvidencePreview[WKD_MEM_EVIDENCE_SIZE];
    ULONG               EvidenceSize;
} WKD_MEM_THREAT, *PWKD_MEM_THREAT;

/**************************************************/
/*               全进程扫描结果                     */
/*  对齐 PS MemoryScanResult (MemoryScanner)       */
/**************************************************/

#define WKD_MEM_MAX_THREATS      64
#define WKD_MEM_MAX_SUSPICIOUS   32

typedef struct _WKD_MEM_SCAN_RESULT {
    ULONG             ScanId;
    DWORD             ProcessId;
    WKD_MEM_SCAN_MODE Mode;
    BOOLEAN           Completed;
    ULONG             TotalRegions;
    ULONG             RegionsScanned;
    ULONG             RegionsSkipped;
    ULONG64           BytesScanned;
    ULONG             ThreatsFound;
    WKD_MEM_THREAT    Threats[WKD_MEM_MAX_THREATS];
    ULONG             SuspiciousRegionCount;
    WKD_MEMORY_REGION SuspiciousRegions[WKD_MEM_MAX_SUSPICIOUS];
    ULONG             OverallRiskScore;        /* 0-100 (0.7*max + 0.3*avg) */
    ULONG             MaxSeverity;             /* 最高威胁 RiskScore (对齐 SS MS_SCAN_RESULT.MaxSeverity, 0=无威胁) */
    ULONG             DurationMs;              /* 扫描耗时 ms (对齐 SS MS_SCAN_RESULT.DurationMs) */
} WKD_MEM_SCAN_RESULT, *PWKD_MEM_SCAN_RESULT;

/*++
 * MsThreatTypeToString
 *   威胁类型 → 字符串 (对齐 PS MemoryThreatTypeToString, MemoryScanner.cpp L205).
 *--*/
PCSTR MsThreatTypeToString(
    _In_ WKD_MEM_THREAT_TYPE Type
    );

/**************************************************/
/*              检测层 API (ShadowStrike 迁移)     */
/*  对齐 PS MemoryScanner 检测层                  */
/**************************************************/

/*++
 * MsScanProcessMemoryFull
 *   全流程内存扫描:枚举区域 → 过滤 → TOCTOU 重查 → 检测层
 *   (PE/壳码/C2/高熵/字符串) → 双引擎 YARA → 威胁聚合。
 *   对齐 PS ScanProcessMemory (MemoryScanner.cpp)。
 *--*/
NTSTATUS MsScanProcessMemoryFull(
    _In_  DWORD ProcessId,
    _In_  WKD_MEM_SCAN_MODE Mode,
    _Out_ PWKD_MEM_SCAN_RESULT Result);

/*++
 * MsScanBufferFull
 *   无进程上下文缓冲扫描 (供 Tier 引擎/内存事件复用)。
 *   对齐 PS ScanBuffer (MemoryScanner.cpp)。
 *--*/
NTSTATUS MsScanBufferFull(
    _In_  const BYTE* Buffer,
    _In_  ULONG BufferSize,
    _Out_ PWKD_MEM_SCAN_RESULT Result);

/*++
 * MsDetectPE
 *   非映像内存 PE 判定:校验 MZ/PE 头,命中填充 Threat(PEInjection)。
 *   对齐 PS ContainsPEInternal + CreatePEThreat (MemoryScanner.cpp)。
 *--*/
BOOLEAN MsDetectPE(
    _In_  const BYTE* Buffer,
    _In_  ULONG Size,
    _Out_ PWKD_MEM_THREAT Threat);

/**************************************************/
/*              模块表对照 (ShadowStrike 迁移)      */
/*  对齐 SS GetPEBModulesImpl / IsAddressInAnyModule */
/*  (ReflectiveDLLDetector.cpp L2293 / L142)       */
/**************************************************/

#define WKD_MEM_MODULE_MAX  512

typedef struct _WKD_MEM_MODULE_SET {
    ULONG_PTR Bases[WKD_MEM_MODULE_MAX];
    SIZE_T    Sizes[WKD_MEM_MODULE_MAX];
    ULONG     Count;
} WKD_MEM_MODULE_SET, *PWKD_MEM_MODULE_SET;

/*++
 * MsBuildModuleSet
 *   构建进程已加载模块基址/大小集 (EnumProcessModules + GetModuleInformation)。
 *   对齐 SS GetPEBModulesImpl (ReflectiveDLLDetector.cpp L2293)。
 *   返回 TRUE = 构建成功且非空。供隐藏模块对照 (isInPEB/isFileBacked) 使用。
 *--*/
BOOL MsBuildModuleSet(
    _In_  DWORD ProcessId,
    _Out_ PWKD_MEM_MODULE_SET Set);

/*++
 * MsIsAddrInModuleSet
 *   地址是否落在任一模块 [Base, Base+Size) 区间内。
 *   对齐 SS IsAddressInAnyModule (ReflectiveDLLDetector.cpp L142)。
 *--*/
BOOLEAN MsIsAddrInModuleSet(
    _In_ const WKD_MEM_MODULE_SET* Set,
    _In_ ULONG_PTR Address);

/*++
 * MsParsePE
 *   从内存缓冲解析 PE 头 (PE32/PE32+),输出关键字段。
 *   对齐 PS ParsePEInternal (MemoryScanner.cpp),补充 wkd PEAnalyzer 缺失字段。
 *   返回 TRUE = 有效 PE。
 *--*/
BOOLEAN MsParsePE(
    _In_  const BYTE* Buffer,
    _In_  ULONG Size,
    _Out_opt_ PULONG_PTR ImageBase,
    _Out_opt_ PULONG ImageSize,
    _Out_opt_ PULONG EntryPoint,
    _Out_opt_ PUSHORT Machine,
    _Out_opt_ PUSHORT Characteristics);

/*++
 * MsDetectShellcode
 *   全文壳码检测 (NOP sled/GetPC/APIhash/syscall/ROP 链)。
 *   对齐 PS DetectShellcode (MemoryScanner.cpp),特征复用 T1 壳码检测。
 *--*/
BOOLEAN MsDetectShellcode(
    _In_  const BYTE* Buffer,
    _In_  ULONG Size,
    _In_  BOOLEAN IsPrivateExecutable,
    _Out_ PWKD_MEM_THREAT Threat);

/*++
 * MsDetectC2Beacon
 *   C2 Beacon 检测 (CS pipe/config + Meterpreter stage 字符串特征)。
 *   对齐 PS DetectC2Beacon (MemoryScanner.cpp)。
 *--*/
BOOLEAN MsDetectC2Beacon(
    _In_  const BYTE* Buffer,
    _In_  ULONG Size,
    _Out_ PWKD_MEM_THREAT Threat);

/*++
 * MsDetectReflectiveLoader
 *   已知反射加载器签名检测 (对齐 SS DetectKnownLoader 启发式, ReflectiveDLLDetector.cpp L1514):
 *     - CS Beacon config marker / sleep mask stub (g_cobaltStrikePatterns L478)
 *     - Meterpreter reflective stub / stage marker (g_meterpreterPatterns L490)
 *     - API-hash 字节模式: ROR-13 x64/x86 / DJB2 / CRC32 (g_apiHashPatterns L176)
 *   供隐藏无背衬 PE 判定后加载器分类使用。
 *--*/
BOOLEAN MsDetectReflectiveLoader(
    _In_  const BYTE* Buffer,
    _In_  ULONG Size,
    _Out_ PWKD_MEM_THREAT Threat);

/*++
 * MsContainsPE
 *   进程级 PE 快速检查: 给定 pid+地址+大小, 读前部字节判断 MZ 签名。
 *   对齐 SS ContainsPE (ReflectiveDLLDetector.cpp L1207-1217).
 *   ※ 死代码: 供实时内存监控 (T4) PE 预判用, 当前无调用者。
 *--*/
BOOLEAN MsContainsPE(
    _In_  DWORD ProcessId,
    _In_  ULONG_PTR Address,
    _In_  SIZE_T Size);

/*++
 * MsHasReflectiveLoading
 *   快速布尔判定: 目标进程是否存在隐藏无背衬 PE (反射加载)。
 *   对齐 SS HasReflectiveLoading (ReflectiveDLLDetector.cpp L1114-1117).
 *   Quick 模式全扫 + 查 WkdMemThreat_PEInjection && !PeInPeb.
 *   ※ 死代码: 供 UI 快速体检/进程体检, 当前无调用者。
 *--*/
BOOLEAN MsHasReflectiveLoading(
    _In_ DWORD ProcessId);

/*++
 * MsHandleKernelImageLoad
 *   镜像加载通知 → PEB 对照 → 无背衬判定 → 定向反射扫描。
 *   对齐 SS OnKernelImageLoad (ReflectiveDLLDetector.cpp L2567-2604):
 *     系统模块/低 PID 跳过 → 模块表对照 (正常加载已入 PEB 则跳过) →
 *     VirtualQueryEx 查 MEM_PRIVATE → MsScanRegionAt 定向扫描。
 *   ※ 死代码: 依赖 ImageLoad 事件接入 IOA (当前 process_manager.c:1720
 *     MsScanOnImageLoad 仅做 YARA 扫描, 未调用本函数)。
 *--*/
VOID MsHandleKernelImageLoad(
    _In_  DWORD ProcessId,
    _In_  ULONG_PTR ImageBase,
    _In_  SIZE_T ImageSize,
    _In_  BOOLEAN IsSystemModule);

/*++
 * MsCheckHighEntropy
 *   高熵判定 (私有可执行 + 熵超阈值 → 加壳/加密载荷)。
 *   对齐 PS 高熵检测层, 复用 CoEntropyBinary (bits*1000)。
 *--*/
BOOLEAN MsCheckHighEntropy(
    _In_  const BYTE* Buffer,
    _In_  ULONG Size,
    _Out_ PULONG Entropy,          /* 输出熵 0-1000 */
    _Out_ PWKD_MEM_THREAT Threat);

/* 高熵区域条目（对齐 SS MS_ENTROPY_REGION，熵 0-1000 尺度） */
typedef struct _WKD_ENTROPY_REGION {
    ULONG_PTR BaseAddress;      /* 目标进程 VA 地址 */
    SIZE_T    RegionSize;
    ULONG     Entropy;          /* 0-1000 */
} WKD_ENTROPY_REGION, *PWKD_ENTROPY_REGION;

/*++
 * MsFindHighEntropyRegions
 *   全进程高熵区域发现（对齐 SS MsFindHighEntropyRegions L2135-2265）：
 *   枚举 MEM_COMMIT 区域 → 读首块采样（64KB）→ 熵 ≥ 阈值 → 记录。
 *   ※ 死代码: 供取证 / UI 主动扫描接线，当前无调用者。
 *--*/
NTSTATUS MsFindHighEntropyRegions(
    _In_  DWORD ProcessId,
    _In_  ULONG EntropyThreshold,      /* 0-1000，默认 MS_ENTROPY_THRESHOLD */
    _Out_writes_to_(MaxResults, *ResultCount) PWKD_ENTROPY_REGION Results,
    _In_  ULONG MaxResults,
    _Out_ PULONG ResultCount);

/*++
 * MsExtractStrings
 *   字符串提取 (ASCII + UTF-16LE 双 pass,上限防 DoS)。
 *   对齐 PS ExtractStringsInternal (MemoryScanner.cpp)。
 *   Out 为逗号拼接的定长缓冲。
 *--*/
ULONG MsExtractStrings(
    _In_  const BYTE* Buffer,
    _In_  ULONG Size,
    _In_  ULONG MinLength,
    _Out_writes_(OutCapacity) PCHAR Out,
    _In_  ULONG OutCapacity);

/**************************************************/
/*  死代码迁移 — 暂不接线                          */
/*  (待 UI 主动扫描 / 取证阶段接入, 功能已实现)     */
/**************************************************/

/*++
 * MsScanProcesses
 *   多进程扫描 (对齐 PS ScanProcesses, MemoryScanner.cpp L1992).
 *   当前为串行实现 (死代码: 待线程池并行化后接线)。
 *--*/
NTSTATUS MsScanProcesses(
    _In_  const DWORD* Pids,
    _In_  ULONG PidCount,
    _Out_writes_(MaxResults) PWKD_MEM_SCAN_RESULT Results,
    _In_  ULONG MaxResults,
    _Out_ PULONG ResultCount);

/*++
 * MsScanAllProcesses
 *   枚举全部进程逐个扫描 (对齐 PS ScanAllProcesses, MemoryScanner.cpp L2031).
 *   死代码: 待 UI 主动全盘扫描接线。
 *--*/
NTSTATUS MsScanAllProcesses(
    _Out_writes_(MaxResults) PWKD_MEM_SCAN_RESULT Results,
    _In_  ULONG MaxResults,
    _Out_ PULONG ResultCount);

/*++
 * MsScanRegionAt
 *   定向扫描指定内存区域 [Base, Base+Size) (对齐 PS ScanRegion, L2059).
 *   为内核内存事件 (OnKernelMemoryEvent) 定向深度分析预留。
 *   死代码: wkd 事件流不同, 暂不接线。
 *--*/
NTSTATUS MsScanRegionAt(
    _In_  DWORD ProcessId,
    _In_  ULONG_PTR BaseAddress,
    _In_  SIZE_T Size,
    _Out_ PWKD_MEM_SCAN_RESULT Result);

/*++
 * MsDumpRegion
 *   单区域内存转储到文件 (对齐 PS DumpRegion, MemoryScanner.cpp L2380).
 *   死代码: 取证阶段接入。
 *--*/
BOOLEAN MsDumpRegion(
    _In_ DWORD ProcessId,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T Size,
    _In_ PCWSTR OutputPath);

/*++
 * MsCreateMemoryDump
 *   全进程内存转储 (对齐 PS CreateMemoryDump, MemoryScanner.cpp L2413).
 *   死代码: 取证阶段接入。
 *--*/
BOOLEAN MsCreateMemoryDump(
    _In_ DWORD ProcessId,
    _In_ PCWSTR OutputPath);

/**************************************************/
/*  死代码补充 — ShadowStrike MemoryScanner 遗漏项  */
/*  (工具函数/完整分析/配置/统计, 暂不接线)         */
/**************************************************/

/* 扫描配置 (对齐 PS MemoryScannerConfig, MemoryScanner.hpp L740) */
typedef struct _WKD_MEM_SCAN_CONFIG {
    WKD_MEM_SCAN_MODE DefaultMode;      /* 默认扫描模式 */
    BOOLEAN           EnableYara;       /* 启用 YARA */
    BOOLEAN           EnableShellcodeDetection; /* 启用壳码检测 */
    BOOLEAN           ScanExecutable;   /* 扫可执行区域 */
    BOOLEAN           ScanRwx;          /* 扫 RWX */
    BOOLEAN           ScanPrivate;      /* 扫私有内存 */
    ULONG             MaxRegionSize;    /* 单区域读取上限 (字节) */
    ULONG             ScanTimeoutMs;    /* 扫描超时 (ms) */
    ULONG             EntropyThreshold; /* 熵阈值 (0-1000) */
    ULONG             MinReportConfidence; /* 最低上报置信度 */
} WKD_MEM_SCAN_CONFIG, *PWKD_MEM_SCAN_CONFIG;

/* 扫描统计 (对齐 PS MemoryScannerStats, MemoryScanner.hpp L866;
 * 补 SS MsGetStatistics 耗时/超时字段) */
typedef struct _WKD_MEM_SCANNER_STATS {
    volatile LONG64 TotalScans;
    volatile LONG64 RegionsScanned;
    volatile LONG64 BytesScanned;
    volatile LONG64 ThreatsFound;
    volatile LONG64 ShellcodeDetections;
    volatile LONG64 PeDetections;
    volatile LONG64 YaraMatches;
    volatile LONG64 ScanErrors;
    volatile LONG64 Timeouts;               /* 对齐 SS MsGetStatistics.Timeouts (扫描超时次数) */
    volatile LONG64 CumulativeScanTimeMs;   /* 对齐 SS Stats.CumulativeScanTimeMs (扫描耗时累计) */
    volatile LONG64 AverageScanTimeMs;      /* 对齐 SS Stats.AverageScanTimeMs (Cumulative/Total) */
} WKD_MEM_SCANNER_STATS, *PWKD_MEM_SCANNER_STATS;

/*++
 * MsGetStatistics
 *   读取扫描统计（对齐 SS MemoryScanner MsGetStatistics L2273-2321；wkd 全局
 *   g_MsStats 由扫描入口 + MsScanRegionContent 埋点维护）。
 *   ※ 死代码: 查询 API 无调用者（对齐项目惯例 #30/#40），供 UI/诊断接线。
 *--*/
VOID MsGetStatistics(_Out_ PWKD_MEM_SCANNER_STATS Stats);

/*++ API 哈希值解析 (ShadowStrike ShellcodeDetector 迁移 2026-08-07):
 *   SdpDetectApiHashing 从 MOV/PUSH imm32 提取 ROR13 哈希 → 查内置 38 条库
 *   解析具体 API 名。wkd 原 g_ApiHashPatterns 仅识别哈希指令字节模式, 本结构
 *   承载"值解析"结果 (强信号, 对齐 SS SD_API_HASH_INFO 精简为值语义)。
 *--*/
typedef struct _WKD_API_HASH_ENTRY {
    ULONG       Hash;       /* ROR13 hash 值 */
    const char* ApiName;    /* 静态串指针, 非拷贝 */
    const char* DllName;
} WKD_API_HASH_ENTRY, *PWKD_API_HASH_ENTRY;

typedef struct _WKD_API_HASH_RESULT {
    ULONG ResolvedCount;                /* 解析成功数 */
    ULONG ResolutionOffset;             /* 首个命中 imm32 相对偏移 (对齐 SS ResolutionCodeStart 语义, 改相对偏移) */
    struct {
        ULONG Hash;                     /* 命中哈希值 */
        CHAR  ApiName[64];
        CHAR  DllName[32];
    } Resolved[16];                     /* SS 上限 32; 值语义栈结构压到 16 防爆栈 */
} WKD_API_HASH_RESULT, *PWKD_API_HASH_RESULT;

/* 直接 syscall stub 摘要 (对齐 SS SD_SYSCALL_INFO, 值语义, StubOffset 为相对偏移) */
typedef struct _WKD_SYSCALL_STUB {
    ULONG      SyscallNumber;           /* 系统调用号 (x64 MOV EAX,imm32 提取) */
    ULONG_PTR  StubOffset;              /* 相对缓冲偏移 */
    ULONG      StubSize;
    BOOLEAN    IsDirect;                /* TRUE=完整 stub / FALSE=裸 SYSCALL/SYSENTER/INT 2E */
} WKD_SYSCALL_STUB, *PWKD_SYSCALL_STUB;

/* 完整壳码分析 (对齐 PS ShellcodeAnalysis, MemoryScanner.hpp L699) */
typedef struct _WKD_SHELLCODE_ANALYSIS {
    BOOLEAN IsShellcode;
    ULONG   Confidence;          /* 0-100 */
    BOOLEAN HasNopSled;
    ULONG   NopSledLength;
    BOOLEAN HasApiHashing;
    CHAR    ApiHashAlgorithm[16]; /* "ROR13"/"ROL/ROR" */
    BOOLEAN HasSyscallStubs;
    BOOLEAN HasGetPc;
    CHAR    Architecture[8];     /* "x64"/"x86"/"mixed" */
    CHAR    Family[32];          /* 已知壳码家族 (预留) */
    /* ShadowStrike ShellcodeDetector 迁移 2026-08：SS 独有检测标志（wkd
     * IocDetectShellcode 未覆盖：EggHunter/编码器循环/HeavensGate/
     * StackPivot/可疑调用，对齐 SS SdpDetect* 系列）。 */
    BOOLEAN HasEggHunter;        /* EggHunter（SEH/syscall/NtDisplayString 签名） */
    BOOLEAN HasEncoder;          /* 编码器循环（XOR/ADD/SUB/ROL/ROR + 邻近循环） */
    CHAR    EncoderType[12];     /* "XOR"/"ADD"/"SUB"/"ROL"/"ROR" */
    BOOLEAN HasHeavensGate;      /* WoW64 32→64 过渡（JMP FAR 0x33 / RETF） */
    BOOLEAN HasStackPivot;       /* 栈转移 gadget（XCHG ESP/MOV ESP/LEAVE RET 等） */
    BOOLEAN HasSuspiciousCall;   /* 间接 CALL/JMP 密集（≥3，动态 API 解析） */
    /* ShadowStrike ShellcodeDetector 评分映射 (2026-08-07) */
    BOOLEAN HasHighEntropy;      /* 熵 ≥ 阈值 (评分 +10) */
    BOOLEAN HasPic;              /* 位置无关代码 GetPC 5 模式 (评分 +15) */
    BOOLEAN HasKnownSignature;   /* 已知签名命中 (评分 +40, 预留) */
    ULONG   ResolvedApiCount;    /* 哈希值解析数 (APIHashing >3 再 +15) */
    CHAR    ResolvedApis[8][64]; /* 解析出的 API 名 */
    ULONG   SyscallCount;        /* 直接 syscall 数 (>2 再 +10) */
    ULONG   SyscallNumbers[16];  /* 系统调用号 */
    ULONG   NopSledOffset;       /* NOP sled 起始相对偏移 (对齐 SS NopSled.StartAddress) */
    UCHAR   NopByte;             /* NOP sled 主导字节 (对齐 SS NopSled.NopByte, 通常 0x90) */
    ULONG   EggHunterOffset;     /* EggHunter 命中相对偏移 (对齐 SS EggHunter.HunterAddress) */
    ULONG   StackPivotGadgetOffset; /* 栈 pivot gadget 相对偏移 (对齐 SS StackPivot.GadgetAddress) */
    ULONG   EncoderLoopOffset;   /* 编码器解码循环起始相对偏移 (对齐 SS Encoder.LoopStart) */
    ULONG   AnalysisDurationMs;  /* 分析耗时 ms (对齐 SS SdAnalyzeBuffer AnalysisDurationMs) */
} WKD_SHELLCODE_ANALYSIS, *PWKD_SHELLCODE_ANALYSIS;

/*++
 * MsReadMemory
 *   安全读进程内存 (对齐 PS ReadMemory, MemoryScanner.cpp L2321).
 *   上限 MS_REGION_READ_LIMIT (256MB 对齐 PS MAX_REGION_SIZE).
 *   返回 Heap 分配缓冲 (调用者 HeapFree/free). 死代码: 工具函数, 暂不接线。
 *--*/
NTSTATUS MsReadMemory(
    _In_  DWORD ProcessId,
    _In_  ULONG_PTR Address,
    _In_  SIZE_T Size,
    _Outptr_ PBYTE* OutBuffer,
    _Out_ PULONG OutSize);

/*++
 * MsExtractPayload
 *   提取反射加载 PE 内存映像 (对齐 SS ExtractPayload, ReflectiveDLLDetector.cpp L1587-1635).
 *   上限 100MB (对齐 SS kMaxExtraction). 死代码: 取证阶段接入。
 *--*/
NTSTATUS MsExtractPayload(
    _In_  DWORD ProcessId,
    _In_  ULONG_PTR BaseAddress,
    _In_  SIZE_T Size,
    _Outptr_ PBYTE* OutBuffer,
    _Out_ PULONG OutSize);

/*++
 * MsDumpPE
 *   提取并写盘 (对齐 SS DumpPE, ReflectiveDLLDetector.cpp L1637-1655). 死代码: 取证阶段接入。
 *--*/
BOOLEAN MsDumpPE(
    _In_  DWORD ProcessId,
    _In_  ULONG_PTR BaseAddress,
    _In_  SIZE_T Size,
    _In_  PCWSTR OutputPath);

/*++
 * MsEnumerateRegions
 *   完整区域枚举 (对齐 PS EnumerateRegions, MemoryScanner.cpp L591).
 *   返回全部提交区域 (含完整区域模型). 死代码: 暂不接线。
 *--*/
NTSTATUS MsEnumerateRegions(
    _In_  DWORD ProcessId,
    _Out_writes_to_(MaxRegions, *Count) PWKD_MEMORY_REGION Regions,
    _In_  ULONG MaxRegions,
    _Out_ PULONG Count);

/*++
 * MsEnumerateExecutableRegions
 *   可执行区域子集 (对齐 PS EnumerateExecutableRegions, MemoryScanner.cpp L2217).
 *   死代码: 暂不接线。
 *--*/
NTSTATUS MsEnumerateExecutableRegions(
    _In_  DWORD ProcessId,
    _Out_writes_to_(MaxRegions, *Count) PWKD_MEMORY_REGION Regions,
    _In_  ULONG MaxRegions,
    _Out_ PULONG Count);

/*++
 * MsEnumerateSuspiciousRegions
 *   可疑区域子集 (对齐 PS EnumerateSuspiciousRegions, MemoryScanner.cpp L2230).
 *   死代码: 暂不接线。
 *--*/
NTSTATUS MsEnumerateSuspiciousRegions(
    _In_  DWORD ProcessId,
    _Out_writes_to_(MaxRegions, *Count) PWKD_MEMORY_REGION Regions,
    _In_  ULONG MaxRegions,
    _Out_ PULONG Count);

/*++
 * MsGetRegionInfo
 *   地址 → 区域信息 (对齐 PS GetRegionInfo, MemoryScanner.cpp L2243).
 *   死代码: 暂不接线。
 *--*/
BOOLEAN MsGetRegionInfo(
    _In_  DWORD ProcessId,
    _In_  ULONG_PTR Address,
    _Out_ PWKD_MEMORY_REGION Region);

/*++
 * MsAnalyzeShellcode
 *   完整壳码分析 (对齐 PS AnalyzeForShellcode, MemoryScanner.cpp L1826).
 *   基于 IocDetectShellcode 特征 + 指标加权置信度 + 架构判定.
 *   死代码: 暂不接线 (MsDetectShellcode 已覆盖检测主路径).
 *--*/
VOID MsAnalyzeShellcode(
    _In_  const BYTE* Buffer,
    _In_  ULONG Size,
    _Out_ PWKD_SHELLCODE_ANALYSIS Analysis);

/*++
 * MsCalculateEntropy
 *   公共熵计算 (对齐 PS CalculateEntropy, 复用 CoEntropyBinary bits*1000).
 *   死代码: 暂不接线。
 *--*/
ULONG MsCalculateEntropy(
    _In_ const BYTE* Buffer,
    _In_ ULONG Size);

/*++
 * MsCheckAPIHashing
 *   公共 API 哈希检测 (对齐 PS CheckAPIHashing, MemoryScanner.cpp L2308).
 *   死代码: 暂不接线。
 *--*/
BOOLEAN MsCheckAPIHashing(
    _In_ const BYTE* Buffer,
    _In_ ULONG Size);
