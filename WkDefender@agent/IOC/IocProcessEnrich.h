/**************************************************/
/*  WkDefender IOC — 进程富化引擎                   */
/*  全量迁移 PhantomCore ProcessMonitor.cpp          */
/*  CategorizeProcess / 用户身份 / 完整性 /          */
/*  PPID Spoofing / PID 复用检测                    */
/**************************************************/

#pragma once

#include <windows.h>
#include "../IOA/IoaTypes.h"
#include "../Memory/MemoryScan.h"   /* WKD_MEM_SCAN_MODE / WKD_MEMORY_REGION */
#include "../Common/PathUtil.h"     /* WkdIsMasquerading / WkdIsSystemDirectory */
#include "PEAnalyzer/PeAnalyzer.h"  /* PWPA_PE_INFO (IpeValidatePeHeader 用) */

//
// 进程分类（对齐 PS ProcessCategory）
//
typedef enum _WKD_PROCESS_CATEGORY {
    WkdPcUnknown            = 0,
    WkdPcSystemCritical     = 1,    // csrss, smss, wininit
    WkdPcSystemCore         = 2,    // services, lsass, winlogon, svchost
    WkdPcSystemService      = 3,    // Windows 服务
    WkdPcSecuritySoftware   = 4,    // AV/EDR/防火墙
    WkdPcEndUserApp         = 5,    // 普通用户应用
    WkdPcInternetBrowser    = 6,    // chrome, firefox, msedge
    WkdPcOffice             = 7,    // winword, excel, powerpnt
    WkdPcScriptHost         = 8,    // powershell, cscript, python, node
    WkdPcSystemUtility      = 9,    // cmd, certutil, bitsadmin
    WkdPcLOLBin             = 10,   // Living-off-the-land
    WkdPcInstaller          = 11,   // 安装程序
    WkdPcDeveloper          = 12,   // IDE/编译器
    WkdPcNetworkUtility     = 13,   // 网络工具
    WkdPcMax
} WKD_PROCESS_CATEGORY, *PWKD_PROCESS_CATEGORY;

//
// 历史进程条目（PID 复用检测用）
//
typedef struct _WKD_HISTORICAL_ENTRY {
    LIST_ENTRY  ListEntry;
    ULONG       Pid;
    LONGLONG    ExitTime;       // FILETIME
    WCHAR       ImagePath[260];
} WKD_HISTORICAL_ENTRY, *PWKD_HISTORICAL_ENTRY;

//
// 历史追踪器
//
typedef struct _WKD_HISTORICAL_TRACKER {
    LIST_ENTRY      EntryHead;
    CRITICAL_SECTION Lock;
    ULONG           MaxEntries;
    ULONG           Count;
} WKD_HISTORICAL_TRACKER, *PWKD_HISTORICAL_TRACKER;

//
// 全局历史追踪器实例
//
extern WKD_HISTORICAL_TRACKER g_WkdHistoricalTracker;

//
// ======================================================================
// 进程分类
// ======================================================================

WKD_PROCESS_CATEGORY
IpeCategorizeProcess(
    _In_ PCWSTR ProcessName,
    _In_ PCWSTR ProcessPath
    );

//
// ======================================================================
// 用户身份 + 完整性采集（对齐 PS GetProcessUser / GetIntegrityLevel）
// ======================================================================

typedef struct _WKD_USER_CONTEXT {
    WCHAR   UserName[64];
    WCHAR   DomainName[64];
    ULONG   IntegrityLevel;
    BOOLEAN IsElevated;
    BOOLEAN IsProtectedProcess;
    BOOLEAN IsWow64;
    BOOLEAN HasRuntimeDep;      // ProcessExecuteFlags 运行时 DEP（迁移自 SS PapAnalyzeSecurityMitigations）
} WKD_USER_CONTEXT, *PWKD_USER_CONTEXT;

BOOL
IpeCollectUserContext(
    _In_  DWORD            ProcessId,
    _Out_ PWKD_USER_CONTEXT Context
    );

//
// ======================================================================
// PPID Spoofing 增强检测（对齐 PS DetectPPIDSpoofingImpl）
// 返回值: TRUE = 检测到 spoofing
// ======================================================================

BOOL
IpeDetectPpidSpoofing(
    _In_ PWKD_PROCESS ChildNode,
    _In_ PWKD_PROCESS ParentNode
    );

//
// ======================================================================
// PID 复用检测（对齐 PS WasPidReused）
// 往历史追踪器添加条目
// ======================================================================

VOID
IpeRecordProcessExit(
    _In_ ULONG   Pid,
    _In_ PCWSTR  ImagePath
    );

//
// 查询指定 PID 是否在短时间内被复用
//
BOOL
IpeWasPidReused(
    _In_ ULONG  Pid,
    _In_ DWORD  WindowMs
    );

//
// ======================================================================
// 父-子分析（对齐 PS GetExpectedParent / AnalyzeParentChildInternal）
// ======================================================================

//
// 父-子异常类型
//
typedef enum _WKD_PARENT_ANOMALY {
    WkdPaNormal                 = 0,
    WkdPaUnexpectedParent       = 1,    // 父进程不是预期父进程
    WkdPaSessionMismatch        = 2,    // 父子会话不同
    WkdPaSuspiciousOfficeChild  = 3,    // Office→cmd/powershell
    WkdPaSuspiciousBrowserChild = 4,    // Browser→cmd/powershell
    WkdPaOrphanProcess          = 5,    // 父进程不存在
    WkdPaSuspiciousSmssChild    = 6,    // 非系统子声称 smss 为父（谱系，非 PPID）
    WkdPaSuspiciousLolbinChild  = 7,    // 非系统 LOLBin 子进程
    WkdPaSuspiciousScriptChain  = 8,    // ScriptHost/Shell→ScriptHost/Shell
} WKD_PARENT_ANOMALY, *PWKD_PARENT_ANOMALY;

//
// 获取预期父进程名（对齐 PS GetExpectedParent，25 条规则）
//
PCWSTR
IpeGetExpectedParent(
    _In_ PCWSTR ChildProcessName
    );

//
// 父-子关系全面分析（对齐 PS AnalyzeParentChildInternal）
//
typedef struct _WKD_PARENT_CHILD_RESULT {
    WKD_PARENT_ANOMALY  Anomaly;
    ULONG               RiskScore;      // 0-100
    BOOLEAN             IsPpidSpoofed;
    BOOLEAN             IsExpectedParent;
    WCHAR               ExpectedParentName[64];
    WCHAR               AnomalyReason[256];
} WKD_PARENT_CHILD_RESULT, *PWKD_PARENT_CHILD_RESULT;

VOID
IpeAnalyzeParentChild(
    _In_  PWKD_PROCESS      ChildNode,
    _In_  PWKD_PROCESS      ParentNode,
    _Out_ PWKD_PARENT_CHILD_RESULT Result
    );

//
// ======================================================================
// 模块可疑检测（对齐 PS FindSuspiciousModulesFromList）
// ======================================================================

//
// 单条模块可疑信息
//
typedef enum _WKD_DLL_TRUST_LEVEL {
    WkdDllTrust_Unknown      = 0,   // 未知
    WkdDllTrust_Malicious    = 1,   // 已知恶意 (哈希命中)
    WkdDllTrust_Suspicious   = 2,   // 可疑特征 (仿冒/高熵/可疑位置)
    WkdDllTrust_Untrusted    = 3,   // 未签名未知
    WkdDllTrust_ThirdParty   = 4,   // 已签名三方
    WkdDllTrust_System       = 5,   // 系统 DLL (微软签名 + 系统目录)
    WkdDllTrust_Whitelisted  = 6    // 白名单
} WKD_DLL_TRUST_LEVEL, *PWKD_DLL_TRUST_LEVEL;

typedef struct _WKD_SUSPICIOUS_MODULE {
    WCHAR   ModulePath[260];
    WCHAR   ModuleName[64];
    ULONG   RiskScore;          // 0-100
    ULONG   Flags;
#define WKD_SMF_UNSIGNED        0x00000001
#define WKD_SMF_REVOKED         0x00000002
#define WKD_SMF_SUSPICIOUS_PATH 0x00000004
#define WKD_SMF_DOUBLE_EXT      0x00000008
#define WKD_SMF_MASQUERADE      0x00000010   /* 仿冒系统 DLL 名 */
#define WKD_SMF_HIGH_ENTROPY    0x00000020   /* 高熵 (疑似混淆/加密) */
#define WKD_SMF_KNOWN_MALICIOUS 0x00000040   /* 哈希命中恶意 */
#define WKD_SMF_SIDE_LOAD       0x00000080   /* DLL 侧加载 */
#define WKD_SMF_SEARCH_ORDER    0x00000100   /* 搜索顺序劫持 */
#define WKD_SMF_PATH_SPACES     0x00000200   /* 路径含空格 (未引号路径风险) */

    /* 信任评估 (对齐 ShadowStrike DetermineTrustLevel) */
    ULONG   TrustLevel;         // WKD_DLL_TRUST_LEVEL
    BOOLEAN IsMicrosoftSigned;
    BOOLEAN IsInSystemDir;
    BOOLEAN HashComputed;
    UCHAR   Sha256Hash[32];
} WKD_SUSPICIOUS_MODULE, *PWKD_SUSPICIOUS_MODULE;

//
// 检测已加载模块中的可疑项
//
ULONG
IpeFindSuspiciousModules(
    _In_  ULONG                    ProcessId,
    _Out_writes_to_(*Count, *Count) PWKD_SUSPICIOUS_MODULE Modules,
    _In_  ULONG                    MaxModules,
    _Out_ PULONG                   Count
    );

//
// 单 DLL 信任级查询（对齐 ShadowStrike GetTrustLevel）
// 基于验签 + 系统目录 + 仿冒 + 哈希, 按 DetermineTrustLevel 顺序判定。
// 返回 WKD_DLL_TRUST_LEVEL (Unknown=无法判定)。
//
ULONG
IpeGetDllTrustLevel(
    _In_ PCWSTR DllPath
    );

//
// ======================================================================
// 模块完整性验证（对齐 PS ValidateModuleIntegrity）
// 比较内存中的 PE 头与磁盘文件的 PE 头是否一致。
// 返回值: TRUE = 完整（一致），FALSE = 被篡改或无法验证
// ======================================================================

BOOL
IpeValidateModuleIntegrity(
    _In_ ULONG    ProcessId,
    _In_ ULONG_PTR ModuleBase,
    _In_ PCWSTR   ModulePath
    );

//
// ======================================================================
// 特权分析增强（对齐 PS AnalyzeSecurityContextInternal）
// 枚举启用特权并检测危险特权
// ======================================================================

typedef struct _WKD_PRIVILEGE_INFO {
    WCHAR   Name[64];
    BOOLEAN Enabled;
    BOOLEAN IsDangerous;
} WKD_PRIVILEGE_INFO, *PWKD_PRIVILEGE_INFO;

//
// 采集进程特权列表
//
ULONG
IpeCollectPrivileges(
    _In_  ULONG                 ProcessId,
    _Out_writes_to_(*Count, *Count) PWKD_PRIVILEGE_INFO Privileges,
    _In_  ULONG                 MaxPrivs,
    _Out_ PULONG                Count
    );

//
// 初始化/清理历史追踪器
//
VOID
IpeInitHistoricalTracker(
    _In_ ULONG MaxEntries
    );

VOID
IpeCleanupHistoricalTracker(
    VOID
    );

//
// ======================================================================
// 系统进程名单（对齐 PS AnalyzerConstants::SYSTEM_PROCESSES，27 条）
// ======================================================================

//
// 判定进程名是否为已知 Windows 系统进程（精确匹配，不区分大小写）
// 返回值: TRUE = 系统进程
//
BOOL
IpeIsSystemProcess(
    _In_ PCWSTR ProcessName
    );

//
// ======================================================================
// 进程镂空检测（对齐 PS ProcessHollowingDetector::ScanProcess）
// ======================================================================

//
// 镂空类型（对齐 PS HollowingType）
//
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

//
// 检测方法（对齐 PS DetectionMethod）
//
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

//
// 镂空检测结果（对齐 PS HollowingDetectionResult）
//
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

//
// 进程镂空检测（对齐 PS ScanProcess）
// ScanMode 复用 WKD_MEM_SCAN_MODE: Quick=仅头比对 / Normal=+节采样+EP / Deep=全量
// 返回 TRUE = 检测执行; FALSE = 无法检测（进程不存在/无权限）
//
BOOL
IpeDetectProcessHollowing(
    _In_  ULONG                  ProcessId,
    _In_  WKD_MEM_SCAN_MODE      ScanMode,
    _Out_ PWKD_HOLLOWING_RESULT  Result
    );

//
// 挂起创建模式判定 (对齐 PS AnalyzeCreationPattern 挂起时长部分)
// ★ 死代码: 激活需驱动补源 (创建挂起标志 + NtResumeThread 事件), 当前无调用者。
//
BOOLEAN
IpeIsSuspiciousSuspendedCreation(
    _In_ BOOLEAN CreatedSuspended,
    _In_ BOOLEAN HasResumed,
    _In_ LONGLONG CreatedTick,
    _In_ LONGLONG ResumedTick,
    _In_ LONGLONG CurrentTick
    );

//
// 镂空类型 → 名称 (对齐 PS GetHollowingTypeName)
//
PCWSTR
IpeHollowingTypeToString(
    _In_ WKD_HOLLOWING_TYPE Type
    );

//
// 检测方法 → 名称 (对齐 PS GetDetectionMethodName)
//
PCWSTR
IpeHollowingMethodToString(
    _In_ WKD_HOLLOWING_METHOD Method
    );

//
// 校验 PE 头有效性 (对齐 PS ValidatePEHeader)
// 返回值: TRUE = 有效 (IsPE + 节数在合理范围)
//
BOOLEAN
IpeValidatePeHeader(
    _In_ PWPA_PE_INFO PeInfo
    );

//
// 校验映像基址 (对齐 PS ValidateImageBase)
// 非 ASLR 二进制加载于非预期基址 / 入口点不一致 → FALSE。
// 返回值: TRUE = 基址正常或无法校验; FALSE = 基址异常。
//
BOOLEAN
IpeValidateImageBase(
    _In_ ULONG      ProcessId,
    _In_ ULONG_PTR  ModuleBase,
    _In_ PCWSTR     ProcessPath
    );

//
// 提取进程主模块载荷 (对齐 PS ExtractPayload, 上限 1MB)
// 返回值: TRUE = 成功, OutBuffer 由调用方 free()。
//
BOOLEAN
IpeExtractPayload(
    _In_  ULONG   ProcessId,
    _Outptr_ PBYTE* OutBuffer,
    _Out_ PULONG  OutSize
    );

//
// 批量镂空扫描 (对齐 PS ScanAllProcesses, 仅返回 IsHollowed 命中)
// ★ 死代码: 供 UI 主动全盘扫描, 当前无调用者。
//
ULONG
IpeScanAllProcessesForHollowing(
    _Out_writes_to_(MaxResults, *ResultCount) PWKD_HOLLOWING_RESULT Results,
    _In_  ULONG                  MaxResults,
    _Out_ PULONG                 ResultCount,
    _In_  WKD_MEM_SCAN_MODE      ScanMode
    );

//
// 按 PID 数组批量镂空扫描 (对齐 PS ScanProcesses, 仅返回 IsHollowed 命中)
//
ULONG
IpeScanProcesses(
    _In_  const ULONG* Pids,
    _In_  ULONG        PidCount,
    _Out_writes_to_(MaxResults, *ResultCount) PWKD_HOLLOWING_RESULT Results,
    _In_  ULONG        MaxResults,
    _Out_ PULONG       ResultCount,
    _In_  WKD_MEM_SCAN_MODE ScanMode
    );

//
// 按进程名批量镂空扫描 (对齐 PS ScanByName, 仅返回 IsHollowed 命中)
// ★ 死代码: 供 UI 定向扫描, 当前无调用者。
//
ULONG
IpeScanProcessesByName(
    _In_  PCWSTR ProcessName,
    _Out_writes_to_(MaxResults, *ResultCount) PWKD_HOLLOWING_RESULT Results,
    _In_  ULONG  MaxResults,
    _Out_ PULONG ResultCount,
    _In_  WKD_MEM_SCAN_MODE ScanMode
    );

//
// 按进程路径批量镂空扫描 (对齐 PS ScanByPath, 仅返回 IsHollowed 命中)
// ★ 死代码: 供 UI 定向扫描, 当前无调用者。
//
ULONG
IpeScanProcessesByPath(
    _In_  PCWSTR ProcessPath,
    _Out_writes_to_(MaxResults, *ResultCount) PWKD_HOLLOWING_RESULT Results,
    _In_  ULONG  MaxResults,
    _Out_ PULONG ResultCount,
    _In_  WKD_MEM_SCAN_MODE ScanMode
    );

//
// 收集疑似镂空进程 PID 列表 (对齐 PS GetHollowedProcesses)
// ★ 死代码: 供 UI 主动全盘扫描, 当前无调用者。
//
ULONG
IpeGetHollowedProcesses(
    _Out_writes_(MaxPids) ULONG* Pids,
    _In_  ULONG   MaxPids,
    _Out_ PULONG  Count,
    _In_  WKD_MEM_SCAN_MODE ScanMode
    );

//
// ======================================================================
// 进程环境分析（对齐 SS EnvironmentMonitor）
// 读取目标进程 PEB 环境块, 检测:
//   PATH 劫持 (T1574.007) / 搜索顺序劫持 (T1574.008) /
//   代理劫持 (T1090.001) / TEMP 覆盖 / 编码混淆 (T1027)
// ======================================================================

//
// 环境分析结果（对齐 SS EM_SUSPICION + EMP_PROCESS_ENV_EXTENDED +
// SuspicionScore 的 agent 化扁平结构）
//
typedef struct _WKD_ENV_ANALYSIS {
    ULONG   Flags;              // WKD_ENV_FLAG_* 位图
    ULONG   SuspicionScore;     // 0-100（对齐 SS EmCalculateSuspicionScore）
    ULONG   PathEntryCount;     // PATH 条目数
    ULONG   EncodedValueCount;  // 编码值计数（Base64/Hex）
    ULONG   HighEntropyCount;   // 高熵值计数（Shannon 近似 > 4.5）
    ULONG   VariableCount;      // 环境变量总数
} WKD_ENV_ANALYSIS, *PWKD_ENV_ANALYSIS;

#define WKD_ENV_FLAG_NONE           0x00000000
#define WKD_ENV_FLAG_MODIFIED_PATH  0x00000001   // PATH 含可写/用户目录 (T1574.007)
#define WKD_ENV_FLAG_SEARCH_ORDER   0x00000002   // PATH 含可疑条目: UNC/相对路径 (T1574.008)
#define WKD_ENV_FLAG_PROXY          0x00000004   // 代理指向 localhost/可疑端口 (T1090.001)
#define WKD_ENV_FLAG_TEMP_OVERRIDE  0x00000008   // TEMP/TMP 指向非系统目录
#define WKD_ENV_FLAG_HIDDEN_VAR     0x00000010   // 变量数 > 500 (注入嫌疑)
#define WKD_ENV_FLAG_ENCODED        0x00000020   // 编码/高熵环境值 (T1027)

//
// 进程环境分析（对齐 SS EmCaptureEnvironment + EmAnalyzeEnvironment）
// 返回 TRUE = 分析执行（Result 有效）; FALSE = 无法读取（进程退出/无权限）。
// ★ 接线: 当前无调用者, 预留 IoaObserve 阶段 4.8 接入（仿 g_IoaCmdLineAnalyzerEnabled）。
//
BOOL
IpeAnalyzeEnvironment(
    _In_  ULONG               ProcessId,
    _Out_ PWKD_ENV_ANALYSIS   Result
    );

//
// 按名查询进程环境变量（对齐 SS EmGetVariable）
// 返回 TRUE = 找到（Value 填充, 截断至 ValueSize-1）; FALSE = 未找到/无法读取。
// ★ 死代码: 当前无调用者（SS 中供外部子系统查询特定变量, agent 无需求,
//   供后续按需读取 PATH/PATHEXT 等）。
//
BOOL
IpeGetEnvironmentVariable(
    _In_  ULONG   ProcessId,
    _In_  PCWSTR  Name,
    _Out_writes_(ValueSize) PWCHAR Value,
    _In_  ULONG   ValueSize
    );
