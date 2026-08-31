/**************************************************/
/*  WkDefender — 威胁评分引擎                       */
/*                                                   */
/*  双链指示记录模型（进程对维度，2026-07 迁移）:     */
/*    IOC 链（批次链，结算后累加进 IocScore 清空）   */
/*    + IOA 链（60s 窗口）+ EWMA 平滑               */
/*  两阶段评分: 内层按来源算分, 外层按来源权重融合    */
/*  + 对数归一标准化 [0,100] /                       */
/*  Verdict: Clean→Suspicious→Malicious→Blocked      */
/*                                                   */
/*  注意：TsContext 生命周期由 AE_PROCESS_PAIR 管理，*/
/*  评分引擎只提供算法和配置，不主动管理上下文。      */
/*  提交只插入记录（AeReportIndicator 系列入口），    */
/*  结算统一在 TsSettleScores（AeOrchestratorDispatch 尾部）。*/
/**************************************************/

#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>
#include "../Common/Constants.h"           /* AE_THREAT_SEVERITY 枚举 */

//=============================================================================
// 前向声明 — 完整定义见 ProcessMonitor.h / ProcessPairContext.h
//=============================================================================

struct _WKD_PROCESS;
typedef struct _WKD_PROCESS *PWKD_PROCESS;
struct _AE_PROCESS_PAIR;
typedef struct _AE_PROCESS_PAIR *PAE_PROCESS_PAIR;

//=============================================================================
// 池标签
//=============================================================================

#define TS_POOL_TAG_ENGINE      'sTsW'      /* WsTs — WkD ThreatScoring Engine */
#define TS_POOL_TAG_CONTEXT     'cTsW'      /* WsTc — WkD ThreatScoring Context */
#define TS_POOL_TAG_RECORD      'rTsW'      /* WsTr — WkD ThreatScoring Record */
#define TS_POOL_TAG_PATH        'pTsW'      /* WsTp — WkD ThreatScoring Path */

//=============================================================================
// 配置常量
//=============================================================================

#define TS_MAX_FACTORS              32
#define TS_HASH_BUCKET_COUNT        256
#define TS_MAX_SCORES_TRACKED       65536
#define TS_MAX_FACTOR_NAME_LEN      64
#define TS_MAX_REASON_LEN           128
#define TS_MAX_VERDICT_REASON_LEN   256
#define TS_MAX_PROCESS_PATH_CHARS   520

//
// 威胁等级合法性判断
// Severity 合法范围为 [AeThreatSeverityLow(1), AeThreatSeverityCritical(4)]；
// AeThreatSeverityNone(0) 表示无威胁贡献、不落记录，提交接口拒绝。
//
#define VALID_SEVERITY(Severity) \
    ((Severity) >= AeThreatSeverityLow && \
     (Severity) <= AeThreatSeverityCritical)

//=============================================================================
// 枚举
//=============================================================================

typedef enum _TS_SOURCE {
    TsSourceUnknow = 0,
    TsSourceStatic,         // PE 分析结果
    TsSourceBehavioral,     // 运行时行为（IOA）
    TsSourceReputation,     // 已知信誉
    TsSourceContext,        // 环境因素
    TsSourceIOC,            // IOC 命中
    TsSourceMITRE,          // MITRE 技术匹配
    TsSourceAnomaly,        // 异常检测
    TsSourceUserDefined,
    TsSourceMaxValue        // 哨兵值（用于验证）
} TS_SOURCE;

//
// 检测指标类型枚举
// 分析引擎通过 AeReportIndicator 系列提交记录时传入此类型；
// 得分 = Severity × 预配置固定权重（g_TsIocWeights/g_TsIoaWeights）。
// 按子系统分组（高 8 位 = 组 ID，低 8 位 = 组内序号）。
//
typedef enum _TS_INDICATOR_TYPE {
    TsIndicator_Unknow                      = 0,

    // ── 进程创建与分析（0x01xx） ──
    TsIndicator_Process_Elevated            = 0x0101,
    TsIndicator_Process_SeDebugPrivilege    = 0x0102,
    TsIndicator_Process_SeImpersonatePrivilege = 0x0103,
    TsIndicator_Process_SeTcbPrivilege      = 0x0104,
    TsIndicator_Process_CrossSession        = 0x0105,
    TsIndicator_Process_PpidSpoofing        = 0x0106,
    TsIndicator_Process_DeepPpidSpoofing    = 0x0107,
    TsIndicator_Process_SuspiciousAncestry  = 0x0108,
    TsIndicator_Process_MissingMitigations  = 0x0109,

    // ── 命令行检测（0x02xx） ──
    TsIndicator_CmdLine_LOLBin              = 0x0201,
    TsIndicator_CmdLine_EncodedCommand      = 0x0202,
    TsIndicator_CmdLine_SuspiciousPowerShell = 0x0203,
    TsIndicator_CmdLine_DownloadCradle      = 0x0204,
    TsIndicator_CmdLine_ReflectionLoad      = 0x0205,
    TsIndicator_CmdLine_ClipboardAbuse      = 0x0206,
    TsIndicator_CmdLine_Obfuscation         = 0x0207,  // 混淆检测（^/%/` 计数，迁移自 SS CommandLineParser）
    TsIndicator_CmdLine_HiddenWindow        = 0x0208,  // 隐藏窗口执行（迁移自 SS CommandLineParser）
    TsIndicator_CmdLine_RemoteExecution     = 0x0209,  // 远程执行（迁移自 SS CommandLineParser）
    TsIndicator_CmdLine_SuspiciousPath      = 0x020A,  // 可疑路径执行（迁移自 SS CommandLineParser）
    TsIndicator_CmdLine_ScriptExecution     = 0x020B,  // 脚本文件执行（迁移自 SS CommandLineParser）

    // ── 注入检测（0x03xx） ──
    TsIndicator_Injection_RemoteThread      = 0x0301,
    TsIndicator_Injection_CrossProcessThread = 0x0302,
    TsIndicator_Injection_ProcessHollowing  = 0x0303,
    TsIndicator_Injection_ThreadShellcode   = 0x0304,
    TsIndicator_Injection_ROPChain          = 0x0305,
    TsIndicator_Injection_HeapSpray         = 0x0306,
    TsIndicator_Injection_ReflectiveDll     = 0x0307,

    // ── 持久化（0x04xx） ──
    TsIndicator_Persistence_RegistryRunKey  = 0x0401,
    TsIndicator_Persistence_MultiTechnique  = 0x0402,
    TsIndicator_Persistence_RansomwarePrep  = 0x0403,
    TsIndicator_Persistence_ServiceInstall  = 0x0404,

    // ── 防御绕过（0x05xx） ──
    TsIndicator_Defense_DisableDefender     = 0x0501,
    TsIndicator_Defense_AppControlBlock     = 0x0502,
    TsIndicator_Defense_StackTampering      = 0x0503,

    // ── 网络（0x06xx） ──
    TsIndicator_Network_Beaconing           = 0x0601,
    TsIndicator_Network_DataExfiltration    = 0x0602,
    TsIndicator_Network_C2Communication     = 0x0603,
    TsIndicator_Network_PortScanning        = 0x0604,
    TsIndicator_Network_KnownC2IOC          = 0x0605,
    TsIndicator_Network_MaliciousJA3        = 0x0606,
    TsIndicator_Network_DGA                 = 0x0607,
    TsIndicator_Network_DnsTunnel           = 0x0608,
    TsIndicator_Network_SuspiciousHTTP      = 0x0609,
    TsIndicator_Network_NamedPipeC2         = 0x060A,  // 命名管道名命中已知 C2 模式（NamedPipeMonitor 迁移 2026-08，T1572）
    TsIndicator_Network_NamedPipeSpoof      = 0x060B,  // 系统管道名被非预期进程创建（T1036.004，NamedPipeMonitor 迁移 2026-08）
    TsIndicator_Network_NamedPipeHighEntropy = 0x060C, // 高熵随机管道名（T1573.001，NamedPipeMonitor 迁移 2026-08）

    // ── 信誉（0x07xx） ──
    TsIndicator_Reputation_ValidSignature   = 0x0701,
    TsIndicator_Reputation_UnsignedBinary   = 0x0702,
    TsIndicator_Reputation_UnsignedNoDEP    = 0x0703,
    TsIndicator_Reputation_SoftwarePacking  = 0x0704,

    // ── 句柄/对象（0x08xx） ──
    TsIndicator_Handle_LsassAccess          = 0x0801,
    TsIndicator_Handle_ProcessTermination   = 0x0802,
    TsIndicator_Handle_ThreadHijack         = 0x0803,

    // ── 线程（0x09xx） ──
    TsIndicator_Thread_ShellcodeStart       = 0x0901,
    TsIndicator_Thread_SuspiciousStart      = 0x0902,

    // ── 映像加载（0x0Axx） ──
    TsIndicator_Image_SuspiciousLoad        = 0x0A01,  // 伞指标：可疑镜像加载（AppControl/agent 侧使用，L1 不再提交）
    TsIndicator_Image_HollowingHeuristic    = 0x0A02,  // W^X 代码区段（SelfModifying，L1 WX 检测复用）
    TsIndicator_Image_SuspiciousPath        = 0x0A03,  // 可疑路径（Temp/Downloads/ProgramData 等）
    TsIndicator_Image_MasqueradingName      = 0x0A04,  // 伪装系统 DLL 名（精确匹配）
    TsIndicator_Image_TypoSquatting         = 0x0A05,  // 系统 DLL 名 typosquatting（1 字符/±1 长度差异）
    TsIndicator_Image_NetworkPath           = 0x0A06,  // UNC 网络路径加载
    TsIndicator_Image_DoubleExtension       = 0x0A07,  // 双扩展名 .pdf.dll
    TsIndicator_Image_PhantomDllUnbacked    = 0x0A08,  // 无背衬内存映射（反射加载信号）
    TsIndicator_Image_EntrypointOutsideCode = 0x0A09,  // EP 不在代码段（镂空信号）
    TsIndicator_Image_NoExports             = 0x0A0A,  // DLL 无导出表

    // ── 注册表（0x0Bxx） ──
    TsIndicator_Registry_SuspiciousMod      = 0x0B01,

    // ── WSL/容器逃逸（0x0Cxx，迁移自 SS WSLMonitor 2026-08） ──
    TsIndicator_Wsl_EscapeToHost            = 0x0C01,  // WSL 父 spawn 原生进程（T1611，对齐 SS 80 分）
    TsIndicator_Wsl_CredentialAccess        = 0x0C02,  // WSL 读宿主凭据文件（T1003，对齐 SS 85 分）
    TsIndicator_Wsl_DriverAccess            = 0x0C03,  // WSL 访问 \drivers\（T1611，对齐 SS 60 分）
    TsIndicator_Wsl_System32Access          = 0x0C04,  // WSL 访问 \System32\（T1611，SS 无分仅记录）

    // ── IOA 行为类型（0x0Dxx，对应 WKD_ASSEMBLY_TYPE，34 项） ──
    TsIndicator_Ioa_SyscallDetected        = 0x0D01,  // WkdMessage_SyscallDetected        (0x1000)
    TsIndicator_Ioa_OpenProcess            = 0x0D02,  // WkdMessage_SyscallOpenProcess      (0x1001)
    TsIndicator_Ioa_AllocateMemory         = 0x0D03,  // WkdMessage_SyscallAllocateMemory   (0x1002)
    TsIndicator_Ioa_WriteMemory            = 0x0D04,  // WkdMessage_SyscallWriteMemory      (0x1003)
    TsIndicator_Ioa_ReadMemory             = 0x0D05,  // WkdMessage_SyscallReadMemory       (0x1004)
    TsIndicator_Ioa_CreateRemoteThread     = 0x0D06,  // WkdMessage_SyscallCreateThread     (0x1005)
    TsIndicator_Ioa_MapSection             = 0x0D07,  // WkdMessage_SyscallMapSection       (0x1006)
    TsIndicator_Ioa_QueueApc               = 0x0D08,  // WkdMessage_SyscallQueueApc         (0x1007)
    TsIndicator_Ioa_SetContextThread       = 0x0D09,  // WkdMessage_SyscallSetContextThread (0x1008)
    TsIndicator_Ioa_ProtectMemory          = 0x0D0A,  // WkdMessage_SyscallProtectMemory    (0x1009)
    TsIndicator_Ioa_MemoryAllocate         = 0x0D0B,  // WkdMessage_MemoryAllocate          (0x1101)
    TsIndicator_Ioa_MemoryFree             = 0x0D0C,  // WkdMessage_MemoryFree              (0x1102)
    TsIndicator_Ioa_MemoryProtect          = 0x0D0D,  // WkdMessage_MemoryProtect           (0x1103)
    TsIndicator_Ioa_RegistrySetValue       = 0x0D0E,  // WkdMessage_RegistrySetValue        (0x1201)
    TsIndicator_Ioa_RegistryDeleteValue    = 0x0D0F,  // WkdMessage_RegistryDeleteValue     (0x1202)
    TsIndicator_Ioa_FileCreate             = 0x0D10,  // WkdMessage_FileCreate              (0x1301)
    TsIndicator_Ioa_FileWrite              = 0x0D11,  // WkdMessage_FileWrite               (0x1302)
    TsIndicator_Ioa_ProcessObjectAccess    = 0x0D12,  // WkdMessage_ProcessObjectAccess     (0x1401)
    TsIndicator_Ioa_ThreadObjectAccess     = 0x0D13,  // WkdMessage_ThreadObjectAccess      (0x1402)
    TsIndicator_Ioa_CrossProcessMemoryAccess = 0x0D14,// WkdMessage_CrossProcessMemoryAccess(0x2001)
    TsIndicator_Ioa_CodeInjectionPattern   = 0x0D15,  // WkdMessage_CodeInjectionPattern    (0x2002)
    TsIndicator_Ioa_ProcessHollowingPattern = 0x0D16, // WkdMessage_ProcessHollowingPattern (0x2003)
    TsIndicator_Ioa_ApcInjectionPattern    = 0x0D17,  // WkdMessage_ApcInjectionPattern     (0x2004)
    TsIndicator_Ioa_ThreatScoreUpdated     = 0x0D18,  // WkdMessage_ThreatScoreUpdated      (0x2201)
    TsIndicator_Ioa_ThreatLevelChanged     = 0x0D19,  // WkdMessage_ThreatLevelChanged      (0x2202)
    TsIndicator_Ioa_ProcessCreated         = 0x0D1A,  // WkdMessage_ProcessCreated          (0x3001)
    TsIndicator_Ioa_ProcessExited          = 0x0D1B,  // WkdMessage_ProcessExited           (0x3002)
    TsIndicator_Ioa_ThreadCreated          = 0x0D1C,  // WkdMessage_ThreadCreated           (0x3003)
    TsIndicator_Ioa_ThreadExited           = 0x0D1D,  // WkdMessage_ThreadExited            (0x3004)
    TsIndicator_Ioa_ProcessSnapshot        = 0x0D1E,  // WkdMessage_ProcessSnapshot         (0x3008)
    TsIndicator_Ioa_HandleScan             = 0x0D1F,  // WkdMessage_HandleScan              (0x3009)
    TsIndicator_Ioa_HandleDuplicate        = 0x0D23,  // WkdMessage_HandleDuplicate         (0x1403, HandleTracker 迁移 2026-08, 死代码)
    TsIndicator_Ioa_FileRename             = 0x0D24,  // WkdMessage_FileRename              (0x1303, FBE 迁移 2026-08)
    TsIndicator_Ioa_FileDelete             = 0x0D25,  // WkdMessage_FileDelete              (0x1304, FBE 迁移 2026-08)
    TsIndicator_Ioa_SecurityEvent          = 0x0D20,  // WkdMessage_SecurityEvent           (0x4001)
    TsIndicator_Ioa_SystemStatus           = 0x0D21,  // WkdMessage_SystemStatus            (0x4002)
    TsIndicator_Ioa_Error                  = 0x0D22,  // WkdMessage_Error                   (0x4003)

    // ── 代码执行映射检测（0x0D26 起，PreAcquireSection 迁移 2026-08） ──
    TsIndicator_Ioa_SectionMapCrossProcess = 0x0D26,  // 跨进程区段映射（syscall 轨 0x1006，T1055.001/004/012）
    TsIndicator_Ioa_SectionMapExecutable   = 0x0D27,  // 可疑可执行映射（文件轨 0x1308，W+RX/可疑路径/ADS）
    TsIndicator_Ioa_SectionMapHollowing    = 0x0D28,  // 进程空心化映射模式（4 信号，T1055.012）
    TsIndicator_Ioa_SectionMapReflective   = 0x0D29,  // 反射加载映射（W+RX+可疑路径/Temp，T1620）
    TsIndicator_Ioa_SectionMapRapid        = 0x0D2A,  // 快速映射异常（>10/s）
    TsIndicator_Ioa_UnmapViewSection       = 0x0D2B,  // 跨进程 Unmap（镂空，syscall 轨 0x1010）

    // ── Section 创建检测（0x0D2C 起，SectionTracker 迁移 2026-08） ──
    // 权重对齐 SS SecpUpdateSuspicionScore（Transacted 300/Deleted 250/
    // NoBackingFile 180/ExecuteAnonymous 200/LargeAnonymous 80）:
    //   ≥250 → Critical / ≥180 → High / ≥80 → Medium
    TsIndicator_Ioa_SectionExecuteAnonymous = 0x0D2C, // 匿名可执行 Section（SS 200 → Critical，反射加载信号）
    TsIndicator_Ioa_SectionLargeAnonymous   = 0x0D2D, // 大匿名 Section >100MB（SS 80 → Medium，堆喷/异常大映射）
    TsIndicator_Ioa_SectionNoBackingFile    = 0x0D2E, // SEC_IMAGE 无背衬文件（SS 180 → High，镜像伪造）
    TsIndicator_Ioa_SectionTransacted       = 0x0D2F, // TxF 事务 Section（SS 300 → Critical，Doppelganging T1055.013）
    TsIndicator_Ioa_SectionDeleted          = 0x0D30, // DeletePending Section（SS 250 → Critical，Doppelganging 变体）

    // ── 文件行为（0x0Exx，FBE/PreSetInfo 迁移 2026-08） ──
    TsIndicator_File_Write                 = 0x0E01,  // 文件写入（勒索加密/破坏）
    TsIndicator_File_Rename                = 0x0E02,  // 文件重命名（勒索扩展名变更）
    TsIndicator_File_Delete                = 0x0E03,  // 文件删除（数据破坏）
    TsIndicator_File_Truncate              = 0x0E04,  // 文件截断（破坏 T1485）
    TsIndicator_File_HighEntropy           = 0x0E05,  // 高熵写入（加密检测 T1486）
    TsIndicator_File_RansomNote            = 0x0E06,  // 勒索信（T1486）
    TsIndicator_File_MassModify            = 0x0E07,  // 大量文件修改（勒索行为）
    TsIndicator_File_ShadowDelete          = 0x0E08,  // 卷影副本删除（T1490，对齐 WkdMessage_FileShadowCopyDelete 0x1306，已接线 FspPreSetInformation）
    TsIndicator_File_HardLink              = 0x0E09,  // 凭据硬链接（T1003.003，PreSetInfo 迁移 2026-08，对齐 FileLinkInformation，已接线 FspPreSetInformation）
    TsIndicator_File_AttributeChange       = 0x0E0A,  // 属性/时间戳/短名变更（T1070.006/T1564.001，PreSetInfo 迁移 2026-08）
    TsIndicator_File_DataDestruction       = 0x0E0B,  // 数据销毁（大量删除 T1485，PreSetInfo 迁移 2026-08，死代码：聚合评分未接入）

    TsIndicator_MaxValue                    // 哨兵值（用于验证）

} TS_INDICATOR_TYPE;

typedef enum _TS_VERDICT {
    TsVerdict_Unknown = 0,
    TsVerdict_Clean,
    TsVerdict_Suspicious,
    TsVerdict_Malicious,
    TsVerdict_Blocked,                  // 超过拦截阈值 — 已采取动作
} TS_VERDICT, * PTS_VERDICT;

//=============================================================================
// 结构体 — 公开
//=============================================================================

//
// 单条评分因子（公开视图）
//
typedef struct _TS_SCORE_FACTOR {
    TS_SOURCE Type;
    CHAR FactorName[TS_MAX_FACTOR_NAME_LEN];
    LONG Score;                         // 可为负（信任）或正（威胁）
    LONG Weight;                        // 权重乘数
    CHAR Reason[TS_MAX_REASON_LEN];
} TS_SCORE_FACTOR, *PTS_SCORE_FACTOR;

//
// 完整威胁评分结果（返回给调用者）
//
typedef struct _TS_THREAT_SCORE {
    HANDLE ProcessId;
    LARGE_INTEGER ProcessCreateTime;    // PID 复用检测
    UNICODE_STRING ProcessPath;         // 调用者必须通过 TsFreeScore 释放

    TS_SCORE_FACTOR Factors[TS_MAX_FACTORS];
    ULONG FactorCount;

    LONG RawScore;                      // 加权因子和（已钳位）
    ULONG NormalizedScore;              // 0-100 归一化

    TS_VERDICT Verdict;
    CHAR VerdictReason[TS_MAX_VERDICT_REASON_LEN];

    ULONG SuspiciousThreshold;
    ULONG MaliciousThreshold;
    ULONG BlockedThreshold;

    LARGE_INTEGER CalculationTime;
} TS_THREAT_SCORE, *PTS_THREAT_SCORE;

//
// 检测指标配置表项
// 每个 TS_INDICATOR_TYPE 对应一条配置，由引擎内部静态定义。
// 注意：得分/权重不在此表定义——记录贡献 = Severity × W(Indicator)，
// 权重常量表按 TS_INDICATOR_TYPE 下标索引（见 ThreatScoring.c）。
//
typedef struct _TS_INDICATOR_CONFIG {
    TS_INDICATOR_TYPE   Indicator;      // 指标枚举值（作为查表键）
    PCSTR               IndicatorName;      // 人类可读的唯一标识（日志用）
    PCSTR               FactorName;         // 因子名称（写入诊断输出）
    PCSTR               Reason;             // 默认原因描述
    PCSTR               MitreTechniqueId;   // MITRE ATT&CK 技术 ID（可 NULL）
} TS_INDICATOR_CONFIG, *PTS_INDICATOR_CONFIG;

//
// 阈值配置
//
typedef struct _TS_THRESHOLD_CONFIG {
    ULONG SuspiciousThreshold;          // 0-100, 默认 50
    ULONG MaliciousThreshold;           // 0-100, 默认 80
    ULONG BlockedThreshold;             // 0-100, 默认 95
} TS_THRESHOLD_CONFIG, *PTS_THRESHOLD_CONFIG;

//
// 不透明引擎句柄
//
typedef struct _TS_ENGINE *PTS_ENGINE;

//
// 全局评分引擎实例（供调用者使用）
//
extern PTS_ENGINE WkdTsEngine;

//=============================================================================
// 公开 API — 初始化/清理
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsInitialize(
    _Outptr_ PTS_ENGINE* Engine
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
TsShutdown(
    _Inout_ PTS_ENGINE Engine
    );

//=============================================================================
// 公开 API — 配置
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsSetThresholds(
    _In_ PTS_ENGINE Engine,
    _In_ ULONG SuspiciousThreshold,
    _In_ ULONG MaliciousThreshold,
    _In_ ULONG BlockedThreshold
    );

//=============================================================================
// 公开 API — TsContext 生命周期（由 ProcessPairContext 调用）
//=============================================================================

//
// TsAllocateProcessPairContext — 为进程对创建/获取 TsContext
// 由 TsReportIndicatorLocked / TsSettleScores 入口惰性确保（创建时全部分配，
// 首次提交时若缺失则分配）。纯分配+初始化，不进入任何引擎链表。
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsAllocateProcessPairContext(
    _In_opt_ PTS_ENGINE Engine,
    _Inout_ PAE_PROCESS_PAIR Pair
    );

//
// TsDestroyProcessPairContext — 销毁进程对的 TsContext
// 由 PsDereferenceWkdProcessPair refcount==0 分支调用。
// 释放双链全部记录 + 释放 TsContext + 置 NULL。
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
TsDestroyProcessPairContext(
    _In_opt_ PTS_ENGINE Engine,
    _In_ PAE_PROCESS_PAIR Pair
    );

//=============================================================================
// 公开 API — 记录提交与结算
//=============================================================================

//
// 统一指示记录 — 分析引擎提交、评分系统持有的最小记录单元。
// 链内按时间升序排列（链头最旧，InsertTailList 保证）。
// 单条贡献 = Severity × TspGetIndicatorWeight(Indicator)。
// 提交只插入记录，零计算；得分在 TsSettleScores 结算时统一计算。
//
typedef struct _TS_INDICATOR_RECORD {
    LIST_ENTRY          Link;           // → TsContext.IocChain / IoaChain
    TS_SOURCE      Source;     // TsSourceIOC / TsSourceBehavioral
    TS_INDICATOR_TYPE   Indicator;      // 0x01xx-0x0Bxx(IOC) / 0x0Dxx(IOA)
    AE_THREAT_SEVERITY Severity;       // AE_THREAT_SEVERITY 1-4（0 不落记录）
    LARGE_INTEGER       Timestamp;      // KeQuerySystemTime
} TS_INDICATOR_RECORD, *PTS_INDICATOR_RECORD;

//
// 追加指示记录 — 评分系统内部提交接口（仅被 AeReportIndicator 系列调用）。
// 按 Source 选择 IocChain（批次链，结算后清空）/ IoaChain（60s 窗口）尾插；
// 权重查表为 0 时返回 STATUS_NOT_SUPPORTED 且不落记录。
//
_IRQL_requires_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
TsReportIndicatorLocked(
    _In_opt_ PTS_ENGINE Engine,
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ TS_SOURCE Source,
    _In_ TS_INDICATOR_TYPE Indicator,
    _In_ UCHAR Severity
    );

//
// 结算威胁评分 — 统一结算入口（进程对维度）。
// IOC 内层 drain 批次链累加进 IocScore（持久累计，只增不减）；
// IOA 内层 60s 窗口 + EWMA 平滑；
// 外层按来源权重融合后对数归一标准化到 [0,100]。
// 由 AeOrchestratorDispatch 事件尾部调用；查询 API 在缓存失效时内部调用。
// Pair->TsContext 为 NULL（无记录 pair）时静默返回成功。
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsSettleScores(
    _In_opt_ PTS_ENGINE Engine,
    _In_ PAE_PROCESS_PAIR Pair
    );

//
// 查配置表 — 根据 TS_INDICATOR_TYPE 查找对应配置项（诊断元数据）
//
_IRQL_requires_max_(APC_LEVEL)
const TS_INDICATOR_CONFIG*
TsLookupIndicatorConfig(
    _In_ TS_INDICATOR_TYPE Type
    );

//=============================================================================
// 公开 API — 评分查询
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsCalculateScore(
    _In_opt_ PTS_ENGINE Engine,
    _In_ PAE_PROCESS_PAIR Pair,
    _Outptr_ PTS_THREAT_SCORE* Score
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsCalculateScoreInPlace(
    _In_ PTS_ENGINE Engine,
    _In_ PAE_PROCESS_PAIR Pair,
    _Out_ PTS_THREAT_SCORE Score
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsGetVerdict(
    _In_opt_ PTS_ENGINE Engine,
    _In_ PAE_PROCESS_PAIR Pair,
    _Out_ PTS_VERDICT Verdict
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TsGetScore(
    _In_ PTS_ENGINE Engine,
    _In_ PAE_PROCESS_PAIR Pair,
    _Out_ PTS_THREAT_SCORE* Score
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
TsFreeScore(
    _In_opt_ PTS_THREAT_SCORE Score
    );

//=============================================================================
// 公开 API — 维护
//=============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TsRunMaintenancePass(
    _In_ PTS_ENGINE Engine
    );
