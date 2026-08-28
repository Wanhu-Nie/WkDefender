/**************************************************/
/*  WkDefender — 威胁评分引擎实现                     */
/*                                                   */
/*  双链指示记录模型（2026-07 重构）:                 */
/*    - IOC 链: 持久、不去重、进程生命周期            */
/*    - IOA 链: 60s 时间窗口、结算时惰性摘除过期      */
/*  两阶段评分:                                       */
/*    内层: IOC 线性累加 / IOA 窗口求和 + EWMA 平滑   */
/*    外层: 按来源权重融合 + 对数归一标准化 [0,100]   */
/*                                                   */
/*  锁约定: TsContext->Lock 恒为叶锁 — 任何路径都不在 */
/*  持有它时获取其他锁。销毁竞态由 EX_RUNDOWN_REF 保护。*/
/*                                                   */
/*  注意：TsContext 生命周期由 WKD_PROCESS 管理，     */
/*  引擎只提供算法/配置/统计，不维护哈希表。          */
/**************************************************/

#include "ThreatScoring.h"
#include "../Process/ProcessPairContext.h"     /* PAE_PROCESS_PAIR 完整定义 */
#include "../Process/ProcessMonitor.h"
#include "../Common/Utils.h"

//
// 全局评分引擎实例
//
PTS_ENGINE WkdTsEngine = NULL;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, TsInitialize)
#pragma alloc_text(PAGE, TsShutdown)
#pragma alloc_text(PAGE, TsSetThresholds)
#pragma alloc_text(PAGE, TsAllocateProcessPairContext)
#pragma alloc_text(PAGE, TsFreeProcessPairContext)
#pragma alloc_text(PAGE, TsReportIndicatorLocked)
#pragma alloc_text(PAGE, TsSettleScores)
#pragma alloc_text(PAGE, TsCalculateScore)
#pragma alloc_text(PAGE, TsCalculateScoreInPlace)
#pragma alloc_text(PAGE, TsGetVerdict)
#pragma alloc_text(PAGE, TsGetScore)
#pragma alloc_text(PAGE, TsFreeScore)
#pragma alloc_text(PAGE, TsRunMaintenancePass)
#endif

//=============================================================================
// 配置常量
//=============================================================================

#define TS_DEFAULT_SUSPICIOUS_THRESHOLD     50
#define TS_DEFAULT_MALICIOUS_THRESHOLD      80
#define TS_DEFAULT_BLOCKED_THRESHOLD        95

/* IOA 时间窗口（秒）— 私有窗口，与 IOA 行为节点过期无关 */
#define TS_IOA_WINDOW_SEC       60
#define TS_IOA_WINDOW_NS        ((LONGLONG)TS_IOA_WINDOW_SEC * 10000000LL)

/* α 动态参数: α = clamp(T/(T+Δt), 0.3, 0.7)，T 与窗口对齐 */
#define TS_ALPHA_TIME_CONST_SEC TS_IOA_WINDOW_SEC
#define TS_ALPHA_MIN_PERCENT    30
#define TS_ALPHA_MAX_PERCENT    70

/* IOA 链上限（防膨胀；超限 FIFO 丢最旧）。IOC 批次链结算即清空，无上限。 */
#define TS_MAX_IOA_RECORDS      2048

/* 外层融合权重（来源维度） */
#define TS_FUSION_W_IOC         8
#define TS_FUSION_W_IOA         5

/* 对数归一 LUT: final = 100 × log(1+raw) / log(101)，raw ∈ [0,100] */
#define TS_NORM_LUT_ENTRIES     101

//=============================================================================
// IOC 权重常量（按 Indicator 类型粒度，命名 Xxx_IOC_xxx）
// 量纲 1-25: 单条 Critical(4)×20=80 raw → final≈93（一条即达 Malicious）
//=============================================================================

/* 进程创建与分析（0x01xx） */
#define W_IOC_PROCESS_ELEVATED              4
#define W_IOC_PROCESS_SE_DEBUG              6
#define W_IOC_PROCESS_SE_IMPERSONATE        5
#define W_IOC_PROCESS_SE_TCB                8
#define W_IOC_PROCESS_CROSS_SESSION         6
#define W_IOC_PROCESS_PPID_SPOOFING        12
#define W_IOC_PROCESS_DEEP_PPID_SPOOFING   15
#define W_IOC_PROCESS_SUSPICIOUS_ANCESTRY  10
#define W_IOC_PROCESS_MISSING_MITIGATIONS   4

/* 命令行（0x02xx） */
#define W_IOC_CMDLINE_LOLBIN                6
#define W_IOC_CMDLINE_ENCODED_COMMAND      10
#define W_IOC_CMDLINE_SUSPICIOUS_POWERSHELL 8
#define W_IOC_CMDLINE_DOWNLOAD_CRADLE       9
#define W_IOC_CMDLINE_REFLECTION_LOAD      10
#define W_IOC_CMDLINE_CLIPBOARD_ABUSE       8

/* 注入（0x03xx） */
#define W_IOC_INJECTION_REMOTE_THREAD      15
#define W_IOC_INJECTION_CROSS_PROCESS_THREAD 18
#define W_IOC_INJECTION_PROCESS_HOLLOWING  18
#define W_IOC_INJECTION_THREAD_SHELLCODE   16
#define W_IOC_INJECTION_ROP_CHAIN          15
#define W_IOC_INJECTION_HEAP_SPRAY         14
#define W_IOC_INJECTION_REFLECTIVE_DLL     17

/* 持久化（0x04xx） */
#define W_IOC_PERSISTENCE_REGISTRY_RUNKEY  14
#define W_IOC_PERSISTENCE_MULTI_TECHNIQUE  17
#define W_IOC_PERSISTENCE_RANSOMWARE_PREP  19
#define W_IOC_PERSISTENCE_SERVICE_INSTALL  15

/* 防御绕过（0x05xx） */
#define W_IOC_DEFENSE_DISABLE_DEFENDER     16
#define W_IOC_DEFENSE_APP_CONTROL_BLOCK    15
#define W_IOC_DEFENSE_STACK_TAMPERING      20

/* 网络（0x06xx） */
#define W_IOC_NETWORK_BEACONING            15
#define W_IOC_NETWORK_DATA_EXFILTRATION    13
#define W_IOC_NETWORK_C2_COMMUNICATION     16
#define W_IOC_NETWORK_PORT_SCANNING        14
#define W_IOC_NETWORK_KNOWN_C2_IOC         18
#define W_IOC_NETWORK_MALICIOUS_JA3        17
#define W_IOC_NETWORK_DGA                  10
#define W_IOC_NETWORK_DNS_TUNNEL           12
#define W_IOC_NETWORK_SUSPICIOUS_HTTP       8
#define W_IOC_NETWORK_NAMED_PIPE_C2         16   /* NamedPipeMonitor 迁移 2026-08（对齐 C2Communication） */
#define W_IOC_NETWORK_NAMED_PIPE_SPOOF      18   /* 系统管道冒充，对齐 KnownC2IOC */
#define W_IOC_NETWORK_NAMED_PIPE_HIGH_ENTROPY 8  /* 高熵随机名，对齐 DGA */

/* 信誉（0x07xx）— ValidSignature 为负向（信任），权重 0 即不落记录 */
#define W_IOC_REPUTATION_VALID_SIGNATURE    0
#define W_IOC_REPUTATION_UNSIGNED_BINARY    3
#define W_IOC_REPUTATION_UNSIGNED_NO_DEP    6
#define W_IOC_REPUTATION_SOFTWARE_PACKING   8

/* 句柄/对象（0x08xx） */
#define W_IOC_HANDLE_LSASS_ACCESS          16
#define W_IOC_HANDLE_PROCESS_TERMINATION   12
#define W_IOC_HANDLE_THREAD_HIJACK         14

/* 线程（0x09xx） */
#define W_IOC_THREAD_SHELLCODE_START       17
#define W_IOC_THREAD_SUSPICIOUS_START      10

/* 映像加载（0x0Axx） */
#define W_IOC_IMAGE_SUSPICIOUS_LOAD        12
#define W_IOC_IMAGE_HOLLOWING_HEURISTIC    16
/* L1 检测细分（SS 分/3 换算，下限 4 上限 18，2026-08-08 镜像边界重构） */
#define W_IOC_IMAGE_SUSPICIOUS_PATH         6   /* SS +15 */
#define W_IOC_IMAGE_MASQUERADING           12   /* SS +40 */
#define W_IOC_IMAGE_TYPOSQUATTING           6   /* SS ~20 */
#define W_IOC_IMAGE_NETWORK_PATH            8   /* SS +25 */
#define W_IOC_IMAGE_DOUBLE_EXTENSION        8   /* SS +30 */
#define W_IOC_IMAGE_UNBACKED               16   /* SS +60 PhantomDll */
#define W_IOC_IMAGE_ENTRYPOINT_OUTSIDE     14   /* SS +50 ProcessHollow */
#define W_IOC_IMAGE_NO_EXPORTS              4   /* SS +15 */

/* 注册表（0x0Bxx） */
#define W_IOC_REGISTRY_SUSPICIOUS_MOD      10

//=============================================================================
// IOA 权重常量（按 Indicator 类型粒度，命名 Xxx_IOA_xxx）
//=============================================================================

#define W_IOA_SYSCALL_DETECTED              2
#define W_IOA_OPEN_PROCESS                  5
#define W_IOA_ALLOCATE_MEMORY               8
#define W_IOA_WRITE_MEMORY                 12
#define W_IOA_READ_MEMORY                   4
#define W_IOA_CREATE_REMOTE_THREAD         15
#define W_IOA_MAP_SECTION                   8
#define W_IOA_QUEUE_APC                    14
#define W_IOA_SET_CONTEXT_THREAD           13
#define W_IOA_PROTECT_MEMORY                9
#define W_IOA_MEMORY_ALLOCATE               6
#define W_IOA_MEMORY_FREE                   3
#define W_IOA_MEMORY_PROTECT                7
#define W_IOA_REGISTRY_SET_VALUE            8
#define W_IOA_REGISTRY_DELETE_VALUE         8
#define W_IOA_FILE_CREATE                   5
#define W_IOA_FILE_WRITE                    7
#define W_IOA_FILE_RENAME                   7   /* FBE 迁移 2026-08，对齐 FileWrite */
#define W_IOA_FILE_DELETE                   8   /* FBE 迁移 2026-08，删除权重略高 */
#define W_IOA_PROCESS_OBJECT_ACCESS         6
#define W_IOA_THREAD_OBJECT_ACCESS          6
#define W_IOA_CROSS_PROCESS_MEMORY_ACCESS  10
#define W_IOA_CODE_INJECTION_PATTERN       14
#define W_IOA_PROCESS_HOLLOWING_PATTERN    16
#define W_IOA_APC_INJECTION_PATTERN        14
#define W_IOA_THREAT_SCORE_UPDATED          2
#define W_IOA_THREAT_LEVEL_CHANGED          4
#define W_IOA_PROCESS_CREATED               6
#define W_IOA_PROCESS_EXITED                3
#define W_IOA_THREAD_CREATED                4
#define W_IOA_THREAD_EXITED                 2
#define W_IOA_PROCESS_SNAPSHOT              2
#define W_IOA_HANDLE_SCAN                   3
#define W_IOA_SECURITY_EVENT                8
#define W_IOA_SYSTEM_STATUS                 1
#define W_IOA_ERROR                         1

/* 代码执行映射检测（0x0D26-0x0D2B，PreAcquireSection 迁移 2026-08。
 * 补登记：原 section 组指示器进入枚举+严重度表但未登记权重，评分链路惰性（权重 0
 * → TspGetIndicatorWeight 返回 0 → 不落记录）。权重按严重度映射量级对齐既有
 * 行为类权重（HOLLOWING=16/APC=14）。 */
#define W_IOA_SECTION_MAP_CROSS_PROCESS    16
#define W_IOA_SECTION_MAP_EXECUTABLE       10
#define W_IOA_SECTION_MAP_HOLLOWING        18
#define W_IOA_SECTION_MAP_REFLECTIVE       18
#define W_IOA_SECTION_MAP_RAPID             8
#define W_IOA_UNMAP_VIEW_SECTION           14

/* Section 创建检测（0x0D2C 起，SectionTracker 迁移 2026-08）。
 * 权重按 SS SecpUpdateSuspicionScore 权重映射：Transacted 300/Deleted 250/
 * ExecuteAnonymous 200/NoBackingFile 180/LargeAnonymous 80 → 归一化到
 * Critical(20-22)/High(14)/Medium(8)。 */
#define W_IOA_SECTION_EXECUTE_ANONYMOUS    20
#define W_IOA_SECTION_LARGE_ANONYMOUS       8
#define W_IOA_SECTION_NO_BACKING_FILE      14
#define W_IOA_SECTION_TRANSACTED           22
#define W_IOA_SECTION_DELETED              20

//=============================================================================
// 权重查表 — 设计化初始化静态数组，下标即 TS_INDICATOR_TYPE 枚举值
//=============================================================================

static const ULONG g_TsIocWeights[TsIndicator_MaxValue] = {
    [TsIndicator_Process_Elevated]          = W_IOC_PROCESS_ELEVATED,
    [TsIndicator_Process_SeDebugPrivilege]  = W_IOC_PROCESS_SE_DEBUG,
    [TsIndicator_Process_SeImpersonatePrivilege] = W_IOC_PROCESS_SE_IMPERSONATE,
    [TsIndicator_Process_SeTcbPrivilege]    = W_IOC_PROCESS_SE_TCB,
    [TsIndicator_Process_CrossSession]      = W_IOC_PROCESS_CROSS_SESSION,
    [TsIndicator_Process_PpidSpoofing]      = W_IOC_PROCESS_PPID_SPOOFING,
    [TsIndicator_Process_DeepPpidSpoofing]  = W_IOC_PROCESS_DEEP_PPID_SPOOFING,
    [TsIndicator_Process_SuspiciousAncestry]= W_IOC_PROCESS_SUSPICIOUS_ANCESTRY,
    [TsIndicator_Process_MissingMitigations]= W_IOC_PROCESS_MISSING_MITIGATIONS,

    [TsIndicator_CmdLine_LOLBin]            = W_IOC_CMDLINE_LOLBIN,
    [TsIndicator_CmdLine_EncodedCommand]    = W_IOC_CMDLINE_ENCODED_COMMAND,
    [TsIndicator_CmdLine_SuspiciousPowerShell] = W_IOC_CMDLINE_SUSPICIOUS_POWERSHELL,
    [TsIndicator_CmdLine_DownloadCradle]    = W_IOC_CMDLINE_DOWNLOAD_CRADLE,
    [TsIndicator_CmdLine_ReflectionLoad]    = W_IOC_CMDLINE_REFLECTION_LOAD,
    [TsIndicator_CmdLine_ClipboardAbuse]    = W_IOC_CMDLINE_CLIPBOARD_ABUSE,

    [TsIndicator_Injection_RemoteThread]    = W_IOC_INJECTION_REMOTE_THREAD,
    [TsIndicator_Injection_CrossProcessThread] = W_IOC_INJECTION_CROSS_PROCESS_THREAD,
    [TsIndicator_Injection_ProcessHollowing]= W_IOC_INJECTION_PROCESS_HOLLOWING,
    [TsIndicator_Injection_ThreadShellcode] = W_IOC_INJECTION_THREAD_SHELLCODE,
    [TsIndicator_Injection_ROPChain]        = W_IOC_INJECTION_ROP_CHAIN,
    [TsIndicator_Injection_HeapSpray]       = W_IOC_INJECTION_HEAP_SPRAY,
    [TsIndicator_Injection_ReflectiveDll]   = W_IOC_INJECTION_REFLECTIVE_DLL,

    [TsIndicator_Persistence_RegistryRunKey]= W_IOC_PERSISTENCE_REGISTRY_RUNKEY,
    [TsIndicator_Persistence_MultiTechnique]= W_IOC_PERSISTENCE_MULTI_TECHNIQUE,
    [TsIndicator_Persistence_RansomwarePrep]= W_IOC_PERSISTENCE_RANSOMWARE_PREP,
    [TsIndicator_Persistence_ServiceInstall]= W_IOC_PERSISTENCE_SERVICE_INSTALL,

    [TsIndicator_Defense_DisableDefender]   = W_IOC_DEFENSE_DISABLE_DEFENDER,
    [TsIndicator_Defense_AppControlBlock]   = W_IOC_DEFENSE_APP_CONTROL_BLOCK,
    [TsIndicator_Defense_StackTampering]    = W_IOC_DEFENSE_STACK_TAMPERING,

    [TsIndicator_Network_Beaconing]         = W_IOC_NETWORK_BEACONING,
    [TsIndicator_Network_DataExfiltration]  = W_IOC_NETWORK_DATA_EXFILTRATION,
    [TsIndicator_Network_C2Communication]   = W_IOC_NETWORK_C2_COMMUNICATION,
    [TsIndicator_Network_PortScanning]      = W_IOC_NETWORK_PORT_SCANNING,
    [TsIndicator_Network_KnownC2IOC]        = W_IOC_NETWORK_KNOWN_C2_IOC,
    [TsIndicator_Network_MaliciousJA3]      = W_IOC_NETWORK_MALICIOUS_JA3,
    [TsIndicator_Network_DGA]               = W_IOC_NETWORK_DGA,
    [TsIndicator_Network_DnsTunnel]         = W_IOC_NETWORK_DNS_TUNNEL,
    [TsIndicator_Network_SuspiciousHTTP]    = W_IOC_NETWORK_SUSPICIOUS_HTTP,
    [TsIndicator_Network_NamedPipeC2]       = W_IOC_NETWORK_NAMED_PIPE_C2,
    [TsIndicator_Network_NamedPipeSpoof]    = W_IOC_NETWORK_NAMED_PIPE_SPOOF,
    [TsIndicator_Network_NamedPipeHighEntropy] = W_IOC_NETWORK_NAMED_PIPE_HIGH_ENTROPY,

    [TsIndicator_Reputation_ValidSignature] = W_IOC_REPUTATION_VALID_SIGNATURE,
    [TsIndicator_Reputation_UnsignedBinary] = W_IOC_REPUTATION_UNSIGNED_BINARY,
    [TsIndicator_Reputation_UnsignedNoDEP]  = W_IOC_REPUTATION_UNSIGNED_NO_DEP,
    [TsIndicator_Reputation_SoftwarePacking]= W_IOC_REPUTATION_SOFTWARE_PACKING,

    [TsIndicator_Handle_LsassAccess]        = W_IOC_HANDLE_LSASS_ACCESS,
    [TsIndicator_Handle_ProcessTermination] = W_IOC_HANDLE_PROCESS_TERMINATION,
    [TsIndicator_Handle_ThreadHijack]       = W_IOC_HANDLE_THREAD_HIJACK,

    [TsIndicator_Thread_ShellcodeStart]     = W_IOC_THREAD_SHELLCODE_START,
    [TsIndicator_Thread_SuspiciousStart]    = W_IOC_THREAD_SUSPICIOUS_START,

    [TsIndicator_Image_SuspiciousLoad]      = W_IOC_IMAGE_SUSPICIOUS_LOAD,
    [TsIndicator_Image_HollowingHeuristic]  = W_IOC_IMAGE_HOLLOWING_HEURISTIC,
    [TsIndicator_Image_SuspiciousPath]      = W_IOC_IMAGE_SUSPICIOUS_PATH,
    [TsIndicator_Image_MasqueradingName]    = W_IOC_IMAGE_MASQUERADING,
    [TsIndicator_Image_TypoSquatting]       = W_IOC_IMAGE_TYPOSQUATTING,
    [TsIndicator_Image_NetworkPath]         = W_IOC_IMAGE_NETWORK_PATH,
    [TsIndicator_Image_DoubleExtension]     = W_IOC_IMAGE_DOUBLE_EXTENSION,
    [TsIndicator_Image_PhantomDllUnbacked]  = W_IOC_IMAGE_UNBACKED,
    [TsIndicator_Image_EntrypointOutsideCode] = W_IOC_IMAGE_ENTRYPOINT_OUTSIDE,
    [TsIndicator_Image_NoExports]           = W_IOC_IMAGE_NO_EXPORTS,

    [TsIndicator_Registry_SuspiciousMod]    = W_IOC_REGISTRY_SUSPICIOUS_MOD,
};

static const ULONG g_TsIoaWeights[TsIndicator_MaxValue] = {
    [TsIndicator_Ioa_SyscallDetected]       = W_IOA_SYSCALL_DETECTED,
    [TsIndicator_Ioa_OpenProcess]           = W_IOA_OPEN_PROCESS,
    [TsIndicator_Ioa_AllocateMemory]        = W_IOA_ALLOCATE_MEMORY,
    [TsIndicator_Ioa_WriteMemory]           = W_IOA_WRITE_MEMORY,
    [TsIndicator_Ioa_ReadMemory]            = W_IOA_READ_MEMORY,
    [TsIndicator_Ioa_CreateRemoteThread]    = W_IOA_CREATE_REMOTE_THREAD,
    [TsIndicator_Ioa_MapSection]            = W_IOA_MAP_SECTION,
    [TsIndicator_Ioa_QueueApc]              = W_IOA_QUEUE_APC,
    [TsIndicator_Ioa_SetContextThread]      = W_IOA_SET_CONTEXT_THREAD,
    [TsIndicator_Ioa_ProtectMemory]         = W_IOA_PROTECT_MEMORY,
    [TsIndicator_Ioa_MemoryAllocate]        = W_IOA_MEMORY_ALLOCATE,
    [TsIndicator_Ioa_MemoryFree]            = W_IOA_MEMORY_FREE,
    [TsIndicator_Ioa_MemoryProtect]         = W_IOA_MEMORY_PROTECT,
    [TsIndicator_Ioa_RegistrySetValue]      = W_IOA_REGISTRY_SET_VALUE,
    [TsIndicator_Ioa_RegistryDeleteValue]   = W_IOA_REGISTRY_DELETE_VALUE,
    [TsIndicator_Ioa_FileCreate]            = W_IOA_FILE_CREATE,
    [TsIndicator_Ioa_FileWrite]             = W_IOA_FILE_WRITE,
    [TsIndicator_Ioa_FileRename]            = W_IOA_FILE_RENAME,
    [TsIndicator_Ioa_FileDelete]            = W_IOA_FILE_DELETE,
    [TsIndicator_Ioa_ProcessObjectAccess]   = W_IOA_PROCESS_OBJECT_ACCESS,
    [TsIndicator_Ioa_ThreadObjectAccess]    = W_IOA_THREAD_OBJECT_ACCESS,
    [TsIndicator_Ioa_CrossProcessMemoryAccess] = W_IOA_CROSS_PROCESS_MEMORY_ACCESS,
    [TsIndicator_Ioa_CodeInjectionPattern]  = W_IOA_CODE_INJECTION_PATTERN,
    [TsIndicator_Ioa_ProcessHollowingPattern] = W_IOA_PROCESS_HOLLOWING_PATTERN,
    [TsIndicator_Ioa_ApcInjectionPattern]   = W_IOA_APC_INJECTION_PATTERN,
    [TsIndicator_Ioa_ThreatScoreUpdated]    = W_IOA_THREAT_SCORE_UPDATED,
    [TsIndicator_Ioa_ThreatLevelChanged]    = W_IOA_THREAT_LEVEL_CHANGED,
    [TsIndicator_Ioa_ProcessCreated]        = W_IOA_PROCESS_CREATED,
    [TsIndicator_Ioa_ProcessExited]         = W_IOA_PROCESS_EXITED,
    [TsIndicator_Ioa_ThreadCreated]         = W_IOA_THREAD_CREATED,
    [TsIndicator_Ioa_ThreadExited]          = W_IOA_THREAD_EXITED,
    [TsIndicator_Ioa_ProcessSnapshot]       = W_IOA_PROCESS_SNAPSHOT,
    [TsIndicator_Ioa_HandleScan]            = W_IOA_HANDLE_SCAN,
    [TsIndicator_Ioa_SecurityEvent]         = W_IOA_SECURITY_EVENT,
    [TsIndicator_Ioa_SystemStatus]          = W_IOA_SYSTEM_STATUS,
    [TsIndicator_Ioa_Error]                 = W_IOA_ERROR,

    /* 代码执行映射检测（0x0D26 起，PreAcquireSection 迁移 2026-08；
     * 补登记修权重 0 惰性缺口） */
    [TsIndicator_Ioa_SectionMapCrossProcess]= W_IOA_SECTION_MAP_CROSS_PROCESS,
    [TsIndicator_Ioa_SectionMapExecutable]  = W_IOA_SECTION_MAP_EXECUTABLE,
    [TsIndicator_Ioa_SectionMapHollowing]   = W_IOA_SECTION_MAP_HOLLOWING,
    [TsIndicator_Ioa_SectionMapReflective]  = W_IOA_SECTION_MAP_REFLECTIVE,
    [TsIndicator_Ioa_SectionMapRapid]       = W_IOA_SECTION_MAP_RAPID,
    [TsIndicator_Ioa_UnmapViewSection]      = W_IOA_UNMAP_VIEW_SECTION,

    /* Section 创建检测（0x0D2C 起，SectionTracker 迁移 2026-08） */
    [TsIndicator_Ioa_SectionExecuteAnonymous] = W_IOA_SECTION_EXECUTE_ANONYMOUS,
    [TsIndicator_Ioa_SectionLargeAnonymous]   = W_IOA_SECTION_LARGE_ANONYMOUS,
    [TsIndicator_Ioa_SectionNoBackingFile]    = W_IOA_SECTION_NO_BACKING_FILE,
    [TsIndicator_Ioa_SectionTransacted]       = W_IOA_SECTION_TRANSACTED,
    [TsIndicator_Ioa_SectionDeleted]          = W_IOA_SECTION_DELETED,
};

C_ASSERT(ARRAYSIZE(g_TsIocWeights) == TsIndicator_MaxValue);
C_ASSERT(ARRAYSIZE(g_TsIoaWeights) == TsIndicator_MaxValue);

//=============================================================================
// 检测指标元数据表（诊断用：FactorName/Reason/MitreTechniqueId）
// 得分/权重不在本表 — 见 g_TsIocWeights / g_TsIoaWeights
//=============================================================================

static const TS_INDICATOR_CONFIG g_TsIndicatorTable[] = {

    // ── 进程创建与分析（0x01xx） ───────────────────────────────────────────
    {TsIndicator_Process_Elevated,          "Process.Elevated",
         "ElevatedProcess",
         "Process running with elevated privileges",                NULL},
    {TsIndicator_Process_SeDebugPrivilege,  "Process.SeDebugPrivilege",
         "SeDebugPrivilege",
         "Process has SeDebugPrivilege (T1134)",                   "T1134"},
    {TsIndicator_Process_SeImpersonatePrivilege, "Process.SeImpersonatePrivilege",
         "SeImpersonatePrivilege",
         "Process has SeImpersonatePrivilege (T1134)",             "T1134"},
    {TsIndicator_Process_SeTcbPrivilege,    "Process.SeTcbPrivilege",
         "SeTcbPrivilege",
         "Process has SeTcbPrivilege",                             NULL},
    {TsIndicator_Process_CrossSession,      "Process.CrossSession",
         "CrossSessionCreation",
         "Process created across session boundary",                NULL},
    {TsIndicator_Process_PpidSpoofing,      "Process.PpidSpoofing",
         "T1134.004-PPID-Spoofing",
         "Parent PID spoofing detected (T1134.004)",               "T1134.004"},
    {TsIndicator_Process_DeepPpidSpoofing,  "Process.DeepPpidSpoofing",
         "T1134.004-DeepPPID",
         "PPID spoofing via creation-time ordering (T1134.004)",   "T1134.004"},
    {TsIndicator_Process_SuspiciousAncestry, "Process.SuspiciousAncestry",
         "ParentChain-SuspiciousAncestry",
         "Suspicious process ancestry chain detected",             NULL},
    {TsIndicator_Process_MissingMitigations, "Process.MissingMitigations",
         "MissingMitigations-ASLR-CFG",
         "Process lacks ASLR and CFG",                             NULL},

    // ── 命令行检测（0x02xx） ───────────────────────────────────────────────
    {TsIndicator_CmdLine_LOLBin,            "CmdLine.LOLBin",
         "T1218-LOLBin",
         "Living-off-the-land binary detected (T1218)",            "T1218"},
    {TsIndicator_CmdLine_EncodedCommand,    "CmdLine.EncodedCommand",
         "T1059-EncodedCommand",
         "Base64/encoded command line (T1059)",                    "T1059"},
    {TsIndicator_CmdLine_SuspiciousPowerShell, "CmdLine.SuspiciousPowerShell",
         "SuspiciousPowerShell",
         "Suspicious PowerShell flags (-nop, -w hidden)",          NULL},
    {TsIndicator_CmdLine_DownloadCradle,    "CmdLine.DownloadCradle",
         "DownloadCradle",
         "Download cradle pattern in command line",                NULL},
    {TsIndicator_CmdLine_ReflectionLoad,    "CmdLine.ReflectionLoad",
         "ReflectionLoad",
         "Reflective loading pattern detected",                    NULL},
    {TsIndicator_CmdLine_ClipboardAbuse,    "CmdLine.ClipboardAbuse",
         "T1115-ClipboardAbuse",
         "Clipboard data access indicators (T1115)",               "T1115"},

    // ── 注入检测（0x03xx） ─────────────────────────────────────────────────
    {TsIndicator_Injection_RemoteThread,    "Injection.RemoteThread",
         "RemoteThread",
         "Remote thread creation detected (T1055)",                "T1055"},
    {TsIndicator_Injection_CrossProcessThread, "Injection.CrossProcessThread",
         "CrossProcessThread",
         "Cross-process thread injection (T1055)",                 "T1055"},
    {TsIndicator_Injection_ProcessHollowing, "Injection.ProcessHollowing",
         "T1055.012-ProcessHollowing",
         "Process hollowing detected (T1055.012)",                 "T1055.012"},
    {TsIndicator_Injection_ThreadShellcode, "Injection.ThreadShellcode",
         "ThreadShellcode",
         "Shellcode at thread start address (T1055)",              "T1055"},
    {TsIndicator_Injection_ROPChain,        "Injection.ROPChain",
         "ROPChain",
         "ROP chain detected in thread stack (T1055)",             "T1055"},
    {TsIndicator_Injection_HeapSpray,       "Injection.HeapSpray",
         "HeapSprayDetected",
         "Heap spray pattern confirmed",                           NULL},
    {TsIndicator_Injection_ReflectiveDll,   "Injection.ReflectiveDll",
         "ReflectiveDllLoad",
         "Reflective DLL loading detected (T1055)",                "T1055"},

    // ── 持久化（0x04xx） ───────────────────────────────────────────────────
    {TsIndicator_Persistence_RegistryRunKey, "Persistence.RegistryRunKey",
         "RegistryPersistence",
         "Suspicious registry key for persistence (T1547)",        "T1547"},
    {TsIndicator_Persistence_MultiTechnique, "Persistence.MultiTechnique",
         "MultiPersistence",
         "Multi-technique persistence (T1547)",                    "T1547"},
    {TsIndicator_Persistence_RansomwarePrep, "Persistence.RansomwarePrep",
         "RansomwarePrep",
         "Ransomware prep: VSS + persistence (T1490)",             "T1490"},
    {TsIndicator_Persistence_ServiceInstall, "Persistence.ServiceInstall",
         "ServicePersistence",
         "Service install for persistence (T1543)",                "T1543"},

    // ── 防御绕过（0x05xx） ─────────────────────────────────────────────────
    {TsIndicator_Defense_DisableDefender,   "Defense.DisableDefender",
         "DefenseEvasion",
         "Windows Defender disabled via registry (T1562)",         "T1562"},
    {TsIndicator_Defense_AppControlBlock,   "Defense.AppControlBlock",
         "AppControlBlock",
         "App control blocked suspicious load",                    NULL},
    {TsIndicator_Defense_StackTampering,    "Defense.StackTampering",
         "StackTampering",
         "Kernel stack frame tampered — SSDT hook detected (T1562)", "T1562"},

    // ── 网络（0x06xx） ─────────────────────────────────────────────────────
    {TsIndicator_Network_Beaconing,         "Network.Beaconing",
         "NetworkBeaconing",
         "Beaconing pattern detected (T1071)",                     "T1071"},
    {TsIndicator_Network_DataExfiltration,  "Network.DataExfiltration",
         "DataExfiltration",
         "Data exfiltration detected (T1041)",                     "T1041"},
    {TsIndicator_Network_C2Communication,   "Network.C2Communication",
         "C2Communication",
         "C2 communication detected (T1071)",                      "T1071"},
    {TsIndicator_Network_PortScanning,      "Network.PortScanning",
         "PortScanning",
         "Port scanning detected (T1046)",                         "T1046"},
    {TsIndicator_Network_KnownC2IOC,        "Network.KnownC2IOC",
         "KnownC2IOC",
         "Connection to known C2 IOC detected",                    NULL},
    {TsIndicator_Network_MaliciousJA3,      "Network.MaliciousJA3",
         "MaliciousJA3",
         "Known-bad JA3 fingerprint (T1573)",                      "T1573"},
    {TsIndicator_Network_DGA,               "Network.DGA",
         "T1568.002-DGA",
         "DGA domain pattern in DNS query (T1568.002)",            "T1568.002"},
    {TsIndicator_Network_DnsTunnel,         "Network.DnsTunnel",
         "T1572-DNSTunnel",
         "DNS tunneling behavior detected (T1572)",                "T1572"},
    {TsIndicator_Network_SuspiciousHTTP,    "Network.SuspiciousHTTP",
         "SuspiciousHTTP",
         "Suspicious HTTP request (T1071)",                        "T1071"},
    {TsIndicator_Network_NamedPipeC2,       "Network.NamedPipeC2",
         "T1572-NamedPipeC2",
         "Named pipe name matches known C2 pattern (T1572)",       "T1572"},
    {TsIndicator_Network_NamedPipeSpoof,    "Network.NamedPipeSpoof",
         "T1036-NamedPipeSpoof",
         "System pipe name created by unauthorized process (T1036.004)",
                                                                    "T1036.004"},
    {TsIndicator_Network_NamedPipeHighEntropy, "Network.NamedPipeHighEntropy",
         "T1573-NamedPipeHighEntropy",
         "High-entropy named pipe name (randomized C2)",           "T1573.001"},

    // ── 信誉（0x07xx） ─────────────────────────────────────────────────────
    {TsIndicator_Reputation_ValidSignature, "Reputation.ValidSignature",
         "ValidSignature",
         "Process image has valid code signature",                 NULL},
    {TsIndicator_Reputation_UnsignedBinary, "Reputation.UnsignedBinary",
         "UnsignedBinary",
         "Process image lacks code signature",                     NULL},
    {TsIndicator_Reputation_UnsignedNoDEP,  "Reputation.UnsignedNoDEP",
         "UnsignedNoDEP",
         "Unsigned binary without DEP (high risk)",                NULL},
    {TsIndicator_Reputation_SoftwarePacking, "Reputation.SoftwarePacking",
         "T1027.002-SoftwarePacking",
         "PE entropy indicates packed executable (T1027.002)",     "T1027.002"},

    // ── 句柄/对象（0x08xx） ────────────────────────────────────────────────
    {TsIndicator_Handle_LsassAccess,        "Handle.LsassAccess",
         "T1003-HandleAccess",
         "Handle access to LSASS process (T1003)",                 "T1003"},
    {TsIndicator_Handle_ProcessTermination, "Handle.ProcessTermination",
         "T1489-ProcTermination",
         "Handle with process termination rights (T1489)",         "T1489"},
    {TsIndicator_Handle_ThreadHijack,       "Handle.ThreadHijack",
         "T1055-ThreadHijack",
         "Thread handle with injection-capable rights (T1055)",    "T1055"},

    // ── 线程（0x09xx） ─────────────────────────────────────────────────────
    {TsIndicator_Thread_ShellcodeStart,     "Thread.ShellcodeStart",
         "ThreadShellcode",
         "Shellcode pattern at thread start (T1055)",              "T1055"},
    {TsIndicator_Thread_SuspiciousStart,    "Thread.SuspiciousStart",
         "SuspiciousThreadStart",
         "Suspicious thread start address",                        NULL},

    // ── 映像加载（0x0Axx） ─────────────────────────────────────────────────
    {TsIndicator_Image_SuspiciousLoad,      "Image.SuspiciousLoad",
         "SuspiciousImage",
         "Suspicious image load detected",                         NULL},
    {TsIndicator_Image_HollowingHeuristic,  "Image.HollowingHeuristic",
         "HollowingHeuristic",
         "Secondary hollowing heuristic: memory modification (T1055.012)",
                                                                   "T1055.012"},
    {TsIndicator_Image_SuspiciousPath,      "Image.SuspiciousPath",
         "SuspiciousImagePath",
         "Image loaded from suspicious path (Temp/Downloads)",     NULL},
    {TsIndicator_Image_MasqueradingName,    "Image.MasqueradingName",
         "MasqueradingDll",
         "Image masquerading as system DLL (T1036)",               "T1036.005"},
    {TsIndicator_Image_TypoSquatting,       "Image.TypoSquatting",
         "TyposquattingDll",
         "Image name one character from system DLL (T1036)",       "T1036.005"},
    {TsIndicator_Image_NetworkPath,         "Image.NetworkPath",
         "NetworkImageLoad",
         "Image loaded from UNC network path",                     NULL},
    {TsIndicator_Image_DoubleExtension,     "Image.DoubleExtension",
         "DoubleExtensionImage",
         "Image with double extension (T1036)",                    "T1036.008"},
    {TsIndicator_Image_PhantomDllUnbacked,  "Image.PhantomDllUnbacked",
         "PhantomDll",
         "Image mapped without backing file - reflective load (T1055)",
                                                                   "T1055"},
    {TsIndicator_Image_EntrypointOutsideCode, "Image.EntrypointOutsideCode",
         "EntrypointOutsideCode",
         "Image entry point outside executable section (T1055.012)",
                                                                   "T1055.012"},
    {TsIndicator_Image_NoExports,           "Image.NoExports",
         "NoExportsDll",
         "DLL without export table",                               NULL},

    // ── 注册表（0x0Bxx） ─────────────────────────────────────────────────
    {TsIndicator_Registry_SuspiciousMod,    "Registry.SuspiciousMod",
         "RegistrySuspiciousMod",
         "Suspicious registry modification detected",              NULL},

    // ── IOA 行为类型（0x0Dxx，诊断元数据） ────────────────────────────────
    {TsIndicator_Ioa_SyscallDetected,       "Ioa.SyscallDetected",
         "SyscallDetected", "Syscall event detected",             NULL},
    {TsIndicator_Ioa_OpenProcess,           "Ioa.OpenProcess",
         "OpenProcess", "Open process handle",                    NULL},
    {TsIndicator_Ioa_AllocateMemory,        "Ioa.AllocateMemory",
         "AllocateMemory", "Allocate virtual memory",             NULL},
    {TsIndicator_Ioa_WriteMemory,           "Ioa.WriteMemory",
         "WriteMemory", "Write virtual memory",                   NULL},
    {TsIndicator_Ioa_ReadMemory,            "Ioa.ReadMemory",
         "ReadMemory", "Read virtual memory",                     NULL},
    {TsIndicator_Ioa_CreateRemoteThread,    "Ioa.CreateRemoteThread",
         "CreateRemoteThread", "Create remote thread (T1055)",    "T1055"},
    {TsIndicator_Ioa_MapSection,            "Ioa.MapSection",
         "MapSection", "Map section view",                        NULL},
    {TsIndicator_Ioa_QueueApc,              "Ioa.QueueApc",
         "QueueApc", "Queue APC to remote thread (T1055.004)",    "T1055.004"},
    {TsIndicator_Ioa_SetContextThread,      "Ioa.SetContextThread",
         "SetContextThread", "Set thread context (T1055.003)",    "T1055.003"},
    {TsIndicator_Ioa_ProtectMemory,         "Ioa.ProtectMemory",
         "ProtectMemory", "Protect virtual memory",               NULL},
    {TsIndicator_Ioa_MemoryAllocate,        "Ioa.MemoryAllocate",
         "MemoryAllocate", "Memory allocate event",               NULL},
    {TsIndicator_Ioa_MemoryFree,            "Ioa.MemoryFree",
         "MemoryFree", "Memory free event",                       NULL},
    {TsIndicator_Ioa_MemoryProtect,         "Ioa.MemoryProtect",
         "MemoryProtect", "Memory protect event",                 NULL},
    {TsIndicator_Ioa_RegistrySetValue,      "Ioa.RegistrySetValue",
         "RegistrySetValue", "Registry set value event",          NULL},
    {TsIndicator_Ioa_RegistryDeleteValue,   "Ioa.RegistryDeleteValue",
         "RegistryDeleteValue", "Registry delete value event",    NULL},
    {TsIndicator_Ioa_FileCreate,            "Ioa.FileCreate",
         "FileCreate", "File create event",                       NULL},
    {TsIndicator_Ioa_FileWrite,             "Ioa.FileWrite",
         "FileWrite", "File write event",                         NULL},
    {TsIndicator_Ioa_FileRename,            "Ioa.FileRename",
         "FileRename", "File rename event (FBE)",                 "T1486"},
    {TsIndicator_Ioa_FileDelete,            "Ioa.FileDelete",
         "FileDelete", "File delete event (FBE)",                 "T1485"},
    {TsIndicator_Ioa_ProcessObjectAccess,   "Ioa.ProcessObjectAccess",
         "ProcessObjectAccess", "Process object access",          NULL},
    {TsIndicator_Ioa_ThreadObjectAccess,    "Ioa.ThreadObjectAccess",
         "ThreadObjectAccess", "Thread object access",            NULL},
    {TsIndicator_Ioa_CrossProcessMemoryAccess, "Ioa.CrossProcessMemoryAccess",
         "CrossProcessMemoryAccess", "Cross-process memory access", NULL},
    {TsIndicator_Ioa_CodeInjectionPattern,  "Ioa.CodeInjectionPattern",
         "CodeInjectionPattern", "Code injection pattern (T1055)", "T1055"},
    {TsIndicator_Ioa_ProcessHollowingPattern, "Ioa.ProcessHollowingPattern",
         "ProcessHollowingPattern", "Process hollowing pattern (T1055.012)",
                                                                    "T1055.012"},
    {TsIndicator_Ioa_ApcInjectionPattern,   "Ioa.ApcInjectionPattern",
         "ApcInjectionPattern", "APC injection pattern (T1055.004)",
                                                                    "T1055.004"},
    {TsIndicator_Ioa_ThreatScoreUpdated,    "Ioa.ThreatScoreUpdated",
         "ThreatScoreUpdated", "Threat score updated",            NULL},
    {TsIndicator_Ioa_ThreatLevelChanged,    "Ioa.ThreatLevelChanged",
         "ThreatLevelChanged", "Threat level changed",            NULL},
    {TsIndicator_Ioa_ProcessCreated,        "Ioa.ProcessCreated",
         "ProcessCreated", "Process created",                     NULL},
    {TsIndicator_Ioa_ProcessExited,         "Ioa.ProcessExited",
         "ProcessExited", "Process exited",                       NULL},
    {TsIndicator_Ioa_ThreadCreated,         "Ioa.ThreadCreated",
         "ThreadCreated", "Thread created",                       NULL},
    {TsIndicator_Ioa_ThreadExited,          "Ioa.ThreadExited",
         "ThreadExited", "Thread exited",                         NULL},
    {TsIndicator_Ioa_ProcessSnapshot,       "Ioa.ProcessSnapshot",
         "ProcessSnapshot", "Process snapshot",                   NULL},
    {TsIndicator_Ioa_HandleScan,            "Ioa.HandleScan",
         "HandleScan", "Handle scan",                             NULL},
    {TsIndicator_Ioa_SecurityEvent,         "Ioa.SecurityEvent",
         "SecurityEvent", "Security event",                       NULL},
    {TsIndicator_Ioa_SystemStatus,          "Ioa.SystemStatus",
         "SystemStatus", "System status",                         NULL},
    {TsIndicator_Ioa_Error,                 "Ioa.Error",
         "Error", "Error event",                                 NULL},

    // ── 文件行为（0x0Exx，FBE 迁移 2026-08，死代码：勒索行为检测未接入流水线） ──
    {TsIndicator_File_Write,                "File.Write",
         "FileWrite", "File write (ransomware encrypt)",          "T1486"},
    {TsIndicator_File_Rename,               "File.Rename",
         "FileRename", "File rename (ransomware ext change)",     "T1486"},
    {TsIndicator_File_Delete,               "File.Delete",
         "FileDelete", "File delete (data destruction)",          "T1485"},
    {TsIndicator_File_Truncate,             "File.Truncate",
         "FileTruncate", "File truncate (destruction)",           "T1485"},
    {TsIndicator_File_HighEntropy,          "File.HighEntropy",
         "HighEntropyWrite", "High-entropy write (T1486)",        "T1486"},
    {TsIndicator_File_RansomNote,           "File.RansomNote",
         "RansomNote", "Ransom note dropped (T1486)",             "T1486"},
    {TsIndicator_File_MassModify,           "File.MassModify",
         "MassModify", "Mass file modification (T1486)",          "T1486"},
};

#define TS_INDICATOR_TABLE_COUNT \
    (sizeof(g_TsIndicatorTable) / sizeof(g_TsIndicatorTable[0]))

//=============================================================================
// 对数归一 LUT — final = 100 × log(1+raw) / log(101)
// raw ∈ [0,100] 最近邻取整；raw≥100 饱和为 100，raw≤0 为 0
//=============================================================================

/*
 * final = 100 × log(1+raw) / log(101)，raw ∈ [0,100] 最近邻取整。
 * raw=100 → 100×log(101)/log(101) = 100（恰好饱和）；
 * raw>100 → 100（clamp）；raw≤0 → 0。
 * 数值由 100×ln(1+i)/ln(101) 四舍五入计算（perl 验证）。
 */
static const UCHAR g_TsNormLut[TS_NORM_LUT_ENTRIES] = {
      0,  15,  24,  30,  35,  39,  42,  45,  48,  50,   /*  0- 9 */
     52,  54,  56,  57,  59,  60,  61,  63,  64,  65,   /* 10-19 */
     66,  67,  68,  69,  70,  71,  71,  72,  73,  74,   /* 20-29 */
     74,  75,  76,  76,  77,  78,  78,  79,  79,  80,   /* 30-39 */
     80,  81,  81,  82,  82,  83,  83,  84,  84,  85,   /* 40-49 */
     85,  86,  86,  86,  87,  87,  88,  88,  88,  89,   /* 50-59 */
     89,  89,  90,  90,  90,  91,  91,  91,  92,  92,   /* 60-69 */
     92,  93,  93,  93,  94,  94,  94,  94,  95,  95,   /* 70-79 */
     95,  95,  96,  96,  96,  97,  97,  97,  97,  98,   /* 80-89 */
     98,  98,  98,  98,  99,  99,  99,  99, 100, 100,   /* 90-99 */
    100,                                                  /* 100 */
};

//=============================================================================
// 内部结构体
//=============================================================================

//
// 每进程评分上下文（生命周期由 WKD_PROCESS 管理，不进任何引擎链表）
//
typedef struct _TS_CONTEXT {
    /* 反向指针，不增加引用计数（pin 契约保证 pair 在 TsContext 生命周期内） */
    PAE_PROCESS_PAIR   Pair;

    /* ---- IOC 批次链：仅缓存"本轮新增"（结算后清空并累加进 IocScore） ---- */
    LIST_ENTRY          IocChain;       // 链头最旧（时间升序）
    volatile ULONG      TotalIocRecords;    // 生命周期累计提交数（单调递增）

    /* ---- IOA 记录链：60s 时间窗口 ---- */
    LIST_ENTRY          IoaChain;       // 链头最旧；结算时惰性摘除过期前缀
    volatile ULONG      TotalIoaRecords;
    volatile ULONG      ActiveIoaRecords;   // 上限 TS_MAX_IOA_RECORDS

    /* ---- IOC 持久累计分（只增不减，钳位防溢出） ---- */
    ULONG               IocScore;

    /* ---- IOA 内层 EWMA 缓存 ---- */
    ULONG               IoaScore;       // EWMA 平滑后的 IOA 内层分
    LARGE_INTEGER       LastSettleTime; // 上次结算时间
    TS_VERDICT          CachedVerdict;

    LARGE_INTEGER       FirstRecordTime;
    LARGE_INTEGER       LastRecordTime;
} TS_CONTEXT, *PTS_CONTEXT;

#define TS_IOC_SCORE_CEILING   (100LL * 100)   /* 10000：远超融合 raw=100 饱和点，防溢出 */

//
// 完整引擎结构体（纯配置 + 统计，不持有任何 TsContext 引用）
//
typedef struct _TS_ENGINE {
    BOOLEAN Initialized;
    EX_RUNDOWN_REF Rundown;

    TS_THRESHOLD_CONFIG Thresholds;

    volatile LONG64 ScoresCalculated;
    volatile LONG64 TotalRecords;
    volatile LONG64 RecordsExpired;

    volatile LONG64 VerdictClean;
    volatile LONG64 VerdictSuspicious;
    volatile LONG64 VerdictMalicious;
    volatile LONG64 VerdictBlocked;

    volatile ULONG TotalContexts;
    volatile ULONG ActiveContexts;

    LARGE_INTEGER StartTime;
} TS_ENGINE;

//=============================================================================
// 内部函数前向声明
//=============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static
ULONG
TspGetIndicatorWeight(
    _In_ TS_INDICATOR_TYPE Type
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static
ULONG
TspGetContextMultiplier(
    _In_ PAE_PROCESS_PAIR Pair
    );

_IRQL_requires_max_(APC_LEVEL)
static
VOID
TspSettleScoresInternal(
    _In_ PTS_ENGINE Engine,
    _Inout_ PTS_CONTEXT Context
    );

static
FORCEINLINE
ULONG
TspNormalizeLog(
    _In_ ULONG Raw
    )
{
    if (Raw == 0) return 0;
    if (Raw >= (LONG64)(TS_NORM_LUT_ENTRIES - 1)) return 100;
    return g_TsNormLut[Raw];
}

_IRQL_requires_max_(APC_LEVEL)
static
TS_VERDICT
TspDetermineVerdict(
    _In_ PTS_ENGINE Engine,
    _In_ ULONG NormalizedScore
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
TspBuildVerdictReason(
    _In_ PTS_CONTEXT Context,
    _Out_writes_z_(ReasonSize) PCHAR Reason,
    _In_ SIZE_T ReasonSize
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
TspPopulateScoreResult(
    _In_ PTS_ENGINE Engine,
    _In_ PTS_CONTEXT Context,
    _Out_ PTS_THREAT_SCORE Score,
    _In_ BOOLEAN AllocatePath
    );

//=============================================================================
// 公开 API 实现
//=============================================================================

_Use_decl_annotations_
NTSTATUS
TsInitialize(
    _Outptr_ PTS_ENGINE* Engine
    )
/*++
Routine Description:
    初始化威胁评分引擎实例。分配非分页内存、设置默认阈值。

Arguments:
    Engine - 输出参数，接收指向已初始化引擎的指针。

Return Value:
    NTSTATUS - 成功返回 STATUS_SUCCESS。
--*/
{
    PTS_ENGINE newEngine = NULL;

    PAGED_CODE();
    if (!Engine) return STATUS_INVALID_PARAMETER;
    *Engine = NULL;

    newEngine = (PTS_ENGINE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(TS_ENGINE), TS_POOL_TAG_ENGINE);
    if (!newEngine) return STATUS_NO_MEMORY;
    RtlZeroMemory(newEngine, sizeof(TS_ENGINE));

    /* 初始化 */
    ExInitializeRundownProtection(&newEngine->Rundown);
    newEngine->Thresholds.SuspiciousThreshold = TS_DEFAULT_SUSPICIOUS_THRESHOLD;
    newEngine->Thresholds.MaliciousThreshold = TS_DEFAULT_MALICIOUS_THRESHOLD;
    newEngine->Thresholds.BlockedThreshold = TS_DEFAULT_BLOCKED_THRESHOLD;
    KeQuerySystemTime(&newEngine->StartTime);
    newEngine->Initialized = TRUE;

#ifdef DBG
    /* 覆盖校验：遍历全部指标枚举，报告未配置权重的项（防新增枚举漏配） */
    {
        ULONG missing = 0;

        for (ULONG i = 0; i < TsIndicator_MaxValue; i++) {
            if (TspGetIndicatorWeight((TS_INDICATOR_TYPE)i) == 0) {
                missing++;
            }
        }
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "[Ts] Weight coverage: %lu/%lu configured, %lu missing\n",
            TsIndicator_MaxValue - missing, TsIndicator_MaxValue, missing);
    }
#endif

    *Engine = newEngine;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
TsShutdown(
    _Inout_ PTS_ENGINE Engine
    )
/*++
Routine Description:
    关闭威胁评分引擎，释放引擎内存。
    注意：TsContext 由进程管理器在 PspDestroyProcess 中释放，
    引擎关闭时不遍历 TsContext。

Arguments:
    Engine - 指向要关闭的引擎实例。
--*/
{
    PAGED_CODE();
    if (!Engine || !Engine->Initialized) return;

    Engine->Initialized = FALSE;
    ExWaitForRundownProtectionRelease(&Engine->Rundown);
    ExFreePoolWithTag(Engine, TS_POOL_TAG_ENGINE);
}

_Use_decl_annotations_
NTSTATUS
TsSetThresholds(
    _In_ PTS_ENGINE Engine,
    _In_ ULONG SuspiciousThreshold,
    _In_ ULONG MaliciousThreshold,
    _In_ ULONG BlockedThreshold
    )
{
    NTSTATUS status;

    PAGED_CODE();
    if (!Engine || !Engine->Initialized) return STATUS_INVALID_PARAMETER;
    if (!ExAcquireRundownProtection(&Engine->Rundown)) return STATUS_DEVICE_NOT_READY;

    if (SuspiciousThreshold > 100 || MaliciousThreshold > 100 || BlockedThreshold > 100) {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }
    if (SuspiciousThreshold >= MaliciousThreshold || MaliciousThreshold >= BlockedThreshold) {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    InterlockedExchange((volatile LONG*)&Engine->Thresholds.SuspiciousThreshold, (LONG)SuspiciousThreshold);
    InterlockedExchange((volatile LONG*)&Engine->Thresholds.MaliciousThreshold, (LONG)MaliciousThreshold);
    InterlockedExchange((volatile LONG*)&Engine->Thresholds.BlockedThreshold, (LONG)BlockedThreshold);

    status = STATUS_SUCCESS;

Cleanup:
    ExReleaseRundownProtection(&Engine->Rundown);
    return status;
}

//=============================================================================
// TsContext 生命周期 — 进程对维度（由 ProcessPairContext 在确定性时刻调用）
//=============================================================================

_Use_decl_annotations_
NTSTATUS
TsAllocateProcessPairContext(
    _In_opt_ PTS_ENGINE Engine,
    _In_ PAE_PROCESS_PAIR Pair
    )
/*++
Routine Description:
    为进程对创建/获取 TsContext。Pair->TsContext 已存在时直接返回成功；
    否则分配并挂载（创建时全部分配语义，由 AeFindOrCreateProcessPair 调用）。

Arguments:
    Engine - 引擎实例（NULL 使用全局引擎）。
    Pair - 目标进程对。

Return Value:
    NTSTATUS。
--*/
{
    PTS_CONTEXT context;

    PAGED_CODE();
    if (!Engine) Engine = WkdTsEngine;
    if (!Engine || !Engine->Initialized || !Pair) return STATUS_INVALID_PARAMETER;
    if (!ExAcquireRundownProtection(&Engine->Rundown)) {
        /* 获取的TS引擎Rundown在上下文释放时解引用 */
        return STATUS_REQUEST_ABORTED;
    }

    context = (PTS_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(TS_CONTEXT), TS_POOL_TAG_CONTEXT);
    if (!context) {
        ExReleaseRundownProtection(&Engine->Rundown);
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(context, sizeof(TS_CONTEXT));

    InitializeListHead(&context->IocChain);
    InitializeListHead(&context->IoaChain);
    context->CachedVerdict = TsVerdict_Unknown;
    KeQuerySystemTime(&context->LastSettleTime);
    InterlockedIncrement(&Engine->TotalContexts);
    InterlockedIncrement(&Engine->ActiveContexts);

    context->Pair = Pair;
    Pair->TsContext = context;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
TsFreeProcessPairContext(
    _In_opt_ PTS_ENGINE Engine,
    _In_ PAE_PROCESS_PAIR Pair
    )
/*++
Routine Description:
    销毁进程对的 TsContext。由 PsDereferenceWkdProcessPair refcount==0
    分支调用。先置 Pair->TsContext = NULL 关闭新提交，再等待运行中
    的提交/结算完成后释放双链与上下文。

Arguments:
    Engine - 引擎实例。
    Pair - 目标进程对（从中读取 TsContext 然后置 NULL）。
--*/
{
    PTS_CONTEXT context;

    PAGED_CODE();
    if (!Engine) Engine = WkdTsEngine;
    if (!Engine || !Engine->Initialized || !Pair)  return;

    /* ---- 无持有者，可安全无锁释放 ---- */
    context = Pair->TsContext;
        
    {
        PLIST_ENTRY entry;

        /* 释放 IOC 链（持久链，全部节点） */
        while (!IsListEmpty(&context->IocChain)) {
            entry = RemoveHeadList(&context->IocChain);
            ExFreePoolWithTag(
                CONTAINING_RECORD(entry, TS_INDICATOR_RECORD, Link),
                TS_POOL_TAG_RECORD);
        }

        /* 释放 IOA 链 */
        while (!IsListEmpty(&context->IoaChain)) {
            entry = RemoveHeadList(&context->IoaChain);
            ExFreePoolWithTag(
                CONTAINING_RECORD(entry, TS_INDICATOR_RECORD, Link),
                TS_POOL_TAG_RECORD);
        }

        ExFreePoolWithTag(context, TS_POOL_TAG_CONTEXT);
        Pair->TsContext = NULL;
        InterlockedDecrement(&Engine->ActiveContexts);
    }

    /* 对称：TsAllocateProcessPairContext 曾获取引擎 RundownRef */
    ExReleaseRundownProtection(&Engine->Rundown);
}

//=============================================================================
// 记录提交 — 只插入记录，零计算
//=============================================================================

_Use_decl_annotations_
NTSTATUS
TsReportIndicatorLocked(
    _In_opt_ PTS_ENGINE Engine,
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ TS_SOURCE Source,
    _In_ TS_INDICATOR_TYPE Indicator,
    _In_ UCHAR Severity
)
/*++
Routine Description:
    追加指示记录到指定链（按 Source 分链：IOC 批次链 / IOA 窗口链）。
    提交只插入记录，不参与任何计算；得分由 TsSettleScores 结算。
    IOC 链为"本轮新增"批次链（结算后清空并累加进 IocScore），
    无上限淘汰；IOA 链维持 TS_MAX_IOA_RECORDS 上限。

    锁约定：本函数获取 context->Lock（独占）。TsContext->Lock 恒为叶锁——
    任何路径不得在持有 context->Lock 时获取其他锁。

Arguments:
    Engine - 引擎实例（NULL 使用全局引擎）。
    Pair - 目标进程对。
    Source - 来源类型（TsSourceIOC / TsSourceBehavioral）。
    Indicator - 指标类型。
    Severity - 威胁程度 AE_THREAT_SEVERITY 1-4（0 拒绝）。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;
    PTS_CONTEXT context;
    PTS_INDICATOR_RECORD record;
    PLIST_ENTRY chainHead;
    LARGE_INTEGER currentTime;
    BOOLEAN isIoa;

    PAGED_CODE();
    if (!Engine) Engine = WkdTsEngine;
    if (!Engine || !Engine->Initialized || !Pair ||
        Indicator >= TsIndicator_MaxValue || !VALID_SEVERITY(Severity)) {
        return STATUS_INVALID_PARAMETER;
    }

    /* ---- 获取TS引擎的Rundown ---- */
    if (!ExAcquireRundownProtection(&Engine->Rundown)) {
        return STATUS_REQUEST_ABORTED;
    }

    isIoa = (Source == TsSourceBehavioral);
    if (Source != TsSourceIOC && !isIoa) {
        status = STATUS_NOT_SUPPORTED;
        goto Cleanup;
    }

    context = Pair->TsContext;

    /* 初始化Record */
    {
        record = (PTS_INDICATOR_RECORD)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(TS_INDICATOR_RECORD), TS_POOL_TAG_RECORD);
        if (!record) {
            status = STATUS_NO_MEMORY;
            goto Cleanup;
        }

        KeQuerySystemTime(&currentTime);
        record->Source = Source;
        record->Indicator = Indicator;
        record->Severity = Severity;
        record->Timestamp = currentTime;
    }

    /* Record插入 */
    {

        chainHead = isIoa ? &context->IoaChain : &context->IocChain;

        /* IOA 链超上限 FIFO 丢最旧（链头）；IOC 批次链结算即清空，无上限 */
        if (isIoa) {
            while (context->ActiveIoaRecords >= TS_MAX_IOA_RECORDS &&
                   !IsListEmpty(chainHead)) {
                PLIST_ENTRY oldest = RemoveHeadList(chainHead);
                PTS_INDICATOR_RECORD victim =
                    CONTAINING_RECORD(oldest, TS_INDICATOR_RECORD, Link);
                ExFreePoolWithTag(victim, TS_POOL_TAG_RECORD);
                context->ActiveIoaRecords--;
                Engine->RecordsExpired++;
            }
        }

        InsertTailList(chainHead, &record->Link);
        if (isIoa) {
            context->TotalIoaRecords++;
            context->ActiveIoaRecords++;
        }
        else {
            context->TotalIocRecords++;
        }
        Engine->TotalRecords++;

        context->LastRecordTime = currentTime;
        if (context->FirstRecordTime.QuadPart == 0) {
            context->FirstRecordTime = currentTime;
        }
    }

Cleanup:
    ExReleaseRundownProtection(&Engine->Rundown);
    return status;
}

//=============================================================================
// 统一结算 — IOC 线性累加 / IOA 窗口 + EWMA / 外层融合 + 对数归一
//=============================================================================

_Use_decl_annotations_
NTSTATUS
TsSettleScores(
    _In_opt_ PTS_ENGINE Engine,
    _In_ PAE_PROCESS_PAIR Pair
    )
/*++
Routine Description:
    统一结算入口（进程对维度）。由 AeOrchestratorDispatch 事件尾部调用；
    查询 API 在缓存失效时内部调用。
    Pair->TsContext 为 NULL（无记录 pair）时静默返回成功。

Arguments:
    Engine - 引擎实例（NULL 使用全局引擎）。
    Pair - 目标进程对。

Return Value:
    NTSTATUS。
--*/
{
    if (!Engine) Engine = WkdTsEngine;
    if (!Engine || !Engine->Initialized ||
        !Pair || !Pair->TsContext) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Engine->Rundown)) {
        return STATUS_REQUEST_ABORTED;
    }
    WkdAcquirePushLockExclusive(&Pair->Lock);
    TspSettleScoresInternal(Engine, Pair->TsContext);
    WkdReleasePushLockExclusive(&Pair->Lock);
    ExReleaseRundownProtection(&Engine->Rundown);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
VOID
TspSettleScoresInternal(
    _In_ PTS_ENGINE Engine,
    _Inout_ PTS_CONTEXT Context
    )
/*++
Routine Description:
    结算算法（2026-07 迁移，进程对维度）:
      ① IOC 内层: drain 批次链 → 累加进 IocScore（持久累计，只增不减）
      ② IOA 内层:
         a) 惰性摘除过期前缀（Timestamp + 60s < now，链头最旧遇新即停）
         b) batchSum = Σ over 窗口内记录: Severity × W(Indicator)
         c) Δt = 窗口内最新两条记录时间戳差（≤1 条 → 0）
         d) α = clamp(100·T/(T+Δt), 30, 70)
         e) IoaScore = (α·IoaScore + (100-α)·batchSum) / 100
      ③ 外层融合: raw = (min(IocScore,100)·W_IOC + IoaScore·W_IOA)
                        / (W_IOC + W_IOA)
      ④ 标准化: final = TspNormalizeLog(raw)（对数归一 LUT）
      ⑤ Verdict: 阈值 50/80/95

    EWMA 语义: 窗口内记录结算后保留，batchSum 是"最近 60s 窗口强度"
    测量值而非增量批次 — 每条记录以 60s 寿命自然退出（先被 EWMA
    渐弱、后随摘除归零），结算幂等不重复计分。
--*/
{
    LARGE_INTEGER now;
    PLIST_ENTRY entry, nextEntry;
    PTS_INDICATOR_RECORD record;
    ULONG ioaBatchSum = 0;  // 时间窗口内的IOA记录总得分
    ULONG raw;

    KeQuerySystemTime(&now);

    /* ================= ① IOC 内层：drain 批次链 → IocScore ============ */
    {
        entry = Context->IocChain.Flink;
        while (entry != &Context->IocChain) {
            nextEntry = entry->Flink;
            record = CONTAINING_RECORD(entry, TS_INDICATOR_RECORD, Link);

            /* 累加进持久累计分（只增不减） */
            Context->IocScore += (ULONG)record->Severity *
                TspGetIndicatorWeight(record->Indicator);

            /* 链种子：累积威胁分（对齐 SS Chain->CumulativeThreatScore，
             * 结算幂等——批次链结算后清空，每条记录只累加一次） */
            if (Context->Pair) {
                Context->Pair->BehaviorContext.CumulativeThreatScore +=
                    (ULONG)record->Severity * TspGetIndicatorWeight(record->Indicator);
            }

            /* 批次链结算后清空释放（本轮新增记录） */
            RemoveEntryList(entry);
            ExFreePoolWithTag(record, TS_POOL_TAG_RECORD);
            entry = nextEntry;
        }

        Context->IocScore = min(Context->IocScore, TS_IOC_SCORE_CEILING);
    }

    /* ================= ② IOA 内层：60s 窗口 + EWMA ================= */
    {
        /* 用于计算IOA记录插入的时间间隔 */
        LONG64 newestT = 0;
        LONG64 secondNewestT = 0;
        LONG64 deltaSec;
        ULONG alpha100;

        /* a) 惰性摘除过期前缀：链头最旧（时间升序），遇新即停 */
        entry = Context->IoaChain.Flink;
        while (entry != &Context->IoaChain) {
            nextEntry = entry->Flink;
            record = CONTAINING_RECORD(entry, TS_INDICATOR_RECORD, Link);
            if (record->Timestamp.QuadPart + TS_IOA_WINDOW_NS >= now.QuadPart) {
                break;                          /* 遇新即停 */
            }

            /* 移除过期记录 */
            RemoveEntryList(entry);
            Context->ActiveIoaRecords--;
            Engine->RecordsExpired--;
            ExFreePoolWithTag(record, TS_POOL_TAG_RECORD);
            entry = nextEntry;
        }

        /* b) ioaBatchSum = Σ 窗口内记录；同时取最新两条时间戳（链尾即最新） */
        entry = Context->IoaChain.Flink;
        while (entry != &Context->IoaChain) {
            record = CONTAINING_RECORD(entry, TS_INDICATOR_RECORD, Link);
            ioaBatchSum += (ULONG)record->Severity *
                TspGetIndicatorWeight(record->Indicator);
            secondNewestT = newestT;
            newestT = record->Timestamp.QuadPart;
            entry = entry->Flink;
        }

        /* b') 上下文评分乘数（迁移自 SS BepCalculateEventThreatScore）：
         *     按进程对行为上下文（LOLBIN/脚本宿主/高风险/惯犯）调节 IOA
         *     窗口分。每次结算重算，反映 SuspiciousEventCount 动态增长。 */
        if (Context->Pair) {
            ioaBatchSum = ioaBatchSum * TspGetContextMultiplier(Context->Pair) / 100;
        }

        /* c) Δt = 最新两条之差（秒）；≤1 条记录 → Δt=0 */
        deltaSec = (newestT - secondNewestT) / 10000000LL;
        if (deltaSec < 0) deltaSec = 0;

        /* d) α = clamp(100·T/(T+Δt), 30, 70)，整数定点 */
        alpha100 = (ULONG)TS_ALPHA_TIME_CONST_SEC * 100 /
            (TS_ALPHA_TIME_CONST_SEC + (ULONG)deltaSec);
        alpha100 = min(alpha100, TS_ALPHA_MAX_PERCENT);
        alpha100 = max(alpha100, TS_ALPHA_MIN_PERCENT);

        /* e) IoaScore = α×IoaScore + (1-α)×batchSum */
        Context->IoaScore = (alpha100 * Context->IoaScore +
            (100 - alpha100) * ioaBatchSum) / 100;
    }

    /* ================= ③ 外层融合 ================= */
    /* IocScore 钳到 100 与 IoaScore 融合（超过 100 后归一化已必然饱和） */
    raw = (min(Context->IocScore, 100) * TS_FUSION_W_IOC +
           Context->IoaScore * TS_FUSION_W_IOA) /
          (TS_FUSION_W_IOC + TS_FUSION_W_IOA);
    raw = max(raw, 0);

    /* ================= ④ 标准化 + ⑤ Verdict ================= */
    Context->CachedVerdict =
        TspDetermineVerdict(Engine, TspNormalizeLog(raw));
    Context->LastSettleTime = now;
}

//=============================================================================
// 上下文评分乘数
//=============================================================================

//
// TspGetContextMultiplier — 进程对上下文评分乘数（%）
//
// 迁移自 SS BepCalculateEventThreatScore（BehaviorEngine.c L4414）：
//   LOLBIN 进程      → ×120
//   脚本宿主进程      → ×115
//   高风险(可疑≥10)  → ×130   （SS HIGH_RISK：BehaviorScore≥500 或 可疑≥10）
//   惯犯(可疑>5)     → ×125
// 连乘 clamp [100, 200]，结果写回 Pair->BehaviorContext.ScoreMultiplierPercent
// 供诊断/上报。结算侧在 IOA 窗口分上应用。
//
_IRQL_requires_max_(DISPATCH_LEVEL)
static
ULONG
TspGetContextMultiplier(
    _In_ PAE_PROCESS_PAIR Pair
    )
{
    ULONG percent = 100;

    if (!Pair) {
        return 100;
    }

    if (Pair->BehaviorContext.BehaviorFlags & WKD_BEHAVIOR_LOLBIN) {
        percent = percent * 120 / 100;
    }
    if (Pair->BehaviorContext.BehaviorFlags & WKD_BEHAVIOR_SCRIPT_HOST) {
        percent = percent * 115 / 100;
    }
    if (Pair->BehaviorContext.SuspiciousEventCount > 5) {
        percent = percent * 125 / 100;   /* 惯犯（SS L4440） */
    }
    if (Pair->BehaviorContext.SuspiciousEventCount >= 10) {
        percent = percent * 130 / 100;   /* 高风险（SS L4437） */
    }

    if (percent > 200) percent = 200;
    if (percent < 100) percent = 100;

    /* 写回缓存（诊断/上报用；结算侧单线程写，volatile 保证可见性） */
    Pair->BehaviorContext.ScoreMultiplierPercent = percent;

    return percent;
}

//=============================================================================
// 权重查询
//=============================================================================

static
ULONG
TspGetIndicatorWeight(
    _In_ TS_INDICATOR_TYPE Type
    )
/*++
Routine Description:
    查预配置固定权重常量（按 Indicator 类型粒度）。
    IOC 指标查 g_TsIocWeights，IOA 指标（0x0Dxx）查 g_TsIoaWeights。

Arguments:
    Type - 指标类型。

Return Value:
    权重值；未配置项返回 0（调用方不应落记录）。
--*/
{
    if (Type >= TsIndicator_MaxValue) {
        return 0;
    }

    if (Type >= TsIndicator_Ioa_SyscallDetected) {
        return g_TsIoaWeights[Type];
    }

    return g_TsIocWeights[Type];
}

_Use_decl_annotations_
const TS_INDICATOR_CONFIG*
TsLookupIndicatorConfig(
    _In_ TS_INDICATOR_TYPE Type
    )
{
    for (ULONG i = 0; i < TS_INDICATOR_TABLE_COUNT; i++) {
        if (g_TsIndicatorTable[i].Indicator == Type) {
            return &g_TsIndicatorTable[i];
        }
    }
    return NULL;
}

//=============================================================================
// 评分查询
//=============================================================================

_Use_decl_annotations_
NTSTATUS
TsCalculateScore(
    _In_opt_ PTS_ENGINE Engine,
    _In_ PAE_PROCESS_PAIR Pair,
    _Outptr_ PTS_THREAT_SCORE* Score
    )
/*++
Routine Description:
    计算指定进程对的综合威胁评分。

Arguments:
    Engine - 引擎实例。
    Pair - 目标进程对。
    Score - 输出参数（需 TsFreeScore 释放）。

Return Value:
    NTSTATUS。
--*/
{
    PTS_CONTEXT context;
    PTS_THREAT_SCORE newScore;

    PAGED_CODE();
    if (!Engine) Engine = WkdTsEngine;
    if (!Engine || !Engine->Initialized || !Pair || !Score) return STATUS_INVALID_PARAMETER;
    *Score = NULL;

    context = Pair->TsContext;
    if (!context) return STATUS_NOT_FOUND;

    newScore = (PTS_THREAT_SCORE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(TS_THREAT_SCORE), TS_POOL_TAG_CONTEXT);
    if (!newScore) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(newScore, sizeof(TS_THREAT_SCORE));

    /* 排他锁下结算 + 快照 */

    TspSettleScoresInternal(Engine, context);


    TspPopulateScoreResult(Engine, context, newScore, TRUE);
    InterlockedIncrement64(&Engine->ScoresCalculated);

    switch (newScore->Verdict) {
    case TsVerdict_Clean:      InterlockedIncrement64(&Engine->VerdictClean);      break;
    case TsVerdict_Suspicious: InterlockedIncrement64(&Engine->VerdictSuspicious);  break;
    case TsVerdict_Malicious:  InterlockedIncrement64(&Engine->VerdictMalicious);   break;
    case TsVerdict_Blocked:    InterlockedIncrement64(&Engine->VerdictBlocked);     break;
    default: break;
    }

    *Score = newScore;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
TsCalculateScoreInPlace(
    _In_ PTS_ENGINE Engine,
    _In_ PAE_PROCESS_PAIR Pair,
    _Out_ PTS_THREAT_SCORE Score
    )
{
    PTS_CONTEXT context;

    PAGED_CODE();
    if (!Engine || !Engine->Initialized || !Pair || !Score) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Score, sizeof(TS_THREAT_SCORE));

    context = Pair->TsContext;
    if (!context) return STATUS_NOT_FOUND;



    TspSettleScoresInternal(Engine, context);


    TspPopulateScoreResult(Engine, context, Score, FALSE);
    InterlockedIncrement64(&Engine->ScoresCalculated);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
TsGetVerdict(
    _In_opt_ PTS_ENGINE Engine,
    _In_ PAE_PROCESS_PAIR Pair,
    _Out_ PTS_VERDICT Verdict
    )
{
    PTS_CONTEXT context;

    PAGED_CODE();
    if (!Engine || !Engine->Initialized ||
        !Pair || !Pair->TsContext || !Verdict) {
        return STATUS_INVALID_PARAMETER;
    }
    *Verdict = TsVerdict_Unknown;

    WkdAcquirePushLockExclusive(&Pair->Lock);

    context = Pair->TsContext;
    TspSettleScoresInternal(Engine, context);
    *Verdict = context->CachedVerdict;

    WkdReleasePushLockExclusive(&Pair->Lock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
TsGetScore(
    _In_ PTS_ENGINE Engine,
    _In_ PAE_PROCESS_PAIR Pair,
    _Out_ PTS_THREAT_SCORE* Score
    )
{
    PAGED_CODE();
    return TsCalculateScore(Engine, Pair, Score);
}

_Use_decl_annotations_
VOID
TsFreeScore(
    _In_opt_ PTS_THREAT_SCORE Score
    )
{
    PAGED_CODE();
    if (!Score) return;
    if (Score->ProcessPath.Buffer) {
        ExFreePoolWithTag(Score->ProcessPath.Buffer, TS_POOL_TAG_PATH);
        Score->ProcessPath.Buffer = NULL;
    }
    ExFreePoolWithTag(Score, TS_POOL_TAG_CONTEXT);
}

_Use_decl_annotations_
NTSTATUS
TsRunMaintenancePass(
    _In_ PTS_ENGINE Engine
    )
/*++
Routine Description:
    维护函数（惰性模式）。
    记录过期摘除与衰减在 TspSettleScoresInternal 中按需惰性执行，
    不再需要后台全局遍历。此函数保留为外部维护线程提供无害入口。

Arguments:
    Engine - 引擎实例。

Return Value:
    NTSTATUS。
--*/
{
    PAGED_CODE();
    if (!Engine || !Engine->Initialized) return STATUS_INVALID_PARAMETER;
    if (!ExAcquireRundownProtection(&Engine->Rundown)) return STATUS_DEVICE_NOT_READY;

    /* 惰性模式：无需全局遍历，仅刷新统计起始时间 */
    KeQuerySystemTime((PLARGE_INTEGER)&Engine->StartTime);

    ExReleaseRundownProtection(&Engine->Rundown);
    return STATUS_SUCCESS;
}

//=============================================================================
// 内部函数实现
//=============================================================================

_Use_decl_annotations_
TS_VERDICT
TspDetermineVerdict(
    _In_ PTS_ENGINE Engine,
    _In_ ULONG NormalizedScore
    )
{
    if (NormalizedScore >= Engine->Thresholds.BlockedThreshold)     return TsVerdict_Blocked;
    if (NormalizedScore >= Engine->Thresholds.MaliciousThreshold)   return TsVerdict_Malicious;
    if (NormalizedScore >= Engine->Thresholds.SuspiciousThreshold)  return TsVerdict_Suspicious;
    return TsVerdict_Clean;
}

_Use_decl_annotations_
static
VOID
TspBuildVerdictReason(
    _In_ PTS_CONTEXT Context,
    _Out_writes_z_(ReasonSize) PCHAR Reason,
    _In_ SIZE_T ReasonSize
    )
{
    PLIST_ENTRY entry;
    PTS_INDICATOR_RECORD rec;
    const TS_INDICATOR_CONFIG* config;
    ULONG64 highestScore = 0;
    PCSTR highestName = NULL;
    PCSTR highestReason = NULL;
    ULONG recordCount = 0;

    Reason[0] = '\0';


    for (entry = Context->IocChain.Flink;
         entry != &Context->IocChain;
         entry = entry->Flink) {

        rec = CONTAINING_RECORD(entry, TS_INDICATOR_RECORD, Link);
        recordCount++;

        config = TsLookupIndicatorConfig(rec->Indicator);
        ULONG64 contribution = (ULONG64)rec->Severity *
                               (ULONG64)TspGetIndicatorWeight(rec->Indicator);
        if (contribution > highestScore) {
            highestScore = contribution;
            highestName = config ? config->FactorName : "Unknown";
            highestReason = config ? config->Reason : "";
        }
    }

    for (entry = Context->IoaChain.Flink;
         entry != &Context->IoaChain;
         entry = entry->Flink) {

        rec = CONTAINING_RECORD(entry, TS_INDICATOR_RECORD, Link);
        recordCount++;

        config = TsLookupIndicatorConfig(rec->Indicator);
        ULONG64 contribution = (ULONG64)rec->Severity *
                               (ULONG64)TspGetIndicatorWeight(rec->Indicator);
        if (contribution > highestScore) {
            highestScore = contribution;
            highestName = config ? config->FactorName : "Unknown";
            highestReason = config ? config->Reason : "";
        }
    }

    if (Context->CachedVerdict == TsVerdict_Clean) {
        RtlStringCbPrintfA(Reason, ReasonSize,
            "No significant threat indicators (%lu records evaluated)", recordCount);
    } else if (Context->CachedVerdict == TsVerdict_Blocked) {
        if (highestName) {
            RtlStringCbPrintfA(Reason, ReasonSize,
                "BLOCKED: %s - %s (%lu records)",
                highestName, highestReason, recordCount);
        } else {
            RtlStringCbPrintfA(Reason, ReasonSize,
                "BLOCKED: Score exceeded block threshold (%lu records)", recordCount);
        }
    } else if (highestName) {
        RtlStringCbPrintfA(Reason, ReasonSize,
            "Primary: %s - %s (%lu records)",
            highestName, highestReason, recordCount);
    } else {
        RtlStringCbPrintfA(Reason, ReasonSize,
            "Aggregate score exceeded threshold (%lu records)", recordCount);
    }

}

_Use_decl_annotations_
static
VOID
TspPopulateScoreResult(
    _In_ PTS_ENGINE Engine,
    _In_ PTS_CONTEXT Context,
    _Out_ PTS_THREAT_SCORE Score,
    _In_ BOOLEAN AllocatePath
    )
{
    LARGE_INTEGER currentTime;
    PWKD_PROCESS sourceProc;
    UNREFERENCED_PARAMETER(Engine);

    KeQuerySystemTime(&currentTime);

    /* 2026-07 迁移：评分单元为进程对。主 actor = 源进程 PID
     * （self-pair 时 Source==Target）；CreateTime/ImagePath
     * 尽力从进程表取源进程，进程已退出则置 0/空串。 */
    Score->ProcessId = Context->Pair->SourceProcessId;
    Score->ProcessCreateTime.QuadPart = 0;

    sourceProc = PsLookupWkdProcessByProcessId(Context->Pair->SourceProcessId);
    if (sourceProc) {
        Score->ProcessCreateTime = sourceProc->Core.CreateTime;
        PsDereferenceWkdProcess(sourceProc);
    }

    Score->Verdict = Context->CachedVerdict;
    Score->SuspiciousThreshold = Engine->Thresholds.SuspiciousThreshold;
    Score->MaliciousThreshold = Engine->Thresholds.MaliciousThreshold;
    Score->BlockedThreshold = Engine->Thresholds.BlockedThreshold;
    Score->CalculationTime = currentTime;

    /* 从双链取贡献 Top-N 填充 Factors（诊断输出） */


    ULONG factorIndex = 0;
    for (PLIST_ENTRY entry = Context->IocChain.Flink;
         entry != &Context->IocChain && factorIndex < TS_MAX_FACTORS;
         entry = entry->Flink) {
        PTS_INDICATOR_RECORD rec =
            CONTAINING_RECORD(entry, TS_INDICATOR_RECORD, Link);
        const TS_INDICATOR_CONFIG* config = TsLookupIndicatorConfig(rec->Indicator);

        Score->Factors[factorIndex].Type = rec->Source;
        Score->Factors[factorIndex].Score =
            (LONG)rec->Severity * (LONG)TspGetIndicatorWeight(rec->Indicator);
        Score->Factors[factorIndex].Weight = TspGetIndicatorWeight(rec->Indicator);
        RtlStringCbCopyA(Score->Factors[factorIndex].FactorName,
            sizeof(Score->Factors[factorIndex].FactorName),
            config ? config->FactorName : "Unknown");
        RtlStringCbCopyA(Score->Factors[factorIndex].Reason,
            sizeof(Score->Factors[factorIndex].Reason),
            config ? config->Reason : "");
        factorIndex++;
    }
    for (PLIST_ENTRY entry = Context->IoaChain.Flink;
         entry != &Context->IoaChain && factorIndex < TS_MAX_FACTORS;
         entry = entry->Flink) {
        PTS_INDICATOR_RECORD rec =
            CONTAINING_RECORD(entry, TS_INDICATOR_RECORD, Link);
        const TS_INDICATOR_CONFIG* config = TsLookupIndicatorConfig(rec->Indicator);

        Score->Factors[factorIndex].Type = rec->Source;
        Score->Factors[factorIndex].Score =
            (LONG)rec->Severity * (LONG)TspGetIndicatorWeight(rec->Indicator);
        Score->Factors[factorIndex].Weight = TspGetIndicatorWeight(rec->Indicator);
        RtlStringCbCopyA(Score->Factors[factorIndex].FactorName,
            sizeof(Score->Factors[factorIndex].FactorName),
            config ? config->FactorName : "Unknown");
        RtlStringCbCopyA(Score->Factors[factorIndex].Reason,
            sizeof(Score->Factors[factorIndex].Reason),
            config ? config->Reason : "");
        factorIndex++;
    }
    Score->FactorCount = factorIndex;


    /* 判决原因 */
    TspBuildVerdictReason(Context, Score->VerdictReason, sizeof(Score->VerdictReason));

    /* 进程路径（尽力从源进程取，进程已退出则空） */
    RtlInitUnicodeString(&Score->ProcessPath, NULL);
    if (AllocatePath) {
        sourceProc = PsLookupWkdProcessByProcessId(Context->Pair->SourceProcessId);
        if (sourceProc) {
            if (sourceProc->Core.ImagePath &&
                sourceProc->Core.ImagePath->Length > 0) {
                SIZE_T pathLen = sourceProc->Core.ImagePath->Length / sizeof(WCHAR);
                SIZE_T bufferSize = (pathLen + 1) * sizeof(WCHAR);

                Score->ProcessPath.Buffer = (PWCHAR)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, bufferSize, TS_POOL_TAG_PATH);
                if (Score->ProcessPath.Buffer) {
                    RtlCopyMemory(Score->ProcessPath.Buffer,
                        sourceProc->Core.ImagePath->Buffer, bufferSize);
                    Score->ProcessPath.Length = (USHORT)(pathLen * sizeof(WCHAR));
                    Score->ProcessPath.MaximumLength = (USHORT)bufferSize;
                }
            }
            PsDereferenceWkdProcess(sourceProc);
        }
    }
}
