#pragma once

#include "../Common/Constants.h"
#include "../Common/HashMap.h"
#include "../Common/HashSet.h"
#include "../Common/ExportParser.h"   /* PS_PROTECTION（PPL） */
#include "ProcessModuleTracker.h"

//
// 向前声明
//
struct _TS_CONTEXT;
typedef struct _TS_CONTEXT TS_CONTEXT, * PTS_CONTEXT;
typedef struct _AE_IOC_CONTEXT AE_IOC_CONTEXT, * PAE_IOC_CONTEXT;
typedef struct _AE_IOA_CONTEXT AE_IOA_CONTEXT, * PAE_IOA_CONTEXT;
typedef struct _WKD_THREAD_CONTEXT WKD_THREAD_CONTEXT, * PWKD_THREAD_CONTEXT;

/* PPL 结构体 */

typedef enum _PS_PROTECTED_TYPE {
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode,
    PsProtectedSignerCodeGen,
    PsProtectedSignerAntimalware,
    PsProtectedSignerLsa,
    PsProtectedSignerWindows,
    PsProtectedSignerWinTcb,
    PsProtectedSignerWinSystem,
    PsProtectedSignerApp,
    PsProtectedSignerMax
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;

// _PS_PROTECTION 结构体已移入 Common/ExportParser.h（未文档化导出解析子引擎，
// 与 PFN_PsGetProcessProtection 共用，避免同 TU 重复定义）。

//
// 安全上下文结构体
//
typedef struct _WKD_SECURITY_CONTEXT {
    /* 上下文推锁 (2026-08-25 锁下沉: 自 WKD_PROCESS.Lock 迁入)
     * 规则: LIST_ENTRY 头必须持本锁访问; 标量字段走原子/单写者 */
    EX_PUSH_LOCK Lock;

    // 令牌特权
    ULONG PrivilegeCount;
    BOOLEAN SeDebugPrivilege;
    BOOLEAN SeImpersonatePrivilege;
    BOOLEAN SeTcbPrivilege;
    BOOLEAN SeAssignPrimaryTokenPrivilege;
    BOOLEAN SeLoadDriverPrivilege;      /* SE_LOAD_DRIVER_PRIVILEGE (10) */
    BOOLEAN SeBackupPrivilege;          /* SE_BACKUP_PRIVILEGE (17) */
    BOOLEAN SeRestorePrivilege;         /* SE_RESTORE_PRIVILEGE (18) */

    // 令牌属性 (对齐 PhantomSensor PnpCaptureTokenInfo)
    BOOLEAN Elevated;                   // 是否提权
    BOOLEAN Restricted;                 /* SeTokenIsRestricted */

    // 进程分类 (对齐 PhantomSensor PnpCaptureTokenInfo)
    ULONG SessionId;                    // 会话 ID
    ULONG ParentSessionId;              /* 父进程 SessionId（跨会话检测用） */
    BOOLEAN IsService;                  /* Session 0 + 提权 */
    BOOLEAN IsSystem;
    BOOLEAN IsAdmin;                    /* SeTokenIsAdmin */
    WKD_INTEGRITY_LEVEL IntegrityLevel; // 完整性级别

    // 行为属性 (用于评分上下文调节因子)
    BOOLEAN PpidSpoofingDetected;   // 活代码仅 IocpDetectPpidSpoofing 写入；保留供未来信任覆盖(TrustOverride)消费
    BOOLEAN CrossSessionDetected;

    // 命令行分析行为标志（对齐 PhantomSensor PN_BEHAVIOR_*）
    ULONG BehaviorFlags;
#define WKD_BEHAVIOR_ENCODED_CMD        0x00000001  // PowerShell 编码命令
#define WKD_BEHAVIOR_SUSPICIOUS_PS      0x00000002  // PS 绕过标志
#define WKD_BEHAVIOR_DOWNLOAD_CRADLE    0x00000004  // 下载器
#define WKD_BEHAVIOR_REFLECTION_LOAD    0x00000008  // 反射加载
#define WKD_BEHAVIOR_SUSPICIOUS_CMD     0x00000010  // cmd.exe 链式命令
#define WKD_BEHAVIOR_LONG_CMDLINE       0x00000020  // > 2048 字符
#define WKD_BEHAVIOR_LOLBIN             0x00000040  // LOLBin 进程（迁移自 SS BE_PROC_FLAG_LOLBIN，评分乘数 ×120）
#define WKD_BEHAVIOR_SUSPICIOUS_PARENT     0x00000080
#define WKD_BEHAVIOR_PARENT_CHILD_MISMATCH 0x00000100
#define WKD_BEHAVIOR_SCRIPT_HOST            0x00000200
#define WKD_BEHAVIOR_CLIPBOARD              0x00000400  // 剪贴板窃取命令行/镜像名（T1115，迁移自 SS ClipboardMonitor）
#define WKD_BEHAVIOR_OBFUSCATED             0x00000800  // 混淆检测（^/%/` 计数 + iex/char 拼接，迁移自 SS CommandLineParser）
#define WKD_BEHAVIOR_HIDDEN_WINDOW          0x00001000  // 隐藏窗口执行（-w hidden/start /min，迁移自 SS CommandLineParser）
#define WKD_BEHAVIOR_REMOTE_EXEC            0x00002000  // 远程执行（Invoke-Command/wmic /node:/psexec，迁移自 SS CommandLineParser）
#define WKD_BEHAVIOR_SUSPICIOUS_PATH        0x00004000  // 可疑路径执行（temp/appdata/recycle，迁移自 SS CommandLineParser）
#define WKD_BEHAVIOR_SCRIPT_FILE            0x00008000  // 脚本文件参数执行（.vbs/.js/.hta，迁移自 SS CommandLineParser）

    /* 句柄追踪行为标志（对齐 SS PN_BEHAVIOR_HANDLE_*，HandleTracker 迁移 2026-08）
     * 写入方：HspAnalyzeNewProcessHandles（创建时快照分析，死代码门控默认关，
     * wkd 以 Ob 回调实时检测（IocDetectHandle）为主路径）。 */
#define WKD_BEHAVIOR_HANDLE_INJECTION       0x00010000  // 持有注入能力句柄（对齐 SS PN_BEHAVIOR_HANDLE_INJECTION）
#define WKD_BEHAVIOR_HANDLE_CRED_ACCESS     0x00020000  // 持有凭证访问句柄（对齐 SS PN_BEHAVIOR_HANDLE_CRED_ACCESS）
#define WKD_BEHAVIOR_HANDLE_TOKEN_STEAL     0x00040000  // 持有令牌窃取句柄（对齐 SS PN_BEHAVIOR_HANDLE_TOKEN_STEAL）

    /* 环境变量监控预留（ShadowStrike EnvironmentMonitor 迁移 2026-08）
     * 0x00080000 首位置已被堆喷占用（见下），剩余 0x00100000-0x0F000000
     * 12 位空闲。SS 侧由 EmFlags 映射为 PN_BEHAVIOR_ENV_DLL_HIJACK/
     * PN_BEHAVIOR_ENV_ENCODED_VALUE；wkd 环境分析在 agent 用户态完成
     * (IpeAnalyzeEnvironment, IOC/IocProcessEnrich)，此处仅预留供未来
     * agent 同步反馈回写阻断（当前无写入者，死代码标注）。 */

    /* 堆喷分配风暴（HeapSpray 迁移 2026-08，bit20）
     * 写入方：ShpUpdateHeapSprayProfile（SyscallHijack.c，死代码门控）；
     * 消费方：IocEngine 评分链路（AeReportIndicatorPair 上报
     * TsIndicator_Injection_HeapSpray 0x0306）。 */
#define WKD_BEHAVIOR_HEAP_SPRAY             0x00080000

    /* WSL/容器逃逸（迁移自 SS WSLMonitor 2026-08）
     * 0x10000000 独立位（bit28），避开 0x80000 起环境预留段。
     * 写入方：IocProcess.c §3.3 IocpDetectWsl（活代码）；读取方：
     *   - 进程创建父链判定（同 §3.3）
     *   - 文件访问逃逸检测（IocProcess.c §9 IocpCheckWslFileAccess，死代码） */
#define WKD_BEHAVIOR_WSL_PROCESS            0x10000000

    // 签名验证
    BOOLEAN IsSignatureValid;            // 对齐 PhantomSensor IsSignatureValid

    // 运行时 DEP 状态（迁移自 ShadowStrike PapAnalyzeSecurityMitigations）
    BOOLEAN DepEnabled;                  // ProcessExecuteFlags & MEM_EXECUTE_OPTION_DISABLE

    // 进程 Ghosting 检测（T1055.013）
    BOOLEAN IsGhostingDetected;          // 对齐 PhantomSensor PhHollowing_Ghosting

    // PPL（Protected Process Light）保护级（2026-08-09 D6，进程创建回调采集）
    // 低 4 位 Type（PS_PROTECTED_TYPE：0=None/1=PPL/2=Full），高 4 位 Signer
    // （PS_PROTECTED_SIGNER：WinSystem/Lsa/Antimalware/...）。0 = 非保护进程。
    // 对齐 SS ShadowStrikeValidateProcessSignature 的 ProcessProtectionInformation 段，
    // 采集自 PsGetProcessProtection（EPROCESS->Protection）。消费点（Exempts 判定
    // / L1 参考）标注未来。
    PS_PROTECTION PplProtection;

    // 安全画像（Pap 句柄防护，2026-09-05 架构重构：自全局集中缓存下沉为进程自述元数据）
    // 打包载荷（单 32 位对齐原子读，OB 回调 DISPATCH 无锁判定）：
    //   Bit 0-7    WKD_PAP_PROCESS_CATEGORY（0=Unknown）
    //   Bit 8-15   WKD_PAP_PROTECTION_LEVEL（0=None）
    //   Bit 16-31  保留（预留进程级访问策略覆盖位）
    // 写入方：IocAnalysisProcess §2.5（进程创建回调，SecurityContext->Lock 独占域内）；
    //         管理面 PapAddProtectedProcess / PapRemoveProtectedProcess（动态添加受保护程序）。
    // 读取方：CbpAuditProcessAccess / PapIsProcessProtected / PapGetProcessProtection
    //         （32 位打包原子读，任意 IRQL 无锁，DISPATCH 判定 O(1) 直达）。
    volatile ULONG PapProfile;
} WKD_SECURITY_CONTEXT, * PWKD_SECURITY_CONTEXT;

//
// 安全画像打包/解包位段（见 WKD_SECURITY_CONTEXT.PapProfile 注释）。
// 本头不引用 WKD_PAP_* 枚举类型（保持无 Process/Pap 反向依赖），
// 编解码由调用方以 ULONG 强转枚举值完成。
//
#define WKD_PAP_PROFILE_SHIFT_CATEGORY  0
#define WKD_PAP_PROFILE_MASK_CATEGORY   0x000000FFUL
#define WKD_PAP_PROFILE_SHIFT_LEVEL     8
#define WKD_PAP_PROFILE_MASK_LEVEL      0x0000FF00UL
#define WKD_PAP_PROFILE_TO_VALUE(Category, Level) \
    ((((ULONG)(Category)) << WKD_PAP_PROFILE_SHIFT_CATEGORY) | \
     (((ULONG)(Level)) << WKD_PAP_PROFILE_SHIFT_LEVEL))

//
// 事件抑制结构体（进程内嵌，用于 Tier 1 生产者侧无锁抑制）
//
#define WKD_SYSCALL_SUPPRESS_WINDOW_MS  50

typedef struct _WKD_SYSCALL_SUPPRESSION {
    volatile HANDLE         LastTargetProcessId;
    volatile ULONG          LastSyscallNumber;
    volatile LARGE_INTEGER  LastTimestamp;
    volatile ULONG          SuppressedCount;
    volatile ULONG          TotalEvents;
} WKD_SYSCALL_SUPPRESSION, *PWKD_SYSCALL_SUPPRESSION;

//
// 逐进程区段映射画像（PreAcquireSection 迁移 2026-08）
// 内嵌于 WKD_PROCESS，随进程退出统一回收（值类型，无独立分配）。
// 支撑空心化/反射加载/快速映射检测的进程级窗口计数与行为标志。
// 标志值对齐 PreAcquireSection.c PAS_BEHAVIOR_*。
//
typedef struct _WKD_PAS_PROCESS_PROFILE {
    volatile UINT64   TotalMappings;      /* 总映射计数（历史累计） */
    volatile UINT64   ExecutableMappings; /* 可执行映射计数 */
    volatile UINT64   ImageMappings;      /* SEC_IMAGE 映射计数 */
    volatile UINT64   SuspiciousMappings; /* 可疑映射计数 */
    volatile UINT64   BlockedMappings;    /* 阻断映射计数 */
    volatile LONG     RecentMappings;     /* 1s 窗口映射数 */
    volatile LONG     RecentExecutables;  /* 1s 窗口可执行映射数 */
    LARGE_INTEGER     WindowStartTime;    /* 窗口起点（继承 CreateTime） */
    volatile LONG     BehaviorFlags;      /* PAS_BEHAVIOR_* 位图 */
    volatile LONG     SuspicionScore;     /* 进程级峰值可疑分（0-100） */
    volatile BOOLEAN  IsEarlyProcess;     /* 创建后 5s 内（空心化窗口） */
    volatile BOOLEAN  IsHollowingSuspect;
    volatile BOOLEAN  IsInjectionSuspect;
    volatile BOOLEAN  IsReflectiveSuspect;
} WKD_PAS_PROCESS_PROFILE, *PWKD_PAS_PROCESS_PROFILE;

//
// 逐进程堆喷画像（HeapSpray 迁移 2026-08）
// 内嵌于 WKD_PROCESS，随进程退出统一回收（值类型，无独立分配）。
// 支撑分配风暴轻量预判: 5s 窗口计数 (对齐 SS HsRecordAllocation 窗口) +
// 阈值命中 → BehaviorFlags 置位 + AeReportIndicatorPair 上报
// TsIndicator_Injection_HeapSpray (0x0306, 预登记槽位激活)。
// ※ 死代码: 依赖 SmInitialize 启用 (WkdEntry.c:261 注释态), syscall 管线
//   恢复后由 ShpProcessExitAllocateMemory (SyscallHijack.c) 调用
//   ShpUpdateHeapSprayProfile 驱动。
//
typedef struct _WKD_HEAP_SPRAY_PROFILE {
    volatile LONG     RecentAllocations;      /* 5s 窗口分配计数 */
    LARGE_INTEGER     WindowStartTime;        /* 窗口起点 (继承 CreateTime) */
    volatile ULONG64  TotalAllocatedSize;     /* 窗口内总字节 */
    volatile LONG     AlignedAllocations;     /* 窗口内对齐分配 (addr & 0xFFFF == 0) */
    volatile LONG     ExecutableAllocations;  /* 窗口内可执行保护分配 */
    volatile BOOLEAN  ThresholdHit;           /* 已命中阈值 (防重复上报) */
} WKD_HEAP_SPRAY_PROFILE, *PWKD_HEAP_SPRAY_PROFILE;

//
// 逐进程内存区域追踪状态（MemoryMonitor 迁移 2026-08）
// 内嵌于 WKD_PROCESS，随进程退出由 PspDestroyProcess → WkdMemRegionCleanupProcess
// 统一回收（区域节点为动态链表，须遍历释放）。
// 区域节点（WKD_MEM_REGION，Memory/MemoryRegion.h）由 MemoryRegion.c 管理，
// 此处仅声明链表头/锁/计数与风险统计（对齐 SS MM_PROCESS_CONTEXT 子集）。
// 支撑 4 类内存事件预判（RWX 初始分配/W→X 解包/Image 区早期 RWX 镂空/
// 跨进程注入标记）与 MemoryRiskScore 0-1000 聚合。
// ※ 死代码: 依赖 SmInitialize 启用 (WkdEntry.c:261 注释态), syscall 管线
//   恢复后由 SyscallHijack.c 内存 case 调用 WkdMemRegionTrack* 驱动。
//
typedef struct _WKD_MEM_REGION_STATE {
    HANDLE            ProcessId;               /* 所属进程（区域节点复用） */
    LIST_ENTRY        RegionList;              /* 区域链表（WKD_MEM_REGION 节点） */
    EX_PUSH_LOCK      RegionLock;              /* 区域锁（APC_LEVEL） */
    volatile LONG     RegionCount;             /* 活跃区域数 */
    volatile LONG     ShellcodeDetectionCount; /* Shellcode 检测计数（×200） */
    volatile LONG     InjectionAttemptCount;   /* 注入尝试计数（×300） */
    volatile LONG64   SuspiciousOperations;    /* 可疑操作计数（×10） */
    volatile LONG     MemoryRiskScore;         /* 0-1000（对齐 SS MmpUpdateProcessRisk） */
    volatile LONG     Flags;                   /* WKD_MEM_PROCESS_FLAG_* */
} WKD_MEM_REGION_STATE, *PWKD_MEM_REGION_STATE;

// 进程级内存标志（对齐 SS MM_PROCESS_FLAG_*）
#define WKD_MEM_PROCESS_FLAG_HOLLOWING_TARGET  0x00000001  // Image 区早期 RWX（镂空指示器）
#define WKD_MEM_PROCESS_FLAG_INJECTION_TARGET  0x00000002  // 注入目标
#define WKD_MEM_PROCESS_FLAG_INJECTION_SOURCE  0x00000004  // 注入源

//
// 核心进程结构体（类似 KPROCESS）
// 仅包含进程最核心、最基础的信息
// 在进程终止后需要保留的数据应放在这里
//
typedef struct _WKD_KPROCESS {
    // 标识信息
    HANDLE ProcessId;                   // 进程 ID
    HANDLE ParentProcessId;             // 父进程 ID（CreateInfo->ParentProcessId）
    HANDLE CreatorProcessId;            // 真实创建者 PID（CreateInfo->CreatingThreadId.UniqueProcess）
    
    // 时间信息
    LARGE_INTEGER CreateTime;           // 创建时间（QuadPart）
    LARGE_INTEGER ExitTime;             // 退出时间（0 = 未退出）
    
    // 内核对象引用
    PEPROCESS EProcess;                 // EPROCESS 对象指针 (保持引用计数，进程终止时需要释放引用)
    
    // 核心路径信息（延迟释放时需要保留）
    PUNICODE_STRING ImagePath;          // 镜像路径（需自行释放）
    
    // 生命周期状态
    volatile BOOLEAN Alive;
    BOOLEAN Audited;                    // 是否已审计
    
} WKD_KPROCESS, * PWKD_KPROCESS;

//
// 扩展进程结构体（类似 EPROCESS）
// 包含完整的安全上下文、行为分析等扩展信息
// 进程终止时可以释放这些扩展信息
//
typedef struct _WKD_PROCESS {
    // 核心数据（嵌入式，非指针）
    WKD_KPROCESS Core;                  // 嵌入核心进程数据

    // 扩展信息（进程终止时可释放）
    PUNICODE_STRING CommandLine;         // 命令行参数

    // 分析引擎上下文（进程本体属性；IOC/IOA/评分上下文已迁至进程对）
    PWKD_SECURITY_CONTEXT SecurityContext;
    PWKD_THREAD_CONTEXT ThreadContext;  // 线程追踪上下文（ThreadNotify 模块管理）
    PWKD_MODULE_CONTEXT ModuleContext;  // 模块追踪上下文（ImageNotify 模块管理）

    WKD_SYSCALL_SUPPRESSION SyscallSuppression;  // 事件抑制状态（内嵌，无需单独分配）
    WKD_PAS_PROCESS_PROFILE SectionMapProfile;   // 区段映射画像（PreAcquireSection 迁移 2026-08，内嵌值类型）
    WKD_HEAP_SPRAY_PROFILE HeapSprayProfile;     // 堆喷画像（HeapSpray 迁移 2026-08，内嵌值类型）
    WKD_MEM_REGION_STATE MemRegionState;         // 内存区域追踪（MemoryMonitor 迁移 2026-08，内嵌值类型）

    // 排除/信任标记（排除子系统 Exempts 写入，自保护/镜像免检依据）
    struct {
        ULONG Trusted : 1;      // 排除命中（CoEvaluateProcessExemption==Trusted）
        ULONG System : 1;       // 系统关键进程（保留）
        ULONG Reserved : 30;
    } SecurityFlags;

    /* 2026-08-25 锁下沉: 进程级全局推锁已删除 —
     * 推锁下沉至 PWKD_SECURITY_CONTEXT / PWKD_THREAD_CONTEXT /
     * PWKD_MODULE_CONTEXT 各自的 Lock 成员, 遵循:
     *   - LIST_ENTRY 头必须持对应上下文锁访问;
     *   - 其他字段通过 Interlocked 原子操作。
     * 子上下文为惰性指针: 无上下文即无锁需求,
     * 上下文挂载点自身以 InterlockedCompareExchangePointer 发布。 */
    LONG            RefCount;

    LIST_ENTRY      Links;
} WKD_PROCESS, *PWKD_PROCESS;

//
// 速率限流器（滑动窗口令牌桶）
// 用于进程创建防 DoS 攻击——超过上限时丢弃进程创建事件
//
#define WKD_PROCESS_CREATE_RATE_LIMIT      1000        // 每秒最多创建数
#define WKD_RATE_LIMIT_WINDOW_NS           (1000 * 10000)  // 窗口宽度（100 微秒单位 = 1 秒）

typedef struct _WKD_RATE_LIMITER {
    LARGE_INTEGER WindowStart;              // 当前窗口起始时间
    volatile ULONG Counter;                 // 当前窗口计数
    volatile ULONG64 DropCount;             // 丢弃总数
} WKD_RATE_LIMITER;

//
// 池限流器（上下文数量 + 内存上限）
//
#define WKD_PROCESS_CONTEXT_POOL_MAX        4096            // 最大进程上下文数
#define WKD_PROCESS_CONTEXT_POOL_MAX_BYTES  (4 * 1024 * 1024)  // 4MB 内存上限

typedef struct _WKD_POOL_LIMITER {
    volatile LONG ActiveContexts;          // 当前活跃上下文数
    volatile LONG ActiveMemoryBytes;    // 当前已分配内存字节数
    volatile LONG DropCount;            // 因池满丢弃总数
} WKD_POOL_LIMITER;

//
// 进程管理器全局状态
//
typedef struct _WKD_PROCESS_MONITOR {
    BOOLEAN Initialized;
    BOOLEAN ShutdownRequested;
    
    LIST_ENTRY ActiveProcessHead;
    WKD_HASH_MAP ProcessTable;
    
    EX_RUNDOWN_REF RundownRef;
    KSPIN_LOCK Lock;              // 使用自旋锁替代 FastMutex，提升短临界区性能
    
    ULONG MaxProcesses;

    struct {
        volatile LONG ActiveProcessCounter;
        volatile LONG ProcessCreations;
        volatile LONG ProcessTerminationCount;

        // 检测统计（对齐 PhantomSensor g_ProcessMonitor.Stats）
        volatile LONG EncodedCommands;
        volatile LONG DownloadCradles;
        volatile LONG ReflectiveLoads;
        volatile LONG ClipboardMatches;      // 剪贴板窃取命令行/镜像名命中（T1115，迁移自 SS ClipboardMonitor）
        volatile LONG ObfuscatedCommands;    // 混淆检测命中（迁移自 SS CommandLineParser）
        volatile LONG HiddenWindowCommands;  // 隐藏窗口执行命中（迁移自 SS CommandLineParser）
        volatile LONG RemoteExecCommands;    // 远程执行命中（迁移自 SS CommandLineParser）
        volatile LONG SuspiciousPathCommands; // 可疑路径命中（迁移自 SS CommandLineParser）
        volatile LONG ScriptFileCommands;    // 脚本文件执行命中（迁移自 SS CommandLineParser）
        volatile LONG WslProcessesDetected;  // WSL 进程追踪数（迁移自 SS WSLMonitor Stats.WslProcessesDetected）
        volatile LONG WslSuspiciousSpawns;   // WSL 子进程 spawn（对齐 SS Stats.SuspiciousSpawns）
        volatile LONG WslEscapeAttempts;     // WSL 逃逸尝试（进程+文件侧共用，对齐 SS Stats.EscapeAttemptsDetected）
        volatile LONG WslCredentialAccess;   // WSL 凭据文件访问（对齐 SS Stats.CredentialAccessAttempts）
        volatile LONG WslFileSystemCrossings; // WSL 文件系统穿越计数（对齐 SS Stats.FileSystemCrossings，§9 死代码）
    } Statistics;

    /* 防护限流 */
    WKD_RATE_LIMITER RateLimiter;           // 创建速率限流
    WKD_POOL_LIMITER PoolLimiter;           // 上下文池限流
} WKD_PROCESS_MONITOR, * PWKD_PROCESS_MONITOR;
    
//
// 全局进程管理器实例
//
extern WKD_PROCESS_MONITOR g_WkdProcessMonitor;

//
// 初始化与清理函数
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PmInitialize(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
PmCleanup(
    VOID
    );

//
// 枚举系统中已有进程并填充全局进程表
// 必须在 CbProcessNotifyInitialize() 之后调用，确保进程创建回调已注册
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PmEnumerateProcesses(
    VOID
    );

//
// 进程查找与操作函数
//
_IRQL_requires_max_(APC_LEVEL)
FORCEINLINE
PWKD_PROCESS
PsLookupWkdProcessByProcessId(
    _In_ HANDLE ProcessId
    )
{
    return CoLookupHashMapEntry(
        &g_WkdProcessMonitor.ProcessTable,
        &ProcessId, sizeof(HANDLE));
}

FORCEINLINE
LONG
PsReferenceWkdProcess(
    _Inout_ PWKD_PROCESS WkdProcess
)
{
    if (!WkdProcess) return MAXLONG;
    return InterlockedIncrement(&WkdProcess->RefCount);
}

LONG
PsDereferenceWkdProcess(
    _Inout_ PWKD_PROCESS WkdProcess
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PsNotifyProcessExit(
    _In_ const PWKD_PROCESS WkdProcess,
    _In_ NTSTATUS ExitStatus
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
PmpCheckPoolLimit(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
PmpUpdatePoolLimitOnDestroy(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PmHashMapRemove(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
PmCheckImageAnomaly(
    _In_ PWKD_PROCESS Process
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
PmCheckFileAttributes(
    _In_ PWKD_PROCESS Process
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PmCreateProcess(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

