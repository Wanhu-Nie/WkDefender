/**************************************************/
/*                                                    */
/*  WkDefender 进程防御规避（Defensive Evasion）       */
/*  检测子系统——对外公共头                             */
/*                                                    */
/*  【唯一对外入口】Process 域之外的内核模块             */
/*  （Memory\MemoryMonitor、AnalysisEngine、           */
/*   Callbacks 等）访问进程镂空/幽灵检测公共能力时       */
/*  一律只允许包含本头，禁止直接包含                   */
/*  Process\HollowingDetector.h（内部私有头）。        */
/*                                                    */
/*  架构分层（对齐 FileSystem 域惯例）：               */
/*    Include\Process\DefensiveEvasion.h   对外公共头  */
/*    Process\HollowingDetector.{c,h}      实现       */
/*    Memory\MemoryMonitor.{c,h}           宿主编排   */
/*    AnalysisEngine\IocProcess.c          检测汇聚   */
/*                                                    */
/*  能力矩阵（MITRE ATT&CK T1055 进程注入 /           */
/*  T1186 进程 Doppelganging / 进程 Ghosting）：       */
/*    - 生命周期：PhInitialize / PhShutdown           */
/*    - 全量分析：PhAnalyzeWkdProcess（WKD_PROCESS    */
/*      权威副本，推荐）/ PsAnalyzeProcessHollowing（按 PID）/ */
/*      PsAnalyzeProcessHollowingAtCreation（创建时快速分析）          */
/*    - 快速预筛：PhQuickCheck                        */
/*    - 专项检测：PhValidateEntryPoint /              */
/*      PhCheckForDoppelganging / PhCheckForGhosting  */
/*      （注：PhCompareImageWithFile 已于 2026-09-13  */
/*       迁入 Memory 域，公共声明见                   */
/*       Include\Memory\MemoryIntegrity.h）           */
/*    - 结果与回调：PhFreeResult / PhRegisterCallback */
/*      / PhUnregisterCallback                        */
/*    - 统计：PhGetStatistics                         */
/*                                                    */
/*  Copyright (c) 2026 WkDefender                      */
/**************************************************/

#ifndef _WC_INCLUDE_PROCESS_DEFENSIVE_EVASION_H_
#define _WC_INCLUDE_PROCESS_DEFENSIVE_EVASION_H_

#include <ntifs.h>
#include <ntddk.h>

#include "WkdProcess.h" /* PWKD_PROCESS（专项检测入参，2026-09-13）；前向 typedef，无结构耦合 */

/* ============================================================================
 * 通用说明
 * ========================================================================== */
/* 本头为 HollowingDetector 子系统（2026-09-13 自 Memory/ 迁入 Process/ 进程域）
 * 的公共导出面：全部对外类型、常量、枚举与函数声明均定义于此。
 * 原 Process\HollowingDetector.h 已瘦身为内部兼容壳（含本头）。               */

#ifdef __cplusplus
extern "C" {
#endif

#pragma warning(push)
#pragma warning(disable:4324) /* 对齐结构体填充警告 */

/* ============================================================================
 * 一、池标签与配置常量
 * ========================================================================== */

/* 池标签：检测器上下文（Process Hollowing 域） */
#define PH_POOL_TAG_CONTEXT     'CXHP'
/* 池标签：分析结果缓冲（PhFreeResult 以同标签释放） */
#define PH_POOL_TAG_RESULT      'ERHP'
/* 池标签：临时读写缓冲 */
#define PH_POOL_TAG_BUFFER      'FBHP'

/* 单次全量分析超时上限（毫秒） */
#define PH_SCAN_TIMEOUT_MS              30000
/* 内存与磁盘文件比对的最大区段长度（字节） */
#define PH_MAX_SECTION_COMPARE_SIZE     (64 * 1024)

/* ============================================================================
 * 二、镂空/规避类型枚举
 * ========================================================================== */

/* 检测出的进程镂空/规避技术类型 */
typedef enum _PH_HOLLOWING_TYPE {
    PhHollowing_None = 0,               /* 未检测到镂空 */
    PhHollowing_Classic,                /* 经典进程镂空（WriteProcessMemory 覆写代码段） */
    PhHollowing_Doppelganging,          /* 进程 Doppelganging（NTFS 事务文件中映射镜像） */
    PhHollowing_Herpaderping,           /* 进程 Herpaderping（写入后改写磁盘映像） */
    PhHollowing_Ghosting,               /* 进程 Ghosting（删除磁盘文件后创建） */
    PhHollowing_Overwriting,            /* 进程覆写（合法镜像加载后覆写代码） */
    PhHollowing_Phantom,                /* Phantom DLL 镂空（无实体文件的映射劫持） */
    PhHollowing_ModuleStomping,         /* 模块践踏（可执行模块内存复用） */
    PhHollowing_TransactionHollow,      /* 事务化镂空（TxF 事务叠加镂空） */
} PH_HOLLOWING_TYPE, *PPH_HOLLOWING_TYPE;

/* ============================================================================
 * 三、检测指标位
 * ========================================================================== */

/* 检测指标位图（可按位组合，用于评估可信度/严重度评分） */
typedef enum _PH_INDICATORS {
    PhIndicator_None                    = 0x00000000,   /* 无指标 */
    PhIndicator_ImagePathMismatch       = 0x00000001,   /* PEB 声明路径与实际镜像路径不一致 */
    PhIndicator_SectionMismatch         = 0x00000002,   /* 内存区段内容与磁盘文件不一致 */
    PhIndicator_EntryPointModified      = 0x00000004,   /* 入口点被篡改 */
    PhIndicator_HeaderModified          = 0x00000008,   /* PE 头被修改 */
    PhIndicator_UnmappedMainModule      = 0x00000010,   /* 主模块未映射 */
    PhIndicator_TransactedFile          = 0x00000020,   /* 检测到 TxF 事务文件 */
    PhIndicator_DeletedFile             = 0x00000040,   /* 后备文件已被删除 */
    PhIndicator_SuspiciousThread        = 0x00000080,   /* 创建时即挂起的可疑线程 */
    PhIndicator_ModifiedPEB             = 0x00000100,   /* PEB 被篡改 */
    PhIndicator_HiddenMemory            = 0x00000200,   /* 隐藏内存区域 */
    PhIndicator_NoPhysicalFile          = 0x00000400,   /* 磁盘上无对应实体文件 */
    PhIndicator_HashMismatch            = 0x00000800,   /* 文件哈希不一致 */
    PhIndicator_TimestampAnomaly        = 0x00001000,   /* 时间戳异常 */
    PhIndicator_SectionCreation         = 0x00002000,   /* 可疑 Section 创建 */
    PhIndicator_MemoryProtection        = 0x00004000,   /* RWX 内存区域 */
} PH_INDICATORS;

/* ============================================================================
 * 四、进程分析结果结构
 * ========================================================================== */

/* 单次进程镂空全量分析的结果（PhAnalyzeWkdProcess / PsAnalyzeProcessHollowing /
 * PsAnalyzeProcessHollowingAtCreation 输出，调用方以 PhFreeResult 释放） */
typedef struct _PH_ANALYSIS_RESULT {
    //
    // 检测概要
    //
    BOOLEAN HollowingDetected;          /* 是否判定为镂空 */
    PH_HOLLOWING_TYPE Type;             /* 镂空类型（见 PH_HOLLOWING_TYPE） */
    PH_INDICATORS Indicators;           /* 命中的指标位组合 */
    ULONG ConfidenceScore;              /* 可信度评分 0-100 */
    ULONG SeverityScore;                /* 严重度评分 0-100 */

    //
    // 进程信息
    //
    HANDLE ProcessId;                   /* 目标进程 PID */
    PUNICODE_STRING ClaimedImagePath;   /* PEB 宣称的镜像路径（CoCopyUnicodeString 分配，CoFreeUnicodeStringSafe 释放，2026-09-13） */
    PUNICODE_STRING ActualImagePath;    /* 实际镜像路径（权威副本/SeLocateProcessImageName 采集，所有权同上） */
    PUNICODE_STRING ProcessName;        /* 进程名（所有权同上） */

    //
    // 内存与磁盘镜像比对
    //
    struct {
        PVOID MemoryBase;               /* 内存镜像基址 */
        SIZE_T MemorySize;              /* 内存镜像大小 */
        UCHAR MemoryHash[32];           /* 内存镜像 SHA-256 */
        PVOID FileBase;                 /* 文件映射基址 */
        ULONG64 FileSize;               /* 文件大小 */
        UCHAR FileHash[32];             /* 文件 SHA-256 */
        BOOLEAN HashMatch;              /* 哈希是否一致 */
        ULONG MismatchOffset;           /* 首个不一致偏移 */
        SIZE_T MismatchSize;            /* 不一致区域大小 */
        ULONG ComparedSectionCount;     /* 参与比对的只读节数量（模块链节表驱动，2026-09-13） */
        ULONG SkippedSectionCount;      /* 跳过的可写节数量（运行期合法写，防误报） */
    } ImageComparison;

    //
    // 入口点分析
    //
    struct {
        PVOID DeclaredEntryPoint;       /* PE 头声明的入口点 */
        PVOID ActualEntryPoint;         /* 内存中的实际入口点 */
        BOOLEAN EntryPointValid;        /* 入口点合法性 */
        BOOLEAN EntryPointExecutable;   /* 入口点是否位于可执行区域 */
        BOOLEAN EntryPointInImage;      /* 入口点是否位于镜像范围内 */
    } EntryPoint;

    //
    // Section（后备文件）分析
    //
    struct {
        BOOLEAN HasBackingFile;         /* 是否存在后备文件 */
        BOOLEAN FileIsTransacted;       /* 后备文件是否处于事务中 */
        BOOLEAN FileIsDeleted;          /* 后备文件是否已删除 */
        BOOLEAN FileIsLocked;           /* 后备文件是否被独占锁定 */
        PUNICODE_STRING BackingFileName;/* 后备文件全路径（CoCopyUnicodeString 分配，2026-09-13） */
    } Section;

    //
    // PEB 篡改分析
    //
    struct {
        BOOLEAN PebModified;            /* PEB 整体被修改 */
        BOOLEAN ImageBaseModified;      /* ImageBaseAddress 被修改 */
        BOOLEAN ProcessParametersModified; /* 进程参数块被修改 */
        BOOLEAN CommandLineModified;    /* 命令行被修改 */
    } PEB;

    //（原 Memory 内存区域统计结构已于 2026-09-13 删除：VAD 枚举统一由
    //  Memory\MemoryRegion 侧提供（WkdMemRegionBuildVadMap 等），
    //  HollowingDetector 不再自持区域遍历与统计）*/

    //
    // 时序信息
    //
    LARGE_INTEGER ProcessCreateTime;    /* 进程创建时间 */
    LARGE_INTEGER FirstThreadCreateTime; /* 首个线程创建时间 */
    LARGE_INTEGER AnalysisTime;         /* 分析起始时间 */
    ULONG AnalysisDurationMs;           /* 分析耗时（毫秒） */

} PH_ANALYSIS_RESULT, *PPH_ANALYSIS_RESULT;

/* ============================================================================
 * 五、检测器配置结构
 * ========================================================================== */

/* 进程镂空检测器（不透明句柄，由 PhInitialize 创建；内部实现见
 * HollowingDetector.c 的 PH_DETECTOR_INTERNAL，本结构为公共可见头部） */
typedef struct _PH_DETECTOR {
    //
    // 配置项
    //
    struct {
        BOOLEAN CompareWithFile;        /* 是否执行内存与磁盘文件比对 */
        BOOLEAN AnalyzePEB;             /* 是否分析 PEB 篡改 */
        BOOLEAN AnalyzeEntryPoint;      /* 是否校验入口点 */
        BOOLEAN AnalyzeMemoryRegions;   /* 已弃用（2026-09-13）：内存区域枚举统一由
                                           Memory\MemoryRegion 侧提供，保留字段仅为
                                           公共 API 兼容，置位不再驱动 Hollowing 分析 */
        BOOLEAN CompareWritableSections; /* 可写节是否参与磁盘比对（默认 FALSE=跳过，
                                            .data 等运行期合法写防误报；2026-09-13） */
        ULONG TimeoutMs;                /* 单次分析超时 */
        ULONG MinConfidenceToReport;    /* 触发回调上报的最低可信度 */
    } Config;

    //
    // 统计信息（近似值：单字段原子，跨字段一致性不保证）
    //
    struct {
        volatile LONG64 ProcessesAnalyzed;  /* 已分析进程数 */
        volatile LONG64 HollowingDetected;  /* 镂空检出数 */
        volatile LONG64 DoppelgangingDetected; /* Doppelganging 检出数 */
        volatile LONG64 GhostingDetected;   /* Ghosting 检出数 */
        LARGE_INTEGER StartTime;            /* 检测器启动时间 */
    } Stats;

} PH_DETECTOR, *PPH_DETECTOR;

/* ============================================================================
 * 六、检测回调类型
 * ========================================================================== */

/* 镂空确认回调：当判定结果可信度达到阈值时在 PASSIVE_LEVEL 以共享锁调用 */
typedef VOID (*PH_DETECTION_CALLBACK)(
    _In_ PPH_ANALYSIS_RESULT Result,    /* 分析结果（仅回调期间有效，勿跨线程保存） */
    _In_opt_ PVOID Context              /* 注册时携带的上下文 */
    );

/* ============================================================================
 * 七、WKD_PROCESS 前向声明
 * ========================================================================== */
/* 完整定义见 Process\ProcessMonitor.h（PowerMonitor 权威进程副本）。
 * 本头仅保留结构体标记前向声明，不 typedef —— 避免与 ProcessMonitor.h 的
 * PWKD_PROCESS 重复 typedef 触发 C2371。                                    */
struct _WKD_PROCESS;

/* ============================================================================
 * 八、公共 API：生命周期
 * ========================================================================== */

/*++
 * PhInitialize
 *   创建进程镂空检测器实例（池分配 + C-1/CAS 状态机初始化）。
 *   失败返回 NTSTATUS 且 *Detector 保持 NULL。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PhInitialize(
    _Out_ PPH_DETECTOR* Detector        /* 输出：检测器实例 */
    );

/*++
 * PhShutdown
 *   销毁检测器：置 SHUTTING_DOWN 状态、等待在途操作退出、释放回调与实例。
 *   线程安全：此后任何分析入口返回 STATUS_DEVICE_NOT_READY。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PhShutdown(
    _Inout_ PPH_DETECTOR Detector       /* 检测器实例 */
    );

/* ============================================================================
 * 九、公共 API：全量检测
 * ========================================================================== */

/*++
 * PhAnalyzeWkdProcess
 *   基于 WKD_PROCESS 权威副本的全量镂空分析（推荐入口，2026-09-13 新增）：
 *     - 进程标识直接取自 WkdProcess->Core（ProcessId / EProcess），
 *       免去 PsLookupProcessByProcessId 二次查找；
 *     - 镜像路径复用 WkdProcess->Core.ImagePath，免去 SeLocateProcessImageName；
 *     - 分析窗口内经 ObReferenceObjectSafe 额外持引用防退出竞态；
 *     - 不回写 WkdProcess->SecurityContext->IsGhostingDetected（该字段由
 *       AnalysisEngine\IocProcess.c 独占维护）。
 *   分析期间调用方必须持有 WkdProcess 引用，不得释放。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PhAnalyzeWkdProcess(
    _In_ PPH_DETECTOR Detector,         /* 检测器实例 */
    _In_ struct _WKD_PROCESS* WkdProcess, /* WKD_PROCESS 权威副本 */
    _Out_ PPH_ANALYSIS_RESULT* Result   /* 输出：全量分析结果（PhFreeResult 释放） */
    );

/*++
 * PsAnalyzeProcessHollowing
 *   按 PID 的全量镂空分析（兼容原 SS API；持有 WKD_PROCESS 副本的调用方
 *   应优先使用 PhAnalyzeWkdProcess）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PsAnalyzeProcessHollowing(
    _In_ PPH_DETECTOR Detector,         /* 检测器实例 */
    _In_ HANDLE ProcessId,              /* 目标进程 PID */
    _Out_ PPH_ANALYSIS_RESULT* Result   /* 输出：全量分析结果（PhFreeResult 释放） */
    );

/*++
 * PsAnalyzeProcessHollowingAtCreation
 *   进程创建时刻的快速全量分析（在进程创建回调中调用，Process 已持引用；
 *   免去句柄查找，直接使用回调下发的 PEPROCESS）。典型用于
 *   MemoryMonitor 的创建时检测路径。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PsAnalyzeProcessHollowingAtCreation(
    _In_ PPH_DETECTOR Detector,         /* 检测器实例 */
    _In_ HANDLE ProcessId,              /* 目标进程 PID */
    _In_ HANDLE ParentId,               /* 父进程 PID */
    _In_ PEPROCESS Process,             /* 进程创建回调下发的 EPROCESS（持引用） */
    _Out_ PPH_ANALYSIS_RESULT* Result   /* 输出：全量分析结果（PhFreeResult 释放） */
    );

/*++
 * PhQuickCheck
 *   快速预筛：仅执行轻量检查（Section/路径/EP 初判），不执行内存比对。
 *   命中可疑时建议调用 PsAnalyzeProcessHollowing 做全量确认。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PhQuickCheck(
    _In_ PPH_DETECTOR Detector,         /* 检测器实例 */
    _In_ HANDLE ProcessId,              /* 目标进程 PID */
    _Out_ PBOOLEAN IsHollowed,          /* 输出：是否疑似镂空 */
    _Out_opt_ PPH_HOLLOWING_TYPE Type,  /* 输出（可选）：疑似镂空类型 */
    _Out_opt_ PULONG Score              /* 输出（可选）：快速评分 */
    );

/* ============================================================================
 * 十、公共 API：专项检测
 * ========================================================================== */

/*++
 * PhValidateEntryPoint
 *   校验目标进程入口点（PE 头声明 vs 内存实际）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PhValidateEntryPoint(
    _In_ PPH_DETECTOR Detector,         /* 检测器实例 */
    _In_ HANDLE ProcessId,              /* 目标进程 PID */
    _Out_ PBOOLEAN Valid                /* 输出：入口点是否有效 */
    );

/*++
 * PhCheckForDoppelganging
 *   专项检测：进程 Doppelganging（事务文件信号）。
 *   2026-09-13 改用 WKD_PROCESS 权威副本（免打开进程 / SeLocate
 *   路径采集——Core.ImagePath 为登记时权威映像路径）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PhCheckForDoppelganging(
    _In_ PPH_DETECTOR Detector,         /* 检测器实例 */
    _In_ PWKD_PROCESS WkdProcess,       /* 目标进程权威副本 */
    _Out_ PBOOLEAN IsDoppelganging      /* 输出：是否命中 Doppelganging */
    );

/*++
 * PhCheckForGhosting
 *   专项检测：进程 Ghosting（无实体文件信号）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PhCheckForGhosting(
    _In_ PPH_DETECTOR Detector,         /* 检测器实例 */
    _In_ PWKD_PROCESS WkdProcess,       /* 目标进程权威副本 */
    _Out_ PBOOLEAN IsGhosting           /* 输出：是否命中 Ghosting */
    );

/* ============================================================================
 * 十一、公共 API：回调管理
 * ========================================================================== */

/*++
 * PhRegisterCallback
 *   注册镂空确认回调（最多 PH_MAX_CALLBACKS 个；在共享回调锁下执行）。
 *--*/
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
PhRegisterCallback(
    _In_ PPH_DETECTOR Detector,         /* 检测器实例 */
    _In_ PH_DETECTION_CALLBACK Callback,/* 回调函数 */
    _In_opt_ PVOID Context              /* 回调上下文 */
    );

/*++
 * PhUnregisterCallback
 *   注销已注册的镂空确认回调。
 *--*/
_IRQL_requires_max_(APC_LEVEL)
VOID
PhUnregisterCallback(
    _In_ PPH_DETECTOR Detector,         /* 检测器实例 */
    _In_ PH_DETECTION_CALLBACK Callback /* 回调函数 */
    );

/* ============================================================================
 * 十二、公共 API：结果释放
 * ========================================================================== */

/*++
 * PhFreeResult
 *   释放 PhAnalyze* 系列 API 返回的分析结果（含内部所有缓冲区）。
 *   线程安全：可在任意 IRQL <= DISPATCH_LEVEL 由任意持有者调用一次。
 *--*/
_IRQL_requires_max_(APC_LEVEL)
VOID
PhFreeResult(
    _In_ PPH_ANALYSIS_RESULT Result     /* 分析结果 */
    );

/* ============================================================================
 * 十三、公共 API：统计
 * ========================================================================== */

/* 检测器统计快照（PhGetStatistics 输出） */
typedef struct _PH_STATISTICS {
    ULONG64 ProcessesAnalyzed;          /* 已分析进程数 */
    ULONG64 HollowingDetected;          /* 镂空检出数 */
    ULONG64 DoppelgangingDetected;      /* Doppelganging 检出数 */
    ULONG64 GhostingDetected;           /* Ghosting 检出数 */
    LARGE_INTEGER UpTime;               /* 检测器运行时长 */
} PH_STATISTICS, *PPH_STATISTICS;

/*++
 * PhGetStatistics
 *   获取检测器统计快照（原子读取各计数）。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
PhGetStatistics(
    _In_ PPH_DETECTOR Detector,         /* 检测器实例 */
    _Out_ PPH_STATISTICS Stats          /* 输出：统计快照 */
    );

#pragma warning(pop) /* 4324 */

#ifdef __cplusplus
}
#endif

#endif /* _WC_INCLUDE_PROCESS_DEFENSIVE_EVASION_H_ */