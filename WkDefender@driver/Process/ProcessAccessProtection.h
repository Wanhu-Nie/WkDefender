/*++
    Process/ProcessAccessProtection.h - 进程访问防护（类型 / 常量 / 接口定义）

    2026-09-05 三次演进后的最终形态：本文件仅为【类型与接口头】——
    判定主流程、运行时与全部实现已随"访问掩码主线"并入
    Callbacks/ObjectNotify.c（机制层），本头文件供以下消费者引用声明：
      - ThreadAccessProtection.h: 复用 WKD_PAP_VERDICT / 等级 / 操作枚举
      - IocProcess.c §2.5:       PapClassifyProcess 安全画像采集
      - WkdEntry.c:              PapInitialize / PapShutdown 生命周期编排
      - ObjectNotify.c:          判定实现（include 本头获取 DTO 与常量）

    检测能力（对齐 ShadowStrike ProcessProtection）：
        - 保护对象: LSASS（Critical）/ csrss·smss·wininit·winlogon（CriticalSystem,
          Strict）/ services·svchost（Service, Medium）/ EDR 组件（Antimalware,
          2026-09-05 起经 Pap 画像/映像名识别，含 +25 自保护绕过专项分）
        - 可疑打分（封顶 100）: 凭据转储 +40 / LSASS VM_READ +20 / 注入 +30 /
          终止 +25 / PROCESS_ALL_ACCESS 调试 +35 / 跨会话 +15 / 句柄复制链 +10 /
          快速枚举 +20（10s 窗口 > 50 次）
        - 裁决: 安全只读 Allow / >=80 Strip / >=40 按等级 / 低分按等级规则；
          Strip 按 WKD_PAP_PROTECTION_LEVEL 矩阵剥危险位（LSASS 严格模式禁
          PROCESS_VM_READ，对应 MITRE T1003）
        - 快速路径（回调内 CbpPapCheckFastPath 完成）: KernelHandle（默认关）/
          源 System(PID 4) / 60s 启动宽限 / 自访问（PEPROCESS 比较）/ EDR 组件互信

    架构演进（2026-09-05 判定逻辑上移机制层）:
        - 受保护 = WKD_SECURITY_CONTEXT.PapProfile 非零（进程创建回调 §2.5
          同步采集的打包分类/等级画像），对象解引用 O(1) 无锁直达
        - 判定主线程（目标画像 + 策略 + 打分 + 裁决 + 剥离写回）内联于
          Callbacks/ObjectNotify.c 的 CbpAuditProcessAccess（参数直传源/目标/
          OB 现场，不再经 WKD_PROCESS_ACCESS_REQUEST 中转）
        - 快速路径过滤下沉 CbpObjectNotifyPreOperationCallback（CbpPapCheckFastPath）
        - 集中缓存（CriticalProcessCache / CacheLock / RundownRef / 进程退出钩子）
          与复合引擎入口（WKD_PAP_ENGINE / PapEvaluateAccess）整段移除

    Synchronization（运行时位于 ObjectNotify.c）:
        - PolicyLock（EX_PUSH_LOCK）: 保护 AccessPolicies（管理面，PASSIVE）
        - RateLock（KSPIN_LOCK）: 保护 RateEntries（源侧限速兜底）
        - PapProfile 读写: 写入方为创建回调（SecurityContext->Lock 独占域）
          或管理面（PASSIVE 单写者）；读取方任意 IRQL 32 位打包原子读，无锁
        - wkd 进程表（PsLookupWkdProcessByProcessId）: 查找即 +1，仅限
          <= APC_LEVEL；DISPATCH 下查询类 API 降级到惰性分类兜底

    生命周期（WkdEntry 编排）:
        PapInitialize -> CbInitializeObjectNotify（机制层依赖运行时就绪）
        ... -> CbObjectNotifyCleanup -> PapShutdown

    Copyright (c) WkDefender Team
--*/

#pragma once

#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 常量定义
 * ============================================================================ */

#define WKD_PAP_POOL_TAG                'aPaW'      /* 池标签（仅在池分配时使用） */

#define WKD_PAP_MAX_POLICIES            32          /* 访问策略最大条数 */
#define WKD_PAP_MAX_RATE_ENTRIES        64          /* 速率限制器源进程槽位数 */
#define WKD_PAP_RATE_WINDOW_SECONDS     10          /* 速率限制时间窗（秒） */
#define WKD_PAP_RATE_LIMIT_THRESHOLD    50          /* 窗内操作次数阈值 */

#define WKD_PAP_PROCESS_NAME_LEN        16          /* 进程映像名最大长度（含 NUL） */

/* 关键进程映像名后缀（小写，PppCategorizeByImageName 对齐 ShadowStrike） */
#define WKD_PAP_IMAGE_LSASS             "lsass.exe"
#define WKD_PAP_IMAGE_CSRSS             "csrss.exe"
#define WKD_PAP_IMAGE_SMSS              "smss.exe"
#define WKD_PAP_IMAGE_WININIT           "wininit.exe"
#define WKD_PAP_IMAGE_WINLOGON          "winlogon.exe"
#define WKD_PAP_IMAGE_SERVICES          "services.exe"
#define WKD_PAP_IMAGE_SVCHOST           "svchost.exe"

/* ============================================================================
 * 裁决枚举
 * ============================================================================ */

typedef enum _WKD_PAP_VERDICT {
    WkdPapVerdict_Allow = 0,            /* 不修改访问 */
    WkdPapVerdict_Strip,                /* 按等级剥离危险位 */
    WkdPapVerdict_Monitor,              /* 放行但记录可疑 */
    WkdPapVerdict_Block,                /* 仅保留 SYNCHRONIZE（预留，当前不产出） */
} WKD_PAP_VERDICT, *PWKD_PAP_VERDICT;

/* ============================================================================
 * 操作类型枚举（对齐 OB_OPERATION_HANDLE_CREATE / DUPLICATE）
 * ============================================================================ */

typedef enum _WKD_PROCESS_ACCESS_OPERATION {
    WkdPapOperation_Unknown = 0,
    WkdPapOperation_Create,             /* OB_OPERATION_HANDLE_CREATE */
    WkdPapOperation_Duplicate,          /* OB_OPERATION_HANDLE_DUPLICATE */
} WKD_PROCESS_ACCESS_OPERATION, *PWKD_PROCESS_ACCESS_OPERATION;

/* ============================================================================
 * 保护等级枚举（对齐 ShadowStrike PP_PROTECTION_LEVEL）
 * ============================================================================ */

typedef enum _WKD_PAP_PROTECTION_LEVEL {
    WkdPapLevel_None = 0,               /* 不保护 */
    WkdPapLevel_Light,                  /* 仅剥终止 */
    WkdPapLevel_Medium,                 /* 剥终止 + 注入 */
    WkdPapLevel_Strict,                 /* 剥终止 + 注入 + 控制 */
    WkdPapLevel_Critical,               /* 剥全部危险位 */
    WkdPapLevel_Antimalware,            /* 剥全部危险位（EDR 组件） */
} WKD_PAP_PROTECTION_LEVEL, *PWKD_PAP_PROTECTION_LEVEL;

/* ============================================================================
 * 进程分类枚举
 * ============================================================================ */

typedef enum _WKD_PAP_PROCESS_CATEGORY {
    WkdPapCategory_Unknown = 0,
    WkdPapCategory_Lsass,               /* lsass.exe（凭据转储核心目标, T1003） */
    WkdPapCategory_CriticalSystem,      /* csrss/smss/wininit/winlogon */
    WkdPapCategory_Service,             /* services.exe / svchost.exe */
    WkdPapCategory_Antimalware,         /* EDR 组件（2026-09-05 起经 Pap 画像/映像名识别） */
} WKD_PAP_PROCESS_CATEGORY, *PWKD_PAP_PROCESS_CATEGORY;

/* ============================================================================
 * 可疑标志位枚举
 * ============================================================================ */

typedef enum _WKD_PAP_SUSPICIOUS_FLAGS {
    WkdPapSuspicious_None               = 0x0000,
    WkdPapSuspicious_CredentialAccess   = 0x0001,   /* 凭据转储模式（LSASS） */
    WkdPapSuspicious_InjectionAttempt   = 0x0002,   /* 注入位请求 */
    WkdPapSuspicious_TerminationAttempt = 0x0004,   /* 终止位请求 */
    WkdPapSuspicious_DebugAttempt       = 0x0008,   /* PROCESS_ALL_ACCESS 调试意图 */
    WkdPapSuspicious_CrossSessionAccess = 0x0010,   /* 用户会话 -> Session 0 */
    WkdPapSuspicious_DuplicationChain   = 0x0020,   /* 句柄复制操作 */
    WkdPapSuspicious_RapidEnumeration   = 0x0040,   /* 快速枚举（速率限制命中） */
    WkdPapSuspicious_SelfProtectBypass  = 0x0080,   /* 打 EDR 组件（自保护绕过） */
} WKD_PAP_SUSPICIOUS_FLAGS, *PWKD_PAP_SUSPICIOUS_FLAGS;

/* ============================================================================
 * 访问掩码常量（PROCESS_* 位由 WDK 提供，此处仅组合）
 *
 * 对齐 ShadowStrike ProcessProtection.h：
 *   PP_DANGEROUS_TERMINATE_ACCESS / PP_DANGEROUS_INJECT_ACCESS /
 *   PP_DANGEROUS_CONTROL_ACCESS / PP_CREDENTIAL_DUMP_ACCESS /
 *   PP_FULL_DANGEROUS_ACCESS
 * ============================================================================ */

#define WKD_PAP_TERMINATE_ACCESS        (PROCESS_TERMINATE)
#define WKD_PAP_INJECT_ACCESS           (PROCESS_VM_WRITE |                \
                                         PROCESS_VM_OPERATION |            \
                                         PROCESS_CREATE_THREAD)
#define WKD_PAP_CONTROL_ACCESS          (PROCESS_SUSPEND_RESUME)
#define WKD_PAP_CREDENTIAL_DUMP_ACCESS  (PROCESS_VM_READ |                 \
                                         PROCESS_QUERY_INFORMATION)
#define WKD_PAP_FULL_DANGEROUS_ACCESS   (WKD_PAP_TERMINATE_ACCESS |        \
                                         WKD_PAP_CONTROL_ACCESS |          \
                                         WKD_PAP_INJECT_ACCESS |           \
                                         PROCESS_VM_READ)
/* LSASS 严格模式追加位（防 T1003 凭据转储） */
#define WKD_PAP_LSASS_STRICT_ACCESS     (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)

/* ============================================================================
 * 前向声明：wkd 进程对象（完整定义在 Process/ProcessMonitor.h，
 * 实现 .c 侧（ObjectNotify.c）include 后即可访问 Core.EProcess / Core.ProcessId /
 * SecurityContext->SessionId；判定参数直传指针，不拷贝扁平字段）
 * ============================================================================ */

typedef struct _WKD_PROCESS *PWKD_PROCESS;

/* ============================================================================
 * 访问判定结果结构（判定 -> 机制层写回）
 *
 * DeniedMask 为判定建议剥离位；机制层与 AU 剥离结果（AUMask）union 后
 * 以 Original & ~(AUMask | DeniedMask) 一次写回。Verdict==Block 时机制层
 * 额外保留 SYNCHRONIZE。
 * ============================================================================ */

typedef struct _WKD_PROCESS_ACCESS_RESULT {
    WKD_PAP_VERDICT             Verdict;            /* 裁决 */
    ACCESS_MASK                 DeniedMask;         /* 建议剥离位（Strip/Block 有效） */
    ULONG                       SuspicionScore;     /* 打分（封顶 100） */
    WKD_PAP_SUSPICIOUS_FLAGS    Flags;              /* 命中的可疑标志位 */
    WKD_PAP_PROTECTION_LEVEL    ProtectionLevel;    /* 目标保护等级 */
    WKD_PAP_PROCESS_CATEGORY    Category;           /* 目标分类 */
} WKD_PROCESS_ACCESS_RESULT, *PWKD_PROCESS_ACCESS_RESULT;

/* ============================================================================
 * 访问策略表条目（PpAddAccessPolicy 对齐）
 * ============================================================================ */

typedef struct _WKD_PROCESS_ACCESS_POLICY {
    WKD_PAP_PROCESS_CATEGORY    Category;           /* 目标分类（按分类命中） */
    HANDLE                      ProcessId;          /* 目标 PID（按 PID 命中，0=不限） */
    ACCESS_MASK                 DeniedAccess;       /* 策略追加剥离位 */
    BOOLEAN                     InUse;              /* 槽位占用标记 */
} WKD_PROCESS_ACCESS_POLICY, *PWKD_PROCESS_ACCESS_POLICY;

/* ============================================================================
 * 配置
 * ============================================================================ */

typedef struct _WKD_PAP_CONFIG {
    BOOLEAN StrictLsassProtection;      /* LSASS 严格模式（禁 VM_READ，默认 TRUE） */
    BOOLEAN EnableKernelHandleFiltering;/* 过滤内核句柄（默认 FALSE，Windows 兼容） */
    BOOLEAN EnablePolicyEnforcement;    /* 启用访问策略表（默认 TRUE） */
    BOOLEAN LogStrippedAccess;          /* 剥离操作 DbgPrint 日志（默认 TRUE） */
    BOOLEAN TrackActivity;              /* 启用速率限制器（默认 TRUE） */
    ULONG   BootGracePeriodSeconds;     /* 启动宽限期（默认 60） */
} WKD_PAP_CONFIG, *PWKD_PAP_CONFIG;

/* ============================================================================
 * 统计（全原子计数）
 * ============================================================================ */

typedef struct _WKD_PAP_STATISTICS {
    volatile LONG64 TotalEvaluations;           /* 进入判定引擎的次数 */
    volatile LONG64 AccessStripped;             /* 发生剥离的次数 */
    volatile LONG64 TerminationAttempts;        /* 终止位剥离次数 */
    volatile LONG64 InjectionAttempts;          /* 注入位剥离次数 */
    volatile LONG64 CredentialAccessAttempts;   /* 凭据转储模式命中次数 */
    volatile LONG64 DebugAttempts;              /* PROCESS_ALL_ACCESS 调试意图次数 */
    volatile LONG64 CrossSessionAccess;         /* 跨会话访问次数 */
    volatile LONG64 RapidEnumerationDetected;   /* 快速枚举命中次数 */
    volatile LONG64 SelfProtectBypassAttempts;  /* 打 EDR 组件次数 */
    volatile LONG64 PolicyMatches;              /* 策略命中次数 */
    volatile LONG64 TotalEvaluationsDenied;     /* 最终产生剥离/阻断的评估次数 */
} WKD_PAP_STATISTICS, *PWKD_PAP_STATISTICS;

/* ============================================================================
 * 公共 API
 * ============================================================================ */

//
// 初始化进程访问保护运行时。
// 初始化锁，设定默认配置与启动时刻（宽限期基准），清空策略表/速率表。
// 必须在 CbInitializeObjectNotify（机制层注册）之前调用。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PapInitialize(
    VOID
    );

//
// 关闭进程访问保护运行时。
// 置位不初始化 -> 清空策略表/速率表。受保护判定状态不归本运行时托管
// （随 wkd_process 生命周期回收），无需排空回调入口。
// 调用前提：OB 回调已注销（CbObjectNotifyCleanup）。
// NULL 安全（对应未初始化）。运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PapShutdown(
    VOID
    );

//
// 动态添加受保护进程（管理面，对齐 ShadowStrike PpAddProtectedProcess）。
// 2026-09-05 重构：改写目标进程自述安全画像（SecurityContext->PapProfile），
// 与进程创建回调采集串行（Lock 独占域 / 管理面单写者），无并发写者。
// 供 ALPC 管理通道后续接线。实现位于 Callbacks/ObjectNotify.c。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PapAddProtectedProcess(
    _In_ HANDLE ProcessId,
    _In_ WKD_PAP_PROCESS_CATEGORY Category,
    _In_ WKD_PAP_PROTECTION_LEVEL ProtectionLevel
    );

//
// 动态移除受保护进程（管理面）。清空目标进程的安全画像（解除保护）。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PapRemoveProtectedProcess(
    _In_ HANDLE ProcessId
    );

//
// 添加访问策略（管理面，对齐 ShadowStrike PpAddAccessPolicy）。
// 策略命中时在等级剥离基础上追加 DeniedAccess。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
PapAddAccessPolicy(
    _In_ CONST WKD_PROCESS_ACCESS_POLICY* Policy
    );

//
// 移除指定分类的所有访问策略（管理面）。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PapRemovePoliciesForCategory(
    _In_ WKD_PAP_PROCESS_CATEGORY Category
    );

//
// 查询统计快照（管理面/诊断）。运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
PapGetStatistics(
    _Out_ WKD_PAP_STATISTICS* Statistics
    );

//
// 查询进程是否受保护（PEPROCESS 版）。
// 2026-09-05 重构：画像优先（wkd 表查询 SecurityContext->PapProfile，含管理面
// 动态添加）；APC_LEVEL 以下查询 wkd 表（查找即 +1 配对释放），DISPATCH 下
// 直接降级到惰性分类。供诊断与 Tap 等对受保护目标的等级参考。
// 未初始化返回 STATUS_DEVICE_NOT_READY（调用方按无保护处理）。
// 运行环境: <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
PapIsProcessProtected(
    _In_ PEPROCESS Process
    );

//
// 查询进程保护等级与分类（PEPROCESS 版，只读）。
// 画像优先（wkd 表查询，O(1) 直达）；wkd 表查询不可用或画像为空时降级到
// 惰性分类但【不写回】（查询路径零副作用）。
// 供 Tap 线程保护引擎等对受保护目标的等级参考。
// 未初始化返回 STATUS_DEVICE_NOT_READY（调用方按无保护处理）。
// 运行环境: <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
PapGetProcessProtection(
    _In_ PEPROCESS Process,
    _Out_ WKD_PAP_PROTECTION_LEVEL* Level,
    _Out_opt_ WKD_PAP_PROCESS_CATEGORY* Category
    );

//
// 进程安全分类（2026-09-05 判定逻辑上移后仍为导出接口）。
// 采集方：IocAnalysisProcess §2.5 创建回调；判定兜底：CbpAuditProcessAccess
// 目标画像为空时现场分类并回写；查询兜底：PapIsProcessProtected /
// PapGetProcessProtection 惰性分类（不写回）。
// 无锁纯计算（2026-09-05 起：Pap 画像 + PsGetProcessImageFileName 后缀匹配），
// 不触碰任何缓存/画像状态；命中返回 TRUE 与分类/等级，未命中返回 FALSE。
// 实现位于 Callbacks/ObjectNotify.c（与判定主线同层托管）。
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
PapClassifyProcess(
    _In_ PEPROCESS Process,
    _Out_ WKD_PAP_PROCESS_CATEGORY* Category,
    _Out_ WKD_PAP_PROTECTION_LEVEL* ProtectionLevel
    );

#ifdef __cplusplus
}
#endif