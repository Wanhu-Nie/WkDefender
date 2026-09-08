/*++
    Process/ThreadAccessProtection.h - 线程访问防护（TAP）类型与契约

    Purpose:
        线程句柄访问（NtOpenThread/NtDuplicateObject）的检测与剥离策略类型与
        接口声明，对齐 ShadowStrike ThreadProtection.c（2089 行）裁剪迁移。

    实现位置（2026-09-05 判定逻辑整体上移）:
        运行时（g_TapRuntime）/ 判定纯函数族（Tapp*）/ 生命周期（TapInitialize /
        TapShutdown）/ 统计快照（TapGetStatistics）/ 判定入口
        （Callbacks/ObjectNotify.c::CbpAuditThreadAccess）已从原
        Process/ThreadAccessProtection.c 并入机制层 Callbacks/ObjectNotify.c，
        本文件收敛为纯类型/接口头（同 Pap 的 ProcessAccessProtection.h 形态）。
        参数直传 源/目标 wkd 对象 + OB 现场，不再经 WKD_TAP_ACCESS_REQUEST
        中转（该结构已随 .c 一并删除）。

    与 Pap（进程级）的关系:
        Pap 在机制层将线程对象映射到归属进程做进程级剥离；Tap 在进程级
        基础上叠加【线程级】危险访问判定（SS ThreadProtect 增量能力）：
        - 上下文操纵（GET/SET_CONTEXT，T1055.003 劫持）
        - APC 注入模式（SET_CONTEXT + SUSPEND_RESUME，T1055.004）
        - Suspend-Inject-Resume 模式（T1055）
        - 线程终止（T1489）
        - 模拟滥用（IMPERSONATE，T1134.001）
        - 系统线程攻击（PsIsSystemThread）
        - 自保护绕过（受保护源进程打其它受保护进程的线程）

    判定流水线（CbpAuditThreadAccess，对齐 SS TpThreadHandlePreCallback）:
        目标等级直读（归属进程 SecurityContext->PapProfile，进程创建回调 §2.5
        同步采集，先于本线程可被句柄化，不兜底）-> 自保护绕过标记 -> 分析
        （flag+打分）-> 攻击判定 -> 裁决 -> DeniedMask 输出（与 Pap/AU 剥离
        结果同槽合并，一次写回 current & ~(AUMask | PapMask | TapMask)）。
        快速路径（源 System / 内核句柄 / 白名单 / 同进程自访问）由对象回调
        统一内联完成，判定入口不再重复。

    Synchronization:
        - RundownRef（EX_RUNDOWN_REF）: 生命周期保护（OB 回调异步入口使用）
        - 判定纯函数无共享可变状态（打分/裁决为纯函数），仅统计走 Interlocked*

    生命周期（WkdEntry 编排）:
        TapInitialize（PapInitialize 之后、CbInitializeObjectNotify 之前）
        ... -> CbObjectNotifyCleanup 之后 -> TapShutdown

    Copyright (c) WkDefender Team
--*/

#pragma once

#include <ntifs.h>
#include "ProcessAccessProtection.h"   /* 复用 WKD_PAP_VERDICT / 等级 / 操作枚举 */

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 常量定义
 * ============================================================================ */

/* 打分常量（对齐 SS ThreadProtection.h TP_SCORE_*） */
#define WKD_TAP_SCORE_CONTEXT_ACCESS    25          /* GET/SET_CONTEXT 访问 */
#define WKD_TAP_SCORE_SUSPEND_ACCESS    20          /* SUSPEND_RESUME 访问 */
#define WKD_TAP_SCORE_TERMINATE_ACCESS  30          /* THREAD_TERMINATE */
#define WKD_TAP_SCORE_CROSS_PROCESS     15          /* 跨进程线程访问 */
#define WKD_TAP_SCORE_APC_PATTERN       40          /* APC 注入模式 */
#define WKD_TAP_SCORE_HIJACK_PATTERN    45          /* 上下文劫持模式 */
#define WKD_TAP_SCORE_IMPERSONATION     25          /* 线程模拟滥用 */
#define WKD_TAP_SCORE_SYSTEM_THREAD     35          /* 系统线程攻击 */
#define WKD_TAP_SCORE_SELF_PROTECT_BYPASS  50       /* 自保护绕过 */

/* 攻击类型加分（对齐 SS TppCalculateSuspicionScore switch） */
#define WKD_TAP_SCORE_ATTACK_HIJACK     20
#define WKD_TAP_SCORE_ATTACK_APC        25
#define WKD_TAP_SCORE_ATTACK_SUSPEND_INJECT 20
#define WKD_TAP_SCORE_ATTACK_TERMINATE  15
#define WKD_TAP_SCORE_ATTACK_SYSTEM     30

/* 裁决阈值（对齐 SS TP_HIGH/MEDIUM_SUSPICION_THRESHOLD） */
#define WKD_TAP_HIGH_SUSPICION_THRESHOLD    80
#define WKD_TAP_MEDIUM_SUSPICION_THRESHOLD  50

/* ============================================================================
 * 危险访问掩码（THREAD_* 位由 WDK 提供，此处仅组合）
 *
 * 对齐 ShadowStrike ThreadProtection.h：
 *   TP_DANGEROUS_TERMINATE_ACCESS / TP_DANGEROUS_INJECT_ACCESS /
 *   TP_DANGEROUS_CONTROL_ACCESS / TP_APC_INJECT_ACCESS /
 *   TP_HIJACK_ACCESS / TP_FULL_DANGEROUS_ACCESS
 * ============================================================================ */

#define WKD_TAP_TERMINATE_ACCESS        (THREAD_TERMINATE)

#define WKD_TAP_INJECT_ACCESS           (THREAD_SET_CONTEXT |    \
                                         THREAD_GET_CONTEXT |    \
                                         THREAD_SET_INFORMATION)

#define WKD_TAP_CONTROL_ACCESS          (THREAD_SUSPEND_RESUME | \
                                         THREAD_IMPERSONATE |    \
                                         THREAD_DIRECT_IMPERSONATION)

/* APC 注入位组合（SET_CONTEXT + SUSPEND_RESUME） */
#define WKD_TAP_APC_INJECT_ACCESS       (THREAD_SET_CONTEXT |    \
                                         THREAD_SUSPEND_RESUME)

/* 线程劫持位组合（GET/SET_CONTEXT + SUSPEND） */
#define WKD_TAP_HIJACK_ACCESS           (THREAD_GET_CONTEXT |    \
                                         THREAD_SET_CONTEXT |    \
                                         THREAD_SUSPEND_RESUME)

#define WKD_TAP_FULL_DANGEROUS_ACCESS   (WKD_TAP_TERMINATE_ACCESS | \
                                         WKD_TAP_INJECT_ACCESS |    \
                                         WKD_TAP_CONTROL_ACCESS)

/* ============================================================================
 * 可疑标志位枚举（对齐 SS TP_SUSPICIOUS_FLAGS 裁剪版）
 * ============================================================================ */

typedef enum _WKD_TAP_SUSPICIOUS_FLAGS {
    WkdTapSuspicious_None               = 0x00000000,
    WkdTapSuspicious_ContextAccess      = 0x00000001,   /* GET/SET_CONTEXT */
    WkdTapSuspicious_SuspendAccess      = 0x00000002,   /* SUSPEND_RESUME */
    WkdTapSuspicious_TerminateAttempt   = 0x00000004,   /* THREAD_TERMINATE */
    WkdTapSuspicious_CrossProcess       = 0x00000008,   /* 跨进程线程访问 */
    WkdTapSuspicious_APCPattern         = 0x00000020,   /* APC 注入模式 */
    WkdTapSuspicious_HijackPattern      = 0x00000040,   /* 线程劫持模式 */
    WkdTapSuspicious_Impersonation      = 0x00000080,   /* 模拟访问 */
    WkdTapSuspicious_SystemThread       = 0x00001000,   /* 系统线程目标 */
    WkdTapSuspicious_SelfProtectBypass  = 0x00000800,   /* 自保护绕过 */
} WKD_TAP_SUSPICIOUS_FLAGS, *PWKD_TAP_SUSPICIOUS_FLAGS;

/* ============================================================================
 * 攻击类型枚举（对齐 SS TP_ATTACK_TYPE 裁剪版）
 * ============================================================================ */

typedef enum _WKD_TAP_ATTACK_TYPE {
    WkdTapAttack_None               = 0,
    WkdTapAttack_ContextHijack      = 1,        /* 线程上下文劫持（T1055.003） */
    WkdTapAttack_APCInjection       = 2,        /* APC 注入（T1055.004） */
    WkdTapAttack_SuspendInject      = 3,        /* Suspend-Inject-Resume */
    WkdTapAttack_Termination        = 4,        /* 线程终止（T1489） */
    WkdTapAttack_Impersonation      = 5,        /* 模拟滥用（T1134.001） */
    WkdTapAttack_SystemThread       = 8,        /* 系统线程攻击 */
    WkdTapAttack_Unknown            = 0xFF,
} WKD_TAP_ATTACK_TYPE, *PWKD_TAP_ATTACK_TYPE;

/* ============================================================================
 * 判定结果结构（判定 -> 机制层写回；判定入口 CbpAuditThreadAccess 内部承载）
 * ============================================================================ */

typedef struct _WKD_TAP_ACCESS_RESULT {
    WKD_PAP_VERDICT Verdict;            /* 裁决（Allow/Strip/Monitor/Block） */
    ULONG SuspicionScore;               /* 可疑分（0-100） */
    ACCESS_MASK DeniedMask;             /* 待剥离位（已与 RequestedAccess 求交） */
    WKD_TAP_SUSPICIOUS_FLAGS Flags;     /* 可疑标志 */
    WKD_TAP_ATTACK_TYPE DetectedAttack; /* 攻击类型 */
    WKD_PAP_PROTECTION_LEVEL ProtectionLevel;   /* 目标保护等级（参考） */
    BOOLEAN TargetIsSystemThread;       /* 目标是系统线程 */
} WKD_TAP_ACCESS_RESULT, *PWKD_TAP_ACCESS_RESULT;

/* ============================================================================
 * 统计结构
 * ============================================================================ */

typedef struct _WKD_TAP_STATISTICS {
    volatile LONG64 TotalEvaluations;           /* 总评估次数 */
    volatile LONG64 AccessStripped;             /* 剥离次数 */
    volatile LONG64 ContextAccessAttempts;      /* 上下文操纵尝试 */
    volatile LONG64 TerminateAttempts;          /* 线程终止尝试 */
    volatile LONG64 SuspendAttempts;            /* 挂起/恢复尝试 */
    volatile LONG64 ImpersonationAttempts;      /* 模拟尝试 */
    volatile LONG64 SystemThreadAttempts;       /* 系统线程攻击 */
    volatile LONG64 APCInjectionPatterns;       /* APC 注入模式 */
    volatile LONG64 HijackPatterns;             /* 劫持模式 */
    volatile LONG64 CrossProcessAccess;         /* 跨进程访问 */
    volatile LONG64 SuspiciousOperations;       /* 可疑操作总数 */
    volatile LONG64 SelfProtectBypassAttempts;  /* 自保护绕过 */
} WKD_TAP_STATISTICS, *PWKD_TAP_STATISTICS;

/* ============================================================================
 * 公共 API
 * ============================================================================ */

//
// 初始化线程访问保护引擎。
// 须在 CbInitializeObjectNotify 之前调用（OB 回调依赖引擎就绪）。
// 失败非致命：仅丧失线程级剥离能力，不阻断加载。
// 运行环境: PASSIVE_LEVEL（可分页）
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
TapInitialize(
    VOID
    );

//
// 关闭线程访问防护运行时。
// 等待回调内判定入口（CbpAuditThreadAccess）经 rundown 排空后复位状态。
// 运行环境: PASSIVE_LEVEL（可分页）
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
TapShutdown(
    VOID
    );

//
// 查询统计快照（管理面/诊断）。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
TapGetStatistics(
    _Out_ WKD_TAP_STATISTICS* Statistics
    );

#ifdef __cplusplus
}
#endif