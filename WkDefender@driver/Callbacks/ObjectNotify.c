#include "ObjectNotify.h"
#include "../Process/ProcessMonitor.h"
#include "../Notification/NotificationManager.h"
#include "../Common/Utils.h"
#include "../Notification/AlpcService.h"
#include "../Process/ProcessPairContext.h"
#include "../Notification/MessageSync.h"
#include "../AnalysisEngine/IocEngine.h"
#include "../AnalysisEngine/AnalysisEngine.h"
#include "../Common/Exempts/Exempts.h"
#include "../SelfProtection/SelfProtectionEngine.h"   /* 自防护引擎：防卸载句柄访问剥离（经引擎暴露接口调用） */
#include "../Process/ProcessAccessProtection.h"       /* Pap 进程访问保护引擎（机制/策略解耦：本文件为机制层） */
#include "../Process/ThreadAccessProtection.h"        /* Tap 线程访问保护引擎（线程级剥离，2026-09-05） */
//
// 未文档化 API 声明 — PsGetProcessImageFileName
// 返回 EPROCESS 内部 15 字节 ANSI 缓冲区（非 PUNICODE_STRING）
//
NTKERNELAPI PUCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

//
// 检查目标进程是否为 LSASS
//
static
BOOLEAN
ObjpIsLsassProcess(
    _In_ PEPROCESS TargetProcess
    )
{
    HANDLE processId = PsGetProcessId(TargetProcess);
    PUCHAR imageName = PsGetProcessImageFileName(TargetProcess);

    /* PID 启发式：常见 LSASS PID */
    if (HandleToULong(processId) == 0x4E0 ||
        HandleToULong(processId) == 0x2E0 ||
        HandleToULong(processId) == 0x3E0) {
        return TRUE;
    }

    /* 映像名匹配 — PsGetProcessImageFileName 返回 ANSI 短名称 */
    if (imageName != NULL) {
        ANSI_STRING lsassAnsi;
        ANSI_STRING imageAnsi;
        RtlInitAnsiString(&lsassAnsi, "lsass.exe");
        imageAnsi.Buffer = (PSZ)imageName;
        imageAnsi.Length = (USHORT)strlen((const char *)imageName);
        imageAnsi.MaximumLength = imageAnsi.Length + 1;
        return RtlCompareString(&imageAnsi, &lsassAnsi, TRUE) == 0;
    }

    return FALSE;
}

/**************************************************/
/*                   全局状态                      */
/**************************************************/

static WKD_OBJECT_CALLBACK_MANAGER g_ObjManager = { 0 };

/* ============================================================================
 * Pap 进程访问防护运行时（2026-09-05 判定逻辑整体上移：与对象回调机制同层托管）
 *
 * 演进史：
 *   - WKD_PAP_ENGINE（集中式缓存建档）-> SecurityContext.PapProfile 画像判定
 *     （受保护判定状态下沉进程自述元数据）-> 本文件（判定主流程 + 运行时
 *     随"访问掩码主线"并入机制层，接口声明保留在 Process/ProcessAccessProtection.h）。
 *   - 本运行时仅含：配置 / 统计 / 全局策略表 / 源侧速率兜底；判定子工具
 *     （打分/裁决/剥离/策略/速率/日志）为无状态纯函数，签名直传源/目标/
 *     操作/掩码（不再经 WKD_PROCESS_ACCESS_REQUEST 中转）。
 *   - 生命周期与对象回调绑定：WkdEntry 编排 PapInitialize 先于
 *     CbInitializeObjectNotify 就绪，逆序 CbObjectNotifyCleanup 后 PapShutdown。
 * ============================================================================ */

/* 速率限制器条目（10 秒窗口滚动计数） */
typedef struct _WKD_PAP_RATE_ENTRY {
    HANDLE          SourceProcessId;    /* 源进程 PID */
    ULONG           Count;              /* 窗口内操作次数 */
    LARGE_INTEGER   WindowStart;        /* 窗口起点（100ns tick） */
    BOOLEAN         InUse;              /* 槽位占用标记 */
} WKD_PAP_RATE_ENTRY, *PWKD_PAP_RATE_ENTRY;

typedef struct _WKD_PAP_RUNTIME {
    volatile LONG   Initialized;        /* 初始化标志（Interlocked 访问） */

    EX_PUSH_LOCK    PolicyLock;         /* 保护 AccessPolicies */
    WKD_PROCESS_ACCESS_POLICY AccessPolicies[WKD_PAP_MAX_POLICIES];
    volatile LONG   PolicyCount;

    KSPIN_LOCK      RateLock;           /* 保护 RateEntries（源侧限速，全局兜底） */
    WKD_PAP_RATE_ENTRY RateEntries[WKD_PAP_MAX_RATE_ENTRIES];

    WKD_PAP_CONFIG      Config;         /* 配置（PASSIVE 初始化） */
    WKD_PAP_STATISTICS  Stats;          /* 统计（原子计数） */
    LARGE_INTEGER       BootTime;       /* 驱动加载时刻（启动宽限期基准） */
} WKD_PAP_RUNTIME, *PWKD_PAP_RUNTIME;

static WKD_PAP_RUNTIME g_PapRuntime;    /* 运行时唯一实例（非池分配，置零初始化） */

/* ============================================================================
 * Pap 内部辅助声明（判定子工具，静态）
 * ============================================================================ */

static VOID
CbpAnalyzeProcessAccessOperation(
    _In_ CONST PWKD_PROCESS SourceWkdProcess,
    _In_ CONST PWKD_PROCESS TargetWkdProcess,
    _In_ WKD_PROCESS_ACCESS_OPERATION Operation,
    _In_ ACCESS_MASK RequestedAccess,
    _In_ WKD_PAP_PROCESS_CATEGORY Category,
    _Out_ PULONG SuspicionScore,
    _Out_ PWKD_PAP_SUSPICIOUS_FLAGS Flags
    );

static WKD_PAP_VERDICT
PappDetermineVerdict(
    _In_ ULONG SuspicionScore,
    _In_ ACCESS_MASK RequestedAccess,
    _In_ WKD_PAP_PROTECTION_LEVEL ProtectionLevel
    );

static ACCESS_MASK
PappCalculateDeniedMask(
    _In_ WKD_PAP_PROTECTION_LEVEL ProtectionLevel,
    _In_ WKD_PAP_PROCESS_CATEGORY Category
    );

static BOOLEAN
CbpFindProcessAccessPolicy(
    _In_ WKD_PAP_PROCESS_CATEGORY Category,
    _In_ HANDLE ProcessId,
    _Out_ WKD_PROCESS_ACCESS_POLICY* OutPolicy
    );

static BOOLEAN
PappIsSourceRateLimited(
    _In_ HANDLE SourceProcessId
    );

static VOID
PappRecordSourceOperation(
    _In_ HANDLE SourceProcessId
    );

static BOOLEAN
PappMatchImageNameSuffixA(
    _In_ PCCHAR ImagePath,
    _In_ SIZE_T ImageLength,
    _In_ PCCHAR Suffix
    );

static VOID
PappLogStrippedAccess(
    _In_ CONST PWKD_PROCESS SourceWkdProcess,
    _In_ CONST PWKD_PROCESS TargetWkdProcess,
    _In_ WKD_PROCESS_ACCESS_OPERATION Operation,
    _In_ ACCESS_MASK RequestedAccess,
    _In_ CONST WKD_PROCESS_ACCESS_RESULT* Result,
    _In_ ACCESS_MASK DeniedByAumask
    );

/* ============================================================================
 * 掩码辅助（对齐 SS PpAccessAllowsInjection/Termination/MatchesCredentialDump/
 *           IsSafeReadOnly）
 * ============================================================================ */




//
// 请求位是否为安全只读（不含任何 FULL 危险位；QUERY_INFORMATION 单独不算危险）
//
static BOOLEAN
PappAccessIsSafeReadOnly(
    _In_ ACCESS_MASK Access
    )
{
    return ((Access & WKD_PAP_FULL_DANGEROUS_ACCESS) == 0);
}

//
// 当前是否处于启动宽限期（驱动加载后 BootGracePeriodSeconds 秒内）
//
static BOOLEAN
PappIsInBootGrace(
    VOID
    )
{
    LARGE_INTEGER now;
    LONGLONG elapsedTicks;

    if (g_PapRuntime.Config.BootGracePeriodSeconds == 0) {
        return FALSE;
    }

    KeQuerySystemTime(&now);
    elapsedTicks = now.QuadPart - g_PapRuntime.BootTime.QuadPart;

    return (elapsedTicks >= 0) &&
           (elapsedTicks < ((LONGLONG)g_PapRuntime.Config.BootGracePeriodSeconds * 10000000LL));
}

/* ============================================================================
 * 映像名分类（PsGetProcessImageFileName 返回 ANSI 全路径，栈拷贝后后缀匹配）
 * ============================================================================ */

//
// 后缀不敏感比较（ANSI 版，对齐 SS PppMatchImageNameSuffix 精神）
//
static BOOLEAN
PappMatchImageNameSuffixA(
    _In_ PCCHAR ImagePath,
    _In_ SIZE_T ImageLength,
    _In_ PCCHAR Suffix
    )
{
    SIZE_T suffixLength;
    SIZE_T i;

    if (ImagePath == NULL || Suffix == NULL) {
        return FALSE;
    }

    suffixLength = strlen(Suffix);
    if (ImageLength < suffixLength) {
        return FALSE;
    }

    ImagePath += (ImageLength - suffixLength);

    for (i = 0; i < suffixLength; i++) {
        CHAR c1 = ImagePath[i];
        CHAR c2 = Suffix[i];

        if (c1 >= 'A' && c1 <= 'Z') {
            c1 = (CHAR)(c1 - 'A' + 'a');
        }
        if (c2 >= 'A' && c2 <= 'Z') {
            c2 = (CHAR)(c2 - 'A' + 'a');
        }
        if (c1 != c2) {
            return FALSE;
        }
    }

    return TRUE;
}

//
// 按映像名/EDR 组件判定进程分类与保护等级（无锁纯计算，不触碰任何状态。
// 采集方：IocAnalysisProcess §2.5 创建回调；判定兜底：CbpAuditProcessAccess
// 目标画像为空时现场分类并回写；查询兜底：PapIsProcessProtected /
// PapGetProcessProtection 惰性分类（不写回））
//
BOOLEAN
PapClassifyProcess(
    _In_ PEPROCESS Process,
    _Out_ WKD_PAP_PROCESS_CATEGORY* Category,
    _Out_ WKD_PAP_PROTECTION_LEVEL* ProtectionLevel
    )
{
    PUCHAR rawPath;
    SIZE_T pathLength = 0;
    SIZE_T i;

    if (Process == NULL) {
        return FALSE;
    }

    //
    // EDR 组件判定优先。2026-09-05：AU 受保护进程体系已删除（表恒空），
    // EDR 组件 = Pap 画像（PapProfile 非零，管理面登记），由下方
    // PapIsProcessProtected / 映像名分类兜底。
    //

    //
    // 映像名分类（PsGetProcessImageFileName 返回 ANSI、以 NUL 结尾的全路径）。
    // 直接扫描长度（上限 127），不拷贝、不依赖 strsafe。
    //
    rawPath = PsGetProcessImageFileName(Process);
    if (rawPath == NULL) {
        return FALSE;
    }

    for (i = 0; i < 127; i++) {
        if (rawPath[i] == '\0') {
            pathLength = i;
            break;
        }
    }
    if (pathLength == 0) {
        return FALSE;
    }

    //
    // LSASS —— 凭据转储核心目标（Critical，T1003）
    //
    if (PappMatchImageNameSuffixA((PCCHAR)rawPath, pathLength, WKD_PAP_IMAGE_LSASS)) {
        *Category = WkdPapCategory_Lsass;
        *ProtectionLevel = WkdPapLevel_Critical;
        return TRUE;
    }

    //
    // 系统关键进程（csrss/smss/wininit/winlogon —— Strict）
    //
    if (PappMatchImageNameSuffixA((PCCHAR)rawPath, pathLength, WKD_PAP_IMAGE_CSRSS) ||
        PappMatchImageNameSuffixA((PCCHAR)rawPath, pathLength, WKD_PAP_IMAGE_SMSS) ||
        PappMatchImageNameSuffixA((PCCHAR)rawPath, pathLength, WKD_PAP_IMAGE_WININIT) ||
        PappMatchImageNameSuffixA((PCCHAR)rawPath, pathLength, WKD_PAP_IMAGE_WINLOGON)) {
        *Category = WkdPapCategory_CriticalSystem;
        *ProtectionLevel = WkdPapLevel_Strict;
        return TRUE;
    }

    //
    // 服务进程（services/svchost —— Medium）
    //
    if (PappMatchImageNameSuffixA((PCCHAR)rawPath, pathLength, WKD_PAP_IMAGE_SERVICES) ||
        PappMatchImageNameSuffixA((PCCHAR)rawPath, pathLength, WKD_PAP_IMAGE_SVCHOST)) {
        *Category = WkdPapCategory_Service;
        *ProtectionLevel = WkdPapLevel_Medium;
        return TRUE;
    }

    return FALSE;
}

/* ============================================================================
 * 打分 / 裁决 / 剥离 / 策略 / 速率 / 日志
 *
 * 2026-09-05 判定逻辑上移机制层后，签名由 WKD_PROCESS_ACCESS_REQUEST 改为
 * 直传 源进程 / 目标进程 / 操作 / 请求掩码（消除中转结构与 PapEvaluateAccess）。
 * ============================================================================ */

//
// 9 项可疑打分，封顶 100。
//
static VOID
CbpAnalyzeProcessAccessOperation(
    _In_ const PWKD_PROCESS SourceWkdProcess,
    _In_ const PWKD_PROCESS TargetWkdProcess,
    _In_ WKD_PROCESS_ACCESS_OPERATION Operation,
    _In_ ACCESS_MASK AccessMask,
    _In_ WKD_PAP_PROCESS_CATEGORY Category,
    _Out_ PULONG SuspicionScore,
    _Out_ PWKD_PAP_SUSPICIOUS_FLAGS Flags
    )
{
    ULONG score = 0;
    WKD_PAP_SUSPICIOUS_FLAGS foundFlags = WkdPapSuspicious_None;

    if (!SourceWkdProcess || !TargetWkdProcess || !Operation ||
        !SourceWkdProcess->SecurityContext || !TargetWkdProcess->SecurityContext ||
        SourceWkdProcess->SecurityContext->PapProfile == 0 ||
        TargetWkdProcess->SecurityContext->PapProfile == 0 ||
        AccessMask == 0 || !SuspicionScore || !Flags) {
        return;
    }
    *SuspicionScore = 0;
    *Flags = WkdPapSuspicious_None;

    //
    // 凭据转储模式（LSASS，T1003）：+40
    //
    if (Category == WkdPapCategory_Lsass) {

        if ((AccessMask & WKD_PAP_CREDENTIAL_DUMP_ACCESS) == WKD_PAP_CREDENTIAL_DUMP_ACCESS) {
            foundFlags |= WkdPapSuspicious_CredentialAccess;
            score += 40;
            InterlockedIncrement64(&g_PapRuntime.Stats.CredentialAccessAttempts);
        }

        //
        // 任何对 LSASS 的内存读取都高度可疑：+20
        //
        if (AccessMask & PROCESS_VM_READ) {
            score += 20;
        }
    }

    //
    // 注入位（T1055）：+30
    //
    if ((AccessMask & WKD_PAP_INJECT_ACCESS) != 0) {
        foundFlags |= WkdPapSuspicious_InjectionAttempt;
        score += 30;
    }

    //
    // 终止位（T1489）：+25
    //
    if ((AccessMask & (PROCESS_TERMINATE)) != 0) {
        foundFlags |= WkdPapSuspicious_TerminationAttempt;
        score += 25;
    }

    //
    // PROCESS_ALL_ACCESS 调试意图：+35
    //
    if ((AccessMask & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS) {
        foundFlags |= WkdPapSuspicious_DebugAttempt;
        score += 35;
        InterlockedIncrement64(&g_PapRuntime.Stats.DebugAttempts);
    }

    //
    // 跨会话（用户会话 -> Session 0）：+15
    // 会话取自 wkd 安全上下文（进程创建回调内 IocpCapturePrivilegeInfo 已同步采集，
    // 不依赖回调现场令牌查询）；安全上下文缺失视为未知，跳过（降级）。
    //
    {
        PWKD_SECURITY_CONTEXT sourceSecurity = SourceWkdProcess->SecurityContext;
        PWKD_SECURITY_CONTEXT targetSecurity = TargetWkdProcess->SecurityContext;

        if (sourceSecurity && targetSecurity &&
            (sourceSecurity->SessionId != targetSecurity->SessionId) &&
            (sourceSecurity->SessionId != 0 && targetSecurity->SessionId == 0)) {
            foundFlags |= WkdPapSuspicious_CrossSessionAccess;
            score += 15;
            InterlockedIncrement64(&g_PapRuntime.Stats.CrossSessionAccess);
        }
    }

    //
    // 句柄复制链：+10
    //
    if (Operation == WkdPapOperation_Duplicate) {
        foundFlags |= WkdPapSuspicious_DuplicationChain;
        score += 10;
    }

    //
    // 快速枚举（速率限制命中）：+20
    //
    //if (PappIsSourceRateLimited(SourceWkdProcess->Core.ProcessId)) {
    //    foundFlags |= WkdPapSuspicious_RapidEnumeration;
    //    score += 20;
    //    InterlockedIncrement64(&g_PapRuntime.Stats.RapidEnumerationDetected);
    //}

    //
    // 打 EDR 组件（自保护绕过，T1562）：+25
    //
    if (Category == WkdPapCategory_Antimalware) {
        foundFlags |= WkdPapSuspicious_SelfProtectBypass;
        score += 25;
        InterlockedIncrement64(&g_PapRuntime.Stats.SelfProtectBypassAttempts);
    }

    *SuspicionScore = min(score, 100);
    *Flags = foundFlags;
}

//
// 裁决：安全只读放行；>=80 剥；>=40 按等级；低分按等级规则剥。
// （对齐 SS PpDetermineVerdict；Block 为预留，当前不产出）
//
static WKD_PAP_VERDICT
PappDetermineVerdict(
    _In_ ULONG SuspicionScore,
    _In_ ACCESS_MASK RequestedAccess,
    _In_ WKD_PAP_PROTECTION_LEVEL ProtectionLevel
    )
{
    //
    // 安全只读访问（不含任何危险位）：始终放行
    //
    if (PappAccessIsSafeReadOnly(RequestedAccess)) {
        return WkdPapVerdict_Allow;
    }

    //
    // 高分（>=80）：必然剥离
    //
    if (SuspicionScore >= 80) {
        return WkdPapVerdict_Strip;
    }

    //
    // 中分（>=40）：按等级 —— Critical/Antimalware/Strict 剥，Medium/Light 仅监控
    //
    if (SuspicionScore >= 40) {
        switch (ProtectionLevel) {
            case WkdPapLevel_Critical:
            case WkdPapLevel_Antimalware:
            case WkdPapLevel_Strict:
                return WkdPapVerdict_Strip;

            case WkdPapLevel_Medium:
            case WkdPapLevel_Light:
            default:
                return WkdPapVerdict_Monitor;
        }
    }

    //
    // 低分：按保护等级规则剥离
    //
    switch (ProtectionLevel) {
        case WkdPapLevel_Critical:
        case WkdPapLevel_Antimalware:
            //
            // 关键进程：任何危险位请求都剥离
            //
            if ((RequestedAccess & WKD_PAP_FULL_DANGEROUS_ACCESS) != 0) {
                return WkdPapVerdict_Strip;
            }
            break;

        case WkdPapLevel_Strict:
        case WkdPapLevel_Medium:
            //
            // 剥终止 + 注入位
            //
            if ((RequestedAccess &
                (WKD_PAP_TERMINATE_ACCESS | WKD_PAP_INJECT_ACCESS)) != 0) {
                return WkdPapVerdict_Strip;
            }
            break;

        case WkdPapLevel_Light:
            //
            // 仅剥终止位
            //
            if ((RequestedAccess & PROCESS_TERMINATE) != 0) {
                return WkdPapVerdict_Strip;
            }
            break;

        default:
            break;
    }

    return WkdPapVerdict_Allow;
}

//
// 按保护等级计算剥离位；LSASS 严格模式额外禁 VM_READ（T1003）。
//
static ACCESS_MASK
PappCalculateDeniedMask(
    _In_ WKD_PAP_PROTECTION_LEVEL ProtectionLevel,
    _In_ WKD_PAP_PROCESS_CATEGORY Category
    )
{
    ACCESS_MASK denied = 0;

    switch (ProtectionLevel) {
        case WkdPapLevel_Critical:
        case WkdPapLevel_Antimalware:
            denied = WKD_PAP_FULL_DANGEROUS_ACCESS;
            break;

        case WkdPapLevel_Strict:
            denied = WKD_PAP_TERMINATE_ACCESS |
                     WKD_PAP_INJECT_ACCESS |
                     WKD_PAP_CONTROL_ACCESS;
            break;

        case WkdPapLevel_Medium:
            denied = WKD_PAP_TERMINATE_ACCESS |
                     WKD_PAP_INJECT_ACCESS;
            break;

        case WkdPapLevel_Light:
            denied = WKD_PAP_TERMINATE_ACCESS;
            break;

        default:
            denied = 0;
            break;
    }

    //
    // LSASS 严格模式：禁 VM_READ|QUERY_INFORMATION（凭据转储核心对抗）
    //
    if (Category == WkdPapCategory_Lsass &&
        g_PapRuntime.Config.StrictLsassProtection) {
        denied |= WKD_PAP_LSASS_STRICT_ACCESS;
    }

    return denied;
}

/* ============================================================================
 * 访问策略表（PushLock）
 * ============================================================================ */

//
// 策略匹配（按分类/PID，返回首个命中）
//
static BOOLEAN
CbpFindProcessAccessPolicy(
    _In_ WKD_PAP_PROCESS_CATEGORY Category,
    _In_ HANDLE ProcessId,
    _Out_ PWKD_PROCESS_ACCESS_POLICY AccessPolicy
    )
{
    BOOLEAN found = FALSE;

    if (!AccessPolicy) return FALSE;
    
    WkdAcquirePushLockShared(&g_PapRuntime.PolicyLock);
    for (ULONG i = 0; i < g_PapRuntime.PolicyCount; i++) {
        if (!g_PapRuntime.AccessPolicies[i].InUse) {
            continue;
        }
        if (g_PapRuntime.AccessPolicies[i].Category != Category) {
            continue;
        }
        if (g_PapRuntime.AccessPolicies[i].ProcessId != ProcessId) {
            continue;
        }

        RtlCopyMemory(AccessPolicy,
            &g_PapRuntime.AccessPolicies[i],
            sizeof(WKD_PROCESS_ACCESS_POLICY));
        found = TRUE;
        break;
    }
    WkdReleasePushLockShared(&g_PapRuntime.PolicyLock);

    return found;
}

/* ============================================================================
 * 速率限制器（KSPIN_LOCK，10s 窗口滚动）
 * ============================================================================ */

//
// 查询源进程是否被限速（窗口内操作 >= 阈值）
//
static BOOLEAN
PappIsSourceRateLimited(
    _In_ HANDLE SourceProcessId
    )
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN limited = FALSE;
    LARGE_INTEGER now;
    LONGLONG windowTicks =
        (LONGLONG)WKD_PAP_RATE_WINDOW_SECONDS * 10000000LL;

    if (!g_PapRuntime.Config.TrackActivity) {
        return FALSE;
    }

    KeQuerySystemTime(&now);

    KeAcquireSpinLock(&g_PapRuntime.RateLock, &oldIrql);

    for (i = 0; i < WKD_PAP_MAX_RATE_ENTRIES; i++) {
        if (!g_PapRuntime.RateEntries[i].InUse) {
            continue;
        }
        if (g_PapRuntime.RateEntries[i].SourceProcessId != SourceProcessId) {
            continue;
        }

        //
        // 窗口滚动：超窗则重置
        //
        if ((now.QuadPart - g_PapRuntime.RateEntries[i].WindowStart.QuadPart) > windowTicks) {
            g_PapRuntime.RateEntries[i].Count = 0;
            g_PapRuntime.RateEntries[i].WindowStart = now;
        }

        limited = (g_PapRuntime.RateEntries[i].Count >= WKD_PAP_RATE_LIMIT_THRESHOLD);
        break;
    }

    KeReleaseSpinLock(&g_PapRuntime.RateLock, oldIrql);

    return limited;
}

//
// 记录源进程一次受保护目标操作（限速器计数）
//
static VOID
PappRecordSourceOperation(
    _In_ HANDLE SourceProcessId
    )
{
    KIRQL oldIrql;
    ULONG i;
    ULONG freeIndex = WKD_PAP_MAX_RATE_ENTRIES;
    LARGE_INTEGER now;
    LONGLONG windowTicks =
        (LONGLONG)WKD_PAP_RATE_WINDOW_SECONDS * 10000000LL;

    if (!g_PapRuntime.Config.TrackActivity) {
        return;
    }

    KeQuerySystemTime(&now);

    KeAcquireSpinLock(&g_PapRuntime.RateLock, &oldIrql);

    for (i = 0; i < WKD_PAP_MAX_RATE_ENTRIES; i++) {
        if (g_PapRuntime.RateEntries[i].InUse) {
            if (g_PapRuntime.RateEntries[i].SourceProcessId == SourceProcessId) {
                if ((now.QuadPart - g_PapRuntime.RateEntries[i].WindowStart.QuadPart) >
                    windowTicks) {
                    g_PapRuntime.RateEntries[i].Count = 0;
                    g_PapRuntime.RateEntries[i].WindowStart = now;
                }
                g_PapRuntime.RateEntries[i].Count++;
                KeReleaseSpinLock(&g_PapRuntime.RateLock, oldIrql);
                return;
            }
        }
        else if (freeIndex == WKD_PAP_MAX_RATE_ENTRIES) {
            freeIndex = i;
        }
    }

    //
    // 新源进程：分配空闲槽
    //
    if (freeIndex < WKD_PAP_MAX_RATE_ENTRIES) {
        g_PapRuntime.RateEntries[freeIndex].SourceProcessId = SourceProcessId;
        g_PapRuntime.RateEntries[freeIndex].Count = 1;
        g_PapRuntime.RateEntries[freeIndex].WindowStart = now;
        g_PapRuntime.RateEntries[freeIndex].InUse = TRUE;
    }

    KeReleaseSpinLock(&g_PapRuntime.RateLock, oldIrql);
}

/* ============================================================================
 * 日志
 * ============================================================================ */

static VOID
PappLogStrippedAccess(
    _In_ CONST PWKD_PROCESS SourceWkdProcess,
    _In_ CONST PWKD_PROCESS TargetWkdProcess,
    _In_ WKD_PROCESS_ACCESS_OPERATION Operation,
    _In_ ACCESS_MASK RequestedAccess,
    _In_ CONST WKD_PROCESS_ACCESS_RESULT* Result,
    _In_ ACCESS_MASK DeniedByAumask
    )
{
    if (!g_PapRuntime.Config.LogStrippedAccess) {
        return;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "[WkDefender] Pap: stripped access PID %lu -> PID %lu "
        "(Op=%s, Original=0x%08X, PapDenied=0x%08X, AuDenied=0x%08X, "
        "Score=%lu, Level=%d, Cat=%d)\n",
        HandleToULong(SourceWkdProcess->Core.ProcessId),
        HandleToULong((TargetWkdProcess != NULL)
            ? TargetWkdProcess->Core.ProcessId : 0),
        (Operation == WkdPapOperation_Create) ? "CREATE" : "DUP",
        RequestedAccess,
        Result->DeniedMask,
        DeniedByAumask,
        Result->SuspicionScore,
        (INT)Result->ProtectionLevel,
        (INT)Result->Category);
}

/* ============================================================================
 * 生命周期（PASSIVE；PAGED_CODE 化，替代原 alloc_text(PAGE, ...)）
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
PapInitialize(
    VOID
    )
{
    PAGED_CODE();

    if (InterlockedCompareExchange(&g_PapRuntime.Initialized, 1, 0) != 0) {
        return STATUS_ALREADY_INITIALIZED;
    }

    ExInitializePushLock(&g_PapRuntime.PolicyLock);
    KeInitializeSpinLock(&g_PapRuntime.RateLock);

    KeQuerySystemTime(&g_PapRuntime.BootTime);

    //
    // 默认配置（对齐 SS PppInitializeDefaultConfig）
    //
    g_PapRuntime.Config.StrictLsassProtection = TRUE;
    g_PapRuntime.Config.EnableKernelHandleFiltering = FALSE;
    g_PapRuntime.Config.EnablePolicyEnforcement = TRUE;
    g_PapRuntime.Config.LogStrippedAccess = TRUE;
    g_PapRuntime.Config.TrackActivity = TRUE;
    g_PapRuntime.Config.BootGracePeriodSeconds = 60;

    RtlZeroMemory(g_PapRuntime.AccessPolicies, sizeof(g_PapRuntime.AccessPolicies));
    RtlZeroMemory(g_PapRuntime.RateEntries, sizeof(g_PapRuntime.RateEntries));
    RtlZeroMemory(&g_PapRuntime.Stats, sizeof(g_PapRuntime.Stats));

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PapShutdown(
    VOID
    )
{
    PAGED_CODE();

    if (InterlockedCompareExchange(&g_PapRuntime.Initialized, 0, 1) != 1) {
        return;
    }

    //
    // 受保护判定状态已随 wkd_process 生命周期回收（PapProfile 不归本运行时托管），
    // 无需排空回调入口——机制层（CbObjectNotifyCleanup）先于本函数注销 OB 回调。
    //
    RtlZeroMemory(g_PapRuntime.AccessPolicies, sizeof(g_PapRuntime.AccessPolicies));
    RtlZeroMemory(g_PapRuntime.RateEntries, sizeof(g_PapRuntime.RateEntries));

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Pap: process access protection runtime shut down\n");
}

/* ============================================================================
 * 管理 API（PASSIVE，供 ALPC 管理通道后续接线）
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
PapAddProtectedProcess(
    _In_ HANDLE ProcessId,
    _In_ WKD_PAP_PROCESS_CATEGORY Category,
    _In_ WKD_PAP_PROTECTION_LEVEL ProtectionLevel
    )
{
    PWKD_PROCESS wkdProcess = NULL;

    PAGED_CODE();

    if (ProcessId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 动态添加受保护程序（管理面）：改写目标进程自述安全画像
    // （SecurityContext->PapProfile，进程创建回调采集与本次管理面回写
    // 串行于 SecurityContext->Lock / 管理面独占语义下，无并发写者）。
    //
    wkdProcess = PsLookupWkdProcessByProcessId(ProcessId);   /* 查找即 +1 */
    if (wkdProcess == NULL) {
        return STATUS_NOT_FOUND;
    }

    if (wkdProcess->SecurityContext != NULL) {
        wkdProcess->SecurityContext->PapProfile =
            (ULONG)WKD_PAP_PROFILE_TO_VALUE(Category, ProtectionLevel);
    }

    PsDereferenceWkdProcess(wkdProcess);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Pap: protected process added (PID=%lu, Level=%d, Cat=%d)\n",
        HandleToULong(ProcessId), (INT)ProtectionLevel, (INT)Category);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PapRemoveProtectedProcess(
    _In_ HANDLE ProcessId
    )
{
    PWKD_PROCESS wkdProcess = NULL;

    PAGED_CODE();

    if (ProcessId == NULL) {
        return;
    }

    wkdProcess = PsLookupWkdProcessByProcessId(ProcessId);   /* 查找即 +1 */
    if (wkdProcess == NULL) {
        return;
    }

    if (wkdProcess->SecurityContext != NULL) {
        wkdProcess->SecurityContext->PapProfile = 0;   /* 清画像 = 解除保护 */
    }

    PsDereferenceWkdProcess(wkdProcess);
}

_Use_decl_annotations_
NTSTATUS
PapAddAccessPolicy(
    _In_ CONST WKD_PROCESS_ACCESS_POLICY* Policy
    )
{
    LONG i;
    LONG freeIndex = -1;

    PAGED_CODE();

    if (Policy == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PapRuntime.PolicyLock);

    //
    // 已存在（同分类+PID）则更新
    //
    for (i = 0; i < WKD_PAP_MAX_POLICIES; i++) {
        if (!g_PapRuntime.AccessPolicies[i].InUse) {
            if (freeIndex < 0) {
                freeIndex = i;
            }
            continue;
        }
        if (g_PapRuntime.AccessPolicies[i].Category == Policy->Category &&
            g_PapRuntime.AccessPolicies[i].ProcessId == Policy->ProcessId) {
            g_PapRuntime.AccessPolicies[i].DeniedAccess = Policy->DeniedAccess;
            ExReleasePushLockExclusive(&g_PapRuntime.PolicyLock);
            KeLeaveCriticalRegion();
            return STATUS_SUCCESS;
        }
    }

    if (freeIndex < 0) {
        ExReleasePushLockExclusive(&g_PapRuntime.PolicyLock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_PapRuntime.AccessPolicies[freeIndex] = *Policy;
    g_PapRuntime.AccessPolicies[freeIndex].InUse = TRUE;
    InterlockedIncrement(&g_PapRuntime.PolicyCount);

    ExReleasePushLockExclusive(&g_PapRuntime.PolicyLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PapRemovePoliciesForCategory(
    _In_ WKD_PAP_PROCESS_CATEGORY Category
    )
{
    LONG i;

    PAGED_CODE();

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PapRuntime.PolicyLock);

    for (i = 0; i < WKD_PAP_MAX_POLICIES; i++) {
        if (g_PapRuntime.AccessPolicies[i].InUse &&
            g_PapRuntime.AccessPolicies[i].Category == Category) {
            RtlZeroMemory(&g_PapRuntime.AccessPolicies[i], sizeof(WKD_PROCESS_ACCESS_POLICY));
            InterlockedDecrement(&g_PapRuntime.PolicyCount);
        }
    }

    ExReleasePushLockExclusive(&g_PapRuntime.PolicyLock);
    KeLeaveCriticalRegion();
}

_Use_decl_annotations_
VOID
PapGetStatistics(
    _Out_ WKD_PAP_STATISTICS* Statistics
    )
{
    if (Statistics == NULL) {
        return;
    }

    RtlCopyMemory(Statistics, &g_PapRuntime.Stats, sizeof(WKD_PAP_STATISTICS));
}

/* ============================================================================
 * 查询 API（<= DISPATCH）
 * ============================================================================ */

_Use_decl_annotations_
BOOLEAN
PapIsProcessProtected(
    _In_ PEPROCESS Process
    )
{
    WKD_PAP_PROCESS_CATEGORY category;
    WKD_PAP_PROTECTION_LEVEL level;

    if (Process == NULL) {
        return FALSE;
    }

    //
    // 画像优先（2026-09-05 重构：进程自述元数据，含管理面动态添加）：
    // PEPROCESS -> PID -> wkd 表（查找即 +1）；表内画像非零即受保护。
    // 进程表为推锁共享，仅限 <= APC_LEVEL；DISPATCH 下直接降级到惰性分类。
    //
    if (KeGetCurrentIrql() <= APC_LEVEL) {
        PWKD_PROCESS wkdProcess =
            PsLookupWkdProcessByProcessId(PsGetProcessId(Process));

        if (wkdProcess != NULL) {
            BOOLEAN protected = FALSE;

            if (wkdProcess->SecurityContext != NULL &&
                wkdProcess->SecurityContext->PapProfile != 0   /* volatile 32 位读 */) {
                protected = TRUE;
            }
            PsDereferenceWkdProcess(wkdProcess);
            if (protected) {
                return TRUE;
            }
        }
    }

    //
    // 兜底：惰性分类（无锁纯计算，不写回——覆盖 EDR 组件后启动的画像缺失窗口）
    //
    return PapClassifyProcess(Process, &category, &level);
}

_Use_decl_annotations_
NTSTATUS
PapGetProcessProtection(
    _In_ PEPROCESS Process,
    _Out_ WKD_PAP_PROTECTION_LEVEL* Level,
    _Out_opt_ WKD_PAP_PROCESS_CATEGORY* Category
    )
{
    WKD_PAP_PROCESS_CATEGORY category = WkdPapCategory_Unknown;
    WKD_PAP_PROTECTION_LEVEL level = WkdPapLevel_None;

    //
    // 参数校验
    //
    if (Level == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Level = WkdPapLevel_None;
    if (Category != NULL) {
        *Category = WkdPapCategory_Unknown;
    }

    if (InterlockedCompareExchange(&g_PapRuntime.Initialized, 0, 0) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (Process == NULL) {
        return STATUS_SUCCESS;
    }

    //
    // 1) 画像优先（2026-09-05 重构）：进程自述元数据 O(1) 直达；
    //    进程表为推锁共享，仅限 <= APC_LEVEL。
    //
    if (KeGetCurrentIrql() <= APC_LEVEL) {
        PWKD_PROCESS wkdProcess =
            PsLookupWkdProcessByProcessId(PsGetProcessId(Process));

        if (wkdProcess != NULL) {
            ULONG packedProfile = 0;

            if (wkdProcess->SecurityContext != NULL) {
                packedProfile = wkdProcess->SecurityContext->PapProfile;   /* volatile 32 位读 */
            }
            if (packedProfile != 0) {
                level = (WKD_PAP_PROTECTION_LEVEL)(
                    (packedProfile & WKD_PAP_PROFILE_MASK_LEVEL) >>
                    WKD_PAP_PROFILE_SHIFT_LEVEL);
                category = (WKD_PAP_PROCESS_CATEGORY)(
                    (packedProfile & WKD_PAP_PROFILE_MASK_CATEGORY) >>
                    WKD_PAP_PROFILE_SHIFT_CATEGORY);

                PsDereferenceWkdProcess(wkdProcess);

                *Level = level;
                if (Category != NULL) {
                    *Category = category;
                }
                return STATUS_SUCCESS;
            }
            PsDereferenceWkdProcess(wkdProcess);
        }
    }

    //
    // 2) 兜底：惰性分类（无锁纯计算，不写回——查询路径零副作用）
    //
    if (PapClassifyProcess(Process, &category, &level)) {
        /* 分类已产出等级 */
    }

    *Level = level;
    if (Category != NULL) {
        *Category = category;
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*                函数前向声明                     */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
ObjpRegisterObjectCallbacks(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
ObjpUnregisterObjectCallbacks(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
static
OB_PREOP_CALLBACK_STATUS
CbpObjectNotifyPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
CbpNotifyIoaObjectAccess(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ POBJECT_TYPE ObjectType,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ACCESS_MASK SensitiveMask
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
CbpNotifyIoaHandleDuplicate(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ POBJECT_TYPE ObjectType,
    _In_ ACCESS_MASK DesiredAccess
    );

/**************************************************/
/*              初始化 / 清理                      */
/**************************************************/

//
// 初始化对象回调模块
//
_Use_decl_annotations_
NTSTATUS
CbInitializeObjectNotify(
    VOID
    )
/*++
Routine Description:
    初始化对象回调模块。
    注册 ObRegisterCallbacks 以拦截对进程和线程对象的敏感权限访问。
    仅注册 PreOperation 回调，不处理 PostOperation。

    关注的敏感操作：
    - 进程对象：VM_WRITE, VM_OPERATION, CREATE_THREAD, SUSPEND_RESUME 等
    - 线程对象：SET_CONTEXT, IMPERSONATE, SUSPEND_RESUME 等

Returns:
    STATUS_SUCCESS — 初始化成功
    其他 NTSTATUS  — 初始化失败
--*/
{
    NTSTATUS status;

    RtlZeroMemory(&g_ObjManager, sizeof(WKD_OBJECT_CALLBACK_MANAGER));
    ExInitializeFastMutex(&g_ObjManager.Lock);

    status = ObjpRegisterObjectCallbacks();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] CbInitializeObjectNotify: ObjpRegisterObjectCallbacks failed: 0x%08X\n",
            status);
        return status;
    }

    g_ObjManager.Initialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] ObjectNotify module initialized.\n");

    return STATUS_SUCCESS;
}

//
// 清理对象回调模块
//
_Use_decl_annotations_
VOID
CbObjectNotifyCleanup(
    VOID
    )
/*++
Routine Description:
    清理对象回调模块，注销 ObRegisterCallbacks 并释放资源。
--*/
{
    if (!g_ObjManager.Initialized) {
        return;
    }

    g_ObjManager.ShutdownRequested = TRUE;

    ObjpUnregisterObjectCallbacks();

    g_ObjManager.Initialized = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] ObjectNotify module cleaned up. "
        "Stats - PreOps: %lld, Sensitive: %lld, ProcessOps: %lld, ThreadOps: %lld\n",
        g_ObjManager.Statistics.TotalPreOps,
        g_ObjManager.Statistics.SensitiveAccess,
        g_ObjManager.Statistics.ProcessOps,
        g_ObjManager.Statistics.ThreadOps);
}

/**************************************************/
/*           回调注册 / 注销                       */
/**************************************************/

//
// 注册对象回调
//
_Use_decl_annotations_
static
NTSTATUS
ObjpRegisterObjectCallbacks(
    VOID
    )
/*++
Routine Description:
    调用 ObRegisterCallbacks 注册进程和线程对象的 PreOperation 回调。
    不注册 PostOperation 回调（按需求仅关注 PreOperation）。
--*/
{
    NTSTATUS status;
    OB_CALLBACK_REGISTRATION callbackReg;
    OB_OPERATION_REGISTRATION operationRegs[2];

    RtlZeroMemory(operationRegs, sizeof(operationRegs));
    RtlZeroMemory(&callbackReg, sizeof(OB_CALLBACK_REGISTRATION));

    //
    // [0] 进程对象回调
    // 关注句柄创建和句柄复制两个操作点
    //
    operationRegs[0].ObjectType = PsProcessType;
    operationRegs[0].Operations = OB_OPERATION_HANDLE_CREATE |
                                   OB_OPERATION_HANDLE_DUPLICATE;
    operationRegs[0].PreOperation = CbpObjectNotifyPreOperationCallback;
    operationRegs[0].PostOperation = NULL;  // 不处理 PostOperation

    //
    // [1] 线程对象回调
    // 关注句柄创建和句柄复制
    //
    operationRegs[1].ObjectType = PsThreadType;
    operationRegs[1].Operations = OB_OPERATION_HANDLE_CREATE |
                                   OB_OPERATION_HANDLE_DUPLICATE;
    operationRegs[1].PreOperation = CbpObjectNotifyPreOperationCallback;
    operationRegs[1].PostOperation = NULL;  // 不处理 PostOperation

    //
    // 组装注册结构（与现有 ObjectManager.c 保持一致，不显式设置 Altitude）
    //
    callbackReg.Version = OB_FLT_REGISTRATION_VERSION;
    callbackReg.OperationRegistrationCount = RTL_NUMBER_OF(operationRegs);
    callbackReg.OperationRegistration = operationRegs;
    callbackReg.RegistrationContext = NULL;

    status = ObRegisterCallbacks(&callbackReg, &g_ObjManager.CallbackHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] ObRegisterCallbacks failed: 0x%08X\n", status);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Object callbacks registered (Process + Thread, PreOp only).\n");

    return STATUS_SUCCESS;
}

//
// 注销对象回调
//
_Use_decl_annotations_
static
NTSTATUS
ObjpUnregisterObjectCallbacks(
    VOID
    )
{
    if (g_ObjManager.CallbackHandle) {
        ObUnRegisterCallbacks(g_ObjManager.CallbackHandle);
        g_ObjManager.CallbackHandle = NULL;
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*           敏感权限判定                          */
/**************************************************/

//
// 判断是否为敏感权限访问
//
_IRQL_requires_(PASSIVE_LEVEL)
static
BOOLEAN
CbpCheckObjectSensitiveAccess(
    _In_ POBJECT_TYPE ObjectType,
    _In_ OB_OPERATION Operation,
    _In_ ACCESS_MASK AccessMask,
    _Out_ PACCESS_MASK DetectedMask
    )
/*++
Routine Description:
    检查当前对象操作是否涉及敏感权限。
    对于进程对象和线程对象分别检查不同的敏感权限位。

    进程敏感权限：
    - PROCESS_VM_WRITE         (0x0020) — WriteProcessMemory
    - PROCESS_VM_OPERATION     (0x0008) — VirtualProtectEx
    - PROCESS_CREATE_THREAD    (0x0002) — CreateRemoteThread
    - PROCESS_SUSPEND_RESUME   (0x0800)
    - PROCESS_SET_INFORMATION  (0x0200)
    - PROCESS_TERMINATE        (0x0001)
    - PROCESS_DUP_HANDLE       (0x0040)

    线程敏感权限：
    - THREAD_SET_CONTEXT       (0x0010) — SetThreadContext
    - THREAD_IMPERSONATE       (0x0100)
    - THREAD_SUSPEND_RESUME    (0x0002)

Arguments:
    ObjectType    — [In] 当前操作涉及的内核对象类型（如 PsProcessType 或 PsThreadType）。
    Operation     — [In] 当前触发的对象操作类型（如 OB_OPERATION_HANDLE_CREATE 等）。
    AccessMask    — [In] 本次操作请求的访问权限掩码（用于比对敏感权限位）。
    DetectedMask  — [Out] 用于接收检测到的敏感权限位。如果返回 TRUE，该参数包含命中的敏感权限。

Returns:
    TRUE  — 访问包含敏感权限
    FALSE — 非敏感访问
--*/
{
    ACCESS_MASK sensitiveMask = 0;

    if (!ObjectType || !Operation || !AccessMask || !DetectedMask) {
        return FALSE;
    }

    *DetectedMask = 0;

    //
    // 仅关注句柄创建/复制操作
    //
    if (Operation != OB_OPERATION_HANDLE_CREATE &&
        Operation != OB_OPERATION_HANDLE_DUPLICATE) {
        return FALSE;
    }

    //
    // 进程对象：检查进程敏感权限
    //
    if (ObjectType == *PsProcessType) {
        sensitiveMask = AccessMask & WKD_SENSITIVE_PROCESS_ACCESS;
    }
    //
    // 线程对象：检查线程敏感权限
    //
    else if (ObjectType == *PsThreadType) {
        sensitiveMask = AccessMask & WKD_SENSITIVE_THREAD_ACCESS;
    }
    else {
        //
        // 其他对象类型暂不关注
        //
        return FALSE;
    }

    if (sensitiveMask) {
        *DetectedMask = sensitiveMask;
        return TRUE;
    }

    return FALSE;
}

/**************************************************/
/*           通知 IOA 引擎                         */
/**************************************************/

//
// 通知 IOA 引擎：敏感对象访问
//
_Use_decl_annotations_
static
VOID
CbpNotifyIoaObjectAccess(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ POBJECT_TYPE ObjectType,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ACCESS_MASK SensitiveMask
    )
/*++
Routine Description:
    构造并发送敏感对象访问通知消息到 IOA 分析引擎。

Arguments:
    SourceProcessId — 发起访问的进程 ID。
    TargetProcessId — 被访问的对象所属进程/线程 ID（对于线程对象，存储线程所属进程）。
    ObjectType      — 对象类型（PsProcessType 或 PsThreadType）。
    DesiredAccess   — 请求的完整访问掩码。
    SensitiveMask   — 命中的敏感权限位。
--*/
{
    PWKD_MESSAGE message;
    WKD_MESSAGE_TYPE msgType;

    //
    // 根据对象类型选择消息类型
    //
    if (ObjectType == *PsProcessType) {
        msgType = WkdMessage_ProcessObjectAccess;
    }
    else {
        msgType = WkdMessage_ThreadObjectAccess;
    }

    message = NtfCreateMessage(
        msgType,
        WkdMessage_SourceObjectCallback,
        WkdMessage_PriorityNormal,
        sizeof(WKD_MESSAGE_BODY_OBJECT_ACCESS));
    if (!message) {
        return;
    }

    message->Header.SourceProcessId = SourceProcessId;
    message->Header.TargetProcessId = TargetProcessId;
    message->Header.ThreadId = PsGetCurrentThreadId();

    //
    // 填充对象访问消息体
    //
    {
        PWKD_MESSAGE_BODY_OBJECT_ACCESS bodyAccess;
        bodyAccess = WKD_MESSAGE_BODY(message, WKD_MESSAGE_BODY_OBJECT_ACCESS);
        bodyAccess->DesiredAccess = DesiredAccess;
        bodyAccess->SensitiveMask = SensitiveMask;
    }

    /*
     * 同步/异步双路径: 根据进程对位图决定阻塞策略
     */
    if (PsPairNeedsSync(
            SourceProcessId, TargetProcessId,
            WkdOp_ObjectAccess)) {

        /* === 同步路径 === */
        WKD_SYNC_REPLY_DATA verdict;
        PWKD_SYNC_REQUEST req;
        NTSTATUS status;

        status = NtfAcquireSyncRequest(&g_SyncMgr,
            &verdict, sizeof(verdict), &req);
        if (!NT_SUCCESS(status)) {
            NmFreeMessage(message);
            return;
        }

        message->Header.SyncRequestId = req->RequestId;

        AlpcSendWkdMessage(message);

        {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -50000000LL;
            status = NtfSyncWait(&g_SyncMgr, req, &timeout);
        }

        if (status != STATUS_SUCCESS) {
            NtfReleaseSyncRequest(&g_SyncMgr, req);
            NmFreeMessage(message);
            return;
        }

        NtfReleaseSyncRequest(&g_SyncMgr, req);
        NmFreeMessage(message);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Sync deny: Src=%p Tgt=%p Access=0x%X\n",
            SourceProcessId, TargetProcessId,
            (ULONG)DesiredAccess);
        return;
    } else {
        /* === 异步路径 (现状) === */
        NtfSendMessageAsync(message);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "[WkDefender] Sensitive object access: Src=%p Tgt=%p Type=%s Access=0x%X Sensitive=0x%X\n",
        SourceProcessId, TargetProcessId,
        (ObjectType == *PsProcessType) ? "Process" : "Thread",
        (ULONG)DesiredAccess, (ULONG)SensitiveMask);
}

/**************************************************/
/*           句柄复制事件上送                       */
/**************************************************/

//
// 构造并发送句柄复制事件（WkdMessage_HandleDuplicate）到 Agent。
// 对齐 SS ObjectCallback.c 的 HtRecordDuplication 触发点（OB 回调 DUPLICATE 分支）。
// 死代码：本模块 CbInitializeObjectNotify 未激活；跨进程复制关联由 Agent
// 因果图消费（对齐 SS PrAddRelationship(PrRelation_HandleDuplication)），
// 内核不维护复制记录列表。
//
_Use_decl_annotations_
static
VOID
CbpNotifyIoaHandleDuplicate(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ POBJECT_TYPE ObjectType,
    _In_ ACCESS_MASK DesiredAccess
    )
{
    PWKD_MESSAGE message;

    message = NtfCreateMessage(
        WkdMessage_HandleDuplicate,
        WkdMessage_SourceObjectCallback,
        WkdMessage_PriorityNormal,
        sizeof(WKD_MESSAGE_BODY_HANDLE_DUPLICATE));
    if (!message) {
        return;
    }

    message->Header.SourceProcessId = SourceProcessId;
    message->Header.TargetProcessId = TargetProcessId;
    message->Header.ThreadId = PsGetCurrentThreadId();

    {
        PWKD_MESSAGE_BODY_HANDLE_DUPLICATE body;
        body = WKD_MESSAGE_BODY(message, WKD_MESSAGE_BODY_HANDLE_DUPLICATE);
        body->SourceProcessId = SourceProcessId;
        body->TargetProcessId = TargetProcessId;
        body->ObjectType = (ObjectType == *PsProcessType) ? 0 : 1;
        body->DesiredAccess = DesiredAccess;
    }

    /* 异步上送（复制事件仅记录，不做同步阻塞，对齐 SS HtRecordDuplication 纯记录语义） */
    NtfSendMessageAsync(message);
}

/**************************************************/
/*         Pap 进程访问保护粘合（机制层）           */
/**************************************************/

//
// 获取原始请求访问位（与本模块 LD 剥离前语义一致：OriginalDesiredAccess）
//
FORCEINLINE
static
ACCESS_MASK
CbpGetOriginalDesiredAccess(
    _In_ const POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        return OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    } else {
        return OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
    }
}

//
// 就地应用 DeniedMask（在当前 DesiredAccess 上二次剥离，与 AU 已剥离结果 union）
// 语义: DesiredAccess' = DesiredAccess & ~DeniedMask
//
static
VOID
ObjpPapApplyDeniedMask(
    _Inout_ const POB_PRE_OPERATION_INFORMATION OperationInformation,
    _In_ ACCESS_MASK DeniedMask
    )
{
    ACCESS_MASK current;

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        current = OperationInformation->Parameters->
            CreateHandleInformation.DesiredAccess;
        OperationInformation->Parameters->
            CreateHandleInformation.DesiredAccess = current & ~DeniedMask;
    }
    else {
        current = OperationInformation->Parameters->
            DuplicateHandleInformation.DesiredAccess;
        OperationInformation->Parameters->
            DuplicateHandleInformation.DesiredAccess = current & ~DeniedMask;
    }
}

//
// 进程访问审计流水线（机制层唯一粘合）：
//
// 2026-09-05 判定逻辑上移：原 PapEvaluateAccess 的"阶段 2-6"（目标画像判定 /
// 补分类回写 / 策略匹配 / 打分 / 裁决 / 速率记录 / 剥离写回）整段并入本函数，
// 参数直传 源进程 / 目标进程 / OB 现场（不再经 WKD_PROCESS_ACCESS_REQUEST
// 中转，快速路径内联在回调完成）。
//
//   - 源进程：调用方（CbpObjectNotifyPreOperationCallback）已 PsLookupWkdProcessByProcessId
//     （查找即 +1，引用由调用方统一释放），本函数直接复用其对象；
//   - 目标进程：调用方已在回调按目标 PEPROCESS 查好 wkd 对象并直传
//     （查找即 +1，引用由调用方统一释放），本函数不查找、不释放；
//     NULL = 表外进程（System/Idle 等不进进程表）-> 按无保护判定放行。
//   - 进程表为推锁共享，仅限 <= APC_LEVEL：DISPATCH 下回调不查找目标
//     （TargetWkdProcess=NULL），保护判定降级放行。
//
static
NTSTATUS
CbpAuditProcessAccess(
    _In_ const PWKD_PROCESS SourceWkdProcess,
    _In_ const PWKD_PROCESS TargetWkdProcess,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    WKD_PROCESS_ACCESS_RESULT result = { 0 };
    WKD_PROCESS_ACCESS_POLICY policy = { 0 };
    WKD_PAP_PROCESS_CATEGORY category = WkdPapCategory_Unknown;
    WKD_PAP_PROTECTION_LEVEL level = WkdPapLevel_None;
    ULONG profile = 0;
    BOOLEAN hasPolicy = FALSE;
    ULONG score = 0;
    WKD_PAP_SUSPICIOUS_FLAGS flags = WkdPapSuspicious_None;
    WKD_PAP_VERDICT verdict = WkdPapVerdict_Allow;
    ACCESS_MASK deniedMask = 0;
    ACCESS_MASK desiredAccess = 0;
    WKD_PROCESS_ACCESS_OPERATION operation;

    if (!SourceWkdProcess || !TargetWkdProcess || !OperationInformation) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 运行时未初始化 / 关闭中 -> 放行
    //
    if (InterlockedCompareExchange(&g_PapRuntime.Initialized, 0, 0) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }

    InterlockedIncrement64(&g_PapRuntime.Stats.TotalEvaluations);

    result.Verdict = WkdPapVerdict_Allow;

    //
    // 解析 OB 现场（不再经请求中转结构，直取）
    //
    operation =
        (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            ? WkdPapOperation_Create
            : WkdPapOperation_Duplicate;
    desiredAccess = CbpGetOriginalDesiredAccess(OperationInformation);

    //
    // 阶段 2（原 PapEvaluateAccess）：受保护目标判定
    // 目标分类/等级取自进程自述安全画像 SecurityContext->PapProfile（进程创建
    // 回调 §2.5 同步采集，32 位打包原子读，对象解引用 O(1) 无锁）。
    //   - PapProfile != 0：直接解包分类/等级，受保护；
    //   - PapProfile == 0（Unknown/采集缺失）：现场补分类（无锁纯计算）并回写
    //     画像——兜底 EDR 组件判定晚于进程创建的窗口；仍无分类则按无保护放行。
    //
    profile = TargetWkdProcess->SecurityContext->PapProfile;   /* volatile 32 位读，x64 对齐原子 */
    if (profile != 0) {
        category = (WKD_PAP_PROCESS_CATEGORY)(
            (profile & WKD_PAP_PROFILE_MASK_CATEGORY) >>
            WKD_PAP_PROFILE_SHIFT_CATEGORY);
        level = (WKD_PAP_PROTECTION_LEVEL)(
            (profile & WKD_PAP_PROFILE_MASK_LEVEL) >>
            WKD_PAP_PROFILE_SHIFT_LEVEL);
    } 
    //else {
    //    
    //    // 补分类兜底（无锁纯计算；成功则回写进程画像，后续判定 O(1) 直达）
    //    
    //    if (PapClassifyProcess(TargetProcess, &category, &level)) {
    //        if (targetSc != NULL) {
    //            targetSc->PapProfile = WKD_PAP_PROFILE_TO_VALUE(category, level);
    //        }
    //        isProtected = TRUE;
    //    }
    //}


    //
    // 阶段 3：策略匹配（可选）
    //
    if (g_PapRuntime.Config.EnablePolicyEnforcement) {
        hasPolicy = CbpFindProcessAccessPolicy(category,
            TargetWkdProcess->Core.ProcessId, &policy);
        if (hasPolicy) {
            InterlockedIncrement64(&g_PapRuntime.Stats.PolicyMatches);
        }
    }

    //
    // 阶段 4：打分（源/目标/操作/掩码直传，无中转结构）
    //
    CbpAnalyzeProcessAccessOperation(SourceWkdProcess, TargetWkdProcess,
        operation, desiredAccess, category, &score, &flags);

    //
    // 阶段 5：裁决
    //
    verdict = PappDetermineVerdict(score, desiredAccess, level);

    result.Verdict = verdict;
    result.SuspicionScore = score;
    result.Flags = flags;
    result.ProtectionLevel = level;
    result.Category = category;

    switch (verdict) {
        case WkdPapVerdict_Allow:
            break;

        case WkdPapVerdict_Strip:
            //
            // 等级矩阵剥离 + 策略追加 + LSASS 严格模式
            //
            deniedMask = PappCalculateDeniedMask(level, category);
            if (hasPolicy && policy.DeniedAccess != 0) {
                deniedMask |= policy.DeniedAccess;
            }
            deniedMask &= desiredAccess;

            result.DeniedMask = deniedMask;
            InterlockedIncrement64(&g_PapRuntime.Stats.AccessStripped);
            InterlockedIncrement64(&g_PapRuntime.Stats.TotalEvaluationsDenied);

            if (deniedMask & PROCESS_TERMINATE) {
                InterlockedIncrement64(&g_PapRuntime.Stats.TerminationAttempts);
            }
            if (deniedMask & WKD_PAP_INJECT_ACCESS) {
                InterlockedIncrement64(&g_PapRuntime.Stats.InjectionAttempts);
            }

            PappLogStrippedAccess(SourceWkdProcess, TargetWkdProcess,
                operation, desiredAccess, &result, 0);
            break;

        case WkdPapVerdict_Monitor:
            //
            // 放行但记录可疑（当前以统计 + DbgPrint 呈现；IOA 上报由机制层承接）
            //
            InterlockedIncrement64(&g_PapRuntime.Stats.TotalEvaluationsDenied);
            break;

        case WkdPapVerdict_Block:
            //
            // 预留：全部剥掉仅保留 SYNCHRONIZE（当前裁决不产出）
            //
            deniedMask = desiredAccess & ~(ACCESS_MASK)SYNCHRONIZE;
            result.DeniedMask = deniedMask;
            InterlockedIncrement64(&g_PapRuntime.Stats.AccessStripped);
            InterlockedIncrement64(&g_PapRuntime.Stats.TotalEvaluationsDenied);
            break;

        default:
            break;
    }

    //
    // 阶段 6：速率限制记录（受保护目标操作）
    //
    PappRecordSourceOperation(SourceWkdProcess->Core.ProcessId);

    //
    // Strip/Block：在 AU 已剥离（current DesiredAccess）基础上二次剥离 Pap 的位。
    // 合并语义: current & ~DeniedMask（等价 Original & ~(AUMask | PapMask)）。
    //
    if ((result.Verdict == WkdPapVerdict_Strip ||
         result.Verdict == WkdPapVerdict_Block) &&
        result.DeniedMask != 0) {
        ObjpPapApplyDeniedMask(OperationInformation, result.DeniedMask);
    }

Done:
    return STATUS_SUCCESS;
}

/* ============================================================================
 * Tap 线程访问防护（2026-09-05 判定逻辑整体上移：与 Pap 同层并入机制层）
 *
 * 演进史：
 *   - Process/ThreadAccessProtection.c（独立引擎 + WKD_TAP_ACCESS_REQUEST
 *     中转）-> 本文件（判定随"访问掩码主线"并入 OB 判定区，类型/接口声明
 *     保留在 Process/ThreadAccessProtection.h）。
 *   - 本块仅含：运行时（rundown/统计/日志开关）/ 无状态判定纯函数族 /
 *     生命周期与统计快照；判定入口为节末 CbpAuditThreadAccess。
 *
 * 与 Pap 的关系（线程域特有依赖）：
 *   - 目标线程 = OB 现场 Object（PETHREAD），归属进程在回调内一次
 *     IoThreadToProcess、一次查 wkd 表（查找即 +1，引用由回调统一释放）；
 *   - 目标等级 = 归属进程 SecurityContext->PapProfile（进程创建回调 §2.5
 *     同步采集，先于本线程可被句柄化，直读不兜底）；
 *   - 快速路径（源 System / 内核句柄 / 白名单 / 同进程自访问）由回调统一
 *     内联完成，本入口不再重复；
 *   - 判定顺序：进程分支（Pap）先剥离，线程分支（Tap）在同一 DesiredAccess
 *     槽上二次剥离，一次写回：current & ~(AUMask | PapMask | TapMask)。
 * ============================================================================ */

typedef struct _WKD_TAP_RUNTIME {
    volatile LONG       Initialized;        /* 初始化标志（Interlocked 访问） */
    EX_RUNDOWN_REF      RundownRef;         /* 生命周期（OB 回调异步入口） */
    WKD_TAP_STATISTICS  Stats;              /* 统计（原子计数） */
    BOOLEAN             LogStrippedAccess;  /* 剥离时输出 DbgPrint */
} WKD_TAP_RUNTIME, *PWKD_TAP_RUNTIME;

static WKD_TAP_RUNTIME g_TapRuntime;        /* 运行时唯一实例（非池分配，置零初始化） */

//
// 攻击模式判定（对齐 SS TpDetectAttackPattern 判定顺序：
// SystemThread 优先 -> APC -> 劫持 -> SuspendInject -> 终止 -> 模拟）
//
static WKD_TAP_ATTACK_TYPE
TappDetectAttack(
    _In_ ACCESS_MASK AccessMask,
    _In_ BOOLEAN TargetIsSystemThread
    )
{
    if (TargetIsSystemThread &&
        (AccessMask & (WKD_TAP_INJECT_ACCESS | WKD_TAP_TERMINATE_ACCESS))) {
        return WkdTapAttack_SystemThread;
    }

    if ((AccessMask & WKD_TAP_APC_INJECT_ACCESS) == WKD_TAP_APC_INJECT_ACCESS) {
        return WkdTapAttack_APCInjection;
    }

    if ((AccessMask & WKD_TAP_HIJACK_ACCESS) == WKD_TAP_HIJACK_ACCESS) {
        return WkdTapAttack_ContextHijack;
    }

    if ((AccessMask & THREAD_SUSPEND_RESUME) &&
        (AccessMask & (THREAD_SET_CONTEXT | THREAD_SET_INFORMATION))) {
        return WkdTapAttack_SuspendInject;
    }

    if (AccessMask & THREAD_TERMINATE) {
        return WkdTapAttack_Termination;
    }

    if (AccessMask & (THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION)) {
        return WkdTapAttack_Impersonation;
    }

    return WkdTapAttack_None;
}

//
// 可疑标志分析与打分（对齐 SS TpAnalyzeOperation + TppCalculateSuspicionScore）。
// 输出 flags 与 score（封顶 100）。SelfProtectBypass 由调用方按需预置。
//
static VOID
TappAnalyzeOperation(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ ACCESS_MASK AccessMask,
    _In_ BOOLEAN TargetIsSystemThread,
    _In_ WKD_TAP_SUSPICIOUS_FLAGS PreSetFlags,
    _Out_ WKD_TAP_SUSPICIOUS_FLAGS* OutFlags,
    _Out_ ULONG* OutScore
    )
{
    WKD_TAP_SUSPICIOUS_FLAGS flags = PreSetFlags;
    ULONG score = 0;

    //
    // 位级危险访问标志
    //
    if (SourceProcessId != TargetProcessId) {
        flags |= WkdTapSuspicious_CrossProcess;
        score += WKD_TAP_SCORE_CROSS_PROCESS;
    }
    if (AccessMask & (THREAD_GET_CONTEXT | THREAD_SET_CONTEXT)) {
        flags |= WkdTapSuspicious_ContextAccess;
        score += WKD_TAP_SCORE_CONTEXT_ACCESS;
    }
    if (AccessMask & THREAD_SUSPEND_RESUME) {
        flags |= WkdTapSuspicious_SuspendAccess;
        score += WKD_TAP_SCORE_SUSPEND_ACCESS;
    }
    if (AccessMask & THREAD_TERMINATE) {
        flags |= WkdTapSuspicious_TerminateAttempt;
        score += WKD_TAP_SCORE_TERMINATE_ACCESS;
    }
    if ((AccessMask & WKD_TAP_APC_INJECT_ACCESS) == WKD_TAP_APC_INJECT_ACCESS) {
        flags |= WkdTapSuspicious_APCPattern;
        score += WKD_TAP_SCORE_APC_PATTERN;
    }
    if ((AccessMask & WKD_TAP_HIJACK_ACCESS) == WKD_TAP_HIJACK_ACCESS) {
        flags |= WkdTapSuspicious_HijackPattern;
        score += WKD_TAP_SCORE_HIJACK_PATTERN;
    }
    if (AccessMask & (THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION)) {
        flags |= WkdTapSuspicious_Impersonation;
        score += WKD_TAP_SCORE_IMPERSONATION;
    }
    if (TargetIsSystemThread) {
        flags |= WkdTapSuspicious_SystemThread;
        score += WKD_TAP_SCORE_SYSTEM_THREAD;
    }

    //
    // 攻击类型加成（对齐 SS TppCalculateSuspicionScore switch）
    //
    switch (TappDetectAttack(AccessMask, TargetIsSystemThread)) {
        case WkdTapAttack_ContextHijack:
            score += WKD_TAP_SCORE_ATTACK_HIJACK;
            break;
        case WkdTapAttack_APCInjection:
            score += WKD_TAP_SCORE_ATTACK_APC;
            break;
        case WkdTapAttack_SuspendInject:
            score += WKD_TAP_SCORE_ATTACK_SUSPEND_INJECT;
            break;
        case WkdTapAttack_Termination:
            score += WKD_TAP_SCORE_ATTACK_TERMINATE;
            break;
        case WkdTapAttack_SystemThread:
            score += WKD_TAP_SCORE_ATTACK_SYSTEM;
            break;
        default:
            break;
    }

    if (score > 100) {
        score = 100;
    }

    *OutFlags = flags;
    *OutScore = score;
}

//
// 裁决（对齐 SS TpDetermineVerdict）：
//  - 无可疑标志 -> Allow
//  - 系统线程攻击 / 高分(>=80) / 明确攻击模式（APC/劫持/SuspendInject）-> Strip
//  - 中分(>=50)：等级 >= Strict 时 Strip，否则 Monitor
//  - 等级表：Antimalware/Critical 任何可疑即 Strip；Strict/Medium/Light 逐步收窄
// 注：Tap 不产出 Block，裁决收敛为三态（Allow / Monitor / Strip）。
//
static WKD_PAP_VERDICT
TappDetermineVerdict(
    _In_ WKD_TAP_SUSPICIOUS_FLAGS Flags,
    _In_ ULONG Score,
    _In_ WKD_TAP_ATTACK_TYPE DetectedAttack,
    _In_ WKD_PAP_PROTECTION_LEVEL ProtectionLevel
    )
{
    if (Flags == WkdTapSuspicious_None) {
        return WkdPapVerdict_Allow;
    }

    if (DetectedAttack == WkdTapAttack_SystemThread) {
        return WkdPapVerdict_Strip;
    }

    if (Score >= WKD_TAP_HIGH_SUSPICION_THRESHOLD) {
        return WkdPapVerdict_Strip;
    }

    if (Score >= WKD_TAP_MEDIUM_SUSPICION_THRESHOLD) {
        if (ProtectionLevel >= WkdPapLevel_Strict) {
            return WkdPapVerdict_Strip;
        }
        return WkdPapVerdict_Monitor;
    }

    if (DetectedAttack == WkdTapAttack_APCInjection ||
        DetectedAttack == WkdTapAttack_ContextHijack ||
        DetectedAttack == WkdTapAttack_SuspendInject) {
        return WkdPapVerdict_Strip;
    }

    switch (ProtectionLevel) {
        case WkdPapLevel_Antimalware:
        case WkdPapLevel_Critical:
            /* 严格保护：任何可疑访问即剥离 */
            return WkdPapVerdict_Strip;

        case WkdPapLevel_Strict:
            if (Flags & (WkdTapSuspicious_ContextAccess |
                         WkdTapSuspicious_SuspendAccess |
                         WkdTapSuspicious_TerminateAttempt)) {
                return WkdPapVerdict_Strip;
            }
            break;

        case WkdPapLevel_Medium:
            if (Flags & (WkdTapSuspicious_TerminateAttempt |
                         WkdTapSuspicious_SuspendAccess)) {
                return WkdPapVerdict_Strip;
            }
            break;

        case WkdPapLevel_Light:
            if (Flags & WkdTapSuspicious_TerminateAttempt) {
                return WkdPapVerdict_Strip;
            }
            break;

        default:
            break;
    }

    return WkdPapVerdict_Monitor;
}

//
// 等级剥离矩阵（对齐 SS TpCalculateAllowedAccess，输出 DeniedMask 形式）。
// 跨域映射：进程域等级 -> 线程域 THREAD_* 危险位集合。
//
static ACCESS_MASK
TappCalculateDeniedMask(
    _In_ WKD_PAP_PROTECTION_LEVEL ProtectionLevel
    )
{
    switch (ProtectionLevel) {
        case WkdPapLevel_Antimalware:
        case WkdPapLevel_Critical:
            return WKD_TAP_FULL_DANGEROUS_ACCESS;

        case WkdPapLevel_Strict:
            return (WKD_TAP_TERMINATE_ACCESS |
                    WKD_TAP_INJECT_ACCESS |
                    WKD_TAP_CONTROL_ACCESS);

        case WkdPapLevel_Medium:
            return (WKD_TAP_TERMINATE_ACCESS |
                    THREAD_SUSPEND_RESUME);

        case WkdPapLevel_Light:
            return WKD_TAP_TERMINATE_ACCESS;

        default:
            return 0;
    }
}

//
// 剥离日志（对齐 SS TppLogOperation 精简版；原内联于引擎入口，上移后提取，
// 签名直传标量，不依赖任何中转结构）。
//
static VOID
TappLogStrippedAccess(
    _In_ HANDLE SourceProcessId,
    _In_ PETHREAD TargetThread,
    _In_ HANDLE TargetProcessId,
    _In_ WKD_PROCESS_ACCESS_OPERATION Operation,
    _In_ ACCESS_MASK DeniedMask,
    _In_ ULONG Score,
    _In_ WKD_PAP_PROTECTION_LEVEL Level,
    _In_ WKD_TAP_ATTACK_TYPE Attack
    )
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Tap: stripped thread access PID %lu -> TID %p "
        "(PID %lu, Op=%s, Mask=0x%08X, Score=%lu, Level=%d, Attack=%d)\n",
        HandleToULong(SourceProcessId),
        PsGetThreadId(TargetThread),
        HandleToULong(TargetProcessId),
        (Operation == WkdPapOperation_Create) ? "CREATE" : "DUP",
        DeniedMask,
        Score,
        (INT)Level,
        (INT)Attack);
}

/* ============================================================================
 * 生命周期 / 统计快照（PASSIVE，可分页）
 * ============================================================================ */

_Use_decl_annotations_
NTSTATUS
TapInitialize(
    VOID
    )
{
    PAGED_CODE();

    if (InterlockedCompareExchange(&g_TapRuntime.Initialized, 1, 0) != 0) {
        return STATUS_ALREADY_INITIALIZED;
    }

    ExInitializeRundownProtection(&g_TapRuntime.RundownRef);
    RtlZeroMemory(&g_TapRuntime.Stats, sizeof(g_TapRuntime.Stats));
    g_TapRuntime.LogStrippedAccess = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Tap: thread access protection engine initialized\n");

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
TapShutdown(
    VOID
    )
{
    PAGED_CODE();

    if (InterlockedCompareExchange(&g_TapRuntime.Initialized, 0, 1) != 1) {
        return;
    }

    ExWaitForRundownProtectionRelease(&g_TapRuntime.RundownRef);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Tap: thread access protection engine shut down\n");
}

_Use_decl_annotations_
VOID
TapGetStatistics(
    _Out_ WKD_TAP_STATISTICS* Statistics
    )
{
    if (Statistics == NULL) {
        return;
    }

    RtlCopyMemory(Statistics, &g_TapRuntime.Stats, sizeof(WKD_TAP_STATISTICS));
}

//
// 线程访问审计流水线（机制层唯一粘合）：直传 源/目标 wkd 对象 + OB 现场，
// 不再经 WKD_TAP_ACCESS_REQUEST 中转。仅应在线程对象分支调用（调用点位于
// ObjectType == *PsThreadType 判断内）。
//
//   - 源进程：调用方已 PsLookupWkdProcessByProcessId（查找即 +1），直接复用；
//   - 目标进程：调用方已在回调按目标线程归属进程查好 wkd 对象并直传
//     （查找即 +1），本函数不查找、不释放；NULL = 表外进程（System 等）
//     或 DISPATCH 下降级 -> 按无保护判定放行；
//   - 目标等级：归属进程 SecurityContext->PapProfile（进程创建回调 §2.5
//     同步采集，先于本线程可被句柄化，直读不兜底；理论不可达的 0 画像按
//     无保护防御性放行）；
//   - 目标线程：OB 现场 Object（PETHREAD），本函数内 IoThreadToProcess
//     一次取归属进程（仅用于 PsIsSystemThread 语义；等级取自 wkd 对象）；
//   - 快速路径（源 System / 内核句柄 / 白名单 / 同进程自访问）由回调统一
//     内联完成，本入口不再重复。
//
static
NTSTATUS
CbpAuditThreadAccess(
    _In_ const PWKD_PROCESS SourceWkdProcess,
    _In_ const PWKD_PROCESS TargetWkdProcess,
    _Inout_ const POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    WKD_TAP_ACCESS_RESULT result = { 0 };
    PETHREAD targetThread = NULL;
    WKD_PAP_PROTECTION_LEVEL level = WkdPapLevel_None;
    WKD_TAP_SUSPICIOUS_FLAGS flags = WkdTapSuspicious_None;
    WKD_TAP_ATTACK_TYPE attack = WkdTapAttack_None;
    WKD_PAP_VERDICT verdict = WkdPapVerdict_Allow;
    ACCESS_MASK deniedMask = 0;
    ACCESS_MASK requestedAccess = 0;
    ULONG score = 0;
    BOOLEAN targetIsSystemThread = FALSE;
    WKD_PROCESS_ACCESS_OPERATION operation;

    if (!SourceWkdProcess || !OperationInformation ||
        !TargetWkdProcess || !TargetWkdProcess->SecurityContext) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 运行时未初始化 / 关闭中 -> 放行
    //
    if (InterlockedCompareExchange(&g_TapRuntime.Initialized, 0, 0) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }

    targetThread = (PETHREAD)OperationInformation->Object;

    InterlockedIncrement64(&g_TapRuntime.Stats.TotalEvaluations);

    //
    // 解析 OB 现场（不再经中转结构，直取）
    //
    operation =
        (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
            ? WkdPapOperation_Create
            : WkdPapOperation_Duplicate;
    requestedAccess = CbpGetOriginalDesiredAccess(OperationInformation);

    //
    // 目标等级：直读归属进程安全画像（volatile 32 位读，x64 对齐原子）
    //
    level = (WKD_PAP_PROTECTION_LEVEL)(
                (TargetWkdProcess->SecurityContext->PapProfile & WKD_PAP_PROFILE_MASK_LEVEL) >>
                WKD_PAP_PROFILE_SHIFT_LEVEL
            );
    if (level == WkdPapLevel_None) goto Done;
    result.ProtectionLevel = level;

    //
    // 自保护绕过标记：源进程亦受保护但访问其它受保护进程的线程 -> 标记
    // 2026-09-05 收敛：受保护 = 源安全上下文 PapProfile 非零（表内进程创建
    // 回调已采集，先于线程可句柄化；与目标等级同源直读）。不再经
    // SpIsProcessProtected/AU 表（AU 表默认空、无注册路径，恒 FALSE 死逻辑）。
    //
    if (SourceWkdProcess->SecurityContext->PapProfile != 0 &&
        SourceWkdProcess->Core.ProcessId != TargetWkdProcess->Core.ProcessId) {
        flags |= WkdTapSuspicious_SelfProtectBypass;
    }

    //
    // 分析（flag + 打分）
    //
    targetIsSystemThread = PsIsSystemThread(targetThread);
    result.TargetIsSystemThread = targetIsSystemThread;

    TappAnalyzeOperation(
        SourceWkdProcess->Core.ProcessId,
        TargetWkdProcess->Core.ProcessId,
        requestedAccess,
        targetIsSystemThread,
        flags,
        &flags,
        &score);

    result.Flags = flags;
    result.SuspicionScore = score;

    //
    // 攻击类型判定
    //
    attack = TappDetectAttack(requestedAccess, targetIsSystemThread);
    result.DetectedAttack = attack;

    //
    // 裁决（Tap 不产出 Block）
    //
    verdict = TappDetermineVerdict(flags, score, attack, level);
    result.Verdict = verdict;

    //
    // 剥离：在 Pap（进程级）与 AU 已剥离（current DesiredAccess）基础上
    // 二次剥离 Tap 的线程级位（current & ~TapMask，一次写回）
    //
    if (verdict == WkdPapVerdict_Strip) {
        deniedMask = TappCalculateDeniedMask(level);
        deniedMask &= requestedAccess;
        result.DeniedMask = deniedMask;

        if (deniedMask != 0) {
            InterlockedIncrement64(&g_TapRuntime.Stats.AccessStripped);
        }
    }

    //
    // 统计
    //
    if (deniedMask & THREAD_TERMINATE) {
        InterlockedIncrement64(&g_TapRuntime.Stats.TerminateAttempts);
    }
    if (deniedMask & (THREAD_GET_CONTEXT | THREAD_SET_CONTEXT)) {
        InterlockedIncrement64(&g_TapRuntime.Stats.ContextAccessAttempts);
    }
    if (deniedMask & THREAD_SUSPEND_RESUME) {
        InterlockedIncrement64(&g_TapRuntime.Stats.SuspendAttempts);
    }
    if (deniedMask & (THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION)) {
        InterlockedIncrement64(&g_TapRuntime.Stats.ImpersonationAttempts);
    }
    if (attack == WkdTapAttack_APCInjection) {
        InterlockedIncrement64(&g_TapRuntime.Stats.APCInjectionPatterns);
    }
    if (attack == WkdTapAttack_ContextHijack) {
        InterlockedIncrement64(&g_TapRuntime.Stats.HijackPatterns);
    }
    if (attack == WkdTapAttack_SystemThread) {
        InterlockedIncrement64(&g_TapRuntime.Stats.SystemThreadAttempts);
    }
    if (flags & WkdTapSuspicious_CrossProcess) {
        InterlockedIncrement64(&g_TapRuntime.Stats.CrossProcessAccess);
    }
    if (flags & WkdTapSuspicious_SelfProtectBypass) {
        InterlockedIncrement64(&g_TapRuntime.Stats.SelfProtectBypassAttempts);
    }
    if (flags != WkdTapSuspicious_None) {
        InterlockedIncrement64(&g_TapRuntime.Stats.SuspiciousOperations);
    }

    //
    // 日志（对齐 SS TppLogOperation 精简版）
    //
    //if (verdict == WkdPapVerdict_Strip &&
    //    deniedMask != 0 &&
    //    g_TapRuntime.LogStrippedAccess) {
    //    TappLogStrippedAccess(
    //        SourceWkdProcess->Core.ProcessId,
    //        targetThread,
    //        TargetWkdProcess->Core.ProcessId,
    //        operation,
    //        deniedMask,
    //        score,
    //        level,
    //        attack);
    //}

    //
    // Strip 写回：与 Pap/AU 剥离结果同槽合并一次写回
    //
    if (result.DeniedMask != 0) {
        ObjpPapApplyDeniedMask(OperationInformation, result.DeniedMask);
    }

Done:
    return STATUS_SUCCESS;
}

/**************************************************/
/*           PreOperation 回调                     */
/**************************************************/

//
// 对象 PreOperation 回调
//
_Use_decl_annotations_
static
OB_PREOP_CALLBACK_STATUS
CbpObjectNotifyPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
/*++
Routine Description:
    对象 PreOperation 回调，在句柄创建/复制时被调用。

    负责：
    1. 过滤系统进程和自访问
    2. 检查敏感权限访问
    3. 将敏感访问事件通过 WKD_MESSAGE 发送给 IOA 分析引擎

    注意：
    - 始终返回 OB_PREOP_SUCCESS（仅监控，不拦截）
    - PostOperation 未注册，不处理

Arguments:
    RegistrationContext  — 注册上下文（未使用）。
    OperationInformation — PreOperation 信息。

Returns:
    OB_PREOP_SUCCESS — 总是允许操作继续。
--*/
{
    NTSTATUS status;
    PWKD_PROCESS sourceWkdProcess = NULL;
    PWKD_PROCESS targetWkdProcess = NULL;
    ACCESS_MASK desiredAccess = 0;
    ACCESS_MASK sensitiveMask = 0;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!g_ObjManager.Initialized || g_ObjManager.ShutdownRequested) {
        goto Permit;
    }

    //
    // 快速路径 - 过滤
    //
    {
        PEPROCESS targetProcess;
        HANDLE sourceProcessId = PsGetCurrentProcessId();

        /* ---- 1. 源为 System（PID 4）：隐式信任 ---- */
        if (HandleToULong(sourceProcessId) == 4) goto Permit;

        /* ---- 2. 内核句柄（默认放行，Windows 兼容；可配置过滤）---- */
        if (OperationInformation->KernelHandle &&
            !g_PapRuntime.Config.EnableKernelHandleFiltering) {
            goto Permit;
        }

        /* ---- 3. 启动宽限期：Session 0 上下文调用者完全放行（防 winlogon 灰屏）---- */
        //if (PappIsInBootGrace() &&
        //    SourceWkdProcess->SecurityContext != NULL &&
        //    SourceWkdProcess->SecurityContext->SessionId == 0) {
        //    return TRUE;
        //}

        /* EDR 组件互信：2026-09-05 删除——原实现依赖 SpIsProcessProtected
         * （AU 表，默认空），且位于本块 sourceWkdProcess 查找赋值之前，
         * 对 NULL 解引用属 P0 缺陷。源受保护判定（SelfProtectBypass 旗标）
         * 已收敛为 Tap 审计入口直读安全上下文画像。 */

        /* ---- 跳过白名单 ---- */
        if (ExemptsIsProcessTrusted(sourceProcessId)) {
            goto Permit;
        }

        /* ---- 获取源进程对象 ---- */
        sourceWkdProcess = PsLookupWkdProcessByProcessId(sourceProcessId);
        if (!sourceWkdProcess) {
            // 发生严重的系统错误!
            // 在未经进程监控的情况下向未知进程发起 Object 操作
            // 可能是进程漏检或者被恶意隐藏
            DbgBreakPoint();
        }

        /* ---- 获取目标进程对象 ---- */
        if (OperationInformation->ObjectType == *PsProcessType) {
            targetProcess = (PEPROCESS)OperationInformation->Object;
            InterlockedIncrement64(&g_ObjManager.Statistics.ProcessOps);
        } else {  // PsThreadType
            targetProcess = IoThreadToProcess((PETHREAD)OperationInformation->Object);
            InterlockedIncrement64(&g_ObjManager.Statistics.ThreadOps);
        }
        targetWkdProcess = PsLookupWkdProcessByProcessId(PsGetProcessId(targetProcess));

        /* ---- 跳过自访问 ---- */
        if (sourceWkdProcess == targetWkdProcess) goto Permit;
    }

    /* ---- 获取请求的访问权限 ---- */
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        desiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    } else {
         ASSERT(sourceWkdProcess->Core.EProcess ==
             OperationInformation->Parameters->DuplicateHandleInformation.SourceProcess);
        ASSERT(targetWkdProcess->Core.EProcess ==
            OperationInformation->Parameters->DuplicateHandleInformation.TargetProcess);

        desiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;

        /* 句柄复制事件上送（对齐 SS ObjectCallback.c 两处 HtRecordDuplication，
         * HandleTracker 迁移 2026-08）。死代码：本模块 CbInitializeObjectNotify
         * 被 WkdEntry 注释未激活；跨进程复制关联由 Agent 因果图消费
         * （对齐 SS PrAddRelationship(PrRelation_HandleDuplication)）。 */
        //CbpNotifyIoaHandleDuplicate(
        //    sourceProcessId,
        //    PsGetProcessId(targetProcess),
        //    OperationInformation->ObjectType,
        //    desiredAccess);
    }

    InterlockedIncrement64(&g_ObjManager.Statistics.TotalPreOps);

    //
    // 2026-09-05：AU 句柄访问剥离（SpCheckObjectAccessMask）删除。
    // 受保护进程（PapProfile 非零）的 DesiredAccess 危险位剥离已由下方
    // CbpAuditProcessAccess / CbpAuditThreadAccess 审计主链承接。
    //

    if (OperationInformation->ObjectType == *PsProcessType) {
        status = CbpAuditProcessAccess(sourceWkdProcess, targetWkdProcess, OperationInformation);
    } else if (OperationInformation->ObjectType == *PsThreadType) {
        status = CbpAuditThreadAccess(sourceWkdProcess, targetWkdProcess, OperationInformation);
    } else {
        // 非法类型???
        DbgBreakPoint();
    }

    //
    // 检查是否为敏感权限访问
    //
    //if (CbpCheckObjectSensitiveAccess(OperationInformation->ObjectType,
    //    OperationInformation->Operation, desiredAccess, &sensitiveMask)) {
    //    InterlockedIncrement64(&g_ObjManager.Statistics.SensitiveAccess);

        //
        // 调用编排器：IOC 检测 + 后续编排
        //
        //AeOrchestratorDispatch(sourceWkdProcess, NULL,
        //          WkdMessage_SourceObjectCallback,
        //          WkdMessage_ProcessObjectAccess,
        //          OperationInformation);

        //
        // 发送事件到 IOA 分析引擎
        //
        //CbpNotifyIoaObjectAccess(
        //    sourceProcessId,
        //    targetProcessId,
        //    OperationInformation->ObjectType,
        //    desiredAccess,
        //    sensitiveMask);
    // }

Permit:
    //
    // 释放引用（源/目标均由回调 PsLookupWkdProcessByProcessId 查找即 +1）
    //
    if (sourceWkdProcess) PsDereferenceWkdProcess(sourceWkdProcess);
    if (targetWkdProcess) PsDereferenceWkdProcess(targetWkdProcess);

    //
    // 始终允许操作（仅监控，不拦截）
    //
    return OB_PREOP_SUCCESS;
}
