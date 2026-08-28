/**************************************************/
/*  WkDefender — 令牌分析引擎实现（全功能版）        */
/*  参考 PhantomSensor: TokenAnalyzer.c +            */
/*  PrivilegeMonitor.c (2026-08-05 融合迁移)         */
/*  TaAnalyzeToken / TaDetectTokenManipulation /     */
/*  TapDetectAttackType / TapCalculateSuspicionScore/ */
/*  PmRecordBaseline / PmCheckForEscalation /         */
/*  PmpDetermineEscalationType / PmpCalculateScore /  */
/*  PmpIsLegitimateEscalation / PmpDetectUACBypass    */
/**************************************************/

#include "TokenAnalyzer.h"
#include <strsafe.h>

#pragma comment(lib, "advapi32.lib")

//
// 基线标志
//
#define WPA_BASELINE_FLAG_SUSPICIOUS 0x00000002

//
// 哈希桶结构
//
typedef struct _WPA_TOKEN_HASH_BUCKET {
    LIST_ENTRY List;
    LONG       Count;
} WPA_TOKEN_HASH_BUCKET, *PWPA_TOKEN_HASH_BUCKET;

/**************************************************/
/*                      静态表                     */
/**************************************************/

//
// UAC 绕过模式表（对齐 SS g_UACBypassPatterns:333-443, 10 模式）
// 分值: PM_SUSPICION_MEDIUM=45 / HIGH=70 / CRITICAL=90
//
static const WPA_UAC_PATTERN g_WpaUacBypassPatterns[] = {
    { L"fodhelper.exe",       L"explorer.exe", NULL, "T1548.002-fodhelper-UAC-Bypass",      70 },
    { L"eventvwr.exe",        L"explorer.exe", NULL, "T1548.002-eventvwr-UAC-Bypass",       70 },
    { L"sdclt.exe",           L"explorer.exe", NULL, "T1548.002-sdclt-UAC-Bypass",          45 },
    { L"computerdefaults.exe",L"explorer.exe", NULL, "T1548.002-computerdefaults-UAC-Bypass",70 },
    { L"cmstp.exe",           NULL,            L"/au", "T1548.002-cmstp-UAC-Bypass",        90 },
    { L"WSReset.exe",         L"explorer.exe", NULL, "T1548.002-WSReset-UAC-Bypass",        70 },
    { L"slui.exe",            L"explorer.exe", NULL, "T1548.002-slui-UAC-Bypass",           45 },
    { L"cleanmgr.exe",        NULL,            L"/autoclean", "T1548.002-DiskCleanup-UAC-Bypass", 45 },
    { L"cleanmgr.exe",        L"svchost.exe",  NULL, "T1548.002-SilentCleanup-UAC-Bypass",  70 },
    { L"msconfig.exe",        L"explorer.exe", NULL, "T1548.002-msconfig-UAC-Bypass",       45 }
};

#define WPA_UAC_PATTERN_COUNT (sizeof(g_WpaUacBypassPatterns) / sizeof(g_WpaUacBypassPatterns[0]))

//
// 已知合法提权进程名单（对齐 SS g_LegitimateElevationProcesses:450-466, 15 条）
//
static const PCWSTR g_WpaLegitimateProcesses[] = {
    L"consent.exe",
    L"svchost.exe",
    L"services.exe",
    L"lsass.exe",
    L"csrss.exe",
    L"wininit.exe",
    L"winlogon.exe",
    L"smss.exe",
    L"System",
    L"dwm.exe",
    L"taskhostw.exe",
    L"RuntimeBroker.exe",
    L"sihost.exe",
    L"fontdrvhost.exe",
    L"WmiPrvSE.exe"
};

#define WPA_LEGITIMATE_PROCESS_COUNT \
    (sizeof(g_WpaLegitimateProcesses) / sizeof(g_WpaLegitimateProcesses[0]))

//
// 攻击类型字符串（对齐 SS TapAttackTypeStrings:476-486）
//
static const PCWSTR g_WpaAttackTypeStrings[] = {
    L"None",
    L"Impersonation",
    L"TokenStealing",
    L"PrivilegeEscalation",
    L"SIDInjection",
    L"IntegrityDowngrade",
    L"GroupModification",
    L"PrimaryTokenReplace",
    L"Unknown"
};

//
// 完整性级别字符串（对齐 SS TapIntegrityLevelStrings:488-497）
//
static const PCWSTR g_WpaIntegrityLevelStrings[] = {
    L"Untrusted",
    L"Low",
    L"Medium",
    L"MediumPlus",
    L"High",
    L"System",
    L"Protected",
    L"Unknown"
};

//
// 提权类型字符串（对齐 SS PM_ESCALATION_TYPE 顺序）
//
static const PCWSTR g_WpaEscalationTypeStrings[] = {
    L"None",
    L"PrivilegeEnable",
    L"TokenElevation",
    L"IntegrityIncrease",
    L"UACBypass",
    L"ServiceCreation",
    L"DriverLoad",
    L"ExploitKernel",
    L"TokenManipulation",
    L"CrossSession",
    L"Unknown"
};

/**************************************************/
/*                      全局引擎                   */
/**************************************************/

//
// 令牌分析引擎（模块级单例）
//
static struct {
    BOOLEAN          Initialized;
    BOOLEAN          ShutdownRequested;
    WPA_TOKEN_CONFIG Config;

    WPA_TOKEN_HASH_BUCKET HashBuckets[WPA_TA_HASH_BUCKETS];
    LIST_ENTRY            BaselineList;
    CRITICAL_SECTION      BaselineLock;
    LONG                  BaselineCount;

    LIST_ENTRY       EventList;
    CRITICAL_SECTION EventLock;
    LONG             EventCount;

    LONG EscalationsDetected;       /* 对齐 SS PM_STATISTICS.EscalationsDetected */
    LONG LegitimateEscalations;     /* 对齐 SS PM_STATISTICS.LegitimateEscalations */
    LONG BlockedEscalations;        /* 对齐 SS PM_STATISTICS.BlockedEscalations (monitor-only 未消费) */
    LONG BaselinesCaptured;
    LONG BaselinesRemoved;

    FILETIME StartTime;             /* 引擎启动时间 */
    FILETIME LastCleanupTime;       /* 最近一次清理时间 */
} g_WpaAnalyzer;

/**************************************************/
/*                      哈希辅助                   */
/**************************************************/

//
// PID 哈希（Murmur 风格混合, 对齐 wkd WpaPmHashPid）
//
static ULONG
WpaHashPid(
    _In_ HANDLE Pid
    )
{
    ULONG_PTR v = (ULONG_PTR)Pid;
    v ^= (v >> 16);
    v *= 0x85ebca6b;
    v ^= (v >> 13);
    v *= 0xc2b2ae35;
    v ^= (v >> 16);
    return (ULONG)(v & WPA_TA_HASH_MASK);
}

/**************************************************/
/*                      令牌采集                   */
/**************************************************/

//
// 判断 SID 是否为已知 SID
//
static BOOLEAN
WpaIsWellKnownSid(
    _In_ PSID Sid,
    _In_ WELL_KNOWN_SID_TYPE Type
    )
{
    BOOLEAN result = FALSE;
    DWORD size = SECURITY_MAX_SID_SIZE;
    PSID testSid = HeapAlloc(GetProcessHeap(), 0, size);
    if (testSid == NULL) return FALSE;

    if (CreateWellKnownSid(Type, NULL, testSid, &size)) {
        result = EqualSid(Sid, testSid);
    }

    HeapFree(GetProcessHeap(), 0, testSid);
    return result;
}

//
// 分析组 SID（对齐 SS TapIsSidAdmin/System/Service/NetworkService/LocalService）
// 注意: 此处 IsSystem/IsService 为 SID 语义（token 是否含对应 SID）。
//
static VOID
WpaAnalyzeGroups(
    _In_  HANDLE    TokenHandle,
    _Out_ PBOOLEAN  IsAdmin,
    _Out_ PBOOLEAN  IsSystem,
    _Out_ PBOOLEAN  IsService,
    _Out_ PBOOLEAN  IsNetworkService,
    _Out_ PBOOLEAN  IsLocalService
    )
{
    DWORD size = 0;
    PTOKEN_GROUPS groups;

    *IsAdmin = FALSE;
    *IsSystem = FALSE;
    *IsService = FALSE;
    *IsNetworkService = FALSE;
    *IsLocalService = FALSE;

    GetTokenInformation(TokenHandle, TokenGroups, NULL, 0, &size);
    if (size == 0) return;

    groups = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(), 0, size);
    if (groups == NULL) return;

    if (!GetTokenInformation(TokenHandle, TokenGroups, groups, size, &size)) {
        HeapFree(GetProcessHeap(), 0, groups);
        return;
    }

    for (DWORD i = 0; i < groups->GroupCount; i++) {
        if (!(groups->Groups[i].Attributes & SE_GROUP_ENABLED)) {
            continue;
        }

        if (WpaIsWellKnownSid(groups->Groups[i].Sid, WinBuiltinAdministratorsSid)) {
            *IsAdmin = TRUE;
        }
        if (WpaIsWellKnownSid(groups->Groups[i].Sid, WinLocalSystemSid)) {
            *IsSystem = TRUE;
        }
        if (WpaIsWellKnownSid(groups->Groups[i].Sid, WinServiceSid)) {
            *IsService = TRUE;
        }
        if (WpaIsWellKnownSid(groups->Groups[i].Sid, WinNetworkServiceSid)) {
            *IsNetworkService = TRUE;
        }
        if (WpaIsWellKnownSid(groups->Groups[i].Sid, WinLocalServiceSid)) {
            *IsLocalService = TRUE;
        }
    }

    HeapFree(GetProcessHeap(), 0, groups);
}

//
// 查询令牌特权 → 位图 + Has* 标志 + 启用计数
// 对齐 SS PmpConvertPrivilegesToFlags:2528 (仅计 SE_PRIVILEGE_ENABLED)
//
static VOID
WpaQueryPrivileges(
    _In_  HANDLE  TokenHandle,
    _Out_ PULONG  PrivilegeBitmap,
    _Out_ PULONG  PrivilegeCount,
    _Out_ PBOOLEAN HasDebug,
    _Out_ PBOOLEAN HasImpersonate,
    _Out_ PBOOLEAN HasAssignPrimary,
    _Out_ PBOOLEAN HasTcb,
    _Out_ PBOOLEAN HasLoadDriver,
    _Out_ PBOOLEAN HasBackup,
    _Out_ PBOOLEAN HasRestore
    )
{
    DWORD size = 0;
    PTOKEN_PRIVILEGES tp;

    *PrivilegeBitmap = 0;
    *PrivilegeCount = 0;
    *HasDebug = FALSE;
    *HasImpersonate = FALSE;
    *HasAssignPrimary = FALSE;
    *HasTcb = FALSE;
    *HasLoadDriver = FALSE;
    *HasBackup = FALSE;
    *HasRestore = FALSE;

    GetTokenInformation(TokenHandle, TokenPrivileges, NULL, 0, &size);
    if (size == 0) return;

    tp = (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), 0, size);
    if (tp == NULL) return;

    if (GetTokenInformation(TokenHandle, TokenPrivileges, tp, size, &size)) {
        for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
            if (!(tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)) {
                continue;
            }

            (*PrivilegeCount)++;

            switch (tp->Privileges[i].Luid.LowPart) {
                case SE_DEBUG_PRIVILEGE:
                    *HasDebug = TRUE;
                    *PrivilegeBitmap |= WPA_PRIV_DEBUG;
                    break;
                case SE_IMPERSONATE_PRIVILEGE:
                    *HasImpersonate = TRUE;
                    *PrivilegeBitmap |= WPA_PRIV_IMPERSONATE;
                    break;
                case SE_ASSIGNPRIMARYTOKEN_PRIVILEGE:
                    *HasAssignPrimary = TRUE;
                    *PrivilegeBitmap |= WPA_PRIV_ASSIGN_PRIMARY;
                    break;
                case SE_TCB_PRIVILEGE:
                    *HasTcb = TRUE;
                    *PrivilegeBitmap |= WPA_PRIV_TCB;
                    break;
                case SE_LOAD_DRIVER_PRIVILEGE:
                    *HasLoadDriver = TRUE;
                    *PrivilegeBitmap |= WPA_PRIV_LOAD_DRIVER;
                    break;
                case SE_BACKUP_PRIVILEGE:
                    *HasBackup = TRUE;
                    *PrivilegeBitmap |= WPA_PRIV_BACKUP;
                    break;
                case SE_RESTORE_PRIVILEGE:
                    *HasRestore = TRUE;
                    *PrivilegeBitmap |= WPA_PRIV_RESTORE;
                    break;
                case SE_CREATE_TOKEN_PRIVILEGE:
                    *PrivilegeBitmap |= WPA_PRIV_CREATE_TOKEN;
                    break;
                case SE_SECURITY_PRIVILEGE:
                    *PrivilegeBitmap |= WPA_PRIV_SECURITY;
                    break;
                case SE_TAKE_OWNERSHIP_PRIVILEGE:
                    *PrivilegeBitmap |= WPA_PRIV_TAKE_OWNERSHIP;
                    break;
                default:
                    break;
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, tp);
}

//
// 查询令牌完整性级别
//
static ULONG
WpaQueryIntegrityLevel(
    _In_ HANDLE TokenHandle
    )
{
    PTOKEN_MANDATORY_LABEL label = NULL;
    DWORD size = 0;
    ULONG level = WPA_INTEGRITY_MEDIUM;

    GetTokenInformation(TokenHandle, TokenIntegrityLevel, NULL, 0, &size);
    if (size == 0) return level;

    label = (PTOKEN_MANDATORY_LABEL)HeapAlloc(GetProcessHeap(), 0, size);
    if (label == NULL) return level;

    if (GetTokenInformation(TokenHandle, TokenIntegrityLevel, label, size, &size)) {
        if (label->Label.Sid) {
            level = *GetSidSubAuthority(label->Label.Sid,
                (DWORD)(*GetSidSubAuthorityCount(label->Label.Sid) - 1));
        }
    }

    HeapFree(GetProcessHeap(), 0, label);
    return level;
}

//
// 全量令牌采集（对齐 SS TapQueryTokenInformation:1935-2086 +
// PmpCaptureTokenState:2362 的 IsSystem/IsService 行为化判定）
// 仅采集不检测。PrivilegeBitmap 可选输出。
//
static HRESULT
WpaCaptureTokenInfo(
    _In_  HANDLE        ProcessId,
    _Out_ PWPA_TOKEN_INFO Info,
    _Out_opt_ PULONG    PrivilegeBitmap
    )
{
    HANDLE hProcess, hToken;
    TOKEN_TYPE tokenType;
    TOKEN_STATISTICS stats;
    DWORD size;

    if (Info == NULL) return E_INVALIDARG;
    RtlZeroMemory(Info, sizeof(*Info));
    Info->ProcessId = ProcessId;
    if (PrivilegeBitmap) *PrivilegeBitmap = 0;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE,
        HandleToULong(ProcessId));
    if (hProcess == NULL) {
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
            HandleToULong(ProcessId));
    }
    if (hProcess == NULL) return HRESULT_FROM_WIN32(GetLastError());

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    /* TokenType + ImpersonationLevel */
    size = sizeof(tokenType);
    if (GetTokenInformation(hToken, TokenType, &tokenType, size, &size)) {
        Info->TokenType = (ULONG)tokenType;
    }

    {
        SECURITY_IMPERSONATION_LEVEL imp;
        size = sizeof(imp);
        if (GetTokenInformation(hToken, TokenImpersonationLevel, &imp, size, &size)) {
            Info->ImpersonationLevel = (ULONG)imp;
        }
    }

    /* 统计信息（含 AuthId + TokenId + 特权/组总数, 对齐 SS TapQueryTokenInformation:1958-1967） */
    size = sizeof(stats);
    if (GetTokenInformation(hToken, TokenStatistics, &stats, size, &size)) {
        Info->AuthenticationId = stats.AuthenticationId;
        Info->TokenId = stats.TokenId;
        Info->PrivilegeCount = stats.PrivilegeCount;
        Info->GroupCount = stats.GroupCount;
    }

    /* 特权（位图 + 启用计数, 对齐 SS PmpConvertPrivilegesToFlags） */
    WpaQueryPrivileges(hToken,
        &Info->PrivilegeBitmap,
        &Info->EnabledPrivileges,
        &Info->HasDebugPrivilege,
        &Info->HasImpersonatePrivilege,
        &Info->HasAssignPrimaryPrivilege,
        &Info->HasTcbPrivilege,
        &Info->HasLoadDriverPrivilege,
        &Info->HasBackupPrivilege,
        &Info->HasRestorePrivilege);

    if (PrivilegeBitmap) *PrivilegeBitmap = Info->PrivilegeBitmap;

    /* 完整性 */
    Info->IntegrityLevel = WpaQueryIntegrityLevel(hToken);

    /* 组/SID 分析 */
    WpaAnalyzeGroups(hToken,
        &Info->IsAdmin, &Info->IsSystem, &Info->IsService,
        &Info->IsNetworkService, &Info->IsLocalService);

    /* 受限令牌 */
    {
        TOKEN_ELEVATION_TYPE elevType;
        size = sizeof(elevType);
        if (GetTokenInformation(hToken, TokenElevationType, &elevType, size, &size)) {
            Info->IsRestricted = (elevType == TokenElevationTypeLimited);
            Info->IsFiltered = (elevType == TokenElevationTypeLimited);
        }
    }

    /* 提权 */
    {
        TOKEN_ELEVATION elev;
        size = sizeof(elev);
        if (GetTokenInformation(hToken, TokenElevation, &elev, size, &size)) {
            Info->IsElevated = (elev.TokenIsElevated != 0);
        }
    }

    /* 会话 ID */
    {
        DWORD sid;
        size = sizeof(sid);
        if (GetTokenInformation(hToken, TokenSessionId, &sid, size, &size)) {
            Info->SessionId = sid;
        }
    }

    /* 虚拟化（对齐 SS TapQueryTokenInformation TokenVirtualizationEnabled） */
    {
        DWORD virt = 0;
        size = sizeof(virt);
        if (GetTokenInformation(hToken, TokenVirtualizationEnabled, &virt, size, &size)) {
            Info->IsVirtualized = (virt != 0);
        }
    }

    /* 沙箱惰性（对齐 SS TokenSandBoxInert） */
    {
        DWORD inert = 0;
        size = sizeof(inert);
        if (GetTokenInformation(hToken, TokenSandBoxInert, &inert, size, &size)) {
            Info->IsSandboxed = (inert != 0);
        }
    }

    /* AppContainer（对齐 SS TokenIsAppContainer） */
    {
        DWORD appc = 0;
        size = sizeof(appc);
        if (GetTokenInformation(hToken, TokenIsAppContainer, &appc, size, &size)) {
            Info->IsAppContainer = (appc != 0);
        }
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);

    return S_OK;
}

/**************************************************/
/*                      基线管理                   */
/**************************************************/

//
// 行为化 SYSTEM/服务判定（对齐 SS PmpCaptureTokenState:2442-2451）
// System = Session0 + System 完整性；Service = Session0 + elevated + 非System。
//
static BOOLEAN
WpaIsBehavioralSystem(
    _In_ PWPA_TOKEN_INFO Info
    )
{
    return (Info->SessionId == 0 && Info->IntegrityLevel >= WPA_INTEGRITY_SYSTEM);
}

static BOOLEAN
WpaIsBehavioralService(
    _In_ PWPA_TOKEN_INFO Info
    )
{
    return (Info->SessionId == 0 && Info->IsElevated &&
            !(Info->IntegrityLevel >= WPA_INTEGRITY_SYSTEM));
}

//
// 查找基线（锁内找到即 +1 引用, 调用方必须 WpaDereferenceBaseline）
//
static PWPA_TOKEN_BASELINE
WpaLookupBaseline(
    _In_ HANDLE ProcessId
    )
{
    ULONG hash = WpaHashPid(ProcessId);
    PLIST_ENTRY entry;
    PWPA_TOKEN_BASELINE bl = NULL;

    EnterCriticalSection(&g_WpaAnalyzer.BaselineLock);
    for (entry = g_WpaAnalyzer.HashBuckets[hash].List.Flink;
         entry != &g_WpaAnalyzer.HashBuckets[hash].List;
         entry = entry->Flink) {

        bl = CONTAINING_RECORD(entry, WPA_TOKEN_BASELINE, HashEntry);
        if (bl->ProcessId == ProcessId && !bl->IsTerminated) {
            InterlockedIncrement(&bl->RefCount);
            LeaveCriticalSection(&g_WpaAnalyzer.BaselineLock);
            return bl;
        }
    }
    LeaveCriticalSection(&g_WpaAnalyzer.BaselineLock);
    return NULL;
}

//
// 释放基线引用（减到 0 时从哈希/链表移除并释放）
//
static VOID
WpaDereferenceBaseline(
    _In_ PWPA_TOKEN_BASELINE Baseline
    )
{
    ULONG hash;

    if (Baseline == NULL) return;

    if (InterlockedDecrement(&Baseline->RefCount) != 0) {
        return;
    }

    hash = WpaHashPid(Baseline->ProcessId);

    EnterCriticalSection(&g_WpaAnalyzer.BaselineLock);
    RemoveEntryList(&Baseline->HashEntry);
    RemoveEntryList(&Baseline->ListEntry);
    InterlockedDecrement(&g_WpaAnalyzer.BaselineCount);
    InterlockedDecrement(&g_WpaAnalyzer.HashBuckets[hash].Count);
    LeaveCriticalSection(&g_WpaAnalyzer.BaselineLock);

    HeapFree(GetProcessHeap(), 0, Baseline);
}

//
// 插入基线（列表 + 哈希双链, RefCount=1 由列表持有）
//
static HRESULT
WpaInsertBaseline(
    _In_ PWPA_TOKEN_BASELINE Baseline
    )
{
    ULONG hash = WpaHashPid(Baseline->ProcessId);

    EnterCriticalSection(&g_WpaAnalyzer.BaselineLock);
    if (g_WpaAnalyzer.BaselineCount >= WPA_TA_MAX_BASELINES) {
        LeaveCriticalSection(&g_WpaAnalyzer.BaselineLock);
        return E_OUTOFMEMORY;
    }

    Baseline->RefCount = 1;
    InsertTailList(&g_WpaAnalyzer.HashBuckets[hash].List, &Baseline->HashEntry);
    InterlockedIncrement(&g_WpaAnalyzer.HashBuckets[hash].Count);
    InsertTailList(&g_WpaAnalyzer.BaselineList, &Baseline->ListEntry);
    InterlockedIncrement(&g_WpaAnalyzer.BaselineCount);
    InterlockedIncrement(&g_WpaAnalyzer.BaselinesCaptured);
    LeaveCriticalSection(&g_WpaAnalyzer.BaselineLock);

    return S_OK;
}

/**************************************************/
/*                      攻击检测                   */
/**************************************************/

//
// 攻击检测（对齐 SS TapDetectAttackType:2558-2647）
// Baseline 为 NULL 时仅做无条件检测。
//
static ULONG
WpaDetectAttackType(
    _In_ PWPA_TOKEN_INFO Current,
    _In_opt_ PWPA_TOKEN_BASELINE Baseline
    )
{
    if (Baseline != NULL) {
        /* Token 替换（AuthId 变化） */
        if (Current->AuthenticationId.LowPart != Baseline->AuthenticationId.LowPart ||
            Current->AuthenticationId.HighPart != Baseline->AuthenticationId.HighPart) {
            if (Current->TokenType == TokenPrimary) {
                return WpaAttack_PrimaryTokenReplace;
            }
            return WpaAttack_TokenStealing;
        }

        /* 特权提升（启用特权数增加 > 3） */
        if (Current->EnabledPrivileges > Baseline->OriginalPrivilegeCount + 3) {
            return WpaAttack_PrivilegeEscalation;
        }

        /* 完整性升高 */
        if (Current->IntegrityLevel > Baseline->OriginalIntegrityLevel) {
            return WpaAttack_PrivilegeEscalation;
        }

        /* 完整性降低（沙箱逃逸准备） */
        if (Current->IntegrityLevel < Baseline->OriginalIntegrityLevel) {
            return WpaAttack_IntegrityDowngrade;
        }

        /* SID 注入 */
        if (Current->IsAdmin && !Baseline->OriginalIsAdmin) {
            return WpaAttack_SIDInjection;
        }

        /* System 提权 */
        if (Current->IsSystem && !Baseline->OriginalIsSystem) {
            return WpaAttack_TokenStealing;
        }

        /* 令牌类型变化（Primary→Impersonation） */
        if (Baseline->TokenType == TokenPrimary &&
            Current->TokenType == TokenImpersonation) {
            return WpaAttack_Impersonation;
        }

        /* 组数激增（SID 注入, 对齐 SS TaDetectTokenManipulation:1227-1231） */
        if (Current->GroupCount > Baseline->OriginalGroupCount + 5) {
            return WpaAttack_SIDInjection;
        }
    }

    /* 无基线也可检测的场景 */

    /* 高完整性模拟令牌 */
    if (Current->TokenType == TokenImpersonation &&
        Current->IntegrityLevel >= WPA_INTEGRITY_HIGH) {
        return WpaAttack_Impersonation;
    }

    /* 非服务进程持有危险特权组合（SeDebug+SeImpersonate+SeAssignPrimary） */
    if (!Current->IsService && !Current->IsNetworkService &&
        !Current->IsLocalService &&
        Current->HasDebugPrivilege &&
        Current->HasImpersonatePrivilege &&
        Current->HasAssignPrimaryPrivilege) {
        return WpaAttack_PrivilegeEscalation;
    }

    return WpaAttack_None;
}

//
// 令牌攻击评分（对齐 SS TapCalculateSuspicionScore:2651-2750）
//
static ULONG
WpaCalculateSuspicionScore(
    _In_ PWPA_TOKEN_INFO Info,
    _In_ ULONG Attack
    )
{
    ULONG score = 0;

    switch (Attack) {
        case WpaAttack_TokenStealing:
            score = 90;
            break;
        case WpaAttack_PrimaryTokenReplace:
            score = 95;
            break;
        case WpaAttack_PrivilegeEscalation:
            score = 85;
            break;
        case WpaAttack_SIDInjection:
            score = 90;
            break;
        case WpaAttack_IntegrityDowngrade:
            score = 60;
            break;
        case WpaAttack_GroupModification:
            score = 75;
            break;
        case WpaAttack_Impersonation:
            score = 70;
            break;
        default:
            break;
    }

    /* 危险特权加成 */
    if (Info->HasDebugPrivilege) score += 15;
    if (Info->HasAssignPrimaryPrivilege) score += 10;
    if (Info->HasImpersonatePrivilege) score += 5;
    if (Info->HasTcbPrivilege) score += 20;
    if (Info->HasLoadDriverPrivilege) score += 15;

    /* 提权状态加成 */
    if (Info->IsSystem) {
        score += 10;
    } else if (Info->IsAdmin) {
        score += 5;
    }

    /* 完整性级别加成 */
    if (Info->IntegrityLevel >= WPA_INTEGRITY_SYSTEM) {
        score += 15;
    } else if (Info->IntegrityLevel >= WPA_INTEGRITY_HIGH) {
        score += 10;
    }

    /* 模拟令牌 + 模拟级别加成 */
    if (Info->TokenType == TokenImpersonation) {
        if (Info->ImpersonationLevel >= SecurityImpersonation) score += 10;
        if (Info->ImpersonationLevel >= SecurityDelegation) score += 15;
    }

    if (score > 100) score = 100;
    return score;
}

/**************************************************/
/*                      提权检测                   */
/**************************************************/

//
// 提权类型判定（对齐 SS PmpDetermineEscalationType:2648-2707）
// 优先级: AuthId→TokenManipulation, 跨会话→CrossSession,
// 完整性跳级→TokenElevation/ExploitKernel/IntegrityIncrease,
// 特权增→DriverLoad/ExploitKernel/PrivilegeEnable。
//
static WPA_ESCALATION_TYPE
WpaDetermineEscalationType(
    _In_ ULONG OldIntegrity,
    _In_ ULONG NewIntegrity,
    _In_ ULONG OldPrivileges,
    _In_ ULONG NewPrivileges,
    _In_ ULONG OldSessionId,
    _In_ ULONG NewSessionId,
    _In_ PLUID OldAuthId,
    _In_ PLUID NewAuthId
    )
{
    ULONG addedPrivileges = NewPrivileges & ~OldPrivileges;

    /* Token 替换/窃取（最严重） */
    if (OldAuthId->LowPart != NewAuthId->LowPart ||
        OldAuthId->HighPart != NewAuthId->HighPart) {
        return WpaEscalation_TokenManipulation;
    }

    /* 跨会话（用户会话 → Session0） */
    if (OldSessionId != NewSessionId && NewSessionId == 0 && OldSessionId != 0) {
        return WpaEscalation_CrossSession;
    }

    /* 完整性升高 */
    if (NewIntegrity > OldIntegrity) {
        if (OldIntegrity <= WPA_INTEGRITY_MEDIUM && NewIntegrity >= WPA_INTEGRITY_HIGH) {
            return WpaEscalation_TokenElevation;
        }
        if (NewIntegrity >= WPA_INTEGRITY_SYSTEM) {
            return WpaEscalation_ExploitKernel;
        }
        return WpaEscalation_IntegrityIncrease;
    }

    /* 新增敏感特权 */
    if (addedPrivileges != 0) {
        if (addedPrivileges & WPA_PRIV_LOAD_DRIVER) {
            return WpaEscalation_DriverLoad;
        }
        if (addedPrivileges & (WPA_PRIV_TCB | WPA_PRIV_CREATE_TOKEN)) {
            return WpaEscalation_ExploitKernel;
        }
        return WpaEscalation_PrivilegeEnable;
    }

    return WpaEscalation_None;
}

//
// 提权评分（对齐 SS PmpCalculateSuspicionScore:2710-2819）
//
static ULONG
WpaCalculateEscalationScore(
    _In_ PWPA_ESCALATION_EVENT Event,
    _In_ PWPA_TOKEN_BASELINE Baseline
    )
{
    ULONG score = 0;
    ULONG newPrivs;

    switch (Event->Type) {
        case WpaEscalation_ExploitKernel:
            score += 95;
            break;
        case WpaEscalation_TokenManipulation:
            score += 90;
            break;
        case WpaEscalation_UACBypass:
            score += 85;
            break;
        case WpaEscalation_CrossSession:
            score += 80;
            break;
        case WpaEscalation_DriverLoad:
            score += 75;
            break;
        case WpaEscalation_TokenElevation:
            score += 65;
            break;
        case WpaEscalation_ServiceCreation:
            score += 55;
            break;
        case WpaEscalation_IntegrityIncrease:
            score += 45;
            break;
        case WpaEscalation_PrivilegeEnable:
            score += 35;
            break;
        default:
            score += 20;
            break;
    }

    /* 完整性跳级幅度 */
    if (Event->NewIntegrityLevel > Event->OldIntegrityLevel) {
        ULONG jump = Event->NewIntegrityLevel - Event->OldIntegrityLevel;
        if (jump >= 0x3000) {
            score += 25;
        } else if (jump >= 0x2000) {
            score += 15;
        } else if (jump >= 0x1000) {
            score += 5;
        }
    }

    /* 新增敏感特权 */
    newPrivs = Event->NewPrivileges & ~Event->OldPrivileges;
    if (newPrivs & WPA_PRIV_DEBUG) score += 15;
    if (newPrivs & WPA_PRIV_TCB) score += 30;
    if (newPrivs & WPA_PRIV_LOAD_DRIVER) score += 25;
    if (newPrivs & WPA_PRIV_CREATE_TOKEN) score += 30;
    if (newPrivs & WPA_PRIV_ASSIGN_PRIMARY) score += 20;
    if (newPrivs & WPA_PRIV_SECURITY) score += 15;
    if (newPrivs & WPA_PRIV_TAKE_OWNERSHIP) score += 10;
    if (newPrivs & WPA_PRIV_BACKUP) score += 10;
    if (newPrivs & WPA_PRIV_RESTORE) score += 10;

    /* 非提权进程获得高完整性 */
    if (!Baseline->OriginalIsElevated && Event->NewIntegrityLevel >= WPA_INTEGRITY_HIGH) {
        score += 15;
    }

    /* 非 SYSTEM 进程获得系统完整性 */
    if (!Baseline->OriginalIsSystem && Event->NewIntegrityLevel >= WPA_INTEGRITY_SYSTEM) {
        score += 25;
    }

    /* 用户会话进入 Session0 */
    if (Baseline->OriginalSessionId != 0 && Event->NewSessionId == 0) {
        score += 20;
    }

    if (score > 100) score = 100;
    return score;
}

//
// 合法提权判定（对齐 SS PmpIsLegitimateEscalation:2822-2865）
//
static BOOLEAN
WpaIsLegitimateEscalation(
    _In_ PWPA_ESCALATION_EVENT Event,
    _In_ PWPA_TOKEN_BASELINE Baseline
    )
{
    ULONG i;

    /* SYSTEM 进程提权常为合法 */
    if (Baseline->OriginalIsSystem) {
        return TRUE;
    }

    /* Session0 服务提权常为合法 */
    if (Baseline->OriginalIsService && Baseline->OriginalSessionId == 0) {
        return TRUE;
    }

    /* 已知合法提权进程 */
    if (Event->ProcessName[0] != L'\0') {
        for (i = 0; i < WPA_LEGITIMATE_PROCESS_COUNT; i++) {
            if (_wcsicmp(Event->ProcessName, g_WpaLegitimateProcesses[i]) == 0) {
                return TRUE;
            }
        }
    }

    /* 低分建议合法 */
    if (Event->SuspicionScore < WPA_SUSPICION_LOW) {
        return TRUE;
    }

    return FALSE;
}

//
// UAC 绕过检测（对齐 SS PmpDetectUACBypass:2868-2942, 10 模式）
// CommandLinePattern 为死代码字段（SS 亦不比对命令行）。
//
BOOLEAN
WpaDetectUACBypass(
    _In_  PWPA_TOKEN_BASELINE Baseline,
    _Out_writes_(WPA_TA_MAX_TECHNIQUE) PCHAR TechniqueBuffer,
    _Out_ PULONG PatternScore
    )
{
    ULONG i;

    TechniqueBuffer[0] = '\0';
    *PatternScore = 0;

    if (Baseline->ProcessName[0] == L'\0') {
        return FALSE;
    }

    for (i = 0; i < WPA_UAC_PATTERN_COUNT; i++) {
        const WPA_UAC_PATTERN* pattern = &g_WpaUacBypassPatterns[i];
        BOOLEAN processMatch = FALSE;
        BOOLEAN parentMatch = TRUE;

        if (_wcsicmp(Baseline->ProcessName, pattern->ProcessName) == 0) {
            processMatch = TRUE;
        }
        if (!processMatch) {
            continue;
        }

        /* 父进程匹配（父未指定默认 TRUE） */
        if (pattern->ParentProcessName != NULL) {
            parentMatch = FALSE;
            if (Baseline->ParentProcessName[0] != L'\0') {
                if (_wcsicmp(Baseline->ParentProcessName,
                             pattern->ParentProcessName) == 0) {
                    parentMatch = TRUE;
                }
            }
        }

        if (!parentMatch) {
            /* 进程匹配但父不匹配 — 仍可疑但降半 */
            if (*PatternScore < pattern->SuspicionScore / 2) {
                *PatternScore = pattern->SuspicionScore / 2;
            }
            continue;
        }

        /* 完全匹配 */
        StringCchCopyA(TechniqueBuffer, WPA_TA_MAX_TECHNIQUE,
                       pattern->TechniqueName);
        *PatternScore = pattern->SuspicionScore;
        return TRUE;
    }

    return FALSE;
}

//
// 创建提权事件并入队（对齐 SS PmpAllocateEvent/PmpInsertEvent）
//
static PWPA_ESCALATION_EVENT
WpaCreateEscalationEvent(
    _In_ PWPA_TOKEN_BASELINE Baseline,
    _In_ WPA_ESCALATION_TYPE Type,
    _In_ PWPA_TOKEN_INFO Current
    )
{
    PWPA_ESCALATION_EVENT evt;

    evt = (PWPA_ESCALATION_EVENT)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY, sizeof(WPA_ESCALATION_EVENT));
    if (evt == NULL) return NULL;

    evt->Type = Type;
    evt->ProcessId = Baseline->ProcessId;
    evt->ParentProcessId = Baseline->ParentProcessId;
    wcscpy_s(evt->ProcessName, ARRAYSIZE(evt->ProcessName), Baseline->ProcessName);
    wcscpy_s(evt->ParentProcessName, ARRAYSIZE(evt->ParentProcessName),
             Baseline->ParentProcessName);

    evt->OldIntegrityLevel = Baseline->OriginalIntegrityLevel;
    evt->NewIntegrityLevel = Current->IntegrityLevel;
    evt->OldPrivileges = Baseline->OriginalPrivileges;
    evt->NewPrivileges = Current->PrivilegeBitmap;
    evt->OldIsElevated = Baseline->OriginalIsElevated;
    evt->NewIsElevated = Current->IsElevated;
    evt->OldSessionId = Baseline->OriginalSessionId;
    evt->NewSessionId = Current->SessionId;
    evt->OldAuthenticationId = Baseline->AuthenticationId;
    evt->NewAuthenticationId = Current->AuthenticationId;

    GetSystemTimeAsFileTime(&evt->Timestamp);
    /* BaselineTime: WPA_TOKEN_BASELINE 用 LARGE_INTEGER, 事件记录用 FILETIME,
     * 64 位布局一致 (LowPart=低32位, HighPart=高32位), 逐部件复制。 */
    evt->BaselineTime.dwLowDateTime  = Baseline->BaselineTime.LowPart;
    evt->BaselineTime.dwHighDateTime = (DWORD)Baseline->BaselineTime.HighPart;

    evt->SuspicionScore = WpaCalculateEscalationScore(evt, Baseline);
    if (WpaIsLegitimateEscalation(evt, Baseline)) {
        evt->Flags |= WPA_EVENT_FLAG_LEGITIMATE;
        InterlockedIncrement(&g_WpaAnalyzer.LegitimateEscalations);   /* 对齐 SS L1617 */
    }
    if (evt->SuspicionScore >= g_WpaAnalyzer.Config.MinAlertScore) {
        evt->Flags |= WPA_EVENT_FLAG_ALERTABLE;
    }

    /* BLOCKED 判定（对齐 SS PmCheckForEscalation:1630-1635, monitor-only 未消费） */
    if (g_WpaAnalyzer.Config.BlockHighRiskEscalation &&
        evt->SuspicionScore >= g_WpaAnalyzer.Config.BlockThresholdScore &&
        !(evt->Flags & WPA_EVENT_FLAG_LEGITIMATE)) {
        evt->Flags |= WPA_EVENT_FLAG_BLOCKED;
        InterlockedIncrement(&g_WpaAnalyzer.BlockedEscalations);      /* 对齐 SS L1634 */
    }

    /* 入队（超上限移除最旧） */
    EnterCriticalSection(&g_WpaAnalyzer.EventLock);
    while (g_WpaAnalyzer.EventCount >= WPA_TA_MAX_EVENTS &&
           !IsListEmpty(&g_WpaAnalyzer.EventList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_WpaAnalyzer.EventList);
        HeapFree(GetProcessHeap(), 0,
                 CONTAINING_RECORD(entry, WPA_ESCALATION_EVENT, ListEntry));
        InterlockedDecrement(&g_WpaAnalyzer.EventCount);
    }
    InsertTailList(&g_WpaAnalyzer.EventList, &evt->ListEntry);
    InterlockedIncrement(&g_WpaAnalyzer.EventCount);
    LeaveCriticalSection(&g_WpaAnalyzer.EventLock);

    InterlockedIncrement(&g_WpaAnalyzer.EscalationsDetected);

    return evt;
}

/**************************************************/
/*                      公共 API                   */
/**************************************************/

_Check_return_
HRESULT
WpaTokenAnalyzerInitialize(
    VOID
    )
{
    ULONG i;

    if (g_WpaAnalyzer.Initialized) {
        return S_OK;
    }

    RtlZeroMemory(&g_WpaAnalyzer, sizeof(g_WpaAnalyzer));

    for (i = 0; i < WPA_TA_HASH_BUCKETS; i++) {
        InitializeListHead(&g_WpaAnalyzer.HashBuckets[i].List);
    }
    InitializeListHead(&g_WpaAnalyzer.BaselineList);
    InitializeCriticalSection(&g_WpaAnalyzer.BaselineLock);
    InitializeListHead(&g_WpaAnalyzer.EventList);
    InitializeCriticalSection(&g_WpaAnalyzer.EventLock);

    /* 默认配置（对齐 SS PmInitialize:805-813） */
    g_WpaAnalyzer.Config.EnableIntegrityMonitoring = TRUE;
    g_WpaAnalyzer.Config.EnablePrivilegeMonitoring = TRUE;
    g_WpaAnalyzer.Config.EnableUACBypassDetection = TRUE;
    g_WpaAnalyzer.Config.EnableTokenManipulationDetection = TRUE;
    g_WpaAnalyzer.Config.EnableCrossSessionDetection = TRUE;
    g_WpaAnalyzer.Config.AlertOnEscalation = TRUE;
    g_WpaAnalyzer.Config.BlockHighRiskEscalation = FALSE;
    g_WpaAnalyzer.Config.MinAlertScore = WPA_TA_DEFAULT_MIN_ALERT;
    g_WpaAnalyzer.Config.BlockThresholdScore = WPA_TA_DEFAULT_BLOCK_SCORE;

    GetSystemTimeAsFileTime(&g_WpaAnalyzer.StartTime);

    g_WpaAnalyzer.Initialized = TRUE;
    return S_OK;
}

VOID
WpaTokenAnalyzerShutdown(
    VOID
    )
{
    PLIST_ENTRY entry;

    if (!g_WpaAnalyzer.Initialized) return;
    g_WpaAnalyzer.ShutdownRequested = TRUE;

    /* 释放全部基线 */
    EnterCriticalSection(&g_WpaAnalyzer.BaselineLock);
    while (!IsListEmpty(&g_WpaAnalyzer.BaselineList)) {
        entry = RemoveHeadList(&g_WpaAnalyzer.BaselineList);
        HeapFree(GetProcessHeap(), 0,
                 CONTAINING_RECORD(entry, WPA_TOKEN_BASELINE, ListEntry));
    }
    g_WpaAnalyzer.BaselineCount = 0;
    LeaveCriticalSection(&g_WpaAnalyzer.BaselineLock);

    /* 释放全部事件 */
    EnterCriticalSection(&g_WpaAnalyzer.EventLock);
    while (!IsListEmpty(&g_WpaAnalyzer.EventList)) {
        entry = RemoveHeadList(&g_WpaAnalyzer.EventList);
        HeapFree(GetProcessHeap(), 0,
                 CONTAINING_RECORD(entry, WPA_ESCALATION_EVENT, ListEntry));
    }
    g_WpaAnalyzer.EventCount = 0;
    LeaveCriticalSection(&g_WpaAnalyzer.EventLock);

    DeleteCriticalSection(&g_WpaAnalyzer.BaselineLock);
    DeleteCriticalSection(&g_WpaAnalyzer.EventLock);

    g_WpaAnalyzer.Initialized = FALSE;
    g_WpaAnalyzer.ShutdownRequested = FALSE;
}

_Check_return_
HRESULT
WpaAnalyzeToken(
    _In_  HANDLE        ProcessId,
    _Out_ PWPA_TOKEN_INFO Info
    )
{
    HRESULT hr;

    if (Info == NULL) return E_INVALIDARG;

    hr = WpaCaptureTokenInfo(ProcessId, Info, NULL);
    if (FAILED(hr)) return hr;

    /* 攻击检测（无基线时仅无条件检测, 对齐 SS TaAnalyzeToken:970-980） */
    Info->DetectedAttack = WpaDetectAttackType(Info, NULL);

    /* 评分 */
    Info->SuspicionScore = WpaCalculateSuspicionScore(Info, Info->DetectedAttack);

    return S_OK;
}

_Check_return_
HRESULT
WpaDetectTokenManipulation(
    _In_  HANDLE  ProcessId,
    _Out_ PULONG  Attack,
    _Out_ PULONG  Score
    )
{
    HRESULT hr;
    WPA_TOKEN_INFO current;
    WPA_TOKEN_BASELINE baseline;
    PWPA_TOKEN_BASELINE bl;
    ULONG attackType;
    ULONG score;

    if (Attack == NULL || Score == NULL) return E_INVALIDARG;
    *Attack = WpaAttack_None;
    *Score = 0;

    /* 当前令牌状态 */
    hr = WpaAnalyzeToken(ProcessId, &current);
    if (FAILED(hr)) return hr;

    /* 取基线快照（修复旧版恒传 NULL 缺陷, 对齐 SS TaDetectTokenManipulation:1155） */
    bl = WpaLookupBaseline(ProcessId);
    if (bl != NULL) {
        RtlZeroMemory(&baseline, sizeof(baseline));
        baseline.AuthenticationId = bl->AuthenticationId;
        baseline.TokenType = bl->TokenType;
        baseline.OriginalIntegrityLevel = bl->OriginalIntegrityLevel;
        baseline.OriginalPrivilegeCount = bl->OriginalPrivilegeCount;
        baseline.OriginalIsAdmin = bl->OriginalIsAdmin;
        baseline.OriginalIsSystem = bl->OriginalIsSystem;
        baseline.OriginalGroupCount = bl->OriginalGroupCount;
        WpaDereferenceBaseline(bl);

        attackType = WpaDetectAttackType(&current, &baseline);
    } else {
        attackType = WpaDetectAttackType(&current, NULL);
    }

    if (attackType != WpaAttack_None) {
        *Attack = attackType;
        score = WpaCalculateSuspicionScore(&current, attackType);
        *Score = score;
    }

    return S_OK;
}

_Check_return_
HRESULT
WpaRecordBaseline(
    _In_ HANDLE ProcessId,
    _In_opt_ PCWSTR ProcessName,
    _In_ HANDLE ParentProcessId,
    _In_opt_ PCWSTR ParentProcessName
    )
{
    PWPA_TOKEN_BASELINE baseline;
    WPA_TOKEN_INFO info;
    ULONG privBitmap = 0;
    HRESULT hr;

    if (!g_WpaAnalyzer.Initialized) return E_UNEXPECTED;

    /* 查重 */
    if (WpaLookupBaseline(ProcessId) != NULL) {
        return S_FALSE;
    }

    hr = WpaCaptureTokenInfo(ProcessId, &info, &privBitmap);
    if (FAILED(hr)) return hr;

    baseline = (PWPA_TOKEN_BASELINE)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY, sizeof(WPA_TOKEN_BASELINE));
    if (baseline == NULL) return E_OUTOFMEMORY;

    InitializeListHead(&baseline->ListEntry);
    InitializeListHead(&baseline->HashEntry);
    baseline->ProcessId = ProcessId;
    baseline->ParentProcessId = ParentProcessId;
    if (ProcessName) {
        wcscpy_s(baseline->ProcessName, ARRAYSIZE(baseline->ProcessName), ProcessName);
    }
    if (ParentProcessName) {
        wcscpy_s(baseline->ParentProcessName,
                 ARRAYSIZE(baseline->ParentProcessName), ParentProcessName);
    }

    /* 原始状态 */
    baseline->AuthenticationId = info.AuthenticationId;
    baseline->TokenType = info.TokenType;
    baseline->OriginalIntegrityLevel = info.IntegrityLevel;
    baseline->OriginalPrivileges = privBitmap;
    baseline->OriginalPrivilegeCount = info.EnabledPrivileges;
    baseline->OriginalGroupCount = info.GroupCount;
    baseline->OriginalIsElevated = info.IsElevated;
    baseline->OriginalIsAdmin = info.IsAdmin;
    baseline->OriginalIsSystem = WpaIsBehavioralSystem(&info);
    baseline->OriginalIsService = WpaIsBehavioralService(&info);
    baseline->OriginalSessionId = info.SessionId;

    /* 当前状态与原始一致 */
    baseline->CurrentIntegrityLevel = info.IntegrityLevel;
    baseline->CurrentPrivileges = privBitmap;
    baseline->CurrentIsElevated = info.IsElevated;
    baseline->CurrentSessionId = info.SessionId;
    baseline->CurrentAuthenticationId = info.AuthenticationId;

    GetSystemTimeAsFileTime(&baseline->BaselineTime);
    baseline->LastCheckTime = baseline->BaselineTime;

    hr = WpaInsertBaseline(baseline);
    if (FAILED(hr)) {
        HeapFree(GetProcessHeap(), 0, baseline);
    }

    return hr;
}

_Check_return_
HRESULT
WpaRemoveBaseline(
    _In_ HANDLE ProcessId
    )
{
    PWPA_TOKEN_BASELINE bl;

    bl = WpaLookupBaseline(ProcessId);
    if (bl == NULL) return S_FALSE;

    /* 直接释放引用（WpaDereferenceBaseline 减到 0 时从列表移除） */
    WpaDereferenceBaseline(bl);
    WpaDereferenceBaseline(bl);
    InterlockedIncrement(&g_WpaAnalyzer.BaselinesRemoved);
    return S_OK;
}

_Check_return_
HRESULT
WpaGetBaselineSnapshot(
    _In_  HANDLE ProcessId,
    _Out_ PWPA_TOKEN_BASELINE Snapshot
    )
{
    PWPA_TOKEN_BASELINE bl;

    if (Snapshot == NULL) return E_INVALIDARG;
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));

    bl = WpaLookupBaseline(ProcessId);
    if (bl == NULL) return S_FALSE;

    *Snapshot = *bl;
    InitializeListHead(&Snapshot->ListEntry);
    InitializeListHead(&Snapshot->HashEntry);

    WpaDereferenceBaseline(bl);
    return S_OK;
}

_Check_return_
HRESULT
WpaCheckForEscalation(
    _In_  HANDLE ProcessId,
    _Out_opt_ PWPA_ESCALATION_EVENT* Event
    )
{
    PWPA_TOKEN_BASELINE baseline;
    WPA_TOKEN_INFO info;
    ULONG privBitmap = 0;
    BOOLEAN escalated = FALSE;
    WPA_ESCALATION_TYPE type = WpaEscalation_None;
    PWPA_ESCALATION_EVENT newEvent = NULL;
    HRESULT hr;

    if (Event) *Event = NULL;
    if (!g_WpaAnalyzer.Initialized) return E_UNEXPECTED;

    baseline = WpaLookupBaseline(ProcessId);
    if (baseline == NULL) {
        /* 无基线自动补录（对齐 SS PmCheckForEscalation:1423-1432） */
        hr = WpaRecordBaseline(ProcessId, NULL, NULL, NULL);
        return FAILED(hr) ? hr : S_FALSE;
    }

    if (baseline->IsTerminated) {
        WpaDereferenceBaseline(baseline);
        return S_FALSE;
    }

    hr = WpaCaptureTokenInfo(ProcessId, &info, &privBitmap);
    if (FAILED(hr)) {
        WpaDereferenceBaseline(baseline);
        return hr;
    }

    GetSystemTimeAsFileTime(&baseline->LastCheckTime);
    baseline->CheckCount++;

    /* 1. 完整性升高 */
    if (g_WpaAnalyzer.Config.EnableIntegrityMonitoring &&
        info.IntegrityLevel > baseline->OriginalIntegrityLevel) {
        escalated = TRUE;
        type = WpaEscalation_IntegrityIncrease;
    }

    /* 2. 新增敏感特权 */
    if (g_WpaAnalyzer.Config.EnablePrivilegeMonitoring) {
        ULONG newPrivs = privBitmap & ~baseline->OriginalPrivileges;
        if (newPrivs & WPA_PRIV_SENSITIVE_MASK) {
            escalated = TRUE;
            type = WpaEscalation_PrivilegeEnable;
        }
    }

    /* 3. 提权状态变化 */
    if (!baseline->OriginalIsElevated && info.IsElevated) {
        escalated = TRUE;
        if (type < WpaEscalation_TokenElevation) {
            type = WpaEscalation_TokenElevation;
        }
    }

    /* 4. Token 替换（AuthId 变化） */
    if (g_WpaAnalyzer.Config.EnableTokenManipulationDetection) {
        if (baseline->AuthenticationId.LowPart != info.AuthenticationId.LowPart ||
            baseline->AuthenticationId.HighPart != info.AuthenticationId.HighPart) {
            escalated = TRUE;
            if (type < WpaEscalation_TokenManipulation) {
                type = WpaEscalation_TokenManipulation;
            }
        }
    }

    /* 5. 跨会话进入 Session0 */
    if (g_WpaAnalyzer.Config.EnableCrossSessionDetection) {
        if (baseline->OriginalSessionId != info.SessionId &&
            info.SessionId == 0 && baseline->OriginalSessionId != 0) {
            escalated = TRUE;
            if (type < WpaEscalation_CrossSession) {
                type = WpaEscalation_CrossSession;
            }
        }
    }

    /* 更新当前状态 */
    baseline->CurrentIntegrityLevel = info.IntegrityLevel;
    baseline->CurrentPrivileges = privBitmap;
    baseline->CurrentIsElevated = info.IsElevated;
    baseline->CurrentSessionId = info.SessionId;
    baseline->CurrentAuthenticationId = info.AuthenticationId;

    if (!escalated) {
        WpaDereferenceBaseline(baseline);
        return S_FALSE;
    }

    /* 精化类型（对齐 SS PmpDetermineEscalationType 优先级） */
    type = WpaDetermineEscalationType(
        baseline->OriginalIntegrityLevel, info.IntegrityLevel,
        baseline->OriginalPrivileges, privBitmap,
        baseline->OriginalSessionId, info.SessionId,
        &baseline->AuthenticationId, &info.AuthenticationId);

    /* UAC 绕过检测覆盖类型 */
    if (g_WpaAnalyzer.Config.EnableUACBypassDetection) {
        CHAR technique[WPA_TA_MAX_TECHNIQUE] = { 0 };
        ULONG patternScore = 0;

        if (WpaDetectUACBypass(baseline, technique, &patternScore)) {
            type = WpaEscalation_UACBypass;
            newEvent = WpaCreateEscalationEvent(baseline, type, &info);
            if (newEvent != NULL) {
                if (patternScore > newEvent->SuspicionScore) {
                    newEvent->SuspicionScore = patternScore;
                }
                StringCchCopyA(newEvent->Technique, WPA_TA_MAX_TECHNIQUE,
                               technique);
            }
        }
    }

    if (newEvent == NULL) {
        newEvent = WpaCreateEscalationEvent(baseline, type, &info);
    }

    baseline->EscalationCount++;
    baseline->HasEscalated = TRUE;
    baseline->Flags |= WPA_BASELINE_FLAG_SUSPICIOUS;

    if (Event && newEvent) {
        *Event = newEvent;
    }

    WpaDereferenceBaseline(baseline);
    return S_OK;
}

VOID
WpaOnProcessTerminated(
    _In_ HANDLE ProcessId
    )
{
    PWPA_TOKEN_BASELINE bl;

    bl = WpaLookupBaseline(ProcessId);
    if (bl == NULL) return;

    /* 置终止标记 + 释放引用（Dereference 减到 0 时移除释放） */
    bl->IsTerminated = TRUE;
    WpaDereferenceBaseline(bl);
    WpaDereferenceBaseline(bl);
    InterlockedIncrement(&g_WpaAnalyzer.BaselinesRemoved);
}

/**************************************************/
/*                      比较增强                   */
/**************************************************/

//
// 权限/组增量对比（对齐 SS TapComparePrivileges:3023/TapCompareGroups:3105）
// ※死代码: WPA_TOKEN_INFO 不含特权数组/组 SID 数组, 仅按聚合字段近似。
// 保留 SS 语义: 返回 TRUE = 有增量变化。
//
static BOOLEAN
WpaComparePrivilegeDelta(
    _In_ PWPA_TOKEN_INFO Original,
    _In_ PWPA_TOKEN_INFO Current,
    _Out_ PULONG AddedPrivileges,
    _Out_ PULONG RemovedPrivileges
    )
{
    ULONG added = 0;
    ULONG removed = 0;
    BOOLEAN result;

    /* 启用特权计数差近似增量（细粒度需完整特权数组, 当前结构不包含） */
    if (Current->PrivilegeCount > Original->PrivilegeCount) {
        added = Current->PrivilegeCount - Original->PrivilegeCount;
    } else if (Original->PrivilegeCount > Current->PrivilegeCount) {
        removed = Original->PrivilegeCount - Current->PrivilegeCount;
    }

    *AddedPrivileges = added;
    *RemovedPrivileges = removed;
    result = (added > 0 || removed > 0);

    UNREFERENCED_PARAMETER(Original);
    UNREFERENCED_PARAMETER(Current);
    return result;
}

//
// 组 SID 增量对比（对齐 SS TapCompareGroups:3105-3175）
// ※近似: WPA_TOKEN_INFO 不含组 SID 数组, 仅按 GroupCount 差值近似增减;
// 细粒度 (具体哪些 SID 增减) 需结构补组数组。WpaCompareTokens 已用
// IsService/IsNetworkService/IsLocalService 状态 + 此组数增量覆盖组变化。
//
static BOOLEAN
WpaCompareGroupSet(
    _In_ PWPA_TOKEN_INFO Info1,
    _In_ PWPA_TOKEN_INFO Info2,
    _Out_ PULONG AddedGroups,
    _Out_ PULONG RemovedGroups
    )
{
    ULONG added = 0;
    ULONG removed = 0;
    BOOLEAN result;

    if (Info2->GroupCount > Info1->GroupCount) {
        added = Info2->GroupCount - Info1->GroupCount;
    } else if (Info1->GroupCount > Info2->GroupCount) {
        removed = Info1->GroupCount - Info2->GroupCount;
    }

    *AddedGroups = added;
    *RemovedGroups = removed;
    result = (added > 0 || removed > 0);

    UNREFERENCED_PARAMETER(Info1);
    UNREFERENCED_PARAMETER(Info2);
    return result;
}

_Check_return_
HRESULT
WpaCompareTokens(
    _In_  PWPA_TOKEN_INFO Original,
    _In_  PWPA_TOKEN_INFO Current,
    _Out_ PBOOLEAN        Changed
    )
{
    ULONG addedPriv, removedPriv;
    ULONG addedGroups, removedGroups;

    if (Original == NULL || Current == NULL || Changed == NULL) {
        return E_INVALIDARG;
    }

    *Changed = FALSE;

    /* AuthId 变化 */
    if (Original->AuthenticationId.LowPart != Current->AuthenticationId.LowPart ||
        Original->AuthenticationId.HighPart != Current->AuthenticationId.HighPart) {
        *Changed = TRUE;
        return S_OK;
    }

    /* 令牌类型变化 */
    if (Original->TokenType != Current->TokenType) {
        *Changed = TRUE;
        return S_OK;
    }

    /* 模拟级别变化 */
    if (Original->ImpersonationLevel != Current->ImpersonationLevel) {
        *Changed = TRUE;
        return S_OK;
    }

    /* 完整性变化 */
    if (Original->IntegrityLevel != Current->IntegrityLevel) {
        *Changed = TRUE;
        return S_OK;
    }

    /* 管理员状态变化 */
    if (Original->IsAdmin != Current->IsAdmin) {
        *Changed = TRUE;
        return S_OK;
    }

    /* System 状态变化 */
    if (Original->IsSystem != Current->IsSystem) {
        *Changed = TRUE;
        return S_OK;
    }

    /* 服务/网络服务/本地服务状态变化（对齐 SS TaCompareTokens:1367-1372） */
    if (Original->IsService != Current->IsService ||
        Original->IsNetworkService != Current->IsNetworkService ||
        Original->IsLocalService != Current->IsLocalService) {
        *Changed = TRUE;
        return S_OK;
    }

    /* 特权计数显著变化 */
    if (Current->EnabledPrivileges > Original->EnabledPrivileges + 3) {
        *Changed = TRUE;
        return S_OK;
    }

    /* 特权增量（对齐 SS TapComparePrivileges, 近似） */
    if (WpaComparePrivilegeDelta(Original, Current, &addedPriv, &removedPriv)) {
        *Changed = TRUE;
        return S_OK;
    }

    /* 组增量（对齐 SS TapCompareGroups, 近似） */
    if (WpaCompareGroupSet(Original, Current, &addedGroups, &removedGroups)) {
        *Changed = TRUE;
        return S_OK;
    }

    /* SessionId 变化 */
    if (Original->SessionId != Current->SessionId) {
        *Changed = TRUE;
        return S_OK;
    }

    /* TokenId 变化（同一 AuthId 下令牌被替换, 对齐 SS TaCompareTokens:1377-1381） */
    if (Original->TokenId.LowPart != Current->TokenId.LowPart ||
        Original->TokenId.HighPart != Current->TokenId.HighPart) {
        *Changed = TRUE;
        return S_OK;
    }

    return S_OK;
}

/**************************************************/
/*                 事件/配置/清理 API               */
/**************************************************/

_Check_return_
HRESULT
WpaGetEscalationEvents(
    _Out_writes_(MaxEvents) WPA_ESCALATION_EVENT* Events,
    _In_  ULONG             MaxEvents,
    _Out_ PULONG            EventCount
    )
/*++
Routine Description:
    出队全部提权事件（对齐 SS PmGetEvents, 拷贝值+释放队内块）。
    调用者持有出队项拷贝, 无需额外释放。

Arguments:
    Events      - 接收事件数组（调用者提供 MaxEvents 大小的缓冲区）。
    MaxEvents   - 最大返回条数。
    EventCount  - 实际返回条数。

Return Value:
    S_OK 有事件 / S_FALSE 无事件 / E_INVALIDARG 参数错误。
--*/
{
    ULONG count = 0;

    if (!g_WpaAnalyzer.Initialized) return E_UNEXPECTED;
    if (Events == NULL || EventCount == NULL || MaxEvents == 0) {
        return E_INVALIDARG;
    }
    *EventCount = 0;

    EnterCriticalSection(&g_WpaAnalyzer.EventLock);
    while (!IsListEmpty(&g_WpaAnalyzer.EventList) && count < MaxEvents) {
        PLIST_ENTRY entry = RemoveHeadList(&g_WpaAnalyzer.EventList);
        Events[count] = *CONTAINING_RECORD(entry, WPA_ESCALATION_EVENT, ListEntry);
        HeapFree(GetProcessHeap(), 0,
                 CONTAINING_RECORD(entry, WPA_ESCALATION_EVENT, ListEntry));
        count++;
    }
    g_WpaAnalyzer.EventCount -= (LONG)count;
    LeaveCriticalSection(&g_WpaAnalyzer.EventLock);

    *EventCount = count;
    return count > 0 ? S_OK : S_FALSE;
}

_Check_return_
HRESULT
WpaClearEscalationEvents(
    VOID
    )
/*++
Routine Description:
    清空全部提权事件队列（对齐 SS PmClearEvents）。

Return Value:
    S_OK。
--*/
{
    if (!g_WpaAnalyzer.Initialized) return E_UNEXPECTED;
    EnterCriticalSection(&g_WpaAnalyzer.EventLock);
    while (!IsListEmpty(&g_WpaAnalyzer.EventList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_WpaAnalyzer.EventList);
        HeapFree(GetProcessHeap(), 0,
                 CONTAINING_RECORD(entry, WPA_ESCALATION_EVENT, ListEntry));
    }
    g_WpaAnalyzer.EventCount = 0;
    LeaveCriticalSection(&g_WpaAnalyzer.EventLock);

    return S_OK;
}

_Check_return_
HRESULT
WpaQueryProcessEscalation(
    _In_  HANDLE   ProcessId,
    _Out_ PBOOLEAN HasEscalated,
    _Out_ PULONG   EscalationCount,
    _Out_ PULONG   CurrentIntegrityLevel
    )
/*++
Routine Description:
    查询进程是否已发生提权（对齐 SS PmQueryProcessEscalation:1918-1959）。

Arguments:
    ProcessId             - 目标进程 ID。
    HasEscalated          - 是否已提权。
    EscalationCount       - 提权次数。
    CurrentIntegrityLevel - 当前完整性级别。

Return Value:
    S_OK / S_FALSE 无基线。
--*/
{
    PWPA_TOKEN_BASELINE bl;

    if (!g_WpaAnalyzer.Initialized) return E_UNEXPECTED;
    if (HasEscalated) *HasEscalated = FALSE;
    if (EscalationCount) *EscalationCount = 0;
    if (CurrentIntegrityLevel) *CurrentIntegrityLevel = 0;

    bl = WpaLookupBaseline(ProcessId);
    if (bl == NULL) return S_FALSE;

    if (HasEscalated) *HasEscalated = bl->HasEscalated;
    if (EscalationCount) *EscalationCount = bl->EscalationCount;
    if (CurrentIntegrityLevel) *CurrentIntegrityLevel = bl->CurrentIntegrityLevel;

    WpaDereferenceBaseline(bl);
    return S_OK;
}

_Check_return_
HRESULT
WpaGetConfig(
    _Out_ PWPA_TOKEN_CONFIG Config
    )
/*++
Routine Description:
    获取引擎配置（对齐 SS PmGetConfiguration）。

Return Value:
    S_OK / E_INVALIDARG。
--*/
{
    if (!g_WpaAnalyzer.Initialized) return E_UNEXPECTED;
    if (Config == NULL) return E_INVALIDARG;
    *Config = g_WpaAnalyzer.Config;
    return S_OK;
}

_Check_return_
HRESULT
WpaSetConfig(
    _In_ PWPA_TOKEN_CONFIG Config
    )
/*++
Routine Description:
    设置引擎配置（对齐 SS PmSetConfiguration）。

Return Value:
    S_OK / E_INVALIDARG。
--*/
{
    if (!g_WpaAnalyzer.Initialized) return E_UNEXPECTED;
    if (Config == NULL) return E_INVALIDARG;
    g_WpaAnalyzer.Config = *Config;
    return S_OK;
}

_Check_return_
HRESULT
WpaGetStatistics(
    _Out_ PWPA_TOKEN_STATISTICS Stats
    )
/*++
Routine Description:
    获取引擎统计（对齐 SS PmGetStatistics:1964-1996）。
    计数经 InterlockedCompareExchange 原子读取（对齐 SS 语义）。

Arguments:
    Stats - 接收统计快照。

Return Value:
    S_OK / E_UNEXPECTED / E_INVALIDARG。
--*/
{
    if (!g_WpaAnalyzer.Initialized) return E_UNEXPECTED;
    if (Stats == NULL) return E_INVALIDARG;

    Stats->EscalationsDetected   = InterlockedCompareExchange(&g_WpaAnalyzer.EscalationsDetected, 0, 0);
    Stats->LegitimateEscalations = InterlockedCompareExchange(&g_WpaAnalyzer.LegitimateEscalations, 0, 0);
    Stats->BlockedEscalations    = InterlockedCompareExchange(&g_WpaAnalyzer.BlockedEscalations, 0, 0);
    Stats->BaselinesCaptured     = InterlockedCompareExchange(&g_WpaAnalyzer.BaselinesCaptured, 0, 0);
    Stats->BaselinesRemoved      = InterlockedCompareExchange(&g_WpaAnalyzer.BaselinesRemoved, 0, 0);
    Stats->CurrentBaselineCount  = InterlockedCompareExchange(&g_WpaAnalyzer.BaselineCount, 0, 0);
    Stats->CurrentEventCount     = InterlockedCompareExchange(&g_WpaAnalyzer.EventCount, 0, 0);
    Stats->StartTime             = g_WpaAnalyzer.StartTime;
    Stats->LastCleanupTime       = g_WpaAnalyzer.LastCleanupTime;

    return S_OK;
}

VOID
WpaCleanupStaleBaselines(
    VOID
    )
/*++
Routine Description:
    清理过期基线（对齐 SS PmpCleanupStaleBaselines:3001, 进程消失则置终止标记）。
    ※死代码: wkd 进程退出回调 (ProcessExit 事件) 已触发 WpaOnProcessTerminated
      立即清理; 此为 SS 周期兜底迁移, 无周期触发源。置终止标记后基线不再被
      WpaLookupBaseline/WpaCheckForEscalation 使用, 由进程退出路径移除释放。
--*/
{
    PLIST_ENTRY entry, next;

    if (!g_WpaAnalyzer.Initialized) return;
    EnterCriticalSection(&g_WpaAnalyzer.BaselineLock);

    for (entry = g_WpaAnalyzer.BaselineList.Flink;
         entry != &g_WpaAnalyzer.BaselineList;
         entry = next) {

        PWPA_TOKEN_BASELINE bl;
        HANDLE h;

        next = entry->Flink;
        bl = CONTAINING_RECORD(entry, WPA_TOKEN_BASELINE, ListEntry);

        if (bl->IsTerminated) {
            continue;
        }

        h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                        HandleToULong(bl->ProcessId));
        if (h == NULL) {
            bl->IsTerminated = TRUE;  /* 进程已消失 */
        } else {
            CloseHandle(h);
        }
    }

    LeaveCriticalSection(&g_WpaAnalyzer.BaselineLock);

    GetSystemTimeAsFileTime(&g_WpaAnalyzer.LastCleanupTime);
}

/**************************************************/
/*                      工具函数                   */
/**************************************************/

PCWSTR
WpaAttackTypeToString(
    _In_ ULONG Attack
    )
{
    if (Attack >= WpaAttack_MaxValue) {
        return g_WpaAttackTypeStrings[WpaAttack_MaxValue];
    }
    return g_WpaAttackTypeStrings[Attack];
}

PCWSTR
WpaIntegrityLevelToString(
    _In_ ULONG IntegrityLevel
    )
{
    if (IntegrityLevel == WPA_INTEGRITY_UNTRUSTED) {
        return g_WpaIntegrityLevelStrings[0];
    } else if (IntegrityLevel <= WPA_INTEGRITY_LOW) {
        return g_WpaIntegrityLevelStrings[1];
    } else if (IntegrityLevel <= WPA_INTEGRITY_MEDIUM) {
        return g_WpaIntegrityLevelStrings[2];
    } else if (IntegrityLevel <= WPA_INTEGRITY_MEDIUM_PLUS) {
        return g_WpaIntegrityLevelStrings[3];
    } else if (IntegrityLevel <= WPA_INTEGRITY_HIGH) {
        return g_WpaIntegrityLevelStrings[4];
    } else if (IntegrityLevel <= WPA_INTEGRITY_SYSTEM) {
        return g_WpaIntegrityLevelStrings[5];
    } else if (IntegrityLevel <= WPA_INTEGRITY_PROTECTED) {
        return g_WpaIntegrityLevelStrings[6];
    }
    return g_WpaIntegrityLevelStrings[7];
}

PCWSTR
WpaEscalationTypeToString(
    _In_ ULONG EscalationType
    )
{
    if (EscalationType >= WpaEscalation_Max) {
        return g_WpaEscalationTypeStrings[WpaEscalation_Max];
    }
    return g_WpaEscalationTypeStrings[EscalationType];
}
