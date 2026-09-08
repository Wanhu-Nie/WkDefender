/**************************************************/
/*  WkDefender Agent — 进程保护决策引擎实现          */
/*  (ProcessProtection.c)                           */
/*                                                   */
/*  纯 C 实现 ShadowStrike ProcessProtection.cpp/hpp  */
/*  迁移。本文件完整覆盖 SS 进程保护能力面：          */
/*   - 访问过滤决策判定链（自访问/目标校验/白名单/    */
/*     SS 组件/SYSTEM/保护级别/威胁分类/危险剥离/      */
/*     覆盖回调）                                    */
/*   - 配置系统（SetConfiguration/DefaultResponse/    */
/*     ThreatResponse 表）                           */
/*   - PPL 提升闭环（Agent 侧占位，驱动桥接后生效）   */
/*   - 进程保护（信息富集/关键进程/完整性/SD 管理）   */
/*   - 线程保护（ProtectThread 系列/HideFromDebugger）*/
/*   - 回调注册/注销（4 类）+ 状态通知                */
/*   - 统计/历史/报告/自检                           */
/*                                                   */
/*  依赖驱动的活性动作（PPL 提升、句柄过滤、终止源    */
/*  处置）保留表达与记账逻辑，"待驱动桥接"占位。      */
/*                                                   */
/*  全部函数 PASSIVE_LEVEL。                          */
/*  编码：UTF-8 with BOM（铁律）                     */
/**************************************************/

#include "ProcessProtection.h"
#include "AccessControlEngine.h"        /* AcGetAccessControlEngine + AcEnumerateProtectedProcessPtrs（受保护进程链，2026-09-06） */
#include "../Process/ProcessTree.h"     /* PsLookupWkdProcessByProcessId + WKD_THREAD 线程链枚举 (2026-09-06) */
#include <wchar.h>

#include <psapi.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <winternl.h>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

/* ------------------------------------------------------------------ */
/* 私有常量                                                           */
/* ------------------------------------------------------------------ */

/* NtQueryInformationProcess 信息类（对齐 SS 自用类常量） */
#define PP_PROCESS_BASIC_INFORMATION      0
#define PP_PROCESS_DEBUG_PORT             7
#define PP_PROCESS_DEBUG_FLAGS           31

/* 自定义进程保护信息类（对齐 SS：class 61。SS 用 61 迁移时标记，
 * 需与 WkDefender 驱动核对一致；若驱动实现不一致在此改回。） */
#define PP_PROCESS_PROTECTION_INFORMATION 61

/* SDK 未提供 PROCESS_READ_CONTROL/WRITE_DAC/WRITE_OWNER 前缀宏，
 * 此处补标准权限位（与 winnt.h 的 READ_CONTROL/WRITE_DAC/WRITE_OWNER 一致；
 * 注意不可用 0x0200/0x0400/0x0800——那是进程对象特定位，会与
 * PROCESS_SET_INFORMATION 等撞车导致 GetKernelObjectSecurity 拒绝）。 */
#ifndef PROCESS_READ_CONTROL
#define PROCESS_READ_CONTROL   (0x00020000)
#endif
#ifndef PROCESS_WRITE_DAC
#define PROCESS_WRITE_DAC      (0x00040000)
#endif
#ifndef PROCESS_WRITE_OWNER
#define PROCESS_WRITE_OWNER    (0x00080000)
#endif

/* 系统关键进程镜像名清单（对齐 SS kCriticalOsImages，防护硬排除） */
static const WCHAR* const PpCriticalOsImages[] = {
    L"winlogon.exe",
    L"lsass.exe",
    L"csrss.exe",
    L"smss.exe",
    L"wininit.exe",
    L"services.exe",
};

/* 本产品组件镜像名清单（对齐 SS IsShadowStrikeComponent 语义：
 * 进程自身 + 已知组件镜像名；组件可直接访问受保护进程。） */
static const WCHAR* const PpComponentImages[] = {
    L"wkdefender@agent.exe",
    L"wkdefenderagent.exe",
    L"wkdefender.exe",
    L"wkdefenderservice.exe",
    L"wkdefenderui.exe",
};

/* 威胁动作可响应索引映射表（对齐 SS m_threatResponses 默认表）：
 * 索引 = 威胁动作位序号（PpThreatXxx 为 1<<n，n=0..8）。
 * 未列入的威胁动作（MemoryAlloc/TokenSteal/ContextModify 等）
 * 回退默认响应。 */
#define PP_THREAT_RESPONSE_TABLE_SIZE    9

/* ------------------------------------------------------------------ */
/* 私有类型                                                           */
/* ------------------------------------------------------------------ */

/* 对齐内核 PS_PROTECTION 的用户态结构（避免 SDK 版本差异） */
typedef struct _PP_PS_PROTECTION {
    volatile UCHAR  Level;   /* 高 4 位 type，低 4 位 signer */
} PP_PS_PROTECTION, *PPP_PS_PROTECTION;

#define PP_PS_PROTECTED_SIGNER_SHIFT     0
#define PP_PS_PROTECTED_SIGNER_MASK      0x0F
#define PP_PS_PROTECTED_TYPE_SHIFT       4
#define PP_PS_PROTECTED_TYPE_MASK        0xF0

/* ntdll 动态函数指针集合 */
typedef struct _PP_NTDLL {
    HMODULE Hmdl;
    NTSTATUS (NTAPI *pNtQueryInformationProcess)(
        _In_ HANDLE, _In_ ULONG, _Out_ PVOID, _In_ ULONG, _Out_opt_ PULONG);
    NTSTATUS (NTAPI *pRtlSetProcessIsCritical)(
        _In_ BOOLEAN, _Out_ PBOOLEAN, _In_ BOOLEAN);
} PP_NTDLL, *PPP_NTDLL;

/* 白名单记录 */
typedef struct _PP_WHITELIST_ENTRY {
    BOOLEAN     InUse;
    WCHAR       ProcessName[PP_MAX_DESCRIPTION];  /* 小写镜像名 */
} PP_WHITELIST_ENTRY, *PPP_WHITELIST_ENTRY;

/* 阻断事件记录（环形缓冲） */
typedef struct _PP_BLOCKED_LOG {
    PP_BLOCKED_ACCESS_EVENT Event;
    BOOLEAN                 InUse;
} PP_BLOCKED_LOG, *PPP_BLOCKED_LOG;

/* 回调注册槽位（每类回调一组） */
typedef struct _PP_CALLBACK_SLOT {
    BOOLEAN     InUse;
    ULONG64     Id;
    PVOID       Callback;
    PVOID       Context;
} PP_CALLBACK_SLOT, *PPP_CALLBACK_SLOT;

/* ------------------------------------------------------------------ */
/* 私有引擎上下文                                                     */
/* ------------------------------------------------------------------ */

struct _PP_ENGINE {
    PP_NTDLL                    Ntdll;

    CRITICAL_SECTION            Lock;
    CRITICAL_SECTION            CallbackLock;

    /* 2026-09-06 受保护进程域化: ProtectedProcesses 镜像数组与受保护线程
     * 台账均已删除——保护状态分别落 WKD_PROCESS::AccessControlContext
     * 与反调试引擎（线程防调试 2026-09-06 统一归位 AntiDebug）。 */
    PP_WHITELIST_ENTRY          Whitelist[PP_MAX_WHITELIST];
    PP_BLOCKED_LOG              BlockedLog[PP_MAX_BLOCKED_ATTEMPTS_LOG];
    ULONG                       BlockedLogCount;

    /* 配置与处置表 */
    PP_CONFIGURATION            Config;
    PP_THREAT_RESPONSE          ThreatResponses[PP_THREAT_RESPONSE_TABLE_SIZE];

    /* 回调注册（4 类 + 初始化静态回调） */
    PP_CALLBACKS                Callbacks;                  /* PpInitialize 注入的静态回调 */
    PP_CALLBACK_SLOT            AccessCallbacks[PP_MAX_CALLBACKS];
    PP_CALLBACK_SLOT            BlockedCallbacks[PP_MAX_CALLBACKS];
    PP_CALLBACK_SLOT            StatusCallbacks[PP_MAX_CALLBACKS];
    PP_CALLBACK_SLOT            ThreatCallbacks[PP_MAX_CALLBACKS];
    ULONG64                     NextCallbackId;

    /* 状态 */
    volatile LONG               Initialized;
    volatile LONG               Status;         /* PP_MODULE_STATUS */
    volatile LONG               IsPPL;          /* 当前进程是否已 PPL（Agent 记忆） */

    ULONG                       NextEventId;    /* 阻断事件 ID 单调递增源 */

    PP_STATISTICS               Stats;
};

/* ------------------------------------------------------------------ */
/* 内部全局：当前进程保护引擎（单例，供 PpGetProtectionLevel 等        */
/* 无 Engine 参数的便捷 API 使用；由 PpInitialize 设置，PpCleanup 清空）*/
/* ------------------------------------------------------------------ */

static PPP_ENGINE g_ProcessProtectionEngine = NULL;

/* ------------------------------------------------------------------ */
/* 私有工具函数声明（内部假定正确使用，不验证参数）                     */
/* ------------------------------------------------------------------ */

static VOID PpWideLower(_Inout_ PWSTR Str);

static ULONG PpGetProcessName(
    _In_ ULONG ProcessId,
    _Out_writes_(MaxLen) PWSTR ImageName,
    _In_ ULONG MaxLen
    );

static BOOLEAN PpEqualProcessName(
    _In_ PCWSTR Name,
    _In_ PCWSTR Target
    );

static BOOLEAN PpIsWkdComponent(
    _In_ ULONG ProcessId
    );

static PP_THREAT_RESPONSE PpGetResponseForAction(
    _In_ PPP_ENGINE Engine,
    _In_ PP_THREAT_ACTION Action
    );

static VOID PpFireBlockedAccess(
    _In_ PPP_ENGINE Engine,
    _In_ PPP_BLOCKED_ACCESS_EVENT Event
    );

static VOID PpFireThreat(
    _In_ PPP_ENGINE Engine,
    _In_ PP_THREAT_ACTION Action,
    _In_ PPP_ACCESS_REQUEST Request
    );

static VOID PpNotifyProtectionStatus(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG ProcessId,
    _In_ PP_PROTECTION_STATUS NewStatus
    );

static VOID PpSetStatus(
    _In_ PPP_ENGINE Engine,
    _In_ PP_MODULE_STATUS Status
    );

static NTSTATUS PpOpenNtdll(
    _Inout_ PPP_NTDLL Ntdll
    );

/* ------------------------------------------------------------------ */
/* 私有工具函数                                                       */
/* ------------------------------------------------------------------ */

/* 将宽字符串就地转小写（按 _STANDARD 库 towlower）。 */
static VOID
PpWideLower(
    _Inout_ PWSTR Str
    )
{
    while (*Str != 0) {
        *Str = (WCHAR)towlower(*Str);
        Str++;
    }
}

/* 取进程镜像名（工具帮助快照；返回字符数）。 */
static ULONG
PpGetProcessName(
    _In_ ULONG ProcessId,
    _Out_writes_(MaxLen) PWSTR ImageName,
    _In_ ULONG MaxLen
    )
{
    HANDLE snapshot;
    PROCESSENTRY32W pe;
    ULONG len = 0;

    if (!ImageName || MaxLen == 0) return 0;
    ImageName[0] = 0;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (pe.th32ProcessID == ProcessId) {
                wcsncpy_s(ImageName, MaxLen, pe.szExeFile, _TRUNCATE);
                len = (ULONG)wcslen(ImageName);
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return len;
}

/* 忽略大小写比较进程名是否匹配。 */
static BOOLEAN
PpEqualProcessName(
    _In_ PCWSTR Name,
    _In_ PCWSTR Target
    )
{
    WCHAR nameLower[PP_MAX_DESCRIPTION];
    WCHAR tgtLower[PP_MAX_DESCRIPTION];

    wcsncpy_s(nameLower, PP_MAX_DESCRIPTION, Name, _TRUNCATE);
    wcsncpy_s(tgtLower, PP_MAX_DESCRIPTION, Target, _TRUNCATE);
    PpWideLower(nameLower);
    PpWideLower(tgtLower);

    return _wcsicmp(nameLower, tgtLower) == 0;
}

/* 判定调用方是否本产品组件（自身进程或已知组件镜像名；对齐 SS
 * IsShadowStrikeComponent。SS 额外校验路径+签名，Agent 侧按镜像名判定。） */
static BOOLEAN
PpIsWkdComponent(
    _In_ ULONG ProcessId
    )
{
    WCHAR imageName[PP_MAX_DESCRIPTION];
    ULONG idx;

    if (ProcessId == GetCurrentProcessId()) return TRUE;
    if (PpGetProcessName(ProcessId, imageName, PP_MAX_DESCRIPTION) == 0) return FALSE;
    PpWideLower(imageName);

    for (idx = 0; idx < RTL_NUMBER_OF(PpComponentImages); idx++) {
        if (_wcsicmp(imageName, PpComponentImages[idx]) == 0) return TRUE;
    }
    return FALSE;
}

/* ULONG PID → wkd 对象级内部登记（配置附加受保护进程用，2026-09-06
 * 对象级签名化：AcRegisterProtectedProcessInternal 收 PWKD_PROCESS，
 * 此封装完成查找 + 引用管理；引用约定：成功后由调用方统一 Deref）。 */
static VOID
PpRegisterProtectedPid(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG ProcessId,
    _In_ ULONG Flags
    )
{
    PWKD_PROCESS proc = NULL;

    if (!Engine || ProcessId == 0) return;
    if (!NT_SUCCESS(PsLookupWkdProcessByProcessId(NULL, (HANDLE)(ULONG_PTR)ProcessId, &proc))) {
        return;
    }
    (VOID)AcRegisterProtectedProcessInternal(Engine, proc, Flags);
    PsDereferenceWkdProcess(proc);
}

/* 根据威胁动作返回建议处置（查处置表，缺省回退默认响应；对齐 SS
 * GetResponseForAction：m_threatResponses 查找 + defaultResponse 回退）。 */
static PP_THREAT_RESPONSE
PpGetResponseForAction(
    _In_ PPP_ENGINE Engine,
    _In_ PP_THREAT_ACTION Action
    )
{
    ULONG idx = 0;

    if (Action == PpThreatNone) return Engine->Config.DefaultResponse;

    /* 威胁动作是位域；取最低置位位查找表（对齐 SS 单动作 key 语义） */
    while ((idx < PP_THREAT_RESPONSE_TABLE_SIZE) &&
           ((Action & (PP_THREAT_ACTION)(1u << idx)) == 0)) {
        idx++;
    }
    if (idx >= PP_THREAT_RESPONSE_TABLE_SIZE) return Engine->Config.DefaultResponse;

    return Engine->ThreatResponses[idx];
}

/* 触发阻断访问回调（静态回调 + 注册表回调）。 */
static VOID
PpFireBlockedAccess(
    _In_ PPP_ENGINE Engine,
    _In_ PPP_BLOCKED_ACCESS_EVENT Event
    )
{
    ULONG i;

    EnterCriticalSection(&Engine->CallbackLock);

    if (Engine->Callbacks.OnBlockedAccess) {
        (VOID)Engine->Callbacks.OnBlockedAccess(Event, Engine->Callbacks.Context);
    }
    for (i = 0; i < PP_MAX_CALLBACKS; i++) {
        if (Engine->BlockedCallbacks[i].InUse &&
            Engine->BlockedCallbacks[i].Callback) {
            PP_BLOCKED_ACCESS_CALLBACK cb =
                (PP_BLOCKED_ACCESS_CALLBACK)Engine->BlockedCallbacks[i].Callback;
            (VOID)cb(Event, Engine->BlockedCallbacks[i].Context);
        }
    }

    LeaveCriticalSection(&Engine->CallbackLock);
}

/* 触发威胁分类回调（静态回调 + 注册表回调）。 */
static VOID
PpFireThreat(
    _In_ PPP_ENGINE Engine,
    _In_ PP_THREAT_ACTION Action,
    _In_ PPP_ACCESS_REQUEST Request
    )
{
    ULONG i;

    EnterCriticalSection(&Engine->CallbackLock);

    if (Engine->Callbacks.OnThreat) {
        (VOID)Engine->Callbacks.OnThreat(Action, Request, Engine->Callbacks.Context);
    }
    for (i = 0; i < PP_MAX_CALLBACKS; i++) {
        if (Engine->ThreatCallbacks[i].InUse &&
            Engine->ThreatCallbacks[i].Callback) {
            PP_THREAT_CALLBACK cb =
                (PP_THREAT_CALLBACK)Engine->ThreatCallbacks[i].Callback;
            (VOID)cb(Action, Request, Engine->ThreatCallbacks[i].Context);
        }
    }

    LeaveCriticalSection(&Engine->CallbackLock);
}

/* 通知保护状态变更（注册表回调）。 */
static VOID
PpNotifyProtectionStatus(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG ProcessId,
    _In_ PP_PROTECTION_STATUS NewStatus
    )
{
    ULONG i;

    EnterCriticalSection(&Engine->CallbackLock);

    for (i = 0; i < PP_MAX_CALLBACKS; i++) {
        if (Engine->StatusCallbacks[i].InUse &&
            Engine->StatusCallbacks[i].Callback) {
            PP_PROTECTION_STATUS_CALLBACK cb =
                (PP_PROTECTION_STATUS_CALLBACK)Engine->StatusCallbacks[i].Callback;
            cb(ProcessId, NewStatus, Engine->StatusCallbacks[i].Context);
        }
    }

    LeaveCriticalSection(&Engine->CallbackLock);
}

/* 设置引擎状态（原子）。 */
static VOID
PpSetStatus(
    _In_ PPP_ENGINE Engine,
    _In_ PP_MODULE_STATUS Status
    )
{
    InterlockedExchange(&Engine->Status, (LONG)Status);
}

/* 动态加载 ntdll 函数。 */
static NTSTATUS
PpOpenNtdll(
    _Inout_ PPP_NTDLL Ntdll
    )
{
    ZeroMemory(Ntdll, sizeof(*Ntdll));

    Ntdll->Hmdl = GetModuleHandleW(L"ntdll.dll");
    if (!Ntdll->Hmdl) return STATUS_DLL_NOT_FOUND;

    Ntdll->pNtQueryInformationProcess = (NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG))
        GetProcAddress(Ntdll->Hmdl, "NtQueryInformationProcess");
    Ntdll->pRtlSetProcessIsCritical = (NTSTATUS(NTAPI*)(BOOLEAN, PBOOLEAN, BOOLEAN))
        GetProcAddress(Ntdll->Hmdl, "RtlSetProcessIsCritical");

    if (!Ntdll->pNtQueryInformationProcess) return STATUS_ENTRYPOINT_NOT_FOUND;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* 公共 API                                                           */
/* ------------------------------------------------------------------ */

/**************************************************/
/* 默认配置（Pp 仅保留进程级访问控制；线程防护已  */
/* 统一归位反调试模块，2026-09-06）               */
/**************************************************/

_Use_decl_annotations_
VOID
PpGetDefaultConfiguration(
    _Out_ PPP_CONFIGURATION Config
    )
{
    if (!Config) return;

    ZeroMemory(Config, sizeof(*Config));
    Config->EnablePPL = TRUE;
    Config->EnableHandleFiltering = TRUE;
    Config->EnableAntiTermination = TRUE;
    Config->EnableAntiSuspension = TRUE;
    Config->EnableAntiInjection = TRUE;
    Config->EnableIntegrityVerification = TRUE;
    Config->SetCriticalProcess = FALSE;             /* 默认不自动设关键进程 */
    Config->EnableASLR = TRUE;                      /* 2026-09-08 从 MemoryProtection 迁移 */
    Config->EnableDEP = TRUE;
    Config->EnableCFG = TRUE;
    Config->DefaultResponse = PpResponseActive;     /* 对齐 SS 默认 Active */
    Config->BlockedProcessAccess = PP_DANGEROUS_PROCESS_ACCESS;
    Config->BlockedThreadAccess = PP_DANGEROUS_THREAD_ACCESS;
    Config->VerboseLogging = FALSE;
    Config->SendTelemetry = TRUE;
    Config->WhitelistedCallerCount = 0;
    Config->AdditionalProtectedPidCount = 0;
}

/**************************************************/
/* 生命周期                                     */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
PpInitialize(
    _Out_ PPP_ENGINE* Engine,
    _In_opt_ PPP_CALLBACKS Callbacks
    )
{
    PPP_ENGINE eng;
    ULONG i;
    NTSTATUS status = STATUS_SUCCESS;

    if (!Engine) return STATUS_INVALID_PARAMETER;
    *Engine = NULL;

    eng = (PPP_ENGINE)malloc(sizeof(PP_ENGINE));
    if (!eng) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(eng, sizeof(PP_ENGINE));

    InitializeCriticalSection(&eng->Lock);
    InitializeCriticalSection(&eng->CallbackLock);

    /* 加载 ntdll 函数 */
    if (!NT_SUCCESS(PpOpenNtdll(&eng->Ntdll))) {
        status = STATUS_ENTRYPOINT_NOT_FOUND;
        goto Cleanup;
    }

    /* 默认配置与默认处置表（对齐 SS 构造函数：默认配置 Active、
     * 处置表：ProcessTerminate→Aggressive、ProcessSuspend→Active、
     * ThreadTerminate→Active、ThreadSuspend→Active、MemoryWrite→Aggressive、
     * ThreadCreate→Active、APCQueue→Aggressive、HandleDuplicate→Passive、
     * DebugAttach→Aggressive；未列入者回退默认） */
    PpGetDefaultConfiguration(&eng->Config);
    eng->ThreatResponses[0] = PpResponseAggressive;  /* ProcessTerminate */
    eng->ThreatResponses[1] = PpResponseActive;      /* ProcessSuspend */
    eng->ThreatResponses[2] = PpResponseActive;      /* ThreadTerminate */
    eng->ThreatResponses[3] = PpResponseActive;      /* ThreadSuspend */
    eng->ThreatResponses[4] = PpResponseAggressive;  /* MemoryWrite */
    eng->ThreatResponses[5] = PpResponseActive;      /* MemoryAlloc */
    eng->ThreatResponses[6] = PpResponseActive;      /* ThreadCreate */
    eng->ThreatResponses[7] = PpResponseAggressive;  /* APCQueue */
    eng->ThreatResponses[8] = PpResponsePassive;     /* HandleDuplicate */

    /* 回调 */
    if (Callbacks) {
        eng->Callbacks = *Callbacks;
    }

    /* 2026-09-06 域化：无进程镜像数组、无线程台账（保护状态落
     * WKD_PROCESS::AccessControlContext；线程防调试归位 AntiDebug） */
    for (i = 0; i < PP_MAX_WHITELIST; i++) {
        eng->Whitelist[i].InUse = FALSE;
    }

    eng->NextCallbackId = 1;
    eng->NextEventId = 1;

    GetSystemTimeAsFileTime((LPFILETIME)&eng->Stats.StartTime);

    PpSetStatus(eng, PpModuleInitializing);
    InterlockedExchange(&eng->Initialized, TRUE);
    g_ProcessProtectionEngine = eng;

    /* 附加保护 PID（对齐 SS Initialize 中 additionalProtectedPids；对象级登记） */
    for (i = 0; i < eng->Config.AdditionalProtectedPidCount; i++) {
        PpRegisterProtectedPid(eng, eng->Config.AdditionalProtectedPids[i],
                               PP_PROTECT_FLAG_PREVENT_TERMINATION);
    }

    PpSetStatus(eng, PpModuleRunning);
    *Engine = eng;
    return STATUS_SUCCESS;

Cleanup:
    /* 回滚：释放已初始化资源后返回失败状态 */
    DeleteCriticalSection(&eng->Lock);
    DeleteCriticalSection(&eng->CallbackLock);
    free(eng);
    return status;
}

_Use_decl_annotations_
VOID
PpCleanup(
    _In_opt_ _Post_invalid_ PPP_ENGINE Engine
    )
{
    if (!Engine) return;

    if (g_ProcessProtectionEngine == Engine) {
        g_ProcessProtectionEngine = NULL;
    }
    InterlockedExchange(&Engine->Initialized, FALSE);
    PpSetStatus(Engine, PpModuleStopped);

    DeleteCriticalSection(&Engine->Lock);
    DeleteCriticalSection(&Engine->CallbackLock);
    free(Engine);
}

_Use_decl_annotations_
BOOLEAN
PpIsInitialized(
    _In_ PPP_ENGINE Engine
    )
{
    if (!Engine) return FALSE;
    return InterlockedCompareExchange(&Engine->Initialized, 0, 0) != 0;
}

_Use_decl_annotations_
PP_MODULE_STATUS
PpGetStatus(
    _In_ PPP_ENGINE Engine
    )
{
    if (!Engine) return PpModuleUninitialized;
    return (PP_MODULE_STATUS)InterlockedCompareExchange(&Engine->Status, 0, 0);
}

/**************************************************/
/* 配置（对齐 SS SetConfiguration 系列）           */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
PpSetConfiguration(
    _In_ PPP_ENGINE Engine,
    _In_ PPP_CONFIGURATION Config
    )
{
    ULONG i;
    PP_CONFIGURATION sanitized;

    if (!Engine || !Config) return STATUS_INVALID_PARAMETER;

    /* 白名单/附加 PID 越界截断（对齐 SS 内部校验） */
    sanitized = *Config;
    if (sanitized.WhitelistedCallerCount > PP_MAX_CONFIG_WHITELIST) {
        sanitized.WhitelistedCallerCount = PP_MAX_CONFIG_WHITELIST;
    }
    if (sanitized.AdditionalProtectedPidCount > PP_MAX_CONFIG_PIDS) {
        sanitized.AdditionalProtectedPidCount = PP_MAX_CONFIG_PIDS;
    }

    EnterCriticalSection(&Engine->Lock);
    Engine->Config = sanitized;
    LeaveCriticalSection(&Engine->Lock);

    /* 配置内附加保护 PID 自动纳入保护（对齐 SS Initialize 后配置生效；对象级登记） */
    for (i = 0; i < sanitized.AdditionalProtectedPidCount; i++) {
        PpRegisterProtectedPid(Engine, sanitized.AdditionalProtectedPids[i],
                               PP_PROTECT_FLAG_PREVENT_TERMINATION);
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PpGetConfiguration(
    _In_ PPP_ENGINE Engine,
    _Out_ PPP_CONFIGURATION Config
    )
{
    if (!Engine || !Config) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&Engine->Lock);
    *Config = Engine->Config;
    LeaveCriticalSection(&Engine->Lock);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PpSetDefaultResponse(
    _In_ PPP_ENGINE Engine,
    _In_ PP_THREAT_RESPONSE Response
    )
{
    if (!Engine) return;
    EnterCriticalSection(&Engine->Lock);
    Engine->Config.DefaultResponse = Response;
    LeaveCriticalSection(&Engine->Lock);
}

_Use_decl_annotations_
VOID
PpSetThreatResponse(
    _In_ PPP_ENGINE Engine,
    _In_ PP_THREAT_ACTION Action,
    _In_ PP_THREAT_RESPONSE Response
    )
{
    ULONG idx;

    if (!Engine || Action == PpThreatNone) return;

    /* 最低置位位对应处置表槽（对齐 SS m_threatResponses[action]） */
    for (idx = 0; idx < PP_THREAT_RESPONSE_TABLE_SIZE; idx++) {
        if ((Action & (PP_THREAT_ACTION)(1u << idx)) != 0) {
            EnterCriticalSection(&Engine->Lock);
            Engine->ThreatResponses[idx] = Response;
            LeaveCriticalSection(&Engine->Lock);
            return;
        }
    }
}

/**************************************************/
/* PPL（Agent 侧表达 + 占位；驱动桥接后生效）      */
/**************************************************/

/* 尝试提升当前进程到 PPL。Agent 侧实现：若本进程已有 PPL 保护级别则
 * 记忆成功；否则向驱动请求（占位），失败返回 FALSE。 */
_Use_decl_annotations_
BOOLEAN
PpElevateToPPL(
    _In_ PPP_ENGINE Engine
    )
{
    PP_PROTECTION_LEVEL self;

    if (!Engine) return FALSE;

    if (InterlockedCompareExchange(&Engine->IsPPL, 0, 0) != 0) return TRUE;

    /* 查询自身保护级别，若已 PPL 直接确认 */
    self = PpGetProtectionLevel(Engine, GetCurrentProcessId());
    if (self.Type != PpProtectionTypeNone) {
        InterlockedExchange(&Engine->IsPPL, TRUE);
        InterlockedIncrement64(&Engine->Stats.TotalElevations);
        return TRUE;
    }

    /* 请求内核提升（占位：未接驱动 → 返回未实现） */
    if (!NT_SUCCESS(PpRequestKernelPplElevation(Engine))) return FALSE;

    InterlockedExchange(&Engine->IsPPL, TRUE);
    return TRUE;
}

_Use_decl_annotations_
BOOLEAN
PpIsPPLProtected(
    _In_ PPP_ENGINE Engine
    )
{
    PP_PROTECTION_LEVEL self;

    if (!Engine) return FALSE;
    self = PpGetProtectionLevel(Engine, GetCurrentProcessId());
    return PP_LEVEL_IS_PPL(self);
}

_Use_decl_annotations_
ULONG
PpGetProtectionLevelRaw(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG ProcessId
    )
{
    PP_PROTECTION_LEVEL level;

    if (!Engine) return 0;
    level = PpGetProtectionLevel(Engine, ProcessId);
    return level.RawLevel;
}

_Use_decl_annotations_
BOOLEAN
PpHasRequiredProtectionLevel(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG ProcessId,
    _In_ PP_PROTECTION_LEVEL Required
    )
{
    PP_PROTECTION_LEVEL current;

    if (!Engine) return FALSE;
    current = PpGetProtectionLevel(Engine, ProcessId);
    return PP_LEVEL_GE(current, Required);
}

/**************************************************/
/* 进程保护                                        */
/**************************************************/

/* 确保受保护进程访问控制上下文存在（惰性构建, 2026-09-06 受保护进程域化）。
 * 进程创建路径（SdfEnsureAccessControlContextObject/Orchestrator）预建后此处直接命中；
 * 注册受保护进程路径在此兜底。二次原子写防竞态，对齐 ThreadContext 惰性模式。
 * Ctx 可选输出：构建/已存在时回填访问控制上下文指针（仍归进程对象所有）。
 * 公开（ProcessProtection.h）：由 Sdf* 编排门面调用。 */
_Use_decl_annotations_
NTSTATUS
AcAllocateProcessAccessControlContextLazy(
    _Inout_ PWKD_PROCESS WkdProcess,
    _Out_opt_ PWKD_ACCESS_CONTROL_CONTEXT* Context
    )
{
    PWKD_ACCESS_CONTROL_CONTEXT ctx;

    if (!WkdProcess) return STATUS_INVALID_PARAMETER;
    if (Context) *Context = NULL;

    if (InterlockedCompareExchangePointer(&WkdProcess->AccessControlContext, NULL, NULL)) {
        if (Context) *Context = WkdProcess->AccessControlContext;
        return STATUS_SUCCESS;
    }

    ctx = (PWKD_ACCESS_CONTROL_CONTEXT)malloc(sizeof(WKD_ACCESS_CONTROL_CONTEXT));
    if (!ctx) return STATUS_NO_MEMORY;
    RtlZeroMemory(ctx, sizeof(WKD_ACCESS_CONTROL_CONTEXT));

    if (InterlockedCompareExchangePointer(
        &WkdProcess->AccessControlContext, ctx, NULL) != NULL) {
        free(ctx);              /* 并发创建者落选，释放本地副本 */
        ctx = WkdProcess->AccessControlContext;
    }

    if (Context) *Context = ctx;
    return STATUS_SUCCESS;
}

/* 打开目标进程缓解查询句柄：自身返回 GetCurrentProcess()（伪句柄无需关闭），
 * 第三方返回 OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)（调用方负责关闭）。 */
static HANDLE
PpOpenProcessForMitigationQuery(
    _In_ ULONG ProcessId
    )
{
    if (HandleToULong(ProcessId) == GetCurrentProcessId()) {
        return GetCurrentProcess();
    }
    return OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
}

/* 跨进程查询单一缓解策略并返回"是否已就位"。 */
static BOOLEAN
PpGetMitigationBit(
    _In_ HANDLE hProcess,
    _In_ ULONG Flag
    )
{
    PROCESS_MITIGATION_ASLR_POLICY aslrPolicy;
    PROCESS_MITIGATION_DEP_POLICY depPolicy;
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy;
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handlePolicy;
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dcPolicy;
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signaturePolicy;
    BOOLEAN on = FALSE;

    ZeroMemory(&aslrPolicy, sizeof(aslrPolicy));
    ZeroMemory(&depPolicy, sizeof(depPolicy));
    ZeroMemory(&cfgPolicy, sizeof(cfgPolicy));
    ZeroMemory(&handlePolicy, sizeof(handlePolicy));
    ZeroMemory(&dcPolicy, sizeof(dcPolicy));
    ZeroMemory(&signaturePolicy, sizeof(signaturePolicy));

    switch (Flag) {
    case PP_HARDENING_ASLR:
        if (GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy,
                &aslrPolicy, sizeof(aslrPolicy))) {
            on = (aslrPolicy.EnableBottomUpRandomization ||
                  aslrPolicy.EnableHighEntropy) != 0;
        }
        break;

    case PP_HARDENING_DEP:
        if (GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy,
                &depPolicy, sizeof(depPolicy))) {
            on = (depPolicy.Enable != 0 || depPolicy.Permanent != 0);
        }
        break;

    case PP_HARDENING_CFG:
        if (GetProcessMitigationPolicy(hProcess, ProcessControlFlowGuardPolicy,
                &cfgPolicy, sizeof(cfgPolicy))) {
            on = (cfgPolicy.EnableControlFlowGuard != 0);
        }
        break;

    case PP_HARDENING_STRICT_HANDLE:
        if (GetProcessMitigationPolicy(hProcess, ProcessStrictHandleCheckPolicy,
                &handlePolicy, sizeof(handlePolicy))) {
            on = (handlePolicy.RaiseExceptionOnInvalidHandleReference != 0);
        }
        break;

    case PP_HARDENING_DYNAMIC_CODE:
        if (GetProcessMitigationPolicy(hProcess, ProcessDynamicCodePolicy,
                &dcPolicy, sizeof(dcPolicy))) {
            /* 对齐 SS：动态代码显式不禁用（ProhibitDynamicCode=0，兼容托管代码） */
            on = (dcPolicy.ProhibitDynamicCode == 0);
        }
        break;

    case PP_HARDENING_SIGNATURE:
        if (GetProcessMitigationPolicy(hProcess, ProcessSignaturePolicy,
                &signaturePolicy, sizeof(signaturePolicy))) {
            on = (signaturePolicy.MicrosoftSignedOnly != 0 ||
                  signaturePolicy.StoreSignedOnly != 0);
        }
        break;

    default:
        break;
    }
    return on;
}

/* 对受保护进程应用缓解加固（登记流水线 AcRegisterProtectedProcessInternal 调用；
 * 配置 EnableASLR/EnableDEP/EnableCFG 任一开启时执行）。
 * 自身：DEP/动态代码/严格句柄 Set 施加 + 全项 Get 复证；
 * 第三方：六项全 Get 观测，配置期望项缺失 → HardeningMismatchCount + 日志告警。
 * 结果写 ctx->HardeningMask（PP_HARDENING_* 位域）。 */
_Use_decl_annotations_
VOID
AcApplyProcessHardening(
    _In_ PPP_ENGINE Engine,
    _In_ PWKD_PROCESS WkdProcess
    )
{
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dcPolicy;
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handlePolicy;
    PWKD_ACCESS_CONTROL_CONTEXT ctx;
    HANDLE hProcess = NULL;
    BOOLEAN remote;
    ULONG mask = 0;
    ULONG wanted = 0;
    WCHAR desc[PP_MAX_DESCRIPTION];

    if (!Engine || !WkdProcess) return;
    ctx = WkdProcess->AccessControlContext;
    if (!ctx) return;
    
    remote = (HandleToULong(WkdProcess->ProcessId) == GetCurrentProcessId());
    if (remote) {
        /* 自身：DEP 施加（若配置开启） */
        if (Engine->Config.EnableDEP) {
            AcpEnableDEP(Engine, WkdProcess);
        }

        /* 缓解策略（对齐 SS applyMitigationPolicies）：
         * - 动态代码：显式置 0（不禁用，兼容托管代码）
         * - 严格句柄检查：永久启用 */
        ZeroMemory(&dcPolicy, sizeof(dcPolicy));
        dcPolicy.ProhibitDynamicCode = 0;
        if (SetProcessMitigationPolicy(ProcessDynamicCodePolicy,
                &dcPolicy, sizeof(dcPolicy))) {
            mask |= PP_HARDENING_DYNAMIC_CODE;
        }

        ZeroMemory(&handlePolicy, sizeof(handlePolicy));
        handlePolicy.RaiseExceptionOnInvalidHandleReference = 1;
        handlePolicy.HandleExceptionsPermanentlyEnabled = 1;
        if (SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy,
                &handlePolicy, sizeof(handlePolicy))) {
            mask |= PP_HARDENING_STRICT_HANDLE;
        }

        hProcess = GetCurrentProcess();
    } else {
        /* 第三方：只读观测 */
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, WkdProcess->ProcessId);
        if (!hProcess) {
            /* 无法观测（权限/已退出）：登记空事实，不告警 */
            ctx->HardeningMask = 0;
            return;
        }
    }

    /* 全项观测（自身=Set 后 Get 复证；第三方=纯 Get） */
    if (PpGetMitigationBit(hProcess, PP_HARDENING_ASLR))          mask |= PP_HARDENING_ASLR;
    if (PpGetMitigationBit(hProcess, PP_HARDENING_DEP))           mask |= PP_HARDENING_DEP;
    if (PpGetMitigationBit(hProcess, PP_HARDENING_CFG))           mask |= PP_HARDENING_CFG;
    if (PpGetMitigationBit(hProcess, PP_HARDENING_STRICT_HANDLE)) mask |= PP_HARDENING_STRICT_HANDLE;
    if (PpGetMitigationBit(hProcess, PP_HARDENING_DYNAMIC_CODE))  mask |= PP_HARDENING_DYNAMIC_CODE;
    if (PpGetMitigationBit(hProcess, PP_HARDENING_SIGNATURE))     mask |= PP_HARDENING_SIGNATURE;

    if (!remote) CloseHandle(hProcess);

    /* 第三方校验：配置期望项缺失 → 记录 + 告警（自身 Set 结果由复证体现，不双重告警） */
    if (!remote) {
        if (Engine->Config.EnableASLR) wanted |= PP_HARDENING_ASLR;
        if (Engine->Config.EnableDEP)  wanted |= PP_HARDENING_DEP;
        if (Engine->Config.EnableCFG)  wanted |= PP_HARDENING_CFG;
        if (wanted != 0 && (mask & wanted) != wanted) {
            InterlockedIncrement64(&Engine->Stats.HardeningMismatchCount);
            InterlockedIncrement64(&Engine->Stats.AlertsRaised);
        }
    }

    ctx->HardeningMask = mask;
}

/* 校验并登记目标进程 ASLR 状态（Get 观测；ASLR 不可运行期设置）。 */
_Use_decl_annotations_
BOOLEAN
PpEnableASLR(
    _In_ PPP_ENGINE Engine,
    _In_ PWKD_PROCESS WkdProcess
    )
{
    HANDLE hProcess;
    BOOLEAN on;
    ULONG pid;

    if (!Engine || !WkdProcess) return FALSE;
    if (!WkdProcess->AccessControlContext) return FALSE;

    pid = (ULONG)(ULONG_PTR)WkdProcess->ProcessId;
    hProcess = PpOpenProcessForMitigationQuery(pid);
    if (!hProcess) return FALSE;

    on = PpGetMitigationBit(hProcess, PP_HARDENING_ASLR);
    if (HandleToULong(WkdProcess->ProcessId) != GetCurrentProcessId()) CloseHandle(hProcess);

    if (on) {
        WkdProcess->AccessControlContext->HardeningMask |= PP_HARDENING_ASLR;
    } else {
        WkdProcess->AccessControlContext->HardeningMask &= ~PP_HARDENING_ASLR;
    }
    return on;
}

/* 查询目标进程 ASLR 加固位（读 ctx->HardeningMask）。 */
_Use_decl_annotations_
BOOLEAN
PpIsASLREnabled(
    _In_ PWKD_PROCESS WkdProcess
    )
{
    if (!WkdProcess || !WkdProcess->AccessControlContext) return FALSE;
    return (WkdProcess->AccessControlContext->HardeningMask & PP_HARDENING_ASLR) != 0;
}

/* 登记目标进程 DEP 状态：自身=SetProcessDEPPolicy 施加（含 AlwaysOn 降级复证）；
 * 第三方=Get 观测。 */
_Use_decl_annotations_
BOOLEAN
AcpEnableDEP(
    _In_ PPP_ENGINE Engine,
    _In_ PWKD_PROCESS WkdProcess
    )
{
    HANDLE hProcess;
    BOOLEAN on;
    ULONG pid;
    DWORD flags;

    if (!Engine || !WkdProcess) return FALSE;
    if (!WkdProcess->AccessControlContext) return FALSE;

    pid = (ULONG)(ULONG_PTR)WkdProcess->ProcessId;

    if (HandleToULong(WkdProcess->ProcessId) == GetCurrentProcessId()) {
        hProcess = GetCurrentProcess();
        if (Engine->Config.EnableDEP) {
            /* 永久 DEP + 禁 ATL thunk 仿真（仅进程初始化阶段可生效） */
            flags = PROCESS_DEP_ENABLE | PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION;
            on = SetProcessDEPPolicy(flags) != FALSE;
            if (!on) {
                /* Win8+ DEP 由引导/组策略强制（AlwaysOn）时 Set 失败但实际已受保护：
                 * 查询复证（迁移自 MpEnableDEP 语义） */
                on = PpGetMitigationBit(hProcess, PP_HARDENING_DEP);
            }
        } else {
            on = PpGetMitigationBit(hProcess, PP_HARDENING_DEP);
        }
    } else {
        hProcess = PpOpenProcessForMitigationQuery(pid);
        if (!hProcess) return FALSE;
        on = PpGetMitigationBit(hProcess, PP_HARDENING_DEP);
        CloseHandle(hProcess);
    }

    if (on) {
        WkdProcess->AccessControlContext->HardeningMask |= PP_HARDENING_DEP;
    } else {
        WkdProcess->AccessControlContext->HardeningMask &= ~PP_HARDENING_DEP;
    }
    return on;
}

/* 查询目标进程 DEP 加固位（读 ctx->HardeningMask）。 */
_Use_decl_annotations_
BOOLEAN
PpIsDEPEnabled(
    _In_ PWKD_PROCESS WkdProcess
    )
{
    if (!WkdProcess || !WkdProcess->AccessControlContext) return FALSE;
    return (WkdProcess->AccessControlContext->HardeningMask & PP_HARDENING_DEP) != 0;
}

/* 校验并登记目标进程 CFG 状态（Get 观测；编译期 /guard:cf 决定，不可运行期设置）。 */
_Use_decl_annotations_
BOOLEAN
PpEnableCFG(
    _In_ PPP_ENGINE Engine,
    _In_ PWKD_PROCESS WkdProcess
    )
{
    HANDLE hProcess;
    BOOLEAN on;
    ULONG pid;

    if (!Engine || !WkdProcess) return FALSE;
    if (!WkdProcess->AccessControlContext) return FALSE;

    pid = (ULONG)(ULONG_PTR)WkdProcess->ProcessId;
    hProcess = PpOpenProcessForMitigationQuery(pid);
    if (!hProcess) return FALSE;

    on = PpGetMitigationBit(hProcess, PP_HARDENING_CFG);
    if (HandleToULong(WkdProcess->ProcessId) != GetCurrentProcessId()) CloseHandle(hProcess);

    if (on) {
        WkdProcess->AccessControlContext->HardeningMask |= PP_HARDENING_CFG;
    } else {
        WkdProcess->AccessControlContext->HardeningMask &= ~PP_HARDENING_CFG;
    }
    return on;
}

/* 查询目标进程 CFG 加固位（读 ctx->HardeningMask）。 */
_Use_decl_annotations_
BOOLEAN
PpIsCFGEnabled(
    _In_ PWKD_PROCESS WkdProcess
    )
{
    if (!WkdProcess || !WkdProcess->AccessControlContext) return FALSE;
    return (WkdProcess->AccessControlContext->HardeningMask & PP_HARDENING_CFG) != 0;
}

/* ULONG 序列化值还原 PP_PROTECTION_LEVEL（RawLevel 含 Type/Signer 位域）。 */
static PP_PROTECTION_LEVEL
PpUnpackProtectionLevel(
    _In_ ULONG Serialized
    )
{
    PP_PROTECTION_LEVEL level;

    ZeroMemory(&level, sizeof(level));
    level.RawLevel = (UCHAR)Serialized;
    level.Type = (PP_PROTECTION_TYPE)((level.RawLevel & PP_PS_PROTECTED_TYPE_MASK) >>
                                      PP_PS_PROTECTED_TYPE_SHIFT);
    level.Signer = (PP_PROTECTION_SIGNER)((level.RawLevel & PP_PS_PROTECTED_SIGNER_MASK) >>
                                          PP_PS_PROTECTED_SIGNER_SHIFT);
    return level;
}

/* wkd 字符串载体拷贝到定长 WCHAR 缓冲（NULL 载体 → 返回 0 且清空缓冲）。 */
static ULONG
PpCopyWkdStringToWchar(
    _In_opt_ PUNICODE_STRING Src,
    _Out_writes_(MaxLen) PWSTR Dst,
    _In_ ULONG MaxLen
    )
{
    if (!Dst || MaxLen == 0) return 0;
    Dst[0] = 0;
    if (!Src || !Src->Buffer) return 0;
    wcsncpy_s(Dst, MaxLen, Src->Buffer, _TRUNCATE);
    return (ULONG)wcslen(Dst);
}

_Use_decl_annotations_
NTSTATUS
AcRegisterProtectedProcessInternal(
    _Inout_opt_ PPP_ENGINE Engine,
    _Inout_ PWKD_PROCESS WkdProcess,
    _In_ ULONG ProtectionFlags
    )
{
    NTSTATUS status;
    PWKD_ACCESS_CONTROL_CONTEXT ctx = NULL;

    // if (!Engine) Engine = xxx;
    if (!Engine || !WkdProcess) return STATUS_INVALID_PARAMETER;
    if (WkdProcess->IsProtectedProcess) return STATUS_ALREADY_REGISTERED;

    /* 惰性构建访问控制上下文（注册受保护进程路径；双参签名取回 ctx） */
    status = AcAllocateProcessAccessControlContextLazy(WkdProcess, &ctx);
    if (!NT_SUCCESS(status) || !ctx) return STATUS_UNSUCCESSFUL;

    /* 登记（锁内更新统计；AccessControlContext 字段为单写者同步路径，直接赋值） */
    GetSystemTimeAsFileTime((LPFILETIME)&ctx->ProtectedSince);
    ctx->LastVerified = ctx->ProtectedSince;
    ctx->ProtectionLevel = PpGetProtectionLevel(Engine, WkdProcess->ProcessId).RawLevel;
    ctx->ProtectionStatus = PpProtectionUserModeOnly;
    if (PpUnpackProtectionLevel(ctx->ProtectionLevel).Type != PpProtectionTypeNone) {
        ctx->ProtectionStatus = PpProtectionPplProtected;
    }
    WkdProcess->IsProtectedProcess = TRUE;

    /* 完整性校验开启时记录当前校验时间（对齐 SS） */
    if (Engine->Config.EnableIntegrityVerification) {
        GetSystemTimeAsFileTime((LPFILETIME)&ctx->LastVerified);
    }

    InterlockedIncrement(&Engine->Stats.ActiveProtected);
    InterlockedIncrement(&Engine->Stats.TotalProtected);

    /* 登记前按配置附加保护：安全描述符（句柄过滤） */
    if (Engine->Config.EnableHandleFiltering) {
        PpApplyRestrictiveSecurityDescriptor(Engine, WkdProcess->ProcessId);
    }

    /* 关键进程标志（对齐 SS ProtectProcess 中 setCritical 分支） */
    if (Engine->Config.SetCriticalProcess) {
        if (NT_SUCCESS(PpSetCriticalProcess(Engine, WkdProcess->ProcessId, TRUE))) {
            ctx->IsCritical = TRUE;
        }
    }

    /* 进程缓解加固（2026-09-08 从 MemoryProtection 迁移）：登记期施加/校验，
     * 结果写 ctx->HardeningMask：自身=Set 施加，第三方=Get 校验+不符告警。 */
    if (Engine->Config.EnableASLR || Engine->Config.EnableDEP || Engine->Config.EnableCFG) {
        AcApplyProcessHardening(Engine, WkdProcess);
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PpUnprotectProcess(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG ProcessId
    )
{
    PWKD_PROCESS proc = NULL;
    PWKD_ACCESS_CONTROL_CONTEXT ctx = NULL;
    NTSTATUS status;

    if (!Engine || ProcessId == 0) return STATUS_INVALID_PARAMETER;

    /* 定位进程域对象（受保护进程域化：权威状态落 WKD_PROCESS::AccessControlContext） */
    status = PsLookupWkdProcessByProcessId(NULL, (HANDLE)(ULONG_PTR)ProcessId, &proc);
    if (!NT_SUCCESS(status)) return STATUS_NOT_FOUND;

    ctx = proc->AccessControlContext;
    if (!ctx || !proc->IsProtectedProcess) {
        PsDereferenceWkdProcess(proc);
        return STATUS_NOT_FOUND;
    }

    /* 清访问控制上下文（链摘除由调用方 Sdf 层负责——RtlZeroMemory 会清零链
     * 节点，须在摘链之后执行） */
    RtlZeroMemory(ctx, sizeof(*ctx));
    proc->IsProtectedProcess = FALSE;

    EnterCriticalSection(&Engine->Lock);
    if (Engine->Stats.ActiveProtected > 0) {
        Engine->Stats.ActiveProtected--;
    }
    LeaveCriticalSection(&Engine->Lock);

    PsDereferenceWkdProcess(proc);

    PpNotifyProtectionStatus(Engine, ProcessId, PpProtectionUnprotected);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
PpIsProcessProtected(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG ProcessId
    )
{
    PWKD_PROCESS proc = NULL;
    BOOLEAN found = FALSE;

    if (!Engine || ProcessId == 0) return FALSE;
    if (!NT_SUCCESS(PsLookupWkdProcessByProcessId(NULL, (HANDLE)(ULONG_PTR)ProcessId, &proc))) {
        return FALSE;
    }
    found = proc->IsProtectedProcess;
    PsDereferenceWkdProcess(proc);
    return found;
}

_Use_decl_annotations_
NTSTATUS
PpGetProtectedProcessInfo(
    _In_  PPP_ENGINE Engine,
    _In_  ULONG ProcessId,
    _Out_ PPP_PROTECTED_PROCESS_INFO Info
    )
{
    PWKD_PROCESS proc = NULL;
    NTSTATUS status;

    if (!Engine || ProcessId == 0 || !Info) return STATUS_INVALID_PARAMETER;
    ZeroMemory(Info, sizeof(*Info));

    if (!NT_SUCCESS(PsLookupWkdProcessByProcessId(NULL, (HANDLE)(ULONG_PTR)ProcessId, &proc))) {
        return STATUS_NOT_FOUND;
    }
    status = PpBuildProtectedProcessInfo(proc, ProcessId, Info);
    PsDereferenceWkdProcess(proc);
    return status;
}

/* 由 wkd 进程对象 + 访问控制上下文组装公开信息（2026-09-06 域化）。 */
static NTSTATUS
PpBuildProtectedProcessInfo(
    _In_ PWKD_PROCESS Proc,
    _In_ ULONG ProcessId,
    _Out_ PPP_PROTECTED_PROCESS_INFO Info
    )
{
    PWKD_ACCESS_CONTROL_CONTEXT ctx;
    PP_PROTECTION_LEVEL level;

    if (!Proc || !Info) return STATUS_INVALID_PARAMETER;
    ctx = Proc->AccessControlContext;
    if (!ctx || !Proc->IsProtectedProcess) return STATUS_NOT_FOUND;

    ZeroMemory(Info, sizeof(*Info));
    Info->ProcessId = ProcessId;
    (VOID)PpCopyWkdStringToWchar(Proc->ImageFileName, Info->ImageName, PP_MAX_DESCRIPTION);
    (VOID)PpCopyWkdStringToWchar(Proc->ImagePath, Info->ImagePath, PP_MAX_DESCRIPTION);
    level = PpUnpackProtectionLevel(ctx->ProtectionLevel);
    Info->ProtectionLevel = level;
    Info->Status = (PP_PROTECTION_STATUS)ctx->ProtectionStatus;
    Info->IsWkdComponent = PpIsWkdComponent(ProcessId) ? TRUE : FALSE;
    Info->IsCritical = ctx->IsCritical;
    Info->ProtectedSince = ctx->ProtectedSince;
    Info->LastVerified = ctx->LastVerified;
    Info->BlockedAttempts = ctx->BlockedAttempts;
    Info->LastBlockedAttempt = ctx->LastBlockedAttempt;
    Info->SessionId = Proc->SessionId;
    Info->IntegrityLevel = Proc->IntegrityLevel;
    Info->HandleCount = 0;                  /* 不再持有进程句柄 */
    Info->ThreadCount = 0;                  /* 线程台账与 wkd ThreadContext 同源，略 */
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PpGetAllProtectedProcesses(
    _In_      PPP_ENGINE Engine,
    _Out_writes_opt_(*Count) PPP_PROTECTED_PROCESS_INFO Buffer,
    _Inout_   PULONG Count
    )
{
    ULONG total = 0;
    ULONG obtained = 0;
    ULONG put = 0;
    ULONG i;
    NTSTATUS status = STATUS_SUCCESS;

    if (!Engine || !Count) return STATUS_INVALID_PARAMETER;

    /* 经编排层受保护进程链枚举（2026-09-06：PP_ENGINE 未来取消，链归
     * ACCESS_CONTROL_ENGINE;PpGetAllProtectedProcesses 走 AcGetAccessControlEngine）。 */
    if (AcGetAccessControlEngine() == NULL) return STATUS_NOT_IMPLEMENTED;

    /* 计数模式 */
    if (!Buffer) {
        status = AcEnumerateProtectedProcessPtrs(NULL, 0, &total);
        *Count = total;
        return status;
    }

    /* 先计数再分配 */
    (VOID)AcEnumerateProtectedProcessPtrs(NULL, 0, &total);
    if (total == 0) {
        *Count = 0;
        return STATUS_SUCCESS;
    }
    if (*Count < total) {
        *Count = total;
        return STATUS_BUFFER_TOO_SMALL;
    }

    obtained = total;
    {
        PWKD_PROCESS* ptrs = (PWKD_PROCESS*)malloc(total * sizeof(PWKD_PROCESS));
        if (!ptrs) return STATUS_INSUFFICIENT_RESOURCES;

        (VOID)AcEnumerateProtectedProcessPtrs(ptrs, total, &obtained);
        for (i = 0; i < obtained; i++) {
            NTSTATUS s = PpBuildProtectedProcessInfo(ptrs[i],
                        (ULONG)(ULONG_PTR)ptrs[i]->ProcessId, &Buffer[put]);
            if (NT_SUCCESS(s)) {
                put++;
            }
            PsDereferenceWkdProcess(ptrs[i]);
        }
        free(ptrs);
    }

    *Count = put;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PpSetCriticalProcess(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG ProcessId,
    _In_ BOOLEAN Critical
    )
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    BOOLEAN prevCritical = FALSE;
    PWKD_PROCESS proc = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (!Engine || ProcessId == 0) return STATUS_INVALID_PARAMETER;

    /* 对齐 SS：仅当前进程可设置关键进程（RtlSetProcessIsCritical 语义） */
    if (ProcessId != GetCurrentProcessId()) return STATUS_ACCESS_DENIED;
    if (!Engine->Ntdll.pRtlSetProcessIsCritical) return STATUS_ENTRYPOINT_NOT_FOUND;

    /* 尝试启用 SeDebugPrivilege（对齐 SS：需要调试权限做恢复） */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            (VOID)AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        }
        CloseHandle(hToken);
    }

    status = Engine->Ntdll.pRtlSetProcessIsCritical(Critical, &prevCritical, FALSE);
    if (!NT_SUCCESS(status)) return status;

    /* 同步受保护进程访问控制上下文关键标志（wkd 域，2026-09-06） */
    if (NT_SUCCESS(PsLookupWkdProcessByProcessId(NULL, (HANDLE)(ULONG_PTR)ProcessId, &proc))) {
        if (proc->AccessControlContext) {
            proc->AccessControlContext->IsCritical = Critical ? TRUE : FALSE;
        }
        PsDereferenceWkdProcess(proc);
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN
PpIsCriticalProcess(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG ProcessId
    )
{
    PWKD_PROCESS proc = NULL;
    BOOLEAN isCritical = FALSE;

    if (!Engine) return FALSE;
    if (!NT_SUCCESS(PsLookupWkdProcessByProcessId(NULL, (HANDLE)(ULONG_PTR)ProcessId, &proc))) {
        return FALSE;
    }
    if (proc->AccessControlContext) {
        isCritical = proc->AccessControlContext->IsCritical;
    }
    PsDereferenceWkdProcess(proc);
    return isCritical;
}

/**************************************************/
/* 访问控制（核心判定链，对齐 SS FilterAccessRequest）*/
/**************************************************/

_Use_decl_annotations_
BOOLEAN
PpIsAccessAllowed(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG CallerProcessId,
    _In_ ULONG TargetProcessId,
    _In_ ULONG DesiredAccess
    )
{
    PP_ACCESS_REQUEST request;
    PP_ACCESS_DECISION_RESULT result;
    NTSTATUS status;

    if (!Engine) return FALSE;

    ZeroMemory(&request, sizeof(request));
    ZeroMemory(&result, sizeof(result));
    request.Type = PpAccessProcessOpen;
    request.CallerProcessId = CallerProcessId;
    request.CallerThreadId = (ULONG)GetCurrentThreadId();
    request.TargetProcessId = TargetProcessId;
    request.DesiredAccess = DesiredAccess;

    status = PpFilterAccessRequest(Engine, &request, &result);
    if (!NT_SUCCESS(status)) return FALSE;
    return (result.Decision == PpAccessDecisionAllow ||
            result.Decision == PpAccessDecisionAllowReduced);
}

/* 核心判定链（对齐 SS FilterAccessRequest 顺序）：
 *  1) 自访问 → Allow
 *  2) 目标未受保护 → Allow
 *  3) 调用方白名单 → Allow
 *  4) 本产品组件 → Allow
 *  5) SYSTEM 调用方且请求非威胁 → Allow
 *  6) 调用方保护级别 ≥ 目标保护级别且调用方 PPL → Allow
 *  7) 威胁分类
 *  8) 威胁处置：Block → Deny；否则 → AllowReduced（裁剪危险位）；无威胁 → Allow
 *  9) 注册的覆盖回调（最后一个返回 TRUE 者生效）
 *  记账：阻断/告警写入历史并触发回调。 */
_Use_decl_annotations_
NTSTATUS
PpFilterAccessRequest(
    _In_  PPP_ENGINE Engine,
    _In_  PPP_ACCESS_REQUEST Request,
    _Out_ PPP_ACCESS_DECISION_RESULT Result
    )
{
    PP_ACCESS_DECISION_RESULT res;
    PP_THREAT_ACTION threat;
    PP_THREAT_RESPONSE response;
    PP_PROTECTION_LEVEL targetLevel;
    ULONG callerIntegrity;
    BOOLEAN callerIsSystem;
    BOOLEAN targetIsProtected;
    BOOLEAN callerPpl;
    PWKD_PROCESS proc;              /* wkd 域查找（2026-09-06 记账段使用） */
    ULONG i;

    if (!Engine || !Request || !Result) return STATUS_INVALID_PARAMETER;

    ZeroMemory(&res, sizeof(res));
    res.Decision = PpAccessDecisionAllow;
    res.GrantedAccess = Request->DesiredAccess;
    res.Response = PpResponseNone;
    res.ThreatAction = PpThreatNone;
    wcscpy_s(res.Reason, PP_MAX_DESCRIPTION, L"allowed");

    InterlockedIncrement64(&Engine->Stats.TotalAccessRequests);

    /* 登记请求上下文（调用方侧由桥接方填充；缺失时兜底探测） */
    callerIntegrity = Request->CallerIntegrityLevel;
    if (callerIntegrity == 0 && Request->CallerProcessId != 0) {
        callerIntegrity = PpGetProcessIntegrityLevel(Request->CallerProcessId);
        Request->CallerIntegrityLevel = callerIntegrity;
    }
    callerIsSystem = PpIsSystemProcess(Request->CallerProcessId);
    Request->CallerIsSystem = callerIsSystem ? TRUE : FALSE;
    Request->CallerIsElevated = (callerIntegrity >= PP_INTEGRITY_HIGH) ? TRUE : FALSE;
    if (Request->CallerProcessId != 0 &&
        Request->CallerProtectionLevel.Type == PpProtectionTypeNone) {
        Request->CallerProtectionLevel = PpGetProtectionLevel(Engine, Request->CallerProcessId);
    }

    /* 1) 自访问 */
    if (Request->CallerProcessId == Request->TargetProcessId) {
        res.Decision = PpAccessDecisionAllow;
        wcscpy_s(res.Reason, PP_MAX_DESCRIPTION, L"self access");
        goto done;
    }

    /* 2) 目标未受保护 */
    targetIsProtected = PpIsProcessProtected(Engine, Request->TargetProcessId);
    if (!targetIsProtected) {
        res.Decision = PpAccessDecisionAllow;
        wcscpy_s(res.Reason, PP_MAX_DESCRIPTION, L"target not protected");
        goto done;
    }

    /* 3) 调用方白名单 */
    if (PpIsWhitelisted(Engine, Request->CallerProcessId)) {
        res.Decision = PpAccessDecisionAllow;
        wcscpy_s(res.Reason, PP_MAX_DESCRIPTION, L"whitelisted caller");
        goto done;
    }

    /* 4) 本产品组件（对齐 SS IsShadowStrikeComponent） */
    if (PpIsWkdComponent(Request->CallerProcessId)) {
        res.Decision = PpAccessDecisionAllow;
        wcscpy_s(res.Reason, PP_MAX_DESCRIPTION, L"wkd component");
        goto done;
    }

    /* 5) SYSTEM 且无威胁动作 → 放行 */
    threat = PpClassifyAccessRequest(Request);
    if (callerIsSystem && threat == PpThreatNone) {
        res.Decision = PpAccessDecisionAllow;
        wcscpy_s(res.Reason, PP_MAX_DESCRIPTION, L"system caller, no threat");
        goto done;
    }

    /* 6) 调用方保护级别 ≥ 目标保护级别（仅 PPL 调用方）→ 放行（对齐 SS
     *    callerProtectionLevel >= targetProtectionLevel 检查） */
    callerPpl = Request->CallerProtectionLevel.Type != PpProtectionTypeNone;
    if (callerPpl) {
        targetLevel = PpGetProtectionLevel(Engine, Request->TargetProcessId);
        if (PP_LEVEL_GE(Request->CallerProtectionLevel, targetLevel)) {
            res.Decision = PpAccessDecisionAllow;
            wcscpy_s(res.Reason, PP_MAX_DESCRIPTION, L"caller protection level sufficient");
            goto done;
        }
    }

    /* 7/8) 威胁分类与处置 */
    if (threat != PpThreatNone) {
        response = PpGetResponseForAction(Engine, threat);
        res.ThreatAction = threat;
        res.Response = response;
        res.ShouldLog = (response & PpResponseLog) ? TRUE : FALSE;
        res.ShouldAlert = (response & PpResponseAlert) ? TRUE : FALSE;

        if (response & PpResponseBlock) {
            res.Decision = PpAccessDecisionDenyAndAlert;
            res.GrantedAccess = 0;
            wcscpy_s(res.Reason, PP_MAX_DESCRIPTION, L"blocked threat");
        } else {
            res.Decision = PpAccessDecisionAllowReduced;
            res.StrippedAccess = Request->DesiredAccess & ~PpStripDangerousAccess(
                Engine, Request->DesiredAccess, FALSE);
            res.GrantedAccess = PpStripDangerousAccess(Engine, Request->DesiredAccess, FALSE);
            wcscpy_s(res.Reason, PP_MAX_DESCRIPTION, L"threat, dangerous access stripped");
        }

        /* 记账 */
        if (res.Decision == PpAccessDecisionDenyAndAlert) {
            InterlockedIncrement64(&Engine->Stats.TotalAccessBlocked);
            if (threat & PpThreatProcessTerminate) InterlockedIncrement64(&Engine->Stats.ProcessTerminationBlocked);
            if (threat & PpThreatProcessSuspend)   InterlockedIncrement64(&Engine->Stats.SuspensionBlocked);
            if (threat & PpThreatMemoryWrite)      InterlockedIncrement64(&Engine->Stats.MemoryWriteBlocked);
            if (threat & PpThreatThreadCreate)     InterlockedIncrement64(&Engine->Stats.ThreadCreationBlocked);
            if (threat & PpThreatHandleDuplicate)  InterlockedIncrement64(&Engine->Stats.HandleDuplicationBlocked);
            if (threat & PpThreatThreadTerminate)  InterlockedIncrement64(&Engine->Stats.ThreadTerminationBlocked);
            if (threat & PpThreatApcQueue)         InterlockedIncrement64(&Engine->Stats.ApcInjectionBlocked);
            if (threat & PpThreatMemoryAlloc)      InterlockedIncrement64(&Engine->Stats.MemoryWriteBlocked);
        } else {
            InterlockedIncrement64(&Engine->Stats.TotalAccessReduced);
        }

        /* 阻断/告警事件：写历史 + 通知回调 */
        if (res.ShouldLog || res.ShouldAlert) {
            PP_BLOCKED_ACCESS_EVENT evt;
            ZeroMemory(&evt, sizeof(evt));
            GetSystemTimeAsFileTime((LPFILETIME)&evt.Timestamp);
            evt.Request = *Request;
            evt.Decision = res;
            evt.ThreatAction = threat;
            evt.ResponseTaken = (ULONG)response;
            EnterCriticalSection(&Engine->Lock);
            evt.EventId = Engine->NextEventId++;
            if (Engine->BlockedLogCount < PP_MAX_BLOCKED_ATTEMPTS_LOG) {
                Engine->BlockedLog[Engine->BlockedLogCount].InUse = TRUE;
                Engine->BlockedLog[Engine->BlockedLogCount].Event = evt;
                Engine->BlockedLogCount++;
            }
            GetSystemTimeAsFileTime((LPFILETIME)&Engine->Stats.LastEventTime);
            LeaveCriticalSection(&Engine->Lock);

            /* 更新目标进程记账（受保护进程，wkd 访问控制上下文，2026-09-06） */
            if (NT_SUCCESS(PsLookupWkdProcessByProcessId(
                    NULL, (HANDLE)(ULONG_PTR)Request->TargetProcessId, &proc))) {
                if (proc->AccessControlContext && proc->IsProtectedProcess) {
                    InterlockedIncrement64(&proc->AccessControlContext->BlockedAttempts);
                    proc->AccessControlContext->LastBlockedAttempt = evt.Timestamp;
                }
                PsDereferenceWkdProcess(proc);
            }

            if (res.ShouldAlert) {
                InterlockedIncrement64(&Engine->Stats.AlertsRaised);
            }
            PpFireBlockedAccess(Engine, &evt);
            PpFireThreat(Engine, threat, Request);
        }
    } else {
        /* 无威胁：全部授予（已通过系统/级别检查） */
        res.Decision = PpAccessDecisionAllow;
        res.GrantedAccess = Request->DesiredAccess;
        wcscpy_s(res.Reason, PP_MAX_DESCRIPTION, L"no threat");
    }

done:
    /* 9) 覆盖回调（最后一个返回 TRUE 者生效；对齐 SS 注册回调尾部处理） */
    EnterCriticalSection(&Engine->CallbackLock);
    for (i = 0; i < PP_MAX_CALLBACKS; i++) {
        if (Engine->AccessCallbacks[i].InUse && Engine->AccessCallbacks[i].Callback) {
            PP_ACCESS_DECISION_CALLBACK cb =
                (PP_ACCESS_DECISION_CALLBACK)Engine->AccessCallbacks[i].Callback;
            PP_ACCESS_DECISION_RESULT overrideResult;
            ZeroMemory(&overrideResult, sizeof(overrideResult));
            if (cb(Request, &overrideResult, Engine->AccessCallbacks[i].Context)) {
                res = overrideResult;
            }
        }
    }
    LeaveCriticalSection(&Engine->CallbackLock);

    *Result = res;
    return STATUS_SUCCESS;
}

/* 威胁分类（对齐 SS ClassifyAccessRequest：进程被保护才分类）。
 * 返回位域组合。 */
_Use_decl_annotations_
PP_THREAT_ACTION
PpClassifyAccessRequest(
    _In_  PPP_ACCESS_REQUEST Request
    )
{
    PP_THREAT_ACTION action = PpThreatNone;
    ULONG access;

    if (!Request) return PpThreatNone;
    access = Request->DesiredAccess;

    switch (Request->Type) {
    case PpAccessProcessOpen:
        if ((access & PROCESS_TERMINATE) != 0)               { action |= PpThreatProcessTerminate; }
        if ((access & PROCESS_SUSPEND_RESUME) != 0)          { action |= PpThreatProcessSuspend; }
        if ((access & PROCESS_VM_WRITE) != 0)                { action |= PpThreatMemoryWrite; }
        if ((access & PROCESS_VM_OPERATION) != 0)            { action |= PpThreatMemoryWrite; }
        if ((access & PROCESS_CREATE_THREAD) != 0)           { action |= PpThreatThreadCreate; }
        if ((access & PROCESS_SET_INFORMATION) != 0)         { action |= PpThreatContextModify; }
        break;

    case PpAccessThreadOpen:
        if ((access & THREAD_TERMINATE) != 0)                { action |= PpThreatThreadTerminate; }
        if ((access & THREAD_SUSPEND_RESUME) != 0)           { action |= PpThreatThreadSuspend; }
        if ((access & THREAD_SET_CONTEXT) != 0)              { action |= PpThreatContextModify; }
        if ((access & THREAD_SET_THREAD_TOKEN) != 0)         { action |= PpThreatTokenSteal; }
        break;

    case PpAccessMemoryWrite:
        action |= PpThreatMemoryWrite;
        break;

    case PpAccessMemoryRead:
        /* 内存读取与注入无关，默认不分类 */
        break;

    case PpAccessThreadCreate:
        action |= PpThreatThreadCreate;
        break;

    case PpAccessApcQueue:
        action |= PpThreatApcQueue;
        break;

    case PpAccessHandleDuplicate:
        action |= PpThreatHandleDuplicate;
        break;

    default:
        break;
    }
    return action;
}

_Use_decl_annotations_
ULONG
PpStripDangerousAccess(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG DesiredAccess,
    _In_ BOOLEAN IsThread
    )
{
    ULONG blocked;

    if (!Engine) return DesiredAccess;
    EnterCriticalSection(&Engine->Lock);
    blocked = IsThread ? Engine->Config.BlockedThreadAccess
                       : Engine->Config.BlockedProcessAccess;
    LeaveCriticalSection(&Engine->Lock);
    return DesiredAccess & ~blocked;
}

_Use_decl_annotations_
VOID
PpSetBlockedProcessAccess(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG AccessMask
    )
{
    if (!Engine) return;
    EnterCriticalSection(&Engine->Lock);
    Engine->Config.BlockedProcessAccess = AccessMask;
    LeaveCriticalSection(&Engine->Lock);
}

_Use_decl_annotations_
VOID
PpSetBlockedThreadAccess(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG AccessMask
    )
{
    if (!Engine) return;
    EnterCriticalSection(&Engine->Lock);
    Engine->Config.BlockedThreadAccess = AccessMask;
    LeaveCriticalSection(&Engine->Lock);
}

/* 便捷判定：SYSTEM 进程（TokenUser → SYSTEM SID）。 */
_Use_decl_annotations_
BOOLEAN
PpIsSystemProcess(
    _In_ ULONG ProcessId
    )
{
    HANDLE hProcess;
    HANDLE hToken = NULL;
    BOOLEAN isSystem = FALSE;
    DWORD size = 0;
    PTOKEN_USER user = NULL;
    static SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID systemSid = NULL;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (!hProcess) return FALSE;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return FALSE;
    }
    (VOID)GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
    if (size != 0) {
        user = (PTOKEN_USER)malloc(size);
        if (user) {
            RtlZeroMemory(user, size);
            if (GetTokenInformation(hToken, TokenUser, user, size, &size)) {
                if (AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
                                             0, 0, 0, 0, 0, 0, 0, &systemSid)) {
                    if (EqualSid(user->User.Sid, systemSid)) {
                        isSystem = TRUE;
                    }
                    FreeSid(systemSid);
                }
            }
            free(user);
        }
    }
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return isSystem;
}

/* 进程完整性级别（TokenIntegrityLevel；返回 0=不可用）。 */
_Use_decl_annotations_
ULONG
PpGetProcessIntegrityLevel(
    _In_ ULONG ProcessId
    )
{
    HANDLE hProcess;
    HANDLE hToken = NULL;
    ULONG integrity = 0;
    DWORD size = 0;
    PTOKEN_MANDATORY_LABEL label = NULL;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (!hProcess) return 0;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return 0;
    }
    (VOID)GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &size);
    if (size != 0) {
        label = (PTOKEN_MANDATORY_LABEL)malloc(size);
        if (label) {
            RtlZeroMemory(label, size);
            if (GetTokenInformation(hToken, TokenIntegrityLevel, label, size, &size) &&
                label->Label.Sid) {
                PULONG sub = GetSidSubAuthority(label->Label.Sid, 0);
                if (sub) {
                    integrity = (*sub) & 0xF000u;
                }
            }
            free(label);
        }
    }
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return integrity;
}

/* 进程保护级别（读内核 PS_PROTECTION，class 与驱动核对占位）。 */
_Use_decl_annotations_
PP_PROTECTION_LEVEL
PpGetProtectionLevel(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG ProcessId
    )
{
    PP_PROTECTION_LEVEL level;
    HANDLE hProcess = NULL;
    PP_PS_PROTECTION ps;
    NTSTATUS status;

    ZeroMemory(&level, sizeof(level));
    if (!Engine || ProcessId == 0) return level;
    if (!Engine->Ntdll.pNtQueryInformationProcess) return level;

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (!hProcess) return level;
    status = Engine->Ntdll.pNtQueryInformationProcess(
        hProcess, PP_PROCESS_PROTECTION_INFORMATION, &ps, sizeof(ps), NULL);
    CloseHandle(hProcess);
    if (!NT_SUCCESS(status)) {
        /* 老版本系统/权限不足：视为未保护 */
        ZeroMemory(&ps, sizeof(ps));
    }

    level.RawLevel = ps.Level;
    level.Type = (PP_PROTECTION_TYPE)((ps.Level & PP_PS_PROTECTED_TYPE_MASK) >> PP_PS_PROTECTED_TYPE_SHIFT);
    level.Signer = (PP_PROTECTION_SIGNER)((ps.Level & PP_PS_PROTECTED_SIGNER_MASK) >> PP_PS_PROTECTED_SIGNER_SHIFT);
    return level;
}

/* 应用限制性安全描述符（对齐 SS ApplyRestrictiveSecurityDescriptor）：
 * 拒绝 Everyone 的全部访问（DENY 优先），放开 SYSTEM/管理员/当前用户，
 * 并把手动覆盖的后代禁用（PROTECTED DACL）。仅作用于被保护进程，且
 * 仅成功时返回成功（不改动关键系统进程——由调用方先做硬排除）。 */
_Use_decl_annotations_
NTSTATUS
PpApplyRestrictiveSecurityDescriptor(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG ProcessId
    )
{
    HANDLE hProcess;
    HANDLE hToken = NULL;
    PSECURITY_DESCRIPTOR psd = NULL;
    PWSTR ownerSidString = NULL;
    PTOKEN_USER user = NULL;
    DWORD size = 0;
    WCHAR sddl[512];
    DWORD sddlLen;
    NTSTATUS status = STATUS_SUCCESS;

    (VOID)Engine;

    if (ProcessId == 0) return STATUS_INVALID_PARAMETER;

    /* 取当前用户 SID 字符串作为 DACL 允许项，避免把自己锁死 */
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return STATUS_ACCESS_DENIED;
    (VOID)GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
    if (size != 0) {
        user = (PTOKEN_USER)malloc(size);
        if (user) {
            RtlZeroMemory(user, size);
            if (GetTokenInformation(hToken, TokenUser, user, size, &size)) {
                (VOID)ConvertSidToStringSidW(user->User.Sid, &ownerSidString);
            }
        }
    }
    CloseHandle(hToken);
    if (user) {
        free(user);
    }
    if (!ownerSidString) return STATUS_ACCESS_DENIED;

    /* 构造 SDDL：DENY Everyone 全部（优先），ALLOW SYSTEM/BA/当前用户 全部 */
    (VOID)swprintf_s(sddl, 512, L"D:P(D;;FA;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;%s)",
                     ownerSidString);
    LocalFree(ownerSidString);

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1,
                                                              &psd, &sddlLen)) {
        return STATUS_INVALID_SECURITY_DESCR;
    }

    hProcess = OpenProcess(PROCESS_READ_CONTROL | PROCESS_WRITE_DAC | PROCESS_WRITE_OWNER,
                           FALSE, ProcessId);
    if (!hProcess) {
        LocalFree(psd);
        return STATUS_ACCESS_DENIED;
    }

    status = (NTSTATUS)SetKernelObjectSecurity(hProcess, DACL_SECURITY_INFORMATION |
                                               PROTECTED_DACL_SECURITY_INFORMATION |
                                               OWNER_SECURITY_INFORMATION, psd);
    CloseHandle(hProcess);
    LocalFree(psd);
    return status;
}

/* 获取进程安全描述符（DACL+Owner 二进制；Buffer=NULL 时返回所需长度）。 */
_Use_decl_annotations_
NTSTATUS
PpGetProcessSecurityDescriptor(
    _In_  PPP_ENGINE Engine,
    _In_  ULONG ProcessId,
    _Out_writes_bytes_opt_(*Length) PUCHAR Buffer,
    _Inout_ PULONG Length
    )
{
    HANDLE hProcess;
    DWORD needed = 0;
    NTSTATUS status;

    (VOID)Engine;

    if (ProcessId == 0 || !Length) return STATUS_INVALID_PARAMETER;

    hProcess = OpenProcess(PROCESS_READ_CONTROL, FALSE, ProcessId);
    if (!hProcess) return STATUS_ACCESS_DENIED;

    if (!Buffer) {
        (VOID)GetKernelObjectSecurity(hProcess, OWNER_SECURITY_INFORMATION |
                                      DACL_SECURITY_INFORMATION, NULL, 0, &needed);
        *Length = needed;
        CloseHandle(hProcess);
        return STATUS_SUCCESS;
    }

    if (!GetKernelObjectSecurity(hProcess, OWNER_SECURITY_INFORMATION |
                                 DACL_SECURITY_INFORMATION, Buffer, *Length, &needed)) {
        status = STATUS_BUFFER_TOO_SMALL;
        *Length = needed;
    } else {
        status = STATUS_SUCCESS;
        *Length = needed;
    }
    CloseHandle(hProcess);
    return status;
}

/* 设置进程完整性级别（对齐 SS SetProcessIntegrityLevel：仅当前进程）。 */
_Use_decl_annotations_
NTSTATUS
PpSetProcessIntegrityLevel(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG ProcessId,
    _In_ ULONG IntegrityLevel
    )
{
    HANDLE hProcess;
    HANDLE hToken = NULL;
    TOKEN_MANDATORY_LABEL label;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    NTSTATUS status;

    (VOID)Engine;

    if (ProcessId == 0) return STATUS_INVALID_PARAMETER;
    if (IntegrityLevel == 0) return STATUS_INVALID_PARAMETER;
    /* 对齐 SS：仅支持设置当前进程（出于安全语义） */
    if (ProcessId != GetCurrentProcessId()) return STATUS_ACCESS_DENIED;

    hProcess = GetCurrentProcess();
    if (!OpenProcessToken(hProcess, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &hToken)) return STATUS_ACCESS_DENIED;
    if (!AllocateAndInitializeSid(&authority, 1, (DWORD)(IntegrityLevel >> 16),
                                  0, 0, 0, 0, 0, 0, 0, &label.Label.Sid)) {
        CloseHandle(hToken);
        return STATUS_INVALID_SID;
    }
    label.Label.Attributes = SE_GROUP_INTEGRITY;
    if (SetTokenInformation(hToken, TokenIntegrityLevel, &label,
                            sizeof(TOKEN_MANDATORY_LABEL))) {
        status = STATUS_SUCCESS;
    } else {
        status = STATUS_UNSUCCESSFUL;
    }
    FreeSid(label.Label.Sid);
    CloseHandle(hToken);
    return status;
}

/**************************************************/
/* 白名单管理（对齐 SS AddToWhitelist 系列）       */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
PpAddToWhitelist(
    _In_ PPP_ENGINE Engine,
    _In_ PCWSTR ProcessName
    )
{
    WCHAR nameLower[PP_MAX_DESCRIPTION];
    ULONG i;
    ULONG freeSlot = PP_MAX_WHITELIST;

    if (!Engine || !ProcessName || ProcessName[0] == 0) return STATUS_INVALID_PARAMETER;

    wcsncpy_s(nameLower, PP_MAX_DESCRIPTION, ProcessName, _TRUNCATE);
    PpWideLower(nameLower);

    /* 仅保存镜像文件名（去掉路径） */
    {
        PWSTR slash = wcsrchr(nameLower, L'\\');
        if (slash) {
            wcscpy_s(nameLower, PP_MAX_DESCRIPTION, slash + 1);
        }
    }

    EnterCriticalSection(&Engine->Lock);
    for (i = 0; i < PP_MAX_WHITELIST; i++) {
        if (Engine->Whitelist[i].InUse) {
            if (_wcsicmp(Engine->Whitelist[i].ProcessName, nameLower) == 0) {
                LeaveCriticalSection(&Engine->Lock);
                return PP_STATUS_ALREADY_EXISTS;
            }
        } else if (freeSlot == PP_MAX_WHITELIST) {
            freeSlot = i;
        }
    }
    if (freeSlot == PP_MAX_WHITELIST) {
        LeaveCriticalSection(&Engine->Lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    wcscpy_s(Engine->Whitelist[freeSlot].ProcessName, PP_MAX_DESCRIPTION, nameLower);
    Engine->Whitelist[freeSlot].InUse = TRUE;
    Engine->Stats.WhitelistCount++;
    LeaveCriticalSection(&Engine->Lock);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PpRemoveFromWhitelist(
    _In_ PPP_ENGINE Engine,
    _In_ PCWSTR ProcessName
    )
{
    WCHAR nameLower[PP_MAX_DESCRIPTION];
    ULONG i;

    if (!Engine || !ProcessName || ProcessName[0] == 0) return STATUS_INVALID_PARAMETER;

    wcsncpy_s(nameLower, PP_MAX_DESCRIPTION, ProcessName, _TRUNCATE);
    PpWideLower(nameLower);
    {
        PWSTR slash = wcsrchr(nameLower, L'\\');
        if (slash) {
            wcscpy_s(nameLower, PP_MAX_DESCRIPTION, slash + 1);
        }
    }

    EnterCriticalSection(&Engine->Lock);
    for (i = 0; i < PP_MAX_WHITELIST; i++) {
        if (Engine->Whitelist[i].InUse &&
            _wcsicmp(Engine->Whitelist[i].ProcessName, nameLower) == 0) {
            Engine->Whitelist[i].InUse = FALSE;
            Engine->Whitelist[i].ProcessName[0] = 0;
            if (Engine->Stats.WhitelistCount > 0) {
                Engine->Stats.WhitelistCount--;
            }
            LeaveCriticalSection(&Engine->Lock);
            return STATUS_SUCCESS;
        }
    }
    LeaveCriticalSection(&Engine->Lock);
    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
BOOLEAN
PpIsWhitelisted(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG ProcessId
    )
{
    WCHAR imageName[PP_MAX_DESCRIPTION];
    WCHAR cfgName[PP_MAX_DESCRIPTION];
    ULONG i;

    if (!Engine || ProcessId == 0) return FALSE;

    if (PpGetProcessName(ProcessId, imageName, PP_MAX_DESCRIPTION) == 0) return FALSE;
    PpWideLower(imageName);

    /* 配置内联白名单 + 运行时白名单表 */
    EnterCriticalSection(&Engine->Lock);
    for (i = 0; i < Engine->Config.WhitelistedCallerCount; i++) {
        wcsncpy_s(cfgName, PP_MAX_DESCRIPTION, Engine->Config.WhitelistedCallers[i], _TRUNCATE);
        PpWideLower(cfgName);
        if (_wcsicmp(cfgName, imageName) == 0) {
            LeaveCriticalSection(&Engine->Lock);
            return TRUE;
        }
    }
    for (i = 0; i < PP_MAX_WHITELIST; i++) {
        if (Engine->Whitelist[i].InUse &&
            _wcsicmp(Engine->Whitelist[i].ProcessName, imageName) == 0) {
            LeaveCriticalSection(&Engine->Lock);
            return TRUE;
        }
    }
    LeaveCriticalSection(&Engine->Lock);
    return FALSE;
}

_Use_decl_annotations_
BOOLEAN
PpIsWhitelistedName(
    _In_ PPP_ENGINE Engine,
    _In_ PCWSTR ProcessName
    )
{
    WCHAR nameLower[PP_MAX_DESCRIPTION];
    WCHAR cfgName[PP_MAX_DESCRIPTION];
    ULONG i;

    if (!Engine || !ProcessName || ProcessName[0] == 0) return FALSE;
    wcsncpy_s(nameLower, PP_MAX_DESCRIPTION, ProcessName, _TRUNCATE);
    PpWideLower(nameLower);
    {
        PWSTR slash = wcsrchr(nameLower, L'\\');
        if (slash) {
            wcscpy_s(nameLower, PP_MAX_DESCRIPTION, slash + 1);
        }
    }

    EnterCriticalSection(&Engine->Lock);
    for (i = 0; i < Engine->Config.WhitelistedCallerCount; i++) {
        wcsncpy_s(cfgName, PP_MAX_DESCRIPTION, Engine->Config.WhitelistedCallers[i], _TRUNCATE);
        PpWideLower(cfgName);
        if (_wcsicmp(cfgName, nameLower) == 0) {
            LeaveCriticalSection(&Engine->Lock);
            return TRUE;
        }
    }
    for (i = 0; i < PP_MAX_WHITELIST; i++) {
        if (Engine->Whitelist[i].InUse &&
            _wcsicmp(Engine->Whitelist[i].ProcessName, nameLower) == 0) {
            LeaveCriticalSection(&Engine->Lock);
            return TRUE;
        }
    }
    LeaveCriticalSection(&Engine->Lock);
    return FALSE;
}

/**************************************************/
/* 回调管理（对齐 SS Register/Unregister 系列）  */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
PpRegisterAccessCallback(
    _In_  PPP_ENGINE Engine,
    _In_  PP_ACCESS_DECISION_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PULONG64 CallbackId
    )
{
    ULONG i;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

    if (!Engine || !Callback || !CallbackId) return STATUS_INVALID_PARAMETER;
    EnterCriticalSection(&Engine->CallbackLock);
    for (i = 0; i < PP_MAX_CALLBACKS; i++) {
        if (!Engine->AccessCallbacks[i].InUse) {
            Engine->AccessCallbacks[i].InUse = TRUE;
            Engine->AccessCallbacks[i].Id = Engine->NextCallbackId++;
            Engine->AccessCallbacks[i].Callback = (PVOID)Callback;
            Engine->AccessCallbacks[i].Context = Context;
            *CallbackId = Engine->AccessCallbacks[i].Id;
            status = STATUS_SUCCESS;
            break;
        }
    }
    LeaveCriticalSection(&Engine->CallbackLock);
    return status;
}

_Use_decl_annotations_
VOID
PpUnregisterAccessCallback(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG64 CallbackId
    )
{
    ULONG i;

    if (!Engine || CallbackId == 0) return;
    EnterCriticalSection(&Engine->CallbackLock);
    for (i = 0; i < PP_MAX_CALLBACKS; i++) {
        if (Engine->AccessCallbacks[i].InUse &&
            Engine->AccessCallbacks[i].Id == CallbackId) {
            Engine->AccessCallbacks[i].InUse = FALSE;
            Engine->AccessCallbacks[i].Callback = NULL;
            Engine->AccessCallbacks[i].Context = NULL;
            break;
        }
    }
    LeaveCriticalSection(&Engine->CallbackLock);
}

_Use_decl_annotations_
NTSTATUS
PpRegisterBlockedAccessCallback(
    _In_  PPP_ENGINE Engine,
    _In_  PP_BLOCKED_ACCESS_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PULONG64 CallbackId
    )
{
    ULONG i;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

    if (!Engine || !Callback || !CallbackId) return STATUS_INVALID_PARAMETER;
    EnterCriticalSection(&Engine->CallbackLock);
    for (i = 0; i < PP_MAX_CALLBACKS; i++) {
        if (!Engine->BlockedCallbacks[i].InUse) {
            Engine->BlockedCallbacks[i].InUse = TRUE;
            Engine->BlockedCallbacks[i].Id = Engine->NextCallbackId++;
            Engine->BlockedCallbacks[i].Callback = (PVOID)Callback;
            Engine->BlockedCallbacks[i].Context = Context;
            *CallbackId = Engine->BlockedCallbacks[i].Id;
            status = STATUS_SUCCESS;
            break;
        }
    }
    LeaveCriticalSection(&Engine->CallbackLock);
    return status;
}

_Use_decl_annotations_
VOID
PpUnregisterBlockedAccessCallback(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG64 CallbackId
    )
{
    ULONG i;

    if (!Engine || CallbackId == 0) return;
    EnterCriticalSection(&Engine->CallbackLock);
    for (i = 0; i < PP_MAX_CALLBACKS; i++) {
        if (Engine->BlockedCallbacks[i].InUse &&
            Engine->BlockedCallbacks[i].Id == CallbackId) {
            Engine->BlockedCallbacks[i].InUse = FALSE;
            Engine->BlockedCallbacks[i].Callback = NULL;
            Engine->BlockedCallbacks[i].Context = NULL;
            break;
        }
    }
    LeaveCriticalSection(&Engine->CallbackLock);
}

_Use_decl_annotations_
NTSTATUS
PpRegisterProtectionStatusCallback(
    _In_  PPP_ENGINE Engine,
    _In_  PP_PROTECTION_STATUS_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PULONG64 CallbackId
    )
{
    ULONG i;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

    if (!Engine || !Callback || !CallbackId) return STATUS_INVALID_PARAMETER;
    EnterCriticalSection(&Engine->CallbackLock);
    for (i = 0; i < PP_MAX_CALLBACKS; i++) {
        if (!Engine->StatusCallbacks[i].InUse) {
            Engine->StatusCallbacks[i].InUse = TRUE;
            Engine->StatusCallbacks[i].Id = Engine->NextCallbackId++;
            Engine->StatusCallbacks[i].Callback = (PVOID)Callback;
            Engine->StatusCallbacks[i].Context = Context;
            *CallbackId = Engine->StatusCallbacks[i].Id;
            status = STATUS_SUCCESS;
            break;
        }
    }
    LeaveCriticalSection(&Engine->CallbackLock);
    return status;
}

_Use_decl_annotations_
VOID
PpUnregisterProtectionStatusCallback(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG64 CallbackId
    )
{
    ULONG i;

    if (!Engine || CallbackId == 0) return;
    EnterCriticalSection(&Engine->CallbackLock);
    for (i = 0; i < PP_MAX_CALLBACKS; i++) {
        if (Engine->StatusCallbacks[i].InUse &&
            Engine->StatusCallbacks[i].Id == CallbackId) {
            Engine->StatusCallbacks[i].InUse = FALSE;
            Engine->StatusCallbacks[i].Callback = NULL;
            Engine->StatusCallbacks[i].Context = NULL;
            break;
        }
    }
    LeaveCriticalSection(&Engine->CallbackLock);
}

_Use_decl_annotations_
NTSTATUS
PpRegisterThreatCallback(
    _In_  PPP_ENGINE Engine,
    _In_  PP_THREAT_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ PULONG64 CallbackId
    )
{
    ULONG i;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

    if (!Engine || !Callback || !CallbackId) return STATUS_INVALID_PARAMETER;
    EnterCriticalSection(&Engine->CallbackLock);
    for (i = 0; i < PP_MAX_CALLBACKS; i++) {
        if (!Engine->ThreatCallbacks[i].InUse) {
            Engine->ThreatCallbacks[i].InUse = TRUE;
            Engine->ThreatCallbacks[i].Id = Engine->NextCallbackId++;
            Engine->ThreatCallbacks[i].Callback = (PVOID)Callback;
            Engine->ThreatCallbacks[i].Context = Context;
            *CallbackId = Engine->ThreatCallbacks[i].Id;
            status = STATUS_SUCCESS;
            break;
        }
    }
    LeaveCriticalSection(&Engine->CallbackLock);
    return status;
}

_Use_decl_annotations_
VOID
PpUnregisterThreatCallback(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG64 CallbackId
    )
{
    ULONG i;

    if (!Engine || CallbackId == 0) return;
    EnterCriticalSection(&Engine->CallbackLock);
    for (i = 0; i < PP_MAX_CALLBACKS; i++) {
        if (Engine->ThreatCallbacks[i].InUse &&
            Engine->ThreatCallbacks[i].Id == CallbackId) {
            Engine->ThreatCallbacks[i].InUse = FALSE;
            Engine->ThreatCallbacks[i].Callback = NULL;
            Engine->ThreatCallbacks[i].Context = NULL;
            break;
        }
    }
    LeaveCriticalSection(&Engine->CallbackLock);
}

/**************************************************/
/* 统计 / 历史 / 报告 / 自检                       */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
PpGetStatistics(
    _In_ PPP_ENGINE Engine,
    _Out_ PPP_STATISTICS Stats
    )
{
    if (!Engine || !Stats) return STATUS_INVALID_PARAMETER;
    EnterCriticalSection(&Engine->Lock);
    *Stats = Engine->Stats;
    LeaveCriticalSection(&Engine->Lock);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PpResetStatistics(
    _In_ PPP_ENGINE Engine
    )
{
    LARGE_INTEGER startTime;

    if (!Engine) return;
    EnterCriticalSection(&Engine->Lock);
    startTime = Engine->Stats.StartTime;
    ZeroMemory(&Engine->Stats, sizeof(Engine->Stats));
    Engine->Stats.StartTime = startTime;
    LeaveCriticalSection(&Engine->Lock);
}

_Use_decl_annotations_
NTSTATUS
PpGetBlockedAccessHistory(
    _In_      PPP_ENGINE Engine,
    _In_      ULONG MaxEntries,
    _Out_writes_opt_(*Count) PPP_BLOCKED_ACCESS_EVENT Buffer,
    _Inout_   PULONG Count
    )
{
    ULONG i;
    ULONG n;
    ULONG startIdx;

    if (!Engine || !Count || MaxEntries == 0) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&Engine->Lock);
    n = Engine->BlockedLogCount;
    if (!Buffer) {
        *Count = (n < MaxEntries) ? n : MaxEntries;
        LeaveCriticalSection(&Engine->Lock);
        return STATUS_SUCCESS;
    }
    if (*Count < ((n < MaxEntries) ? n : MaxEntries)) {
        *Count = (n < MaxEntries) ? n : MaxEntries;
        LeaveCriticalSection(&Engine->Lock);
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* 最新在前：日志按产生顺序填满即止（超限丢弃最旧），
     * 取时从最新偏移（n-1）回溯 MaxEntries 条 */
    startIdx = (n > MaxEntries) ? (n - MaxEntries) : 0;
    for (i = 0; i < n - startIdx; i++) {
        Buffer[i] = Engine->BlockedLog[startIdx + i].Event;
    }
    for (; i < *Count; i++) {
        ZeroMemory(&Buffer[i], sizeof(PP_BLOCKED_ACCESS_EVENT));
    }
    *Count = n - startIdx;
    LeaveCriticalSection(&Engine->Lock);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
PpClearBlockedAccessHistory(
    _In_ PPP_ENGINE Engine
    )
{
    ULONG i;

    if (!Engine) return;
    EnterCriticalSection(&Engine->Lock);
    for (i = 0; i < Engine->BlockedLogCount; i++) {
        ZeroMemory(&Engine->BlockedLog[i].Event, sizeof(PP_BLOCKED_ACCESS_EVENT));
        Engine->BlockedLog[i].InUse = FALSE;
    }
    Engine->BlockedLogCount = 0;
    LeaveCriticalSection(&Engine->Lock);
}

/* 辅助：宽字符串 JSON 转义。 */
static VOID
PpJsonEscape(
    _In_ PCWSTR Src,
    _Out_writes_(DstChars) PWSTR Dst,
    _In_ ULONG DstChars
    )
{
    ULONG s = 0;
    ULONG d = 0;

    if (!Src) {
        Src = L"";
    }
    while (Src[s] != 0 && d + 1 < DstChars) {
        if (Src[s] == L'"') {
            if (d + 2 < DstChars) { Dst[d++] = L'\\'; Dst[d++] = L'"'; }
        } else if (Src[s] == L'\\') {
            if (d + 2 < DstChars) { Dst[d++] = L'\\'; Dst[d++] = L'\\'; }
        } else {
            Dst[d++] = Src[s];
        }
        s++;
    }
    Dst[d] = 0;
}

_Use_decl_annotations_
NTSTATUS
PpExportReport(
    _In_      PPP_ENGINE Engine,
    _Out_writes_opt_(*Length) PWSTR Buffer,
    _Inout_   PULONG Length
    )
{
    PP_STATISTICS stats;
    PP_PROTECTED_PROCESS_INFO procs[PP_MAX_PROTECTED_PROCESSES];
    ULONG procCount;
    WCHAR imgEsc[PP_MAX_DESCRIPTION * 2];
    ULONG need;
    ULONG used;
    ULONG i;

    if (!Engine || !Length) return STATUS_INVALID_PARAMETER;

    (VOID)PpGetStatistics(Engine, &stats);
    procCount = PP_MAX_PROTECTED_PROCESSES;
    (VOID)PpGetAllProtectedProcesses(Engine, procs, &procCount);

    /* 估算所需字符数（长度模式） */
    need = 512 + procCount * (PP_MAX_DESCRIPTION * 4 + 64);
    if (!Buffer) {
        *Length = need;
        return STATUS_SUCCESS;
    }
    if (*Length < need) {
        *Length = need;
        return STATUS_BUFFER_TOO_SMALL;
    }

    used = (ULONG)swprintf_s(Buffer, *Length,
        L"{\"module\":\"ProcessProtection\",\"version\":\"%s\","
        L"\"isPPL\":%s,"
        L"\"totalAccessRequests\":%lld,\"totalAccessBlocked\":%lld,"
        L"\"alertsRaised\":%lld,\"protectedProcessCount\":%u,"
        L"\"whitelistCount\":%u,"
        L"\"protectedProcesses\":[",
        PpGetVersionString(),
        PpIsPPLProtected(Engine) ? L"true" : L"false",
        stats.TotalAccessRequests,
        stats.TotalAccessBlocked,
        stats.AlertsRaised,
        stats.ActiveProtected,
        stats.WhitelistCount);
    if (used == (ULONG)-1) {
        used = 0;
    }

    for (i = 0; i < procCount; i++) {
        PpJsonEscape(procs[i].ImageName, imgEsc, PP_MAX_DESCRIPTION * 2);
        used += (ULONG)swprintf_s(Buffer + used, *Length - used,
                (i == 0) ? L"{\"processId\":%lu,\"imageName\":\"%s\","
                           L"\"status\":\"%s\",\"blockedAttempts\":%lld}"
                         : L",{\"processId\":%lu,\"imageName\":\"%s\","
                           L"\"status\":\"%s\",\"blockedAttempts\":%lld}",
                procs[i].ProcessId,
                imgEsc,
                PpProtectionStatusName(procs[i].Status),
                procs[i].BlockedAttempts);
        if (used == (ULONG)-1) {
            break;
        }
    }
    used += (ULONG)swprintf_s(Buffer + used, *Length - used, L"]}\n");
    return STATUS_SUCCESS;
}

/* 自检（对齐 SS SelfTest：4 项） */
_Use_decl_annotations_
BOOLEAN
PpSelfTest(
    _In_ PPP_ENGINE Engine
    )
{
    ULONG checks = 0;
    PP_CONFIGURATION cfg;
    PP_PROTECTION_LEVEL self;
    ULONG integrity;
    PP_ACCESS_REQUEST request;
    PP_ACCESS_DECISION_RESULT result;

    if (!Engine) return FALSE;

    /* 1) 配置有效性：默认配置应有意义 */
    PpGetDefaultConfiguration(&cfg);
    if (cfg.DefaultResponse != PpResponseNone &&
        cfg.BlockedProcessAccess != 0) {
        checks++;
    }

    /* 2) 保护级别查询（应返回合法类型） */
    self = PpGetProtectionLevel(Engine, GetCurrentProcessId());
    if (self.Type == PpProtectionTypeNone ||
        self.Type == PpProtectionTypeProtectedLight ||
        self.Type == PpProtectionTypeProtected) {
        checks++;
    }

    /* 3) 完整性查询 */
    integrity = PpGetProcessIntegrityLevel(GetCurrentProcessId());
    if (integrity >= PP_INTEGRITY_LOW) {
        checks++;
    }

    /* 4) 访问过滤流水线（自进程请求） */
    ZeroMemory(&request, sizeof(request));
    ZeroMemory(&result, sizeof(result));
    request.Type = PpAccessProcessOpen;
    request.CallerProcessId = GetCurrentProcessId();
    request.CallerThreadId = (ULONG)GetCurrentThreadId();
    request.TargetProcessId = GetCurrentProcessId();
    request.DesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION;
    if (NT_SUCCESS(PpFilterAccessRequest(Engine, &request, &result))) {
        checks++;
    }

    return checks >= PP_SELF_TEST_CHECKS;
}

_Use_decl_annotations_
PCWSTR
PpGetVersionString(
    VOID
    )
{
    return L"1.1.0.0";
}

/**************************************************/
/* 内核桥（驱动投递点待接通，Agent 侧已对齐 SS      */
/* OnKernelHandleAlert 实体语义：日志 + 受保护判定  */
/* + 高分告警事件 → 安全事件桥接）                  */
/**************************************************/

_Use_decl_annotations_
VOID
PpOnKernelHandleAlert(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG SourceProcessId,
    _In_ ULONG TargetProcessId,
    _In_ ULONG RequestedAccess,
    _In_ ULONG GrantedAccess,
    _In_ ULONG SuspicionScore,
    _In_ ULONG SuspiciousFlags
    )
{
    PP_ACCESS_REQUEST request;
    PP_ACCESS_DECISION_RESULT result;
    PP_THREAT_ACTION threat;
    PP_BLOCKED_ACCESS_EVENT evt;
    NTSTATUS status;
    WCHAR desc[PP_MAX_DESCRIPTION];

    if (!Engine) return;
    InterlockedIncrement64(&Engine->Stats.KernelHandleOperations);
    GetSystemTimeAsFileTime((LPFILETIME)&Engine->Stats.LastEventTime);

    /* 内核句柄告警日志（对齐 SS OnKernelHandleAlert 日志行：
     * src/tgt/req/granted/score/flags） */
    swprintf_s(desc, PP_MAX_DESCRIPTION,
        L"[ProcessProtection] Kernel handle alert: src=%lu tgt=%lu "
        L"req=0x%X granted=0x%X score=%lu flags=0x%X",
        SourceProcessId, TargetProcessId, RequestedAccess, GrantedAccess,
        SuspicionScore, SuspiciousFlags);
    OutputDebugStringW(desc);

    ZeroMemory(&request, sizeof(request));
    ZeroMemory(&result, sizeof(result));
    request.Type = PpAccessProcessOpen;
    request.CallerProcessId = SourceProcessId;
    request.CallerThreadId = 0;
    request.TargetProcessId = TargetProcessId;
    request.DesiredAccess = RequestedAccess;

    status = PpFilterAccessRequest(Engine, &request, &result);
    if (NT_SUCCESS(status) &&
        SuspicionScore >= PP_KERNEL_ALERT_SUSPICION_THRESHOLD &&
        result.Decision != PpAccessDecisionAllow) {
        /* 高度可疑且用户态判定非放行：告警上报
         * （对齐 SS 高分告警线：ReportBlockedAccessAlert）。 */
        InterlockedIncrement64(&Engine->Stats.AlertsRaised);

        threat = PpClassifyAccessRequest(&request);

        /* 构造阻断事件快照并触发回调
         * （→ AccessControlEngine 桥接为自防护安全事件）。 */
        ZeroMemory(&evt, sizeof(evt));
        GetSystemTimeAsFileTime((LPFILETIME)&evt.Timestamp);
        evt.Request = request;
        evt.Decision = result;
        evt.ThreatAction = threat;
        evt.ResponseTaken = (ULONG)result.Response;
        EnterCriticalSection(&Engine->Lock);
        evt.EventId = Engine->NextEventId++;
        LeaveCriticalSection(&Engine->Lock);

        PpFireBlockedAccess(Engine, &evt);
        PpFireThreat(Engine, threat, &request);

        if (Engine->Config.SendTelemetry) {
            (VOID)0;   /* 遥测出口：未来接 ETW/管道（占位，对齐 SS TelemetryCollector 语义） */
        }
    }
}

/* 请求内核 PPL 提升（占位：驱动桥接后经 ALPC 下发）。 */
_Use_decl_annotations_
NTSTATUS
PpRequestKernelPplElevation(
    _In_ PPP_ENGINE Engine
    )
{
    (VOID)Engine;
    return STATUS_NOT_IMPLEMENTED;
}

/* 请求内核阻断进程（占位：驱动桥接后经 ALPC 下发）。 */
_Use_decl_annotations_
NTSTATUS
PpRequestKernelProcessBlock(
    _In_ PPP_ENGINE Engine,
    _In_ ULONG ProcessId,
    _In_ PCWSTR Reason
    )
{
    (VOID)Engine;
    (VOID)ProcessId;
    (VOID)Reason;
    return STATUS_NOT_IMPLEMENTED;
}

/**************************************************/
/* 名称工具（对齐 SS Get*Name 系列）               */
/**************************************************/

_Use_decl_annotations_
PCWSTR
PpThreatActionName(
    _In_ PP_THREAT_ACTION Action
    )
{
    switch (Action) {
    case PpThreatNone:             return L"None";
    case PpThreatProcessTerminate: return L"ProcessTerminate";
    case PpThreatProcessSuspend:   return L"ProcessSuspend";
    case PpThreatThreadTerminate:  return L"ThreadTerminate";
    case PpThreatThreadSuspend:    return L"ThreadSuspend";
    case PpThreatMemoryWrite:      return L"MemoryWrite";
    case PpThreatMemoryAlloc:      return L"MemoryAlloc";
    case PpThreatThreadCreate:     return L"ThreadCreate";
    case PpThreatApcQueue:         return L"ApcQueue";
    case PpThreatHandleDuplicate:  return L"HandleDuplicate";
    case PpThreatTokenSteal:       return L"TokenSteal";
    case PpThreatContextModify:    return L"ContextModify";
    case PpThreatDebugAttach:      return L"DebugAttach";
    default:                       return L"Unknown";
    }
}

_Use_decl_annotations_
PCWSTR
PpAccessRequestTypeName(
    _In_ PP_ACCESS_REQUEST_TYPE Type
    )
{
    switch (Type) {
    case PpAccessProcessOpen:      return L"ProcessOpen";
    case PpAccessProcessDuplicate: return L"ProcessDuplicate";
    case PpAccessThreadOpen:       return L"ThreadOpen";
    case PpAccessThreadDuplicate:  return L"ThreadDuplicate";
    case PpAccessHandleDuplicate:  return L"HandleDuplicate";
    case PpAccessMemoryRead:       return L"MemoryRead";
    case PpAccessMemoryWrite:      return L"MemoryWrite";
    case PpAccessThreadCreate:     return L"ThreadCreate";
    case PpAccessApcQueue:         return L"ApcQueue";
    default:                       return L"Unknown";
    }
}

_Use_decl_annotations_
PCWSTR
PpDecisionName(
    _In_ PP_ACCESS_DECISION Decision
    )
{
    switch (Decision) {
    case PpAccessDecisionAllow:        return L"Allow";
    case PpAccessDecisionAllowReduced: return L"AllowReduced";
    case PpAccessDecisionDeny:         return L"Deny";
    case PpAccessDecisionDenyAndAlert: return L"DenyAndAlert";
    default:                           return L"Unknown";
    }
}

_Use_decl_annotations_
PCWSTR
PpProtectionTypeName(
    _In_ PP_PROTECTION_TYPE Type
    )
{
    switch (Type) {
    case PpProtectionTypeNone:          return L"None";
    case PpProtectionTypeProtectedLight:return L"ProtectedLight";
    case PpProtectionTypeProtected:     return L"Protected";
    default:                            return L"Unknown";
    }
}

_Use_decl_annotations_
PCWSTR
PpProtectionSignerName(
    _In_ PP_PROTECTION_SIGNER Signer
    )
{
    switch (Signer) {
    case PpProtectionSignerNone:        return L"None";
    case PpProtectionSignerAuthenticode:return L"Authenticode";
    case PpProtectionSignerCodeGen:     return L"CodeGen";
    case PpProtectionSignerAntimalware: return L"Antimalware";
    case PpProtectionSignerLsa:         return L"Lsa";
    case PpProtectionSignerWindows:     return L"Windows";
    case PpProtectionSignerWinTcb:      return L"WinTcb";
    default:                            return L"Unknown";
    }
}

_Use_decl_annotations_
PCWSTR
PpProtectionStatusName(
    _In_ PP_PROTECTION_STATUS Status
    )
{
    switch (Status) {
    case PpProtectionUnprotected:     return L"Unprotected";
    case PpProtectionUserModeOnly:    return L"UserModeOnly";
    case PpProtectionKernelProtected: return L"KernelProtected";
    case PpProtectionPplProtected:    return L"PPLProtected";
    case PpProtectionCritical:        return L"Critical";
    default:                          return L"Unknown";
    }
}

_Use_decl_annotations_
VOID
PpFormatAccessRights(
    _In_ ULONG AccessRights,
    _In_ BOOLEAN IsThread,
    _Out_writes_(BufferChars) PWSTR Buffer,
    _In_ ULONG BufferChars
    )
{
    ULONG used = 0;

    if (!Buffer || BufferChars == 0) return;
    Buffer[0] = 0;

#define PP_APPEND_RIGHT(_mask, _name)                                          \
    do { if ((AccessRights & (_mask)) != 0) {                                   \
        used += (ULONG)swprintf_s(Buffer + used, BufferChars - used,            \
                                  (used == 0) ? L"%s" : L"|%s", (_name));       \
    } } while (0)

    if (IsThread) {
        PP_APPEND_RIGHT(THREAD_TERMINATE,            L"THREAD_TERMINATE");
        PP_APPEND_RIGHT(THREAD_SUSPEND_RESUME,       L"THREAD_SUSPEND_RESUME");
        PP_APPEND_RIGHT(THREAD_GET_CONTEXT,          L"THREAD_GET_CONTEXT");
        PP_APPEND_RIGHT(THREAD_SET_CONTEXT,          L"THREAD_SET_CONTEXT");
        PP_APPEND_RIGHT(THREAD_SET_INFORMATION,      L"THREAD_SET_INFORMATION");
        PP_APPEND_RIGHT(THREAD_QUERY_INFORMATION,    L"THREAD_QUERY_INFORMATION");
        PP_APPEND_RIGHT(THREAD_SET_THREAD_TOKEN,     L"THREAD_SET_THREAD_TOKEN");
        PP_APPEND_RIGHT(THREAD_QUERY_LIMITED_INFORMATION, L"THREAD_QUERY_LIMITED_INFORMATION");
    } else {
        PP_APPEND_RIGHT(PROCESS_TERMINATE,           L"PROCESS_TERMINATE");
        PP_APPEND_RIGHT(PROCESS_SUSPEND_RESUME,      L"PROCESS_SUSPEND_RESUME");
        PP_APPEND_RIGHT(PROCESS_VM_READ,             L"PROCESS_VM_READ");
        PP_APPEND_RIGHT(PROCESS_VM_WRITE,            L"PROCESS_VM_WRITE");
        PP_APPEND_RIGHT(PROCESS_VM_OPERATION,        L"PROCESS_VM_OPERATION");
        PP_APPEND_RIGHT(PROCESS_CREATE_THREAD,       L"PROCESS_CREATE_THREAD");
        PP_APPEND_RIGHT(PROCESS_SET_INFORMATION,     L"PROCESS_SET_INFORMATION");
        PP_APPEND_RIGHT(PROCESS_QUERY_INFORMATION,   L"PROCESS_QUERY_INFORMATION");
        PP_APPEND_RIGHT(PROCESS_QUERY_LIMITED_INFORMATION, L"PROCESS_QUERY_LIMITED_INFORMATION");
        PP_APPEND_RIGHT(PROCESS_CREATE_PROCESS,      L"PROCESS_CREATE_PROCESS");
    }
    PP_APPEND_RIGHT(SYNCHRONIZE,                     L"SYNCHRONIZE");
#undef PP_APPEND_RIGHT

    if (Buffer[0] == 0) {
        wcscpy_s(Buffer, BufferChars, L"NONE");
    }
}
