/**************************************************/
/*  WkDefender IOC — 进程富化引擎实现               */
/*  全量迁移 PhantomCore ProcessMonitor.cpp          */
/*                                                   */
/*  CategorizeProcess — 17 分类                     */
/*  GetProcessUser — 用户名 + 域                    */
/*  GetProcessIntegrityLevel — 完整性级别           */
/*  IsProcessElevated — 提权检测                    */
/*  DetectPPIDSpoofing — 创建时间比对 + smss 规则   */
/*  WasPidReused — 历史 PID 复用窗口检测            */
/**************************************************/

#include "IocProcessEnrich.h"
#include "IocScanner.h"
#include "../Common/FileUtils.h"
#include "PEAnalyzer/PeAnalyzer.h"
#include "../Memory/MemoryScan.h"
#include "../IOA/Tier1/T1ShellcodeDetect.h"
#include "../ProcessThreads.h"   /* WptAnalyzeThreads */
#include <stdio.h>
#include <string.h>
#include <sddl.h>
#include <tlhelp32.h>

#pragma comment(lib, "advapi32.lib")

//
// 全局历史追踪器
//
WKD_HISTORICAL_TRACKER g_WkdHistoricalTracker = { 0 };

//
// PEB / RTL_USER_PROCESS_PARAMETERS 布局（对齐 SS EM_PEB/EM_PROCESS_PARAMETERS）
// 仅定义到 Environment 指针偏移（x64 0x80 / x86 0x48）。
// 定义置于文件头部: 多个检测函数早于原定义位置使用 (C89 需类型先行)。
//
typedef struct _IPE_PEB64 {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[1];         // 0x08
    PVOID ImageBaseAddress;     // 0x10 (对齐 C 版 PH_PEB)
    PVOID Ldr;                  // 0x18
    PVOID ProcessParameters;    // 0x20
} IPE_PEB64;

typedef struct _IPE_PEB32 {
    BYTE Reserved1[4];
    ULONG Mutant;               // 0x04
    ULONG ImageBaseAddress;     // 0x08
    ULONG Ldr;                  // 0x0C
    ULONG ProcessParameters;    // 0x10
} IPE_PEB32;

typedef struct _IPE_PROCESS_PARAMETERS64 {
    BYTE Reserved1[16];             // 0x00-0x10
    PVOID Reserved2[10];            // 0x10-0x60
    UNICODE_STRING ImagePathName;   // 0x60
    UNICODE_STRING CommandLine;     // 0x70
    PVOID Environment;              // 0x80
} IPE_PROCESS_PARAMETERS64;

typedef struct _IPE_PROCESS_PARAMETERS32 {
    BYTE Reserved1[16];             // 0x00-0x10
    ULONG Reserved2[5];             // 0x10-0x24
    BYTE Reserved3[12];             // 0x24-0x30 (CURDIR)
    ULONG Reserved4[6];             // 0x30-0x48 (3 x UNICODE_STRING)
    ULONG Environment;              // 0x48
} IPE_PROCESS_PARAMETERS32;

//
// 内部辅助: 不区分大小写子串匹配
//
static BOOL
IpeStrStrI(
    _In_ PCWSTR Haystack,
    _In_ PCWSTR Needle
    )
{
    if (!Haystack || !Needle) return FALSE;
    SIZE_T needleLen = wcslen(Needle);
    for (; *Haystack; Haystack++) {
        if (_wcsnicmp(Haystack, Needle, needleLen) == 0) return TRUE;
    }
    return FALSE;
}

//
// 内部辅助: 从路径提取文件名（最后一段）
//
static PCWSTR
IpeExtractFileName(
    _In_ PCWSTR FullPath
    )
{
    PCWSTR p;
    if (!FullPath || !FullPath[0]) return NULL;
    p = FullPath + wcslen(FullPath) - 1;
    while (p >= FullPath) {
        if (*p == L'\\' || *p == L'/') return p + 1;
        p--;
    }
    return FullPath;
}

// ============================================================================
// 进程分类（对齐 PS CategorizeProcess，17 分类）
// ============================================================================

_Use_decl_annotations_
WKD_PROCESS_CATEGORY
IpeCategorizeProcess(
    PCWSTR ProcessName,
    PCWSTR ProcessPath
    )
{
    if (!ProcessName || !ProcessPath) return WkdPcUnknown;

    /* System critical */
    if (wcscmp(ProcessName, L"system") == 0 ||
        wcscmp(ProcessName, L"smss.exe") == 0 ||
        wcscmp(ProcessName, L"csrss.exe") == 0 ||
        wcscmp(ProcessName, L"wininit.exe") == 0) {
        return WkdPcSystemCritical;
    }

    /* System core */
    if (wcscmp(ProcessName, L"services.exe") == 0 ||
        wcscmp(ProcessName, L"lsass.exe") == 0 ||
        wcscmp(ProcessName, L"winlogon.exe") == 0 ||
        wcscmp(ProcessName, L"svchost.exe") == 0) {
        return WkdPcSystemCore;
    }

    /* Browsers */
    if (wcscmp(ProcessName, L"chrome.exe") == 0 ||
        wcscmp(ProcessName, L"firefox.exe") == 0 ||
        wcscmp(ProcessName, L"msedge.exe") == 0 ||
        wcscmp(ProcessName, L"iexplore.exe") == 0) {
        return WkdPcInternetBrowser;
    }

    /* Office */
    if (wcsstr(ProcessName, L"winword") != NULL ||
        wcsstr(ProcessName, L"excel") != NULL ||
        wcsstr(ProcessName, L"powerpnt") != NULL ||
        wcsstr(ProcessName, L"outlook") != NULL) {
        return WkdPcOffice;
    }

    /* Script hosts */
    if (wcscmp(ProcessName, L"powershell.exe") == 0 ||
        wcscmp(ProcessName, L"pwsh.exe") == 0 ||
        wcscmp(ProcessName, L"cscript.exe") == 0 ||
        wcscmp(ProcessName, L"wscript.exe") == 0 ||
        wcscmp(ProcessName, L"python.exe") == 0 ||
        wcscmp(ProcessName, L"node.exe") == 0) {
        return WkdPcScriptHost;
    }

    /* LOLBins */
    if (wcscmp(ProcessName, L"certutil.exe") == 0 ||
        wcscmp(ProcessName, L"bitsadmin.exe") == 0 ||
        wcscmp(ProcessName, L"rundll32.exe") == 0 ||
        wcscmp(ProcessName, L"regsvr32.exe") == 0 ||
        wcscmp(ProcessName, L"mshta.exe") == 0 ||
        wcscmp(ProcessName, L"installutil.exe") == 0 ||
        wcscmp(ProcessName, L"msiexec.exe") == 0) {
        return WkdPcLOLBin;
    }

    /* System utilities */
    if (wcscmp(ProcessName, L"cmd.exe") == 0 ||
        wcscmp(ProcessName, L"conhost.exe") == 0 ||
        wcscmp(ProcessName, L"reg.exe") == 0 ||
        wcscmp(ProcessName, L"sc.exe") == 0 ||
        wcscmp(ProcessName, L"taskkill.exe") == 0 ||
        wcscmp(ProcessName, L"tasklist.exe") == 0) {
        return WkdPcSystemUtility;
    }

    /* Installers */
    if (IpeStrStrI(ProcessName, L"setup.exe") ||
        IpeStrStrI(ProcessName, L"install.exe") ||
        IpeStrStrI(ProcessName, L"msiexec") ||
        wcscmp(ProcessName, L"msiexec.exe") == 0) {
        return WkdPcInstaller;
    }

    /* Developer tools */
    if (wcscmp(ProcessName, L"devenv.exe") == 0 ||
        wcscmp(ProcessName, L"code.exe") == 0 ||
        IpeStrStrI(ProcessName, L"gcc") ||
        IpeStrStrI(ProcessName, L"cl.exe") ||
        wcscmp(ProcessName, L"make.exe") == 0) {
        return WkdPcDeveloper;
    }

    /* Network tools */
    if (wcscmp(ProcessName, L"curl.exe") == 0 ||
        wcscmp(ProcessName, L"wget.exe") == 0 ||
        wcscmp(ProcessName, L"netsh.exe") == 0 ||
        wcscmp(ProcessName, L"netstat.exe") == 0 ||
        wcscmp(ProcessName, L"ping.exe") == 0 ||
        wcscmp(ProcessName, L"tracert.exe") == 0) {
        return WkdPcNetworkUtility;
    }

    /* Security software */
    if (IpeStrStrI(ProcessPath, L"\\program files\\windows defender") ||
        IpeStrStrI(ProcessPath, L"\\program files\\trend micro") ||
        IpeStrStrI(ProcessPath, L"\\program files\\symantec") ||
        IpeStrStrI(ProcessPath, L"\\program files\\mcafee") ||
        IpeStrStrI(ProcessPath, L"\\program files\\crowdstrike") ||
        IpeStrStrI(ProcessPath, L"\\program files\\carbon black") ||
        IpeStrStrI(ProcessPath, L"\\program files\\sentinelone") ||
        IpeStrStrI(ProcessPath, L"wkdefender")) {
        return WkdPcSecuritySoftware;
    }

    /* System service (from System32) */
    if (ProcessPath && ProcessPath[0]) {
        if (wcsstr(ProcessPath, L"\\system32\\") != NULL ||
            wcsstr(ProcessPath, L"\\syswow64\\") != NULL) {
            return WkdPcSystemService;
        }
    }

    return WkdPcEndUserApp;
}

// ============================================================================
// 用户身份 + 完整性采集（对齐 PS GetProcessUser / GetIntegrityLevel）
// ============================================================================

_Use_decl_annotations_
BOOL
IpeCollectUserContext(
    DWORD            ProcessId,
    PWKD_USER_CONTEXT Context
    )
{
    HANDLE hProcess;
    HANDLE hToken = NULL;
    BOOL result = FALSE;

    RtlZeroMemory(Context, sizeof(*Context));

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (!hProcess) return FALSE;

    /* 检查 WOW64 */
    {
        BOOL isWow64 = FALSE;
        if (IsWow64Process(hProcess, &isWow64)) {
            Context->IsWow64 = (isWow64 != FALSE);
        }
    }

    /* 打开令牌 */
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    /* 用户身份（对齐 PS GetProcessUser） */
    {
        DWORD dwLength = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
        if (dwLength > 0 && dwLength <= 4096) {
            PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwLength);
            if (pTokenUser) {
                if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength)) {
                    WCHAR user[256] = {0}, domain[256] = {0};
                    DWORD userSize = 256, domainSize = 256;
                    SID_NAME_USE sidType;

                    if (LookupAccountSidW(NULL, pTokenUser->User.Sid,
                        user, &userSize, domain, &domainSize, &sidType)) {
                        wcsncpy_s(Context->UserName, RTL_NUMBER_OF(Context->UserName),
                                  user, _TRUNCATE);
                        wcsncpy_s(Context->DomainName, RTL_NUMBER_OF(Context->DomainName),
                                  domain, _TRUNCATE);
                    }
                }
                free(pTokenUser);
            }
        }
    }

    /* 完整性级别（对齐 PS GetProcessIntegrityLevel） */
    {
        DWORD dwLength = 0;
        GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength);
        if (dwLength > 0 && dwLength <= 4096) {
            PTOKEN_MANDATORY_LABEL pLabel = (PTOKEN_MANDATORY_LABEL)malloc(dwLength);
            if (pLabel) {
                if (GetTokenInformation(hToken, TokenIntegrityLevel,
                    pLabel, dwLength, &dwLength)) {
                    if (GetSidSubAuthorityCount(pLabel->Label.Sid) &&
                        *GetSidSubAuthorityCount(pLabel->Label.Sid) > 0) {
                        Context->IntegrityLevel = *GetSidSubAuthority(
                            pLabel->Label.Sid, *GetSidSubAuthorityCount(pLabel->Label.Sid) - 1);
                    }
                }
                free(pLabel);
            }
        }
    }

    /* 提权检测（对齐 PS IsProcessElevated） */
    {
        TOKEN_ELEVATION elevation = {0};
        DWORD dwSize = 0;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            Context->IsElevated = (elevation.TokenIsElevated != 0);
        }
    }

    /* 运行时 DEP 策略（迁移自 SS PapAnalyzeSecurityMitigations L2205-2266）
     * ProcessExecuteFlags=34, MEM_EXECUTE_OPTION_DISABLE(0x1)=DEP 启用。
     * 本函数以 PROCESS_QUERY_LIMITED_INFORMATION 打开句柄，查询可能因权限
     * 不足失败（STATUS_ACCESS_DENIED），失败时保持 HasRuntimeDep=FALSE（未确认），
     * 不误报启用。文件级声明见本文件 L2384。 */
    {
        extern NTSTATUS NTAPI NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS,
                                                        PVOID, ULONG, PULONG);
        ULONG executeFlags = 0;
        ULONG retLen = 0;
        if (NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)34, &executeFlags,
                sizeof(executeFlags), &retLen) == 0) {
            Context->HasRuntimeDep = ((executeFlags & 0x1) != 0);
        }
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);
    return TRUE;
}

// ============================================================================
// PPID Spoofing 增强检测（对齐 PS DetectPPIDSpoofingImpl）
// ============================================================================

_Use_decl_annotations_
BOOL
IpeDetectPpidSpoofing(
    PWKD_PROCESS ChildNode,
    PWKD_PROCESS ParentNode
    )
{
    if (!ChildNode || !ParentNode) return FALSE;

    /*
     * PPID 欺骗时序检测：父进程创建时间晚于子进程（物理上不可能）。
     * 规则②③④（smss 直生 / 期望父名 / explorer 跨会话）已归位 IpeAnalyzeParentChild
     * ——期望父、跨会话属谱系/父子关系，非 PPID 本体，避免命名混淆。
     */
    if (ParentNode->CreateTime.QuadPart > ChildNode->CreateTime.QuadPart) {
        printf("[IpeDetectPpidSpoofing] PPID spoofing: Child PID=%lu claims parent %lu "
               "created AFTER child\n",
               (ULONG)(ULONG_PTR)ChildNode->ProcessId,
               (ULONG)(ULONG_PTR)ParentNode->ProcessId);
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// PID 复用检测（对齐 PS WasPidReused）
// ============================================================================

_Use_decl_annotations_
VOID
IpeRecordProcessExit(
    ULONG  Pid,
    PCWSTR ImagePath
    )
{
    PWKD_HISTORICAL_ENTRY entry;

    if (g_WkdHistoricalTracker.MaxEntries == 0) return;

    entry = (PWKD_HISTORICAL_ENTRY)malloc(sizeof(WKD_HISTORICAL_ENTRY));
    if (!entry) return;

    RtlZeroMemory(entry, sizeof(*entry));
    entry->Pid = Pid;
    GetSystemTimeAsFileTime((LPFILETIME)&entry->ExitTime);
    if (ImagePath) {
        wcsncpy_s(entry->ImagePath, RTL_NUMBER_OF(entry->ImagePath),
                  ImagePath, _TRUNCATE);
    }

    EnterCriticalSection(&g_WkdHistoricalTracker.Lock);

    if (g_WkdHistoricalTracker.Count >= g_WkdHistoricalTracker.MaxEntries) {
        PLIST_ENTRY old = g_WkdHistoricalTracker.EntryHead.Flink;
        RemoveEntryList(old);
        free(CONTAINING_RECORD(old, WKD_HISTORICAL_ENTRY, ListEntry));
        g_WkdHistoricalTracker.Count--;
    }

    InsertTailList(&g_WkdHistoricalTracker.EntryHead, &entry->ListEntry);
    g_WkdHistoricalTracker.Count++;

    LeaveCriticalSection(&g_WkdHistoricalTracker.Lock);
}

_Use_decl_annotations_
BOOL
IpeWasPidReused(
    ULONG  Pid,
    DWORD  WindowMs
    )
{
    PLIST_ENTRY entry;
    LARGE_INTEGER now, cutoff;

    if (g_WkdHistoricalTracker.MaxEntries == 0) return FALSE;

    GetSystemTimeAsFileTime((LPFILETIME)&now);
    cutoff.QuadPart = now.QuadPart - (LONGLONG)WindowMs * 10000;  // 100ns 单位

    EnterCriticalSection(&g_WkdHistoricalTracker.Lock);

    for (entry = g_WkdHistoricalTracker.EntryHead.Flink;
         entry != &g_WkdHistoricalTracker.EntryHead;
         entry = entry->Flink) {

        PWKD_HISTORICAL_ENTRY he = CONTAINING_RECORD(entry, WKD_HISTORICAL_ENTRY, ListEntry);
        if (he->Pid == Pid && he->ExitTime > cutoff.QuadPart) {
            LeaveCriticalSection(&g_WkdHistoricalTracker.Lock);
            return TRUE;
        }
    }

    LeaveCriticalSection(&g_WkdHistoricalTracker.Lock);
    return FALSE;
}

_Use_decl_annotations_
VOID
IpeInitHistoricalTracker(
    ULONG MaxEntries
    )
{
    RtlZeroMemory(&g_WkdHistoricalTracker, sizeof(g_WkdHistoricalTracker));
    InitializeListHead(&g_WkdHistoricalTracker.EntryHead);
    InitializeCriticalSection(&g_WkdHistoricalTracker.Lock);
    g_WkdHistoricalTracker.MaxEntries = (MaxEntries > 0) ? MaxEntries : 1024;
}

_Use_decl_annotations_
VOID
IpeCleanupHistoricalTracker(
    VOID
    )
{
    PLIST_ENTRY entry;

    EnterCriticalSection(&g_WkdHistoricalTracker.Lock);

    while (!IsListEmpty(&g_WkdHistoricalTracker.EntryHead)) {
        entry = RemoveHeadList(&g_WkdHistoricalTracker.EntryHead);
        free(CONTAINING_RECORD(entry, WKD_HISTORICAL_ENTRY, ListEntry));
    }
    g_WkdHistoricalTracker.Count = 0;

    LeaveCriticalSection(&g_WkdHistoricalTracker.Lock);
    DeleteCriticalSection(&g_WkdHistoricalTracker.Lock);
}

// ============================================================================
// 辅助: 从路径提取文件名（最后一段），返回指针指向路径内
// ============================================================================

static PCWSTR
IpepExtractFileName(
    _In_ PCWSTR FullPath
    )
{
    PCWSTR p;
    if (!FullPath || !FullPath[0]) return NULL;
    p = FullPath + wcslen(FullPath) - 1;
    while (p >= FullPath) {
        if (*p == L'\\' || *p == L'/') return p + 1;
        p--;
    }
    return FullPath;
}

// ============================================================================
// 预期父进程（对齐 PS GetExpectedParent，25 条规则）
// ============================================================================

_Use_decl_annotations_
PCWSTR
IpeGetExpectedParent(
    PCWSTR ChildProcessName
    )
{
    WCHAR lower[64];
    PCWSTR name;
    ULONG i;

    if (!ChildProcessName || !ChildProcessName[0]) return L"explorer.exe";

    name = IpepExtractFileName(ChildProcessName);
    for (i = 0; i < 63 && name[i]; i++) {
        WCHAR c = name[i];
        lower[i] = (c >= L'A' && c <= L'Z') ? (c - L'A' + L'a') : c;
    }
    lower[i] = L'\0';

    /* Office 应用 */
    if (wcscmp(lower, L"winword.exe") == 0 ||
        wcscmp(lower, L"excel.exe") == 0 ||
        wcscmp(lower, L"powerpnt.exe") == 0 ||
        wcscmp(lower, L"outlook.exe") == 0) {
        return L"explorer.exe";
    }

    /* 浏览器 */
    if (wcscmp(lower, L"chrome.exe") == 0 ||
        wcscmp(lower, L"firefox.exe") == 0 ||
        wcscmp(lower, L"msedge.exe") == 0 ||
        wcscmp(lower, L"iexplore.exe") == 0) {
        return L"explorer.exe";
    }

    /* 系统服务链 */
    if (wcscmp(lower, L"svchost.exe") == 0) return L"services.exe";
    if (wcscmp(lower, L"services.exe") == 0) return L"wininit.exe";
    if (wcscmp(lower, L"lsass.exe") == 0) return L"wininit.exe";
    if (wcscmp(lower, L"winlogon.exe") == 0) return L"smss.exe";
    if (wcscmp(lower, L"csrss.exe") == 0) return L"smss.exe";
    if (wcscmp(lower, L"smss.exe") == 0) return L"System";
    if (wcscmp(lower, L"wininit.exe") == 0) return L"smss.exe";
    if (wcscmp(lower, L"dwm.exe") == 0) return L"svchost.exe";
    if (wcscmp(lower, L"conhost.exe") == 0) return L"csrss.exe";
    if (wcscmp(lower, L"taskhostw.exe") == 0) return L"svchost.exe";
    if (wcscmp(lower, L"runtimebroker.exe") == 0) return L"svchost.exe";

    /* 用户应用默认父进程为 explorer */
    return L"explorer.exe";
}

// ============================================================================
// 父-子关系全面分析（对齐 PS AnalyzeParentChildInternal）
// ============================================================================

//
// 谱系类别判定（对齐 SS PctpIsOfficeApp/PctpIsBrowser/PctpIsShell/
//   PctpIsScriptHost/PctpIsLOLBin，ParentChainTracker.c:1862-1993）。
// 输入为已小写的文件名。属谱系/父子关系判定，不涉 PPID 欺骗语义。
//

static BOOLEAN
IpeIsOfficeApp(
    _In_ PCWSTR LowerName
    )
{
    static const PCWSTR s_Office[] = {
        L"winword.exe", L"excel.exe",   L"powerpnt.exe", L"outlook.exe",
        L"msaccess.exe", L"onenote.exe", L"mspub.exe",   L"visio.exe",
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(s_Office); i++) {
        if (wcscmp(LowerName, s_Office[i]) == 0) return TRUE;
    }
    return FALSE;
}

static BOOLEAN
IpeIsBrowser(
    _In_ PCWSTR LowerName
    )
{
    static const PCWSTR s_Browsers[] = {
        L"chrome.exe", L"firefox.exe", L"msedge.exe", L"iexplore.exe",
        L"opera.exe",  L"brave.exe",   L"vivaldi.exe",
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(s_Browsers); i++) {
        if (wcscmp(LowerName, s_Browsers[i]) == 0) return TRUE;
    }
    return FALSE;
}

static BOOLEAN
IpeIsShell(
    _In_ PCWSTR LowerName
    )
{
    static const PCWSTR s_Shells[] = {
        L"cmd.exe", L"powershell.exe", L"pwsh.exe", L"bash.exe",
        L"wscript.exe", L"cscript.exe", L"mshta.exe",
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(s_Shells); i++) {
        if (wcscmp(LowerName, s_Shells[i]) == 0) return TRUE;
    }
    return FALSE;
}

static BOOLEAN
IpeIsScriptHost(
    _In_ PCWSTR LowerName
    )
{
    static const PCWSTR s_ScriptHosts[] = {
        L"powershell.exe", L"pwsh.exe", L"cmd.exe",     L"wscript.exe",
        L"cscript.exe",    L"mshta.exe", L"wmic.exe",   L"bash.exe",
        L"python.exe",     L"python3.exe", L"perl.exe", L"ruby.exe",
        L"node.exe",
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(s_ScriptHosts); i++) {
        if (wcscmp(LowerName, s_ScriptHosts[i]) == 0) return TRUE;
    }
    return FALSE;
}

static BOOLEAN
IpeIsLolbin(
    _In_ PCWSTR LowerName
    )
{
    static const PCWSTR s_Lolbins[] = {
        L"regsvr32.exe", L"rundll32.exe", L"msiexec.exe", L"msbuild.exe",
        L"installutil.exe", L"regasm.exe", L"regsvcs.exe", L"cmstp.exe",
        L"certutil.exe", L"bitsadmin.exe", L"forfiles.exe", L"pcalua.exe",
        L"syncappvpublishingserver.exe", L"control.exe", L"presentationhost.exe",
        L"dnscmd.exe", L"infdefaultinstall.exe", L"mavinject.exe",
        L"ftp.exe", L"xwizard.exe",
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(s_Lolbins); i++) {
        if (wcscmp(LowerName, s_Lolbins[i]) == 0) return TRUE;
    }
    return FALSE;
}

_Use_decl_annotations_
VOID
IpeAnalyzeParentChild(
    PWKD_PROCESS       ChildNode,
    PWKD_PROCESS       ParentNode,
    PWKD_PARENT_CHILD_RESULT Result
    )
{
    PCWSTR expectedParent, childName, parentName;
    WCHAR childLower[64], parentLower[64];
    ULONG i;

    RtlZeroMemory(Result, sizeof(*Result));

    if (!ChildNode) return;

    childName = ChildNode->ImageFileName && ChildNode->ImageFileName->Buffer
                ? ChildNode->ImageFileName->Buffer : L"";
    parentName = ParentNode && ParentNode->ImageFileName && ParentNode->ImageFileName->Buffer
                 ? ParentNode->ImageFileName->Buffer : L"";

    for (i = 0; i < 63 && childName[i]; i++) {
        WCHAR c = childName[i];
        childLower[i] = (c >= L'A' && c <= L'Z') ? (c - L'A' + L'a') : c;
    }
    childLower[i] = L'\0';
    for (i = 0; i < 63 && parentName[i]; i++) {
        WCHAR c = parentName[i];
        parentLower[i] = (c >= L'A' && c <= L'Z') ? (c - L'A' + L'a') : c;
    }
    parentLower[i] = L'\0';

    /* 父进程不存在 */
    if (!ParentNode) {
        if ((ULONG_PTR)ChildNode->ProcessId > 4) {
            Result->Anomaly = WkdPaOrphanProcess;
            wcsncpy_s(Result->AnomalyReason, RTL_NUMBER_OF(Result->AnomalyReason),
                      L"Parent process does not exist", _TRUNCATE);
            Result->RiskScore = 20;
        }
        return;
    }

    /* 预期父进程校验 */
    expectedParent = IpeGetExpectedParent(childName);
    wcsncpy_s(Result->ExpectedParentName, RTL_NUMBER_OF(Result->ExpectedParentName),
              expectedParent, _TRUNCATE);

    {
        WCHAR expectedLower[64];
        for (i = 0; i < 63 && expectedParent[i]; i++) {
            WCHAR c = expectedParent[i];
            expectedLower[i] = (c >= L'A' && c <= L'Z') ? (c - L'A' + L'a') : c;
        }
        expectedLower[i] = L'\0';

        if (wcscmp(parentLower, expectedLower) != 0) {
            Result->IsExpectedParent = FALSE;
            Result->Anomaly = WkdPaUnexpectedParent;
            swprintf_s(Result->AnomalyReason, RTL_NUMBER_OF(Result->AnomalyReason),
                       L"Unexpected parent: %ls (expected: %ls)", parentName, expectedParent);
            Result->RiskScore = 20;
        } else {
            Result->IsExpectedParent = TRUE;
        }
    }

    /* smss 直生非系统子进程（smss 是会话管理器，不直接 spawn 用户进程）。
     * 原为 PPID 检测规则②，属谱系/父子关系（期望父特例），归位至此并提分
     * 保信号强度（20→30）。 */
    if (wcscmp(parentLower, L"smss.exe") == 0 && !ChildNode->IsSystemProcess) {
        Result->Anomaly = WkdPaSuspiciousSmssChild;
        swprintf_s(Result->AnomalyReason, RTL_NUMBER_OF(Result->AnomalyReason),
                   L"Non-system process claims smss.exe as parent");
        Result->RiskScore = 30;
    }

    /* 会话不匹配 */
    if (ChildNode->SessionId != 0 && ParentNode->SessionId != 0 &&
        ChildNode->SessionId != ParentNode->SessionId) {
        Result->Anomaly = WkdPaSessionMismatch;
        swprintf_s(Result->AnomalyReason, RTL_NUMBER_OF(Result->AnomalyReason),
                   L"Session mismatch: child session %lu vs parent session %lu",
                   ChildNode->SessionId, ParentNode->SessionId);
        Result->RiskScore = 15;
    }

    /* Office 生可疑子进程（对齐 SS PctpAnalyzeChain Office→Shell/LOLBin，
     * 类别级判定覆盖 8 款 Office 应用） */
    if (IpeIsOfficeApp(parentLower) &&
        (IpeIsShell(childLower) || IpeIsLolbin(childLower))) {
        Result->Anomaly = WkdPaSuspiciousOfficeChild;
        swprintf_s(Result->AnomalyReason, RTL_NUMBER_OF(Result->AnomalyReason),
                   L"Office spawned suspicious child: %ls", childName);
        Result->RiskScore = 30;
    }

    /* Browser 生可疑子进程（对齐 SS PctpAnalyzeChain Browser→Shell/LOLBin，
     * 类别级判定覆盖 7 款浏览器） */
    if (IpeIsBrowser(parentLower) &&
        (IpeIsShell(childLower) || IpeIsLolbin(childLower))) {
        Result->Anomaly = WkdPaSuspiciousBrowserChild;
        swprintf_s(Result->AnomalyReason, RTL_NUMBER_OF(Result->AnomalyReason),
                   L"Browser spawned suspicious child: %ls", childName);
        Result->RiskScore = 25;
    }

    /* 非系统 LOLBin 子进程（对齐 SS LOLBin 链）。门控：仅当前未命中更高
     * 优先级异常时判定（替代 last-writer-wins）。 */
    if (Result->Anomaly == WkdPaNormal &&
        IpeIsLolbin(childLower) && !ChildNode->IsSystemProcess) {
        Result->Anomaly = WkdPaSuspiciousLolbinChild;
        swprintf_s(Result->AnomalyReason, RTL_NUMBER_OF(Result->AnomalyReason),
                   L"Suspicious LOLBin child: %ls", childName);
        Result->RiskScore = 20;
    }

    /* 脚本宿主/Shell 链（对齐 SS ScriptHost→ScriptHost 链） */
    if (Result->Anomaly == WkdPaNormal &&
        IpeIsScriptHost(parentLower) && IpeIsScriptHost(childLower)) {
        Result->Anomaly = WkdPaSuspiciousScriptChain;
        swprintf_s(Result->AnomalyReason, RTL_NUMBER_OF(Result->AnomalyReason),
                   L"Script host spawned script host: %ls -> %ls", parentName, childName);
        Result->RiskScore = 15;
    }

    /* PPID Spoofing 检测（复用已有检测器） */
    if (IpeDetectPpidSpoofing(ChildNode, ParentNode)) {
        Result->IsPpidSpoofed = TRUE;
        Result->Anomaly = WkdPaUnexpectedParent;
        wcsncpy_s(Result->AnomalyReason, RTL_NUMBER_OF(Result->AnomalyReason),
                  L"PPID spoofing detected", _TRUNCATE);
        Result->RiskScore = 40;
    }
}

// ============================================================================
// DLL 侧载/搜索劫持辅助（对齐 ShadowStrike DetectSideLoadingImpl /
// DetectSearchOrderHijackImpl / DetermineTrustLevel）
// ============================================================================

/* 已知 DLL 侧载配对 (小写, 对齐 ShadowStrike g_knownSideLoadPairs) */
typedef struct _IPE_SIDE_LOAD_PAIR {
    PCWSTR Executable;      /* 可执行文件名 (小写) */
    PCWSTR DllName;         /* 被侧载 DLL 名 (小写) */
} IPE_SIDE_LOAD_PAIR;

static const IPE_SIDE_LOAD_PAIR g_IpeSideLoadPairs[] = {
    /* 浏览器 */
    { L"chrome.exe",   L"version.dll" },
    { L"chrome.exe",   L"wtsapi32.dll" },
    { L"msedge.exe",   L"version.dll" },
    { L"firefox.exe",  L"mozglue.dll" },
    /* 微软开发工具 */
    { L"msbuild.exe",  L"version.dll" },
    { L"devenv.exe",   L"version.dll" },
    /* Office */
    { L"winword.exe",  L"wwlib.dll" },
    { L"excel.exe",    L"xllex.dll" },
    { L"outlook.exe",  L"olmapi32.dll" },
    { L"powerpnt.exe", L"ppcore.dll" },
    /* 系统工具 */
    { L"explorer.exe", L"shell32.dll" },
    { L"cmd.exe",      L"cmd.dll" },
    { L"notepad.exe",  L"notepad.dll" },
    { L"control.exe",  L"version.dll" },
    { L"rundll32.exe", L"version.dll" },
    { L"mmc.exe",      L"elsext.dll" },
    { L"cmstp.exe",    L"version.dll" },
    /* 常见 APT 目标 */
    { L"vmtoolsd.exe", L"vsock.dll" },
    { L"vmnat.exe",    L"shfolder.dll" },
    { L"putty.exe",    L"winmm.dll" },
    { L"winscp.exe",   L"dui70.dll" },
    { L"7z.exe",       L"7z.dll" },
    { L"acrobat.exe",  L"acrord32.dll" },
    { L"acrord32.exe", L"rdrsefui.dll" },
    { L"winrar.exe",   L"rar.dll" },
    /* 签名脆弱加载器 (APT 滥用) */
    { L"dllhost.exe",  L"comsvcs.dll" },
    { L"svchost.exe",  L"version.dll" },
    { L"searchprotocolhost.exe", L"msfte.dll" },
    { L"consent.exe",  L"version.dll" },
};

/* 高熵阈值 (对齐 ShadowStrike HIGH_ENTROPY_THRESHOLD=7.2, Wpa 0-1000 刻度) */
#define IPE_HIGH_ENTROPY_THRESHOLD      720

/* 前向声明: 定义位于本文件后半部, 多处早于定义处调用 (C89 需原型) */
static BOOLEAN
IpepReadFileBuffer(
    _In_  PCWSTR FilePath,
    _Out_writes_(MaxSize) PBYTE Buffer,
    _In_  ULONG  MaxSize,
    _Out_ PULONG BytesRead
    );

/* 计算文件 Shannon 熵 (采样前 64KB, 对齐 ShadowStrike CalculateFileEntropy).
 * 复用 IpepReadFileBuffer + WpeCalculateEntropy。 */
static
BOOLEAN
IpepCalculateFileEntropy(
    _In_  PCWSTR FilePath,
    _Out_ PULONG Entropy
    )
{
    BYTE buffer[65536];
    ULONG read = 0;

    if (!FilePath || !Entropy) return FALSE;
    *Entropy = 0;

    if (!IpepReadFileBuffer(FilePath, buffer, sizeof(buffer), &read)) {
        return FALSE;
    }
    if (read < 256) {
        return FALSE;
    }
    *Entropy = (ULONG)(CoEntropyBinary(buffer, read, 0) * 1000.0); return S_OK;
}

/* 搜索顺序劫持: 系统 DLL 名 + 非系统目录加载 */
static
BOOLEAN
IpepIsSearchOrderHijack(
    _In_ PCWSTR ModuleName,
    _In_ BOOLEAN IsInSystemDir
    )
{
    if (IsInSystemDir) {
        return FALSE;
    }
    return WkdIsSystemDllName(ModuleName);
}

/* 侧载: 命中已知配对 && 实际加载路径 != 预期进程目录 */
static
BOOLEAN
IpepIsSideLoaded(
    _In_ PCWSTR ProcessPath,
    _In_ PCWSTR ModulePath,
    _In_ PCWSTR ModuleName
    )
{
    WCHAR exeName[64];
    WCHAR lowerModule[64];
    WCHAR procDir[260];
    WCHAR expectedPath[260];
    PCWSTR slash;
    ULONG i;

    if (!ProcessPath || !ModulePath || !ModuleName || ProcessPath[0] == L'\0') {
        return FALSE;
    }

    /* 进程 exe 名 (小写) */
    slash = wcsrchr(ProcessPath, L'\\');
    if (!slash) {
        return FALSE;
    }
    _snwprintf_s(exeName, 64, _TRUNCATE, L"%ls", slash + 1);
    for (i = 0; exeName[i]; i++) exeName[i] = (WCHAR)towlower(exeName[i]);

    /* 模块名 (小写) */
    _snwprintf_s(lowerModule, 64, _TRUNCATE, L"%ls", ModuleName);
    for (i = 0; lowerModule[i]; i++) lowerModule[i] = (WCHAR)towlower(lowerModule[i]);

    for (i = 0; i < ARRAYSIZE(g_IpeSideLoadPairs); i++) {
        if (wcscmp(exeName, g_IpeSideLoadPairs[i].Executable) == 0 &&
            wcscmp(lowerModule, g_IpeSideLoadPairs[i].DllName) == 0) {
            /* 预期路径 = 进程目录\DLL名 */
            _snwprintf_s(procDir, 260, _TRUNCATE, L"%ls", ProcessPath);
            slash = wcschr(procDir, L'\\');
            if (slash) {
                {
                    /* 从进程路径内切出目录部分 (修改副本, 非 const 输入) */
                    WCHAR* last = wcsrchr(procDir, L'\\');
                    if (last) *last = L'\0';
                }
            }
            _snwprintf_s(expectedPath, 260, _TRUNCATE,
                         L"%ls\\%ls", procDir, g_IpeSideLoadPairs[i].DllName);

            return (_wcsicmp(ModulePath, expectedPath) != 0);
        }
    }
    return FALSE;
}

/* 六层信任分级 (对齐 ShadowStrike DetermineTrustLevel 判定顺序) */
static
VOID
IpepDetermineTrustLevel(
    _Inout_ PWKD_SUSPICIOUS_MODULE Mod
    )
{
    if (Mod->Flags & WKD_SMF_KNOWN_MALICIOUS) {
        Mod->TrustLevel = WkdDllTrust_Malicious;
    } else if (Mod->IsInSystemDir && Mod->IsMicrosoftSigned) {
        Mod->TrustLevel = WkdDllTrust_System;
    } else if (Mod->Flags & (WKD_SMF_MASQUERADE | WKD_SMF_HIGH_ENTROPY |
                             WKD_SMF_SUSPICIOUS_PATH)) {
        Mod->TrustLevel = WkdDllTrust_Suspicious;
    } else if (Mod->IsMicrosoftSigned) {
        Mod->TrustLevel = WkdDllTrust_ThirdParty;
    } else {
        Mod->TrustLevel = WkdDllTrust_Untrusted;
    }
}

// ============================================================================
// 模块可疑检测（对齐 PS FindSuspiciousModulesFromList + ShadowStrike
// DetermineTrustLevel / DetectSideLoadingImpl / DetectSearchOrderHijackImpl）
// ============================================================================

_Use_decl_annotations_
ULONG
IpeFindSuspiciousModules(
    ULONG                    ProcessId,
    PWKD_SUSPICIOUS_MODULE   Modules,
    ULONG                    MaxModules,
    PULONG                   Count
    )
{
    HANDLE hSnapshot;
    ULONG found = 0;

    if (Count) *Count = 0;
    if (!Modules || MaxModules == 0) return 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W me = { sizeof(me) };
    WCHAR processPath[260] = L"";
    HANDLE hProc;

    /* 进程完整路径 (用于侧载预期路径判定) */
    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (hProc) {
        DWORD pathSize = 260;
        QueryFullProcessImageNameW(hProc, 0, processPath, &pathSize);
        CloseHandle(hProc);
    }

    if (Module32FirstW(hSnapshot, &me)) {
        do {
            if (found >= MaxModules) break;

            ULONG flags = 0;
            ULONG risk = 0;
            WCHAR lowerPath[MAX_PATH];
            WCHAR lowerName[64];
            ULONG i;
            BOOLEAN isInSystemDir = FALSE;
            BOOLEAN isMsSigned = FALSE;
            BOOLEAN hashComputed = FALSE;
            UCHAR hashBytes[DEF_SHA256_SIZE];

            /* 转小写 */
            for (i = 0; i < MAX_PATH - 1 && me.szExePath[i]; i++) {
                lowerPath[i] = (me.szExePath[i] >= L'A' && me.szExePath[i] <= L'Z')
                               ? (me.szExePath[i] - L'A' + L'a') : me.szExePath[i];
            }
            lowerPath[i] = L'\0';
            for (i = 0; i < 63 && me.szModule[i]; i++) {
                lowerName[i] = (me.szModule[i] >= L'A' && me.szModule[i] <= L'Z')
                               ? (me.szModule[i] - L'A' + L'a') : me.szModule[i];
            }
            lowerName[i] = L'\0';

            /* 可疑路径（Temp/AppData/Downloads/ProgramData/Users/Public） */
            if (wcsstr(lowerPath, L"\\temp\\") != NULL ||
                wcsstr(lowerPath, L"\\appdata\\local\\temp\\") != NULL ||
                wcsstr(lowerPath, L"\\downloads\\") != NULL ||
                wcsstr(lowerPath, L"\\programdata\\") != NULL ||
                wcsstr(lowerPath, L"\\users\\public\\") != NULL) {
                flags |= WKD_SMF_SUSPICIOUS_PATH;
                risk += 20;
            }

            /* 双扩展名（如 .pdf.dll） */
            {
                PCWSTR dot = wcschr(lowerName, L'.');
                if (dot) {
                    PCWSTR dot2 = wcschr(dot + 1, L'.');
                    if (dot2) {
                        flags |= WKD_SMF_DOUBLE_EXT;
                        risk += 15;
                    }
                }
            }

            /* 逐模块验签（对齐 PS FindSuspiciousModulesFromList）
             * 未签名 +15（对齐 RISK_WEIGHT_UNSIGNED=15）
             * 吊销   +50（对齐 RISK_WEIGHT_REVOKED_CERT=50）
             * 微软签名识别 (对齐 ShadowStrike ValidateSignature → isMicrosoftSigned) */
            {
                IOC_SCAN_RESULT sigResult;
                if (IocVerifySignature(me.szExePath, &sigResult) == STATUS_SUCCESS) {
                    if (sigResult.CertStatus == DefCertStatus_Revoked) {
                        flags |= WKD_SMF_REVOKED;
                        risk += 50;
                    } else if (sigResult.CertStatus == DefCertStatus_Unsigned) {
                        flags |= WKD_SMF_UNSIGNED;
                        risk += 15;
                    }
                    /* 微软签名统一判定 (2026-08 统一接入): 读统一入口 (VerifySignature→
                     * ReputationScore→ClassifySigner 名称+指纹双通道) 填充的 SignerCategory;
                     * 原 wcsstr 子串匹配绕过已修复。 */
                    if (IocScan_IsMicrosoftSigned(&sigResult)) {
                        isMsSigned = TRUE;
                    }
                }
            }

            /* 系统目录判定 */
            isInSystemDir = WkdIsSystemDirectory(me.szExePath);

            /* 仿冒系统 DLL 名 (对齐 ShadowStrike IsMasquerading, +50) */
            if (WkdIsMasquerading(me.szModule)) {
                flags |= WKD_SMF_MASQUERADE;
                risk += 50;
            }

            /* 高熵 (对齐 ShadowStrike HIGH_ENTROPY_THRESHOLD=7.2, +20) */
            {
                ULONG entropy = 0;
                if (IpepCalculateFileEntropy(me.szExePath, &entropy) &&
                    entropy >= IPE_HIGH_ENTROPY_THRESHOLD) {
                    flags |= WKD_SMF_HIGH_ENTROPY;
                    risk += 20;
                }
            }

            /* 哈希威胁情报 (对齐 ShadowStrike PerformHashLookup, 恶意 +100) */
            {
                DEF_SHA256_HASH hash;
                BOOLEAN foundMalicious = FALSE;

                if (IocScanner_ComputeFileSha256(me.szExePath, &hash)) {
                    hashComputed = TRUE;
                    memcpy(hashBytes, hash.Data, DEF_SHA256_SIZE);
                    if (IocScanner_QueryHash(&hash, &foundMalicious) == STATUS_SUCCESS &&
                        foundMalicious) {
                        flags |= WKD_SMF_KNOWN_MALICIOUS;
                        risk += 100;
                    }
                }
            }

            /* DLL 侧载 (对齐 ShadowStrike DetectSideLoadingImpl, +80) */
            if (IpepIsSideLoaded(processPath, me.szExePath, me.szModule)) {
                flags |= WKD_SMF_SIDE_LOAD;
                risk += 80;
            }

            /* 搜索顺序劫持 (对齐 ShadowStrike DetectSearchOrderHijackImpl, +85) */
            if (IpepIsSearchOrderHijack(me.szModule, isInSystemDir)) {
                flags |= WKD_SMF_SEARCH_ORDER;
                risk += 85;
            }

            /* 未引号路径风险 (路径含空格, 对齐 ShadowStrike pathHasSpaces) */
            if (!isInSystemDir && wcschr(me.szExePath, L' ') != NULL) {
                flags |= WKD_SMF_PATH_SPACES;
                risk += 10;
            }

            if (flags != 0) {
                wcsncpy_s(Modules[found].ModulePath,
                          sizeof(Modules[found].ModulePath) / sizeof(Modules[found].ModulePath[0]),
                          me.szExePath, _TRUNCATE);
                wcsncpy_s(Modules[found].ModuleName,
                          sizeof(Modules[found].ModuleName) / sizeof(Modules[found].ModuleName[0]),
                          me.szModule, _TRUNCATE);
                Modules[found].Flags = flags;
                Modules[found].RiskScore = min(risk, 100);
                Modules[found].IsMicrosoftSigned = isMsSigned;
                Modules[found].IsInSystemDir = isInSystemDir;
                Modules[found].HashComputed = hashComputed;
                if (hashComputed) {
                    memcpy(Modules[found].Sha256Hash, hashBytes, DEF_SHA256_SIZE);
                }
                IpepDetermineTrustLevel(&Modules[found]);
                found++;
            }

        } while (Module32NextW(hSnapshot, &me));
    }

    CloseHandle(hSnapshot);
    if (Count) *Count = found;
    return found;
}

// ============================================================================
// 单 DLL 信任级查询（对齐 ShadowStrike GetTrustLevel）
// ============================================================================

_Use_decl_annotations_
ULONG
IpeGetDllTrustLevel(
    _In_ PCWSTR DllPath
    )
/*++
Routine Description:
    单 DLL 信任级查询 (对齐 ShadowStrike GetTrustLevel)。

    基于验签 + 系统目录 + 仿冒 + 哈希, 按 IpepDetermineTrustLevel
    判定顺序 (恶意→系统→可疑→三方→未信任) 输出六层信任级。
    与 IpeFindSuspiciousModules 共享判定逻辑, 供主动查询/白名单决策使用。

Arguments:
    DllPath - DLL 完整路径。

Return Value:
    WKD_DLL_TRUST_LEVEL 值 (WkdDllTrust_Unknown=无法判定)。
--*/
{
    WKD_SUSPICIOUS_MODULE mod;
    IOC_SCAN_RESULT sigResult;
    WCHAR dllName[64];
    PCWSTR slash;
    BOOLEAN isMsSigned = FALSE;

    if (!DllPath) {
        return WkdDllTrust_Unknown;
    }
    RtlZeroMemory(&mod, sizeof(mod));

    mod.IsInSystemDir = WkdIsSystemDirectory(DllPath);

    /* 验签 + 微软签名识别 (SS PE_sig_verf 迁移收尾: 精确全串替代 wcsstr 子串) */
    if (IocVerifySignature(DllPath, &sigResult) == STATUS_SUCCESS) {
        if (sigResult.CertStatus == DefCertStatus_Revoked) {
            mod.Flags |= WKD_SMF_REVOKED;
        }
        /* 微软签名统一判定 (2026-08 统一接入: 读统一入口填充的 SignerCategory) */
        if (IocScan_IsMicrosoftSigned(&sigResult)) {
            isMsSigned = TRUE;
        }
    }
    mod.IsMicrosoftSigned = isMsSigned;

    /* 仿冒系统 DLL 名 */
    slash = wcsrchr(DllPath, L'\\');
    _snwprintf_s(dllName, ARRAYSIZE(dllName), _TRUNCATE,
                 L"%ls", slash ? (slash + 1) : DllPath);
    if (WkdIsMasquerading(dllName)) {
        mod.Flags |= WKD_SMF_MASQUERADE;
    }

    /* 哈希恶意判定 */
    {
        DEF_SHA256_HASH hash;
        BOOLEAN foundMalicious = FALSE;

        if (IocScanner_ComputeFileSha256(DllPath, &hash) &&
            IocScanner_QueryHash(&hash, &foundMalicious) == STATUS_SUCCESS &&
            foundMalicious) {
            mod.Flags |= WKD_SMF_KNOWN_MALICIOUS;
        }
    }

    IpepDetermineTrustLevel(&mod);
    return mod.TrustLevel;
}

// ============================================================================
// 模块完整性验证（对齐 PS ValidateModuleIntegrity）
// 比较内存中 PE 头与磁盘文件 PE 头是否一致。
// ============================================================================

_Use_decl_annotations_
BOOL
IpeValidateModuleIntegrity(
    ULONG     ProcessId,
    ULONG_PTR ModuleBase,
    PCWSTR    ModulePath
    )
{
    /* 手写头比对已收敛至 PEAnalyzer (WpeValidateModuleIntegrity,
     * 增强为 7 字段 WpeComparePEHeaders)。死代码: 无调用者。 */
    return WpeValidateModuleIntegrity(ProcessId, ModuleBase, ModulePath);
}

// ============================================================================
// 特权采集（对齐 PS AnalyzeSecurityContextInternal / GetProcessPrivileges）
// ============================================================================

_Use_decl_annotations_
ULONG
IpeCollectPrivileges(
    ULONG                 ProcessId,
    PWKD_PRIVILEGE_INFO   Privileges,
    ULONG                 MaxPrivs,
    PULONG                Count
    )
{
    HANDLE hProcess, hToken;
    ULONG found = 0;

    static const PCWSTR dangerousPrivs[] = {
        L"SeDebugPrivilege",
        L"SeTcbPrivilege",
        L"SeAssignPrimaryTokenPrivilege",
        L"SeLoadDriverPrivilege",
        L"SeTakeOwnershipPrivilege",
        L"SeCreateTokenPrivilege",
        L"SeBackupPrivilege",
        L"SeRestorePrivilege",
        L"SeImpersonatePrivilege",
        L"SeEnableDelegationPrivilege"
    };

    if (Count) *Count = 0;
    if (!Privileges || MaxPrivs == 0) return 0;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (!hProcess) return 0;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return 0;
    }

    /* 查询特权大小 */
    DWORD bufSize = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &bufSize);
    if (bufSize > 0 && bufSize <= 65536) {
        PTOKEN_PRIVILEGES privs = (PTOKEN_PRIVILEGES)malloc(bufSize);
        if (privs) {
            if (GetTokenInformation(hToken, TokenPrivileges, privs, bufSize, &bufSize)) {
                for (DWORD i = 0; i < privs->PrivilegeCount && found < MaxPrivs; i++) {
                    WCHAR name[64] = {0};
                    DWORD nameLen = 64;
                    if (LookupPrivilegeNameW(NULL, &privs->Privileges[i].Luid, name, &nameLen)) {
                        BOOL enabled = (privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
                        BOOL dangerous = FALSE;

                        for (int d = 0; d < RTL_NUMBER_OF(dangerousPrivs); d++) {
                            if (_wcsicmp(name, dangerousPrivs[d]) == 0) {
                                dangerous = TRUE;
                                break;
                            }
                        }

                        wcsncpy_s(Privileges[found].Name, RTL_NUMBER_OF(Privileges[found].Name),
                                  name, _TRUNCATE);
                        Privileges[found].Enabled = enabled;
                        Privileges[found].IsDangerous = dangerous;
                        found++;
                    }
                }
            }
            free(privs);
        }
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);
    if (Count) *Count = found;
    return found;
}

// ============================================================================
// 系统进程名单（对齐 PS AnalyzerConstants::SYSTEM_PROCESSES，27 条）
// ============================================================================

static PCWSTR const g_IpeSystemProcesses[] = {
    L"System", L"smss.exe", L"csrss.exe", L"wininit.exe",
    L"winlogon.exe", L"services.exe", L"lsass.exe", L"svchost.exe",
    L"fontdrvhost.exe", L"dwm.exe", L"spoolsv.exe", L"taskhost.exe",
    L"taskhostw.exe", L"sihost.exe", L"ctfmon.exe", L"conhost.exe",
    L"RuntimeBroker.exe", L"SearchIndexer.exe", L"SearchProtocolHost.exe",
    L"WmiPrvSE.exe", L"dllhost.exe", L"msiexec.exe", L"TrustedInstaller.exe",
    L"audiodg.exe", L"MsMpEng.exe", L"NisSrv.exe", L"SecurityHealthService.exe"
};

#define IPE_SYSTEM_PROCESS_COUNT (sizeof(g_IpeSystemProcesses) / sizeof(g_IpeSystemProcesses[0]))

_Use_decl_annotations_
BOOL
IpeIsSystemProcess(
    PCWSTR ProcessName
    )
/*++
Routine Description:
    判定进程名是否为已知 Windows 系统进程（精确匹配，不区分大小写）。

Arguments:
    ProcessName - 进程文件名（如 "svchost.exe"）。

Return Value:
    TRUE = 系统进程。
--*/
{
    ULONG i;

    if (!ProcessName || !ProcessName[0]) return FALSE;

    for (i = 0; i < IPE_SYSTEM_PROCESS_COUNT; i++) {
        if (_wcsicmp(ProcessName, g_IpeSystemProcesses[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

// ============================================================================
// 进程镂空检测（对齐 PS ProcessHollowingDetector::ScanProcess）
// ============================================================================

//
// 内部辅助: 记录检测方法（去重）
//
static VOID
IpepAddHollowingMethod(
    _Inout_ PWKD_HOLLOWING_RESULT Result,
    _In_    WKD_HOLLOWING_METHOD  Method
    )
{
    ULONG i;
    if (Result->DetectionMethodCount >= WKD_HOLLOWING_MAX_METHODS) return;
    for (i = 0; i < Result->DetectionMethodCount; i++) {
        if (Result->DetectionMethods[i] == (ULONG)Method) return;
    }
    Result->DetectionMethods[Result->DetectionMethodCount++] = (ULONG)Method;
}

//
// 内部辅助: 读目标进程内存
//
static BOOLEAN
IpepReadRemoteMemory(
    _In_  ULONG      ProcessId,
    _In_  ULONG_PTR  Address,
    _Out_writes_(Size) PBYTE Buffer,
    _In_  ULONG      Size,
    _Out_ PULONG     BytesRead
    )
{
    HANDLE hProcess;
    SIZE_T read = 0;
    BOOLEAN ok = FALSE;

    if (BytesRead) *BytesRead = 0;
    if (!Buffer || Size == 0) return FALSE;

    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (!hProcess) return FALSE;

    if (ReadProcessMemory(hProcess, (LPCVOID)Address, Buffer, Size, &read) && read > 0) {
        if (BytesRead) *BytesRead = (ULONG)read;
        ok = TRUE;
    }

    CloseHandle(hProcess);
    return ok;
}

//
// 内部辅助: 读磁盘文件（从头读取，上限 MaxSize）
//
static BOOLEAN
IpepReadFileBuffer(
    _In_  PCWSTR FilePath,
    _Out_writes_(MaxSize) PBYTE Buffer,
    _In_  ULONG  MaxSize,
    _Out_ PULONG BytesRead
    )
{
    HANDLE hFile;
    DWORD read = 0;
    BOOLEAN ok = FALSE;

    if (BytesRead) *BytesRead = 0;
    if (!FilePath || !Buffer || MaxSize == 0) return FALSE;

    hFile = CreateFileW(FilePath, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    if (ReadFile(hFile, Buffer, MaxSize, &read, NULL) && read > 0) {
        if (BytesRead) *BytesRead = read;
        ok = TRUE;
    }

    CloseHandle(hFile);
    return ok;
}

//
// 内部辅助: 从 PE 缓冲解析头字段 + 节表
//
static VOID
IpepParsePeBuffer(
    _In_  PBYTE Buffer,
    _In_  ULONG Size,
    _Out_ PWPA_PE_INFO PeInfo,
    _Out_writes_(MaxSections) PWKD_PE_SECTION Sections,
    _In_  ULONG MaxSections,
    _Out_ PULONG SectionCount
    )
{
    RtlZeroMemory(PeInfo, sizeof(*PeInfo));
    if (SectionCount) *SectionCount = 0;

    if (WpeAnalyzePEHeadersFromBuffer(Buffer, Size, PeInfo) != S_OK) {
        return;
    }
    if (!PeInfo->IsPE) return;

    if (Sections && SectionCount && MaxSections > 0) {
        WpeParseSectionHeaders(Buffer, Size, Sections, MaxSections, SectionCount);
    }
}

_Use_decl_annotations_
BOOL
IpeDetectProcessHollowing(
    ULONG                 ProcessId,
    WKD_MEM_SCAN_MODE     ScanMode,
    PWKD_HOLLOWING_RESULT Result
    )
/*++
Routine Description:
    进程镂空检测（对齐 PS ProcessHollowingDetector::ScanProcess + C 版
    HollowingDetector 补遗）:
    1. 主模块 PE 头 7 字段比对 (磁盘 vs 内存, 含 ASLR/Checksum 豁免)
    2. 入口点分析 (EP 节归属 / RWX / 壳码 / 实际内存保护)
    2.5 PEB 篡改检测 (ImageBase 比对 + ImagePathName 比对, 对齐 C 版 PhpAnalyzePEB)
    3. 代码节内容采样比对 (diffRatio > 10%)
    4. 无映像可执行内存 / RWX 区域 (复用 MsScanMemoryRegions)
    5. Module Stomping (非主模块内存 vs 磁盘比对)
    6. Ghosting / Herpaderping 文件状态
    7. 载荷提取 + SHA256 + IOC 关联
    8. 置信度 / 风险分 / 镂空类型判定 (含 Overwriting / Phantom, 对齐 C 版)

    创建模式向量 (Unmap+Map+Write+SetCtx / 挂起时长 / EarlyBird /
    ThreadHijack / Doppelganging) 依赖驱动补 syscall 事件源, 本次以
    死代码标注, 见 IoaInjectionClassifier::IoaClassifyFromEdges。
    Doppelganging (TxF) 激活: 驱动 WkdFspCheckTransactedAccess (Filter.c)
    + g_FsTxnList 接线 → agent 事件; 用户态近似 = 文件不存在 + 无物理
    文件判定 (FileDeletePending 已覆盖部分语义)。

    SS HollowingDetector (ShadowStrike Memory/HollowingDetector.c, 2026-08 对比)
    14 指示器 → wkd 方法映射（功能面已全覆盖，本函数为唯一落点）:
      ImagePathMismatch→PebImagePathMismatch / SectionMismatch→SectionMismatch /
      EntryPointModified→EntryPointAnomaly / HeaderModified→PEHeaderMismatch /
      UnmappedMainModule→UnbackedExecMemory(近似) / TransactedFile→WkdHt_ProcessDoppelganging
      (TxF 依赖驱动, 死代码) / DeletedFile→DeletePendingFile / SuspiciousThread→
      IpeIsSuspiciousSuspendedCreation(死代码, 依赖驱动挂起标志) / ModifiedPEB→
      PebImageBaseMismatch / HiddenMemory→UnbackedExecMemory / NoPhysicalFile→
      DeletePending+WkdHt_Phantom / HashMismatch→SectionMismatch(哈希) /
      TimestampAnomaly→FileModifiedAfterMap(Herpaderping) / MemoryProtection→
      EntropyAnomaly+SectionCharacteristics
    8 类型: Classic/SectionHollowing/ModuleStomping/Ghosting/Herpaderping/
      EarlyBird(死)/ThreadHijack(死)/Doppelganging(死,TxF)/Overwriting/Phantom
      全在 WKD_HOLLOWING_TYPE。

Arguments:
    ProcessId - 目标进程 PID。
    ScanMode  - Quick=仅头比对+EP; Normal=+节采样+ModuleStomping;
                Deep=+无映像内存。载荷提取在命中时执行 (不分档)。
    Result    - 检测结果。

Return Value:
    TRUE = 检测已执行; FALSE = 无法检测 (进程不存在/无权限/非 PE)。
--*/
{
    WPA_PE_INFO memInfo = { 0 };
    WPA_PE_INFO diskInfo = { 0 };
    WKD_PE_SECTION memSections[WKD_PE_MAX_SECTIONS];
    WKD_PE_SECTION diskSections[WKD_PE_MAX_SECTIONS];
    ULONG memSecCount = 0;
    ULONG diskSecCount = 0;
    WKD_PE_HEADER_COMPARE compare = { 0 };
    WCHAR processPath[MAX_PATH] = { 0 };
    ULONG_PTR moduleBase = 0;
    BYTE headerBuf[8192];
    ULONG headerRead = 0;
    PBYTE diskFileBuf = NULL;
    ULONG diskFileRead = 0;
    HANDLE hProcess = NULL;
    SIZE_T sizeRead = 0;
    ULONG i;

    if (Result == NULL) return FALSE;
    RtlZeroMemory(Result, sizeof(*Result));

    if (ProcessId == 0 || ProcessId == 4) return FALSE;
    if (ScanMode != WkdMemScan_Quick && ScanMode != WkdMemScan_Normal &&
        ScanMode != WkdMemScan_Deep) {
        ScanMode = WkdMemScan_Normal;
    }

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId);
    if (!hProcess) {
        wcsncpy_s(Result->ScanError, RTL_NUMBER_OF(Result->ScanError),
                  L"Cannot open process", _TRUNCATE);
        return FALSE;
    }

    /* 获取映像路径 */
    {
        DWORD pathLen = RTL_NUMBER_OF(processPath);
        if (!QueryFullProcessImageNameW(hProcess, 0, processPath, &pathLen)) {
            CloseHandle(hProcess);
            wcsncpy_s(Result->ScanError, RTL_NUMBER_OF(Result->ScanError),
                      L"Cannot query image path", _TRUNCATE);
            return FALSE;
        }
    }

    /* 获取主模块基址 (Toolhelp 第一个模块即主模块) */
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me = { sizeof(me) };
            if (Module32FirstW(hSnap, &me)) {
                moduleBase = (ULONG_PTR)me.modBaseAddr;
            }
            CloseHandle(hSnap);
        }
    }
    if (moduleBase == 0) {
        CloseHandle(hProcess);
        wcsncpy_s(Result->ScanError, RTL_NUMBER_OF(Result->ScanError),
                  L"Cannot determine module base", _TRUNCATE);
        return FALSE;
    }

    /* 读内存 PE 头 (8192 字节, 覆盖节表) + 解析 */
    if (ReadProcessMemory(hProcess, (LPCVOID)moduleBase, headerBuf,
                          sizeof(headerBuf), &sizeRead) && sizeRead >= sizeof(IMAGE_DOS_HEADER)) {
        headerRead = (ULONG)sizeRead;
    }
    if (headerRead == 0) {
        CloseHandle(hProcess);
        wcsncpy_s(Result->ScanError, RTL_NUMBER_OF(Result->ScanError),
                  L"Cannot read memory PE header", _TRUNCATE);
        return FALSE;
    }
    IpepParsePeBuffer(headerBuf, headerRead, &memInfo,
                      memSections, WKD_PE_MAX_SECTIONS, &memSecCount);
    if (!memInfo.IsPE) {
        CloseHandle(hProcess);
        wcsncpy_s(Result->ScanError, RTL_NUMBER_OF(Result->ScanError),
                  L"Memory image is not PE", _TRUNCATE);
        return FALSE;
    }

    /* 读磁盘文件 (上限 1MB, 头解析与节采样共用) + 解析 */
    diskFileBuf = (PBYTE)malloc(1024 * 1024);
    if (diskFileBuf) {
        if (IpepReadFileBuffer(processPath, diskFileBuf, 1024 * 1024, &diskFileRead) &&
            diskFileRead > 0) {
            IpepParsePeBuffer(diskFileBuf, diskFileRead, &diskInfo,
                              diskSections, WKD_PE_MAX_SECTIONS, &diskSecCount);
        }
        /* 文件不可读时磁盘 PE 无效, 由步骤 6 统一做 Ghosting 文件状态判定 */
    }

    /* 1. 头 7 字段比对 */
    if (diskInfo.IsPE) {
        WpeComparePEHeaders(&diskInfo, &memInfo, &compare);
        Result->MismatchCount = compare.MismatchCount;
        Result->OverallSimilarity = compare.OverallSimilarity;
        if (!compare.HeadersMatch) {
            IpepAddHollowingMethod(Result, WkdHm_PEHeaderMismatch);
            Result->IsHollowed = TRUE;
        }
    }

    /* 2. 入口点分析 (EP 节归属 / RWX / 壳码) */
    {
        ULONG epRva = memInfo.EntryPoint;
        if (epRva != 0 && diskInfo.IsPE) {
            BOOLEAN epFound = FALSE;
            BOOLEAN epExec = FALSE;
            BOOLEAN epWx = FALSE;

            for (i = 0; i < diskSecCount; i++) {
                ULONG64 secStart = diskSections[i].VirtualAddress;
                ULONG64 secEnd = secStart +
                    max(diskSections[i].VirtualSize, diskSections[i].SizeOfRawData);
                if ((ULONG64)epRva >= secStart && (ULONG64)epRva < secEnd) {
                    epFound = TRUE;
                    epExec = diskSections[i].IsExecutable || diskSections[i].ContainsCode;
                    epWx = diskSections[i].IsWritable && diskSections[i].IsExecutable;
                    break;
                }
            }

            /* EP 落在节外 / RWX 节 / 非可执行节 → 异常 (对齐 PS, 均置 IsHollowed) */
            if (!epFound || epWx || !epExec) {
                IpepAddHollowingMethod(Result, WkdHm_EntryPointAnomaly);
                Result->IsHollowed = TRUE;
            }
        }

        /* EP 起始字节壳码判定 (对齐 PS AnalyzeEntryPoint) */
        if (epRva != 0) {
            BYTE epBytes[64];
            ULONG epRead = 0;
            if (IpepReadRemoteMemory(ProcessId, moduleBase + epRva,
                                     epBytes, sizeof(epBytes), &epRead) && epRead >= 2) {
                if (T1DetectShellcodePatterns(epBytes, epRead)) {
                    Result->HasShellcodeAtEntryPoint = TRUE;
                    IpepAddHollowingMethod(Result, WkdHm_EntryPointAnomaly);
                    Result->IsHollowed = TRUE;
                }
            }
        }

        /* EP 实际内存保护检查 (对齐 C 版 PhpAnalyzeEntryPoint 的 ZwQueryVirtualMemory 分支):
           节归属判断基于磁盘节特性, 攻击者把内存节改 RWX 而磁盘节正常时漏检;
           此处直接查 EP 地址运行时保护捕获盲区。 */
        if (epRva != 0) {
            MEMORY_BASIC_INFORMATION epMbi = { 0 };
            if (VirtualQueryEx(hProcess, (LPCVOID)(moduleBase + epRva),
                               &epMbi, sizeof(epMbi)) && epMbi.State == MEM_COMMIT) {
                BOOLEAN epMemExec = (epMbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                BOOLEAN epMemWx  = (epMbi.Protect & PAGE_EXECUTE_READWRITE) != 0;
                if (!epMemExec || epMemWx) {
                    IpepAddHollowingMethod(Result, WkdHm_EntryPointAnomaly);
                    Result->IsHollowed = TRUE;
                }
            }
        }
    }

    /* 2.5 PEB 篡改检测 (对齐 C 版 HollowingDetector PhpAnalyzePEB):
       ① PEB.ImageBaseAddress vs 主模块基址 (Toolhelp) — 捕获 PEB 声称基址被改;
       ② PEB.ProcessParameters.ImagePathName vs 实际路径 — 捕获 PEB 声称路径被改。
       PEB 读取失败 (受限权限/进程退出) 静默跳过, 不影响其余步骤 (对齐 C 版非致命继续)。 */
    {
        PROCESS_BASIC_INFORMATION pbi = { 0 };
        ULONG retLen = 0;
        if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi,
                                      sizeof(pbi), &retLen) == 0 && pbi.PebBaseAddress != NULL) {
            IPE_PEB64 peb = { 0 };
            ULONG pebRead = 0;
            if (IpepReadRemoteMemory(ProcessId, (ULONG_PTR)pbi.PebBaseAddress,
                                     (PBYTE)&peb, sizeof(peb), &pebRead) &&
                pebRead >= sizeof(peb)) {
                /* ① ImageBase 比对: PEB 声称基址 vs Toolhelp 主模块基址 */
                if (peb.ImageBaseAddress != NULL &&
                    (ULONG_PTR)peb.ImageBaseAddress != moduleBase) {
                    Result->PebImageBaseModified = TRUE;
                    IpepAddHollowingMethod(Result, WkdHm_PebImageBaseMismatch);
                    Result->IsHollowed = TRUE;
                }

                /* ② ImagePathName 比对: 读 PEB.ProcessParameters.ImagePathName vs processPath */
                if (peb.ProcessParameters != NULL) {
                    IPE_PROCESS_PARAMETERS64 params = { 0 };
                    ULONG paramsRead = 0;
                    if (IpepReadRemoteMemory(ProcessId, (ULONG_PTR)peb.ProcessParameters,
                                             (PBYTE)&params, sizeof(params), &paramsRead) &&
                        paramsRead >= sizeof(params)) {
                        ULONG_PTR imgBuf = (ULONG_PTR)params.ImagePathName.Buffer;
                        USHORT     imgLen = params.ImagePathName.Length;
                        /* 地址合法性: 用户态 + 长度合理 (对齐 C 版 H-6 fix) */
                        if (imgBuf >= 0x10000 && imgBuf < 0x00007FFFFFFFFFFFULL &&
                            imgLen > 0 && imgLen < MAX_PATH * sizeof(WCHAR)) {
                            WCHAR pebPath[MAX_PATH] = { 0 };
                            ULONG pathRead = 0;
                            if (IpepReadRemoteMemory(ProcessId, imgBuf,
                                                     (PBYTE)pebPath, imgLen, &pathRead) &&
                                pathRead > 0) {
                                pebPath[pathRead / sizeof(WCHAR)] = L'\0';
                                if (_wcsicmp(pebPath, processPath) != 0) {
                                    Result->PebImagePathMismatch = TRUE;
                                    IpepAddHollowingMethod(Result, WkdHm_PebImagePathMismatch);
                                    Result->IsHollowed = TRUE;
                                }
                            }
                        }
                    }
                }
            }
            /* WoW64 (32 位) PEB: IPE_PEB32.ImageBaseAddress @0x08 可比对基址;
               32 位 ImagePathName 需 x86 RTL_USER_PROCESS_PARAMETERS @0x38 (UNICODE_STRING32),
               IPE_PROCESS_PARAMETERS32 未定义该字段 — 32 位镂空少见, 路径比对死代码标注。 */
        }
    }

    /* 线程起始地址检查 (对齐 PS AnalyzeEntryPoint 主线程无支撑 RWX 检查, L2103-2132) */
    if (ScanMode >= WkdMemScan_Normal) {
        WKD_THREAD_PROFILE tprof = { 0 };
        if (WptAnalyzeThreads(ProcessId, &tprof) == STATUS_SUCCESS &&
            tprof.UnbackedStartCount > 0) {
            for (i = 0; i < tprof.AnalyzedCount; i++) {
                MEMORY_BASIC_INFORMATION mbi = { 0 };
                if (tprof.Threads[i].IsStartAddressBacked ||
                    tprof.Threads[i].StartAddress == 0) {
                    continue;
                }
                /* 精确判定: 起始地址落在无支撑 RWX 私有内存 (对齐 PS 条件) */
                if (VirtualQueryEx(hProcess, (LPCVOID)tprof.Threads[i].StartAddress,
                                   &mbi, sizeof(mbi)) &&
                    mbi.State == MEM_COMMIT &&
                    (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0 &&
                    (mbi.Type == 0 || mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED)) {
                    IpepAddHollowingMethod(Result, WkdHm_ThreadContextAnomaly);
                    Result->IsHollowed = TRUE;
                }
            }
        }
    }

    /* 3. 代码节内容采样比对 (Normal+) */
    if (ScanMode >= WkdMemScan_Normal && diskInfo.IsPE && memInfo.IsPE) {
        ULONG minSec = min(diskSecCount, memSecCount);
        for (i = 0; i < minSec; i++) {
            const WKD_PE_SECTION* ds = &diskSections[i];
            const WKD_PE_SECTION* ms = &memSections[i];

            /* 节特性变化 */
            if (ds->Characteristics != ms->Characteristics) {
                IpepAddHollowingMethod(Result, WkdHm_SectionCharacteristics);
            }

            /* 仅代码/可执行节采样比对 */
            if ((ds->ContainsCode || ds->IsExecutable) && ds->PointerToRawData > 0) {
                ULONG sampleSize = min(4096UL, min(ds->VirtualSize, ms->VirtualSize));
                if (sampleSize > 0) {
                    BYTE memSample[4096];
                    BYTE diskSample[4096];
                    ULONG memRead = 0;

                    /* 内存节采样 */
                    if (IpepReadRemoteMemory(ProcessId, moduleBase + ms->VirtualAddress,
                                             memSample, sampleSize, &memRead) && memRead > 0) {
                        /* 节熵 (对齐 PS EntropyAnomaly) */
                        ULONG entropy = 0;
                        entropy = (ULONG)(CoEntropyBinary(memSample, memRead, 0) * 1000.0);
                        if (
                            entropy >= WPA_ENTROPY_THRESHOLD_PACKED) {
                            IpepAddHollowingMethod(Result, WkdHm_EntropyAnomaly);
                        }

                        /* 磁盘节采样 (从已读文件缓冲按 PointerToRawData 偏移取) */
                        if (diskFileBuf && diskFileRead > ds->PointerToRawData) {
                            ULONG diskLen = min(memRead, min(ds->SizeOfRawData,
                                              diskFileRead - ds->PointerToRawData));
                            ULONG diff = 0;
                            ULONG b;
                            if (diskLen > 0) {
                                memcpy(diskSample, diskFileBuf + ds->PointerToRawData, diskLen);
                                for (b = 0; b < min(memRead, diskLen); b++) {
                                    if (memSample[b] != diskSample[b]) diff++;
                                }
                                if (min(memRead, diskLen) > 0 &&
                                    ((double)diff / (double)min(memRead, diskLen)) > 0.1) {
                                    IpepAddHollowingMethod(Result, WkdHm_SectionMismatch);
                                    Result->IsHollowed = TRUE;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /* 4. 无映像可执行内存 / RWX (Deep+, 复用 MsScanMemoryRegions) */
    if (ScanMode >= WkdMemScan_Deep) {
        WKD_MEMORY_REGION regions[64];
        ULONG regCount = 0;
        if (MsScanMemoryRegions(ProcessId, regions, RTL_NUMBER_OF(regions), &regCount)) {
            for (i = 0; i < regCount; i++) {
                if (regions[i].IsUnbackedExec) {
                    Result->HasUnbackedExec = TRUE;
                    IpepAddHollowingMethod(Result, WkdHm_UnbackedExecMemory);
                }
                if (regions[i].IsRwx) {
                    Result->HasRwx = TRUE;
                }
            }
        }
    }

    /* 5. Module Stomping (Normal+, 非主模块内存 vs 磁盘比对) */
    if (ScanMode >= WkdMemScan_Normal) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me = { sizeof(me) };
            if (Module32FirstW(hSnap, &me)) {
                do {
                    BYTE memBuf[4096];
                    BYTE diskBuf[4096];
                    ULONG memRead = 0;
                    ULONG diskRead = 0;
                    ULONG_PTR modBase = (ULONG_PTR)me.modBaseAddr;
                    PIMAGE_DOS_HEADER dm;
                    PIMAGE_DOS_HEADER dd;

                    if (modBase == moduleBase || modBase == 0) continue;

                    if (IpepReadRemoteMemory(ProcessId, modBase, memBuf, sizeof(memBuf), &memRead) &&
                        memRead >= sizeof(IMAGE_DOS_HEADER) &&
                        IpepReadFileBuffer(me.szExePath, diskBuf, sizeof(diskBuf), &diskRead) &&
                        diskRead >= sizeof(IMAGE_DOS_HEADER)) {

                        dm = (PIMAGE_DOS_HEADER)memBuf;
                        dd = (PIMAGE_DOS_HEADER)diskBuf;
                        if (dm->e_magic == IMAGE_DOS_SIGNATURE && dd->e_magic == IMAGE_DOS_SIGNATURE &&
                            dm->e_lfanew == dd->e_lfanew) {
                            SIZE_T off = (SIZE_T)dm->e_lfanew;
                            if (off + sizeof(IMAGE_NT_HEADERS64) <= memRead &&
                                off + sizeof(IMAGE_NT_HEADERS64) <= diskRead) {
                                PIMAGE_NT_HEADERS nm = (PIMAGE_NT_HEADERS)(memBuf + off);
                                PIMAGE_NT_HEADERS nd = (PIMAGE_NT_HEADERS)(diskBuf + off);
                                if (nm->Signature == IMAGE_NT_SIGNATURE && nd->Signature == IMAGE_NT_SIGNATURE) {
                                    /* 入口点或节数不一致 → 模块被替换 */
                                    if (nm->OptionalHeader.AddressOfEntryPoint !=
                                            nd->OptionalHeader.AddressOfEntryPoint ||
                                        nm->FileHeader.NumberOfSections !=
                                            nd->FileHeader.NumberOfSections) {
                                        Result->ModuleStompingDetected = TRUE;
                                        IpepAddHollowingMethod(Result, WkdHm_SectionMismatch);
                                        Result->IsHollowed = TRUE;
                                    }
                                }
                            }
                        }
                    }
                } while (Module32NextW(hSnap, &me));
            }
            CloseHandle(hSnap);
        }
    }

    /* 6. 文件状态 (Ghosting / Herpaderping, 无条件检查对齐 PS) */
    if (GetFileAttributesW(processPath) == INVALID_FILE_ATTRIBUTES &&
        GetLastError() == ERROR_FILE_NOT_FOUND) {
        Result->FileDeletePending = TRUE;
        IpepAddHollowingMethod(Result, WkdHm_DeletePendingFile);
        Result->IsHollowed = TRUE;
    } else {
        HANDLE hf = CreateFileW(processPath, FILE_READ_ATTRIBUTES,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            FILE_STANDARD_INFO info = { 0 };
            if (GetFileInformationByHandleEx(hf, FileStandardInfo, &info, sizeof(info)) &&
                info.DeletePending) {
                Result->FileDeletePending = TRUE;
                IpepAddHollowingMethod(Result, WkdHm_DeletePendingFile);
                Result->IsHollowed = TRUE;
            }
            CloseHandle(hf);
        }
    }
    /* Herpaderping: 磁盘时间戳 != 内存时间戳 (磁盘在映射后被修改) */
    if (diskInfo.IsPE && memInfo.IsPE &&
        diskInfo.TimeDateStamp != memInfo.TimeDateStamp) {
        Result->FileModifiedAfterMap = TRUE;
    }

    /* 7. 载荷提取 + SHA256 + IOC 关联 (命中时, 复用 MsReadMemory) */
    if (Result->IsHollowed && memInfo.ImageSize > 0) {
        ULONG extractSize = min(memInfo.ImageSize, 1024 * 1024UL);
        PBYTE payload = NULL;
        ULONG payRead = 0;
        if (MsReadMemory(ProcessId, moduleBase, extractSize, &payload, &payRead) ==
                STATUS_SUCCESS && payRead > 0) {
            DEF_SHA256_HASH hash = { 0 };
            if (IocScanner_ComputeBufferSha256(payload, payRead, &hash)) {
                Result->PayloadHash = hash;
                Result->PayloadHashValid = TRUE;
                {
                    BOOLEAN found = FALSE;
                    if (IocScanner_QueryHash(&hash, &found) == STATUS_SUCCESS && found) {
                        Result->CorrelatedWithKnownThreat = TRUE;
                    }
                }
            }
            free(payload);
        }
    }

    /* 8. 置信度 (对齐 PS CalculateConfidence: 检测法去重加权) */
    {
        ULONG score = 0;
        for (i = 0; i < Result->DetectionMethodCount; i++) {
            switch (Result->DetectionMethods[i]) {
                case WkdHm_PEHeaderMismatch:      score += 3; break;
                case WkdHm_SectionMismatch:       score += 3; break;
                case WkdHm_DeletePendingFile:     score += 3; break;
                case WkdHm_EntryPointAnomaly:     score += 2; break;
                case WkdHm_ThreadContextAnomaly:  score += 2; break;
                case WkdHm_UnbackedExecMemory:    score += 2; break;
                case WkdHm_PebImageBaseMismatch:  score += 2; break;   /* 对齐 C 版 ModifiedPEB=30 */
                case WkdHm_PebImagePathMismatch:  score += 2; break;   /* 对齐 C 版 ImagePathMismatch=25 */
                case WkdHm_SectionCharacteristics: score += 1; break;
                case WkdHm_EntropyAnomaly:        score += 1; break;
                default: break;
            }
        }
        if (score >= 6) {
            Result->Confidence = 90;        /* Confirmed */
        } else if (score >= 4) {
            Result->Confidence = 70;        /* High */
        } else if (score >= 2) {
            Result->Confidence = 50;        /* Medium */
        } else if (score >= 1) {
            Result->Confidence = 30;        /* Low */
        }
    }

    /* 风险分 (对齐 PS CalculateRiskScore, 封顶 100) */
    {
        ULONG risk = 0;
        switch (Result->Confidence) {
            case 90: risk = 90; break;
            case 70: risk = 70; break;
            case 50: risk = 50; break;
            case 30: risk = 30; break;
            default: risk = 0; break;
        }
        if (Result->HasUnbackedExec) risk += 5;
        if (Result->HasRwx) risk += 5;
        if (Result->HasShellcodeAtEntryPoint) risk += 10;
        if (Result->ModuleStompingDetected) risk += 10;
        if (Result->CorrelatedWithKnownThreat) risk += 10;
        Result->RiskScore = min(risk, 100);
    }

    /* 镂空类型判定 (对齐 PS; EarlyBird/ThreadHijack/Doppelganging 依赖事件源) */
    if (Result->IsHollowed) {
        BOOLEAN hasHeaderMismatch = FALSE;
        BOOLEAN hasSectionMismatch = FALSE;
        BOOLEAN hasEpAnomaly = FALSE;

        for (i = 0; i < Result->DetectionMethodCount; i++) {
            if (Result->DetectionMethods[i] == WkdHm_PEHeaderMismatch) hasHeaderMismatch = TRUE;
            if (Result->DetectionMethods[i] == WkdHm_SectionMismatch) hasSectionMismatch = TRUE;
            if (Result->DetectionMethods[i] == WkdHm_EntryPointAnomaly) hasEpAnomaly = TRUE;
        }

        if (Result->FileDeletePending) {
            Result->Type = WkdHt_ProcessGhosting;
        } else if (Result->FileModifiedAfterMap) {
            Result->Type = WkdHt_ProcessHerpaderping;
        } else if (Result->ModuleStompingDetected) {
            Result->Type = WkdHt_ModuleStomping;
        } else if (hasHeaderMismatch && hasSectionMismatch && !hasEpAnomaly) {
            /* RunPE 覆写: 头+节整体替换但 EP 仍有效 (对齐 C 版 Overwriting) */
            Result->Type = WkdHt_Overwriting;
        } else if (!diskInfo.IsPE && Result->HasUnbackedExec) {
            /* 无物理文件 + 隐藏可执行内存 (对齐 C 版 Phantom) */
            Result->Type = WkdHt_Phantom;
        } else {
            Result->Type = WkdHt_ClassicHollowing;
        }
    }

    if (diskFileBuf) free(diskFileBuf);
    CloseHandle(hProcess);
    return TRUE;
}

//
// 挂起创建模式判定 (对齐 PS AnalyzeCreationPattern 挂起时长部分, L2203-2229)
// ★ 死代码: 依赖驱动补「进程以 CREATE_SUSPENDED 创建」线格式字段 +
//   NtResumeThread 事件源 (当前均无, 见 IoaInjectionClassifier.h 数据源依赖)。
//   事件驱动创建模式 (Unmap+Map+Write+SetCtx 序列) 已由
//   IoaClassifyFromEdges 死分支覆盖, 本函数补充「挂起时长」维度。
//
_Use_decl_annotations_
BOOLEAN
IpeIsSuspiciousSuspendedCreation(
    BOOLEAN CreatedSuspended,
    BOOLEAN HasResumed,
    LONGLONG CreatedTick,
    LONGLONG ResumedTick,
    LONGLONG CurrentTick
    )
/*++
Routine Description:
    依据进程挂起创建/恢复时间判定可疑模式:
      - 已恢复且挂起时长在 (100ms, 5000ms) → 自动化特征 (对齐 PS MIN/MAX_CREATION_TO_RESUME)
      - 未恢复且挂起超过 5000ms → 注入进行中
    ★ 死代码: 激活需驱动补源 (创建挂起标志 + NtResumeThread), 当前无调用者。

Arguments:
    CreatedSuspended - 进程是否以挂起方式创建。
    HasResumed       - 是否已恢复。
    CreatedTick      - 创建时刻 (100ns 单位, FILETIME)。
    ResumedTick      - 恢复时刻 (100ns 单位), 未恢复传 0。
    CurrentTick      - 当前时刻 (100ns 单位)。

Return Value:
    TRUE = 挂起时长可疑。
--*/
{
    const LONGLONG MinSuspendedMs = 100;
    const LONGLONG MaxSuspendedMs = 5000;
    LONGLONG elapsedMs;

    if (!CreatedSuspended) return FALSE;

    if (HasResumed && ResumedTick > CreatedTick) {
        elapsedMs = (ResumedTick - CreatedTick) / 10000;
        if (elapsedMs > MinSuspendedMs && elapsedMs < MaxSuspendedMs) {
            return TRUE;
        }
    } else {
        elapsedMs = (CurrentTick - CreatedTick) / 10000;
        if (elapsedMs > MaxSuspendedMs) {
            return TRUE;
        }
    }

    return FALSE;
}

//
// 镂空类型 → 名称 (对齐 PS GetHollowingTypeName)
//
_Use_decl_annotations_
PCWSTR
IpeHollowingTypeToString(
    WKD_HOLLOWING_TYPE Type
    )
{
    switch (Type) {
        case WkdHt_ClassicHollowing:     return L"Classic Hollowing";
        case WkdHt_SectionHollowing:     return L"Section Hollowing";
        case WkdHt_ModuleStomping:       return L"Module Stomping";
        case WkdHt_ProcessGhosting:      return L"Process Ghosting";
        case WkdHt_ProcessHerpaderping:  return L"Process Herpaderping";
        case WkdHt_EarlyBird:            return L"Early Bird";
        case WkdHt_ThreadHijack:         return L"Thread Hijack";
        case WkdHt_ProcessDoppelganging: return L"Process Doppelganging";
        case WkdHt_Overwriting:          return L"Process Overwriting";
        case WkdHt_Phantom:              return L"Phantom DLL Hollowing";
        default: return L"Unknown";
    }
}

//
// 检测方法 → 名称 (对齐 PS GetDetectionMethodName)
//
_Use_decl_annotations_
PCWSTR
IpeHollowingMethodToString(
    WKD_HOLLOWING_METHOD Method
    )
{
    switch (Method) {
        case WkdHm_PEHeaderMismatch:        return L"PE Header Mismatch";
        case WkdHm_EntryPointAnomaly:       return L"Entry Point Anomaly";
        case WkdHm_SectionMismatch:         return L"Section Mismatch";
        case WkdHm_SectionCharacteristics:  return L"Section Characteristics";
        case WkdHm_ImageBaseAnomaly:        return L"ImageBase Anomaly";
        case WkdHm_ChecksumMismatch:        return L"Checksum Mismatch";
        case WkdHm_TimestampMismatch:       return L"Timestamp Mismatch";
        case WkdHm_SizeOfImageMismatch:     return L"SizeOfImage Mismatch";
        case WkdHm_UnbackedExecMemory:      return L"Unbacked Executable Memory";
        case WkdHm_ThreadContextAnomaly:    return L"Thread Context Anomaly";
        case WkdHm_CreationPatternAnomaly:  return L"Creation Pattern Anomaly";
        case WkdHm_PebImageBaseMismatch:    return L"PEB Image Base Mismatch";
        case WkdHm_PebImagePathMismatch:    return L"PEB Image Path Mismatch";
        case WkdHm_DeletePendingFile:       return L"Delete Pending File";
        case WkdHm_EntropyAnomaly:          return L"Entropy Anomaly";
        default: return L"Unknown";
    }
}

//
// 校验 PE 头有效性 (对齐 PS ValidatePEHeader)
//
_Use_decl_annotations_
BOOLEAN
IpeValidatePeHeader(
    PWPA_PE_INFO PeInfo
    )
{
    return PeInfo != NULL && PeInfo->IsPE &&
           PeInfo->NumberOfSections > 0 &&
           PeInfo->NumberOfSections <= WKD_PE_MAX_SECTIONS;
}

//
// 校验映像基址 (对齐 PS ValidateImageBase)
//
_Use_decl_annotations_
BOOLEAN
IpeValidateImageBase(
    ULONG      ProcessId,
    ULONG_PTR  ModuleBase,
    PCWSTR     ProcessPath
    )
/*++
Routine Description:
    校验进程映像加载基址:
      - 非 ASLR 二进制加载于非预期基址 → 异常
      - 内存 EP 与磁盘 EP 不一致 → 异常
    ASLR 二进制基址偏移属正常, 不判异常。

Arguments:
    ProcessId  - 目标进程 PID。
    ModuleBase - 映像加载基址。
    ProcessPath- 磁盘映像路径。

Return Value:
    TRUE = 基址正常或无法校验; FALSE = 基址/EP 异常。
--*/
{
    WPA_PE_INFO memInfo = { 0 };
    WPA_PE_INFO diskInfo = { 0 };
    BYTE headerBuf[8192];
    BYTE diskBuf[8192];
    ULONG headerRead = 0;
    ULONG diskRead = 0;

    if (ModuleBase == 0 || !ProcessPath || !ProcessPath[0]) return TRUE;

    /* 读内存 PE */
    if (!IpepReadRemoteMemory(ProcessId, ModuleBase, headerBuf, sizeof(headerBuf), &headerRead) ||
        headerRead < sizeof(IMAGE_DOS_HEADER)) {
        return TRUE;   /* 无法读取, 保守 */
    }
    if (WpeAnalyzePEHeadersFromBuffer(headerBuf, headerRead, &memInfo) != S_OK ||
        !memInfo.IsPE) {
        return FALSE;  /* 基址处不是 PE → 可疑 */
    }

    /* 读磁盘 PE */
    if (!IpepReadFileBuffer(ProcessPath, diskBuf, sizeof(diskBuf), &diskRead) ||
        diskRead < sizeof(IMAGE_DOS_HEADER)) {
        return TRUE;
    }
    if (WpeAnalyzePEHeadersFromBuffer(diskBuf, diskRead, &diskInfo) != S_OK ||
        !diskInfo.IsPE) {
        return TRUE;
    }

    /* 非 ASLR 且基址不匹配 → 异常 */
    if ((diskInfo.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0 &&
        diskInfo.ImageBase != ModuleBase) {
        return FALSE;
    }

    /* 入口点不一致 → 异常 */
    if (diskInfo.EntryPoint != memInfo.EntryPoint) {
        return FALSE;
    }

    return TRUE;
}

//
// 提取进程主模块载荷 (对齐 PS ExtractPayload, 上限 1MB)
//
_Use_decl_annotations_
BOOLEAN
IpeExtractPayload(
    ULONG    ProcessId,
    PBYTE*   OutBuffer,
    PULONG   OutSize
    )
/*++
Routine Description:
    提取进程主模块完整载荷 (ImageSize 字节, 上限 1MB), 供取证/哈希复用。
    对齐 PS ExtractPayload (ProcessHollowingDetector.cpp L2529)。

Arguments:
    ProcessId  - 目标进程 PID。
    OutBuffer  - 输出堆缓冲, 调用方 free()。
    OutSize    - 实际读取字节数。

Return Value:
    TRUE = 成功。
--*/
{
    ULONG_PTR moduleBase = 0;
    BYTE headerBuf[8192];
    ULONG headerRead = 0;
    WPA_PE_INFO memInfo = { 0 };
    PBYTE buf = NULL;
    ULONG got = 0;

    if (!OutBuffer || !OutSize) return FALSE;
    *OutBuffer = NULL;
    *OutSize = 0;

    /* 主模块基址 (Toolhelp 第一个模块) */
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me = { sizeof(me) };
            if (Module32FirstW(hSnap, &me)) {
                moduleBase = (ULONG_PTR)me.modBaseAddr;
            }
            CloseHandle(hSnap);
        }
    }
    if (moduleBase == 0) return FALSE;

    /* 读内存 PE 头拿 ImageSize */
    if (!IpepReadRemoteMemory(ProcessId, moduleBase, headerBuf, sizeof(headerBuf), &headerRead) ||
        headerRead < sizeof(IMAGE_DOS_HEADER)) {
        return FALSE;
    }
    if (WpeAnalyzePEHeadersFromBuffer(headerBuf, headerRead, &memInfo) != S_OK ||
        !memInfo.IsPE || memInfo.ImageSize == 0) {
        return FALSE;
    }

    /* 提取 (复用 MsReadMemory) */
    {
        ULONG size = min(memInfo.ImageSize, 1024 * 1024UL);
        if (MsReadMemory(ProcessId, moduleBase, size, &buf, &got) != STATUS_SUCCESS || got == 0) {
            if (buf) free(buf);
            return FALSE;
        }
    }

    *OutBuffer = buf;
    *OutSize = got;
    return TRUE;
}

#pragma warning(push)
#pragma warning(disable:4505)  /* 死代码 static, 激活条件见下方注释 */
//
// 内部辅助: 整体内存镜像 vs 磁盘文件 64KB 比对 + 双 SHA256
// (对齐 C 版 HollowingDetector PhpCompareMemoryWithFile, L2395-2611)
// ★ 死代码: 成本高 (每进程 64KB 内存 + 64KB 磁盘读 + 双 SHA256), 与
//   IpeDetectProcessHollowing 现有节采样 (4096B/节) + 头比对重叠。
//   激活条件 = Deep 扫描门控或 ScanProcess 接线后按需调用。
//   语义对齐 C 版: 不一致 → *Match=FALSE (HashMismatch + SectionMismatch,
//   wkd 复用 WkdHm_SectionMismatch, 不新增方法枚举)。
//
_Use_decl_annotations_
static BOOLEAN
IpepCompareFullImageWithFile(
    _In_  ULONG      ProcessId,
    _In_  ULONG_PTR  ModuleBase,
    _In_  PCWSTR     FilePath,
    _Out_ PBOOLEAN   Match,
    _Out_opt_ PULONG MismatchOffset,
    _Out_opt_ PDEF_SHA256_HASH MemoryHash,
    _Out_opt_ PDEF_SHA256_HASH FileHash
    )
/*++
Routine Description:
    读目标进程主模块前 64KB (对齐 C 版 PH_MAX_SECTION_COMPARE) 与磁盘文件前
    64KB, 逐字节比对 (memcmp) 并计算双方 SHA256。与 C 版一致, 磁盘读不足
    64KB 时以实际读到的字节数为准 (对齐 C 版 CWE-393 防护, 防稀疏/截断
    文件伪造哈希不匹配)。读失败 (进程退出/权限) 返回 FALSE 不判定。

Arguments:
    ProcessId      - 目标进程 PID。
    ModuleBase     - 主模块内存基址。
    FilePath       - 磁盘文件路径。
    Match          - 输出: 内存与磁盘 64KB 是否一致。
    MismatchOffset - 可选: 首个不一致字节偏移。
    MemoryHash     - 可选: 内存前 64KB SHA256。
    FileHash       - 可选: 磁盘前 64KB SHA256。

Return Value:
    TRUE = 比对执行; FALSE = 无法读取内存或磁盘。
--*/
{
    const ULONG CompareSize = 64 * 1024;
    PBYTE memBuf = NULL;
    PBYTE fileBuf = NULL;
    ULONG memRead = 0;
    ULONG fileRead = 0;
    ULONG compareLen;
    ULONG i;
    BOOLEAN ok = FALSE;

    if (Match == NULL) return FALSE;
    *Match = FALSE;
    if (MismatchOffset) *MismatchOffset = 0;

    memBuf = (PBYTE)malloc(CompareSize);
    fileBuf = (PBYTE)malloc(CompareSize);
    if (memBuf == NULL || fileBuf == NULL) {
        goto Cleanup;
    }

    if (!IpepReadRemoteMemory(ProcessId, ModuleBase, memBuf, CompareSize, &memRead) ||
        memRead < CompareSize) {
        goto Cleanup;
    }
    if (!IpepReadFileBuffer(FilePath, fileBuf, CompareSize, &fileRead) ||
        fileRead < CompareSize) {
        goto Cleanup;
    }

    /* 对齐 C 版 CWE-393: 以实际读到字节数为准, 不比对越界零填充 */
    compareLen = min(memRead, fileRead);
    *Match = (memcmp(memBuf, fileBuf, compareLen) == 0);
    if (!*Match && MismatchOffset) {
        for (i = 0; i < compareLen; i++) {
            if (memBuf[i] != fileBuf[i]) {
                *MismatchOffset = i;
                break;
            }
        }
    }

    if (MemoryHash) {
        IocScanner_ComputeBufferSha256(memBuf, compareLen, MemoryHash);
    }
    if (FileHash) {
        IocScanner_ComputeBufferSha256(fileBuf, compareLen, FileHash);
    }

    ok = TRUE;

Cleanup:
    if (memBuf) free(memBuf);
    if (fileBuf) free(fileBuf);
    return ok;
}
#pragma warning(pop)  /* 4505 */

//
// 批量镂空扫描 (对齐 PS ScanAllProcesses, 仅返回 IsHollowed 命中)
// ★ 死代码: 供 UI 主动全盘扫描, 当前无调用者。
//
_Use_decl_annotations_
ULONG
IpeScanAllProcessesForHollowing(
    PWKD_HOLLOWING_RESULT Results,
    ULONG                  MaxResults,
    PULONG                 ResultCount,
    WKD_MEM_SCAN_MODE      ScanMode
    )
{
    HANDLE hSnap;
    ULONG count = 0;
    PROCESSENTRY32W pe;

    if (ResultCount) *ResultCount = 0;
    if (!Results || MaxResults == 0) return 0;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (count >= MaxResults) break;
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;

            if (IpeDetectProcessHollowing(pe.th32ProcessID, ScanMode, &Results[count]) &&
                Results[count].IsHollowed) {
                count++;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    if (ResultCount) *ResultCount = count;
    return count;
}

//
// 按 PID 数组批量镂空扫描 (对齐 PS ScanProcesses, 仅返回 IsHollowed 命中)
//
_Use_decl_annotations_
ULONG
IpeScanProcesses(
    const ULONG* Pids,
    ULONG        PidCount,
    PWKD_HOLLOWING_RESULT Results,
    ULONG        MaxResults,
    PULONG       ResultCount,
    WKD_MEM_SCAN_MODE ScanMode
    )
{
    ULONG count = 0;
    ULONG i;

    if (ResultCount) *ResultCount = 0;
    if (!Pids || PidCount == 0 || !Results || MaxResults == 0) return 0;

    for (i = 0; i < PidCount && count < MaxResults; i++) {
        if (Pids[i] == 0 || Pids[i] == 4) continue;
        if (IpeDetectProcessHollowing(Pids[i], ScanMode, &Results[count]) &&
            Results[count].IsHollowed) {
            count++;
        }
    }

    if (ResultCount) *ResultCount = count;
    return count;
}

//
// 按进程名批量镂空扫描 (对齐 PS ScanByName, 仅返回 IsHollowed 命中)
// ★ 死代码: 供 UI 定向扫描。
//
_Use_decl_annotations_
ULONG
IpeScanProcessesByName(
    PCWSTR ProcessName,
    PWKD_HOLLOWING_RESULT Results,
    ULONG  MaxResults,
    PULONG ResultCount,
    WKD_MEM_SCAN_MODE ScanMode
    )
{
    HANDLE hSnap;
    ULONG count = 0;
    PROCESSENTRY32W pe;

    if (ResultCount) *ResultCount = 0;
    if (!ProcessName || !ProcessName[0] || !Results || MaxResults == 0) return 0;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (count >= MaxResults) break;
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
            if (_wcsicmp(pe.szExeFile, ProcessName) != 0) continue;

            if (IpeDetectProcessHollowing(pe.th32ProcessID, ScanMode, &Results[count]) &&
                Results[count].IsHollowed) {
                count++;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    if (ResultCount) *ResultCount = count;
    return count;
}

//
// 按进程路径批量镂空扫描 (对齐 PS ScanByPath, 仅返回 IsHollowed 命中)
// ★ 死代码: 供 UI 定向扫描。
//
_Use_decl_annotations_
ULONG
IpeScanProcessesByPath(
    PCWSTR ProcessPath,
    PWKD_HOLLOWING_RESULT Results,
    ULONG  MaxResults,
    PULONG ResultCount,
    WKD_MEM_SCAN_MODE ScanMode
    )
{
    HANDLE hSnap;
    ULONG count = 0;
    PROCESSENTRY32W pe;

    if (ResultCount) *ResultCount = 0;
    if (!ProcessPath || !ProcessPath[0] || !Results || MaxResults == 0) return 0;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            WCHAR fullPath[MAX_PATH] = { 0 };
            DWORD pathLen = RTL_NUMBER_OF(fullPath);
            HANDLE hp;
            BOOLEAN match = FALSE;

            if (count >= MaxResults) break;
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;

            hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hp) {
                if (QueryFullProcessImageNameW(hp, 0, fullPath, &pathLen)) {
                    match = (_wcsicmp(fullPath, ProcessPath) == 0);
                }
                CloseHandle(hp);
            }
            if (!match) continue;

            if (IpeDetectProcessHollowing(pe.th32ProcessID, ScanMode, &Results[count]) &&
                Results[count].IsHollowed) {
                count++;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    if (ResultCount) *ResultCount = count;
    return count;
}

//
// 收集疑似镂空进程 PID 列表 (对齐 PS GetHollowedProcesses)
// ★ 死代码: 供 UI 主动全盘扫描。
//
_Use_decl_annotations_
ULONG
IpeGetHollowedProcesses(
    ULONG* Pids,
    ULONG  MaxPids,
    PULONG Count,
    WKD_MEM_SCAN_MODE ScanMode
    )
{
    HANDLE hSnap;
    ULONG count = 0;
    PROCESSENTRY32W pe;

    if (Count) *Count = 0;
    if (!Pids || MaxPids == 0) return 0;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            WKD_HOLLOWING_RESULT r = { 0 };
            if (count >= MaxPids) break;
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;

            if (IpeDetectProcessHollowing(pe.th32ProcessID, ScanMode, &r) && r.IsHollowed) {
                Pids[count++] = pe.th32ProcessID;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    if (Count) *Count = count;
    return count;
}

// ============================================================================
// 进程环境分析（对齐 SS EnvironmentMonitor, 2026-08-05 功能面迁移）
//
// 功能面全量迁移 ShadowStrike Callbacks/Process/EnvironmentMonitor.c（重实现非复制）:
//   - PEB 环境块读取（仿 process_manager.c WkGetProcessCommandLine:
//     NtQueryInformationProcess(ProcessBasicInformation) + WOW64 class 26）
//   - 6 维度检测:
//       PATH 可写/用户/可疑条目   -> MODIFIED_PATH / SEARCH_ORDER (T1574.007/008)
//       代理劫持 (9 变量)          -> PROXY (T1090.001)
//       TEMP/TMP 覆盖              -> TEMP_OVERRIDE
//       Base64/Hex 编码            -> ENCODED (T1027)
//       高熵 (Shannon 近似 >4.5)   -> ENCODED (T1027)
//       变量数 >500 (注入嫌疑)      -> HIDDEN_VAR
//   - 评分 0-100（对齐 SS EmpCalculateSuspicionScore）
//
// ★ 接线: IpeAnalyzeEnvironment 当前无调用者, 预留 IoaObserve 阶段 4.8
//   接入（仿 g_IoaCmdLineAnalyzerEnabled）, 结果挂 PROCESS_NODE.ExtraData。
//   驱动侧不迁移: 创建回调 attach+64KB 拷贝成本高, 环境分析属 L2 深度分析,
//   agent 用户态自读 PEB 已覆盖; 内核侧仅预留 WKD_BEHAVIOR_ENV_* 标志位。
//
// 迁移决策说明:
//   - SS g_DllVariables(IsSystemVariable 存储属性) 不迁移: agent 分析一次性,
//     不存变量列表, 该字段在 SS 亦无检测消费者。
//   - SS EmFlags→PN_BEHAVIOR_ENV_*/BeEngineSubmitEvent 三路分发(DLLHijacking 40/
//     SandboxEvasion 35/ProcessMasquerading 30) 由阶段4.8 SuspicionScore 提升
//     finalScore 覆盖(触发 T2/T3 分级 + VerdictEngine 融合)。
//   - 高熵检测重实现 SS Shannon 近似(×1000, 阈值 4500): wkd WpeCalculateEntropy
//     为简化熵(0-1000 尺度), 尺度语义不同, 不复用以保检测行为一致。
//   - SS EmGetVariable(按名查询) 已迁移为 IpeGetEnvironmentVariable (死代码,
//     无调用者, 供后续按需读取 PATH/PATHEXT 等)。
//   - SS Stats(ProcessesMonitored/SuspiciousEnvFound/CacheHits/CacheMisses) 不迁移:
//     服务于缓存性能监控, agent 无缓存且统计已由 VerdictEngine/进程表体系覆盖。
// ============================================================================

#define IPE_MAX_ENV_NAME        256
#define IPE_MAX_ENV_VALUE       8192
#define IPE_MAX_ENV_BLOCK_SIZE  (64 * 1024)
#define IPE_MAX_VARIABLES       1024
#define IPE_MAX_PATH_ENTRIES    256
#define IPE_ENTROPY_THRESHOLD   4500    /* 熵 > 4.5（Shannon 近似 x1000, 对齐 SS） */
#define IPE_SAFE_STRING_MAX     32768

//
// 常量表（对齐 SS g_ProxyVariables / g_TempVariables / g_SuspiciousPathDirs）
//
static const PCWSTR g_IpeProxyVariables[] = {
    L"HTTP_PROXY", L"HTTPS_PROXY", L"FTP_PROXY", L"ALL_PROXY", L"NO_PROXY",
    L"http_proxy", L"https_proxy", L"ftp_proxy", L"all_proxy"
};

static const PCWSTR g_IpeTempVariables[] = {
    L"TEMP", L"TMP", L"TMPDIR"
};

static const PCWSTR g_IpeSuspiciousPathDirs[] = {
    L"\\Users\\", L"\\Temp\\", L"\\AppData\\", L"\\Downloads\\",
    L"\\Desktop\\", L"\\Documents\\", L"\\Public\\", L"\\ProgramData\\"
};

//
// 内部: 环境分析中间状态（对齐 SS EMP_PROCESS_ENV_EXTENDED）
//
typedef struct _IPE_ENV_EXTENDED {
    BOOLEAN HasWritablePathEntry;
    BOOLEAN HasUserPathEntry;
    BOOLEAN HasSuspiciousPathEntry;
    BOOLEAN HasProxySettings;
    BOOLEAN ProxyIsLocalhost;
    BOOLEAN ProxyIsSuspicious;
    BOOLEAN HasTempOverride;
    BOOLEAN TempPointsToWritable;
    ULONG   PathEntryCount;
    ULONG   EncodedValueCount;
    ULONG   HighEntropyCount;
    ULONG   VariableCount;
} IPE_ENV_EXTENDED, *PIPE_ENV_EXTENDED;

//
// 环境块解析内部类型（占位, 已前移 PEB 布局到文件头部）
//

//
// NtQueryInformationProcess 声明（对齐 process_manager.c L2397-2404）
//
NTSTATUS NTAPI NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                         PVOID ProcessInformation, ULONG ProcessInformationLength,
                                         PULONG ReturnLength);

//
// 内部辅助: 捕获远程进程环境块（逐页读取, 扫描双 null 结尾, cap 64KB）
// 对齐 SS EmpCaptureEnvironmentBlockSafe 的逐 WCHAR 双 null 扫描;
// agent 用 ReadProcessMemory 逐 4KB 页读, 未提交页失败时用已捕获部分。
//
static ULONG
IpepCaptureEnvironmentBlock(
    _In_  HANDLE    hProcess,
    _In_  ULONG_PTR EnvAddress,
    _Out_writes_bytes_(Capacity) PBYTE Buffer,
    _In_  ULONG     Capacity
    )
{
    ULONG total = 0;
    BOOLEAN prevNull = FALSE;

    if (Buffer == NULL || Capacity < sizeof(WCHAR) * 2) {
        return 0;
    }
    if (Capacity & 1) {
        Capacity--;                     /* WCHAR 对齐 */
    }

    while (total + sizeof(WCHAR) <= Capacity) {
        ULONG chunk = 4096;
        ULONG start = total;
        SIZE_T read = 0;

        if (chunk > Capacity - total) {
            chunk = Capacity - total;
        }
        chunk &= ~1UL;                  /* 偶数, 保 WCHAR 对齐 */
        if (chunk < sizeof(WCHAR)) {
            break;
        }

        if (!ReadProcessMemory(hProcess, (LPCVOID)(EnvAddress + total),
                               Buffer + total, chunk, &read) || read < sizeof(WCHAR)) {
            break;                      /* 未提交页/失败: 用已捕获部分 */
        }
        read &= ~1UL;                   /* 保 WCHAR 对齐 */
        total += (ULONG)read;

        for (ULONG i = start; i + sizeof(WCHAR) <= total; i += sizeof(WCHAR)) {
            WCHAR ch = *(WCHAR*)(Buffer + i);
            if (ch == L'\0') {
                if (prevNull) {
                    return total;       /* 双 null: 环境块结束 */
                }
                prevNull = TRUE;
            } else {
                prevNull = FALSE;
            }
        }
    }

    return total;
}

//
// 内部辅助: 大小写不敏感子串匹配（对齐 SS EmpSafeWcsStr）
//
static BOOLEAN
IpepSafeWcsStr(
    _In_ PCWSTR Haystack,
    _In_ SIZE_T HaystackLength,
    _In_ PCWSTR Needle
    )
{
    SIZE_T needleLength;
    SIZE_T i;

    if (Haystack == NULL || Needle == NULL || HaystackLength == 0) {
        return FALSE;
    }
    needleLength = wcslen(Needle);
    if (needleLength == 0 || needleLength > HaystackLength) {
        return FALSE;
    }
    for (i = 0; i <= HaystackLength - needleLength; i++) {
        SIZE_T j;
        BOOLEAN match = TRUE;
        for (j = 0; j < needleLength; j++) {
            WCHAR c1 = Haystack[i + j];
            WCHAR c2 = Needle[j];
            if (c1 >= L'A' && c1 <= L'Z') c1 = (WCHAR)(c1 - L'A' + L'a');
            if (c2 >= L'A' && c2 <= L'Z') c2 = (WCHAR)(c2 - L'A' + L'a');
            if (c1 != c2) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// 内部辅助: 路径判定（对齐 SS EmpIsWritablePath/EmpIsUserPath/
// EmpIsSuspiciousPath/EmpIsSystemPath）
//
static BOOLEAN
IpepIsWritablePath(
    _In_ PCWSTR Path,
    _In_ SIZE_T PathLength
    )
{
    ULONG i;
    for (i = 0; i < ARRAYSIZE(g_IpeSuspiciousPathDirs); i++) {
        if (IpepSafeWcsStr(Path, PathLength, g_IpeSuspiciousPathDirs[i])) {
            return TRUE;
        }
    }
    /* 当前目录占位符 . / .\ / .; */
    if (PathLength >= 1 && Path[0] == L'.') {
        if (PathLength == 1 || Path[1] == L'\\' || Path[1] == L';') {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
IpepIsUserPath(
    _In_ PCWSTR Path,
    _In_ SIZE_T PathLength
    )
{
    if (IpepSafeWcsStr(Path, PathLength, L"\\Users\\")) return TRUE;
    if (IpepSafeWcsStr(Path, PathLength, L"\\AppData\\")) return TRUE;
    return FALSE;
}

static BOOLEAN
IpepIsSuspiciousPath(
    _In_ PCWSTR Path,
    _In_ SIZE_T PathLength
    )
{
    if (PathLength < 1) {
        return FALSE;
    }
    /* UNC 路径 */
    if (PathLength >= 2 && Path[0] == L'\\' && Path[1] == L'\\') {
        return TRUE;
    }
    /* 相对路径（非 \ 开头, 非 X:\ 形式, 首字符非字母） */
    if (PathLength >= 3) {
        if (Path[0] != L'\\' && (Path[1] != L':' || Path[2] != L'\\')) {
            if (!((Path[0] >= L'A' && Path[0] <= L'Z') ||
                  (Path[0] >= L'a' && Path[0] <= L'z'))) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static BOOLEAN
IpepIsSystemPath(
    _In_ PCWSTR Path,
    _In_ SIZE_T PathLength
    )
{
    if (IpepSafeWcsStr(Path, PathLength, L"\\Windows\\")) return TRUE;
    if (IpepSafeWcsStr(Path, PathLength, L"\\System32\\")) return TRUE;
    if (IpepSafeWcsStr(Path, PathLength, L"\\SysWOW64\\")) return TRUE;
    if (IpepSafeWcsStr(Path, PathLength, L"\\Program Files\\")) return TRUE;
    if (IpepSafeWcsStr(Path, PathLength, L"\\Program Files (x86)\\")) return TRUE;
    return FALSE;
}

//
// PATH 分析（对齐 SS EmpAnalyzePathVariable）: 分号分隔解析 PATH 条目,
// 判定可写目录/用户目录/可疑路径（UNC·相对路径）。
//
static VOID
IpepAnalyzePathVariable(
    _In_  PCWSTR            PathValue,
    _In_  SIZE_T            PathLength,
    _Inout_ PIPE_ENV_EXTENDED Ext
    )
{
    PWCHAR pathCopy;
    PWCHAR token;
    ULONG entryCount = 0;

    if (PathValue == NULL || PathLength == 0) {
        return;
    }
    if (PathLength >= IPE_MAX_ENV_VALUE) {
        return;
    }

    pathCopy = (PWCHAR)malloc((PathLength + 1) * sizeof(WCHAR));
    if (pathCopy == NULL) {
        return;
    }
    wcsncpy_s(pathCopy, PathLength + 1, PathValue, PathLength);
    pathCopy[PathLength] = L'\0';

    token = pathCopy;
    while (token != NULL && entryCount < IPE_MAX_PATH_ENTRIES) {
        PWCHAR nextToken = wcschr(token, L';');
        SIZE_T tokenLen;

        if (nextToken != NULL) {
            *nextToken = L'\0';
            nextToken++;
        }
        tokenLen = wcslen(token);
        if (tokenLen == 0) {
            token = nextToken;
            continue;
        }

        if (IpepIsWritablePath(token, tokenLen)) {
            Ext->HasWritablePathEntry = TRUE;
        }
        if (IpepIsUserPath(token, tokenLen)) {
            Ext->HasUserPathEntry = TRUE;
        }
        if (IpepIsSuspiciousPath(token, tokenLen)) {
            Ext->HasSuspiciousPathEntry = TRUE;
        }
        entryCount++;
        token = nextToken;
    }

    Ext->PathEntryCount = entryCount;
    free(pathCopy);
}

//
// 代理劫持分析（对齐 SS EmpAnalyzeProxySettingsLocked）:
// 9 个 proxy 变量, 值指向 localhost/127.0.0.1/::1 或非白名单端口 -> 可疑。
//
static BOOLEAN
IpepIsProxyVariable(
    _In_ PCWSTR Name,
    _In_ SIZE_T NameLength
    )
{
    ULONG i;
    for (i = 0; i < ARRAYSIZE(g_IpeProxyVariables); i++) {
        if (NameLength == wcslen(g_IpeProxyVariables[i]) &&
            _wcsnicmp(Name, g_IpeProxyVariables[i], NameLength) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
IpepParsePortFromWide(
    _In_  PCWSTR Str,
    _Out_ PULONG Port
    )
{
    ULONG result = 0;
    ULONG i;

    *Port = 0;
    if (Str == NULL || Str[0] == L'\0') {
        return FALSE;
    }
    for (i = 0; i < 5 && Str[i] != L'\0'; i++) {
        WCHAR c = Str[i];
        if (c >= L'0' && c <= L'9') {
            result = result * 10 + (c - L'0');
            if (result > 65535) {
                return FALSE;
            }
        } else if (c == L'/') {
            break;                      /* URL 路径分隔 */
        } else {
            return FALSE;
        }
    }
    *Port = result;
    return TRUE;
}

static VOID
IpepAnalyzeProxyValue(
    _In_  PCWSTR            Value,
    _In_  SIZE_T            ValueLength,
    _Inout_ PIPE_ENV_EXTENDED Ext
    )
{
    PCWSTR colonPos;

    Ext->HasProxySettings = TRUE;
    if (ValueLength == 0) {
        return;
    }

    if (wcsstr(Value, L"127.0.0.1") != NULL ||
        wcsstr(Value, L"localhost") != NULL ||
        wcsstr(Value, L"::1") != NULL) {
        Ext->ProxyIsLocalhost = TRUE;
        Ext->ProxyIsSuspicious = TRUE;
    }

    /* 非白名单端口（对齐 SS: 80/443/8080/3128 白名单） */
    colonPos = wcsrchr(Value, L':');
    if (colonPos != NULL && colonPos < Value + ValueLength - 1) {
        ULONG port = 0;
        if (IpepParsePortFromWide(colonPos + 1, &port)) {
            if (port != 80 && port != 443 && port != 8080 && port != 3128) {
                Ext->ProxyIsSuspicious = TRUE;
            }
        }
    }
}

//
// TEMP/TMP 覆盖分析（对齐 SS EmpAnalyzeTempOverridesLocked）:
// 指向非系统目录 -> override; 且可写 -> writable。
//
static BOOLEAN
IpepIsTempVariable(
    _In_ PCWSTR Name,
    _In_ SIZE_T NameLength
    )
{
    ULONG i;
    for (i = 0; i < ARRAYSIZE(g_IpeTempVariables); i++) {
        if (NameLength == wcslen(g_IpeTempVariables[i]) &&
            _wcsnicmp(Name, g_IpeTempVariables[i], NameLength) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static VOID
IpepAnalyzeTempValue(
    _In_  PCWSTR            Value,
    _In_  SIZE_T            ValueLength,
    _Inout_ PIPE_ENV_EXTENDED Ext
    )
{
    if (ValueLength == 0) {
        return;
    }
    if (!IpepIsSystemPath(Value, ValueLength)) {
        Ext->HasTempOverride = TRUE;
        if (IpepIsWritablePath(Value, ValueLength)) {
            Ext->TempPointsToWritable = TRUE;
        }
    }
}

//
// 编码检测（对齐 SS EmpIsEncodedValue/EmpIsBase64Encoded/EmpIsHexEncoded）:
// 值长度 >= 8, Base64 判定（>=80% 有效字符 + %4==0 + >=16 有效 + padding<=2）
// 或 Hex 判定（全 hex 字符 + 偶数 + >=16）。
//
static BOOLEAN
IpepIsBase64Encoded(
    _In_ PCWSTR Value,
    _In_ SIZE_T ValueLength
    )
{
    ULONG validChars = 0;
    ULONG paddingCount = 0;
    BOOLEAN hasInvalidChar = FALSE;
    SIZE_T i;

    if (ValueLength < 4 || ValueLength > IPE_SAFE_STRING_MAX) {
        return FALSE;
    }
    for (i = 0; i < ValueLength; i++) {
        WCHAR c = Value[i];
        if ((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
            (c >= L'0' && c <= L'9') || c == L'+' || c == L'/') {
            validChars++;
        } else if (c == L'=') {
            paddingCount++;
        } else if (c == L' ' || c == L'\t' || c == L'\r' || c == L'\n') {
            /* 允许空白 */
        } else {
            hasInvalidChar = TRUE;
            break;
        }
    }
    if (hasInvalidChar) {
        return FALSE;
    }
    if (paddingCount > 2) {
        return FALSE;
    }
    {
        ULONG totalValidChars = validChars + paddingCount;
        if (totalValidChars >= (ValueLength * 8 / 10) &&
            (totalValidChars % 4) == 0 &&
            validChars >= 16) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
IpepIsHexEncoded(
    _In_ PCWSTR Value,
    _In_ SIZE_T ValueLength
    )
{
    ULONG hexChars = 0;
    SIZE_T i;

    if (ValueLength < 8 || ValueLength > IPE_SAFE_STRING_MAX) {
        return FALSE;
    }
    for (i = 0; i < ValueLength; i++) {
        WCHAR c = Value[i];
        if ((c >= L'0' && c <= L'9') ||
            (c >= L'A' && c <= L'F') ||
            (c >= L'a' && c <= L'f')) {
            hexChars++;
        } else if (c == L' ' || c == L'\t' || c == L'\r' || c == L'\n') {
            /* 允许空白 */
        } else {
            return FALSE;
        }
    }
    if (hexChars >= 16 && (hexChars % 2) == 0) {
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN
IpepIsEncodedValue(
    _In_ PCWSTR Value,
    _In_ SIZE_T ValueLength
    )
{
    if (ValueLength < 8) {
        return FALSE;
    }
    if (IpepIsBase64Encoded(Value, ValueLength)) {
        return TRUE;
    }
    if (IpepIsHexEncoded(Value, ValueLength)) {
        return TRUE;
    }
    return FALSE;
}

//
// 熵计算（对齐 SS EmpCalculateEntropyScaled）: Shannon 熵整数近似 x1000。
// 环境值高熵判定专用; wkd 的 WpeCalculateEntropy 为简化熵(0-1000 尺度),
// 尺度语义不同故不复用, 保持与 SS 检测行为一致。
//
static ULONG
IpepCalculateEntropyScaled(
    _In_ PCWSTR Value,
    _In_ SIZE_T ValueLength
    )
{
    ULONG frequency[256] = { 0 };
    ULONG entropyScaled = 0;
    ULONG i;

    if (ValueLength == 0 || ValueLength > IPE_SAFE_STRING_MAX) {
        return 0;
    }
    for (i = 0; i < ValueLength; i++) {
        frequency[(UCHAR)Value[i]]++;
    }
    for (i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            ULONG ratio = (ULONG)(ValueLength / frequency[i]);
            ULONG log2Approx = 0;
            ULONG temp = ratio;
            ULONG contribution;

            while (temp > 1) {
                temp >>= 1;
                log2Approx++;
            }
            contribution = (frequency[i] * log2Approx * 1000) / (ULONG)ValueLength;
            entropyScaled += contribution;
        }
    }
    return entropyScaled;
}

//
// 环境块解析 + 6 维度即时分析（对齐 SS EmpParseEnvironmentBlock）:
// 逐变量: PATH / 代理 / TEMP / 编码 / 高熵 判定, 计数累计。
// 代理与 TEMP 在解析循环内即时判定（agent 不存储变量列表）。
//
static VOID
IpepParseEnvironmentBlock(
    _In_  PVOID            EnvironmentBlock,
    _In_  ULONG            BlockSize,
    _Inout_ PIPE_ENV_EXTENDED Ext
    )
{
    PWCHAR envPtr = (PWCHAR)EnvironmentBlock;
    PWCHAR endPtr = (PWCHAR)((PBYTE)EnvironmentBlock + BlockSize);

    if (EnvironmentBlock == NULL || BlockSize < sizeof(WCHAR) * 2) {
        return;
    }

    while (envPtr < endPtr && *envPtr != L'\0' && Ext->VariableCount < IPE_MAX_VARIABLES) {
        PWCHAR stringEnd = envPtr;
        PWCHAR equalSign = NULL;

        while (stringEnd < endPtr && *stringEnd != L'\0') {
            stringEnd++;
        }
        if (stringEnd >= endPtr) {
            break;                      /* 畸形块: 无 null 结尾 */
        }
        if (stringEnd == envPtr) {
            break;
        }

        for (PWCHAR p = envPtr; p < stringEnd; p++) {
            if (*p == L'=') {
                if (p != envPtr) {
                    equalSign = p;      /* 跳过首字符 '=' 的特殊变量 (=C: 等) */
                }
                break;
            }
        }
        if (equalSign == NULL) {
            envPtr = stringEnd + 1;
            continue;
        }

        {
            SIZE_T nameLen = (SIZE_T)(equalSign - envPtr);
            SIZE_T valueLen = (SIZE_T)(stringEnd - equalSign - 1);
            PCWSTR name = envPtr;
            PCWSTR value = equalSign + 1;

            if (nameLen == 0 || nameLen >= IPE_MAX_ENV_NAME) {
                envPtr = stringEnd + 1;
                continue;
            }
            if (valueLen >= IPE_MAX_ENV_VALUE) {
                valueLen = IPE_MAX_ENV_VALUE - 1;
            }

            /* PATH 分析（对齐 SS: NameLength==4 && "PATH"） */
            if (nameLen == 4 && _wcsnicmp(name, L"PATH", 4) == 0) {
                IpepAnalyzePathVariable(value, valueLen, Ext);
            }

            /* 代理劫持 */
            if (IpepIsProxyVariable(name, nameLen)) {
                IpepAnalyzeProxyValue(value, valueLen, Ext);
            }

            /* TEMP/TMP 覆盖 */
            if (IpepIsTempVariable(name, nameLen)) {
                IpepAnalyzeTempValue(value, valueLen, Ext);
            }

            /* 编码检测（Base64/Hex） */
            if (IpepIsEncodedValue(value, valueLen)) {
                Ext->EncodedValueCount++;
            }

            /* 高熵检测（Shannon 近似 > 4.5） */
            if (IpepCalculateEntropyScaled(value, valueLen) > IPE_ENTROPY_THRESHOLD) {
                Ext->HighEntropyCount++;
            }

            Ext->VariableCount++;
            envPtr = stringEnd + 1;
        }
    }
}

//
// 标志汇总 / 评分（对齐 SS EmpDetectSuspiciousConditions + EmpCalculateSuspicionScore）
//
static ULONG
IpepDetectSuspiciousConditions(
    _In_ PIPE_ENV_EXTENDED Ext
    )
{
    ULONG flags = WKD_ENV_FLAG_NONE;

    if (Ext->HasWritablePathEntry || Ext->HasUserPathEntry) {
        flags |= WKD_ENV_FLAG_MODIFIED_PATH;
    }
    if (Ext->HasSuspiciousPathEntry) {
        flags |= WKD_ENV_FLAG_SEARCH_ORDER;
    }
    if (Ext->HasProxySettings && Ext->ProxyIsSuspicious) {
        flags |= WKD_ENV_FLAG_PROXY;
    }
    if (Ext->HasTempOverride) {
        flags |= WKD_ENV_FLAG_TEMP_OVERRIDE;
    }
    if (Ext->EncodedValueCount > 0 || Ext->HighEntropyCount > 2) {
        flags |= WKD_ENV_FLAG_ENCODED;
    }
    if (Ext->VariableCount > 500) {
        flags |= WKD_ENV_FLAG_HIDDEN_VAR;
    }
    return flags;
}

static ULONG
IpepCalculateSuspicionScore(
    _In_ PIPE_ENV_EXTENDED Ext,
    _In_ ULONG             Flags
    )
{
    ULONG score = 0;

    if (Flags & WKD_ENV_FLAG_MODIFIED_PATH) score += 25;
    if (Flags & WKD_ENV_FLAG_SEARCH_ORDER)  score += 40;
    if (Flags & WKD_ENV_FLAG_PROXY)         score += 35;
    if (Flags & WKD_ENV_FLAG_TEMP_OVERRIDE) score += 20;
    if (Flags & WKD_ENV_FLAG_HIDDEN_VAR)    score += 15;
    if (Flags & WKD_ENV_FLAG_ENCODED)       score += 30;

    if (Ext->ProxyIsLocalhost)              score += 20;
    if (Ext->EncodedValueCount > 3)         score += 15;
    if (Ext->HighEntropyCount > 5)          score += 15;
    if (Ext->TempPointsToWritable)          score += 10;

    if (score > 100) {
        score = 100;
    }
    return score;
}

//
// 内部辅助: 读取目标进程 PEB 环境块
// （对齐 SS EmpCaptureEnvironmentBlockSafe; 仿 WkGetProcessCommandLine 的
// NtQueryInformationProcess + WOW64 class 26 双路径）
//
static BOOLEAN
IpepReadEnvironmentBlock(
    _In_  ULONG  ProcessId,
    _Out_writes_bytes_(MaxSize) PVOID Buffer,
    _In_  ULONG  MaxSize,
    _Out_ PULONG OutSize
    )
{
    BOOLEAN ok = FALSE;
    HANDLE hProcess = NULL;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen = 0;
    ULONG_PTR envAddr = 0;
    BOOLEAN isWow64 = FALSE;

    if (Buffer == NULL || MaxSize == 0 || OutSize == NULL) {
        return FALSE;
    }
    *OutSize = 0;

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                           FALSE, ProcessId);
    if (hProcess == NULL) {
        return FALSE;
    }

    RtlZeroMemory(&pbi, sizeof(pbi));
    if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi,
                                  sizeof(pbi), &retLen) != 0 || pbi.PebBaseAddress == NULL) {
        goto done;
    }

    /* WOW64 判定: IsWow64Process2 优先, 回退 IsWow64Process（对齐 WkGetProcessCommandLine） */
    {
        typedef BOOL(WINAPI* PFN_IsWow64Process2)(HANDLE, USHORT*, USHORT*);
        static PFN_IsWow64Process2 pIsWow64Process2 = NULL;
        USHORT procMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;

        if (pIsWow64Process2 == NULL) {
            pIsWow64Process2 = (PFN_IsWow64Process2)GetProcAddress(
                GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
        }
        if (pIsWow64Process2 != NULL) {
            if (pIsWow64Process2(hProcess, &procMachine, &nativeMachine)) {
                isWow64 = (procMachine != IMAGE_FILE_MACHINE_UNKNOWN) &&
                          (procMachine != nativeMachine);
            } else {
                BOOL wow = FALSE;
                IsWow64Process(hProcess, &wow);
                isWow64 = (wow == TRUE);
            }
        } else {
            BOOL wow = FALSE;
            IsWow64Process(hProcess, &wow);
            isWow64 = (wow == TRUE);
        }
    }

#ifdef _WIN64
    if (isWow64) {
        ULONG_PTR peb32Address = 0;
        IPE_PEB32 peb32;
        IPE_PROCESS_PARAMETERS32 params32;
        SIZE_T read = 0;

        if (NtQueryInformationProcess(hProcess, ProcessWow64Information, &peb32Address,
                                      sizeof(peb32Address), NULL) != 0 || peb32Address == 0) {
            goto done;
        }
        RtlZeroMemory(&peb32, sizeof(peb32));
        if (!ReadProcessMemory(hProcess, (LPCVOID)peb32Address, &peb32, sizeof(peb32), &read) ||
            read != sizeof(peb32) || peb32.ProcessParameters == 0) {
            goto done;
        }
        RtlZeroMemory(&params32, sizeof(params32));
        read = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)(ULONG_PTR)peb32.ProcessParameters,
                               &params32, sizeof(params32), &read) ||
            read != sizeof(params32) || params32.Environment == 0) {
            goto done;
        }
        envAddr = (ULONG_PTR)params32.Environment;
    } else
#endif
    {
        IPE_PEB64 peb;
        IPE_PROCESS_PARAMETERS64 params;
        SIZE_T read = 0;

        RtlZeroMemory(&peb, sizeof(peb));
        if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &read) ||
            read != sizeof(peb) || peb.ProcessParameters == NULL) {
            goto done;
        }
        RtlZeroMemory(&params, sizeof(params));
        read = 0;
        if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), &read) ||
            read != sizeof(params) || params.Environment == NULL) {
            goto done;
        }
        envAddr = (ULONG_PTR)params.Environment;
    }

    *OutSize = IpepCaptureEnvironmentBlock(hProcess, envAddr, (PBYTE)Buffer, MaxSize);
    if (*OutSize >= sizeof(WCHAR) * 2) {
        ok = TRUE;
    }

done:
    CloseHandle(hProcess);
    return ok;
}

_Use_decl_annotations_
BOOL
IpeAnalyzeEnvironment(
    ULONG               ProcessId,
    PWKD_ENV_ANALYSIS   Result
    )
/*++
Routine Description:
    进程环境分析（对齐 SS EmCaptureEnvironment + EmAnalyzeEnvironment）:
    读取目标进程 PEB 环境块, 解析全部变量并执行 6 维度静态分析:
      PATH 可写/用户/可疑条目 / 代理劫持 / TEMP 覆盖 /
      Base64·Hex 编码 / 高熵 (Shannon>4.5) / 变量数>500
    结果输出 WKD_ENV_ANALYSIS（标志位 + 0-100 评分 + 计数）。

Arguments:
    ProcessId - 目标进程 ID.
    Result    - 分析结果（输出）.

Return Value:
    TRUE  - 分析执行（Result 有效）。
    FALSE - 无法读取（进程退出/无权限）。
--*/
{
    BOOLEAN ok = FALSE;
    PBYTE blockBuffer = NULL;
    ULONG blockSize = 0;
    IPE_ENV_EXTENDED ext;

    if (Result == NULL) {
        return FALSE;
    }
    RtlZeroMemory(Result, sizeof(*Result));

    blockBuffer = (PBYTE)malloc(IPE_MAX_ENV_BLOCK_SIZE);
    if (blockBuffer == NULL) {
        return FALSE;
    }

    if (!IpepReadEnvironmentBlock(ProcessId, blockBuffer, IPE_MAX_ENV_BLOCK_SIZE, &blockSize)) {
        free(blockBuffer);
        return FALSE;
    }

    RtlZeroMemory(&ext, sizeof(ext));
    IpepParseEnvironmentBlock(blockBuffer, blockSize, &ext);

    Result->Flags = IpepDetectSuspiciousConditions(&ext);
    Result->SuspicionScore = IpepCalculateSuspicionScore(&ext, Result->Flags);
    Result->PathEntryCount = ext.PathEntryCount;
    Result->EncodedValueCount = ext.EncodedValueCount;
    Result->HighEntropyCount = ext.HighEntropyCount;
    Result->VariableCount = ext.VariableCount;

    ok = TRUE;
    free(blockBuffer);
    return ok;
}

_Use_decl_annotations_
BOOL
IpeGetEnvironmentVariable(
    ULONG               ProcessId,
    PCWSTR              Name,
    PWCHAR              Value,
    ULONG               ValueSize
    )
/*++
Routine Description:
    按名查询进程环境变量（对齐 SS EmGetVariable）:
    读取目标进程 PEB 环境块, 逐变量做大小写不敏感名字匹配, 命中拷贝值。
    agent 不存储变量列表, 每次独立读取环境块（与 IpeAnalyzeEnvironment 共享
    IpepReadEnvironmentBlock）。

Arguments:
    ProcessId - 目标进程 ID.
    Name      - 变量名（如 L"PATH", 大小写不敏感）.
    Value     - 输出缓冲.
    ValueSize - 输出缓冲容量（WCHAR 数, 含结尾 null）.

Return Value:
    TRUE  - 找到（Value 填充, 截断至 ValueSize-1）。
    FALSE - 未找到 / 无法读取（进程退出/无权限）。
--*/
{
    BOOLEAN found = FALSE;
    PBYTE blockBuffer = NULL;
    ULONG blockSize = 0;
    PWCHAR envPtr;
    PWCHAR endPtr;
    SIZE_T nameLen;

    if (Value == NULL || ValueSize == 0) {
        return FALSE;
    }
    Value[0] = L'\0';
    if (Name == NULL || Name[0] == L'\0') {
        return FALSE;
    }
    nameLen = wcslen(Name);
    if (nameLen >= IPE_MAX_ENV_NAME) {
        return FALSE;
    }

    blockBuffer = (PBYTE)malloc(IPE_MAX_ENV_BLOCK_SIZE);
    if (blockBuffer == NULL) {
        return FALSE;
    }

    if (!IpepReadEnvironmentBlock(ProcessId, blockBuffer, IPE_MAX_ENV_BLOCK_SIZE, &blockSize)) {
        free(blockBuffer);
        return FALSE;
    }

    envPtr = (PWCHAR)blockBuffer;
    endPtr = (PWCHAR)((PBYTE)blockBuffer + blockSize);

    while (envPtr < endPtr && *envPtr != L'\0') {
        PWCHAR stringEnd = envPtr;
        PWCHAR equalSign = NULL;

        while (stringEnd < endPtr && *stringEnd != L'\0') {
            stringEnd++;
        }
        if (stringEnd >= endPtr) {
            break;
        }
        if (stringEnd == envPtr) {
            break;
        }

        for (PWCHAR p = envPtr; p < stringEnd; p++) {
            if (*p == L'=') {
                if (p != envPtr) {
                    equalSign = p;
                }
                break;
            }
        }
        if (equalSign == NULL) {
            envPtr = stringEnd + 1;
            continue;
        }

        {
            SIZE_T curNameLen = (SIZE_T)(equalSign - envPtr);
            SIZE_T curValLen = (SIZE_T)(stringEnd - equalSign - 1);

            if (curNameLen == nameLen && _wcsnicmp(envPtr, Name, nameLen) == 0) {
                SIZE_T copyLen = (curValLen < (SIZE_T)(ValueSize - 1))
                                 ? curValLen : (SIZE_T)(ValueSize - 1);
                memcpy(Value, equalSign + 1, copyLen * sizeof(WCHAR));
                Value[copyLen] = L'\0';
                found = TRUE;
                break;
            }
        }
        envPtr = stringEnd + 1;
    }

    free(blockBuffer);
    return found;
}
