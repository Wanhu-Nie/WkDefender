/**************************************************/
/*  WkDefender IOA — 本地提权 (LPE) 模式检测器实现  */
/*                                                  */
/*  迁移自 ShadowStrike PrivilegeEscalationDetector */
/*  (PrivilegeEscalationDetector.cpp, v3.0.1)       */
/*  功能重实现 (C 重写), 非源码复制。                */
/*                                                  */
/*  独立模块 (死代码): 不挂接 IoaObserve 流水线,     */
/*  由调用方周期调用 LpdRunSweep 或分类入口。        */
/*  Token 操控检测不移植 (TokenAnalyzer 已覆盖)。    */
/**************************************************/

#include "LpePatternDetector.h"

#include <AclAPI.h>
#include <sddl.h>
#include <TlHelp32.h>
#include <ShellAPI.h>
#include <wchar.h>
#include <stdlib.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")

/**************************************************/
/*               模块级实例 (单例)                  */
/**************************************************/

static struct _LPD_DETECTOR {
    BOOLEAN             Initialized;
    LPD_CONFIG          Config;
    LPD_DETECTED_CALLBACK Callback;
    PVOID               CallbackContext;
    LPD_STATISTICS      Stats;
    volatile LONG       EventSequence;      /* 事件 ID 自增 */
} g_Lpd = { FALSE, { 0 }, NULL, NULL, { 0 }, 0 };

/**************************************************/
/*               静态知识库                         */
/*  对齐 SS: PrivEscConstants + 类内成员数组        */
/**************************************************/

/* UAC 绕过注册表路径 (HKCU 标准用户可写, SS L179-187) */
static const PCWSTR g_LpdUacBypassPaths[] = {
    L"Software\\Classes\\ms-settings\\Shell\\Open\\command",
    L"Software\\Classes\\mscfile\\shell\\open\\command",
    L"Software\\Classes\\exefile\\shell\\runas\\command",
    L"Software\\Classes\\Folder\\shell\\open\\command",
    L"Software\\Classes\\ms-settings\\shell\\open\\command",
    L"Software\\Classes\\CLSID\\{0A29FF9E-7F9C-4437-8B11-F424491E3931}\\InprocServer32",
    L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths",
};
#define LPD_UAC_BYPASS_PATH_COUNT \
    (sizeof(g_LpdUacBypassPaths) / sizeof(g_LpdUacBypassPaths[0]))

/* IFEO 注册表根 (SS IFEO_REGISTRY_PATH) */
#define LPD_IFEO_REGISTRY_PATH \
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"

/* IFEO 枚举时跳过的良性条目 (SS L1876-1878) */
static const PCWSTR g_LpdIfeoSkipEntries[] = {
    L"Your Image File Name Here without a path",
    L"Microsoft.Phone.exe",
    L"svchost.exe",
};
#define LPD_IFEO_SKIP_COUNT \
    (sizeof(g_LpdIfeoSkipEntries) / sizeof(g_LpdIfeoSkipEntries[0]))

/* Potato 家族二进制名 (SS m_knownPotatoBinaries) */
static const PCWSTR g_LpdPotatoBinaries[] = {
    L"juicypotato.exe", L"juicypotatong.exe", L"roguepotato.exe",
    L"sweetpotato.exe", L"godpotato.exe", L"printspoofer.exe",
    L"badpotato.exe",   L"elevate.exe",       L"potato.exe",
};
#define LPD_POTATO_BINARY_COUNT \
    (sizeof(g_LpdPotatoBinaries) / sizeof(g_LpdPotatoBinaries[0]))

/* Potato 管道名特征 (SS m_suspiciousPipeNames) */
static const PCWSTR g_LpdSuspiciousPipeNames[] = {
    L"potato", L"msagent", L"genericgodpotato", L"juicypotato",
    L"roguepotato", L"sweetpotato", L"PrintSpoofer",
};
#define LPD_PIPE_NAME_COUNT \
    (sizeof(g_LpdSuspiciousPipeNames) / sizeof(g_LpdSuspiciousPipeNames[0]))

/* 自动提升二进制白名单 (SS AUTO_ELEVATE_BINARIES) */
static const PCWSTR g_LpdAutoElevateBinaries[] = {
    L"wusa.exe", L"pkgmgr.exe", L"spinstall.exe", L"cliconfg.exe",
};
#define LPD_AUTO_ELEVATE_COUNT \
    (sizeof(g_LpdAutoElevateBinaries) / sizeof(g_LpdAutoElevateBinaries[0]))

/* COM UAC 绕过键 (SS DetectCOMBypasses comBypassKeys) */
static const PCWSTR g_LpdComBypassKeys[] = {
    L"Software\\Classes\\CLSID\\{3E5FC7F9-9A51-4367-9063-A120244FBEC7}",  /* fodhelper CLSID */
    L"Software\\Classes\\CLSID\\{D5ED91F7-3E42-41C6-A5A0-57D177878115}",  /* eventvwr CLSID */
    L"Software\\Classes\\ms-settings\\Shell\\Open\\command",               /* ms-settings */
    L"Software\\Classes\\mscfile\\shell\\open\\command",                   /* mscfile */
    L"Software\\Classes\\Folder\\shell\\open\\command",                    /* Folder (ComputerDefaults) */
    L"Software\\Classes\\exefile\\shell\\runas\\command",                  /* exefile elevation */
};
#define LPD_COM_BYPASS_KEY_COUNT \
    (sizeof(g_LpdComBypassKeys) / sizeof(g_LpdComBypassKeys[0]))

/**************************************************/
/*               内部辅助函数                       */
/**************************************************/

static
VOID
Lpd_GetTimestamp(
    _Out_ PLARGE_INTEGER Timestamp
    )
/*++
Routine Description:
    获取当前系统时间 (100ns 间隔, FILETIME 语义)。
--*/
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    Timestamp->LowPart = ft.dwLowDateTime;
    Timestamp->HighPart = ft.dwHighDateTime;
}

static
VOID
Lpd_InitEvent(
    _Out_ PLPD_EVENT Evt,
    _In_  LPD_TECHNIQUE Technique,
    _In_  ULONG ConfidenceScore
    )
/*++
Routine Description:
    初始化事件公共字段 (序号/技术/置信度/时间/计数)。
--*/
{
    RtlZeroMemory(Evt, sizeof(*Evt));
    Evt->EventId = (ULONG)InterlockedIncrement(&g_Lpd.EventSequence);
    Evt->Technique = Technique;
    Evt->ConfidenceScore = ConfidenceScore;
    Lpd_GetTimestamp(&Evt->Timestamp);
}

/*
 * Lpd_PublishEvent — 事件发射:
 *   写入调用者缓冲 (受 MaxEvents 约束) + 实时回调 + 统计。
 * 返回 1 (每事件), 供调用方累计命中总数。
 */
static
ULONG
Lpd_PublishEvent(
    _Inout_ PLPD_EVENT  Evt,
    _Out_writes_to_opt_(MaxEvents, *pWritten) PLPD_EVENT Events,
    _In_    ULONG                               MaxEvents,
    _Inout_ PULONG                              pWritten
    )
{
    InterlockedIncrement(&g_Lpd.Stats.EventsReported);

    if (Events && pWritten && *pWritten < MaxEvents) {
        Events[*pWritten] = *Evt;
        (*pWritten)++;
    }

    if (g_Lpd.Callback) {
        g_Lpd.Callback(Evt, g_Lpd.CallbackContext);
    }

    return 1;
}

static
BOOLEAN
Lpd_IsProcessWhitelisted(
    _In_ PCWSTR ProcessPath
    )
/*++
Routine Description:
    白名单子串匹配 (大小写不敏感), IsProcessWhitelisted。
--*/
{
    ULONG i;
    WCHAR lowerPath[DEF_MAX_PATH * 2];

    if (!ProcessPath || g_Lpd.Config.WhitelistCount == 0) {
        return FALSE;
    }

    wcscpy_s(lowerPath, ARRAYSIZE(lowerPath), ProcessPath);
    _wcslwr_s(lowerPath, ARRAYSIZE(lowerPath));

    for (i = 0; i < g_Lpd.Config.WhitelistCount; i++) {
        WCHAR lowerWl[DEF_MAX_PATH * 2];
        wcscpy_s(lowerWl, ARRAYSIZE(lowerWl),
                 g_Lpd.Config.WhitelistedProcesses[i]);
        _wcslwr_s(lowerWl, ARRAYSIZE(lowerWl));

        if (wcsstr(lowerPath, lowerWl) != NULL) {
            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
Lpd_IsPrivilegedAccount(
    _In_ PCWSTR UserSid
    )
/*++
Routine Description:
    判 SID 是否属特权账户 (SYSTEM/LOCAL SERVICE/NETWORK SERVICE/
    Administrators 组), IsPrivilegedAccount。
--*/
{
    if (!UserSid) return FALSE;

    return (wcsncmp(UserSid, L"S-1-5-18", 8) == 0) ||   /* SYSTEM */
           (wcsncmp(UserSid, L"S-1-5-19", 8) == 0) ||   /* LOCAL SERVICE */
           (wcsncmp(UserSid, L"S-1-5-20", 8) == 0) ||   /* NETWORK SERVICE */
           (wcsstr(UserSid, L"-544") != NULL);          /* Administrators */
}

static
VOID
Lpd_SidToString(
    _In_  PSID    Sid,
    _Out_writes_(BufferChars) PWSTR Buffer,
    _In_  ULONG   BufferChars
    )
/*++
Routine Description:
    SID → 字符串 (ConvertSidToStringSidW 封装)。
--*/
{
    LPWSTR sidStr = NULL;

    Buffer[0] = L'\0';
    if (!Sid || !IsValidSid(Sid)) return;

    if (ConvertSidToStringSidW(Sid, &sidStr) && sidStr) {
        wcscpy_s(Buffer, BufferChars, sidStr);
        LocalFree(sidStr);
    }
}

static
VOID
Lpd_StringToLower(
    _Inout_ PWSTR Str
    )
{
    if (Str) _wcslwr_s(Str, wcslen(Str) + 1);
}

/**************************************************/
/*               注册表读取辅助                     */
/**************************************************/

/*
 * Lpd_ReadRegStringValue — 读 REG_SZ / REG_EXPAND_SZ 值。
 * 返回 FALSE 表示键/值不存在或类型不符 (调用方按缺席处理)。
 */
static
BOOLEAN
Lpd_ReadRegStringValue(
    _In_  HKEY    RootKey,
    _In_  PCWSTR  SubKey,
    _In_  PCWSTR  ValueName,
    _Out_writes_(BufferChars) PWSTR Buffer,
    _In_  ULONG   BufferChars
    )
{
    HKEY hKey = NULL;
    LONG status;
    DWORD type = 0;
    DWORD cbData = 0;
    BOOLEAN ok = FALSE;
    PWSTR raw = NULL;

    if (!SubKey || !Buffer || BufferChars == 0) return FALSE;
    Buffer[0] = L'\0';

    status = RegOpenKeyExW(RootKey, SubKey, 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS) return FALSE;

    /* 先查询类型与大小 */
    if (RegQueryValueExW(hKey, ValueName, NULL, &type, NULL, &cbData)
            != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ) ||
        cbData < sizeof(WCHAR) || cbData > 64 * 1024) {
        RegCloseKey(hKey);
        return FALSE;
    }

    raw = (PWSTR)HeapAlloc(GetProcessHeap(), 0, cbData + sizeof(WCHAR));
    if (!raw) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RtlZeroMemory(raw, cbData + sizeof(WCHAR));

    if (RegQueryValueExW(hKey, ValueName, NULL, &type,
            (LPBYTE)raw, &cbData) == ERROR_SUCCESS) {
        raw[cbData / sizeof(WCHAR)] = L'\0';

        if (type == REG_EXPAND_SZ) {
            DWORD expanded = ExpandEnvironmentStringsW(raw, Buffer, BufferChars);
            ok = (expanded > 0 && expanded <= BufferChars);
        } else {
            wcscpy_s(Buffer, BufferChars, raw);
            ok = TRUE;
        }
    }

    HeapFree(GetProcessHeap(), 0, raw);
    RegCloseKey(hKey);
    return ok;
}

static
BOOLEAN
Lpd_ReadRegDword(
    _In_  HKEY    RootKey,
    _In_  PCWSTR  SubKey,
    _In_  PCWSTR  ValueName,
    _Out_ PDWORD  pValue
    )
{
    HKEY hKey = NULL;
    LONG status;
    DWORD type = 0;
    DWORD cbData = sizeof(DWORD);
    DWORD value = 0;
    BOOLEAN ok = FALSE;

    if (!SubKey || !pValue) return FALSE;

    status = RegOpenKeyExW(RootKey, SubKey, 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS) return FALSE;

    if (RegQueryValueExW(hKey, ValueName, NULL, &type,
            (LPBYTE)&value, &cbData) == ERROR_SUCCESS &&
        (type == REG_DWORD)) {
        *pValue = value;
        ok = TRUE;
    }

    RegCloseKey(hKey);
    return ok;
}

/**************************************************/
/*               二进制路径提取                     */
/**************************************************/

static
VOID
Lpd_ExtractBinaryPath(
    _In_  PCWSTR CommandLine,
    _Out_writes_(BufferChars) PWSTR Buffer,
    _In_  ULONG  BufferChars
    )
/*++
Routine Description:
    从服务命令行提取二进制路径 (CommandLineToArgvW 正规解析),
    ExtractBinaryPath。
--*/
{
    int argc = 0;
    LPWSTR* argv = NULL;

    Buffer[0] = L'\0';
    if (!CommandLine || BufferChars == 0) return;

    argv = CommandLineToArgvW(CommandLine, &argc);
    if (!argv || argc == 0) {
        if (argv) LocalFree(argv);
        wcscpy_s(Buffer, BufferChars, CommandLine);  /* 解析失败回退原串 */
        return;
    }

    wcscpy_s(Buffer, BufferChars, argv[0]);
    LocalFree(argv);
}

/**************************************************/
/*               ACL 写检查                        */
/**************************************************/

static
BOOLEAN
Lpd_CheckAclWriteForSid(
    _In_ PACL Dacl,
    _In_ PSID Sid,
    _In_ BOOLEAN AllowUsersGroupOnlyWriteData
    )
/*++
Routine Description:
    检查指定 SID 在 DACL 中是否具备写/改权限。
    CheckDirectoryWriteACL 的 GetEffectiveRightsFromAclW 判定。
--*/
{
    TRUSTEE_W trustee = { 0 };
    ACCESS_MASK accessMask = 0;

    trustee.TrusteeForm = TRUSTEE_IS_SID;
    trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    trustee.ptstrName = (LPWSTR)Sid;

    if (GetEffectiveRightsFromAclW(Dacl, &trustee, &accessMask)
            != ERROR_SUCCESS) {
        return FALSE;
    }

    if (AllowUsersGroupOnlyWriteData) {
        /* BUILTIN\Users: 仅需写数据即可判定 (SS 行2817 措辞更严) */
        return (accessMask & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;
    }

    return (accessMask & (FILE_WRITE_DATA | FILE_APPEND_DATA |
                          WRITE_DAC | WRITE_OWNER)) != 0;
}

static
BOOLEAN
Lpd_CheckDirectoryWriteACL(
    _In_ PCWSTR DirectoryPath
    )
/*++
Routine Description:
    目录写权限 ACL 检查 (Everyone / Authenticated Users / Users),
    无文件创建副作用, CheckDirectoryWriteACL。
--*/
{
    PACL pDacl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD result;
    BOOLEAN vulnerable = FALSE;

    if (!DirectoryPath) return FALSE;

    result = GetNamedSecurityInfoW(
        DirectoryPath, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, &pDacl, NULL, &pSD);

    if (result != ERROR_SUCCESS || !pDacl) {
        if (pSD) LocalFree(pSD);
        return FALSE;
    }

    /* Everyone (S-1-1-0) */
    {
        PSID pEveryone = NULL;
        SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
        if (AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID,
                0, 0, 0, 0, 0, 0, 0, &pEveryone)) {
            if (Lpd_CheckAclWriteForSid(pDacl, pEveryone, FALSE)) {
                vulnerable = TRUE;
            }
            FreeSid(pEveryone);
        }
    }

    /* Authenticated Users (S-1-5-11) */
    if (!vulnerable) {
        PSID pAuthUsers = NULL;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&ntAuth, 1, SECURITY_AUTHENTICATED_USER_RID,
                0, 0, 0, 0, 0, 0, 0, &pAuthUsers)) {
            if (Lpd_CheckAclWriteForSid(pDacl, pAuthUsers, FALSE)) {
                vulnerable = TRUE;
            }
            FreeSid(pAuthUsers);
        }
    }

    /* BUILTIN\Users (S-1-5-32-545) */
    if (!vulnerable) {
        PSID pUsers = NULL;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &pUsers)) {
            if (Lpd_CheckAclWriteForSid(pDacl, pUsers, TRUE)) {
                vulnerable = TRUE;
            }
            FreeSid(pUsers);
        }
    }

    if (pSD) LocalFree(pSD);
    return vulnerable;
}

/* DLL 劫持: 二进制文件自身弱 ACL (Users 可写) */
static
BOOLEAN
Lpd_CheckFileWeakAcl(
    _In_ PCWSTR FilePath
    )
/*++
Routine Description:
    检查二进制文件本身是否 BUILTIN\Users 可修改 (弱 ACL),
    AnalyzeService 的文件 ACL 分支。
--*/
{
    PACL pDacl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD result;
    BOOLEAN weak = FALSE;

    if (!FilePath) return FALSE;

    result = GetNamedSecurityInfoW(
        FilePath, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, &pDacl, NULL, &pSD);

    if (result != ERROR_SUCCESS || !pDacl) {
        if (pSD) LocalFree(pSD);
        return FALSE;
    }

    {
        PSID pUsers = NULL;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                DOMAIN_ALIAS_RID_USERS, 0, 0, 0, 0, 0, 0, &pUsers)) {
            weak = Lpd_CheckAclWriteForSid(pDacl, pUsers, FALSE);
            FreeSid(pUsers);
        }
    }

    if (pSD) LocalFree(pSD);
    return weak;
}

/**************************************************/
/*               进程特权检查                       */
/**************************************************/

static
BOOLEAN
Lpd_ProcessHasEnabledPrivilege(
    _In_ ULONG   ProcessId,
    _In_ PCWSTR TargetPrivilege
    )
/*++
Routine Description:
    检查进程令牌是否启用指定特权 (如 SeImpersonatePrivilege)。
    DetectPotatoAttacks 的令牌遍历分支。
--*/
{
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    DWORD cbSize = 0;
    BOOLEAN has = FALSE;

    if (!TargetPrivilege) return FALSE;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (!hProcess) return FALSE;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    /* 尺寸探测: 必须 ERROR_INSUFFICIENT_BUFFER 且 0 < cbSize <= 1MB */
    if (GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &cbSize) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        cbSize == 0 || cbSize > (1u << 20)) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    {
        PTOKEN_PRIVILEGES pPrivs =
            (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), 0, cbSize);
        if (pPrivs) {
            if (GetTokenInformation(hToken, TokenPrivileges,
                    pPrivs, cbSize, &cbSize)) {
                ULONG i;
                for (i = 0; i < pPrivs->PrivilegeCount; i++) {
                    WCHAR privName[256];
                    DWORD nameLen = ARRAYSIZE(privName);
                    if (LookupPrivilegeNameW(NULL,
                            &pPrivs->Privileges[i].Luid,
                            privName, &nameLen) &&
                        _wcsicmp(privName, TargetPrivilege) == 0 &&
                        (pPrivs->Privileges[i].Attributes &
                         SE_PRIVILEGE_ENABLED)) {
                        has = TRUE;
                        break;
                    }
                }
            }
            HeapFree(GetProcessHeap(), 0, pPrivs);
        }
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);
    return has;
}

/**************************************************/
/*               自动响应                           */
/**************************************************/

static
VOID
Lpd_RespondToHighConfidence(
    _Inout_ PLPD_EVENT Event
    )
/*++
Routine Description:
    高置信度自动响应 (RespondToHighConfidenceDetection):
    置信度 >= 阈值 && TerminateOnHighConfidence && 非白名单
    → 终止嫌疑进程。
--*/
{
    HANDLE hProcess;

    if (!g_Lpd.Config.BlockOnDetection ||
        !g_Lpd.Config.TerminateOnHighConfidence) {
        return;
    }

    if (Event->ConfidenceScore < LPD_AUTO_BLOCK_THRESHOLD) return;

    if (Event->ProcessPath[0] != L'\0' &&
        Lpd_IsProcessWhitelisted(Event->ProcessPath)) {
        return;
    }

    if (Event->ProcessId == 0) return;

    hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, Event->ProcessId);
    if (hProcess) {
        if (TerminateProcess(hProcess, 1)) {
            Event->WasBlocked = TRUE;
            InterlockedIncrement(&g_Lpd.Stats.EscalationsBlocked);
            InterlockedIncrement(&g_Lpd.Stats.ProcessesTerminated);
        }
        CloseHandle(hProcess);
    }
}

/**************************************************/
/*               UAC 绕过检测                       */
/**************************************************/

/* fodhelper 绕过键 */
#define LPD_UAC_FODHELPER_KEY \
    L"Software\\Classes\\ms-settings\\Shell\\Open\\command"
/* eventvwr 绕过键 */
#define LPD_UAC_EVENTVWR_KEY \
    L"Software\\Classes\\mscfile\\shell\\open\\command"
/* computerdefaults 绕过键 */
#define LPD_UAC_COMPDEF_KEY \
    L"Software\\Classes\\Folder\\shell\\open\\command"

/*
 * Lpd_CheckUacBypassKey — 检查 HKCU 注册表键是否被注入命令。
 * 键下 (Default) 值非空即认为被劫持 (DetectUACBypasses)。
 */
static
BOOLEAN
Lpd_CheckUacBypassKey(
    _In_  PCWSTR SubKey,
    _Out_writes_(BufferChars) PWSTR Buffer,
    _In_  ULONG  BufferChars
    )
{
    return Lpd_ReadRegStringValue(HKEY_CURRENT_USER, SubKey, L"", Buffer,
                                  BufferChars);
}

ULONG
LpdDetectUacBypasses(
    _Out_writes_to_opt_(MaxEvents, *pReturned) PLPD_EVENT Events,
    _In_                               ULONG       MaxEvents,
    _Out_opt_                          PULONG      pReturned
    )
/*++
Routine Description:
    检测 UAC 绕过注册表注入:
      1. fodhelper / eventvwr / computerdefaults 三键 (Default) 值劫持;
      2. 全表 UAC_BYPASS_PATHS 遍历 (统计级告警)。
    DetectUACBypasses + MonitorUacBypassPoints。

Arguments:
    Events    — 事件缓冲 (可空, 仅回调模式)。
    MaxEvents — 缓冲容量。
    pReturned — 已写缓冲数 (可空)。

Return Value:
    命中事件总数 (含回调)。
--*/
{
    ULONG total = 0;
    ULONG written = 0;
    WCHAR value[DEF_MAX_PATH * 4];

    UNREFERENCED_PARAMETER(Events);   /* 经 Lpd_PublishEvent 统一写入 */

    if (!g_Lpd.Initialized || !g_Lpd.Config.MonitorUacBypass) return 0;

    /* 全表遍历: 存在非空值即视为可疑 (统计级) */
    {
        ULONG i;
        for (i = 0; i < LPD_UAC_BYPASS_PATH_COUNT; i++) {
            if (Lpd_ReadRegStringValue(HKEY_CURRENT_USER,
                    g_LpdUacBypassPaths[i], L"",
                    value, ARRAYSIZE(value))) {
                InterlockedIncrement(&g_Lpd.Stats.UacBypassesDetected);
            }
        }
    }

    /* fodhelper */
    if (Lpd_CheckUacBypassKey(LPD_UAC_FODHELPER_KEY,
            value, ARRAYSIZE(value))) {
        LPD_EVENT evt;
        Lpd_InitEvent(&evt, LpdTech_FodhelperBypass,
                      LPD_CONFIDENCE_SCORE(LpdConf_VeryHigh));
        wcscpy_s(evt.TargetRegistryKey, ARRAYSIZE(evt.TargetRegistryKey),
                 LPD_UAC_FODHELPER_KEY);
        swprintf_s(evt.Details, ARRAYSIZE(evt.Details),
                   L"Fodhelper.exe UAC bypass (command: %s)", value);
        InterlockedIncrement(&g_Lpd.Stats.UacBypassesDetected);
        total += Lpd_PublishEvent(&evt, Events, MaxEvents, &written);
        Lpd_RespondToHighConfidence(&evt);
    }

    /* eventvwr */
    if (Lpd_CheckUacBypassKey(LPD_UAC_EVENTVWR_KEY,
            value, ARRAYSIZE(value))) {
        LPD_EVENT evt;
        Lpd_InitEvent(&evt, LpdTech_EventViewerBypass,
                      LPD_CONFIDENCE_SCORE(LpdConf_VeryHigh));
        wcscpy_s(evt.TargetRegistryKey, ARRAYSIZE(evt.TargetRegistryKey),
                 LPD_UAC_EVENTVWR_KEY);
        swprintf_s(evt.Details, ARRAYSIZE(evt.Details),
                   L"Event Viewer UAC bypass (command: %s)", value);
        InterlockedIncrement(&g_Lpd.Stats.UacBypassesDetected);
        total += Lpd_PublishEvent(&evt, Events, MaxEvents, &written);
        Lpd_RespondToHighConfidence(&evt);
    }

    /* computerdefaults */
    if (Lpd_CheckUacBypassKey(LPD_UAC_COMPDEF_KEY,
            value, ARRAYSIZE(value))) {
        LPD_EVENT evt;
        Lpd_InitEvent(&evt, LpdTech_ComputerDefaultsBypass,
                      LPD_CONFIDENCE_SCORE(LpdConf_VeryHigh));
        wcscpy_s(evt.TargetRegistryKey, ARRAYSIZE(evt.TargetRegistryKey),
                 LPD_UAC_COMPDEF_KEY);
        swprintf_s(evt.Details, ARRAYSIZE(evt.Details),
                   L"ComputerDefaults UAC bypass (command: %s)", value);
        InterlockedIncrement(&g_Lpd.Stats.UacBypassesDetected);
        total += Lpd_PublishEvent(&evt, Events, MaxEvents, &written);
        Lpd_RespondToHighConfidence(&evt);
    }

    if (pReturned) *pReturned = written;
    return total;
}

/**************************************************/
/*               COM UAC 绕过检测                  */
/**************************************************/

ULONG
LpdDetectComBypasses(
    _Out_writes_to_opt_(MaxEvents, *pReturned) PLPD_EVENT Events,
    _In_                               ULONG       MaxEvents,
    _Out_opt_                          PULONG      pReturned
    )
/*++
Routine Description:
    检测 COM 对象 UAC 绕过:
      1. HKCU 下 comBypassKeys 键 (Default)/DelegateExecute 劫持;
      2. DelegateExecute 清空 + command 置位 (激活载荷);
      3. 自动提升二进制从非标准路径运行。
    DetectCOMBypasses。

Return Value:
    命中事件总数 (含回调)。
--*/
{
    ULONG total = 0;
    ULONG written = 0;
    ULONG i;

    UNREFERENCED_PARAMETER(Events);

    if (!g_Lpd.Initialized || !g_Lpd.Config.DetectComBypass) return 0;

    /* 1. COM 键 (Default)/DelegateExecute 劫持 */
    for (i = 0; i < LPD_COM_BYPASS_KEY_COUNT; i++) {
        HKEY hKey = NULL;
        WCHAR defaultVal[DEF_MAX_PATH * 4] = { 0 };
        DWORD cbSize = sizeof(defaultVal);
        DWORD type = 0;
        BOOLEAN hit = FALSE;

        if (RegOpenKeyExW(HKEY_CURRENT_USER, g_LpdComBypassKeys[i], 0,
                KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS) {
            continue;
        }

        if (RegQueryValueExW(hKey, L"", NULL, &type,
                (LPBYTE)defaultVal, &cbSize) == ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ) &&
            defaultVal[0] != L'\0') {
            hit = TRUE;
        }

        RegCloseKey(hKey);

        if (hit) {
            LPD_EVENT evt;
            Lpd_InitEvent(&evt, LpdTech_UacBypassCom,
                          LPD_CONFIDENCE_SCORE(LpdConf_VeryHigh));
            wcscpy_s(evt.TargetRegistryKey, ARRAYSIZE(evt.TargetRegistryKey),
                     g_LpdComBypassKeys[i]);
            swprintf_s(evt.Details, ARRAYSIZE(evt.Details),
                       L"COM UAC bypass key under HKCU: %s",
                       g_LpdComBypassKeys[i]);
            InterlockedIncrement(&g_Lpd.Stats.ComBypassesDetected);
            total += Lpd_PublishEvent(&evt, Events, MaxEvents, &written);
            Lpd_RespondToHighConfidence(&evt);
        }
    }

    /* 2. DelegateExecute 清空 + command 置位 (激活载荷) */
    for (i = 0; i < LPD_COM_BYPASS_KEY_COUNT; i++) {
        WCHAR fullKey[DEF_MAX_PATH * 4];
        HKEY hKey = NULL;
        WCHAR delegate[256] = { 0 };
        DWORD delegateSize = sizeof(delegate);
        DWORD dummyType = 0;
        WCHAR cmdVal[DEF_MAX_PATH * 4] = { 0 };
        DWORD cmdSize = sizeof(cmdVal);
        BOOLEAN delegateCleared = FALSE;

        swprintf_s(fullKey, ARRAYSIZE(fullKey), L"%s\\Shell\\Open\\command",
                   g_LpdComBypassKeys[i]);

        if (RegOpenKeyExW(HKEY_CURRENT_USER, fullKey, 0,
                KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS) {
            continue;
        }

        if (RegQueryValueExW(hKey, L"DelegateExecute", NULL, &dummyType,
                (LPBYTE)delegate, &delegateSize) == ERROR_SUCCESS &&
            delegateSize <= sizeof(WCHAR) && delegate[0] == L'\0') {
            delegateCleared = TRUE;
        }

        if (delegateCleared &&
            RegQueryValueExW(hKey, L"", NULL, &dummyType,
                (LPBYTE)cmdVal, &cmdSize) == ERROR_SUCCESS &&
            cmdVal[0] != L'\0') {
            LPD_EVENT evt;
            Lpd_InitEvent(&evt, LpdTech_FodhelperBypass,
                          LPD_CONFIDENCE_SCORE(LpdConf_Confirmed));
            wcscpy_s(evt.TargetRegistryKey, ARRAYSIZE(evt.TargetRegistryKey),
                     fullKey);
            swprintf_s(evt.Details, ARRAYSIZE(evt.Details),
                       L"DelegateExecute suppressed + command set: %s",
                       cmdVal);
            InterlockedIncrement(&g_Lpd.Stats.ComBypassesDetected);
            total += Lpd_PublishEvent(&evt, Events, MaxEvents, &written);
            Lpd_RespondToHighConfidence(&evt);
        }

        RegCloseKey(hKey);
    }

    /* 3. 自动提升二进制从非标准路径运行 (LOLBins 滥用) */
    {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe32 = { 0 };
            pe32.dwSize = sizeof(pe32);

            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    WCHAR lowerName[DEF_MAX_IMAGE_NAME];
                    ULONG j;
                    BOOLEAN isAutoElevate = FALSE;

                    wcscpy_s(lowerName, ARRAYSIZE(lowerName), pe32.szExeFile);
                    Lpd_StringToLower(lowerName);

                    for (j = 0; j < LPD_AUTO_ELEVATE_COUNT; j++) {
                        if (_wcsicmp(lowerName, g_LpdAutoElevateBinaries[j])
                                == 0) {
                            isAutoElevate = TRUE;
                            break;
                        }
                    }

                    if (isAutoElevate) {
                        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION,
                                                   FALSE, pe32.th32ProcessID);
                        if (hProc) {
                            WCHAR procPath[DEF_MAX_PATH * 2] = { 0 };
                            WCHAR lowerPath[DEF_MAX_PATH * 2];
                            DWORD pathLen = ARRAYSIZE(procPath);

                            if (QueryFullProcessImageNameW(hProc, 0,
                                    procPath, &pathLen)) {
                                wcscpy_s(lowerPath, ARRAYSIZE(lowerPath),
                                         procPath);
                                Lpd_StringToLower(lowerPath);

                                /* 合法路径仅限 System32/SysWOW64/WinSxS */
                                if (wcsstr(lowerPath, L"\\windows\\system32\\")
                                        == NULL &&
                                    wcsstr(lowerPath, L"\\windows\\syswow64\\")
                                        == NULL &&
                                    wcsstr(lowerPath, L"\\windows\\winsxs\\")
                                        == NULL) {
                                    LPD_EVENT evt;
                                    Lpd_InitEvent(&evt,
                                        LpdTech_UacBypassAutoElevate,
                                        LPD_CONFIDENCE_SCORE(LpdConf_High));
                                    evt.ProcessId = pe32.th32ProcessID;
                                    wcscpy_s(evt.ProcessName,
                                             ARRAYSIZE(evt.ProcessName),
                                             pe32.szExeFile);
                                    wcscpy_s(evt.ProcessPath,
                                             ARRAYSIZE(evt.ProcessPath),
                                             procPath);
                                    wcscpy_s(evt.TargetFilePath,
                                             ARRAYSIZE(evt.TargetFilePath),
                                             procPath);
                                    swprintf_s(evt.Details,
                                               ARRAYSIZE(evt.Details),
                                               L"Auto-elevate binary from "
                                               L"suspicious path");
                                    InterlockedIncrement(
                                        &g_Lpd.Stats.ComBypassesDetected);
                                    total += Lpd_PublishEvent(&evt, Events,
                                        MaxEvents, &written);
                                    Lpd_RespondToHighConfidence(&evt);
                                }
                            }
                            CloseHandle(hProc);
                        }
                    }
                } while (Process32NextW(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
    }

    if (pReturned) *pReturned = written;
    return total;
}

/**************************************************/
/*               Potato 家族检测                   */
/**************************************************/

ULONG
LpdDetectPotatoAttacks(
    _Out_writes_to_opt_(MaxEvents, *pReturned) PLPD_EVENT Events,
    _In_                               ULONG       MaxEvents,
    _Out_opt_                          PULONG      pReturned
    )
/*++
Routine Description:
    检测 Potato 家族提权攻击:
      进程名命中已知 Potato 二进制 + 令牌启用 SeImpersonatePrivilege。
    DetectPotatoAttacks (不含 ThreatIntel 哈希查证)。

Return Value:
    命中事件总数 (含回调)。
--*/
{
    ULONG total = 0;
    ULONG written = 0;
    HANDLE hSnapshot;

    UNREFERENCED_PARAMETER(Events);

    if (!g_Lpd.Initialized || !g_Lpd.Config.DetectPotato) return 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    {
        PROCESSENTRY32W pe32 = { 0 };
        pe32.dwSize = sizeof(pe32);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                WCHAR lowerName[DEF_MAX_IMAGE_NAME];
                ULONG j;
                BOOLEAN isPotato = FALSE;

                wcscpy_s(lowerName, ARRAYSIZE(lowerName), pe32.szExeFile);
                Lpd_StringToLower(lowerName);

                for (j = 0; j < LPD_POTATO_BINARY_COUNT; j++) {
                    if (wcsstr(lowerName, g_LpdPotatoBinaries[j]) != NULL) {
                        isPotato = TRUE;
                        break;
                    }
                }

                if (!isPotato) continue;

                /* Potato 家族先决条件: SeImpersonatePrivilege 启用 */
                if (!Lpd_ProcessHasEnabledPrivilege(pe32.th32ProcessID,
                        L"SeImpersonatePrivilege")) {
                    continue;
                }

                {
                    LPD_EVENT evt;
                    const WCHAR* variantName = L"Potato Family Attack";

                    Lpd_InitEvent(&evt, LpdTech_PotatoAttack,
                                  LPD_CONFIDENCE_SCORE(LpdConf_VeryHigh));
                    evt.ProcessId = pe32.th32ProcessID;
                    wcscpy_s(evt.ProcessName, ARRAYSIZE(evt.ProcessName),
                             pe32.szExeFile);
                    swprintf_s(evt.Details, ARRAYSIZE(evt.Details),
                               L"Potato binary with SeImpersonatePrivilege: %s",
                               pe32.szExeFile);

                    /* 细分变体 (m_knownPotatoBinaries 分支) */
                    if (wcsstr(lowerName, L"juicy") != NULL) {
                        variantName = L"JuicyPotato";
                    } else if (wcsstr(lowerName, L"rogue") != NULL) {
                        variantName = L"RoguePotato";
                    } else if (wcsstr(lowerName, L"sweet") != NULL) {
                        variantName = L"SweetPotato";
                    } else if (wcsstr(lowerName, L"printspoofer") != NULL) {
                        variantName = L"PrintSpoofer";
                    }

                    swprintf_s(evt.Details, ARRAYSIZE(evt.Details),
                               L"%s (SeImpersonatePrivilege enabled)",
                               variantName);

                    /* 尝试取映像全路径 */
                    {
                        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION,
                                                   FALSE, pe32.th32ProcessID);
                        if (hProc) {
                            WCHAR procPath[DEF_MAX_PATH * 2] = { 0 };
                            DWORD pathLen = ARRAYSIZE(procPath);
                            if (QueryFullProcessImageNameW(hProc, 0,
                                    procPath, &pathLen)) {
                                wcscpy_s(evt.ProcessPath,
                                         ARRAYSIZE(evt.ProcessPath), procPath);
                                wcscpy_s(evt.TargetFilePath,
                                         ARRAYSIZE(evt.TargetFilePath),
                                         procPath);
                            }
                            CloseHandle(hProc);
                        }
                    }

                    InterlockedIncrement(&g_Lpd.Stats.PotatoAttacksDetected);
                    total += Lpd_PublishEvent(&evt, Events, MaxEvents,
                                              &written);
                    Lpd_RespondToHighConfidence(&evt);
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
    }

    CloseHandle(hSnapshot);

    if (pReturned) *pReturned = written;
    return total;
}

/**************************************************/
/*               命名管道模拟检测                   */
/**************************************************/

static
BOOLEAN
Lpd_IsSuspiciousPipeName(
    _In_ PCWSTR PipeName
    )
/*++
Routine Description:
    管道名与 Potato 特征子串匹配, IsSuspiciousPipeName。
--*/
{
    ULONG i;
    WCHAR lower[DEF_MAX_PATH * 2];

    if (!PipeName) return FALSE;

    wcscpy_s(lower, ARRAYSIZE(lower), PipeName);
    Lpd_StringToLower(lower);

    for (i = 0; i < LPD_PIPE_NAME_COUNT; i++) {
        if (wcsstr(lower, g_LpdSuspiciousPipeNames[i]) != NULL) {
            return TRUE;
        }
    }

    return FALSE;
}

ULONG
LpdDetectNamedPipeImpersonation(
    _Out_writes_to_opt_(MaxEvents, *pReturned) PLPD_EVENT Events,
    _In_                               ULONG       MaxEvents,
    _Out_opt_                          PULONG      pReturned
    )
/*++
Routine Description:
    检测可疑命名管道 (Potato 特征名 + 非特权属主)。
    DetectNamedPipeImpersonation。

Return Value:
    命中事件总数 (含回调)。
--*/
{
    ULONG total = 0;
    ULONG written = 0;
    WIN32_FIND_DATAW findData = { 0 };
    HANDLE hFind;

    UNREFERENCED_PARAMETER(Events);

    if (!g_Lpd.Initialized || !g_Lpd.Config.DetectNamedPipe) return 0;

    hFind = FindFirstFileW(L"\\\\.\\pipe\\*", &findData);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        WCHAR fullName[DEF_MAX_PATH * 2];
        HANDLE hPipe;

        swprintf_s(fullName, ARRAYSIZE(fullName), L"\\\\.\\pipe\\%s",
                   findData.cFileName);

        if (!Lpd_IsSuspiciousPipeName(fullName)) continue;

        /* 打开管道查其安全描述符属主 */
        hPipe = CreateFileW(fullName, GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe == INVALID_HANDLE_VALUE) continue;

        {
            PSECURITY_DESCRIPTOR pSD = NULL;
            if (GetSecurityInfo(hPipe, SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    NULL, NULL, NULL, NULL, &pSD) == ERROR_SUCCESS && pSD) {
                PSID ownerSid = NULL;
                BOOL hasOwner = FALSE;

                if (GetSecurityDescriptorOwner(pSD, &ownerSid, &hasOwner) &&
                    ownerSid) {
                    WCHAR ownerSidStr[256];
                    Lpd_SidToString(ownerSid, ownerSidStr,
                                    ARRAYSIZE(ownerSidStr));

                    /* 非特权账户创建的 Potato 特征管道 = 可疑 */
                    if (!Lpd_IsPrivilegedAccount(ownerSidStr)) {
                        LPD_EVENT evt;
                        Lpd_InitEvent(&evt, LpdTech_NamedPipeImpersonation,
                                      LPD_CONFIDENCE_SCORE(LpdConf_High));
                        wcscpy_s(evt.TargetFilePath,
                                 ARRAYSIZE(evt.TargetFilePath), fullName);
                        swprintf_s(evt.Details, ARRAYSIZE(evt.Details),
                                   L"Suspicious named pipe owned by %s",
                                   ownerSidStr);
                        InterlockedIncrement(
                            &g_Lpd.Stats.NamedPipeImpersonations);
                        total += Lpd_PublishEvent(&evt, Events, MaxEvents,
                                                  &written);
                        Lpd_RespondToHighConfidence(&evt);
                    }
                }
                LocalFree(pSD);
            }
        }

        CloseHandle(hPipe);
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);

    if (pReturned) *pReturned = written;
    return total;
}

/**************************************************/
/*               服务漏洞分析                       */
/**************************************************/

NTSTATUS
LpdAnalyzeService(
    _In_  PCWSTR           ServiceName,
    _Out_ PLPD_SERVICE_INFO Info
    )
/*++
Routine Description:
    分析单个服务漏洞: 未加引号路径 / 可写目录 / 弱文件 ACL。
    AnalyzeService。

Arguments:
    ServiceName — 服务名 (lpServiceName)。
    Info        — 输出服务安全信息。

Return Value:
    STATUS_SUCCESS 分析完成;
    STATUS_NOT_FOUND 服务无法打开;
    其他 NTSTATUS 失败。
--*/
{
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    DWORD bytesNeeded = 0;
    NTSTATUS ret = STATUS_SUCCESS;

    if (!ServiceName || !Info) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Info, sizeof(*Info));

    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) return STATUS_ACCESS_DENIED;

    hService = OpenServiceW(hSCManager, ServiceName,
                            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return STATUS_NOT_FOUND;
    }

    wcscpy_s(Info->ServiceName, ARRAYSIZE(Info->ServiceName), ServiceName);

    /* 尺寸探测: 必须 ERROR_INSUFFICIENT_BUFFER 且 0 < bytes <= 1MB */
    bytesNeeded = 0;
    if (QueryServiceConfigW(hService, NULL, 0, &bytesNeeded) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        bytesNeeded == 0 || bytesNeeded > (1u << 20)) {
        ret = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    {
        LPQUERY_SERVICE_CONFIGW pConfig =
            (LPQUERY_SERVICE_CONFIGW)HeapAlloc(GetProcessHeap(), 0,
                                               bytesNeeded);
        if (!pConfig) {
            ret = STATUS_NO_MEMORY;
            goto Done;
        }

        if (QueryServiceConfigW(hService, pConfig, bytesNeeded,
                &bytesNeeded)) {
            Info->StartType = pConfig->dwStartType;
            Info->ServiceType = pConfig->dwServiceType;
            if (pConfig->lpBinaryPathName) {
                wcscpy_s(Info->BinaryPath, ARRAYSIZE(Info->BinaryPath),
                         pConfig->lpBinaryPathName);
            }
            if (pConfig->lpDisplayName) {
                wcscpy_s(Info->DisplayName, ARRAYSIZE(Info->DisplayName),
                         pConfig->lpDisplayName);
            }
            if (pConfig->lpServiceStartName) {
                wcscpy_s(Info->RunAsAccount, ARRAYSIZE(Info->RunAsAccount),
                         pConfig->lpServiceStartName);
            }

            /* 未加引号路径: 提取二进制后含空格且未引用 */
            if (Info->BinaryPath[0] != L'\0') {
                WCHAR binaryOnly[DEF_MAX_PATH * 2];

                Lpd_ExtractBinaryPath(Info->BinaryPath, binaryOnly,
                                      ARRAYSIZE(binaryOnly));

                /* 未加引号: 首字符非引号且二进制路径含空格 */
                if (Info->BinaryPath[0] != L'"' &&
                    wcschr(binaryOnly, L' ') != NULL) {
                    Info->HasUnquotedPath = TRUE;
                    Info->Vulnerability = LpdSvcVuln_UnquotedPath;
                }

                /* 二进制存在 → 目录 ACL 与文件 ACL 检查 */
                if (binaryOnly[0] != L'\0' &&
                    GetFileAttributesW(binaryOnly) !=
                        INVALID_FILE_ATTRIBUTES) {
                    WCHAR dirPath[DEF_MAX_PATH * 2];
                    wcscpy_s(dirPath, ARRAYSIZE(dirPath), binaryOnly);
                    /* 去掉末尾文件名, 取父目录 */
                    {
                        PWSTR slash = wcsrchr(dirPath, L'\\');
                        if (slash) {
                            *slash = L'\0';
                        }
                    }

                    if (dirPath[0] != L'\0' &&
                        Lpd_CheckDirectoryWriteACL(dirPath)) {
                        Info->IsPathWritable = TRUE;
                        if (Info->Vulnerability == LpdSvcVuln_None) {
                            Info->Vulnerability = LpdSvcVuln_WritableDirectory;
                        }
                    }

                    if (Lpd_CheckFileWeakAcl(binaryOnly)) {
                        Info->IsPathWritable = TRUE;
                        Info->Vulnerability = LpdSvcVuln_WeakFilePermissions;
                    }
                }
            }
        }

        HeapFree(GetProcessHeap(), 0, pConfig);
    }

    /* 服务状态 */
    {
        SERVICE_STATUS_PROCESS statusProc = { 0 };
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
                (LPBYTE)&statusProc, sizeof(statusProc), &bytesNeeded)) {
            Info->CurrentState = statusProc.dwCurrentState;
        }
    }

Done:
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return ret;
}

ULONG
LpdScanServices(
    _Out_writes_to_opt_(MaxInfos, *pReturned) PLPD_SERVICE_INFO Infos,
    _In_                               ULONG              MaxInfos,
    _Out_opt_                          PULONG             pReturned
    )
/*++
Routine Description:
    枚举全部 Win32 服务并逐项分析, 输出存在漏洞的服务。
    ScanServices (枚举 + AnalyzeService 过滤漏洞)。

Return Value:
    有漏洞服务总数。
--*/
{
    ULONG total = 0;
    ULONG written = 0;
    SC_HANDLE hSCManager = NULL;
    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    UNREFERENCED_PARAMETER(Infos);

    if (!g_Lpd.Initialized || !g_Lpd.Config.MonitorServiceConfig) return 0;

    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) return 0;

    /* 尺寸探测: 必须 ERROR_MORE_DATA 且 bytesNeeded > 0 */
    if (EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32, SERVICE_STATE_ALL,
            NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL) ||
        GetLastError() != ERROR_MORE_DATA || bytesNeeded == 0) {
        CloseServiceHandle(hSCManager);
        return 0;
    }

    /* 恶意 SCM 响应防护: 上限 16MB */
    if (bytesNeeded > (16u * 1024u * 1024u)) {
        bytesNeeded = 16u * 1024u * 1024u;
    }

    {
        LPBYTE buffer = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, bytesNeeded);
        if (!buffer) {
            CloseServiceHandle(hSCManager);
            return 0;
        }

        if (EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32, SERVICE_STATE_ALL,
                buffer, bytesNeeded, &bytesNeeded, &servicesReturned,
                &resumeHandle, NULL)) {
            LPENUM_SERVICE_STATUS_PROCESSW pServices =
                (LPENUM_SERVICE_STATUS_PROCESSW)buffer;
            ULONG i;

            for (i = 0; i < servicesReturned; i++) {
                LPD_SERVICE_INFO info;
                if (NT_SUCCESS(LpdAnalyzeService(
                        pServices[i].lpServiceName, &info)) &&
                    info.Vulnerability != LpdSvcVuln_None) {

                    InterlockedIncrement(&g_Lpd.Stats.ServiceAbusesDetected);
                    total++;

                    if (Infos && written < MaxInfos) {
                        Infos[written] = info;
                        written++;
                    }
                }
            }
        }

        HeapFree(GetProcessHeap(), 0, buffer);
    }

    CloseServiceHandle(hSCManager);

    if (pReturned) *pReturned = written;
    return total;
}

/**************************************************/
/*               注册表滥用检测                     */
/**************************************************/

BOOLEAN
LpdIsAlwaysInstallElevatedEnabled(VOID)
/*++
Routine Description:
    检查 AlwaysInstallElevated (HKLM + HKCU 双 DWORD=1)。
    命中时产生 RegistryAlwaysInstall 事件 (统计语义,
    补全事件上报)。

Return Value:
    TRUE = 配置启用 (提权向量存在)。
--*/
{
    DWORD hklm = 0;
    DWORD hkcu = 0;
    BOOLEAN enabled;
    ULONG written = 0;

    if (!g_Lpd.Initialized) return FALSE;

    Lpd_ReadRegDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
        L"AlwaysInstallElevated", &hklm);
    Lpd_ReadRegDword(HKEY_CURRENT_USER,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
        L"AlwaysInstallElevated", &hkcu);

    enabled = (hklm == 1 && hkcu == 1);
    if (enabled) {
        LPD_EVENT evt;
        Lpd_InitEvent(&evt, LpdTech_RegistryAlwaysInstall,
                      LPD_CONFIDENCE_SCORE(LpdConf_High));
        wcscpy_s(evt.TargetRegistryKey, ARRAYSIZE(evt.TargetRegistryKey),
                 L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer");
        wcscpy_s(evt.Details, ARRAYSIZE(evt.Details),
                 L"AlwaysInstallElevated enabled (HKLM+HKCU) - LPE vector");
        InterlockedIncrement(&g_Lpd.Stats.RegistryAbusesDetected);
        Lpd_PublishEvent(&evt, NULL, 0, &written);
    }

    return enabled;
}

ULONG
LpdGetIfeoDebuggers(
    _Out_writes_to_opt_(MaxEntries, *pReturned) PLPD_IFEO_ENTRY Entries,
    _In_                               ULONG           MaxEntries,
    _Out_opt_                          PULONG          pReturned
    )
/*++
Routine Description:
    枚举 IFEO (HKLM + HKCU) 下的 Debugger 值。
    HKCU 条目 (标准用户可写) 额外产生 RegistryIFEO 事件。
    GetIFEODebuggers (含 GlobalFlag 告警)。

Return Value:
    Debugger 条目总数。
--*/
{
    ULONG total = 0;
    ULONG written = 0;

    UNREFERENCED_PARAMETER(Entries);

    if (!g_Lpd.Initialized || !g_Lpd.Config.MonitorIfeo) return 0;

    /* ◆ HKLM 分支 (第一段) */
    {
        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, LPD_IFEO_REGISTRY_PATH, 0,
                KEY_ENUMERATE_SUB_KEYS, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;

            while (index < LPD_MAX_IFEO_ENTRIES) {
                WCHAR subKeyName[256] = { 0 };
                DWORD nameLen = ARRAYSIZE(subKeyName);
                HKEY hSubKey = NULL;
                ULONG skip;
                BOOLEAN isSkip = FALSE;

                if (RegEnumKeyExW(hKey, index, subKeyName, &nameLen,
                        NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
                    break;
                }

                /* 跳过良性条目 */
                for (skip = 0; skip < LPD_IFEO_SKIP_COUNT; skip++) {
                    if (_wcsicmp(subKeyName, g_LpdIfeoSkipEntries[skip])
                            == 0) {
                        isSkip = TRUE;
                        break;
                    }
                }

                if (!isSkip &&
                    RegOpenKeyExW(hKey, subKeyName, 0,
                        KEY_QUERY_VALUE, &hSubKey) == ERROR_SUCCESS) {
                    WCHAR debuggerValue[DEF_MAX_PATH * 4] = { 0 };
                    DWORD dataSize = sizeof(debuggerValue);
                    DWORD dataType = 0;

                    if (RegQueryValueExW(hSubKey, L"Debugger", NULL,
                            &dataType, (LPBYTE)debuggerValue,
                            &dataSize) == ERROR_SUCCESS &&
                        dataType == REG_SZ && dataSize > sizeof(WCHAR)) {
                        if (Entries && written < MaxEntries) {
                            wcscpy_s(Entries[written].TargetExecutable,
                                     ARRAYSIZE(
                                        Entries[written].TargetExecutable),
                                     subKeyName);
                            wcscpy_s(Entries[written].Debugger,
                                     ARRAYSIZE(Entries[written].Debugger),
                                     debuggerValue);
                            Entries[written].FromHkcu = FALSE;
                            written++;
                        }
                        total++;
                        InterlockedIncrement(&g_Lpd.Stats.IfeoAbusesDetected);
                    }

                    /* GlobalFlag: FLG_MONITOR_SILENT_PROCESS_EXIT (0x200)
                     * Silent Process Exit 持久化告警 (对齐 SS) */
                    {
                        DWORD globalFlag = 0;
                        DWORD flagSize = sizeof(globalFlag);
                        DWORD flagType = 0;
                        if (RegQueryValueExW(hSubKey, L"GlobalFlag", NULL,
                                &flagType, (LPBYTE)&globalFlag,
                                &flagSize) == ERROR_SUCCESS &&
                            (globalFlag & 0x200)) {
                            InterlockedIncrement(
                                &g_Lpd.Stats.IfeoAbusesDetected);
                        }
                    }

                    RegCloseKey(hSubKey);
                }

                index++;
            }

            RegCloseKey(hKey);
        }
    }

    /* ◆ HKCU 分支 (标准用户可写 = 即时提权/持久化向量, 高危) */
    {
        HKEY hKeyCu = NULL;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, LPD_IFEO_REGISTRY_PATH, 0,
                KEY_ENUMERATE_SUB_KEYS, &hKeyCu) == ERROR_SUCCESS) {
            DWORD index = 0;

            while (index < LPD_MAX_IFEO_ENTRIES) {
                WCHAR subKeyName[256] = { 0 };
                DWORD nameLen = ARRAYSIZE(subKeyName);
                HKEY hSubKey = NULL;

                if (RegEnumKeyExW(hKeyCu, index, subKeyName, &nameLen,
                        NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
                    break;
                }

                if (RegOpenKeyExW(hKeyCu, subKeyName, 0,
                        KEY_QUERY_VALUE, &hSubKey) == ERROR_SUCCESS) {
                    WCHAR debuggerValue[DEF_MAX_PATH * 4] = { 0 };
                    DWORD dataSize = sizeof(debuggerValue);
                    DWORD dataType = 0;

                    if (RegQueryValueExW(hSubKey, L"Debugger", NULL,
                            &dataType, (LPBYTE)debuggerValue,
                            &dataSize) == ERROR_SUCCESS &&
                        dataType == REG_SZ && dataSize > sizeof(WCHAR)) {
                        if (Entries && written < MaxEntries) {
                            wcscpy_s(Entries[written].TargetExecutable,
                                     ARRAYSIZE(
                                        Entries[written].TargetExecutable),
                                     subKeyName);
                            wcscpy_s(Entries[written].Debugger,
                                     ARRAYSIZE(Entries[written].Debugger),
                                     debuggerValue);
                            Entries[written].FromHkcu = TRUE;
                            written++;
                        }
                        total++;
                        InterlockedIncrement(&g_Lpd.Stats.IfeoAbusesDetected);

                        /* HKCU IFEO = 高置信度事件 (行1956-1973) */
                        {
                            LPD_EVENT evt;
                            ULONG evtWritten = 0;
                            Lpd_InitEvent(&evt, LpdTech_RegistryIfeo,
                                LPD_CONFIDENCE_SCORE(LpdConf_VeryHigh));
                            swprintf_s(evt.TargetRegistryKey,
                                       ARRAYSIZE(evt.TargetRegistryKey),
                                       L"%s\\%s", LPD_IFEO_REGISTRY_PATH,
                                       subKeyName);
                            swprintf_s(evt.Details, ARRAYSIZE(evt.Details),
                                       L"HKCU IFEO debugger injection: %s -> %s",
                                       subKeyName, debuggerValue);
                            Lpd_PublishEvent(&evt, NULL, 0, &evtWritten);
                        }
                    }
                    RegCloseKey(hSubKey);
                }

                index++;
            }

            RegCloseKey(hKeyCu);
        }
    }

    if (pReturned) *pReturned = written;
    return total;
}

/**************************************************/
/*                DLL 劫持检测                     */
/**************************************************/

BOOLEAN
LpdIsDllHijackVulnerable(VOID)
/*++
Routine Description:
    检查常见 DLL 搜索路径劫持向量:
      1. Windows 目录 WriteDAC 可写 (经典提权);
      2. 进程环境块可信 DLL 路径可写 (仅当导出表含
         KnownDLLs 或 safe boot 未启用 — 判定);
      3. 当前目录可写 (AlwaysInstallElevated 场景辅助)。

Return Value:
    TRUE = 存在 DLL 劫持向量。
--*/
{
    BOOLEAN vulnerable = FALSE;
    ULONG written = 0;

    if (!g_Lpd.Initialized) return FALSE;

    /* 1. %WINDIR% WriteDAC 可写 → 任何系统账户进程可被劫持 */
    {
        WCHAR systemDir[DEF_MAX_PATH];
        if (GetSystemDirectoryW(systemDir, ARRAYSIZE(systemDir)) > 0 &&
            Lpd_CheckDirectoryWriteACL(systemDir)) {
            LPD_EVENT evt;
            Lpd_InitEvent(&evt, LpdTech_DllHijacking,
                          LPD_CONFIDENCE_SCORE(LpdConf_High));
            wcscpy_s(evt.TargetDirectory, ARRAYSIZE(evt.TargetDirectory),
                     systemDir);
            wcscpy_s(evt.Details, ARRAYSIZE(evt.Details),
                     L"System32 WriteDAC writable - DLL search order hijack");
            InterlockedIncrement(&g_Lpd.Stats.DllHijacksDetected);
            Lpd_PublishEvent(&evt, NULL, 0, &written);
            vulnerable = TRUE;
        }
    }

    /* 2. 当前目录可写 (标准用户目录) — 辅助信号 */
    {
        WCHAR cwd[DEF_MAX_PATH];
        if (GetCurrentDirectoryW(ARRAYSIZE(cwd), cwd) > 0 &&
            Lpd_CheckDirectoryWriteACL(cwd)) {
            LPD_EVENT evt;
            Lpd_InitEvent(&evt, LpdTech_DllHijacking,
                          LPD_CONFIDENCE_SCORE(LpdConf_Medium));
            wcscpy_s(evt.TargetDirectory, ARRAYSIZE(evt.TargetDirectory), cwd);
            wcscpy_s(evt.Details, ARRAYSIZE(evt.Details),
                     L"CWD writable - potential DLL hijack surface");
            InterlockedIncrement(&g_Lpd.Stats.DllHijacksDetected);
            Lpd_PublishEvent(&evt, NULL, 0, &written);
            vulnerable = TRUE;
        }
    }

    return vulnerable;
}

/**************************************************/
/*               计划任务滥用检测                   */
/**************************************************/

/* 计划任务 XML 输出行缓冲 */
#define LPD_SCHTASKS_OUTPUT_LINE_MAX 4096

static
ULONG
Lpd_RunSchtasksAndParse(
    _In_z_ const WCHAR* Args,
    _In_    BOOLEAN     Verbose
    )
/*++
Routine Description:
    执行 schtasks /query /fo CSV /nh /v 并解析输出,
    标记"以 SYSTEM 身份运行"的异常任务并上报事件。
    判定语义DetectScheduledTaskAbuse
    (行内含 SYSTEM 且 Logon Mode 字段为 ",NT AUTHORITY\SYSTEM," 或
    ",\SYSTEM,")。SS 原实现为计数 stub 不产事件, 本迁移补全事件上报。

Arguments:
    Args    — /query 附加参数 (当前实现恒为空串保留扩展点)。
    Verbose — TRUE 表示同时记录审计日志级信息。

Return Value:
    命中 (上报) 事件总数。
--*/
{
    WCHAR appPath[DEF_MAX_PATH * 2] = { 0 };
    WCHAR cmdLine[DEF_MAX_PATH * 4];
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    HANDLE hStdoutRd = NULL;
    HANDLE hStdoutWr = NULL;
    SECURITY_ATTRIBUTES sa = { 0 };
    DWORD pipeRead = 0;
    ULONG hitIndex = 0;

    UNREFERENCED_PARAMETER(Verbose);

    /* schtasks.exe 位于 %SystemRoot%\System32 */
    if (GetSystemDirectoryW(appPath, ARRAYSIZE(appPath)) == 0) return 0;
    wcscat_s(appPath, ARRAYSIZE(appPath), L"\\schtasks.exe");

    swprintf_s(cmdLine, ARRAYSIZE(cmdLine),
               L"\"%s\" /query %s /fo CSV /nh /v", appPath, Args);

    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hStdoutRd, &hStdoutWr, &sa, 0)) return 0;
    SetHandleInformation(hStdoutRd, HANDLE_FLAG_INHERIT, 0);

    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hStdoutWr;
    si.hStdError = hStdoutWr;

    if (!CreateProcessW(NULL, cmdLine, NULL, NULL, TRUE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hStdoutRd);
        CloseHandle(hStdoutWr);
        return 0;
    }

    CloseHandle(hStdoutWr);
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    /* 读全部输出 */
    {
        CHAR output[LPD_SCHTASKS_OUTPUT_LINE_MAX * 16] = { 0 };
        DWORD totalRead = 0;
        BOOL keepReading = TRUE;

        while (keepReading &&
               ReadFile(hStdoutRd, output + totalRead,
                        sizeof(output) - totalRead - 1, &pipeRead, NULL)) {
            totalRead += pipeRead;
            if (totalRead >= sizeof(output) - 1) keepReading = FALSE;
        }
        CloseHandle(hStdoutRd);
        output[totalRead] = L'\0';

        /* 解析每行 CSV (OEM 代码页文本, "SYSTEM" 等 ASCII 可靠) */
        if (totalRead > 0) {
            CHAR* line = output;
            ULONG lineCount = 0;

            while (line && *line && lineCount < LPD_MAX_SCHEDULED_TASKS) {
                CHAR* next = strchr(line, '\r');
                if (next) *next = L'\0';

                /* 判定语义: 任务以 SYSTEM 身份运行 → 提权/持久化信号 */
                if (strstr(line, "SYSTEM") != NULL &&
                    (strstr(line, ",NT AUTHORITY\\SYSTEM,") != NULL ||
                     strstr(line, ",\\SYSTEM,") != NULL)) {

                    /* 解析任务名 (第2列, 跳过 /nh 无标题) */
                    CHAR taskName[512] = { 0 };
                    CHAR* p = line;
                    ULONG col = 0;

                    while (p && col < 1) {
                        p = strchr(p, L',');
                        if (p) { p++; col++; }
                    }
                    if (p) {
                        CHAR* end = strchr(p, L',');
                        if (end) {
                            ULONG n = (ULONG)(end - p);
                            if (n >= sizeof(taskName)) {
                                n = sizeof(taskName) - 1;
                            }
                            memcpy(taskName, p, n);
                            taskName[n] = L'\0';
                        }
                    }

                    {
                        WCHAR wideTask[512] = { 0 };
                        LPD_EVENT evt;
                        ULONG evtWritten = 0;

                        MultiByteToWideChar(CP_OEMCP, 0, taskName, -1,
                            wideTask, ARRAYSIZE(wideTask));

                        Lpd_InitEvent(&evt, LpdTech_ScheduledTaskAbuse,
                            LPD_CONFIDENCE_SCORE(LpdConf_High));
                        if (wideTask[0] != L'\0') {
                            wcscpy_s(evt.TaskName, ARRAYSIZE(evt.TaskName),
                                     wideTask);
                        }
                        swprintf_s(evt.Details, ARRAYSIZE(evt.Details),
                            L"Scheduled task running as SYSTEM (created by "
                            L"non-system account?)");
                        InterlockedIncrement(
                            &g_Lpd.Stats.ScheduledTaskAbuses);
                        Lpd_PublishEvent(&evt, NULL, 0, &evtWritten);
                        hitIndex++;
                    }
                }

                if (!next) break;
                line = next + 1;
                lineCount++;
            }
        }
    }

    return hitIndex;
}

ULONG
LpdDetectScheduledTaskAbuse(
    _Out_writes_to_opt_(MaxEvents, *pReturned) PLPD_EVENT Events,
    _In_                               ULONG       MaxEvents,
    _Out_opt_                          PULONG      pReturned
    )
/*++
Routine Description:
    检测以 SYSTEM 身份运行的可疑计划任务 (语义, 补全事件上报)。
    事件经回调发布, Events 缓冲参数保留以匹配统一调用约定。

Return Value:
    命中事件总数。
--*/
{
    ULONG total;

    UNREFERENCED_PARAMETER(Events);
    UNREFERENCED_PARAMETER(MaxEvents);

    if (!g_Lpd.Initialized || !g_Lpd.Config.DetectScheduledTasks) return 0;

    total = Lpd_RunSchtasksAndParse(L"", TRUE);

    if (pReturned) *pReturned = 0;
    return total;
}

/**************************************************/
/*               全量扫描编排                       */
/**************************************************/

ULONG
LpdRunSweep(
    _Out_writes_to_opt_(MaxEvents, *pReturned) PLPD_EVENT Events,
    _In_                               ULONG       MaxEvents,
    _Out_opt_                          PULONG      pReturned
    )
/*++
Routine Description:
    单次全量扫描 (监控线程一轮):
      1. UAC 绕过 (注册表键)      — LpdDetectUacBypasses
      2. COM UAC 绕过             — LpdDetectComBypasses
      3. Potato 家族              — LpdDetectPotatoAttacks
      4. 命名管道模拟             — LpdDetectNamedPipeImpersonation
      5. 计划任务滥用             — LpdDetectScheduledTaskAbuse
      6. 注册表滥用 (AlwaysInstallElevated)
      7. IFEO Debugger            — LpdGetIfeoDebuggers
      8. 服务漏洞 (事件化)        — LpdScanServices
      9. DLL 劫持面               — LpdIsDllHijackVulnerable

    各类内部已经回调实时上报; 服务漏洞在本级事件化后一并写入缓冲。

Return Value:
    本轮命中事件总数 (含回调)。
--*/
{
    ULONG total = 0;
    ULONG written = 0;
    ULONG i;

    if (pReturned) *pReturned = 0;
    if (!g_Lpd.Initialized) return 0;

    /* 1. UAC 绕过键 */
    total += LpdDetectUacBypasses(Events, MaxEvents, &written);

    /* 2. COM UAC 绕过 + 自动提升二进制滥用 */
    total += LpdDetectComBypasses(Events, MaxEvents, &written);

    /* 3. Potato 家族 */
    total += LpdDetectPotatoAttacks(Events, MaxEvents, &written);

    /* 4. 命名管道模拟 */
    total += LpdDetectNamedPipeImpersonation(Events, MaxEvents, &written);

    /* 5. 计划任务滥用 */
    total += LpdDetectScheduledTaskAbuse(Events, MaxEvents, &written);

    /* 6. AlwaysInstallElevated (内部上报, 无缓冲语义) */
    if (g_Lpd.Config.DetectDllHijacking &&
        LpdIsAlwaysInstallElevatedEnabled()) {
        total++;
    }

    /* 7. IFEO Debugger (HKCU 命中内部上报) */
    if (g_Lpd.Config.MonitorIfeo) {
        ULONG ifeoWritten = 0;
        total += LpdGetIfeoDebuggers(NULL, 0, &ifeoWritten);
    }

    /* 8. 服务漏洞 → 事件化 (本地缓冲收集 → 逐条发布) */
    if (g_Lpd.Config.MonitorServiceConfig) {
        LPD_SERVICE_INFO svcInfos[64];
        ULONG svcCount = 0;

        LpdScanServices(svcInfos, ARRAYSIZE(svcInfos), &svcCount);
        for (i = 0; i < svcCount; i++) {
            LPD_EVENT evt;
            LPD_TECHNIQUE tech;

            switch (svcInfos[i].Vulnerability) {
            case LpdSvcVuln_UnquotedPath:
                tech = LpdTech_ServiceUnquotedPath;
                break;
            case LpdSvcVuln_WritableDirectory:
                tech = LpdTech_ServiceWritableDir;
                break;
            case LpdSvcVuln_WeakFilePermissions:
                tech = LpdTech_ServiceWeakFilePerms;
                break;
            default:
                tech = LpdTech_ServiceUnquotedPath;
                break;
            }

            Lpd_InitEvent(&evt, tech,
                          LPD_CONFIDENCE_SCORE(LpdConf_High));
            wcscpy_s(evt.ProcessName, ARRAYSIZE(evt.ProcessName),
                     svcInfos[i].ServiceName);
            wcscpy_s(evt.TargetFilePath, ARRAYSIZE(evt.TargetFilePath),
                     svcInfos[i].BinaryPath);
            swprintf_s(evt.Details, ARRAYSIZE(evt.Details),
                       L"Vulnerable service: %s (start=%u, runas=%s)",
                       svcInfos[i].ServiceName,
                       svcInfos[i].StartType,
                       svcInfos[i].RunAsAccount);
            total += Lpd_PublishEvent(&evt, Events, MaxEvents, &written);
        }
    }

    /* 9. DLL 劫持面 */
    if (g_Lpd.Config.DetectDllHijacking && LpdIsDllHijackVulnerable()) {
        total++;
    }

    InterlockedIncrement(&g_Lpd.Stats.SweepsRun);

    if (pReturned) *pReturned = written;
    return total;
}

/**************************************************/
/*               生命周期                           */
/**************************************************/

NTSTATUS
LpdInitialize(
    _In_ const LPD_CONFIG* Config   /* NULL = LPD_DEFAULT_CONFIG */
    )
/*++
Routine Description:
    初始化检测器单例 (幂等: 重复调用视为重建)。

Arguments:
    Config — 配置; NULL 使用 LPD_DEFAULT_CONFIG。

Return Value:
    STATUS_SUCCESS。
--*/
{
    if (Config) {
        g_Lpd.Config = *Config;
        if (g_Lpd.Config.WhitelistCount > LPD_MAX_WHITELIST) {
            g_Lpd.Config.WhitelistCount = LPD_MAX_WHITELIST;
        }
    } else {
        g_Lpd.Config = (LPD_CONFIG)LPD_DEFAULT_CONFIG;
    }

    g_Lpd.Callback = NULL;
    g_Lpd.CallbackContext = NULL;
    g_Lpd.EventSequence = 0;
    RtlZeroMemory(&g_Lpd.Stats, sizeof(g_Lpd.Stats));
    g_Lpd.Initialized = TRUE;

    return STATUS_SUCCESS;
}

VOID
LpdShutdown(VOID)
/*++
Routine Description:
    停止检测器并释放状态 (清空回调与统计)。
--*/
{
    g_Lpd.Initialized = FALSE;
    g_Lpd.Callback = NULL;
    g_Lpd.CallbackContext = NULL;
    RtlZeroMemory(&g_Lpd.Stats, sizeof(g_Lpd.Stats));
    g_Lpd.EventSequence = 0;
}

BOOLEAN
LpdIsInitialized(VOID)
{
    return g_Lpd.Initialized;
}

/**************************************************/
/*               回调 / 统计                        */
/**************************************************/

VOID
LpdRegisterCallback(
    _In_opt_ LPD_DETECTED_CALLBACK Callback,
    _In_opt_ PVOID                 Context
    )
/*++
Routine Description:
    注册事件回调 (覆盖式, 仅支持单回调; 事件流语义)。
--*/
{
    g_Lpd.Callback = Callback;
    g_Lpd.CallbackContext = Context;
}

VOID
LpdGetStatistics(
    _Out_ PLPD_STATISTICS Stats
    )
{
    if (Stats) {
        RtlCopyMemory(Stats, &g_Lpd.Stats, sizeof(*Stats));
    }
}

VOID
LpdResetStatistics(VOID)
{
    RtlZeroMemory(&g_Lpd.Stats, sizeof(g_Lpd.Stats));
}

/**************************************************/
/*               工具函数                           */
/**************************************************/

/*
 * 技术 → 名称 / MITRE ATT&CK 映射表
 * MITRE 事件硬编码 ID (见头文件注释)。
 */
static const struct _LPD_TECH_TABLE {
    LPD_TECHNIQUE Tech;
    PCSTR         Name;
    PCSTR         MitreId;
} g_LpdTechniqueTable[] = {
    { LpdTech_FodhelperBypass,      "Fodhelper UAC Bypass",       "T1548.002" },
    { LpdTech_EventViewerBypass,    "Event Viewer UAC Bypass",    "T1548.002" },
    { LpdTech_ComputerDefaultsBypass,"ComputerDefaults UAC Bypass","T1548.002" },
    { LpdTech_UacBypassCom,         "COM UAC Bypass",             "T1548.002" },
    { LpdTech_UacBypassAutoElevate, "Auto-Elevate Binary Abuse",  "T1548.002" },
    { LpdTech_UacBypassRegistry,    "UAC Bypass Registry",        "T1548.002" },
    { LpdTech_ServiceUnquotedPath,  "Service Unquoted Path",      "T1543.003" },
    { LpdTech_ServiceWritableDir,   "Service Writable Directory", "T1543.003" },
    { LpdTech_ServiceWeakFilePerms, "Service Weak File Permissions","T1543.003" },
    { LpdTech_DllHijack,            "DLL Search Order Hijack",    "T1574.001" },
    { LpdTech_RegistryAlwaysInstall,"AlwaysInstallElevated",      "T1548.002" },
    { LpdTech_RegistryIfeo,         "IFEO Debugger Injection",    "T1546.012" },
    { LpdTech_PotatoAttack,         "Potato Family Attack",       "T1068"     },
    { LpdTech_NamedPipeImpersonation,"Named Pipe Impersonation",  "T1055.003" },
    { LpdTech_ScheduledTaskAbuse,   "Scheduled Task Abuse",       "T1053.005" },
};

PCSTR
LpdGetTechniqueName(
    _In_ LPD_TECHNIQUE Technique
    )
{
    ULONG i;
    for (i = 0; i < ARRAYSIZE(g_LpdTechniqueTable); i++) {
        if (g_LpdTechniqueTable[i].Tech == Technique) {
            return g_LpdTechniqueTable[i].Name;
        }
    }
    return "Unknown";
}

PCSTR
LpdGetTechniqueMitreId(
    _In_ LPD_TECHNIQUE Technique
    )
{
    ULONG i;
    for (i = 0; i < ARRAYSIZE(g_LpdTechniqueTable); i++) {
        if (g_LpdTechniqueTable[i].Tech == Technique) {
            return g_LpdTechniqueTable[i].MitreId;
        }
    }
    return "-";
}