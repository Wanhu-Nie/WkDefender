/**************************************************/
/*  WkDefender Agent — 目录监控编排层实现           */
/*                                                  */
/*  迁移自 ShadowStrike DirectoryMonitor.cpp        */
/*  (1604 行), 按功能融合重实现, 非源码复制。        */
/*                                                  */
/*  核心机制:                                       */
/*    - 每监控目录一个 worker 线程 + OVERLAPPED      */
/*      异步 ReadDirectoryChangesW (64KB 缓冲)       */
/*    - 停止协议: SetEvent → CancelIoEx → Wait       */
/*      (10s) → TerminateThread 兜底                */
/*    - 缓冲溢出 (bytesReturned==0) 显式上报 + 记错  */
/*    - FILE_NOTIFY_INFORMATION 解析加固 (对齐/越界) */
/*    - reparse point 拒绝 + 句柄最终路径验证        */
/*      (FILE_FLAG_OPEN_REPARSE_POINT, 防 TOCTOU)    */
/*    - rename 配对 (OLD_NAME→NEW_NAME)              */
/*    - 智能过滤 + 限流 + 统计 + 回调锁外调用        */
/**************************************************/

#include "DirectoryMonitor.h"
#include "Common/TextSanitize.h"
#include "Common/Exempts/Exempts.h"      /* 统一豁免门面 (Exempts 重构 #67, 替代 IocFileWhitelist) */

#include <windows.h>
#include <wchar.h>
#include <wctype.h>
#include <stdio.h>

/**************************************************/
/*               内部结构                           */
/**************************************************/

/* 槽位状态: 控制槽复用 (Add 只在 StFree 分配, Remove 在 worker 退出后置 StFree) */
typedef enum _WKD_DIR_MON_STATE {
    WkdDirMonSt_Free     = 0,
    WkdDirMonSt_Starting = 1,
    WkdDirMonSt_Active   = 2,
    WkdDirMonSt_Stopping = 3,
} WKD_DIR_MON_STATE;

typedef struct _WKD_DIR_MONITOR {
    ULONG            MonitorId;
    WCHAR            Path[DEF_MAX_PATH];
    WKD_DIR_CATEGORY Category;
    BOOLEAN          Recursive;
    volatile LONG    State;           /* WKD_DIR_MON_STATE */

    /* worker 可见状态 (原子, 供外部快照) */
    volatile LONG    IsPaused;
    volatile LONG64  EventsReceived;
    volatile LONG64  LastEventNs;
    LARGE_INTEGER    CreatedTime;

    HANDLE           hDirectory;
    HANDLE           hStopEvent;
    HANDLE           hThread;
    BYTE*            Buffer;          /* malloc(WKD_DIR_NOTIFY_BUFFER) */
    OVERLAPPED       Overlapped;

    /* rename 配对 (worker 独占) */
    WCHAR            PendingOldName[WKD_DIR_MAX_FILENAME];
    BOOLEAN          PendingOldValid;

    /* 限流滑动窗口 (worker 独占) */
    LARGE_INTEGER    RateTimes[WKD_DIR_MAX_RATELIMIT_TICKS];
    ULONG            RateCount;
    ULONG            RateDropCount;

    PVOID            pImpl;           /* = &g_DirMon */
} WKD_DIR_MONITOR, *PWKD_DIR_MONITOR;

typedef struct _WKD_DIR_GLOBAL {
    BOOLEAN             Initialized;
    volatile LONG       Status;          /* WKD_DIR_STATUS */
    LARGE_INTEGER       PerfFreq;        /* QueryPerformanceFrequency (耗时统计) */
    CRITICAL_SECTION    Lock;          /* 保护 monitors 表 + 配置 */
    CRITICAL_SECTION    CbLock;        /* 保护回调指针 */
    WKD_DIR_MONITOR_CONFIG Config;
    WKD_DIR_MONITOR     Monitors[WKD_DIR_MAX_MONITORS];
    volatile LONG       NextMonitorId;
    volatile LONG64     NextEventId;
    WKD_DIR_EVENT_CB    EventCb;
    WKD_DIR_STATUS_CB   StatusCb;
    WKD_DIR_ERROR_CB    ErrorCb;
    WKD_DIR_STATS       Stats;
} WKD_DIR_GLOBAL, *PWKD_DIR_GLOBAL;

static WKD_DIR_GLOBAL g_DirMon;

/**************************************************/
/*               内部辅助函数                       */
/**************************************************/

static
VOID
DmConfigDefault(
    _Out_ PWKD_DIR_MONITOR_CONFIG Config
    )
/*++
Routine Description:
    填充默认配置 (对齐 SS CreateDefault)。

Arguments:
    Config — 输出配置。

Return Value:
    无。
--*/
{
    RtlZeroMemory(Config, sizeof(*Config));
    Config->Enabled                  = TRUE;
    Config->MonitorSystemPaths        = TRUE;
    Config->MonitorUserPaths          = TRUE;
    Config->MonitorStartupLocations   = TRUE;
    Config->MonitorTempDirectories    = TRUE;
    Config->EnableRateLimiting        = TRUE;
    Config->EnableIntelligentFiltering = TRUE;
    Config->MaxConcurrentMonitors     = WKD_DIR_MAX_MONITORS;
    Config->RateLimitWindowSec        = 60;
    Config->MaxEventsPerWindow        = 1000;
}

static
BOOLEAN
DmConfigIsValid(
    _In_ const WKD_DIR_MONITOR_CONFIG* Config
    )
/*++
Routine Description:
    配置合法性校验 (对齐 SS IsValid)。

Arguments:
    Config — 待校验配置。

Return Value:
    TRUE 合法 / FALSE 非法。
--*/
{
    if (!Config->Enabled) return TRUE;
    if (Config->MaxConcurrentMonitors == 0) return FALSE;
    if (Config->MaxConcurrentMonitors > WKD_DIR_MAX_MONITORS) return FALSE;
    if (Config->EnableRateLimiting && Config->RateLimitWindowSec == 0) return FALSE;
    if (Config->EnableRateLimiting && Config->MaxEventsPerWindow == 0) return FALSE;
    return TRUE;
}

static
BOOLEAN
DmIsReparsePoint(
    _In_ PCWSTR Path
    )
/*++
Routine Description:
    判断路径是否指向 reparse point (符号链接/junction/挂载点)。
    监控前必须拒绝, 否则成为 TOCTOU 替换原语。

Arguments:
    Path — 目录路径。

Return Value:
    TRUE 是 reparse point。
--*/
{
    DWORD attrs = GetFileAttributesW(Path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }
    return (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

static
BOOLEAN
DmCanonicalizeFull(
    _In_ PCWSTR Path,
    _Out_writes_(DEF_MAX_PATH) WCHAR* Out
    )
/*++
Routine Description:
    长路径规范化 (对齐 SS CanonicalizeFull)。GetFullPathNameW
    动态缓冲, 处理相对路径; 超 DEF_MAX_PATH 截断返回 FALSE。

Arguments:
    Path — 输入路径。
    Out  — 输出缓冲。

Return Value:
    TRUE 成功。
--*/
{
    DWORD needed;
    WCHAR* buf;
    BOOLEAN ok = FALSE;

    if (!Path || !Path[0] || !Out) return FALSE;

    needed = GetFullPathNameW(Path, 0, NULL, NULL);
    if (needed == 0) return FALSE;

    if (needed >= DEF_MAX_PATH) {
        /* 长路径暂不支持 (搁置项), 返回 FALSE */
        return FALSE;
    }

    buf = (WCHAR*)malloc(needed * sizeof(WCHAR));
    if (!buf) return FALSE;

    if (GetFullPathNameW(Path, needed, buf, NULL) != 0) {
        wcscpy_s(Out, DEF_MAX_PATH, buf);
        ok = TRUE;
    }
    free(buf);
    return ok;
}

static
BOOLEAN
DmVerifyHandleResolvesTo(
    _In_ HANDLE hDirectory,
    _In_ PCWSTR Requested
    )
/*++
Routine Description:
    打开目录句柄后, 用 GetFinalPathNameByHandleW 取内核最终路径,
    与请求路径大小写不敏感比对。不一致说明被 symlink/junction 重定向,
    拒绝监控 (对齐 SS VerifyHandleResolvesTo, 防 TOCTOU)。

Arguments:
    hDirectory — 已打开目录句柄。
    Requested  — 请求监控的规范化路径。

Return Value:
    TRUE 句柄解析到请求路径。
--*/
{
    WCHAR resolved[DEF_MAX_PATH];
    DWORD needed;
    PCWSTR a;
    PCWSTR b;
    size_t la, lb;
    BOOLEAN ok = FALSE;

    needed = GetFinalPathNameByHandleW(hDirectory, resolved, DEF_MAX_PATH,
                                       FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (needed == 0 || needed >= DEF_MAX_PATH) return FALSE;

    /* 去 \\?\ 前缀 (VOLUME_NAME_DOS 一般不返回, 防御) */
    a = resolved;
    if (wcslen(resolved) > 4 &&
        resolved[0] == L'\\' && resolved[1] == L'\\' &&
        resolved[2] == L'?' && resolved[3] == L'\\') {
        a = resolved + 4;
    }
    b = Requested;

    /* 去尾斜杠后大小写不敏感比较 */
    la = wcslen(a);
    lb = wcslen(b);
    while (la > 0 && (a[la - 1] == L'\\' || a[la - 1] == L'/')) la--;
    while (lb > 0 && (b[lb - 1] == L'\\' || b[lb - 1] == L'/')) lb--;

    if (la == lb) {
        ok = TRUE;
        for (size_t i = 0; i < la; i++) {
            if (towlower(a[i]) != towlower(b[i])) {
                ok = FALSE;
                break;
            }
        }
    }
    return ok;
}

/* 路径去重追加 (GetQuickScanRoots 用) */
static
VOID
DmAddPath(
    _Inout_ WCHAR (*Roots)[DEF_MAX_PATH],
    _In_ ULONG MaxCount,
    _Inout_ PULONG Count,
    _In_ PCWSTR Path
    )
{
    ULONG i;

    if (!Path || !Path[0] || *Count >= MaxCount) return;
    if (wcslen(Path) >= DEF_MAX_PATH) return;

    for (i = 0; i < *Count; i++) {
        if (_wcsicmp(Roots[i], Path) == 0) return;
    }
    wcscpy_s(Roots[*Count], DEF_MAX_PATH, Path);
    (*Count)++;
}

/**************************************************/
/*               路径发现 (对齐 SS L490-564)        */
/**************************************************/

/* 系统关键路径: System32 / Windows / drivers / Program Files */
static
VOID
DmGetSystemCriticalPaths(
    _Inout_ WCHAR (*Roots)[DEF_MAX_PATH],
    _In_ ULONG MaxCount,
    _Inout_ PULONG Count
    )
{
    WCHAR buf[DEF_MAX_PATH];
    WCHAR tmp[DEF_MAX_PATH];

    if (GetSystemDirectoryW(buf, DEF_MAX_PATH) > 0) {
        DmAddPath(Roots, MaxCount, Count, buf);
    }
    if (GetWindowsDirectoryW(buf, DEF_MAX_PATH) > 0) {
        DmAddPath(Roots, MaxCount, Count, buf);
        _snwprintf_s(tmp, DEF_MAX_PATH, _TRUNCATE, L"%s\\System32\\drivers", buf);
        DmAddPath(Roots, MaxCount, Count, tmp);
    }
    if (GetEnvironmentVariableW(L"ProgramFiles", buf, DEF_MAX_PATH) > 0) {
        DmAddPath(Roots, MaxCount, Count, buf);
    }
    if (GetEnvironmentVariableW(L"ProgramFiles(x86)", buf, DEF_MAX_PATH) > 0) {
        DmAddPath(Roots, MaxCount, Count, buf);
    }
}

/* 用户路径: AppData / LocalAppData / Documents / Desktop */
static
VOID
DmGetUserProfilePaths(
    _Inout_ WCHAR (*Roots)[DEF_MAX_PATH],
    _In_ ULONG MaxCount,
    _Inout_ PULONG Count
    )
{
    WCHAR buf[DEF_MAX_PATH];
    WCHAR tmp[DEF_MAX_PATH];
    PCWSTR known[] = { L"APPDATA", L"LOCALAPPDATA", L"USERPROFILE" };
    ULONG i;

    for (i = 0; i < 3; i++) {
        if (GetEnvironmentVariableW(known[i], buf, DEF_MAX_PATH) > 0) {
            DmAddPath(Roots, MaxCount, Count, buf);
        }
    }
    /* Documents / Desktop (无 shell32 依赖, 用 USERPROFILE 拼接) */
    if (GetEnvironmentVariableW(L"USERPROFILE", buf, DEF_MAX_PATH) > 0) {
        _snwprintf_s(tmp, DEF_MAX_PATH, _TRUNCATE, L"%s\\Documents", buf);
        DmAddPath(Roots, MaxCount, Count, tmp);
        _snwprintf_s(tmp, DEF_MAX_PATH, _TRUNCATE, L"%s\\Desktop", buf);
        DmAddPath(Roots, MaxCount, Count, tmp);
    }
}

/* 启动目录: 用户 + 全局 Start Menu\Programs\Startup */
static
VOID
DmGetStartupPaths(
    _Inout_ WCHAR (*Roots)[DEF_MAX_PATH],
    _In_ ULONG MaxCount,
    _Inout_ PULONG Count
    )
{
    WCHAR buf[DEF_MAX_PATH];
    WCHAR tmp[DEF_MAX_PATH];

    if (GetEnvironmentVariableW(L"APPDATA", buf, DEF_MAX_PATH) > 0) {
        _snwprintf_s(tmp, DEF_MAX_PATH, _TRUNCATE,
                     L"%s\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", buf);
        DmAddPath(Roots, MaxCount, Count, tmp);
    }
    if (GetEnvironmentVariableW(L"ProgramData", buf, DEF_MAX_PATH) > 0) {
        _snwprintf_s(tmp, DEF_MAX_PATH, _TRUNCATE,
                     L"%s\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp", buf);
        DmAddPath(Roots, MaxCount, Count, tmp);
    }
}

/* 下载目录: %USERPROFILE%\Downloads */
static
VOID
DmGetDownloadPaths(
    _Inout_ WCHAR (*Roots)[DEF_MAX_PATH],
    _In_ ULONG MaxCount,
    _Inout_ PULONG Count
    )
{
    WCHAR buf[DEF_MAX_PATH];
    WCHAR tmp[DEF_MAX_PATH];

    if (GetEnvironmentVariableW(L"USERPROFILE", buf, DEF_MAX_PATH) > 0) {
        _snwprintf_s(tmp, DEF_MAX_PATH, _TRUNCATE, L"%s\\Downloads", buf);
        DmAddPath(Roots, MaxCount, Count, tmp);
    }
}

/* 临时目录: GetTempPathW + %TEMP% */
static
VOID
DmGetTempPaths(
    _Inout_ WCHAR (*Roots)[DEF_MAX_PATH],
    _In_ ULONG MaxCount,
    _Inout_ PULONG Count
    )
{
    WCHAR buf[DEF_MAX_PATH];

    if (GetTempPathW(DEF_MAX_PATH, buf) > 0) {
        DmAddPath(Roots, MaxCount, Count, buf);
    }
    if (GetEnvironmentVariableW(L"TEMP", buf, DEF_MAX_PATH) > 0) {
        DmAddPath(Roots, MaxCount, Count, buf);
    }
}

/**************************************************/
/*               过滤与限流                         */
/**************************************************/

/* 智能过滤 (对齐 SS ShouldFilterEvent): 已知噪声文件/白名单 */
static
BOOLEAN
DmShouldFilterEvent(
    _In_ const WKD_DIR_EVENT* Evt,
    _In_ BOOLEAN             IntelligentFiltering
    )
{
    WCHAR filename[WKD_DIR_MAX_FILENAME];
    WCHAR fullPath[DEF_MAX_PATH + WKD_DIR_MAX_FILENAME];
    size_t len;
    PCWSTR name;
    PCWSTR dot;

    if (!IntelligentFiltering) return FALSE;
    if (!Evt->FileName[0]) return FALSE;

    /* 小写副本 (尺寸小, 直接栈上) */
    wcscpy_s(filename, WKD_DIR_MAX_FILENAME, Evt->FileName);
    for (len = 0; filename[len]; len++) {
        filename[len] = (WCHAR)towlower(filename[len]);
    }

    /* 临时/备份后缀 + ~ 结尾 */
    if (len >= 4 && _wcsicmp(filename + len - 4, L".tmp") == 0) return TRUE;
    if (len >= 6 && _wcsicmp(filename + len - 6, L".cache") == 0) return TRUE;
    if (len >= 4 && _wcsicmp(filename + len - 4, L".bak") == 0) return TRUE;
    if (len > 0 && filename[len - 1] == L'~') return TRUE;

    /* 系统噪声文件 */
    if (_wcsicmp(filename, L"thumbs.db") == 0) return TRUE;
    if (_wcsicmp(filename, L"desktop.ini") == 0) return TRUE;
    if (len >= 2 && filename[0] == L'~' && filename[1] == L'$') return TRUE;

    /* 白名单 (Exempts 统一豁免: 证书/路径/哈希; 未初始化安全返回 FALSE) */
    if (wcscpy_s(fullPath, sizeof(fullPath) / sizeof(fullPath[0]), Evt->Path) == 0) {
        len = wcslen(fullPath);
        if (len > 0 && fullPath[len - 1] != L'\\' && fullPath[len - 1] != L'/') {
            fullPath[len++] = L'\\';
            fullPath[len] = L'\0';
        }
        wcscat_s(fullPath, sizeof(fullPath) / sizeof(fullPath[0]), Evt->FileName);
        if (ExemptsIsWhitelisted(fullPath, NULL, NULL)) {
            return TRUE;
        }
    }
    (void)name; (void)dot;
    return FALSE;
}

/* 限流: per-monitor 滑动窗口 (对齐 SS ShouldRateLimit, worker 独占无锁) */
static
BOOLEAN
DmShouldRateLimit(
    _Inout_ PWKD_DIR_MONITOR Monitor,
    _In_ BOOLEAN             Enabled,
    _In_ ULONG               WindowSec,
    _In_ ULONG               MaxEventsPerWindow
    )
{
    LARGE_INTEGER now;
    LARGE_INTEGER windowStart;
    ULONG i;

    if (!Enabled) return FALSE;

    GetSystemTimeAsFileTime((PFILETIME)&now);
    windowStart.QuadPart = now.QuadPart - (LONGLONG)WindowSec * 10000000LL;

    /* 滑出窗口的时间戳丢弃 */
    i = 0;
    while (i < Monitor->RateCount &&
           Monitor->RateTimes[i].QuadPart < windowStart.QuadPart) {
        i++;
    }
    if (i > 0) {
        if (i < Monitor->RateCount) {
            memmove(Monitor->RateTimes, Monitor->RateTimes + i,
                    (Monitor->RateCount - i) * sizeof(LARGE_INTEGER));
        }
        Monitor->RateCount -= i;
    }

    if (Monitor->RateCount >= MaxEventsPerWindow) {
        Monitor->RateDropCount++;
        return TRUE;
    }
    Monitor->RateTimes[Monitor->RateCount].QuadPart = now.QuadPart;
    Monitor->RateCount++;
    return FALSE;
}

/**************************************************/
/*               事件处理 (对齐 SS ProcessNotification) */
/**************************************************/

static
VOID
DmSnapshotConfig(
    _Out_ BOOLEAN* IntelligentFiltering,
    _Out_ BOOLEAN* RateLimiting,
    _Out_ ULONG*   RateWindowSec,
    _Out_ ULONG*   MaxEventsPerWindow
    )
{
    EnterCriticalSection(&g_DirMon.Lock);
    *IntelligentFiltering = g_DirMon.Config.EnableIntelligentFiltering;
    *RateLimiting         = g_DirMon.Config.EnableRateLimiting;
    *RateWindowSec        = g_DirMon.Config.RateLimitWindowSec;
    *MaxEventsPerWindow   = g_DirMon.Config.MaxEventsPerWindow;
    LeaveCriticalSection(&g_DirMon.Lock);
}

static
VOID
DmFireEventCallback(
    _In_ const WKD_DIR_EVENT* Evt
    )
/*++
Routine Description:
    事件回调快照 + 锁外调用 (对齐 SS, 防重入死锁)。
--*/
{
    WKD_DIR_EVENT_CB cb;

    EnterCriticalSection(&g_DirMon.CbLock);
    cb = g_DirMon.EventCb;
    LeaveCriticalSection(&g_DirMon.CbLock);

    if (cb) {
        cb(Evt);
        InterlockedIncrement64(&g_DirMon.Stats.CallbackInvocations);
    }
}

static
VOID
DmProcessNotification(
    _Inout_ PWKD_DIR_MONITOR Monitor,
    _In_    const FILE_NOTIFY_INFORMATION* Fni
    )
/*++
Routine Description:
    单条 FNI 记录 → WKD_DIR_EVENT, 走过滤/限流/统计/回调。
    RENAMED_OLD_NAME 存 pendingOldName 等 NEW_NAME 配对。
--*/
{
    WKD_DIR_EVENT event;
    BOOLEAN intelligent, rateLimit;
    ULONG windowSec, maxEvents;
    ULONG idx;
    LARGE_INTEGER start, end;

    QueryPerformanceCounter(&start);
    RtlZeroMemory(&event, sizeof(event));
    event.EventId   = (ULONG)InterlockedIncrement64(&g_DirMon.NextEventId);
    event.MonitorId = Monitor->MonitorId;
    wcscpy_s(event.Path, DEF_MAX_PATH, Monitor->Path);
    event.Category  = Monitor->Category;
    GetSystemTimeAsFileTime((PFILETIME)&event.Timestamp);

    if (Fni->FileNameLength > 0 &&
        Fni->FileNameLength <= (WKD_DIR_MAX_RECORD_FILENAME * sizeof(WCHAR))) {
        ULONG chars = Fni->FileNameLength / sizeof(WCHAR);
        if (chars >= WKD_DIR_MAX_FILENAME) chars = WKD_DIR_MAX_FILENAME - 1;
        memcpy(event.FileName, Fni->FileName, chars * sizeof(WCHAR));
        event.FileName[chars] = L'\0';
    }

    switch (Fni->Action) {
    case FILE_ACTION_ADDED:
        event.Action = WkdDirAct_FileAdded;
        break;
    case FILE_ACTION_REMOVED:
        event.Action = WkdDirAct_FileRemoved;
        break;
    case FILE_ACTION_MODIFIED:
        event.Action = WkdDirAct_FileModified;
        break;
    case FILE_ACTION_RENAMED_OLD_NAME:
        /* 暂存旧名, 等同一 burst 的 NEW_NAME */
        wcscpy_s(Monitor->PendingOldName, WKD_DIR_MAX_FILENAME, event.FileName);
        Monitor->PendingOldValid = TRUE;
        return;
    case FILE_ACTION_RENAMED_NEW_NAME:
        event.Action = WkdDirAct_FileRenamed;
        if (Monitor->PendingOldValid) {
            wcscpy_s(event.OldFileName, WKD_DIR_MAX_FILENAME, Monitor->PendingOldName);
        }
        Monitor->PendingOldValid = FALSE;
        Monitor->PendingOldName[0] = L'\0';
        break;
    default:
        event.Action = WkdDirAct_Unknown;
        break;
    }

    InterlockedIncrement64(&g_DirMon.Stats.TotalEvents);

    DmSnapshotConfig(&intelligent, &rateLimit, &windowSec, &maxEvents);

    if (DmShouldFilterEvent(&event, intelligent)) {
        InterlockedIncrement64(&g_DirMon.Stats.FilteredEvents);
        return;
    }
    if (DmShouldRateLimit(Monitor, rateLimit, windowSec, maxEvents)) {
        InterlockedIncrement64(&g_DirMon.Stats.RateLimitedEvents);
        return;
    }

    idx = (ULONG)event.Action;
    if (idx < 8) InterlockedIncrement64(&g_DirMon.Stats.ByAction[idx]);
    idx = (ULONG)event.Category;
    if (idx < 10) InterlockedIncrement64(&g_DirMon.Stats.ByCategory[idx]);

    DmFireEventCallback(&event);

    /* 处理耗时统计 (对齐 SS totalProcessingTimeUs) */
    QueryPerformanceCounter(&end);
    if (g_DirMon.PerfFreq.QuadPart > 0) {
        InterlockedAdd64(&g_DirMon.Stats.TotalProcessingTimeUs,
            (end.QuadPart - start.QuadPart) * 1000000 / g_DirMon.PerfFreq.QuadPart);
    }
}

/**************************************************/
/*               worker 线程 (对齐 SS MonitorThreadProc) */
/**************************************************/

static DWORD WINAPI
DmMonitorThreadProc(
    _In_ LPVOID Param
    )
{
    PWKD_DIR_MONITOR monitor = (PWKD_DIR_MONITOR)Param;
    const DWORD notifyFilter = FILE_NOTIFY_CHANGE_FILE_NAME |
                               FILE_NOTIFY_CHANGE_DIR_NAME  |
                               FILE_NOTIFY_CHANGE_ATTRIBUTES |
                               FILE_NOTIFY_CHANGE_SIZE       |
                               FILE_NOTIFY_CHANGE_LAST_WRITE |
                               FILE_NOTIFY_CHANGE_CREATION;
    DWORD bytesReturned = 0;
    unsigned consecutiveErrors = 0;

    if (!monitor || !monitor->pImpl) return 1;

    while (TRUE) {
        HANDLE waitHandles[2];
        DWORD waitResult;
        const BYTE* cur;
        const BYTE* bufEnd;

        if (WaitForSingleObject(monitor->hStopEvent, 0) == WAIT_OBJECT_0) {
            break;
        }

        ResetEvent(monitor->Overlapped.hEvent);

        if (!ReadDirectoryChangesW(
                monitor->hDirectory,
                monitor->Buffer,
                WKD_DIR_NOTIFY_BUFFER,
                monitor->Recursive ? TRUE : FALSE,
                notifyFilter,
                &bytesReturned,
                &monitor->Overlapped,
                NULL)) {
            DWORD err = GetLastError();
            if (err != ERROR_IO_PENDING) {
                if (++consecutiveErrors >= WKD_DIR_CONSECUTIVE_ERRORS) {
                    WKD_DIR_ERROR_CB cb;
                    EnterCriticalSection(&g_DirMon.CbLock);
                    cb = g_DirMon.ErrorCb;
                    LeaveCriticalSection(&g_DirMon.CbLock);
                    if (cb) {
                        cb(monitor->Path, L"ReadDirectoryChangesW persistently failing");
                    }
                    InterlockedIncrement64(&g_DirMon.Stats.Errors);
                    break;
                }
                InterlockedIncrement64(&g_DirMon.Stats.Errors);
                Sleep(50);
                continue;
            }
        }
        consecutiveErrors = 0;

        waitHandles[0] = monitor->hStopEvent;
        waitHandles[1] = monitor->Overlapped.hEvent;
        waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

        if (waitResult == WAIT_OBJECT_0) {
            CancelIoEx(monitor->hDirectory, &monitor->Overlapped);
            GetOverlappedResult(monitor->hDirectory, &monitor->Overlapped,
                                &bytesReturned, TRUE);
            break;
        }
        if (waitResult != WAIT_OBJECT_0 + 1) {
            InterlockedIncrement64(&g_DirMon.Stats.Errors);
            break;
        }

        if (!GetOverlappedResult(monitor->hDirectory, &monitor->Overlapped,
                                 &bytesReturned, FALSE)) {
            DWORD err = GetLastError();
            if (err == ERROR_OPERATION_ABORTED || err == ERROR_INVALID_HANDLE) {
                break;
            }
            InterlockedIncrement64(&g_DirMon.Stats.Errors);
            continue;
        }

        /* 缓冲溢出: bytesReturned==0 → 整批丢弃, 显式上报 (检测规避兜底) */
        if (bytesReturned == 0) {
            WKD_DIR_ERROR_CB cb;
            EnterCriticalSection(&g_DirMon.CbLock);
            cb = g_DirMon.ErrorCb;
            LeaveCriticalSection(&g_DirMon.CbLock);
            if (cb) {
                cb(monitor->Path, L"ReadDirectoryChangesW buffer overflow - events lost");
            }
            InterlockedIncrement64(&g_DirMon.Stats.Errors);
            continue;
        }

        if (monitor->IsPaused) {
            continue;
        }

        cur   = monitor->Buffer;
        bufEnd = monitor->Buffer + bytesReturned;

        while (TRUE) {
            const FILE_NOTIFY_INFORMATION* fni;
            DWORD fnameLen;
            DWORD nextOff;
            size_t recordBytes;

            if (cur < monitor->Buffer || cur > bufEnd) break;
            if ((size_t)(bufEnd - cur) < FIELD_OFFSET(FILE_NOTIFY_INFORMATION, FileName)) break;

            fni      = (const FILE_NOTIFY_INFORMATION*)cur;
            fnameLen = fni->FileNameLength;
            nextOff  = fni->NextEntryOffset;

            if (fnameLen > (WKD_DIR_MAX_RECORD_FILENAME * sizeof(WCHAR))) break;
            recordBytes = FIELD_OFFSET(FILE_NOTIFY_INFORMATION, FileName) + fnameLen;
            if ((size_t)(bufEnd - cur) < recordBytes) break;

            DmProcessNotification(monitor, fni);
            InterlockedIncrement64(&monitor->EventsReceived);
            {
                LARGE_INTEGER now;
                GetSystemTimeAsFileTime((PFILETIME)&now);
                monitor->LastEventNs = now.QuadPart;   /* FILETIME 100ns (对齐 SS lastEventNs) */
            }

            if (nextOff == 0) break;
            if (nextOff < recordBytes || (nextOff % 4) != 0) break;
            if ((size_t)(bufEnd - cur) <= nextOff) break;
            cur += nextOff;
        }
    }

    return 0;
}

/**************************************************/
/*               停止协议 (对齐 SS StopMonitor)     */
/**************************************************/

static
VOID
DmStopMonitor(
    _Inout_ PWKD_DIR_MONITOR Monitor
    )
/*++
Routine Description:
    停止单个 monitor: SetEvent → CancelIoEx → Wait(10s) →
    TerminateThread 兜底 → 关闭句柄。

Arguments:
    Monitor — monitor (槽位仍被占用, 由调用方管理状态)。

Return Value:
    无。
--*/
{
    if (Monitor->hStopEvent) {
        SetEvent(Monitor->hStopEvent);
    }
    if (Monitor->hDirectory && Monitor->hDirectory != INVALID_HANDLE_VALUE) {
        CancelIoEx(Monitor->hDirectory, &Monitor->Overlapped);
    }
    if (Monitor->hThread) {
        DWORD wr = WaitForSingleObject(Monitor->hThread, WKD_DIR_STOP_TIMEOUT_MS);
        if (wr != WAIT_OBJECT_0) {
            TerminateThread(Monitor->hThread, 1);
            WaitForSingleObject(Monitor->hThread, 1000);
        }
        CloseHandle(Monitor->hThread);
        Monitor->hThread = NULL;
    }
    if (Monitor->hStopEvent) {
        CloseHandle(Monitor->hStopEvent);
        Monitor->hStopEvent = NULL;
    }
    if (Monitor->Overlapped.hEvent) {
        CloseHandle(Monitor->Overlapped.hEvent);
        Monitor->Overlapped.hEvent = NULL;
    }
    if (Monitor->hDirectory && Monitor->hDirectory != INVALID_HANDLE_VALUE) {
        CloseHandle(Monitor->hDirectory);
        Monitor->hDirectory = INVALID_HANDLE_VALUE;
    }
    if (Monitor->Buffer) {
        free(Monitor->Buffer);
        Monitor->Buffer = NULL;
    }
    Monitor->IsPaused = 0;
}

static
VOID
DmStopAllMonitors(
    VOID
    )
/*++
Routine Description:
    摘除全部 monitor (锁外停止 worker, 避免持锁阻塞)。
--*/
{
    ULONG i;
    PWKD_DIR_MONITOR monitors = NULL;
    ULONG count = 0;
    ULONG ids[WKD_DIR_MAX_MONITORS];

    EnterCriticalSection(&g_DirMon.Lock);
    for (i = 0; i < WKD_DIR_MAX_MONITORS; i++) {
        if (g_DirMon.Monitors[i].State != WkdDirMonSt_Free) {
            ids[count++] = i;
        }
    }
    monitors = g_DirMon.Monitors;
    LeaveCriticalSection(&g_DirMon.Lock);

    for (i = 0; i < count; i++) {
        DmStopMonitor(&monitors[ids[i]]);
        EnterCriticalSection(&g_DirMon.Lock);
        RtlZeroMemory(&monitors[ids[i]], sizeof(WKD_DIR_MONITOR));
        monitors[ids[i]].State = WkdDirMonSt_Free;
        LeaveCriticalSection(&g_DirMon.Lock);
    }

    InterlockedExchange(&g_DirMon.Stats.ActiveMonitors, 0);
}

/**************************************************/
/*               回调分发 (锁外调用)                */
/**************************************************/

static
VOID
DmFireStatusCallback(
    _In_ ULONG MonitorId,
    _In_ BOOLEAN Active
    )
{
    WKD_DIR_STATUS_CB cb;

    EnterCriticalSection(&g_DirMon.CbLock);
    cb = g_DirMon.StatusCb;
    LeaveCriticalSection(&g_DirMon.CbLock);

    if (cb) {
        cb(MonitorId, Active);
    }
}

static
VOID
DmFireErrorCallback(
    _In_ PCWSTR Path,
    _In_ PCWSTR Error
    )
{
    WKD_DIR_ERROR_CB cb;

    EnterCriticalSection(&g_DirMon.CbLock);
    cb = g_DirMon.ErrorCb;
    LeaveCriticalSection(&g_DirMon.CbLock);

    if (cb) {
        cb(Path, Error);
    }
}

/**************************************************/
/*               生命周期                           */
/**************************************************/

NTSTATUS
DirectoryMonitor_Initialize(
    _In_opt_ const WKD_DIR_MONITOR_CONFIG* Config
    )
/*++
Routine Description:
    初始化目录监控。配置非法返回 STATUS_INVALID_PARAMETER;
    !Enabled 视为停用, 返回 STATUS_SUCCESS。
--*/
{
    ULONG i;

    if (g_DirMon.Initialized) {
        return STATUS_SUCCESS;
    }

    InitializeCriticalSection(&g_DirMon.Lock);
    InitializeCriticalSection(&g_DirMon.CbLock);
    QueryPerformanceFrequency(&g_DirMon.PerfFreq);
    InterlockedExchange(&g_DirMon.Status, WkdDirStatus_Initializing);

    if (Config) {
        if (!DmConfigIsValid(Config)) {
            InterlockedExchange(&g_DirMon.Status, WkdDirStatus_Error);
            DeleteCriticalSection(&g_DirMon.Lock);
            DeleteCriticalSection(&g_DirMon.CbLock);
            return STATUS_INVALID_PARAMETER;
        }
        g_DirMon.Config = *Config;
    } else {
        DmConfigDefault(&g_DirMon.Config);
    }

    for (i = 0; i < WKD_DIR_MAX_MONITORS; i++) {
        g_DirMon.Monitors[i].State = WkdDirMonSt_Free;
        g_DirMon.Monitors[i].hDirectory = INVALID_HANDLE_VALUE;
        g_DirMon.Monitors[i].hStopEvent = NULL;
        g_DirMon.Monitors[i].hThread    = NULL;
        g_DirMon.Monitors[i].Buffer     = NULL;
        g_DirMon.Monitors[i].pImpl      = &g_DirMon;
    }

    g_DirMon.NextMonitorId = 1;
    g_DirMon.NextEventId   = 1;
    g_DirMon.Initialized   = TRUE;

    /* 状态机 (对齐 SS: !Enabled 配置 = Stopped 非 Error) */
    InterlockedExchange(&g_DirMon.Status,
        g_DirMon.Config.Enabled ? WkdDirStatus_Running : WkdDirStatus_Stopped);

    return STATUS_SUCCESS;
}

VOID
DirectoryMonitor_Cleanup(
    VOID
    )
{
    if (!g_DirMon.Initialized) return;

    InterlockedExchange(&g_DirMon.Status, WkdDirStatus_Stopping);
    DmStopAllMonitors();

    EnterCriticalSection(&g_DirMon.CbLock);
    g_DirMon.EventCb  = NULL;
    g_DirMon.StatusCb = NULL;
    g_DirMon.ErrorCb  = NULL;
    LeaveCriticalSection(&g_DirMon.CbLock);

    g_DirMon.Initialized = FALSE;
    InterlockedExchange(&g_DirMon.Status, WkdDirStatus_Stopped);
    DeleteCriticalSection(&g_DirMon.Lock);
    DeleteCriticalSection(&g_DirMon.CbLock);
}

VOID
DirectoryMonitor_MonitorCriticalPaths(
    VOID
    )
/*++
Routine Description:
    按配置监控所有关键路径。单个失败仅记统计, 不中止。
--*/
{
    WCHAR roots[WKD_DIR_MAX_QUICK_ROOTS][DEF_MAX_PATH];
    ULONG count = 0;
    ULONG i;

    if (!g_DirMon.Initialized) return;

    if (g_DirMon.Config.MonitorSystemPaths) {
        count = 0;
        DmGetSystemCriticalPaths(roots, WKD_DIR_MAX_QUICK_ROOTS, &count);
        for (i = 0; i < count; i++) {
            (void)DirectoryMonitor_AddMonitor(roots[i], WkdDirCat_SystemCritical, FALSE);
        }
    }
    if (g_DirMon.Config.MonitorUserPaths) {
        count = 0;
        DmGetUserProfilePaths(roots, WKD_DIR_MAX_QUICK_ROOTS, &count);
        for (i = 0; i < count; i++) {
            (void)DirectoryMonitor_AddMonitor(roots[i], WkdDirCat_UserProfile, FALSE);
        }
    }
    if (g_DirMon.Config.MonitorStartupLocations) {
        count = 0;
        DmGetStartupPaths(roots, WKD_DIR_MAX_QUICK_ROOTS, &count);
        for (i = 0; i < count; i++) {
            (void)DirectoryMonitor_AddMonitor(roots[i], WkdDirCat_Startup, FALSE);
        }
    }
    {
        count = 0;
        DmGetDownloadPaths(roots, WKD_DIR_MAX_QUICK_ROOTS, &count);
        for (i = 0; i < count; i++) {
            (void)DirectoryMonitor_AddMonitor(roots[i], WkdDirCat_Downloads, FALSE);
        }
    }
    if (g_DirMon.Config.MonitorTempDirectories) {
        count = 0;
        DmGetTempPaths(roots, WKD_DIR_MAX_QUICK_ROOTS, &count);
        for (i = 0; i < count; i++) {
            (void)DirectoryMonitor_AddMonitor(roots[i], WkdDirCat_Temporary, FALSE);
        }
    }
}

/**************************************************/
/*               监控管理                           */
/**************************************************/

ULONG
DirectoryMonitor_AddMonitor(
    _In_ PCWSTR            Path,
    _In_ WKD_DIR_CATEGORY  Category,
    _In_ BOOLEAN           Recursive
    )
/*++
Routine Description:
    添加目录监控: 规范化 → reparse 拒绝 → 排除 → 去重 → 上限 →
    CreateFile(OPEN_REPARSE_POINT) → 句柄最终路径验证 → 建 worker。
--*/
{
    WCHAR canonical[DEF_MAX_PATH];
    ULONG slot;
    ULONG i;
    ULONG monitorId;
    PWKD_DIR_MONITOR monitor;
    HANDLE hDirectory = INVALID_HANDLE_VALUE;
    HANDLE hStopEvent = NULL;
    HANDLE hOverlapEvent = NULL;
    BYTE*  buffer = NULL;
    ULONG maxMonitors;

    if (!g_DirMon.Initialized || !Path || !Path[0]) {
        return 0;
    }

    if (!DmCanonicalizeFull(Path, canonical)) {
        return 0;
    }

    /* 拒绝 reparse point (TOCTOU 替换原语) */
    if (DmIsReparsePoint(canonical)) {
        DmFireErrorCallback(canonical, L"Refusing to monitor reparse point");
        return 0;
    }

    EnterCriticalSection(&g_DirMon.Lock);

    /* 排除路径 (规范化形式) */
    for (i = 0; i < g_DirMon.Config.ExcludedPathCount; i++) {
        if (_wcsicmp(g_DirMon.Config.ExcludedPaths[i], canonical) == 0) {
            LeaveCriticalSection(&g_DirMon.Lock);
            return 0;
        }
    }

    /* 去重 (已监控同路径) */
    for (i = 0; i < WKD_DIR_MAX_MONITORS; i++) {
        if (g_DirMon.Monitors[i].State != WkdDirMonSt_Free &&
            g_DirMon.Monitors[i].MonitorId != 0 &&
            _wcsicmp(g_DirMon.Monitors[i].Path, canonical) == 0) {
            LeaveCriticalSection(&g_DirMon.Lock);
            return g_DirMon.Monitors[i].MonitorId;
        }
    }

    /* 上限 */
    maxMonitors = g_DirMon.Config.MaxConcurrentMonitors;
    if (maxMonitors == 0) maxMonitors = WKD_DIR_MAX_MONITORS;
    slot = WKD_DIR_MAX_MONITORS;
    for (i = 0; i < WKD_DIR_MAX_MONITORS; i++) {
        if (g_DirMon.Monitors[i].State == WkdDirMonSt_Free) {
            slot = i;
            break;
        }
    }
    if (slot == WKD_DIR_MAX_MONITORS || slot >= maxMonitors) {
        LeaveCriticalSection(&g_DirMon.Lock);
        InterlockedIncrement64(&g_DirMon.Stats.Errors);
        return 0;
    }

    monitor = &g_DirMon.Monitors[slot];
    monitor->State = WkdDirMonSt_Starting;
    LeaveCriticalSection(&g_DirMon.Lock);

    /* 资源准备 (锁外, 不阻塞其他管理操作) */
    buffer = (BYTE*)malloc(WKD_DIR_NOTIFY_BUFFER);
    if (!buffer) {
        goto fail;
    }

    /* FILE_FLAG_OPEN_REPARSE_POINT: 打开不遍历 junction, 防替换竞态 */
    hDirectory = CreateFileW(
        canonical,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    if (hDirectory == INVALID_HANDLE_VALUE) {
        goto fail;
    }

    /* 句柄最终路径验证 (防 symlink/junction 前缀替换) */
    if (!DmVerifyHandleResolvesTo(hDirectory, canonical)) {
        DmFireErrorCallback(canonical, L"Handle does not resolve to canonical path");
        goto fail;
    }

    hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!hStopEvent) {
        goto fail;
    }
    hOverlapEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!hOverlapEvent) {
        goto fail;
    }

    /* 回填 monitor (槽位在 Remove 前保持占用) */
    EnterCriticalSection(&g_DirMon.Lock);
    monitorId = (ULONG)InterlockedIncrement(&g_DirMon.NextMonitorId);
    wcscpy_s(monitor->Path, DEF_MAX_PATH, canonical);
    monitor->MonitorId       = monitorId;
    monitor->Category        = Category;
    monitor->Recursive       = Recursive;
    monitor->IsPaused        = 0;
    monitor->EventsReceived  = 0;
    monitor->LastEventNs     = 0;
    GetSystemTimeAsFileTime((PFILETIME)&monitor->CreatedTime);
    monitor->hDirectory      = hDirectory;
    monitor->hStopEvent      = hStopEvent;
    monitor->hThread         = NULL;
    monitor->Buffer          = buffer;
    monitor->Overlapped.hEvent = hOverlapEvent;
    RtlZeroMemory(monitor->RateTimes, sizeof(monitor->RateTimes));
    monitor->RateCount    = 0;
    monitor->RateDropCount = 0;
    monitor->PendingOldValid = FALSE;
    monitor->PendingOldName[0] = L'\0';
    monitor->pImpl = &g_DirMon;
    LeaveCriticalSection(&g_DirMon.Lock);

    monitor->hThread = CreateThread(NULL, 0, DmMonitorThreadProc, monitor, 0, NULL);
    if (!monitor->hThread) {
        EnterCriticalSection(&g_DirMon.Lock);
        DmStopMonitor(monitor);
        RtlZeroMemory(monitor, sizeof(*monitor));
        monitor->State = WkdDirMonSt_Free;
        LeaveCriticalSection(&g_DirMon.Lock);
        return 0;
    }

    /* worker 已启动, 置 Active */
    EnterCriticalSection(&g_DirMon.Lock);
    if (monitor->State == WkdDirMonSt_Starting) {
        monitor->State = WkdDirMonSt_Active;
    }
    LeaveCriticalSection(&g_DirMon.Lock);

    InterlockedIncrement(&g_DirMon.Stats.ActiveMonitors);
    InterlockedIncrement64(&g_DirMon.Stats.PathsDiscovered);

    DmFireStatusCallback(monitorId, TRUE);

    return monitorId;

fail:
    if (hDirectory != INVALID_HANDLE_VALUE) CloseHandle(hDirectory);
    if (hStopEvent) CloseHandle(hStopEvent);
    if (hOverlapEvent) CloseHandle(hOverlapEvent);
    if (buffer) free(buffer);
    EnterCriticalSection(&g_DirMon.Lock);
    if (monitor) {
        RtlZeroMemory(monitor, sizeof(*monitor));
        monitor->State = WkdDirMonSt_Free;
        monitor->hDirectory = INVALID_HANDLE_VALUE;
    }
    LeaveCriticalSection(&g_DirMon.Lock);
    InterlockedIncrement64(&g_DirMon.Stats.Errors);
    return 0;
}

VOID
DirectoryMonitor_RemoveMonitor(
    _In_ ULONG MonitorId
    )
/*++
Routine Description:
    移除监控: 锁内标记 Stopping → 锁外停 worker → 锁内清槽。
--*/
{
    ULONG i;
    PWKD_DIR_MONITOR monitor = NULL;

    EnterCriticalSection(&g_DirMon.Lock);
    for (i = 0; i < WKD_DIR_MAX_MONITORS; i++) {
        /* 只移除 Active/Stopping 槽; Starting (AddMonitor 进行中) 不可移除, 防竞态 */
        if (g_DirMon.Monitors[i].MonitorId == MonitorId &&
            (g_DirMon.Monitors[i].State == WkdDirMonSt_Active ||
             g_DirMon.Monitors[i].State == WkdDirMonSt_Stopping)) {
            monitor = &g_DirMon.Monitors[i];
            monitor->State = WkdDirMonSt_Stopping;
            break;
        }
    }
    LeaveCriticalSection(&g_DirMon.Lock);

    if (!monitor) {
        return;
    }

    /* 锁外停止 worker (StopMonitor 阻塞等待线程退出) */
    DmStopMonitor(monitor);

    EnterCriticalSection(&g_DirMon.Lock);
    RtlZeroMemory(monitor, sizeof(*monitor));
    monitor->State = WkdDirMonSt_Free;
    monitor->hDirectory = INVALID_HANDLE_VALUE;
    LeaveCriticalSection(&g_DirMon.Lock);

    InterlockedDecrement(&g_DirMon.Stats.ActiveMonitors);
    DmFireStatusCallback(MonitorId, FALSE);
}

VOID
DirectoryMonitor_RemoveAll(
    VOID
    )
{
    ULONG i;

    for (i = 0; i < WKD_DIR_MAX_MONITORS; i++) {
        ULONG id;
        EnterCriticalSection(&g_DirMon.Lock);
        id = (g_DirMon.Monitors[i].State != WkdDirMonSt_Free)
                 ? g_DirMon.Monitors[i].MonitorId : 0;
        LeaveCriticalSection(&g_DirMon.Lock);
        if (id != 0) {
            DirectoryMonitor_RemoveMonitor(id);
        }
    }
}

BOOLEAN
DirectoryMonitor_IsMonitored(
    _In_ PCWSTR Path
    )
/*++
Routine Description:
    路径是否已被监控 (规范化后比较)。
--*/
{
    WCHAR canonical[DEF_MAX_PATH];
    ULONG i;
    BOOLEAN found = FALSE;

    if (!g_DirMon.Initialized || !Path) return FALSE;
    if (!DmCanonicalizeFull(Path, canonical)) return FALSE;

    EnterCriticalSection(&g_DirMon.Lock);
    for (i = 0; i < WKD_DIR_MAX_MONITORS; i++) {
        if (g_DirMon.Monitors[i].State == WkdDirMonSt_Free) continue;
        if (_wcsicmp(g_DirMon.Monitors[i].Path, canonical) == 0) {
            found = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&g_DirMon.Lock);
    return found;
}

ULONG
DirectoryMonitor_GetActiveCount(
    VOID
    )
{
    return (ULONG)InterlockedCompareExchange(&g_DirMon.Stats.ActiveMonitors, 0, 0);
}

VOID
DirectoryMonitor_PauseAll(
    VOID
    )
{
    ULONG i;
    EnterCriticalSection(&g_DirMon.Lock);
    for (i = 0; i < WKD_DIR_MAX_MONITORS; i++) {
        if (g_DirMon.Monitors[i].State == WkdDirMonSt_Active) {
            g_DirMon.Monitors[i].IsPaused = 1;
        }
    }
    LeaveCriticalSection(&g_DirMon.Lock);
    InterlockedExchange(&g_DirMon.Status, WkdDirStatus_Paused);
}

VOID
DirectoryMonitor_ResumeAll(
    VOID
    )
{
    ULONG i;
    EnterCriticalSection(&g_DirMon.Lock);
    for (i = 0; i < WKD_DIR_MAX_MONITORS; i++) {
        if (g_DirMon.Monitors[i].State == WkdDirMonSt_Active) {
            g_DirMon.Monitors[i].IsPaused = 0;
        }
    }
    LeaveCriticalSection(&g_DirMon.Lock);
    InterlockedExchange(&g_DirMon.Status, WkdDirStatus_Running);
}

VOID
DirectoryMonitor_PauseMonitor(
    _In_ ULONG MonitorId
    )
{
    ULONG i;
    EnterCriticalSection(&g_DirMon.Lock);
    for (i = 0; i < WKD_DIR_MAX_MONITORS; i++) {
        if (g_DirMon.Monitors[i].MonitorId == MonitorId &&
            g_DirMon.Monitors[i].State == WkdDirMonSt_Active) {
            g_DirMon.Monitors[i].IsPaused = 1;
            break;
        }
    }
    LeaveCriticalSection(&g_DirMon.Lock);
}

VOID
DirectoryMonitor_ResumeMonitor(
    _In_ ULONG MonitorId
    )
{
    ULONG i;
    EnterCriticalSection(&g_DirMon.Lock);
    for (i = 0; i < WKD_DIR_MAX_MONITORS; i++) {
        if (g_DirMon.Monitors[i].MonitorId == MonitorId &&
            g_DirMon.Monitors[i].State == WkdDirMonSt_Active) {
            g_DirMon.Monitors[i].IsPaused = 0;
            break;
        }
    }
    LeaveCriticalSection(&g_DirMon.Lock);
}

/**************************************************/
/*               回调注册                           */
/**************************************************/

VOID
DirectoryMonitor_SetEventCallback(
    _In_opt_ WKD_DIR_EVENT_CB Callback
    )
{
    EnterCriticalSection(&g_DirMon.CbLock);
    g_DirMon.EventCb = Callback;
    LeaveCriticalSection(&g_DirMon.CbLock);
}

VOID
DirectoryMonitor_SetStatusCallback(
    _In_opt_ WKD_DIR_STATUS_CB Callback
    )
{
    EnterCriticalSection(&g_DirMon.CbLock);
    g_DirMon.StatusCb = Callback;
    LeaveCriticalSection(&g_DirMon.CbLock);
}

VOID
DirectoryMonitor_SetErrorCallback(
    _In_opt_ WKD_DIR_ERROR_CB Callback
    )
{
    EnterCriticalSection(&g_DirMon.CbLock);
    g_DirMon.ErrorCb = Callback;
    LeaveCriticalSection(&g_DirMon.CbLock);
}

NTSTATUS
DirectoryMonitor_GetStatistics(
    _Out_ PWKD_DIR_STATS Stats
    )
{
    if (!Stats) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Stats, sizeof(*Stats));
    Stats->ActiveMonitors       = (ULONG)InterlockedCompareExchange(&g_DirMon.Stats.ActiveMonitors, 0, 0);
    Stats->TotalEvents          = InterlockedCompareExchange64(&g_DirMon.Stats.TotalEvents, 0, 0);
    Stats->FilteredEvents       = InterlockedCompareExchange64(&g_DirMon.Stats.FilteredEvents, 0, 0);
    Stats->RateLimitedEvents    = InterlockedCompareExchange64(&g_DirMon.Stats.RateLimitedEvents, 0, 0);
    Stats->Errors               = InterlockedCompareExchange64(&g_DirMon.Stats.Errors, 0, 0);
    Stats->PathsDiscovered      = InterlockedCompareExchange64(&g_DirMon.Stats.PathsDiscovered, 0, 0);
    Stats->CallbackInvocations  = InterlockedCompareExchange64(&g_DirMon.Stats.CallbackInvocations, 0, 0);
    Stats->TotalProcessingTimeUs = InterlockedCompareExchange64(&g_DirMon.Stats.TotalProcessingTimeUs, 0, 0);
    memcpy(Stats->ByCategory, g_DirMon.Stats.ByCategory, sizeof(Stats->ByCategory));
    memcpy(Stats->ByAction, g_DirMon.Stats.ByAction, sizeof(Stats->ByAction));

    return STATUS_SUCCESS;
}

/**************************************************/
/*               自测                               */
/**************************************************/

BOOLEAN
DirectoryMonitor_SelfTest(
    VOID
    )
/*++
Routine Description:
    生命周期自测: Temp 路径 Add → IsMonitored → Pause → Resume → Remove。
    对齐 SS SelfTest (裁剪掉统计/版本部分)。
--*/
{
    WCHAR tempPath[DEF_MAX_PATH];
    ULONG monitorId;

    if (!g_DirMon.Initialized) return FALSE;

    if (GetTempPathW(DEF_MAX_PATH, tempPath) == 0) {
        return FALSE;
    }

    monitorId = DirectoryMonitor_AddMonitor(tempPath, WkdDirCat_Temporary, FALSE);
    if (monitorId == 0) {
        return FALSE;
    }

    if (!DirectoryMonitor_IsMonitored(tempPath)) {
        DirectoryMonitor_RemoveMonitor(monitorId);
        return FALSE;
    }

    DirectoryMonitor_PauseMonitor(monitorId);
    DirectoryMonitor_ResumeMonitor(monitorId);
    DirectoryMonitor_RemoveMonitor(monitorId);

    if (DirectoryMonitor_IsMonitored(tempPath)) {
        return FALSE;
    }

    return TRUE;
}

/**************************************************/
/*               关键路径发现 (ScanManager 融合)    */
/**************************************************/

NTSTATUS
DirectoryMonitor_GetQuickScanRoots(
    _Out_writes_(MaxCount) WCHAR (*Roots)[DEF_MAX_PATH],
    _In_ ULONG             MaxCount,
    _Out_ PULONG           Count
    )
/*++
Routine Description:
    聚合五类关键路径, 供 ScanManager Quick 扫描多根遍历。
--*/
{
    ULONG count = 0;

    if (!Roots || !Count || MaxCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Roots, MaxCount * sizeof(Roots[0]));
    DmGetSystemCriticalPaths(Roots, MaxCount, &count);
    DmGetUserProfilePaths(Roots, MaxCount, &count);
    DmGetStartupPaths(Roots, MaxCount, &count);
    DmGetDownloadPaths(Roots, MaxCount, &count);
    DmGetTempPaths(Roots, MaxCount, &count);

    *Count = count;
    return (count > 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/**************************************************/
/*               查询/配置/统计补全                 */
/*  (对齐 SS GetMonitoredPaths/GetMonitorById/      */
/*   SetConfiguration/GetConfiguration/            */
/*   ResetStatistics/UnregisterCallbacks)          */
/**************************************************/

NTSTATUS
DirectoryMonitor_GetMonitoredPaths(
    _Out_writes_(MaxCount) PWKD_DIR_MONITORED_PATH Paths,
    _In_ ULONG             MaxCount,
    _Out_ PULONG           Count
    )
{
    ULONG i;
    ULONG n = 0;

    if (!Paths || !Count || MaxCount == 0) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&g_DirMon.Lock);
    for (i = 0; i < WKD_DIR_MAX_MONITORS && n < MaxCount; i++) {
        PWKD_DIR_MONITOR m = &g_DirMon.Monitors[i];
        if (m->State == WkdDirMonSt_Free) continue;

        RtlZeroMemory(&Paths[n], sizeof(Paths[n]));
        Paths[n].MonitorId      = m->MonitorId;
        wcscpy_s(Paths[n].Path, DEF_MAX_PATH, m->Path);
        Paths[n].Category       = m->Category;
        Paths[n].Recursive      = m->Recursive;
        Paths[n].IsActive       = (m->State == WkdDirMonSt_Active);
        Paths[n].EventsReceived = m->EventsReceived;
        Paths[n].LastEventNs.QuadPart    = m->LastEventNs;
        Paths[n].CreatedTime    = m->CreatedTime;
        n++;
    }
    LeaveCriticalSection(&g_DirMon.Lock);

    *Count = n;
    return STATUS_SUCCESS;
}

BOOLEAN
DirectoryMonitor_GetMonitorById(
    _In_ ULONG                  MonitorId,
    _Out_ PWKD_DIR_MONITORED_PATH Path
    )
{
    ULONG i;
    BOOLEAN found = FALSE;

    if (!Path) return FALSE;

    EnterCriticalSection(&g_DirMon.Lock);
    for (i = 0; i < WKD_DIR_MAX_MONITORS; i++) {
        PWKD_DIR_MONITOR m = &g_DirMon.Monitors[i];
        if (m->State == WkdDirMonSt_Free) continue;
        if (m->MonitorId == MonitorId) {
            RtlZeroMemory(Path, sizeof(*Path));
            Path->MonitorId      = m->MonitorId;
            wcscpy_s(Path->Path, DEF_MAX_PATH, m->Path);
            Path->Category       = m->Category;
            Path->Recursive      = m->Recursive;
            Path->IsActive       = (m->State == WkdDirMonSt_Active);
            Path->EventsReceived = m->EventsReceived;
            Path->LastEventNs.QuadPart    = m->LastEventNs;
            Path->CreatedTime    = m->CreatedTime;
            found = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&g_DirMon.Lock);
    return found;
}

NTSTATUS
DirectoryMonitor_SetConfiguration(
    _In_ const WKD_DIR_MONITOR_CONFIG* Config
    )
{
    if (!Config) return STATUS_INVALID_PARAMETER;
    if (!DmConfigIsValid(Config)) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&g_DirMon.Lock);
    g_DirMon.Config = *Config;
    LeaveCriticalSection(&g_DirMon.Lock);
    return STATUS_SUCCESS;
}

VOID
DirectoryMonitor_GetConfiguration(
    _Out_ PWKD_DIR_MONITOR_CONFIG Config
    )
{
    if (!Config) return;
    EnterCriticalSection(&g_DirMon.Lock);
    *Config = g_DirMon.Config;
    LeaveCriticalSection(&g_DirMon.Lock);
}

VOID
DirectoryMonitor_ResetStatistics(
    VOID
    )
{
    InterlockedExchange(&g_DirMon.Stats.ActiveMonitors, 0);
    InterlockedExchange64(&g_DirMon.Stats.TotalEvents, 0);
    InterlockedExchange64(&g_DirMon.Stats.FilteredEvents, 0);
    InterlockedExchange64(&g_DirMon.Stats.RateLimitedEvents, 0);
    InterlockedExchange64(&g_DirMon.Stats.Errors, 0);
    InterlockedExchange64(&g_DirMon.Stats.PathsDiscovered, 0);
    InterlockedExchange64(&g_DirMon.Stats.CallbackInvocations, 0);
    InterlockedExchange64(&g_DirMon.Stats.TotalProcessingTimeUs, 0);
    RtlZeroMemory(g_DirMon.Stats.ByCategory, sizeof(g_DirMon.Stats.ByCategory));
    RtlZeroMemory(g_DirMon.Stats.ByAction, sizeof(g_DirMon.Stats.ByAction));
}

VOID
DirectoryMonitor_UnregisterCallbacks(
    VOID
    )
{
    EnterCriticalSection(&g_DirMon.CbLock);
    g_DirMon.EventCb  = NULL;
    g_DirMon.StatusCb = NULL;
    g_DirMon.ErrorCb  = NULL;
    LeaveCriticalSection(&g_DirMon.CbLock);
}

/**************************************************/
/*               状态/诊断补全                      */
/*  (对齐 SS IsInitialized/GetStatus/              */
/*   GetAverageProcessingTimeMs/GetVersionString/  */
/*   枚举名/ToJson)                                */
/**************************************************/

BOOLEAN
DirectoryMonitor_IsInitialized(
    VOID
    )
{
    return g_DirMon.Initialized;
}

WKD_DIR_STATUS
DirectoryMonitor_GetStatus(
    VOID
    )
{
    return (WKD_DIR_STATUS)InterlockedCompareExchange(&g_DirMon.Status, 0, 0);
}

double
DirectoryMonitor_GetAverageProcessingTimeMs(
    VOID
    )
{
    LONG64 total = InterlockedCompareExchange64(&g_DirMon.Stats.TotalEvents, 0, 0);
    LONG64 us;

    if (total == 0) return 0.0;
    us = InterlockedCompareExchange64(&g_DirMon.Stats.TotalProcessingTimeUs, 0, 0);
    return ((double)us / (double)total) / 1000.0;
}

PCWSTR
DirectoryMonitor_GetVersionString(
    VOID
    )
{
    /* 对齐 SS DirectoryMonitorConstants VERSION_MAJOR/MINOR/PATCH */
    return L"3.0.0";
}

PCWSTR
DirectoryMonitor_GetCategoryName(
    _In_ WKD_DIR_CATEGORY Category
    )
{
    switch (Category) {
    case WkdDirCat_Unknown:        return L"Unknown";
    case WkdDirCat_SystemCritical: return L"SystemCritical";
    case WkdDirCat_UserProfile:    return L"UserProfile";
    case WkdDirCat_Startup:        return L"Startup";
    case WkdDirCat_Downloads:      return L"Downloads";
    case WkdDirCat_Temporary:      return L"Temporary";
    case WkdDirCat_RemovableMedia: return L"RemovableMedia";
    case WkdDirCat_NetworkShare:   return L"NetworkShare";
    case WkdDirCat_CloudSync:      return L"CloudSync";
    case WkdDirCat_Custom:         return L"Custom";
    }
    return L"Unknown";
}

PCWSTR
DirectoryMonitor_GetActionName(
    _In_ WKD_DIR_ACTION Action
    )
{
    switch (Action) {
    case WkdDirAct_Unknown:      return L"Unknown";
    case WkdDirAct_FileAdded:    return L"FileAdded";
    case WkdDirAct_FileRemoved:  return L"FileRemoved";
    case WkdDirAct_FileModified: return L"FileModified";
    case WkdDirAct_FileRenamed:  return L"FileRenamed";
    case WkdDirAct_DirAdded:     return L"DirectoryAdded";
    case WkdDirAct_DirRemoved:   return L"DirectoryRemoved";
    case WkdDirAct_DirRenamed:   return L"DirectoryRenamed";
    }
    return L"Unknown";
}

PCWSTR
DirectoryMonitor_GetStatusName(
    _In_ WKD_DIR_STATUS Status
    )
{
    switch (Status) {
    case WkdDirStatus_Uninitialized: return L"Uninitialized";
    case WkdDirStatus_Initializing:  return L"Initializing";
    case WkdDirStatus_Running:       return L"Running";
    case WkdDirStatus_Paused:        return L"Paused";
    case WkdDirStatus_Error:         return L"Error";
    case WkdDirStatus_Stopping:      return L"Stopping";
    case WkdDirStatus_Stopped:       return L"Stopped";
    }
    return L"Unknown";
}

/**************************************************/
/*               ToJson 序列化 (死代码工具)         */
/**************************************************/

/* JSON 字符串转义 (防引号/反斜杠破坏 JSON, 对齐 SS EscapeJson) */
static
VOID
DmJsonEscape(
    _In_ PCWSTR In,
    _Out_writes_(MaxLen) WCHAR* Out,
    _In_ ULONG MaxLen
    )
{
    ULONG o = 0;

    if (!In || MaxLen == 0) return;
    while (*In && o + 1 < MaxLen) {
        if (*In == L'"' || *In == L'\\') {
            if (o + 2 < MaxLen) {
                Out[o++] = L'\\';
                Out[o++] = *In;
            } else {
                break;
            }
        } else {
            Out[o++] = *In;
        }
        In++;
    }
    Out[o] = L'\0';
}

NTSTATUS
DirectoryMonitor_EventToJson(
    _In_ const WKD_DIR_EVENT* Evt,
    _Out_writes_(MaxLen) WCHAR* Out,
    _In_ ULONG MaxLen
    )
{
    WCHAR path[DEF_MAX_PATH * 2];
    WCHAR file[WKD_DIR_MAX_FILENAME * 2];

    if (!Evt || !Out || MaxLen == 0) return STATUS_INVALID_PARAMETER;

    DmJsonEscape(Evt->Path, path, DEF_MAX_PATH * 2);
    DmJsonEscape(Evt->FileName, file, WKD_DIR_MAX_FILENAME * 2);
    _snwprintf_s(Out, MaxLen, _TRUNCATE,
        L"{\"eventId\":%lu,\"monitorId\":%lu,\"path\":\"%ls\",\"filename\":\"%ls\","
        L"\"action\":%d,\"category\":%d}",
        Evt->EventId, Evt->MonitorId, path, file,
        (int)Evt->Action, (int)Evt->Category);
    return STATUS_SUCCESS;
}

NTSTATUS
DirectoryMonitor_PathToJson(
    _In_ const WKD_DIR_MONITORED_PATH* Path,
    _Out_writes_(MaxLen) WCHAR* Out,
    _In_ ULONG MaxLen
    )
{
    WCHAR path[DEF_MAX_PATH * 2];

    if (!Path || !Out || MaxLen == 0) return STATUS_INVALID_PARAMETER;

    DmJsonEscape(Path->Path, path, DEF_MAX_PATH * 2);
    _snwprintf_s(Out, MaxLen, _TRUNCATE,
        L"{\"monitorId\":%lu,\"path\":\"%ls\",\"category\":%d,"
        L"\"recursive\":%s,\"isActive\":%s,\"eventsReceived\":%lld}",
        Path->MonitorId, path, (int)Path->Category,
        Path->Recursive ? L"true" : L"false",
        Path->IsActive ? L"true" : L"false",
        (LONGLONG)Path->EventsReceived);
    return STATUS_SUCCESS;
}

NTSTATUS
DirectoryMonitor_ConfigToJson(
    _In_ const WKD_DIR_MONITOR_CONFIG* Config,
    _Out_writes_(MaxLen) WCHAR* Out,
    _In_ ULONG MaxLen
    )
{
    if (!Config || !Out || MaxLen == 0) return STATUS_INVALID_PARAMETER;

    _snwprintf_s(Out, MaxLen, _TRUNCATE,
        L"{\"enabled\":%s,\"monitorSystemPaths\":%s,\"monitorUserPaths\":%s,"
        L"\"monitorStartupLocations\":%s,\"monitorTempDirectories\":%s,"
        L"\"enableRateLimiting\":%s,\"enableIntelligentFiltering\":%s,"
        L"\"maxConcurrentMonitors\":%lu}",
        Config->Enabled ? L"true" : L"false",
        Config->MonitorSystemPaths ? L"true" : L"false",
        Config->MonitorUserPaths ? L"true" : L"false",
        Config->MonitorStartupLocations ? L"true" : L"false",
        Config->MonitorTempDirectories ? L"true" : L"false",
        Config->EnableRateLimiting ? L"true" : L"false",
        Config->EnableIntelligentFiltering ? L"true" : L"false",
        Config->MaxConcurrentMonitors);
    return STATUS_SUCCESS;
}

NTSTATUS
DirectoryMonitor_StatsToJson(
    _In_ const WKD_DIR_STATS* Stats,
    _Out_writes_(MaxLen) WCHAR* Out,
    _In_ ULONG MaxLen
    )
{
    double avg;

    if (!Stats || !Out || MaxLen == 0) return STATUS_INVALID_PARAMETER;

    avg = (Stats->TotalEvents > 0)
        ? ((double)Stats->TotalProcessingTimeUs / (double)Stats->TotalEvents) / 1000.0
        : 0.0;
    _snwprintf_s(Out, MaxLen, _TRUNCATE,
        L"{\"activeMonitors\":%ld,\"totalEvents\":%lld,\"filteredEvents\":%lld,"
        L"\"rateLimitedEvents\":%lld,\"errors\":%lld,\"callbackInvocations\":%lld,"
        L"\"pathsDiscovered\":%lld,\"avgProcessingTimeMs\":%.3f}",
        (LONG)Stats->ActiveMonitors,
        (LONGLONG)Stats->TotalEvents,
        (LONGLONG)Stats->FilteredEvents,
        (LONGLONG)Stats->RateLimitedEvents,
        (LONGLONG)Stats->Errors,
        (LONGLONG)Stats->CallbackInvocations,
        (LONGLONG)Stats->PathsDiscovered,
        avg);
    return STATUS_SUCCESS;
}
