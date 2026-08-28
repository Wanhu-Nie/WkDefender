/**************************************************/
/*  WkDefender 文件锁管理 — 实现                    */
/*                                                  */
/*  迁移自 ShadowStrike FileLockManager.cpp         */
/*  (The Keymaster, v4.0), 功能重实现非源码复制。    */
/*  各函数注释引用 SS 源文件行号。                   */
/*                                                  */
/*  功能面:                                         */
/*    锁检测 (IsFileLocked/GetLockType/CanDelete/    */
/*    双路枚举) + 五级解锁链 + RM + 重启调度 +       */
/*    威胁关联 + 内核协议(死代码)                    */
/*                                                  */
/*  融合决策: 签名验证→IocVerifySignature;   */
/*    终止→ProcessManager_KillProcess; 内核解锁→     */
/*    死代码 (SS 驱动端未实现); 回调→ALPC 覆盖废弃。  */
/**************************************************/

#include "FileLockManager.h"

#include <winternl.h>
#include <restartmanager.h>
#include <ntstatus.h>

#include "process_manager.h"
#include "IOC/IocScanner.h"
#include "Common/Utils.h"

/* RM 静态链接 (SS #pragma comment(lib,"Rstrtmgr.lib")) */
#pragma comment(lib, "Rstrtmgr.lib")

/**************************************************/
/*              内部常量 / NT 结构                   */
/**************************************************/

/* 系统句柄枚举类 (SS L107 SystemExtendedHandleInformationClass) */
#define WKD_FLM_SYSTEM_EXT_HANDLE_INFO   64

/* 句柄枚举最大缓冲 (SS MAX_HANDLE_BUFFER_BYTES = 256MB) */
#define WKD_FLM_MAX_HANDLE_BUFFER_BYTES  ((ULONG)256 << 20)

#define WKD_FLM_NT_STATUS_INFO_LEN_MISMATCH ((NTSTATUS)0xC0000004L)

/* 关键进程名单 (对齐 SS L91-102 CRITICAL_PROC_NAMES) */
static const PCWSTR g_FlmCriticalProcessNames[] = {
    L"system", L"csrss.exe", L"smss.exe", L"wininit.exe", L"services.exe",
    L"lsass.exe", L"svchost.exe", L"winlogon.exe", L"explorer.exe",
    L"dwm.exe"
};
#define WKD_FLM_CRITICAL_PROC_COUNT \
    (sizeof(g_FlmCriticalProcessNames) / sizeof(g_FlmCriticalProcessNames[0]))

/* 句柄表项 (对齐 SS L115-130, 64 位安全) */
typedef struct _WKD_FLM_SYSTEM_HANDLE_ENTRY_EX {
    PVOID       Object;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
} WKD_FLM_SYSTEM_HANDLE_ENTRY_EX;

typedef struct _WKD_FLM_SYSTEM_HANDLE_INFO_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    WKD_FLM_SYSTEM_HANDLE_ENTRY_EX Handles[1];
} WKD_FLM_SYSTEM_HANDLE_INFO_EX;

typedef NTSTATUS (NTAPI *WKD_FLM_NT_QUERY_SYSTEM_INFORMATION)(
    _In_  ULONG  SystemInformationClass,
    _In_  PVOID  SystemInformation,
    _In_  ULONG  SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

/* 死代码: SS Initialize 解析 (L231-233) 但从未使用, 保留对齐 */
typedef NTSTATUS (NTAPI *WKD_FLM_NT_QUERY_OBJECT_INFORMATION)(
    _In_  HANDLE Handle,
    _In_  ULONG  ObjectInformationClass,
    _Out_ PVOID  ObjectInformation,
    _In_  ULONG  ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

/* RM 会话辅助键缓冲 (对齐 SS CCH_RM_SESSION_KEY) */
#define WKD_FLM_RM_SESSION_KEY_BUFLEN 256

/**************************************************/
/*   内核通信协议 (死代码, 对齐 SS L200-212)        */
/*   SS 驱动端未实现该协议 (PhantomSensor CommPort  */
/*   switch 无这些命令), 纯用户态预留。              */
/**************************************************/

enum {
    WkdFlmKernelCmd_QueryFileLocks   = 0x200,
    WkdFlmKernelCmd_ForceCloseHandle = 0x201,
    WkdFlmKernelCmd_LockForQuarantine = 0x202,
    WkdFlmKernelCmd_ReleaseFileLock  = 0x203
};

typedef struct _WKD_FLM_KERNEL_REQ_HEADER {
    ULONG Command;
    ULONG DataLength;
} WKD_FLM_KERNEL_REQ_HEADER;

typedef struct _WKD_FLM_KERNEL_FORCE_CLOSE_REQ {
    WKD_FLM_KERNEL_REQ_HEADER Header;
    ULONG  TargetProcessId;
    ULONG64 HandleValue;
    WCHAR  FilePath[260];
} WKD_FLM_KERNEL_FORCE_CLOSE_REQ;

typedef struct _WKD_FLM_KERNEL_QUERY_LOCKS_REQ {
    WKD_FLM_KERNEL_REQ_HEADER Header;
    WCHAR  FilePath[260];
} WKD_FLM_KERNEL_QUERY_LOCKS_REQ;

typedef struct _WKD_FLM_KERNEL_RESP_HEADER {
    ULONG Status;
    ULONG DataLength;
} WKD_FLM_KERNEL_RESP_HEADER;

typedef struct _WKD_FLM_KERNEL_FORCE_CLOSE_RESP {
    WKD_FLM_KERNEL_RESP_HEADER Header;
    ULONG HandlesAffected;
    ULONG ErrorCode;
} WKD_FLM_KERNEL_FORCE_CLOSE_RESP;

/* fltUser 动态加载 (死代码, 避免 FltLib.lib 静态依赖) */
typedef HRESULT (WINAPI *WKD_FLM_FILTER_CONNECT_COMM)(
    _In_ PCWSTR lpPortName,
    _In_ DWORD dwFlags,
    _In_opt_ const VOID* lpContext,
    _In_ DWORD dwSizeOfContext,
    _In_opt_ PVOID lpSecurityAttributes,
    _Out_ PHANDLE hPort
    );
typedef HRESULT (WINAPI *WKD_FLM_FILTER_SEND_MESSAGE)(
    _In_ HANDLE hPort,
    _In_opt_ const VOID* lpMessage,
    _In_ DWORD dwMessageSize,
    _In_opt_ LPVOID lpReply,
    _In_ DWORD dwReplySize,
    _Out_opt_ LPDWORD lpBytesReceived
    );

/**************************************************/
/*               模块级全局状态                     */
/**************************************************/

typedef struct _WKD_FLM_GLOBAL {
    WKD_FILE_LOCK_CONFIG Config;
    BOOLEAN     Initialized;
    BOOLEAN     HasDebugPrivilege;
    BOOLEAN     KernelDriverAvailable;
    BOOLEAN     KernelPortConnected;
    HANDLE      KernelPort;
    UINT8       FileTypeIndex;

    WKD_FLM_NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInfo;
    WKD_FLM_NT_QUERY_OBJECT_INFORMATION NtQueryObject;   /* 死代码: SS 解析未使用 (对齐 L231-233) */

    /* 回调 (死代码: ALPC 覆盖告警分发, 保留 SS API 面对齐) */
    WKD_FLM_TERMINATE_CALLBACK TerminateCb;
    WKD_FLM_PROGRESS_CALLBACK  ProgressCb;
    WKD_FLM_LOCK_EVENT_CALLBACK LockEventCb;

    WKD_FILE_LOCK_STATS Stats;

    WKD_PENDING_OPERATION PendingOps[WKD_FLM_MAX_PENDING];
    ULONG           PendingCount;

    CRITICAL_SECTION Lock;
    CRITICAL_SECTION PendingLock;
    CRITICAL_SECTION KernelLock;
    CRITICAL_SECTION CallbackLock;   /* 回调注册/读取 (对齐 SS m_callbackMutex) */
} WKD_FLM_GLOBAL;

static WKD_FLM_GLOBAL g_Flm;

/**************************************************/
/*               内部辅助函数声明                   */
/**************************************************/

static BOOLEAN FlmNormalizePath(_In_ PCWSTR Path, _Out_writes_(OutCch) PWCHAR Out, _In_ ULONG OutCch);
static BOOLEAN FlmEnableDebugPrivilege(VOID);
static BOOLEAN FlmIsCriticalProcessName(_In_ PCWSTR Name);
static UINT8   FlmResolveObjectTypeIndex(VOID);
static WKD_LOCK_TYPE FlmClassifyLockType(_In_ ULONG AccessMask);
static VOID    FlmEnrichProcessInfo(_Inout_ PWKD_LOCK_OWNER Owner);
static BOOLEAN FlmVerifyFileSignature(_In_ PCWSTR Path);
static BOOLEAN FlmDetectProcessInjection(_In_ ULONG Pid);
static BOOLEAN FlmRmViaSession(_In_ PCWSTR FilePath, _In_ BOOLEAN Shutdown);
static ULONG   FlmGetLockingProcessesRM(_In_ PCWSTR FilePath, _Out_ PWKD_LOCK_OWNER Owners, _In_ ULONG MaxOwners);
static ULONG   FlmGetLockingProcessesHandleEnum(_In_ PCWSTR FilePath, _Out_ PWKD_LOCK_OWNER Owners, _In_ ULONG MaxOwners);
static ULONG   FlmCollectLockingProcesses(_In_ PCWSTR NormPath, _Out_ PWKD_LOCK_OWNER Owners, _In_ ULONG MaxOwners);
static NTSTATUS FlmGetLockingProcessesInternal(_In_ PCWSTR FilePath, _Out_ PWKD_LOCK_OWNER* Owners, _Out_ PULONG Count);
static WKD_LOCK_PATTERN FlmDetectLockPatternInternal(_In_ const WKD_FILE_LOCK_INFO* Info);
static VOID    FlmAnalyzeThreatInternal(_In_ const WKD_FILE_LOCK_INFO* Info, _Out_ PWKD_THREAT_ASSESSMENT Threat);
static BOOLEAN FlmTryRestartManager(_In_ PCWSTR FilePath, _Inout_ PWKD_UNLOCK_OPERATION Op);
static BOOLEAN FlmTryHandleClose(_In_ const WKD_LOCK_OWNER* Owners, _In_ ULONG Count, _Inout_ PWKD_UNLOCK_OPERATION Op);
static BOOLEAN FlmTryProcessTerminate(_In_ const WKD_LOCK_OWNER* Owners, _In_ ULONG Count, _Inout_ PWKD_UNLOCK_OPERATION Op);
static BOOLEAN FlmTryKernelUnlock(_In_ PCWSTR FilePath, _Inout_ PWKD_UNLOCK_OPERATION Op);
static VOID    FlmFinalizeResult(_Inout_ PWKD_UNLOCK_OPERATION Op, _In_ ULONG64 StartUs);
static ULONG64 FlmQueryPerfUs(VOID);
static VOID    FlmAddError(_Inout_ PWKD_UNLOCK_OPERATION Op, _In_ PCSTR Text);
static VOID    FlmReportProgress(_In_ PCWSTR Status, _In_ ULONG Percent);
static BOOLEAN FlmCheckKernelDriver(VOID);
static BOOLEAN FlmConnectKernelDriverInternalLocked(VOID);

/**************************************************/
/*                内部辅助函数实现                  */
/**************************************************/

/*++
 * FlmNormalizePath — GetFullPathNameW 两遍归一化 (对齐 SS L719-734)。
 *   返回 FALSE 表示路径非法/超长 (调用方回退用原路径)。
 *--*/
static BOOLEAN
FlmNormalizePath(
    _In_ PCWSTR Path,
    _Out_writes_(OutCch) PWCHAR Out,
    _In_ ULONG OutCch
    )
{
    DWORD len;
    DWORD written;

    if (!Path || !Path[0] || OutCch == 0) return FALSE;

    len = GetFullPathNameW(Path, 0, NULL, NULL);
    if (len == 0 || len >= OutCch) return FALSE;

    written = GetFullPathNameW(Path, len, Out, NULL);
    if (written == 0 || written >= OutCch) return FALSE;

    Out[written] = L'\0';
    return TRUE;
}

/*++
 * FlmEnableDebugPrivilege — 启用 SeDebugPrivilege (对齐 SS L736-747)。
 *   注: wkd process_manager.c WkEnableDebugPrivilege(static, :3056) 同实现,
 *   本模块独立保留避免跨模块 static 依赖; 后续可统一提升为 Ut 工具。
 *--*/
static BOOLEAN
FlmEnableDebugPrivilege(
    VOID
    )
{
    HANDLE hToken = NULL;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_PRIVILEGE_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

/*++
 * FlmIsCriticalProcessName — 关键进程名判定 (对齐 SS L97-102)。
 *   大小写不敏感精确匹配 g_FlmCriticalProcessNames。
 *--*/
static BOOLEAN
FlmIsCriticalProcessName(
    _In_ PCWSTR Name
    )
{
    ULONG i;

    if (!Name) return FALSE;
    for (i = 0; i < WKD_FLM_CRITICAL_PROC_COUNT; i++) {
        if (_wcsicmp(Name, g_FlmCriticalProcessNames[i]) == 0) return TRUE;
    }
    return FALSE;
}

/*++
 * FlmResolveObjectTypeIndex — 探测 File 对象 ObjectTypeIndex (对齐 SS L761-812)。
 *   临时文件 %TEMP%\WkFlmXXX 打开后经 SystemExtendedHandleInformation 查自身句柄。
 *   返回 0 表示探测失败 (句柄枚举跳过类型过滤)。
 *--*/
static UINT8
FlmResolveObjectTypeIndex(
    VOID
    )
{
    WCHAR tempDir[MAX_PATH] = { 0 };
    WCHAR tempFile[MAX_PATH] = { 0 };
    HANDLE hFile;
    DWORD tdLen;
    ULONG bufSize;
    PBYTE buf = NULL;
    NTSTATUS st;
    WKD_FLM_SYSTEM_HANDLE_INFO_EX* info;
    ULONG_PTR i;

    if (!g_Flm.NtQuerySystemInfo) return 0;

    tdLen = GetTempPathW(MAX_PATH, tempDir);
    if (tdLen == 0 || tdLen >= MAX_PATH) return 0;
    if (GetTempFileNameW(tempDir, L"WkFlm", 0, tempFile) == 0) return 0;

    hFile = CreateFileW(tempFile, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DeleteFileW(tempFile);
        return 0;
    }

    bufSize = 1u << 20;
    buf = (PBYTE)UtHeapAlloc(bufSize);
    if (!buf) { CloseHandle(hFile); return 0; }

    st = g_Flm.NtQuerySystemInfo(WKD_FLM_SYSTEM_EXT_HANDLE_INFO, buf, bufSize, NULL);
    while (st == WKD_FLM_NT_STATUS_INFO_LEN_MISMATCH && bufSize < WKD_FLM_MAX_HANDLE_BUFFER_BYTES) {
        if (bufSize > WKD_FLM_MAX_HANDLE_BUFFER_BYTES / 2) break;
        bufSize *= 2;
        UtHeapFree(buf);
        buf = (PBYTE)UtHeapAlloc(bufSize);
        if (!buf) { CloseHandle(hFile); return 0; }
        st = g_Flm.NtQuerySystemInfo(WKD_FLM_SYSTEM_EXT_HANDLE_INFO, buf, bufSize, NULL);
    }

    if (st >= 0) {
        DWORD myPid = GetCurrentProcessId();
        info = (WKD_FLM_SYSTEM_HANDLE_INFO_EX*)buf;
        for (i = 0; i < info->NumberOfHandles; i++) {
            const WKD_FLM_SYSTEM_HANDLE_ENTRY_EX* e = &info->Handles[i];
            if ((DWORD)e->UniqueProcessId == myPid &&
                (HANDLE)e->HandleValue == hFile) {
                UINT8 idx = (UINT8)e->ObjectTypeIndex;
                CloseHandle(hFile);
                UtHeapFree(buf);
                return idx;
            }
        }
    }

    CloseHandle(hFile);
    UtHeapFree(buf);
    return 0;
}

/*++
 * FlmClassifyLockType — 访问掩码 → 锁类型 (对齐 SS L814-824)。
 *--*/
static WKD_LOCK_TYPE
FlmClassifyLockType(
    _In_ ULONG AccessMask
    )
{
    BOOLEAN canWrite = (AccessMask & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE)) != 0;
    BOOLEAN canRead  = (AccessMask & (FILE_READ_DATA | GENERIC_READ)) != 0;
    BOOLEAN hasDelete = (AccessMask & DELETE) != 0;

    if (canWrite && hasDelete) return WkdLock_Exclusive;
    if (canWrite && canRead)  return WkdLock_ReadWrite;
    if (canWrite) return WkdLock_Write;
    if (canRead)  return WkdLock_Read;
    if (hasDelete) return WkdLock_Delete;
    return WkdLock_Read;
}

/*++
 * FlmVerifyFileSignature — 文件签名验证 (复用 wkd IocVerifySignature,
 *   对齐 SS VerifyFileSignature L956-968)。签名成功返回 TRUE。
 *--*/
static BOOLEAN
FlmVerifyFileSignature(
    _In_ PCWSTR Path
    )
{
    IOC_SCAN_RESULT scanResult;

    if (!Path || !Path[0]) return FALSE;

    RtlZeroMemory(&scanResult, sizeof(scanResult));
    return NT_SUCCESS(IocVerifySignature(Path, &scanResult));
}

/*++
 * FlmDetectProcessInjection — 轻量注入探测 (对齐 SS L970-996)。
 *   遍历进程内存, MEM_PRIVATE + PAGE_EXECUTE* 区域 ≥3 判定。
 *   注: wkd IoaInjectionClassifier 阶段4.5 有更强注入判定, 本实现
 *   仅用于锁 owner 快照富化 (低开销 VirtualQueryEx 计数)。
 *--*/
static BOOLEAN
FlmDetectProcessInjection(
    _In_ ULONG Pid
    )
{
    HANDLE hProc;
    MEMORY_BASIC_INFORMATION mbi;
    PUCHAR addr = NULL;
    ULONG suspiciousCount = 0;
    const ULONG threshold = 3;

    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!hProc) {
        hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Pid);
        if (!hProc) return FALSE;
    }

    while (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.Type == MEM_PRIVATE &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            suspiciousCount++;
            if (suspiciousCount >= threshold) {
                CloseHandle(hProc);
                return TRUE;
            }
        }
        addr = (PUCHAR)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (PUCHAR)mbi.BaseAddress) break;
    }

    CloseHandle(hProc);
    return FALSE;
}

/*++
 * FlmEnrichProcessInfo — 富化锁 owner (对齐 SS L924-938)。
 *   QueryFullProcessImageNameW → 路径/名; isSystem (pid<=4);
 *   isCritical (名单); 信任分析 (签名+注入)。
 *--*/
static VOID
FlmEnrichProcessInfo(
    _Inout_ PWKD_LOCK_OWNER Owner
    )
{
    HANDLE hProc;
    WCHAR exePath[WKD_FLM_MAX_PROC_PATH];
    DWORD sz;
    PCWSTR base;

    if (!Owner) return;

    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Owner->Pid);
    if (!hProc) return;

    sz = WKD_FLM_MAX_PROC_PATH;
    if (QueryFullProcessImageNameW(hProc, 0, exePath, &sz)) {
        wcsncpy_s(Owner->ProcessPath, WKD_FLM_MAX_PROC_PATH, exePath, _TRUNCATE);
        base = wcsrchr(exePath, L'\\');
        if (base) {
            wcsncpy_s(Owner->ProcessName, WKD_FLM_MAX_PROC_NAME, base + 1, _TRUNCATE);
        } else {
            wcsncpy_s(Owner->ProcessName, WKD_FLM_MAX_PROC_NAME, exePath, _TRUNCATE);
        }
    }
    CloseHandle(hProc);

    Owner->IsSystemProcess = (Owner->Pid <= WKD_FLM_SYSTEM_PID);
    Owner->IsCriticalProcess = FlmIsCriticalProcessName(Owner->ProcessName);

    /* 信任分析 (对齐 SS AnalyzeProcessTrust L947-955) */
    if (Owner->ProcessPath[0] == L'\0') {
        Owner->IsSuspicious = TRUE;
        return;
    }
    Owner->IsSigned = FlmVerifyFileSignature(Owner->ProcessPath);
    Owner->IsInjectedProcess = FlmDetectProcessInjection(Owner->Pid);
    Owner->IsSuspicious = (!Owner->IsSigned) || Owner->IsInjectedProcess;
    Owner->IsUntrustedSigner = !Owner->IsSigned;
}

/*++
 * FlmRmViaSession — Restart Manager 会话辅助 (对齐 SS L826-853/L570-588)。
 *   Shutdown=TRUE 时 RmShutdown(RmForceShutdown) 强关应用 (UseRestartManagerOp);
 *   FALSE 时仅注册+枚举探测 (GetLockingProcessesRM 已独立实现枚举, 本辅助
 *   主要用于 UseRestartManagerOp 的会话生命周期)。
 *--*/
static BOOLEAN
FlmRmViaSession(
    _In_ PCWSTR FilePath,
    _In_ BOOLEAN Shutdown
    )
{
    DWORD dwSession = 0;
    WCHAR szKey[WKD_FLM_RM_SESSION_KEY_BUFLEN] = { 0 };
    DWORD err;
    LPCWSTR pszFile = FilePath;
    UINT needed = 0, count = 0;
    DWORD dwRebootReasons = 0;
    BOOLEAN success = FALSE;

    if (!FilePath) return FALSE;

    err = RmStartSession(&dwSession, 0, szKey);
    if (err != ERROR_SUCCESS) return FALSE;

    err = RmRegisterResources(dwSession, 1, &pszFile, 0, NULL, 0, NULL);
    if (err != ERROR_SUCCESS) { RmEndSession(dwSession); return FALSE; }

    err = RmGetList(dwSession, &needed, &count, NULL, &dwRebootReasons);
    if (Shutdown) {
        if ((err == ERROR_SUCCESS || err == ERROR_MORE_DATA) && needed > 0 &&
            needed <= WKD_FLM_MAX_OWNERS) {
            RM_PROCESS_INFO* procs =
                (RM_PROCESS_INFO*)UtHeapAlloc(sizeof(RM_PROCESS_INFO) * needed);
            if (procs) {
                count = needed;
                err = RmGetList(dwSession, &needed, &count, procs, &dwRebootReasons);
                if (err == ERROR_SUCCESS) {
                    err = RmShutdown(dwSession, RmForceShutdown, NULL);
                    success = (err == ERROR_SUCCESS);
                }
                UtHeapFree(procs);
            }
        }
    } else {
        success = (err == ERROR_SUCCESS || err == ERROR_MORE_DATA);
    }

    RmEndSession(dwSession);
    return success;
}

/*++
 * FlmGetLockingProcessesRM — RM 来源锁 owner 枚举 (对齐 SS L826-853)。
 *   填充 Owners 数组, 返回填充数。
 *--*/
static ULONG
FlmGetLockingProcessesRM(
    _In_ PCWSTR FilePath,
    _Out_ PWKD_LOCK_OWNER Owners,
    _In_ ULONG MaxOwners
    )
{
    DWORD dwSession = 0;
    WCHAR szKey[WKD_FLM_RM_SESSION_KEY_BUFLEN] = { 0 };
    LPCWSTR pszFile = FilePath;
    UINT needed = 0, count = 0;
    DWORD dwRebootReasons = 0;
    DWORD err;
    ULONG filled = 0;
    RM_PROCESS_INFO* procs = NULL;
    ULONG i;

    if (!FilePath || !Owners || MaxOwners == 0) return 0;

    if (RmStartSession(&dwSession, 0, szKey) != ERROR_SUCCESS) return 0;
    err = RmRegisterResources(dwSession, 1, &pszFile, 0, NULL, 0, NULL);
    if (err != ERROR_SUCCESS) { RmEndSession(dwSession); return 0; }

    err = RmGetList(dwSession, &needed, &count, NULL, &dwRebootReasons);
    if ((err == ERROR_MORE_DATA || err == ERROR_SUCCESS) && needed > 0 &&
        needed <= WKD_FLM_MAX_OWNERS) {
        procs = (RM_PROCESS_INFO*)UtHeapAlloc(sizeof(RM_PROCESS_INFO) * needed);
        if (procs) {
            count = needed;
            err = RmGetList(dwSession, &needed, &count, procs, &dwRebootReasons);
            if (err == ERROR_SUCCESS) {
                for (i = 0; i < count && filled < MaxOwners; i++) {
                    PWKD_LOCK_OWNER o = &Owners[filled];
                    RtlZeroMemory(o, sizeof(WKD_LOCK_OWNER));
                    o->Pid = procs[i].Process.dwProcessId;
                    wcsncpy_s(o->ProcessName, WKD_FLM_MAX_PROC_NAME,
                              procs[i].strAppName, _TRUNCATE);
                    FlmEnrichProcessInfo(o);
                    filled++;
                }
            }
            UtHeapFree(procs);
        }
    }

    RmEndSession(dwSession);
    return filled;
}

/*++
 * FlmGetLockingProcessesHandleEnum — 句柄枚举来源锁 owner (对齐 SS L854-922)。
 *   SystemExtendedHandleInformation 全表枚举 + 文件 ID (卷序+nFileIndex) 匹配,
 *   ObjectTypeIndex 预过滤 + DuplicateHandle 复核 + foundPids 去重。
 *--*/
static ULONG
FlmGetLockingProcessesHandleEnum(
    _In_ PCWSTR FilePath,
    _Out_ PWKD_LOCK_OWNER Owners,
    _In_ ULONG MaxOwners
    )
{
    HANDLE hTarget;
    BY_HANDLE_FILE_INFORMATION targetInfo;
    BOOLEAN haveTargetInfo = FALSE;
    ULONG bufSize;
    PBYTE buf = NULL;
    NTSTATUS st;
    ULONG filled = 0;
    DWORD myPid = GetCurrentProcessId();
    typedef struct { ULONG Pid; HANDLE Handle; } PROC_CACHE;
    PROC_CACHE cache[64];
    ULONG cacheCount = 0;
    ULONG foundPids[WKD_FLM_MAX_OWNERS];
    ULONG foundCount = 0;
    ULONG_PTR idx;
    ULONG i;

    if (!FilePath || !Owners || MaxOwners == 0) return 0;
    if (!g_Flm.NtQuerySystemInfo) return 0;

    /* 目标文件 ID (对齐 SS L858-863) */
    hTarget = CreateFileW(FilePath, 0,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
                          NULL);
    if (hTarget != INVALID_HANDLE_VALUE) {
        haveTargetInfo = (GetFileInformationByHandle(hTarget, &targetInfo) != 0);
        CloseHandle(hTarget);
    }
    if (!haveTargetInfo) return 0;

    bufSize = (ULONG)WKD_FLM_HANDLE_ENUM_INIT_MB << 20;
    buf = (PBYTE)UtHeapAlloc(bufSize);
    if (!buf) return 0;

    st = g_Flm.NtQuerySystemInfo(WKD_FLM_SYSTEM_EXT_HANDLE_INFO, buf, bufSize, NULL);
    for (i = 0; st == WKD_FLM_NT_STATUS_INFO_LEN_MISMATCH && i < 5 &&
            bufSize < WKD_FLM_MAX_HANDLE_BUFFER_BYTES; i++) {
        bufSize *= 2;
        UtHeapFree(buf);
        buf = (PBYTE)UtHeapAlloc(bufSize);
        if (!buf) return 0;
        st = g_Flm.NtQuerySystemInfo(WKD_FLM_SYSTEM_EXT_HANDLE_INFO, buf, bufSize, NULL);
    }
    if (st < 0) {
        UtHeapFree(buf);
        return 0;
    }

    {
        WKD_FLM_SYSTEM_HANDLE_INFO_EX* sysInfo = (WKD_FLM_SYSTEM_HANDLE_INFO_EX*)buf;
        for (idx = 0; idx < sysInfo->NumberOfHandles && filled < MaxOwners; idx++) {
            const WKD_FLM_SYSTEM_HANDLE_ENTRY_EX* e = &sysInfo->Handles[idx];
            ULONG handlePid;
            ULONG j;
            BOOLEAN pidKnown = FALSE;
            HANDLE hProc = NULL;
            HANDLE hDup = NULL;
            BY_HANDLE_FILE_INFORMATION dupInfo;

            /* ObjectTypeIndex 过滤 */
            if (g_Flm.FileTypeIndex != 0 && e->ObjectTypeIndex != g_Flm.FileTypeIndex) continue;

            handlePid = (DWORD)e->UniqueProcessId;
            if (handlePid == myPid || handlePid == WKD_FLM_IDLE_PID || handlePid == WKD_FLM_SYSTEM_PID) continue;

            /* foundPids 去重: 已发现的 PID 仅保留写/删权限句柄 (对齐 SS L884) */
            for (j = 0; j < foundCount; j++) {
                if (foundPids[j] == handlePid) { pidKnown = TRUE; break; }
            }
            if (pidKnown && !(e->GrantedAccess & (FILE_WRITE_DATA | DELETE))) continue;

            /* OpenProcess 缓存查找 (仿 SS unordered_map processCache L876-892) */
            for (j = 0; j < cacheCount; j++) {
                if (cache[j].Pid == handlePid) { hProc = cache[j].Handle; break; }
            }
            if (!hProc && cacheCount < 64) {
                hProc = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, handlePid);
                cache[cacheCount].Pid = handlePid;
                cache[cacheCount].Handle = hProc;
                cacheCount++;
            }
            if (!hProc) continue;

            /* DuplicateHandle + 文件类型 + 文件 ID 匹配 (对齐 SS L894-905) */
            if (!DuplicateHandle(hProc, (HANDLE)e->HandleValue, GetCurrentProcess(),
                                 &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) continue;
            if (GetFileType(hDup) != FILE_TYPE_DISK) { CloseHandle(hDup); continue; }
            if (!GetFileInformationByHandle(hDup, &dupInfo)) { CloseHandle(hDup); continue; }
            if (dupInfo.dwVolumeSerialNumber != targetInfo.dwVolumeSerialNumber ||
                dupInfo.nFileIndexHigh != targetInfo.nFileIndexHigh ||
                dupInfo.nFileIndexLow != targetInfo.nFileIndexLow) {
                CloseHandle(hDup);
                continue;
            }
            CloseHandle(hDup);

            /* 匹配: 填充 owner */
            {
                PWKD_LOCK_OWNER o = &Owners[filled];
                RtlZeroMemory(o, sizeof(WKD_LOCK_OWNER));
                o->Pid = handlePid;
                o->HandleValue = (ULONG64)e->HandleValue;
                o->AccessMask = e->GrantedAccess;
                o->LockType = FlmClassifyLockType(e->GrantedAccess);
                FlmEnrichProcessInfo(o);
                filled++;
                if (foundCount < WKD_FLM_MAX_OWNERS) {
                    foundPids[foundCount] = handlePid;
                    foundCount++;
                }
            }
        }
    }

    /* 清理 OpenProcess 缓存 */
    for (i = 0; i < cacheCount; i++) {
        if (cache[i].Handle) CloseHandle(cache[i].Handle);
    }

    UtHeapFree(buf);
    InterlockedIncrement64(&g_Flm.Stats.HandleEnumerations);
    return filled;
}

/*++
 * FlmCollectLockingProcesses — RM + 句柄枚举双路合并去重 (对齐 SS L259-290)。
 *   供 GetLockingProcesses/GetLockInfo/UnlockFile 系列复用。
 *   RM 优先, 句柄枚举补充 handleValue/accessMask/lockType。无锁。
 *--*/
static ULONG
FlmCollectLockingProcesses(
    _In_ PCWSTR NormPath,
    _Out_ PWKD_LOCK_OWNER Owners,
    _In_ ULONG MaxOwners
    )
{
    ULONG count = 0;
    ULONG rmCount;
    ULONG heCount;
    ULONG i;

    if (!NormPath || !Owners || MaxOwners == 0) return 0;

    rmCount = FlmGetLockingProcessesRM(NormPath, Owners, MaxOwners);
    count = rmCount;

    heCount = FlmGetLockingProcessesHandleEnum(NormPath, &Owners[count], MaxOwners - count);
    for (i = 0; i < heCount; i++) {
        ULONG j;
        BOOLEAN known = FALSE;
        PWKD_LOCK_OWNER ho = &Owners[count + i];
        for (j = 0; j < count; j++) {
            if (Owners[j].Pid == ho->Pid) {
                known = TRUE;
                if (Owners[j].HandleValue == 0) {
                    Owners[j].HandleValue = ho->HandleValue;
                    Owners[j].AccessMask = ho->AccessMask;
                    Owners[j].LockType = ho->LockType;
                }
                break;
            }
        }
        if (!known) { Owners[count] = *ho; count++; }
    }
    return count;
}

/*++
 * FlmGetLockingProcessesInternal — 双路合并 + 动态数组输出 (无锁)。
 *--*/
static NTSTATUS
FlmGetLockingProcessesInternal(
    _In_ PCWSTR FilePath,
    _Out_ PWKD_LOCK_OWNER* Owners,
    _Out_ PULONG Count
    )
{
    WCHAR norm[WKD_FLM_MAX_PATH];
    WKD_LOCK_OWNER all[WKD_FLM_MAX_OWNERS];
    ULONG count;
    PWKD_LOCK_OWNER out;

    if (!FilePath || !Owners || !Count) return STATUS_INVALID_PARAMETER;

    *Owners = NULL;
    *Count = 0;

    if (!FlmNormalizePath(FilePath, norm, WKD_FLM_MAX_PATH)) {
        wcsncpy_s(norm, WKD_FLM_MAX_PATH, FilePath, _TRUNCATE);
    }

    count = FlmCollectLockingProcesses(norm, all, WKD_FLM_MAX_OWNERS);
    if (count == 0) return STATUS_SUCCESS;

    out = (PWKD_LOCK_OWNER)UtHeapAlloc(sizeof(WKD_LOCK_OWNER) * count);
    if (!out) return STATUS_NO_MEMORY;
    RtlCopyMemory(out, all, sizeof(WKD_LOCK_OWNER) * count);

    *Owners = out;
    *Count = count;
    return STATUS_SUCCESS;
}

/*++
 * FlmDetectLockPatternInternal — 锁行为模式判定 (对齐 SS L1031-1052)。
 *   勒索/注入/规避/外渗/持久化 → 对应模式; 否则 Normal。
 *--*/
static WKD_LOCK_PATTERN
FlmDetectLockPatternInternal(
    _In_ const WKD_FILE_LOCK_INFO* Info
    )
{
    static const PCWSTR docExts[] = {
        L".doc", L".docx", L".xls", L".xlsx", L".pdf", L".pptx",
        L".txt", L".csv", L".db", L".sqlite"
    };
    ULONG i;
    PCWSTR dot;
    WCHAR ext[16];
    ULONG k;
    ULONG extCount = sizeof(docExts) / sizeof(docExts[0]);

    if (!Info) return WkdLockPattern_Normal;

    for (i = 0; i < Info->LockCount; i++) {
        const WKD_LOCK_OWNER* o = &Info->Owners[i];

        if (!o->IsSigned && o->IsSuspicious && o->LockType == WkdLock_Exclusive) {
            PCWSTR name = Info->FilePath;
            PCWSTR slash = wcsrchr(Info->FilePath, L'\\');
            if (slash) name = slash + 1;
            dot = wcsrchr(name, L'.');       /* 取文件名段扩展名 (对齐 SS fs::path::extension) */
            if (dot) {
                BOOLEAN isDoc = FALSE;
                wcsncpy_s(ext, 16, dot, _TRUNCATE);
                _wcslwr_s(ext, 16);
                for (k = 0; k < extCount; k++) {
                    if (wcscmp(ext, docExts[k]) == 0) { isDoc = TRUE; break; }
                }
                if (isDoc) return WkdLockPattern_Ransomware;
            }
        }
        if (o->IsInjectedProcess && o->IsSigned && o->LockType != WkdLock_Unknown) {
            return WkdLockPattern_ProcessInjection;
        }
        if (o->IsInjectedProcess && !o->IsSigned) {
            return WkdLockPattern_DefenseEvasion;
        }
    }

    for (i = 0; i < Info->LockCount; i++) {
        const WKD_LOCK_OWNER* o = &Info->Owners[i];
        if (o->IsSuspicious && (o->AccessMask & FILE_READ_DATA) && Info->FileSize > (1 << 20)) {
            return WkdLockPattern_DataExfiltration;
        }
        if (o->IsSuspicious && (o->AccessMask & FILE_WRITE_ATTRIBUTES)) {
            WCHAR lowerPath[WKD_FLM_MAX_PATH];
            wcsncpy_s(lowerPath, WKD_FLM_MAX_PATH, Info->FilePath, _TRUNCATE);
            _wcslwr_s(lowerPath, WKD_FLM_MAX_PATH);
            if (wcsstr(lowerPath, L"\\system32\\") != NULL ||
                wcsstr(lowerPath, L"\\startup") != NULL) {
                return WkdLockPattern_Persistence;
            }
        }
    }

    return WkdLockPattern_Normal;
}

/*++
 * FlmAnalyzeThreatInternal — 锁上下文 APT 威胁评估 (对齐 SS L998-1029)。
 *   评分: 未签名+15/注入+40/系统独占+30/多锁>3 每+5/模式加成。
 *   阈值: suspicious≥30 / action≥70。
 *--*/
static VOID
FlmAnalyzeThreatInternal(
    _In_ const WKD_FILE_LOCK_INFO* Info,
    _Out_ PWKD_THREAT_ASSESSMENT Threat
    )
{
    DOUBLE score = 0.0;
    ULONG i;
    WKD_LOCK_PATTERN pattern;

    if (!Info || !Threat) return;
    RtlZeroMemory(Threat, sizeof(WKD_THREAT_ASSESSMENT));

    for (i = 0; i < Info->LockCount; i++) {
        const WKD_LOCK_OWNER* o = &Info->Owners[i];
        if (o->IsSuspicious) Threat->UntrustedLockCount++;
        if (o->IsUntrustedSigner) { Threat->UnsignedProcessCount++; score += 15.0; }
        if (o->IsInjectedProcess) { Threat->InjectedProcessCount++; score += 40.0; }
        if (o->IsRemoteProcess) Threat->RemoteLockCount++;
        if (o->IsSystemProcess && o->LockType == WkdLock_Exclusive) score += 30.0;
    }
    if (Info->LockCount > 3) score += (DOUBLE)Info->LockCount * 5.0;

    pattern = FlmDetectLockPatternInternal(Info);
    Threat->DominantPattern = pattern;
    switch (pattern) {
    case WkdLockPattern_Ransomware:
        score += 80.0;
        strncpy_s(Threat->Indicators[Threat->IndicatorCount], WKD_FLM_MAX_INDICATOR_LEN,
                  "Ransomware lock pattern", _TRUNCATE);
        Threat->IndicatorCount++;
        break;
    case WkdLockPattern_ProcessInjection:
        score += 60.0;
        strncpy_s(Threat->Indicators[Threat->IndicatorCount], WKD_FLM_MAX_INDICATOR_LEN,
                  "Process injection pattern", _TRUNCATE);
        Threat->IndicatorCount++;
        break;
    case WkdLockPattern_DefenseEvasion:
        score += 50.0;
        strncpy_s(Threat->Indicators[Threat->IndicatorCount], WKD_FLM_MAX_INDICATOR_LEN,
                  "Defense evasion", _TRUNCATE);
        Threat->IndicatorCount++;
        break;
    case WkdLockPattern_DataExfiltration:
        score += 45.0;
        strncpy_s(Threat->Indicators[Threat->IndicatorCount], WKD_FLM_MAX_INDICATOR_LEN,
                  "Data exfiltration", _TRUNCATE);
        Threat->IndicatorCount++;
        break;
    case WkdLockPattern_Persistence:
        score += 40.0;
        strncpy_s(Threat->Indicators[Threat->IndicatorCount], WKD_FLM_MAX_INDICATOR_LEN,
                  "Persistence mechanism", _TRUNCATE);
        Threat->IndicatorCount++;
        break;
    default:
        break;
    }

    Threat->OverallThreatScore = (score > 100.0) ? 100.0 : (score < 0.0 ? 0.0 : score);
    Threat->IsSuspiciousActivity = Threat->OverallThreatScore >= 30.0;
    Threat->RequiresImmediateAction = Threat->OverallThreatScore >= 70.0;
    if (Threat->RequiresImmediateAction) {
        wcsncpy_s(Threat->RecommendedAction, WKD_FLM_MAX_ACTION_LEN,
                  L"Immediate quarantine and process termination recommended", _TRUNCATE);
    }
}

/* 解锁链辅助 (对齐 SS L1058-1093 Try 系列) */

static VOID
FlmAddError(
    _Inout_ PWKD_UNLOCK_OPERATION Op,
    _In_ PCSTR Text
    )
{
    if (!Op || Op->ErrorCount >= WKD_FLM_MAX_ERRORS) return;
    strncpy_s(Op->Errors[Op->ErrorCount], 256, Text, _TRUNCATE);
    Op->ErrorCount++;
}

/* FlmReportProgress — 解锁进度回调 (对齐 SS ReportProgress L1099-1103)。
 * 死代码: 默认无回调注册 (ALPC 覆盖), no-op; 保留 SS 功能面 (ProgressCb 注册后生效)。 */
static VOID
FlmReportProgress(
    _In_ PCWSTR Status,
    _In_ ULONG Percent
    )
{
    WKD_FLM_PROGRESS_CALLBACK cb;
    EnterCriticalSection(&g_Flm.CallbackLock);
    cb = g_Flm.ProgressCb;
    LeaveCriticalSection(&g_Flm.CallbackLock);
    if (cb) cb(Status, Percent);
}

static BOOLEAN
FlmTryRestartManager(
    _In_ PCWSTR FilePath,
    _Inout_ PWKD_UNLOCK_OPERATION Op
    )
{
    if (FlmRmViaSession(FilePath, TRUE)) return TRUE;
    FlmAddError(Op, "RestartManager failed");
    return FALSE;
}

static BOOLEAN
FlmTryHandleClose(
    _In_ const WKD_LOCK_OWNER* Owners,
    _In_ ULONG Count,
    _Inout_ PWKD_UNLOCK_OPERATION Op
    )
{
    ULONG i;
    BOOLEAN any = FALSE;

    for (i = 0; i < Count; i++) {
        const WKD_LOCK_OWNER* o = &Owners[i];
        if (o->IsCriticalProcess && g_Flm.Config.ProtectCriticalProcesses) continue;
        if (o->HandleValue != 0 && FileLockManager_CloseHandle(o)) {
            any = TRUE;
            Op->HandlesClosed++;
        }
    }
    if (!any) FlmAddError(Op, "Handle close: no handles closed");
    return any;
}

static BOOLEAN
FlmTryProcessTerminate(
    _In_ const WKD_LOCK_OWNER* Owners,
    _In_ ULONG Count,
    _Inout_ PWKD_UNLOCK_OPERATION Op
    )
{
    ULONG i;
    BOOLEAN any = FALSE;

    for (i = 0; i < Count; i++) {
        const WKD_LOCK_OWNER* o = &Owners[i];
        if (o->IsCriticalProcess && g_Flm.Config.ProtectCriticalProcesses) continue;
        if (o->IsSystemProcess && g_Flm.Config.ProtectSystemProcesses) continue;
        if (FileLockManager_TerminateProcess(o, FALSE)) {
            any = TRUE;
            Op->ProcessesTerminated++;
        }
    }
    if (!any) FlmAddError(Op, "Process termination: none terminated");
    return any;
}

static BOOLEAN
FlmTryKernelUnlock(
    _In_ PCWSTR FilePath,
    _Inout_ PWKD_UNLOCK_OPERATION Op
    )
{
    if (FileLockManager_KernelUnlockFile(FilePath)) return TRUE;
    FlmAddError(Op, "Kernel unlock failed");
    return FALSE;
}

static ULONG64
FlmQueryPerfUs(
    VOID
    )
{
    static LARGE_INTEGER freq = { 0 };
    LARGE_INTEGER now;
    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
        if (freq.QuadPart == 0) return 0;
    }
    QueryPerformanceCounter(&now);
    return (ULONG64)(now.QuadPart * 1000000 / freq.QuadPart);
}

static VOID
FlmFinalizeResult(
    _Inout_ PWKD_UNLOCK_OPERATION Op,
    _In_ ULONG64 StartUs
    )
{
    ULONG64 now = FlmQueryPerfUs();
    if (Op && now >= StartUs) Op->DurationMs = (ULONG)((now - StartUs) / 1000);
}

/**************************************************/
/*            内核集成 (死代码, 对齐 SS L648-759)    */
/**************************************************/

/*++
 * FlmCheckKernelDriver — 探测 wkd 驱动 FLT 端口可用性 (对齐 SS CheckKernelDriver
 *   L749-759)。动态加载 fltlib.dll 试连 YaraScanPort, 连上即关闭。
 *--*/
static BOOLEAN
FlmCheckKernelDriver(
    VOID
    )
{
    HMODULE hFltLib;
    WKD_FLM_FILTER_CONNECT_COMM pConnect;
    HANDLE hPort = INVALID_HANDLE_VALUE;
    HRESULT hr;

    hFltLib = LoadLibraryW(L"fltlib.dll");
    if (!hFltLib) return FALSE;
    pConnect = (WKD_FLM_FILTER_CONNECT_COMM)GetProcAddress(hFltLib, "FilterConnectCommunicationPort");
    if (!pConnect) { FreeLibrary(hFltLib); return FALSE; }

    hr = pConnect(L"\\WkDefenderYaraPort", 0, NULL, 0, NULL, &hPort);
    if (SUCCEEDED(hr) && hPort != INVALID_HANDLE_VALUE && hPort != NULL) {
        CloseHandle(hPort);
        FreeLibrary(hFltLib);
        return TRUE;
    }

    FreeLibrary(hFltLib);
    return FALSE;
}

/*++
 * FlmConnectKernelDriverInternalLocked — 连接 wkd 驱动 FLT 端口 (死代码)。
 *   对齐 SS ConnectToKernelDriverInternalLocked L694-709。
 *   ※SS 驱动端无对应命令, wkd 驱动 FspMessageNotify 空壳为预留扩展点。
 *--*/
static BOOLEAN
FlmConnectKernelDriverInternalLocked(
    VOID
    )
{
    HMODULE hFltLib;
    WKD_FLM_FILTER_CONNECT_COMM pConnect;
    ULONG i;

    if (g_Flm.KernelPortConnected && g_Flm.KernelPort != INVALID_HANDLE_VALUE && g_Flm.KernelPort != NULL) {
        return TRUE;
    }

    hFltLib = LoadLibraryW(L"fltlib.dll");
    if (!hFltLib) return FALSE;
    pConnect = (WKD_FLM_FILTER_CONNECT_COMM)GetProcAddress(hFltLib, "FilterConnectCommunicationPort");
    if (!pConnect) { FreeLibrary(hFltLib); return FALSE; }

    for (i = 0; i < WKD_FLM_KERNEL_RETRY; i++) {
        HANDLE newPort = INVALID_HANDLE_VALUE;
        HRESULT hr = pConnect(L"\\WkDefenderYaraPort", 0, NULL, 0, NULL, &newPort);
        if (SUCCEEDED(hr) && newPort != INVALID_HANDLE_VALUE && newPort != NULL) {
            g_Flm.KernelPort = newPort;
            g_Flm.KernelPortConnected = TRUE;
            FreeLibrary(hFltLib);
            return TRUE;
        }
        if (i + 1 < WKD_FLM_KERNEL_RETRY) {
            Sleep(WKD_FLM_KERNEL_RETRY_DELAY_MS);
        }
    }

    FreeLibrary(hFltLib);
    return FALSE;
}

/*++
 * FileLockManager_KernelUnlockFile — 驱动强制关句柄请求 (死代码)。
 *   对齐 SS KernelUnlockFileOp L648-684。协议结构/端口名对齐 SS,
 *   targetPid=0/handleValue=0 表示关闭该文件全部句柄。
 *   ※SS 驱动端未实现; wkd 未接线; 实际兜底 FileLockManager_CloseHandle。
 *--*/
BOOLEAN
FileLockManager_KernelUnlockFile(
    _In_ PCWSTR FilePath
    )
{
    WKD_FLM_KERNEL_FORCE_CLOSE_REQ req;
    WKD_FLM_KERNEL_FORCE_CLOSE_RESP resp;
    HMODULE hFltLib;
    WKD_FLM_FILTER_SEND_MESSAGE pSend;
    DWORD bytesRet = 0;
    HRESULT hr;
    size_t pathLen;

    if (!g_Flm.Initialized || !FilePath) return FALSE;

    EnterCriticalSection(&g_Flm.KernelLock);
    if (!g_Flm.KernelPortConnected) {
        if (!FlmConnectKernelDriverInternalLocked()) {
            LeaveCriticalSection(&g_Flm.KernelLock);
            return FALSE;
        }
    }
    LeaveCriticalSection(&g_Flm.KernelLock);

    RtlZeroMemory(&req, sizeof(req));
    RtlZeroMemory(&resp, sizeof(resp));

    /* 路径长度校验: 超协议上限拒绝 (对齐 SS L658-664) */
    pathLen = wcslen(FilePath);
    if (pathLen >= _countof(req.FilePath)) return FALSE;

    req.Header.Command = WkdFlmKernelCmd_ForceCloseHandle;
    req.Header.DataLength = (ULONG)(sizeof(req) - sizeof(req.Header));
    req.TargetProcessId = 0;
    req.HandleValue = 0;
    wcsncpy_s(req.FilePath, _countof(req.FilePath), FilePath, _TRUNCATE);

    hFltLib = LoadLibraryW(L"fltlib.dll");
    if (!hFltLib) return FALSE;
    pSend = (WKD_FLM_FILTER_SEND_MESSAGE)GetProcAddress(hFltLib, "FilterSendMessage");
    if (!pSend) { FreeLibrary(hFltLib); return FALSE; }

    EnterCriticalSection(&g_Flm.KernelLock);
    hr = pSend(g_Flm.KernelPort, &req, (DWORD)sizeof(req),
               &resp, (DWORD)sizeof(resp), &bytesRet);
    LeaveCriticalSection(&g_Flm.KernelLock);

    FreeLibrary(hFltLib);

    if (SUCCEEDED(hr) && bytesRet >= sizeof(resp) && resp.Header.Status == 0) {
        InterlockedIncrement64(&g_Flm.Stats.KernelUnlocks);
        return resp.HandlesAffected > 0;
    }
    return FALSE;
}

BOOLEAN
FileLockManager_IsKernelDriverAvailable(
    VOID
    )
{
    return g_Flm.KernelDriverAvailable;
}

BOOLEAN
FileLockManager_ConnectKernelDriver(
    VOID
    )
{
    EnterCriticalSection(&g_Flm.KernelLock);
    {
        BOOLEAN ok = FlmConnectKernelDriverInternalLocked();
        LeaveCriticalSection(&g_Flm.KernelLock);
        return ok;
    }
}

VOID
FileLockManager_DisconnectKernelDriver(
    VOID
    )
{
    EnterCriticalSection(&g_Flm.KernelLock);
    if (g_Flm.KernelPort != INVALID_HANDLE_VALUE && g_Flm.KernelPort != NULL) {
        CloseHandle(g_Flm.KernelPort);
    }
    g_Flm.KernelPort = INVALID_HANDLE_VALUE;
    g_Flm.KernelPortConnected = FALSE;
    LeaveCriticalSection(&g_Flm.KernelLock);
}

/**************************************************/
/*               生命周期 / 配置工厂                */
/**************************************************/

VOID
FileLockManager_ConfigDefault(
    _Out_ PWKD_FILE_LOCK_CONFIG Config
    )
{
    if (!Config) return;
    RtlZeroMemory(Config, sizeof(WKD_FILE_LOCK_CONFIG));
    Config->AllowRestartManager = TRUE;
    Config->AllowProcessTermination = FALSE;
    Config->AllowKernelUnlock = TRUE;
    Config->ProtectCriticalProcesses = TRUE;
    Config->ProtectSystemProcesses = TRUE;
    Config->ProtectServices = TRUE;
    Config->RetryCount = 3;
    Config->RetryDelayMs = 500;
    Config->UnlockTimeoutMs = 30000;
}

VOID
FileLockManager_ConfigAggressive(
    _Out_ PWKD_FILE_LOCK_CONFIG Config
    )
{
    if (!Config) return;
    RtlZeroMemory(Config, sizeof(WKD_FILE_LOCK_CONFIG));
    Config->AllowRestartManager = TRUE;
    Config->AllowProcessTermination = TRUE;
    Config->AllowKernelUnlock = TRUE;
    Config->ProtectCriticalProcesses = TRUE;
    Config->ProtectSystemProcesses = FALSE;
    Config->ProtectServices = FALSE;
    Config->RetryCount = 5;
    Config->RetryDelayMs = 500;
    Config->UnlockTimeoutMs = 60000;
}

VOID
FileLockManager_ConfigSafe(
    _Out_ PWKD_FILE_LOCK_CONFIG Config
    )
{
    if (!Config) return;
    RtlZeroMemory(Config, sizeof(WKD_FILE_LOCK_CONFIG));
    Config->AllowRestartManager = TRUE;
    Config->AllowProcessTermination = FALSE;
    Config->AllowKernelUnlock = FALSE;
    Config->ProtectCriticalProcesses = TRUE;
    Config->ProtectSystemProcesses = TRUE;
    Config->ProtectServices = TRUE;
    Config->RetryCount = 2;
    Config->RetryDelayMs = 500;
    Config->UnlockTimeoutMs = 15000;
}

_Check_return_
NTSTATUS
FileLockManager_Initialize(
    _In_opt_ PWKD_FILE_LOCK_CONFIG Config
    )
{
    HMODULE hNtdll;

    RtlZeroMemory(&g_Flm, sizeof(g_Flm));
    g_Flm.KernelPort = INVALID_HANDLE_VALUE;
    InitializeCriticalSection(&g_Flm.Lock);
    InitializeCriticalSection(&g_Flm.PendingLock);
    InitializeCriticalSection(&g_Flm.KernelLock);
    InitializeCriticalSection(&g_Flm.CallbackLock);

    if (Config) {
        g_Flm.Config = *Config;
    } else {
        FileLockManager_ConfigDefault(&g_Flm.Config);
    }

    g_Flm.HasDebugPrivilege = FlmEnableDebugPrivilege();

    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        g_Flm.NtQuerySystemInfo =
            (WKD_FLM_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        /* 死代码: 对齐 SS L232-233, 解析未使用 */
        g_Flm.NtQueryObject =
            (WKD_FLM_NT_QUERY_OBJECT_INFORMATION)GetProcAddress(hNtdll, "NtQueryObject");
    }

    g_Flm.FileTypeIndex = FlmResolveObjectTypeIndex();
    g_Flm.KernelDriverAvailable = FlmCheckKernelDriver();

    /* 死代码: 端口无对应驱动命令, 仅探测不常驻连接 */
    if (g_Flm.KernelDriverAvailable && g_Flm.Config.AllowKernelUnlock) {
        FileLockManager_ConnectKernelDriver();
    }

    g_Flm.Initialized = TRUE;
    return STATUS_SUCCESS;
}

VOID
FileLockManager_Shutdown(
    VOID
    )
{
    EnterCriticalSection(&g_Flm.Lock);
    FileLockManager_DisconnectKernelDriver();
    g_Flm.Initialized = FALSE;
    LeaveCriticalSection(&g_Flm.Lock);

    DeleteCriticalSection(&g_Flm.KernelLock);
    DeleteCriticalSection(&g_Flm.PendingLock);
    DeleteCriticalSection(&g_Flm.CallbackLock);
    DeleteCriticalSection(&g_Flm.Lock);
}

/**************************************************/
/*                   锁检测                        */
/**************************************************/

BOOLEAN
FileLockManager_IsFileLocked(
    _In_ PCWSTR FilePath,
    _Out_opt_ PBOOLEAN AccessDeniedMisreport
    )
{
    HANDLE hFile;
    DWORD err;

    if (!FilePath || !FilePath[0]) return FALSE;
    if (AccessDeniedMisreport) *AccessDeniedMisreport = FALSE;

    hFile = CreateFileW(FilePath, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
                        NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        return FALSE;
    }

    err = GetLastError();
    if (err == ERROR_ACCESS_DENIED) {
        /* 只读系统文件误报: 不是锁, 是权限 (对齐 SS L335-338) */
        if (AccessDeniedMisreport) *AccessDeniedMisreport = TRUE;
        return FALSE;
    }
    return (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION);
}

WKD_LOCK_TYPE
FileLockManager_GetLockType(
    _In_ PCWSTR FilePath
    )
{
    HANDLE hr;
    HANDLE hw;
    BOOLEAN rOk;
    BOOLEAN wOk;

    if (!FilePath || !FilePath[0]) return WkdLock_Unknown;

    hr = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    hw = CreateFileW(FilePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    rOk = (hr != INVALID_HANDLE_VALUE);
    wOk = (hw != INVALID_HANDLE_VALUE);
    if (hr != INVALID_HANDLE_VALUE) CloseHandle(hr);
    if (hw != INVALID_HANDLE_VALUE) CloseHandle(hw);

    if (!rOk && !wOk) return WkdLock_Exclusive;
    if (!wOk) return WkdLock_Write;
    if (!rOk) return WkdLock_Read;
    return WkdLock_Unknown;
}

BOOLEAN
FileLockManager_CanDeleteFile(
    _In_ PCWSTR FilePath
    )
{
    HANDLE hFile;

    if (!FilePath || !FilePath[0]) return FALSE;

    hFile = CreateFileW(FilePath, DELETE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    CloseHandle(hFile);
    return TRUE;
}

_Check_return_
NTSTATUS
FileLockManager_GetLockingProcesses(
    _In_ PCWSTR FilePath,
    _Out_ PWKD_LOCK_OWNER* Owners,
    _Out_ PULONG Count
    )
{
    NTSTATUS status;

    if (!Owners || !Count) return STATUS_INVALID_PARAMETER;
    *Owners = NULL;
    *Count = 0;
    if (!g_Flm.Initialized || !FilePath) return STATUS_SUCCESS;

    EnterCriticalSection(&g_Flm.Lock);
    status = FlmGetLockingProcessesInternal(FilePath, Owners, Count);
    LeaveCriticalSection(&g_Flm.Lock);

    return status;
}

VOID
FileLockManager_FreeLockOwners(
    _In_opt_ PWKD_LOCK_OWNER Owners
    )
{
    if (Owners) UtHeapFree(Owners);
}

/* EnumerateHandles — 仅句柄枚举级深层枚举 (对齐 SS EnumerateHandles L1108-1110,
 * 不含 RM 合并, 供取证/调试)。动态分配, 以 FileLockManager_FreeLockOwners 释放。 */
_Check_return_
NTSTATUS
FileLockManager_EnumerateHandles(
    _In_ PCWSTR FilePath,
    _Out_ PWKD_LOCK_OWNER* Owners,
    _Out_ PULONG Count
    )
{
    WCHAR norm[WKD_FLM_MAX_PATH];
    WKD_LOCK_OWNER all[WKD_FLM_MAX_OWNERS];
    ULONG count;
    PWKD_LOCK_OWNER out;

    if (!FilePath || !Owners || !Count) return STATUS_INVALID_PARAMETER;
    *Owners = NULL;
    *Count = 0;
    if (!g_Flm.Initialized) return STATUS_SUCCESS;

    if (!FlmNormalizePath(FilePath, norm, WKD_FLM_MAX_PATH)) {
        wcsncpy_s(norm, WKD_FLM_MAX_PATH, FilePath, _TRUNCATE);
    }

    EnterCriticalSection(&g_Flm.Lock);
    count = FlmGetLockingProcessesHandleEnum(norm, all, WKD_FLM_MAX_OWNERS);
    if (count > 0) {
        out = (PWKD_LOCK_OWNER)UtHeapAlloc(sizeof(WKD_LOCK_OWNER) * count);
        if (out) {
            RtlCopyMemory(out, all, sizeof(WKD_LOCK_OWNER) * count);
            *Owners = out;
            *Count = count;
        }
    }
    LeaveCriticalSection(&g_Flm.Lock);

    return STATUS_SUCCESS;
}

_Check_return_
NTSTATUS
FileLockManager_GetLockInfo(
    _In_ PCWSTR FilePath,
    _Out_ PWKD_FILE_LOCK_INFO Info
    )
{
    ULONG64 startUs;
    WCHAR norm[WKD_FLM_MAX_PATH];
    WKD_LOCK_OWNER all[WKD_FLM_MAX_OWNERS];
    ULONG count;
    ULONG i;
    PWKD_LOCK_OWNER out;
    WIN32_FILE_ATTRIBUTE_DATA fad;

    if (!FilePath || !Info) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Info, sizeof(WKD_FILE_LOCK_INFO));
    startUs = FlmQueryPerfUs();
    wcsncpy_s(Info->FilePath, WKD_FLM_MAX_PATH, FilePath, _TRUNCATE);

    if (!g_Flm.Initialized) { Info->FileExists = FALSE; return STATUS_SUCCESS; }

    if (!GetFileAttributesExW(FilePath, GetFileExInfoStandard, &fad)) {
        Info->FileExists = FALSE;
        return STATUS_SUCCESS;
    }
    Info->FileExists = TRUE;
    Info->IsDirectory = (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (!Info->IsDirectory) {
        ULARGE_INTEGER sz;
        sz.LowPart = fad.nFileSizeLow;
        sz.HighPart = fad.nFileSizeHigh;
        Info->FileSize = sz.QuadPart;
    }

    if (!FlmNormalizePath(FilePath, norm, WKD_FLM_MAX_PATH)) {
        wcsncpy_s(norm, WKD_FLM_MAX_PATH, FilePath, _TRUNCATE);
    }

    EnterCriticalSection(&g_Flm.Lock);

    count = FlmCollectLockingProcesses(norm, all, WKD_FLM_MAX_OWNERS);
    Info->LockCount = count;
    Info->IsLocked = (count > 0);

    if (count > 0) {
        out = (PWKD_LOCK_OWNER)UtHeapAlloc(sizeof(WKD_LOCK_OWNER) * count);
        if (out) {
            RtlCopyMemory(out, all, sizeof(WKD_LOCK_OWNER) * count);
            Info->Owners = out;
            Info->CanForceUnlock = TRUE;
            for (i = 0; i < count; i++) {
                if (out[i].IsSystemProcess) Info->HasSystemLock = TRUE;
                if (out[i].IsCriticalProcess) {
                    Info->HasCriticalLock = TRUE;
                    Info->CanForceUnlock = FALSE;
                }
            }
        } else {
            /* 分配失败: 回退为空锁, 防 FlmAnalyzeThreatInternal 空指针 */
            Info->LockCount = 0;
            Info->IsLocked = FALSE;
        }
    }

    FlmAnalyzeThreatInternal(Info, &Info->ThreatAssessment);

    LeaveCriticalSection(&g_Flm.Lock);

    InterlockedIncrement64(&g_Flm.Stats.LocksDetected);
    if (Info->ThreatAssessment.IsSuspiciousActivity) {
        InterlockedIncrement64(&g_Flm.Stats.ThreatsDetected);
    }

    Info->DetectionDurationUs = FlmQueryPerfUs() - startUs;
    return STATUS_SUCCESS;
}

VOID
FileLockManager_FreeLockInfo(
    _Inout_ PWKD_FILE_LOCK_INFO Info
    )
{
    if (!Info) return;
    if (Info->Owners) {
        UtHeapFree(Info->Owners);
        Info->Owners = NULL;
    }
    Info->LockCount = 0;
}

_Check_return_
NTSTATUS
FileLockManager_GetApplicationsUsingFile(
    _In_ PCWSTR FilePath,
    _Out_ PWKD_LOCK_APP** Apps,
    _Out_ PULONG Count
    )
{
    DWORD dwSession = 0;
    WCHAR szKey[WKD_FLM_RM_SESSION_KEY_BUFLEN] = { 0 };
    LPCWSTR pszFile;
    UINT needed = 0, cnt = 0;
    DWORD dwRebootReasons = 0;
    DWORD err;
    RM_PROCESS_INFO* procs = NULL;
    PWKD_LOCK_APP out = NULL;
    ULONG filled = 0;
    ULONG i;

    if (!FilePath || !Apps || !Count) return STATUS_INVALID_PARAMETER;
    *Apps = NULL;
    *Count = 0;

    if (!g_Flm.Initialized) return STATUS_SUCCESS;

    EnterCriticalSection(&g_Flm.Lock);

    if (RmStartSession(&dwSession, 0, szKey) != ERROR_SUCCESS) {
        LeaveCriticalSection(&g_Flm.Lock);
        return STATUS_SUCCESS;
    }
    pszFile = FilePath;
    err = RmRegisterResources(dwSession, 1, &pszFile, 0, NULL, 0, NULL);
    if (err == ERROR_SUCCESS) {
        err = RmGetList(dwSession, &needed, &cnt, NULL, &dwRebootReasons);
        if (err == ERROR_MORE_DATA && needed > 0 && needed <= WKD_FLM_MAX_APPS) {
            procs = (RM_PROCESS_INFO*)UtHeapAlloc(sizeof(RM_PROCESS_INFO) * needed);
            if (procs) {
                cnt = needed;
                if (RmGetList(dwSession, &needed, &cnt, procs, &dwRebootReasons) == ERROR_SUCCESS) {
                    out = (PWKD_LOCK_APP)UtHeapAlloc(sizeof(WKD_LOCK_APP) * cnt);
                    if (out) {
                        for (i = 0; i < cnt; i++) {
                            wcsncpy_s(out[filled].AppName, WKD_FLM_MAX_APP_NAME,
                                      procs[i].strAppName, _TRUNCATE);
                            out[filled].Pid = procs[i].Process.dwProcessId;
                            filled++;
                        }
                    }
                }
                UtHeapFree(procs);
            }
        }
    }
    RmEndSession(dwSession);

    LeaveCriticalSection(&g_Flm.Lock);

    if (filled > 0 && out) {
        *Apps = out;
        *Count = filled;
    }
    return STATUS_SUCCESS;
}

VOID
FileLockManager_FreeApps(
    _In_opt_ PWKD_LOCK_APP Apps
    )
{
    if (Apps) UtHeapFree(Apps);
}

/**************************************************/
/*                   解锁操作                       */
/**************************************************/

/*++
 * FileLockManager_UnlockFile — 五级升级链 (对齐 SS L365-437)。
 *   RM→HandleClose→KernelUnlock→ProcessTerminate→DeleteOnReboot。
 *   critical 保护前置检查返回 ProcessCritical。
 *--*/
_Check_return_
NTSTATUS
FileLockManager_UnlockFile(
    _In_ PCWSTR FilePath,
    _Out_ PWKD_UNLOCK_OPERATION Op
    )
{
    ULONG64 startUs;
    WKD_LOCK_OWNER owners[WKD_FLM_MAX_OWNERS];
    ULONG count;
    ULONG i;
    WCHAR norm[WKD_FLM_MAX_PATH];
    BOOLEAN accessDeniedMisreport = FALSE;

    if (!FilePath || !Op) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Op, sizeof(WKD_UNLOCK_OPERATION));
    wcsncpy_s(Op->FilePath, WKD_FLM_MAX_PATH, FilePath, _TRUNCATE);
    startUs = FlmQueryPerfUs();

    if (!g_Flm.Initialized || !FilePath[0]) {
        Op->Result = WkdUnlockResult_Failed;
        FlmAddError(Op, "FileLockManager not initialized or empty path");
        FlmFinalizeResult(Op, startUs);
        return STATUS_SUCCESS;
    }

    /* 进度上报 (对齐 SS L375) */
    FlmReportProgress(L"Detecting file locks", 10);

    /* 轻量探测 (对齐 SS L376) */
    if (!FileLockManager_IsFileLocked(FilePath, &accessDeniedMisreport)) {
        Op->Result = WkdUnlockResult_NotLocked;
        FlmFinalizeResult(Op, startUs);
        return STATUS_SUCCESS;
    }

    EnterCriticalSection(&g_Flm.Lock);

    if (!FlmNormalizePath(FilePath, norm, WKD_FLM_MAX_PATH)) {
        wcsncpy_s(norm, WKD_FLM_MAX_PATH, FilePath, _TRUNCATE);
    }

    count = FlmCollectLockingProcesses(norm, owners, WKD_FLM_MAX_OWNERS);

    /* 进度上报 (对齐 SS L384) */
    FlmReportProgress(L"Analyzing lock owners", 30);

    if (count == 0) {
        Op->Result = WkdUnlockResult_Failed;
        FlmAddError(Op, "File locked but owner unidentifiable");
        InterlockedIncrement64(&g_Flm.Stats.FailedUnlocks);
        LeaveCriticalSection(&g_Flm.Lock);
        FlmFinalizeResult(Op, startUs);
        return STATUS_SUCCESS;
    }

    /* 关键进程保护 (对齐 SS L385-392) */
    for (i = 0; i < count; i++) {
        if (owners[i].IsCriticalProcess && g_Flm.Config.ProtectCriticalProcesses) {
            Op->Result = WkdUnlockResult_ProcessCritical;
            FlmAddError(Op, "Locked by critical process");
            LeaveCriticalSection(&g_Flm.Lock);
            FlmFinalizeResult(Op, startUs);
            return STATUS_SUCCESS;
        }
    }

    /* 进度上报 (对齐 SS L393) */
    FlmReportProgress(L"Attempting unlock", 50);

    /* 解锁链: RM → HandleClose → Kernel → Terminate → DeleteOnReboot */
    if (g_Flm.Config.AllowRestartManager && FlmTryRestartManager(FilePath, Op)) {
        Op->Result = WkdUnlockResult_Success;
        Op->Method = WkdUnlock_RestartManager;
        InterlockedIncrement64(&g_Flm.Stats.SuccessfulUnlocks);
        LeaveCriticalSection(&g_Flm.Lock);
        FlmFinalizeResult(Op, startUs);
        return STATUS_SUCCESS;
    }

    if (FlmTryHandleClose(owners, count, Op) &&
        !FileLockManager_IsFileLocked(FilePath, NULL)) {
        Op->Result = WkdUnlockResult_Success;
        Op->Method = WkdUnlock_HandleClose;
        InterlockedIncrement64(&g_Flm.Stats.SuccessfulUnlocks);
        LeaveCriticalSection(&g_Flm.Lock);
        FlmFinalizeResult(Op, startUs);
        return STATUS_SUCCESS;
    }

    if (g_Flm.Config.AllowKernelUnlock && g_Flm.KernelDriverAvailable &&
        FlmTryKernelUnlock(FilePath, Op) &&
        !FileLockManager_IsFileLocked(FilePath, NULL)) {
        Op->Result = WkdUnlockResult_Success;
        Op->Method = WkdUnlock_KernelDriver;
        InterlockedIncrement64(&g_Flm.Stats.SuccessfulUnlocks);
        LeaveCriticalSection(&g_Flm.Lock);
        FlmFinalizeResult(Op, startUs);
        return STATUS_SUCCESS;
    }

    if (g_Flm.Config.AllowProcessTermination && FlmTryProcessTerminate(owners, count, Op)) {
        Sleep(100);
        if (!FileLockManager_IsFileLocked(FilePath, NULL)) {
            Op->Result = WkdUnlockResult_Success;
            Op->Method = WkdUnlock_ProcessTerminate;
            InterlockedIncrement64(&g_Flm.Stats.SuccessfulUnlocks);
            LeaveCriticalSection(&g_Flm.Lock);
            FlmFinalizeResult(Op, startUs);
            return STATUS_SUCCESS;
        }
    }

    /* 进度上报 (对齐 SS L419) */
    FlmReportProgress(L"Scheduling reboot operation", 90);

    /* DeleteOnReboot (对齐 SS L419-425) */
    if (FileLockManager_ScheduleDeleteOnReboot(FilePath)) {
        Op->Result = WkdUnlockResult_RequiresReboot;
        Op->Method = WkdUnlock_DeleteOnReboot;
        Op->RequiresReboot = TRUE;
        wcsncpy_s(Op->PendingOperation, WKD_FLM_MAX_ACTION_LEN,
                  L"Delete on reboot", _TRUNCATE);
        InterlockedIncrement64(&g_Flm.Stats.RebootScheduled);
        LeaveCriticalSection(&g_Flm.Lock);
        FlmFinalizeResult(Op, startUs);
        return STATUS_SUCCESS;
    }

    Op->Result = WkdUnlockResult_Failed;
    FlmAddError(Op, "All unlock methods exhausted");
    InterlockedIncrement64(&g_Flm.Stats.FailedUnlocks);
    LeaveCriticalSection(&g_Flm.Lock);
    FlmFinalizeResult(Op, startUs);
    return STATUS_SUCCESS;
}

_Check_return_
NTSTATUS
FileLockManager_UnlockFileWithMethod(
    _In_ PCWSTR FilePath,
    _In_ WKD_UNLOCK_METHOD Method,
    _Out_ PWKD_UNLOCK_OPERATION Op
    )
{
    ULONG64 startUs;
    WKD_LOCK_OWNER owners[WKD_FLM_MAX_OWNERS];
    ULONG count;
    BOOLEAN ok = FALSE;

    if (!FilePath || !Op) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Op, sizeof(WKD_UNLOCK_OPERATION));
    wcsncpy_s(Op->FilePath, WKD_FLM_MAX_PATH, FilePath, _TRUNCATE);
    Op->Method = Method;
    startUs = FlmQueryPerfUs();

    if (!g_Flm.Initialized || !FilePath[0]) {
        Op->Result = WkdUnlockResult_Failed;
        FlmAddError(Op, "FileLockManager not initialized or empty path");
        FlmFinalizeResult(Op, startUs);
        return STATUS_SUCCESS;
    }

    switch (Method) {
    case WkdUnlock_HandleClose:
    case WkdUnlock_ProcessTerminate:
        EnterCriticalSection(&g_Flm.Lock);
        count = FlmCollectLockingProcesses(FilePath, owners, WKD_FLM_MAX_OWNERS);
        if (Method == WkdUnlock_HandleClose) {
            ok = FlmTryHandleClose(owners, count, Op);
        } else {
            ok = FlmTryProcessTerminate(owners, count, Op);
        }
        LeaveCriticalSection(&g_Flm.Lock);
        Op->Result = ok ? WkdUnlockResult_Success : WkdUnlockResult_Failed;
        break;
    case WkdUnlock_RestartManager:
        ok = FlmTryRestartManager(FilePath, Op);
        Op->Result = ok ? WkdUnlockResult_Success : WkdUnlockResult_Failed;
        break;
    case WkdUnlock_KernelDriver:
        ok = FlmTryKernelUnlock(FilePath, Op);
        Op->Result = ok ? WkdUnlockResult_Success : WkdUnlockResult_Failed;
        break;
    case WkdUnlock_DeleteOnReboot:
        if (FileLockManager_ScheduleDeleteOnReboot(FilePath)) {
            Op->Result = WkdUnlockResult_RequiresReboot;
            Op->RequiresReboot = TRUE;
        } else {
            Op->Result = WkdUnlockResult_Failed;
        }
        break;
    default:
        Op->Result = WkdUnlockResult_Failed;
        FlmAddError(Op, "Invalid unlock method");
        break;
    }

    if (Op->Result == WkdUnlockResult_Success) {
        InterlockedIncrement64(&g_Flm.Stats.SuccessfulUnlocks);
    } else if (Op->Result == WkdUnlockResult_Failed) {
        InterlockedIncrement64(&g_Flm.Stats.FailedUnlocks);
    }

    FlmFinalizeResult(Op, startUs);
    return STATUS_SUCCESS;
}

_Check_return_
NTSTATUS
FileLockManager_ForceUnlockFile(
    _In_ PCWSTR FilePath,
    _Out_ PWKD_UNLOCK_OPERATION Op
    )
{
    ULONG64 startUs;
    WKD_LOCK_OWNER owners[WKD_FLM_MAX_OWNERS];
    ULONG count;
    BOOLEAN unlocked = FALSE;

    if (!FilePath || !Op) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Op, sizeof(WKD_UNLOCK_OPERATION));
    wcsncpy_s(Op->FilePath, WKD_FLM_MAX_PATH, FilePath, _TRUNCATE);
    startUs = FlmQueryPerfUs();

    if (!g_Flm.Initialized || !FilePath[0]) {
        Op->Result = WkdUnlockResult_Failed;
        FlmAddError(Op, "FileLockManager not initialized or empty path");
        FlmFinalizeResult(Op, startUs);
        return STATUS_SUCCESS;
    }

    EnterCriticalSection(&g_Flm.Lock);

    count = FlmCollectLockingProcesses(FilePath, owners, WKD_FLM_MAX_OWNERS);

    if (FlmTryHandleClose(owners, count, Op) &&
        !FileLockManager_IsFileLocked(FilePath, NULL)) {
        unlocked = TRUE;
    }
    if (!unlocked && g_Flm.Config.AllowProcessTermination &&
        FlmTryProcessTerminate(owners, count, Op)) {
        Sleep(100);
        if (!FileLockManager_IsFileLocked(FilePath, NULL)) unlocked = TRUE;
    }
    if (!unlocked && g_Flm.KernelDriverAvailable &&
        FlmTryKernelUnlock(FilePath, Op) &&
        !FileLockManager_IsFileLocked(FilePath, NULL)) {
        unlocked = TRUE;
    }
    if (!unlocked && FileLockManager_ScheduleDeleteOnReboot(FilePath)) {
        Op->Result = WkdUnlockResult_RequiresReboot;
        Op->RequiresReboot = TRUE;
        InterlockedIncrement64(&g_Flm.Stats.RebootScheduled);
        LeaveCriticalSection(&g_Flm.Lock);
        FlmFinalizeResult(Op, startUs);
        return STATUS_SUCCESS;
    }

    Op->Result = unlocked ? WkdUnlockResult_Success : WkdUnlockResult_Failed;
    if (unlocked) {
        InterlockedIncrement64(&g_Flm.Stats.SuccessfulUnlocks);
    } else {
        InterlockedIncrement64(&g_Flm.Stats.FailedUnlocks);
    }

    LeaveCriticalSection(&g_Flm.Lock);
    FlmFinalizeResult(Op, startUs);
    return STATUS_SUCCESS;
}

/*++
 * FileLockManager_CloseHandle — 复制句柄关闭 (对齐 SS CloseHandleOp L492-528)。
 *   DuplicateHandle+DUPLICATE_CLOSE_SOURCE + PID 复核 + 进程退出复核。
 *--*/
BOOLEAN
FileLockManager_CloseHandle(
    _In_ const PWKD_LOCK_OWNER Owner
    )
{
    HANDLE hProcess;
    DWORD verifiedPid;
    FILETIME createTime, exitTime, kernelTime, userTime;
    HANDLE hDup = NULL;
    BOOLEAN ok;

    if (!Owner || Owner->HandleValue == 0) return FALSE;

    hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Owner->Pid);
    if (!hProcess) return FALSE;

    /* PID 复用纵深防御 (对齐 SS L503-509) */
    verifiedPid = GetProcessId(hProcess);
    if (verifiedPid == 0 || verifiedPid != Owner->Pid) {
        CloseHandle(hProcess);
        return FALSE;
    }

    /* 进程已退出跳过 (对齐 SS L511-517) */
    if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
        if (exitTime.dwLowDateTime != 0 || exitTime.dwHighDateTime != 0) {
            CloseHandle(hProcess);
            return FALSE;
        }
    }

    ok = DuplicateHandle(hProcess, (HANDLE)Owner->HandleValue, GetCurrentProcess(),
                         &hDup, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    if (ok && hDup) {
        CloseHandle(hDup);
        InterlockedIncrement64(&g_Flm.Stats.HandlesClosed);
        CloseHandle(hProcess);
        return TRUE;
    }

    CloseHandle(hProcess);
    return FALSE;
}

/*++
 * FileLockManager_TerminateProcess — 终止持锁进程 (对齐 SS TerminateProcessOp
 *   L530-565)。委托 wkd ProcessManager_KillProcess (8 级升级链 + TOCTOU +
 *   关键进程豁免 + 信任表), SS 裸 TerminateProcess+PID 复核不重复实现。
 *--*/
BOOLEAN
FileLockManager_TerminateProcess(
    _In_ const PWKD_LOCK_OWNER Owner,
    _In_ BOOLEAN Force
    )
{
    NTSTATUS status;

    if (!Owner) return FALSE;

    /* 对齐 SS L532-538: critical/system 保护 + 终止前回调确认 (Force 时跳过) */
    if (!Force) {
        WKD_FLM_TERMINATE_CALLBACK cb;
        if (Owner->IsCriticalProcess && g_Flm.Config.ProtectCriticalProcesses) return FALSE;
        if (Owner->IsSystemProcess && g_Flm.Config.ProtectSystemProcesses) return FALSE;
        EnterCriticalSection(&g_Flm.CallbackLock);
        cb = g_Flm.TerminateCb;
        LeaveCriticalSection(&g_Flm.CallbackLock);
        if (cb && !cb(Owner)) return FALSE;   /* 调用方否决终止 */
    }

    status = ProcessManager_KillProcess(Owner->Pid);
    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_Flm.Stats.ProcessesTerminated);
        return TRUE;
    }
    return FALSE;
}

BOOLEAN
FileLockManager_UseRestartManager(
    _In_ PCWSTR FilePath
    )
{
    return FlmRmViaSession(FilePath, TRUE);
}

/**************************************************/
/*                 重启调度操作                     */
/**************************************************/

BOOLEAN
FileLockManager_ScheduleDeleteOnReboot(
    _In_ PCWSTR FilePath
    )
{
    WKD_PENDING_OPERATION op;

    if (!FilePath || !FilePath[0]) return FALSE;

    if (!MoveFileExW(FilePath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)) return FALSE;

    RtlZeroMemory(&op, sizeof(op));
    wcsncpy_s(op.SourcePath, WKD_FLM_MAX_PATH, FilePath, _TRUNCATE);
    op.IsDelete = TRUE;
    GetSystemTimeAsFileTime((PFILETIME)&op.ScheduledTime);
    strncpy_s(op.Reason, sizeof(op.Reason), "File locked - scheduled for deletion", _TRUNCATE);

    EnterCriticalSection(&g_Flm.PendingLock);
    if (g_Flm.PendingCount < WKD_FLM_MAX_PENDING) {
        g_Flm.PendingOps[g_Flm.PendingCount] = op;
        g_Flm.PendingCount++;
    }
    LeaveCriticalSection(&g_Flm.PendingLock);

    return TRUE;
}

BOOLEAN
FileLockManager_ScheduleMoveOnReboot(
    _In_ PCWSTR SourcePath,
    _In_ PCWSTR DestinationPath
    )
{
    WKD_PENDING_OPERATION op;

    if (!SourcePath || !DestinationPath || !SourcePath[0] || !DestinationPath[0]) return FALSE;

    if (!MoveFileExW(SourcePath, DestinationPath, MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING)) {
        return FALSE;
    }

    RtlZeroMemory(&op, sizeof(op));
    wcsncpy_s(op.SourcePath, WKD_FLM_MAX_PATH, SourcePath, _TRUNCATE);
    wcsncpy_s(op.DestinationPath, WKD_FLM_MAX_PATH, DestinationPath, _TRUNCATE);
    op.IsMove = TRUE;
    GetSystemTimeAsFileTime((PFILETIME)&op.ScheduledTime);
    strncpy_s(op.Reason, sizeof(op.Reason), "File locked - scheduled for move", _TRUNCATE);

    EnterCriticalSection(&g_Flm.PendingLock);
    if (g_Flm.PendingCount < WKD_FLM_MAX_PENDING) {
        g_Flm.PendingOps[g_Flm.PendingCount] = op;
        g_Flm.PendingCount++;
    }
    LeaveCriticalSection(&g_Flm.PendingLock);

    return TRUE;
}

/* 接口活代码, 当前无 UI/驱动消费方 (死代码标注) */
ULONG
FileLockManager_GetPendingOperations(
    _Out_ PWKD_PENDING_OPERATION* Operations
    )
{
    ULONG n = 0;

    if (!Operations) return 0;
    *Operations = NULL;

    EnterCriticalSection(&g_Flm.PendingLock);
    if (g_Flm.PendingCount > 0) {
        PWKD_PENDING_OPERATION out =
            (PWKD_PENDING_OPERATION)UtHeapAlloc(sizeof(WKD_PENDING_OPERATION) * g_Flm.PendingCount);
        if (out) {
            RtlCopyMemory(out, g_Flm.PendingOps, sizeof(WKD_PENDING_OPERATION) * g_Flm.PendingCount);
            *Operations = out;
            n = g_Flm.PendingCount;
        }
    }
    LeaveCriticalSection(&g_Flm.PendingLock);

    return n;
}

VOID
FileLockManager_FreePendingOperations(
    _In_opt_ PWKD_PENDING_OPERATION Operations
    )
{
    if (Operations) UtHeapFree(Operations);
}

BOOLEAN
FileLockManager_CancelPendingOperation(
    _In_ PCWSTR SourcePath
    )
{
    ULONG i;
    BOOLEAN removed = FALSE;

    if (!SourcePath) return FALSE;

    EnterCriticalSection(&g_Flm.PendingLock);
    for (i = 0; i < g_Flm.PendingCount; i++) {
        if (_wcsicmp(g_Flm.PendingOps[i].SourcePath, SourcePath) == 0) {
            if (i + 1 < g_Flm.PendingCount) {
                RtlMoveMemory(&g_Flm.PendingOps[i], &g_Flm.PendingOps[i + 1],
                              sizeof(WKD_PENDING_OPERATION) * (g_Flm.PendingCount - i - 1));
            }
            g_Flm.PendingCount--;
            removed = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&g_Flm.PendingLock);

    return removed;
}

/**************************************************/
/*               威胁关联 (对齐 SS AnalyzeThreat)    */
/**************************************************/

_Check_return_
NTSTATUS
FileLockManager_AnalyzeThreat(
    _In_ PWKD_FILE_LOCK_INFO Info,
    _Out_ PWKD_THREAT_ASSESSMENT Threat
    )
{
    if (!Info || !Threat) return STATUS_INVALID_PARAMETER;

    FlmAnalyzeThreatInternal(Info, Threat);
    return STATUS_SUCCESS;
}

/**************************************************/
/*               配置与统计                         */
/**************************************************/

VOID
FileLockManager_SetAllowProcessTermination(
    _In_ BOOLEAN Allow
    )
{
    EnterCriticalSection(&g_Flm.Lock);
    g_Flm.Config.AllowProcessTermination = Allow;
    LeaveCriticalSection(&g_Flm.Lock);
}

VOID
FileLockManager_SetProtectSystemProcesses(
    _In_ BOOLEAN Protect
    )
{
    EnterCriticalSection(&g_Flm.Lock);
    g_Flm.Config.ProtectSystemProcesses = Protect;
    LeaveCriticalSection(&g_Flm.Lock);
}

/* 回调注册 (死代码: ALPC 覆盖告警分发, 保留 SS 公共 API 面对齐, 供后续接线) */

VOID
FileLockManager_SetTerminateCallback(
    _In_opt_ WKD_FLM_TERMINATE_CALLBACK Callback
    )
{
    EnterCriticalSection(&g_Flm.CallbackLock);
    g_Flm.TerminateCb = Callback;
    LeaveCriticalSection(&g_Flm.CallbackLock);
}

VOID
FileLockManager_SetProgressCallback(
    _In_opt_ WKD_FLM_PROGRESS_CALLBACK Callback
    )
{
    EnterCriticalSection(&g_Flm.CallbackLock);
    g_Flm.ProgressCb = Callback;
    LeaveCriticalSection(&g_Flm.CallbackLock);
}

VOID
FileLockManager_SetLockEventCallback(
    _In_opt_ WKD_FLM_LOCK_EVENT_CALLBACK Callback
    )
{
    EnterCriticalSection(&g_Flm.CallbackLock);
    g_Flm.LockEventCb = Callback;
    LeaveCriticalSection(&g_Flm.CallbackLock);
}

VOID
FileLockManager_GetStatistics(
    _Out_ PWKD_FILE_LOCK_STATS Stats
    )
{
    if (!Stats) return;
    Stats->LocksDetected = InterlockedCompareExchange64(&g_Flm.Stats.LocksDetected, 0, 0);
    Stats->SuccessfulUnlocks = InterlockedCompareExchange64(&g_Flm.Stats.SuccessfulUnlocks, 0, 0);
    Stats->FailedUnlocks = InterlockedCompareExchange64(&g_Flm.Stats.FailedUnlocks, 0, 0);
    Stats->ProcessesTerminated = InterlockedCompareExchange64(&g_Flm.Stats.ProcessesTerminated, 0, 0);
    Stats->HandlesClosed = InterlockedCompareExchange64(&g_Flm.Stats.HandlesClosed, 0, 0);
    Stats->RebootScheduled = InterlockedCompareExchange64(&g_Flm.Stats.RebootScheduled, 0, 0);
    Stats->KernelUnlocks = InterlockedCompareExchange64(&g_Flm.Stats.KernelUnlocks, 0, 0);
    Stats->HandleEnumerations = InterlockedCompareExchange64(&g_Flm.Stats.HandleEnumerations, 0, 0);
    Stats->ThreatsDetected = InterlockedCompareExchange64(&g_Flm.Stats.ThreatsDetected, 0, 0);
}

VOID
FileLockManager_ResetStatistics(
    VOID
    )
{
    InterlockedExchange64(&g_Flm.Stats.LocksDetected, 0);
    InterlockedExchange64(&g_Flm.Stats.SuccessfulUnlocks, 0);
    InterlockedExchange64(&g_Flm.Stats.FailedUnlocks, 0);
    InterlockedExchange64(&g_Flm.Stats.ProcessesTerminated, 0);
    InterlockedExchange64(&g_Flm.Stats.HandlesClosed, 0);
    InterlockedExchange64(&g_Flm.Stats.RebootScheduled, 0);
    InterlockedExchange64(&g_Flm.Stats.KernelUnlocks, 0);
    InterlockedExchange64(&g_Flm.Stats.HandleEnumerations, 0);
    InterlockedExchange64(&g_Flm.Stats.ThreatsDetected, 0);
}

/**************************************************/
/*                   自测                           */
/**************************************************/

_Check_return_
NTSTATUS
FileLockManager_SelfTest(
    VOID
    )
{
    WCHAR tempDir[MAX_PATH];
    WCHAR tempFile[MAX_PATH];
    HANDLE hLock = INVALID_HANDLE_VALUE;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN locked;
    WKD_LOCK_TYPE lt;
    PWKD_LOCK_OWNER owners = NULL;
    ULONG ownerCount = 0;
    WKD_FILE_LOCK_INFO info;
    WKD_UNLOCK_OPERATION op;
    BOOLEAN accessDenied = FALSE;

    /* 1. 创建独占锁临时文件 */
    if (GetTempPathW(MAX_PATH, tempDir) == 0) return STATUS_UNSUCCESSFUL;
    if (GetTempFileNameW(tempDir, L"WkdFlm", 0, tempFile) == 0) return STATUS_UNSUCCESSFUL;

    hLock = CreateFileW(tempFile, GENERIC_READ | GENERIC_WRITE, 0 /* 无共享 */,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hLock == INVALID_HANDLE_VALUE) {
        DeleteFileW(tempFile);
        return STATUS_UNSUCCESSFUL;
    }

    /* 2. IsFileLocked 真锁 */
    locked = FileLockManager_IsFileLocked(tempFile, &accessDenied);
    if (!locked || accessDenied) status = STATUS_UNSUCCESSFUL;

    /* 3. GetLockType 独占 */
    lt = FileLockManager_GetLockType(tempFile);
    if (lt != WkdLock_Exclusive) status = STATUS_UNSUCCESSFUL;

    /* 4. CanDeleteFile 被锁不可删 */
    if (FileLockManager_CanDeleteFile(tempFile)) status = STATUS_UNSUCCESSFUL;

    /* 5. 句柄枚举应识别自进程锁 */
    if (FileLockManager_GetLockingProcesses(tempFile, &owners, &ownerCount) != STATUS_SUCCESS) {
        status = STATUS_UNSUCCESSFUL;
    } else {
        FileLockManager_FreeLockOwners(owners);
    }

    /* 6. GetLockInfo 汇总 */
    RtlZeroMemory(&info, sizeof(info));
    if (FileLockManager_GetLockInfo(tempFile, &info) != STATUS_SUCCESS) {
        status = STATUS_UNSUCCESSFUL;
    } else {
        if (!info.IsLocked) status = STATUS_UNSUCCESSFUL;
        FileLockManager_FreeLockInfo(&info);
    }

    /* 7. 释放锁后探测 */
    CloseHandle(hLock);
    hLock = INVALID_HANDLE_VALUE;
    if (FileLockManager_IsFileLocked(tempFile, NULL)) status = STATUS_UNSUCCESSFUL;

    /* 8. 解锁链: 未锁 → NotLocked */
    RtlZeroMemory(&op, sizeof(op));
    if (FileLockManager_UnlockFile(tempFile, &op) == STATUS_SUCCESS) {
        if (op.Result != WkdUnlockResult_NotLocked) status = STATUS_UNSUCCESSFUL;
    } else {
        status = STATUS_UNSUCCESSFUL;
    }

    DeleteFileW(tempFile);
    return status;
}
