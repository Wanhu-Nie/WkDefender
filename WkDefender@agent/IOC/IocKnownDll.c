/**************************************************/
/*  WkDefender IOC — 地址→函数名惰性缓存实现        */
/*                                                  */
/*  架构:                                           */
/*    - 两套链表缓存（x64 / x32），惰性填充           */
/*    - 查询 → 链表遍历 → 未命中 → 模块范围匹配 →   */
/*      一次性读取整 DLL 镜像 → 本地 PE 解析 → 缓存  */
/*    - 无预定义关注名单、无预填充                    */
/**************************************************/

#include "IocKnownDll.h"
#include "PEAnalyzer/PeAnalyzer.h"  /* WpeResolveModuleExportName (导出解析收敛) */
#include <psapi.h>          /* EnumProcessModulesEx, GetModuleInformation */
#pragma comment(lib, "Psapi.lib")

/**************************************************/
/*           缓存链表节点（文件作用域）               */
/**************************************************/

typedef struct _IOC_CACHE_NODE {
    PVOID                   Address;      /* 函数地址                 */
    PWSTR                   DllName;      /* 堆拷贝，如 L"kernel32"   */
    PWSTR                   FuncName;     /* 堆拷贝，如 L"LoadLibraryA" */
    struct _IOC_CACHE_NODE* Next;
} IOC_CACHE_NODE, *PIOC_CACHE_NODE;

/**************************************************/
/*               全局缓存（文件作用域）               */
/**************************************************/

/* x64 / x32 各一条链表 */
static IOC_CACHE_NODE* g_Cache64 = NULL;
static IOC_CACHE_NODE* g_Cache32 = NULL;

/* 保护链表并发访问 */
static CRITICAL_SECTION g_CacheLock;
static BOOLEAN          g_LockInitialized = FALSE;

/**************************************************/
/*           内部函数声明                           */
/**************************************************/

static
BOOLEAN
IocpLazyResolve(
    _In_  ULONG64           Address,
    _In_  ULONG             TargetProcessId,
    _In_  BOOLEAN           IsWow64,
    _Out_ PIOC_CACHE_NODE*  OutNode
    );

static
BOOLEAN
IocpAppendCache(
    _In_  BOOLEAN           IsWow64,
    _In_  ULONG64           Address,
    _In_  PCWSTR            DllName,
    _In_  PCWSTR            FuncName,
    _Out_ PIOC_CACHE_NODE*  OutNode
    );

static
NTSTATUS
IocpExtractDllShortName(
    _In_  PCWSTR FullPath,
    _Out_ PWSTR  ShortName,
    _In_  SIZE_T ShortSize
    );

/**************************************************/
/*               初始化（空桩）                      */
/**************************************************/

VOID
IocInitKnownDllAddresses(
    VOID
    )
/*++
Routine Description:
    惰性模式下仅初始化锁。
    IocEngine_Initialize 启动时调用。
--*/
{
    if (!g_LockInitialized) {
        InitializeCriticalSection(&g_CacheLock);
        g_LockInitialized = TRUE;
    }
}

/**************************************************/
/*           公共查询接口                           */
/**************************************************/

NTSTATUS
IocMatchSensitiveFunc(
    _In_  ULONG64           Address,
    _In_  ULONG             TargetProcessId,
    _Out_ PIOC_FUNC_INFO    OutInfo
    )
/*++
Routine Description:
    将地址解析为 (DLL名, 函数名)。
    两段式：先查链表缓存 → 未命中则惰性解析。

Arguments:
    Address   — 待解析地址
    TargetProcessId — 目标进程 PID
    OutInfo   — 输出解析结果
--*/
{
    NTSTATUS status;

    if (!Address || !TargetProcessId || !OutInfo)
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(OutInfo, sizeof(IOC_FUNC_INFO));

    /* ── Step 1: 判断目标进程位数 ── */
    BOOL isWow64 = FALSE;
    {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                      FALSE, TargetProcessId);
        if (!hProcess) {
            return STATUS_UNSUCCESSFUL;
        }
        if (!IsWow64Process(hProcess, &isWow64)) {
            CloseHandle(hProcess);
            return STATUS_UNSUCCESSFUL;
        }
        CloseHandle(hProcess);
    }

    /* ── Step 2: 遍历缓存链表 ── */
    PIOC_CACHE_NODE cachedNode = NULL;
    EnterCriticalSection(&g_CacheLock);
    {
        PIOC_CACHE_NODE curr = isWow64 ? g_Cache32 : g_Cache64;
        while (curr) {
            if (curr->Address == Address) {
                cachedNode = curr;
                break;
            }
            curr = curr->Next;
        }
    }
    LeaveCriticalSection(&g_CacheLock);

    /* 缓存命中 → 从节点填充 OutInfo */
    if (cachedNode) goto Success;

    /* ── Step 3: 未命中 → 惰性解析（返回节点指针后填充 OutInfo） ── */
    if (!IocpLazyResolve(Address, TargetProcessId, isWow64, &cachedNode))
        return STATUS_UNSUCCESSFUL;

Success:
    OutInfo->Address  = cachedNode->Address;
    OutInfo->DllName  = cachedNode->DllName;
    OutInfo->FuncName = cachedNode->FuncName;

    return STATUS_SUCCESS;
}

/**************************************************/
/*           惰性解析：范围匹配 + 一次性读 DLL       */
/**************************************************/

static
BOOLEAN
IocpLazyResolve(
    _In_  ULONG64           Address,
    _In_  ULONG             TargetProcessId,
    _In_  BOOLEAN           IsWow64,
    _Out_ PIOC_CACHE_NODE*  OutNode
)
/*++
Routine Description:
    惰性解析地址。
    打开目标进程 → 枚举模块 → 地址范围匹配 → 一次性读 DLL →
    本地 PE 导出解析 → 缓存。

Arguments:
    Address   — 待解析地址
    TargetProcessId — 目标进程 PID
    IsWow64   — TRUE=WOW64 / FALSE=x64
    OutNode   — 输出缓存节点指针

Return Value:
    TRUE  = 解析成功并已缓存
    FALSE = 无法解析
--*/
{
    ULONG   i;
    HANDLE  hProcess;
    WCHAR   modulePath[MAX_PATH];
    ULONG_PTR moduleBase;

    if (OutNode) *OutNode = NULL;

    /* ── 步骤1：打开目标进程 ── */
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                           FALSE, TargetProcessId);
    if (!hProcess) {
        return FALSE;
    }

    /* 步骤2：定位目标 DLL */
    {
        /* ── 枚举模块 → 地址范围匹配 ── */
        HMODULE hModules[64];
        DWORD   cbNeeded;
        BOOLEAN found = FALSE;

        if (!EnumProcessModulesEx(hProcess, hModules, sizeof(hModules),
            &cbNeeded, IsWow64 ? LIST_MODULES_32BIT : LIST_MODULES_ALL)) {
            CloseHandle(hProcess);
            return FALSE;
        }

        for (i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
            MODULEINFO modInfo;
            if (!GetModuleInformation(hProcess, hModules[i],
                &modInfo, sizeof(modInfo)))
                continue;

            ULONG64 baseAddr = (ULONG64)(ULONG_PTR)hModules[i];
            if (Address >= baseAddr &&
                Address < baseAddr + modInfo.SizeOfImage) {
                moduleBase = (ULONG_PTR)baseAddr;

                if (!GetModuleFileNameExW(hProcess, hModules[i],
                    modulePath, MAX_PATH))
                    continue;

                found = TRUE;
                break;
            }
        }

        if (!found) {
            CloseHandle(hProcess);
            return FALSE;
        }
    }

    /* 步骤3：PE 解析 (收敛至 PEAnalyzer WpeResolveModuleExportName:
     * 内存模式 IocAnalyzeFromProcess + WpeParseExports EAT 精确匹配, 跳过 forwarder) */
    {
        WCHAR funcNameW[PE_MAX_FUNCTION_NAME + 1];
        WCHAR shortDllName[32];
        BOOLEAN appendResult;

        if (!NT_SUCCESS(WpeResolveModuleExportName(hProcess, moduleBase,
                                                   Address, funcNameW,
                                                   PE_MAX_FUNCTION_NAME + 1))) {
            goto Failed;
        }
        if (funcNameW[0] == L'\0') goto Failed;

        /* 提取 DLL 短名 */
        IocpExtractDllShortName(modulePath, shortDllName, sizeof(shortDllName));

        /* IocpAppendCache 内部会堆拷贝 funcNameW，之后可释放 */
        appendResult = IocpAppendCache(IsWow64, Address, shortDllName, funcNameW, OutNode);

        CloseHandle(hProcess);
        return appendResult;
    }

Failed:
    CloseHandle(hProcess);
    return FALSE;
}

/**************************************************/
/*           线程安全：追加缓存节点                  */
/**************************************************/

static
BOOLEAN
IocpAppendCache(
    _In_  BOOLEAN           IsWow64,
    _In_  ULONG64           Address,
    _In_  PCWSTR            DllName,
    _In_  PCWSTR            FuncName,
    _Out_ PIOC_CACHE_NODE*  OutNode
    )
/*++
Routine Description:
    创建缓存节点追加到链表（头插）。
    加 CRITICAL_SECTION 保证线程安全。
    插入前再次查重（防止并发重复插入）。

Arguments:
    IsWow64  — TRUE → g_Cache32, FALSE → g_Cache64
    Address  — 函数地址
    DllName  — DLL 短名（将被堆拷贝）
    FuncName — 函数名（将被堆拷贝，调用者不再负责释放）
    OutNode  — 输出指向缓存节点的指针
--*/
{
    *OutNode = NULL;

    /* 堆拷贝字符串 */
    PWSTR dllCopy  = _wcsdup(DllName);
    PWSTR funcCopy = _wcsdup(FuncName);
    if (!dllCopy || !funcCopy) goto Failed;

    PIOC_CACHE_NODE node = (PIOC_CACHE_NODE)malloc(sizeof(IOC_CACHE_NODE));
    if (!node) goto Failed;

    node->Address  = Address;
    node->DllName  = dllCopy;
    node->FuncName = funcCopy;

    EnterCriticalSection(&g_CacheLock);

    /* 查重：可能另一线程在执行 IocpLazyResolve 时已插入 */
    {
        PIOC_CACHE_NODE curr = IsWow64 ? g_Cache32 : g_Cache64;
        while (curr) {
            if (curr->Address == Address) {
                /* 已被其他线程缓存，返回已有节点 */
                if (OutNode) *OutNode = curr;
                LeaveCriticalSection(&g_CacheLock);
                free(node);
                free(dllCopy);
                free(funcCopy);
                return TRUE;
            }
            curr = curr->Next;
        }
    }

    /* 头插 */
    if (IsWow64) {
        node->Next   = g_Cache32;
        g_Cache32    = node;
    } else {
        node->Next   = g_Cache64;
        g_Cache64    = node;
    }

    LeaveCriticalSection(&g_CacheLock);

    if (OutNode)
        *OutNode = node;

    return TRUE;

Failed:
    if (dllCopy)  free(dllCopy);
    if (funcCopy) free(funcCopy);
    return FALSE;
}

/**************************************************/
/*           工具：从路径提取 DLL 短名               */
/**************************************************/

static
NTSTATUS
IocpExtractDllShortName(
    _In_  PCWSTR FullPath,
    _Out_ PWSTR  ShortName,
    _In_  SIZE_T ShortSize
    )
/*++
Routine Description:
    从完整 DLL 路径提取短名（去掉路径和扩展名）。
    例如: L"C:\\Windows\\System32\\kernel32.dll" → L"kernel32"
--*/
{
    if (!FullPath || !ShortName || ShortSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(ShortName, ShortSize);

    /* 找最后一个 '\\' */
    PCWSTR baseName = wcsrchr(FullPath, L'\\');
    if (baseName) {
        baseName++;  /* 跳过反斜杠 */
    } else {
        baseName = FullPath;
    }

    /* 拷贝文件名（带扩展名） */
    wcscpy_s(ShortName, ShortSize / sizeof(WCHAR), baseName);

    /* 去掉扩展名：找最后一个 '.' */
    PWSTR dot = wcsrchr(ShortName, L'.');
    if (dot) {
        *dot = L'\0';
    }
}
