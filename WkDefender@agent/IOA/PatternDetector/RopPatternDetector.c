/**************************************************/
/*  WkDefender IOA — ROP 代码复用攻击模式检测器实现  */
/*                                                  */
/*  迁移自 ShadowStrike ROPProtection.cpp           */
/*  (v3.0.0) 功能重实现 (C 重写), 非源码复制。      */
/*                                                  */
/*  与 SS 源码的对齐/裁剪 (注释就地标注):            */
/*    - 无日志设施: 关键路径以回调事件上报, 调试     */
/*      细节注释说明 (对齐 LPE/KED 先例)             */
/*    - 去 C++ 容器: unordered_map/set/deque/shared_ */
/*      ptr/PIMPL → 静态数组 + SRWLOCK + 每栈自旋锁  */
/*    - 状态收敛: 全局线程影子栈槽位 4096→256 (LRU), */
/*      受保护进程/模块缓存设静态上限 (见头文件)     */
/*    - SelfTest 测试 2 的可执行地址改用运行时枚举   */
/*      (SS 硬编码 0x400000, ASLR 下不可靠)          */
/*    - 内核告警: WkDefender 无 SS 消息枚举, 不做     */
/*      MsgType 枚举比对, 由调用方把关转发; 线格式   */
/*      ABI 与 SS 完全一致 (334B 头 + 45B gadget)    */
/**************************************************/

#include "RopPatternDetector.h"

#include <windows.h>
#include <ntstatus.h>
#include <psapi.h>
#include <intrin.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "psapi.lib")       /* EnumProcessModules / GetModuleInformation */

/**************************************************/
/*               内置容量 (头文件未暴露)            */
/**************************************************/

#define RPD_MAX_PROTECTED_PROCESSES     64          /* 受保护进程表上限 (SS 无上限) */
#define RPD_CACHED_MODULES_PER_PID      64          /* 单进程模块缓存上限 */
#define RPD_MAX_UNIQUE_GADGETS          256         /* 栈扫描去重数组上限 */

/**************************************************/
/*               Gadget 模式表                      */
/*  ROP_GADGET_PATTERNS (15 条, 显式长度,  */
/*  0x00 是合法 x86 操作码不能作哨兵)。             */
/**************************************************/

typedef struct _RPD_GADGET_PATTERN {
    UCHAR Bytes[16];
    UCHAR Length;
} RPD_GADGET_PATTERN;

static const RPD_GADGET_PATTERN g_RopGadgetPatterns[] = {
    {{0x58, 0xC3},                          2},  /* POP EAX; RET */
    {{0x59, 0xC3},                          2},  /* POP ECX; RET */
    {{0x5A, 0xC3},                          2},  /* POP EDX; RET */
    {{0x5B, 0xC3},                          2},  /* POP EBX; RET */
    {{0x5C, 0xC3},                          2},  /* POP ESP; RET (栈迁移!) */
    {{0x5D, 0xC3},                          2},  /* POP EBP; RET */
    {{0x5E, 0xC3},                          2},  /* POP ESI; RET */
    {{0x5F, 0xC3},                          2},  /* POP EDI; RET */
    {{0x58, 0x58, 0xC3},                    3},  /* POP EAX; POP EAX; RET */
    {{0xFF, 0xE4},                          2},  /* JMP ESP */
    {{0xFF, 0xE0},                          2},  /* JMP EAX */
    {{0xFF, 0xD4},                          2},  /* CALL ESP */
    {{0xC2, 0x04, 0x00},                    3},  /* RET 4 */
    {{0xC2, 0x08, 0x00},                    3},  /* RET 8 */
    {{0x0F, 0x05, 0xC3},                    3},  /* SYSCALL; RET */
};

#define RPD_GADGET_PATTERN_COUNT \
    (sizeof(g_RopGadgetPatterns) / sizeof(g_RopGadgetPatterns[0]))

/**************************************************/
/*               默认受保护 API 表                  */
/*  DEFAULT_PROTECTED_APIS (21 项)。        */
/**************************************************/

typedef struct _RPD_DEFAULT_API {
    const char*         Name;
    RPD_API_CATEGORY    Category;
} RPD_DEFAULT_API;

static const RPD_DEFAULT_API g_DefaultProtectedApis[] = {
    {"VirtualAlloc",          RpdApiCat_MemoryAllocation},
    {"VirtualAllocEx",        RpdApiCat_MemoryAllocation},
    {"VirtualProtect",        RpdApiCat_MemoryProtection},
    {"VirtualProtectEx",      RpdApiCat_MemoryProtection},
    {"NtProtectVirtualMemory", RpdApiCat_MemoryProtection},
    {"HeapAlloc",             RpdApiCat_MemoryAllocation},
    {"CreateProcess",         RpdApiCat_ProcessCreation},
    {"CreateProcessA",        RpdApiCat_ProcessCreation},
    {"CreateProcessW",        RpdApiCat_ProcessCreation},
    {"CreateThread",          RpdApiCat_ThreadCreation},
    {"CreateRemoteThread",    RpdApiCat_ThreadCreation},
    {"LoadLibrary",           RpdApiCat_DllLoading},
    {"LoadLibraryA",          RpdApiCat_DllLoading},
    {"LoadLibraryW",          RpdApiCat_DllLoading},
    {"LoadLibraryEx",         RpdApiCat_DllLoading},
    {"LoadLibraryExA",        RpdApiCat_DllLoading},
    {"LoadLibraryExW",        RpdApiCat_DllLoading},
    {"ShellExecute",          RpdApiCat_CodeExecution},
    {"ShellExecuteA",         RpdApiCat_CodeExecution},
    {"ShellExecuteW",         RpdApiCat_CodeExecution},
    {"WinExec",               RpdApiCat_CodeExecution},
};

/**************************************************/
/*               内部数据结构                       */
/**************************************************/

/* 影子栈条目 (SS ShadowStackEntry 实际仅填充
 * returnAddress/callSite/timestamp 三字段, 此处对齐) */
typedef struct _RPD_SS_ENTRY {
    UINT64      ReturnAddress;
    UINT64      CallSite;
    ULONGLONG   Timestamp;          /* GetTickCount64 */
} RPD_SS_ENTRY;

/* 逐线程影子栈: 动态容量 MaxDepth, 满则丢弃最老 (SS deque pop_front) */
typedef struct _RPD_THREAD_STACK {
    ULONG           ThreadId;
    RPD_SS_ENTRY*   Entries;
    ULONG           Depth;
    ULONG           Capacity;
    ULONGLONG       LastActivity;
    UINT64          PushCount;
    UINT64          PopCount;
    UINT64          MismatchCount;
    CRITICAL_SECTION Cs;            /* 每栈独立锁 (SS stackMutex) */
} RPD_THREAD_STACK;

/* 受保护进程条目 */
typedef struct _RPD_PROTECTED_PROCESS {
    ULONG   ProcessId;
    BOOLEAN CetEnabled;
    WCHAR   ProcessName[DEF_MAX_IMAGE_NAME];
    WCHAR   ProcessPath[DEF_MAX_PATH * 2];
} RPD_PROTECTED_PROCESS;

/* 模块缓存条目 (per-PID) */
typedef struct _RPD_CACHED_MODULE {
    UINT64  Base;
    SIZE_T  Size;
    WCHAR   Name[DEF_MAX_IMAGE_NAME];
} RPD_CACHED_MODULE;

typedef struct _RPD_MOD_CACHE {
    ULONG               ProcessId;
    BOOLEAN             Valid;
    ULONGLONG           Timestamp;      /* 缓存填充 tick */
    ULONG               ModuleCount;
    RPD_CACHED_MODULE   Modules[RPD_CACHED_MODULES_PER_PID];
} RPD_MOD_CACHE;

/* 全局状态 (对标 SS ROPProtectionImpl 成员) */
static struct {
    RPD_STATUS              Status;
    RPD_CONFIG              Config;
    BOOLEAN                 Initialized;
    SRWLOCK                 Lock;               /* 状态/配置/进程保护表 */

    /* 受保护 API 表 */
    RPD_PROTECTED_API_INFO  Apis[RPD_MAX_PROTECTED_APIS];
    ULONG                   ApiCount;
    SRWLOCK                 ApiLock;

    /* 受保护进程表 */
    RPD_PROTECTED_PROCESS   Processes[RPD_MAX_PROTECTED_PROCESSES];
    ULONG                   ProcessCount;

    /* 进程模块缓存 (per-PID, TTL) */
    RPD_MOD_CACHE           ModuleCache[RPD_MAX_CACHED_PIDS];

    /* 全局线程影子栈槽位 (LRU 淘汰) */
    RPD_THREAD_STACK*       ThreadStacks[RPD_MAX_THREAD_STACK_SLOTS];
    SRWLOCK                 ThreadStackLock;

    /* 检测历史环形缓冲 */
    RPD_EVENT               History[RPD_HISTORY_CAPACITY];
    ULONG                   HistoryCount;
    ULONG                   HistoryHead;        /* 满后下一覆盖位置 */
    ULONG                   HistoryLast;        /* 最新元素位置 */
    SRWLOCK                 HistoryLock;

    /* 回调 */
    RPD_DETECTED_CALLBACK   Callback;
    PVOID                   CallbackContext;
    SRWLOCK                 CallbackLock;

    /* 统计与运行时钟 */
    RPD_STATISTICS          Stats;
    ULONGLONG               StartTick;
    BOOLEAN                 CetAvailable;

    /* 事件/链 ID 自增 */
    volatile LONG           NextEventId;
    volatile LONG           NextChainId;
} g_Rpd = { 0 };

/**************************************************/
/*               内部辅助: 内存探测                 */
/**************************************************/

/* SEH 安全读单字节 (SS SehMatches* 系列共用, 防页竞态) */
static BOOLEAN
RpdpSafeReadByte(
    _In_ UINT64 Address,
    _Out_ UCHAR* Out
    )
{
    __try {
        *Out = *(volatile UCHAR*)(UINT_PTR)Address;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

/* CALL 前导模式探测 (SehMatches* 六种) */
static BOOLEAN
RpdpMatchesCallRel32(_In_ UINT64 I)
{
    UCHAR b;
    return RpdpSafeReadByte(I, &b) && (b == 0xE8);
}

static BOOLEAN
RpdpMatchesCallReg(_In_ UINT64 I)
{
    UCHAR b1, b2;
    return RpdpSafeReadByte(I, &b1) && RpdpSafeReadByte(I + 1, &b2) &&
           (b1 == 0xFF) && ((b2 & 0xF8) == 0xD0);
}

static BOOLEAN
RpdpMatchesCallRipRelative(_In_ UINT64 I)
{
    UCHAR b1, b2;
    return RpdpSafeReadByte(I, &b1) && RpdpSafeReadByte(I + 1, &b2) &&
           (b1 == 0xFF) && (b2 == 0x15);
}

static BOOLEAN
RpdpMatchesCallDisp8(_In_ UINT64 I)
{
    UCHAR b1, b2;
    return RpdpSafeReadByte(I, &b1) && RpdpSafeReadByte(I + 1, &b2) &&
           (b1 == 0xFF) && ((b2 & 0xF8) == 0x50);
}

static BOOLEAN
RpdpMatchesRexCallReg(_In_ UINT64 I)
{
    UCHAR b1, b2, b3;
    return RpdpSafeReadByte(I, &b1) && RpdpSafeReadByte(I + 1, &b2) &&
           RpdpSafeReadByte(I + 2, &b3) &&
           ((b1 & 0xF0) == 0x40) && (b2 == 0xFF) && ((b3 & 0xF8) == 0xD0);
}

static BOOLEAN
RpdpMatchesRexCallRipRelative(_In_ UINT64 I)
{
    UCHAR b1, b2, b3;
    return RpdpSafeReadByte(I, &b1) && RpdpSafeReadByte(I + 1, &b2) &&
           RpdpSafeReadByte(I + 2, &b3) &&
           ((b1 & 0xF0) == 0x40) && (b2 == 0xFF) && (b3 == 0x15);
}

/* 返回地址前是否紧跟合法 CALL 编码 (SS SehHasRecognizedCallSite) */
static BOOLEAN
RpdpHasCallSite(
    _In_ UINT64 ReturnAddress,
    _In_ UINT64 RegionBase
    )
{
    if (ReturnAddress >= 5 && (ReturnAddress - 5) >= RegionBase &&
        RpdpMatchesCallRel32(ReturnAddress - 5)) {
        return TRUE;
    }
    if (ReturnAddress >= 2 && (ReturnAddress - 2) >= RegionBase &&
        RpdpMatchesCallReg(ReturnAddress - 2)) {
        return TRUE;
    }
    if (ReturnAddress >= 6 && (ReturnAddress - 6) >= RegionBase &&
        RpdpMatchesCallRipRelative(ReturnAddress - 6)) {
        return TRUE;
    }
    if (ReturnAddress >= 3 && (ReturnAddress - 3) >= RegionBase &&
        RpdpMatchesCallDisp8(ReturnAddress - 3)) {
        return TRUE;
    }
    if (ReturnAddress >= 3 && (ReturnAddress - 3) >= RegionBase &&
        RpdpMatchesRexCallReg(ReturnAddress - 3)) {
        return TRUE;
    }
    if (ReturnAddress >= 7 && (ReturnAddress - 7) >= RegionBase &&
        RpdpMatchesRexCallRipRelative(ReturnAddress - 7)) {
        return TRUE;
    }
    return FALSE;
}

/* 归一化页保护 (SS IsExecutableProtection) */
static BOOLEAN
RpdpIsExecutableProtection(_In_ DWORD Protect)
{
    const DWORD normalized = Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
    return (normalized == PAGE_EXECUTE ||
            normalized == PAGE_EXECUTE_READ ||
            normalized == PAGE_EXECUTE_READWRITE ||
            normalized == PAGE_EXECUTE_WRITECOPY);
}

/* 目标进程地址是否为可读可执行已提交区 (SS IsReadableExecutableRegion) */
static BOOLEAN
RpdpIsReadableExecutableRegion(
    _In_ HANDLE  hProcess,
    _In_ UINT64  Address,
    _In_ SIZE_T  RequiredBytes
    )
{
    MEMORY_BASIC_INFORMATION mbi;
    UINT64 base, regionSize, offset, needed;

    ZeroMemory(&mbi, sizeof(mbi));

    if (hProcess == NULL || Address < 0x10000 || RequiredBytes == 0) {
        return FALSE;
    }
#ifdef _WIN64
    if (Address > 0x00007FFFFFFFFFFFULL) {
        return FALSE;
    }
#endif
    if (VirtualQueryEx(hProcess, (LPCVOID)(UINT_PTR)Address, &mbi, sizeof(mbi)) == 0) {
        return FALSE;
    }

    base = (UINT64)(UINT_PTR)mbi.BaseAddress;
    regionSize = (UINT64)mbi.RegionSize;
    if (mbi.State != MEM_COMMIT || regionSize == 0 || Address < base) {
        return FALSE;
    }

    offset = Address - base;
    needed = (UINT64)RequiredBytes;
    if (offset >= regionSize || needed > (regionSize - offset)) {
        return FALSE;
    }

    return RpdpIsExecutableProtection(mbi.Protect);
}

/**************************************************/
/*               内部辅助: 文本清洗                 */
/**************************************************/

/* 写入宽字符文本, 不可打印字符替换为空格, 强制 NUL 结尾 */
static VOID
RpdpSanitizeW(
    _Out_writes_(MaxChars) WCHAR* Out,
    _In_                   ULONG  MaxChars,
    _In_                   PCWSTR In
    )
{
    ULONG i;
    ULONG len;

    if (Out == NULL || MaxChars == 0) {
        return;
    }
    if (In == NULL) {
        Out[0] = L'\0';
        return;
    }

    len = (ULONG)wcslen(In);
    if (len >= MaxChars) {
        len = MaxChars - 1;
    }
    for (i = 0; i < len; ++i) {
        WCHAR ch = In[i];
        if (ch < 0x20 || ch == 0x7F) {
            ch = L' ';
        }
        Out[i] = ch;
    }
    Out[len] = L'\0';
}

/**************************************************/
/*               内部辅助: 进程信息                 */
/**************************************************/

static VOID
RpdpQueryProcessInfo(
    _In_  ULONG  ProcessId,
    _Out_ WCHAR  ProcessName[DEF_MAX_IMAGE_NAME],
    _Out_ WCHAR  ProcessPath[DEF_MAX_PATH * 2]
    )
{
    HANDLE hProcess;
    WCHAR  path[DEF_MAX_PATH * 2];
    DWORD  size;
    WCHAR* slash;

    if (ProcessName != NULL) {
        ProcessName[0] = L'\0';
    }
    if (ProcessPath != NULL) {
        ProcessPath[0] = L'\0';
    }

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (hProcess == NULL) {
        return;
    }

    size = DEF_MAX_PATH * 2;
    if (QueryFullProcessImageNameW(hProcess, 0, path, &size) && size > 0) {
        if (ProcessPath != NULL) {
            RpdpSanitizeW(ProcessPath, DEF_MAX_PATH * 2, path);
        }
        if (ProcessName != NULL) {
            slash = wcsrchr(path, L'\\');
            RpdpSanitizeW(ProcessName, DEF_MAX_IMAGE_NAME,
                          (slash != NULL) ? (slash + 1) : path);
        }
    }
    CloseHandle(hProcess);
}

/**************************************************/
/*               内部辅助: 模块缓存                 */
/*  对标 SS GetModuleForAddress + TTL 缓存。        */
/**************************************************/

static BOOLEAN
RpdpEnumAndCacheModules(
    _In_  ULONG        ProcessId,
    _In_  HANDLE       hProcess,
    _Out_ PRPD_MOD_CACHE OutCache
    )
{
    RPD_MOD_CACHE cache;
    DWORD  needed;
    DWORD  neededRetry;
    HMODULE modules[RPD_CACHED_MODULES_PER_PID];
    ULONG  moduleCount;
    ULONG  i;

    ZeroMemory(&cache, sizeof(cache));
    ZeroMemory(modules, sizeof(modules));

    if (!EnumProcessModules(hProcess, NULL, 0, &needed) && needed == 0) {
        return FALSE;
    }

    /* 模块数超过缓存上限时只枚举前 RPD_CACHED_MODULES_PER_PID 个 */
    moduleCount = needed / sizeof(HMODULE);
    if (moduleCount > RPD_CACHED_MODULES_PER_PID) {
        moduleCount = RPD_CACHED_MODULES_PER_PID;
    }
    if (moduleCount == 0) {
        return FALSE;
    }

    if (!EnumProcessModules(hProcess, modules,
                            moduleCount * sizeof(HMODULE), &neededRetry)) {
        return FALSE;
    }
    moduleCount = neededRetry / sizeof(HMODULE);
    if (moduleCount > RPD_CACHED_MODULES_PER_PID) {
        moduleCount = RPD_CACHED_MODULES_PER_PID;
    }

    cache.ProcessId = ProcessId;
    cache.Timestamp = GetTickCount64();
    cache.ModuleCount = moduleCount;

    for (i = 0; i < moduleCount; ++i) {
        MODULEINFO modInfo;
        WCHAR      modName[DEF_MAX_IMAGE_NAME];

        ZeroMemory(&modInfo, sizeof(modInfo));
        modName[0] = L'\0';

        if (!GetModuleInformation(hProcess, modules[i], &modInfo, sizeof(modInfo))) {
            continue;
        }
        if (!GetModuleFileNameExW(hProcess, modules[i], modName, DEF_MAX_IMAGE_NAME)) {
            continue;
        }

        cache.Modules[i].Base = (UINT64)(UINT_PTR)modInfo.lpBaseOfDll;
        cache.Modules[i].Size = modInfo.SizeOfImage;
        RpdpSanitizeW(cache.Modules[i].Name, DEF_MAX_IMAGE_NAME, modName);
    }

    *OutCache = cache;
    return TRUE;
}

static VOID
RpdpCacheSet(
    _In_ PRPD_MOD_CACHE Cache,
    _In_ BOOLEAN        AcquireLock
    )
{
    ULONG      oldestIdx;
    ULONG      i;
    ULONGLONG  oldestTick;

    if (AcquireLock) {
        AcquireSRWLockExclusive(&g_Rpd.Lock);
    }

    /* 同 PID 直接覆盖; 否则占用空闲槽或淘汰最旧槽 */
    for (i = 0; i < RPD_MAX_CACHED_PIDS; ++i) {
        if (g_Rpd.ModuleCache[i].Valid && g_Rpd.ModuleCache[i].ProcessId == Cache->ProcessId) {
            g_Rpd.ModuleCache[i] = *Cache;
            g_Rpd.ModuleCache[i].Valid = TRUE;
            if (AcquireLock) {
                ReleaseSRWLockExclusive(&g_Rpd.Lock);
            }
            return;
        }
    }

    oldestIdx = 0;
    oldestTick = (ULONGLONG)-1;
    for (i = 0; i < RPD_MAX_CACHED_PIDS; ++i) {
        if (!g_Rpd.ModuleCache[i].Valid) {
            oldestIdx = i;
            break;
        }
        if (g_Rpd.ModuleCache[i].Timestamp < oldestTick) {
            oldestTick = g_Rpd.ModuleCache[i].Timestamp;
            oldestIdx = i;
        }
    }
    g_Rpd.ModuleCache[oldestIdx] = *Cache;
    g_Rpd.ModuleCache[oldestIdx].Valid = TRUE;

    if (AcquireLock) {
        ReleaseSRWLockExclusive(&g_Rpd.Lock);
    }
}

/* 查询地址所属模块 (命中填 Name/Offset 并返回 TRUE) */
static BOOLEAN
RpdpGetModuleForAddress(
    _In_  ULONG   ProcessId,
    _In_  UINT64  Address,
    _Out_writes_(DEF_MAX_IMAGE_NAME) WCHAR* OutName,
    _Out_ UINT64* OutOffset
    )
{
    ULONG        i;
    ULONG        slot;
    RPD_MOD_CACHE cache;
    BOOLEAN      found;
    ULONGLONG    now;
    HANDLE       hProcess;

    found = FALSE;
    slot = RPD_MAX_CACHED_PIDS;
    now = GetTickCount64();

    /* 查缓存 (TTL 有效期内) */
    AcquireSRWLockShared(&g_Rpd.Lock);
    for (i = 0; i < RPD_MAX_CACHED_PIDS; ++i) {
        if (g_Rpd.ModuleCache[i].Valid && g_Rpd.ModuleCache[i].ProcessId == ProcessId) {
            slot = i;
            break;
        }
    }
    if (slot != RPD_MAX_CACHED_PIDS) {
        if ((now - g_Rpd.ModuleCache[slot].Timestamp) < RPD_MODULE_CACHE_TTL_MS) {
            for (i = 0; i < g_Rpd.ModuleCache[slot].ModuleCount; ++i) {
                RPD_CACHED_MODULE* mod = &g_Rpd.ModuleCache[slot].Modules[i];
                if (Address >= mod->Base &&
                    Address < (mod->Base + (UINT64)mod->Size) &&
                    mod->Base != 0) {
                    RpdpSanitizeW(OutName, DEF_MAX_IMAGE_NAME, mod->Name);
                    *OutOffset = Address - mod->Base;
                    ReleaseSRWLockShared(&g_Rpd.Lock);
                    return TRUE;
                }
            }
            ReleaseSRWLockShared(&g_Rpd.Lock);
            return FALSE;   /* 地址确实不在任何已缓存模块内 */
        }
        /* 缓存过期, 落入重新枚举 */
    }
    ReleaseSRWLockShared(&g_Rpd.Lock);

    /* 未命中或缓存过期: 重新枚举.
     * 双检 TTL (double-checked): 若其他线程已刷新缓存则用之,
     * 否则覆盖式写回本次枚举结果 (最后写者赢, 简化处理并在语义上
     * 等同于一次新的 TTL 刷新, 注释说明与 SS 保守方案的差异)。 */
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId);
    if (hProcess == NULL) {
        return FALSE;
    }

    if (!RpdpEnumAndCacheModules(ProcessId, hProcess, &cache)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    found = FALSE;
    slot = RPD_MAX_CACHED_PIDS;
    AcquireSRWLockShared(&g_Rpd.Lock);
    for (i = 0; i < RPD_MAX_CACHED_PIDS; ++i) {
        if (g_Rpd.ModuleCache[i].Valid && g_Rpd.ModuleCache[i].ProcessId == ProcessId) {
            slot = i;
            break;
        }
    }
    if (slot != RPD_MAX_CACHED_PIDS &&
        (now - g_Rpd.ModuleCache[slot].Timestamp) < RPD_MODULE_CACHE_TTL_MS) {
        /* 其他线程已刷新缓存, 用之 */
        found = TRUE;
    }
    ReleaseSRWLockShared(&g_Rpd.Lock);

    if (!found) {
        /* 覆盖式写回 (并发下最后写者赢, 见上注释) */
        RpdpCacheSet(&cache, TRUE);
    }

    CloseHandle(hProcess);

    /* 直接在本次枚举结果 (或他人刷新的缓存) 中查找地址.
     * 若 found 则他人缓存与本次枚举内容等价 (同 PID 同模块集),
     * 统一查本地 cache 即可, 避免陷入 g_Rpd 表的双重查找。 */
    for (i = 0; i < cache.ModuleCount; ++i) {
        RPD_CACHED_MODULE* mod = &cache.Modules[i];
        if (Address >= mod->Base &&
            Address < (mod->Base + (UINT64)mod->Size) &&
            mod->Base != 0) {
            RpdpSanitizeW(OutName, DEF_MAX_IMAGE_NAME, mod->Name);
            *OutOffset = Address - mod->Base;
            return TRUE;
        }
    }
    return FALSE;
}

/**************************************************/
/*               内部辅助: 事件                    */
/**************************************************/

static RPD_EVENT
RpdpCreateEvent(
    _In_ ULONG               ProcessId,
    _In_ ULONG               ThreadId,
    _In_ RPD_DETECTION_METHOD Method,
    _In_ PCWSTR              Details
    )
{
    RPD_EVENT evt;
    ULONG     pid;
    ULONG     i;
    BOOLEAN   inTable;

    ZeroMemory(&evt, sizeof(evt));

    evt.EventId = (ULONG)InterlockedIncrement(&g_Rpd.NextEventId);
    evt.ProcessId = ProcessId;
    evt.ThreadId = ThreadId;
    evt.Method = Method;
    if (Details != NULL) {
        RpdpSanitizeW(evt.Details, 512, Details);
    }
    GetSystemTimeAsFileTime((LPFILETIME)&evt.Timestamp);

    /* 优先从受保护进程表取进程信息 (SS 缓存优先) */
    inTable = FALSE;
    AcquireSRWLockShared(&g_Rpd.Lock);
    for (i = 0; i < g_Rpd.ProcessCount; ++i) {
        pid = g_Rpd.Processes[i].ProcessId;
        if (pid == ProcessId) {
            RpdpSanitizeW(evt.ProcessName, DEF_MAX_IMAGE_NAME, g_Rpd.Processes[i].ProcessName);
            RpdpSanitizeW(evt.ProcessPath, DEF_MAX_PATH * 2, g_Rpd.Processes[i].ProcessPath);
            inTable = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(&g_Rpd.Lock);

    if (!inTable) {
        RpdpQueryProcessInfo(ProcessId, evt.ProcessName, evt.ProcessPath);
    }

    return evt;
}

/* 历史写入 + 回调上报 (SS NotifyRopDetected) */
static VOID
RpdpNotify(
    _In_ const RPD_EVENT* Event
    )
{
    RPD_DETECTED_CALLBACK cb;
    PVOID ctx;

    AcquireSRWLockExclusive(&g_Rpd.HistoryLock);

    if (g_Rpd.HistoryCount < RPD_HISTORY_CAPACITY) {
        g_Rpd.History[g_Rpd.HistoryCount] = *Event;
        g_Rpd.HistoryLast = g_Rpd.HistoryCount;
        ++g_Rpd.HistoryCount;
    } else {
        g_Rpd.History[g_Rpd.HistoryHead] = *Event;
        g_Rpd.HistoryLast = g_Rpd.HistoryHead;
        g_Rpd.HistoryHead = (g_Rpd.HistoryHead + 1) % RPD_HISTORY_CAPACITY;
    }

    ReleaseSRWLockExclusive(&g_Rpd.HistoryLock);

    AcquireSRWLockShared(&g_Rpd.CallbackLock);
    cb = g_Rpd.Callback;
    ctx = g_Rpd.CallbackContext;
    ReleaseSRWLockShared(&g_Rpd.CallbackLock);

    if (cb != NULL) {
        cb(Event, ctx);
    }
}

/* 置信度计算 (SS CalculateConfidence) */
static RPD_CONFIDENCE
RpdpComputeConfidence(
    _In_ const RPD_CHAIN_INFO* Chain
    )
{
    ULONG score = 0;

    if (Chain->ChainLength >= 10)      score += 3;
    else if (Chain->ChainLength >= 5)  score += 2;
    else if (Chain->ChainLength >= 3)  score += 1;

    if (Chain->UsesKnownSequence)       score += 2;
    if (Chain->SignatureMatch[0] != L'\0') score += 3;
    if (Chain->IsCompleteChain)         score += 1;

    if (score >= 7) return RpdConf_Confirmed;
    if (score >= 5) return RpdConf_VeryHigh;
    if (score >= 3) return RpdConf_High;
    if (score >= 2) return RpdConf_Medium;
    return RpdConf_Low;
}

/* 强制终止进程 (SS EnforceTermination, 退出码对齐 0xDEAD0001) */
static VOID
RpdpEnforceTermination(
    _In_ ULONG   ProcessId,
    _In_ PCWSTR  Reason,
    _Inout_ RPD_EVENT* Event
    )
{
    HANDLE hProcess;

    hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, ProcessId);
    if (hProcess != NULL) {
        if (TerminateProcess(hProcess, 0xDEAD0001)) {
            Event->ProcessTerminated = TRUE;
            Event->WasBlocked = TRUE;
            InterlockedIncrement(&g_Rpd.Stats.ProcessesTerminated);
            InterlockedIncrement(&g_Rpd.Stats.AttacksBlocked);
        }
        CloseHandle(hProcess);
    }
}

/**************************************************/
/*               内部辅助: CET 探测                 */
/**************************************************/

/* CPUID leaf 7 / subleaf 0 / ECX bit7 = CET_SS (SS 同款) */
static BOOLEAN
RpdpDetectCet(VOID)
{
    int cpuInfo[4];
    int maxLeaf;

    __cpuid(cpuInfo, 0);
    maxLeaf = cpuInfo[0];
    if (maxLeaf >= 7) {
        __cpuidex(cpuInfo, 7, 0);
        return ((cpuInfo[2] & (1 << 7)) != 0);
    }
    return FALSE;
}

/**************************************************/
/*               内部辅助: 线程影子栈               */
/**************************************************/

static VOID
RpdpStackAcquire(_In_ PRPD_THREAD_STACK Stack)
{
    EnterCriticalSection(&Stack->Cs);
}

static VOID
RpdpStackRelease(_In_ PRPD_THREAD_STACK Stack)
{
    LeaveCriticalSection(&Stack->Cs);
}

static PRPD_THREAD_STACK
RpdpFindStackLocked(_In_ ULONG ThreadId)
{
    ULONG i;
    for (i = 0; i < RPD_MAX_THREAD_STACK_SLOTS; ++i) {
        if (g_Rpd.ThreadStacks[i] != NULL &&
            g_Rpd.ThreadStacks[i]->ThreadId == ThreadId) {
            return g_Rpd.ThreadStacks[i];
        }
    }
    return NULL;
}

/* 取线程栈, 无则创建; 槽满复用 LastActivity 最旧槽.
 * SS 以 shared_ptr 防悬垂指针 UAF; C 静态化采用"延迟释放":
 * 淘汰仅重置槽位状态 (重复使用该槽指针与 Entries 缓冲),
 * 内存直至 Shutdown 才释放, 杜绝并发 Push 侧悬垂访问。 */
static PRPD_THREAD_STACK
RpdpGetOrCreateStack(_In_ ULONG ThreadId)
{
    PRPD_THREAD_STACK stack;
    ULONG  oldestIdx;
    ULONG  i;
    ULONGLONG oldestTick;
    BOOLEAN foundSlot;
    ULONG  need;

    stack = NULL;
    oldestIdx = 0;
    oldestTick = (ULONGLONG)-1;
    foundSlot = FALSE;
    need = g_Rpd.Config.MaxShadowStackDepth;

    if (need == 0 || need > RPD_MAX_SHADOW_STACK_ENTRIES) {
        need = RPD_MAX_SHADOW_STACK_ENTRIES;
    }

    AcquireSRWLockExclusive(&g_Rpd.ThreadStackLock);

    stack = RpdpFindStackLocked(ThreadId);
    if (stack != NULL) {
        ReleaseSRWLockExclusive(&g_Rpd.ThreadStackLock);
        return stack;
    }

    for (i = 0; i < RPD_MAX_THREAD_STACK_SLOTS; ++i) {
        if (g_Rpd.ThreadStacks[i] == NULL) {
            oldestIdx = i;
            foundSlot = TRUE;
            break;
        }
        if (g_Rpd.ThreadStacks[i]->LastActivity < oldestTick) {
            oldestTick = g_Rpd.ThreadStacks[i]->LastActivity;
            oldestIdx = i;
            foundSlot = TRUE;
        }
    }

    if (!foundSlot) {
        ReleaseSRWLockExclusive(&g_Rpd.ThreadStackLock);
        return NULL;
    }

    if (g_Rpd.ThreadStacks[oldestIdx] != NULL) {
        /* 复用槽位: 容量不足才重分配 Entries */
        PRPD_THREAD_STACK victim = g_Rpd.ThreadStacks[oldestIdx];

        if (victim->Capacity < need) {
            RPD_SS_ENTRY* newBuf = (RPD_SS_ENTRY*)LocalAlloc(
                LMEM_ZEROINIT, need * sizeof(RPD_SS_ENTRY));
            if (newBuf == NULL) {
                ReleaseSRWLockExclusive(&g_Rpd.ThreadStackLock);
                return NULL;
            }
            LocalFree(victim->Entries);
            victim->Entries = newBuf;
            victim->Capacity = need;
        }
        victim->ThreadId = ThreadId;
        victim->Depth = 0;
        victim->PushCount = 0;
        victim->PopCount = 0;
        victim->MismatchCount = 0;
        victim->LastActivity = GetTickCount64();
        stack = victim;
    } else {
        stack = (PRPD_THREAD_STACK)LocalAlloc(LMEM_ZEROINIT, sizeof(RPD_THREAD_STACK));
        if (stack == NULL) {
            ReleaseSRWLockExclusive(&g_Rpd.ThreadStackLock);
            return NULL;
        }
        stack->ThreadId = ThreadId;
        stack->Capacity = need;
        stack->Entries = (RPD_SS_ENTRY*)LocalAlloc(
            LMEM_ZEROINIT, stack->Capacity * sizeof(RPD_SS_ENTRY));
        if (stack->Entries == NULL) {
            LocalFree(stack);
            ReleaseSRWLockExclusive(&g_Rpd.ThreadStackLock);
            return NULL;
        }
        stack->LastActivity = GetTickCount64();
        InitializeCriticalSection(&stack->Cs);
        g_Rpd.ThreadStacks[oldestIdx] = stack;
    }

    ReleaseSRWLockExclusive(&g_Rpd.ThreadStackLock);
    return stack;
}

static PRPD_THREAD_STACK
RpdpGetStack(_In_ ULONG ThreadId)
{
    PRPD_THREAD_STACK stack;

    AcquireSRWLockShared(&g_Rpd.ThreadStackLock);
    stack = RpdpFindStackLocked(ThreadId);
    ReleaseSRWLockShared(&g_Rpd.ThreadStackLock);
    return stack;
}

/**************************************************/
/*               内部辅助: Gadget                  */
/**************************************************/

/* 已知模式匹配 (SS ContainsGadgetPattern) */
static BOOLEAN
RpdpContainsGadgetPattern(
    _In_reads_(ByteCount) const UCHAR* Data,
    _In_                        ULONG   ByteCount
    )
{
    ULONG p;
    ULONG i;

    if (Data == NULL || ByteCount < 2) {
        return FALSE;
    }

    for (p = 0; p < RPD_GADGET_PATTERN_COUNT; ++p) {
        const RPD_GADGET_PATTERN* pat = &g_RopGadgetPatterns[p];
        ULONG patLen = pat->Length;

        if (patLen == 0 || patLen > ByteCount) {
            continue;
        }
        for (i = 0; i <= ByteCount - patLen; ++i) {
            if (memcmp(&Data[i], pat->Bytes, patLen) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

/* 计数潜在 gadget (有进程句柄版, SS CountPotentialGadgets HANDLE 重载) */
static ULONG
RpdpCountPotentialGadgets(
    _In_ HANDLE                                   hProcess,
    _In_reads_(ByteCount) const UCHAR*            StackData,
    _In_                               ULONG      ByteCount
    )
{
    UINT64  unique[RPD_MAX_UNIQUE_GADGETS];
    ULONG   uniqueCount;
    ULONG   count;
    ULONG   i;
    SIZE_T  bytesRead;
    UCHAR   codeBuf[RPD_GADGET_SCAN_DEPTH];
    BOOLEAN foundRet;
    ULONG   j;
    SIZE_T  k;
    BOOLEAN already;

    count = 0;
    uniqueCount = 0;

    for (i = 0; (i + sizeof(UINT64)) <= ByteCount; i += sizeof(UINT64)) {
        UINT64 addr = 0;

        memcpy(&addr, &StackData[i], sizeof(UINT64));

        if (addr == 0 || addr < 0x10000) {
            continue;
        }
#ifdef _WIN64
        if (addr > 0x00007FFFFFFFFFFFULL) {
            continue;
        }
#endif
        if (!RpdpIsReadableExecutableRegion(hProcess, addr, 1)) {
            continue;
        }

        bytesRead = 0;
        ZeroMemory(codeBuf, sizeof(codeBuf));
        if (!ReadProcessMemory(hProcess, (LPCVOID)(UINT_PTR)addr,
                               codeBuf, sizeof(codeBuf), &bytesRead)) {
            continue;
        }
        if (bytesRead < 1) {
            continue;
        }

        foundRet = FALSE;
        for (k = 0; k < bytesRead; ++k) {
            if (codeBuf[k] == RPD_RET_OPCODE || codeBuf[k] == RPD_RETN_OPCODE) {
                foundRet = TRUE;
                break;
            }
        }
        if (!foundRet) {
            continue;
        }

        if (RpdpContainsGadgetPattern(codeBuf, (ULONG)bytesRead) || foundRet) {
            /* 去重 (SS unordered_set; 数组上限 256, 超限仅计数) */
            already = FALSE;
            for (j = 0; j < uniqueCount; ++j) {
                if (unique[j] == addr) {
                    already = TRUE;
                    break;
                }
            }
            if (!already) {
                if (uniqueCount < RPD_MAX_UNIQUE_GADGETS) {
                    unique[uniqueCount++] = addr;
                }
                ++count;
            }
        }
    }

    return count;
}

/* 识别 gadget (有进程句柄版, SS IdentifyGadgetWithHandle) */
static NTSTATUS
RpdpIdentifyGadgetWithHandle(
    _In_  HANDLE           hProcess,
    _In_  ULONG            ProcessId,
    _In_  UINT64           Address,
    _Out_ PRPD_GADGET_INFO OutInfo
    )
{
    UCHAR   bytes[RPD_GADGET_SCAN_DEPTH];
    SIZE_T  bytesRead;
    SIZE_T  i;
    SIZE_T  retOffset;
    BOOLEAN foundRet;
    RPD_GADGET_TYPE type;
    WCHAR   modName[DEF_MAX_IMAGE_NAME];
    UINT64  modOffset;

    if (OutInfo == NULL || !RpdpIsReadableExecutableRegion(hProcess, Address, 1)) {
        return STATUS_INVALID_PARAMETER;
    }

    ZeroMemory(bytes, sizeof(bytes));
    bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(UINT_PTR)Address,
                           bytes, sizeof(bytes), &bytesRead)) {
        return STATUS_NOT_FOUND;
    }
    if (bytesRead < 2) {
        return STATUS_NOT_FOUND;
    }

    /* 查找 RET 系列操作码并确定 gadget 类型 */
    retOffset = 0;
    foundRet = FALSE;
    type = RpdGadget_Unknown;

    for (i = 0; i < bytesRead; ++i) {
        if (bytes[i] == RPD_RET_OPCODE) {
            retOffset = i;
            type = RpdGadget_Ret;
            foundRet = TRUE;
            break;
        } else if (bytes[i] == RPD_RETN_OPCODE && (i + 1 + sizeof(USHORT)) <= bytesRead) {
            retOffset = i;
            type = RpdGadget_RetN;
            foundRet = TRUE;
            break;
        } else if (bytes[i] == RPD_RETF_OPCODE) {
            retOffset = i;
            type = RpdGadget_Ret;
            foundRet = TRUE;
            break;
        } else if (bytes[i] == RPD_RETFN_OPCODE && (i + 1 + sizeof(USHORT)) <= bytesRead) {
            retOffset = i;
            type = RpdGadget_RetN;
            foundRet = TRUE;
            break;
        }
    }

    if (!foundRet) {
        return STATUS_NOT_FOUND;
    }

    ZeroMemory(OutInfo, sizeof(*OutInfo));
    OutInfo->Address = Address;
    OutInfo->Type = type;
    OutInfo->Length = (ULONG)(retOffset + 1);
    OutInfo->IsAslrDependent = TRUE;

    if (OutInfo->Length > sizeof(OutInfo->GadgetBytes)) {
        OutInfo->Length = (ULONG)sizeof(OutInfo->GadgetBytes);
    }
    memcpy(OutInfo->GadgetBytes, bytes, OutInfo->Length);
    OutInfo->ByteCount = (UCHAR)OutInfo->Length;

    /* RET N 栈调整值 */
    if (type == RpdGadget_RetN && (retOffset + 1 + sizeof(USHORT)) <= bytesRead) {
        USHORT imm = 0;
        memcpy(&imm, &bytes[retOffset + 1], sizeof(imm));
        OutInfo->StackAdjustment = imm;
    }

    /* 模块归属 */
    modName[0] = L'\0';
    modOffset = 0;
    if (RpdpGetModuleForAddress(ProcessId, Address, modName, &modOffset)) {
        RpdpSanitizeW(OutInfo->ModuleName, DEF_MAX_IMAGE_NAME, modName);
        OutInfo->ModuleOffset = modOffset;
        OutInfo->IsAslrDependent = (modOffset != 0);
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*               内部辅助: 反汇编                  */
/**************************************************/

/* 追加一行反汇编输出 (SS 每指令 oss.str()) */
static VOID
RpdpAsmAppendLine(
    _Out_writes_(BufChars) PCHAR   Out,
    _In_                   ULONG   BufChars,
    _Inout_                PULONG  pOffset,
    _In_                   PCSTR   Line
    )
{
    ULONG off = *pOffset;
    if (off >= BufChars) {
        return;
    }
    _snprintf_s(Out + off, BufChars - off, _TRUNCATE, "%s\r\n", Line);
    *pOffset = off + (ULONG)strlen(Out + off);
}

/* 简单 x64 反汇编器 (DisassembleGadget 支持子集) */
static VOID
RpdpDisassemble(
    _In_reads_(ByteCount) const UCHAR* Bytes,
    _In_                          ULONG   ByteCount,
    _In_                          UINT64  BaseAddress,
    _Out_writes_(BufChars)        PCHAR   Out,
    _In_                          ULONG   BufChars
    )
{
    static const char* s_Regs32[]  = { "EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI" };
    static const char* s_Regs64[]  = { "RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI" };
    static const char* s_RegsR8[]  = { "R8", "R9", "R10","R11","R12","R13","R14","R15" };
    static const char* s_ArithOps[]= { "ADD","OR","ADC","SBB","AND","SUB","XOR","CMP" };

    ULONG   i;
    ULONG   off;
    char    line[128];

    off = 0;

    if (Bytes == NULL || BufChars == 0) {
        return;
    }
    if (ByteCount == 0) {
        Out[0] = '\0';
        return;
    }

    for (i = 0; i < ByteCount; ) {
        UCHAR  b = Bytes[i];
        BOOLEAN rexW = FALSE;
        BOOLEAN rexB = FALSE;
        int    reg;
        UINT64 disp;

        _snprintf_s(line, sizeof(line), _TRUNCATE, "0x%016I64X: ",
                    (UINT64)(BaseAddress + (UINT64)i));

        /* REX 前缀 (0x40-0x4F) */
        if ((b & 0xF0) == 0x40 && (i + 1) < ByteCount) {
            rexW = ((b >> 3) & 1U) != 0;
            rexB = ((b >> 0) & 1U) != 0;
            ++i;
            if (i >= ByteCount) {
                strcat_s(line, sizeof(line), "REX prefix (truncated)");
                RpdpAsmAppendLine(Out, BufChars, &off, line);
                break;
            }
            b = Bytes[i];
        }

        if (b >= 0x58 && b <= 0x5F) {           /* POP r64/r32 (58+rd) */
            reg = b - 0x58;
            if (rexB) {
                _snprintf_s(line, sizeof(line), _TRUNCATE, "%sPOP %s",
                            line, s_RegsR8[reg]);
            } else {
                _snprintf_s(line, sizeof(line), _TRUNCATE, "%sPOP %s",
                            line, rexW ? s_Regs64[reg] : s_Regs32[reg]);
            }
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            ++i;
            continue;
        }
        if (b >= 0x50 && b <= 0x57) {           /* PUSH r64 (50+rd) */
            _snprintf_s(line, sizeof(line), _TRUNCATE, "%sPUSH %s",
                        line, s_Regs64[b - 0x50]);
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            ++i;
            continue;
        }
        if (b == 0xC3) {                        /* RET */
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            break;
        }
        if (b == 0xC2 && (i + 1 + sizeof(USHORT)) <= ByteCount) {   /* RET imm16 */
            USHORT imm;
            memcpy(&imm, &Bytes[i + 1], sizeof(imm));
            _snprintf_s(line, sizeof(line), _TRUNCATE, "%sRET 0x%X", line, imm);
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            break;
        }
        if (b == 0xCB) {                        /* RETF */
            strcat_s(line, sizeof(line), "RETF");
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            break;
        }
        if (b == 0xCA && (i + 1 + sizeof(USHORT)) <= ByteCount) {   /* RETF imm16 */
            USHORT imm;
            memcpy(&imm, &Bytes[i + 1], sizeof(imm));
            _snprintf_s(line, sizeof(line), _TRUNCATE, "%sRETF 0x%X", line, imm);
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            break;
        }
        if (b == 0x90) {                        /* NOP */
            strcat_s(line, sizeof(line), "NOP");
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            ++i;
            continue;
        }
        if (b >= 0x91 && b <= 0x97) {           /* XCHG EAX/RAX, reg */
            _snprintf_s(line, sizeof(line), _TRUNCATE, "%sXCHG %s, %s",
                        line, rexW ? "RAX" : "EAX", s_Regs32[b - 0x91]);
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            ++i;
            continue;
        }
        if (b == 0x83 && (i + 2) < ByteCount) { /* 83 /x ib */
            UCHAR modrm = Bytes[i + 1];
            int   opIdx = (modrm >> 3) & 7;
            _snprintf_s(line, sizeof(line), _TRUNCATE,
                        "%s%s [ModRM=0x%X], 0x%X",
                        line, s_ArithOps[opIdx], modrm, Bytes[i + 2]);
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            i += 3;
            continue;
        }
        if (b >= 0x88 && b <= 0x8B && (i + 1) < ByteCount) {        /* MOV */
            _snprintf_s(line, sizeof(line), _TRUNCATE, "%sMOV [ModRM=0x%X]",
                        line, Bytes[i + 1]);
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            i += 2;
            continue;
        }
        if (b == 0xEB && (i + 1) < ByteCount) { /* JMP short */
            CHAR rel = (CHAR)Bytes[i + 1];
            _snprintf_s(line, sizeof(line), _TRUNCATE, "%sJMP SHORT +0x%X",
                        line, (UINT)(rel + 2));
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            i += 2;
            continue;
        }
        if (b == 0xE9 && (i + 4) < ByteCount) { /* JMP near */
            LONG rel;
            memcpy(&rel, &Bytes[i + 1], sizeof(rel));
            disp = (UINT64)(rel + 5);
            _snprintf_s(line, sizeof(line), _TRUNCATE, "%sJMP NEAR +0x%X",
                        line, (UINT32)disp);
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            i += 5;
            continue;
        }
        if (b == 0xE8 && (i + 4) < ByteCount) { /* CALL near */
            LONG rel;
            memcpy(&rel, &Bytes[i + 1], sizeof(rel));
            disp = (UINT64)(rel + 5);
            _snprintf_s(line, sizeof(line), _TRUNCATE, "%sCALL NEAR +0x%X",
                        line, (UINT32)disp);
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            i += 5;
            continue;
        }
        if (b == 0xFF && (i + 1) < ByteCount) { /* FF /4 JMP /2 CALL /6 PUSH */
            UCHAR modrm = Bytes[i + 1];
            int   regOp = (modrm >> 3) & 7;
            if (regOp == 4) {
                _snprintf_s(line, sizeof(line), _TRUNCATE, "%sJMP  %s",
                            line, s_Regs64[modrm & 7]);
            } else if (regOp == 2) {
                _snprintf_s(line, sizeof(line), _TRUNCATE, "%sCALL %s",
                            line, s_Regs64[modrm & 7]);
            } else if (regOp == 6) {
                _snprintf_s(line, sizeof(line), _TRUNCATE, "%sPUSH %s",
                            line, s_Regs64[modrm & 7]);
            } else {
                _snprintf_s(line, sizeof(line), _TRUNCATE, "%sFF /0x%X [ModRM=0x%X]",
                            line, regOp, modrm);
            }
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            i += 2;
            continue;
        }
        if (b == 0x0F && (i + 1) < ByteCount && Bytes[i + 1] == 0x05) { /* SYSCALL */
            strcat_s(line, sizeof(line), "SYSCALL");
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            i += 2;
            continue;
        }
        if (b == 0xCD && (i + 1) < ByteCount) { /* INT n */
            _snprintf_s(line, sizeof(line), _TRUNCATE, "%sINT 0x%X",
                        line, Bytes[i + 1]);
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            i += 2;
            continue;
        }
        if (b == 0xC9) {                        /* LEAVE */
            strcat_s(line, sizeof(line), "LEAVE");
            RpdpAsmAppendLine(Out, BufChars, &off, line);
            ++i;
            continue;
        }

        /* 未知: 输出 DB 伪指令 */
        _snprintf_s(line, sizeof(line), _TRUNCATE, "%sDB 0x%02X", line, b);
        RpdpAsmAppendLine(Out, BufChars, &off, line);
        ++i;
    }

    if (off == 0) {
        Out[0] = '\0';
    }
}

/**************************************************/
/*               生命周期                           */
/**************************************************/

NTSTATUS
RpdInitialize(
    _In_opt_ const RPD_CONFIG* Config
    )
{
    RPD_CONFIG cfg;
    ULONG i;

    if (Config != NULL) {
        cfg = *Config;
    } else {
        cfg = RPD_DEFAULT_CONFIG;
    }

    /* 配置合法性 (SS IsValid: 深度非 0 且不超上限) */
    if (cfg.MaxShadowStackDepth == 0 ||
        cfg.MaxShadowStackDepth > RPD_MAX_SHADOW_STACK_ENTRIES) {
        return STATUS_INVALID_PARAMETER;
    }

    AcquireSRWLockExclusive(&g_Rpd.Lock);

    if (g_Rpd.Initialized) {
        ReleaseSRWLockExclusive(&g_Rpd.Lock);
        return STATUS_SUCCESS;      /* SS: 重复初始化视为成功 */
    }

    g_Rpd.Status = RpdStatus_Initializing;
    g_Rpd.Config = cfg;
    g_Rpd.CetAvailable = RpdpDetectCet();

    /* 默认受保护 API 表 (SS Initialize 内联填充, 避免锁序).
     * 数量由表本身推导, 避免硬编码与头文件维护脱节。 */
    #define RPD_DEFAULT_API_COUNT \
        ((ULONG)(sizeof(g_DefaultProtectedApis) / sizeof(g_DefaultProtectedApis[0])))

    AcquireSRWLockExclusive(&g_Rpd.ApiLock);
    g_Rpd.ApiCount = 0;
    for (i = 0; i < RPD_MAX_PROTECTED_APIS && i < RPD_DEFAULT_API_COUNT; ++i) {
        RPD_PROTECTED_API_INFO* info = &g_Rpd.Apis[g_Rpd.ApiCount];
        strncpy_s(info->ApiName, sizeof(info->ApiName), g_DefaultProtectedApis[i].Name, _TRUNCATE);
        info->Category = g_DefaultProtectedApis[i].Category;
        info->IsHooked = FALSE;
        ++g_Rpd.ApiCount;
    }
    ReleaseSRWLockExclusive(&g_Rpd.ApiLock);

    /* 统计与 ID 复位 */
    ZeroMemory(&g_Rpd.Stats, sizeof(g_Rpd.Stats));
    g_Rpd.StartTick = GetTickCount64();
    g_Rpd.NextEventId = 0;
    g_Rpd.NextChainId = 0;

    g_Rpd.Initialized = TRUE;
    g_Rpd.Status = RpdStatus_Running;

    ReleaseSRWLockExclusive(&g_Rpd.Lock);
    return STATUS_SUCCESS;
}

VOID
RpdShutdown(VOID)
{
    ULONG i;

    AcquireSRWLockExclusive(&g_Rpd.Lock);

    if (!g_Rpd.Initialized) {
        ReleaseSRWLockExclusive(&g_Rpd.Lock);
        return;
    }

    g_Rpd.Status = RpdStatus_Stopping;

    /* 释放线程影子栈 */
    AcquireSRWLockExclusive(&g_Rpd.ThreadStackLock);
    for (i = 0; i < RPD_MAX_THREAD_STACK_SLOTS; ++i) {
        if (g_Rpd.ThreadStacks[i] != NULL) {
            DeleteCriticalSection(&g_Rpd.ThreadStacks[i]->Cs);
            if (g_Rpd.ThreadStacks[i]->Entries != NULL) {
                LocalFree(g_Rpd.ThreadStacks[i]->Entries);
            }
            LocalFree(g_Rpd.ThreadStacks[i]);
            g_Rpd.ThreadStacks[i] = NULL;
        }
    }
    ReleaseSRWLockExclusive(&g_Rpd.ThreadStackLock);

    /* 清空进程保护表 / API 表 */
    g_Rpd.ProcessCount = 0;
    AcquireSRWLockExclusive(&g_Rpd.ApiLock);
    g_Rpd.ApiCount = 0;
    ReleaseSRWLockExclusive(&g_Rpd.ApiLock);

    /* 清回调 */
    AcquireSRWLockExclusive(&g_Rpd.CallbackLock);
    g_Rpd.Callback = NULL;
    g_Rpd.CallbackContext = NULL;
    ReleaseSRWLockExclusive(&g_Rpd.CallbackLock);

    /* 模块缓存复位 */
    ZeroMemory(g_Rpd.ModuleCache, sizeof(g_Rpd.ModuleCache));

    g_Rpd.Initialized = FALSE;
    g_Rpd.Status = RpdStatus_Stopped;

    ReleaseSRWLockExclusive(&g_Rpd.Lock);
}

BOOLEAN
RpdIsInitialized(VOID)
{
    return g_Rpd.Initialized;
}

RPD_STATUS
RpdGetStatus(VOID)
{
    return g_Rpd.Status;
}

PCSTR
RpdGetVersionString(VOID)
{
    return "3.0.0";
}

/**************************************************/
/*               API 保护                          */
/**************************************************/

/* 查 API 表索引 (-1 = 未保护) */
static LONG
RpdpFindApi(_In_ PCSTR ApiName)
{
    ULONG i;

    if (ApiName == NULL) {
        return -1;
    }
    for (i = 0; i < g_Rpd.ApiCount; ++i) {
        if (_stricmp(g_Rpd.Apis[i].ApiName, ApiName) == 0) {
            return (LONG)i;
        }
    }
    return -1;
}

BOOLEAN
RpdValidateApiCall(
    _In_ UINT64 ReturnAddress
    )
{
    BOOLEAN result;
    MEMORY_BASIC_INFORMATION mbi;
    UINT64 regionBase;

    result = FALSE;

    if (!g_Rpd.Initialized) {
        return TRUE;        /* SS: 未初始化放行 */
    }
    if (g_Rpd.Status == RpdStatus_Paused) {
        return TRUE;
    }

    InterlockedIncrement(&g_Rpd.Stats.ApiCallsValidated);

    __try {
        /* 拒绝保留区/零地址 */
        if (ReturnAddress == 0 || ReturnAddress < 0x10000) {
            InterlockedIncrement(&g_Rpd.Stats.ByMethod[RpdMethod_ReturnAddressInvalid]);
            return FALSE;
        }
#ifdef _WIN64
        /* 拒绝内核区地址 */
        if (ReturnAddress > 0x00007FFFFFFFFFFFULL) {
            InterlockedIncrement(&g_Rpd.Stats.ByMethod[RpdMethod_ReturnAddressInvalid]);
            return FALSE;
        }
#endif
        /* 目标须为已提交可执行内存 */
        ZeroMemory(&mbi, sizeof(mbi));
        if (VirtualQuery((LPCVOID)(UINT_PTR)ReturnAddress, &mbi, sizeof(mbi)) == 0) {
            InterlockedIncrement(&g_Rpd.Stats.ByMethod[RpdMethod_ReturnAddressInvalid]);
            return FALSE;
        }
        if (mbi.State != MEM_COMMIT) {
            InterlockedIncrement(&g_Rpd.Stats.ByMethod[RpdMethod_ReturnAddressInvalid]);
            return FALSE;
        }
        if (!RpdpIsExecutableProtection(mbi.Protect)) {
            InterlockedIncrement(&g_Rpd.Stats.ByMethod[RpdMethod_ReturnAddressInvalid]);
            return FALSE;
        }
        /* RWX 可疑但仅标记 (JIT 合法使用, 不硬拦) */
        if (mbi.Protect == PAGE_EXECUTE_READWRITE) {
            InterlockedIncrement(&g_Rpd.Stats.ByMethod[RpdMethod_ReturnAddressInvalid]);
        }
        /* 前导 CALL 编码探测 (SS: 非 CALL 返回点计入 CallRetMismatch) */
        regionBase = (UINT64)(UINT_PTR)mbi.BaseAddress;
        if (!RpdpHasCallSite(ReturnAddress, regionBase) &&
            g_Rpd.Config.EnableApiReturnValidation) {
            InterlockedIncrement(&g_Rpd.Stats.ByMethod[RpdMethod_CallRetMismatch]);
        }
        result = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result = FALSE;     /* 异常失败关闭 (SS fail-closed) */
    }

    return result;
}

BOOLEAN
RpdValidateApiCallEx(
    _In_ UINT64  ReturnAddress,
    _In_ PCSTR   ApiName,
    _In_ ULONG   ProcessId,
    _In_ ULONG   ThreadId
    )
{
    BOOLEAN isProtected;
    BOOLEAN isValid;
    LONG    idx;
    RPD_EVENT evt;
    PRPD_THREAD_STACK stack;
    UINT64 diff;
    WCHAR  apiNameW[64];

    if (!g_Rpd.Initialized) {
        return TRUE;
    }
    if (g_Rpd.Status == RpdStatus_Paused) {
        return TRUE;
    }

    InterlockedIncrement(&g_Rpd.Stats.ApiCallsValidated);

    /* 查受保护表 */
    isProtected = FALSE;
    idx = RpdpFindApi(ApiName);
    if (idx >= 0) {
        isProtected = TRUE;
        AcquireSRWLockExclusive(&g_Rpd.ApiLock);
        if (idx < (LONG)g_Rpd.ApiCount) {
            ++g_Rpd.Apis[idx].CallCount;
        }
        ReleaseSRWLockExclusive(&g_Rpd.ApiLock);
    }

    isValid = RpdValidateApiCall(ReturnAddress);

    /* 受保护 API + 受保护进程的附加校验 */
    if (isProtected && RpdIsProcessProtected(ProcessId)) {
        if (g_Rpd.Config.EnableShadowStack) {
            stack = RpdpGetStack(ThreadId);
            if (stack != NULL) {
                RpdpStackAcquire(stack);
                if (stack->Depth > 0) {
                    RPD_SS_ENTRY* top = &stack->Entries[stack->Depth - 1];
                    diff = (ReturnAddress > top->ReturnAddress)
                        ? (ReturnAddress - top->ReturnAddress)
                        : (top->ReturnAddress - ReturnAddress);
                    if (diff > RPD_SHADOW_STACK_TOLERANCE) {
                        InterlockedIncrement(&g_Rpd.Stats.ShadowStackMismatches);

                        MultiByteToWideChar(CP_ACP, 0, ApiName, -1, apiNameW, 64);
                        evt = RpdpCreateEvent(ProcessId, ThreadId,
                            RpdMethod_ShadowStackMismatch,
                            L"API call with mismatched return address");
                        RpdpSanitizeW(evt.ApiFunction, 64, apiNameW);
                        evt.ExpectedReturn = top->ReturnAddress;
                        evt.ActualReturn = ReturnAddress;
                        evt.Confidence = RpdConf_High;
                        evt.ConfidenceScore = RPD_CONFIDENCE_SCORE(RpdConf_High);

                        RpdpNotify(&evt);

                        if (g_Rpd.Config.BlockOnDetection) {
                            isValid = FALSE;
                            InterlockedIncrement(&g_Rpd.Stats.AttacksBlocked);
                            evt.WasBlocked = TRUE;
                        }
                    }
                }
                RpdpStackRelease(stack);
            }
        }

        /* 返回地址须位于可执行模块内 */
        if (isValid) {
            WCHAR  modName[DEF_MAX_IMAGE_NAME];
            UINT64 modOffset;
            if (!RpdpGetModuleForAddress(ProcessId, ReturnAddress, modName, &modOffset)) {
                MultiByteToWideChar(CP_ACP, 0, ApiName, -1, apiNameW, 64);
                evt = RpdpCreateEvent(ProcessId, ThreadId,
                    RpdMethod_ReturnAddressInvalid,
                    L"API call with invalid return address");
                RpdpSanitizeW(evt.ApiFunction, 64, apiNameW);
                evt.ActualReturn = ReturnAddress;
                evt.Confidence = RpdConf_Medium;
                evt.ConfidenceScore = RPD_CONFIDENCE_SCORE(RpdConf_Medium);

                RpdpNotify(&evt);

                if (g_Rpd.Config.BlockOnDetection) {
                    isValid = FALSE;
                    InterlockedIncrement(&g_Rpd.Stats.AttacksBlocked);
                }
            }
        }
    }

    return isValid;
}

NTSTATUS
RpdProtectApi(
    _In_ PCSTR           ApiName,
    _In_ RPD_API_CATEGORY Category
    )
{
    RPD_PROTECTED_API_INFO* info;
    NTSTATUS status;

    status = STATUS_SUCCESS;

    if (ApiName == NULL || ApiName[0] == '\0') {
        return STATUS_INVALID_PARAMETER;
    }

    AcquireSRWLockExclusive(&g_Rpd.ApiLock);

    if (RpdpFindApi(ApiName) >= 0) {
        /* 已保护: 更新分类 */
        LONG idx = RpdpFindApi(ApiName);
        g_Rpd.Apis[idx].Category = Category;
        goto done;
    }
    if (g_Rpd.ApiCount >= RPD_MAX_PROTECTED_APIS) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    info = &g_Rpd.Apis[g_Rpd.ApiCount];
    ZeroMemory(info, sizeof(*info));
    strncpy_s(info->ApiName, sizeof(info->ApiName), ApiName, _TRUNCATE);
    info->Category = Category;
    info->IsHooked = FALSE;
    ++g_Rpd.ApiCount;

done:
    ReleaseSRWLockExclusive(&g_Rpd.ApiLock);
    return status;
}

VOID
RpdUnprotectApi(
    _In_ PCSTR ApiName
    )
{
    LONG idx;

    if (ApiName == NULL) {
        return;
    }

    AcquireSRWLockExclusive(&g_Rpd.ApiLock);
    idx = RpdpFindApi(ApiName);
    if (idx >= 0) {
        /* 尾元素填补空缺 */
        if ((ULONG)idx < g_Rpd.ApiCount - 1) {
            memcpy(&g_Rpd.Apis[idx], &g_Rpd.Apis[g_Rpd.ApiCount - 1],
                   sizeof(RPD_PROTECTED_API_INFO));
        }
        --g_Rpd.ApiCount;
    }
    ReleaseSRWLockExclusive(&g_Rpd.ApiLock);
}

ULONG
RpdGetProtectedApis(
    _Out_writes_to_opt_(MaxInfos, *pReturned) PRPD_PROTECTED_API_INFO Infos,
    _In_                               ULONG                   MaxInfos,
    _Out_opt_                          PULONG                  pReturned
    )
{
    ULONG take;
    ULONG i;

    if (pReturned != NULL) {
        *pReturned = 0;
    }
    if (Infos == NULL || MaxInfos == 0) {
        /* 计数路径也加共享锁, 避免与其他线程 ProtectApi/UnprotectApi
         * 并发编辑 ApiCount 时读到半更新值 (SelfTest 等会依赖此计数) */
        ULONG count;
        AcquireSRWLockShared(&g_Rpd.ApiLock);
        count = g_Rpd.ApiCount;
        ReleaseSRWLockShared(&g_Rpd.ApiLock);
        return count;
    }

    AcquireSRWLockShared(&g_Rpd.ApiLock);

    take = (g_Rpd.ApiCount < MaxInfos) ? g_Rpd.ApiCount : MaxInfos;
    for (i = 0; i < take; ++i) {
        Infos[i] = g_Rpd.Apis[i];
    }
    if (pReturned != NULL) {
        *pReturned = take;
    }

    ReleaseSRWLockShared(&g_Rpd.ApiLock);
    return take;
}

/**************************************************/
/*               影子栈                            */
/**************************************************/

VOID
RpdShadowStackPush(
    _In_ ULONG   ThreadId,
    _In_ UINT64  ReturnAddress,
    _In_ UINT64  CallSite
    )
{
    PRPD_THREAD_STACK stack;

    if (!g_Rpd.Initialized || !g_Rpd.Config.EnableShadowStack) {
        return;
    }

    stack = RpdpGetOrCreateStack(ThreadId);
    if (stack == NULL) {
        return;
    }

    RpdpStackAcquire(stack);

    if (stack->Depth >= stack->Capacity) {
        /* 满: 丢弃最老 (SS deque pop_front) */
        if (stack->Depth > 1) {
            memmove(&stack->Entries[0], &stack->Entries[1],
                    (stack->Depth - 1) * sizeof(RPD_SS_ENTRY));
        }
        stack->Depth = stack->Capacity - 1;
    }

    stack->Entries[stack->Depth].ReturnAddress = ReturnAddress;
    stack->Entries[stack->Depth].CallSite = CallSite;
    stack->Entries[stack->Depth].Timestamp = GetTickCount64();
    ++stack->Depth;

    ++stack->PushCount;
    stack->LastActivity = GetTickCount64();

    RpdpStackRelease(stack);

    InterlockedIncrement(&g_Rpd.Stats.ShadowStackPushes);
}

BOOLEAN
RpdShadowStackPop(
    _In_ ULONG  ThreadId,
    _In_ UINT64 ExpectedReturn
    )
{
    PRPD_THREAD_STACK stack;
    BOOLEAN match;

    if (!g_Rpd.Initialized || !g_Rpd.Config.EnableShadowStack) {
        return TRUE;
    }

    stack = RpdpGetStack(ThreadId);
    if (stack == NULL) {
        return TRUE;        /* SS: 下溢放行 */
    }

    match = TRUE;
    RpdpStackAcquire(stack);

    if (stack->Depth == 0) {
        RpdpStackRelease(stack);
        return TRUE;        /* SS: 空栈放行 */
    }

    {
        RPD_SS_ENTRY* top = &stack->Entries[stack->Depth - 1];
        match = (top->ReturnAddress == ExpectedReturn);
        if (!match) {
            ++stack->MismatchCount;
            InterlockedIncrement(&g_Rpd.Stats.ShadowStackMismatches);
        }
        --stack->Depth;
    }

    ++stack->PopCount;
    stack->LastActivity = GetTickCount64();

    RpdpStackRelease(stack);

    InterlockedIncrement(&g_Rpd.Stats.ShadowStackPops);
    return match;
}

VOID
RpdShadowStackClear(
    _In_ ULONG ThreadId
    )
{
    PRPD_THREAD_STACK stack;

    stack = RpdpGetStack(ThreadId);
    if (stack == NULL) {
        return;
    }
    RpdpStackAcquire(stack);
    stack->Depth = 0;
    RpdpStackRelease(stack);
}

ULONG
RpdGetShadowStackDepth(
    _In_ ULONG ThreadId
    )
{
    PRPD_THREAD_STACK stack;
    ULONG depth;

    stack = RpdpGetStack(ThreadId);
    if (stack == NULL) {
        return 0;
    }
    RpdpStackAcquire(stack);
    depth = stack->Depth;
    RpdpStackRelease(stack);
    return depth;
}

/**************************************************/
/*               Gadget 分析                       */
/**************************************************/

ULONG
RpdScanStackForRop(
    _In_                               ULONG      ProcessId,
    _In_                               UINT64     StackPointer,
    _In_                               ULONG      ScanSize,
    _Out_writes_to_opt_(MaxEvents, *pReturned) PRPD_EVENT Events,
    _In_                               ULONG      MaxEvents,
    _Out_opt_                          PULONG     pReturned
    )
{
    UCHAR   stackData[RPD_MAX_STACK_SCAN_SIZE];
    ULONG   hitCount;
    ULONG   gadgetCount;
    SIZE_T  bytesRead;
    HANDLE  hProcess;
    RPD_CHAIN_INFO chain;
    RPD_GADGET_INFO gadgets[RPD_GADGET_SCAN_DEPTH];
    ULONG   gadgetN;
    RPD_EVENT evt;
    ULONG   eventsWritten;

    if (pReturned != NULL) {
        *pReturned = 0;
    }
    hitCount = 0;
    eventsWritten = 0;

    if (!g_Rpd.Initialized || !g_Rpd.Config.EnableGadgetScan) {
        return 0;
    }
    if (ScanSize == 0) {
        ScanSize = RPD_MAX_STACK_SCAN_SIZE;
    }
    if (ScanSize > RPD_MAX_STACK_SCAN_SIZE) {
        ScanSize = RPD_MAX_STACK_SCAN_SIZE;     /* SS: cap 8KB */
    }

    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (hProcess == NULL) {
        return 0;
    }

    ZeroMemory(stackData, sizeof(stackData));
    bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(UINT_PTR)StackPointer,
                           stackData, ScanSize, &bytesRead) || bytesRead < sizeof(UINT64)) {
        CloseHandle(hProcess);
        return 0;
    }

    gadgetCount = RpdpCountPotentialGadgets(hProcess, stackData, (ULONG)bytesRead);

    if (gadgetCount >= RPD_MIN_ROP_CHAIN_GADGETS) {
        ZeroMemory(&chain, sizeof(chain));
        ZeroMemory(gadgets, sizeof(gadgets));
        gadgetN = 0;

        /* SS 以 MAX_GADGET_CHAIN_LENGTH(256) 为上限收集链条;
         * 本模块调用侧缓冲为 RPD_GADGET_SCAN_DEPTH(32), 足以覆盖
         * 检测阈值(5)与完整链判定(3/4)及置信度打分, 故按缓冲上限
         * 收紧收集数量, 避免越界写。 */
        if (NT_SUCCESS(RpdAnalyzeRopChain(ProcessId, StackPointer,
                                          RPD_GADGET_SCAN_DEPTH,
                                          &chain, gadgets, &gadgetN))) {
            InterlockedIncrement(&g_Rpd.Stats.RopChainsDetected);
            if (chain.AttackType == RpdAttack_JOP) {
                InterlockedIncrement(&g_Rpd.Stats.JopChainsDetected);
            }

            evt = RpdpCreateEvent(ProcessId, 0, RpdMethod_HeuristicGadgetScan,
                                  L"ROP chain detected via stack scan");
            evt.StackPointer = StackPointer;
            evt.ChainStartAddress = chain.ChainStartAddress;
            evt.ChainLength = chain.ChainLength;
            evt.ChainTotalBytes = chain.TotalBytes;
            evt.AttackType = chain.AttackType;
            evt.IsCompleteChain = chain.IsCompleteChain;
            evt.UsesKnownSequence = chain.UsesKnownSequence;
            evt.Confidence = chain.Confidence;
            evt.ConfidenceScore = RPD_CONFIDENCE_SCORE(chain.Confidence);

            if (g_Rpd.Config.BlockOnDetection) {
                evt.WasBlocked = TRUE;
                InterlockedIncrement(&g_Rpd.Stats.AttacksBlocked);
            }
            if (g_Rpd.Config.TerminateOnConfirmed &&
                evt.Confidence == RpdConf_Confirmed) {
                RpdpEnforceTermination(ProcessId,
                                       L"Confirmed ROP chain via stack scan", &evt);
            }

            RpdpNotify(&evt);
            ++hitCount;

            /* 事件写调用方缓冲 */
            if (Events != NULL && eventsWritten < MaxEvents) {
                Events[eventsWritten++] = evt;
            }
        }
    }

    CloseHandle(hProcess);

    if (pReturned != NULL) {
        *pReturned = eventsWritten;
    }
    return hitCount;
}

NTSTATUS
RpdAnalyzeRopChain(
    _In_                               ULONG          ProcessId,
    _In_                               UINT64         ChainStart,
    _In_                               ULONG          MaxGadgets,
    _Out_                              PRPD_CHAIN_INFO  ChainInfo,
    _Out_writes_to_opt_(MaxGadgets, *pReturned) PRPD_GADGET_INFO Gadgets,
    _Out_opt_                          PULONG         pGadgetCount
    )
{
    HANDLE hProcess;
    UINT64 addresses[RPD_MAX_GADGET_CHAIN_LENGTH];
    ULONG  capped;
    SIZE_T bytesRead;
    SIZE_T addressCount;
    ULONG  i;
    ULONG  outCount;
    NTSTATUS status;

    if (pGadgetCount != NULL) {
        *pGadgetCount = 0;
    }
    if (ChainInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    ZeroMemory(ChainInfo, sizeof(*ChainInfo));

    capped = (MaxGadgets < RPD_MAX_GADGET_CHAIN_LENGTH) ? MaxGadgets : RPD_MAX_GADGET_CHAIN_LENGTH;
    if (capped == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (hProcess == NULL) {
        return STATUS_ACCESS_DENIED;
    }

    ZeroMemory(addresses, sizeof(addresses));
    bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(UINT_PTR)ChainStart,
                           addresses, capped * sizeof(UINT64), &bytesRead)) {
        CloseHandle(hProcess);
        return STATUS_NOT_FOUND;
    }

    addressCount = bytesRead / sizeof(UINT64);
    outCount = 0;
    status = STATUS_NOT_FOUND;

    for (i = 0; i < (ULONG)addressCount && outCount < capped; ++i) {
        UINT64 addr = addresses[i];
        RPD_GADGET_INFO gi;
        NTSTATUS st;

        if (addr == 0 || addr < 0x10000) {
            continue;
        }
#ifdef _WIN64
        if (addr > 0x00007FFFFFFFFFFFULL) {
            continue;
        }
#endif
        ZeroMemory(&gi, sizeof(gi));
        st = RpdpIdentifyGadgetWithHandle(hProcess, ProcessId, addr, &gi);
        if (NT_SUCCESS(st)) {
            if (Gadgets != NULL && outCount < MaxGadgets) {
                Gadgets[outCount] = gi;
            }
            ++outCount;
            ChainInfo->TotalBytes += gi.Length;
            InterlockedIncrement(&g_Rpd.Stats.GadgetsIdentified);
            status = STATUS_SUCCESS;
        }
    }

    ChainInfo->ChainId = (UINT64)InterlockedIncrement(&g_Rpd.NextChainId);
    ChainInfo->ChainStartAddress = ChainStart;
    ChainInfo->ChainLength = outCount;
    ChainInfo->AttackType = RpdAttack_ROP;
    ChainInfo->IsCompleteChain = (outCount >= RPD_MIN_COMPLETE_CHAIN_GADGETS);
    ChainInfo->Confidence = RpdpComputeConfidence(ChainInfo);

    if (pGadgetCount != NULL) {
        *pGadgetCount = outCount;
    }

    CloseHandle(hProcess);

    if (status == STATUS_SUCCESS && outCount == 0) {
        status = STATUS_NOT_FOUND;      /* 无实际 gadget */
    }
    return status;
}

NTSTATUS
RpdIdentifyGadget(
    _In_  ULONG          ProcessId,
    _In_  UINT64         Address,
    _Out_ PRPD_GADGET_INFO OutInfo
    )
{
    HANDLE   hProcess;
    NTSTATUS status;

    if (OutInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (hProcess == NULL) {
        return STATUS_ACCESS_DENIED;
    }

    status = RpdpIdentifyGadgetWithHandle(hProcess, ProcessId, Address, OutInfo);

    CloseHandle(hProcess);
    return status;
}

ULONG
RpdDisassembleGadget(
    _In_reads_(ByteCount) const UCHAR*  Bytes,
    _In_                          ULONG   ByteCount,
    _In_                          UINT64  BaseAddress,
    _Out_writes_(BufChars)        PCHAR   Out,
    _In_                          ULONG   BufChars
    )
{
    if (Out == NULL || BufChars == 0) {
        return 0;
    }
    Out[0] = '\0';
    if (Bytes == NULL || ByteCount == 0) {
        return 0;
    }

    RpdpDisassemble(Bytes, ByteCount, BaseAddress, Out, BufChars);
    return (ULONG)strlen(Out);
}

/**************************************************/
/*               进程保护                           */
/**************************************************/

static LONG
RpdpFindProcess(_In_ ULONG ProcessId)
{
    ULONG i;
    for (i = 0; i < g_Rpd.ProcessCount; ++i) {
        if (g_Rpd.Processes[i].ProcessId == ProcessId) {
            return (LONG)i;
        }
    }
    return -1;
}

BOOLEAN
RpdProtectProcess(
    _In_ ULONG ProcessId
    )
{
    LONG idx;

    if (ProcessId == 0) {
        return FALSE;
    }

    AcquireSRWLockExclusive(&g_Rpd.Lock);

    idx = RpdpFindProcess(ProcessId);
    if (idx >= 0) {
        ReleaseSRWLockExclusive(&g_Rpd.Lock);
        return TRUE;        /* SS: 已保护视为成功 */
    }
    if (g_Rpd.ProcessCount >= RPD_MAX_PROTECTED_PROCESSES) {
        ReleaseSRWLockExclusive(&g_Rpd.Lock);
        return FALSE;
    }

    {
        RPD_PROTECTED_PROCESS* pp = &g_Rpd.Processes[g_Rpd.ProcessCount];
        pp->ProcessId = ProcessId;
        pp->CetEnabled = FALSE;
        RpdpQueryProcessInfo(ProcessId, pp->ProcessName, pp->ProcessPath);
        ++g_Rpd.ProcessCount;
    }

    ReleaseSRWLockExclusive(&g_Rpd.Lock);
    return TRUE;
}

VOID
RpdUnprotectProcess(
    _In_ ULONG ProcessId
    )
{
    LONG idx;

    AcquireSRWLockExclusive(&g_Rpd.Lock);
    idx = RpdpFindProcess(ProcessId);
    if (idx >= 0) {
        if ((ULONG)idx < g_Rpd.ProcessCount - 1) {
            memcpy(&g_Rpd.Processes[idx], &g_Rpd.Processes[g_Rpd.ProcessCount - 1],
                   sizeof(RPD_PROTECTED_PROCESS));
        }
        --g_Rpd.ProcessCount;
    }
    ReleaseSRWLockExclusive(&g_Rpd.Lock);
}

BOOLEAN
RpdIsProcessProtected(
    _In_ ULONG ProcessId
    )
{
    BOOLEAN result;

    AcquireSRWLockShared(&g_Rpd.Lock);
    result = (RpdpFindProcess(ProcessId) >= 0);
    ReleaseSRWLockShared(&g_Rpd.Lock);
    return result;
}

ULONG
RpdGetProtectedProcesses(
    _Out_writes_(MaxPids) PULONG Pids,
    _In_                  ULONG  MaxPids
    )
{
    ULONG take;
    ULONG i;

    if (Pids == NULL || MaxPids == 0) {
        return 0;
    }

    AcquireSRWLockShared(&g_Rpd.Lock);
    take = (g_Rpd.ProcessCount < MaxPids) ? g_Rpd.ProcessCount : MaxPids;
    for (i = 0; i < take; ++i) {
        Pids[i] = g_Rpd.Processes[i].ProcessId;
    }
    ReleaseSRWLockShared(&g_Rpd.Lock);
    return take;
}

/**************************************************/
/*               硬件特性 (CET)                    */
/**************************************************/

BOOLEAN
RpdIsHardwareCetAvailable(VOID)
{
    return g_Rpd.CetAvailable;
}

BOOLEAN
RpdIsHardwareCetEnabled(
    _In_ ULONG ProcessId
    )
{
    BOOLEAN enabled;
    LONG    idx;

    AcquireSRWLockShared(&g_Rpd.Lock);
    idx = RpdpFindProcess(ProcessId);
    enabled = (idx >= 0) ? g_Rpd.Processes[idx].CetEnabled : FALSE;
    ReleaseSRWLockShared(&g_Rpd.Lock);
    return enabled;
}

BOOLEAN
RpdEnableHardwareCet(
    _In_ ULONG ProcessId
    )
{
    typedef NTSTATUS (NTAPI* PFN_NT_SET_INFORMATION_PROCESS)(
        HANDLE ProcessHandle,
        ULONG  ProcessInformationClass,
        PVOID  ProcessInformation,
        ULONG  ProcessInformationLength);

    BOOLEAN result;
    LONG    idx;
    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY policy;
    HANDLE  hProcess;
    NTSTATUS status;
    PFN_NT_SET_INFORMATION_PROCESS pNtSIP;

    result = FALSE;
    pNtSIP = NULL;

    if (!RpdIsHardwareCetAvailable()) {
        return FALSE;
    }

    /* 若进程尚未登记保护, 先登记 */
    if (!RpdIsProcessProtected(ProcessId)) {
        RpdProtectProcess(ProcessId);
    }

    AcquireSRWLockExclusive(&g_Rpd.Lock);
    idx = RpdpFindProcess(ProcessId);
    if (idx < 0) {
        ReleaseSRWLockExclusive(&g_Rpd.Lock);
        return FALSE;
    }
    if (g_Rpd.Processes[idx].CetEnabled) {
        ReleaseSRWLockExclusive(&g_Rpd.Lock);
        return TRUE;        /* 已启用 */
    }

    if (ProcessId == (ULONG)GetCurrentProcessId()) {
        /* 当前进程: SetProcessMitigationPolicy (强制模式, 非审计) */
        ZeroMemory(&policy, sizeof(policy));
        policy.EnableUserShadowStack = 1;
        policy.AuditUserShadowStack = 0;

        if (!SetProcessMitigationPolicy(ProcessUserShadowStackPolicy,
                                        &policy, sizeof(policy))) {
            ReleaseSRWLockExclusive(&g_Rpd.Lock);
            return FALSE;
        }
        g_Rpd.Processes[idx].CetEnabled = TRUE;
        ReleaseSRWLockExclusive(&g_Rpd.Lock);
        return TRUE;
    }

    /* 外部进程: NtSetInformationProcess 类 39 (Windows 10 2004+).
     * SS 释放全局写锁再调用 (避免持锁阻塞系统调用)。 */
    ReleaseSRWLockExclusive(&g_Rpd.Lock);

    pNtSIP = (PFN_NT_SET_INFORMATION_PROCESS)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess");
    if (pNtSIP == NULL) {
        return FALSE;
    }

    hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, ProcessId);
    if (hProcess == NULL) {
        return FALSE;
    }

    ZeroMemory(&policy, sizeof(policy));
    policy.EnableUserShadowStack = 1;
    policy.AuditUserShadowStack = 0;

    status = pNtSIP(hProcess, 39, &policy, (ULONG)sizeof(policy));
    CloseHandle(hProcess);

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    /* 回写 CET 标志 */
    AcquireSRWLockExclusive(&g_Rpd.Lock);
    idx = RpdpFindProcess(ProcessId);
    if (idx >= 0) {
        g_Rpd.Processes[idx].CetEnabled = TRUE;
        result = TRUE;
    }
    ReleaseSRWLockExclusive(&g_Rpd.Lock);

    return result;
}

/**************************************************/
/*               内核集成                           */
/**************************************************/

VOID
RpdProcessKernelMemoryAlert(
    _In_ ULONG  MsgType,
    _In_reads_bytes_(PayloadSize) const VOID* Payload,
    _In_ ULONG  PayloadSize
    )
{
    RPD_KERNEL_ROP_ALERT alert;
    ULONG  safeGadgetCount;
    ULONG  expectedSize;
    ULONG  i;
    const UCHAR* gadgetBytes;
    RPD_CHAIN_INFO chain;
    RPD_EVENT evt;
    RPD_ATTACK_TYPE attackType;
    WCHAR  desc[512];
    SIZE_T descLen;
    ULONG  descLen32;

    /* SS 在此校验 FilterMessageType_MemoryAlert 枚举; WkDefender 无该
     * 消息枚举, 由调用方仅转发 MemoryAlert 类消息 (见头文件注释)。 */
    (VOID)MsgType;

    if (!g_Rpd.Initialized) {
        return;
    }
    if (Payload == NULL || PayloadSize < sizeof(RPD_KERNEL_ROP_ALERT)) {
        return;
    }

    memcpy(&alert, Payload, sizeof(alert));

    if (!alert.ChainDetected) {
        return;             /* 信息性消息, 非确认链 */
    }

    /* gadget 计数截断 (SS: 超上限截断) */
    safeGadgetCount = (alert.GadgetCount < RPD_MAX_GADGET_CHAIN_LENGTH)
        ? alert.GadgetCount : RPD_MAX_GADGET_CHAIN_LENGTH;

    expectedSize = sizeof(RPD_KERNEL_ROP_ALERT) + safeGadgetCount *
                   sizeof(RPD_KERNEL_ROP_GADGET_ENTRY);
    if (PayloadSize < expectedSize) {
        return;
    }

    /* 攻击类型映射 (SS ROP_ATTACK_TYPE → CodeReuseType) */
    switch (alert.AttackType) {
        case 1:  attackType = RpdAttack_ROP;  break;
        case 2:  attackType = RpdAttack_JOP;  break;
        case 3:  attackType = RpdAttack_COP;  break;
        case 4:  attackType = RpdAttack_SOP;  break;
        case 5:  attackType = RpdAttack_BROP; break;
        default: attackType = RpdAttack_ROP;  break;   /* Mixed/Unknown */
    }

    /* 链摘要 */
    ZeroMemory(&chain, sizeof(chain));
    chain.ChainId = (UINT64)InterlockedIncrement(&g_Rpd.NextChainId);
    chain.ChainStartAddress = alert.CurrentSp;
    chain.AttackType = attackType;
    chain.ChainLength = safeGadgetCount;
    chain.IsCompleteChain = (safeGadgetCount >= RPD_MIN_COMPLETE_KERNEL_CHAIN);

    if (alert.PayloadInferred) {
        WCHAR buf[256];
        buf[0] = L'\0';

        if (alert.MayEscalatePrivileges) wcscat_s(buf, 256, L"PrivEsc+");
        if (alert.MayExecuteCode)        wcscat_s(buf, 256, L"CodeExec+");
        if (alert.MayDisableDefenses)    wcscat_s(buf, 256, L"DefBypass+");
        if (buf[0] != L'\0') {
            buf[wcslen(buf) - 1] = L'\0';   /* 去尾部 + */
            RpdpSanitizeW(chain.PayloadType, 64, buf);
        }

        /* 内核描述: 限长 255 字节拷贝 (SS strnlen 语义).
         * 先置空缓冲, 转换失败时不会把未初始化的栈垃圾交给后续
         * RpdpSanitizeW (其内部 wcslen 会越界读取)。 */
        desc[0] = L'\0';
        descLen = strnlen(alert.PayloadDescription, sizeof(alert.PayloadDescription) - 1);
        if (descLen > 0) {
            descLen32 = (ULONG)descLen;
            if (MultiByteToWideChar(CP_ACP, 0, alert.PayloadDescription, (int)descLen32,
                                    desc, 512) > 0) {
                desc[descLen32] = L'\0';
                RpdpSanitizeW(desc, 512, desc);
                if (chain.PayloadType[0] != L'\0') {
                    wcscat_s(chain.PayloadType, 64, L":");
                    wcscat_s(chain.PayloadType, 64, desc);
                } else {
                    RpdpSanitizeW(chain.PayloadType, 64, desc);
                }
            }
        }
    }

    /* gadget 明细统计 (SS 逐条构建; 此处仅累计总量与计数) */
    gadgetBytes = (const UCHAR*)Payload + sizeof(RPD_KERNEL_ROP_ALERT);
    for (i = 0; i < safeGadgetCount; ++i) {
        RPD_KERNEL_ROP_GADGET_ENTRY ke;
        memcpy(&ke, gadgetBytes + ((SIZE_T)i * sizeof(RPD_KERNEL_ROP_GADGET_ENTRY)),
               sizeof(ke));
        chain.TotalBytes += ke.GadgetSize;
        InterlockedIncrement(&g_Rpd.Stats.GadgetsIdentified);
    }

    /* 事件构建 */
    evt = RpdpCreateEvent(alert.ProcessId, alert.ThreadId, RpdMethod_KernelAlert,
                          L"Kernel ROPDetector alert");
    evt.StackPointer = alert.CurrentSp;
    evt.ChainStartAddress = alert.CurrentSp;
    evt.ChainLength = safeGadgetCount;
    evt.AttackType = attackType;
    evt.IsCompleteChain = chain.IsCompleteChain;
    evt.ConfidenceScore = alert.ConfidenceScore;
    evt.Confidence = (alert.ConfidenceScore >= 80) ? RpdConf_Confirmed :
                     (alert.ConfidenceScore >= 60) ? RpdConf_VeryHigh  :
                     (alert.ConfidenceScore >= 40) ? RpdConf_High      :
                     (alert.ConfidenceScore >= 20) ? RpdConf_Medium    :
                                                     RpdConf_Low;

    InterlockedIncrement(&g_Rpd.Stats.RopChainsDetected);
    if (attackType == RpdAttack_JOP) {
        InterlockedIncrement(&g_Rpd.Stats.JopChainsDetected);
    }

    /* 响应 (SS: 确认链终止 / 否则按配置拦截) */
    if (g_Rpd.Config.TerminateOnConfirmed &&
        evt.Confidence == RpdConf_Confirmed) {
        RpdpEnforceTermination(alert.ProcessId, L"Kernel-confirmed ROP chain", &evt);
    } else if (g_Rpd.Config.BlockOnDetection) {
        evt.WasBlocked = TRUE;
        InterlockedIncrement(&g_Rpd.Stats.AttacksBlocked);
    }

    RpdpNotify(&evt);
}

/**************************************************/
/*               统计 / 历史                        */
/**************************************************/

VOID
RpdGetStatistics(
    _Out_ PRPD_STATISTICS Stats
    )
{
    if (Stats == NULL) {
        return;
    }
    *Stats = g_Rpd.Stats;
    Stats->UptimeSeconds = (ULONG)((GetTickCount64() - g_Rpd.StartTick) / 1000ULL);
}

VOID
RpdResetStatistics(VOID)
{
    ZeroMemory(&g_Rpd.Stats, sizeof(g_Rpd.Stats));
    g_Rpd.StartTick = GetTickCount64();
}

ULONG
RpdGetRecentDetections(
    _Out_writes_to_opt_(MaxEvents, *pReturned) PRPD_EVENT Events,
    _In_                               ULONG      MaxEvents,
    _Out_opt_                          PULONG     pReturned
    )
{
    ULONG take;
    ULONG count;
    ULONG idx;
    ULONG i;

    if (pReturned != NULL) {
        *pReturned = 0;
    }
    if (Events == NULL || MaxEvents == 0) {
        return 0;
    }

    AcquireSRWLockShared(&g_Rpd.HistoryLock);

    count = g_Rpd.HistoryCount;
    take = (count < MaxEvents) ? count : MaxEvents;

    /* 从最新元素倒数 (SS GetRecentDetections 倒序语义) */
    idx = g_Rpd.HistoryLast;
    for (i = 0; i < take; ++i) {
        Events[i] = g_Rpd.History[idx];
        idx = (idx + RPD_HISTORY_CAPACITY - 1) % RPD_HISTORY_CAPACITY;
    }
    if (pReturned != NULL) {
        *pReturned = take;
    }

    ReleaseSRWLockShared(&g_Rpd.HistoryLock);
    return take;
}

/* SelfTest 辅助: 枚举当前进程首个可执行区域地址 (替代 SS 硬编码 0x400000) */
static UINT64
RpdpFindExecutableAddress(VOID)
{
    UINT64 address;
    MEMORY_BASIC_INFORMATION mbi;
    SYSTEM_INFO si;

    address = 0;
    ZeroMemory(&si, sizeof(si));
    GetSystemInfo(&si);

    for (address = (UINT64)(UINT_PTR)si.lpMinimumApplicationAddress;
         address < (UINT64)(UINT_PTR)si.lpMaximumApplicationAddress; ) {
        ZeroMemory(&mbi, sizeof(mbi));
        if (VirtualQuery((LPCVOID)(UINT_PTR)address, &mbi, sizeof(mbi)) == 0) {
            break;
        }
        if (mbi.State == MEM_COMMIT &&
            RpdpIsExecutableProtection(mbi.Protect) &&
            (UINT64)(UINT_PTR)mbi.RegionSize > 0x1000) {
            return address + 0x100;     /* 区域内部可执行地址 */
        }
        address += (UINT64)(UINT_PTR)mbi.RegionSize;
        if (mbi.RegionSize == 0) {
            break;
        }
    }
    return 0;
}

BOOLEAN
RpdSelfTest(VOID)
{
    ULONG            testThreadId;
    RPD_CONFIG       savedConfig;
    BOOLEAN          ok;
    BOOLEAN          shadowEnabled;
    ULONG            beforeCount;
    UINT64           execAddr;
    UCHAR            gadgetData[2];

    if (!g_Rpd.Initialized) {
        return FALSE;
    }

    ok = TRUE;
    testThreadId = 12345;
    savedConfig = g_Rpd.Config;
    shadowEnabled = g_Rpd.Config.EnableShadowStack;

    /* 测试 1: 影子栈操作 */
    g_Rpd.Config.EnableShadowStack = TRUE;
    RpdShadowStackClear(testThreadId);

    RpdShadowStackPush(testThreadId, 0x12345678ULL, 0x87654321ULL);
    if (RpdGetShadowStackDepth(testThreadId) != 1) {
        ok = FALSE;
    }
    if (ok && !RpdShadowStackPop(testThreadId, 0x12345678ULL)) {
        ok = FALSE;
    }
    if (ok) {
        RpdShadowStackPush(testThreadId, 0xAAAAAAAAULL, 0);
        if (RpdShadowStackPop(testThreadId, 0xBBBBBBBBULL)) {
            ok = FALSE;     /* 失配应返回 FALSE */
        }
    }
    RpdShadowStackClear(testThreadId);
    g_Rpd.Config.EnableShadowStack = shadowEnabled;

    /* 测试 2: 返回地址校验 */
    if (ok && RpdValidateApiCall(0)) {
        ok = FALSE;         /* NULL 应拒绝 */
    }
    execAddr = RpdpFindExecutableAddress();
    if (ok && execAddr != 0) {
        if (!RpdValidateApiCall(execAddr)) {
            ok = FALSE;     /* 可执行地址应放行 */
        }
    }

    /* 测试 3: gadget pattern 检测 */
    if (ok) {
        gadgetData[0] = 0x58;   /* POP EAX */
        gadgetData[1] = 0xC3;   /* RET */
        if (!RpdpContainsGadgetPattern(gadgetData, 2)) {
            ok = FALSE;
        }
    }

    /* 测试 4: 受保护 API 表增删 */
    if (ok) {
        beforeCount = RpdGetProtectedApis(NULL, 0, NULL);
        if (NT_SUCCESS(RpdProtectApi("RpdSelfTestApi", RpdApiCat_Unknown))) {
            if (RpdGetProtectedApis(NULL, 0, NULL) != beforeCount + 1) {
                ok = FALSE;
            }
            RpdUnprotectApi("RpdSelfTestApi");
            if (ok && RpdGetProtectedApis(NULL, 0, NULL) != beforeCount) {
                ok = FALSE;
            }
        }
    }

    /* 还原配置 (SelfTest 不持久化开关) */
    g_Rpd.Config = savedConfig;

    return ok;
}

/**************************************************/
/*               回调                              */
/**************************************************/

VOID
RpdRegisterCallback(
    _In_opt_ RPD_DETECTED_CALLBACK Callback,
    _In_opt_ PVOID                 Context
    )
{
    AcquireSRWLockExclusive(&g_Rpd.CallbackLock);
    g_Rpd.Callback = Callback;
    g_Rpd.CallbackContext = Context;
    ReleaseSRWLockExclusive(&g_Rpd.CallbackLock);
}

/**************************************************/
/*               工具函数                           */
/**************************************************/

PCSTR
RpdGetDetectionMethodName(
    _In_ RPD_DETECTION_METHOD Method
    )
{
    switch (Method) {
        case RpdMethod_ShadowStackMismatch:     return "ShadowStackMismatch";
        case RpdMethod_StackPointerOutOfBounds: return "StackPointerOutOfBounds";
        case RpdMethod_ReturnAddressInvalid:    return "ReturnAddressInvalid";
        case RpdMethod_CallRetMismatch:         return "CallRetMismatch";
        case RpdMethod_HeuristicGadgetScan:     return "HeuristicGadgetScan";
        case RpdMethod_PatternMatch:            return "PatternMatch";
        case RpdMethod_ApiReturnValidation:     return "ApiReturnValidation";
        case RpdMethod_HardwareCET:             return "HardwareCET";
        case RpdMethod_KernelAlert:             return "KernelAlert";
        default:                                return "Unknown";
    }
}

PCSTR
RpdGetAttackTypeName(
    _In_ RPD_ATTACK_TYPE Type
    )
{
    switch (Type) {
        case RpdAttack_ROP:  return "ROP";
        case RpdAttack_JOP:  return "JOP";
        case RpdAttack_COP:  return "COP";
        case RpdAttack_SOP:  return "SOP";
        case RpdAttack_BROP: return "BROP";
        case RpdAttack_COOP: return "COOP";
        default:             return "Unknown";
    }
}

PCSTR
RpdGetGadgetTypeName(
    _In_ RPD_GADGET_TYPE Type
    )
{
    switch (Type) {
        case RpdGadget_Ret:     return "RetGadget";
        case RpdGadget_RetN:    return "RetNGadget";
        case RpdGadget_Jmp:     return "JmpGadget";
        case RpdGadget_Call:    return "CallGadget";
        case RpdGadget_Syscall: return "SyscallGadget";
        case RpdGadget_Int:     return "IntGadget";
        default:                return "Unknown";
    }
}

PCSTR
RpdGetApiCategoryName(
    _In_ RPD_API_CATEGORY Category
    )
{
    switch (Category) {
        case RpdApiCat_MemoryAllocation:  return "MemoryAllocation";
        case RpdApiCat_MemoryProtection:  return "MemoryProtection";
        case RpdApiCat_ProcessCreation:   return "ProcessCreation";
        case RpdApiCat_ThreadCreation:    return "ThreadCreation";
        case RpdApiCat_DllLoading:        return "DllLoading";
        case RpdApiCat_CodeExecution:     return "CodeExecution";
        case RpdApiCat_FileOperations:    return "FileOperations";
        case RpdApiCat_RegistryAccess:    return "RegistryAccess";
        case RpdApiCat_NetworkOperations: return "NetworkOperations";
        default:                          return "Unknown";
    }
}

BOOLEAN
RpdIsReturnInstruction(
    _In_ UCHAR Opcode
    )
{
    return (Opcode == RPD_RET_OPCODE ||
            Opcode == RPD_RETN_OPCODE ||
            Opcode == RPD_RETF_OPCODE ||
            Opcode == RPD_RETFN_OPCODE);
}

BOOLEAN
RpdIsJumpInstruction(
    _In_reads_(ByteCount) const UCHAR* Bytes,
    _In_                          ULONG  ByteCount
    )
{
    UCHAR opcode;
    UCHAR modrm;

    if (Bytes == NULL || ByteCount == 0) {
        return FALSE;
    }
    opcode = Bytes[0];

    if (opcode == 0xEB || opcode == 0xE9 || opcode == 0xEA) {
        return TRUE;        /* JMP short/near/far */
    }
    if (ByteCount >= 2 && opcode == 0xFF) {
        modrm = Bytes[1];   /* JMP r/m (FF /4) */
        return ((modrm & 0x38) == 0x20);
    }
    return FALSE;
}

BOOLEAN
RpdIsCallInstruction(
    _In_reads_(ByteCount) const UCHAR* Bytes,
    _In_                          ULONG  ByteCount
    )
{
    UCHAR opcode;
    UCHAR modrm;

    if (Bytes == NULL || ByteCount == 0) {
        return FALSE;
    }
    opcode = Bytes[0];

    if (opcode == 0xE8 || opcode == 0x9A) {
        return TRUE;        /* CALL near/far */
    }
    if (ByteCount >= 2 && opcode == 0xFF) {
        modrm = Bytes[1];   /* CALL r/m (FF /2) */
        return ((modrm & 0x38) == 0x10);
    }
    return FALSE;
}