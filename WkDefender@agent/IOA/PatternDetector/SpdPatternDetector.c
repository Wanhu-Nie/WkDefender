/**************************************************/
/*  WkDefender IOA — 栈迁移 (Stack Pivot) 攻击检测器  */
/*  实现文件                                          */
/*                                                  */
/*  迁移自 ShadowStrike StackPivotDetector.cpp       */
/*  (v3.0.0, 2421 行) — 功能重实现 (C 重写)。        */
/*                                                  */
/*  架构对齐:                                        */
/*    - PIMPL + Meyers 单例 ↔ C 静态全局状态          */
/*    - std::shared_mutex ↔ SRWLOCK (共享/排他)       */
/*    - std::mutex ↔ CRITICAL_SECTION                */
/*    - RAII 句柄 ↔ 显示 Open/Close 配对              */
/*    - try/catch ↔ NTSTATUS / BOOLEAN 返回值         */
/*                                                  */
/*  性能 (声称):                             */
/*    - 栈上限缓存 (TEB 读取, 30s TTL 整体清理)       */
/*    - O(1) 边界检查 (SPD_RANGE_CONTAINS)            */
/*    - 进程句柄 LRU 缓存 (256) 减少重复 OpenProcess  */
/*                                                  */
/*  锁纪律:                                          */
/*    主锁 g_StateLock 只保护状态/配置; 持锁期间      */
/*    不得获取子锁 (g_CacheLock 等) —         */
/*    "Main mutex RELEASED before child locks"。      */
/**************************************************/

#include "SpdPatternDetector.h"

#include <tlhelp32.h>
#include <psapi.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "Psapi.lib")

/**************************************************/
/*              编译期常量 (gadget 表)               */
/*  StackPivotDetector.cpp L94-141。         */
/**************************************************/

/* 2 字节 x86 栈迁移 gadget (17 项) */
static const UCHAR g_SpdPivotGadgets2B[][2] = {
    { 0x87, 0xE0 }, /* XCHG ESP,EAX                    */
    { 0x87, 0xC4 }, /* XCHG ESP,EAX (交替编码)         */
    { 0x8B, 0xE0 }, /* MOV ESP,EAX                     */
    { 0x8B, 0xE1 }, /* MOV ESP,ECX                     */
    { 0x8B, 0xE2 }, /* MOV ESP,EDX                     */
    { 0x8B, 0xE3 }, /* MOV ESP,EBX                     */
    { 0x8B, 0xE5 }, /* MOV ESP,EBP                     */
    { 0x8B, 0xE6 }, /* MOV ESP,ESI                     */
    { 0x8B, 0xE7 }, /* MOV ESP,EDI                     */
    { 0xC9, 0xC3 }, /* LEAVE; RET 序列                 */
    { 0x83, 0xC4 }, /* ADD ESP,imm8 前缀               */
    { 0x81, 0xC4 }, /* ADD ESP,imm32 前缀              */
    { 0x83, 0xEC }, /* SUB ESP,imm8 前缀               */
    { 0x81, 0xEC }, /* SUB ESP,imm32 前缀              */
    { 0x54, 0xC3 }, /* PUSH ESP; RET                   */
    { 0xFF, 0xE4 }, /* JMP ESP                         */
    { 0xFF, 0xD4 }  /* CALL ESP                        */
};

/* 1 字节 x86 栈迁移 gadget (2 项) */
static const UCHAR g_SpdPivotGadgets1B[] = {
    0x94,           /* XCHG ESP,EAX (短形式)           */
    0x5C            /* POP ESP                         */
};

/* x64 栈迁移 gadget (3 字节带 REX 前缀, 13 项) */
static const UCHAR g_SpdPivotGadgetsX64[][3] = {
    { 0x48, 0x87, 0xE0 }, /* XCHG RSP,RAX             */
    { 0x48, 0x87, 0xC4 }, /* XCHG RSP,RAX (交替编码)   */
    { 0x48, 0x8B, 0xE0 }, /* MOV RSP,RAX              */
    { 0x48, 0x8B, 0xE1 }, /* MOV RSP,RCX              */
    { 0x48, 0x8B, 0xE2 }, /* MOV RSP,RDX              */
    { 0x48, 0x8B, 0xE3 }, /* MOV RSP,RBX              */
    { 0x48, 0x8B, 0xE5 }, /* MOV RSP,RBP              */
    { 0x48, 0x8B, 0xE6 }, /* MOV RSP,RSI              */
    { 0x48, 0x8B, 0xE7 }, /* MOV RSP,RDI              */
    { 0x48, 0x83, 0xC4 }, /* ADD RSP,imm8             */
    { 0x48, 0x81, 0xC4 }, /* ADD RSP,imm32            */
    { 0x48, 0x83, 0xEC }, /* SUB RSP,imm8             */
    { 0x48, 0x81, 0xEC }  /* SUB RSP,imm32            */
};

/* x64 POP RSP (REX.B + POP, 2 字节) */
static const UCHAR g_SpdPopRspGadget[2] = { 0x41, 0x5C };

/* LEAVE 指令 (栈帧操纵) */
#define SPD_LEAVE_OPCODE 0xC9

/**************************************************/
/*            NT API 结构 (TEB/PEB 访问)            */
/*  StackPivotDetector.cpp L186-226。        */
/**************************************************/

#if !defined(_WIN64)
typedef struct _SPD_NT_TIB32 {
    ULONG ExceptionList;
    ULONG StackBase;
    ULONG StackLimit;
    ULONG SubSystemTib;
    ULONG FiberData;
    ULONG ArbitraryUserPointer;
    ULONG Self;
} SPD_NT_TIB32;
#else
typedef struct _SPD_NT_TIB64 {
    ULONG64 ExceptionList;
    ULONG64 StackBase;
    ULONG64 StackLimit;
    ULONG64 SubSystemTib;
    ULONG64 FiberData;
    ULONG64 ArbitraryUserPointer;
    ULONG64 Self;
} SPD_NT_TIB64;
#endif

/* THREAD_BASIC_INFORMATION — winternl.h 未全覆盖, 本地定义 */
typedef struct _SPD_THREAD_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG      Priority;
    LONG      BasePriority;
} SPD_THREAD_BASIC_INFORMATION;

typedef NTSTATUS (NTAPI *SPD_NT_QUERY_INFORMATION_THREAD)(
    _In_      HANDLE ThreadHandle,
    _In_      LONG   ThreadInformationClass,
    _Inout_   PVOID  ThreadInformation,
    _In_      ULONG  ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

/**************************************************/
/*               内部数据结构                       */
/**************************************************/

/* 栈上限缓存条目 (key = pid<<32|tid, MakeCacheKey) */
typedef struct _SPD_STACK_CACHE_ENTRY {
    UINT64          Key;    /* pid<<32|tid, Valid=FALSE 时空槽 */
    BOOLEAN         Valid;
    SPD_STACK_RANGE Range;  /* LastUpdated 未用 */
} SPD_STACK_CACHE_ENTRY;

/* 进程句柄 LRU 缓存条目 (CachedProcessHandle) */
typedef struct _SPD_PROCESS_HANDLE_ENTRY {
    DWORD   ProcessId;
    HANDLE  Handle;
    UINT64  LastUsedTick;
    BOOLEAN Valid;
} SPD_PROCESS_HANDLE_ENTRY;

/**************************************************/
/*               静态全局状态                       */
/*  StackPivotDetectorImpl 成员。            */
/**************************************************/

static SRWLOCK g_StateLock    = SRWLOCK_INIT;   /* 状态 + 配置         */
static SRWLOCK g_CacheLock    = SRWLOCK_INIT;   /* 栈上限缓存          */
static SRWLOCK g_HandleCacheLock = SRWLOCK_INIT; /* 进程句柄缓存       */
static SRWLOCK g_MonitorLock  = SRWLOCK_INIT;   /* 监控进程集合        */
static SRWLOCK g_CallbackLock = SRWLOCK_INIT;   /* 检测回调            */
static SRWLOCK g_DetectionLock = SRWLOCK_INIT;  /* 最近检测环形        */
static SRWLOCK g_CacheClearLock = SRWLOCK_INIT; /* 缓存 TTL 清理双检   */

static SPD_STATUS g_Status = SpdStatus_Uninitialized;
static SPD_CONFIG g_Config;                     /* 默认 = SPD_DEFAULT_CONFIG */
static SPD_STATISTICS g_Stats;                  /* volatile LONG 原子计数 */
static LONG g_EventCounter = 0;                 /* 事件序号 (替代 SS 字符串 ID) */
static UINT64 g_StartTick = 0;                  /* GetTickCount64 起点 */

static SPD_STACK_CACHE_ENTRY g_StackCache[SPD_STACK_CACHE_ENTRIES];
static UINT64 g_LastCacheClearTick = 0;         /* TTL 清理时间戳 */

static SPD_PROCESS_HANDLE_ENTRY g_ProcessHandleCache[SPD_PROCESS_HANDLE_CACHE_ENTRIES];

static ULONG g_MonitoredProcesses[SPD_MAX_MONITORED_PROCESSES];
static ULONG g_MonitoredCount = 0;

static SPD_DETECTION_EVENT g_RecentDetections[SPD_MAX_RECENT_DETECTIONS];
static ULONG g_DetectionCount = 0;              /* 0..SPD_MAX_RECENT_DETECTIONS */
static ULONG g_DetectionHead = 0;               /* 下一写入槽 (最旧)   */

static SPD_DETECTED_CALLBACK g_Callback = NULL;
static PVOID g_CallbackContext = NULL;

/**************************************************/
/*               内部工具函数                       */
/**************************************************/

/*++

    生成 (pid, tid) 缓存键 (MakeCacheKey)。

--*/
static UINT64
SpdpMakeCacheKey(
    _In_ ULONG Pid,
    _In_ ULONG Tid
    )
{
    return ((UINT64)Pid << 32) | Tid;
}

/*++

    可执行内存保护判定 (IsExecutableProtection):
    归一化处理 PAGE_GUARD/PAGE_NOCACHE/PAGE_WRITECOMBINE 后
    精确匹配 PAGE_EXECUTE 系列。

--*/
static BOOLEAN
SpdpIsExecutableProtection(
    _In_ ULONG Protect
    )
{
    const ULONG normalized = Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);

    return (normalized == PAGE_EXECUTE ||
            normalized == PAGE_EXECUTE_READ ||
            normalized == PAGE_EXECUTE_READWRITE ||
            normalized == PAGE_EXECUTE_WRITECOPY);
}

/*++

    栈上限缓存查询 (锁内查找 + 拷贝, 无 TOCTOU)。

--*/
static BOOLEAN
SpdpCacheLookup(
    _In_  UINT64 Key,
    _Out_ PSPD_STACK_RANGE OutRange
    )
{
    ULONG i;
    BOOLEAN found = FALSE;

    if (OutRange == NULL) {
        return FALSE;
    }

    AcquireSRWLockShared(&g_CacheLock);
    for (i = 0; i < SPD_STACK_CACHE_ENTRIES; ++i) {
        if (g_StackCache[i].Valid && g_StackCache[i].Key == Key) {
            *OutRange = g_StackCache[i].Range;
            found = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(&g_CacheLock);

    return found;
}

/*++

    栈上限缓存插入 (已存在则更新; 空槽优先, 全满丢弃 —
    SS 为无界 map + 30s TTL, C 静态化以定长 + TTL 兜底)。

--*/
static VOID
SpdpCacheInsert(
    _In_ UINT64 Key,
    _In_ const SPD_STACK_RANGE* Range
    )
{
    ULONG i;
    ULONG freeSlot = SPD_STACK_CACHE_ENTRIES;

    AcquireSRWLockExclusive(&g_CacheLock);
    for (i = 0; i < SPD_STACK_CACHE_ENTRIES; ++i) {
        if (g_StackCache[i].Valid && g_StackCache[i].Key == Key) {
            break;                              /* 已存在 → 更新 */
        }
        if (!g_StackCache[i].Valid && freeSlot == SPD_STACK_CACHE_ENTRIES) {
            freeSlot = i;
        }
    }

    if (i < SPD_STACK_CACHE_ENTRIES) {
        g_StackCache[i].Range = *Range;
    } else if (freeSlot < SPD_STACK_CACHE_ENTRIES) {
        g_StackCache[freeSlot].Key = Key;
        g_StackCache[freeSlot].Range = *Range;
        g_StackCache[freeSlot].Valid = TRUE;
    }
    /* 全满: 丢弃本次插入 (30s TTL 清理定期回收, 语义等价) */

    ReleaseSRWLockExclusive(&g_CacheLock);
}

/*++

    栈上限缓存删除 (UnregisterThread/RefreshStackLimits 的 erase)。

--*/
static VOID
SpdpCacheErase(
    _In_ UINT64 Key
    )
{
    ULONG i;

    AcquireSRWLockExclusive(&g_CacheLock);
    for (i = 0; i < SPD_STACK_CACHE_ENTRIES; ++i) {
        if (g_StackCache[i].Valid && g_StackCache[i].Key == Key) {
            g_StackCache[i].Valid = FALSE;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_CacheLock);
}

/*++

    过期缓存整体清理 (ClearExpiredCache):
    快路径近似时间检查 (良性竞态) + CacheClearLock 双检 +
    整体清空。TTL = SPD_STACK_CACHE_TTL_MS (30s)。

--*/
static VOID
SpdpClearExpiredCache(VOID)
{
    const UINT64 now = GetTickCount64();

    /* 快路径近似检查 (良性竞态 — 最坏是多取一次互斥) */
    if (now - g_LastCacheClearTick < SPD_STACK_CACHE_TTL_MS) {
        return;
    }

    AcquireSRWLockExclusive(&g_CacheClearLock);

    /* 双检 (与写 g_LastCacheClearTick 同锁) */
    if (now - g_LastCacheClearTick < SPD_STACK_CACHE_TTL_MS) {
        ReleaseSRWLockExclusive(&g_CacheClearLock);
        return;
    }

    AcquireSRWLockExclusive(&g_CacheLock);
    memset(g_StackCache, 0, sizeof(g_StackCache));
    ReleaseSRWLockExclusive(&g_CacheLock);

    g_LastCacheClearTick = now;
    ReleaseSRWLockExclusive(&g_CacheClearLock);
}

/*++

    进程句柄 LRU 缓存 (GetProcessHandleForPid):
    命中更新 LastUsedTick; 未命中锁外 OpenProcess 后双检插入,
    满时淘汰最旧项。上限 SPD_PROCESS_HANDLE_CACHE_ENTRIES (256)。

--*/
static HANDLE
SpdpGetCachedProcessHandle(
    _In_ DWORD ProcessId
    )
{
    const UINT64 now = GetTickCount64();
    ULONG i;
    ULONG oldest = 0;
    ULONG freeSlot = SPD_PROCESS_HANDLE_CACHE_ENTRIES;
    HANDLE h;

    if (ProcessId == 0) {
        return NULL;
    }

    AcquireSRWLockExclusive(&g_HandleCacheLock);
    for (i = 0; i < SPD_PROCESS_HANDLE_CACHE_ENTRIES; ++i) {
        if (g_ProcessHandleCache[i].Valid) {
            if (g_ProcessHandleCache[i].ProcessId == ProcessId) {
                g_ProcessHandleCache[i].LastUsedTick = now;
                h = g_ProcessHandleCache[i].Handle;
                ReleaseSRWLockExclusive(&g_HandleCacheLock);
                return h;
            }
            if (g_ProcessHandleCache[i].LastUsedTick < g_ProcessHandleCache[oldest].LastUsedTick) {
                oldest = i;
            }
        } else if (freeSlot == SPD_PROCESS_HANDLE_CACHE_ENTRIES) {
            freeSlot = i;
        }
    }
    ReleaseSRWLockExclusive(&g_HandleCacheLock);

    /* 锁外 OpenProcess (避免持锁期间做 IO) */
    h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if (h == NULL) {
        return NULL;
    }

    /* 双检插入: 期间可能已被其他线程填入 */
    AcquireSRWLockExclusive(&g_HandleCacheLock);
    for (i = 0; i < SPD_PROCESS_HANDLE_CACHE_ENTRIES; ++i) {
        if (g_ProcessHandleCache[i].Valid && g_ProcessHandleCache[i].ProcessId == ProcessId) {
            CloseHandle(h);
            g_ProcessHandleCache[i].LastUsedTick = now;
            h = g_ProcessHandleCache[i].Handle;
            ReleaseSRWLockExclusive(&g_HandleCacheLock);
            return h;
        }
    }

    if (freeSlot < SPD_PROCESS_HANDLE_CACHE_ENTRIES) {
        i = freeSlot;
    } else {
        i = oldest;                             /* 全满 → 淘汰最旧 */
        CloseHandle(g_ProcessHandleCache[i].Handle);
    }

    g_ProcessHandleCache[i].ProcessId = ProcessId;
    g_ProcessHandleCache[i].Handle = h;
    g_ProcessHandleCache[i].LastUsedTick = now;
    g_ProcessHandleCache[i].Valid = TRUE;
    ReleaseSRWLockExclusive(&g_HandleCacheLock);

    return h;
}

/*++

    读取线程 TEB 栈限制 (ReadTEBStackLimits):
    动态解析 NtQueryInformationThread (ThreadBasicInformation=0),
    经进程句柄缓存 ReadProcessMemory 读取 NT_TIB, 并用
    VirtualQueryEx(StackLimit) 取得真实 AllocationBase。

--*/
static BOOLEAN
SpdpReadTebStackLimits(
    _In_  HANDLE hThread,
    _In_  ULONG  ThreadId,
    _Out_ PSPD_STACK_RANGE Range
    )
{
    static SPD_NT_QUERY_INFORMATION_THREAD s_NtQueryInformationThread = NULL;
    SPD_THREAD_BASIC_INFORMATION tbi;
    ULONG returnLength = 0;
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T bytesRead = 0;

    if (hThread == NULL || Range == NULL) {
        return FALSE;
    }

    if (s_NtQueryInformationThread == NULL) {
        /* 静态缓存函数指针, 幂等赋值免锁 */
        s_NtQueryInformationThread = (SPD_NT_QUERY_INFORMATION_THREAD)
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");
    }
    if (s_NtQueryInformationThread == NULL) {
        return FALSE;
    }

    memset(&tbi, 0, sizeof(tbi));
    /* ThreadBasicInformation = 0 */
    if (s_NtQueryInformationThread(hThread, 0, &tbi, (ULONG)sizeof(tbi), &returnLength) != 0) {
        return FALSE;
    }

    hProcess = SpdpGetCachedProcessHandle(
        (DWORD)(ULONG_PTR)tbi.ClientId.UniqueProcess);
    if (hProcess == NULL) {
        return FALSE;
    }

    memset(Range, 0, sizeof(*Range));
    memset(&mbi, 0, sizeof(mbi));

#ifdef _WIN64
    {
        SPD_NT_TIB64 tib;

        if (!ReadProcessMemory(hProcess, tbi.TebBaseAddress, &tib, sizeof(tib), &bytesRead) ||
            bytesRead != sizeof(tib) ||
            tib.StackBase <= tib.StackLimit) {
            return FALSE;
        }

        Range->ThreadId = ThreadId;
        Range->StackBase = tib.StackBase;
        Range->StackLimit = tib.StackLimit;

        /* 取栈真实分配基址 */
        if (VirtualQueryEx(hProcess, (LPCVOID)tib.StackLimit, &mbi, sizeof(mbi))) {
            Range->AllocationBase = (UINT64)mbi.AllocationBase;
        } else {
            Range->AllocationBase = tib.StackLimit;
        }

        Range->StackSize = (SIZE_T)(tib.StackBase - tib.StackLimit);
        Range->CommittedSize = Range->StackSize;
        Range->ReservedSize = (Range->AllocationBase <= Range->StackBase)
            ? (SIZE_T)(Range->StackBase - Range->AllocationBase)
            : 0;
        Range->HasGuardPage = TRUE;
        GetSystemTimeAsFileTime((LPFILETIME)&Range->LastUpdated);
    }
#else
    {
        SPD_NT_TIB32 tib;

        if (!ReadProcessMemory(hProcess, tbi.TebBaseAddress, &tib, sizeof(tib), &bytesRead) ||
            bytesRead != sizeof(tib) ||
            tib.StackBase <= tib.StackLimit) {
            return FALSE;
        }

        Range->ThreadId = ThreadId;
        Range->StackBase = (UINT64)tib.StackBase;
        Range->StackLimit = (UINT64)tib.StackLimit;

        if (VirtualQueryEx(hProcess, (LPCVOID)(ULONG_PTR)tib.StackLimit, &mbi, sizeof(mbi))) {
            Range->AllocationBase = (UINT64)mbi.AllocationBase;
        } else {
            Range->AllocationBase = (UINT64)tib.StackLimit;
        }

        Range->StackSize = (SIZE_T)(tib.StackBase - tib.StackLimit);
        Range->CommittedSize = Range->StackSize;
        Range->ReservedSize = (Range->AllocationBase <= Range->StackBase)
            ? (SIZE_T)(Range->StackBase - Range->AllocationBase)
            : 0;
        Range->HasGuardPage = TRUE;
        GetSystemTimeAsFileTime((LPFILETIME)&Range->LastUpdated);
    }
#endif

    return TRUE;
}

/*++

    获取进程映像名 (不含路径, GetProcessName)。

--*/
static VOID
SpdpGetProcessName(
    _In_  ULONG  ProcessId,
    _Out_writes_(BufferChars) PWSTR Buffer,
    _In_  ULONG  BufferChars
    )
{
    HANDLE hProcess;
    WCHAR path[DEF_MAX_PATH * 2];
    DWORD size;
    size_t pos;

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    Buffer[0] = 0;
    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (hProcess == NULL) {
        wcsncpy_s(Buffer, BufferChars, L"Unknown", _TRUNCATE);
        return;
    }

    size = (DWORD)ARRAYSIZE(path);
    if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        pos = wcsrchr(path, L'\\') != NULL ? (size_t)(wcsrchr(path, L'\\') - path) : (SIZE_T)-1;
        if (pos != (SIZE_T)-1) {
            wcsncpy_s(Buffer, BufferChars, path + pos + 1, _TRUNCATE);
        } else {
            wcsncpy_s(Buffer, BufferChars, path, _TRUNCATE);
        }
    } else {
        wcsncpy_s(Buffer, BufferChars, L"Unknown", _TRUNCATE);
    }

    CloseHandle(hProcess);
}

/*++

    获取进程完整路径 (GetProcessPath)。

--*/
static VOID
SpdpGetProcessPath(
    _In_  ULONG  ProcessId,
    _Out_writes_(BufferChars) PWSTR Buffer,
    _In_  ULONG  BufferChars
    )
{
    HANDLE hProcess;
    WCHAR path[DEF_MAX_PATH * 2];
    DWORD size;

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    Buffer[0] = 0;
    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (hProcess == NULL) {
        return;
    }

    size = (DWORD)ARRAYSIZE(path);
    if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        wcsncpy_s(Buffer, BufferChars, path, _TRUNCATE);
    }

    CloseHandle(hProcess);
}

/*++

    栈指针边界校验 (ValidateStackPointer(rsp, limits) 重载):
    范围内 → Valid (邻近 guard page → NearGuardPage);
    高于基址 → Underflow; 低于下限 → Overflow。

--*/
static SPD_VALIDATION_RESULT
SpdpValidateStackRange(
    _In_ UINT64 StackPointer,
    _In_ const SPD_STACK_RANGE* Limits
    )
{
    /* 范围内: 有效栈位置 */
    if (StackPointer >= Limits->StackLimit && StackPointer <= Limits->StackBase) {
        /* 邻近 guard page 检查 (SS guardPage 字段
           ReadTEBStackLimits 不填充 → 恒 0 不触发) */
        if (Limits->HasGuardPage && Limits->GuardPage != 0) {
            const UINT64 distanceToGuard =
                (StackPointer > Limits->GuardPage)
                    ? StackPointer - Limits->GuardPage
                    : Limits->GuardPage - StackPointer;

            if (distanceToGuard < (UINT64)SPD_GUARD_PAGE_SIZE * 2) {
                return SpdValid_NearGuardPage;
            }
        }

        return SpdValid_Valid;
    }

    /* 超出基址: 下溢 (可疑) */
    if (StackPointer > Limits->StackBase) {
        return SpdValid_Underflow;
    }

    /* 低于下限: 溢出或迁移 */
    if (StackPointer < Limits->StackLimit) {
        return SpdValid_Overflow;
    }

    /* 不可达: 防御性保留 */
    return SpdValid_Unknown;
}

/*++

    写入最近检测环形缓冲 (AddRecentDetection, 最新在前)。

--*/
static VOID
SpdpAddRecentDetection(
    _In_ const SPD_DETECTION_EVENT* Event
    )
{
    AcquireSRWLockExclusive(&g_DetectionLock);

    g_RecentDetections[g_DetectionHead] = *Event;
    g_DetectionHead = (g_DetectionHead + 1) % SPD_MAX_RECENT_DETECTIONS;
    if (g_DetectionCount < SPD_MAX_RECENT_DETECTIONS) {
        ++g_DetectionCount;
    }

    ReleaseSRWLockExclusive(&g_DetectionLock);
}

/*++

    触发检测回调 (复制指针后锁外调用, FirePivotCallbacks)。

--*/
static VOID
SpdpFireDetectionCallback(
    _In_ const SPD_DETECTION_EVENT* Event
    )
{
    SPD_DETECTED_CALLBACK callback;
    PVOID context;

    AcquireSRWLockShared(&g_CallbackLock);
    callback = g_Callback;
    context = g_CallbackContext;
    ReleaseSRWLockShared(&g_CallbackLock);

    if (callback != NULL) {
        callback(Event, context);
    }
}

/*++

    配置有效性 (StackPivotDetectorConfiguration::IsValid):
    仅校验 ValidationIntervalMs ∈ [10, 60000]。

--*/
static BOOLEAN
SpdpIsValidConfig(
    _In_ const SPD_CONFIG* Config
    )
{
    if (Config == NULL) {
        return FALSE;
    }
    if (Config->ValidationIntervalMs < 10 || Config->ValidationIntervalMs > 60000) {
        return FALSE;
    }
    return TRUE;
}

/**************************************************/
/*               生命周期                           */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
SpdInitialize(
    const SPD_CONFIG* Config
    )
{
    SPD_CONFIG defaultConfig = SPD_DEFAULT_CONFIG;
    const SPD_CONFIG* effective = (Config != NULL) ? Config : &defaultConfig;
    ULONG i;

    AcquireSRWLockExclusive(&g_StateLock);

    if (g_Status != SpdStatus_Uninitialized && g_Status != SpdStatus_Stopped) {
        ReleaseSRWLockExclusive(&g_StateLock);
        return STATUS_ALREADY_INITIALIZED;
    }

    if (!SpdpIsValidConfig(effective)) {
        ReleaseSRWLockExclusive(&g_StateLock);
        return STATUS_INVALID_PARAMETER;
    }

    g_Status = SpdStatus_Initializing;
    g_Config = *effective;

    /* 统计重置 (Initialize: m_stats.Reset + startTime) */
    InterlockedExchange(&g_Stats.ChecksPerformed, 0);
    InterlockedExchange(&g_Stats.ThreadsMonitored, 0);
    InterlockedExchange(&g_Stats.PivotsDetected, 0);
    InterlockedExchange(&g_Stats.HeapPivots, 0);
    InterlockedExchange(&g_Stats.DataPivots, 0);
    InterlockedExchange(&g_Stats.ImagePivots, 0);
    InterlockedExchange(&g_Stats.AttacksBlocked, 0);
    InterlockedExchange(&g_Stats.ProcessesTerminated, 0);
    for (i = 0; i < SPD_TECHNIQUE_SLOTS; ++i) {
        InterlockedExchange(&g_Stats.ByTechnique[i], 0);
    }
    g_Stats.UptimeSeconds = 0;
    g_StartTick = GetTickCount64();

    g_Status = SpdStatus_Running;

    ReleaseSRWLockExclusive(&g_StateLock);

    /* SS 此处经 IPCManager::RegisterGenericHandler 注册内核内存
       告警回调 (FilterMessageType_MemoryAlert)。WkDefender agent
       无内核 IPC 通道, 已裁剪 — 调用方直接喂
       SpdProcessKernelMemoryAlert 即可。 */

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
SpdShutdown(VOID)
{
    ULONG i;

    /* Step 1: 主锁下转 Stopping */
    AcquireSRWLockExclusive(&g_StateLock);
    if (g_Status == SpdStatus_Uninitialized || g_Status == SpdStatus_Stopped) {
        ReleaseSRWLockExclusive(&g_StateLock);
        return;
    }
    g_Status = SpdStatus_Stopping;
    ReleaseSRWLockExclusive(&g_StateLock);

    /* 主锁已释放 — 依次独立获取子锁, 不嵌套 (Shutdown 步骤 2-4) */

    /* Step 2: 清监控集合 */
    AcquireSRWLockExclusive(&g_MonitorLock);
    g_MonitoredCount = 0;
    ReleaseSRWLockExclusive(&g_MonitorLock);

    /* Step 3: 清回调 */
    AcquireSRWLockExclusive(&g_CallbackLock);
    g_Callback = NULL;
    g_CallbackContext = NULL;
    ReleaseSRWLockExclusive(&g_CallbackLock);

    /* Step 4a: 清栈缓存 */
    AcquireSRWLockExclusive(&g_CacheLock);
    memset(g_StackCache, 0, sizeof(g_StackCache));
    ReleaseSRWLockExclusive(&g_CacheLock);

    /* Step 4b: 清并关闭进程句柄缓存 */
    AcquireSRWLockExclusive(&g_HandleCacheLock);
    for (i = 0; i < SPD_PROCESS_HANDLE_CACHE_ENTRIES; ++i) {
        if (g_ProcessHandleCache[i].Valid) {
            CloseHandle(g_ProcessHandleCache[i].Handle);
            g_ProcessHandleCache[i].Valid = FALSE;
        }
    }
    ReleaseSRWLockExclusive(&g_HandleCacheLock);

    /* Step 4c: 清最近检测 */
    AcquireSRWLockExclusive(&g_DetectionLock);
    g_DetectionCount = 0;
    g_DetectionHead = 0;
    memset(g_RecentDetections, 0, sizeof(g_RecentDetections));
    ReleaseSRWLockExclusive(&g_DetectionLock);

    /* Step 5: 终态 */
    AcquireSRWLockExclusive(&g_StateLock);
    g_Status = SpdStatus_Stopped;
    ReleaseSRWLockExclusive(&g_StateLock);
}

_Use_decl_annotations_
BOOLEAN
SpdIsInitialized(VOID)
{
    BOOLEAN initialized;

    AcquireSRWLockShared(&g_StateLock);
    initialized = (g_Status == SpdStatus_Running);
    ReleaseSRWLockShared(&g_StateLock);

    return initialized;
}

_Use_decl_annotations_
SPD_STATUS
SpdGetStatus(VOID)
{
    SPD_STATUS status;

    AcquireSRWLockShared(&g_StateLock);
    status = g_Status;
    ReleaseSRWLockShared(&g_StateLock);

    return status;
}

_Use_decl_annotations_
BOOLEAN
SpdUpdateConfiguration(
    const SPD_CONFIG* Config
    )
{
    BOOLEAN ok = FALSE;

    if (Config == NULL) {
        return FALSE;
    }

    if (!SpdpIsValidConfig(Config)) {
        return FALSE;
    }

    AcquireSRWLockExclusive(&g_StateLock);
    g_Config = *Config;
    ok = TRUE;
    ReleaseSRWLockExclusive(&g_StateLock);

    return ok;
}

_Use_decl_annotations_
NTSTATUS
SpdGetConfiguration(
    PSPD_CONFIG Config
    )
{
    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    AcquireSRWLockShared(&g_StateLock);
    *Config = g_Config;
    ReleaseSRWLockShared(&g_StateLock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
PCSTR
SpdGetVersionString(VOID)
{
    return "3.0.0";
}

/**************************************************/
/*               栈验证                             */
/**************************************************/

_Use_decl_annotations_
SPD_VALIDATION_RESULT
SpdValidateStackPointer(
    ULONG  ProcessId,
    ULONG  ThreadId,
    UINT64 StackPointer
    )
{
    SPD_STACK_RANGE range;

    InterlockedIncrement(&g_Stats.ChecksPerformed);

    /* 优先走缓存, 未命中读 TEB 并回填 */
    if (!SpdpCacheLookup(SpdpMakeCacheKey(ProcessId, ThreadId), &range)) {
        if (SpdGetStackLimits(ProcessId, ThreadId, &range) != STATUS_SUCCESS) {
            return SpdValid_InvalidBounds;
        }
    }

    return SpdpValidateStackRange(StackPointer, &range);
}

_Use_decl_annotations_
BOOLEAN
SpdIsOnValidStack(
    ULONG  ProcessId,
    UINT64 Address
    )
{
    ULONG i;
    BOOLEAN found = FALSE;

    SpdpClearExpiredCache();

    AcquireSRWLockShared(&g_CacheLock);
    for (i = 0; i < SPD_STACK_CACHE_ENTRIES; ++i) {
        if (g_StackCache[i].Valid &&
            (ULONG)(g_StackCache[i].Key >> 32) == ProcessId) {
            if (SPD_RANGE_CONTAINS(&g_StackCache[i].Range, Address)) {
                found = TRUE;
                break;
            }
        }
    }
    ReleaseSRWLockShared(&g_CacheLock);

    return found;
}

_Use_decl_annotations_
BOOLEAN
SpdDetectPivot(
    ULONG                 ProcessId,
    ULONG                 ThreadId,
    UINT64                CurrentRsp,
    UINT64                CurrentRip,
    PSPD_DETECTION_EVENT  Event
    )
{
    SPD_DETECTION_EVENT localEvent;
    SPD_DETECTION_EVENT* outEvent = (Event != NULL) ? Event : &localEvent;
    SPD_VALIDATION_RESULT validationResult;
    SPD_STACK_RANGE range;
    SPD_MEMORY_REGION region;
    BOOLEAN blockOnPivot = FALSE;
    BOOLEAN terminateOnPivot = FALSE;
    ULONG i;
    FILETIME ft;

    memset(outEvent, 0, sizeof(*outEvent));

    /* 排除列表检查 (以状态锁保护配置读取, 锁内比对) */
    AcquireSRWLockShared(&g_StateLock);
    if (g_Status != SpdStatus_Running) {
        ReleaseSRWLockShared(&g_StateLock);
        return FALSE;
    }
    if (g_Config.ExcludedProcessCount > 0) {
        WCHAR procName[DEF_MAX_IMAGE_NAME];

        SpdpGetProcessName(ProcessId, procName, ARRAYSIZE(procName));
        for (i = 0; i < g_Config.ExcludedProcessCount; ++i) {
            if (_wcsicmp(procName, g_Config.ExcludedProcesses[i]) == 0) {
                ReleaseSRWLockShared(&g_StateLock);
                return FALSE;
            }
        }
    }
    ReleaseSRWLockShared(&g_StateLock);

    /* 栈指针验证 */
    validationResult = SpdValidateStackPointer(ProcessId, ThreadId, CurrentRsp);

    if (validationResult == SpdValid_Valid ||
        validationResult == SpdValid_NearGuardPage) {
        return FALSE;                           /* 无迁移 */
    }

    if (validationResult == SpdValid_InvalidBounds ||
        validationResult == SpdValid_Unknown) {
        return FALSE;                           /* 信息不足 */
    }

    /* 迁移疑似 — 构造事件 (PivotEvent 填充) */
    outEvent->EventId = (ULONG)InterlockedIncrement(&g_EventCounter);
    outEvent->ProcessId = ProcessId;
    outEvent->ThreadId = ThreadId;
    SpdpGetProcessName(ProcessId, outEvent->ProcessName, ARRAYSIZE(outEvent->ProcessName));
    SpdpGetProcessPath(ProcessId, outEvent->ProcessPath, ARRAYSIZE(outEvent->ProcessPath));
    outEvent->NewStackPointer = CurrentRsp;
    outEvent->InstructionPointer = CurrentRip;
    GetSystemTimeAsFileTime(&ft);
    outEvent->Timestamp.LowPart = ft.dwLowDateTime;
    outEvent->Timestamp.HighPart = ft.dwHighDateTime;

    /* 原始栈限制 */
    if (SpdGetStackLimits(ProcessId, ThreadId, &range) == STATUS_SUCCESS) {
        outEvent->OriginalStackBase = range.StackBase;
        outEvent->OriginalStackLimit = range.StackLimit;
    }

    /* 目的地类型与区域信息 */
    if (SpdGetMemoryRegionInfo(ProcessId, CurrentRsp, &region) == STATUS_SUCCESS) {
        outEvent->DestinationType = region.RegionType;
        outEvent->DestinationBase = region.BaseAddress;
        outEvent->DestinationSize = (UINT64)region.RegionSize;
        wcsncpy_s(outEvent->DestinationModuleName,
                  ARRAYSIZE(outEvent->DestinationModuleName),
                  region.ModuleName, _TRUNCATE);
    } else {
        outEvent->DestinationType = SpdGetRegionType(ProcessId, CurrentRsp);
    }

    /* 置信度决策表 (DetectPivot L1134-1153) */
    switch (outEvent->DestinationType) {
    case SpdDest_Heap:
        outEvent->Confidence = SpdConf_VeryHigh;
        outEvent->ConfidenceScore = 95;
        InterlockedIncrement(&g_Stats.HeapPivots);
        break;

    case SpdDest_DataSection:
    case SpdDest_ImageSection:
        outEvent->Confidence = SpdConf_High;
        outEvent->ConfidenceScore = 85;
        if (outEvent->DestinationType == SpdDest_DataSection) {
            InterlockedIncrement(&g_Stats.DataPivots);
        } else {
            InterlockedIncrement(&g_Stats.ImagePivots);
        }
        break;

    case SpdDest_PrivateMemory:
        outEvent->Confidence = SpdConf_Medium;
        outEvent->ConfidenceScore = 70;
        break;

    default:
        outEvent->Confidence = SpdConf_Low;
        outEvent->ConfidenceScore = 50;
        break;
    }

    (void)swprintf_s(outEvent->Details,
                     ARRAYSIZE(outEvent->Details),
                     L"Stack pivot detected: RSP moved to %hs",
                     SpdGetDestinationTypeName(outEvent->DestinationType));

    /* Block/Terminate 配置快照 (锁内读取, L1158-1165) */
    AcquireSRWLockShared(&g_StateLock);
    blockOnPivot = g_Config.BlockOnPivot;
    terminateOnPivot = g_Config.TerminateOnPivot;
    ReleaseSRWLockShared(&g_StateLock);

    if (blockOnPivot) {
        outEvent->WasBlocked = TRUE;
        InterlockedIncrement(&g_Stats.AttacksBlocked);

        if (terminateOnPivot && outEvent->Confidence >= SpdConf_High) {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, ProcessId);

            if (hProcess != NULL) {
                TerminateProcess(hProcess, 1);
                CloseHandle(hProcess);
                outEvent->ProcessTerminated = TRUE;
                InterlockedIncrement(&g_Stats.ProcessesTerminated);
            }
        }
    }

    InterlockedIncrement(&g_Stats.PivotsDetected);

    /* RIP 处 gadget 识别 (L1189-1209) */
    if (CurrentRip != 0) {
        HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                   FALSE, ProcessId);

        if (hProc != NULL) {
            MEMORY_BASIC_INFORMATION mbi;

            memset(&mbi, 0, sizeof(mbi));
            if (VirtualQueryEx(hProc, (LPCVOID)CurrentRip, &mbi, sizeof(mbi)) != 0 &&
                mbi.State == MEM_COMMIT &&
                SpdpIsExecutableProtection(mbi.Protect)) {
                UCHAR gadgetBytes[SPD_GADGET_CAPTURE_BYTES];
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(hProc, (LPCVOID)CurrentRip,
                                      gadgetBytes, sizeof(gadgetBytes), &bytesRead) &&
                    bytesRead >= 2 &&
                    SpdIsPivotGadgetBytes(gadgetBytes, (ULONG)bytesRead)) {
                    outEvent->PivotGadgetAddress = CurrentRip;
                    memcpy(outEvent->PivotGadgetBytes, gadgetBytes, bytesRead);
                    outEvent->PivotGadgetBytesLength = (ULONG)bytesRead;
                    outEvent->Technique = SpdIdentifyPivotTechnique(
                        gadgetBytes, (ULONG)bytesRead);
                }
            }
            CloseHandle(hProc);
        }
    }

    /* 按技术统计 (L1211-1217) */
    if ((ULONG)outEvent->Technique < SPD_TECHNIQUE_SLOTS) {
        InterlockedIncrement(&g_Stats.ByTechnique[outEvent->Technique]);
    }

    /* SS 此处经 AlertSystem.RaiseAlert 上报 SIEM 通道 —
       WkDefender 无该通道, 已裁剪; 代之以回调 + 环形历史 */

    SpdpAddRecentDetection(outEvent);
    SpdpFireDetectionCallback(outEvent);

    return TRUE;
}

/**************************************************/
/*               栈跟踪                             */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
SpdGetStackLimits(
    ULONG           ProcessId,
    ULONG           ThreadId,
    PSPD_STACK_RANGE Range
    )
{
    const UINT64 key = SpdpMakeCacheKey(ProcessId, ThreadId);
    HANDLE hThread;
    BOOLEAN ok;

    if (Range == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 缓存优先 */
    if (SpdpCacheLookup(key, Range)) {
        return STATUS_SUCCESS;
    }

    /* TTL 清理 (SS 在缓存未命中快路径前调用) */
    SpdpClearExpiredCache();

    hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, ThreadId);
    if (hThread == NULL) {
        return STATUS_NOT_FOUND;
    }

    ok = SpdpReadTebStackLimits(hThread, ThreadId, Range);
    CloseHandle(hThread);

    if (!ok) {
        return STATUS_NOT_FOUND;
    }

    SpdpCacheInsert(key, Range);
    InterlockedIncrement(&g_Stats.ThreadsMonitored);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
SpdRefreshStackLimitsForProcess(
    ULONG ProcessId
    )
{
    HANDLE snapshot;
    THREADENTRY32 te32;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    memset(&te32, 0, sizeof(te32));
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(snapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == ProcessId) {
                SpdRefreshStackLimits(ProcessId, te32.th32ThreadID);
            }
        } while (Thread32Next(snapshot, &te32));
    }

    CloseHandle(snapshot);
}

_Use_decl_annotations_
VOID
SpdRefreshStackLimits(
    ULONG ProcessId,
    ULONG ThreadId
    )
{
    SPD_STACK_RANGE ignored;

    /* 删除缓存强制刷新; 重新读取自动回填 */
    SpdpCacheErase(SpdpMakeCacheKey(ProcessId, ThreadId));
    (void)SpdGetStackLimits(ProcessId, ThreadId, &ignored);
}

_Use_decl_annotations_
NTSTATUS
SpdGetProcessStackRanges(
    ULONG           ProcessId,
    PSPD_STACK_RANGE Ranges,
    ULONG           MaxRanges,
    PULONG          pReturned
    )
{
    ULONG i;
    ULONG returned = 0;

    if (Ranges == NULL && MaxRanges != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (pReturned != NULL) {
        *pReturned = 0;
    }

    AcquireSRWLockShared(&g_CacheLock);
    for (i = 0; i < SPD_STACK_CACHE_ENTRIES; ++i) {
        if (g_StackCache[i].Valid &&
            (ULONG)(g_StackCache[i].Key >> 32) == ProcessId) {
            if (Ranges != NULL && returned < MaxRanges) {
                Ranges[returned] = g_StackCache[i].Range;
            }
            ++returned;
        }
    }
    ReleaseSRWLockShared(&g_CacheLock);

    if (pReturned != NULL) {
        *pReturned = returned;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
SpdRegisterThread(
    ULONG ProcessId,
    ULONG ThreadId
    )
{
    SPD_STACK_RANGE ignored;

    /* 强制将栈限制载入缓存 */
    (void)SpdGetStackLimits(ProcessId, ThreadId, &ignored);
}

_Use_decl_annotations_
VOID
SpdUnregisterThread(
    ULONG ProcessId,
    ULONG ThreadId
    )
{
    SpdpCacheErase(SpdpMakeCacheKey(ProcessId, ThreadId));
}

/**************************************************/
/*               内存分析                           */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
SpdGetMemoryRegionInfo(
    ULONG            ProcessId,
    UINT64           Address,
    PSPD_MEMORY_REGION Region
    )
{
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    BOOLEAN isHeap = FALSE;

    if (Region == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    memset(Region, 0, sizeof(*Region));
    Region->BaseAddress = Address;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId);
    if (hProcess == NULL) {
        Region->RegionType = SpdDest_Unknown;
        return STATUS_ACCESS_DENIED;
    }

    memset(&mbi, 0, sizeof(mbi));
    if (!VirtualQueryEx(hProcess, (LPCVOID)Address, &mbi, sizeof(mbi))) {
        CloseHandle(hProcess);
        Region->RegionType = SpdDest_Unknown;
        return STATUS_INVALID_ADDRESS;
    }

    Region->BaseAddress = (UINT64)mbi.BaseAddress;
    Region->RegionSize = mbi.RegionSize;
    Region->AllocationBase = (UINT64)mbi.AllocationBase;
    Region->State = mbi.State;
    Region->Protection = mbi.Protect;
    Region->Type = mbi.Type;

    Region->IsExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    Region->IsWritable = (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

    /* 区域类型判定 (GetMemoryRegionInfo L1487-1530) */
    if (mbi.State == MEM_FREE) {
        Region->RegionType = SpdDest_FreeMemory;
    } else if (mbi.State == MEM_RESERVE) {
        Region->RegionType = SpdDest_ReservedMemory;
    } else if (mbi.Protect & PAGE_GUARD) {
        Region->RegionType = SpdDest_GuardPage;
    } else if (mbi.Type == MEM_IMAGE) {
        Region->RegionType = SpdDest_ImageSection;

        /* 尝试取模块名 */
        if (GetMappedFileNameW(hProcess, (LPVOID)Address,
                               Region->ModuleName,
                               (DWORD)ARRAYSIZE(Region->ModuleName)) == 0) {
            Region->ModuleName[0] = 0;
        }
    } else if (mbi.Type == MEM_MAPPED) {
        Region->RegionType = SpdDest_MappedFile;
    } else if (mbi.Type == MEM_PRIVATE) {
        /* 可能为堆 / 栈 / 私有分配 */

        /* 先判有效栈 */
        if (SpdIsOnValidStack(ProcessId, Address)) {
            Region->RegionType = SpdDest_ValidStack;
        } else {
            /* 仅对当前进程做堆分类 — 远程进程 GetProcessHeaps 无效
               (L1511-1524) */
            if (ProcessId == (ULONG)GetCurrentProcessId()) {
                HANDLE heaps[256];
                DWORD heapCount;
                DWORD j;

                heapCount = GetProcessHeaps((DWORD)ARRAYSIZE(heaps), heaps);
                for (j = 0; j < heapCount && j < (DWORD)ARRAYSIZE(heaps); ++j) {
                    if (Region->AllocationBase == (UINT64)heaps[j]) {
                        isHeap = TRUE;
                        break;
                    }
                }
            }
            Region->RegionType = isHeap ? SpdDest_Heap : SpdDest_PrivateMemory;
        }
    } else {
        Region->RegionType = SpdDest_Unknown;
    }

    CloseHandle(hProcess);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
SPD_PIVOT_DEST_TYPE
SpdGetRegionType(
    ULONG  ProcessId,
    UINT64 Address
    )
{
    SPD_MEMORY_REGION region;

    if (SpdGetMemoryRegionInfo(ProcessId, Address, &region) == STATUS_SUCCESS) {
        return region.RegionType;
    }

    return SpdDest_Unknown;
}

_Use_decl_annotations_
BOOLEAN
SpdIsHeapAddress(
    ULONG  ProcessId,
    UINT64 Address
    )
{
    return SpdGetRegionType(ProcessId, Address) == SpdDest_Heap;
}

_Use_decl_annotations_
BOOLEAN
SpdIsImageAddress(
    ULONG  ProcessId,
    UINT64 Address
    )
{
    return SpdGetRegionType(ProcessId, Address) == SpdDest_ImageSection;
}

/**************************************************/
/*               进程监控                           */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
SpdMonitorProcess(
    ULONG ProcessId
    )
{
    ULONG i;
    BOOLEAN inserted = FALSE;

    AcquireSRWLockExclusive(&g_MonitorLock);

    if (ProcessId == 0) {
        ReleaseSRWLockExclusive(&g_MonitorLock);
        return FALSE;
    }

    for (i = 0; i < g_MonitoredCount; ++i) {
        if (g_MonitoredProcesses[i] == ProcessId) {
            ReleaseSRWLockExclusive(&g_MonitorLock);
            return FALSE;                       /* 已存在 (set::insert .second=false) */
        }
    }

    if (g_MonitoredCount < SPD_MAX_MONITORED_PROCESSES) {
        g_MonitoredProcesses[g_MonitoredCount++] = ProcessId;
        inserted = TRUE;
    }

    ReleaseSRWLockExclusive(&g_MonitorLock);

    if (inserted) {
        /* 监控锁外刷新栈限制 (对齐 SS: 避免持监控锁做 IO) */
        SpdRefreshStackLimitsForProcess(ProcessId);
    }

    return inserted;
}

_Use_decl_annotations_
VOID
SpdStopMonitoring(
    ULONG ProcessId
    )
{
    ULONG i;

    AcquireSRWLockExclusive(&g_MonitorLock);
    for (i = 0; i < g_MonitoredCount; ++i) {
        if (g_MonitoredProcesses[i] == ProcessId) {
            /* 尾元素前移, 保持紧凑 */
            --g_MonitoredCount;
            g_MonitoredProcesses[i] = g_MonitoredProcesses[g_MonitoredCount];
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_MonitorLock);
}

_Use_decl_annotations_
BOOLEAN
SpdIsMonitoring(
    ULONG ProcessId
    )
{
    ULONG i;
    BOOLEAN found = FALSE;

    AcquireSRWLockShared(&g_MonitorLock);
    for (i = 0; i < g_MonitoredCount; ++i) {
        if (g_MonitoredProcesses[i] == ProcessId) {
            found = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(&g_MonitorLock);

    return found;
}

_Use_decl_annotations_
NTSTATUS
SpdGetMonitoredProcesses(
    PULONG  Pids,
    ULONG   MaxPids,
    PULONG  pReturned
    )
{
    ULONG i;

    if (Pids == NULL && MaxPids != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (pReturned != NULL) {
        *pReturned = 0;
    }

    AcquireSRWLockShared(&g_MonitorLock);
    for (i = 0; i < g_MonitoredCount; ++i) {
        if (Pids != NULL && i < MaxPids) {
            Pids[i] = g_MonitoredProcesses[i];
        }
    }
    if (pReturned != NULL) {
        *pReturned = g_MonitoredCount;
    }
    ReleaseSRWLockShared(&g_MonitorLock);

    return STATUS_SUCCESS;
}

/**************************************************/
/*               内核集成                           */
/**************************************************/

_Use_decl_annotations_
VOID
SpdProcessKernelMemoryAlert(
    ULONG  ProcessId,
    UINT64 Address,
    SIZE_T Size,
    ULONG  Protection
    )
{
    const BOOLEAN isWritable =
        (Protection & (PAGE_READWRITE | PAGE_WRITECOPY |
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    UINT64 alertEnd;
    HANDLE snapshot;
    THREADENTRY32 te32;
    SIZE_T inspectedThreads = 0;

    /* 仅运行态处理 (SS 用 m_status + m_acceptingKernelAlerts 双标志,
       C 版以状态 Running 等价) */
    if (!SpdIsInitialized()) {
        return;
    }

    /* 栈迁移通常以 RW/RWX 私有分配作伪栈 (L2236-2244) */
    if (!isWritable || Size < SPD_MIN_STACK_SIZE) {
        return;
    }

    /* 溢出检查 (L2246-2251) */
    if (Address > (UINT64)-1 - (UINT64)Size) {
        return;
    }
    alertEnd = Address + (UINT64)Size;

    /* 仅检查受监控进程 */
    if (!SpdIsMonitoring(ProcessId)) {
        return;
    }

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    memset(&te32, 0, sizeof(te32));
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(snapshot, &te32)) {
        CloseHandle(snapshot);
        return;
    }

    do {
        HANDLE hThread;
        CONTEXT ctx;

        if (te32.th32OwnerProcessID != ProcessId) {
            continue;
        }

        /* 单轮线程检查硬上限 (MAX_KERNEL_ALERT_THREADS_INSPECTED) */
        if (++inspectedThreads > SPD_MAX_KERNEL_ALERT_THREADS) {
            break;
        }

        hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                             FALSE, te32.th32ThreadID);
        if (hThread == NULL) {
            continue;
        }

        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_CONTROL;

        if (GetThreadContext(hThread, &ctx)) {
#ifdef _WIN64
            const UINT64 rsp = ctx.Rsp;
            const UINT64 rip = ctx.Rip;
#else
            const UINT64 rsp = (UINT64)ctx.Esp;
            const UINT64 rip = (UINT64)ctx.Eip;
#endif
            /* RSP 落入告警内存区 — 判定迁移 */
            if (rsp >= Address && rsp < alertEnd) {
                SPD_DETECTION_EVENT event;

                /* SS 在 DetectPivot 后追加 "[Kernel memory alert
                   correlated]" 并做跨模块相关性提升
                   (CorrelateWithExploitChain, 依赖 HeapSprayDetector /
                   ROPProtection, 已裁剪)。SpdDetectPivot 内部已上报
                   回调并写入历史, 此处不重复处理。 */
                (void)SpdDetectPivot(ProcessId, te32.th32ThreadID, rsp, rip, &event);
            }
        }

        CloseHandle(hThread);
    } while (Thread32Next(snapshot, &te32));

    CloseHandle(snapshot);
}

/**************************************************/
/*               统计 / 历史                        */
/**************************************************/

_Use_decl_annotations_
VOID
SpdGetStatistics(
    PSPD_STATISTICS Stats
    )
{
    if (Stats == NULL) {
        return;
    }

    memcpy(Stats, (void*)&g_Stats, sizeof(*Stats));
    Stats->UptimeSeconds = (ULONG)((GetTickCount64() - g_StartTick) / 1000);
}

_Use_decl_annotations_
VOID
SpdResetStatistics(VOID)
{
    ULONG i;

    InterlockedExchange(&g_Stats.ChecksPerformed, 0);
    InterlockedExchange(&g_Stats.ThreadsMonitored, 0);
    InterlockedExchange(&g_Stats.PivotsDetected, 0);
    InterlockedExchange(&g_Stats.HeapPivots, 0);
    InterlockedExchange(&g_Stats.DataPivots, 0);
    InterlockedExchange(&g_Stats.ImagePivots, 0);
    InterlockedExchange(&g_Stats.AttacksBlocked, 0);
    InterlockedExchange(&g_Stats.ProcessesTerminated, 0);
    for (i = 0; i < SPD_TECHNIQUE_SLOTS; ++i) {
        InterlockedExchange(&g_Stats.ByTechnique[i], 0);
    }
    g_Stats.UptimeSeconds = 0;
    g_StartTick = GetTickCount64();
}

_Use_decl_annotations_
ULONG
SpdGetRecentDetections(
    PSPD_DETECTION_EVENT Events,
    ULONG                MaxEvents,
    PULONG               pReturned
    )
{
    ULONG count;
    ULONG i;
    ULONG idx;

    if (Events == NULL && MaxEvents != 0) {
        if (pReturned != NULL) {
            *pReturned = 0;
        }
        return 0;
    }

    AcquireSRWLockShared(&g_DetectionLock);

    count = (g_DetectionCount < MaxEvents) ? g_DetectionCount : MaxEvents;
    if (pReturned != NULL) {
        *pReturned = count;
    }

    /* 最新在前 (rbegin 倒序) */
    for (i = 0; i < count; ++i) {
        idx = (g_DetectionHead + SPD_MAX_RECENT_DETECTIONS - 1 - i) %
              SPD_MAX_RECENT_DETECTIONS;
        if (Events != NULL) {
            Events[i] = g_RecentDetections[idx];
        }
    }

    ReleaseSRWLockShared(&g_DetectionLock);

    return count;
}

_Use_decl_annotations_
BOOLEAN
SpdSelfTest(VOID)
{
    SPD_STACK_RANGE range;
    SPD_CONFIG defaultConfig = SPD_DEFAULT_CONFIG;
    UINT64 key1;
    UINT64 key2;
    UCHAR gadget1[] = { 0x87, 0xE0 };       /* XCHG ESP,EAX        */
    UCHAR gadget2[] = { 0x48, 0x87, 0xE0 }; /* XCHG RSP,RAX (x64)  */
    UCHAR gadget3[] = { SPD_LEAVE_OPCODE, 0xC3 }; /* LEAVE; RET    */

    /* Test 1: 栈范围验证 (SelfTest L1743-1767) */
    memset(&range, 0, sizeof(range));
    range.ThreadId = 0;
    range.StackBase = 0x00007FF000000000ULL;
    range.StackLimit = 0x00007FEFFFFF0000ULL;
    range.StackSize = (SIZE_T)(range.StackBase - range.StackLimit);

    /* 有效地址 */
    if (!SPD_RANGE_CONTAINS(&range, 0x00007FEFFFFE0000ULL)) {
        return FALSE;
    }
    /* 过高地址 (超出基址) */
    if (SPD_RANGE_CONTAINS(&range, 0x00007FF000010000ULL)) {
        return FALSE;
    }
    /* 过低地址 (低于下限) */
    if (SPD_RANGE_CONTAINS(&range, 0x00007FEFFFEE0000ULL)) {
        return FALSE;
    }

    /* Test 2: gadget 检测 (L1769-1791) */
    if (!SpdIsPivotGadgetBytes(gadget1, (ULONG)sizeof(gadget1))) {
        return FALSE;
    }
    if (!SpdIsPivotGadgetBytes(gadget2, (ULONG)sizeof(gadget2))) {
        return FALSE;
    }
    if (!SpdIsPivotGadgetBytes(gadget3, (ULONG)sizeof(gadget3))) {
        return FALSE;
    }

    /* Test 3: 配置有效性 (L1793-1800) */
    if (!SpdpIsValidConfig(&defaultConfig)) {
        return FALSE;
    }

    /* Test 4: 缓存键生成与还原 (L1802-1820) */
    key1 = SpdpMakeCacheKey(1234, 5678);
    key2 = SpdpMakeCacheKey(1234, 5679);

    if (key1 == key2) {
        return FALSE;                           /* 唯一性 */
    }
    if ((ULONG)(key1 >> 32) != 1234 || (ULONG)(key1 & 0xFFFFFFFFULL) != 5678) {
        return FALSE;                           /* pid/tid 还原 */
    }

    return TRUE;
}

/**************************************************/
/*               回调                              */
/**************************************************/

_Use_decl_annotations_
VOID
SpdRegisterCallback(
    SPD_DETECTED_CALLBACK Callback,
    PVOID                 Context
    )
{
    AcquireSRWLockExclusive(&g_CallbackLock);
    g_Callback = Callback;
    g_CallbackContext = Context;
    ReleaseSRWLockExclusive(&g_CallbackLock);
}

/**************************************************/
/*               工具函数                           */
/**************************************************/

_Use_decl_annotations_
PCSTR
SpdGetDestinationTypeName(
    SPD_PIVOT_DEST_TYPE Type
    )
{
    switch (Type) {
    case SpdDest_ValidStack:      return "Valid Stack";
    case SpdDest_Heap:            return "Heap";
    case SpdDest_ImageSection:    return "Image Section";
    case SpdDest_DataSection:     return "Data Section";
    case SpdDest_MappedFile:      return "Mapped File";
    case SpdDest_PrivateMemory:   return "Private Memory";
    case SpdDest_SharedMemory:    return "Shared Memory";
    case SpdDest_GuardPage:       return "Guard Page";
    case SpdDest_ReservedMemory:  return "Reserved Memory";
    case SpdDest_FreeMemory:      return "Free Memory";
    case SpdDest_OtherThreadStack: return "Other Thread Stack";
    case SpdDest_KernelStack:     return "Kernel Stack";
    default:                      return "Unknown";
    }
}

_Use_decl_annotations_
PCSTR
SpdGetTechniqueName(
    SPD_PIVOT_TECHNIQUE Technique
    )
{
    switch (Technique) {
    case SpdTech_XchgEspEax:      return "XCHG ESP,EAX";
    case SpdTech_XchgRspRax:      return "XCHG RSP,RAX";
    case SpdTech_MovEspReg:       return "MOV ESP,reg";
    case SpdTech_MovRspReg:       return "MOV RSP,reg";
    case SpdTech_PopEsp:          return "POP ESP";
    case SpdTech_PopRsp:          return "POP RSP";
    case SpdTech_LeaveRet:        return "LEAVE; RET";
    case SpdTech_AddEspImm:       return "ADD ESP,imm";
    case SpdTech_SubEspImm:       return "SUB ESP,imm";
    case SpdTech_PushSpRet:       return "PUSH ESP; RET";
    case SpdTech_CallStackPivot:  return "CALL pivot gadget";
    case SpdTech_LongjmpAbuse:    return "longjmp abuse";
    case SpdTech_ExceptionDispatch: return "Exception handler";
    case SpdTech_FiberSwitch:     return "Fiber switch";
    default:                      return "Unknown";
    }
}

_Use_decl_annotations_
PCSTR
SpdGetValidationResultName(
    SPD_VALIDATION_RESULT Result
    )
{
    switch (Result) {
    case SpdValid_Valid:          return "Valid";
    case SpdValid_PivotDetected:  return "Pivot Detected";
    case SpdValid_NearGuardPage:  return "Near Guard Page";
    case SpdValid_Overflow:       return "Stack Overflow";
    case SpdValid_Underflow:      return "Stack Underflow";
    case SpdValid_InvalidBounds:  return "Invalid Bounds";
    default:                      return "Unknown";
    }
}

_Use_decl_annotations_
BOOLEAN
SpdIsPivotGadgetBytes(
    const UCHAR* Bytes,
    ULONG        ByteCount
    )
{
    ULONG i;

    if (Bytes == NULL || ByteCount == 0) {
        return FALSE;
    }

    /* 1 字节 x86 gadget */
    for (i = 0; i < ARRAYSIZE(g_SpdPivotGadgets1B); ++i) {
        if (Bytes[0] == g_SpdPivotGadgets1B[i]) {
            return TRUE;
        }
    }

    /* 2 字节 x86 gadget */
    if (ByteCount >= 2) {
        for (i = 0; i < ARRAYSIZE(g_SpdPivotGadgets2B); ++i) {
            if (Bytes[0] == g_SpdPivotGadgets2B[i][0] &&
                Bytes[1] == g_SpdPivotGadgets2B[i][1]) {
                return TRUE;
            }
        }

        /* x64 POP RSP (2 字节) */
        if (Bytes[0] == g_SpdPopRspGadget[0] && Bytes[1] == g_SpdPopRspGadget[1]) {
            return TRUE;
        }
    }

    /* 3 字节 x64 gadget */
    if (ByteCount >= 3) {
        for (i = 0; i < ARRAYSIZE(g_SpdPivotGadgetsX64); ++i) {
            if (Bytes[0] == g_SpdPivotGadgetsX64[i][0] &&
                Bytes[1] == g_SpdPivotGadgetsX64[i][1] &&
                Bytes[2] == g_SpdPivotGadgetsX64[i][2]) {
                return TRUE;
            }
        }
    }

    /* LEAVE+RET 序列 (裸 LEAVE 误报率高, 要求 RET 结尾 —
       L2095-2098) */
    if (ByteCount >= 2 && Bytes[0] == SPD_LEAVE_OPCODE && Bytes[1] == 0xC3) {
        return TRUE;
    }

    return FALSE;
}

_Use_decl_annotations_
SPD_PIVOT_TECHNIQUE
SpdIdentifyPivotTechnique(
    const UCHAR* Bytes,
    ULONG        ByteCount
    )
{
    if (Bytes == NULL || ByteCount == 0) {
        return SpdTech_Unknown;
    }

    /* x64 3 字节 pattern (先于 2 字节匹配, L2108-2141) */
    if (ByteCount >= 3) {
        /* XCHG RSP,RAX 变体 */
        if (Bytes[0] == 0x48 && Bytes[1] == 0x87 &&
            (Bytes[2] == 0xE0 || Bytes[2] == 0xC4)) {
            return SpdTech_XchgRspRax;
        }

        /* MOV RSP,reg (x64) */
        if (Bytes[0] == 0x48 && Bytes[1] == 0x8B &&
            Bytes[2] >= 0xE0 && Bytes[2] <= 0xE7) {
            return SpdTech_MovRspReg;
        }

        /* ADD RSP,imm8 / imm32 */
        if (Bytes[0] == 0x48 && Bytes[1] == 0x83 && Bytes[2] == 0xC4) {
            return SpdTech_AddEspImm;
        }
        if (Bytes[0] == 0x48 && Bytes[1] == 0x81 && Bytes[2] == 0xC4) {
            return SpdTech_AddEspImm;
        }

        /* SUB RSP,imm8 / imm32 */
        if (Bytes[0] == 0x48 && Bytes[1] == 0x83 && Bytes[2] == 0xEC) {
            return SpdTech_SubEspImm;
        }
        if (Bytes[0] == 0x48 && Bytes[1] == 0x81 && Bytes[2] == 0xEC) {
            return SpdTech_SubEspImm;
        }
    }

    /* x86 2 字节 pattern (L2144-2200) */
    if (ByteCount >= 2) {
        /* XCHG ESP,EAX (ModR/M 形式) */
        if ((Bytes[0] == 0x87 && Bytes[1] == 0xE0) ||
            (Bytes[0] == 0x87 && Bytes[1] == 0xC4)) {
            return SpdTech_XchgEspEax;
        }

        /* POP RSP (x64: REX.B 0x41, 0x5C) */
        if (Bytes[0] == 0x41 && Bytes[1] == 0x5C) {
            return SpdTech_PopRsp;
        }

        /* MOV ESP,reg (x86) */
        if (Bytes[0] == 0x8B && Bytes[1] >= 0xE0 && Bytes[1] <= 0xE7) {
            return SpdTech_MovEspReg;
        }

        /* ADD ESP,imm8 / imm32 */
        if (Bytes[0] == 0x83 && Bytes[1] == 0xC4) {
            return SpdTech_AddEspImm;
        }
        if (Bytes[0] == 0x81 && Bytes[1] == 0xC4) {
            return SpdTech_AddEspImm;
        }

        /* SUB ESP,imm8 / imm32 */
        if (Bytes[0] == 0x83 && Bytes[1] == 0xEC) {
            return SpdTech_SubEspImm;
        }
        if (Bytes[0] == 0x81 && Bytes[1] == 0xEC) {
            return SpdTech_SubEspImm;
        }

        /* PUSH ESP; RET (PUSH RSP; RET 同编码) */
        if (Bytes[0] == 0x54 && Bytes[1] == 0xC3) {
            return SpdTech_PushSpRet;
        }

        /* JMP ESP / JMP RSP */
        if (Bytes[0] == 0xFF && Bytes[1] == 0xE4) {
            return SpdTech_CallStackPivot;
        }

        /* CALL ESP / CALL RSP */
        if (Bytes[0] == 0xFF && Bytes[1] == 0xD4) {
            return SpdTech_CallStackPivot;
        }

        /* LEAVE; RET 序列 */
        if (Bytes[0] == SPD_LEAVE_OPCODE && Bytes[1] == 0xC3) {
            return SpdTech_LeaveRet;
        }
    }

    /* 1 字节 pattern (L2202-2211) */
    /* XCHG ESP,EAX (短形式 0x94) */
    if (Bytes[0] == 0x94) {
        return SpdTech_XchgEspEax;
    }

    /* POP ESP (x86: 0x5C) */
    if (Bytes[0] == 0x5C) {
        return SpdTech_PopEsp;
    }

    return SpdTech_Unknown;
}  /* SpdIdentifyPivotTechnique */