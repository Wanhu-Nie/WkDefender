/**************************************************/
/*  WkDefender 线程画像分析实现                     */
/*  迁移自 ShadowStrike ProcessAnalyzer            */
/*  AnalyzeThreadsInternal + GetThreadInfoInternal */
/**************************************************/

#include "ProcessThreads.h"
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <string.h>
#include "process_manager.h"                 /* WptTerminateAttacker 委托处置引擎 */
#include "IOA/Tier1/T1ShellcodeDetect.h"   /* IocDetectShellcode (RIP 处壳码判定) */

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "dbghelp.lib")

/**************************************************/
/*           模块列表（预枚举一次）                 */
/**************************************************/

typedef struct _WPT_MODULE_ENTRY {
    ULONG_PTR Base;
    SIZE_T    Size;
    WCHAR     Name[64];
} WPT_MODULE_ENTRY, *PWPT_MODULE_ENTRY;

#define WPT_MAX_MODULES 1024

static ULONG
WptEnumerateModules(
    _In_  DWORD             ProcessId,
    _Out_ PWPT_MODULE_ENTRY Modules,
    _In_  ULONG             Max
    )
{
    HANDLE hSnapshot;
    MODULEENTRY32W me;
    ULONG count = 0;

    hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    me.dwSize = sizeof(me);
    if (Module32FirstW(hSnapshot, &me)) {
        do {
            if (count >= Max) break;
            Modules[count].Base = (ULONG_PTR)me.modBaseAddr;
            Modules[count].Size = me.modBaseSize;
            wcsncpy_s(Modules[count].Name, RTL_NUMBER_OF(Modules[count].Name),
                      me.szModule, _TRUNCATE);
            count++;
        } while (Module32NextW(hSnapshot, &me));
    }

    CloseHandle(hSnapshot);
    return count;
}

static BOOLEAN
WptResolveStartModule(
    _In_  ULONG_PTR Start,
    _In_  const PWPT_MODULE_ENTRY Modules,
    _In_  ULONG      Count,
    _Out_writes_(OutCch) WCHAR* OutName,
    _In_  ULONG      OutCch
    )
{
    ULONG i;
    for (i = 0; i < Count; i++) {
        if (Start >= Modules[i].Base &&
            Start < Modules[i].Base + Modules[i].Size) {
            wcsncpy_s(OutName, OutCch, Modules[i].Name, _TRUNCATE);
            return TRUE;
        }
    }
    return FALSE;
}

/**************************************************/
/*        NtQueryInformationThread 起始地址        */
/**************************************************/

typedef NTSTATUS (NTAPI* PNtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);

/* 文件级 NtQueryInformationThread 解析 (一次性, 跨函数复用) */
static PNtQueryInformationThread
WptGetNtQuery(VOID)
{
    static PNtQueryInformationThread pNtQuery = NULL;

    if (!pNtQuery) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            pNtQuery = (PNtQueryInformationThread)
                GetProcAddress(hNtdll, "NtQueryInformationThread");
        }
    }
    return pNtQuery;
}

static ULONG_PTR
WptQueryStartAddress(
    _In_ HANDLE hThread
    )
{
    PNtQueryInformationThread pNtQuery = WptGetNtQuery();
    ULONG_PTR start = 0;
    ULONG retLen = 0;
    NTSTATUS status;

    if (!pNtQuery) return 0;

    /* ThreadQuerySetWin32StartAddress = 9 */
    status = pNtQuery(hThread, 9, &start, sizeof(start), &retLen);
    if (status < 0) return 0;
    return start;
}

/**************************************************/
/*               主入口                           */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
WptAnalyzeThreads(
    DWORD               ProcessId,
    PWKD_THREAD_PROFILE Profile
    )
/*++
Routine Description:
    分析指定进程的全部线程：枚举线程，查询起始地址，
    判断起始地址是否落在已加载模块内（模块支撑判定）。

Arguments:
    ProcessId - 目标进程 PID。
    Profile   - 输出线程画像结果。

Return Value:
    NTSTATUS。
--*/
{
    WPT_MODULE_ENTRY modules[WPT_MAX_MODULES];
    ULONG modCount;
    HANDLE hSnapshot;
    THREADENTRY32 te;

    if (!Profile) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Profile, sizeof(*Profile));

    if (ProcessId == 0 || ProcessId == 4) return STATUS_SUCCESS;

    /* 预枚举模块一次，避免 O(线程 * 模块) 比对（对齐 PS 缓存模块列表） */
    modCount = WptEnumerateModules(ProcessId, modules, WPT_MAX_MODULES);

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return STATUS_SUCCESS;

    te.dwSize = sizeof(te);
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID != ProcessId) continue;

            Profile->TotalThreads++;
            if (Profile->AnalyzedCount >= WKD_THREAD_MAX_ANALYZE) break;

            PWKD_THREAD_INFO ti = &Profile->Threads[Profile->AnalyzedCount];
            ti->ThreadId = te.th32ThreadID;
            ti->OwnerPid = ProcessId;

            HANDLE hThread = OpenThread(
                THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                FALSE, te.th32ThreadID);
            if (hThread) {
                ti->StartAddress = WptQueryStartAddress(hThread);
                CloseHandle(hThread);

                if (ti->StartAddress != 0) {
                    ti->IsStartAddressBacked = WptResolveStartModule(
                        ti->StartAddress, modules, modCount,
                        ti->StartAddressModule, RTL_NUMBER_OF(ti->StartAddressModule));

                    if (ti->IsStartAddressBacked) {
                        /* 起始地址落 kernel32/kernelbase → LoadLibrary 远程线程靶点
                         *（对齐 PS StartAtExportedFunction 嫌疑） */
                        if (_wcsicmp(ti->StartAddressModule, L"kernel32.dll") == 0 ||
                            _wcsicmp(ti->StartAddressModule, L"kernelbase.dll") == 0) {
                            ti->Suspicion = WkdTs_StartAtExportedFunction;
                            ti->RiskScore = 20;
                        }
                    } else {
                        /* 起始地址不在任何已知模块 → 未支撑起始地址（对齐 PS riskScore=40） */
                        ti->Suspicion = WkdTs_UnbackedStartAddress;
                        ti->RiskScore = 40;
                        Profile->UnbackedStartCount++;
                    }
                }
            }

            Profile->AnalyzedCount++;
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return STATUS_SUCCESS;
}

/**************************************************/
/*   无背衬线程起始地址精确判定 (SS 补充)           */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
WptIsThreadStartUnbacked(
    DWORD Tid
    )
/*++
Routine Description:
    精确判定线程起始地址是否落在无背衬可执行区域。
    对齐 SS IsThreadStartUnbacked (ReflectiveDLLDetector.cpp L1390-1425):
      NtQueryInformationThread=9 取起始地址 → Toolhelp 定位所属进程 →
      VirtualQueryEx 查区域 (MEM_COMMIT + 可执行 + MEM_PRIVATE)。

Arguments:
    Tid - 线程 ID。

Return Value:
    TRUE = 起始地址在无背衬可执行区域 (或查询失败时为 FALSE)。
    ※ 死代码: WptAnalyzeThreads 已用模块表比对近似 (IsStartAddressBacked),
      本函数供反射加载线程入口精确确认, 当前无调用者。
--*/
{
    HANDLE hThread, hSnap, hProcess;
    THREADENTRY32 te;
    ULONG_PTR start;
    DWORD pid = 0;
    MEMORY_BASIC_INFORMATION mbi;
    BOOLEAN unbacked = FALSE;

    if (Tid == 0) return FALSE;

    hThread = OpenThread(
        THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
        FALSE, Tid);
    if (!hThread) return FALSE;
    start = WptQueryStartAddress(hThread);
    CloseHandle(hThread);
    if (start == 0) return FALSE;

    /* 定位所属进程 (对齐 SS Toolhelp 定位) */
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;
    te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32ThreadID == Tid) {
                pid = te.th32OwnerProcessID;
                break;
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    if (pid == 0) return FALSE;

    /* 查询起始地址所在区域类型/保护 (对齐 SS L1413-1424) */
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return FALSE;

    if (VirtualQueryEx(hProcess, (LPCVOID)start, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        unbacked = (mbi.State == MEM_COMMIT) &&
                   (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0 &&
                   (mbi.Type == MEM_PRIVATE);
    }

    CloseHandle(hProcess);
    return unbacked;
}

/**************************************************/
/*   调用栈无背衬帧统计 (SS CountUnbackedCallStack) */
/**************************************************/

/* dbghelp (StackWalk64/SymXxx) 非线程安全, 进程级全局串行 (对齐 SS DbgHelpMutex L334-337) */
static CRITICAL_SECTION g_WptDbgHelpCs;
static INIT_ONCE        g_WptDbgHelpOnce = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK
WptInitDbgHelpCs(
    _In_ PINIT_ONCE Once,
    _In_ PVOID      Param,
    _Inout_ PVOID*  Ctx
    )
{
    InitializeCriticalSection(&g_WptDbgHelpCs);
    return TRUE;
}

static VOID
WptEnsureDbgHelpLock(VOID)
{
    /* 无竞态一次性初始化 (对齐 SS static std::mutex 的线程安全语义) */
    InitOnceExecuteOnce(&g_WptDbgHelpOnce, WptInitDbgHelpCs, NULL, NULL);
}

_Use_decl_annotations_
ULONG
WptCountUnbackedCallStackFrames(
    DWORD Tid
    )
/*++
Routine Description:
    统计线程调用栈中未落任何已加载模块的帧数。
    对齐 SS CountUnbackedCallStackFrames (ReflectiveDLLDetector.cpp L1427-1508):
      挂起线程 (RAII 保证 Resume) → GetThreadContext → StackWalk64 →
      逐帧模块判定 (未模块帧计数)。

Arguments:
    Tid - 线程 ID。

Return Value:
    未模块帧数 (查询失败/不可挂起返回 0)。
    ※ 死代码: 成本高 (挂线程 + dbghelp 全局锁), 定位 Deep/Forensic 模式,
      当前无调用者。
--*/
{
    HANDLE hThread, hSnap, hProcess;
    THREADENTRY32 te;
    DWORD pid = 0;
    CONTEXT ctx;
    STACKFRAME64 frame;
    ULONG unbackedCount = 0;
    ULONG modCount;
    WPT_MODULE_ENTRY modules[WPT_MAX_MODULES];
    BOOLEAN suspended = FALSE;
    size_t i;
#ifdef _M_X64
    DWORD machineType = IMAGE_FILE_MACHINE_AMD64;
#else
    DWORD machineType = IMAGE_FILE_MACHINE_I386;
#endif

    if (Tid == 0) return 0;

    hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                         THREAD_QUERY_INFORMATION, FALSE, Tid);
    if (!hThread) return 0;

    /* 定位所属进程 (对齐 SS Toolhelp) */
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        te.dwSize = sizeof(te);
        if (Thread32First(hSnap, &te)) {
            do {
                if (te.th32ThreadID == Tid) {
                    pid = te.th32OwnerProcessID;
                    break;
                }
            } while (Thread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
    }
    if (pid == 0) {
        CloseHandle(hThread);
        return 0;
    }

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        CloseHandle(hThread);
        return 0;
    }

    /* 预枚举模块一次 (对齐 SS IsAddressInAnyModule 缓存) */
    modCount = WptEnumerateModules(pid, modules, WPT_MAX_MODULES);

    /* 挂起线程 — 保证所有出口 Resume (对齐 SS ScopedThreadSuspend RAII) */
    if (SuspendThread(hThread) == (DWORD)-1) {
        /* 保护/关键线程不可挂起 → 不走栈 (对齐 SS L1456-1460) */
        CloseHandle(hProcess);
        CloseHandle(hThread);
        return 0;
    }
    suspended = TRUE;

    RtlZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    if (GetThreadContext(hThread, &ctx)) {
        RtlZeroMemory(&frame, sizeof(frame));
#ifdef _M_X64
        frame.AddrPC.Offset    = ctx.Rip;
        frame.AddrFrame.Offset = ctx.Rbp;
        frame.AddrStack.Offset = ctx.Rsp;
#else
        frame.AddrPC.Offset    = ctx.Eip;
        frame.AddrFrame.Offset = ctx.Ebp;
        frame.AddrStack.Offset = ctx.Esp;
#endif
        frame.AddrPC.Mode    = AddrModeFlat;
        frame.AddrFrame.Mode = AddrModeFlat;
        frame.AddrStack.Mode = AddrModeFlat;

        /* dbghelp 全局串行 (对齐 SS DbgHelpMutex L1488) */
        WptEnsureDbgHelpLock();
        EnterCriticalSection(&g_WptDbgHelpCs);

        for (i = 0; i < 64; i++) {   /* 对齐 SS kMaxFrames=64 */
            WCHAR frameMod[64];
            if (!StackWalk64(machineType, hProcess, hThread, &frame, &ctx,
                             NULL, SymFunctionTableAccess64, SymGetModuleBase64,
                             NULL)) {
                break;
            }
            if (frame.AddrPC.Offset == 0) break;

            if (!WptResolveStartModule((ULONG_PTR)frame.AddrPC.Offset,
                                       modules, modCount,
                                       frameMod, RTL_NUMBER_OF(frameMod))) {
                unbackedCount++;
            }
        }

        LeaveCriticalSection(&g_WptDbgHelpCs);
    }

    if (suspended) {
        ResumeThread(hThread);   /* 对齐 SS ScopedThreadSuspend dtor */
    }

    CloseHandle(hProcess);
    CloseHandle(hThread);
    return unbackedCount;
}

/**************************************************/
/*   线程上下文验证工具 (T1055.003 迁移)           */
/*   ShadowStrike ThreadHijackDetector 迁移        */
/*   GetThreadContextInternal + GetThreadStackBounds */
/*   + ValidateThreadInternal + CalculateRiskScore */
/**************************************************/

/*
 * WptGetThreadContext — 读取线程上下文 (含 WoW64)。
 *
 * 对齐 SS GetThreadContextInternal (ThreadHijackDetector.cpp L1310-1415):
 *   32 位线程 (WoW64) 用 Wow64GetThreadContext 取 WOW64_CONTEXT 并投影到
 *   64 位结构 (否则 GetThreadContext 返回的是 ntdll wow64 转换栈的上下文,
 *   看不到攻击者的 32 位劫持状态)。
 * ※ 死代码: 供线程劫持定向确认与主动扫描使用, 当前无调用者。
 */
_Use_decl_annotations_
BOOLEAN
WptGetThreadContext(
    DWORD               Tid,
    PWKD_THREAD_CONTEXT64 Ctx
    )
{
    HANDLE hThread;
    DWORD pid = 0;
    BOOLEAN wow64 = FALSE;
    BOOLEAN ok = FALSE;

    if (!Ctx) return FALSE;
    RtlZeroMemory(Ctx, sizeof(*Ctx));
    if (Tid == 0) return FALSE;

    hThread = OpenThread(
        THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
        FALSE, Tid);
    if (!hThread) return FALSE;

    pid = GetProcessIdOfThread(hThread);
    if (pid != 0) {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc) {
            IsWow64Process(hProc, &wow64);
            CloseHandle(hProc);
        }
    }
    Ctx->IsWow64 = wow64;

#ifdef _M_X64
    if (wow64) {
        WOW64_CONTEXT c32;
        RtlZeroMemory(&c32, sizeof(c32));
        c32.ContextFlags = WOW64_CONTEXT_FULL | WOW64_CONTEXT_DEBUG_REGISTERS;
        if (Wow64GetThreadContext(hThread, &c32)) {
            Ctx->Rip = c32.Eip;   Ctx->Rsp = c32.Esp;   Ctx->Rbp = c32.Ebp;
            Ctx->Rax = c32.Eax;   Ctx->Rbx = c32.Ebx;   Ctx->Rcx = c32.Ecx;
            Ctx->Rdx = c32.Edx;   Ctx->Rsi = c32.Esi;   Ctx->Rdi = c32.Edi;
            Ctx->SegCs = c32.SegCs; Ctx->SegSs = c32.SegSs;
            Ctx->Dr0 = c32.Dr0;   Ctx->Dr1 = c32.Dr1;   Ctx->Dr2 = c32.Dr2;
            Ctx->Dr3 = c32.Dr3;   Ctx->Dr6 = c32.Dr6;   Ctx->Dr7 = c32.Dr7;
            ok = TRUE;
        }
    }
    if (!ok) {
        CONTEXT c;
        RtlZeroMemory(&c, sizeof(c));
        c.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(hThread, &c)) {
            Ctx->Rip = c.Rip;   Ctx->Rsp = c.Rsp;   Ctx->Rbp = c.Rbp;
            Ctx->Rax = c.Rax;   Ctx->Rbx = c.Rbx;   Ctx->Rcx = c.Rcx;
            Ctx->Rdx = c.Rdx;   Ctx->Rsi = c.Rsi;   Ctx->Rdi = c.Rdi;
            Ctx->R8  = c.R8;    Ctx->R9  = c.R9;    Ctx->R10 = c.R10;
            Ctx->R11 = c.R11;   Ctx->R12 = c.R12;   Ctx->R13 = c.R13;
            Ctx->R14 = c.R14;   Ctx->R15 = c.R15;
            Ctx->SegCs = c.SegCs; Ctx->SegSs = c.SegSs;
            Ctx->Dr0 = c.Dr0;   Ctx->Dr1 = c.Dr1;   Ctx->Dr2 = c.Dr2;
            Ctx->Dr3 = c.Dr3;   Ctx->Dr6 = c.Dr6;   Ctx->Dr7 = c.Dr7;
            ok = TRUE;
        }
    }
#else
    {
        CONTEXT c;
        RtlZeroMemory(&c, sizeof(c));
        c.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(hThread, &c)) {
            Ctx->Rip = c.Eip;   Ctx->Rsp = c.Esp;   Ctx->Rbp = c.Ebp;
            Ctx->SegCs = c.SegCs; Ctx->SegSs = c.SegSs;
            Ctx->Dr0 = c.Dr0;   Ctx->Dr1 = c.Dr1;   Ctx->Dr2 = c.Dr2;
            Ctx->Dr3 = c.Dr3;   Ctx->Dr6 = c.Dr6;   Ctx->Dr7 = c.Dr7;
            ok = TRUE;
        }
    }
#endif

    CloseHandle(hThread);
    return ok;
}

/*
 * WptGetThreadStackBounds — 读取线程 TEB 栈边界 (StackBase/StackLimit)。
 *
 * 对齐 SS GetThreadStackBounds (ThreadHijackDetector.cpp L463-526):
 *   NtQueryInformationThread(ThreadBasicInformation=0) 取 TebBaseAddress →
 *   ReadProcessMemory 读 NT_TIB 栈边界。
 *     x64: StackBase@+0x08, StackLimit@+0x10
 *     WoW64: 32 位 TEB 位于 TebBaseAddress+0x2000, StackBase@+0x04, StackLimit@+0x08
 *   Reject 明显非法值 (零/内核页/颠倒), 避免 RSP 校验失真。
 * ※ 死代码: agent 侧此前无 TEB 读取实现, 本函数为线程劫持/栈验证核心。
 */
_Use_decl_annotations_
BOOLEAN
WptGetThreadStackBounds(
    DWORD               Tid,
    PULONG_PTR          StackBase,
    PULONG_PTR          StackLimit
    )
{
    PNtQueryInformationThread pNtQuery;
    HANDLE hThread;
    HANDLE hProc;
    DWORD pid = 0;
    BOOLEAN wow64 = FALSE;
    struct {
        LONG            ExitStatus;
        ULONG_PTR       TebBaseAddress;
        ULONG_PTR       ClientIdProcess;
        ULONG_PTR       ClientIdThread;
    } tbi;
    ULONG retLen = 0;
    NTSTATUS status;
    BOOLEAN ok = FALSE;
    SIZE_T rd = 0;

    if (!StackBase || !StackLimit) return FALSE;
    if (Tid == 0) return FALSE;

    pNtQuery = WptGetNtQuery();
    if (!pNtQuery) return FALSE;

    hThread = OpenThread(
        THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
        FALSE, Tid);
    if (!hThread) return FALSE;

    pid = GetProcessIdOfThread(hThread);
    if (pid != 0) {
        HANDLE hChk = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hChk) {
            IsWow64Process(hChk, &wow64);
            CloseHandle(hChk);
        }
    }

    RtlZeroMemory(&tbi, sizeof(tbi));
    status = pNtQuery(hThread, 0 /* ThreadBasicInformation */,
                      &tbi, sizeof(tbi), &retLen);
    CloseHandle(hThread);
    if (status < 0 || tbi.TebBaseAddress == 0) return FALSE;

    hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
                        FALSE, pid);
    if (!hProc) return FALSE;

    if (wow64) {
        /* 32 位 TEB: TebBaseAddress + 0x2000, NT_TIB32 StackBase@+0x04/StackLimit@+0x08 */
        ULONG_PTR teb32 = tbi.TebBaseAddress + 0x2000;
        ULONG base32 = 0, limit32 = 0;
        if (ReadProcessMemory(hProc, (LPCVOID)(teb32 + 0x04), &base32,
                              sizeof(base32), &rd) && rd == sizeof(base32) &&
            ReadProcessMemory(hProc, (LPCVOID)(teb32 + 0x08), &limit32,
                              sizeof(limit32), &rd) && rd == sizeof(limit32)) {
            *StackBase = base32;
            *StackLimit = limit32;
            ok = TRUE;
        }
    } else {
        /* x64 NT_TIB: StackBase@+0x08, StackLimit@+0x10 */
        ULONG_PTR buf[2];
        if (ReadProcessMemory(hProc, (LPCVOID)(tbi.TebBaseAddress + 0x08),
                              buf, sizeof(buf), &rd) && rd == sizeof(buf)) {
            *StackBase = buf[0];
            *StackLimit = buf[1];
            ok = TRUE;
        }
    }

    CloseHandle(hProc);

    /* Reject 明显非法值 (对齐 SS L524-525): 零/颠倒/内核页/超用户空间 */
    if (ok) {
        if (*StackBase <= *StackLimit ||
            *StackBase <= 0x10000 ||
            *StackBase > 0x7FFFFFFFFFFFULL) {
            ok = FALSE;
        }
    }
    return ok;
}

/*
 * WptIsAddressInRwxPrivate — 地址区域 RWX 私有判定。
 * 对齐 SS IsAddressInRWXPrivate (ThreadHijackDetector.cpp L410-438) 的
 * VirtualQueryEx 路径: MEM_PRIVATE + PAGE_EXECUTE*。
 */
static BOOLEAN
WptIsAddressInRwxPrivate(
    _In_ DWORD       pid,
    _In_ ULONG_PTR   address
    )
{
    HANDLE hProc;
    MEMORY_BASIC_INFORMATION mbi;
    BOOLEAN rwx = FALSE;

    hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return FALSE;

    if (VirtualQueryEx(hProc, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        rwx = (mbi.Type == MEM_PRIVATE) &&
              (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                              PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    }
    CloseHandle(hProc);
    return rwx;
}

/*
 * WptHasShellcodeAt — RIP 处内存壳码判定。
 * 对齐 SS HasShellcodeAtAddress (ThreadHijackDetector.cpp L321-387):
 *   校验用户态地址范围 → ReadProcessMemory 读 256 字节 →
 *   委托 IocDetectShellcode 做 T1_SC_* 特征匹配
 *   (NOP sled / GetPC / API hash / syscall stub / ROP 链),
 *   区域 MEM_PRIVATE 属性作为 ROP 检测前置输入。
 */
static BOOLEAN
WptHasShellcodeAt(
    _In_ DWORD       pid,
    _In_ ULONG_PTR   address
    )
{
    HANDLE hProc;
    UCHAR buffer[256];
    SIZE_T rd = 0;
    MEMORY_BASIC_INFORMATION mbi;
    BOOLEAN isPrivate = FALSE;

    /* 用户态地址合法性 + 读长度防回绕 (对齐 SS L345-347) */
    if (address < 0x10000 ||
        address > 0x7FFFFFFFFFFFULL ||
        address > (0x7FFFFFFFFFFFULL - sizeof(buffer))) {
        return FALSE;
    }

    hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                        FALSE, pid);
    if (!hProc) return FALSE;

    if (VirtualQueryEx(hProc, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        isPrivate = (mbi.Type == MEM_PRIVATE);
    }

    if (!ReadProcessMemory(hProc, (LPCVOID)address, buffer,
                           sizeof(buffer), &rd)) {
        CloseHandle(hProc);
        return FALSE;
    }
    CloseHandle(hProc);

    if (rd < 20) return FALSE;   /* 过短不足以判定 (对齐 SS L356) */

    return (IocDetectShellcode(buffer, rd, isPrivate) != 0);
}

/*
 * WptValidateThread — 综合验证线程上下文 → 风险分。
 *
 * 对齐 SS ValidateThreadInternal (ThreadHijackDetector.cpp L889-1081) +
 * CalculateRiskScore (L531-551):
 *   unbacked RIP +40 / shellcode +25 / RWX 私有 +15 / 栈翻转 +15 /
 *   段异常 +30 / 调试寄存器 +10 / 调用栈无背衬帧(>1) +25 / 跨进程 +20。
 *   IsCompromised = 风险分 ≥40 或栈翻转或 RIP 无背衬。
 * ※ 死代码: 供线程劫持定向确认 (IoaConfirmThreadHijacking) 使用, 当前无调用者。
 */
_Use_decl_annotations_
NTSTATUS
WptValidateThread(
    DWORD               Tid,
    BOOLEAN             CrossProcess,
    BOOLEAN             AnalyzeCallStack,
    PWKD_THREAD_VALIDATION Val
    )
{
    WPT_MODULE_ENTRY modules[WPT_MAX_MODULES];
    ULONG modCount;
    ULONG risk = 0;
    DWORD pid = 0;
    HANDLE hSnap;
    THREADENTRY32 te;
    WCHAR modName[64];

    if (!Val) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Val, sizeof(*Val));
    Val->ThreadId = Tid;
    if (Tid == 0) return STATUS_INVALID_PARAMETER;

    /* 定位所属进程 (对齐 SS Toolhelp) */
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        te.dwSize = sizeof(te);
        if (Thread32First(hSnap, &te)) {
            do {
                if (te.th32ThreadID == Tid) {
                    pid = te.th32OwnerProcessID;
                    break;
                }
            } while (Thread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
    }
    Val->OwnerPid = pid;
    if (pid == 0) return STATUS_NOT_FOUND;

    /* 预枚举模块一次 (对齐 SS IsAddressInModule 缓存) */
    modCount = WptEnumerateModules(pid, modules, WPT_MAX_MODULES);

    /* 上下文读取 */
    if (!WptGetThreadContext(Tid, &Val->Ctx)) {
        return STATUS_UNSUCCESSFUL;
    }

    /* RIP 模块对照 */
    Val->RipIsBacked = WptResolveStartModule(
        Val->Ctx.Rip, modules, modCount,
        modName, RTL_NUMBER_OF(modName));
    if (!Val->RipIsBacked) {
        risk += 40;   /* unbacked RIP */
        Val->RipHasShellcode = (BOOLEAN)(WptHasShellcodeAt(pid, Val->Ctx.Rip) != 0);
        if (Val->RipHasShellcode) {
            risk += 25;
        }
        if (WptIsAddressInRwxPrivate(pid, Val->Ctx.Rip)) {
            Val->RipInRwxPrivate = TRUE;
            risk += 15;
        }
    }

    /* 栈边界 (TEB 校验, 失败回退 RSP 基本合理性) */
    if (WptGetThreadStackBounds(Tid, &Val->StackBase, &Val->StackLimit)) {
        Val->StackInRange =
            (Val->Ctx.Rsp >= Val->StackLimit && Val->Ctx.Rsp <= Val->StackBase);
        if (!Val->StackInRange) {
            Val->StackPivoted = TRUE;
            risk += 15;
        }
    } else {
        if (Val->Ctx.Rsp < 0x10000 || Val->Ctx.Rsp > 0x7FFFFFFFFFFFULL) {
            Val->StackPivoted = TRUE;
            risk += 15;
        } else {
            Val->StackInRange = TRUE;
        }
    }

    /* 段寄存器 (WoW64 豁免: 32 位线程 CS=0x1B) */
    if (Val->Ctx.IsWow64) {
        Val->SegmentsValid = (Val->Ctx.SegCs == 0x1B);
    } else {
        Val->SegmentsValid =
            (Val->Ctx.SegCs == 0x33 && Val->Ctx.SegSs == 0x2B);
    }
    if (!Val->SegmentsValid) {
        risk += 30;
    }

    /* 调试寄存器 (DR7 使能位, 对齐 SS HasActiveDebugRegistersInternal) */
    Val->HasHardwareBreakpoints = (Val->Ctx.Dr7 & 0xFF) != 0;
    if (Val->HasHardwareBreakpoints) {
        risk += 10;
    }

    /* 调用栈无背衬帧 (可选, 成本高: 挂线程 + dbghelp 全局锁) */
    if (AnalyzeCallStack) {
        Val->UnbackedFrameCount = WptCountUnbackedCallStackFrames(Tid);
        if (Val->UnbackedFrameCount > 1) {
            risk += 25;
        }
    }

    /* 跨进程修改 +20 */
    if (CrossProcess) {
        risk += 20;
    }

    Val->RiskScore = min(risk, 100);
    Val->IsCompromised = (Val->RiskScore >= 40) ||
                         Val->StackPivoted ||
                         !Val->RipIsBacked;

    /* 劫持方式判定 (对齐 SS DetectHijackInternal L1556-1567) */
    if (Val->RipHasShellcode) {
        Val->HijackType = WkdHijack_RipModification;
    } else if (Val->StackPivoted) {
        Val->HijackType = WkdHijack_StackPivot;
    } else if (Val->HasHardwareBreakpoints) {
        Val->HijackType = WkdHijack_HardwareBreakpoint;
    } else if (!Val->RipIsBacked) {
        Val->HijackType = WkdHijack_RipModification;
    } else {
        Val->HijackType = WkdHijack_Unknown;
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*   主动扫描 / 基线 / 响应 (T1055.003 迁移)       */
/*   ShadowStrike ScanProcess/ScanAllProcesses +   */
/*   EstablishBaseline/GetBaseline/ClearBaseline + */
/*   RestoreContext                                */
/**************************************************/

#define WPT_MAX_BASELINES   8192    /* 基线表 cap (对齐 SS kMaxBaselineThreads=16384, 保守减半) */
static WKD_THREAD_BASELINE g_WptBaselines[WPT_MAX_BASELINES];
static volatile LONG       g_WptBaselineCount = 0;

/*
 * WptScanProcess — 主动扫描进程全部线程。
 * 对齐 SS ScanProcessInternal (ThreadHijackDetector.cpp L1665-1740):
 *   Toolhelp 枚举线程 → 逐线程 WptValidateThread → 收集 compromised 线程。
 * ※ 死代码: 与事件驱动架构冲突, 定位未来主动扫描任务, 当前无调用者。
 */
_Use_decl_annotations_
NTSTATUS
WptScanProcess(
    DWORD               ProcessId,
    PWKD_THREAD_SCAN_RESULT Result
    )
{
    HANDLE hSnapshot;
    THREADENTRY32 te;

    if (!Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));
    Result->TargetProcessId = ProcessId;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return STATUS_SUCCESS;

    te.dwSize = sizeof(te);
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID != ProcessId) continue;

            Result->ThreadsScanned++;
            if (Result->CompromisedFound >= WKD_THREAD_SCAN_MAX) break;

            /* 调用栈分析开启 (激活 WptCountUnbackedCallStackFrames 调用点) */
            WKD_THREAD_VALIDATION val;
            if (NT_SUCCESS(WptValidateThread(te.th32ThreadID, FALSE, TRUE, &val))) {
                /* 起始地址无背衬补充 (激活 WptIsThreadStartUnbacked 调用点,
                 * 对齐 SS ValidateThreadStartInternal 的 APC/Early-Bird 维度) */
                if (WptIsThreadStartUnbacked(te.th32ThreadID)) {
                    val.IsCompromised = TRUE;
                    val.RiskScore = max(val.RiskScore, 40);
                }

                if (val.IsCompromised) {
                    Result->Compromised[Result->CompromisedFound++] = val;
                    Result->HijackDetected = TRUE;
                    if (val.RiskScore > Result->HighestRiskScore) {
                        Result->HighestRiskScore = val.RiskScore;
                    }
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return STATUS_SUCCESS;
}

/*
 * WptScanAllProcesses — 主动扫描全系统进程。
 * 对齐 SS ScanAllProcesses (ThreadHijackDetector.cpp L2533-2579)。
 * 汇总计数 (Compromised 数组不填满: 全系统线程可能超上限)。
 * ※ 死代码: 同上。
 */
_Use_decl_annotations_
NTSTATUS
WptScanAllProcesses(
    PWKD_THREAD_SCAN_RESULT Result
    )
{
    HANDLE hSnapshot;
    PROCESSENTRY32W pe;

    if (!Result) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Result, sizeof(*Result));
    Result->TargetProcessId = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return STATUS_SUCCESS;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            WKD_THREAD_SCAN_RESULT sub;
            if (!NT_SUCCESS(WptScanProcess(pe.th32ProcessID, &sub))) continue;

            Result->ThreadsScanned    += sub.ThreadsScanned;
            Result->CompromisedFound  += sub.CompromisedFound;
            if (sub.HijackDetected)    Result->HijackDetected = TRUE;
            if (sub.HighestRiskScore > Result->HighestRiskScore) {
                Result->HighestRiskScore = sub.HighestRiskScore;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return STATUS_SUCCESS;
}

/*
 * WptEstablishBaseline — 建立线程上下文基线。
 * 对齐 SS EstablishBaselineInternal (ThreadHijackDetector.cpp L2060-2129):
 *   上下文快照 + GetThreadTimes 创建时间 (TID 复用锚, 防同 TID 线程继承旧基线)。
 * 基线表 cap 8192 (WPT_MAX_BASELINES)。
 * ※ 死代码: 基线唯一来源是 agent 周期扫描 (驱动 SetContext 事件无旧上下文),
 *   当前无调用者。
 */
_Use_decl_annotations_
BOOLEAN
WptEstablishBaseline(
    DWORD Tid
    )
{
    WKD_THREAD_CONTEXT64 ctx;
    WKD_THREAD_BASELINE base;
    HANDLE hThread;
    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    LONG i;
    BOOLEAN replaced = FALSE;

    if (Tid == 0 || Tid == GetCurrentThreadId()) return FALSE;

    /* 上下文快照 */
    if (!WptGetThreadContext(Tid, &ctx)) return FALSE;

    /* 创建时间 (TID 复用锚, 对齐 SS GetThreadTimes) */
    RtlZeroMemory(&base, sizeof(base));
    hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, Tid);
    if (hThread) {
        if (GetThreadTimes(hThread, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
            base.CreateTime.LowPart = ftCreate.dwLowDateTime;
            base.CreateTime.HighPart = ftCreate.dwHighDateTime;
        }
        CloseHandle(hThread);
    }
    base.ThreadId = Tid;
    {
        HANDLE hOwner = OpenThread(THREAD_QUERY_INFORMATION, FALSE, Tid);
        if (hOwner) {
            base.OwnerPid = GetProcessIdOfThread(hOwner);
            CloseHandle(hOwner);
        }
    }
    base.Ctx = ctx;

    /* 覆盖已存在项 (同 TID), 否则追加 (超 cap 拒绝) */
    for (i = 0; i < WPT_MAX_BASELINES; i++) {
        if (g_WptBaselines[i].ThreadId == Tid &&
            g_WptBaselines[i].OwnerPid != 0) {
            g_WptBaselines[i] = base;
            replaced = TRUE;
            break;
        }
    }
    if (!replaced) {
        if (g_WptBaselineCount >= WPT_MAX_BASELINES) {
            return FALSE;
        }
        for (i = 0; i < WPT_MAX_BASELINES; i++) {
            if (g_WptBaselines[i].OwnerPid == 0) {
                g_WptBaselines[i] = base;
                InterlockedIncrement(&g_WptBaselineCount);
                break;
            }
        }
    }
    return TRUE;
}

/*
 * WptGetBaseline — 查询线程基线。
 */
_Use_decl_annotations_
BOOLEAN
WptGetBaseline(
    DWORD               Tid,
    PWKD_THREAD_BASELINE Base
    )
{
    LONG i;

    if (!Base) return FALSE;
    for (i = 0; i < WPT_MAX_BASELINES; i++) {
        if (g_WptBaselines[i].ThreadId == Tid &&
            g_WptBaselines[i].OwnerPid != 0) {
            *Base = g_WptBaselines[i];
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * WptClearBaseline — 清除线程基线。
 */
VOID
WptClearBaseline(
    DWORD Tid
    )
{
    LONG i;

    for (i = 0; i < WPT_MAX_BASELINES; i++) {
        if (g_WptBaselines[i].ThreadId == Tid &&
            g_WptBaselines[i].OwnerPid != 0) {
            RtlZeroMemory(&g_WptBaselines[i], sizeof(g_WptBaselines[i]));
            InterlockedDecrement(&g_WptBaselineCount);
            break;
        }
    }
}

/*
 * WptRestoreContext — 从基线恢复线程上下文。
 * 对齐 SS RestoreContextInternal (ThreadHijackDetector.cpp L1948-2025):
 *   拒绝恢复自身 → 查基线 → OpenThread(SET_CONTEXT|SUSPEND_RESUME|GET_CONTEXT)
 *   → 挂起 (保证恢复) → SetThreadContext (含 CONTEXT_DEBUG_REGISTERS,
 *   基线 DR 值覆盖, 防遗留硬件断点) → 恢复线程。
 * ※ 死代码: 事后恢复是妥协方案 (WkD 第2层同步阻塞在事前拦截执行权转移),
 *   当前无调用者。
 */
_Use_decl_annotations_
BOOLEAN
WptRestoreContext(
    DWORD Tid
    )
{
    WKD_THREAD_BASELINE base;
    HANDLE hThread;
    BOOLEAN suspended = FALSE;
    BOOLEAN restored = FALSE;
    CONTEXT ctx;

    /* 拒绝恢复自身 (对齐 SS L1951-1954) */
    if (Tid == 0 || Tid == GetCurrentThreadId()) return FALSE;

    if (!WptGetBaseline(Tid, &base)) return FALSE;

    hThread = OpenThread(
        THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
        FALSE, Tid);
    if (!hThread) return FALSE;

    /* RAII 挂起: 所有出口恢复 (对齐 SS ScopedThreadSuspend) */
    if (SuspendThread(hThread) == (DWORD)-1) {
        CloseHandle(hThread);
        return FALSE;
    }
    suspended = TRUE;

    /* 从基线构建 CONTEXT (含调试寄存器, 清零攻击者硬件断点) */
    RtlZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
    ctx.Rip = base.Ctx.Rip;   ctx.Rsp = base.Ctx.Rsp;   ctx.Rbp = base.Ctx.Rbp;
    ctx.Rax = base.Ctx.Rax;   ctx.Rbx = base.Ctx.Rbx;   ctx.Rcx = base.Ctx.Rcx;
    ctx.Rdx = base.Ctx.Rdx;   ctx.Rsi = base.Ctx.Rsi;   ctx.Rdi = base.Ctx.Rdi;
    ctx.R8  = base.Ctx.R8;    ctx.R9  = base.Ctx.R9;    ctx.R10 = base.Ctx.R10;
    ctx.R11 = base.Ctx.R11;   ctx.R12 = base.Ctx.R12;   ctx.R13 = base.Ctx.R13;
    ctx.R14 = base.Ctx.R14;   ctx.R15 = base.Ctx.R15;
    ctx.Dr0 = base.Ctx.Dr0;   ctx.Dr1 = base.Ctx.Dr1;   ctx.Dr2 = base.Ctx.Dr2;
    ctx.Dr3 = base.Ctx.Dr3;   ctx.Dr6 = base.Ctx.Dr6;   ctx.Dr7 = base.Ctx.Dr7;

    if (SetThreadContext(hThread, &ctx)) {
        restored = TRUE;
    }

    if (suspended) {
        ResumeThread(hThread);
    }
    CloseHandle(hThread);
    return restored;
}

/*
 * WptTerminateAttacker — 终止攻击者进程 (线程劫持响应)。
 * 对齐 SS TerminateAttackerInternal (ThreadHijackDetector.cpp L2027-2054)。
 * 迁移后委托 ProcessManager_KillProcess (处置引擎核心)。
 * 语义变化: 旧实现硬编码豁免 PID{4,8,16}; 新核心豁免 {0,4,self} + 关键性判定
 *   (CRITICAL_PROCESSES 名称 + 系统二进制目录双重校验, 对齐 SS IsProcessCritical)。
 *   PID 8/16 (System Idle/Registry) 在旧实现下被豁免, 新核心下取决于名称/路径判定。
 * ※ 死代码: 依赖 remediation 通道 (WkD 第2层同步阻塞已覆盖事前拦截,
 *   主动终止是可选处置), 当前无调用者。
 */
_Use_decl_annotations_
BOOLEAN
WptTerminateAttacker(
    DWORD AttackerPid
    )
{
    return (ProcessManager_KillProcess(AttackerPid) == STATUS_SUCCESS);
}

/**************************************************/
/*   上下文前后对比 (SS CompareContexts 迁移)       */
/*   ThreadHijackDetector.cpp L1417-1490           */
/**************************************************/

/*
 * WptCompareContexts — 对比两个上下文快照, 提取 RIP/RSP/DR7 变化。
 *
 * 对齐 SS CompareContextsInternal (ThreadHijackDetector.cpp L1417-1490):
 *   - RIP 变化: 新旧模块对照 (WptResolveStartModule), 新 RIP 无背衬 → 可疑
 *   - RSP 变化: 无符号 delta > 1MB → 栈翻转 → 可疑
 *   - DR7 变化: 新 DR7 != 0 → 硬件断点 → 可疑
 * ※ 死代码: 供 SetContext 前后对比 (对齐 SS OnSetContextThreadInternal),
 *   当前无调用者。
 */
_Use_decl_annotations_
NTSTATUS
WptCompareContexts(
    const WKD_THREAD_CONTEXT64* Before,
    const WKD_THREAD_CONTEXT64* After,
    DWORD                       OwnerPid,
    PWKD_CONTEXT_CHANGE         Changes,
    ULONG                       MaxChanges,
    PULONG                      ChangeCount
    )
{
    WPT_MODULE_ENTRY modules[WPT_MAX_MODULES];
    ULONG modCount;
    ULONG count = 0;
    ULONG_PTR delta;

    if (!Before || !After || !Changes || !ChangeCount) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Changes, sizeof(WKD_CONTEXT_CHANGE) * MaxChanges);
    *ChangeCount = 0;

    /* 模块表预枚举 (对齐 SS GetModuleForAddress 每次枚举) */
    modCount = WptEnumerateModules(OwnerPid, modules, WPT_MAX_MODULES);

    /* RIP 变化 (对齐 SS L1426-1446) */
    if (Before->Rip != After->Rip && count < MaxChanges) {
        PWKD_CONTEXT_CHANGE c = &Changes[count];
        c->Type = WkdCtxMod_InstructionPointer;
        c->OldValue = Before->Rip;
        c->NewValue = After->Rip;
        WptResolveStartModule(Before->Rip, modules, modCount,
                              c->OldModule, RTL_NUMBER_OF(c->OldModule));
        c->NewRipIsBacked = WptResolveStartModule(
            After->Rip, modules, modCount,
            c->NewModule, RTL_NUMBER_OF(c->NewModule));
        c->IsSuspicious = !c->NewRipIsBacked;
        if (!c->NewRipIsBacked) {
            wcsncpy_s(c->SuspicionReason, RTL_NUMBER_OF(c->SuspicionReason),
                      L"RIP changed to unbacked memory", _TRUNCATE);
        } else if (_wcsicmp(c->OldModule, c->NewModule) != 0) {
            c->IsSuspicious = TRUE;
            wcsncpy_s(c->SuspicionReason, RTL_NUMBER_OF(c->SuspicionReason),
                      L"RIP changed to different module", _TRUNCATE);
        }
        count++;
    }

    /* RSP 变化 (栈翻转 >1MB, 对齐 SS L1449-1470) */
    if (Before->Rsp != After->Rsp && count < MaxChanges) {
        PWKD_CONTEXT_CHANGE c = &Changes[count];
        c->Type = WkdCtxMod_StackPointer;
        c->OldValue = Before->Rsp;
        c->NewValue = After->Rsp;
        delta = (After->Rsp > Before->Rsp) ?
                (After->Rsp - Before->Rsp) : (Before->Rsp - After->Rsp);
        c->IsSuspicious = (delta > 0x100000);   /* >1MB */
        if (c->IsSuspicious) {
            wcsncpy_s(c->SuspicionReason, RTL_NUMBER_OF(c->SuspicionReason),
                      L"Stack pivot detected (large RSP change)", _TRUNCATE);
        }
        count++;
    }

    /* DR7 变化 (硬件断点, 对齐 SS L1473-1482) */
    if (Before->Dr7 != After->Dr7 && count < MaxChanges) {
        PWKD_CONTEXT_CHANGE c = &Changes[count];
        c->Type = WkdCtxMod_DebugRegisters;
        c->OldValue = Before->Dr7;
        c->NewValue = After->Dr7;
        c->IsSuspicious = (After->Dr7 != 0);
        if (c->IsSuspicious) {
            wcsncpy_s(c->SuspicionReason, RTL_NUMBER_OF(c->SuspicionReason),
                      L"Debug registers modified", _TRUNCATE);
        }
        count++;
    }

    *ChangeCount = count;
    return STATUS_SUCCESS;
}

/**************************************************/
/*   周期监控 / 基线清理 (SS Worker 迁移)          */
/**************************************************/

/*
 * WptMonitoringWorkerOnce — 周期监控单次扫描。
 * 对齐 SS MonitoringThreadWorker (ThreadHijackDetector.cpp L2151-2196)
 * 的 1s 周期遍历: 全系统线程验证 + 劫持确认。WkD 以全系统扫描
 * (WptScanAllProcesses) 替代 SS 的被监控线程集合遍历。
 * ※ 死代码: WkD 事件驱动无独立监控线程, 激活需创建专用线程周期调用
 *   (对齐 SS 1s 间隔)。
 */
_Use_decl_annotations_
NTSTATUS
WptMonitoringWorkerOnce(
    VOID
    )
{
    WKD_THREAD_SCAN_RESULT result;

    if (NT_SUCCESS(WptScanAllProcesses(&result))) {
        if (result.HijackDetected) {
            /* 结果消费 (告警/记录/持久化) 预留: 对接策略引擎与 ALPC 告警 */
            printf("[WptMonitoring] Hijack scan: threads=%lu compromised=%lu "
                   "highestRisk=%lu\n",
                   result.ThreadsScanned, result.CompromisedFound,
                   result.HighestRiskScore);
        }
        return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;
}

/*
 * WptCleanupBaselines — 基线表 TTL 清理。
 * 对齐 SS CleanupThreadWorker (ThreadHijackDetector.cpp L2198-2244):
 *   清理 CreateTime 超过 1h 的基线条目 (SS 用 lastChecked, WkD 基线为
 *   一次性快照, 以 CreateTime 作为时间锚)。
 * ※ 死代码: 基线表当前只写不清理, 激活需周期调用。
 */
_Use_decl_annotations_
VOID
WptCleanupBaselines(
    VOID
    )
{
    LARGE_INTEGER now;
    LONG i;
    LONGLONG ageSeconds;

    GetSystemTimeAsFileTime((PFILETIME)&now);

    for (i = 0; i < WPT_MAX_BASELINES; i++) {
        if (g_WptBaselines[i].OwnerPid == 0) continue;
        ageSeconds = (now.QuadPart - g_WptBaselines[i].CreateTime.QuadPart) / 10000000;
        if (ageSeconds > 3600) {    /* 1h */
            RtlZeroMemory(&g_WptBaselines[i], sizeof(g_WptBaselines[i]));
            InterlockedDecrement(&g_WptBaselineCount);
        }
    }
}
