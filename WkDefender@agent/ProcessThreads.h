/**************************************************/
/*  WkDefender 线程画像分析                         */
/*  迁移自 ShadowStrike ProcessAnalyzer            */
/*  AnalyzeThreadsInternal + GetThreadInfoInternal */
/**************************************************/

#pragma once

#include <windows.h>
#include <winnt.h>

//
// 线程嫌疑分类（对齐 PS ThreadSuspicion 核心子集）
//
typedef enum _WKD_THREAD_SUSPICION {
    WkdTs_Normal              = 0,
    WkdTs_UnbackedStartAddress = 1,   // 起始地址不在任何已知模块
    WkdTs_StartAtExportedFunction = 2, // 起始地址落 kernel32/kernelbase（LoadLibrary 注入靶点）
} WKD_THREAD_SUSPICION, *PWKD_THREAD_SUSPICION;

//
// 单线程画像
//
typedef struct _WKD_THREAD_INFO {
    ULONG       ThreadId;
    ULONG       OwnerPid;
    ULONG_PTR   StartAddress;
    BOOLEAN     IsStartAddressBacked;
    WCHAR       StartAddressModule[64];
    WKD_THREAD_SUSPICION Suspicion;
    ULONG       RiskScore;      // 0-100
} WKD_THREAD_INFO, *PWKD_THREAD_INFO;

//
// 线程画像结果
//
#define WKD_THREAD_MAX_ANALYZE    128

typedef struct _WKD_THREAD_PROFILE {
    ULONG           TotalThreads;
    ULONG           UnbackedStartCount;
    ULONG           AnalyzedCount;
    WKD_THREAD_INFO Threads[WKD_THREAD_MAX_ANALYZE];
} WKD_THREAD_PROFILE, *PWKD_THREAD_PROFILE;

//
// 分析指定进程的全部线程：起始地址是否落在已加载模块内
// 参考 PS: Toolhelp 枚举线程 + NtQueryInformationThread(ThreadQuerySetWin32StartAddress)
//       + 预枚举模块一次比对（避免 O(线程*模块)）
//
NTSTATUS
WptAnalyzeThreads(
    _In_  DWORD                ProcessId,
    _Out_ PWKD_THREAD_PROFILE  Profile
    );

//
// 精确判定线程起始地址是否落在无背衬可执行区域 (MEM_PRIVATE + 可执行)。
// 对齐 SS IsThreadStartUnbacked (ReflectiveDLLDetector.cpp L1390-1425):
//   NtQueryInformationThread=9 取起始地址 → Toolhelp 定位所属进程 →
//   VirtualQueryEx 查区域类型/保护。
// ※ 死代码补充: WptAnalyzeThreads 已用"模块表比对"近似覆盖 (IsStartAddressBacked),
//   本函数提供区域级精确判定 (反射加载线程入口确认), 当前无调用者。
//
BOOLEAN
WptIsThreadStartUnbacked(
    _In_ DWORD Tid
    );

//
// 统计线程调用栈中未落任何已加载模块的帧数。
// 对齐 SS CountUnbackedCallStackFrames (ReflectiveDLLDetector.cpp L1427-1508):
//   挂起线程 → GetThreadContext → StackWalk64 (dbghelp 全局串行) →
//   逐帧模块判定 (未模块帧数)。
// ※ 死代码: 成本高 (挂线程 + dbghelp 全局锁), 定位 Deep/Forensic 模式,
//   当前无调用者。
//
ULONG
WptCountUnbackedCallStackFrames(
    _In_ DWORD Tid
    );

/**************************************************/
/*   线程上下文验证工具 (T1055.003 迁移)           */
/*   ShadowStrike ThreadHijackDetector 迁移        */
/*   GetThreadContextInternal + GetThreadStackBounds */
/*   + ValidateThreadInternal + CalculateRiskScore */
/**************************************************/

//
// 简化 x64 线程上下文 (对齐 SS ThreadContext64 子集, 含 WoW64 投影)
//
typedef struct _WKD_THREAD_CONTEXT64 {
    ULONG_PTR   Rip;
    ULONG_PTR   Rsp;
    ULONG_PTR   Rbp;
    ULONG_PTR   Rax, Rbx, Rcx, Rdx, Rsi, Rdi;
    ULONG_PTR   R8, R9, R10, R11, R12, R13, R14, R15;
    USHORT      SegCs;
    USHORT      SegSs;
    ULONG_PTR   Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    BOOLEAN     IsWow64;    // 32 位线程 (x64 系统上)
} WKD_THREAD_CONTEXT64, *PWKD_THREAD_CONTEXT64;

//
// 线程上下文验证结果 (对齐 SS ThreadValidation + CalculateRiskScore)
//

// 劫持方式细分 (对齐 SS HijackType 子集 + DetectHijackInternal 类型判定)
typedef enum _WKD_HIJACK_TYPE {
    WkdHijack_Unknown            = 0,
    WkdHijack_RipModification    = 1,   /* RIP 指向无背衬/壳码 */
    WkdHijack_StackPivot         = 2,   /* RSP 越界 (栈翻转) */
    WkdHijack_HardwareBreakpoint = 3,   /* DR7 硬件断点 */
} WKD_HIJACK_TYPE, *PWKD_HIJACK_TYPE;

typedef struct _WKD_THREAD_VALIDATION {
    ULONG       ThreadId;
    ULONG       OwnerPid;

    /* 上下文快照 */
    WKD_THREAD_CONTEXT64 Ctx;

    /* RIP 验证 */
    BOOLEAN     RipIsBacked;        // RIP 落已加载模块
    BOOLEAN     RipHasShellcode;    // RIP 处壳码模式
    BOOLEAN     RipInRwxPrivate;    // RIP 区域 RWX 私有

    /* 栈验证 (TEB 栈边界) */
    ULONG_PTR   StackBase;
    ULONG_PTR   StackLimit;
    BOOLEAN     StackInRange;       // RSP ∈ [StackLimit, StackBase]
    BOOLEAN     StackPivoted;       // RSP 越界 (栈翻转)

    /* 段寄存器 */
    BOOLEAN     SegmentsValid;      // CS/SS 合法 (WoW64 用 0x1B 豁免)

    /* 调试寄存器 */
    BOOLEAN     HasHardwareBreakpoints;  // DR7 & 0xFF

    /* 调用栈 (可选分析) */
    ULONG       UnbackedFrameCount;

    /* 综合 */
    BOOLEAN     IsCompromised;
    ULONG       RiskScore;          // 0-100 对齐 SS CalculateRiskScore
    WKD_HIJACK_TYPE HijackType;     // 对齐 SS DetectHijackInternal 类型判定
} WKD_THREAD_VALIDATION, *PWKD_THREAD_VALIDATION;

//
// 读取线程上下文 (含 WoW64: 32 位线程取 WOW64_CONTEXT 投影到 64 位)。
// 对齐 SS GetThreadContextInternal (ThreadHijackDetector.cpp L1310-1415)。
// ※ 死代码: 供线程劫持定向确认 (IoaConfirmThreadHijacking) 与主动扫描使用,
//   当前无调用者 (激活依赖注入分类器接线)。
//
BOOLEAN
WptGetThreadContext(
    _In_ DWORD Tid,
    _Out_ PWKD_THREAD_CONTEXT64 Ctx
    );

//
// 读取线程 TEB 栈边界 (StackBase/StackLimit)。
// 对齐 SS GetThreadStackBounds (ThreadHijackDetector.cpp L463-526):
//   NtQueryInformationThread(ThreadBasicInformation=0) 取 TebBaseAddress →
//   ReadProcessMemory 读 NT_TIB (x64: StackBase@+0x08/StackLimit@+0x10;
//   WoW64: 32 位 TEB 位于 TebBaseAddress+0x2000, StackBase@+0x04/StackLimit@+0x08)。
// ※ 死代码: agent 侧此前无 TEB 读取实现, 本函数为线程劫持/栈验证核心。
//
BOOLEAN
WptGetThreadStackBounds(
    _In_ DWORD Tid,
    _Out_ PULONG_PTR StackBase,
    _Out_ PULONG_PTR StackLimit
    );

//
// 综合验证线程上下文 (RIP/栈/段/调试寄存器/可选调用栈) → 风险分。
// 对齐 SS ValidateThreadInternal + CalculateRiskScore:
//   unbacked RIP+40 / shellcode+25 / RWX 私有+15 / 栈翻转+15 /
//   段异常+30 / 调试寄存器+10 / 调用栈无背衬帧(>1)+25 / 跨进程+20, cap 100。
// ※ 死代码: 供线程劫持定向确认 (IoaConfirmThreadHijacking) 使用, 当前无调用者。
//
NTSTATUS
WptValidateThread(
    _In_ DWORD Tid,
    _In_ BOOLEAN CrossProcess,
    _In_ BOOLEAN AnalyzeCallStack,
    _Out_ PWKD_THREAD_VALIDATION Val
    );

/**************************************************/
/*   主动扫描 / 基线 / 响应 (T1055.003 迁移)       */
/*   ShadowStrike ScanProcess/ScanAllProcesses +   */
/*   EstablishBaseline/GetBaseline/ClearBaseline + */
/*   RestoreContext                                */
/**************************************************/

//
// 线程主动扫描结果 (对齐 SS ScanResult 精简版)
//
#define WKD_THREAD_SCAN_MAX    WKD_THREAD_MAX_ANALYZE

typedef struct _WKD_THREAD_SCAN_RESULT {
    ULONG       TargetProcessId;              /* 0 = 全系统 */
    ULONG       ThreadsScanned;
    ULONG       CompromisedFound;
    BOOLEAN     HijackDetected;
    ULONG       HighestRiskScore;
    WKD_THREAD_VALIDATION Compromised[WKD_THREAD_SCAN_MAX]; /* 单进程扫描填充 */
} WKD_THREAD_SCAN_RESULT, *PWKD_THREAD_SCAN_RESULT;

//
// 线程上下文基线 (对齐 SS MonitoredThread 子集, 供 RestoreContext 恢复)
//
typedef struct _WKD_THREAD_BASELINE {
    ULONG               ThreadId;
    ULONG               OwnerPid;
    LARGE_INTEGER       CreateTime;      /* 线程创建时间 (TID 复用锚, 对齐 SS EstablishBaseline) */
    WKD_THREAD_CONTEXT64 Ctx;
} WKD_THREAD_BASELINE, *PWKD_THREAD_BASELINE;

//
// 主动扫描进程全部线程 (Toolhelp 枚举 + 逐线程 WptValidateThread)。
// 对齐 SS ScanProcessInternal (ThreadHijackDetector.cpp L1665-1740)。
// ※ 死代码: 与事件驱动架构冲突, 定位未来主动扫描任务, 当前无调用者。
//
NTSTATUS
WptScanProcess(
    _In_ DWORD ProcessId,
    _Out_ PWKD_THREAD_SCAN_RESULT Result
    );

//
// 主动扫描全系统进程 (汇总计数)。
// 对齐 SS ScanAllProcesses (ThreadHijackDetector.cpp L2533-2579)。
// ※ 死代码: 同上。
//
NTSTATUS
WptScanAllProcesses(
    _Out_ PWKD_THREAD_SCAN_RESULT Result
    );

//
// 建立线程上下文基线 (基线表 cap 8192, TID 复用锚 = CreateTime)。
// 对齐 SS EstablishBaselineInternal (ThreadHijackDetector.cpp L2060-2129)。
// ※ 死代码: 基线唯一来源是 agent 周期扫描 (驱动 SetContext 事件无旧上下文),
//   当前无调用者。
//
BOOLEAN
WptEstablishBaseline(
    _In_ DWORD Tid
    );

//
// 查询线程基线。
//
BOOLEAN
WptGetBaseline(
    _In_ DWORD Tid,
    _Out_ PWKD_THREAD_BASELINE Base
    );

//
// 清除线程基线。
//
VOID
WptClearBaseline(
    _In_ DWORD Tid
    );

//
// 从基线恢复线程上下文 (含 DR0-7 清零, 防遗留硬件断点)。
// 对齐 SS RestoreContextInternal (ThreadHijackDetector.cpp L1948-2025)。
// ※ 死代码: 事后恢复是妥协方案 (WkD 第2层同步阻塞在事前拦截), 当前无调用者。
//
BOOLEAN
WptRestoreContext(
    _In_ DWORD Tid
    );

//
// 终止攻击者进程 (线程劫持响应)。
// 对齐 SS TerminateAttackerInternal (ThreadHijackDetector.cpp L2027-2054):
//   OpenProcess(PROCESS_TERMINATE) + TerminateProcess; 豁免关键系统进程。
// ※ 死代码: 依赖 remediation 通道 (WkD 第2层同步阻塞已覆盖事前拦截), 当前无调用者。
//
BOOLEAN
WptTerminateAttacker(
    _In_ DWORD AttackerPid
    );

/**************************************************/
/*   上下文前后对比 (SS CompareContexts 迁移)       */
/*   ThreadHijackDetector.cpp L1417-1490           */
/**************************************************/

//
// 上下文修改类型 (对齐 SS ContextModificationType 子集)
//
typedef enum _WKD_CONTEXT_MOD_TYPE {
    WkdCtxMod_None               = 0,
    WkdCtxMod_InstructionPointer = 1,   /* RIP/EIP 变化 */
    WkdCtxMod_StackPointer       = 2,   /* RSP/ESP 变化 (栈翻转) */
    WkdCtxMod_DebugRegisters     = 3,   /* DR7 变化 (硬件断点) */
} WKD_CONTEXT_MOD_TYPE, *PWKD_CONTEXT_MOD_TYPE;

#define WKD_CTX_CHANGE_MAX  4

//
// 单条上下文变化 (对齐 SS ContextChange)
//
typedef struct _WKD_CONTEXT_CHANGE {
    WKD_CONTEXT_MOD_TYPE Type;
    ULONG_PTR           OldValue;
    ULONG_PTR           NewValue;
    WCHAR               OldModule[64];      /* 旧 RIP 所在模块 */
    WCHAR               NewModule[64];      /* 新 RIP 所在模块 */
    BOOLEAN             NewRipIsBacked;     /* 新 RIP 落模块 */
    BOOLEAN             IsSuspicious;       /* 无背衬 / 栈翻转>1MB / 新 DR7!=0 */
    WCHAR               SuspicionReason[128];
} WKD_CONTEXT_CHANGE, *PWKD_CONTEXT_CHANGE;

//
// 对比两个上下文快照, 提取 RIP/RSP/DR7 变化。
// 对齐 SS CompareContextsInternal (ThreadHijackDetector.cpp L1417-1490):
//   - RIP 变化: 新旧模块对照, 新 RIP 无背衬→可疑
//   - RSP 变化: delta > 1MB → 栈翻转 (可疑)
//   - DR7 变化: 新 DR7 != 0 → 硬件断点 (可疑)
// ※ 死代码: 供 SetContext 前后对比 (对齐 SS OnSetContextThreadInternal),
//   当前无调用者。
//
NTSTATUS
WptCompareContexts(
    _In_ const WKD_THREAD_CONTEXT64* Before,
    _In_ const WKD_THREAD_CONTEXT64* After,
    _In_ DWORD OwnerPid,
    _Out_writes_(MaxChanges) PWKD_CONTEXT_CHANGE Changes,
    _In_ ULONG MaxChanges,
    _Out_ PULONG ChangeCount
    );

/**************************************************/
/*   周期监控 / 基线清理 (SS Worker 迁移)          */
/*   MonitoringThreadWorker + CleanupThreadWorker  */
/**************************************************/

//
// 周期监控单次扫描 (对齐 SS MonitoringThreadWorker 的 1s 周期遍历,
//   ThreadHijackDetector.cpp L2151-2196): 全系统线程验证 + 劫持确认。
// ※ 死代码: WkD 事件驱动无独立监控线程, 激活需创建专用线程周期调用。
//
NTSTATUS
WptMonitoringWorkerOnce(
    VOID
    );

//
// 基线表 TTL 清理 (对齐 SS CleanupThreadWorker L2198-2244):
//   清理 CreateTime 超过 1h 的基线条目。
// ※ 死代码: 基线表当前只写不清理, 激活需周期调用。
//
VOID
WptCleanupBaselines(
    VOID
    );
