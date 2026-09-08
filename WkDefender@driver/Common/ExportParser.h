/*++
    Common/ExportParser.h - 未文档化导出函数解析子引擎

    Purpose:
        收拢 driver 侧所有"已导出但未在 WDK 头文件声明"（或仅局部使用需动态
        解析）的内核函数的解析：typedef 原型 + 类型化全局函数指针 + 由静态
        映射表驱动的统一按名解析。

        解决此前各文件割裂的几种声明/访问形态（NTSYSAPI 直接链接声明、
        各自 typedef + MmGetSystemRoutineAddress、extern 跨文件引用他人
        指针）导致的冗余、不一致与类型强转隐患（如 C4113）。

    子引擎范式（对齐 AlpcService / Exempts 等现有子引擎）:
        - 全局对象描述：WKD_EXPORT_PARSER（状态机 + 解析统计 + 映射表视图）
        - 生命周期：CoInitializeExportParser / ExportParserTeardown
        - 统一解析条目：WKD_EXPORT_ENTRY 一个模型同时表达"按名解析"与
          "特征码定位"（未导出函数经宿主导出函数体内 call 反推）。初始化以
          for 循环逐条解析全局函数指针；对外提供单条解析原语
          CoExportFunctionAddress，供子引擎一次性动态解析（调用方自带条目
          与槽位，无共享表、无锁）。辅助定位函数（宿主）仅为条目的属性，
          不作为独立项注册。

    设计与并发（为何不引入 EX_RUNDOWN_REF）:
        本引擎"解析一次即只读"：函数指针在 Initialize 后不再变化，所有调用
        点均在 PASSIVE_LEVEL 且由 DriverEntry/DriverUnload 确定性编排
        （先解析后使用、先停用后卸载），不存在异步并发关闭竞态。故沿用
        项目铁律——只有存在异步并发关闭/排空语义的对象才持有 rundown，
        此处以 Interlocked 状态机防重复初始化/释放即可。

    Copyright (c) WkDefender Team
--*/

#pragma once

#include <ntifs.h>
#include <ntimage.h>    /* SE_SIGNING_LEVEL / PSE_SIGNING_LEVEL */

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * 类型定义（从原始局部定义处抽离集中，供相关导出函数 typedef 复用）
 * ============================================================================ */

//
// SYSTEM_INFORMATION_CLASS —— 未文档化；仅定义本引擎解析所需的最小枚举。
// 抽离自 Process/ProcessMonitor.c 原局部定义。
//
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5,
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

//
// KTHREAD_STATE —— 与 SYSTEM_THREAD_INFORMATION 配套使用。
// 抽离自 Process/ProcessMonitor.c 原局部定义。
//
typedef enum _KTHREAD_STATE
{
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWaitObsolete,
    WaitingForProcessInSwap,
    MaximumThreadState
} KTHREAD_STATE, * PKTHREAD_STATE;

//
// SYSTEM_THREAD_INFORMATION
// 抽离自 Process/ProcessMonitor.c 原局部定义。
//
typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;                   // 内核态时间。
    LARGE_INTEGER UserTime;                     // 用户态时间。
    LARGE_INTEGER CreateTime;                   // 线程创建时间。
    ULONG WaitTime;                             // 就绪/等待队列停留时间。
    PVOID StartAddress;                         // 线程起始地址。
    CLIENT_ID ClientId;                         // 线程与其所属进程的标识。
    KPRIORITY Priority;                         // 动态优先级。
    KPRIORITY BasePriority;                     // 基础优先级。
    ULONG ContextSwitches;                      // 上下文切换次数。
    KTHREAD_STATE ThreadState;                  // 当前线程状态。
    KWAIT_REASON WaitReason;                    // 当前等待原因。
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

//
// SYSTEM_PROCESS_INFORMATION
// 抽离自 Process/ProcessMonitor.c 原局部定义。
//
typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    ULONGLONG WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakPOOL_FLAG_NON_PAGEDUsage;
    SIZE_T QuotaPOOL_FLAG_NON_PAGEDUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

//
// PS_PROTECTION —— 进程保护等级（Win8.1+）。
// 未文档化；WDK 头文件（含 ntifs.h/ntddk.h，10.0.26100.0）未提供该类型，
// 此处按与内核一致的内存布局自行定义，供 PFN_PsGetProcessProtection 使用。
// 布局：Level(4) | Type(2) | Audit(1) | Signer(1)，Value 为整个字节。
//
typedef struct _PS_PROTECTION {
    union {
        struct {
            UCHAR Level : 4;
            UCHAR Type  : 2;
            UCHAR Audit : 1;
            UCHAR Signer: 1;
        } Signature;
        UCHAR Value;
    };
} PS_PROTECTION, *PPS_PROTECTION;

/* ============================================================================
 * 导出函数 typedef 原型
 * ============================================================================ */

//
// ZwQuerySystemInformation
// 未文档化（导出但无 WDK 头文件声明）；内核态可用 Zw 版本。
//
typedef NTSTATUS (NTAPI *PFN_ZwQuerySystemInformation)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

//
// ZwQueryInformationProcess
// 未文档化（导出但无 WDK 头文件声明）；内核态可用 Zw 版本。
//
typedef NTSTATUS (NTAPI *PFN_ZwQueryInformationProcess)(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_opt_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

//
// ZwOpenThread / ZwQueryInformationThread
// 未文档化（导出但无 WDK 头文件声明）；内核态可用 Zw 版本。
// 抽离自 Callbacks/ThreadNotify.c 原 typedef。
//
typedef NTSTATUS (NTAPI *PFN_ZwOpenThread)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
    );

typedef NTSTATUS (NTAPI *PFN_ZwQueryInformationThread)(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

//
// PsGetProcessSessionId
// 未文档化；部分 WDK 版本未导出，故运行时按名解析。
//
typedef ULONG (NTAPI *PFN_PsGetProcessSessionId)(
    _In_ PEPROCESS Process
    );

//
// PsGetProcessInheritedFromUniqueProcessId
// 未文档化；返回进程的父进程 UniqueProcessId。
//
typedef HANDLE (NTAPI *PFN_PsGetProcessInheritedFromUniqueProcessId)(
    _In_ PEPROCESS Process
    );

//
// PsGetProcessProtection
// 未文档化；返回 PS_PROTECTION（保护进程等级），Win8.1+。
//
typedef PS_PROTECTION (NTAPI *PFN_PsGetProcessProtection)(
    _In_ PEPROCESS Process
    );

//
// PsGetProcessSignatureLevel
// 未文档化；返回进程的镜像签名等级，Win8.1+。
//
#if (NTDDI_VERSION >= NTDDI_WINBLUE)
typedef UCHAR (NTAPI *PFN_PsGetProcessSignatureLevel)(
    _In_ PEPROCESS Process,
    _Out_ PUCHAR SectionSignatureLevel
    );
#endif

//
// SeGetCachedSigningLevel
// 未文档化；获取文件对象已缓存的签名等级与指纹。
//
typedef NTSTATUS (NTAPI *PFN_SeGetCachedSigningLevel)(
    _In_ PFILE_OBJECT FileObject,
    _Out_ PULONG Flags,
    _Out_ PSE_SIGNING_LEVEL SigningLevel,
    _Out_opt_ PUCHAR Thumbprint,
    _Out_opt_ PULONG ThumbprintSize,
    _Out_opt_ PULONG ThumbprintAlgorithm
    );

//
// ExAllocateFromNPagedLookasideList
// 在当前目标 Windows 版本上已不再导出（微软文档未更新），无法链入 IAT。
// 仍被导出的 FsRtlInitializeBaseMcbEx 在其函数体内调用，故通过特征码扫描
// FsRtlInitializeBaseMcbEx 并从 call 指令解析目标地址获得。
// 注意：Win10 中不存在 ExAllocateFromPagedLookasideList，分页/非分页统一
// 由本函数 + 传入的 Lookaside 指针决定（底层 AllocateEx 区分）。
//
typedef PVOID (NTAPI *PFN_ExAllocateFromNPagedLookasideList)(
    _Inout_ PVOID Lookaside
    );

//
// ExFreeToPagedLookasideList / ExFreeToNPagedLookasideList
// 这两个函数在当前目标 Windows 版本上已不再导出（微软文档未更新），
// 无法经 MmGetSystemRoutineAddress 按名解析，也无法链入 IAT。
// 二者仍被导出的 FsRtlUninitializeBaseMcb 在其函数体内调用，故通过
// 特征码扫描 FsRtlUninitializeBaseMcb 并从 call 指令解析目标地址获得。
//
typedef VOID (NTAPI *PFN_ExFreeToPagedLookasideList)(
    _Inout_ PVOID Lookaside,
    _In_ _Post_invalid_ PVOID Entry
    );

typedef VOID (NTAPI *PFN_ExFreeToNPagedLookasideList)(
    _Inout_ PVOID Lookaside,
    _In_ _Post_invalid_ PVOID Entry
    );

/* ============================================================================
 * 类型化全局函数指针（ExportParser.c 定义）
 * ============================================================================ */

extern PFN_ZwQueryInformationProcess           pfnZwQueryInformationProcess;
extern PFN_ZwQuerySystemInformation            pfnZwQuerySystemInformation;
extern PFN_ZwOpenThread                        pfnZwOpenThread;
extern PFN_ZwQueryInformationThread            pfnZwQueryInformationThread;
extern PFN_PsGetProcessSessionId               pfnPsGetProcessSessionId;
extern PFN_PsGetProcessInheritedFromUniqueProcessId pfnPsGetProcessInheritedFromUniqueProcessId;
extern PFN_PsGetProcessProtection              pfnPsGetProcessProtection;
#if (NTDDI_VERSION >= NTDDI_WINBLUE)
extern PFN_PsGetProcessSignatureLevel          pfnPsGetProcessSignatureLevel;
#endif
extern PFN_SeGetCachedSigningLevel             pfnSeGetCachedSigningLevel;

//
// ExLookaside* 未导出系列（特征码定位所得，见 g_ExportTable 特征码项 / CopExportBySignature）
//
extern PFN_ExAllocateFromNPagedLookasideList  pfnExAllocateFromNPagedLookasideList;
extern PFN_ExFreeToPagedLookasideList          pfnExFreeToPagedLookasideList;
extern PFN_ExFreeToNPagedLookasideList         pfnExFreeToNPagedLookasideList;

/* ============================================================================
 * 函数映射表 / 子引擎全局对象
 * ============================================================================ */

//
// 解析方式：按名 / 特征码定位。
// ByName：目标函数已导出，按名字 MmGetSystemRoutineAddress 解析。
// BySignature：目标函数未导出，在宿主导出函数（HostName）函数体内按特征码
//              匹配并从 call rel32 指令反推目标地址。
//
typedef enum _WKD_RESOLVE_METHOD {
    WkdResolveByName = 0,
    WkdResolveBySignature = 1
} WKD_RESOLVE_METHOD, *PWKD_RESOLVE_METHOD;

//
// 统一解析条目——同时表达"按名"与"特征码定位"两种解析需求。
// Method=ByName 时使用 Name/Slot/Mandatory；
// Method=BySignature 时使用 HostName/Pattern/Mask/PatternLength/CallOffset/
//           Instance/Slot/Mandatory（Name 可为 NULL）。
// 本条目始终由调用方持有（全局静态表、栈局部、模块私有区皆可），引擎只按
// 条目执行解析并回填 *Slot；解析完成后条目生命周期即结束（一次性语义）。
//
// Name/HostName 以宽字符串指针保存（静态表可用字面量初始化，为编译期常量）；
// 引擎内部解析时经 RtlInitUnicodeString 构造 UNICODE_STRING 后调用
// MmGetSystemRoutineAddress，避免 MSVC C 语言静态聚合初始化的限制。
//
// HostName：特征码定位时承载特征码的宿主导出函数名（辅助定位，本身不作为
//           独立解析项、不写入任何槽位；随条目一次性使用）。
//
typedef struct _WKD_EXPORT_ENTRY {
    WKD_RESOLVE_METHOD Method;   /* 解析方式 */
    /* ---- 按名（Method==ByName） ---- */
    PCWSTR            Name;      /* 目标导出函数名 */
    /* ---- 特征码定位（Method==BySignature） ---- */
    union {
        PVOID           BaseAddress;
        PCWSTR          HostName;      /* 宿主导出函数名（辅助定位，一次性） */
    };
    const UCHAR*      Pattern;       /* 特征码字节 */
    const UCHAR*      Mask;          /* 掩码（0xFF 精确，0x00 通配） */
    UCHAR             PatternLength; /* 特征码长度（字节） */
    ULONG             CallOffset;    /* E8 call 指令在匹配点内的字节偏移 */
    UCHAR             Instance;      /* 命中序号（0=首次，1=第二次...） */
    /* ---- 输出/必需 ---- */
    PVOID*            Address;          /* 输出函数指针槽位（解析后回填） */
    BOOLEAN           Mandatory;     /* TRUE=失败阻断初始化；FALSE=仅记录 */
} WKD_EXPORT_ENTRY, *PWKD_EXPORT_ENTRY;

//
// 按名导出项（简洁版）——保留供 AlpcService 等子引擎批量按名解析使用。
// Name:     导出函数名（Unicode，供 MmGetSystemRoutineAddress）
// Slot:     输出函数指针槽位（指向模块私有指针）
// Mandatory:TRUE=解析失败阻断初始化；FALSE=失败仅记录（调用点自行判空）
//
typedef struct _WKD_EXPORT_ENTRY2 {
    PWCHAR      Name;
    PVOID*      Address;
    BOOLEAN     Mandatory;
} WKD_EXPORT_ENTRY2, *PWKD_EXPORT_ENTRY2;

//
// 子引擎全局对象描述。
// State: 生命周期状态机（Uninitialized/Resolved/TornDown）
// 其它字段为解析统计与映射表视图（只读，供初始化期/诊断使用）。
// 注意：Table 指向统一 WKD_EXPORT_ENTRY 静态表；本引擎不持共享可变注册表，
//       动态解析由调用方自带条目走单条原语（无竞态、无锁）。
//
typedef struct _WKD_EXPORT_PARSER {
    volatile LONG       State;          /* 生命周期状态 */
    ULONG               ResolvedCount;  /* 成功解析的函数数 */
    ULONG               FailedCount;    /* 失败解析的函数数 */
    PWKD_EXPORT_ENTRY  Table;          /* 统一函数映射表（静态） */
    SIZE_T              TableSize;      /* 表项数 */
} WKD_EXPORT_PARSER, *PWKD_EXPORT_PARSER;

/* ============================================================================
 * 生命周期 API
 * ============================================================================ */

//
// 初始化导出解析子引擎：按静态映射表逐个按名解析所有导出函数指针。
// 需在任一依赖方使用函数指针之前调用（DriverEntry 最早阶段）。
// 返回: STATUS_SUCCESS（全部解析成功或仅非必需项失败）；
//       若存在必需项解析失败，返回对应失败状态（不阻断其它项）。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CoInitializeExportParser(
    VOID
    );

//
// 关闭导出解析子引擎：复位状态机与统计计数。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExportParserTeardown(
    VOID
    );

//
// 查询某个导出函数指针是否已成功解析。
// Name: 导出函数名（Unicode）
// 返回: TRUE=已解析；FALSE=未解析/未知。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExportParserIsResolved(
    _In_ PCWSTR Name
    );

//
// 对外统一解析一个解析条目（单条原语）。
// 同时支持按名与特征码定位；解析完成回填 *Entry->Slot。
// 调用方自带条目与槽位（全局 pfn / 模块私有 / 栈局部皆可），本引擎不持有
// 共享注册表，因此该原语可在线程间安全并发调用（无竞态、无锁）。
// 特征码定位所需的宿主导出函数（辅助定位）仅为条目属性，不作为独立项。
// 返回: STATUS_SUCCESS；条目无效或必需解析失败返回对应错误。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CoExportFunctionAddress(
    _Inout_ PWKD_EXPORT_ENTRY Entry
    );

//
// 对外统一解析一组导出项（供自带类型的子引擎如 ALPC 复用统一解析）。
// 把调用方持有的 {名称, 槽位, 必需} 数组交给本引擎集中按名解析，消除
// 各子引擎手写的 RtlInitUnicodeString + MmGetSystemRoutineAddress 样板。
// 类型与指针槽仍由调用方私有持有，不进入 Common，故无循环依赖。
// Entries: 调用方持有的导出项数组。 Count: 数组项数。
// 返回: STATUS_SUCCESS；存在必需项缺失返回 STATUS_NOT_FOUND。
// 运行环境: PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ExportParserResolveExports(
    _In_reads_(Count) PWKD_EXPORT_ENTRY2 Entries,
    _In_ ULONG Count,
    _Out_opt_ PULONG Resolved,
    _Out_opt_ PULONG Failed
    );

#ifdef __cplusplus
}
#endif
