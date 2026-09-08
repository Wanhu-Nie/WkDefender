#pragma once

#include "../Common/Constants.h"
#include "../Process/ProcessMonitor.h"

/**************************************************/
/*    注入检测指示器（对齐 PS TnIndicator_*）       */
/**************************************************/

#define WKD_INJECT_REMOTE_THREAD        0x00000001  // 远程线程 (PS: 100)
#define WKD_INJECT_SUSPENDED_START      0x00000002  // 挂起创建 (PS: 50)
#define WKD_INJECT_UNBACKED_START       0x00000004  // 入口点在无文件映射内存 (PS: 200)
#define WKD_INJECT_RWX_START            0x00000008  // 入口点内存为 RWX (PS: 250)
#define WKD_INJECT_CROSS_SESSION        0x00000010  // 跨会话注入 (PS: 100)
#define WKD_INJECT_SYSTEM_TARGET        0x00000020  // 目标为系统进程 (PS: 150)
#define WKD_INJECT_ELEVATED_SOURCE      0x00000040  // 创建者提权 (PS: 50)
#define WKD_INJECT_SHELLCODE_PATTERN    0x00000080  // 入口有 shellcode 特征 (PS: 300)
#define WKD_INJECT_PROTECTED_TARGET     0x00000100  // 目标为受保护进程 (PS: 200)
#define WKD_INJECT_UNUSUAL_ENTRY        0x00000200  // 入口点不在任何已加载模块 (PS: 75)
#define WKD_INJECT_RAPID_CREATION       0x00000400  // 远程线程快速创建 (PS: 100)

/**************************************************/
/*    风险等级（对齐 PS TN_RISK_LEVEL）            */
/**************************************************/

typedef enum _WKD_THREAD_RISK_LEVEL {
    WkdRiskNone     = 0,
    WkdRiskLow      = 1,    // >= 100
    WkdRiskMedium   = 2,    // >= 300
    WkdRiskHigh     = 3,    // >= 500
    WkdRiskCritical = 4,    // >= 700
    WkdRiskMax
} WKD_THREAD_RISK_LEVEL, *PWKD_THREAD_RISK_LEVEL;

/**************************************************/
/*                   结构体声明                    */
/**************************************************/

//
// 线程记录条目 —— 挂载在 WKD_PROCESS.ThreadContext 链表中
// 记录当前进程拥有的每个线程的完整信息，
// 支撑 IOA 行为分析中的线程注入检测和攻击链构建
//
typedef struct _WKD_THREAD {
    LIST_ENTRY Links;                   // 链表节点
    /* 引用计数 (2026-08-25 强制对称契约):
     *   创建时 =1 (创建临时引用, 经出参转移给调用方)
     *   插入链表 +1 (表引用) — CbpUnregistryThread 摘链时归还
     *   归零即 PsDereferenceWkdThread 自动销毁 (ETHREAD 解引 + 池释放) */
    volatile LONG RefCount;

    /* === 核心标识 === */
    HANDLE ProcessId;                   // 进程 ID (tPid)
    HANDLE ThreadId;                    // 线程 ID (tTid)

    /* === 内核对象 === */
    PETHREAD EThread;                   // ETHREAD 对象指针（已引用，防 UAF）

    /* === 创建上下文 === */
    LARGE_INTEGER CreateTime;           // 线程创建时间
    HANDLE CreatorProcessId;            // 创建者进程 ID (sPid)
    HANDLE CreatorThreadId;             // 创建者线程 ID (sTid)    

    /* === syscall 上下文（来自 ETW 缓存，未匹配时全为 0） === */
    PVOID StartRoutine;                 // 线程入口地址（NtCreateThreadEx 的 StartRoutine）
    PVOID Argument;                     // NtCreateThreadEx 的 Argument（DLL路径/shellcode参数）
    ULONG DesiredAccess;                // NtCreateThreadEx 的 DesiredAccess
    ULONG CreateFlags;                  // NtCreateThreadEx 的 CreateFlags

    ULONG64 Indicators;                 // 线程指标
    /* === 内存分析（对齐 PS TnpGetMemoryProtection） === */
    PVOID MemoryRegionBaseAddress;      // 线程起始地址所在内存域基址
    ULONG MemoryProtection;             // 入口点内存保护属性 (PAGE_*)
    BOOLEAN IsStartAddrBacked;          // 是否有 MEM_IMAGE 文件映射

    /* === 注入分析上下文（对齐 PS TnpAnalyzeThreadCreation） === */
    ULONG CreatorSessionId;             // 创建者会话 ID
    ULONG TargetSessionId;              // 目标进程会话 ID
    BOOLEAN IsSystemTarget;             // 目标为系统进程

    /* === 受保护/提权/异常入口/快速创建判定（对齐 PS TnIndicator_*） === */
    BOOLEAN IsProtectedTarget;          // 目标为受保护进程 (PS: 200)
    BOOLEAN IsElevatedSource;           // 创建者进程提权 (PS: 50)
    BOOLEAN IsUnusualEntry;             // 入口点不在任何已加载模块 (PS: 75, 依赖模块归属, 死代码填充)
    BOOLEAN IsRapidCreation;            // 远程线程快速创建 (PS: 100, 死代码填充)

    /* === 模块归属（对齐 PS TnpFindModuleForAddress） === */
    PVOID  ModuleBase;                  // 入口点所属模块基址（未命中=NULL）
    SIZE_T ModuleSize;                  // 模块大小
    WCHAR  ModuleName[64];              // 模块文件名（BaseDllName）

    /* === 入口点内存原始字节（供 agent shellcode 模式匹配，对齐 PS TnpCheckShellcodePatterns） === */
    UCHAR  StartBytes[128];             // 线程入口点前 128 字节
    ULONG  StartBytesSize;              // 有效字节数

    /* === 安全上下文 === */
    BOOLEAN HasImpersonation;           // 是否正在模拟
    BOOLEAN ImpersonationLevel;         // 模拟级别

    /* === 生命周期 === */
    LARGE_INTEGER ExitTime;             // 退出时间（0 = 存活）
    LARGE_INTEGER UserTime;             // 累积用户态执行时间
    LARGE_INTEGER KernelTime;           // 累积内核态执行时间

    /* === 标志位 === */
    union {
        struct {
            ULONG IsRemote : 1;         // 跨进程创建（远程线程）
            ULONG IsSuspended : 1;      // 创建时挂起
            ULONG HasStartRoutine : 1;  // StartRoutine 已成功填充
            ULONG HasSyscallCtx : 1;    // syscall 上下文匹配成功（Argument 有效）
            ULONG IsStartAddrRead : 1;  // MemoryProtection 已成功采集
            ULONG HasStartBytes : 1;    // StartBytes 已成功采集
            ULONG Reserved : 26;
        };
        ULONG ThreadFlags;
    };
} WKD_THREAD, *PWKD_THREAD;

//
// 线程上下文 —— 每个 WKD_PROCESS 内嵌一个
// 管理该进程下所有线程的追踪信息
// 使用自旋锁保护（回调运行在 PASSIVE_LEVEL）
//
typedef struct _WKD_THREAD_CONTEXT {
    /* 上下文推锁 (2026-08-25 锁下沉: 自 WKD_PROCESS.Lock 迁入)
     * 规则: ThreadHead/RecentEvents 链头必须持本锁访问;
     * Statistics 计数域走 Interlocked 原子, 无需持锁 */
    EX_PUSH_LOCK          Lock;

    LIST_ENTRY          ThreadHead;     // 线程条目链表头

    //
    // 统计信息
    //
    struct {
        volatile LONG   ActiveThreads;  // 当前线程数量
        volatile LONG   TotalCreated;   // 累计创建数
        volatile LONG   RemoteCreated;  // 远程线程创建数（跨进程）
        volatile LONG   TotalTerminated;// 累计终止数
    } Statistics;

    /* === 快速线程创建窗口（对齐 PS TN_PROCESS_CONTEXT.WindowStart/LastRemoteThread/RemoteThreadsInWindow） ===
     * 供死代码 CbpCheckRapidCreation 使用；活代码链路由 agent RA_METRIC_THREAD 频率分析覆盖 */
    LARGE_INTEGER WindowStart;          // 远程线程窗口起始
    LARGE_INTEGER LastRemoteThread;     // 最近一次远程线程时间
    volatile LONG RemoteThreadsInWindow;// 窗口内远程线程数

    /* === 单进程累积风险（对齐 PS TN_PROCESS_CONTEXT.CumulativeScore/CumulativeIndicators/OverallRisk） ===
     * 死代码 CbpUpdateThreadRisk 使用；注意 wkd 评分体系在进程对上下文（AE_PROCESS_PAIR.TsContext），
     * 此为 PS 单进程累积语义的功能面保留，不接入活代码评分链路 */
    volatile ULONG          CumulativeScore;        // 累积注入评分
    volatile ULONG          CumulativeIndicators;   // 累积指示器位图
    WKD_THREAD_RISK_LEVEL   OverallRisk;            // 累积风险等级

    /* === 最近线程事件历史（对齐 PS TN_PROCESS_CONTEXT.RecentEvents/EventCount） ===
     * 死代码 CbpStoreEventHistory/CbpPruneOldEvents 使用（ThreadNotify.c 死代码区）。
     * wkd 架构以存活线程列表（ThreadHead）+ agent 事件流（SQLite/环形缓冲）覆盖事件历史，
     * 此环形为 PS TrackThreadHistory（默认 TRUE）语义的功能面保留，供未来事件历史查询。 */
    LIST_ENTRY RecentEvents;        // 最近线程事件历史（FIFO，上限 TN_MAX_RECENT_EVENTS）
} WKD_THREAD_CONTEXT, *PWKD_THREAD_CONTEXT;

/**************************************************/
/*                   函数声明                      */
/**************************************************/

//
// 初始化线程回调模块（注册 PsSetCreateThreadNotifyRoutine）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CbThreadNotifyInitialize(
    VOID
    );

//
// 线程条目引用计数 (2026-08-25 强制对称契约)
//   Reference: InterlockedIncrement, 返回新值;
//   Dereference: 归零自动销毁 (ObDereferenceObject(EThread) +
//                ExFreePoolWithTag) — 调用方用完必须归还。
// 链表持有 1 个表引用; 摘链即 CbpUnregistryThread 内部归还,
// 借出方 (ALPC 消息构建等) 通过出参获得 pin, 用完 Dereference。
//
FORCEINLINE
LONG
PsReferenceWkdThread(
    _Inout_ PWKD_THREAD WkdThread
    )
{
    if (!WkdThread) return MAXLONG;
    return InterlockedIncrement(&WkdThread->RefCount);
}

VOID
PsDereferenceWkdThread(
    _Inout_ PWKD_THREAD WkdThread
    );

//
// 清理线程回调模块
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
CbThreadNotifyCleanup(
    VOID
    );

//
// 根据 ThreadId 在进程的线程上下文中查找线程条目
//
_IRQL_requires_(PASSIVE_LEVEL)
PWKD_THREAD
CbLookupThreadEntry(
    _In_ PWKD_PROCESS Process,
    _In_ HANDLE ThreadId
    );

//
// 获取进程的线程数量
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG
CbGetThreadCount(
    _In_ PWKD_PROCESS Process
    );

//
// 为进程注册线程上下文
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
CbAllocateThreadContext(
    _Inout_ PWKD_PROCESS WkdProcess
    );

//
// 注销线程上下文（在进程销毁时调用）
// 清理所有线程条目并释放 WKD_THREAD_CONTEXT
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
CbDistroyThreadContext(
    _Inout_ PWKD_PROCESS WkdProcess
    );

VOID
CbThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    );