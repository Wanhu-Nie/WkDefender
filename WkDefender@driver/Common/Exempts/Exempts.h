/**************************************************/
/*  WkDefender — 排除子系统公共接口                   */
/*                                                   */
/*  本头文件是排除子系统的唯一对外接口。外部模块      */
/*  （ProcessMonitor / AlpcService / Filter /         */
/*  ObjectNotify / ThreadNotify / SyscallHijack /     */
/*  WkdEntry）只依赖本头，不接触内部组件结构。        */
/*                                                   */
/*  职责划分:                                        */
/*    Exempts.c          — 门面/管理引擎（唯一对外） */
/*    ExemptsManager.c   — 纯存储仓库（四表规则）    */
/*    ExemptPid.c        — PID 信任状态 + 判定逻辑   */
/*    ExemptPath.c       — 无状态路径算法            */
/*  内部组件结构/原型见 ExemptsInternal.h（私有头）。 */
/**************************************************/

#ifndef WKD_EXEMPT_H
#define WKD_EXEMPT_H

struct _WKD_PROCESS;
typedef struct _WKD_PROCESS *PWKD_PROCESS;

#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

//=============================================================================
// 枚举类型
//=============================================================================

// 排除规则类型
typedef enum _EXEMPT_RULE_TYPE {
    ExemptRule_Path = 0,            // 路径前缀排除
    ExemptRule_Extension = 1,       // 文件扩展名排除
    ExemptRule_ProcessName = 2,     // 进程名排除
    ExemptRule_ProcessId = 3,       // PID 排除
    ExemptRule_MaxValue
} EXEMPT_RULE_TYPE;

// 排除规则标志
typedef enum _EXEMPT_FLAGS {
    EXEMPT_FLAG_NONE           = 0x00, // 无特殊标志
    EXEMPT_FLAG_CASE_SENSITIVE = 0x01, // 大小写敏感
    EXEMPT_FLAG_WILDCARD       = 0x02, // 通配符匹配
    EXEMPT_FLAG_RECURSIVE      = 0x04, // 递归子目录
    EXEMPT_FLAG_TEMPORARY      = 0x08, // 临时排除（自动过期）
    EXEMPT_FLAG_SYSTEM         = 0x10  // 系统排除（不可移除）
} EXEMPT_FLAGS;

// 排除评估判决
typedef enum _EXEMPT_VERDICT {
    ExemptVerdict_Trusted = 0,      // 进程完全可信，跳过威胁评分
    ExemptVerdict_NotTrusted,       // 进程不受信任
} EXEMPT_VERDICT;

// 排除匹配原因
typedef enum _EXEMPT_REASON {
    ExemptReason_None = 0,          // 未匹配任何排除
    ExemptReason_PathExclusion,     // 路径排除匹配
    ExemptReason_ExtensionMatch,    // 扩展名排除匹配
    ExemptReason_ProcessNameMatch,  // 进程名排除匹配
    ExemptReason_PidExclusion,      // PID 排除匹配
    ExemptReason_TrustedParent,     // 父进程可信继承
    ExemptReason_SystemExclusion,   // 系统关键进程
    ExemptReason_ManualExclusion,   // 手动排除（用户主动信任）
    ExemptReason_MaxValue
} EXEMPT_REASON;
typedef EXEMPT_REASON *PEXEMPT_REASON;

//=============================================================================
// 常量
//=============================================================================

//=============================================================================
// 函数声明 — 门面（Exempts.c）
//  唯一对外接口。内部封装各组件（Manager/Pid/Path）。
//=============================================================================

//---------------------------------------------------------------------------
// 生命周期
//---------------------------------------------------------------------------

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CoInitializeExempts(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptsCleanup(
    VOID
    );

//---------------------------------------------------------------------------
// 判定与进程生命周期
//---------------------------------------------------------------------------

// 统一排除入口判定（EDR 自保护 → 路径/进程名排除 → TrustedPID）
_IRQL_requires_(PASSIVE_LEVEL)
EXEMPT_VERDICT
CoEvaluateProcessExemption(
    _In_ PWKD_PROCESS WkdProcess,
    _Out_opt_ PEXEMPT_REASON Reason
    );

// 进程创建播种（原 CoExemptCreatedProcess）：判定路径/进程名/父继承排除，命中写可信位图
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
CoExemptCreatedProcess(
    _In_ HANDLE ProcessId,
    _In_opt_ HANDLE ParentProcessId,
    _In_opt_ PCUNICODE_STRING ImagePath,
    _Out_ PBOOLEAN Exempt
    );

// 进程终止通知：清理可信集 + 回收 PID 规则表 TTL=0 条目
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptsOnProcessTerminate(
    _In_ HANDLE ProcessId
    );

// 热路径可信查询（门面转发，持全局 rundown 保护）
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ExemptsIsProcessTrusted(
    _In_ HANDLE ProcessId
    );

//---------------------------------------------------------------------------
// 规则管理门面（转发 ExemptsManager 存储仓库）
//---------------------------------------------------------------------------

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ExemptsAddPathExclusion(
    _In_ PCUNICODE_STRING Path,
    _In_ UINT8 Flags,
    _In_ ULONG TTLSeconds
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExemptsRemovePathExclusion(
    _In_ PCUNICODE_STRING Path
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ExemptsAddExtensionExclusion(
    _In_ PCUNICODE_STRING Extension,
    _In_ UINT8 Flags
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExemptsRemoveExtensionExclusion(
    _In_ PCUNICODE_STRING Extension
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ExemptsAddProcessExclusion(
    _In_ PCUNICODE_STRING ProcessName,
    _In_ UINT8 Flags
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExemptsRemoveProcessExclusion(
    _In_ PCUNICODE_STRING ProcessName
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
ExemptsAddPidExclusion(
    _In_ HANDLE ProcessId,
    _In_opt_ ULONG TTLSeconds
    );

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
ExemptsRemovePidExclusion(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ExemptsClearExclusions(
    _In_ EXEMPT_RULE_TYPE Type
    );

#endif // WKD_EXEMPT_H
