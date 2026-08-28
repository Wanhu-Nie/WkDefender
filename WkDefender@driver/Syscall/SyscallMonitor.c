#include "SyscallMonitor.h"
#include "SyscallHijack.h"
#include "SyscallService.h"
#include "SyscallAggregation.h"
#include "SyscallContextCache.h"
#include "../Memory/MemorySignature.h"
#include "../Memory/MemoryScan.h"
#include "../Process/ProcessMonitor.h"
#include "../AnalysisEngine/IoaEngine.h"

//
// 记录系统调用事件到进程行为上下文
// 注意: 当前整个分析链路已由 IoaEngine 中 IoaMessageDispatcher →
// IoapHandleSyscallEvent → IoaRecordBehavior 接管。
// 此函数作为 SyscallMonitor 模块的独立入口保留，用于直接分析的场景。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
SmRecordSyscallEvent(
    _In_ HANDLE ProcessId,
    _In_ WKD_MESSAGE_TYPE EventType,
    _In_ ULONG SyscallNumber,
    _In_ PWKD_SYSCALL_CONTEXT Parameters,
    _In_ NTSTATUS Status
    )
{
    UNREFERENCED_PARAMETER(SyscallNumber);

    if (!ProcessId || !Parameters) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // 转调用 IoaRecordBehavior（新接口：返回 WKD_INSERT_RESULT）
    //
    {
        PWKD_PROCESS sourceProcess;

        sourceProcess = PsLookupWkdProcessByProcessId(ProcessId);
        if (!sourceProcess) {
            return STATUS_NOT_FOUND;
        }

        /*
         * 2026-07 迁移：IOA 行为记录已迁至进程对维度（IoaAnalysisBehavior
         * 收 pair），进程侧 IoaContext 不存在。本路径（SmRecordSyscallEvent）
         * 为死代码（IoaRecordBehavior 调用被注释），保留进程查找后直接返回。
         */
        PsDereferenceWkdProcess(sourceProcess);
        return STATUS_SUCCESS;
    }
}

//
// 分析进程的 syscall 事件序列（L1 不做攻击链推导，转交 L2）。
// 此函数保留为预留接口。
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
SmAnalyzeSyscallPattern(
    _In_ PWKD_PROCESS Process
    )
{
    /*
     * 跨进程攻击链检测已从 L1 移除，由 L2（用户态 Agent）独立完成。
     * L1 仅负责单事件分类 + AtomicRiskScore 累加。
     */
    UNREFERENCED_PARAMETER(Process);
    return FALSE;
}

//
// 初始化系统调用监控模块
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
SmInitialize()
{
    NTSTATUS status;

    /*
     * 初始化 ETW → 线程回调 参数缓存链表。
     * 必须先于 ETW 回调注册，避免竞态。
     */
    CtxCacheInitialize();

    status = ShRegisterEtwCallback(NULL);

    return status;
}

//
// 清理系统调用监控模块
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
ScmCleanup(
    VOID
    )
{
    DbgBreakPoint();
}
