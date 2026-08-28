/**************************************************/
/*  WkDefender — 线程创建 IOC 检测流水线            */
/*                                                   */
/*  检测: 远程线程/跨会话/shellcode/RWX/挂起创建     */
/**************************************************/

#include "IocThread.h"
#include "AnalysisEngine.h"
#include "../Callbacks/ThreadNotify.h"
#include "../Process/ProcessModuleTracker.h"     /* PsLookupWkdModuleContainingAddress（模块归属查询，替代 PEB 遍历） */

#ifndef MEM_IMAGE
#define MEM_IMAGE   0x1000000
#endif

/**************************************************/
/*       孤儿注入器判定 (对齐 SS 进程关系图)          */
/*                                                  */
/*  迁移自 ShadowStrike ProcessRelationship.c       */
/*  PrpCalculateRelationshipScore 的                */
/*  PR_SCORE_ORPHANED_INJECTOR(+200) 修正项:        */
/*  源节点 IsOrphan(父进程已退出) 时注入关系分叠加。  */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static
BOOLEAN
IocpIsSourceOrphan(
    _In_ HANDLE SourceProcessId
    )
/*++
Routine Description:
    判定源进程是否为"孤儿注入器" — 其父进程已退出（不在进程表）。
    对齐 ShadowStrike PrpIsProcessOrphanCached 语义:
      SS: 源节点 IsOrphan = 父节点已从图移除。
      wkd: 终止进程已 PmHashMapRemove 摘表 → 父 PID 查表返回 NULL 即孤儿。

    排除: PID 0/4 (Idle/System) 及无父进程不计孤儿。

    [死代码] IocDetectThread 整体依赖 AeDispatchThreadCreated 重接线
    （ThreadNotify.c 用户决策 2026-08: 线程事件只上送 agent 不驱动评分）。
    活代码等价物: agent IoaGenealogy isOrphan (T1_GFLAG_ORPHAN) +
    IoaInjectionClassifier 注入风险分孤儿修正。

Arguments:
    SourceProcessId — 源（创建者）进程 PID。

Return Value:
    TRUE = 源进程为孤儿; FALSE = 非孤儿/无法判定。
--*/
{
    PWKD_PROCESS source = NULL;
    PWKD_PROCESS parent = NULL;
    HANDLE parentId;

    if (SourceProcessId == NULL) {
        return FALSE;
    }

    source = PsLookupWkdProcessByProcessId(SourceProcessId);
    if (source == NULL) {
        /* 源进程不在表: 无法判定父存活, 保守不判孤儿（防乱序误报） */
        return FALSE;
    }

    parentId = source->Core.ParentProcessId;
    PsDereferenceWkdProcess(source);

    if (parentId == NULL || HandleToULong(parentId) <= 4) {
        return FALSE;   /* 无父 / System 父不算孤儿 */
    }

    parent = PsLookupWkdProcessByProcessId(parentId);
    if (parent == NULL) {
        return TRUE;    /* 父已摘表（进程退出）→ 源进程为孤儿 */
    }

    PsDereferenceWkdProcess(parent);
    return FALSE;
}

_Use_decl_annotations_
NTSTATUS
IocDetectThread(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ PWKD_THREAD WkdThread
    )
{
    NTSTATUS status;
    PWKD_PROCESS wkdProcess;

    if (!Pair || !WkdThread) return STATUS_INVALID_PARAMETER;

    wkdProcess = PsLookupWkdProcessByProcessId(WkdThread->ProcessId);
    if (!NT_SUCCESS(wkdProcess)) DbgBreakPoint();

    /*
     * === 内存分析（对齐 PS TnpGetMemoryProtection） ===
     */
    WkdThread->IsStartAddrRead = FALSE;
    if (WkdThread->HasStartRoutine && WkdThread->StartRoutine != NULL &&
        (ULONG_PTR)WkdThread->StartRoutine >= 0x10000ULL &&
        (ULONG_PTR)WkdThread->StartRoutine <= 0x7FFFFFFFFFFFULL) {
        HANDLE hProcess;
        PWKD_MODULE_INSTANCE instance;

        status = ObOpenObjectByPointer(
            wkdProcess->Core.EProcess, OBJ_KERNEL_HANDLE, NULL,
            PROCESS_QUERY_LIMITED_INFORMATION,
            *PsProcessType, KernelMode, &hProcess);

        if (NT_SUCCESS(status)) {
            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T retLen = 0;

            status = ZwQueryVirtualMemory(
                hProcess, WkdThread->StartRoutine,
                MemoryBasicInformation,
                &mbi, sizeof(MEMORY_BASIC_INFORMATION), &retLen);

            if (NT_SUCCESS(status)) {
                WkdThread->MemoryRegionBaseAddress = mbi.AllocationBase;
                WkdThread->MemoryProtection = mbi.Protect;
                WkdThread->IsStartAddrBacked = (mbi.Type == MEM_IMAGE);
                WkdThread->IsStartAddrRead = TRUE;

                //if (!isBacked) {
                //    indicators |= WKD_INJECT_UNBACKED_START;
                //    // score = CbpSafeAddScore(score, 200);
                //}

                //if ((protection & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
                //    indicators |= WKD_INJECT_RWX_START;
                //    score = CbpSafeAddScore(score, 250);
                //}
            }

            ZwClose(hProcess);
        }

        /*
         * 判定线程起始地址是否落在目标进程已加载模块区间内：
         *   命中 → 确认在模块内（IsUnusualEntry = FALSE）；
         *   未命中 → 无模块背衬，标记异常入口（IsUnusualEntry = TRUE）。
         * 供下游 WKD_INJECT_UNUSUAL_ENTRY / WKD_INJECT_UNBACKED_START 指示器与 agent 早期校验使用。
         * 全程内核数据结构（PsLookupWkdModuleContainingAddress 遍历 ModuleContext，无用户态地址访问）。
         */
        status = PsLookupWkdModuleContainingAddress(wkdProcess,
                                                    WkdThread->StartRoutine, &instance);
        if (NT_SUCCESS(status)) {
            WkdThread->IsUnusualEntry = FALSE;   /* 落在已知模块区间内 */
        }
        else {
            WkdThread->IsUnusualEntry = TRUE;    /* 无模块背衬 → 异常入口 */
        }

        /* 模块起始地址是否与MemoryRegionBaseAddress一致??? */
        if (WkdThread->MemoryRegionBaseAddress != instance->Module->ImageSize) {
            DbgBreakPoint();
        }
    }

    /*
     * === 入口点内存原始字节采集（供 agent shellcode 模式匹配，对齐 PS TnpCheckShellcodePatterns） ===
     */
    //WkdThread->HasStartBytes = FALSE;
    //WkdThread->StartBytesSize = 0;
    //if (WkdThread->HasStartRoutine && WkdThread->IsStartAddrRead &&
    //    (ULONG_PTR)WkdThread->StartRoutine >= 0x10000ULL &&
    //    (ULONG_PTR)WkdThread->StartRoutine <= 0x7FFFFFFFFFFFULL) {

    //    PEPROCESS targetProcess = NULL;
    //    NTSTATUS byteStatus;

    //    byteStatus = PsLookupProcessByProcessId(WkdThread->ProcessId, &targetProcess);
    //    if (NT_SUCCESS(byteStatus)) {
    //        KAPC_STATE apcState;

    //        MmCopyVirtualMemory();
    //       
    //        /* __try { */
    //        ProbeForRead(WkdThread->StartRoutine, sizeof(WkdThread->StartBytes), 1);
    //        RtlCopyMemory(WkdThread->StartBytes, WkdThread->StartRoutine, sizeof(WkdThread->StartBytes));
    //        WkdThread->StartBytesSize = sizeof(WkdThread->StartBytes);
    //        WkdThread->HasStartBytes = TRUE;
    //        /* } __except (EXCEPTION_EXECUTE_HANDLER) {
    //            /* 内存不可读 — 不记录字节，指标不设置 * /
    //            WkdThread->HasStartBytes = FALSE;
    //            WkdThread->StartBytesSize = 0;
    //        } */

    //        KeUnstackDetachProcess(&apcState);
    //        ObDereferenceObject(targetProcess);
    //    }
    //}

    /*
     * === 系统进程目标检测（对齐 PS TnpIsSystemProcess） ===
     */
    //{
    //    PEPROCESS targetProc = NULL;

    //    if (NT_SUCCESS(PsLookupProcessByProcessId(WkdThread->ProcessId, &targetProc))) {
    //        if ((ULONG_PTR)WkdThread->ProcessId == 4 ||
    //            PsIsSystemProcess(targetProc)) {
    //            WkdThread->IsSystemTarget = TRUE;
    //        }
    //        ObDereferenceObject(targetProc);
    //    }
    //}

    /*
     * === 创建者提权判定（对齐 PS TnIndicator_ElevatedSource, 权重 50） ===
     * 仅远程线程时判定：本地线程的创建者即自身，提权无跨进程注入语义。
     * PsLookupWkdProcessByProcessId 返回持引用（HashMap Reference），用后必须配对释放。
     */
    //if (WkdThread->IsRemote && WkdThread->CreatorProcessId != NULL) {
    //    PWKD_PROCESS creatorProc = PsLookupWkdProcessByProcessId(WkdThread->CreatorProcessId);
    //    if (creatorProc != NULL) {
    //        if (creatorProc->SecurityContext &&
    //            creatorProc->SecurityContext->Elevated) {
    //            WkdThread->IsElevatedSource = TRUE;
    //        }
    //        PsDereferenceWkdProcess(creatorProc);
    //    }
    //}

    /*
     * === 受保护进程目标判定（对齐 PS TnIndicator_ProtectedProcess, 权重 200） ===
     * 复用 IocSyscall 的受保护进程判定（IocspIsProtectedProcess 已提升为导出）。
     */
    //if (WkdThread->IsRemote) {
    //    WkdThread->IsProtectedTarget = IocspIsProtectedProcess(WkdThread->ProcessId);
    //}

    /*
     * === 注入指示器采集（对齐 PS TnpAnalyzeThreadCreation） ===
     */
    //{
    //    ULONG indicators = 0;

    //    if (WkdThread->IsRemote) {
    //        indicators |= WKD_INJECT_REMOTE_THREAD;
    //    }
    //    if (WkdThread->CreateFlags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED) {
    //        indicators |= WKD_INJECT_SUSPENDED_START;
    //    }
    //    if (WkdThread->IsStartAddrRead && !WkdThread->IsStartAddrBacked) {
    //        indicators |= WKD_INJECT_UNBACKED_START;
    //    }
    //    if (WkdThread->IsStartAddrRead &&
    //        (WkdThread->MemoryProtection & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
    //        indicators |= WKD_INJECT_RWX_START;
    //    }
    //    if (WkdThread->IsCrossSession) {
    //        indicators |= WKD_INJECT_CROSS_SESSION;
    //    }
    //    if (WkdThread->IsSystemTarget) {
    //        indicators |= WKD_INJECT_SYSTEM_TARGET;
    //    }
    //    if (WkdThread->IsElevatedSource) {
    //        indicators |= WKD_INJECT_ELEVATED_SOURCE;
    //    }
    //    if (WkdThread->HasStartBytes && WkdThread->StartBytesSize > 0) {
    //        indicators |= WKD_INJECT_SHELLCODE_PATTERN;
    //    }
    //    if (WkdThread->IsProtectedTarget) {
    //        indicators |= WKD_INJECT_PROTECTED_TARGET;
    //    }
    //    if (WkdThread->IsUnusualEntry) {
    //        indicators |= WKD_INJECT_UNUSUAL_ENTRY;
    //    }
    //    if (WkdThread->IsRapidCreation) {
    //        indicators |= WKD_INJECT_RAPID_CREATION;
    //    }

    //    WkdThread->Indicators = indicators;
    //}

    /*
     * === 安全上下文 ===
     */
     // WkdThread->HasImpersonation = PsIsThreadImpersonating(ethread);

    /*
     * 1. 远程线程 — 来源: AeOrchestratorDispatch 内联
     */
    //if (WkdThread->IsRemote) {
    //    AeReportIndicator(Pair, TsSourceBehavioral,
    //        TsIndicator_Injection_RemoteThread);
    //}

    /*
     * 2. 跨会话线程注入 — 来源: AeOrchestratorDispatch 内联
     */
    //if (WkdThread->IsCrossSession) {
    //    AeReportIndicator(Pair, TsSourceBehavioral,
    //        TsIndicator_Injection_CrossProcessThread);
    //}

    /*
     * 3. 远程线程攻击系统进程 — 来源: AeOrchestratorDispatch 内联
     */
    //if (WkdThread->IsSystemTarget && WkdThread->IsRemote) {
    //    AeReportIndicatorEx(Pair, TsSourceIOC,
    //        TsIndicator_Injection_CrossProcessThread, 3);
    //}

    /*
     * 4. 入口点有 shellcode 特征 — 来源: AeOrchestratorDispatch 内联
     */
    //if (WkdThread->HasStartBytes && WkdThread->StartBytesSize >= 4) {
    //    AeReportIndicator(Pair, TsSourceBehavioral,
    //        TsIndicator_Injection_ThreadShellcode);
    //}

    /*
     * 5. (新增) 入口点内存为 RWX — 高风险注入信号
     */
    //if (WkdThread->IsStartAddrRead &&
    //    (WkdThread->MemoryProtection & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
    //    AeReportIndicatorEx(Pair, TsSourceIOC,
    //        TsIndicator_Injection_ThreadShellcode, 3);
    //}

    /*
     * 6. (新增) 挂起创建 — 注入后通过 ResumeThread 执行
     */
    //if (WkdThread->IsRemote &&
    //    (WkdThread->CreateFlags & 0x00000001)) {  /* CREATE_SUSPENDED */
    //    AeReportIndicatorEx(Pair, TsSourceIOC,
    //        TsIndicator_Injection_RemoteThread, 2);
    //}

    /*
     * 7. (新增) 受保护进程目标 + 远程 — 高权重注入信号（对齐 PS TnIndicator_ProtectedProcess 200）
     */
    //if (WkdThread->IsRemote && WkdThread->IsProtectedTarget) {
    //    AeReportIndicatorEx(Pair, TsSourceIOC,
    //        TsIndicator_Injection_CrossProcessThread, 3);
    //}

    /*
     * 8. (新增) 创建者提权源（对齐 PS TnIndicator_ElevatedSource 50）
     */
    //if (WkdThread->IsElevatedSource) {
    //    AeReportIndicatorEx(Pair, TsSourceBehavioral,
    //        TsIndicator_Injection_RemoteThread, 2);
    //}

    /*
     * 9. (新增) 远程线程快速创建（对齐 PS TnIndicator_RapidCreation 100）
     *    IsRapidCreation 由死代码 CbpCheckRapidCreation 填充（ThreadNotify.c），
     *    活代码链路由 agent RA_METRIC_THREAD 频率分析覆盖。
     */
    //if (WkdThread->IsRapidCreation) {
    //    AeReportIndicatorEx(Pair, TsSourceBehavioral,
    //        TsIndicator_Injection_RemoteThread, 3);
    //}

    /*
     * 10. (新增) 孤儿注入器 — 源进程父进程已退出
     *     对齐 SS PR_SCORE_ORPHANED_INJECTOR=200 修正（源节点 IsOrphan）。
     *     [死代码] 同 IocDetectThread 整体（依赖 AeDispatchThreadCreated 重接线，
     *     ThreadNotify.c 用户决策 2026-08）; 活代码等价物:
     *     agent IoaInjectionClassifier 注入风险分孤儿修正。
     */
    //if (WkdThread->IsRemote && IocpIsSourceOrphan(Pair->SourceProcessId)) {
    //    AeReportIndicatorEx(Pair, TsSourceIOC,
    //        TsIndicator_Injection_RemoteThread, 3);
    //}

Cleanup:
    PsDereferenceWkdProcess(wkdProcess);
    return STATUS_SUCCESS;
}
