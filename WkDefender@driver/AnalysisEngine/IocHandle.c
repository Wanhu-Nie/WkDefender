/**************************************************/
/*  WkDefender — 句柄访问 IOC 检测流水线            */
/*                                                   */
/*  检测: LSASS 访问/进程终止/线程劫持/句柄前兆      */
/**************************************************/

#include "IocHandle.h"
#include "AnalysisEngine.h"

//
// 未文档化 API 声明 — PsGetProcessImageFileName
// 返回 EPROCESS 内部 15 字节 ANSI 缓冲区
//
NTKERNELAPI PUCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

//
// 获取所需访问权限（兼容 HANDLE_CREATE / HANDLE_DUPLICATE）
//
static
ACCESS_MASK
IochGetDesiredAccess(
    _In_ POB_PRE_OPERATION_INFORMATION OpInfo
    )
{
    if (OpInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
        return OpInfo->Parameters->CreateHandleInformation.DesiredAccess;
    }
    /* HANDLE_DUPLICATE */
    return OpInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
}

_Use_decl_annotations_
NTSTATUS
IocDetectHandle(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ POB_PRE_OPERATION_INFORMATION OpInfo
    )
{
    ACCESS_MASK desiredAccess;

    if (!Pair || !OpInfo) {
        return STATUS_INVALID_PARAMETER;
    }

    desiredAccess = IochGetDesiredAccess(OpInfo);

    if (OpInfo->ObjectType == *PsProcessType) {
        PEPROCESS targetEProcess = (PEPROCESS)OpInfo->Object;
        PCHAR imageName;
        BOOLEAN isLsass = FALSE;

        /* ---- LSASS 识别 ---- */
        imageName = PsGetProcessImageFileName(targetEProcess);
        if (imageName != NULL) {
            ANSI_STRING imgA, lsassA;
            RtlInitAnsiString(&lsassA, "lsass.exe");
            RtlInitAnsiString(&imgA, imageName);
            isLsass = (RtlCompareString(&imgA, &lsassA, TRUE) == 0);
        }

        /*
         * 1. LSASS 敏感访问 — 来源: AeOrchestratorDispatch 内联
         */
        if (isLsass &&
            (desiredAccess &
             (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION))) {
            AeReportIndicator(Pair, TsSourceIOC,
                TsIndicator_Handle_LsassAccess);
        }

        /*
         * 2. 进程终止 — 来源: AeOrchestratorDispatch 内联
         */
        if (desiredAccess & PROCESS_TERMINATE) {
            AeReportIndicator(Pair, TsSourceIOC,
                TsIndicator_Handle_ProcessTermination);
        }

        /*
         * 3. (新增) 远程线程创建的句柄前兆
         */
        if (desiredAccess & PROCESS_CREATE_THREAD) {
            AeReportIndicator(Pair, TsSourceIOC,
                TsIndicator_Handle_ThreadHijack);
        }

        /*
         * 4. (新增) VirtualProtectEx 的句柄前兆
         */
        if (desiredAccess & PROCESS_VM_OPERATION) {
            AeReportIndicator(Pair, TsSourceIOC,
                TsIndicator_Injection_ProcessHollowing);
        }

    } else if (OpInfo->ObjectType == *PsThreadType) {

        /*
         * 5. 线程劫持 — 来源: AeOrchestratorDispatch 内联
         */
        if (desiredAccess &
            (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME |
             THREAD_SET_THREAD_TOKEN)) {
            AeReportIndicator(Pair, TsSourceIOC,
                TsIndicator_Handle_ThreadHijack);
        }

        /*
         * 6. (新增) 独立 SET_CONTEXT 判定（APC 注入/Context 劫持）
         */
        if (desiredAccess & THREAD_SET_CONTEXT) {
            AeReportIndicatorEx(Pair, TsSourceIOC,
                TsIndicator_Handle_ThreadHijack, 3);
        }
    }

    return STATUS_SUCCESS;
}
