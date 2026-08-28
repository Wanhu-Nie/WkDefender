#include "ObjectNotify.h"
#include "../Process/ProcessMonitor.h"
#include "../Notification/NotificationManager.h"
#include "../Common/Utils.h"
#include "../Notification/AlpcService.h"
#include "../Process/ProcessPairContext.h"
#include "../Notification/MessageSync.h"
#include "../AnalysisEngine/IocEngine.h"
#include "../AnalysisEngine/AnalysisEngine.h"
#include "../Common/Exempts/Exempts.h"
//
// 未文档化 API 声明 — PsGetProcessImageFileName
// 返回 EPROCESS 内部 15 字节 ANSI 缓冲区（非 PUNICODE_STRING）
//
NTKERNELAPI PUCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

//
// 检查目标进程是否为 LSASS
//
static
BOOLEAN
ObjpIsLsassProcess(
    _In_ PEPROCESS TargetProcess
    )
{
    HANDLE processId = PsGetProcessId(TargetProcess);
    PUCHAR imageName = PsGetProcessImageFileName(TargetProcess);

    /* PID 启发式：常见 LSASS PID */
    if (HandleToULong(processId) == 0x4E0 ||
        HandleToULong(processId) == 0x2E0 ||
        HandleToULong(processId) == 0x3E0) {
        return TRUE;
    }

    /* 映像名匹配 — PsGetProcessImageFileName 返回 ANSI 短名称 */
    if (imageName != NULL) {
        ANSI_STRING lsassAnsi;
        ANSI_STRING imageAnsi;
        RtlInitAnsiString(&lsassAnsi, "lsass.exe");
        imageAnsi.Buffer = (PSZ)imageName;
        imageAnsi.Length = (USHORT)strlen((const char *)imageName);
        imageAnsi.MaximumLength = imageAnsi.Length + 1;
        return RtlCompareString(&imageAnsi, &lsassAnsi, TRUE) == 0;
    }

    return FALSE;
}

/**************************************************/
/*                   全局状态                      */
/**************************************************/

static WKD_OBJECT_CALLBACK_MANAGER g_ObjManager = { 0 };

/**************************************************/
/*                函数前向声明                     */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
ObjpRegisterObjectCallbacks(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
ObjpUnregisterObjectCallbacks(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
OB_PREOP_CALLBACK_STATUS
CbpObjectNotifyPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
CbpNotifyIoaObjectAccess(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ POBJECT_TYPE ObjectType,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ACCESS_MASK SensitiveMask
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
CbpNotifyIoaHandleDuplicate(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ POBJECT_TYPE ObjectType,
    _In_ ACCESS_MASK DesiredAccess
    );

/**************************************************/
/*              初始化 / 清理                      */
/**************************************************/

//
// 初始化对象回调模块
//
_Use_decl_annotations_
NTSTATUS
CbObjectNotifyInitialize(
    VOID
    )
/*++
Routine Description:
    初始化对象回调模块。
    注册 ObRegisterCallbacks 以拦截对进程和线程对象的敏感权限访问。
    仅注册 PreOperation 回调，不处理 PostOperation。

    关注的敏感操作：
    - 进程对象：VM_WRITE, VM_OPERATION, CREATE_THREAD, SUSPEND_RESUME 等
    - 线程对象：SET_CONTEXT, IMPERSONATE, SUSPEND_RESUME 等

Returns:
    STATUS_SUCCESS — 初始化成功
    其他 NTSTATUS  — 初始化失败
--*/
{
    NTSTATUS status;

    RtlZeroMemory(&g_ObjManager, sizeof(WKD_OBJECT_CALLBACK_MANAGER));
    ExInitializeFastMutex(&g_ObjManager.Lock);

    status = ObjpRegisterObjectCallbacks();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] CbObjectNotifyInitialize: ObjpRegisterObjectCallbacks failed: 0x%08X\n",
            status);
        return status;
    }

    g_ObjManager.Initialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] ObjectNotify module initialized.\n");

    return STATUS_SUCCESS;
}

//
// 清理对象回调模块
//
_Use_decl_annotations_
VOID
CbObjectNotifyCleanup(
    VOID
    )
/*++
Routine Description:
    清理对象回调模块，注销 ObRegisterCallbacks 并释放资源。
--*/
{
    if (!g_ObjManager.Initialized) {
        return;
    }

    g_ObjManager.ShutdownRequested = TRUE;

    ObjpUnregisterObjectCallbacks();

    g_ObjManager.Initialized = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] ObjectNotify module cleaned up. "
        "Stats - PreOps: %lld, Sensitive: %lld, ProcessOps: %lld, ThreadOps: %lld\n",
        g_ObjManager.Statistics.TotalPreOps,
        g_ObjManager.Statistics.SensitiveAccess,
        g_ObjManager.Statistics.ProcessOps,
        g_ObjManager.Statistics.ThreadOps);
}

/**************************************************/
/*           回调注册 / 注销                       */
/**************************************************/

//
// 注册对象回调
//
_Use_decl_annotations_
static
NTSTATUS
ObjpRegisterObjectCallbacks(
    VOID
    )
/*++
Routine Description:
    调用 ObRegisterCallbacks 注册进程和线程对象的 PreOperation 回调。
    不注册 PostOperation 回调（按需求仅关注 PreOperation）。
--*/
{
    NTSTATUS status;
    OB_CALLBACK_REGISTRATION callbackReg;
    OB_OPERATION_REGISTRATION operationRegs[2];

    RtlZeroMemory(operationRegs, sizeof(operationRegs));
    RtlZeroMemory(&callbackReg, sizeof(OB_CALLBACK_REGISTRATION));

    //
    // [0] 进程对象回调
    // 关注句柄创建和句柄复制两个操作点
    //
    operationRegs[0].ObjectType = PsProcessType;
    operationRegs[0].Operations = OB_OPERATION_HANDLE_CREATE |
                                   OB_OPERATION_HANDLE_DUPLICATE;
    operationRegs[0].PreOperation = CbpObjectNotifyPreOperationCallback;
    operationRegs[0].PostOperation = NULL;  // 不处理 PostOperation

    //
    // [1] 线程对象回调
    // 关注句柄创建和句柄复制
    //
    operationRegs[1].ObjectType = PsThreadType;
    operationRegs[1].Operations = OB_OPERATION_HANDLE_CREATE |
                                   OB_OPERATION_HANDLE_DUPLICATE;
    operationRegs[1].PreOperation = CbpObjectNotifyPreOperationCallback;
    operationRegs[1].PostOperation = NULL;  // 不处理 PostOperation

    //
    // 组装注册结构（与现有 ObjectManager.c 保持一致，不显式设置 Altitude）
    //
    callbackReg.Version = OB_FLT_REGISTRATION_VERSION;
    callbackReg.OperationRegistrationCount = RTL_NUMBER_OF(operationRegs);
    callbackReg.OperationRegistration = operationRegs;
    callbackReg.RegistrationContext = NULL;

    status = ObRegisterCallbacks(&callbackReg, &g_ObjManager.CallbackHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] ObRegisterCallbacks failed: 0x%08X\n", status);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Object callbacks registered (Process + Thread, PreOp only).\n");

    return STATUS_SUCCESS;
}

//
// 注销对象回调
//
_Use_decl_annotations_
static
NTSTATUS
ObjpUnregisterObjectCallbacks(
    VOID
    )
{
    if (g_ObjManager.CallbackHandle) {
        ObUnRegisterCallbacks(g_ObjManager.CallbackHandle);
        g_ObjManager.CallbackHandle = NULL;
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*           敏感权限判定                          */
/**************************************************/

//
// 判断是否为敏感权限访问
//
_IRQL_requires_(PASSIVE_LEVEL)
static
BOOLEAN
CbpCheckObjectSensitiveAccess(
    _In_ POBJECT_TYPE ObjectType,
    _In_ OB_OPERATION Operation,
    _In_ ACCESS_MASK AccessMask,
    _Out_ PACCESS_MASK DetectedMask
    )
/*++
Routine Description:
    检查当前对象操作是否涉及敏感权限。
    对于进程对象和线程对象分别检查不同的敏感权限位。

    进程敏感权限：
    - PROCESS_VM_WRITE         (0x0020) — WriteProcessMemory
    - PROCESS_VM_OPERATION     (0x0008) — VirtualProtectEx
    - PROCESS_CREATE_THREAD    (0x0002) — CreateRemoteThread
    - PROCESS_SUSPEND_RESUME   (0x0800)
    - PROCESS_SET_INFORMATION  (0x0200)
    - PROCESS_TERMINATE        (0x0001)
    - PROCESS_DUP_HANDLE       (0x0040)

    线程敏感权限：
    - THREAD_SET_CONTEXT       (0x0010) — SetThreadContext
    - THREAD_IMPERSONATE       (0x0100)
    - THREAD_SUSPEND_RESUME    (0x0002)

Arguments:
    ObjectType    — [In] 当前操作涉及的内核对象类型（如 PsProcessType 或 PsThreadType）。
    Operation     — [In] 当前触发的对象操作类型（如 OB_OPERATION_HANDLE_CREATE 等）。
    AccessMask    — [In] 本次操作请求的访问权限掩码（用于比对敏感权限位）。
    DetectedMask  — [Out] 用于接收检测到的敏感权限位。如果返回 TRUE，该参数包含命中的敏感权限。

Returns:
    TRUE  — 访问包含敏感权限
    FALSE — 非敏感访问
--*/
{
    ACCESS_MASK sensitiveMask = 0;

    if (!ObjectType || !Operation || !AccessMask || !DetectedMask) {
        return FALSE;
    }

    *DetectedMask = 0;

    //
    // 仅关注句柄创建/复制操作
    //
    if (Operation != OB_OPERATION_HANDLE_CREATE &&
        Operation != OB_OPERATION_HANDLE_DUPLICATE) {
        return FALSE;
    }

    //
    // 进程对象：检查进程敏感权限
    //
    if (ObjectType == *PsProcessType) {
        sensitiveMask = AccessMask & WKD_SENSITIVE_PROCESS_ACCESS;
    }
    //
    // 线程对象：检查线程敏感权限
    //
    else if (ObjectType == *PsThreadType) {
        sensitiveMask = AccessMask & WKD_SENSITIVE_THREAD_ACCESS;
    }
    else {
        //
        // 其他对象类型暂不关注
        //
        return FALSE;
    }

    if (sensitiveMask) {
        *DetectedMask = sensitiveMask;
        return TRUE;
    }

    return FALSE;
}

/**************************************************/
/*           通知 IOA 引擎                         */
/**************************************************/

//
// 通知 IOA 引擎：敏感对象访问
//
_Use_decl_annotations_
static
VOID
CbpNotifyIoaObjectAccess(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ POBJECT_TYPE ObjectType,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ACCESS_MASK SensitiveMask
    )
/*++
Routine Description:
    构造并发送敏感对象访问通知消息到 IOA 分析引擎。

Arguments:
    SourceProcessId — 发起访问的进程 ID。
    TargetProcessId — 被访问的对象所属进程/线程 ID（对于线程对象，存储线程所属进程）。
    ObjectType      — 对象类型（PsProcessType 或 PsThreadType）。
    DesiredAccess   — 请求的完整访问掩码。
    SensitiveMask   — 命中的敏感权限位。
--*/
{
    PWKD_MESSAGE message;
    WKD_MESSAGE_TYPE msgType;

    //
    // 根据对象类型选择消息类型
    //
    if (ObjectType == *PsProcessType) {
        msgType = WkdMessage_ProcessObjectAccess;
    }
    else {
        msgType = WkdMessage_ThreadObjectAccess;
    }

    message = NtfCreateMessage(
        msgType,
        WkdMessage_SourceObjectCallback,
        WkdMessage_PriorityNormal,
        sizeof(WKD_MESSAGE_BODY_OBJECT_ACCESS));
    if (!message) {
        return;
    }

    message->Header.SourceProcessId = SourceProcessId;
    message->Header.TargetProcessId = TargetProcessId;
    message->Header.ThreadId = PsGetCurrentThreadId();

    //
    // 填充对象访问消息体
    //
    {
        PWKD_MESSAGE_BODY_OBJECT_ACCESS bodyAccess;
        bodyAccess = WKD_MESSAGE_BODY(message, WKD_MESSAGE_BODY_OBJECT_ACCESS);
        bodyAccess->DesiredAccess = DesiredAccess;
        bodyAccess->SensitiveMask = SensitiveMask;
    }

    /*
     * 同步/异步双路径: 根据进程对位图决定阻塞策略
     */
    if (PsPairNeedsSync(
            SourceProcessId, TargetProcessId,
            WkdOp_ObjectAccess)) {

        /* === 同步路径 === */
        WKD_SYNC_REPLY_DATA verdict;
        PWKD_SYNC_REQUEST req;
        NTSTATUS status;

        status = NtfAcquireSyncRequest(&g_SyncMgr,
            &verdict, sizeof(verdict), &req);
        if (!NT_SUCCESS(status)) {
            NmFreeMessage(message);
            return;
        }

        message->Header.SyncRequestId = req->RequestId;

        AlpcSendWkdMessage(message);

        {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -50000000LL;
            status = NtfSyncWait(&g_SyncMgr, req, &timeout);
        }

        if (status != STATUS_SUCCESS) {
            NtfReleaseSyncRequest(&g_SyncMgr, req);
            NmFreeMessage(message);
            return;
        }

        NtfReleaseSyncRequest(&g_SyncMgr, req);
        NmFreeMessage(message);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Sync deny: Src=%p Tgt=%p Access=0x%X\n",
            SourceProcessId, TargetProcessId,
            (ULONG)DesiredAccess);
        return;
    } else {
        /* === 异步路径 (现状) === */
        NtfSendMessageAsync(message);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "[WkDefender] Sensitive object access: Src=%p Tgt=%p Type=%s Access=0x%X Sensitive=0x%X\n",
        SourceProcessId, TargetProcessId,
        (ObjectType == *PsProcessType) ? "Process" : "Thread",
        (ULONG)DesiredAccess, (ULONG)SensitiveMask);
}

/**************************************************/
/*           句柄复制事件上送                       */
/**************************************************/

//
// 构造并发送句柄复制事件（WkdMessage_HandleDuplicate）到 Agent。
// 对齐 SS ObjectCallback.c 的 HtRecordDuplication 触发点（OB 回调 DUPLICATE 分支）。
// 死代码：本模块 CbObjectNotifyInitialize 未激活；跨进程复制关联由 Agent
// 因果图消费（对齐 SS PrAddRelationship(PrRelation_HandleDuplication)），
// 内核不维护复制记录列表。
//
_Use_decl_annotations_
static
VOID
CbpNotifyIoaHandleDuplicate(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ POBJECT_TYPE ObjectType,
    _In_ ACCESS_MASK DesiredAccess
    )
{
    PWKD_MESSAGE message;

    message = NtfCreateMessage(
        WkdMessage_HandleDuplicate,
        WkdMessage_SourceObjectCallback,
        WkdMessage_PriorityNormal,
        sizeof(WKD_MESSAGE_BODY_HANDLE_DUPLICATE));
    if (!message) {
        return;
    }

    message->Header.SourceProcessId = SourceProcessId;
    message->Header.TargetProcessId = TargetProcessId;
    message->Header.ThreadId = PsGetCurrentThreadId();

    {
        PWKD_MESSAGE_BODY_HANDLE_DUPLICATE body;
        body = WKD_MESSAGE_BODY(message, WKD_MESSAGE_BODY_HANDLE_DUPLICATE);
        body->SourceProcessId = SourceProcessId;
        body->TargetProcessId = TargetProcessId;
        body->ObjectType = (ObjectType == *PsProcessType) ? 0 : 1;
        body->DesiredAccess = DesiredAccess;
    }

    /* 异步上送（复制事件仅记录，不做同步阻塞，对齐 SS HtRecordDuplication 纯记录语义） */
    NtfSendMessageAsync(message);
}

/**************************************************/
/*           PreOperation 回调                     */
/**************************************************/

//
// 对象 PreOperation 回调
//
_Use_decl_annotations_
static
OB_PREOP_CALLBACK_STATUS
CbpObjectNotifyPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
/*++
Routine Description:
    对象 PreOperation 回调，在句柄创建/复制时被调用。

    负责：
    1. 过滤系统进程和自访问
    2. 检查敏感权限访问
    3. 将敏感访问事件通过 WKD_MESSAGE 发送给 IOA 分析引擎

    注意：
    - 始终返回 OB_PREOP_SUCCESS（仅监控，不拦截）
    - PostOperation 未注册，不处理

Arguments:
    RegistrationContext  — 注册上下文（未使用）。
    OperationInformation — PreOperation 信息。

Returns:
    OB_PREOP_SUCCESS — 总是允许操作继续。
--*/
{
    HANDLE sourceProcessId;
    HANDLE targetProcessId;
    PWKD_PROCESS sourceWkdProcess = NULL;
    PEPROCESS sourceProcess = NULL;
    PEPROCESS targetProcess = NULL;
    ACCESS_MASK desiredAccess = 0;
    ACCESS_MASK sensitiveMask = 0;

    UNREFERENCED_PARAMETER(RegistrationContext);

    //
    // 模块未初始化或正在关闭
    //
    if (!g_ObjManager.Initialized || g_ObjManager.ShutdownRequested) {
        goto Permit;
    }

    //
    // 获取源进程对象（发起此次句柄操作的进程）
    //
    sourceProcessId = PsGetCurrentProcessId();
    sourceWkdProcess = PsLookupWkdProcessByProcessId(sourceProcessId);
    if (!sourceWkdProcess) {
        // 发生严重的系统错误!
        // 在未经进程监控的情况下向未知进程发起 Object 操作
        // 可能是进程漏检或者被恶意隐藏
        DbgBreakPoint();
    }
    sourceProcess = sourceWkdProcess->Core.EProcess;

    //
    // 跳过白名单
    //
    if (ExemptsIsProcessTrusted(sourceWkdProcess->Core.ProcessId)) {
        goto Permit;
    }

    InterlockedIncrement64(&g_ObjManager.Statistics.TotalPreOps);

    //
    // 获取目标进程对象
    //
    if (OperationInformation->ObjectType == *PsProcessType) {
        targetProcess = (PEPROCESS)OperationInformation->Object;
        InterlockedIncrement64(&g_ObjManager.Statistics.ProcessOps);
    }
    else {  // PsThreadType
        targetProcess = IoThreadToProcess((PETHREAD)OperationInformation->Object);
        InterlockedIncrement64(&g_ObjManager.Statistics.ThreadOps);
    }

    //
    // 获取请求的访问权限
    //
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        desiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    }
    else {
        /* 句柄复制 */
        ASSERT(sourceProcess == OperationInformation->Parameters->DuplicateHandleInformation.SourceProcess);
        ASSERT(targetProcess == OperationInformation->Parameters->DuplicateHandleInformation.TargetProcess);

        desiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;

        /* 句柄复制事件上送（对齐 SS ObjectCallback.c 两处 HtRecordDuplication，
         * HandleTracker 迁移 2026-08）。死代码：本模块 CbObjectNotifyInitialize
         * 被 WkdEntry 注释未激活；跨进程复制关联由 Agent 因果图消费
         * （对齐 SS PrAddRelationship(PrRelation_HandleDuplication)）。 */
        CbpNotifyIoaHandleDuplicate(
            sourceProcessId,
            PsGetProcessId(targetProcess),
            OperationInformation->ObjectType,
            desiredAccess);
    }

    //
    // 跳过自访问
    //
    //if (sourceProcess == targetProcess) {
    //    goto Permit;
    //}

    targetProcessId = PsGetProcessId(targetProcess);

    //
    // 检查是否为敏感权限访问
    //
    if (CbpCheckObjectSensitiveAccess(OperationInformation->ObjectType,
        OperationInformation->Operation, desiredAccess, &sensitiveMask)) {
        InterlockedIncrement64(&g_ObjManager.Statistics.SensitiveAccess);

        //
        // 调用编排器：IOC 检测 + 后续编排
        //
        //AeOrchestratorDispatch(sourceWkdProcess, NULL,
        //          WkdMessage_SourceObjectCallback,
        //          WkdMessage_ProcessObjectAccess,
        //          OperationInformation);

        //
        // 发送事件到 IOA 分析引擎
        //
        CbpNotifyIoaObjectAccess(
            sourceProcessId,
            targetProcessId,
            OperationInformation->ObjectType,
            desiredAccess,
            sensitiveMask);
    }

Permit:
    //
    // 释放引用
    //
    if (sourceWkdProcess) {
        PsDereferenceWkdProcess(sourceWkdProcess);
    }

    //
    // 始终允许操作（仅监控，不拦截）
    //
    return OB_PREOP_SUCCESS;
}
