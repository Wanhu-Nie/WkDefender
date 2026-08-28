#include "ObjectManager.h"
#include "../Notification/NotificationManager.h"

// 对象管理器结构
typedef struct _OBJECT_MANAGER {
    FAST_MUTEX Lock;
    HANDLE CallbackHandle;
    BOOLEAN Initialized;
} OBJECT_MANAGER, *POBJECT_MANAGER;

// 全局对象管理器实例
OBJECT_MANAGER g_ObjectManager;

NTSTATUS RegisterObjectCallback();

// 初始化对象管理器
NTSTATUS InitializeObjectManager()
{
    NTSTATUS status;

    RtlZeroMemory(&g_ObjectManager, sizeof(OBJECT_MANAGER));
    ExInitializeFastMutex(&g_ObjectManager.Lock);
    g_ObjectManager.CallbackHandle = NULL;

    status = RegisterObjectCallback();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] 对象回调注册失败: 0x%x\n", status);
        return status;
    }

    g_ObjectManager.Initialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[WkDefender] 对象管理器初始化成功!\n");
    return STATUS_SUCCESS;
}

// 对象预操作回调函数
// 仅监控 NtOpenProcess —— 记录源/目标进程，不拦截操作
OB_PREOP_CALLBACK_STATUS OnObjectPreOperation(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    PEPROCESS targetEProcess;
    PEPROCESS sourceEProcess;
    HANDLE sourceProcessId;
    HANDLE TargetProcessId;
    ACCESS_MASK desiredAccess;
    PWKD_MESSAGE message;

    if (!g_ObjectManager.Initialized)
    {
        return OB_PREOP_SUCCESS;
    }

    // 仅监控进程对象
    if (OperationInformation->ObjectType != *PsProcessType)
    {
        return OB_PREOP_SUCCESS;
    }

    targetEProcess = (PEPROCESS)OperationInformation->Object;
    if (!targetEProcess)
    {
        return OB_PREOP_SUCCESS;
    }

    TargetProcessId = PsGetProcessId(targetEProcess);
    sourceProcessId = PsGetCurrentProcessId();

    // 跳过自访问
    if (sourceProcessId == TargetProcessId)
    {
        return OB_PREOP_SUCCESS;
    }

    // 跳过系统进程和 Idle
    if (((ULONG_PTR)TargetProcessId <= 4) || ((ULONG_PTR)sourceProcessId <= 4))
    {
        return OB_PREOP_SUCCESS;
    }

    // 提取请求的访问权限
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
    {
        POB_PRE_OPERATION_PARAMETERS params = OperationInformation->Parameters;
        desiredAccess = params->CreateHandleInformation.DesiredAccess;
    }
    else
    {
        desiredAccess = 0;
    }

    // 构造消息并异步发送
    message = NtfCreateMessage(
        WkdMessage_SyscallOpenProcess,
        WkdMessage_SourceSyscall,
        WkdMessage_PriorityNormal,
        sizeof(WKD_MESSAGE_BODY_SYSCALL));
    if (message)
    {
        PWKD_MESSAGE_BODY_SYSCALL body;

        message->Header.SourceProcessId = sourceProcessId;
        message->Header.TargetProcessId = TargetProcessId;
        body = WKD_MESSAGE_BODY(message, WKD_MESSAGE_BODY_SYSCALL);
        body->SyscallNumber = 0x26;  // NtOpenProcess
        body->TimeWindowMs = 0;

        NtfSendMessageAsync(message);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] ObProcessOpen: Source=%p, Target=%p, Access=0x%x\n",
        sourceProcessId, TargetProcessId, desiredAccess);

    // 始终允许操作（只记录，不拦截）
    return OB_PREOP_SUCCESS;
}

// 对象后操作回调函数
VOID OnObjectPostOperation(
    PVOID RegistrationContext,
    POB_POST_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OperationInformation);
}

// 注册对象回调
NTSTATUS RegisterObjectCallback()
{
    NTSTATUS status;
    OB_CALLBACK_REGISTRATION callbackRegistration;
    OB_OPERATION_REGISTRATION operationRegistration;

    RtlZeroMemory(&operationRegistration, sizeof(OB_OPERATION_REGISTRATION));
    operationRegistration.ObjectType = PsProcessType;
    operationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration.PreOperation = OnObjectPreOperation;
    operationRegistration.PostOperation = OnObjectPostOperation;

    RtlZeroMemory(&callbackRegistration, sizeof(OB_CALLBACK_REGISTRATION));
    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 1;
    callbackRegistration.OperationRegistration = &operationRegistration;
    callbackRegistration.RegistrationContext = NULL;

    status = ObRegisterCallbacks(&callbackRegistration, &g_ObjectManager.CallbackHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] ObRegisterCallbacks 失败: 0x%x\n", status);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[WkDefender] 对象回调注册成功!\n");
    return STATUS_SUCCESS;
}
