#include "NotificationManager.h"
#include "AlpcService.h"
#include "../Common/Utils.h"

//
// 通知转发回调（2026-08 迁移，B1 修复）：
// 把 NotificationManager 总线上的异步消息经 ALPC 转发到 Agent。
// 替换调试示例回调 NmpNotificationCallback，修复"Callback 未注册
// → 消费线程 NtfpMessageBusDispatcher 直接释放消息（异步消息被丢弃）"
// 的缺陷。AlpcSendWkdMessage 对 9 类已知消息映射 ALPC 类型，其余以
// WkdAlpcMsgUnknown 上送（WKD_MESSAGE 内容完整，Agent 按 Header.Type 识别）。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
NmpAlpcForwardCallback(
    _In_ PWKD_MESSAGE Message,
    _In_opt_ PVOID Context
    )
{
    UNREFERENCED_PARAMETER(Context);

    if (!Message) {
        return;
    }

    AlpcSendWkdMessage(Message);
}

//
// 通知回调处理函数（调试示例，保留供手动切换调试；当前由
// NmpAlpcForwardCallback 取代注册——本函数含 DbgBreakPoint 不适合作线上回调）
// 此函数将被注册到通知管理器，接收所有组件发送的通知
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
NmpNotificationCallback(
    _In_ PWKD_MESSAGE Message,
    _In_opt_ PVOID Context
    )
{
    UNREFERENCED_PARAMETER(Context);

    if (!Message) {
        return;
    }

    // 验证消息完整性
    if (Message->Header.Magic != WKD_NOTIFICATION_MAGIC) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Invalid notification message received\n");
        return;
    }
    
    DbgBreakPoint();

    // 根据消息类型分发处理
    switch (Message->Header.Type) {
    case WkdMessage_SyscallOpenProcess:
    case WkdMessage_SyscallAllocateMemory:
    case WkdMessage_SyscallWriteMemory:
    case WkdMessage_SyscallCreateThread:
    case WkdMessage_SyscallReadMemory:
    case WkdMessage_SyscallMapSection:
    case WkdMessage_SyscallQueueApc:
        // 原始syscall事件（已由BehaviorEngine处理）
        //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        //    "[WkDefender] [SYSCALL] Seq=%lu, Type=0x%X\n",
        //    sequenceNum, Message->Header.Type);
        break;

    //case WkdMessage_DllInjectionDetected:
    //    {
    //        PWKD_MESSAGE_BODY_DLL_INJECTION body = WKD_MESSAGE_BODY(Message, WKD_MESSAGE_BODY_DLL_INJECTION);
    //        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
    //            "[WkDefender] [ALERT] DLL Injection detected!\n"
    //            "  EventId=0x%I64X, CorrelationId=0x%I64X\n"
    //            "  Injector PID: %p\n"
    //            "  Target PID: %p\n"
    //            "  Method: %lu\n"
    //            "  Address: 0x%p\n"
    //            "  Size: %zu\n"
    //            "  Threat Score: %lu\n"
    //            "  Attack Chain ID: %lu\n"
    //            "  Injector Path: %ws\n"
    //            "  Target Path: %ws\n",
    //            eventId, correlationId,
    //            body->InjectorPid,
    //            body->TargetProcessId,
    //            body->InjectionMethod,
    //            body->InjectedAddress,
    //            body->InjectedSize,
    //            body->ThreatScore,
    //            body->AttackChainId,
    //            body->InjectorPath,
    //            body->TargetPath);

    //        // TODO: 在此处触发响应动作（如终止进程、隔离文件等）
    //    }
    //    break;

    case WkdMessage_ProcessCreated:
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WkDefender] [NOTIFICATION] Process created: PID=%p\n",
                Message->Header.SourceProcessId);
        }
        break;

    case WkdMessage_SecurityEvent:
        {
            PWKD_MESSAGE_BODY_SECURITY_EVENT body = WKD_MESSAGE_BODY(Message, WKD_MESSAGE_BODY_SECURITY_EVENT);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[WkDefender] [SECURITY EVENT] %ws (ID=%lu, Severity=%lu)\n"
                "  Description: %ws\n"
                "  Related PID: %p\n",
                body->EventName,
                body->EventId,
                body->Severity,
                body->Description,
                body->RelatedProcessId);
        }
        break;

    default:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Unknown notification type: 0x%X\n",
            Message->Header.Type);
        break;
    }

    // 根据优先级采取不同行动
    if (Message->Header.Priority == WkdMessage_PriorityCritical) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] *** CRITICAL NOTIFICATION - Immediate action required ***\n");
        // TODO: 触发紧急响应机制
    }
}

//
// 初始化通知系统并注册回调
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NtfInitializeServiceWithCallback(
    VOID
    )
{
    NTSTATUS status;

    // 初始化通知管理器
    status = NtfInitializeService();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to initialize notification manager: 0x%08X\n", status);
        return status;
    }

    // 注册回调函数（B1 修复：注册 ALPC 转发回调，替代调试打印回调）
    status = NmRegisterCallback(NmpAlpcForwardCallback, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to register notification callback: 0x%08X\n", status);
        NmCleanup();
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Notification system initialized with callback handler\n");

    return STATUS_SUCCESS;
}
