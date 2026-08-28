#include "NotificationManager.h"
#include "../Common/Utils.h"
#include "AlpcService.h"

#define WKD_MESSAGE_QUEUE_MAX_COUNT     1024

//
// 全局通知管理器实例
//
WKD_NOTIFICATION_SERVICE WkdNotificationService = {0};

//
// 优先级映射：将 WKD_MESSAGE_PRIORITY (4级) 转为 MessageQueue 索引 (3级)
//
//   Critical (3) / High (2)  → WKD_QUEUE_PRIORITY_HIGH   (0)
//   Normal   (1)             → WKD_QUEUE_PRIORITY_NORMAL (1)
//   Low      (0)             → WKD_QUEUE_PRIORITY_LOW    (2)
//
FORCEINLINE
ULONG
NmpMapQueuePriority(
    _In_ WKD_MESSAGE_PRIORITY Priority
    )
{
    if (Priority >= WkdMessage_PriorityHigh) {
        return WKD_QUEUE_PRIORITY_HIGH;
    }
    if (Priority == WkdMessage_PriorityNormal) {
        return WKD_QUEUE_PRIORITY_NORMAL;
    }
    return WKD_QUEUE_PRIORITY_LOW;
}

//
// 消息总线的派发函数
//
// 初始化时序说明：
//   NtfInitializeService 创建此消费线程时，service->Callback 可能尚未设置
//   （Callback 由 IoaInitialize → NmRegisterCallback 在初始化步骤 7 注册）。
//   因此本线程不要求在启动时 Callback 非 NULL，而是：
//   1) 先进入等待循环，MessageQueue 为空时休眠；
//   2) 出队消息后，若有 Callback 则分发处理；
//   3) 无 Callback 时仍释放消息（防止内存泄漏），等待下次唤醒。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
NtfpMessageBusDispatcher(
    _In_ PVOID Context
    )
{
    PWKD_NOTIFICATION_SERVICE service = (PWKD_NOTIFICATION_SERVICE)Context;
    PWKD_MESSAGE_QUEUE_NODE node = NULL;
    PLIST_ENTRY listEntry = NULL;

    if (!service) {
        PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
        return;
    }

    while (!service->ShutdownRequested) {
        // 等待处理事件或关闭信号
        KeWaitForSingleObject(
            &service->ProcessEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL
            );

        // 处理队列中的所有消息（按严格优先级出队）
        while (TRUE) {
            listEntry = NtfMessageDequeue(&service->MsgQueue);
            if (!listEntry) {
                break;
            }

            node = CONTAINING_RECORD(listEntry, WKD_MESSAGE_QUEUE_NODE, Links);

            //
            // 回调处理：
            //   - Callback 已注册 → 调用处理函数
            //   - Callback 未注册 → 直接释放消息（此时处于初始化阶段，
            //     消息丢失可接受。后续 IoaInitialize 注册回调后，新消息正常处理）
            //
            if (!node->Processed) {
                /* __try { */
                    service->Callback(node->Message, service->CallbackContext);
                    node->Processed = TRUE;

                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                        "[WkDefender] Notification processed: Type=0x%X, Source=%d, Priority=%d\n",
                        node->Message->Header.Type,
                        node->Message->Header.Source,
                        node->Message->Header.Priority);
                /* }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "[WkDefender] Exception in notification callback: 0x%08X\n",
                        GetExceptionCode());
                } */
            }

            // 释放节点和消息
            if (node->Message) {
                NmFreeMessage(node->Message);
            }
            ExFreePoolWithTag(node, 'NmQn');
        }

        // 重置事件，等待下一批消息
        KeClearEvent(&service->ProcessEvent);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

//
// 初始化通知管理器
//
_Use_decl_annotations_
NTSTATUS
NtfInitializeService(
    VOID
    )
{
    NTSTATUS status;

    RtlZeroMemory(&WkdNotificationService, sizeof(WKD_NOTIFICATION_SERVICE));

    // 初始化优先级消息队列（最大 1024 条消息）
    NtfInitializeMessageQueue(&WkdNotificationService.MsgQueue, WKD_MESSAGE_QUEUE_MAX_COUNT);

    // 初始化处理事件
    KeInitializeEvent(&WkdNotificationService.ProcessEvent, NotificationEvent, FALSE);

    // 创建消费线程
    status = PsCreateSystemThread(
        &WkdNotificationService.ConsumerThread,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        NtfpMessageBusDispatcher,
        &WkdNotificationService
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to create consumer thread: 0x%08X\n", status);
        return status;
    }

    WkdNotificationService.Initialized = TRUE;
    WkdNotificationService.ShutdownRequested = FALSE;

    // 初始化 ALPC 服务
    status = AlpcCreateServer();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Notification Manager initialized\n");

    return STATUS_SUCCESS;
}

//
// 清理通知管理器
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
NmCleanup(
    VOID
    )
{
    PLIST_ENTRY listEntry;
    PWKD_MESSAGE_QUEUE_NODE node;

    if (!WkdNotificationService.Initialized) {
        return;
    }

    WkdNotificationService.ShutdownRequested = TRUE;

    // 触发消费线程处理剩余消息
    KeSetEvent(&WkdNotificationService.ProcessEvent, IO_NO_INCREMENT, FALSE);

    // 等待消费线程退出
    if (WkdNotificationService.ConsumerThread) {
        KeWaitForSingleObject(WkdNotificationService.ConsumerThread,
            Executive, KernelMode, FALSE, NULL);
        ZwClose(WkdNotificationService.ConsumerThread);
        WkdNotificationService.ConsumerThread = NULL;
    }

    // 清理队列中剩余的消息
    while (TRUE) {
        listEntry = NtfMessageDequeue(&WkdNotificationService.MsgQueue);
        if (!listEntry) {
            break;
        }

        node = CONTAINING_RECORD(listEntry, WKD_MESSAGE_QUEUE_NODE, Links);
        if (node->Message) {
            NmFreeMessage(node->Message);
        }
        ExFreePoolWithTag(node, 'NmQn');
    }

    WkdNotificationService.Initialized = FALSE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Notification Manager cleaned up\n");
}

//
// 创建消息（辅助函数）
//
_IRQL_requires_(PASSIVE_LEVEL)
PWKD_MESSAGE
NtfCreateMessage(
    _In_ WKD_MESSAGE_TYPE Type,
    _In_ WKD_MESSAGE_SOURCE Source,
    _In_ WKD_MESSAGE_PRIORITY Priority,
    _In_ ULONG BodySize
    )
{
    PWKD_MESSAGE message = NULL;
    SIZE_T totalSize = 0;
    static volatile LONG sequenceCounter = 0;

    totalSize = sizeof(WKD_MESSAGE_HEADER) + BodySize;

    message = ExAllocatePool2(POOL_FLAG_NON_PAGED, totalSize, 'NmMs');
    if (!message)  return NULL;
    RtlZeroMemory(message, totalSize);

    message->Header.Magic = WKD_NOTIFICATION_MAGIC;
    message->Header.Version = WKD_NOTIFICATION_VERSION;
    message->Header.Type = Type;
    message->Header.Source = Source;
    message->Header.Priority = Priority;
    KeQuerySystemTime(&message->Header.Timestamp);
    message->Header.BodySize = BodySize;
    message->Header.Flags.IsAsync = TRUE;

    return message;
}

//
// 释放消息
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
NmFreeMessage(
    _In_ PWKD_MESSAGE Message
    )
{
    if (Message) {
        ExFreePoolWithTag(Message, 'NmMs');
    }
}

//
// 消息入队（封装节点分配 + 优先级映射 + 入队 + 唤醒消费线程）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NtfpQueueInsert(
    _In_ PWKD_MESSAGE Message
    )
{
    NTSTATUS status;
    PWKD_MESSAGE_QUEUE_NODE node = NULL;
    ULONG queuePriority;

    if (!Message) {
        return STATUS_INVALID_PARAMETER;
    }

    // 创建队列节点
    node = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(WKD_MESSAGE_QUEUE_NODE), 'NmQn');
    if (!node) {
        NmFreeMessage(Message);
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(node, sizeof(WKD_MESSAGE_QUEUE_NODE));
    node->Message = Message;
    node->Processed = FALSE;
    KeQuerySystemTime(&node->EnqueueTime);

    // 映射优先级并入队
    queuePriority = NmpMapQueuePriority(Message->Header.Priority);
    status = NtfMessageEnqueue(&WkdNotificationService.MsgQueue, queuePriority, &node->Links);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Failed to enqueue message: 0x%X (Priority=%d)\n",
            status, Message->Header.Priority);

        NmFreeMessage(Message);
        ExFreePoolWithTag(node, 'NmQn');
        return status;
    }

    // 触发消费线程处理
    KeSetEvent(&WkdNotificationService.ProcessEvent, IO_NO_INCREMENT, FALSE);

    return STATUS_SUCCESS;
}

//
// 异步提交消息（加入优先级队列，由消费线程处理）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NtfSendMessageAsync(
    _In_ PWKD_MESSAGE Message
    )
/*
 * WKD_MESSAGE 的声明周期由异步队列消费者接管
 */
{
    if (!Message || !WkdNotificationService.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    // 验证消息魔数
    if (Message->Header.Magic != WKD_NOTIFICATION_MAGIC) {
        return STATUS_INVALID_PARAMETER;
    }

    return NtfpQueueInsert(Message);
}

//
// 同步提交消息
//
// 设计意图：
//   对于已知的紧急/阻断类消息（如进程终止、隔离响应），
//   应直接调用对应的处理函数，而不是经队列绕一圈。
//   这样可以确保最快的响应路径。
//
// TODO: 建立 [消息类型 → 处理函数] 的直接映射表，替代通用的回调调用。
//       当前实现暂为直接调用注册的回调，后续需改为按消息类型路由。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NmSendMessageSync(
    _In_ PWKD_MESSAGE Message
    )
{
    if (!Message || !WkdNotificationService.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    // 验证消息魔数
    if (Message->Header.Magic != WKD_NOTIFICATION_MAGIC) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // TODO: 紧急阻断类消息应直接调用目标函数：
    //
    //   switch (Message->Header.Type) {
    //   case WkdMessage_ThreatLevelChanged:
    //       if (Message->Header.Priority >= WkdMessage_PriorityCritical) {
    //           // 直接调用阻断函数，不经过回调
    //           TmExecuteThreatResponse(Message);
    //           NmFreeMessage(Message);
    //           return STATUS_SUCCESS;
    //       }
    //       break;
    //   }
    //

    // 当前暂通过回调处理
    if (WkdNotificationService.Callback) {
        /* __try { */
            WkdNotificationService.Callback(Message,
                WkdNotificationService.CallbackContext);
        /* }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WkDefender] Exception in sync notification callback: 0x%08X\n",
                GetExceptionCode());
            NmFreeMessage(Message);
            return STATUS_UNSUCCESSFUL;
        } */
    }

    NmFreeMessage(Message);
    return STATUS_SUCCESS;
}

//
// 注册通知回调
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NmRegisterCallback(
    _In_ PFN_NOTIFICATION_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    if (!Callback) {
        return STATUS_INVALID_PARAMETER;
    }

    WkdNotificationService.Callback = Callback;
    WkdNotificationService.CallbackContext = Context;

    return STATUS_SUCCESS;
}

//
// 刷新消息队列（立即处理所有待处理消息）
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NmFlushQueue(
    VOID
    )
{
    if (!WkdNotificationService.Initialized) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // 触发工作项并等待处理完成
    KeSetEvent(&WkdNotificationService.ProcessEvent, IO_NO_INCREMENT, FALSE);

    // 等待一段时间让工作项处理完
    KeDelayExecutionThread(KernelMode, FALSE,
        &(LARGE_INTEGER){ .QuadPart = -1 * 100 * 1000 * 10 });  // 100ms

    return STATUS_SUCCESS;
}

//
// 获取队列统计信息
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
NmGetStatistics(
    _Out_ PLONG64 TotalEnqueued,
    _Out_ PLONG64 TotalProcessed,
    _Out_ PLONG64 TotalDropped,
    _Out_ PLONG64 CurrentQueueSize
    )
{
    LONG64 enqueued, dequeued, dropped;
    ULONG currentCount;

    MqGetStatistics(&WkdNotificationService.MsgQueue,
        &enqueued, &dequeued, &dropped, &currentCount);

    //
    // TotalProcessed 映射到 Mq 的 TotalDequeued
    // 注意：这与旧统计中的 TotalProcessed 概念一致（成功消费 = 出队）
    //
    if (TotalEnqueued) {
        *TotalEnqueued = enqueued;
    }
    if (TotalProcessed) {
        *TotalProcessed = dequeued;
    }
    if (TotalDropped) {
        *TotalDropped = dropped;
    }
    if (CurrentQueueSize) {
        *CurrentQueueSize = currentCount;
    }
}

//
// 从动态数组导出 WKD_MESSAGE（批量发送场景）
//
_Use_decl_annotations_
PWKD_MESSAGE
NmExportFromDynamicArray(
    _In_ PWKD_MESSAGE_HEADER Template,
    _In_ PWKD_DYNAMIC_ARRAY *Array
    )
{
    PWKD_MESSAGE msg;
    SIZE_T totalBody;

    //if (!Template || !Array || !Array->Count) {
    //    return NULL;
    //}

    //totalBody = (SIZE_T)Array->Count * Array->ElementSize;

    //msg = NtfCreateMessage(
    //    Template->Type,
    //    Template->Source,
    //    Template->Priority,
    //    (ULONG)totalBody);
    //if (!msg) {
    //    return NULL;
    //}

    ///* 拷贝公共头（保留已初始化的字段，覆盖模板字段） */
    //msg->Header.SourceProcessId = Template->SourceProcessId;
    //msg->Header.TargetProcessId = Template->TargetProcessId;
    //msg->Header.ThreadId = Template->ThreadId;

    ///* 拷贝所有元素到 body 区 */
    //RtlCopyMemory(msg->BodyData, Array->Data, totalBody);

    //return msg;
    return NULL;
}
