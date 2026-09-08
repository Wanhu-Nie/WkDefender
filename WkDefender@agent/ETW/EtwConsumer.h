/*
 * WkDefender - Enterprise NGAV/EDR Agent Kernel Driver
 *
 * EtwConsumer.h - ETW (Event Tracing for Windows) 消费器（用户态）。
 * ============================================================================
 * 迁移：ShadowStrike/PhantomCore/Utils/ProcessUtils.cpp ETW 消费框架
 *       (EnableETWProcessTracing/DisableETWProcessTracing, ~2k 行) 纯 C 迁移。
 * 迁移日期：2026-09-07
 *
 * 与 ShadowStrike 的差异（WKD 化）：
 *  - 消费目标从系统 Kernel-Process Provider 改为自家 WkDefender Provider
 *    （WKD_ETW_PROVIDER_GUID {9F2C4D1A-3B6E-4C70-9A8B-1D2E3F4A5B6C}）。
 *  - 事件载荷直解 WKD_MESSAGE（[WKD_MESSAGE_HEADER + WKD_MESSAGE_BODY_*]），
 *    与 ALPC 通道同源同构 —— Agent 端"同一份解析模板"双通道复用。
 *  - SS std::thread/std::mutex/std::vector → Win32 CreateThread/CRITICAL_SECTION
 *    /栈缓冲，纯 C 无 STL 依赖。
 *  - 会话名 WkDefender-EtwTrace（共享实时会话）。
 *  - 本期不接编排层（不调 OrcWkdMessageEnqueueCallback）：ETW 消费到
 *    消费者为止，EventRecordCallback 直解 WKD_MESSAGE 后按 Type 打印/分发
 *    内建轻量消费者；预留 SetDispatchCallback 扩展点（下一阶段接编排）。
 *
 * 线程模型：
 *  - EtwConsumerThreadProc 单线程阻塞 ProcessTrace，消费回调在 ETW 服务
 *    线程内同步执行（SS 同款，回调须快进快出）。
 *  - 停止序列：CloseTrace(consumerHandle) 解阻塞 → 等待线程退出 →
 *    ControlTraceW(EVENT_TRACE_CONTROL_STOP)。
 *
 * 权限面：ETW 实时会话可被任意管理员进程（存在性察觉）——注意与 ALPC
 * 私有信道的权限差异（文档注明，设计取舍见重构档案）。
 *
 * @author WkDefender Team
 * @version 1.0.0
 * ============================================================================
 */

#ifndef WKDEFENDER_ETW_CONSUMER_H
#define WKDEFENDER_ETW_CONSUMER_H

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>   /* EVENT_RECORD 完整结构 + PROCESS_TRACE_MODE_* (新 SDK 26100 迁至此处) */

#include "../WkDefenderHeader.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief WkDefender ETW Provider GUID（与 Driver 侧 WKD_ETW_PROVIDER_GUID
 *        同值，Driver 发布 / Agent 订阅）。
 *
 * 本 TU 定义实例（普通链接），头文件 extern 声明。
 */
EXTERN_C GUID WKD_ETW_PROVIDER_GUID;

/**
 * @brief WKDefender ETW 实时会话名。
 *
 * 同机器同权限下唯一；会话已存在时 Start 会自动先停旧会话再重建
 * （对齐 SS EnableETWProcessTracing 的 ERROR_ALREADY_EXISTS 处理）。
 */
#define WKD_ETW_SESSION_NAME        L"WkDefender-EtwTrace"

/**
 * @brief ETW 会话 FlushTimer（秒）。
 */
#define WKD_ETW_FLUSH_TIMER_SEC     1

/**
 * @brief 消费回调函数指针（可选扩展点，下一阶段接 OrcWkdMessageEnqueueCallback）。
 *
 * @param Header   合法 WKD_MESSAGE_HEADER（指向 ETW UserData，回调期间有效）。
 * @param Body     Body 区首地址（可为空，若 BodySize=0）。
 * @param BodySize 载荷 Body 字节数（已做边界校验，<= UserData 剩余）。
 */
typedef VOID (WINAPI *ETW_DISPATCH_CALLBACK)(
    _In_ PWKD_MESSAGE_HEADER Header,
    _In_opt_ PVOID Body,
    _In_ ULONG BodySize
    );

/**
 * @brief 初始化消费器（幂等，置零内部状态）。
 *
 * 可安全重复调用；会复位已注册的分派回调。
 * @return 恒 STATUS_SUCCESS。
 */
NTSTATUS
EtwConsumer_Initialize(
    VOID
    );

/**
 * @brief 启动 ETW 实时消费会话。
 *
 * 流程：StartTraceW → EnableTraceEx2（全关键字/VERBOSE）→ OpenTraceW
 * （REAL_TIME | EVENT_RECORD）→ 创建消费者线程 ProcessTrace。
 *
 * 会话已存在（ERROR_ALREADY_EXISTS）时自动停旧会话重建。
 * 失败时内部已做逐级清理，不残留会话/句柄。
 *
 * @return STATUS_SUCCESS 成功；STATUS_ACCESS_DENIED 权限不足；
 *         STATUS_INSUFFICIENT_RESOURCES 资源不足；其他 NTSTATUS 失败。
 */
NTSTATUS
EtwConsumer_Start(
    VOID
    );

/**
 * @brief 停止 ETW 实时消费会话（幂等）。
 *
 * CloseTrace 解阻塞 ProcessTrace → 等待消费者线程退出 → ControlTraceW
 * (STOP)。重复调用安全。
 */
VOID
EtwConsumer_Shutdown(
    VOID
    );

/**
 * @brief 查询消费器是否活跃。
 * @return TRUE 会话已启动且未停止。
 */
BOOLEAN
EtwConsumer_IsActive(
    VOID
    );

/**
 * @brief 注册 WKD_MESSAGE 分派回调（下一阶段接编排层的扩展点）。
 *
 * 回调在 ETW 服务线程内同步执行，须快进快出、禁止重入 ETW 会话操作。
 * 传 NULL 可解除注册（恢复内建默认打印消费者）。
 */
VOID
EtwConsumer_SetDispatchCallback(
    _In_opt_ ETW_DISPATCH_CALLBACK Callback
    );

#ifdef __cplusplus
}   /* extern "C" */
#endif

#endif  /* WKDEFENDER_ETW_CONSUMER_H */