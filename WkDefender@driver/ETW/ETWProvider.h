/*
 * WkDefender - Enterprise NGAV/EDR Agent Kernel Driver
 *
 * ETWProvider.h - ETW (Event Tracing for Windows) provider.
 *
 * ============================================================================
 * 迁移说明（ShadowStrike 校验资产 → WkDefender）
 * ============================================================================
 * 本模块由 ShadowStrike/PhantomSensor/PhantomSensor/ETW/ETWProvider.{c,h}
 * 迁移而来（2026-09-07）。
 *
 * 迁移决策（与用户确认）：
 *  1. 仅迁移 ETWProvider 引擎核心（~3.2k 行），不迁移 TelemetryEvents/
 *     ETWConsumer/EventSchema/ManifestGenerator（双轨冗余/与编排层重叠/线
 *     下工具链，与"独立子系统"目标不符）。
 *  2. ETW 事件载荷改造为 WKD_MESSAGE 协议（[WKD_MESSAGE_HEADER +
 *     WKD_MESSAGE_BODY_*]），使 Driver 端"同一份消息双出口"（ALPC /
 *     ETW），Agent 端"同一份解析模板"（ALPC 收包 / ETW 消费）——彻底实现
 *     用户态消费逻辑复用。EtwEventId = WKD_MESSAGE_TYPE 值（单枚举双通道）。
 *  3. Provider GUID 新生成（WkDefender 专属，与 ShadowStrike 并存不冲突）。
 *  4. 独立子系统：本期不接入任何现有回调（ProcessNotify/ImageNotify 等
 *     EtwWrite 接线为下一阶段）；仅靠 9xx 诊断事件自产验证连通性。
 *
 * 保留的 SS 引擎核心（battle-tested）：
 *  - 状态机生命周期（InterlockedCompareExchange 防双初始化）
 *  - 每事件 ID 描述符 + 关键字/级别过滤
 *  - 每严重级别限速（CRITICAL 永不丢弃）
 *  - 原子使能快照（锁无关使能跟踪）
 *  - in-flight 写入引用计数 + 有界排空超时
 *  - ReadAcquire 内存序（ARM64 安全）
 *  - 有界字符串拷贝（wcsnlen / Length 字段）
 *  - NPAGED_LOOKASIDE_LIST 事件缓冲池
 *
 * 与 SS 的差异：
 *  - 不再提供 EtwWriteProcessEvent 等 14 个语义化便捷构造器；统一经
 *    EtwWriteWkdMessage 写入（调用方自行构造 WKD_MESSAGE）。
 *    保留 EtwWriteDiagnosticEvent 便捷封装（Diagnostic 段 9xx 用于自产
 *    诊断/连通性验证，与进程/镜像等业务事件来源不同）。
 *  - include 集合按 WkDefender 风格收敛（ntifs.h + NotificationManager.h）。
 *
 * @author WkDefender Team
 * @version 1.0.0
 * ============================================================================
 */

#ifndef WKDEFENDER_ETW_PROVIDER_H
#define WKDEFENDER_ETW_PROVIDER_H

#include "../../framework.h"
#include "../Notification/NotificationManager.h"

//
// ETW control codes — evntrace.h 内核分区未导出时补全
//
#ifndef EVENT_CONTROL_CODE_DISABLE_PROVIDER
#define EVENT_CONTROL_CODE_DISABLE_PROVIDER  0
#endif
#ifndef EVENT_CONTROL_CODE_ENABLE_PROVIDER
#define EVENT_CONTROL_CODE_ENABLE_PROVIDER   1
#endif
#ifndef EVENT_CONTROL_CODE_CAPTURE_STATE
#define EVENT_CONTROL_CODE_CAPTURE_STATE     2
#endif

// ============================================================================
// ETW PROVIDER 配置
// ============================================================================

/**
 * @brief WkDefender ETW Provider GUID。
 *
 * 头文件 extern 声明，ETWProvider.c 内 INITGUID+DEFINE_GUID 定义，
 * 避免多 TU 包含时的重复定义链接错误。
 *
 * 属"WkDefender 专属"，新生成，与 ShadowStrike {3A5E8B2C-...} 并存不冲突。
 */
// {9F2C4D1A-3B6E-4C70-9A8B-1D2E3F4A5B6C}
EXTERN_C const GUID WKD_ETW_PROVIDER_GUID;

/**
 * @brief 提供者名称。
 */
#define WKD_ETW_PROVIDER_NAME L"WkDefender-Security-Driver"

/**
 * @brief 池标签。
 */
#define ETW_POOL_TAG_GENERAL    'wWEk'
#define ETW_POOL_TAG_EVENT      'vWEk'
#define ETW_POOL_TAG_BUFFER     'bWEk'

// ============================================================================
// ETW 关键词（用于过滤）
// ============================================================================

#define ETW_KEYWORD_PROCESS      0x0000000000000001ULL
#define ETW_KEYWORD_THREAD       0x0000000000000002ULL
#define ETW_KEYWORD_IMAGE        0x0000000000000004ULL
#define ETW_KEYWORD_FILE         0x0000000000000008ULL
#define ETW_KEYWORD_REGISTRY     0x0000000000000010ULL
#define ETW_KEYWORD_MEMORY       0x0000000000000020ULL
#define ETW_KEYWORD_NETWORK      0x0000000000000040ULL
#define ETW_KEYWORD_BEHAVIOR     0x0000000000000080ULL
#define ETW_KEYWORD_SECURITY     0x0000000000000100ULL
#define ETW_KEYWORD_DIAGNOSTIC   0x0000000000000200ULL
#define ETW_KEYWORD_THREAT       0x0000000000000400ULL

// ============================================================================
// ETW 级别
// ============================================================================

#define ETW_LEVEL_CRITICAL            1
#define ETW_LEVEL_ERROR               2
#define ETW_LEVEL_WARNING             3
#define ETW_LEVEL_INFORMATIONAL       4
#define ETW_LEVEL_VERBOSE             5

// ============================================================================
// ETW 事件载荷（WKD_MESSAGE 容器）
// ============================================================================

/**
 * @brief WKD ETW 事件载荷。
 *
 * 载荷 = [WKD_MESSAGE_HEADER + WKD_MESSAGE_BODY_*]，与 ALPC 通道
 * 完全同源（Driver 同构构建 / Agent 同构解析）。
 *
 * DataSize = sizeof(WKD_MESSAGE_HEADER) + Header.BodySize。
 * Data 首地址按 8 字节对齐（EtwEventDataDescCreate 对敏感字段的对齐要求）。
 */

/**
 * @brief ETW 载荷最大字节数（防御上界，防止构造错误导致异常事件）。
 *
 * WKD_MESSAGE_BODY_* 最大者约 1.9KB（SECURITY_EVENT Evidence[1024]），
 * 取 8KB 上界足够覆盖全部现役/未来 Body。
 */
#define WKD_ETW_MAX_PAYLOAD_SIZE        8192

// ============================================================================
// ETW PROVIDER 生命周期状态
// ============================================================================

typedef enum _ETW_PROVIDER_STATE {
    EtwState_Uninitialized = 0,
    EtwState_Initializing  = 1,
    EtwState_Ready         = 2,
    EtwState_ShuttingDown  = 3,
    EtwState_Shutdown      = 4
} ETW_PROVIDER_STATE;

// ============================================================================
// ETW PROVIDER 全局状态
// ============================================================================

typedef struct _ETW_PROVIDER_GLOBALS {
    // 生命周期状态（Interlocked 访问）
    volatile LONG State;
    UINT32 Reserved0;

    // 注册
    REGHANDLE ProviderHandle;

    // 使能状态（EnableCallback 写入，事件写入方读取）
    volatile LONG Enabled;
    UINT32 Reserved3;
    volatile UCHAR EnableLevel;
    UINT8 EnablePadding[7];
    volatile LONGLONG EnableFlags;

    // 统计
    volatile LONG64 EventsWritten;
    volatile LONG64 EventsDropped;
    volatile LONG64 BytesWritten;

    // 限速
    volatile LONG EventsThisSecond;
    UINT32 Reserved1;
    volatile LONG64 CurrentSecondStart;
    UINT32 MaxEventsPerSecond;
    UINT32 Reserved2;

    // in-flight 写入引用计数（安全停机）
    volatile LONG InFlightWriters;
    UINT32 Reserved4;

    // Lookaside 列表 — 尺寸 = 最大载荷，向上取整 256 字节
    NPAGED_LOOKASIDE_LIST EventBufferLookaside;
} ETW_PROVIDER_GLOBALS, *PETW_PROVIDER_GLOBALS;

// ============================================================================
// 编译期安全断言
// ============================================================================

#define ETW_PAYLOAD_BUFFER_SIZE \
    ((WKD_ETW_MAX_PAYLOAD_SIZE + 255) & ~(SIZE_T)255)

C_ASSERT(sizeof(WKD_MESSAGE_HEADER) >= 8);
C_ASSERT(ETW_PAYLOAD_BUFFER_SIZE >= sizeof(WKD_MESSAGE_HEADER));

// ============================================================================
// 公共 API — 初始化
// ============================================================================

/**
 * @brief 初始化 ETW Provider。
 * @return STATUS_SUCCESS 成功。
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
EtwProviderInitialize(
    VOID
    );

/**
 * @brief 关闭 ETW Provider。
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
EtwProviderShutdown(
    VOID
    );

// ============================================================================
// 公共 API — 使能查询
// ============================================================================

/**
 * @brief 检查 ETW 是否在指定级别+关键字下使能。
 * @param Level 事件级别。
 * @param Keywords 事件关键字。
 * @return TRUE 使能。
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
EtwProviderIsEnabled(
    _In_ UCHAR Level,
    _In_ ULONGLONG Keywords
    );

// ============================================================================
// 公共 API — 事件写入
// ============================================================================

/**
 * @brief 写入一条 WKD_MESSAGE 容器事件（主入口）。
 *
 * @param Message   指向 WKD_MESSAGE（Header+Body 连续内存）。
 *                  Header.Magic 必须 = WKD_NOTIFICATION_MAGIC，
 *                  Header.BodySize 决定载荷长度。
 * @param Keywords  事件关键字（ETW_KEYWORD_*）。
 * @param Level     事件级别（ETW_LEVEL_*）。
 * @return STATUS_SUCCESS 成功；含未使能返回 STATUS_SUCCESS（幂等旁路）；
 *         PROV 状态非 READY / 载荷超界返回 STATUS_UNSUCCESSFUL 等。
 * @irql <= DISPATCH_LEVEL
 *
 * 注意：CRITICAL 级别事件不受限速影响（永不丢弃）。
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EtwWriteWkdMessage(
    _In_ const PWKD_MESSAGE Message,
    _In_ ULONGLONG Keywords,
    _In_ UCHAR Level
    );

/**
 * @brief 便捷写入诊断事件（9xx 段，用于自产诊断/连通性验证）。
 *
 * 载荷 = [WKD_MESSAGE_HEADER] + [WKD_MESSAGE_BODY_DIAGNOSTIC_EVENT]。
 * 与 EtwWriteWkdMessage 等价，仅省去调用方手工构造。
 *
 * @param Type        WKD_MESSAGE_TYPE 诊断枚举（WkdMessage_DriverStarted/
 *                    Heartbeat/ComponentHealth/DriverError 等 0x41xx）。
 * @param ComponentId 组件 ID。
 * @param Severity    严重程度 1-10。
 * @param ErrorCode   错误码（NTSTATUS 或自定义）。
 * @param ComponentName 组件名（ANSI/宽字符串皆可，内部有界拷贝）。
 * @param Message     诊断消息。
 * @return STATUS_SUCCESS 成功。
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EtwWriteDiagnosticEvent(
    _In_ WKD_MESSAGE_TYPE Type,
    _In_ ULONG ComponentId,
    _In_ ULONG Severity,
    _In_ ULONG ErrorCode,
    _In_ PCWSTR ComponentName,
    _In_ PCWSTR Message
    );

// ============================================================================
// 公共 API — 统计
// ============================================================================

/**
 * @brief 获取 ETW Provider 统计（原子读）。
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EtwProviderGetStatistics(
    _Out_ PUINT64 EventsWritten,
    _Out_ PUINT64 EventsDropped,
    _Out_ PUINT64 BytesWritten
    );

// ============================================================================
// 便捷宏
// ============================================================================

/**
 * @brief 若使能则写入 WKD 容器事件。
 */
#define ETW_LOG_WKD(message, keywords, level) \
    do { \
        if (EtwProviderIsEnabled((level), (keywords))) { \
            EtwWriteWkdMessage((message), (keywords), (level)); \
        } \
    } while (0)

/**
 * @brief 若使能则写入诊断事件（CRITICAL/ERROR→DriverError，WARNING→
 *        ComponentHealth，INFO/VERBOSE→Heartbeat）。
 */
#define ETW_LOG_DIAGNOSTIC(level, componentId, componentName, message) \
    do { \
        if (EtwProviderIsEnabled((level), ETW_KEYWORD_DIAGNOSTIC)) { \
            WKD_MESSAGE_TYPE _etwDiagId = \
                ((level) <= ETW_LEVEL_ERROR) ? WkdMessage_DriverError : \
                ((level) <= ETW_LEVEL_WARNING) ? WkdMessage_ComponentHealth : \
                WkdMessage_Heartbeat; \
            EtwWriteDiagnosticEvent(_etwDiagId, (componentId), (level), 0, \
                                    (componentName), (message)); \
        } \
    } while (0)

#endif // WKDEFENDER_ETW_PROVIDER_H
