/*
 * WkDefender - Enterprise NGAV/EDR Agent Kernel Driver
 *
 * ETWProvider.c - ETW (Event Tracing for Windows) provider.
 * ============================================================================
 * 迁移：ShadowStrike/PhantomSensor/PhantomSensor/ETW/ETWProvider.c (v2.1.0)
 * 迁移日期：2026-09-07
 *
 * 保留的引擎核心（SHADOWSTRIKE 校验资产，battle-tested）：
 *  - EtwpAcquireWriterRef/EtwpReleaseWriterRef（in-flight 引用计数 + 停机排空）
 *  - EtwpCheckRateLimit（每级别限速，CRITICAL 永不丢弃）
 *  - EtwpEnableCallback（原子使能快照发布）
 *  - EtwpCopyBoundedString / EtwpCopyUnicodeStringBounded
 *  - EtwpWriteEvent（通用 ETW 写入尾，描述符 + 数据描述符数组）
 *
 * 与 SHADOWSTRIKE 的差异（WKD 化）：
 *  - 载荷 = WKD_MESSAGE（[HEADER + BODY]）单 blob，非 SS 的逐字段描述符。
 *  - 移除了 EtwWriteProcessEvent 等 14 个语义化便捷构造器（统一经
 *    EtwWriteWkdMessage 写入）；保留 EtwWriteDiagnosticEvent 便捷封装。
 *  - 移除了 TELEMETRY_PERFORMANCE/BehaviorTypes/NetworkTypes 等 Shared 类型
 *    （本地化 / 合并进 WKD_BODY_*）。
 *  - 事件描述符按 WKD_MESSAGE_TYPE 段映射关键词/级别（见 EtwpDescriptorForType）。
 *
 * Copyright (c) WkDefender Team
 * ============================================================================
 */

#include <initguid.h>
#include "ETWProvider.h"

//
// GUID 定义（本 TU 经 INITGUID 定义；头文件 extern 声明）
//
#ifdef DEFINE_GUID
// {9F2C4D1A-3B6E-4C70-9A8B-1D2E3F4A5B6C}
DEFINE_GUID(WKD_ETW_PROVIDER_GUID,
    0x9f2c4d1a, 0x3b6e, 0x4c70, 0x9a, 0x8b, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b, 0x6c);
#endif

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, EtwProviderInitialize)
#pragma alloc_text(PAGE, EtwProviderShutdown)
#endif

// ============================================================================
// 内部常量
// ============================================================================

#define ETW_MAX_EVENTS_PER_SECOND           10000
#define ETW_LOOKASIDE_DEPTH                 256
#define ETW_RATE_LIMIT_WINDOW_100NS         (10000000LL)  // 1 秒（100ns 单位）
#define ETW_MAX_DIAGNOSTIC_MSG_CHARS        512
#define ETW_SHUTDOWN_DRAIN_SPIN_LIMIT       1000
#define ETW_SHUTDOWN_DRAIN_SLEEP_MS         1
#define ETW_SHUTDOWN_MAX_DRAIN_100NS        (10000000LL * 10)  // 最多 10 秒排空

// ============================================================================
// 全局状态
// ============================================================================

static ETW_PROVIDER_GLOBALS g_EtwGlobals = { 0 };

// ============================================================================
// 内部函数前向声明
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
EtwpCheckRateLimit(
    _In_ UCHAR EventLevel
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
EtwpUpdateStatistics(
    _In_ ULONG EventSize,
    _In_ BOOLEAN Success
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID NTAPI
EtwpEnableCallback(
    _In_ LPCGUID SourceId,
    _In_ ULONG IsEnabled,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _In_opt_ PVOID CallbackContext
    );

static BOOLEAN
EtwpAcquireWriterRef(
    VOID
    );

static VOID
EtwpReleaseWriterRef(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
EtwpCopyBoundedString(
    _Out_writes_(DestChars) PWCHAR Dest,
    _In_ ULONG DestChars,
    _In_ PCWSTR Src,
    _In_ ULONG MaxSrcChars
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
EtwpCopyUnicodeStringBounded(
    _Out_writes_(DestChars) PWCHAR Dest,
    _In_ ULONG DestChars,
    _In_ PCUNICODE_STRING Src
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
EtwpInitMessageHeader(
    _Out_ PWKD_MESSAGE_HEADER Header,
    _In_ WKD_MESSAGE_TYPE Type,
    _In_ ULONG BodySize,
    _In_ ULONG Priority
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
EtwpValidateWkdMessage(
    _In_ const PWKD_MESSAGE Message
    );

// ============================================================================
// 事件描述符表（按 WKD_MESSAGE_TYPE 段映射 关键词/级别）
// ============================================================================

/**
 * @brief 依据 WKD_MESSAGE_TYPE 派生事件描述符。
 *
 * 载荷逻辑级别/关键词由调用方传入，本函数仅在调用方未显式指定时按
 * 类型段提供默认值，并在内部分配 EventId（= WKD_MESSAGE_TYPE 值）。
 * 出于简单与一致性，主写入路径（EtwWriteWkdMessage）直接以内联构造
 * 保存 ID=Type 的方式写入，无需此处静态描述符表。
 */

// ============================================================================
// 内部实现 — EtwpCheckRateLimit
// ============================================================================

_Use_decl_annotations_
static BOOLEAN
EtwpCheckRateLimit(
    _In_ UCHAR EventLevel
    )
/*++

Routine Description:

    限制非关键事件的写入速率。CRITICAL 级别事件永不丢弃。
    使用 100ns 精度的秒窗口，窗口切换时重置计数。

Arguments:

    EventLevel - 事件级别（ETW_LEVEL_*）。

Return Value:

    TRUE  - 允许写入。
    FALSE - 超过限速，拒绝（非关键）。

--*/
{
    LARGE_INTEGER now;
    LONG eventsThisSecond;

    // CRITICAL 永不限速
    if (EventLevel <= ETW_LEVEL_CRITICAL) {
        return TRUE;
    }

    KeQuerySystemTimePrecise(&now);
    if (now.QuadPart - g_EtwGlobals.CurrentSecondStart >= ETW_RATE_LIMIT_WINDOW_100NS) {
        // 新秒窗口：原子替换起始时刻，防止多线程重复重置
        InterlockedCompareExchange64(
            &g_EtwGlobals.CurrentSecondStart,
            now.QuadPart,
            g_EtwGlobals.CurrentSecondStart
            );
        // 重置计数（窗口竞争下允许轻微超发，可接受）
        InterlockedExchange(&g_EtwGlobals.EventsThisSecond, 0);
    }

    eventsThisSecond = InterlockedIncrement(&g_EtwGlobals.EventsThisSecond);
    if ((ULONG)eventsThisSecond > g_EtwGlobals.MaxEventsPerSecond) {
        InterlockedDecrement(&g_EtwGlobals.EventsThisSecond);
        return FALSE;
    }

    return TRUE;
}

// ============================================================================
// 内部实现 — EtwpUpdateStatistics
// ============================================================================

_Use_decl_annotations_
static VOID
EtwpUpdateStatistics(
    _In_ ULONG EventSize,
    _In_ BOOLEAN Success
    )
{
    if (Success) {
        InterlockedIncrement64(&g_EtwGlobals.EventsWritten);
        InterlockedAdd64(&g_EtwGlobals.BytesWritten, EventSize);
    } else {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
    }
}

// ============================================================================
// 内部实现 — 使能回调（原子使能快照发布）
// ============================================================================

_Use_decl_annotations_
static VOID NTAPI
EtwpEnableCallback(
    _In_ LPCGUID SourceId,
    _In_ ULONG IsEnabled,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _In_opt_ PVOID CallbackContext
    )
/*++

Routine Description:

    ETW 控制器使能/禁用回调。将控制器下发的使能状态、级别、关键字
    发布到全局原子快照，供无锁事件写入方读取。

--*/
{
    UNREFERENCED_PARAMETER(SourceId);
    UNREFERENCED_PARAMETER(MatchAllKeyword);
    UNREFERENCED_PARAMETER(FilterData);
    UNREFERENCED_PARAMETER(CallbackContext);

    if (IsEnabled) {
        InterlockedExchange(&g_EtwGlobals.Enabled, TRUE);
        InterlockedExchange8((volatile CHAR*)&g_EtwGlobals.EnableLevel, (CHAR)Level);
        InterlockedExchange64(&g_EtwGlobals.EnableFlags, (LONGLONG)MatchAnyKeyword);
    } else {
        InterlockedExchange(&g_EtwGlobals.Enabled, FALSE);
        InterlockedExchange8((volatile CHAR*)&g_EtwGlobals.EnableLevel, 0);
        InterlockedExchange64(&g_EtwGlobals.EnableFlags, 0);
    }

    MemoryBarrier();
}

// ============================================================================
// 内部实现 — 写入引用计数（安全停机）
// ============================================================================

_Use_decl_annotations_
static BOOLEAN
EtwpAcquireWriterRef(
    VOID
    )
/*++

Routine Description:

    获取写入引用。若 Provider 非 READY 状态（停机中）返回 FALSE，阻止新写入。

    使用 ReadAcquire 进行两次状态检查以强制弱序架构（ARM64）的顺序性：
    第一次检查确保停机期间不新增写入；Increment 后第二次检查确保若停机
    竞态进入，立即释放引用，停机排空循环可一致收敛。

--*/
{
    if (ReadAcquire(&g_EtwGlobals.State) != EtwState_Ready) {
        return FALSE;
    }

    InterlockedIncrement(&g_EtwGlobals.InFlightWriters);

    if (ReadAcquire(&g_EtwGlobals.State) != EtwState_Ready) {
        InterlockedDecrement(&g_EtwGlobals.InFlightWriters);
        return FALSE;
    }

    return TRUE;
}

_Use_decl_annotations_
static VOID
EtwpReleaseWriterRef(
    VOID
    )
{
    InterlockedDecrement(&g_EtwGlobals.InFlightWriters);
}

// ============================================================================
// 内部实现 — 有界字符串拷贝
// ============================================================================

_Use_decl_annotations_
static VOID
EtwpCopyBoundedString(
    _Out_writes_(DestChars) PWCHAR Dest,
    _In_ ULONG DestChars,
    _In_ PCWSTR Src,
    _In_ ULONG MaxSrcChars
    )
/*++

Routine Description:

    将 PCWSTR 有界拷贝到定长 WCHAR 缓冲。用 wcsnlen 防止扫描越过
    MaxSrcChars。恒以 NUL 结尾。

    TRUSTED-CALLER CONTRACT: Src 必须指向合法可读内核内存，长度至少
    MaxSrcChars * sizeof(WCHAR) 字节。本函数仅内部使用，不得以用户态
    指针或已释放/分页内存的指针在提升 IRQL 下调用。

--*/
{
    size_t srcLen;
    ULONG copyChars;

    if (DestChars == 0) {
        return;
    }

    if (Src == NULL) {
        Dest[0] = L'\0';
        return;
    }

    srcLen = wcsnlen(Src, MaxSrcChars);
    copyChars = (ULONG)min(srcLen, (size_t)(DestChars - 1));

    if (copyChars > 0) {
        RtlCopyMemory(Dest, Src, copyChars * sizeof(WCHAR));
    }

    Dest[copyChars] = L'\0';
}

_Use_decl_annotations_
static VOID
EtwpCopyUnicodeStringBounded(
    _Out_writes_(DestChars) PWCHAR Dest,
    _In_ ULONG DestChars,
    _In_ PCUNICODE_STRING Src
    )
/*++

Routine Description:

    将 UNICODE_STRING 有界拷贝到定长 WCHAR 缓冲。用 Length 字段（字节）
    计算，无无界扫描。恒以 NUL 结尾。

--*/
{
    ULONG srcChars;
    ULONG copyChars;

    if (DestChars == 0) {
        return;
    }

    if (Src == NULL || Src->Buffer == NULL || Src->Length == 0) {
        Dest[0] = L'\0';
        return;
    }

    srcChars = Src->Length / sizeof(WCHAR);
    copyChars = min(srcChars, DestChars - 1);

    if (copyChars > 0) {
        RtlCopyMemory(Dest, Src->Buffer, copyChars * sizeof(WCHAR));
    }

    Dest[copyChars] = L'\0';
}

// ============================================================================
// 内部实现 — WKD 消息校验
// ============================================================================

_Use_decl_annotations_
static BOOLEAN
EtwpValidateWkdMessage(
    _In_ const PWKD_MESSAGE Message
    )
/*++

Routine Description:

    校验 WKD_MESSAGE 载荷有效性：
      - 非空指针
      - Magic 匹配
      - BodySize 与 Header 一致性（0 <= BodySize < 上限）

--*/
{
    if (Message == NULL) {
        return FALSE;
    }

    if (Message->Header.Magic != WKD_NOTIFICATION_MAGIC) {
        return FALSE;
    }

    if (Message->Header.BodySize > (WKD_ETW_MAX_PAYLOAD_SIZE - sizeof(WKD_MESSAGE_HEADER))) {
        return FALSE;
    }

    return TRUE;
}

// ============================================================================
// 内部实现 — WKD 消息头初始化
// ============================================================================

_Use_decl_annotations_
static VOID
EtwpInitMessageHeader(
    _Out_ PWKD_MESSAGE_HEADER Header,
    _In_ WKD_MESSAGE_TYPE Type,
    _In_ ULONG BodySize,
    _In_ ULONG Priority
    )
{
    LARGE_INTEGER now;

    KeQuerySystemTimePrecise(&now);

    Header->Magic = WKD_NOTIFICATION_MAGIC;
    Header->Version = WKD_NOTIFICATION_VERSION;
    Header->Type = Type;
    Header->Source = WkdMessage_SourceEtw;
    Header->Priority = (WKD_MESSAGE_PRIORITY)Priority;
    Header->Timestamp = now;
    Header->SourceProcessId = NULL;
    Header->TargetProcessId = NULL;
    Header->ThreadId = NULL;
    Header->BodySize = BodySize;
    RtlZeroMemory(&Header->Flags, sizeof(Header->Flags));
    Header->AtomicRisk = 0;
    Header->SyncRequestId = 0;
}

// ============================================================================
// 内部通用写入尾
// ============================================================================

_Use_decl_annotations_
static NTSTATUS
EtwpWriteEvent(
    _In_ ULONG EventId,
    _In_ UCHAR Level,
    _In_ ULONGLONG Keywords,
    _In_ ULONG UserDataCount,
    _In_reads_(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
    )
/*++

Routine Description:

    执行实际 EtwWrite 调用。构造 EVENT_DESCRIPTOR，调用 EtwWriteEx。

Arguments:

    EventId       - 事件 ID（= WKD_MESSAGE_TYPE 值）。
    Level         - 事件级别。
    Keywords      - 事件关键字。
    UserDataCount - 数据描述符数量。
    UserData      - 数据描述符数组。

Return Value:

    STATUS_SUCCESS 成功。

--*/
{
    NTSTATUS status;
    EVENT_DESCRIPTOR descriptor;
    UCHAR effectiveLevel = Level;
    ULONGLONG effectiveKeywords = Keywords;

    // CRITICAL 永不丢弃，其余受级别/关键字过滤
    if (!EtwpCheckRateLimit(effectiveLevel)) {
        // 超限速：由调用方计入 dropped（本函数不触碰计数器）
        return STATUS_REQUEST_ABORTED;
    }

    EventDescCreate(&descriptor, (USHORT)EventId, 0, 0, effectiveLevel, 0, 0, effectiveKeywords);

    status = EtwWriteEx(
        g_EtwGlobals.ProviderHandle,
        &descriptor,
        0,              // Filter（WKD 无独立过滤语义，ETW 层按 descriptor 过滤）
        0,              // Flags（PASSIVE/DISPATCH 常规路径，无需 NO_FAULTING）
        NULL,           // no activity id
        NULL,           // no related activity id
        UserDataCount,
        UserData
        );

    return status;
}

// ============================================================================
// 公共 API — EtwProviderInitialize
// ============================================================================

_Use_decl_annotations_
NTSTATUS
EtwProviderInitialize(
    VOID
    )
/*++

Routine Description:

    初始化 ETW Provider 子系统。用 InterlockedCompareExchange 状态机
    防止并发双初始化。

Return Value:

    STATUS_SUCCESS 成功。
    STATUS_ALREADY_INITIALIZED 已初始化。
    STATUS_UNSUCCESSFUL 状态转换失败。

--*/
{
    NTSTATUS status;
    LONG previousState;

    PAGED_CODE();

    // 原子状态转换：UNINITIALIZED -> INITIALIZING
    previousState = InterlockedCompareExchange(
        &g_EtwGlobals.State,
        EtwState_Initializing,
        EtwState_Uninitialized
        );

    if (previousState == EtwState_Ready) {
        return STATUS_ALREADY_INITIALIZED;
    }

    if (previousState != EtwState_Uninitialized) {
        return STATUS_UNSUCCESSFUL;
    }

    // 独占初始化路径。除 State 外清零，避免另一线程瞬时看到
    // State 回退为 Uninitialized 而并发进入二次初始化。
    RtlZeroMemory(
        (PUCHAR)&g_EtwGlobals + FIELD_OFFSET(ETW_PROVIDER_GLOBALS, Reserved0),
        sizeof(ETW_PROVIDER_GLOBALS) - FIELD_OFFSET(ETW_PROVIDER_GLOBALS, Reserved0)
        );

    // 注册 ETW Provider
    status = EtwRegister(
        &WKD_ETW_PROVIDER_GUID,
        EtwpEnableCallback,
        NULL,
        &g_EtwGlobals.ProviderHandle
        );

    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&g_EtwGlobals.State, EtwState_Uninitialized);
        return status;
    }

    // 初始化 Lookaside 缓冲池（尺寸 = 最大载荷，取整 256 字节）
    ExInitializeNPagedLookasideList(
        &g_EtwGlobals.EventBufferLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        (ULONG)ETW_PAYLOAD_BUFFER_SIZE,
        ETW_POOL_TAG_BUFFER,
        ETW_LOOKASIDE_DEPTH
        );

    // 初始化限速
    g_EtwGlobals.MaxEventsPerSecond = ETW_MAX_EVENTS_PER_SECOND;
    InterlockedExchange(&g_EtwGlobals.EventsThisSecond, 0);

    {
        LARGE_INTEGER now;
        KeQuerySystemTimePrecise(&now);
        InterlockedExchange64(&g_EtwGlobals.CurrentSecondStart, now.QuadPart);
    }

    // 统计已由 RtlZeroMemory 清零；in-flight 计数从 0 开始。
    // 注意：不要在 EtwRegister 返回后强制 Enabled=FALSE。ETW 可能在
    // EtwRegister 内部同步调用 EnableCallback（存在预启用的会话，如
    // SIEM 或 autologger）。若此处清空 Enabled 会静默丢弃这些既有会话
    // 的所有事件，直至控制器再次切换使能。RtlZeroMemory 已将 Enabled
    // 清零，此后唯一的写入者即合法的使能回调——应保留其结果。

    // 状态转换：INITIALIZING -> READY（发布给其他线程）
    MemoryBarrier();
    InterlockedExchange(&g_EtwGlobals.State, EtwState_Ready);

    return STATUS_SUCCESS;
}

// ============================================================================
// 公共 API — EtwProviderShutdown
// ============================================================================

_Use_decl_annotations_
VOID
EtwProviderShutdown(
    VOID
    )
/*++

Routine Description:

    关闭 ETW Provider。状态机推进 SHUTTING_DOWN，等待 in-flight 写入
    排空（有界），注销 Provider，释放 Lookaside 缓冲池。

--*/
{
    LONG previousState;
    LARGE_INTEGER startTime;
    LARGE_INTEGER now;

    PAGED_CODE();

    // 状态转换：READY -> SHUTTING_DOWN（原子）
    previousState = InterlockedCompareExchange(
        &g_EtwGlobals.State,
        EtwState_ShuttingDown,
        EtwState_Ready
        );

    if (previousState != EtwState_Ready) {
        // 未初始化或已在关闭，直接归零
        InterlockedExchange(&g_EtwGlobals.State, EtwState_Shutdown);
        return;
    }

    // 有界排空：等待 in-flight 写入者完成
    KeQuerySystemTimePrecise(&startTime);
    for (;;) {
        if (ReadAcquire(&g_EtwGlobals.InFlightWriters) == 0) {
            break;
        }

        KeQuerySystemTimePrecise(&now);
        if (now.QuadPart - startTime.QuadPart > ETW_SHUTDOWN_MAX_DRAIN_100NS) {
            // 超时：放弃等待（极端情况，写入方卡死）
            break;
        }

        // 先短自旋再睡眠，兼顾低延迟与省 CPU
        {
            ULONG spin = 0;
            while (spin < ETW_SHUTDOWN_DRAIN_SPIN_LIMIT &&
                   g_EtwGlobals.InFlightWriters != 0) {
                YieldProcessor();
                spin++;
            }
        }
        if (g_EtwGlobals.InFlightWriters == 0) {
            break;
        }
        LARGE_INTEGER delay;
        delay.QuadPart = -(ETW_SHUTDOWN_DRAIN_SLEEP_MS * 10000LL);
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    // 即使排空超时，注销 Provider；EtwUnregister 内部会等待其传入的
    // 回调完成，后续 EtwWriteEx 因已注销返回错误（且写入方因状态
    // != READY 已无法获取引用）。
    if (g_EtwGlobals.ProviderHandle != 0) {
        EtwUnregister(g_EtwGlobals.ProviderHandle);
        g_EtwGlobals.ProviderHandle = 0;
    }

    // 释放 Lookaside 缓冲池
    ExDeleteNPagedLookasideList(&g_EtwGlobals.EventBufferLookaside);

    InterlockedExchange(&g_EtwGlobals.State, EtwState_Shutdown);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] ETW Provider shutdown complete.\n");
}

// ============================================================================
// 公共 API — EtwProviderIsEnabled
// ============================================================================

_Use_decl_annotations_
BOOLEAN
EtwProviderIsEnabled(
    _In_ UCHAR Level,
    _In_ ULONGLONG Keywords
    )
{
    // 快速路径：未使能直接返回 FALSE
    if (ReadAcquire(&g_EtwGlobals.Enabled) == 0) {
        return FALSE;
    }

    return (ReadAcquire((volatile LONG*)&g_EtwGlobals.EnableLevel) >= (LONG)Level &&
            (ReadAcquire64(&g_EtwGlobals.EnableFlags) & (LONGLONG)Keywords) == (LONGLONG)Keywords);
}

// ============================================================================
// 公共 API — EtwWriteWkdMessage（主入口）
// ============================================================================

_Use_decl_annotations_
NTSTATUS
EtwWriteWkdMessage(
    _In_ const PWKD_MESSAGE Message,
    _In_ ULONGLONG Keywords,
    _In_ UCHAR Level
    )
/*++

Routine Description:

    写入一条 WKD_MESSAGE 容器事件。载荷 = [WKD_MESSAGE_HEADER +
    WKD_MESSAGE_BODY_*] 单 blit 描述符。EventId = WKD_MESSAGE_TYPE 值。

    安全机制：
      - 校验 Magic/BodySize（EtwpValidateWkdMessage）
      - EtwpAcquireWriterRef 停机保护
      - 载荷大小上界（WKD_ETW_MAX_PAYLOAD_SIZE）
      - 从 lookaside 池分配暂存（对齐 8 字节），拷贝后写入，避免引用
        调用方可能分页/易失的内存。

Arguments:

    Message  - 待写入的 WKD_MESSAGE（Header+Body 连续内存）。
    Keywords - 事件关键字（ETW_KEYWORD_*）。
    Level    - 事件级别（ETW_LEVEL_*）。

Return Value:

    STATUS_SUCCESS 成功（含未使能幂等旁路）。
    其他 NTSTATUS 失败（未初始化/校验失败/载荷超界）。

--*/
{
    NTSTATUS status;
    BOOLEAN acquired;
    PUCHAR buffer;
    ULONG payloadSize;
    EVENT_DATA_DESCRIPTOR dataDescriptor;

    // 校验（幂等：无效载荷直接拒绝，不正副作用统计）
    if (!EtwpValidateWkdMessage(Message)) {
        InterlockedIncrement64(&g_EtwGlobals.EventsDropped);
        return STATUS_INVALID_PARAMETER;
    }

    // 未使能早退（无锁读，热路径优先）
    if (!EtwProviderIsEnabled(Level, Keywords)) {
        return STATUS_SUCCESS;
    }

    // 停机保护
    acquired = EtwpAcquireWriterRef();
    if (!acquired) {
        return STATUS_DEVICE_NOT_READY;
    }

    payloadSize = (ULONG)sizeof(WKD_MESSAGE_HEADER) + Message->Header.BodySize;

    // 从 lookaside 分配暂存缓冲（对齐 8 字节，EtwEventDataDescCreate 要求）
    buffer = (PUCHAR)ExAllocateFromNPagedLookasideList(&g_EtwGlobals.EventBufferLookaside);
    if (buffer == NULL) {
        EtwpReleaseWriterRef();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 拷贝载荷（HEADER + BODY）
    RtlCopyMemory(buffer, &Message->Header, sizeof(WKD_MESSAGE_HEADER));
    if (Message->Header.BodySize > 0) {
        RtlCopyMemory(buffer + sizeof(WKD_MESSAGE_HEADER), Message->Body, Message->Header.BodySize);
    }

    // 构造单数据描述符（blit 整个 WKD 载荷）
    EventDataDescCreate(&dataDescriptor, buffer, payloadSize);

    status = EtwpWriteEvent(
        (ULONG)Message->Header.Type,     // EventId = WKD_MESSAGE_TYPE 值
        Level,
        Keywords,
        1,
        &dataDescriptor
        );

    // 统计
    if (!NT_SUCCESS(status)) {
        EtwpUpdateStatistics(payloadSize, FALSE);
    } else {
        EtwpUpdateStatistics(payloadSize, TRUE);
    }

    // 释放暂存
    ExFreeToNPagedLookasideList(&g_EtwGlobals.EventBufferLookaside, buffer);
    EtwpReleaseWriterRef();

    return STATUS_SUCCESS;
}

// ============================================================================
// 公共 API — EtwWriteDiagnosticEvent（便捷封装）
// ============================================================================

_Use_decl_annotations_
NTSTATUS
EtwWriteDiagnosticEvent(
    _In_ WKD_MESSAGE_TYPE Type,
    _In_ ULONG ComponentId,
    _In_ ULONG Severity,
    _In_ ULONG ErrorCode,
    _In_ PCWSTR ComponentName,
    _In_ PCWSTR Message
    )
/*++

Routine Description:

    便捷写入诊断事件（9xx 段）。构造 WKD_MESSAGE_HEADER +
    WKD_MESSAGE_BODY_DIAGNOSTIC_EVENT 载荷后经 EtwWriteWkdMessage 写入。

Arguments:

    Type          - WKD_MESSAGE_TYPE 诊断枚举（0x41xx）。
    ComponentId   - 组件 ID。
    Severity      - 严重程度 1-10。
    ErrorCode     - 错误码。
    ComponentName - 组件名（ANSI/宽字符串，内部有界拷贝）。
    Message       - 诊断消息。

Return Value:

    STATUS_SUCCESS 成功（含未使能幂等旁路）。

--*/
{
    NTSTATUS status;
    WKD_MESSAGE_BODY_DIAGNOSTIC_EVENT body;
    UCHAR stackBuffer[sizeof(WKD_MESSAGE_HEADER) + sizeof(WKD_MESSAGE_BODY_DIAGNOSTIC_EVENT)];
    PWKD_MESSAGE wkdMsg = (PWKD_MESSAGE)stackBuffer;
    ULONG payloadSize;
    EVENT_DATA_DESCRIPTOR dataDescriptor;
    BOOLEAN acquired;

    RtlZeroMemory(&body, sizeof(body));

    // 时间戳
    {
        LARGE_INTEGER now;
        KeQuerySystemTimePrecise(&now);
        body.Timestamp = now;
    }

    body.ComponentId = ComponentId;
    body.Severity = Severity;
    body.ErrorCode = ErrorCode;
    body.RelatedProcessId = NULL;

    EtwpCopyBoundedString(body.ComponentName, 128, ComponentName, 256);
    EtwpCopyBoundedString(body.Message, 512, Message, ETW_MAX_DIAGNOSTIC_MSG_CHARS);

    if (!EtwProviderIsEnabled(ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_DIAGNOSTIC)) {
        return STATUS_SUCCESS;
    }

    acquired = EtwpAcquireWriterRef();
    if (!acquired) {
        return STATUS_DEVICE_NOT_READY;
    }

    EtwpInitMessageHeader(&wkdMsg->Header, Type, (ULONG)sizeof(body), WkdMessage_PriorityLow);
    RtlCopyMemory(wkdMsg->Body, &body, sizeof(body));

    payloadSize = (ULONG)(sizeof(WKD_MESSAGE_HEADER) + sizeof(body));
    EventDataDescCreate(&dataDescriptor, wkdMsg, payloadSize);

    status = EtwpWriteEvent(
        (ULONG)Type,
        ETW_LEVEL_INFORMATIONAL,
        ETW_KEYWORD_DIAGNOSTIC,
        1,
        &dataDescriptor
        );

    if (!NT_SUCCESS(status)) {
        EtwpUpdateStatistics(payloadSize, FALSE);
    } else {
        EtwpUpdateStatistics(payloadSize, TRUE);
    }

    EtwpReleaseWriterRef();
    return STATUS_SUCCESS;
}

// ============================================================================
// 公共 API — EtwProviderGetStatistics
// ============================================================================

_Use_decl_annotations_
NTSTATUS
EtwProviderGetStatistics(
    _Out_ PUINT64 EventsWritten,
    _Out_ PUINT64 EventsDropped,
    _Out_ PUINT64 BytesWritten
    )
{
    if (EventsWritten == NULL || EventsDropped == NULL || BytesWritten == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *EventsWritten = (UINT64)ReadAcquire64(&g_EtwGlobals.EventsWritten);
    *EventsDropped = (UINT64)ReadAcquire64(&g_EtwGlobals.EventsDropped);
    *BytesWritten = (UINT64)ReadAcquire64(&g_EtwGlobals.BytesWritten);

    return STATUS_SUCCESS;
}
