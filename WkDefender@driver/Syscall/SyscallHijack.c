#include "SyscallHijack.h"
#include "SyscallService.h"
#include "SyscallMonitor.h"
#include "SyscallContextCache.h"
#include "../Common/Utils.h"
#include "../Memory/MemoryScan.h"
#include "../Memory/MemoryRegion.h"
#include "../Memory/AmsiBypassDetector.h"
#include "../Notification/NotificationManager.h"
#include "../Notification/AlpcService.h"
#include "../Process/ProcessPairContext.h"
#include "SyscallAggregation.h"
#include "../AnalysisEngine/IocEngine.h"
#include "../AnalysisEngine/AnalysisEngine.h"
#include "../Common/Exempts/Exempts.h"
//
// 检查目标 PID 是否为 LSASS（用于跨进程 syscall 检测）
//
static
BOOLEAN
ShpIsLsassPid(
    _In_ HANDLE ProcessId
    )
{
    ULONG pid = HandleToULong(ProcessId);

    /* 常见 LSASS PID 范围 */
    return (pid == 0x4E0 || pid == 0x2E0 || pid == 0x3E0 || pid == 0x1E0);
}

typedef ULONG64 *PWMI_LOGGER_CONTEXT;

//
// 外部符号：SECTION 类型对象（MmSectionObjectType，Win10 导出；此处声明以
// 供 NtMapViewOfSection 轨中 ObReferenceObjectByHandle 使用）
//
extern POBJECT_TYPE *MmSectionObjectType;

//typedef struct _WMI_LOGGER_CONTEXT {
//    ULONG LoggerId;
//    LONG BufferSize;
//    LONG MaximumEventSize;
//    ULONG LoggerMode;
//    LONG AcceptNewEvents;
//    ULONG EventMarker[2];
//    ULONG ErrorMarker;
//    ULONG64 SizeMask;
//    PVOID GetCpuClock;
//    // ...
//} WMI_LOGGER_CONTEXT, * PWMI_LOGGER_CONTEXT;

#define CKCL_PROVIDER_NAME              L"Circular Kernel Context Logger"
#define CKCL_LOGGER_ID                  2
#define EVENT_TRACE_BUFFERING_MODE      0x00000400
#define WNODE_FLAG_TRACED_GUID          0x00020000   // denotes a trace

#define ETW_TRACE_MAGIC_SYSCALL         0x501802
#define ETW_TRACE_MAGIC_SYSCALL_ENTRY   0xF33
#define ETW_TRACE_MAGIC_SYSCALL_EXIT    0xF34


// 详见 https://learn.microsoft.com/zh-cn/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
typedef enum _EVENT_TRACE_FLAG {
    EVENT_TRACE_FLAG_PROCESS = 0x00000001,
    EVENT_TRACE_FLAG_THREAD = 0x00000002,
    EVENT_TRACE_FLAG_IMAGE_LOAD = 0x00000004,
    EVENT_TRACE_FLAG_SYSTEMCALL = 0x00000080,
    EVENT_TRACE_FLAG_NETWORK_TCPIP = 0x00010000,
    EVENT_TRACE_FLAG_REGISTRY = 0x00020000,
} EVENT_TRACE_FLAG;

static const GUID CkclSessionGuid =
{ 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

// .text:000000014042FD10 48 83 64 24 30 00 and [rsp + 28h + arg_0], 0
// .text : 000000014042FD16 48 8D 4C 24 30                          lea     rcx, [rsp + 28h + arg_0]
// .text : 000000014042FD1B 48 8B 05 BE 0C 7D 00                    mov     rax, cs : off_140C009E0
// .text : 000000014042FD22 E8 B9 90 FD FF                          call    _guard_dispatch_icall
// .text : 000000014042FD27 48 8B 44 24 30                          mov     rax, [rsp + 28h + arg_0]
// .text : 000000014042FD2C E9 2D 96 DF FF                          jmp     loc_14022935E
static const WKD_MEMORY_SIGNATURE_DEFINE WkdMemorySignature_EtwpGetLoggerTimeStampCallback = {
    "EtwpGetLoggerTimeStampCallback@2",
     {0x48, 0x83, 0x64, 0x24, 0x00, 0x00, 0x48, 0x8D, 0x4C, 0x24, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x00, 0xE9},
     {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF},
     28
};


static PVOID WkdDynamicTraceMask = NULL;
// PAGE:00000001408C03AF F0 83 0D 49 C2 43 00 02                    lock or cs:KiDynamicTraceMask, 2
static const WKD_MEMORY_SIGNATURE_DEFINE WkdMemorySignature_KiDynamicTraceMask = {
    "KiDynamicTraceMask",
    {0xF0, 0x83, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x02},
    {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF},
    8
};

//
// 全局变量定义
//
WKD_SYSCALL_MONITOR g_WkdSyscallMonitor = { 0 };

//
// 内部函数声明
//
typedef struct _WNODE_HEADER
{
    ULONG BufferSize;   // 为事件跟踪会话属性分配的总内存大小（以字节为单位）。 内存大小必须包括 EVENT_TRACE_PROPERTIES 结构的空间，以及内存中结构后面的会话名称字符串和日志文件名称字符串。
    ULONG ProviderId;
    union {
        ULONG64 HistoricalContext;
        struct {
            ULONG Version;
            ULONG Linkage;
        };
    };
    union {
        HANDLE KernelHandle;
        LARGE_INTEGER TimeStamp;
    };
    GUID Guid;
    ULONG ClientContext;    // 记录每个事件的时间戳时要使用的时钟解析，默认值为QPC。
    /*
        1. 查询性能计数器 (QPC)
        2. 系统时间
        3. CPU 周期计数器
    */
    ULONG Flags;
} WNODE_HEADER, * PWNODE_HEADER;

typedef struct _EVENT_TRACE_PROPERTIES
{
    WNODE_HEADER Wnode;
    // 为每个事件跟踪会话缓冲区分配的千字节内存。 最小缓冲区大小为 4 (4KB)；最大缓冲区大小为 16384 (16MB) 
    // 大多数用户应通过将 MinimumBuffers 和 MaximumBuffers 设置为相同的值来开始优化其会话。
    ULONG BufferSize;
    ULONG MinimumBuffers;
    ULONG MaximumBuffers;
    ULONG MaximumFileSize;
    ULONG LogFileMode;
    ULONG FlushTimer;
    ULONG EnableFlags;
    union {
        LONG AgeLimit;
        LONG FlushThreshold;
    } DUMMYUNIONNAME;
    ULONG NumberOfBuffers;
    ULONG FreeBuffers;
    ULONG EventsLost;
    ULONG BuffersWritten;
    ULONG LogBuffersLost;
    ULONG RealTimeBuffersLost;
    HANDLE LoggerThreadId;
    ULONG LogFileNameOffset;
    ULONG LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, * PEVENT_TRACE_PROPERTIES;

typedef struct _CKCL_TRACE_PROPERIES
{
    EVENT_TRACE_PROPERTIES EventTraceProperties;
    ULONG64 Unknown[3];
    UNICODE_STRING ProviderName;
} CKCL_TRACE_PROPERTIES, * PCKCL_TRACE_PROPERTIES;


VOID ScTrampoline(VOID);    // 阻塞跳板函数声明

NTSYSAPI
NTSTATUS
ZwTraceControl(
    _In_ ULONG FunctionCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnLength
);

//
// ETW Trace 控制
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
SmEtwTraceControl(
    _In_ ETW_TRACE_CONTROL_CODE Control
)
{
    NTSTATUS status;
    PCKCL_TRACE_PROPERTIES properties = NULL;
    WCHAR* providerName = NULL;
    ULONG length = 0;

    properties = (PCKCL_TRACE_PROPERTIES)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(CKCL_TRACE_PROPERTIES),
        'etwH'
    );

    if (!properties) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Allocate CKCL trace properties struct failed.\n");
        return STATUS_MEMORY_NOT_ALLOCATED;
    }
    RtlZeroMemory(properties, sizeof(CKCL_TRACE_PROPERTIES));

    RtlInitUnicodeString(&properties->ProviderName, (PCWSTR)CKCL_PROVIDER_NAME);

    // 结构体填充
    properties->EventTraceProperties.Wnode.BufferSize = PAGE_SIZE;
    properties->EventTraceProperties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->EventTraceProperties.Wnode.Guid = CkclSessionGuid;
    properties->EventTraceProperties.Wnode.ClientContext = 3;   // 时钟类型
    properties->EventTraceProperties.BufferSize = 4;            // KB
    properties->EventTraceProperties.MinimumBuffers = 4;
    properties->EventTraceProperties.MaximumBuffers = 4;
    properties->EventTraceProperties.LogFileMode = EVENT_TRACE_BUFFERING_MODE;
    properties->EventTraceProperties.EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;

    // 执行操作
    status = ZwTraceControl(
        Control,
        properties,
        PAGE_SIZE,
        properties,
        PAGE_SIZE,
        &length
    );

    // 释放内存空间
    ExFreePoolWithTag(properties, 'etwH');

    return status;
}

//
// 内部辅助函数：发送syscall检测通知
//
_IRQL_requires_(PASSIVE_LEVEL)
static
ULONG
ShpMapMsgTypeToOpType(
    _In_ WKD_MESSAGE_TYPE MsgType
    )
/*++
Routine Description:
    将 WKD_MESSAGE_TYPE 映射到 WKD_OP_TYPE（用于位图查询）。

Arguments:
    MsgType — syscall 消息类型。

Return Value:
    对应的 WKD_OP_TYPE 值，未映射返回 -1。
--*/
{
    switch (MsgType) {
    case WkdMessage_SyscallOpenProcess:    return WkdOp_OpenProcess;
    case WkdMessage_SyscallAllocateMemory: return WkdOp_AllocateVirtualMemory;
    case WkdMessage_SyscallWriteMemory:    return WkdOp_WriteVirtualMemory;
    case WkdMessage_SyscallReadMemory:     return WkdOp_ReadVirtualMemory;
    case WkdMessage_SyscallProtectMemory:  return WkdOp_ProtectVirtualMemory;
    case WkdMessage_SyscallCreateThread:   return WkdOp_CreateRemoteThread;
    case WkdMessage_SyscallMapSection:     return WkdOp_MapViewOfSection;
    case WkdMessage_SyscallQueueApc:       return WkdOp_QueueApcThread;
    case WkdMessage_SyscallSetContextThread: return WkdOp_SetContextThread;
    case WkdMessage_SyscallSuspendThread:  return WkdOp_SuspendThread;
    case WkdMessage_SyscallResumeThread:   return WkdOp_ResumeThread;
    default: return (ULONG)-1;
    }
}

_Use_decl_annotations_
PVOID
ScTrampolineCallback(
    VOID
    )
{
    NTSTATUS status;
    PVOID routineAddress;
    PWKD_SYNC_REQUEST req;
    WKD_SYNC_REPLY_DATA verdict;

    /* 从缓存取出 defer 数据（按当前线程 TID 匹配） */
    status = CtxCacheConsumeDeferSync(
        PsGetCurrentThreadId(),
        &routineAddress, &req);
    if (!NT_SUCCESS(status)) {
        return NULL;
    }

    /* 阻塞等待 Agent 回复（此时 ETW buffer 已释放） */
    {
        //LARGE_INTEGER timeout;
        //timeout.QuadPart = -50000000LL;  /* 5 秒 */
        status = NtfSyncWait(&g_SyncMgr, req, NULL);

        if (status != STATUS_SUCCESS) {
            /* 超时 → 保守拒绝 */
            NtfReleaseSyncRequest(&g_SyncMgr, req);
            return NULL;
        }
    }

    RtlCopyMemory(&verdict, req->ReplyBuffer, sizeof(WKD_SYNC_REPLY_DATA));
    NtfReleaseSyncRequest(&g_SyncMgr, req);

    if (verdict.Verdict == WkdSyncVerdict_Allow) {
        return routineAddress;    /* 放行 → 执行原始系统调用 */
    }

    return NULL;                /* Deny/Forward → 拒绝，自行处理 */
}

NTSTATUS
ShpSendSyscallMessage(
    _In_ WKD_MESSAGE_TYPE MessageType,
    _In_ PWKD_SYSCALL_CONTEXT SyscallContext
    )
{
    NTSTATUS status;
    PWKD_MESSAGE message;
    PWKD_MESSAGE_BODY_SYSCALL body;
    ULONG opType;

    message = NtfCreateMessage(
        MessageType,
        WkdMessage_SourceSyscall,
        WkdMessage_PriorityHigh,
        sizeof(WKD_MESSAGE_BODY_SYSCALL)
        );

    if (!message) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Failed to create syscall notification message\n");
        return STATUS_UNSUCCESSFUL;
    }

    /* 填充消息头 */
    message->Header.SourceProcessId = SyscallContext->SourceProcessId;
    message->Header.TargetProcessId = SyscallContext->TargetProcessId;
    message->Header.ThreadId = SyscallContext->TargetThreadId;

    /* 填充消息体 */
    body = WKD_MESSAGE_BODY(message, WKD_MESSAGE_BODY_SYSCALL);
    body->SyscallCount = 1;
    body->SyscallNumber = SyscallContext->SyscallNumber;
    body->ParameterNumber = SyscallContext->ParameterNumber;
    RtlCopyMemory(
        &body->ParameterBase,
        &SyscallContext->ParameterBlock,
        sizeof(ULONG64) * SyscallContext->ParameterNumber
    );

    /* 判断是否需要同步阻塞 */
    opType = ShpMapMsgTypeToOpType(MessageType);

    if (opType != (ULONG)-1 &&
        PsPairNeedsSync(
            message->Header.SourceProcessId,
            message->Header.TargetProcessId,
            opType)) {

        /* === 同步路径: 阻塞执行线程, 等待 IOA 决策 === */
        WKD_SYNC_REPLY_DATA    verdict;     // 判决
        PWKD_SYNC_REQUEST      req;

        status = NtfAcquireSyncRequest(&g_SyncMgr,
            &verdict, sizeof(verdict), &req);
        if (!NT_SUCCESS(status)) {
            /* 池满, 走保守拒绝 */
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[WkDefender] Sync pool full, deny syscall\n");
            NmFreeMessage(message);
            return STATUS_ACCESS_DENIED;
        }

        /* 插入缓存（供 ScTrampolineCallback 消费） */
        CtxCacheInsertDeferSync(SyscallContext, req);

        /* 篡改栈上服务例程地址 → ScTrampoline 跳板 */
        *SyscallContext->StackRoutineAddress = ScTrampoline;

        /* WKD_MESSAGE 绑定同步请求ID */
        message->Header.SyncRequestId = req->RequestId;
    } 

    /* === 异步路径 === */
    status = NtfSendMessageAsync(message);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Failed to submit syscall notification: 0x%08X\n",
            status);
        
        return STATUS_SUCCESS;
    }
}

/*++
ShpSendSectionMapMessage

    区段映射专用上送（PreAcquireSection 迁移 2026-08）。
    WKD_MESSAGE_BODY_SYSCALL.ParameterBase 槽位有限(8)，NtMapViewOfSection 10 参
    直接 RtlCopyMemory 会越界 16 字节，故走 WKD_MESSAGE_BODY_SECTION_MAP 专用体
    （文件轨 AcquireSection 与 syscall 轨共用同一 body，Origin 区分来源）。
    仅跨进程映射上送（同进程 DLL 加载由文件轨覆盖，避免噪声）；
    驱动侧评分经 AeReportIndicatorPair 建进程对 + 落 IOA 记录，agent 侧
    0x6005/0x6006 边映射（Allocates/Hollows）与注入分类器消费。
    SectionObject 为内核 Section 对象指针（SectionTracker 迁移 2026-08，
    agent 以它为键聚合跨进程映射/RemoteMap 判定）。
    触发前置：SmInitialize() 启用（WkdEntry.c，当前注释保持关闭）。
--*/
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
ShpSendSectionMapMessage(
    _In_ WKD_MESSAGE_TYPE MessageType,
    _In_ PWKD_SYSCALL_CONTEXT SyscallContext,
    _In_ ULONG Origin,
    _In_ BOOLEAN WasBlocked,
    _In_ ULONG64 SectionObject
    )
{
    PWKD_MESSAGE message = NULL;
    PWKD_MESSAGE_BODY_SECTION_MAP body;
    NTSTATUS status;

    message = NtfCreateMessage(
        MessageType,
        WkdMessage_SourceSyscall,
        WkdMessage_PriorityHigh,
        sizeof(WKD_MESSAGE_BODY_SECTION_MAP)
        );
    if (!message) {
        return STATUS_UNSUCCESSFUL;
    }

    message->Header.SourceProcessId = SyscallContext->SourceProcessId;
    message->Header.TargetProcessId = SyscallContext->TargetProcessId;
    message->Header.ThreadId = SyscallContext->TargetThreadId;

    body = WKD_MESSAGE_BODY(message, WKD_MESSAGE_BODY_SECTION_MAP);
    body->ProcessId = SyscallContext->TargetProcessId;
    body->ThreadId = PsGetCurrentThreadId();
    body->SectionType = 0;   /* syscall 侧无 SEC_IMAGE 位（CreateSection 时已定），agent 参数消费 */
    body->MappingFlags = 0;  /* syscall 侧行为判定归 agent（0x6005 边），驱动仅上送参数 */
    body->SuspicionScore = 0;
    body->Origin = Origin;
    body->Flags = WasBlocked ? 1 : 0;
    body->SectionObject = SectionObject;   /* SectionTracker 迁移 2026-08：agent 聚合键 */
    body->FilePath.Buffer = NULL;
    body->FilePath.Length = 0;
    body->FilePath.MaximumLength = 0;
    KeQuerySystemTime(&body->Timestamp);

    if (Origin == 2) {
        /* NtUnmapViewOfSection：2 参 */
        body->PageProtection = 0;
        body->SectionHandle = 0;
        body->BaseAddress = (ULONG64)SyscallContext->ParameterBlock.UnmapViewOfSection.BaseAddress;
        body->RegionSize = 0;
    } else {
        /* NtMapViewOfSection：10 参 */
        body->PageProtection = (ULONG)SyscallContext->ParameterBlock.MapViewOfSection.Win32Protect;
        body->SectionHandle = (ULONG64)SyscallContext->ParameterBlock.MapViewOfSection.SectionHandle;
        body->BaseAddress = (ULONG64)SyscallContext->ParameterBlock.MapViewOfSection.BaseAddress;
        body->RegionSize = (ULONG64)SyscallContext->ParameterBlock.MapViewOfSection.ViewSize;
    }

    status = NtfSendMessageAsync(message);
    if (!NT_SUCCESS(status)) {
        NmFreeMessage(message);
    }
    return status;
}

/*++
ShpSendSectionCreateMessage

    Section 创建专用上送（SectionTracker 迁移 2026-08）。
    用于 WkdMessage_SyscallCreateSection(0x1011) + WKD_MESSAGE_BODY_SECTION_CREATE。
    ShpProcessExitCreateSection 检测完成后填充检测结果随消息上送。
    ※ 死代码: 依赖 SmInitialize 启用（WkdEntry.c:261 注释态）。
--*/
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
ShpSendSectionCreateMessage(
    _In_ PWKD_SYSCALL_CONTEXT SyscallContext,
    _In_ ULONG64 SectionObject,
    _In_ ULONG64 MaximumSize,
    _In_ ULONG SuspicionFlags,
    _In_ ULONG SuspicionScore
    )
{
    PWKD_MESSAGE message = NULL;
    PWKD_MESSAGE_BODY_SECTION_CREATE body;
    NTSTATUS status;

    message = NtfCreateMessage(
        WkdMessage_SyscallCreateSection,
        WkdMessage_SourceSyscall,
        WkdMessage_PriorityHigh,
        sizeof(WKD_MESSAGE_BODY_SECTION_CREATE)
        );
    if (!message) {
        return STATUS_UNSUCCESSFUL;
    }

    message->Header.SourceProcessId = SyscallContext->SourceProcessId;
    message->Header.TargetProcessId = SyscallContext->TargetProcessId;
    message->Header.ThreadId = SyscallContext->SourceThreadId;

    body = WKD_MESSAGE_BODY(message, WKD_MESSAGE_BODY_SECTION_CREATE);
    body->ProcessId = SyscallContext->SourceProcessId;
    body->ThreadId = SyscallContext->SourceThreadId;
    body->SectionObject = SectionObject;
    body->MaximumSize = MaximumSize;
    body->SectionPageProtection = SyscallContext->ParameterBlock.CreateSection.SectionPageProtection;
    body->AllocationAttributes = SyscallContext->ParameterBlock.CreateSection.AllocationAttributes;
    body->SectionType = (SyscallContext->ParameterBlock.CreateSection.AllocationAttributes & SEC_IMAGE) ? 1 : 0;
    body->IsAnonymous = ((SyscallContext->ParameterBlock.CreateSection.FileHandle == NULL) &&
                         (SyscallContext->ParameterBlock.CreateSection.ObjectAttributes == NULL)) ? 1 : 0;
    body->SuspicionFlags = SuspicionFlags;
    body->SuspicionScore = SuspicionScore;
    KeQuerySystemTime(&body->Timestamp);

    status = NtfSendMessageAsync(message);
    if (!NT_SUCCESS(status)) {
        NmFreeMessage(message);
    }
    return status;
}

/*++

//
// 堆喷分配风暴预判（HeapSpray 迁移 2026-08，死代码）
//
// 在 ShpProcessExitAllocateMemory 发送前调用，更新源进程 HeapSprayProfile
// 5s 窗口计数（对齐 SS HsRecordAllocation 窗口语义）; 命中阈值
//   (a) ≥100 次 && 总字节 ≥1MB
//   (b) 对齐分配 ≥50% && ≥100 次
// → SecurityContext.BehaviorFlags 置 WKD_BEHAVIOR_HEAP_SPRAY + 上报
//   TsIndicator_Injection_HeapSpray (0x0306, 预登记槽位激活,
//   IocEngine G_IocSeverityMap = High)。
// ※ 死代码: 依赖 SmInitialize 启用 (WkdEntry.c:261 注释态), syscall 管线
//   恢复后自动生效。severity=0 走 AeReportIndicatorPair 默认威胁程度表。
//
--*/
#define WKD_DRV_HS_SPRAY_SIZE        (1024 * 1024)        /* 对齐 SS HS_MIN_SPRAY_SIZE */
#define WKD_DRV_HS_SIMILAR_ALLOC     100                  /* 对齐 SS HS_MIN_SIMILAR_ALLOCATIONS */
#define WKD_DRV_HS_WINDOW_MS         5000                 /* 对齐 SS HS_ALLOCATION_WINDOW_MS */

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
ShpUpdateHeapSprayProfile(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ PVOID  BaseAddress,
    _In_ SIZE_T Size,
    _In_ ULONG  PageProtection
    )
{
    PWKD_PROCESS proc;
    PWKD_HEAP_SPRAY_PROFILE profile;
    LARGE_INTEGER now;
    BOOLEAN aligned;
    BOOLEAN exec;
    ULONG alignedPct;

    KeQuerySystemTime(&now);

    proc = PsLookupWkdProcessByProcessId(SourceProcessId);
    if (proc == NULL || proc->SecurityContext == NULL) {
        return;
    }

    profile = &proc->HeapSprayProfile;

    /* 滑窗: 5s 到期重置 */
    if (now.QuadPart - profile->WindowStartTime.QuadPart >
        (LONGLONG)WKD_DRV_HS_WINDOW_MS * 10000LL) {
        profile->RecentAllocations      = 0;
        profile->TotalAllocatedSize     = 0;
        profile->AlignedAllocations     = 0;
        profile->ExecutableAllocations  = 0;
        profile->ThresholdHit           = FALSE;
        profile->WindowStartTime        = now;
    }
    if (profile->WindowStartTime.QuadPart == 0) {
        profile->WindowStartTime = now;
    }

    /* 聚合计数 */
    InterlockedIncrement(&profile->RecentAllocations);
    InterlockedAdd64((volatile LONG64*)&profile->TotalAllocatedSize, (LONG64)Size);

    aligned = (((ULONG_PTR)BaseAddress & 0xFFFF) == 0);
    if (aligned) {
        InterlockedIncrement(&profile->AlignedAllocations);
    }

    exec = (PageProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                              PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    if (exec) {
        InterlockedIncrement(&profile->ExecutableAllocations);
    }

    /* 阈值判定 (对齐 SS HsRecordAllocation L925-928 阈值) */
    if (!profile->ThresholdHit &&
        profile->RecentAllocations >= WKD_DRV_HS_SIMILAR_ALLOC) {
        BOOLEAN hit = FALSE;

        if (profile->TotalAllocatedSize >= WKD_DRV_HS_SPRAY_SIZE) {
            hit = TRUE;
        } else {
            alignedPct = (ULONG)((ULONG64)profile->AlignedAllocations * 100 /
                                 (ULONG)profile->RecentAllocations);
            if (alignedPct >= 50) {
                hit = TRUE;
            }
        }

        if (hit) {
            profile->ThresholdHit = TRUE;
            proc->SecurityContext->BehaviorFlags |= WKD_BEHAVIOR_HEAP_SPRAY;
            AeReportIndicatorPair(SourceProcessId, TargetProcessId,
                                  TsSourceIOC, TsIndicator_Injection_HeapSpray, 0);
        }
    }
}

/*++
ShpProcessExitAllocateMemory

    NtAllocateVirtualMemory 的 Exit 回调处理。
    从缓存中读取 Entry 时保存的输入参数指针，
    在 Exit 上下文中 dereference 获取输出值（实际分配地址 + 实际分配大小），
    然后发送消息。

    注意：
    - Exit 回调在系统调用刚完成时触发，输出参数已被内核写入。
    - 使用 __try/__except + ProbeForRead 安全读取用户态内存。
    - 不获取 NTSTATUS 返回值（当前栈布局下难以跨版本定位）。

--*/
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
ShpProcessExitAllocateMemory(
    _In_ PWKD_SYSCALL_CONTEXT SyscallContext
    )
{
    PCTX_CACHE_ENTRY cacheEntry;
    PVOID allocatedBase = NULL;
    SIZE_T allocatedSize = 0;

    /*
     * 从缓存匹配 Entry 时插入的参数。
     * 匹配键：SourceTid + SyscallNumber（同一线程串行执行).
     */
    cacheEntry = CtxCacheConsumeByTid(
        SyscallContext->SourceThreadId,
        SyscallContext->SyscallNumber);

    if (cacheEntry == NULL) {
        return STATUS_NOT_FOUND;
    }

    /*
     * 在 Exit 上下文中安全读取输出参数。
     * 系统调用已完成，输出参数已被内核写入到用户态指针指向的内存。
     */
    if (cacheEntry->Params.AllocateVirtualMemory.BaseAddress != NULL) {
        /* __try { */
            ProbeForRead(
                cacheEntry->Params.AllocateVirtualMemory.BaseAddress,
                sizeof(PVOID),
                sizeof(PVOID));
            allocatedBase = *cacheEntry->Params.AllocateVirtualMemory.BaseAddress;
        /* } __except (EXCEPTION_EXECUTE_HANDLER) {
            allocatedBase = NULL;
        } */
    }

    if (cacheEntry->Params.AllocateVirtualMemory.RegionSize != NULL) {
        /* __try { */
            ProbeForRead(
                cacheEntry->Params.AllocateVirtualMemory.RegionSize,
                sizeof(SIZE_T),
                sizeof(SIZE_T));
            allocatedSize = *cacheEntry->Params.AllocateVirtualMemory.RegionSize;
        /* } __except (EXCEPTION_EXECUTE_HANDLER) {
            allocatedSize = 0;
        } */
    }

    /*
     * 用实际输出值覆盖 SyscallContext 中的参数字段。
     * 调用 ShpSendSyscallMessage 时，RtlCopyMemory 会将
     *    ParameterBase[1] ← allocatedBase（实际分配地址）
     *    ParameterBase[3] ← allocatedSize（实际分配大小）
     * 这样 Agent 侧收到的就不再是指针值，而是真实有效的输出值。
     */
    RtlCopyMemory(
        &SyscallContext->ParameterBlock,
        &cacheEntry->Params,
        SyscallContext->ParameterNumber * sizeof(PVOID));
    SyscallContext->SourceProcessId = cacheEntry->SourceProcessId;
    SyscallContext->TargetProcessId = cacheEntry->TargetProcessId;
    SyscallContext->ParameterBlock.AllocateVirtualMemory.BaseAddress =
        (PVOID*)allocatedBase;          /* 覆盖为实际地址值 */
    SyscallContext->ParameterBlock.AllocateVirtualMemory.RegionSize =
        (PSIZE_T)allocatedSize;         /* 覆盖为实际大小值 */

    /* 堆喷分配风暴预判 (死代码, SmInitialize 启用后生效; 参数块此时
     * BaseAddress/RegionSize 已被实际输出值覆盖, PageProtection 保留原值) */
    ShpUpdateHeapSprayProfile(
        SyscallContext->SourceProcessId,
        SyscallContext->TargetProcessId,
        allocatedBase,
        allocatedSize,
        SyscallContext->ParameterBlock.AllocateVirtualMemory.PageProtection);

    /* 内存区域追踪（MemoryMonitor 迁移 2026-08，死代码: SmInitialize 启用后
     * 生效）。分配完成，用实际输出值（allocatedBase/allocatedSize）记录区域
     * + RWX 初始分配预判。 */
    WkdMemRegionTrackAllocation(
        SyscallContext->SourceProcessId,
        SyscallContext->TargetProcessId,
        (ULONG64)(ULONG_PTR)allocatedBase,
        (ULONG64)allocatedSize,
        SyscallContext->ParameterBlock.AllocateVirtualMemory.PageProtection);

    /* 发送消息 */
    ShpSendSyscallMessage(WkdMessage_SyscallAllocateMemory, SyscallContext);

    /* 释放缓存条目 */
    ExFreePool(cacheEntry);

    return STATUS_SUCCESS;
}

/*++

ShpProcessExitProtectMemory

    NtProtectVirtualMemory 的 Exit 回调处理。
    读取 *OldProtection 输出参数。

--*/
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
ShpProcessExitProtectMemory(
    _In_ PWKD_SYSCALL_CONTEXT SyscallContext
    )
{
    PCTX_CACHE_ENTRY cacheEntry;
    ULONG oldProtection = 0;

    cacheEntry = CtxCacheConsumeByTid(
        PsGetCurrentThreadId(),
        SyscallContext->SyscallNumber);

    if (cacheEntry == NULL) {
        return STATUS_NOT_FOUND;
    }

    /* 读取 OldProtection 输出参数 */
    if (cacheEntry->Params.ProtectVirtualMemory.OldProtection != NULL) {
        /* __try { */
            ProbeForRead(
                cacheEntry->Params.ProtectVirtualMemory.OldProtection,
                sizeof(ULONG),
                sizeof(ULONG));
            oldProtection = *cacheEntry->Params.ProtectVirtualMemory.OldProtection;
        /* } __except (EXCEPTION_EXECUTE_HANDLER) {
            oldProtection = 0;
        } */
    }

    /* 覆盖参数字段 */
    SyscallContext->ParameterBlock.ProtectVirtualMemory.ProcessHandle =
        cacheEntry->Params.ProtectVirtualMemory.ProcessHandle;
    SyscallContext->ParameterBlock.ProtectVirtualMemory.BaseAddress =
        (PVOID*)cacheEntry->Params.ProtectVirtualMemory.BaseAddress;
    SyscallContext->ParameterBlock.ProtectVirtualMemory.RegionSize =
        cacheEntry->Params.ProtectVirtualMemory.RegionSize;
    SyscallContext->ParameterBlock.ProtectVirtualMemory.NewProtection =
        cacheEntry->Params.ProtectVirtualMemory.NewProtection;
    SyscallContext->ParameterBlock.ProtectVirtualMemory.OldProtection =
        (PULONG)(ULONG_PTR)oldProtection;   /* 覆盖为实际旧保护值 */

    ShpSendSyscallMessage(WkdMessage_SyscallProtectMemory, SyscallContext);

    /* AMSI 绕过检测器接线（预留）：
     * 对齐 SS MemoryMonitor 集成 — VirtualProtect 使 amsi.dll 区域可写 → 上报。
     * 依赖 SyscallMonitor 激活（SmInitialize 当前注释），激活后自动生效。
     * 仅 PASSIVE_LEVEL 下解引用用户指针（ProbeForRead 要求 IRQL <= APC_LEVEL）。 */
    if (KeGetCurrentIrql() == PASSIVE_LEVEL &&
        SyscallContext->TargetProcessId != NULL) {
        PVOID   baseAddr = NULL;
        SIZE_T  regionSize = 0;
        ULONG   newProt = cacheEntry->Params.ProtectVirtualMemory.NewProtection;

        /* __try { */
            if (cacheEntry->Params.ProtectVirtualMemory.BaseAddress != NULL) {
                ProbeForRead(cacheEntry->Params.ProtectVirtualMemory.BaseAddress,
                             sizeof(PVOID), 1);
                baseAddr = *(PVOID*)cacheEntry->Params.ProtectVirtualMemory.BaseAddress;
            }
            if (cacheEntry->Params.ProtectVirtualMemory.RegionSize != NULL) {
                ProbeForRead(cacheEntry->Params.ProtectVirtualMemory.RegionSize,
                             sizeof(SIZE_T), 1);
                regionSize = *(PSIZE_T)cacheEntry->Params.ProtectVirtualMemory.RegionSize;
            }
        /* } __except (EXCEPTION_EXECUTE_HANDLER) {
            baseAddr = NULL;
            regionSize = 0;
        } */

        if (baseAddr != NULL && regionSize != 0) {
            (VOID)AbdCheckProtectionChange(
                SyscallContext->TargetProcessId,
                baseAddr, regionSize, oldProtection, newProt);
        }
    }

    ExFreePool(cacheEntry);
    return STATUS_SUCCESS;
}

/*++

ShpProcessExitWriteMemory

    NtWriteVirtualMemory 的 Exit 回调处理。
    读取 *NumberOfBytesWritten 输出参数。

--*/
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
ShpProcessExitWriteMemory(
    _In_ PWKD_SYSCALL_CONTEXT SyscallContext
    )
{
    PCTX_CACHE_ENTRY cacheEntry;
    SIZE_T bytesWritten = 0;

    cacheEntry = CtxCacheConsumeByTid(
        PsGetCurrentThreadId(),
        SyscallContext->SyscallNumber);

    if (cacheEntry == NULL) {
        return STATUS_NOT_FOUND;
    }

    /* 读取 NumberOfBytesWritten 输出参数 */
    if (cacheEntry->Params.WriteVirtualMemory.NumberOfBytesWritten != NULL) {
        /* __try { */
            ProbeForRead(
                cacheEntry->Params.WriteVirtualMemory.NumberOfBytesWritten,
                sizeof(SIZE_T),
                sizeof(SIZE_T));
            bytesWritten = *cacheEntry->Params.WriteVirtualMemory.NumberOfBytesWritten;
        /* } __except (EXCEPTION_EXECUTE_HANDLER) {
            bytesWritten = 0;
        } */
    }

    SyscallContext->ParameterBlock.WriteVirtualMemory.ProcessHandle =
        cacheEntry->Params.WriteVirtualMemory.ProcessHandle;
    SyscallContext->ParameterBlock.WriteVirtualMemory.BaseAddress =
        cacheEntry->Params.WriteVirtualMemory.BaseAddress;
    SyscallContext->ParameterBlock.WriteVirtualMemory.Buffer =
        cacheEntry->Params.WriteVirtualMemory.Buffer;
    SyscallContext->ParameterBlock.WriteVirtualMemory.NumberOfBytesToWrite =
        cacheEntry->Params.WriteVirtualMemory.NumberOfBytesToWrite;
    SyscallContext->ParameterBlock.WriteVirtualMemory.NumberOfBytesWritten =
        (PSIZE_T)bytesWritten;          /* 覆盖为实际写入字节数 */

    ShpSendSyscallMessage(WkdMessage_SyscallWriteMemory, SyscallContext);

    ExFreePool(cacheEntry);
    return STATUS_SUCCESS;
}

/*++

ShpProcessExitReadMemory

    NtReadVirtualMemory 的 Exit 回调处理。
    读取 *NumberOfBytesRead 输出参数（Buffer 内容暂不读取，数据量可能很大）。

--*/
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
ShpProcessExitReadMemory(
    _In_ PWKD_SYSCALL_CONTEXT SyscallContext
    )
{
    PCTX_CACHE_ENTRY cacheEntry;
    SIZE_T bytesRead = 0;

    cacheEntry = CtxCacheConsumeByTid(
        PsGetCurrentThreadId(),
        SyscallContext->SyscallNumber);

    if (cacheEntry == NULL) {
        return STATUS_NOT_FOUND;
    }

    /* 读取 NumberOfBytesRead 输出参数 */
    if (cacheEntry->Params.ReadVirtualMemory.NumberOfBytesRead != NULL) {
        /* __try { */
            ProbeForRead(
                cacheEntry->Params.ReadVirtualMemory.NumberOfBytesRead,
                sizeof(SIZE_T),
                sizeof(SIZE_T));
            bytesRead = *cacheEntry->Params.ReadVirtualMemory.NumberOfBytesRead;
        /* } __except (EXCEPTION_EXECUTE_HANDLER) {
            bytesRead = 0;
        } */
    }

    SyscallContext->ParameterBlock.ReadVirtualMemory.ProcessHandle =
        cacheEntry->Params.ReadVirtualMemory.ProcessHandle;
    SyscallContext->ParameterBlock.ReadVirtualMemory.BaseAddress =
        cacheEntry->Params.ReadVirtualMemory.BaseAddress;
    SyscallContext->ParameterBlock.ReadVirtualMemory.Buffer =
        cacheEntry->Params.ReadVirtualMemory.Buffer;
    SyscallContext->ParameterBlock.ReadVirtualMemory.NumberOfBytesToRead =
        cacheEntry->Params.ReadVirtualMemory.NumberOfBytesToRead;
    SyscallContext->ParameterBlock.ReadVirtualMemory.NumberOfBytesRead =
        (PSIZE_T)bytesRead;             /* 覆盖为实际读取字节数 */

    ShpSendSyscallMessage(WkdMessage_SyscallReadMemory, SyscallContext);

    ExFreePool(cacheEntry);
    return STATUS_SUCCESS;
}

/*++
ShpProcessExitCreateSection

    NtCreateSection 的 Exit 回调处理（SectionTracker 迁移 2026-08）。
    从缓存读取 Entry 时保存的输入参数，deref 输出 SectionHandle 得 SectionObject，
    执行 5 类怀疑信号检测（对齐 SS SectionTracker.c SecpUpdateSuspicionScore 权重）：
      - ExecuteAnonymous（匿名可执行 200，反射加载信号）
      - LargeAnonymous（匿名 >100MB 80，堆喷/异常大映射）
      - NoBackingFile（SEC_IMAGE 无背衬文件 180，镜像伪造）
      - Transacted（TxF 事务 300，Doppelganging T1055.013）
      - Deleted（DeletePending 250，Doppelganging 变体）
    评分 = 权重和 + ≥3 标志组合加成（indicatorCount×50），随消息上送 +
    AeReportIndicatorPair 上报（severity=0 查 G_IocSeverityMap）。
    ※ 死代码: 依赖 SmInitialize 启用（WkdEntry.c:261 注释态）。
--*/

/* 大匿名 Section 阈值（对齐 SS SEC_SUSPICIOUS_SIZE_THRESHOLD = 100MB） */
#define WKD_SEC_LARGE_ANONYMOUS_THRESHOLD   (100ULL * 1024ULL * 1024ULL)

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
ShpProcessExitCreateSection(
    _In_ PWKD_SYSCALL_CONTEXT SyscallContext
    )
{
    PCTX_CACHE_ENTRY cacheEntry;
    HANDLE sectionObject = NULL;
    ULONG64 maximumSize = 0;
    ULONG suspicionFlags = 0;
    ULONG score = 0;
    ULONG indicatorCount = 0;
    BOOLEAN isAnonymous;

    cacheEntry = CtxCacheConsumeByTid(
        SyscallContext->SourceThreadId,
        SyscallContext->SyscallNumber);
    if (cacheEntry == NULL) {
        return STATUS_NOT_FOUND;
    }

    /* 重建参数块（从 Entry 缓存） */
    RtlCopyMemory(
        &SyscallContext->ParameterBlock,
        &cacheEntry->Params,
        SyscallContext->ParameterNumber * sizeof(PVOID));
    SyscallContext->SourceProcessId = cacheEntry->SourceProcessId;
    SyscallContext->TargetProcessId = cacheEntry->TargetProcessId;

    /* deref 输出 SectionHandle → SectionObject（内核对象指针，agent 聚合键） */
    if (cacheEntry->Params.CreateSection.SectionHandle != NULL) {
        /* __try { */
            ProbeForRead(
                cacheEntry->Params.CreateSection.SectionHandle,
                sizeof(HANDLE),
                sizeof(HANDLE));
            sectionObject = *cacheEntry->Params.CreateSection.SectionHandle;
        /* } __except (EXCEPTION_EXECUTE_HANDLER) {
            sectionObject = NULL;
        } */
    }

    /* 读 MaximumSize（输入指针，Exit 时仍有效；对齐 SS SecTrackSectionCreate） */
    if (cacheEntry->Params.CreateSection.MaximumSize != NULL) {
        /* __try { */
            ProbeForRead(
                cacheEntry->Params.CreateSection.MaximumSize,
                sizeof(LARGE_INTEGER),
                sizeof(LARGE_INTEGER));
            maximumSize = (ULONG64)cacheEntry->Params.CreateSection.MaximumSize->QuadPart;
        /* } __except (EXCEPTION_EXECUTE_HANDLER) {
            maximumSize = 0;
        } */
    }

    /* 匿名判定（对齐 SS SecTrackSectionCreate FileObject==NULL 分支）：
     * FileHandle 与 ObjectAttributes 二选一，两者皆空 = 纯匿名 Section */
    isAnonymous = (cacheEntry->Params.CreateSection.FileHandle == NULL) &&
                  (cacheEntry->Params.CreateSection.ObjectAttributes == NULL);

    /* 5 类怀疑信号检测（权重对齐 SS SecpUpdateSuspicionScore） */
    if (isAnonymous) {
        /* ExecuteAnonymous：匿名 + 可执行保护（反射加载/自包含 shellcode 载体） */
        if (cacheEntry->Params.CreateSection.SectionPageProtection &
            (PAGE_EXECUTE | PAGE_EXECUTE_READ |
             PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
            suspicionFlags |= WKD_SEC_SUSPICION_EXECUTE_ANONYMOUS;
        }
        /* LargeAnonymous：匿名 + >100MB */
        if (maximumSize > WKD_SEC_LARGE_ANONYMOUS_THRESHOLD) {
            suspicionFlags |= WKD_SEC_SUSPICION_LARGE_ANONYMOUS;
        }
        /* NoBackingFile：SEC_IMAGE 标志但无文件（镜像伪造/镂空前置） */
        if (cacheEntry->Params.CreateSection.AllocationAttributes & SEC_IMAGE) {
            suspicionFlags |= WKD_SEC_SUSPICION_NO_BACKING_FILE;
        }
    } else if (cacheEntry->Params.CreateSection.FileHandle != NULL) {
        /* Transacted / Deleted：仅基于文件的 SEC_IMAGE section（Doppelganging 序列）。
         * 对齐 SS SecpIsTransactedFile（IoGetTransactionParameterBlock）/
         * SecpIsFileDeleted（DeletePending）。 */
        PFILE_OBJECT fileObject = NULL;
        NTSTATUS fsStatus = ObReferenceObjectByHandle(
            cacheEntry->Params.CreateSection.FileHandle,
            FILE_ANY_ACCESS,
            *IoFileObjectType,
            KernelMode,
            (PVOID*)&fileObject,
            NULL);
        if (NT_SUCCESS(fsStatus) && fileObject != NULL) {
            if (IoGetTransactionParameterBlock(fileObject) != NULL) {
                suspicionFlags |= WKD_SEC_SUSPICION_TRANSACTED;
            }
            if (fileObject->DeletePending) {
                suspicionFlags |= WKD_SEC_SUSPICION_DELETED;
            }
            ObDereferenceObject(fileObject);
        }
    }

    /* 评分 = 权重和 + ≥3 标志组合加成（对齐 SS c:2346） */
    if (suspicionFlags & WKD_SEC_SUSPICION_TRANSACTED)         score += 300;
    if (suspicionFlags & WKD_SEC_SUSPICION_DELETED)            score += 250;
    if (suspicionFlags & WKD_SEC_SUSPICION_EXECUTE_ANONYMOUS)  score += 200;
    if (suspicionFlags & WKD_SEC_SUSPICION_NO_BACKING_FILE)    score += 180;
    if (suspicionFlags & WKD_SEC_SUSPICION_LARGE_ANONYMOUS)    score += 80;

    {
        ULONG tmp = suspicionFlags;
        while (tmp) {
            indicatorCount += (tmp & 1);
            tmp >>= 1;
        }
    }
    if (indicatorCount >= 3) {
        score += indicatorCount * 50;
    }

    /* 上报（severity=0 → IocGetIndicatorSeverity 查 G_IocSeverityMap） */
    if (suspicionFlags & WKD_SEC_SUSPICION_TRANSACTED) {
        AeReportIndicatorPair(SyscallContext->SourceProcessId, SyscallContext->SourceProcessId,
                              TsSourceBehavioral, TsIndicator_Ioa_SectionTransacted, 0);
    }
    if (suspicionFlags & WKD_SEC_SUSPICION_DELETED) {
        AeReportIndicatorPair(SyscallContext->SourceProcessId, SyscallContext->SourceProcessId,
                              TsSourceBehavioral, TsIndicator_Ioa_SectionDeleted, 0);
    }
    if (suspicionFlags & WKD_SEC_SUSPICION_EXECUTE_ANONYMOUS) {
        AeReportIndicatorPair(SyscallContext->SourceProcessId, SyscallContext->SourceProcessId,
                              TsSourceBehavioral, TsIndicator_Ioa_SectionExecuteAnonymous, 0);
    }
    if (suspicionFlags & WKD_SEC_SUSPICION_NO_BACKING_FILE) {
        AeReportIndicatorPair(SyscallContext->SourceProcessId, SyscallContext->SourceProcessId,
                              TsSourceBehavioral, TsIndicator_Ioa_SectionNoBackingFile, 0);
    }
    if (suspicionFlags & WKD_SEC_SUSPICION_LARGE_ANONYMOUS) {
        AeReportIndicatorPair(SyscallContext->SourceProcessId, SyscallContext->SourceProcessId,
                              TsSourceBehavioral, TsIndicator_Ioa_SectionLargeAnonymous, 0);
    }

    ShpSendSectionCreateMessage(
        SyscallContext,
        (ULONG64)sectionObject,
        maximumSize,
        suspicionFlags,
        score);

    ExFreePool(cacheEntry);
    return STATUS_SUCCESS;
}

//
// 内部辅助函数：解析线程句柄 → 目标进程 ID
//
// 与现有 syscall case 不同（现有均以 stackArgs[0] 为进程句柄，
// 用 *PsProcessType 解析），线程操作 syscall（SetContext/Suspend/
// Resume/QueueApc）的 stackArgs[0] 是线程句柄，须用 *PsThreadType
// 解析 PETHREAD 后经 IoThreadToProcess 得到所属进程。
// DesiredAccess=0：仅解析对象引用，跳过访问掩码校验（syscall 已进入
// 内核，调用者已完成参数校验），最大化解析成功率。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
ShpResolveThreadTarget(
    _In_ HANDLE ThreadHandle,
    _Out_ PHANDLE TargetProcessId,
    _Out_opt_ PHANDLE TargetThreadId
    )
/*++
Routine Description:
    将线程句柄解析为所属进程 ID 与线程 ID
    （跨进程线程操作的检测前提，线程劫持时序按线程关联）。

Arguments:
    ThreadHandle    - 目标线程句柄（来自 syscall 参数）。
    TargetProcessId - 输出目标线程所属进程 ID。
    TargetThreadId  - [可选] 输出目标线程 ID（PsGetThreadId）。

Returns:
    STATUS_SUCCESS      — 解析成功。
    其他 NTSTATUS       — 句柄无效/类型不匹配/权限不足。
--*/
{
    NTSTATUS status;
    PETHREAD ethread = NULL;
    PEPROCESS eprocess;

    if (!TargetProcessId || !ThreadHandle) {
        return STATUS_INVALID_PARAMETER;
    }

    status = ObReferenceObjectByHandleWithTag(
        ThreadHandle,
        0,
        *PsThreadType,
        UserMode,
        'Shep',
        (PVOID *)&ethread,
        NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    eprocess = IoThreadToProcess(ethread);
    *TargetProcessId = PsGetProcessId(eprocess);
    if (TargetThreadId) {
        *TargetThreadId = PsGetThreadId(ethread);
    }

    ObDereferenceObjectWithTag(ethread, 'Shep');
    return STATUS_SUCCESS;
}

//
// 内部辅助函数：从栈帧提取系统调用参数
// 注意：这是基于x64 Windows调用约定的简化实现
// 实际参数位置可能因Windows版本和编译优化而有所不同
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
ShpExtractSyscallParameters(
    _In_ ULONG SyscallNumber,
    _Inout_ PWKD_SYSCALL_CONTEXT SyscallContext
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PULONG64 stackArgs, stackArgsEx = NULL;
    PEPROCESS eprocess;

    if (!SyscallNumber || !SyscallContext) {
        return STATUS_INVALID_PARAMETER;
    }

    // 获取当前线程所属进程ID
    SyscallContext->SourceProcessId = PsGetCurrentProcessId();

    // 获取当前栈上系统服务例程指针的栈地址
    SyscallContext->StackRoutineAddress = 
        (PVOID*)((PUCHAR)SyscallContext->TrapFrame -
        (SyscallContext->ParameterNumber > 4 ? 0x70 : 0) -
        0x50 + 0x40);

    /*
    * 定位参数块位置
    */

    // .text:00000001401D3207 48 83 EC 50               sub     rsp, 50h
    // .text:00000001401D320B 48 89 4C 24 20            mov[rsp + 50h + var_30], rcx; 初始rsp指向_KTrap_Frame
    // .text:00000001401D3210 48 89 54 24 28            mov[rsp + 50h + var_28], rdx
    // .text:00000001401D3215 4C 89 44 24 30            mov[rsp + 50h + var_20], r8
    // .text:00000001401D321A 4C 89 4C 24 38            mov[rsp + 50h + var_18], r9
    // .text:00000001401D321F 4C 89 54 24 40            mov[rsp + 50h + func_address], r10
    // .text:00000001401D3224 49 8B CA                  mov     rcx, r10
    // .text:00000001401D3227 E8 C4 DC 15 00            call    PerfInfoLogSysCallEntry
    // .text:00000001401D322C 48 8B 4C 24 20            mov     rcx, [rsp + 50h + var_30]
    // .text:00000001401D3231 48 8B 54 24 28            mov     rdx, [rsp + 50h + var_28]
    // .text:00000001401D3236 4C 8B 44 24 30            mov     r8, [rsp + 50h + var_20]
    // .text:00000001401D323B 4C 8B 4C 24 38            mov     r9, [rsp + 50h + var_18]
    // .text:00000001401D3240 4C 8B 54 24 40            mov     r10, [rsp + 50h + func_address]
    // .text:00000001401D3245 48 83 C4 50               add     rsp, 50h
    // .text:00000001401D3249 49 8B C2                  mov     rax, r10
    // .text:00000001401D324C FF D0                     call    rax; 执行系统调用
    // .text:00000001401D324E 0F 1F 00                  nop     dword ptr[rax]
    // .text:00000001401D3251 48 8B C8                  mov     rcx, rax
    // .text:00000001401D3254 E8 37 DD 15 00            call    PerfInfoLogSysCallExit; rsp指向_KTrap_Frame
    // .text:00000001401D3259 E9 BA FA FF FF            jmp     loc_1401D2D18; 系统调用追踪返回，内部执行"call rax"
    stackArgs = (PULONG64)((PUCHAR)SyscallContext->TrapFrame -
        (SyscallContext->ParameterNumber > 4 ? 0x70 : 0) -
        0x50 +
        0x20                                            // rcx
        );

    // .text:00000001401D2C39 C1 E0 03                  shl     eax, 3
    // .text:00000001401D2C3C 48 8D 64 24 90            lea     rsp, [rsp - 70h]
    //                                                  ; rsp指向_KTrap_Frame - 70, 扩展栈, 用于填充额外参数
    // .text:00000001401D2C41 48 8D 7C 24 18            lea     rdi, [rsp + 70h + var_58]; 取填充位首地址
    // .text:00000001401D2CE8 48 8B 46 08               mov     rax, [rsi+8]
    // .text:00000001401D2CEC 48 89 47 08               mov     [rdi+8], rax
    if (SyscallContext->ParameterNumber > 4) {
        stackArgsEx = (PULONG64)((PUCHAR)SyscallContext->TrapFrame -
            0x70 + 0x20);
    }

    /* __try { */
        switch (SyscallNumber) {
        case WkdSyscall_NtOpenProcess:
            SyscallContext->TargetProcessId = *(PHANDLE)stackArgs[3];
            SyscallContext->ParameterBlock.OpenProcess.ProcessHandle = (HANDLE)stackArgs[0];
            SyscallContext->ParameterBlock.OpenProcess.DesiredAccess = (ACCESS_MASK)stackArgs[1];
            SyscallContext->ParameterBlock.OpenProcess.ObjectAttributes = (PCOBJECT_ATTRIBUTES)stackArgs[2];
            SyscallContext->ParameterBlock.OpenProcess.ClientId = (PCLIENT_ID)stackArgs[3];
            break;

        case WkdSyscall_NtAllocateVirtualMemory:
            status = ObReferenceObjectByHandleWithTag(
                (HANDLE)stackArgs[0],
                PROCESS_VM_READ,
                *PsProcessType, UserMode,
                'Shep', &eprocess, NULL);
            if (NT_SUCCESS(status)) {
                SyscallContext->TargetProcessId = PsGetProcessId(eprocess);
                SyscallContext->ParameterBlock.AllocateVirtualMemory.ProcessHandle = (HANDLE)stackArgs[0];
                SyscallContext->ParameterBlock.AllocateVirtualMemory.BaseAddress = (PVOID*)stackArgs[1];
                SyscallContext->ParameterBlock.AllocateVirtualMemory.ZeroBits = (ULONG_PTR)stackArgs[2];
                SyscallContext->ParameterBlock.AllocateVirtualMemory.RegionSize = (PSIZE_T)stackArgs[3];
                SyscallContext->ParameterBlock.AllocateVirtualMemory.AllocationType = (ULONG)stackArgsEx[0];
                SyscallContext->ParameterBlock.AllocateVirtualMemory.PageProtection = (ULONG)stackArgsEx[1];
                ObfDereferenceObjectWithTag(eprocess, 'Shep');
            }
            break;

        case WkdSyscall_NtProtectVirtualMemory:
            status = ObReferenceObjectByHandleWithTag(
                (HANDLE)stackArgs[0],
                PROCESS_VM_READ,
                *PsProcessType, UserMode,
                'Shep', &eprocess, NULL);
            if (NT_SUCCESS(status)) {
                SyscallContext->TargetProcessId = PsGetProcessId(eprocess);
                SyscallContext->ParameterBlock.ProtectVirtualMemory.ProcessHandle = (HANDLE)stackArgs[0];
                SyscallContext->ParameterBlock.ProtectVirtualMemory.BaseAddress = (PVOID*)stackArgs[1];
                SyscallContext->ParameterBlock.ProtectVirtualMemory.RegionSize = (PSIZE_T)stackArgs[2];
                SyscallContext->ParameterBlock.ProtectVirtualMemory.NewProtection = (ULONG)stackArgs[3];
                SyscallContext->ParameterBlock.ProtectVirtualMemory.OldProtection = (ULONG)stackArgsEx[0];
                ObfDereferenceObjectWithTag(eprocess, 'Shep');
            }
            break;

        case WkdSyscall_NtWriteVirtualMemory:
            status = ObReferenceObjectByHandleWithTag(
                (HANDLE)stackArgs[0],
                PROCESS_VM_READ,
                *PsProcessType, UserMode,
                'Shep', &eprocess, NULL);
            if (NT_SUCCESS(status)) {
                SyscallContext->TargetProcessId = PsGetProcessId(eprocess);
                SyscallContext->ParameterBlock.WriteVirtualMemory.ProcessHandle = (HANDLE)stackArgs[0];
                SyscallContext->ParameterBlock.WriteVirtualMemory.BaseAddress = (PVOID)stackArgs[1];
                SyscallContext->ParameterBlock.WriteVirtualMemory.Buffer = (PVOID)stackArgs[2];
                SyscallContext->ParameterBlock.WriteVirtualMemory.NumberOfBytesToWrite = (SIZE_T)stackArgs[3];
                SyscallContext->ParameterBlock.WriteVirtualMemory.NumberOfBytesWritten = (PSIZE_T)stackArgsEx[0];
                ObfDereferenceObjectWithTag(eprocess, 'Shep');
            }
            break;

        case WkdSyscall_NtCreateThreadEx:
            status = ObReferenceObjectByHandleWithTag(
                (HANDLE)stackArgs[3],
                PROCESS_CREATE_THREAD,
                *PsProcessType, UserMode,
                'Shep', &eprocess, NULL);
            if (NT_SUCCESS(status)) {
                SyscallContext->TargetProcessId = PsGetProcessId(eprocess);
                SyscallContext->ParameterBlock.CreateRemoteThread.ThreadHandle = stackArgs[0];
                SyscallContext->ParameterBlock.CreateRemoteThread.DesiredAccess = stackArgs[1];
                SyscallContext->ParameterBlock.CreateRemoteThread.ObjectAttributes = stackArgs[2];
                SyscallContext->ParameterBlock.CreateRemoteThread.ProcessHandle = stackArgs[3];
                SyscallContext->ParameterBlock.CreateRemoteThread.StartRoutine = stackArgsEx[0];
                SyscallContext->ParameterBlock.CreateRemoteThread.Argument = stackArgsEx[1];
                SyscallContext->ParameterBlock.CreateRemoteThread.CreateFlags = stackArgsEx[2];
                SyscallContext->ParameterBlock.CreateRemoteThread.ZeroBits = stackArgsEx[3];
                SyscallContext->ParameterBlock.CreateRemoteThread.StackSize = stackArgsEx[4];
                SyscallContext->ParameterBlock.CreateRemoteThread.MaximumStackSize = stackArgsEx[5];
                SyscallContext->ParameterBlock.CreateRemoteThread.AttributeList = stackArgsEx[6];
                ObfDereferenceObjectWithTag(eprocess, 'Shep');
            }
            break;

        case WkdSyscall_NtReadVirtualMemory:

            // 将进程句柄转换为EPROCESS
            status = ObReferenceObjectByHandleWithTag(
                (HANDLE)stackArgs[0],
                PROCESS_VM_READ,
                *PsProcessType, UserMode,
                'Shep', &eprocess, NULL);
            if (NT_SUCCESS(status)) {
                SyscallContext->TargetProcessId = PsGetProcessId(eprocess);
                SyscallContext->ParameterBlock.ReadVirtualMemory.ProcessHandle = (HANDLE)stackArgs[0];
                SyscallContext->ParameterBlock.ReadVirtualMemory.BaseAddress = (PVOID)stackArgs[1];
                SyscallContext->ParameterBlock.ReadVirtualMemory.Buffer = (PVOID)stackArgs[2];
                SyscallContext->ParameterBlock.ReadVirtualMemory.NumberOfBytesToRead = (SIZE_T)stackArgs[3];
                SyscallContext->ParameterBlock.ReadVirtualMemory.NumberOfBytesRead = (PSIZE_T)stackArgsEx[0];
                ObfDereferenceObjectWithTag(eprocess, 'Shep');
            }
            break;

        case WkdSyscall_NtQueueApcThread:
            // 5 参：ThreadHandle, ApcRoutine, ApcArgument1/2/3
            status = ShpResolveThreadTarget(
                (HANDLE)stackArgs[0],
                &SyscallContext->TargetProcessId,
                &SyscallContext->TargetThreadId);
            if (NT_SUCCESS(status)) {
                SyscallContext->ParameterBlock.QueueApcThread.ThreadHandle = (HANDLE)stackArgs[0];
                SyscallContext->ParameterBlock.QueueApcThread.ApcRoutine = (PVOID)stackArgs[1];
                SyscallContext->ParameterBlock.QueueApcThread.ApcArgument1 = (PVOID)stackArgs[2];
                SyscallContext->ParameterBlock.QueueApcThread.ApcArgument2 = (PVOID)stackArgs[3];
                SyscallContext->ParameterBlock.QueueApcThread.ApcArgument3 = (PVOID)stackArgsEx[0];
            }
            break;

        case WkdSyscall_NtSetContextThread:
            // 2 参：ThreadHandle, ThreadContext(PCONTEXT)
            status = ShpResolveThreadTarget(
                (HANDLE)stackArgs[0],
                &SyscallContext->TargetProcessId,
                &SyscallContext->TargetThreadId);
            if (NT_SUCCESS(status)) {
                SyscallContext->ParameterBlock.SetContextThread.ThreadHandle = (HANDLE)stackArgs[0];
                SyscallContext->ParameterBlock.SetContextThread.ThreadContext = (PVOID)stackArgs[1];
            }
            break;

        case WkdSyscall_NtSuspendThread:
            // 1 参：ThreadHandle（PreviousSuspendCount 为输出参数，Entry 时未写）
            status = ShpResolveThreadTarget(
                (HANDLE)stackArgs[0],
                &SyscallContext->TargetProcessId,
                &SyscallContext->TargetThreadId);
            if (NT_SUCCESS(status)) {
                SyscallContext->ParameterBlock.SuspendThread.ThreadHandle = (HANDLE)stackArgs[0];
                SyscallContext->ParameterBlock.SuspendThread.PreviousSuspendCount = (PULONG)stackArgs[1];
            }
            break;

        case WkdSyscall_NtResumeThread:
            // 1 参：ThreadHandle（PreviousSuspendCount 为输出参数，Entry 时未写）
            status = ShpResolveThreadTarget(
                (HANDLE)stackArgs[0],
                &SyscallContext->TargetProcessId,
                &SyscallContext->TargetThreadId);
            if (NT_SUCCESS(status)) {
                SyscallContext->ParameterBlock.ResumeThread.ThreadHandle = (HANDLE)stackArgs[0];
                SyscallContext->ParameterBlock.ResumeThread.PreviousSuspendCount = (PULONG)stackArgs[1];
            }
            break;

        case WkdSyscall_NtAdjustPrivilegesToken:
            // 6 参：TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength
            // 令牌句柄无进程反查（无 IoThreadToProcess 等价物，令牌可被多进程引用）→
            // 目标进程回退源进程；agent WpaCheckForEscalation 重采当前令牌对比基线，
            // 不依赖句柄指向。
            SyscallContext->TargetProcessId = SyscallContext->SourceProcessId;
            SyscallContext->ParameterBlock.AdjustPrivilegesToken.TokenHandle = (HANDLE)stackArgs[0];
            SyscallContext->ParameterBlock.AdjustPrivilegesToken.DisableAllPrivileges = (BOOLEAN)stackArgs[1];
            SyscallContext->ParameterBlock.AdjustPrivilegesToken.NewState = (PVOID)stackArgs[2];
            SyscallContext->ParameterBlock.AdjustPrivilegesToken.BufferLength = (ULONG)stackArgs[3];
            SyscallContext->ParameterBlock.AdjustPrivilegesToken.PreviousState = (PVOID)stackArgsEx[0];
            SyscallContext->ParameterBlock.AdjustPrivilegesToken.ReturnLength = (PVOID)stackArgsEx[1];
            break;

        case WkdSyscall_NtDuplicateToken:
            // 5 参：ExistingTokenHandle, DesiredAccess, ObjectAttributes, EffectiveOnly, TokenType
            // 同上：令牌无进程反查，目标回退源进程。
            SyscallContext->TargetProcessId = SyscallContext->SourceProcessId;
            SyscallContext->ParameterBlock.DuplicateToken.ExistingTokenHandle = (HANDLE)stackArgs[0];
            SyscallContext->ParameterBlock.DuplicateToken.DesiredAccess = (ACCESS_MASK)stackArgs[1];
            SyscallContext->ParameterBlock.DuplicateToken.ObjectAttributes = (PVOID)stackArgs[2];
            SyscallContext->ParameterBlock.DuplicateToken.EffectiveOnly = (BOOLEAN)stackArgs[3];
            SyscallContext->ParameterBlock.DuplicateToken.TokenType = (TOKEN_TYPE)stackArgsEx[0];
            break;

        case WkdSyscall_NtSetInformationToken:
            // 4 参：TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength
            SyscallContext->TargetProcessId = SyscallContext->SourceProcessId;
            SyscallContext->ParameterBlock.SetInformationToken.TokenHandle = (HANDLE)stackArgs[0];
            SyscallContext->ParameterBlock.SetInformationToken.TokenInformationClass = (ULONG)stackArgs[1];
            SyscallContext->ParameterBlock.SetInformationToken.TokenInformation = (PVOID)stackArgs[2];
            SyscallContext->ParameterBlock.SetInformationToken.TokenInformationLength = (ULONG)stackArgs[3];
            break;

        case WkdSyscall_NtImpersonateThread:
            // 3 参：ServerThreadHandle, ClientThreadHandle, SecurityQos
            // ClientThreadHandle 是线程句柄可反查 → 真实目标进程（被模拟线程所属进程）。
            status = ShpResolveThreadTarget(
                (HANDLE)stackArgs[1],
                &SyscallContext->TargetProcessId,
                &SyscallContext->TargetThreadId);
            if (!NT_SUCCESS(status)) {
                SyscallContext->TargetProcessId = SyscallContext->SourceProcessId;
            }
            SyscallContext->ParameterBlock.ImpersonateThread.ServerThreadHandle = (HANDLE)stackArgs[0];
            SyscallContext->ParameterBlock.ImpersonateThread.ClientThreadHandle = (HANDLE)stackArgs[1];
            SyscallContext->ParameterBlock.ImpersonateThread.SecurityQos = (PVOID)stackArgs[2];
            break;

        case WkdSyscall_NtMapViewOfSection:
            // 10 参（PreAcquireSection 迁移 2026-08）。ProcessHandle 反查 → 目标进程，
            // 用于跨进程映射判定（同进程 DLL 加载由文件轨 AcquireSection 覆盖）。
            status = ObReferenceObjectByHandleWithTag(
                (HANDLE)stackArgs[1], PROCESS_VM_OPERATION, *PsProcessType,
                UserMode, 'Shep', (PVOID*)&eprocess, NULL);
            if (NT_SUCCESS(status)) {
                SyscallContext->TargetProcessId = PsGetProcessId(eprocess);
                ObDereferenceObject(eprocess);
            } else {
                SyscallContext->TargetProcessId = SyscallContext->SourceProcessId;
            }
            SyscallContext->ParameterBlock.MapViewOfSection.SectionHandle = (HANDLE)stackArgs[0];
            SyscallContext->ParameterBlock.MapViewOfSection.ProcessHandle = (HANDLE)stackArgs[1];
            SyscallContext->ParameterBlock.MapViewOfSection.BaseAddress = (PVOID*)stackArgs[2];
            SyscallContext->ParameterBlock.MapViewOfSection.ZeroBits = (ULONG_PTR)stackArgs[3];
            SyscallContext->ParameterBlock.MapViewOfSection.CommitSize = (SIZE_T)stackArgsEx[0];
            SyscallContext->ParameterBlock.MapViewOfSection.SectionOffset = (PLARGE_INTEGER)stackArgsEx[1];
            SyscallContext->ParameterBlock.MapViewOfSection.ViewSize = (PSIZE_T)stackArgsEx[2];
            SyscallContext->ParameterBlock.MapViewOfSection.InheritDisposition = (ULONG)stackArgsEx[3];
            SyscallContext->ParameterBlock.MapViewOfSection.AllocationType = (ULONG)stackArgsEx[4];
            SyscallContext->ParameterBlock.MapViewOfSection.Win32Protect = (ULONG)stackArgsEx[5];
            break;

        case WkdSyscall_NtUnmapViewOfSection:
            // 2 参（进程镂空前置）。ProcessHandle 反查 → 目标进程。
            status = ObReferenceObjectByHandleWithTag(
                (HANDLE)stackArgs[0], PROCESS_VM_OPERATION, *PsProcessType,
                UserMode, 'Shep', (PVOID*)&eprocess, NULL);
            if (NT_SUCCESS(status)) {
                SyscallContext->TargetProcessId = PsGetProcessId(eprocess);
                ObDereferenceObject(eprocess);
            } else {
                SyscallContext->TargetProcessId = SyscallContext->SourceProcessId;
            }
            SyscallContext->ParameterBlock.UnmapViewOfSection.ProcessHandle = (HANDLE)stackArgs[0];
            SyscallContext->ParameterBlock.UnmapViewOfSection.BaseAddress = (PVOID)stackArgs[1];
            break;

        case WkdSyscall_NtCreateSection:
            // 7 参（SectionTracker 迁移 2026-08）。无进程句柄参数（FileHandle 为
            // 文件句柄）→ 目标进程回退源进程（对齐令牌类 case 语义）。
            // 输出 SectionHandle 为 PHANDLE，Entry 时仅存指针值，Exit 时
            // ShpProcessExitCreateSection deref 得 SectionObject。
            SyscallContext->TargetProcessId = SyscallContext->SourceProcessId;
            SyscallContext->ParameterBlock.CreateSection.SectionHandle = (PHANDLE)stackArgs[0];
            SyscallContext->ParameterBlock.CreateSection.DesiredAccess = (ACCESS_MASK)stackArgs[1];
            SyscallContext->ParameterBlock.CreateSection.ObjectAttributes = (PCOBJECT_ATTRIBUTES)stackArgs[2];
            SyscallContext->ParameterBlock.CreateSection.MaximumSize = (PLARGE_INTEGER)stackArgs[3];
            SyscallContext->ParameterBlock.CreateSection.SectionPageProtection = (ULONG)stackArgsEx[0];
            SyscallContext->ParameterBlock.CreateSection.AllocationAttributes = (ULONG)stackArgsEx[1];
            SyscallContext->ParameterBlock.CreateSection.FileHandle = (HANDLE)stackArgsEx[2];
            break;

        default:
            status = STATUS_NOT_SUPPORTED;
            break;
        }
    /* }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Exception while extracting syscall parameters: 0x%08X\n",
            GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
    } */

    return status;
}

//
// 内部辅助函数：获取PerfInfoLogSysCallEntry函数的Magic用于判断Pre/Post
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
ShpParsePerfSyscallMagic(
    _In_ PKTRAP_FRAME TrapFrame,
    _In_ BOOLEAN StackExpansion,          // 是否栈扩展
    _Out_ PULONG Magic1,
    _Out_ PULONG Magic2
)
{
    NTSTATUS status;
    ULONG stackSub;

    if (!TrapFrame || !Magic1 || !Magic2) {
        return STATUS_INVALID_PARAMETER;
    }

    // 此时默认开启 syscall trace，满足: PerfGlobalGroupMask+8 & 0x40 == TRUE
    // Path 1: PerfInfoLogSysCallEntry
    stackSub = 0x50 + 0x8 + 0x30 + (StackExpansion ? 0x70 : 0);  // 定位 magic

    /* 存在版本依赖，后期需要做适配！ */
    *Magic1 = *(PULONG)((ULONG64)TrapFrame - stackSub);
    if (*Magic1 == ETW_TRACE_MAGIC_SYSCALL) {
        *Magic2 = *(PUSHORT)((ULONG64)TrapFrame - stackSub - 8);
    } else {
        *Magic1 = *(PULONG)((ULONG64)TrapFrame - stackSub + 0x50);
        *Magic2 = *(PUSHORT)((ULONG64)TrapFrame - stackSub - 8 + 0x50);
    }
    
    return STATUS_SUCCESS;
}

//
// 解析系统服务例程及其参数
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShpParseSystemServiceRoutine(
    _In_ ULONG SyscallNumber,
    _Out_ PWKD_SYSCALL_CONTEXT SyscallContext
)
{
    NTSTATUS status;
    PULONG ssdt = NULL;     // entry 每项4字节
    ULONG entry = 0;

    if (!SyscallNumber || !SyscallContext) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(SyscallContext, sizeof(WKD_SYSCALL_CONTEXT));

    // 设置系统调用号
    SyscallContext->SyscallNumber = SyscallNumber;

    // 获取TrapFrame
    SyscallContext->TrapFrame = UtGetCurrentThreadTrapFrame();
    
    // 设置发起者线程ID
    SyscallContext->SourceThreadId = PsGetCurrentThreadId();

    // 获取 SSDT 表
    ssdt = SsGetSsdtBase();
    if (!ssdt) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to get KeServiceDescriptorTable\n");
        return NULL;
    }

    // === 暂时不考虑 ===
    //dynamicTraceMask = ShGetDynamicTraceMask();
    //if (dynamicTraceMask & 1) {
    //    // 已开启动态调试
    //    // Path 2: KiTrackSystemCallEntry->PerfInfoLogSysCallEntry
    //    stackSub += 0x58;
    //}


    //
    // 使用 SEH 保护 SSDT 访问，防止因内核结构变化导致蓝屏
    //
    /* __try { */
        // 从 SSDT 中获取偏移量并计算实际地址
        // Windows x64 的 SSDT 条目格式：低位 4 位是参数个数，高 28 位是偏移；每项（4字节）
        entry = ssdt[SyscallNumber];

        // 计算实际的服务例程地址
        SyscallContext->RoutineAddress = (PVOID)((ULONG64)ssdt + (entry >> 4));

        // 验证地址有效性（可检查是否位于Ntoskrnl的地址范围内?）
        if ((ULONG64)SyscallContext->RoutineAddress < 0xFFFF800000000000ULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WkDefender] Invalid service routine address: 0x%p\n",
                SyscallContext->RoutineAddress);
            return STATUS_UNSUCCESSFUL;
        }

        // 检查参数个数
        if (entry & 0xf) {
            SyscallContext->ParameterNumber = 4 + entry & 0xf;
        }
        else {
            SyscallContext->ParameterNumber = 4;
        }

        /*
         * 修正线程操作 syscall 的参数个数。
         * (4 + entry) & 0xf 依赖运算符优先级，对 1/2 参 syscall 会误算成
         * 5/6 → 触发 StackExpansion 分支，stackArgs 基址偏移 0x70 读错参数。
         * 直接按实参个数覆盖：Suspend/Resume=1、SetContext=2、QueueApc=5。
         */
        switch (SyscallNumber) {
        case WkdSyscall_NtSetContextThread:
            SyscallContext->ParameterNumber = 2;
            break;
        case WkdSyscall_NtSuspendThread:
        case WkdSyscall_NtResumeThread:
            SyscallContext->ParameterNumber = 1;
            break;
        case WkdSyscall_NtQueueApcThread:
            SyscallContext->ParameterNumber = 5;
            break;
        case WkdSyscall_NtAdjustPrivilegesToken:
            SyscallContext->ParameterNumber = 6;
            break;
        case WkdSyscall_NtDuplicateToken:
            SyscallContext->ParameterNumber = 5;
            break;
        case WkdSyscall_NtSetInformationToken:
            SyscallContext->ParameterNumber = 4;
            break;
        case WkdSyscall_NtImpersonateThread:
            SyscallContext->ParameterNumber = 3;
            break;
        case WkdSyscall_NtMapViewOfSection:
            SyscallContext->ParameterNumber = 10;   /* PreAcquireSection 迁移 2026-08 */
            break;
        case WkdSyscall_NtUnmapViewOfSection:
            SyscallContext->ParameterNumber = 2;    /* PreAcquireSection 迁移 2026-08 */
            break;
        case WkdSyscall_NtCreateSection:
            SyscallContext->ParameterNumber = 7;    /* SectionTracker 迁移 2026-08 */
            break;
        default:
            break;
        }

        // 检查PerfInfoLogSysCallEntry的Pre/Post
        status = ShpParsePerfSyscallMagic(
            SyscallContext->TrapFrame,
            (SyscallContext->ParameterNumber > 4 ? TRUE : FALSE),
            &SyscallContext->Magic1,
            &SyscallContext->Magic2
        );
        if (!NT_SUCCESS(status)) {
            // 解析PerfInfoLogSysCallEntry函数栈Magic失败
        }

        // ETW Callback
        if (SyscallContext->Magic1 == ETW_TRACE_MAGIC_SYSCALL) {
            // Pre路径下，栈上的参数可靠
            if (SyscallContext->Magic2 == ETW_TRACE_MAGIC_SYSCALL_ENTRY) {
                // 提取syscall参数
                status = ShpExtractSyscallParameters(
                    SyscallNumber,
                    SyscallContext
                );
                if (!NT_SUCCESS(status)) {
                    // 提取系统调用参数失败
                    DbgBreakPoint();
                }

                // 栈完整性检查
                if (SyscallContext->RoutineAddress == *SyscallContext->StackRoutineAddress) {
                    SyscallContext->Integrity = TRUE;
                }
            }
        }
        
    /* }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 捕获访问违例或其他异常
        NTSTATUS exceptionCode = GetExceptionCode();

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Exception occurred while accessing SSDT for syscall 0x%X: 0x%08X\n",
            SyscallNumber, exceptionCode);

        return STATUS_UNSUCCESSFUL;
    } */

   
    return STATUS_SUCCESS;
}

//
// 自定义 CPU Lock 获取函数（用于劫持系统调用监控）
//
_IRQL_requires_(PASSIVE_LEVEL)
static
ULONG64
ShpEtwCallback(
    PVOID Context
    )
{
    NTSTATUS status;
    WKD_SYSCALL_TYPE syscallNumber;
    PWKD_PROCESS currentWkdProcess = NULL;
    WKD_MESSAGE_TYPE messageType;
    
    // Syscall事件记录相关变量
    HANDLE sourceProcessId = 0;
    WKD_SYSCALL_CONTEXT syscallContext = { 0 };

    // 过滤内核模式的调用
    if (ExGetPreviousMode() == KernelMode) {
        goto Rdtsc;
    }

    //
    // 白名单检查：系统进程和 EDR 自身的 syscall 无需关注
    // 系统服务（svchost.exe 等）频繁跨进程操作是正常行为，跳过可大幅降噪
    //
    {
        currentWkdProcess = PsLookupWkdProcessByProcessId(PsGetCurrentProcessId());
        if (currentWkdProcess && ExemptsIsProcessTrusted(currentWkdProcess->Core.ProcessId)) {
            goto Rdtsc;
        }
    }

    // 读取系统调用号
    syscallNumber = (WKD_SYSCALL_TYPE)UtGetCurrentThreadSyscallNumber();

    // 系统调用号过滤
    // 暂时仅起用NtReadVirtualMemory
    switch (syscallNumber) {
    case WkdSyscall_NtOpenProcess:
        messageType = WkdMessage_SyscallOpenProcess;
        break;
    case WkdSyscall_NtAllocateVirtualMemory:
        messageType = WkdMessage_SyscallAllocateMemory;
        break;
    case WkdSyscall_NtProtectVirtualMemory:
        messageType = WkdMessage_SyscallProtectMemory;
        break;
    case WkdSyscall_NtReadVirtualMemory:
        messageType = WkdMessage_SyscallReadMemory;
        break;
    case WkdSyscall_NtWriteVirtualMemory:
        messageType = WkdMessage_SyscallWriteMemory;
        break;
    case WkdSyscall_NtCreateThreadEx:
        messageType = WkdMessage_SyscallCreateThread;
        break;
    case WkdSyscall_NtQueueApcThread:
        messageType = WkdMessage_SyscallQueueApc;
        break;
    case WkdSyscall_NtSetContextThread:
        messageType = WkdMessage_SyscallSetContextThread;
        break;
    case WkdSyscall_NtSuspendThread:
        messageType = WkdMessage_SyscallSuspendThread;
        break;
    case WkdSyscall_NtResumeThread:
        messageType = WkdMessage_SyscallResumeThread;
        break;
    case WkdSyscall_NtAdjustPrivilegesToken:
        messageType = WkdMessage_SyscallAdjustPrivileges;
        break;
    case WkdSyscall_NtDuplicateToken:
        messageType = WkdMessage_SyscallDuplicateToken;
        break;
    case WkdSyscall_NtSetInformationToken:
        messageType = WkdMessage_SyscallSetInformationToken;
        break;
    case WkdSyscall_NtImpersonateThread:
        messageType = WkdMessage_SyscallImpersonateThread;
        break;
    case WkdSyscall_NtMapViewOfSection:
        messageType = WkdMessage_SyscallMapSection;   /* PreAcquireSection 迁移 2026-08（跨进程注入） */
        break;
    case WkdSyscall_NtUnmapViewOfSection:
        messageType = WkdMessage_SyscallUnmapSection; /* PreAcquireSection 迁移 2026-08（进程镂空） */
        break;
    case WkdSyscall_NtCreateSection:
        messageType = WkdMessage_SyscallCreateSection; /* SectionTracker 迁移 2026-08（匿名可执行/大匿名/无背衬/TxF） */
        break;
    default:
        goto Rdtsc;
    }

    // 解析系统调用服务例程: address/参数个数/TrapFrame/magic/参数值/发起对象/目标对象
    status = ShpParseSystemServiceRoutine(syscallNumber, &syscallContext);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender] Failed to parse service routine for syscall 0x%X\n", syscallNumber);
        DbgBreakPoint();
    }

    if (syscallContext.Magic1 == ETW_TRACE_MAGIC_SYSCALL) {

        switch (syscallContext.Magic2) {

        case ETW_TRACE_MAGIC_SYSCALL_ENTRY:
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            //    "[WkDefender] PerfInfoLogSysCallEntry: Syscall=0x%X, Caller -> %ws\n",
            //    syscallNumber, (PWSTR)NULL);

            if (!syscallContext.Integrity) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[WkDefender] Stack frame has been tampered with: orig -> 0x%p, new -> 0x%p. Caller: %ws\n",
                    syscallContext.RoutineAddress, syscallContext.StackRoutineAddress, (PWSTR)NULL);

                // 上报栈完整性检测指标（高置信度 rootkit 行为）
                // 栈篡改是进程自属性 → self-pair（Severity=0 查默认等级表）
                if (currentWkdProcess != NULL) {
                    AeReportIndicatorPair(
                        currentWkdProcess->Core.ProcessId,
                        currentWkdProcess->Core.ProcessId,
                        TsSourceBehavioral,
                        TsIndicator_Defense_StackTampering, 0);
                }

                // 统计栈帧篡改次数
                InterlockedIncrement64(&g_WkdSyscallMonitor.Statistics.TamperedStackCount);
                goto Rdtsc;
            }

            // 统计 Syscall Entry 次数
            InterlockedIncrement64(&g_WkdSyscallMonitor.Statistics.SyscallEntryCount);

            if (NT_SUCCESS(status)) {
                // 通过通知管理器发送异步消息
                // 行为引擎将通过消息队列消费这些事件并记录到行为上下文

                /* 内存区域追踪（MemoryMonitor 迁移 2026-08，死代码）：
                 * 在跨进程过滤（default 分支）之前，为内存类 syscall 维护区域
                 * 状态表 + 轻量预判。进程内保护变化（W→X 解包）不经过 default
                 * 的跨进程过滤，必须在此先行处理。
                 * 依赖 SmInitialize 启用（WkdEntry.c:261 注释态）。 */
                switch (syscallNumber) {
                case WkdSyscall_NtProtectVirtualMemory:
                    WkdMemRegionTrackProtectionChange(
                        syscallContext.TargetProcessId,
                        (ULONG64)(ULONG_PTR)syscallContext.ParameterBlock.ProtectVirtualMemory.BaseAddress,
                        (ULONG64)(ULONG_PTR)syscallContext.ParameterBlock.ProtectVirtualMemory.RegionSize,
                        syscallContext.ParameterBlock.ProtectVirtualMemory.OldProtection,
                        syscallContext.ParameterBlock.ProtectVirtualMemory.NewProtection,
                        (syscallContext.SourceProcessId != syscallContext.TargetProcessId),
                        syscallContext.SourceProcessId);
                    break;
                case WkdSyscall_NtWriteVirtualMemory:
                    /* 仅跨进程写（进程内写是正常代码执行）；default 分支已过滤 */
                    if (syscallContext.SourceProcessId != syscallContext.TargetProcessId) {
                        WkdMemRegionTrackCrossProcessWrite(
                            syscallContext.SourceProcessId,
                            syscallContext.TargetProcessId,
                            (ULONG64)(ULONG_PTR)syscallContext.ParameterBlock.WriteVirtualMemory.BaseAddress,
                            (ULONG64)syscallContext.ParameterBlock.WriteVirtualMemory.NumberOfBytesToWrite,
                            syscallContext.ParameterBlock.WriteVirtualMemory.Buffer);
                    }
                    break;
                default:
                    break;
                }

                switch (syscallNumber) {
                case WkdSyscall_NtCreateThreadEx:
                    /*
                     * 将 NtCreateThreadEx 的 syscall 上下文挂入缓存链表，
                     * 等待线程回调触发时消费匹配。
                     *
                     * 此处不发送消息（避免与线程回调重复），
                     * 线程回调会将 syscall 参数合并到 WKD_MESSAGE_BODY_THREAD_CREATE 中。
                     */
                    CtxCacheInsertEx(&syscallContext);
                    break;

                case WkdSyscall_NtAllocateVirtualMemory:
                    /*
                     * 有输出参数（*BaseAddress / *RegionSize + NTSTATUS）的 syscall，
                     * Entry 时先缓存输入参数指针，Exit 时读取输出值再发送。
                     */
                    if (NT_SUCCESS(status)) {
                        CtxCacheInsertEx(&syscallContext);
                    }
                    break;

                case WkdSyscall_NtCreateSection:
                    /* SectionTracker 迁移 2026-08（死代码，SmInitialize 启用后生效）：
                     * 有输出参数（*SectionHandle → SectionObject），Entry 时缓存输入
                     * 参数（MaximumSize/SectionPageProtection/AllocationAttributes/
                     * ObjectAttributes/FileHandle），Exit 时 ShpProcessExitCreateSection
                     * deref 输出得 SectionObject + 5 信号检测 + 评分上送。 */
                    if (NT_SUCCESS(status)) {
                        CtxCacheInsertEx(&syscallContext);
                    }
                    break;

                case WkdSyscall_NtAdjustPrivilegesToken:
                case WkdSyscall_NtDuplicateToken:
                case WkdSyscall_NtSetInformationToken:
                case WkdSyscall_NtImpersonateThread:
                    /* 令牌操作即提权信号（T1134/T1548）：无条件上送，不走 default 的
                     * "进程内跳过"逻辑。目标进程在 ShpExtractSyscallParameters 已解析
                     * （非模拟类回退源进程，ImpersonateThread 为被模拟线程所属进程）。 */
                    ShpSendSyscallMessage(messageType, &syscallContext);
                    break;

                case WkdSyscall_NtMapViewOfSection:
                case WkdSyscall_NtUnmapViewOfSection:
                    /*
                     * 区段映射（PreAcquireSection 迁移 2026-08）：仅跨进程映射上送
                     * （同进程 DLL 加载由文件轨 AcquireSection 覆盖，避免噪声）。
                     * 走 ShpSendSectionMapMessage 专用体（ParameterBase 8 槽越界规避）。
                     * 驱动侧经 AeReportIndicatorPair 建进程对 + 落 IOA 记录；agent 侧
                     * 0x6005/0x6006 边映射（Allocates/Hollows）与注入分类器消费。
                     * SectionObject（内核对象指针）供 agent 以 SectionObject 为键聚合
                     * 跨进程映射/RemoteMap 判定（SectionTracker 迁移 2026-08）。
                     * 触发前置：SmInitialize() 启用（WkdEntry.c，当前注释保持关闭）。 */
                    if (syscallContext.SourceProcessId != syscallContext.TargetProcessId) {
                        ULONG origin =
                            (syscallNumber == WkdSyscall_NtMapViewOfSection) ? 1 : 2;
                        ULONG64 sectionObject = 0;

                        /* Map 轨解析 SectionHandle → SectionObject（仅跨进程上送路径，
                         * 内核模式 ObReferenceObjectByHandle 免 ProbeForRead） */
                        if (origin == 1 &&
                            syscallContext.ParameterBlock.MapViewOfSection.SectionHandle != NULL) {
                            PVOID sectionObj = NULL;
                            NTSTATUS secStatus = ObReferenceObjectByHandle(
                                syscallContext.ParameterBlock.MapViewOfSection.SectionHandle,
                                SECTION_MAP_READ, *MmSectionObjectType,
                                KernelMode, &sectionObj, NULL);
                            if (NT_SUCCESS(secStatus)) {
                                sectionObject = (ULONG64)sectionObj;
                                ObDereferenceObject(sectionObj);
                            }
                        }

                        ShpSendSectionMapMessage(messageType, &syscallContext, origin, FALSE,
                                                 sectionObject);

                        /* 内存区域追踪（MemoryMonitor 迁移 2026-08，死代码）：
                         * 跨进程 section 映射 → MAPPED 区域 + 注入目标标记。
                         * 仅 Map 轨（Unmap 不产生新区域）。 */
                        if (origin == 1) {
                            WkdMemRegionTrackSectionMap(
                                syscallContext.SourceProcessId,
                                syscallContext.TargetProcessId,
                                (ULONG64)(ULONG_PTR)syscallContext.ParameterBlock.MapViewOfSection.BaseAddress,
                                (ULONG64)syscallContext.ParameterBlock.MapViewOfSection.ViewSize,
                                (ULONG)syscallContext.ParameterBlock.MapViewOfSection.Win32Protect,
                                TRUE);
                        }

                        AeReportIndicatorPair(
                            syscallContext.SourceProcessId,
                            syscallContext.TargetProcessId,
                            TsSourceBehavioral,
                            (origin == 1) ? TsIndicator_Ioa_SectionMapCrossProcess
                                          : TsIndicator_Ioa_UnmapViewSection,
                            0);
                    }
                    break;

                default:
                    // 进程内部的操作直接跳过（敏感事件除外）
                    if (syscallContext.SourceProcessId == syscallContext.TargetProcessId) {
                        goto Rdtsc;
                    }

                    //
                    // 调用编排器：IOC 检测 + IOA 记录 + 评分
                    //
                    if (currentWkdProcess != NULL) {
                        PWKD_PROCESS targetProcess =
                            PsLookupWkdProcessByProcessId(syscallContext.TargetProcessId);

                        //AeOrchestratorDispatch(currentWkdProcess, targetProcess,
                        //          WkdMessage_SourceSyscall,
                        //          WkdMessage_SyscallDetected,
                        //          &syscallContext);

                        if (targetProcess) {
                            PsDereferenceWkdProcess(targetProcess);
                        }
                    }

                    //
                    // Tier 1: 生产者侧事件抑制检查
                    // 与上次相同 (target, syscall) 且在窗口内则跳过队列
                    //
                    //{
                    //    if (currentWkdProcess) {
                    //        if (SaSyscallSuppress(currentWkdProcess, syscallContext.TargetProcessId, syscallNumber)) {
                    //            InterlockedIncrement64(&g_WkdSyscallMonitor.Statistics.SyscallEntryCount);
                    //            goto Rdtsc;
                    //        }
                    //    }
                    //}

                    ShpSendSyscallMessage(messageType, &syscallContext);
                }
            }

            break;

        case ETW_TRACE_MAGIC_SYSCALL_EXIT:
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            //    "[WkDefender] PerfInfoLogSysCallExit: Caller -> %ws\n",
            //    (PWSTR)NULL);

            if (NT_SUCCESS(status)) {
                switch (syscallNumber) {
                case WkdSyscall_NtAllocateVirtualMemory:
                    ShpProcessExitAllocateMemory(&syscallContext);
                    break;

                case WkdSyscall_NtCreateSection:
                    /* SectionTracker 迁移 2026-08（死代码，SmInitialize 启用后生效） */
                    ShpProcessExitCreateSection(&syscallContext);
                    break;

                default:
                    break;
                }
            }

            // 统计 Syscall Exit 次数
            InterlockedIncrement64(&g_WkdSyscallMonitor.Statistics.SyscallExitCount);
            break;

        default:
            DbgBreakPoint();
        }
    }

Rdtsc:
    if (currentWkdProcess) {
        PsDereferenceWkdProcess(currentWkdProcess);
    }
    return __rdtsc();
}

//
// 判断是否为 Windows 10 2004 或更高版本
// Windows 10 2004 起始构建号为 19041
//
_IRQL_requires_(PASSIVE_LEVEL)
static
BOOLEAN
WkdIsWindows10Version2004OrLater(
    VOID
)
{
    ULONG buildNumber = UtGetWindowsBuildNumber();
    return (buildNumber >= 19041);
}

//
// 获取 EtwpHostSiloState 偏移量
//
_IRQL_requires_(PASSIVE_LEVEL)
static
ULONG
ShpGetEtwSiloStateOffset(
    VOID
)
{
    ULONG offset = 0;
    ULONG buildNumber = UtGetWindowsBuildNumber();

    /* 目标结构体：_ESERVERSILO_GLOBALS::EtwSiloState -> _ETW_SILODRIVERSTATE */

    switch (buildNumber) {
    case 19045:
        offset = 0x360;
        break;
    default:
        break;
    }

    return offset;
}

//
// 获取 EtwpLoggerContext 偏移量
//
_IRQL_requires_(PASSIVE_LEVEL)
static
ULONG
ShpGetEtwLoggerContextOffset(
    VOID
)
{
    ULONG offset = 0;
    ULONG buildNumber = UtGetWindowsBuildNumber();

    /* 目标结构体：_ETW_SILODRIVERSTATE::EtwpLoggerContext -> _WMI_LOGGER_CONTEXT */

    switch (buildNumber) {
    case 19045:
        offset = 0x1c8;
        break;
    default:
        break;
    }

    return offset;
}

//
// 获取 LoggerContext 中 CpuLock 的偏移量
//
_IRQL_requires_(PASSIVE_LEVEL)
static
ULONG
ShpGetEtwLoggerContextCpuClockOffset(
    VOID
)
{
    ULONG offset = 0;
    ULONG buildNumber = UtGetWindowsBuildNumber();

    /* 目标结构体：_WMI_LOGGER_CONTEXT::GetCpuClock */

    switch (buildNumber) {
    case 19045:
        offset = 0x28;
        break;
    default:
        break;
    }

    return offset;
}

_IRQL_requires_(PASSIVE_LEVEL)
static
PVOID
ShpGetEtwpGetLoggerTimeStampAddress(
    VOID
    )
{
    UNICODE_STRING usKeQueryPerformanceCounter;
    PVOID pfnKeQueryPerformanceCounter = NULL;
    PVOID halpPerformanceCounter;

    RtlInitUnicodeString(&usKeQueryPerformanceCounter, L"KeQueryPerformanceCounter");
    pfnKeQueryPerformanceCounter = MmGetSystemRoutineAddress(&usKeQueryPerformanceCounter);
    if (!pfnKeQueryPerformanceCounter) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to get KeQueryPerformanceCounter address\n");
        return STATUS_UNSUCCESSFUL;
    }

    halpPerformanceCounter = *(PVOID *)(*(PLONG32)((LONG64)pfnKeQueryPerformanceCounter + 0x15) +
        (LONG64)pfnKeQueryPerformanceCounter + 0x19);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[WkDefender] HalpPerformanceCounter: 0x%p\n",
        halpPerformanceCounter);
       
    return halpPerformanceCounter;
}

//
// 获取 KeSetTracepoint 中 KiDynamicTraceMask 的偏移量
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG64
ShGetDynamicTraceMask(
    VOID
)
{
    NTSTATUS status;
    UNICODE_STRING usKeSetTracepoint;
    PVOID pfnKeSetTracepoint;
    PWKD_MEMORY_SIGNATURE sigKiDynamicTraceMask = NULL;
    WKD_SCAN_RESULT scanResult;
    PVOID p = NULL;

    if (WkdDynamicTraceMask) {
        return *(PULONG64*)WkdDynamicTraceMask;
    }

    // WkdDynamicTraceMask 未初始化，执行初始化
    RtlInitUnicodeString(&usKeSetTracepoint, L"KeSetTracepoint");
    pfnKeSetTracepoint = MmGetSystemRoutineAddress(&usKeSetTracepoint);
    if (!pfnKeSetTracepoint) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to get KeSetTracepoint address\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    // KeSetTracepoint 为导出函数，可通过该函数快速定位
    status = MsRegisterSignature(
        &WkdMemorySignature_KiDynamicTraceMask,
        WkdMemorySignatureTemporary,
        &sigKiDynamicTraceMask
    );

    // 获取 KiDynamicTraceMask，这将影响系统调用执行流
    status = MmScanMemoryRange(pfnKeSetTracepoint,PAGE_SIZE, sigKiDynamicTraceMask, &scanResult);
    if (scanResult.Found) {
        p = scanResult.MatchAddress;
        p = (PVOID)(*(PULONG32)((ULONG64)p + 3) + (ULONG64)p + 8);
        InterlockedCompareExchangePointer(
            (PVOID volatile*)&WkdDynamicTraceMask,
            p,
            NULL
        );
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "[WkDefender] KiDynamicTraceMask: 0x%p -> 0x%p\n", 
            WkdDynamicTraceMask, *(PVOID *)WkdDynamicTraceMask);
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WkDefender] Get KiDynamicTraceMask failed.\n");
        DbgBreakPoint();
    }

    return *(PULONG64*)WkdDynamicTraceMask;
}

//
// 根据当前系统版本设置ETW回调
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
ShpRegisterEtwCallbackInternal(
    PWMI_LOGGER_CONTEXT LoggerContext
)
{
    NTSTATUS status;
    PVOID getCpuClock;
    ULONG etwLoggerContextCpuClockOffset;
    PWKD_MEMORY_SIGNATURE sigEtwpGetLoggerTimeStampCallback = NULL;
    WKD_SCAN_RESULT scanResult;

    if (!LoggerContext) {
        return STATUS_INVALID_PARAMETER;
    }

    etwLoggerContextCpuClockOffset = ShpGetEtwLoggerContextCpuClockOffset();
    getCpuClock = (PVOID)((ULONG64)LoggerContext + etwLoggerContextCpuClockOffset);

    switch (UtGetWindowsBuildNumber()) {
    case 19045:
        // 篡改CpuClock -> 1, EtwpGetLoggerTimeStamp -> KeQueryPerformanceCounter -> 回调函数
        // 外部函数ShRegisterEtwCallback已经使用了__try, 此处直接使用硬编码
        status = MsRegisterSignature(
            &WkdMemorySignature_EtwpGetLoggerTimeStampCallback,
            WkdMemorySignatureTemporary,
            &sigEtwpGetLoggerTimeStampCallback
        );
        
        status = MmScanSection(UtGetNtoskrnlBase(), ".text", sigEtwpGetLoggerTimeStampCallback, &scanResult);
        if (scanResult.Found) {
            g_WkdSyscallMonitor.GetCpuClockPtr = (PVOID)(*(PULONG32)((ULONG64)scanResult.MatchAddress + 0xe) + (ULONG64)scanResult.MatchAddress + 0x12);
            g_WkdSyscallMonitor.GetCpuClockType = InterlockedExchange64(getCpuClock, 2);
        }
        else {
            g_WkdSyscallMonitor.GetCpuClockPtr = NULL;
        }
        break;
    default:
        g_WkdSyscallMonitor.GetCpuClockType = 4;    // 无效
        // 直接篡改GetCpuClock字段
        g_WkdSyscallMonitor.GetCpuClockPtr = getCpuClock;
        break;
    }

    
    g_WkdSyscallMonitor.GetCpuClockPtr = InterlockedExchange64(
        g_WkdSyscallMonitor.GetCpuClockPtr, 
        ShpEtwCallback
        );
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[WkDefender] LoggerContext: orig -> 0x%p, new -> 0x%p (cpuLock offset: 0x%X)\n",
        g_WkdSyscallMonitor.GetCpuClockPtr, ShpEtwCallback, etwLoggerContextCpuClockOffset);

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ShRegisterEtwCallback(
    _In_opt_ ULONG LoggerId
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING ucPsGetServerSiloServiceSessionId;
    PVOID pfnPsGetServerSiloServiceSessionId = NULL;
    PULONG64 pspHostSiloGlobals = NULL;
    PULONG64 etwpHostSiloState = NULL;
    PULONG64 etwpLoggerContext = NULL;
    PWMI_LOGGER_CONTEXT loggerContext = NULL;
    BOOLEAN exceptionOccurred = FALSE;

    if (!LoggerId) {
        LoggerId = CKCL_LOGGER_ID;
    }

    // 清空全局状态
    RtlZeroMemory(&g_WkdSyscallMonitor, sizeof(WKD_SYSCALL_MONITOR));

    // 启动 CKCL Trace
    status = SmEtwTraceControl(EtwUpdateLoggerCode);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Start CKCL failed: 0x%08X\n", status);
        return status;
    }

    //
    // 使用 SEH 保护内核结构访问，防止因版本差异导致蓝屏
    //
    /* __try { */
        // 解析 PsGetServerSiloActiveConsoleId 函数地址
        RtlInitUnicodeString(&ucPsGetServerSiloServiceSessionId, L"PsGetServerSiloServiceSessionId");
        pfnPsGetServerSiloServiceSessionId = MmGetSystemRoutineAddress(&ucPsGetServerSiloServiceSessionId);
        if (!pfnPsGetServerSiloServiceSessionId) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WkDefender] Failed to get PsGetServerSiloServiceSessionId address\n");
            return STATUS_UNSUCCESSFUL;
        }

        // 获取 CKCL Logger Context 地址
        // 使用动态偏移量适配不同 Windows 版本
        ULONG etwHostSiloStateOffset = ShpGetEtwSiloStateOffset();
        ULONG etwLoggerContextOffset = ShpGetEtwLoggerContextOffset();

        pspHostSiloGlobals = (PULONG64)(*(PLONG32)((LONG64)pfnPsGetServerSiloServiceSessionId + 3) + 
            (LONG64)pfnPsGetServerSiloServiceSessionId + 7);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] PspHostSiloGlobals: 0x%p\n",
            pspHostSiloGlobals);

        etwpHostSiloState = *(PULONG64*)((ULONG64)pspHostSiloGlobals + etwHostSiloStateOffset);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] EtwpHostSiloState: 0x%p (offset: 0x%X)\n",
            etwpHostSiloState, etwHostSiloStateOffset);

        etwpLoggerContext = *(PULONG64*)((ULONG64)etwpHostSiloState + etwLoggerContextOffset);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] EtwpLoggerContext: 0x%p (offset: 0x%X)\n",
            etwpLoggerContext, etwLoggerContextOffset);

        loggerContext = (PWMI_LOGGER_CONTEXT)(etwpLoggerContext[LoggerId]);

        // 根据当前系统版本选择ETW回调的注册方法
        status = ShpRegisterEtwCallbackInternal(loggerContext);

    /* }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 捕获访问违例或其他异常
        exceptionOccurred = TRUE;
        status = GetExceptionCode();
            status);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] This may indicate Windows version incompatibility or invalid offsets\n");

        // 清理已分配的资源
        ScmCleanup();

        return status;
    } */

    // 检查是否发生异常
    if (exceptionOccurred) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Syscall Monitor initialization aborted due to exception\n");
        return STATUS_UNSUCCESSFUL;
    }

    // 保存 Logger ID
    g_WkdSyscallMonitor.LoggerId = LoggerId;
    g_WkdSyscallMonitor.Initialized = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Syscall Monitor initialized successfully\n");
    return STATUS_SUCCESS;
}