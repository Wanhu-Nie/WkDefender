#pragma once

#include "SyscallService.h"
#include "../Common/Constants.h"
#include "../Common/DynamicArray.h"
#include "../Process/ProcessMonitor.h"
#include "../Notification/NotificationManager.h"

//
// ETW Trace 类型枚举
//
typedef enum _ETW_TRACE_CONTROL_CODE {
    EtwStartLoggerCode = 1,                         // inout WMI_LOGGER_INFORMATION (>= 0xB0)
    EtwStopLoggerCode = 2,                          // inout WMI_LOGGER_INFORMATION (>= 0xB0)
    EtwQueryLoggerCode = 3,                         // inout WMI_LOGGER_INFORMATION (>= 0xB0)
    EtwUpdateLoggerCode = 4,                        // inout WMI_LOGGER_INFORMATION (>= 0xB0)
    EtwFlushLoggerCode = 5,                         // inout WMI_LOGGER_INFORMATION (>= 0xB0)
    EtwIncrementLoggerFile = 6,                     // inout WMI_LOGGER_INFORMATION (>= 0xB0)
    EtwRealtimeTransition = 7,                      // inout WMI_LOGGER_INFORMATION (>= 0xB0)
    // reserved
    EtwRealtimeConnectCode = 11,                    // inout ETW_REALTIME_CONNECT_INFORMATION
    EtwActivityIdCreate = 12,                       // out ETW_ACTIVITY_ID_CREATE_INFORMATION
    EtwWdiScenarioCode = 13,                        // in ETW_WDI_SCENARIO_INFORMATION
    EtwRealtimeDisconnectCode = 14,                 // in ETW_REALTIME_DISCONNECT_INFORMATION
    EtwRegisterGuidsCode = 15,                      // in ETW_UM_REGISTRATION_INFORMATION, out ETW_UM_REGISTRATION_REPLY
    EtwReceiveNotification = 16,                    // out ETW_NOTIFICATION_HEADER + payload
    EtwSendDataBlock = 17,                          // in ETW_ENABLE_NOTIFICATION_PACKET, out ETW_SESSION_NOTIFICATION_PACKET
    EtwSendReplyDataBlock = 18,                     // in ETW_NOTIFICATION_HEADER + payload
    EtwReceiveReplyDataBlock = 19,                  // in ETW_RECEIVE_REPLY_DATA_BLOCK_INFORMATION, out ETW_NOTIFICATION_HEADER + payload
    EtwWdiSemUpdate = 20,                           // inout no input/output buffers
    EtwEnumTraceGuidList = 21,                      // out ETW_TRACE_GUID_LIST
    EtwGetTraceGuidInfo = 22,                       // in ETW_TRACE_GUID_INFO_INFORMATION, out ETW_TRACE_GUID_INFO + ETW_TRACE_PROVIDER_INSTANCE_INFO + ETW_TRACE_ENABLE_INFO[]
    EtwEnumerateTraceGuids = 23,                    // out TRACE_GUID_PROPERTIES[]
    EtwRegisterSecurityProv = 24,                   // inout no input/output buffers
    EtwReferenceTimeCode = 25,                      // in ETW_REFERENCE_TIME_INFORMATION, out ETW_REF_CLOCK
    EtwTrackBinaryCode = 26,                        // in ETW_PROVIDER_BINARY_TRACKING_INFORMATION
    EtwAddNotificationEvent = 27,                   // in ETW_NOTIFICATION_EVENT_INFORMATION
    EtwUpdateDisallowList = 28,                     // in ETW_UPDATE_DISALLOW_LIST_INFORMATION
    EtwSetEnableAllKeywordsCode = 29,               // in not implemented
    EtwSetProviderTraitsCode = 30,                  // in ETW_SET_PROVIDER_TRAITS_INFORMATION, out ETW_SET_PROVIDER_TRAITS_REPLY
    EtwUseDescriptorTypeCode = 31,                  // in ETW_USE_DESCRIPTOR_TYPE_INFORMATION
    EtwEnumTraceGroupList = 32,                     // out ETW_TRACE_GUID_LIST
    EtwGetTraceGroupInfo = 33,                      // in ETW_TRACE_GROUP_INFO_INFORMATION, out ETW_TRACE_GROUP_INFO
    EtwGetDisallowList = 34,                        // in ETW_GET_DISALLOW_LIST_INFORMATION, out ETW_DISALLOW_LIST
    EtwSetCompressionSettings = 35,                 // in ETW_SET_COMPRESSION_SETTINGS_INFORMATION
    EtwGetCompressionSettings = 36,                 // in ETW_GET_COMPRESSION_SETTINGS_INFORMATION, out ETW_COMPRESSION_SETTINGS_DATA
    EtwUpdatePeriodicCaptureState = 37,             // in ETW_UPDATE_PERIODIC_CAPTURE_STATE_INFORMATION
    EtwGetPrivateSessionTraceHandle = 38,           // in ETW_GET_PRIVATE_SESSION_TRACE_HANDLE_INFORMATION, out USHORT PrivateSessionHandle
    EtwRegisterPrivateSession = 39,                 // inout ETW_REGISTER_PRIVATE_SESSION_INFORMATION
    EtwQuerySessionDemuxObject = 40,                // inout ETW_QUERY_SESSION_DEMUX_OBJECT_INFORMATION
    EtwSetProviderBinaryTracking = 41,              // in ETW_SET_PROVIDER_BINARY_TRACKING_INFORMATION
    EtwMaxLoggers = 42,                             // out ETW_MAX_LOGGERS_INFORMATION
    EtwMaxPmcCounter = 43,                          // out ETW_MAX_PMC_COUNTER_INFORMATION
    EtwQueryUsedProcessorCount = 44,                // in ETW_QUERY_USED_PROCESSOR_COUNT_INFORMATION (LoggerId), out ULONG // since WIN11
    EtwGetPmcOwnership = 45,                        // inout ETW_PMC_OWNERSHIP_INFORMATION
    EtwGetPmcSessions = 46,                         // out ETW_PMC_SESSION_INFORMATION[]
    EtwTraceControlMax = 47,
} ETW_TRACE_CONTROL_CODE;

typedef union _WKD_SYSCALL_PARAMETER_BLOCK {
    // NtOpenProcess 参数
    struct {
        _Out_ PHANDLE ProcessHandle;
        _In_ ACCESS_MASK DesiredAccess;
        _In_ PCOBJECT_ATTRIBUTES ObjectAttributes;
        _In_opt_ PCLIENT_ID ClientId;
    } OpenProcess;

    // NtAllocateVirtualMemory 参数
    struct {
        _In_ HANDLE ProcessHandle;
        _Inout_ PVOID* BaseAddress;
        _In_ ULONG_PTR ZeroBits;
        _Inout_ PSIZE_T RegionSize;
        _In_ ULONG AllocationType;
        _In_ ULONG PageProtection;
    } AllocateVirtualMemory;

    // NtProtectVirtualMemory 参数
    struct {
        _In_ HANDLE ProcessHandle;
        _Inout_ PVOID* BaseAddress;
        _Inout_ PSIZE_T RegionSize;
        _In_ ULONG NewProtection;
        _Out_ PULONG OldProtection;
    } ProtectVirtualMemory;

    // NtWriteVirtualMemory 参数
    struct {
        _In_ HANDLE ProcessHandle;
        _In_opt_ PVOID BaseAddress;
        _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer;
        _In_ SIZE_T NumberOfBytesToWrite;
        _Out_opt_ PSIZE_T NumberOfBytesWritten;
    } WriteVirtualMemory;

    // NtCreateThreadEx 参数
    struct {
        _Out_ PHANDLE ThreadHandle;
        _In_ ACCESS_MASK DesiredAccess;
        _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes;
        _In_ HANDLE ProcessHandle;
        _In_ PVOID StartRoutine;    // PUSER_THREAD_START_ROUTINE → PVOID
        _In_opt_ PVOID Argument;
        _In_ ULONG CreateFlags;     // THREAD_CREATE_FLAGS_*
        _In_ SIZE_T ZeroBits;
        _In_ SIZE_T StackSize;
        _In_ SIZE_T MaximumStackSize;
        _In_opt_ PVOID AttributeList;    // PPS_ATTRIBUTE_LIST → PVOID
    } CreateRemoteThread;

    // NtReadVirtualMemory 参数
    struct {
        _In_ HANDLE ProcessHandle;
        _In_opt_ PVOID BaseAddress;
        _Out_writes_bytes_to_(NumberOfBytesToRead, *NumberOfBytesRead) PVOID Buffer;
        _In_ SIZE_T NumberOfBytesToRead;
        _Out_opt_ PSIZE_T NumberOfBytesRead;
    } ReadVirtualMemory;

    // NtQueueApcThread 参数（APC 注入 / AtomBombing 检测）
    struct {
        _In_ HANDLE ThreadHandle;
        _In_opt_ PVOID ApcRoutine;      // APC 例程地址（跨进程目标线程）
        _In_opt_ PVOID ApcArgument1;
        _In_opt_ PVOID ApcArgument2;
        _In_opt_ PVOID ApcArgument3;
    } QueueApcThread;

    // NtSetContextThread 参数（线程劫持 / 镂空：改 RIP/RSP）
    struct {
        _In_ HANDLE ThreadHandle;
        _In_opt_ PVOID ThreadContext;   // PCONTEXT 指针（值供 agent 解析）
    } SetContextThread;

    // NtSuspendThread 参数（线程劫持前置：挂起目标线程）
    struct {
        _In_ HANDLE ThreadHandle;
        _Out_opt_ PULONG PreviousSuspendCount;
    } SuspendThread;

    // NtResumeThread 参数（线程劫持恢复：执行权转移）
    struct {
        _In_ HANDLE ThreadHandle;
        _Out_opt_ PULONG PreviousSuspendCount;
    } ResumeThread;

    // NtAdjustPrivilegesToken 参数（PrivilegeMonitor 迁移 2026-08-06，令牌特权调整）
    struct {
        _In_ HANDLE TokenHandle;            // 目标令牌句柄（无法反查进程，目标回退源进程）
        _In_ BOOLEAN DisableAllPrivileges;  // 禁用全部特权
        _In_opt_ PVOID NewState;            // PTOKEN_PRIVILEGES（Entry 时仅存指针值，不深读）
        _In_ ULONG BufferLength;
        _Out_opt_ PVOID PreviousState;      // PTOKEN_PRIVILEGES
        _Out_opt_ PVOID ReturnLength;       // PULONG
    } AdjustPrivilegesToken;

    // NtDuplicateToken 参数（令牌复制，T1134.001）
    struct {
        _In_ HANDLE ExistingTokenHandle;    // 被复制令牌句柄
        _In_ ACCESS_MASK DesiredAccess;     // 请求访问掩码
        _In_opt_ PVOID ObjectAttributes;    // POBJECT_ATTRIBUTES
        _In_ BOOLEAN EffectiveOnly;
        _In_ TOKEN_TYPE TokenType;          // TokenPrimary / TokenImpersonation
    } DuplicateToken;

    // NtSetInformationToken 参数（令牌属性修改，T1134）
    struct {
        _In_ HANDLE TokenHandle;
        _In_ ULONG TokenInformationClass;   // TOKEN_INFORMATION_CLASS
        _In_opt_ PVOID TokenInformation;
        _In_ ULONG TokenInformationLength;
    } SetInformationToken;

    // NtImpersonateThread 参数（线程模拟，T1134.003）
    struct {
        _In_ HANDLE ServerThreadHandle;     // 服务线程句柄（调用者）
        _In_ HANDLE ClientThreadHandle;     // 被模拟客户端线程句柄 → 目标进程
        _In_opt_ PVOID SecurityQos;         // PSECURITY_QUALITY_OF_SERVICE
    } ImpersonateThread;

    // NtMapViewOfSection 参数（区段映射注入，PreAcquireSection 迁移 2026-08，
    // 10 参。跨进程映射检测 + agent 0x6005 消费链）
    struct {
        _In_ HANDLE     SectionHandle;      // 区段句柄
        _In_ HANDLE     ProcessHandle;      // 目标进程句柄（→ TargetProcessId）
        _Inout_ PVOID*  BaseAddress;        // 映射基址（in/out，Entry 时仅指针值）
        _In_ ULONG_PTR  ZeroBits;
        _In_ SIZE_T     CommitSize;
        _In_opt_ PLARGE_INTEGER SectionOffset;
        _Inout_ PSIZE_T ViewSize;           // 视图大小（in/out）
        _In_ ULONG      InheritDisposition;
        _In_ ULONG      AllocationType;
        _In_ ULONG      Win32Protect;       // 请求保护
    } MapViewOfSection;

    // NtUnmapViewOfSection 参数（进程镂空前置，PreAcquireSection 迁移 2026-08，
    // 2 参。agent 0x6006 → DefEdge_Hollows 消费链）
    struct {
        _In_ HANDLE ProcessHandle;          // 目标进程句柄
        _In_opt_ PVOID BaseAddress;         // 解除映射基址
    } UnmapViewOfSection;

    // NtCreateSection 参数（SectionTracker 迁移 2026-08，7 参）。
    // 匿名可执行（ExecuteAnonymous=200）/大匿名（LargeAnonymous=80）/无背衬 Image
    // （NoBackingFile=180）/TxF 事务（Transacted=300）/DeletePending（Deleted=250）
    // 检测的捕获点（对齐 SS SectionTracker.c SecTrackSectionCreate）。
    // 无进程句柄参数（FileHandle 为文件句柄）→ TargetProcessId=SourceProcessId
    // （对齐令牌类 case 回退语义）。
    struct {
        _Out_ PHANDLE SectionHandle;        // 输出（Exit 后 deref 得 SectionObject 内核指针）
        _In_ ACCESS_MASK DesiredAccess;
        _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes;  // 匿名判定（NULL=匿名）
        _In_opt_ PLARGE_INTEGER MaximumSize;             // 大匿名阈值判定（>100MB）
        _In_ ULONG SectionPageProtection;   // 可执行判定（PAGE_EXECUTE*）
        _In_ ULONG AllocationAttributes;    // SEC_IMAGE 位（NoBackingFile 判定）
        _In_opt_ HANDLE FileHandle;         // 基于文件的 section（TxF/DeletePending 判定）
    } CreateSection;
} WKD_SYSCALL_PARAMETER_BLOCK, *PWKD_SYSCALL_PARAMETER_BLOCK;

//
// 系统调用事件参数结构体
//
typedef struct _WKD_SYSCALL_CONTEXT {
    WKD_SYSCALL_TYPE SyscallNumber;         // 系统调用号
    PKTRAP_FRAME TrapFrame;
    PVOID RoutineAddress;                   // 系统服务例程地址
    PVOID* StackRoutineAddress;             // TrapFrame栈上的系统服务例程指针地址(被篡改)
    BOOLEAN Integrity;                      // 栈完整性
    ULONG ParameterNumber;                  // 参数个数
    ULONG Magic1;                           // PerfInfoLogSysCallEntry函数调用指纹 - Pre/Post
    ULONG Magic2;

    HANDLE SourceThreadId;                  // 发起者线程ID
    HANDLE SourceProcessId;                 // 发起者进程ID
    HANDLE TargetProcessId;                 // 目标进程ID
    HANDLE TargetThreadId;                  // 目标线程ID（线程操作 syscall: SetContext/Suspend/Resume/QueueApc）
    
    WKD_SYSCALL_PARAMETER_BLOCK ParameterBlock;
    NTSTATUS ReturnValue;                   // 系统调用返回值
} WKD_SYSCALL_CONTEXT, *PWKD_SYSCALL_CONTEXT;

//
// 系统调用监控模块全局状态
//
typedef struct _WKD_SYSCALL_MONITOR {
    BOOLEAN Initialized;
    BOOLEAN ShutdownRequested;
    
    ULONG LoggerId;                     // CKCL Logger ID
        
    ULONG64 GetCpuClockType;              // 0-3               
    PVOID GetCpuClockPtr;               // 通过HalpPerformanceCounter间接调用, GetCpuClock为类型标识
    PULONG64 KiDynamicTraceMask;        // 动态 Trace Mask 指针
    
    struct {
        volatile LONG64 SyscallEntryCount;
        volatile LONG64 SyscallExitCount;
        volatile LONG64 TamperedStackCount;
        volatile LONG64 SuspiciousPatternDetected;  // 可疑模式检测次数
    } Statistics;
} WKD_SYSCALL_MONITOR, *PWKD_SYSCALL_MONITOR;

//
// 全局系统调用监控器实例
//
extern WKD_SYSCALL_MONITOR g_WkdSyscallMonitor;

/****************************************************
**                      函数声明                    **
*****************************************************/

//
// 初始化与清理函数
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
SmInitialize(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ScmCleanup(
    VOID
    );

//
// 记录系统调用事件到进程行为上下文
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
SmRecordSyscallEvent(
    _In_ HANDLE ProcessId,
    _In_ WKD_MESSAGE_TYPE EventType,
    _In_ ULONG SyscallNumber,
    _In_ PWKD_SYSCALL_CONTEXT Parameters,
    _In_ NTSTATUS Status
    );

//
// 分析进程的syscall事件序列，检测可疑模式
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
SmAnalyzeSyscallPattern(
    _In_ PWKD_PROCESS Process
    );

//
// 自定义 CPU Lock 获取函数（用于劫持系统调用监控）
//
_IRQL_requires_(PASSIVE_LEVEL)
ULONG64
WkGetCpuLock(
    VOID
    );

//
// 获取系统服务例程地址（外部依赖函数）
//
PVOID
GetSystemServiceRoutineAddress(
    _In_ ULONG SyscallNumber
    );

//
// 判断内核栈是否扩展（外部依赖函数）
//
BOOLEAN
IsKernelStackExpend(
    _In_ ULONG SyscallNumber
    );
