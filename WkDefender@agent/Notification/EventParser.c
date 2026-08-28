/**************************************************/
/*  WkDefender 事件解析系统实现                      */
/**************************************************/

#include "EventParser.h"
#include "../tools.h"

WKD_SCHEMA_TABLE g_DefSchemaTable = { 0 };

/**************************************************/
/*           进程创建事件解析                        */
/**************************************************/

static
NTSTATUS
NtfpEventParseProcessCreate(
    _In_ const PWKD_MESSAGE Message,
    _Out_ PWKD_EVENT_HEADER* Event
    )
/*++
Routine Description:
    ProcessCreate 解析 (2026-08-25 嵌入式扁平化):
    单块分配 [header][payload][WCHAR 数据区], 三串内嵌
    UNICODE_STRING.Buffer 指向数据区游标, 排布序 = 字段声明序
    (ImagePath → CommandLine → ImageFileName), 与驱动
    WKD_MESSAGE_BODY_PROCESS_CREATE 线格式同构; 有效串含 NUL 终止,
    缺失串 Length/MaximumLength/Buffer 全零; PayloadSize 含数据区
    总长 (归档整块拷贝依赖此约定)。
--*/
{
    PWKD_EVENT_HEADER event;
    PEVENT_PAYLOAD_PROCESS_CREATE payload;
    PWKD_MESSAGE_HEADER msgHdr;
    PWKD_MESSAGE_BODY_PROCESS_CREATE msgBody;
    ULONG totalSize;
    ULONG pathBytes, cmdBytes;
    ULONG pathMax, cmdMax, nameMax, nameBytes;
    PCWSTR pathSrc, cmdSrc, nameSrc;
    PUCHAR strCursor;

    if (!Message ||
        Message->Header.BodySize < sizeof(WKD_MESSAGE_BODY_PROCESS_CREATE)) {
        return STATUS_INVALID_PARAMETER;
    }

    msgBody = (PWKD_MESSAGE_BODY_PROCESS_CREATE)Message->Body;

    /* 线格式: ImagePath.Buffer → 固定头之后, CommandLine.Buffer 紧随其后 */
    pathSrc = (PCWSTR)((PUCHAR)msgBody + sizeof(WKD_MESSAGE_BODY_PROCESS_CREATE));
    cmdSrc  = (PCWSTR)((PUCHAR)pathSrc + msgBody->ImagePath.MaximumLength);

    pathBytes = CoCheckUnicodeStringValidity(&msgBody->ImagePath)
                ? msgBody->ImagePath.Length : 0;
    cmdBytes  = CoCheckUnicodeStringValidity(&msgBody->CommandLine)
                ? msgBody->CommandLine.Length : 0;

    /* 文件名 = 完整路径最后一个 '\\' 之后的部分 (手动扫描, 不依赖 NUL) */
    {
        PCWSTR scan = pathSrc;
        PCWSTR end  = pathSrc + pathBytes / sizeof(WCHAR);
        PCWSTR lastSlash = NULL;

        while (scan < end) {
            if (*scan == L'\\') lastSlash = scan;
            scan++;
        }
        nameSrc   = lastSlash ? (lastSlash + 1) : pathSrc;
        nameBytes = (ULONG)((PUCHAR)end - (PUCHAR)nameSrc);
    }

    /* 预算: 有效串含 NUL 终止, 缺失串零字节 */
    pathMax = pathBytes ? (pathBytes + sizeof(WCHAR)) : 0;
    cmdMax  = cmdBytes  ? (cmdBytes + sizeof(WCHAR))  : 0;
    nameMax = nameBytes ? (nameBytes + sizeof(WCHAR)) : 0;

    totalSize = sizeof(WKD_EVENT_HEADER) + sizeof(EVENT_PAYLOAD_PROCESS_CREATE)
                + pathMax + cmdMax + nameMax;
    event = (PWKD_EVENT_HEADER)UtHeapAlloc(totalSize);   /* HEAP_ZERO_MEMORY */
    if (!event) return STATUS_NO_MEMORY;

    CoCreateGuid(&event->EventId);
    event->Class = DefEventClass_IOA;
    event->Type = WkdEvent_ProcessCreate;
    event->SchemaVersion = 1;
    event->Confidence = 1000;
    event->Severity = DefThreatSeverity_None;
    event->PayloadSize = totalSize - (ULONG)sizeof(WKD_EVENT_HEADER);

    msgHdr = &Message->Header;
    event->Timestamp = msgHdr->Timestamp;
    GetSystemTimeAsFileTime((PFILETIME)&event->IngestTime);

    payload = (PEVENT_PAYLOAD_PROCESS_CREATE)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));

    /* 载荷与消息体同为 HANDLE 口径, 直接拷贝 (2026-08-24 对齐) */
    payload->ProcessId = msgBody->ProcessId;
    payload->CreateTime = msgBody->CreateTime;
    payload->ParentProcessId = msgBody->ParentProcessId;
    payload->ParentCreateTime.QuadPart = 0;   /* 驱动未上报父进程创建时间 */
    payload->SessionId = msgBody->SessionId;
    payload->IntegrityLevel = msgBody->IntegrityLevel;
    payload->IsElevated = (BOOLEAN)msgBody->Elevated;
    payload->Amd64 = TRUE;
    payload->IsProtectedProcess = (msgBody->SecurityFlags & 2) ? TRUE : FALSE;

    /* 三串游标填充 (声明序), 缺失串保持全零 */
    strCursor = (PUCHAR)(payload + 1);

    if (pathMax) {
        payload->ImagePath.Length = (USHORT)pathBytes;
        payload->ImagePath.MaximumLength = (USHORT)pathMax;
        payload->ImagePath.Buffer = (PWCHAR)strCursor;
        RtlCopyMemory(strCursor, pathSrc, pathBytes);
        ((PWCHAR)strCursor)[pathBytes / sizeof(WCHAR)] = L'\0';
        strCursor += pathMax;
    }

    if (cmdMax) {
        payload->CommandLine.Length = (USHORT)cmdBytes;
        payload->CommandLine.MaximumLength = (USHORT)cmdMax;
        payload->CommandLine.Buffer = (PWCHAR)strCursor;
        RtlCopyMemory(strCursor, cmdSrc, cmdBytes);
        ((PWCHAR)strCursor)[cmdBytes / sizeof(WCHAR)] = L'\0';
        strCursor += cmdMax;
    }

    if (nameMax) {
        payload->ImageFileName.Length = (USHORT)nameBytes;
        payload->ImageFileName.MaximumLength = (USHORT)nameMax;
        payload->ImageFileName.Buffer = (PWCHAR)strCursor;
        RtlCopyMemory(strCursor, nameSrc, nameBytes);
        ((PWCHAR)strCursor)[nameBytes / sizeof(WCHAR)] = L'\0';
    }

    *Event = event;
    return STATUS_SUCCESS;
}

/**************************************************/
/*           进程退出事件解析                        */
/**************************************************/

static
NTSTATUS
NtfpParseProcessExit(
    _In_ const PWKD_MESSAGE Message,
    _Out_ PWKD_EVENT_HEADER* Event
    )
/*++
Routine Description:
    进程退出解析 (2026-08-25 结构化): 按驱动线格式
    WKD_MESSAGE_BODY_PROCESS_EXIT 结构化拷贝 — 原实现按
    raw[0]/raw[1] 裸读, x64 下 raw[1] 实为 PID 高 32 位而非
    ExitCode (HANDLE 8 字节对齐错位)。
--*/
{
    PWKD_EVENT_HEADER           event;
    PEVENT_PAYLOAD_PROCESS_EXIT payload;
    PWKD_MESSAGE_BODY_PROCESS_EXIT body;
    ULONG totalSize;

    if (!Message || 
        Message->Header.Type != WkdMessage_ProcessExited ||
        Message->Header.BodySize < sizeof(WKD_MESSAGE_BODY_PROCESS_EXIT)) {
        return STATUS_INVALID_PARAMETER;
    }

    totalSize = sizeof(WKD_EVENT_HEADER) + sizeof(EVENT_PAYLOAD_PROCESS_EXIT);
    event = (PWKD_EVENT_HEADER)UtHeapAlloc(totalSize);
    if (!event) return STATUS_NO_MEMORY;

    CoCreateGuid(&event->EventId);
    event->Class = DefEventClass_IOA;
    event->Type = WkdEvent_ProcessExit;
    event->SchemaVersion = 1;
    event->Timestamp = Message->Header.Timestamp;
    GetSystemTimeAsFileTime((PFILETIME)&event->IngestTime);
    event->Severity = DefThreatSeverity_None;
    event->PayloadSize = sizeof(EVENT_PAYLOAD_PROCESS_EXIT);

    body = (PWKD_MESSAGE_BODY_PROCESS_EXIT)Message->Body;
    payload = (PEVENT_PAYLOAD_PROCESS_EXIT)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));

    /* 线格式 → 载荷 同构直拷 */
    payload->ProcessId       = body->ProcessId;
    payload->ExitCode        = body->ExitCode;
    payload->ParentProcessId = body->ParentProcessId;
    payload->CreateTime      = body->CreateTime;
    payload->ExitTime        = body->ExitTime;
    payload->SessionId       = body->SessionId;
    payload->ExitFlags       = body->ExitFlags;

    *Event = event;
    return STATUS_SUCCESS;
}

/**************************************************/
/*           Syscall聚合事件解析                    */
/**************************************************/

static NTSTATUS
DefEventParseSyscall(_In_ PWKD_MESSAGE Message, _Out_ PWKD_EVENT_HEADER* Event)
{
    PWKD_EVENT_HEADER       event;
    PEVENT_PAYLOAD_SYSCALL    payload;
    PWKD_MSG_BODY_SYSCALL   body;
    ULONG                   totalSize;
    ULONG                   bFlags = 0, score = 0, sev = 0, repeat = 0;

    body = (PWKD_MSG_BODY_SYSCALL)Message->Body;
    /* 解析 L1 元数据 */
    if (Message->Header.BodySize >= sizeof(WKD_MSG_BODY_SYSCALL) + sizeof(WCHAR)*2) {
        WCHAR desc[256] = { 0 };
        PWCHAR pDesc = (PWCHAR)((PUCHAR)body + sizeof(WKD_MSG_BODY_SYSCALL));
        wcsncpy_s(desc, 256, pDesc, min((Message->Header.BodySize - sizeof(WKD_MSG_BODY_SYSCALL)) / sizeof(WCHAR), 255));
        swscanf_s(desc, L"L1|F=%x|S=%lu|V=%lu|R=%lu", &bFlags, &score, &sev, &repeat);
    }

    totalSize = sizeof(WKD_EVENT_HEADER) + sizeof(EVENT_PAYLOAD_SYSCALL);
    event = (PWKD_EVENT_HEADER)UtHeapAlloc(totalSize);
    if (!event) return STATUS_NO_MEMORY;

    CoCreateGuid(&event->EventId);
    event->Class = DefEventClass_IOA;
    event->SchemaVersion = 1;
    event->Timestamp = Message->Header.Timestamp;
    GetSystemTimeAsFileTime((PFILETIME)&event->IngestTime);
    event->BehaviorFlags = bFlags;
    event->Severity = (sev >= DefThreatSeverity_Critical) ? DefThreatSeverity_Critical : (DEF_THREAT_SEVERITY)sev;
    event->PayloadSize = sizeof(EVENT_PAYLOAD_SYSCALL);

    switch (Message->Header.Type) {
    case WkdMessage_SyscallOpenProcess:
        event->Type = WkdEvent_ProcessOpen;
        break;
    case WkdMessage_SyscallAllocateMemory:
        event->Type = WkdEvent_MemoryAllocate;
        break;
    case WkdMessage_SyscallProtectMemory:
        event->Type = WkdEvent_MemoryProtect;
        break;
    case WkdMessage_SyscallReadMemory:
        event->Type = WkdEvent_MemoryRead;
        break;
    case WkdMessage_SyscallWriteMemory:
        event->Type = WkdEvent_MemoryWrite;
        break;
    default:
        event->Type = WkdEvent_SyscallAggregated;
    }

    payload = (PEVENT_PAYLOAD_SYSCALL)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));
    payload->SourceProcessId = Message->Header.SourceProcessId;
    payload->TargetProcessId = Message->Header.TargetProcessId;
    payload->SyscallNumber = body->SyscallNumber;
    payload->RepeatCount = repeat;
    payload->TimeWindowMs = 500;
    payload->TargetProcessId = Message->Header.TargetProcessId;
    payload->OverallScore = score;
    payload->ParameterNumber = body->ParameterNumber;
    RtlCopyMemory(payload->ParameterBase, body->ParameterBase, sizeof(ULONG64) * body->ParameterNumber);

    event->Confidence = (score >= 200 || (bFlags & DEF_BEHAVIOR_FLAG_LOLBIN)) ? min(score * 2, 1000) : score;
    *Event = event;
    return STATUS_SUCCESS;
}

/**************************************************/
/*           AMSI 绕过检测事件解析                   */
/**************************************************/

static
NTSTATUS
NtfpParseAmsiBypass(_In_ PWKD_MESSAGE Message, _Out_ PWKD_EVENT_HEADER* Event)
{
    PWKD_EVENT_HEADER           event;
    PEVENT_PAYLOAD_AMSI_BYPASS    payload;
    PWKD_MSG_BODY_AMSI_BYPASS   body;
    ULONG                       totalSize;

    body = (PWKD_MSG_BODY_AMSI_BYPASS)Message->Body;

    totalSize = sizeof(WKD_EVENT_HEADER) + sizeof(EVENT_PAYLOAD_AMSI_BYPASS);
    event = (PWKD_EVENT_HEADER)UtHeapAlloc(totalSize);
    if (!event) return STATUS_NO_MEMORY;

    CoCreateGuid(&event->EventId);
    event->Class = DefEventClass_IOA;
    event->Type = WkdEvent_AmsiBypass;
    event->SchemaVersion = 1;
    event->Timestamp = Message->Header.Timestamp;
    GetSystemTimeAsFileTime((PFILETIME)&event->IngestTime);
    /* 高置信度进 VerdictEngine E5 (Behavior 源) 融合 */
    event->Confidence = 600;
    event->Severity = DefThreatSeverity_High;
    event->BehaviorFlags = DEF_BEHAVIOR_FLAG_AMSI_BYPASS;
    event->PayloadSize = sizeof(EVENT_PAYLOAD_AMSI_BYPASS);

    payload = (PEVENT_PAYLOAD_AMSI_BYPASS)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));
    payload->SourceProcessId = Message->Header.SourceProcessId;
    payload->TargetProcessId = Message->Header.TargetProcessId;
    payload->BypassType = body->BypassType;
    payload->TargetAddress = (ULONG64)body->TargetAddress;
    payload->OldProtection = body->OldProtection;
    payload->NewProtection = body->NewProtection;
    RtlCopyMemory(payload->CurrentBytes, body->CurrentBytes, sizeof(payload->CurrentBytes));
    MultiByteToWideChar(CP_ACP, 0, body->FunctionName, -1,
                        payload->FunctionName,
                        (int)(sizeof(payload->FunctionName) / sizeof(WCHAR)));

    *Event = event;
    return STATUS_SUCCESS;
}

/**************************************************/
/*               线程事件解析                        */
/**************************************************/

static
NTSTATUS
NtfpParseThreadCreate(
    _In_  PWKD_MESSAGE       Message,
    _Out_ PWKD_EVENT_HEADER* Event
    )
{
    PWKD_EVENT_HEADER           event;
    PEVENT_PAYLOAD_THREAD_CREATE  payload;
    PWKD_MESSAGE_BODY_THREAD_CREATE body;
    ULONG                       totalSize;
    BOOLEAN                     isRemote;

    body = (PWKD_MESSAGE_BODY_THREAD_CREATE)Message->Body;
    isRemote = (body->Flags & 0x00000001) != 0;

    totalSize = sizeof(WKD_EVENT_HEADER) + sizeof(EVENT_PAYLOAD_THREAD_CREATE);
    event = (PWKD_EVENT_HEADER)UtHeapAlloc(totalSize);
    if (!event) return STATUS_NO_MEMORY;

    CoCreateGuid(&event->EventId);
    event->Class = DefEventClass_IOA;
    event->Type = isRemote ? WkdEvent_RemoteThreadCreate : WkdEvent_ThreadCreate;
    event->SchemaVersion = 3;   /* v3: 新增 MemoryProtection/CreatorSessionId/TargetSessionId/InjectIndicators/InjectionScore/RiskLevel (对齐 PS TnpAnalyzeThreadCreation) */
    event->Timestamp = Message->Header.Timestamp;
    GetSystemTimeAsFileTime((PFILETIME)&event->IngestTime);
    event->Confidence = isRemote ? 600 : 100;
    event->Severity = isRemote ? DefThreatSeverity_Medium : DefThreatSeverity_None;
    event->PayloadSize = sizeof(EVENT_PAYLOAD_THREAD_CREATE);

    /*
     * SourceProcessId / TargetProcessId 暂不在此处设置。
     * IOA 引擎在 IoaObserve 中通过 payload 中的 PID
     * 查谱系获取真实 NodeId 后回填（见 IoaEngine.c）。
     */

    if (isRemote) {
        event->BehaviorFlags |= DEF_BEHAVIOR_FLAG_REMOTE_THREAD;
    }

    payload = (PEVENT_PAYLOAD_THREAD_CREATE)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));
    payload->ProcessId = (HANDLE)(ULONG_PTR)Message->Header.TargetProcessId;
    payload->ThreadId = body->ThreadId;
    payload->CreatorProcessId = Message->Header.SourceProcessId;
    payload->CreatorThreadId = body->CreatorThreadId;
    payload->StartRoutine  = body->StartRoutine;
    payload->Argument      = body->Argument;
    payload->DesiredAccess = body->DesiredAccess;
    payload->CreateFlags   = body->CreateFlags;
    payload->CreateTime    = body->CreateTime;
    payload->Flags         = body->Flags;

    /*
     * 注入分析字段（对齐 PS TnpAnalyzeThreadCreation）
     */
    payload->MemoryProtection  = body->MemoryProtection;
    payload->CreatorSessionId = body->CreatorSessionId;
    payload->TargetSessionId  = body->TargetSessionId;
    payload->InjectIndicators = body->InjectIndicators;
    payload->InjectionScore   = body->InjectionScore;
    payload->RiskLevel        = body->RiskLevel;

    /*
     * 入口点内存原始字节（供 shellcode 模式匹配，对齐 PS TnpCheckShellcodePatterns）
     */
    payload->StartBytesSize = body->StartBytesSize;
    if (body->StartBytesSize > 0) {
        ULONG copySz = min(body->StartBytesSize, sizeof(payload->StartBytes));
        RtlCopyMemory(payload->StartBytes, body->StartBytes, copySz);
    } else {
        RtlZeroMemory(payload->StartBytes, sizeof(payload->StartBytes));
    }

/*
     * 入口点归属结论（driver IocDetectThread 计算，经 ALPC 上送）。
     * agent IocObserveThread 直接消费，无需重做归属检查。
     * 由 InjectIndicators 位图推导（与 IoaInjectionClassifier 保持一致）：
     *   WKD_MSG_INJECT_UNUSUAL_ENTRY (0x00000200) → 入口点不在已知模块
     *   WKD_MSG_INJECT_UNBACKED_START  (0x00000004) → 起始地址无模块背衬
     */
    payload->IsUnusualEntry    = (payload->InjectIndicators & 0x00000200) != 0;
    payload->IsStartAddrBacked = !(payload->InjectIndicators & 0x00000004);

    *Event = event;
    return STATUS_SUCCESS;
}

/*
 * NtfpParseThreadExit — WkdMessage_ThreadExited → WkdEvent_ThreadExit 事件。
 *
 * 载荷为 WKD_MESSAGE_BODY_THREAD_CREATE（Flags bit1=Create=0），仅取进程/线程
 * 标识 + 创建时间，供进程表线程计数递减与线程生命周期感知。
 * 数据源状态: 驱动 ThreadNotify.c CbpThreadNotifyCallback 终止分支已恢复上送
 *   WkdMessage_ThreadExited（2026-08 迁移），修复"ThreadExited 消息被误解析
 *   为 ThreadCreate"的既有缺陷。
 */
static
NTSTATUS
NtfpParseThreadExit(
    _In_  PWKD_MESSAGE       Message,
    _Out_ PWKD_EVENT_HEADER* Event
    )
{
    PWKD_EVENT_HEADER           event;
    PEVENT_PAYLOAD_THREAD_EXIT    payload;
    PWKD_MESSAGE_BODY_THREAD_CREATE body;
    ULONG                       totalSize;

    body = (PWKD_MESSAGE_BODY_THREAD_CREATE)Message->Body;

    totalSize = sizeof(WKD_EVENT_HEADER) + sizeof(EVENT_PAYLOAD_THREAD_EXIT);
    event = (PWKD_EVENT_HEADER)UtHeapAlloc(totalSize);
    if (!event) return STATUS_NO_MEMORY;

    CoCreateGuid(&event->EventId);
    event->Class = DefEventClass_IOA;
    event->Type = WkdEvent_ThreadExit;
    event->SchemaVersion = 1;
    event->Timestamp = Message->Header.Timestamp;
    GetSystemTimeAsFileTime((PFILETIME)&event->IngestTime);
    event->Confidence = 100;
    event->Severity = DefThreatSeverity_None;
    event->PayloadSize = sizeof(EVENT_PAYLOAD_THREAD_EXIT);

    payload = (PEVENT_PAYLOAD_THREAD_EXIT)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));
    payload->SourceProcessId = Message->Header.SourceProcessId;
    payload->TargetProcessId = Message->Header.TargetProcessId;
    payload->ThreadId = body->ThreadId;
    payload->CreatorThreadId = body->CreatorThreadId;
    payload->CreateTime = body->CreateTime;
    payload->Flags = body->Flags;

    *Event = event;
    return STATUS_SUCCESS;
}

/**************************************************/
/*           APC 队列事件解析                       */
/**************************************************/

/*
 * NtfpParseQueueApc — NtQueueApcThread 消息 → WkdEvent_QueueApc 事件。
 *
 * 从 WKD_MSG_BODY_SYSCALL.ParameterBase[8] 按约定布局提取:
 *   [0]=ThreadHandle, [1]=ApcRoutine, [2..4]=ApcArgument1/2/3。
 * ApcRoutine 为 AtomBombing (T1055.009) 精准判定的核心信号。
 * 数据源状态: 驱动当前未挂 NtQueueApcThread case 且参数未解析,
 *   ApcRoutine==0 时分类器原子判定自然不触发, 不引入误报。
 */
static
NTSTATUS
NtfpParseQueueApc(
    _In_  PWKD_MESSAGE       Message,
    _Out_ PWKD_EVENT_HEADER* Event
    )
{
    PWKD_EVENT_HEADER       event;
    PEVENT_PAYLOAD_QUEUE_APC  payload;
    PWKD_MSG_BODY_SYSCALL   body;
    ULONG                   totalSize;

    body = (PWKD_MSG_BODY_SYSCALL)Message->Body;

    totalSize = sizeof(WKD_EVENT_HEADER) + sizeof(EVENT_PAYLOAD_QUEUE_APC);
    event = (PWKD_EVENT_HEADER)UtHeapAlloc(totalSize);
    if (!event) return STATUS_NO_MEMORY;

    CoCreateGuid(&event->EventId);
    event->Class = DefEventClass_IOA;
    event->Type = WkdEvent_QueueApc;
    event->SchemaVersion = 1;
    event->Timestamp = Message->Header.Timestamp;
    GetSystemTimeAsFileTime((PFILETIME)&event->IngestTime);
    event->BehaviorFlags |= DEF_BEHAVIOR_FLAG_APC_INJECTION;
    event->Confidence = 500;
    event->Severity = DefThreatSeverity_Medium;
    event->PayloadSize = sizeof(EVENT_PAYLOAD_QUEUE_APC);

    payload = (PEVENT_PAYLOAD_QUEUE_APC)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));
    payload->SourceProcessId = Message->Header.SourceProcessId;
    payload->TargetProcessId = Message->Header.TargetProcessId;
    payload->ThreadId = Message->Header.ThreadId;
    payload->ApcRoutine = 0;
    payload->ApcArgument1 = 0;
    payload->ApcArgument2 = 0;
    payload->ApcArgument3 = 0;

    if (body->ParameterNumber >= 2) {
        payload->ApcRoutine = (ULONG_PTR)body->ParameterBase[1];
    }
    if (body->ParameterNumber >= 3) {
        payload->ApcArgument1 = (ULONG_PTR)body->ParameterBase[2];
    }
    if (body->ParameterNumber >= 4) {
        payload->ApcArgument2 = (ULONG_PTR)body->ParameterBase[3];
    }
    if (body->ParameterNumber >= 5) {
        payload->ApcArgument3 = (ULONG_PTR)body->ParameterBase[4];
    }

    *Event = event;
    return STATUS_SUCCESS;
}

/**************************************************/
/*           线程操作事件解析                        */
/**************************************************/

/*
 * NtfpParseThreadOp — NtSetContextThread/NtSuspendThread/NtResumeThread
 * 消息 → WkdEvent_SetThreadContext / WkdEvent_ThreadSuspend / WkdEvent_ThreadResume。
 *
 * 从 WKD_MSG_BODY_SYSCALL.ParameterBase[8] 按约定布局提取:
 *   [0]=ThreadHandle。
 * ThreadId 取 WKD_MESSAGE_HEADER.ThreadId（驱动 ShpResolveThreadTarget 回填）。
 * 时序状态 (Suspend→SetContext→Resume) 由 IOA 阶段4.5b 消费，见 IoaEngine.c。
 * 数据源状态: 需驱动补 NtSetContextThread/NtSuspendThread/NtResumeThread case。
 */
static
NTSTATUS
NtfpParseThreadOp(
    _In_  PWKD_MESSAGE       Message,
    _Out_ PWKD_EVENT_HEADER* Event
    )
{
    PWKD_EVENT_HEADER       event;
    PEVENT_PAYLOAD_THREAD_OP  payload;
    PWKD_MSG_BODY_SYSCALL   body;
    ULONG                   totalSize;

    body = (PWKD_MSG_BODY_SYSCALL)Message->Body;

    totalSize = sizeof(WKD_EVENT_HEADER) + sizeof(EVENT_PAYLOAD_THREAD_OP);
    event = (PWKD_EVENT_HEADER)UtHeapAlloc(totalSize);
    if (!event) return STATUS_NO_MEMORY;

    CoCreateGuid(&event->EventId);
    event->Class = DefEventClass_IOA;
    event->SchemaVersion = 1;
    event->Timestamp = Message->Header.Timestamp;
    GetSystemTimeAsFileTime((PFILETIME)&event->IngestTime);
    event->Confidence = 300;
    event->Severity = DefThreatSeverity_None;
    event->PayloadSize = sizeof(EVENT_PAYLOAD_THREAD_OP);

    switch (Message->Header.Type) {
    case WkdMessage_SyscallSetContextThread:
        event->Type = WkdEvent_SetThreadContext;
        event->BehaviorFlags |= DEF_BEHAVIOR_FLAG_SET_CONTEXT;
        event->Confidence = 600;
        event->Severity = DefThreatSeverity_Low;
        break;
    case WkdMessage_SyscallSuspendThread:
        event->Type = WkdEvent_ThreadSuspend;
        break;
    case WkdMessage_SyscallResumeThread:
        event->Type = WkdEvent_ThreadResume;
        event->Confidence = 400;
        break;
    default:
        UtHeapFree(event);
        return STATUS_INVALID_PARAMETER;
    }

    payload = (PEVENT_PAYLOAD_THREAD_OP)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));
    payload->SourceProcessId = Message->Header.SourceProcessId;
    payload->TargetProcessId = Message->Header.TargetProcessId;
    payload->ThreadId = Message->Header.ThreadId;
    payload->ThreadHandle = 0;
    if (body->ParameterNumber >= 1) {
        payload->ThreadHandle = (ULONG_PTR)body->ParameterBase[0];
    }

    *Event = event;
    return STATUS_SUCCESS;
}

//
// 区段映射解析器（PreAcquireSection 迁移 2026-08-06）
// 消息 → WkdEvent_MapViewOfSection(0x6005) / WkdEvent_UnmapViewOfSection(0x6006)。
//
// 来源：文件轨（WkdMessage_SectionMap=0x1308，minifilter AcquireSection，Origin=0）
//       / syscall 轨（WkdMessage_SyscallMapSection=0x1006，NtMapViewOfSection，
//       Origin=1 / WkdMessage_SyscallUnmapSection=0x1010，NtUnmapViewOfSection，
//       Origin=2）。
// 统一从 WKD_MESSAGE_BODY_SECTION_MAP 读取（驱动两侧共用同一线格式）。
// Source/Target 取 Header（syscall 轨跨进程 Source≠Target → IoaObserve 阶段1
// default 分支建进程对）。
// 消费方：IOA 边映射 MapViewOfSection→DefEdge_Allocates、Unmap→DefEdge_Hollows
//   （IoaFsmEngine.c / IoaCarsalGraph.c 已就位）→ 注入分类器 WkdInjection_SectionMapping。
// 数据源状态: 文件轨已激活（Filter.c FspPreAcquireSection）；syscall 轨 case 已落位
//   （SyscallHijack.c），触发依赖 SmInitialize() 启用（WkdEntry.c 当前注释保持关闭）。
//
static
NTSTATUS
NtfpParseSectionOp(
    _In_  PWKD_MESSAGE       Message,
    _Out_ PWKD_EVENT_HEADER* Event
    )
{
    PWKD_EVENT_HEADER       event;
    PEVENT_PAYLOAD_SECTION_MAP payload;
    PWKD_MESSAGE_BODY_SECTION_MAP body;
    ULONG                   totalSize;

    body = (PWKD_MESSAGE_BODY_SECTION_MAP)Message->Body;

    totalSize = sizeof(WKD_EVENT_HEADER) + sizeof(EVENT_PAYLOAD_SECTION_MAP);
    event = (PWKD_EVENT_HEADER)UtHeapAlloc(totalSize);
    if (!event) return STATUS_NO_MEMORY;

    CoCreateGuid(&event->EventId);
    event->Class = DefEventClass_IOA;
    event->SchemaVersion = 1;
    event->Timestamp = Message->Header.Timestamp;
    GetSystemTimeAsFileTime((PFILETIME)&event->IngestTime);
    event->Confidence = 300;
    event->Severity = DefThreatSeverity_None;
    event->PayloadSize = sizeof(EVENT_PAYLOAD_SECTION_MAP);

    switch (Message->Header.Type) {
    case WkdMessage_SyscallMapSection:
    case WkdMessage_SectionMap:
        event->Type = WkdEvent_MapViewOfSection;
        /* syscall 轨（Origin=1，跨进程注入）高置信；文件轨按评分保留基础置信 */
        if (body->Origin == 1) {
            event->Confidence = 700;
        }
        break;
    case WkdMessage_SyscallUnmapSection:
        event->Type = WkdEvent_UnmapViewOfSection;
        event->Confidence = 500;
        break;
    default:
        UtHeapFree(event);
        return STATUS_INVALID_PARAMETER;
    }

    payload = (PEVENT_PAYLOAD_SECTION_MAP)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));
    payload->SourceProcessId = Message->Header.SourceProcessId;
    payload->TargetProcessId = Message->Header.TargetProcessId;
    payload->ThreadId = body->ThreadId;
    payload->PageProtection = body->PageProtection;
    payload->SectionType = body->SectionType;
    payload->MappingFlags = body->MappingFlags;
    payload->SuspicionScore = body->SuspicionScore;
    payload->Origin = body->Origin;
    payload->Flags = body->Flags;
    payload->SectionHandle = body->SectionHandle;
    payload->BaseAddress = body->BaseAddress;
    payload->RegionSize = body->RegionSize;
    payload->Timestamp = body->Timestamp;
    /* 展平布局不复制路径（IoaObserve 阶段1 仅取 PID；路径语义归文件轨驱动侧）。
     * 嵌入式布局 (2026-08-25): UtHeapAlloc 零初始化即"空串"语义, 无需显式置 NULL。 */

    *Event = event;
    return STATUS_SUCCESS;
}

//
// Section 创建解析器（SectionTracker 迁移 2026-08）
// 消息 → WkdEvent_SectionCreate(0x6007)。
// 来源：syscall 轨 WkdMessage_SyscallCreateSection(0x1011)，NtCreateSection Exit。
// 从 WKD_MESSAGE_BODY_SECTION_CREATE 读取（驱动解析后上送：SectionObject/MaximumSize/
//   5 类怀疑信号 + 评分）。
// Source/Target 取 Header（创建为单进程事件，Target=同源 → IoaObserve 阶段1
//   default 分支解析节点）。
// SectionObject 为聚合键：IoaInjectionClassifier 共享 Section 聚合表按它关联
//   WkdEvent_MapViewOfSection 的跨进程映射（RemoteMap 三方判定）。
// 消费方：IoaObserve 阶段4.12（g_IoaSectionSharingEnabled 门控）。
// 数据源状态: 驱动 SyscallHijack.c NtCreateSection case 已落位（死代码），
//   触发依赖 SmInitialize() 启用（WkdEntry.c 当前注释保持关闭）。
//
static
NTSTATUS
NtfpParseSectionCreate(
    _In_  PWKD_MESSAGE       Message,
    _Out_ PWKD_EVENT_HEADER* Event
    )
{
    PWKD_EVENT_HEADER       event;
    PEVENT_PAYLOAD_SECTION_CREATE payload;
    PWKD_MESSAGE_BODY_SECTION_CREATE body;
    ULONG                   totalSize;

    body = (PWKD_MESSAGE_BODY_SECTION_CREATE)Message->Body;

    totalSize = sizeof(WKD_EVENT_HEADER) + sizeof(EVENT_PAYLOAD_SECTION_CREATE);
    event = (PWKD_EVENT_HEADER)UtHeapAlloc(totalSize);
    if (!event) return STATUS_NO_MEMORY;

    CoCreateGuid(&event->EventId);
    event->Class = DefEventClass_IOA;
    event->SchemaVersion = 1;
    event->Timestamp = Message->Header.Timestamp;
    GetSystemTimeAsFileTime((PFILETIME)&event->IngestTime);
    event->Confidence = 300;
    event->Severity = DefThreatSeverity_None;
    event->PayloadSize = sizeof(EVENT_PAYLOAD_SECTION_CREATE);

    switch (Message->Header.Type) {
    case WkdMessage_SyscallCreateSection:
        event->Type = WkdEvent_SectionCreate;
        /* 命中高置信信号（TxF/DeletePending/匿名可执行）提升置信度 */
        if (body->SuspicionFlags &
            (WKD_SEC_SUSPICION_TRANSACTED | WKD_SEC_SUSPICION_DELETED |
             WKD_SEC_SUSPICION_EXECUTE_ANONYMOUS)) {
            event->Confidence = 700;
        }
        break;
    default:
        UtHeapFree(event);
        return STATUS_INVALID_PARAMETER;
    }

    payload = (PEVENT_PAYLOAD_SECTION_CREATE)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));
    payload->SourceProcessId = Message->Header.SourceProcessId;
    payload->TargetProcessId = Message->Header.TargetProcessId;
    payload->ThreadId = body->ThreadId;
    payload->SectionObject = body->SectionObject;
    payload->MaximumSize = body->MaximumSize;
    payload->SectionPageProtection = body->SectionPageProtection;
    payload->AllocationAttributes = body->AllocationAttributes;
    payload->SectionType = body->SectionType;
    payload->IsAnonymous = body->IsAnonymous;
    payload->SuspicionFlags = body->SuspicionFlags;
    payload->SuspicionScore = body->SuspicionScore;
    payload->Timestamp = body->Timestamp;

    *Event = event;
    return STATUS_SUCCESS;
}

//
// 令牌操作 syscall 解析器（PrivilegeMonitor 迁移 2026-08-06）
// 消息 → WkdEvent_TokenAdjustPrivileges / TokenDuplicate / TokenSetInformation
//   / TokenImpersonate。
//
// 从 WKD_MSG_BODY_SYSCALL.ParameterBase 按约定布局提取:
//   [0]=TokenHandle, [1]=DesiredAccess/InfoClass(Duplicate/SetInfo 按 OpType),
//   [4]=TokenType(Duplicate 第 5 参)。
// TargetProcessId 取 WKD_MESSAGE_HEADER.TargetProcessId（驱动回填：非模拟类
//   回退源进程, Impersonate=被模拟线程所属进程）。
// 数据源状态: 驱动 SyscallHijack.c 已接线 4 个 case（消息 0x100C-0x100F）。
// 消费: IoaObserve 阶段4.9b 触发 WpaCheckForEscalation（见 IoaEngine.c）。
// OpType/TokenType/AccessMask/InfoClass 为死代码字段（当前不消费, 供后续深化）。
//
static
NTSTATUS
NtfpParseTokenOp(
    _In_  PWKD_MESSAGE       Message,
    _Out_ PWKD_EVENT_HEADER* Event
    )
{
    PWKD_EVENT_HEADER       event;
    PEVENT_PAYLOAD_TOKEN_OP   payload;
    PWKD_MSG_BODY_SYSCALL   body;
    ULONG                   totalSize;

    body = (PWKD_MSG_BODY_SYSCALL)Message->Body;

    totalSize = sizeof(WKD_EVENT_HEADER) + sizeof(EVENT_PAYLOAD_TOKEN_OP);
    event = (PWKD_EVENT_HEADER)UtHeapAlloc(totalSize);
    if (!event) return STATUS_NO_MEMORY;

    CoCreateGuid(&event->EventId);
    event->Class = DefEventClass_IOA;
    event->SchemaVersion = 1;
    event->Timestamp = Message->Header.Timestamp;
    GetSystemTimeAsFileTime((PFILETIME)&event->IngestTime);
    event->Confidence = 300;
    event->Severity = DefThreatSeverity_None;
    event->PayloadSize = sizeof(EVENT_PAYLOAD_TOKEN_OP);

    payload = (PEVENT_PAYLOAD_TOKEN_OP)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));
    RtlZeroMemory(payload, sizeof(EVENT_PAYLOAD_TOKEN_OP));
    payload->SourceProcessId = Message->Header.SourceProcessId;
    payload->TargetProcessId = Message->Header.TargetProcessId;
    if (body->ParameterNumber >= 1) {
        payload->TokenHandle = (HANDLE)body->ParameterBase[0];
    }

    switch (Message->Header.Type) {
    case WkdMessage_SyscallAdjustPrivileges:
        event->Type = WkdEvent_TokenAdjustPrivileges;
        payload->OpType = 0;
        event->Confidence = 600;
        event->Severity = DefThreatSeverity_Low;
        break;
    case WkdMessage_SyscallDuplicateToken:
        event->Type = WkdEvent_TokenDuplicate;
        payload->OpType = 1;
        if (body->ParameterNumber >= 5) payload->TokenType = (ULONG)body->ParameterBase[4];
        if (body->ParameterNumber >= 2) payload->AccessMask = (ULONG)body->ParameterBase[1];
        event->Confidence = 500;
        event->Severity = DefThreatSeverity_Low;
        break;
    case WkdMessage_SyscallSetInformationToken:
        event->Type = WkdEvent_TokenSetInformation;
        payload->OpType = 2;
        if (body->ParameterNumber >= 2) payload->InfoClass = (ULONG)body->ParameterBase[1];
        event->Confidence = 500;
        break;
    case WkdMessage_SyscallImpersonateThread:
        event->Type = WkdEvent_TokenImpersonate;
        payload->OpType = 3;
        event->Confidence = 700;
        event->Severity = DefThreatSeverity_Low;
        break;
    default:
        UtHeapFree(event);
        return STATUS_INVALID_PARAMETER;
    }

    *Event = event;
    return STATUS_SUCCESS;
}

/**************************************************/
/*           文件操作事件解析                       */
/**************************************************/

/*
 * WkdMessage_FileWrite/FileRename/FileDelete → WkdEvent_FileWrite/FileRename/
 * FileDelete（FBE 迁移 2026-08）。驱动线格式 WKD_MESSAGE_BODY_FILE_EVENT
 * （扁平：UNICODE_STRING.Buffer 指向固定头之后）。解析为 EVENT_PAYLOAD_FILE_EVENT，
 * 路径以展平格式内嵌事件块（仿 ProcessCreate 展平，DefEventFree 整块释放）。
 * 前两字段 SourceProcessId/TargetProcessId 与 EVENT_PAYLOAD_SYSCALL 布局一致，
 * 供 IoaObserve 阶段1 文件事件 case 解析节点（单进程事件 Target=同源）。
 */
static NTSTATUS
NtfpParseFileEvent(_In_ PWKD_MESSAGE Message, _Out_ PWKD_EVENT_HEADER* Event)
{
    PWKD_EVENT_HEADER        event;
    PEVENT_PAYLOAD_FILE_EVENT  payload;
    PWKD_MESSAGE_BODY_FILE_EVENT body;
    ULONG                    totalSize;

    if (Message->Header.BodySize < sizeof(WKD_MESSAGE_BODY_FILE_EVENT)) {
        return STATUS_INVALID_PARAMETER;
    }

    body = (PWKD_MESSAGE_BODY_FILE_EVENT)Message->Body;

    /* 嵌入式扁平化 (2026-08-25): 数据区紧随载荷, 不再内嵌 UNICODE_STRING 结构 */
    totalSize = sizeof(WKD_EVENT_HEADER) + sizeof(EVENT_PAYLOAD_FILE_EVENT)
                + body->FilePath.Length;
    event = (PWKD_EVENT_HEADER)UtHeapAlloc(totalSize);
    if (!event) return STATUS_NO_MEMORY;

    CoCreateGuid(&event->EventId);
    event->Class = DefEventClass_IOA;
    switch (Message->Header.Type) {
    case WkdMessage_FileCreate:
        event->Type = WkdEvent_FileCreate;
        break;
    case WkdMessage_FileRename:
        event->Type = WkdEvent_FileRename;
        break;
    case WkdMessage_FileDelete:
        event->Type = WkdEvent_FileDelete;
        break;
    case WkdMessage_FileShadowCopyDelete:
        event->Type = WkdEvent_FileShadowCopyDelete;
        break;
    default:
        event->Type = WkdEvent_FileWrite;
        break;
    }
    event->SchemaVersion = 1;
    event->Timestamp = Message->Header.Timestamp;
    GetSystemTimeAsFileTime((PFILETIME)&event->IngestTime);
    event->Severity = DefThreatSeverity_None;
    event->PayloadSize = totalSize - (ULONG)sizeof(WKD_EVENT_HEADER);   /* 含数据区 (2026-08-25 扁平化约定) */

    payload = (PEVENT_PAYLOAD_FILE_EVENT)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));
    payload->SourceProcessId = body->ProcessId;
    payload->TargetProcessId = body->ProcessId;   /* 单进程事件 */
    payload->OperationType = body->OperationType;
    payload->FileSize = body->FileSize;
    payload->WriteOffset = body->WriteOffset;
    payload->BytesWritten = body->BytesWritten;
    payload->FileId = body->FileId;
    payload->FileEntropy = body->FileEntropy;
    payload->Flags = body->Flags;
    payload->Timestamp = body->Timestamp;
    payload->FilePath.Length = (USHORT)body->FilePath.Length;
    payload->FilePath.MaximumLength = (USHORT)body->FilePath.Length;
    payload->FilePath.Buffer = body->FilePath.Length
                               ? (PWCHAR)(payload + 1) : NULL;
    if (payload->FilePath.Buffer) {
        RtlCopyMemory(payload->FilePath.Buffer,
                      body->FilePath.Buffer, body->FilePath.Length);
    }

    *Event = event;
    return STATUS_SUCCESS;
}

/**************************************************/
/*           命名管道创建事件解析                    */
/**************************************************/

/*
 * WkdMessage_NamedPipeCreate → WkdEvent_NamedPipeCreate（NamedPipeMonitor 迁移
 * 2026-08）。驱动线格式 WKD_MESSAGE_BODY_NAMED_PIPE（扁平：UNICODE_STRING.Buffer
 * 指向固定头之后）。解析为 EVENT_PAYLOAD_NAMED_PIPE，管道名以展平格式内嵌事件块
 * （仿文件事件，DefEventFree 整块释放）。
 * 前两字段 SourceProcessId/TargetProcessId 与 EVENT_PAYLOAD_SYSCALL 布局一致，
 * 供 IoaObserve 阶段1 单进程事件 case 解析节点（单进程事件 Target=同源）。
 */
static NTSTATUS
NtfpParseNamedPipe(_In_ PWKD_MESSAGE Message, _Out_ PWKD_EVENT_HEADER* Event)
{
    PWKD_EVENT_HEADER        event;
    PEVENT_PAYLOAD_NAMED_PIPE  payload;
    PWKD_MESSAGE_BODY_NAMED_PIPE body;
    ULONG                    totalSize;

    if (Message->Header.BodySize < sizeof(WKD_MESSAGE_BODY_NAMED_PIPE)) {
        return STATUS_INVALID_PARAMETER;
    }

    body = (PWKD_MESSAGE_BODY_NAMED_PIPE)Message->Body;

    /* 嵌入式扁平化 (2026-08-25): 数据区紧随载荷 */
    totalSize = sizeof(WKD_EVENT_HEADER) + sizeof(EVENT_PAYLOAD_NAMED_PIPE)
                + body->PipeName.Length;
    event = (PWKD_EVENT_HEADER)UtHeapAlloc(totalSize);
    if (!event) return STATUS_NO_MEMORY;

    CoCreateGuid(&event->EventId);
    event->Class = DefEventClass_IOA;
    event->Type = WkdEvent_NamedPipeCreate;
    event->SchemaVersion = 1;
    event->Timestamp = Message->Header.Timestamp;
    GetSystemTimeAsFileTime((PFILETIME)&event->IngestTime);
    event->Severity = DefThreatSeverity_None;
    event->PayloadSize = totalSize - (ULONG)sizeof(WKD_EVENT_HEADER);   /* 含数据区 */

    payload = (PEVENT_PAYLOAD_NAMED_PIPE)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));
    payload->SourceProcessId = body->ProcessId;
    payload->TargetProcessId = body->ProcessId;   /* 单进程事件 */
    payload->Classification = body->Classification;
    payload->ThreatLevel = body->ThreatLevel;
    payload->ThreatScore = body->ThreatScore;
    payload->Flags = body->Flags;
    MultiByteToWideChar(CP_ACP, 0, body->CreatorImageName, -1,
                        payload->CreatorImageName, 16);
    payload->PipeName.Length = (USHORT)body->PipeName.Length;
    payload->PipeName.MaximumLength = (USHORT)body->PipeName.Length;
    payload->PipeName.Buffer = body->PipeName.Length
                               ? (PWCHAR)(payload + 1) : NULL;
    if (payload->PipeName.Buffer) {
        RtlCopyMemory(payload->PipeName.Buffer,
                      body->PipeName.Buffer, body->PipeName.Length);
    }

    *Event = event;
    return STATUS_SUCCESS;
}

/**************************************************/
/*           镜像加载事件解析                        */
/**************************************************/

/*
 * WkdMessage_ImageLoaded → WkdEvent_ImageLoad（2026-08-09 镜像职责收敛）。
 * 驱动线格式 WKD_MESSAGE_BODY_IMAGE_LOAD v2（扁平：UNICODE_STRING.Buffer 指向
 * 固定头之后，含 SignatureStatus/ImageIndicators/PE 摘要，无熵/哈希字段）。
 * 解析为 EVENT_PAYLOAD_IMAGE_LOAD，路径以展平格式内嵌事件块（DefEventFree 整块释放）。
 * 前两字段 SourceProcessId/TargetProcessId 与 EVENT_PAYLOAD_SYSCALL 布局一致，
 * 供 IoaObserve 阶段1 单进程事件 case 解析节点（单进程事件 Target=同源）。
 * Confidence 按指示器/签名设定：无背衬/EP 越界强信号高置信，可疑指示器中，签名有效低。
 */
static NTSTATUS
NtfpParseImageLoad(
    _In_ const PWKD_MESSAGE Message,
    _Out_ PWKD_EVENT_HEADER* Event
    )
{
    PWKD_EVENT_HEADER event = NULL;
    PWKD_MESSAGE_BODY_IMAGE_LOAD body;
    PEVENT_PAYLOAD_IMAGE_LOAD  payload;
    SIZE_T totalSize;
    ULONG confidence = 400;

    if (!Message ||
        Message->Header.BodySize < sizeof(WKD_MESSAGE_BODY_IMAGE_LOAD)) {
        return STATUS_INVALID_PARAMETER;
    }

    body = (PWKD_MESSAGE_BODY_IMAGE_LOAD)Message->Body;

    /* ---- Step 1: 创建 Event 实例 ----
     * [!!] 三元表达式必须括号分组 — 无括号时 '+' 优先级高于 '?:',
     * 条件退化为常量真, totalSize 仅剩字符串区 → 写入 header/payload
     * 大规模越界踩堆 (2026-08-25 堆损坏事故根因)。 */
    totalSize = sizeof(WKD_EVENT_HEADER) + sizeof(EVENT_PAYLOAD_IMAGE_LOAD)
        + (CoCheckUnicodeStringValidity(&body->ImagePath)
           ? body->ImagePath.Length + sizeof(WCHAR) : 0);
    event = (PWKD_EVENT_HEADER)UtHeapAlloc(totalSize);
    if (!event) return STATUS_NO_MEMORY;
    RtlZeroMemory(event, totalSize);

    /* ---- Step 2: 解析并复制字段 ---- */
    CoCreateGuid(&event->EventId);
    event->Class = DefEventClass_IOA;
    event->Type = WkdEvent_ImageLoad;
    event->SchemaVersion = 1;
    event->Timestamp = Message->Header.Timestamp;
    GetSystemTimeAsFileTime((PFILETIME)&event->IngestTime);
    event->Severity = DefThreatSeverity_None;
    event->PayloadSize = (ULONG)totalSize - (ULONG)sizeof(WKD_EVENT_HEADER);   /* 含数据区 */

    if (body->ImageIndicators & (WKD_IMG_IND_UNBACKED | WKD_IMG_IND_ENTRYPOINT_OUTSIDE)) {
        confidence = 700;    /* 反射加载/镂空强信号 */
    } else if (body->ImageIndicators & (WKD_IMG_IND_MASQUERADING_DLL |
                                        WKD_IMG_IND_DOUBLE_EXTENSION |
                                        WKD_IMG_IND_TYPOSQUATTING |
                                        WKD_IMG_IND_NETWORK_PATH)) {
        confidence = 550;
    } else if (body->SignatureStatus == IMG_SIGNATURE_VALID) {
        confidence = 300;
    }
    event->Confidence = confidence;

    payload = (PEVENT_PAYLOAD_IMAGE_LOAD)(event + 1);
    payload->SourceProcessId = Message->Header.SourceProcessId;
    payload->TargetProcessId = Message->Header.TargetProcessId;
    if (payload->TargetProcessId > 0x2000)
        printf("");
    payload->ImageBase = body->ImageBase;
    payload->ImageSize = body->ImageSize;
    payload->ImageType = body->ImageType;
    payload->ImageIndicators = body->ImageIndicators;
    payload->SignatureStatus = body->SignatureStatus;
    payload->Reserved[0] = body->Reserved[0];
    payload->Reserved[1] = body->Reserved[1];
    payload->Reserved[2] = body->Reserved[2];
   
    if (CoCheckUnicodeStringValidity(&body->ImagePath)) {
        payload->ImagePath.Length = body->ImagePath.Length;
        payload->ImagePath.MaximumLength = body->ImagePath.Length + sizeof(WCHAR);
        payload->ImagePath.Buffer = (PWSTR)(payload + 1);
        /* 修正 body->ImagePath.Buffer 指针指向真实地址 */
        RtlCopyMemory(payload->ImagePath.Buffer,
            body + 1, body->ImagePath.Length);
        payload->ImagePath.Buffer[body->ImagePath.Length / sizeof(WCHAR)] = L'\0';
    }

    *Event = event;
    return STATUS_SUCCESS;
}

NTSTATUS
NtfWkdMessageParse(
    _In_ const PWKD_SCHEMA_TABLE Table,
    _In_ const PWKD_MESSAGE Message,
    _Out_ const PWKD_EVENT_HEADER* Event
    )
{
    WKD_EVENT_TYPE eventType;

    switch (Message->Header.Type) {
    case WkdMessage_ProcessCreated:
    case WkdMessage_ProcessSnapshot:
        eventType = WkdEvent_ProcessCreate;
        break;
    case WkdMessage_ProcessExited:
        eventType = WkdEvent_ProcessExit;
        break;
    case WkdMessage_ThreadCreated:
        eventType = WkdEvent_ThreadCreate;
        break;
    case WkdMessage_ThreadExited:
        eventType = WkdEvent_ThreadExit;
        break;
    case WkdMessage_SyscallOpenProcess:
    case WkdMessage_SyscallAllocateMemory:
    case WkdMessage_SyscallReadMemory:
    case WkdMessage_SyscallWriteMemory:
        eventType = WkdEvent_SyscallAggregated;
        break;
    case WkdMessage_SyscallQueueApc:
        eventType = WkdEvent_QueueApc;
        break;
    case WkdMessage_SyscallSetContextThread:
        eventType = WkdEvent_SetThreadContext;
        break;
    case WkdMessage_SyscallSuspendThread:
        eventType = WkdEvent_ThreadSuspend;
        break;
    case WkdMessage_SyscallResumeThread:
        eventType = WkdEvent_ThreadResume;
        break;
    case WkdMessage_SyscallAdjustPrivileges:
        eventType = WkdEvent_TokenAdjustPrivileges;
        break;
    case WkdMessage_SyscallDuplicateToken:
        eventType = WkdEvent_TokenDuplicate;
        break;
    case WkdMessage_SyscallSetInformationToken:
        eventType = WkdEvent_TokenSetInformation;
        break;
    case WkdMessage_SyscallImpersonateThread:
        eventType = WkdEvent_TokenImpersonate;
        break;
    case WkdMessage_AmsiBypassDetected:
        eventType = WkdEvent_AmsiBypass;
        break;
    case WkdMessage_FileCreate:
        eventType = WkdEvent_FileCreate;
        break;
    case WkdMessage_FileWrite:
        eventType = WkdEvent_FileWrite;
        break;
    case WkdMessage_FileRename:
        eventType = WkdEvent_FileRename;
        break;
    case WkdMessage_FileDelete:
        eventType = WkdEvent_FileDelete;
        break;
    case WkdMessage_FileShadowCopyDelete:
        eventType = WkdEvent_FileShadowCopyDelete;
        break;
    case WkdMessage_NamedPipeCreate:
        eventType = WkdEvent_NamedPipeCreate;
        break;
    case WkdMessage_ImageLoaded:
        eventType = WkdEvent_ImageLoad;   /* 2026-08-09 镜像职责收敛：0x3005 接入 */
        break;
    case WkdMessage_SyscallMapSection:
    case WkdMessage_SectionMap:
        eventType = WkdEvent_MapViewOfSection;   /* PreAcquireSection 迁移 2026-08 */
        break;
    case WkdMessage_SyscallUnmapSection:
        eventType = WkdEvent_UnmapViewOfSection; /* PreAcquireSection 迁移 2026-08 */
        break;
    case WkdMessage_SyscallCreateSection:
        eventType = WkdEvent_SectionCreate;      /* SectionTracker 迁移 2026-08 */
        break;
    default: return STATUS_NOT_SUPPORTED;
    }

    for (ULONG i = 0; i < Table->Count; i++) {
        if (Table->Entries[i].Type == eventType)
            return Table->Entries[i].ParseWkdMessage(Message, Event);
    }
    return STATUS_NOT_FOUND;
}

VOID DefEventFree(PWKD_EVENT_HEADER Event)
{
    /* 载荷字符串为嵌入式扁平布局 (2026-08-25): UNICODE_STRING 内嵌于载荷,
     * Buffer 指向同块数据区, 无独立堆副本 — 整块一次释放。 */
    if (Event) {
        /* 调试期防护 (2026-08-25): free 前校验进程默认堆块完整性 —
         * 堆损坏在此提前暴露并打印事件指纹, 而非等 HeapFree 报损;
         * 定位后删除。 */
        if (!HeapValidate(GetProcessHeap(), 0, Event)) {
            printf("[DefEventFree] !!! HEAP CORRUPTION on event block: "
                   "Type=0x%X PayloadSize=%lu SchemaVersion=%u\n",
                   Event->Type, Event->PayloadSize, Event->SchemaVersion);
            DebugBreak();
        }
        UtHeapFree(Event);
    }
}

/**************************************************/
/*               Schema 表管理                      */
/**************************************************/

NTSTATUS WkdEvent_InitializeSchema(VOID)
{
    RtlZeroMemory(&g_DefSchemaTable, sizeof(g_DefSchemaTable));
    InitializeCriticalSection(&g_DefSchemaTable.Lock);

    WKD_EVENT_SCHEMA_ENTRY e;
    RtlZeroMemory(&e, sizeof(e));

    e.Type = WkdEvent_ProcessCreate; e.Version = 1;
    e.ParseWkdMessage = NtfpEventParseProcessCreate; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_ProcessExit; e.Version = 1;
    e.ParseWkdMessage = NtfpParseProcessExit; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_SyscallAggregated; e.Version = 1;
    e.ParseWkdMessage = DefEventParseSyscall; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_ThreadCreate; e.Version = 1;
    e.ParseWkdMessage = NtfpParseThreadCreate; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_ThreadExit; e.Version = 1;
    e.ParseWkdMessage = NtfpParseThreadExit; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_QueueApc; e.Version = 1;
    e.ParseWkdMessage = NtfpParseQueueApc; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_SetThreadContext; e.Version = 1;
    e.ParseWkdMessage = NtfpParseThreadOp; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_ThreadSuspend; e.Version = 1;
    e.ParseWkdMessage = NtfpParseThreadOp; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_ThreadResume; e.Version = 1;
    e.ParseWkdMessage = NtfpParseThreadOp; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_TokenAdjustPrivileges; e.Version = 1;
    e.ParseWkdMessage = NtfpParseTokenOp; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_TokenDuplicate; e.Version = 1;
    e.ParseWkdMessage = NtfpParseTokenOp; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_TokenSetInformation; e.Version = 1;
    e.ParseWkdMessage = NtfpParseTokenOp; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_TokenImpersonate; e.Version = 1;
    e.ParseWkdMessage = NtfpParseTokenOp; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_AmsiBypass; e.Version = 1;
    e.ParseWkdMessage = NtfpParseAmsiBypass; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_FileCreate; e.Version = 1;
    e.ParseWkdMessage = NtfpParseFileEvent; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_FileWrite; e.Version = 1;
    e.ParseWkdMessage = NtfpParseFileEvent; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_FileRename; e.Version = 1;
    e.ParseWkdMessage = NtfpParseFileEvent; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_FileDelete; e.Version = 1;
    e.ParseWkdMessage = NtfpParseFileEvent; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    /* 卷影副本删除（T1490，PreSetInfo 迁移 2026-08 补漏）：驱动 0x1306 解析后
     * 不再因 schema 未注册被丢弃，可达 IoaRansomware_UpdateScore 卷影分支 +40。 */
    e.Type = WkdEvent_FileShadowCopyDelete; e.Version = 1;
    e.ParseWkdMessage = NtfpParseFileEvent; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_NamedPipeCreate; e.Version = 1;
    e.ParseWkdMessage = NtfpParseNamedPipe; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    /* 镜像加载（2026-08-09 镜像职责收敛）：驱动 0x3005 上送，无签名或非白名单
     * 镜像。此前因 schema 未注册 + NtfWkdMessageParse 无 case 被丢弃。 */
    e.Type = WkdEvent_ImageLoad; e.Version = 1;
    e.ParseWkdMessage = NtfpParseImageLoad; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    /* 区段映射（PreAcquireSection 迁移 2026-08）：文件轨(0x1308)与 syscall 轨
     * (0x1006/0x1010) 共用 NtfpParseSectionOp，闭合 agent 侧 0x6005/0x6006 消费链。 */
    e.Type = WkdEvent_MapViewOfSection; e.Version = 1;
    e.ParseWkdMessage = NtfpParseSectionOp; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    e.Type = WkdEvent_UnmapViewOfSection; e.Version = 1;
    e.ParseWkdMessage = NtfpParseSectionOp; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    /* Section 创建（SectionTracker 迁移 2026-08）：驱动 0x1011 NtCreateSection
     * Exit 检测上送。SectionObject 为共享 Section 聚合表键。 */
    e.Type = WkdEvent_SectionCreate; e.Version = 1;
    e.ParseWkdMessage = NtfpParseSectionCreate; e.FreeEvent = DefEventFree;
    g_DefSchemaTable.Entries[g_DefSchemaTable.Count++] = e;

    printf("[EventSystem] Schema initialized: %lu parsers\n", g_DefSchemaTable.Count);
    return STATUS_SUCCESS;
}

VOID WkdEvent_CleanupSchema(VOID)
{
    DeleteCriticalSection(&g_DefSchemaTable.Lock);
    RtlZeroMemory(&g_DefSchemaTable, sizeof(g_DefSchemaTable));
}

_Use_decl_annotations_
NTSTATUS
NtfExtractEventPids(
    _In_ const PWKD_EVENT_HEADER Event,
    _Out_ PHANDLE SourceProcessId,
    _Out_ PHANDLE TargetProcessId
    )
/*++
Routine Description:
    从事件 payload 提取 (源,目标) PID 二元组, 供进程对维度分析使用。
    统一 ProcessCreate/线程/文件/镜像/命名管道/syscall 各类型的 PID 字段
    布局 (均落在 WKD_EVENT_HEADER 之后固定偏移), 使 OrcpWkdMessageDispatcher
    (switch 前统一建 pair) 与 IoaObserve (阶段1 节点反查) 共用同一套提取
    逻辑, 避免两处维护。

    进程创建为单进程事件 (Target=Source=子进程 PID), 由此产出自环对
    <childPid, childPid>; 文件/镜像/命名管道亦为单进程事件 (Source=Target);
    syscall/线程为跨进程事件 (Source≠Target)。

Arguments:
    Event  — 已解析事件头。
    SrcPid — [输出] 源进程 PID。
    TgtPid — [输出] 目标进程 PID。
--*/
{
    if (!Event || !SourceProcessId || !TargetProcessId) {
        return STATUS_INVALID_PARAMETER;
    }
    *SourceProcessId = 0;
    *TargetProcessId = 0;

    switch (Event->Type) {
    case WkdEvent_ProcessCreate: {
        PEVENT_PAYLOAD_PROCESS_CREATE payload =
            (PEVENT_PAYLOAD_PROCESS_CREATE)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
        *SourceProcessId = payload->ParentProcessId;
        *TargetProcessId = payload->ProcessId;
        break;
    }
    case WkdEvent_ProcessExit: {
        PEVENT_PAYLOAD_PROCESS_EXIT payload =
            (PEVENT_PAYLOAD_PROCESS_EXIT)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
        *SourceProcessId = payload->ParentProcessId;
        *TargetProcessId = payload->ProcessId;
        break;
    }
    case WkdEvent_ThreadCreate:
    case WkdEvent_RemoteThreadCreate: {
        PEVENT_PAYLOAD_THREAD_CREATE payload =
            (PEVENT_PAYLOAD_THREAD_CREATE)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
        *SourceProcessId = payload->CreatorProcessId;
        *TargetProcessId = payload->ProcessId;
        break;
    }
    case WkdEvent_ThreadExit: {
        PEVENT_PAYLOAD_THREAD_EXIT payload =
            (PEVENT_PAYLOAD_THREAD_EXIT)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
        *SourceProcessId = payload->SourceProcessId;
        *TargetProcessId = payload->TargetProcessId;
        break;
    }
    case WkdEvent_FileWrite:
    case WkdEvent_FileRename:
    case WkdEvent_FileDelete: {
        PEVENT_PAYLOAD_FILE_EVENT payload =
            (PEVENT_PAYLOAD_FILE_EVENT)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
        *SourceProcessId = (ULONG)(ULONG_PTR)payload->SourceProcessId;
        *TargetProcessId = (ULONG)(ULONG_PTR)payload->TargetProcessId;
        break;
    }
    case WkdEvent_NamedPipeCreate: {
        PEVENT_PAYLOAD_NAMED_PIPE payload =
            (PEVENT_PAYLOAD_NAMED_PIPE)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
        *SourceProcessId = (ULONG)(ULONG_PTR)payload->SourceProcessId;
        *TargetProcessId = (ULONG)(ULONG_PTR)payload->TargetProcessId;
        break;
    }
    case WkdEvent_ImageLoad: {
        PEVENT_PAYLOAD_IMAGE_LOAD payload =
            (PEVENT_PAYLOAD_IMAGE_LOAD)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
        *SourceProcessId = (ULONG)(ULONG_PTR)payload->SourceProcessId;
        *TargetProcessId = (ULONG)(ULONG_PTR)payload->TargetProcessId;
        break;
    }
    default:
        //PEVENT_PAYLOAD_SYSCALL payload =
        //    (PEVENT_PAYLOAD_SYSCALL)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
        //*SourceProcessId = (ULONG)(ULONG_PTR)payload->SourceProcessId;
        //*TargetProcessId = (ULONG)(ULONG_PTR)payload->TargetProcessId;
        //break;
        return STATUS_NOT_SUPPORTED;
    }

    return STATUS_SUCCESS;
}