#include "process_manager.h"
#include "Notification/AlpcService.h"
#include "Orchestrator/VerdictEngine.h"        /* VerdictEngine_OnProcessTerminate: 活跃威胁清理 */
#include "ScanManager.h"                      /* 病毒扫描编排层 (SS ScanEngine 迁移) */
#include "log_manager.h"
#include "Notification/NotificationService.h"  /* .c 文件包含安全，不会造成头文件循环展开 */
#include "tools.h"
#include "Memory/MemoryScan.h"                 /* 机制 B 进程内存 YARA（回路 B） */
#include "IOC/IocProcessEnrich.h"             /* IpeCategorizeProcess/IpeCollectUserContext/IpeRecordProcessExit */
#include "Process/ProcessSnapshot.h"          /* 进程域快照兜底 (统一重构 2026-08-15) */
#include "Process/ProcessTree.h"              /* 进程域树 WkdProcessTree (统一重构 2026-08-15) */
#include "Process/ProcessModule.h"            /* 进程域模块表 (统一重构 2026-08-15) */

/* 处置引擎：宽字符与 Nt* 函数依赖 */
#include <wchar.h>
#include <wctype.h>
#include <tlhelp32.h>                         /* ProcessSnapshot:Toolhelp 枚举 */
#include <stdlib.h>                           /* ProcessSnapshot:realloc */

#pragma comment(lib, "ntdll.lib")

/* 处置引擎 static 函数前向声明（进程监控分区定义在处置引擎之前，调用需先声明；
 * 声明与 process_manager.c 处置引擎处实现完全一致） */
static NTSTATUS WkGetProtectionInfoInternal(_In_ ULONG Pid, _Out_ PWKD_PROCESS_PROTECTION_INFO Out);

/* 处置引擎持久化清理（服务/计划任务/注册表）所需 */
#include <winsvc.h>
#include <taskschd.h>
#include <oleauto.h>   /* VARIANT/BSTR/SysAllocString（taskschd COM，C 兼容；不用 comdef.h——C++ 专属） */

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// 声明全局Agent上下文
extern WKDEFENDER_AGENT WkDefenderAgent;

/* 回路 B：镜像加载事件触发机制 B 内存 YARA。fire-and-forget 线程，避免阻塞
 * 消息队列 handler（内存扫描需 ReadProcessMemory，可能耗时）。 */
/*
 * [已删除] 旧镜像内存 YARA 消费（MS_SCAN_THREAD_PARAM / MsScanThreadProc /
 * MsScanOnImageLoad）—— 2026-08-09 镜像职责收敛：WkdMessage_ImageLoaded 消费
 * 迁至主编排链（EventParser NtfpParseImageLoad + Engine.c 阶段4b ScanFileDirect
 * 全量校验）。原 fire-and-forget 内存 YARA（MsScanWithYARA）归 Memory 子系统
 * 独立接线（MsScanOnImageLoad 语义），此处不再保留 static 死代码。
 */

// 全局进程管理器
PROCESS_MANAGER g_ProcessManager = {
    .Initialized = FALSE
};

/* ──────────────────────────────────────────────── */
/*   ProcessMonitor 迁移:分类/富化/谱系              */
/*   （快照兜底已迁至 Process/ProcessSnapshot.c）    */
/*   对齐 ShadowStrike ProcessMonitor.cpp            */
/*   (2026-08-04,按功能融合,复用 IocProcessEnrich)   */
/* ──────────────────────────────────────────────── */


/* 分类 → 展示字符串（供 UI 进程列表/详情，替代原模拟 "Process description"） */
static PCSTR
ProcessMonitor_CategoryString(
    _In_ ULONG Category
    )
{
    switch (Category) {
    case WkdPcSystemCritical:   return "SystemCritical";
    case WkdPcSystemCore:       return "SystemCore";
    case WkdPcSystemService:    return "SystemService";
    case WkdPcSecuritySoftware: return "SecuritySoftware";
    case WkdPcEndUserApp:       return "EndUserApp";
    case WkdPcInternetBrowser:  return "Browser";
    case WkdPcOffice:           return "Office";
    case WkdPcScriptHost:       return "ScriptHost";
    case WkdPcSystemUtility:    return "SystemUtility";
    case WkdPcLOLBin:           return "LOLBin";
    case WkdPcInstaller:        return "Installer";
    case WkdPcDeveloper:        return "Developer";
    case WkdPcNetworkUtility:   return "NetworkUtility";
    default:                    return "Unknown";
    }
}

/* 信任等级展示字符串（分类 + 谱系 + 威胁等级综合，替代原模拟 "Unknown"） */
static PCSTR
ProcessMonitor_TrustLevelString(
    _In_ PWKD_PROCESS Node
    )
{
    ULONG cat;

    if (Node == NULL) return "Unknown";

    if (Node->IsProtectedProcess) return "Protected";
    if (Node->IsPpidSpoofed)      return "Suspicious";
    if (Node->IsOrphan)           return "Suspicious";

    cat = Node->ProcessCategory;
    if (cat == (ULONG)WkdPcSystemCritical || cat == (ULONG)WkdPcSystemCore ||
        cat == (ULONG)WkdPcSystemService || cat == (ULONG)WkdPcSecuritySoftware) {
        return "Trusted";
    }
    if (cat == (ULONG)WkdPcLOLBin || cat == (ULONG)WkdPcScriptHost ||
        cat == (ULONG)WkdPcSystemUtility) {
        return "Suspicious";
    }
    if (Node->ThreatLevel >= THREAT_LEVEL_HIGH)  return "Malicious";
    if (Node->ThreatLevel >= THREAT_LEVEL_MEDIUM) return "Threat";
    return "Normal";
}

/**************************************************/
/*         进程列表请求处理（适配新 ALPC 类型）      */
/**************************************************/

static NTSTATUS
HandleGetProcessListRequest(
    _In_ PWKD_ALPC_SERVER   AlpcServer,
    _In_ PWKD_MESSAGE       RequestMsg
    )
/*++
Routine Description:
    处理 UI 发来的进程列表请求，调用 ProcessManager_GetProcessList
    获取列表后通过 ALPC 发回响应。

Arguments:
    AlpcServer - ALPC 服务器实例。
    RecvMsg    - 收到的请求消息（未使用，保留签名兼容）。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS        status;
    PPROCESS_INFO   processList = NULL;
    ULONG           processCount = 0;
    ULONG           totalSize;
    PWKD_ALPC_MESSAGE   respMsg;
    PUCHAR          cursor;

    UNREFERENCED_PARAMETER(RequestMsg);

    if (!AlpcServer) {
        return STATUS_INVALID_PARAMETER;
    }

    status = ProcessManager_GetProcessList(&processList, &processCount);
    if (!NT_SUCCESS(status)) {
        printf("[ProcessManager] GetProcessList failed: 0x%X\n", status);
        return status;
    }

    /* 构造响应消息：WKD_ALPC_MESSAGE 头部 + 进程数据 */
    totalSize = sizeof(WKD_ALPC_MESSAGE) + processCount * sizeof(PROCESS_INFO);

    respMsg = (PWKD_ALPC_MESSAGE)UtHeapAlloc(totalSize);
    if (!respMsg) {
        ProcessManager_FreeProcessList(processList);
        return STATUS_NO_MEMORY;
    }

    respMsg->Header.u1.s1.DataLength = (USHORT)(totalSize - sizeof(PORT_MESSAGE));
    respMsg->Header.u1.s1.TotalLength = (USHORT)totalSize;
    respMsg->MessageType = WkdAlpcMsg_GetProcessListResp;
    respMsg->ItemCount = (USHORT)processCount;

    /* 复制进程数据 */
    cursor = (PUCHAR)respMsg + sizeof(WKD_ALPC_MESSAGE);
    memcpy(cursor, processList, processCount * sizeof(PROCESS_INFO));

    /* 通过 ALPC 发送响应 */
    //status = AlpcSendMessage(AlpcServer,
    //                            AlpcServer->AcceptedPorts[WkdAlpcConnectionUi],
    //                            respMsg,
    //                            0);

    UtHeapFree(respMsg);
    ProcessManager_FreeProcessList(processList);

    return status;
}

// 事件统计
static struct {
    ULONG TotalEvents;
    ULONG ProcessCreateEvents;
    ULONG ProcessExitEvents;
    ULONG ThreadCreateEvents;
    ULONG ThreadExitEvents;
    ULONG ApiCallEvents;
} g_EventStats = {0};

// 初始化进程管理模块（自注册模式）
NTSTATUS ProcessManager_InitializeService(
    _In_opt_ PWKD_ALPC_SERVER AlpcServer
    )
{
    NTSTATUS status;
    PWKD_ALPC_SERVER targetServer;

    printf("[ProcessManager] Initializing service...\n");

    // 默认使用全局 ALPC 服务器
    targetServer = AlpcServer ? AlpcServer : &WkdDefaultAlpcServer;

    // 初始化临界区
    InitializeCriticalSection(&g_ProcessManager.Lock);

    // 初始化消息队列（不启动线程，StartAllModules 阶段统一启动）
    status = NtfInitializeMessageQueueMessageQueue(&g_ProcessManager.MessageQueue, WKD_MSG_QUEUE_MAX_SIZE, ProcessManager_MessageHandler, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[ProcessManager] Failed to initialize message queue: 0x%X\n", status);
        DeleteCriticalSection(&g_ProcessManager.Lock);
        return status;
    }
    printf("ProcessManager MessageQueue MaxSize: %lu\n", g_ProcessManager.MessageQueue.MaxQueueSize);

    // 注册消息路由
    // UI → Agent: 进程列表 / 终止进程 / 病毒扫描 请求
    AlpcRegisterRoute(targetServer,
        WkdAlpcMsg_GetProcessListReq, WkdAlpcMsg_RunScanReq,
        WkdMsgQueueAlpcHandler, &g_ProcessManager.MessageQueue);

    g_ProcessManager.Initialized = TRUE;

    /* 启动周期快照兜底线程(驱动事件缺失时进程表仍有数据) */
    //status = ProcessSnapshot_Start();
    //if (!NT_SUCCESS(status)) {
    //    printf("[ProcessManager] Snapshot thread start failed: 0x%X\n", status);
    //}

    printf("[ProcessManager] Service initialized successfully\n");

    return STATUS_SUCCESS;
}

// 清理进程管理模块资源
VOID ProcessManager_Cleanup()
{
    if (g_ProcessManager.Initialized) {
        printf("[ProcessManager] Cleaning up...\n");

        // 清理消息队列
        WkdMsgQueueStopProcessing(&g_ProcessManager.MessageQueue);
        WkdMsgQueueCleanup(&g_ProcessManager.MessageQueue);

        // 清理临界区
        DeleteCriticalSection(&g_ProcessManager.Lock);

        // 停止快照兜底线程
        ProcessSnapshot_Stop();

        g_ProcessManager.Initialized = FALSE;
        printf("[ProcessManager] Cleanup completed\n");
    }
}

/* GetProcessList 枚举上下文: List 为 NULL 时仅统计存活数,
 * 否则向 List 填充并以 Capacity 兜底 (HashMap 逐桶共享锁,
 * 统计与填充两次枚举间允许弱一致)。 */
typedef struct _PM_ENUM_LIST_CTX {
    PPROCESS_INFO List;
    ULONG         Capacity;
    ULONG         Count;
} PM_ENUM_LIST_CTX, *PPM_ENUM_LIST_CTX;

/* 枚举回调: 统计/填充存活进程节点 (CoEnumerateHashMap 共享锁内调用,
 * 仅做拷贝, 不触碰节点生命周期) */
static BOOLEAN PM_EnumAliveNodesCallback(HANDLE Key, ULONG KeySize, PVOID Value, PVOID Ctx)
{
    PWKD_PROCESS n = (PWKD_PROCESS)Value;
    PPM_ENUM_LIST_CTX ctx = (PPM_ENUM_LIST_CTX)Ctx;

    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(KeySize);

    if (!n || !n->Alive) return TRUE;

    if (ctx->List) {
        if (ctx->Count >= ctx->Capacity) return FALSE;   /* 并发新增, 提前终止 */

        ctx->List[ctx->Count].ProcessId = n->ProcessId;
        if (n->ImageFileName && n->ImageFileName->Buffer)
            wcstombs_s(NULL, ctx->List[ctx->Count].Name, sizeof(ctx->List[ctx->Count].Name),
                       n->ImageFileName->Buffer, _TRUNCATE);
        else ctx->List[ctx->Count].Name[0] = '\0';
        ctx->List[ctx->Count].Name[sizeof(ctx->List[ctx->Count].Name) - 1] = '\0';

        /* 填充分类/信任等级（替代模拟数据,ProcessMonitor 迁移） */
        strncpy_s(ctx->List[ctx->Count].Description, sizeof(ctx->List[ctx->Count].Description),
                  ProcessMonitor_CategoryString(n->ProcessCategory), _TRUNCATE);
        ctx->List[ctx->Count].CpuUsage = 0.0;
        ctx->List[ctx->Count].MemoryUsageMB = 0.0;   /* MemoryUsage 字段已删除 (2026-08-15) */

        if (n->ImagePath && n->ImagePath->Buffer)
            wcstombs_s(NULL, ctx->List[ctx->Count].FilePath, sizeof(ctx->List[ctx->Count].FilePath),
                       n->ImagePath->Buffer, _TRUNCATE);
        else ctx->List[ctx->Count].FilePath[0] = '\0';
        ctx->List[ctx->Count].FilePath[sizeof(ctx->List[ctx->Count].FilePath) - 1] = '\0';

        strncpy_s(ctx->List[ctx->Count].TrustLevel, sizeof(ctx->List[ctx->Count].TrustLevel),
                  ProcessMonitor_TrustLevelString(n), _TRUNCATE);
        strcpy_s(ctx->List[ctx->Count].DigitalSignature, sizeof(ctx->List[ctx->Count].DigitalSignature), "None");

        if (n->CommandLine && n->CommandLine->Buffer)
            wcstombs_s(NULL, ctx->List[ctx->Count].CommandLine, sizeof(ctx->List[ctx->Count].CommandLine),
                       n->CommandLine->Buffer, _TRUNCATE);
        else ctx->List[ctx->Count].CommandLine[0] = '\0';
        ctx->List[ctx->Count].CommandLine[sizeof(ctx->List[ctx->Count].CommandLine) - 1] = '\0';
    }

    ctx->Count++;
    return TRUE;
}

// 获取进程列表
NTSTATUS ProcessManager_GetProcessList(
    PPROCESS_INFO* pProcessList,
    PULONG pCount
)
{
    if (!g_ProcessManager.Initialized || !pProcessList || !pCount) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;
    PPROCESS_INFO processList = NULL;
    PM_ENUM_LIST_CTX ctx;

    /* 遍历进程域树 (2026-08-24 HashMap 化: 替代 ProcessListHead 全局链)。
     * CoEnumerateHashMap 逐桶共享锁, 回调内仅拷贝。 */
    ctx.List = NULL;
    ctx.Capacity = 0;
    ctx.Count = 0;
    CoEnumerateHashMap(&WkdProcessTree.PidMap, PM_EnumAliveNodesCallback, &ctx);

    if (ctx.Count > 0) {
        // 分配内存用于存储进程信息
        processList = (PPROCESS_INFO)UtHeapAlloc(ctx.Count * sizeof(PROCESS_INFO));
        if (!processList) {
            return STATUS_NO_MEMORY;
        }

        // 第二遍枚举, 填充进程信息
        ctx.List = processList;
        ctx.Capacity = ctx.Count;
        ctx.Count = 0;
        CoEnumerateHashMap(&WkdProcessTree.PidMap, PM_EnumAliveNodesCallback, &ctx);
    }

    // 设置返回值 (以实际填充数为准, 兜底并发插入导致的容量差)
    *pCount = ctx.Count;
    *pProcessList = processList;

    return status;
}

// 获取进程详细信息（查询进程域树,ProcessMonitor 迁移）
NTSTATUS ProcessManager_GetProcessDetail(
    DWORD Pid,
    PPROCESS_INFO pProcessInfo
)
{
    PWKD_PROCESS node;
    NTSTATUS status;

    if (!g_ProcessManager.Initialized || !pProcessInfo) {
        return STATUS_INVALID_PARAMETER;
    }

    ZeroMemory(pProcessInfo, sizeof(PROCESS_INFO));
    pProcessInfo->ProcessId = Pid;

    NTSTATUS lookupStatus = PsLookupWkdProcessByStrictProcessId(&WkdProcessTree, Pid, NULL, &node);
    if (!NT_SUCCESS(lookupStatus)) {
        return STATUS_NOT_FOUND;
    }
    if (!node->Alive) {
        PsDereferenceWkdProcess(node);   /* 归还查找 pin */
        return STATUS_NOT_FOUND;
    }

    if (node->ImageFileName && node->ImageFileName->Buffer)
        wcstombs_s(NULL, pProcessInfo->Name, sizeof(pProcessInfo->Name),
                   node->ImageFileName->Buffer, _TRUNCATE);
    if (node->ImagePath && node->ImagePath->Buffer)
        wcstombs_s(NULL, pProcessInfo->FilePath, sizeof(pProcessInfo->FilePath),
                   node->ImagePath->Buffer, _TRUNCATE);
    if (node->CommandLine && node->CommandLine->Buffer)
        wcstombs_s(NULL, pProcessInfo->CommandLine, sizeof(pProcessInfo->CommandLine),
                   node->CommandLine->Buffer, _TRUNCATE);
    pProcessInfo->MemoryUsageMB = 0.0;   /* MemoryUsage 字段已删除 (2026-08-15) */

    strncpy_s(pProcessInfo->Description, sizeof(pProcessInfo->Description),
              ProcessMonitor_CategoryString(node->ProcessCategory), _TRUNCATE);
    strncpy_s(pProcessInfo->TrustLevel, sizeof(pProcessInfo->TrustLevel),
              ProcessMonitor_TrustLevelString(node), _TRUNCATE);

    PsDereferenceWkdProcess(node);   /* 归还查找 pin */
    return STATUS_SUCCESS;
}

// 获取进程模块列表
NTSTATUS ProcessManager_GetProcessModules(
    DWORD Pid,
    PPROCESS_MODULE_INFO* pModuleList,
    PULONG pCount
)
{
    PWKD_PROCESS node;
    NTSTATUS status;
    PPROCESS_MODULE_INFO list;
    PLIST_ENTRY e;
    ULONG count;
    ULONG index = 0;

    if (!g_ProcessManager.Initialized || !pModuleList || !pCount) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 2026-08-15 进程域: 从进程模块上下文（WKD_MODULE 视图）枚举 */
    NTSTATUS lookupStatus = PsLookupWkdProcessByStrictProcessId(&WkdProcessTree, Pid, NULL, &node);
    if (!NT_SUCCESS(lookupStatus)) {
        *pCount = 0;
        *pModuleList = NULL;
        return STATUS_NOT_FOUND;
    }

    /* 2026-08-23 进程域 Context 惰性申请: ModuleContext 可能为 NULL（无模块进程） */
    PWKD_MODULE_CONTEXT ctx = node->ModuleContext;
    if (!ctx) {
        *pCount = 0;
        *pModuleList = NULL;
        PsDereferenceWkdProcess(node);   /* 归还查找 pin */
        return STATUS_SUCCESS;
    }

    AcquireSRWLockShared(&ctx->Lock);
    count = ctx->ActiveModules;
    if (count == 0) {
        ReleaseSRWLockShared(&ctx->Lock);
        *pCount = 0;
        *pModuleList = NULL;
        PsDereferenceWkdProcess(node);   /* 归还查找 pin */
        return STATUS_SUCCESS;
    }

    list = (PPROCESS_MODULE_INFO)UtHeapAlloc(count * sizeof(PROCESS_MODULE_INFO));
    if (!list) {
        ReleaseSRWLockShared(&ctx->Lock);
        PsDereferenceWkdProcess(node);   /* 归还查找 pin */
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(list, count * sizeof(PROCESS_MODULE_INFO));

    e = ctx->ModuleList.Flink;
    while (e != &ctx->ModuleList) {
        PWKD_MODULE_INSTANCE inst = CONTAINING_RECORD(e, WKD_MODULE_INSTANCE, ListEntry);
        if (inst->Module) {
            if (inst->Module->ImagePath && inst->Module->ImagePath->Buffer) {
                wcstombs_s(NULL, list[index].ModuleName, sizeof(list[index].ModuleName),
                           inst->Module->ImagePath->Buffer, _TRUNCATE);
                wcstombs_s(NULL, list[index].FilePath, sizeof(list[index].FilePath),
                           inst->Module->ImagePath->Buffer, _TRUNCATE);
            }
            sprintf_s(list[index].BaseAddress, sizeof(list[index].BaseAddress),
                      "0x%p", inst->ImageBase);
            list[index].Size = (UINT32)inst->Module->ImageSize;
        }
        index++;
        e = e->Flink;
    }
    ReleaseSRWLockShared(&ctx->Lock);

    *pCount = index;
    *pModuleList = list;
    PsDereferenceWkdProcess(node);   /* 归还查找 pin */
    return STATUS_SUCCESS;
}

// 终止进程 / 隔离进程 / 信任进程 的完整实现已下移至文件末尾
// "处置引擎"分区（迁移自 ShadowStrike ProcessKiller，按功能融合；
//  头文件声明保留，实现统一在末尾，static 辅助无需前向声明）。

// 释放进程列表内存
VOID ProcessManager_FreeProcessList(
    PPROCESS_INFO pProcessList
)
{
    if (pProcessList) {
        UtHeapFree(pProcessList);
    }
}

// 释放进程模块列表内存
VOID ProcessManager_FreeModuleList(
    PPROCESS_MODULE_INFO pModuleList
)
{
    if (pModuleList) {
        UtHeapFree(pModuleList);
    }
}


// 处理进程退出事件
// 进程消息处理函数 - 由消息队列调用
PVOID ProcessManager_MessageHandler(
    PVOID Context,
    ULONG MessageType,
    PVOID Data
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PWKD_MESSAGE msg = (PWKD_MESSAGE)Data;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(MessageType);

    printf("[ProcessManager] Processing message: Type=0x%X\n", msg->Header.Type);

    switch (msg->Header.Type) {
    case WkdAlpcMsg_GetProcessListReq: {
        printf("[ProcessManager] Processing get process list request\n");
        // 调用HandleGetProcessListRequest函数发送消息
        if (WkDefenderAgent.NotificationManager != NULL && WkDefenderAgent.NotificationManager->AlpcServer != NULL) {
            status = HandleGetProcessListRequest(WkDefenderAgent.NotificationManager->AlpcServer, msg);
        } else {
            printf("[ProcessManager] ALPC server not initialized\n");
            status = STATUS_INVALID_DEVICE_STATE;
        }
        break;
    }

    case WkdMessage_SyscallDetected: {
        printf("[ProcessManager] Processing driver syscall event\n");

        //
        // 已解包的 WKD_MESSAGE：Header + Body 在连续内存中
        //
        ULONG totalPayloadSize = msg->Header.BodySize;

        if (totalPayloadSize < sizeof(WKD_MSG_BODY_SYSCALL)) {
            printf("[ProcessManager] Invalid syscall event payload\n");
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        //
        // 解析元数据：Description 中的 "L1|F=0x%08X|S=%lu|V=%d|R=%lu"
        //
        ULONG behaviorFlags = 0, overallScore = 0, severity = 0, repeatCount = 0;
        ULONG eventType = 0;
        ULONG syscallNumber = 0;
        HANDLE srcPid = NULL, tgtPid = NULL;
        ULONG tgtPidUlong = 0;
        PWKD_PROCESS node = NULL;
        LARGE_INTEGER timestamp = { 0 };
        WCHAR description[256] = { 0 };

        //
        // 使用 WKD_MESSAGE 结构解引用
        //
        {
            PWKD_MESSAGE_HEADER hdr;
            PWKD_MSG_BODY_SYSCALL body;
            ULONG minPayloadSize = sizeof(WKD_MSG_BODY_SYSCALL);

            if (totalPayloadSize < minPayloadSize) {
                printf("[ProcessManager] Syscall event payload too small: %lu < %lu\n",
                    totalPayloadSize, minPayloadSize);
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            hdr = &msg->Header;
            body = (PWKD_MSG_BODY_SYSCALL)msg->Body;

            eventType     = hdr->Type;
            srcPid        = hdr->SourceProcessId;
            tgtPid        = hdr->TargetProcessId;
            timestamp     = hdr->Timestamp;
            syscallNumber = body->SyscallNumber;
            repeatCount   = body->SyscallCount;

            /* Description（如果 Body 尾部还有额外数据） */
            if (totalPayloadSize >= minPayloadSize + sizeof(WCHAR) * 2) {
                PWCHAR pDesc = (PWCHAR)((PUCHAR)body + sizeof(WKD_MSG_BODY_SYSCALL));
                SIZE_T descBytes = totalPayloadSize - minPayloadSize;
                SIZE_T wcharsToCopy = descBytes / sizeof(WCHAR);
                if (wcharsToCopy > 255) wcharsToCopy = 255;
                memcpy(description, pDesc, wcharsToCopy * sizeof(WCHAR));
                description[wcharsToCopy] = L'\0';

                /* 解析 "L1|F=0x%08X|S=%lu|V=%d|R=%lu" */
                ULONG parsed[4] = { 0 };
                int parsedCount = swscanf_s(description, L"L1|F=%x|S=%lu|V=%lu|R=%lu",
                    &parsed[0], &parsed[1], &parsed[2], &parsed[3]);
                if (parsedCount >= 3) {
                    behaviorFlags = parsed[0];
                    overallScore  = parsed[1];
                    severity      = parsed[2];
                    if (parsedCount >= 4) {
                        repeatCount = parsed[3];
                    }
                }
            }
        }

        //
        // 1. 更新进程追踪
        //
        ULONG srcPidUlong = (ULONG)(ULONG_PTR)srcPid;
        tgtPidUlong = (ULONG)(ULONG_PTR)tgtPid;
        HANDLE srcHandle = (HANDLE)(ULONG_PTR)srcPid;
        NTSTATUS lookupStatus = PsLookupWkdProcessByStrictProcessId(&WkdProcessTree, srcHandle, NULL, &node);
        if (node) {
            InterlockedIncrement(&node->IoaEventCount);
            node->LastUpdateTime = timestamp;
            if (behaviorFlags != 0) {
                InterlockedIncrement(&node->SuspiciousBehaviorCount);
            }
            /* 并发安全重构 2026-08-23：整值覆盖写者走 InterlockedExchange，
             * 与 IocEngine.c 的 InterlockedExchangeAdd 累加者并发时
             * 仅"后写胜出"，威胁分数近似可接受（不引入节点锁）。 */
            InterlockedExchange(&node->CumulativeRiskScore, (LONG)overallScore);
        }
        if (!node) {
            return STATUS_NOT_FOUND;
        }

        //
        // 2. 记录到 SQLite
        //
        SECURITY_LOG_ENTRY logEntry;
        memset(&logEntry, 0, sizeof(SECURITY_LOG_ENTRY));
        logEntry.Timestamp = timestamp;
        logEntry.EventType = EVENT_TYPE_SYSCALL;
        logEntry.ProcessId = srcPidUlong;
        logEntry.ThreatLevel = severity;

        // details 存 JSON
        char details[1024];
        snprintf(details, sizeof(details),
            "{\"eventType\":\"0x%X\",\"syscall\":%lu,\"targetPid\":%lu,"
            "\"flags\":\"0x%08X\",\"score\":%lu,\"repeat\":%lu}",
            eventType, syscallNumber, tgtPidUlong,
            behaviorFlags, overallScore, repeatCount);
        strncpy_s(logEntry.Details, sizeof(logEntry.Details), details, _TRUNCATE);

        LogManager_WriteLog(&g_LogManager, &logEntry);

        //
        // 3. 高风险事件通知 UI
        //
        if (severity >= LOG_THREAT_HIGH || overallScore >= 150) {
            NotificationManager_SendThreatNotification(
                WkDefenderAgent.NotificationManager,
                L"Syscall event from driver");
        }

        printf("[ProcessManager] Syscall event: type=0x%X, src=%lu, tgt=%lu, "
            "score=%lu, flags=0x%08X, repeat=%lu\n",
            eventType, srcPidUlong, tgtPidUlong,
            overallScore, behaviorFlags, repeatCount);

        PsDereferenceWkdProcess(node);   /* 归还查找 pin */

        status = STATUS_SUCCESS;
        break;
    }

    case WkdAlpcMsg_RunScanReq: {
        /* 0x1010 — UI 请求启动病毒扫描。
         *
         * 改号自 0x1003：与驱动 WkdMessage_SyscallWriteMemory=0x1003 数值冲突，
         * 复用会拦截驱动单发 syscall 事件（SyscallHijack.c:590 ShpSendSyscallMessage）。
         * 链路缺陷（既有，同 KillProcessReq）：UI SendCommandToAgent 固定 ItemCount=0，
         * 命令当前到不了本分支；UI 发送格式改造见 AlpcSecurityService.cs。 */
        WKD_SCAN_TYPE scanType = WkdScanType_Full;
        WCHAR scanPath[MAX_PATH] = L"";
        ULONG jobId = 0;
        NTSTATUS s;

        /* 载荷 { ULONG ScanType; WCHAR Path[MAX_PATH] }，可缺省 */
        if (msg->Header.BodySize >= sizeof(ULONG)) {
            scanType = (WKD_SCAN_TYPE)*(PULONG)msg->Body;
            if (msg->Header.BodySize > sizeof(ULONG) + sizeof(WCHAR)) {
                SIZE_T pathBytes = msg->Header.BodySize - sizeof(ULONG);
                SIZE_T chars = pathBytes / sizeof(WCHAR);
                if (chars > MAX_PATH - 1) chars = MAX_PATH - 1;
                memcpy(scanPath, (PUCHAR)msg->Body + sizeof(ULONG), chars * sizeof(WCHAR));
                scanPath[chars] = L'\0';
            }
        }

        s = ScanManager_StartScan(scanType, scanPath[0] ? scanPath : NULL, &jobId);
        printf("[ProcessManager] RunScanReq: type=%d job=%lu status=0x%X\n",
               (int)scanType, jobId, s);

        /* 回复 0x4002（载荷 JobId） */
        if (NT_SUCCESS(s) && WkDefenderAgent.NotificationManager != NULL &&
            WkDefenderAgent.NotificationManager->AlpcServer != NULL) {
            status = WkdAlpcSendToUiEx(
                WkDefenderAgent.NotificationManager->AlpcServer,
                WkdAlpcMsg_RunScanResponse, &jobId, sizeof(jobId), 0);
        }
        break;
    }

    case WkdAlpcMsg_KillProcessReq: {
        /* 0x1004 — UI 请求终止进程。
         *
         * 注意：WkdMessage_SyscallReadMemory 亦为 0x1004（驱动→Agent），当前驱动
         * 走 0x1000 聚合事件不单发，二者在路由到本 switch 时不冲突；未来禁止再添加
         * SyscallReadMemory 分支，否则重复 case 值编译失败。
         *
         * 链路缺陷（既有）：UI SendCommandToAgent 固定 ItemCount=0 + 裸 4 字节 PID，
         * 而解包层要求 ItemCount>=1 且数据区为 WKD_MESSAGE —— 命令当前到不了本分支。
         * 本阶段 Agent 侧处理逻辑齐备，UI 发送格式改造留待后续
         * （最小改动 = ItemCount=1 + 数据区包 WKD_MESSAGE{Header.Type=0x1004, Body=4B PID}）。
         * 0x6001 ProcessTerminatedNotification（裸 PID 载荷）线格式两端未对齐，暂不发送。 */
        ULONG pid;

        if (msg->Header.BodySize < sizeof(ULONG)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        pid = *(PULONG)msg->Body;
        printf("[ProcessManager] KillProcessReq: pid=%lu\n", pid);

        /* fire-and-forget：异步执行终止 + 回复 0x2004，避免阻塞队列消费线程 */
        status = ProcessManager_KillProcessAsync(pid);
        break;
    }

    case WkdAlpcMsg_RollbackProcessReq: {
        /* 0x1007 — UI 请求回滚进程文件（FBE 迁移 2026-08）。
         * 对齐 KillProcessReq 解包模式：Body = ULONG PID。
         * 链路缺陷（既有，同 KillProcessReq）：UI SendCommandToAgent 固定
         * ItemCount=0 + 裸数据，命令当前到不了本分支，UI 发送格式改造留待后续。 */
        ULONG pid;

        if (msg->Header.BodySize < sizeof(ULONG)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        pid = *(PULONG)msg->Body;
        printf("[ProcessManager] RollbackProcessReq: pid=%lu\n", pid);

        /* 转驱动执行内核态回滚（FbeRollbackProcess），fire-and-forget */
        // status = WkdAlpcSendToDriver(&WkdDefaultAlpcServer,
        //                              WkdAlpcMessage_RollbackProcessReq,
        //                              &pid, sizeof(pid));
        break;
    }

    default:
        printf("[ProcessManager] Unknown message type: 0x%X\n", MessageType);
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    //if (message != NULL) {
    //    FreeHeapMemory(message);
    //}

    return (PVOID)(ULONG_PTR)status;
}

/**************************************************/
/*           处置引擎：进程终止/挂起/隔离/防护       */
/*                                                */
/*  迁移自 ShadowStrike ProcessKiller.cpp (2452行) */
/*  按功能融合重实现，非源码复制。                  */
/*  原则：功能面全量覆盖，未接入流水线的以死代码     */
/*  落位并在注释说明对齐的 SS 源函数与不接入原因。   */
/**************************************************/

/**************************************************/
/*              Nt 函数声明与辅助结构               */
/**************************************************/

/* Nt* 声明使用 PROCESSINFOCLASS 参数，与 <winternl.h>（WkDefenderHeader.h 已引入）
 * 签名一致；若 SDK winternl.h 已声明，重复声明相同原型合法（至多 dllimport 警告）。 */

NTSTATUS NTAPI NtSuspendProcess(HANDLE ProcessHandle);
NTSTATUS NTAPI NtResumeProcess(HANDLE ProcessHandle);
NTSTATUS NTAPI NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
NTSTATUS NTAPI NtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                       PVOID ProcessInformation, ULONG ProcessInformationLength);
NTSTATUS NTAPI NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                         PVOID ProcessInformation, ULONG ProcessInformationLength,
                                         PULONG ReturnLength);

/* ProcessExtendedBasicInformation (对齐 SS ProcessKiller.cpp L193-211) */
typedef struct _WKD_PROCESS_EXTENDED_BASIC_INFORMATION {
    SIZE_T Size;
    PROCESS_BASIC_INFORMATION BasicInfo;
    union {
        ULONG Flags;
        struct {
            ULONG IsProtectedProcess : 1;
            ULONG IsWow64Process : 1;
            ULONG IsProcessDeleting : 1;
            ULONG IsCrossSessionCreate : 1;
            ULONG IsFrozen : 1;
            ULONG IsBackground : 1;
            ULONG IsStronglyNamed : 1;
            ULONG IsSecureProcess : 1;
            ULONG IsSubsystemProcess : 1;
            ULONG SpareBits : 23;
        };
    };
} WKD_PROCESS_EXTENDED_BASIC_INFORMATION;

/**************************************************/
/*              常量表与全局                       */
/**************************************************/

/* 禁杀名单（须位于系统二进制目录才生效，防 csrss.exe 伪装绕过） */
static const WCHAR* g_WkCriticalProcessNames[WK_CRITICAL_PROCESS_COUNT] = {
    L"System", L"smss.exe", L"csrss.exe", L"wininit.exe",
    L"services.exe", L"lsass.exe", L"winlogon.exe"
};

/* 谨慎名单（系统服务级，非禁止） */
static const WCHAR* g_WkSystemProcessNames[WK_SYSTEM_PROCESS_COUNT] = {
    L"svchost.exe", L"dwm.exe", L"fontdrvhost.exe", L"sihost.exe",
    L"taskhostw.exe", L"ctfmon.exe", L"explorer.exe", L"RuntimeBroker.exe"
};

/* 终止统计（Interlocked 保护） */
static WKD_KILLER_STATISTICS g_WkKillStats = { 0 };

/* 信任进程表（TrustProcess 的语义：加入后 GetCriticality 降级为 Normal） */
#define WK_TRUST_TABLE_MAX 64
static ULONG g_WkTrustedPids[WK_TRUST_TABLE_MAX];
static ULONG g_WkTrustedPidCount = 0;

/* 回调注册表（4 类回调共享槽位，按注册 Id 定位） */
#define WK_CALLBACK_MAX 16
typedef enum _WKD_CALLBACK_KIND {
    WkCallback_PreKill = 0,
    WkCallback_PostKill,
    WkCallback_TreeProgress,
    WkCallback_Watchdog
} WKD_CALLBACK_KIND;

typedef struct _WKD_CALLBACK_ENTRY {
    UINT64 Id;
    WKD_CALLBACK_KIND Kind;
    PVOID Func;
} WKD_CALLBACK_ENTRY;

static WKD_CALLBACK_ENTRY g_WkCallbacks[WK_CALLBACK_MAX];
static ULONG g_WkCallbackCount = 0;
static UINT64 g_WkNextCallbackId = 1;

/**************************************************/
/*              进程查询族（static 重实现）          */
/**************************************************/

/*
 * WkIsProcessRunning — 进程是否存活。
 * 对齐 SS ProcessKiller.cpp L264-288：OpenProcess(SYNCHRONIZE)+WaitForSingleObject(0)
 * 判活（WAIT_TIMEOUT=运行），回退 GetExitCodeProcess(STILL_ACTIVE)。
 */
static BOOLEAN
WkIsProcessRunning(
    _In_ ULONG Pid
    )
{
    HANDLE hProcess;
    DWORD wr;
    DWORD exitCode = 0;

    if (Pid == 0) return FALSE;

    hProcess = OpenProcess(SYNCHRONIZE, FALSE, Pid);
    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
        if (!hProcess) return FALSE;
    }

    wr = WaitForSingleObject(hProcess, 0);
    if (wr == WAIT_TIMEOUT) {
        CloseHandle(hProcess);
        return TRUE;
    }
    if (wr == WAIT_OBJECT_0) {
        CloseHandle(hProcess);
        return FALSE;
    }

    exitCode = 0;
    if (GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE) {
        CloseHandle(hProcess);
        return TRUE;
    }
    CloseHandle(hProcess);
    return FALSE;
}

/*
 * WkGetProcessPath — 取进程完整路径。
 * 对齐 SS ProcessUtils.cpp L350-374 QueryFullImagePath：
 * OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) + QueryFullProcessImageNameW。
 */
static NTSTATUS
WkGetProcessPath(
    _In_ ULONG Pid,
    _Out_writes_(BufLen) PWSTR Buf,
    _In_ ULONG BufLen
    )
{
    HANDLE hProcess;
    DWORD len;
    NTSTATUS status;

    if (!Buf || BufLen == 0) return STATUS_INVALID_PARAMETER;
    Buf[0] = L'\0';

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!hProcess) return STATUS_NOT_FOUND;

    len = BufLen;
    if (QueryFullProcessImageNameW(hProcess, 0, Buf, &len)) {
        status = STATUS_SUCCESS;
    } else {
        status = (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
                 ? STATUS_BUFFER_TOO_SMALL : STATUS_NOT_FOUND;
    }
    CloseHandle(hProcess);
    return status;
}

/*
 * WkGetProcessName — 取进程文件名（路径 basename）。
 * 对齐 SS ProcessUtils.cpp L1607-1611。
 */
static NTSTATUS
WkGetProcessName(
    _In_ ULONG Pid,
    _Out_writes_(BufLen) PWSTR Buf,
    _In_ ULONG BufLen
    )
{
    WCHAR path[260];
    NTSTATUS status;
    PWSTR base;
    ULONG i;

    if (!Buf || BufLen == 0) return STATUS_INVALID_PARAMETER;
    Buf[0] = L'\0';

    status = WkGetProcessPath(Pid, path, 260);
    if (!NT_SUCCESS(status)) return status;

    base = path;
    for (i = 0; path[i] != L'\0'; i++) {
        if (path[i] == L'\\' || path[i] == L'/') base = &path[i + 1];
    }
    wcsncpy_s(Buf, BufLen, base, _TRUNCATE);
    return STATUS_SUCCESS;
}

/*
 * WkGetParentProcessId — 取父进程 PID。
 * 对齐 SS ProcessUtils.cpp L1631-1649：Toolhelp TH32CS_SNAPPROCESS。
 */
static ULONG
WkGetParentProcessId(
    _In_ ULONG Pid
    )
{
    HANDLE hSnap;
    PROCESSENTRY32W pe;
    ULONG parentPid = 0;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == Pid) {
                parentPid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return parentPid;
}

/*
 * WkGetChildrenInternal — 取直接子进程 PID 列表（UtHeapAlloc，调用方 UtHeapFree）。
 * 对齐 SS ProcessUtils.cpp L1659-1685。
 */
static NTSTATUS
WkGetChildrenInternal(
    _In_ ULONG ParentProcessId,
    _Outptr_ PULONG* Pids,
    _Out_ PULONG Count
    )
{
    HANDLE hSnap;
    PROCESSENTRY32W pe;
    PULONG list = NULL;
    ULONG cap = 0, n = 0;

    if (!Pids || !Count) return STATUS_INVALID_PARAMETER;
    *Pids = NULL;
    *Count = 0;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return STATUS_UNSUCCESSFUL;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ParentProcessID == ParentProcessId) {
                if (n == cap) {
                    ULONG newCap = cap ? cap * 2 : 16;
                    PULONG tmp = (PULONG)UtHeapAlloc(newCap * sizeof(ULONG));
                    if (!tmp) {
                        if (list) UtHeapFree(list);
                        CloseHandle(hSnap);
                        return STATUS_NO_MEMORY;
                    }
                    if (list) {
                        memcpy(tmp, list, n * sizeof(ULONG));
                        UtHeapFree(list);
                    }
                    list = tmp;
                    cap = newCap;
                }
                list[n++] = pe.th32ProcessID;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    *Pids = list;
    *Count = n;
    return STATUS_SUCCESS;
}

/*
 * WkGetThreadIds — 取进程全部线程 ID 列表（Toolhelp TH32CS_SNAPTHREAD）。
 * 对齐 SS ProcessKiller.cpp L312-331。
 */
static NTSTATUS
WkGetThreadIds(
    _In_ ULONG Pid,
    _Outptr_ PULONG* Tids,
    _Out_ PULONG Count
    )
{
    HANDLE hSnap;
    THREADENTRY32 te;
    PULONG list = NULL;
    ULONG cap = 0, n = 0;

    if (!Tids || !Count) return STATUS_INVALID_PARAMETER;
    *Tids = NULL;
    *Count = 0;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return STATUS_UNSUCCESSFUL;

    te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == Pid) {
                if (n == cap) {
                    ULONG newCap = cap ? cap * 2 : 16;
                    PULONG tmp = (PULONG)UtHeapAlloc(newCap * sizeof(ULONG));
                    if (!tmp) {
                        if (list) UtHeapFree(list);
                        CloseHandle(hSnap);
                        return STATUS_NO_MEMORY;
                    }
                    if (list) {
                        memcpy(tmp, list, n * sizeof(ULONG));
                        UtHeapFree(list);
                    }
                    list = tmp;
                    cap = newCap;
                }
                list[n++] = te.th32ThreadID;
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);

    *Tids = list;
    *Count = n;
    return STATUS_SUCCESS;
}

/* 远程内存可读性预校验（VirtualQueryEx，对齐 SS IsRemoteRangeReadable） */
static BOOLEAN
WkIsRemoteRangeReadable(
    _In_ HANDLE hProcess,
    _In_ PVOID Base,
    _In_ SIZE_T Size
    )
{
    MEMORY_BASIC_INFORMATION mbi;

    if (Size == 0) return TRUE;
    if (!VirtualQueryEx(hProcess, Base, &mbi, sizeof(mbi))) return FALSE;
    if (mbi.State != MEM_COMMIT) return FALSE;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return FALSE;
    if (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                       PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) {
        return TRUE;
    }
    return FALSE;
}

/* PEB 结构（x64 读 WOW64 用 32 位投影，对齐 SS ProcessUtils.cpp L1395-1421） */
typedef struct _WKD_PEB32 {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    ULONG Reserved3[2];
    ULONG Ldr;
    ULONG ProcessParameters;
} WKD_PEB32;

typedef struct _WKD_UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Buffer;
} WKD_UNICODE_STRING32;

typedef struct _WKD_RTL_USER_PROCESS_PARAMETERS32 {
    BYTE Reserved1[16];
    ULONG Reserved2[10];
    WKD_UNICODE_STRING32 ImagePathName;
    WKD_UNICODE_STRING32 CommandLine;
} WKD_RTL_USER_PROCESS_PARAMETERS32;

typedef struct _WKD_PEB64 {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
} WKD_PEB64;

typedef struct _WKD_RTL_USER_PROCESS_PARAMETERS64 {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} WKD_RTL_USER_PROCESS_PARAMETERS64;

/*
 * WkGetProcessCommandLine — 读取进程命令行。
 * 对齐 SS ProcessUtils.cpp L1348-1605：NtQueryInformationProcess(ProcessBasicInformation)
 * 读 PEB → RTL_USER_PROCESS_PARAMETERS.CommandLine；WOW64 用 class 26 拿 32 位 PEB；
 * 长度上限 32768；读前预校验内存可读。
 */
static NTSTATUS
WkGetProcessCommandLine(
    _In_ ULONG Pid,
    _Out_writes_(BufLen) PWSTR Buf,
    _In_ ULONG BufLen
    )
{
    HANDLE hProcess;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen = 0;
    NTSTATUS status = STATUS_SUCCESS;
    WCHAR isTargetWow64 = 0;

    if (!Buf || BufLen == 0) return STATUS_INVALID_PARAMETER;
    Buf[0] = L'\0';

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, Pid);
    if (!hProcess) return STATUS_NOT_FOUND;

    RtlZeroMemory(&pbi, sizeof(pbi));
    if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi,
                                  sizeof(pbi), &retLen) != 0 || !pbi.PebBaseAddress) {
        CloseHandle(hProcess);
        return STATUS_UNSUCCESSFUL;
    }

    /* WOW64 判定：IsWow64Process2 优先，回退 IsWow64Process */
    {
        typedef BOOL(WINAPI *PIsWow64Process2)(HANDLE, USHORT*, USHORT*);
        static PIsWow64Process2 pIsWow64Process2 = NULL;
        USHORT procMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;

        if (!pIsWow64Process2) {
            pIsWow64Process2 = (PIsWow64Process2)GetProcAddress(
                GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
        }
        if (pIsWow64Process2) {
            if (pIsWow64Process2(hProcess, &procMachine, &nativeMachine)) {
                isTargetWow64 = (procMachine != IMAGE_FILE_MACHINE_UNKNOWN) &&
                                (procMachine != nativeMachine);
            } else {
                BOOL wow = FALSE;
                IsWow64Process(hProcess, &wow);
                isTargetWow64 = (wow == TRUE);
            }
        } else {
            BOOL wow = FALSE;
            IsWow64Process(hProcess, &wow);
            isTargetWow64 = (wow == TRUE);
        }
    }

#ifdef _WIN64
    if (isTargetWow64) {
        /* x64 读 WOW64 进程 */
        PVOID peb32Address = NULL;
        WKD_PEB32 peb32;
        WKD_RTL_USER_PROCESS_PARAMETERS32 params32;
        SIZE_T read = 0;
        PVOID cmdBuf32;
        ULONG cmdLen;

        RtlZeroMemory(&peb32, sizeof(peb32));
        RtlZeroMemory(&params32, sizeof(params32));

        if (NtQueryInformationProcess(hProcess, ProcessWow64Information, &peb32Address,
                                      sizeof(peb32Address), NULL) != 0 || !peb32Address) {
            CloseHandle(hProcess);
            return STATUS_UNSUCCESSFUL;
        }
        if (!WkIsRemoteRangeReadable(hProcess, peb32Address, sizeof(peb32)) ||
            !ReadProcessMemory(hProcess, peb32Address, &peb32, sizeof(peb32), &read) ||
            read != sizeof(peb32) || !peb32.ProcessParameters) {
            CloseHandle(hProcess);
            return STATUS_UNSUCCESSFUL;
        }
        {
            PVOID pp32 = (PVOID)(ULONG_PTR)peb32.ProcessParameters;
            if (!WkIsRemoteRangeReadable(hProcess, pp32, sizeof(params32)) ||
                !ReadProcessMemory(hProcess, pp32, &params32, sizeof(params32), &read) ||
                read != sizeof(params32)) {
                CloseHandle(hProcess);
                return STATUS_UNSUCCESSFUL;
            }
        }
        if (!params32.CommandLine.Buffer || params32.CommandLine.Length == 0 ||
            params32.CommandLine.Length > 32768) {
            CloseHandle(hProcess);
            return STATUS_SUCCESS;  /* 无命令行视为成功(空) */
        }
        cmdLen = params32.CommandLine.Length;
        /* 限制读取长度不超过 Buf 容量，防溢出（SS 用 std::wstring 动态分配） */
        if (cmdLen > (BufLen - 1) * sizeof(WCHAR)) cmdLen = (BufLen - 1) * sizeof(WCHAR);
        cmdBuf32 = (PVOID)(ULONG_PTR)params32.CommandLine.Buffer;
        if (!WkIsRemoteRangeReadable(hProcess, cmdBuf32, cmdLen) ||
            !ReadProcessMemory(hProcess, cmdBuf32, Buf, cmdLen, &read) ||
            read != cmdLen) {
            CloseHandle(hProcess);
            return STATUS_UNSUCCESSFUL;
        }
        Buf[cmdLen / sizeof(WCHAR)] = L'\0';
        CloseHandle(hProcess);
        return STATUS_SUCCESS;
    }
#else
    (void)isTargetWow64;
#endif

    /* 原生指针大小（x64 读 x64） */
    {
        WKD_PEB64 peb;
        WKD_RTL_USER_PROCESS_PARAMETERS64 params;
        SIZE_T read = 0;
        PVOID cmdBuf;
        ULONG cmdLen;

        RtlZeroMemory(&peb, sizeof(peb));
        RtlZeroMemory(&params, sizeof(params));

        if (!WkIsRemoteRangeReadable(hProcess, pbi.PebBaseAddress, sizeof(peb)) ||
            !ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &read) ||
            read != sizeof(peb) || !peb.ProcessParameters) {
            CloseHandle(hProcess);
            return STATUS_UNSUCCESSFUL;
        }
        if (!WkIsRemoteRangeReadable(hProcess, peb.ProcessParameters, sizeof(params)) ||
            !ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), &read) ||
            read != sizeof(params)) {
            CloseHandle(hProcess);
            return STATUS_UNSUCCESSFUL;
        }
        if (!params.CommandLine.Buffer || params.CommandLine.Length == 0) {
            CloseHandle(hProcess);
            return STATUS_SUCCESS;
        }
        if (params.CommandLine.Length > 32768) {
            CloseHandle(hProcess);
            return STATUS_SUCCESS;
        }
        cmdLen = params.CommandLine.Length;
        /* 限制读取长度不超过 Buf 容量，防溢出 */
        if (cmdLen > (BufLen - 1) * sizeof(WCHAR)) cmdLen = (BufLen - 1) * sizeof(WCHAR);
        cmdBuf = params.CommandLine.Buffer;
        if (!WkIsRemoteRangeReadable(hProcess, cmdBuf, cmdLen) ||
            !ReadProcessMemory(hProcess, cmdBuf, Buf, cmdLen, &read) ||
            read != cmdLen) {
            CloseHandle(hProcess);
            return STATUS_UNSUCCESSFUL;
        }
        Buf[cmdLen / sizeof(WCHAR)] = L'\0';
        /* 截断到第一个内嵌 null（对齐 SS ProcessUtils.cpp L1595-1600） */
        {
            ULONG i;
            ULONG maxChars = cmdLen / sizeof(WCHAR);
            for (i = 0; i < maxChars; i++) {
                if (Buf[i] == L'\0') break;
            }
            Buf[i] = L'\0';
        }
    }

    CloseHandle(hProcess);
    return status;
}

/*
 * WkGetProcessOwner — 取进程所有者 (Domain\User)。
 * 对齐 SS ProcessUtils.cpp L1119-1181 GetProcessSecurityInfo：OpenProcessToken +
 * GetTokenInformation(TokenUser) + LookupAccountSidW。
 */
static NTSTATUS
WkGetProcessOwner(
    _In_ ULONG Pid,
    _Out_writes_(BufLen) PWSTR Buf,
    _In_ ULONG BufLen
    )
{
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    DWORD len = 0;
    PUCHAR buf = NULL;
    PTOKEN_USER tu;
    WCHAR name[256], domain[256];
    DWORD cchName = 256, cchDomain = 256;
    SID_NAME_USE use = SidTypeUnknown;
    NTSTATUS status = STATUS_SUCCESS;

    if (!Buf || BufLen == 0) return STATUS_INVALID_PARAMETER;
    Buf[0] = L'\0';

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!hProcess) return STATUS_NOT_FOUND;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        status = STATUS_ACCESS_DENIED;
        goto done;
    }

    GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || len == 0 || len > 4096) {
        status = STATUS_UNSUCCESSFUL;
        goto done;
    }
    buf = (PUCHAR)UtHeapAlloc(len);
    if (!buf) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }
    if (!GetTokenInformation(hToken, TokenUser, buf, len, &len)) {
        status = STATUS_UNSUCCESSFUL;
        goto done;
    }

    tu = (PTOKEN_USER)buf;
    if (tu->User.Sid &&
        LookupAccountSidW(NULL, tu->User.Sid, name, &cchName, domain, &cchDomain, &use)) {
        if (domain[0] != L'\0') {
            _snwprintf_s(Buf, BufLen, _TRUNCATE, L"%s\\%s", domain, name);
        } else {
            wcsncpy_s(Buf, BufLen, name, _TRUNCATE);
        }
    }

done:
    if (buf) UtHeapFree(buf);
    if (hToken) CloseHandle(hToken);
    if (hProcess) CloseHandle(hProcess);
    return status;
}

/* 进程创建时间（TOCTOU 防护：OpenProcess 后与 kill 时比对） */
static BOOLEAN
WkGetProcessCreationTime(
    _In_ HANDLE hProcess,
    _Out_ PFILETIME Out
    )
{
    FILETIME creation = { 0 }, exit = { 0 }, kernel = { 0 }, user = { 0 };

    if (!hProcess || !Out) return FALSE;
    if (!GetProcessTimes(hProcess, &creation, &exit, &kernel, &user)) return FALSE;
    *Out = creation;
    return TRUE;
}

static BOOLEAN
WkCreationTimesMatch(
    _In_ FILETIME A,
    _In_ FILETIME B
    )
{
    return A.dwLowDateTime == B.dwLowDateTime && A.dwHighDateTime == B.dwHighDateTime;
}

/* 启用 SeDebugPrivilege（对齐 SS ProcessKiller.cpp L238-262） */
static BOOLEAN
WkEnableDebugPrivilege(
    VOID
    )
{
    HANDLE hToken = NULL;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_PRIVILEGE_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

/* 保留 PID：0(System Idle) / 4(System) / 自身 */
static BOOLEAN
WkIsReservedPid(
    _In_ ULONG Pid
    )
{
    return (Pid == 0 || Pid == 4 || Pid == GetCurrentProcessId());
}

/*
 * WkIsSystemBinaryDirectory — 路径是否位于系统二进制目录。
 * 对齐 SS ProcessKiller.cpp L293-301 IsSystemDirectoryPath：
 * 小写化 + 匹配 \windows\system32\ / syswow64 / winsxs。
 * 注意：不复用 WkdIsSystemDirectory（范围过宽，会把 C:\Windows\Temp\csrss.exe 误判）。
 */
static BOOLEAN
WkIsSystemBinaryDirectory(
    _In_ PCWSTR Path
    )
{
    WCHAR lower[520];
    ULONG len = 0, i;

    if (!Path || Path[0] == L'\0') return FALSE;

    while (Path[len] != L'\0' && len < 519) {
        lower[len] = (WCHAR)towlower(Path[len]);
        len++;
    }
    lower[len] = L'\0';

    return (wcsstr(lower, L"\\windows\\system32\\") != NULL) ||
           (wcsstr(lower, L"\\windows\\syswow64\\") != NULL) ||
           (wcsstr(lower, L"\\windows\\winsxs\\") != NULL);
}

/* 名称是否命中禁杀名单（不区分大小写） */
static BOOLEAN
WkIsCriticalProcessName(
    _In_ PCWSTR Name
    )
{
    ULONG i;

    if (!Name) return FALSE;
    for (i = 0; i < WK_CRITICAL_PROCESS_COUNT; i++) {
        if (_wcsicmp(Name, g_WkCriticalProcessNames[i]) == 0) return TRUE;
    }
    return FALSE;
}

/**************************************************/
/*                保护分析                          */
/**************************************************/

/*
 * WkGetProtectionInfoInternal — 进程保护信息。
 * 对齐 SS ProcessKiller.cpp L1047-1088 GetProtectionInfoInternal：
 * BreakOnTermination(29) 检测临界进程(BSOD)；PROCESS_EXTENDED_BASIC_INFORMATION(0)
 * 检测 PP / VBS Secure。
 */
static NTSTATUS
WkGetProtectionInfoInternal(
    _In_ ULONG Pid,
    _Out_ PWKD_PROCESS_PROTECTION_INFO Out
    )
{
    HANDLE hProcess;
    ULONG breakOnTermination = 0;
    ULONG retLen = 0;
    WKD_PROCESS_EXTENDED_BASIC_INFORMATION extInfo;

    if (!Out) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Out, sizeof(*Out));

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!hProcess) return STATUS_NOT_FOUND;

    if (NtQueryInformationProcess(hProcess, ProcessBreakOnTermination,
                                  &breakOnTermination, sizeof(breakOnTermination), &retLen) == 0 &&
        breakOnTermination) {
        Out->IsCritical = TRUE;
        Out->IsBreakOnTermination = TRUE;
        Out->CanTerminate = FALSE;
        wcscpy_s(Out->ProtectionDescription, 128, L"Critical process (BSOD on termination)");
    }

    RtlZeroMemory(&extInfo, sizeof(extInfo));
    extInfo.Size = sizeof(extInfo);
    retLen = 0;
    if (NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                  &extInfo, sizeof(extInfo), &retLen) == 0) {
        if (extInfo.IsProtectedProcess) {
            Out->Level = WkProtection_Full;
            Out->CanTerminate = FALSE;
            wcscpy_s(Out->ProtectionDescription, 128, L"Protected Process (PP)");
        } else if (extInfo.IsSecureProcess) {
            Out->IsSecure = TRUE;
            Out->Level = WkProtection_Full;
            Out->CanTerminate = FALSE;
            wcscpy_s(Out->ProtectionDescription, 128, L"Secure process (VBS-protected)");
        }
    }

    CloseHandle(hProcess);
    return STATUS_SUCCESS;
}

/*
 * WkGetCriticalityInternal — 进程关键性判定。
 * 对齐 SS ProcessKiller.cpp L1090-1123 GetCriticalityInternal：
 * 名称命中禁杀名单且路径位于系统二进制目录 → Forbidden（否则 masquerade 降级+日志）；
 * BreakOnTermination → Critical；名称命中谨慎名单且系统目录 → SystemService。
 */
static WKD_PROCESS_CRITICALITY
WkGetCriticalityInternal(
    _In_ ULONG Pid
    )
{
    WCHAR name[260] = { 0 };
    WCHAR path[260] = { 0 };
    WKD_PROCESS_PROTECTION_INFO prot;
    ULONG i;
    BOOLEAN hasPath;

    if (WkGetProcessName(Pid, name, 260) != STATUS_SUCCESS) {
        return WkCriticality_Unknown;
    }

    if (WkIsCriticalProcessName(name)) {
        /* 纵深防御：名称匹配只有在系统二进制目录才权威；
         * 否则视为 masquerade（如 C:\Temp\csrss.exe）降级并记日志。 */
        hasPath = (WkGetProcessPath(Pid, path, 260) == STATUS_SUCCESS);
        if (!hasPath || WkIsSystemBinaryDirectory(path)) {
            return WkCriticality_Forbidden;
        }
        printf("[ProcessManager] Process %u uses critical-process name '%ls' but resides "
               "at '%ls' (not a system binary directory) - masquerade suspected, "
               "criticality downgraded\n", Pid, name, path);
    }

    RtlZeroMemory(&prot, sizeof(prot));
    if (WkGetProtectionInfoInternal(Pid, &prot) == STATUS_SUCCESS && prot.IsCritical) {
        return WkCriticality_Critical;
    }

    for (i = 0; i < WK_SYSTEM_PROCESS_COUNT; i++) {
        if (_wcsicmp(name, g_WkSystemProcessNames[i]) == 0) {
            hasPath = (WkGetProcessPath(Pid, path, 260) == STATUS_SUCCESS);
            if (!hasPath || WkIsSystemBinaryDirectory(path)) {
                return WkCriticality_SystemService;
            }
        }
    }
    return WkCriticality_Normal;
}

static BOOLEAN
WkIsCriticalProcessInternal(
    _In_ ULONG Pid
    )
{
    return WkGetCriticalityInternal(Pid) >= WkCriticality_Critical;
}

/**************************************************/
/*                 8 级终止链                      */
/**************************************************/

/* 每级方法先 OpenProcess 后比对 creation time，不符返回 NotFound（防 PID 复用误杀）。
 * 对齐 SS ProcessKiller.cpp L1210-1486。 */

static WKD_KILL_RESULT
WkKillStandard(
    _In_ ULONG Pid,
    _In_ ULONG ExitCode,
    _In_ FILETIME Expected
    )
{
    HANDLE hProcess;
    FILETIME current;

    hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, Pid);
    if (!hProcess) {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            InterlockedIncrement64(&g_WkKillStats.AccessDeniedErrors);
            return WkKillResult_AccessDenied;
        }
        return WkIsProcessRunning(Pid) ? WkKillResult_Failed : WkKillResult_AlreadyDead;
    }

    if (Expected.dwLowDateTime || Expected.dwHighDateTime) {
        if (!WkGetProcessCreationTime(hProcess, &current) ||
            !WkCreationTimesMatch(Expected, current)) {
            CloseHandle(hProcess);
            return WkKillResult_NotFound;
        }
    }

    if (!TerminateProcess(hProcess, ExitCode)) {
        CloseHandle(hProcess);
        return WkKillResult_Failed;
    }
    CloseHandle(hProcess);
    InterlockedIncrement64(&g_WkKillStats.StandardKills);
    return WkKillResult_Success;
}

static WKD_KILL_RESULT
WkKillPrivileged(
    _In_ ULONG Pid,
    _In_ ULONG ExitCode,
    _In_ FILETIME Expected
    )
{
    HANDLE hProcess;
    FILETIME current;

    (void)WkEnableDebugPrivilege();
    hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
    if (!hProcess) {
        InterlockedIncrement64(&g_WkKillStats.AccessDeniedErrors);
        return WkKillResult_AccessDenied;
    }

    if (Expected.dwLowDateTime || Expected.dwHighDateTime) {
        if (!WkGetProcessCreationTime(hProcess, &current) ||
            !WkCreationTimesMatch(Expected, current)) {
            CloseHandle(hProcess);
            return WkKillResult_NotFound;
        }
    }

    if (!TerminateProcess(hProcess, ExitCode)) {
        CloseHandle(hProcess);
        return WkKillResult_Failed;
    }
    CloseHandle(hProcess);
    InterlockedIncrement64(&g_WkKillStats.PrivilegedKills);
    return WkKillResult_Success;
}

static WKD_KILL_RESULT
WkKillFreeze(
    _In_ ULONG Pid,
    _In_ ULONG ExitCode,
    _In_ FILETIME Expected
    )
{
    HANDLE hSuspend;
    HANDLE hProcess;
    FILETIME current;

    hSuspend = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, FALSE, Pid);
    if (hSuspend) {
        NtSuspendProcess(hSuspend);
        CloseHandle(hSuspend);
    }
    Sleep(50);

    hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, Pid);
    if (!hProcess) {
        return WkIsProcessRunning(Pid) ? WkKillResult_AccessDenied : WkKillResult_AlreadyDead;
    }

    if (Expected.dwLowDateTime || Expected.dwHighDateTime) {
        if (!WkGetProcessCreationTime(hProcess, &current) ||
            !WkCreationTimesMatch(Expected, current)) {
            CloseHandle(hProcess);
            return WkKillResult_NotFound;
        }
    }

    if (!TerminateProcess(hProcess, ExitCode)) {
        CloseHandle(hProcess);
        return WkKillResult_Failed;
    }
    CloseHandle(hProcess);
    InterlockedIncrement64(&g_WkKillStats.FreezeKills);
    return WkKillResult_Success;
}

/*
 * WkKillJobObject — 通过 Job 对象终止。
 * 对齐 SS ProcessKiller.cpp L1290-1323。
 * ※ 死代码：对已入其它 Job/提升/受保护进程 AssignProcessToJobObject 通常被拒，
 *   1-3 级几乎总能成功，保留作级别占位防 API 行为变化。
 */
static WKD_KILL_RESULT
WkKillJobObject(
    _In_ ULONG Pid,
    _In_ ULONG ExitCode,
    _In_ FILETIME Expected
    )
{
    HANDLE hJob;
    HANDLE hProcess;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo;
    FILETIME current;

    UNREFERENCED_PARAMETER(ExitCode);

    hJob = CreateJobObjectW(NULL, NULL);
    if (!hJob) return WkKillResult_Failed;

    RtlZeroMemory(&jobInfo, sizeof(jobInfo));
    jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                                 &jobInfo, sizeof(jobInfo))) {
        CloseHandle(hJob);
        return WkKillResult_Failed;
    }

    hProcess = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, Pid);
    if (!hProcess) {
        CloseHandle(hJob);
        return WkKillResult_AccessDenied;
    }

    if (Expected.dwLowDateTime || Expected.dwHighDateTime) {
        if (!WkGetProcessCreationTime(hProcess, &current) ||
            !WkCreationTimesMatch(Expected, current)) {
            CloseHandle(hProcess);
            CloseHandle(hJob);
            return WkKillResult_NotFound;
        }
    }

    if (!AssignProcessToJobObject(hJob, hProcess)) {
        CloseHandle(hProcess);
        CloseHandle(hJob);
        return WkKillResult_Failed;
    }
    CloseHandle(hProcess);
    CloseHandle(hJob);
    Sleep(100);

    if (WkIsProcessRunning(Pid)) return WkKillResult_Timeout;

    InterlockedIncrement64(&g_WkKillStats.JobObjectKills);
    return WkKillResult_Success;
}

/*
 * WkKillTokenManipulation — 剥除目标 token 特权后终止。
 * 对齐 SS ProcessKiller.cpp L1326-1351。
 * ※ 死代码：SS 自身标注为无效级 —— AdjustTokenPrivileges(DisableAll) 撤销的是目标进程
 *   自身特权，不提升调用者对目标的访问权限，TerminateProcess 成败不受其影响。仅占位。
 */
static WKD_KILL_RESULT
WkKillTokenManipulation(
    _In_ ULONG Pid,
    _In_ ULONG ExitCode,
    _In_ FILETIME Expected
    )
{
    HANDLE hProcess;
    HANDLE hToken = NULL;
    FILETIME current;

    (void)WkEnableDebugPrivilege();
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, FALSE, Pid);
    if (!hProcess) {
        InterlockedIncrement64(&g_WkKillStats.AccessDeniedErrors);
        return WkKillResult_AccessDenied;
    }

    if (Expected.dwLowDateTime || Expected.dwHighDateTime) {
        if (!WkGetProcessCreationTime(hProcess, &current) ||
            !WkCreationTimesMatch(Expected, current)) {
            CloseHandle(hProcess);
            return WkKillResult_NotFound;
        }
    }

    if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        AdjustTokenPrivileges(hToken, TRUE, NULL, 0, NULL, NULL);
        CloseHandle(hToken);
    }

    if (!TerminateProcess(hProcess, ExitCode)) {
        CloseHandle(hProcess);
        return WkKillResult_Failed;
    }
    CloseHandle(hProcess);
    return WkKillResult_Success;
}

static WKD_KILL_RESULT
WkKillNtTerminate(
    _In_ ULONG Pid,
    _In_ ULONG ExitCode,
    _In_ FILETIME Expected
    )
{
    HANDLE hProcess;
    FILETIME current;
    NTSTATUS status;

    (void)WkEnableDebugPrivilege();
    hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, Pid);
    if (!hProcess) {
        InterlockedIncrement64(&g_WkKillStats.AccessDeniedErrors);
        return WkKillResult_AccessDenied;
    }

    if (Expected.dwLowDateTime || Expected.dwHighDateTime) {
        if (!WkGetProcessCreationTime(hProcess, &current) ||
            !WkCreationTimesMatch(Expected, current)) {
            CloseHandle(hProcess);
            return WkKillResult_NotFound;
        }
    }

    status = NtTerminateProcess(hProcess, (NTSTATUS)ExitCode);
    CloseHandle(hProcess);
    if (!NT_SUCCESS(status)) return WkKillResult_Failed;

    InterlockedIncrement64(&g_WkKillStats.KernelKills);
    return WkKillResult_Success;
}

static WKD_KILL_RESULT
WkKillForceNtTerminate(
    _In_ ULONG Pid,
    _In_ ULONG ExitCode,
    _In_ FILETIME Expected
    )
{
    HANDLE hProcess;
    FILETIME current;
    NTSTATUS status;
    ULONG breakOnTerm = 0;

    (void)WkEnableDebugPrivilege();
    hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION,
                           FALSE, Pid);
    if (!hProcess) {
        InterlockedIncrement64(&g_WkKillStats.AccessDeniedErrors);
        return WkKillResult_AccessDenied;
    }

    if (Expected.dwLowDateTime || Expected.dwHighDateTime) {
        if (!WkGetProcessCreationTime(hProcess, &current) ||
            !WkCreationTimesMatch(Expected, current)) {
            CloseHandle(hProcess);
            return WkKillResult_NotFound;
        }
    }

    /* 清除 BreakOnTermination，避免终止致 BSOD */
    NtSetInformationProcess(hProcess, ProcessBreakOnTermination,
                            &breakOnTerm, sizeof(breakOnTerm));

    status = NtTerminateProcess(hProcess, (NTSTATUS)ExitCode);
    CloseHandle(hProcess);
    if (!NT_SUCCESS(status)) return WkKillResult_Failed;

    InterlockedIncrement64(&g_WkKillStats.KernelKills);
    return WkKillResult_Success;
}

/*
 * WkKillKernelDriver — 内核驱动 IOCTL 终止。
 * 对齐 SS ProcessKiller.cpp L1410-1486（KillKernelDriver）。
 * ※ 死代码：依赖内核驱动 IPC 通道（SS 的 IPCManager.SendToKernel），WkD 当前用户态
 *   Agent 无等价驱动终止通道，直接返回 Failed。
 */
static WKD_KILL_RESULT
WkKillKernelDriver(
    _In_ ULONG Pid,
    _In_ ULONG ExitCode,
    _In_ FILETIME Expected
    )
{
    UNREFERENCED_PARAMETER(Pid);
    UNREFERENCED_PARAMETER(ExitCode);
    UNREFERENCED_PARAMETER(Expected);
    return WkKillResult_Failed;
}

static WKD_KILL_RESULT
WkKillWithMethod(
    _In_ ULONG Pid,
    _In_ WKD_KILL_METHOD Method,
    _In_ PCWKD_KILL_OPTIONS Options,
    _Inout_ PWKD_PROCESS_KILL_INFO Info,
    _In_ FILETIME Expected
    )
{
    ULONG exitCode = Options ? Options->ExitCode : WK_EXIT_CODE_KILLED;

    if (Info) {
        Info->AttemptCount++;
        Info->MethodUsed = Method;
    }

    if (!WkIsProcessRunning(Pid)) return WkKillResult_AlreadyDead;

    switch (Method) {
    case WkKillMethod_Standard:
        return WkKillStandard(Pid, exitCode, Expected);
    case WkKillMethod_Privileged:
        return WkKillPrivileged(Pid, exitCode, Expected);
    case WkKillMethod_Freeze:
        return WkKillFreeze(Pid, exitCode, Expected);
    case WkKillMethod_JobObject:
        return WkKillJobObject(Pid, exitCode, Expected);
    case WkKillMethod_TokenManipulation:
        return WkKillTokenManipulation(Pid, exitCode, Expected);
    case WkKillMethod_Kernel:
        return WkKillNtTerminate(Pid, exitCode, Expected);
    case WkKillMethod_ForceKernel:
        return WkKillForceNtTerminate(Pid, exitCode, Expected);
    case WkKillMethod_Nuclear:
        return WkKillKernelDriver(Pid, exitCode, Expected);
    case WkKillMethod_Auto:
    default:
        return WkKillResult_Failed;
    }
}

/*
 * WkEscalatingKill — 1→8 逐级升级终止。
 * 对齐 SS ProcessKiller.cpp L1133-1185 EscalatingKill：
 * 每级成功/AlreadyDead 即返回；escalateOnFailure=FALSE 则首级失败即止。
 */
static WKD_KILL_RESULT
WkEscalatingKill(
    _In_ ULONG Pid,
    _In_ PCWKD_KILL_OPTIONS Options,
    _Inout_ PWKD_PROCESS_KILL_INFO Info,
    _In_ FILETIME Expected
    )
{
    WKD_KILL_RESULT result;

    result = WkKillWithMethod(Pid, WkKillMethod_Standard, Options, Info, Expected);
    if (result == WkKillResult_Success || result == WkKillResult_AlreadyDead) return result;
    if (!Options->EscalateOnFailure) return result;

    InterlockedIncrement64(&g_WkKillStats.EscalatedKills);

    result = WkKillWithMethod(Pid, WkKillMethod_Privileged, Options, Info, Expected);
    if (result == WkKillResult_Success || result == WkKillResult_AlreadyDead) return result;

    result = WkKillWithMethod(Pid, WkKillMethod_Freeze, Options, Info, Expected);
    if (result == WkKillResult_Success || result == WkKillResult_AlreadyDead) return result;

    result = WkKillWithMethod(Pid, WkKillMethod_JobObject, Options, Info, Expected);
    if (result == WkKillResult_Success || result == WkKillResult_AlreadyDead) return result;

    result = WkKillWithMethod(Pid, WkKillMethod_TokenManipulation, Options, Info, Expected);
    if (result == WkKillResult_Success || result == WkKillResult_AlreadyDead) return result;

    result = WkKillWithMethod(Pid, WkKillMethod_Kernel, Options, Info, Expected);
    if (result == WkKillResult_Success || result == WkKillResult_AlreadyDead) return result;

    result = WkKillWithMethod(Pid, WkKillMethod_ForceKernel, Options, Info, Expected);
    if (result == WkKillResult_Success || result == WkKillResult_AlreadyDead) return result;

    result = WkKillWithMethod(Pid, WkKillMethod_Nuclear, Options, Info, Expected);
    if (result == WkKillResult_Success || result == WkKillResult_AlreadyDead) return result;

    return result;
}

/**************************************************/
/*             验证与取证保留                       */
/**************************************************/

/*
 * WkVerifyTerminationInternal — 轮询验证进程确已终止。
 * 对齐 SS ProcessKiller.cpp L1492-1501。
 */
static BOOLEAN
WkVerifyTerminationInternal(
    _In_ ULONG Pid,
    _In_ ULONG TimeoutMs
    )
{
    ULONG waited = 0;

    while (waited < TimeoutMs) {
        if (!WkIsProcessRunning(Pid)) return TRUE;
        Sleep(WK_VERIFY_INTERVAL_MS);
        waited += WK_VERIFY_INTERVAL_MS;
    }
    return !WkIsProcessRunning(Pid);
}

/*
 * WkPreserveEvidence — 杀前收集取证信息（命令行 + 所有者）。
 * 对齐 SS ProcessKiller.cpp L1503-1508 PreserveEvidence。
 */
static VOID
WkPreserveEvidence(
    _In_ ULONG Pid,
    _Inout_ PWKD_PROCESS_KILL_INFO Info
    )
{
    WCHAR tmp[1024] = { 0 };
    WCHAR owner[64] = { 0 };

    if (!Info) return;

    if (WkGetProcessCommandLine(Pid, tmp, 1024) == STATUS_SUCCESS && tmp[0] != L'\0') {
        wcsncpy_s(Info->CommandLine, 1024, tmp, _TRUNCATE);
    }
    if (WkGetProcessOwner(Pid, owner, 64) == STATUS_SUCCESS && owner[0] != L'\0') {
        wcsncpy_s(Info->UserName, 64, owner, _TRUNCATE);
    }
}

/**************************************************/
/*                进程树枚举                        */
/**************************************************/

/*
 * WkBuildTreeRecursive — 递归构建进程树。
 * 对齐 SS ProcessKiller.cpp L844-856 BuildTreeRecursive：
 * visited 数组防环、深度/大小上限、跳过保留 PID。
 */
static NTSTATUS
WkBuildTreeRecursive(
    _In_ ULONG Pid,
    _Inout_ PULONG Tree,
    _Inout_ PULONG Count,
    _In_ ULONG MaxSize,
    _In_ ULONG Depth,
    _In_ ULONG MaxDepth,
    _Inout_ PULONG Visited,
    _In_ ULONG VisitedCount
    )
{
    ULONG i;
    PULONG children = NULL;
    ULONG childCount = 0;
    NTSTATUS status;

    if (Depth > MaxDepth || *Count >= MaxSize) return STATUS_SUCCESS;
    if (WkIsReservedPid(Pid)) return STATUS_SUCCESS;

    for (i = 0; i < VisitedCount; i++) {
        if (Visited[i] == Pid) return STATUS_SUCCESS;
    }

    Tree[*Count] = Pid;
    (*Count)++;
    Visited[VisitedCount] = Pid;
    VisitedCount++;

    status = WkGetChildrenInternal(Pid, &children, &childCount);
    if (!NT_SUCCESS(status)) return status;

    for (i = 0; i < childCount && *Count < MaxSize; i++) {
        status = WkBuildTreeRecursive(children[i], Tree, Count, MaxSize,
                                      Depth + 1, MaxDepth, Visited, VisitedCount);
        if (!NT_SUCCESS(status)) break;
    }
    if (children) UtHeapFree(children);
    return STATUS_SUCCESS;
}

/*
 * WkGetProcessTreeInternal — 根在前（深度优先），调用方 UtHeapFree。
 * 对齐 SS ProcessKiller.cpp L833-856 GetProcessTreeInternal。
 */
static NTSTATUS
WkGetProcessTreeInternal(
    _In_ ULONG RootPid,
    _In_ ULONG MaxDepth,
    _Outptr_ PULONG* Pids,
    _Out_ PULONG Count
    )
{
    PULONG tree = NULL;
    PULONG visited = NULL;
    ULONG treeCount = 0;
    NTSTATUS status;

    if (!Pids || !Count) return STATUS_INVALID_PARAMETER;
    *Pids = NULL;
    *Count = 0;

    tree = (PULONG)UtHeapAlloc(WK_MAX_TREE_SIZE * sizeof(ULONG));
    visited = (PULONG)UtHeapAlloc(WK_MAX_TREE_SIZE * sizeof(ULONG));
    if (!tree || !visited) {
        if (tree) UtHeapFree(tree);
        if (visited) UtHeapFree(visited);
        return STATUS_NO_MEMORY;
    }

    status = WkBuildTreeRecursive(RootPid, tree, &treeCount, WK_MAX_TREE_SIZE,
                                  MaxDepth, WK_MAX_TREE_DEPTH, visited, 0);
    UtHeapFree(visited);
    if (!NT_SUCCESS(status)) {
        UtHeapFree(tree);
        return status;
    }

    *Pids = tree;
    *Count = treeCount;
    return STATUS_SUCCESS;
}

/**************************************************/
/*               Watchdog 检测与瓦解                */
/**************************************************/

/*
 * WkDetectWatchdogsInternal — 检测单进程 watchdog。
 * 对齐 SS ProcessKiller.cpp L880-931 DetectWatchdogs：
 * (1) 父子同 exe → MutualProcess； (2) 父进程下同 exe 兄弟 >1 → ParentChild。
 * 输出数组为 UtHeapAlloc（本实现单进程最多 2 条，固定分配 2 槽）。
 */
static NTSTATUS
WkDetectWatchdogsInternal(
    _In_ ULONG Pid,
    _Outptr_ PWKD_WATCHDOG_INFO* Out,
    _Out_ PULONG OutCount
    )
{
    WCHAR targetPath[260] = { 0 };
    WCHAR targetName[260] = { 0 };
    WCHAR tmpPath[260] = { 0 };
    ULONG parentPid;
    PULONG siblings = NULL;
    ULONG sibCount = 0, i, sameExeCount = 0;
    PWKD_WATCHDOG_INFO list;
    ULONG n = 0;
    BOOLEAN found = FALSE;

    if (!Out || !OutCount) return STATUS_INVALID_PARAMETER;
    *Out = NULL;
    *OutCount = 0;

    if (WkGetProcessPath(Pid, targetPath, 260) != STATUS_SUCCESS) return STATUS_SUCCESS;
    if (WkGetProcessName(Pid, targetName, 260) != STATUS_SUCCESS) return STATUS_SUCCESS;

    list = (PWKD_WATCHDOG_INFO)UtHeapAlloc(2 * sizeof(WKD_WATCHDOG_INFO));
    if (!list) return STATUS_NO_MEMORY;

    parentPid = WkGetParentProcessId(Pid);
    if (parentPid != 0 && WkIsProcessRunning(parentPid)) {
        if (WkGetProcessPath(parentPid, tmpPath, 260) == STATUS_SUCCESS &&
            _wcsicmp(targetPath, tmpPath) == 0) {
            /* 父子同 exe：自 watchdog（父重启子） */
            RtlZeroMemory(&list[n], sizeof(list[n]));
            list[n].Type = WkWatchdog_MutualProcess;
            list[n].WatcherPid = parentPid;
            list[n].WatchedPid = Pid;
            WkGetProcessName(parentPid, list[n].WatcherName, 260);
            wcsncpy_s(list[n].WatchedName, 260, targetName, _TRUNCATE);
            wcscpy_s(list[n].Mechanism, 128, L"Parent runs same binary as child (self-watchdog)");
            n++;
            found = TRUE;
        }

        /* 父进程下同 exe 兄弟 >1：多实例 watchdog */
        if (WkGetChildrenInternal(parentPid, &siblings, &sibCount) == STATUS_SUCCESS) {
            for (i = 0; i < sibCount; i++) {
                if (siblings[i] == Pid) continue;
                if (WkGetProcessPath(siblings[i], tmpPath, 260) == STATUS_SUCCESS &&
                    _wcsicmp(tmpPath, targetPath) == 0) {
                    sameExeCount++;
                }
            }
            if (sameExeCount > 0 && n < 2) {
                RtlZeroMemory(&list[n], sizeof(list[n]));
                list[n].Type = WkWatchdog_ParentChild;
                list[n].WatcherPid = parentPid;
                list[n].WatchedPid = Pid;
                WkGetProcessName(parentPid, list[n].WatcherName, 260);
                wcsncpy_s(list[n].WatchedName, 260, targetName, _TRUNCATE);
                wcscpy_s(list[n].Mechanism, 128,
                         L"Parent spawns multiple instances of same binary");
                n++;
                found = TRUE;
            }
            UtHeapFree(siblings);
        }
    }

    if (!found) {
        UtHeapFree(list);
        list = NULL;
    } else {
        InterlockedIncrement64(&g_WkKillStats.WatchdogsDetected);
    }

    *Out = list;
    *OutCount = n;
    return STATUS_SUCCESS;
}

/*
 * WkDetectWatchdogGroupsInternal — 对 PID 集合构图求连通分量，分量 >1 构成 watchdog 组。
 * 对齐 SS ProcessKiller.cpp L933-970 DetectWatchdogGroupsInternal。
 * 输出组数组为 UtHeapAlloc，调用方 ProcessManager_DetectWatchdogGroups 释放。
 */
static NTSTATUS
WkDetectWatchdogGroupsInternal(
    _In_ const ULONG* Pids,
    _In_ ULONG PidCount,
    _Outptr_ PWKD_WATCHDOG_GROUP* Out,
    _Out_ PULONG OutCount
    )
{
    PWKD_WATCHDOG_GROUP groups = NULL;
    ULONG groupCount = 0;
    ULONG i, j, k;
    PUCHAR adjMat = NULL;
    PUCHAR visited = NULL;
    PULONG queue = NULL;
    PWKD_WATCHDOG_INFO infos = NULL;
    ULONG infoCount = 0;
    ULONG infoPid = 0;
    BOOLEAN inSet;

    if (!Pids || !Out || !OutCount) return STATUS_INVALID_PARAMETER;
    *Out = NULL;
    *OutCount = 0;
    if (PidCount == 0 || PidCount > WK_MAX_TREE_SIZE) return STATUS_INVALID_PARAMETER;

    adjMat = (PUCHAR)UtHeapAlloc(PidCount * PidCount);
    visited = (PUCHAR)UtHeapAlloc(PidCount);
    queue = (PULONG)UtHeapAlloc(PidCount * sizeof(ULONG));
    groups = (PWKD_WATCHDOG_GROUP)UtHeapAlloc(WK_MAX_WATCHDOG_GROUPS * sizeof(WKD_WATCHDOG_GROUP));
    if (!adjMat || !visited || !queue || !groups) {
        if (adjMat) UtHeapFree(adjMat);
        if (visited) UtHeapFree(visited);
        if (queue) UtHeapFree(queue);
        if (groups) UtHeapFree(groups);
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(adjMat, PidCount * PidCount);
    RtlZeroMemory(visited, PidCount);

    /* 构图：对每个 pid 检测 watchdog，边指向集合内的另一端 */
    for (i = 0; i < PidCount; i++) {
        infoPid = Pids[i];
        infos = NULL;
        infoCount = 0;
        if (WkDetectWatchdogsInternal(infoPid, &infos, &infoCount) == STATUS_SUCCESS && infos) {
            for (k = 0; k < infoCount; k++) {
                for (j = 0; j < PidCount; j++) {
                    if (Pids[j] == infos[k].WatcherPid || Pids[j] == infos[k].WatchedPid) {
                        if (j != i) {
                            adjMat[i * PidCount + j] = 1;
                            adjMat[j * PidCount + i] = 1;
                        }
                    }
                }
            }
            UtHeapFree(infos);
        }
    }

    /* BFS 求连通分量 */
    for (i = 0; i < PidCount; i++) {
        ULONG head = 0, tail = 0;

        if (visited[i]) continue;
        if (!adjMat[i * PidCount + i]) {
            /* 无任何边的孤立节点，不算组 */
            inSet = FALSE;
            for (j = 0; j < PidCount; j++) {
                if (adjMat[i * PidCount + j]) { inSet = TRUE; break; }
            }
            if (!inSet) { visited[i] = 1; continue; }
        }

        visited[i] = 1;
        queue[tail++] = i;

        while (head < tail) {
            ULONG cur = queue[head++];
            for (j = 0; j < PidCount; j++) {
                if (adjMat[cur * PidCount + j] && !visited[j]) {
                    visited[j] = 1;
                    queue[tail++] = j;
                }
            }
        }

        /* tail = 分量大小 */
        if (tail > 1 && groupCount < WK_MAX_WATCHDOG_GROUPS) {
            RtlZeroMemory(&groups[groupCount], sizeof(groups[groupCount]));
            for (j = 0; j < tail && j < WK_MAX_TREE_SIZE; j++) {
                groups[groupCount].ProcessIds[j] = Pids[queue[j]];
                groups[groupCount].ProcessCount = j + 1;
            }
            groups[groupCount].RequiresSimultaneousKill = TRUE;
            groupCount++;
        }
    }

    UtHeapFree(adjMat);
    UtHeapFree(visited);
    UtHeapFree(queue);

    if (groupCount == 0) {
        UtHeapFree(groups);
        groups = NULL;
    }

    *Out = groups;
    *OutCount = groupCount;
    return STATUS_SUCCESS;
}

/*
 * WkDefeatWatchdogGroupInternal — 瓦解 watchdog 组。
 * 对齐 SS ProcessKiller.cpp L972-1041 DefeatWatchdogGroupInternal：
 * Phase1 全部成员先记 creation time + NtSuspendProcess 冻结（sleep 50ms）；
 * Phase2 逐成员 OpenProcess(TERMINATE|QUERY_LIMITED) 复核 creation time 不符拒绝，
 * 再 TerminateProcess(EXIT_CODE_SECURITY)。
 * （SS 用 std::async 并行，C 实现顺序执行；※ 死代码，未接入处置流水线）
 */
static BOOLEAN
WkDefeatWatchdogGroupInternal(
    _In_ PWKD_WATCHDOG_GROUP Group
    )
{
    struct WkGroupMember {
        ULONG Pid;
        FILETIME CreationTime;
        BOOLEAN Valid;
    } members[WK_MAX_TREE_SIZE];
    ULONG memberCount = 0;
    ULONG i;
    BOOLEAN allKilled = TRUE;
    BOOLEAN any = FALSE;

    if (!Group || Group->ProcessCount == 0) return TRUE;
    if (Group->ProcessCount > WK_MAX_TREE_SIZE) return FALSE;

    /* Phase 1：冻结全部成员 + 记录 creation time */
    for (i = 0; i < Group->ProcessCount; i++) {
        HANDLE hProc;
        members[memberCount].Pid = Group->ProcessIds[i];
        members[memberCount].CreationTime.dwLowDateTime = 0;
        members[memberCount].CreationTime.dwHighDateTime = 0;
        members[memberCount].Valid = FALSE;

        hProc = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION,
                            FALSE, Group->ProcessIds[i]);
        if (hProc) {
            FILETIME ct = { 0 };
            if (WkGetProcessCreationTime(hProc, &ct)) {
                members[memberCount].CreationTime = ct;
                members[memberCount].Valid = (ct.dwLowDateTime != 0 || ct.dwHighDateTime != 0);
            }
            NtSuspendProcess(hProc);
            CloseHandle(hProc);
        }
        memberCount++;
    }
    Sleep(50);

    /* Phase 2：终止全部成员，复核 creation time 防 PID 复用 */
    for (i = 0; i < memberCount; i++) {
        HANDLE hProc;
        FILETIME current = { 0 };
        BOOLEAN kill = TRUE;

        hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                            FALSE, members[i].Pid);
        if (!hProc) {
            allKilled = FALSE;
            continue;
        }
        if (members[i].Valid && WkGetProcessCreationTime(hProc, &current)) {
            if (!WkCreationTimesMatch(members[i].CreationTime, current)) {
                printf("[ProcessManager] Watchdog defeat: PID %u reused - refusing to kill\n",
                       members[i].Pid);
                kill = FALSE;
            }
        }
        if (kill && TerminateProcess(hProc, WK_EXIT_CODE_SECURITY)) {
            any = TRUE;
        } else {
            allKilled = FALSE;
        }
        CloseHandle(hProc);
    }

    if (allKilled && any) {
        InterlockedIncrement64(&g_WkKillStats.WatchdogsDefeated);
    }
    return allKilled;
}

/**************************************************/
/*            持久化清理（全部死代码）               */
/**************************************************/

/*
 * WkRemoveServiceInternal — 移除与进程关联的服务。
 * 对齐 SS ProcessKiller.cpp L1514-1587 RemoveServiceInternal：
 * SCM EnumServicesStatusExW 匹配 BinaryPathName 含进程路径 → STOP + DELETE。
 * ※ 死代码：持久化清理未接入隔离/终止流程（KillOptions.CleanPersistence 默认 FALSE，
 *   且无调用者）。全量迁移仅保证功能面覆盖，接入由后续决策决定。
 */
static BOOLEAN
WkRemoveServiceInternal(
    _In_ ULONG Pid
    )
{
    WCHAR processPath[260] = { 0 };
    WCHAR lowerPath[520] = { 0 };
    SC_HANDLE hSCM;
    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    LPBYTE buffer = NULL;
    ENUM_SERVICE_STATUS_PROCESSW* services;
    DWORD i;
    BOOLEAN anyRemoved = FALSE;

    if (WkGetProcessPath(Pid, processPath, 260) != STATUS_SUCCESS) return FALSE;
    wcscpy_s(lowerPath, 520, processPath);
    _wcslwr_s(lowerPath, 520);

    hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return FALSE;

    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);
    if (GetLastError() != ERROR_MORE_DATA || bytesNeeded == 0 || bytesNeeded > 4u * 1024 * 1024) {
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    buffer = (LPBYTE)UtHeapAlloc(bytesNeeded);
    if (!buffer) {
        CloseServiceHandle(hSCM);
        return FALSE;
    }
    resumeHandle = 0;
    if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                               buffer, bytesNeeded, &bytesNeeded, &servicesReturned,
                               &resumeHandle, NULL)) {
        UtHeapFree(buffer);
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    services = (ENUM_SERVICE_STATUS_PROCESSW*)buffer;
    for (i = 0; i < servicesReturned; i++) {
        SC_HANDLE hService;
        DWORD cfgSize = 0;
        LPQUERY_SERVICE_CONFIGW config = NULL;
        SERVICE_STATUS ss;

        if (services[i].ServiceStatusProcess.dwProcessId != Pid) continue;

        hService = OpenServiceW(hSCM, services[i].lpServiceName,
                                SERVICE_STOP | DELETE | SERVICE_QUERY_CONFIG);
        if (!hService) continue;

        QueryServiceConfigW(hService, NULL, 0, &cfgSize);
        if (cfgSize > 0 && cfgSize < 64 * 1024) {
            config = (LPQUERY_SERVICE_CONFIGW)UtHeapAlloc(cfgSize);
            if (config) {
                if (QueryServiceConfigW(hService, config, cfgSize, &cfgSize)) {
                    WCHAR lowerSvc[1024] = { 0 };
                    if (config->lpBinaryPathName) {
                        wcscpy_s(lowerSvc, 1024, config->lpBinaryPathName);
                        _wcslwr_s(lowerSvc, 1024);
                        if (wcsstr(lowerSvc, lowerPath) != NULL) {
                            ControlService(hService, SERVICE_CONTROL_STOP, &ss);
                            if (DeleteService(hService)) {
                                printf("[ProcessManager] Removed malicious service: %ls\n",
                                       services[i].lpServiceName);
                                anyRemoved = TRUE;
                            }
                        }
                    }
                }
                UtHeapFree(config);
            }
        }
        CloseServiceHandle(hService);
    }

    UtHeapFree(buffer);
    CloseServiceHandle(hSCM);
    return anyRemoved;
}

/*
 * WkRemoveScheduledTasksInternal — 移除指向进程路径的计划任务。
 * 对齐 SS ProcessKiller.cpp L1589-1749 RemoveScheduledTasksInternal：
 * COM ITaskService 枚举根目录任务，Action 路径含进程路径 → DeleteTask。
 * 要求调用线程 COM 已初始化（内部 CoInitializeEx(STA) + RPC_E_CHANGED_MODE 容忍）。
 * ※ 死代码：同 RemoveService。
 */
static BOOLEAN
WkRemoveScheduledTasksInternal(
    _In_ ULONG Pid
    )
{
    WCHAR processPath[260] = { 0 };
    WCHAR lowerPath[520] = { 0 };
    HRESULT hr;
    BOOLEAN needUninit = FALSE;
    BOOLEAN anyRemoved = FALSE;
    ITaskService* pService = NULL;
    ITaskFolder* pRootFolder = NULL;
    IRegisteredTaskCollection* pCollection = NULL;
    LONG taskCount = 0, limit;
    LONG i, j;

    if (WkGetProcessPath(Pid, processPath, 260) != STATUS_SUCCESS) return FALSE;
    wcscpy_s(lowerPath, 520, processPath);
    _wcslwr_s(lowerPath, 520);

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return FALSE;
    needUninit = SUCCEEDED(hr);

    hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                          &IID_ITaskService, (void**)&pService);
    if (FAILED(hr) || !pService) goto done;

    /* Connect(4×VT_EMPTY) —— C 兼容：VARIANT 替代 C++ 的 _variant_t() */
    {
        VARIANT vtConnect;
        VariantInit(&vtConnect);   /* vt = VT_EMPTY */
        hr = pService->lpVtbl->Connect(pService, vtConnect, vtConnect, vtConnect, vtConnect);
        VariantClear(&vtConnect);
        if (FAILED(hr)) goto done;
    }

    /* GetFolder(BSTR) —— C 兼容：SysAllocString 替代 _bstr_t */
    {
        BSTR bsRoot = SysAllocString(L"\\");
        if (!bsRoot) goto done;
        hr = pService->lpVtbl->GetFolder(pService, bsRoot, &pRootFolder);
        SysFreeString(bsRoot);
        if (FAILED(hr) || !pRootFolder) goto done;
    }

    hr = pRootFolder->lpVtbl->GetTasks(pRootFolder, 0, &pCollection);
    if (FAILED(hr) || !pCollection) goto done;

    pCollection->lpVtbl->get_Count(pCollection, &taskCount);
    limit = (taskCount < 4096) ? taskCount : 4096;

    for (i = 1; i <= limit; i++) {
        IRegisteredTask* pTask = NULL;
        ITaskDefinition* pDef = NULL;
        IActionCollection* pActions = NULL;
        LONG actionCount = 0;

        /* get_Item(VARIANT VT_I4) —— C 兼容 */
        {
            VARIANT vtIndex;
            VariantInit(&vtIndex);
            vtIndex.vt = VT_I4;
            vtIndex.lVal = i;
            hr = pCollection->lpVtbl->get_Item(pCollection, vtIndex, &pTask);
            VariantClear(&vtIndex);
            if (FAILED(hr) || !pTask) continue;
        }

        pTask->lpVtbl->get_Definition(pTask, &pDef);
        if (!pDef) { pTask->lpVtbl->Release(pTask); continue; }

        pDef->lpVtbl->get_Actions(pDef, &pActions);
        if (!pActions) { pDef->lpVtbl->Release(pDef); pTask->lpVtbl->Release(pTask); continue; }

        pActions->lpVtbl->get_Count(pActions, &actionCount);
        for (j = 1; j <= actionCount; j++) {
            IAction* pAction = NULL;
            TASK_ACTION_TYPE actionType;

            pActions->lpVtbl->get_Item(pActions, j, &pAction);
            if (!pAction) continue;
            pAction->lpVtbl->get_Type(pAction, &actionType);

            if (actionType == TASK_ACTION_EXEC) {
                IExecAction* pExec = NULL;
                /* C 兼容：IID_IExecAction 全局变量替代 IID_PPV_ARGS(__uuidof) */
                hr = pAction->lpVtbl->QueryInterface(pAction, &IID_IExecAction, (void**)&pExec);
                if (SUCCEEDED(hr) && pExec) {
                    BSTR bstrPath = NULL;
                    pExec->lpVtbl->get_Path(pExec, &bstrPath);
                    if (bstrPath) {
                        WCHAR lowerAct[1024] = { 0 };
                        wcscpy_s(lowerAct, 1024, bstrPath);
                        _wcslwr_s(lowerAct, 1024);
                        if (wcsstr(lowerAct, lowerPath) != NULL) {
                            BSTR bstrName = NULL;
                            pTask->lpVtbl->get_Name(pTask, &bstrName);
                            if (bstrName) {
                                hr = pRootFolder->lpVtbl->DeleteTask(pRootFolder, bstrName, 0);   /* 直接传 BSTR */
                                if (SUCCEEDED(hr)) {
                                    printf("[ProcessManager] Removed malicious scheduled task: %ls\n",
                                           bstrName);
                                    anyRemoved = TRUE;
                                }
                                SysFreeString(bstrName);
                            }
                        }
                        SysFreeString(bstrPath);
                    }
                    pExec->lpVtbl->Release(pExec);
                }
            }
            pAction->lpVtbl->Release(pAction);
        }

        pActions->lpVtbl->Release(pActions);
        pDef->lpVtbl->Release(pDef);
        pTask->lpVtbl->Release(pTask);
    }

done:
    if (pCollection) pCollection->lpVtbl->Release(pCollection);
    if (pRootFolder) pRootFolder->lpVtbl->Release(pRootFolder);
    if (pService) pService->lpVtbl->Release(pService);
    if (needUninit) CoUninitialize();
    return anyRemoved;
}

/*
 * WkRemoveRegistryPersistenceInternal — 移除注册表持久化（Run/RunOnce/IFEO）。
 * 对齐 SS ProcessKiller.cpp L1751-1829 RemoveRegistryPersistenceInternal：
 * HKLM/HKCU/Wow6432Node 的 Run/RunOnce 枚举 REG_SZ/REG_EXPAND_SZ 匹配路径删除；
 * IFEO Debugger 值匹配路径删除。
 * ※ 死代码：同 RemoveService。
 */
static BOOLEAN
WkRemoveRegistryPersistenceInternal(
    _In_ ULONG Pid
    )
{
    static const struct {
        HKEY Root;
        const WCHAR* Path;
    } locs[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    };
    WCHAR processPath[260] = { 0 };
    WCHAR lowerPath[520] = { 0 };
    WCHAR exeName[260] = { 0 };
    ULONG i;
    BOOLEAN anyRemoved = FALSE;

    if (WkGetProcessPath(Pid, processPath, 260) != STATUS_SUCCESS) return FALSE;
    wcscpy_s(lowerPath, 520, processPath);
    _wcslwr_s(lowerPath, 520);

    for (i = 0; i < sizeof(locs) / sizeof(locs[0]); i++) {
        HKEY hKey = NULL;
        DWORD idx = 0;
        WCHAR toDelete[16][512];
        ULONG delCount = 0;

        if (RegOpenKeyExW(locs[i].Root, locs[i].Path, 0, KEY_READ | KEY_WRITE, &hKey)
            != ERROR_SUCCESS) {
            continue;
        }

        for (;;) {
            WCHAR vName[512];
            WCHAR vData[2048];
            DWORD vNameLen = 512;
            DWORD vDataSize = sizeof(vData);
            DWORD vType = 0;
            LONG r;

            vName[0] = L'\0';
            r = RegEnumValueW(hKey, idx, vName, &vNameLen, NULL, &vType,
                              (LPBYTE)vData, &vDataSize);
            if (r != ERROR_SUCCESS) break;

            if ((vType == REG_SZ || vType == REG_EXPAND_SZ) && delCount < 16) {
                WCHAR lowerData[2048] = { 0 };
                wcscpy_s(lowerData, 2048, vData);
                _wcslwr_s(lowerData, 2048);
                if (wcsstr(lowerData, lowerPath) != NULL) {
                    wcscpy_s(toDelete[delCount], 512, vName);
                    delCount++;
                }
            }
            idx++;
        }

        {
            ULONG d;
            for (d = 0; d < delCount; d++) {
                if (RegDeleteValueW(hKey, toDelete[d]) == ERROR_SUCCESS) {
                    printf("[ProcessManager] Removed registry persistence: %ls\\%ls\n",
                           locs[i].Path, toDelete[d]);
                    anyRemoved = TRUE;
                }
            }
        }
        RegCloseKey(hKey);
    }

    /* IFEO：Debugger 值指向进程路径 */
    if (WkGetProcessName(Pid, exeName, 260) == STATUS_SUCCESS) {
        WCHAR ifeo[520] = { 0 };
        HKEY hKey;

        _snwprintf_s(ifeo, 520, _TRUNCATE,
                     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                     L"Image File Execution Options\\%s", exeName);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ifeo, 0, KEY_READ | KEY_WRITE, &hKey)
            == ERROR_SUCCESS) {
            WCHAR dbg[1024] = { 0 };
            DWORD dbgSz = sizeof(dbg);
            DWORD type = 0;
            if (RegQueryValueExW(hKey, L"Debugger", NULL, &type, (LPBYTE)dbg, &dbgSz)
                == ERROR_SUCCESS) {
                WCHAR lowerDbg[1024] = { 0 };
                wcscpy_s(lowerDbg, 1024, dbg);
                _wcslwr_s(lowerDbg, 1024);
                if (wcsstr(lowerDbg, lowerPath) != NULL) {
                    if (RegDeleteValueW(hKey, L"Debugger") == ERROR_SUCCESS) {
                        printf("[ProcessManager] Removed IFEO persistence for %ls\n", exeName);
                        anyRemoved = TRUE;
                    }
                }
            }
            RegCloseKey(hKey);
        }
    }

    return anyRemoved;
}

/*
 * WkRemoveProtectionInternal — 清除进程保护。
 * 对齐 SS ProcessKiller.cpp L1831-1868 RemoveProtectionInternal：
 * 用户态清 BreakOnTermination；PPL 剥离需驱动（※ 死代码分支）。
 */
static BOOLEAN
WkRemoveProtectionInternal(
    _In_ ULONG Pid
    )
{
    HANDLE hProcess;
    ULONG breakOnTerm = 0;
    NTSTATUS status;

    (void)WkEnableDebugPrivilege();
    hProcess = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, FALSE, Pid);
    if (!hProcess) return FALSE;

    status = NtSetInformationProcess(hProcess, ProcessBreakOnTermination,
                                     &breakOnTerm, sizeof(breakOnTerm));
    CloseHandle(hProcess);

    if (NT_SUCCESS(status)) {
        printf("[ProcessManager] Cleared BreakOnTermination for pid %u\n", Pid);
        return TRUE;
    }
    /* ※ 死代码：BreakOnTermination 清除失败（多为 PPL）时需驱动从 ring-0 剥离，
     *   WkD 当前无等价驱动通道。 */
    return FALSE;
}

/**************************************************/
/*                 回调调用辅助                     */
/*   快照式调用避免锁重入死锁（对齐 SS Invoke* 快照模式） */
/**************************************************/

static BOOLEAN
WkInvokePreKillCallbacks(
    _In_ ULONG Pid,
    _In_ PCWKD_KILL_OPTIONS Options
    )
{
    ULONG i;

    for (i = 0; i < WK_CALLBACK_MAX; i++) {
        if (g_WkCallbacks[i].Id != 0 && g_WkCallbacks[i].Kind == WkCallback_PreKill) {
            WKD_PRE_KILL_CALLBACK cb = (WKD_PRE_KILL_CALLBACK)g_WkCallbacks[i].Func;
            if (cb && !cb(Pid, Options)) return FALSE;
        }
    }
    return TRUE;
}

static VOID
WkInvokePostKillCallbacks(
    _In_ PWKD_PROCESS_KILL_INFO Info
    )
{
    ULONG i;

    if (!Info) return;
    for (i = 0; i < WK_CALLBACK_MAX; i++) {
        if (g_WkCallbacks[i].Id != 0 && g_WkCallbacks[i].Kind == WkCallback_PostKill) {
            WKD_POST_KILL_CALLBACK cb = (WKD_POST_KILL_CALLBACK)g_WkCallbacks[i].Func;
            if (cb) cb(Info);
        }
    }
}

static VOID
WkInvokeTreeProgressCallbacks(
    _In_ ULONG Current,
    _In_ ULONG Total,
    _In_ PWKD_PROCESS_KILL_INFO Info
    )
{
    ULONG i;

    for (i = 0; i < WK_CALLBACK_MAX; i++) {
        if (g_WkCallbacks[i].Id != 0 && g_WkCallbacks[i].Kind == WkCallback_TreeProgress) {
            WKD_TREE_PROGRESS_CALLBACK cb = (WKD_TREE_PROGRESS_CALLBACK)g_WkCallbacks[i].Func;
            if (cb) cb(Current, Total, Info);
        }
    }
}

static VOID
WkInvokeWatchdogCallbacks(
    _In_ PWKD_WATCHDOG_INFO Watchdog
    )
{
    ULONG i;

    if (!Watchdog) return;
    for (i = 0; i < WK_CALLBACK_MAX; i++) {
        if (g_WkCallbacks[i].Id != 0 && g_WkCallbacks[i].Kind == WkCallback_Watchdog) {
            WKD_WATCHDOG_CALLBACK cb = (WKD_WATCHDOG_CALLBACK)g_WkCallbacks[i].Func;
            if (cb) cb(Watchdog);
        }
    }
}

static UINT64
WkRegisterCallback(
    _In_ WKD_CALLBACK_KIND Kind,
    _In_ PVOID Func
    )
{
    ULONG i;

    if (!Func) return 0;
    for (i = 0; i < WK_CALLBACK_MAX; i++) {
        if (g_WkCallbacks[i].Id == 0) {
            g_WkCallbacks[i].Id = g_WkNextCallbackId++;
            g_WkCallbacks[i].Kind = Kind;
            g_WkCallbacks[i].Func = Func;
            g_WkCallbackCount++;
            return g_WkCallbacks[i].Id;
        }
    }
    return 0;
}

static VOID
WkUnregisterCallback(
    _In_ UINT64 CallbackId
    )
{
    ULONG i;

    for (i = 0; i < WK_CALLBACK_MAX; i++) {
        if (g_WkCallbacks[i].Id == CallbackId) {
            g_WkCallbacks[i].Id = 0;
            g_WkCallbacks[i].Func = NULL;
            if (g_WkCallbackCount > 0) g_WkCallbackCount--;
            return;
        }
    }
}

/**************************************************/
/*               KillOptions 工厂                   */
/*  对齐 SS CreateStandard/Aggressive/MalwareKill/Forensic */
/**************************************************/

VOID
WkKillOptions_Standard(
    _Out_ PWKD_KILL_OPTIONS Options
    )
{
    if (!Options) return;
    RtlZeroMemory(Options, sizeof(*Options));
    Options->PreferredMethod = WkKillMethod_Auto;
    Options->TimeoutMs = WK_KILL_TIMEOUT_MS_DEFAULT;
    Options->MaxRetries = WK_MAX_RETRY_ATTEMPTS;
    Options->EscalateOnFailure = TRUE;
    Options->KillTree = FALSE;
    Options->TreeStrategy = WkTreeStrategy_BottomUp;
    Options->DefeatWatchdogs = FALSE;
    Options->CleanPersistence = FALSE;
    Options->VerifyTermination = TRUE;
    Options->PreserveEvidence = FALSE;
    Options->AllowCritical = FALSE;
    Options->ExitCode = WK_EXIT_CODE_KILLED;
}

VOID
WkKillOptions_Aggressive(
    _Out_ PWKD_KILL_OPTIONS Options
    )
{
    if (!Options) return;
    RtlZeroMemory(Options, sizeof(*Options));
    Options->PreferredMethod = WkKillMethod_Auto;
    Options->TimeoutMs = 10000;
    Options->MaxRetries = 5;
    Options->EscalateOnFailure = TRUE;
    Options->KillTree = TRUE;
    Options->TreeStrategy = WkTreeStrategy_BottomUp;
    Options->DefeatWatchdogs = TRUE;
    Options->CleanPersistence = FALSE;
    Options->VerifyTermination = TRUE;
    Options->PreserveEvidence = FALSE;
    Options->AllowCritical = FALSE;
    Options->ExitCode = WK_EXIT_CODE_KILLED;
}

VOID
WkKillOptions_MalwareKill(
    _Out_ PWKD_KILL_OPTIONS Options
    )
{
    if (!Options) return;
    RtlZeroMemory(Options, sizeof(*Options));
    Options->PreferredMethod = WkKillMethod_Auto;
    Options->TimeoutMs = WK_TREE_KILL_TIMEOUT_MS;
    Options->MaxRetries = WK_MAX_RETRY_ATTEMPTS;
    Options->EscalateOnFailure = TRUE;
    Options->KillTree = TRUE;
    Options->TreeStrategy = WkTreeStrategy_Simultaneous;
    Options->DefeatWatchdogs = TRUE;
    Options->CleanPersistence = TRUE;
    Options->VerifyTermination = TRUE;
    Options->PreserveEvidence = TRUE;
    Options->AllowCritical = FALSE;
    Options->ExitCode = WK_EXIT_CODE_SECURITY;
}

VOID
WkKillOptions_Forensic(
    _Out_ PWKD_KILL_OPTIONS Options
    )
{
    if (!Options) return;
    RtlZeroMemory(Options, sizeof(*Options));
    Options->PreferredMethod = WkKillMethod_Freeze;
    Options->TimeoutMs = WK_KILL_TIMEOUT_MS_DEFAULT;
    Options->MaxRetries = 1;
    Options->EscalateOnFailure = FALSE;
    Options->KillTree = FALSE;
    Options->TreeStrategy = WkTreeStrategy_BottomUp;
    Options->DefeatWatchdogs = FALSE;
    Options->CleanPersistence = FALSE;
    Options->VerifyTermination = TRUE;
    Options->PreserveEvidence = TRUE;
    Options->AllowCritical = FALSE;
    Options->ExitCode = WK_EXIT_CODE_KILLED;
}

/**************************************************/
/*                 终止核心实现                     */
/**************************************************/

typedef struct _WK_KILL_REQ_PARAM {
    ULONG Pid;
} WK_KILL_REQ_PARAM;

/* fire-and-forget 终止线程：执行 kill → 回复 UI（0x2004）。 */
static DWORD WINAPI
WkKillRequestThreadProc(
    _In_ LPVOID Param
    )
{
    WK_KILL_REQ_PARAM* p = (WK_KILL_REQ_PARAM*)Param;
    WKD_PROCESS_KILL_INFO info;
    NTSTATUS st;
    BOOLEAN ok;
    PWKD_ALPC_SERVER server;
    ULONG pid;

    if (!p) return 0;
    pid = p->Pid;
    UtHeapFree(p);

    st = ProcessManager_KillProcessEx(pid, NULL, &info);
    ok = NT_SUCCESS(st);

    server = (WkDefenderAgent.NotificationManager != NULL)
             ? WkDefenderAgent.NotificationManager->AlpcServer : NULL;
    if (server) {
        /* 回复 0x2004 KillProcessResp：状态字节写 ConnectionType 低位（对齐 UI） */
        WkdAlpcSendToUiEx(server, WkdAlpcMsg_KillProcessResp, NULL, 0, ok ? 0 : 1);
    }
    return 0;
}

NTSTATUS
ProcessManager_KillProcessAsync(
    _In_ DWORD Pid
    )
{
    WK_KILL_REQ_PARAM* p;
    HANDLE h;

    if (!g_ProcessManager.Initialized) return STATUS_INVALID_PARAMETER;

    p = (WK_KILL_REQ_PARAM*)UtHeapAlloc(sizeof(WK_KILL_REQ_PARAM));
    if (!p) return STATUS_INSUFFICIENT_RESOURCES;
    p->Pid = Pid;

    h = CreateThread(NULL, 0, WkKillRequestThreadProc, p, 0, NULL);
    if (h) {
        CloseHandle(h);
        return STATUS_SUCCESS;
    }
    UtHeapFree(p);
    return STATUS_UNSUCCESSFUL;
}

/*
 * ProcessManager_KillProcessEx — 终止进程核心。
 * 对齐 SS ProcessKiller.cpp L517-637 TerminateEx：
 * reserved → criticality → 信任表 → protection → pre-callback → preserve →
 * capture creation → Escalating/Auto → verify → post-callback。
 */
NTSTATUS
ProcessManager_KillProcessEx(
    _In_ DWORD Pid,
    _In_opt_ PCWKD_KILL_OPTIONS Options,
    _Out_opt_ PWKD_PROCESS_KILL_INFO OutInfo
    )
{
    WKD_KILL_OPTIONS opts;
    WKD_PROCESS_KILL_INFO info;
    FILETIME capturedCreation = { 0 };
    WKD_KILL_RESULT result;
    WKD_PROCESS_CRITICALITY criticality;
    BOOLEAN trusted = FALSE;
    ULONG i;
    BOOLEAN succeeded;

    if (!g_ProcessManager.Initialized) return STATUS_INVALID_PARAMETER;

    if (Options == NULL) {
        WkKillOptions_Standard(&opts);
        Options = &opts;
    }

    RtlZeroMemory(&info, sizeof(info));
    info.ProcessId = Pid;
    info.MethodUsed = Options->PreferredMethod;
    GetSystemTimeAsFileTime((PFILETIME)&info.StartTime);   /* 对齐 SS TerminateEx 的 startTime */

    if (WkIsReservedPid(Pid)) {
        info.Result = WkKillResult_Critical;
        wcscpy_s(info.ErrorMessage, 256,
                 (Pid == GetCurrentProcessId())
                 ? L"Cannot terminate own process (self-protection)"
                 : L"Cannot terminate system reserved process (PID 0 or 4)");
        InterlockedIncrement64(&g_WkKillStats.CriticalProcessesBlocked);
        succeeded = FALSE;
        goto out;
    }

    InterlockedIncrement64(&g_WkKillStats.TotalKillAttempts);

    WkGetProcessName(Pid, info.ProcessName, 260);
    WkGetProcessPath(Pid, info.ProcessPath, 260);
    info.ParentProcessId = WkGetParentProcessId(Pid);

    if (!WkIsProcessRunning(Pid)) {
        info.Result = WkKillResult_AlreadyDead;
        succeeded = TRUE;
        goto out;
    }

    criticality = WkGetCriticalityInternal(Pid);
    if (criticality >= WkCriticality_Critical && !Options->AllowCritical) {
        info.Result = WkKillResult_Critical;
        wcscpy_s(info.ErrorMessage, 256, L"Process is critical to system stability");
        InterlockedIncrement64(&g_WkKillStats.CriticalProcessesBlocked);
        printf("[ProcessManager] Blocked termination of critical process: %ls (pid=%u)\n",
               info.ProcessName, Pid);
        succeeded = FALSE;
        goto out;
    }

    /* 信任表检查（替代 SS WhitelistStore） */
    for (i = 0; i < g_WkTrustedPidCount; i++) {
        if (g_WkTrustedPids[i] == Pid) {
            trusted = TRUE;
            break;
        }
    }
    if (trusted) {
        info.Result = WkKillResult_Blocked;
        wcscpy_s(info.ErrorMessage, 256, L"Process is trusted");
        succeeded = FALSE;
        goto out;
    }

    WkGetProtectionInfoInternal(Pid, &info.ProtectionInfo);
    if (info.ProtectionInfo.Level != WkProtection_None) {
        InterlockedIncrement64(&g_WkKillStats.ProtectedProcessesEncountered);
    }

    if (!WkInvokePreKillCallbacks(Pid, Options)) {
        info.Result = WkKillResult_Blocked;
        wcscpy_s(info.ErrorMessage, 256, L"Blocked by pre-kill callback");
        succeeded = FALSE;
        goto out;
    }

    if (Options->PreserveEvidence) {
        WkPreserveEvidence(Pid, &info);
    }

    /* 捕获 creation time 供各级 kill 做 TOCTOU 比对 */
    {
        HANDLE hProbe = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);
        if (hProbe) {
            WkGetProcessCreationTime(hProbe, &capturedCreation);
            CloseHandle(hProbe);
        }
    }

    if (Options->PreferredMethod == WkKillMethod_Auto) {
        result = WkEscalatingKill(Pid, Options, &info, capturedCreation);
    } else {
        result = WkKillWithMethod(Pid, Options->PreferredMethod, Options, &info, capturedCreation);
    }
    info.Result = result;

    if (Options->VerifyTermination && result == WkKillResult_Success) {
        if (!WkVerifyTerminationInternal(Pid, Options->TimeoutMs)) {
            info.Result = WkKillResult_Timeout;
            InterlockedIncrement64(&g_WkKillStats.TimeoutErrors);
            printf("[ProcessManager] Termination verification timed out for pid %u\n", Pid);
        }
    }

    if (info.Result == WkKillResult_Success || info.Result == WkKillResult_AlreadyDead) {
        InterlockedIncrement64(&g_WkKillStats.SuccessfulKills);
        /* 状态记账：进程域树节点置 Terminated（统一重构 2026-08-15 替代哈希表） */
        {
            PWKD_PROCESS node = NULL;
            NTSTATUS lookupStatus = PsLookupWkdProcessByStrictProcessId(&WkdProcessTree, (HANDLE)Pid, NULL, &node);
            if (NT_SUCCESS(lookupStatus) && node) {
                node->Status = DefProcessStatus_Terminated;
                node->Alive = FALSE;
                WkQuerySystemTime(&node->ExitTime);
                PsDereferenceWkdProcess(node);   /* 归还查找 pin */
            }
        }
        succeeded = TRUE;
    } else {
        InterlockedIncrement64(&g_WkKillStats.FailedKills);
        succeeded = FALSE;
    }

    WkInvokePostKillCallbacks(&info);

out:
    GetSystemTimeAsFileTime((PFILETIME)&info.KillTime);
    if (OutInfo) *OutInfo = info;
    return succeeded ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS
ProcessManager_KillProcess(
    _In_ DWORD Pid
    )
{
    return ProcessManager_KillProcessEx(Pid, NULL, NULL);
}

/**************************************************/
/*                 隔离/信任                        */
/**************************************************/

/* 隔离语义：挂起进程 + 哈希表节点标记 ISOLATED（※ 消息接线待 UI 阶段） */
NTSTATUS
ProcessManager_IsolateProcess(
    _In_ DWORD Pid
    )
{
    WKD_SUSPEND_RESULT sr;
    PWKD_PROCESS node;

    if (!g_ProcessManager.Initialized) return STATUS_INVALID_PARAMETER;

    sr = ProcessManager_SuspendProcess(Pid);
    if (sr == WkSuspendResult_NotFound || sr == WkSuspendResult_AccessDenied) {
        return STATUS_UNSUCCESSFUL;
    }

    node = NULL;
    NTSTATUS lookupStatus = PsLookupWkdProcessByStrictProcessId(&WkdProcessTree, (HANDLE)Pid, NULL, &node);
    if (NT_SUCCESS(lookupStatus) && node) {
        node->MonitorFlags |= WKD_PROCESS_MONITOR_ISOLATED;
        PsDereferenceWkdProcess(node);   /* 归还查找 pin */
    }
    printf("[ProcessManager] Process isolated: PID=%u\n", Pid);
    return STATUS_SUCCESS;
}

/* 信任语义：加入进程内信任表，GetCriticality 命中时降级 Normal（※ 替代 SS WhitelistStore） */
NTSTATUS
ProcessManager_TrustProcess(
    _In_ DWORD Pid
    )
{
    ULONG i;

    if (!g_ProcessManager.Initialized) return STATUS_INVALID_PARAMETER;

    for (i = 0; i < g_WkTrustedPidCount; i++) {
        if (g_WkTrustedPids[i] == Pid) return STATUS_SUCCESS;
    }
    if (g_WkTrustedPidCount >= WK_TRUST_TABLE_MAX) return STATUS_INSUFFICIENT_RESOURCES;

    g_WkTrustedPids[g_WkTrustedPidCount++] = Pid;
    printf("[ProcessManager] Process trusted: PID=%u\n", Pid);
    return STATUS_SUCCESS;
}

/**************************************************/
/*             挂起/恢复/冻结/判挂起                */
/**************************************************/

/* 对齐 SS ProcessKiller.cpp L755-793 SuspendProcessEx */
WKD_SUSPEND_RESULT
ProcessManager_SuspendProcess(
    _In_ DWORD Pid
    )
{
    HANDLE hProcess;
    NTSTATUS status;
    PULONG tids = NULL;
    ULONG tidCount = 0, i, suspendedCount = 0;

    InterlockedIncrement64(&g_WkKillStats.SuspendAttempts);

    hProcess = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, FALSE, Pid);
    if (!hProcess) {
        return (GetLastError() == ERROR_ACCESS_DENIED)
               ? WkSuspendResult_AccessDenied : WkSuspendResult_NotFound;
    }

    status = NtSuspendProcess(hProcess);
    CloseHandle(hProcess);
    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_WkKillStats.SuccessfulSuspends);
        return WkSuspendResult_Success;
    }

    /* 回退：逐线程 SuspendThread */
    if (WkGetThreadIds(Pid, &tids, &tidCount) != STATUS_SUCCESS || tidCount == 0) {
        if (tids) UtHeapFree(tids);
        return WkSuspendResult_NotFound;
    }
    for (i = 0; i < tidCount; i++) {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                                    FALSE, tids[i]);
        if (hThread) {
            if (SuspendThread(hThread) != (DWORD)-1) suspendedCount++;
            CloseHandle(hThread);
        }
    }
    UtHeapFree(tids);

    if (suspendedCount == tidCount) {
        InterlockedIncrement64(&g_WkKillStats.SuccessfulSuspends);
        return WkSuspendResult_Success;
    }
    return (suspendedCount > 0) ? WkSuspendResult_PartialSuccess : WkSuspendResult_Failed;
}

/* 对齐 SS ProcessKiller.cpp L795-805 ResumeProcessEx */
BOOLEAN
ProcessManager_ResumeProcess(
    _In_ DWORD Pid
    )
{
    HANDLE hProcess;
    NTSTATUS status;

    InterlockedIncrement64(&g_WkKillStats.ResumeAttempts);

    hProcess = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, FALSE, Pid);
    if (!hProcess) return FALSE;
    status = NtResumeProcess(hProcess);
    CloseHandle(hProcess);
    return NT_SUCCESS(status);
}

WKD_SUSPEND_RESULT
ProcessManager_FreezeProcess(
    _In_ DWORD Pid
    )
{
    return ProcessManager_SuspendProcess(Pid);
}

BOOLEAN
ProcessManager_ThawProcess(
    _In_ DWORD Pid
    )
{
    return ProcessManager_ResumeProcess(Pid);
}

LONG NTAPI QueryThreadSuspendCount(HANDLE ThreadHandle, PULONG SuspendCount)
{
    /* 线程挂起计数信息类（未文档化，稳定值 = 25）：
     * NtQueryInformationThread(ThreadSuspendCount) 返回 ULONG 挂起计数 */
    NTSTATUS st;
    ULONG Count = 0;

    if (ThreadHandle == NULL || SuspendCount == NULL) {
        return FALSE;
    }
    st = NtQueryInformationThread(ThreadHandle,
                                  (THREADINFOCLASS)25,   /* ThreadSuspendCount */
                                  &Count, sizeof(Count), NULL);
    if (!NT_SUCCESS(st)) {
        return FALSE;
    }
    *SuspendCount = Count;
    return TRUE;
}

/* 对齐 SS ProcessUtils.cpp L1820-1856：全部线程 suspendCount>0 才算挂起 */
BOOLEAN
ProcessManager_IsProcessSuspended(
    _In_ DWORD Pid
    )
{
    HANDLE hSnap;
    THREADENTRY32 te;
    BOOLEAN anyThread = FALSE;
    BOOLEAN anyRunning = FALSE;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;

    te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == Pid) {
                HANDLE hThread;

                anyThread = TRUE;
                hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread) {
                    ULONG suspendCount = 0;
                    if (!QueryThreadSuspendCount(hThread, &suspendCount) || suspendCount == 0) {
                        anyRunning = TRUE;
                    }
                    CloseHandle(hThread);
                } else {
                    anyRunning = TRUE;
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return anyThread && !anyRunning;
}

/**************************************************/
/*                进程树公共函数                    */
/**************************************************/

NTSTATUS
ProcessManager_GetProcessTree(
    _In_ DWORD RootPid,
    _In_ ULONG MaxDepth,
    _Outptr_ PULONG* Pids,
    _Out_ PULONG Count
    )
{
    return WkGetProcessTreeInternal(RootPid, MaxDepth, Pids, Count);
}

NTSTATUS
ProcessManager_GetChildren(
    _In_ DWORD Pid,
    _In_ BOOLEAN Recursive,
    _Outptr_ PULONG* Pids,
    _Out_ PULONG Count
    )
{
    PULONG tree = NULL;
    ULONG n = 0;
    NTSTATUS status;

    if (!Pids || !Count) return STATUS_INVALID_PARAMETER;
    *Pids = NULL;
    *Count = 0;

    if (!Recursive) {
        return WkGetChildrenInternal(Pid, Pids, Count);
    }

    status = WkGetProcessTreeInternal(Pid, WK_MAX_TREE_DEPTH, &tree, &n);
    if (!NT_SUCCESS(status)) return status;
    if (n > 0 && tree[0] == Pid) {
        /* 去掉根（对齐 SS GetChildren recursive） */
        memmove(tree, tree + 1, (n - 1) * sizeof(ULONG));
        n--;
    }
    *Pids = tree;
    *Count = n;
    return STATUS_SUCCESS;
}

/*
 * ProcessManager_TerminateProcessTree — 进程树终止。
 * 对齐 SS ProcessKiller.cpp L639-749 TerminateTreeEx。
 */
NTSTATUS
ProcessManager_TerminateProcessTree(
    _In_ DWORD RootPid,
    _In_opt_ PCWKD_KILL_OPTIONS Options,
    _Out_ PWKD_TREE_KILL_INFO OutInfo
    )
{
    WKD_KILL_OPTIONS opts;
    PULONG tree = NULL;
    ULONG treeCount = 0;
    PULONG killOrder = NULL;
    ULONG orderCount = 0;
    WKD_TREE_KILL_INFO info;
    NTSTATUS status;
    ULONG i;

    if (!OutInfo) return STATUS_INVALID_PARAMETER;
    if (Options == NULL) {
        WkKillOptions_Standard(&opts);
        Options = &opts;
    }

    RtlZeroMemory(&info, sizeof(info));
    info.RootPid = RootPid;
    WkGetProcessName(RootPid, info.RootName, 260);
    WkQuerySystemTime(&info.StartTime);
    info.Strategy = Options->TreeStrategy;
    InterlockedIncrement64(&g_WkKillStats.TreeKillAttempts);

    status = WkGetProcessTreeInternal(RootPid, WK_MAX_TREE_DEPTH, &tree, &treeCount);
    if (!NT_SUCCESS(status)) {
        info.OverallResult = WkKillResult_Failed;
        goto out;
    }
    info.TotalProcesses = treeCount;
    if (treeCount == 0) {
        info.OverallResult = WkKillResult_NotFound;
        goto out;
    }

    killOrder = (PULONG)UtHeapAlloc(treeCount * sizeof(ULONG));
    if (!killOrder) {
        info.OverallResult = WkKillResult_Failed;
        goto out;
    }
    memcpy(killOrder, tree, treeCount * sizeof(ULONG));
    orderCount = treeCount;

    switch (Options->TreeStrategy) {
    case WkTreeStrategy_BottomUp:
        for (i = 0; i < orderCount / 2; i++) {
            ULONG t = killOrder[i];
            killOrder[i] = killOrder[orderCount - 1 - i];
            killOrder[orderCount - 1 - i] = t;
        }
        break;

    case WkTreeStrategy_TopDown:
        break;

    case WkTreeStrategy_Simultaneous:
        /* 先全部冻结，再逐个终止（C 顺序版；SS 用 std::async 并行） */
        for (i = 0; i < orderCount; i++) {
            HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION,
                                   FALSE, killOrder[i]);
            if (h) {
                NtSuspendProcess(h);
                CloseHandle(h);
            }
        }
        Sleep(50);
        break;

    case WkTreeStrategy_Selective:
        {
            ULONG w = 0;
            for (i = 0; i < orderCount; i++) {
                if (!WkIsCriticalProcessInternal(killOrder[i])) {
                    killOrder[w++] = killOrder[i];
                } else {
                    info.SkippedProcesses++;
                }
            }
            orderCount = w;
        }
        break;

    default:
        break;
    }

    info.Results = (PWKD_TREE_KILL_NODE)UtHeapAlloc(treeCount * sizeof(WKD_TREE_KILL_NODE));
    if (!info.Results) {
        info.OverallResult = WkKillResult_Failed;
        goto out;
    }
    RtlZeroMemory(info.Results, treeCount * sizeof(WKD_TREE_KILL_NODE));

    for (i = 0; i < orderCount; i++) {
        WKD_PROCESS_KILL_INFO ki;

        RtlZeroMemory(&ki, sizeof(ki));
        ProcessManager_KillProcessEx(killOrder[i], Options, &ki);
        info.Results[i].Pid = killOrder[i];
        info.Results[i].Result = ki.Result;
        info.Results[i].MethodUsed = ki.MethodUsed;

        if (ki.Result == WkKillResult_Success || ki.Result == WkKillResult_AlreadyDead) {
            info.KilledProcesses++;
            InterlockedIncrement64(&g_WkKillStats.ProcessesInTreesKilled);
        } else if (ki.Result == WkKillResult_Critical || ki.Result == WkKillResult_Blocked) {
            info.SkippedProcesses++;
        } else {
            info.FailedProcesses++;
        }
        WkInvokeTreeProgressCallbacks(i + 1, orderCount, &ki);
    }

    if (info.SkippedProcesses >= info.TotalProcesses ||
        info.KilledProcesses >= (info.TotalProcesses - info.SkippedProcesses)) {
        info.OverallResult = WkKillResult_Success;
    } else if (info.KilledProcesses > 0) {
        info.OverallResult = WkKillResult_PartialSuccess;
    } else {
        info.OverallResult = WkKillResult_Failed;
    }

out:
    if (tree) UtHeapFree(tree);
    if (killOrder) UtHeapFree(killOrder);
    WkQuerySystemTime(&info.EndTime);
    *OutInfo = info;
    return STATUS_SUCCESS;
}

VOID
ProcessManager_FreeTreeKillInfo(
    _Inout_ PWKD_TREE_KILL_INFO Info
    )
{
    if (Info && Info->Results) {
        UtHeapFree(Info->Results);
        Info->Results = NULL;
    }
}

/**************************************************/
/*                保护分析公共函数                  */
/**************************************************/

NTSTATUS
ProcessManager_GetProtectionInfo(
    _In_ DWORD Pid,
    _Out_ PWKD_PROCESS_PROTECTION_INFO OutInfo
    )
{
    if (!OutInfo) return STATUS_INVALID_PARAMETER;
    return WkGetProtectionInfoInternal(Pid, OutInfo);
}

BOOLEAN
ProcessManager_IsProtectedProcess(
    _In_ DWORD Pid
    )
{
    WKD_PROCESS_PROTECTION_INFO info;

    RtlZeroMemory(&info, sizeof(info));
    if (WkGetProtectionInfoInternal(Pid, &info) != STATUS_SUCCESS) return FALSE;
    return info.Level != WkProtection_None;
}

WKD_PROCESS_CRITICALITY
ProcessManager_GetCriticality(
    _In_ DWORD Pid
    )
{
    return WkGetCriticalityInternal(Pid);
}

BOOLEAN
ProcessManager_IsCriticalProcess(
    _In_ DWORD Pid
    )
{
    return WkIsCriticalProcessInternal(Pid);
}

BOOLEAN
ProcessManager_CanTerminate(
    _In_ DWORD Pid
    )
{
    return WkGetCriticalityInternal(Pid) < WkCriticality_Critical;
}

BOOLEAN
ProcessManager_RemoveProtection(
    _In_ DWORD Pid
    )
{
    /* ※ 死代码：用户态仅清 BreakOnTermination，PPL 剥离需驱动 */
    return WkRemoveProtectionInternal(Pid);
}

/*
 * WkRequestKernelProtectionRemoval — 请求驱动剥离 PPL。
 * 对齐 SS ProcessKiller.cpp L1872-1913 RequestKernelProtectionRemoval：
 * 经 IPC 向驱动发 FilterMessageType_RegisterProtectedProcess(action=0) 剥离 PPL。
 * ※ 死代码：依赖内核驱动 IPC 通道（SS 的 IPCManager.SendToKernel），WkD 当前
 *   用户态 Agent 无等价驱动通道，恒返回 FALSE。
 */
BOOLEAN
WkRequestKernelProtectionRemoval(
    _In_ DWORD Pid
    )
{
    UNREFERENCED_PARAMETER(Pid);
    return FALSE;
}

/**************************************************/
/*               Watchdog 公共函数                 */
/**************************************************/

NTSTATUS
ProcessManager_DetectWatchdogs(
    _In_ DWORD Pid,
    _Outptr_ PWKD_WATCHDOG_INFO* OutList,
    _Out_ PULONG OutCount
    )
{
    NTSTATUS status;

    if (!OutList || !OutCount) return STATUS_INVALID_PARAMETER;
    *OutList = NULL;
    *OutCount = 0;

    status = WkDetectWatchdogsInternal(Pid, OutList, OutCount);
    if (NT_SUCCESS(status) && *OutList && *OutCount > 0) {
        ULONG i;
        for (i = 0; i < *OutCount; i++) {
            WkInvokeWatchdogCallbacks(&(*OutList)[i]);
        }
    }
    return status;
}

NTSTATUS
ProcessManager_DetectWatchdogGroups(
    _In_ const ULONG* Pids,
    _In_ ULONG PidCount,
    _Outptr_ PWKD_WATCHDOG_GROUP* OutList,
    _Out_ PULONG OutCount
    )
{
    if (!OutList || !OutCount) return STATUS_INVALID_PARAMETER;
    return WkDetectWatchdogGroupsInternal(Pids, PidCount, OutList, OutCount);
}

BOOLEAN
ProcessManager_DefeatWatchdogGroup(
    _In_ PWKD_WATCHDOG_GROUP Group
    )
{
    /* ※ 死代码：未接入处置流水线 */
    return WkDefeatWatchdogGroupInternal(Group);
}

/* 去重追加（KillWithWatchdogs 用） */
static BOOLEAN
WkAddUnique(
    _Inout_ PULONG Arr,
    _Inout_ PULONG Count,
    _In_ ULONG Cap,
    _In_ ULONG Pid
    )
{
    ULONG i;

    if (*Count >= Cap) return FALSE;
    for (i = 0; i < *Count; i++) {
        if (Arr[i] == Pid) return TRUE;
    }
    Arr[*Count] = Pid;
    (*Count)++;
    return TRUE;
}

/*
 * ProcessManager_KillWithWatchdogs — 连 watchdog 一起终止。
 * 对齐 SS ProcessKiller.cpp L2254-2313 KillWithWatchdogs：
 * 检测 watchdog + 展开每个成员后代树合并集合 + 逐个 TerminateEx（非树）。
 */
NTSTATUS
ProcessManager_KillWithWatchdogs(
    _In_ DWORD Pid,
    _In_opt_ PCWKD_KILL_OPTIONS Options,
    _Out_ PWKD_TREE_KILL_INFO OutInfo
    )
{
    WKD_KILL_OPTIONS opts;
    WKD_KILL_OPTIONS perPid;
    PWKD_WATCHDOG_INFO infos = NULL;
    ULONG infoCount = 0, i, n;
    PULONG allPids = NULL;
    ULONG allCount = 0;
    WKD_TREE_KILL_INFO info;

    if (!OutInfo) return STATUS_INVALID_PARAMETER;
    if (Options == NULL) {
        WkKillOptions_MalwareKill(&opts);
        Options = &opts;
    }

    RtlZeroMemory(&info, sizeof(info));
    info.RootPid = Pid;
    WkGetProcessName(Pid, info.RootName, 260);
    WkQuerySystemTime(&info.StartTime);
    info.Strategy = WkTreeStrategy_Simultaneous;

    allPids = (PULONG)UtHeapAlloc(WK_MAX_TREE_SIZE * sizeof(ULONG));
    if (!allPids) return STATUS_NO_MEMORY;

    WkAddUnique(allPids, &allCount, WK_MAX_TREE_SIZE, Pid);

    if (WkDetectWatchdogsInternal(Pid, &infos, &infoCount) == STATUS_SUCCESS && infos) {
        for (i = 0; i < infoCount; i++) {
            if (infos[i].WatcherPid) {
                WkAddUnique(allPids, &allCount, WK_MAX_TREE_SIZE, infos[i].WatcherPid);
            }
            if (infos[i].WatchedPid) {
                WkAddUnique(allPids, &allCount, WK_MAX_TREE_SIZE, infos[i].WatchedPid);
            }
        }
        UtHeapFree(infos);
    }

    /* 展开每个成员的后代树 */
    for (i = 0; i < allCount; i++) {
        PULONG t = NULL;
        ULONG tc = 0;
        if (WkGetProcessTreeInternal(allPids[i], WK_MAX_TREE_DEPTH, &t, &tc) == STATUS_SUCCESS) {
            for (n = 0; n < tc; n++) {
                WkAddUnique(allPids, &allCount, WK_MAX_TREE_SIZE, t[n]);
            }
            UtHeapFree(t);
        }
    }

    info.TotalProcesses = allCount;
    info.Results = (PWKD_TREE_KILL_NODE)UtHeapAlloc(allCount * sizeof(WKD_TREE_KILL_NODE));
    if (!info.Results) {
        UtHeapFree(allPids);
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(info.Results, allCount * sizeof(WKD_TREE_KILL_NODE));

    for (i = 0; i < allCount; i++) {
        WKD_PROCESS_KILL_INFO ki;

        WkKillOptions_MalwareKill(&perPid);
        perPid.KillTree = FALSE;

        RtlZeroMemory(&ki, sizeof(ki));
        ProcessManager_KillProcessEx(allPids[i], &perPid, &ki);
        info.Results[i].Pid = allPids[i];
        info.Results[i].Result = ki.Result;

        if (ki.Result == WkKillResult_Success || ki.Result == WkKillResult_AlreadyDead) {
            info.KilledProcesses++;
        } else if (ki.Result == WkKillResult_Critical || ki.Result == WkKillResult_Blocked) {
            info.SkippedProcesses++;
            if (ki.ErrorMessage[0] != L'\0') {
                wcsncpy_s(info.LastError, 256, ki.ErrorMessage, _TRUNCATE);
            }
        } else {
            info.FailedProcesses++;
            if (ki.ErrorMessage[0] != L'\0') {
                wcsncpy_s(info.LastError, 256, ki.ErrorMessage, _TRUNCATE);
            }
        }
    }

    if (info.FailedProcesses == 0) info.OverallResult = WkKillResult_Success;
    else if (info.KilledProcesses > 0) info.OverallResult = WkKillResult_PartialSuccess;
    else info.OverallResult = WkKillResult_Failed;

    UtHeapFree(allPids);
    WkQuerySystemTime(&info.EndTime);
    *OutInfo = info;
    return STATUS_SUCCESS;
}

/**************************************************/
/*              持久化清理公共函数                  */
/**************************************************/

BOOLEAN
ProcessManager_CleanPersistence(
    _In_ DWORD Pid
    )
{
    BOOLEAN any = FALSE;

    /* ※ 死代码：未接入隔离/终止流程 */
    any |= WkRemoveServiceInternal(Pid);
    any |= WkRemoveScheduledTasksInternal(Pid);
    any |= WkRemoveRegistryPersistenceInternal(Pid);
    return any;
}

BOOLEAN
ProcessManager_RemoveService(
    _In_ DWORD Pid
    )
{
    return WkRemoveServiceInternal(Pid);
}

BOOLEAN
ProcessManager_RemoveScheduledTasks(
    _In_ DWORD Pid
    )
{
    return WkRemoveScheduledTasksInternal(Pid);
}

BOOLEAN
ProcessManager_RemoveRegistryPersistence(
    _In_ DWORD Pid
    )
{
    return WkRemoveRegistryPersistenceInternal(Pid);
}

/**************************************************/
/*                验证与复活检测                    */
/**************************************************/

BOOLEAN
ProcessManager_VerifyTermination(
    _In_ DWORD Pid,
    _In_ ULONG TimeoutMs
    )
{
    return WkVerifyTerminationInternal(Pid, TimeoutMs);
}

/*
 * ProcessManager_CheckResurrection — 按名+路径+创建时间检测进程复活。
 * 对齐 SS ProcessKiller.cpp L2366-2397 CheckResurrection：
 * 枚举进程，name/path 匹配且 creation time 晚于 SinceFileTime 即判定复活，返回新 PID。
 */
ULONG
ProcessManager_CheckResurrection(
    _In_ PCWSTR Name,
    _In_ PCWSTR Path,
    _In_ LARGE_INTEGER SinceFileTime
    )
{
    HANDLE hSnap;
    PROCESSENTRY32W pe;
    ULONG foundPid = 0;

    if (!Name || !Path) return 0;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            WCHAR path[260];
            HANDLE hProc;
            FILETIME creation = { 0 };

            if (_wcsicmp(pe.szExeFile, Name) != 0) continue;
            if (WkGetProcessPath(pe.th32ProcessID, path, 260) != STATUS_SUCCESS) continue;
            if (_wcsicmp(path, Path) != 0) continue;

            hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProc) continue;
            if (WkGetProcessCreationTime(hProc, &creation)) {
                ULARGE_INTEGER uli;
                uli.LowPart = creation.dwLowDateTime;
                uli.HighPart = creation.dwHighDateTime;
                if (uli.QuadPart > (ULONGLONG)SinceFileTime.QuadPart) {
                    foundPid = pe.th32ProcessID;
                    InterlockedIncrement64(&g_WkKillStats.ResurrectionsDetected);
                    printf("[ProcessManager] Process resurrection detected: %ls (pid=%u)\n",
                           Name, foundPid);
                    CloseHandle(hProc);
                    break;
                }
            }
            CloseHandle(hProc);
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return foundPid;
}

/**************************************************/
/*                统计与回调注册                    */
/**************************************************/

NTSTATUS
ProcessManager_GetKillStatistics(
    _Out_ PWKD_KILLER_STATISTICS Out
    )
{
    if (!Out) return STATUS_INVALID_PARAMETER;
    *Out = g_WkKillStats;
    return STATUS_SUCCESS;
}

VOID
ProcessManager_ResetKillStatistics(
    VOID
    )
{
    RtlZeroMemory(&g_WkKillStats, sizeof(g_WkKillStats));
}

/*
 * WkKillStatistics_GetSuccessRate — 终止成功率（成功/总尝试 * 100）。
 * 对齐 SS KillerStatistics::GetSuccessRate（ProcessKiller.cpp L435-439）。
 * ※ 死代码：无调用者。
 */
double
WkKillStatistics_GetSuccessRate(
    VOID
    )
{
    LONG64 total = InterlockedCompareExchange64(&g_WkKillStats.TotalKillAttempts, 0, 0);
    LONG64 success = InterlockedCompareExchange64(&g_WkKillStats.SuccessfulKills, 0, 0);

    if (total == 0) return 0.0;
    return ((double)success / (double)total) * 100.0;
}

/* 回调注册（※ 死代码：当前无消费者） */
UINT64
ProcessManager_RegisterPreKillCallback(
    _In_ WKD_PRE_KILL_CALLBACK Cb
    )
{
    return WkRegisterCallback(WkCallback_PreKill, (PVOID)Cb);
}

UINT64
ProcessManager_RegisterPostKillCallback(
    _In_ WKD_POST_KILL_CALLBACK Cb
    )
{
    return WkRegisterCallback(WkCallback_PostKill, (PVOID)Cb);
}

UINT64
ProcessManager_RegisterTreeProgressCallback(
    _In_ WKD_TREE_PROGRESS_CALLBACK Cb
    )
{
    return WkRegisterCallback(WkCallback_TreeProgress, (PVOID)Cb);
}

UINT64
ProcessManager_RegisterWatchdogCallback(
    _In_ WKD_WATCHDOG_CALLBACK Cb
    )
{
    return WkRegisterCallback(WkCallback_Watchdog, (PVOID)Cb);
}

VOID
ProcessManager_UnregisterCallback(
    _In_ UINT64 CallbackId
    )
{
    WkUnregisterCallback(CallbackId);
}

/**************************************************/
/*          结果/方法 → 字符串（死代码）             */
/**************************************************/

PCWSTR
WkKillResultToString(
    _In_ WKD_KILL_RESULT Result
    )
{
    switch (Result) {
    case WkKillResult_Success:          return L"Success";
    case WkKillResult_AlreadyDead:      return L"AlreadyDead";
    case WkKillResult_AccessDenied:     return L"AccessDenied";
    case WkKillResult_Protected:        return L"Protected";
    case WkKillResult_Critical:         return L"Critical";
    case WkKillResult_NotFound:         return L"NotFound";
    case WkKillResult_Timeout:          return L"Timeout";
    case WkKillResult_PartialSuccess:   return L"PartialSuccess";
    case WkKillResult_Failed:           return L"Failed";
    case WkKillResult_Blocked:          return L"Blocked";
    case WkKillResult_Resurrected:      return L"Resurrected";
    case WkKillResult_InsufficientPriv: return L"InsufficientPriv";
    default:                            return L"Unknown";
    }
}

PCWSTR
WkKillMethodToString(
    _In_ WKD_KILL_METHOD Method
    )
{
    switch (Method) {
    case WkKillMethod_Auto:             return L"Auto";
    case WkKillMethod_Standard:         return L"Standard";
    case WkKillMethod_Privileged:       return L"Privileged";
    case WkKillMethod_Freeze:           return L"Freeze";
    case WkKillMethod_JobObject:        return L"JobObject";
    case WkKillMethod_TokenManipulation:return L"TokenManipulation";
    case WkKillMethod_Kernel:           return L"Kernel";
    case WkKillMethod_ForceKernel:      return L"ForceKernel";
    case WkKillMethod_Nuclear:          return L"Nuclear";
    default:                            return L"Unknown";
    }
}

/**************************************************/
/*       批量/按名/按路径终止 与 树挂起（死代码）    */
/**************************************************/

/* 枚举全部进程 PID（Toolhelp，对齐 SS ProcessUtils EnumerateProcesses） */
static NTSTATUS
WkEnumerateAllProcessIds(
    _Outptr_ PULONG* Pids,
    _Out_ PULONG Count
    )
{
    HANDLE hSnap;
    PROCESSENTRY32W pe;
    PULONG list = NULL;
    ULONG cap = 0, n = 0;

    if (!Pids || !Count) return STATUS_INVALID_PARAMETER;
    *Pids = NULL;
    *Count = 0;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return STATUS_UNSUCCESSFUL;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (n == cap) {
                ULONG newCap = cap ? cap * 2 : 128;
                PULONG tmp = (PULONG)UtHeapAlloc(newCap * sizeof(ULONG));
                if (!tmp) {
                    if (list) UtHeapFree(list);
                    CloseHandle(hSnap);
                    return STATUS_NO_MEMORY;
                }
                if (list) {
                    memcpy(tmp, list, n * sizeof(ULONG));
                    UtHeapFree(list);
                }
                list = tmp;
                cap = newCap;
            }
            list[n++] = pe.th32ProcessID;
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    *Pids = list;
    *Count = n;
    return STATUS_SUCCESS;
}

/*
 * ProcessManager_TerminateMultiple — 批量终止。
 * 对齐 SS ProcessKiller.cpp L2157-2163 TerminateMultiple。
 * ※ 死代码：无调用者。
 */
NTSTATUS
ProcessManager_TerminateMultiple(
    _In_ const ULONG* Pids,
    _In_ ULONG PidCount,
    _In_opt_ PCWKD_KILL_OPTIONS Options
    )
{
    WKD_KILL_OPTIONS opts;
    ULONG i;
    ULONG successCount = 0;

    if (!Pids || PidCount == 0) return STATUS_INVALID_PARAMETER;
    if (Options == NULL) {
        WkKillOptions_Standard(&opts);
        Options = &opts;
    }

    for (i = 0; i < PidCount; i++) {
        WKD_PROCESS_KILL_INFO ki;
        RtlZeroMemory(&ki, sizeof(ki));
        if (NT_SUCCESS(ProcessManager_KillProcessEx(Pids[i], Options, &ki)) &&
            (ki.Result == WkKillResult_Success || ki.Result == WkKillResult_AlreadyDead)) {
            successCount++;
        }
    }
    return (successCount == PidCount) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/*
 * ProcessManager_TerminateByName — 按名终止全部同名进程。
 * 对齐 SS ProcessKiller.cpp L2165-2175 TerminateByName。
 * ※ 死代码：无调用者。
 */
NTSTATUS
ProcessManager_TerminateByName(
    _In_ PCWSTR ProcessName,
    _In_opt_ PCWKD_KILL_OPTIONS Options
    )
{
    WKD_KILL_OPTIONS opts;
    PULONG pids = NULL;
    ULONG pidCount = 0, i;
    ULONG matched = 0;

    if (!ProcessName || ProcessName[0] == L'\0') return STATUS_INVALID_PARAMETER;
    if (Options == NULL) {
        WkKillOptions_Standard(&opts);
        Options = &opts;
    }

    if (WkEnumerateAllProcessIds(&pids, &pidCount) != STATUS_SUCCESS) return STATUS_UNSUCCESSFUL;

    for (i = 0; i < pidCount; i++) {
        WCHAR name[260] = { 0 };
        if (WkGetProcessName(pids[i], name, 260) == STATUS_SUCCESS &&
            _wcsicmp(name, ProcessName) == 0) {
            WKD_PROCESS_KILL_INFO ki;
            RtlZeroMemory(&ki, sizeof(ki));
            if (NT_SUCCESS(ProcessManager_KillProcessEx(pids[i], Options, &ki)) &&
                (ki.Result == WkKillResult_Success || ki.Result == WkKillResult_AlreadyDead)) {
                matched++;
            }
        }
    }
    if (pids) UtHeapFree(pids);
    return (matched > 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/*
 * ProcessManager_TerminateByPath — 按路径终止全部匹配进程。
 * 对齐 SS ProcessKiller.cpp L2177-2192 TerminateByPath。
 * ※ 死代码：无调用者。
 */
NTSTATUS
ProcessManager_TerminateByPath(
    _In_ PCWSTR ProcessPath,
    _In_opt_ PCWKD_KILL_OPTIONS Options
    )
{
    WKD_KILL_OPTIONS opts;
    PULONG pids = NULL;
    ULONG pidCount = 0, i;
    ULONG matched = 0;

    if (!ProcessPath || ProcessPath[0] == L'\0') return STATUS_INVALID_PARAMETER;
    if (Options == NULL) {
        WkKillOptions_Standard(&opts);
        Options = &opts;
    }

    if (WkEnumerateAllProcessIds(&pids, &pidCount) != STATUS_SUCCESS) return STATUS_UNSUCCESSFUL;

    for (i = 0; i < pidCount; i++) {
        WCHAR path[260] = { 0 };
        if (WkGetProcessPath(pids[i], path, 260) == STATUS_SUCCESS &&
            _wcsicmp(path, ProcessPath) == 0) {
            WKD_PROCESS_KILL_INFO ki;
            RtlZeroMemory(&ki, sizeof(ki));
            if (NT_SUCCESS(ProcessManager_KillProcessEx(pids[i], Options, &ki)) &&
                (ki.Result == WkKillResult_Success || ki.Result == WkKillResult_AlreadyDead)) {
                matched++;
            }
        }
    }
    if (pids) UtHeapFree(pids);
    return (matched > 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/*
 * ProcessManager_SuspendTree — 挂起整棵进程树。
 * 对齐 SS ProcessKiller.cpp L2226-2230 SuspendTree。
 * ※ 死代码：无调用者。
 */
BOOLEAN
ProcessManager_SuspendTree(
    _In_ DWORD RootPid
    )
{
    PULONG tree = NULL;
    ULONG count = 0, i;
    BOOLEAN all = TRUE;

    if (WkGetProcessTreeInternal(RootPid, WK_MAX_TREE_DEPTH, &tree, &count) != STATUS_SUCCESS) {
        return FALSE;
    }
    for (i = 0; i < count; i++) {
        if (ProcessManager_SuspendProcess(tree[i]) != WkSuspendResult_Success) all = FALSE;
    }
    if (tree) UtHeapFree(tree);
    return all;
}

/*
 * ProcessManager_ResumeTree — 恢复整棵进程树。
 * 对齐 SS ProcessKiller.cpp L2232-2236 ResumeTree。
 * ※ 死代码：无调用者。
 */
BOOLEAN
ProcessManager_ResumeTree(
    _In_ DWORD RootPid
    )
{
    PULONG tree = NULL;
    ULONG count = 0, i;
    BOOLEAN all = TRUE;

    if (WkGetProcessTreeInternal(RootPid, WK_MAX_TREE_DEPTH, &tree, &count) != STATUS_SUCCESS) {
        return FALSE;
    }
    for (i = 0; i < count; i++) {
        if (!ProcessManager_ResumeProcess(tree[i])) all = FALSE;
    }
    if (tree) UtHeapFree(tree);
    return all;
}

/* 对齐 SS IsKernelModeAvailable：WkD 当前无驱动终止/剥离通道，恒 FALSE */
BOOLEAN
ProcessManager_IsKernelModeAvailable(
    VOID
    )
{
    return FALSE;
}

/* 对齐 SS GetVersion：处置引擎版本 */
PCWSTR
WkKillGetVersion(
    VOID
    )
{
    return L"1.0.0";
}

