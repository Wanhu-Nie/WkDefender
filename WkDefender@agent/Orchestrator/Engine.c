/**************************************************/
/*  WkDefender Agent — 主编排层                     */
/*  调度: EventParse → IOC → IOA → Policy → Storage */
/*  IOC/IOA 双引擎已独立，此处仅做事件路由           */
/**************************************************/

#include "Engine.h"
#include "VerdictEngine.h"
#include "../IOC/IocEngine.h"
#include "../IOA/IoaEngine.h"
#include "../Notification/AlpcService.h"
#include "../IOA/Tier2/IoaFsmEngine.h"
#include "../IOA/IoaGraphRingBuffer.h"
#include "../IOA/Tier2/IoaTier2Backtrack.h"
#include "../IOA/Tier3/Tier3Engine.h"
#include "../PolicyEngine/PolicyEngine.h"
#include "../IOA/IoaPersistQueue.h"
#include "../IOA/IoaProcessPair.h"
#include "../Storage/StorageEngine.h"
#include "../Notification/EventArchive.h"
#include "../ScanManager.h"
#include "../Process/ProcessModule.h"          /* 进程域模块挂载 (2026-08-15) */
#include "../Process/ProcessThread.h"           /* PsThreadAttachProcess (线程实体挂载, 返回 PWKD_THREAD) */
#include "../Process/ProcessTree.h"             /* WkdProcessTree / PsLookupWkdProcessByStrictProcessId */
#include "../IOC/ImageAnalyzer/ImageAnalyzer.h"   /* 统一镜像分析流水线 (2026-08-15) */
#include "../IOC/Signature/SignatureHunting.h"   /* 镜像签名异常 (SS DSV OnKernelImageLoad 迁移) */

//
// 镜像全量分析桥接开关（2026-08-09 镜像职责收敛；2026-08-15 统一流水线化）
// 置 TRUE 后 OrcpWkdMessageDispatcher 对 WkdEvent_ImageLoad 事件同步调
// ImageAnalyzer（Tier3 深度分析），命中模块 Done 则 O(1) 复用，未命中触发
// 六件套全量（每唯一镜像一次）；结果回写事件 Severity 进策略/Verdict 链。
// 对齐 IoaEngine.c 各 g_IoaXxxEnabled 门控模式，默认关（死代码开关）。
// ProcessCreate 路径（IocObserveProcess → ImageAnalyzer）不受此门控，始终分析。
//
BOOLEAN g_IoaImageAnalysisEnabled = FALSE;

/**************************************************/
/*         同步阻塞查询回复数据格式                  */
/*   Driver 侧根据此结构体内容判定放行/阻断          */
/**************************************************/

typedef struct _WKD_BLOCKING_VERDICT {
    BOOLEAN Allow;              /* TRUE=放行, FALSE=阻断 */
    ULONG   Confidence;         /* 置信度 [0-1000] */
    ULONG   Severity;           /* 严重等级 */
} WKD_BLOCKING_VERDICT;
typedef WKD_BLOCKING_VERDICT *PWKD_BLOCKING_VERDICT;

/* 位图升级宏 — 与 Driver 侧 IoaEngine.c 对齐 */
#define PAIR_BITMAP_ESCALATE \
    ((1ULL << 5) |  /* CreateRemoteThread */  \
     (1ULL << 6) |  /* MapViewOfSection */    \
     (1ULL << 7) |  /* QueueApcThread */      \
     (1ULL << 9) |  /* ResumeThread */        \
     (1ULL << 2) |  /* WriteVirtualMemory */  \
     (1ULL << 1))   /* AllocateVirtualMemory */

/**************************************************/
/*               全局实例                           */
/**************************************************/

ORC_ENGINE WkdOrchestratorEngine = { 0 };

/**************************************************/
/*               CGE 消息消费线程                    */
/**************************************************/

static PVOID
OrcWkdMessageHandler(
    _In_ PVOID              Context,
    _In_ ULONG              MessageType,
    _In_ PWKD_MESSAGE       Message
    )
{
    PORC_ENGINE engine = (PORC_ENGINE)Context;
    UNREFERENCED_PARAMETER(MessageType);
    if (engine && Message) {
        OrcpWkdMessageDispatcher(Message, engine);
    }
    return NULL;
}

/**************************************************/
/*               维护线程                           */
/**************************************************/

static DWORD WINAPI
CgEngineMaintenanceThread(_In_ LPVOID Param)
{
    PORC_ENGINE engine = (PORC_ENGINE)Param;
    LARGE_INTEGER now, edgeWindow;
    printf("[Orchestrator] Maintenance thread started\n");

    while (engine->MaintenanceRunning) {
        Sleep(engine->Config.PruneIntervalMs);
        if (!engine->MaintenanceRunning) break;
        GetSystemTimeAsFileTime((PFILETIME)&now);
        edgeWindow.QuadPart = now.QuadPart - (LONGLONG)engine->Config.EdgeRetentionWindowMs * 10000;
        IoaCarsalGraphPrune(WkdIoaEngine.Graph, edgeWindow);
    }
    printf("[Orchestrator] Maintenance thread exited\n");
    return 0;
}

/**************************************************/
/*           FSM 过期追踪器清理线程                  */
/**************************************************/

static DWORD WINAPI
CgFsmCleanupThread(_In_ LPVOID Param)
{
    PORC_ENGINE engine = (PORC_ENGINE)Param;
    printf("[Orchestrator] FSM cleanup thread started (interval=%ums)\n",
           FSM_CLEANUP_INTERVAL_MS);

    while (engine->FsmCleanupRunning) {
        Sleep(FSM_CLEANUP_INTERVAL_MS);
        if (!engine->FsmCleanupRunning) break;

        if (WkdIoaEngine.FsmEngine && WkdIoaEngine.FsmEngine->Initialized) {
            FsmCleanupExpired(WkdIoaEngine.FsmEngine);
        }

        /* 序列规则状态超时清理 (ShadowStrike PatternMatcher 迁移, 2026-08;
         * 按 SequenceTimeoutMs 硬超时杀状态, 补 FSM 整链超时不杀状态缺陷) */
        PolicyEngine_CleanupSequenceStates();
    }
    printf("[Orchestrator] FSM cleanup thread exited\n");
    return 0;
}

/**************************************************/
/*           Tier 2 告警异步处理线程                 */
/**************************************************/

static DWORD WINAPI
CgT2AlertThread(_In_ LPVOID Param)
{
    PORC_ENGINE engine = (PORC_ENGINE)Param;
    printf("[Orchestrator] T2 alert thread started\n");

    while (engine->T2AlertRunning) {
        if (WkdIoaEngine.Tier2 && WkdIoaEngine.Tier2->Initialized) {
            /* 等待告警唤醒事件或 100ms 超时 */
            WaitForSingleObject(WkdIoaEngine.Tier2->AlertWakeEvent, INFINITE);
            if (!engine->T2AlertRunning) break;

            T2ProcessAlertQueue(WkdIoaEngine.Tier2);
        } else {
            Sleep(100);
        }
    }
    printf("[Orchestrator] T2 alert thread exited\n");
    return 0;
}

static DWORD WINAPI
CgT3MaintenanceThread(_In_ LPVOID Param)
/*++
Routine Description:
    Tier 3 定期维护线程。
    周期性淘汰过期链、多点攻击关联扫描。
    T3DeepForensics 本身是同步调用 — 不需要后台任务队列。
--*/
{
    PIOA_TIER3_ENGINE t3 = (PIOA_TIER3_ENGINE)Param;
    printf("[Orchestrator] T3 maintenance thread started\n");

    while (t3 && t3->Initialized) {
        T3PeriodicMaintenance(t3);
        Sleep(60000);  /* 每 60 秒执行一次维护 */
    }

    printf("[Orchestrator] T3 maintenance thread exited\n");
    return 0;
}

/**************************************************/
/*               ALPC消息分发 (核心流水线)          */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
OrcpWkdMessageDispatcher(
    _In_ PWKD_MESSAGE Message,
    _In_opt_ PVOID Context
    )
/*++
Routine Description:
    事件处理主流水线:
      1. Parse   : WKD_MESSAGE → WKD_EVENT_HEADER
      2. IOC     : 进程创建时触发静态分析
      3. IOA     : 所有事件触发行为分析 (谱系/图/时序/评分)
      4. Policy  : 规则评估 + 告警
      5. Storage : 持久化

Arguments:
    Message — 已解包的 WKD_MESSAGE。
    Context — 引擎上下文。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PWKD_EVENT_HEADER   event;
    PORC_ENGINE         engine;
    PWKD_PROCESS targetWkdProcess = NULL;
    PWKD_PROCESS sourceWkdProcess = NULL;

    engine = (PORC_ENGINE)Context;
    if (!engine || !engine->Config.AnalysisEnabled || !Message)
        return STATUS_INVALID_PARAMETER;

    InterlockedIncrement(&engine->Statistics.EvnetsIngested);

    /* Step 1: 解析Event */
    status = NtfWkdMessageParse(engine->SchemaTable, Message, &event);
    if (!NT_SUCCESS(status)) {
        printf("[Orchestrator] Parse failed: type=0x%X status=0x%X\n",
               Message->Header.Type, status);
        return status;
    }

    /* Step 2: 异步持久化 (统一入口) */
    {
        PWKD_EVENT_HEADER eventCopy = NULL;
        ULONG flatSize = 0;

        status = NtfEventArchive(event, &eventCopy, &flatSize);
        if (NT_SUCCESS(status)) {
            /*
             * 展平后 eventCopy 可能与 event 相同（非 ProcessCreate），
             * 需确保异步队列持有独立堆副本，避免 DefEventFree 释放后悬空。
             */

            if (eventCopy) {
                IoaPersistQueueEnqueue(WkdIoaEngine.PersistQueue,
                    PersistType_Event, eventCopy,
                    (PERSIST_SERDE_WRITE_FN)StPersistEvent,
                    FALSE);
            }
        }
    }

    /* Step 2.4: 进程退出直通分支 (2026-08-25 新增)
     * 谱系节点标记退出属结构体构建范畴, 不受 IOC/IOA 分析注释影响;
     * 且退出进程不参与 pair 维度 — 阶段2.5 前分流, 避免为将死进程
     * 建自环对 (NtfExtractEventPids 对 Exit 无分支, 原实现经
     * NOT_SUPPORTED → Cleanup 直接丢弃, 谱系退出标记全部丢失)。
     * 处理内容: PsHandleProcessExit + IpeRecordProcessExit (PID 复用) +
     * VerdictEngine_OnProcessTerminate + Terminates 边入环形缓冲。 */
    /* 进程退出/线程退出分支已并入下方阶段3 主 switch 的对应 case (2026-08-27 重构):
     * 退出事件不参与进程对维度 (阶段2.5 块内已对二者跳过建 pair) */

    /* 阶段3: 三级级联 — 实体创建 → IOC 写回实体 → IOA 行为分析
     * 将原先埋在 IoaObserve 内部的实体创建显式化到分发层，与
     * IocObserveProcess / PsHandleImageLoad 对齐。每个 case 末尾显式调
     * IoaObserve 保证所有事件都被行为分析一次；default 兜底其余类型。 */

    /* 阶段2.5: switch 前统一建进程对 (2026-08-24 上提: 实体创建收口)
     * ProcessCreate → PsCreateWkdProcess 完整建 child 节点 (GUID+父链接+
     *   PidMap+GlobalLink+持久化+事件头 NodeId 回填), 再建自环对 <child,child>;
     * 其它事件 → NtfExtractEventPids 提取 PID, 经 PsLookupWkdProcessByStrictProcessId 只查不建
     *   取真实端点节点 (端点须已由既往 ProcessCreate 建立), 缺失即数据不一致
     *   直接 Cleanup。IoaObserve 阶段2 降级只查, 不再创建。 */
    {
        HANDLE srcPid = 0, tgtPid = 0;
        PAE_PROCESS_PAIR pair = NULL;

        status = NtfExtractEventPids(event, &srcPid, &tgtPid);
        if (!NT_SUCCESS(status)) goto Cleanup;

        if (event->Type == WkdEvent_ProcessCreate) {
            status = PsCreateWkdProcess(event, &targetWkdProcess);
            if (!NT_SUCCESS(status)) goto Cleanup;
        }
        else {
            status = PsLookupWkdProcessByProcessId(&WkdProcessTree, tgtPid, &targetWkdProcess);
            if (!NT_SUCCESS(status)) goto Cleanup;
        }

        status = PsLookupWkdProcessByProcessId(NULL, srcPid, &sourceWkdProcess);
        if (!NT_SUCCESS(status)) goto Cleanup;

        status = AeFindOrCreateProcessPair(sourceWkdProcess, targetWkdProcess, &pair);
        if (!NT_SUCCESS(status)) goto Cleanup;

        /* 归还 pair 借出 pin (2026-08-25 HashMap ref/deref 契约):
         * 此处仅确保 pair 已物化 (分发层职责), 后续 IoaObserve 阶段2
         * 经 AeLookupProcessPair 自行借 pin, 不跨函数传递指针。 */
        AeDereferenceProcessPair(pair);
    }
   
    switch (event->Type) {

    case WkdEvent_ProcessCreate: {

        /* ② IOC: 对刚创建的进程节点做静态分析，结果写回 IocVerdict/IocConfidence
         * [2026-08-25 调试注释] 结构体构建验证期关闭 — IocObserveProcess →
         * IocAnalyseImage 含 SHA256 全文件读取 + WinVerifyTrust + PE 深度解析,
         * 且四态契约中 IN_PROGRESS 会 WaitForSingleObject(CompleteEvent, 2s)、
         * IA_QUEUE_MAX(256) 打满后同步兜底自做 — 同一镜像高频建进程时将把
         * AlpcpWorkerThread (Reactor, 同步直调 handler) 卡死至秒级/条。
         * 恢复分析时建议移入异步 worker 投递, 不占 ALPC 线程。 */
        status = IocObserveProcess(targetWkdProcess);
        if (!NT_SUCCESS(status)) goto Cleanup;

        /* ③ IOA: 行为分析 (节点已由分发层建立，直接进入后续共同路径) */
        // IoaObserve(event);
        break;
    }

    case WkdEvent_ProcessExit: {
        /*const PEVENT_PAYLOAD_PROCESS_EXIT payload =
            (const PEVENT_PAYLOAD_PROCESS_EXIT)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));*/
       
        CoRemoveHashMapEntry(&WkdProcessTree.PidMap,
                             &targetWkdProcess->ProcessId,
                             sizeof(HANDLE));
        PsDereferenceWkdProcess(&targetWkdProcess->RefCount);
        targetWkdProcess = NULL;

        // PsHandleProcessExit(&WkdProcessTree, targetWkdProcess->NodeId, payload->ExitTime);
        InterlockedIncrement(&WkdIoaEngine.Stats.ProcessNodesTerminated);

        /* 记录进程退出到历史追踪器（PID 复用检测; HANDLE → ULONG 截断） */
        //IpeRecordProcessExit(
        //    (ULONG)(ULONG_PTR)payload->ProcessId,
        //    targetWkdProcess->ImagePath && targetWkdProcess->ImagePath->Buffer ? targetWkdProcess->ImagePath->Buffer : L"");

        /* 活跃威胁清理（2026-08-15 自 process_manager 迁移: 进程退出事件走编排链，
            * 原 ProcessManager_ProcessProcessExit 路径不可达致此清理丢失） */
        // VerdictEngine_OnProcessTerminate((ULONG)(ULONG_PTR)payload->ProcessId);
        

        /* 边描述符 → 环形缓冲区 (Layer 0) */
        //GRAPH_EDGE_DESCRIPTOR edgeDesc;
        //RtlZeroMemory(&edgeDesc, sizeof(edgeDesc));
        //WkdCreateGuid(&edgeDesc.EdgeId);
        //WkdCopyGuid(&edgeDesc.SrcNodeId, &event->SourceProcessId);
        //WkdCopyGuid(&edgeDesc.TgtNodeId, &targetWkdProcess->NodeId);
        //edgeDesc.EdgeType = DefEdge_Terminates;
        //edgeDesc.EventClass = event->Class;
        //edgeDesc.BehaviorFlags = event->BehaviorFlags;
        //edgeDesc.Confidence = event->Confidence;
        //edgeDesc.Timestamp = event->Timestamp;

        /*GrbWriteEdge(WkdIoaEngine.RingBuffer, &edgeDesc, GraphLayer_Hot);
        WkdIoaEngine.Stats.RingBufferWrites++;*/
        

        break;
    }

    case WkdEvent_ThreadCreate:
    case WkdEvent_RemoteThreadCreate: {
        PWKD_THREAD thread = NULL;
        const PEVENT_PAYLOAD_THREAD_CREATE payload =
            (const PEVENT_PAYLOAD_THREAD_CREATE)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));

        /* ① 实体: WKD_THREAD 挂载到目标进程线程表 */
        status = PsThreadAttachProcess(targetWkdProcess, payload, &thread);
        if (!NT_SUCCESS(status)) goto Cleanup;

        /* ② IOC: 线程级静态特征分析，写回 WKD_THREAD IOC 区域 */
        /*status = IocObserveThread(thread, payload);
        if (!NT_SUCCESS(status)) goto Cleanup;*/
        
        /* ③ IOA: 行为分析 (注入评分 + 因果图) */
        /*status = IoaObserve(event);
        if (!NT_SUCCESS(status)) goto Cleanup;*/

        break;
    }

    case WkdEvent_ThreadExit: {
        PWKD_PROCESS node = NULL;
        const PEVENT_PAYLOAD_THREAD_EXIT payload = 
            (const PEVENT_PAYLOAD_THREAD_EXIT)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));

        /* 从进程线程表摘除并释放该 wkd_thread (ThreadId 截断为 ULONG) */
        PsThreadDetachProcess(targetWkdProcess, payload->ThreadId);
        InterlockedIncrement(&WkdIoaEngine.Stats.ThreadNodesTerminated);
     
        break;
    }

    case WkdEvent_ImageLoad:
        /* ① 实体: 进程域模块挂载 (2026-08-15)
         * ImageLoad 事件 → 全局 WKD_MODULE 去重 + 进程视图挂载。 */
        PsHandleImageLoad(event);

        /* ② IOC: 统一镜像分析（2026-08-09 镜像职责收敛；2026-08-15 流水线化）
         * 驱动已按"白名单 / CI 签名 → 不推；无签名或非白名单 → 推"过滤，
         * 到达本层的 WkdEvent_ImageLoad 均需校验。同步调 ImageAnalyzer：
         *   - PsHandleImageLoad 已建模块并挂视图，本调用命中模块 Done 则 O(1) 复用
         *     （消除旧 ScanFileDirect 重复 SHA256/PE 解析）；
         *   - 未命中触发 Tier3 六件套全量（每唯一镜像一次）；
         * 命中可疑/恶意回写事件 Severity，进阶段5/6 链。 */
        if (event->Type == WkdEvent_ImageLoad && g_IoaImageAnalysisEnabled) {
            PEVENT_PAYLOAD_IMAGE_LOAD payload =
                (PEVENT_PAYLOAD_IMAGE_LOAD)((PUCHAR)event + sizeof(WKD_EVENT_HEADER));

            if (payload->ImagePath.Length > 0 && payload->ImagePath.Buffer != NULL) {
                WCHAR pathBuf[1024];

                if (payload->ImagePath.Length < sizeof(pathBuf)) {
                    ULONG pathChars = payload->ImagePath.Length / sizeof(WCHAR);
                    IOC_SCAN_RESULT scanRes;

                    RtlCopyMemory(pathBuf, payload->ImagePath.Buffer, payload->ImagePath.Length);
                    pathBuf[pathChars] = L'\0';

                    RtlZeroMemory(&scanRes, sizeof(scanRes));
                    if (NT_SUCCESS(IocAnalyseImage(pathBuf, NULL, &scanRes))) {
                        if (scanRes.FinalVerdict >= DefIocVerdict_Suspicious) {
                            event->Severity = (scanRes.FinalVerdict >= DefIocVerdict_Malicious)
                                ? DefThreatSeverity_High : DefThreatSeverity_Medium;
                            event->Confidence = (USHORT)min(900, event->Confidence + 300);
                        }

                        /* 镜像签名异常 (SS DSV OnKernelImageLoad L2274-2338 迁移, 2026-08-09):
                         * 未签名 .sys 驱动 (+100/T1014) + 内核/用户态签名等级不匹配 (+80/
                         * T1553.006) 叠加进 scanRes.SignatureHunt (未狩猎时补跑 9 类)。
                         * RiskScore ≥90 → 事件提级 High (对齐 SS 阻断阈值, wkd monitor-only
                         * 告警; 响应分发由阶段6 VerdictEngine 决定)。 */
                        if (g_IoaSignatureHuntingEnabled) {
                            IoaSigHunt_AnalyzeImageLoad(pathBuf, payload->SignatureStatus, &scanRes);
                            if (scanRes.SignatureHunt.RiskScore >= 90 &&
                                event->Severity < DefThreatSeverity_High) {
                                event->Severity = DefThreatSeverity_High;
                                event->Confidence = (USHORT)min(900, event->Confidence + 200);
                            }
                        }
                    }
                }
            }
        }

        /* ③ IOA: 行为分析 */
        // IoaObserve(event);
        break;

    // default:
        /* 阶段4: 其余事件类型直接进 IOA 行为分析 (所有事件) */
        // IoaObserve(event);
    }

    /* 阶段5: 策略引擎评估 */
    //if (engine->Config.AnalysisEnabled) {
    //    PWKD_PROCESS procNode = NULL;

    //    /* 传真真实进程节点: 优先目标进程, 回退源进程。
    //     * 修复原实现 (procNode 恒 NULL → 分数阈值规则失效)。 */
    //    if (!DefIsNullNodeId(event->TargetProcessId)) {
    //        procNode = IoaEngine_LookupProcess(event->TargetProcessId);
    //    }
    //    if (!procNode && !DefIsNullNodeId(event->SourceProcessId)) {
    //        procNode = IoaEngine_LookupProcess(event->SourceProcessId);
    //    }
    //    PolicyEngine_Evaluate(event, procNode);
    //}

    /* 阶段6: VerdictEngine 中央判定 (ShadowStrike ThreatDetector 迁移, 2026-08-04)
     * 多引擎融合 → 活跃威胁 → 告警持久化 → UI 通知 → 响应分发。
     * 原 printf 高危通知段由统一 Verdict 判定取代。 */
    //if (engine->Config.AnalysisEnabled) {
    //    PWKD_PROCESS verdictNode = NULL;
    //    WKD_VERDICT verdict;

    //    /* 传真真实进程节点 (与阶段5 同策略: 目标优先, 源回退) */
    //    if (!DefIsNullNodeId(event->TargetProcessId)) {
    //        verdictNode = IoaEngine_LookupProcess(event->TargetProcessId);
    //    }
    //    if (!verdictNode && !DefIsNullNodeId(event->SourceProcessId)) {
    //        verdictNode = IoaEngine_LookupProcess(event->SourceProcessId);
    //    }

    //    if (VerdictEngine_Fuse(event, verdictNode, &verdict)) {
    //        VerdictEngine_UpsertActiveThreat(&verdict);

    //        if (verdict.Severity >= g_VerdictEngine.Config.MinNotifySeverity ||
    //            verdict.ThreatScore >= g_VerdictEngine.Config.DetectionThreshold) {
    //            /* 告警持久化 (IOA_ALERT 单块堆副本, 队列异步落盘后整体释放) */
    //            PIOA_ALERT alert = VerdictEngine_AllocPersistAlert(&verdict);
    //            if (alert) {
    //                IoaPersistQueueEnqueue(WkdIoaEngine.PersistQueue,
    //                    PersistType_Alert, alert,
    //                    (PERSIST_SERDE_WRITE_FN)StPersistAlert, TRUE);
    //            }
    //            /* UI 主动通知 (载荷 = WKD_VERDICT) */
    //            WkdAlpcSendToUiEx(&WkdDefaultAlpcServer,
    //                WkdAlpcMsg_ThreatVerdictNotification, &verdict, sizeof(verdict), 0);
    //            /* 响应分发 (monitor-only 默认: 仅告警不处置) */
    //            VerdictEngine_DispatchResponse(&verdict);
    //            // engine->Stats.ThreatsEscalated++;
    //        }
    //    }
    //}

    /* 阶段7: 同步回复 + 位图下发 */
    //if (Message->Header.SyncRequestId != 0) {
    //    SIZE_T replySize = sizeof(WKD_ALPC_SYNC_REPLY) + sizeof(WKD_BLOCKING_VERDICT);
    //    PWKD_ALPC_SYNC_REPLY syncReply = (PWKD_ALPC_SYNC_REPLY)UtHeapAlloc(replySize);
    //    if (syncReply) {
    //        PWKD_BLOCKING_VERDICT verdict = (PWKD_BLOCKING_VERDICT)syncReply->Data;

    //        syncReply->RequestId = Message->Header.SyncRequestId;
    //        verdict->Allow = (event->Severity < DefThreatSeverity_High);
    //        verdict->Confidence = event->Confidence;
    //        verdict->Severity = event->Severity;

    //        // WkdAlpcSendToDriver(&WkdDefaultAlpcServer,
    //        //     WkdAlpcMessage_SyncReply, syncReply, (ULONG)replySize);
    //        UtHeapFree(syncReply);
    //    }
    //}

    /* 阶段8: 位图下发（异步路径 — 得分高时升级进程对为同步） */
    //if (event->Severity >= DefThreatSeverity_High && engine->Config.AnalysisEnabled) {
    //    extern IOA_ENGINE WkdIoaEngine;
    //    UNREFERENCED_PARAMETER(WkdIoaEngine);

    //    /* 用 EwmaRiskScore 判断是否需要升级位图 */
    //    if (event->Confidence >= 500 || event->Severity >= DefThreatSeverity_High) {
    //        HANDLE sPid = (HANDLE)(ULONG_PTR)event->SourceProcessId.Data1;
    //        HANDLE tPid = (HANDLE)(ULONG_PTR)event->TargetProcessId.Data1;

    //        /* 将该进程对标记为同步 — 后续所有跨进程操作阻塞等待 */
    //        WkdAlpcSendPairBitmapUpdate(&WkdDefaultAlpcServer,
    //            sPid, tPid,
    //            PAIR_BITMAP_ESCALATE);
    //    }
    //}

Cleanup:
    if (!NT_SUCCESS(status)) InterlockedIncrement(&engine->Statistics.EventsRefused);
    /* 归还查询/创建借出的节点 pin (2026-08-25 HashMap ref/deref 契约):
     * 修复原条件反转 bug (写成了 !target 才 Deref, 恰好永不执行 → 泄漏)。 */
    if (targetWkdProcess) PsDereferenceWkdProcess(targetWkdProcess);
    if (sourceWkdProcess) PsDereferenceWkdProcess(sourceWkdProcess);
    DefEventFree(event);
    return status;
}

/**************************************************/
/*               ALPC 入队包装函数                  */
/**************************************************/

NTSTATUS
OrcWkdMessageEnqueueCallback(
    _In_ PWKD_ALPC_SERVER   Server,
    _In_ PWKD_MESSAGE       Message,
    _In_opt_ PVOID          Context
    )
{
    PORC_ENGINE engine = (PORC_ENGINE)Context;
    UNREFERENCED_PARAMETER(Server);
    if (!engine || !Message) return STATUS_INVALID_PARAMETER;

    return WkdMsgQueueEnqueue(&engine->MessageQueue, Message->Header.Type,
        WkdMsgPriority_Medium, Message,
        sizeof(WKD_MESSAGE_HEADER) + Message->Header.BodySize);
}

/**************************************************/
/*                   公开API                        */
/**************************************************/

NTSTATUS
OrcEngineInitialize(_In_ PORC_ENGINE Engine, _In_ PORC_ENGINE_CONFIG Config)
{
    NTSTATUS status;
    if (!Engine || !Config) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Engine, sizeof(ORC_ENGINE));
    memcpy(&Engine->Config, Config, sizeof(ORC_ENGINE_CONFIG));
    InitializeCriticalSection(&Engine->Lock);

    printf("========================================\n");
    printf("  WkDefender Agent — IOC/IOA Dual Engine\n");
    printf("========================================\n\n");

    /* 1. 初始化共用存储层 */
    printf("[Orchestrator] Initializing Storage...\n");
    status = StInitialize(Config->WarmDbPath, Config->ColdDbPath, Config->ColdRetentionDays);
    if (!NT_SUCCESS(status)) { DeleteCriticalSection(&Engine->Lock); return status; }

    /* 2. 初始化事件Schema */
    printf("[Orchestrator] Initializing Event Schema...\n");
    status = WkdEvent_InitializeSchema();
    if (!NT_SUCCESS(status)) { StCleanup(); DeleteCriticalSection(&Engine->Lock); return status; }
    Engine->SchemaTable = &g_DefSchemaTable;

    /* 3. 初始化 IOA 引擎 (内部创建 Genealogy/Graph/Temporal/Scorer) */
    printf("[Orchestrator] Initializing IOA Engine...\n");
    {
        IOA_ENGINE_CONFIG ioaCfg = { 0 };
        ioaCfg.HotCacheMaxEntries = Config->HotCacheMaxEntries;
        ioaCfg.PruneIntervalMs = Config->PruneIntervalMs;
        ioaCfg.EdgeRetentionWindowMs = Config->EdgeRetentionWindowMs;
        ioaCfg.TemporalWindowMs = Config->TemporalWindowMs;
        ioaCfg.ScoreDecayIntervalMs = Config->ScoreDecayIntervalMs;
        ioaCfg.VerboseLogging = Config->VerboseLogging;
        status = IoaEngine_Initialize(&ioaCfg);
        if (!NT_SUCCESS(status)) {
            printf("[Orchestrator] IOA Engine init failed: 0x%X\n", status);
            WkdEvent_CleanupSchema();
            StCleanup();
            DeleteCriticalSection(&Engine->Lock);
            return status;
        }
    }

    /* 4. 初始化 IOC 引擎 */
    if (Config->AnalysisEnabled) {
        printf("[Orchestrator] Initializing IOC Engine...\n");
        status = IocEngine_Initialize();
        if (!NT_SUCCESS(status)) {
            printf("[Orchestrator] IOC Engine init failed: 0x%X\n", status);
            IoaEngine_Cleanup();
            WkdEvent_CleanupSchema();
            StCleanup();
            DeleteCriticalSection(&Engine->Lock);
            return status;
        }
    }

    /* 5. 初始化策略引擎 */
    if (Config->AnalysisEnabled) {
        printf("[Orchestrator] Initializing Policy Engine...\n");
        PolicyEngine_Initialize(Config->AlertThrottleSeconds);
    }

    /* 6. 初始化消息队列 */
    printf("[Orchestrator] Initializing Message Queue...\n");
    status = NtfInitializeMessageQueueMessageQueue(&Engine->MessageQueue,
        WKD_MSG_QUEUE_MAX_SIZE, OrcWkdMessageHandler, Engine);
    if (!NT_SUCCESS(status)) {
        if (Config->AnalysisEnabled) { PolicyEngine_Cleanup(); IocEngine_Cleanup(); }
        IoaEngine_Cleanup();
            WkdEvent_CleanupSchema();
            StCleanup();
        DeleteCriticalSection(&Engine->Lock);
        return status;
    }

    Engine->Initialized = TRUE;
    // if (Config->StatsCollection) RtlZeroMemory(&Engine->Stats, sizeof(ORC_ENGINE_STATS));
    printf("\n[Orchestrator] All subsystems initialized successfully\n\n");
    return STATUS_SUCCESS;
}

NTSTATUS CgEngineStart(_In_ PORC_ENGINE Engine)
{
    NTSTATUS status; DWORD tid;
    if (!Engine || !Engine->Initialized) return STATUS_INVALID_PARAMETER;

    status = WkdMsgQueueStartProcessing(&Engine->MessageQueue);
    if (!NT_SUCCESS(status)) return status;

    /* 原有: 图修剪维护线程 */
    Engine->MaintenanceRunning = TRUE;
    // Engine->MaintenanceThread = CreateThread(NULL, 0, CgEngineMaintenanceThread, Engine, 0, &tid);
    // if (!Engine->MaintenanceThread) {
    //     WkdMsgQueueStopProcessing(&Engine->MessageQueue);
    //     return STATUS_UNSUCCESSFUL;
    // }

    /* 新增: FSM 过期追踪器清理线程 */
    Engine->FsmCleanupRunning = TRUE;
    // Engine->FsmCleanupThread = CreateThread(NULL, 0, CgFsmCleanupThread, Engine, 0, &tid);
    // if (!Engine->FsmCleanupThread) {
    //     Engine->FsmCleanupRunning = FALSE;
    //     Engine->MaintenanceRunning = FALSE;
    //     WaitForSingleObject(Engine->MaintenanceThread, 5000);
    //     CloseHandle(Engine->MaintenanceThread);
    //     WkdMsgQueueStopProcessing(&Engine->MessageQueue);
    //     return STATUS_UNSUCCESSFUL;
    // }

    /* 环形缓冲区消费线程 (由 GrbStartConsumer 管理) */
    status = GrbStartConsumer(WkdIoaEngine.RingBuffer);
    if (!NT_SUCCESS(status)) {
        Engine->FsmCleanupRunning = FALSE;
        WaitForSingleObject(Engine->FsmCleanupThread, 5000);
        CloseHandle(Engine->FsmCleanupThread);
        Engine->MaintenanceRunning = FALSE;
        WaitForSingleObject(Engine->MaintenanceThread, 5000);
        CloseHandle(Engine->MaintenanceThread);
        WkdMsgQueueStopProcessing(&Engine->MessageQueue);
        return STATUS_UNSUCCESSFUL;
    }

    /* Tier 2 告警异步处理线程 */
    Engine->T2AlertRunning = TRUE;
    Engine->T2AlertThread = CreateThread(NULL, 0, CgT2AlertThread, Engine, 0, &tid);
    if (!Engine->T2AlertThread) {
        Engine->T2AlertRunning = FALSE;
        GrbStopConsumer(WkdIoaEngine.RingBuffer);
        Engine->FsmCleanupRunning = FALSE;
        WaitForSingleObject(Engine->FsmCleanupThread, 5000);
        CloseHandle(Engine->FsmCleanupThread);
        Engine->MaintenanceRunning = FALSE;
        WaitForSingleObject(Engine->MaintenanceThread, 5000);
        CloseHandle(Engine->MaintenanceThread);
        WkdMsgQueueStopProcessing(&Engine->MessageQueue);
        return STATUS_UNSUCCESSFUL;
    }

    /* Tier 3 深度取证异步处理线程 */
    if (WkdIoaEngine.Tier3 && WkdIoaEngine.Tier3->Initialized) {
        Engine->T3MaintenanceRunning = TRUE;
        Engine->T3MaintenanceThread = CreateThread(NULL, 0,
            CgT3MaintenanceThread, WkdIoaEngine.Tier3, 0, &tid);
        if (!Engine->T3MaintenanceThread) {
            Engine->T3MaintenanceRunning = FALSE;
            printf("[Orchestrator] WARNING: T3 worker thread creation failed\n");
        }
    }

    Engine->Running = TRUE;
    printf("[Orchestrator] Started (%s background threads)\n",
           Engine->T3MaintenanceThread ? L"5" : L"4");
    return STATUS_SUCCESS;
}

NTSTATUS CgEngineStop(_In_ PORC_ENGINE Engine)
{
    if (!Engine || !Engine->Running) return STATUS_INVALID_DEVICE_STATE;
    Engine->Running = FALSE;

    /* 逆序停止: T3维护 → T2 → RingConsumer(Grb) → FsmCleanup → Maintenance */
    Engine->T3MaintenanceRunning = FALSE;
    if (Engine->T3MaintenanceThread) {
        WaitForSingleObject(Engine->T3MaintenanceThread, 5000);
        CloseHandle(Engine->T3MaintenanceThread);
        Engine->T3MaintenanceThread = NULL;
    }

    Engine->T2AlertRunning = FALSE;
    if (Engine->T2AlertThread) {
        WaitForSingleObject(Engine->T2AlertThread, 5000);
        CloseHandle(Engine->T2AlertThread);
        Engine->T2AlertThread = NULL;
    }

    GrbStopConsumer(WkdIoaEngine.RingBuffer);

    Engine->FsmCleanupRunning = FALSE;
    if (Engine->FsmCleanupThread) {
        WaitForSingleObject(Engine->FsmCleanupThread, 5000);
        CloseHandle(Engine->FsmCleanupThread);
        Engine->FsmCleanupThread = NULL;
    }

    Engine->MaintenanceRunning = FALSE;
    if (Engine->MaintenanceThread) {
        WaitForSingleObject(Engine->MaintenanceThread, 5000);
        CloseHandle(Engine->MaintenanceThread);
        Engine->MaintenanceThread = NULL;
    }

    WkdMsgQueueStopProcessing(&Engine->MessageQueue);
    return STATUS_SUCCESS;
}

VOID CgEngineCleanup(_In_ PORC_ENGINE Engine)
{
    if (!Engine || !Engine->Initialized) return;
    if (Engine->Running) CgEngineStop(Engine);
    printf("[Orchestrator] Cleaning up...\n");
    if (Engine->Config.StatsCollection) CgEnginePrintStats(Engine);

    WkdMsgQueueCleanup(&Engine->MessageQueue);
    if (Engine->Config.AnalysisEnabled) { PolicyEngine_Cleanup(); IocEngine_Cleanup(); }
    IoaEngine_Cleanup();
    WkdEvent_CleanupSchema();
    StCleanup();

    Engine->Initialized = FALSE;
    DeleteCriticalSection(&Engine->Lock);
    printf("[Orchestrator] Cleanup complete\n");
}

VOID CgEnginePrintStats(_In_ PORC_ENGINE Engine)
{
    if (!Engine) return;
    printf("\n========================================\n");
    printf("  WkDefender Agent Statistics\n");
    printf("========================================\n");
    //printf("  Events Ingested: %lld (IOC:%lld IOA:%lld)\n",
    //       Engine->Stats.TotalEventsIngested, Engine->Stats.IocEvents, Engine->Stats.IoaEvents);
    //printf("  Threats Escalated: %lld\n", Engine->Stats.ThreatsEscalated);
    printf("========================================\n\n");
    IoaEngine_PrintStats();
    IocEngine_PrintStats();
}
