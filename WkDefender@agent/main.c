/**************************************************/
/*  WkDefender Agent — 统一入口 (IOC/IOA 双引擎)    */
/**************************************************/

#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <stdio.h>
#include <ntstatus.h>

#include "DefendTypes.h"
#include "Process/ProcessTree.h"               /* 进程域谱系树 (统一重构 2026-08-15) */
#include "Process/ProcessModule.h"             /* 进程域全局模块表 (统一重构 2026-08-15) */
#include "IOC/ImageAnalyzer/ImageAnalyzer.h"    /* 镜像分析流水线 + 异步工作线程 (2026-08-18) */
#include "Orchestrator/Engine.h"
#include "Notification/AlpcService.h"
#include "Notification/msg_queue.h"
#include "IOC/IocEngine.h"
#include "IOC/IocYaraScanner.h"
#include "Storage/YaraRule.h"
#include "IOA/IoaEngine.h"
#include "PolicyEngine/PolicyEngine.h"
#include "Storage/StorageEngine.h"
#include "Notification/EventParser.h"
#include "process_manager.h"
#include "log_manager.h"
#include "system_manager.h"
#include "ScanManager.h"                       /* 扫描编排层 (SS ScanEngine 迁移) */
#include "DirectoryMonitor.h"                  /* 目录监控编排层 (SS DirectoryMonitor 迁移 2026-08) */
#include "FileLockManager.h"                   /* 文件锁管理 (SS FileLockManager 迁移 2026-08) */
#include "MountPointMonitor.h"                 /* 挂载点监控 (SS MountPointMonitor 迁移 2026-08) */
#include "Common/Exempts/Exempts.h"    /* 统一豁免门面 (Exempts 重构 2026-08-14, 档案 #67, 替代 Whitelist/IocWhitelistPush) */
#include "Orchestrator/VerdictEngine.h"        /* 中央判定层 (SS ThreatDetector 迁移) */
#include "IOA/IoaPersistenceDetect.h"          /* 目录级持久化投放判定 (死代码) */
#include "IOA/IoaRansomwareDetect.h"           /* 目录级批量变化判定 (死代码) */
#include "Common/TextSanitize.h"               /* 日志消毒 (TxtSanitizeForDisplay) */
#include "Notification/NotificationService.h"
#include "Notification/YaraScanPort.h"
#include "Driver/Install.h"
#include "WkDefenderHeader.h"

WKDEFENDER_AGENT WkDefenderAgent;

/* YARA FLT 端口客户端线程（步骤 4，接收内核文件扫描请求） */
static HANDLE g_YaraScanThread = NULL;
static HANDLE g_YaraScanStop    = NULL;

/* 目录监控接线开关（死代码开关，默认关闭，对齐 g_IoaCmdLineAnalyzerEnabled）。
 * 置 TRUE 后 OnDirectoryEvent 触发扫描/持久化/勒索/告警消费链。
 * 编排器本体 (DirectoryMonitor_* 管理 API) 始终可用/SelfTest。 */
static BOOLEAN g_IoaDirectoryMonitorEnabled = FALSE;

/* 挂载点监控接线开关 (死代码开关, 默认关闭, 对齐 g_IoaDirectoryMonitorEnabled)。
 * 置 TRUE 后 OnMountEvent 触发设备威胁告警消费链 (NULL-NodeId 设备级告警)。
 * 编排器本体 (WkdMpm_* 管理 API) 始终可用/SelfTest。 */
static BOOLEAN g_IoaMountPointMonitorEnabled = FALSE;

/* 目录级勒索聚合状态（按 MonitorId 索引，取模防溢出，DirectoryMonitor 迁移 2026-08） */
static WKD_DIR_RANSOM_STATE g_DirRansomStates[WKD_DIR_MAX_MONITORS];

/**************************************************/
/*               扫描回调 → ALPC 通知               */
/*  ScanManager 进度/威胁/完成 → UI 通知端口       */
/**************************************************/

static VOID ScanManager_OnProgress(ULONG JobId, ULONG Progress, ULONG Files, ULONG Threats)
{
    UNREFERENCED_PARAMETER(JobId); UNREFERENCED_PARAMETER(Files); UNREFERENCED_PARAMETER(Threats);
    if (WkDefenderAgent.NotificationManager != NULL &&
        WkDefenderAgent.NotificationManager->AlpcServer != NULL) {
        WkdAlpcSendToUiEx(WkDefenderAgent.NotificationManager->AlpcServer,
            WkdAlpcMsg_ScanProgressNotification, &Progress, sizeof(Progress), 0);
    }
}

static VOID ScanManager_OnThreat(ULONG JobId, PWKD_SCAN_THREAT Threat)
{
    CHAR filePathA[260];
    CHAR threatNameA[64];
    CHAR buf[512];
    ULONG len;
    UNREFERENCED_PARAMETER(JobId);

    if (!Threat) return;
    WideCharToMultiByte(CP_UTF8, 0, Threat->FilePath,  -1, filePathA,  260, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, Threat->ThreatName, -1, threatNameA, 64,  NULL, NULL);
    /* 载荷 = "路径|威胁名|严重级(0低1中2高)" (UTF-8) */
    len = (ULONG)snprintf(buf, sizeof(buf), "%s|%s|%d", filePathA, threatNameA,
                          (int)Threat->Severity);
    if (WkDefenderAgent.NotificationManager != NULL &&
        WkDefenderAgent.NotificationManager->AlpcServer != NULL) {
        WkdAlpcSendToUiEx(WkDefenderAgent.NotificationManager->AlpcServer,
            WkdAlpcMsg_ThreatDetectedNotification, buf, len + 1, 0);
    }
}

static VOID ScanManager_OnComplete(ULONG JobId, ULONG Threats)
{
    UNREFERENCED_PARAMETER(JobId);
    if (WkDefenderAgent.NotificationManager != NULL &&
        WkDefenderAgent.NotificationManager->AlpcServer != NULL) {
        WkdAlpcSendToUiEx(WkDefenderAgent.NotificationManager->AlpcServer,
            WkdAlpcMsg_ScanCompletedNotification, &Threats, sizeof(Threats), 0);
    }
}

/**************************************************/
/*               目录监控事件回调                    */
/*  (DirectoryMonitor 迁移 2026-08, L2 独立信号源)  */
/**************************************************/

/* 构造 NULL-NodeId 目录级 Verdict (目录事件无进程上下文, 本地 GUID 生成) */
static VOID
DirBuildVerdict(
    _In_ ULONG                Score,
    _In_ DEF_THREAT_CATEGORY  Category,
    _In_ ULONG                DetectionFlags,
    _In_ PCWSTR               Description,
    _In_ const WKD_DIR_EVENT* Evt,
    _Out_ PWKD_VERDICT        Verdict
    )
{
    LARGE_INTEGER now;
    static volatile LONG64 sDirSeq = 0;

    RtlZeroMemory(Verdict, sizeof(*Verdict));
    GetSystemTimeAsFileTime((PFILETIME)&now);
    Verdict->VerdictId.Data1    = (ULONG)now.LowPart;
    Verdict->VerdictId.Data2    = (USHORT)(now.QuadPart >> 32);
    Verdict->VerdictId.Data3    = (USHORT)(InterlockedIncrement64(&sDirSeq) & 0xFFFF);
    Verdict->VerdictId.Data4[0] = (UCHAR)(sDirSeq >> 16);
    Verdict->Timestamp = now;
    /* SuspectNodeId/VictimNodeId = NULL GUID: 目录事件无进程上下文 */
    Verdict->ThreatScore       = min(Score, 100);
    Verdict->Severity          = (Score >= 70) ? DefThreatSeverity_Critical :
                                 (Score >= 50) ? DefThreatSeverity_High :
                                 (Score >= 30) ? DefThreatSeverity_Medium : DefThreatSeverity_Low;
    Verdict->Confidence        = 80;
    Verdict->ConfidenceLevel   = DefConfidence_Medium;
    Verdict->Category          = Category;
    Verdict->RecommendedAction = DefRespAction_Alert;
    Verdict->PrimarySource     = DefDetSrc_Behavior;
    Verdict->DetectionFlags    = DetectionFlags;
    TxtSanitizeForDisplay(Evt->Path, Verdict->ProcessName, WKD_VERDICT_NAME_LEN);
    wcscpy_s(Verdict->Description, WKD_VERDICT_DESC_LEN,
             Description ? Description : L"");
}

static VOID
OnDirectoryEvent(
    _In_ const WKD_DIR_EVENT* Evt
    )
/*++
Routine Description:
    目录监控事件回调 (DirectoryMonitor 迁移 2026-08)。
    RDCW 事件无进程上下文, 消费链独立于 IoaObserve 进程级主链:
      ① FileAdded → ScanFileDirect 触发扫描 (投放到 Downloads/Temp 即扫)
      ② FileAdded → IoaPersistence_CheckDirectoryDrop (Startup/AppData 投放)
      ③ Rename/Delete → IoaRansomware_CheckDirectoryActivity (目录级批量变化)
    任一命中 → 构造 NULL-NodeId 目录级告警 → VerdictEngine 持久化+通知。
    默认 g_IoaDirectoryMonitorEnabled=FALSE 死代码开关 (对齐惯例)。

Arguments:
    Evt — 目录监控事件 (RDCW, 无 PID)。

Return Value:
    无。
--*/
{
    ULONG score = 0;
    ULONG flags = 0;
    DEF_THREAT_CATEGORY category = DefThreatCat_SuspiciousBehavior;
    PCWSTR ext;
    WCHAR description[WKD_VERDICT_DESC_LEN];
    WKD_VERDICT verdict;
    PIOA_ALERT alert;

    if (!Evt || !g_IoaDirectoryMonitorEnabled) return;

    ext = wcsrchr(Evt->FileName, L'.');

    if (Evt->Action == WkdDirAct_FileAdded) {
        WCHAR fullPath[DEF_MAX_PATH + WKD_DIR_MAX_FILENAME];
        IOC_SCAN_RESULT result;
        size_t pl;

        /* ① 目录新增文件 → 单文件扫描 (ScanFileDirect 无内部锁, 回调线程安全) */
        wcscpy_s(fullPath, sizeof(fullPath) / sizeof(fullPath[0]), Evt->Path);
        pl = wcslen(fullPath);
        if (pl > 0 && fullPath[pl - 1] != L'\\' && fullPath[pl - 1] != L'/') {
            wcscat_s(fullPath, sizeof(fullPath) / sizeof(fullPath[0]), L"\\");
        }
        wcscat_s(fullPath, sizeof(fullPath) / sizeof(fullPath[0]), Evt->FileName);

        if (NT_SUCCESS(ScanManager_ScanFileDirect(fullPath, &result))) {
            if (result.FinalVerdict >= DefIocVerdict_Suspicious) {
                score    = (result.FinalVerdict >= DefIocVerdict_Malicious) ? 90 : 60;
                category = DefThreatCat_Malware;
                flags   |= DEF_BEHAVIOR_FLAG_PERSISTENCE;
                _snwprintf_s(description, WKD_VERDICT_DESC_LEN, _TRUNCATE,
                             L"Directory scan hit: %hs", result.ThreatName);
                goto build_alert;
            }
        }

        /* ② 持久化投放判定 (Startup/ntuser.dat/系统目录 DLL·SYS 植入) */
        score = IoaPersistence_CheckDirectoryDrop(Evt->Path, Evt->FileName, ext);
        if (score > 0) {
            category = DefThreatCat_Persistence;
            flags   |= DEF_BEHAVIOR_FLAG_PERSISTENCE;
            _snwprintf_s(description, WKD_VERDICT_DESC_LEN, _TRUNCATE,
                         L"Directory persistence drop: %s\\%s", Evt->Path, Evt->FileName);
            goto build_alert;
        }
        return;
    }

    /* ③ 目录级批量变化 (rename/delete) → 勒索判定 */
    if (Evt->Action == WkdDirAct_FileRenamed || Evt->Action == WkdDirAct_DirRenamed ||
        Evt->Action == WkdDirAct_FileRemoved || Evt->Action == WkdDirAct_DirRemoved) {
        ULONG idx = Evt->MonitorId % WKD_DIR_MAX_MONITORS;
        BOOLEAN isRename = (Evt->Action == WkdDirAct_FileRenamed ||
                            Evt->Action == WkdDirAct_DirRenamed);
        BOOLEAN isDelete = (Evt->Action == WkdDirAct_FileRemoved ||
                            Evt->Action == WkdDirAct_DirRemoved);

        score = IoaRansomware_CheckDirectoryActivity(
            &g_DirRansomStates[idx], isRename, isDelete, Evt->FileName);
        if (score > 0) {
            category = DefThreatCat_Ransomware;
            flags   |= DEF_BEHAVIOR_FLAG_RANSOMWARE_ENC;
            _snwprintf_s(description, WKD_VERDICT_DESC_LEN, _TRUNCATE,
                         L"Directory %s activity: %s\\%s",
                         isRename ? L"mass rename" : L"mass delete",
                         Evt->Path, Evt->FileName);
            goto build_alert;
        }
        return;
    }

    return;

build_alert:
    DirBuildVerdict(score, category, flags, description, Evt, &verdict);
    VerdictEngine_UpsertActiveThreat(&verdict);
    alert = VerdictEngine_AllocPersistAlert(&verdict);
    if (alert) {
        IoaPersistQueueEnqueue(WkdIoaEngine.PersistQueue,
            PersistType_Alert, alert,
            (PERSIST_SERDE_WRITE_FN)StPersistAlert, TRUE);
    }
    /* UI 主动通知 (载荷 = WKD_VERDICT, 对齐 Engine.c 阶段6) */
    WkdAlpcSendToUiEx(&WkdDefaultAlpcServer,
        WkdAlpcMsg_ThreatVerdictNotification, &verdict, sizeof(verdict), 0);
    VerdictEngine_DispatchResponse(&verdict);
}

/**************************************************/
/*               挂载点监控事件回调                  */
/*  (MountPointMonitor 迁移 2026-08, L2 卷/设备级    */
/*   信号源, 无 PID 不进进程级因果主链)             */
/**************************************************/

/* 构造 NULL-NodeId 设备级 Verdict (卷/设备事件无进程上下文, 本地 GUID 生成,
 * 复用 DirBuildVerdict 同构) */
static VOID
MpmBuildVerdict(
    _In_ ULONG                Score,
    _In_ DEF_THREAT_CATEGORY  Category,
    _In_ ULONG                DetectionFlags,
    _In_ PCWSTR               Description,
    _In_ const WKD_MPM_MOUNT_EVENT* Evt,
    _Out_ PWKD_VERDICT        Verdict
    )
{
    LARGE_INTEGER now;
    static volatile LONG64 sMpmSeq = 0;

    RtlZeroMemory(Verdict, sizeof(*Verdict));
    GetSystemTimeAsFileTime((PFILETIME)&now);
    Verdict->VerdictId.Data1    = (ULONG)now.LowPart;
    Verdict->VerdictId.Data2    = (USHORT)(now.QuadPart >> 32);
    Verdict->VerdictId.Data3    = (USHORT)(InterlockedIncrement64(&sMpmSeq) & 0xFFFF);
    Verdict->VerdictId.Data4[0] = (UCHAR)(sMpmSeq >> 16);
    Verdict->Timestamp = now;
    /* SuspectNodeId/VictimNodeId = NULL GUID: 卷事件无进程上下文 */
    Verdict->ThreatScore       = min(Score, 100);
    Verdict->Severity          = (Score >= 70) ? DefThreatSeverity_Critical :
                                 (Score >= 50) ? DefThreatSeverity_High :
                                 (Score >= 30) ? DefThreatSeverity_Medium : DefThreatSeverity_Low;
    Verdict->Confidence        = 80;
    Verdict->ConfidenceLevel   = DefConfidence_Medium;
    Verdict->Category          = Category;
    Verdict->RecommendedAction = DefRespAction_Alert;
    Verdict->PrimarySource     = DefDetSrc_Behavior;
    Verdict->DetectionFlags    = DetectionFlags;
    TxtSanitizeForDisplay(Evt->Path, Verdict->ProcessName, WKD_VERDICT_NAME_LEN);
    wcscpy_s(Verdict->Description, WKD_VERDICT_DESC_LEN,
             Description ? Description : L"");
}

/* 挂载点监控事件回调 (MountPointMonitor 迁移 2026-08)。
 * 卷/设备事件无进程上下文, 消费链独立于 IoaObserve 进程级主链:
 *   DriveArrival + ThreatType != None → NULL-NodeId 设备级告警。
 * 默认 g_IoaMountPointMonitorEnabled=FALSE 死代码开关 (对齐惯例)。
 * MITRE: Masquerading→T1036/T1052.001; RubberDucky/BadUSB→T1091/T1200;
 *        Unauthorized/PolicyViolation→T1091 设备准入。 */
static VOID
OnMountEvent(
    _In_ const WKD_MPM_MOUNT_EVENT* Evt
    )
{
    ULONG score = 0;
    ULONG flags = 0;
    DEF_THREAT_CATEGORY category = DefThreatCat_SuspiciousBehavior;
    WCHAR description[WKD_VERDICT_DESC_LEN];
    WKD_VERDICT verdict;
    PIOA_ALERT alert;
    PCWSTR threatName;

    if (!Evt || !g_IoaMountPointMonitorEnabled) return;

    /* 仅处理到达事件 + 有威胁分类 */
    if (Evt->Event != WkdMpmEvent_DriveArrival ||
        Evt->DriveInfo.ThreatType == WkdMpmThreat_None) {
        return;
    }

    threatName = WkdMpm_GetDeviceThreatTypeName(Evt->DriveInfo.ThreatType);

    switch (Evt->DriveInfo.ThreatType) {
        case WkdMpmThreat_Masquerading:
            /* USB 伪装 CD-ROM: 类型伪装 T1036 */
            score    = 65;
            category = DefThreatCat_SuspiciousBehavior;
            flags   |= DEF_BEHAVIOR_FLAG_MASQUERADE;
            _snwprintf_s(description, WKD_VERDICT_DESC_LEN, _TRUNCATE,
                         L"USB device masquerading on %c: %ls (VID %ls/PID %ls)",
                         Evt->DriveInfo.DriveLetter, threatName,
                         Evt->DriveInfo.VendorId, Evt->DriveInfo.ProductId);
            break;

        case WkdMpmThreat_RubberDucky:
        case WkdMpmThreat_BadUSB:
            /* 硬件键盘注入/恶意 VID-PID: T1091/BadUSB T1200 */
            score    = 80;
            category = DefThreatCat_Malware;
            _snwprintf_s(description, WKD_VERDICT_DESC_LEN, _TRUNCATE,
                         L"BadUSB device on %c: %ls (VID %ls/PID %ls, serial %ls)",
                         Evt->DriveInfo.DriveLetter, threatName,
                         Evt->DriveInfo.VendorId, Evt->DriveInfo.ProductId,
                         Evt->DriveInfo.SerialNumber);
            break;

        case WkdMpmThreat_Unauthorized:
        case WkdMpmThreat_PolicyViolation:
        default:
            /* 非白名单/策略违反: 设备准入 T1091 */
            score    = 55;
            category = DefThreatCat_PolicyViolation;
            _snwprintf_s(description, WKD_VERDICT_DESC_LEN, _TRUNCATE,
                         L"Device policy violation on %c: %ls (serial %ls)",
                         Evt->DriveInfo.DriveLetter, threatName,
                         Evt->DriveInfo.SerialNumber);
            break;
    }

    MpmBuildVerdict(score, category, flags, description, Evt, &verdict);
    VerdictEngine_UpsertActiveThreat(&verdict);
    alert = VerdictEngine_AllocPersistAlert(&verdict);
    if (alert) {
        IoaPersistQueueEnqueue(WkdIoaEngine.PersistQueue,
            PersistType_Alert, alert,
            (PERSIST_SERDE_WRITE_FN)StPersistAlert, TRUE);
    }
    /* UI 主动通知 (载荷 = WKD_VERDICT, 对齐 Engine.c 阶段6) */
    WkdAlpcSendToUiEx(&WkdDefaultAlpcServer,
        WkdAlpcMsg_ThreatVerdictNotification, &verdict, sizeof(verdict), 0);
    VerdictEngine_DispatchResponse(&verdict);
}

/**************************************************/
/*               初始化                             */
/**************************************************/

static NTSTATUS InitializeSubsystems(VOID)
{
    NTSTATUS status;
    ORC_ENGINE_CONFIG cfg = CG_DEFAULT_CONFIG;

    printf("========================================\n");
    printf("  WkDefender Agent — IOC/IOA Dual Engine\n");
    printf("========================================\n\n");

    /* 1. 共用存储层 */
    printf("[Main] Initializing Storage...\n");
    status = StInitialize(cfg.WarmDbPath, cfg.ColdDbPath, cfg.ColdRetentionDays);
    if (!NT_SUCCESS(status)) { printf("[Main] Storage failed: 0x%X\n", status); return status; }

    /* 2. 事件解析 Schema */
    printf("[Main] Initializing Event Schema...\n");
    status = WkdEvent_InitializeSchema();
    if (!NT_SUCCESS(status)) { StCleanup(); return status; }

    /* 3. 进程域树 + 全局模块表 (须先于 IOA 引擎, Storage 已就绪) */
    printf("[Main] Initializing Process Tree...\n");
    status = PtTreeInitialize(&WkdProcessTree);
    if (!NT_SUCCESS(status)) { WkdEvent_CleanupSchema(); StCleanup(); return status; }
    PmInitialize();   /* 2026-08-15 进程域: 全局模块表（模块跟踪） */
    IaAsyncInitialize();   /* 2026-08-18: 镜像深度分析异步工作线程 */

    /* 3.5 IOA 引擎 (内部创建 Graph/Temporal/Scorer; 进程谱系由进程域树承担) */
    printf("[Main] Initializing IOA Engine...\n");
    {
        IOA_ENGINE_CONFIG ioaCfg = IOA_DEFAULT_CONFIG;
        ioaCfg.TemporalWindowMs = cfg.TemporalWindowMs;
        ioaCfg.ScoreDecayIntervalMs = cfg.ScoreDecayIntervalMs;
        status = IoaEngine_Initialize(&ioaCfg);
        if (!NT_SUCCESS(status)) { PtTreeCleanup(&WkdProcessTree); PmCleanup(); WkdEvent_CleanupSchema(); StCleanup(); return status; }
    }

    /* 4. IOC 引擎 */
    printf("[Main] Initializing IOC Engine...\n");
    status = IocEngine_Initialize();
    if (!NT_SUCCESS(status)) { IoaEngine_Cleanup(); WkdEvent_CleanupSchema(); StCleanup(); return status; }

    /* 4.5 自动导入 YARA 规则（规则表为空时从 TestData 灌入） */
    /*      PhantomSensor 签名：ImportFromYaraRulesRepo / AddRulesFromDirectory
     *      我们提供等价的 import-directory 入口，在 SQLite 空表时自动填充。     */
    if (YaraRule_GetRules() == NULL) {
        printf("[Main] yara_rules 表为空，自动从 TestData/YaraRules 导入...\n");
        status = YaraRule_ImportDirectory(L"TestData\\YaraRules");
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_NOT_FOUND) {
                printf("[Main] TestData/YaraRules 不存在或无可导入文件（跳过）\n");
            } else {
                printf("[Main] YaraRule_ImportDirectory 返回 0x%X（继续启动）\n", status);
            }
        } else {
            printf("[Main] YARA 规则导入完成\n");
        }
    }

    /* 5. 策略引擎 */
    printf("[Main] Initializing Policy Engine...\n");
    status = PolicyEngine_Initialize(cfg.AlertThrottleSeconds);
    if (!NT_SUCCESS(status)) { IocEngine_Cleanup(); IoaEngine_Cleanup(); WkdEvent_CleanupSchema(); StCleanup(); return status; }

    /* 6. 进程域树已由步骤 3 初始化（进程表收编，g_ProcessHashTable 已删除 2026-08-15） */

    /* 7. NotificationService */
    printf("[Main] Initializing NotificationService...\n");
    status = NtfInitializeService();
    if (!NT_SUCCESS(status)) { PolicyEngine_Cleanup(); IocEngine_Cleanup(); IoaEngine_Cleanup(); PtTreeCleanup(&WkdProcessTree); WkdEvent_CleanupSchema(); StCleanup(); return status; }
    WkDefenderAgent.NotificationManager = &WkdNotificationService;

    /* 8. ProcessManager */
    status = ProcessManager_InitializeService(NULL);
    if (!NT_SUCCESS(status)) { goto cleanup_7; }

    /* 9. LogManager */
    status = LogManager_InitializeService(&g_LogManager, L"WkDefender.db", NULL);
    if (!NT_SUCCESS(status)) { ProcessManager_Cleanup(); goto cleanup_7; }

    /* 10. SystemManager */
    status = SystemManager_InitializeService(NULL);
    if (!NT_SUCCESS(status)) { LogManager_Cleanup(&g_LogManager); ProcessManager_Cleanup(); goto cleanup_7; }

    /* 11. CGE 编排层 (消息队列) */
    printf("[Main] Initializing CGE Engine...\n");
    status = OrcEngineInitialize(&WkdOrchestratorEngine, &cfg);
    if (!NT_SUCCESS(status)) { SystemManager_Cleanup(); LogManager_Cleanup(&g_LogManager); ProcessManager_Cleanup(); goto cleanup_7; }

    /* 12. CGE 路由注册
     * Driver→Agent 段 [0x3001, 0x300C]：进程/线程/镜像/文件/命名管道事件
     * 统一入队 OrcWkdMessageEnqueueCallback，内部按 WKD_MESSAGE.Header.Type
     * 细粒度分发。0x300C = WkdAlpcMessage_NamedPipeEvent（NamedPipeMonitor
     * 迁移 2026-08）。 */
    AlpcRegisterRoute(&WkdDefaultAlpcServer,
        WkdAlpcMessage_ProcessCreate, WkdAlpcMessage_NamedPipeEvent,
        OrcWkdMessageEnqueueCallback, &WkdOrchestratorEngine);

    /* 12.5 VerdictEngine 中央判定层 (ShadowStrike ThreatDetector 迁移, 2026-08-04)
     *      多引擎融合 + 活跃威胁管理 + 响应分发 (monitor-only)。
     *      阶段6 已在 OrcpWkdMessageDispatcher 接线。 */
    printf("[Main] Initializing VerdictEngine...\n");
    status = VerdictEngine_Initialize(NULL);
    if (!NT_SUCCESS(status)) { goto cleanup_7; }

    /* VerdictEngine 查询路由 (UI→Agent 活跃威胁/单判定, 精确单点范围) */
    AlpcRegisterRoute(&WkdDefaultAlpcServer,
        WkdAlpcMsg_GetActiveThreatsReq, WkdAlpcMsg_GetActiveThreatsReq,
        VerdictEngine_GetActiveThreatsHandler, NULL);
    AlpcRegisterRoute(&WkdDefaultAlpcServer,
        WkdAlpcMsg_GetVerdictReq, WkdAlpcMsg_GetVerdictReq,
        VerdictEngine_GetVerdictHandler, NULL);

    /* 12.7 Exempts 排除子系统 (SS Whitelist 重构 2026-08-14, 档案 #67)
     *      统一豁免门面 (替代 IocFileWhitelist/WhiteListStore/IocWhitelistPush/
     *      IocInjectionWhitelist 四处)。ScanManager/DirectoryMonitor/IoaEngine 消费。
     *      规则加载自 SQLite exempt_rules 表; 系统组件采集 + ALPC 推送在
     *      Notification 服务就绪后 (步骤 17)。须先于 ScanManager 初始化。 */
    printf("[Main] Initializing Exempts...\n");
    status = ExemptsInitialize();
    if (!NT_SUCCESS(status)) { goto cleanup_13; }

    /* 13. ScanManager 扫描编排层 (SS ScanEngine 迁移, 2026-08-04) */
    printf("[Main] Initializing ScanManager...\n");
    status = ScanManager_Initialize();
    if (!NT_SUCCESS(status)) { goto cleanup_13; }
    ScanManager_SetCallbacks(ScanManager_OnProgress, ScanManager_OnComplete);
    ScanManager_SetThreatCallback(ScanManager_OnThreat);

    /* 14. DirectoryMonitor 目录监控编排层 (SS DirectoryMonitor 迁移, 2026-08)
     *      目录级状态监控事件源 (L2 独立信号源, RDCW 无 PID 不进进程级因果主链)。
     *      消费链 (扫描触发/持久化/勒索/告警) 默认 g_IoaDirectoryMonitorEnabled=FALSE
     *      死代码开关, 编排器本体初始化 + 关键路径监控始终启用。 */
    printf("[Main] Initializing DirectoryMonitor...\n");
    status = DirectoryMonitor_Initialize(NULL);
    if (!NT_SUCCESS(status)) { goto cleanup_13; }
    DirectoryMonitor_SetEventCallback(OnDirectoryEvent);
    // DirectoryMonitor_MonitorCriticalPaths();

    /* 15. FileLockManager 文件锁管理 (SS FileLockManager 迁移, 2026-08)
     *      锁检测 (RM+句柄枚举) + 五级解锁链 + 重启调度 + 锁模式威胁关联。
     *      服务 ScanManager 锁探测门控 / quarantine 隔离 / FBE 回滚 / UI 多消费方。
     *      默认 Config (allowProcessTermination=FALSE, 防误杀)。 */
    printf("[Main] Initializing FileLockManager...\n");
    status = FileLockManager_Initialize(NULL);
    if (!NT_SUCCESS(status)) { goto cleanup_13; }

    /* 16. MountPointMonitor 挂载点监控 (SS MountPointMonitor 迁移, 2026-08)
     *      卷/设备级事件源 (WM_DEVICECHANGE 自足, 不依赖驱动)。
     *      消费链 (设备威胁告警) 默认 g_IoaMountPointMonitorEnabled=FALSE
     *      死代码开关, 编排器本体初始化 + 消息窗口线程始终启用。 */
    printf("[Main] Initializing MountPointMonitor...\n");
    status = WkdMpm_Initialize(NULL);
    if (!NT_SUCCESS(status)) { goto cleanup_16; }
    WkdMpm_SetMountEventCallback(OnMountEvent);
    status = WkdMpm_Start();
    if (!NT_SUCCESS(status)) { goto cleanup_16; }

    /* 17. Exempts 系统可信哈希生产与推送 (Exempts 重构 2026-08-14, 档案 #67)
     *      枚举系统组件 SHA256 写入 Exempts 规则库（agent 本地豁免判定）
     *      + ALPC 0x3105 推送 Path 规则至 driver（驱动 Exempts 不消费
     *      TrustedHash）。失败不阻断 (驱动重连后 ExemptsPushAll 重推)。 */
    //printf("[Main] Pushing Exempts to driver...\n");
    //status = ExemptsPushAll();
    //if (!NT_SUCCESS(status)) {
    //    printf("[Main] WARNING: ExemptsPushAll failed: 0x%X\n", status);
    //}

    printf("[Main] All subsystems initialized\n\n");
    return STATUS_SUCCESS;

cleanup_16:
    WkdMpm_Cleanup();

cleanup_13:
    ScanManager_Cleanup();
    ExemptsCleanup();               /* Exempts 统一豁免门面 (重构 #67) */
    VerdictEngine_Cleanup();

cleanup_7:
    NotificationManager_Cleanup(WkDefenderAgent.NotificationManager);
    WkDefenderAgent.NotificationManager = NULL;
    PolicyEngine_Cleanup(); IocEngine_Cleanup(); IoaEngine_Cleanup();
    PtTreeCleanup(&WkdProcessTree);
    IaAsyncShutdown();   /* 2026-08-18: 先停深度工作线程, 释放未处理 pin */
    PmCleanup();   /* 2026-08-15 进程域: 全局模块表 */
    WkdEvent_CleanupSchema(); StCleanup();
    return status;
}

/**************************************************/
/*               启动所有模块                       */
/**************************************************/

static NTSTATUS StartAllModules(VOID)
{
    NTSTATUS s;

    /* 1. CGE 引擎 */
    printf("[Main] Starting CGE Engine...\n");
    s = CgEngineStart(&WkdOrchestratorEngine); if (!NT_SUCCESS(s)) return s;

    /* 2. 各模块消息队列 */
    printf("[Main] Starting ProcessManager queue...\n");
    s = WkdMsgQueueStartProcessing(&g_ProcessManager.MessageQueue); if (!NT_SUCCESS(s)) return s;
    printf("[Main] Starting LogManager queue...\n");
    s = WkdMsgQueueStartProcessing(&g_LogManager.MessageQueue); if (!NT_SUCCESS(s)) { WkdMsgQueueStopProcessing(&g_ProcessManager.MessageQueue); return s; }
    printf("[Main] Starting SystemManager queue...\n");
    s = WkdMsgQueueStartProcessing(&g_SystemManager.MessageQueue); if (!NT_SUCCESS(s)) { WkdMsgQueueStopProcessing(&g_LogManager.MessageQueue); WkdMsgQueueStopProcessing(&g_ProcessManager.MessageQueue); return s; }
    printf("[Main] Starting IocYara queue...\n");
    s = WkdMsgQueueStartProcessing(&g_IocEngine.YaraScanner.Queue); if (!NT_SUCCESS(s)) { WkdMsgQueueStopProcessing(&g_SystemManager.MessageQueue); WkdMsgQueueStopProcessing(&g_LogManager.MessageQueue); WkdMsgQueueStopProcessing(&g_ProcessManager.MessageQueue); return s; }
    printf("[Main] Starting NotificationManager queue...\n");
    s = WkdMsgQueueStartProcessing(&WkdNotificationService.MessageQueue); if (!NT_SUCCESS(s)) { WkdMsgQueueStopProcessing(&g_IocEngine.YaraScanner.Queue); WkdMsgQueueStopProcessing(&g_SystemManager.MessageQueue); WkdMsgQueueStopProcessing(&g_LogManager.MessageQueue); WkdMsgQueueStopProcessing(&g_ProcessManager.MessageQueue); return s; }

    /* 3. NotificationManager (ALPC + Pipe) */
    printf("[Main] Starting NotificationManager (ALPC + Pipe)...\n");
    s = NtfStartService(WkDefenderAgent.NotificationManager);
    if (!NT_SUCCESS(s)) { WkdMsgQueueStopProcessing(&WkdNotificationService.MessageQueue); WkdMsgQueueStopProcessing(&g_IocEngine.YaraScanner.Queue); WkdMsgQueueStopProcessing(&g_SystemManager.MessageQueue); WkdMsgQueueStopProcessing(&g_LogManager.MessageQueue); WkdMsgQueueStopProcessing(&g_ProcessManager.MessageQueue); return s; }

    /* 4.1 YARA FLT 端口客户端（与内核 \\WkDefenderYaraPort 对接，单线程） */
    // g_YaraScanStop = CreateEventW(NULL, TRUE, FALSE, NULL);
    // if (g_YaraScanStop) {
    //     g_YaraScanThread = YaraScanPort_Start(g_YaraScanStop);
    //     if (!g_YaraScanThread) {
    //         CloseHandle(g_YaraScanStop); g_YaraScanStop = NULL;
    //     }
    // }

    printf("[Main] All modules started\n\n");
    return STATUS_SUCCESS;
}

/**************************************************/
/*               清理                               */
/**************************************************/

static VOID CleanupAllModules(VOID)
{
    printf("[Main] Shutting down...\n");

    /* 先停 YARA 端口客户端线程（依赖 IocYara/Storage，须先于其清理） */
    if (g_YaraScanStop) SetEvent(g_YaraScanStop);
    if (g_YaraScanThread) {
        WaitForSingleObject(g_YaraScanThread, INFINITE);
        CloseHandle(g_YaraScanThread); g_YaraScanThread = NULL;
    }
    if (g_YaraScanStop) { CloseHandle(g_YaraScanStop); g_YaraScanStop = NULL; }

    NotificationManager_Cleanup(WkDefenderAgent.NotificationManager);
    WkDefenderAgent.NotificationManager = NULL;

    WkdMsgQueueStopProcessing(&g_SystemManager.MessageQueue); WkdMsgQueueCleanup(&g_SystemManager.MessageQueue);
    WkdMsgQueueStopProcessing(&g_LogManager.MessageQueue); WkdMsgQueueCleanup(&g_LogManager.MessageQueue);
    WkdMsgQueueStopProcessing(&g_ProcessManager.MessageQueue); WkdMsgQueueCleanup(&g_ProcessManager.MessageQueue);

    SystemManager_Cleanup(); LogManager_Cleanup(&g_LogManager); ProcessManager_Cleanup();
    DirectoryMonitor_Cleanup();                 /* 目录监控 (SS DirectoryMonitor 迁移 2026-08, 须先于 ScanManager 停 worker) */
    WkdMpm_Cleanup();                           /* 挂载点监控 (SS MountPointMonitor 迁移 2026-08, 须先于 StCleanup) */
    ScanManager_Cleanup();
    ExemptsCleanup();                           /* Exempts 统一豁免门面 (重构 #67, 须先于 StCleanup) */
    VerdictEngine_Cleanup();                    /* 中央判定层 (SS ThreatDetector 迁移) */
    FileLockManager_Shutdown();                 /* 文件锁管理 (SS FileLockManager 迁移 2026-08) */
    CgEngineCleanup(&WkdOrchestratorEngine);
    PolicyEngine_Cleanup(); IocEngine_Cleanup(); IoaEngine_Cleanup();
    WkdEvent_CleanupSchema(); StCleanup();

    printf("[Main] Shutdown complete\n");
}

/**************************************************/
/*                   主函数                         */
/**************************************************/

int main(int argc, char** argv)
{
    /* 步骤 7：运行前确保驱动已安装并加载（含 runas 自提权）。
     * 提权子进程（--install-driver）装完即退出；未提权时原进程发 runas 后退出。 */
    // NTSTATUS preStatus = EnsureDriverReady(argc, argv);
    // if (preStatus == STATUS_REBOOTED_FOR_INSTALL) {
    //     /* runas 子进程已接管安装，原进程直接退出，不重复初始化 */
    //     printf("[Agent] Elevated child handled driver install. Exiting.\n");
    //     return 0;
    // }
    // if (!NT_SUCCESS(preStatus)) {
    //     printf("[FATAL] Driver not ready: 0x%X\n", preStatus);
    //     getchar();
    //     return -1;
    // }

    NTSTATUS status = InitializeSubsystems();
    if (!NT_SUCCESS(status)) { printf("[FATAL] Init failed: 0x%X\n", status); getchar(); return -1; }

    status = StartAllModules();
    if (!NT_SUCCESS(status)) { printf("[FATAL] Start failed: 0x%X\n", status); CleanupAllModules(); getchar(); return -1; }

    printf("[Agent] ALPC: \\RPC Control\\WkDefender@Agent  Pipe: WkDefender_Notification_Service\n");
    printf("[Agent] IOC/IOA Dual Engine running. Press Enter to shutdown...\n\n");
    getchar();

    CleanupAllModules();
    printf("[Agent] Goodbye.\n");
    return 0;
}
