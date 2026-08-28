/**************************************************/
/*  WkDefender IOC 引擎 — 编排层实现                */
/*  IOC 是独立的静态分析引擎，可通过事件触发         */
/*  也可主动执行文件和内存扫描                      */
/**************************************************/

#include "IocEngine.h"
#include "IocProcessEnrich.h"
#include "IocMatcher.h"          /* 实时IOC匹配引擎（布隆过滤器+域名/IP/通配符） */
#include "ImageAnalyzer/ImageAnalyzer.h" /* 统一镜像分析流水线 (2026-08-15) */
#include "../IOA/IoaTypes.h"     /* 使用 IOA 的进程节点定义 */
#include "../IOA/Tier1/T1ShellcodeDetect.h" /* IocDetectShellcode / T1_SC_* 标志 */
#include "../Memory/MemoryScan.h"    /* 机制 B 进程内存 YARA */
#include "../Storage/YaraRule.h"     /* YARA 规则管理（初始化/重载） */
#include "../Storage/StorageEngine.h" /* 告警落库 (cg_alerts) */
#include "../Common/Exempts/Exempts.h" /* 进程身份豁免（无镜像假进程快速通道） */
#include "../Process/ProcessTypes.h"  /* WKD_THREAD / PWKD_THREAD */
#include "../Process/ProcessThread.h" /* PsThreadAttachProcess 返回值类型 */
#include "../Process/ProcessModule.h" /* PsFindOrCreateModule / PsModuleInstanceAttachProcess (主映像实例化, 2026-08-25) */
#include "../WkDefenderHeader.h"      /* IMG_SIGNATURE_UNEVALUATED (主映像补挂签名占位, 2026-08-25) */
#include "../ProcessThreads.h"        /* WptHasShellcodeAt (线程入口字节级判定) */
#include <sqlite3.h>

/**************************************************/
/*               全局实例                           */
/**************************************************/

IOC_ENGINE g_IocEngine = { 0 };

/**************************************************/
/*                   公开 API                       */
/**************************************************/

NTSTATUS
IocEngine_Initialize(
    VOID
    )
/*++
Routine Description:
    初始化 IOC 引擎和 YARA 异步扫描器。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;
    
    RtlZeroMemory(&g_IocEngine, sizeof(g_IocEngine));

    /* 0. 进程历史追踪器（PID 复用检测） */
    IpeInitHistoricalTracker(1024);

    /* 1. YARA 规则引擎初始化（yr_initialize + 编译全部规则） */
    status = YaraRule_Initialize();
    if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND) {
        printf("[IocEngine] YaraRule_Initialize returned 0x%X (continuing)\n", status);
    }

    /* 1. YARA 扫描器初始化（消息队列） */
    status = IocYara_Initialize(&g_IocEngine.YaraScanner);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* 2. 机制 B：构建 AC 模式索引（与机制 A 同源 yara_rules 表） */
    MsScanInitialize();

    /* 初始化已知系统 DLL 函数地址缓存（供 Tier3 等模块查询） */
    IocInitKnownDllAddresses();

    g_IocEngine.Initialized = TRUE;

    /* 5. 实时 IOC 匹配引擎（布隆过滤器 + 域名/IP/通配符匹配） */
    {
        IOC_MATCHER_CONFIG matcherCfg = IOC_MATCHER_DEFAULT_CONFIG;
        status = IocMatcher_Initialize(&matcherCfg);
        if (!NT_SUCCESS(status)) {
            printf("[IocEngine] IocMatcher_Initialize returned 0x%X (continuing)\n", status);
        }
    }

    printf("[IocEngine] Initialized — independent static analysis engine\n");
    printf("[IocEngine] Capabilities: Hash/Cert/LOLBin/Cmdline/PE/YARA/KnownDll\n");
    return STATUS_SUCCESS;
}

VOID
IocEngine_Cleanup(
    VOID
    )
/*++
Routine Description:
    清理 IOC 引擎和 YARA 扫描器。
    严格遵循清理时序（与初始化逆向）：
      1) 停止异步扫描（IocYara_Cleanup — 停消息队列，等待 in-flight 完成）
      2) 停止机制 B 内存扫描（MsScanCleanup）
      3) 销毁规则（YaraRule_Cleanup — 持 Level 1 Exclusive 等待所有扫描结束）

Return Value:
    无。
--*/
{
    if (!g_IocEngine.Initialized) return;

    IocEngine_PrintStats();

    /* STEP 1: 停止 YARA 消息队列（阻止新扫描请求入队） */
    IocYara_Cleanup(&g_IocEngine.YaraScanner);

    /* STEP 2: 停止机制 B 内存扫描 */
    MsScanCleanup();

    /* STEP 3: 销毁规则（AcquireExclusive(g_YaraLock) 等待所有 in-flight 扫描结束） */
    YaraRule_Cleanup();

    /* STEP 4: 清理历史追踪器 */
    IpeCleanupHistoricalTracker();

    /* STEP 5: 关闭实时 IOC 匹配引擎 */
    IocMatcher_Shutdown();

    printf("[IocEngine] Cleanup complete\n");
    g_IocEngine.Initialized = FALSE;
}

NTSTATUS
IocObserveProcess(
    _Inout_ PWKD_PROCESS WkdProcess
    )
/*++
Routine Description:
    进程创建事件驱动入口。由 Engine.c 在流水线中调用。
    调度各 IOC 检测器对进程进行静态分析，结果直接写入 Node。

Arguments:
    Process — IOA 管理的进程节点（SecCtx.IocVerdict/IocConfidence 在此更新）。

Return Value:
    NTSTATUS。
--*/
{
    IOC_SCAN_RESULT result;

    if (!g_IocEngine.Initialized || !WkdProcess) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&result, sizeof(result));

    /* 进程身份豁免快速通道（2026-08-20，Exempts 子系统）：
     * 无镜像内核假进程（System/Registry/Secure System/Memory
     * Compression）没有真实可执行文件，深度静态分析无输入意义，
     * 伪路径会触发无效磁盘 IO、污染信号与统计。用户态无法伪装
     * 这些名字（内核假进程），豁免无绕过面；名单红线见
     * Exempts.h CoExemptPseudoSystemProcess 注记——有真实文件的
     * 进程禁止按名豁免，其豁免走 ExemptsEvaluate 文件四维。 */
    if (CoExemptPseudoSystemProcess(WkdProcess->ImagePath->Buffer)) {
        InterlockedIncrement(&g_IocEngine.Stats.SystemSkipped);
        return STATUS_SUCCESS;
    }

    InterlockedIncrement(&g_IocEngine.Stats.TotalScans);

    /*
     * 进程富化步骤（对齐 PS ProcessMonitor 的 EnrichFromLiveProcess）
     * 在静态扫描前执行，确保分类/身份信息已就绪。
     */
    {
        /*
         * 进程分类（对齐 PS CategorizeProcess，17 分类）
         */
        //Node->ProcessCategory = (ULONG)IpeCategorizeProcess(
        //    Node->ImageFileName ? (Node->ImageFileName->Buffer ? Node->ImageFileName->Buffer : L"") : L"",
        //    Node->ImagePath ? (Node->ImagePath->Buffer ? Node->ImagePath->Buffer : L"") : L"");

        /*
         * 用户身份 + 完整性采集（对齐 PS GetProcessUser / GetIntegrityLevel）
         * 仅在 UserName 为空时补充（内核可能已通过 ALPC 发送）
         */
        // 这部分完全可以在内核完成???
        //if (Process->UserName[0] == L'\0' &&
        //    Process->ProcessId != 0 &&
        //    Process->ProcessId != 4) {
        //    WKD_USER_CONTEXT userCtx;
        //    if (IpeCollectUserContext(Process->ProcessId, &userCtx)) {
        //        wcsncpy_s(Process->UserName, RTL_NUMBER_OF(Process->UserName),
        //                  userCtx.UserName, _TRUNCATE);
        //        wcsncpy_s(Process->DomainName, RTL_NUMBER_OF(Process->DomainName),
        //                  userCtx.DomainName, _TRUNCATE);
        //        if (!Process->IntegrityLevel)
        //            Process->IntegrityLevel = userCtx.IntegrityLevel;
        //        if (!Process->IsElevated)
        //            Process->IsElevated = userCtx.IsElevated;
        //    }
        //}

        /*
         * 父-子关系全面分析（对齐 PS AnalyzeParentChildInternal）。
         * PPID 时序检测已归并至此——IpeDetectPpidSpoofing 由 IpeAnalyzeParentChild
         * 内部调用，经 pcResult.IsPpidSpoofed 置标志，不再在此独立调用（防双计）。
         */
        //{
        //    WKD_PARENT_CHILD_RESULT pcResult;
        //    // 这部分可以结合进程谱系图进行分析
        //    IpeAnalyzeParentChild(Process, Process->Parent, &pcResult);

        //    if (pcResult.Anomaly != WkdPaNormal) {
        //        printf("[IocEngine] ParentChild anomaly: PID=%lu type=%d reason=%ls score=%u\n",
        //            Process->ProcessId, pcResult.Anomaly,
        //               pcResult.AnomalyReason, pcResult.RiskScore);
        //        Process->CumulativeRiskScore += pcResult.RiskScore;

        //        if (pcResult.IsPpidSpoofed) {
        //            Process->BehaviorFlags |= DEF_BEHAVIOR_FLAG_PPID_SPOOF;
        //        }
        //    }
        //}

        /*
         * PID 复用检测（对齐 PS WasPidReused）
         */
        //if (IpeWasPidReused(Process->ProcessId, 5000)) {
        //    Process->CumulativeRiskScore += 15;
        //}
    }

    /*
     * 模块可疑检测（对齐 PS FindSuspiciousModulesFromList）已删除（2026-08-15）：
     * 进程创建时是空壳，Toolhelp TH32CS_SNAPMODULE 枚举必然为空/失败，
     * 该检测从未在正确时机工作过；后续模块加载全部有 ImageLoad 事件，
     * 经 PsHandleImageLoad 挂入模块域 + ImageAnalyzer 覆盖。模块级可疑检测
     * 收敛至 ImageLoad 流水线；存量进程模块由 ProcessSnapshot 补挂兜底。
     */

    /* 统一镜像分析流水线（ImageAnalyzer, 2026-08-15）：
     * 进程创建空壳无映射，只读磁盘分析 exe 镜像；建 WKD_MODULE
     * 权威副本，后续 ImageLoad 事件命中 O(1) 复用（消除重复解析）。
     * Cmdline 为进程级信号，随本调用合并进 result（不写模块 FileResult）。 */
    {
        PCWSTR filePath = CoCheckUnicodeStringValidity(WkdProcess->ImagePath) ?
                            WkdProcess->ImagePath->Buffer : NULL;
        PCWSTR cmdLine  = CoCheckUnicodeStringValidity(WkdProcess->CommandLine) ?
                            WkdProcess->CommandLine->Buffer : NULL;

        if (filePath) {
            PWKD_MODULE mainModule = NULL;

            /* 主映像实例化 (2026-08-25): 主映像加载先于监控注册/事件流,
             * 不会有对应 ImageLoad 事件 — 若不在此补挂, 进程模块列表
             * 将永久缺失 exe 视图。PsFindOrCreateModule 命中上方
             * IocAnalyseImage 刚建的权威副本 (OPsModuleInstanceAttachProcessNULL
             * 表征磁盘视图 (迟到的真实 ImageLoad 经 PmAttachInstance
             * 原位升级为映射视图)。失败静默 — 不影响分析兜底路径。 */
            if (NT_SUCCESS(PsFindOrCreateModule(filePath,
                                                0 /* 磁盘视图未知映射大小 */,
                                                IMG_SIGNATURE_UNEVALUATED,
                                                &mainModule))) {
                PsModuleInstanceAttachProcess(WkdProcess, mainModule, NULL, NULL);
                PsDereferenceWkdModule(mainModule);   /* 释放查找 pin */
            }
        } else if (cmdLine) {
            /* 无镜像路径（异常节点）→ 仅命令行扫描 */
            IocScanner_ScanCmdline(cmdLine, &result);
        }
    }

    // IocScan_LolbinCheck(fileName, Result);

    /* 进程镜像异步 YARA 扫描（归位 2026-08-15：恢复 IocYara_Enqueue
     * 唯一入队点，原被注释禁用；YARA 为进程级扫描，随进程创建触发） */
    //if (Process->ImagePath && Process->ImagePath->Buffer) {
    //    IocYara_Enqueue(&g_IocEngine.YaraScanner, Process);
    //    result.YaraSubmitted = TRUE;
    //}

    /* 统计 */
    if (result.HashChecked && result.HashVerdict >= DefIocVerdict_Suspicious)
        g_IocEngine.Stats.HashHits++;
    if (!result.CertTrusted)
        g_IocEngine.Stats.CertFailures++;
    if (result.IsLolbin)
        g_IocEngine.Stats.LolbinHits++;
    if (result.CmdlineFlags)
        g_IocEngine.Stats.CmdlineHits++;
    if (result.YaraSubmitted)
        g_IocEngine.Stats.YaraSubmitted++;

    /* 结果写入进程节点安全上下文 (2026-08-23 聚合至 SecCtx) */
    WkdProcess->SecCtx.IocVerdict    = result.FinalVerdict;
    WkdProcess->SecCtx.IocConfidence = result.FinalConfidence;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
IocObserveThread(
    _In_ PWKD_THREAD WkdThread,
    _In_ const EVENT_PAYLOAD_THREAD_CREATE* Payload
    )
/*++
Routine Description:
    线程创建事件驱动的 IOC 静态特征分析入口（对标 IocObserveProcess）。
    三级级联的第 ② 步：将 IOC 结论写回线程实体 IOC 区域。

    段1 — 同步轻量：直接消费 driver IocDetectThread 已计算的
          起始地址归属结论（IsUnusualEntry / IsStartAddrBacked），
          不重做归属检查（driver 已用 PsLookupWkdModuleContainingAddress
          完成模块区间判定）。
    段2 — 同步重型：对异常入口线程做字节级 shellcode 确认
          （OpenProcess + ReadProcessMemory + IocDetectShellcode）。

    [同步路径 · 调试期临时方案]
    段2 的字节级确认本应在异步 IOC 确认任务中执行（避免高频
    ThreadCreate 同步阻塞进程内存读取）。为便于联调可见结果，
    当前临时置于同步路径。后续接入异步队列时，将本段整体下沉，
    结果原子写回 IOC 区域。绝大多数正常线程（有模块背衬的本地
    线程）跳过段2，无 IO 开销。

    IOC 区域字段契约（为后期异步化预留）：
    本函数（或其异步后继）是 IOC 区域三字段唯一写者；
    IOA 行为分析只读、永不回写。

Arguments:
    WkdThread — 刚由 PsThreadAttachProcess 挂载的线程实体节点。
    Payload   — 线程创建事件载荷（含 driver 上送的归属结论）。

Return Value:
    NTSTATUS。
--*/
{
    HANDLE hProcess;
    ULONG scFlags;
    UCHAR buf[256];
    SIZE_T read = 0;
    PVOID address;
    NTSTATUS status = STATUS_SUCCESS;

    if (!WkdThread || !Payload) return STATUS_INVALID_PARAMETER;

    /* ---- Step 1：消费 driver 已计算的归属结论 ---- */
    WkdThread->IoacUnusualEntry    = Payload->IsUnusualEntry;
    WkdThread->IoacUnbackedStart   = !Payload->IsStartAddrBacked;

    /* 拒绝越界 (对齐 SS kUserModeMax 防回绕) */
    address = Payload->StartRoutine;
    if (address < 0x10000 || address > 0x7FFFFFFFFFFFULL) return STATUS_INVALID_ADDRESS;

    /*
     * ── 段2：字节级 shellcode 确认（仅异常入口线程触发）──
     * 正常线程（有模块背衬 = IsStartAddrBacked）跳过，无 IO 开销。
     */
    if (!(WkdThread->IoacUnbackedStart || WkdThread->IoacUnusualEntry)) {
        return STATUS_SUCCESS;
    }

    hProcess = OpenProcess(PROCESS_VM_READ, FALSE,
                            HandleToULong(Payload->ProcessId));
    if (!hProcess) return STATUS_UNSUCCESSFUL;

    if (!ReadProcessMemory(hProcess, (LPCVOID)address, buf, sizeof(buf), &read) || read < 20) {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    // IocDetectShellcode(buf, (ULONG)read, TRUE);

    /* ROP 栈分析 */

   /* if (scFlags & (T1_SC_APIHASH | T1_SC_SYSCALL |
                   T1_SC_ROP_CHAIN | T1_SC_NOP_SLED)) {
        WkdThread->IoacShellcodeSuspected = TRUE;
    }*/

Cleanup:
    if (hProcess) CloseHandle(hProcess);
    return status;
}

NTSTATUS
IocEngine_ScanFile(
    _In_  PCWSTR            FilePath,
    _Out_ IOC_SCAN_RESULT*  Result
    )
/*++
Routine Description:
    主动扫描指定文件（独立于进程事件）。
    可用于 UI 触发的按需扫描或定时扫描关键目录。

Arguments:
    FilePath — 文件完整路径。
    Result   — 输出扫描结果。

Return Value:
    NTSTATUS。
--*/
{
    if (!g_IocEngine.Initialized || !FilePath || !Result) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Result, sizeof(IOC_SCAN_RESULT));
    g_IocEngine.Stats.TotalScans++;
    return IocScanner_ScanFile(FilePath, Result);
}

/*++
 * IocEngine_WriteMemoryAlert
 *   内存扫描命中告警落库到 cg_alerts 表 (带 ProcessId/RegionBase/Mitre).
 *   对齐 WriteYaraAlert (IocYaraScanner.c) 的告警格式。
 *--*/
static VOID
IocEngine_WriteMemoryAlert(
    _In_ DWORD ProcessId,
    _In_ PWKD_MEM_THREAT Threat
    )
{
    sqlite3_stmt* stmt = NULL;
    CHAR alertId[64];
    CHAR desc[512];
    LARGE_INTEGER now;
    INT severity;

    if (!WkdStorageEngine.WarmDb || !Threat) return;

    GetSystemTimeAsFileTime((PFILETIME)&now);
    _snprintf_s(alertId, sizeof(alertId), _TRUNCATE,
                "MEM-%llx-%08lx", now.QuadPart, ProcessId);

    _snprintf_s(desc, sizeof(desc), _TRUNCATE,
                "Memory threat pid=%lu base=0x%llX rule=%s",
                ProcessId, (ULONGLONG)Threat->RegionBase, Threat->MatchedRule);

    const char* sql =
        "INSERT INTO cg_alerts "
        "(alert_id,timestamp,process_node_id,rule_name,mitre_id,"
        "severity,score,confidence,description) "
        "VALUES (?,?,?,?,?,?,?,?,?)";

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return;

    severity = (Threat->RiskScore > 75) ? 4 : (Threat->RiskScore > 50) ? 3 : 2;

    sqlite3_bind_text(stmt, 1, alertId, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, now.QuadPart);
    sqlite3_bind_text(stmt, 3, "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, Threat->MatchedRule, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, Threat->MitreTechnique, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, severity);
    sqlite3_bind_int(stmt, 7, (int)Threat->RiskScore);
    sqlite3_bind_int(stmt, 8, (int)Threat->Confidence);
    sqlite3_bind_text(stmt, 9, desc, -1, SQLITE_STATIC);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    WkdStorageEngine.WarmWrites++;
}

NTSTATUS
IocEngine_ScanMemory(
    _In_ PWKD_PROCESS Node
    )
/*++
Routine Description:
    对运行中进程执行全流程内存扫描 (ShadowStrike MemoryScanner 迁移):
      区域枚举 → 过滤 → TOCTOU → 检测层 (PE/壳码/高熵/C2) → 双引擎 YARA.
    命中结果出口:
      ① 告警落库 cg_alerts (IocEngine_WriteMemoryAlert)
      ② IOA 回填进程节点 (BehaviorFlags / CumulativeRiskScore)

Arguments:
    Node — 进程节点 (BehaviorFlags/CumulativeRiskScore 在此回填)。

Return Value:
    NTSTATUS。
--*/
{
    WKD_MEM_SCAN_RESULT result;
    DWORD pid;
    ULONG i;

    if (!g_IocEngine.Initialized || !Node) {
        return STATUS_INVALID_PARAMETER;
    }

    g_IocEngine.Stats.MemoryScans++;
    pid = (DWORD)(ULONG_PTR)Node->ProcessId;

    if (!NT_SUCCESS(MsScanProcessMemoryFull(pid, WkdMemScan_Normal, &result))) {
        return STATUS_UNSUCCESSFUL;
    }

    for (i = 0; i < result.ThreatsFound; i++) {
        PWKD_MEM_THREAT t = &result.Threats[i];

        /* ① 告警落库 */
        IocEngine_WriteMemoryAlert(pid, t);

        /* ② IOA 回填进程节点 */
        switch (t->Type) {
        case WkdMemThreat_PEInjection:
            InterlockedOr(&Node->BehaviorFlags, DEF_BEHAVIOR_FLAG_REFLECTIVE_LOAD);
            InterlockedExchangeAdd(&Node->CumulativeRiskScore, 40);
            break;
        case WkdMemThreat_Shellcode:
        case WkdMemThreat_APIHashing:
        case WkdMemThreat_SyscallStub:
        case WkdMemThreat_ROPChain:
            InterlockedOr(&Node->BehaviorFlags, DEF_BEHAVIOR_FLAG_INJECTION);
            InterlockedExchangeAdd(&Node->CumulativeRiskScore, 30);
            break;
        case WkdMemThreat_EncryptedPayload:
            InterlockedExchangeAdd(&Node->CumulativeRiskScore, 20);
            break;
        case WkdMemThreat_CobaltStrike:
        case WkdMemThreat_Meterpreter:
            /* 反射加载器签名 (MsDetectReflectiveLoader 在隐藏无背衬 PE 内命中,
               或 MsDetectC2Beacon 独立命中 C2 信标) → 反射加载活动 + 已知威胁分 */
            InterlockedOr(&Node->BehaviorFlags, DEF_BEHAVIOR_FLAG_REFLECTIVE_LOAD);
            InterlockedExchangeAdd(&Node->CumulativeRiskScore, 35);
            break;
        default:
            break;
        }
    }

    if (result.ThreatsFound > 0) {
        printf("[IocEngine] Memory scan PID=%lu threats=%lu risk=%u\n",
               pid, result.ThreatsFound, result.OverallRiskScore);
    }
    return STATUS_SUCCESS;
}

VOID
IocEngine_PrintStats(
    VOID
    )
{
    printf("\n");
    printf("  --- IOC Engine ---\n");
    printf("  Total Scans:         %lld\n", g_IocEngine.Stats.TotalScans);
    printf("  System Skipped:      %lld\n", g_IocEngine.Stats.SystemSkipped);
    printf("  Hash Hits:           %lld\n", g_IocEngine.Stats.HashHits);
    printf("  Cert Failures:       %lld\n", g_IocEngine.Stats.CertFailures);
    printf("  LOLBin Hits:         %lld\n", g_IocEngine.Stats.LolbinHits);
    printf("  Cmdline Hits:        %lld\n", g_IocEngine.Stats.CmdlineHits);
    printf("  YARA Submitted:      %lld\n", g_IocEngine.Stats.YaraSubmitted);
    printf("  Memory Scans:        %lld\n", g_IocEngine.Stats.MemoryScans);
    printf("  Suspicious Modules:  %lld\n", g_IocEngine.Stats.SuspiciousModules);
}
