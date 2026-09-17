/**************************************************/
/*  WkDefender Agent — 反射注入检测器实现           */
/*                                                  */
/*  2026-09-15 新增: ShadowStrike                  */
/*  ReflectiveDLLDetector 决策层迁移 (Rid*)         */
/*                                                  */
/*  职责: 反射 DLL 加载的"判定决策层"。             */
/*  复用 Memory 子系统检测原语 (Ms 系列) +           */
/*  PEAnalyzer 深度验证 (WpeAnalyzePEDeep) +        */
/*  ProcessThreads 线程画像 (WptAnalyzeThreads),    */
/*  输出结构化反射加载判定 (加载器分类 + 置信度 +    */
/*  风险分)。                                       */
/*                                                  */
/*  已合并原 IoaConfirmReflectiveLoading             */
/*  (IoaInjectionClassifier.c L907-975): 事件驱动   */
/*  定向确认入口统一为 PspDetermineReflectiveLoading。 */
/*                                                  */
/*  对齐 ShadowStrike ReflectiveDLLDetector.cpp:    */
/*    AnalyzeCandidate L2318-2502 (判定决策)         */
/*    LoaderSignatureDB L826-906 (签名库)            */
/*    CalculateRiskScore L505-552 (评分)             */
/**************************************************/

#include <strsafe.h>                     /* StringCchCopyA */

#include "../Include/Process/InjectionDetector.h"
#include "InjectionDetectorInternal.h"
#include "ProcessModule.h"             /* PsFindModuleByAddress (域背衬判定) */
#include "ProcessTree.h"               /* PsLookupWkdProcessByProcessId */
#include "../Memory/MemoryScan.h"      /* Ms 系列检测原语 */
#include "../IOC/PEAnalyzer/PeAnalyzer.h"/* WpeAnalyzePEDeep (深度验证) */
#include "../ProcessThreads.h"           /* WptAnalyzeThreads / WKD_THREAD_PROFILE */

/**************************************************/
/*       已知反射加载器知识库 (SS LoaderSignatureDB) */
/*  结构化签名表: 字节模式可扩展 (HasPattern=TRUE   */
/*  时按 pattern/mask/offset 掩码匹配); 当前字节    */
/*  模式硬编码收敛于 MsDetectReflectiveLoader,      */
/*  本表承载元数据映射 (名称/分类/MITRE)。          */
/**************************************************/

#define RID_SIG_STORE_COUNT  3

static const RID_LOADER_SIGNATURE g_RidLoaderSignatures[RID_SIG_STORE_COUNT] = {
    {
        "Cobalt Strike Beacon",
        RidLoad_CobaltStrikeBeacon,
        "T1620",
        "Cobalt Strike reflective loader detected",
        { 0 }, { 0 }, 0, FALSE
    },
    {
        "Metasploit Meterpreter",
        RidLoad_MeterpreterStage,
        "T1620",
        "Meterpreter reflective stage detected",
        { 0 }, { 0 }, 0, FALSE
    },
    {
        "Classic Reflective DLL",
        RidLoad_ClassicReflective,
        "T1055.001",
        "Stephen Fewer's reflective DLL technique",
        { 0 }, { 0 }, 0, FALSE
    }
};

/**************************************************/
/*               内部工具函数                       */
/**************************************************/

/* RWX 保护判定 (对齐 MsIsRwxProtection 语义, 忽略 modifier 位) */
static
BOOLEAN
RidIsRwxProtection(
    _In_ ULONG Protection
    )
{
    return (((Protection & 0xFF) == PAGE_EXECUTE_READWRITE) ? TRUE : FALSE);
}

/* 掩码逐字节比对 (对齐 SS LoaderSignatureDB::MatchesSignature L881-902) */
static
BOOLEAN
RidMaskedBytesEqual(
    _In_ const UCHAR* Data,
    _In_ const UCHAR* Pattern,
    _In_ const UCHAR* Mask,
    _In_ ULONG        Length
    )
{
    ULONG i;
    BOOLEAN allZeroMask = TRUE;

    for (i = 0; i < Length; i++) {
        if (Mask[i] != 0x00) {
            allZeroMask = FALSE;
            if ((Data[i] & Mask[i]) != (Pattern[i] & Mask[i])) {
                return FALSE;
            }
        }
    }

    /* 全零掩码: 未配置字节模式, 不能按字节匹配 (仅启发式) */
    return (allZeroMask ? FALSE : TRUE);
}

/* 统计起始地址落入 [Base, Base+RegionSize) 的线程数 (SS FindSuspiciousThreads 聚合) */
static
ULONG
RidCountThreadsInCandidate(
    _In_ const WKD_THREAD_PROFILE* Threads,
    _In_ PRID_CANDIDATE            Candidate
    )
{
    ULONG i, count = 0;

    if (Threads == NULL) {
        return 0;
    }

    for (i = 0; i < Threads->AnalyzedCount; i++) {
        ULONG_PTR start = Threads->Threads[i].StartAddress;

        if (start >= Candidate->BaseAddress &&
            start < Candidate->BaseAddress + Candidate->RegionSize) {
            count++;
        }
    }

    return count;
}

/**************************************************/
/*       加载器签名匹配 (SS LoaderSignatureDB)      */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
RidMatchLoaderSignature(
    _In_  const BYTE* Buffer,
    _In_  ULONG       Size,
    _Out_ PRID_LOADER_SIGNATURE Signature
    )
/*++
Routine Description:
    候选区头部加载器签名匹配。
    1) 结构化签名表掩码匹配 (HasPattern 条目, 可扩展);
    2) 委托 MsDetectReflectiveLoader (字节模式硬编码于 MemoryScan,
       DetectKnownLoader 迁移): CS Beacon config/sleep mask、
       Meterpreter stub/stage marker、API-hash 模式。
    字节签名命中时输出签名条目 (名称/分类/MITRE)。

Arguments:
    Buffer    - 候选区首部字节 (含 PE 头 + 加载器 stub)。
    Size      - Buffer 有效长度。
    Signature - [输出] 命中签名条目。

Return Value:
    TRUE = 已知加载器签名命中; FALSE = 未命中 (启发式分类兜底)。
--*/
{
    WKD_MEM_THREAT threat;
    ULONG i;

    /* 1) 结构化表掩码匹配 */
    for (i = 0; i < RID_SIG_STORE_COUNT; i++) {
        const RID_LOADER_SIGNATURE* sig = &g_RidLoaderSignatures[i];

        if (sig->HasPattern &&
            Size >= sig->Offset + RID_SIGNATURE_LENGTH &&
            RidMaskedBytesEqual(Buffer + sig->Offset, sig->Pattern,
                                sig->Mask, RID_SIGNATURE_LENGTH)) {
            *Signature = *sig;
            return TRUE;
        }
    }

    /* 2) 委托 MsDetectReflectiveLoader (字节模式现实实现) */
    if (MsDetectReflectiveLoader(Buffer, Size, &threat)) {
        switch (threat.Type) {
        case WkdMemThreat_CobaltStrike:
            *Signature = g_RidLoaderSignatures[0]; /* Cobalt Strike Beacon */
            return TRUE;

        case WkdMemThreat_Meterpreter:
            *Signature = g_RidLoaderSignatures[1]; /* Metasploit Meterpreter */
            return TRUE;

        default:
            /* API-hash 等通用加载器 stub 特征: 启发式分类兜底 (不视为具名签名) */
            break;
        }
    }

    return FALSE;
}

/**************************************************/
/*       加载器类型分类 (SS AnalyzeCandidate       */
/*       L2456-2465 默认分类 + 特征启发式扩展)      */
/**************************************************/

_Use_decl_annotations_
RID_LOAD_TYPE
RidClassifyLoadType(
    _In_ PRID_CANDIDATE Candidate
    )
/*++
Routine Description:
    无具名签名命中时的加载器类型启发式分类:
      - 隐藏无背衬有效 PE: 含重定位表 → ManualMapping (手工 rebase 特征);
                         含 TLS 目录 → MemoryModule (TLS 回调初始化特征);
                         否则       → ClassicReflective。
      - 其他 → CustomLoader (加壳/加密/未知包装归此, 由二进制威胁
        WkdMemThreat_EncryptedPayload 精确表达)。

Arguments:
    Candidate - 已收集特征 (IsValidPe/IsUnbacked/IsInPeb/HasReloc/HasTls)。

Return Value:
    分类结果 (不返回 RidLoad_Unknown: 调用方保证候选为有效 PE)。
--*/
{
    if (Candidate->IsUnbacked && Candidate->IsInPeb == FALSE) {
        if (Candidate->HasReloc) {
            return RidLoad_ManualMapping;   /* 重定位表 → 需手工 rebase */
        }
        if (Candidate->HasTls) {
            return RidLoad_MemoryModule;    /* TLS 回调 → MemoryModule 类初始化 */
        }
        return RidLoad_ClassicReflective;
    }

    return RidLoad_CustomLoader;            /* 加壳/加密/未知包装 (PackedReflective 并入) */
}

/**************************************************/
/*       综合风险评分 (SS CalculateRiskScore       */
/*       L505-552, 0-100 尺度直接照搬)             */
/**************************************************/

_Use_decl_annotations_
ULONG
RidCalculateRiskScore(
    _In_ PRID_CANDIDATE Candidate,
    _In_ RID_CONFIDENCE  Confidence,
    _In_ RID_LOAD_TYPE   LoadType,
    _In_ BOOLEAN         CorrelatedWithKnownThreat
    )
/*++
Routine Description:
    反射加载综合风险评分 0-100:
      置信度分级 + 内存特征 (RWX/无背衬/隐藏) + 已知威胁关联 +
      载荷类型严重度 + 线程活动 + 调用栈未背衬帧。

Arguments:
    Candidate                  - 候选特征。
    Confidence                 - 决策置信度。
    LoadType                   - 加载器分类。
    CorrelatedWithKnownThreat  - 签名/威胁情报命中。

Return Value:
    0-100 风险分。
--*/
{
    ULONG score = 0;

    /* Confidence level (L509-515) */
    switch (Confidence) {
    case RidConf_Confirmed: score += 50; break;
    case RidConf_High:      score += 40; break;
    case RidConf_Medium:    score += 25; break;
    case RidConf_Low:       score += 10; break;
    default:                break;
    }

    /* Memory characteristics (L517-520) */
    if (Candidate->IsRwx)            score += 20;
    if (Candidate->IsUnbacked)       score += 15;
    if (!Candidate->IsInPeb)         score += 15;

    /* Known threat correlation (L522-523) */
    if (CorrelatedWithKnownThreat)   score += 30;

    /* Load type severity (L525-542) */
    switch (LoadType) {
    case RidLoad_CobaltStrikeBeacon:
    case RidLoad_MeterpreterStage:
        score += 25;
        break;
    case RidLoad_ClassicReflective:
    case RidLoad_Srdi:
        score += 20;
        break;
    case RidLoad_ManualMapping:
    case RidLoad_MemoryModule:
    case RidLoad_ModuleOverloading:
        score += 15;
        break;
    default:
        score += 5;
        break;
    }

    /* Thread activity (L544-546) */
    if (Candidate->ThreadCount > 0) score += 10;
    if (Candidate->ThreadCount > 1) score += 5;

    /* Call stack presence (L548-549) */
    if (Candidate->CallStackFrames > 0) score += 10;

    return min(score, 100u);
}

/**************************************************/
/*       候选特征收集 (SS PECandidate 画像)        */
/**************************************************/

static
VOID
RidCollectCandidate(
    _In_ HANDLE                ProcessHandle, /* 可 NULL: 跳过深度验证 */
    _In_ const WKD_MEM_THREAT* Threat,
    _Out_ PRID_CANDIDATE       Candidate
    )
/*++
Routine Description:
    由单条内存威胁 (WKD_MEM_THREAT, MsScan* 产物) 收集决策特征:
      区域/保护 → 深度 PE 验证 (WpeAnalyzePEDeep: 节熵/数据目录/SHA256)
      → 特征布尔汇总。
    isInPEB / isFileBacked 直接复用 Ms 扫描填充值 (EnumProcessModules)。

Arguments:
    ProcessHandle - 目标进程句柄 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)。
    Threat        - 单条威胁 (Type == WkdMemThreat_PEInjection)。
    Candidate     - [输出] 候选特征。
--*/
{
    ULONG_PTR base;

    RtlZeroMemory(Candidate, sizeof(*Candidate));

    base = (Threat->PeImageBase != 0) ? Threat->PeImageBase : Threat->RegionBase;
    Candidate->BaseAddress = base;
    Candidate->RegionSize  = Threat->RegionSize;
    Candidate->Protection  = Threat->Protection;
    Candidate->IsRwx       = RidIsRwxProtection(Threat->Protection);
    Candidate->IsFileBacked= Threat->PeFileBacked;
    Candidate->IsInPeb     = Threat->PeInPeb;
    Candidate->IsValidPe   = Threat->PeValid;

    /* 深度验证 (节表逐节熵/SHA256/数据目录, ValidatePEImpl 迁移) */
    if (ProcessHandle != NULL &&
        SUCCEEDED(WpeAnalyzePEDeep(ProcessHandle, base, &Candidate->Deep))) {
        Candidate->IsValidPe  |= Candidate->Deep.IsValidPE;
        Candidate->IsPacked    = Candidate->Deep.IsPacked;
        Candidate->IsEncrypted = Candidate->Deep.IsEncrypted;
        Candidate->HasTls      = Candidate->Deep.HasTLSDirectory;
        Candidate->HasReloc    = Candidate->Deep.HasRelocationTable;
    }
}

/**************************************************/
/*       单候选判定决策 (SS AnalyzeCandidate       */
/*       L2318-2502, 仅迁移核心路径)               */
/**************************************************/

static
BOOLEAN
RidAnalyzeCandidateImpl(
    _In_  HANDLE                      ProcessHandle, /* PROCESS_VM_READ | QUERY_INFORMATION */
    _In_  DWORD                       ProcessId,
    _In_  PRID_CANDIDATE              Candidate,
    _In_  WKD_MEM_SCAN_MODE           Mode,
    _In_opt_ const WKD_THREAD_PROFILE* Threads,      /* 全量扫描路径传入; 定向确认路径可 NULL */
    _Out_ PRID_REFLECTIVE_DETECTION   Detection
    )
/*++
Routine Description:
    单候选反射加载判定 (对齐 AnalyzeCandidate L2318-2502):
      1. 合法加载模块跳过 (isInPEB && isFileBacked);
      2. 特征组合逐条提升置信度 (Unbacked→Low / RWX→Medium /
         隐藏有效PE→High / TLS→High / 高熵→Medium);
      3. 线程起始分析: 起始地址落入候选区 → Confirmed (活动注入);
      4. 调用栈未背衬帧 (Deep 模式, 关联线程);
      5. 已知加载器签名 → Confirmed + correlatedWithKnownThreat;
      6. 默认分类 → MITRE 兜底 T1620 → 风险评分;
      7. 置信度 ≥ Medium 才输出 (对齐 alertThreshold)。

Arguments:
    ProcessHandle - 目标进程句柄。
    ProcessId     - 目标进程 ID。
    Candidate     - 已收集候选特征。
    Mode          - 扫描模式 (WkdMemScan_Deep 启用调用栈分析)。
    Threads       - [可选] 线程画像 (全量扫描); NULL 时用 Candidate->ThreadCount
                    (定向确认路径由调用方预填)。
    Detection     - [输出] 结构化检测结果。

Return Value:
    TRUE = 判定为反射加载 (置信度 ≥ Medium); FALSE = 未达阈值/合法模块。
--*/
{
    RID_CONFIDENCE conf;
    RID_LOAD_TYPE  loadType = RidLoad_Unknown;
    RID_LOADER_SIGNATURE sigHit;
    BYTE header[RID_HEADER_SCAN_SIZE];
    ULONG headerSize = 0;
    BOOLEAN knownThreat = FALSE;
    SIZE_T bytesRead = 0;

    /* 1. 合法加载模块跳过 (L2323-2326) */
    if (Candidate->IsFileBacked && Candidate->IsInPeb) {
        return FALSE;
    }

    RtlZeroMemory(Detection, sizeof(*Detection));
    Detection->BaseAddress = Candidate->BaseAddress;
    Detection->RegionSize  = Candidate->RegionSize;
    Detection->Protection  = Candidate->Protection;

    /* 2. 特征组合 → 置信度 (L2361-2401) */
    conf = RidConf_None;

    if (!Candidate->IsFileBacked) {
        Detection->IsUnbacked = TRUE;
        conf = max(conf, RidConf_Low);
    }

    if (Candidate->IsRwx) {
        Detection->IsRwx = TRUE;
        conf = max(conf, RidConf_Medium);
    }

    if (!Candidate->IsInPeb && Candidate->IsValidPe) {
        Detection->IsHiddenFromPeb = TRUE;
        conf = max(conf, RidConf_High);
    }

    if (Candidate->IsPacked || Candidate->IsEncrypted) {
        conf = max(conf, RidConf_Medium);
    }

    if (Candidate->HasTls && !Candidate->IsFileBacked) {
        conf = max(conf, RidConf_High);
    }

    /* 3. 线程起始分析 (L2403-2419): 起始地址落入候选区 → Confirmed */
    Candidate->ThreadCount = (Threads != NULL)
        ? RidCountThreadsInCandidate(Threads, Candidate)
        : Candidate->ThreadCount;
    if (Candidate->ThreadCount > 0) {
        Detection->HasThreadStartingHere = TRUE;
        Detection->ThreadCount = Candidate->ThreadCount;
        conf = RidConf_Confirmed;
    }

    /* 4. 调用栈未背衬帧 (L2421-2434, 仅 Deep 模式) */
    if (Mode == WkdMemScan_Deep && Detection->HasThreadStartingHere) {
        /* 关联线程最大未背衬帧数: 全量扫描路径需遍历画像中命中线程,
         * 精简实现: 单候选区无线程明细映射, 由 WptCountUnbackedCallStackFrames
         * 按 Threads 画像命中线程逐个统计 (成本高, 仅 Deep)。 */
        ULONG i;

        if (Threads != NULL) {
            for (i = 0; i < Threads->AnalyzedCount; i++) {
                ULONG_PTR start = Threads->Threads[i].StartAddress;

                if (start >= Candidate->BaseAddress &&
                    start < Candidate->BaseAddress + Candidate->RegionSize) {
                    ULONG frames = WptCountUnbackedCallStackFrames(
                        Threads->Threads[i].ThreadId);

                    Candidate->CallStackFrames = max(Candidate->CallStackFrames, frames);
                }
            }
        }
    }

    /* 5. 已知加载器签名 (L2436-2447) */
    if (ReadProcessMemory(ProcessHandle, (LPCVOID)Candidate->BaseAddress,
                          header, sizeof(header), &bytesRead) && bytesRead > 0) {
        headerSize = (bytesRead < sizeof(header))
            ? (ULONG)bytesRead : (ULONG)sizeof(header);

        if (RidMatchLoaderSignature(header, headerSize, &sigHit)) {
            loadType = sigHit.Type;
            conf = RidConf_Confirmed;
            knownThreat = TRUE;
            StringCchCopyA(Detection->ThreatName, ARRAYSIZE(Detection->ThreatName),
                           sigHit.Name);
            StringCchCopyA(Detection->MitreTechnique, ARRAYSIZE(Detection->MitreTechnique),
                           sigHit.MitreId);
        }
    }

    /* 6. 默认分类 (L2455-2471) + MITRE 兜底 */
    if (loadType == RidLoad_Unknown) {
        loadType = RidClassifyLoadType(Candidate);
    }
    Detection->LoadType = loadType;

    if (Detection->MitreTechnique[0] == '\0') {
        StringCchCopyA(Detection->MitreTechnique,
                       ARRAYSIZE(Detection->MitreTechnique), "T1620");
    }

    Detection->Confidence = conf;
    Detection->CorrelatedWithKnownThreat = knownThreat;
    Detection->RiskScore = RidCalculateRiskScore(Candidate, conf, loadType, knownThreat);

    if (Candidate->Deep.IsValidPE) {
        Detection->Sha256 = Candidate->Deep.Sha256;
    }

    /* 7. 上报门槛 (L2496-2501) */
    return (conf >= RID_ALERT_CONFIDENCE) ? TRUE : FALSE;
}

/**************************************************/
/*               公共 API 1: 全量扫描               */
/**************************************************/

NTSTATUS
RidScanProcess(
    _In_  DWORD  ProcessId,
    _In_  WKD_MEM_SCAN_MODE Mode,
    _Out_writes_to_(MaxDetections, *DetectionCount) PRID_REFLECTIVE_DETECTION Detections,
    _In_  ULONG  MaxDetections,
    _Out_ PULONG DetectionCount
    )
/*++
Routine Description:
    进程反射加载全量扫描 (主动扫描决策层)。
    Scan (ReflectiveDLLDetector.cpp L981-1100):
      MsScanProcessMemoryFull 全量扫描 → 逐候选 (PEInjection && !PeInPeb)
      收集特征 → 深度决策 → 输出结构化检测。
    复用: MsScanProcessMemoryFull / WptAnalyzeThreads /
          WpeAnalyzePEDeep / MsDetectReflectiveLoader。

Arguments:
    ProcessId      - 目标进程 ID。
    Mode           - 扫描模式 (WkdMemScan_Deep 启用调用栈分析)。
    Detections     - [输出] 检测结果数组 (仅置信度 ≥ Medium)。
    MaxDetections  - 输出数组容量。
    DetectionCount - [输出] 实际检测数。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER / 底层扫描错误码。
--*/
{
    WKD_MEM_SCAN_RESULT scan;
    WKD_THREAD_PROFILE  threads;
    RID_CANDIDATE       candidate;
    RID_REFLECTIVE_DETECTION det;
    HANDLE hProcess = NULL;
    NTSTATUS status;
    ULONG i, outCount = 0;

    if (Detections == NULL || DetectionCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *DetectionCount = 0;

    /* 1. 全量内存扫描 (区域枚举 + 检测层, PS ScanProcessMemory 迁移) */
    RtlZeroMemory(&scan, sizeof(scan));
    status = MsScanProcessMemoryFull(ProcessId, Mode, &scan);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* 2. 线程画像 (线程起始分析与 Deep 调用栈分析) */
    RtlZeroMemory(&threads, sizeof(threads));
    if (!NT_SUCCESS(WptAnalyzeThreads(ProcessId, &threads))) {
        threads.AnalyzedCount = 0;   /* 线程画像失败不阻塞扫描 */
    }

    /* 3. 候选收集 + 逐候选决策 */
    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                           FALSE, ProcessId);
    if (hProcess == NULL) {
        return STATUS_ACCESS_DENIED;
    }

    for (i = 0; i < scan.ThreatsFound && i < WKD_MEM_MAX_THREATS; i++) {
        PWKD_MEM_THREAT t = &scan.Threats[i];

        /* 非映像内存 PE 且不在模块表 → 反射加载候选 */
        if (t->Type != WkdMemThreat_PEInjection || t->PeInPeb) {
            continue;
        }

        RidCollectCandidate(hProcess, t, &candidate);

        if (RidAnalyzeCandidateImpl(hProcess, ProcessId, &candidate, Mode,
                                    &threads, &det)) {
            if (outCount < MaxDetections) {
                Detections[outCount++] = det;
            } else {
                break;   /* 输出缓冲已满 */
            }
        }
    }

    CloseHandle(hProcess);
    *DetectionCount = outCount;
    return STATUS_SUCCESS;
}

/**************************************************/
/*    公共 API 2: 事件驱动定向确认 (合并原          */
/*    IoaConfirmReflectiveLoading)                 */
/**************************************************/

BOOLEAN
PspDetermineReflectiveLoading(
    _In_  ULONG             TargetProcessId,
    _In_  ULONG_PTR         StartRoutine,
    _Out_opt_ PRID_LOAD_TYPE  LoadType,
    _Out_opt_ PULONG        Confidence,
    _Out_opt_ PULONG        RiskScore
    )
/*++
Routine Description:
    反射 DLL 精确确认 — 事件驱动定向验证。
    合并原 IoaConfirmReflectiveLoading (IoaInjectionClassifier.c L907-975):
      分类器以 UNBACKED_START 近似判定 ReflectiveDLL; 本函数用线程入口
      地址定向确认:
        MmGetMemoryRegionInformation 定位入口区域 → 私有可执行 → MsScanRegionAt 定向扫描
        → 隐藏无背衬 PE (PEInjection && !PeInPeb) → WpeAnalyzePEDeep 深度
        验证 → 决策 (hasThreadStartingHere = TRUE → Confirmed) → 加载器
        分类 + 评分。
    对齐 AnalyzeCandidate 的内存扫描确认阶段 (ReflectiveDLLDetector.cpp
      L2403-2418)。
    不可验证时返回 FALSE, 不改变原近似判定, 不引入误报。
    确认成功时 Confidence/RiskScore 输出确认级 (≥90)。

Arguments:
    TargetProcessId - 目标进程 PID。
    StartRoutine    - 远程线程入口地址 (ThreadCreate 载荷 StartRoutine)。
    LoadType        - [可选] 加载器分类输出。
    Confidence      - [可选] 确认后置信度 (95)。
    RiskScore       - [可选] 确认后风险分 (≥90, 评分不足 90 时对齐至 90)。

Return Value:
    TRUE = 确认隐藏无背衬 PE (反射加载); FALSE = 不可验证/未确认。
--*/
{
    WKD_MEMORY_REGION region;
    PWKD_MEM_SCAN_RESULT scan;
    RID_CANDIDATE candidate;
    RID_REFLECTIVE_DETECTION det;
    HANDLE hProcess;
    ULONG i;
    BOOLEAN confirmed = FALSE;
    PWKD_PROCESS process = NULL;
    PWKD_MODULE_INSTANCE inst = NULL;

    if (LoadType)   *LoadType   = RidLoad_Unknown;
    if (Confidence) *Confidence = 0;
    if (RiskScore)  *RiskScore  = 0;

    if (TargetProcessId <= 4 || StartRoutine == 0) {
        return FALSE;
    }

    /* 域快速否定: 入口点落在已登记模块区间 (PEB 模块域, PsHandleImageLoad
     * 事件驱动维护) → 有背衬映像, 非反射加载, 直接否定。
     * 域由驱动 ImageLoad 事件填充: MEM_IMAGE 区域已被下方
     * region.Type != WkdMemType_Private 拦截, 此处仅省一次
     * OpenProcess+定向扫描; 域缺项 (模块域未登记) 时回退原扫描
     * 确认路径, 不改变判定, 不引入误报。 */
    if (NT_SUCCESS(PsLookupWkdProcessByProcessId(
            NULL, (HANDLE)(ULONG_PTR)TargetProcessId, &process)) &&
        process != NULL) {
        BOOLEAN backed;

        backed = NT_SUCCESS(PsFindModuleByAddress(
            process, StartRoutine, &inst));
        PsDereferenceWkdProcess(process);
        if (backed) {
            return FALSE;
        }
    }

    /* 入口所在区域: 私有可执行 → 候选无背衬加载 (FindUnbackedExecutable) */
    if (!MmGetMemoryRegionInformation(TargetProcessId, StartRoutine, &region)) {
        return FALSE;
    }
    if (region.Type != WkdMemType_Private || !region.IsExecutable) {
        return FALSE;
    }

    /* 定向扫描入口所在区域 (DispatchAsyncScan 的定向版本, MsScanRegionAt) */
    scan = (PWKD_MEM_SCAN_RESULT)malloc(sizeof(WKD_MEM_SCAN_RESULT));
    if (scan == NULL) {
        return FALSE;
    }

    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                           FALSE, TargetProcessId);
    if (hProcess == NULL) {
        free(scan);
        return FALSE;
    }

    if (NT_SUCCESS(MsScanRegionAt(TargetProcessId, region.BaseAddress,
                                  region.RegionSize, scan))) {
        for (i = 0; i < scan->ThreatsFound; i++) {
            if (scan->Threats[i].Type == WkdMemThreat_PEInjection &&
                !scan->Threats[i].PeInPeb) {
                /* 深度 PE 验证 (ValidatePEImpl, WpeAnalyzePEDeep) + 决策 */
                RidCollectCandidate(hProcess, &scan->Threats[i], &candidate);

                /* 入口地址即线程起点: hasThreadStartingHere = TRUE (L2403-2418) */
                if (candidate.IsValidPe) {
                    candidate.ThreadCount = 1;

                    if (RidAnalyzeCandidateImpl(hProcess, TargetProcessId,
                                                &candidate, WkdMemScan_Normal,
                                                NULL, &det)) {
                        confirmed = TRUE;
                        if (LoadType)   *LoadType   = det.LoadType;
                        if (Confidence) *Confidence = RID_CONFIRM_CONFIDENCE;
                        if (RiskScore)  *RiskScore  = max(det.RiskScore, RID_CONFIRM_RISK);
                    }
                }
                break;
            }
        }
    }

    CloseHandle(hProcess);
    free(scan);
    return confirmed;
}