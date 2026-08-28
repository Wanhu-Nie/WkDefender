/**************************************************/
/*  WkDefender IOA 引擎 — 堆喷检测 feature 模块实现  */
/**************************************************/

#include "IoaHeapSprayDetect.h"

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#include "../Memory/MemoryScan.h"          /* MsReadMemory (内容采样) */
#include "../IOC/IocZeroDayDetector.h"     /* 内容模式分析 (HeapSpray 迁移补全) */

/**************************************************/
/*               内部辅助                           */
/**************************************************/

static
LARGE_INTEGER
IoaHsGetNow(
    VOID
    )
/*++
Routine Description:
    当前系统时间 (FILETIME 100ns 单位, 对齐 SS KeQuerySystemTimePrecise)。
--*/
{
    FILETIME ft;
    LARGE_INTEGER li;

    GetSystemTimeAsFileTime(&ft);
    li.LowPart  = ft.dwLowDateTime;
    li.HighPart = (LONG)ft.dwHighDateTime;
    return li;
}

static
ULONG
IoaHsFnv1a32(
    _In_reads_bytes_(Size) const UCHAR* Data,
    _In_ ULONG Size
    )
/*++
Routine Description:
    FNV-1a 哈希 (对齐 SS ShadowStrikeHashBytes, HspCalculatePatternHash
    委托的哈希算法)。PatternHash 当前无消费方, 保留字段对齐 SS。
--*/
{
    ULONG hash = 2166136261UL;
    ULONG i;

    for (i = 0; i < Size; i++) {
        hash ^= Data[i];
        hash *= 16777619UL;
    }
    return hash;
}

static
VOID
IoaHsRollWindow(
    _Inout_ PWKD_HEAP_SPRAY_STATE State,
    _In_ LARGE_INTEGER Now
    )
/*++
Routine Description:
    滑窗修剪 — 窗口到期全量清零+重置 (对齐 IoaRateAnalyzer 窗口轮转,
    非 SS 逐记录修剪; agent 无 65536 分配记录池, 只存聚合计数)。
    重置清 SprayAlerted, 允许同进程下一窗口重新告警。
--*/
{
    LONGLONG elapsed = Now.QuadPart - State->WindowStartTime.QuadPart;

    if (elapsed > (LONGLONG)WKD_HS_ALLOCATION_WINDOW_MS * 10000LL) {
        State->AllocationCount    = 0;
        State->TotalAllocatedSize = 0;
        State->AllocationsInWindow = 0;
        State->AlignedCount       = 0;
        State->ExecCount          = 0;
        State->LowestAddress      = 0;
        State->HighestAddress     = 0;
        State->LastAllocation.QuadPart = 0;
        State->WindowStartTime    = Now;
        State->SprayScore         = 0;
        State->SprayInProgress    = FALSE;
        State->SprayAlerted       = FALSE;
        State->DetectionFlags     = 0;
    }
}

static
NTSTATUS
IoaHsSampleRegion(
    _Inout_ PWKD_HEAP_SPRAY_STATE State,
    _In_ ULONG Pid,
    _In_ ULONG_PTR Addr,
    _In_ SIZE_T Size
    )
/*++
Routine Description:
    门控内容采样 — 复用 MsReadMemory (MemoryScan.c L1774) 读取分配
    前 min(Size,256) 字节, 计算 RepetitionScore/PatternHash, 置
    SuspectedType。对齐 SS HsRecordAllocation 的 KeStackAttachProcess
    + ProbeForRead 采样语义 (采样移至 agent ReadProcessMemory)。
--*/
{
    PBYTE buffer = NULL;
    ULONG outSize = 0;
    SIZE_T sampleLen = (Size < WKD_HS_PATTERN_SAMPLE_SIZE)
                     ? Size : WKD_HS_PATTERN_SAMPLE_SIZE;
    NTSTATUS status;

    RtlZeroMemory(State->PatternSample, WKD_HS_PATTERN_SAMPLE_SIZE);
    State->PatternSampleSize = 0;
    State->RepetitionScore   = 0;
    State->PatternHash       = 0;

    /* 地址用户态范围护栏 (对齐 SS HsRecordAllocation L843-847) */
    if (Addr < 0x10000 || Addr > WKD_HS_MAX_USER_ADDRESS) {
        return STATUS_SUCCESS;
    }

    status = MsReadMemory(Pid, Addr, sampleLen, &buffer, &outSize);
    if (!NT_SUCCESS(status) || buffer == NULL || outSize == 0) {
        if (buffer != NULL) {
            free(buffer);
        }
        return status;
    }

    if (outSize > WKD_HS_PATTERN_SAMPLE_SIZE) {
        outSize = WKD_HS_PATTERN_SAMPLE_SIZE;
    }

    memcpy(State->PatternSample, buffer, outSize);
    State->PatternSampleSize = outSize;
    State->RepetitionScore = IocZeroDay_CalculateRepetitionScore(
                                 State->PatternSample, outSize);
    State->PatternHash = IoaHsFnv1a32(State->PatternSample, outSize);

    free(buffer);
    return STATUS_SUCCESS;
}

/**************************************************/
/*               分配事件处理                       */
/**************************************************/

NTSTATUS
IoaHeapSpray_OnAllocate(
    _Inout_ PWKD_HEAP_SPRAY_STATE State,
    _In_ ULONG Pid,
    _In_ ULONG_PTR Addr,
    _In_ SIZE_T Size,
    _In_ ULONG Protect
    )
/*++
Routine Description:
    分配事件处理 — 聚合计数 + 门控采样 + 评分 + 判定。
    对齐 SS HsRecordAllocation (HeapSpray.c L698-1017)。

Arguments:
    State  - 进程堆喷窗口状态 (挂 WKD_PROCESS_BEHAVIOR_STATE.HeapSpray)。
    Pid    - 分配进程 PID。
    Addr   - 实际分配基址 (驱动 Exit 上送, ParameterBase[1])。
    Size   - 实际分配大小 (驱动 Exit 上送, ParameterBase[3])。
    Protect- 分配保护属性 (ParameterBase[5])。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER (Size 护栏拒收)。
--*/
{
    LARGE_INTEGER now;
    ULONG sprayScore;
    ULONG allocsPerSecond;
    BOOLEAN isExec;
    BOOLEAN doSample;

    if (State == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* 护栏: 拒绝明显不合理大小 (对齐 SS HsRecordAllocation L759-761,
     * 损坏遥测的 SIZE_T 会破坏聚合求和) */
    if (Size > WKD_HS_MAX_SINGLE_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Addr == 0 || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    now = IoaHsGetNow();

    /* 滑窗修剪 (窗口到期全清) */
    IoaHsRollWindow(State, now);
    if (State->WindowStartTime.QuadPart == 0) {
        State->WindowStartTime = now;
    }

    /* 聚合计数 */
    State->AllocationCount++;
    State->TotalAllocatedSize += Size;
    State->AllocationsInWindow++;
    if (((ULONG_PTR)Addr & 0xFFFF) == 0) {
        State->AlignedCount++;
    }

    /* 地址范围统计 (对齐 SS HsAnalyzeProcess L1232-1268) */
    if (State->LowestAddress == 0 || Addr < State->LowestAddress) {
        State->LowestAddress = Addr;
    }
    if (Addr > State->HighestAddress) {
        State->HighestAddress = Addr;
    }
    State->LastAllocation = now;

    isExec = (Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    if (isExec) {
        State->ExecCount++;
    }

    /* 分配率 (窗口内 /s) */
    allocsPerSecond = 0;
    if (now.QuadPart > State->WindowStartTime.QuadPart) {
        allocsPerSecond = (ULONG)(((LONG64)State->AllocationsInWindow * 10000000LL) /
                                  (now.QuadPart - State->WindowStartTime.QuadPart));
    }

    /* 门控采样: 可执行分配 / 分配率≥25/s / 对齐分配≥20 (防 DoS)。
     * 只保留最新一次采样, 不进记录池 (对齐 IoaHandleRealTimeMemoryEvent
     * 触发模式, SS 逐次采样成本在 agent 侧不可承受) */
    doSample = isExec ||
               (allocsPerSecond >= WKD_HS_SAMPLE_RATE_THRESHOLD) ||
               (State->AlignedCount >= WKD_HS_SAMPLE_ALIGN_THRESHOLD);
    if (doSample) {
        IoaHsSampleRegion(State, Pid, Addr, Size);

        State->SuspectedType = IocZeroDay_DetectSprayType(
                                   State->PatternSample, State->PatternSampleSize);
        if (State->SuspectedType == WkdHeapSpray_JitSpray) {
            State->DetectionFlags |= WKD_HSF_JIT_PATTERN;
        }
        if (IocZeroDay_ContainsShellcodeSignatures(
                State->PatternSample, State->PatternSampleSize)) {
            State->DetectionFlags |= WKD_HSF_SHELLCODE_PATTERN;
        }
        /* 重复度标志 (对齐 SS HsRecordAllocation L969-971: >80 置 RepeatedPattern) */
        if (State->RepetitionScore > WKD_HS_REPETITION_THRESHOLD) {
            State->DetectionFlags |= WKD_HSF_REPEATED_PATTERN;
        }
    }

    /* 评分 (0-1000) */
    sprayScore = IoaHeapSpray_CalculateSprayScore(State);
    State->SprayScore = sprayScore;

    /* 大块连续标志 (对齐 SS HsAnalyzeProcess L1367-1369: >10MB 置 LargeContiguous) */
    if (State->TotalAllocatedSize > WKD_HS_LARGE_CONTIGUOUS_SIZE) {
        State->DetectionFlags |= WKD_HSF_LARGE_CONTIGUOUS;
    }

    /* 判定 (对齐 SS HsRecordAllocation L925-947, 半阈值迟滞防振荡) */
    if (sprayScore >= WKD_HS_MIN_SCORE_FOR_SPRAY &&
        State->TotalAllocatedSize >= WKD_HS_MIN_SPRAY_SIZE &&
        State->AllocationCount >= WKD_HS_MIN_SIMILAR_ALLOCATIONS) {
        State->SprayInProgress = TRUE;
    } else if (sprayScore < WKD_HS_MIN_SCORE_FOR_SPRAY / 2) {
        State->SprayInProgress = FALSE;
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*               评分                              */
/**************************************************/

ULONG
IoaHeapSpray_CalculateSprayScore(
    _In_ PWKD_HEAP_SPRAY_STATE State
    )
/*++
Routine Description:
    堆喷评分 (0-1000)。对齐 SS HspCalculateSprayScore
    (HeapSpray.c L2160-2246)。

Arguments:
    State - 进程堆喷窗口状态。

Return Value:
    评分 [0,1000]。
--*/
{
    ULONG score = 0;
    LARGE_INTEGER windowDuration;
    ULONG allocsPerSecond;

    if (State == NULL) {
        return 0;
    }

    /* 重复度 ×3 (0-300) */
    score += State->RepetitionScore * 3;

    /* 分配计数 (100 + (count-100)×2 cap 200, 共 300) */
    if (State->AllocationCount > WKD_HS_MIN_SIMILAR_ALLOCATIONS) {
        score += 100 + min((State->AllocationCount - WKD_HS_MIN_SIMILAR_ALLOCATIONS) * 2, 200);
    }

    /* 总大小 (100 + MB 数 cap 100, 共 200) */
    if (State->TotalAllocatedSize > WKD_HS_MIN_SPRAY_SIZE) {
        score += 100;
        score += min((ULONG)(State->TotalAllocatedSize / (1024 * 1024)), 100);
    }

    /* 分配率 (>50/s → 150) */
    windowDuration.QuadPart = IoaHsGetNow().QuadPart - State->WindowStartTime.QuadPart;
    if (windowDuration.QuadPart > 0) {
        allocsPerSecond = (ULONG)(((LONG64)State->AllocationsInWindow * 10000000LL) /
                                  windowDuration.QuadPart);
        if (allocsPerSecond > WKD_HS_HIGH_ALLOC_RATE_THRESHOLD) {
            score += 150;
            State->DetectionFlags |= WKD_HSF_HIGH_ALLOC_RATE;
        }
    }

    /* 已知堆喷模式 (+200) */
    if (State->PatternSampleSize >= 4 &&
        IocZeroDay_IsKnownSprayPattern(State->PatternSample, State->PatternSampleSize)) {
        score += 200;
    }

    /* NOP sled (+250) */
    if (State->PatternSampleSize >= 4 &&
        IocZeroDay_ContainsNopSled(State->PatternSample, State->PatternSampleSize)) {
        score += 250;
    }

    /* 壳码签名 (+300, 标志已在 OnAllocate 采样分支置位) */
    if (State->DetectionFlags & WKD_HSF_SHELLCODE_PATTERN) {
        score += 300;
    }

    /* 可执行保护 (+100) */
    if (State->ExecCount > 0) {
        score += 100;
        State->DetectionFlags |= WKD_HSF_EXECUTABLE_ALLOC;
    }

    /* 对齐地址 (+50) */
    if (State->AlignedCount > 0) {
        score += 50;
        State->DetectionFlags |= WKD_HSF_ALIGNED_ADDRESSES;
    }

    return min(score, 1000);
}

/**************************************************/
/*               告警构造                           */
/**************************************************/

PIOA_ALERT
IoaHeapSpray_AllocAlert(
    _In_ GUID SuspectNodeId,
    _In_ PWKD_HEAP_SPRAY_STATE State
    )
/*++
Routine Description:
    堆喷告警构造 (单块堆分配, 含字符串缓冲)。对齐 RaAllocStatAlert
    (IoaRateAnalyzer.c L1556-1650) 分配语义, 满足持久化队列
    UtHeapFree(Data) 整体释放; 调用方转移所有权。入队由调用方执行。

Arguments:
    SuspectNodeId - 嫌疑进程节点 GUID (堆喷为进程内自分配)。
    State         - 进程堆喷窗口状态。

Return Value:
    告警指针 (调用方转移所有权); 分配失败返回 NULL。
--*/
{
    static const WCHAR* sMitreExploit = L"T1203";   /* 利用客户端执行 */
    static const WCHAR* sMitreDos     = L"T1499";   /* 端点 DoS */
    const WCHAR* ruleName = L"HeapSpray/Detected";
    const WCHAR* mitreId;
    DEF_THREAT_SEVERITY severity;
    size_t ruleLen, mitreLen, descLen, total;
    PIOA_ALERT alert;
    PWCHAR buf;
    WCHAR descBuf[256];

    if (State == NULL) {
        return NULL;
    }

    /* 高分配率标志 → T1499 (资源耗尽); 否则 T1203 (利用客户端执行) */
    mitreId = (State->DetectionFlags & WKD_HSF_HIGH_ALLOC_RATE)
            ? sMitreDos : sMitreExploit;

    severity = (State->SprayScore >= 700) ? DefThreatSeverity_Critical
             : (State->SprayScore >= WKD_HS_MIN_SCORE_FOR_SPRAY) ? DefThreatSeverity_High
             : DefThreatSeverity_Medium;

    swprintf_s(descBuf, 256,
               L"HeapSpray: type=%d count=%lu size=%llu aligned=%lu score=%lu",
               (int)State->SuspectedType, State->AllocationCount,
               (unsigned long long)State->TotalAllocatedSize,
               State->AlignedCount, State->SprayScore);

    ruleLen  = wcslen(ruleName);
    mitreLen = wcslen(mitreId);
    descLen  = wcslen(descBuf);
    total = sizeof(IOA_ALERT) +
            (ruleLen + 1 + mitreLen + 1 + descLen + 1) * sizeof(WCHAR);

    alert = (PIOA_ALERT)UtHeapAlloc(total);
    if (alert == NULL) {
        return NULL;
    }
    RtlZeroMemory(alert, total);

    CoCreateGuid(&alert->AlertId);
    alert->Timestamp         = IoaHsGetNow();
    alert->SuspectNodeId     = SuspectNodeId;
    alert->VictimNodeId      = SuspectNodeId;   /* 堆喷为进程内自分配, 无独立受害实体 */
    alert->Severity          = severity;
    alert->Score             = State->SprayScore;
    alert->Confidence        = 80;
    alert->Category          = DefThreatCat_Exploit;
    alert->ConfidenceLevel   = DefConfidence_Medium;
    alert->RecommendedAction = DefRespAction_Alert;   /* monitor-only, 仅告警 */
    alert->DetectionSource   = DefDetSrc_Behavior;

    buf = (PWCHAR)((PUCHAR)alert + sizeof(IOA_ALERT));
    alert->RuleName = buf;
    wcscpy_s(buf, ruleLen + 1, ruleName);
    buf += ruleLen + 1;

    alert->MitreId = buf;
    wcscpy_s(buf, mitreLen + 1, mitreId);
    buf += mitreLen + 1;

    alert->Description = buf;
    wcscpy_s(buf, descLen + 1, descBuf);

    return alert;
}

/**************************************************/
/*               查询 API (死代码)                  */
/**************************************************/

NTSTATUS
IoaHeapSpray_AnalyzeProcess(
    _In_ ULONG Pid,
    _In_ PWKD_HEAP_SPRAY_STATE State,
    _Out_ PWKD_HEAP_SPRAY_RESULT Result
    )
/*++
Routine Description:
    堆喷完整分析 (查询 API)。对齐 SS HsAnalyzeProcess (HeapSpray.c L1125-1398)。
    ※ 死代码: 供 UI/进程详情查询, 当前无调用者。

Arguments:
    Pid    - 进程 PID。
    State  - 进程堆喷窗口状态。
    Result - 输出分析结果 (值语义, 无需释放)。

Return Value:
    STATUS_SUCCESS。
--*/
{
    LARGE_INTEGER lastAlloc;

    if (State == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Result, sizeof(*Result));

    Result->SprayDetected     = (State->SprayInProgress != 0);
    Result->Type              = State->SuspectedType;
    Result->Flags             = State->DetectionFlags;
    Result->ConfidenceScore   = State->SprayScore;
    Result->ProcessId         = Pid;
    Result->AllocationCount   = State->AllocationCount;
    Result->TotalSize         = State->TotalAllocatedSize;
    Result->AverageSize       = (State->AllocationCount > 0)
                              ? State->TotalAllocatedSize / State->AllocationCount : 0;
    Result->AlignedCount      = State->AlignedCount;
    Result->PatternRepetitions= State->RepetitionScore;
    Result->UniquePatterns    = (State->PatternSampleSize > 0) ? 1 : 0;

    /* 地址范围 (对齐 SS HsAnalyzeProcess L1260-1268) */
    if (State->AllocationCount > 0) {
        Result->LowestAddress  = State->LowestAddress;
        Result->HighestAddress = State->HighestAddress;
        Result->AddressSpan    = (SIZE_T)(State->HighestAddress - State->LowestAddress);
    }

    /* 时序 (对齐 SS L1376-1390: FirstAllocation=窗口起点, LastAllocation=最后分配) */
    Result->FirstAllocation = State->WindowStartTime;
    lastAlloc = State->LastAllocation;
    if (lastAlloc.QuadPart == 0) {
        lastAlloc = IoaHsGetNow();
    }
    Result->LastAllocation = lastAlloc;
    if (lastAlloc.QuadPart > State->WindowStartTime.QuadPart) {
        Result->DurationMs = (ULONG)((lastAlloc.QuadPart -
                                      State->WindowStartTime.QuadPart) / 10000);
    } else {
        Result->DurationMs = 0;
    }

    if (Result->DurationMs > 0) {
        Result->AllocationsPerSecond =
            (ULONG)(((ULONG64)State->AllocationsInWindow * 1000) / Result->DurationMs);
    }

    if (State->PatternSampleSize > 0) {
        ULONG n = min(State->PatternSampleSize, 64);
        memcpy(Result->DominantPattern, State->PatternSample, n);
        Result->DominantPatternSize = n;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
IoaHeapSpray_CheckForSpray(
    _In_ PWKD_HEAP_SPRAY_STATE State,
    _Out_ PBOOLEAN SprayDetected,
    _Out_opt_ PWKD_HEAP_SPRAY_TYPE Type,
    _Out_opt_ PULONG Score
    )
/*++
Routine Description:
    堆喷快速检查 (查询 API)。对齐 SS HsCheckForSpray (HeapSpray.c L1402-1471)。
    ※ 死代码: 供快速体检, 当前无调用者。

Arguments:
    State         - 进程堆喷窗口状态。
    SprayDetected - 接收是否判定堆喷。
    Type          - 可选; 接收堆喷类型。
    Score         - 可选; 接收评分。

Return Value:
    STATUS_SUCCESS。
--*/
{
    if (State == NULL || SprayDetected == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *SprayDetected = (State->SprayInProgress != 0);
    if (Type) {
        *Type = State->SuspectedType;
    }
    if (Score) {
        *Score = State->SprayScore;
    }

    return STATUS_SUCCESS;
}
