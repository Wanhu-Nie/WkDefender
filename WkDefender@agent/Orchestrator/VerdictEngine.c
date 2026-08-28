/**************************************************/
/*  WkDefender VerdictEngine — 中央判定层实现        */
/*  多引擎加权融合 + 活跃威胁管理 + 响应分发          */
/*  ShadowStrike ThreatDetector 迁移 (2026-08-04)   */
/**************************************************/

#include "VerdictEngine.h"

#include <string.h>
#include <wchar.h>

#include "../Common/Utils.h"
#include "../IOA/IoaProcessPair.h"
#include "../Process/ProcessTree.h"
#include "../IOA/IoaMitreMapper.h"
#include "../IOA/Tier2/IoaTier2Backtrack.h"   /* T2_VERDICT_* */
#include "../process_manager.h"

VERDICT_ENGINE g_VerdictEngine = { 0 };

#define VERDICT_HASH_BUCKETS   1024

/**************************************************/
/*               内部工具                           */
/**************************************************/

/* 本地 GUID 生成 (时间+计数器, 不依赖 CoCreateGuid) */
static VOID
VerdictGenId(
    _Out_ GUID* Id
    )
{
    LARGE_INTEGER now;
    GetSystemTimeAsFileTime((PFILETIME)&now);
    RtlZeroMemory(Id, sizeof(GUID));
    Id->Data1 = (ULONG)now.LowPart;
    Id->Data2 = (USHORT)(now.QuadPart >> 32);
    Id->Data3 = (USHORT)(InterlockedIncrement64(&g_VerdictEngine.VerdictsProduced) & 0xFFFF);
    Id->Data4[0] = (UCHAR)(g_VerdictEngine.VerdictsProduced >> 16);
}

static ULONG
VerdictHashNode(
    _In_ GUID NodeId
    )
{
    return (NodeId.Data1 ^ NodeId.Data2 ^ NodeId.Data3) & (VERDICT_HASH_BUCKETS - 1);
}

/* 定位与事件相关的进程对 (src→tgt, 有向)。
 * 2026-08-23 pair 键 PID 化: header GUID 经谱系树反查 PID 后查找。 */
static PAE_PROCESS_PAIR
VerdictFindPairContext(
    _In_ PWKD_EVENT_HEADER Event
    )
{
    extern IOA_ENGINE WkdIoaEngine;
    PWKD_PROCESS srcNode;
    PWKD_PROCESS tgtNode;

    if (!WkdIoaEngine.PairManager) return NULL;
    if (DefIsNullNodeId(Event->SourceProcessId) || DefIsNullNodeId(Event->TargetProcessId))
        return NULL;

    srcNode = PtTreeLookupByNodeId(&WkdProcessTree, Event->SourceProcessId);
    tgtNode = PtTreeLookupByNodeId(&WkdProcessTree, Event->TargetProcessId);
    if (!srcNode || !tgtNode ||
        srcNode->SecCtx.Placeholder || tgtNode->SecCtx.Placeholder) {
        return NULL;
    }
    {
        PAE_PROCESS_PAIR pair = NULL;
        if (NT_SUCCESS(AeLookupProcessPair(srcNode->ProcessId, tgtNode->ProcessId, &pair)))
            return pair;
        return NULL;
    }
}

/* 引擎权重 (Q8 定点) — 对齐 SS GetEngineWeight (cpp L529-554) */
static ULONG
VerdictEngineWeight(
    _In_ DEF_DETECTION_SOURCE Source
    )
{
    switch (Source) {
        case DefDetSrc_IOC:       return g_VerdictEngine.Config.WeightIoc;
        case DefDetSrc_IOA_Tier1: return g_VerdictEngine.Config.WeightT1;
        case DefDetSrc_IOA_Tier2: return g_VerdictEngine.Config.WeightT2;
        case DefDetSrc_IOA_Tier3: return g_VerdictEngine.Config.WeightT3;
        case DefDetSrc_Behavior:  return g_VerdictEngine.Config.WeightBehavior;
        default:                  return 0;
    }
}

/* FsmClass → Category (T3 确认类优先映射) */
static DEF_THREAT_CATEGORY
VerdictClassToCategory(
    _In_ FSM_ATTACK_CLASS Class
    )
{
    switch (Class) {
        case FsmClass_ProcessInjection:  return DefThreatCat_ProcessInjection;
        case FsmClass_ProcessHollowing:  return DefThreatCat_ProcessHollowing;
        case FsmClass_CredentialAccess:  return DefThreatCat_CredentialAccess;
        case FsmClass_DefenseEvasion:    return DefThreatCat_DefenseEvasion;
        case FsmClass_Persistence:       return DefThreatCat_Persistence;
        case FsmClass_LateralMovement:   return DefThreatCat_LateralMovement;
        case FsmClass_Collection:        return DefThreatCat_Collection;
        case FsmClass_CommandAndControl: return DefThreatCat_CommandAndControl;
        default:                         return DefThreatCat_None;
    }
}

/* 类别推断 — 对齐 SS InferCategory (cpp L159-198):
 *   T3 确认类优先 → Ransomware 标志 → Behavior 源 → Malware 兜底 */
static DEF_THREAT_CATEGORY
VerdictInferCategory(
    _In_opt_ PAE_PROCESS_PAIR PairCtx,
    _In_ PWKD_ENGINE_DETECTION Detections,
    _In_ ULONG               Count,
    _In_ ULONG               DetectionFlags
    )
{
    if (PairCtx && PairCtx->T3Tactic.ConfirmedClass != FsmClass_None) {
        DEF_THREAT_CATEGORY cat = VerdictClassToCategory(PairCtx->T3Tactic.ConfirmedClass);
        if (cat != DefThreatCat_None) return cat;
    }
    if (DetectionFlags & (DEF_BEHAVIOR_FLAG_RANSOMWARE_ENC |
                          DEF_BEHAVIOR_FLAG_RANSOMWARE_DELETE |
                          DEF_BEHAVIOR_FLAG_RANSOMWARE_SHADOW)) {
        return DefThreatCat_Ransomware;
    }
    for (ULONG i = 0; i < Count; i++) {
        if (Detections[i].Source == DefDetSrc_Behavior)
            return DefThreatCat_SuspiciousBehavior;
    }
    return DefThreatCat_Malware;
}

/* MITRE 技术收集: 引擎 MitreId + 行为标志经 IoaMitreLookupTechnique 映射, 去重 */
static VOID
VerdictCollectMitre(
    _Inout_ PWKD_VERDICT V,
    _In_opt_ PAE_PROCESS_PAIR PairCtx,
    _In_opt_ PWKD_PROCESS Node,
    _In_ PWKD_ENGINE_DETECTION Detections,
    _In_ ULONG               Count
    )
{
    UNREFERENCED_PARAMETER(PairCtx);

    for (ULONG i = 0; i < Count && V->MitreCount < WKD_VERDICT_MAX_MITRE; i++) {
        PCWSTR tech = Detections[i].MitreId;
        if (!tech || !tech[0]) continue;
        BOOLEAN dup = FALSE;
        for (ULONG j = 0; j < V->MitreCount; j++) {
            if (wcscmp(V->MitreIds[j], tech) == 0) { dup = TRUE; break; }
        }
        if (!dup) wcsncpy_s(V->MitreIds[V->MitreCount++], 16, tech, _TRUNCATE);
    }
    if (Node) {
        ULONG flags = Node->BehaviorFlags;
        for (ULONG bit = 0; bit < 31 && V->MitreCount < WKD_VERDICT_MAX_MITRE; bit++) {
            ULONG flag = (ULONG)(1ULL << bit);
            if (flags & flag) {
                PCWSTR tech = IoaMitreLookupTechnique(flag);
                if (tech && tech[0] && wcscmp(tech, L"T0000") != 0) {
                    BOOLEAN dup = FALSE;
                    for (ULONG j = 0; j < V->MitreCount; j++) {
                        if (wcscmp(V->MitreIds[j], tech) == 0) { dup = TRUE; break; }
                    }
                    if (!dup) wcsncpy_s(V->MitreIds[V->MitreCount++], 16, tech, _TRUNCATE);
                }
            }
        }
    }
}

/**************************************************/
/*               多引擎融合判定                     */
/**************************************************/

ULONG
VerdictEngine_CollectEngineDetections(
    _In_ PWKD_EVENT_HEADER   Event,
    _In_opt_ PWKD_PROCESS Node,
    _Out_ PWKD_ENGINE_DETECTION Detections,
    _In_ ULONG               MaxCount
    )
{
    ULONG n = 0;
    PAE_PROCESS_PAIR pairCtx = VerdictFindPairContext(Event);
    WKD_ENGINE_DETECTION d;
    /* E1 — IOC 判定 (Node.SecCtx.IocVerdict × IocConfidence, 尺度 0-1000;
     * 2026-08-23 迁入 WKD_PROCESS_SECURITY_CONTEXT) */
    if (Node && Node->SecCtx.IocVerdict >= DefIocVerdict_Suspicious && n < MaxCount) {
        ULONG base = (Node->SecCtx.IocVerdict == DefIocVerdict_Malicious) ? 85 : 40;
        ULONG conf = (Node->SecCtx.IocConfidence > 1000) ? 1000 : Node->SecCtx.IocConfidence;
        d.Source = DefDetSrc_IOC;
        d.Confidence = conf / 10;
        d.Score = base * conf / 1000;
        d.MitreId = NULL;
        Detections[n++] = d;
    }

    /* E2 — IOA-T1 进程对累积评分 (CumulativeRiskScore [0,100]) */
    if (pairCtx && pairCtx->T1Feature.CumulativeRiskScore > 0 && n < MaxCount) {
        ULONG score = pairCtx->T1Feature.CumulativeRiskScore;
        if (score > 100) score = 100;
        d.Source = DefDetSrc_IOA_Tier1;
        d.Score = score;
        d.Confidence = score;
        d.MitreId = NULL;
        Detections[n++] = d;
    }

    /* E3 — IOA-T2 判定 (BENIGN/SUSPICIOUS/ATTACK) */
    if (pairCtx && pairCtx->T1Feature.LastT2Verdict >= T2_VERDICT_SUSPICIOUS && n < MaxCount) {
        ULONG score = (pairCtx->T1Feature.LastT2Verdict == T2_VERDICT_ATTACK) ? 85 : 45;
        d.Source = DefDetSrc_IOA_Tier2;
        d.Score = score;
        d.Confidence = score;
        d.MitreId = NULL;
        Detections[n++] = d;
    }

    /* E4 — IOA-T3 战术置信度 (T3Tactic.Confidence [0,98] → 归一化 [0,100]) */
    if (pairCtx && pairCtx->T3Tactic.Confidence > 0 && n < MaxCount) {
        d.Source = DefDetSrc_IOA_Tier3;
        d.Score = pairCtx->T3Tactic.Confidence * 100 / 98;
        d.Confidence = pairCtx->T3Tactic.Confidence;
        d.MitreId = pairCtx->T3Tactic.ConfirmedTechnique;
        Detections[n++] = d;
    }

    /* E5 — 事件级行为信号 (注入分类器阶段4.5 回填 Event->Confidence, 尺度 0-1000) */
    if (Event->Confidence >= 500 && n < MaxCount) {
        ULONG score = Event->Confidence / 10;
        if (score > 100) score = 100;
        d.Source = DefDetSrc_Behavior;
        d.Score = score;
        d.Confidence = score;
        d.MitreId = NULL;
        Detections[n++] = d;
    }    /* E6 — 行为检测器 MaliceScore (※死代码: WKD_PROCESS_BEHAVIOR_STATE
     *   (IoaTypes.h:614) 未接入流水线。接入时按 Node 关联读取 →
     *   DefDetSrc_Behavior, 与 E5 同源需合并权重, 避免双计。)
     * ML 融合源 (SS AnalyzeWithMLEngine cpp L1479-1503) 同为死代码:
     *   无 ONNX 运行时, 接入后作为 DefDetSrc_Scan 或独立源。
     *
     * 文件锁模式检测接入点 (FileLockManager 迁移 2026-08): agent 侧
     * FileLockManager_AnalyzeThreat 产出锁上下文威胁评分 (勒索独占锁/注入
     * 持锁等, SS AnalyzeThreatInternal L998-1029)。接入时按 FilePath 关联
     * 目标节点 → 与 E6 同源 (DefDetSrc_Behavior), 注意与 E5/IoaRansomware
     * 勒索分防双计; 接线预留于 IoaEngine 阶段4.9d (g_IoaLockPatternEnabled)。 */

    /* 归还 pair 查找 pin (2026-08-25 HashMap ref/deref 契约) */
    if (pairCtx) AeDereferenceProcessPair(pairCtx);

    return n;
}

BOOLEAN
VerdictEngine_Fuse(
    _In_ PWKD_EVENT_HEADER   Event,
    _In_opt_ PWKD_PROCESS Node,
    _Out_ PWKD_VERDICT       Verdict
    )
{
    WKD_ENGINE_DETECTION dets[WKD_VERDICT_MAX_DETECTIONS];
    ULONG count;
    ULONG64 totalWeighted = 0;
    ULONG totalWeight = 0;
    ULONG positive = 0;
    ULONG bestScore = 0;
    DEF_DETECTION_SOURCE bestSource = DefDetSrc_None;
    ULONG score;
    PAE_PROCESS_PAIR pairCtx;

    if (!g_VerdictEngine.Initialized || !Event || !Verdict) return FALSE;

    /* 本地白名单早退 (对齐 SS EnrichEvent isWhitelisted 跳过判定) */
    if (VerdictEngine_IsWhitelisted(Event->SourceProcessId.Data1, NULL)) return FALSE;

    RtlZeroMemory(Verdict, sizeof(*Verdict));
    VerdictGenId(&Verdict->VerdictId);
    GetSystemTimeAsFileTime((PFILETIME)&Verdict->Timestamp);
    Verdict->SuspectNodeId = Event->SourceProcessId;
    Verdict->VictimNodeId  = Event->TargetProcessId;
    Verdict->DetectionFlags = Event->BehaviorFlags | (Node ? Node->BehaviorFlags : 0);
    if (Node && Node->ImageFileName && Node->ImageFileName->Buffer) {
        wcsncpy_s(Verdict->ProcessName, WKD_VERDICT_NAME_LEN,
                  Node->ImageFileName->Buffer, _TRUNCATE);
    }

    pairCtx = VerdictFindPairContext(Event);
    count = VerdictEngine_CollectEngineDetections(Event, Node, dets, WKD_VERDICT_MAX_DETECTIONS);
    if (count == 0) {
        if (pairCtx) AeDereferenceProcessPair(pairCtx);
        return FALSE;
    }

    /* 加权融合: threatScore = Σ(score×weight) / Σweight (仅有权重信号) */
    for (ULONG i = 0; i < count; i++) {
        ULONG w = VerdictEngineWeight(dets[i].Source);
        if (w == 0) continue;
        totalWeighted += (ULONG64)dets[i].Score * w;
        totalWeight += w;
        if (dets[i].Score >= g_VerdictEngine.Config.DetectionThreshold) positive++;
        if (dets[i].Score > bestScore) {
            bestScore = dets[i].Score;
            bestSource = dets[i].Source;
        }
    }
    if (totalWeight == 0) {
        if (pairCtx) AeDereferenceProcessPair(pairCtx);
        return FALSE;
    }

    score = (ULONG)(totalWeighted / totalWeight);
    if (score > 100) score = 100;

    Verdict->ThreatScore = score;
    Verdict->EngineCount = count;
    Verdict->EngineAgreement = positive * 100 / count;
    Verdict->BestEngineScore = bestScore;
    Verdict->PrimarySource = bestSource;

    /* 严重度分级 (对齐 SS cpp L477-487) */
    if (score >= g_VerdictEngine.Config.CriticalThreshold) {
        Verdict->Severity = DefThreatSeverity_Critical;
    } else if (score >= g_VerdictEngine.Config.HighThreshold) {
        Verdict->Severity = DefThreatSeverity_High;
    } else if (score >= g_VerdictEngine.Config.MediumThreshold) {
        Verdict->Severity = DefThreatSeverity_Medium;
    } else if (score > 0) {
        Verdict->Severity = DefThreatSeverity_Low;
    } else {
        Verdict->Severity = DefThreatSeverity_None;
    }

    /* 引擎一致率 → 置信度级别 (对齐 SS cpp L490-504) */
    if (Verdict->EngineAgreement >= 90) {
        Verdict->ConfidenceLevel = DefConfidence_Confirmed;
    } else if (Verdict->EngineAgreement >= 70) {
        Verdict->ConfidenceLevel = DefConfidence_High;
    } else if (Verdict->EngineAgreement >= 50) {
        Verdict->ConfidenceLevel = DefConfidence_Medium;
    } else {
        Verdict->ConfidenceLevel = DefConfidence_Low;
    }
    Verdict->Confidence = Verdict->EngineAgreement;

    /* 类别推断 */
    Verdict->Category = VerdictInferCategory(pairCtx, dets, count, Verdict->DetectionFlags);

    /* 推荐动作 (对齐 SS cpp L507-513) */
    switch (Verdict->Severity) {
        case DefThreatSeverity_Critical: Verdict->RecommendedAction = DefRespAction_Terminate;  break;
        case DefThreatSeverity_High:     Verdict->RecommendedAction = DefRespAction_Quarantine; break;
        case DefThreatSeverity_Medium:   Verdict->RecommendedAction = DefRespAction_Block;      break;
        case DefThreatSeverity_Low:      Verdict->RecommendedAction = DefRespAction_Alert;      break;
        default:                         Verdict->RecommendedAction = DefRespAction_None;       break;
    }

    /* MITRE 技术收集 */
    VerdictCollectMitre(Verdict, pairCtx, Node, dets, count);

    swprintf_s(Verdict->Description, WKD_VERDICT_DESC_LEN,
               L"VerdictEngine fusion: %lu engine(s) score=%lu src=%d agree=%lu",
               count, score, (int)bestSource, Verdict->EngineAgreement);

    /* 归还 pair 查找 pin (2026-08-25 HashMap ref/deref 契约) */
    if (pairCtx) AeDereferenceProcessPair(pairCtx);

    return TRUE;
}

/**************************************************/
/*               活跃威胁管理                       */
/**************************************************/

VOID
VerdictEngine_UpsertActiveThreat(
    _In_ PWKD_VERDICT Verdict
    )
{
    PWKD_ACTIVE_THREAT entry = NULL;
    ULONG bucket;
    PLIST_ENTRY head, it;

    if (!g_VerdictEngine.Initialized || !Verdict) return;
    if (DefIsNullNodeId(Verdict->SuspectNodeId)) return;

    EnterCriticalSection(&g_VerdictEngine.Lock);

    bucket = VerdictHashNode(Verdict->SuspectNodeId);
    head = &g_VerdictEngine.HashBuckets[bucket];
    for (it = head->Flink; it != head; it = it->Flink) {
        PWKD_ACTIVE_THREAT cur = CONTAINING_RECORD(it, WKD_ACTIVE_THREAT, HashLink);
        if (DefGuidEqual(&cur->Verdict.SuspectNodeId, &Verdict->SuspectNodeId)) {
            entry = cur;
            break;
        }
    }

    if (entry) {
        /* 已存在: 取更高威胁评分, 合并行为标志 */
        if (Verdict->ThreatScore > entry->Verdict.ThreatScore) {
            entry->Verdict = *Verdict;
        } else {
            entry->Verdict.Timestamp = Verdict->Timestamp;
            entry->Verdict.DetectionFlags |= Verdict->DetectionFlags;
            entry->Verdict.EngineCount = Verdict->EngineCount;
        }
        RemoveEntryList(&entry->LruLink);
        InsertHeadList(&g_VerdictEngine.LruHead, &entry->LruLink);
        entry->LastUpdate = Verdict->Timestamp;
    } else {
        /* 容量上限: 淘汰 LRU 尾部最旧条目 */
        if (g_VerdictEngine.Count >= g_VerdictEngine.Config.MaxActiveThreats) {
            PLIST_ENTRY tail = g_VerdictEngine.LruHead.Blink;
            if (tail != &g_VerdictEngine.LruHead) {
                PWKD_ACTIVE_THREAT victim = CONTAINING_RECORD(tail, WKD_ACTIVE_THREAT, LruLink);
                RemoveEntryList(&victim->LruLink);
                RemoveEntryList(&victim->HashLink);
                UtHeapFree(victim);
                g_VerdictEngine.Count--;
            }
        }
        entry = (PWKD_ACTIVE_THREAT)UtHeapAlloc(sizeof(WKD_ACTIVE_THREAT));
        if (entry) {
            entry->Verdict = *Verdict;
            entry->LastUpdate = Verdict->Timestamp;
            InsertHeadList(&g_VerdictEngine.LruHead, &entry->LruLink);
            InsertTailList(&g_VerdictEngine.HashBuckets[bucket], &entry->HashLink);
            g_VerdictEngine.Count++;

            /* Verdict 统计细分 (新增条目时计数, 对齐 SS ThreatDetectorStats) */
            if ((ULONG)Verdict->Severity < 5) {
                InterlockedIncrement64(
                    &g_VerdictEngine.ThreatsBySeverity[(ULONG)Verdict->Severity]);
            }
            if ((ULONG)Verdict->Category < DefThreatCat_Max) {
                InterlockedIncrement64(
                    &g_VerdictEngine.ThreatsByCategory[(ULONG)Verdict->Category]);
            }
        }
    }

    LeaveCriticalSection(&g_VerdictEngine.Lock);
}

ULONG
VerdictEngine_GetActiveThreatCount(
    VOID
    )
{
    ULONG n;
    EnterCriticalSection(&g_VerdictEngine.Lock);
    n = g_VerdictEngine.Count;
    LeaveCriticalSection(&g_VerdictEngine.Lock);
    return n;
}

ULONG
VerdictEngine_GetActiveThreats(
    _Out_ PWKD_VERDICT Out,
    _In_ ULONG          MaxCount
    )
{
    ULONG n = 0;
    PLIST_ENTRY it;

    if (!Out || MaxCount == 0) return 0;

    EnterCriticalSection(&g_VerdictEngine.Lock);
    for (it = g_VerdictEngine.LruHead.Flink;
         it != &g_VerdictEngine.LruHead && n < MaxCount;
         it = it->Flink) {
        PWKD_ACTIVE_THREAT cur = CONTAINING_RECORD(it, WKD_ACTIVE_THREAT, LruLink);
        Out[n++] = cur->Verdict;
    }
    LeaveCriticalSection(&g_VerdictEngine.Lock);
    return n;
}

BOOLEAN
VerdictEngine_GetVerdict(
    _In_ GUID      NodeId,
    _Out_ PWKD_VERDICT Verdict
    )
{
    PLIST_ENTRY head, it;
    BOOLEAN found = FALSE;

    if (!Verdict || DefIsNullNodeId(NodeId)) return FALSE;

    EnterCriticalSection(&g_VerdictEngine.Lock);
    head = &g_VerdictEngine.HashBuckets[VerdictHashNode(NodeId)];
    for (it = head->Flink; it != head; it = it->Flink) {
        PWKD_ACTIVE_THREAT cur = CONTAINING_RECORD(it, WKD_ACTIVE_THREAT, HashLink);
        if (DefGuidEqual(&cur->Verdict.SuspectNodeId, &NodeId)) {
            *Verdict = cur->Verdict;
            found = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&g_VerdictEngine.Lock);
    return found;
}

ULONG
VerdictEngine_GetProcessThreatScore(
    _In_ ULONG Pid
    )
{
    ULONG maxScore = 0;
    PLIST_ENTRY it;

    EnterCriticalSection(&g_VerdictEngine.Lock);
    for (it = g_VerdictEngine.LruHead.Flink;
         it != &g_VerdictEngine.LruHead;
         it = it->Flink) {
        PWKD_ACTIVE_THREAT cur = CONTAINING_RECORD(it, WKD_ACTIVE_THREAT, LruLink);
        if (cur->Verdict.SuspectNodeId.Data1 == Pid &&
            cur->Verdict.ThreatScore > maxScore) {
            maxScore = cur->Verdict.ThreatScore;
        }
    }
    LeaveCriticalSection(&g_VerdictEngine.Lock);
    return maxScore;
}

/* 进程退出清理 (对齐 SS OnProcessTerminate cpp L2187-2224):
 * 删除该进程活跃威胁, 防 PID 复用误信 */
VOID
VerdictEngine_OnProcessTerminate(
    _In_ ULONG Pid
    )
{
    PLIST_ENTRY it, next;

    if (Pid == 0) return;

    EnterCriticalSection(&g_VerdictEngine.Lock);
    for (it = g_VerdictEngine.LruHead.Flink; it != &g_VerdictEngine.LruHead;) {
        PWKD_ACTIVE_THREAT cur = CONTAINING_RECORD(it, WKD_ACTIVE_THREAT, LruLink);
        next = it->Flink;
        if (cur->Verdict.SuspectNodeId.Data1 == Pid) {
            RemoveEntryList(&cur->LruLink);
            RemoveEntryList(&cur->HashLink);
            UtHeapFree(cur);
            g_VerdictEngine.Count--;
        }
        it = next;
    }
    LeaveCriticalSection(&g_VerdictEngine.Lock);

    /* 同步清理本地 PID 白名单 (防 PID 复用信任, 对齐 SS OnProcessTerminate cpp L2216-2219) */
    EnterCriticalSection(&g_VerdictEngine.WhitelistLock);
    for (ULONG i = 0; i < g_VerdictEngine.WhitelistedPidCount; i++) {
        if (g_VerdictEngine.WhitelistedPids[i] == Pid) {
            if (i + 1 < g_VerdictEngine.WhitelistedPidCount) {
                g_VerdictEngine.WhitelistedPids[i] =
                    g_VerdictEngine.WhitelistedPids[g_VerdictEngine.WhitelistedPidCount - 1];
            }
            g_VerdictEngine.WhitelistedPidCount--;
            break;
        }
    }
    LeaveCriticalSection(&g_VerdictEngine.WhitelistLock);
}

/**************************************************/
/*               本地白名单 (SS 迁移)                */
/*  WhitelistProcess/WhitelistHash — 防误报         */
/*  哈希小写归一化防大小写绕过 (对齐 SS cpp L2243-2257) */
/**************************************************/

static VOID
VerdictToLowerHex(
    _In_ PCSTR In,
    _Out_writes_(65) PCHAR Out
    )
{
    size_t n = 0;
    for (; In[n] && n < 64; n++) {
        CHAR c = In[n];
        if (c >= 'A' && c <= 'Z') c = (CHAR)(c + 32);
        Out[n] = c;
    }
    Out[n] = 0;
}

VOID
VerdictEngine_WhitelistProcess(
    _In_ ULONG Pid
    )
{
    if (Pid == 0) return;

    EnterCriticalSection(&g_VerdictEngine.WhitelistLock);
    if (g_VerdictEngine.WhitelistedPidCount < VERDICT_WHITELIST_MAX_PIDS) {
        for (ULONG i = 0; i < g_VerdictEngine.WhitelistedPidCount; i++) {
            if (g_VerdictEngine.WhitelistedPids[i] == Pid) goto done;
        }
        g_VerdictEngine.WhitelistedPids[g_VerdictEngine.WhitelistedPidCount++] = Pid;
    }
done:
    LeaveCriticalSection(&g_VerdictEngine.WhitelistLock);
}

VOID
VerdictEngine_WhitelistHash(
    _In_ PCSTR Sha256Hex
    )
{
    CHAR lower[65];

    if (!Sha256Hex || Sha256Hex[0] == 0) return;
    VerdictToLowerHex(Sha256Hex, lower);

    EnterCriticalSection(&g_VerdictEngine.WhitelistLock);
    if (g_VerdictEngine.WhitelistedHashCount < VERDICT_WHITELIST_MAX_HASHES) {
        for (ULONG i = 0; i < g_VerdictEngine.WhitelistedHashCount; i++) {
            if (strcmp(g_VerdictEngine.WhitelistedHashes[i], lower) == 0) goto done;
        }
        strcpy_s(g_VerdictEngine.WhitelistedHashes[g_VerdictEngine.WhitelistedHashCount++],
                 65, lower);
    }
done:
    LeaveCriticalSection(&g_VerdictEngine.WhitelistLock);
}

BOOLEAN
VerdictEngine_IsWhitelisted(
    _In_ ULONG Pid,
    _In_opt_ PCSTR Sha256Hex
    )
{
    BOOLEAN found = FALSE;
    CHAR lower[65];

    EnterCriticalSection(&g_VerdictEngine.WhitelistLock);

    if (Pid != 0) {
        for (ULONG i = 0; i < g_VerdictEngine.WhitelistedPidCount; i++) {
            if (g_VerdictEngine.WhitelistedPids[i] == Pid) { found = TRUE; goto done; }
        }
    }
    if (!found && Sha256Hex && Sha256Hex[0]) {
        VerdictToLowerHex(Sha256Hex, lower);
        for (ULONG i = 0; i < g_VerdictEngine.WhitelistedHashCount; i++) {
            if (strcmp(g_VerdictEngine.WhitelistedHashes[i], lower) == 0) { found = TRUE; break; }
        }
    }
done:
    LeaveCriticalSection(&g_VerdictEngine.WhitelistLock);
    return found;
}

/**************************************************/
/*               误报反馈 (SS 迁移)                 */
/*  ReportFalsePositive — 用户反馈移除威胁 + 计数   */
/**************************************************/

VOID
VerdictEngine_ReportFalsePositive(
    _In_ GUID VerdictId
    )
{
    PLIST_ENTRY it, next;

    if (DefIsNullNodeId(VerdictId)) return;

    EnterCriticalSection(&g_VerdictEngine.Lock);
    for (it = g_VerdictEngine.LruHead.Flink; it != &g_VerdictEngine.LruHead;) {
        PWKD_ACTIVE_THREAT cur = CONTAINING_RECORD(it, WKD_ACTIVE_THREAT, LruLink);
        next = it->Flink;
        if (DefGuidEqual(&cur->Verdict.VerdictId, &VerdictId)) {
            RemoveEntryList(&cur->LruLink);
            RemoveEntryList(&cur->HashLink);
            UtHeapFree(cur);
            g_VerdictEngine.Count--;
            break;
        }
        it = next;
    }
    LeaveCriticalSection(&g_VerdictEngine.Lock);

    InterlockedIncrement64(&g_VerdictEngine.FalsePositives);
}

/**************************************************/
/*               查询 API 补全 (SS 迁移)            */
/*  GetThreatsByProcess/BySeverity/ByCategory/     */
/*  HasActiveThreat — 对齐 SS cpp L1676-1750       */
/**************************************************/

ULONG
VerdictEngine_GetThreatsByProcess(
    _In_ ULONG Pid,
    _Out_ PWKD_VERDICT Out,
    _In_ ULONG MaxCount
    )
{
    ULONG n = 0;
    PLIST_ENTRY it;

    if (!Out || MaxCount == 0) return 0;

    EnterCriticalSection(&g_VerdictEngine.Lock);
    for (it = g_VerdictEngine.LruHead.Flink;
         it != &g_VerdictEngine.LruHead && n < MaxCount;
         it = it->Flink) {
        PWKD_ACTIVE_THREAT cur = CONTAINING_RECORD(it, WKD_ACTIVE_THREAT, LruLink);
        if (cur->Verdict.SuspectNodeId.Data1 == Pid) Out[n++] = cur->Verdict;
    }
    LeaveCriticalSection(&g_VerdictEngine.Lock);
    return n;
}

ULONG
VerdictEngine_GetThreatsBySeverity(
    _In_ DEF_THREAT_SEVERITY MinSeverity,
    _Out_ PWKD_VERDICT Out,
    _In_ ULONG MaxCount
    )
{
    ULONG n = 0;
    PLIST_ENTRY it;

    if (!Out || MaxCount == 0) return 0;

    EnterCriticalSection(&g_VerdictEngine.Lock);
    for (it = g_VerdictEngine.LruHead.Flink;
         it != &g_VerdictEngine.LruHead && n < MaxCount;
         it = it->Flink) {
        PWKD_ACTIVE_THREAT cur = CONTAINING_RECORD(it, WKD_ACTIVE_THREAT, LruLink);
        if ((ULONG)cur->Verdict.Severity >= (ULONG)MinSeverity) Out[n++] = cur->Verdict;
    }
    LeaveCriticalSection(&g_VerdictEngine.Lock);
    return n;
}

ULONG
VerdictEngine_GetThreatsByCategory(
    _In_ DEF_THREAT_CATEGORY Category,
    _Out_ PWKD_VERDICT Out,
    _In_ ULONG MaxCount
    )
{
    ULONG n = 0;
    PLIST_ENTRY it;

    if (!Out || MaxCount == 0) return 0;

    EnterCriticalSection(&g_VerdictEngine.Lock);
    for (it = g_VerdictEngine.LruHead.Flink;
         it != &g_VerdictEngine.LruHead && n < MaxCount;
         it = it->Flink) {
        PWKD_ACTIVE_THREAT cur = CONTAINING_RECORD(it, WKD_ACTIVE_THREAT, LruLink);
        if (cur->Verdict.Category == Category) Out[n++] = cur->Verdict;
    }
    LeaveCriticalSection(&g_VerdictEngine.Lock);
    return n;
}

BOOLEAN
VerdictEngine_HasActiveThreat(
    _In_ ULONG Pid
    )
{
    BOOLEAN found = FALSE;
    PLIST_ENTRY it;

    EnterCriticalSection(&g_VerdictEngine.Lock);
    for (it = g_VerdictEngine.LruHead.Flink; it != &g_VerdictEngine.LruHead; it = it->Flink) {
        PWKD_ACTIVE_THREAT cur = CONTAINING_RECORD(it, WKD_ACTIVE_THREAT, LruLink);
        if (cur->Verdict.SuspectNodeId.Data1 == Pid) { found = TRUE; break; }
    }
    LeaveCriticalSection(&g_VerdictEngine.Lock);
    return found;
}

/**************************************************/
/*               统计快照 (SS GetStats 迁移)        */
/**************************************************/

VOID
VerdictEngine_GetStats(
    _Out_opt_ PULONG64 ThreatsBySeverity,
    _Out_opt_ PULONG64 ThreatsByCategory,
    _Out_opt_ PULONG64 FalsePositives
    )
{
    if (ThreatsBySeverity) {
        for (ULONG i = 0; i < 5; i++) ThreatsBySeverity[i] =
            g_VerdictEngine.ThreatsBySeverity[i];
    }
    if (ThreatsByCategory) {
        for (ULONG i = 0; i < DefThreatCat_Max; i++) ThreatsByCategory[i] =
            g_VerdictEngine.ThreatsByCategory[i];
    }
    if (FalsePositives) *FalsePositives = g_VerdictEngine.FalsePositives;
}

VOID
VerdictEngine_ResetStats(
    VOID
    )
{
    for (ULONG i = 0; i < 5; i++) g_VerdictEngine.ThreatsBySeverity[i] = 0;
    for (ULONG i = 0; i < DefThreatCat_Max; i++) g_VerdictEngine.ThreatsByCategory[i] = 0;
    g_VerdictEngine.FalsePositives = 0;
    g_VerdictEngine.VerdictsProduced = 0;
    g_VerdictEngine.ResponsesDispatched = 0;
}

/**************************************************/
/*               响应分发 (monitor-only)            */
/**************************************************/

VOID
VerdictEngine_DispatchResponse(
    _In_ PWKD_VERDICT Verdict
    )
{
    ULONG pid;

    if (!g_VerdictEngine.Initialized || !Verdict) return;
    pid = Verdict->SuspectNodeId.Data1;
    if (pid == 0) return;

    /* monitor-only 默认: 所有 Auto* 开关 FALSE 时仅记录, 不处置 */
    if (!g_VerdictEngine.Config.AutoTerminate &&
        !g_VerdictEngine.Config.AutoQuarantine &&
        !g_VerdictEngine.Config.AutoIsolate) {
        return;
    }

    switch (Verdict->RecommendedAction) {
        case DefRespAction_Terminate:
            /* 复用处置引擎 (废弃 SS OpenProcess+TerminateProcess 裸杀) */
            if (g_VerdictEngine.Config.AutoTerminate)
                ProcessManager_KillProcessAsync(pid);
            break;
        case DefRespAction_Quarantine:
            if (g_VerdictEngine.Config.AutoQuarantine)
                ProcessManager_IsolateProcess(pid);
            break;
        case DefRespAction_Isolate:
            if (g_VerdictEngine.Config.AutoIsolate)
                ProcessManager_IsolateProcess(pid);
            break;
        default:
            break;
    }
    InterlockedIncrement64(&g_VerdictEngine.ResponsesDispatched);
}

/**************************************************/
/*               Verdict → IOA_ALERT 投影           */
/**************************************************/

VOID
VerdictEngine_VerdictToAlert(
    _In_ PWKD_VERDICT Verdict,
    _Inout_ PIOA_ALERT Alert
    )
{
    if (!Verdict || !Alert) return;

    RtlZeroMemory(Alert, sizeof(*Alert));
    Alert->AlertId = Verdict->VerdictId;
    Alert->Timestamp = Verdict->Timestamp;
    Alert->SuspectNodeId = Verdict->SuspectNodeId;
    Alert->VictimNodeId = Verdict->VictimNodeId;
    Alert->RuleName = L"VerdictEngine";
    Alert->MitreId = (Verdict->MitreCount > 0) ? Verdict->MitreIds[0] : NULL;
    Alert->Severity = Verdict->Severity;
    Alert->Score = Verdict->ThreatScore;
    Alert->Confidence = Verdict->Confidence;
    Alert->Category = Verdict->Category;
    Alert->ConfidenceLevel = Verdict->ConfidenceLevel;
    Alert->RecommendedAction = Verdict->RecommendedAction;
    Alert->DetectionSource = Verdict->PrimarySource;
    Alert->Description = Verdict->Description[0] ? Verdict->Description : NULL;
}

/* 单块堆分配 (IOA_ALERT + 字符串缓冲), 满足持久化队列
 * UtHeapFree(Data) 整体释放语义 (IoaPersistQueue.c L60-62) */
PIOA_ALERT
VerdictEngine_AllocPersistAlert(
    _In_ PWKD_VERDICT Verdict
    )
{
    size_t ruleLen = wcslen(L"VerdictEngine");
    size_t mitreLen = (Verdict->MitreCount > 0) ? wcslen(Verdict->MitreIds[0]) : 0;
    size_t descLen = Verdict->Description[0] ? wcslen(Verdict->Description) : 0;
    size_t total = sizeof(IOA_ALERT) +
                   (ruleLen + 1 + mitreLen + 1 + descLen + 1) * sizeof(WCHAR);
    PIOA_ALERT alert = (PIOA_ALERT)UtHeapAlloc(total);
    PWCHAR buf;

    if (!alert) return NULL;
    RtlZeroMemory(alert, total);

    VerdictEngine_VerdictToAlert(Verdict, alert);

    buf = (PWCHAR)((PUCHAR)alert + sizeof(IOA_ALERT));
    alert->RuleName = buf;
    wcscpy_s(buf, ruleLen + 1, L"VerdictEngine");
    buf += ruleLen + 1;

    if (mitreLen) {
        alert->MitreId = buf;
        wcscpy_s(buf, mitreLen + 1, Verdict->MitreIds[0]);
        buf += mitreLen + 1;
    }
    if (descLen) {
        alert->Description = buf;
        wcscpy_s(buf, descLen + 1, Verdict->Description);
    }
    return alert;
}

/**************************************************/
/*               运行时规则 (死代码)                */
/**************************************************/

NTSTATUS
VerdictEngine_ApplyRuntimeRules(
    _In_ PWKD_EVENT_HEADER   Event,
    _In_opt_ PWKD_PROCESS Node,
    _Inout_ PULONG           Score
    )
/*++
Routine Description:
    运行时规则评估 (※死代码: EnableRuntimeRules=FALSE, 评估逻辑预留)。
    SS DetectionRule 的 ApplyRules 亦为假 API (声明未实现), 此处保留
    接口占位; 规则注册表在 PolicyEngine (WKD_DETECTION_RULE), 待接线。
--*/
{
    UNREFERENCED_PARAMETER(Event);
    UNREFERENCED_PARAMETER(Node);
    if (Score) *Score = 0;
    return STATUS_NOT_IMPLEMENTED;
}

/**************************************************/
/*               ALPC 查询 handler                  */
/**************************************************/

/* 0x1005 GetActiveThreatsReq → 0x2005 响应 (WKD_VERDICT 数组) */
NTSTATUS
VerdictEngine_GetActiveThreatsHandler(
    _In_ PWKD_ALPC_SERVER Server,
    _In_ PWKD_MESSAGE     Message,
    _In_opt_ PVOID        Context
    )
{
    ULONG count;
    PWKD_VERDICT arr;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Message);
    UNREFERENCED_PARAMETER(Context);

    count = VerdictEngine_GetActiveThreatCount();
    if (count == 0) {
        return WkdAlpcSendToUiEx(Server, WkdAlpcMsg_GetActiveThreatsResp, NULL, 0, 0);
    }

    arr = (PWKD_VERDICT)UtHeapAlloc(sizeof(WKD_VERDICT) * count);
    if (!arr) return STATUS_NO_MEMORY;

    count = VerdictEngine_GetActiveThreats(arr, count);
    status = WkdAlpcSendToUiEx(Server, WkdAlpcMsg_GetActiveThreatsResp,
                               arr, (ULONG)(sizeof(WKD_VERDICT) * count), 0);
    UtHeapFree(arr);
    return status;
}

/* 0x1006 GetVerdictReq (载荷=GUID NodeId) → 0x2006 响应 (WKD_VERDICT) */
NTSTATUS
VerdictEngine_GetVerdictHandler(
    _In_ PWKD_ALPC_SERVER Server,
    _In_ PWKD_MESSAGE     Message,
    _In_opt_ PVOID        Context
    )
{
    GUID nodeId;
    WKD_VERDICT verdict;

    UNREFERENCED_PARAMETER(Context);

    if (!Message || Message->Header.BodySize < sizeof(GUID)) {
        return WkdAlpcSendToUiEx(Server, WkdAlpcMsg_GetVerdictResp, NULL, 0, 0);
    }
    memcpy(&nodeId, Message->Body, sizeof(GUID));

    if (!VerdictEngine_GetVerdict(nodeId, &verdict)) {
        return WkdAlpcSendToUiEx(Server, WkdAlpcMsg_GetVerdictResp, NULL, 0, 0);
    }
    return WkdAlpcSendToUiEx(Server, WkdAlpcMsg_GetVerdictResp,
                             &verdict, sizeof(verdict), 0);
}

/**************************************************/
/*               生命周期                           */
/**************************************************/

NTSTATUS
VerdictEngine_Initialize(
    _In_opt_ PVERDICT_ENGINE_CONFIG Config
    )
{
    if (g_VerdictEngine.Initialized) return STATUS_SUCCESS;

    RtlZeroMemory(&g_VerdictEngine, sizeof(g_VerdictEngine));
    {
        /* MSVC C89 不支持结构体赋值聚合字面量, 用 static const 实例 */
        static const VERDICT_ENGINE_CONFIG defaultCfg = VERDICT_DEFAULT_CONFIG;
        g_VerdictEngine.Config = Config ? *Config : defaultCfg;
    }
    if (!g_VerdictEngine.Config.Enabled) return STATUS_SUCCESS;

    for (ULONG i = 0; i < VERDICT_HASH_BUCKETS; i++) {
        InitializeListHead(&g_VerdictEngine.HashBuckets[i]);
    }
    InitializeListHead(&g_VerdictEngine.LruHead);
    InitializeCriticalSection(&g_VerdictEngine.Lock);
    InitializeCriticalSection(&g_VerdictEngine.WhitelistLock);
    g_VerdictEngine.Initialized = TRUE;

    printf("[VerdictEngine] Initialized: th=%lu/%lu/%lu weights=%lu/%lu/%lu/%lu/%lu/%lu "
           "autoTerm=%d autoQuar=%d autoIso=%d\n",
           g_VerdictEngine.Config.DetectionThreshold,
           g_VerdictEngine.Config.HighThreshold,
           g_VerdictEngine.Config.CriticalThreshold,
           g_VerdictEngine.Config.WeightIoc,
           g_VerdictEngine.Config.WeightT1,
           g_VerdictEngine.Config.WeightT2,
           g_VerdictEngine.Config.WeightT3,
           g_VerdictEngine.Config.WeightClassifier,
           g_VerdictEngine.Config.WeightBehavior,
           g_VerdictEngine.Config.AutoTerminate,
           g_VerdictEngine.Config.AutoQuarantine,
           g_VerdictEngine.Config.AutoIsolate);
    return STATUS_SUCCESS;
}

VOID
VerdictEngine_Cleanup(
    VOID
    )
{
    if (!g_VerdictEngine.Initialized) return;

    printf("[VerdictEngine] Cleanup: verdicts=%lld dispatched=%lld active=%lu\n",
           g_VerdictEngine.VerdictsProduced,
           g_VerdictEngine.ResponsesDispatched,
           g_VerdictEngine.Count);

    EnterCriticalSection(&g_VerdictEngine.Lock);
    while (!IsListEmpty(&g_VerdictEngine.LruHead)) {
        PLIST_ENTRY head = g_VerdictEngine.LruHead.Flink;
        PWKD_ACTIVE_THREAT cur = CONTAINING_RECORD(head, WKD_ACTIVE_THREAT, LruLink);
        RemoveEntryList(&cur->LruLink);
        RemoveEntryList(&cur->HashLink);
        UtHeapFree(cur);
    }
    g_VerdictEngine.Count = 0;
    LeaveCriticalSection(&g_VerdictEngine.Lock);

    DeleteCriticalSection(&g_VerdictEngine.Lock);
    DeleteCriticalSection(&g_VerdictEngine.WhitelistLock);
    g_VerdictEngine.Initialized = FALSE;
}
