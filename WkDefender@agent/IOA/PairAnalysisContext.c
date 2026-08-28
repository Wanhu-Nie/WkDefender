/**************************************************/
/*  WkDefender IOA — 进程对三分析上下文实现           */
/*  (对齐 driver Ioc/Ioa/Ts 三 Allocate/Free 裁剪)   */
/*  2026-08-23 新建: 进程对维度分析+评分核心挂载单元  */
/**************************************************/

#include "PairAnalysisContext.h"
#include "../Common/Utils.h"
#include <string.h>

/**************************************************/
/*               上下文分配                          */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
AeCreateProcessPairContexts(
    _Inout_ PAE_PROCESS_PAIR Pair
    )
/*++
Routine Description:
    分配进程对的三分析上下文 (IOC/IOA/TS)。由 AeFindOrCreateProcessPair
    慢路径 double-check 通过后调用, 创建时全部分配三上下文
    (对齐 driver AeFindOrCreateProcessPair 2026-07 迁移: 进程对成为
    分析+评分核心挂载单元, 无进程侧挂链)。

    任一上下文分配失败回滚已分配部分并返回失败 (调用方释放 pair 整体)。

Arguments:
    Pair — 已 RtlZeroMemory 的进程对上下文 (三指针域初始 NULL)。

Return Value:
    STATUS_SUCCESS          — 三上下文已分配并初始化。
    STATUS_INSUFFICIENT_RESOURCES — 内存分配失败 (已回滚)。
--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    PAE_PROCESS_PAIR_IOC_CONTEXT ioc;
    PAE_PROCESS_PAIR_IOA_CONTEXT ioa;
    PAE_PROCESS_PAIR_TS_CONTEXT  ts;

    if (!Pair) return STATUS_INVALID_PARAMETER;

    /* ---- IOC ---- */
    ioc = (PAE_PROCESS_PAIR_IOC_CONTEXT)malloc(sizeof(AE_PROCESS_PAIR_IOC_CONTEXT));
    if (!ioc) return STATUS_NO_MEMORY;
    RtlZeroMemory(ioc, sizeof(AE_PROCESS_PAIR_IOC_CONTEXT));
    InitializeListHead(&ioc->IocChain);

    /* ---- IOA ---- */
    ioa = (PAE_PROCESS_PAIR_IOA_CONTEXT)malloc(sizeof(AE_PROCESS_PAIR_IOA_CONTEXT));
    if (!ioa) { status = STATUS_NO_MEMORY; goto Cleanup; }
    RtlZeroMemory(ioa, sizeof(AE_PROCESS_PAIR_IOA_CONTEXT));
    InitializeListHead(&ioa->BehaviorHead);
    InitializeListHead(&ioa->IoaChain);
    
    /* ---- TS ---- */
    ts = (PAE_PROCESS_PAIR_TS_CONTEXT)malloc(sizeof(AE_PROCESS_PAIR_TS_CONTEXT));
    if (!ts) { status = STATUS_NO_MEMORY; goto Cleanup; }
    RtlZeroMemory(ts, sizeof(AE_PROCESS_PAIR_TS_CONTEXT));
    InitializeListHead(&ts->PendingIocChain);
    InitializeListHead(&ts->IoaChain);

    Pair->IocContext = ioc;
    Pair->IoaContext = ioa;
    Pair->TsContext = ts;
    return STATUS_SUCCESS;

Cleanup:
    if (ioc) free(ioc);
    if (ioa) free(ioa);
    return status;
}

/**************************************************/
/*               上下文释放                          */
/**************************************************/

_Use_decl_annotations_
VOID
AeDestroyProcessPairContexts(
    _Inout_ PAE_PROCESS_PAIR Pair
    )
/*++
Routine Description:
    释放进程对的三分析上下文。遍历三链释放全部记录节点 + 释放上下文 +
    置 NULL。由 PairManager_CleanupExpired (摘除成功后) / PairManager_Cleanup
    调用 (对齐 driver PsDereferenceWkdProcessPair refcount==0 分支)。
    **无锁访问**

    合法性前置: 调用方需保证 pair 已脱离索引且无并发写者
    (CleanupExpired 摘除后 / Cleanup 全局释放时满足)。

Arguments:
    Pair — 进程对上下文。
--*/
{
    PLIST_ENTRY entry;
    PIOA_PAIR_IOC_RECORD iocRec;
    PIOA_PAIR_IOA_RECORD ioaRec;
    PIOA_PAIR_TS_RECORD  tsRec;
    PAE_PROCESS_PAIR_IOC_CONTEXT ioc;
    PAE_PROCESS_PAIR_IOA_CONTEXT ioa;
    PAE_PROCESS_PAIR_TS_CONTEXT  ts;

    if (!Pair) return;

    ioc = Pair->IocContext;
    ioa = Pair->IoaContext;
    ts  = Pair->TsContext;

    /* 释放 IOC 证据链 */
    if (ioc) {
        while (!IsListEmpty(&ioc->IocChain)) {
            entry = RemoveHeadList(&ioc->IocChain);
            iocRec = CONTAINING_RECORD(entry, IOA_PAIR_IOC_RECORD, Link);
            free(iocRec);
        }
        free(ioc);
        Pair->IocContext = NULL;
    }

    /* 释放 IOA 行为摘要链 */
    if (ioa) {
        while (!IsListEmpty(&ioa->IoaChain)) {
            entry = RemoveHeadList(&ioa->IoaChain);
            ioaRec = CONTAINING_RECORD(entry, IOA_PAIR_IOA_RECORD, Link);
            free(ioaRec);
        }
        free(ioa);
        Pair->IoaContext = NULL;
    }

    /* 释放 TS 待结算 IOC 链 + IOA 窗口链 */
    if (ts) {
        while (!IsListEmpty(&ts->PendingIocChain)) {
            entry = RemoveHeadList(&ts->PendingIocChain);
            tsRec = CONTAINING_RECORD(entry, IOA_PAIR_TS_RECORD, Link);
            free(tsRec);
        }
        while (!IsListEmpty(&ts->IoaChain)) {
            entry = RemoveHeadList(&ts->IoaChain);
            tsRec = CONTAINING_RECORD(entry, IOA_PAIR_TS_RECORD, Link);
            free(tsRec);
        }
        free(ts);
        Pair->TsContext = NULL;
    }
}

/**************************************************/
/*               评分结算                            */
/**************************************************/

/*
 * 单条记录的贡献分 = Severity × 固定权重。
 * 对齐 driver TspGetIndicatorWeight 简化: agent 当前无完整权重表,
 * 采用 Severity 线性映射 (1→20 / 2→40 / 3→70 / 4→100), 与 IOC 严重度
 * 语义一致; 后续可接入 DefendTypes 权重表扩展。
 */
static
ULONG
IoaPairpRecordScore(
    _In_ DEF_THREAT_SEVERITY Severity
    )
{
    switch (Severity) {
    case DefThreatSeverity_Low:      return 20;
    case DefThreatSeverity_Medium:   return 40;
    case DefThreatSeverity_High:     return 70;
    case DefThreatSeverity_Critical: return 100;
    default:                          return 0;
    }
}

VOID
IoaPairTsSettle(
    _Inout_ PAE_PROCESS_PAIR Pair
    )
/*++
Routine Description:
    进程对评分结算 (60s 窗口, 委托 VerdictEngine 周期驱动)。

    逻辑 (对齐 driver TspSettleScoresInternal 裁剪):
      - PendingIocChain 归并进 IocScore 后清空 (只增不减, 钳位防溢出)
      - IoaChain 过期前缀惰性摘除 (IOA_PAIR_SETTLE_WINDOW_MS),
        存活记录 EWMA 更新 IoaScore
      - 综合分 = IocScore (进程对维度 IOC 累加) 与 IoaScore 的融合,
        钳位至 IOA_PAIR_SCORE_CEILING → CachedVerdict

    并发: 单结算线程调用 (VerdictEngine 周期驱动, 复用其维护节奏)。
    事件线程写 PendingIocChain/IoaChain 在持 pair 引用时, 与结算的非原子
    窗口由流水线串行性缓解 (最坏情况延至下轮结算兜底), 对齐 driver 范式。

Arguments:
    Pair — 进程对上下文。
--*/
{
    PLIST_ENTRY entry;
    PIOA_PAIR_TS_RECORD  rec;
    LARGE_INTEGER now;
    LONGLONG windowMs;
    PAE_PROCESS_PAIR_TS_CONTEXT ts;
    ULONG iocContribution;
    ULONG ioaContribution;
    ULONG combined;

    if (!Pair) return;
    ts = Pair->TsContext;
    if (!ts) return;

    GetSystemTimeAsFileTime((PFILETIME)&now);
    windowMs = (LONGLONG)IOA_PAIR_SETTLE_WINDOW_MS * 10000;

    /* ── 阶段1: PendingIocChain 归并 IOC 累计分 ── */
    while (!IsListEmpty(&ts->PendingIocChain)) {
        entry = RemoveHeadList(&ts->PendingIocChain);
        rec = CONTAINING_RECORD(entry, IOA_PAIR_TS_RECORD, Link);
        iocContribution = IoaPairpRecordScore(rec->Severity);
        ts->IocScore = (ts->IocScore > (0xFFFFFFFF - iocContribution))
                        ? 0xFFFFFFFF : (ts->IocScore + iocContribution);
        free(rec);   /* 与同文件记录释放口径一致 (2026-08-25) */
    }
    ts->TotalIocRecords += 0;   /* 已在提交时累计, 此处不重复 */

    /* ── 阶段2: IoaChain 过期摘除 + EWMA ── */
    while (!IsListEmpty(&ts->IoaChain)) {
        entry = ts->IoaChain.Flink;
        rec = CONTAINING_RECORD(entry, IOA_PAIR_TS_RECORD, Link);
        if (now.QuadPart - rec->Timestamp.QuadPart <= windowMs) {
            break;   /* 链时间升序, 头部未过期则后续均存活 */
        }
        RemoveEntryList(entry);
        ioaContribution = IoaPairpRecordScore(rec->Severity);
        /* EWMA: 新样本权重 0.3, 历史 0.7 (对齐 driver 内层平滑) */
        ts->IoaScore = (ULONG)((ts->IoaScore * 7 + ioaContribution * 3) / 10);
        if (ts->ActiveIoaRecords > 0) ts->ActiveIoaRecords--;
        free(rec);   /* 与同文件记录释放口径一致 (2026-08-25) */
    }

    /* ── 阶段3: 综合分钳位 + 裁决 ── */
    combined = (ts->IocScore > ts->IoaScore) ? ts->IocScore : ts->IoaScore;
    combined = (combined > IOA_PAIR_SCORE_CEILING) ? IOA_PAIR_SCORE_CEILING : combined;

    if (combined >= IOA_PAIR_BLOCKED_THRESHOLD) {
        ts->CachedVerdict = IoaPairVerdict_Blocked;
    } else if (combined >= IOA_PAIR_MALICIOUS_THRESHOLD) {
        ts->CachedVerdict = IoaPairVerdict_Malicious;
    } else if (combined >= IOA_PAIR_SUSPICIOUS_THRESHOLD) {
        ts->CachedVerdict = IoaPairVerdict_Suspicious;
    } else if (combined == 0) {
        ts->CachedVerdict = IoaPairVerdict_Clean;
    } else {
        ts->CachedVerdict = IoaPairVerdict_Suspicious;
    }

    ts->LastSettleTime = now;
}
