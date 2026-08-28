/**************************************************/
/*  WkDefender — IOC 引擎（静态特征检测 + 等级映射） */
/*                                                   */
/*  职责:                                            */
/*    1. IOC 检测函数（命令行/LOLBin/签名等）          */
/*    2. 指标 → 默认威胁程度映射表                    */
/*       （IocGetIndicatorSeverity，供             */
/*        AeReportIndicator 查默认等级）              */
/*                                                   */
/*  注意（2026-07 迁移）: IocContext 迁至进程对，      */
/*  持有按 Indicator 去重的 IOC 证据链；              */
/*  重复命中不再上报评分系统（评分侧只收新事实）。     */
/**************************************************/

#pragma once

#include <ntifs.h>
#include "../ThreatScoring/ThreatScoring.h"     /* TS_INDICATOR_TYPE, TS_SOURCE */
#include "../Common/Constants.h"                /* AE_THREAT_SEVERITY */

struct _AE_PROCESS_PAIR;
typedef struct _AE_PROCESS_PAIR AE_PROCESS_PAIR, *PAE_PROCESS_PAIR;

//
// IocContext — 进程对 IOC 证据链（按 Indicator 去重，新覆盖旧）。
// 生命周期 = pair 生命周期；重复命中不再上报评分系统。
//
#define WKD_MAX_IOC_RECORDS         64      /* TS_INDICATOR_TYPE IOC 段实际 51 项，64 富余 */

//
// IOC 证据节点 — 每个节点代表一条去重后的 IOC 检测结果
//
typedef struct _AE_IOC_RECORD {
    LIST_ENTRY          Link;           // → IocContext.IocChain
    TS_INDICATOR_TYPE   Indicator;      // 指标类型（查重键）
    AE_THREAT_SEVERITY Severity;       // 威胁程度 1-4
    LARGE_INTEGER       Timestamp;      // 最近一次命中时间
} AE_IOC_RECORD, *PAE_IOC_RECORD;

typedef struct _AE_IOC_CONTEXT {
    LIST_ENTRY      IocChain;           /* IOC 证据链：按 Indicator 去重（键 = Indicator） */
    volatile ULONG  TotalRecords;       /* 去重后命中总数（持久统计） */
    volatile ULONG  ActiveRecords;      /* 当前链长（≤ WKD_MAX_IOC_RECORDS） */
} AE_IOC_CONTEXT, * PAE_IOC_CONTEXT;

//
// 初始化与清理
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocInitialize(
    VOID
);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IocCleanup(
    VOID
);

//
// 分配进程对的 IocContext — 由 AeFindOrCreateProcessPair 创建时调用。
// 分配 + 初始化链头 + 锁。失败返回 NULL。
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IocAllocateProcessPairContext(
    _Inout_ PAE_PROCESS_PAIR Pair
    );

//
// 销毁进程对的 IocContext — 由 PsDereferenceWkdProcessPair refcount==0 分支调用。
// 遍历 IocChain 释放全部证据节点 + 释放 context + 置 NULL。
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IocFreeProcessPairContext(
    _Inout_ PAE_PROCESS_PAIR Pair
);

//
// 查询指标默认威胁程度 — 分析引擎威胁程度映射表
// 返回 AE_THREAT_SEVERITY (0-4)；0 表示无威胁贡献（不落记录）。
// 由 AeReportIndicator 查默认等级使用。
//
_IRQL_requires_max_(APC_LEVEL)
UCHAR
IocGetIndicatorSeverity(
    _In_ TS_INDICATOR_TYPE Indicator
);

//
// IOC 证据链查重 + "新覆盖旧"（持有 IocContext->Lock 独占时调用）。
// 命中返回 TRUE（调用方不得再上报评分系统）；未命中返回 FALSE。
//
_IRQL_requires_(APC_LEVEL)
BOOLEAN
IocIndicatorDedupLocked(
    _Inout_ PAE_IOC_CONTEXT IocContext,
    _In_ TS_INDICATOR_TYPE Indicator,
    _In_ UCHAR Severity,
    _In_ LARGE_INTEGER Timestamp
);

//
// IOC 检测函数（保留，功能不变）
//
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocCheckPowershellEncoded(
    _In_ PUNICODE_STRING CommandLine
);

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocCheckDownloader(
    _In_ PUNICODE_STRING CommandLine
);

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocCheckReflectiveLoad(
    _In_ PUNICODE_STRING CommandLine
);

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocCheckSuspiciousCmd(
    _In_ PUNICODE_STRING CommandLine
);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IocAnalyzeCommandLine(
    _In_ PUNICODE_STRING CommandLine,
    _Out_ PULONG Flags
);

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocCheckLolbin(
    _In_ PUNICODE_STRING ImagePath
);

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocValidateSignature(
    _In_ PWKD_PROCESS WkdProcess
);

_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN
IocValidatePeHeader(
    _In_ PWKD_PROCESS WkdProcess
);
