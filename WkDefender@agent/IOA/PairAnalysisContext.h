/**************************************************/
/*  WkDefender IOA — 进程对三分析上下文                 */
/*  (对齐 driver AE_PROCESS_PAIR 内嵌                 */
/*   IocContext/IoaContext/TsContext, 2026-08-23)     */
/*                                                  */
/*  职责:                                            */
/*    - IOC 证据链: 进程对维度的互动 IOC 痕迹          */
/*      (如 shellcode 注入证据), 按 Indicator 去重     */
/*    - IOA 行为摘要链: 行为记录 FIFO                  */
/*    - 评分上下文: 仅数据结构, 60s 结算委托            */
/*      VerdictEngine (不复刻 driver 维护线程)         */
/*                                                  */
/*  IOC 回归本义: 互动产生的 IOC 证据挂进程对          */
/*  IocContext; 进程固有静态结论挂 WKD_PROCESS        */
/*  安全上下文 (SecCtx), 二者不重叠。                  */
/**************************************************/

#pragma once

#include "IoaTypes.h"       /* PAE_PROCESS_PAIR, DEF_THREAT_SEVERITY via DefendTypes.h */

/**************************************************/
/*               评分裁决枚举                        */
/**************************************************/

/* 对齐 driver TS_VERDICT (裁剪内核专属字段) */
typedef enum _IOA_PAIR_VERDICT {
    IoaPairVerdict_Unknown = 0,
    IoaPairVerdict_Clean,
    IoaPairVerdict_Suspicious,
    IoaPairVerdict_Malicious,
    IoaPairVerdict_Blocked,            /* 超拦截阈值 — 已采取动作 */
} IOA_PAIR_VERDICT, *PIOA_PAIR_VERDICT;

/**************************************************/
/*               常量                               */
/**************************************************/

#define IOA_MAX_IOC_RECORDS     64      /* 对齐 driver WKD_MAX_IOC_RECORDS */
#define IOA_MAX_IOA_RECORDS     1024    /* 对齐 driver WKD_MAX_IOA_CHAIN_RECORDS */
#define IOA_PAIR_SETTLE_WINDOW_MS  60000   /* 60s 评分结算窗口 (委托 VerdictEngine) */

/* 归一化阈值 (对齐 driver TS_THRESHOLD_CONFIG 默认) */
#define IOA_PAIR_SUSPICIOUS_THRESHOLD  50
#define IOA_PAIR_MALICIOUS_THRESHOLD   80
#define IOA_PAIR_BLOCKED_THRESHOLD     95
#define IOA_PAIR_SCORE_CEILING        100     /* 综合分钳位上限 */

/**************************************************/
/*               IOC 证据链                         */
/**************************************************/

/*
 * IOC 证据节点 — 每个节点代表一条去重后的 IOC 检测结果。
 * 查重键 = Indicator (互动产生的 IOC 痕迹, 如 shellcode 注入)。
 */
typedef struct _IOA_PAIR_IOC_RECORD {
    LIST_ENTRY          Link;           /* → IocContext.IocChain */
    ULONG               Indicator;      /* 指标类型 (0x0Dxx IOA 段 / 0x02xx CmdLine 段) */
    DEF_THREAT_SEVERITY Severity;       /* 威胁程度 1-4 */
    LARGE_INTEGER       Timestamp;      /* 最近一次命中时间 */
} IOA_PAIR_IOC_RECORD, *PIOA_PAIR_IOC_RECORD;

typedef struct _AE_PROCESS_PAIR_IOC_CONTEXT {
    LIST_ENTRY          IocChain;       /* IOC 证据链: 按 Indicator 去重 */
    ULONG               TotalRecords;   /* 去重后命中总数 (持久统计, 只增不减) */
    ULONG               ActiveRecords;  /* 当前链长 (≤ IOA_MAX_IOC_RECORDS) */
} AE_PROCESS_PAIR_IOC_CONTEXT, *PAE_PROCESS_PAIR_IOC_CONTEXT;

/**************************************************/
/*               IOA 行为摘要链                     */
/**************************************************/

/*
 * IOA 摘要记录 — 行为摘要 (证据, 生命周期 = pair = IoaContext)。
 */
typedef struct _IOA_PAIR_IOA_RECORD {
    LIST_ENTRY          Link;           /* → IoaContext.IoaChain */
    ULONG               Indicator;      /* 评分指标类型 (0x0Dxx IOA 段) */
    DEF_THREAT_SEVERITY Severity;       /* 威胁程度 1-4 */
    LARGE_INTEGER       Timestamp;      /* 提交时间 */
} IOA_PAIR_IOA_RECORD, *PIOA_PAIR_IOA_RECORD;

typedef struct _AE_PROCESS_PAIR_IOA_CONTEXT {
    /* 行为链 (前瞻: agent 当前无 WKD_BEHAVIOR 节点实现, 保留对齐 driver) */
    LIST_ENTRY          BehaviorHead;   /* 行为节点链表 */
    ULONG               ActiveBehaviors;/* 当前行为节点数 */
    ULONG               TotalBehaviors; /* 累计行为节点数 (只增不减) */

    /* 行为记录统计 (迁移自 pair->TotalRecords/ActiveRecords) */
    ULONG               TotalRecords;   /* 累计行为记录数 (只增不减) */
    ULONG               ActiveRecords;  /* 当前 IOA 所有有效行为记录数 */

    /* 摘要记录链 (FIFO 上限 IOA_MAX_IOA_RECORDS) */
    LIST_ENTRY          IoaChain;
    ULONG               IoaChainCount;  /* 当前摘要记录数 (FIFO 判断) */
    LARGE_INTEGER       LastRecordTime;
} AE_PROCESS_PAIR_IOA_CONTEXT, *PAE_PROCESS_PAIR_IOA_CONTEXT;

/**************************************************/
/*               评分上下文                         */
/**************************************************/

/*
 * IOA_PAIR_TS_RECORD — TS 上下文内的统一记录节点
 * (PendingIocChain / IoaChain 共用, 由所属链表头区分)。
 * 生命周期 = pair = TsContext; 提交时分配, 结算时摘除释放。
 */
typedef struct _IOA_PAIR_TS_RECORD {
    LIST_ENTRY          Link;           /* → TsContext.PendingIocChain | IoaChain */
    ULONG               Indicator;      /* 指标类型 */
    DEF_THREAT_SEVERITY Severity;        /* 威胁程度 1-4 */
    LARGE_INTEGER       Timestamp;       /* 提交时间 */
} IOA_PAIR_TS_RECORD, *PIOA_PAIR_TS_RECORD;

/*
 * 每进程对评分上下文 (生命周期由 pair 管理, 不进任何引擎链表)。
 * 仅数据结构 + 60s 结算; 结算委托 VerdictEngine 周期驱动。
 */
typedef struct _AE_PROCESS_PAIR_TS_CONTEXT {
    /* IOC 批次链: 仅缓存"本轮新增" (结算后清空并累加进 IocScore) */
    LIST_ENTRY          PendingIocChain;/* 链头最旧 (时间升序) */
    ULONG               TotalIocRecords;/* 生命周期累计提交数 (单调递增) */

    /* IOA 记录链: 60s 时间窗口 */
    LIST_ENTRY          IoaChain;       /* 链头最旧; 结算时惰性摘除过期前缀 */
    ULONG               TotalIoaRecords;
    ULONG               ActiveIoaRecords;/* 上限 IOA_MAX_IOA_RECORDS */

    /* IOC 持久累计分 (只增不减, 钳位防溢出) */
    ULONG               IocScore;

    /* IOA 内层 EWMA 缓存 */
    ULONG               IoaScore;       /* EWMA 平滑后的 IOA 内层分 */
    LARGE_INTEGER       LastSettleTime; /* 上次结算时间 */
    IOA_PAIR_VERDICT    CachedVerdict;

    LARGE_INTEGER       FirstRecordTime;
    LARGE_INTEGER       LastRecordTime;
} AE_PROCESS_PAIR_TS_CONTEXT, *PAE_PROCESS_PAIR_TS_CONTEXT;

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * 分配进程对的三分析上下文 (对齐 driver Ioc/Ioa/Ts 三 Allocate 合一)。
 * 由 AeFindOrCreateProcessPair 创建时调用 (慢路径 double-check 通过后)。
 * 任一上下文分配失败回滚已分配部分并返回失败。
 */
NTSTATUS
AeCreateProcessPairContexts(
    _Inout_ PAE_PROCESS_PAIR Pair
    );

/*
 * 释放进程对的三分析上下文 (对齐 driver PsDereferenceWkdProcessPair refcount==0
 * 分支)。遍历三链释放全部记录节点 + 释放上下文 + 置 NULL。
 * 由 IocCleanupExpiredProcessPair (摘除成功后) / PairManager_Cleanup 调用。
 */
VOID
AeDestroyProcessPairContexts(
    _Inout_ PAE_PROCESS_PAIR Pair
    );

/*
 * 进程对评分结算 (60s 窗口, 委托 VerdictEngine 周期驱动)。
 *  - PendingIocChain 归并进 IocScore 后清空
 *  - IoaChain 过期前缀惰性摘除 (IOA_PAIR_SETTLE_WINDOW_MS), EWMA 更新 IoaScore
 *  - 综合分钳位 → CachedVerdict
 * 单结算线程调用; 与事件线程并发写评分的锁保护见 PairManager_SettleAll 注释。
 */
VOID
IoaPairTsSettle(
    _Inout_ PAE_PROCESS_PAIR Pair
    );
