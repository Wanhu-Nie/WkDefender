/**************************************************/
/*  WkDefender — 异步持久化队列                      */
/*  共享 schema，各子系统注册 serde                  */
/*  Tier 1 写图后入队，后台线程批量落盘              */
/**************************************************/

#pragma once

#include "../DefendTypes.h"

/**************************************************/
/*               持久化条目类型                     */
/**************************************************/

typedef enum _IOA_RECORD_ENTRY_TYPE {
    PersistType_Event  = 0,         /* WKD_EVENT_HEADER */
    PersistType_Node,               /* WKD_PROCESS */
    PersistType_Edge,               /* IOA_GRAPH_EDGE         */
    PersistType_Alert               /* 告警结构体       */
} IOA_RECORD_ENTRY_TYPE;

/**************************************************/
/*               Serde 函数指针                     */
/**************************************************/

typedef NTSTATUS (*PERSIST_SERDE_WRITE_FN)(PVOID Data);

/**************************************************/
/*               持久化条目                         */
/**************************************************/

typedef struct _IOA_RECORD_ENTRY {
    LIST_ENTRY              Link;
    IOA_RECORD_ENTRY_TYPE   Type;
    PVOID                   Data;           /* 数据副本指针 */
    PERSIST_SERDE_WRITE_FN  SerdeWrite;     /* 写入 serde 函数 */
    BOOLEAN                 IsCritical;     /* TRUE = 不可丢弃 */
} IOA_RECORD_ENTRY, *PIOA_RECORD_ENTRY;

/**************************************************/
/*               异步持久化队列                     */
/**************************************************/

typedef struct _IOA_PERSIST_QUEUE {
    LIST_ENTRY              Head;           /* IOA_RECORD_ENTRY 链表头 */
    volatile LONG           Count;          /* 当前队列长度 */
    volatile LONG           MaxCount;       /* 最大容量（超限时丢弃非关键条目） */
    CRITICAL_SECTION        Lock;
    HANDLE                  WorkerThread;
    volatile BOOLEAN        Running;
    HANDLE                  WakeEvent;      /* 自动重置事件，唤醒后台线程 */
    volatile LONG64         TotalEnqueued;
    volatile LONG64         TotalWritten;
    volatile LONG64         TotalDropped;
} IOA_PERSIST_QUEUE, *PIOA_PERSIST_QUEUE;

/**************************************************/
/*               告警结构体                         */
/**************************************************/

typedef struct _IOA_ALERT {
    GUID                    AlertId;
    LARGE_INTEGER           Timestamp;
    GUID                    SuspectNodeId;      /* 嫌疑进程 */
    GUID                    VictimNodeId;       /* 受害进程/实体 */
    PCWSTR                  RuleName;
    PCWSTR                  MitreId;
    DEF_THREAT_SEVERITY     Severity;
    ULONG                   Score;
    ULONG                   Confidence;

    /* ── Verdict 扩展 (ThreatDetector 迁移, 2026-08-04) ──
     * 作为 WKD_VERDICT 的持久化投影，字段语义对齐 DefendTypes.h
     * 新增的 DEF_THREAT_CATEGORY / DEF_CONFIDENCE_LEVEL /
     * DEF_RESPONSE_ACTION / DEF_DETECTION_SOURCE。 */
    DEF_THREAT_CATEGORY     Category;           /* 威胁类别 */
    DEF_CONFIDENCE_LEVEL    ConfidenceLevel;    /* 置信度级别 (引擎一致率) */
    DEF_RESPONSE_ACTION     RecommendedAction;  /* 推荐响应动作 */
    DEF_DETECTION_SOURCE    DetectionSource;    /* 主检测源 */

    PWCHAR                  Description;        /* 堆分配，需要释放 */
} IOA_ALERT, *PIOA_ALERT;

/**************************************************/
/*               函数声明                           */
/**************************************************/

NTSTATUS PersistQueue_Initialize(
    _Out_ PIOA_PERSIST_QUEUE* OutQueue,
    _In_  ULONG               MaxCapacity
    );

VOID     PersistQueue_Cleanup(
    _In_ PIOA_PERSIST_QUEUE Queue
    );

/* 非阻塞入队：调用后立即返回，后台线程负责落盘 */
VOID
IoaPersistQueueEnqueue(
    PIOA_PERSIST_QUEUE Queue,
    IOA_RECORD_ENTRY_TYPE Type,
    PVOID              Data,
    PERSIST_SERDE_WRITE_FN SerdeWrite,
    BOOLEAN            IsCritical
    );

/* 统计 */
VOID     PersistQueue_Flush(
    _In_ PIOA_PERSIST_QUEUE Queue        /* 同步刷盘（用于关闭前） */
    );
