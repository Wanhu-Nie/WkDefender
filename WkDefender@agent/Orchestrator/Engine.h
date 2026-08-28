/**************************************************/
/*  WkDefender Agent — 主编排层                     */
/*  IOC/IOA 双引擎已独立，此处仅做事件路由           */
/**************************************************/

#pragma once

#include "../DefendTypes.h"
#include "../WkDefenderHeader.h"
#include "../Notification/EventParser.h"
#include "../Notification/msg_queue.h"

/**************************************************/
/*               引擎配置                           */
/**************************************************/

typedef struct _ORC_ENGINE_CONFIG {
    ULONG   HotCacheMaxEntries;
    ULONG   HotCacheTtlMs;
    ULONG   PruneIntervalMs;
    ULONG   EdgeRetentionWindowMs;
    WCHAR   WarmDbPath[DEF_MAX_PATH];
    WCHAR   ColdDbPath[DEF_MAX_PATH];
    ULONG   ColdRetentionDays;
    ULONG   AttackChainMaxDepth;
    ULONG   AttackChainMinScore;
    BOOLEAN VerboseLogging;
    BOOLEAN StatsCollection;
    BOOLEAN AnalysisEnabled;
    UCHAR   Reserved;
    ULONG   TemporalWindowMs;
    ULONG   AlertThrottleSeconds;
    ULONG   ScoreDecayIntervalMs;
} ORC_ENGINE_CONFIG, *PORC_ENGINE_CONFIG;

#define CG_DEFAULT_CONFIG                   \
    {                                       \
        DEF_HOT_CACHE_MAX_ENTRIES,          \
        DEF_HOT_CACHE_TTL_MS,               \
        60000, 3600000,                     \
        L"cg_warm.db", L"cg_cold.db",       \
        90, DEF_PATH_MAX_DEPTH, 50,         \
        TRUE, TRUE, TRUE, 0,                \
        60000, 300, 60000,                  \
    }

/**************************************************/
/*               引擎上下文                         */
/**************************************************/


typedef struct _ORC_ENGINE {
    BOOLEAN             Initialized;
    BOOLEAN             Running;
    ORC_ENGINE_CONFIG    Config;
    PWKD_SCHEMA_TABLE   SchemaTable;
    WKD_MSG_QUEUE       MessageQueue;

    struct {
        volatile ULONG  EvnetsIngested;
        volatile ULONG  EventsRefused;      /* 事件分发过程中出现错误 */
        volatile ULONG  ThreatsEscalated;
    } Statistics;

    HANDLE              MaintenanceThread;
    BOOLEAN             MaintenanceRunning;

    /* IOA 异步处理线程 */
    HANDLE              FsmCleanupThread;       /* FSM 追踪器过期清理 */
    BOOLEAN             FsmCleanupRunning;
    HANDLE              T2AlertThread;          /* Tier 2 告警异步处理 */
    BOOLEAN             T2AlertRunning;
    HANDLE              T3MaintenanceThread;    /* Tier 3 定期维护 (淘汰过期链+多点关联) */
    BOOLEAN             T3MaintenanceRunning;

    CRITICAL_SECTION    Lock;
} ORC_ENGINE, *PORC_ENGINE;

extern ORC_ENGINE WkdOrchestratorEngine;

NTSTATUS OrcEngineInitialize(_In_ PORC_ENGINE Engine, _In_ PORC_ENGINE_CONFIG Config);
NTSTATUS CgEngineStart(_In_ PORC_ENGINE Engine);
NTSTATUS CgEngineStop(_In_ PORC_ENGINE Engine);
VOID     CgEngineCleanup(_In_ PORC_ENGINE Engine);
NTSTATUS OrcWkdMessageEnqueueCallback(_In_ struct _WKD_ALPC_SERVER* Server, _In_ PWKD_MESSAGE Message, _In_opt_ PVOID Context);
VOID     CgEnginePrintStats(_In_ PORC_ENGINE Engine);

/* 内部: 消息分发流水线 */
NTSTATUS
OrcpWkdMessageDispatcher(
    _In_ PWKD_MESSAGE Message,
    _In_opt_ PVOID Context
    );
