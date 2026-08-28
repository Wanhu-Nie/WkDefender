#pragma once

#include "WkDefenderHeader.h"
#include "process_manager.h"
#include "Notification/msg_queue.h"
#include "Process/ProcessTypes.h"          /* PWKD_PROCESS (进程域统一重构 2026-08-15) */

/*
 * 日志管理模块头文件
 * 功能：实现安全事件日志的持久化存储、查询和定期清理
 * 数据库：SQLite3
 * 作者：WkDefender Team
 * 日期：2026-04-09
 */

// SQLite3 前置声明
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

// 日志数据库文件路径
#define LOG_DATABASE_PATH       L"WkDefender_Logs.db"
#define LOG_DATABASE_VERSION    1

// 日志表名
#define TABLE_SECURITY_LOGS     "security_logs"
#define TABLE_FILTER_RULES      "filter_rules"
#define TABLE_LOG_METADATA      "log_metadata"

// 事件类型定义
typedef enum _SECURITY_EVENT_TYPE {
    EVENT_TYPE_UNKNOWN = 0,
    EVENT_TYPE_PROCESS_CREATE = 1,
    EVENT_TYPE_PROCESS_EXIT = 2,
    EVENT_TYPE_THREAD_CREATE = 3,
    EVENT_TYPE_THREAD_EXIT = 4,
    EVENT_TYPE_API_CALL = 5,
    EVENT_TYPE_MODULE_LOAD = 6,
    EVENT_TYPE_REGISTRY_ACCESS = 7,
    EVENT_TYPE_FILE_ACCESS = 8,
    EVENT_TYPE_NETWORK_CONNECTION = 9,
    EVENT_TYPE_SYSCALL = 10,                        // 驱动转发的 syscall 事件
    EVENT_TYPE_THREAT_DETECTED = 100,
    EVENT_TYPE_BEHAVIOR_BLOCKED = 101,
    EVENT_TYPE_ISOLATION_TRIGGERED = 102
} SECURITY_EVENT_TYPE;

// 威胁等级定义
typedef enum _LOG_THREAT_LEVEL {
    LOG_THREAT_NORMAL = 0,
    LOG_THREAT_LOW = 1,
    LOG_THREAT_MEDIUM = 2,
    LOG_THREAT_HIGH = 3,
    LOG_THREAT_CRITICAL = 4
} LOG_THREAT_LEVEL;

// 日志记录结构
typedef struct _SECURITY_LOG_ENTRY {
    LONGLONG Id;                        // 记录ID
    LARGE_INTEGER Timestamp;            // 时间戳
    ULONG EventType;                    // 事件类型
    ULONG ProcessId;                    // 进程ID
    WCHAR ProcessName[260];             // 进程名称
    ULONG ParentProcessId;              // 父进程ID
    WCHAR ParentProcessName[260];       // 父进程名称
    ULONG ThreatLevel;                  // 威胁等级
    WCHAR ImagePath[260];               // 映像路径
    WCHAR Details[2048];                // 详细信息（JSON格式）
    BOOL IsRead;                        // 是否已读
    BOOL IsArchived;                    // 是否已归档
    LARGE_INTEGER CreatedAt;            // 创建时间
} SECURITY_LOG_ENTRY, *PSECURITY_LOG_ENTRY;

// 过滤规则结构
typedef struct _LOG_FILTER_RULE {
    ULONG RuleId;                       // 规则ID
    WCHAR RuleName[128];                // 规则名称
    ULONG EventTypeFilter;              // 事件类型过滤（0表示全部）
    ULONG MinThreatLevel;               // 最小威胁等级
    WCHAR ProcessNameFilter[260];       // 进程名称过滤（支持通配符）
    WCHAR PathFilter[260];              // 路径过滤
    BOOL IsEnabled;                     // 是否启用
    ULONG Action;                       // 动作：0=记录, 1=忽略, 2=阻止
    WCHAR Description[512];             // 规则描述
} LOG_FILTER_RULE, *PLOG_FILTER_RULE;

// 日志查询条件
typedef struct _LOG_QUERY_CONDITION {
    LARGE_INTEGER StartTime;            // 开始时间
    LARGE_INTEGER EndTime;              // 结束时间
    ULONG EventType;                    // 事件类型（0表示全部）
    ULONG MinThreatLevel;               // 最小威胁等级
    WCHAR ProcessNameFilter[260];       // 进程名称过滤
    BOOL OnlyUnread;                    // 仅未读
    ULONG MaxResults;                   // 最大返回数量
    ULONG Offset;                       // 偏移量（分页）
} LOG_QUERY_CONDITION, *PLOG_QUERY_CONDITION;

// 日志管理器上下文
typedef struct _LOG_MANAGER {
    sqlite3* Database;                  // SQLite数据库句柄
    BOOL Initialized;                   // 是否已初始化
    CRITICAL_SECTION Lock;              // 同步锁
    WCHAR DatabasePath[MAX_PATH];       // 数据库文件路径

    // 统计信息
    LONGLONG TotalLogs;                 // 总日志数
    LONGLONG UnreadLogs;                // 未读日志数
    LONGLONG ThreatLogs;                // 威胁日志数

    // 维护线程
    HANDLE MaintenanceThread;           // 维护线程
    BOOL MaintenanceRunning;            // 维护线程运行标志
    ULONG RetentionDays;                // 日志保留天数
    ULONG MaxDatabaseSizeMB;            // 最大数据库大小（MB）
    
    // 消息队列
    WKD_MSG_QUEUE MessageQueue;         // 独立的消息队列
    HANDLE WorkerThread;                // 独立的处理线程
} LOG_MANAGER, *PLOG_MANAGER;

// 全局日志管理器声明
extern LOG_MANAGER g_LogManager;

// 日志查询回调函数类型
typedef BOOL (*LOG_QUERY_CALLBACK)(PSECURITY_LOG_ENTRY LogEntry, PVOID Context);

// 函数声明

// 初始化日志管理器（自注册模式）
// 内部完成结构体初始化、数据库打开、消息队列初始化。
// AlpcServer 参数当前保留（日志模块暂不注册 ALPC 路由，后续扩展）。
NTSTATUS LogManager_InitializeService(
    _Out_ PLOG_MANAGER LogManager,
    _In_ PCWSTR DatabasePath,
    _In_opt_ PWKD_ALPC_SERVER AlpcServer
);

// 清理日志管理器
VOID LogManager_Cleanup(
    _In_ PLOG_MANAGER LogManager
);

// 打开数据库连接
NTSTATUS LogManager_OpenDatabase(
    _In_ PLOG_MANAGER LogManager,
    _In_ PCWSTR DatabasePath
);

// 关闭数据库连接
VOID LogManager_CloseDatabase(
    _In_ PLOG_MANAGER LogManager
);

// 初始化数据库表结构
NTSTATUS LogManager_InitDatabaseSchema(
    _In_ PLOG_MANAGER LogManager
);

// 写入安全日志
NTSTATUS LogManager_WriteLog(
    _In_ PLOG_MANAGER LogManager,
    _In_ PSECURITY_LOG_ENTRY LogEntry
);

// 从进程节点写入日志（2026-08-15 进程域: WKD_PROCESS）
NTSTATUS LogManager_WriteProcessLog(
    _In_ PLOG_MANAGER LogManager,
    _In_ PWKD_PROCESS ProcessNode,
    _In_ ULONG EventType,
    _In_ ULONG ThreatLevel,
    _In_ PCWSTR Details
);

// 批量写入日志
NTSTATUS LogManager_WriteLogsBatch(
    _In_ PLOG_MANAGER LogManager,
    _In_ PSECURITY_LOG_ENTRY LogEntries,
    _In_ ULONG Count
);

// 查询日志
NTSTATUS LogManager_QueryLogs(
    _In_ PLOG_MANAGER LogManager,
    _In_ PLOG_QUERY_CONDITION Condition,
    _In_ LOG_QUERY_CALLBACK Callback,
    _In_opt_ PVOID Context
);

// 获取日志列表（数组形式）
NTSTATUS LogManager_GetLogs(
    _In_ PLOG_MANAGER LogManager,
    _In_ PLOG_QUERY_CONDITION Condition,
    _Out_ PSECURITY_LOG_ENTRY* LogEntries,
    _Out_ PULONG Count
);

// 根据ID获取单条日志
NTSTATUS LogManager_GetLogById(
    _In_ PLOG_MANAGER LogManager,
    _In_ LONGLONG LogId,
    _Out_ PSECURITY_LOG_ENTRY LogEntry
);

// 标记日志为已读
NTSTATUS LogManager_MarkAsRead(
    _In_ PLOG_MANAGER LogManager,
    _In_ LONGLONG LogId
);

// 批量标记为已读
NTSTATUS LogManager_MarkAsReadBatch(
    _In_ PLOG_MANAGER LogManager,
    _In_ PLONGLONG LogIds,
    _In_ ULONG Count
);

// 删除日志
NTSTATUS LogManager_DeleteLog(
    _In_ PLOG_MANAGER LogManager,
    _In_ LONGLONG LogId
);

// 删除指定时间之前的日志
NTSTATUS LogManager_DeleteLogsBefore(
    _In_ PLOG_MANAGER LogManager,
    _In_ LARGE_INTEGER Timestamp
);

// 归档旧日志
NTSTATUS LogManager_ArchiveOldLogs(
    _In_ PLOG_MANAGER LogManager,
    _In_ ULONG DaysOld
);

// 获取日志统计信息
NTSTATUS LogManager_GetStatistics(
    _In_ PLOG_MANAGER LogManager,
    _Out_ PLONGLONG TotalLogs,
    _Out_ PLONGLONG UnreadLogs,
    _Out_ PLONGLONG ThreatLogs
);

// 获取指定时间范围内的日志数量
NTSTATUS LogManager_GetLogCountInRange(
    _In_ PLOG_MANAGER LogManager,
    _In_ PLARGE_INTEGER StartTime,
    _In_ PLARGE_INTEGER EndTime,
    _Out_ PLONGLONG Count
);

// 过滤规则管理
NTSTATUS LogManager_AddFilterRule(
    _In_ PLOG_MANAGER LogManager,
    _In_ PLOG_FILTER_RULE Rule
);

NTSTATUS LogManager_UpdateFilterRule(
    _In_ PLOG_MANAGER LogManager,
    _In_ PLOG_FILTER_RULE Rule
);

NTSTATUS LogManager_DeleteFilterRule(
    _In_ PLOG_MANAGER LogManager,
    _In_ ULONG RuleId
);

NTSTATUS LogManager_GetFilterRules(
    _In_ PLOG_MANAGER LogManager,
    _Out_ PLOG_FILTER_RULE* Rules,
    _Out_ PULONG Count
);

// 检查过滤规则
NTSTATUS LogManager_CheckFilterRules(
    _In_ PLOG_MANAGER LogManager,
    _In_ PSECURITY_LOG_ENTRY LogEntry,
    _Out_ PULONG Action
);

// 导出日志到文件
NTSTATUS LogManager_ExportToFile(
    _In_ PLOG_MANAGER LogManager,
    _In_ PLOG_QUERY_CONDITION Condition,
    _In_ PCWSTR FilePath,
    _In_ ULONG Format  // 0=JSON, 1=CSV, 2=XML
);

// 导入日志从文件
NTSTATUS LogManager_ImportFromFile(
    _In_ PLOG_MANAGER LogManager,
    _In_ PCWSTR FilePath,
    _In_ ULONG Format
);

// 数据库维护（清理、优化）
NTSTATUS LogManager_PerformMaintenance(
    _In_ PLOG_MANAGER LogManager
);

// 设置日志保留策略
NTSTATUS LogManager_SetRetentionPolicy(
    _In_ PLOG_MANAGER LogManager,
    _In_ ULONG RetentionDays,
    _In_ ULONG MaxDatabaseSizeMB
);

// 获取数据库文件大小
NTSTATUS LogManager_GetDatabaseSize(
    _In_ PLOG_MANAGER LogManager,
    _Out_ PULONGLONG SizeBytes
);

// 压缩数据库
NTSTATUS LogManager_VacuumDatabase(
    _In_ PLOG_MANAGER LogManager
);

// 辅助函数：事件类型转字符串
PCWSTR LogManager_EventTypeToString(
    _In_ ULONG EventType
);

// 辅助函数：威胁等级转字符串
PCWSTR LogManager_ThreatLevelToString(
    _In_ ULONG ThreatLevel
);

// 辅助函数：将日志条目转换为JSON
NTSTATUS LogManager_LogEntryToJson(
    _In_ PSECURITY_LOG_ENTRY LogEntry,
    _Out_ PCHAR* JsonBuffer,
    _Out_ PULONG BufferSize
);
