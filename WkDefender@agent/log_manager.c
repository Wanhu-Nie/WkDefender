#include "log_manager.h"
#include <sqlite3.h>
#include <string.h>
#include <time.h>
#include "Notification/msg_queue.h"

// 全局日志管理器实例
LOG_MANAGER g_LogManager = { 0 };

// SQL语句定义
#define SQL_CREATE_TABLE_LOGS \
    "CREATE TABLE IF NOT EXISTS " TABLE_SECURITY_LOGS " (" \
    "id INTEGER PRIMARY KEY AUTOINCREMENT," \
    "timestamp INTEGER NOT NULL," \
    "event_type INTEGER NOT NULL," \
    "process_id INTEGER NOT NULL," \
    "process_name TEXT," \
    "parent_process_id INTEGER," \
    "parent_process_name TEXT," \
    "threat_level INTEGER NOT NULL DEFAULT 0," \
    "image_path TEXT," \
    "details TEXT," \
    "is_read INTEGER DEFAULT 0," \
    "is_archived INTEGER DEFAULT 0," \
    "created_at INTEGER DEFAULT 0" \
    ")"

#define SQL_CREATE_TABLE_RULES \
    "CREATE TABLE IF NOT EXISTS " TABLE_FILTER_RULES " (" \
    "rule_id INTEGER PRIMARY KEY AUTOINCREMENT," \
    "rule_name TEXT NOT NULL," \
    "event_type_filter INTEGER DEFAULT 0," \
    "min_threat_level INTEGER DEFAULT 0," \
    "process_name_filter TEXT," \
    "path_filter TEXT," \
    "is_enabled INTEGER DEFAULT 1," \
    "action INTEGER DEFAULT 0," \
    "description TEXT," \
    "created_at INTEGER DEFAULT 0," \
    "updated_at INTEGER DEFAULT 0" \
    ")"

#define SQL_CREATE_INDEX_TIMESTAMP \
    "CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON " TABLE_SECURITY_LOGS " (timestamp)"

#define SQL_CREATE_INDEX_EVENT_TYPE \
    "CREATE INDEX IF NOT EXISTS idx_logs_event_type ON " TABLE_SECURITY_LOGS " (event_type)"

#define SQL_CREATE_INDEX_THREAT_LEVEL \
    "CREATE INDEX IF NOT EXISTS idx_logs_threat_level ON " TABLE_SECURITY_LOGS " (threat_level)"

#define SQL_CREATE_INDEX_PROCESS_ID \
    "CREATE INDEX IF NOT EXISTS idx_logs_process_id ON " TABLE_SECURITY_LOGS " (process_id)"

#define SQL_CREATE_INDEX_IS_READ \
    "CREATE INDEX IF NOT EXISTS idx_logs_is_read ON " TABLE_SECURITY_LOGS " (is_read)"

// 初始化日志管理器（自注册模式）
NTSTATUS LogManager_InitializeService(
    _Out_ PLOG_MANAGER LogManager,
    _In_ PCWSTR DatabasePath,
    _In_opt_ PWKD_ALPC_SERVER AlpcServer
)
{
    NTSTATUS status;

    if (DatabasePath == NULL || LogManager == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    UNREFERENCED_PARAMETER(AlpcServer);  /* 保留，日志模块暂不注册路由 */

    printf("[LogManager] Initializing service...\n");

    // 初始化临界区
    InitializeCriticalSection(&LogManager->Lock);

    // 复制数据库路径
    wcsncpy_s(LogManager->DatabasePath, MAX_PATH, DatabasePath, _TRUNCATE);

    // 打开数据库
    status = LogManager_OpenDatabase(LogManager, DatabasePath);
    if (!NT_SUCCESS(status)) {
        printf("[LogManager] Failed to open database: 0x%X\n", status);
        DeleteCriticalSection(&LogManager->Lock);
        return status;
    }

    // 初始化表结构
    status = LogManager_InitDatabaseSchema(LogManager);
    if (!NT_SUCCESS(status)) {
        printf("[LogManager] Failed to initialize database schema: 0x%X\n", status);
        LogManager_CloseDatabase(LogManager);
        DeleteCriticalSection(&LogManager->Lock);
        return status;
    }

    // 初始化统计信息
    LogManager_GetStatistics(LogManager, &LogManager->TotalLogs,
        &LogManager->UnreadLogs, &LogManager->ThreatLogs);

    // 设置默认保留策略
    LogManager->RetentionDays = 30;
    LogManager->MaxDatabaseSizeMB = 1024;

    // 初始化消息队列（不启动线程，StartAllModules 阶段统一启动）
    status = NtfInitializeMessageQueueMessageQueue(&LogManager->MessageQueue, WKD_MSG_QUEUE_MAX_SIZE, NULL, LogManager);
    if (!NT_SUCCESS(status)) {
        printf("[LogManager] Failed to initialize message queue: 0x%X\n", status);
        LogManager_CloseDatabase(LogManager);
        DeleteCriticalSection(&LogManager->Lock);
        return status;
    }

    LogManager->Initialized = TRUE;
    LogManager->MaintenanceRunning = FALSE;
    LogManager->MaintenanceThread = NULL;

    printf("[LogManager] Service initialized successfully. Total logs: %lld\n", LogManager->TotalLogs);
    return STATUS_SUCCESS;
}

// 清理日志管理器
VOID LogManager_Cleanup(
    _In_ PLOG_MANAGER LogManager
)
{
    if (LogManager == NULL || !LogManager->Initialized) {
        return;
    }

    printf("[LogManager] Cleaning up log manager...\n");

    // 停止维护线程
    LogManager->MaintenanceRunning = FALSE;
    if (LogManager->MaintenanceThread != NULL) {
        WaitForSingleObject(LogManager->MaintenanceThread, 5000);
        CloseHandle(LogManager->MaintenanceThread);
        LogManager->MaintenanceThread = NULL;
    }

    // 清理消息队列
    WkdMsgQueueStopProcessing(&LogManager->MessageQueue);
    WkdMsgQueueCleanup(&LogManager->MessageQueue);

    // 关闭数据库
    LogManager_CloseDatabase(LogManager);

    // 删除临界区
    DeleteCriticalSection(&LogManager->Lock);

    LogManager->Initialized = FALSE;

    printf("[LogManager] Log manager cleanup completed\n");
}

// 打开数据库连接
NTSTATUS LogManager_OpenDatabase(
    _In_ PLOG_MANAGER LogManager,
    _In_ PCWSTR DatabasePath
)
{
    int rc;
    char* pathUtf8 = NULL;
    int pathLen;

    if (LogManager == NULL || DatabasePath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // 转换路径为UTF-8
    pathLen = WideCharToMultiByte(CP_UTF8, 0, DatabasePath, -1, NULL, 0, NULL, NULL);
    if (pathLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    pathUtf8 = (char*)UtHeapAlloc(pathLen);
    if (pathUtf8 == NULL) {
        return STATUS_NO_MEMORY;
    }

    WideCharToMultiByte(CP_UTF8, 0, DatabasePath, -1, pathUtf8, pathLen, NULL, NULL);

    // 打开数据库
    rc = sqlite3_open(pathUtf8, &LogManager->Database);

    UtHeapFree(pathUtf8);

    if (rc != SQLITE_OK) {
        printf("[LogManager] Failed to open database: %s\n", sqlite3_errmsg(LogManager->Database));
        return STATUS_UNSUCCESSFUL;
    }

    // 启用外键约束
    sqlite3_exec(LogManager->Database, "PRAGMA foreign_keys = ON", NULL, NULL, NULL);

    // 设置同步模式为NORMAL（平衡性能和安全性）
    sqlite3_exec(LogManager->Database, "PRAGMA synchronous = NORMAL", NULL, NULL, NULL);

    // 设置日志模式为WAL（提高并发性能）
    sqlite3_exec(LogManager->Database, "PRAGMA journal_mode = WAL", NULL, NULL, NULL);

    printf("[LogManager] Database opened successfully\n");
    return STATUS_SUCCESS;
}

// 关闭数据库连接
VOID LogManager_CloseDatabase(
    _In_ PLOG_MANAGER LogManager
)
{
    if (LogManager == NULL || LogManager->Database == NULL) {
        return;
    }

    sqlite3_close(LogManager->Database);
    LogManager->Database = NULL;

    printf("[LogManager] Database closed\n");
}

// 初始化数据库表结构
NTSTATUS LogManager_InitDatabaseSchema(
    _In_ PLOG_MANAGER LogManager
)
{
    int rc;
    char* errMsg = NULL;

    if (LogManager == NULL || LogManager->Database == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    EnterCriticalSection(&LogManager->Lock);

    // 创建日志表
    rc = sqlite3_exec(LogManager->Database, SQL_CREATE_TABLE_LOGS, NULL, NULL, &errMsg);
    if (rc != SQLITE_OK) {
        printf("[LogManager] Failed to create logs table: %s\n", errMsg);
        sqlite3_free(errMsg);
        LeaveCriticalSection(&LogManager->Lock);
        return STATUS_UNSUCCESSFUL;
    }

    // 创建过滤规则表
    rc = sqlite3_exec(LogManager->Database, SQL_CREATE_TABLE_RULES, NULL, NULL, &errMsg);
    if (rc != SQLITE_OK) {
        printf("[LogManager] Failed to create rules table: %s\n", errMsg);
        sqlite3_free(errMsg);
        LeaveCriticalSection(&LogManager->Lock);
        return STATUS_UNSUCCESSFUL;
    }

    // 创建索引
    sqlite3_exec(LogManager->Database, SQL_CREATE_INDEX_TIMESTAMP, NULL, NULL, NULL);
    sqlite3_exec(LogManager->Database, SQL_CREATE_INDEX_EVENT_TYPE, NULL, NULL, NULL);
    sqlite3_exec(LogManager->Database, SQL_CREATE_INDEX_THREAT_LEVEL, NULL, NULL, NULL);
    sqlite3_exec(LogManager->Database, SQL_CREATE_INDEX_PROCESS_ID, NULL, NULL, NULL);
    sqlite3_exec(LogManager->Database, SQL_CREATE_INDEX_IS_READ, NULL, NULL, NULL);

    LeaveCriticalSection(&LogManager->Lock);

    printf("[LogManager] Database schema initialized\n");
    return STATUS_SUCCESS;
}

// 写入安全日志
NTSTATUS LogManager_WriteLog(
    _In_ PLOG_MANAGER LogManager,
    _In_ PSECURITY_LOG_ENTRY LogEntry
)
{
    int rc;
    sqlite3_stmt* stmt = NULL;
    const char* sql = "INSERT INTO " TABLE_SECURITY_LOGS
        " (timestamp, event_type, process_id, process_name, parent_process_id,"
        " parent_process_name, threat_level, image_path, details, is_read, is_archived, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    if (LogManager == NULL || LogEntry == NULL || LogManager->Database == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // 检查过滤规则
    ULONG action = 0;
    LogManager_CheckFilterRules(LogManager, LogEntry, &action);
    if (action == 1) { // 忽略
        return STATUS_SUCCESS;
    }

    EnterCriticalSection(&LogManager->Lock);

    // 准备SQL语句
    rc = sqlite3_prepare_v2(LogManager->Database, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("[LogManager] Failed to prepare statement: %s\n", sqlite3_errmsg(LogManager->Database));
        LeaveCriticalSection(&LogManager->Lock);
        return STATUS_UNSUCCESSFUL;
    }

    // 绑定参数
    sqlite3_bind_int64(stmt, 1, LogEntry->Timestamp.QuadPart);
    sqlite3_bind_int(stmt, 2, LogEntry->EventType);
    sqlite3_bind_int(stmt, 3, LogEntry->ProcessId);
    sqlite3_bind_text16(stmt, 4, LogEntry->ProcessName, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, LogEntry->ParentProcessId);
    sqlite3_bind_text16(stmt, 6, LogEntry->ParentProcessName, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 7, LogEntry->ThreatLevel);
    sqlite3_bind_text16(stmt, 8, LogEntry->ImagePath, -1, SQLITE_STATIC);
    sqlite3_bind_text16(stmt, 9, LogEntry->Details, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 10, LogEntry->IsRead ? 1 : 0);
    sqlite3_bind_int(stmt, 11, LogEntry->IsArchived ? 1 : 0);
    sqlite3_bind_int64(stmt, 12, LogEntry->CreatedAt.QuadPart);

    // 执行插入
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        printf("[LogManager] Failed to insert log: %s\n", sqlite3_errmsg(LogManager->Database));
        LeaveCriticalSection(&LogManager->Lock);
        return STATUS_UNSUCCESSFUL;
    }

    // 更新统计信息
    LogEntry->Id = sqlite3_last_insert_rowid(LogManager->Database);
    LogManager->TotalLogs++;
    if (!LogEntry->IsRead) {
        LogManager->UnreadLogs++;
    }
    if (LogEntry->ThreatLevel >= LOG_THREAT_MEDIUM) {
        LogManager->ThreatLogs++;
    }

    LeaveCriticalSection(&LogManager->Lock);

    printf("[LogManager] Log written: ID=%lld, Type=%u, PID=%u, Threat=%u\n",
        LogEntry->Id, LogEntry->EventType, LogEntry->ProcessId, LogEntry->ThreatLevel);

    return STATUS_SUCCESS;
}

// 从进程节点写入日志（2026-08-15 进程域: WKD_PROCESS）
NTSTATUS LogManager_WriteProcessLog(
    _In_ PLOG_MANAGER LogManager,
    _In_ PWKD_PROCESS ProcessNode,
    _In_ ULONG EventType,
    _In_ ULONG ThreatLevel,
    _In_ PCWSTR Details
)
{
    SECURITY_LOG_ENTRY logEntry;

    if (LogManager == NULL || ProcessNode == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    memset(&logEntry, 0, sizeof(SECURITY_LOG_ENTRY));

    logEntry.Timestamp = ProcessNode->CreateTime;
    logEntry.EventType = EventType;
    logEntry.ProcessId = (HANDLE)(ULONG_PTR)ProcessNode->ProcessId;
    if (ProcessNode->ImageFileName && ProcessNode->ImageFileName->Buffer)
        wcsncpy_s(logEntry.ProcessName, 259, ProcessNode->ImageFileName->Buffer, _TRUNCATE);
    logEntry.ParentProcessId = (HANDLE)(ULONG_PTR)ProcessNode->ParentProcessId;
    wcsncpy_s(logEntry.ParentProcessName, 259, ProcessNode->ParentImageName, _TRUNCATE);
    logEntry.ThreatLevel = ThreatLevel;
    if (ProcessNode->ImagePath && ProcessNode->ImagePath->Buffer)
        wcsncpy_s(logEntry.ImagePath, 259, ProcessNode->ImagePath->Buffer, _TRUNCATE);

    if (Details != NULL) {
        wcsncpy_s(logEntry.Details, 2048, Details, _TRUNCATE);
    } else {
        // 构建默认详细信息（JSON格式; handle_count/memory_usage 字段已删除 2026-08-15）
        swprintf(logEntry.Details, 2048,
            L"{\"thread_count\":%u,\"handle_count\":0,\"memory_usage\":0,\"suspicious_count\":%u}",
            /* 2026-08-23 进程域 Context 惰性申请: 不持锁裸读 volatile 允许近似计数 */
            ProcessNode->ThreadContext ? ProcessNode->ThreadContext->ActiveThreads : 0,
            ProcessNode->SuspiciousBehaviorCount);
    }

    logEntry.IsRead = FALSE;
    logEntry.IsArchived = FALSE;
    GetSystemTimeAsFileTime((PFILETIME)&logEntry.CreatedAt);

    return LogManager_WriteLog(LogManager, &logEntry);
}

// 获取日志统计信息
NTSTATUS LogManager_GetStatistics(
    _In_ PLOG_MANAGER LogManager,
    _Out_ PLONGLONG TotalLogs,
    _Out_ PLONGLONG UnreadLogs,
    _Out_ PLONGLONG ThreatLogs
)
{
    int rc;
    sqlite3_stmt* stmt = NULL;

    if (LogManager == NULL || LogManager->Database == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    EnterCriticalSection(&LogManager->Lock);

    // 获取总日志数
    rc = sqlite3_prepare_v2(LogManager->Database,
        "SELECT COUNT(*) FROM " TABLE_SECURITY_LOGS, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            *TotalLogs = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    // 获取未读日志数
    rc = sqlite3_prepare_v2(LogManager->Database,
        "SELECT COUNT(*) FROM " TABLE_SECURITY_LOGS " WHERE is_read = 0", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            *UnreadLogs = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    // 获取威胁日志数
    rc = sqlite3_prepare_v2(LogManager->Database,
        "SELECT COUNT(*) FROM " TABLE_SECURITY_LOGS " WHERE threat_level >= 2", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            *ThreatLogs = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    LeaveCriticalSection(&LogManager->Lock);

    return STATUS_SUCCESS;
}

// 辅助函数：事件类型转字符串
PCWSTR LogManager_EventTypeToString(
    _In_ ULONG EventType
)
{
    switch (EventType) {
    case EVENT_TYPE_PROCESS_CREATE: return L"ProcessCreate";
    case EVENT_TYPE_PROCESS_EXIT: return L"ProcessExit";
    case EVENT_TYPE_THREAD_CREATE: return L"ThreadCreate";
    case EVENT_TYPE_THREAD_EXIT: return L"ThreadExit";
    case EVENT_TYPE_API_CALL: return L"ApiCall";
    case EVENT_TYPE_MODULE_LOAD: return L"ModuleLoad";
    case EVENT_TYPE_REGISTRY_ACCESS: return L"RegistryAccess";
    case EVENT_TYPE_FILE_ACCESS: return L"FileAccess";
    case EVENT_TYPE_NETWORK_CONNECTION: return L"NetworkConnection";
    case EVENT_TYPE_THREAT_DETECTED: return L"ThreatDetected";
    case EVENT_TYPE_BEHAVIOR_BLOCKED: return L"BehaviorBlocked";
    case EVENT_TYPE_ISOLATION_TRIGGERED: return L"IsolationTriggered";
    default: return L"Unknown";
    }
}

// 辅助函数：威胁等级转字符串
PCWSTR LogManager_ThreatLevelToString(
    _In_ ULONG ThreatLevel
)
{
    switch (ThreatLevel) {
    case LOG_THREAT_NORMAL: return L"Normal";
    case LOG_THREAT_LOW: return L"Low";
    case LOG_THREAT_MEDIUM: return L"Medium";
    case LOG_THREAT_HIGH: return L"High";
    case LOG_THREAT_CRITICAL: return L"Critical";
    default: return L"Unknown";
    }
}

// 其他函数实现（简化版本，可以根据需要扩展）

// 查询日志
NTSTATUS LogManager_QueryLogs(
    _In_ PLOG_MANAGER LogManager,
    _In_ PLOG_QUERY_CONDITION Condition,
    _In_ LOG_QUERY_CALLBACK Callback,
    _In_opt_ PVOID Context
)
{
    // 简化实现，完整实现需要构建动态SQL查询
    return STATUS_NOT_IMPLEMENTED;
}

// 根据ID获取单条日志
NTSTATUS LogManager_GetLogById(
    _In_ PLOG_MANAGER LogManager,
    _In_ LONGLONG LogId,
    _Out_ PSECURITY_LOG_ENTRY LogEntry
)
{
    int rc;
    sqlite3_stmt* stmt = NULL;
    const char* sql = "SELECT * FROM " TABLE_SECURITY_LOGS " WHERE id = ?";

    if (LogManager == NULL || LogEntry == NULL || LogManager->Database == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    EnterCriticalSection(&LogManager->Lock);

    rc = sqlite3_prepare_v2(LogManager->Database, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LeaveCriticalSection(&LogManager->Lock);
        return STATUS_UNSUCCESSFUL;
    }

    sqlite3_bind_int64(stmt, 1, LogId);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        LogEntry->Id = sqlite3_column_int64(stmt, 0);
        LogEntry->Timestamp.QuadPart = sqlite3_column_int64(stmt, 1);
        LogEntry->EventType = sqlite3_column_int(stmt, 2);
        LogEntry->ProcessId = sqlite3_column_int(stmt, 3);
        wcsncpy_s(LogEntry->ProcessName, 260, (PCWSTR)sqlite3_column_text16(stmt, 4), _TRUNCATE);
        LogEntry->ParentProcessId = sqlite3_column_int(stmt, 5);
        wcsncpy_s(LogEntry->ParentProcessName, 260, (PCWSTR)sqlite3_column_text16(stmt, 6), _TRUNCATE);
        LogEntry->ThreatLevel = sqlite3_column_int(stmt, 7);
        wcsncpy_s(LogEntry->ImagePath, 260, (PCWSTR)sqlite3_column_text16(stmt, 8), _TRUNCATE);
        wcsncpy_s(LogEntry->Details, 2048, (PCWSTR)sqlite3_column_text16(stmt, 9), _TRUNCATE);
        LogEntry->IsRead = sqlite3_column_int(stmt, 10) != 0;
        LogEntry->IsArchived = sqlite3_column_int(stmt, 11) != 0;
        LogEntry->CreatedAt.QuadPart = sqlite3_column_int64(stmt, 12);
    }

    sqlite3_finalize(stmt);
    LeaveCriticalSection(&LogManager->Lock);

    return (rc == SQLITE_ROW) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

// 标记日志为已读
NTSTATUS LogManager_MarkAsRead(
    _In_ PLOG_MANAGER LogManager,
    _In_ LONGLONG LogId
)
{
    int rc;
    char sql[256];

    if (LogManager == NULL || LogManager->Database == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    sprintf_s(sql, sizeof(sql), "UPDATE " TABLE_SECURITY_LOGS " SET is_read = 1 WHERE id = %lld", LogId);

    EnterCriticalSection(&LogManager->Lock);
    rc = sqlite3_exec(LogManager->Database, sql, NULL, NULL, NULL);
    LeaveCriticalSection(&LogManager->Lock);

    return (rc == SQLITE_OK) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

// 删除指定时间之前的日志
NTSTATUS LogManager_DeleteLogsBefore(
    _In_ PLOG_MANAGER LogManager,
    _In_ LARGE_INTEGER Timestamp
)
{
    int rc;
    sqlite3_stmt* stmt = NULL;
    const char* sql = "DELETE FROM " TABLE_SECURITY_LOGS " WHERE timestamp < ?";

    if (LogManager == NULL || LogManager->Database == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    EnterCriticalSection(&LogManager->Lock);

    rc = sqlite3_prepare_v2(LogManager->Database, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LeaveCriticalSection(&LogManager->Lock);
        return STATUS_UNSUCCESSFUL;
    }

    sqlite3_bind_int64(stmt, 1, Timestamp.QuadPart);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    LeaveCriticalSection(&LogManager->Lock);

    printf("[LogManager] Deleted logs before timestamp: %lld\n", Timestamp.QuadPart);

    return (rc == SQLITE_DONE) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

// 执行数据库维护
NTSTATUS LogManager_PerformMaintenance(
    _In_ PLOG_MANAGER LogManager
)
{
    int rc;

    if (LogManager == NULL || LogManager->Database == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    printf("[LogManager] Performing database maintenance...\n");

    EnterCriticalSection(&LogManager->Lock);

    // 清理已归档的旧日志
    LARGE_INTEGER cutoffTime;
    FILETIME fileTime;
    GetSystemTimeAsFileTime(&fileTime);
    cutoffTime.LowPart = fileTime.dwLowDateTime;
    cutoffTime.HighPart = fileTime.dwHighDateTime;
    cutoffTime.QuadPart -= (LONGLONG)LogManager->RetentionDays * 24 * 60 * 60 * 10000000LL; // 转换为100纳秒单位

    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(LogManager->Database,
        "DELETE FROM " TABLE_SECURITY_LOGS " WHERE is_archived = 1 AND timestamp < ?", -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, cutoffTime.QuadPart);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // 优化数据库
    sqlite3_exec(LogManager->Database, "VACUUM", NULL, NULL, NULL);
    sqlite3_exec(LogManager->Database, "ANALYZE", NULL, NULL, NULL);

    LeaveCriticalSection(&LogManager->Lock);

    printf("[LogManager] Database maintenance completed\n");

    return STATUS_SUCCESS;
}

// 检查过滤规则
NTSTATUS LogManager_CheckFilterRules(
    _In_ PLOG_MANAGER LogManager,
    _In_ PSECURITY_LOG_ENTRY LogEntry,
    _Out_ PULONG Action
)
{
    // 简化实现，默认记录所有日志
    if (Action != NULL) {
        *Action = 0; // 记录
    }
    return STATUS_SUCCESS;
}
