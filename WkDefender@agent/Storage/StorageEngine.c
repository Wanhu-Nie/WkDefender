/**************************************************/
/*  WkDefender 分层存储引擎实现                      */
/*  Hot(内存LRU) / Warm(SQLite WAL) / Cold(归档)   */
/**************************************************/

#include "StorageEngine.h"
#include "../IOA/IoaTypes.h"
#include "../IOA/IoaPersistQueue.h"
#include "../Notification/EventTypes.h"
#include "../Notification/EventArchive.h"
#include "../IOC/IocMatcher.h"   /* StUpsertIocHash 布隆同步 (SS FileReputation 黑名单) */
#include "../Common/Utils.h"     /* UtHeapAlloc/UtHeapFree/UtHexEncode/UtHexDecode (Exempts 重构 #67) */
#include <sqlite3.h>
#include <string.h>            /* strncpy_s/strnlen (SS FileReputation 迁移) */
#include <time.h>                /* time() (file_reputation 时间戳, SS FileReputation 迁移) */

STORAGE_ENGINE WkdStorageEngine = { 0 };

/**************************************************/
/*               SQLite Schema 创建                 */
/**************************************************/

static NTSTATUS
StCreateSchema(_In_ sqlite3* Db)
{
    char* errMsg = NULL;
    const char* schemas[] = {
        "CREATE TABLE IF NOT EXISTS cg_nodes ("
        "  node_id BLOB PRIMARY KEY, node_type INTEGER NOT NULL,"
        "  pid INTEGER, create_time INTEGER NOT NULL, exit_time INTEGER DEFAULT 0,"
        "  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,"
        "  parent_node_id BLOB, integrity_level INTEGER, session_id INTEGER,"
        "  image_path TEXT, command_line TEXT, behavior_flags INTEGER DEFAULT 0,"
        "  risk_score INTEGER DEFAULT 0, ioc_verdict INTEGER DEFAULT 0,"
        "  is_root INTEGER DEFAULT 0)",

        "CREATE TABLE IF NOT EXISTS cg_edges ("
        "  edge_id BLOB PRIMARY KEY, edge_type INTEGER NOT NULL,"
        "  event_class INTEGER NOT NULL, src_node_id BLOB NOT NULL,"
        "  tgt_node_id BLOB NOT NULL, first_seen INTEGER NOT NULL,"
        "  last_seen INTEGER NOT NULL, occurrence_count INTEGER DEFAULT 1,"
        "  confidence INTEGER DEFAULT 1000, weight INTEGER DEFAULT 0,"
        "  behavior_flags INTEGER DEFAULT 0)",

        "CREATE TABLE IF NOT EXISTS cg_events ("
        "  event_id BLOB PRIMARY KEY, event_type INTEGER NOT NULL,"
        "  event_class INTEGER NOT NULL, timestamp INTEGER NOT NULL,"
        "  src_process_id BLOB, tgt_process_id BLOB,"
        "  confidence INTEGER DEFAULT 1000, severity INTEGER DEFAULT 0,"
        "  payload BLOB)",

        DEF_SQL_ALERTS,
        DEF_SQL_IOC_HASHES,
        DEF_SQL_IOC_CERTS,
        DEF_SQL_YARA_RULES,
        DEF_SQL_FILE_REPUTATION,   /* SS FileReputation 迁移, 2026-08-06 */
        DEF_SQL_CERT_REPUTATION,   /* SS 证书信任管理迁移, 2026-08-06 */
        DEF_SQL_DEVICE_HISTORY,    /* SS MountPointMonitor 迁移 2026-08, ※死代码预留 (MountPointMonitor 历史主体在内存) */
        DEF_SQL_DEVICE_WHITELIST,  /* SS MountPointMonitor 迁移 2026-08, ※死代码预留 (白名单主体在内存) */
        DEF_SQL_EXEMPT_RULES,      /* Exempts 重构 2026-08-14, 档案 #67 */

        "CREATE INDEX IF NOT EXISTS idx_nodes_pid ON cg_nodes(pid, create_time)",
        "CREATE INDEX IF NOT EXISTS idx_edges_src ON cg_edges(src_node_id, last_seen)",
        "CREATE INDEX IF NOT EXISTS idx_edges_tgt ON cg_edges(tgt_node_id, last_seen)",
        "CREATE INDEX IF NOT EXISTS idx_events_time ON cg_events(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_time ON cg_alerts(timestamp)",
        NULL
    };

    for (int i = 0; schemas[i]; i++) {
        sqlite3_exec(Db, schemas[i], NULL, NULL, &errMsg);
        if (errMsg) { printf("[Storage] Schema err: %s\n", errMsg); sqlite3_free(errMsg); }
    }

    /* 迁移：为旧版 yara_rules 表补充新列（不存在则 ADD，忽略重复列错误） */
    const char* migrations[] = {
        "ALTER TABLE yara_rules ADD COLUMN compiled_rule BLOB",
        "ALTER TABLE yara_rules ADD COLUMN threat_level INTEGER DEFAULT 2",
        "ALTER TABLE yara_rules ADD COLUMN author TEXT",
        "ALTER TABLE yara_rules ADD COLUMN description TEXT",
        "ALTER TABLE yara_rules ADD COLUMN tags TEXT",
        "ALTER TABLE yara_rules ADD COLUMN hit_count INTEGER DEFAULT 0",
        "ALTER TABLE yara_rules ADD COLUMN last_modified INTEGER DEFAULT (unixepoch())",
        /* VerdictEngine 扩展列 (ThreatDetector 迁移, 2026-08-04):
         * 旧库补齐 Verdict 投影字段, 已有新库忽略重复列错误 */
        "ALTER TABLE cg_alerts ADD COLUMN category INTEGER DEFAULT 0",
        "ALTER TABLE cg_alerts ADD COLUMN confidence_level INTEGER DEFAULT 0",
        "ALTER TABLE cg_alerts ADD COLUMN recommended_action INTEGER DEFAULT 0",
        "ALTER TABLE cg_alerts ADD COLUMN detection_source INTEGER DEFAULT 0",
        /* SS FileReputation 黑名单管理迁移, 2026-08-06: ioc_hashes 补威胁名列
         * (对齐 SS AddToBlacklist hash→threatName) */
        "ALTER TABLE ioc_hashes ADD COLUMN threat_name TEXT",
        NULL
    };
    for (int i = 0; migrations[i]; i++) {
        int rc = sqlite3_exec(Db, migrations[i], NULL, NULL, &errMsg);
        if (rc != SQLITE_OK && errMsg) {
            /* 重复列错误（SQLITE_ERROR 1）属于正常迁移场景，不打印 */
            if (rc != SQLITE_ERROR) {
                printf("[Storage] Migration warn: %s\n", errMsg);
            }
            sqlite3_free(errMsg); errMsg = NULL;
        }
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*               打开数据库                         */
/**************************************************/

static NTSTATUS
StOpenDb(_In_ PCWSTR Path, _Out_ sqlite3** Db, _In_ BOOLEAN Wal)
{
    char utf8Path[512] = { 0 };
    WideCharToMultiByte(CP_UTF8, 0, Path, -1, utf8Path, sizeof(utf8Path), NULL, NULL);

    if (sqlite3_open_v2(utf8Path, Db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
        printf("[Storage] Cannot open: %s\n", sqlite3_errmsg(*Db));
        return STATUS_UNSUCCESSFUL;
    }
    if (Wal) sqlite3_exec(*Db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    sqlite3_exec(*Db, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);
    return STATUS_SUCCESS;
}

/**************************************************/
/*               热缓存实现                         */
/**************************************************/

static VOID StHotEvict(PSTORAGE_ENGINE Mgr)
{
    ULONG oldestIdx = 0;
    LARGE_INTEGER oldestTime = Mgr->HotCache.Entries[0].LastAccess;
    for (ULONG i = 1; i < Mgr->HotCache.Count; i++) {
        if (Mgr->HotCache.Entries[i].LastAccess.QuadPart < oldestTime.QuadPart) {
            oldestTime = Mgr->HotCache.Entries[i].LastAccess; oldestIdx = i;
        }
    }
    if (Mgr->HotCache.Entries[oldestIdx].Data && !Mgr->HotCache.Entries[oldestIdx].PointerMode)
        UtHeapFree(Mgr->HotCache.Entries[oldestIdx].Data);
    if (oldestIdx < Mgr->HotCache.Count - 1)
        memmove(&Mgr->HotCache.Entries[oldestIdx], &Mgr->HotCache.Entries[oldestIdx + 1],
                (Mgr->HotCache.Count - oldestIdx - 1) * sizeof(DEF_HOT_CACHE_ENTRY));
    Mgr->HotCache.Count--;
}

NTSTATUS StHotPut(GUID NodeId, DEF_NODE_TYPE NodeType, PVOID Data, ULONG DataSize)
{
    LARGE_INTEGER now; LARGE_INTEGER ttl; PVOID copy; BOOLEAN ptrMode = (DataSize == 0);
    if (!Data && !ptrMode) return STATUS_INVALID_PARAMETER;

    if (!ptrMode) {
        copy = UtHeapAlloc(DataSize);
        if (!copy) return STATUS_NO_MEMORY;
        memcpy(copy, Data, DataSize);
    } else { copy = Data; }

    EnterCriticalSection(&WkdStorageEngine.HotCache.Lock);
    while (WkdStorageEngine.HotCache.Count >= WkdStorageEngine.HotCache.Capacity)
        StHotEvict(&WkdStorageEngine);
    GetSystemTimeAsFileTime((PFILETIME)&now);
    ttl.QuadPart = now.QuadPart + (LONGLONG)DEF_HOT_CACHE_TTL_MS * 10000;

    PDEF_HOT_CACHE_ENTRY e = &WkdStorageEngine.HotCache.Entries[WkdStorageEngine.HotCache.Count];
    e->NodeId = NodeId; e->NodeType = NodeType; e->LastAccess = now;
    e->ExpiryTime = ttl; e->Data = copy; e->DataSize = DataSize;
    e->Dirty = FALSE; e->PointerMode = ptrMode;
    WkdStorageEngine.HotCache.Count++;
    LeaveCriticalSection(&WkdStorageEngine.HotCache.Lock);
    return STATUS_SUCCESS;
}

PVOID StHotGet(GUID NodeId)
{
    LARGE_INTEGER now;
    EnterCriticalSection(&WkdStorageEngine.HotCache.Lock);
    GetSystemTimeAsFileTime((PFILETIME)&now);
    for (ULONG i = 0; i < WkdStorageEngine.HotCache.Count; i++) {
        if (DefGuidEqual(&WkdStorageEngine.HotCache.Entries[i].NodeId, &NodeId)) {
            if (WkdStorageEngine.HotCache.Entries[i].ExpiryTime.QuadPart < now.QuadPart) {
                LeaveCriticalSection(&WkdStorageEngine.HotCache.Lock); WkdStorageEngine.HotMisses++; return NULL;
            }
            WkdStorageEngine.HotCache.Entries[i].LastAccess = now; WkdStorageEngine.HotHits++;
            LeaveCriticalSection(&WkdStorageEngine.HotCache.Lock);
            return WkdStorageEngine.HotCache.Entries[i].Data;
        }
    }
    LeaveCriticalSection(&WkdStorageEngine.HotCache.Lock); WkdStorageEngine.HotMisses++; return NULL;
}

NTSTATUS StHotRemove(GUID NodeId)
{
    EnterCriticalSection(&WkdStorageEngine.HotCache.Lock);
    for (ULONG i = 0; i < WkdStorageEngine.HotCache.Count; i++) {
        if (DefGuidEqual(&WkdStorageEngine.HotCache.Entries[i].NodeId, &NodeId)) {
            if (WkdStorageEngine.HotCache.Entries[i].Data && !WkdStorageEngine.HotCache.Entries[i].PointerMode)
                UtHeapFree(WkdStorageEngine.HotCache.Entries[i].Data);
            if (i < WkdStorageEngine.HotCache.Count - 1)
                memmove(&WkdStorageEngine.HotCache.Entries[i], &WkdStorageEngine.HotCache.Entries[i + 1],
                        (WkdStorageEngine.HotCache.Count - i - 1) * sizeof(DEF_HOT_CACHE_ENTRY));
            WkdStorageEngine.HotCache.Count--;
            LeaveCriticalSection(&WkdStorageEngine.HotCache.Lock); return STATUS_SUCCESS;
        }
    }
    LeaveCriticalSection(&WkdStorageEngine.HotCache.Lock); return STATUS_NOT_FOUND;
}

/**************************************************/
/*               持久化实现                         */
/**************************************************/

static
FORCEINLINE
VOID StpGuidToBlob(GUID* id, UCHAR* blob) {
    memcpy(blob, id, 16);
}

NTSTATUS StPersistNode(PWKD_PROCESS Node)
{
    if (!WkdStorageEngine.WarmDb || !Node) return STATUS_INVALID_PARAMETER;

    const char* sql = "INSERT OR REPLACE INTO cg_nodes (node_id,node_type,pid,create_time,"
        "exit_time,first_seen,last_seen,parent_node_id,integrity_level,session_id,"
        "image_path,command_line,behavior_flags,risk_score,ioc_verdict,is_root) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    sqlite3_stmt* stmt = NULL;
    UCHAR nid[16], pid[16];
    char imgPath[DEF_MAX_PATH*2]={0}, cmdLine[DEF_MAX_COMMAND_LINE*2]={0};

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK) return STATUS_UNSUCCESSFUL;

    StpGuidToBlob(&Node->NodeId, nid);
    StpGuidToBlob(&Node->ParentNodeId, pid);

    {
        PCWSTR ip = (Node->ImagePath && Node->ImagePath->Buffer) ? Node->ImagePath->Buffer : L"";
        PCWSTR cl = (Node->CommandLine && Node->CommandLine->Buffer) ? Node->CommandLine->Buffer : L"";
        WideCharToMultiByte(CP_UTF8, 0, ip, -1, imgPath, sizeof(imgPath), NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, cl, -1, cmdLine, sizeof(cmdLine), NULL, NULL);
    }

    sqlite3_bind_blob(stmt, 1, nid, 16, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, DefNode_Process);
    sqlite3_bind_int(stmt, 3, Node->ProcessId);
    sqlite3_bind_int64(stmt, 4, Node->CreateTime.QuadPart);
    sqlite3_bind_int64(stmt, 5, Node->ExitTime.QuadPart);
    sqlite3_bind_int64(stmt, 6, Node->CreateTime.QuadPart);
    sqlite3_bind_int64(stmt, 7, Node->LastActivity.QuadPart);
    sqlite3_bind_blob(stmt, 8, pid, 16, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 9, Node->IntegrityLevel);
    sqlite3_bind_int(stmt, 10, Node->SessionId);
    sqlite3_bind_text(stmt, 11, imgPath, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 12, cmdLine, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 13, Node->BehaviorFlags);
    sqlite3_bind_int(stmt, 14, Node->CumulativeRiskScore);
    sqlite3_bind_int(stmt, 15, Node->SecCtx.IocVerdict);
    sqlite3_bind_int(stmt, 16, 0);

    sqlite3_step(stmt); sqlite3_finalize(stmt);
    WkdStorageEngine.WarmWrites++; return STATUS_SUCCESS;
}

NTSTATUS StPersistEvent(PWKD_EVENT_HEADER Event)
{
    NTSTATUS status = STATUS_SUCCESS;
    sqlite3_stmt* stmt = NULL;

    if (!WkdStorageEngine.WarmDb || !Event) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&WkdStorageEngine.Lock);

    const char* sql = "INSERT OR REPLACE INTO cg_events (event_id,event_type,event_class,"
        "timestamp,src_process_id,tgt_process_id,confidence,severity,payload) "
        "VALUES (?,?,?,?,?,?,?,?,?)";
    
    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK) {
        status =  STATUS_UNSUCCESSFUL;
        goto Return;
    }

    sqlite3_bind_blob(stmt, 1, &Event->EventId, 16, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, Event->Type);
    sqlite3_bind_int(stmt, 3, Event->Class);
    sqlite3_bind_int64(stmt, 4, Event->Timestamp.QuadPart);
    sqlite3_bind_blob(stmt, 5, &Event->SourceProcessId, 16, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 6, &Event->TargetProcessId, 16, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 7, Event->Confidence);
    sqlite3_bind_int(stmt, 8, Event->Severity);
    sqlite3_bind_blob(stmt, 9, (PUCHAR)Event + sizeof(WKD_EVENT_HEADER),
                      Event->PayloadSize, SQLITE_STATIC);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    WkdStorageEngine.WarmWrites++;
    status = STATUS_SUCCESS;

 Return:
    LeaveCriticalSection(&WkdStorageEngine.Lock);
    return status;
}

/**************************************************/
/*           Tier3 反查接口 — 从SQLite恢复历史数据    */
/**************************************************/

PVOID
StLoadNode(
    _In_ GUID NodeId
    )
/*++
Routine Description:
    从 SQLite cg_nodes 表按 GUID 恢复进程节点。
    用于 Tier3 证据锚定时恢复已从内存因果图中淘汰的节点。

    返回值: 堆分配的 WKD_PROCESS（调用方负责 UtHeapFree）。
            NULL = 未找到或失败。
--*/
{
    sqlite3_stmt* stmt = NULL;
    PWKD_PROCESS node = NULL;
    UCHAR nid[16];
    const char* sql =
        "SELECT node_type,pid,create_time,exit_time,first_seen,last_seen,"
        "parent_node_id,integrity_level,session_id,image_path,command_line,"
        "behavior_flags,risk_score,ioc_verdict,is_root "
        "FROM cg_nodes WHERE node_id=? LIMIT 1";

    if (!WkdStorageEngine.WarmDb) return NULL;

    StpGuidToBlob(&NodeId, nid);

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return NULL;

    sqlite3_bind_blob(stmt, 1, nid, 16, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        node = UtHeapAlloc(sizeof(WKD_PROCESS));
        if (!node) { sqlite3_finalize(stmt); return NULL; }
        RtlZeroMemory(node, sizeof(WKD_PROCESS));

        WkdCopyGuid(&node->NodeId, &NodeId);
        node->ProcessId = (HANDLE)(ULONG_PTR)sqlite3_column_int(stmt, 1);
        node->CreateTime.QuadPart  = sqlite3_column_int64(stmt, 2);
        node->ExitTime.QuadPart    = sqlite3_column_int64(stmt, 3);
        node->LastActivity.QuadPart  = sqlite3_column_int64(stmt, 5);

        /* ParentNodeId */
        {
            const void* blob = sqlite3_column_blob(stmt, 6);
            if (blob && sqlite3_column_bytes(stmt, 6) == 16)
                memcpy(&node->ParentNodeId, blob, 16);
        }

        node->IntegrityLevel       = sqlite3_column_int(stmt, 7);
        node->SessionId            = sqlite3_column_int(stmt, 8);
        node->BehaviorFlags        = sqlite3_column_int(stmt, 11);
        node->CumulativeRiskScore  = sqlite3_column_int(stmt, 12);
        node->SecCtx.IocVerdict    = (DEF_IOC_VERDICT)sqlite3_column_int(stmt, 13);
        node->TreeDepth            = 0; /* 从SQLite恢复时无法精确还原 */

        /* ImagePath */
        {
            const char* text = (const char*)sqlite3_column_text(stmt, 9);
            if (text) {
                int len = (int)strlen(text) + 1;
                node->ImagePath = UtHeapAlloc(sizeof(UNICODE_STRING) + len * sizeof(WCHAR));
                if (node->ImagePath) {
                    node->ImagePath->Length = (USHORT)((len - 1) * sizeof(WCHAR));
                    node->ImagePath->MaximumLength = (USHORT)(len * sizeof(WCHAR));
                    node->ImagePath->Buffer = (PWCHAR)((PUCHAR)node->ImagePath + sizeof(UNICODE_STRING));
                    MultiByteToWideChar(CP_UTF8, 0, text, -1,
                                        node->ImagePath->Buffer, len);
                }
            }
        }

        /* CommandLine */
        {
            const char* text = (const char*)sqlite3_column_text(stmt, 10);
            if (text) {
                int len = (int)strlen(text) + 1;
                node->CommandLine = UtHeapAlloc(sizeof(UNICODE_STRING) + len * sizeof(WCHAR));
                if (node->CommandLine) {
                    node->CommandLine->Length = (USHORT)((len - 1) * sizeof(WCHAR));
                    node->CommandLine->MaximumLength = (USHORT)(len * sizeof(WCHAR));
                    node->CommandLine->Buffer = (PWCHAR)((PUCHAR)node->CommandLine + sizeof(UNICODE_STRING));
                    MultiByteToWideChar(CP_UTF8, 0, text, -1,
                                        node->CommandLine->Buffer, len);
                }
            }
        }
    }

    sqlite3_finalize(stmt);
    return node;
}

NTSTATUS
StLoadEventByGuid(
    _In_  GUID               EventId,
    _Out_ PWKD_EVENT_HEADER* OutEvent
    )
/*++
Routine Description:
    从 SQLite cg_events 表按 event_id 恢复完整事件（header + payload）。
    用于 Tier3 证据反查时获取具体事件的API调用参数。

    返回值: STATUS_SUCCESS = 成功（*OutEvent 堆分配，调用方负责 UtHeapFree）。
            STATUS_NOT_FOUND = 未找到。
--*/

/*
 * ═══════════════════════════════════════════════════════════════
 *
 *  【sqlite3_stmt *stmt】
 *     预编译语句句柄。SQL 字符串先被"编译"成 stmt，然后：
 *       1. sqlite3_bind_xxx(stmt, 参数索引, 值) — 填充 SQL 中的 ? 占位符
 *       2. sqlite3_step(stmt) — 执行，返回 SQLITE_ROW（有行）或 SQLITE_DONE（结束）
 *       3. sqlite3_column_xxx(stmt, 列索引) — 读取当前行的各列
 *       4. sqlite3_finalize(stmt) — 销毁句柄，释放资源
 *St
 *  【绑定函数  sqlite3_bind_blob(stmt, idx, data, size, 标志)】
 *     第 1 个 ? 对应 idx=1（不是 0！）。
 *     第 4 个参数 SQLITE_STATIC 表示 data 指针在 stmt 生命周期内有效。
 *
 *  【列读取函数  sqlite3_column_xxx(stmt, col)】
 *     列索引从 0 开始，对应 SELECT 中列的顺序。
 *     - column_int(stmt, 0)   → 读取第 1 列为 int
 *     - column_int64(stmt, 2) → 读取第 3 列为 64 位整数
 *     - column_blob(stmt, 3)  → 读取第 4 列为二进制 blob（返回 void* 指针）
 *     - column_bytes(stmt, 7) → 读取第 8 列的字节长度（通常和 blob 配合使用）
 *
 *  【SQL 中的 ? 占位符】
 *     "WHERE event_id=?" 表示 event_id 的值由外部绑定，
 *     避免字符串拼接导致的 SQL 注入风险。
 *
 *  【GUID ↔ BLOB 转换】
 *     GUID 是 16 字节结构体。SQLite 没有 GUID 类型，
 *     所以用 BLOB(16) 存储，通过 StGuidToBlob 拷成 16 字节数组再绑定。
 * ═══════════════════════════════════════════════════════════════
 */
{
    /*
     * sqlite3_stmt* — 预编译语句句柄。
     * 相当于一个"已解析的 SQL 模板"，稍后绑定参数、执行、读结果。
     */
    sqlite3_stmt* stmt = NULL;

    /*
     * SQL 模板字符串。
     * 各列含义（column index）：
     *   0: event_type       — 事件类型枚举值（int）
     *   1: event_class      — 事件分类枚举值（int）
     *   2: timestamp        — 64 位时间戳（INTEGER）
     *   3: src_process_id   — 源进程 GUID（BLOB 16字节）
     *   4: tgt_process_id   — 目标进程 GUID（BLOB 16字节）
     *   5: confidence       — 置信度（int）
     *   6: severity         — 威胁严重度枚举值（int）
     *   7: payload          — 事件载荷（BLOB，视事件类型而异的可变长数据）
     *
     * WHERE event_id=? 中的 ? 是参数占位符，
     * 稍后通过 sqlite3_bind_blob 绑定实际值。
     */
    const static char* sql =
        "SELECT event_type,event_class,timestamp,src_process_id,tgt_process_id,"
        "confidence,severity,payload "
        "FROM cg_events WHERE event_id=? LIMIT 1";

    /* ── 参数校验 ── */
    if (!WkdStorageEngine.WarmDb || DefIsNullNodeId(EventId) || !OutEvent)
        return STATUS_INVALID_PARAMETER;

    *OutEvent = NULL;

    /*
     * sqlite3_prepare_v2 — 编译 SQL 字符串为预编译语句。
     *
     * 参数说明：
     *   WkdStorageEngine.WarmDb  — SQLite 数据库连接句柄（已打开的 db 文件）
     *   sql                   — SQL 字符串
     *   -1                    — SQL 长度（-1 表示自动计算到 \0 结尾）
     *   &stmt                 — 输出：预编译语句句柄
     *   NULL                  — 不需要 SQL 剩余部分指针
     *
     * 返回值：SQLITE_OK（0）表示成功，否则是错误码。
     * prepare 之后 stmt 就是"待执行的 SQL 模板"。
     */
    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;

    /*
     * sqlite3_bind_blob — 把参数绑定到 SQL 中的 ? 占位符。
     *
     * 参数说明：
     *   stmt         — 预编译语句
     *   1            — 参数索引（第 1 个 ?，注意从 1 开始！不是 0）
     *   eid          — 要绑定的 16 字节 BLOB 数据
     *   16           — 数据长度
     *   SQLITE_STATIC — 表示 eid 内存在 stmt 生命周期内保持有效
     *                   （本函数中 eid 是栈变量，stmt 在函数结束前 finalize，没问题）
     *
     * 执行完这一步，SQL 相当于：
     *   "SELECT ... WHERE event_id= <16字节二进制GUID>" LIMIT 1
     */
    sqlite3_bind_blob(stmt, 1, &EventId, 16, SQLITE_STATIC);

    /*
     * sqlite3_step — 执行预编译语句，前进一步。
     *
     * 返回值：
     *   SQLITE_ROW — 有数据行返回（通过 sqlite3_column_xxx 读取）
     *   SQLITE_DONE — 查询完毕没有更多行（此处表示没找到匹配的 event_id）
     *   其他       — 错误
     *
     * 对于 SELECT 查询，每次调用 step 移动到下一行。
     * 本 SQL 有 LIMIT 1，所以最多只有 0 或 1 行。
     */
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        /*
         * sqlite3_column_bytes(stmt, 7) — 读取第 8 列（payload）的字节长度。
         * column_bytes 返回的是该列数据的实际字节数。
         *
         * column_bytes 和 column_blob 通常是配对使用的：
         *   - column_blob(stmt, col) → 获取数据指针
         *   - column_bytes(stmt, col) → 获取数据长度
         */
        ULONG payloadSize = (ULONG)sqlite3_column_bytes(stmt, 7);
        ULONG totalSize = sizeof(WKD_EVENT_HEADER) + payloadSize;

        /*
         * 分配一块连续内存存放完整事件（header + payload）。
         * 调用方使用完后必须 UtHeapFree。
         */
        PWKD_EVENT_HEADER event = UtHeapAlloc(totalSize);
        if (!event) { sqlite3_finalize(stmt); return STATUS_NO_MEMORY; }
        RtlZeroMemory(event, totalSize);

        /* ── 填充固定头字段 ── */

        /* EventId 直接用入参，无需从 DB 读（WHERE 条件已知） */
        WkdCopyGuid(&event->EventId, &EventId);

        /*
         * sqlite3_column_int(stmt, 0) — 读取第 1 列（event_type）为 int。
         * 列索引从 0 开始对应 SELECT 顺序。
         */
        event->Type = (WKD_EVENT_TYPE)sqlite3_column_int(stmt, 0);
        event->Class = (DEF_EVENT_CLASS)sqlite3_column_int(stmt, 1);

        /*
         * sqlite3_column_int64 — 读取 64 位整数列。
         * Timestamp 是 LARGE_INTEGER（本质是 __int64）。
         */
        event->Timestamp.QuadPart = sqlite3_column_int64(stmt, 2);

        /*
    Stte3_column_blob(stmt, 3) — 读取第 4 列（src_process_id）为 BLOB。
         * 返回 const void* 指针指向 SQLite 内部缓冲区（不要 free）。
         * 需要自己 memcpy（因为 SQLite 内部数据可能在 finalize 后失效）。
         *
         * 二次校验 column_bytes == 16 防止数据损坏。
         */
        {
            const void* blob = sqlite3_column_blob(stmt, 3);
            if (blob && sqlite3_column_bytes(stmt, 3) == 16)
                memcpy(&event->SourceProcessId, blob, 16);
        }
        {
            const void* blob = sqlite3_column_blob(stmt, 4);
            if (blob && sqlite3_column_bytes(stmt, 4) == 16)
                memcpy(&event->TargetProcessId, blob, 16);
        }

        event->Confidence  = sqlite3_column_int(stmt, 5);
        event->Severity    = (DEF_THREAT_SEVERITY)sqlite3_column_int(stmt, 6);
        event->PayloadSize = payloadSize;

        /*
         * 恢复 payload（可变长载荷）。
         * payload 在第 7 列（索引从 0 算起）。
         * 各事件类型的 payload 结构不同，由调用方按 event->Type 自行转型解析。
         * 例如：WkdEvent_ProcessCreate → PEVENT_PAYLOAD_PROCESS_CREATE
         */
        if (payloadSize > 0) {
            const void* payload = sqlite3_column_blob(stmt, 7);
            if (payload) {
                /*
                 * 把 payload 拷贝到 event 结构体之后的位置上。
                 * event 是按 totalSize = sizeof(WKD_EVENT_HEADER) + payloadSize 分配的，
                 * 所以头部后面就是 payload 的存放位置。
                 */
                memcpy((PUCHAR)event + sizeof(WKD_EVENT_HEADER), payload, payloadSize);
            }
        }

        /* 反展平: 将偏移量还原为实际指针 */
        NtfEventRestore(event);

        *OutEvent = event;

        /*
         * sqlite3_finalize — 销毁预编译语句句柄，释放内部资源。
         * 每调用一次 prepare，必须对应一次 finalize，否则内存泄漏。
         * finalize 之后 stmt 不可再用。
         */
        sqlite3_finalize(stmt);
        return STATUS_SUCCESS;
    }

    /* 未找到匹配行 */
    sqlite3_finalize(stmt);
    return STATUS_NOT_FOUND;
}

NTSTATUS
StPersistAlert(
    _In_ PVOID AlertData
    )
/*++
Routine Description:
    持久化告警到 cg_alerts 表。
    Phase 4: 从 T2SerdeAlert 迁移到 T3 取证报告持久化。
--*/
{
    PIOA_ALERT alert = (PIOA_ALERT)AlertData;
    sqlite3_stmt* stmt = NULL;
    char alertId[64] = { 0 };
    char nodeId[64] = { 0 };
    char desc[2048] = { 0 };
    char ruleNameUtf8[128] = { 0 };   /* 修复: rule_name 不再写死 */
    char mitreIdUtf8[32] = { 0 };     /* 修复: mitre_id 不再写死 */

    if (!WkdStorageEngine.WarmDb || !alert) return STATUS_INVALID_PARAMETER;

    const char* sql =
        "INSERT OR REPLACE INTO cg_alerts "
        "(alert_id,timestamp,process_node_id,rule_name,mitre_id,"
        "severity,score,confidence,description,category,confidence_level,"
        "recommended_action,detection_source) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;

    /* alert_id: GUID → hex string */
    snprintf(alertId, sizeof(alertId),
             "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             alert->AlertId.Data1, alert->AlertId.Data2, alert->AlertId.Data3,
             alert->AlertId.Data4[0], alert->AlertId.Data4[1],
             alert->AlertId.Data4[2], alert->AlertId.Data4[3],
             alert->AlertId.Data4[4], alert->AlertId.Data4[5],
             alert->AlertId.Data4[6], alert->AlertId.Data4[7]);

    /* suspect node_id → hex string */
    snprintf(nodeId, sizeof(nodeId),
             "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             alert->SuspectNodeId.Data1, alert->SuspectNodeId.Data2,
             alert->SuspectNodeId.Data3,
             alert->SuspectNodeId.Data4[0], alert->SuspectNodeId.Data4[1],
             alert->SuspectNodeId.Data4[2], alert->SuspectNodeId.Data4[3],
             alert->SuspectNodeId.Data4[4], alert->SuspectNodeId.Data4[5],
             alert->SuspectNodeId.Data4[6], alert->SuspectNodeId.Data4[7]);

    /* description: rule_name + mitre_chain → UTF-8 */
    if (alert->RuleName) {
        WideCharToMultiByte(CP_UTF8, 0, alert->RuleName, -1,
                            desc, sizeof(desc), NULL, NULL);
    }
    if (alert->Description) {
        size_t len = strlen(desc);
        snprintf(desc + len, sizeof(desc) - len, " | %S", alert->Description);
    }

    /* rule_name / mitre_id: 使用真实值 (修复原写死 "T3 Forensics Report"/"See MITRE Chain") */
    if (alert->RuleName) {
        WideCharToMultiByte(CP_UTF8, 0, alert->RuleName, -1,
                            ruleNameUtf8, sizeof(ruleNameUtf8), NULL, NULL);
    }
    if (alert->MitreId) {
        WideCharToMultiByte(CP_UTF8, 0, alert->MitreId, -1,
                            mitreIdUtf8, sizeof(mitreIdUtf8), NULL, NULL);
    }

    sqlite3_bind_text(stmt, 1, alertId, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, alert->Timestamp.QuadPart);
    sqlite3_bind_text(stmt, 3, nodeId, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4,
        ruleNameUtf8[0] ? ruleNameUtf8 : "Unknown", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5,
        mitreIdUtf8[0] ? mitreIdUtf8 : "Unknown", -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, alert->Severity);
    sqlite3_bind_int(stmt, 7, alert->Score);
    sqlite3_bind_int(stmt, 8, alert->Confidence);
    sqlite3_bind_text(stmt, 9, desc, -1, SQLITE_STATIC);
    /* Verdict 扩展投影 (ThreatDetector 迁移, 2026-08-04) */
    sqlite3_bind_int(stmt, 10, (int)alert->Category);
    sqlite3_bind_int(stmt, 11, (int)alert->ConfidenceLevel);
    sqlite3_bind_int(stmt, 12, (int)alert->RecommendedAction);
    sqlite3_bind_int(stmt, 13, (int)alert->DetectionSource);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    WkdStorageEngine.WarmWrites++;
    return STATUS_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════ */
/*          文件信誉 API (SS FileReputation 迁移, 2026-08-06)           */
/* ═══════════════════════════════════════════════════════════════════ */

/* 证书 thumbprint 规范化 (SS NormalizeThumbprint L224-236 迁移, 活代码):
 * 去空格/冒号 (容忍用户格式化) + 转小写 (对齐 wkd IOC_SCAN_RESULT.Thumbprint
 * SHA1 小写 hex 约定)。键统一, 防大小写/分隔符差异导致信任表 bypass。 */
static VOID
IocStpNormalizeThumbprint(
    _In_  PCSTR Thumbprint,
    _Out_ CHAR* Out,        /* ≥ 48 (40 hex + NUL) */
    _In_  ULONG OutCch
    )
{
    ULONG o = 0;
    ULONG i;

    if (!Thumbprint || !Out || OutCch == 0) return;
    for (i = 0; Thumbprint[i] && (o + 1) < OutCch; i++) {
        CHAR c = Thumbprint[i];
        if (c == ' ' || c == ':') continue;
        if (c >= 'A' && c <= 'F') c = (CHAR)(c - 'A' + 'a');
        Out[o++] = c;
    }
    Out[o] = '\0';
}

NTSTATUS
StPersistFileReputation(
    _In_  PCSTR Sha256Hex,
    _In_  const WKD_FILE_REPUTATION* Rep,
    _In_  ULONG Verdict,
    _In_opt_ PCSTR ThreatName,
    _In_opt_ PCSTR Reasons,
    _Out_opt_ PBOOLEAN IsNew
    )
/*++
Routine Description:
    持久化文件信誉到 file_reputation 表 (SS FileReputation prevalence 机器维度)。
    upsert: 首次插入 seen_count=1, 再次扫描 seen_count+1 且 last_seen 刷新,
    first_seen 保持首次。IsNew 输出是否首次出现。

Arguments:
    Sha256Hex  - 文件 SHA256 小写 hex。
    Rep        - 信誉结果 (score/level/confidence)。
    Verdict    - DefIocVerdict 判定。
    ThreatName - 威胁名 (可空)。
    Reasons    - 竖线分隔归因 (可空)。
    IsNew      - 可选输出首次出现标志。

Return Value:
    NTSTATUS。
--*/
{
    sqlite3_stmt* stmt = NULL;
    ULONG64 nowSec;
    BOOLEAN isNew = FALSE;
    char threat[64] = { 0 }, reasons[256] = { 0 };

    if (!WkdStorageEngine.WarmDb || !Sha256Hex || !Rep) return STATUS_INVALID_PARAMETER;
    if (IsNew) *IsNew = FALSE;

    nowSec = (ULONG64)time(NULL);
    if (ThreatName) strncpy_s(threat, sizeof(threat), ThreatName, _TRUNCATE);
    if (Reasons) strncpy_s(reasons, sizeof(reasons), Reasons, _TRUNCATE);

    /* 存在性预查 (isNew = 首次出现) */
    if (IsNew) {
        const char* probe = "SELECT 1 FROM file_reputation WHERE sha256_hex=?";
        if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, probe, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, Sha256Hex, -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) != SQLITE_ROW) isNew = TRUE;
            sqlite3_finalize(stmt);
        }
        stmt = NULL;
    }

    {
        const char* sql =
            "INSERT INTO file_reputation (sha256_hex,reputation_score,reputation_level,"
            "confidence,verdict,threat_name,reasons,seen_count,first_seen,last_seen) "
            "VALUES (?,?,?,?,?,?,?,1,?,?) "
            "ON CONFLICT(sha256_hex) DO UPDATE SET "
            "reputation_score=excluded.reputation_score,"
            "reputation_level=excluded.reputation_level,"
            "confidence=excluded.confidence,"
            "verdict=excluded.verdict,"
            "threat_name=excluded.threat_name,"
            "reasons=excluded.reasons,"
            "seen_count=seen_count+1,"
            "last_seen=excluded.last_seen";
        if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
            return STATUS_UNSUCCESSFUL;

        sqlite3_bind_text(stmt, 1, Sha256Hex, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 2, Rep->Score);
        sqlite3_bind_int(stmt, 3, (int)Rep->Level);
        sqlite3_bind_int(stmt, 4, (int)Rep->Confidence);
        sqlite3_bind_int(stmt, 5, (int)Verdict);
        sqlite3_bind_text(stmt, 6, threat, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 7, reasons, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 8, (sqlite3_int64)nowSec);
        sqlite3_bind_int64(stmt, 9, (sqlite3_int64)nowSec);

        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    WkdStorageEngine.WarmWrites++;
    if (IsNew) *IsNew = isNew;
    return STATUS_SUCCESS;
}

NTSTATUS
StLoadFileReputation(
    _In_  PCSTR Sha256Hex,
    _Out_ PWKD_FILE_REPUTATION Rep,
    _Out_opt_ PULONG Verdict,
    _Out_opt_ PULONG SeenCount,
    _Out_opt_ PULONGLONG FirstSeen
    )
/*++
Routine Description:
    加载文件信誉 (file_reputation 表)。

Arguments:
    Sha256Hex - 文件 SHA256 小写 hex。
    Rep       - 输出信誉结果。
    Verdict   - 可选输出最近判定。
    SeenCount - 可选输出出现次数。
    FirstSeen - 可选输出首次出现 Unix 秒。

Return Value:
    STATUS_SUCCESS / STATUS_NOT_FOUND。
--*/
{
    const char* sql =
        "SELECT reputation_score,reputation_level,confidence,verdict,"
        "threat_name,reasons,seen_count,first_seen,last_seen "
        "FROM file_reputation WHERE sha256_hex=?";
    sqlite3_stmt* stmt = NULL;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (!WkdStorageEngine.WarmDb || !Sha256Hex || !Rep) return STATUS_INVALID_PARAMETER;

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;

    sqlite3_bind_text(stmt, 1, Sha256Hex, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        RtlZeroMemory(Rep, sizeof(*Rep));
        Rep->Score = sqlite3_column_int(stmt, 0);
        Rep->Level = (WKD_REPUTATION_LEVEL)sqlite3_column_int(stmt, 1);
        Rep->Confidence = (ULONG)sqlite3_column_int(stmt, 2);
        if (Verdict)   *Verdict   = (ULONG)sqlite3_column_int(stmt, 3);
        if (SeenCount) *SeenCount = (ULONG)sqlite3_column_int(stmt, 6);
        if (FirstSeen) *FirstSeen = (ULONGLONG)sqlite3_column_int64(stmt, 7);
        status = STATUS_SUCCESS;
    }
    sqlite3_finalize(stmt);
    return status;
}

NTSTATUS
StUpsertIocHash(
    _In_ PCSTR Sha256Hex,
    _In_ ULONG Verdict,
    _In_ ULONG Confidence,
    _In_opt_ PCSTR ThreatName
    )
/*++
Routine Description:
    写入 ioc_hashes 黑名单 (对齐 SS AddToBlacklist hash→threatName)。
    INSERT OR REPLACE + IocMatcher 布隆同步 (使 IocScan_HashQuery 预检命中)。

Arguments:
    Sha256Hex  - 文件 SHA256 hex (64 字符)。
    Verdict    - DefIocVerdict (Malicious 等)。
    Confidence - 置信度。
    ThreatName - 威胁名 (可空)。

Return Value:
    NTSTATUS。
--*/
{
    const char* sql =
        "INSERT OR REPLACE INTO ioc_hashes (sha256_hex,md5_hex,verdict,confidence,"
        "source,last_updated,threat_name) VALUES (?,NULL,?,?,?,?,?)";
    sqlite3_stmt* stmt = NULL;
    static const char source[] = "reputation";
    char threat[64] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    if (!WkdStorageEngine.WarmDb || !Sha256Hex) return STATUS_INVALID_PARAMETER;
    if (strnlen(Sha256Hex, 65) != 64) return STATUS_INVALID_PARAMETER;

    if (ThreatName) strncpy_s(threat, sizeof(threat), ThreatName, _TRUNCATE);

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;

    sqlite3_bind_text(stmt, 1, Sha256Hex, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, (int)Verdict);
    sqlite3_bind_int(stmt, 3, (int)Confidence);
    sqlite3_bind_text(stmt, 4, source, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)time(NULL));
    sqlite3_bind_text(stmt, 6, threat, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) status = STATUS_UNSUCCESSFUL;
    sqlite3_finalize(stmt);
    WkdStorageEngine.WarmWrites++;

    /* 布隆同步 (IocMatcher 用小写 hex 匹配, 对齐 MatchHash 语义)。
     * 使 IocScanner_QueryHash 的 BloomCheck 预检命中, 黑名单立即生效。 */
    if (status == STATUS_SUCCESS) {
        IOC_MATCH_INPUT ioc;
        RtlZeroMemory(&ioc, sizeof(ioc));
        ioc.Type = IocType_FileHash_SHA256;
        strncpy_s(ioc.Value, sizeof(ioc.Value), Sha256Hex, _TRUNCATE);
        ioc.ValueLength = 64;
        if (ThreatName) {
            strncpy_s(ioc.ThreatName, sizeof(ioc.ThreatName), ThreatName, _TRUNCATE);
        }
        IocMatcher_LoadIOC(&ioc);
    }
    return status;
}

NTSTATUS
StRemoveIocHash(
    _In_ PCSTR Sha256Hex
    )
/*++
Routine Description:
    移除 ioc_hashes 黑名单 (对齐 SS RemoveFromBlacklist)。

Arguments:
    Sha256Hex - 文件 SHA256 hex。

Return Value:
    NTSTATUS。
--*/
{
    const char* sql = "DELETE FROM ioc_hashes WHERE sha256_hex=?";
    sqlite3_stmt* stmt = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (!WkdStorageEngine.WarmDb || !Sha256Hex) return STATUS_INVALID_PARAMETER;

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;

    sqlite3_bind_text(stmt, 1, Sha256Hex, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) status = STATUS_UNSUCCESSFUL;
    sqlite3_finalize(stmt);

    /* 布隆不更新移除: 误报无害 (BloomCheck 命中后走 SQLite 精确查询返回
     * NOT_FOUND), 避免引入 IOC 移除/重建复杂度。 */
    return status;
}

NTSTATUS
StUpsertCertReputation(
    _In_ PCSTR Thumbprint,
    _In_ BOOLEAN IsTrusted,
    _In_opt_ PCSTR Reason
    )
/*++
Routine Description:
    写入证书信任 (cert_reputation 表, thumbprint 键)。
    对齐 SS AddTrustedCertificate/AddUntrustedCertificate (L953-1003)。

Arguments:
    Thumbprint - SHA1 指纹 hex 小写 (对齐 IOC_SCAN_RESULT.Thumbprint)。
    IsTrusted  - TRUE=可信 / FALSE=不可信。
    Reason     - 信任/不信任理由 (可空)。

Return Value:
    NTSTATUS。
--*/
{
    const char* sql =
        "INSERT OR REPLACE INTO cert_reputation (thumbprint,is_trusted,reason,last_updated) "
        "VALUES (?,?,?,?)";
    sqlite3_stmt* stmt = NULL;
    char reasonBuf[128] = { 0 };
    char norm[64] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    if (!WkdStorageEngine.WarmDb || !Thumbprint) return STATUS_INVALID_PARAMETER;
    IocStpNormalizeThumbprint(Thumbprint, norm, sizeof(norm));
    if (norm[0] == '\0') return STATUS_INVALID_PARAMETER;
    if (Reason) strncpy_s(reasonBuf, sizeof(reasonBuf), Reason, _TRUNCATE);

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;

    sqlite3_bind_text(stmt, 1, norm, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, IsTrusted ? 1 : 0);
    sqlite3_bind_text(stmt, 3, reasonBuf, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)time(NULL));

    if (sqlite3_step(stmt) != SQLITE_DONE) status = STATUS_UNSUCCESSFUL;
    sqlite3_finalize(stmt);
    WkdStorageEngine.WarmWrites++;
    return status;
}

NTSTATUS
StGetCertReputation(
    _In_ PCSTR Thumbprint,
    _Out_ PINT Trusted,
    _Out_opt_ PCHAR Reason,
    _In_ ULONG ReasonCch
    )
/*++
Routine Description:
    查询证书信任 (对齐 SS GetCertificateTrust L927-951)。

Arguments:
    Thumbprint - SHA1 指纹 hex 小写。
    Trusted    - 输出 1=trusted / 0=untrusted。
    Reason     - 可选输出信任理由。
    ReasonCch  - Reason 缓冲容量。

Return Value:
    STATUS_SUCCESS / STATUS_NOT_FOUND。
--*/
{
    const char* sql = "SELECT is_trusted,reason FROM cert_reputation WHERE thumbprint=?";
    sqlite3_stmt* stmt = NULL;
    char norm[64] = { 0 };
    NTSTATUS status = STATUS_NOT_FOUND;

    if (!WkdStorageEngine.WarmDb || !Thumbprint || !Trusted) return STATUS_INVALID_PARAMETER;
    IocStpNormalizeThumbprint(Thumbprint, norm, sizeof(norm));
    if (norm[0] == '\0') return STATUS_INVALID_PARAMETER;

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;

    sqlite3_bind_text(stmt, 1, norm, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *Trusted = sqlite3_column_int(stmt, 0);
        if (Reason && ReasonCch > 0 && sqlite3_column_type(stmt, 1) == SQLITE_TEXT) {
            const unsigned char* txt = sqlite3_column_text(stmt, 1);
            if (txt) strncpy_s(Reason, ReasonCch, (const char*)txt, _TRUNCATE);
        }
        status = STATUS_SUCCESS;
    }
    sqlite3_finalize(stmt);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  设备历史/白名单 (SS MountPointMonitor 迁移 2026-08)                 */
/*  ※死代码预留: MountPointMonitor 设备历史/白名单主体在内存, 本组 API  */
/*  未接线 (UI 查询/策略下发待定), 保 StorageEngine 功能面。            */
/* ═══════════════════════════════════════════════════════════════════ */

NTSTATUS
StPersistDeviceHistory(
    _In_ PCSTR Serial,
    _In_opt_ PCSTR Vid,
    _In_opt_ PCSTR Pid,
    _In_opt_ PCSTR FriendlyName,
    _In_ LONGLONG FirstSeen,
    _In_ LONGLONG LastSeen,
    _In_ ULONG ConnectionCount,
    _In_ BOOLEAN IsWhitelisted
    )
/*++
Routine Description:
    写入设备历史 (device_history 表, serial 键 upsert)。
    对齐 SS MountPointMonitor UpdateDeviceHistory 的持久化侧 (SS 无, wkd 预留)。

Arguments:
    Serial          - 设备序列号 (UTF-8, 键)。
    Vid/Pid         - 厂商/产品 ID (可空)。
    FriendlyName    - 友好名 (可空)。
    FirstSeen/LastSeen - FILETIME 100ns。
    ConnectionCount - 连接次数。
    IsWhitelisted   - 是否白名单。

Return Value:
    NTSTATUS。
--*/
{
    const char* sql =
        "INSERT OR REPLACE INTO device_history "
        "(serial,vid,pid,friendly_name,first_seen,last_seen,connection_count,is_whitelisted) "
        "VALUES (?,?,?,?,?,?,?,?)";
    sqlite3_stmt* stmt = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (!WkdStorageEngine.WarmDb || !Serial) return STATUS_INVALID_PARAMETER;

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;

    sqlite3_bind_text(stmt, 1, Serial, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, Vid ? Vid : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, Pid ? Pid : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, FriendlyName ? FriendlyName : "", -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)FirstSeen);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)LastSeen);
    sqlite3_bind_int(stmt, 7, (int)ConnectionCount);
    sqlite3_bind_int(stmt, 8, IsWhitelisted ? 1 : 0);

    if (sqlite3_step(stmt) != SQLITE_DONE) status = STATUS_UNSUCCESSFUL;
    sqlite3_finalize(stmt);
    WkdStorageEngine.WarmWrites++;
    return status;
}

NTSTATUS
StLoadDeviceHistory(
    _In_ PCSTR Serial,
    _Out_ PINT ConnectionCount,
    _Out_opt_ PLONGLONG LastSeen,
    _Out_opt_ PLONGLONG FirstSeen
    )
/*++
Routine Description:
    查询设备历史 (device_history 表)。

Arguments:
    Serial          - 设备序列号 (UTF-8)。
    ConnectionCount - 输出连接次数。
    LastSeen/FirstSeen - 可选输出 FILETIME 100ns。

Return Value:
    STATUS_SUCCESS / STATUS_NOT_FOUND。
--*/
{
    const char* sql =
        "SELECT connection_count,last_seen,first_seen FROM device_history WHERE serial=?";
    sqlite3_stmt* stmt = NULL;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (!WkdStorageEngine.WarmDb || !Serial || !ConnectionCount)
        return STATUS_INVALID_PARAMETER;

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;

    sqlite3_bind_text(stmt, 1, Serial, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *ConnectionCount = sqlite3_column_int(stmt, 0);
        if (LastSeen)  *LastSeen  = (LONGLONG)sqlite3_column_int64(stmt, 1);
        if (FirstSeen) *FirstSeen = (LONGLONG)sqlite3_column_int64(stmt, 2);
        status = STATUS_SUCCESS;
    }
    sqlite3_finalize(stmt);
    return status;
}

NTSTATUS
StUpsertDeviceWhitelist(
    _In_ PCSTR Serial
    )
/*++
Routine Description:
    写入设备白名单 (device_whitelist 表, INSERT OR IGNORE)。

Arguments:
    Serial - 设备序列号 (UTF-8)。

Return Value:
    NTSTATUS。
--*/
{
    const char* sql =
        "INSERT OR IGNORE INTO device_whitelist (serial,added_time) VALUES (?,?)";
    sqlite3_stmt* stmt = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (!WkdStorageEngine.WarmDb || !Serial) return STATUS_INVALID_PARAMETER;

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;

    sqlite3_bind_text(stmt, 1, Serial, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)time(NULL));

    if (sqlite3_step(stmt) != SQLITE_DONE) status = STATUS_UNSUCCESSFUL;
    sqlite3_finalize(stmt);
    WkdStorageEngine.WarmWrites++;
    return status;
}

/**************************************************/
/*              排除规则 (Exempts #67)               */
/**************************************************/

NTSTATUS
StPersistExemptRule(
    _In_ PEXEMPT_RULE Rule,
    _Out_opt_ PBOOLEAN IsNew
    )
/*++
Routine Description:
    持久化排除规则 (exempt_rules 表, upsert by rule_id)。
    Hash 规则序列化 hash_hex (64 hex 小写), 其余序列化 pattern。

Arguments:
    Rule  - 规则。
    IsNew - 可选输出是否首次插入。

Return Value:
    NTSTATUS。
--*/
{
    const char* sql =
        "INSERT INTO exempt_rules (rule_id,rule_type,reason,match_mode,flags,"
        "hash_algorithm,hash_hex,pattern,description,policy_id,hit_count,"
        "created_time,modified_time,expiration_time) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(rule_id) DO UPDATE SET "
        "rule_type=excluded.rule_type,reason=excluded.reason,"
        "match_mode=excluded.match_mode,flags=excluded.flags,"
        "hash_algorithm=excluded.hash_algorithm,hash_hex=excluded.hash_hex,"
        "pattern=excluded.pattern,description=excluded.description,"
        "policy_id=excluded.policy_id,hit_count=excluded.hit_count,"
        "created_time=excluded.created_time,modified_time=excluded.modified_time,"
        "expiration_time=excluded.expiration_time";
    sqlite3_stmt* stmt = NULL;
    char hashHex[EXEMPT_HASH_SIZE * 2 + 1];
    char patternUtf8[EXEMPT_MAX_PATTERN * 3];
    char descUtf8[EXEMPT_MAX_DESCRIPTION * 3];
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN isNew = FALSE;

    if (!WkdStorageEngine.WarmDb || !Rule) return STATUS_INVALID_PARAMETER;
    if (IsNew) *IsNew = FALSE;

    hashHex[0] = '\0';
    patternUtf8[0] = '\0';
    descUtf8[0] = '\0';

    if (Rule->Type == ExemptRule_Hash && Rule->HashLength > 0) {
        UtHexEncode(Rule->HashData, Rule->HashLength, hashHex, sizeof(hashHex), FALSE);
    } else if (Rule->Pattern[0] != L'\0') {
        WideCharToMultiByte(CP_UTF8, 0, Rule->Pattern, -1,
                            patternUtf8, (int)sizeof(patternUtf8), NULL, NULL);
    }
    if (Rule->Description[0] != L'\0') {
        WideCharToMultiByte(CP_UTF8, 0, Rule->Description, -1,
                            descUtf8, (int)sizeof(descUtf8), NULL, NULL);
    }

    /* 存在性预查 (IsNew) */
    if (IsNew) {
        const char* probe = "SELECT 1 FROM exempt_rules WHERE rule_id=?";
        if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, probe, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, (sqlite3_int64)Rule->RuleId);
            if (sqlite3_step(stmt) != SQLITE_ROW) isNew = TRUE;
            sqlite3_finalize(stmt);
        }
        stmt = NULL;
    }

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)Rule->RuleId);
    sqlite3_bind_int(stmt, 2, (int)Rule->Type);
    sqlite3_bind_int(stmt, 3, (int)Rule->Reason);
    sqlite3_bind_int(stmt, 4, (int)Rule->MatchMode);
    sqlite3_bind_int(stmt, 5, (int)Rule->Flags);
    sqlite3_bind_int(stmt, 6, (int)Rule->HashAlgorithm);
    sqlite3_bind_text(stmt, 7, hashHex, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, patternUtf8, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, descUtf8, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 10, (int)Rule->PolicyId);
    sqlite3_bind_int(stmt, 11, (int)Rule->HitCount);
    sqlite3_bind_int64(stmt, 12, (sqlite3_int64)Rule->CreatedTime);
    sqlite3_bind_int64(stmt, 13, (sqlite3_int64)Rule->ModifiedTime);
    sqlite3_bind_int64(stmt, 14, (sqlite3_int64)Rule->ExpirationTime);

    if (sqlite3_step(stmt) != SQLITE_DONE) status = STATUS_UNSUCCESSFUL;
    sqlite3_finalize(stmt);

    WkdStorageEngine.WarmWrites++;
    if (IsNew) *IsNew = isNew;
    return status;
}

NTSTATUS
StLoadExemptRules(
    _Out_ PEXEMPT_RULE* OutRules,
    _Out_ PULONG Count
    )
/*++
Routine Description:
    加载全部排除规则 (exempt_rules 表)。堆数组由调用方 UtHeapFree 释放。

Arguments:
    OutRules - 输出规则数组 (堆分配)。
    Count    - 输出规则数。

Return Value:
    STATUS_SUCCESS / STATUS_NOT_FOUND (空表) / STATUS_INVALID_PARAMETER /
    STATUS_INSUFFICIENT_RESOURCES。
--*/
{
    const char* sql =
        "SELECT rule_id,rule_type,reason,match_mode,flags,hash_algorithm,"
        "hash_hex,pattern,description,policy_id,hit_count,"
        "created_time,modified_time,expiration_time FROM exempt_rules";
    sqlite3_stmt* stmt = NULL;
    PEXEMPT_RULE arr = NULL;
    ULONG total = 0, idx = 0;
    NTSTATUS status = STATUS_SUCCESS;

    if (!WkdStorageEngine.WarmDb || !OutRules || !Count) return STATUS_INVALID_PARAMETER;
    *OutRules = NULL;
    *Count = 0;

    /* 第一次遍历计数 */
    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        total++;
    }
    sqlite3_finalize(stmt);

    if (total == 0) {
        return STATUS_NOT_FOUND;
    }

    arr = (PEXEMPT_RULE)UtHeapAlloc((SIZE_T)total * sizeof(EXEMPT_RULE));
    if (arr == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ZeroMemory(arr, (SIZE_T)total * sizeof(EXEMPT_RULE));

    /* 第二次遍历填充 */
    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK) {
        UtHeapFree(arr);
        return STATUS_UNSUCCESSFUL;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        PEXEMPT_RULE r = &arr[idx];
        const unsigned char* hashHex =
            sqlite3_column_text(stmt, 6);
        const unsigned char* pattern =
            sqlite3_column_text(stmt, 7);
        const unsigned char* desc =
            sqlite3_column_text(stmt, 8);

        r->RuleId = (UINT64)sqlite3_column_int64(stmt, 0);
        r->Type = (UINT8)sqlite3_column_int(stmt, 1);
        r->Reason = (UINT8)sqlite3_column_int(stmt, 2);
        r->MatchMode = (UINT8)sqlite3_column_int(stmt, 3);
        r->Flags = (UINT8)sqlite3_column_int(stmt, 4);
        r->HashAlgorithm = (UINT8)sqlite3_column_int(stmt, 5);
        r->PolicyId = (UINT32)sqlite3_column_int(stmt, 9);
        r->HitCount = (ULONG)sqlite3_column_int(stmt, 10);
        r->CreatedTime = (UINT64)sqlite3_column_int64(stmt, 11);
        r->ModifiedTime = (UINT64)sqlite3_column_int64(stmt, 12);
        r->ExpirationTime = (UINT64)sqlite3_column_int64(stmt, 13);

        /* 还原哈希 (hash_hex → HashData) 或模式 (pattern → Pattern) */
        if (r->Type == ExemptRule_Hash && hashHex != NULL) {
            ULONG written = 0;
            if (UtHexDecode((PCSTR)hashHex, r->HashData, EXEMPT_HASH_SIZE, &written)) {
                r->HashLength = (UINT8)written;
            }
        } else if (pattern != NULL) {
            MultiByteToWideChar(CP_UTF8, 0, (PCSTR)pattern, -1,
                                r->Pattern, EXEMPT_MAX_PATTERN);
        }
        if (desc != NULL) {
            MultiByteToWideChar(CP_UTF8, 0, (PCSTR)desc, -1,
                                r->Description, EXEMPT_MAX_DESCRIPTION);
        }

        idx++;
    }
    sqlite3_finalize(stmt);

    *OutRules = arr;
    *Count = idx;
    return STATUS_SUCCESS;
}

NTSTATUS
StRemoveExemptRule(
    _In_ UINT64 RuleId
    )
/*++
Routine Description:
    按 RuleId 移除排除规则 (exempt_rules 表)。

Arguments:
    RuleId - 规则 ID。

Return Value:
    NTSTATUS。
--*/
{
    const char* sql = "DELETE FROM exempt_rules WHERE rule_id=?";
    sqlite3_stmt* stmt = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (!WkdStorageEngine.WarmDb) return STATUS_INVALID_PARAMETER;

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)RuleId);

    if (sqlite3_step(stmt) != SQLITE_DONE) status = STATUS_UNSUCCESSFUL;
    sqlite3_finalize(stmt);
    WkdStorageEngine.WarmWrites++;
    return status;
}

NTSTATUS
StClearExemptRules(
    _In_ UINT8 Type
    )
/*++
Routine Description:
    按类型清空排除规则 (exempt_rules 表)。Type==ExemptRule_MaxValue 清空全部。

Arguments:
    Type - EXEMPT_RULE_TYPE。

Return Value:
    NTSTATUS。
--*/
{
    const char* sqlAll = "DELETE FROM exempt_rules";
    const char* sqlTyped = "DELETE FROM exempt_rules WHERE rule_type=?";
    sqlite3_stmt* stmt = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (!WkdStorageEngine.WarmDb) return STATUS_INVALID_PARAMETER;

    if (Type == ExemptRule_MaxValue) {
        if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sqlAll, -1, &stmt, NULL) != SQLITE_OK)
            return STATUS_UNSUCCESSFUL;
    } else {
        if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sqlTyped, -1, &stmt, NULL) != SQLITE_OK)
            return STATUS_UNSUCCESSFUL;
        sqlite3_bind_int(stmt, 1, (int)Type);
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) status = STATUS_UNSUCCESSFUL;
    sqlite3_finalize(stmt);
    WkdStorageEngine.WarmWrites++;
    return status;
}

/* ═══════════════════════════════════════════════════════════════════ */
/*                   公开 API                                         */
/* ═══════════════════════════════════════════════════════════════════ */

NTSTATUS StInitialize(PCWSTR WarmPath, PCWSTR ColdPath, ULONG RetentionDays)
{
    NTSTATUS status;
    RtlZeroMemory(&WkdStorageEngine, sizeof(WkdStorageEngine));

    WkdStorageEngine.HotCache.Entries = UtHeapAlloc(
        sizeof(DEF_HOT_CACHE_ENTRY) * DEF_HOT_CACHE_MAX_ENTRIES);
    if (!WkdStorageEngine.HotCache.Entries) return STATUS_NO_MEMORY;
    WkdStorageEngine.HotCache.Capacity = DEF_HOT_CACHE_MAX_ENTRIES;
    InitializeCriticalSection(&WkdStorageEngine.HotCache.Lock);
    InitializeCriticalSection(&WkdStorageEngine.Lock);

    status = StOpenDb(WarmPath, &WkdStorageEngine.WarmDb, TRUE);
    if (!NT_SUCCESS(status)) { UtHeapFree(WkdStorageEngine.HotCache.Entries); return status; }

    StCreateSchema(WkdStorageEngine.WarmDb);
    wcsncpy_s(WkdStorageEngine.WarmDbPath, DEF_MAX_PATH, WarmPath, _TRUNCATE);
    WkdStorageEngine.RetentionDays = RetentionDays;
    WkdStorageEngine.Initialized = TRUE;

    printf("[Storage] Initialized: WAL=%S retention=%lud\n", WarmPath, RetentionDays);
    return STATUS_SUCCESS;
}

VOID StCleanup(VOID)
{
    if (!WkdStorageEngine.Initialized) return;
    for (ULONG i = 0; i < WkdStorageEngine.HotCache.Count; i++)
        if (WkdStorageEngine.HotCache.Entries[i].Data && !WkdStorageEngine.HotCache.Entries[i].PointerMode)
            UtHeapFree(WkdStorageEngine.HotCache.Entries[i].Data);
    UtHeapFree(WkdStorageEngine.HotCache.Entries);
    if (WkdStorageEngine.WarmDb) sqlite3_close(WkdStorageEngine.WarmDb);
    if (WkdStorageEngine.ColdDb) sqlite3_close(WkdStorageEngine.ColdDb);
    DeleteCriticalSection(&WkdStorageEngine.HotCache.Lock);
    DeleteCriticalSection(&WkdStorageEngine.Lock);
    printf("[Storage] Cleanup: hits=%lld misses=%lld writes=%lld\n",
           WkdStorageEngine.HotHits, WkdStorageEngine.HotMisses, WkdStorageEngine.WarmWrites);
}
