/**************************************************/
/*  WkDefender 分层存储引擎 — IOC/IOA 共用基础设施  */
/*  Hot(内存LRU) / Warm(SQLite WAL) / Cold(归档)   */
/**************************************************/

#pragma once

#include "../DefendTypes.h"
#include "../Notification/EventTypes.h"
#include "../IOC/IocTypes.h"   /* WKD_FILE_REPUTATION (SS FileReputation 迁移) */
#include "../Common/Exempts/Exempts.h"  /* EXEMPT_RULE (Exempts 重构 2026-08-14, 档案 #67) */

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

/**************************************************/
/*               热图缓存条目                       */
/**************************************************/

typedef struct _DEF_HOT_CACHE_ENTRY {
    GUID         NodeId;
    DEF_NODE_TYPE       NodeType;
    LARGE_INTEGER       LastAccess;
    LARGE_INTEGER       ExpiryTime;
    PVOID               Data;
    ULONG               DataSize;
    BOOLEAN             Dirty;
    BOOLEAN             PointerMode;
    UCHAR               Reserved[2];
} DEF_HOT_CACHE_ENTRY, *PDEF_HOT_CACHE_ENTRY;

typedef struct _DEF_HOT_CACHE {
    DEF_HOT_CACHE_ENTRY* Entries;
    ULONG               Capacity;
    ULONG               Count;
    CRITICAL_SECTION    Lock;
} DEF_HOT_CACHE, *PDEF_HOT_CACHE;

/**************************************************/
/*               分层存储管理器                     */
/**************************************************/

typedef struct _STORAGE_ENGINE {
    BOOLEAN             Initialized;
    DEF_HOT_CACHE       HotCache;
    sqlite3*            WarmDb;
    WCHAR               WarmDbPath[DEF_MAX_PATH];
    sqlite3*            ColdDb;
    WCHAR               ColdDbPath[DEF_MAX_PATH];
    ULONG               RetentionDays;
    volatile LONG64     HotHits;
    volatile LONG64     HotMisses;
    volatile LONG64     WarmWrites;
    volatile LONG64     ColdWrites;
    CRITICAL_SECTION    Lock;
} STORAGE_ENGINE, *PSTORAGE_ENGINE;

extern STORAGE_ENGINE WkdStorageEngine;

/* SQL Schema */
#define DEF_SQL_NODES       "CREATE TABLE IF NOT EXISTS cg_nodes (...)"
#define DEF_SQL_EDGES       "CREATE TABLE IF NOT EXISTS cg_edges (...)"
#define DEF_SQL_EVENTS      "CREATE TABLE IF NOT EXISTS cg_events (...)"
#define DEF_SQL_ALERTS      "CREATE TABLE IF NOT EXISTS cg_alerts (alert_id TEXT PRIMARY KEY, timestamp INTEGER NOT NULL, process_node_id TEXT NOT NULL, rule_name TEXT NOT NULL, mitre_id TEXT, severity INTEGER NOT NULL, score INTEGER NOT NULL, confidence INTEGER DEFAULT 0, description TEXT, acknowledged INTEGER DEFAULT 0, category INTEGER DEFAULT 0, confidence_level INTEGER DEFAULT 0, recommended_action INTEGER DEFAULT 0, detection_source INTEGER DEFAULT 0)"
#define DEF_SQL_IOC_HASHES  "CREATE TABLE IF NOT EXISTS ioc_hashes (sha256_hex TEXT PRIMARY KEY, md5_hex TEXT, verdict INTEGER NOT NULL, confidence INTEGER NOT NULL, source TEXT, last_updated INTEGER DEFAULT 0)"
#define DEF_SQL_IOC_CERTS   "CREATE TABLE IF NOT EXISTS ioc_certs (subject TEXT PRIMARY KEY, verdict INTEGER NOT NULL, last_updated INTEGER DEFAULT 0)"
#define DEF_SQL_YARA_RULES  "CREATE TABLE IF NOT EXISTS yara_rules (rule_id TEXT PRIMARY KEY, rule_name TEXT NOT NULL, rule_text TEXT NOT NULL, compiled_rule BLOB, threat_level INTEGER DEFAULT 2, author TEXT, description TEXT, tags TEXT, hit_count INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1, last_modified INTEGER DEFAULT (unixepoch()))"
/* 文件信誉表 (SS FileReputation prevalence 机器维度迁移, 2026-08-06):
 * seen_count 出现频次 + first/last_seen 时间维度, 哈希小写 hex 与白名单/缓存统一 */
#define DEF_SQL_FILE_REPUTATION \
    "CREATE TABLE IF NOT EXISTS file_reputation (sha256_hex TEXT PRIMARY KEY, " \
    "reputation_score INTEGER DEFAULT 0, reputation_level INTEGER DEFAULT 0, " \
    "confidence INTEGER DEFAULT 0, verdict INTEGER DEFAULT 0, " \
    "threat_name TEXT, reasons TEXT, " \
    "seen_count INTEGER DEFAULT 1, " \
    "first_seen INTEGER DEFAULT 0, last_seen INTEGER DEFAULT 0)"
/* 证书信任表 (SS AddTrustedCertificate/AddUntrustedCertificate 迁移,
 * thumbprint 键 SHA1 hex 小写, 对齐 IOC_SCAN_RESULT.Thumbprint 格式) */
#define DEF_SQL_CERT_REPUTATION \
    "CREATE TABLE IF NOT EXISTS cert_reputation (thumbprint TEXT PRIMARY KEY, " \
    "is_trusted INTEGER DEFAULT 1, reason TEXT, last_updated INTEGER DEFAULT 0)"
/* 设备历史表 (SS MountPointMonitor 迁移 2026-08, ※死代码预留:
 * MountPointMonitor 设备历史/白名单主体在内存, 本表待接线) */
#define DEF_SQL_DEVICE_HISTORY \
    "CREATE TABLE IF NOT EXISTS device_history (serial TEXT PRIMARY KEY, " \
    "vid TEXT, pid TEXT, friendly_name TEXT, " \
    "first_seen INTEGER DEFAULT 0, last_seen INTEGER DEFAULT 0, " \
    "connection_count INTEGER DEFAULT 1, is_whitelisted INTEGER DEFAULT 0)"
/* 设备白名单表 (SS MountPointMonitor 迁移 2026-08, ※死代码预留) */
#define DEF_SQL_DEVICE_WHITELIST \
    "CREATE TABLE IF NOT EXISTS device_whitelist (serial TEXT PRIMARY KEY, " \
    "added_time INTEGER DEFAULT 0)"
/* 排除规则表 (Exempts 重构 2026-08-14, 档案 #67):
 * 四维规则 Hash/Path/Certificate/Publisher 统一存储, rule_type 区分。
 * Hash 规则存 hash_hex (64 hex 小写), 其余存 pattern。
 * 时间戳 FILETIME 100ns (0=永不过期)。 */
#define DEF_SQL_EXEMPT_RULES \
    "CREATE TABLE IF NOT EXISTS exempt_rules (" \
    "rule_id INTEGER PRIMARY KEY AUTOINCREMENT, " \
    "rule_type INTEGER NOT NULL, " \
    "reason INTEGER DEFAULT 0, " \
    "match_mode INTEGER DEFAULT 0, " \
    "flags INTEGER DEFAULT 0, " \
    "hash_algorithm INTEGER DEFAULT 0, " \
    "hash_hex TEXT, " \
    "pattern TEXT, " \
    "description TEXT, " \
    "policy_id INTEGER DEFAULT 0, " \
    "hit_count INTEGER DEFAULT 0, " \
    "created_time INTEGER DEFAULT 0, " \
    "modified_time INTEGER DEFAULT 0, " \
    "expiration_time INTEGER DEFAULT 0)"

NTSTATUS StInitialize(_In_ PCWSTR WarmPath, _In_ PCWSTR ColdPath, _In_ ULONG RetentionDays);
VOID     StCleanup(VOID);

/* Hot 缓存 (内存 LRU) */
NTSTATUS StHotPut(GUID NodeId, DEF_NODE_TYPE NodeType, PVOID Data, ULONG DataSize);
PVOID    StHotGet(GUID NodeId);
NTSTATUS StHotRemove(GUID NodeId);

/* ── 统一持久化接口 (各子系统注册 serde) ──────────────────────── */

/*
 * Persist: IOA 管线必须调用环节，非可选项。
 * 各子系统注册自己的 serde 函数做数据格式适配。
 * 共享 schema，不共享对象。
 */

/* 持久化事件（WKD_EVENT_HEADER → cg_events 表） */
NTSTATUS
StPersistEvent(
    _In_ PWKD_EVENT_HEADER Event
    );

/* 持久化节点（WKD_PROCESS → cg_nodes 表） */
NTSTATUS StPersistNode(_In_ PVOID NodeData);

/* 持久化边（IOA_GRAPH_EDGE → cg_edges 表） */
NTSTATUS StPersistEdge(_In_ PVOID EdgeData);

/* 持久化告警（IOA_ALERT → cg_alerts 表） */
NTSTATUS StPersistAlert(_In_ PVOID AlertData);

/* ── 文件信誉 (SS FileReputation 迁移, 2026-08-06) ──────────────────── */

/* 持久化文件信誉 (file_reputation 表, upsert seen_count++, 输出 IsNew)。
 * Sha256Hex 小写 hex; Reasons 竖线分隔归因 (经 TxtSanitize 后)。 */
NTSTATUS StPersistFileReputation(
    _In_  PCSTR Sha256Hex,
    _In_  const WKD_FILE_REPUTATION* Rep,
    _In_  ULONG Verdict,
    _In_opt_ PCSTR ThreatName,
    _In_opt_ PCSTR Reasons,
    _Out_opt_ PBOOLEAN IsNew
    );

/* 加载文件信誉 (file_reputation 表), 未找到返回 STATUS_NOT_FOUND */
NTSTATUS StLoadFileReputation(
    _In_  PCSTR Sha256Hex,
    _Out_ PWKD_FILE_REPUTATION Rep,
    _Out_opt_ PULONG Verdict,
    _Out_opt_ PULONG SeenCount,
    _Out_opt_ PULONGLONG FirstSeen
    );

/* 写入 ioc_hashes 黑名单 (INSERT OR REPLACE + IocMatcher 布隆同步)。
 * 对齐 SS AddToBlacklist (hash → threatName)。 */
NTSTATUS StUpsertIocHash(
    _In_ PCSTR Sha256Hex,
    _In_ ULONG Verdict,
    _In_ ULONG Confidence,
    _In_opt_ PCSTR ThreatName
    );

/* 移除 ioc_hashes 黑名单 (对齐 SS RemoveFromBlacklist) */
NTSTATUS StRemoveIocHash(
    _In_ PCSTR Sha256Hex
    );

/* 证书信任管理 (cert_reputation 表, thumbprint 键 SHA1 hex 小写,
 * 对齐 SS AddTrustedCertificate/AddUntrustedCertificate)。 */
NTSTATUS StUpsertCertReputation(
    _In_ PCSTR Thumbprint,
    _In_ BOOLEAN IsTrusted,
    _In_opt_ PCSTR Reason
    );

/* 查询证书信任: Trusted 输出 1=trusted / 0=untrusted; 未找到返回 STATUS_NOT_FOUND */
NTSTATUS StGetCertReputation(
    _In_ PCSTR Thumbprint,
    _Out_ PINT Trusted,
    _Out_opt_ PCHAR Reason,
    _In_ ULONG ReasonCch
    );

/* ── 设备历史/白名单 (SS MountPointMonitor 迁移, 2026-08) ──────────── */
/* ※死代码预留: MountPointMonitor 设备历史/白名单主体在内存, 本组 API 未接线
 * (UI 查询/策略下发待定), 保 StorageEngine 功能面。时间戳为 FILETIME 100ns
 * (LARGE_INTEGER.QuadPart)。 */

/* 持久化设备历史 (device_history 表, upsert, serial 键) */
NTSTATUS StPersistDeviceHistory(
    _In_  PCSTR Serial,
    _In_opt_ PCSTR Vid,
    _In_opt_ PCSTR Pid,
    _In_opt_ PCSTR FriendlyName,
    _In_  LONGLONG FirstSeen,
    _In_  LONGLONG LastSeen,
    _In_  ULONG ConnectionCount,
    _In_  BOOLEAN IsWhitelisted
    );

/* 加载设备历史 (device_history 表), 未找到返回 STATUS_NOT_FOUND */
NTSTATUS StLoadDeviceHistory(
    _In_  PCSTR Serial,
    _Out_ PINT ConnectionCount,
    _Out_opt_ PLONGLONG LastSeen,
    _Out_opt_ PLONGLONG FirstSeen
    );

/* 写入设备白名单 (device_whitelist 表, INSERT OR IGNORE) */
NTSTATUS StUpsertDeviceWhitelist(
    _In_ PCSTR Serial
    );

/* ── 排除规则 (Exempts 重构 2026-08-14, 档案 #67) ────────────────────── */

/* 持久化排除规则 (exempt_rules 表, upsert by rule_id) */
NTSTATUS StPersistExemptRule(
    _In_ PEXEMPT_RULE Rule,
    _Out_opt_ PBOOLEAN IsNew
    );

/* 加载全部排除规则 (exempt_rules 表, 堆数组调用方 UtHeapFree) */
NTSTATUS StLoadExemptRules(
    _Out_ PEXEMPT_RULE* OutRules,
    _Out_ PULONG Count
    );

/* 按 RuleId 移除排除规则 */
NTSTATUS StRemoveExemptRule(
    _In_ UINT64 RuleId
    );

/* 按类型清空排除规则 (ExemptRule_MaxValue=全部) */
NTSTATUS StClearExemptRules(
    _In_ UINT8 Type
    );

/* ── 三级读链接口 ──────────────────────────────────────────────── */

/*
 * Tier 2/3 回溯时需要恢复历史数据:
 *   优先内存图 → Warm DB (SQLite) Fallback → Cold DB (归档)
 */

/* 加载进程节点 (通过 GUID) */
PVOID StLoadNode(_In_ GUID NodeId);

/* 加载事件 (通过 event_id GUID，用于 Tier3 证据反查) */
NTSTATUS StLoadEventByGuid(_In_ GUID EventId, _Out_ PWKD_EVENT_HEADER* OutEvent);

/* 加载边 (通过源/目标节点 GUID + 方向)
 * dir: 0 = 出边, 1 = 入边. 返回 Heap 分配的 IOA_GRAPH_EDGE 数组，调用者释放 */
PVOID StLoadEdges(_In_ GUID NodeId, _In_ ULONG Dir, _Out_ PULONG EdgeCount);

/* 事件展平: 独立分配 → 连续内存布局（供持久化使用） */
NTSTATUS
StFlattenEventForPersist(
    _In_  PWKD_EVENT_HEADER  Event,
    _Out_ PWKD_EVENT_HEADER* FlatEvent,
    _Out_ ULONG* FlatSize
    );