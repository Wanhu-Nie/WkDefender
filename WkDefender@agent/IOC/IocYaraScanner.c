/**************************************************/
/*  WkDefender IOC — YARA 扫描器 (机制 A 封装实现)   */
/*  职责：YARA 扫描（ScanFile/ScanBuffer），不管理规则 */
/*  规则管理由 Storage/YaraRule.c 负责                */
/*                                                  */
/*  锁层次：                                         */
/*    Level 1: g_YaraLock Shared   — 保护 rules 指针 */
/*    Level 2: g_YaraScanLock Exclusive — 串行化扫描 */
/**************************************************/

#include "IocYaraScanner.h"
#include "../Storage/YaraRule.h"
#include "../Storage/StorageEngine.h"
#include "../Common/TitaniumLimits.h"
#include "../Common/YaraUtils.h"
#include "../WkDefenderHeader.h"
#include <sqlite3.h>

/* 回调上下文：收集最高威胁命中 + DoS 计数器 + 延迟命中记录 */
#define WKD_YARA_MAX_MATCHED_RULES 64

typedef struct _WKD_YARA_CB_CTX {
    BOOLEAN Hit;
    ULONG   TopScore;
    CHAR    TopRule[128];       /* 最高威胁规则名（含命名空间） */
    ULONG   MatchCount;         /* 当前扫描总命中计数 */
    /* 延迟命中记录（扫描结束后批量写入 SQLite） */
    CHAR    MatchedRules[WKD_YARA_MAX_MATCHED_RULES][128];
    ULONG   PerRuleCounts[WKD_YARA_MAX_MATCHED_RULES];  /* 每规则命中数 */
    ULONG   MatchedCount;       /* 已记录的唯一规则数 */
} WKD_YARA_CB_CTX, *PWKD_YARA_CB_CTX;

/* 异步队列任务 */
typedef struct { GUID NodeId; WCHAR Path[DEF_MAX_PATH]; } YARA_TASK;

/*++
 * WriteYaraAlert
 *   YARA 命中告警落库到 cg_alerts 表。
 *--*/
static VOID
WriteYaraAlert(
    _In_ PCWSTR FilePath,
    _In_ PCWSTR RuleName,
    _In_ ULONG Score,
    _In_ BOOLEAN IsAsync
)
{
    if (!WkdStorageEngine.WarmDb) return;

    sqlite3_stmt* stmt = NULL;
    CHAR alertId[64];
    LARGE_INTEGER now;
    GetSystemTimeAsFileTime((PFILETIME)&now);
    _snprintf_s(alertId, sizeof(alertId), _TRUNCATE,
                "YARA-%llx-%08lx", now.QuadPart, (ULONG)(ULONG_PTR)FilePath);

    CHAR desc[2048] = {0};
    {
        CHAR pathA[DEF_MAX_PATH * 2] = {0};
        WideCharToMultiByte(CP_UTF8, 0, FilePath, -1, pathA, sizeof(pathA), NULL, NULL);
        CHAR ruleA[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, RuleName, -1, ruleA, sizeof(ruleA), NULL, NULL);
        _snprintf_s(desc, sizeof(desc), _TRUNCATE,
                    "YARA %s: %s matched %s",
                    IsAsync ? "async" : "sync", pathA, ruleA);
    }

    const char* sql =
        "INSERT INTO cg_alerts "
        "(alert_id,timestamp,process_node_id,rule_name,mitre_id,"
        "severity,score,confidence,description) "
        "VALUES (?,?,?,?,?,?,?,?,?)";

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return;

    INT severity = (Score > 75) ? 4 : (Score > 50) ? 3 : (Score > 25) ? 2 : 1;

    CHAR ruleA[256] = {0};
    WideCharToMultiByte(CP_UTF8, 0, RuleName, -1, ruleA, sizeof(ruleA), NULL, NULL);

    sqlite3_bind_text(stmt, 1, alertId, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, now.QuadPart);
    sqlite3_bind_text(stmt, 3, "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, ruleA, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, "", -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, severity);
    sqlite3_bind_int(stmt, 7, (int)Score);
    sqlite3_bind_int(stmt, 8, 80);
    sqlite3_bind_text(stmt, 9, desc, -1, SQLITE_STATIC);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    WkdStorageEngine.WarmWrites++;
}

/*++
 * IocYara_ThreatLevelToScore
 *   将 YARA 规则元数据 threat_level（整数 0-4）映射为 0-100 评分。
 *--*/
static ULONG IocYara_ThreatLevelToScore(_In_ int Level)
{
    switch (Level) {
        case 0: return 0;
        case 1: return 25;
        case 2: return 50;
        case 3: return 75;
        case 4: return 100;
        default: return 50;
    }
}

/*++
 * IocYara_ScanCallback
 *   yr_rules_scan_mem 的 C 回调（CALLBACK_MSG_RULE_MATCHING）。
 *   参考 PhantomSensor YaraRuleStore::PerformScan 回调（行 2064-2182）：
 *     - 每规则匹配上限（maxMatchesPerRule → PerRuleCount）
 *     - 总匹配上限（MAX_TOTAL_MATCHES → CALLBACK_ABORT）
 *     - 延迟命中计数（不在此回调中做 SQLite 写入）
 *--*/
static int IocYara_ScanCallback(
    _In_ YR_SCAN_CONTEXT* Context,
    _In_ int Message,
    _In_ void* MessageData,
    _In_ void* UserData)
{
    UNREFERENCED_PARAMETER(Context);
    if (Message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;

    YR_RULE* rule = (YR_RULE*)MessageData;
    if (!rule || !rule->identifier || !UserData) return CALLBACK_CONTINUE;

    PWKD_YARA_CB_CTX ctx = (PWKD_YARA_CB_CTX)UserData;

    /* DoS 防护 1：总命中数超限 → 立即中止扫描 */
    ctx->MatchCount++;
    if (ctx->MatchCount > WKD_YARA_MAX_TOTAL_MATCHES) {
        return CALLBACK_ABORT;
    }

    ctx->Hit = TRUE;

    /* 规则全名 = 命名空间::标识符 */
    const char* ns = (rule->ns && rule->ns->name) ? rule->ns->name : "default";
    char fullName[160];
    _snprintf_s(fullName, sizeof(fullName), _TRUNCATE, "%s::%s", ns, rule->identifier);

    /* 取 threat_level 元数据；缺省中危 50 */
    ULONG score = 50;
    YR_META* meta = NULL;
    yr_rule_metas_foreach(rule, meta) {
        if (meta && meta->identifier &&
            _stricmp(meta->identifier, "threat_level") == 0) {
            if (meta->type == META_TYPE_INTEGER) {
                score = IocYara_ThreatLevelToScore((int)meta->integer);
            }
        }
    }

    /* 取最高威胁 */
    if (score > ctx->TopScore) {
        ctx->TopScore = score;
        strncpy_s(ctx->TopRule, sizeof(ctx->TopRule), fullName, _TRUNCATE);
    }

    /* 收集命中规则名 + 每规则上限检测 */
    {
        BOOLEAN found = FALSE;
        for (ULONG i = 0; i < ctx->MatchedCount; i++) {
            if (_stricmp(ctx->MatchedRules[i], fullName) == 0) {
                /* DoS 防护 2：该规则已超每规则匹配上限 → 不记录也不打标 */
                ctx->PerRuleCounts[i]++;
                if (ctx->PerRuleCounts[i] > WKD_YARA_MAX_MATCHES_PER_RULE) {
                    return CALLBACK_CONTINUE;
                }
                found = TRUE;
                break;
            }
        }
        if (!found && ctx->MatchedCount < WKD_YARA_MAX_MATCHED_RULES) {
            strncpy_s(ctx->MatchedRules[ctx->MatchedCount],
                      sizeof(ctx->MatchedRules[0]), fullName, _TRUNCATE);
            ctx->PerRuleCounts[ctx->MatchedCount] = 1;
            ctx->MatchedCount++;
        }
    }

    return CALLBACK_CONTINUE;
}

/*++
 * IocYara_UpdateHitCounts
 *   扫描结束后（锁外）批量更新 SQLite hit_count。
 *   参考 PhantomSensor：延迟命中计数（PerformScan 返回后 UpdateRuleHitCount）。
 *--*/
static VOID
IocYara_UpdateHitCounts(
    _In_ PWKD_YARA_CB_CTX Ctx
)
{
    if (!Ctx || Ctx->MatchedCount == 0) return;

    for (ULONG i = 0; i < Ctx->MatchedCount; i++) {
        /* 仅取规则名（去掉命名空间前缀） */
        CHAR* ruleName = Ctx->MatchedRules[i];
        PCSTR sep = strstr(ruleName, "::");
        if (sep) {
            ruleName = (CHAR*)(sep + 2);
        }
        YaraRule_IncrementHitCount(ruleName);
    }
}

/*====================================================================*/
/*  异步队列部分                                                      */
/*====================================================================*/

static PVOID IocYara_Handler(PVOID Ctx, ULONG Type, PWKD_MESSAGE Msg)
{
    PIOC_YARA_SCANNER s = (PIOC_YARA_SCANNER)Ctx;
    YARA_TASK* t = (YARA_TASK*)Msg->Body;
    UNREFERENCED_PARAMETER(Type);

    BOOLEAN detected = FALSE;
    ULONG score = 0;
    WCHAR ruleName[128] = {0};
    NTSTATUS st = IocYara_ScanFile(t->Path, &detected, &score, ruleName, ARRAYSIZE(ruleName));
    if (NT_SUCCESS(st) && detected) {
        printf("[IocYara] Async hit: %S rule=%S score=%u\n", t->Path, ruleName, score);
        WriteYaraAlert(t->Path, ruleName, score, TRUE);
    } else {
        printf("[IocYara] Async scan: %S (no hit / fail-open)\n", t->Path);
    }

    s->Completed++;
    return NULL;
}

/*====================================================================*/
/*  公开 API                                                          */
/*====================================================================*/

NTSTATUS
IocYara_Initialize(
    PIOC_YARA_SCANNER Scaner
    )
{
    if (!Scaner) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Scaner, sizeof(IOC_YARA_SCANNER));
    NtfInitializeMessageQueueMessageQueue(&Scaner->Queue, WKD_YARA_QUEUE_MAX_PENDING,
                                          IocYara_Handler, Scaner);
    Scaner->Initialized = TRUE;
    printf("[IocYara] Initialized (scanner ready, rules in YaraRule)\n");
    return STATUS_SUCCESS;
}

VOID IocYara_Cleanup(PIOC_YARA_SCANNER S)
{
    if (!S || !S->Initialized) return;
    S->Running = FALSE;
    WkdMsgQueueStopProcessing(&S->Queue);
    WkdMsgQueueCleanup(&S->Queue);
    printf("[IocYara] Cleanup: enq=%lld comp=%lld\n", S->Enqueued, S->Completed);
}

NTSTATUS IocYara_Enqueue(PIOC_YARA_SCANNER S, PWKD_PROCESS Node)
{
    if (!S || !S->Initialized || !Node) return STATUS_INVALID_PARAMETER;

    YARA_TASK task; WKD_MESSAGE msg;
    RtlZeroMemory(&task, sizeof(task)); RtlZeroMemory(&msg, sizeof(msg));
    task.NodeId = Node->NodeId;
    if (Node->ImagePath && Node->ImagePath->Buffer)
        wcsncpy_s(task.Path, DEF_MAX_PATH, Node->ImagePath->Buffer, _TRUNCATE);

    msg.Header.BodySize = sizeof(YARA_TASK);
    memcpy(msg.Body, &task, sizeof(YARA_TASK));

    NTSTATUS st = WkdMsgQueueEnqueue(&S->Queue, 0, WkdMsgPriority_Normal, &msg,
        sizeof(WKD_MESSAGE_HEADER) + sizeof(YARA_TASK));
    if (NT_SUCCESS(st)) S->Enqueued++;
    return st;
}

/*====================================================================*/
/*  同步文件扫描（机制 A 核心，供 YaraScanPort 调用）                    */
/*====================================================================*/

NTSTATUS
IocYara_ScanFile(
    _In_ PCWSTR FilePath,
    _Out_ PBOOLEAN Detected,
    _Out_ PULONG Score,
    _Out_writes_opt_(RuleNameCch) PWCHAR RuleName,
    _In_ ULONG RuleNameCch
    )
{
    if (Detected) *Detected = FALSE;
    if (Score) *Score = 0;
    if (RuleName && RuleNameCch) RuleName[0] = L'\0';
    if (!FilePath || !FilePath[0]) return STATUS_INVALID_PARAMETER;

    PSRWLOCK lock = YaraRule_GetLock();
    YR_RULES* rules = YaraRule_GetRules();

    /* Level 1: 共享锁保护 rules 指针不被并发重载释放 */
    AcquireSRWLockShared(lock);
    if (!rules) {
        ReleaseSRWLockShared(lock);
        return STATUS_UNSUCCESSFUL;
    }

    /* 打开文件 */
    HANDLE hFile = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        ReleaseSRWLockShared(lock);
        return STATUS_UNSUCCESSFUL;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0 ||
        (ULONGLONG)fileSize.QuadPart > WKD_MAX_FILE_SIZE) {
        CloseHandle(hFile);
        ReleaseSRWLockShared(lock);
        return STATUS_UNSUCCESSFUL;
    }

    /* 内存映射 */
    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hMap) {
        ReleaseSRWLockShared(lock);
        return STATUS_UNSUCCESSFUL;
    }

    PVOID view = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!view) {
        CloseHandle(hMap);
        ReleaseSRWLockShared(lock);
        return STATUS_UNSUCCESSFUL;
    }

    /* Level 2: 扫描锁串行化 yr_rules_scan_mem（YARA 非线程安全） */
    YaraRule_AcquireScanLock();

    WKD_YARA_CB_CTX ctx;
    RtlZeroMemory(&ctx, sizeof(ctx));

    int yrErr = yr_rules_scan_mem(rules,
                                  (const uint8_t*)view,
                                  (size_t)fileSize.QuadPart,
                                  0,
                                  IocYara_ScanCallback,
                                  &ctx,
                                  WKD_YARA_SCAN_TIMEOUT_SEC);

    YaraRule_ReleaseScanLock();   /* Level 2 先释放 */
    ReleaseSRWLockShared(lock);   /* Level 1 后释放 */

    UnmapViewOfFile(view);
    CloseHandle(hMap);

    if (yrErr != ERROR_SUCCESS && yrErr != ERROR_COULD_NOT_MAP_FILE) {
        return STATUS_UNSUCCESSFUL;
    }

    /* 锁外批量更新 hit_count */
    IocYara_UpdateHitCounts(&ctx);

    if (ctx.Hit) {
        if (Detected) *Detected = TRUE;
        if (Score) *Score = ctx.TopScore;
        if (RuleName && RuleNameCch) {
            size_t i;
            SIZE_T nameLen = strnlen(ctx.TopRule, sizeof(ctx.TopRule));
            for (i = 0; i < nameLen && i < RuleNameCch - 1; i++)
                RuleName[i] = (WCHAR)(UCHAR)ctx.TopRule[i];
            RuleName[i] = L'\0';
        }
    }
    return STATUS_SUCCESS;
}

/*====================================================================*/
/*  通用内存缓冲扫描（供 PackerDetector / 加壳检测等模块调用）           */
/*====================================================================*/

NTSTATUS
IocYara_ScanBuffer(
    _In_ const BYTE* Buffer,
    _In_ ULONG BufferSize,
    _Out_ PBOOLEAN Detected,
    _Out_ PULONG Score,
    _Out_writes_opt_(RuleNameCch) PWCHAR RuleName,
    _In_ ULONG RuleNameCch
    )
{
    if (Detected) *Detected = FALSE;
    if (Score) *Score = 0;
    if (RuleName && RuleNameCch) RuleName[0] = L'\0';
    if (!Buffer || BufferSize == 0) return STATUS_INVALID_PARAMETER;

    PSRWLOCK lock = YaraRule_GetLock();
    YR_RULES* rules = YaraRule_GetRules();

    /* Level 1: 共享锁保护 rules 指针 */
    AcquireSRWLockShared(lock);
    if (!rules) {
        ReleaseSRWLockShared(lock);
        return STATUS_UNSUCCESSFUL;
    }

    /* Level 2: 扫描锁串行化 */
    YaraRule_AcquireScanLock();

    WKD_YARA_CB_CTX ctx;
    RtlZeroMemory(&ctx, sizeof(ctx));

    int yrErr = yr_rules_scan_mem(rules,
                                  (const uint8_t*)Buffer,
                                  (size_t)BufferSize,
                                  0,
                                  IocYara_ScanCallback,
                                  &ctx,
                                  WKD_YARA_SCAN_TIMEOUT_SEC);

    YaraRule_ReleaseScanLock();   /* Level 2 */
    ReleaseSRWLockShared(lock);   /* Level 1 */

    if (yrErr != ERROR_SUCCESS && yrErr != ERROR_COULD_NOT_MAP_FILE) {
        return STATUS_UNSUCCESSFUL;
    }

    /* 锁外批量更新 hit_count */
    IocYara_UpdateHitCounts(&ctx);

    if (ctx.Hit) {
        if (Detected) *Detected = TRUE;
        if (Score) *Score = ctx.TopScore;
        if (RuleName && RuleNameCch) {
            size_t i;
            SIZE_T nameLen = strnlen(ctx.TopRule, sizeof(ctx.TopRule));
            for (i = 0; i < nameLen && i < RuleNameCch - 1; i++)
                RuleName[i] = (WCHAR)(UCHAR)ctx.TopRule[i];
            RuleName[i] = L'\0';
        }
    }
    return STATUS_SUCCESS;
}
