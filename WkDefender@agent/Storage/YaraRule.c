/**************************************************/
/*  WkDefender YARA 规则管理模块实现                */
/*  规则导入(.yar) → SQLite 存储 → 编译缓存 → 热重载 */
/**************************************************/

#include "YaraRule.h"
#include "StorageEngine.h"
#include "../Common/TitaniumLimits.h"
#include "../Common/YaraUtils.h"
#include "../WkDefenderHeader.h"
#include <sqlite3.h>

/*====================================================================*/
/*  全局规则状态（遵循锁层次：Level1 g_YaraLock, Level2 g_YaraScanLock）*/
/*====================================================================*/

static YR_RULES*  g_YaraRules     = NULL;
static SRWLOCK    g_YaraLock      = SRWLOCK_INIT;       /* Level 1 */
static SRWLOCK    g_YaraScanLock  = SRWLOCK_INIT;       /* Level 2 */
static LONG       g_YaraInitGuard = 0;   /* 0=未初始化 1=已初始化 */
static LONG       g_YaraInitLock  = 0;   /* 自旋互斥，保护单例切换 */

/*====================================================================*/
/*  规则访问接口（供扫描器 IocYaraScanner 使用）                       */
/*====================================================================*/

YR_RULES* YaraRule_GetRules(VOID)
{
    return g_YaraRules;
}

PSRWLOCK YaraRule_GetLock(VOID)
{
    return &g_YaraLock;
}

VOID YaraRule_AcquireScanLock(VOID)
{
    AcquireSRWLockExclusive(&g_YaraScanLock);
}

VOID YaraRule_ReleaseScanLock(VOID)
{
    ReleaseSRWLockExclusive(&g_YaraScanLock);
}

/*====================================================================*/
/*  编译缓存 — compiled_rule BLOB 读写                                */
/*====================================================================*/

/*++
 * YaraRule_SaveRulesToBlob
 *   把 YR_RULES* 序列化到内存缓冲（先写临时文件，再读回）。
 *   调用方负责用 UtHeapFree 释放 *OutBlob。
 *   参考 PhantomSensor YaraCompiler::SaveToBuffer。
 *--*/
static BYTE*
YaraRule_SaveRulesToBlob(
    _In_ YR_RULES* Rules,
    _Out_ PULONG OutSize
)
{
    if (!Rules || !OutSize) return NULL;
    *OutSize = 0;

    /* 1. 写临时文件 */
    WCHAR tempPath[MAX_PATH] = {0};
    WCHAR tempFile[MAX_PATH] = {0};
    if (GetTempPathW(MAX_PATH, tempPath) == 0) return NULL;
    if (GetTempFileNameW(tempPath, L"yr", 0, tempFile) == 0) return NULL;

    char tempFileA[MAX_PATH] = {0};
    WideCharToMultiByte(CP_UTF8, 0, tempFile, -1, tempFileA, MAX_PATH, NULL, NULL);

    int yrErr = yr_rules_save(Rules, tempFileA);
    if (yrErr != ERROR_SUCCESS) {
        DeleteFileW(tempFile);
        return NULL;
    }

    /* 2. 读回缓冲 */
    HANDLE hFile = CreateFileW(tempFile, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DeleteFileW(tempFile);
        return NULL;
    }

    LARGE_INTEGER fs;
    if (!GetFileSizeEx(hFile, &fs) || fs.QuadPart == 0 ||
        fs.QuadPart > (LONGLONG)WKD_MAX_COMPILED_RULES_SIZE) {
        CloseHandle(hFile);
        DeleteFileW(tempFile);
        return NULL;
    }

    ULONG blobSize = (ULONG)fs.QuadPart;
    BYTE* blob = (BYTE*)UtHeapAlloc(blobSize);
    if (!blob) {
        CloseHandle(hFile);
        DeleteFileW(tempFile);
        return NULL;
    }

    DWORD readBytes = 0;
    if (!ReadFile(hFile, blob, blobSize, &readBytes, NULL) || readBytes != blobSize) {
        UtHeapFree(blob);
        CloseHandle(hFile);
        DeleteFileW(tempFile);
        return NULL;
    }

    CloseHandle(hFile);
    DeleteFileW(tempFile);

    *OutSize = blobSize;
    return blob;
}

/*++
 * YaraRule_LoadRulesFromBlob
 *   从 compiled_rule BLOB 加载 YR_RULES*。
 *   流程：写临时文件 → yr_rules_load → 删除临时文件。
 *   参考 PhantomSensor YaraRuleStore::LoadRulesInternal（行 3493）。
 *--*/
static YR_RULES*
YaraRule_LoadRulesFromBlob(
    _In_ const BYTE* Blob,
    _In_ ULONG BlobSize
)
{
    if (!Blob || BlobSize == 0) return NULL;

    /* 写临时文件（yr_rules_load 需要文件路径） */
    WCHAR tempPath[MAX_PATH] = {0};
    WCHAR tempFile[MAX_PATH] = {0};
    if (GetTempPathW(MAX_PATH, tempPath) == 0) return NULL;
    if (GetTempFileNameW(tempPath, L"yr", 0, tempFile) == 0) return NULL;

    HANDLE hFile = CreateFileW(tempFile, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DeleteFileW(tempFile);
        return NULL;
    }

    DWORD written = 0;
    WriteFile(hFile, Blob, BlobSize, &written, NULL);
    CloseHandle(hFile);

    if (written != BlobSize) {
        DeleteFileW(tempFile);
        return NULL;
    }

    YR_RULES* rules = NULL;
    int yrErr = yr_rules_load(tempFile, &rules);

    DeleteFileW(tempFile);

    if (yrErr != ERROR_SUCCESS || !rules) return NULL;
    return rules;
}

/*++
 * YaraRule_UpdateCompiledBlob
 *   把当前 g_YaraRules 序列化并回写到 SQLite yara_rules 表的 compiled_rule。
 *   调用方须已持 g_YaraLock Shared（锁外可安全调 SQLite）。
 *--*/
static NTSTATUS
YaraRule_UpdateCompiledBlob(VOID)
{
    if (!g_YaraRules) return STATUS_UNSUCCESSFUL;

    ULONG blobSize = 0;
    BYTE* blob = YaraRule_SaveRulesToBlob(g_YaraRules, &blobSize);
    if (!blob || blobSize == 0) {
        if (blob) UtHeapFree(blob);
        return STATUS_UNSUCCESSFUL;
    }

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb,
            "UPDATE yara_rules SET compiled_rule=? WHERE rowid IN "
            "(SELECT MIN(rowid) FROM yara_rules WHERE enabled=1)",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(stmt, 1, blob, (int)blobSize, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    UtHeapFree(blob);
    return STATUS_SUCCESS;
}

/*++
 * YaraRule_TryLoadCompiledBlob
 *   尝试从 SQLite compiled_rule 列加载全部规则。成功返回 YR_RULES*。
 *--*/
static YR_RULES*
YaraRule_TryLoadCompiledBlob(VOID)
{
    if (!WkdStorageEngine.WarmDb) return NULL;

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb,
            "SELECT compiled_rule FROM yara_rules WHERE enabled=1 "
            "AND compiled_rule IS NOT NULL LIMIT 1",
            -1, &stmt, NULL) != SQLITE_OK) return NULL;

    YR_RULES* rules = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* blob = sqlite3_column_blob(stmt, 0);
        int size = sqlite3_column_bytes(stmt, 0);
        if (blob && size > 0) {
            rules = YaraRule_LoadRulesFromBlob((const BYTE*)blob, (ULONG)size);
        }
    }
    sqlite3_finalize(stmt);
    return rules;
}

/*====================================================================*/
/*  核心：从 SQLite 源码编译规则                                      */
/*====================================================================*/

/*++
 * YaraRule_CompileFromSource
 *   从 yara_rules 表选取全部 enabled 规则源码，用 yr_compiler 编译。
 *   返回新分配的 YR_RULES*（调用方负责 yr_rules_destroy）。
 *   此函数不做锁定，调用方须确保 g_YaraLock 已持 Exclusive。
 *   参考 PhantomSensor AddRulesFromSource + 合并逻辑。
 *--*/
static YR_RULES*
YaraRule_CompileFromSource(VOID)
{
    if (!WkdStorageEngine.WarmDb) return NULL;

    YR_COMPILER* compiler = NULL;
    int yrErr = yr_compiler_create(&compiler);
    if (yrErr != ERROR_SUCCESS || !compiler) {
        printf("[YaraRule] yr_compiler_create failed: %d\n", yrErr);
        return NULL;
    }

    sqlite3_stmt* stmt = NULL;
    const char* sql = "SELECT rule_text FROM yara_rules WHERE enabled=1";
    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK) {
        printf("[YaraRule] prepare yara_rules failed: %s\n",
               sqlite3_errmsg(WkdStorageEngine.WarmDb));
        yr_compiler_destroy(compiler);
        return NULL;
    }

    int ruleCount = 0;
    int addErrors = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* ruleText = (const char*)sqlite3_column_text(stmt, 0);
        if (!ruleText) continue;
        if (yr_compiler_add_string(compiler, ruleText, NULL) != 0) {
            addErrors++;
            continue;
        }
        ruleCount++;
    }
    sqlite3_finalize(stmt);

    if (ruleCount == 0) {
        printf("[YaraRule] No enabled YARA rules in storage (addErrors=%d)\n", addErrors);
        yr_compiler_destroy(compiler);
        return NULL;
    }

    YR_RULES* rules = NULL;
    yrErr = yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);

    if (yrErr != ERROR_SUCCESS || !rules) {
        printf("[YaraRule] yr_compiler_get_rules failed: %d\n", yrErr);
        return NULL;
    }

    printf("[YaraRule] Compiled %d YARA rule(s) (addErrors=%d)\n", ruleCount, addErrors);
    return rules;
}

/*====================================================================*/
/*  YaraRule_Recompile — 热重载（含编译缓存）                          */
/*====================================================================*/

NTSTATUS
YaraRule_Recompile(
    VOID
    )
{
    if (!WkdStorageEngine.WarmDb) return STATUS_UNSUCCESSFUL;

    /* Level 1 Exclusive — 保护 g_YaraRules 指针替换 */
    AcquireSRWLockExclusive(&g_YaraLock);

    YR_RULES* newRules = NULL;

    /* 1. 尝试从 compiled_rule BLOB 加载（加速启动） */
    newRules = YaraRule_TryLoadCompiledBlob();

    /* 2. BLOB 不存在或加载失败 → 从源码编译 */
    if (!newRules) {
        newRules = YaraRule_CompileFromSource();
        if (newRules) {
            ULONG blobSize = 0;
            BYTE* blob = YaraRule_SaveRulesToBlob(newRules, &blobSize);
            if (blob) UtHeapFree(blob);  /* 编译缓存回填在锁外另做 */
        }
    }

    /* 3. 热替换 */
    YR_RULES* oldRules = g_YaraRules;
    g_YaraRules = newRules;
    ReleaseSRWLockExclusive(&g_YaraLock);   /* Level 1 释放 */

    if (oldRules) yr_rules_destroy(oldRules);

    if (!newRules) {
        printf("[YaraRule] Recompile: no rules loaded\n");
        return STATUS_NOT_FOUND;
    }

    /* 4. 锁外回填 compiled_rule BLOB（SQLite 操作在锁外执行，防死锁） */
    AcquireSRWLockShared(&g_YaraLock);
    YaraRule_UpdateCompiledBlob();
    ReleaseSRWLockShared(&g_YaraLock);

    printf("[YaraRule] Recompile: rules reloaded successfully\n");
    return STATUS_SUCCESS;
}

/*====================================================================*/
/*  规则导入                                                          */
/*====================================================================*/

NTSTATUS
YaraRule_ImportFile(
    _In_ PCWSTR FilePath,
    _In_opt_ PCSTR Namespace
)
{
    NTSTATUS status;

    if (!FilePath || !FilePath[0]) return STATUS_INVALID_PARAMETER;
    UNREFERENCED_PARAMETER(Namespace);

    /* 1. 路径规范化 + CWE-22 防遍历（参考 PhantomSensor ValidateAndCanonicalizePath） */
    WCHAR canonicalPath[MAX_PATH] = {0};
    if (!YaraUtils_ValidateAndCanonicalizePath(FilePath, canonicalPath)) {
        printf("[YaraRule] Invalid path (CWE-22 reject): %S\n", FilePath);
        return STATUS_INVALID_PARAMETER;
    }

    /* 2. 打开文件 */
    HANDLE hFile = CreateFileW(canonicalPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[YaraRule] Cannot open file: %S\n", canonicalPath);
        return STATUS_UNSUCCESSFUL;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0 ||
        fileSize.QuadPart > (LONGLONG)WKD_MAX_RULE_FILE_SIZE) {
        printf("[YaraRule] File too large or empty: %S\n", canonicalPath);
        CloseHandle(hFile);
        return STATUS_UNSUCCESSFUL;
    }

    /* 3. 读取内容 */
    ULONG size = (ULONG)fileSize.QuadPart;
    PCHAR content = (PCHAR)UtHeapAlloc(size + 1);
    if (!content) {
        CloseHandle(hFile);
        return STATUS_NO_MEMORY;
    }

    DWORD readBytes = 0;
    if (!ReadFile(hFile, content, size, &readBytes, NULL) || readBytes != size) {
        printf("[YaraRule] ReadFile failed: %S\n", canonicalPath);
        UtHeapFree(content);
        CloseHandle(hFile);
        return STATUS_UNSUCCESSFUL;
    }
    content[size] = '\0';
    CloseHandle(hFile);

    /* 4. 语法预校验（使用 YaraUtils） */
    if (!YaraUtils_ValidateSyntax(content)) {
        printf("[YaraRule] Syntax validation failed: %S\n", canonicalPath);
        UtHeapFree(content);
        return STATUS_UNSUCCESSFUL;
    }

    /*============================================================*/
    /*  5. 生成 basename（用作 rule_id 前缀，如 "malware_rules"）   */
    /*============================================================*/

    CHAR basename[128] = {0};
    {
        PCWSTR baseName = wcsrchr(canonicalPath, L'\\');
        if (!baseName) baseName = wcsrchr(canonicalPath, L'/');
        if (!baseName) baseName = canonicalPath; else baseName++;
        WCHAR nameBuf[128] = {0};
        wcsncpy_s(nameBuf, sizeof(nameBuf) / sizeof(WCHAR), baseName, _TRUNCATE);
        PWCHAR dot = wcschr(nameBuf, L'.');
        if (dot) *dot = L'\0';
        WideCharToMultiByte(CP_UTF8, 0, nameBuf, -1, basename, sizeof(basename), NULL, NULL);
    }

    /*============================================================*/
    /*  6. 将文件内容拆分为独立规则                                 */
    /*============================================================*/

    /* SplitYarContent 返回的每条 RuleContent 包含：
     *   preamble（import "pe" 等文件级声明）+ 单条规则体
     * 原因：YARA 编译器没有"全局共享 imports"机制，import 必须
     * 和引用它的规则在同一个 yr_compiler_add_string 调用中。
     * 详见 YaraUtils.h YARA_RULE_SPLIT 结构体注释。 */
    PYARA_RULE_SPLIT rules      = NULL;
    ULONG            ruleCount  = 0;

    status = YaraUtils_SplitYarContent(content, &rules, &ruleCount);
    if (!NT_SUCCESS(status) || ruleCount == 0) {
        printf("[YaraRule] No rules found in file: %S\n", canonicalPath);
        UtHeapFree(content);
        return STATUS_NOT_FOUND;
    }

    /*============================================================*/
    /*  7. 事务：删除旧规则 + 逐条插入新规则                       */
    /*============================================================*/

    CHAR prefix[160] = {0};
    snprintf(prefix, sizeof(prefix), "%s:", basename);

    sqlite3_exec(WkdStorageEngine.WarmDb, "BEGIN", NULL, NULL, NULL);

    /* 7a. 删除此文件之前导入的所有规则 */
    status = YaraRule_DeleteRulesByPrefix(prefix);
    if (!NT_SUCCESS(status)) {
        sqlite3_exec(WkdStorageEngine.WarmDb, "ROLLBACK", NULL, NULL, NULL);
        printf("[YaraRule] DeleteRulesByPrefix failed: %S\n", canonicalPath);
        for (ULONG i = 0; i < ruleCount; i++) UtHeapFree(rules[i].RuleContent);
        UtHeapFree(rules);
        UtHeapFree(content);
        return status;
    }

    /* 7b. 逐规则 Upsert */
    ULONG  okCount   = 0;
    ULONG  failCount = 0;
    BOOLEAN anyFailed = FALSE;

    for (ULONG i = 0; i < ruleCount; i++) {
        /* 提取元数据 */
        INT  threatLevel = 2;
        CHAR author[256]       = {0};
        CHAR description[1024] = {0};
        CHAR tags[512]         = {0};
        YaraUtils_ExtractMetadata(rules[i].RuleContent, &threatLevel,
                                  author, sizeof(author),
                                  description, sizeof(description),
                                  tags, sizeof(tags));

        /* 生成唯一 rule_id：basename:rulename */
        CHAR ruleId[256] = {0};
        snprintf(ruleId, sizeof(ruleId), "%s:%s", basename, rules[i].RuleName);

        NTSTATUS upSt = YaraRule_UpsertRule(
            ruleId, rules[i].RuleName, rules[i].RuleContent,
            NULL, 0,
            threatLevel,
            author[0] ? author : NULL,
            description[0] ? description : NULL,
            tags[0] ? tags : NULL,
            TRUE);

        if (NT_SUCCESS(upSt)) {
            okCount++;
        } else {
            failCount++;
            anyFailed = TRUE;
            printf("[YaraRule] Upsert failed for rule '%s' in %S\n",
                   rules[i].RuleName, canonicalPath);
        }
    }

    /* 7c. 若全部失败则回滚，否则提交 */
    if (anyFailed && okCount == 0) {
        sqlite3_exec(WkdStorageEngine.WarmDb, "ROLLBACK", NULL, NULL, NULL);
        printf("[YaraRule] All %u rules failed to import: %S\n", failCount, canonicalPath);
        for (ULONG i = 0; i < ruleCount; i++) UtHeapFree(rules[i].RuleContent);
        UtHeapFree(rules);
        UtHeapFree(content);
        return STATUS_UNSUCCESSFUL;
    }

    sqlite3_exec(WkdStorageEngine.WarmDb, "COMMIT", NULL, NULL, NULL);

    /*============================================================*/
    /*  8. 释放资源                                                */
    /*============================================================*/

    for (ULONG i = 0; i < ruleCount; i++) UtHeapFree(rules[i].RuleContent);
    UtHeapFree(rules);
    UtHeapFree(content);

    printf("[YaraRule] Imported: %S — %u rules OK, %u failed\n",
           canonicalPath, okCount, failCount);

    /* 9. 触发热重载 */
    return YaraRule_Recompile();
}

NTSTATUS
YaraRule_ImportDirectory(
    _In_ PCWSTR DirectoryPath
    )
{
    if (!DirectoryPath || !DirectoryPath[0]) return STATUS_INVALID_PARAMETER;

    /* 使用 YaraUtils_FindYaraFiles 发现所有 .yar/.yara 文件 */
    PWSTR* files = NULL;
    ULONG  fileCount = 0;
    NTSTATUS findSt = YaraUtils_FindYaraFiles(DirectoryPath, &files, &fileCount);
    if (!NT_SUCCESS(findSt) || !files || fileCount == 0) {
        printf("[YaraRule] ImportDirectory: %S — no yara files found\n", DirectoryPath);
        if (files) {
            for (ULONG i = 0; i < fileCount; i++) if (files[i]) UtHeapFree(files[i]);
            UtHeapFree(files);
        }
        return STATUS_NOT_FOUND;
    }

    ULONG importCount = 0;
    ULONG failCount = 0;

    for (ULONG i = 0; i < fileCount; i++) {
        if (!files[i]) continue;
        NTSTATUS st = YaraRule_ImportFile(files[i], NULL);
        if (NT_SUCCESS(st)) importCount++;
        else failCount++;
        UtHeapFree(files[i]);
    }
    UtHeapFree(files);

    printf("[YaraRule] ImportDirectory: %S — %u imported, %u failed\n",
           DirectoryPath, importCount, failCount);
    return (importCount > 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/*====================================================================*/
/*  SQLite 操作                                                       */
/*====================================================================*/

NTSTATUS
YaraRule_UpsertRule(
    _In_ PCSTR RuleId,
    _In_ PCSTR RuleName,
    _In_ PCSTR RuleText,
    _In_opt_ const void* CompiledBlob,
    _In_ ULONG CompiledBlobSize,
    _In_ INT ThreatLevel,
    _In_opt_ PCSTR Author,
    _In_opt_ PCSTR Description,
    _In_opt_ PCSTR Tags,
    _In_ BOOLEAN Enabled
)
{
    sqlite3_stmt* stmt = NULL;
    if (!WkdStorageEngine.WarmDb || !RuleId || !RuleName || !RuleText)
        return STATUS_INVALID_PARAMETER;

    const char* sql =
        "INSERT OR REPLACE INTO yara_rules "
        "(rule_id,rule_name,rule_text,compiled_rule,threat_level,"
        "author,description,tags,enabled,last_modified) "
        "VALUES (?,?,?,?,?,?,?,?,?,unixepoch())";

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK) {
        printf("[YaraRule] UpsertRule prepare failed: %s\n",
               sqlite3_errmsg(WkdStorageEngine.WarmDb));
        return STATUS_UNSUCCESSFUL;
    }

    sqlite3_bind_text(stmt, 1, RuleId, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, RuleName, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, RuleText, -1, SQLITE_STATIC);

    if (CompiledBlob && CompiledBlobSize > 0)
        sqlite3_bind_blob(stmt, 4, CompiledBlob, (int)CompiledBlobSize, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 4);

    sqlite3_bind_int(stmt, 5, ThreatLevel);
    sqlite3_bind_text(stmt, 6, Author ? Author : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, Description ? Description : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, Tags ? Tags : "", -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 9, Enabled ? 1 : 0);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        printf("[YaraRule] UpsertRule step failed: %s\n",
               sqlite3_errmsg(WkdStorageEngine.WarmDb));
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
YaraRule_DeleteRule(
    _In_ PCSTR RuleId
)
{
    sqlite3_stmt* stmt = NULL;
    if (!WkdStorageEngine.WarmDb || !RuleId) return STATUS_INVALID_PARAMETER;

    const char* sql = "DELETE FROM yara_rules WHERE rule_id=?";
    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;

    sqlite3_bind_text(stmt, 1, RuleId, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return STATUS_SUCCESS;
}

/*====================================================================*/
/*  YaraRule_DeleteRulesByPrefix                                       */
/*====================================================================*/

NTSTATUS
YaraRule_DeleteRulesByPrefix(
    _In_ PCSTR RuleIdPrefix
)
{
    if (!WkdStorageEngine.WarmDb || !RuleIdPrefix || !RuleIdPrefix[0])
        return STATUS_INVALID_PARAMETER;

    /* LIKE 'prefix%' 匹配所有以此开头的 rule_id */
    sqlite3_stmt* stmt = NULL;
    const char* sql = "DELETE FROM yara_rules WHERE rule_id LIKE ?";
    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;

    /* 构造 'prefix%' 模式字符串 */
    CHAR pattern[256] = {0};
    snprintf(pattern, sizeof(pattern), "%s%%", RuleIdPrefix);
    sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS
YaraRule_ListRules(
    _Out_ PYARA_RULE_INFO* OutRules,
    _Out_ PULONG OutCount
)
{
    sqlite3_stmt* stmt = NULL;
    if (!WkdStorageEngine.WarmDb || !OutRules || !OutCount)
        return STATUS_INVALID_PARAMETER;

    *OutRules = NULL;
    *OutCount = 0;

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb,
            "SELECT COUNT(*) FROM yara_rules", -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;
    sqlite3_step(stmt);
    ULONG count = (ULONG)sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    if (count == 0) return STATUS_SUCCESS;

    PYARA_RULE_INFO rules = (PYARA_RULE_INFO)UtHeapAlloc(sizeof(YARA_RULE_INFO) * count);
    if (!rules) return STATUS_NO_MEMORY;

    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb,
            "SELECT rule_id,rule_name,threat_level,enabled,hit_count "
            "FROM yara_rules ORDER BY rule_name",
            -1, &stmt, NULL) != SQLITE_OK) {
        UtHeapFree(rules);
        return STATUS_UNSUCCESSFUL;
    }

    ULONG idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < count) {
        const char* id = (const char*)sqlite3_column_text(stmt, 0);
        const char* name = (const char*)sqlite3_column_text(stmt, 1);
        strncpy_s(rules[idx].RuleId, sizeof(rules[idx].RuleId),
                  id ? id : "", _TRUNCATE);
        strncpy_s(rules[idx].RuleName, sizeof(rules[idx].RuleName),
                  name ? name : "", _TRUNCATE);
        rules[idx].ThreatLevel = sqlite3_column_int(stmt, 2);
        rules[idx].Enabled = sqlite3_column_int(stmt, 3) != 0;
        rules[idx].HitCount = sqlite3_column_int(stmt, 4);
        idx++;
    }
    sqlite3_finalize(stmt);

    *OutRules = rules;
    *OutCount = idx;
    return STATUS_SUCCESS;
}

NTSTATUS
YaraRule_IncrementHitCount(
    _In_ PCSTR RuleName
)
{
    sqlite3_stmt* stmt = NULL;
    if (!WkdStorageEngine.WarmDb || !RuleName) return STATUS_INVALID_PARAMETER;

    const char* sql =
        "UPDATE yara_rules SET hit_count = hit_count + 1 "
        "WHERE rule_name=? AND enabled=1";
    if (sqlite3_prepare_v2(WkdStorageEngine.WarmDb, sql, -1, &stmt, NULL) != SQLITE_OK)
        return STATUS_UNSUCCESSFUL;

    sqlite3_bind_text(stmt, 1, RuleName, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return STATUS_SUCCESS;
}

/*====================================================================*/
/*  生命周期                                                          */
/*====================================================================*/

NTSTATUS
YaraRule_Initialize(
    VOID
    )
{
    /* 进程级 yr_initialize 单例 */
    while (InterlockedCompareExchange(&g_YaraInitLock, 1, 0) != 0) {
        SwitchToThread();
    }
    if (InterlockedCompareExchange(&g_YaraInitGuard, 1, 0) == 0) {
        int yrErr = yr_initialize();
        if (yrErr != ERROR_SUCCESS) {
            printf("[YaraRule] yr_initialize failed: %d\n", yrErr);
            InterlockedExchange(&g_YaraInitGuard, 0);
            InterlockedExchange(&g_YaraInitLock, 0);
            return STATUS_UNSUCCESSFUL;
        }
    }
    InterlockedExchange(&g_YaraInitLock, 0);

    InitializeSRWLock(&g_YaraLock);
    InitializeSRWLock(&g_YaraScanLock);  /* Level 2 扫描锁 */

    /* 首次编译规则 */
    NTSTATUS status = YaraRule_Recompile();
    if (!NT_SUCCESS(status) && status != STATUS_NOT_FOUND) {
        printf("[YaraRule] Initial compile returned 0x%X\n", status);
    }

    printf("[YaraRule] Initialized\n");
    return STATUS_SUCCESS;
}

VOID
YaraRule_Cleanup(VOID)
{
    /* 参考 PhantomSensor Close() 独占锁防扫描 UAF */
    /* 注意：Cleanup 必须等在 IocYara_Cleanup 之后调用（消息队列已停） */
    AcquireSRWLockExclusive(&g_YaraLock);   /* Level 1 Exclusive — 等待所有扫描结束 */
    if (g_YaraRules) {
        yr_rules_destroy(g_YaraRules);
        g_YaraRules = NULL;
    }
    ReleaseSRWLockExclusive(&g_YaraLock);

    /* yr_finalize 单例 */
    while (InterlockedCompareExchange(&g_YaraInitLock, 1, 0) != 0) {
        SwitchToThread();
    }
    if (InterlockedCompareExchange(&g_YaraInitGuard, 0, 1) == 1) {
        yr_finalize();
    }
    InterlockedExchange(&g_YaraInitLock, 0);

    printf("[YaraRule] Cleanup\n");
}
