/**************************************************/
/*  WkDefender YARA 规则管理模块                    */
/*  职责：规则导入(.yar)、存储(SQLite)、编译缓存、热重载 */
/*  参考 PhantomSensor SignatureStore/YaraRuleStore.hpp/.cpp */
/**************************************************/

#pragma once

#include <windows.h>
#include <yara.h>

#ifdef __cplusplus
extern "C" {
#endif

/*====================================================================*/
/*  锁层次声明                                                        */
/*====================================================================*/

/*
 *  锁层次（Level 编号，所有模块必须遵循此获取顺序）：
 *    Level 1: g_YaraLock     — 保护 g_YaraRules 指针生命周期
 *    Level 2: g_YaraScanLock — 串行化 yr_rules_scan_mem（YARA 非线程安全）
 *    Level 3: SQLite 内部锁  — sqlite3_mutex 自动管理
 *
 *  典型获取路径：
 *    扫描：   AcquireShared(Level1) → AcquireExclusive(Level2) → yr_rules_scan_mem
 *               → Release(Level2) → Release(Level1)
 *    重载：   AcquireExclusive(Level1) → 替换 rules 指针 → Release(Level1)
 *              → （锁外）SQLite 操作
 *    Cleanup： AcquireExclusive(Level1) → 销毁 rules → Release(Level1)
 *              → yr_finalize
 */

/*====================================================================*/
/*  规则信息结构（供 ListRules 输出）                                  */
/*====================================================================*/

typedef struct _YARA_RULE_INFO {
    CHAR    RuleId[64];
    CHAR    RuleName[256];
    INT     ThreatLevel;
    BOOLEAN Enabled;
    INT     HitCount;
} YARA_RULE_INFO, *PYARA_RULE_INFO;

/*====================================================================*/
/*  生命周期                                                          */
/*====================================================================*/

NTSTATUS YaraRule_Initialize(VOID);
VOID     YaraRule_Cleanup(VOID);

/*====================================================================*/
/*  供扫描器访问                                                      */
/*====================================================================*/

YR_RULES* YaraRule_GetRules(VOID);
PSRWLOCK  YaraRule_GetLock(VOID);

/*++
 * YaraRule_AcquireScanLock / YaraRule_ReleaseScanLock
 *   串行化 YARA 扫描（yr_rules_scan_mem 非线程安全）。
 *   用法：
 *       AcquireSRWLockShared(YaraRule_GetLock());      // Level 1: 保护 rules 指针
 *       YaraRule_AcquireScanLock();                     // Level 2: 串行化扫描
 *       yr_rules_scan_mem(rules, ...);
 *       YaraRule_ReleaseScanLock();
 *       ReleaseSRWLockShared(YaraRule_GetLock());
 *--*/
VOID YaraRule_AcquireScanLock(VOID);
VOID YaraRule_ReleaseScanLock(VOID);

/*====================================================================*/
/*  规则管理                                                          */
/*====================================================================*/

NTSTATUS YaraRule_ImportFile(
    _In_ PCWSTR FilePath,
    _In_opt_ PCSTR Namespace
);

NTSTATUS YaraRule_ImportDirectory(
    _In_ PCWSTR DirectoryPath
);

NTSTATUS YaraRule_Recompile(VOID);

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
);

NTSTATUS YaraRule_DeleteRule(_In_ PCSTR RuleId);

/*++
 * YaraRule_DeleteRulesByPrefix
 *   删除 rule_id 以指定前缀开头的所有规则（如 "basename:"）。
 *   用于重新导入 .yar 文件前清理旧规则。
 *--*/
NTSTATUS
YaraRule_DeleteRulesByPrefix(
    _In_ PCSTR RuleIdPrefix
);

NTSTATUS
YaraRule_ListRules(
    _Out_ PYARA_RULE_INFO* OutRules,
    _Out_ PULONG OutCount
);

NTSTATUS YaraRule_IncrementHitCount(_In_ PCSTR RuleName);

#ifdef __cplusplus
}
#endif
