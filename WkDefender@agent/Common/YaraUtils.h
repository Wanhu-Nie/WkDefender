/**************************************************/
/*  WkDefender YARA 工具命名空间                     */
/*  参考 PhantomSensor YaraUtils                    */
/*  （YaraRuleStore.cpp:4338-4664）                 */
/**************************************************/

/*
 * 职责：
 *   1) YARA 规则文本的语法校验（ValidateSyntax）
 *   2) 从规则文本提取规则名（ExtractRuleName）
 *   3) 从 meta: 段提取元数据（ExtractMetadata / ParseThreatLevel）
 *   4) 文件系统扫描 .yar/.yara 文件（FindYaraFiles）
 *
 * 这些函数在 YaraRule 存储层和 IocYaraScanner 扫描层之间共享。
 */

#pragma once

#include <windows.h>
#include <yara.h>

/*====================================================================*/
/*  多规则拆分结构（一个 .yar 文件 → N 条独立规则）                    */
/*====================================================================*/

typedef struct _YARA_RULE_SPLIT {
    /* RuleContent 包含的是 preamble + 规则体，而非仅规则体。
     * 原因是 YARA 的 import（如 "import \"pe\""）和 include 声明
     * 位于 .yar 文件首部（第一个 "rule " 之前），必须随每条规则
     * 一并送入 yr_compiler_add_string 才能独立编译通过。
     * 若只存规则体，import "pe" 会丢失，导致 pe.is_dll() 等调用
     * 编译时因模块未定义而失败。PhantomSensor 同样存全文件内容。 */
    PCHAR RuleContent;    /* 完整规则文本：preamble（import/注释）+ 规则体 */
    ULONG RuleContentLen; /* 文本长度（不含 NUL 终止符）                    */
    CHAR  RuleName[256];  /* 规则标识符（如 "Malware_Generic"）           */
} YARA_RULE_SPLIT, *PYARA_RULE_SPLIT;

/*++
 * YaraUtils_SplitYarContent
 *   将 .yar 源文件内容拆分为独立规则数组，每条规则附带 preamble。
 *
 *   为什么保留 preamble：
 *     YARA 的 import "pe" / import "math" 等模块声明只能出现在
 *     文件首部，在 yr_compiler_add_string 的编译单元生效范围内。
 *     如果拆分时丢弃 preamble，每条规则单独编译时都会因为模块
 *     未加载而失败。因此把文件首部的 import/全局注释（preamble）
 *     拼接到每条规则前，确保每条拆出的文本都能独立编译通过。
 *
 *   算法：
 *     1) 扫描全文，找到所有行首 "rule " 关键字位置
 *     2) 提取 preamble（第一个 "rule " 之前的内容，含 import / 全局注释）
 *     3) 对每条规则，拼接 preamble + 规则体
 *     4) 为每条规则提取规则名
 *   调用方须用 UtHeapFree 释放 OutRules 中每个 Split->RuleContent 及数组本身。
 *   参考 PhantomSensor 的多规则文件处理模式（逐规则编译）。
 *--*/
NTSTATUS
YaraUtils_SplitYarContent(
    _In_ PCSTR Content,
    _Out_ PYARA_RULE_SPLIT* Rules,
    _Out_ PULONG Count
    );

#ifdef __cplusplus
extern "C" {
#endif

/*====================================================================*/
/*  语法校验                                                          */
/*====================================================================*/

/*++
 * YaraUtils_ValidateSyntax
 *   用 libyara 编译器预校验规则文本语法。
 *   返回 TRUE 表示语法合法 / FALSE 表示语法错误。
 *   参考 PhantomSensor YaraUtils::ValidateRuleSyntax。
 *--*/
BOOLEAN
YaraUtils_ValidateSyntax(
    _In_ PCSTR RuleText
);

/*====================================================================*/
/*  规则名提取                                                        */
/*====================================================================*/

/*++
 * YaraUtils_ExtractRuleName
 *   从 YARA 规则文本中提取第一个 rule 的标识符。
 *   简单状态机：查找 "rule " 之后的标识符（遇到 : 或 { 或空白结束）。
 *   参考 PhantomSensor YaraUtils::ExtractRuleName（概念等价）。
 *--*/
BOOLEAN
YaraUtils_ExtractRuleName(
    _In_ PCSTR RuleText,
    _Out_writes_(NameCch) PCHAR RuleName,
    _In_ ULONG NameCch
);

/*====================================================================*/
/*  元数据提取                                                        */
/*====================================================================*/

/*++
 * YaraUtils_ExtractMetadata
 *   从 YARA 规则文本的 meta: 段提取 threat_level、author、description、tags。
 *   参考 PhantomSensor YaraUtils::ExtractMetadata / ExtractTags / ParseThreatLevel。
 *--*/
VOID
YaraUtils_ExtractMetadata(
    _In_ PCSTR RuleText,
    _Out_opt_ PINT ThreatLevel,
    _Out_writes_opt_(AuthorCch) PCHAR Author,
    _In_ ULONG AuthorCch,
    _Out_writes_opt_(DescCch) PCHAR Description,
    _In_ ULONG DescCch,
    _Out_writes_opt_(TagsCch) PCHAR Tags,
    _In_ ULONG TagsCch
);

/*++
 * YaraUtils_ParseThreatLevel
 *   将威胁级字符串映射为整数（0-4）。
 *   参考 PhantomSensor YaraUtils::ParseThreatLevel。
 *   大小写不敏感映射：
 *     critical/severe → 4, high → 3, medium/moderate → 2,
 *     low/minor → 1, info/informational → 0, 其它 → 2（默认）
 *--*/
INT
YaraUtils_ParseThreatLevel(
    _In_ PCSTR Value
);

/*====================================================================*/
/*  文件发现                                                          */
/*====================================================================*/

/*++
 * YaraUtils_FindYaraFiles
 *   递归扫描目录下所有 .yar / .yara 文件。
 *   参考 PhantomSensor YaraUtils::FindYaraFiles（行 4567）。
 *   参数：
 *       DirectoryPath  — 根目录
 *       OutFiles       — 输出文件路径数组（须用 UtHeapFree 释放）
 *       OutCount       — 输出文件数
 *   返回 STATUS_SUCCESS 或错误码。
 *--*/
NTSTATUS
YaraUtils_FindYaraFiles(
    _In_ PCWSTR DirectoryPath,
    _Out_ PWSTR** OutFiles,
    _Out_ PULONG OutCount
);

/*====================================================================*/
/*  路径校验（CWE-22 防遍历）                                          */
/*====================================================================*/

/*++
 * YaraUtils_ValidateAndCanonicalizePath
 *   参考 PhantomSensor Format::ValidateAndCanonicalizePath（7 步）。
 *   校验规则：
 *     1) 空/超长(32767)/含 NUL → 拒绝
 *     2) 含 ..\ 或 \\.\ 或保留设备名(CON/PRN/NUL/COM/LPT) → 拒绝
 *     3) GetFullPathNameW 规范化
 *     4) 规范化后再次检测遍历模式
 *     5) 须为绝对路径（盘符开头或 UNC）
 *   若校验通过，OutPath 写入规范化后的路径（调用方提供 MAX_PATH 缓冲区）。
 *--*/
BOOLEAN
YaraUtils_ValidateAndCanonicalizePath(
    _In_ PCWSTR RawPath,
    _Out_writes_(MAX_PATH) PWCHAR OutPath
);

#ifdef __cplusplus
}
#endif
