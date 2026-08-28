/**************************************************/
/*  WkDefender YARA 工具命名空间实现                 */
/*  参考 PhantomSensor YaraUtils                    */
/*  （YaraRuleStore.cpp:4338-4664）                 */
/**************************************************/

#include "YaraUtils.h"
#include "../WkDefenderHeader.h"   /* UtHeapAlloc/UtHeapFree */
#include "../Common/TitaniumLimits.h"
#include <stdio.h>

/*====================================================================*/
/*  YaraUtils_ValidateSyntax                                          */
/*====================================================================*/

BOOLEAN
YaraUtils_ValidateSyntax(
    _In_ PCSTR RuleText
)
{
    if (!RuleText || !RuleText[0]) return FALSE;

    YR_COMPILER* compiler = NULL;
    int yrErr = yr_compiler_create(&compiler);
    if (yrErr != ERROR_SUCCESS || !compiler) return FALSE;

    int result = yr_compiler_add_string(compiler, RuleText, NULL);
    yr_compiler_destroy(compiler);
    return (result == 0);
}

/*====================================================================*/
/*  YaraUtils_ExtractRuleName                                         */
/*====================================================================*/

BOOLEAN
YaraUtils_ExtractRuleName(
    _In_ PCSTR RuleText,
    _Out_writes_(NameCch) PCHAR RuleName,
    _In_ ULONG NameCch
)
{
    if (!RuleText || !RuleName || NameCch == 0) return FALSE;
    RuleName[0] = '\0';

    PCSTR p = RuleText;
    while (*p) {
        if ((p == RuleText || *(p - 1) == '\n' || *(p - 1) == '\r' ||
             *(p - 1) == ' ' || *(p - 1) == '\t') &&
            _strnicmp(p, "rule ", 5) == 0) {
            p += 5;
            /* 跳过空白 */
            while (*p == ' ' || *p == '\t') p++;
            /* 读标识符（遇 :、{、空白 结束） */
            ULONG i = 0;
            while (*p && *p != ':' && *p != '{' && *p != ' ' && *p != '\t' &&
                   *p != '\n' && *p != '\r' && i < NameCch - 1) {
                RuleName[i++] = *p++;
            }
            RuleName[i] = '\0';
            return (i > 0);
        }
        p++;
    }
    return FALSE;
}

/*====================================================================*/
/*  YaraUtils_ParseThreatLevel                                        */
/*====================================================================*/

INT
YaraUtils_ParseThreatLevel(
    _In_ PCSTR Value
)
{
    if (!Value || !Value[0]) return 2; /* 默认中危 */

    int val = atoi(Value);
    if (val != 0 || Value[0] == '0') {
        /* 纯数字 */
        if (val < 0) return 0;
        if (val > 4) return 4;
        return val;
    }

    /* 字符串映射 */
    if (_stricmp(Value, "critical") == 0 || _stricmp(Value, "severe") == 0) return 4;
    if (_stricmp(Value, "high") == 0) return 3;
    if (_stricmp(Value, "medium") == 0 || _stricmp(Value, "moderate") == 0) return 2;
    if (_stricmp(Value, "low") == 0 || _stricmp(Value, "minor") == 0) return 1;
    if (_stricmp(Value, "info") == 0 || _stricmp(Value, "informational") == 0) return 0;

    return 2; /* 默认中危 */
}

/*====================================================================*/
/*  YaraUtils_ExtractMetadata                                         */
/*====================================================================*/

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
)
{
    if (ThreatLevel) *ThreatLevel = 2;  /* 默认中危 */
    if (Author && AuthorCch) Author[0] = '\0';
    if (Description && DescCch) Description[0] = '\0';
    if (Tags && TagsCch) Tags[0] = '\0';

    if (!RuleText) return;

    /* 定位 meta: 段 */
    PCSTR metaPos = NULL;
    {
        PCSTR p = RuleText;
        while (*p) {
            if ((p == RuleText || *(p - 1) == '\n' || *(p - 1) == '\r') &&
                _strnicmp(p, "meta:", 5) == 0) {
                metaPos = p + 5;
                break;
            }
            p++;
        }
    }
    if (!metaPos) return;

    /* 逐行解析 key = value */
    PCSTR line = metaPos;
    while (*line) {
        if (_strnicmp(line, "strings:", 8) == 0 ||
            _strnicmp(line, "condition:", 10) == 0 ||
            *line == '}') break;

        while (*line == ' ' || *line == '\t') line++;
        if (*line == '\0' || *line == '\n' || *line == '\r' || *line == '}') {
            if (*line == '\n' || *line == '\r') line++;
            continue;
        }

        CHAR key[128];
        ULONG ki = 0;
        while (*line && *line != '=' && *line != ' ' && *line != '\t' &&
               ki < sizeof(key) - 1) {
            key[ki++] = *line++;
        }
        key[ki] = '\0';

        while (*line == ' ' || *line == '\t') line++;
        if (*line == '=') line++;
        while (*line == ' ' || *line == '\t') line++;

        CHAR value[4096];
        ULONG vi = 0;
        if (*line == '"') {
            line++;
            while (*line && *line != '"' && vi < sizeof(value) - 1) {
                if (*line == '\\' && *(line + 1)) line++;
                value[vi++] = *line++;
            }
            if (*line == '"') line++;
        } else {
            while (*line && *line != '\n' && *line != '\r' && *line != '}' &&
                   vi < sizeof(value) - 1) {
                value[vi++] = *line++;
            }
        }
        value[vi] = '\0';

        /* 分配输出 */
        if (_stricmp(key, "threat_level") == 0 || _stricmp(key, "severity") == 0) {
            if (ThreatLevel) {
                *ThreatLevel = YaraUtils_ParseThreatLevel(value);
            }
        } else if (_stricmp(key, "author") == 0) {
            if (Author && AuthorCch) strncpy_s(Author, AuthorCch, value, _TRUNCATE);
        } else if (_stricmp(key, "description") == 0) {
            if (Description && DescCch) strncpy_s(Description, DescCch, value, _TRUNCATE);
        } else if (_stricmp(key, "tags") == 0) {
            if (Tags && TagsCch) strncpy_s(Tags, TagsCch, value, _TRUNCATE);
        }

        while (*line && *line != '\n') line++;
        if (*line == '\n') line++;
    }
}

/*====================================================================*/
/*  YaraUtils_ValidateAndCanonicalizePath                              */
/*  参考 PhantomSensor Format::ValidateAndCanonicalizePath 7 步        */
/*====================================================================*/

BOOLEAN
YaraUtils_ValidateAndCanonicalizePath(
    _In_ PCWSTR RawPath,
    _Out_writes_(MAX_PATH) PWCHAR OutPath
)
{
    if (!RawPath || !OutPath) return FALSE;
    OutPath[0] = L'\0';

    /* STEP 1: 空/超长/NUL 检测 */
    if (RawPath[0] == L'\0') return FALSE;

    SIZE_T rawLen = wcslen(RawPath);
    if (rawLen >= WKD_MAX_PATH_LENGTH) return FALSE;
    if (rawLen == 0) return FALSE;

    /* STEP 2: 遍历模式检测 */
    /* 检测 ..\ 和 ../ */
    if (wcsstr(RawPath, L"..\\") != NULL || wcsstr(RawPath, L"../") != NULL)
        return FALSE;

    /* 检测 \\.\ 设备路径前缀（除 \\?\ 外） */
    if (wcsncmp(RawPath, L"\\\\.\\", 4) == 0 && wcsncmp(RawPath, L"\\\\?\\", 4) != 0)
        return FALSE;

    /* 检测保留 DOS 设备名 */
    {
        /* 取文件名部分（最后一段不含目录） */
        PCWSTR base = wcsrchr(RawPath, L'\\');
        if (!base) base = wcsrchr(RawPath, L'/');
        if (!base) base = RawPath; else base++;

        WCHAR upper[16] = {0};
        ULONG i;
        /* 去掉扩展名后转换大写比较 */
        for (i = 0; i < 15 && base[i] && base[i] != L'.'; i++) {
            upper[i] = (WCHAR)towupper(base[i]);
        }
        upper[i] = L'\0';

        if (wcscmp(upper, L"CON") == 0 || wcscmp(upper, L"PRN") == 0 ||
            wcscmp(upper, L"AUX") == 0 || wcscmp(upper, L"NUL") == 0 ||
            wcsncmp(upper, L"COM", 3) == 0 || wcsncmp(upper, L"LPT", 3) == 0)
            return FALSE;
    }

    /* STEP 3: GetFullPathNameW 规范化 */
    WCHAR canonical[MAX_PATH] = {0};
    DWORD canonLen = GetFullPathNameW(RawPath, MAX_PATH, canonical, NULL);
    if (canonLen == 0 || canonLen >= MAX_PATH) return FALSE;

    /* STEP 4: 规范化后再次检测遍历模式（防御性） */
    if (wcsstr(canonical, L"..\\") != NULL || wcsstr(canonical, L"../") != NULL)
        return FALSE;

    /* STEP 5: 必须为绝对路径（盘符\\ 或 UNC \\） */
    if (!((canonical[0] >= L'A' && canonical[0] <= L'Z') ||
          (canonical[0] >= L'a' && canonical[0] <= L'z')) ||
        canonical[1] != L':' || canonical[2] != L'\\') {
        /* 检查 UNC */
        if (wcsncmp(canonical, L"\\\\", 2) != 0)
            return FALSE;
    }

    wcscpy_s(OutPath, MAX_PATH, canonical);
    return TRUE;
}

/*====================================================================*/
/*  YaraUtils_FindYaraFiles                                           */
/*  递归扫描 .yar / .yara 文件。参考 PhantomSensor FindYaraFiles。     */
/*  上层调用方须用 UtHeapFree 释放 OutFiles 及其中的每个字符串。        */
/*====================================================================*/

NTSTATUS
YaraUtils_FindYaraFiles(
    _In_ PCWSTR DirectoryPath,
    _Out_ PWSTR** OutFiles,
    _Out_ PULONG OutCount
)
{
    if (!DirectoryPath || !OutFiles || !OutCount)
        return STATUS_INVALID_PARAMETER;

    *OutFiles = NULL;
    *OutCount = 0;

    /* 规范化路径 */
    WCHAR canonDir[MAX_PATH] = {0};
    if (!YaraUtils_ValidateAndCanonicalizePath(DirectoryPath, canonDir))
        return STATUS_INVALID_PARAMETER;

    /* 确保尾部有 \ */
    size_t dirLen = wcslen(canonDir);
    if (dirLen > 0 && canonDir[dirLen - 1] != L'\\') {
        canonDir[dirLen] = L'\\';
        canonDir[dirLen + 1] = L'\0';
        dirLen++;
    }

    /* 使用动态数组收集 */
    PWSTR* files = NULL;
    ULONG  count = 0;
    ULONG  capacity = 0;

    /* 辅助宏：添加文件路径 */
#define FINDYARA_ADD_FILE(fullPath)                                        \
    do {                                                                   \
        if (count >= WKD_MAX_YARA_FILES_IN_REPO) goto done;                \
        if (count >= capacity) {                                           \
            ULONG newCap = (capacity == 0) ? 256 : capacity * 2;           \
            PWSTR* newFiles = (PWSTR*)UtHeapAlloc(sizeof(PWSTR) * newCap); \
            if (!newFiles) goto done;                                      \
            if (files) {                                                   \
                CopyMemory(newFiles, files, sizeof(PWSTR) * count);        \
                UtHeapFree(files);                                         \
            }                                                              \
            files = newFiles;                                              \
            capacity = newCap;                                             \
        }                                                                  \
        size_t flen = wcslen(fullPath) + 1;                                \
        files[count] = (PWSTR)UtHeapAlloc(flen * sizeof(WCHAR));           \
        if (files[count]) {                                                \
            wcscpy_s(files[count], flen, fullPath);                        \
            count++;                                                       \
        }                                                                  \
    } while (0)

    /* 第一轮：.yar */
    {
        WCHAR pattern[MAX_PATH] = {0};
        wcscpy_s(pattern, MAX_PATH, canonDir);
        wcscat_s(pattern, MAX_PATH, L"*.yar");

        WIN32_FIND_DATAW ffd;
        HANDLE hFind = FindFirstFileW(pattern, &ffd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                WCHAR full[MAX_PATH] = {0};
                wcscpy_s(full, MAX_PATH, canonDir);
                wcscat_s(full, MAX_PATH, ffd.cFileName);
                FINDYARA_ADD_FILE(full);
            } while (FindNextFileW(hFind, &ffd) != 0 && count < WKD_MAX_YARA_FILES_IN_REPO);
            FindClose(hFind);
        }
    }

    /* 第二轮：.yara */
    {
        WCHAR pattern[MAX_PATH] = {0};
        wcscpy_s(pattern, MAX_PATH, canonDir);
        wcscat_s(pattern, MAX_PATH, L"*.yara");

        WIN32_FIND_DATAW ffd;
        HANDLE hFind = FindFirstFileW(pattern, &ffd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                WCHAR full[MAX_PATH] = {0};
                wcscpy_s(full, MAX_PATH, canonDir);
                wcscat_s(full, MAX_PATH, ffd.cFileName);
                FINDYARA_ADD_FILE(full);
            } while (FindNextFileW(hFind, &ffd) != 0 && count < WKD_MAX_YARA_FILES_IN_REPO);
            FindClose(hFind);
        }
    }

    /* 第三轮：递归子目录 */
    {
        WCHAR pattern[MAX_PATH] = {0};
        wcscpy_s(pattern, MAX_PATH, canonDir);
        wcscat_s(pattern, MAX_PATH, L"*");

        WIN32_FIND_DATAW ffd;
        HANDLE hFind = FindFirstFileW(pattern, &ffd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0)
                    continue;

                WCHAR subDir[MAX_PATH] = {0};
                wcscpy_s(subDir, MAX_PATH, canonDir);
                wcscat_s(subDir, MAX_PATH, ffd.cFileName);

                PWSTR* subFiles = NULL;
                ULONG  subCount = 0;
                NTSTATUS subSt = YaraUtils_FindYaraFiles(subDir, &subFiles, &subCount);
                if (NT_SUCCESS(subSt) && subFiles && subCount > 0) {
                    for (ULONG si = 0; si < subCount && count < WKD_MAX_YARA_FILES_IN_REPO; si++) {
                        FINDYARA_ADD_FILE(subFiles[si]);
                        UtHeapFree(subFiles[si]);
                    }
                    UtHeapFree(subFiles);
                }
            } while (FindNextFileW(hFind, &ffd) != 0);
            FindClose(hFind);
        }
    }

done:
    if (count == 0 && files) {
        UtHeapFree(files);
        files = NULL;
    }

    *OutFiles = files;
    *OutCount = count;
    return (count > 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;

#undef FINDYARA_ADD_FILE
}

/*====================================================================*/
/*  YaraUtils_SplitYarContent — 多规则文件拆分                         */
/*  将包含 N 条规则的 .yar 源拆分为 N 个独立的 YARA_RULE_SPLIT 条目。   */
/*====================================================================*/

NTSTATUS
YaraUtils_SplitYarContent(
    _In_ PCSTR Content,
    _Out_ PYARA_RULE_SPLIT* Rules,
    _Out_ PULONG Count
)
{
    if (!Content || !Rules || !Count)
        return STATUS_INVALID_PARAMETER;

    *Rules = NULL;
    *Count = 0;

    ULONG contentLen = (ULONG)strlen(Content);
    if (contentLen == 0) return STATUS_NOT_FOUND;

    /*============================================================*/
    /*  第 1 步：扫描行首 "rule "，收集所有规则起始位置             */
    /*============================================================*/

    /* 预分配 64 个槽，不够再扩容 */
    ULONG  ruleCap = 64;
    PULONG rulePos = (PULONG)UtHeapAlloc(sizeof(ULONG) * ruleCap);
    if (!rulePos) return STATUS_NO_MEMORY;

    ULONG ruleCount = 0;
    for (ULONG i = 0; i < contentLen; i++) {
        /* 检查 "rule " 模式 */
        if (Content[i] != 'r') continue;
        if (contentLen - i < 5) break;
        if (Content[i + 1] != 'u' || Content[i + 2] != 'l' ||
            Content[i + 3] != 'e' || Content[i + 4] != ' ')
            continue;

        /* 验证此 "rule " 位于行首（可带前导空白） */
        BOOLEAN atLineStart = FALSE;
        if (i == 0) {
            atLineStart = TRUE;
        } else {
            /* 向前跳过空白 */
            LONG b = (LONG)i - 1;
            while (b >= 0 && (Content[b] == ' ' || Content[b] == '\t'))
                b--;
            if (b < 0 || Content[b] == '\n')
                atLineStart = TRUE;
        }

        if (!atLineStart)
            continue;

        if (ruleCount >= ruleCap) {
            ULONG newCap = ruleCap * 2;
            PULONG newPos = (PULONG)UtHeapAlloc(sizeof(ULONG) * newCap);
            if (!newPos) {
                UtHeapFree(rulePos);
                return STATUS_NO_MEMORY;
            }
            CopyMemory(newPos, rulePos, sizeof(ULONG) * ruleCount);
            UtHeapFree(rulePos);
            rulePos = newPos;
            ruleCap = newCap;
        }
        rulePos[ruleCount++] = i;
    }

    if (ruleCount == 0) {
        UtHeapFree(rulePos);
        return STATUS_NOT_FOUND;   /* 文件中没有 "rule " 声明 */
    }

    /*============================================================*/
    /*  第 2 步：提取 preamble（第一个 "rule " 之前的所有内容）     */
    /*============================================================*/

    /* preamble 包含 import / include / 全局注释等文件级声明。
     * YARA 编译器要求这些声明在 yr_compiler_add_string 传入的
     * 文本中才生效——不能通过后续"补充注入"来跨编译单元共享。
     * 因此拆分时必须保留 preamble，拼接到每条规则前，否则：
     *   ❌ "pe.is_dll()" → 编译报 "undefined identifier 'pe'"
     * PhantomSensor 同样方式处理（AddYaraRule 存全文件内容）。 */
    ULONG preambleLen = rulePos[0];
    PCSTR preamble = Content;    /* 即 Content[0..preambleLen) */
    /* preamble 可以是空串（文件直接以 rule 开头） */

    /*============================================================*/
    /*  第 3 步：分配输出数组，逐规则填充                           */
    /*============================================================*/

    PYARA_RULE_SPLIT splits = (PYARA_RULE_SPLIT)UtHeapAlloc(sizeof(YARA_RULE_SPLIT) * ruleCount);
    if (!splits) {
        UtHeapFree(rulePos);
        return STATUS_NO_MEMORY;
    }

    ULONG successCount = 0;
    for (ULONG ri = 0; ri < ruleCount; ri++) {
        /* 规则体范围：规则起始 ～ 下一条规则起始（或文件末尾） */
        ULONG bodyStart = rulePos[ri];
        ULONG bodyEnd   = (ri + 1 < ruleCount) ? rulePos[ri + 1] : contentLen;
        ULONG bodyLen   = bodyEnd - bodyStart;

        /* 拼接 preamble + 规则体
         * 将文件首部的 import/include/注释 与单条规则体合并，
         * 使最终文本能独立送入 yr_compiler_add_string 编译。
         * 若不拼接，规则体中的 pe.is_dll()、math.entropy() 等
         * 调用会因缺少对应 import 而编译失败（模块未注册）。
         * 多条规则包含相同 preamble，YARA 编译器会静默去重，
         * 不会产生"重复 import"错误。 */
        ULONG fullLen = preambleLen + bodyLen;
        PCHAR fullText = (PCHAR)UtHeapAlloc(fullLen + 1);
        if (!fullText) {
            /* 释放此前已分配的资源 */
            for (ULONG j = 0; j < successCount; j++) {
                UtHeapFree(splits[j].RuleContent);
            }
            UtHeapFree(splits);
            UtHeapFree(rulePos);
            return STATUS_NO_MEMORY;
        }

        if (preambleLen > 0)
            CopyMemory(fullText, preamble, preambleLen);
        CopyMemory(fullText + preambleLen, Content + bodyStart, bodyLen);
        fullText[fullLen] = '\0';

        splits[successCount].RuleContent    = fullText;
        splits[successCount].RuleContentLen = fullLen;

        /* 提取规则名（从规则体中获取，避免 preamble 干扰） */
        if (!YaraUtils_ExtractRuleName(Content + bodyStart,
                                       splits[successCount].RuleName,
                                       sizeof(splits[successCount].RuleName))) {
            /* 兜底：用 "unknown_%u" 填充 */
            snprintf(splits[successCount].RuleName,
                     sizeof(splits[successCount].RuleName),
                     "unknown_%u", ri);
        }

        successCount++;
    }

    UtHeapFree(rulePos);

    *Rules = splits;
    *Count = successCount;
    return STATUS_SUCCESS;
}
