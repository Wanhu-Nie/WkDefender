/**************************************************/
/*  WkDefender — 路径算法实现                        */
/*                                                   */
/*  按 wkd 架构重写自 SS PathExclusion.c（对齐 SS     */
/*  行号: PeNormalizePath L236 / MatchPathPattern     */
/*  L343 / ExtractExtension L456）                    */
/*                                                   */
/*  无状态算法模块：路径归一化/模式匹配/basename 提取。*/
/*  纯函数，零全局状态，零堆分配（热路径）。           */
/*  匹配仅依赖 WCHAR 数组与 UNICODE_STRING。          */
/*  CoGetBasenameFromPath 为 basename 提取唯一实现       */
/*  （合并原 ExemptsGetFileName / ExemptPidGetFileName */
/*  两处重复）。                                      */
/**************************************************/

#include "ExemptsInternal.h"

#ifdef ALLOC_PRAGMA
// #pragma alloc_text(PAGE, CopNormalizeExemptedPath)
#endif

/**************************************************/
/*                  内部常量                        */
/**************************************************/

#define EXEMPT_PATH_SEPARATOR  L'\\'

/*
 * 通配符匹配最大迭代次数。
 * 限制对抗性模式（如 *?*?*?*?*）的总工作量。
 * 520 字符路径 × 520 字符模式最坏 270400 次迭代。
 */
#define EXEMPT_MAX_WILDCARD_ITERATIONS  (EXEMPT_MAX_PATH_LENGTH * \
                                          EXEMPT_MAX_PATH_LENGTH)

/**************************************************/
/*                  内部辅助函数                    */
/**************************************************/

/*
 * 大小写不敏感比较两个宽字符。
 * 两侧通常在插入时已归一化为大写，此处仅作未归一化调用方的安全网。
 */
_IRQL_requires_max_(APC_LEVEL)
static FORCEINLINE BOOLEAN
ExemptpCharsEqualCI(
    _In_ WCHAR A,
    _In_ WCHAR B
    )
{
    if (A == B) {
        return TRUE;
    }
    return RtlUpcaseUnicodeChar(A) == RtlUpcaseUnicodeChar(B);
}

/*
 * 内部通配符匹配引擎（有界迭代）。
 * '?' 匹配单字符；'*' 匹配零或多字符。非递归模式下均不跨路径分隔符。
 * 采用迭代 star 回溯算法，迭代次数受 EXEMPT_MAX_WILDCARD_ITERATIONS 限制。
 *
 * Arguments:
 *    String / StringLen  - 待匹配字符串与长度。
 *    Pattern / PatternLen- 匹配模式与长度。
 *    CaseSensitive       - TRUE 精确大小写。
 *    Recursive           - TRUE 允许 '*' 跨路径分隔符。
 *
 * Return Value:
 *    TRUE 匹配成功。
 */
_IRQL_requires_max_(APC_LEVEL)
static
BOOLEAN
ExemptpWildcardMatch(
    _In_reads_(StringLen) PCWCH String,
    _In_ USHORT StringLen,
    _In_reads_(PatternLen) PCWCH Pattern,
    _In_ USHORT PatternLen,
    _In_ BOOLEAN CaseSensitive,
    _In_ BOOLEAN Recursive
    )
{
    USHORT si = 0;
    USHORT pi = 0;
    USHORT starSi = (USHORT)-1;
    USHORT starPi = (USHORT)-1;
    ULONG iterations = 0;

    if (StringLen == 0 || PatternLen == 0) {
        return FALSE;
    }
  
    while (si < StringLen) {
        if (++iterations > EXEMPT_MAX_WILDCARD_ITERATIONS) {
            return FALSE;
        }

        if (pi < PatternLen && Pattern[pi] == L'?') {
            if (!Recursive && String[si] == EXEMPT_PATH_SEPARATOR) {
                if (starPi != (USHORT)-1) {
                    pi = starPi + 1;
                    starSi++;
                    si = starSi;
                    continue;
                }
                return FALSE;
            }
            si++;
            pi++;
        }
        else if (pi < PatternLen && Pattern[pi] == L'*') {
            starPi = pi;
            starSi = si;
            pi++;
        }
        else if (pi < PatternLen &&
                 (CaseSensitive ? (String[si] == Pattern[pi])
                                : ExemptpCharsEqualCI(String[si], Pattern[pi]))) {
            si++;
            pi++;
        }
        else if (starPi != (USHORT)-1) {
            pi = starPi + 1;
            starSi++;

            /*
             * 非递归模式：'*' 不跨路径分隔符。当 star 展开遇到分隔符时，
             * 清除书签并把 si 定位到分隔符，由主循环按字面量匹配 Pattern[pi]，
             * 正确处理 "dir\*\subdir" 这类单组件内匹配模式。
             */
            if (!Recursive && starSi < StringLen && String[starSi] == EXEMPT_PATH_SEPARATOR) {
                si = starSi;
                starPi = (USHORT)-1;
                starSi = (USHORT)-1;
                continue;
            }

            si = starSi;
        }
        else {
            return FALSE;
        }
    }

    while (pi < PatternLen && Pattern[pi] == L'*') {
        pi++;
    }

    return (pi == PatternLen);
}

/**************************************************/
/*                  函数实现                        */
/**************************************************/

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ExemptpMatchPathPattern(
    _In_ PCUNICODE_STRING FilePath,
    _In_ PCUNICODE_STRING Pattern,
    _In_ UINT8 Flags
    )
/*++
Routine Description:
    路径模式匹配。通配路径走 star 回溯；非通配走前缀+路径组件边界校验
    （"C:\WIN" 不匹配 "C:\WINDOWS\..."）。

Arguments:
    FilePath  - 待匹配文件路径。
    Pattern   - 排除模式（通常在插入时已归一化大写）。
    Flags     - EXEMPT_FLAG_CASE_SENSITIVE / WILDCARD / RECURSIVE。

Return Value:
    TRUE 匹配。
--*/
{
    BOOLEAN caseSensitive;
    BOOLEAN recursive;
    BOOLEAN wildcard;
    USHORT patternChars;
    USHORT fileChars;

    if (FilePath->Length == 0 || Pattern->Length == 0) {
        return FALSE;
    }

    caseSensitive = (Flags & EXEMPT_FLAG_CASE_SENSITIVE) != 0;
    recursive = (Flags & EXEMPT_FLAG_RECURSIVE) != 0;
    wildcard = (Flags & EXEMPT_FLAG_WILDCARD) != 0;

    patternChars = Pattern->Length / sizeof(WCHAR);
    fileChars = FilePath->Length / sizeof(WCHAR);

    if (wildcard) {
        return ExemptpWildcardMatch(
            FilePath->Buffer,
            fileChars,
            Pattern->Buffer,
            patternChars,
            caseSensitive,
            recursive
        );
    }

    if (patternChars > fileChars) {
        return FALSE;
    }

    if (caseSensitive) {
        if (RtlCompareMemory(FilePath->Buffer, Pattern->Buffer,
                             patternChars * sizeof(WCHAR))
            != patternChars * sizeof(WCHAR)) {
            return FALSE;
        }
    } else {
        UNICODE_STRING filePrefix;
        filePrefix.Buffer = FilePath->Buffer;
        filePrefix.Length = patternChars * sizeof(WCHAR);
        filePrefix.MaximumLength = filePrefix.Length;

        if (RtlCompareUnicodeString(&filePrefix, Pattern, TRUE) != 0) {
            return FALSE;
        }
    }

    if (patternChars == fileChars) {
        return TRUE;
    }

    if (recursive) {
        if (Pattern->Buffer[patternChars - 1] == EXEMPT_PATH_SEPARATOR) {
            return TRUE;
        }

        if (FilePath->Buffer[patternChars] == EXEMPT_PATH_SEPARATOR) {
            return TRUE;
        }

        return FALSE;
    }

    return FALSE;
}

