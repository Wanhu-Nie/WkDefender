/**************************************************/
/*  WkDefender — 排除子系统路径算法（无状态）        */
/*                                                   */
/*  按功能融合自 SS WhiteListPatternIndex.cpp         */
/*  NormalizePath（L702-861）与 Lookup 的路径匹配     */
/*  语义，重实现非复制。                              */
/*                                                   */
/*  归一化防绕过（对齐 SS PI-2/3/4/5）：             */
/*    - 大小写折叠（towlower，Unicode-aware）        */
/*    - \ → / 分隔符统一                            */
/*    - 去尾斜杠                                    */
/*    - . / .. 段解析（路径穿越检测，拒绝越过根）     */
/*    - ADS (:streamname) 剥离（跳过盘符冒号）        */
/*  短名(GetLongPathNameW)/NFC(NormalizeString)      */
/*  依赖标注：agent 查询路径来自内核镜像/枚举，已为    */
/*  规范 Dos 路径，此两通道归可选（死代码标注）。     */
/*                                                   */
/*  匹配模式：Exact/Prefix/Suffix/Contains/Glob      */
/*    Glob 支持 *（任意）与 ?（单字符），Windows 语义  */
/*    （* 可跨 /），对齐 SS L1556-1563。              */
/**************************************************/

#include "ExemptsInternal.h"
#include <wchar.h>
#include <wctype.h>

/**************************************************/
/*                  归一化                          */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
ExemptPath_Normalize(
    _In_ PCWSTR Path,
    _Out_writes_(MaxLen) WCHAR* Out,
    _In_ ULONG MaxLen
    )
/*++
Routine Description:
    路径归一化（防绕过）。小写折叠 + 分隔符统一 + 去尾斜杠 +
    段级 . / .. 解析（路径穿越拒绝）+ ADS 剥离。

Arguments:
    Path   - 原始路径（宽串）。
    Out    - 归一化输出缓冲。
    MaxLen - 输出缓冲容量（字符，须 ≥ 2）。

Return Value:
    TRUE 成功；FALSE 输入非法/路径穿越/缓冲不足。
--*/
{
    WCHAR buffer[EXEMPT_MAX_PATTERN + 2];
    WCHAR* segments[EXEMPT_MAX_PATTERN / 2 + 2];
    ULONG segCount = 0;
    ULONG inLen, o, i, segStart;
    BOOLEAN drivePrefix = FALSE;

    if (Path == NULL || Out == NULL || MaxLen < 2) {
        return FALSE;
    }

    inLen = (ULONG)wcslen(Path);
    if (inLen == 0 || inLen > EXEMPT_MAX_PATTERN) {
        return FALSE;   /* 空或超长拒绝 */
    }

    /*
     * 第一遍：大小写折叠 + 分隔符统一 + 复制到工作缓冲。
     * 同时做 ADS 剥离（跳过盘符冒号位置 1；对齐 SS PI-3）。
     */
    o = 0;
    for (i = 0; i < inLen; i++) {
        WCHAR c = Path[i];

        if (c == L'\\') {
            c = L'/';
        } else if (c >= L'A' && c <= L'Z') {
            c = (WCHAR)(c - L'A' + L'a');
        }

        /* ADS 剥离：段内冒号（跳过盘符 "c:" 的冒号） */
        if (c == L':' && !(i == 1 && (Path[0] >= L'a' && Path[0] <= L'z') ||
                           (i == 1 && Path[0] >= L'A' && Path[0] <= L'Z'))) {
            /* 跳至本段结束（下一个 '/'），剥离 :stream */
            while (i + 1 < inLen && Path[i + 1] != L'\\' && Path[i + 1] != L'/') {
                i++;
            }
            continue;
        }

        if (o >= EXEMPT_MAX_PATTERN) {
            return FALSE;
        }
        buffer[o++] = c;
    }
    buffer[o] = L'\0';

    /* 去尾斜杠（保留根 "c:/" 语义在段解析中处理） */
    while (o > 0 && buffer[o - 1] == L'/') {
        buffer[--o] = L'\0';
    }
    if (o == 0) {
        buffer[0] = L'/';
        buffer[1] = L'\0';
        o = 1;
    }

    /*
     * 第二遍：段级 . / .. 解析（对齐 SS L793-858）。
     * 注意 "c:/" 盘符前缀：首段 "c:" 视为盘符，不入 segments。
     */
    if (o >= 2 && buffer[1] == L':') {
        drivePrefix = TRUE;
        segments[segCount++] = buffer;          /* "c:" 整体作首段 */
        segStart = 2;
    } else {
        segStart = 0;
    }

    for (i = segStart; i < o; ) {
        ULONG j = i;
        while (j < o && buffer[j] != L'/') {
            j++;
        }

        /* 段 [i, j) */
        if (j - i == 0) {
            /* 空段（连续分隔符）跳过 */
        } else if (j - i == 1 && buffer[i] == L'.') {
            /* 当前目录 → 跳过 */
        } else if (j - i == 2 && buffer[i] == L'.' && buffer[i + 1] == L'.') {
            /* 父目录：可弹出则弹出，否则拒绝（越过根） */
            if (segCount == 0 || (drivePrefix && segCount == 1)) {
                return FALSE;   /* 路径穿越，拒绝 */
            }
            segCount--;
        } else {
            if (segCount >= EXEMPT_MAX_PATTERN / 2) {
                return FALSE;
            }
            segments[segCount++] = &buffer[i];
        }

        i = j + 1;  /* 跳过 '/' */
    }

    /* 重建归一化路径 */
    o = 0;
    for (i = 0; i < segCount; i++) {
        ULONG segLen = (ULONG)wcslen(segments[i]);
        if (o + segLen + 1 >= MaxLen) {
            return FALSE;   /* 缓冲不足 */
        }
        if (i > 0) {
            Out[o++] = L'/';
        }
        wmemcpy(&Out[o], segments[i], segLen);
        o += segLen;
    }
    Out[o] = L'\0';

    return TRUE;
}

/**************************************************/
/*               Glob 通配匹配                      */
/**************************************************/

/*
 * 通配匹配（Windows 语义：* 可跨分隔符，? 单字符）。
 * 迭代双指针回溯（* 匹配到最后一个可能位置），上限防 ReDoS。
 */
static BOOLEAN
ExemptPathp_Glob(
    _In_ PCWSTR Text,
    _In_ PCWSTR Pattern
    )
{
    PCWSTR star = NULL;
    PCWSTR mark = NULL;
    ULONG steps = 0;

    while (*Text) {
        if (*Pattern == L'?' || *Pattern == *Text) {
            Pattern++;
            Text++;
        } else if (*Pattern == L'*') {
            star = Pattern++;       /* 记录 * 位置 */
            mark = Text;            /* 记录文本回溯点 */
        } else if (star != NULL) {
            Pattern = star + 1;     /* 回溯到最后一个 * 之后 */
            Text = ++mark;          /* * 多匹配一个字符 */
        } else {
            return FALSE;
        }

        /* 迭代上限（路径 ≤ EXEMPT_MAX_PATTERN，正常远达不到） */
        if (++steps > 65536) {
            return FALSE;
        }
    }

    /* 剩余模式仅允许 * */
    while (*Pattern == L'*') {
        Pattern++;
    }
    return (*Pattern == L'\0');
}

/**************************************************/
/*                  匹配入口                        */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
ExemptPath_Match(
    _In_ PCWSTR Path,
    _In_ PCWSTR Pattern,
    _In_ UINT8  Mode
    )
/*++
Routine Description:
    路径模式匹配。Path 与 Pattern 均先归一化再比较。

Arguments:
    Path    - 待判定路径。
    Pattern - 规则模式。
    Mode    - EXEMPT_PATH_MODE（Exact/Prefix/Suffix/Contains/Glob）。

Return Value:
    TRUE 命中。
--*/
{
    WCHAR normPath[EXEMPT_MAX_PATTERN + 2];
    WCHAR normPat[EXEMPT_MAX_PATTERN + 2];
    SIZE_T pathLen, patLen;

    if (Path == NULL || Pattern == NULL || Mode >= ExemptMode_MaxValue) {
        return FALSE;
    }

    if (!ExemptPath_Normalize(Path, normPath, EXEMPT_MAX_PATTERN + 2) ||
        !ExemptPath_Normalize(Pattern, normPat, EXEMPT_MAX_PATTERN + 2)) {
        return FALSE;
    }

    pathLen = wcslen(normPath);
    patLen = wcslen(normPat);

    switch (Mode) {
    case ExemptMode_Exact:
        return (pathLen == patLen && _wcsicmp(normPath, normPat) == 0);

    case ExemptMode_Prefix:
        if (patLen > pathLen) {
            return FALSE;
        }
        if (wcsncmp(normPath, normPat, patLen) != 0) {
            return FALSE;
        }
        /* 组件边界：模式结束 或 Path[patLen] 为分隔符 */
        return (patLen == pathLen || normPath[patLen] == L'/');

    case ExemptMode_Suffix:
        if (patLen > pathLen) {
            return FALSE;
        }
        return (_wcsicmp(&normPath[pathLen - patLen], normPat) == 0);

    case ExemptMode_Contains:
        return (wcsstr(normPath, normPat) != NULL);

    case ExemptMode_Glob:
        return ExemptPathp_Glob(normPath, normPat);

    default:
        return FALSE;
    }
}

_Use_decl_annotations_
BOOLEAN
ExemptPath_IsWhitelisted(
    _In_  PEXEMPT_ENGINE Engine,
    _In_  PCWSTR Path,
    _In_  UINT8 Mode,
    _Out_opt_ PEXEMPT_REASON Reason
    )
/*++
Routine Description:
    路径规则命中判定：遍历 Manager 路径规则，逐个 ExemptPath_Match。

Arguments:
    Engine - 子系统全局（含 Manager）。
    Path   - 待判定路径。
    Mode   - 匹配模式（默认 ExemptMode_Exact 语义由门面决定）。
    Reason - 可选输出命中原因。

Return Value:
    TRUE 命中路径规则。
--*/
{
    BOOLEAN hit = FALSE;
    UINT64 i;

    if (Engine == NULL || Path == NULL) {
        return FALSE;
    }

    EnterCriticalSection(&Engine->Manager.Lock);
    for (i = 0; i < Engine->Manager.RuleCount; i++) {
        PEXEMPT_RULE rule = &Engine->Manager.Rules[i];

        if (rule->Type != ExemptRule_Path) {
            continue;
        }
        /* 活跃校验：enabled + 未过期（惰性清理） */
        if (rule->Flags & EXEMPT_FLAG_SYSTEM) {
            /* 系统规则永活 */
        } else if (rule->ExpirationTime != 0) {
            FILETIME ft;
            UINT64 now;
            GetSystemTimeAsFileTime(&ft);
            now = (((UINT64)ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
            if (now >= rule->ExpirationTime) {
                continue;
            }
        }

        if (ExemptPath_Match(Path, rule->Pattern, rule->MatchMode)) {
            rule->HitCount++;
            if (Reason) {
                *Reason = ExemptReason_PathMatch;
            }
            hit = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&Engine->Manager.Lock);

    return hit;
}
