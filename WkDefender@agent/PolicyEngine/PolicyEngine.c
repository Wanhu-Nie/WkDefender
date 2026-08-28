/**************************************************/
/*  WkDefender PolicyEngine — 策略引擎实现          */
/*  规则评估 + 告警去重 + 持久化 + 日志             */
/**************************************************/

#include "PolicyEngine.h"
#include "../Storage/StorageEngine.h"
#include "../IOA/IoaPersistQueue.h"
#include "../Orchestrator/VerdictEngine.h"
#include <wchar.h>
#include <wctype.h>
#include <string.h>

POLICY_ENGINE g_PolicyEngine = { 0 };

/**************************************************/
/*       序列规则引擎状态 (ShadowStrike PatternMatcher 迁移)  */
/*                                                  */
/*  实现 WKD_DETECTION_RULE.IsAtomic=FALSE 的        */
/*  序列分支。文件级全局, 仿 g_PolicyEngine。         */
/*  默认 EnableSequenceRules=FALSE (死代码开关),      */
/*  注册 API 为活代码。                              */
/**************************************************/

typedef struct _WKD_SEQ_ENGINE {
    BOOLEAN         Initialized;
    BOOLEAN         EnableSequenceRules;        /* 死代码总开关, 默认 FALSE */

    /* 规则表 (固定数组, 对齐 g_PolicyEngine.RuntimeRules) */
    WKD_SEQUENCE_RULE Rules[WKD_SEQ_MAX_RULES];
    ULONG             RuleCount;

    /* 状态稀疏哈希 <SrcNodeId,TgtNodeId,RuleIndex> (对齐 FSM PatternHashBuckets) */
    LIST_ENTRY        StateHashBuckets[WKD_SEQ_STATE_HASH_BUCKETS];
    volatile LONG     StateCount;

    CRITICAL_SECTION  Lock;

    /* 统计 (对齐 PM_MATCHER.Stats) */
    volatile LONG64   TotalEventsProcessed;
    volatile LONG64   TotalMatches;
    volatile LONG64   TotalTimeouts;
    volatile LONG64   TotalStatesCreated;
    volatile LONG64   TotalStatesFreed;
} WKD_SEQ_ENGINE, *PWKD_SEQ_ENGINE;

static WKD_SEQ_ENGINE g_SeqEngine = { 0 };

/**************************************************/
/*               规则评估                           */
/**************************************************/

static BOOLEAN
Policy_EvaluateRule(
    _In_ const POLICY_RULE* Rule,
    _In_ PWKD_EVENT_HEADER  Event,
    _In_ PWKD_PROCESS  Node
    )
{
    ULONG score, flags;

    if (!Rule->Enabled) return FALSE;

    score = Node ? Node->CumulativeRiskScore : 0;
    flags = (Node ? Node->BehaviorFlags : 0) | Event->BehaviorFlags;

    if (score < Rule->MinScore) return FALSE;
    if (Rule->RequiredFlags && ((flags & Rule->RequiredFlags) != Rule->RequiredFlags)) return FALSE;
    if (Rule->AnyFlags && !(flags & Rule->AnyFlags)) return FALSE;

    return TRUE;
}

/**************************************************/
/*               告警去重                           */
/**************************************************/

static BOOLEAN
Policy_IsDuplicate(
    _In_ GUID    NodeId,
    _In_ PCWSTR         RuleName
    )
{
    LARGE_INTEGER now;
    LONGLONG throttleTicks = (LONGLONG)g_PolicyEngine.ThrottleSeconds * 10000000LL;

    GetSystemTimeAsFileTime((PFILETIME)&now);

    for (ULONG i = 0; i < g_PolicyEngine.DedupCount; i++) {
        if (DefGuidEqual(&g_PolicyEngine.DedupTable[i].ProcessNodeId, &NodeId) &&
            wcscmp(g_PolicyEngine.DedupTable[i].RuleName, RuleName) == 0) {
            if ((now.QuadPart - g_PolicyEngine.DedupTable[i].LastAlertTime.QuadPart) < throttleTicks)
                return TRUE;
            g_PolicyEngine.DedupTable[i].LastAlertTime = now;
            return FALSE;
        }
    }

    if (g_PolicyEngine.DedupCount < POLICY_DEDUP_MAX) {
        g_PolicyEngine.DedupTable[g_PolicyEngine.DedupCount].ProcessNodeId = NodeId;
        wcscpy_s(g_PolicyEngine.DedupTable[g_PolicyEngine.DedupCount].RuleName, 128, RuleName);
        g_PolicyEngine.DedupTable[g_PolicyEngine.DedupCount].LastAlertTime = now;
        g_PolicyEngine.DedupCount++;
    }
    return FALSE;
}

/**************************************************/
/*                   公开 API                       */
/**************************************************/

NTSTATUS
PolicyEngine_Initialize(_In_ ULONG ThrottleSeconds)
{
    RtlZeroMemory(&g_PolicyEngine, sizeof(g_PolicyEngine));
    g_PolicyEngine.ThrottleSeconds = ThrottleSeconds;
    InitializeCriticalSection(&g_PolicyEngine.Lock);
    g_PolicyEngine.Initialized = TRUE;

    /* 序列规则引擎初始化 (ShadowStrike PatternMatcher 迁移, 2026-08-05)
     * 默认 EnableSequenceRules=FALSE (死代码开关), 注册 API 可用。 */
    RtlZeroMemory(&g_SeqEngine, sizeof(g_SeqEngine));
    for (ULONG i = 0; i < WKD_SEQ_STATE_HASH_BUCKETS; i++) {
        InitializeListHead(&g_SeqEngine.StateHashBuckets[i]);
    }
    InitializeCriticalSection(&g_SeqEngine.Lock);
    g_SeqEngine.Initialized = TRUE;

    printf("[PolicyEngine] Initialized: %u rules, throttle=%lus\n",
           (ULONG)BUILTIN_RULE_COUNT, ThrottleSeconds);
    return STATUS_SUCCESS;
}

VOID
PolicyEngine_Cleanup(VOID)
{
    if (!g_PolicyEngine.Initialized) return;
    printf("[PolicyEngine] Cleanup: alerts=%lld throttled=%lld\n",
           g_PolicyEngine.AlertsGenerated, g_PolicyEngine.AlertsThrottled);
    g_PolicyEngine.Initialized = FALSE;
    DeleteCriticalSection(&g_PolicyEngine.Lock);

    /* 序列规则引擎清理: 释放全部状态 */
    if (g_SeqEngine.Initialized) {
        EnterCriticalSection(&g_SeqEngine.Lock);
        for (ULONG b = 0; b < WKD_SEQ_STATE_HASH_BUCKETS; b++) {
            PLIST_ENTRY head = &g_SeqEngine.StateHashBuckets[b];
            while (!IsListEmpty(head)) {
                PLIST_ENTRY e = RemoveHeadList(head);
                PWKD_SEQ_MATCH_STATE st = CONTAINING_RECORD(
                    e, WKD_SEQ_MATCH_STATE, HashLink);
                if (!IsListEmpty(&st->PairLink)) RemoveEntryList(&st->PairLink);
                UtHeapFree(st);
            }
        }
        g_SeqEngine.StateCount = 0;
        LeaveCriticalSection(&g_SeqEngine.Lock);
        DeleteCriticalSection(&g_SeqEngine.Lock);
        g_SeqEngine.Initialized = FALSE;
    }
}

NTSTATUS
PolicyEngine_Evaluate(
    _In_ PWKD_EVENT_HEADER  Event,
    _In_opt_ PWKD_PROCESS Node
    )
{
    GUID nodeId;

    if (!g_PolicyEngine.Initialized || !Event) return STATUS_INVALID_PARAMETER;

    nodeId = Node ? Node->NodeId : Event->TargetProcessId;

    EnterCriticalSection(&g_PolicyEngine.Lock);

    for (ULONG i = 0; i < BUILTIN_RULE_COUNT; i++) {
        if (!Policy_EvaluateRule(&g_BuiltinRules[i], Event, Node))
            continue;

        if (Policy_IsDuplicate(nodeId, g_BuiltinRules[i].Name)) {
            g_PolicyEngine.AlertsThrottled++;
            continue;
        }

        /* 输出告警 */
        {
            PCWSTR imgName = (Node && Node->ImageFileName && Node->ImageFileName->Buffer)
                             ? Node->ImageFileName->Buffer : L"?";
            ULONG pid = Node ? Node->ProcessId : 0;
            ULONG score = Node ? Node->CumulativeRiskScore : Event->Confidence;

            printf("\n[PolicyEngine] *** ALERT ***\n"
                   "  Rule:     %S\n  Process:  %S (PID=%lu)\n"
                   "  MITRE:    %S\n  Score:    %lu Severity: %d\n"
                   "  Desc:     %S\n\n",
                   g_BuiltinRules[i].Name, imgName, pid,
                   g_BuiltinRules[i].MitreId, score,
                   max(Event->Severity, g_BuiltinRules[i].MinSeverity),
                   g_BuiltinRules[i].Description);

            g_PolicyEngine.AlertsGenerated++;
        }
    }

    LeaveCriticalSection(&g_PolicyEngine.Lock);

    /* 运行时规则评估 (ThreatDetector 迁移, 2026-08-04)
     * 默认 EnableRuntimeRules=FALSE 关闭; 开启后叠加运行时规则加分。 */
    if (g_PolicyEngine.EnableRuntimeRules) {
        PolicyEngine_EvaluateRuntime(Event, Node, NULL);
    }

    return STATUS_SUCCESS;
}

/**************************************************/
/*         运行时规则引擎 (ThreatDetector 迁移)       */
/*                                                  */
/*  注册表 API 为活代码 (可经 ALPC/UI 调用);         */
/*  评估逻辑默认 EnableRuntimeRules=FALSE 不执行。   */
/*  SS DetectionRule 的 ApplyRules 为假 API (声明   */
/*  未实现), 此处评估逻辑自行实现。                  */
/**************************************************/

/**************************************************/
/*       完整通配匹配 (ShadowStrike 迁移, 2026-08)    */
/*                                                  */
/*  '*' 任意串 + '?' 单字符 + 大小写折叠 + 迭代上限   */
/*  防 ReDoS。                                      */
/*                                                  */
/*  升级: 原实现仅支持单 '*' 前后缀。现对齐           */
/*  SS PmpMatchWildcardSafe (PatternMatcher.c        */
/*  L1599-1701) 的 starP/starS 贪婪回溯 + 迭代上限,  */
/*  及 IompMatchWildcard (IocMatcherMatch.c L16-73)  */
/*  '?' 支持, WCHAR 版 (towlower 全覆盖折叠)。       */
/*  供 Policy_RuntimeRuleMatch 与序列规则引擎共用。    */
/**************************************************/
BOOLEAN
Policy_WildcardMatch(
    _In_ PCWSTR Pattern,
    _In_ PCWSTR Text
    )
{
    PCWSTR p = Pattern;
    PCWSTR s = Text;
    PCWSTR starP = NULL;
    PCWSTR starS = NULL;
    SIZE_T patternLen;
    SIZE_T stringLen;
    ULONG iterations = 0;

    if (!Pattern || !Text) return FALSE;

    patternLen = wcsnlen(Pattern, WKD_SEQ_PATTERN_LEN);
    if (patternLen == 0) return TRUE;               /* 空模式匹配一切 */
    if (wcscmp(Pattern, L"*") == 0) return TRUE;

    stringLen = wcsnlen(Text, WKD_SEQ_PATTERN_LEN);

    while ((SIZE_T)(s - Text) < stringLen && *s != L'\0') {
        /* 防 ReDoS: 迭代上限 (对齐 PM_MAX_WILDCARD_ITERATIONS) */
        if (++iterations > WKD_SEQ_MAX_WILDCARD_ITERATIONS) return FALSE;

        /* 模式越界且无 '*' 可回溯 */
        if ((SIZE_T)(p - Pattern) >= patternLen && starP == NULL) return FALSE;

        if ((SIZE_T)(p - Pattern) < patternLen && *p == L'*') {
            starP = p++;
            starS = s;
        } else if ((SIZE_T)(p - Pattern) < patternLen &&
                   (*p == L'?' ||
                    towlower((wint_t)*p) == towlower((wint_t)*s))) {
            p++;
            s++;
        } else if (starP) {
            p = starP + 1;
            s = ++starS;
        } else {
            return FALSE;
        }
    }

    /* 跳过尾部 '*' */
    while ((SIZE_T)(p - Pattern) < patternLen && *p == L'*') p++;

    return ((SIZE_T)(p - Pattern) >= patternLen || *p == L'\0');
}

/**************************************************/
/*       多条件 AND 组合求值 (RuleEngine 迁移, 2026-08)  */
/*                                                  */
/*  迁移自 SS RuleEngine.c (重功能实现非复制):        */
/*    Policy_MatchString       ← RepMatchUnicodeString */
/*    Policy_EvaluateCondition ← RepEvaluateCondition */
/*    Policy_CompileRule       ← RepCompileRule +    */
/*                               4 子编译器          */
/*                                                  */
/*  缺数据语义对齐 SS: 上下文字段 NULL → 条件不满足    */
/*  (规则不命中), 区别于便捷字段的"缺数据放行"。       */
/*  编译缓存 Cc 恒有效 (规则经 AddRule→CompileRule);   */
/*  兜底未编译时仅字符串条件可现算。                  */
/**************************************************/

/* 字符串条件匹配 (对齐 SS RepMatchUnicodeString L2209-2325;
 * CaseInsensitive 恒 TRUE, 对齐 SS 编译 L1749)。 */
static BOOLEAN
Policy_MatchString(
    _In_ PCWSTR        Pattern,
    _In_ ULONG         PatternLen,
    _In_ PCWSTR        Value,
    _In_ WKD_OPERATOR  Operator
    )
{
    ULONG valueLen;
    ULONG i;

    if (!Pattern || !Value) return FALSE;

    valueLen = (ULONG)wcslen(Value);

    switch (Operator) {
    case WkdOp_Equals:
        if (PatternLen != valueLen) return FALSE;
        return _wcsnicmp(Pattern, Value, PatternLen) == 0;

    case WkdOp_NotEquals:
        if (PatternLen != valueLen) return TRUE;
        return _wcsnicmp(Pattern, Value, PatternLen) != 0;

    case WkdOp_Contains:
        if (PatternLen > valueLen) return FALSE;
        for (i = 0; i <= valueLen - PatternLen; i++) {
            if (_wcsnicmp(Pattern, Value + i, PatternLen) == 0) return TRUE;
        }
        return FALSE;

    case WkdOp_StartsWith:
        if (PatternLen > valueLen) return FALSE;
        return _wcsnicmp(Pattern, Value, PatternLen) == 0;

    case WkdOp_EndsWith:
        if (PatternLen > valueLen) return FALSE;
        return _wcsnicmp(Pattern, Value + valueLen - PatternLen, PatternLen) == 0;

    case WkdOp_Wildcard:
        return Policy_WildcardMatch(Pattern, Value);

    case WkdOp_InList:
        /* ※死代码: 编译期拒绝 (对齐 SS RepCompileRule L1755-1757) */
        return FALSE;

    default:
        return FALSE;
    }
}

/* 哈希条件编译 (对齐 SS RepCompileHashCondition L1858-1906: 64 hex→32 bytes) */
static BOOLEAN
Policy_CompileHashCondition(
    _In_ PCWSTR HexString,
    _Out_ PWKD_COMPILED_CONDITION Compiled
    )
{
    size_t length;
    ULONG i, j;

    length = wcslen(HexString);
    if (length != 64) return FALSE;

    RtlZeroMemory(Compiled->FileHash, sizeof(Compiled->FileHash));

    for (i = 0; i < 32; i++) {
        for (j = 0; j < 2; j++) {
            WCHAR c = HexString[i * 2 + j];
            ULONG v;
            if (c >= L'0' && c <= L'9')      v = (ULONG)(c - L'0');
            else if (c >= L'A' && c <= L'F') v = (ULONG)(c - L'A') + 10;
            else if (c >= L'a' && c <= L'f') v = (ULONG)(c - L'a') + 10;
            else return FALSE;
            Compiled->FileHash[i] = (UCHAR)((Compiled->FileHash[i] << 4) | v);
        }
    }
    return TRUE;
}

/* 时间段条件编译 (对齐 SS RepCompileTimeCondition L1931-1983: "HH:MM-HH:MM") */
static BOOLEAN
Policy_CompileTimeCondition(
    _In_ PCWSTR TimeSpec,
    _Out_ PWKD_COMPILED_CONDITION Compiled
    )
{
    size_t length;
    ULONG startHour, startMinute, endHour, endMinute;
    ULONG i;

    length = wcslen(TimeSpec);
    if (length != 11) return FALSE;
    if (TimeSpec[2] != L':' || TimeSpec[5] != L'-' || TimeSpec[8] != L':') return FALSE;

    for (i = 0; i < 11; i++) {
        if (i == 2 || i == 5 || i == 8) continue;
        if (TimeSpec[i] < L'0' || TimeSpec[i] > L'9') return FALSE;
    }

    startHour   = (ULONG)(TimeSpec[0] - L'0') * 10 + (ULONG)(TimeSpec[1] - L'0');
    startMinute = (ULONG)(TimeSpec[3] - L'0') * 10 + (ULONG)(TimeSpec[4] - L'0');
    endHour     = (ULONG)(TimeSpec[6] - L'0') * 10 + (ULONG)(TimeSpec[7] - L'0');
    endMinute   = (ULONG)(TimeSpec[9] - L'0') * 10 + (ULONG)(TimeSpec[10] - L'0');

    if (startHour >= 24 || startMinute >= 60 ||
        endHour >= 24 || endMinute >= 60) return FALSE;

    Compiled->TimeStartMinute = startHour * 60 + startMinute;
    Compiled->TimeEndMinute   = endHour * 60 + endMinute;
    return TRUE;
}

/* 规则编译 (对齐 SS RepCompileRule L1727-1809 + 子编译器; 用户态无 Unicode 转换) */
static NTSTATUS
Policy_CompileRule(
    _Inout_ PWKD_DETECTION_RULE Rule
    )
{
    ULONG i;

    if (!Rule) return STATUS_INVALID_PARAMETER;
    if (Rule->ConditionCount > WKD_RULE_MAX_CONDITIONS) return STATUS_INVALID_PARAMETER;
    if (Rule->ActionCount   > WKD_RULE_MAX_ACTIONS)    return STATUS_INVALID_PARAMETER;

    Rule->CompiledConditionCount = 0;
    Rule->IsCompiled = FALSE;

    for (i = 0; i < Rule->ConditionCount; i++) {
        PWKD_CONDITION          cond = &Rule->Conditions[i];
        PWKD_COMPILED_CONDITION cc   = &Rule->CompiledConditions[i];
        size_t valueLen;

        if (cond->Type >= WkdCond_MaxValue || cond->Operator >= WkdOp_MaxValue)
            return STATUS_INVALID_PARAMETER;

        RtlZeroMemory(cc, sizeof(*cc));

        /* InList 编译期拒绝 (对齐 SS RepCompileRule L1755-1757) */
        if (cond->Operator == WkdOp_InList)
            return STATUS_NOT_SUPPORTED;

        valueLen = wcslen(cond->Value);

        switch (cond->Type) {
        case WkdCond_ProcessName:
        case WkdCond_ParentName:
        case WkdCond_CommandLine:
        case WkdCond_FilePath:
        case WkdCond_RegistryPath:
        case WkdCond_NetworkAddress:
        case WkdCond_Domain:
        case WkdCond_MitreTechnique:
        case WkdCond_Custom:
            /* 字符串条件 (对齐 SS RepCompileStringCondition L1811-1856,
             * 用户态 WCHAR 原生免转换, 省略预哈希) */
            if (valueLen == 0 || valueLen > WKD_RULE_MAX_VALUE_LEN)
                return STATUS_INVALID_PARAMETER;
            cc->PatternLen = (ULONG)valueLen;
            cc->IsCompiled = TRUE;
            break;

        case WkdCond_FileHash:
            if (!Policy_CompileHashCondition(cond->Value, cc))
                return STATUS_INVALID_PARAMETER;
            cc->IsCompiled = TRUE;
            break;

        case WkdCond_ThreatScore:
        case WkdCond_BehaviorFlag:
            /* 数值条件 (对齐 SS RepCompileNumericCondition L1908-1929;
             * wcstoul base 0 支持 0x 前缀) */
            cc->NumericValue = (ULONG)wcstoul(cond->Value, NULL, 0);
            cc->IsCompiled = TRUE;
            break;

        case WkdCond_TimeOfDay:
            if (!Policy_CompileTimeCondition(cond->Value, cc))
                return STATUS_INVALID_PARAMETER;
            cc->IsCompiled = TRUE;
            break;

        default:
            return STATUS_INVALID_PARAMETER;
        }

        Rule->CompiledConditionCount++;
    }

    Rule->IsCompiled = TRUE;
    return STATUS_SUCCESS;
}

/* 单条件求值 (对齐 SS RepEvaluateCondition L1989-2203)。
 * 编译缓存 Cc 有效时用预解析值; 无效时仅字符串条件现算兜底。
 * Negate 由调用方取反 (对齐 SS ReEvaluate L996-998)。 */
static BOOLEAN
Policy_EvaluateCondition(
    _In_ PCWKD_CONDITION          Cond,
    _In_opt_ PCWKD_COMPILED_CONDITION Cc,
    _In_ PCWKD_EVAL_CONTEXT       Ctx
    )
{
    BOOLEAN compiled;
    ULONG patternLen;
    ULONG numericValue;
    BOOLEAN result = FALSE;

    if (!Cond || !Ctx) return FALSE;

    compiled    = (Cc != NULL && Cc->IsCompiled);
    patternLen  = compiled ? Cc->PatternLen : (ULONG)wcslen(Cond->Value);
    numericValue = (compiled && (Cond->Type == WkdCond_ThreatScore ||
                                 Cond->Type == WkdCond_BehaviorFlag))
                 ? Cc->NumericValue : (ULONG)wcstoul(Cond->Value, NULL, 0);

    switch (Cond->Type) {
    case WkdCond_ProcessName:
        if (Ctx->ProcessName) {
            result = Policy_MatchString(Cond->Value, patternLen,
                                        Ctx->ProcessName, Cond->Operator);
        }
        break;

    case WkdCond_ParentName:
        if (Ctx->ParentName) {
            result = Policy_MatchString(Cond->Value, patternLen,
                                        Ctx->ParentName, Cond->Operator);
        }
        break;

    case WkdCond_CommandLine:
        if (Ctx->CommandLine) {
            result = Policy_MatchString(Cond->Value, patternLen,
                                        Ctx->CommandLine, Cond->Operator);
        }
        break;

    case WkdCond_FilePath:
        if (Ctx->FilePath) {
            result = Policy_MatchString(Cond->Value, patternLen,
                                        Ctx->FilePath, Cond->Operator);
        }
        break;

    case WkdCond_FileHash:
        /* ※死代码: Ctx->FileHash 恒 NULL (文件信誉由 ioc_hashes/IocMatcher 覆盖) */
        if (compiled && Ctx->FileHash) {
            BOOLEAN hashMatch = (RtlCompareMemory(Cc->FileHash, Ctx->FileHash, 32) == 32);
            result = (Cond->Operator == WkdOp_NotEquals) ? !hashMatch : hashMatch;
        }
        break;

    case WkdCond_RegistryPath:
        /* ※死代码: Ctx->RegistryPath 恒 NULL (注册表载荷未接 IOA) */
        if (Ctx->RegistryPath) {
            result = Policy_MatchString(Cond->Value, patternLen,
                                        Ctx->RegistryPath, Cond->Operator);
        }
        break;

    case WkdCond_NetworkAddress:
        /* ※死代码: Ctx->NetworkAddress 恒 NULL (网络事件源未接通) */
        if (Ctx->NetworkAddress) {
            result = Policy_MatchString(Cond->Value, patternLen,
                                        Ctx->NetworkAddress, Cond->Operator);
        }
        break;

    case WkdCond_Domain:
        /* ※死代码: Ctx->Domain 恒 NULL (网络事件源未接通) */
        if (Ctx->Domain) {
            result = Policy_MatchString(Cond->Value, patternLen,
                                        Ctx->Domain, Cond->Operator);
        }
        break;

    case WkdCond_ThreatScore:
        switch (Cond->Operator) {
        case WkdOp_Equals:       result = (Ctx->ThreatScore == numericValue); break;
        case WkdOp_NotEquals:    result = (Ctx->ThreatScore != numericValue); break;
        case WkdOp_GreaterThan:  result = (Ctx->ThreatScore >  numericValue); break;
        case WkdOp_LessThan:     result = (Ctx->ThreatScore <  numericValue); break;
        default:                 result = FALSE; break;
        }
        break;

    case WkdCond_MitreTechnique:
        /* ※死代码: Ctx->MitreTechnique 恒 NULL (单事件上下文无标注, T3Tactic 在 PairContext) */
        if (Ctx->MitreTechnique) {
            result = Policy_MatchString(Cond->Value, patternLen,
                                        Ctx->MitreTechnique, Cond->Operator);
        }
        break;

    case WkdCond_BehaviorFlag:
        {
            BOOLEAN hasFlag = (Ctx->BehaviorFlags & numericValue) != 0;
            switch (Cond->Operator) {
            case WkdOp_Equals:    result = ((Ctx->BehaviorFlags & numericValue) == numericValue); break;
            case WkdOp_NotEquals: result = !hasFlag; break;
            default:              result = hasFlag; break;
            }
        }
        break;

    case WkdCond_TimeOfDay:
        /* 对齐 SS L2155-2186: 系统时间→当日分钟, 环回区间处理 */
        if (compiled) {
            ULONG currentMinute = (ULONG)(Ctx->CurrentTime.wHour * 60 + Ctx->CurrentTime.wMinute);
            if (Cc->TimeStartMinute <= Cc->TimeEndMinute) {
                result = (currentMinute >= Cc->TimeStartMinute &&
                          currentMinute <= Cc->TimeEndMinute);
            } else {
                result = (currentMinute >= Cc->TimeStartMinute ||
                          currentMinute <= Cc->TimeEndMinute);
            }
        }
        break;

    case WkdCond_Custom:
        /* ※死代码: 无运行时 handler, 恒 FALSE (对齐 SS L2188-2195) */
        result = FALSE;
        break;

    default:
        result = FALSE;
        break;
    }

    return result;
}

/* 单条运行时规则匹配 (对齐 SS DetectionRule 字段语义) */
static BOOLEAN
Policy_RuntimeRuleMatch(
    _In_ const WKD_DETECTION_RULE* Rule,
    _In_ PWKD_EVENT_HEADER         Event,
    _In_opt_ PWKD_PROCESS     Node,
    _Out_ PULONG                   ScoreOut
    )
{
    ULONG score;
    ULONG flags;

    if (!Rule->Enabled) return FALSE;

    score = Node ? Node->CumulativeRiskScore : 0;
    flags = (Node ? Node->BehaviorFlags : 0) | Event->BehaviorFlags;

    /* 事件类型匹配 (0=任意) */
    if (Rule->EventType && Rule->EventType != Event->Type) return FALSE;

    /* 进程名通配 */
    if (Rule->ProcessPattern[0] && Node && Node->ImageFileName && Node->ImageFileName->Buffer) {
        if (!Policy_WildcardMatch(Rule->ProcessPattern, Node->ImageFileName->Buffer)) return FALSE;
    }

    /* 评分/标志门槛 (融合 POLICY_RULE 语义) */
    if (Rule->MinScore && score < Rule->MinScore) return FALSE;
    if (Rule->RequiredFlags && ((flags & Rule->RequiredFlags) != Rule->RequiredFlags)) return FALSE;
    if (Rule->AnyFlags && !(flags & Rule->AnyFlags)) return FALSE;

    if (ScoreOut) *ScoreOut = Rule->ScoreContribution;
    return TRUE;
}

NTSTATUS
PolicyEngine_AddRule(
    _In_ const WKD_DETECTION_RULE* Rule
    )
{
    WKD_DETECTION_RULE candidate;
    ULONG insertIndex;
    ULONG i;

    if (!Rule || Rule->RuleId[0] == 0) return STATUS_INVALID_PARAMETER;
    if (!g_PolicyEngine.Initialized) return STATUS_NOT_IMPLEMENTED;

    candidate = *Rule;
    candidate.EvaluationCount = 0;
    candidate.MatchCount = 0;
    candidate.LastMatchTime.QuadPart = 0;
    candidate.IsCompiled = FALSE;
    candidate.CompiledConditionCount = 0;

    /* 编译校验 (锁外; 对齐 SS ReLoadRule 编译在持锁前 L650-692) */
    if (candidate.ConditionCount > 0) {
        NTSTATUS status = Policy_CompileRule(&candidate);
        if (!NT_SUCCESS(status)) {
            printf("[PolicyEngine] Runtime rule compile failed: %ls (0x%08X)\n",
                   Rule->RuleId, status);
            return status;
        }
    }

    EnterCriticalSection(&g_PolicyEngine.Lock);

    if (g_PolicyEngine.RuntimeRuleCount >= POLICY_RUNTIME_RULES_MAX) {
        LeaveCriticalSection(&g_PolicyEngine.Lock);
        printf("[PolicyEngine] Runtime rule cap reached (%d)\n", POLICY_RUNTIME_RULES_MAX);
        return STATUS_TOO_MANY_COMMANDS;
    }
    /* 去重: 同 RuleId 拒绝 */
    for (i = 0; i < g_PolicyEngine.RuntimeRuleCount; i++) {
        if (wcscmp(g_PolicyEngine.RuntimeRules[i].RuleId, Rule->RuleId) == 0) {
            LeaveCriticalSection(&g_PolicyEngine.Lock);
            return STATUS_DUPLICATE_OBJECTID;
        }
    }

    /* 按 Priority 插入排序 (低=高优先级在前; 对齐 SS
     * RepInsertRuleSortedLocked L2451-2483) */
    insertIndex = g_PolicyEngine.RuntimeRuleCount;
    for (i = 0; i < g_PolicyEngine.RuntimeRuleCount; i++) {
        if (candidate.Priority < g_PolicyEngine.RuntimeRules[i].Priority) {
            insertIndex = i;
            break;
        }
    }
    if (insertIndex < g_PolicyEngine.RuntimeRuleCount) {
        memmove(&g_PolicyEngine.RuntimeRules[insertIndex + 1],
                &g_PolicyEngine.RuntimeRules[insertIndex],
                (g_PolicyEngine.RuntimeRuleCount - insertIndex) *
                sizeof(WKD_DETECTION_RULE));
    }

    g_PolicyEngine.RuntimeRules[insertIndex] = candidate;
    g_PolicyEngine.RuntimeRuleCount++;

    printf("[PolicyEngine] Runtime rule added: %ls (id=%ls, score=%lu, priority=%lu%s)\n",
           Rule->Name, Rule->RuleId, Rule->ScoreContribution, Rule->Priority,
           (Rule->ConditionCount > 0) ? L", conditions" : L"");

    LeaveCriticalSection(&g_PolicyEngine.Lock);
    return STATUS_SUCCESS;
}

NTSTATUS
PolicyEngine_RemoveRule(
    _In_ PCWSTR RuleId
    )
{
    if (!RuleId || RuleId[0] == 0) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&g_PolicyEngine.Lock);
    for (ULONG i = 0; i < g_PolicyEngine.RuntimeRuleCount; i++) {
        if (wcscmp(g_PolicyEngine.RuntimeRules[i].RuleId, RuleId) == 0) {
            /* 尾元素覆盖移除, 保持紧凑 */
            if (i + 1 < g_PolicyEngine.RuntimeRuleCount) {
                g_PolicyEngine.RuntimeRules[i] = g_PolicyEngine.RuntimeRules[g_PolicyEngine.RuntimeRuleCount - 1];
            }
            g_PolicyEngine.RuntimeRuleCount--;
            printf("[PolicyEngine] Runtime rule removed: %ls\n", RuleId);
            LeaveCriticalSection(&g_PolicyEngine.Lock);
            return STATUS_SUCCESS;
        }
    }
    LeaveCriticalSection(&g_PolicyEngine.Lock);
    return STATUS_NOT_FOUND;
}

VOID
PolicyEngine_SetRuleEnabled(
    _In_ PCWSTR RuleId,
    _In_ BOOLEAN Enabled
    )
{
    EnterCriticalSection(&g_PolicyEngine.Lock);
    for (ULONG i = 0; i < g_PolicyEngine.RuntimeRuleCount; i++) {
        if (wcscmp(g_PolicyEngine.RuntimeRules[i].RuleId, RuleId) == 0) {
            g_PolicyEngine.RuntimeRules[i].Enabled = Enabled;
            break;
        }
    }
    LeaveCriticalSection(&g_PolicyEngine.Lock);
}

ULONG
PolicyEngine_GetRuleCount(
    VOID
    )
{
    ULONG n;
    EnterCriticalSection(&g_PolicyEngine.Lock);
    n = g_PolicyEngine.RuntimeRuleCount;
    LeaveCriticalSection(&g_PolicyEngine.Lock);
    return n;
}

/* 返回所有运行时规则 (对齐 SS GetRules cpp L1859-1870) */
ULONG
PolicyEngine_GetRules(
    _Out_ PWKD_DETECTION_RULE Out,
    _In_ ULONG                MaxCount
    )
{
    ULONG n = 0;

    if (!Out || MaxCount == 0) return 0;

    EnterCriticalSection(&g_PolicyEngine.Lock);
    for (ULONG i = 0; i < g_PolicyEngine.RuntimeRuleCount && n < MaxCount; i++) {
        Out[n] = g_PolicyEngine.RuntimeRules[i];
        /* 清零内部编译缓存, 不暴露给调用方 (对齐 SS ReGetRule
         * 清 ListEntry, RuleEngine.c L1314-1315) */
        Out[n].CompiledConditionCount = 0;
        Out[n].IsCompiled = FALSE;
        RtlZeroMemory(Out[n].CompiledConditions, sizeof(Out[n].CompiledConditions));
        n++;
    }
    LeaveCriticalSection(&g_PolicyEngine.Lock);
    return n;
}

VOID
PolicyEngine_GetStats(
    _Out_opt_ PULONG64 Evaluations,
    _Out_opt_ PULONG64 Matches,
    _Out_opt_ PULONG64 Blocks
    )
/*++
Routine Description:
    引擎级统计快照 (RuleEngine 迁移, 对齐 SS ReGetStatistics
    RuleEngine.c L1388-1420; StartTime/Reserved 低价值省略)。
--*/
{
    if (Evaluations) *Evaluations = g_PolicyEngine.Evaluations;
    if (Matches)     *Matches     = g_PolicyEngine.Matches;
    if (Blocks)      *Blocks      = g_PolicyEngine.Blocks;
}

/**************************************************/
/*       评估上下文构建 (RuleEngine 迁移)            */
/*  (对齐 SS RE_EVALUATION_CONTEXT 字段语义;         */
/*   FileHash/RegistryPath/NetworkAddress/Domain/    */
/*   MitreTechnique 恒 NULL — 死代码条件)            */
/**************************************************/

static VOID
Policy_BuildEvalContext(
    _In_ PWKD_EVENT_HEADER   Event,
    _In_opt_ PWKD_PROCESS Node,
    _Out_ PWKD_EVAL_CONTEXT  Ctx
    )
{
    if (!Ctx) return;
    RtlZeroMemory(Ctx, sizeof(*Ctx));

    Ctx->Event = Event;
    Ctx->Node  = Node;

    if (Node) {
        Ctx->ProcessName = (Node->ImageFileName && Node->ImageFileName->Buffer)
                           ? Node->ImageFileName->Buffer : NULL;
        Ctx->ParentName  = (Node->Parent && Node->Parent->ImageFileName &&
                            Node->Parent->ImageFileName->Buffer)
                           ? Node->Parent->ImageFileName->Buffer : NULL;
        Ctx->CommandLine = (Node->CommandLine && Node->CommandLine->Buffer)
                           ? Node->CommandLine->Buffer : NULL;
        Ctx->FilePath    = (Node->ImagePath && Node->ImagePath->Buffer)
                           ? Node->ImagePath->Buffer : NULL;
        Ctx->ThreatScore = Node->CumulativeRiskScore;
        Ctx->BehaviorFlags = Node->BehaviorFlags;
    }
    if (Event) Ctx->BehaviorFlags |= Event->BehaviorFlags;

    GetLocalTime(&Ctx->CurrentTime);
}

/**************************************************/
/*       规则命中告警构造 + 入队                    */
/*  (对齐 SeqAllocAndEnqueueAlert 单块堆分配语义,    */
/*   PolicyEngine.c L640-712; 字段对齐 IOA_ALERT)   */
/**************************************************/

static VOID
Policy_AllocAndEnqueueRuleAlert(
    _In_ PWKD_DETECTION_RULE Rule,
    _In_ PWKD_EVENT_HEADER   Event,
    _In_opt_ PWKD_PROCESS Node
    )
{
    WCHAR descBuf[512];
    size_t ruleLen, mitreLen, descLen, total;
    PIOA_ALERT alert;
    PWCHAR buf;
    PCWSTR mitreId;
    GUID suspectId, victimId;

    if (!Rule || !Event) return;

    mitreId = Rule->MitreId[0] != L'\0' ? Rule->MitreId : NULL;

    swprintf_s(descBuf, 512,
               L"Runtime rule matched: %ls (score=%lu)",
               Rule->Name, Rule->ScoreContribution);

    ruleLen  = wcslen(Rule->Name);
    mitreLen = mitreId ? wcslen(mitreId) : 0;
    descLen  = wcslen(descBuf);

    total = sizeof(IOA_ALERT) +
            (ruleLen + 1 + mitreLen + 1 + descLen + 1) * sizeof(WCHAR);

    alert = (PIOA_ALERT)UtHeapAlloc(total);
    if (!alert) return;
    RtlZeroMemory(alert, total);

    suspectId = (Node) ? Node->NodeId : Event->SourceProcessId;
    victimId  = Event->TargetProcessId;

    CoCreateGuid(&alert->AlertId);
    alert->Timestamp       = Event->Timestamp;
    alert->SuspectNodeId   = suspectId;
    alert->VictimNodeId    = victimId;
    alert->Severity        = Rule->Severity;
    alert->Score           = Rule->ScoreContribution;
    alert->Confidence      = 100;   /* 规则命中确定性满 */
    alert->Category        = Rule->Category;
    alert->ConfidenceLevel    = DefConfidence_Confirmed;
    alert->RecommendedAction  = Rule->Severity >= DefThreatSeverity_Critical
                              ? DefRespAction_Block : DefRespAction_Alert;
    alert->DetectionSource    = DefDetSrc_Rule;

    buf = (PWCHAR)((PUCHAR)alert + sizeof(IOA_ALERT));
    alert->RuleName = buf;
    wcscpy_s(buf, ruleLen + 1, Rule->Name);
    buf += ruleLen + 1;

    if (mitreLen) {
        alert->MitreId = buf;
        wcscpy_s(buf, mitreLen + 1, mitreId);
        buf += mitreLen + 1;
    }
    if (descLen) {
        alert->Description = buf;
        wcscpy_s(buf, descLen + 1, descBuf);
    }

    if (WkdIoaEngine.PersistQueue) {
        IoaPersistQueueEnqueue(WkdIoaEngine.PersistQueue,
                               PersistType_Alert, alert,
                               (PERSIST_SERDE_WRITE_FN)StPersistAlert,
                               TRUE);
    } else {
        UtHeapFree(alert);   /* 无持久化队列时释放 (正常情况不触发) */
    }
}

/**************************************************/
/*       规则动作 → VerdictEngine 统一出口          */
/*  (对齐 SS ReAction Block/Terminate/Quarantine    */
/*  语义; 处置走 VerdictEngine_DispatchResponse,     */
/*  内部 monitor-only 门控 Auto* = FALSE)           */
/**************************************************/

static VOID
Policy_BuildVerdictAndDispatch(
    _In_ PWKD_DETECTION_RULE Rule,
    _In_ PWKD_EVENT_HEADER   Event,
    _In_opt_ PWKD_PROCESS Node,
    _In_ DEF_RESPONSE_ACTION RecommendedAction
    )
{
    WKD_VERDICT verdict;
    GUID suspectId, victimId;

    if (!Rule || !Event) return;

    RtlZeroMemory(&verdict, sizeof(verdict));
    CoCreateGuid(&verdict.VerdictId);
    verdict.Timestamp = Event->Timestamp;
    suspectId = (Node) ? Node->NodeId : Event->SourceProcessId;
    victimId  = Event->TargetProcessId;
    verdict.SuspectNodeId     = suspectId;
    verdict.VictimNodeId      = victimId;
    verdict.ThreatScore       = Rule->ScoreContribution;
    verdict.Severity          = Rule->Severity;
    verdict.Confidence        = 100;
    verdict.ConfidenceLevel   = DefConfidence_Confirmed;
    verdict.Category          = Rule->Category;
    verdict.RecommendedAction = RecommendedAction;
    verdict.PrimarySource     = DefDetSrc_Rule;
    verdict.EngineCount       = 1;
    verdict.EngineAgreement   = 100;
    verdict.BestEngineScore   = Rule->ScoreContribution;
    verdict.DetectionFlags    = 0;
    verdict.MitreCount        = (Rule->MitreId[0] != L'\0') ? 1 : 0;
    if (verdict.MitreCount) {
        wcscpy_s(verdict.MitreIds[0], 16, Rule->MitreId);
    }
    if (Node && Node->ImageFileName && Node->ImageFileName->Buffer) {
        wcsncpy_s(verdict.ProcessName, WKD_VERDICT_NAME_LEN,
                  Node->ImageFileName->Buffer, _TRUNCATE);
    }
    swprintf_s(verdict.Description, WKD_VERDICT_DESC_LEN,
               L"Runtime rule action: %ls", Rule->Name);

    VerdictEngine_UpsertActiveThreat(&verdict);
    VerdictEngine_DispatchResponse(&verdict);
}

/**************************************************/
/*       规则动作分派                              */
/*  (对齐 SS ReEvaluate PrimaryAction L1042-1059:   */
/*   Actions[0] 为 PrimaryAction)                  */
/**************************************************/

static VOID
Policy_ApplyActions(
    _In_ PWKD_DETECTION_RULE Rule,
    _In_ PWKD_EVENT_HEADER   Event,
    _In_opt_ PWKD_PROCESS Node
    )
{
    WKD_RULE_ACTION primary;

    if (!Rule || !Event) return;

    primary = (Rule->ActionCount > 0) ? Rule->Actions[0].Type : WkdRuleAction_None;

    switch (primary) {
    case WkdRuleAction_None:
        break;

    case WkdRuleAction_Allow:
        /* 白名单语义: 免告警免加分 (Score 由命中路径正常输出) */
        break;

    case WkdRuleAction_Alert:
        Policy_AllocAndEnqueueRuleAlert(Rule, Event, Node);
        break;

    case WkdRuleAction_Block:
        Policy_BuildVerdictAndDispatch(Rule, Event, Node, DefRespAction_Block);
        break;

    case WkdRuleAction_Quarantine:
        Policy_BuildVerdictAndDispatch(Rule, Event, Node, DefRespAction_Quarantine);
        break;

    case WkdRuleAction_Terminate:
        Policy_BuildVerdictAndDispatch(Rule, Event, Node, DefRespAction_Terminate);
        break;

    case WkdRuleAction_Log:
        printf("[PolicyEngine] Rule matched (log): %ls (id=%ls)\n",
               Rule->Name, Rule->RuleId);
        break;

    case WkdRuleAction_Investigate:
        /* ※死代码: 无对应处置语义, 降级 Alert */
        Policy_AllocAndEnqueueRuleAlert(Rule, Event, Node);
        break;

    case WkdRuleAction_Custom:
        /* ※死代码: 无 handler, 按 None */
        break;

    default:
        break;
    }
}

NTSTATUS
PolicyEngine_EvaluateRuntime(
    _In_ PWKD_EVENT_HEADER   Event,
    _In_opt_ PWKD_PROCESS Node,
    _Inout_opt_ PULONG       Score
    )
{
    /* 对齐 SS ReEvaluate L887-1254: 规则按 Priority 排序, 首个命中停止。
     * ConditionCount>0 → 多条件 AND 组合; =0 → 便捷字段 (既有路径)。 */
    WKD_EVAL_CONTEXT ctx;
    ULONG bestScore = 0;

    if (!Event || !g_PolicyEngine.Initialized) return STATUS_INVALID_PARAMETER;

    Policy_BuildEvalContext(Event, Node, &ctx);

    EnterCriticalSection(&g_PolicyEngine.Lock);
    for (ULONG i = 0; i < g_PolicyEngine.RuntimeRuleCount; i++) {
        PWKD_DETECTION_RULE rule = &g_PolicyEngine.RuntimeRules[i];
        ULONG ruleScore = 0;
        BOOLEAN matched = FALSE;

        if (!rule->Enabled) continue;

        /* 规则级 + 引擎级评估统计 (对齐 SS L979-980) */
        InterlockedIncrement64(&rule->EvaluationCount);
        InterlockedIncrement64(&g_PolicyEngine.Evaluations);

        if (rule->ConditionCount > 0) {
            /* 多条件 AND 组合评估 (RuleEngine 迁移) */
            ULONG c;
            matched = rule->IsCompiled;
            for (c = 0; matched && c < rule->ConditionCount; c++) {
                BOOLEAN condResult = Policy_EvaluateCondition(
                    &rule->Conditions[c],
                    &rule->CompiledConditions[c],
                    &ctx);
                /* 对齐 SS ReEvaluate L996-998: Negate 取反 */
                if (rule->Conditions[c].Negate) condResult = !condResult;
                if (!condResult) matched = FALSE;
            }
        } else {
            /* 便捷字段回退 (既有路径) */
            matched = Policy_RuntimeRuleMatch(rule, Event, Node, &ruleScore);
        }

        if (matched) {
            ruleScore = rule->ScoreContribution;

            InterlockedIncrement64(&rule->MatchCount);
            InterlockedIncrement64(&g_PolicyEngine.Matches);
            if (rule->ActionCount > 0 && rule->Actions[0].Type == WkdRuleAction_Block) {
                InterlockedIncrement64(&g_PolicyEngine.Blocks);   /* 对齐 SS L1057-1059 */
            }

            if (ruleScore > bestScore) bestScore = ruleScore;
            GetSystemTimeAsFileTime((PFILETIME)&rule->LastMatchTime);

            /* 动作分派: Alert→IOA_ALERT; Block/Terminate/Quarantine→VerdictEngine */
            Policy_ApplyActions(rule, Event, Node);

            if (rule->StopProcessing) break;   /* 首个命中停止 (对齐 SS L1076) */
        }
    }
    LeaveCriticalSection(&g_PolicyEngine.Lock);

    if (Score) *Score = bestScore;
    return STATUS_SUCCESS;
}

NTSTATUS
PolicyEngine_LoadRulesFromFile(
    _In_ PCWSTR FilePath
    )
/*++
Routine Description:
    从 JSON/YAML 规则文件加载运行时规则 (※死代码: 序列化未实现。
    对齐 SS LoadRulesFromFile stub — 声明存在但空转, 注册表 AddRule 为活代码)。
--*/
{
    UNREFERENCED_PARAMETER(FilePath);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
PolicyEngine_SaveRulesToFile(
    _In_ PCWSTR FilePath
    )
/*++
Routine Description:
    保存运行时规则到文件 (※死代码: 序列化未实现, 对齐 SS stub)。
--*/
{
    UNREFERENCED_PARAMETER(FilePath);
    return STATUS_NOT_IMPLEMENTED;
}

/**************************************************/
/*       序列规则引擎 (ShadowStrike PatternMatcher 迁移)  */
/*                                                  */
/*  实现 WKD_DETECTION_RULE.IsAtomic=FALSE 的        */
/*  序列分支: 数据驱动事件序列模式匹配。              */
/*                                                  */
/*  迁移自 SS PhantomSensor Behavioral/PatternMatcher.c: */
/*    PolicyEngine_EvaluateSequenceRules ← PmSubmitEvent (双阶段) */
/*    SeqCheckStepConstraint          ← PmpCheckEventConstraint */
/*    SeqAdvanceMatchState            ← PmpAdvanceMatchState  */
/*    SeqCheckPatternComplete         ← PmpCheckPatternComplete */
/*    SeqAllocAndEnqueueAlert         ← PmpNotifyCallback 回调 */
/*    PolicyEngine_CleanupSequenceStates ← PmpCleanupStaleStates */
/*    PolicyEngine_GetSequenceStates  ← PmGetActiveStates     */
/*    PolicyEngine_RemoveSequenceRule ← PmUnloadPattern       */
/*                                                  */
/*  结构映射 (PolicyRules.h):                        */
/*    WKD_SEQUENCE_RULE      ← PM_PATTERN            */
/*    WKD_SEQUENCE_STEP      ← PM_EVENT_CONSTRAINT   */
/*    WKD_SEQ_MATCH_STATE    ← PM_MATCH_STATE_INTERNAL */
/*                                                  */
/*  ※默认 EnableSequenceRules=FALSE 不评估 (死代码),  */
/*    注册 API 为活代码 (可经 ALPC/UI 调用)。         */
/*    与 Tier2 FSM 互补: FSM 编译期硬编码 6 种已知     */
/*    攻击模式; 序列规则为运行时数据驱动规则。          */
/**************************************************/

/**************************************************/
/*               内部辅助: 稀疏哈希                  */
/*  (对齐 FsmpPatternHash, 键 = SrcGuid||TgtGuid||  */
/*   RuleIndex)                                    */
/**************************************************/

static ULONG
SeqHashState(
    _In_ GUID   SrcNodeId,
    _In_ GUID   TgtNodeId,
    _In_ ULONG  RuleIndex
    )
{
    ULONG hash = 5381;
    PUCHAR p;
    ULONG i;

    p = (PUCHAR)&SrcNodeId;
    for (i = 0; i < sizeof(GUID); i++) {
        hash = ((hash << 5) + hash) ^ p[i];
    }
    p = (PUCHAR)&TgtNodeId;
    for (i = 0; i < sizeof(GUID); i++) {
        hash = ((hash << 5) + hash) ^ p[i];
    }
    hash = ((hash << 5) + hash) ^ RuleIndex;
    return hash % WKD_SEQ_STATE_HASH_BUCKETS;
}

/* 查找活跃匹配状态 (对齐 PM stateExists 检查 L1297-1325) */
static PWKD_SEQ_MATCH_STATE
SeqLookupState(
    _In_ GUID   SrcNodeId,
    _In_ GUID   TgtNodeId,
    _In_ ULONG  RuleIndex
    )
{
    ULONG bucket = SeqHashState(SrcNodeId, TgtNodeId, RuleIndex);
    PLIST_ENTRY entry;

    for (entry = g_SeqEngine.StateHashBuckets[bucket].Flink;
         entry != &g_SeqEngine.StateHashBuckets[bucket];
         entry = entry->Flink) {
        PWKD_SEQ_MATCH_STATE state =
            CONTAINING_RECORD(entry, WKD_SEQ_MATCH_STATE, HashLink);
        if (state->RuleIndex == RuleIndex &&
            !state->IsComplete && !state->IsStale && !state->IsRemoved &&
            DefGuidEqual(&state->SrcNodeId, &SrcNodeId) &&
            DefGuidEqual(&state->TgtNodeId, &TgtNodeId)) {
            return state;
        }
    }
    return NULL;
}

/* 创建匹配状态 (对齐 PmpCreateMatchState) */
static PWKD_SEQ_MATCH_STATE
SeqCreateState(
    _In_ GUID             SrcNodeId,
    _In_ GUID             TgtNodeId,
    _In_ ULONG            RuleIndex,
    _In_ PWKD_EVENT_HEADER Event
    )
{
    PWKD_SEQ_MATCH_STATE state;

    state = (PWKD_SEQ_MATCH_STATE)UtHeapAlloc(sizeof(WKD_SEQ_MATCH_STATE));
    if (!state) return NULL;

    RtlZeroMemory(state, sizeof(WKD_SEQ_MATCH_STATE));
    WkdCopyGuid(&state->SrcNodeId, &SrcNodeId);
    WkdCopyGuid(&state->TgtNodeId, &TgtNodeId);
    state->RuleIndex       = RuleIndex;
    state->CurrentStep     = 0;
    state->MatchedEvents   = 0;
    state->IsComplete      = FALSE;
    state->IsStale         = FALSE;
    state->IsRemoved       = FALSE;
    state->AlertSent       = FALSE;
    state->ConfidenceScore = 0;
    state->FirstEventTime  = Event->Timestamp;
    state->LastEventTime   = Event->Timestamp;
    state->NextMatchOrder  = 0;
    state->RefCount        = 1;    /* 引擎持有引用 */

    InitializeListHead(&state->HashLink);
    InitializeListHead(&state->PairLink);
    return state;
}

/* 释放匹配状态: 从哈希桶 + 进程对链表移除并释放 (防 double-remove) */
static VOID
SeqFreeState(
    _In_ PWKD_SEQ_MATCH_STATE State
    )
{
    if (!IsListEmpty(&State->HashLink)) RemoveEntryList(&State->HashLink);
    if (!IsListEmpty(&State->PairLink)) RemoveEntryList(&State->PairLink);
    InterlockedDecrement(&g_SeqEngine.StateCount);
    InterlockedIncrement64(&g_SeqEngine.TotalStatesFreed);
    UtHeapFree(State);
}

/**************************************************/
/*               事件值提取 (步骤 ValuePattern)      */
/**************************************************/

/* 从事件载荷提取值串 (供步骤 ValuePattern 匹配)。
 * ※死代码数据源: 多数事件载荷无统一字符串, 返回 NULL;
 *   pattern 指定但数据缺失 → 步骤匹配放行 (对齐 PM
 *   PmpCheckEventConstraint 的 Path==NULL 分支 L1869)。
 *   文件/注册表/网络载荷补齐后此函数自然激活。 */
static PCWSTR
SeqExtractEventValue(
    _In_ PWKD_EVENT_HEADER Event
    )
{
    if (!Event) return NULL;

    switch (Event->Type) {
    case WkdEvent_ProcessCreate: {
        PEVENT_PAYLOAD_PROCESS_CREATE payload =
            (PEVENT_PAYLOAD_PROCESS_CREATE)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));
        if (payload->CommandLine.Length && payload->CommandLine.Buffer)
            return payload->CommandLine.Buffer;
        return NULL;
    }
    default:
        return NULL;
    }
}

/**************************************************/
/*               命中告警构造 + 入队               */
/*  (对齐 RaAllocStatAlert 单块堆分配语义)          */
/**************************************************/

static VOID
SeqAllocAndEnqueueAlert(
    _In_ PWKD_SEQ_MATCH_STATE  State,
    _In_ PWKD_SEQUENCE_RULE    Rule,
    _In_ PWKD_EVENT_HEADER     Event
    )
{
    WCHAR descBuf[512];
    size_t ruleLen, mitreLen, descLen, total;
    PIOA_ALERT alert;
    PWCHAR buf;
    PCWSTR mitreId;
    DEF_CONFIDENCE_LEVEL confLevel;

    mitreId = Rule->MitreId[0] != L'\0' ? Rule->MitreId : NULL;

    swprintf_s(descBuf, 512,
               L"Sequence rule matched: %ls (%lu/%lu steps, conf=%lu)",
               Rule->Name, State->MatchedEvents, Rule->StepCount,
               State->ConfidenceScore);

    ruleLen  = wcslen(Rule->Name);
    mitreLen = mitreId ? wcslen(mitreId) : 0;
    descLen  = wcslen(descBuf);

    total = sizeof(IOA_ALERT) +
            (ruleLen + 1 + mitreLen + 1 + descLen + 1) * sizeof(WCHAR);

    alert = (PIOA_ALERT)UtHeapAlloc(total);
    if (!alert) return;
    RtlZeroMemory(alert, total);

    CoCreateGuid(&alert->AlertId);
    alert->Timestamp       = Event->Timestamp;
    alert->SuspectNodeId   = State->SrcNodeId;   /* 源=执行者 */
    alert->VictimNodeId    = State->TgtNodeId;   /* 目标=受害实体 */
    alert->Severity        = Rule->Severity;
    alert->Score           = Rule->ScoreContribution;
    alert->Confidence      = State->ConfidenceScore;
    alert->Category        = Rule->Category;
    confLevel = State->ConfidenceScore >= 90 ? DefConfidence_Confirmed
              : State->ConfidenceScore >= 70 ? DefConfidence_High
              : State->ConfidenceScore >= 50 ? DefConfidence_Medium
              : DefConfidence_Low;
    alert->ConfidenceLevel    = confLevel;
    alert->RecommendedAction  = Rule->Severity >= DefThreatSeverity_Critical
                              ? DefRespAction_Block : DefRespAction_Alert;
    alert->DetectionSource    = DefDetSrc_Rule;

    buf = (PWCHAR)((PUCHAR)alert + sizeof(IOA_ALERT));
    alert->RuleName = buf;
    wcscpy_s(buf, ruleLen + 1, Rule->Name);
    buf += ruleLen + 1;

    if (mitreLen) {
        alert->MitreId = buf;
        wcscpy_s(buf, mitreLen + 1, mitreId);
        buf += mitreLen + 1;
    }
    if (descLen) {
        alert->Description = buf;
        wcscpy_s(buf, descLen + 1, descBuf);
    }

    if (WkdIoaEngine.PersistQueue) {
        IoaPersistQueueEnqueue(WkdIoaEngine.PersistQueue,
                               PersistType_Alert, alert,
                               (PERSIST_SERDE_WRITE_FN)StPersistAlert,
                               TRUE);
    } else {
        UtHeapFree(alert);   /* 无持久化队列时释放 (正常情况不触发) */
    }
}

/**************************************************/
/*               单步约束匹配                      */
/*  (对齐 PmpCheckEventConstraint L1828-1934)      */
/**************************************************/

static BOOLEAN
SeqCheckStepConstraint(
    _In_ PWKD_SEQUENCE_STEP    Step,
    _In_ IOA_GRAPH_EDGE_TYPE   EdgeType,
    _In_opt_ PWKD_PROCESS SrcNode,
    _In_opt_ PWKD_PROCESS TgtNode,
    _In_opt_ PCWSTR            Value,
    _In_opt_ PWKD_SEQ_MATCH_STATE State,
    _In_ PWKD_EVENT_HEADER     Event
    )
{
    LONGLONG timeDelta;
    PCWSTR procName = NULL;
    PCWSTR pathName = NULL;

    /* 边类型检查 (最廉, 对齐 PM L1862) */
    if (Step->EdgeType != 0 && Step->EdgeType != EdgeType) return FALSE;

    /* 源进程名通配 (数据缺失放行, 对齐 PM Path==NULL 分支) */
    if (Step->ProcessPattern[0] != L'\0') {
        if (SrcNode && SrcNode->ImageFileName && SrcNode->ImageFileName->Buffer)
            procName = SrcNode->ImageFileName->Buffer;
        if (procName) {
            if (!Policy_WildcardMatch(Step->ProcessPattern, procName)) return FALSE;
        }
    }

    /* 目标路径通配 */
    if (Step->PathPattern[0] != L'\0') {
        if (TgtNode && TgtNode->ImagePath && TgtNode->ImagePath->Buffer)
            pathName = TgtNode->ImagePath->Buffer;
        else if (TgtNode && TgtNode->ImageFileName && TgtNode->ImageFileName->Buffer)
            pathName = TgtNode->ImageFileName->Buffer;
        if (pathName) {
            if (!Policy_WildcardMatch(Step->PathPattern, pathName)) return FALSE;
        }
    }

    /* 值通配 (数据缺失放行) */
    if (Step->ValuePattern[0] != L'\0' && Value != NULL) {
        if (!Policy_WildcardMatch(Step->ValuePattern, Value)) return FALSE;
    }

    /* 步间时序窗口 (对齐 PM L1914-1931; 首步 State==NULL 不检时序) */
    if (State != NULL &&
        (Step->MaxTimeFromPrevious > 0 || Step->MinTimeFromPrevious > 0)) {
        timeDelta = (Event->Timestamp.QuadPart - State->LastEventTime.QuadPart) / 10000LL;
        if (Step->MaxTimeFromPrevious > 0 &&
            timeDelta > (LONGLONG)Step->MaxTimeFromPrevious) return FALSE;
        if (Step->MinTimeFromPrevious > 0 &&
            timeDelta < (LONGLONG)Step->MinTimeFromPrevious) return FALSE;
    }

    return TRUE;
}

/**************************************************/
/*               状态推进                          */
/*  (对齐 PmpAdvanceMatchState L1936-1997)         */
/**************************************************/

static VOID
SeqAdvanceMatchState(
    _Inout_ PWKD_SEQ_MATCH_STATE State,
    _In_ ULONG                   StepIndex,
    _In_ PWKD_EVENT_HEADER       Event
    )
{
    PWKD_SEQUENCE_RULE rule;

    if (StepIndex >= WKD_SEQ_MAX_STEPS) return;
    if (State->NextMatchOrder >= WKD_SEQ_MAX_STEPS) return;

    State->EventMatched[StepIndex] = TRUE;
    State->EventTimes[StepIndex]   = Event->Timestamp;
    State->EventMatchOrder[State->NextMatchOrder] = StepIndex;
    State->NextMatchOrder++;
    State->MatchedEvents++;
    State->LastEventTime = Event->Timestamp;

    /* 若按序推进: 步索引前进并跳过后续未匹配的 Optional 步 (对齐 PM L1980-1996) */
    if (StepIndex == State->CurrentStep) {
        State->CurrentStep++;
        rule = &g_SeqEngine.Rules[State->RuleIndex];
        while (State->CurrentStep < rule->StepCount &&
               State->CurrentStep < WKD_SEQ_MAX_STEPS) {
            if (!State->EventMatched[State->CurrentStep] &&
                rule->Steps[State->CurrentStep].Optional) {
                State->CurrentStep++;
            } else {
                break;
            }
        }
    }
}

/**************************************************/
/*               完成判定                          */
/*  (对齐 PmpCheckPatternComplete L1999-2130)      */
/**************************************************/

static VOID
SeqCheckPatternComplete(
    _Inout_ PWKD_SEQ_MATCH_STATE State,
    _In_ PWKD_EVENT_HEADER       Event,
    _Inout_opt_ PULONG           ScoreOut
    )
{
    PWKD_SEQUENCE_RULE rule;
    ULONG requiredEvents = 0, matchedRequired = 0, i;
    LONGLONG totalTime;
    BOOLEAN hasTerminal = FALSE, terminalMatched = FALSE;

    if (State->IsComplete) return;

    rule = &g_SeqEngine.Rules[State->RuleIndex];

    /* 硬超时: 整链超时杀状态 (对齐 PM MaxTotalTimeMs L2052-2059;
     * 补 wkd FSM 缺陷 — FSM TotalTimeoutMs 只用于衰减不杀状态) */
    if (rule->SequenceTimeoutMs > 0) {
        totalTime = (Event->Timestamp.QuadPart - State->FirstEventTime.QuadPart) / 10000LL;
        if (totalTime > (LONGLONG)rule->SequenceTimeoutMs) {
            State->IsStale = TRUE;
            InterlockedIncrement64(&g_SeqEngine.TotalTimeouts);
            return;
        }
    }

    /* 必需步 + Terminal 计数 (对齐 PM L2033-2047) */
    for (i = 0; i < rule->StepCount && i < WKD_SEQ_MAX_STEPS; i++) {
        if (!rule->Steps[i].Optional) {
            requiredEvents++;
            if (State->EventMatched[i]) matchedRequired++;
        }
        if (rule->Steps[i].Terminal) {
            hasTerminal = TRUE;
            if (State->EventMatched[i]) terminalMatched = TRUE;
        }
    }

    /* 完成判定 (对齐 PM L2064-2085) */
    if (rule->MinMatchedEvents > 0) {
        if (State->MatchedEvents < rule->MinMatchedEvents) return;
    } else {
        if (matchedRequired < requiredEvents) return;
    }
    if (hasTerminal && !terminalMatched) return;

    /* 完成: 标记 + 置信度 + 统计 (对齐 PM L2087-2105) */
    State->IsComplete = TRUE;
    State->ConfidenceScore =
        rule->StepCount > 0 ? (State->MatchedEvents * 100) / rule->StepCount : 100;

    InterlockedIncrement64(&rule->MatchCount);
    InterlockedIncrement64(&g_SeqEngine.TotalMatches);
    GetSystemTimeAsFileTime((PFILETIME)&rule->LastMatchTime);

    if (ScoreOut && rule->ScoreContribution > *ScoreOut)
        *ScoreOut = rule->ScoreContribution;

    /* 命中动作: 告警 (对齐 PmpNotifyCallback; 一状态只告警一次) */
    if (!State->AlertSent) {
        SeqAllocAndEnqueueAlert(State, rule, Event);
        State->AlertSent = TRUE;
    }
}

/**************************************************/
/*               序列规则注册表                     */
/*  (对齐 PolicyEngine_AddRule/RemoveRule 风格 +    */
/*   PmUnloadPattern states sweep)                */
/**************************************************/

NTSTATUS
PolicyEngine_AddSequenceRule(
    _In_ const WKD_SEQUENCE_RULE* Rule
    )
{
    if (!Rule || Rule->RuleId[0] == 0) return STATUS_INVALID_PARAMETER;
    if (Rule->StepCount == 0 || Rule->StepCount > WKD_SEQ_MAX_STEPS)
        return STATUS_INVALID_PARAMETER;
    if (!g_SeqEngine.Initialized) return STATUS_NOT_IMPLEMENTED;

    EnterCriticalSection(&g_SeqEngine.Lock);

    if (g_SeqEngine.RuleCount >= WKD_SEQ_MAX_RULES) {
        LeaveCriticalSection(&g_SeqEngine.Lock);
        return STATUS_TOO_MANY_COMMANDS;
    }
    /* 去重: 同 RuleId 拒绝 */
    for (ULONG i = 0; i < g_SeqEngine.RuleCount; i++) {
        if (wcscmp(g_SeqEngine.Rules[i].RuleId, Rule->RuleId) == 0) {
            LeaveCriticalSection(&g_SeqEngine.Lock);
            return STATUS_DUPLICATE_OBJECTID;
        }
    }

    g_SeqEngine.Rules[g_SeqEngine.RuleCount] = *Rule;

    /* 注册即计算首步边类型位图 (严格序规则的启动预过滤;
     * 等价 PatternMatcher 的 PatternIndex[事件类型] 索引) */
    {
        PWKD_SEQUENCE_RULE r = &g_SeqEngine.Rules[g_SeqEngine.RuleCount];
        r->FirstStepEdgeMask = 0;
        if (r->Steps[0].EdgeType > 0 && (ULONG)r->Steps[0].EdgeType < 64) {
            r->FirstStepEdgeMask = (ULONG64)1 << (ULONG)r->Steps[0].EdgeType;
        }
        r->MatchCount = 0;
        g_SeqEngine.RuleCount++;
    }

    printf("[PolicyEngine] Sequence rule added: %ls (id=%ls, steps=%lu, score=%lu)\n",
           Rule->Name, Rule->RuleId, Rule->StepCount, Rule->ScoreContribution);

    LeaveCriticalSection(&g_SeqEngine.Lock);
    return STATUS_SUCCESS;
}

NTSTATUS
PolicyEngine_RemoveSequenceRule(
    _In_ PCWSTR RuleId
    )
{
    ULONG idx = ULONG_MAX;

    if (!RuleId || RuleId[0] == 0) return STATUS_INVALID_PARAMETER;
    if (!g_SeqEngine.Initialized) return STATUS_NOT_IMPLEMENTED;

    EnterCriticalSection(&g_SeqEngine.Lock);

    for (ULONG i = 0; i < g_SeqEngine.RuleCount; i++) {
        if (wcscmp(g_SeqEngine.Rules[i].RuleId, RuleId) == 0) { idx = i; break; }
    }
    if (idx == ULONG_MAX) {
        LeaveCriticalSection(&g_SeqEngine.Lock);
        return STATUS_NOT_FOUND;
    }

    /* 杀该规则的全部状态 (对齐 PmUnloadPattern states sweep L1031-1049) */
    for (ULONG b = 0; b < WKD_SEQ_STATE_HASH_BUCKETS; b++) {
        PLIST_ENTRY head = &g_SeqEngine.StateHashBuckets[b];
        PLIST_ENTRY entry = head->Flink;
        while (entry != head) {
            PLIST_ENTRY next = entry->Flink;
            PWKD_SEQ_MATCH_STATE st =
                CONTAINING_RECORD(entry, WKD_SEQ_MATCH_STATE, HashLink);
            if (st->RuleIndex == idx) SeqFreeState(st);
            entry = next;
        }
    }

    /* 尾元素覆盖移除 + 迁移原尾部规则状态索引 (对齐 PolicyEngine_RemoveRule) */
    {
        ULONG lastIdx = g_SeqEngine.RuleCount - 1;
        if (idx != lastIdx) {
            g_SeqEngine.Rules[idx] = g_SeqEngine.Rules[lastIdx];
            for (ULONG b = 0; b < WKD_SEQ_STATE_HASH_BUCKETS; b++) {
                PLIST_ENTRY head = &g_SeqEngine.StateHashBuckets[b];
                for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
                    PWKD_SEQ_MATCH_STATE st =
                        CONTAINING_RECORD(e, WKD_SEQ_MATCH_STATE, HashLink);
                    if (st->RuleIndex == lastIdx) st->RuleIndex = idx;
                }
            }
        }
        g_SeqEngine.RuleCount--;
    }

    printf("[PolicyEngine] Sequence rule removed: %ls\n", RuleId);
    LeaveCriticalSection(&g_SeqEngine.Lock);
    return STATUS_SUCCESS;
}

VOID
PolicyEngine_SetSequenceRuleEnabled(
    _In_ PCWSTR  RuleId,
    _In_ BOOLEAN Enabled
    )
{
    EnterCriticalSection(&g_SeqEngine.Lock);
    for (ULONG i = 0; i < g_SeqEngine.RuleCount; i++) {
        if (wcscmp(g_SeqEngine.Rules[i].RuleId, RuleId) == 0) {
            g_SeqEngine.Rules[i].Enabled = Enabled;
            break;
        }
    }
    LeaveCriticalSection(&g_SeqEngine.Lock);
}

ULONG
PolicyEngine_GetSequenceRuleCount(
    VOID
    )
{
    ULONG n;
    EnterCriticalSection(&g_SeqEngine.Lock);
    n = g_SeqEngine.RuleCount;
    LeaveCriticalSection(&g_SeqEngine.Lock);
    return n;
}

ULONG
PolicyEngine_GetSequenceRules(
    _Out_ PWKD_SEQUENCE_RULE Out,
    _In_  ULONG              MaxCount
    )
{
    ULONG n = 0;

    if (!Out || MaxCount == 0) return 0;

    EnterCriticalSection(&g_SeqEngine.Lock);
    for (ULONG i = 0; i < g_SeqEngine.RuleCount && n < MaxCount; i++) {
        Out[n++] = g_SeqEngine.Rules[i];
    }
    LeaveCriticalSection(&g_SeqEngine.Lock);
    return n;
}

VOID
PolicyEngine_SetSequenceRulesEnabled(_In_ BOOLEAN Enabled)
{
    EnterCriticalSection(&g_SeqEngine.Lock);
    g_SeqEngine.EnableSequenceRules = Enabled;
    LeaveCriticalSection(&g_SeqEngine.Lock);
    printf("[PolicyEngine] Sequence rules %s\n", Enabled ? "enabled" : "disabled");
}

/**************************************************/
/*               序列规则评估 (双阶段)              */
/*  (对齐 PmSubmitEvent L1114-1395)               */
/**************************************************/

NTSTATUS
PolicyEngine_EvaluateSequenceRules(
    _In_  PAE_PROCESS_PAIR PairCtx,
    _In_  PWKD_EVENT_HEADER         Event,
    _In_opt_ PWKD_PROCESS      SrcNode,
    _In_opt_ PWKD_PROCESS      TgtNode,
    _In_  IOA_GRAPH_EDGE_TYPE       EdgeType,
    _Out_opt_ PULONG                MaxScoreOut
    )
/*++
Routine Description:
    序列规则双阶段评估 (IoaObserve 阶段4.6 调用):
      阶段1 — 推进该进程对已有活跃状态 (对齐 PM Phase 1)
      阶段2 — 检查事件是否启动新规则状态 (对齐 PM Phase 2)
    命中规则产分写入 MaxScoreOut (供阶段6c2 合并进 finalScore),
    告警由 SeqCheckPatternComplete 内部构造入队。

    ※默认 EnableSequenceRules=FALSE 直接短路 (死代码开关)。
--*/
{
    ULONG bestScore = 0;

    if (!g_SeqEngine.Initialized || !g_SeqEngine.EnableSequenceRules)
        return STATUS_SUCCESS;
    if (!PairCtx || !Event) return STATUS_INVALID_PARAMETER;

    EnterCriticalSection(&g_SeqEngine.Lock);
    g_SeqEngine.TotalEventsProcessed++;

    /* ── 阶段1: 推进已有活跃状态 ── */
    {
        PLIST_ENTRY se = PairCtx->SeqMatchHead.Flink;
        while (se != &PairCtx->SeqMatchHead) {
            PLIST_ENTRY next = se->Flink;
            PWKD_SEQ_MATCH_STATE state =
                CONTAINING_RECORD(se, WKD_SEQ_MATCH_STATE, PairLink);
            PWKD_SEQUENCE_RULE rule;

            if (state->IsComplete || state->IsStale) { se = next; continue; }

            rule = &g_SeqEngine.Rules[state->RuleIndex];
            if (rule->Enabled) {
                for (ULONG i = state->CurrentStep;
                     i < rule->StepCount && i < WKD_SEQ_MAX_STEPS; i++) {
                    PCWSTR value;

                    if (state->EventMatched[i]) continue;

                    value = (rule->Steps[i].ValuePattern[0] != L'\0')
                          ? SeqExtractEventValue(Event) : NULL;

                    if (SeqCheckStepConstraint(&rule->Steps[i], EdgeType,
                                               SrcNode, TgtNode, value,
                                               state, Event)) {
                        SeqAdvanceMatchState(state, i, Event);
                        SeqCheckPatternComplete(state, Event, &bestScore);
                        break;                       /* 一事件一步, 对齐 PM L1258 */
                    }

                    if (rule->RequireExactOrder && !rule->Steps[i].Optional) {
                        break;                       /* 对齐 PM L1261 */
                    }
                }
            }
            se = next;
        }
    }

    /* ── 阶段2: 启动新状态 ── */
    for (ULONG r = 0; r < g_SeqEngine.RuleCount; r++) {
        PWKD_SEQUENCE_RULE rule = &g_SeqEngine.Rules[r];

        if (!rule->Enabled) continue;

        /* 首步位图预过滤 (严格序规则只从首步启动; 对齐 PatternIndex) */
        if (rule->RequireExactOrder &&
            rule->Steps[0].EdgeType > 0 &&
            (ULONG)rule->Steps[0].EdgeType < 64 &&
            !(rule->FirstStepEdgeMask & ((ULONG64)1 << (ULONG)EdgeType))) {
            continue;
        }

        /* 每进程对状态数限制 (对齐 PM L1293) */
        if (PairCtx->SeqMatchCount >= WKD_SEQ_MAX_STATES_PER_PAIR) break;

        /* 同规则同进程对已有活跃状态 → 不重复启动 (对齐 stateExists)
         * 2026-08-23 pair 键 PID 化: NodeId 经谱系树反查 */
        {
            GUID pairSrcId, pairTgtId;
            IoaPairResolveNodeIds(PairCtx, &pairSrcId, &pairTgtId);
            if (SeqLookupState(pairSrcId, pairTgtId, r) != NULL) {
                continue;
            }
        }

        for (ULONG i = 0; i < rule->StepCount && i < WKD_SEQ_MAX_STEPS; i++) {
            PCWSTR value;

            if (rule->RequireExactOrder && i != 0) continue;

            if (rule->Steps[i].EdgeType != 0 && rule->Steps[i].EdgeType != EdgeType)
                continue;

            value = (rule->Steps[i].ValuePattern[0] != L'\0')
                  ? SeqExtractEventValue(Event) : NULL;

            if (SeqCheckStepConstraint(&rule->Steps[i], EdgeType,
                                       SrcNode, TgtNode, value,
                                       NULL, Event)) {
                PWKD_SEQ_MATCH_STATE state;
                GUID pairSrcId, pairTgtId;
                IoaPairResolveNodeIds(PairCtx, &pairSrcId, &pairTgtId);

                state = SeqCreateState(pairSrcId, pairTgtId, r, Event);
                if (!state) break;

                /* 插入状态哈希 (对齐 PmpInsertStateIntoProcessHash) */
                {
                    ULONG bucket = SeqHashState(state->SrcNodeId, state->TgtNodeId, r);
                    InsertTailList(&g_SeqEngine.StateHashBuckets[bucket], &state->HashLink);
                    InterlockedIncrement(&g_SeqEngine.StateCount);
                    InterlockedIncrement64(&g_SeqEngine.TotalStatesCreated);
                }

                /* 链入进程对列表 + 标记首步匹配 (对齐 PM L1365-1385) */
                InsertTailList(&PairCtx->SeqMatchHead, &state->PairLink);
                PairCtx->SeqMatchCount++;
                SeqAdvanceMatchState(state, i, Event);
                SeqCheckPatternComplete(state, Event, &bestScore);

                break;   /* 一规则一状态, 对齐 PM goto NextPattern */
            }
        }
    }

    LeaveCriticalSection(&g_SeqEngine.Lock);

    if (MaxScoreOut) *MaxScoreOut = bestScore;
    return STATUS_SUCCESS;
}

/**************************************************/
/*               状态查询 (死代码)                 */
/*  (对齐 PmGetActiveStates / PmReleaseState)      */
/**************************************************/

NTSTATUS
PolicyEngine_GetSequenceStates(
    _In_  GUID SrcNodeId,
    _In_  GUID TgtNodeId,
    _Out_ PWKD_SEQ_MATCH_STATE* States,
    _In_  ULONG                  MaxStates,
    _Out_ PULONG                 StateCount
    )
/*++
Routine Description:
    查询进程对活跃序列状态 (※死代码: 无调用者, 对齐 SS
    PmGetActiveStates)。返回状态指针并递增引用计数,
    调用方须用 PolicyEngine_ReleaseSequenceState 释放。
--*/
{
    ULONG count = 0;

    if (!States || !StateCount) return STATUS_INVALID_PARAMETER;
    *StateCount = 0;
    if (MaxStates == 0) return STATUS_SUCCESS;
    if (!g_SeqEngine.Initialized) return STATUS_NOT_IMPLEMENTED;

    EnterCriticalSection(&g_SeqEngine.Lock);
    for (ULONG r = 0; r < g_SeqEngine.RuleCount; r++) {
        PWKD_SEQ_MATCH_STATE st = SeqLookupState(SrcNodeId, TgtNodeId, r);
        if (st && count < MaxStates) {
            InterlockedIncrement(&st->RefCount);
            States[count++] = st;
        }
    }
    LeaveCriticalSection(&g_SeqEngine.Lock);

    *StateCount = count;
    return STATUS_SUCCESS;
}

VOID
PolicyEngine_ReleaseSequenceState(
    _In_ PWKD_SEQ_MATCH_STATE State
    )
/* 释放查询引用 (※死代码: 无调用者, 对齐 SS PmReleaseState) */
{
    if (!State) return;
    InterlockedDecrement(&State->RefCount);
}

/**************************************************/
/*               状态清理                          */
/*  (对齐 PmpCleanupStaleStates)                  */
/**************************************************/

VOID
PolicyEngine_RemovePairSequenceStates(
    _In_ PAE_PROCESS_PAIR PairCtx
    )
/*++
Routine Description:
    进程对淘汰 (LRU / TTL) 时回收其全部序列状态。
    遍历 PairCtx->SeqMatchHead, 从哈希桶 + 本链表移除并释放。
--*/
{
    if (!PairCtx) return;
    if (!g_SeqEngine.Initialized) return;

    EnterCriticalSection(&g_SeqEngine.Lock);
    while (!IsListEmpty(&PairCtx->SeqMatchHead)) {
        PLIST_ENTRY e = RemoveHeadList(&PairCtx->SeqMatchHead);
        PWKD_SEQ_MATCH_STATE st =
            CONTAINING_RECORD(e, WKD_SEQ_MATCH_STATE, PairLink);
        PairCtx->SeqMatchCount--;
        SeqFreeState(st);   /* 从哈希桶移除 + 释放 */
    }
    LeaveCriticalSection(&g_SeqEngine.Lock);
}

VOID
PolicyEngine_CleanupSequenceStates(VOID)
/*++
Routine Description:
    超时/完成状态周期清理 (CgFsmCleanupThread 30s 调用)。
    对齐 PmpCleanupStaleStates: 硬超时杀状态 + 回收
    IsStale/IsComplete/IsRemoved 状态。
    补 wkd FSM 缺陷: FSM 只按单步 TimeoutMs 清理 (IoaFsmEngine.c
    L780), 整链 TotalTimeoutMs 不杀状态; 此处按 SequenceTimeoutMs
    从 FirstEventTime 主动杀状态。
--*/
{
    LARGE_INTEGER now;

    if (!g_SeqEngine.Initialized) return;

    GetSystemTimeAsFileTime((PFILETIME)&now);
    EnterCriticalSection(&g_SeqEngine.Lock);

    for (ULONG b = 0; b < WKD_SEQ_STATE_HASH_BUCKETS; b++) {
        PLIST_ENTRY head = &g_SeqEngine.StateHashBuckets[b];
        PLIST_ENTRY entry = head->Flink;
        while (entry != head) {
            PLIST_ENTRY next = entry->Flink;
            PWKD_SEQ_MATCH_STATE st =
                CONTAINING_RECORD(entry, WKD_SEQ_MATCH_STATE, HashLink);

            if (st->IsStale || st->IsComplete || st->IsRemoved) {
                /* 已过期/完成: 无外部引用则回收, 否则延迟 (对齐 PM RefCount<=1) */
                if (st->RefCount <= 1) {
                    SeqFreeState(st);
                }
            } else {
                /* 硬超时主动杀状态 (对齐 PM L2440-2446) */
                PWKD_SEQUENCE_RULE rule = &g_SeqEngine.Rules[st->RuleIndex];
                if (rule->SequenceTimeoutMs > 0) {
                    LONGLONG ageMs =
                        (now.QuadPart - st->FirstEventTime.QuadPart) / 10000LL;
                    if (ageMs > (LONGLONG)rule->SequenceTimeoutMs) {
                        st->IsStale = TRUE;
                        InterlockedIncrement64(&g_SeqEngine.TotalTimeouts);
                        if (st->RefCount <= 1) {
                            SeqFreeState(st);
                        } else {
                            st->IsRemoved = TRUE;
                        }
                    }
                }
            }
            entry = next;
        }
    }

    LeaveCriticalSection(&g_SeqEngine.Lock);
}

/**************************************************/
/*               序列规则持久化 (死代码)            */
/*  (对齐 PolicyEngine_LoadRulesFromFile stub)     */
/**************************************************/

NTSTATUS
PolicyEngine_LoadSequenceRulesFromFile(
    _In_ PCWSTR FilePath
    )
/*++
Routine Description:
    从 JSON/YAML 规则文件加载序列规则 (※死代码: 序列化未实现,
    对齐 SS stub; 注册表 AddSequenceRule 为活代码)。
--*/
{
    UNREFERENCED_PARAMETER(FilePath);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
PolicyEngine_SaveSequenceRulesToFile(
    _In_ PCWSTR FilePath
    )
/*++
Routine Description:
    保存序列规则到文件 (※死代码: 序列化未实现, 对齐 SS stub)。
--*/
{
    UNREFERENCED_PARAMETER(FilePath);
    return STATUS_NOT_IMPLEMENTED;
}
