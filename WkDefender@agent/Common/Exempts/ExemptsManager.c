/**************************************************/
/*  WkDefender — 排除规则存储仓库（纯存储）          */
/*                                                   */
/*  职责：统一规则数组（Type 区分 Hash/Path/Cert/    */
/*  Publisher 四维）的存储、维护（Add/Remove/Clear/  */
/*  快照/过期清理）与查询原语。不再持有状态机/线程    */
/*  （这些归 EXEMPT_ENGINE，由门面 Exempts.c 持有）。 */
/*                                                   */
/*  量级小（几十条），统一数组 + 线性扫描 + 按类型    */
/*  过滤足够；SS 的 B+Tree/Bloom/StringPool 大库      */
/*  索引明确不迁移（SQLite 持久化 + 内存线性覆盖）。  */
/*  全部操作 CRITICAL_SECTION 保护。                  */
/**************************************************/

#include "ExemptsInternal.h"
#include <string.h>
#include <wchar.h>   /* _wcsicmp */

/**************************************************/
/*                  内部辅助                        */
/**************************************************/

/*
 * 规则是否活跃（enabled + 未过期）。SYSTEM 规则永活。
 */
static BOOLEAN
ExemptsMgrp_IsActive(
    _In_ PEXEMPT_RULE Rule
    )
{
    FILETIME ft;
    UINT64 now;

    if (Rule->Flags & EXEMPT_FLAG_SYSTEM) {
        return TRUE;
    }
    if (Rule->ExpirationTime == 0) {
        return TRUE;
    }

    GetSystemTimeAsFileTime(&ft);
    now = (((UINT64)ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    return (now < Rule->ExpirationTime);
}

/*
 * 哈希规则去重判定（algorithm/length/data 全等）。
 */
static BOOLEAN
ExemptsMgrp_SameHash(
    _In_ PEXEMPT_RULE Rule,
    _In_ PDEF_SHA256_HASH Hash
    )
{
    if (Rule->HashAlgorithm != 1 /* SHA256 */) {
        return FALSE;
    }
    if (Rule->HashLength != EXEMPT_HASH_SIZE) {
        return FALSE;
    }
    return (memcmp(Rule->HashData, Hash->Data, EXEMPT_HASH_SIZE) == 0);
}

/*
 * 模式规则去重判定（type + matchMode + pattern 全等，大小写不敏感）。
 */
static BOOLEAN
ExemptsMgrp_SamePattern(
    _In_ PEXEMPT_RULE Rule,
    _In_ UINT8 Type,
    _In_ PCWSTR Pattern,
    _In_ UINT8 MatchMode
    )
{
    return (Rule->Type == Type &&
            Rule->MatchMode == MatchMode &&
            _wcsicmp(Rule->Pattern, Pattern) == 0);
}

/*
 * 数组扩容（倍增，上限 EXEMPT_MAX_RULES）。
 */
static BOOLEAN
ExemptsMgrp_EnsureCapacity(
    _Inout_ PEXEMPT_ENGINE Engine,
    _In_ UINT64 Need
    )
{
    EXEMPT_MANAGER* mgr = &Engine->Manager;
    UINT64 newCap;
    PEXEMPT_RULE newArr;

    if (Need <= mgr->RuleCapacity) {
        return TRUE;
    }

    newCap = (mgr->RuleCapacity == 0) ? 64 : mgr->RuleCapacity * 2;
    if (newCap > EXEMPT_MAX_RULES) {
        newCap = EXEMPT_MAX_RULES;
    }
    if (Need > newCap) {
        return FALSE;
    }

    newArr = (PEXEMPT_RULE)UtHeapAlloc((SIZE_T)newCap * sizeof(EXEMPT_RULE));
    if (newArr == NULL) {
        return FALSE;
    }
    if (mgr->RuleCount > 0) {
        memcpy(newArr, mgr->Rules, (SIZE_T)mgr->RuleCount * sizeof(EXEMPT_RULE));
    }
    if (mgr->Rules != NULL) {
        UtHeapFree(mgr->Rules);
    }
    mgr->Rules = newArr;
    mgr->RuleCapacity = newCap;
    return TRUE;
}

/*
 * 按数组下标移除（尾移压缩，维护数组紧凑）。
 */
static VOID
ExemptsMgrp_RemoveAt(
    _Inout_ PEXEMPT_ENGINE Engine,
    _In_ UINT64 Index
    )
{
    EXEMPT_MANAGER* mgr = &Engine->Manager;

    if (Index + 1 < mgr->RuleCount) {
        memmove(&mgr->Rules[Index], &mgr->Rules[Index + 1],
                (SIZE_T)(mgr->RuleCount - Index - 1) * sizeof(EXEMPT_RULE));
    }
    mgr->RuleCount--;
}

/**************************************************/
/*                  生命周期                        */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
ExemptsMgr_Initialize(
    _Inout_ PEXEMPT_ENGINE Engine
    )
/*++
Routine Description:
    初始化存储仓库：零初始化 + CRITICAL_SECTION。

Arguments:
    Engine - 子系统全局。

Return Value:
    STATUS_SUCCESS。
--*/
{
    if (Engine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ZeroMemory(&Engine->Manager, sizeof(EXEMPT_MANAGER));
    InitializeCriticalSection(&Engine->Manager.Lock);
    Engine->Manager.NextRuleId = 1;
    Engine->Manager.Initialized = TRUE;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ExemptsMgr_Shutdown(
    _Inout_ PEXEMPT_ENGINE Engine
    )
/*++
Routine Description:
    清理存储仓库：释放规则数组 + 锁。

Arguments:
    Engine - 子系统全局。

Return Value:
    无。
--*/
{
    if (Engine == NULL || !Engine->Manager.Initialized) {
        return;
    }

    if (Engine->Manager.Rules != NULL) {
        UtHeapFree(Engine->Manager.Rules);
        Engine->Manager.Rules = NULL;
    }
    Engine->Manager.RuleCount = 0;
    Engine->Manager.RuleCapacity = 0;
    DeleteCriticalSection(&Engine->Manager.Lock);
    Engine->Manager.Initialized = FALSE;
}

/**************************************************/
/*                  规则维护                        */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
ExemptsMgr_AddRule(
    _Inout_ PEXEMPT_ENGINE Engine,
    _In_    PEXEMPT_RULE    Rule,
    _Out_opt_ PBOOLEAN      IsNew
    )
/*++
Routine Description:
    添加规则（四维通用）。去重幂等：同键规则已存在则不重复插入。

Arguments:
    Engine - 子系统全局。
    Rule   - 待添加规则（RuleId 由仓库分配，忽略输入值）。
    IsNew  - 可选输出是否新插入。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER / STATUS_INSUFFICIENT_RESOURCES。
--*/
{
    FILETIME ft;
    UINT64 i;
    PEXEMPT_RULE existing = NULL;

    if (Engine == NULL || Rule == NULL || !Engine->Manager.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    GetSystemTimeAsFileTime(&ft);
    {
        UINT64 now = (((UINT64)ft.dwHighDateTime) << 32) | ft.dwLowDateTime;

        EnterCriticalSection(&Engine->Manager.Lock);

        /* 去重查找（哈希键 / 模式键） */
        for (i = 0; i < Engine->Manager.RuleCount; i++) {
            PEXEMPT_RULE r = &Engine->Manager.Rules[i];

            if (Rule->Type == ExemptRule_Hash) {
                if (ExemptsMgrp_SameHash(r, (PDEF_SHA256_HASH)Rule->HashData)) {
                    existing = r;
                    break;
                }
            } else if (Rule->Type == ExemptRule_Path ||
                       Rule->Type == ExemptRule_Certificate ||
                       Rule->Type == ExemptRule_Publisher) {
                if (ExemptsMgrp_SamePattern(r, Rule->Type, Rule->Pattern, Rule->MatchMode)) {
                    existing = r;
                    break;
                }
            } else {
                break;
            }
        }

        if (existing != NULL) {
            /* 幂等：刷新修改时间 + 命中计数保留 */
            existing->ModifiedTime = now;
            if (Rule->ExpirationTime != 0) {
                existing->ExpirationTime = Rule->ExpirationTime;
            }
            if (Rule->Description[0] != L'\0') {
                wcsncpy_s(existing->Description, EXEMPT_MAX_DESCRIPTION,
                          Rule->Description, _TRUNCATE);
            }
            if (IsNew) {
                *IsNew = FALSE;
            }
            LeaveCriticalSection(&Engine->Manager.Lock);
            return STATUS_SUCCESS;
        }

        /* 新插入：容量检查 + 追加 */
        if (!ExemptsMgrp_EnsureCapacity(Engine, Engine->Manager.RuleCount + 1)) {
            LeaveCriticalSection(&Engine->Manager.Lock);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        {
            PEXEMPT_RULE dst = &Engine->Manager.Rules[Engine->Manager.RuleCount];
            *dst = *Rule;
            dst->RuleId = Engine->Manager.NextRuleId++;
            dst->CreatedTime = now;
            dst->ModifiedTime = now;
            if (dst->ExpirationTime == 0) {
                dst->Flags &= (UINT8)~EXEMPT_FLAG_TEMPORARY;
            }
            Engine->Manager.RuleCount++;
        }

        if (IsNew) {
            *IsNew = TRUE;
        }
        LeaveCriticalSection(&Engine->Manager.Lock);
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ExemptsMgr_RemoveRule(
    _Inout_ PEXEMPT_ENGINE Engine,
    _In_ UINT64 RuleId
    )
{
    UINT64 i;

    if (Engine == NULL || !Engine->Manager.Initialized) {
        return;
    }

    EnterCriticalSection(&Engine->Manager.Lock);
    for (i = 0; i < Engine->Manager.RuleCount; i++) {
        if (Engine->Manager.Rules[i].RuleId == RuleId) {
            ExemptsMgrp_RemoveAt(Engine, i);
            break;
        }
    }
    LeaveCriticalSection(&Engine->Manager.Lock);
}

_Use_decl_annotations_
VOID
ExemptsMgr_RemoveHashRule(
    _Inout_ PEXEMPT_ENGINE Engine,
    _In_ PDEF_SHA256_HASH   Hash
    )
{
    UINT64 i;

    if (Engine == NULL || Hash == NULL || !Engine->Manager.Initialized) {
        return;
    }

    EnterCriticalSection(&Engine->Manager.Lock);
    for (i = 0; i < Engine->Manager.RuleCount; i++) {
        if (Engine->Manager.Rules[i].Type == ExemptRule_Hash &&
            ExemptsMgrp_SameHash(&Engine->Manager.Rules[i], Hash)) {
            ExemptsMgrp_RemoveAt(Engine, i);
            break;
        }
    }
    LeaveCriticalSection(&Engine->Manager.Lock);
}

_Use_decl_annotations_
VOID
ExemptsMgr_RemovePatternRule(
    _Inout_ PEXEMPT_ENGINE Engine,
    _In_ UINT8 Type,
    _In_ PCWSTR Pattern,
    _In_ UINT8 MatchMode
    )
{
    UINT64 i;

    if (Engine == NULL || Pattern == NULL || !Engine->Manager.Initialized) {
        return;
    }

    EnterCriticalSection(&Engine->Manager.Lock);
    for (i = 0; i < Engine->Manager.RuleCount; i++) {
        if (ExemptsMgrp_SamePattern(&Engine->Manager.Rules[i], Type, Pattern, MatchMode)) {
            ExemptsMgrp_RemoveAt(Engine, i);
            break;
        }
    }
    LeaveCriticalSection(&Engine->Manager.Lock);
}

_Use_decl_annotations_
VOID
ExemptsMgr_ClearRules(
    _Inout_ PEXEMPT_ENGINE Engine,
    _In_ UINT8 Type
    )
{
    UINT64 i;

    if (Engine == NULL || !Engine->Manager.Initialized) {
        return;
    }

    EnterCriticalSection(&Engine->Manager.Lock);

    /* 反向遍历删除（System 规则保留，除非 Type==MaxValue 强制全清） */
    for (i = Engine->Manager.RuleCount; i > 0; i--) {
        PEXEMPT_RULE r = &Engine->Manager.Rules[i - 1];

        if (Type != ExemptRule_MaxValue && r->Type != Type) {
            continue;
        }
        if ((r->Flags & EXEMPT_FLAG_SYSTEM) && Type != ExemptRule_MaxValue) {
            continue;   /* 保留系统规则 */
        }
        ExemptsMgrp_RemoveAt(Engine, i - 1);
    }

    LeaveCriticalSection(&Engine->Manager.Lock);
}

/**************************************************/
/*                  查询原语                        */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
ExemptsMgr_FindHashRule(
    _In_  PEXEMPT_ENGINE Engine,
    _In_  PDEF_SHA256_HASH Hash,
    _Out_opt_ PEXEMPT_RULE Out
    )
{
    UINT64 i;
    BOOLEAN hit = FALSE;

    if (Engine == NULL || Hash == NULL || !Engine->Manager.Initialized) {
        return FALSE;
    }

    EnterCriticalSection(&Engine->Manager.Lock);
    for (i = 0; i < Engine->Manager.RuleCount; i++) {
        PEXEMPT_RULE r = &Engine->Manager.Rules[i];

        if (r->Type != ExemptRule_Hash || !ExemptsMgrp_SameHash(r, Hash)) {
            continue;
        }
        if (!ExemptsMgrp_IsActive(r)) {
            continue;
        }
        r->HitCount++;
        if (Out) {
            *Out = *r;
        }
        hit = TRUE;
        break;
    }
    LeaveCriticalSection(&Engine->Manager.Lock);

    return hit;
}

_Use_decl_annotations_
BOOLEAN
ExemptsMgr_FindPathRule(
    _In_  PEXEMPT_ENGINE Engine,
    _In_  PCWSTR Path,
    _In_  UINT8 Mode,
    _Out_opt_ PEXEMPT_RULE Out
    )
{
    UINT64 i;
    BOOLEAN hit = FALSE;

    if (Engine == NULL || Path == NULL || !Engine->Manager.Initialized) {
        return FALSE;
    }

    EnterCriticalSection(&Engine->Manager.Lock);
    for (i = 0; i < Engine->Manager.RuleCount; i++) {
        PEXEMPT_RULE r = &Engine->Manager.Rules[i];

        if (r->Type != ExemptRule_Path) {
            continue;
        }
        if (!ExemptsMgrp_IsActive(r)) {
            continue;
        }
        if (ExemptPath_Match(Path, r->Pattern, r->MatchMode)) {
            r->HitCount++;
            if (Out) {
                *Out = *r;
            }
            hit = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&Engine->Manager.Lock);

    return hit;
}

_Use_decl_annotations_
BOOLEAN
ExemptsMgr_FindPatternRule(
    _In_  PEXEMPT_ENGINE Engine,
    _In_  UINT8 Type,
    _In_  PCWSTR Pattern,
    _Out_opt_ PEXEMPT_RULE Out
    )
{
    UINT64 i;
    BOOLEAN hit = FALSE;

    if (Engine == NULL || Pattern == NULL || !Engine->Manager.Initialized) {
        return FALSE;
    }
    if (Type != ExemptRule_Certificate && Type != ExemptRule_Publisher) {
        return FALSE;
    }

    EnterCriticalSection(&Engine->Manager.Lock);
    for (i = 0; i < Engine->Manager.RuleCount; i++) {
        PEXEMPT_RULE r = &Engine->Manager.Rules[i];

        if (r->Type != Type) {
            continue;
        }
        if (!ExemptsMgrp_IsActive(r)) {
            continue;
        }
        if (_wcsicmp(r->Pattern, Pattern) == 0) {
            r->HitCount++;
            if (Out) {
                *Out = *r;
            }
            hit = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&Engine->Manager.Lock);

    return hit;
}

_Use_decl_annotations_
NTSTATUS
ExemptsMgr_GetRules(
    _In_  PEXEMPT_ENGINE Engine,
    _Out_ PEXEMPT_RULE*  OutRules,
    _Out_ PULONG         Count
    )
/*++
Routine Description:
    全量规则快照（堆分配数组，调用方 UtHeapFree 释放）。

Arguments:
    Engine   - 子系统全局。
    OutRules - 输出数组（调用方 UtHeapFree）。
    Count    - 输出有效规则数。

Return Value:
    STATUS_SUCCESS / STATUS_INVALID_PARAMETER / STATUS_INSUFFICIENT_RESOURCES。
--*/
{
    PEXEMPT_RULE arr;

    if (Engine == NULL || OutRules == NULL || Count == NULL ||
        !Engine->Manager.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    EnterCriticalSection(&Engine->Manager.Lock);
    if (Engine->Manager.RuleCount == 0) {
        *OutRules = NULL;
        *Count = 0;
        LeaveCriticalSection(&Engine->Manager.Lock);
        return STATUS_SUCCESS;
    }

    arr = (PEXEMPT_RULE)UtHeapAlloc(
        (SIZE_T)Engine->Manager.RuleCount * sizeof(EXEMPT_RULE));
    if (arr == NULL) {
        *OutRules = NULL;
        *Count = 0;
        LeaveCriticalSection(&Engine->Manager.Lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(arr, Engine->Manager.Rules,
           (SIZE_T)Engine->Manager.RuleCount * sizeof(EXEMPT_RULE));
    *OutRules = arr;
    *Count = (ULONG)Engine->Manager.RuleCount;
    LeaveCriticalSection(&Engine->Manager.Lock);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
UINT64
ExemptsMgr_GetRuleCount(
    _In_ PEXEMPT_ENGINE Engine,
    _In_ UINT8 Type
    )
{
    UINT64 count = 0;
    UINT64 i;

    if (Engine == NULL || !Engine->Manager.Initialized) {
        return 0;
    }

    EnterCriticalSection(&Engine->Manager.Lock);
    for (i = 0; i < Engine->Manager.RuleCount; i++) {
        if (Type == ExemptRule_MaxValue ||
            Engine->Manager.Rules[i].Type == Type) {
            count++;
        }
    }
    LeaveCriticalSection(&Engine->Manager.Lock);

    return count;
}

_Use_decl_annotations_
VOID
ExemptsMgr_CleanupExpired(
    _Inout_ PEXEMPT_ENGINE Engine
    )
/*++
Routine Description:
    惰性过期清理：删除已过期的非 SYSTEM 规则。

Arguments:
    Engine - 子系统全局。

Return Value:
    无。
--*/
{
    UINT64 i;

    if (Engine == NULL || !Engine->Manager.Initialized) {
        return;
    }

    EnterCriticalSection(&Engine->Manager.Lock);
    for (i = Engine->Manager.RuleCount; i > 0; i--) {
        PEXEMPT_RULE r = &Engine->Manager.Rules[i - 1];

        if (r->Flags & EXEMPT_FLAG_SYSTEM) {
            continue;
        }
        if (!ExemptsMgrp_IsActive(r)) {
            ExemptsMgrp_RemoveAt(Engine, i - 1);
        }
    }
    LeaveCriticalSection(&Engine->Manager.Lock);
}
