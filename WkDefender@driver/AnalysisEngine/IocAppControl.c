/**************************************************/
/*  WkDefender — AppControl 执行策略判定引擎实现   */
/*                                                  */
/*  零信任执行控制（按功能融合 ShadowStrike        */
/*  AppControl.c，重实现非复制）：哈希/路径黑名单 + */
/*  内置信任目录 + 三策略模式，为进程创建早期阻断   */
/*  提供判定（调用方设 CreateInfo->CreationStatus）。*/
/*  默认门控关闭（monitor-only 姿态），命中判定由   */
/*  Agent 策略开启；Learning/Signer 等风险面以      */
/*  死代码形式覆盖并标注。                          */
/**************************************************/

#include "IocAppControl.h"
#include "../AnalysisEngine/AnalysisEngine.h"     /* AepIsCriticalProcess / AeReportIndicatorPair */
#include "../Common/Utils.h"                      /* WkdAcquire/ReleasePushLock */

/* 26100 SDK 已移除 STATUS_NOT_READY（旧值 0x00000110L）；本地补回兼容宏，
 * 值对齐旧 SDK 语义（功能未就绪，供本模块各查询入口早期返回）。 */
#ifndef STATUS_NOT_READY
#define STATUS_NOT_READY ((NTSTATUS)0x00000110L)
#endif

/**************************************************/
/*                 内置信任路径前缀                 */
/**************************************************/

static const UNICODE_STRING g_IocAcTrustedPaths[] = {
    RTL_CONSTANT_STRING(L"\\Windows\\"),
    RTL_CONSTANT_STRING(L"\\Windows\\System32\\"),
    RTL_CONSTANT_STRING(L"\\Windows\\SysWOW64\\"),
    RTL_CONSTANT_STRING(L"\\Program Files\\"),
    RTL_CONSTANT_STRING(L"\\Program Files (x86)\\"),
};

#define IOC_AC_TRUSTED_PATH_COUNT \
    (sizeof(g_IocAcTrustedPaths) / sizeof(g_IocAcTrustedPaths[0]))

static const UNICODE_STRING g_IocAcSystemRootPrefix =
    RTL_CONSTANT_STRING(L"\\SystemRoot\\");

static const UNICODE_STRING g_IocAcDevicePrefix =
    RTL_CONSTANT_STRING(L"\\Device\\");

/**************************************************/
/*               引擎状态（对齐 WkdIocEngine）      */
/**************************************************/

typedef struct _IOC_AC_STATE {
    volatile LONG State;                /* 0=未初始化 1=初始化中 2=就绪 3=关闭 */
    EX_RUNDOWN_REF RundownRef;

    WKD_HASH_MAP HashTable;             /* SHA256(32B) → (RuleType<<32)|RuleId */

    LIST_ENTRY PathAllowList;
    LIST_ENTRY PathBlockList;
    EX_PUSH_LOCK PathLock;
    volatile LONG PathRuleCount;
    volatile LONG HashRuleCount;

    volatile LONG PolicyMode;           /* IOC_AC_POLICY_MODE */
    IOC_AC_STATISTICS Stats;

    NPAGED_LOOKASIDE_LIST PathRuleLookaside;
} IOC_AC_STATE, * PIOC_AC_STATE;

static IOC_AC_STATE g_IocAcState;

/*
 * 模块门控：默认关闭，判定接线不生效（零行为变化）。
 * Learning 门控：默认关闭（自动洗白风险，见 IocAcpLearnHashRule）。
 */
static BOOLEAN g_IocAcModuleEnabled = FALSE;
static BOOLEAN g_IocAcLearningEnabled = FALSE;

/* 哈希规则值编码：高 32 位 RuleType，低 32 位 RuleId（RuleId 从 1 起，值域避开 0） */
#define IOC_AC_RULE_VALUE(RuleType, RuleId) \
    (((ULONG64)(RuleType) << 32) | (ULONG)(RuleId))
#define IOC_AC_RULE_TYPE_FROM_VALUE(Value) \
    ((IOC_AC_RULE_TYPE)(((Value) >> 32) & 0xFFFFFFFF))

/**************************************************/
/*              HashMap 无操作回调                */
/*                                                  */
/*  CoInsertHashMap/CoRemoveHashMapEntry 对         */
/*  Reference/Dereference 无条件调用（无    */
/*  NULL 守卫）。哈希规则表存纯标量值，须注册无     */
/*  操作回调避免崩溃。                              */
/**************************************************/

static
VOID
IocAcpNoopReference(
    _In_ PVOID Value
    )
{
    UNREFERENCED_PARAMETER(Value);
}

static
VOID
IocAcpNoopDereference(
    _In_ PVOID Value
    )
{
    UNREFERENCED_PARAMETER(Value);
}

/**************************************************/
/*              Rundown 进入/离开                  */
/**************************************************/

static
BOOLEAN
IocAcpEnterOperation(
    VOID
    )
{
    if (InterlockedCompareExchange(&g_IocAcState.State, 0, 0) != 2) {
        return FALSE;
    }
    return ExAcquireRundownProtection(&g_IocAcState.RundownRef);
}

static
VOID
IocAcpLeaveOperation(
    VOID
    )
{
    ExReleaseRundownProtection(&g_IocAcState.RundownRef);
}

/**************************************************/
/*            内置信任目录判定                     */
/*                                                  */
/*  支持 \SystemRoot\、\??\X:\、\Device\<name>\     */
/*  三种根格式解析后与信任目录前缀比较。            */
/*  注意（对齐 SS 缺陷）：\Windows\ 前缀会放行      */
/*  \Windows\Temp\、\Windows\Tasks\ 等用户可写      */
/*  目录，需依赖 PathBlock 规则补充。               */
/**************************************************/

static
BOOLEAN
IocAcpIsTrustedPath(
    _In_ PCUNICODE_STRING ImagePath
    )
{
    USHORT lenChars;
    USHORT rootOffset = MAXUSHORT;
    USHORT remainingBytes;

    if (ImagePath == NULL || ImagePath->Buffer == NULL ||
        ImagePath->Length < 8) {
        return FALSE;
    }

    lenChars = ImagePath->Length / sizeof(WCHAR);

    /* \SystemRoot\ 前缀恒可信（恒映射 %SystemRoot%） */
    if (ImagePath->Length >= g_IocAcSystemRootPrefix.Length) {
        UNICODE_STRING sub;
        sub.Buffer = ImagePath->Buffer;
        sub.Length = g_IocAcSystemRootPrefix.Length;
        sub.MaximumLength = g_IocAcSystemRootPrefix.Length;
        if (RtlEqualUnicodeString(&sub, &g_IocAcSystemRootPrefix, TRUE)) {
            return TRUE;
        }
    }

    /* \??\X:\ — DOS 设备路径，根起点在盘符冒号后 */
    if (lenChars > 6 &&
        ImagePath->Buffer[0] == L'\\' &&
        ImagePath->Buffer[1] == L'?' &&
        ImagePath->Buffer[2] == L'?' &&
        ImagePath->Buffer[3] == L'\\' &&
        ImagePath->Buffer[5] == L':' &&
        ImagePath->Buffer[6] == L'\\') {
        rootOffset = 6;
    }

    /* \Device\<name>\ — NT 设备路径，在设备名后找反斜杠（扫描上限 80 防畸形路径） */
    if (rootOffset == MAXUSHORT && lenChars > 9) {
        if (ImagePath->Length >= g_IocAcDevicePrefix.Length) {
            UNICODE_STRING sub;
            sub.Buffer = ImagePath->Buffer;
            sub.Length = g_IocAcDevicePrefix.Length;
            sub.MaximumLength = g_IocAcDevicePrefix.Length;
            if (RtlEqualUnicodeString(&sub, &g_IocAcDevicePrefix, TRUE)) {
                USHORT scanLimit = (lenChars < 80) ? lenChars : 80;
                for (USHORT i = 8; i < scanLimit; i++) {
                    if (ImagePath->Buffer[i] == L'\\') {
                        rootOffset = i;
                        break;
                    }
                }
            }
        }
    }

    if (rootOffset == MAXUSHORT || rootOffset >= lenChars) {
        return FALSE;
    }

    /* 检查根起点之后是否以信任目录开头 */
    remainingBytes = (USHORT)((lenChars - rootOffset) * sizeof(WCHAR));
    for (ULONG i = 0; i < IOC_AC_TRUSTED_PATH_COUNT; i++) {
        if (remainingBytes >= g_IocAcTrustedPaths[i].Length) {
            UNICODE_STRING sub;
            sub.Buffer = &ImagePath->Buffer[rootOffset];
            sub.Length = g_IocAcTrustedPaths[i].Length;
            sub.MaximumLength = g_IocAcTrustedPaths[i].Length;

            if (RtlEqualUnicodeString(&sub, &g_IocAcTrustedPaths[i], TRUE)) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

/**************************************************/
/*              路径规则判定                       */
/*                                                  */
/*  黑名单优先（Block/Audit），未命中再查白名单。   */
/*  前缀匹配不区分大小写。Walk 上限 ≥ 规则上限，    */
/*  防止规则静默失效。                              */
/**************************************************/

static
IOC_AC_VERDICT
IocAcpCheckPathRules(
    _In_ PCUNICODE_STRING ImagePath
    )
{
    PLIST_ENTRY listEntry;
    ULONG walkCount;
    IOC_AC_VERDICT verdict = AcVerdict_Unknown;

    WkdAcquirePushLockShared(&g_IocAcState.PathLock);

    /* 黑名单优先（更高优先级） */
    walkCount = 0;
    for (listEntry = g_IocAcState.PathBlockList.Flink;
         listEntry != &g_IocAcState.PathBlockList &&
         walkCount < IOC_AC_MAX_PATH_WALK;
         listEntry = listEntry->Flink, walkCount++) {

        PIOC_AC_PATH_RULE rule = CONTAINING_RECORD(
            listEntry, IOC_AC_PATH_RULE, Link);

        if (ImagePath->Length >= rule->PathPrefix.Length) {
            UNICODE_STRING prefix;
            prefix.Buffer = ImagePath->Buffer;
            prefix.Length = rule->PathPrefix.Length;
            prefix.MaximumLength = rule->PathPrefix.Length;

            if (RtlEqualUnicodeString(&prefix, &rule->PathPrefix, TRUE)) {
                IOC_AC_POLICY_MODE mode = (IOC_AC_POLICY_MODE)g_IocAcState.PolicyMode;
                verdict = (mode == AcMode_Enforce) ? AcVerdict_Block : AcVerdict_Audit;
                break;
            }
        }
    }

    /* 白名单（仅当黑名单未命中） */
    if (verdict == AcVerdict_Unknown) {
        walkCount = 0;
        for (listEntry = g_IocAcState.PathAllowList.Flink;
             listEntry != &g_IocAcState.PathAllowList &&
             walkCount < IOC_AC_MAX_PATH_WALK;
             listEntry = listEntry->Flink, walkCount++) {

            PIOC_AC_PATH_RULE rule = CONTAINING_RECORD(
                listEntry, IOC_AC_PATH_RULE, Link);

            if (ImagePath->Length >= rule->PathPrefix.Length) {
                UNICODE_STRING prefix;
                prefix.Buffer = ImagePath->Buffer;
                prefix.Length = rule->PathPrefix.Length;
                prefix.MaximumLength = rule->PathPrefix.Length;

                if (RtlEqualUnicodeString(&prefix, &rule->PathPrefix, TRUE)) {
                    verdict = AcVerdict_Allow;
                    break;
                }
            }
        }
    }

    WkdReleasePushLockShared(&g_IocAcState.PathLock);
    return verdict;
}

/**************************************************/
/*              哈希规则查询                       */
/**************************************************/

static
BOOLEAN
IocAcpFindHashRule(
    _In_ const UCHAR* Hash,
    _Out_ IOC_AC_RULE_TYPE* FoundRuleType
    )
{
    ULONG64 value = (ULONG64)(ULONG_PTR)CoLookupHashMapEntry(
        &g_IocAcState.HashTable,
        (PVOID)Hash,
        IOC_AC_HASH_SIZE
        );

    if (value == 0) {
        return FALSE;
    }

    *FoundRuleType = IOC_AC_RULE_TYPE_FROM_VALUE(value);
    return TRUE;
}

/**************************************************/
/*          路径规则去重（锁内调用）               */
/*                                                  */
/*  调用者必须已持有 PathLock 独占锁。             */
/**************************************************/

static
BOOLEAN
IocAcpPathRuleExistsLocked(
    _In_ IOC_AC_RULE_TYPE RuleType,
    _In_ PCUNICODE_STRING Prefix
    )
{
    PLIST_ENTRY head = (RuleType == AcRule_PathAllow)
        ? &g_IocAcState.PathAllowList
        : &g_IocAcState.PathBlockList;

    for (PLIST_ENTRY le = head->Flink; le != head; le = le->Flink) {
        PIOC_AC_PATH_RULE rule = CONTAINING_RECORD(le, IOC_AC_PATH_RULE, Link);
        if (RtlEqualUnicodeString(&rule->PathPrefix, Prefix, TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

/**************************************************/
/*          Learning 自学习（死代码）              */
/*                                                  */
/*  对齐 SS AcpLearnHashRule：为观察到的可执行文件  */
/*  自动加入哈希白名单。风险：攻击样本首次执行即被  */
/*  "学习"为白名单（自动洗白），默认门控关闭。      */
/*  SS 规则管理入口缺失，本迁移补 Learning 门控。   */
/**************************************************/

static
VOID
IocAcpLearnHashRule(
    _In_ const UCHAR* Hash
    )
{
    BOOLEAN exists = FALSE;
    NTSTATUS status;
    ULONG ruleId;

    if (!g_IocAcLearningEnabled) {
        return;
    }

    if ((ULONG)InterlockedCompareExchange(&g_IocAcState.HashRuleCount, 0, 0)
        >= IOC_AC_MAX_HASH_RULES) {
        return;
    }

    ruleId = (ULONG)InterlockedIncrement(&g_IocAcState.HashRuleCount);
    if (ruleId > IOC_AC_MAX_HASH_RULES) {
        InterlockedDecrement(&g_IocAcState.HashRuleCount);
        return;
    }

    status = CoInsertHashMap(
        &g_IocAcState.HashTable,
        (PVOID)Hash,
        IOC_AC_HASH_SIZE,
        IOC_AC_RULE_VALUE(AcRule_HashAllow, ruleId),
        &exists
        );

    if (exists || !NT_SUCCESS(status)) {
        InterlockedDecrement(&g_IocAcState.HashRuleCount);
    }
}

/**************************************************/
/*                 生命周期                        */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
IocAppControlInitialize(
    VOID
    )
/*++
Routine Description:
    初始化 AppControl 执行策略引擎（默认 Audit 模式，门控关闭）。

Arguments:
    无。

Return Value:
    STATUS_SUCCESS 或初始化失败码。
--*/
{
    LONG previous;
    NTSTATUS status;

    previous = InterlockedCompareExchange(&g_IocAcState.State, 1, 0);
    if (previous != 0) {
        return (previous == 2) ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
    }

    ExInitializeRundownProtection(&g_IocAcState.RundownRef);

    status = CoInitializeHashMap(
        &g_IocAcState.HashTable,
        IOC_AC_HASH_BUCKET_COUNT,
        TRUE,
        IocAcpNoopReference,
        NULL,                   /* ShouldRemove: pure scalar values, no liveness verdict */
        IocAcpNoopDereference
        );
    if (!NT_SUCCESS(status)) {
        g_IocAcState.State = 0;
        return status;
    }

    /* Noop ref/deref registered via CoInitializeHashMap (2026-08-25 mandatory
       symmetric contract): scalar values need no refcount, callbacks are
       no-op stubs to satisfy the required paired registration. */

    InitializeListHead(&g_IocAcState.PathAllowList);
    InitializeListHead(&g_IocAcState.PathBlockList);
    ExInitializePushLock(&g_IocAcState.PathLock);
    g_IocAcState.PathRuleCount = 0;
    g_IocAcState.HashRuleCount = 0;

    /* 默认 Audit（安全部署）；Enforce 需 Agent 策略显式开启 */
    g_IocAcState.PolicyMode = AcMode_Audit;

    ExInitializeNPagedLookasideList(
        &g_IocAcState.PathRuleLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(IOC_AC_PATH_RULE),
        IOC_AC_RULE_POOL_TAG,
        0
        );

    RtlZeroMemory(&g_IocAcState.Stats, sizeof(IOC_AC_STATISTICS));

    InterlockedExchange(&g_IocAcState.State, 2);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WkDefender/AC] AppControl initialized (Mode=Audit, enabled=%s)\n",
               g_IocAcModuleEnabled ? "yes" : "no");

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
IocAppControlShutdown(
    VOID
    )
/*++
Routine Description:
    关闭 AppControl 引擎：等待进行中判定结束并释放全部规则。

Arguments:
    无。

Return Value:
    无。
--*/
{
    PLIST_ENTRY listEntry;
    ULONG freed;

    if (InterlockedCompareExchange(&g_IocAcState.State, 3, 2) != 2) {
        return;
    }

    ExWaitForRundownProtectionRelease(&g_IocAcState.RundownRef);

    /* 释放路径白名单 */
    freed = 0;
    WkdAcquirePushLockExclusive(&g_IocAcState.PathLock);
    while (!IsListEmpty(&g_IocAcState.PathAllowList) &&
           freed < IOC_AC_MAX_PATH_RULES) {
        listEntry = RemoveHeadList(&g_IocAcState.PathAllowList);
        PIOC_AC_PATH_RULE rule = CONTAINING_RECORD(
            listEntry, IOC_AC_PATH_RULE, Link);
        ExFreeToNPagedLookasideList(&g_IocAcState.PathRuleLookaside, rule);
        freed++;
    }

    /* 释放路径黑名单 */
    freed = 0;
    while (!IsListEmpty(&g_IocAcState.PathBlockList) &&
           freed < IOC_AC_MAX_PATH_RULES) {
        listEntry = RemoveHeadList(&g_IocAcState.PathBlockList);
        PIOC_AC_PATH_RULE rule = CONTAINING_RECORD(
            listEntry, IOC_AC_PATH_RULE, Link);
        ExFreeToNPagedLookasideList(&g_IocAcState.PathRuleLookaside, rule);
        freed++;
    }
    WkdReleasePushLockExclusive(&g_IocAcState.PathLock);

    CoFreeHashMap(&g_IocAcState.HashTable);
    ExDeleteNPagedLookasideList(&g_IocAcState.PathRuleLookaside);

    g_IocAcState.HashRuleCount = 0;
    g_IocAcState.PathRuleCount = 0;
    InterlockedExchange(&g_IocAcState.State, 0);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[WkDefender/AC] AppControl shutdown complete.\n");
}

/**************************************************/
/*                  模块门控                       */
/**************************************************/

_Use_decl_annotations_
BOOLEAN
IocAcEnabled(
    VOID
    )
/*++
Routine Description:
    查询模块是否启用且已就绪（接线点门控）。

Arguments:
    无。

Return Value:
    TRUE 时判定接线生效；FALSE 时所有判定跳过。
--*/
{
    return g_IocAcModuleEnabled &&
        (InterlockedCompareExchange(&g_IocAcState.State, 0, 0) == 2);
}

_Use_decl_annotations_
NTSTATUS
IocAcSetEnabled(
    _In_ BOOLEAN Enable
    )
/*++
Routine Description:
    设置模块门控（由 Agent 策略或管理命令调用）。

Arguments:
    Enable - TRUE 启用判定接线，FALSE 关闭。

Return Value:
    恒 STATUS_SUCCESS。
--*/
{
    g_IocAcModuleEnabled = Enable ? TRUE : FALSE;
    return STATUS_SUCCESS;
}

/**************************************************/
/*           进程创建执行判定                      */
/*                                                  */
/*  对齐 SS AcCheckProcessExecution 判定链：        */
/*    哈希 → 路径规则 → 内置信任路径 → 默认策略。   */
/*  Block 时调用方应设置 CreateInfo->CreationStatus */
/*  = STATUS_ACCESS_DENIED 阻断创建。               */
/*  阻断豁免：关键进程（AepIsCriticalProcess）不允   */
/*  许 AppControl 终止，降级为放行。                */
/**************************************************/

_Use_decl_annotations_
IOC_AC_VERDICT
IocAppControlCheckProcessExecution(
    _In_ PCUNICODE_STRING ImagePath,
    _In_opt_ const UCHAR* ImageHash,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId
    )
/*++
Routine Description:
    进程创建执行判定链：哈希/路径黑名单 + 内置信任目录 + 策略模式。

Arguments:
    ImagePath       - 归一化镜像路径（可含短文件名）。
    ImageHash       - 可选 SHA-256（进程创建路径通常为 NULL，对齐 SS 异步哈希）。
    ProcessId       - 新进程 ID。
    ParentProcessId - 父进程 ID（命中上报的源进程，标记攻击者）。

Return Value:
    AcVerdict_Allow/Block/Audit。Block 时调用方须阻断创建。
--*/
{
    IOC_AC_VERDICT verdict = AcVerdict_Unknown;
    IOC_AC_POLICY_MODE mode;

    if (ImagePath == NULL || ImagePath->Buffer == NULL ||
        ImagePath->Length == 0) {
        return AcVerdict_Allow;
    }

    if (!IocAcpEnterOperation()) {
        return AcVerdict_Allow;
    }

    InterlockedIncrement64(&g_IocAcState.Stats.ExecutionsChecked);
    mode = (IOC_AC_POLICY_MODE)g_IocAcState.PolicyMode;

    /* Step 1: 哈希查找（最具体；无哈希则跳过，对齐 SS） */
    if (ImageHash != NULL) {
        IOC_AC_RULE_TYPE hashRuleType;
        InterlockedIncrement64(&g_IocAcState.Stats.HashLookups);
        if (IocAcpFindHashRule(ImageHash, &hashRuleType)) {
            verdict = (hashRuleType == AcRule_HashBlock)
                ? ((mode == AcMode_Enforce) ? AcVerdict_Block : AcVerdict_Audit)
                : AcVerdict_Allow;
        }
    }

    /* Step 2: 路径规则 */
    if (verdict == AcVerdict_Unknown) {
        InterlockedIncrement64(&g_IocAcState.Stats.PathLookups);
        verdict = IocAcpCheckPathRules(ImagePath);
    }

    /* Step 3: 内置信任路径 */
    if (verdict == AcVerdict_Unknown) {
        if (IocAcpIsTrustedPath(ImagePath)) {
            verdict = AcVerdict_Allow;
        }
    }

    /* Step 4: 默认策略 */
    if (verdict == AcVerdict_Unknown) {
        switch (mode) {
        case AcMode_Enforce:
            verdict = AcVerdict_Block;
            break;
        case AcMode_Audit:
            verdict = AcVerdict_Audit;
            break;
        case AcMode_Learning:
            verdict = AcVerdict_Allow;
            if (ImageHash != NULL) {
                IocAcpLearnHashRule(ImageHash);
            }
            InterlockedIncrement64(&g_IocAcState.Stats.RulesLearned);
            break;
        default:
            /* 非法模式值 fail-closed：视作 Enforce，绝不静默降级 */
            verdict = AcVerdict_Block;
            break;
        }
    }

    /* 阻断豁免：关键进程不允许 AppControl 终止（对齐 wkd AepIsCriticalProcess） */
    if (verdict == AcVerdict_Block && AepIsCriticalProcess(ProcessId, ImagePath)) {
        verdict = AcVerdict_Allow;
    }

    /*
     * 命中上报（对齐 SS BeEngineSubmitEvent：Block→90 / Audit→40）：
     * 经 AeReportIndicatorPair 上报 TsIndicator_Defense_AppControlBlock
     * （权重 15，默认等级 High），进程对 = (父→子) 标记攻击者。
     * 对未跟踪父进程返回错误，非致命忽略。
     */
    if (verdict == AcVerdict_Block || verdict == AcVerdict_Audit) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   (verdict == AcVerdict_Block) ? DPFLTR_WARNING_LEVEL : DPFLTR_TRACE_LEVEL,
                   "[WkDefender/AC] %s execution: %wZ (PID=%lu)\n",
                   (verdict == AcVerdict_Block) ? "BLOCKED" : "AUDIT",
                   ImagePath, HandleToULong(ProcessId));
        AeReportIndicatorPair(
            ParentProcessId, ProcessId,
            TsSourceIOC,
            TsIndicator_Defense_AppControlBlock,
            (verdict == AcVerdict_Block) ? AeThreatSeverityHigh : AeThreatSeverityMedium);
    }

    /* 统计更新 */
    switch (verdict) {
    case AcVerdict_Allow:
        InterlockedIncrement64(&g_IocAcState.Stats.ExecutionsAllowed);
        break;
    case AcVerdict_Block:
        InterlockedIncrement64(&g_IocAcState.Stats.ExecutionsBlocked);
        break;
    case AcVerdict_Audit:
        InterlockedIncrement64(&g_IocAcState.Stats.ExecutionsAudited);
        break;
    default:
        break;
    }

    IocAcpLeaveOperation();
    return verdict;
}

/**************************************************/
/*           镜像加载判定（通知型）                */
/*                                                  */
/*  对齐 SS AcCheckImageLoad：仅路径规则 + 信任     */
/*  路径，无哈希判定。镜像加载回调无法阻断，命中    */
/*  Block 仅由调用方加分上报。                      */
/**************************************************/

_Use_decl_annotations_
IOC_AC_VERDICT
IocAppControlCheckImageLoad(
    _In_ PCUNICODE_STRING ImagePath,
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    镜像/DLL 加载判定：路径规则 + 内置信任路径。

Arguments:
    ImagePath - 完整镜像路径。
    ProcessId - 加载进程 ID。

Return Value:
    AcVerdict_Allow/Block（通知型，不阻断加载）。
--*/
{
    IOC_AC_VERDICT verdict;

    if (ImagePath == NULL || ImagePath->Buffer == NULL ||
        ImagePath->Length == 0) {
        return AcVerdict_Allow;
    }

    if (!IocAcpEnterOperation()) {
        return AcVerdict_Allow;
    }

    InterlockedIncrement64(&g_IocAcState.Stats.ImagesChecked);

    /* 仅路径规则（哈希验证开销大，对齐 SS） */
    verdict = IocAcpCheckPathRules(ImagePath);

    if (verdict == AcVerdict_Unknown) {
        if (IocAcpIsTrustedPath(ImagePath)) {
            verdict = AcVerdict_Allow;
        } else {
            IOC_AC_POLICY_MODE mode = (IOC_AC_POLICY_MODE)g_IocAcState.PolicyMode;
            verdict = (mode == AcMode_Enforce) ? AcVerdict_Block : AcVerdict_Allow;
        }
    }

    if (verdict == AcVerdict_Block) {
        InterlockedIncrement64(&g_IocAcState.Stats.ImagesBlocked);
    }

    IocAcpLeaveOperation();
    return verdict;
}

/**************************************************/
/*                   统计                          */
/**************************************************/

_Use_decl_annotations_
VOID
IocAppControlGetStatistics(
    _Out_ PIOC_AC_STATISTICS Statistics
    )
/*++
Routine Description:
    读取引擎统计快照（未就绪时清零输出）。

Arguments:
    Statistics - 输出缓冲区（非空）。

Return Value:
    无。
--*/
{
    if (Statistics == NULL) {
        return;
    }

    RtlZeroMemory(Statistics, sizeof(IOC_AC_STATISTICS));

    if (InterlockedCompareExchange(&g_IocAcState.State, 0, 0) != 2) {
        return;
    }

    Statistics->ExecutionsChecked = g_IocAcState.Stats.ExecutionsChecked;
    Statistics->ExecutionsAllowed = g_IocAcState.Stats.ExecutionsAllowed;
    Statistics->ExecutionsBlocked = g_IocAcState.Stats.ExecutionsBlocked;
    Statistics->ExecutionsAudited = g_IocAcState.Stats.ExecutionsAudited;
    Statistics->ImagesChecked = g_IocAcState.Stats.ImagesChecked;
    Statistics->ImagesBlocked = g_IocAcState.Stats.ImagesBlocked;
    Statistics->RulesLearned = g_IocAcState.Stats.RulesLearned;
    Statistics->HashLookups = g_IocAcState.Stats.HashLookups;
    Statistics->PathLookups = g_IocAcState.Stats.PathLookups;
}

/**************************************************/
/*        策略/规则管理（Agent 推送通道）          */
/*                                                  */
/*  以下 API 功能面就绪，调用点依赖第二阶段新增     */
/*  Agent→Driver 管理命令（ALPC/IOCTL）。当前无     */
/*  调用者，规则表初始为空。                        */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
IocAppControlSetPolicyMode(
    _In_ IOC_AC_POLICY_MODE Mode
    )
/*++
Routine Description:
    设置策略模式（Audit/Enforce/Learning）。

Arguments:
    Mode - 目标模式。

Return Value:
    STATUS_SUCCESS 或 STATUS_INVALID_PARAMETER。
--*/
{
    if (Mode != AcMode_Audit && Mode != AcMode_Enforce && Mode != AcMode_Learning) {
        return STATUS_INVALID_PARAMETER;
    }

    InterlockedExchange(&g_IocAcState.PolicyMode, (LONG)Mode);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
IocAppControlAddHashRule(
    _In_ const UCHAR* Hash,
    _In_ IOC_AC_RULE_TYPE RuleType
    )
/*++
Routine Description:
    添加 SHA-256 哈希规则（Allow/Block）。

Arguments:
    Hash     - 32 字节 SHA-256。
    RuleType - AcRule_HashAllow 或 AcRule_HashBlock。

Return Value:
    状态码；STATUS_INSUFFICIENT_RESOURCES 表示规则数达上限。
--*/
{
    BOOLEAN exists = FALSE;
    ULONG ruleId;
    ULONG64 value;
    NTSTATUS status;

    if (Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (RuleType != AcRule_HashAllow && RuleType != AcRule_HashBlock) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(&g_IocAcState.State, 0, 0) != 2) {
        return STATUS_NOT_READY;
    }
    if ((ULONG)InterlockedCompareExchange(&g_IocAcState.HashRuleCount, 0, 0)
        >= IOC_AC_MAX_HASH_RULES) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ruleId = (ULONG)InterlockedIncrement(&g_IocAcState.HashRuleCount);
    if (ruleId > IOC_AC_MAX_HASH_RULES) {
        InterlockedDecrement(&g_IocAcState.HashRuleCount);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    value = IOC_AC_RULE_VALUE(RuleType, ruleId);
    status = CoInsertHashMap(
        &g_IocAcState.HashTable,
        (PVOID)Hash,
        IOC_AC_HASH_SIZE,
        value,
        &exists
        );

    if (exists) {
        InterlockedDecrement(&g_IocAcState.HashRuleCount);
    }

    return status;
}

_Use_decl_annotations_
NTSTATUS
IocAppControlAddPathRule(
    _In_ PCUNICODE_STRING Prefix,
    _In_ IOC_AC_RULE_TYPE RuleType
    )
/*++
Routine Description:
    添加路径前缀规则（Allow/Block），前缀匹配不区分大小写。

Arguments:
    Prefix   - 路径前缀（如 L"\\Windows\\Temp\\"）。
    RuleType - AcRule_PathAllow 或 AcRule_PathBlock。

Return Value:
    状态码；STATUS_DUPLICATE_OBJECTID 表示同链表已存在同前缀。
--*/
{
    PIOC_AC_PATH_RULE rule;
    PLIST_ENTRY head;

    if (Prefix == NULL || Prefix->Buffer == NULL || Prefix->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Prefix->Length > sizeof(rule->PathBuffer)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (RuleType != AcRule_PathAllow && RuleType != AcRule_PathBlock) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(&g_IocAcState.State, 0, 0) != 2) {
        return STATUS_NOT_READY;
    }

    WkdAcquirePushLockExclusive(&g_IocAcState.PathLock);

    if ((ULONG)g_IocAcState.PathRuleCount >= IOC_AC_MAX_PATH_RULES) {
        WkdReleasePushLockExclusive(&g_IocAcState.PathLock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (IocAcpPathRuleExistsLocked(RuleType, Prefix)) {
        WkdReleasePushLockExclusive(&g_IocAcState.PathLock);
        return STATUS_DUPLICATE_OBJECTID;
    }

    rule = (PIOC_AC_PATH_RULE)ExAllocateFromNPagedLookasideList(
        &g_IocAcState.PathRuleLookaside);
    if (rule == NULL) {
        WkdReleasePushLockExclusive(&g_IocAcState.PathLock);
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(rule, sizeof(IOC_AC_PATH_RULE));
    rule->RuleType = RuleType;
    rule->RuleId = (ULONG)++g_IocAcState.PathRuleCount;

    /* 前缀拷贝：按字节拷贝 Length，PathPrefix 指向 PathBuffer 内嵌存储 */
    RtlCopyMemory(rule->PathBuffer, Prefix->Buffer, Prefix->Length);
    RtlInitUnicodeString(&rule->PathPrefix, rule->PathBuffer);
    rule->PathPrefix.Length = Prefix->Length;

    head = (RuleType == AcRule_PathAllow)
        ? &g_IocAcState.PathAllowList
        : &g_IocAcState.PathBlockList;
    InsertTailList(head, &rule->Link);

    WkdReleasePushLockExclusive(&g_IocAcState.PathLock);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
IocAppControlRemoveHashRule(
    _In_ const UCHAR* Hash
    )
/*++
Routine Description:
    移除 SHA-256 哈希规则。

Arguments:
    Hash - 32 字节 SHA-256。

Return Value:
    STATUS_SUCCESS 或 STATUS_NOT_FOUND。
--*/
{
    if (Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(&g_IocAcState.State, 0, 0) != 2) {
        return STATUS_NOT_READY;
    }

    if (CoRemoveHashMapEntry(
            &g_IocAcState.HashTable,
            (PVOID)Hash,
            IOC_AC_HASH_SIZE)) {
        if ((ULONG)InterlockedCompareExchange(&g_IocAcState.HashRuleCount, 0, 0)
            > 0) {
            InterlockedDecrement(&g_IocAcState.HashRuleCount);
        }
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
IocAppControlRemovePathRule(
    _In_ PCUNICODE_STRING Prefix
    )
/*++
Routine Description:
    移除指定前缀的路径规则（Allow/Block 两条链均查）。

Arguments:
    Prefix - 待移除的前缀。

Return Value:
    恒 STATUS_SUCCESS（未命中无副作用）。
--*/
{
    PLIST_ENTRY listEntry;

    if (Prefix == NULL || Prefix->Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(&g_IocAcState.State, 0, 0) != 2) {
        return STATUS_NOT_READY;
    }

    WkdAcquirePushLockExclusive(&g_IocAcState.PathLock);

    /* 白名单链 */
    for (listEntry = g_IocAcState.PathAllowList.Flink;
         listEntry != &g_IocAcState.PathAllowList; ) {
        PIOC_AC_PATH_RULE rule = CONTAINING_RECORD(
            listEntry, IOC_AC_PATH_RULE, Link);
        PLIST_ENTRY next = listEntry->Flink;

        if (RtlEqualUnicodeString(&rule->PathPrefix, Prefix, TRUE)) {
            RemoveEntryList(listEntry);
            ExFreeToNPagedLookasideList(&g_IocAcState.PathRuleLookaside, rule);
            if ((ULONG)InterlockedCompareExchange(&g_IocAcState.PathRuleCount, 0, 0) > 0) {
                InterlockedDecrement(&g_IocAcState.PathRuleCount);
            }
        }

        listEntry = next;
    }

    /* 黑名单链 */
    for (listEntry = g_IocAcState.PathBlockList.Flink;
         listEntry != &g_IocAcState.PathBlockList; ) {
        PIOC_AC_PATH_RULE rule = CONTAINING_RECORD(
            listEntry, IOC_AC_PATH_RULE, Link);
        PLIST_ENTRY next = listEntry->Flink;

        if (RtlEqualUnicodeString(&rule->PathPrefix, Prefix, TRUE)) {
            RemoveEntryList(listEntry);
            ExFreeToNPagedLookasideList(&g_IocAcState.PathRuleLookaside, rule);
            if ((ULONG)InterlockedCompareExchange(&g_IocAcState.PathRuleCount, 0, 0) > 0) {
                InterlockedDecrement(&g_IocAcState.PathRuleCount);
            }
        }

        listEntry = next;
    }

    WkdReleasePushLockExclusive(&g_IocAcState.PathLock);
    return STATUS_SUCCESS;
}
