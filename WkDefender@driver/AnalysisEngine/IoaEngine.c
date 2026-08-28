#include "IoaEngine.h"
#include "AnalysisEngine.h"                 /* AeReportIndicatorEx */
#include "../Process/ProcessMonitor.h"
#include "../Process/ProcessPairContext.h"
#include "../ThreatScoring/ThreatScoring.h"
#include "../Common/Utils.h"
#include "../Common/DynamicArray.h"
#include "../Syscall/SyscallMonitor.h"      /* PWKD_SYSCALL_CONTEXT */

/**************************************************/
/*            IoaEngine 内部状态                    */
/**************************************************/

static struct {
    BOOLEAN Initialized;
    EX_RUNDOWN_REF RundownRef;
    volatile ULONG TotalAnalyzers;
    volatile ULONG ActiveAnalyzers;
} WkdIoaEngine = { 0 };

/**************************************************/
/*         行为节点全局哈希表                       */
/*                                                  */
/*  使用 WKD_HASH_MAP（HashMap.c）统一管理。         */
/*  Key = <Pair, Type>，Value = PWKD_BEHAVIOR。      */
/*  桶级锁自动管理并发，查找命中通过 Reference pin。*/
/**************************************************/

WKD_HASH_MAP WkdBehaviorMap = { 0 };

/**************************************************/
/*            内部函数前向声明                      */
/**************************************************/

//
// IOA 行为类型 → 评分指示器映射查找（定义于文件末尾）
//
_IRQL_requires_max_(APC_LEVEL)
static
BOOLEAN
IoapLookupIoaIndicator(
    _In_ WKD_ASSEMBLY_TYPE Type,
    _Out_ TS_INDICATOR_TYPE* Indicator
    );

/**************************************************/
/*            行为构建/解析调度表                    */
/*                                                  */
/*  每种行为类型注册 Builder（原始Context→Record）和   */
/*  Resolver（Record→威胁贡献值）回调。               */
/**************************************************/

#define IOA_DISPATCH_MAX 32

typedef struct _IOA_BEHAVIOR_DISPATCHER {
    WKD_ASSEMBLY_TYPE Type;
    SIZE_T RecordSize;

    NTSTATUS (*Builder)(
        _In_ PIOA_BEHAVIOR_RECORD_ENTRY_HEADER RecordHeader,
        _In_ LARGE_INTEGER CurrentTime,
        _In_ WKD_ASSEMBLY_TYPE Type,
        _In_opt_ PVOID Context
        );

    ULONG (*Resolver)(
        _In_ PIOA_BEHAVIOR_RECORD_ENTRY_HEADER Header
        );

} IOA_BEHAVIOR_DISPATCHER, *PIOA_BEHAVIOR_DISPATCHER;

static IOA_BEHAVIOR_DISPATCHER g_IoaDispatcherTable[IOA_DISPATCH_MAX];
static ULONG g_IoaDispatcherCount = 0;

//
// IoapRegisterDispatcher — 注册一个行为类型的构建器+解析器
//
//
// Builder 回调统一为 4 参数签名（与 IOA_BEHAVIOR_DISPATCHER::Builder 完全一致）：
//   (RecordHeader, CurrentTime, Type, Context)
// 历史 3 参数版本（RecordHeader, RecordSize, Context）与调用点
// dispatcher->Builder(slot, currentTime, Type, Context) 错位，
// 会导致 IoapBuilderOpenProcess 把 Type 误当成 Context 解引用（蓝屏）。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
IoapRegisterDispatcher(
    _In_ WKD_ASSEMBLY_TYPE Type,
    _In_ SIZE_T RecordSize,
    _In_ NTSTATUS (*Builder)(
        _In_ PIOA_BEHAVIOR_RECORD_ENTRY_HEADER RecordHeader,
        _In_ LARGE_INTEGER CurrentTime,
        _In_ WKD_ASSEMBLY_TYPE BuilderType,
        _In_opt_ PVOID Context
        ),
    _In_ ULONG (*Resolver)(
        _In_ PIOA_BEHAVIOR_RECORD_ENTRY_HEADER Header
        )
    )
{
    if (g_IoaDispatcherCount >= IOA_DISPATCH_MAX || !Builder || !Resolver) {
        return STATUS_INVALID_PARAMETER;
    }

    g_IoaDispatcherTable[g_IoaDispatcherCount].Type = Type;
    g_IoaDispatcherTable[g_IoaDispatcherCount].RecordSize = RecordSize;
    g_IoaDispatcherTable[g_IoaDispatcherCount].Builder = Builder;
    g_IoaDispatcherTable[g_IoaDispatcherCount].Resolver = Resolver;
    g_IoaDispatcherCount++;

    return STATUS_SUCCESS;
}

//
// IoapLookupDispatcher — 查找 Type 对应的注册条目
//
static
PIOA_BEHAVIOR_DISPATCHER
IoapLookupDispatcher(
    _In_ WKD_ASSEMBLY_TYPE Type
    )
{
    for (ULONG i = 0; i < g_IoaDispatcherCount; i++) {
        if (g_IoaDispatcherTable[i].Type == Type) {
            return &g_IoaDispatcherTable[i];
        }
    }
    return NULL;
}

static
NTSTATUS
IoapInitializeDispatchTable(
    VOID
    );

/**************************************************/
/*           初始化 / 清理                         */
/**************************************************/

//
// Reference 回调 — 查找命中时 pin 住行为节点防止 UAF
//
FORCEINLINE
static
VOID
IoapBehaviorAddRef(
    _In_ PVOID Value
    )
{
    InterlockedIncrement(&((PWKD_BEHAVIOR)Value)->RefCount);
}

//
// Dereference 回调 — CoRemoveHashMapEntry 摘除条目成功时在桶独占锁内调用，
// 释放 HashMap 持有的节点引用（与插入时的 Reference 配对）。
// 修复前 HashMap 无解引用机制，节点每次从哈希表摘除后 RefCount 恒残留 +1，
// 导致行为节点（含 Records 数组）永久泄漏。
//
// 约束：桶锁内回调，仅允许无锁/原子操作；
// PsDereferenceBehavior 内部为 InterlockedDecrement + 可能的
// DaDestroy/ExFreePoolWithTag，均不获取锁，安全。
//
FORCEINLINE
static
VOID
IoapBehaviorDeref(
    _In_ PVOID Value
    )
{
    PsDereferenceBehavior((PWKD_BEHAVIOR)Value);
}

//
// ShouldRemove 回调 — CoRemoveHashMapEntry 在桶独占锁内调用，
// 裁决是否允许摘除该节点。返回 TRUE = 允许移除。
//
// 由于调用发生在桶独占锁内，且调用方通常持有 behavior->Lock，
// ActiveRecords 不会被并发修改，该检查结果可靠。
//
static
BOOLEAN
IoapBehaviorShouldRemove(
    _In_ PVOID Value
    )
{
    PWKD_BEHAVIOR behavior = (PWKD_BEHAVIOR)Value;

    /* 当Ref=2时，说明除了hashmap和调用者外无任何持有者，可安全删除 */
    return (InterlockedCompareExchange(&behavior->RefCount, 0, 0) == 2);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
IoaInitialize(
    VOID
    )
{
    NTSTATUS status;

    RtlZeroMemory(&WkdIoaEngine, sizeof(WkdIoaEngine));
    ExInitializeRundownProtection(&WkdIoaEngine.RundownRef);
    
    /* ---- 初始化行为节点哈希表 ---- */
    {
        status = CoInitializeHashMap(&WkdBehaviorMap, 64, TRUE,
                                     IoapBehaviorAddRef,
                                     IoapBehaviorShouldRemove,
                                     IoapBehaviorDeref);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    /* ---- 初始化构建+解析注册表 ---- */
    status = IoapInitializeDispatchTable();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WkdIoaEngine.Initialized = TRUE;
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
IoaCleanup(
    VOID
)
{
    /* 等待持有IOA引擎Rundown的所有对象释放 */
    ExWaitForRundownProtectionRelease(&WkdIoaEngine.RundownRef);
    
    /* ---- 无锁安全释放 ---- */
    CoFreeHashMap(&WkdBehaviorMap);
    WkdIoaEngine.Initialized = FALSE;
}

/**************************************************/
/*       IoaContext — 摘要链销毁                    */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
IoaAllocateProcessPairContext(
    _Inout_ PAE_PROCESS_PAIR Pair
    )
/*++
Routine Description:
    分配进程对的 IoaContext。由 AeFindOrCreateProcessPair 创建时调用。

Return Value:
    分配成功的 PAE_IOA_CONTEXT；失败返回 NULL。
--*/
{
    PAE_IOA_CONTEXT ioaContext;

    if (!Pair) return STATUS_INVALID_PARAMETER;
    if (!ExAcquireRundownProtection(&WkdIoaEngine.RundownRef)) {
        /* 获取IOA引擎的Rundown后，在上下文释放阶段解引用 */
        return STATUS_REQUEST_ABORTED;
    }

    ioaContext = ExAllocatePool2(POOL_FLAG_NON_PAGED,
        sizeof(AE_IOA_CONTEXT), 'ioaC');
    if (!ioaContext) {
        ExReleaseRundownProtection(&WkdIoaEngine.RundownRef);
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(ioaContext, sizeof(AE_IOA_CONTEXT));

    InitializeListHead(&ioaContext->IoaChain);
    InitializeListHead(&ioaContext->BehaviorHead);
    InterlockedIncrement(&WkdIoaEngine.TotalAnalyzers);
    InterlockedIncrement(&WkdIoaEngine.ActiveAnalyzers);

    Pair->IoaContext = ioaContext;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
IoaFreeProcessPairContext(
    _Inout_ PAE_PROCESS_PAIR Pair
    )
/*++
Routine Description:
    销毁进程对的 IoaContext。由 PsDereferenceWkdProcessPair refcount==0
    分支调用。先原子置 Pair->IoaContext = NULL 关闭新提交入口，
    再等待运行中的提交路径（AeReportIndicatorEx IOA 分支持 rundown）
    退出，最后无锁释放摘要链全部节点与上下文。

    与 TsFreeProcessPairContext 同模式：提交路径必须先
    ExAcquireRundownProtection(&IoaContext->Rundown) 再使用。
    另须对称解引用 IoaAllocateProcessPairContext 获取的引擎级
    RundownRef，否则 IoaCleanup 的 ExWaitForRundownProtectionRelease
    将因引用计数永不归零而挂起。

Arguments:
    Pair - 目标进程对（IoaContext 为 NULL 时静默返回）。

Return Value:
    VOID。
--*/
{
    PAE_IOA_CONTEXT ioaContext;
    PLIST_ENTRY entry;

    if (!Pair || !Pair->IoaContext) return;

    /* ---- 无持有者，可安全无锁释放 ---- */
    ioaContext = Pair->IoaContext;

    /* 释放 IOA 摘要链（FIFO 链，全部节点） */
    while (!IsListEmpty(&ioaContext->IoaChain)) {
        entry = RemoveHeadList(&ioaContext->IoaChain);
        ExFreePoolWithTag(
            CONTAINING_RECORD(entry, AE_IOA_RECORD, Link),
            'ioaS');
    }

    ExFreePoolWithTag(ioaContext, 'ioaC');
    Pair->IoaContext = NULL;
    InterlockedDecrement(&WkdIoaEngine.ActiveAnalyzers);

    /* 对称：IoaAllocateProcessPairContext 曾获取引擎 RundownRef */
    ExReleaseRundownProtection(&WkdIoaEngine.RundownRef);
}

/**************************************************/
/*            行为条目大小查找                      */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static
SIZE_T
IoapGetRecordSize(
    _In_ WKD_ASSEMBLY_TYPE Type
    )
{
    PIOA_BEHAVIOR_DISPATCHER dispatcher = IoapLookupDispatcher(Type);
    if (dispatcher) {
        return dispatcher->RecordSize;
    }

    return 0;
}

/**************************************************/
/*        IoapEsitimateSeverity — 威胁等级估算       */
/*                                                  */
/*  根据事件类型和参数快速估算本次行为的威胁等级。    */
/*  输出 {0=正常, 1=低, 2=中, 3=高}。              */
/*  此等级供评分系统参考，不作为最终判决。            */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static
UCHAR
IoapEsitimateSeverity(
    _In_ WKD_ASSEMBLY_TYPE Type,
    _In_opt_ PVOID Data
    )
{
    UNREFERENCED_PARAMETER(Data);

    /*
     * 快速威胁等级映射：
     *   执行权转移类（CreateRemoteThread/QueueApc/SetContext）→ 高 (3)
     *   内存写/分配（跨进程）→ 中 (2)
     *   内存读/打开句柄 → 低 (1)
     *   其他 → 正常 (0)
     */
    switch (Type) {
    case WkdMessage_ProcessCreated:

        break;

    case WkdMessage_SyscallCreateThread:
    case WkdMessage_SyscallQueueApc:
    case WkdMessage_SyscallSetContextThread:
        return 3;

    case WkdMessage_SyscallAllocateMemory:
    case WkdMessage_SyscallWriteMemory:
        return 2;

    case WkdMessage_SyscallOpenProcess:
    case WkdMessage_SyscallReadMemory:
    case WkdMessage_SyscallProtectMemory:
    case WkdMessage_SyscallMapSection:
        return 1;

    default:
        return 0;
    }
}

/**************************************************/
/*        行为节点哈希表 — WKD_HASH_MAP 封装         */
/**************************************************/

//
// 在全局行为节点哈希表中查找指定 <SourceProcessId, TargetProcessId, Type> 的节点。
// 返回的 PWKD_BEHAVIOR 已被 Reference（即 RefCount++），
// 调用者使用完毕后需 PsDereferenceBehavior。
// 返回 NULL 表示未命中。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
PWKD_BEHAVIOR
IoapLookupBehavior(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _In_ WKD_ASSEMBLY_TYPE Type
    )
{
    if (!SourceProcessId || !TargetProcessId || !Type) {
        return NULL;
    }

    WKD_BEHAVIOR_KEY key = { SourceProcessId, TargetProcessId, Type };
    return CoLookupHashMapEntry(
        &WkdBehaviorMap, &key, sizeof(WKD_BEHAVIOR_KEY));
}

/**************************************************/
/*        行为节点查找 / 创建                       */
/*                                                  */
/*  优先用哈希表 O(1) 查找；未命中则创建并挂入      */
/*  哈希表 + BehaviorHead（遍历链表）。              */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
IoapFindOrCreateBehavior(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ WKD_ASSEMBLY_TYPE Type,
    _Outptr_ PWKD_BEHAVIOR* Behavior
    )
{
    NTSTATUS status;
    PWKD_BEHAVIOR behavior;

    if (!Pair || !Pair->IoaContext || !Type || !Behavior) {
        return STATUS_INVALID_PARAMETER;
    }
    *Behavior = NULL;

    /* ---- IOA上下文的Rundown由外部函数IoaAnalysisBehavior持有 ---- */

    /* ★ 哈希表 O(1) 查找，替代 O(n) 链表遍历 */
    behavior = IoapLookupBehavior(
        Pair->SourceProcessId, Pair->TargetProcessId, Type);
    if (behavior != NULL) goto Success;

    if (InterlockedCompareExchange(&Pair->IoaContext->ActiveBehaviors, 0, 0) >=
        IOA_MAX_BEHAVIORS_PER_PAIR) {
        return STATUS_QUOTA_EXCEEDED;
    }

    /* 创建行为节点 */
    {
        behavior = ExAllocatePool2(POOL_FLAG_NON_PAGED,
            sizeof(WKD_BEHAVIOR), 'bhNd');
        if (!behavior) return STATUS_NO_MEMORY;
        RtlZeroMemory(behavior, sizeof(WKD_BEHAVIOR));

        behavior->RefCount = 1; /* 返回给调用者 */
        ExInitializePushLock(&behavior->Lock);
        behavior->Type = Type;
        /* 惰性初始化，真正插入记录时申请内存 */
        DaInitialize(&behavior->Records,
            (ULONG)IoapGetRecordSize(Type),
            POOL_FLAG_NON_PAGED, 'bhRc');
    }

    /* 持有Pair的写锁 */
    {
        ULONG retry = 3;    /* 默认3次重试机会 */
        BOOLEAN alreadyExists = FALSE;
        WKD_BEHAVIOR_KEY insertKey = { Pair->SourceProcessId, Pair->TargetProcessId, Type };

    Loop:
        /* 防止因内存持续不足导致的无限递归 */
        if (0 == retry--) goto Cleanup;

        /* ---- 挂入全局哈希表（自动增加引用计数） ---- */
        status = CoInsertHashMap(&WkdBehaviorMap,
            &insertKey, sizeof(insertKey), (ULONG64)behavior, &alreadyExists);
        if (NT_SUCCESS(status) && !alreadyExists) {
            /* ---- 挂入遍历链表（需要持有Pair+Behavior锁确保安全） ---- */
            WkdAcquirePushLockExclusive(&Pair->Lock);
            WkdAcquirePushLockExclusive(&behavior->Lock);
            InsertTailList(&Pair->IoaContext->BehaviorHead, &behavior->Links);
            WkdReleasePushLockExclusive(&behavior->Lock);
            Pair->IoaContext->TotalBehaviors++;
            Pair->IoaContext->ActiveBehaviors++;
            WkdReleasePushLockExclusive(&Pair->Lock);
            /* 插入完成，返回Behavor对象 */
            goto Success;
        } else if (alreadyExists) {
            /* double-check 命中：其他线程先插入了 → 回退 */
            PWKD_BEHAVIOR existing = IoapLookupBehavior(
                Pair->SourceProcessId, Pair->TargetProcessId, Type);
            if (existing) {
                *Behavior = existing;
                status = STATUS_SUCCESS;
                goto Cleanup;
            }
        } 
        /* 插入失败，重试 */
        goto Loop;
    }

Success:
    *Behavior = behavior;
    return STATUS_SUCCESS;

Cleanup:
    ExFreePoolWithTag(behavior, 'bhNd');
    return status;
}

// ============================================================================
// MITRE ATT&CK 技术权重表（预留）
//
// 用途:
//   在语义权重基础上, 叠加 MITRE 技术的基础分。
//   使得高危技术（注入 T1055 base=65）在 L1 阶段就获得比低危技术
//   （系统发现 T1057 base=15）更高的评分贡献, 而不需要等到 L2 异步分析。
//
// 增强评分公式（实现时参考）:
//   slotScore = weight × sat(count) × mitreBaseScore / MITRE_BASE_REF
//   其中 MITRE_BASE_REF = 50（作为权重归一化参考基准）
//
// 数据来源:
//   MITRE ATT&CK 企业版 v13+
//
// 评分映射原则:
//   15-19: 发现类技术（T1082 系统信息发现, T1057 进程发现）
//          本身危害低, 但在攻击链中常见, 作为上下文辅助。
//   20-39: 常规执行技术（T1059.001 PowerShell, T1106 Native API）
//          依赖具体参数和上下文决定威胁, L1 只给保守分。
//   40-59: 中等威胁技术（T1027 混淆, T1218 LOLBin, T1546 事件触发）
//          常见的攻击组件, 单次出现不一定恶意, 组合出现才危险。
//   60-79: 高危技术（T1055 进程注入, T1003 凭据转储, T1562 防御逃逸）
//          核心攻击行为, 单次出现就值得 L2 关注。
//   80-100:严重技术（T1486 勒索, T1014 Rootkit, T1490 删除卷影）
//          可直接确认入侵, L1 应触发 REJECT 阻断。
//
// 填表说明:
//   - 数组下标与 G_SlotFlags 和 IoapEventTypeToSlot 的槽位号一一对应
//   - 槽位 9/10 (ObjectAccess) 的子类型在运行时由 SensitiveMask 决定,
//     当前给默认分; 实现时可根据 SensitiveMask 进一步细分:
//       PROCESS_TERMINATE → T1055 base=65
//       PROCESS_VM_OPERATION → T1055.001 base=55
//       PROCESS_DUP_HANDLE → T1055.001 base=45
//       THREAD_SET_CONTEXT → T1055.003 base=50
//   - 槽位 13-15 预留, mitreBaseScore 填 0 表示尚未分配
// ============================================================================

//
// MITRE 技术基础分 — 每槽位一个, 数组下标 = 槽位索引
// 映射关系与 IoapEventTypeToSlot / G_SlotFlags 同步
//
#define MITRE_BASE_REF          50      /* 评分参考基准 */
#define MITRE_SLOT_COUNT        16      /* 必须与 WKD_IOA_SLOT_COUNT 一致 */

static const struct {
    ULONG   mitreBaseScore;             /* MITRE 基础分, 范围 0-100 */
    PCCHAR  mitreTechniqueId;           /* MITRE ATT&CK ID 字符串 */
    PCCHAR  mitreTechniqueName;         /* 可读描述 */
} G_MitreSlotTable[MITRE_SLOT_COUNT] = {
    //
    // 槽位 0: 打开进程句柄 — T1057 进程发现 / T1003 凭据转储准备
    //
    { 15,  "T1057",     "Process Discovery / 进程发现" },

    //
    // 槽位 1: 分配虚拟内存 — T1055.001 进程注入: 分配
    //
    { 45,  "T1055.001", "Process Injection: Allocate Memory / 进程注入: 内存分配" },

    //
    // 槽位 2: 写入虚拟内存 — T1055.001 进程注入: 写入
    //
    { 55,  "T1055.001", "Process Injection: Write Memory / 进程注入: 内存写入" },

    //
    // 槽位 3: 读取虚拟内存 — T1055.001 进程注入: 读取
    //
    { 30,  "T1055.001", "Process Injection: Read Memory / 进程注入: 内存读取" },

    //
    // 槽位 4: 创建远程线程 — T1055 进程注入: 远程线程创建
    //
    { 65,  "T1055",     "Process Injection: Remote Thread / 进程注入: 远程线程" },

    //
    // 槽位 5: 映射视图 — T1055.001 进程注入: 映射视图 / T1055.012 进程镂空
    //
    { 40,  "T1055.001", "Process Injection: Map Section / 进程注入: 映射视图" },

    //
    // 槽位 6: 队列 APC — T1055.004 进程注入: APC 注入 (异步过程调用)
    //
    { 60,  "T1055.004", "Process Injection: APC / 进程注入: APC" },

    //
    // 槽位 7: 设置线程上下文 — T1055.003 进程注入: 线程劫持
    //
    { 50,  "T1055.003", "Process Injection: Thread Hijacking / 进程注入: 线程劫持" },

    //
    // 槽位 8: 修改内存保护 — T1027 混淆 / T1055.001 分配可执行内存
    //
    { 40,  "T1027",     "Obfuscated Files or Info: Memory Protection / 内存保护修改" },

    //
    // 槽位 9: 进程对象访问 — 运行时由 SensitiveMask 子类型决定
    //         默认值 15 (T1057), 实现时建议根据 SensitiveMask 细化:
    //           PROCESS_TERMINATE → 65 (T1055)
    //           PROCESS_VM_OPERATION → 55 (T1055.001)
    //           PROCESS_DUP_HANDLE → 45 (T1055.001)
    //           PROCESS_CREATE_THREAD → 50 (T1055)
    //           PROCESS_SUSPEND_RESUME → 35 (T1055.003)
    //           其他 → 15 (T1057)
    //
    { 15,  "T1057",     "Process Object Access (unrefined) / 进程对象访问(未细化)" },

    //
    // 槽位 10: 线程对象访问 — 运行时由 SensitiveMask 子类型决定
    //          默认值 25 (T1055), 实现时建议根据 SensitiveMask 细化:
    //            THREAD_SET_CONTEXT → 50 (T1055.003)
    //            THREAD_SUSPEND_RESUME → 35 (T1055.003)
    //            THREAD_IMPERSONATE → 60 (T1134 访问令牌操纵)
    //            其他 → 25 (T1055)
    //
    { 25,  "T1055",     "Thread Object Access (unrefined) / 线程对象访问(未细化)" },

    //
    // 槽位 11: 进程镂空模式 — T1055.012 进程镂空
    //
    { 70,  "T1055.012", "Process Hollowing / 进程镂空" },

    //
    // 槽位 12: 线程创建（来自 ThreadNotify）— T1055 进程注入
    //
    { 30,  "T1055",     "Thread Creation / 线程创建" },

    //
    // 槽位 13-15: 预留
    //
    { 0,   NULL,        NULL },
    { 0,   NULL,        NULL },
    { 0,   NULL,        NULL },
};

//
// 查询 MITRE 基础分 — 槽位索引 → MITRE 基础分
// 实现增强评分时在此函数中叠加 SensitiveMask 子类型细化逻辑
//
_IRQL_requires_(PASSIVE_LEVEL)
static
ULONG
IoapGetMitreBaseScore(
    _In_ UCHAR SlotIndex
    )
{
    if (SlotIndex >= MITRE_SLOT_COUNT) {
        return 0;
    }
    return G_MitreSlotTable[SlotIndex].mitreBaseScore;
}

//
// IoapEventTypeToSlot — 行为事件类型 → MITRE 评分槽位
//
// 槽位号与 G_MitreSlotTable / G_SlotFlags 一一对应（16 槽）。
// 未映射的事件返回保留槽 13（mitreBase=0，severity 不上调）。
// 用于 L1 前置评分：高危注入技术在提交评分前按 MITRE 基础分上调 severity。
//
_IRQL_requires_(PASSIVE_LEVEL)
static
UCHAR
IoapEventTypeToSlot(
    _In_ WKD_ASSEMBLY_TYPE Type
    )
{
    switch (Type) {
    case WkdMessage_SyscallOpenProcess:       return 0;   /* T1057/T1003 进程发现/凭据准备 */
    case WkdMessage_SyscallAllocateMemory:    return 1;   /* T1055.001 分配 */
    case WkdMessage_SyscallWriteMemory:       return 2;   /* T1055.001 写入 */
    case WkdMessage_CrossProcessMemoryAccess: return 2;   /* T1055.001 跨进程内存写 */
    case WkdMessage_SyscallReadMemory:        return 3;   /* T1055.001 读取 */
    case WkdMessage_SyscallCreateThread:      return 4;   /* T1055 远程线程 */
    case WkdMessage_CodeInjectionPattern:     return 4;   /* T1055 注入模式 */
    case WkdMessage_SyscallMapSection:        return 5;   /* T1055.001 映射视图 */
    case WkdMessage_SyscallQueueApc:          return 6;   /* T1055.004 APC */
    case WkdMessage_ApcInjectionPattern:      return 6;   /* T1055.004 APC 模式 */
    case WkdMessage_SyscallSetContextThread:  return 7;   /* T1055.003 线程劫持 */
    case WkdMessage_SyscallProtectMemory:     return 8;   /* T1027 内存保护修改 */
    case WkdMessage_ProcessObjectAccess:      return 9;   /* T1057 进程对象访问 */
    case WkdMessage_ThreadObjectAccess:       return 10;  /* T1055 线程对象访问 */
    case WkdMessage_ProcessHollowingPattern:  return 11;  /* T1055.012 进程镂空 */
    case WkdMessage_ThreadCreated:            return 12;  /* T1055 线程创建 */
    default:                                  return 13;  /* 预留槽（mitreBase=0，不上调） */
    }
}

/**************************************************/
/*       位图辅助函数                               */
/*                                                  */
/*  所有函数要求调用者持有 Node->Lock（独占）。       */
/**************************************************/

//
// IoapExpandRecordCapacityLocked 前向声明
//
_IRQL_requires_(APC_LEVEL)
static
NTSTATUS
IoapExpandRecordCapacityLocked(
    _Inout_ PWKD_BEHAVIOR Behavior,
    _In_ ULONG NewCapacity
    );

//
// IoapFindRecordSlotLocked — 在位图中找可用槽位
// 返回第一个 ValidBitmap=0 且在 Capacity 范围内的槽位指针。
// 所有记录在 Capacity 内均满时返回 NULL。
//
_IRQL_requires_(APC_LEVEL)
static
NTSTATUS
IoapFindRecordSlotLocked(
    _Inout_ PWKD_BEHAVIOR Behavior,
    _Outptr_ PIOA_BEHAVIOR_RECORD_ENTRY_HEADER* Slot,
    _Out_opt_ PULONG SlotIndex
    )
{
    NTSTATUS status;
    ULONG capacity;
    ULONG wordCount;

    if (!Behavior || !Slot)
        goto NotFound;
    *Slot = NULL;
    if (SlotIndex) *SlotIndex = 0;

Retry:
    capacity = Behavior->Records.Capacity;

    /* 有效记录数达到容量上限 → 无空位 */
    if (Behavior->Records.Count >= capacity)
        goto NotFound;

    // 取上整数
    wordCount = (capacity + 63) / 64;

    for (ULONG i = 0; i < wordCount; i++) {
        ULONG64 used = Behavior->ValidBitmap[i];

        /* 最后一字屏蔽超出 capacity 的位 */
        if (i == wordCount - 1 && (capacity & 63) != 0) {
            used |= (~0ULL << (capacity & 63)); // 将无效的高位置为1，标识已被占用（实际未使用）
        }

        if (used != ~0ULL) {
            ULONG bit, absSlot;
                
            _BitScanForward64(&bit, ~used);     // 返回第一个空闲位
            absSlot = i * 64 + bit;

            if (SlotIndex) *SlotIndex = absSlot;
            *Slot = (PIOA_BEHAVIOR_RECORD_ENTRY_HEADER)
                ((PUCHAR)Behavior->Records.Data + absSlot * Behavior->Records.ElementSize);
            return STATUS_SUCCESS;
        }
    }

NotFound:
    /*
     * 已达全局容量上限（WKD_DA_MAX_CAPACITY）且无空位 → 返回
     * STATUS_BUFFER_TOO_SMALL，避免无限扩容重试死循环。
     */
    if (capacity >= WKD_DA_MAX_CAPACITY)
        return STATUS_BUFFER_TOO_SMALL;

    capacity = (capacity == 0) ?
        WKD_DA_DEFAULT_CAPACITY : capacity * 2;
    if (capacity > WKD_DA_MAX_CAPACITY) {
        capacity = WKD_DA_MAX_CAPACITY;
    }

    status = IoapExpandRecordCapacityLocked(Behavior, capacity);
    if (!NT_SUCCESS(status)) return status;

    goto Retry;
}

//
// IoapExpandRecordCapacityLocked — 扩容行为节点记录数组
// 遍历位图拷贝有效记录到新数组相同索引，位图/Count 保持不变。
//
_IRQL_requires_(APC_LEVEL)
static
NTSTATUS
IoapExpandRecordCapacityLocked(
    _Inout_ PWKD_BEHAVIOR Behavior,
    _In_ ULONG NewCapacity
    )
{
    PVOID newData;
    SIZE_T elemSize, newSize;
    ULONG oldCapacity;

    if (!Behavior || !NewCapacity) {
        return STATUS_INVALID_PARAMETER;
    }

    elemSize = Behavior->Records.ElementSize;
    newSize = (SIZE_T)NewCapacity * elemSize;
    oldCapacity = Behavior->Records.Capacity;

    newData = ExAllocatePool2(POOL_FLAG_NON_PAGED, newSize, 'bhRc');
    if (!newData) return STATUS_NO_MEMORY;
    RtlZeroMemory(newData, newSize);

    /* 只拷贝位图中标记为有效的记录（相同索引） */
    {
        ULONG bitmapWords = (oldCapacity + 63) / 64;
        for (ULONG i = 0; i < bitmapWords; i++) {
            ULONG64 bits = Behavior->ValidBitmap[i];
            if (bits == 0) continue;

            ULONG idx;
            while (bits) {
                _BitScanForward64(&idx, bits);
                ULONG absIdx = i * 64 + idx;
                if (absIdx >= oldCapacity) break;

                RtlCopyMemory(
                    (PUCHAR)newData + absIdx * elemSize,
                    (PUCHAR)Behavior->Records.Data + absIdx * elemSize,
                    elemSize);

                bits &= (bits - 1);
            }
        }
    }

    /* 释放旧缓冲区 */
    if (Behavior->Records.Data)
        ExFreePool(Behavior->Records.Data);

    Behavior->Records.Data = newData;
    Behavior->Records.Capacity = NewCapacity;
    /* Records.Count / ValidBitmap 不变 */

    return STATUS_SUCCESS;
}

//
// IoapReclaimExpiredRecordsLocked — 回收本节点过期记录
// 位图清除替代 Valid=FALSE，Records.Count 同步递减。
// 持有 Behavior 的写锁。
//
static
ULONG
IoapReclaimExpiredRecordsLocked(
    _Inout_ PWKD_BEHAVIOR Behavior,
    _In_ LARGE_INTEGER CurrentTime
    )
{
    LONG reclaimed = 0;
    LONGLONG earliestExpiry = 0;

    if (!Behavior || !CurrentTime.QuadPart) {
        return MAXULONG;
    }

    //
    // 快速路径：没有有效记录，或最早过期时间尚未到达。
    // EarliestExpiryTime 在记录追加（IoaRecordBehavior）和回收后
    // （本函数末尾）均有维护，因此缓存值足够可靠。
    //
    {
        if (Behavior->Records.Count == 0) {
            Behavior->EarliestExpiryTime.QuadPart = 0;
            return MAXULONG;
        }

        earliestExpiry = Behavior->EarliestExpiryTime.QuadPart;
        if (earliestExpiry >= CurrentTime.QuadPart) {
            return MAXULONG;
        }
    }

    for (ULONG i = 0; i < Behavior->Records.Capacity; i++) {
        PIOA_BEHAVIOR_RECORD_ENTRY_HEADER header;

        /* 位图测试替代 header->Valid 检查 */
        if (!(Behavior->ValidBitmap[i / 64] & (1ULL << (i % 64)))) {
            continue;
        }

        header = (PIOA_BEHAVIOR_RECORD_ENTRY_HEADER)
            ((PUCHAR)Behavior->Records.Data + i * Behavior->Records.ElementSize);

        if (WKD_IOA_RECORD_EXPIRY(header->TimeStamp) < CurrentTime.QuadPart) {
            /* 过期 — 从累积值中移除贡献 */
            Behavior->AccumulatedThreat -= (ULONG)header->Severity;
            Behavior->ValidBitmap[i / 64] &= ~(1ULL << (i % 64));
            header->Valid = FALSE;  /* 冗余标记，调试友好 */
            reclaimed++;
        } else {
            /* 未过期 — 更新最早过期时间 */
            if (earliestExpiry == 0 ||
                WKD_IOA_RECORD_EXPIRY(header->TimeStamp) < earliestExpiry) {
                earliestExpiry = WKD_IOA_RECORD_EXPIRY(header->TimeStamp);
            }
        }
    }

    Behavior->Records.Count -= reclaimed;
    Behavior->EarliestExpiryTime.QuadPart = earliestExpiry;

    return reclaimed;
}

/**************************************************/
/*       内置构建器 + 解析器                       */
/**************************************************/

//
// 通用构建器 — 仅填充 Header，不提取特定参数
//
static
NTSTATUS
IoapBuilderDefault(
    _In_ PIOA_BEHAVIOR_RECORD_ENTRY_HEADER RecordHeader,
    _In_ LARGE_INTEGER CurrentTime,
    _In_ WKD_ASSEMBLY_TYPE Type,
    _In_opt_ PVOID Context
    )
{
    if (!RecordHeader || !CurrentTime.QuadPart || !Type) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(RecordHeader, sizeof(IOA_BEHAVIOR_RECORD_ENTRY_HEADER));
    RecordHeader->TimeStamp = CurrentTime;
    RecordHeader->BehaviorType = Type;
    RecordHeader->Valid = TRUE;

    switch (Type) {
    case WkdMessage_ProcessCreated:
        RecordHeader->Severity = AeThreatSeverityHigh;
        break;

    default:
        RecordHeader->Severity = AeThreatSeverityLow;
    }

    return STATUS_SUCCESS;
}

//
// 通用解析器 — 返回固定贡献值 1
//
static
ULONG
IoapResolverDefault(
    _In_ PIOA_BEHAVIOR_RECORD_ENTRY_HEADER Header
    )
{
    UNREFERENCED_PARAMETER(Header);
    return 1;
}

//
// OpenProcess 解析器 — 根据 DesiredAccess 判定贡献值
//
static
ULONG
IoapResolverOpenProcess(
    _In_ PIOA_BEHAVIOR_RECORD_ENTRY_HEADER Header
    )
{
    PIOA_BEHAVIOR_RECORD_ENTRY_OPEN_PROCESS entry =
        (PIOA_BEHAVIOR_RECORD_ENTRY_OPEN_PROCESS)Header;
    ULONG w = 0;

    if (entry->DesiredAccess & PROCESS_VM_WRITE)      w += 20;
    if (entry->DesiredAccess & PROCESS_CREATE_THREAD) w += 25;
    if (entry->DesiredAccess & PROCESS_VM_OPERATION)  w += 15;
    if (entry->DesiredAccess & PROCESS_TERMINATE)     w += 20;
    if (entry->DesiredAccess & PROCESS_DUP_HANDLE)    w += 10;
    if (entry->DesiredAccess & PROCESS_SUSPEND_RESUME) w += 5;
    return (w > 0) ? w : 1;
}

//
// OpenProcess 构建器 — 将 PWKD_SYSCALL_CONTEXT 转为记录
//
// 注：必须为 4 参数签名（与 IOA_BEHAVIOR_DISPATCHER::Builder 一致），
// 且先复用 IoapBuilderDefault 填充公共头部（TimeStamp/BehaviorType/Valid），
// 否则 TimeStamp 为零值会导致记录在过期回收（IoapReclaimExpiredRecordsLocked）
// 中被立即判为过期。
//
static
NTSTATUS
IoapBuilderOpenProcess(
    _In_ PIOA_BEHAVIOR_RECORD_ENTRY_HEADER RecordHeader,
    _In_ LARGE_INTEGER CurrentTime,
    _In_ WKD_ASSEMBLY_TYPE Type,
    _In_opt_ PVOID Context
    )
{
    NTSTATUS status;
    PIOA_BEHAVIOR_RECORD_ENTRY_OPEN_PROCESS entry =
        (PIOA_BEHAVIOR_RECORD_ENTRY_OPEN_PROCESS)RecordHeader;
    PWKD_SYSCALL_CONTEXT ctx = (PWKD_SYSCALL_CONTEXT)Context;

    /* 先填充公共头部（TimeStamp / BehaviorType / Valid） */
    status = IoapBuilderDefault(RecordHeader, CurrentTime, Type, Context);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (!ctx) {
        return STATUS_INVALID_PARAMETER;
    }

    entry->DesiredAccess = ctx->ParameterBlock.OpenProcess.DesiredAccess;
    entry->ProcessHandle = NULL;
    entry->ObjectAttributes = NULL;
    entry->ClientId = NULL;

    /* Severity 保持 IoapBuilderDefault 的事件级威胁程度（Low）；Resolver
     * 贡献值（DesiredAccess 加权 1-95）由 IoaRecordBehavior 累加进
     * AccumulatedThreat。原实现把 1-100 贡献值写入 1-4 枚举 Severity，
     * 触发 VALID_SEVERITY 拒绝 → OpenProcess 记录被静默丢弃。 */
    return STATUS_SUCCESS;
}

//
// WriteMemory 解析器 — 根据写入大小判定贡献值
//
static
ULONG
IoapResolverWriteMemory(
    _In_ PIOA_BEHAVIOR_RECORD_ENTRY_HEADER Header
    )
{
    PIOA_BEHAVIOR_RECORD_ENTRY_WRITE_MEMORY entry =
        (PIOA_BEHAVIOR_RECORD_ENTRY_WRITE_MEMORY)Header;

    if (entry->NumberOfBytesWritten > 4096)     return 20;
    if (entry->NumberOfBytesWritten > 1024)     return 10;
    return 5;
}

//
// CreateThread 解析器 — 远程线程创建高权重
//
static
ULONG
IoapResolverCreateThread(
    _In_ PIOA_BEHAVIOR_RECORD_ENTRY_HEADER Header
    )
{
    UNREFERENCED_PARAMETER(Header);
    return 30;
}

//
// IoapInitializeDispatchTable — 初始化注册表
//
static
NTSTATUS
IoapInitializeDispatchTable(
    VOID
    )
{
    NTSTATUS status;

    /* 注：Builder 回调在后续迭代中完善参数提取 */

    status = IoapRegisterDispatcher(WkdMessage_SyscallOpenProcess,
        sizeof(IOA_BEHAVIOR_RECORD_ENTRY_OPEN_PROCESS),
        IoapBuilderOpenProcess, IoapResolverOpenProcess);
    if (!NT_SUCCESS(status)) return status;

    /* 其余类型使用通用构建器+内置特定解析器 */
    status = IoapRegisterDispatcher(WkdMessage_SyscallWriteMemory,
        sizeof(IOA_BEHAVIOR_RECORD_ENTRY_WRITE_MEMORY),
        IoapBuilderDefault, IoapResolverWriteMemory);
    if (!NT_SUCCESS(status)) return status;

    status = IoapRegisterDispatcher(WkdMessage_SyscallCreateThread,
        sizeof(IOA_BEHAVIOR_RECORD_ENTRY_CREATE_THREAD),
        IoapBuilderDefault, IoapResolverCreateThread);
    if (!NT_SUCCESS(status)) return status;

    /* 剩余类型全部注册通用构建器+通用解析器 */
#define IOAP_REGISTER_DEFAULT(Type, Size) \
    do { \
        status = IoapRegisterDispatcher((Type), (Size), \
            IoapBuilderDefault, IoapResolverDefault); \
        if (!NT_SUCCESS(status)) return status; \
    } while (0)

    IOAP_REGISTER_DEFAULT(WkdMessage_ProcessObjectAccess,
        sizeof(IOA_BEHAVIOR_RECORD_ENTRY_OBJECT_ACCESS));
    IOAP_REGISTER_DEFAULT(WkdMessage_ThreadObjectAccess,
        sizeof(IOA_BEHAVIOR_RECORD_ENTRY_OBJECT_ACCESS));
    IOAP_REGISTER_DEFAULT(WkdMessage_SyscallAllocateMemory,
        sizeof(IOA_BEHAVIOR_RECORD_ENTRY_ALLOCATE_MEMORY));
    IOAP_REGISTER_DEFAULT(WkdMessage_SyscallProtectMemory,
        sizeof(IOA_BEHAVIOR_RECORD_ENTRY_PROTECT_MEMORY));
    IOAP_REGISTER_DEFAULT(WkdMessage_SyscallReadMemory,
        sizeof(IOA_BEHAVIOR_RECORD_ENTRY_READ_MEMORY));
    IOAP_REGISTER_DEFAULT(WkdMessage_SyscallMapSection,
        sizeof(IOA_BEHAVIOR_RECORD_ENTRY_MAP_SECTION));
    IOAP_REGISTER_DEFAULT(WkdMessage_SyscallQueueApc,
        sizeof(IOA_BEHAVIOR_RECORD_ENTRY_QUEUE_APC));
    IOAP_REGISTER_DEFAULT(WkdMessage_SyscallSetContextThread,
        sizeof(IOA_BEHAVIOR_RECORD_ENTRY_SET_CONTEXT));
    IOAP_REGISTER_DEFAULT(WkdMessage_ThreadCreated,
        sizeof(IOA_BEHAVIOR_RECORD_ENTRY_THREAD));
    IOAP_REGISTER_DEFAULT(WkdMessage_ThreadExited,
        sizeof(IOA_BEHAVIOR_RECORD_ENTRY_THREAD));
    IOAP_REGISTER_DEFAULT(WkdMessage_ProcessCreated,
        sizeof(IOA_BEHAVIOR_RECORD_ENTRY_PROCESS_CREATE));

#undef IOAP_REGISTER_DEFAULT

    return STATUS_SUCCESS;
}

/*
 * 两阶段刷新进程对的行为节点。
 * Phase 1（Pair->Lock 读锁）: 枚举 BehaviorHead，收集需释放和刷新的节点。
 * Phase 2（Pair->Lock 写锁）: 处理收集结果。
 */
_Use_decl_annotations_
NTSTATUS
IoaRefreshProcessPair(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ LARGE_INTEGER CurrentTime
    )
/*++
Routine Description:
    两阶段刷新进程对的行为节点:
    Phase 1 在 Pair->Lock 读锁下枚举 BehaviorHead 并收集节点指针至局部数组，
    Phase 2 在 Pair->Lock 写锁下统一处理收集结果。

    解决了原实现中行为节点链表裸遍历（无 pair->Lock 保护）、
    锁升级窗口期链表被修改、以及 Records.Count==0 时 behavior->Lock
    写锁未释放的锁泄漏问题。

Arguments:
    Pair        — 待刷新的进程对。
    CurrentTime — 当前系统时间。

Return Value:
    VOID
--*/
{
    PWKD_BEHAVIOR behavior;
    PWKD_BEHAVIOR toRelease[64];
    PWKD_BEHAVIOR toRefresh[64];
    ULONG releaseCount = 0;
    ULONG refreshCount = 0;

    if (!Pair || !CurrentTime.QuadPart) {
        return STATUS_INVALID_PARAMETER;
    }

    /* ============ Phase 1: 读锁枚举 + 收集 ============ */
    {
        PLIST_ENTRY entry;

        WkdAcquirePushLockShared(&Pair->Lock);

        entry = Pair->IoaContext->BehaviorHead.Flink;
        while (entry != &Pair->IoaContext->BehaviorHead) {
            behavior = CONTAINING_RECORD(entry, WKD_BEHAVIOR, Links);
            entry = entry->Flink;           /* Pair读锁下推进安全 */

            /* 安全引用Behavior，防止ufa */
            InterlockedIncrement(&behavior->RefCount);

            if (InterlockedCompareExchange(&behavior->Records.Count, 0, 0) == 0) {
                if (releaseCount < 64) {
                    toRelease[releaseCount++] = behavior;
                }
                else {
                    InterlockedDecrement(&behavior->RefCount);
                }
            }
            /* 无锁原子读Behavior，第一轮仅判断 */
            else if (InterlockedCompareExchange(
                &behavior->EarliestExpiryTime.QuadPart, 0, 0) < CurrentTime.QuadPart) {
                if (refreshCount < 64) {
                    toRefresh[refreshCount++] = behavior;
                }
                else {
                    InterlockedDecrement(&behavior->RefCount);
                }
            }
            else {
                InterlockedDecrement(&behavior->RefCount);
            }
        }

        WkdReleasePushLockShared(&Pair->Lock);

        if (releaseCount == 0 && refreshCount == 0)
            return STATUS_SUCCESS;
    }

    /* ============ Phase 2: 写锁处理 ============ */

    WkdAcquirePushLockExclusive(&Pair->Lock);

    /* ---- 处理待刷新节点（记录过期） ---- */
    for (ULONG i = 0; i < refreshCount; i++) {
        ULONG reclaimed = 0;

        behavior = toRefresh[i];
        WkdAcquirePushLockExclusive(&behavior->Lock);

        reclaimed = IoapReclaimExpiredRecordsLocked(behavior, CurrentTime);
        if (reclaimed != MAXULONG) {
            Pair->IoaContext->ActiveRecords -= reclaimed;
        }
        
        if (behavior->Records.Count == 0) {
            /*
             * 降级节点追加到 toRelease 时必须判满（R2 修复）：
             * toRelease 固定 64 项，Phase 1 收集时可能已满（最多 64），
             * 此处再追加即越界写栈。判满后仅释放 Phase 1 pin，
             * 节点保留在链上留待下一轮刷新（60s 后）再次回收。
             * 当前注册的行为类型 12 种 < 64 不可触发，属防御性修复。
             */
            if (releaseCount < 64) {
                toRelease[releaseCount++] = behavior;
            } else {
                InterlockedDecrement(&behavior->RefCount);
            }
        } else {
            InterlockedDecrement(&behavior->RefCount);
        }

        WkdReleasePushLockExclusive(&behavior->Lock);
    }

    /* ---- 处理待释放节点（ActiveRecords == 0） ---- */
    for (ULONG i = 0; i < releaseCount; i++) {
        behavior = toRelease[i];
        WkdAcquirePushLockExclusive(&behavior->Lock);

        if (behavior->Records.Count == 0) {

            /* 从全局哈希表中删除（内含 ShouldRemove 回调验证） */
            WKD_BEHAVIOR_KEY removeKey = 
                { Pair->SourceProcessId, Pair->TargetProcessId, behavior->Type };
            if (CoRemoveHashMapEntry(&WkdBehaviorMap, &removeKey, sizeof(removeKey))) {

                /* 哈希表摘除成功——从Behavior链中移除 */
                RemoveEntryList(&behavior->Links);
                Pair->IoaContext->ActiveBehaviors--;

                /* Ref持有者仅当前线程，可安全释放 */
                ASSERT(InterlockedCompareExchange(&behavior->RefCount, 0, 0) == 1);
                WkdReleasePushLockExclusive(&behavior->Lock);
                PsDereferenceBehavior(behavior);
            } else {
                //
                // ShouldRemove 回调拒绝移除（Behavior存在持有者）。
                // 等待下一轮操作
                //
                WkdReleasePushLockExclusive(&behavior->Lock);
                PsDereferenceBehavior(behavior);
            }
        } else {
            WkdReleasePushLockExclusive(&behavior->Lock);
            PsDereferenceBehavior(behavior);
        }
    }

    WkdReleasePushLockExclusive(&Pair->Lock);

    return STATUS_SUCCESS;
}

/**************************************************/
/*         统一事件记录 — IoaRecordBehavior            */
/*                                                  */
/*  内部函数，使用构建器+解析器将原始 Context 转换     */
/*  为记录条目并插入数组。                         */
/*  插入路径中顺带回收过期记录，确保 AccumulatedThreat  */
/*  反映当前有效记录状态。                            */
/*                                                  */
/**************************************************/
_IRQL_requires_max_(APC_LEVEL)
static
NTSTATUS
IoaRecordBehavior(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ WKD_ASSEMBLY_TYPE Type,
    _In_opt_ PVOID Context,
    _Out_ PAE_THREAT_SEVERITY Severity
    )
{
    NTSTATUS status;
    PIOA_BEHAVIOR_DISPATCHER dispatcher;
    PWKD_BEHAVIOR var_behavior;
    PIOA_BEHAVIOR_RECORD_ENTRY_HEADER slot;
    LARGE_INTEGER currentTime;
    ULONG slotIndex;

    if (!Pair || !Pair->IoaContext ||!Type || !Severity) {
        return STATUS_INVALID_PARAMETER;
    }
    *Severity = AeThreatSeverityNone;

    /* ---- IOA上下文的Rundown由外部函数IoaAnalysisBehavior持有 ---- */

    /* ---- 获取当前时间 ---- */
    KeQuerySystemTime(&currentTime);

    status = IoapFindOrCreateBehavior(Pair, Type, &var_behavior);
    if (!NT_SUCCESS(status)) return status;

    /* ---- 获取节点推锁（独占） ---- */
    WkdAcquirePushLockExclusive(&var_behavior->Lock);

    /* ---- 回收过期记录 ---- */
    IoapReclaimExpiredRecordsLocked(var_behavior, currentTime);

    /* ---- 找槽位，必要时扩容 ---- */
    status = IoapFindRecordSlotLocked(var_behavior, &slot, &slotIndex);
    if (!NT_SUCCESS(status)) goto Cleanup;

    /* ---- 构建记录（填充 ThreatContribution） ---- */
    dispatcher = IoapLookupDispatcher(Type);
    if (!dispatcher) {
        status = STATUS_NOT_SUPPORTED;
        goto Cleanup;
    }
    /* 构建记录；失败则作废回退（slot 未标记位图、计数未增，槽位可被下次复用） */
    status = dispatcher->Builder(slot, currentTime, Type, Context);
    if (!NT_SUCCESS(status)) goto Cleanup;

    /* 位图标记 + 有效计数 */
    var_behavior->ValidBitmap[slotIndex / 64] |= (1ULL << (slotIndex % 64));
    var_behavior->Records.Count++;

    /* ---- 累积威胁贡献（Resolver 连续威胁值；Severity 仅用于评分提交） ---- */
    if (dispatcher->Resolver) {
        var_behavior->AccumulatedThreat += dispatcher->Resolver(slot);
    } else {
        var_behavior->AccumulatedThreat += (ULONG)slot->Severity;
    }

    /* 更新节点的最早过期时间 */
    if (var_behavior->EarliestExpiryTime.QuadPart == 0 ||
        WKD_IOA_RECORD_EXPIRY(currentTime) < var_behavior->EarliestExpiryTime.QuadPart) {
        var_behavior->EarliestExpiryTime.QuadPart = WKD_IOA_RECORD_EXPIRY(currentTime);
    }

    /* ---- MITRE 基础分 severity 上调（L1 前置评分） ----
     * 对齐 SS g_EventMitreMap 高危技术加权：T1055 系(≥65)→+2、
     * T1027/T1055.004 等(40-60)→+1、发现类(<40)不变。仅上调提交评分
     * severity，记录保留原始事件严重度（忠实记录原则）。 */
    {
        UCHAR mitreSlot = IoapEventTypeToSlot(Type);
        ULONG mitreBase = IoapGetMitreBaseScore(mitreSlot);
        AE_THREAT_SEVERITY submitSev = slot->Severity;

        if (mitreBase >= 65) {
            submitSev = (AE_THREAT_SEVERITY)min((ULONG)submitSev + 2, (ULONG)AeThreatSeverityCritical);
        } else if (mitreBase >= 40) {
            submitSev = (AE_THREAT_SEVERITY)min((ULONG)submitSev + 1, (ULONG)AeThreatSeverityCritical);
        }
        *Severity = submitSev;
    }
    status = STATUS_SUCCESS;

Cleanup:
    WkdReleasePushLockExclusive(&var_behavior->Lock);
    PsDereferenceBehavior(var_behavior);

    if (NT_SUCCESS(status)) {
        /* ---- 更新进程对元数据（避免锁序反转导致的死锁问题） ---- */
        WkdAcquirePushLockExclusive(&Pair->Lock);
        Pair->LastAccessTime = currentTime;
        Pair->IoaContext->TotalRecords++;
        Pair->IoaContext->ActiveRecords++;
        WkdReleasePushLockExclusive(&Pair->Lock);
    }

    return status;
}

/**************************************************/
/*        IoaAnalysisBehavior — 行为记录统一入口       */
/*                                                  */
/*  进程对维度。调用方须持有 pair pin                */
/*  （AeOrchestratorDispatch Phase 0 获得）。        */
/*  内部流水线:                                     */
/*    1. 行为记录（注册表构建器+位图数组插入）         */
/*    2. 事件级威胁程度（来自记录条目 Severity）      */
/*    3. 提交 IOA 指示记录（统一入口）                */
/*                                                  */
/*  返回: IOA 威胁程度 1-4                          */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
IoaAnalysisBehavior(
    _In_ PAE_PROCESS_PAIR Pair,
    _In_ WKD_ASSEMBLY_TYPE Type,
    _In_opt_ PVOID Context,
    _Out_opt_ PAE_THREAT_SEVERITY Severity
    )
{
    NTSTATUS status;
    AE_THREAT_SEVERITY severity = AeThreatSeverityNone;

    if (!Pair || !Pair->IoaContext || !Type) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Severity) *Severity = AeThreatSeverityNone;

    /* 获取IOA引擎的Rundown */
    if (!ExAcquireRundownProtection(&WkdIoaEngine.RundownRef)) {
        status = STATUS_REQUEST_ABORTED;
        goto Cleanup;
    }

    /* ---- 步骤 1: 忠实记录（注册表构建+位图数组插入） ---- */
    status = IoaRecordBehavior(Pair, Type, Context, &severity);
    if (!NT_SUCCESS(status) || !VALID_SEVERITY(severity))
        return status;

    /* ---- 步骤 2: 提交 IOA 指示记录（统一入口） ----
     * 此处不持任何 IOA 锁（IoaRecordBehavior 已释放 behavior->Lock，
     * pair->Lock 仅在 IoapFindOrCreateBehavior 插入段短暂持有），
     * 取 TsContext->Lock 无锁序风险。
     */
    {
        TS_INDICATOR_TYPE indicator;

        if (IoapLookupIoaIndicator(Type, &indicator)) {
            status = AeReportIndicatorEx(
                Pair, TsSourceBehavioral, indicator, severity);
        }
    }

    /* ---- 惯犯计数（对齐 SS BepUpdateProcessContext：可疑事件数） ----
     * severity≥Medium 递增进程对行为上下文的可疑事件计数，
     * 供结算侧评分乘数（TspGetContextMultiplier 惯犯/高风险档）使用。 */
    if (severity >= AeThreatSeverityMedium) {
        InterlockedIncrement(&Pair->BehaviorContext.SuspiciousEventCount);
    }

    /* ---- 输出威胁程度 ---- */
    if (Severity) *Severity = severity;

Cleanup:
    ExReleaseRundownProtection(&WkdIoaEngine.RundownRef);
    return status;
}

/**************************************************/
/*        IOA 行为类型 → 评分指示器映射表           */
/*                                                   */
/*  将 WKD_ASSEMBLY_TYPE（行为事件类型）映射为        */
/*  TS_INDICATOR_TYPE 的 0x0Dxx IOA 段枚举值，        */
/*  供 IoaAnalysisBehavior 提交评分记录使用。         */
/**************************************************/

typedef struct _IOA_INDICATOR_MAP_ENTRY {
    WKD_ASSEMBLY_TYPE   Type;
    TS_INDICATOR_TYPE   Indicator;
} IOA_INDICATOR_MAP_ENTRY;

static const IOA_INDICATOR_MAP_ENTRY G_IoaIndicatorMap[] = {
    { WkdMessage_SyscallDetected,           TsIndicator_Ioa_SyscallDetected },
    { WkdMessage_SyscallOpenProcess,        TsIndicator_Ioa_OpenProcess },
    { WkdMessage_SyscallAllocateMemory,     TsIndicator_Ioa_AllocateMemory },
    { WkdMessage_SyscallWriteMemory,        TsIndicator_Ioa_WriteMemory },
    { WkdMessage_SyscallReadMemory,         TsIndicator_Ioa_ReadMemory },
    { WkdMessage_SyscallCreateThread,       TsIndicator_Ioa_CreateRemoteThread },
    { WkdMessage_SyscallMapSection,         TsIndicator_Ioa_MapSection },
    { WkdMessage_SyscallQueueApc,           TsIndicator_Ioa_QueueApc },
    { WkdMessage_SyscallSetContextThread,   TsIndicator_Ioa_SetContextThread },
    { WkdMessage_SyscallProtectMemory,      TsIndicator_Ioa_ProtectMemory },
    { WkdMessage_MemoryAllocate,            TsIndicator_Ioa_MemoryAllocate },
    { WkdMessage_MemoryFree,                TsIndicator_Ioa_MemoryFree },
    { WkdMessage_MemoryProtect,             TsIndicator_Ioa_MemoryProtect },
    { WkdMessage_RegistrySetValue,          TsIndicator_Ioa_RegistrySetValue },
    { WkdMessage_RegistryDeleteValue,       TsIndicator_Ioa_RegistryDeleteValue },
    { WkdMessage_FileCreate,                TsIndicator_Ioa_FileCreate },
    { WkdMessage_FileWrite,                 TsIndicator_Ioa_FileWrite },
    { WkdMessage_FileRename,                TsIndicator_Ioa_FileRename },
    { WkdMessage_FileDelete,                TsIndicator_Ioa_FileDelete },
    { WkdMessage_ProcessObjectAccess,       TsIndicator_Ioa_ProcessObjectAccess },
    { WkdMessage_ThreadObjectAccess,        TsIndicator_Ioa_ThreadObjectAccess },
    { WkdMessage_CrossProcessMemoryAccess,  TsIndicator_Ioa_CrossProcessMemoryAccess },
    { WkdMessage_CodeInjectionPattern,      TsIndicator_Ioa_CodeInjectionPattern },
    { WkdMessage_ProcessHollowingPattern,   TsIndicator_Ioa_ProcessHollowingPattern },
    { WkdMessage_ApcInjectionPattern,       TsIndicator_Ioa_ApcInjectionPattern },
    { WkdMessage_ThreatScoreUpdated,        TsIndicator_Ioa_ThreatScoreUpdated },
    { WkdMessage_ThreatLevelChanged,        TsIndicator_Ioa_ThreatLevelChanged },
    { WkdMessage_ProcessCreated,            TsIndicator_Ioa_ProcessCreated },
    { WkdMessage_ProcessExited,             TsIndicator_Ioa_ProcessExited },
    { WkdMessage_ThreadCreated,             TsIndicator_Ioa_ThreadCreated },
    { WkdMessage_ThreadExited,              TsIndicator_Ioa_ThreadExited },
    { WkdMessage_ProcessSnapshot,           TsIndicator_Ioa_ProcessSnapshot },
    { WkdMessage_HandleScan,                TsIndicator_Ioa_HandleScan },
    { WkdMessage_HandleDuplicate,           TsIndicator_Ioa_HandleDuplicate },   /* 句柄复制（HandleTracker 迁移 2026-08，死代码：事件经 ALPC 直送 Agent 因果图，不驱动驱动 IOA 管线） */
    { WkdMessage_SecurityEvent,             TsIndicator_Ioa_SecurityEvent },
    { WkdMessage_SystemStatus,              TsIndicator_Ioa_SystemStatus },
    { WkdMessage_Error,                     TsIndicator_Ioa_Error },
};

_IRQL_requires_max_(APC_LEVEL)
static
BOOLEAN
IoapLookupIoaIndicator(
    _In_ WKD_ASSEMBLY_TYPE Type,
    _Out_ TS_INDICATOR_TYPE* Indicator
    )
/*++
Routine Description:
    查 IOA 行为类型 → 评分指示器映射（线性扫描，34 项）。

Arguments:
    Type      - 行为事件类型。
    Indicator - 输出评分指示器。

Return Value:
    TRUE = 命中；FALSE = 未命中（不提交评分记录）。
--*/
{
    for (ULONG i = 0; i < ARRAYSIZE(G_IoaIndicatorMap); i++) {
        if (G_IoaIndicatorMap[i].Type == Type) {
            *Indicator = G_IoaIndicatorMap[i].Indicator;
            return TRUE;
        }
    }
    return FALSE;
}