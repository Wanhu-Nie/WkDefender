/**************************************************/
/*  WkDefender Agent — 进程域谱系树实现             */
/*                                                  */
/*  2026-08-15 迁自 IOA/IoaGenealogy.c 并改名。      */
/*  全局实例 WkdProcessTree，main.c 生命周期管理。   */
/**************************************************/

#include "ProcessTree.h"
#include "ProcessThread.h"              /* PsDestroyThreadContext: 进程退出释放线程表 */
#include "ProcessModule.h"              /* PsDestroyModuleContext: 进程退出释放模块视图 */
#include "../Storage/StorageEngine.h"   /* StHotPut/StPersistNode */
#include "../tools.h"

/* PID 索引容量：桶数/配额（对齐驱动三表量级） */
#define WKD_PROCESS_TREE_PID_MAP_BUCKETS    1021
#define WKD_PROCESS_TREE_PID_MAP_MAX        65536

/* 全局进程域索引 */
WKD_PROCESS_TREE WkdProcessTree;

/**************************************************/
/*               内部辅助函数                       */
/*                                                  */
/*  2026-08-23 PID 索引层换 WKD_HASH_MAP：           */
/*  PtTreePidHash/PidBuckets 桶遍历退役，查找走       */
/*  CoLookupHashMapEntry（key=ULONG 字节块）。         */
/**************************************************/

static
VOID
PspDestroyWkdProcess(
    _In_ PWKD_PROCESS WkdProcess
    )
/*++
Routine Description:
    释放进程节点及其持有的字符串资源。

Arguments:
    Node — 待释放的进程节点。

Return Value:
    VOID。
--*/
{
    if (!WkdProcess) return;

    if (CoCheckUnicodeStringValidity(&WkdProcess->ImagePath) &&
        _wcsicmp(WkdProcess->ImagePath->Buffer,
            L"c:\\users\\walker\\desktop\\loadpe.exe") == 0) {
        printf("==> loadpe.exe destroy!\n");
    }

    /* 释放线程/模块 */
    PsDestroyThreadContext(WkdProcess);
    PsDestroyModuleContext(WkdProcess);

    /* 子侧清理防悬链: 若本节点自身作为「子」挂入了父进程 ChildrenHead,
     * 从父链摘除本节点并释放对父的引用 (self 作为「子」的父引用线)。
     * 与 PspUnlinkAndOrphanChildren (本节点作为「父」时解链其子) 是两条
     * 不同方向引用线, 互补不重叠, 无重复 Dereference。 */
    //if (!IsListEmpty(&WkdProcess->ChildrenLink) && WkdProcess->Parent != NULL) {
    //    RemoveEntryList(&WkdProcess->ChildrenLink);
    //    PsDereferenceWkdProcess(WkdProcess->Parent);
    //    WkdProcess->Parent = NULL;
    //}

    /* 2026-08-24 重构: 释放节点前清理进程对双向关联。
        * 摘除所有挂入本节点的 pair 链节 (SourceProcessLinks/TargetProcessLinks) 并递减
        * 对应计数。pair 自身仍由 PairManager 释放, 此处仅保证节点
        * 释放后无残留野链指向已释放内存 (UAF 防护)。
        * 链头锁原则 (2026-08-25): 摘链持本节点 PairLinksLock —
        * 与 pair 创建/清扫摘除同锁域, 防并发挂/摘撕裂。 */
    //AcquireSRWLockExclusive(&WkdProcess->PairLinksLock);
    //while (!IsListEmpty(&WkdProcess->OutPairListHead)) {
    //    RemoveEntryList(WkdProcess->OutPairListHead.Flink);
    //    InterlockedDecrement(&WkdProcess->OutPairCount);
    //}
    //while (!IsListEmpty(&WkdProcess->InPairListHead)) {
    //    RemoveEntryList(WkdProcess->InPairListHead.Flink);
    //    InterlockedDecrement(&WkdProcess->InPairCount);
    //}
    //ReleaseSRWLockExclusive(&WkdProcess->PairLinksLock);

    CoFreeUnicodeString(WkdProcess->ImagePath);
    CoFreeUnicodeString(WkdProcess->CommandLine);
    CoFreeUnicodeString(WkdProcess->ImageFileName);
    
    free(WkdProcess);   /* 节点本体统一 Ut 堆 (malloc 系上下文除外) */
}

/**************************************************/
/*  谱系父子链接辅助 (原子重构 2026-08-25)：         */
/*  以下三函数均须由调用方持 Tree->Lock(EXCLUSIVE)  */
/*  期间调用（PsInsertProcessTreeEntity /            */
/*  PtTreeUpsertSnapshot / PtTreeCleanup 已满足）。   */
/*  链接方向: 子持有父的引用 (child refs parent),   */
/*  使父可被存活子延迟释放, 契合下游无锁读            */
/*  child->Parent 的生命周期期望。                   */
/**************************************************/

/**************************************************/
/*  将子节点挂入父进程 ChildrenHead 并持有父引用。    */
/*  前提: 调用方已确认父存在于 PidMap。              */
/*  调用者需持有进程树的锁                           */
/**************************************************/
static
VOID
PspLinkChildToParentLocked(
    _Inout_ PWKD_PROCESS_TREE Tree,
    _Inout_ PWKD_PROCESS Child
    )
{
    HANDLE ppid;
    PWKD_PROCESS parent;

    if (!Tree || !Child) return;

    /* ppid=0 视为根, 无父链接意义, 不挂 PendingOrphans */
    if (Child->ParentProcessId == 0) {
        Child->IsOrphan  = FALSE;
        Child->Parent    = NULL;
        return;
    }

    ppid = Child->ParentProcessId;
    parent = (PWKD_PROCESS)CoLookupHashMapEntry(
        &Tree->PidMap, &ppid, sizeof(HANDLE));
    if (parent) {
        AcquireSRWLockExclusive(&parent->GenealogyLock);
        InsertTailList(&parent->ChildrenHead, &Child->ChildrenLink);
        Child->Parent        = parent;
        Child->ParentNodeId  = parent->NodeId;
        Child->TreeDepth     = parent->TreeDepth + 1;
        Child->IsOrphan      = FALSE;
        ReleaseSRWLockExclusive(&parent->GenealogyLock);
        /* 查找 pin 不归还 — 就地转为「子持父引用」(2026-08-25
         * ref/deref 契约): Child->Parent 指针的存活由该引用保证,
         * 与 PspUnlinkAndOrphanChildren 的 PsDereferenceWkdProcess
         * 配对。 */
    } else {
        /* 父晚到: 暂挂 PendingOrphans (复用节点 GlobalLink),
         * 待父节点入树经 PspDrainPendingOrphansForParentLocked 认领。 */
        Child->IsOrphan = TRUE;
        InsertTailList(&Tree->PendingOrphans, &Child->GlobalLink);
    }
}

/**************************************************/
/*  父节点成功入树后, 按「父自身 PID」认领等待它的   */
/*  孤儿 (即 ParentProcessId == newParentProcessId 的子节点)。   */
/*  注意 key 是新节点「自身」PID, 而非其 ParentProcessId。 */
/**************************************************/
static
VOID
PspDrainPendingOrphansForParentLocked(
    _In_ const PWKD_PROCESS_TREE Tree,
    _In_ HANDLE NewParentProcessId
    )
{
    PWKD_PROCESS orphan;
    PWKD_PROCESS parent;
    PLIST_ENTRY entry, next;

    if (!Tree || !NewParentProcessId) return;

    /* 父自身刚成功入树, 必在 PidMap 中 */
    parent = (PWKD_PROCESS)CoLookupHashMapEntry(
        &Tree->PidMap, &NewParentProcessId, sizeof(HANDLE));
    if (!parent) return;

    /* 锁序约定 (2026-08-25): GenealogyLock 嵌套一律沿谱系"父先子后"
     * 方向 (本函数 parent→orphan 与 PspUnlinkAndOrphanChildren
     * WkdProcess→child 同向), 等待图为树形 DAG 不成环, 无 ABBA 死锁。
     * Tree->Lock 恒为最外层 (调用方已持)。 */
    AcquireSRWLockExclusive(&parent->GenealogyLock);
    entry = Tree->PendingOrphans.Flink;
    while (entry != &Tree->PendingOrphans) {
        next = entry->Flink;
        orphan = CONTAINING_RECORD(entry, WKD_PROCESS, GlobalLink);

        if (orphan->ParentProcessId == NewParentProcessId) {
            AcquireSRWLockExclusive(&orphan->GenealogyLock);
            RemoveEntryList(&orphan->GlobalLink);
            InsertTailList(&parent->ChildrenHead, &orphan->ChildrenLink);
            orphan->Parent        = parent;
            orphan->ParentNodeId  = parent->NodeId;
            orphan->TreeDepth     = parent->TreeDepth + 1;
            orphan->IsOrphan      = FALSE;
            ReleaseSRWLockExclusive(&orphan->GenealogyLock);
            PsReferenceWkdProcess(parent);   /* 子持有父引用 (独立于查找 pin) */
        }
        entry = next;
    }
    ReleaseSRWLockExclusive(&parent->GenealogyLock);

    /* 查找 pin 释放: CoLookupHashMapEntry 命中时的 +1 由本函数消费完毕,
     * 此处归还 (树引用兜底, 不会归零销毁)。子持父引用由上方显式 +1 承担。 */
    PsDereferenceWkdProcess(parent);
}

/**************************************************/
/*  旧代/覆盖销毁前, 将父名下的子节点重新孤立:       */
/*  摘除各子 ChildrenLink、清其父指针与 NodeId、      */
/*  置孤儿标记, 并由子释放对「本父」的引用。          */
/*  前提: 调用方已持 Tree->Lock, 本父即将被销毁。    */
/**************************************************/
static
VOID
PspUnlinkAndOrphanChildren(
    _In_ PWKD_PROCESS WkdProcess
    )
{
    PLIST_ENTRY entry, next;
    PWKD_PROCESS child;

    if (!WkdProcess) return;

    AcquireSRWLockExclusive(&WkdProcess->GenealogyLock);
    entry = WkdProcess->ChildrenHead.Flink;
    while (entry != &WkdProcess->ChildrenHead) {
        next  = entry->Flink;
        child = CONTAINING_RECORD(entry, WKD_PROCESS, ChildrenLink);

        AcquireSRWLockExclusive(&child->GenealogyLock);
        RemoveEntryList(&child->ChildrenLink);
        RtlZeroMemory(&child->ParentNodeId, sizeof(GUID));
        child->Parent = NULL;
        child->IsOrphan = TRUE;
        ReleaseSRWLockExclusive(&child->GenealogyLock);
        PsDereferenceWkdProcess(WkdProcess);   /* 子释放对父的引用 */
        entry = next;
    }
    ReleaseSRWLockExclusive(&WkdProcess->GenealogyLock);
}

/**************************************************/
/*  引用计数 (2026-08-25 强制对称契约):              */
/*  PidMap 注册 PsReference/DereferenceWkdProcess —  */
/*  Insert 成功 +1 = 树基础引用 (兜底, 防表中节点    */
/*  消失); Lookup 命中 +1 = 调用方查找 pin (借出,   */
/*  用完须 PsDereferenceWkdProcess 归还)。归零触发   */
/*  PspDestroyWkdProcess 真正释放。子持父引用由      */
/*  PspLinkChildToParentLocked 就地转化查找 pin /    */
/*  DrainPendingOrphans 显式 +1 设立。               */
/**************************************************/

_Use_decl_annotations_
LONG
PsReferenceWkdProcess(
    _Inout_ PWKD_PROCESS WkdProcess
    )
{
    if (!WkdProcess) return MAXLONG;
    else return InterlockedIncrement(&WkdProcess->RefCount);
}

_Use_decl_annotations_
LONG
PsDereferenceWkdProcess(
    _Inout_ PWKD_PROCESS WkdProcess
    )
/*++
Routine Description:
    减少进程节点引用计数；归零时释放节点。

Arguments:
    Process — 进程节点指针。

Return Value:
    VOID。
--*/
{
    LONG ref;

    if (!WkdProcess) return MAXLONG;
    ref = InterlockedDecrement(&WkdProcess->RefCount);
    /* 当前仅有 hashmap 持有引用计数，说明进程已退出，进程对和聚合边均已经被清理 */
    if (ref  == 1) {
        if (CoCheckUnicodeStringValidity(&WkdProcess->ImagePath) &&
            _wcsicmp(WkdProcess->ImagePath->Buffer,
                L"c:\\users\\walker\\desktop\\loadpe.exe") == 0) {
            printf("found\n");
        }
        BOOLEAN removed = CoRemoveHashMapEntry(&WkdProcessTree.PidMap,
            &WkdProcess->ProcessId,
            sizeof(HANDLE), FALSE);
        if (remove) ref = 0;
    } else if (ref == 0) {
        /* 进程对象无任何持有者，安全无锁释放 */
        PspDestroyWkdProcess(WkdProcess);
    }
    return ref;
}

/**************************************************/
/*                   公开 API                       */
/**************************************************/

NTSTATUS
PtTreeInitialize(
    _Inout_ PWKD_PROCESS_TREE Tree
    )
/*++
Routine Description:
    初始化进程谱系树（全局 WkdProcessTree，main.c 生命周期管理）。
    须先于 IoaEngine_Initialize（IoaObserve 依赖查树）。

Arguments:
    Tree — 谱系树实例。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;

    if (!Tree) return STATUS_INVALID_PARAMETER;
    if (Tree->Initialized) return STATUS_SUCCESS;

    /* 2026-08-23 PID 索引层: WKD_HASH_MAP（key=PID）
     * 2026-08-25 改造: 启用 ref/deref 对称契约 (UseRefCallbacks=TRUE),
     * 全局单锁模式 (PerBucketLock=FALSE)。Dereference=PsDereference-
     * WkdProcess: 摘除时表引用 -1, 归零自动销毁节点。已核实
     * PspDestroyWkdProcess 销毁链不重入 PidMap (仅触达 Thread/Module
     * Context 与 parent->GenealogyLock), 持 HashMap 桶锁释放无自锁风险。 */
    status = CoInitializeHashMap(&Tree->PidMap,
                                 WKD_PROCESS_TREE_PID_MAP_BUCKETS,
                                 WKD_PROCESS_TREE_PID_MAP_MAX,
                                 FALSE, TRUE,
                                 PsReferenceWkdProcess,
                                 NULL,
                                 PsDereferenceWkdProcess);
    if (!NT_SUCCESS(status)) return status;

    InitializeSRWLock(&Tree->Lock);
    InitializeListHead(&Tree->PendingOrphans);
    Tree->Initialized = TRUE;
    Tree->ActiveUpserts = 0;
    Tree->ActiveRemovals = 0;
    Tree->SnapshotUpserts = 0;
    Tree->SnapshotRemovals = 0;

    printf("[ProcessTree] Initialized: pid hash map (%u buckets)\n",
           WKD_PROCESS_TREE_PID_MAP_BUCKETS);
    return STATUS_SUCCESS;
}

/*++
    PidMap 枚举回调: 销毁每个 Value（进程节点）。
    契约签名对齐 PFN_HASH_MAP_ENUM(Key, KeySize, Value, Context)。
--*/
static
BOOLEAN
PtpDestroyNodeEnumCallback(
    _In_ PVOID Key,
    _In_ ULONG KeySize,
    _In_ PVOID Value,
    _Inout_ PVOID Context
    )
{
    PWKD_PROCESS node = (PWKD_PROCESS)Value;
    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(KeySize);
    UNREFERENCED_PARAMETER(Context);

    /* 已知隐患告警: Cleanup 须在所有进程对已完成 Dereference 后调用;
     * 若此刻 RefCount>1 说明仍有外部引用未释放 (潜在泄漏), 仅告警不影响释放。 */
    if (node->RefCount > 1) {
        printf("[ProcessTree] WARN leak: node pid=%lu RefCount=%ld at cleanup\n",
               (ULONG)(ULONG_PTR)node->ProcessId, node->RefCount);
    }
    /* 先解链本节点的子 (各子释放对父的引用), 再释放表引用 (Insert
     * callback 建立的树基础引用) → 归零销毁。仅一次 Deref:
     * 强语义下表引用即原「树基础引用」, 多减即 UAF。 */
    PspUnlinkAndOrphanChildren(node);
    PsDereferenceWkdProcess(node);
    return TRUE;   /* 继续遍历 */
}

/*++
    PidMap 枚举回调: 按 NodeId(GUID) 匹配进程节点, 命中提前终止。
--*/
typedef struct _PT_NODE_LOOKUP_CTX {
    const GUID*   NodeId;
    PWKD_PROCESS  Found;
} PT_NODE_LOOKUP_CTX, *PPT_NODE_LOOKUP_CTX;

static
BOOLEAN
PtpFindNodeByGuidCallback(
    _In_ PVOID Key,
    _In_ ULONG KeySize,
    _In_ PVOID Value,
    _Inout_ PVOID Context
    )
{
    PWKD_PROCESS node = (PWKD_PROCESS)Value;
    PPT_NODE_LOOKUP_CTX ctx = (PPT_NODE_LOOKUP_CTX)Context;

    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(KeySize);

    if (DefGuidEqual(&node->NodeId, ctx->NodeId)) {
        ctx->Found = node;
        return FALSE;   /* 命中: 提前终止遍历 */
    }
    return TRUE;
}

VOID
PtTreeCleanup(
    _Inout_ PWKD_PROCESS_TREE Tree
    )
/*++
Routine Description:
    清理进程谱系树，释放所有节点。

Arguments:
    Tree — 谱系树实例。

Return Value:
    VOID。
--*/
{
    if (!Tree || !Tree->Initialized) return;

    /* 枚举销毁全部节点（Cleanup 为单线程收尾场景，锁内销毁可接受；
     * PidMap 回调契约: BOOLEAN (Key, KeySize, Value, Context)）。
     * 枚举回调对每节点解链子 + 释放表引用 → 归零销毁。 */
    CoEnumerateHashMap(&Tree->PidMap, PtpDestroyNodeEnumCallback, Tree);

    /* 摘除索引（条目 key/entry 内存随表释放; CoHashMapClear 对齐驱动
     * teardown 语义不清引用 — Value 已在上一步全部销毁）。 */
    CoHashMapClear(&Tree->PidMap);

    /* 枚举已释放全部节点 (含原 PendingOrphans 中的孤儿, 它们仍在 PidMap),
     * 此处仅重置链表头防御残留指针。 */
    InitializeListHead(&Tree->PendingOrphans);

    Tree->Initialized = FALSE;
}

_Use_decl_annotations_
NTSTATUS
PsInsertProcessTreeEntity(
    _Inout_opt_ PWKD_PROCESS_TREE Tree,
    _Inout_ PWKD_PROCESS Child,
    _Out_opt_ PHANDLE ParentProcessId
    )
/*++
Routine Description:
    将一个已初始化 (由 PsCreateWkdProcess 完成) 的进程节点登记入谱系树。
    HashMap 化: 负责「PID 索引登记」+「父子链接」+「孤儿回填」——
      · 同 PID 已有节点: 按 CreateTime 新者胜出;
        - 旧者胜出 → 既有节点已历史链接, 直接返回 (Child 由调用方释放);
        - 新者覆盖 → 摘除旧代索引位并解链其子后就地销毁, Child 入索引;
      · 无同 PID 节点 → 直接插入 PidMap;
    入树成功的 liveNode (新插入/覆盖的 Child) 建立父子链接,
    并按自身 PID 认领 PendingOrphans 中等待它的孤儿。

Arguments:
    Tree   — 谱系树实例。
    Child  — 已初始化的进程节点 (未入树时由调用方释放)。
    OutNode— 接收最终生效节点 (Child 或既有更新节点; 失败为 NULL, 借出非拥有)。

Return Value:
    NTSTATUS。
--*/
{
    HANDLE selfPid;
    PWKD_PROCESS existing;
    NTSTATUS status = STATUS_SUCCESS;

    if (!Tree) Tree = &WkdProcessTree;
    if (!Tree || !Child) return STATUS_INVALID_PARAMETER;
    if (ParentProcessId) *ParentProcessId = NULL;

    AcquireSRWLockExclusive(&Tree->Lock);

    /* ---- Step 1: 同 PID 去重查找，是否存在「同 PID 旧代节点」 ---- */
    selfPid = Child->ProcessId;
    existing = (PWKD_PROCESS)CoLookupHashMapEntry(
        &Tree->PidMap, &selfPid, sizeof(HANDLE));

    /* ---- Step 2-1: 旧者胜出 → 既有节点已历史链接, 直接返回 ---- */
    if (existing && existing->CreateTime.QuadPart >= Child->CreateTime.QuadPart) {
        /* 归还查找 pin (Step 1 的 CoLookupHashMapEntry 命中 +1);
         * 表引用兜底, 此处不会归零销毁。 */
Cleanup_1:
        PsDereferenceWkdProcess(existing);
        status = STATUS_OBJECT_NAME_EXISTS;
        if (ParentProcessId) *ParentProcessId = existing->ParentProcessId;
        goto Cleanup;
    }

    /* ---- Step 2-2: 新代覆盖 → 解链旧代子节点后销毁, Child 接管索引 ---- */
    if (existing) {
        if (!CoRemoveHashMapEntry(&Tree->PidMap, &selfPid, sizeof(HANDLE), FALSE)) {
            /* 防御性回退 (锁内不可达): Remove 失败未摘除, 归还查找 pin
             * 后按「旧者胜出」语义返回。 */
            goto Cleanup_1;
        }
        PspUnlinkAndOrphanChildren(existing);    /* 旧代子节点重新孤立 (各子释放对父引用) */
        /* Remove 已触发 Dereference (-1 表引用); 此处归还 Step 1
         * 查找 pin — 通常即归零销毁 (子引用已在 Unlink 中逐个释放)。 */
        PsDereferenceWkdProcess(existing);
    }

    /* ---- Step 2-3: 对象插入 ---- */
    {
        ULONG attempts = 3;
Retry:
        if (0 == attempts--) goto Cleanup;

        status = CoInsertHashMapEntry(&Tree->PidMap,
            &selfPid, sizeof(HANDLE), Child);
        if (!(NT_SUCCESS(status) ||
            status == STATUS_OBJECT_NAME_COLLISION)) {
            /* 除对象成功插入和冲突外的其他错误，尝试有限次尝试重新插入 */
            goto Retry;
        }
    }

    /* ---- Step 3: 建链 + 认领孤儿 (仅 liveNode 入树成功时) ---- */
    PspLinkChildToParentLocked(Tree, Child);
    // 理论上父进程晚到不可能发生!!!
    PspDrainPendingOrphansForParentLocked(Tree, Child->ProcessId);

    /* 如果孤儿进程（ppid无效）被挂载到System或父父进程（父进程退出），
     * 需要更新ppid。*/
    if (ParentProcessId) *ParentProcessId = Child->ParentProcessId;
    InterlockedIncrement(&Tree->ActiveUpserts);
    status = STATUS_SUCCESS;

Cleanup:
    ReleaseSRWLockExclusive(&Tree->Lock);
    return status;
}

_Use_decl_annotations_
NTSTATUS
PsCreateWkdProcess(
    _Inout_ PWKD_EVENT_HEADER Event,
    _Out_ PWKD_PROCESS* WkdProcess
    )
/*++
Routine Description:
    按事件类型创建进程实体 (实体创建收口入口, 2026-08-24 重构)。
    仅 ProcessCreate 事件调用，职责分两层：
      ① 结构体创建与初始化 (锁无关): UtHeapAlloc + 填充 payload
         基本属性 (GUID/ProcessId/CreateTime/SessionId/IntegrityLevel/
         Elevated/Protected/ImagePath/CommandLine/ImageFileName/
         ImageHash/ParentProcessId/Alive/LastActivity) + 内嵌链表头初始化;
      ② 树登记 (委托 PsInsertProcessTreeEntity): PidMap 索引登记,
         同 PID 按 CreateTime 新者胜出。
    回填事件头 NodeId: TargetProcessId = 生效节点 NodeId,
    SourceProcessId = 其 ParentNodeId (新节点为 0, 快照升级节点为既有值)。

    非 ProcessCreate 事件不应调用本函数; 其端点经
    PsLookupWkdProcessByStrictProcessId (只查不建) 获取，端点不存在即数据不一致。

Arguments:
    Event — 已解析的进程创建事件。

Return Value:
    STATUS_SUCCESS 时 *WkdProcess 为最终生效节点; 失败返回相应 NTSTATUS。
--*/
{
    NTSTATUS status;
    PWKD_PROCESS process;
    PEVENT_PAYLOAD_PROCESS_CREATE payload;

    if (!Event || Event->Type != WkdEvent_ProcessCreate ||
        !WkdProcess) return STATUS_INVALID_PARAMETER;
    *WkdProcess = NULL;

    payload = (PEVENT_PAYLOAD_PROCESS_CREATE)((PUCHAR)Event + sizeof(WKD_EVENT_HEADER));

    process = (PWKD_PROCESS)malloc(sizeof(WKD_PROCESS));
    if (!process) return STATUS_NO_MEMORY;
    RtlZeroMemory(process, sizeof(WKD_PROCESS));

    CoCreateGuid(&process->NodeId);
    process->ProcessId      = payload->ProcessId;
    process->CreateTime     = payload->CreateTime;
    process->SessionId      = payload->SessionId;
    process->IntegrityLevel = payload->IntegrityLevel;
    process->IsElevated     = payload->IsElevated;
    process->IsProtectedProcess = payload->IsProtectedProcess;
    process->Status        = DefProcessStatus_Running;
    process->Alive         = TRUE;
    process->ParentProcessId     = (ULONG)(ULONG_PTR)payload->ParentProcessId;
    process->LastActivity  = Event->Timestamp;
    /* 初始状态+1 - 进程有效；返回给调用者+1 */
    process->RefCount = 2;
    InitializeListHead(&process->ChildrenHead);
    InitializeListHead(&process->ChildrenLink);
    InitializeListHead(&process->GlobalLink);
    InitializeSRWLock(&process->GenealogyLock);
    InitializeSRWLock(&process->PairLinksLock);
    InitializeListHead(&process->OutPairListHead);
    InitializeListHead(&process->InPairListHead);

    if (CoCheckUnicodeStringValidity(&payload->ImagePath))
        CoCopyUnicodeString(&process->ImagePath, &payload->ImagePath);
    if (CoCheckUnicodeStringValidity(&payload->CommandLine))
        CoCopyUnicodeString(&process->CommandLine, &payload->CommandLine);
    if (CoCheckUnicodeStringValidity(&payload->ImageFileName))
        CoCopyUnicodeString(&process->ImageFileName, &payload->ImageFileName);
    RtlCopyMemory(&process->ImageHash, &payload->ImageHash, sizeof(DEF_SHA256_HASH));

    /* 系统进程检测 */
    //if (process->ImagePath && process->ImagePath->Buffer) {
    //    if (wcsstr(process->ImagePath->Buffer, L"\\System32\\") ||
    //        wcsstr(process->ImagePath->Buffer, L"\\system32\\")) {
    //        process->IsSystemProcess = TRUE;
    //    }
    //}

    /* ② 树登记: inserted 接收最终生效节点。
     * - Child 入树成功   → inserted == process;
     * - 同 PID 存在更新代 → inserted == 既有节点, 临时副本就地弃用
     *   (PsInsertProcessTreeEntity 不持有未入树的 Child);
     * - 失败             → process 未入树, 由本函数释放。 */
    {
        status = PsInsertProcessTreeEntity(&WkdProcessTree, process, NULL);
        if (!NT_SUCCESS(status)) {
            PspDestroyWkdProcess(process);   /* 未入树: 本函数释放 */
            return status;
        }
    }

    Event->TargetProcessId = process->NodeId;
    Event->SourceProcessId = process->ParentNodeId;

    *WkdProcess = process;
    return STATUS_SUCCESS;
}

NTSTATUS
PsHandleProcessExit(
    _In_ PWKD_PROCESS WkdProcess,
    _In_ LARGE_INTEGER ExitTime
    )
/*++
Routine Description:
    将指定进程节点标记为已退出。

Arguments:
    Tree     — 谱系树实例。
    NodeId   — 进程节点 GUID。
    ExitTime — 退出时间戳。

Return Value:
    NTSTATUS。
--*/
{

    //if (!WkdProcess || ExitTime.QuadPart == 0) {
    //    return STATUS_INVALID_PARAMETER;
    //}

    //AcquireSRWLockExclusive(&Tree->Lock);
    //
    //WkdProcess->Status = DefProcessStatus_Terminated;
    //WkdProcess->ExitTime = ExitTime;
    //WkdProcess->Alive = FALSE;
    //WkdProcess->LastActivity = ExitTime;

    //PsDestroyThreadContext(WkdProcess);   /* 2026-08-15 进程域: 释放线程表 */
    //PsDestroyModuleContext(WkdProcess);   /* 2026-08-15 进程域: 释放模块视图 */

    //StHotPut(NodeId, DefNode_Process, WkdProcess, 0);
    //StPersistNode(WkdProcess);

    //ReleaseSRWLockExclusive(&Tree->Lock);
    return STATUS_SUCCESS;
}

PWKD_PROCESS
PtTreeLookupByNodeId(
    _In_ PWKD_PROCESS_TREE Tree,
    _In_ GUID               NodeId
    )
/*++
Routine Description:
    通过 GUID NodeId 查找进程节点。
    优先从热缓存查找，回退到全表扫描。

Arguments:
    Tree   — 谱系树实例。
    NodeId — 目标节点 GUID。

Return Value:
    进程节点指针，未找到返回 NULL。
--*/
{
    PT_NODE_LOOKUP_CTX ctx;
    PWKD_PROCESS       cached;

    if (!Tree || !Tree->Initialized) return NULL;

    /* 优先热缓存 */
    cached = StHotGet(NodeId);
    if (cached) return cached;

    /* 回退: PidMap 全表枚举比对 GUID NodeId */
    ctx.NodeId = &NodeId;
    ctx.Found  = NULL;

    CoEnumerateHashMap(&Tree->PidMap, PtpFindNodeByGuidCallback, &ctx);
    return ctx.Found;
}

_Use_decl_annotations_
NTSTATUS
PsLookupWkdProcessByStrictProcessId(
    _In_opt_ PWKD_PROCESS_TREE Tree,
    _In_ HANDLE ProcessId,
    _In_ PLARGE_INTEGER CreateTime,
    _Outptr_ PWKD_PROCESS* WkdProcess
    )
/*++
Routine Description:
    通过 PID（和可选的创建时间）精确查找进程节点。
    2026-08-24 HashMap 化：PidMap O(1) 取「最新代」节点：
    - CreateTime == NULL：直接返回最新代节点（全部现存调用方语义）；
    - CreateTime != NULL：仅当与最新代精确匹配才命中；
    历史代查询已废弃（全局链移除），不匹配一律 STATUS_NOT_FOUND。

Arguments:
    Tree       — 谱系树实例（NULL 时使用全局树）。
    ProcessId  — 进程 ID。
    CreateTime — 可选创建时间精确匹配条件。
    WkdProcess — 输出节点指针 (借出查找 pin, 调用方用完须
                 PsDereferenceWkdProcess 归还)。

Return Value:
    STATUS_SUCCESS / STATUS_NOT_FOUND / STATUS_INVALID_PARAMETER。
--*/
{
    PWKD_PROCESS process;

    if (!Tree) Tree = &WkdProcessTree;
    if (!Tree || !Tree->Initialized || !ProcessId || !WkdProcess) {
        return STATUS_INVALID_PARAMETER;
    }
    *WkdProcess = NULL;

    process = (PWKD_PROCESS)CoLookupHashMapEntry(&Tree->PidMap,
                                                 &ProcessId,
                                                 sizeof(ProcessId));
    if (!process) return STATUS_NOT_FOUND;

    if (CreateTime &&
        process->CreateTime.QuadPart != CreateTime->QuadPart) {
        PsDereferenceWkdProcess(process);   /* 不匹配: 归还查找 pin */
        return STATUS_NOT_FOUND;   /* 最新代不匹配: 历史代已随全局链废弃 */
    }

    /* 借出查找 pin: 调用方用完须 PsDereferenceWkdProcess 归还
     * (对齐 HashMap ref/deref 契约; 表引用兜底, 期间节点不会被销毁)。 */
    *WkdProcess = process;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PsLookupWkdProcessByProcessId(
    _Inout_opt_ PWKD_PROCESS_TREE Tree,
    _In_ HANDLE ProcessId,
    _Outptr_ PWKD_PROCESS* WkdProcess
    )
/*++
Routine Description:
    按 PID 查找进程节点 (只查不建)。命中返回节点指针;
    未命中返回 STATUS_NOT_FOUND。

    2026-08-24 重构: 移除原"未命中则分配最小占位节点"路径。
    重构后实体创建收口于分发层 (ProcessCreate 经 PsCreateWkdProcess
    完整建节点; 其它事件端点要求真实节点已由既往 ProcessCreate 建立),
    不再需要占位机制, 避免 placeholder 泄漏 + 进程对双向链表挂错对象。

Arguments:
    Tree — 谱系树实例。
    Pid  — 进程 ID。

Return Value:
    已存在的进程节点指针 (STATUS_SUCCESS) 或未命中 (STATUS_NOT_FOUND)。
--*/
{
    PWKD_PROCESS process;

    if (!Tree) Tree = &WkdProcessTree;
    if (!Tree || !Tree->Initialized || !ProcessId) return STATUS_INVALID_PARAMETER;
    *WkdProcess = NULL;

    process = (PWKD_PROCESS)CoLookupHashMapEntry(&Tree->PidMap,
        &ProcessId, sizeof(HANDLE));
    if (process) {
        /* 借出查找 pin: 调用方用完须 PsDereferenceWkdProcess 归还
         * (对齐 HashMap ref/deref 契约; 表引用兜底, 期间节点不会被销毁)。 */
        *WkdProcess = process;
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

/**************************************************/
/*               快照兜底 API                      */
/**************************************************/

/*++
    弃用未入树的快照节点: 其链表头未初始化且无树引用,
    不可走 PspDestroyWkdProcess, 按分配器配对方式就地释放。
--*/
static
VOID
PtpDiscardUninsertedSnapshot(
    _In_ PWKD_PROCESS SnapshotNode
    )
{
    if (!SnapshotNode) return;

    CoFreeUnicodeString(SnapshotNode->ImagePath);
    CoFreeUnicodeString(SnapshotNode->CommandLine);
    CoFreeUnicodeString(SnapshotNode->ImageFileName);
    free(SnapshotNode);   /* 与 ProcessSnapshot 的 malloc 配对 (2026-08-25 堆口径对齐) */
}

NTSTATUS
PtTreeUpsertSnapshot(
    _Inout_ PWKD_PROCESS_TREE Tree,
    _In_    PWKD_PROCESS       SnapshotNode
    )
/*++
Routine Description:
    快照 upsert：查重 + 插入或字段级合并（2026-08-15 收编 g_ProcessHashTable，
    2026-08-24 HashMap 化重写）。
    - 同 PID 存活节点（Driver 或 Snapshot）已存在：弃用快照副本，不重插；
    - 同 PID 已退出历史代在索引：快照必为新代（CreateTime 更晚），覆盖之；
    - 无任何该 PID 节点：初始化链表头后插入（不持久化、不产 IOA 事件）。
    未入树的快照节点一律由本函数经 PtpDiscardUninsertedSnapshot 释放。

Arguments:
    Tree         — 谱系树实例。
    SnapshotNode — 调用方构造的快照节点（成功后由树持有）。

Return Value:
    NTSTATUS。
--*/
{
    PWKD_PROCESS existing;
    NTSTATUS     status;

    if (!Tree || !Tree->Initialized || !SnapshotNode) return STATUS_INVALID_PARAMETER;

    AcquireSRWLockExclusive(&Tree->Lock);

    existing = (PWKD_PROCESS)CoLookupHashMapEntry(
        &Tree->PidMap, &SnapshotNode->ProcessId, sizeof(HANDLE));

    /* 已存在存活节点 (Driver 或上一轮快照): 弃用快照副本 */
    if (existing && existing->Alive) {
        PsDereferenceWkdProcess(existing);   /* 归还查找 pin */
        ReleaseSRWLockExclusive(&Tree->Lock);
        PtpDiscardUninsertedSnapshot(SnapshotNode);
        return STATUS_SUCCESS;
    }

    /* 已退出历史代在索引: 快照按代新建, CreateTime 不晚于旧代则弃用 */
    if (existing) {
        if (SnapshotNode->CreateTime.QuadPart <= existing->CreateTime.QuadPart) {
            PsDereferenceWkdProcess(existing);   /* 归还查找 pin */
            ReleaseSRWLockExclusive(&Tree->Lock);
            PtpDiscardUninsertedSnapshot(SnapshotNode);
            return STATUS_SUCCESS;
        }
        if (CoRemoveHashMapEntry(&Tree->PidMap,
                                 &SnapshotNode->ProcessId, sizeof(HANDLE), FALSE)) {
            PspUnlinkAndOrphanChildren(existing);   /* 旧代子节点重新孤立 */
            /* Remove 已触发 Dereference (-1 表引用); 此处归还查找 pin,
             * 通常即归零销毁。 */
            PsDereferenceWkdProcess(existing);
        }
    }

    SnapshotNode->Alive  = TRUE;
    SnapshotNode->Status = DefProcessStatus_Running;
    InitializeListHead(&SnapshotNode->ChildrenHead);
    InitializeListHead(&SnapshotNode->ChildrenLink);
    InitializeListHead(&SnapshotNode->GlobalLink);
    InitializeSRWLock(&SnapshotNode->GenealogyLock);
    InitializeSRWLock(&SnapshotNode->PairLinksLock);
    InitializeListHead(&SnapshotNode->OutPairListHead);
    InitializeListHead(&SnapshotNode->InPairListHead);

    status = CoInsertHashMapEntry(&Tree->PidMap,
                                  &SnapshotNode->ProcessId,
                                  sizeof(HANDLE), SnapshotNode);
    if (NT_SUCCESS(status)) {
        /* 树基础引用由 Insert 的 Reference (+1) 建立, 不再手动置 1 */
        PspLinkChildToParentLocked(Tree, SnapshotNode);          /* 存量补全谱系 */
        PspDrainPendingOrphansForParentLocked(Tree, SnapshotNode->ProcessId);
        InterlockedIncrement64(&Tree->SnapshotUpserts);
    } else {
        PtpDiscardUninsertedSnapshot(SnapshotNode);   /* QUOTA/NO_MEMORY 就地弃用 */
    }

    ReleaseSRWLockExclusive(&Tree->Lock);
    return status;
}

/*++
    PidMap 枚举回调: 对不在本轮存活集合中的 Snapshot 源节点
    标记退出 (Alive=FALSE + ExitTime) 并触发退出回调;
    节点保留为历史, 不从表中移除; Driver 节点不在此处理。
--*/
typedef struct _PT_SNAPSHOT_RECONCILE_CTX {
    PWKD_PROCESS_TREE    Tree;
    PULONG               LivePids;
    ULONG                PidCount;
    PT_SNAPSHOT_EXIT_CB  ExitCb;
} PT_SNAPSHOT_RECONCILE_CTX, *PPT_SNAPSHOT_RECONCILE_CTX;

static
BOOLEAN
PtpReconcileEnumCallback(
    _In_ PVOID Key,
    _In_ ULONG KeySize,
    _In_ PVOID Value,
    _Inout_ PVOID Context
    )
{
    PWKD_PROCESS n = (PWKD_PROCESS)Value;
    PPT_SNAPSHOT_RECONCILE_CTX ctx = (PPT_SNAPSHOT_RECONCILE_CTX)Context;
    BOOLEAN found = FALSE;
    ULONG k;

    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(KeySize);

    if (!n || n->NodeSource != WkdProcessSource_Snapshot || !n->Alive) {
        return TRUE;   /* 仅处理存活的快照节点 */
    }

    for (k = 0; k < ctx->PidCount; k++) {
        if (ctx->LivePids[k] == (ULONG)(ULONG_PTR)n->ProcessId) {
            found = TRUE;
            break;
        }
    }
    if (found) return TRUE;

    n->Alive  = FALSE;
    n->Status = DefProcessStatus_Terminated;
    GetSystemTimeAsFileTime((PFILETIME)&n->ExitTime);
    n->LastActivity = n->ExitTime;
    InterlockedIncrement64(&ctx->Tree->SnapshotRemovals);

    PsDestroyThreadContext(n);   /* 2026-08-15 进程域: 释放线程表 */
    PsDestroyModuleContext(n);   /* 2026-08-15 进程域: 释放模块视图 */

    if (ctx->ExitCb) {
        ctx->ExitCb((ULONG)(ULONG_PTR)n->ProcessId,
                    n->ImageFileName ? n->ImageFileName->Buffer : L"");
    }
    return TRUE;   /* 继续遍历 */
}

VOID
PtTreeReconcileSnapshot(
    _Inout_ PWKD_PROCESS_TREE Tree,
    _In_    PULONG             LivePids,
    _In_    ULONG              PidCount,
    _In_opt_ PT_SNAPSHOT_EXIT_CB ExitCb
    )
/*++
Routine Description:
    快照差集 reconcile：对存活的快照节点（NodeSource=Snapshot）做差集删除。
    Driver 节点由驱动事件控制生命周期，不在此处理。
    差集节点：Alive=FALSE + ExitTime + 回调通知（保留历史，不整表移除）。

Arguments:
    Tree      — 谱系树实例。
    LivePids  — 本轮快照枚举到的 PID 集合。
    PidCount  — PID 数量。
    ExitCb    — 可选退出回调（如 ProcessSnapshot_OnExit）。

Return Value:
    VOID。
--*/
{
    PT_SNAPSHOT_RECONCILE_CTX ctx;

    if (!Tree || !Tree->Initialized || !LivePids) return;

    ctx.Tree     = Tree;
    ctx.LivePids = LivePids;
    ctx.PidCount = PidCount;
    ctx.ExitCb   = ExitCb;

    AcquireSRWLockExclusive(&Tree->Lock);
    CoEnumerateHashMap(&Tree->PidMap, PtpReconcileEnumCallback, &ctx);
    ReleaseSRWLockExclusive(&Tree->Lock);
}
