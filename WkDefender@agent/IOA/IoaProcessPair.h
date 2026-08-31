/**************************************************/
/*  WkDefender IOA — 进程对管理器                    */
/*  Key: <SourceProcessId, TargetProcessId> (AE_PROCESS_PAIR_KEY)*/
/*  Value: AE_PROCESS_PAIR                  */
/*                                                  */
/*  轻量聚合入口。边类型统计存储在 EdgeAggregateTable */
/*  中，本结构持有 EdgeListHead 链向各 EdgeAggregate。 */
/*                                                  */
/*  设计约束: 不存储具体事件参数（通过 RecentEventIds */
/*  指向 Causal Graph / SQLite 按需查询）。           */
/*  InteractionBitmap (128位) 统一承载数据层+语义层。   */
/*                                                  */
/*  2026-08-23 HashMap 化重构（对齐 driver 三表范式）:  */
/*    - 自定义 HashBuckets[4096]+PairCtxHash+LRU 删除,*/
/*      索引统一 WKD_HASH_MAP (key=复合键字节块)。     */
/*    - 键 GUID→PID: pair 只依赖 PID 不缓存节点指针,   */
/*      节点反查经 PsLookupWkdProcessByStrictProcessId。                */
/*    - LRU 淘汰废弃: 配额由 MaxEntries(QUOTA) 承接,   */
/*      淘汰由维护清扫按 LastSeen 摘除 (TTL 保留)。    */
/*    - 双向关联 (SourceProcessLinks/TargetProcessLinks 链入节点            */
/*      Out/InPairListHead) 为节点内部链表，保留。     */
/**************************************************/

#pragma once

#include "IoaTypes.h"
#include "IoaEdgeAggregate.h"

/**************************************************/
/*               进程对管理器                        */
/**************************************************/

#define PAIR_MAP_BUCKETS    1024
#define PAIR_MAX_COUNT      4096
#define PAIR_TTL_MS         300000      /* 5 分钟无活动则淘汰 */
#define PAIR_CLEANUP_INTERVAL_MS 60000  /* 每分钟清理一次 */

/* DirtyFlags 位定义 */
#define IOA_PAIR_DIRTY_TIER1    0x01
#define IOA_PAIR_DIRTY_TIER2    0x02
#define IOA_PAIR_DIRTY_TIER3    0x04

/**************************************************/
/*               函数声明                           */
/**************************************************/

/*
 * 初始化进程对管理器。
 */
NTSTATUS PairManager_Initialize(
    _Out_ PIOA_PROCESS_PAIR_MANAGER* Out
    );

/*
 * 清理进程对管理器。
 */
VOID PairManager_Cleanup(
    _In_ PIOA_PROCESS_PAIR_MANAGER Manager
    );

/*
 * 查找或创建进程对上下文 (2026-08-24 重构: 收 PWKD_PROCESS 节点指针,
 * 对齐 driver AeFindOrCreateProcessPair 双路径范式)。
 * 调用方须保证 Src/Tgt 节点已存在 (ProcessCreate 经 PsCreateWkdProcess
 * 建立; 其它事件端点由 Engine.c 上提步骤经 PsLookupWkdProcessByStrictProcessId 只查不建
 * 取回)。内部用节点 ProcessId 构造 PID 二元组键 (保持键不变)。
 * 创建时建立与进程节点的双向关联 (SourceProcessLinks→Src->OutPairListHead,
 * TargetProcessLinks→Tgt->InPairListHead) 并 PsReferenceWkdProcess 两端。
 *
 * 参数:
 *   Src   — 源进程节点指针。
 *   Tgt   — 目标进程节点指针。
 *
 * 返回值:
 *   STATUS_SUCCESS + *Pair 指向找到或新创建的进程对; 失败返回错误码。
 */
NTSTATUS
AeFindOrCreateProcessPair(
    _Inout_ PWKD_PROCESS SourceWkdProcess,
    _Inout_ PWKD_PROCESS TargetWkdProcess,
    _Out_ PAE_PROCESS_PAIR* Pair
    );

/*
 * 查找进程对上下文（不创建）。
 * 2026-08-25 HashMap ref/deref 契约: 命中经回调 pin (+1) 借出,
 * 调用方用完须 AeDereferenceProcessPair 归还; 仅护同步消费,
 * 不可跨清扫摘除窗口长期持有。
 */
NTSTATUS
AeLookupProcessPair(
    _In_ HANDLE SourceProcessId,
    _In_ HANDLE TargetProcessId,
    _Out_ PAE_PROCESS_PAIR* Pair
    );

LONG
AeReferenceProcessPair(
    _In_ PAE_PROCESS_PAIR Pair
    );

/*
 * 归还 pair 查找 pin (RefCount--, 仅 -1 不释放本体)。
 * 与 AeLookupProcessPair/AeFindOrCreateProcessPair 借出配对。
 */
LONG
AeDereferenceProcessPair(
    _In_ PAE_PROCESS_PAIR Pair
    );

/*
 * 进程对键 → 节点 NodeId 反查（2026-08-23 pair 键 PID 化配套）。
 * pair 不再缓存 GUID，T1/Tier3 等消费方经此 helper 从谱系树取
 * NodeId。任一端反查失败（占位/已回收）对应输出置零 GUID 并返回
 * FALSE。
 */
BOOLEAN
IoaPairResolveNodeIds(
    _In_      PAE_PROCESS_PAIR PairCtx,
    _Out_opt_ GUID*                     SourceNodeId,
    _Out_opt_ GUID*                     TargetNodeId
    );

/*
 * 将边聚合条目挂载到进程对上下文的 EdgeListHead。
 * 数据层位图由 T1Evaluate 负责更新, 此处仅做链表关联。
 *
 * 参数:
 *   PairCtx — 进程对上下文。
 *   Entry   — 边聚合条目（必须已由 IoaFindOrCreateAggregateEdge 创建）。
 */
NTSTATUS
IoaAggregateEdgeAttachProcessPair(
    _Inout_ PAE_PROCESS_PAIR Pair,
    _Inout_ PIOA_AGGREGATE_EDGE AggEdge
    );

/*
 * 刷新进程对的统计计数。
 *
 * 遍历 EdgeListHead，对所有边聚合条目汇总 TotalEvents 和 ActiveEdges。
 * 结果写入 PairCtx->TotalEvents 和 ActiveEdges。
 *
 * 参数:
 *   PairCtx — 进程对上下文。
 *   SrcNode — 源进程节点 (可 NULL, 保留用于未来扩展)。
 */
VOID PairContext_RefreshScore(
    _Inout_ PAE_PROCESS_PAIR PairCtx,
    _In_opt_ PWKD_PROCESS        SrcNode
    );

/*
 * 后台清理过期进程对。
 * 移除超过 PAIR_TTL_MS 无活动的进程对及其关联边聚合。
 */
VOID IocCleanupExpiredProcessPair(
    _In_opt_ PIOA_PROCESS_PAIR_MANAGER Manager
    );

/*
 * 注册为"受监视进程对" (调试/存在性巡检用途)。
 * 按 PID 二元组去重记录; 供 IocCleanupExpiredProcessPair 快照后精确
 * 直查 PairMap 验证目标进程对 (如 <system,loadpe>/<explorer,loadpe>/
 * <loadpe,loadpe>) 是否真实存在于表中, 以对照快照枚举是否漏项。
 *
 * 调用方: Engine.c 命中目标 loadpe.exe 事件时, 以当前事件源/目标 PID 注册。
 *
 * 参数:
 *   SourcePid — 源进程 PID (不得为 0)。
 *   TargetPid — 目标进程 PID (不得为 0)。
 */
VOID IocRegisterMonitoredProcessPair(
    _In_ HANDLE SourcePid,
    _In_ HANDLE TargetPid
    );

/*
 * 获取活跃进程对计数。
 */
ULONG PairManager_GetCount(
    _In_ PIOA_PROCESS_PAIR_MANAGER Manager
    );

/*
 * 获取峰值进程对计数。
 */
ULONG PairManager_GetPeakCount(
    _In_ PIOA_PROCESS_PAIR_MANAGER Manager
    );
