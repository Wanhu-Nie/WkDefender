/**************************************************/
/*  WkDefender Agent — 进程域谱系树                */
/*                                                  */
/*  进程域统一重构 (2026-08-15)：                    */
/*    原 IOA/IoaGenealogy.{h,c} 迁入并改名：         */
/*      WKD_IOA_GENEALOGY  → WKD_PROCESS_TREE       */
/*      IoaGenealogy*       → PtTree*               */
/*    全局实例 WkdProcessTree 独立于 IoaEngine       */
/*    （谱系比因果图更基础，被 IOA/处置/UI 共享）。   */
/*                                                  */
/*  职责：事件驱动进程插入/退出/查重 + 全局 PID 索引  */
/*        + 谱系父子树。快照收编（PtTreeUpsert-       */
/*        Snapshot/Reconcile）在步骤4 追加。          */
/**************************************************/

#pragma once

#include "ProcessTypes.h"
#include "../Notification/EventTypes.h"
#include "../Common/HashMap.h"

/**************************************************/
/*               谱系树定义                         */
/*                                                  */
/*  2026-08-23 PID 索引层换 WKD_HASH_MAP            */
/*  （对齐 driver 三表全 HashMap 范式）：             */
/*    - PidMap: key=HANDLE PID 字节块，value=          */
/*      PWKD_PROCESS；表中恒持同 PID「最新代」        */
/*      （登记碰撞按 CreateTime 新者胜出）。           */
/*    - 不注册 Reference/Dereference 回调：保持既有    */
/*      裸指针返回语义（HashMap 仅作索引层，           */
/*      对象生命周期由树锁 + 引用计数管理）。          */
/*    - 历史代全局链 (ProcessListHead) 已随 HashMap 化  */
/*      移除；谱系父子树 / pair 双向引用仍为节点       */
/*      内部链表，与索引层并存（对齐驱动设计）。       */
/**************************************************/

typedef struct _WKD_PROCESS_TREE {
    BOOLEAN             Initialized;
    WKD_HASH_MAP        PidMap;                 /* PID→最新代节点索引（O(1)） */
    SRWLOCK             Lock;
    volatile ULONG      ActiveUpserts;      // 基于回调通知
    volatile ULONG      ActiveRemovals;
    volatile ULONG      SnapshotUpserts;    // 基于初始化快照
    volatile ULONG      SnapshotRemovals;
    /* 父进程晚于子到达时，子节点入树后暂存于此（复用节点 GlobalLink）。
     * 父节点成功入树时经 PspDrainPendingOrphansForParentLocked 按父 PID 认领回填。
     * 持 Tree->Lock（EXCLUSIVE）访问。 */
    LIST_ENTRY          PendingOrphans;
} WKD_PROCESS_TREE, *PWKD_PROCESS_TREE;

/* 全局进程域索引（对齐 WkdStorageEngine 模式，main.c 生命周期管理） */
extern WKD_PROCESS_TREE WkdProcessTree;

/**************************************************/
/*               函数声明                           */
/**************************************************/

NTSTATUS
PtTreeInitialize(
    _Inout_ PWKD_PROCESS_TREE Tree
    );

VOID
PtTreeCleanup(
    _Inout_ PWKD_PROCESS_TREE Tree
    );

NTSTATUS
PsInsertProcessTreeEntity(
    _Inout_opt_ PWKD_PROCESS_TREE Tree,
    _Inout_ PWKD_PROCESS Child,
    _Out_opt_ PHANDLE ParentProcessId
    );

/*
 * 按事件类型创建进程实体 (收口入口, 2026-08-24 重构)。
 * 仅 ProcessCreate 调用: 负责进程结构体的创建与初始化
 * (alloc + 填充 payload 基本属性, 锁无关),
 * 然后委托 PsInsertProcessTreeEntity 做 PID 索引登记
 * (同 PID 按 CreateTime 新者胜出), 并回填事件头 NodeId。
 *
 * 返回 STATUS_SUCCESS 时 *WkdProcess 为最终生效节点
 * (新建节点或既有更新代); 失败返回相应 NTSTATUS。
 */
NTSTATUS
PsCreateWkdProcess(
    _Inout_ PWKD_EVENT_HEADER Event,
    _Out_ PWKD_PROCESS* WkdProcess
    );

NTSTATUS
PsHandleProcessExit(
    _Inout_ PWKD_PROCESS_TREE Tree,
    _In_    GUID               NodeId,
    _In_    LARGE_INTEGER      ExitTime
    );

PWKD_PROCESS
PtTreeLookupByNodeId(
    _In_ PWKD_PROCESS_TREE Tree,
    _In_ GUID               NodeId
    );

NTSTATUS
PsLookupWkdProcessByStrictProcessId(
    _In_opt_ PWKD_PROCESS_TREE Tree,
    _In_ HANDLE ProcessId,
    _In_opt_ PLARGE_INTEGER CreateTime,
    _Outptr_ PWKD_PROCESS* WkdProcess
    );

/*
 * 按 PID 查找进程节点 (只查不建, 2026-08-24 重构)。
 * 命中返回节点指针 (STATUS_SUCCESS); 未命中返回 STATUS_NOT_FOUND。
 * 占位机制已移除: 实体创建收口于分发层 (ProcessCreate 经 PsCreateWkdProcess
 * 完整建节点; 其它事件端点要求真实节点已由既往 ProcessCreate 建立)。
 */
NTSTATUS
PsLookupWkdProcessByProcessId(
    _In_opt_ PWKD_PROCESS_TREE Tree,
    _In_ HANDLE ProcessId,
    _Outptr_ PWKD_PROCESS* WkdProcess
    );

/*
 * 引用计数 (2026-08-24 重构, 对齐 driver 范式)。
 * 节点成功纳入 PidMap 时由 PsInsertProcessTreeEntity / PtTreeUpsertSnapshot
 * 显式设 RefCount=1 (树基础引用); pair 双向关联时 PsReferenceWkdProcess(+1),
 * 释放时 PsDereferenceWkdProcess(-1); 归零即释放节点。
 * 注意: 基础引用须由上述两处建链点设立, 调用方不得对 PsInsertProcessTreeEntity
 * 出参 *Parent 做 Dereference (出参为借出, 非拥有)。
 */
LONG
PsReferenceWkdProcess(
    _Inout_ PWKD_PROCESS WkdProcess
    );

LONG
PsDereferenceWkdProcess(
    _Inout_ PWKD_PROCESS WkdProcess
    );

/**************************************************/
/*         快照兜底 API (步骤4 收编进程表)          */
/*                                                  */
/*  快照节点语义: GUID=零、NodeSource=Snapshot、     */
/*  不持久化、不产 IOA 事件。驱动事件到达同 PID 时   */
/*  按 CreateTime 新者胜出: 快照副本被既有/新 Driver */
/*  节点取代并释放 (PsInsertProcessTreeEntity)。     */
/**************************************************/

/* 差集删除回调（快照节点消失时通知，如 IpeRecordProcessExit） */
typedef VOID (*PT_SNAPSHOT_EXIT_CB)(
    _In_ ULONG    Pid,
    _In_ PCWSTR   ImageFileName
    );

NTSTATUS
PtTreeUpsertSnapshot(
    _Inout_ PWKD_PROCESS_TREE Tree,
    _In_    PWKD_PROCESS       SnapshotNode
    );

VOID
PtTreeReconcileSnapshot(
    _Inout_ PWKD_PROCESS_TREE Tree,
    _In_    PULONG             LivePids,
    _In_    ULONG              PidCount,
    _In_opt_ PT_SNAPSHOT_EXIT_CB ExitCb
    );
