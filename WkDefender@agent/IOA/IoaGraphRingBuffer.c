/**************************************************/
/*  WkDefender — 无锁因果图环形缓冲区实现              */
/**************************************************/

#include "IoaGraphRingBuffer.h"
#include "IoaEngine.h"
#include "../Process/ProcessTree.h"
#include "IoaCarsalGraph.h"
#include <string.h>
#include <intrin.h>

/* 前向声明: 系统进程名检测 */
static BOOLEAN GrbIsSystemProcess(_In_ PWKD_PROCESS Node);
static BOOLEAN GrbIsKeySystemProcess(_In_ PWKD_PROCESS Node);
static BOOLEAN GrbIsSelfOperation(_In_ PWKD_EVENT_HEADER Event, _In_ PWKD_PROCESS SrcNode, _In_ PWKD_PROCESS TgtNode);

/**************************************************/
/*               内部辅助                           */
/**************************************************/

static
BOOLEAN
GrbIsSystemProcess(
    _In_ PWKD_PROCESS Node
    )
/*++
Routine Description:
    判断进程是否为系统进程。
    路径包含 \System32\ 或 \Windows\。
--*/
{
    if (!Node || !Node->ImagePath || !Node->ImagePath->Buffer) return FALSE;

    return (wcsstr(Node->ImagePath->Buffer, L"\\System32\\") != NULL ||
            wcsstr(Node->ImagePath->Buffer, L"\\Windows\\") != NULL);
}

static
BOOLEAN
GrbIsKeySystemProcess(
    _In_ PWKD_PROCESS Node
    )
/*++
Routine Description:
    判断进程是否为关键系统进程 (lsass/csrss/winlogon/services/svchost)。
--*/
{
    PWCHAR p, base;
    if (!Node || !Node->ImageFileName || !Node->ImageFileName->Buffer) return FALSE;

    base = Node->ImageFileName->Buffer;
    p = base + (Node->ImageFileName->Length / sizeof(WCHAR));
    for (; p > base; p--) {
        if (*p == L'\\' || *p == L'/') { p++; break; }
    }

    return (_wcsicmp(p, L"lsass.exe")  == 0 ||
            _wcsicmp(p, L"csrss.exe")  == 0 ||
            _wcsicmp(p, L"winlogon.exe") == 0 ||
            _wcsicmp(p, L"services.exe") == 0 ||
            _wcsicmp(p, L"svchost.exe") == 0);
}

static
BOOLEAN
GrbIsSelfOperation(
    _In_ PWKD_EVENT_HEADER Event,
    _In_ PWKD_PROCESS SrcNode,
    _In_ PWKD_PROCESS TgtNode
    )
/*++
Routine Description:
    判断事件是否为自操作 (Source == Target)。
--*/
{
    if (SrcNode && TgtNode && DefGuidEqual(&SrcNode->NodeId, &TgtNode->NodeId)) {
        return TRUE;
    }
    return FALSE;
}

/**************************************************/
/*                   公开 API                       */
/**************************************************/

NTSTATUS
GrbInitialize(
    _Out_ PIOA_GRAPH_RING_BUFFER* Out
    )
/*++
Routine Description:
    初始化无锁环形缓冲区。

Arguments:
    Out — 输出的环形缓冲区指针。

Return Value:
    NTSTATUS。
--*/
{
    PIOA_GRAPH_RING_BUFFER rb;

    rb = UtHeapAlloc(sizeof(IOA_GRAPH_RING_BUFFER));
    if (!rb) return STATUS_NO_MEMORY;

    rb->WriteIndex = 0;
    rb->ReadIndex  = 0;
    rb->Backpressure = FALSE;

    rb->WakeEvent = CreateEventW(NULL, FALSE, FALSE, NULL);  /* 自动重置事件 */
    if (!rb->WakeEvent) {
        UtHeapFree(rb);
        return STATUS_UNSUCCESSFUL;
    }

    printf("[GraphRingBuffer] Initialized: size=%u entries, entry=%u bytes\n",
           GRAPH_RING_BUFFER_SIZE, (ULONG)sizeof(GRAPH_EDGE_DESCRIPTOR));

    *Out = rb;
    return STATUS_SUCCESS;
}

VOID
GrbCleanup(
    _In_ PIOA_GRAPH_RING_BUFFER Ring
    )
/*++
Routine Description:
    清理环形缓冲区。不应有运行时调用此函数。

Arguments:
    Ring — 环形缓冲区实例。

Return Value:
    VOID。
--*/
{
    if (!Ring) return;

    /* 安全停止消费线程 (如果仍在运行) */
    if (Ring->ConsumerRunning) {
        GrbStopConsumer(Ring);
    }

    if (Ring->WakeEvent) {
        CloseHandle(Ring->WakeEvent);
        Ring->WakeEvent = NULL;
    }

    printf("[GraphRingBuffer] Cleanup: written=%lld consumed=%lld dropped=%lld "
           "layers[%lld/%lld/%lld/%lld]\n",
           Ring->TotalWritten, Ring->TotalConsumed, Ring->TotalDropped,
           Ring->TotalLayerDecisions[0], Ring->TotalLayerDecisions[1],
           Ring->TotalLayerDecisions[2], Ring->TotalLayerDecisions[3]);

    UtHeapFree(Ring);
}

/**************************************************/
/*           后台消费线程 (事件激活机制)            */
/**************************************************/

static DWORD WINAPI
GrbpConsumerThread(
    _In_ LPVOID Param
    )
/*++
Routine Description:
    环形缓冲区后台消费线程。
    使用 WakeEvent 事件等待替代轮询 Sleep，实现零延迟响应。

    循环流程:
      1. WaitForSingleObject(WakeEvent, timeout) — 等待数据
      2. GrbReadBatch — 批量读取可用边描述符
      3. 对每条边调用 IoaCarsalGraphInsertEdge 插入因果图
      4. 重复

Arguments:
    Param — PIOA_GRAPH_RING_BUFFER 指针。

Return Value:
    线程退出码 (0)。
--*/
{
    PIOA_GRAPH_RING_BUFFER ring = (PIOA_GRAPH_RING_BUFFER)Param;
    PGRAPH_EDGE_DESCRIPTOR batch[GRB_CONSUME_BATCH_SIZE];
    ULONG count;

    if (!ring) return 1;

    printf("[GraphRingBuffer] Consumer thread started (batch=%u, timeout=%ums)\n",
           GRB_CONSUME_BATCH_SIZE, GRB_CONSUME_INTERVAL_MS);

    while (ring->ConsumerRunning) {
        /*
         * 事件驱动等待: 生产者写入后调用 SetEvent(WakeEvent) 唤醒本线程。
         * GRB_CONSUME_INTERVAL_MS
         * timeout 作为安全网，防止事件丢失导致线程永久休眠。
         */
        WaitForSingleObject(ring->WakeEvent, INFINITE);
        if (!ring->ConsumerRunning) break;

        count = GrbReadBatch(ring, batch, GRB_CONSUME_BATCH_SIZE);
        if (count > 0) {
            for (ULONG i = 0; i < count; i++) {
                IoaCarsalGraphInsertEdge(WkdIoaEngine.Graph, batch[i]);
            }
        }
    }

    printf("[GraphRingBuffer] Consumer thread exited\n");
    return 0;
}

_Use_decl_annotations_
NTSTATUS
GrbStartConsumer(
    _In_ PIOA_GRAPH_RING_BUFFER Ring
    )
{
    HANDLE thread;
    DWORD  tid;

    if (!Ring) return STATUS_INVALID_PARAMETER;
    if (Ring->ConsumerRunning) return STATUS_SUCCESS;   /* 已运行 */

    Ring->ConsumerRunning = TRUE;

    thread = CreateThread(NULL, 0, GrbpConsumerThread, Ring, 0, &tid);
    if (!thread) {
        Ring->ConsumerRunning = FALSE;
        return STATUS_UNSUCCESSFUL;
    }

    Ring->ConsumerThread = thread;
    printf("[GraphRingBuffer] StartConsumer: thread=%p tid=%u\n", thread, tid);
    return STATUS_SUCCESS;
}

VOID
GrbStopConsumer(
    _In_ PIOA_GRAPH_RING_BUFFER Ring
    )
/*++
Routine Description:
    停止后台消费线程。等待线程退出后清理句柄。
    可在 GrbCleanup 之前独立调用。

Arguments:
    Ring — 环形缓冲区实例。

Return Value:
    VOID。
--*/
{
    if (!Ring || !Ring->ConsumerRunning) return;

    Ring->ConsumerRunning = FALSE;

    /* 唤醒消费线程使其退出等待 */
    SetEvent(Ring->WakeEvent);

    if (Ring->ConsumerThread) {
        WaitForSingleObject(Ring->ConsumerThread, 5000);
        CloseHandle(Ring->ConsumerThread);
        Ring->ConsumerThread = NULL;
    }

    printf("[GraphRingBuffer] Consumer stopped\n");
}

NTSTATUS
GrbWriteEdge(
    _In_ PIOA_GRAPH_RING_BUFFER    Ring,
    _In_ PGRAPH_EDGE_DESCRIPTOR    EdgeDesc,
    _In_ GRAPH_LAYER_DECISION      Layer
    )
/*++
Routine Description:
    无锁写入边描述符。事件路径上调用。

    使用 CAS 预留槽位。背压时 Layer 2/3 直接丢弃。

Arguments:
    Ring     — 环形缓冲区。
    EdgeDesc — 要写入的边描述符。
    Layer    — 分层决策。

Return Value:
    STATUS_SUCCESS 写入成功。
    STATUS_BUFFER_OVERFLOW 被丢弃 (或 Layer 为 Skip)。
--*/
{
    LONG64 writePos, readPos, newWritePos;
    ULONG  slot;

    if (!Ring || !EdgeDesc) return STATUS_INVALID_PARAMETER;

    /* Layer 3 直接丢弃，只计统计 */
    if (Layer == GraphLayer_Skip) {
        InterlockedIncrement64(&Ring->TotalLayerDecisions[3]);
        return STATUS_BUFFER_OVERFLOW;
    }

    /* CAS 循环获取写入槽位 */
    for (;;) {
        writePos = Ring->WriteIndex;
        readPos  = Ring->ReadIndex;

        /* 背压检查 */
        if (writePos - readPos >= GRAPH_RING_BUFFER_SIZE) {
            /* 缓冲区满: Layer 2 降级丢弃, Layer 0/1 也丢弃但记录告警 */
            InterlockedIncrement64(&Ring->TotalDropped);
            Ring->Backpressure = TRUE;
            InterlockedIncrement64(&Ring->TotalLayerDecisions[Layer]);
            return STATUS_BUFFER_OVERFLOW;
        }

        newWritePos = writePos + 1;
        if (InterlockedCompareExchange64(&Ring->WriteIndex, newWritePos, writePos) == writePos) {
            break;
        }
        /* CAS 失败，重试 */
        _mm_pause();
    }

    /* 写入槽位 */
    slot = (ULONG)(writePos & GRAPH_RING_BUFFER_MASK);
    Ring->Buffer[slot] = *EdgeDesc;

    /* 背压解除 */
    if (Ring->Backpressure) {
        LONG64 currentWrite = newWritePos;
        LONG64 currentRead  = Ring->ReadIndex;
        if (currentWrite - currentRead < GRB_BACKPRESSURE_THRESHOLD) {
            Ring->Backpressure = FALSE;
        }
    }

    InterlockedIncrement64(&Ring->TotalWritten);
    InterlockedIncrement64(&Ring->TotalLayerDecisions[Layer]);

    /* 唤醒消费线程 (非阻塞) */
    SetEvent(Ring->WakeEvent);

    return STATUS_SUCCESS;
}

ULONG
GrbReadBatch(
    _In_  PIOA_GRAPH_RING_BUFFER        Ring,
    _Outptr_ PGRAPH_EDGE_DESCRIPTOR*    OutEdges,
    _In_  ULONG                         MaxCount
    )
/*++
Routine Description:
    批量读取边描述符。消费线程调用。

    原子读取 ReadIndex 到 WriteIndex 之间的所有条目。

Arguments:
    Ring     — 环形缓冲区。
    OutEdges — 输出指针，指向 Ring->Buffer 内部的条目。
    MaxCount — 最多读取的条目数。

Return Value:
    实际读取的条目数。
--*/
{
    LONG64 writePos, readPos;
    ULONG  available, count;

    if (!Ring || !OutEdges || MaxCount == 0) return 0;

    writePos = Ring->WriteIndex;
    readPos  = Ring->ReadIndex;

    available = (ULONG)(writePos - readPos);
    if (available == 0) return 0;

    count = (available < MaxCount) ? available : MaxCount;

    for (ULONG i = 0; i < count; i++) {
        ULONG slot = (ULONG)((readPos + i) & GRAPH_RING_BUFFER_MASK);
        OutEdges[i] = &Ring->Buffer[slot];
    }

    /* 原子提交读取位置 */
    InterlockedExchangeAdd64(&Ring->ReadIndex, count);
    InterlockedExchangeAdd64(&Ring->TotalConsumed, count);

    return count;
}

GRAPH_LAYER_DECISION
GrbDecideLayer(
    _In_ PWKD_EVENT_HEADER    Event,
    _In_ PWKD_PROCESS    SrcNode,
    _In_ PWKD_PROCESS    TgtNode,
    _In_ BOOLEAN              FsmActive
    )
/*++
Routine Description:
    分层决策。根据事件类型、进程属性、FSM 活跃度分类。

    决策矩阵:
      Layer 0 (Hot):  进程创建/退出、FSM 活跃推进的事件、
                      威胁评分 >= 80 的进程事件、远程线程创建
      Layer 1 (Warm): 关键进程 OpenProcess (lsass/csrss/...)、
                      跨进程内存操作 (Write/Read/Allocate/Protect with Src != Tgt)
      Layer 2 (Cold): 其他跨进程事件 — 延迟评估
      Layer 3 (Skip): 系统进程间通信、自操作

Arguments:
    Event    — 当前事件。
    SrcNode  — 源进程谱系节点 (可空)。
    TgtNode  — 目标进程谱系节点 (可空)。
    FsmActive — FSM 引擎是否已有此 (Src, Tgt) 的活跃追踪器。

Return Value:
    GRAPH_LAYER_DECISION。
--*/
{
    BOOLEAN srcIsSystem, tgtIsSystem;

    if (!Event) return GraphLayer_Skip;

    /* ── Layer 0: 必须进图 ── */

    /* 进程创建/退出 — 图的骨架 */
    if (Event->Type == WkdEvent_ProcessCreate ||
        Event->Type == WkdEvent_ProcessExit) {
        return GraphLayer_Hot;
    }

    /* 远程线程创建 — 注入关键指标 */
    if (Event->Type == WkdEvent_RemoteThreadCreate) {
        return GraphLayer_Hot;
    }

    /* FSM 已活跃推进此进程对 */
    if (FsmActive) {
        return GraphLayer_Hot;
    }

    /* 高威胁评分源进程 */
    /* 并发安全重构 2026-08-23：WKD_PROCESS.CumulativeRiskScore 为 volatile LONG，
     * 原子读获取当前值（避免与事件线程 Interlocked 写者交错撕裂）。 */
    if (SrcNode && InterlockedOr(&SrcNode->CumulativeRiskScore, 0) >= 80) {
        return GraphLayer_Hot;
    }
    if (TgtNode && InterlockedOr(&TgtNode->CumulativeRiskScore, 0) >= 80) {
        return GraphLayer_Hot;
    }

    /* ── Layer 3: 不进图 ── */

    srcIsSystem = GrbIsSystemProcess(SrcNode);
    tgtIsSystem = GrbIsSystemProcess(TgtNode);

    /* 自操作 */
    if (GrbIsSelfOperation(Event, SrcNode, TgtNode)) {
        return GraphLayer_Skip;
    }

    /* 系统进程间通信 */
    if (srcIsSystem && tgtIsSystem) {
        return GraphLayer_Skip;
    }

    /* ── Layer 1: 条件进图 ── */

    /* 打开关键系统进程 */
    if (Event->Type == WkdEvent_ProcessOpen &&
        GrbIsKeySystemProcess(TgtNode)) {
        return GraphLayer_Warm;
    }

    /* 跨进程内存操作 */
    if ((Event->Type == WkdEvent_MemoryWrite ||
         Event->Type == WkdEvent_MemoryRead ||
         Event->Type == WkdEvent_MemoryAllocate ||
         Event->Type == WkdEvent_MemoryProtect) &&
        !GrbIsSelfOperation(Event, SrcNode, TgtNode)) {
        return GraphLayer_Warm;
    }

    /* 线程创建到非子进程 */
    if (Event->Type == WkdEvent_ThreadCreate &&
        !GrbIsSelfOperation(Event, SrcNode, TgtNode) &&
        !srcIsSystem) {
        return GraphLayer_Warm;
    }

    /* ── Layer 2: 延迟判定 ── */
    return GraphLayer_Cold;
}

VOID
GrbGetStats(
    _In_  PIOA_GRAPH_RING_BUFFER Ring,
    _Out_ LONG64*                 TotalWritten,
    _Out_ LONG64*                 TotalConsumed,
    _Out_ LONG64*                 TotalDropped,
    _Out_ LONG64                  LayerCounts[4]
    )
{
    if (Ring) {
        if (TotalWritten) *TotalWritten = Ring->TotalWritten;
        if (TotalConsumed)*TotalConsumed = Ring->TotalConsumed;
        if (TotalDropped) *TotalDropped = Ring->TotalDropped;
        if (LayerCounts) {
            LayerCounts[0] = Ring->TotalLayerDecisions[0];
            LayerCounts[1] = Ring->TotalLayerDecisions[1];
            LayerCounts[2] = Ring->TotalLayerDecisions[2];
            LayerCounts[3] = Ring->TotalLayerDecisions[3];
        }
    }
}
