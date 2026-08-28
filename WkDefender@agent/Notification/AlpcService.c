/**************************************************/
/*  WkDefender Agent — 统一 ALPC 通信模块实现         */
/*  基于 cg_alpc.c 的 ALPC 基础设施，融合旧的        */
/*  RouteMessageHandler 分发机制                     */
/*  版本: 4.0.0                                     */
/**************************************************/

#include "AlpcService.h"

/**************************************************/
/*               全局实例                           */
/**************************************************/

WKD_ALPC_SERVER WkdDefaultAlpcServer = { 0 };

/**************************************************/
/*               端口名称配置表                     */
/**************************************************/

static const WCHAR* s_WkdAlpcPortNames[WkdAlpcConnectionMax] = {
    L"\\RPC Control\\WkDefender@UI",
    L"\\RPC Control\\WkDefender@Driver",
    L"\\RPC Control\\WkDefender@Helper"
};

/**************************************************/
/*               反向连接                           */
/**************************************************/

static NTSTATUS
WkdAlpcReverseConnect(
    _In_ PWKD_ALPC_SERVER     Server,
    _In_ WKD_ALPC_CONNECTION_TYPE    ConnType
    )
/*++
Routine Description:
    反向连接到指定类型的 ALPC 端口（Agent→Driver/UI/Helper）。

Arguments:
    Server   — ALPC 服务器实例。
    ConnType — 目标连接类型。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS        status;
    UNICODE_STRING  portName;
    HANDLE          portHandle;

    if (!Server || ConnType >= WkdAlpcConnectionMax) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&portName, s_WkdAlpcPortNames[ConnType]);

    status = NtAlpcConnectPort(
        &portHandle,
        &portName,
        NULL, NULL, 0,
        NULL,
        NULL, NULL, NULL, NULL, NULL
    );

    if (!NT_SUCCESS(status)) {
        printf("[WkdAlpc] Reverse connect to %S failed: 0x%X\n",
               s_WkdAlpcPortNames[ConnType], status);
        return status;
    }

    Server->OutboundPorts[ConnType] = portHandle;
    printf("[WkdAlpc] Reverse connected to %S\n", s_WkdAlpcPortNames[ConnType]);
    return STATUS_SUCCESS;
}

/**************************************************/
/*               共享节池管理                        */
/**************************************************/

static
PWKD_ALPC_SECTION_VIEW
AlpcpSectionPoolFindFree(
    _In_ PWKD_ALPC_SECTION_VIEW     Pool,
    _In_ SIZE_T                     MinSize
    )
/*++
Routine Description:
    在池中查找首个 Active && !Busy && ViewSize >= MinSize 的节。
    O(POOL_SIZE) 扫描，池规模小无需复杂数据结构。

Arguments:
    Pool    — 连接类型的池首地址。
    MinSize — 最小所需大小（字节）。

Return Value:
    匹配的空闲节指针，无匹配则 NULL。
--*/
{
    for (ULONG i = 0; i < WKD_ALPC_MAX_POOL_SIZE; i++) {
        if (Pool[i].Active && !Pool[i].Busy && Pool[i].ViewAttr.ViewSize >= MinSize) {
            return &Pool[i];
        }
    }
    return NULL;
}

static
PWKD_ALPC_SECTION_VIEW
AlpcpSectionPoolFindLruVictim(
    _In_ PWKD_ALPC_SECTION_VIEW     Pool
    )
/*++
Routine Description:
    在池中查找 Active && !Busy 中最旧的节作为 LRU 淘汰候选。
    O(POOL_SIZE) 扫描。

Arguments:
    Pool — 连接类型的池首地址。

Return Value:
    指向 LRU victim 的指针，全部 Busy 时返回 NULL。
--*/
{
    PWKD_ALPC_SECTION_VIEW victim = NULL;

    for (ULONG i = 0; i < WKD_ALPC_MAX_POOL_SIZE; i++) {
        if (!Pool[i].Active || Pool[i].Busy) {
            continue;
        }
        if (!victim || Pool[i].LastUsedTime.QuadPart < victim->LastUsedTime.QuadPart) {
            victim = &Pool[i];
        }
    }
    return victim;
}


static
NTSTATUS
AlpcpSectionViewCreate(
    _In_    PWKD_ALPC_SERVER            Server,
    _In_    WKD_ALPC_CONNECTION_TYPE    ConnType,
    _In_    SIZE_T                      Size,
    _Out_   PWKD_ALPC_SECTION_VIEW      Section
    )
/*++
Routine Description:
    底层创建单个共享节：NtAlpcCreatePortSection → NtAlpcCreateSectionView。
    填充 Section->ViewAttr 和 Section->Active，Section->Busy 由调用方设置。

Arguments:
    Server   — ALPC 服务器实例。
    ConnType — 目标连接类型。
    Size     — 请求的共享节大小。
    Section  — 指向目标槽位，创建成功后填充。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS                    status;
    SIZE_T                      msgAttrSize;
    PALPC_MSG_ATTRIBUTES        msgAttr;
    PALPC_DATA_VIEW_ATTR        viewAttr = NULL;

    if (!Server || ConnType >= WkdAlpcConnectionMax || !Section) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Server->OutboundPorts[ConnType]) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* 初始化消息属性 */
    AlpcInitializeMessageAttribute(WKD_ALPC_MESSAGE_VIEW_ATTR, NULL, 0, &msgAttrSize);
    msgAttr = (PALPC_MSG_ATTRIBUTES)UtHeapAlloc(msgAttrSize);
    if (!msgAttr) {
        return STATUS_NO_MEMORY;
    }

    AlpcInitializeMessageAttribute(WKD_ALPC_MESSAGE_VIEW_ATTR, msgAttr, msgAttrSize, &msgAttrSize);
    viewAttr = (PALPC_DATA_VIEW_ATTR)
        AlpcGetMessageAttribute(msgAttr, WKD_ALPC_MESSAGE_VIEW_ATTR);

    /* 创建 Port Section */
    status = NtAlpcCreatePortSection(
        Server->OutboundPorts[ConnType],
        0, NULL, Size,
        &viewAttr->SectionHandle,
        &viewAttr->ViewSize
    );
    if (!NT_SUCCESS(status)) {
        printf("[WkdAlpc] CreatePortSection failed: 0x%X\n", status);
        UtHeapFree(msgAttr);
        return status;
    }

    /* 创建共享视图 */
    status = NtAlpcCreateSectionView(
        Server->OutboundPorts[ConnType],
        0, viewAttr
    );
    if (!NT_SUCCESS(status)) {
        printf("[WkdAlpc] CreateSectionView failed: 0x%X\n", status);
        UtHeapFree(msgAttr);
        return status;
    }

    /* 填充 section 缓存 */
    Section->Active = TRUE;
    Section->Busy = FALSE;
    RtlCopyMemory(&Section->ViewAttr, viewAttr, sizeof(ALPC_DATA_VIEW_ATTR));
    GetSystemTimeAsFileTime((PFILETIME)&Section->LastUsedTime);
    Section->AllocCount = 0;
    UtHeapFree(msgAttr);

    printf("[WkdAlpc] Section created: conn=%d, base=0x%p, size=%zu\n",
           ConnType, viewAttr->ViewBase, viewAttr->ViewSize);

    return STATUS_SUCCESS;
}

static
NTSTATUS
AlpcpSectionViewDestroy(
    _Inout_ PWKD_ALPC_SERVER            Server,
    _In_    WKD_ALPC_CONNECTION_TYPE    ConnType,
    _Inout_ PWKD_ALPC_SECTION_VIEW      Section
    )
/*++
Routine Description:
    底层销毁单个共享节：NtAlpcDeleteSectionView → NtAlpcDeletePortSection。
    销毁后设置 Section->Active = FALSE。

Arguments:
    Server   — ALPC 服务器实例。
    ConnType — 目标连接类型。
    Section  — 要销毁的节槽位。
--*/
{
    NTSTATUS status;

    printf("[WkdAlpc] Destroying SectionView: base=0x%p, size=%zu\n",
           Section->ViewAttr.ViewBase,
           Section->ViewAttr.ViewSize);

    status = NtAlpcDeleteSectionView(Server->OutboundPorts[ConnType], 0,
        Section->ViewAttr.ViewBase);
    if (!NT_SUCCESS(status)) {
        printf("[WkdAlpc] DeleteSectionView failed: 0x%X\n", status);
        /* 继续尝试删除 PortSection */
        return STATUS_UNSUCCESSFUL;
    }

    status = NtAlpcDeletePortSection(Server->OutboundPorts[ConnType], 0,
        Section->ViewAttr.SectionHandle);
    if (!NT_SUCCESS(status)) {
        printf("[WkdAlpc] DeletePortSection failed: 0x%X\n", status);
        /* 非致命，Section View 已删除 */
        return STATUS_UNSUCCESSFUL;
    }

    Section->Active = FALSE;
    Section->Busy = FALSE;

    return STATUS_SUCCESS;
}

NTSTATUS
AlpcpSectionPoolAcquire(
    _Inout_ PWKD_ALPC_SERVER            Server,
    _In_    WKD_ALPC_CONNECTION_TYPE    ConnType,
    _In_    SIZE_T                      RequiredSize,
    _Out_   PWKD_ALPC_SECTION_VIEW      *Section
    )
/*++
Routine Description:
    从池中分配共享节。四阶段分配：
      阶段1 — 查找匹配的空闲节（Active && !Busy && ViewSize >= RequiredSize）
      阶段2 — LRU 淘汰重建（无匹配时选最旧空闲节销毁后重建）
      阶段3 — 填空槽（无可淘汰节时使用未分配的槽位）
      阶段4 — 全部 Busy，返回 STATUS_INSUFFICIENT_RESOURCES

    分配成功后标记 Busy = TRUE 并刷新 LastUsedTime。

Arguments:
    Server       — ALPC 服务器实例。
    ConnType     — 目标连接类型。
    RequiredSize — 最小所需大小（字节）。
    Section      — 输出，指向分配到的节。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;
    PWKD_ALPC_SECTION_VIEW pool;
    
    if (!Server || ConnType >= WkdAlpcConnectionMax || !Section) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Server->OutboundPorts[ConnType]) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    pool = Server->SectionPool[ConnType];
    *Section = NULL;

    /* --- 阶段1: 精确匹配 --- */
    {
        PWKD_ALPC_SECTION_VIEW result;

        result = AlpcpSectionPoolFindFree(pool, RequiredSize);
        if (result) {
            result->Busy = TRUE;
            GetSystemTimeAsFileTime((PFILETIME)&result->LastUsedTime);
            result->AllocCount++;
            *Section = result;

            printf("[WkdAlpc] Pool hit: conn=%d, base=0x%p, count=%lu\n",
                ConnType, result->ViewAttr.ViewBase, result->AllocCount);
            return STATUS_SUCCESS;
        }
    }

    /* --- 阶段2: LRU 淘汰重建 --- */
    {
        PWKD_ALPC_SECTION_VIEW victim;

        victim = AlpcpSectionPoolFindLruVictim(pool);
        if (victim) {
            printf("[WkdAlpc] LRU evict: conn=%d, base=0x%p, size=%zu→%zu\n",
                ConnType, victim->ViewAttr.ViewBase,
                victim->ViewAttr.ViewSize, RequiredSize);

            status = AlpcpSectionViewDestroy(Server, ConnType, victim);
            if (!NT_SUCCESS(status)) {
                printf("[WkdAlpc] LRU destroy failed: 0x%X\n", status);
                return status;
            }

            status = AlpcpSectionViewCreate(Server, ConnType, RequiredSize, victim);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            victim->Busy = TRUE;
            victim->AllocCount = 1;
            *Section = victim;
            return STATUS_SUCCESS;
        }
    }

    /* --- 阶段3: 填空槽 --- */
    for (ULONG i = 0; i < WKD_ALPC_MAX_POOL_SIZE; i++) {
        if (!pool[i].Active) {
            printf("[WkdAlpc] Fill empty slot: conn=%d, slot=%lu\n", ConnType, i);

            status = AlpcpSectionViewCreate(Server, ConnType, RequiredSize, &pool[i]);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            pool[i].Busy = TRUE;
            pool[i].AllocCount = 1;
            *Section = &pool[i];
            return STATUS_SUCCESS;
        }
    }

    /* --- 阶段4: 池满全部 Busy --- */
    printf("[WkdAlpc] Pool exhausted: conn=%d, all %d slots in use\n",
           ConnType, WKD_ALPC_MAX_POOL_SIZE);
    return STATUS_INSUFFICIENT_RESOURCES;
}

VOID
AlpcpSectionPoolRelease(
    _Inout_ PWKD_ALPC_SECTION_VIEW  Section
    )
/*++
Routine Description:
    归还共享节到池。Busy = FALSE，刷新 LastUsedTime 供 LRU/TTL 使用。

Arguments:
    Section — 要归还的节槽位。
--*/
{
    if (!Section) {
        return;
    }
    Section->Busy = FALSE;
    GetSystemTimeAsFileTime((PFILETIME)&Section->LastUsedTime);
}

VOID
AlpcpSectionPoolCleanup(
    _Inout_ PWKD_ALPC_SERVER        Server,
    _In_    WKD_ALPC_CONNECTION_TYPE ConnType
    )
/*++
Routine Description:
    清理指定连接类型的整个共享节池。销毁所有 Active 的节。
    在服务停止或连接断开时调用。

Arguments:
    Server   — ALPC 服务器实例。
    ConnType — 目标连接类型。
--*/
{
    ULONG i;

    if (!Server || ConnType >= WkdAlpcConnectionMax) {
        return;
    }

    for (i = 0; i < WKD_ALPC_MAX_POOL_SIZE; i++) {
        if (Server->SectionPool[ConnType][i].Active) {
            AlpcpSectionViewDestroy(Server, ConnType,
                &Server->SectionPool[ConnType][i]);
        }
    }
    printf("[WkdAlpc] Section pool cleaned up: conn=%d\n", ConnType);
}

static
VOID
AlpcpSectionPoolCheckTtl(
    _In_ PWKD_ALPC_SERVER Server
    )
/*++
Routine Description:
    检查共享节池中所有空闲节的 TTL，超时则销毁。
    Worker 线程每轮循环调用。
    跳过 Busy 的节（正在传输中）。

Arguments:
    Server — ALPC 服务器实例。
--*/
{
    FILETIME now;
    LONGLONG elapsedMs;

    GetSystemTimeAsFileTime(&now);

    for (ULONG i = 0; i < WkdAlpcConnectionMax; i++) {
        for (ULONG j = 0; j < WKD_ALPC_MAX_POOL_SIZE; j++) {
            PWKD_ALPC_SECTION_VIEW s = &Server->SectionPool[i][j];

            if (!s->Active || s->Busy) {
                continue;
            }

            elapsedMs = (now.dwLowDateTime - s->LastUsedTime.LowPart) / 10000 +
                        (now.dwHighDateTime - s->LastUsedTime.HighPart) *
                        (0xFFFFFFFF / 10000 + 1);

            if (elapsedMs > WKD_ALPC_SECTION_TTL_MS) {
                printf("[WkdAlpc] TTL expired: conn=%d, slot=%lu, idle=%lldms\n",
                       i, j, elapsedMs);
                AlpcpSectionViewDestroy(Server, i, s);
            }
        }
    }
}

/**************************************************/
/*          紧急消息判断与处理                      */
/**************************************************/
FORCEINLINE
static
BOOLEAN
AlpcpIsEmergencyMessage(
    _In_ WKD_ALPC_MESSAGE_TYPE MsgType
    )
/*++
Routine Description:
    判断消息类型是否为紧急控制消息。
    紧急消息直接在 Worker 线程内联处理，不入业务消息队列。

Arguments:
    MsgType — ALPC 消息类型。

Return Value:
    TRUE  = 紧急消息，需内联处理。
    FALSE = 普通消息，走路由表。
--*/
{
    switch (MsgType) {
    case WkdAlpcMessage_SectionViewRequest:
        return TRUE;
    default:
        return FALSE;
    }
}

static
NTSTATUS
AlpcpNotifySectionViewReady(
    _In_ PWKD_ALPC_SERVER               Server,
    _In_ WKD_ALPC_CONNECTION_TYPE       ConnType,
    _In_ PWKD_ALPC_SECTION_VIEW         Section,
    _In_ PWKD_ALPC_SECTION_VIEW_PAYLOAD Payload
    )
/*++
Routine Description:
    向指定连接类型发送 SectionViewReady 回复消息。
    消息数据域携带 SlotIndex（ULONG），消息属性携带 ALPC_MESSAGE_VIEW_ATTRIBUTE，
    ALPC 内核自动在对端（Driver）地址空间中创建共享节视图映射。

Arguments:
    Server    — ALPC 服务器实例。
    ConnType  — 目标连接类型。
    Section   — 已分配的共享节（从池中获取）。
    SlotIndex — 池中的槽位索引（Driver 凭此归还节）。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS                    status;
    SIZE_T                      msgSize;
    PWKD_ALPC_MESSAGE           replyMsg;
    PALPC_MSG_ATTRIBUTES        msgAttr;

    if (!Server || ConnType >= WkdAlpcConnectionMax || !Section) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Server->OutboundPorts[ConnType]) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* 消息体 = WKD_ALPC_MESSAGE + SlotIndex(ULONG) */
    msgSize = sizeof(WKD_ALPC_MESSAGE) + sizeof(WKD_ALPC_SECTION_VIEW_PAYLOAD);
    replyMsg = (PWKD_ALPC_MESSAGE)UtHeapAlloc(msgSize);
    if (!replyMsg) {
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(replyMsg, msgSize);
    replyMsg->Header.u1.s1.DataLength = (USHORT)(msgSize - sizeof(PORT_MESSAGE));
    replyMsg->Header.u1.s1.TotalLength = (USHORT)msgSize;
    replyMsg->ConnectionType = WkdAlpcConnectionAgent;
    replyMsg->MessageType = WkdAlpcMessage_SectionViewReady;
    replyMsg->Flags.Response = TRUE;
    replyMsg->ItemCount = 0;

    /* 填充 SlotIndex 到数据域 */
    RtlCopyMemory((PUCHAR)(replyMsg + 1), Payload, sizeof(WKD_ALPC_SECTION_VIEW_PAYLOAD));

    /* 构造 SendMessageAttributes，携带 ALPC_MESSAGE_VIEW_ATTRIBUTE */
    {
        SIZE_T                  msgAttrSize;
        PALPC_DATA_VIEW_ATTR    viewAttr;

        AlpcInitializeMessageAttribute(WKD_ALPC_MESSAGE_VIEW_ATTR, NULL, 0, &msgAttrSize);
        msgAttr = (PALPC_MSG_ATTRIBUTES)UtHeapAlloc(msgAttrSize);
        if (!msgAttr) {
            UtHeapFree(replyMsg);
            return STATUS_NO_MEMORY;
        }
        AlpcInitializeMessageAttribute(WKD_ALPC_MESSAGE_VIEW_ATTR, msgAttr, msgAttrSize, &msgAttrSize);

        viewAttr = (PALPC_DATA_VIEW_ATTR)
            AlpcGetMessageAttribute(msgAttr, WKD_ALPC_MESSAGE_VIEW_ATTR);
        RtlCopyMemory(viewAttr, &Section->ViewAttr, sizeof(ALPC_DATA_VIEW_ATTR));
        msgAttr->ValidAttributes = WKD_ALPC_MESSAGE_VIEW_ATTR;
    }

    status = AlpcSendMessageAsync(Server, ConnType, replyMsg, 0, msgAttr);
    if (!NT_SUCCESS(status)) {
        printf("[WkdAlpc] Send SectionReady failed: 0x%X\n", status);
    }

    UtHeapFree(msgAttr);
    UtHeapFree(replyMsg);

    return status;
}

static
NTSTATUS
AlpcpHandleEmergencyMessage(
    _In_ PWKD_ALPC_SERVER       Server,
    _In_ PWKD_ALPC_MESSAGE      RecvMsg
    )
/*++
Routine Description:
    处理紧急控制消息（仅 SectionViewRequest 共享节分配协商）。
    共享节数据提取已移至 AlpcpUnpackMessage 路径 B。

    所有紧急消息在 Worker 线程中同步处理，不入业务消息队列。

Arguments:
    Server  — ALPC 服务器实例。
    RecvMsg — 收到的 ALPC 消息。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS    status;

    switch (RecvMsg->MessageType) {
    case WkdAlpcMessage_SectionViewRequest: {
        PWKD_ALPC_SECTION_VIEW          allocatedSection;
        PWKD_ALPC_SECTION_VIEW_PAYLOAD  payload;

        if (RecvMsg->Header.u1.s1.TotalLength !=
            sizeof(WKD_ALPC_MESSAGE) + sizeof(WKD_ALPC_SECTION_VIEW_PAYLOAD)) {
            printf("[WkdAlpc] Invalid RequestSection message (too short)\n");
            return STATUS_INVALID_PARAMETER;
        }

        payload = (PWKD_ALPC_SECTION_VIEW_PAYLOAD)(RecvMsg + 1);
        printf("[WkdAlpc] RequestSectionView: size=%u\n", payload->DataSize);

        status = AlpcpSectionPoolAcquire(Server, RecvMsg->ConnectionType,
            payload->DataSize, &allocatedSection);
        if (!NT_SUCCESS(status)) {
            printf("[WkdAlpc] AlpcpSectionPoolAcquire failed: 0x%X\n", status);
            return status;
        }

        /* 指针运算：计算出该节在池中的槽位索引 */
        payload->SlotIndex =
            (ULONG)(allocatedSection - Server->SectionPool[RecvMsg->ConnectionType]);
        
        status = AlpcpNotifySectionViewReady(Server, RecvMsg->ConnectionType,
                                    allocatedSection, payload);
        if (!NT_SUCCESS(status)) {
            printf("[WkdAlpc] AlpcpNotifySectionViewReady failed: 0x%X\n", status);
            return status;
        }
        
        return STATUS_SUCCESS;
    }

    default:
        printf("[WkdAlpc] Unknown emergency message type: 0x%X\n", RecvMsg->MessageType);
        return STATUS_NOT_FOUND;
    }
}

/**************************************************/
/*      ALPC → WKD_MESSAGE[] 解包层（v5.1）         */
/*      支持单条和批量 WKD_MESSAGE 解包             */
/**************************************************/

static
NTSTATUS
AlpcpUnpackWkdAlpcMessage(
    _In_  PWKD_ALPC_SERVER      Server,
    _In_  PWKD_ALPC_MESSAGE     AlpcMsg,
    _Outptr_ PWKD_MESSAGE       **WkdMsgs,
    _Out_ PULONG                MsgCount
    )
/*++
Routine Description:
    将 ALPC 消息解包为多个堆上分配的 WKD_MESSAGE。
    根据 AlpcMsg->ItemCount 确定数据区中连续存放了多少条 WKD_MESSAGE，
    逐条校验 Magic 并堆拷贝。子系统只看到 PWKD_MESSAGE，完全屏蔽 ALPC 细节。

    两条路径：
      A. 普通消息 (UseSectionView=0):
            数据区直接包含 ItemCount × [WKD_MESSAGE]。
      B. 共享节消息 (UseSectionView=1):
            从共享节读取数据，格式同路径 A。

Arguments:
    Server    — ALPC 服务器实例（访问共享节池）。
    AlpcMsg   — 收到的 ALPC 消息。
    WkdMsgs   — 输出 PWKD_MESSAGE 指针数组（HeapAlloc，调用者释放）。
    MsgCount  — 输出消息数量。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG itemCount;
    PWKD_MESSAGE* msgArray = NULL;
    PUCHAR dataBase;
    ULONG dataLen;
    PWKD_ALPC_SECTION_VIEW sectionToRelease = NULL;

    if (!Server || !AlpcMsg || !WkdMsgs || !MsgCount) {
        return STATUS_INVALID_PARAMETER;
    }
    *WkdMsgs = NULL;
    *MsgCount = 0;

    itemCount = AlpcMsg->ItemCount;
    if (itemCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    /* ================================================================ */
    /* 路径 B: 共享节消息                                                */
    /* ================================================================ */
    if (AlpcMsg->Flags.UseSectionView) {
        PWKD_ALPC_SECTION_VIEW_PAYLOAD  payload;
        ULONG                           agentSlotIndex;
        PWKD_ALPC_SECTION_VIEW          section;

        if (AlpcMsg->Header.u1.s1.TotalLength !=
            sizeof(WKD_ALPC_SECTION_VIEW_PAYLOAD) + sizeof(WKD_ALPC_MESSAGE)) {
            printf("[WkdAlpc] Unpack: ALPC message error\n");
            return STATUS_INVALID_PARAMETER;
        }

        payload = (PWKD_ALPC_SECTION_VIEW_PAYLOAD)(AlpcMsg + 1);
        agentSlotIndex = payload->SlotIndex;

        if (agentSlotIndex >= WKD_ALPC_MAX_POOL_SIZE) {
            printf("[WkdAlpc] Unpack: Invalid AgentSlotIndex=%lu\n", agentSlotIndex);
            return STATUS_INVALID_PARAMETER;
        }

        section = &Server->SectionPool[AlpcMsg->ConnectionType][agentSlotIndex];

        if (!section->Active || !section->Busy || !section->ViewAttr.ViewBase) {
            printf("[WkdAlpc] Unpack: Section slot %lu not ready\n", agentSlotIndex);
            return STATUS_INVALID_DEVICE_STATE;
        }

        dataBase = (PUCHAR)section->ViewAttr.ViewBase;
        dataLen = payload->DataSize;
        sectionToRelease = section;
    } else {
        /* ================================================================ */
        /* 路径 A: 普通消息                                                 */
        /* ================================================================ */
        dataBase = (PUCHAR)(AlpcMsg + 1);
        dataLen = AlpcMsg->Header.u1.s1.TotalLength - sizeof(WKD_ALPC_MESSAGE);
    }

    /* 分配结果数组 */
    msgArray = (PWKD_MESSAGE*)UtHeapAlloc(itemCount * sizeof(PWKD_MESSAGE));
    if (!msgArray) {
        if (sectionToRelease) AlpcpSectionPoolRelease(sectionToRelease);
        return STATUS_NO_MEMORY;
    }

    /* 逐条解包 WKD_MESSAGE */
    ULONG i;
    PUCHAR cursor = dataBase;
    for (i = 0; i < itemCount; i++) {
        PWKD_MESSAGE_HEADER hdr;
        ULONG totalSize;

        if ((ULONG)(cursor - dataBase) + sizeof(WKD_MESSAGE_HEADER) > dataLen) {
            printf("[WkdAlpc] Unpack: truncated at msg %lu\n", i);
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        hdr = (PWKD_MESSAGE_HEADER)cursor;

        if (hdr->Magic != WKD_NOTIFICATION_MAGIC) {
            printf("[WkdAlpc] Unpack: Bad magic 0x%X at msg %lu\n", hdr->Magic, i);
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        totalSize = sizeof(WKD_MESSAGE_HEADER) + hdr->BodySize;

        if ((ULONG)(cursor - dataBase) + totalSize > dataLen) {
            printf("[WkdAlpc] Unpack: body overflow at msg %lu\n", i);
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        msgArray[i] = (PWKD_MESSAGE)UtHeapAlloc(totalSize);
        if (!msgArray[i]) {
            status = STATUS_NO_MEMORY;
            break;
        }

        RtlCopyMemory(msgArray[i], cursor, totalSize);
        cursor += totalSize;
    }

    /* 归还共享节 */
    if (sectionToRelease) {
        AlpcpSectionPoolRelease(sectionToRelease);
    }

    if (!NT_SUCCESS(status)) {
        /* 清理已分配的消息 */
        for (ULONG j = 0; j < i; j++) {
            UtHeapFree(msgArray[j]);
        }
        UtHeapFree(msgArray);
        return status;
    }

    printf("[WkdAlpc] Unpack: %lu WKD_MESSAGE(s) from ALPC type=0x%X\n",
        itemCount, AlpcMsg->MessageType);

    *WkdMsgs = msgArray;
    *MsgCount = itemCount;
    return STATUS_SUCCESS;
}

static
VOID
AlpcpFreeMessage(
    _In_ PWKD_MESSAGE Message
    )
{
    if (Message) {
        UtHeapFree(Message);
    }
}

/**************************************************/
/*               连接处理                           */
/**************************************************/

static NTSTATUS
AlpcpHandleConnectionRequest(
    _In_ PWKD_ALPC_SERVER       Server,
    _In_ PWKD_ALPC_MESSAGE      RecvMsg
    )
/*++
Routine Description:
    处理 ALPC 连接请求。
    流程：NtAlpcAcceptConnectPort → 反向连接 → 记入 AcceptedPorts。

Arguments:
    Server  — ALPC 服务器实例。
    RecvMsg — 连接请求消息。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS                status;
    HANDLE                  tempPort;
    WKD_ALPC_CONNECTION_TYPE       connType;

    printf("[WkdAlpc] Connection request received\n");

    status = NtAlpcAcceptConnectPort(
        &tempPort,
        Server->ServerPort,
        0,
        NULL, NULL, NULL,
        (PPORT_MESSAGE)RecvMsg,
        NULL,
        TRUE
    );

    if (!NT_SUCCESS(status)) {
        printf("[WkdAlpc] AcceptConnectPort failed: 0x%X\n", status);
        return status;
    }

    connType = RecvMsg->ConnectionType;
    if (connType >= WkdAlpcConnectionMax) {
        printf("[WkdAlpc] Invalid connection type: %d\n", connType);
        NtAlpcDisconnectPort(tempPort, 0);
        return STATUS_INVALID_PARAMETER;
    }

    Server->AcceptedPorts[connType] = tempPort;
    printf("[WkdAlpc] Connection accepted: type=%d\n", connType);

    /* 反向连接 */
    status = WkdAlpcReverseConnect(Server, connType);
    if (!NT_SUCCESS(status)) {
        printf("[WkdAlpc] Warning: reverse connect type=%d failed: 0x%X\n",
               connType, status);
        /* 不致命，继续 */
    }

    return STATUS_SUCCESS;
}

static VOID
WkdAlpcHandleDisconnect(
    _In_ PWKD_ALPC_SERVER     Server,
    _In_ WKD_ALPC_CONNECTION_TYPE    ConnType
    )
/*++
Routine Description:
    处理连接断开事件。
    清理端口句柄和对应共享节。

Arguments:
    Server   — ALPC 服务器实例。
    ConnType — 断开连接的连接类型。
--*/
{
    printf("[WkdAlpc] Client disconnected: type=%d\n", ConnType);

    if (ConnType < WkdAlpcConnectionMax) {
        /* 销毁该连接的共享节池 */
        AlpcpSectionPoolCleanup(Server, ConnType);

        /* 清理端口句柄 */
        if (Server->AcceptedPorts[ConnType]) {
            Server->AcceptedPorts[ConnType] = NULL;
        }
        if (Server->OutboundPorts[ConnType]) {
            Server->OutboundPorts[ConnType] = NULL;
        }
    }
}

/**************************************************/
/*               消息路由                           */
/**************************************************/

static
NTSTATUS
AlpcpRouteMessage(
    _In_ PWKD_ALPC_SERVER           Server,
    _In_ WKD_ALPC_MESSAGE_TYPE      AlpcMsgType,
    _In_ PWKD_MESSAGE               WkdMsg
    )
/*++
Routine Description:
    按 ALPC 消息类型匹配路由表 → 调用子系统处理器。
    子系统只看到 PWKD_MESSAGE，完全屏蔽 ALPC 传输细节。
    路由匹配基于 WKD_ALPC_MESSAGE_TYPE（消息来源和意图），
    处理器内部再按 WKD_MESSAGE.Header.Type 做细粒度分发。

    注意：此函数在 Worker 线程中调用，handler 实现应快速返回。

Arguments:
    Server      — ALPC 服务器实例。
    AlpcMsgType — ALPC 消息类型（路由匹配依据）。
    WkdMsg      — 已解包的 WKD_MESSAGE（堆分配，调用者负责释放）。

Return Value:
    NTSTATUS。
--*/
{
    Server->TotalRecv++;

    /* 查路由表（MsgTypeStart/End 为 WKD_ALPC_MESSAGE_TYPE 数值） */
    for (ULONG i = 0; i < Server->RouteCount; i++) {
        PWKD_ALPC_MESSAGE_ROUTE route = &Server->RouteTable[i];

        if (AlpcMsgType >= route->MsgTypeStart && AlpcMsgType <= route->MsgTypeEnd) {
            if (route->Handler) {
                route->Handler(Server, WkdMsg, route->Context);
                Server->TotalRouted++;
                return STATUS_SUCCESS;
            }
        }
    }

    /* 未匹配任何路由 */
    Server->TotalDropped++;
    printf("[WkdAlpc] No route: ALPC type=0x%X (WKD type=0x%X)\n",
           AlpcMsgType, WkdMsg->Header.Type);
    return STATUS_NOT_FOUND;
}

/**************************************************/
/*               Worker 线程 (Reactor)              */
/**************************************************/

static 
DWORD WINAPI
AlpcpWorkerThread(
    _In_ LPVOID Param
    )
/*++
Routine Description:
    ALPC 服务器主工作线程（Reactor 模式）。
    循环接收消息 → 复制 → 路由入队 → 回到 recv（绝不阻塞在业务处理上）。
    每次循环末尾检查共享节 TTL。

Arguments:
    Param — 指向 WKD_ALPC_SERVER 的指针。

Return Value:
    线程退出码。
--*/
{
    PWKD_ALPC_SERVER    server = (PWKD_ALPC_SERVER)Param;
    PWKD_ALPC_MESSAGE   recvMsg;
    SIZE_T              recvSize = WKD_ALPC_MAX_MESSAGE_SUPPORTED;
    NTSTATUS            status;
    UCHAR               alpcType;

    recvMsg = (PWKD_ALPC_MESSAGE)UtHeapAlloc(recvSize);
    if (!recvMsg) {
        printf("[WkdAlpc] Failed to allocate recv buffer\n");
        return 1;
    }

    printf("[WkdAlpc] Worker thread started on: %S\n", server->PortName);

    while (server->Running) {

        status = NtAlpcSendWaitReceivePort(
            server->ServerPort,
            0,
            NULL, NULL,
            (PPORT_MESSAGE)recvMsg,
            &recvSize,
            NULL, NULL
        );

        if (!NT_SUCCESS(status)) {
            if (server->Running) {
                printf("[WkdAlpc] Receive failed: 0x%X\n", status);
            }
            DebugBreak();
            continue;
        }

        alpcType = (UCHAR)recvMsg->Header.u2.s2.Type;
        switch (alpcType) {
        case LPC_REQUEST:
            /* 紧急控制消息内联处理（仅 SectionViewRequest 分配协商） */
            if (AlpcpIsEmergencyMessage(recvMsg->MessageType)) {
                AlpcpHandleEmergencyMessage(server, recvMsg);
            }
            else {
                /* 业务消息：解包（含共享节数据提取）→ 逐条路由分发 */
                PWKD_MESSAGE* wkdMsgs;
                ULONG msgCount;
                status = AlpcpUnpackWkdAlpcMessage(server, recvMsg, &wkdMsgs, &msgCount);
                if (NT_SUCCESS(status)) {
                    for (ULONG mi = 0; mi < msgCount; mi++) {
                        AlpcpRouteMessage(server, recvMsg->MessageType, wkdMsgs[mi]);
                        AlpcpFreeMessage(wkdMsgs[mi]);
                    }
                    UtHeapFree(wkdMsgs);
                } else {
                    server->TotalDropped++;
                    printf("[WkdAlpc] Unpack failed: 0x%X\n", status);
                }
            }
            break;

        case LPC_CONNECTION_REQUEST:
            AlpcpHandleConnectionRequest(server, recvMsg);
            break;

        case LPC_PORT_CLOSED:
        case LPC_CLIENT_DIED: {
            /* 根据 ClientId 确定哪个连接断了 */
            /* 简单实现：遍历找到对应端口 */
            ULONG j;
            for (j = 0; j < WkdAlpcConnectionMax; j++) {
                if (server->AcceptedPorts[j]) {
                    /* TODO: 更精确地匹配 ClientId */
                }
            }
            printf("[WkdAlpc] Port closed / client died\n");
            break;
        }

        case LPC_DATAGRAM:
            /* 数据报不处理 */
            break;

        default:
            printf("[WkdAlpc] Unhandled LPC type: 0x%X\n", alpcType);
            break;
        }
    }

    /* 每轮检查共享节池 TTL */
    AlpcpSectionPoolCheckTtl(server);

    UtHeapFree(recvMsg);
    printf("[WkdAlpc] Worker thread exited (recv=%lld routed=%lld dropped=%lld)\n",
           server->TotalRecv, server->TotalRouted, server->TotalDropped);
    return 0;
}

/**************************************************/
/*                   公开 API                       */
/**************************************************/

NTSTATUS
AlpcCreateServer(
    _In_ PWKD_ALPC_SERVER   Server,
    _In_ LPCWSTR            PortName
    )
/*++
Routine Description:
    初始化 ALPC 服务器，创建监听端口。

Arguments:
    Server   — 未初始化的 ALPC 服务器结构体。
    PortName — ALPC 端口名称。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS                status;
    OBJECT_ATTRIBUTES       objAttr;
    UNICODE_STRING          portStr;
    ALPC_PORT_ATTRIBUTES    portAttr;

    if (!Server || !PortName) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Server, sizeof(WKD_ALPC_SERVER));
    wcscpy_s(Server->PortName, MAX_PATH, PortName);
    Server->State = WkdAlpcStateStopped;

    InitializeCriticalSection(&Server->Lock);

    /* 初始化端口句柄数组和共享节池 */
    for (ULONG i = 0; i < WkdAlpcConnectionMax; i++) {
        Server->AcceptedPorts[i] = NULL;
        Server->OutboundPorts[i] = NULL;
        for (ULONG j = 0; j < WKD_ALPC_MAX_POOL_SIZE; j++) {
            Server->SectionPool[i][j].Active = FALSE;
            Server->SectionPool[i][j].Busy = FALSE;
        }
    }

    /* 创建 ALPC 监听端口 */
    RtlInitUnicodeString(&portStr, Server->PortName);
    InitializeObjectAttributes(&objAttr, &portStr, 0, NULL, NULL);
    RtlZeroMemory(&portAttr, sizeof(portAttr));
    portAttr.MaxMessageLength = WKD_ALPC_MAX_MESSAGE_SUPPORTED;

    status = NtAlpcCreatePort(
        &Server->ServerPort,
        &objAttr,
        &portAttr
    );

    if (!NT_SUCCESS(status)) {
        printf("[WkdAlpc] CreatePort failed: 0x%X\n", status);
        DeleteCriticalSection(&Server->Lock);
        return status;
    }

    printf("[WkdAlpc] Port created: %S\n", Server->PortName);
    return STATUS_SUCCESS;
}

NTSTATUS
AlpcStartServer(
    _In_ PWKD_ALPC_SERVER Server
    )
/*++
Routine Description:
    启动 ALPC 服务器工作线程。

Arguments:
    Server — 已初始化的 ALPC 服务器。

Return Value:
    NTSTATUS。
--*/
{
    DWORD threadId;

    if (!Server || Server->State != WkdAlpcStateStopped) {
        return STATUS_INVALID_PARAMETER;
    }

    Server->WorkerThread = CreateThread(
        NULL, 0,
        AlpcpWorkerThread,
        Server,
        0,
        &threadId
    );

    if (!Server->WorkerThread) {
        Server->Running = FALSE;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Server->Running = TRUE;
    Server->State = WkdAlpcStateRunning;
    printf("[WkdAlpc] Server started on: %S\n", Server->PortName);

    return STATUS_SUCCESS;
}

NTSTATUS
WkdAlpcStopServer(
    _In_ PWKD_ALPC_SERVER Server
    )
/*++
Routine Description:
    停止 ALPC 服务器。断开所有连接并等待工作线程退出。

Arguments:
    Server — 运行中的 ALPC 服务器。

Return Value:
    NTSTATUS。
--*/
{
    ULONG i;

    if (!Server || Server->State != WkdAlpcStateRunning) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    printf("[WkdAlpc] Stopping...\n");
    Server->Running = FALSE;

    /* 等待工作线程退出 */
    if (Server->WorkerThread) {
        WaitForSingleObject(Server->WorkerThread, 5000);
        CloseHandle(Server->WorkerThread);
        Server->WorkerThread = NULL;
    }

    /* 销毁所有共享节池 */
    for (i = 0; i < WkdAlpcConnectionMax; i++) {
        AlpcpSectionPoolCleanup(Server, i);
    }

    /* 断开所有连接 */
    for (i = 0; i < WkdAlpcConnectionMax; i++) {
        if (Server->AcceptedPorts[i]) {
            NtAlpcDisconnectPort(Server->AcceptedPorts[i], 0);
            Server->AcceptedPorts[i] = NULL;
        }
        if (Server->OutboundPorts[i]) {
            NtAlpcDisconnectPort(Server->OutboundPorts[i], 0);
            Server->OutboundPorts[i] = NULL;
        }
    }

    if (Server->ServerPort) {
        NtAlpcDisconnectPort(Server->ServerPort, 0);
        Server->ServerPort = NULL;
    }

    Server->State = WkdAlpcStateStopped;
    printf("[WkdAlpc] Stopped\n");
    return STATUS_SUCCESS;
}

VOID
WkdAlpcCleanup(
    _In_ PWKD_ALPC_SERVER Server
    )
/*++
Routine Description:
    清理 ALPC 服务器所有资源。

Arguments:
    Server — ALPC 服务器实例。
--*/
{
    if (!Server) {
        return;
    }

    if (Server->State == WkdAlpcStateRunning) {
        WkdAlpcStopServer(Server);
    }

    DeleteCriticalSection(&Server->Lock);
    printf("[WkdAlpc] Cleanup complete\n");
}

NTSTATUS
AlpcRegisterRoute(
    _In_ PWKD_ALPC_SERVER           Server,
    _In_ ULONG                      MsgTypeStart,
    _In_ ULONG                      MsgTypeEnd,
    _In_ PWKD_MESSAGE_HANDLER       Handler,
    _In_opt_ PVOID                  Context
    )
/*++
Routine Description:
    注册消息路由条目。路由表由 Worker 线程使用（只读访问）。
    匹配键为 WKD_MESSAGE.Header.Type（WKD_MESSAGE_TYPE 数值）。

Arguments:
    Server       — ALPC 服务器实例。
    MsgTypeStart — 匹配范围起始（包含）。
    MsgTypeEnd   — 匹配范围结束（包含）。
    Handler      — 处理回调（接收已解包的 PWKD_MESSAGE）。
    Context      — 回调上下文。

Return Value:
    NTSTATUS。
--*/
{
    PWKD_ALPC_MESSAGE_ROUTE route;

    if (!Server || !Handler) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Server->RouteCount >= WKD_ALPC_MAX_ROUTES) {
        printf("[WkdAlpc] Route table full\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    route = &Server->RouteTable[Server->RouteCount];
    route->MsgTypeStart = MsgTypeStart;
    route->MsgTypeEnd = MsgTypeEnd;
    route->Handler = Handler;
    route->Context = Context;

    Server->RouteCount++;

    printf("[WkdAlpc] Route registered: 0x%X-0x%X (total=%lu)\n",
           MsgTypeStart, MsgTypeEnd, Server->RouteCount);
    return STATUS_SUCCESS;
}

NTSTATUS
AlpcSendMessageAsync(
    _In_ PWKD_ALPC_SERVER           Server,
    _In_ WKD_ALPC_CONNECTION_TYPE   ConnType,
    _In_ PWKD_ALPC_MESSAGE          Message,
    _In_opt_ ULONG                  Flags,
    _In_opt_ PALPC_MSG_ATTRIBUTES   MessageAttributes
    )
/*++
Routine Description:
    向指定端口发送 ALPC 消息。

Arguments:
    Server     — ALPC 服务器实例。
    PortHandle — 目标端口句柄。
    Message    — 要发送的消息。
    Flags      — ALPC 同步标识符。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;

    if (!Server || !ConnType || !Message) {
        return STATUS_INVALID_PARAMETER;
    }

    status = NtAlpcSendWaitReceivePort(
        Server->OutboundPorts[ConnType],
        Flags,
        (PPORT_MESSAGE)Message,
        MessageAttributes,
        NULL, NULL, NULL, NULL
    );

    if (!NT_SUCCESS(status)) {
        printf("[WkdAlpc] Send message failed: 0x%X\n", status);
    }
    return status;
}

NTSTATUS
WkdAlpcSendToUi(
    _In_ PWKD_ALPC_SERVER           Server,
    _In_ WKD_ALPC_MESSAGE_TYPE           MsgType,
    _In_opt_ PVOID                  Data,
    _In_ ULONG                      DataLength
    )
/*++
Routine Description:
    向 UI 发送消息。小消息走消息体，大消息走共享节。

Arguments:
    Server     — ALPC 服务器实例。
    MsgType    — 消息类型。
    Data       — 数据载荷。
    DataLength — 数据长度。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS        status;
    SIZE_T          msgSize;
    PWKD_ALPC_MESSAGE    msg;

    if (!Server || Server->State != WkdAlpcStateRunning) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!Server->OutboundPorts[WkdAlpcConnectionUi]) {
        printf("[WkdAlpc] UI not connected\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    msgSize = sizeof(WKD_ALPC_MESSAGE) + DataLength;
    msg = (PWKD_ALPC_MESSAGE)UtHeapAlloc(msgSize);
    if (!msg) {
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(msg, msgSize);
    msg->Header.u1.s1.DataLength = (USHORT)(msgSize - sizeof(PORT_MESSAGE));
    msg->Header.u1.s1.TotalLength = (USHORT)msgSize;
    msg->MessageType = MsgType;
    msg->Flags.Response = FALSE;
    msg->ItemCount = 0;

    if (Data && DataLength > 0) {
        memcpy((PUCHAR)msg + sizeof(WKD_ALPC_MESSAGE), Data, DataLength);
    }

    /* 直接发送（UI 消息通常为小消息，超大消息由 SectionViewRequest 流程处理） */
    status = NtAlpcSendWaitReceivePort(
        Server->OutboundPorts[WkdAlpcConnectionUi], 0,
        (PPORT_MESSAGE)msg,
        NULL,
        NULL, NULL, NULL, NULL
    );

    UtHeapFree(msg);
    return status;
}

NTSTATUS
WkdAlpcSendToUiEx(
    _In_ PWKD_ALPC_SERVER           Server,
    _In_ WKD_ALPC_MESSAGE_TYPE           MsgType,
    _In_opt_ PVOID                  Data,
    _In_ ULONG                      DataLength,
    _In_ BYTE                       StatusByte
    )
/*++
Routine Description:
    向 UI 发送消息（带状态字节）。

    注意：UI 侧 WKDEFENDER_MESSAGE 的 Status 字段位于偏移 0x1C，
    即 Agent WKD_ALPC_MESSAGE 的 ConnectionType 字段位置（MessageType 两者
    均在 0x20）。因此状态字节写入 ConnectionType 低位，UI 才能读到正确结果。
    本函数为 ProcessKiller 处置回复（KillProcessResp 0x2004）服务。

Arguments:
    Server     — ALPC 服务器实例。
    MsgType    — 消息类型。
    Data       — 数据载荷。
    DataLength — 数据长度。
    StatusByte — 状态字节（0=成功, 非0=失败），写入 ConnectionType 低位。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS        status;
    SIZE_T          msgSize;
    PWKD_ALPC_MESSAGE    msg;

    if (!Server || Server->State != WkdAlpcStateRunning) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!Server->OutboundPorts[WkdAlpcConnectionUi]) {
        printf("[WkdAlpc] UI not connected\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    msgSize = sizeof(WKD_ALPC_MESSAGE) + DataLength;
    msg = (PWKD_ALPC_MESSAGE)UtHeapAlloc(msgSize);
    if (!msg) {
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(msg, msgSize);
    msg->Header.u1.s1.DataLength = (USHORT)(msgSize - sizeof(PORT_MESSAGE));
    msg->Header.u1.s1.TotalLength = (USHORT)msgSize;
    msg->MessageType = MsgType;
    msg->Flags.Response = TRUE;
    msg->ItemCount = 0;
    /* 状态字节写入 ConnectionType 低位（对齐 UI Status 字段偏移 0x1C） */
    msg->ConnectionType = (WKD_ALPC_CONNECTION_TYPE)(StatusByte & 0xFF);

    if (Data && DataLength > 0) {
        memcpy((PUCHAR)msg + sizeof(WKD_ALPC_MESSAGE), Data, DataLength);
    }

    status = NtAlpcSendWaitReceivePort(
        Server->OutboundPorts[WkdAlpcConnectionUi], 0,
        (PPORT_MESSAGE)msg,
        NULL,
        NULL, NULL, NULL, NULL
    );

    UtHeapFree(msg);
    return status;
}

NTSTATUS
WkdAlpcSendToDriver(
    _In_ PWKD_ALPC_SERVER           Server,
    _In_ WKD_ALPC_MESSAGE_TYPE           MsgType,
    _In_opt_ PVOID                  Data,
    _In_ ULONG                      DataLength
    )
/*++
Routine Description:
    向 Driver 发送消息。

Arguments:
    Server     — ALPC 服务器实例。
    MsgType    — 消息类型。
    Data       — 数据载荷。
    DataLength — 数据长度。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS        status;
    SIZE_T          msgSize;
    PWKD_ALPC_MESSAGE    msg;

    if (!Server || Server->State != WkdAlpcStateRunning) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!Server->OutboundPorts[WkdAlpcConnectionDriver]) {
        printf("[WkdAlpc] Driver not connected, cannot send\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    msgSize = sizeof(WKD_ALPC_MESSAGE) + DataLength;
    msg = (PWKD_ALPC_MESSAGE)UtHeapAlloc(msgSize);
    if (!msg) {
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(msg, msgSize);
    msg->Header.u1.s1.DataLength = (USHORT)(msgSize - sizeof(PORT_MESSAGE));
    msg->Header.u1.s1.TotalLength = (USHORT)msgSize;
    msg->MessageType = MsgType;
    msg->Flags.Response = TRUE;
    msg->ItemCount = 0;

    if (Data && DataLength > 0) {
        memcpy((PUCHAR)msg + sizeof(WKD_ALPC_MESSAGE), Data, DataLength);
    }

    status = NtAlpcSendWaitReceivePort(
        Server->OutboundPorts[WkdAlpcConnectionDriver], 0,
        (PPORT_MESSAGE)msg, NULL,
        NULL, NULL, NULL, NULL
    );

    UtHeapFree(msg);
    return status;
}

/**************************************************/
/*         进程对位图更新发送                        */
/**************************************************/

NTSTATUS
WkdAlpcSendPairBitmapUpdate(
    _In_ PWKD_ALPC_SERVER           Server,
    _In_ HANDLE                     SourceProcessId,
    _In_ HANDLE                     TargetProcessId,
    _In_ ULONG64                    NewBitmap
    )
/*++
Routine Description:
    向 Driver 异步发送进程对位图更新。
    NewBitmap == 0 表示删除条目。

Arguments:
    Server           — ALPC 服务器实例。
    SourceProcessId  — 源进程 PID。
    TargetProcessId  — 目标进程 PID。
    NewBitmap        — 新的位图值。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS                    status;
    SIZE_T                      msgSize;
    PWKD_ALPC_MESSAGE           msg;
    PWKD_ALPC_PAIR_BITMAP_UPDATE update;

    if (!Server || Server->State != WkdAlpcStateRunning) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!Server->OutboundPorts[WkdAlpcConnectionDriver]) {
        printf("[WkdAlpc] Driver not connected, cannot send bitmap update\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    msgSize = sizeof(WKD_ALPC_MESSAGE) + sizeof(WKD_ALPC_PAIR_BITMAP_UPDATE);
    msg = (PWKD_ALPC_MESSAGE)UtHeapAlloc(msgSize);
    if (!msg) {
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(msg, msgSize);
    msg->Header.u1.s1.DataLength = (USHORT)(msgSize - sizeof(PORT_MESSAGE));
    msg->Header.u1.s1.TotalLength = (USHORT)msgSize;
    msg->MessageType = WkdAlpcMessage_PairBitmapUpdate;
    msg->Flags.Response = FALSE;

    update = (PWKD_ALPC_PAIR_BITMAP_UPDATE)(msg + 1);
    update->SourceProcessId = SourceProcessId;
    update->TargetProcessId = TargetProcessId;
    update->NewBitmap = NewBitmap;

    status = NtAlpcSendWaitReceivePort(
        Server->OutboundPorts[WkdAlpcConnectionDriver], 0,
        (PPORT_MESSAGE)msg, NULL,
        NULL, NULL, NULL, NULL
    );

    UtHeapFree(msg);

    printf("[WkdAlpc] Bitmap update sent: sPid=%p tPid=%p bitmap=0x%llx\n",
           SourceProcessId, TargetProcessId, NewBitmap);
    return status;
}

/**************************************************/
/*         排除规则推送发送（同步回执）              */
/**************************************************/

NTSTATUS
WkdAlpcSendExemptsUpdate(
    _In_ PWKD_ALPC_SERVER              Server,
    _In_ PWKD_ALPC_EXEMPT_UPDATE      Update,
    _Out_opt_ PWKD_ALPC_EXEMPT_ACK    Ack
    )
/*++
Routine Description:
    向 Driver 推送单条排除规则并等待同步回执（ALPC 请求-回复语义）。
    Driver 处理后经 0x3106 ExemptsAck 返回 {Version, AppliedCount, Status}。

Arguments:
    Server - ALPC 服务器实例。
    Update - 排除规则（每消息 1 条）。
    Ack    - 可选输出回执。

Return Value:
    NTSTATUS。
--*/
{
    NTSTATUS status;
    SIZE_T msgSize;
    PWKD_ALPC_MESSAGE msg;
    UCHAR replyBuf[WKD_ALPC_MAX_MESSAGE_SUPPORTED];
    SIZE_T replySize = sizeof(replyBuf);

    if (!Server || Server->State != WkdAlpcStateRunning) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!Server->OutboundPorts[WkdAlpcConnectionDriver]) {
        printf("[WkdAlpc] Driver not connected, cannot send exempts update\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    msgSize = sizeof(WKD_ALPC_MESSAGE) + sizeof(WKD_ALPC_EXEMPT_UPDATE);
    msg = (PWKD_ALPC_MESSAGE)UtHeapAlloc(msgSize);
    if (!msg) {
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(msg, msgSize);
    msg->Header.u1.s1.DataLength = (USHORT)(msgSize - sizeof(PORT_MESSAGE));
    msg->Header.u1.s1.TotalLength = (USHORT)msgSize;
    msg->Header.u2.s2.Type = LPC_REQUEST;
    msg->MessageType = WkdAlpcMessage_ExemptsUpdate;
    msg->Flags.Response = TRUE;
    msg->ItemCount = 0;
    RtlCopyMemory((PUCHAR)msg + sizeof(WKD_ALPC_MESSAGE), Update,
                  sizeof(WKD_ALPC_EXEMPT_UPDATE));

    RtlZeroMemory(replyBuf, sizeof(replyBuf));

    status = NtAlpcSendWaitReceivePort(
        Server->OutboundPorts[WkdAlpcConnectionDriver], 0,
        (PPORT_MESSAGE)msg, NULL,
        (PPORT_MESSAGE)replyBuf, &replySize,
        NULL, NULL);

    if (NT_SUCCESS(status) && Ack != NULL &&
        replySize >= sizeof(WKD_ALPC_MESSAGE) + sizeof(WKD_ALPC_EXEMPT_ACK)) {
        PWKD_ALPC_MESSAGE reply = (PWKD_ALPC_MESSAGE)replyBuf;
        if (reply->MessageType == WkdAlpcMessage_ExemptsAck) {
            RtlCopyMemory(Ack, (PUCHAR)reply + sizeof(WKD_ALPC_MESSAGE),
                          sizeof(WKD_ALPC_EXEMPT_ACK));
        }
    }

    UtHeapFree(msg);

    printf("[WkdAlpc] Exempts update sent: ver=%lu op=%u type=%u status=0x%X\n",
           Update->Version, Update->BatchOp, Update->RuleType, status);
    return status;
}

/**************************************************/
/*          ALPC 路由通用入队助手                    */
/**************************************************/

NTSTATUS
WkdMsgQueueAlpcHandler(
    _In_ PWKD_ALPC_SERVER       Server,
    _In_ PWKD_MESSAGE           Message,
    _In_opt_ PVOID              Context
    )
/*++
Routine Description:
    通用消息路由处理器：将已解包的 WKD_MESSAGE 深拷贝后入队到指定模块的
    WKD_MSG_QUEUE。作为 PWKD_MESSAGE_HANDLER 使用，Context 指向 PWKD_MSG_QUEUE。

Arguments:
    Server  — ALPC 服务器实例（未使用）。
    Message — 已解包的 WKD_MESSAGE。
    Context — 指向 PWKD_MSG_QUEUE 的指针。

Return Value:
    NTSTATUS。
--*/
{
    PWKD_MSG_QUEUE queue;

    UNREFERENCED_PARAMETER(Server);

    if (!Message || !Context) {
        return STATUS_INVALID_PARAMETER;
    }

    queue = (PWKD_MSG_QUEUE)Context;

    return WkdMsgQueueEnqueue(
        queue,
        Message->Header.Type,
        WkdMsgPriority_Normal,
        Message,
        sizeof(WKD_MESSAGE_HEADER) + Message->Header.BodySize
    );
}

WKD_ALPC_SERVER_STATE
WkdAlpcGetState(
    _In_ PWKD_ALPC_SERVER Server
    )
{
    if (!Server) {
        return WkdAlpcStateError;
    }
    return Server->State;
}

BOOLEAN
WkdAlpcIsDriverConnected(
    _In_ PWKD_ALPC_SERVER Server
    )
{
    if (!Server) {
        return FALSE;
    }
    return (Server->OutboundPorts[WkdAlpcConnectionDriver] != NULL);
}

BOOLEAN
WkdAlpcIsUiConnected(
    _In_ PWKD_ALPC_SERVER Server
    )
{
    if (!Server) {
        return FALSE;
    }
    return (Server->OutboundPorts[WkdAlpcConnectionUi] != NULL);
}
