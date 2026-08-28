#include "MessageSync.h"
#include "AlpcService.h"
#include "../Process/ProcessPairContext.h"
#include "../FileSystem/FileBackupEngine.h"   /* �ع������ļ���FBE�� */
#include "../Common/Utils.h"
#include "../Common/Exempts/Exempts.h"        /* �ų��������ͣ����� Exempts�� */

/**************************************************/
/*              ALPC ��־λ����                    */
/**************************************************/

#define ALPC_PORT_FLAG_SYSTEM_PROCESS          0x00100000
#define ALPC_MESSAGE_HANDLE_ATTRIBUTE          0x10000000
#define ALPC_MESSAGE_CONTEXT_ATTRIBUTE         0x20000000
#define ALPC_MESSAGE_VIEW_ATTRIBUTE            0x40000000
#define ALPC_MESSAGE_SECURITY_ATTRIBUTE        0x80000000

/**************************************************/
/*         Section �����ظ����ݸ�ʽ                 */
/*         WorkerThread ֵ�������ˣ��ȴ��߳�ֱ�Ӷ�  */
/**************************************************/

typedef struct _WKD_SECTION_VIEW_REPLY {
    ULONG   SlotIndex;  // Agent �๲���ڴ������
    PVOID   ViewBase;
    SIZE_T  ViewSize;
} WKD_SECTION_VIEW_REPLY;

/* Alpc ��֧�ֵ������Ϣ */
#define WKD_ALPC_MAX_MESSAGE_SUPPORTED      256

/**************************************************/
/*            ALPC ����ָ�루�ڲ���                */
/**************************************************/

static pfnZwAlpcCreatePort             WkdAlpcCreatePort = NULL;
static pfnZwAlpcConnectPort            WkdAlpcConnectPort = NULL;
static pfnZwAlpcDisconnectPort         WkdAlpcDisconnectPort = NULL;
static pfnZwAlpcAcceptConnectPort      WkdAlpcAcceptConnectPort = NULL;
static pfnZwAlpcSendWaitReceivePort    WkdAlpcSendWaitReceivePort = NULL;
static pfnZwAlpcCreatePortSection      WkdAlpcCreatePortSection = NULL;
static pfnZwAlpcCreateSectionView      WkdAlpcCreateSectionView = NULL;
static pfnAlpcGetMessageAttribute      WkdAlpcGetMessageAttribute = NULL;
static pfnAlpcInitializeMessageAttribute WkdAlpcInitializeMessageAttribute = NULL;

WKD_ALPC_SERVER WkdDefaultAlpcServer = { 0 };

/*++
AlpcpSafeClosePort
    Safely disconnect and close an ALPC port handle.
    ZwAlpcDisconnectPort only notifies the peer; it does NOT close the
    handle nor release the port object reference. ZwClose must follow to
    actually free the object. Every path that overwrites/rebuilds/stops a
    port handle must call this first, to keep reference counting symmetric
    and avoid handle leak / extra-free leading to quota underflow (0x103).
--*/
_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
AlpcpSafeClosePort(
    _Inout_ HANDLE* PortHandle
    )
{
    HANDLE h;

    if (!PortHandle) {
        return;
    }

    h = *PortHandle;
    if (h == NULL) {
        return;
    }

    if (WkdAlpcDisconnectPort != NULL) {
        WkdAlpcDisconnectPort(h, 0);
    }

    ZwClose(h);
    *PortHandle = NULL;
}

typedef enum _ALPC_PORT_MESSAGE_TYPE {
    LPC_REQUEST = 1,
    LPC_REPLY = 2,
    LPC_DATAGRAM = 3,
    LPC_LOST_REPLY = 4,
    LPC_PORT_CLOSED = 5,
    LPC_CLIENT_DIED = 6,
    LPC_EXCEPTION = 7,
    LPC_DEBUG_EVENT = 8,
    LPC_ERROR_EVENT = 9,
    LPC_CONNECTION_REQUEST = 10,
    LPC_CONNECTION_REPLY = 11,
    LPC_CANCELED = 12,
    LPC_UNREGISTER_PROCESS = 13
} ALPC_PORT_MESSAGE_TYPE;

/**************************************************/
/*                ����ǰ������                     */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
AlpcpStartServer(
    _In_ PWKD_ALPC_SERVER Server
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
AlpcpStopServer(
    _In_ PWKD_ALPC_SERVER Server
    );

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
AlpcpMessageDispatch(
    _In_ PWKD_ALPC_SERVER Server,
    _In_ PWKD_ALPC_MESSAGE RecvMsg,
    _In_ PALPC_MESSAGE_ATTRIBUTES MsgAttr
    );

/**************************************************/
/*           ALPC ��������                         */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
AlpcpParseRoutines(
    VOID
    )
{
    UNICODE_STRING uniStr;

    RtlInitUnicodeString(&uniStr, L"ZwAlpcCreatePort");
    WkdAlpcCreatePort =
        (pfnZwAlpcCreatePort)MmGetSystemRoutineAddress(&uniStr);

    RtlInitUnicodeString(&uniStr, L"ZwAlpcConnectPort");
    WkdAlpcConnectPort =
        (pfnZwAlpcConnectPort)MmGetSystemRoutineAddress(&uniStr);

    RtlInitUnicodeString(&uniStr, L"ZwAlpcDisconnectPort");
    WkdAlpcDisconnectPort =
        (pfnZwAlpcDisconnectPort)MmGetSystemRoutineAddress(&uniStr);

    RtlInitUnicodeString(&uniStr, L"ZwAlpcAcceptConnectPort");
    WkdAlpcAcceptConnectPort =
        (pfnZwAlpcAcceptConnectPort)MmGetSystemRoutineAddress(&uniStr);

    RtlInitUnicodeString(&uniStr, L"ZwAlpcSendWaitReceivePort");
    WkdAlpcSendWaitReceivePort =
        (pfnZwAlpcSendWaitReceivePort)MmGetSystemRoutineAddress(&uniStr);

    /* ������ */
    RtlInitUnicodeString(&uniStr, L"ZwAlpcCreatePortSection");
    WkdAlpcCreatePortSection =
        (pfnZwAlpcCreatePortSection)MmGetSystemRoutineAddress(&uniStr);

    RtlInitUnicodeString(&uniStr, L"ZwAlpcCreateSectionView");
    WkdAlpcCreateSectionView =
        (pfnZwAlpcCreateSectionView)MmGetSystemRoutineAddress(&uniStr);

    RtlInitUnicodeString(&uniStr, L"AlpcGetMessageAttribute");
    WkdAlpcGetMessageAttribute =
        (pfnAlpcGetMessageAttribute)MmGetSystemRoutineAddress(&uniStr);

    RtlInitUnicodeString(&uniStr, L"AlpcInitializeMessageAttribute");
    WkdAlpcInitializeMessageAttribute =
        (pfnAlpcInitializeMessageAttribute)MmGetSystemRoutineAddress(&uniStr);

    /* ����Ƿ�����ɹ� */
    if (!WkdAlpcCreatePort || !WkdAlpcConnectPort || !WkdAlpcDisconnectPort ||
        !WkdAlpcAcceptConnectPort || !WkdAlpcSendWaitReceivePort || !WkdAlpcCreatePortSection ||
        !WkdAlpcCreateSectionView || !WkdAlpcGetMessageAttribute || !WkdAlpcInitializeMessageAttribute) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to prase ALPC routine addresses\n");
        return STATUS_NOT_FOUND;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] ALPC routines initialized successfully\n");
    return STATUS_SUCCESS;
}

/**************************************************/
/*            ALPC ��Ϣ������/�ͷ�                 */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
AlpcpAllocateMessage(
    _Out_ PWKD_ALPC_MESSAGE* Package,
    _In_ WKD_ALPC_MESSAGE_TYPE MessageType,
    _In_ ULONG Status,
    _In_ BOOLEAN Response,
    _In_ ULONG ItemCount,
    _In_ ULONG DataSize,
    _Out_ PVOID* Data
)
{
    PWKD_ALPC_MESSAGE msg;
    SIZE_T totalSize;

    if (!DataSize || !ItemCount || !Data || !Package) {
        return STATUS_INVALID_PARAMETER;
    }

    totalSize = sizeof(WKD_ALPC_MESSAGE) + DataSize;

    msg = ExAllocatePool2(POOL_FLAG_NON_PAGED, totalSize, 'Alpc');
    if (!msg) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to allocate buffer for ALPC package\n");
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(msg, totalSize);

    /* Alpc��Ϣ��TotalLength/DataLength���ڷ��ͳ�����Ϣʱ���ܴ��ڽض�������⣬
     * ��ʱ��ʱ����Reserved2�洢�ܳ��ȣ�AlpcSendMessage�����ڲ�����ʶ��ʹ�����*/
    if ((LONG64)totalSize > MAXSHORT) {
        msg->Header.ClientViewSize = (ULONG64)totalSize;
        msg->Header.u1.Length = 0;
    } else {
        msg->Header.u1.s1.TotalLength = (CSHORT)totalSize;
        msg->Header.u1.s1.DataLength = (CSHORT)(totalSize - sizeof(PORT_MESSAGE));
    }
    msg->ConnectionType = WkdAlpcConnectionDriver;
    msg->MessageType = MessageType;
    msg->Status = (UCHAR)Status;
    msg->Flags.Response = (UCHAR)(Response ? 1 : 0);
    msg->ItemCount = (USHORT)ItemCount;

    *Package = msg;
    *Data = (PVOID)((PUCHAR)msg + sizeof(WKD_ALPC_MESSAGE));

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
FORCEINLINE
static
VOID
AlpcpFreeMessage(
    _In_ PWKD_ALPC_MESSAGE Message
)
{
    ExFreePoolWithTag(Message, 'Alpc');
}

/**************************************************/
/*          ���� Agent�����ͷ���                  */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
AlpcpConnectToAgent(
    _In_ PWKD_ALPC_SERVER Server
    )
{
    NTSTATUS status;
    SIZE_T size;
    UNICODE_STRING portName;
    WKD_ALPC_MESSAGE msg = { 0 };

    if (!Server) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Received connection request from agent\n");

    /* close previous handle first to avoid leak / refcount imbalance */
    AlpcpSafeClosePort(&Server->AgentPort);

    RtlInitUnicodeString(&portName, L"\\RPC Control\\WkDefender@Agent");

    size = sizeof(WKD_ALPC_MESSAGE);
    msg.ConnectionType = WkdAlpcConnectionDriver;
    msg.MessageType = WkdAlpcMessage_PortConnect;
    msg.Header.u1.s1.TotalLength = sizeof(WKD_ALPC_MESSAGE);
    msg.Header.u1.s1.DataLength = sizeof(WKD_ALPC_MESSAGE) - sizeof(PORT_MESSAGE);

    status = WkdAlpcConnectPort(
        &Server->AgentPort,
        &portName,
        NULL,
        NULL,
        0,
        NULL,
        (PPORT_MESSAGE)&msg,
        &size,
        NULL,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to connect to Agent communication port: 0x%X\n", status);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Connected to Agent communication port: 0x%llx\n", Server->AgentPort);
    return STATUS_SUCCESS;
}

/**************************************************/
/*          ALPC �����߳�                         */
/*                                                 */
/*  ����� ServerPort �������� Agent �� ALPC ��Ϣ�� */
/*  ���������������ܣ�������Ϣֱ���ɷ���             */
/*  AlpcpMessageDispatch ת������ȫ����Ϣ���С�      */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static
VOID
AlpcpWorkerThread(
    _In_ PVOID Context
    )
{
    NTSTATUS status;
    SIZE_T bufferSize = WKD_ALPC_MAX_MESSAGE_SUPPORTED;
    PWKD_ALPC_MESSAGE recvMsg;
    PALPC_MESSAGE_ATTRIBUTES msgAttr;
    PWKD_ALPC_SERVER server = (PWKD_ALPC_SERVER)Context;

    recvMsg = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'Alpc');
    if (!recvMsg) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to allocate buffer for ALPC message\n");
        PsTerminateSystemThread(STATUS_NO_MEMORY);
        return;
    }

    /* ��ȡ section view ������ */
    {
        SIZE_T msgAttrSize;
        WkdAlpcInitializeMessageAttribute(ALPC_MESSAGE_VIEW_ATTRIBUTE, NULL, 0, &msgAttrSize);
        msgAttr = ExAllocatePool2(POOL_FLAG_NON_PAGED, msgAttrSize, 'MAtr');
        if (!msgAttr) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WkDefender] Failed to allocate buffer for message attribute\n");
            ExFreePoolWithTag(recvMsg, 'Alpc');
            return;
        }
        WkdAlpcInitializeMessageAttribute(ALPC_MESSAGE_VIEW_ATTRIBUTE, msgAttr, msgAttrSize, &msgAttrSize);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] ALPC message thread started\n");

    while (server->Running) {

        status = WkdAlpcSendWaitReceivePort(
            server->ServerPort,
            0,
            NULL,
            NULL,
            (PPORT_MESSAGE)recvMsg,
            &bufferSize,
            msgAttr,
            NULL
        );

        if (!NT_SUCCESS(status)) {
            if (status == STATUS_PORT_DISCONNECTED) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[WkDefender] Agent port disconnected\n");
                break;
            }

            // �ӳ�����
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WkDefender] Failed to receive message: 0x%X\n", status);
            KeDelayExecutionThread(KernelMode, FALSE,
                &(LARGE_INTEGER){ .QuadPart = -10000000 });
            continue;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WkDefender] Received message: Type=%d, DataLength=%d\n",
            recvMsg->Header.u2.s2.Type, recvMsg->Header.u1.s1.DataLength);

        // ��Ϣ�ɷ����������� �� AcceptConnectPort������ �� ת������ȫ�ֶ���
        AlpcpMessageDispatch(server, recvMsg, msgAttr);
    }

    ExFreePoolWithTag(msgAttr, 'MAtr');
    ExFreePoolWithTag(recvMsg, 'Alpc');
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] ALPC message thread stopped\n");

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/**************************************************/
/*          ALPC ��Ϣ�ɷ�                          */
/*                                                 */
/*  ��������0xA���� AcceptConnectPort              */
/*  ������Ϣ �� ת��Ϊ WKD_MESSAGE ������ȫ�ֶ���    */
/**************************************************/

/*
 * 64 hex �ַ� �� 32 �ֽڣ�SHA-256���������ܾ�ȷ���ȣ�Сдʮ�����ơ�
 */
static BOOLEAN
AlpcpHexDecode(
    _In_ PCWCH Hex,
    _Out_ PUCHAR Buffer,
    _In_ ULONG BufferSize
    )
{
    ULONG i;
    ULONG pos = 0;

    if (Hex == NULL || Buffer == NULL) {
        return FALSE;
    }

    for (i = 0; i < BufferSize; i++) {
        UCHAR hi;
        UCHAR lo;

        hi = (UCHAR)Hex[pos++];
        lo = (UCHAR)Hex[pos++];

        if (hi >= L'0' && hi <= L'9') hi -= L'0';
        else if (hi >= L'a' && hi <= L'f') hi = (UCHAR)(hi - L'a' + 10);
        else if (hi >= L'A' && hi <= L'F') hi = (UCHAR)(hi - L'A' + 10);
        else return FALSE;

        if (lo >= L'0' && lo <= L'9') lo -= L'0';
        else if (lo >= L'a' && lo <= L'f') lo = (UCHAR)(lo - L'a' + 10);
        else if (lo >= L'A' && lo <= L'F') lo = (UCHAR)(lo - L'A' + 10);
        else return FALSE;

        Buffer[i] = (UCHAR)((hi << 4) | lo);
    }

    return (Hex[pos] == L'\0');
}

/*
 * Ӧ�õ��� ALPC �ų�����A7 ӳ�䣺BatchOp/RuleType �� ���� Exempts����
 * ������Ӧ����Ŀ����
 */
static ULONG
ExemptpApplyAlpcUpdate(
    _In_ PWKD_ALPC_EXEMPT_UPDATE Update
    )
{
    NTSTATUS status;
    UNICODE_STRING us;
    ULONG applied = 0;

    if (Update == NULL || Update->Value[0] == L'\0') {
        return 0;
    }

    RtlInitUnicodeString(&us, Update->Value);

    switch (Update->RuleType) {
    case 0:  /* Path */
        if (Update->BatchOp == 1) {
            status = ExemptsAddPathExclusion(&us, Update->Flags, Update->TTLSeconds);
            if (NT_SUCCESS(status)) applied++;
        } else if (Update->BatchOp == 2) {
            if (ExemptsRemovePathExclusion(&us)) applied++;
        }
        break;

    case 1:  /* Extension */
        if (Update->BatchOp == 1) {
            status = ExemptsAddExtensionExclusion(&us, Update->Flags);
            if (NT_SUCCESS(status)) applied++;
        } else if (Update->BatchOp == 2) {
            if (ExemptsRemoveExtensionExclusion(&us)) applied++;
        }
        break;

    case 2:  /* ProcessName */
        if (Update->BatchOp == 1) {
            status = ExemptsAddProcessExclusion(&us, Update->Flags);
            if (NT_SUCCESS(status)) applied++;
        } else if (Update->BatchOp == 2) {
            if (ExemptsRemoveProcessExclusion(&us)) applied++;
        }
        break;

    case 3:  /* ProcessId��Value=ʮ�����ַ����� */
    {
        ULONG pid = 0;
        if (!NT_SUCCESS(RtlUnicodeStringToInteger(&us, 10, &pid)) || pid == 0) {
            break;
        }
        if (Update->BatchOp == 1) {
            status = ExemptsAddPidExclusion((HANDLE)(ULONG_PTR)pid, Update->TTLSeconds);
            if (NT_SUCCESS(status)) applied++;
        } else if (Update->BatchOp == 2) {
            if (ExemptsRemovePidExclusion((HANDLE)(ULONG_PTR)pid)) applied++;
        }
        break;
    }

    default:
        break;
    }

    return applied;
}

_Use_decl_annotations_
static
VOID
AlpcpMessageDispatch(
    _In_ PWKD_ALPC_SERVER Server,
    _In_ PWKD_ALPC_MESSAGE RecvMsg,
    _In_ PALPC_MESSAGE_ATTRIBUTES MsgAttr
    )
{
    NTSTATUS status;
    PWKD_MESSAGE wkdMsg;
    

    /* ======================================================== */
    /* ��������LPC_CONNECTION_REQUEST = 0xA��                  */
    /* �����ڽ����߳���������ͬ������ AcceptConnectPort��        */
    /* ======================================================== */
    switch ((UCHAR)RecvMsg->Header.u2.s2.Type) {
    case LPC_REQUEST:

        /* 
         * ת��Ϊ WKD_MESSAGE ����ȫ����Ϣ���� 
         */
        switch (RecvMsg->MessageType) {

        //
        // �����ھ���֪ͨ �� ����Ϣ��������ȡ ViewAttr��
        // ���� DriverSlotIndex �����Ӧ�ı�����ʱ��λ�������¼���
        //
        case WkdAlpcMessage_SectionViewReady: {
            PALPC_DATA_VIEW_ATTR attr;
            PWKD_ALPC_SECTION_VIEW_PAYLOAD payload;
            ULONG requestId, agentSlotIdx;

            if (!(MsgAttr->ValidAttributes & ALPC_MESSAGE_VIEW_ATTRIBUTE)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[WkDefender] SectionViewReady without ViewAttr\n");
                break;
            }

            attr = (PALPC_DATA_VIEW_ATTR)
                WkdAlpcGetMessageAttribute(MsgAttr, ALPC_MESSAGE_VIEW_ATTRIBUTE);
            if (!attr) {
                break;
            }

            /* ����Ϣ��������� [RequestId, AgentSlotIndex] */
            if (RecvMsg->Header.u1.s1.TotalLength !=
                (CSHORT)(sizeof(WKD_ALPC_MESSAGE) + sizeof(WKD_ALPC_SECTION_VIEW_PAYLOAD))) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[WkDefender] SectionViewReady missing payload\n");
                break;
            }

            payload = (PWKD_ALPC_SECTION_VIEW_PAYLOAD)(RecvMsg + 1);
            requestId = payload->RequestId;
            agentSlotIdx = payload->SlotIndex;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WkDefender] SectionViewReady: requestId=%lu, agentSlot=%lu, "
                "base=0x%p, size=%llu\n",
                requestId, agentSlotIdx,
                attr->ViewBase, (ULONG64)attr->ViewSize);

            /* ͨ��ͳһ�ظ����ƻ��ѵȴ��̣߳�ֵ����������ָ�룩 */
            {
                WKD_SECTION_VIEW_REPLY reply;
                reply.ViewBase = attr->ViewBase;
                reply.ViewSize = attr->ViewSize;
                reply.SlotIndex = agentSlotIdx;

                NtfSyncWriteReply(
                    &g_SyncMgr,
                    requestId,
                    &reply,
                    sizeof(reply)
                );
            }
            break;
        }

        //
        // ͳһͬ���ظ� �� Agent ���ص�ͬ��������ѯ���
        // WorkerThread ֻ�� memcpy�������� Data ��ʽ��
        //
        case WkdAlpcMessage_SyncReply: {
            PWKD_ALPC_SYNC_REPLY reply = (PWKD_ALPC_SYNC_REPLY)(RecvMsg + 1);
            ULONG dataLen = RecvMsg->Header.u1.s1.DataLength -
                (sizeof(WKD_ALPC_MESSAGE) - sizeof(PORT_MESSAGE)) -
                sizeof(WKD_ALPC_SYNC_REPLY);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WkDefender] SyncReply: requestId=%lu, dataLen=%lu\n",
                reply->RequestId, dataLen);

            NtfSyncWriteReply(
                &g_SyncMgr,
                reply->RequestId,
                reply->Data,
                dataLen
            );
            break;
        }

        //
        // ���̶�λͼ���� �� Agent �첽�·�
        //
        case WkdAlpcMessage_PairBitmapUpdate:
        {
            PWKD_ALPC_PAIR_BITMAP_UPDATE update;

            if (RecvMsg->Header.u1.s1.DataLength !=
                (CSHORT)(sizeof(WKD_ALPC_MESSAGE) - sizeof(PORT_MESSAGE) + sizeof(WKD_ALPC_PAIR_BITMAP_UPDATE))) {
                break;
            }

            update = (PWKD_ALPC_PAIR_BITMAP_UPDATE)(RecvMsg + 1);

            PsUpdatePairBitmap(
                update->SourceProcessId,
                update->TargetProcessId,
                update->NewBitmap);
            break;
        }

        //
        // �ع������ļ� �� Agent �·���FBE Ǩ�� 2026-08��
        // �غ� = ULONG PID��0=��Ч��v1 �������̻ع���
        //
        case WkdAlpcMessage_RollbackProcessReq:
        {
            ULONG pid = 0;
            FBE_ROLLBACK_RESULT fbResult = 0; /* ��ʼ����FBE �ų��ڼ��޻ع���� */

            if (RecvMsg->Header.u1.s1.DataLength >=
                (CSHORT)(sizeof(WKD_ALPC_MESSAGE) - sizeof(PORT_MESSAGE) + sizeof(ULONG))) {
                pid = *(PULONG)(RecvMsg + 1);
            }

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WkDefender] RollbackProcessReq: pid=%lu\n", pid);

            /* PASSIVE_LEVEL��Worker �̣߳���ͬ��ֱ���ں�̬�ع���
             * ע���ָ� I/O �ڽ����߳�ִ�У��ļ��϶�ʱ��ʱ�ϳ���������Ǩ
             * FBE ר�� worker �̣߳����� SS �û�̬�������壩��
             * 2026-08-10 [FileSystem �ų�]: FbeRollbackProcess ������
             * FileSystem\FileBackupEngine.c���ݲ�������룬����ע�͡� */
#if 0 /* [FileSystem �ų�-�ݴ����] */
            fbResult = FbeRollbackProcess((HANDLE)(ULONG_PTR)pid, NULL);
#endif /* [FileSystem �ų�-�ݴ����] */
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WkDefender] RollbackProcess result: %d\n", fbResult);
            break;
        }

        //
        // Agent ת���� WKD_MESSAGE����ע�ͣ�Ԥ����
            //PWKD_MESSAGE srcMsg;

            //if (RecvMsg->Header.u1.s1.TotalLength < (CSHORT)(sizeof(WKD_ALPC_MESSAGE) + sizeof(WKD_MESSAGE_HEADER))) {
            //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            //        "[WkDefender] Invalid WkdMessageForward payload size\n");
            //    break;
            //}

            //srcMsg = (PWKD_MESSAGE)((PUCHAR)RecvMsg + sizeof(WKD_ALPC_MESSAGE));

            //if (srcMsg->Header.Magic != WKD_NOTIFICATION_MAGIC) {
            //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,

            //        "[WkDefender] Invalid WKD_MESSAGE magic in ALPC forward\n");
            //    break;
            //}

            //wkdMsg = NtfCreateMessage(
            //    srcMsg->Header.Type,
            //    srcMsg->Header.Source,
            //    srcMsg->Header.Priority,
            //    srcMsg->Header.BodySize);
            //if (!wkdMsg) {
            //    break;
            //}

            //RtlCopyMemory(&wkdMsg->Body, &srcMsg->Body, srcMsg->Header.BodySize);
            //wkdMsg->Header.SourceProcessId = srcMsg->Header.SourceProcessId;
            //wkdMsg->Header.TargetProcessId = srcMsg->Header.TargetProcessId;
            //wkdMsg->Header.ThreadId = srcMsg->Header.ThreadId;

            //NtfpQueueInsert(wkdMsg);
  

        //
        // Agent �·��� IOC ����
        // TODO: ���� IOC ���ݲ����� IoC ���滺��
        //
        //case (WKD_ALPC_MESSAGE_TYPE)0xC:
        //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        //        "[WkDefender] Received IOC update message - handler pending\n");
        //    break;

            //
            // �����������
            // TODO: ֱ�ӵ�����ϴ���������������ȫ����Ϣ���У�
            //
        //case WkdAlpcMsgKillProcessRequest:
        //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        //        "[WkDefender] Received kill process request - handler pending\n");
        //    break;

            //
            // ϵͳ״̬/�����б���ѯ����
            // TODO: ֱ���ڽ����߳��й�����Ӧ�����ͻ� Agent
            //
        //case WkdAlpcMsgGetSystemStatusRequest:
        //case WkdAlpcMsgGetProcessListRequest:
        //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        //        "[WkDefender] Received query request type=%d - handler pending\n",
        //        RecvMsg->MessageType);
        //    break;

        //
        // ================================================================
        // TODO[HandleScanner��ALPC]: Agent ������ɨ��
        // ���̣�
        //   1. ����Ϣ Body ����Ŀ�� PID��WKD_ALPC_MESSAGE + ULONG pid��
        //   2. ���� HsScanProcessHandles() ɨ����
        //   3. ���� WKD_MESSAGE_BODY_HANDLE_SCAN + ��Ŀ����
        //   4. ͨ�� AlpcSendWkdMessage �����ڷ��� agent
        //
        // ���ݸ�ʽ������:
        //   ALPC Body = ULONG TargetProcessId
        //
        // ���ݸ�ʽ���ظ���:
        //   ALPC Body = [WKD_MESSAGE_BODY_HANDLE_SCAN]
        //               [WKD_MESSAGE_BODY_HANDLE_ENTRY �� Count]
        // ================================================================
        case WkdAlpcMessage_HandleScan:
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WkDefender] HandleScan request received �� ALPC comm TODO\n");
            break;

        //
        // �ų��������� �� Agent �ȸ��£��ų���ϵͳ Exempts��A7 ӳ�䣩
        // BatchOp: 0=Clear+Replace 1=Add 2=Remove 3=Clear
        // ������ AgentBoundPort ͬ����ִ WKD_ALPC_EXEMPT_ACK��
        //
        case WkdAlpcMessage_ExemptsUpdate:
        {
            PWKD_ALPC_EXEMPT_UPDATE update;
            WKD_ALPC_EXEMPT_ACK ack;
            WKD_ALPC_MESSAGE replyMsg;
            ULONG applied = 0;

            if (RecvMsg->Header.u1.s1.TotalLength <
                (CSHORT)(sizeof(WKD_ALPC_MESSAGE) + sizeof(WKD_ALPC_EXEMPT_UPDATE))) {
                break;
            }

            update = (PWKD_ALPC_EXEMPT_UPDATE)(RecvMsg + 1);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WkDefender] ExemptsUpdate: version=%lu, op=%u, type=%u\n",
                update->Version, update->BatchOp, update->RuleType);

            /* 2026-08-10 �ָ���Common\Exempts �������룬���������·��ԭ */
            /* Clear+Replace / Clear �� �����ȫ�����汾����ʱȫ�����ƣ� */
            if (update->BatchOp == 0 || update->BatchOp == 3) {
                ExemptsClearExclusions(ExemptRule_Path);
                ExemptsClearExclusions(ExemptRule_Extension);
                ExemptsClearExclusions(ExemptRule_ProcessName);
                ExemptsClearExclusions(ExemptRule_ProcessId);
            }

            /* Ӧ�õ�������Clear ����ʱ���� Add�� */
            if (update->BatchOp != 3) {
                applied = ExemptpApplyAlpcUpdate(update);
            }

            /* �����ִ��ͬ���ظ���ALPC LPC_REPLY + MessageId ������ */
            RtlZeroMemory(&ack, sizeof(ack));
            ack.Version = update->Version;
            ack.AppliedCount = applied;
            ack.Status = STATUS_SUCCESS;

            RtlZeroMemory(&replyMsg, sizeof(replyMsg));
            replyMsg.Header.u1.s1.TotalLength =
                (CSHORT)(sizeof(WKD_ALPC_MESSAGE) + sizeof(WKD_ALPC_EXEMPT_ACK));
            replyMsg.Header.u1.s1.DataLength =
                (CSHORT)(sizeof(WKD_ALPC_MESSAGE) - sizeof(PORT_MESSAGE) +
                         sizeof(WKD_ALPC_EXEMPT_ACK));
            replyMsg.Header.u2.s2.Type = LPC_REPLY;
            replyMsg.Header.MessageId = RecvMsg->Header.MessageId;
            replyMsg.ConnectionType = WkdAlpcConnectionAgent;
            replyMsg.MessageType = WkdAlpcMessage_ExemptsAck;
            RtlCopyMemory((PUCHAR)&replyMsg + sizeof(WKD_ALPC_MESSAGE), &ack, sizeof(ack));

            if (Server->AgentBoundPort != NULL && WkdAlpcSendWaitReceivePort != NULL) {
                WkdAlpcSendWaitReceivePort(
                    Server->AgentBoundPort,
                    ALPC_MSGFLG_REPLY_MESSAGE,
                    (PPORT_MESSAGE)&replyMsg,
                    NULL,
                    NULL, NULL, NULL, NULL);
            }
            break;
        }

        default:
            break;
        }

        break;

    case LPC_CONNECTION_REQUEST: {
        HANDLE boundPort = NULL;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WkDefender] Received connection request from agent\n");

        status = WkdAlpcAcceptConnectPort(
            &boundPort,
            Server->ServerPort,
            0,
            NULL,
            NULL,
            NULL,
            (PPORT_MESSAGE)RecvMsg,
            NULL,
            TRUE
        );

        if (NT_SUCCESS(status)) {
            AlpcpSafeClosePort(&Server->AgentBoundPort);
            Server->AgentBoundPort = boundPort;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WkDefender] Connection accepted from agent, bound port: 0x%llx\n", boundPort);
        }
        else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WkDefender] Failed to accept connection: 0x%X\n", status);
        }

        break;
    }
    //
    // δ֪��Ϣ����
    //
    default:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[WkDefender] Unknown ALPC message type: %d\n", RecvMsg->MessageType);
        break;
    }
}

/**************************************************/
/*             ���� ALPC ������                    */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
AlpcCreateServer(
    VOID
    )
{
    NTSTATUS status;
    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES objAttr;
    ALPC_PORT_ATTRIBUTES portAttr;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Initializing ALPC service...\n");

    RtlZeroMemory(&WkdDefaultAlpcServer, sizeof(WKD_ALPC_SERVER));

    status = AlpcpParseRoutines();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* ��ʼ��ͳһͬ����������� */
    WkdSyncInitialize(&g_SyncMgr);

    WkdDefaultAlpcServer.State = WkdAlpcStateStopped;
    wcscpy_s(WkdDefaultAlpcServer.PortName, MAX_PATH,
        L"\\RPC Control\\WkDefender@Driver");
    RtlInitUnicodeString(&portName, WkdDefaultAlpcServer.PortName);
    InitializeObjectAttributes(&objAttr, &portName, 0, NULL, NULL);
    RtlZeroMemory(&portAttr, sizeof(ALPC_PORT_ATTRIBUTES));
    portAttr.MaxMessageLength = WKD_ALPC_MAX_MESSAGE_SUPPORTED;
    portAttr.Flags = ALPC_PORT_FLAG_SYSTEM_PROCESS;

    status = WkdAlpcCreatePort(
        &WkdDefaultAlpcServer.ServerPort,
        &objAttr,
        &portAttr
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to create server port: 0x%X\n", status);
        return status;
    }

    status = AlpcpStartServer(&WkdDefaultAlpcServer);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to start server port: 0x%X\n", status);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] ALPC server initialized successfully\n");
    return STATUS_SUCCESS;
}

/**************************************************/
/*              ���� ALPC ������                   */
/**************************************************/

_Use_decl_annotations_
static
NTSTATUS
AlpcpStartServer(
    _In_ PWKD_ALPC_SERVER Server
    )
{
    NTSTATUS status;

    if (!Server) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Starting ALPC server...\n");

    // ���������̣߳�������� ALPC ��Ϣ���ɷ���
    status = PsCreateSystemThread(
        &Server->MessageThread,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        AlpcpWorkerThread,
        Server
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to create message thread: 0x%X\n", status);
        Server->Running = FALSE;
        Server->State = WkdAlpcStateError;
        AlpcpSafeClosePort(&Server->AgentPort);
        return status;
    }

    Server->Running = TRUE;
    Server->State = WkdAlpcStateRunning;

    status = AlpcpConnectToAgent(Server);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to connect to Agent: 0x%X\n", status);
        Server->State = WkdAlpcStateError;
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] ALPC server started successfully\n");
    return STATUS_SUCCESS;
}

/**************************************************/
/*              ֹͣ ALPC ������                   */
/**************************************************/

_IRQL_requires_(PASSIVE_LEVEL)
static
NTSTATUS
AlpcpStopServer(
    _In_ PWKD_ALPC_SERVER Server
    )
{
    if (!Server) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Stopping ALPC server...\n");

    /* ��������ͬ���ȴ��̣߳��˿ڼ����Ͽ����������ù��� */
    WkdSyncCancelAll(&g_SyncMgr);

    Server->Running = FALSE;

    // �ȴ������߳��˳�
    if (Server->MessageThread) {
        KeWaitForSingleObject(Server->MessageThread,
            Executive, KernelMode, FALSE, NULL);
        ZwClose(Server->MessageThread);
        Server->MessageThread = NULL;
    }

    AlpcpSafeClosePort(&Server->AgentBoundPort);
    AlpcpSafeClosePort(&Server->AgentPort);
    AlpcpSafeClosePort(&Server->ServerPort);

    Server->State = WkdAlpcStateStopped;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] ALPC server stopped successfully\n");
    return STATUS_SUCCESS;
}

/**************************************************/
/*              ���� ALPC ����                     */
/**************************************************/

_Use_decl_annotations_
VOID
AlpcCleanupService(
    VOID
    )
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Cleaning up ALPC service...\n");
    AlpcpStopServer(&WkdDefaultAlpcServer);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] ALPC service cleaned up successfully\n");
}

/**************************************************/
/*              ���� ALPC ��Ϣ                     */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
AlpcSendMessage(
    _In_opt_ PWKD_ALPC_SERVER Server,
    _In_ PWKD_ALPC_MESSAGE Message
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    const ULONG MAX_RETRIES = 3;

    if (!Message) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Server) {
        Server = &WkdDefaultAlpcServer;
    }

    /*
     * ������Ϣʹ�� SectionView��ͳһͬ����������� + �¼�������
     * ���̣�
     *   1. �� SyncRequestMgr ��������ڵ㣨�� RequestId��
     *   2. ���� SectionViewRequest��payload Я�� RequestId�����첽����
     *   3. �� SyncRequestMgr �ϵȴ����Զ����� WorkerThread �ظ���
     *   4. д�����ݵ�������
     *   5. ���� DataReady ��Ϣ֪ͨ Agent �����Ѿ���
     *   6. �ͷ�����ڵ�
     */
    if (Message->Header.u1.s1.TotalLength > WKD_ALPC_MAX_MESSAGE_SUPPORTED ||
        Message->Header.u1.Length == 0) {
        PWKD_SYNC_REQUEST               syncReq;
        WKD_SECTION_VIEW_REPLY          sectionReply = { 0 };
        SIZE_T                          payloadSize;
        PWKD_ALPC_SECTION_VIEW_PAYLOAD  payload;

        if (Message->Header.u1.Length == 0) {
            payloadSize =
                (SIZE_T)Message->Header.ClientViewSize - sizeof(WKD_ALPC_MESSAGE);
            Message->Header.ClientViewSize = 0;
        } else {
            payloadSize =
                (SIZE_T)Message->Header.u1.s1.TotalLength - sizeof(WKD_ALPC_MESSAGE);
        }
        
        /* ------------------------------------------------------------ */
        /* �׶�1: �������ڣ�SyncRequestMgr ͳһ������                   */
        /* ------------------------------------------------------------ */
        {
            /* 1a. ��ͳһͬ���������������ڵ� */
            status = NtfAcquireSyncRequest(
                &g_SyncMgr,
                &sectionReply,
                sizeof(sectionReply),
                &syncReq
            );
            if (!NT_SUCCESS(status)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[WkDefender] No free sync request available\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            /* 1b. ���� SectionViewRequest������: [RequestId, PayloadSize]�� */
            PWKD_ALPC_MESSAGE   reqMsg = NULL;
            PVOID               reqData = NULL;

            status = AlpcpAllocateMessage(
                &reqMsg,
                WkdAlpcMessage_SectionViewRequest,
                STATUS_SUCCESS,
                FALSE,
                1,
                sizeof(WKD_ALPC_SECTION_VIEW_PAYLOAD),
                &reqData
            );
            if (!NT_SUCCESS(status)) {
                NtfReleaseSyncRequest(&g_SyncMgr, syncReq);
                return status;
            }

            payload = (PWKD_ALPC_SECTION_VIEW_PAYLOAD)reqData;
            payload->RequestId  = syncReq->RequestId;    // ͳһ RequestId
            payload->SlotIndex  = (ULONG)-1;
            payload->DataSize   = payloadSize;

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WkDefender] Request section: requestId=%lu, size=%llu\n",
                syncReq->RequestId, (ULONG64)payloadSize);

            /* 1c. �������� */
            status = AlpcSendMessage(Server, reqMsg);
            AlpcpFreeMessage(reqMsg);

            if (!NT_SUCCESS(status)) {
                NtfReleaseSyncRequest(&g_SyncMgr, syncReq);
                return status;
            }

            /* 1d. �� SyncRequestMgr �ϵȴ� WorkerThread �ظ� */
            {
                //LARGE_INTEGER timeout;
                //timeout.QuadPart = -36000000000LL;

                status = NtfSyncWait(&g_SyncMgr, syncReq, NULL);

                if (status != STATUS_SUCCESS) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "[WkDefender] Wait for SectionViewReady timed out: 0x%X\n", status);
                    NtfReleaseSyncRequest(&g_SyncMgr, syncReq);
                    return STATUS_TIMEOUT;
                }
            }

            /* 1e. �� ReplyBuffer ����ȡ ViewAttr �� AgentSlotIndex */
            if (!(sectionReply.ViewBase && sectionReply.ViewSize > 0)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[WkDefender] SectionViewReady triggered but ViewBase is NULL\n");
                NtfReleaseSyncRequest(&g_SyncMgr, syncReq);
                return STATUS_UNSUCCESSFUL;
            }

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[WkDefender] Section ready: requestId=%lu, agentSlot=%lu, "
                "base=0x%p, size=%llu\n",
                syncReq->RequestId, sectionReply.SlotIndex,
                sectionReply.ViewBase, (ULONG64)sectionReply.ViewSize);
        }

        /* ------------------------------------------------------------ */
        /* �׶�2: д�����ݵ�������                                           */
        /* ------------------------------------------------------------ */

        {
            if (payloadSize > sectionReply.ViewSize) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[WkDefender] ALPC message too large for section view: %llu > %llu\n",
                    (ULONG64)payloadSize, (ULONG64)sectionReply.ViewSize);

                NtfReleaseSyncRequest(&g_SyncMgr, syncReq);
                return STATUS_PORT_MESSAGE_TOO_LONG;
            }

            RtlCopyMemory(
                sectionReply.ViewBase,
                (PUCHAR)(Message + 1),
                payloadSize);
        }

        /* �ͷ�ͬ������ڵ㣨������д�빲���ڣ� */
        NtfReleaseSyncRequest(&g_SyncMgr, syncReq);

        /* ------------------------------------------------------------ */
        /* �׶�3: ���� Message ͷ �� ALPC ������д�� Payload              */
        /* ------------------------------------------------------------ */

        {
            payload = (PWKD_ALPC_SECTION_VIEW_PAYLOAD)(Message + 1);
            payload->RequestId = (ULONG)-1;                 // DataReady ����Ҫ�ظ�
            payload->SlotIndex = sectionReply.SlotIndex;    // Agent ƾ�˹黹
            payload->DataSize = payloadSize;

            Message->Header.u1.s1.TotalLength =
                (CSHORT)(sizeof(WKD_ALPC_MESSAGE) + sizeof(WKD_ALPC_SECTION_VIEW_PAYLOAD));
            Message->Header.u1.s1.DataLength =
                (CSHORT)(sizeof(WKD_ALPC_MESSAGE) + sizeof(WKD_ALPC_SECTION_VIEW_PAYLOAD) - sizeof(PORT_MESSAGE));
            Message->Flags.UseSectionView = TRUE;
        }
    }

    ULONG retryCount = 0;
    while (retryCount++ < MAX_RETRIES) {
        status = WkdAlpcSendWaitReceivePort(
            Server->AgentPort,
            0,
            (PPORT_MESSAGE)Message,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
        );

        if (NT_SUCCESS(status)) {
            break;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender] Failed to send ALPC message (attempt %d): 0x%X\n",
            retryCount, status);

        if (status == STATUS_PORT_DISCONNECTED || status == STATUS_INVALID_HANDLE) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WkDefender] Port disconnected, attempting to reconnect...\n");
            status = AlpcpConnectToAgent(&WkdDefaultAlpcServer);
            if (NT_SUCCESS(status)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "[WkDefender] Reconnected to Agent successfully\n");
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[WkDefender] Failed to reconnect to Agent: 0x%X\n", status);
            }
        }

        KeDelayExecutionThread(KernelMode, FALSE,
            &(LARGE_INTEGER){ .QuadPart = -5000000 });
    }

    return status;
}

/**************************************************/
/*            ALPC ״̬��ѯ API                    */
/**************************************************/

_Use_decl_annotations_
WKD_ALPC_SERVER_STATE
AlpcGetState(
    _In_ PWKD_ALPC_SERVER Server
    )
{
    if (!Server) {
        return WkdAlpcStateNotFound;
    }
    return Server->State;
}

_Use_decl_annotations_
BOOLEAN
AlpcIsAgentConnected(
    _In_ PWKD_ALPC_SERVER Server
)
{
    if (!Server) {
        return FALSE;
    }
    return Server->AgentPort != NULL;
}

/**************************************************/
/*    ת�� WKD_MESSAGE �� Agent��ָ����Ϣ���ͣ�    */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
AlpcSendWkdMessage(
    _In_ PWKD_MESSAGE Message
    )
/*++
Routine Description:
    �� WKD_MESSAGE ��װ�� ALPC ��Ϣ�����������͵� Agent��

Arguments:
    Message     �� Ҫ���͵� WKD_MESSAGE��Header + Body����

Return Value:
    NTSTATUS��
--*/
{
    NTSTATUS status;
    PWKD_ALPC_MESSAGE alpcMsg;
    WKD_ALPC_MESSAGE_TYPE alpcMsgType;
    PVOID data = NULL;
    SIZE_T exactSize;

    if (!Message) {
        return STATUS_INVALID_PARAMETER;
    }

    /* ȷ�� Agent ������ */
    if (!WkdDefaultAlpcServer.AgentPort) {
        status = AlpcpConnectToAgent(&WkdDefaultAlpcServer);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WkDefender] Failed to connect to Agent for WKD_MESSAGE forwarding: 0x%X\n",
                status);
            return status;
        }
    }

    exactSize = sizeof(WKD_MESSAGE_HEADER) + Message->Header.BodySize;

    switch (Message->Header.Type) {
    case WkdMessage_ProcessCreated:
        alpcMsgType = WkdAlpcMessage_ProcessCreate;
        break;
    case WkdMessage_ThreadCreated:
        alpcMsgType = WkdAlpcMessage_ThreadCreate;
        break;
    case WkdMessage_ThreadExited:
        alpcMsgType = WkdAlpcMessage_ThreadExit;
        break;
    case WkdMessage_ImageLoaded:
        alpcMsgType = WkdAlpcMessage_ImageLoad;
        break;
    case WkdMessage_ProcessExited:
        /* 与 WkdMessage_ProcessCreated 对称：进程退出事件上送 Agent。
         * 修复前漏写此分支，导致 ALPC 外层类型落入 WkdAlpcMsgUnknown(0)，
         * agent 路由表 [0x3001,0x300C] 不匹配而被丢弃（进程退出通知丢失）。 */
        alpcMsgType = WkdAlpcMessage_ProcessExit;   /* 0x3002 */
        break;
    case WkdMessage_SyscallOpenProcess:
    case WkdMessage_SyscallAllocateMemory:
    case WkdMessage_SyscallReadMemory:
    case WkdMessage_SyscallWriteMemory:
    case WkdMessage_SyscallCreateThread:
    case WkdMessage_SyscallMapSection:
    case WkdMessage_SyscallQueueApc:
    case WkdMessage_SyscallSetContextThread:
    case WkdMessage_SyscallProtectMemory:
    case WkdMessage_SyscallSuspendThread:
    case WkdMessage_SyscallResumeThread:
    case WkdMessage_SyscallAdjustPrivileges:
    case WkdMessage_SyscallDuplicateToken:
    case WkdMessage_SyscallSetInformationToken:
    case WkdMessage_SyscallImpersonateThread:
    case WkdMessage_SyscallUnmapSection:
    case WkdMessage_SyscallCreateSection:   /* SectionTracker Ǩ�� 2026-08 */
        /* ȫ�� syscall �¼�ͳһ�� WkdAlpcMessage_Syscall(0x3007) ���ͣ�
         * agent AlpcpRouteMessage ����ƥ��·�ɣ�0x3001-0x3009 ���䣩��
         * �ڲ��ٰ� WKD_MESSAGE.Header.Type ϸ���ȷַ���
         * 2026-08-06 ��ȫ��ԭ�� 4 ��ӳ�䣬���� syscall�����̲߳���/���Ʋ�����
         * �� default��WkdAlpcMsgUnknown��agent ·�ɶ�����
         * SyscallUnmapSection(0x1010) Ϊ PreAcquireSection Ǩ�� 2026-08 ������ */
        alpcMsgType = WkdAlpcMessage_Syscall;
        break;
    case WkdMessage_HandleScan:
        alpcMsgType = WkdAlpcMessage_HandleScanResult;
        break;
    case WkdMessage_FileWrite:
    case WkdMessage_FileRename:
    case WkdMessage_FileDelete:
    case WkdMessage_SectionMap:
        /* �ļ������¼�ͳһ�� WkdAlpcMessage_FileEvent(0x300A) ����
         * ��FBE Ǩ�� 2026-08����FileCreate �������ߣ�PreCreate �� YARA FLT
         * �˿ڶ��� ALPC�������ڴ�ӳ�䡣
         * SectionMap(0x1308) Ϊ����ִ��ӳ���⣨PreAcquireSection Ǩ��
         * 2026-08���������ļ��¼��飬agent �� Header.Type ϸ�ַ��� */
        alpcMsgType = WkdAlpcMessage_FileEvent;
        break;
    case WkdMessage_FileRollbackResult:
        /* �ع������ WkdAlpcMessage_FileRollbackResult(0x300B) ���� */
        alpcMsgType = WkdAlpcMessage_FileRollbackResult;
        break;
    case WkdMessage_NamedPipeCreate:
        /* �����ܵ������� WkdAlpcMessage_NamedPipeEvent(0x300C) ����
         * ��NamedPipeMonitor Ǩ�� 2026-08����agent AlpcpRouteMessage ��
         * 0x3001-0x300C ����·�ɣ��ڲ��� WKD_MESSAGE.Header.Type=0x1307
         * ϸ���ȷַ���NtfWkdMessageParse �� WkdEvent_NamedPipeCreate���� */
        alpcMsgType = WkdAlpcMessage_NamedPipeEvent;
        break;
    case WkdMessage_AmsiBypassDetected:
        alpcMsgType = WkdAlpcMessage_AmsiBypass;
        break;
    default:
        alpcMsgType = WkdAlpcMsgUnknown;
    }

    status = AlpcpAllocateMessage(
        &alpcMsg,
        alpcMsgType,
        STATUS_SUCCESS,
        FALSE,
        1,                          /* ItemCount = 1������ WKD_MESSAGE�� */
        (ULONG)exactSize,
        &data
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* �� WKD_MESSAGE ��ȷ��С������ ALPC ���� Data �� */
    RtlCopyMemory(data, Message, exactSize);

    status = AlpcSendMessage(&WkdDefaultAlpcServer, alpcMsg);
    AlpcpFreeMessage(alpcMsg);

    return status;
}

/**************************************************/
/*    ����ת�� WKD_MESSAGE ���鵽 Agent             */
/**************************************************/

_Use_decl_annotations_
NTSTATUS
AlpcSendWkdMessageBatch(
    _In_ WKD_ALPC_MESSAGE_TYPE  AlpcMsgType,
    _In_ PWKD_MESSAGE           *Messages,
    _In_ ULONG                  MessageCount
    )
/*++
Routine Description:
    ����������� WKD_MESSAGE ˳������һ�� ALPC ��Ϣ�����͵� Agent��
    ÿ�� WKD_MESSAGE ���԰��������� Header + Body����������һ��������¼��

    ���ݲ���:
        ALPC Data = [WKD_MESSAGE#0][WKD_MESSAGE#1]...[WKD_MESSAGE#N-1]
        ALPC ItemCount = MessageCount

Arguments:
    AlpcMsgType  �� ALPC ��Ϣ���͡�
    Messages     �� WKD_MESSAGE ָ�����顣
    MessageCount �� ���鳤�ȡ�

Return Value:
    NTSTATUS��
--*/
{
    NTSTATUS status;
    PWKD_ALPC_MESSAGE alpcMsg = NULL;
    PVOID data = NULL;
    SIZE_T totalDataSize = 0;
    ULONG i;

    if (!Messages || MessageCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    /* ȷ�� Agent ������ */
    if (!WkdDefaultAlpcServer.AgentPort) {
        status = AlpcpConnectToAgent(&WkdDefaultAlpcServer);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[WkDefender] Failed to connect to Agent for batch forwarding: 0x%X\n",
                status);
            return status;
        }
    }

    /* ���������ݴ�С */
    for (i = 0; i < MessageCount; i++) {
        totalDataSize += sizeof(WKD_MESSAGE_HEADER) + Messages[i]->Header.BodySize;
    }

    status = AlpcpAllocateMessage(
        &alpcMsg,
        AlpcMsgType,
        STATUS_SUCCESS,
        FALSE,
        MessageCount,
        (ULONG)totalDataSize,
        &data
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* �������� WKD_MESSAGE �� ALPC ������ */
    PUCHAR cursor = (PUCHAR)data;
    for (i = 0; i < MessageCount; i++) {
        SIZE_T msgSize = sizeof(WKD_MESSAGE_HEADER) + Messages[i]->Header.BodySize;

        RtlCopyMemory(cursor, Messages[i], msgSize);
        cursor += msgSize;
    }

    status = AlpcSendMessage(&WkdDefaultAlpcServer, alpcMsg);
    AlpcpFreeMessage(alpcMsg);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] Batch sent: %u messages, %Iu bytes, status=0x%X\n",
        MessageCount, totalDataSize, status);

    return status;
}
