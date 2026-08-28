/**************************************************/
/*  WkDefender Agent — YARA FLT 端口客户端 (步骤 4)  */
/**************************************************/

#include "YaraScanPort.h"
#include "../WkDefenderHeader.h"

/* 链接 fltlib（用户态 minifilter 通信客户端） */
#pragma comment(lib, "fltlib.lib")

/* libyara 由 External/yara/ 提供，始终启用。 */

#define WKD_YARA_PORT_NAME_CLIENT  L"\\WkDefenderYaraPort"
#define WKD_YARA_CLIENT_MSG_SIZE   4096   /* 与内核 WKD_YARA_PORT_MSG_SIZE 一致 */
#define WKD_YARA_CONNECT_RETRY_MS  2000   /* 端口未就绪重试间隔 */

/* 停止事件（由主线程在退出时置位） */
static HANDLE g_StopEvent = NULL;

/*++
 * YaraScanPort_Connect
 *   连接内核 YARA 通信端口。端口不存在时返回 NULL（调用方按重试处理）。
 *   参考 Filter.cpp::ConnectToDriver（行 411）。
 *--*/
static HANDLE YaraScanPort_Connect(VOID)
{
    HANDLE hPort = INVALID_HANDLE_VALUE;
    HRESULT hr = FilterConnectCommunicationPort(
        WKD_YARA_PORT_NAME_CLIENT,
        FLT_PORT_FLAG_SYNC_HANDLE,
        NULL,
        0,
        NULL,
        &hPort);
    if (FAILED(hr)) {
        if (HRESULT_CODE(hr) == ERROR_FILE_NOT_FOUND) {
            /* 驱动未加载或端口未创建，等待重试 */
            return INVALID_HANDLE_VALUE;
        }
        printf("[YaraScanPort] Connect failed: 0x%08X\n", hr);
        return INVALID_HANDLE_VALUE;
    }
    printf("[YaraScanPort] Connected to driver port\n");
    return hPort;
}

/*++
 * YaraScanPort_ThreadProc
 *   单线程消息循环（D4 决策）：连接 → FilterGetMessage 阻塞收请求 →
 *   调 IocYara_ScanFile → FilterReplyMessage 回 verdict。
 *   参考 Filter.cpp::MessageLoop（行 515）。
 *--*/
DWORD WINAPI YaraScanPort_ThreadProc(_In_ LPVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);

    HANDLE hPort = INVALID_HANDLE_VALUE;

    for (;;) {
        /* 停止检查 */
        if (g_StopEvent) {
            if (WaitForSingleObject(g_StopEvent, 0) == WAIT_OBJECT_0) {
                break;
            }
        }

        /* 连接（含重试） */
        if (hPort == INVALID_HANDLE_VALUE) {
            hPort = YaraScanPort_Connect();
            if (hPort == INVALID_HANDLE_VALUE) {
                if (g_StopEvent &&
                    WaitForSingleObject(g_StopEvent, WKD_YARA_CONNECT_RETRY_MS) == WAIT_OBJECT_0) {
                    break;
                }
                continue;
            }
        }

        /* 分配消息缓冲：FILTER_MESSAGE_HEADER + 应用数据 */
        BYTE buffer[WKD_YARA_CLIENT_MSG_SIZE];
        PFILTER_MESSAGE_HEADER msg = (PFILTER_MESSAGE_HEADER)buffer;
        RtlZeroMemory(buffer, sizeof(FILTER_MESSAGE_HEADER));

        HRESULT hr = FilterGetMessage(hPort, msg, sizeof(buffer), NULL);
        if (FAILED(hr)) {
            if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) ||
                hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
                /* 端口被驱动关闭，断开重连 */
                printf("[YaraScanPort] Port closed by driver, reconnecting...\n");
                CloseHandle(hPort);
                hPort = INVALID_HANDLE_VALUE;
                continue;
            }
            /* 其他错误：短暂退避后继续 */
            printf("[YaraScanPort] FilterGetMessage failed: 0x%08X\n", hr);
            if (g_StopEvent &&
                WaitForSingleObject(g_StopEvent, WKD_YARA_CONNECT_RETRY_MS) == WAIT_OBJECT_0) {
                break;
            }
            continue;
        }

        /* 应用数据 = FILTER_MESSAGE_HEADER 之后 */
        PWKD_YARA_SCAN_REQUEST req =
            (PWKD_YARA_SCAN_REQUEST)(buffer + sizeof(FILTER_MESSAGE_HEADER));

        if (req->MsgType != WkdYaraMsg_ScanRequest) {
            /* 未知消息类型，回 Allow 不阻塞 */
            printf("[YaraScanPort] Unknown msg type 0x%X\n", req->MsgType);
            continue;
        }

        /* 取出路径（变长，PathLength 为字符数） */
        WCHAR pathBuf[DEF_MAX_PATH] = { 0 };
        USHORT copyChars = req->PathLength;
        if (copyChars >= DEF_MAX_PATH) copyChars = DEF_MAX_PATH - 1;
        if (copyChars > 0) {
            RtlCopyMemory(pathBuf, req->Path, copyChars * sizeof(WCHAR));
        }
        pathBuf[copyChars] = L'\0';

        /* 调机制 A 同步扫描 */
        BOOLEAN detected = FALSE;
        ULONG score = 0;
        WCHAR ruleName[128] = {0};
        IocYara_ScanFile(pathBuf, &detected, &score, ruleName, ARRAYSIZE(ruleName));

        /* 构造 reply：FILTER_REPLY_HEADER + WKD_YARA_SCAN_VERDICT */
        WKD_YARA_REPLY reply;
        RtlZeroMemory(&reply, sizeof(reply));
        reply.Header.Status = 0;
        reply.Header.MessageId = msg->MessageId;   /* 必须对应收到的消息 */
        reply.Verdict.MsgType   = WkdYaraMsg_ScanVerdict;
        reply.Verdict.RequestId = req->RequestId;
        reply.Verdict.Verdict   = detected ? WkdYaraVerdict_Deny : WkdYaraVerdict_Allow;
        reply.Verdict.Score     = score;

        HRESULT hrReply = FilterReplyMessage(hPort, (PFILTER_REPLY_HEADER)&reply, sizeof(reply));
        if (FAILED(hrReply)) {
            printf("[YaraScanPort] FilterReplyMessage failed: 0x%08X (req=%u)\n",
                   hrReply, req->RequestId);
        } else if (detected) {
            printf("[YaraScanPort] DENY %S rule=%S score=%u\n",
                   pathBuf, ruleName, score);
        }
    }

    if (hPort != INVALID_HANDLE_VALUE) {
        CloseHandle(hPort);
    }
    printf("[YaraScanPort] Thread exited\n");
    return 0;
}

/*++
 * YaraScanPort_Start
 *   创建停止事件并启动端口客户端线程。返回线程句柄（调用方负责在退出时
 *   置位 StopEvent 并等待线程）。
 *   参数 StopEvent：外部创建的停止事件（可 NULL，则线程仅在端口致命错误时退出）。
 *--*/
HANDLE YaraScanPort_Start(_In_opt_ HANDLE StopEvent)
{
    g_StopEvent = StopEvent;
    HANDLE hThread = CreateThread(
        NULL, 0, YaraScanPort_ThreadProc, NULL, 0, NULL);
    if (!hThread) {
        printf("[YaraScanPort] Failed to create thread\n");
    }
    return hThread;
}
