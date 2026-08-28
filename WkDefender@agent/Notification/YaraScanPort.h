/**************************************************/
/*  WkDefender Agent — YARA FLT 端口客户端 (步骤 4)  */
/**************************************************/

/*
 * 职责：
 *   用户态 FLT 通信端口客户端，与内核驱动的独立 YARA 端口
 *   \\WkDefenderYaraPort 对接（DEC-02 = X1 模型），接收 PreCreate 触发的
 *   同步文件扫描请求，调机制 A（libyara，IocYara_ScanFile）扫描，回 verdict。
 *
 * 通信配对（必须与内核侧一致）：
 *   内核 FltSendMessage(SenderBuffer=WKD_YARA_SCAN_REQUEST, ReplyBuffer=WKD_YARA_SCAN_VERDICT)
 *   用户态 FilterGetMessage 收 [FILTER_MESSAGE_HEADER + WKD_YARA_SCAN_REQUEST]
 *   用户态 FilterReplyMessage 回 [FILTER_REPLY_HEADER + WKD_YARA_SCAN_VERDICT]
 *
 * 参考 PhantomSensor：
 *   src/PhantomCore/RealTime/Filter.cpp
 *     - ConnectToDriver（FilterConnectCommunicationPort，行 411）
 *     - MessageLoop（FilterGetMessage 同步循环，行 515）
 *   单线程模型（D4 决策）：简化、匹配 fail-open 需求，避免 IOCP 复杂度。
 *
 * 链接：fltlib.lib（#pragma comment 见 .c）；libyara 由使用者自供（DEC-01）。
 */

#pragma once

#include <windows.h>
#include <fltUser.h>
#include "../IOC/IocYaraScanner.h"

/* 共享协议头（与驱动 Filter.h 共用，字段定义单源） */
#include "../Common/YaraProtocol.h"

/* FilterReplyMessage 的 reply 缓冲 = FILTER_REPLY_HEADER + verdict */
typedef struct _WKD_YARA_REPLY {
    FILTER_REPLY_HEADER   Header;      /* Status=0, MessageId=收到的 MessageId */
    WKD_YARA_SCAN_VERDICT Verdict;
} WKD_YARA_REPLY, *PWKD_YARA_REPLY;

/*====================================================================*/
/*  接口                                                */
/*====================================================================*/

/*++
 * YaraScanPort_ThreadProc
 *   端口客户端线程体（阻塞消息循环），由 YaraScanPort_Start 创建。
 *--*/
DWORD WINAPI YaraScanPort_ThreadProc(_In_ LPVOID Parameter);

/*++
 * YaraScanPort_Start
 *   创建并启动端口客户端线程。StopEvent 用于通知线程退出（可 NULL）。
 *   返回线程句柄；调用方在退出时置位 StopEvent 并等待该线程结束。
 *--*/
HANDLE YaraScanPort_Start(_In_opt_ HANDLE StopEvent);
