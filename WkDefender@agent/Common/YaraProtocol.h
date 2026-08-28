/**************************************************/
/*  WkDefender YARA FLT 端口协议 — 驱动/Agent 共享   */
/*  所有结构定义必须与内核态和用户态兼容               */
/*  维护说明：改此文件后必须同步更新两侧引用方          */
/**************************************************/

#pragma once

/*
 * 本头文件被两侧包含：
 *   - 驱动侧：Filter.h（内核态，fltKernel.h/ntifs.h）
 *   - Agent 侧：YaraScanPort.h（用户态，windows.h/fltUser.h）
 * 故仅使用两边均可用的基础类型（ULONG/USHORT/WCHAR/enum 等）。
 */

#ifdef __cplusplus
extern "C" {
#endif

/* FLT 通信端口名（承载 YARA 文件扫描同步回路） */
#define WKD_YARA_PORT_NAME        L"\\WkDefenderYaraPort"
#define WKD_YARA_PORT_MAX_CONNECT 1
#define WKD_YARA_PORT_MSG_SIZE    4096

/* 同步文件扫描超时（100ms，fail-open：超时/未连接则放行） */
#define WKD_YARA_SCAN_TIMEOUT_MS  100

/* 消息类型枚举 */
typedef enum _WKD_YARA_MSG_TYPE {
    WkdYaraMsg_ScanRequest = 0x01,   /* 驱动 PreCreate → Agent：请求扫描文件 */
    WkdYaraMsg_ScanVerdict = 0x02,   /* Agent → 驱动：返回扫描裁决 */
} WKD_YARA_MSG_TYPE, *PWKD_YARA_MSG_TYPE;

/* 扫描请求（驱动 → Agent，变长结构） */
typedef struct _WKD_YARA_SCAN_REQUEST {
    WKD_YARA_MSG_TYPE MsgType;       /* = WkdYaraMsg_ScanRequest */
    ULONG             RequestId;     /* 递增 ID，匹配 verdict */
    ULONG             ProcessId;     /* 发起文件操作的进程 PID */
    USHORT            PathLength;    /* 路径字符数（不含 NUL） */
    WCHAR             Path[ANYSIZE_ARRAY]; /* 变长文件路径 */
} WKD_YARA_SCAN_REQUEST, *PWKD_YARA_SCAN_REQUEST;

/* Verdict 枚举 */
typedef enum _WKD_YARA_VERDICT {
    WkdYaraVerdict_Allow = 0,        /* 放行 */
    WkdYaraVerdict_Deny  = 1,        /* 拒绝 */
} WKD_YARA_VERDICT, *PWKD_YARA_VERDICT;

/* 扫描裁决（Agent → 驱动） */
typedef struct _WKD_YARA_SCAN_VERDICT {
    WKD_YARA_MSG_TYPE MsgType;       /* = WkdYaraMsg_ScanVerdict */
    ULONG             RequestId;     /* 对应请求 ID */
    WKD_YARA_VERDICT  Verdict;       /* Allow=0, Deny=1 */
    ULONG             Score;         /* 0-100 威胁评分 */
} WKD_YARA_SCAN_VERDICT, *PWKD_YARA_SCAN_VERDICT;

/* 注意：WKD_YARA_REPLY（FILTER_REPLY_HEADER + WKD_YARA_SCAN_VERDICT）
 * 仅用于 Agent 侧 FilterReplyMessage，不在本共享头中定义。 */

#ifdef __cplusplus
}
#endif
