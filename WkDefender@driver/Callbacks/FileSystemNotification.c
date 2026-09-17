/* ============================================================================
 * FileSystemNotification.c
 *   WkDefender 文件系统回调薄层（拆分自 FileSystem\Filter.c，2026-09）。
 *
 *   架构分层（2026-09 拆分决策/2026-10 微调）：
 *     Callbacks\FileSystemNotification  = 本文件：minifilter 注册 + 回调壳 + FLT
 *       YARA 端口 + 事件上送（薄层，不含判定逻辑）
 *     FileSystem\FileScan            = 静态/统计分析能力（路径/蜜罐/速率/排除）
 *     FileSystem\ProcessFileContext  = 勒索行为评分（AeReportIndicatorPair 链）
 *     FileSystem\USBDeviceControl    = 只读卷写保护 + autorun 阻断（已接线）
 *     FileSystem\PreSetInformation   = SetInformation 前置回调流水线（2026-10
 *       自本薄层提取：FsPreSetInformationNotifyCallback + 备份豁免 FspIsBackupDirPath 迁入，
 *       事件上送原语 FspSendFileEvent 去 static 保留于薄层并经公共头共用）
 *     FileSystem\PreCreate           = Create 前置回调流水线（2026-10 提取，与
 *       PreSetInformation 同批：CbpPreCreateNotifyCallback 迁入并补齐 SS 语义
 *       ——排除/自保护/autorun/boot/本地评分。薄层操作表 IRP_MJ_CREATE 经
 *       公共头十二分区直接引用 FsPreCreateNotifyCallback）
 *     FileSystem\PreWrite            = Write 前置回调流水线（2026-10 提取：
 *       FspPreWrite 迁入（FsPreWriteNotifyCallback），私有辅助 FspQueryFileId
 *       （原 WkdFspQueryFileId）随迁。薄层操作表 IRP_MJ_WRITE 经公共头
 *       十三分区直接引用 FsPreWriteNotifyCallback）
 *
 *   相对原 Filter.c 的改动：
 *     ① UDC 三处 TODO 全部激活：InstanceSetup/TeardownComplete → WkdUdc*；
 *        PreWrite → WkdUdcIsWriteBlocked；PreSetInfo → WkdUdcIsSetInfoBlocked。
 *     ② 新增 FspPreCleanup（用户决策②：简化重扫，不挂 stream context，对
 *        可扫描扩展名直接 YARA 重扫），操作表 5 → 6 项。
 *     ③ 勒索评分接线：PreWrite → WkdPfcpNotifyFileOperation(Write)；
 *        PreSetInfo Rename/Delete/Truncate → WkdPfcpNotifyFileOperation。
 *     ④ 删除：WkdFspCacheRemove 缓存失效块（缓存未启用）、
 *        WkdFspShouldLogOperation 限速、死代码分区（B1/B3/B4/B6/B7/B8.x/
 *        B9/B10 作用域分类/分区 C 勒索评分——评分职责移交 ProcessFileContext）。
 *     ⑤ WkdFspProcessNotify、活动表、蜜罐 canary 等分析原语移交 FileScan。
 *     ⑥ 文件事件标志 WKD_FS_FILE_FLAG_* 原保留在本薄层（事件上送层语义）；
 *        2026-10 PreSetInformation 提取时上移公共头（薄层+能力模块共用）。
 *     ⑦ 2026-10 PreCreate 迁移：CbpPreCreateNotifyCallback 判定主体迁入
 *        FileSystem\PreCreate.c（FsPreCreateNotifyCallback），薄层操作表
 *        IRP_MJ_CREATE 引用改为公共头十二分区声明。
 *     ⑧ 2026-10 PreWrite 迁移：FspPreWrite 判定主体迁入
 *        FileSystem\PreWrite.c（FsPreWriteNotifyCallback），私有辅助
 *        WkdFspQueryFileId 随迁改名 FspQueryFileId；薄层操作表 IRP_MJ_WRITE
 *        引用改为公共头十三分区声明。事件上送原语 FspSendFileEvent 仍留薄层。
 * ========================================================================== */

#include <ntddk.h>
#include <fltkernel.h>

#include "FileSystemNotification.h"          /* 薄层自身导出面（瘦身后仅 include 公共头） */
#include "../Include/FileSystem.h"           /* 对外公共头：能力模块 API + 薄层导出声明（2026-09-13 重构） */
#include "../Notification/NotificationManager.h"
#include "../AnalysisEngine/AnalysisEngine.h" /* AepIsCriticalProcess / AeReportIndicatorPair（2026-10 补） */
#include "../Common/Utils.h"                 /* 通用工具（Utils.h 位于 Common\ 根，2026-10 修正路径） */
#include "../Common/Exempts/Exempts.h"
#include "../ThreatScoring/ThreatScoring.h"

/**************************************************/
/*                   全局状态                      */
/**************************************************/

/* minifilter 句柄（FBE FltCreateFileEx 依赖，WkdFsGetFilterHandle 返回） */
PFLT_FILTER WkdFileSystemFilter = NULL;

/* YARA FLT 通信端口（服务端/客户端）与连接 PID 防递归 */
static PFLT_PORT WkdFltServerPort = NULL;
static PFLT_PORT g_FsClientPort = NULL;
static volatile LONG g_FsConnectedPid = 0;
static FAST_MUTEX g_FsPortLock;

/* 命名管道阻断门控：默认关闭（仅上报+评分），避免系统管道表误伤 RPC 子系统 */
static BOOLEAN g_NpmBlockingEnabled = FALSE;

/* PsGetProcessImageFileName 可能未在所有 WDK 配置声明，导出自 ntoskrnl */
extern PUCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

/**************************************************/
/*              可扫描扩展名集合（YARA 范围）        */
/**************************************************/

/* 对齐 phantom_sensor / 原 Filter.c g_FsScannableExtensions（含文档/图片/压缩/执行）
 * 注：这是 agent 侧 YARA 扫描的"驱动白名单"，不是威胁判定依据。 */
typedef struct _FSF_EXTENSION_ENTRY {
    PCWSTR Extension;
} FSF_EXTENSION_ENTRY, *PFSF_EXTENSION_ENTRY;

static const FSF_EXTENSION_ENTRY g_FsScannableExtensions[] = {
    { L"doc"   }, { L"docx"  }, { L"xls"  }, { L"xlsx" },
    { L"ppt"   }, { L"pptx"  }, { L"pdf"  }, { L"rtf"  },
    { L"txt"   }, { L"csv"   }, { L"log"  }, { L"zip"  },
    { L"rar"   }, { L"7z"    }, { L"tar"  }, { L"gz"   },
    { L"exe"   }, { L"dll"   }, { L"sys"  }, { L"bin"  },
    { L"msi"   }, { L"bat"   }, { L"cmd"  }, { L"ps1"  },
    { L"vbs"   }, { L"js"    }, { L"jse"  }, { L"wsf"  },
    { L"hta"   }, { L"scr"   }, { L"com"  }, { L"pif"  },
    { L"cpl"   }, { L"ocx"   }, { L"drv"  }, { L"efi"  },
    { L"apk"   }, { L"jar"   }, { L"py"   }, { L"pl"   },
    { L"sh"    }, { L"php"   }, { L"asp"  }, { L"aspx" },
    { L"dat"   }, { L"db"    }, { L"mdb"  }, { L"sql"  },
    { L"xml"   }, { L"html"  }, { L"htm"  }, { L"mht"  },
    { L"eml"   }, { L"msg"   }, { L"png"  }, { L"jpg"  },
    { L"jpeg"  }, { L"gif"   }, { L"bmp"  }, { L"ico"  },
    { NULL }
};

/* code-bearing 子集（PcClassifyFile Executable/Script/Document/Archive
 * 分类，G2 扫描范围收敛 2026-09）：41 项 =
 *   执行 14（exe dll sys bin msi scr com pif cpl ocx drv efi apk jar）
 *  + 脚本 14（bat cmd ps1 vbs js jse wsf hta py pl sh php asp aspx）
 *  + 文档 8（doc docx xls xlsx ppt pptx pdf rtf）
 *  + 压缩 5（zip rar 7z tar gz）
 * 说明：txt/csv/log/图片/数据库/网页/邮件等惰性数据类不在集合内——这些是
 * Explorer 枚举/缩略图高频纯读对象，阻塞扫描会序列化系统 I/O（SS 观察到的
 * 系统级停顿根因），由写与执行时扫描覆盖。 */
static const FSF_EXTENSION_ENTRY g_FsCodeBearingExtensions[] = {
    /* 执行 */
    { L"exe"   }, { L"dll"   }, { L"sys"  }, { L"bin"  }, { L"msi"  },
    { L"scr"   }, { L"com"   }, { L"pif"  }, { L"cpl"  }, { L"ocx"  },
    { L"drv"   }, { L"efi"   }, { L"apk"  }, { L"jar"  },
    /* 脚本 */
    { L"bat"   }, { L"cmd"   }, { L"ps1"  }, { L"vbs"  }, { L"js"   },
    { L"jse"   }, { L"wsf"   }, { L"hta"  }, { L"py"   }, { L"pl"   },
    { L"sh"    }, { L"php"   }, { L"asp"  }, { L"aspx" },
    /* 文档 */
    { L"doc"   }, { L"docx"  }, { L"xls"  }, { L"xlsx" },
    { L"ppt"   }, { L"pptx"  }, { L"pdf"  }, { L"rtf"  },
    /* 压缩 */
    { L"zip"   }, { L"rar"   }, { L"7z"   }, { L"tar"  }, { L"gz"   },
    { NULL }
};

/*++
 * FsIsScannableExtension
 *   扩展名命中可扫描集合（ASCII 大小写不敏感折叠比较，DISPATCH_LEVEL 安全）。
 *   仅做成员判定，不做威胁判定——fail-open 语义由调用方保证。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
FsIsScannableExtension(
    _In_ PCUNICODE_STRING Extension
    )
{
    ULONG i;
    ULONG j;
    USHORT extensionLength;

    if (Extension == NULL || Extension->Buffer == NULL || Extension->Length == 0) {
        return FALSE;
    }
    extensionLength = Extension->Length / sizeof(WCHAR);

    for (i = 0; g_FsScannableExtensions[i].Extension != NULL; i++) {
        PCWSTR candidate = g_FsScannableExtensions[i].Extension;
        ULONG candidateLength = (ULONG)wcslen(candidate);

        if (candidateLength != extensionLength) {
            continue;
        }
        for (j = 0; j < candidateLength; j++) {
            WCHAR a = (WCHAR)Extension->Buffer[j];
            WCHAR b = candidate[j];

            if (a >= L'a' && a <= L'z') a -= (L'a' - L'A');
            if (b >= L'a' && b <= L'z') b -= (L'a' - L'A');
            if (a != b) {
                break;
            }
        }
        if (j == candidateLength) {
            return TRUE;
        }
    }
    return FALSE;
}

/*++ 
 * FsIsCodeBearingExtension
 *   code-bearing 集合成员判定（PcClassifyFile 的 Executable/Script/
 *   Document/Archive 四类）。G2 扫描范围收敛（2026-09）：纯读访问且非
 *   code-bearing 时 FsPreCreateNotifyCallback（FileSystem\PreCreate.c）跳过
 *   同步扫描，防高频枚举阻塞系统 I/O。
 *   实现与 FsIsScannableExtension 对称（ASCII 折叠比较，DISPATCH_LEVEL 安全）。
 *--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
FsIsCodeBearingExtension(
    _In_ PCUNICODE_STRING Extension
    )
{
    ULONG i;
    ULONG j;
    USHORT extensionLength;

    if (Extension == NULL || Extension->Buffer == NULL || Extension->Length == 0) {
        return FALSE;
    }
    extensionLength = Extension->Length / sizeof(WCHAR);

    for (i = 0; g_FsCodeBearingExtensions[i].Extension != NULL; i++) {
        PCWSTR candidate = g_FsCodeBearingExtensions[i].Extension;
        ULONG candidateLength = (ULONG)wcslen(candidate);

        if (candidateLength != extensionLength) {
            continue;
        }
        for (j = 0; j < candidateLength; j++) {
            WCHAR a = (WCHAR)Extension->Buffer[j];
            WCHAR b = candidate[j];

            if (a >= L'a' && a <= L'z') a -= (L'a' - L'A');
            if (b >= L'a' && b <= L'z') b -= (L'a' - L'A');
            if (a != b) {
                break;
            }
        }
        if (j == candidateLength) {
            return TRUE;
        }
    }
    return FALSE;
}

/**************************************************/
/*              boot 窗口（防早期 I/O 洪泛）        */
/**************************************************/

#define WKD_FSF_BOOT_PHASE_MS        120000

static volatile LONG g_FsBootPhaseActive = TRUE;

/* 一次性锁死的 boot 期判断（ShadowFsIsBootPhase）。
 * 导出：PostCreateContext 模块（FsPostCreateNotifyCallback boot 防御）依赖。 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WkdFspIsBootPhase(
    VOID
    )
{
    LARGE_INTEGER now;
    LONGLONG elapsedMs;

    if (ReadNoFence(&g_FsBootPhaseActive) == FALSE) {
        return FALSE;
    }
    now = KeQueryUnbiasedInterruptTime();
    elapsedMs = now.QuadPart / 10000;                      /* 100ns → ms */
    if (elapsedMs >= WKD_FSF_BOOT_PHASE_MS) {
        InterlockedExchange(&g_FsBootPhaseActive, FALSE); /* 过期一次性锁死 */
        return FALSE;
    }
    return TRUE;
}

/**************************************************/
/*             FLT 通信端口回调（YARA 回路 A）      */
/**************************************************/

/* 连接回调：仅允许单一主扫描客户端 + 记录 scanner PID 防递归死锁 */
static NTSTATUS
CbpFileSystemConnectNotifyCallback(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_ PVOID* ConnectionCookie
    )
{
    HANDLE pid;

    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    /* 仅允许单一主扫描客户端；重复连接拒绝（X1 模型） */
    ExAcquireFastMutex(&g_FsPortLock);
    if (g_FsClientPort != NULL) {
        ExReleaseFastMutex(&g_FsPortLock);
        return STATUS_CONNECTION_IN_USE;
    }

    /* 记录 scanner PID 防递归：连接进程自身触发的文件 I/O 不进入同步扫描回路，
     * 避免 scanner 打开/读取规则文件时递归回 PreCreate -> FltSendMessage 死锁。 */
    pid = PsGetCurrentProcessId();
    g_FsClientPort = ClientPort;
    InterlockedExchange(&g_FsConnectedPid, HandleToLong(pid));
    ExReleaseFastMutex(&g_FsPortLock);

    *ConnectionCookie = NULL;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] YARA FLT port connected (PID=%p)\n", pid);
    return STATUS_SUCCESS;
}

/* 断开回调：清空客户端端口与 scanner PID */
static VOID
CbpFileSystemDisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie
    )
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    ExAcquireFastMutex(&g_FsPortLock);
    g_FsClientPort = NULL;
    InterlockedExchange(&g_FsConnectedPid, 0);
    ExReleaseFastMutex(&g_FsPortLock);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[WkDefender] YARA FLT port disconnected\n");
}

/* 消息回调：本期同步 verdict 走 FltSendMessage reply，此回调仅保留扩展点 */
static NTSTATUS
CbpFileSystemMessageNotifyCallback(
    _In_opt_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    UNREFERENCED_PARAMETER(ClientPort);
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(ReturnOutputBufferLength);
    return STATUS_SUCCESS;
}

/**************************************************/
/*          FsSendYaraScanRequest（同步阻塞）      */
/**************************************************/

/*++
 * FsSendYaraScanRequest
 *   同步阻塞式文件扫描请求（回路 A 内核侧核心）。简化：去加密/HMAC；
 *   直接 FltSendMessage 阻塞 + fail-open。必须在 PASSIVE_LEVEL 调用。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
WKD_YARA_SCAN_VERDICT
FsSendYaraScanRequest(
    _In_ PUNICODE_STRING FilePath,
    _In_ ULONG ProcessId
    )
{
    NTSTATUS status;
    LARGE_INTEGER timeout;
    ULONG reqSize;
    ULONG replySize;
    PWKD_YARA_SCAN_REQUEST req = NULL;
    WKD_YARA_SCAN_VERDICT verdict;
    USHORT copyLen;
    static volatile LONG g_RequestId = 0;
    PUNICODE_STRING normPath = NULL;
    PFLT_PORT clientPort;

    /* fail-open 默认：未连接 / 超时 / 错误 均放行 */
    verdict.Verdict = WkdYaraVerdict_Allow;
    verdict.Score = 0;

    /* 未连接 agent（如 boot 早期）直接 fail-open，避免卡死创建 */
    ExAcquireFastMutex(&g_FsPortLock);
    clientPort = g_FsClientPort;
    if (clientPort == NULL) {
        ExReleaseFastMutex(&g_FsPortLock);
        return verdict;
    }
    ExReleaseFastMutex(&g_FsPortLock);

    /* scanner 自身触发的 I/O 豁免（防递归死锁） */
    if (HandleToULong(PsGetCurrentProcessId()) == (ULONG)ReadNoFence(&g_FsConnectedPid)) {
        return verdict;
    }

    /* 路径标准化：NT 设备路径 → DOS 路径（CoNormalizeDosPath 不发 IRP，无递归
     * 风险）。标准化失败则 fallback 到原始 NT 路径。 */
    CoNormalizeDosPath(FilePath, &normPath);

    /* 构造变长请求：WKD_YARA_SCAN_REQUEST + 路径 */
    copyLen = (normPath->Length > MAX_PATH * sizeof(WCHAR)) ?
              (MAX_PATH * sizeof(WCHAR)) : normPath->Length;
    reqSize = sizeof(WKD_YARA_SCAN_REQUEST) + copyLen;

    req = (PWKD_YARA_SCAN_REQUEST)ExAllocatePool2(
        POOL_FLAG_PAGED, reqSize, WKD_YARA_PORT_TAG);
    if (req == NULL) {
        if (normPath != NULL) {
            ExFreePoolWithTag(normPath->Buffer, 'upbp');
            ExFreePoolWithTag(normPath, 'upsp');
        }
        return verdict;   /* 内存不足，fail-open */
    }
    RtlZeroMemory(req, reqSize);

    req->MsgType    = WkdYaraMsg_ScanRequest;
    req->RequestId  = (ULONG)InterlockedIncrement(&g_RequestId);
    req->ProcessId  = ProcessId;
    req->PathLength = copyLen / sizeof(WCHAR);
    if (copyLen > 0) {
        RtlCopyMemory(req->Path, normPath->Buffer, copyLen);
    }

    /* 释放标准化路径缓冲（内容已复制到 req 中） */
    if (normPath != NULL) {
        ExFreePoolWithTag(normPath->Buffer, 'upbp');
        ExFreePoolWithTag(normPath, 'upsp');
    }

    replySize = sizeof(WKD_YARA_SCAN_VERDICT);
    timeout.QuadPart = -(LONGLONG)WKD_YARA_SCAN_TIMEOUT_MS * 10000LL;  /* 相对超时（100ns） */

    /* 用锁内捕获的 clientPort 副本发送，避免 DisconnectNotify 并发置 NULL */
    status = FltSendMessage(
        WkdFileSystemFilter,
        &clientPort,
        req,
        reqSize,
        &verdict,
        &replySize,
        &timeout
        );
    if (!NT_SUCCESS(status)) {
        /* 超时/端口断开等：fail-open 放行 */
        verdict.Verdict = WkdYaraVerdict_Allow;
        verdict.Score = 0;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender/FS] YARA scan request failed (fail-open): 0x%X\n", status);
    }

    if (req != NULL) {
        ExFreePoolWithTag(req, WKD_YARA_PORT_TAG);
    }
    return verdict;
}

/**************************************************/
/*             文件事件上送（0x1301-0x1306）       */
/**************************************************/

/*++
 * FspSendFileEvent
 *   备份处理完成后上送文件操作事件（Write/Rename/Delete）到 agent，
 *   供勒索行为检测（IoaRansomwareDetect）与因果图消费。
 *   OperationType 值对齐 WKD_FLT_OP_*（NotificationManager.h）。
 *   变长路径布局仿 WKD_MESSAGE_BODY_PROCESS_CREATE（Buffer 指向头后数据）。
 *   【迁移 2026-10】static 去除：声明入公共头，能力模块 PreSetInformation
 *   （FileSystem\PreSetInformation.c）共用事件上送层原语。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
VOID
FspSendFileEvent(
    _In_ ULONG OperationType,
    _In_ PCUNICODE_STRING FilePath,
    _In_ ULONG FileSize,
    _In_ ULONG FileEntropy,
    _In_ ULONG Flags,
    _In_ LONGLONG WriteOffset,
    _In_ ULONG BytesWritten,
    _In_ ULONG64 FileId
    )
{
    NTSTATUS status;
    PWKD_MESSAGE msg;
    PWKD_MESSAGE_BODY_FILE_EVENT body;
    WKD_MESSAGE_TYPE type;
    WKD_MESSAGE_PRIORITY priority;
    ULONG bodySize;
    USHORT copyLen;

    switch (OperationType) {
    case WKD_FLT_OP_RENAME:
        type = WkdMessage_FileRename;
        break;
    case WKD_FLT_OP_DELETE:
        type = (Flags & WKD_FS_FILE_FLAG_SHADOW_DELETE) ?
            WkdMessage_FileShadowCopyDelete : WkdMessage_FileDelete;
        break;
    case WKD_FLT_OP_TRUNCATE:
    case WKD_FLT_OP_HARDLINK:
    case WKD_FLT_OP_ATTRIBUTE:
        /* 截断/硬链接/属性复用 FileWrite 消息上送（零线格式变更），agent 按
         * payload->OperationType（3/4/5）区分。 */
        type = WkdMessage_FileWrite;
        break;
    case WKD_FLT_OP_WRITE:
    default:
        type = (Flags & WKD_FS_FILE_FLAG_CREATE) ?
            WkdMessage_FileCreate : WkdMessage_FileWrite;
        break;
    }

    /* 路径长度钳制（MAX_PATH 内），防 ALPC 缓冲越界 */
    copyLen = (FilePath->Length > MAX_PATH * sizeof(WCHAR)) ?
              (MAX_PATH * sizeof(WCHAR)) : FilePath->Length;

    bodySize = sizeof(WKD_MESSAGE_BODY_FILE_EVENT) + copyLen;

    /* 勒索速率异常（RAPID_RATE）→ 提升优先级，供 agent 及时处置 */
    priority = (Flags & WKD_FS_FILE_FLAG_RAPID_RATE) ?
        WkdMessage_PriorityHigh : WkdMessage_PriorityNormal;
    msg = NtfCreateMessage(type, WkdMessage_SourceFile, priority, bodySize);
    if (msg == NULL) {
        return;
    }

    body = (PWKD_MESSAGE_BODY_FILE_EVENT)msg->Body;
    body->ProcessId = PsGetCurrentProcessId();
    body->ThreadId = PsGetCurrentThreadId();
    body->OperationType = OperationType;
    body->FileSize = FileSize;
    body->WriteOffset = WriteOffset;
    body->BytesWritten = BytesWritten;
    body->FileId = FileId;
    body->FileEntropy = FileEntropy;
    body->Flags = Flags;
    KeQuerySystemTime(&body->Timestamp);
    body->FilePath.Buffer = (PWSTR)(body + 1);
    body->FilePath.Length = copyLen;
    body->FilePath.MaximumLength = copyLen;
    RtlCopyMemory(body->FilePath.Buffer, FilePath->Buffer, copyLen);

    status = NtfSendMessageAsync(msg);
    if (!NT_SUCCESS(status)) {
        NmFreeMessage(msg);
    }
}

/**************************************************/
/*        PreCleanup 回调（简化 YARA 重扫，新增）   */
/**************************************************/

/*++
 * FspPreCleanup
 *   Cleanup 重扫（用户决策②，2026-09）：文件生命周期终点前的最后一次 YARA
 *   重扫窗口——恶意内容可能在打开期间写入、PreCreate 扫描时未检出（如先以
 *   无扩展名句柄打开再改名）。
 *
 *   wkd 简化版（决策②）：不挂 stream context / 不跟踪 Dirty 位，直接对可扫描
 *   扩展名同步 YARA 重扫（成本由 FsIsScannableExtension 前置过滤 + scanner
 *   自身豁免控制）；命中 Deny → STATUS_ACCESS_DENIED（最后一次句柄引用处
 *   完成 I/O 前阻断）。
 *   语义对齐 PhantomSensor ShadowStrikePreCleanup（FilterRegistration.c L588+）。
 *--*/
_IRQL_requires_(PASSIVE_LEVEL)
static
FLT_PREOP_CALLBACK_STATUS
FspPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    UNICODE_STRING extension;
    WKD_YARA_SCAN_VERDICT verdict;

    *CompletionContext = NULL;

    /* 内核模式 / 系统进程 / 可信进程放行（对齐 PreCreate 快速跳过） */
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (PsGetCurrentProcessId() == (HANDLE)4 ||
        ExemptsIsProcessTrusted(PsGetCurrentProcessId())) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* boot 期跳过（防早期句柄洪泛重扫） */
    if (WkdFspIsBootPhase()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    RtlInitUnicodeString(&extension, nameInfo->Extension.Buffer);
    extension.Length = nameInfo->Extension.Length;
    if (!FsIsScannableExtension(&extension)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* verdict 缓存有效（Scanned && !Dirty）→ 免 cleanup 重扫（PostCreate 迁移
     * 2026-09：Windows 处理 PreCreate 直接重扫，但非全部 create 均经 FltMgr
     * 且部分创建已被 PreCreate 扫过，此处命中率不低）。 */
    if (WkdPocHasFreshVerdict(FltObjects)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    verdict = FsSendYaraScanRequest(
        &nameInfo->Name,
        HandleToULong(PsGetCurrentProcessId()));

    if (verdict.Verdict == WkdYaraVerdict_Deny) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[WkDefender/FS] BLOCKED cleanup rescan: %wZ (PID=%lu)\n",
            &nameInfo->Name, HandleToULong(PsGetCurrentProcessId()));
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/**************************************************/
/*        命名管道创建回调（NamedPipeMonitor）      */
/**************************************************/

/* 创建者镜像名捕获（PsGetProcessImageFileName 15 字符，NpmGetCreatorImageName） */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
WkdFspGetCreatorImageName(
    _In_ PEPROCESS Process,
    _Out_writes_(16) PCHAR ImageNameOut
    )
{
    PUCHAR imageName;

    if (Process == NULL) {
        ImageNameOut[0] = '\0';
        return;
    }
    imageName = PsGetProcessImageFileName(Process);
    if (imageName != NULL) {
        RtlCopyMemory(ImageNameOut, imageName, 15);
        ImageNameOut[15] = '\0';
    } else {
        ImageNameOut[0] = '\0';
    }
}

/* 管道分类 → TsIndicator（severity 经 AeReportIndicatorPair 内部查 G_IocSeverityMap） */
static TS_INDICATOR_TYPE
WkdFspPipeClassToIndicator(
    _In_ WKD_NPM_PIPE_CLASS Classification
    )
{
    if (Classification == WkdNpmClass_SpoofedSystem) {
        return TsIndicator_Network_NamedPipeSpoof;
    }
    if (Classification >= WkdNpmClass_C2_CobaltStrike &&
        Classification <= WkdNpmClass_C2_Generic) {
        return TsIndicator_Network_NamedPipeC2;
    }
    if (Classification == WkdNpmClass_HighEntropy) {
        return TsIndicator_Network_NamedPipeHighEntropy;
    }
    return TsIndicator_Unknow;
}

/* 命名管道事件上送（仿 FspSendFileEvent，变长路径 Buffer=body+1）。仅分类命中调用 */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
FspSendNamedPipeEvent(
    _In_ HANDLE ProcessId,
    _In_ PCWSTR PipeName,
    _In_ USHORT NameLengthBytes,
    _In_ PCSTR CreatorImageName,
    _In_ WKD_NPM_PIPE_CLASS Classification,
    _In_ ULONG ThreatScore,
    _In_ BOOLEAN WasBlocked
    )
{
    NTSTATUS status;
    PWKD_MESSAGE msg;
    PWKD_MESSAGE_BODY_NAMED_PIPE body;
    ULONG bodySize;

    bodySize = sizeof(WKD_MESSAGE_BODY_NAMED_PIPE) + NameLengthBytes;
    msg = NtfCreateMessage(WkdMessage_NamedPipeCreate, WkdMessage_SourceFile,
                           WkdMessage_PriorityNormal, bodySize);
    if (msg == NULL) {
        return;
    }

    body = (PWKD_MESSAGE_BODY_NAMED_PIPE)msg->Body;
    body->ProcessId = ProcessId;
    body->ThreadId = PsGetCurrentThreadId();
    body->Classification = (ULONG)Classification;
    body->ThreatLevel = (ULONG)WkdNpmClassToThreatLevel(Classification, ThreatScore);
    body->ThreatScore = ThreatScore;
    body->Flags = WasBlocked ? 1 : 0;
    RtlCopyMemory(body->CreatorImageName, CreatorImageName, 16);
    body->PipeName.Buffer = (PWSTR)(body + 1);
    body->PipeName.Length = NameLengthBytes;
    body->PipeName.MaximumLength = NameLengthBytes;
    RtlCopyMemory(body->PipeName.Buffer, PipeName, NameLengthBytes);

    status = NtfSendMessageAsync(msg);
    if (!NT_SUCCESS(status)) {
        NmFreeMessage(msg);
        WkdNpmNoteEventDropped();
    } else {
        WkdNpmNoteEventQueued();
    }
}

/* Pre-op：命名管道创建检测（分类→阻断→评分→上送） */
_Use_decl_annotations_
static
FLT_PREOP_CALLBACK_STATUS
CbpPreCreateNotifyCallbackPipe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    WCHAR pipeName[WKD_NPM_MAX_PIPE_NAME_CCH];
    USHORT nameBytes = 0;
    CHAR creatorImage[16];
    WKD_NPM_PIPE_CLASS cls;
    ULONG threatScore = 0;
    HANDLE pid;
    TS_INDICATOR_TYPE indicator;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    /* 未激活（未初始化/boot 期）跳过 */
    if (!WkdNpmIsActive()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 内核模式请求跳过（对齐 FsPreSetInformationNotifyCallback KernelMode 跳过） */
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    pid = PsGetCurrentProcessId();

    /* 排除豁免：可信进程跳过分析（ExemptsIsProcessTrusted） */
    if (ExemptsIsProcessTrusted(pid)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 提取管道名（FinalComponent = \Device\NamedPipe\ 之后的部分） */
    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    if (nameInfo->FinalComponent.Length == 0 ||
        nameInfo->FinalComponent.Buffer == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    nameBytes = nameInfo->FinalComponent.Length;
    if (nameBytes > (WKD_NPM_MAX_PIPE_NAME_CCH - 1) * sizeof(WCHAR)) {
        nameBytes = (WKD_NPM_MAX_PIPE_NAME_CCH - 1) * sizeof(WCHAR);
    }
    RtlCopyMemory(pipeName, nameInfo->FinalComponent.Buffer, nameBytes);
    pipeName[nameBytes / sizeof(WCHAR)] = L'\0';
    FltReleaseFileNameInformation(nameInfo);

    if (nameBytes == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 创建者镜像名 */
    WkdFspGetCreatorImageName(PsGetCurrentProcess(), creatorImage);

    /* 分类引擎（内部：系统管道验证[限速豁免] → 限速 → C2/熵分类 → 统计） */
    cls = WkdNpmPreCreateNamedPipe(pipeName, nameBytes, creatorImage, &threatScore);

    /* 无害分类（Unknown/System/KnownApplication）跳过 */
    if (cls == WkdNpmClass_Unknown ||
        cls == WkdNpmClass_System ||
        cls == WkdNpmClass_KnownApplication) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 阻断判定（门控默认关，Audit 模式；系统管道冒充无条件 / C2≥90 达标，
     * 临界进程豁免防系统自身误阻断）。阻断与非阻断均评分+上送，仅 WasBlocked
     * 标志区分（供 agent 取证）。 */
    if (g_NpmBlockingEnabled && WkdNpmIsBlockworthy(cls, threatScore) &&
        !AepIsCriticalProcess(pid, NULL)) {
        WkdNpmNoteBlocked();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[WkDefender/FS] BLOCKED named pipe: '%.64ws' class=%d score=%u creator=%hs PID=%lu\n",
            pipeName, (int)cls, threatScore, creatorImage, HandleToULong(pid));

        indicator = WkdFspPipeClassToIndicator(cls);
        if (indicator != TsIndicator_Unknow) {
            AeReportIndicatorPair(pid, pid, TsSourceIOC, indicator, 0);
        }
        FspSendNamedPipeEvent(pid, pipeName, nameBytes, creatorImage, cls, threatScore, TRUE);

        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* 评分上报（severity=0 → AeReportIndicatorPair 内部查 IocGetIndicatorSeverity） */
    indicator = WkdFspPipeClassToIndicator(cls);
    if (indicator != TsIndicator_Unknow) {
        AeReportIndicatorPair(pid, pid, TsSourceIOC, indicator, 0);
    }

    /* 事件上送（仅分类命中；Suspicious 类也上送供 agent 关联） */
    FspSendNamedPipeEvent(pid, pipeName, nameBytes, creatorImage, cls, threatScore, FALSE);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/**************************************************/
/*    代码执行映射检测回调（PreAcquireSection）     */
/**************************************************/

/* 卷类型判定（网络/可移除）：补齐 SS 注入检测 NETWORK/REMOVABLE 标志的生产者 */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
WkdFspGetVolumeNetworkRemovable(
    _In_ PFLT_VOLUME Volume,
    _Out_ PBOOLEAN IsNetwork,
    _Out_ PBOOLEAN IsRemovable
    )
{
    FLT_VOLUME_PROPERTIES volumeProps;
    ULONG bytesReturned;
    NTSTATUS status;

    *IsNetwork = FALSE;
    *IsRemovable = FALSE;

    if (Volume == NULL) {
        return;
    }
    status = FltGetVolumeProperties(Volume, &volumeProps,
        sizeof(volumeProps), &bytesReturned);
    if (NT_SUCCESS(status)) {
        if (volumeProps.DeviceCharacteristics & FILE_REMOTE_DEVICE) {
            *IsNetwork = TRUE;
        }
        if (volumeProps.DeviceCharacteristics & FILE_REMOVABLE_MEDIA) {
            *IsRemovable = TRUE;
        }
    }
}

/* 映射标志 → 指示器（按行为严重度优先级取最严重一个） */
static TS_INDICATOR_TYPE
FspSectionMapIndicator(
    _In_ ULONG MappingFlags
    )
{
    if (MappingFlags & PAS_MAP_FLAG_HOLLOWING_SUSPECT) {
        return TsIndicator_Ioa_SectionMapHollowing;
    }
    if (MappingFlags & PAS_MAP_FLAG_REFLECTIVE_SUSPECT) {
        return TsIndicator_Ioa_SectionMapReflective;
    }
    if (MappingFlags & PAS_MAP_FLAG_WRITABLE) {
        return TsIndicator_Ioa_SectionMapExecutable;
    }
    if (MappingFlags & PAS_MAP_FLAG_SUSPICIOUS_PATH) {
        return TsIndicator_Ioa_SectionMapExecutable;
    }
    return TsIndicator_Unknow;
}

/* 区段映射事件上送（0x1308，仿 FspSendNamedPipeEvent 变长范式）。
 * 文件轨 Origin=0；syscall 轨复用本 body（Origin=1/2），FilePath 可空。 */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
FspSendSectionMapEvent(
    _In_ HANDLE ProcessId,
    _In_ PCUNICODE_STRING FilePath,
    _In_ ULONG PageProtection,
    _In_ ULONG MappingFlags,
    _In_ ULONG SuspicionScore,
    _In_ ULONG Origin,
    _In_ BOOLEAN WasBlocked
    )
{
    NTSTATUS status;
    PWKD_MESSAGE msg;
    PWKD_MESSAGE_BODY_SECTION_MAP body;
    ULONG bodySize;
    USHORT copyLen;

    copyLen = (FilePath->Length > MAX_PATH * sizeof(WCHAR)) ?
              (MAX_PATH * sizeof(WCHAR)) : FilePath->Length;

    bodySize = sizeof(WKD_MESSAGE_BODY_SECTION_MAP) + copyLen;
    msg = NtfCreateMessage(WkdMessage_SectionMap, WkdMessage_SourceFile,
                           WkdMessage_PriorityHigh, bodySize);
    if (msg == NULL) {
        return;
    }

    body = (PWKD_MESSAGE_BODY_SECTION_MAP)msg->Body;
    body->ProcessId = ProcessId;
    body->ThreadId = PsGetCurrentThreadId();
    body->PageProtection = PageProtection;
    body->SectionType = (PageProtection & SEC_IMAGE) ? 1 : 0;
    body->MappingFlags = MappingFlags;
    body->SuspicionScore = SuspicionScore;
    body->Origin = Origin;
    body->Flags = WasBlocked ? 1 : 0;
    body->SectionHandle = 0;
    body->BaseAddress = 0;
    body->RegionSize = 0;
    KeQuerySystemTime(&body->Timestamp);
    body->FilePath.Buffer = (PWSTR)(body + 1);
    body->FilePath.Length = copyLen;
    body->FilePath.MaximumLength = copyLen;
    RtlCopyMemory(body->FilePath.Buffer, FilePath->Buffer, copyLen);

    status = NtfSendMessageAsync(msg);
    if (!NT_SUCCESS(status)) {
        NmFreeMessage(msg);
    }
}

_Use_decl_annotations_
static
FLT_PREOP_CALLBACK_STATUS
CbpPreAcquireSectionNotifyCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG pageProtection;
    ULONG pathFlags = 0;
    ULONG pathScore = 0;
    BOOLEAN isNetwork = FALSE;
    BOOLEAN isRemovable = FALSE;
    ULONG preMappedFlags = 0;
    WKD_PAS_INPUT input;
    ULONG score = 0;
    ULONG mapFlags = 0;
    HANDLE pid;
    TS_INDICATOR_TYPE indicator;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    /* boot 期跳过（ShadowFsIsBootPhase） */
    //if (WkdFspIsBootPhase()) {
    //    return FLT_PREOP_SUCCESS_NO_CALLBACK;
    //}

    /* 初始化守卫（惰性初始化在编排器 FsInitialize 完成；未初始化/关闭中安全跳过） */
    if (!WkdPasIsActive()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* FSC-2：SyncType 必须是 SyncTypeCreateSection，PageProtection 才有效 */
    if (Data == NULL || Data->Iopb == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType !=
        SyncTypeCreateSection) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    pageProtection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;

    /* 快速路径：非执行映射放行（PAS_EXECUTE_PROTECTION_MASK） */
    if (!(pageProtection & PAS_EXECUTE_PROTECTION_MASK)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 信任内核/系统/受保护进程 */
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    pid = PsGetCurrentProcessId();
    if (pid == (HANDLE)(ULONG_PTR)4 || ExemptsIsProcessTrusted(pid)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 路径查询：必须 CACHE_ONLY 防死锁（L1650-1654） */
    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_CACHE_ONLY, &nameInfo);
    if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    
    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* 自保护：阻止 EDR 自身文件被执行映射（强信号，不受 EnableBlocking 门控） */
    if (WkdFsShouldBlockFileAccess(&nameInfo->Name, SECTION_MAP_EXECUTE, pid, FALSE)) {
        WkdPasNoteSelfProtectBlock();
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* 路径排除（FileScan，ShadowStrikeIsPathExcluded） */
    if (WkdFsIsPathExcluded(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* ============================================================ */
    /* verdict 缓存强信号阻断（2026-09 激活）：PostCreate 迁移补齐     */
    /* 生产者（STREAM_CONTEXT 挂载 YARA verdict：Scanned/ScanResult）， */
    /* 此处消费CacheLookup 路径（L1527-1542）——恶意 verdict   */
    /* 立即阻断（Score=100 语义），不受 EnableBlocking Audit 门控     */
    /* （与自保护同类强信号）。Dirty/未扫 → verdict 失效不阻断。       */
    /* ============================================================ */
    if (FltObjects != NULL && FltObjects->Instance != NULL &&
        FltObjects->FileObject != NULL) {
        PWKD_POC_STREAM_CONTEXT streamCtx = NULL;

        status = FltGetStreamContext(
            FltObjects->Instance,
            FltObjects->FileObject,
            (PFLT_CONTEXT*)&streamCtx);

        if (NT_SUCCESS(status)) {
            if (FsCheckStreamContextValidity(streamCtx) &&
                !WkdPocNeedsRescan(streamCtx)) {

                WkdPasNoteCacheHit();

                if (!streamCtx->ScanResult) {
                    /* 恶意 verdict → 强信号阻断（CACHE HIT - BLOCK） */
                    WkdPasNoteCacheBlock();
                    FltReleaseContext((PFLT_CONTEXT)streamCtx);
                    FltReleaseFileNameInformation(nameInfo);
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;
                    return FLT_PREOP_COMPLETE;
                }
            } else {
                WkdPasNoteCacheMiss();
            }

            FltReleaseContext((PFLT_CONTEXT)streamCtx);
        } else {
            WkdPasNoteCacheMiss();
        }
    }

    /* B2 路径分析（FileScan，复用 PreCreate 路径威胁评分，供映射评分融合） */
    pathScore = FspAnalyzeFilePath(&nameInfo->Name, &nameInfo->Extension, &pathFlags);

    /* 卷类型判定（网络/可移除 → 注入检测生产者） */
    if (FltObjects != NULL && FltObjects->Volume != NULL) {
        WkdFspGetVolumeNetworkRemovable(FltObjects->Volume, &isNetwork, &isRemovable);
    }

    /* 把 B2 路径标志 + 卷类型预映射为 PAS_MAP_FLAG_*（两宏集合跨文件） */
    if (pathFlags & WKD_FS_PATH_ADS) {
        preMappedFlags |= PAS_MAP_FLAG_ADS;
    }
    if (pathFlags & WKD_FS_PATH_TEMP) {
        preMappedFlags |= PAS_MAP_FLAG_TEMP_LOCATION;
    }
    if (pathFlags & ~(WKD_FS_PATH_ADS | WKD_FS_PATH_TEMP)) {
        preMappedFlags |= PAS_MAP_FLAG_SUSPICIOUS_PATH;
    }
    if (isNetwork) {
        preMappedFlags |= PAS_MAP_FLAG_NETWORK;
    }
    if (isRemovable) {
        preMappedFlags |= PAS_MAP_FLAG_REMOVABLE;
    }

    /* 检测引擎（分类/行为检测/评分融合） */
    RtlZeroMemory(&input, sizeof(input));
    input.ProcessId = pid;
    input.PageProtection = pageProtection;
    input.FileName = &nameInfo->Name;
    input.PathScore = pathScore;
    input.PreMappedFlags = preMappedFlags;
    status = FsAuditMemeoryMapping(&input, &score, &mapFlags);

    /* 事件上送（score≥Medium 或阻断命中） */
    if (NT_SUCCESS(status) && WkdPasShouldReport(score)) {
        FspSendSectionMapEvent(pid, &nameInfo->Name, pageProtection, mapFlags,
                               score, 0, FALSE);
    }

    /* 评分上报（severity=0 → AeReportIndicatorPair 内部查 G_IocSeverityMap） */
    indicator = FspSectionMapIndicator(mapFlags);
    if (indicator != TsIndicator_Unknow) {
        AeReportIndicatorPair(pid, pid, TsSourceBehavioral, indicator, 0);
    }

    /* Audit 门控阻断（默认 EnableBlocking=FALSE 仅上报+评分） */
    if (WkdPasShouldBlock(score)) {
        WkdPasNoteBlocked();
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    WkdPasNoteAllowed();
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/**************************************************/
/*           UDC 实例回调（卷挂载/解除追踪）        */
/**************************************************/

/* InstanceSetup：USB 卷策略判定（可移除卷 → 写保护/autorun 策略入卷表）。
 * fail-safe：UDC 未初始化/禁用 → WkdUdcCheckVolumePolicy 返回 TRUE（放行附加）。 */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
FspInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    WKD_UDC_DEVICE_POLICY policy;
    BOOLEAN allowed;

    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    allowed = WkdUdcCheckVolumePolicy(FltObjects, &policy);
    if (!allowed) {
        if (FltObjects != NULL && FltObjects->Volume != NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[WkDefender/FS] Rejected instance attach (USB policy) on %wZ\n",
                &FltObjects->Volume->VolumeName);
        }
        return STATUS_FLT_DO_NOT_ATTACH;
    }
    WkdUdcNotifyVolumeMount(FltObjects, policy);
    return STATUS_SUCCESS;
}

/* InstanceTeardownComplete：卷解除追踪 */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
FspInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);
    WkdUdcNotifyVolumeDismount(FltObjects);
}

/**************************************************/
/*            操作回调表 + minifilter 注册          */
/**************************************************/

/* minifilter 卸载回调（前置于 WkdFltRegistration 引用） */
NTSTATUS
FsFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;  /* 端口/句柄由 FsUnregisterFilter 释放 */
}

static FLT_OPERATION_REGISTRATION WkdFltOperations[] = {
    { IRP_MJ_CREATE,            0, FsPreCreateNotifyCallback, FsPostCreateNotifyCallback, NULL },
    { IRP_MJ_CLEANUP,           0, FspPreCleanup,         NULL,                NULL },
    { IRP_MJ_WRITE,             0, FsPreWriteNotifyCallback, FsPostWriteNotifyCallabck, NULL },
    { IRP_MJ_SET_INFORMATION,   0, FsPreSetInformationNotifyCallback,  NULL,                NULL },
    { IRP_MJ_CREATE_NAMED_PIPE, 0, CbpPreCreateNotifyCallbackPipe,      NULL,                NULL },
    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, CbpPreAcquireSectionNotifyCallback, NULL, NULL },
    { IRP_MJ_OPERATION_END }
};

static FLT_CONTEXT_REGISTRATION g_FsContextRegistration[] = {
    /* PostCreate 迁移（2026-09）：
     *   STREAM_CONTEXT      —— 每文件 verdict 缓存 + 变更基线（FsPostCreateNotifyCallback 挂载）
     *   STREAMHANDLE_CONTEXT —— 每次打开元数据（WkdPocpCreateHandleContext 挂载）
     * 结构体全内嵌无外部资源 → ContextCleanupCallback 置 NULL（对比 SS 需 cleanup
     * 释放动态 name buffer；wkd 内嵌化布局免释放）。固定大小注册。 */
    { FLT_STREAM_CONTEXT,       0, NULL, sizeof(WKD_POC_STREAM_CONTEXT),      WKD_POC_STREAM_CONTEXT_TAG },
    { FLT_STREAMHANDLE_CONTEXT, 0, NULL, sizeof(WKD_POC_HANDLE_CONTEXT),      WKD_POC_HANDLE_CONTEXT_TAG },
    { FLT_CONTEXT_END }
};

static FLT_REGISTRATION WkdFltRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,   /* 必须：注册 AcquireSection IRP 时 MSDN 强制 */
    g_FsContextRegistration,   /* ContextRegistration：PostCreate 迁移（2026-09 接线） */
    WkdFltOperations,
    FsFilterUnload,
    FspInstanceSetup,              /* InstanceSetup：USB 卷策略判定（迁移 2026-08 接线） */
    NULL,                          /* InstanceQueryTeardown */
    NULL,                          /* InstanceTeardownStart */
    FspInstanceTeardownComplete,   /* InstanceTeardownComplete：USB 卷解除追踪（迁移 2026-08 接线） */
    NULL, NULL, NULL, NULL, NULL
};

/**************************************************/
/*                FsRegisterFilter / FsUnregisterFilter                     */
/**************************************************/

/*++
 * FsRegisterFilter
 *   纯注册职责（2026-09-13 重构）：注册 minifilter + 创建 YARA 专用 FLT
 *   通信端口（与 ALPC 主通道隔离，X1 模型）+ StartFiltering。
 *
 *   分析能力模块初始化统一由编排器 FsInitialize 负责（FileScan → UDC → Pfcp
 *   → Poc → Pwc → 本函数 → Pas → FBE → NPM）。StartFiltering 生效后回调可能
 *   先于 Pas/FBE/NPM 初始化完成——各回调壳经 WkdPasIsActive()/WkdNpmIsActive()
 *   状态门控安全跳过初始化窗口。
 *--*/
_Use_decl_annotations_
NTSTATUS
FsRegisterFilter(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DriverObject);

    ExInitializeFastMutex(&g_FsPortLock);

    /* 1. 注册 minifilter */
    status = FltRegisterFilter(DriverObject, &WkdFltRegistration, &WkdFileSystemFilter);
    if (!NT_SUCCESS(status)) goto Cleanup;

    /* 2. 创建 YARA 专用 FLT 通信端口（与 ALPC 主通道隔离，X1 模型） */
    /* 安全描述符：构造 NULL DACL（DaclPresent=TRUE, Dacl=NULL）= 允许所有用户连接。
     * 开发阶段用此简化调试；切勿传 NULL sd（那等于 SYSTEM-only）。
     * TODO：生产环境应创建自定义 DACL 仅允许 SYSTEM + Administrators 连接。 */
    {
        SECURITY_DESCRIPTOR secDesc;
        UNICODE_STRING portName;
        OBJECT_ATTRIBUTES objAttr;

        status = RtlCreateSecurityDescriptor(&secDesc, SECURITY_DESCRIPTOR_REVISION);
        if (!NT_SUCCESS(status)) goto Cleanup;

        status = RtlSetDaclSecurityDescriptor(&secDesc, TRUE, NULL, FALSE);
        if (!NT_SUCCESS(status)) goto Cleanup;

        RtlInitUnicodeString(&portName, WKD_YARA_PORT_NAME);
        InitializeObjectAttributes(&objAttr, &portName,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, &secDesc);

        status = FltCreateCommunicationPort(
            WkdFileSystemFilter,
            &WkdFltServerPort,
            &objAttr,
            NULL,       /* ServerPortCookie */
            CbpFileSystemConnectNotifyCallback,
            CbpFileSystemDisconnectNotifyCallback,
            CbpFileSystemMessageNotifyCallback,
            WKD_YARA_PORT_MAX_CONNECT);
        if (!NT_SUCCESS(status)) goto Cleanup;
    }

    /* 3. 启动过滤（开始回调生效） */
    status = FltStartFiltering(WkdFileSystemFilter);
    if (!NT_SUCCESS(status)) goto StartFilteringFailed;

    return STATUS_SUCCESS;

StartFilteringFailed:
    if (WkdFltServerPort) FltCloseCommunicationPort(WkdFltServerPort);

Cleanup:
    if (WkdFileSystemFilter) FltUnregisterFilter(WkdFileSystemFilter);
    return status;
}

/*++
 * FsUnregisterFilter
 *   纯反注册职责（2026-09-13 重构）：关闭 YARA FLT 端口 + FltUnregisterFilter。
 *   分析能力模块逆序清理由编排器 FsCleanup 统一负责（NPM → FBE → Pas → Pwc
 *   → Poc → Pfcp → Udc → FileScan → 本函数）。
 *--*/
_Use_decl_annotations_
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FsUnregisterFilter(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (WkdFltServerPort != NULL) {
        FltCloseCommunicationPort(WkdFltServerPort);
        WkdFltServerPort = NULL;
    }
    if (WkdFileSystemFilter != NULL) {
        FltUnregisterFilter(WkdFileSystemFilter);
        WkdFileSystemFilter = NULL;
    }
    g_FsClientPort = NULL;
    InterlockedExchange(&g_FsConnectedPid, 0);
}

/*++
 * WkdFsGetFilterHandle
 *   返回 minifilter 句柄（FileBackupEngine FltCreateFileEx 依赖）。
 *--*/
_Use_decl_annotations_
PFLT_FILTER
WkdFsGetFilterHandle(
    VOID
    )
{
    return WkdFileSystemFilter;
}